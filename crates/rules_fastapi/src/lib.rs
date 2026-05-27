use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, Severity,
    SourceSpan,
};
use codehealth_parser::Span;
use codehealth_rules::{
    find_rule, Rule, RuleContext, RuleMetadata, FASTAPI_BLOCKING_CALL_IN_ASYNC_ROUTE,
    FASTAPI_BROAD_EXCEPTION_IN_ROUTE, FASTAPI_BUSINESS_LOGIC_IN_ROUTE,
    FASTAPI_DUPLICATED_PYDANTIC_MODEL, FASTAPI_DUPLICATE_ROUTE, FASTAPI_INCONSISTENT_STATUS_CODE,
    FASTAPI_LARGE_ROUTE_HANDLER, FASTAPI_MISSING_RESPONSE_MODEL, FASTAPI_REPEATED_AUTH_LOGIC,
    FASTAPI_REPEATED_DEPENDENCY_LOGIC, FASTAPI_REQUESTS_CALL_INSIDE_ASYNC_ROUTE,
    FASTAPI_ROUTE_CONFLICT, FASTAPI_ROUTE_HANDLER_DUPLICATE_LOGIC,
    FASTAPI_SYNC_DB_CALL_INSIDE_ASYNC_ROUTE,
};
use codehealth_symbols::{Definition, DefinitionKind, FrameworkTag, Language};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

pub const FASTAPI_RULE_NAMESPACE: &str = "fastapi";

type RuleRunner = fn(&RuleContext<'_>) -> Vec<Finding>;

pub fn finding_kind() -> FindingKind {
    FindingKind::FastApi
}

pub fn fastapi_rules() -> Vec<Box<dyn Rule>> {
    vec![
        boxed(FASTAPI_DUPLICATE_ROUTE, duplicate_route),
        boxed(FASTAPI_ROUTE_CONFLICT, route_conflict),
        boxed(
            FASTAPI_BLOCKING_CALL_IN_ASYNC_ROUTE,
            blocking_call_in_async_route,
        ),
        boxed(FASTAPI_MISSING_RESPONSE_MODEL, missing_response_model),
        boxed(FASTAPI_LARGE_ROUTE_HANDLER, large_route_handler),
        boxed(FASTAPI_BUSINESS_LOGIC_IN_ROUTE, business_logic_in_route),
        boxed(FASTAPI_REPEATED_DEPENDENCY_LOGIC, repeated_dependency_logic),
        boxed(FASTAPI_REPEATED_AUTH_LOGIC, repeated_auth_logic),
        boxed(FASTAPI_BROAD_EXCEPTION_IN_ROUTE, broad_exception_in_route),
        boxed(FASTAPI_INCONSISTENT_STATUS_CODE, inconsistent_status_code),
        boxed(FASTAPI_DUPLICATED_PYDANTIC_MODEL, duplicated_pydantic_model),
        boxed(
            FASTAPI_ROUTE_HANDLER_DUPLICATE_LOGIC,
            route_handler_duplicate_logic,
        ),
        boxed(
            FASTAPI_SYNC_DB_CALL_INSIDE_ASYNC_ROUTE,
            sync_db_call_inside_async_route,
        ),
        boxed(
            FASTAPI_REQUESTS_CALL_INSIDE_ASYNC_ROUTE,
            requests_call_inside_async_route,
        ),
    ]
}

fn boxed(rule_id: &'static str, runner: RuleRunner) -> Box<dyn Rule> {
    Box::new(BuiltinFastApiRule { rule_id, runner })
}

struct BuiltinFastApiRule {
    rule_id: &'static str,
    runner: RuleRunner,
}

impl Rule for BuiltinFastApiRule {
    fn id(&self) -> &'static str {
        self.rule_id
    }

    fn metadata(&self) -> RuleMetadata {
        find_rule(self.rule_id).expect("built-in FastAPI rule exists in catalog")
    }

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        (self.runner)(ctx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastApiRouteModel {
    pub method: String,
    pub path: String,
    pub raw_path: String,
    pub handler_name: String,
    pub qualified_name: String,
    pub file: PathBuf,
    pub span: Span,
    pub body_span: Span,
    pub router_variable: Option<String>,
    pub response_model: Option<String>,
    pub status_code: Option<String>,
    pub dependencies: Vec<String>,
    pub tags: Vec<String>,
    pub summary: Option<String>,
    pub auth_dependency: Option<String>,
    pub is_async: bool,
    pub calls: Vec<String>,
    pub db_session_usage: Vec<String>,
    pub source: String,
    pub lines_of_code: usize,
    pub structural_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PydanticModel {
    name: String,
    qualified_name: String,
    file: PathBuf,
    span: Span,
    fields: Vec<PydanticField>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PydanticField {
    name: String,
    annotation: String,
}

fn duplicate_route(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) || !ctx.config.fastapi_detect_duplicate_routes {
        return Vec::new();
    }
    let mut groups: BTreeMap<String, Vec<FastApiRouteModel>> = BTreeMap::new();
    for route in all_routes(ctx) {
        groups
            .entry(format!("{} {}", route.method, route.path))
            .or_default()
            .push(route);
    }

    groups
        .into_iter()
        .filter(|(_, group)| group.len() > 1)
        .filter_map(|(route_key, mut group)| {
            sort_routes(&mut group);
            let primary = group.first()?.clone();
            if primary.file != ctx.source_file.path {
                return None;
            }
            let mut metadata = route_metadata(&primary);
            metadata.insert("route".to_string(), json!(route_key));
            metadata.insert("routes".to_string(), json!(group.len()));
            Some(group_finding(
                ctx,
                FASTAPI_DUPLICATE_ROUTE,
                &group,
                format!(
                    "{} FastAPI handlers register the same route '{}'.",
                    group.len(),
                    metadata["route"].as_str().unwrap_or_default()
                ),
                "Remove one route, merge the handlers, or change one method/path combination."
                    .to_string(),
                "Resolved FastAPI route metadata was grouped by HTTP method and path.".to_string(),
                metadata,
            ))
        })
        .collect()
}

fn route_conflict(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    let mut by_method: BTreeMap<String, Vec<FastApiRouteModel>> = BTreeMap::new();
    for route in all_routes(ctx) {
        by_method
            .entry(route.method.clone())
            .or_default()
            .push(route);
    }

    let mut findings = Vec::new();
    let mut emitted = BTreeSet::new();
    for routes in by_method.into_values() {
        for left_index in 0..routes.len() {
            for right in routes.iter().skip(left_index + 1) {
                let left = &routes[left_index];
                if left.path == right.path || !paths_conflict(&left.path, &right.path) {
                    continue;
                }
                let mut group = vec![left.clone(), right.clone()];
                sort_routes(&mut group);
                let key = group
                    .iter()
                    .map(|route| format!("{}:{}:{}", route.method, route.path, route.handler_name))
                    .collect::<Vec<_>>()
                    .join("|");
                if !emitted.insert(key) || group[0].file != ctx.source_file.path {
                    continue;
                }
                let mut metadata = route_metadata(&group[0]);
                metadata.insert(
                    "conflicting_routes".to_string(),
                    json!(group.iter().map(route_label).collect::<Vec<_>>()),
                );
                findings.push(group_finding(
                    ctx,
                    FASTAPI_ROUTE_CONFLICT,
                    &group,
                    format!(
                        "FastAPI routes '{}' and '{}' can match the same {} request.",
                        group[0].path, group[1].path, group[0].method
                    ),
                    "Make the route patterns distinct, order static routes before dynamic routes, or use clearer path parameter constraints."
                        .to_string(),
                    "Path templates for the same method have compatible static and parameter segments."
                        .to_string(),
                    metadata,
                ));
            }
        }
    }
    findings
}

fn blocking_call_in_async_route(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) || !ctx.config.fastapi_detect_blocking_async_calls {
        return Vec::new();
    }
    current_routes(ctx)
        .into_iter()
        .filter(|route| route.is_async)
        .flat_map(|route| {
            blocking_matches(
                &route,
                &ctx.config.fastapi_blocking_call_patterns,
                &ctx.config.fastapi_blocking_call_allowlist,
            )
            .into_iter()
            .map(move |pattern| {
                let mut metadata = route_metadata(&route);
                metadata.insert("blocking_call".to_string(), json!(pattern));
                route_finding(
                    ctx,
                    FASTAPI_BLOCKING_CALL_IN_ASYNC_ROUTE,
                    &route,
                    format!(
                        "Async FastAPI route '{}' calls blocking API '{}'.",
                        route.handler_name, pattern
                    ),
                    "Use an async client/driver, move blocking work to a threadpool, or make the route synchronous when appropriate."
                        .to_string(),
                    "The async route source contains a configured blocking call pattern."
                        .to_string(),
                    metadata,
                )
            })
        })
        .collect()
}

fn missing_response_model(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) || ctx.config.fastapi_require_response_model == "off" {
        return Vec::new();
    }
    current_routes(ctx)
        .into_iter()
        .filter(|route| route.response_model.is_none())
        .filter(route_should_have_response_model)
        .map(|route| {
            let mut finding = route_finding(
                ctx,
                FASTAPI_MISSING_RESPONSE_MODEL,
                &route,
                format!(
                    "FastAPI route '{} {}' has no response_model.",
                    route.method, route.path
                ),
                "Add an explicit response_model, or suppress the rule if this route intentionally returns a raw Response/stream."
                    .to_string(),
                "The route decorator has no response_model and the handler does not look like a raw Response route."
                    .to_string(),
                route_metadata(&route),
            );
            if ctx.config.fastapi_require_response_model == "error" {
                finding.severity = Severity::High;
            }
            finding
        })
        .collect()
}

fn large_route_handler(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    let max_lines = ctx
        .config
        .options_for(FASTAPI_LARGE_ROUTE_HANDLER)
        .max_lines
        .unwrap_or(80);
    current_routes(ctx)
        .into_iter()
        .filter(|route| route.lines_of_code > max_lines)
        .map(|route| {
            let mut metadata = route_metadata(&route);
            metadata.insert("max_lines".to_string(), json!(max_lines));
            route_finding(
                ctx,
                FASTAPI_LARGE_ROUTE_HANDLER,
                &route,
                format!(
                    "FastAPI route handler '{}' is {} lines long.",
                    route.handler_name, route.lines_of_code
                ),
                "Move validation, orchestration, and data access into dependencies or service functions."
                    .to_string(),
                "The indexed route handler body exceeds the configured line threshold.".to_string(),
                metadata,
            )
        })
        .collect()
}

fn business_logic_in_route(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    current_routes(ctx)
        .into_iter()
        .filter(|route| business_logic_score(route) >= 4)
        .map(|route| {
            let mut metadata = route_metadata(&route);
            metadata.insert("business_logic_score".to_string(), json!(business_logic_score(&route)));
            route_finding(
                ctx,
                FASTAPI_BUSINESS_LOGIC_IN_ROUTE,
                &route,
                format!(
                    "FastAPI route handler '{}' mixes routing with business logic.",
                    route.handler_name
                ),
                "Extract domain decisions, persistence, and external service orchestration below the route boundary."
                    .to_string(),
                "The route combines multiple logic signals such as branches, loops, DB/session usage, external calls, and longer body length."
                    .to_string(),
                metadata,
            )
        })
        .collect()
}

fn repeated_dependency_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    let min_routes = ctx
        .config
        .options_for(FASTAPI_REPEATED_DEPENDENCY_LOGIC)
        .min_nodes
        .unwrap_or(3);
    grouped_route_rule(
        ctx,
        FASTAPI_REPEATED_DEPENDENCY_LOGIC,
        min_routes,
        |route| {
            (!route.dependencies.is_empty()).then(|| normalized_list_key(&route.dependencies))
        },
        "FastAPI routes repeat the same dependency list.",
        "Move repeated dependencies to APIRouter dependencies, a shared dependency wrapper, or route-group composition.",
        "Routes were grouped by normalized dependency calls.",
    )
}

fn repeated_auth_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    let min_routes = ctx
        .config
        .options_for(FASTAPI_REPEATED_AUTH_LOGIC)
        .min_nodes
        .unwrap_or(3);
    grouped_route_rule(
        ctx,
        FASTAPI_REPEATED_AUTH_LOGIC,
        min_routes,
        |route| route.auth_dependency.clone(),
        "FastAPI routes repeat the same auth/security dependency.",
        "Attach shared auth at the router level or extract an auth dependency that expresses the route group intent.",
        "Routes were grouped by normalized security dependency usage.",
    )
}

fn broad_exception_in_route(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    current_routes(ctx)
        .into_iter()
        .filter(|route| has_broad_exception(&route.source))
        .map(|route| {
            route_finding(
                ctx,
                FASTAPI_BROAD_EXCEPTION_IN_ROUTE,
                &route,
                format!(
                    "FastAPI route handler '{}' catches a broad exception.",
                    route.handler_name
                ),
                "Catch the narrow exception type, let FastAPI exception handlers handle expected failures, or re-raise unexpected errors."
                    .to_string(),
                "The route body contains `except Exception`, `except BaseException`, or a bare except."
                    .to_string(),
                route_metadata(&route),
            )
        })
        .collect()
}

fn inconsistent_status_code(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    current_routes(ctx)
        .into_iter()
        .filter_map(|route| status_code_issue(&route).map(|issue| (route, issue)))
        .map(|(route, issue)| {
            let mut metadata = route_metadata(&route);
            metadata.insert("status_code_issue".to_string(), json!(issue));
            route_finding(
                ctx,
                FASTAPI_INCONSISTENT_STATUS_CODE,
                &route,
                format!(
                    "FastAPI route '{} {}' has a possibly inconsistent status code.",
                    route.method, route.path
                ),
                "Make the decorator status_code match the route behavior, especially for create and no-content responses."
                    .to_string(),
                "Route method, handler name, decorator status_code, and return shape suggest a mismatch."
                    .to_string(),
                metadata,
            )
        })
        .collect()
}

fn duplicated_pydantic_model(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    let min_fields = ctx
        .config
        .options_for(FASTAPI_DUPLICATED_PYDANTIC_MODEL)
        .min_nodes
        .unwrap_or(3);
    let mut groups: BTreeMap<String, Vec<PydanticModel>> = BTreeMap::new();
    for model in all_pydantic_models(ctx) {
        if model.fields.len() < min_fields || has_intentional_model_suffix(&model.name) {
            continue;
        }
        groups
            .entry(model_field_key(&model.fields, true))
            .or_default()
            .push(model);
    }

    groups
        .into_iter()
        .filter(|(_, group)| group.len() > 1)
        .filter_map(|(hash, mut group)| {
            group.sort_by(|left, right| {
                left.file
                    .cmp(&right.file)
                    .then_with(|| left.span.start.cmp(&right.span.start))
                    .then_with(|| left.qualified_name.cmp(&right.qualified_name))
            });
            if group[0].file != ctx.source_file.path {
                return None;
            }
            let mut metadata = BTreeMap::new();
            metadata.insert("canonical_hash".to_string(), json!(hash));
            metadata.insert(
                "model_names".to_string(),
                json!(
                    group
                        .iter()
                        .map(|model| model.qualified_name.clone())
                        .collect::<Vec<_>>()
                ),
            );
            metadata.insert("field_count".to_string(), json!(group[0].fields.len()));
            Some(model_group_finding(
                ctx,
                &group,
                format!(
                    "{} Pydantic models share the same field set.",
                    group.len()
                ),
                "Consider a shared base model only if the API contracts are intentionally coupled; otherwise suppress with the contract reason."
                    .to_string(),
                "Pydantic model field names/types matched and model names did not suggest create/update/response/internal separation."
                    .to_string(),
                metadata,
            ))
        })
        .collect()
}

fn route_handler_duplicate_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) {
        return Vec::new();
    }
    let min_lines = ctx
        .config
        .options_for(FASTAPI_ROUTE_HANDLER_DUPLICATE_LOGIC)
        .min_lines
        .unwrap_or(5);
    let mut groups: BTreeMap<String, Vec<FastApiRouteModel>> = BTreeMap::new();
    for route in all_routes(ctx) {
        if route.lines_of_code < min_lines {
            continue;
        }
        if let Some(hash) = &route.structural_hash {
            groups.entry(hash.clone()).or_default().push(route);
        }
    }

    groups
        .into_iter()
        .filter(|(_, group)| group.len() > 1)
        .filter_map(|(hash, mut group)| {
            sort_routes(&mut group);
            if group[0].file != ctx.source_file.path {
                return None;
            }
            let mut metadata = route_metadata(&group[0]);
            metadata.insert("canonical_hash".to_string(), json!(hash));
            metadata.insert("routes".to_string(), json!(group.len()));
            Some(group_finding(
                ctx,
                FASTAPI_ROUTE_HANDLER_DUPLICATE_LOGIC,
                &group,
                format!(
                    "{} FastAPI route handlers share duplicated logic.",
                    group.len()
                ),
                "Extract the shared route logic below the API layer if these handlers perform the same domain work."
                    .to_string(),
                "Route handler bodies share the same structural fingerprint.".to_string(),
                metadata,
            ))
        })
        .collect()
}

fn sync_db_call_inside_async_route(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) || !ctx.config.fastapi_detect_blocking_async_calls {
        return Vec::new();
    }
    current_routes(ctx)
        .into_iter()
        .filter(|route| route.is_async)
        .filter(|route| !route.db_session_usage.is_empty())
        .map(|route| {
            let mut metadata = route_metadata(&route);
            metadata.insert("db_calls".to_string(), json!(route.db_session_usage));
            route_finding(
                ctx,
                FASTAPI_SYNC_DB_CALL_INSIDE_ASYNC_ROUTE,
                &route,
                format!(
                    "Async FastAPI route '{}' appears to use synchronous DB/session calls.",
                    route.handler_name
                ),
                "Use an async database driver/session, run blocking DB work in a threadpool, or make the route synchronous."
                    .to_string(),
                "The async route body contains common synchronous DB/session call patterns."
                    .to_string(),
                metadata,
            )
        })
        .collect()
}

fn requests_call_inside_async_route(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !fastapi_allowed(ctx) || !ctx.config.fastapi_detect_blocking_async_calls {
        return Vec::new();
    }
    current_routes(ctx)
        .into_iter()
        .filter(|route| route.is_async)
        .filter(|route| route.source.contains("requests."))
        .map(|route| {
            route_finding(
                ctx,
                FASTAPI_REQUESTS_CALL_INSIDE_ASYNC_ROUTE,
                &route,
                format!(
                    "Async FastAPI route '{}' calls the synchronous requests client.",
                    route.handler_name
                ),
                "Use an async HTTP client such as httpx.AsyncClient, move the call to a threadpool, or make the route synchronous."
                    .to_string(),
                "The async route body contains a `requests.*` call.".to_string(),
                route_metadata(&route),
            )
        })
        .collect()
}

fn fastapi_allowed(ctx: &RuleContext<'_>) -> bool {
    ctx.config.fastapi_enabled
        && ctx.workspace.fastapi.detected
        && ctx.source_file.language.name.eq_ignore_ascii_case("python")
}

fn current_routes(ctx: &RuleContext<'_>) -> Vec<FastApiRouteModel> {
    all_routes(ctx)
        .into_iter()
        .filter(|route| route.file == ctx.source_file.path)
        .collect()
}

fn all_routes(ctx: &RuleContext<'_>) -> Vec<FastApiRouteModel> {
    ctx.symbols
        .map(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| definition.kind == DefinitionKind::FastApiRoute)
                .filter_map(|definition| route_from_definition(ctx, definition))
                .collect()
        })
        .unwrap_or_default()
}

fn route_from_definition(
    ctx: &RuleContext<'_>,
    definition: &Definition,
) -> Option<FastApiRouteModel> {
    let route = definition.framework_tags.iter().find_map(|tag| {
        if let FrameworkTag::FastApiRoute(route) = tag {
            Some(route)
        } else {
            None
        }
    })?;
    let body_span = definition.body_span.unwrap_or(definition.span);
    let file_source = source_for_definition(ctx, definition)?;
    let source = slice_span(&file_source, body_span).to_string();
    let calls = route_calls(ctx, definition);
    let db_session_usage = db_session_usage(&source, &calls);
    Some(FastApiRouteModel {
        method: route.method.clone(),
        path: normalize_route_path(&route.path),
        raw_path: route.raw_path.clone().unwrap_or_else(|| route.path.clone()),
        handler_name: definition.name.clone(),
        qualified_name: definition.qualified_name.clone(),
        file: definition.file.clone(),
        span: definition.span,
        body_span,
        router_variable: route.router_variable.clone(),
        response_model: route
            .response_model
            .clone()
            .filter(|value| !value.is_empty()),
        status_code: route.status_code.clone().filter(|value| !value.is_empty()),
        dependencies: route.dependencies.clone(),
        tags: route.tags.clone(),
        summary: route.summary.clone(),
        auth_dependency: route.auth_dependency.clone(),
        is_async: definition.is_async,
        calls,
        db_session_usage,
        lines_of_code: source.lines().count().max(1),
        structural_hash: definition
            .structural_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.stable_hash_hex.clone()),
        source,
    })
}

fn source_for_definition(ctx: &RuleContext<'_>, definition: &Definition) -> Option<String> {
    if definition.file == ctx.source_file.path {
        Some(ctx.source_file.source.clone())
    } else {
        fs::read_to_string(&definition.file).ok()
    }
}

fn route_calls(ctx: &RuleContext<'_>, definition: &Definition) -> Vec<String> {
    let mut calls = BTreeSet::new();
    if let Some(symbols) = ctx.symbols {
        for call in &symbols.call_sites {
            if call.language == Language::Python
                && call.file == definition.file
                && call.span.start >= definition.span.start
                && call.span.end <= definition.span.end
            {
                calls.insert(call.callee.clone());
            }
        }
    }
    calls.into_iter().collect()
}

fn all_pydantic_models(ctx: &RuleContext<'_>) -> Vec<PydanticModel> {
    ctx.symbols
        .map(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| definition.kind == DefinitionKind::PydanticModel)
                .filter_map(|definition| pydantic_model_from_definition(ctx, definition))
                .collect()
        })
        .unwrap_or_default()
}

fn pydantic_model_from_definition(
    ctx: &RuleContext<'_>,
    definition: &Definition,
) -> Option<PydanticModel> {
    let source = source_for_definition(ctx, definition)?;
    let span = definition.body_span.unwrap_or(definition.span);
    let body = slice_span(&source, span);
    let mut fields = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("class ")
            || trimmed.starts_with("def ")
            || trimmed.starts_with('@')
            || !trimmed.contains(':')
        {
            continue;
        }
        let (name, rest) = trimmed.split_once(':')?;
        let name = name.trim();
        if !is_identifier(name) {
            continue;
        }
        let annotation = rest
            .split('=')
            .next()
            .unwrap_or(rest)
            .trim()
            .trim_end_matches(',')
            .to_string();
        if !annotation.is_empty() {
            fields.push(PydanticField {
                name: name.to_string(),
                annotation,
            });
        }
    }
    fields.sort();
    fields.dedup();
    (!fields.is_empty()).then(|| PydanticModel {
        name: definition.name.clone(),
        qualified_name: definition.qualified_name.clone(),
        file: definition.file.clone(),
        span: definition.span,
        fields,
    })
}

fn grouped_route_rule(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    min_routes: usize,
    key: impl Fn(&FastApiRouteModel) -> Option<String>,
    message: &str,
    remediation: &str,
    detection_reason: &str,
) -> Vec<Finding> {
    let mut groups: BTreeMap<String, Vec<FastApiRouteModel>> = BTreeMap::new();
    for route in all_routes(ctx) {
        if let Some(key) = key(&route) {
            groups.entry(key).or_default().push(route);
        }
    }

    groups
        .into_iter()
        .filter(|(_, group)| group.len() >= min_routes)
        .filter_map(|(key, mut group)| {
            sort_routes(&mut group);
            if group[0].file != ctx.source_file.path {
                return None;
            }
            let mut metadata = route_metadata(&group[0]);
            metadata.insert("canonical_hash".to_string(), json!(stable_hash(&key)));
            metadata.insert("routes".to_string(), json!(group.len()));
            Some(group_finding(
                ctx,
                rule_id,
                &group,
                format!("{} {} occurrences.", message, group.len()),
                remediation.to_string(),
                detection_reason.to_string(),
                metadata,
            ))
        })
        .collect()
}

fn route_finding(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    route: &FastApiRouteModel,
    message: String,
    remediation: String,
    detection_reason: String,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    let metadata_rule = find_rule(rule_id);
    let baseline_key = fastapi_key(ctx.root, &route.file, rule_id, route.span, &message);
    Finding {
        finding_id: format!("{rule_id}:{}", &baseline_key[..12]),
        baseline_key,
        rule_id: rule_id.to_string(),
        kind: FindingKind::FastApi,
        severity: metadata_rule
            .as_ref()
            .map(|rule| rule.default_severity)
            .unwrap_or(Severity::Medium),
        confidence: metadata_rule
            .as_ref()
            .map(|rule| rule.default_confidence)
            .unwrap_or(Confidence::Medium),
        message,
        locations: vec![location(route.file.clone(), route.span)],
        language: Some("python".to_string()),
        framework: Some("fastapi".to_string()),
        explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.explanation)
            .unwrap_or("FastAPI health rule finding.")
            .to_string(),
        remediation,
        detection_reason,
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.autofix_explanation)
            .unwrap_or_default()
            .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn group_finding(
    _ctx: &RuleContext<'_>,
    rule_id: &'static str,
    group: &[FastApiRouteModel],
    message: String,
    remediation: String,
    detection_reason: String,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    let metadata_rule = find_rule(rule_id);
    let stable = stable_hash(&format!(
        "{rule_id}|{}",
        group.iter().map(route_label).collect::<Vec<_>>().join("|")
    ));
    Finding {
        finding_id: format!("{rule_id}:{}", &stable[..12]),
        baseline_key: stable,
        rule_id: rule_id.to_string(),
        kind: FindingKind::FastApi,
        severity: metadata_rule
            .as_ref()
            .map(|rule| rule.default_severity)
            .unwrap_or(Severity::Medium),
        confidence: metadata_rule
            .as_ref()
            .map(|rule| rule.default_confidence)
            .unwrap_or(Confidence::Medium),
        message,
        locations: group
            .iter()
            .map(|route| location(route.file.clone(), route.span))
            .collect(),
        language: Some("python".to_string()),
        framework: Some("fastapi".to_string()),
        explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.explanation)
            .unwrap_or("FastAPI health rule finding.")
            .to_string(),
        remediation,
        detection_reason,
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.autofix_explanation)
            .unwrap_or_default()
            .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn model_group_finding(
    ctx: &RuleContext<'_>,
    group: &[PydanticModel],
    message: String,
    remediation: String,
    detection_reason: String,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    let rule_id = FASTAPI_DUPLICATED_PYDANTIC_MODEL;
    let metadata_rule = find_rule(rule_id);
    let stable = stable_hash(&format!(
        "{rule_id}|{}",
        group
            .iter()
            .map(|model| format!("{}:{}", normalize_path(ctx.root, &model.file), model.name))
            .collect::<Vec<_>>()
            .join("|")
    ));
    Finding {
        finding_id: format!("{rule_id}:{}", &stable[..12]),
        baseline_key: stable,
        rule_id: rule_id.to_string(),
        kind: FindingKind::FastApi,
        severity: metadata_rule
            .as_ref()
            .map(|rule| rule.default_severity)
            .unwrap_or(Severity::Low),
        confidence: metadata_rule
            .as_ref()
            .map(|rule| rule.default_confidence)
            .unwrap_or(Confidence::Medium),
        message,
        locations: group
            .iter()
            .map(|model| location(model.file.clone(), model.span))
            .collect(),
        language: Some("python".to_string()),
        framework: Some("fastapi".to_string()),
        explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.explanation)
            .unwrap_or("FastAPI health rule finding.")
            .to_string(),
        remediation,
        detection_reason,
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.autofix_explanation)
            .unwrap_or_default()
            .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn location(path: PathBuf, span: Span) -> FindingLocation {
    FindingLocation {
        path,
        span: Some(SourceSpan {
            start: span.start,
            end: span.end,
        }),
        start: Some(Location {
            line: span.start_position.line,
            column: span.start_position.column,
            byte_offset: span.start,
        }),
        language: Some("python".to_string()),
    }
}

fn route_metadata(route: &FastApiRouteModel) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = BTreeMap::new();
    metadata.insert("method".to_string(), json!(route.method));
    metadata.insert("path".to_string(), json!(route.path));
    metadata.insert("raw_path".to_string(), json!(route.raw_path));
    metadata.insert("handler".to_string(), json!(route.qualified_name));
    metadata.insert("router_variable".to_string(), json!(route.router_variable));
    metadata.insert("response_model".to_string(), json!(route.response_model));
    metadata.insert("status_code".to_string(), json!(route.status_code));
    metadata.insert("dependencies".to_string(), json!(route.dependencies));
    metadata.insert("tags".to_string(), json!(route.tags));
    metadata.insert("auth_dependency".to_string(), json!(route.auth_dependency));
    metadata.insert("is_async".to_string(), json!(route.is_async));
    metadata.insert("calls".to_string(), json!(route.calls));
    metadata.insert(
        "db_session_usage".to_string(),
        json!(route.db_session_usage),
    );
    metadata.insert("lines".to_string(), json!(route.lines_of_code));
    metadata
}

fn fastapi_key(root: &Path, path: &Path, rule_id: &str, span: Span, message: &str) -> String {
    stable_hash(&format!(
        "{rule_id}|{}|{}|{}",
        normalize_path(root, path),
        span.start_position.line,
        collapse_whitespace(message)
    ))
}

fn stable_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
}

fn normalize_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn sort_routes(routes: &mut [FastApiRouteModel]) {
    routes.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.start.cmp(&right.span.start))
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| left.path.cmp(&right.path))
    });
}

fn route_label(route: &FastApiRouteModel) -> String {
    format!("{} {} {}", route.method, route.path, route.qualified_name)
}

fn normalize_route_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_matches('/'))
    }
}

fn paths_conflict(left: &str, right: &str) -> bool {
    let left = path_segments(left);
    let right = path_segments(right);
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .all(|(left, right)| left == right || is_path_parameter(left) || is_path_parameter(right))
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn is_path_parameter(segment: &str) -> bool {
    (segment.starts_with('{') && segment.ends_with('}'))
        || (segment.starts_with('<') && segment.ends_with('>'))
}

fn blocking_matches(
    route: &FastApiRouteModel,
    patterns: &[String],
    allowlist: &[String],
) -> Vec<String> {
    let mut matches = Vec::new();
    for pattern in patterns {
        if pattern.is_empty() || allowlist.iter().any(|allowed| allowed == pattern) {
            continue;
        }
        if route.source.contains(pattern)
            || route
                .calls
                .iter()
                .any(|call| call.contains(pattern.trim_end_matches('(')))
        {
            matches.push(pattern.clone());
        }
    }
    matches.sort();
    matches.dedup();
    matches
}

fn route_should_have_response_model(route: &FastApiRouteModel) -> bool {
    if route.method == "DELETE" || route.path == "/health" || route.path.ends_with("/health") {
        return false;
    }
    let source = route.source.as_str();
    ![
        "Response",
        "StreamingResponse",
        "FileResponse",
        "PlainTextResponse",
        "RedirectResponse",
    ]
    .iter()
    .any(|name| source.contains(name))
}

fn business_logic_score(route: &FastApiRouteModel) -> usize {
    usize::from(route.lines_of_code > 20)
        + usize::from(route.source.contains(" if ") || route.source.contains("\n    if "))
        + usize::from(route.source.contains(" for ") || route.source.contains("\n    for "))
        + usize::from(route.source.contains(" while ") || route.source.contains("\n    while "))
        + usize::from(!route.db_session_usage.is_empty())
        + usize::from(route.calls.len() > 4)
        + usize::from(route.source.contains("requests.") || route.source.contains("httpx."))
}

fn db_session_usage(source: &str, calls: &[String]) -> Vec<String> {
    let mut usage = BTreeSet::new();
    for pattern in [
        ".query(",
        ".execute(",
        ".commit(",
        ".rollback(",
        ".add(",
        "Session(",
        "sessionmaker(",
    ] {
        if source.contains(pattern) {
            usage.insert(pattern.to_string());
        }
    }
    for call in calls {
        if call.contains("session.") || call.contains("db.") {
            usage.insert(call.clone());
        }
    }
    usage.into_iter().collect()
}

fn normalized_list_key(values: &[String]) -> String {
    let mut values = values
        .iter()
        .map(|value| collapse_whitespace(value))
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values.join("|")
}

fn has_broad_exception(source: &str) -> bool {
    source.contains("except Exception")
        || source.contains("except BaseException")
        || source
            .lines()
            .any(|line| line.trim_start().starts_with("except:"))
}

fn status_code_issue(route: &FastApiRouteModel) -> Option<&'static str> {
    let status = route.status_code.as_deref().unwrap_or_default();
    if route.method == "POST"
        && status.is_empty()
        && (route.handler_name.starts_with("create")
            || route.handler_name.starts_with("add")
            || route.handler_name.starts_with("register"))
    {
        return Some("post_create_route_without_201_status");
    }
    if route.method == "DELETE" && status.is_empty() {
        return Some("delete_route_without_explicit_status");
    }
    if status.contains("204")
        && (route.response_model.is_some()
            || route.source.contains("return {")
            || route.source.contains("return ["))
    {
        return Some("no_content_status_with_response_body");
    }
    None
}

fn model_field_key(fields: &[PydanticField], include_types: bool) -> String {
    stable_hash(
        &fields
            .iter()
            .map(|field| {
                if include_types {
                    format!("{}:{}", field.name, collapse_whitespace(&field.annotation))
                } else {
                    field.name.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("|"),
    )
}

fn has_intentional_model_suffix(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    [
        "create", "update", "patch", "response", "read", "out", "public", "internal",
    ]
    .iter()
    .any(|token| lowered.contains(token))
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn slice_span(source: &str, span: Span) -> &str {
    if span.end <= source.len()
        && source.is_char_boundary(span.start)
        && source.is_char_boundary(span.end)
    {
        &source[span.start..span.end]
    } else {
        ""
    }
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
