use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, Severity,
    SourceSpan,
};
use codehealth_parser::{child_by_field_name, named_children, Span};
use codehealth_rules::{
    find_rule, Rule, RuleContext, RuleMetadata, RUST_DEEPLY_NESTED_MATCH,
    RUST_DUPLICATE_FREE_FUNCTION, RUST_DUPLICATE_IMPL_METHOD,
    RUST_DUPLICATE_TRAIT_METHOD_IMPLEMENTATION, RUST_EXPECT_WITHOUT_CONTEXT,
    RUST_LARGE_ENUM_VARIANT_LOGIC, RUST_LARGE_FUNCTION,
    RUST_MANUAL_OPTION_RESULT_PATTERN_CANDIDATE, RUST_REPEATED_CONVERSION_FUNCTION,
    RUST_REPEATED_ERROR_MAPPING, RUST_REPEATED_MATCH_ARM_BODY, RUST_REPEATED_RESULT_HANDLING,
    RUST_REPEATED_SERDE_GLUE, RUST_REPEATED_VALIDATION_LOGIC, RUST_SUSPICIOUS_UNWRAP_POLICY,
    RUST_TOO_MANY_PARAMETERS,
};
use codehealth_symbols::{Definition, DefinitionKind, Language, Visibility};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tree_sitter::Node;

pub const RUST_RULE_NAMESPACE: &str = "rust";

type RuleRunner = fn(&RuleContext<'_>) -> Vec<Finding>;

pub fn finding_kind() -> FindingKind {
    FindingKind::Rust
}

pub fn rust_rules() -> Vec<Box<dyn Rule>> {
    vec![
        boxed(RUST_LARGE_FUNCTION, large_function),
        boxed(RUST_TOO_MANY_PARAMETERS, too_many_parameters),
        boxed(RUST_DUPLICATE_FREE_FUNCTION, duplicate_free_function),
        boxed(RUST_DUPLICATE_IMPL_METHOD, duplicate_impl_method),
        boxed(
            RUST_DUPLICATE_TRAIT_METHOD_IMPLEMENTATION,
            duplicate_trait_method_implementation,
        ),
        boxed(RUST_REPEATED_MATCH_ARM_BODY, repeated_match_arm_body),
        boxed(RUST_SUSPICIOUS_UNWRAP_POLICY, suspicious_unwrap_policy),
        boxed(RUST_EXPECT_WITHOUT_CONTEXT, expect_without_context),
        boxed(RUST_REPEATED_ERROR_MAPPING, repeated_error_mapping),
        boxed(
            RUST_MANUAL_OPTION_RESULT_PATTERN_CANDIDATE,
            manual_option_result_pattern_candidate,
        ),
        boxed(RUST_DEEPLY_NESTED_MATCH, deeply_nested_match),
        boxed(RUST_LARGE_ENUM_VARIANT_LOGIC, large_enum_variant_logic),
        boxed(RUST_REPEATED_RESULT_HANDLING, repeated_result_handling),
        boxed(
            RUST_REPEATED_CONVERSION_FUNCTION,
            repeated_conversion_function,
        ),
        boxed(RUST_REPEATED_VALIDATION_LOGIC, repeated_validation_logic),
        boxed(RUST_REPEATED_SERDE_GLUE, repeated_serde_glue),
    ]
}

fn boxed(rule_id: &'static str, runner: RuleRunner) -> Box<dyn Rule> {
    Box::new(BuiltinRustRule { rule_id, runner })
}

struct BuiltinRustRule {
    rule_id: &'static str,
    runner: RuleRunner,
}

impl Rule for BuiltinRustRule {
    fn id(&self) -> &'static str {
        self.rule_id
    }

    fn metadata(&self) -> RuleMetadata {
        find_rule(self.rule_id).expect("built-in Rust rule exists in catalog")
    }

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        (self.runner)(ctx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustFunctionModel {
    pub name: String,
    pub qualified_name: String,
    pub kind: DefinitionKind,
    pub file: PathBuf,
    pub span: Span,
    pub body_span: Span,
    pub visibility: Visibility,
    pub attributes: Vec<String>,
    pub parameters: Vec<String>,
    pub source: String,
    pub lines_of_code: usize,
    pub token_count: usize,
    pub structural_hash: Option<String>,
    pub impl_context: Option<RustImplContext>,
    pub calls: Vec<String>,
    pub macro_calls: Vec<String>,
    pub unsafe_blocks: usize,
    pub unwrap_calls: usize,
    pub expect_calls: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustImplContext {
    pub target_type: String,
    pub trait_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustEnumModel {
    name: String,
    file: PathBuf,
    span: Span,
    source: String,
}

fn large_function(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let max_lines = ctx
        .config
        .options_for(RUST_LARGE_FUNCTION)
        .max_lines
        .unwrap_or_else(|| ctx.config.rust_max_function_lines.max(1));

    current_functions(ctx)
        .into_iter()
        .filter(|function| function.lines_of_code > max_lines)
        .map(|function| {
            let mut metadata = function_metadata(&function);
            metadata.insert("max_lines".to_string(), json!(max_lines));
            rust_finding(
                ctx,
                RUST_LARGE_FUNCTION,
                function.body_span,
                format!(
                    "Rust function '{}' is {} lines long.",
                    function.qualified_name, function.lines_of_code
                ),
                "Split cohesive parsing, validation, conversion, or error-handling steps into named helpers."
                    .to_string(),
                "The indexed Rust function body exceeds the configured line threshold."
                    .to_string(),
                metadata,
            )
        })
        .collect()
}

fn too_many_parameters(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let max_params = ctx
        .config
        .options_for(RUST_TOO_MANY_PARAMETERS)
        .max_params
        .unwrap_or_else(|| ctx.config.rust_max_params.max(1));

    current_functions(ctx)
        .into_iter()
        .filter(|function| effective_parameter_count(function) > max_params)
        .map(|function| {
            let mut metadata = function_metadata(&function);
            metadata.insert("max_params".to_string(), json!(max_params));
            metadata.insert(
                "parameter_count".to_string(),
                json!(effective_parameter_count(&function)),
            );
            rust_finding(
                ctx,
                RUST_TOO_MANY_PARAMETERS,
                function.span,
                format!(
                    "Rust function '{}' has {} parameters.",
                    function.qualified_name,
                    effective_parameter_count(&function)
                ),
                "Group related inputs into a small struct or move repeated setup behind a builder/helper."
                    .to_string(),
                "The function signature exceeds the configured Rust parameter threshold."
                    .to_string(),
                metadata,
            )
        })
        .collect()
}

fn duplicate_free_function(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    duplicate_function_group_rule(
        ctx,
        RUST_DUPLICATE_FREE_FUNCTION,
        |function| function.kind == DefinitionKind::Function,
        "Rust free functions share duplicated logic.",
        "Extract a shared helper or intentionally route callers through one public function.",
        "Free functions were grouped by structural body fingerprint.",
    )
}

fn duplicate_impl_method(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    duplicate_function_group_rule(
        ctx,
        RUST_DUPLICATE_IMPL_METHOD,
        |function| function.kind == DefinitionKind::Method,
        "Rust impl methods share duplicated logic.",
        "Extract shared behavior into a private helper, trait default method, or macro only if it improves clarity.",
        "Impl methods were grouped by structural body fingerprint.",
    )
}

fn duplicate_trait_method_implementation(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let min_lines = ctx
        .config
        .options_for(RUST_DUPLICATE_TRAIT_METHOD_IMPLEMENTATION)
        .min_lines
        .unwrap_or(3);
    let min_tokens = ctx
        .config
        .options_for(RUST_DUPLICATE_TRAIT_METHOD_IMPLEMENTATION)
        .min_tokens
        .unwrap_or(20);
    let mut groups: BTreeMap<String, Vec<RustFunctionModel>> = BTreeMap::new();
    for function in all_functions(ctx) {
        let Some(context) = &function.impl_context else {
            continue;
        };
        let Some(trait_name) = &context.trait_name else {
            continue;
        };
        if function.lines_of_code < min_lines || function.token_count < min_tokens {
            continue;
        }
        if function.macro_heavy() {
            continue;
        }
        if let Some(hash) = &function.structural_hash {
            groups
                .entry(format!("{trait_name}|{}|{hash}", function.name))
                .or_default()
                .push(function);
        }
    }
    grouped_function_findings(
        ctx,
        RUST_DUPLICATE_TRAIT_METHOD_IMPLEMENTATION,
        groups,
        "Rust trait method implementations share duplicated logic.",
        "Consider a trait default method or helper when the repeated implementation is intentional across implementors.",
        "Trait impl methods were grouped by trait name, method name, and structural body fingerprint.",
    )
}

fn repeated_match_arm_body(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "match_expression" {
            return;
        }
        let arms = descendants_of_kind(node, "match_arm");
        let mut by_body: BTreeMap<String, Vec<Node<'_>>> = BTreeMap::new();
        for arm in arms {
            let body = child_by_field_name(arm, "body")
                .or_else(|| arm.named_child(arm.named_child_count().saturating_sub(1)));
            let Some(body) = body else {
                continue;
            };
            let normalized = collapse_whitespace(ctx.tree.text_for_node(body));
            if normalized.len() < 8 {
                continue;
            }
            by_body.entry(normalized).or_default().push(body);
        }
        for group in by_body.into_values().filter(|group| group.len() > 1) {
            let mut metadata = BTreeMap::new();
            metadata.insert("arms".to_string(), json!(group.len()));
            findings.push(rust_finding(
                ctx,
                RUST_REPEATED_MATCH_ARM_BODY,
                ctx.tree.span_for_node(group[0]),
                format!("{} Rust match arms share the same body.", group.len()),
                "Merge equivalent patterns with `|` or extract the repeated body into a helper when appropriate."
                    .to_string(),
                "A match expression contains more than one arm with the same normalized body."
                    .to_string(),
                metadata,
            ));
        }
    });
    findings
}

fn suspicious_unwrap_policy(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let max_unwraps = ctx
        .config
        .options_for(RUST_SUSPICIOUS_UNWRAP_POLICY)
        .max_unwraps
        .unwrap_or(ctx.config.rust_max_unwraps);
    current_functions(ctx)
        .into_iter()
        .filter(|function| function.unwrap_calls + function.expect_calls > max_unwraps)
        .map(|function| {
            let mut metadata = function_metadata(&function);
            metadata.insert(
                "unwrap_like_calls".to_string(),
                json!(function.unwrap_calls + function.expect_calls),
            );
            metadata.insert("max_unwraps".to_string(), json!(max_unwraps));
            rust_finding(
                ctx,
                RUST_SUSPICIOUS_UNWRAP_POLICY,
                function.body_span,
                format!(
                    "Rust function '{}' has {} unwrap/expect calls.",
                    function.qualified_name,
                    function.unwrap_calls + function.expect_calls
                ),
                "Prefer propagating errors, handling None/Err explicitly, or using one justified expect at a boundary."
                    .to_string(),
                "The function body contains repeated unwrap or expect calls beyond the configured threshold."
                    .to_string(),
                metadata,
            )
        })
        .collect()
}

fn expect_without_context(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for function in current_functions(ctx) {
        for (offset, message) in generic_expect_messages(&function.source) {
            let span = span_for_body_offset(ctx, function.body_span, offset, ".expect(".len());
            let mut metadata = function_metadata(&function);
            metadata.insert("expect_message".to_string(), json!(message));
            findings.push(rust_finding(
                ctx,
                RUST_EXPECT_WITHOUT_CONTEXT,
                span,
                format!(
                    "Rust function '{}' has an expect call without useful context.",
                    function.qualified_name
                ),
                "Use an expect message that names the invariant, input, or boundary that makes failure unexpected."
                    .to_string(),
                "The expect message is empty, very short, or a generic failure word.".to_string(),
                metadata,
            ));
        }
    }
    findings
}

fn repeated_error_mapping(ctx: &RuleContext<'_>) -> Vec<Finding> {
    repeated_snippet_rule(
        ctx,
        RUST_REPEATED_ERROR_MAPPING,
        ".map_err(",
        |snippet| snippet.contains("map_err"),
        "Rust code repeats the same error mapping closure.",
        "Extract a shared From/Into implementation or small error conversion helper if the mapping is part of the domain boundary.",
        "map_err closures were grouped by normalized source text.",
    )
}

fn manual_option_result_pattern_candidate(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "match_expression" {
            return;
        }
        let text = ctx.tree.text_for_node(node);
        let option_like = text.contains("Some(") && text.contains("None");
        let result_like = text.contains("Ok(") && text.contains("Err(");
        if !(option_like || result_like) || text.lines().count() > 8 {
            return;
        }
        findings.push(rust_finding(
            ctx,
            RUST_MANUAL_OPTION_RESULT_PATTERN_CANDIDATE,
            ctx.tree.span_for_node(node),
            "Manual Rust Result/Option match may have an idiomatic combinator.".to_string(),
            "Consider `map`, `and_then`, `unwrap_or`, `ok_or`, or `?` if it keeps the intent clearer."
                .to_string(),
            "A small match expression handles Result/Option variants manually.".to_string(),
            BTreeMap::new(),
        ));
    });
    findings
}

fn deeply_nested_match(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let max_depth = ctx
        .config
        .options_for(RUST_DEEPLY_NESTED_MATCH)
        .max_depth
        .unwrap_or_else(|| ctx.config.rust_max_match_depth.max(1));
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "match_expression" {
            return;
        }
        let depth = nested_match_depth(node);
        if depth <= max_depth {
            return;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("match_depth".to_string(), json!(depth));
        metadata.insert("max_depth".to_string(), json!(max_depth));
        findings.push(rust_finding(
            ctx,
            RUST_DEEPLY_NESTED_MATCH,
            ctx.tree.span_for_node(node),
            format!("Rust match expression is nested {depth} levels deep."),
            "Extract nested matching into named helpers or flatten the state handling when it improves readability."
                .to_string(),
            "Nested match expressions exceed the configured depth threshold.".to_string(),
            metadata,
        ));
    });
    findings
}

fn large_enum_variant_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let max_fields = ctx
        .config
        .options_for(RUST_LARGE_ENUM_VARIANT_LOGIC)
        .max_params
        .unwrap_or(6);
    current_enums(ctx)
        .into_iter()
        .filter_map(|enum_model| {
            largest_enum_variant(&enum_model.source).and_then(|(variant, fields)| {
                (fields > max_fields).then(|| {
                    let mut metadata = BTreeMap::new();
                    metadata.insert("enum_name".to_string(), json!(enum_model.name));
                    metadata.insert("variant".to_string(), json!(variant));
                    metadata.insert("field_count".to_string(), json!(fields));
                    metadata.insert("max_fields".to_string(), json!(max_fields));
                    rust_finding(
                        ctx,
                        RUST_LARGE_ENUM_VARIANT_LOGIC,
                        enum_model.span,
                        format!(
                            "Rust enum '{}' has a large variant payload.",
                            enum_model.name
                        ),
                        "Move the payload into a named struct or box large variants when that clarifies API and layout tradeoffs."
                            .to_string(),
                        "An enum variant has more fields than the configured threshold."
                            .to_string(),
                        metadata,
                    )
                })
            })
        })
        .collect()
}

fn repeated_result_handling(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let min_nodes = ctx
        .config
        .options_for(RUST_REPEATED_RESULT_HANDLING)
        .min_nodes
        .unwrap_or(2);
    let mut groups: BTreeMap<String, Vec<Span>> = BTreeMap::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "match_expression" {
            return;
        }
        let text = ctx.tree.text_for_node(node);
        if text.contains("Ok(") && text.contains("Err(") && text.lines().count() <= 12 {
            groups
                .entry(normalize_pattern_text(text))
                .or_default()
                .push(ctx.tree.span_for_node(node));
        }
    });
    snippet_group_findings(
        ctx,
        RUST_REPEATED_RESULT_HANDLING,
        groups,
        min_nodes,
        "Rust code repeats the same Result handling pattern.",
        "Extract a helper, use `?`, or use Result combinators if that keeps the happy path clearer.",
        "Small Ok/Err match expressions were grouped by normalized source shape.",
    )
}

fn repeated_conversion_function(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    duplicate_function_group_rule(
        ctx,
        RUST_REPEATED_CONVERSION_FUNCTION,
        |function| {
            conversion_name(&function.name)
                && function.lines_of_code
                    >= function
                        .structural_hash
                        .as_ref()
                        .map(|_| 1)
                        .unwrap_or(usize::MAX)
        },
        "Rust conversion functions share duplicated logic.",
        "Extract shared conversion steps or implement From/TryFrom where the API relationship is intentional.",
        "Conversion-like functions were grouped by structural body fingerprint.",
    )
}

fn repeated_validation_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    repeated_snippet_rule(
        ctx,
        RUST_REPEATED_VALIDATION_LOGIC,
        "return Err(",
        |snippet| snippet.contains("if ") || snippet.contains("return Err("),
        "Rust code repeats validation-and-error-return logic.",
        "Extract a named validator or shared error constructor when the validation rule is the same domain rule.",
        "Validation snippets ending in Err returns were grouped by normalized source text.",
    )
}

fn repeated_serde_glue(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    duplicate_function_group_rule(
        ctx,
        RUST_REPEATED_SERDE_GLUE,
        |function| {
            let lower = function.source.to_ascii_lowercase();
            lower.contains("serialize")
                || lower.contains("deserialize")
                || lower.contains("serde")
                || function
                    .attributes
                    .iter()
                    .any(|attribute| attribute.contains("serde"))
        },
        "Rust serialization/deserialization helpers share duplicated logic.",
        "Centralize repeated serde glue behind a helper or derive/custom serializer boundary when appropriate.",
        "Serde-like functions were grouped by structural body fingerprint.",
    )
}

fn rust_allowed(ctx: &RuleContext<'_>) -> bool {
    ctx.config.rust_enabled && ctx.source_file.language.name.eq_ignore_ascii_case("rust")
}

fn current_functions(ctx: &RuleContext<'_>) -> Vec<RustFunctionModel> {
    all_functions(ctx)
        .into_iter()
        .filter(|function| function.file == ctx.source_file.path)
        .collect()
}

fn all_functions(ctx: &RuleContext<'_>) -> Vec<RustFunctionModel> {
    ctx.symbols
        .map(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| {
                    definition.language == Language::Rust
                        && matches!(
                            definition.kind,
                            DefinitionKind::Function | DefinitionKind::Method
                        )
                })
                .filter_map(|definition| function_from_definition(ctx, definition))
                .collect()
        })
        .unwrap_or_default()
}

fn function_from_definition(
    ctx: &RuleContext<'_>,
    definition: &Definition,
) -> Option<RustFunctionModel> {
    let body_span = definition.body_span.unwrap_or(definition.span);
    let file_source = source_for_definition(ctx, definition)?;
    let source = slice_span(&file_source, body_span).to_string();
    let calls = definition_calls(ctx, definition);
    let macro_calls = calls
        .iter()
        .filter(|call| call.ends_with('!') || call.contains("!"))
        .cloned()
        .collect::<Vec<_>>();
    Some(RustFunctionModel {
        name: definition.name.clone(),
        qualified_name: definition.qualified_name.clone(),
        kind: definition.kind,
        file: definition.file.clone(),
        span: definition.span,
        body_span,
        visibility: definition.visibility.clone(),
        attributes: definition
            .attributes
            .iter()
            .map(|attribute| attribute.name.clone())
            .collect(),
        parameters: definition
            .signature
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .collect(),
        lines_of_code: source.lines().count().max(1),
        token_count: source.split_whitespace().count(),
        structural_hash: definition
            .structural_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.stable_hash_hex.clone()),
        impl_context: (definition.kind == DefinitionKind::Method)
            .then(|| impl_context_for_method(&file_source, definition.span.start))
            .flatten(),
        unsafe_blocks: source.matches("unsafe {").count(),
        unwrap_calls: source.matches(".unwrap()").count(),
        expect_calls: source.matches(".expect(").count(),
        source,
        calls,
        macro_calls,
    })
}

fn source_for_definition(ctx: &RuleContext<'_>, definition: &Definition) -> Option<String> {
    if definition.file == ctx.source_file.path {
        Some(ctx.source_file.source.clone())
    } else {
        fs::read_to_string(&definition.file).ok()
    }
}

fn definition_calls(ctx: &RuleContext<'_>, definition: &Definition) -> Vec<String> {
    let mut calls = BTreeSet::new();
    if let Some(symbols) = ctx.symbols {
        for call in &symbols.call_sites {
            if call.language == Language::Rust
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

fn current_enums(ctx: &RuleContext<'_>) -> Vec<RustEnumModel> {
    ctx.symbols
        .map(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| {
                    definition.language == Language::Rust
                        && definition.kind == DefinitionKind::RustEnum
                        && definition.file == ctx.source_file.path
                })
                .filter_map(|definition| {
                    let source = source_for_definition(ctx, definition)?;
                    Some(RustEnumModel {
                        name: definition.name.clone(),
                        file: definition.file.clone(),
                        span: definition.span,
                        source: slice_span(&source, definition.span).to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn duplicate_function_group_rule(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    predicate: impl Fn(&RustFunctionModel) -> bool,
    message: &str,
    remediation: &str,
    detection_reason: &str,
) -> Vec<Finding> {
    let options = ctx.config.options_for(rule_id);
    let min_lines = options.min_lines.unwrap_or(3);
    let min_tokens = options.min_tokens.unwrap_or(20);
    let mut groups: BTreeMap<String, Vec<RustFunctionModel>> = BTreeMap::new();
    for function in all_functions(ctx) {
        if !predicate(&function)
            || function.lines_of_code < min_lines
            || function.token_count < min_tokens
            || function.macro_heavy()
        {
            continue;
        }
        if let Some(hash) = &function.structural_hash {
            groups.entry(hash.clone()).or_default().push(function);
        }
    }
    grouped_function_findings(ctx, rule_id, groups, message, remediation, detection_reason)
}

fn grouped_function_findings(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    groups: BTreeMap<String, Vec<RustFunctionModel>>,
    message: &str,
    remediation: &str,
    detection_reason: &str,
) -> Vec<Finding> {
    groups
        .into_iter()
        .filter(|(_, group)| group.len() > 1)
        .filter_map(|(hash, mut group)| {
            sort_functions(&mut group);
            if group[0].file != ctx.source_file.path {
                return None;
            }
            let mut metadata = function_metadata(&group[0]);
            metadata.insert("canonical_hash".to_string(), json!(hash));
            metadata.insert("functions".to_string(), json!(group.len()));
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

fn repeated_snippet_rule(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    marker: &str,
    accepts: impl Fn(&str) -> bool,
    message: &str,
    remediation: &str,
    detection_reason: &str,
) -> Vec<Finding> {
    if !rust_allowed(ctx) {
        return Vec::new();
    }
    let min_nodes = ctx.config.options_for(rule_id).min_nodes.unwrap_or(2);
    let mut groups: BTreeMap<String, Vec<Span>> = BTreeMap::new();
    for (offset, snippet) in snippets_around_marker(&ctx.source_file.source, marker) {
        if !accepts(&snippet) {
            continue;
        }
        groups
            .entry(normalize_pattern_text(&snippet))
            .or_default()
            .push(codehealth_parser::span_for_offsets(
                &ctx.source_file.source,
                offset,
                (offset + snippet.len()).min(ctx.source_file.source.len()),
            ));
    }
    snippet_group_findings(
        ctx,
        rule_id,
        groups,
        min_nodes,
        message,
        remediation,
        detection_reason,
    )
}

fn snippet_group_findings(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    groups: BTreeMap<String, Vec<Span>>,
    min_nodes: usize,
    message: &str,
    remediation: &str,
    detection_reason: &str,
) -> Vec<Finding> {
    groups
        .into_iter()
        .filter(|(_, spans)| spans.len() >= min_nodes)
        .map(|(key, spans)| {
            let mut metadata = BTreeMap::new();
            metadata.insert("canonical_hash".to_string(), json!(stable_hash(&key)));
            metadata.insert("occurrences".to_string(), json!(spans.len()));
            let locations = spans
                .iter()
                .map(|span| location(ctx.source_file.path.clone(), *span))
                .collect::<Vec<_>>();
            rust_multi_location_finding(
                ctx,
                rule_id,
                locations,
                format!("{} {} occurrences.", message, spans.len()),
                remediation.to_string(),
                detection_reason.to_string(),
                metadata,
            )
        })
        .collect()
}

fn rust_finding(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    span: Span,
    message: String,
    remediation: String,
    detection_reason: String,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    rust_multi_location_finding(
        ctx,
        rule_id,
        vec![location(ctx.source_file.path.clone(), span)],
        message,
        remediation,
        detection_reason,
        metadata,
    )
}

fn group_finding(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    group: &[RustFunctionModel],
    message: String,
    remediation: String,
    detection_reason: String,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    let locations = group
        .iter()
        .map(|function| location(function.file.clone(), function.span))
        .collect::<Vec<_>>();
    rust_multi_location_finding(
        ctx,
        rule_id,
        locations,
        message,
        remediation,
        detection_reason,
        metadata,
    )
}

fn rust_multi_location_finding(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    locations: Vec<FindingLocation>,
    message: String,
    remediation: String,
    detection_reason: String,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    let metadata_rule = find_rule(rule_id);
    let stable = stable_hash(&format!(
        "{rule_id}|{}|{}",
        locations
            .iter()
            .map(|location| {
                format!(
                    "{}:{}",
                    normalize_path(ctx.root, &location.path),
                    location.start.map(|start| start.line).unwrap_or(0)
                )
            })
            .collect::<Vec<_>>()
            .join("|"),
        collapse_whitespace(&message)
    ));
    Finding {
        finding_id: format!("{rule_id}:{}", &stable[..12]),
        baseline_key: stable,
        rule_id: rule_id.to_string(),
        kind: FindingKind::Rust,
        severity: metadata_rule
            .as_ref()
            .map(|rule| rule.default_severity)
            .unwrap_or(Severity::Medium),
        confidence: metadata_rule
            .as_ref()
            .map(|rule| rule.default_confidence)
            .unwrap_or(Confidence::Medium),
        message,
        locations,
        language: Some("rust".to_string()),
        framework: None,
        explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.explanation)
            .unwrap_or("Rust health rule finding.")
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
        language: Some("rust".to_string()),
    }
}

fn function_metadata(function: &RustFunctionModel) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = BTreeMap::new();
    metadata.insert("function".to_string(), json!(function.qualified_name));
    metadata.insert("kind".to_string(), json!(function.kind.label()));
    metadata.insert("visibility".to_string(), json!(function.visibility.label()));
    metadata.insert("attributes".to_string(), json!(function.attributes));
    metadata.insert("parameters".to_string(), json!(function.parameters));
    metadata.insert("lines".to_string(), json!(function.lines_of_code));
    metadata.insert("tokens".to_string(), json!(function.token_count));
    metadata.insert("calls".to_string(), json!(function.calls));
    metadata.insert("macro_calls".to_string(), json!(function.macro_calls));
    metadata.insert("unsafe_blocks".to_string(), json!(function.unsafe_blocks));
    metadata.insert("unwrap_calls".to_string(), json!(function.unwrap_calls));
    metadata.insert("expect_calls".to_string(), json!(function.expect_calls));
    if let Some(context) = &function.impl_context {
        metadata.insert("impl_target".to_string(), json!(context.target_type));
        metadata.insert("impl_trait".to_string(), json!(context.trait_name));
    }
    metadata
}

fn effective_parameter_count(function: &RustFunctionModel) -> usize {
    function
        .parameters
        .iter()
        .filter(|parameter| {
            let parameter = parameter.trim();
            !matches!(parameter, "self" | "&self" | "&mut self" | "mut self")
        })
        .count()
}

impl RustFunctionModel {
    fn macro_heavy(&self) -> bool {
        self.source.contains("macro_rules!") || self.macro_calls.len() > 2
    }
}

fn impl_context_for_method(source: &str, method_start: usize) -> Option<RustImplContext> {
    let prefix = &source[..method_start.min(source.len())];
    let impl_index = prefix.rfind("impl ")?;
    let header = source[impl_index..method_start.min(source.len())]
        .split('{')
        .next()?
        .trim();
    parse_impl_context(header)
}

fn parse_impl_context(header: &str) -> Option<RustImplContext> {
    let header = header.strip_prefix("impl")?.trim();
    let header = strip_leading_generics(header);
    if let Some((trait_name, target_type)) = header.split_once(" for ") {
        Some(RustImplContext {
            target_type: collapse_whitespace(target_type.trim()),
            trait_name: Some(collapse_whitespace(trait_name.trim())),
        })
    } else {
        Some(RustImplContext {
            target_type: collapse_whitespace(header.trim()),
            trait_name: None,
        })
    }
}

fn strip_leading_generics(value: &str) -> &str {
    let value = value.trim();
    if !value.starts_with('<') {
        return value;
    }
    value
        .split_once('>')
        .map(|(_, rest)| rest.trim())
        .unwrap_or(value)
}

fn sort_functions(functions: &mut [RustFunctionModel]) {
    functions.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.start.cmp(&right.span.start))
            .then_with(|| left.qualified_name.cmp(&right.qualified_name))
    });
}

fn generic_expect_messages(source: &str) -> Vec<(usize, String)> {
    let mut messages = Vec::new();
    for (index, _) in source.match_indices(".expect(") {
        let Some((message, _quote)) = first_string_argument(&source[index..]) else {
            continue;
        };
        let lowered = message.to_ascii_lowercase();
        if message.trim().len() < 12
            || matches!(
                lowered.trim(),
                "" | "todo" | "fixme" | "failed" | "error" | "invalid" | "unwrap"
            )
        {
            messages.push((index, message));
        }
    }
    messages
}

fn first_string_argument(text: &str) -> Option<(String, char)> {
    for quote in ['"', '\''] {
        let Some(start) = text.find(quote) else {
            continue;
        };
        let rest = &text[start + 1..];
        let Some(end) = rest.find(quote) else {
            continue;
        };
        return Some((rest[..end].to_string(), quote));
    }
    None
}

fn span_for_body_offset(ctx: &RuleContext<'_>, body_span: Span, offset: usize, len: usize) -> Span {
    codehealth_parser::span_for_offsets(
        &ctx.source_file.source,
        body_span.start + offset,
        (body_span.start + offset + len).min(ctx.source_file.source.len()),
    )
}

fn nested_match_depth(node: Node<'_>) -> usize {
    if node.kind() != "match_expression" {
        return named_children(node)
            .into_iter()
            .map(nested_match_depth)
            .max()
            .unwrap_or(0);
    }
    1 + named_children(node)
        .into_iter()
        .map(nested_match_depth)
        .max()
        .unwrap_or(0)
}

fn largest_enum_variant(source: &str) -> Option<(String, usize)> {
    let body = source.split_once('{')?.1.rsplit_once('}')?.0;
    let mut largest: Option<(String, usize)> = None;
    for raw in body.lines() {
        let line = raw.trim().trim_end_matches(',');
        if line.is_empty() || line.starts_with("#[") || line.starts_with("//") {
            continue;
        }
        let name = line
            .split(['(', '{', '='])
            .next()
            .unwrap_or(line)
            .trim()
            .to_string();
        if name.is_empty() || !is_identifier(&name) {
            continue;
        }
        let field_count = if let Some(fields) = extract_between(line, '(', ')') {
            split_nonempty(&fields, ',').len()
        } else if let Some(fields) = extract_between(line, '{', '}') {
            split_nonempty(&fields, ',')
                .into_iter()
                .filter(|field| field.contains(':'))
                .count()
        } else {
            0
        };
        if largest
            .as_ref()
            .map(|(_, count)| field_count > *count)
            .unwrap_or(true)
        {
            largest = Some((name, field_count));
        }
    }
    largest
}

fn snippets_around_marker(source: &str, marker: &str) -> Vec<(usize, String)> {
    let mut snippets = Vec::new();
    for (index, _) in source.match_indices(marker) {
        let start = source[..index]
            .rfind('\n')
            .map(|value| value + 1)
            .unwrap_or(0);
        let rest = &source[index..];
        let end = rest
            .find('\n')
            .map(|value| index + value)
            .unwrap_or(source.len());
        let line = source[start..end].trim().to_string();
        if !line.is_empty() {
            snippets.push((start, line));
        }
    }
    snippets
}

fn conversion_name(name: &str) -> bool {
    name.starts_with("from_")
        || name.starts_with("to_")
        || name.starts_with("into_")
        || name.starts_with("as_")
        || matches!(name, "from" | "into")
}

fn normalize_pattern_text(value: &str) -> String {
    collapse_whitespace(value)
        .split_whitespace()
        .map(|part| {
            let core = part.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
            if core.len() > 1
                && core
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                && !matches!(core, "Ok" | "Err" | "Some" | "None" | "return" | "match")
            {
                part.replacen(core, "_", 1)
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn walk(node: Node<'_>, visitor: &mut impl FnMut(Node<'_>)) {
    visitor(node);
    for child in named_children(node) {
        walk(child, visitor);
    }
}

fn descendants_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut output = Vec::new();
    collect_descendants_of_kind(node, kind, &mut output);
    output
}

fn collect_descendants_of_kind<'tree>(
    node: Node<'tree>,
    kind: &str,
    output: &mut Vec<Node<'tree>>,
) {
    if node.kind() == kind {
        output.push(node);
    }
    for child in named_children(node) {
        collect_descendants_of_kind(child, kind, output);
    }
}

fn extract_between(text: &str, start: char, end: char) -> Option<String> {
    let start_index = text.find(start)?;
    let rest = &text[start_index + start.len_utf8()..];
    let end_index = rest.rfind(end)?;
    Some(rest[..end_index].trim().to_string())
}

fn split_nonempty(value: &str, separator: char) -> Vec<&str> {
    value
        .split(separator)
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
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

fn normalize_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn stable_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
}
