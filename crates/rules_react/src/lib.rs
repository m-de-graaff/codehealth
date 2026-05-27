use codehealth_core::{
    AutofixSafety, Confidence, Edit, Finding, FindingKind, FindingLocation, Fix, FixApplicability,
    Location, Severity, SourceSpan,
};
use codehealth_parser::{named_children, span_for_offsets, Span};
use codehealth_rules::{
    find_rule, Rule, RuleContext, RuleMetadata, REACT_COMPONENT_TOO_MANY_RESPONSIBILITIES,
    REACT_DEEPLY_NESTED_JSX, REACT_DERIVED_STATE_CANDIDATE, REACT_DUPLICATE_COMPONENT_SHAPE,
    REACT_INLINE_COMPONENT_INSIDE_RENDER, REACT_LARGE_COMPONENT, REACT_LARGE_CONTEXT_PROVIDER,
    REACT_MISSING_KEY, REACT_MIXED_DATA_FETCHING_AND_RENDERING, REACT_PROP_DRILLING_CANDIDATE,
    REACT_REDUNDANT_FRAGMENT, REACT_REPEATED_HOOK_LOGIC, REACT_TOO_MANY_PROPS,
    REACT_UNNECESSARY_EFFECT_CANDIDATE, REACT_UNSTABLE_LIST_KEY,
};
use codehealth_symbols::{Definition, DefinitionKind, FrameworkTag};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tree_sitter::Node;

pub const REACT_RULE_NAMESPACE: &str = "react";

type RuleRunner = fn(&RuleContext<'_>) -> Vec<Finding>;

pub fn finding_kind() -> FindingKind {
    FindingKind::React
}

pub fn react_rules() -> Vec<Box<dyn Rule>> {
    vec![
        boxed(REACT_LARGE_COMPONENT, large_component),
        boxed(REACT_TOO_MANY_PROPS, too_many_props),
        boxed(REACT_DEEPLY_NESTED_JSX, deeply_nested_jsx),
        boxed(REACT_DUPLICATE_COMPONENT_SHAPE, duplicate_component_shape),
        boxed(REACT_REPEATED_HOOK_LOGIC, repeated_hook_logic),
        boxed(
            REACT_UNNECESSARY_EFFECT_CANDIDATE,
            unnecessary_effect_candidate,
        ),
        boxed(REACT_DERIVED_STATE_CANDIDATE, derived_state_candidate),
        boxed(
            REACT_INLINE_COMPONENT_INSIDE_RENDER,
            inline_component_inside_render,
        ),
        boxed(REACT_UNSTABLE_LIST_KEY, unstable_list_key),
        boxed(REACT_MISSING_KEY, missing_key),
        boxed(REACT_PROP_DRILLING_CANDIDATE, prop_drilling_candidate),
        boxed(REACT_LARGE_CONTEXT_PROVIDER, large_context_provider),
        boxed(
            REACT_MIXED_DATA_FETCHING_AND_RENDERING,
            mixed_data_fetching_and_rendering,
        ),
        boxed(
            REACT_COMPONENT_TOO_MANY_RESPONSIBILITIES,
            component_too_many_responsibilities,
        ),
        boxed(REACT_REDUNDANT_FRAGMENT, redundant_fragment),
    ]
}

fn boxed(rule_id: &'static str, runner: RuleRunner) -> Box<dyn Rule> {
    Box::new(BuiltinReactRule { rule_id, runner })
}

struct BuiltinReactRule {
    rule_id: &'static str,
    runner: RuleRunner,
}

impl Rule for BuiltinReactRule {
    fn id(&self) -> &'static str {
        self.rule_id
    }

    fn metadata(&self) -> RuleMetadata {
        find_rule(self.rule_id).expect("built-in React rule exists in catalog")
    }

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        (self.runner)(ctx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactComponentModel {
    pub name: String,
    pub qualified_name: String,
    pub file: PathBuf,
    pub span: Span,
    pub body_span: Span,
    pub props: Vec<String>,
    pub state_hooks: usize,
    pub effects: usize,
    pub context_usage: usize,
    pub child_components: Vec<String>,
    pub jsx_element_count: usize,
    pub lines_of_code: usize,
    pub cyclomatic_complexity: usize,
    pub event_handlers: Vec<String>,
    pub external_calls: Vec<String>,
    pub jsx_depth: usize,
    pub shape_hash: Option<String>,
    pub hook_logic_hash: Option<String>,
    pub responsibility_score: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReactComponentGraph {
    pub components: Vec<ReactComponentModel>,
    pub edges: Vec<ReactComponentEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactComponentEdge {
    pub parent: String,
    pub child: String,
    pub file: PathBuf,
}

pub fn component_graph(ctx: &RuleContext<'_>) -> ReactComponentGraph {
    let components = all_component_models(ctx);
    let names = components
        .iter()
        .map(|component| component.name.clone())
        .collect::<BTreeSet<_>>();
    let mut edges = Vec::new();
    for component in &components {
        for child in &component.child_components {
            if names.contains(child) {
                edges.push(ReactComponentEdge {
                    parent: component.qualified_name.clone(),
                    child: child.clone(),
                    file: component.file.clone(),
                });
            }
        }
    }

    ReactComponentGraph { components, edges }
}

fn large_component(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let max_lines = ctx
        .config
        .options_for(REACT_LARGE_COMPONENT)
        .max_lines
        .unwrap_or_else(|| ctx.config.react_max_component_lines.max(1));

    current_component_models(ctx)
        .into_iter()
        .filter(|component| component.lines_of_code > max_lines)
        .map(|component| {
            let mut metadata = component_metadata(&component);
            metadata.insert("max_lines".to_string(), json!(max_lines));
            react_finding(
                ctx,
                REACT_LARGE_COMPONENT,
                component.body_span,
                format!(
                    "React component '{}' is {} lines long.",
                    component.name, component.lines_of_code
                ),
                "Extract cohesive child components, hooks, or pure helpers around clear UI and data boundaries."
                    .to_string(),
                "The indexed component body exceeds the configured React component line threshold."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            )
        })
        .collect()
}

fn too_many_props(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let max_props = ctx
        .config
        .options_for(REACT_TOO_MANY_PROPS)
        .max_params
        .unwrap_or_else(|| ctx.config.react_max_props.max(1));

    current_component_models(ctx)
        .into_iter()
        .filter(|component| component.props.len() > max_props)
        .map(|component| {
            let mut metadata = component_metadata(&component);
            metadata.insert("props".to_string(), json!(component.props));
            metadata.insert("max_props".to_string(), json!(max_props));
            react_finding(
                ctx,
                REACT_TOO_MANY_PROPS,
                component.span,
                format!(
                    "React component '{}' accepts {} props.",
                    component.name,
                    metadata["props"].as_array().map_or(0, Vec::len)
                ),
                "Group related props into a model, split the component, or move repeated setup into a hook."
                    .to_string(),
                "The component signature and observed prop member access exceed the configured prop threshold."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            )
        })
        .collect()
}

fn deeply_nested_jsx(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let max_depth = ctx
        .config
        .options_for(REACT_DEEPLY_NESTED_JSX)
        .max_depth
        .unwrap_or(5);

    current_component_models(ctx)
        .into_iter()
        .filter(|component| component.jsx_depth > max_depth)
        .map(|component| {
            let mut metadata = component_metadata(&component);
            metadata.insert("max_depth".to_string(), json!(max_depth));
            react_finding(
                ctx,
                REACT_DEEPLY_NESTED_JSX,
                component.body_span,
                format!(
                    "React component '{}' has JSX nested {} levels deep.",
                    component.name, component.jsx_depth
                ),
                "Extract named child components for repeated or deeply nested regions.".to_string(),
                "The component JSX tree exceeds the configured nesting threshold.".to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            )
        })
        .collect()
}

fn duplicate_component_shape(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let min_nodes = ctx
        .config
        .options_for(REACT_DUPLICATE_COMPONENT_SHAPE)
        .min_nodes
        .unwrap_or(3);
    let mut groups: BTreeMap<String, Vec<ReactComponentModel>> = BTreeMap::new();
    for component in all_component_models(ctx) {
        if component.jsx_element_count < min_nodes {
            continue;
        }
        if let Some(hash) = &component.shape_hash {
            groups.entry(hash.clone()).or_default().push(component);
        }
    }

    groups
        .into_iter()
        .filter(|(_, group)| group.len() > 1)
        .filter_map(|(hash, mut group)| {
            group.sort_by(|left, right| {
                left.file
                    .cmp(&right.file)
                    .then_with(|| left.span.start.cmp(&right.span.start))
            });
            let primary = group.first()?.clone();
            if primary.file != ctx.source_file.path {
                return None;
            }
            let mut metadata = component_metadata(&primary);
            metadata.insert("canonical_hash".to_string(), json!(hash));
            metadata.insert("components".to_string(), json!(group.len()));
            metadata.insert(
                "component_names".to_string(),
                json!(
                    group
                        .iter()
                        .map(|component| component.qualified_name.clone())
                        .collect::<Vec<_>>()
                ),
            );
            Some(react_group_finding(
                ctx,
                REACT_DUPLICATE_COMPONENT_SHAPE,
                &group,
                format!(
                    "{} React components share a similar JSX shape.",
                    group.len()
                ),
                "Consolidate the shared JSX into a reusable component or extract the differing content into props."
                    .to_string(),
                "Component JSX trees share the same normalized element and prop shape.".to_string(),
                metadata,
            ))
        })
        .collect()
}

fn repeated_hook_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let mut groups: BTreeMap<String, Vec<ReactComponentModel>> = BTreeMap::new();
    for component in all_component_models(ctx) {
        if let Some(hash) = &component.hook_logic_hash {
            groups.entry(hash.clone()).or_default().push(component);
        }
    }

    groups
        .into_iter()
        .filter(|(_, group)| group.len() > 1)
        .filter_map(|(hash, mut group)| {
            group.sort_by(|left, right| {
                left.file
                    .cmp(&right.file)
                    .then_with(|| left.span.start.cmp(&right.span.start))
            });
            let primary = group.first()?.clone();
            if primary.file != ctx.source_file.path {
                return None;
            }
            let mut metadata = component_metadata(&primary);
            metadata.insert("canonical_hash".to_string(), json!(hash));
            metadata.insert("components".to_string(), json!(group.len()));
            Some(react_group_finding(
                ctx,
                REACT_REPEATED_HOOK_LOGIC,
                &group,
                format!(
                    "{} React components repeat the same hook sequence.",
                    group.len()
                ),
                "Extract the repeated state/effect/context sequence into a custom hook when the behavior is shared."
                    .to_string(),
                "Components or hooks share the same normalized hook call sequence.".to_string(),
                metadata,
            ))
        })
        .collect()
}

fn unnecessary_effect_candidate(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    current_component_models(ctx)
        .into_iter()
        .filter(|component| component.effects > 0)
        .filter(|component| {
            let text = component_source(ctx, component);
            text.contains("useEffect(") && setter_like_count(&text) > 0
        })
        .map(|component| {
            react_finding(
                ctx,
                REACT_UNNECESSARY_EFFECT_CANDIDATE,
                component.body_span,
                format!(
                    "React component '{}' may derive state inside an effect.",
                    component.name
                ),
                "Prefer deriving values during render or memoizing expensive derivations instead of syncing state in an effect."
                    .to_string(),
                "The component has a useEffect body that appears to call a state setter."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                component_metadata(&component),
            )
        })
        .collect()
}

fn derived_state_candidate(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    current_component_models(ctx)
        .into_iter()
        .filter(|component| component.state_hooks > 0 && component.effects > 0)
        .filter(|component| setter_like_count(&component_source(ctx, component)) > 0)
        .map(|component| {
            react_finding(
                ctx,
                REACT_DERIVED_STATE_CANDIDATE,
                component.body_span,
                format!(
                    "React component '{}' has state/effect coupling that may be derived state.",
                    component.name
                ),
                "Replace synchronized local state with a derived value where the state is fully determined by props or other state."
                    .to_string(),
                "The component combines useState, useEffect, and setter calls in the same body."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                component_metadata(&component),
            )
        })
        .collect()
}

fn inline_component_inside_render(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let Some(symbols) = ctx.symbols else {
        return Vec::new();
    };
    let components = current_component_models(ctx);
    let mut findings = Vec::new();

    for parent in components {
        for definition in &symbols.definitions {
            if definition.file != ctx.source_file.path
                || definition.kind != DefinitionKind::ReactComponent
                || definition.span == parent.span
            {
                continue;
            }
            if definition.span.start > parent.body_span.start
                && definition.span.end < parent.body_span.end
            {
                let mut metadata = component_metadata(&parent);
                metadata.insert(
                    "inline_component".to_string(),
                    json!(definition.qualified_name),
                );
                findings.push(react_finding(
                    ctx,
                    REACT_INLINE_COMPONENT_INSIDE_RENDER,
                    definition.span,
                    format!(
                        "React component '{}' is declared inside '{}'.",
                        definition.name, parent.name
                    ),
                    "Move the nested component to module scope or extract the render branch into a stable child component."
                        .to_string(),
                    "A React component definition is nested inside another component body.".to_string(),
                    AutofixSafety::SuggestionOnly,
                    Vec::new(),
                    metadata,
                ));
            }
        }
    }

    findings
}

fn unstable_list_key(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for pattern in [
        "key={index}",
        "key={i}",
        "key={idx}",
        "key={Math.random()}",
        "key={Date.now()}",
    ] {
        findings.extend(pattern_spans(&ctx.source_file.source, pattern).into_iter().map(
            |span| {
                let mut metadata = BTreeMap::new();
                metadata.insert("key_expression".to_string(), json!(pattern));
                react_finding(
                    ctx,
                    REACT_UNSTABLE_LIST_KEY,
                    span,
                    "React list key appears unstable.".to_string(),
                    "Use a stable item identity such as a database id, slug, or durable composite key."
                        .to_string(),
                    "A JSX key prop uses an array index or runtime-generated value.".to_string(),
                    AutofixSafety::SuggestionOnly,
                    Vec::new(),
                    metadata,
                )
            },
        ));
    }

    findings
}

fn missing_key(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for map_span in map_callback_spans(&ctx.source_file.source) {
        let callback = slice_span(&ctx.source_file.source, map_span);
        if !callback.contains('<') || callback.contains("key=") {
            continue;
        }
        findings.push(react_finding(
            ctx,
            REACT_MISSING_KEY,
            map_span,
            "JSX returned from an array map appears to be missing a key prop.".to_string(),
            "Add a stable key to the outer element returned by the map callback.".to_string(),
            "A .map callback contains JSX but no key prop in the callback text.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            BTreeMap::new(),
        ));
    }

    findings
}

fn prop_drilling_candidate(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let threshold = ctx
        .config
        .options_for(REACT_PROP_DRILLING_CANDIDATE)
        .max_depth
        .unwrap_or_else(|| ctx.config.react_prop_drilling_depth.max(1));

    current_component_models(ctx)
        .into_iter()
        .filter_map(|component| {
            let source = component_source(ctx, &component);
            let forwarded = forwarded_props(&source);
            let repeated = forwarded
                .iter()
                .filter(|(_, count)| **count >= threshold)
                .collect::<Vec<_>>();
            if repeated.is_empty() {
                return None;
            }
            let mut metadata = component_metadata(&component);
            metadata.insert(
                "forwarded_props".to_string(),
                json!(
                    repeated
                        .iter()
                        .map(|(name, count)| json!({ "name": name, "occurrences": count }))
                        .collect::<Vec<_>>()
                ),
            );
            Some(react_finding(
                ctx,
                REACT_PROP_DRILLING_CANDIDATE,
                component.body_span,
                format!(
                    "React component '{}' forwards props repeatedly through child components.",
                    component.name
                ),
                "Consider extracting a container component, context, or a custom hook if the forwarded props represent shared workflow state."
                    .to_string(),
                "The same prop names are passed through multiple child component props without local use evidence."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            ))
        })
        .collect()
}

fn large_context_provider(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let max_values = ctx
        .config
        .options_for(REACT_LARGE_CONTEXT_PROVIDER)
        .max_context_values
        .unwrap_or(6);

    current_component_models(ctx)
        .into_iter()
        .filter_map(|component| {
            let source = component_source(ctx, &component);
            if !source.contains(".Provider") {
                return None;
            }
            let value_count = count_context_values(&source).max(component.state_hooks);
            if value_count <= max_values {
                return None;
            }
            let mut metadata = component_metadata(&component);
            metadata.insert("context_values".to_string(), json!(value_count));
            metadata.insert("max_context_values".to_string(), json!(max_values));
            Some(react_finding(
                ctx,
                REACT_LARGE_CONTEXT_PROVIDER,
                component.body_span,
                format!(
                    "React context provider '{}' appears to expose {value_count} values.",
                    component.name
                ),
                "Split unrelated context values or move workflow-specific state closer to the consuming subtree."
                    .to_string(),
                "A provider value object or state hook count exceeds the configured context size threshold."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            ))
        })
        .collect()
}

fn mixed_data_fetching_and_rendering(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    current_component_models(ctx)
        .into_iter()
        .filter(|component| {
            component.jsx_element_count >= 5 && has_data_fetching(&component_source(ctx, component))
        })
        .map(|component| {
            react_finding(
                ctx,
                REACT_MIXED_DATA_FETCHING_AND_RENDERING,
                component.body_span,
                format!(
                    "React component '{}' mixes data access with substantial rendering.",
                    component.name
                ),
                "Move data loading into a route loader, query hook, or container boundary so the component can focus on rendering state."
                    .to_string(),
                "The component contains data-fetching call patterns and a non-trivial JSX tree."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                component_metadata(&component),
            )
        })
        .collect()
}

fn component_too_many_responsibilities(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let max_responsibilities = ctx
        .config
        .options_for(REACT_COMPONENT_TOO_MANY_RESPONSIBILITIES)
        .max_responsibilities
        .unwrap_or(5);

    current_component_models(ctx)
        .into_iter()
        .filter(|component| component.responsibility_score > max_responsibilities)
        .map(|component| {
            let mut metadata = component_metadata(&component);
            metadata.insert(
                "max_responsibilities".to_string(),
                json!(max_responsibilities),
            );
            react_finding(
                ctx,
                REACT_COMPONENT_TOO_MANY_RESPONSIBILITIES,
                component.body_span,
                format!(
                    "React component '{}' combines {} responsibility signals.",
                    component.name, component.responsibility_score
                ),
                "Separate data access, event orchestration, context ownership, and dense JSX into clearer component or hook boundaries."
                    .to_string(),
                "The component combines state, effect, context, event, data, JSX, and child-component signals beyond the configured threshold."
                    .to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            )
        })
        .collect()
}

fn redundant_fragment(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !react_allowed(ctx) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "jsx_element" {
            return;
        }
        let text = ctx.tree.text_for_node(node).trim();
        if !text.starts_with("<>") || !text.ends_with("</>") || text.contains("{/*") {
            return;
        }
        let children = jsx_direct_child_nodes(node);
        if children.len() != 1 {
            return;
        }
        let child = children[0];
        let span = ctx.tree.span_for_node(node);
        let replacement = ctx.tree.text_for_node(child).trim().to_string();
        let fix = Fix {
            title: "Remove redundant fragment".to_string(),
            safety: AutofixSafety::Safe,
            applicability: FixApplicability::MachineApplicable,
            edits: vec![Edit {
                file: ctx.source_file.path.clone(),
                span: SourceSpan {
                    start: span.start,
                    end: span.end,
                },
                replacement,
            }],
        };
        findings.push(react_finding(
            ctx,
            REACT_REDUNDANT_FRAGMENT,
            span,
            "React fragment wraps a single JSX child.".to_string(),
            "Remove the fragment and return the child directly.".to_string(),
            "The fragment has exactly one JSX element child and no JSX comment.".to_string(),
            AutofixSafety::Safe,
            vec![fix],
            BTreeMap::new(),
        ));
    });

    findings
}

fn react_allowed(ctx: &RuleContext<'_>) -> bool {
    ctx.config.react_enabled
        && ctx.workspace.react.detected
        && matches!(ctx.source_file.language.name, "tsx" | "typescript")
}

fn current_component_models(ctx: &RuleContext<'_>) -> Vec<ReactComponentModel> {
    ctx.symbols
        .map(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| {
                    definition.file == ctx.source_file.path
                        && definition.kind == DefinitionKind::ReactComponent
                })
                .filter_map(|definition| model_from_definition(ctx, definition))
                .collect()
        })
        .unwrap_or_default()
}

fn all_component_models(ctx: &RuleContext<'_>) -> Vec<ReactComponentModel> {
    ctx.symbols
        .map(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| definition.kind == DefinitionKind::ReactComponent)
                .filter_map(|definition| model_from_definition(ctx, definition))
                .collect()
        })
        .unwrap_or_default()
}

fn model_from_definition(
    ctx: &RuleContext<'_>,
    definition: &Definition,
) -> Option<ReactComponentModel> {
    let body_span = definition.body_span.unwrap_or(definition.span);
    let source = source_for_definition(ctx, definition)?;
    let body_source = slice_span(&source, body_span);
    if body_source.is_empty() {
        return None;
    }
    let props = prop_names(definition, body_source);
    let child_components = child_components(definition);
    let event_handlers = event_handlers(body_source);
    let external_calls = external_calls(ctx, definition, body_source);
    let jsx_element_count = jsx_element_count(body_source);
    let jsx_depth = if definition.file == ctx.source_file.path {
        max_jsx_depth_for_span(ctx.tree.root_node(), body_span)
    } else {
        lexical_jsx_depth(body_source)
    };
    let state_hooks = hook_name_count(body_source, "useState");
    let effects = hook_name_count(body_source, "useEffect");
    let context_usage = hook_name_count(body_source, "useContext");
    let hook_logic = hook_sequence(body_source);
    let shape = canonical_jsx_shape(body_source);
    let responsibility_score = responsibility_score(ResponsibilitySignals {
        body_source,
        state_hooks,
        effects,
        context_usage,
        child_count: child_components.len(),
        event_handler_count: event_handlers.len(),
        external_call_count: external_calls.len(),
        jsx_element_count,
    });

    Some(ReactComponentModel {
        name: definition.name.clone(),
        qualified_name: definition.qualified_name.clone(),
        file: definition.file.clone(),
        span: definition.span,
        body_span,
        props,
        state_hooks,
        effects,
        context_usage,
        child_components,
        jsx_element_count,
        lines_of_code: line_count(body_source),
        cyclomatic_complexity: cyclomatic_complexity(body_source),
        event_handlers,
        external_calls,
        jsx_depth,
        shape_hash: shape
            .filter(|value| value.len() >= 8)
            .map(|value| stable_hash(&value)),
        hook_logic_hash: (hook_logic.len() >= 2).then(|| stable_hash(&hook_logic.join("|"))),
        responsibility_score,
    })
}

fn source_for_definition(ctx: &RuleContext<'_>, definition: &Definition) -> Option<String> {
    if definition.file == ctx.source_file.path {
        Some(ctx.source_file.source.clone())
    } else {
        fs::read_to_string(&definition.file).ok()
    }
}

fn component_source(ctx: &RuleContext<'_>, component: &ReactComponentModel) -> String {
    if component.file == ctx.source_file.path {
        slice_span(&ctx.source_file.source, component.body_span).to_string()
    } else {
        fs::read_to_string(&component.file)
            .ok()
            .map(|source| slice_span(&source, component.body_span).to_string())
            .unwrap_or_default()
    }
}

fn prop_names(definition: &Definition, source: &str) -> Vec<String> {
    let mut props = BTreeSet::new();
    for parameter in &definition.signature.parameters {
        let name = parameter
            .name
            .trim()
            .trim_matches(['{', '}'])
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        for part in name.split(',') {
            let part = part.trim();
            if !part.is_empty() && part != "props" {
                props.insert(part.to_string());
            }
        }
        if name == "props" {
            props.extend(member_access_names(source, "props."));
        }
    }
    props.into_iter().collect()
}

fn child_components(definition: &Definition) -> Vec<String> {
    let mut children = BTreeSet::new();
    for tag in &definition.framework_tags {
        if let FrameworkTag::ReactChildComponent(name) = tag {
            if name != &definition.name {
                children.insert(name.clone());
            }
        }
    }
    children.into_iter().collect()
}

fn external_calls(ctx: &RuleContext<'_>, definition: &Definition, source: &str) -> Vec<String> {
    let mut calls = BTreeSet::new();
    if let Some(symbols) = ctx.symbols {
        for call in &symbols.call_sites {
            if call.file != definition.file
                || call.span.start < definition.span.start
                || call.span.end > definition.span.end
            {
                continue;
            }
            if is_react_internal_call(&call.callee) {
                continue;
            }
            calls.insert(call.callee.clone());
        }
    }
    for pattern in ["fetch", "axios", "client.query", "supabase"] {
        if source.contains(pattern) {
            calls.insert(pattern.to_string());
        }
    }
    calls.into_iter().collect()
}

fn is_react_internal_call(callee: &str) -> bool {
    callee.starts_with("use")
        || callee.starts_with("set")
        || matches!(
            callee,
            "memo" | "forwardRef" | "React.memo" | "React.useMemo"
        )
}

fn component_metadata(component: &ReactComponentModel) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = BTreeMap::new();
    metadata.insert("component".to_string(), json!(component.qualified_name));
    metadata.insert("lines".to_string(), json!(component.lines_of_code));
    metadata.insert(
        "jsx_elements".to_string(),
        json!(component.jsx_element_count),
    );
    metadata.insert("jsx_depth".to_string(), json!(component.jsx_depth));
    metadata.insert("state_hooks".to_string(), json!(component.state_hooks));
    metadata.insert("effects".to_string(), json!(component.effects));
    metadata.insert("context_usage".to_string(), json!(component.context_usage));
    metadata.insert(
        "child_components".to_string(),
        json!(component.child_components),
    );
    metadata.insert(
        "event_handlers".to_string(),
        json!(component.event_handlers),
    );
    metadata.insert(
        "external_calls".to_string(),
        json!(component.external_calls),
    );
    metadata.insert(
        "complexity".to_string(),
        json!(component.cyclomatic_complexity),
    );
    metadata.insert(
        "responsibility_score".to_string(),
        json!(component.responsibility_score),
    );
    if let Some(hash) = &component.shape_hash {
        metadata.insert("canonical_hash".to_string(), json!(hash));
    }
    metadata
}

#[allow(clippy::too_many_arguments)]
fn react_finding(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    span: Span,
    message: String,
    remediation: String,
    detection_reason: String,
    autofix: AutofixSafety,
    fixes: Vec<Fix>,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    let metadata_rule = find_rule(rule_id);
    let severity = metadata_rule
        .as_ref()
        .map(|rule| rule.default_severity)
        .unwrap_or(Severity::Medium);
    let confidence = metadata_rule
        .as_ref()
        .map(|rule| rule.default_confidence)
        .unwrap_or(Confidence::Medium);
    let explanation = metadata_rule
        .as_ref()
        .map(|rule| rule.explanation)
        .unwrap_or("React health rule finding.")
        .to_string();
    let baseline_key = react_key(ctx.root, &ctx.source_file.path, rule_id, span, &message);

    Finding {
        finding_id: format!("{rule_id}:{}", &baseline_key[..12]),
        baseline_key,
        rule_id: rule_id.to_string(),
        kind: FindingKind::React,
        severity,
        confidence,
        message,
        locations: vec![finding_location(
            ctx.source_file.path.clone(),
            span,
            ctx.source_file.language.name,
        )],
        language: Some(ctx.source_file.language.name.to_string()),
        framework: Some("react".to_string()),
        explanation,
        remediation,
        detection_reason,
        autofix,
        autofix_explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.autofix_explanation)
            .unwrap_or_default()
            .to_string(),
        fixes,
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn react_group_finding(
    ctx: &RuleContext<'_>,
    rule_id: &'static str,
    group: &[ReactComponentModel],
    message: String,
    remediation: String,
    detection_reason: String,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    let metadata_rule = find_rule(rule_id);
    let group_key = group
        .iter()
        .map(|component| {
            format!(
                "{}:{}",
                normalize_path(ctx.root, &component.file),
                component.qualified_name
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    let baseline_key = stable_hash(&format!(
        "{rule_id}|{}|{group_key}",
        metadata
            .get("canonical_hash")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
    ));

    Finding {
        finding_id: format!("{rule_id}:{}", &baseline_key[..12]),
        baseline_key,
        rule_id: rule_id.to_string(),
        kind: FindingKind::React,
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
            .map(|component| finding_location(component.file.clone(), component.span, "tsx"))
            .collect(),
        language: Some("tsx".to_string()),
        framework: Some("react".to_string()),
        explanation: metadata_rule
            .as_ref()
            .map(|rule| rule.explanation)
            .unwrap_or("React health rule finding.")
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

fn finding_location(path: PathBuf, span: Span, language: &str) -> FindingLocation {
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
        language: Some(language.to_string()),
    }
}

fn react_key(root: &Path, path: &Path, rule_id: &str, span: Span, message: &str) -> String {
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

fn walk(node: Node<'_>, visitor: &mut impl FnMut(Node<'_>)) {
    visitor(node);
    for child in named_children(node) {
        walk(child, visitor);
    }
}

fn max_jsx_depth_for_span(root: Node<'_>, span: Span) -> usize {
    let mut max_depth = 0;
    walk(root, &mut |node| {
        if !node_in_span(node, span) || !is_jsx_node(node) {
            return;
        }
        let depth = jsx_ancestor_depth(node, span);
        max_depth = max_depth.max(depth);
    });
    max_depth
}

fn node_in_span(node: Node<'_>, span: Span) -> bool {
    node.start_byte() >= span.start && node.end_byte() <= span.end
}

fn is_jsx_node(node: Node<'_>) -> bool {
    node.kind().starts_with("jsx_")
}

fn jsx_ancestor_depth(mut node: Node<'_>, span: Span) -> usize {
    let mut depth = 1;
    while let Some(parent) = node.parent() {
        if parent.start_byte() < span.start || parent.end_byte() > span.end {
            break;
        }
        if is_jsx_node(parent) {
            depth += 1;
        }
        node = parent;
    }
    depth
}

fn jsx_direct_child_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| {
            matches!(
                child.kind(),
                "jsx_element" | "jsx_self_closing_element" | "jsx_expression"
            )
        })
        .collect()
}

fn line_count(source: &str) -> usize {
    source.lines().count().max(1)
}

fn cyclomatic_complexity(source: &str) -> usize {
    1 + source.matches(" if ").count()
        + source.matches("if (").count()
        + source.matches("&&").count()
        + source.matches("||").count()
        + source.matches('?').count()
        + source.matches(".map(").count()
        + source.matches(".filter(").count()
}

fn hook_name_count(source: &str, hook: &str) -> usize {
    source.matches(&format!("{hook}(")).count() + source.matches(&format!("React.{hook}(")).count()
}

fn setter_like_count(source: &str) -> usize {
    source
        .match_indices("set")
        .filter(|(index, _)| {
            source[*index + 3..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_uppercase())
        })
        .count()
}

fn jsx_element_count(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut count = 0;
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'<'
            && bytes[index + 1].is_ascii_alphabetic()
            && !source[index..].starts_with("</")
        {
            count += 1;
        }
        index += 1;
    }
    count
}

fn lexical_jsx_depth(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut depth = 0_usize;
    let mut max_depth = 0_usize;
    while index + 1 < bytes.len() {
        if bytes[index] == b'<' {
            if bytes[index + 1] == b'/' {
                depth = depth.saturating_sub(1);
            } else if bytes[index + 1].is_ascii_alphabetic() {
                depth += 1;
                max_depth = max_depth.max(depth);
                if source[index..]
                    .find('>')
                    .map(|end| source[index..index + end].trim_end().ends_with('/'))
                    .unwrap_or(false)
                {
                    depth = depth.saturating_sub(1);
                }
            }
        }
        index += 1;
    }
    max_depth
}

fn event_handlers(source: &str) -> Vec<String> {
    let mut handlers = BTreeSet::new();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] == b'o' && bytes[index + 1] == b'n' && bytes[index + 2].is_ascii_uppercase()
        {
            let start = index;
            index += 3;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if source[index..].trim_start().starts_with('=') {
                handlers.insert(source[start..index].to_string());
            }
        }
        index += 1;
    }
    handlers.into_iter().collect()
}

fn member_access_names(source: &str, prefix: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    for (index, _) in source.match_indices(prefix) {
        let start = index + prefix.len();
        let mut end = start;
        for (offset, ch) in source[start..].char_indices() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                end = start + offset + ch.len_utf8();
            } else {
                break;
            }
        }
        if end > start {
            names.insert(source[start..end].to_string());
        }
    }
    names.into_iter().collect()
}

fn canonical_jsx_shape(source: &str) -> Option<String> {
    let mut shape = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'<' {
            let closing = bytes[index + 1] == b'/';
            let name_start = index + if closing { 2 } else { 1 };
            if name_start < bytes.len() && bytes[name_start].is_ascii_alphabetic() {
                let mut name_end = name_start;
                while name_end < bytes.len()
                    && (bytes[name_end].is_ascii_alphanumeric()
                        || matches!(bytes[name_end], b'.' | b'_'))
                {
                    name_end += 1;
                }
                let tag = &source[name_start..name_end];
                if !closing {
                    let close = source[name_end..]
                        .find('>')
                        .map(|offset| name_end + offset)
                        .unwrap_or(name_end);
                    let props = prop_shape(&source[name_end..close]);
                    shape.push(format!("<{}:{}>", normalize_tag(tag), props.join(",")));
                } else {
                    shape.push(format!("</{}>", normalize_tag(tag)));
                }
                index = name_end;
            }
        }
        index += 1;
    }

    (shape.len() >= 3).then(|| shape.join(""))
}

fn normalize_tag(tag: &str) -> &str {
    if tag
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_uppercase())
    {
        "Component"
    } else {
        tag
    }
}

fn prop_shape(source: &str) -> Vec<String> {
    let mut props = BTreeSet::new();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(bytes[index], b'_' | b'-' | b':'))
            {
                index += 1;
            }
            let name = source[start..index].trim();
            if !name.is_empty()
                && !matches!(name, "true" | "false")
                && source[index..].trim_start().starts_with('=')
            {
                props.insert(name.to_string());
            }
        }
        index += 1;
    }
    props.into_iter().collect()
}

fn hook_sequence(source: &str) -> Vec<String> {
    let mut hooks = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if source[index..].starts_with("use")
            && source[index + 3..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_uppercase())
        {
            let start = index;
            index += 3;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if source[index..].trim_start().starts_with('(') {
                hooks.push(source[start..index].to_string());
            }
        }
        index += 1;
    }
    hooks
}

fn forwarded_props(source: &str) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let name_start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let name = &source[name_start..index];
        let rest = source[index..].trim_start();
        let Some(after_equal) = rest.strip_prefix("={") else {
            continue;
        };
        let value = after_equal.split('}').next().unwrap_or_default().trim();
        if value == name || value.ends_with(&format!(".{name}")) {
            *counts.entry(name.to_string()).or_default() += 1;
        }
    }
    counts
}

fn count_context_values(source: &str) -> usize {
    let Some(value_index) = source.find("value={{") else {
        return 0;
    };
    let rest = &source[value_index + "value={{".len()..];
    let object = rest.split("}}").next().unwrap_or_default();
    object
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .count()
}

fn has_data_fetching(source: &str) -> bool {
    [
        "fetch(",
        "axios.",
        "useQuery(",
        "useSuspenseQuery(",
        "graphql",
        "supabase.",
        "client.query(",
    ]
    .iter()
    .any(|pattern| source.contains(pattern))
}

struct ResponsibilitySignals<'a> {
    body_source: &'a str,
    state_hooks: usize,
    effects: usize,
    context_usage: usize,
    child_count: usize,
    event_handler_count: usize,
    external_call_count: usize,
    jsx_element_count: usize,
}

fn responsibility_score(signals: ResponsibilitySignals<'_>) -> usize {
    let ResponsibilitySignals {
        body_source,
        state_hooks,
        effects,
        context_usage,
        child_count,
        event_handler_count,
        external_call_count,
        jsx_element_count,
    } = signals;

    usize::from(state_hooks > 1)
        + usize::from(effects > 0)
        + usize::from(context_usage > 0)
        + usize::from(child_count > 3)
        + usize::from(event_handler_count > 3)
        + usize::from(external_call_count > 1)
        + usize::from(jsx_element_count > 12)
        + usize::from(has_data_fetching(body_source))
        + usize::from(body_source.contains(".Provider"))
}

fn pattern_spans(source: &str, pattern: &str) -> Vec<Span> {
    source
        .match_indices(pattern)
        .map(|(start, _)| span_for_offsets(source, start, start + pattern.len()))
        .collect()
}

fn map_callback_spans(source: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for (index, _) in source.match_indices(".map(") {
        let start = index;
        let mut cursor = index + ".map(".len();
        let mut depth = 1_i32;
        let bytes = source.as_bytes();
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        spans.push(span_for_offsets(source, start, cursor + 1));
                        break;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
    }
    spans
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
