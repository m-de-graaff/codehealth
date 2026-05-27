use crate::{
    find_rule, PYTHON_BROAD_EXCEPTION, PYTHON_DUPLICATED_ROUTE_HANDLER_BUSINESS_LOGIC,
    PYTHON_REPEATED_VALIDATION_LOGIC, RUST_DUPLICATE_MATCH_ARM_BODY,
    RUST_MANUAL_RESULT_OPTION_PATTERN, RUST_REPEATED_UNWRAP_POLICY,
    STYLE_BOOLEAN_RETURN_SIMPLIFIABLE, STYLE_COMPLEX_CONDITION, STYLE_DUPLICATED_LITERAL,
    STYLE_EXPRESSION_ARROW_SIMPLIFIABLE, STYLE_GUARD_CLAUSE, STYLE_HIGH_PARAMETER_COUNT,
    STYLE_LARGE_FUNCTION, STYLE_NESTED_CONDITIONAL, STYLE_UNNECESSARY_ELSE_AFTER_RETURN,
};
use crate::{Rule, RuleContext, RuleMetadata};
use codehealth_core::{
    AutofixSafety, Confidence, Edit, Finding, FindingKind, FindingLocation, Fix, FixApplicability,
    Location, Severity, SourceSpan,
};
use codehealth_parser::{child_by_field_name, named_children, Span};
use codehealth_symbols::{Definition, DefinitionKind, FrameworkTag, Language};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tree_sitter::Node;

type RuleRunner = fn(&RuleContext<'_>) -> Vec<Finding>;

pub fn style_rules() -> Vec<Box<dyn Rule>> {
    vec![
        boxed(
            STYLE_BOOLEAN_RETURN_SIMPLIFIABLE,
            boolean_return_simplifiable,
        ),
        boxed(
            STYLE_EXPRESSION_ARROW_SIMPLIFIABLE,
            expression_arrow_simplifiable,
        ),
        boxed(
            STYLE_UNNECESSARY_ELSE_AFTER_RETURN,
            unnecessary_else_after_return,
        ),
        boxed(STYLE_NESTED_CONDITIONAL, nested_conditional),
        boxed(STYLE_GUARD_CLAUSE, guard_clause_candidate),
        boxed(STYLE_DUPLICATED_LITERAL, duplicated_literals),
        boxed(STYLE_LARGE_FUNCTION, large_functions),
        boxed(STYLE_HIGH_PARAMETER_COUNT, high_parameter_count),
        boxed(STYLE_COMPLEX_CONDITION, complex_condition),
        boxed(PYTHON_BROAD_EXCEPTION, python_broad_exception),
        boxed(
            PYTHON_REPEATED_VALIDATION_LOGIC,
            python_repeated_validation_logic,
        ),
        boxed(
            PYTHON_DUPLICATED_ROUTE_HANDLER_BUSINESS_LOGIC,
            python_duplicated_route_logic,
        ),
        boxed(RUST_DUPLICATE_MATCH_ARM_BODY, rust_duplicate_match_arm_body),
        boxed(RUST_REPEATED_UNWRAP_POLICY, rust_repeated_unwrap_policy),
        boxed(
            RUST_MANUAL_RESULT_OPTION_PATTERN,
            rust_manual_result_option_pattern,
        ),
    ]
}

fn boxed(rule_id: &'static str, runner: RuleRunner) -> Box<dyn Rule> {
    Box::new(BuiltinRule { rule_id, runner })
}

struct BuiltinRule {
    rule_id: &'static str,
    runner: RuleRunner,
}

impl Rule for BuiltinRule {
    fn id(&self) -> &'static str {
        self.rule_id
    }

    fn metadata(&self) -> RuleMetadata {
        find_rule(self.rule_id).expect("built-in style rule exists in catalog")
    }

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        (self.runner)(ctx)
    }
}

fn boolean_return_simplifiable(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.config.simplify_boolean_returns {
        return Vec::new();
    }

    match ctx.source_file.language.name {
        "typescript" | "tsx" => typescript_boolean_return_simplifiable(ctx),
        "python" => python_boolean_return_simplifiable(ctx),
        "rust" => rust_boolean_return_simplifiable(ctx),
        _ => Vec::new(),
    }
}

fn typescript_boolean_return_simplifiable(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "if_statement" || child_by_field_name(node, "alternative").is_some() {
            return;
        }
        let Some(condition) = if_condition_text(ctx, node) else {
            return;
        };
        let Some(consequence) = child_by_field_name(node, "consequence") else {
            return;
        };
        let Some(first_return) = return_statement_from(consequence) else {
            return;
        };
        let Some(next_return) = node.next_named_sibling().and_then(return_statement_from) else {
            return;
        };
        let Some(first_bool) = return_bool(ctx, first_return) else {
            return;
        };
        let Some(second_bool) = return_bool(ctx, next_return) else {
            return;
        };
        if first_bool == second_bool {
            return;
        }

        let span = span_between(ctx, node, next_return);
        let replacement = if first_bool {
            format!(
                "{}return {};",
                line_indent(&ctx.source_file.source, span.start),
                condition
            )
        } else {
            format!(
                "{}return !({});",
                line_indent(&ctx.source_file.source, span.start),
                condition
            )
        };
        findings.push(boolean_finding(
            ctx,
            span,
            condition,
            first_bool,
            replacement,
        ));
    });
    findings
}

fn python_boolean_return_simplifiable(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "if_statement" || child_by_field_name(node, "alternative").is_some() {
            return;
        }
        let Some(condition) = if_condition_text(ctx, node) else {
            return;
        };
        let Some(consequence) = child_by_field_name(node, "consequence") else {
            return;
        };
        let Some(first_return) = return_statement_from(consequence) else {
            return;
        };
        let Some(next_return) = node.next_named_sibling().and_then(return_statement_from) else {
            return;
        };
        let Some(first_bool) = return_bool(ctx, first_return) else {
            return;
        };
        let Some(second_bool) = return_bool(ctx, next_return) else {
            return;
        };
        if first_bool == second_bool {
            return;
        }

        let span = span_between(ctx, node, next_return);
        let indent = line_indent(&ctx.source_file.source, span.start);
        let replacement = if first_bool {
            format!("{indent}return {condition}")
        } else {
            format!("{indent}return not ({condition})")
        };
        findings.push(boolean_finding(
            ctx,
            span,
            condition,
            first_bool,
            replacement,
        ));
    });
    findings
}

fn rust_boolean_return_simplifiable(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "if_expression" {
            return;
        }
        let Some(condition) = if_condition_text(ctx, node) else {
            return;
        };
        let Some(consequence) =
            child_by_field_name(node, "consequence").or_else(|| child_by_field_name(node, "body"))
        else {
            return;
        };
        let Some(alternative) = child_by_field_name(node, "alternative") else {
            return;
        };
        let Some(first_bool) = block_bool_expr(ctx, consequence) else {
            return;
        };
        let Some(second_bool) = block_bool_expr(ctx, alternative) else {
            return;
        };
        if first_bool == second_bool {
            return;
        }

        let span = ctx.tree.span_for_node(node);
        let replacement = if first_bool {
            condition.clone()
        } else {
            format!("!({condition})")
        };
        findings.push(boolean_finding(
            ctx,
            span,
            condition,
            first_bool,
            replacement,
        ));
    });
    findings
}

fn expression_arrow_simplifiable(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.config.prefer_expression_arrows
        || !matches!(ctx.source_file.language.name, "typescript" | "tsx")
    {
        return Vec::new();
    }

    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "arrow_function" {
            return;
        }
        let Some(body) = child_by_field_name(node, "body") else {
            return;
        };
        let Some(return_statement) = single_return_in_block(body) else {
            return;
        };
        let Some(expression) = return_expression_text(ctx, return_statement) else {
            return;
        };
        let body_text = ctx.tree.text_for_node(body);
        if body_text.contains("arguments") || body_text.contains("this") {
            return;
        }
        let replacement = if expression.trim_start().starts_with('{') {
            format!("({})", expression.trim())
        } else {
            expression.trim().to_string()
        };
        let span = ctx.tree.span_for_node(body);
        let fix = safe_fix(
            ctx,
            "Convert arrow function to expression body",
            span,
            replacement,
        );
        findings.push(style_finding(
            ctx,
            STYLE_EXPRESSION_ARROW_SIMPLIFIABLE,
            span,
            "Arrow function can use an expression body.".to_string(),
            "Replace the block body with the returned expression.".to_string(),
            "The arrow function body contains a single return statement.".to_string(),
            AutofixSafety::Safe,
            vec![fix],
            BTreeMap::new(),
        ));
    });
    findings
}

fn unnecessary_else_after_return(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !matches!(
        ctx.source_file.language.name,
        "typescript" | "tsx" | "python"
    ) {
        return findings;
    }

    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "if_statement" {
            return;
        }
        let Some(alternative) = child_by_field_name(node, "alternative") else {
            return;
        };
        let Some(consequence) = child_by_field_name(node, "consequence") else {
            return;
        };
        if !ends_with_return(consequence) {
            return;
        }
        let span = ctx.tree.span_for_node(alternative);
        findings.push(style_finding(
            ctx,
            STYLE_UNNECESSARY_ELSE_AFTER_RETURN,
            span,
            "Else branch follows a branch that returns.".to_string(),
            "Remove the else and let the following branch run after the early return.".to_string(),
            "The if branch ends in a return statement and the alternate branch is therefore unnecessary nesting.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            BTreeMap::new(),
        ));
    });
    findings
}

fn nested_conditional(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if !matches!(node.kind(), "if_statement" | "if_expression") {
            return;
        }
        let Some(consequence) =
            child_by_field_name(node, "consequence").or_else(|| child_by_field_name(node, "body"))
        else {
            return;
        };
        let nested = named_children(consequence)
            .into_iter()
            .find(|child| matches!(child.kind(), "if_statement" | "if_expression"));
        let Some(nested) = nested else {
            return;
        };
        let span = ctx.tree.span_for_node(nested);
        findings.push(style_finding(
            ctx,
            STYLE_NESTED_CONDITIONAL,
            span,
            "Nested conditional can be simplified.".to_string(),
            "Consider flattening the condition or extracting a guard clause/helper.".to_string(),
            "An if statement is directly nested inside another if branch.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            BTreeMap::new(),
        ));
    });
    findings
}

fn guard_clause_candidate(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.config.prefer_guard_clauses {
        return Vec::new();
    }

    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if !matches!(node.kind(), "if_statement" | "if_expression")
            || child_by_field_name(node, "alternative").is_some()
        {
            return;
        }
        let Some(consequence) =
            child_by_field_name(node, "consequence").or_else(|| child_by_field_name(node, "body"))
        else {
            return;
        };
        let span = ctx.tree.span_for_node(consequence);
        let lines = span
            .end_position
            .line
            .saturating_sub(span.start_position.line)
            + 1;
        if lines < 4 || ends_with_return(consequence) {
            return;
        }
        findings.push(style_finding(
            ctx,
            STYLE_GUARD_CLAUSE,
            ctx.tree.span_for_node(node),
            "Branch may be clearer as a guard clause.".to_string(),
            "Consider returning early for the inverse condition and unindenting the main path."
                .to_string(),
            "The if branch is several lines long and has no alternate branch.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            BTreeMap::new(),
        ));
    });
    findings
}

fn duplicated_literals(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !matches!(ctx.source_file.language.name, "typescript" | "tsx") {
        return Vec::new();
    }
    let max = ctx
        .config
        .options_for(STYLE_DUPLICATED_LITERAL)
        .max_literal_occurrences
        .unwrap_or(3);
    let mut by_literal: BTreeMap<String, Vec<Span>> = BTreeMap::new();
    for literal in scan_literals(&ctx.source_file.source) {
        by_literal
            .entry(literal.text)
            .or_default()
            .push(literal.span);
    }

    let mut findings = Vec::new();
    for (literal, spans) in by_literal {
        if spans.len() <= max {
            continue;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("literal".to_string(), json!(literal));
        metadata.insert("occurrences".to_string(), json!(spans.len()));
        findings.push(style_finding(
            ctx,
            STYLE_DUPLICATED_LITERAL,
            spans[0],
            format!("Literal appears {} times.", spans.len()),
            "Introduce a named constant if the repeated literal represents one concept."
                .to_string(),
            "The same literal token appears more often than the configured threshold.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            metadata,
        ));
    }
    findings
}

fn large_functions(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let max_lines = ctx
        .config
        .options_for(STYLE_LARGE_FUNCTION)
        .max_lines
        .unwrap_or(80);
    file_definitions(ctx)
        .into_iter()
        .filter(|definition| function_like(definition.kind))
        .filter_map(|definition| {
            let span = definition.body_span.unwrap_or(definition.span);
            let lines = span
                .end_position
                .line
                .saturating_sub(span.start_position.line)
                + 1;
            (lines > max_lines).then(|| {
                let mut metadata = BTreeMap::new();
                metadata.insert("lines".to_string(), json!(lines));
                metadata.insert("max_lines".to_string(), json!(max_lines));
                style_finding(
                    ctx,
                    STYLE_LARGE_FUNCTION,
                    span,
                    format!(
                        "Function '{}' is {lines} lines long.",
                        definition.qualified_name
                    ),
                    "Split unrelated responsibilities or extract cohesive helper functions."
                        .to_string(),
                    "The indexed function body exceeds the configured line threshold.".to_string(),
                    AutofixSafety::SuggestionOnly,
                    Vec::new(),
                    metadata,
                )
            })
        })
        .collect()
}

fn high_parameter_count(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let max_params = ctx
        .config
        .options_for(STYLE_HIGH_PARAMETER_COUNT)
        .max_params
        .unwrap_or(6);
    file_definitions(ctx)
        .into_iter()
        .filter(|definition| function_like(definition.kind))
        .filter_map(|definition| {
            let count = definition.signature.parameters.len();
            (count > max_params).then(|| {
                let mut metadata = BTreeMap::new();
                metadata.insert("parameters".to_string(), json!(count));
                metadata.insert("max_params".to_string(), json!(max_params));
                style_finding(
                    ctx,
                    STYLE_HIGH_PARAMETER_COUNT,
                    definition.signature_span.unwrap_or(definition.span),
                    format!("Function '{}' has {count} parameters.", definition.qualified_name),
                    "Consider grouping related values into an options object, request model, or domain type.".to_string(),
                    "The indexed function signature exceeds the configured parameter threshold.".to_string(),
                    AutofixSafety::SuggestionOnly,
                    Vec::new(),
                    metadata,
                )
            })
        })
        .collect()
}

fn complex_condition(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let max_terms = ctx
        .config
        .options_for(STYLE_COMPLEX_CONDITION)
        .max_condition_terms
        .unwrap_or(3);
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if !matches!(
            node.kind(),
            "if_statement" | "if_expression" | "while_statement" | "while_expression"
        ) {
            return;
        }
        let Some(condition_node) = child_by_field_name(node, "condition") else {
            return;
        };
        let condition = ctx.tree.text_for_node(condition_node);
        let terms = boolean_term_count(condition);
        if terms <= max_terms {
            return;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("condition_terms".to_string(), json!(terms));
        metadata.insert("max_condition_terms".to_string(), json!(max_terms));
        findings.push(style_finding(
            ctx,
            STYLE_COMPLEX_CONDITION,
            ctx.tree.span_for_node(condition_node),
            format!("Condition has {terms} boolean terms."),
            "Extract the condition into named predicates or split the branch.".to_string(),
            "The condition contains more boolean terms than the configured threshold.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            metadata,
        ));
    });
    findings
}

fn python_broad_exception(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    walk(ctx.tree.root_node(), &mut |node| {
        if node.kind() != "except_clause" {
            return;
        }
        let text = ctx.tree.text_for_node(node).trim_start();
        if !(text.starts_with("except:")
            || text.starts_with("except Exception")
            || text.starts_with("except BaseException"))
        {
            return;
        }
        findings.push(style_finding(
            ctx,
            PYTHON_BROAD_EXCEPTION,
            ctx.tree.span_for_node(node),
            "Broad exception handler can hide unrelated failures.".to_string(),
            "Catch the narrowest expected exception type and let unexpected failures surface."
                .to_string(),
            "The except clause catches Exception, BaseException, or every exception.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            BTreeMap::new(),
        ));
    });
    findings
}

fn python_repeated_validation_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut groups: BTreeMap<String, Vec<Span>> = BTreeMap::new();
    let lines = ctx.source_file.source.lines().collect::<Vec<_>>();
    let mut offset = 0;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let next = lines.get(index + 1).map(|line| line.trim()).unwrap_or("");
        if trimmed.starts_with("if ") && next.starts_with("raise ") {
            let key = format!(
                "{}|{}",
                normalize_validation(trimmed),
                next.split('(').next().unwrap_or(next)
            );
            let start = offset + line.find("if").unwrap_or(0);
            let end = offset + line.len() + 1 + next.len();
            groups
                .entry(key)
                .or_default()
                .push(codehealth_parser::span_for_offsets(
                    &ctx.source_file.source,
                    start,
                    end.min(ctx.source_file.source.len()),
                ));
        }
        offset += line.len() + 1;
    }

    let mut findings = Vec::new();
    for spans in groups.into_values() {
        if spans.len() < 2 {
            continue;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("occurrences".to_string(), json!(spans.len()));
        findings.push(style_finding(
            ctx,
            PYTHON_REPEATED_VALIDATION_LOGIC,
            spans[0],
            format!("Validation-and-raise pattern appears {} times.", spans.len()),
            "Consider extracting a shared validation helper when the repeated checks represent the same rule.".to_string(),
            "The same normalized validation branch and raise type appears more than once.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            metadata,
        ));
    }
    findings
}

fn python_duplicated_route_logic(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(symbols) = ctx.symbols else {
        return Vec::new();
    };
    let mut groups: BTreeMap<String, Vec<&Definition>> = BTreeMap::new();
    for definition in &symbols.definitions {
        if definition.file != ctx.source_file.path || definition.language != Language::Python {
            continue;
        }
        if !definition
            .framework_tags
            .iter()
            .any(|tag| matches!(tag, FrameworkTag::FastApiRoute(_)))
        {
            continue;
        }
        let Some(fingerprint) = &definition.structural_fingerprint else {
            continue;
        };
        groups
            .entry(fingerprint.stable_hash_hex.clone())
            .or_default()
            .push(definition);
    }

    groups
        .into_values()
        .filter(|group| group.len() > 1)
        .map(|group| {
            let mut metadata = BTreeMap::new();
            metadata.insert("route_handlers".to_string(), json!(group.len()));
            metadata.insert(
                "canonical_hash".to_string(),
                json!(
                    group[0]
                        .structural_fingerprint
                        .as_ref()
                        .map(|fingerprint| fingerprint.stable_hash_hex.as_str())
                ),
            );
            let primary = group[0].body_span.unwrap_or(group[0].span);
            style_finding(
                ctx,
                PYTHON_DUPLICATED_ROUTE_HANDLER_BUSINESS_LOGIC,
                primary,
                format!(
                    "{} FastAPI route handlers have duplicated business logic.",
                    group.len()
                ),
                "Extract shared business logic below the routing layer if these handlers perform the same domain work.".to_string(),
                "FastAPI route-handler bodies share the same structural fingerprint.".to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            )
        })
        .collect()
}

fn rust_duplicate_match_arm_body(ctx: &RuleContext<'_>) -> Vec<Finding> {
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
            findings.push(style_finding(
                ctx,
                RUST_DUPLICATE_MATCH_ARM_BODY,
                ctx.tree.span_for_node(group[0]),
                format!("{} match arms share the same body.", group.len()),
                "Merge equivalent patterns with `|` or extract the repeated body into a helper when appropriate.".to_string(),
                "A match expression contains more than one arm with the same normalized body.".to_string(),
                AutofixSafety::SuggestionOnly,
                Vec::new(),
                metadata,
            ));
        }
    });
    findings
}

fn rust_repeated_unwrap_policy(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let max_unwraps = ctx
        .config
        .options_for(RUST_REPEATED_UNWRAP_POLICY)
        .max_unwraps
        .unwrap_or(2);
    file_definitions(ctx)
        .into_iter()
        .filter(|definition| definition.language == Language::Rust && function_like(definition.kind))
        .filter_map(|definition| {
            let span = definition.body_span.unwrap_or(definition.span);
            let source = slice_span(&ctx.source_file.source, span);
            let count = source.matches(".unwrap()").count() + source.matches(".expect(").count();
            (count > max_unwraps).then(|| {
                let mut metadata = BTreeMap::new();
                metadata.insert("unwrap_like_calls".to_string(), json!(count));
                metadata.insert("max_unwraps".to_string(), json!(max_unwraps));
                style_finding(
                    ctx,
                    RUST_REPEATED_UNWRAP_POLICY,
                    span,
                    format!("Function '{}' has {count} unwrap/expect calls.", definition.qualified_name),
                    "Prefer propagating errors, handling None/Err explicitly, or adding one justified expect message near the boundary.".to_string(),
                    "The function body contains repeated unwrap or expect calls beyond the configured threshold.".to_string(),
                    AutofixSafety::SuggestionOnly,
                    Vec::new(),
                    metadata,
                )
            })
        })
        .collect()
}

fn rust_manual_result_option_pattern(ctx: &RuleContext<'_>) -> Vec<Finding> {
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
        findings.push(style_finding(
            ctx,
            RUST_MANUAL_RESULT_OPTION_PATTERN,
            ctx.tree.span_for_node(node),
            "Manual Result/Option match may have an idiomatic combinator.".to_string(),
            "Consider `map`, `and_then`, `unwrap_or`, `ok_or`, or `?` if it keeps the intent clearer.".to_string(),
            "A small match expression handles Result/Option variants manually.".to_string(),
            AutofixSafety::SuggestionOnly,
            Vec::new(),
            BTreeMap::new(),
        ));
    });
    findings
}

fn boolean_finding(
    ctx: &RuleContext<'_>,
    span: Span,
    condition: String,
    positive: bool,
    replacement: String,
) -> Finding {
    let mut metadata = BTreeMap::new();
    metadata.insert("condition".to_string(), json!(condition));
    metadata.insert("inverse".to_string(), json!(!positive));
    let fix = safe_fix(ctx, "Simplify boolean return", span, replacement);
    style_finding(
        ctx,
        STYLE_BOOLEAN_RETURN_SIMPLIFIABLE,
        span,
        "Boolean return branch can be simplified.".to_string(),
        "Return the condition directly instead of returning true/false from separate branches."
            .to_string(),
        "The branch returns one boolean literal and the following alternate path returns the opposite boolean literal."
            .to_string(),
        AutofixSafety::Safe,
        vec![fix],
        metadata,
    )
}

#[allow(clippy::too_many_arguments)]
fn style_finding(
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
    let kind = metadata_rule
        .as_ref()
        .map(|rule| rule.kind)
        .unwrap_or(FindingKind::Style);
    let severity = metadata_rule
        .as_ref()
        .map(|rule| rule.default_severity)
        .unwrap_or(Severity::Low);
    let confidence = metadata_rule
        .as_ref()
        .map(|rule| rule.default_confidence)
        .unwrap_or(Confidence::Medium);
    let explanation = metadata_rule
        .as_ref()
        .map(|rule| rule.explanation)
        .unwrap_or("Style rule finding.")
        .to_string();
    let baseline_key = style_key(ctx, rule_id, span, &message);
    let framework = metadata_rule
        .as_ref()
        .and_then(|rule| rule.framework)
        .map(str::to_string);

    Finding {
        finding_id: format!("{rule_id}:{}", &baseline_key[..12]),
        baseline_key,
        rule_id: rule_id.to_string(),
        kind,
        severity,
        confidence,
        message,
        locations: vec![FindingLocation {
            path: ctx.source_file.path.clone(),
            span: Some(SourceSpan {
                start: span.start,
                end: span.end,
            }),
            start: Some(Location {
                line: span.start_position.line,
                column: span.start_position.column,
                byte_offset: span.start,
            }),
            language: Some(ctx.source_file.language.name.to_string()),
        }],
        language: Some(ctx.source_file.language.name.to_string()),
        framework,
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

fn safe_fix(ctx: &RuleContext<'_>, title: &str, span: Span, replacement: String) -> Fix {
    Fix {
        title: title.to_string(),
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
    }
}

fn style_key(ctx: &RuleContext<'_>, rule_id: &str, span: Span, message: &str) -> String {
    let snippet = slice_span(&ctx.source_file.source, span);
    let normalized = collapse_whitespace(snippet);
    let path = ctx
        .source_file
        .path
        .strip_prefix(ctx.root)
        .unwrap_or(&ctx.source_file.path)
        .to_string_lossy()
        .replace('\\', "/");
    stable_hash(&format!("{rule_id}|{path}|{normalized}|{message}"))
}

fn stable_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
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

fn if_condition_text(ctx: &RuleContext<'_>, node: Node<'_>) -> Option<String> {
    let condition = child_by_field_name(node, "condition").or_else(|| node.named_child(0))?;
    let raw = ctx.tree.text_for_node(condition).trim();
    Some(strip_wrapping_parens(raw).to_string())
}

fn return_statement_from(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "return_statement" {
        return Some(node);
    }
    single_return_in_block(node)
}

fn single_return_in_block(node: Node<'_>) -> Option<Node<'_>> {
    let children = named_children(node);
    if children.len() == 1 && children[0].kind() == "return_statement" {
        Some(children[0])
    } else {
        None
    }
}

fn return_expression_text(ctx: &RuleContext<'_>, node: Node<'_>) -> Option<String> {
    node.named_child(0)
        .map(|expression| ctx.tree.text_for_node(expression).trim().to_string())
}

fn return_bool(ctx: &RuleContext<'_>, node: Node<'_>) -> Option<bool> {
    let text = return_expression_text(ctx, node)?;
    match text.trim() {
        "true" | "True" => Some(true),
        "false" | "False" => Some(false),
        _ => None,
    }
}

fn block_bool_expr(ctx: &RuleContext<'_>, node: Node<'_>) -> Option<bool> {
    let children = named_children(node);
    let expression = if children.len() == 1 {
        children[0]
    } else {
        node
    };
    let text = ctx.tree.text_for_node(expression).trim();
    match text
        .trim_matches(['{', '}'])
        .trim()
        .trim_end_matches(';')
        .trim()
    {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn ends_with_return(node: Node<'_>) -> bool {
    if node.kind() == "return_statement" {
        return true;
    }
    let children = named_children(node);
    children
        .last()
        .is_some_and(|child| child.kind() == "return_statement" || ends_with_return(*child))
}

fn span_between(ctx: &RuleContext<'_>, start: Node<'_>, end: Node<'_>) -> Span {
    codehealth_parser::span_for_offsets(&ctx.source_file.source, start.start_byte(), end.end_byte())
}

fn line_indent(source: &str, byte: usize) -> String {
    let start = source[..byte.min(source.len())]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    source[start..byte.min(source.len())]
        .chars()
        .take_while(|character| character.is_whitespace() && *character != '\n')
        .collect()
}

fn strip_wrapping_parens(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        trimmed[1..trimmed.len() - 1].trim()
    } else {
        trimmed
    }
}

fn boolean_term_count(condition: &str) -> usize {
    1 + condition.matches("&&").count()
        + condition.matches("||").count()
        + condition.matches(" and ").count()
        + condition.matches(" or ").count()
}

fn file_definitions<'a>(ctx: &'a RuleContext<'_>) -> Vec<&'a Definition> {
    ctx.symbols
        .map(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| definition.file == ctx.source_file.path)
                .collect()
        })
        .unwrap_or_default()
}

fn function_like(kind: DefinitionKind) -> bool {
    matches!(
        kind,
        DefinitionKind::Function
            | DefinitionKind::Method
            | DefinitionKind::ReactComponent
            | DefinitionKind::ReactHook
            | DefinitionKind::FastApiRoute
            | DefinitionKind::FastApiDependency
    )
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

fn normalize_validation(value: &str) -> String {
    value
        .split_whitespace()
        .map(|part| {
            let core = part.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
            if !core.is_empty()
                && core
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                part.replacen(core, "_", 1)
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug)]
struct LiteralToken {
    text: String,
    span: Span,
}

fn scan_literals(source: &str) -> Vec<LiteralToken> {
    let mut tokens = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'\'' | b'"' | b'`') {
            let quote = byte;
            let start = index;
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                let current = bytes[index];
                index += 1;
                if escaped {
                    escaped = false;
                    continue;
                }
                if current == b'\\' {
                    escaped = true;
                    continue;
                }
                if current == quote {
                    break;
                }
            }
            let end = index.min(source.len());
            let text = source[start..end].to_string();
            if text.len() > 4 {
                tokens.push(LiteralToken {
                    text,
                    span: codehealth_parser::span_for_offsets(source, start, end),
                });
            }
            continue;
        }

        if byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit() || matches!(bytes[index], b'.' | b'_'))
            {
                index += 1;
            }
            let text = source[start..index].replace('_', "");
            if !matches!(text.as_str(), "0" | "1") {
                tokens.push(LiteralToken {
                    text,
                    span: codehealth_parser::span_for_offsets(source, start, index),
                });
            }
            continue;
        }

        index += 1;
    }

    tokens
}
