use codehealth_core::{AutofixSafety, Confidence, Finding, FindingKind, Severity};
use codehealth_parser::{SourceFile, SyntaxTree};
use codehealth_symbols::SymbolIndex;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

mod style;

pub use style::style_rules;

pub const DUPLICATE_EXACT_FILE: &str = "duplicate.exact.file";
pub const DUPLICATE_EXACT_BODY: &str = "duplicate.exact.body";
pub const STYLE_BOOLEAN_RETURN_SIMPLIFIABLE: &str = "style.boolean_return_simplifiable";
pub const STYLE_EXPRESSION_ARROW_SIMPLIFIABLE: &str = "style.expression_arrow_simplifiable";
pub const STYLE_UNNECESSARY_ELSE_AFTER_RETURN: &str = "style.unnecessary_else_after_return";
pub const STYLE_NESTED_CONDITIONAL: &str = "style.nested_conditional";
pub const STYLE_GUARD_CLAUSE: &str = "style.guard_clause";
pub const STYLE_DUPLICATED_LITERAL: &str = "style.duplicated_literal";
pub const STYLE_LARGE_FUNCTION: &str = "style.large_function";
pub const STYLE_HIGH_PARAMETER_COUNT: &str = "style.high_parameter_count";
pub const STYLE_COMPLEX_CONDITION: &str = "style.complex_condition";
pub const PYTHON_BROAD_EXCEPTION: &str = "python.broad_exception";
pub const PYTHON_REPEATED_VALIDATION_LOGIC: &str = "python.repeated_validation_logic";
pub const PYTHON_DUPLICATED_ROUTE_HANDLER_BUSINESS_LOGIC: &str =
    "python.duplicated_route_handler_business_logic";
pub const RUST_DUPLICATE_MATCH_ARM_BODY: &str = "rust.duplicate_match_arm_body";
pub const RUST_REPEATED_UNWRAP_POLICY: &str = "rust.repeated_unwrap_policy";
pub const RUST_MANUAL_RESULT_OPTION_PATTERN: &str = "rust.manual_result_option_pattern";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    pub code: &'static str,
    pub aliases: &'static [&'static str],
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub kind: FindingKind,
    pub default_severity: Severity,
    pub default_confidence: Confidence,
    pub implemented: bool,
    pub language: Option<&'static str>,
    pub framework: Option<&'static str>,
    pub explanation: &'static str,
    pub remediation: &'static str,
    pub detection_reason: &'static str,
    pub autofix: AutofixSafety,
    pub autofix_explanation: &'static str,
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str {
        self.metadata().code
    }

    fn metadata(&self) -> RuleMetadata;

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleExecutionConfig {
    pub simplify_boolean_returns: bool,
    pub prefer_expression_arrows: bool,
    pub prefer_guard_clauses: bool,
    pub disabled_rules: BTreeSet<String>,
    pub options: BTreeMap<String, RuleOptionSettings>,
}

impl RuleExecutionConfig {
    pub fn options_for(&self, rule_id: &str) -> RuleOptionSettings {
        canonical_rule_id(rule_id)
            .and_then(|canonical| self.options.get(canonical))
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleOptionSettings {
    pub min_tokens: Option<usize>,
    pub min_lines: Option<usize>,
    pub min_confidence: Option<Confidence>,
    pub max_lines: Option<usize>,
    pub max_params: Option<usize>,
    pub max_condition_terms: Option<usize>,
    pub max_literal_occurrences: Option<usize>,
    pub max_unwraps: Option<usize>,
}

#[derive(Debug)]
pub struct RuleContext<'a> {
    pub root: &'a Path,
    pub source_file: &'a SourceFile,
    pub tree: &'a SyntaxTree,
    pub symbols: Option<&'a SymbolIndex>,
    pub config: &'a RuleExecutionConfig,
    pub workspace_frameworks: &'a [&'a str],
}

#[derive(Default)]
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_builtin_rules() -> Self {
        let mut registry = Self::new();
        for rule in style_rules() {
            registry.register_box(rule);
        }
        registry
    }

    pub fn register<R>(&mut self, rule: R)
    where
        R: Rule + 'static,
    {
        self.rules.push(Box::new(rule));
    }

    pub fn register_box(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            let metadata = rule.metadata();
            if ctx.config.disabled_rules.contains(metadata.code) {
                continue;
            }
            if let Some(language) = metadata.language {
                if !language_matches(language, ctx.source_file.language.name) {
                    continue;
                }
            }
            if let Some(framework) = metadata.framework {
                if !ctx
                    .workspace_frameworks
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(framework))
                {
                    continue;
                }
            }
            findings.extend(rule.run(ctx));
        }
        findings
    }
}

pub fn run_noop_rules() -> Vec<Finding> {
    Vec::new()
}

pub fn canonical_rule_id(rule_id: &str) -> Option<&'static str> {
    let normalized = rule_id.trim();
    rule_catalog()
        .into_iter()
        .find(|rule| {
            rule.code.eq_ignore_ascii_case(normalized)
                || rule
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(normalized))
        })
        .map(|rule| rule.code)
}

pub fn rule_catalog() -> Vec<RuleMetadata> {
    let mut rules = vec![
        RuleMetadata {
            code: DUPLICATE_EXACT_FILE,
            aliases: &["duplicate.exact_file"],
            name: "Exact duplicate file",
            description: "Finds supported source files with identical contents after whitespace normalization.",
            category: "duplication",
            kind: FindingKind::ExactDuplicate,
            default_severity: Severity::High,
            default_confidence: Confidence::Certain,
            implemented: true,
            language: None,
            framework: None,
            explanation: "Finds supported source files with identical contents after whitespace normalization.",
            remediation: "Remove one copy, consolidate shared logic, or document why the duplicate file is intentional.",
            detection_reason: "Files are grouped by a stable hash of whitespace-normalized contents.",
            autofix: AutofixSafety::SuggestionOnly,
            autofix_explanation: "The tool cannot safely choose which file to keep or update imports automatically.",
        },
        RuleMetadata {
            code: DUPLICATE_EXACT_BODY,
            aliases: &["duplicate.exact_body"],
            name: "Exact duplicate body",
            description: "Finds functions, methods, components, hooks, and route handlers with identical normalized bodies.",
            category: "duplication",
            kind: FindingKind::ExactDuplicate,
            default_severity: Severity::High,
            default_confidence: Confidence::Certain,
            implemented: true,
            language: None,
            framework: None,
            explanation: "Finds functions, methods, components, hooks, and route handlers with identical normalized bodies.",
            remediation: "Extract a shared helper, remove the duplicate, export an alias, or suppress intentional duplication.",
            detection_reason: "Symbol bodies are grouped by a stable hash after comments and whitespace are normalized.",
            autofix: AutofixSafety::SuggestionOnly,
            autofix_explanation: "The tool cannot safely extract shared logic automatically because APIs, imports, ownership, and side effects may change.",
        },
        RuleMetadata {
            code: "duplicate.name.function",
            aliases: &[],
            name: "Duplicate symbol name",
            description: "Finds indexed function symbols that share a name.",
            category: "duplication",
            kind: FindingKind::DuplicateName,
            default_severity: Severity::Medium,
            default_confidence: Confidence::High,
            implemented: true,
            language: None,
            framework: None,
            explanation:
                "Finds indexed symbols that share the same language, kind, and simple name.",
            remediation:
                "Rename one symbol, narrow its scope, or document why the duplicate name is intentional.",
            detection_reason:
                "Definitions are grouped by the language-independent symbol table.",
            autofix: AutofixSafety::SuggestionOnly,
            autofix_explanation:
                "The tool cannot safely rename symbols because call sites, exports, and public APIs may need coordinated changes.",
        },
        duplicate_name_rule("duplicate.name.class", "Duplicate class/model name"),
        duplicate_name_rule("duplicate.name.method", "Duplicate method name"),
        duplicate_name_rule("duplicate.name.react_component", "Duplicate React component name")
            .with_framework("react"),
        duplicate_name_rule("duplicate.name.react_hook", "Duplicate React hook name")
            .with_framework("react"),
        duplicate_name_rule(
            "duplicate.name.fastapi_route_handler",
            "Duplicate FastAPI route handler name",
        )
        .with_framework("fastapi"),
        duplicate_name_rule("duplicate.name.rust_type", "Duplicate Rust type name")
            .with_language("rust"),
        duplicate_name_rule(
            "duplicate.name.rust_impl_method",
            "Duplicate Rust impl method name",
        )
        .with_language("rust"),
        RuleMetadata {
            code: "duplicate.structural.function",
            aliases: &["duplicate.structural_function"],
            name: "Structural duplicate function",
            description: "Finds functions, methods, components, hooks, and route handlers with the same canonical AST after parameter and local identifier normalization.",
            category: "duplication",
            kind: FindingKind::StructuralDuplicate,
            default_severity: Severity::Medium,
            default_confidence: Confidence::High,
            implemented: true,
            language: None,
            framework: None,
            explanation: "Finds functions, methods, components, hooks, and route handlers with the same canonical AST after parameter and local identifier normalization.",
            remediation: "Compare domain intent, then extract a shared helper, consolidate behind one exported function, or suppress intentional duplication with a reason.",
            detection_reason: "Definitions are grouped by a canonical AST fingerprint that preserves member/API names while normalizing local identifiers.",
            autofix: AutofixSafety::SuggestionOnly,
            autofix_explanation: "Structural duplicates are not auto-fixed because same shape can still represent intentionally separate domain behavior, public APIs, ownership rules, or side effects.",
        },
        planned(
            "duplicate.near.function",
            &["duplicate.near_function"],
            "Near duplicate function",
            FindingKind::NearDuplicate,
        ),
        style_rule(
            STYLE_BOOLEAN_RETURN_SIMPLIFIABLE,
            "Boolean return simplifiable",
            "Finds branches that return boolean literals and can return the condition directly.",
            AutofixSafety::Safe,
        )
        .with_autofix(AutofixSafety::Safe, "Safe local rewrite available for simple boolean-return branches."),
        style_rule(
            STYLE_EXPRESSION_ARROW_SIMPLIFIABLE,
            "Expression-bodied arrow simplifiable",
            "Converts arrow functions with a single return statement to expression-bodied arrows when no semantic risk is detected.",
            AutofixSafety::Safe,
        )
        .with_language("typescript"),
        style_rule(
            STYLE_UNNECESSARY_ELSE_AFTER_RETURN,
            "Unnecessary else after return",
            "Finds else branches that follow a branch guaranteed to return.",
            AutofixSafety::SuggestionOnly,
        ),
        style_rule(
            STYLE_NESTED_CONDITIONAL,
            "Nested conditional",
            "Finds nested conditionals that can usually be flattened or split.",
            AutofixSafety::SuggestionOnly,
        ),
        style_rule(
            STYLE_GUARD_CLAUSE,
            "Guard clause candidate",
            "Finds branches where an early return would reduce indentation.",
            AutofixSafety::SuggestionOnly,
        ),
        style_rule(
            STYLE_DUPLICATED_LITERAL,
            "Duplicated literal",
            "Finds repeated literals that may deserve a named constant.",
            AutofixSafety::SuggestionOnly,
        )
        .with_language("typescript"),
        style_rule(
            STYLE_LARGE_FUNCTION,
            "Large function",
            "Finds functions whose body length exceeds the configured threshold.",
            AutofixSafety::SuggestionOnly,
        ),
        style_rule(
            STYLE_HIGH_PARAMETER_COUNT,
            "High parameter count",
            "Finds functions with more parameters than the configured threshold.",
            AutofixSafety::SuggestionOnly,
        ),
        style_rule(
            STYLE_COMPLEX_CONDITION,
            "Complex condition",
            "Finds conditions with many boolean terms that may deserve extraction.",
            AutofixSafety::SuggestionOnly,
        ),
        style_rule(
            PYTHON_BROAD_EXCEPTION,
            "Broad Python exception",
            "Finds broad Python exception handlers that may hide unrelated failures.",
            AutofixSafety::SuggestionOnly,
        )
        .with_language("python"),
        style_rule(
            PYTHON_REPEATED_VALIDATION_LOGIC,
            "Repeated Python validation logic",
            "Finds repeated validation-and-raise patterns that may deserve a shared validator.",
            AutofixSafety::SuggestionOnly,
        )
        .with_language("python"),
        style_rule(
            PYTHON_DUPLICATED_ROUTE_HANDLER_BUSINESS_LOGIC,
            "Duplicated FastAPI route-handler business logic",
            "Finds FastAPI route handlers with duplicated structural bodies.",
            AutofixSafety::SuggestionOnly,
        )
        .with_language("python")
        .with_framework("fastapi"),
        style_rule(
            RUST_DUPLICATE_MATCH_ARM_BODY,
            "Duplicate Rust match arm body",
            "Finds match arms with repeated bodies.",
            AutofixSafety::SuggestionOnly,
        )
        .with_language("rust"),
        style_rule(
            RUST_REPEATED_UNWRAP_POLICY,
            "Repeated Rust unwrap policy",
            "Finds functions with repeated unwrap or expect calls.",
            AutofixSafety::SuggestionOnly,
        )
        .with_language("rust"),
        style_rule(
            RUST_MANUAL_RESULT_OPTION_PATTERN,
            "Manual Rust Result/Option pattern",
            "Finds simple manual Result/Option matches that may have idiomatic combinators.",
            AutofixSafety::SuggestionOnly,
        )
        .with_language("rust"),
        planned(
            "react.large.component",
            &["react.large_component"],
            "Large React component",
            FindingKind::React,
        )
        .with_framework("react"),
        planned(
            "react.unstable.list_key",
            &["react.unstable_list_key"],
            "Unstable React list key",
            FindingKind::React,
        )
        .with_framework("react"),
        RuleMetadata {
            code: "fastapi.duplicate.route",
            aliases: &["fastapi.duplicate_route"],
            name: "Duplicate FastAPI route",
            description: "Finds FastAPI route handlers that register the same HTTP method and path.",
            category: "fastapi",
            kind: FindingKind::FastApi,
            default_severity: Severity::High,
            default_confidence: Confidence::Certain,
            implemented: true,
            language: Some("python"),
            framework: Some("fastapi"),
            explanation: "Finds FastAPI route handlers that register the same HTTP method and path.",
            remediation: "Remove one route, merge the handlers, or change one path/method combination.",
            detection_reason: "FastAPI route metadata is grouped by HTTP method and route path.",
            autofix: AutofixSafety::SuggestionOnly,
            autofix_explanation: "The tool cannot safely choose which route handler should own a duplicated API path.",
        },
        planned(
            "fastapi.blocking_call_in_async_route",
            &[],
            "Blocking call in async FastAPI route",
            FindingKind::FastApi,
        )
        .with_framework("fastapi"),
        planned(
            "fastapi.missing.response_model",
            &["fastapi.missing_response_model"],
            "Missing FastAPI response model",
            FindingKind::FastApi,
        )
        .with_framework("fastapi"),
        planned(
            "rust.unwrap_expect_policy",
            &[],
            "Rust unwrap/expect policy",
            FindingKind::Rust,
        )
        .with_language("rust"),
    ];

    rules.sort_by(|left, right| left.code.cmp(right.code));
    rules
}

fn duplicate_name_rule(code: &'static str, name: &'static str) -> RuleMetadata {
    RuleMetadata {
        code,
        aliases: &[],
        name,
        description: "Finds duplicate symbol names using scope, path, framework, and public API signals.",
        category: "duplication",
        kind: FindingKind::DuplicateName,
        default_severity: Severity::Medium,
        default_confidence: Confidence::High,
        implemented: true,
        language: None,
        framework: None,
        explanation: "Finds duplicate symbol names using scope, path, framework, and public API signals.",
        remediation:
            "Rename one symbol, narrow its scope, or suppress intentional duplication with a reason.",
        detection_reason: "Definitions are grouped by the language-independent symbol table.",
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation:
            "The tool cannot safely rename symbols because call sites, exports, and public APIs may need coordinated changes.",
    }
}

pub fn find_rule(code: &str) -> Option<RuleMetadata> {
    canonical_rule_id(code).and_then(|canonical| {
        rule_catalog()
            .into_iter()
            .find(|rule| rule.code == canonical)
    })
}

fn planned(
    code: &'static str,
    aliases: &'static [&'static str],
    name: &'static str,
    kind: FindingKind,
) -> RuleMetadata {
    RuleMetadata {
        code,
        aliases,
        name,
        description:
            "This rule is part of the v1 taxonomy but is not implemented in the CLI foundation yet.",
        category: category_for_kind(kind),
        kind,
        default_severity: Severity::Low,
        default_confidence: Confidence::Medium,
        implemented: false,
        language: None,
        framework: None,
        explanation:
            "This rule is part of the v1 taxonomy but is not implemented in the CLI foundation yet.",
        remediation: "No automated recommendation is available until the detector is implemented.",
        detection_reason: "Not implemented in this phase.",
        autofix: AutofixSafety::Unavailable,
        autofix_explanation: "No detector output exists for this rule yet.",
    }
}

fn style_rule(
    code: &'static str,
    name: &'static str,
    description: &'static str,
    autofix: AutofixSafety,
) -> RuleMetadata {
    RuleMetadata {
        code,
        aliases: &[],
        name,
        description,
        category: "style",
        kind: if code.starts_with("rust.") {
            FindingKind::Rust
        } else {
            FindingKind::Style
        },
        default_severity: Severity::Low,
        default_confidence: Confidence::Medium,
        implemented: true,
        language: None,
        framework: None,
        explanation: description,
        remediation: "Prefer the simpler form when it preserves behavior and improves readability.",
        detection_reason: "The style rule inspected parsed syntax and conservative source patterns.",
        autofix,
        autofix_explanation: match autofix {
            AutofixSafety::Safe => "Safe autofix is available for mechanically local rewrites covered by parser validation.",
            AutofixSafety::SuggestionOnly => "Suggestion only. The transformation may require human judgment or broader refactoring.",
            AutofixSafety::Unavailable => "No automated fix is available.",
        },
    }
}

fn category_for_kind(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::DuplicateName
        | FindingKind::ExactDuplicate
        | FindingKind::StructuralDuplicate
        | FindingKind::NearDuplicate
        | FindingKind::SemanticCandidate => "duplication",
        FindingKind::Style => "style",
        FindingKind::React => "react",
        FindingKind::FastApi => "fastapi",
        FindingKind::Rust => "rust_idiom",
    }
}

fn language_matches(rule_language: &str, file_language: &str) -> bool {
    rule_language.eq_ignore_ascii_case(file_language)
        || (rule_language.eq_ignore_ascii_case("typescript")
            && file_language.eq_ignore_ascii_case("tsx"))
}

impl RuleMetadata {
    fn with_language(mut self, language: &'static str) -> Self {
        self.language = Some(language);
        self
    }

    fn with_framework(mut self, framework: &'static str) -> Self {
        self.framework = Some(framework);
        self
    }

    fn with_autofix(mut self, safety: AutofixSafety, explanation: &'static str) -> Self {
        self.autofix = safety;
        self.autofix_explanation = explanation;
        self
    }
}
