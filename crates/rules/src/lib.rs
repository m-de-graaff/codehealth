use codehealth_core::{AutofixSafety, Confidence, Finding, FindingKind, Severity};
use codehealth_parser::{SourceFile, SyntaxTree};
use codehealth_symbols::SymbolIndex;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
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
pub const REACT_LARGE_COMPONENT: &str = "react.large_component";
pub const REACT_TOO_MANY_PROPS: &str = "react.too_many_props";
pub const REACT_DEEPLY_NESTED_JSX: &str = "react.deeply_nested_jsx";
pub const REACT_DUPLICATE_COMPONENT_SHAPE: &str = "react.duplicate_component_shape";
pub const REACT_REPEATED_HOOK_LOGIC: &str = "react.repeated_hook_logic";
pub const REACT_UNNECESSARY_EFFECT_CANDIDATE: &str = "react.unnecessary_effect_candidate";
pub const REACT_DERIVED_STATE_CANDIDATE: &str = "react.derived_state_candidate";
pub const REACT_INLINE_COMPONENT_INSIDE_RENDER: &str = "react.inline_component_inside_render";
pub const REACT_UNSTABLE_LIST_KEY: &str = "react.unstable_list_key";
pub const REACT_MISSING_KEY: &str = "react.missing_key";
pub const REACT_PROP_DRILLING_CANDIDATE: &str = "react.prop_drilling_candidate";
pub const REACT_LARGE_CONTEXT_PROVIDER: &str = "react.large_context_provider";
pub const REACT_MIXED_DATA_FETCHING_AND_RENDERING: &str = "react.mixed_data_fetching_and_rendering";
pub const REACT_COMPONENT_TOO_MANY_RESPONSIBILITIES: &str =
    "react.component_too_many_responsibilities";
pub const REACT_REDUNDANT_FRAGMENT: &str = "react.redundant_fragment";

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
    pub react_enabled: bool,
    pub react_max_component_lines: usize,
    pub react_max_props: usize,
    pub react_prop_drilling_depth: usize,
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
    pub max_depth: Option<usize>,
    pub min_nodes: Option<usize>,
    pub max_context_values: Option<usize>,
    pub max_responsibilities: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleWorkspaceMetadata {
    pub react: RuleReactWorkspaceMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleReactWorkspaceMetadata {
    pub detected: bool,
    pub via_dependency: bool,
    pub via_tsx_or_jsx: bool,
    pub via_next_dependency: bool,
    pub via_vite_dependency: bool,
    pub via_remix_dependency: bool,
    pub source_directories: BTreeSet<PathBuf>,
}

#[derive(Debug)]
pub struct RuleContext<'a> {
    pub root: &'a Path,
    pub source_file: &'a SourceFile,
    pub tree: &'a SyntaxTree,
    pub symbols: Option<&'a SymbolIndex>,
    pub config: &'a RuleExecutionConfig,
    pub workspace_frameworks: &'a [&'a str],
    pub workspace: &'a RuleWorkspaceMetadata,
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
        react_rule(
            REACT_LARGE_COMPONENT,
            &["react.large.component"],
            "Large React component",
            "Finds React components whose body length exceeds the configured threshold.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_TOO_MANY_PROPS,
            &[],
            "Too many React props",
            "Finds React components with more props than the configured threshold.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_DEEPLY_NESTED_JSX,
            &[],
            "Deeply nested JSX",
            "Finds components whose JSX tree is nested beyond the configured depth.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_DUPLICATE_COMPONENT_SHAPE,
            &[],
            "Duplicate React component shape",
            "Finds React components with structurally similar JSX trees.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_REPEATED_HOOK_LOGIC,
            &[],
            "Repeated React hook logic",
            "Finds components or hooks with repeated hook call sequences.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_UNNECESSARY_EFFECT_CANDIDATE,
            &[],
            "Unnecessary React effect candidate",
            "Finds effects that appear to derive local state from existing values.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_DERIVED_STATE_CANDIDATE,
            &[],
            "Derived React state candidate",
            "Finds state/effect pairs that may be replaceable with derived values.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_INLINE_COMPONENT_INSIDE_RENDER,
            &[],
            "Inline component inside render",
            "Finds component declarations nested inside another component render path.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_UNSTABLE_LIST_KEY,
            &["react.unstable.list_key"],
            "Unstable React list key",
            "Finds array-index list keys that can cause unstable reconciliation.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_MISSING_KEY,
            &[],
            "Missing React list key",
            "Finds JSX returned from array maps without an apparent key prop.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_PROP_DRILLING_CANDIDATE,
            &[],
            "React prop drilling candidate",
            "Finds props forwarded through repeated child components.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_LARGE_CONTEXT_PROVIDER,
            &[],
            "Large React context provider",
            "Finds context providers whose values appear to carry too many responsibilities.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_MIXED_DATA_FETCHING_AND_RENDERING,
            &[],
            "Mixed React data fetching and rendering",
            "Finds components that combine data fetching calls with substantial JSX rendering.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_COMPONENT_TOO_MANY_RESPONSIBILITIES,
            &[],
            "React component with too many responsibilities",
            "Finds components combining many state, effect, event, data, context, and rendering responsibilities.",
            AutofixSafety::SuggestionOnly,
        ),
        react_rule(
            REACT_REDUNDANT_FRAGMENT,
            &[],
            "Redundant React fragment",
            "Finds fragments that wrap exactly one JSX child and can be removed safely.",
            AutofixSafety::Safe,
        ),
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

fn react_rule(
    code: &'static str,
    aliases: &'static [&'static str],
    name: &'static str,
    description: &'static str,
    autofix: AutofixSafety,
) -> RuleMetadata {
    RuleMetadata {
        code,
        aliases,
        name,
        description,
        category: "react",
        kind: FindingKind::React,
        default_severity: Severity::Medium,
        default_confidence: Confidence::Medium,
        implemented: true,
        language: None,
        framework: Some("react"),
        explanation: description,
        remediation: "Refactor the component toward smaller render units, clearer hook boundaries, stable list rendering, or shared JSX abstractions as appropriate.",
        detection_reason: "The React analyzer inspected component symbols, JSX structure, hook usage, and component graph signals.",
        autofix,
        autofix_explanation: match autofix {
            AutofixSafety::Safe => "Safe autofix is available for narrowly local JSX syntax rewrites that preserve rendered output.",
            AutofixSafety::SuggestionOnly => "Suggestion only. React refactors can change component boundaries, state lifetimes, or rendering behavior.",
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
