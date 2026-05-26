use codehealth_core::{AutofixSafety, Confidence, Finding, FindingKind, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    pub code: &'static str,
    pub name: &'static str,
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
    fn metadata(&self) -> &'static RuleMetadata;

    fn check(&self) -> Vec<Finding> {
        Vec::new()
    }
}

pub fn run_noop_rules() -> Vec<Finding> {
    Vec::new()
}

pub fn rule_catalog() -> Vec<RuleMetadata> {
    let mut rules = vec![
        RuleMetadata {
            code: "duplicate.exact_file",
            name: "Exact duplicate file",
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
        planned(
            "duplicate.structural_function",
            "Structural duplicate function",
            FindingKind::StructuralDuplicate,
        ),
        planned(
            "duplicate.near_function",
            "Near duplicate function",
            FindingKind::NearDuplicate,
        ),
        planned(
            "style.boolean_return_simplifiable",
            "Boolean return simplifiable",
            FindingKind::Style,
        ),
        planned(
            "react.large_component",
            "Large React component",
            FindingKind::React,
        )
        .with_framework("react"),
        planned(
            "react.unstable_list_key",
            "Unstable React list key",
            FindingKind::React,
        )
        .with_framework("react"),
        planned(
            "fastapi.missing_response_model",
            "Missing FastAPI response model",
            FindingKind::FastApi,
        )
        .with_framework("fastapi"),
        planned(
            "rust.unwrap_expect_policy",
            "Rust unwrap/expect policy",
            FindingKind::Rust,
        )
        .with_language("rust"),
    ];

    rules.sort_by(|left, right| left.code.cmp(right.code));
    rules
}

pub fn find_rule(code: &str) -> Option<RuleMetadata> {
    rule_catalog()
        .into_iter()
        .find(|rule| rule.code.eq_ignore_ascii_case(code))
}

fn planned(code: &'static str, name: &'static str, kind: FindingKind) -> RuleMetadata {
    RuleMetadata {
        code,
        name,
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

impl RuleMetadata {
    fn with_language(mut self, language: &'static str) -> Self {
        self.language = Some(language);
        self
    }

    fn with_framework(mut self, framework: &'static str) -> Self {
        self.framework = Some(framework);
        self
    }
}
