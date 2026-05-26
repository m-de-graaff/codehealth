use codehealth_core::{AutofixSafety, Finding};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutofixPlan {
    pub safety: AutofixSafety,
    pub edits: Vec<TextEdit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEdit {
    pub path: std::path::PathBuf,
    pub replacement: String,
}

pub fn plan_autofix(_finding: &Finding) -> AutofixPlan {
    AutofixPlan {
        safety: AutofixSafety::Unavailable,
        edits: Vec::new(),
    }
}
