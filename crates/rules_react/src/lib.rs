use codehealth_core::FindingKind;

pub const REACT_RULE_NAMESPACE: &str = "react";

pub fn finding_kind() -> FindingKind {
    FindingKind::React
}
