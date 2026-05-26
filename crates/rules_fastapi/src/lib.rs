use codehealth_core::FindingKind;

pub const FASTAPI_RULE_NAMESPACE: &str = "fastapi";

pub fn finding_kind() -> FindingKind {
    FindingKind::FastApi
}
