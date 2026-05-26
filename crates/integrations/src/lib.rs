use codehealth_core::ScanResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiDecision {
    Pass,
    Fail,
}

pub fn default_ci_decision(result: &ScanResult) -> CiDecision {
    if result.has_blocking_findings() {
        CiDecision::Fail
    } else {
        CiDecision::Pass
    }
}
