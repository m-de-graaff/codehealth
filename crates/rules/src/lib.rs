use codehealth_core::Finding;

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;

    fn check(&self) -> Vec<Finding> {
        Vec::new()
    }
}

pub fn run_noop_rules() -> Vec<Finding> {
    Vec::new()
}
