use codehealth_core::ScanResult;
use std::path::{Path, PathBuf};

pub fn fixture_root(crate_manifest_dir: &str) -> PathBuf {
    Path::new(crate_manifest_dir).join("../../fixtures")
}

pub fn assert_valid_report_json(raw: &str) -> ScanResult {
    serde_json::from_str(raw).expect("report JSON should deserialize into ScanResult")
}
