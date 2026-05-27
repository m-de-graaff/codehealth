use std::path::{Path, PathBuf};

pub fn fixture_root(crate_manifest_dir: &str) -> PathBuf {
    Path::new(crate_manifest_dir).join("../../fixtures")
}

pub fn assert_valid_report_json(raw: &str) -> serde_json::Value {
    let value: serde_json::Value =
        serde_json::from_str(raw).expect("report JSON should deserialize");
    assert_eq!(value["schemaVersion"], "1.0.0");
    assert!(value["findings"].is_array());
    value
}
