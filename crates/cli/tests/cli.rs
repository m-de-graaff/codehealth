use assert_cmd::Command;
use predicates::str::contains;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn version_command_works() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("codehealth"));
}

#[test]
fn scan_text_report_works() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(workspace_root().join("fixtures"))
        .assert()
        .success()
        .stdout(contains("Findings: 0"));
}

#[test]
fn scan_json_report_works() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    let output = command
        .arg("scan")
        .arg(workspace_root().join("fixtures"))
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid json");

    assert_eq!(json["findings"].as_array().expect("array").len(), 0);
    assert!(json["files_scanned"].as_u64().expect("number") >= 6);
}
