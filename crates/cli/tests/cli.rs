use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(path: &str) -> PathBuf {
    workspace_root().join("fixtures").join(path)
}

#[test]
fn root_command_prints_help() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .assert()
        .success()
        .stdout(contains("Local-first code health"));
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
fn scan_text_report_works_on_empty_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(contains("Code Health Report"))
        .stdout(contains("Files scanned: 0"))
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

    assert_eq!(json["schema_version"], 1);
    assert!(json["stats"]["files_scanned"].as_u64().expect("number") >= 8);
    assert!(!json["findings"].as_array().expect("array").is_empty());
}

#[test]
fn dupes_reports_exact_file_duplicates() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("dupes")
        .arg(fixture("duplicates"))
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("HIGH  duplicate.exact_file"))
        .stdout(contains("a.ts:1:1"))
        .stdout(contains("b.ts:1:1"));
}

#[test]
fn color_can_be_forced_or_disabled() {
    let mut color_command = Command::cargo_bin("codehealth").expect("binary exists");
    color_command
        .arg("dupes")
        .arg(fixture("duplicates"))
        .arg("--color")
        .arg("always")
        .assert()
        .success()
        .stdout(contains("\u{1b}[31mHIGH\u{1b}[0m"));

    let mut no_color_command = Command::cargo_bin("codehealth").expect("binary exists");
    no_color_command
        .arg("dupes")
        .arg(fixture("duplicates"))
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(predicate::str::contains("\u{1b}[").not());
}

#[test]
fn fail_on_high_returns_non_zero_when_threshold_is_met() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--fail-on")
        .arg("high")
        .assert()
        .failure()
        .code(1);
}

#[test]
fn fail_on_high_returns_zero_when_no_blocking_findings_exist() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--fail-on")
        .arg("high")
        .assert()
        .success();
}

#[test]
fn severity_filter_can_hide_duplicate_findings() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--only")
        .arg("medium")
        .assert()
        .success()
        .stdout(contains("Findings: 0"));
}

#[test]
fn sarif_and_html_formats_render() {
    let mut sarif = Command::cargo_bin("codehealth").expect("binary exists");
    sarif
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--format")
        .arg("sarif")
        .assert()
        .success()
        .stdout(contains("\"version\": \"2.1.0\""));

    let mut html = Command::cargo_bin("codehealth").expect("binary exists");
    html.arg("scan")
        .arg(fixture("duplicates"))
        .arg("--format")
        .arg("html")
        .assert()
        .success()
        .stdout(contains("<!doctype html>"));
}

#[test]
fn output_flag_writes_report_to_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("report.json");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&output)
        .assert()
        .success()
        .stdout(contains("Wrote report"));

    let raw = std::fs::read_to_string(output).expect("report exists");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
    assert_eq!(json["findings"].as_array().expect("array").len(), 1);
}

#[test]
fn init_and_config_validate_work() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    let mut init = Command::cargo_bin("codehealth").expect("binary exists");

    init.arg("init")
        .arg("--path")
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("Created"));

    let mut validate = Command::cargo_bin("codehealth").expect("binary exists");
    validate
        .arg("config")
        .arg("validate")
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("Config valid"));
}

#[test]
fn explain_known_rule_works() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("explain")
        .arg("duplicate.exact_file")
        .assert()
        .success()
        .stdout(contains("Exact duplicate file"))
        .stdout(contains("Why detected"));
}

#[test]
fn debug_commands_work_for_supported_files() {
    let mut parse = Command::cargo_bin("codehealth").expect("binary exists");
    parse
        .arg("debug")
        .arg("parse")
        .arg(fixture("rust/lib.rs"))
        .assert()
        .success()
        .stdout(contains("Language: rust"))
        .stdout(contains("Root: source_file"));

    let mut fingerprints = Command::cargo_bin("codehealth").expect("binary exists");
    fingerprints
        .arg("debug")
        .arg("fingerprints")
        .arg(fixture("duplicates/a.ts"))
        .assert()
        .success()
        .stdout(contains("Stable hash"));
}
