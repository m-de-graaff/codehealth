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
        .arg("--only")
        .arg("high")
        .assert()
        .success()
        .stdout(contains("HIGH  duplicate.exact.file"))
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
        .arg("low")
        .assert()
        .success()
        .stdout(contains("Findings: 0"));
}

#[test]
fn scan_reports_duplicate_symbol_names() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("a.ts"),
        "export function sharedName() { return 1; }\n",
    )
    .expect("write a");
    std::fs::write(
        temp.path().join("b.ts"),
        "export function sharedName() { return 2; }\n",
    )
    .expect("write b");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("Definitions indexed: 2"))
        .stdout(contains("MEDIUM  duplicate.name.function"))
        .stdout(contains("a.ts:1:8"))
        .stdout(contains("b.ts:1:8"));
}

#[test]
fn scan_reports_exact_symbol_bodies_with_different_names() {
    let temp = tempfile::tempdir().expect("tempdir");
    let duplicate_body = r#"
  let total = 0;
  for (const item of items) {
    const subtotal = item.price * item.quantity;
    const discount = subtotal > 100 ? subtotal * 0.1 : 0;
    total += subtotal - discount;
  }
  const tax = total * 0.2;
  const rounded = Math.round((total + tax) * 100) / 100;
  return rounded;
"#;
    std::fs::write(
        temp.path().join("invoice.ts"),
        format!(
            "export function calculateInvoiceTotal(items: Array<{{price: number, quantity: number}}): number {{{duplicate_body}}}\n"
        ),
    )
    .expect("write invoice");
    std::fs::write(
        temp.path().join("cart.ts"),
        format!(
            "export function computeCartTotal(items: Array<{{price: number, quantity: number}}): number {{{duplicate_body}}}\n"
        ),
    )
    .expect("write cart");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("HIGH  duplicate.exact.body"))
        .stdout(contains("Symbols: calculateInvoiceTotal, computeCartTotal"))
        .stdout(contains("Names differ: true; signatures differ: false"));
}

#[test]
fn exact_symbol_bodies_honor_min_lines_and_tokens() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("a.ts"),
        "export function left() { return 1; }\n",
    )
    .expect("write a");
    std::fs::write(
        temp.path().join("b.ts"),
        "export function right() { return 1; }\n",
    )
    .expect("write b");

    let mut default_thresholds = Command::cargo_bin("codehealth").expect("binary exists");
    default_thresholds
        .arg("scan")
        .arg(temp.path())
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("Findings: 0"));

    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [duplication]
            min_lines = 1
            min_tokens = 1
        "#,
    )
    .expect("write config");

    let mut relaxed_thresholds = Command::cargo_bin("codehealth").expect("binary exists");
    relaxed_thresholds
        .arg("scan")
        .arg(temp.path())
        .arg("--config")
        .arg(config)
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("HIGH  duplicate.exact.body"));
}

#[test]
fn exact_symbol_body_json_metadata_is_stable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let body = r#"
  let total = 0;
  for (const item of items) {
    total += item.price * item.quantity;
    total += item.tax;
    total -= item.discount;
  }
  const rounded = Math.round(total * 100) / 100;
  const audited = rounded + 0;
  return audited;
"#;
    std::fs::write(
        temp.path().join("left.ts"),
        format!("export function left(items: any[]): number {{{body}}}\n"),
    )
    .expect("write left");
    std::fs::write(
        temp.path().join("right.ts"),
        format!("export function right(items: any[]): number {{{body}}}\n"),
    )
    .expect("write right");

    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid json");
    let exact_body = json["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .find(|finding| finding["rule_id"] == "duplicate.exact.body")
        .expect("exact body finding");

    assert_eq!(exact_body["metadata"]["names_differ"], true);
    assert_eq!(exact_body["metadata"]["signatures_differ"], false);
    assert!(
        exact_body["metadata"]["line_count"]
            .as_u64()
            .expect("line count")
            >= 5
    );
    assert!(
        exact_body["metadata"]["token_estimate"]
            .as_u64()
            .expect("tokens")
            >= 40
    );
    assert_eq!(
        exact_body["metadata"]["symbol_names"],
        serde_json::json!(["left", "right"])
    );
}

#[test]
fn scan_reports_duplicate_fastapi_routes() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("app.py"),
        r#"
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()

@app.get("/users/{user_id}", response_model=dict[str, int])
async def get_user(user_id: int) -> dict[str, int]:
    return {"id": user_id}

@router.get("/users/{user_id}", response_model=dict[str, int])
async def read_user(user_id: int) -> dict[str, int]:
    return {"id": user_id}
"#,
    )
    .expect("write fastapi app");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("HIGH  fastapi.duplicate.route"))
        .stdout(contains("GET /users/{user_id}"));
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
        .arg("--only")
        .arg("high")
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
        .stdout(contains("duplicate.exact.file"))
        .stdout(contains("Exact duplicate file"))
        .stdout(contains("Why detected"));
}

#[test]
fn config_can_disable_exact_duplicates() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [duplication]
            detect_exact = false
            detect_names = false
        "#,
    )
    .expect("write config");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--config")
        .arg(config)
        .assert()
        .success()
        .stdout(contains("Findings: 0"));
}

#[test]
fn config_rule_severity_override_changes_output_and_exit_behavior() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [rules]
            "duplicate.exact_file" = "warn"
        "#,
    )
    .expect("write config");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--config")
        .arg(config)
        .arg("--fail-on")
        .arg("high")
        .assert()
        .success()
        .stdout(contains("MEDIUM  duplicate.exact.file"));
}

#[test]
fn ignore_paths_remove_files_from_scan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [ignore]
            paths = ["duplicates"]

            [rules]
            "duplicate.name.function" = "off"
        "#,
    )
    .expect("write config");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(workspace_root().join("fixtures"))
        .arg("--config")
        .arg(config)
        .assert()
        .success()
        .stdout(contains("Findings: 0"));
}

#[test]
fn config_validate_rejects_unknown_rule_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [rules]
            "not.a.rule" = "warn"
        "#,
    )
    .expect("write config");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("config")
        .arg("validate")
        .arg(config)
        .assert()
        .failure()
        .stderr(contains("unknown rule id 'not.a.rule'"));
}

#[test]
fn config_validate_rejects_invalid_rule_levels() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [rules]
            "duplicate.exact.file" = "sometimes"
        "#,
    )
    .expect("write config");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("config")
        .arg("validate")
        .arg(config)
        .assert()
        .failure()
        .stderr(contains("invalid rule level"));
}

#[test]
fn config_validate_accepts_scanner_options() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [scanner]
            include = ["src/**"]
            exclude = ["src/generated/**"]
            max_file_size_bytes = 4096
            follow_symlinks = false
            include_generated = false
            include_binary = false
            detect_javascript = true
        "#,
    )
    .expect("write config");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("config")
        .arg("validate")
        .arg(config)
        .assert()
        .success()
        .stdout(contains("Config valid"));
}

#[test]
fn generated_duplicates_are_skipped_by_default() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("a.ts"),
        "// @generated\nexport const value = 1;\n",
    )
    .expect("write generated a");
    std::fs::write(
        temp.path().join("b.ts"),
        "// @generated\nexport const value = 1;\n",
    )
    .expect("write generated b");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(contains("Files scanned: 0"))
        .stdout(contains("Files skipped: 2"))
        .stdout(contains("Findings: 0"));
}

#[test]
fn debug_workspace_reports_metadata() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("package.json"),
        r#"{"packageManager":"pnpm@9.0.0","dependencies":{"react":"latest"}}"#,
    )
    .expect("write package json");
    std::fs::write(
        temp.path().join("app.py"),
        "from fastapi import FastAPI\napp = FastAPI()\n",
    )
    .expect("write fastapi app");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("debug")
        .arg("workspace")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(contains("Files scanned: 1"))
        .stdout(contains("Package managers: pnpm"))
        .stdout(contains("Frameworks: react, fastapi"));
}

#[test]
fn suppressions_hide_findings_by_default_and_can_be_shown() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [duplication]
            detect_names = false
        "#,
    )
    .expect("write config");

    let mut hidden = Command::cargo_bin("codehealth").expect("binary exists");
    hidden
        .arg("scan")
        .arg(fixture("suppressions"))
        .arg("--config")
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("Findings: 0"))
        .stdout(contains("Suppressed findings: 2"))
        .stderr(contains("suppression reason is missing"));

    let mut shown = Command::cargo_bin("codehealth").expect("binary exists");
    shown
        .arg("scan")
        .arg(fixture("suppressions"))
        .arg("--config")
        .arg(&config)
        .arg("--show-suppressed")
        .assert()
        .success()
        .stdout(contains("duplicate.exact.file  (suppressed)"))
        .stdout(contains(
            "Suppression warning: suppression reason is missing",
        ));
}

#[test]
fn config_discovery_walks_parent_directories() {
    let temp = tempfile::tempdir().expect("tempdir");
    let nested = temp.path().join("nested");
    std::fs::create_dir_all(&nested).expect("nested dir");
    std::fs::write(
        temp.path().join("codehealth.toml"),
        r#"
            [rules]
            "duplicate.exact.file" = "off"
            "duplicate.name.function" = "off"
        "#,
    )
    .expect("write config");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .current_dir(&nested)
        .arg("scan")
        .arg(fixture("duplicates"))
        .assert()
        .success()
        .stdout(contains("Findings: 0"));
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
        .stdout(contains("Root: source_file"))
        .stdout(contains("Diagnostics: 0"));

    let mut symbols = Command::cargo_bin("codehealth").expect("binary exists");
    symbols
        .arg("debug")
        .arg("symbols")
        .arg(fixture("parser/rust/definitions.rs"))
        .assert()
        .success()
        .stdout(contains("Definitions:"))
        .stdout(contains("method  Repository.save"));

    let mut query = Command::cargo_bin("codehealth").expect("binary exists");
    query
        .arg("debug")
        .arg("query")
        .arg(fixture("parser/typescript/definitions.ts"))
        .arg("--kind")
        .arg("definitions")
        .assert()
        .success()
        .stdout(contains("Query: definitions v1"))
        .stdout(contains("@definition.name"));

    let mut fingerprints = Command::cargo_bin("codehealth").expect("binary exists");
    fingerprints
        .arg("debug")
        .arg("fingerprints")
        .arg(fixture("duplicates/a.ts"))
        .assert()
        .success()
        .stdout(contains("Stable hash"));
}

#[test]
fn debug_symbols_include_framework_specific_symbols() {
    let mut tsx = Command::cargo_bin("codehealth").expect("binary exists");
    tsx.arg("debug")
        .arg("symbols")
        .arg(fixture("parser/tsx/components.tsx"))
        .assert()
        .success()
        .stdout(contains("react_component  ProfileCard"))
        .stdout(contains("react_hook  useProfile"))
        .stdout(contains("react.component"));

    let mut fastapi = Command::cargo_bin("codehealth").expect("binary exists");
    fastapi
        .arg("debug")
        .arg("symbols")
        .arg(fixture("fastapi/app.py"))
        .assert()
        .success()
        .stdout(contains("fastapi_route  health"))
        .stdout(contains("fastapi.route:GET /health"));
}

#[test]
fn scan_indexes_parse_stats_and_tolerates_parse_errors() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(temp.path().join("broken.ts"), "export function broken( {\n")
        .expect("write malformed source");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(contains("Files parsed: 1"))
        .stdout(contains("Parse errors:"))
        .stdout(contains("Findings: 0"));
}
