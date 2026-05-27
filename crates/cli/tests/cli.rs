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

    assert_eq!(json["schemaVersion"], "1.0.0");
    assert_eq!(json["toolVersion"], env!("CARGO_PKG_VERSION"));
    assert!(json["configHash"].as_str().expect("config hash").len() >= 64);
    assert_eq!(json["score"]["enabled"], true);
    assert!(json["score"]["overall"].as_u64().expect("score") <= 100);
    assert!(json["metrics"]["linesScanned"].as_u64().expect("lines") > 0);
    assert!(json["metrics"]["filesScanned"].as_u64().expect("number") >= 8);
    assert!(json["timing"]["scanMs"].as_u64().is_some());
    assert!(!json["findings"].as_array().expect("array").is_empty());
}

#[test]
fn score_can_be_disabled_for_one_run() {
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--no-score")
        .assert()
        .success()
        .stdout(contains("Score: disabled"));
}

#[test]
fn config_can_disable_score() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [scoring]
            enabled = false
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
        .stdout(contains("Score: disabled"));
}

#[test]
fn config_can_select_markdown_report_format() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [report]
            default_format = "markdown"
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
        .stdout(contains("# Code Health Summary"));
}

#[test]
fn report_counts_new_findings_when_baseline_exists() {
    let temp = tempfile::tempdir().expect("tempdir");
    let baseline = temp.path().join("baseline.json");
    std::fs::write(&baseline, r#"{"findings":[]}"#).expect("write baseline");
    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--baseline")
        .arg(&baseline)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid json");

    assert_eq!(json["metrics"]["baseline"]["status"], "compared");
    assert!(
        json["metrics"]["baseline"]["newFindings"]
            .as_u64()
            .expect("new findings")
            > 0
    );
    assert!(
        json["score"]["categories"]["ciRisk"]["score"]
            .as_u64()
            .expect("ci risk score")
            < 100
    );
}

#[test]
fn write_baseline_creates_stable_entries_with_owner() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(temp.path().join("a.ts"), "export const value = 1;\n").expect("write a");
    std::fs::write(temp.path().join("b.ts"), "export const value = 1;\n").expect("write b");
    let baseline = temp.path().join(".codehealth/baseline.json");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--write-baseline")
        .arg(&baseline)
        .arg("--baseline-owner")
        .arg("platform")
        .assert()
        .success();

    let raw = std::fs::read_to_string(baseline).expect("baseline exists");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("valid baseline");
    let entries = json["entries"].as_array().expect("entries");

    assert_eq!(json["schemaVersion"], "1.0.0");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["ruleId"], "duplicate.exact.file");
    assert_eq!(entries[0]["owner"], "platform");
    assert!(
        entries[0]["fingerprint"]
            .as_str()
            .expect("fingerprint")
            .len()
            >= 64
    );
    assert!(entries[0]["firstSeen"].as_u64().expect("first seen") > 0);
    assert_eq!(
        entries[0]["relatedLocations"]
            .as_array()
            .expect("related")
            .len(),
        2
    );
}

#[test]
fn ci_allows_existing_findings_and_fails_new_high_findings() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(temp.path().join("a.ts"), "export const value = 1;\n").expect("write a");
    std::fs::write(temp.path().join("b.ts"), "export const value = 1;\n").expect("write b");
    let baseline = temp.path().join(".codehealth/baseline.json");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--write-baseline")
        .arg(&baseline)
        .assert()
        .success();

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("ci")
        .arg(temp.path())
        .arg("--baseline")
        .arg(&baseline)
        .arg("--fail-on")
        .arg("new-high")
        .assert()
        .success();

    std::fs::write(temp.path().join("c.ts"), "export const other = 2;\n").expect("write c");
    std::fs::write(temp.path().join("d.ts"), "export const other = 2;\n").expect("write d");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("ci")
        .arg(temp.path())
        .arg("--baseline")
        .arg(&baseline)
        .arg("--fail-on")
        .arg("new-high")
        .assert()
        .failure()
        .code(1)
        .stdout(contains("New findings: 1"));
}

#[test]
fn fixed_findings_are_reported_against_baseline() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(temp.path().join("a.ts"), "export const value = 1;\n").expect("write a");
    std::fs::write(temp.path().join("b.ts"), "export const value = 1;\n").expect("write b");
    let baseline = temp.path().join(".codehealth/baseline.json");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--write-baseline")
        .arg(&baseline)
        .assert()
        .success();
    std::fs::remove_file(temp.path().join("b.ts")).expect("remove duplicate");

    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--baseline")
        .arg(&baseline)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid json");

    assert_eq!(json["metrics"]["baseline"]["fixedFindings"], 1);
    assert_eq!(
        json["metrics"]["baseline"]["fixed"]
            .as_array()
            .expect("fixed")
            .len(),
        1
    );
}

#[test]
fn formatting_only_changes_do_not_create_new_ci_findings() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(temp.path().join("a.ts"), "export const value = 1;\n").expect("write a");
    std::fs::write(temp.path().join("b.ts"), "export const value = 1;\n").expect("write b");
    let baseline = temp.path().join(".codehealth/baseline.json");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--write-baseline")
        .arg(&baseline)
        .assert()
        .success();
    std::fs::write(
        temp.path().join("b.ts"),
        "export   const   value    =    1;\n\n",
    )
    .expect("format b");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("ci")
        .arg(temp.path())
        .arg("--baseline")
        .arg(&baseline)
        .arg("--fail-on")
        .arg("new-high")
        .assert()
        .success()
        .stdout(contains("New findings: 0"));
}

#[test]
fn moved_duplicate_group_is_changed_not_new() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(temp.path().join("a.ts"), "export const value = 1;\n").expect("write a");
    std::fs::write(temp.path().join("b.ts"), "export const value = 1;\n").expect("write b");
    let baseline = temp.path().join(".codehealth/baseline.json");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--write-baseline")
        .arg(&baseline)
        .assert()
        .success();
    std::fs::rename(temp.path().join("b.ts"), temp.path().join("c.ts")).expect("rename b");

    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--baseline")
        .arg(&baseline)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid json");

    assert_eq!(json["metrics"]["baseline"]["newFindings"], 0);
    assert_eq!(json["metrics"]["baseline"]["changedFindings"], 1);
    assert_eq!(json["findings"][0]["baselineStatus"], "changed");
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
fn style_safe_autofix_dry_run_does_not_write() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("vote.ts");
    let before = r#"
function canVote(person) {
  if (person.age >= 18) return true;
  return false;
}
"#;
    std::fs::write(&file, before).expect("write ts");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--fix-safe")
        .arg("--dry-run")
        .assert()
        .success()
        .stderr(contains("Would apply 1 safe edits"));

    assert_eq!(std::fs::read_to_string(file).expect("read ts"), before);
}

#[test]
fn style_safe_autofix_rewrites_typescript_boolean_and_arrow() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("vote.ts");
    std::fs::write(
        &file,
        r#"
function canVote(person) {
  if (person.age >= 18) return true;
  return false;
}

const isAdult = (user) => {
  return user.age >= 18;
};
"#,
    )
    .expect("write ts");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--fix-safe")
        .assert()
        .success()
        .stderr(contains("Applied 2 safe edits"));

    let after = std::fs::read_to_string(file).expect("read ts");
    assert!(after.contains("return person.age >= 18;"));
    assert!(after.contains("const isAdult = (user) => user.age >= 18;"));
    assert!(!after.contains("return false;"));
}

#[test]
fn style_safe_autofix_rewrites_python_and_rust_boolean_returns() {
    let temp = tempfile::tempdir().expect("tempdir");
    let python = temp.path().join("policy.py");
    let rust = temp.path().join("lib.rs");
    std::fs::write(
        &python,
        r#"
def is_adult(user):
    if user.age >= 18:
        return True
    return False
"#,
    )
    .expect("write python");
    std::fs::write(
        &rust,
        r#"
fn is_adult(user: User) -> bool {
    if user.age >= 18 {
        true
    } else {
        false
    }
}
"#,
    )
    .expect("write rust");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--fix-safe")
        .assert()
        .success()
        .stderr(contains("Applied 2 safe edits"));

    assert!(std::fs::read_to_string(python)
        .expect("read python")
        .contains("return user.age >= 18"));
    assert!(std::fs::read_to_string(rust)
        .expect("read rust")
        .contains("user.age >= 18"));
}

#[test]
fn style_json_report_includes_fix_metadata() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("vote.ts"),
        "function canVote(person) {\n  if (person.age >= 18) return true;\n  return false;\n}\n",
    )
    .expect("write ts");

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
    let finding = json["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["ruleId"] == "style.boolean_return_simplifiable")
        .expect("style finding");

    assert_eq!(finding["autofix"], "safe");
    assert_eq!(finding["fixes"][0]["applicability"], "machine_applicable");
    assert_eq!(
        finding["fixes"][0]["edits"][0]["replacement"],
        "  return person.age >= 18;"
    );
}

#[test]
fn typescript_style_suggestion_rules_are_reported() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("style.ts"),
        r#"
function branch(a, b, c, d) {
  if (a) { return 1; } else { return 2; }
  if (a && b && c && d) {
    if (b) return 3;
  }
  const one = "shared-literal";
  const two = "shared-literal";
  const three = "shared-literal";
  const four = "shared-literal";
}
"#,
    )
    .expect("write ts");

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
    let rules = finding_rule_ids(&output);

    assert!(rules.contains(&"style.unnecessary_else_after_return".to_string()));
    assert!(rules.contains(&"style.nested_conditional".to_string()));
    assert!(rules.contains(&"style.complex_condition".to_string()));
    assert!(rules.contains(&"style.duplicated_literal".to_string()));
}

#[test]
fn python_and_rust_style_suggestion_rules_are_reported() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("validators.py"),
        r#"
def left(value):
    if not value:
        raise ValueError("missing")

def right(item):
    if not item:
        raise ValueError("missing")

def risky():
    try:
        work()
    except Exception:
        pass
"#,
    )
    .expect("write python");
    std::fs::write(
        temp.path().join("policy.rs"),
        r#"
fn repeated(value: Option<i32>, flag: i32) -> i32 {
    match flag {
        1 => value.unwrap(),
        2 => value.unwrap(),
        _ => 0,
    }
}

fn manual(value: Option<i32>) -> i32 {
    match value {
        Some(inner) => inner,
        None => 0,
    }
}

fn unwraps(a: Option<i32>, b: Option<i32>, c: Option<i32>) -> i32 {
    a.unwrap() + b.unwrap() + c.unwrap()
}
"#,
    )
    .expect("write rust");

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
    let rules = finding_rule_ids(&output);

    assert!(rules.contains(&"python.broad_exception".to_string()));
    assert!(rules.contains(&"python.repeated_validation_logic".to_string()));
    assert!(rules.contains(&"rust.duplicate_match_arm_body".to_string()));
    assert!(rules.contains(&"rust.manual_result_option_pattern".to_string()));
    assert!(rules.contains(&"rust.repeated_unwrap_policy".to_string()));
}

#[test]
fn suggestion_only_style_findings_are_not_applied_by_fix_safe() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("risky.py");
    let before = r#"
def risky():
    try:
        work()
    except Exception:
        pass
"#;
    std::fs::write(&file, before).expect("write python");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--fix-safe")
        .assert()
        .success()
        .stderr(predicate::str::is_empty());

    assert_eq!(std::fs::read_to_string(file).expect("read python"), before);
}

fn finding_rule_ids(output: &[u8]) -> Vec<String> {
    let json: serde_json::Value = serde_json::from_slice(output).expect("valid json");
    json["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|finding| finding["ruleId"].as_str().map(str::to_string))
        .collect()
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
        .find(|finding| finding["ruleId"] == "duplicate.exact.body")
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
fn scan_reports_structural_typescript_duplicates_after_parameter_renaming() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("math.ts"),
        r#"
export function add(x: number, y: number): number {
  return x + y;
}

export function sum(a: number, b: number): number {
  return a + b;
}
"#,
    )
    .expect("write ts");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("MEDIUM  duplicate.structural.function"))
        .stdout(contains("Symbols: add, sum"))
        .stdout(contains("Domain warning"));
}

#[test]
fn scan_reports_structural_python_member_duplicates_with_domain_warning() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("policy.py"),
        r#"
def is_adult(user):
    return user.age >= 18

def can_vote(person):
    return person.age >= 18
"#,
    )
    .expect("write python");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(contains("MEDIUM  duplicate.structural.function"))
        .stdout(contains("Symbols: can_vote, is_adult"))
        .stdout(contains(
            "same shape can still represent intentionally separate behavior",
        ));
}

#[test]
fn structural_duplicates_do_not_flag_tiny_trivial_bodies_by_default() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("tiny.ts"),
        r#"
export function left(): boolean {
  return true;
}

export function right(): boolean {
  return true;
}
"#,
    )
    .expect("write ts");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--color")
        .arg("never")
        .assert()
        .success()
        .stdout(predicate::str::contains("duplicate.structural.function").not());
}

#[test]
fn config_can_disable_structural_duplicates() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [duplication]
            detect_exact = false
            detect_names = false
            detect_structural = false
        "#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("math.ts"),
        r#"
export function add(x: number, y: number): number {
  return x + y;
}

export function sum(a: number, b: number): number {
  return a + b;
}
"#,
    )
    .expect("write ts");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("scan")
        .arg(temp.path())
        .arg("--config")
        .arg(config)
        .assert()
        .success()
        .stdout(contains("Findings: 0"));
}

#[test]
fn structural_duplicate_json_metadata_is_stable() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("math.ts"),
        r#"
export function add(x: number, y: number): number {
  return x + y;
}

export function sum(a: number, b: number): number {
  return a + b;
}
"#,
    )
    .expect("write ts");

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
    let structural = json["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .find(|finding| finding["ruleId"] == "duplicate.structural.function")
        .expect("structural finding");

    assert_eq!(structural["metadata"]["names_differ"], true);
    assert_eq!(structural["metadata"]["parameter_count"], 2);
    assert!(structural["metadata"]["canonical_hash"].as_str().is_some());
    assert!(
        structural["metadata"]["node_count"]
            .as_u64()
            .expect("node count")
            >= 5
    );
    assert_eq!(
        structural["metadata"]["symbol_names"],
        serde_json::json!(["add", "sum"])
    );
}

#[test]
fn debug_canonical_explains_identifier_slots_and_member_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("policy.ts");
    std::fs::write(
        &file,
        r#"
export function isAdult(user: { age: number }): boolean {
  return user.age >= 18;
}
"#,
    )
    .expect("write ts");
    let mut command = Command::cargo_bin("codehealth").expect("binary exists");

    command
        .arg("debug")
        .arg("canonical")
        .arg(&file)
        .arg("--symbol")
        .arg("isAdult")
        .assert()
        .success()
        .stdout(contains("Canonical hash"))
        .stdout(contains("user -> PARAM_0"))
        .stdout(contains("PARAM_0.age"));
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
fn sarif_html_and_markdown_formats_render() {
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

    let mut markdown = Command::cargo_bin("codehealth").expect("binary exists");
    markdown
        .arg("scan")
        .arg(fixture("duplicates"))
        .arg("--format")
        .arg("markdown")
        .assert()
        .success()
        .stdout(contains("# Code Health Summary"));
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
            detect_structural = false
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
            "duplicate.structural.function" = "off"
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
            detect_structural = false
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
            "duplicate.structural.function" = "off"
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
