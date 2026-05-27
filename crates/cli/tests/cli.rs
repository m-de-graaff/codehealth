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
fn react_health_rules_report_component_risks() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .expect("write package json");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [rule_options."react.large_component"]
            max_lines = 8

            [rule_options."react.too_many_props"]
            max_params = 2

            [rule_options."react.deeply_nested_jsx"]
            max_depth = 2

            [rule_options."react.prop_drilling_candidate"]
            max_depth = 2

            [rule_options."react.large_context_provider"]
            max_context_values = 2

            [rule_options."react.component_too_many_responsibilities"]
            max_responsibilities = 3
        "#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("Dashboard.tsx"),
        r#"
import React, { useEffect, useState } from "react";

const Context = React.createContext(null);
type Props = { enabled: boolean; items: Array<{ id: string; name: string }>; user: string; token: string; org: string };

export function Dashboard(props: Props) {
  const [value, setValue] = useState(0);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    setReady(props.enabled);
    setValue(props.items.length);
  }, [props.enabled, props.items]);
  function InlineWidget() {
    return <span>{value}</span>;
  }
  const load = () => fetch("/api");
  const rows = props.items.map((item, index) => <li key={index}><span>{item.name}</span></li>);
  return (
    <Context.Provider value={{value, ready, setValue, setReady}}>
      <section onClick={() => setReady(true)} onMouseEnter={() => load()} onKeyDown={() => setValue(2)} onFocus={() => setReady(false)}>
        <div>
          <main>
            <article>
              <InlineWidget user={props.user} token={props.token} org={props.org} />
              <Child user={props.user} token={props.token} org={props.org} />
              <Other user={props.user} token={props.token} org={props.org} />
              {props.items.map((item) => <div>{item.name}</div>)}
              {rows}
            </article>
          </main>
        </div>
      </section>
    </Context.Provider>
  );
}
"#,
    )
    .expect("write tsx");

    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--config")
        .arg(config)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rules = finding_rule_ids(&output);

    for expected in [
        "react.large_component",
        "react.too_many_props",
        "react.deeply_nested_jsx",
        "react.unnecessary_effect_candidate",
        "react.derived_state_candidate",
        "react.inline_component_inside_render",
        "react.unstable_list_key",
        "react.missing_key",
        "react.prop_drilling_candidate",
        "react.large_context_provider",
        "react.mixed_data_fetching_and_rendering",
        "react.component_too_many_responsibilities",
    ] {
        assert!(rules.contains(&expected.to_string()), "missing {expected}");
    }
}

#[test]
fn react_duplicate_component_shape_includes_related_locations() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .expect("write package json");
    std::fs::write(
        temp.path().join("Cards.tsx"),
        r#"
export function UserCard({ user }) {
  return <section className="card"><h2>{user.name}</h2><p>{user.email}</p></section>;
}

export function AccountCard({ account }) {
  return <section className="card"><h2>{account.name}</h2><p>{account.email}</p></section>;
}
"#,
    )
    .expect("write tsx");

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
        .find(|finding| finding["ruleId"] == "react.duplicate_component_shape")
        .expect("duplicate component shape finding");

    assert_eq!(finding["locations"].as_array().expect("locations").len(), 2);
    assert!(finding["metadata"]["canonical_hash"].as_str().is_some());
}

#[test]
fn react_safe_autofix_removes_redundant_fragment() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .expect("write package json");
    let file = temp.path().join("Card.tsx");
    std::fs::write(
        &file,
        r#"
export function Card() {
  return <><div className="card" /></>;
}
"#,
    )
    .expect("write tsx");

    Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--fix-safe")
        .assert()
        .success()
        .stderr(contains("Applied 1 safe edits"));

    let after = std::fs::read_to_string(file).expect("read tsx");
    assert!(after.contains(r#"return <div className="card" />;"#));
    assert!(!after.contains("<>"));
}

#[test]
fn react_rules_can_be_disabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .expect("write package json");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
            [react]
            enabled = false

            [rule_options."react.large_component"]
            max_lines = 1
        "#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("App.tsx"),
        r#"
export function App() {
  return (
    <main>
      <section>
        <div>
          <span>Disabled</span>
        </div>
      </section>
    </main>
  );
}
"#,
    )
    .expect("write tsx");

    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(temp.path())
        .arg("--config")
        .arg(config)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rules = finding_rule_ids(&output);

    assert!(!rules.iter().any(|rule| rule.starts_with("react.")));
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
    assert!(rules.contains(&"rust.repeated_match_arm_body".to_string()));
    assert!(rules.contains(&"rust.manual_option_result_pattern_candidate".to_string()));
    assert!(rules.contains(&"rust.suspicious_unwrap_policy".to_string()));
}

#[test]
fn rust_health_rules_report_duplication_and_maintainability() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
[rust]
max_function_lines = 4
max_params = 3
max_unwraps = 1
max_match_depth = 1

[rule_options."rust.duplicate_free_function"]
min_lines = 1
min_tokens = 1

[rule_options."rust.duplicate_impl_method"]
min_lines = 1
min_tokens = 1

[rule_options."rust.duplicate_trait_method_implementation"]
min_lines = 1
min_tokens = 1

[rule_options."rust.repeated_conversion_function"]
min_lines = 1
min_tokens = 1

[rule_options."rust.repeated_serde_glue"]
min_lines = 1
min_tokens = 1

[rule_options."rust.large_enum_variant_logic"]
max_params = 3
"#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("policy.rs"),
        r#"
pub enum Event {
    Empty,
    Huge(i32, i32, i32, i32, i32),
}

pub fn too_many(a: i32, b: i32, c: i32, d: i32) -> i32 {
    a + b + c + d
}

pub fn large() -> i32 {
    let mut total = 0;
    total += 1;
    total += 2;
    total += 3;
    total
}

pub fn duplicate_left(value: Option<i32>) -> i32 {
    let inner = value.unwrap();
    inner + 1
}

pub fn duplicate_right(item: Option<i32>) -> i32 {
    let inner = item.unwrap();
    inner + 1
}

pub struct Repo;

impl Repo {
    pub fn save_left(&self, value: Option<i32>) -> i32 {
        let inner = value.unwrap();
        inner + 1
    }

    pub fn save_right(&self, item: Option<i32>) -> i32 {
        let inner = item.unwrap();
        inner + 1
    }
}

pub trait Load {
    fn load(&self, value: Option<i32>) -> i32;
}

pub struct A;
pub struct B;

impl Load for A {
    fn load(&self, value: Option<i32>) -> i32 {
        let inner = value.unwrap();
        inner + 1
    }
}

impl Load for B {
    fn load(&self, item: Option<i32>) -> i32 {
        let inner = item.unwrap();
        inner + 1
    }
}

pub fn repeated_match(value: i32, item: Option<i32>) -> i32 {
    match value {
        1 => item.unwrap(),
        2 => item.unwrap(),
        _ => 0,
    }
}

pub fn unwraps(a: Option<i32>, b: Option<i32>) -> i32 {
    a.unwrap() + b.unwrap()
}

pub fn bad_expect(value: Option<i32>) -> i32 {
    value.expect("failed")
}

pub fn manual(value: Option<i32>) -> i32 {
    match value {
        Some(inner) => inner,
        None => 0,
    }
}

pub fn nested(value: Result<Option<i32>, ()>) -> i32 {
    match value {
        Ok(inner) => match inner {
            Some(number) => number,
            None => 0,
        },
        Err(_) => 0,
    }
}

pub fn map_left(value: Result<i32, Error>) -> Result<i32, AppError> {
    value.map_err(|err| AppError::from(err))
}

pub fn map_right(value: Result<i32, Error>) -> Result<i32, AppError> {
    value.map_err(|err| AppError::from(err))
}

pub fn result_left(value: Result<i32, Error>) -> i32 {
    match value {
        Ok(inner) => inner,
        Err(_) => 0,
    }
}

pub fn result_right(item: Result<i32, Error>) -> i32 {
    match item {
        Ok(inner) => inner,
        Err(_) => 0,
    }
}

pub fn from_left(value: User) -> Dto {
    Dto { id: value.id }
}

pub fn from_right(account: Account) -> Dto {
    Dto { id: account.id }
}

pub fn validate_left(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::Missing);
    }
    Ok(())
}

pub fn validate_right(item: &str) -> Result<(), Error> {
    if item.is_empty() {
        return Err(Error::Missing);
    }
    Ok(())
}

pub fn serialize_left(value: &User) -> Result<String, Error> {
    serde_json::to_string(value).map_err(|err| Error::from(err))
}

pub fn serialize_right(value: &Account) -> Result<String, Error> {
    serde_json::to_string(value).map_err(|err| Error::from(err))
}
"#,
    )
    .expect("write rust");

    let ids = finding_ids(&scan_json_with_config(temp.path(), &config));

    assert!(ids.contains(&"rust.large_function".to_string()));
    assert!(ids.contains(&"rust.too_many_parameters".to_string()));
    assert!(ids.contains(&"rust.duplicate_free_function".to_string()));
    assert!(ids.contains(&"rust.duplicate_impl_method".to_string()));
    assert!(ids.contains(&"rust.duplicate_trait_method_implementation".to_string()));
    assert!(ids.contains(&"rust.repeated_match_arm_body".to_string()));
    assert!(ids.contains(&"rust.suspicious_unwrap_policy".to_string()));
    assert!(ids.contains(&"rust.expect_without_context".to_string()));
    assert!(ids.contains(&"rust.repeated_error_mapping".to_string()));
    assert!(ids.contains(&"rust.manual_option_result_pattern_candidate".to_string()));
    assert!(ids.contains(&"rust.deeply_nested_match".to_string()));
    assert!(ids.contains(&"rust.large_enum_variant_logic".to_string()));
    assert!(ids.contains(&"rust.repeated_result_handling".to_string()));
    assert!(ids.contains(&"rust.repeated_conversion_function".to_string()));
    assert!(ids.contains(&"rust.repeated_validation_logic".to_string()));
    assert!(ids.contains(&"rust.repeated_serde_glue".to_string()));
}

#[test]
fn rust_clippy_unavailable_is_nonfatal_when_requested() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join("src")).expect("create src");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
[rust]
clippy_enabled = true
clippy_command = "definitely-not-codehealth-clippy"
"#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("Cargo.toml"),
        r#"
[package]
name = "sample"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("write cargo");
    std::fs::write(
        temp.path().join("src/lib.rs"),
        "pub fn value() -> i32 { 1 }\n",
    )
    .expect("write rust");

    let ids = finding_ids(&scan_json_with_config(temp.path(), &config));

    assert!(ids.contains(&"rust.clippy_unavailable".to_string()));
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

fn scan_json(path: &Path) -> serde_json::Value {
    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(path)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("valid json")
}

fn scan_json_with_config(path: &Path, config: &Path) -> serde_json::Value {
    let output = Command::cargo_bin("codehealth")
        .expect("binary exists")
        .arg("scan")
        .arg(path)
        .arg("--config")
        .arg(config)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("valid json")
}

fn finding_ids(json: &serde_json::Value) -> Vec<String> {
    json["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|finding| finding["ruleId"].as_str().map(str::to_string))
        .collect()
}

fn finding_by_rule<'a>(json: &'a serde_json::Value, rule_id: &str) -> &'a serde_json::Value {
    json["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["ruleId"] == rule_id)
        .unwrap_or_else(|| panic!("missing finding {rule_id}"))
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
fn fastapi_duplicate_routes_include_resolved_prefix_and_related_locations() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("app.py"),
        r#"
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter(prefix="/users")

@router.get("/{user_id}", response_model=dict[str, int])
async def get_user(user_id: int) -> dict[str, int]:
    return {"id": user_id}

@router.get("/{user_id}", response_model=dict[str, int])
async def read_user(user_id: int) -> dict[str, int]:
    return {"id": user_id}

app.include_router(router, prefix="/api")
"#,
    )
    .expect("write fastapi app");

    let json = scan_json(temp.path());
    let duplicate = finding_by_rule(&json, "fastapi.duplicate.route");

    assert_eq!(duplicate["metadata"]["path"], "/api/users/{user_id}");
    assert_eq!(duplicate["metadata"]["raw_path"], "/{user_id}");
    assert_eq!(
        duplicate["locations"].as_array().expect("locations").len(),
        2
    );
    assert_eq!(
        duplicate["relatedLocations"]
            .as_array()
            .expect("related locations")
            .len(),
        1
    );
}

#[test]
fn fastapi_route_rules_report_async_blocking_and_contract_risks() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
[rule_options."fastapi.large_route_handler"]
max_lines = 4
"#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("app.py"),
        r#"
from fastapi import Depends, FastAPI, Security
import requests
import time

app = FastAPI()

def get_db():
    return None

def current_user():
    return "user"

@app.get("/users/{user_id}")
async def read_user(user_id: int, db=Depends(get_db), user=Security(current_user)):
    if user_id < 1:
        return {"error": "bad"}
    results = []
    for item in range(2):
        results.append(item)
    time.sleep(1)
    data = requests.get("https://example.com").json()
    users = db.query(User).all()
    try:
        audit(data)
    except Exception:
        pass
    return {"id": user_id, "users": users}
"#,
    )
    .expect("write fastapi app");

    let ids = finding_ids(&scan_json_with_config(temp.path(), &config));

    assert!(ids.contains(&"fastapi.blocking_call_in_async_route".to_string()));
    assert!(ids.contains(&"fastapi.requests_call_inside_async_route".to_string()));
    assert!(ids.contains(&"fastapi.sync_db_call_inside_async_route".to_string()));
    assert!(ids.contains(&"fastapi.missing_response_model".to_string()));
    assert!(ids.contains(&"fastapi.large_route_handler".to_string()));
    assert!(ids.contains(&"fastapi.business_logic_in_route".to_string()));
    assert!(ids.contains(&"fastapi.broad_exception_in_route".to_string()));
}

#[test]
fn fastapi_route_conflicts_and_repeated_dependency_patterns_are_reported() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("app.py"),
        r#"
from fastapi import Depends, FastAPI, Security

app = FastAPI()

def get_db():
    return None

def current_user():
    return "user"

@app.get("/users/{user_id}", response_model=dict[str, int])
async def read_user(user_id: int, db=Depends(get_db), user=Security(current_user)):
    return {"id": user_id}

@app.get("/users/{id}", response_model=dict[str, int])
async def read_user_alias(id: int, db=Depends(get_db), user=Security(current_user)):
    return {"id": id}

@app.get("/accounts/{account_id}", response_model=dict[str, int])
async def read_account(account_id: int, db=Depends(get_db), user=Security(current_user)):
    return {"id": account_id}
"#,
    )
    .expect("write fastapi app");

    let ids = finding_ids(&scan_json(temp.path()));

    assert!(ids.contains(&"fastapi.route_conflict".to_string()));
    assert!(ids.contains(&"fastapi.repeated_dependency_logic".to_string()));
    assert!(ids.contains(&"fastapi.repeated_auth_logic".to_string()));
}

#[test]
fn fastapi_pydantic_duplicate_model_suggestions_are_conservative() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("app.py"),
        r#"
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class UserPayload(BaseModel):
    name: str
    email: str
    age: int

class AccountPayload(BaseModel):
    name: str
    email: str
    age: int

class UserCreate(BaseModel):
    name: str
    email: str
    age: int

class UserResponse(BaseModel):
    name: str
    email: str
    age: int
"#,
    )
    .expect("write fastapi app");

    let json = scan_json(temp.path());
    let finding = finding_by_rule(&json, "fastapi.duplicated_pydantic_model");

    assert_eq!(finding["locations"].as_array().expect("locations").len(), 2);
    assert_eq!(
        finding["metadata"]["model_names"]
            .as_array()
            .expect("model names")
            .len(),
        2
    );
}

#[test]
fn fastapi_status_code_and_duplicate_route_logic_are_reported() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
[rule_options."fastapi.route_handler_duplicate_logic"]
min_lines = 3
"#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("app.py"),
        r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/users", response_model=dict)
async def create_user(payload: dict) -> dict:
    value = payload.get("id")
    if value:
        return {"id": value}
    return {"id": 1}

@app.post("/accounts", response_model=dict)
async def create_account(payload: dict) -> dict:
    value = payload.get("id")
    if value:
        return {"id": value}
    return {"id": 1}

@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    return {"deleted": user_id}
"#,
    )
    .expect("write fastapi app");

    let ids = finding_ids(&scan_json_with_config(temp.path(), &config));

    assert!(ids.contains(&"fastapi.inconsistent_status_code".to_string()));
    assert!(ids.contains(&"fastapi.route_handler_duplicate_logic".to_string()));
}

#[test]
fn fastapi_blocking_call_allowlist_suppresses_configured_pattern() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("codehealth.toml");
    std::fs::write(
        &config,
        r#"
[fastapi]
blocking_call_allowlist = ["time.sleep"]
blocking_call_patterns = ["time.sleep"]
"#,
    )
    .expect("write config");
    std::fs::write(
        temp.path().join("app.py"),
        r#"
from fastapi import FastAPI
import time

app = FastAPI()

@app.get("/slow")
async def slow():
    time.sleep(1)
    return {"ok": True}
"#,
    )
    .expect("write fastapi app");

    let ids = finding_ids(&scan_json_with_config(temp.path(), &config));

    assert!(!ids.contains(&"fastapi.blocking_call_in_async_route".to_string()));
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

            [react]
            enabled = false

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
