use codehealth_config::CodehealthConfig;
use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, Severity,
    SourceSpan,
};
use codehealth_rules::{RUST_CLIPPY_RUN_FAILED, RUST_CLIPPY_UNAVAILABLE};
use codehealth_workspace::{WorkspaceFile, WorkspaceMetadata};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

pub fn run_clippy_checks(
    config: &CodehealthConfig,
    root: &Path,
    metadata: &WorkspaceMetadata,
    files: &[WorkspaceFile],
) -> Vec<Finding> {
    if !config.rust.enabled || !files.iter().any(|file| file.language.name == "rust") {
        return Vec::new();
    }
    if metadata.rust.cargo_tomls.is_empty() {
        return vec![tool_finding(
            root,
            RUST_CLIPPY_UNAVAILABLE,
            "Optional Clippy integration was requested, but no Cargo.toml was discovered.",
            "Run from a Rust workspace or disable Clippy integration for this scan.",
            None,
        )];
    }

    let runs = clippy_runs(root, &metadata.rust.cargo_tomls);
    let mut findings = Vec::new();
    for manifest in runs {
        let manifest_dir = manifest.as_ref().and_then(|path| path.parent());
        let mut args = config.rust.clippy_args.clone();
        if let Some(manifest) = &manifest {
            if !args.iter().any(|arg| arg == "--manifest-path") {
                args.push("--manifest-path".to_string());
                args.push(manifest.to_string_lossy().to_string());
            }
        }
        let output = Command::new(&config.rust.clippy_command)
            .args(&args)
            .current_dir(root)
            .output();
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let before = findings.len();
                findings.extend(parse_clippy_messages(root, manifest_dir, &stdout));
                findings.extend(parse_clippy_messages(root, manifest_dir, &stderr));
                if !output.status.success() && findings.len() == before {
                    findings.push(tool_finding(
                        root,
                        RUST_CLIPPY_RUN_FAILED,
                        "Optional Clippy integration exited unsuccessfully before producing usable diagnostics.",
                        "Run the configured Clippy command locally to inspect build errors, or disable Clippy integration for this scan.",
                        Some(format!("exit_status={}", output.status)),
                    ));
                }
            }
            Err(error) => {
                findings.push(tool_finding(
                    root,
                    RUST_CLIPPY_UNAVAILABLE,
                    "Optional Clippy integration was requested, but the configured command could not be launched.",
                    "Install Cargo/Clippy or update rust.clippy_command in codehealth.toml.",
                    Some(error.to_string()),
                ));
            }
        }
    }
    findings
}

fn clippy_runs(root: &Path, cargo_tomls: &[PathBuf]) -> Vec<Option<PathBuf>> {
    let root_manifest = root.join("Cargo.toml");
    if cargo_tomls.iter().any(|path| path == &root_manifest) {
        vec![None]
    } else {
        cargo_tomls.iter().cloned().map(Some).collect()
    }
}

fn parse_clippy_messages(root: &Path, manifest_dir: Option<&Path>, raw: &str) -> Vec<Finding> {
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value["reason"] == "compiler-message")
        .filter_map(|value| clippy_finding_from_message(root, manifest_dir, &value["message"]))
        .collect()
}

fn clippy_finding_from_message(
    root: &Path,
    manifest_dir: Option<&Path>,
    message: &Value,
) -> Option<Finding> {
    let code = message
        .get("code")
        .and_then(|code| code.get("code"))
        .and_then(Value::as_str)?;
    if !code.starts_with("clippy::") {
        return None;
    }
    let rule_id = format!("rust.clippy.{}", code.trim_start_matches("clippy::"));
    let message_text = message
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Clippy diagnostic")
        .to_string();
    let level = message
        .get("level")
        .and_then(Value::as_str)
        .unwrap_or("warning");
    let span = primary_span(message)?;
    let file = resolve_clippy_path(root, manifest_dir, span.file_name);
    let start = span.byte_start.unwrap_or(0);
    let end = span
        .byte_end
        .unwrap_or(start.saturating_add(1))
        .max(start + 1);
    let stable = stable_hash(&format!(
        "{rule_id}|{}|{}|{}",
        normalize_path(root, &file),
        start,
        collapse_whitespace(&message_text)
    ));
    let mut metadata = BTreeMap::new();
    metadata.insert("clippy_code".to_string(), serde_json::json!(code));
    metadata.insert("clippy_level".to_string(), serde_json::json!(level));
    metadata.insert("source".to_string(), serde_json::json!("clippy"));
    Some(Finding {
        finding_id: format!("{rule_id}:{}", &stable[..12]),
        baseline_key: stable,
        rule_id,
        kind: FindingKind::Rust,
        severity: clippy_severity(level),
        confidence: Confidence::High,
        message: format!("Clippy: {message_text}"),
        locations: vec![FindingLocation {
            path: file,
            span: Some(SourceSpan { start, end }),
            start: Some(Location {
                line: span.line_start.unwrap_or(1),
                column: span.column_start.unwrap_or(1),
                byte_offset: start,
            }),
            language: Some("rust".to_string()),
        }],
        language: Some("rust".to_string()),
        framework: None,
        explanation: "This diagnostic came from optional cargo clippy integration.".to_string(),
        remediation: message
            .get("rendered")
            .and_then(Value::as_str)
            .map(|rendered| rendered.trim().to_string())
            .filter(|rendered| !rendered.is_empty())
            .unwrap_or_else(|| {
                "Review the Clippy diagnostic and apply the suggested Rust idiom when appropriate."
                    .to_string()
            }),
        detection_reason: "cargo clippy emitted a JSON compiler-message diagnostic.".to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: "Clippy suggestions are not auto-applied by codehealth in this phase."
            .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    })
}

#[derive(Debug, Clone, Copy)]
struct ClippySpan<'a> {
    file_name: &'a str,
    byte_start: Option<usize>,
    byte_end: Option<usize>,
    line_start: Option<usize>,
    column_start: Option<usize>,
}

fn primary_span(message: &Value) -> Option<ClippySpan<'_>> {
    message
        .get("spans")
        .and_then(Value::as_array)?
        .iter()
        .find(|span| {
            span.get("is_primary")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .or_else(|| message.get("spans")?.as_array()?.first())
        .and_then(|span| {
            Some(ClippySpan {
                file_name: span.get("file_name")?.as_str()?,
                byte_start: span
                    .get("byte_start")
                    .and_then(Value::as_u64)
                    .map(|value| value as usize),
                byte_end: span
                    .get("byte_end")
                    .and_then(Value::as_u64)
                    .map(|value| value as usize),
                line_start: span
                    .get("line_start")
                    .and_then(Value::as_u64)
                    .map(|value| value as usize),
                column_start: span
                    .get("column_start")
                    .and_then(Value::as_u64)
                    .map(|value| value as usize),
            })
        })
}

fn resolve_clippy_path(root: &Path, manifest_dir: Option<&Path>, file_name: &str) -> PathBuf {
    let path = PathBuf::from(file_name);
    if path.is_absolute() {
        path
    } else {
        manifest_dir.unwrap_or(root).join(path)
    }
}

fn tool_finding(
    root: &Path,
    rule_id: &'static str,
    message: &str,
    remediation: &str,
    detail: Option<String>,
) -> Finding {
    let stable = stable_hash(&format!(
        "{rule_id}|{}|{}",
        root.display(),
        detail.as_deref().unwrap_or_default()
    ));
    let mut metadata = BTreeMap::new();
    metadata.insert("source".to_string(), serde_json::json!("clippy"));
    if let Some(detail) = detail {
        metadata.insert("detail".to_string(), serde_json::json!(detail));
    }
    Finding {
        finding_id: format!("{rule_id}:{}", &stable[..12]),
        baseline_key: stable,
        rule_id: rule_id.to_string(),
        kind: FindingKind::Rust,
        severity: Severity::Info,
        confidence: Confidence::High,
        message: message.to_string(),
        locations: vec![FindingLocation {
            path: root.to_path_buf(),
            span: None,
            start: None,
            language: Some("rust".to_string()),
        }],
        language: Some("rust".to_string()),
        framework: None,
        explanation:
            "Optional Clippy integration is nonfatal and reports tool availability as a finding."
                .to_string(),
        remediation: remediation.to_string(),
        detection_reason: "The configured Clippy command could not produce parsed diagnostics."
            .to_string(),
        autofix: AutofixSafety::Unavailable,
        autofix_explanation: "There is no code fix for tool availability.".to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn clippy_severity(level: &str) -> Severity {
    match level {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" | "help" => Severity::Info,
        _ => Severity::Low,
    }
}

fn stable_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
}

fn normalize_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clippy_json_diagnostics() {
        let raw = r#"{"reason":"compiler-message","message":{"message":"used unwrap on an Option value","code":{"code":"clippy::unwrap_used"},"level":"warning","spans":[{"file_name":"src/lib.rs","byte_start":10,"byte_end":20,"line_start":2,"column_start":5,"is_primary":true}],"rendered":"warning: used unwrap"}} "#;
        let root = Path::new("C:/repo");

        let findings = parse_clippy_messages(root, None, raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "rust.clippy.unwrap_used");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].locations[0].path, root.join("src/lib.rs"));
    }
}
