use codehealth_config::IntegrationsConfig;
use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, ScanResult,
    Severity, SourceSpan,
};
use codehealth_workspace::{ConfigFileKind, WorkspaceConfigFile, WorkspaceFile, WorkspaceMetadata};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

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

pub fn run_external_tools(
    config: &IntegrationsConfig,
    root: &Path,
    metadata: &WorkspaceMetadata,
    config_files: &[WorkspaceConfigFile],
    files: &[WorkspaceFile],
) -> Vec<Finding> {
    if !config.any_enabled() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let timeout = Duration::from_millis(config.timeout_ms);

    run_if_enabled(ConfiguredToolRun {
        findings: &mut findings,
        enabled: config.eslint,
        tool: ExternalTool::Eslint,
        command: &config.eslint_command,
        args: &config.eslint_args,
        roots: roots_for_tool(root, config_files, files, ExternalTool::Eslint),
        scan_root: root,
        timeout,
        fail_on_tool_error: config.fail_on_tool_error,
    });
    run_if_enabled(ConfiguredToolRun {
        findings: &mut findings,
        enabled: config.biome,
        tool: ExternalTool::Biome,
        command: &config.biome_command,
        args: &config.biome_args,
        roots: roots_for_tool(root, config_files, files, ExternalTool::Biome),
        scan_root: root,
        timeout,
        fail_on_tool_error: config.fail_on_tool_error,
    });
    run_if_enabled(ConfiguredToolRun {
        findings: &mut findings,
        enabled: config.tsc,
        tool: ExternalTool::Tsc,
        command: &config.tsc_command,
        args: &config.tsc_args,
        roots: roots_for_tool(root, config_files, files, ExternalTool::Tsc),
        scan_root: root,
        timeout,
        fail_on_tool_error: config.fail_on_tool_error,
    });
    run_if_enabled(ConfiguredToolRun {
        findings: &mut findings,
        enabled: config.ruff,
        tool: ExternalTool::Ruff,
        command: &config.ruff_command,
        args: &config.ruff_args,
        roots: roots_for_tool(root, config_files, files, ExternalTool::Ruff),
        scan_root: root,
        timeout,
        fail_on_tool_error: config.fail_on_tool_error,
    });
    run_if_enabled(ConfiguredToolRun {
        findings: &mut findings,
        enabled: config.mypy,
        tool: ExternalTool::Mypy,
        command: &config.mypy_command,
        args: &config.mypy_args,
        roots: roots_for_tool(root, config_files, files, ExternalTool::Mypy),
        scan_root: root,
        timeout,
        fail_on_tool_error: config.fail_on_tool_error,
    });
    run_if_enabled(ConfiguredToolRun {
        findings: &mut findings,
        enabled: config.pyright,
        tool: ExternalTool::Pyright,
        command: &config.pyright_command,
        args: &config.pyright_args,
        roots: roots_for_tool(root, config_files, files, ExternalTool::Pyright),
        scan_root: root,
        timeout,
        fail_on_tool_error: config.fail_on_tool_error,
    });
    run_if_enabled(ConfiguredToolRun {
        findings: &mut findings,
        enabled: config.semgrep,
        tool: ExternalTool::Semgrep,
        command: &config.semgrep_command,
        args: &config.semgrep_args,
        roots: roots_for_tool(root, config_files, files, ExternalTool::Semgrep),
        scan_root: root,
        timeout,
        fail_on_tool_error: config.fail_on_tool_error,
    });

    if config.cargo_check {
        for invocation in rust_invocations(
            root,
            &metadata.rust.cargo_tomls,
            ExternalTool::CargoCheck,
            &config.cargo_check_command,
            &config.cargo_check_args,
        ) {
            findings.extend(run_invocation(
                root,
                invocation,
                timeout,
                config.fail_on_tool_error,
            ));
        }
    }

    if config.clippy {
        let invocations = rust_invocations(
            root,
            &metadata.rust.cargo_tomls,
            ExternalTool::Clippy,
            &config.clippy_command,
            &config.clippy_args,
        );
        if invocations.is_empty() {
            findings.push(tool_failure_finding(
                root,
                ExternalTool::Clippy,
                FailureKind::Unavailable,
                "Optional Clippy integration was requested, but no Cargo.toml was discovered.",
                "Run from a Rust workspace or disable Clippy integration for this scan.",
                None,
                config.fail_on_tool_error,
            ));
        } else {
            for invocation in invocations {
                findings.extend(run_invocation(
                    root,
                    invocation,
                    timeout,
                    config.fail_on_tool_error,
                ));
            }
        }
    }

    dedupe_external_findings(findings)
}

pub fn merge_external_findings(findings: &mut Vec<Finding>, external_findings: Vec<Finding>) {
    for external_finding in dedupe_external_findings(external_findings) {
        let Some(primary) = external_finding.locations.first() else {
            findings.push(external_finding);
            continue;
        };
        let Some(existing) = findings.iter_mut().find(|finding| {
            finding.kind != FindingKind::ExternalTool
                && finding
                    .locations
                    .first()
                    .is_some_and(|location| locations_overlap(location, primary))
        }) else {
            findings.push(external_finding);
            continue;
        };

        let entry = existing
            .metadata
            .entry("external_overlaps".to_string())
            .or_insert_with(|| serde_json::json!([]));
        if let Some(values) = entry.as_array_mut() {
            values.push(serde_json::json!({
                "tool": external_finding
                    .metadata
                    .get("external_tool")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                "rule_id": external_finding.rule_id,
                "message": external_finding.message,
            }));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ExternalTool {
    Eslint,
    Biome,
    Tsc,
    Ruff,
    Mypy,
    Pyright,
    CargoCheck,
    Clippy,
    Semgrep,
}

impl ExternalTool {
    fn id(self) -> &'static str {
        match self {
            Self::Eslint => "eslint",
            Self::Biome => "biome",
            Self::Tsc => "tsc",
            Self::Ruff => "ruff",
            Self::Mypy => "mypy",
            Self::Pyright => "pyright",
            Self::CargoCheck => "cargo_check",
            Self::Clippy => "clippy",
            Self::Semgrep => "semgrep",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Eslint => "ESLint",
            Self::Biome => "Biome",
            Self::Tsc => "TypeScript compiler",
            Self::Ruff => "Ruff",
            Self::Mypy => "mypy",
            Self::Pyright => "Pyright",
            Self::CargoCheck => "cargo check",
            Self::Clippy => "Clippy",
            Self::Semgrep => "Semgrep",
        }
    }

    fn language(self) -> Option<&'static str> {
        match self {
            Self::Eslint | Self::Biome | Self::Tsc => Some("typescript"),
            Self::Ruff | Self::Mypy | Self::Pyright => Some("python"),
            Self::CargoCheck | Self::Clippy => Some("rust"),
            Self::Semgrep => None,
        }
    }
}

#[derive(Debug, Clone)]
struct ToolInvocation {
    tool: ExternalTool,
    command: String,
    args: Vec<String>,
    cwd: PathBuf,
    manifest_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ExternalDiagnostic {
    tool: ExternalTool,
    rule_code: String,
    severity: Severity,
    confidence: Confidence,
    message: String,
    path: PathBuf,
    line: Option<usize>,
    column: Option<usize>,
    byte_span: Option<SourceSpan>,
    external_severity: Option<String>,
    help: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum FailureKind {
    Unavailable,
    RunFailed,
}

struct ConfiguredToolRun<'a> {
    findings: &'a mut Vec<Finding>,
    enabled: bool,
    tool: ExternalTool,
    command: &'a str,
    args: &'a [String],
    roots: Vec<PathBuf>,
    scan_root: &'a Path,
    timeout: Duration,
    fail_on_tool_error: bool,
}

fn run_if_enabled(run: ConfiguredToolRun<'_>) {
    if !run.enabled {
        return;
    }

    for cwd in run.roots {
        let invocation = ToolInvocation {
            tool: run.tool,
            command: run.command.to_string(),
            args: run.args.to_vec(),
            cwd,
            manifest_dir: None,
        };
        run.findings.extend(run_invocation(
            run.scan_root,
            invocation,
            run.timeout,
            run.fail_on_tool_error,
        ));
    }
}

fn run_invocation(
    root: &Path,
    invocation: ToolInvocation,
    timeout: Duration,
    fail_on_tool_error: bool,
) -> Vec<Finding> {
    let output = run_command(
        &invocation.command,
        &invocation.args,
        &invocation.cwd,
        timeout,
    );
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let diagnostics = parse_tool_output(
                invocation.tool,
                root,
                &invocation.cwd,
                invocation.manifest_dir.as_deref(),
                &stdout,
                &stderr,
            );
            if !diagnostics.is_empty() {
                return diagnostics
                    .into_iter()
                    .map(|diagnostic| diagnostic_to_finding(root, &invocation.cwd, diagnostic))
                    .collect();
            }
            if !output.status.success() {
                return vec![tool_failure_finding(
                    root,
                    invocation.tool,
                    FailureKind::RunFailed,
                    &format!(
                        "Optional {} integration exited unsuccessfully before producing usable diagnostics.",
                        invocation.tool.display_name()
                    ),
                    &format!(
                        "Run the configured {} command locally to inspect the failure, or disable this integration for this scan.",
                        invocation.tool.display_name()
                    ),
                    Some(format!("exit_status={}", output.status)),
                    fail_on_tool_error,
                )];
            }
            Vec::new()
        }
        Err(CommandRunError::Launch(error)) => vec![tool_failure_finding(
            root,
            invocation.tool,
            FailureKind::Unavailable,
            &format!(
                "Optional {} integration was requested, but the configured command could not be launched.",
                invocation.tool.display_name()
            ),
            &format!(
                "Install {}, update its command override in codehealth.toml, or disable this integration.",
                invocation.tool.display_name()
            ),
            Some(error),
            fail_on_tool_error,
        )],
        Err(CommandRunError::Timeout) => vec![tool_failure_finding(
            root,
            invocation.tool,
            FailureKind::RunFailed,
            &format!(
                "Optional {} integration timed out before producing usable diagnostics.",
                invocation.tool.display_name()
            ),
            "Increase integrations.timeout_ms, narrow the project scope, or disable this integration."
                .to_string()
                .as_str(),
            Some(format!("timeout_ms={}", timeout.as_millis())),
            fail_on_tool_error,
        )],
    }
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum CommandRunError {
    Launch(String),
    Timeout,
}

fn run_command(
    command: &str,
    args: &[String],
    cwd: &Path,
    timeout: Duration,
) -> Result<CommandOutput, CommandRunError> {
    let mut child = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CommandRunError::Launch(error.to_string()))?;

    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| CommandRunError::Launch(error.to_string()))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|error| CommandRunError::Launch(error.to_string()))?;
            return Ok(CommandOutput {
                status: output.status,
                stdout: output.stdout,
                stderr: output.stderr,
            });
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CommandRunError::Timeout);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn roots_for_tool(
    root: &Path,
    config_files: &[WorkspaceConfigFile],
    files: &[WorkspaceFile],
    tool: ExternalTool,
) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    for config_file in config_files {
        if config_kind_matches_tool(config_file.kind, tool) {
            if let Some(parent) = config_file.path.parent() {
                roots.insert(parent.to_path_buf());
            }
        }
    }

    if roots.is_empty() && files.iter().any(|file| file_matches_tool(file, tool)) {
        roots.insert(root.to_path_buf());
    }

    roots.into_iter().collect()
}

fn config_kind_matches_tool(kind: ConfigFileKind, tool: ExternalTool) -> bool {
    match tool {
        ExternalTool::Eslint => matches!(kind, ConfigFileKind::EslintConfig),
        ExternalTool::Biome => matches!(kind, ConfigFileKind::BiomeConfig),
        ExternalTool::Tsc => matches!(kind, ConfigFileKind::TsconfigJson),
        ExternalTool::Ruff => matches!(
            kind,
            ConfigFileKind::RuffConfig | ConfigFileKind::PyprojectToml
        ),
        ExternalTool::Mypy => matches!(
            kind,
            ConfigFileKind::MypyConfig | ConfigFileKind::PyprojectToml
        ),
        ExternalTool::Pyright => matches!(kind, ConfigFileKind::PyrightConfig),
        ExternalTool::Semgrep => matches!(kind, ConfigFileKind::SemgrepConfig),
        ExternalTool::CargoCheck | ExternalTool::Clippy => false,
    }
}

fn file_matches_tool(file: &WorkspaceFile, tool: ExternalTool) -> bool {
    match tool {
        ExternalTool::Eslint | ExternalTool::Biome | ExternalTool::Tsc => {
            matches!(file.language.name, "typescript" | "tsx")
        }
        ExternalTool::Ruff | ExternalTool::Mypy | ExternalTool::Pyright => {
            file.language.name == "python"
        }
        ExternalTool::Semgrep => true,
        ExternalTool::CargoCheck | ExternalTool::Clippy => file.language.name == "rust",
    }
}

fn rust_invocations(
    root: &Path,
    cargo_tomls: &[PathBuf],
    tool: ExternalTool,
    command: &str,
    args: &[String],
) -> Vec<ToolInvocation> {
    if cargo_tomls.is_empty() {
        return Vec::new();
    }

    let root_manifest = root.join("Cargo.toml");
    if cargo_tomls.iter().any(|path| path == &root_manifest) {
        return vec![ToolInvocation {
            tool,
            command: command.to_string(),
            args: args.to_vec(),
            cwd: root.to_path_buf(),
            manifest_dir: Some(root.to_path_buf()),
        }];
    }

    cargo_tomls
        .iter()
        .map(|manifest| {
            let mut invocation_args = args.to_vec();
            if !invocation_args.iter().any(|arg| arg == "--manifest-path") {
                invocation_args.push("--manifest-path".to_string());
                invocation_args.push(manifest.to_string_lossy().to_string());
            }
            ToolInvocation {
                tool,
                command: command.to_string(),
                args: invocation_args,
                cwd: root.to_path_buf(),
                manifest_dir: manifest.parent().map(Path::to_path_buf),
            }
        })
        .collect()
}

fn parse_tool_output(
    tool: ExternalTool,
    root: &Path,
    cwd: &Path,
    manifest_dir: Option<&Path>,
    stdout: &str,
    stderr: &str,
) -> Vec<ExternalDiagnostic> {
    match tool {
        ExternalTool::Eslint => parse_eslint_json(root, cwd, stdout),
        ExternalTool::Biome => parse_biome_json(root, cwd, stdout),
        ExternalTool::Tsc => parse_tsc_text(root, cwd, &format!("{stdout}\n{stderr}")),
        ExternalTool::Ruff => parse_ruff_json(root, cwd, stdout),
        ExternalTool::Mypy => parse_mypy_text(root, cwd, &format!("{stdout}\n{stderr}")),
        ExternalTool::Pyright => parse_pyright_json(root, cwd, stdout),
        ExternalTool::CargoCheck => parse_cargo_messages(tool, root, manifest_dir, stdout, stderr),
        ExternalTool::Clippy => parse_cargo_messages(tool, root, manifest_dir, stdout, stderr),
        ExternalTool::Semgrep => parse_semgrep_json(root, cwd, stdout),
    }
}

fn parse_eslint_json(root: &Path, cwd: &Path, raw: &str) -> Vec<ExternalDiagnostic> {
    let Ok(value) = serde_json::from_str::<Value>(raw.trim()) else {
        return Vec::new();
    };
    let Some(files) = value.as_array() else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    for file_result in files {
        let Some(file_path) = file_result.get("filePath").and_then(Value::as_str) else {
            continue;
        };
        let path = resolve_path(cwd, file_path);
        let Some(messages) = file_result.get("messages").and_then(Value::as_array) else {
            continue;
        };
        for message in messages {
            let text = message
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("ESLint diagnostic");
            let rule_code = message
                .get("ruleId")
                .and_then(Value::as_str)
                .unwrap_or("diagnostic");
            let severity = match message.get("severity").and_then(Value::as_u64).unwrap_or(1) {
                2 => Severity::High,
                1 => Severity::Medium,
                _ => Severity::Info,
            };
            diagnostics.push(ExternalDiagnostic {
                tool: ExternalTool::Eslint,
                rule_code: sanitize_rule_code(rule_code),
                severity,
                confidence: Confidence::High,
                message: text.to_string(),
                path: path.clone(),
                line: usize_field(message, "line"),
                column: usize_field(message, "column"),
                byte_span: None,
                external_severity: message.get("severity").map(|severity| severity.to_string()),
                help: None,
            });
        }
    }
    normalize_paths(root, diagnostics)
}

fn parse_biome_json(root: &Path, cwd: &Path, raw: &str) -> Vec<ExternalDiagnostic> {
    let Ok(value) = serde_json::from_str::<Value>(raw.trim()) else {
        return Vec::new();
    };
    let Some(diagnostics_value) = value
        .get("diagnostics")
        .and_then(Value::as_array)
        .or_else(|| value.pointer("/data/diagnostics").and_then(Value::as_array))
    else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    for item in diagnostics_value {
        let path = item
            .pointer("/location/path/file")
            .and_then(Value::as_str)
            .or_else(|| item.pointer("/location/path").and_then(Value::as_str))
            .or_else(|| item.get("file_path").and_then(Value::as_str))
            .map(|path| resolve_path(cwd, path))
            .unwrap_or_else(|| cwd.to_path_buf());
        let message = item
            .get("description")
            .and_then(Value::as_str)
            .or_else(|| item.get("message").and_then(Value::as_str))
            .unwrap_or("Biome diagnostic");
        let category = item
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("diagnostic");
        let external_severity = item
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("warning");
        diagnostics.push(ExternalDiagnostic {
            tool: ExternalTool::Biome,
            rule_code: sanitize_rule_code(category),
            severity: severity_from_text(external_severity),
            confidence: Confidence::Medium,
            message: message.to_string(),
            path,
            line: None,
            column: None,
            byte_span: None,
            external_severity: Some(external_severity.to_string()),
            help: None,
        });
    }
    normalize_paths(root, diagnostics)
}

fn parse_tsc_text(root: &Path, cwd: &Path, raw: &str) -> Vec<ExternalDiagnostic> {
    let mut diagnostics = Vec::new();
    for line in raw.lines() {
        let Some(open) = line.find('(') else {
            continue;
        };
        let Some(close_rel) = line[open..].find("): ") else {
            continue;
        };
        let close = open + close_rel;
        let path = &line[..open];
        let mut position = line[open + 1..close].split(',');
        let line_number = position.next().and_then(parse_usize);
        let column = position.next().and_then(parse_usize);
        let rest = &line[close + 3..];
        let Some(code_start) = rest.find("TS") else {
            continue;
        };
        let code_end = rest[code_start..]
            .find(':')
            .map(|index| code_start + index)
            .unwrap_or(rest.len());
        let code = &rest[code_start..code_end];
        let message = rest
            .get(code_end + 1..)
            .map(str::trim)
            .filter(|message| !message.is_empty())
            .unwrap_or(rest);
        diagnostics.push(ExternalDiagnostic {
            tool: ExternalTool::Tsc,
            rule_code: sanitize_rule_code(code),
            severity: Severity::High,
            confidence: Confidence::Certain,
            message: message.to_string(),
            path: resolve_path(cwd, path),
            line: line_number,
            column,
            byte_span: None,
            external_severity: Some("error".to_string()),
            help: None,
        });
    }
    normalize_paths(root, diagnostics)
}

fn parse_ruff_json(root: &Path, cwd: &Path, raw: &str) -> Vec<ExternalDiagnostic> {
    let Ok(value) = serde_json::from_str::<Value>(raw.trim()) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    for item in items {
        let Some(filename) = item.get("filename").and_then(Value::as_str) else {
            continue;
        };
        let code = item
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("diagnostic");
        let message = item
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Ruff diagnostic");
        diagnostics.push(ExternalDiagnostic {
            tool: ExternalTool::Ruff,
            rule_code: sanitize_rule_code(code),
            severity: Severity::Medium,
            confidence: Confidence::High,
            message: message.to_string(),
            path: resolve_path(cwd, filename),
            line: item
                .pointer("/location/row")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
            column: item
                .pointer("/location/column")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
            byte_span: None,
            external_severity: Some(code.to_string()),
            help: None,
        });
    }
    normalize_paths(root, diagnostics)
}

fn parse_mypy_text(root: &Path, cwd: &Path, raw: &str) -> Vec<ExternalDiagnostic> {
    let mut diagnostics = Vec::new();
    for line in raw.lines() {
        let parts = line.split(':').collect::<Vec<_>>();
        let Some(position_index) = parts.windows(2).position(|window| {
            parse_usize(window[0]).is_some() && parse_usize(window[1]).is_some()
        }) else {
            continue;
        };
        if parts.len() <= position_index + 3 {
            continue;
        }
        let path = parts[..position_index].join(":");
        let line_number = parse_usize(parts[position_index]);
        let column = parse_usize(parts[position_index + 1]);
        let severity_text = parts[position_index + 2].trim();
        let message_text = parts[position_index + 3..].join(":").trim().to_string();
        let code = bracketed_code(&message_text).unwrap_or("diagnostic");
        diagnostics.push(ExternalDiagnostic {
            tool: ExternalTool::Mypy,
            rule_code: sanitize_rule_code(code),
            severity: severity_from_text(severity_text),
            confidence: Confidence::High,
            message: message_text,
            path: resolve_path(cwd, &path),
            line: line_number,
            column,
            byte_span: None,
            external_severity: Some(severity_text.to_string()),
            help: None,
        });
    }
    normalize_paths(root, diagnostics)
}

fn parse_pyright_json(root: &Path, cwd: &Path, raw: &str) -> Vec<ExternalDiagnostic> {
    let Ok(value) = serde_json::from_str::<Value>(raw.trim()) else {
        return Vec::new();
    };
    let Some(items) = value.get("generalDiagnostics").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    for item in items {
        let Some(file) = item.get("file").and_then(Value::as_str) else {
            continue;
        };
        let severity = item
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("error");
        let message = item
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Pyright diagnostic");
        let rule = item
            .get("rule")
            .and_then(Value::as_str)
            .unwrap_or("diagnostic");
        diagnostics.push(ExternalDiagnostic {
            tool: ExternalTool::Pyright,
            rule_code: sanitize_rule_code(rule),
            severity: severity_from_text(severity),
            confidence: Confidence::High,
            message: message.to_string(),
            path: resolve_path(cwd, file),
            line: item
                .pointer("/range/start/line")
                .and_then(Value::as_u64)
                .map(|value| value as usize + 1),
            column: item
                .pointer("/range/start/character")
                .and_then(Value::as_u64)
                .map(|value| value as usize + 1),
            byte_span: None,
            external_severity: Some(severity.to_string()),
            help: None,
        });
    }
    normalize_paths(root, diagnostics)
}

fn parse_semgrep_json(root: &Path, cwd: &Path, raw: &str) -> Vec<ExternalDiagnostic> {
    let Ok(value) = serde_json::from_str::<Value>(raw.trim()) else {
        return Vec::new();
    };
    let Some(items) = value.get("results").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    for item in items {
        let Some(path) = item.get("path").and_then(Value::as_str) else {
            continue;
        };
        let rule = item
            .get("check_id")
            .and_then(Value::as_str)
            .unwrap_or("diagnostic");
        let message = item
            .pointer("/extra/message")
            .and_then(Value::as_str)
            .unwrap_or("Semgrep diagnostic");
        let severity = item
            .pointer("/extra/severity")
            .and_then(Value::as_str)
            .unwrap_or("warning");
        diagnostics.push(ExternalDiagnostic {
            tool: ExternalTool::Semgrep,
            rule_code: sanitize_rule_code(rule),
            severity: severity_from_text(severity),
            confidence: Confidence::Medium,
            message: message.to_string(),
            path: resolve_path(cwd, path),
            line: item
                .pointer("/start/line")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
            column: item
                .pointer("/start/col")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
            byte_span: None,
            external_severity: Some(severity.to_string()),
            help: None,
        });
    }
    normalize_paths(root, diagnostics)
}

fn parse_cargo_messages(
    tool: ExternalTool,
    root: &Path,
    manifest_dir: Option<&Path>,
    stdout: &str,
    stderr: &str,
) -> Vec<ExternalDiagnostic> {
    stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value["reason"] == "compiler-message")
        .filter_map(|value| {
            rust_diagnostic_from_message(tool, root, manifest_dir, &value["message"])
        })
        .collect()
}

fn rust_diagnostic_from_message(
    tool: ExternalTool,
    root: &Path,
    manifest_dir: Option<&Path>,
    message: &Value,
) -> Option<ExternalDiagnostic> {
    let code = message
        .get("code")
        .and_then(|code| code.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("diagnostic");
    if tool == ExternalTool::Clippy && !code.starts_with("clippy::") {
        return None;
    }
    let rule_code = code.trim_start_matches("clippy::");
    let message_text = message
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Rust compiler diagnostic")
        .to_string();
    let level = message
        .get("level")
        .and_then(Value::as_str)
        .unwrap_or("warning");
    let span = primary_rust_span(message)?;
    let file = resolve_rust_path(root, manifest_dir, span.file_name);
    let start = span.byte_start.unwrap_or(0);
    let end = span
        .byte_end
        .unwrap_or(start.saturating_add(1))
        .max(start + 1);
    Some(ExternalDiagnostic {
        tool,
        rule_code: sanitize_rule_code(rule_code),
        severity: severity_from_text(level),
        confidence: Confidence::High,
        message: message_text,
        path: file,
        line: span.line_start,
        column: span.column_start,
        byte_span: Some(SourceSpan { start, end }),
        external_severity: Some(level.to_string()),
        help: message
            .get("rendered")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
    })
}

#[derive(Debug, Clone, Copy)]
struct RustSpan<'a> {
    file_name: &'a str,
    byte_start: Option<usize>,
    byte_end: Option<usize>,
    line_start: Option<usize>,
    column_start: Option<usize>,
}

fn primary_rust_span(message: &Value) -> Option<RustSpan<'_>> {
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
            Some(RustSpan {
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

fn diagnostic_to_finding(root: &Path, cwd: &Path, diagnostic: ExternalDiagnostic) -> Finding {
    let rule_id = format!("external.{}.{}", diagnostic.tool.id(), diagnostic.rule_code);
    let stable = stable_hash(&format!(
        "{}|{}|{}|{}|{}|{}",
        rule_id,
        normalize_path(root, &diagnostic.path),
        diagnostic.line.unwrap_or_default(),
        diagnostic.column.unwrap_or_default(),
        diagnostic
            .byte_span
            .map(|span| span.start)
            .unwrap_or_default(),
        collapse_whitespace(&diagnostic.message)
    ));
    let mut metadata = BTreeMap::new();
    metadata.insert("source".to_string(), serde_json::json!("external_tool"));
    metadata.insert(
        "external_tool".to_string(),
        serde_json::json!(diagnostic.tool.id()),
    );
    metadata.insert(
        "external_rule_code".to_string(),
        serde_json::json!(diagnostic.rule_code),
    );
    metadata.insert(
        "command_cwd".to_string(),
        serde_json::json!(normalize_path(root, cwd)),
    );
    if let Some(severity) = diagnostic.external_severity {
        metadata.insert("external_severity".to_string(), serde_json::json!(severity));
    }

    Finding {
        finding_id: format!("{rule_id}:{}", &stable[..12]),
        baseline_key: stable,
        rule_id,
        kind: FindingKind::ExternalTool,
        severity: diagnostic.severity,
        confidence: diagnostic.confidence,
        message: format!("{}: {}", diagnostic.tool.display_name(), diagnostic.message),
        locations: vec![FindingLocation {
            path: diagnostic.path,
            span: diagnostic.byte_span,
            start: diagnostic.line.map(|line| Location {
                line,
                column: diagnostic.column.unwrap_or(1),
                byte_offset: diagnostic.byte_span.map(|span| span.start).unwrap_or(0),
            }),
            language: diagnostic.tool.language().map(str::to_string),
        }],
        language: diagnostic.tool.language().map(str::to_string),
        framework: None,
        explanation: format!(
            "This diagnostic was normalized from optional {} integration output.",
            diagnostic.tool.display_name()
        ),
        remediation: diagnostic.help.unwrap_or_else(|| {
            format!(
                "Review the {} diagnostic and apply the tool's suggested remediation where appropriate.",
                diagnostic.tool.display_name()
            )
        }),
        detection_reason: format!(
            "{} emitted a parsed diagnostic during the external integration run.",
            diagnostic.tool.display_name()
        ),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation:
            "External tool suggestions are reported but not auto-applied by codehealth.".to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn tool_failure_finding(
    root: &Path,
    tool: ExternalTool,
    kind: FailureKind,
    message: &str,
    remediation: &str,
    detail: Option<String>,
    fail_on_tool_error: bool,
) -> Finding {
    let rule_id = match (tool, kind) {
        (ExternalTool::Clippy, FailureKind::Unavailable) => "rust.clippy_unavailable".to_string(),
        (ExternalTool::Clippy, FailureKind::RunFailed) => "rust.clippy_run_failed".to_string(),
        (_, FailureKind::Unavailable) => format!("external.{}.unavailable", tool.id()),
        (_, FailureKind::RunFailed) => format!("external.{}.run_failed", tool.id()),
    };
    let stable = stable_hash(&format!(
        "{rule_id}|{}|{}",
        root.display(),
        detail.as_deref().unwrap_or_default()
    ));
    let mut metadata = BTreeMap::new();
    metadata.insert("source".to_string(), serde_json::json!("external_tool"));
    metadata.insert("external_tool".to_string(), serde_json::json!(tool.id()));
    if let Some(detail) = detail {
        metadata.insert("detail".to_string(), serde_json::json!(detail));
    }
    Finding {
        finding_id: format!("{rule_id}:{}", &stable[..12]),
        baseline_key: stable,
        rule_id,
        kind: FindingKind::ExternalTool,
        severity: if fail_on_tool_error {
            Severity::High
        } else {
            Severity::Info
        },
        confidence: Confidence::High,
        message: message.to_string(),
        locations: vec![FindingLocation {
            path: root.to_path_buf(),
            span: None,
            start: None,
            language: tool.language().map(str::to_string),
        }],
        language: tool.language().map(str::to_string),
        framework: None,
        explanation: "Optional external integrations are nonfatal unless integrations.fail_on_tool_error is enabled.".to_string(),
        remediation: remediation.to_string(),
        detection_reason: format!(
            "The configured {} command could not produce parsed diagnostics.",
            tool.display_name()
        ),
        autofix: AutofixSafety::Unavailable,
        autofix_explanation: "There is no code fix for external tool availability.".to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn dedupe_external_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for finding in findings {
        let key = external_finding_key(&finding);
        if seen.insert(key) {
            output.push(finding);
        }
    }
    output
}

fn external_finding_key(finding: &Finding) -> String {
    let primary = finding.locations.first();
    let path = primary
        .map(|location| location.path.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    let span = primary
        .and_then(|location| location.span)
        .map(|span| span.start.to_string())
        .unwrap_or_default();
    let start = primary
        .and_then(|location| location.start)
        .map(|location| format!("{}:{}", location.line, location.column))
        .unwrap_or_default();
    format!(
        "{}|{}|{}|{}|{}",
        finding.rule_id,
        path,
        span,
        start,
        collapse_whitespace(&finding.message)
    )
}

fn locations_overlap(left: &FindingLocation, right: &FindingLocation) -> bool {
    if left.path != right.path {
        return false;
    }
    let Some(left_span) = left.span else {
        return false;
    };
    let Some(right_span) = right.span else {
        return false;
    };
    left_span.start < right_span.end && right_span.start < left_span.end
}

fn normalize_paths(root: &Path, diagnostics: Vec<ExternalDiagnostic>) -> Vec<ExternalDiagnostic> {
    diagnostics
        .into_iter()
        .map(|mut diagnostic| {
            if diagnostic.path.is_relative() {
                diagnostic.path = root.join(&diagnostic.path);
            }
            diagnostic
        })
        .collect()
}

fn resolve_path(cwd: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn resolve_rust_path(root: &Path, manifest_dir: Option<&Path>, file_name: &str) -> PathBuf {
    let path = PathBuf::from(file_name);
    if path.is_absolute() {
        path
    } else {
        manifest_dir.unwrap_or(root).join(path)
    }
}

fn usize_field(value: &Value, field: &str) -> Option<usize> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
}

fn parse_usize(value: &str) -> Option<usize> {
    value.trim().parse::<usize>().ok()
}

fn bracketed_code(value: &str) -> Option<&str> {
    let end = value.trim_end().strip_suffix(']')?;
    let start = end.rfind('[')?;
    Some(&end[start + 1..])
}

fn severity_from_text(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "critical" | "fatal" => Severity::Critical,
        "error" => Severity::High,
        "warning" | "warn" => Severity::Medium,
        "information" | "info" | "note" | "help" => Severity::Info,
        _ => Severity::Low,
    }
}

fn sanitize_rule_code(value: &str) -> String {
    let sanitized = value
        .trim()
        .trim_start_matches('@')
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>()
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    if sanitized.is_empty() {
        "diagnostic".to_string()
    } else {
        sanitized
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
    fn parses_eslint_json_diagnostics() {
        let raw = r#"[{"filePath":"src/app.ts","messages":[{"ruleId":"no-unused-vars","severity":2,"message":"'x' is unused","line":3,"column":5}]}]"#;
        let findings = parse_eslint_json(Path::new("C:/repo"), Path::new("C:/repo"), raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_code, "no.unused.vars");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line, Some(3));
    }

    #[test]
    fn parses_tsc_text_diagnostics() {
        let raw =
            "src/index.ts(1,7): error TS2322: Type 'number' is not assignable to type 'string'.";
        let findings = parse_tsc_text(Path::new("C:/repo"), Path::new("C:/repo"), raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_code, "ts2322");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line, Some(1));
    }

    #[test]
    fn parses_ruff_json_diagnostics() {
        let raw = r#"[{"filename":"pkg/app.py","code":"F401","message":"unused import","location":{"row":2,"column":1}}]"#;
        let findings = parse_ruff_json(Path::new("C:/repo"), Path::new("C:/repo"), raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_code, "f401");
        assert_eq!(findings[0].line, Some(2));
    }

    #[test]
    fn parses_mypy_text_with_windows_paths() {
        let raw = "C:\\repo\\pkg\\app.py:4:9: error: Incompatible types [assignment]";
        let findings = parse_mypy_text(Path::new("C:/repo"), Path::new("C:/repo"), raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_code, "assignment");
        assert_eq!(findings[0].line, Some(4));
        assert_eq!(findings[0].column, Some(9));
    }

    #[test]
    fn parses_pyright_json_diagnostics() {
        let raw = r#"{"generalDiagnostics":[{"file":"pkg/app.py","severity":"error","message":"Type mismatch","rule":"reportAssignmentType","range":{"start":{"line":0,"character":4}}}]}"#;
        let findings = parse_pyright_json(Path::new("C:/repo"), Path::new("C:/repo"), raw);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_code, "reportassignmenttype");
        assert_eq!(findings[0].line, Some(1));
        assert_eq!(findings[0].column, Some(5));
    }

    #[test]
    fn parses_clippy_json_diagnostics() {
        let raw = r#"{"reason":"compiler-message","message":{"message":"used unwrap on an Option value","code":{"code":"clippy::unwrap_used"},"level":"warning","spans":[{"file_name":"src/lib.rs","byte_start":10,"byte_end":20,"line_start":2,"column_start":5,"is_primary":true}],"rendered":"warning: used unwrap"}} "#;
        let findings = parse_cargo_messages(
            ExternalTool::Clippy,
            Path::new("C:/repo"),
            Some(Path::new("C:/repo")),
            raw,
            "",
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_code, "unwrap.used");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].path, Path::new("C:/repo").join("src/lib.rs"));
    }

    #[test]
    fn dedupes_identical_external_findings() {
        let diagnostic = ExternalDiagnostic {
            tool: ExternalTool::Tsc,
            rule_code: "ts2322".to_string(),
            severity: Severity::High,
            confidence: Confidence::Certain,
            message: "Type mismatch".to_string(),
            path: PathBuf::from("C:/repo/src/app.ts"),
            line: Some(1),
            column: Some(1),
            byte_span: None,
            external_severity: Some("error".to_string()),
            help: None,
        };
        let first = diagnostic_to_finding(
            Path::new("C:/repo"),
            Path::new("C:/repo"),
            diagnostic.clone(),
        );
        let second = diagnostic_to_finding(Path::new("C:/repo"), Path::new("C:/repo"), diagnostic);

        assert_eq!(dedupe_external_findings(vec![first, second]).len(), 1);
    }
}
