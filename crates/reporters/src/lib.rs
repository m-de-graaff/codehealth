use codehealth_core::{AutofixSafety, Finding, FindingKind, FindingLocation, ScanResult, Severity};
use serde_json::json;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
    Sarif,
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOptions {
    pub format: ReportFormat,
    pub use_color: bool,
}

impl ReportOptions {
    pub fn new(format: ReportFormat, use_color: bool) -> Self {
        Self { format, use_color }
    }
}

pub fn render_result(result: &ScanResult, options: ReportOptions) -> Result<String, ReporterError> {
    match options.format {
        ReportFormat::Text => Ok(render_text(result, options.use_color)),
        ReportFormat::Json => serde_json::to_string_pretty(result).map_err(ReporterError::Json),
        ReportFormat::Sarif => render_sarif(result),
        ReportFormat::Html => Ok(render_html(result)),
    }
}

fn render_text(result: &ScanResult, use_color: bool) -> String {
    let mut output = String::new();
    output.push_str("Code Health Report\n\n");
    output.push_str(&format!("Score: {}/100\n", result.score));
    output.push_str(&format!("Files scanned: {}\n", result.stats.files_scanned));
    if result.stats.files_discovered > result.stats.files_scanned {
        output.push_str(&format!(
            "Files discovered: {}\n",
            result.stats.files_discovered
        ));
    }
    if result.stats.files_skipped > 0 {
        output.push_str(&format!("Files skipped: {}\n", result.stats.files_skipped));
    }
    if result.stats.config_files > 0 {
        output.push_str(&format!("Config files: {}\n", result.stats.config_files));
    }
    if result.stats.files_parsed > 0 {
        output.push_str(&format!("Files parsed: {}\n", result.stats.files_parsed));
    }
    if result.stats.parse_errors > 0 {
        output.push_str(&format!("Parse errors: {}\n", result.stats.parse_errors));
    }
    output.push_str(&format!(
        "Definitions indexed: {}\n",
        result.stats.definitions_indexed
    ));
    output.push_str(&format!(
        "Imports indexed: {}\n",
        result.stats.imports_indexed
    ));
    output.push_str(&format!("Findings: {}\n", result.findings.len()));
    output.push_str(&format!(
        "Suppressed findings: {}\n",
        result.stats.suppressed_findings
    ));

    if result.findings.is_empty() {
        output.push('\n');
        return output;
    }

    for (section, findings) in grouped_findings(&result.findings) {
        output.push('\n');
        output.push_str(section);
        output.push('\n');

        for finding in findings {
            output.push_str(&format!(
                "  {}  {}{}\n",
                color_severity(finding.severity, use_color),
                finding.rule_id,
                if finding.is_suppressed {
                    "  (suppressed)"
                } else {
                    ""
                }
            ));

            for location in &finding.locations {
                output.push_str(&format!(
                    "    {}\n",
                    format_location(&result.root, location)
                ));
            }

            for line in metadata_lines(finding) {
                output.push_str(&format!("    {line}\n"));
            }
            output.push_str(&format!("    {}\n", finding.explanation));
            output.push_str(&format!("    Suggested action: {}\n", finding.remediation));
            output.push_str(&format!("    Why detected: {}\n", finding.detection_reason));
            output.push_str(&format!(
                "    Autofix: {}\n",
                autofix_text(finding.autofix, &finding.autofix_explanation)
            ));
            if let Some(suppression) = &finding.suppression {
                let reason = suppression.reason.as_deref().unwrap_or("missing reason");
                output.push_str(&format!(
                    "    Suppressed by: {}:{} ({reason})\n",
                    format_report_path(&result.root, &suppression.path),
                    suppression.line
                ));
                for warning in &suppression.warnings {
                    output.push_str(&format!("    Suppression warning: {warning}\n"));
                }
            }
        }
    }

    output
}

fn metadata_lines(finding: &Finding) -> Vec<String> {
    if finding.rule_id == "duplicate.exact.body" {
        let body_size = metadata_usize(finding, "body_size_bytes");
        let line_count = metadata_usize(finding, "line_count");
        let token_estimate = metadata_usize(finding, "token_estimate");
        let names = metadata_string_array(finding, "symbol_names");
        let names_differ = metadata_bool(finding, "names_differ");
        let signatures_differ = metadata_bool(finding, "signatures_differ");
        let mut lines = Vec::new();
        if !names.is_empty() {
            lines.push(format!("Symbols: {}", names.join(", ")));
        }
        if let (Some(body_size), Some(line_count), Some(token_estimate)) =
            (body_size, line_count, token_estimate)
        {
            lines.push(format!(
                "Body: {body_size} bytes, {line_count} lines, ~{token_estimate} tokens"
            ));
        }
        if let (Some(names_differ), Some(signatures_differ)) = (names_differ, signatures_differ) {
            lines.push(format!(
                "Names differ: {names_differ}; signatures differ: {signatures_differ}"
            ));
        }
        return lines;
    }

    if finding.kind == FindingKind::DuplicateName {
        if let (Some(scope), Some(score)) = (
            finding
                .metadata
                .get("scope")
                .and_then(|value| value.as_str()),
            metadata_usize(finding, "score"),
        ) {
            return vec![format!("Scope: {scope}; duplicate-name score: {score}")];
        }
    }

    if finding.rule_id == "fastapi.duplicate.route" {
        if let Some(route) = finding
            .metadata
            .get("route")
            .and_then(|value| value.as_str())
        {
            return vec![format!("Route: {route}")];
        }
    }

    Vec::new()
}

fn metadata_usize(finding: &Finding, key: &str) -> Option<usize> {
    finding
        .metadata
        .get(key)?
        .as_u64()
        .and_then(|value| value.try_into().ok())
}

fn metadata_bool(finding: &Finding, key: &str) -> Option<bool> {
    finding.metadata.get(key)?.as_bool()
}

fn metadata_string_array(finding: &Finding, key: &str) -> Vec<String> {
    finding
        .metadata
        .get(key)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn grouped_findings(findings: &[Finding]) -> Vec<(&'static str, Vec<&Finding>)> {
    let mut duplicate_high = Vec::new();
    let mut style = Vec::new();
    let mut react = Vec::new();
    let mut fastapi = Vec::new();
    let mut rust = Vec::new();
    let mut other = Vec::new();

    for finding in findings {
        match finding.kind {
            FindingKind::ExactDuplicate
            | FindingKind::StructuralDuplicate
            | FindingKind::NearDuplicate
            | FindingKind::DuplicateName
            | FindingKind::SemanticCandidate => {
                if finding.confidence >= codehealth_core::Confidence::High {
                    duplicate_high.push(finding);
                } else {
                    other.push(finding);
                }
            }
            FindingKind::Style => style.push(finding),
            FindingKind::React => react.push(finding),
            FindingKind::FastApi => fastapi.push(finding),
            FindingKind::Rust => rust.push(finding),
        }
    }

    let mut sections = Vec::new();
    push_section(&mut sections, "High confidence duplicates", duplicate_high);
    push_section(&mut sections, "Style", style);
    push_section(&mut sections, "React", react);
    push_section(&mut sections, "FastAPI", fastapi);
    push_section(&mut sections, "Rust", rust);
    push_section(&mut sections, "Other", other);
    sections
}

fn push_section<'a>(
    sections: &mut Vec<(&'static str, Vec<&'a Finding>)>,
    label: &'static str,
    findings: Vec<&'a Finding>,
) {
    if !findings.is_empty() {
        sections.push((label, findings));
    }
}

fn color_severity(severity: Severity, use_color: bool) -> String {
    let label = severity.label();
    if !use_color {
        return label.to_string();
    }

    let code = match severity {
        Severity::Critical => "\x1b[1;91m",
        Severity::High => "\x1b[31m",
        Severity::Medium => "\x1b[33m",
        Severity::Low => "\x1b[34m",
        Severity::Info => "\x1b[2;36m",
    };

    format!("{code}{label}\x1b[0m")
}

fn format_location(root: &Path, location: &FindingLocation) -> String {
    let path = format_report_path(root, &location.path);

    if let Some(start) = location.start {
        format!("{path}:{}:{}", start.line, start.column)
    } else {
        path
    }
}

fn format_report_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn autofix_text(safety: AutofixSafety, explanation: &str) -> String {
    match safety {
        AutofixSafety::Unavailable => format!("Not available. {explanation}"),
        AutofixSafety::SuggestionOnly => format!("Suggestion only. {explanation}"),
        AutofixSafety::Safe => format!("Safe autofix available. {explanation}"),
    }
}

fn render_sarif(result: &ScanResult) -> Result<String, ReporterError> {
    let rules = result
        .findings
        .iter()
        .map(|finding| {
            json!({
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": { "text": finding.message },
                "fullDescription": { "text": finding.explanation },
                "help": { "text": finding.remediation },
            })
        })
        .collect::<Vec<_>>();

    let results = result
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.rule_id,
                "level": sarif_level(finding.severity),
                "message": { "text": finding.message },
                "locations": finding.locations.iter().map(|location| sarif_location(&result.root, location)).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "codehealth",
                    "informationUri": "https://github.com/m-de-graaff/codehealth",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }))
    .map_err(ReporterError::Json)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

fn sarif_location(root: &Path, location: &FindingLocation) -> serde_json::Value {
    let uri = location
        .path
        .strip_prefix(root)
        .unwrap_or(&location.path)
        .to_string_lossy()
        .replace('\\', "/");
    let start = location.start;

    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": uri },
            "region": {
                "startLine": start.map(|location| location.line).unwrap_or(1),
                "startColumn": start.map(|location| location.column).unwrap_or(1),
            }
        }
    })
}

fn render_html(result: &ScanResult) -> String {
    let mut output = String::new();
    output.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    output.push_str("<title>Code Health Report</title>");
    output.push_str("<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#18202a;background:#f7f8fa}main{max-width:960px;margin:auto}h1{margin-bottom:.25rem}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.75rem;margin:1rem 0}.metric,.finding{background:white;border:1px solid #d9dee7;border-radius:8px;padding:1rem}.severity-critical{color:#b00020}.severity-high{color:#c62828}.severity-medium{color:#9a6700}.severity-low{color:#1d4ed8}.severity-info{color:#0e7490}code{font-family:ui-monospace,monospace}</style>");
    output.push_str("</head><body><main>");
    output.push_str("<h1>Code Health Report</h1>");
    output.push_str("<section class=\"summary\">");
    metric(&mut output, "Score", &format!("{}/100", result.score));
    metric(
        &mut output,
        "Files scanned",
        &result.stats.files_scanned.to_string(),
    );
    metric(
        &mut output,
        "Definitions indexed",
        &result.stats.definitions_indexed.to_string(),
    );
    metric(
        &mut output,
        "Imports indexed",
        &result.stats.imports_indexed.to_string(),
    );
    metric(&mut output, "Findings", &result.findings.len().to_string());
    output.push_str("</section>");

    for finding in &result.findings {
        output.push_str("<article class=\"finding\">");
        output.push_str(&format!(
            "<h2><span class=\"severity-{}\">{}</span> <code>{}</code></h2>",
            finding.severity,
            finding.severity.label(),
            escape_html(&finding.rule_id)
        ));
        output.push_str("<ul>");
        for location in &finding.locations {
            output.push_str(&format!(
                "<li><code>{}</code></li>",
                escape_html(&format_location(&result.root, location))
            ));
        }
        output.push_str("</ul>");
        output.push_str(&format!("<p>{}</p>", escape_html(&finding.explanation)));
        output.push_str(&format!(
            "<p><strong>Suggested action:</strong> {}</p>",
            escape_html(&finding.remediation)
        ));
        output.push_str(&format!(
            "<p><strong>Why detected:</strong> {}</p>",
            escape_html(&finding.detection_reason)
        ));
        output.push_str(&format!(
            "<p><strong>Autofix:</strong> {}</p>",
            escape_html(&autofix_text(finding.autofix, &finding.autofix_explanation))
        ));
        output.push_str("</article>");
    }

    output.push_str("</main></body></html>");
    output
}

fn metric(output: &mut String, label: &str, value: &str) {
    output.push_str(&format!(
        "<div class=\"metric\"><strong>{}</strong><br>{}</div>",
        escape_html(label),
        escape_html(value)
    ));
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Debug, Error)]
pub enum ReporterError {
    #[error("failed to serialize JSON report")]
    Json(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_core::{Confidence, FindingKind, Location, SourceSpan};
    use std::path::PathBuf;

    #[test]
    fn text_report_includes_counts() {
        let result = ScanResult::new("fixtures").finalize();

        let rendered =
            render_result(&result, ReportOptions::new(ReportFormat::Text, false)).expect("text");

        assert!(rendered.contains("Code Health Report"));
        assert!(rendered.contains("Files scanned: 0"));
        assert!(rendered.contains("Findings: 0"));
    }

    #[test]
    fn json_report_has_expected_shape() {
        let result = ScanResult::new("fixtures").finalize();

        let rendered =
            render_result(&result, ReportOptions::new(ReportFormat::Json, false)).expect("json");
        let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(json["stats"]["files_scanned"], 0);
        assert!(json["findings"].as_array().expect("array").is_empty());
    }

    #[test]
    fn color_can_be_forced_for_text_output() {
        let mut result = ScanResult::new("fixtures");
        result.findings.push(sample_finding());
        let result = result.finalize();

        let rendered =
            render_result(&result, ReportOptions::new(ReportFormat::Text, true)).expect("text");

        assert!(rendered.contains("\u{1b}[31mHIGH\u{1b}[0m"));
    }

    fn sample_finding() -> Finding {
        Finding {
            finding_id: "id".to_string(),
            baseline_key: "baseline".to_string(),
            rule_id: "duplicate.exact.file".to_string(),
            kind: FindingKind::ExactDuplicate,
            severity: Severity::High,
            confidence: Confidence::Certain,
            message: "duplicate".to_string(),
            locations: vec![FindingLocation {
                path: PathBuf::from("fixtures/a.ts"),
                span: Some(SourceSpan { start: 0, end: 1 }),
                start: Some(Location {
                    line: 1,
                    column: 1,
                    byte_offset: 0,
                }),
                language: Some("typescript".to_string()),
            }],
            language: Some("typescript".to_string()),
            framework: None,
            explanation: "explanation".to_string(),
            remediation: "remediation".to_string(),
            detection_reason: "reason".to_string(),
            autofix: AutofixSafety::SuggestionOnly,
            autofix_explanation: "not safe".to_string(),
            metadata: Default::default(),
            is_suppressed: false,
            suppression: None,
        }
    }
}
