use codehealth_core::ScanResult;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
}

pub fn render_result(result: &ScanResult, format: ReportFormat) -> Result<String, ReporterError> {
    match format {
        ReportFormat::Text => Ok(render_text(result)),
        ReportFormat::Json => serde_json::to_string_pretty(result).map_err(ReporterError::Json),
    }
}

fn render_text(result: &ScanResult) -> String {
    let mut output = String::new();
    output.push_str(&format!("Root: {}\n", result.root.display()));
    output.push_str(&format!("Files scanned: {}\n", result.files_scanned));
    output.push_str(&format!("Findings: {}\n", result.findings.len()));

    for finding in &result.findings {
        let path = finding
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<workspace>".to_string());
        output.push_str(&format!(
            "- {:?}/{:?} [{}]: {}\n",
            finding.severity, finding.confidence, path, finding.message
        ));
    }

    output
}

#[derive(Debug, Error)]
pub enum ReporterError {
    #[error("failed to serialize JSON report")]
    Json(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_report_includes_counts() {
        let result = ScanResult::new("fixtures");

        let rendered = render_result(&result, ReportFormat::Text).expect("text renders");

        assert!(rendered.contains("Files scanned: 0"));
        assert!(rendered.contains("Findings: 0"));
    }

    #[test]
    fn json_report_has_expected_shape() {
        let result = ScanResult::new("fixtures");

        let rendered = render_result(&result, ReportFormat::Json).expect("json renders");
        let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(json["files_scanned"], 0);
        assert!(json["findings"].as_array().expect("array").is_empty());
    }
}
