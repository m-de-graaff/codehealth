use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeMap, fmt, path::PathBuf, str::FromStr};
use thiserror::Error;

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn blocks_by_default(self, confidence: Confidence) -> bool {
        matches!(self, Self::High | Self::Critical)
            && matches!(confidence, Confidence::High | Confidence::Certain)
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for Severity {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(ParseEnumError {
                enum_name: "severity",
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Certain,
}

impl Confidence {
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Certain => 3,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Certain => "certain",
        }
    }
}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

impl FromStr for Confidence {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "certain" => Ok(Self::Certain),
            _ => Err(ParseEnumError {
                enum_name: "confidence",
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutofixSafety {
    Unavailable,
    SuggestionOnly,
    Safe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    DuplicateName,
    ExactDuplicate,
    StructuralDuplicate,
    NearDuplicate,
    SemanticCandidate,
    Style,
    React,
    FastApi,
    Rust,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub baseline_key: String,
    pub rule_id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub locations: Vec<FindingLocation>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub explanation: String,
    pub remediation: String,
    pub detection_reason: String,
    pub autofix: AutofixSafety,
    pub autofix_explanation: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub is_suppressed: bool,
    pub suppression: Option<Suppression>,
}

impl Finding {
    pub fn blocks_by_default(&self) -> bool {
        self.severity.blocks_by_default(self.confidence)
    }

    pub fn primary_location(&self) -> Option<&FindingLocation> {
        self.locations.first()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingLocation {
    pub path: PathBuf,
    pub span: Option<SourceSpan>,
    pub start: Option<Location>,
    pub language: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    pub rule_id: String,
    pub path: PathBuf,
    pub line: usize,
    pub kind: SuppressionKind,
    pub reason: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionKind {
    NextLine,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

impl SourceSpan {
    pub fn new(start: usize, end: usize) -> Result<Self, SourceError> {
        if start > end {
            return Err(SourceError::InvalidSpan { start, end });
        }

        Ok(Self { start, end })
    }

    pub fn len(self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub line: usize,
    pub column: usize,
    pub byte_offset: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SourceError {
    #[error("invalid span: start {start} is after end {end}")]
    InvalidSpan { start: usize, end: usize },

    #[error("byte offset {offset} is outside source length {source_len}")]
    OffsetOutOfBounds { offset: usize, source_len: usize },

    #[error("byte offset {offset} is not a UTF-8 character boundary")]
    InvalidUtf8Boundary { offset: usize },
}

pub fn line_column_for_offset(source: &str, byte_offset: usize) -> Result<Location, SourceError> {
    if byte_offset > source.len() {
        return Err(SourceError::OffsetOutOfBounds {
            offset: byte_offset,
            source_len: source.len(),
        });
    }

    if !source.is_char_boundary(byte_offset) {
        return Err(SourceError::InvalidUtf8Boundary {
            offset: byte_offset,
        });
    }

    let mut line = 1;
    let mut column = 1;

    for character in source[..byte_offset].chars() {
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    Ok(Location {
        line,
        column,
        byte_offset,
    })
}

pub fn slice_source(source: &str, span: SourceSpan) -> Result<&str, SourceError> {
    if span.end > source.len() {
        return Err(SourceError::OffsetOutOfBounds {
            offset: span.end,
            source_len: source.len(),
        });
    }

    if !source.is_char_boundary(span.start) {
        return Err(SourceError::InvalidUtf8Boundary { offset: span.start });
    }

    if !source.is_char_boundary(span.end) {
        return Err(SourceError::InvalidUtf8Boundary { offset: span.end });
    }

    Ok(&source[span.start..span.end])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub root: PathBuf,
    pub mode: ScanMode,
    pub filters: FindingFilters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    All,
    DuplicatesOnly,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingFilters {
    pub min_severity: Option<Severity>,
    pub only_severity: Option<Severity>,
    pub min_confidence: Option<Confidence>,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
}

impl FindingFilters {
    pub fn allows(&self, finding: &Finding) -> bool {
        if let Some(minimum) = self.min_severity {
            if finding.severity < minimum {
                return false;
            }
        }

        if let Some(only) = self.only_severity {
            if finding.severity != only {
                return false;
            }
        }

        if let Some(minimum) = self.min_confidence {
            if finding.confidence < minimum {
                return false;
            }
        }

        if !self.languages.is_empty() && !finding_matches_language(finding, &self.languages) {
            return false;
        }

        if !self.frameworks.is_empty() {
            if let Some(framework) = &finding.framework {
                return self
                    .frameworks
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(framework));
            }
        }

        true
    }
}

fn finding_matches_language(finding: &Finding, languages: &[String]) -> bool {
    if let Some(language) = &finding.language {
        return languages
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(language));
    }

    finding.locations.iter().any(|location| {
        location.language.as_ref().is_some_and(|language| {
            languages
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(language))
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub schema_version: u32,
    pub root: PathBuf,
    pub score: u8,
    pub stats: ScanStats,
    pub findings: Vec<Finding>,
}

impl ScanResult {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            root: root.into(),
            score: 100,
            stats: ScanStats::default(),
            findings: Vec::new(),
        }
    }

    pub fn finalize(mut self) -> Self {
        sort_findings(&mut self.findings);
        self.score = calculate_score(&self.findings);
        self
    }

    pub fn has_blocking_findings(&self) -> bool {
        self.findings.iter().any(Finding::blocks_by_default)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_discovered: usize,
    pub files_skipped: usize,
    pub config_files: usize,
    pub files_parsed: usize,
    pub parse_errors: usize,
    pub definitions_indexed: usize,
    pub imports_indexed: usize,
    pub suppressed_findings: usize,
}

pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| primary_path(left).cmp(&primary_path(right)))
            .then_with(|| primary_span_start(left).cmp(&primary_span_start(right)))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
}

fn primary_path(finding: &Finding) -> PathBuf {
    finding
        .primary_location()
        .map(|location| location.path.clone())
        .unwrap_or_default()
}

fn primary_span_start(finding: &Finding) -> usize {
    finding
        .primary_location()
        .and_then(|location| location.span)
        .map(|span| span.start)
        .unwrap_or_default()
}

pub fn calculate_score(findings: &[Finding]) -> u8 {
    let penalty: u16 = findings
        .iter()
        .filter(|finding| !finding.is_suppressed)
        .map(|finding| match finding.severity {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 8,
            Severity::Critical => 15,
        })
        .sum();

    100_u16.saturating_sub(penalty).try_into().unwrap_or(0)
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid {enum_name} value: {value}")]
pub struct ParseEnumError {
    pub enum_name: &'static str,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_blocks_only_high_confidence_high_or_critical_findings() {
        assert!(Severity::High.blocks_by_default(Confidence::High));
        assert!(Severity::Critical.blocks_by_default(Confidence::Certain));
        assert!(!Severity::High.blocks_by_default(Confidence::Medium));
        assert!(!Severity::Medium.blocks_by_default(Confidence::Certain));
    }

    #[test]
    fn line_column_counts_utf8_characters() {
        let source = "a\nbete\nc";
        let offset = source.find('c').expect("fixture contains c");
        let location = line_column_for_offset(source, offset).expect("valid offset");

        assert_eq!(location.line, 3);
        assert_eq!(location.column, 1);
    }

    #[test]
    fn slicing_rejects_non_utf8_boundary() {
        let source = "eclair";
        let source = source.replacen('e', "é", 1);
        let span = SourceSpan::new(1, 2).expect("ordered span");

        assert!(matches!(
            slice_source(&source, span),
            Err(SourceError::InvalidUtf8Boundary { offset: 1 })
        ));
    }

    #[test]
    fn score_applies_deterministic_penalty() {
        let finding = Finding {
            finding_id: "one".to_string(),
            baseline_key: "one".to_string(),
            rule_id: "duplicate.exact.file".to_string(),
            kind: FindingKind::ExactDuplicate,
            severity: Severity::High,
            confidence: Confidence::Certain,
            message: "duplicate".to_string(),
            locations: Vec::new(),
            language: None,
            framework: None,
            explanation: String::new(),
            remediation: String::new(),
            detection_reason: String::new(),
            autofix: AutofixSafety::Unavailable,
            autofix_explanation: String::new(),
            metadata: BTreeMap::new(),
            is_suppressed: false,
            suppression: None,
        };

        assert_eq!(calculate_score(&[finding]), 92);
    }
}
