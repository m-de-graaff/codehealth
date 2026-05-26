use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

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
    pub fn blocks_by_default(self, confidence: Confidence) -> bool {
        matches!(self, Self::High | Self::Critical)
            && matches!(confidence, Confidence::High | Confidence::Certain)
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
    pub rule_id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub path: Option<PathBuf>,
    pub span: Option<SourceSpan>,
    pub autofix: AutofixSafety,
}

impl Finding {
    pub fn blocks_by_default(&self) -> bool {
        self.severity.blocks_by_default(self.confidence)
    }
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub root: PathBuf,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
}

impl ScanResult {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            files_scanned: 0,
            findings: Vec::new(),
        }
    }

    pub fn has_blocking_findings(&self) -> bool {
        self.findings.iter().any(Finding::blocks_by_default)
    }
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
        let offset = source.find("c").expect("fixture contains c");
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
}
