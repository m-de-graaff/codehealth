use codehealth_core::{AutofixSafety, Edit, Finding, Fix, FixApplicability, SourceSpan};
use codehealth_parser::{LanguageRegistry, SourceFile};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AutofixSummary {
    pub planned_fixes: usize,
    pub planned_edits: usize,
    pub files_touched: usize,
    pub applied_edits: usize,
    pub dry_run: bool,
}

pub fn collect_safe_fixes(findings: &[Finding]) -> Vec<Fix> {
    findings
        .iter()
        .filter(|finding| !finding.is_suppressed)
        .flat_map(|finding| finding.fixes.iter())
        .filter(|fix| {
            fix.safety == AutofixSafety::Safe
                && fix.applicability == FixApplicability::MachineApplicable
        })
        .cloned()
        .collect()
}

pub fn apply_safe_fixes(
    findings: &[Finding],
    registry: &LanguageRegistry,
    dry_run: bool,
) -> Result<AutofixSummary, AutofixError> {
    apply_fixes(&collect_safe_fixes(findings), registry, dry_run)
}

pub fn apply_fixes(
    fixes: &[Fix],
    registry: &LanguageRegistry,
    dry_run: bool,
) -> Result<AutofixSummary, AutofixError> {
    let mut edits_by_file: BTreeMap<PathBuf, Vec<Edit>> = BTreeMap::new();
    for fix in fixes {
        if fix.safety != AutofixSafety::Safe
            || fix.applicability != FixApplicability::MachineApplicable
        {
            continue;
        }
        for edit in &fix.edits {
            edits_by_file
                .entry(edit.file.clone())
                .or_default()
                .push(edit.clone());
        }
    }

    let planned_edits = edits_by_file.values().map(Vec::len).sum();
    if planned_edits == 0 {
        return Ok(AutofixSummary {
            planned_fixes: fixes.len(),
            dry_run,
            ..AutofixSummary::default()
        });
    }

    let mut rewritten = BTreeMap::new();
    for (path, edits) in edits_by_file.iter_mut() {
        edits.sort_by(|left, right| {
            left.span
                .start
                .cmp(&right.span.start)
                .then_with(|| left.span.end.cmp(&right.span.end))
                .then_with(|| left.replacement.cmp(&right.replacement))
        });
        detect_conflicts(path, edits)?;

        let original = std::fs::read_to_string(path).map_err(|source| AutofixError::Read {
            path: path.clone(),
            source,
        })?;
        validate_spans(path, &original, edits)?;
        reject_parse_errors_in_touched_regions(path, &original, edits, registry)?;
        let next = apply_edits_to_source(&original, edits);
        reject_parse_errors_after_rewrite(path, &next, registry)?;
        rewritten.insert(path.clone(), next);
    }

    if !dry_run {
        for (path, source) in &rewritten {
            std::fs::write(path, source).map_err(|source| AutofixError::Write {
                path: path.clone(),
                source,
            })?;
        }
    }

    Ok(AutofixSummary {
        planned_fixes: fixes.len(),
        planned_edits,
        files_touched: rewritten.len(),
        applied_edits: if dry_run { 0 } else { planned_edits },
        dry_run,
    })
}

fn detect_conflicts(path: &Path, edits: &[Edit]) -> Result<(), AutofixError> {
    for pair in edits.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        if right.span.start < left.span.end {
            return Err(AutofixError::OverlappingEdits {
                path: path.to_path_buf(),
                left: left.span,
                right: right.span,
            });
        }
    }
    Ok(())
}

fn validate_spans(path: &Path, source: &str, edits: &[Edit]) -> Result<(), AutofixError> {
    for edit in edits {
        if edit.span.start > edit.span.end || edit.span.end > source.len() {
            return Err(AutofixError::InvalidSpan {
                path: path.to_path_buf(),
                span: edit.span,
                source_len: source.len(),
            });
        }
        if !source.is_char_boundary(edit.span.start) || !source.is_char_boundary(edit.span.end) {
            return Err(AutofixError::InvalidSpan {
                path: path.to_path_buf(),
                span: edit.span,
                source_len: source.len(),
            });
        }
    }
    Ok(())
}

fn reject_parse_errors_in_touched_regions(
    path: &Path,
    source: &str,
    edits: &[Edit],
    registry: &LanguageRegistry,
) -> Result<(), AutofixError> {
    let Some(tree) = parse(path, source, registry)? else {
        return Ok(());
    };
    for diagnostic in tree.diagnostics() {
        let diagnostic_span = SourceSpan {
            start: diagnostic.span.start,
            end: diagnostic.span.end,
        };
        if edits
            .iter()
            .any(|edit| spans_overlap(edit.span, diagnostic_span))
        {
            return Err(AutofixError::ParseErrorInTouchedRegion {
                path: path.to_path_buf(),
                span: diagnostic_span,
                message: diagnostic.message.clone(),
            });
        }
    }
    Ok(())
}

fn reject_parse_errors_after_rewrite(
    path: &Path,
    source: &str,
    registry: &LanguageRegistry,
) -> Result<(), AutofixError> {
    let Some(tree) = parse(path, source, registry)? else {
        return Ok(());
    };
    if let Some(diagnostic) = tree.diagnostics().first() {
        return Err(AutofixError::RewriteParseError {
            path: path.to_path_buf(),
            span: SourceSpan {
                start: diagnostic.span.start,
                end: diagnostic.span.end,
            },
            message: diagnostic.message.clone(),
        });
    }
    Ok(())
}

fn parse(
    path: &Path,
    source: &str,
    registry: &LanguageRegistry,
) -> Result<Option<codehealth_parser::SyntaxTree>, AutofixError> {
    let Some(language) = registry.language_for_path(path) else {
        return Ok(None);
    };
    let Some(parser) = registry.adapter_for_path(path) else {
        return Ok(None);
    };
    parser
        .parse(&SourceFile::new(
            path.to_path_buf(),
            language,
            source.to_string(),
        ))
        .map(Some)
        .map_err(|source| AutofixError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
}

fn apply_edits_to_source(source: &str, edits: &[Edit]) -> String {
    let mut output = source.to_string();
    for edit in edits.iter().rev() {
        output.replace_range(edit.span.start..edit.span.end, &edit.replacement);
    }
    output
}

fn spans_overlap(left: SourceSpan, right: SourceSpan) -> bool {
    left.start < right.end && right.start < left.end
}

#[derive(Debug, Error)]
pub enum AutofixError {
    #[error("failed to read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("overlapping safe autofix edits in {path}: {left:?} overlaps {right:?}")]
    OverlappingEdits {
        path: PathBuf,
        left: SourceSpan,
        right: SourceSpan,
    },

    #[error("invalid autofix span in {path}: {span:?} for source length {source_len}")]
    InvalidSpan {
        path: PathBuf,
        span: SourceSpan,
        source_len: usize,
    },

    #[error("refusing autofix in {path}: parse error touches edit region at {span:?}: {message}")]
    ParseErrorInTouchedRegion {
        path: PathBuf,
        span: SourceSpan,
        message: String,
    },

    #[error("refusing autofix in {path}: rewritten file does not parse at {span:?}: {message}")]
    RewriteParseError {
        path: PathBuf,
        span: SourceSpan,
        message: String,
    },

    #[error("failed to parse {path} before applying autofix")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<codehealth_parser::ParseError>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_core::FixApplicability;

    #[test]
    fn rejects_overlapping_edits() {
        let path = PathBuf::from("a.ts");
        let edits = vec![
            Edit {
                file: path.clone(),
                span: SourceSpan { start: 0, end: 5 },
                replacement: "one".to_string(),
            },
            Edit {
                file: path.clone(),
                span: SourceSpan { start: 4, end: 7 },
                replacement: "two".to_string(),
            },
        ];

        assert!(matches!(
            detect_conflicts(&path, &edits),
            Err(AutofixError::OverlappingEdits { .. })
        ));
    }

    #[test]
    fn applies_multi_edit_fixes_from_the_end() {
        let edits = vec![
            Edit {
                file: PathBuf::from("a.ts"),
                span: SourceSpan { start: 0, end: 5 },
                replacement: "let".to_string(),
            },
            Edit {
                file: PathBuf::from("a.ts"),
                span: SourceSpan { start: 13, end: 14 },
                replacement: "value".to_string(),
            },
        ];

        assert_eq!(
            apply_edits_to_source("const name = 1;", &edits),
            "let name = value;"
        );
    }

    #[test]
    fn collects_only_safe_machine_applicable_fixes() {
        let safe_fix = Fix {
            title: "safe".to_string(),
            safety: AutofixSafety::Safe,
            applicability: FixApplicability::MachineApplicable,
            edits: Vec::new(),
        };
        let suggestion = Fix {
            title: "suggest".to_string(),
            safety: AutofixSafety::SuggestionOnly,
            applicability: FixApplicability::SuggestionOnly,
            edits: Vec::new(),
        };
        let finding = Finding {
            finding_id: "id".to_string(),
            baseline_key: "key".to_string(),
            rule_id: "style.test".to_string(),
            kind: codehealth_core::FindingKind::Style,
            severity: codehealth_core::Severity::Low,
            confidence: codehealth_core::Confidence::Medium,
            message: "message".to_string(),
            locations: Vec::new(),
            language: None,
            framework: None,
            explanation: String::new(),
            remediation: String::new(),
            detection_reason: String::new(),
            autofix: AutofixSafety::Safe,
            autofix_explanation: String::new(),
            fixes: vec![safe_fix, suggestion],
            metadata: BTreeMap::new(),
            is_suppressed: false,
            suppression: None,
        };

        assert_eq!(collect_safe_fixes(&[finding]).len(), 1);
    }
}
