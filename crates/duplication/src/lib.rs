use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, Severity,
    SourceSpan,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

pub const EXACT_FILE_RULE: &str = "duplicate.exact.file";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateInput {
    pub path: PathBuf,
    pub language: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyFingerprint {
    pub fast_hash: u64,
    pub stable_hash_hex: String,
    pub normalized_len: usize,
}

#[derive(Debug, Clone)]
struct FileFingerprint {
    path: PathBuf,
    language: String,
    source_len: usize,
    first_relevant_location: Location,
    fingerprint: BodyFingerprint,
}

pub fn find_exact_file_duplicates(
    inputs: &[DuplicateInput],
) -> Result<Vec<Finding>, DuplicateError> {
    let mut by_hash: BTreeMap<String, Vec<FileFingerprint>> = BTreeMap::new();

    for input in inputs {
        let source =
            std::fs::read_to_string(&input.path).map_err(|source| DuplicateError::Read {
                path: input.path.clone(),
                source,
            })?;

        let fingerprint = fingerprint_normalized_body(&source);
        if fingerprint.normalized_len == 0 {
            continue;
        }

        by_hash
            .entry(fingerprint.stable_hash_hex.clone())
            .or_default()
            .push(FileFingerprint {
                path: input.path.clone(),
                language: input.language.clone(),
                source_len: source.len(),
                first_relevant_location: first_relevant_location(&source),
                fingerprint,
            });
    }

    let mut findings = Vec::new();

    for files in by_hash.values() {
        if files.len() < 2 {
            continue;
        }

        let mut files = files.clone();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        findings.push(build_exact_file_finding(&files));
    }

    Ok(findings)
}

pub fn fingerprint_normalized_body(source: &str) -> BodyFingerprint {
    let normalized = normalize_source(source);
    let stable_hash = Sha256::digest(normalized.as_bytes());

    BodyFingerprint {
        fast_hash: xxh3_64(normalized.as_bytes()),
        stable_hash_hex: format!("{stable_hash:x}"),
        normalized_len: normalized.len(),
    }
}

pub fn normalize_source(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn build_exact_file_finding(files: &[FileFingerprint]) -> Finding {
    let stable_hash = &files[0].fingerprint.stable_hash_hex;
    let path_fingerprint = files
        .iter()
        .map(|file| file.path.to_string_lossy())
        .collect::<Vec<_>>()
        .join("|");
    let baseline_key = stable_key(EXACT_FILE_RULE, stable_hash, &path_fingerprint);
    let language = shared_language(files);

    Finding {
        finding_id: format!("{}:{}", EXACT_FILE_RULE, &baseline_key[..12]),
        baseline_key,
        rule_id: EXACT_FILE_RULE.to_string(),
        kind: FindingKind::ExactDuplicate,
        severity: Severity::High,
        confidence: Confidence::Certain,
        message: format!(
            "{} files have identical normalized contents.",
            files.len()
        ),
        locations: files
            .iter()
            .map(|file| FindingLocation {
                path: file.path.clone(),
                span: Some(SourceSpan {
                    start: 0,
                    end: file.source_len,
                }),
                start: Some(Location {
                    line: file.first_relevant_location.line,
                    column: file.first_relevant_location.column,
                    byte_offset: file.first_relevant_location.byte_offset,
                }),
                language: Some(file.language.clone()),
            })
            .collect(),
        language,
        framework: None,
        explanation: "These files have the same contents after whitespace normalization."
            .to_string(),
        remediation: "Remove one copy, consolidate shared logic, or document why the duplicate file is intentional."
            .to_string(),
        detection_reason: "The detector grouped files by a stable hash of their whitespace-normalized contents."
            .to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: "Exact duplicate files are not auto-fixed because choosing which file to keep can change imports, ownership, and public APIs."
            .to_string(),
        is_suppressed: false,
        suppression: None,
    }
}

fn first_relevant_location(source: &str) -> Location {
    let mut byte_offset = 0;

    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let is_suppression = trimmed.contains("codehealth-ignore-");
        if !trimmed.is_empty() && !is_suppression {
            return Location {
                line: index + 1,
                column: line
                    .chars()
                    .position(|character| !character.is_whitespace())
                    .map(|column| column + 1)
                    .unwrap_or(1),
                byte_offset,
            };
        }

        byte_offset += line.len() + 1;
    }

    Location {
        line: 1,
        column: 1,
        byte_offset: 0,
    }
}

fn shared_language(files: &[FileFingerprint]) -> Option<String> {
    let first = files.first()?.language.as_str();
    if files.iter().all(|file| file.language == first) {
        Some(first.to_string())
    } else {
        None
    }
}

fn stable_key(rule: &str, content_hash: &str, path_fingerprint: &str) -> String {
    let raw = format!("{rule}|{content_hash}|{path_fingerprint}");
    let digest = Sha256::digest(raw.as_bytes());
    format!("{digest:x}")
}

#[derive(Debug, Error)]
pub enum DuplicateError {
    #[error("failed to read source file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn language_name_for_path(path: &Path) -> Option<&'static str> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "ts" => Some("typescript"),
        "tsx" => Some("tsx"),
        "py" => Some("python"),
        "rs" => Some("rust"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_ignores_whitespace_changes() {
        let left = fingerprint_normalized_body("return   value");
        let right = fingerprint_normalized_body("return value");

        assert_eq!(left, right);
    }

    #[test]
    fn normalizes_source_by_whitespace_only() {
        assert_eq!(normalize_source("a\n\n  b\tc"), "a b c");
    }
}
