use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, Severity,
    SourceSpan,
};
use codehealth_symbols::{Definition, DefinitionKind, FrameworkTag, SymbolIndex};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

pub const EXACT_FILE_RULE: &str = "duplicate.exact.file";
pub const EXACT_BODY_RULE: &str = "duplicate.exact.body";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactBodyOptions {
    pub min_lines: usize,
    pub min_tokens: usize,
}

impl Default for ExactBodyOptions {
    fn default() -> Self {
        Self {
            min_lines: 5,
            min_tokens: 40,
        }
    }
}

#[derive(Debug, Clone)]
struct SymbolBodyFingerprint {
    definition: Definition,
    body_size_bytes: usize,
    line_count: usize,
    token_estimate: usize,
    fingerprint: BodyFingerprint,
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
    fingerprint_normalized_text(&normalize_source(source))
}

pub fn normalize_source(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn find_exact_body_duplicates(
    index: &SymbolIndex,
    options: ExactBodyOptions,
) -> Result<Vec<Finding>, DuplicateError> {
    let mut source_cache = BTreeMap::new();
    let mut by_hash: BTreeMap<String, Vec<SymbolBodyFingerprint>> = BTreeMap::new();

    for definition in &index.definitions {
        if !exact_body_kind(definition.kind) {
            continue;
        }
        let Some(body_span) = definition.body_span else {
            continue;
        };
        let source = source_for_definition(definition, &mut source_cache)?;
        if body_span.end > source.len()
            || !source.is_char_boundary(body_span.start)
            || !source.is_char_boundary(body_span.end)
        {
            continue;
        }

        let body = &source[body_span.start..body_span.end];
        let comment_stripped = strip_comments_preserving_literals(body).replace("\r\n", "\n");
        let normalized = normalize_source(&comment_stripped);
        if normalized.is_empty() {
            continue;
        }
        let line_count = normalized_line_count(&comment_stripped);
        let token_estimate = token_estimate(&normalized);
        if line_count < options.min_lines || token_estimate < options.min_tokens {
            continue;
        }

        let fingerprint = fingerprint_normalized_text(&normalized);
        by_hash
            .entry(fingerprint.stable_hash_hex.clone())
            .or_default()
            .push(SymbolBodyFingerprint {
                definition: definition.clone(),
                body_size_bytes: body.len(),
                line_count,
                token_estimate,
                fingerprint,
            });
    }

    let mut findings = Vec::new();
    for group in by_hash.values() {
        let distinct_symbols = group
            .iter()
            .map(|item| {
                (
                    item.definition.file.clone(),
                    item.definition.span.start,
                    item.definition.qualified_name.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        if distinct_symbols.len() < 2 {
            continue;
        }
        let mut group = group.clone();
        group.sort_by(|left, right| {
            left.definition
                .file
                .cmp(&right.definition.file)
                .then_with(|| left.definition.span.start.cmp(&right.definition.span.start))
                .then_with(|| {
                    left.definition
                        .qualified_name
                        .cmp(&right.definition.qualified_name)
                })
        });
        findings.push(build_exact_body_finding(&group));
    }

    Ok(findings)
}

pub fn normalize_body_source(source: &str) -> String {
    normalize_source(&strip_comments_preserving_literals(source).replace("\r\n", "\n"))
}

pub fn strip_comments_preserving_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let chars = source.char_indices().collect::<Vec<_>>();
    let mut index = 0;
    let mut in_string: Option<char> = None;
    let mut in_triple_string = false;

    while index < chars.len() {
        let (_, character) = chars[index];
        let next = chars.get(index + 1).map(|(_, next)| *next);

        if let Some(quote) = in_string {
            output.push(character);
            if character == '\\' {
                if let Some((_, escaped)) = chars.get(index + 1) {
                    output.push(*escaped);
                    index += 2;
                    continue;
                }
            }
            if in_triple_string {
                if character == quote
                    && next == Some(quote)
                    && chars.get(index + 2).map(|(_, third)| *third) == Some(quote)
                {
                    output.push(quote);
                    output.push(quote);
                    index += 3;
                    in_string = None;
                    in_triple_string = false;
                    continue;
                }
            } else if character == quote {
                in_string = None;
            }
            index += 1;
            continue;
        }

        if matches!(character, '"' | '\'' | '`') {
            in_triple_string = matches!(character, '"' | '\'')
                && next == Some(character)
                && chars.get(index + 2).map(|(_, third)| *third) == Some(character);
            in_string = Some(character);
            output.push(character);
            if in_triple_string {
                output.push(character);
                output.push(character);
                index += 3;
            } else {
                index += 1;
            }
            continue;
        }

        if character == '/' && next == Some('/') {
            output.push(' ');
            index += 2;
            while index < chars.len() && chars[index].1 != '\n' {
                index += 1;
            }
            continue;
        }

        if character == '/' && next == Some('*') {
            output.push(' ');
            index += 2;
            while index + 1 < chars.len() {
                if chars[index].1 == '*' && chars[index + 1].1 == '/' {
                    index += 2;
                    break;
                }
                if chars[index].1 == '\n' {
                    output.push('\n');
                }
                index += 1;
            }
            continue;
        }

        if character == '#' {
            output.push(' ');
            index += 1;
            while index < chars.len() && chars[index].1 != '\n' {
                index += 1;
            }
            continue;
        }

        output.push(character);
        index += 1;
    }

    output
}

fn source_for_definition<'a>(
    definition: &Definition,
    source_cache: &'a mut BTreeMap<PathBuf, String>,
) -> Result<&'a str, DuplicateError> {
    if !source_cache.contains_key(&definition.file) {
        let source =
            std::fs::read_to_string(&definition.file).map_err(|source| DuplicateError::Read {
                path: definition.file.clone(),
                source,
            })?;
        source_cache.insert(definition.file.clone(), source);
    }

    Ok(source_cache
        .get(&definition.file)
        .expect("source was just inserted"))
}

fn exact_body_kind(kind: DefinitionKind) -> bool {
    matches!(
        kind,
        DefinitionKind::Function
            | DefinitionKind::Method
            | DefinitionKind::ReactComponent
            | DefinitionKind::ReactHook
            | DefinitionKind::FastApiRoute
            | DefinitionKind::FastApiDependency
    )
}

fn fingerprint_normalized_text(normalized: &str) -> BodyFingerprint {
    let stable_hash = Sha256::digest(normalized.as_bytes());

    BodyFingerprint {
        fast_hash: xxh3_64(normalized.as_bytes()),
        stable_hash_hex: format!("{stable_hash:x}"),
        normalized_len: normalized.len(),
    }
}

fn normalized_line_count(normalized: &str) -> usize {
    normalized
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        .max(1)
}

pub fn token_estimate(normalized: &str) -> usize {
    let mut count = 0;
    let mut in_token = false;

    for character in normalized.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            if !in_token {
                count += 1;
                in_token = true;
            }
        } else {
            in_token = false;
            if !character.is_whitespace() {
                count += 1;
            }
        }
    }

    count
}

fn build_exact_body_finding(group: &[SymbolBodyFingerprint]) -> Finding {
    let stable_hash = &group[0].fingerprint.stable_hash_hex;
    let symbol_fingerprint = group
        .iter()
        .map(|item| {
            format!(
                "{}:{}:{}",
                item.definition.file.to_string_lossy(),
                item.definition.span.start,
                item.definition.qualified_name
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    let baseline_key = stable_key(EXACT_BODY_RULE, stable_hash, &symbol_fingerprint);
    let names = group
        .iter()
        .map(|item| item.definition.name.clone())
        .collect::<BTreeSet<_>>();
    let signatures = group
        .iter()
        .map(|item| signature_key(&item.definition))
        .collect::<BTreeSet<_>>();
    let kinds = group
        .iter()
        .map(|item| item.definition.kind.label().to_string())
        .collect::<BTreeSet<_>>();
    let line_count = group.iter().map(|item| item.line_count).max().unwrap_or(0);
    let body_size = group
        .iter()
        .map(|item| item.body_size_bytes)
        .max()
        .unwrap_or(0);
    let token_estimate = group
        .iter()
        .map(|item| item.token_estimate)
        .max()
        .unwrap_or(0);
    let names_differ = names.len() > 1;
    let signatures_differ = signatures.len() > 1;
    let language = shared_symbol_language(group);
    let framework = shared_symbol_framework(group);
    let mut metadata = BTreeMap::new();
    metadata.insert("body_size_bytes".to_string(), serde_json::json!(body_size));
    metadata.insert("line_count".to_string(), serde_json::json!(line_count));
    metadata.insert(
        "token_estimate".to_string(),
        serde_json::json!(token_estimate),
    );
    metadata.insert(
        "symbol_names".to_string(),
        serde_json::json!(names.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert("names_differ".to_string(), serde_json::json!(names_differ));
    metadata.insert(
        "signatures_differ".to_string(),
        serde_json::json!(signatures_differ),
    );
    metadata.insert(
        "normalized_body_hash".to_string(),
        serde_json::json!(stable_hash),
    );
    metadata.insert(
        "definition_kinds".to_string(),
        serde_json::json!(kinds.iter().cloned().collect::<Vec<_>>()),
    );

    Finding {
        finding_id: format!("{}:{}", EXACT_BODY_RULE, &baseline_key[..12]),
        baseline_key,
        rule_id: EXACT_BODY_RULE.to_string(),
        kind: FindingKind::ExactDuplicate,
        severity: Severity::High,
        confidence: Confidence::Certain,
        message: format!(
            "{} symbols have identical normalized bodies.",
            group.len()
        ),
        locations: group
            .iter()
            .map(|item| FindingLocation {
                path: item.definition.file.clone(),
                span: item.definition.body_span.map(|span| SourceSpan {
                    start: span.start,
                    end: span.end,
                }),
                start: item.definition.body_span.map(|span| Location {
                    line: span.start_position.line,
                    column: span.start_position.column,
                    byte_offset: span.start,
                }),
                language: Some(item.definition.language.label().to_string()),
            })
            .collect(),
        language,
        framework,
        explanation: format!(
            "These symbols have the same normalized body after comments and whitespace are removed. Body size: {body_size} bytes, lines: {line_count}, token estimate: {token_estimate}. Names differ: {names_differ}. Signatures differ: {signatures_differ}."
        ),
        remediation:
            "Extract a shared helper, remove the duplicate, export an alias, or keep the duplication with a suppression comment if it is intentional."
                .to_string(),
        detection_reason:
            "The detector hashed normalized symbol bodies and grouped definitions with the same stable hash."
                .to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation:
            "Exact body duplicates are not auto-fixed because extracting shared logic can change APIs, ownership, imports, and behavior around side effects."
                .to_string(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn signature_key(definition: &Definition) -> String {
    let parameters = definition
        .signature
        .parameters
        .iter()
        .map(|parameter| {
            format!(
                "{}:{}={}",
                parameter.name,
                parameter.type_annotation.as_deref().unwrap_or_default(),
                parameter.default_value.as_deref().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let return_type = definition
        .signature
        .return_type
        .as_ref()
        .map(|return_type| return_type.text.as_str())
        .unwrap_or_default();
    format!("{}({parameters})->{return_type}", definition.is_async)
}

fn shared_symbol_language(group: &[SymbolBodyFingerprint]) -> Option<String> {
    let first = group.first()?.definition.language;
    if group.iter().all(|item| item.definition.language == first) {
        Some(first.label().to_string())
    } else {
        None
    }
}

fn shared_symbol_framework(group: &[SymbolBodyFingerprint]) -> Option<String> {
    let frameworks = group
        .iter()
        .filter_map(|item| framework_for_definition(&item.definition))
        .collect::<BTreeSet<_>>();
    if frameworks.len() == 1 {
        frameworks.into_iter().next().map(str::to_string)
    } else {
        None
    }
}

fn framework_for_definition(definition: &Definition) -> Option<&'static str> {
    if matches!(
        definition.kind,
        DefinitionKind::ReactComponent | DefinitionKind::ReactHook
    ) {
        return Some("react");
    }
    if matches!(
        definition.kind,
        DefinitionKind::FastApiRoute | DefinitionKind::FastApiDependency
    ) || definition.framework_tags.iter().any(|tag| {
        matches!(
            tag,
            FrameworkTag::FastApiRoute(_) | FrameworkTag::FastApiDependency
        )
    }) {
        return Some("fastapi");
    }
    None
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
        metadata: BTreeMap::new(),
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
        "ts" | "mts" | "cts" => Some("typescript"),
        "tsx" => Some("tsx"),
        "py" | "pyi" => Some("python"),
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

    #[test]
    fn strips_comments_without_changing_literals() {
        let source = r##"
const url = "https://example.test/path"; // remove me
const hash = "#still-string";
/*
remove block
*/
return url + hash;
"##;

        let normalized = normalize_body_source(source);

        assert!(normalized.contains("https://example.test/path"));
        assert!(normalized.contains("#still-string"));
        assert!(!normalized.contains("remove me"));
        assert!(!normalized.contains("remove block"));
    }

    #[test]
    fn token_estimate_counts_words_and_punctuation() {
        assert!(token_estimate("return value + 1;") >= 5);
    }
}
