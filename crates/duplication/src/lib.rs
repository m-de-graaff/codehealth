use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, Severity,
    SourceSpan,
};
use codehealth_symbols::{
    Definition, DefinitionKind, FrameworkTag, Language, LiteralPolicy, SemanticFingerprint,
    StructuralFingerprint, SymbolIndex,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

pub const EXACT_FILE_RULE: &str = "duplicate.exact.file";
pub const EXACT_BODY_RULE: &str = "duplicate.exact.body";
pub const STRUCTURAL_FUNCTION_RULE: &str = "duplicate.structural.function";
pub const NEAR_FUNCTION_RULE: &str = "duplicate.near.function";
pub const SEMANTIC_FUNCTION_RULE: &str = "duplicate.semantic.function";
pub const SEMANTIC_VECTOR_CANDIDATE_RULE: &str = "duplicate.semantic.vector_candidate";
const NEAR_DUPLICATE_VERSION: &str = "near_duplicate_v1";
const VECTOR_SUMMARY_VERSION: &str = "vector_summary_v1";
const VECTOR_CANDIDATE_VERSION: &str = "vector_candidate_v1";

pub trait EmbeddingProvider {
    fn embed(&self, input: &str) -> Vec<f32>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopEmbeddingProvider;

impl EmbeddingProvider for NoopEmbeddingProvider {
    fn embed(&self, _input: &str) -> Vec<f32> {
        Vec::new()
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralOptions {
    pub min_lines: usize,
    pub min_tokens: usize,
    pub min_nodes: usize,
    pub max_opaque_percent: u8,
    pub normalize_literals: bool,
}

impl Default for StructuralOptions {
    fn default() -> Self {
        Self {
            min_lines: 1,
            min_tokens: 5,
            min_nodes: 5,
            max_opaque_percent: 25,
            normalize_literals: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NearDuplicateOptions {
    pub min_lines: usize,
    pub min_tokens: usize,
    pub similarity_threshold: u8,
    pub hash_functions: usize,
    pub lsh_bands: usize,
    pub lsh_rows: usize,
    pub common_shingle_max_percent: u8,
    pub common_shingle_min_occurrences: usize,
    pub max_bucket_size: usize,
    pub max_candidate_pairs: usize,
}

impl Default for NearDuplicateOptions {
    fn default() -> Self {
        Self {
            min_lines: 5,
            min_tokens: 40,
            similarity_threshold: 82,
            hash_functions: 96,
            lsh_bands: 24,
            lsh_rows: 4,
            common_shingle_max_percent: 5,
            common_shingle_min_occurrences: 20,
            max_bucket_size: 200,
            max_candidate_pairs: 250_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticDuplicateOptions {
    pub min_lines: usize,
    pub min_tokens: usize,
    pub min_confidence: Confidence,
    pub property_reads_are_pure: bool,
    pub normalize_boolean_returns: bool,
    pub normalize_commutative_ops: bool,
    pub normalize_comparisons: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorCandidateOptions {
    pub min_lines: usize,
    pub min_tokens: usize,
    pub similarity_threshold: u8,
    pub candidate_limit: usize,
    pub provider_id: String,
    pub privacy_mode: String,
    pub cache_enabled: bool,
    pub cache_dir: PathBuf,
    pub skip_generated_paths: BTreeSet<PathBuf>,
}

impl Default for VectorCandidateOptions {
    fn default() -> Self {
        Self {
            min_lines: 1,
            min_tokens: 5,
            similarity_threshold: 80,
            candidate_limit: 100,
            provider_id: "none".to_string(),
            privacy_mode: "disabled".to_string(),
            cache_enabled: false,
            cache_dir: PathBuf::from(".codehealth/cache"),
            skip_generated_paths: BTreeSet::new(),
        }
    }
}

impl Default for SemanticDuplicateOptions {
    fn default() -> Self {
        Self {
            min_lines: 1,
            min_tokens: 5,
            min_confidence: Confidence::Medium,
            property_reads_are_pure: false,
            normalize_boolean_returns: true,
            normalize_commutative_ops: true,
            normalize_comparisons: true,
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
struct StructuralSymbolFingerprint {
    definition: Definition,
    line_count: usize,
    fingerprint: StructuralFingerprint,
}

#[derive(Debug, Clone)]
struct SemanticSymbolFingerprint {
    definition: Definition,
    line_count: usize,
    fingerprint: SemanticFingerprint,
    structural_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEmbeddingSummary {
    pub version: String,
    pub language: String,
    pub kind: String,
    pub name: String,
    pub qualified_name: String,
    pub signature: String,
    pub ast_summary: String,
    pub calls: Vec<String>,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub return_shape: String,
    pub framework_tags: Vec<String>,
    pub comment_context: Option<String>,
    pub input: String,
    pub stable_hash_hex: String,
}

#[derive(Debug, Clone)]
struct VectorFunctionFeature {
    definition: Definition,
    summary: FunctionEmbeddingSummary,
    vector: Vec<f32>,
    line_count: usize,
    token_estimate: usize,
    canonical_hash: String,
    signature_shape: NearSignatureShape,
    ast_shingles: WeightedShingles,
    call_shingles: WeightedShingles,
    name_shingles: WeightedShingles,
    framework_shingles: WeightedShingles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VectorPairScore {
    left: usize,
    right: usize,
    vector_similarity: u8,
    rank_score: u8,
    ast_similarity: u8,
    signature_similarity: u8,
    call_similarity: u8,
    name_similarity: u8,
    framework_similarity: u8,
}

#[derive(Debug, Clone)]
struct FileFingerprint {
    path: PathBuf,
    language: String,
    source_len: usize,
    line_count: usize,
    first_relevant_location: Location,
    fingerprint: BodyFingerprint,
}

#[derive(Debug, Clone)]
struct RawNearFunctionFeatures {
    definition: Definition,
    line_count: usize,
    token_count: usize,
    statement_count: usize,
    canonical_hash: String,
    signature_shape: NearSignatureShape,
    statements: Vec<StatementRegion>,
    token_shingles: Vec<String>,
    ast_shingles: Vec<String>,
    statement_shingles: Vec<String>,
    call_shingles: Vec<String>,
    control_shingles: Vec<String>,
}

#[derive(Debug, Clone)]
struct NearFunctionFeatures {
    definition: Definition,
    line_count: usize,
    token_count: usize,
    statement_count: usize,
    canonical_hash: String,
    feature_hash: String,
    signature_shape: NearSignatureShape,
    statements: Vec<StatementRegion>,
    token_shingles: WeightedShingles,
    ast_shingles: WeightedShingles,
    statement_shingles: WeightedShingles,
    call_shingles: WeightedShingles,
    control_shingles: WeightedShingles,
    combined_shingles: WeightedShingles,
    minhash_signature: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NearSignatureShape {
    parameter_count: usize,
    return_shape: String,
    is_async: bool,
    kind: DefinitionKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatementRegion {
    line: usize,
    normalized: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NearPairScore {
    left: usize,
    right: usize,
    score: u8,
    token_similarity: u8,
    ast_similarity: u8,
    statement_similarity: u8,
    statement_count_similarity: u8,
    call_similarity: u8,
    signature_similarity: u8,
    signature_estimate: u8,
    control_flow_similarity: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LshCandidates {
    pairs: BTreeSet<(usize, usize)>,
    skipped_large_buckets: usize,
    candidate_limit_reached: bool,
}

type WeightedShingles = BTreeMap<u64, u16>;

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
                line_count: source.lines().count().max(1),
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

pub fn find_structural_duplicates(index: &SymbolIndex, options: StructuralOptions) -> Vec<Finding> {
    let mut by_hash: BTreeMap<(Language, String), Vec<StructuralSymbolFingerprint>> =
        BTreeMap::new();

    for definition in &index.definitions {
        if !exact_body_kind(definition.kind) {
            continue;
        }
        let Some(fingerprint) = selected_structural_fingerprint(definition, options) else {
            continue;
        };
        if fingerprint.node_count < options.min_nodes
            || fingerprint.token_estimate < options.min_tokens
        {
            continue;
        }
        if opaque_percent(fingerprint) > options.max_opaque_percent {
            continue;
        }
        let line_count = structural_line_count(definition);
        if line_count < options.min_lines {
            continue;
        }

        by_hash
            .entry((definition.language, fingerprint.stable_hash_hex.clone()))
            .or_default()
            .push(StructuralSymbolFingerprint {
                definition: definition.clone(),
                line_count,
                fingerprint: fingerprint.clone(),
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
        findings.push(build_structural_finding(&group));
    }

    findings
}

pub fn find_semantic_function_duplicates(
    index: &SymbolIndex,
    options: SemanticDuplicateOptions,
) -> Vec<Finding> {
    let mut by_hash: BTreeMap<(Language, String), Vec<SemanticSymbolFingerprint>> = BTreeMap::new();

    for definition in &index.definitions {
        if !exact_body_kind(definition.kind) {
            continue;
        }
        let Some(fingerprint) = selected_semantic_fingerprint(definition, options) else {
            continue;
        };
        if !semantic_options_compatible(fingerprint, options) {
            continue;
        }
        if semantic_token_estimate(fingerprint) < options.min_tokens
            || fingerprint.confidence < options.min_confidence
        {
            continue;
        }
        let line_count = structural_line_count(definition);
        if line_count < options.min_lines {
            continue;
        }

        by_hash
            .entry((definition.language, fingerprint.stable_hash_hex.clone()))
            .or_default()
            .push(SemanticSymbolFingerprint {
                definition: definition.clone(),
                line_count,
                fingerprint: fingerprint.clone(),
                structural_hash: definition
                    .structural_fingerprint
                    .as_ref()
                    .map(|fingerprint| fingerprint.stable_hash_hex.clone()),
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
        if group
            .iter()
            .flat_map(|item| item.fingerprint.rewrites.iter())
            .collect::<BTreeSet<_>>()
            .is_empty()
        {
            continue;
        }

        let structural_hashes = group
            .iter()
            .filter_map(|item| item.structural_hash.as_deref())
            .collect::<BTreeSet<_>>();
        let structural_hash_count = group
            .iter()
            .filter(|item| item.structural_hash.is_some())
            .count();
        if structural_hashes.len() == 1 && structural_hash_count == group.len() {
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
        findings.push(build_semantic_finding(&group));
    }

    findings
}

pub fn find_vector_semantic_candidates(
    index: &SymbolIndex,
    provider: &dyn EmbeddingProvider,
    options: VectorCandidateOptions,
) -> Vec<Finding> {
    if options.candidate_limit == 0 || options.similarity_threshold == 0 {
        return Vec::new();
    }

    let mut source_cache = BTreeMap::new();
    let mut vector_cache = VectorCache::new(
        options.cache_enabled && options.provider_id != "none",
        options.cache_dir.clone(),
    );
    let mut features = Vec::new();

    for definition in &index.definitions {
        if !exact_body_kind(definition.kind)
            || options.skip_generated_paths.contains(&definition.file)
            || structural_line_count(definition) < options.min_lines
        {
            continue;
        }
        let Some(fingerprint) = definition.structural_fingerprint.as_ref() else {
            continue;
        };
        if fingerprint.token_estimate < options.min_tokens {
            continue;
        }
        let summary = embedding_summary_for_definition(definition, &mut source_cache);
        let vector = vector_cache
            .get(&options.provider_id, &options.privacy_mode, &summary)
            .unwrap_or_else(|| {
                let vector = provider.embed(&summary.input);
                if !vector.is_empty() {
                    vector_cache.put(
                        &options.provider_id,
                        &options.privacy_mode,
                        &summary,
                        &vector,
                    );
                }
                vector
            });
        let Some(vector) = normalize_vector(vector) else {
            continue;
        };
        features.push(vector_feature(definition, fingerprint, summary, vector));
    }

    if features.len() < 2 {
        return Vec::new();
    }

    features.sort_by(|left, right| {
        left.definition
            .language
            .cmp(&right.definition.language)
            .then_with(|| left.definition.file.cmp(&right.definition.file))
            .then_with(|| left.definition.span.start.cmp(&right.definition.span.start))
            .then_with(|| {
                left.definition
                    .qualified_name
                    .cmp(&right.definition.qualified_name)
            })
    });

    let candidate_pairs = vector_lsh_candidate_pairs(&features, options.candidate_limit);
    let mut pair_scores = Vec::new();
    for (left, right) in candidate_pairs {
        let left_feature = &features[left];
        let right_feature = &features[right];
        if left_feature.definition.language != right_feature.definition.language
            || left_feature.canonical_hash == right_feature.canonical_hash
        {
            continue;
        }
        let score = vector_pair_score(left, right, left_feature, right_feature);
        if score.vector_similarity >= options.similarity_threshold
            && vector_pair_has_deterministic_support(score)
        {
            pair_scores.push(score);
        }
    }

    if pair_scores.is_empty() {
        return Vec::new();
    }

    connected_vector_groups(&pair_scores)
        .into_iter()
        .map(|group| build_vector_candidate_finding(&features, &pair_scores, &group, &options))
        .collect()
}

pub fn find_near_function_duplicates(
    index: &SymbolIndex,
    options: NearDuplicateOptions,
) -> Vec<Finding> {
    if options.hash_functions == 0
        || options.lsh_bands == 0
        || options.lsh_rows == 0
        || options.hash_functions != options.lsh_bands * options.lsh_rows
    {
        return Vec::new();
    }

    let mut source_cache = BTreeMap::new();
    let mut raw_features = Vec::new();
    for definition in &index.definitions {
        if !exact_body_kind(definition.kind) {
            continue;
        }
        let Some(preserved_fingerprint) = definition.structural_fingerprint.as_ref() else {
            continue;
        };
        let feature_fingerprint = definition
            .literal_normalized_structural_fingerprint
            .as_ref()
            .unwrap_or(preserved_fingerprint);
        let Some(raw) = raw_near_features(
            definition,
            &preserved_fingerprint.stable_hash_hex,
            feature_fingerprint,
            options,
            &mut source_cache,
        )
        .ok()
        .flatten() else {
            continue;
        };
        raw_features.push(raw);
    }

    if raw_features.len() < 2 {
        return Vec::new();
    }

    raw_features.sort_by(|left, right| {
        left.definition
            .language
            .cmp(&right.definition.language)
            .then_with(|| left.definition.file.cmp(&right.definition.file))
            .then_with(|| left.definition.span.start.cmp(&right.definition.span.start))
            .then_with(|| {
                left.definition
                    .qualified_name
                    .cmp(&right.definition.qualified_name)
            })
    });

    let document_frequency = near_document_frequency(&raw_features);
    let total_definitions = raw_features.len();
    let mut features = raw_features
        .into_iter()
        .filter_map(|raw| near_features(raw, &document_frequency, total_definitions, options))
        .collect::<Vec<_>>();

    for feature in &mut features {
        feature.minhash_signature = minhash_signature(&feature.combined_shingles, options);
    }

    if features.len() < 2 {
        return Vec::new();
    }

    let candidates = lsh_candidate_pairs(&features, options);
    let mut pair_scores = Vec::new();
    for (left, right) in &candidates.pairs {
        let left_feature = &features[*left];
        let right_feature = &features[*right];
        if left_feature.definition.language != right_feature.definition.language {
            continue;
        }
        if left_feature.canonical_hash == right_feature.canonical_hash {
            continue;
        }
        let score = near_pair_score(*left, *right, left_feature, right_feature);
        if score.score >= options.similarity_threshold {
            pair_scores.push(score);
        }
    }

    if pair_scores.is_empty() {
        return Vec::new();
    }

    let groups = connected_near_groups(&pair_scores);
    groups
        .into_iter()
        .map(|group| build_near_finding(&features, &pair_scores, &group, &candidates))
        .collect()
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

fn selected_structural_fingerprint(
    definition: &Definition,
    options: StructuralOptions,
) -> Option<&StructuralFingerprint> {
    if options.normalize_literals {
        definition
            .literal_normalized_structural_fingerprint
            .as_ref()
    } else {
        definition.structural_fingerprint.as_ref()
    }
}

fn structural_line_count(definition: &Definition) -> usize {
    let span = definition.body_span.unwrap_or(definition.span);
    span.end_position
        .line
        .saturating_sub(span.start_position.line)
        + 1
}

fn opaque_percent(fingerprint: &StructuralFingerprint) -> u8 {
    if fingerprint.node_count == 0 {
        return 100;
    }

    ((fingerprint.opaque_node_count * 100) / fingerprint.node_count)
        .try_into()
        .unwrap_or(100)
}

fn raw_near_features(
    definition: &Definition,
    preserved_canonical_hash: &str,
    fingerprint: &StructuralFingerprint,
    options: NearDuplicateOptions,
    source_cache: &mut BTreeMap<PathBuf, String>,
) -> Result<Option<RawNearFunctionFeatures>, DuplicateError> {
    let Some(body_span) = definition.body_span else {
        return Ok(None);
    };
    let line_count = structural_line_count(definition);
    if line_count < options.min_lines {
        return Ok(None);
    }
    let source = source_for_definition(definition, source_cache)?;
    if body_span.end > source.len()
        || !source.is_char_boundary(body_span.start)
        || !source.is_char_boundary(body_span.end)
    {
        return Ok(None);
    }

    let body = &source[body_span.start..body_span.end];
    let stripped_body = strip_comments_preserving_literals(body).replace("\r\n", "\n");
    let body_tokens = lexical_tokens(&stripped_body);
    let token_count = body_tokens.len().max(fingerprint.token_estimate);
    if token_count < options.min_tokens {
        return Ok(None);
    }
    let canonical_tokens = lexical_tokens(&fingerprint.serialization);
    let ast_paths = ast_path_tokens(&fingerprint.serialization);
    let statements = statement_regions(&stripped_body, body_span.start_position.line);
    let statement_tokens = statements
        .iter()
        .map(|statement| statement.normalized.clone())
        .collect::<Vec<_>>();
    let control_tokens = control_flow_tokens(&body_tokens);
    let size = near_shingle_size(token_count);
    let statement_size = near_statement_shingle_size(token_count);

    Ok(Some(RawNearFunctionFeatures {
        definition: definition.clone(),
        line_count,
        token_count,
        statement_count: statement_tokens.len(),
        canonical_hash: preserved_canonical_hash.to_string(),
        signature_shape: NearSignatureShape {
            parameter_count: fingerprint.parameter_count,
            return_shape: fingerprint.return_shape.clone(),
            is_async: fingerprint.is_async,
            kind: definition.kind,
        },
        statements,
        token_shingles: shingle_strings(&canonical_tokens, size),
        ast_shingles: shingle_strings(&ast_paths, near_ast_shingle_size(token_count)),
        statement_shingles: shingle_strings(&statement_tokens, statement_size),
        call_shingles: shingle_strings(&fingerprint.call_names, 1),
        control_shingles: shingle_strings(&control_tokens, 1),
    }))
}

fn near_features(
    raw: RawNearFunctionFeatures,
    document_frequency: &BTreeMap<u64, usize>,
    total_definitions: usize,
    options: NearDuplicateOptions,
) -> Option<NearFunctionFeatures> {
    let token_shingles = weighted_shingles(
        "token",
        &raw.token_shingles,
        document_frequency,
        total_definitions,
        options,
    );
    let ast_shingles = weighted_shingles(
        "ast",
        &raw.ast_shingles,
        document_frequency,
        total_definitions,
        options,
    );
    let statement_shingles = weighted_shingles(
        "statement",
        &raw.statement_shingles,
        document_frequency,
        total_definitions,
        options,
    );
    let call_shingles = weighted_shingles(
        "call",
        &raw.call_shingles,
        document_frequency,
        total_definitions,
        options,
    );
    let control_shingles = weighted_shingles(
        "control",
        &raw.control_shingles,
        document_frequency,
        total_definitions,
        options,
    );
    let combined_shingles = combine_weighted_shingles(&[
        &token_shingles,
        &ast_shingles,
        &statement_shingles,
        &call_shingles,
        &control_shingles,
    ]);
    if combined_shingles.is_empty() {
        return None;
    }
    let feature_hash = near_feature_hash(
        raw.definition.language,
        &raw.canonical_hash,
        &combined_shingles,
    );

    Some(NearFunctionFeatures {
        definition: raw.definition,
        line_count: raw.line_count,
        token_count: raw.token_count,
        statement_count: raw.statement_count,
        canonical_hash: raw.canonical_hash,
        feature_hash,
        signature_shape: raw.signature_shape,
        statements: raw.statements,
        token_shingles,
        ast_shingles,
        statement_shingles,
        call_shingles,
        control_shingles,
        combined_shingles,
        minhash_signature: Vec::new(),
    })
}

fn near_document_frequency(features: &[RawNearFunctionFeatures]) -> BTreeMap<u64, usize> {
    let mut frequency = BTreeMap::new();
    for feature in features {
        let mut document = BTreeSet::new();
        insert_shingle_hashes(&mut document, "token", &feature.token_shingles);
        insert_shingle_hashes(&mut document, "ast", &feature.ast_shingles);
        insert_shingle_hashes(&mut document, "statement", &feature.statement_shingles);
        insert_shingle_hashes(&mut document, "call", &feature.call_shingles);
        insert_shingle_hashes(&mut document, "control", &feature.control_shingles);
        for hash in document {
            *frequency.entry(hash).or_insert(0) += 1;
        }
    }
    frequency
}

fn insert_shingle_hashes(document: &mut BTreeSet<u64>, namespace: &str, shingles: &[String]) {
    for shingle in shingles {
        document.insert(shingle_hash(namespace, shingle));
    }
}

fn weighted_shingles(
    namespace: &str,
    shingles: &[String],
    document_frequency: &BTreeMap<u64, usize>,
    total_definitions: usize,
    options: NearDuplicateOptions,
) -> WeightedShingles {
    let common_cutoff = common_shingle_cutoff(total_definitions, options);
    let mut output: WeightedShingles = BTreeMap::new();
    for shingle in shingles {
        let hash = shingle_hash(namespace, shingle);
        let frequency = document_frequency.get(&hash).copied().unwrap_or(1);
        if frequency >= common_cutoff {
            continue;
        }
        let weight = rare_shingle_weight(total_definitions, frequency);
        output
            .entry(hash)
            .and_modify(|existing| *existing = (*existing).max(weight))
            .or_insert(weight);
    }
    output
}

fn combine_weighted_shingles(groups: &[&WeightedShingles]) -> WeightedShingles {
    let mut combined = BTreeMap::new();
    for group in groups {
        for (hash, weight) in *group {
            combined
                .entry(*hash)
                .and_modify(|existing: &mut u16| *existing = (*existing).max(*weight))
                .or_insert(*weight);
        }
    }
    combined
}

fn common_shingle_cutoff(total_definitions: usize, options: NearDuplicateOptions) -> usize {
    let percent_cutoff = total_definitions * usize::from(options.common_shingle_max_percent) / 100;
    options
        .common_shingle_min_occurrences
        .max(percent_cutoff)
        .max(2)
}

fn rare_shingle_weight(total_definitions: usize, frequency: usize) -> u16 {
    let frequency = frequency.max(1);
    let mut ratio = total_definitions / frequency;
    let mut weight = 1;
    while ratio >= 2 && weight < 8 {
        weight += 1;
        ratio /= 2;
    }
    weight
}

fn near_shingle_size(token_count: usize) -> usize {
    if token_count < 80 {
        3
    } else if token_count < 250 {
        5
    } else {
        7
    }
}

fn near_ast_shingle_size(token_count: usize) -> usize {
    if token_count < 80 {
        3
    } else if token_count < 250 {
        4
    } else {
        5
    }
}

fn near_statement_shingle_size(token_count: usize) -> usize {
    if token_count < 80 {
        1
    } else if token_count < 250 {
        2
    } else {
        3
    }
}

fn shingle_strings(tokens: &[String], size: usize) -> Vec<String> {
    if tokens.is_empty() {
        return Vec::new();
    }
    let size = size.max(1).min(tokens.len());
    tokens
        .windows(size)
        .map(|window| window.join(" "))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn lexical_tokens(source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let push_current = |current: &mut String, tokens: &mut Vec<String>| {
        if !current.is_empty() {
            tokens.push(current.to_ascii_lowercase());
            current.clear();
        }
    };

    for character in source.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            current.push(character);
        } else {
            push_current(&mut current, &mut tokens);
            if !character.is_whitespace() {
                tokens.push(character.to_string());
            }
        }
    }
    push_current(&mut current, &mut tokens);
    tokens
}

fn ast_path_tokens(serialization: &str) -> Vec<String> {
    let node_names = lexical_tokens(serialization)
        .into_iter()
        .filter(|token| canonical_node_token(token))
        .collect::<Vec<_>>();
    let mut paths = Vec::new();
    let mut stack = Vec::<String>::new();
    for token in node_names {
        stack.push(token);
        if stack.len() > 4 {
            stack.remove(0);
        }
        paths.push(stack.join(">"));
    }
    paths
}

fn canonical_node_token(token: &str) -> bool {
    matches!(
        token,
        "function"
            | "params"
            | "block"
            | "return"
            | "if"
            | "binary"
            | "call"
            | "member"
            | "identifier"
            | "literal"
            | "assign"
            | "await"
            | "match"
            | "try"
            | "macro"
            | "unsafe"
            | "opaque"
            | "empty"
    )
}

fn statement_regions(source: &str, start_line: usize) -> Vec<StatementRegion> {
    let mut regions = Vec::new();
    for (offset, line) in source.lines().enumerate() {
        let normalized = normalize_source(
            line.trim()
                .trim_matches('{')
                .trim_matches('}')
                .trim_end_matches(';')
                .trim(),
        );
        if normalized.is_empty() || matches!(normalized.as_str(), "{" | "}" | ");" | "};") {
            continue;
        }
        regions.push(StatementRegion {
            line: start_line + offset,
            normalized,
        });
    }
    regions
}

fn control_flow_tokens(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| {
            matches!(
                token.as_str(),
                "if" | "else"
                    | "for"
                    | "while"
                    | "match"
                    | "case"
                    | "catch"
                    | "except"
                    | "try"
                    | "return"
                    | "await"
                    | "?"
            )
        })
        .cloned()
        .collect()
}

fn shingle_hash(namespace: &str, shingle: &str) -> u64 {
    xxh3_64(format!("{NEAR_DUPLICATE_VERSION}|{namespace}|{shingle}").as_bytes())
}

fn seeded_hash(seed: usize, value: u64) -> u64 {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&(seed as u64).to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    xxh3_64(&bytes)
}

fn minhash_signature(shingles: &WeightedShingles, options: NearDuplicateOptions) -> Vec<u64> {
    if shingles.is_empty() {
        return vec![u64::MAX; options.hash_functions];
    }
    (0..options.hash_functions)
        .map(|seed| {
            shingles
                .keys()
                .map(|hash| seeded_hash(seed, *hash))
                .min()
                .unwrap_or(u64::MAX)
        })
        .collect()
}

fn minhash_estimate(left: &[u64], right: &[u64]) -> u8 {
    let total = left.len().min(right.len());
    if total == 0 {
        return 0;
    }
    let equal = left
        .iter()
        .zip(right.iter())
        .filter(|(left, right)| left == right)
        .count();
    percent(equal, total)
}

fn lsh_candidate_pairs(
    features: &[NearFunctionFeatures],
    options: NearDuplicateOptions,
) -> LshCandidates {
    let mut buckets: BTreeMap<(Language, usize, u64), Vec<usize>> = BTreeMap::new();
    for (index, feature) in features.iter().enumerate() {
        if feature
            .minhash_signature
            .iter()
            .all(|value| *value == u64::MAX)
        {
            continue;
        }
        for band in 0..options.lsh_bands {
            let start = band * options.lsh_rows;
            let end = start + options.lsh_rows;
            if end > feature.minhash_signature.len() {
                continue;
            }
            let hash = band_hash(band, &feature.minhash_signature[start..end]);
            buckets
                .entry((feature.definition.language, band, hash))
                .or_default()
                .push(index);
        }
        let shape_hash = near_shape_bucket_hash(feature);
        buckets
            .entry((
                feature.definition.language,
                options.lsh_bands + 1,
                shape_hash,
            ))
            .or_default()
            .push(index);
    }

    let mut pairs = BTreeSet::new();
    let mut skipped_large_buckets = 0;
    let mut candidate_limit_reached = false;
    for bucket in buckets.values() {
        if bucket.len() > options.max_bucket_size {
            skipped_large_buckets += 1;
            continue;
        }
        for left_index in 0..bucket.len() {
            for right_index in left_index + 1..bucket.len() {
                let left = bucket[left_index].min(bucket[right_index]);
                let right = bucket[left_index].max(bucket[right_index]);
                pairs.insert((left, right));
                if pairs.len() >= options.max_candidate_pairs {
                    candidate_limit_reached = true;
                    return LshCandidates {
                        pairs,
                        skipped_large_buckets,
                        candidate_limit_reached,
                    };
                }
            }
        }
    }

    LshCandidates {
        pairs,
        skipped_large_buckets,
        candidate_limit_reached,
    }
}

fn near_shape_bucket_hash(feature: &NearFunctionFeatures) -> u64 {
    let token_bucket = feature.token_count / 25;
    let statement_bucket = feature.statement_count / 2;
    xxh3_64(
        format!(
            "near-shape|{}|{}|{}|{}|{}|{}",
            feature.definition.language,
            feature.signature_shape.kind.label(),
            feature.signature_shape.parameter_count,
            feature.signature_shape.is_async,
            token_bucket,
            statement_bucket
        )
        .as_bytes(),
    )
}

fn band_hash(band: usize, values: &[u64]) -> u64 {
    let mut bytes = Vec::with_capacity(8 + values.len() * 8);
    bytes.extend_from_slice(&(band as u64).to_le_bytes());
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    xxh3_64(&bytes)
}

fn near_pair_score(
    left: usize,
    right: usize,
    left_feature: &NearFunctionFeatures,
    right_feature: &NearFunctionFeatures,
) -> NearPairScore {
    let token_similarity =
        weighted_jaccard(&left_feature.token_shingles, &right_feature.token_shingles);
    let ast_similarity = weighted_jaccard(&left_feature.ast_shingles, &right_feature.ast_shingles);
    let statement_similarity = weighted_jaccard(
        &left_feature.statement_shingles,
        &right_feature.statement_shingles,
    );
    let statement_count_similarity =
        count_similarity(left_feature.statement_count, right_feature.statement_count);
    let call_similarity =
        weighted_jaccard(&left_feature.call_shingles, &right_feature.call_shingles);
    let signature_similarity = signature_similarity(
        &left_feature.signature_shape,
        &right_feature.signature_shape,
    );
    let signature_estimate = minhash_estimate(
        &left_feature.minhash_signature,
        &right_feature.minhash_signature,
    );
    let control_flow_similarity = weighted_jaccard(
        &left_feature.control_shingles,
        &right_feature.control_shingles,
    );
    let score = weighted_average(&[
        (token_similarity, 30),
        (ast_similarity, 25),
        (statement_similarity, 15),
        (statement_count_similarity, 5),
        (call_similarity, 10),
        (signature_estimate, 10),
        (control_flow_similarity, 5),
    ]);

    NearPairScore {
        left,
        right,
        score,
        token_similarity,
        ast_similarity,
        statement_similarity,
        statement_count_similarity,
        call_similarity,
        signature_similarity,
        signature_estimate,
        control_flow_similarity,
    }
}

fn weighted_jaccard(left: &WeightedShingles, right: &WeightedShingles) -> u8 {
    if left.is_empty() && right.is_empty() {
        return 100;
    }
    if left.is_empty() || right.is_empty() {
        return 0;
    }
    let keys = left
        .keys()
        .chain(right.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut intersection = 0usize;
    let mut union = 0usize;
    for key in keys {
        let left_weight = left.get(&key).copied().unwrap_or(0);
        let right_weight = right.get(&key).copied().unwrap_or(0);
        intersection += usize::from(left_weight.min(right_weight));
        union += usize::from(left_weight.max(right_weight));
    }
    percent(intersection, union)
}

fn count_similarity(left: usize, right: usize) -> u8 {
    if left == 0 && right == 0 {
        return 100;
    }
    let min = left.min(right);
    let max = left.max(right);
    percent(min, max)
}

fn signature_similarity(left: &NearSignatureShape, right: &NearSignatureShape) -> u8 {
    if left == right {
        return 100;
    }
    let mut score = 0;
    if left.parameter_count == right.parameter_count {
        score += 40;
    }
    if left.return_shape == right.return_shape {
        score += 30;
    }
    if left.is_async == right.is_async {
        score += 20;
    }
    if left.kind == right.kind {
        score += 10;
    }
    score
}

fn weighted_average(values: &[(u8, usize)]) -> u8 {
    let total_weight = values.iter().map(|(_, weight)| *weight).sum::<usize>();
    if total_weight == 0 {
        return 0;
    }
    let weighted = values
        .iter()
        .map(|(value, weight)| usize::from(*value) * *weight)
        .sum::<usize>();
    ((weighted + total_weight / 2) / total_weight)
        .try_into()
        .unwrap_or(100)
}

fn percent(numerator: usize, denominator: usize) -> u8 {
    if denominator == 0 {
        return 0;
    }
    (((numerator * 100) + denominator / 2) / denominator)
        .min(100)
        .try_into()
        .unwrap_or(100)
}

fn connected_near_groups(pair_scores: &[NearPairScore]) -> Vec<Vec<usize>> {
    let mut adjacency: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for pair in pair_scores {
        adjacency.entry(pair.left).or_default().insert(pair.right);
        adjacency.entry(pair.right).or_default().insert(pair.left);
    }

    let mut visited = BTreeSet::new();
    let mut groups = Vec::new();
    for start in adjacency.keys().copied().collect::<Vec<_>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![start];
        let mut group = BTreeSet::new();
        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }
            group.insert(node);
            if let Some(neighbors) = adjacency.get(&node) {
                for neighbor in neighbors.iter().rev() {
                    if !visited.contains(neighbor) {
                        stack.push(*neighbor);
                    }
                }
            }
        }
        if group.len() > 1 {
            groups.push(group.into_iter().collect());
        }
    }
    groups
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
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn build_structural_finding(group: &[StructuralSymbolFingerprint]) -> Finding {
    let fingerprint = &group[0].fingerprint;
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
    let baseline_key = stable_key(
        STRUCTURAL_FUNCTION_RULE,
        &fingerprint.stable_hash_hex,
        &symbol_fingerprint,
    );
    let names = group
        .iter()
        .map(|item| item.definition.name.clone())
        .collect::<BTreeSet<_>>();
    let qualified_names = group
        .iter()
        .map(|item| item.definition.qualified_name.clone())
        .collect::<Vec<_>>();
    let kinds = group
        .iter()
        .map(|item| item.definition.kind.label().to_string())
        .collect::<BTreeSet<_>>();
    let line_count = group.iter().map(|item| item.line_count).max().unwrap_or(0);
    let max_opaque_percent = group
        .iter()
        .map(|item| opaque_percent(&item.fingerprint))
        .max()
        .unwrap_or(0);
    let names_differ = names.len() > 1;
    let language = shared_structural_language(group);
    let framework = shared_structural_framework(group);
    let confidence_score = structural_confidence_score(group);
    let signals = structural_signals(group);
    let domain_warning = names_differ
        || group
            .iter()
            .map(|item| owner_context(&item.definition))
            .collect::<BTreeSet<_>>()
            .len()
            > 1;

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "canonical_hash".to_string(),
        serde_json::json!(&fingerprint.stable_hash_hex),
    );
    metadata.insert(
        "canonical_version".to_string(),
        serde_json::json!(&fingerprint.version),
    );
    metadata.insert(
        "literal_policy".to_string(),
        serde_json::json!(literal_policy_label(fingerprint.literal_policy)),
    );
    metadata.insert(
        "node_count".to_string(),
        serde_json::json!(fingerprint.node_count),
    );
    metadata.insert(
        "opaque_node_count".to_string(),
        serde_json::json!(fingerprint.opaque_node_count),
    );
    metadata.insert(
        "opaque_ratio".to_string(),
        serde_json::json!(max_opaque_percent as f64 / 100.0),
    );
    metadata.insert(
        "opaque_percent".to_string(),
        serde_json::json!(max_opaque_percent),
    );
    metadata.insert("line_count".to_string(), serde_json::json!(line_count));
    metadata.insert(
        "token_estimate".to_string(),
        serde_json::json!(fingerprint.token_estimate),
    );
    metadata.insert(
        "parameter_count".to_string(),
        serde_json::json!(fingerprint.parameter_count),
    );
    metadata.insert(
        "return_shape".to_string(),
        serde_json::json!(&fingerprint.return_shape),
    );
    metadata.insert(
        "call_names".to_string(),
        serde_json::json!(&fingerprint.call_names),
    );
    metadata.insert(
        "framework_context".to_string(),
        serde_json::json!(&fingerprint.framework_context),
    );
    metadata.insert(
        "symbol_names".to_string(),
        serde_json::json!(names.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert(
        "qualified_names".to_string(),
        serde_json::json!(qualified_names),
    );
    metadata.insert(
        "definition_kinds".to_string(),
        serde_json::json!(kinds.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert("names_differ".to_string(), serde_json::json!(names_differ));
    metadata.insert(
        "domain_warning".to_string(),
        serde_json::json!(domain_warning),
    );
    metadata.insert(
        "confidence_score".to_string(),
        serde_json::json!(confidence_score),
    );
    metadata.insert("signals".to_string(), serde_json::json!(signals));

    Finding {
        finding_id: format!("{}:{}", STRUCTURAL_FUNCTION_RULE, &baseline_key[..12]),
        baseline_key,
        rule_id: STRUCTURAL_FUNCTION_RULE.to_string(),
        kind: FindingKind::StructuralDuplicate,
        severity: Severity::Medium,
        confidence: if confidence_score >= 75 {
            Confidence::High
        } else {
            Confidence::Medium
        },
        message: format!(
            "{} symbols have the same canonical AST after identifier normalization.",
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
        explanation: "These symbols have the same canonical AST after parameters and local identifiers are renamed. Treat this as a high-confidence clone signal, not proof that the domain behavior should be merged."
            .to_string(),
        remediation:
            "Compare the domain intent, then extract a shared helper, consolidate behind one exported function, or keep the duplication with a suppression comment and reason."
                .to_string(),
        detection_reason:
            "The detector serialized a normalized AST, preserved API/member names, and grouped definitions by the canonical structural hash."
                .to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation:
            "Structural duplicates are not auto-fixed because equivalent shape can still represent intentionally separate domain behavior, public APIs, ownership rules, or side effects."
                .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn build_semantic_finding(group: &[SemanticSymbolFingerprint]) -> Finding {
    let fingerprint = &group[0].fingerprint;
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
    let baseline_key = stable_key(
        SEMANTIC_FUNCTION_RULE,
        &fingerprint.stable_hash_hex,
        &symbol_fingerprint,
    );
    let names = group
        .iter()
        .map(|item| item.definition.name.clone())
        .collect::<BTreeSet<_>>();
    let qualified_names = group
        .iter()
        .map(|item| item.definition.qualified_name.clone())
        .collect::<Vec<_>>();
    let kinds = group
        .iter()
        .map(|item| item.definition.kind.label().to_string())
        .collect::<BTreeSet<_>>();
    let canonical_hashes = group
        .iter()
        .filter_map(|item| item.structural_hash.clone())
        .collect::<BTreeSet<_>>();
    let line_count = group.iter().map(|item| item.line_count).max().unwrap_or(0);
    let token_estimate = group
        .iter()
        .map(|item| semantic_token_estimate(&item.fingerprint))
        .max()
        .unwrap_or(0);
    let confidence = group
        .iter()
        .map(|item| item.fingerprint.confidence)
        .min()
        .unwrap_or(Confidence::Medium);
    let language = shared_semantic_language(group);
    let framework = shared_semantic_framework(group);
    let rewrites = union_metadata(group, |item| &item.fingerprint.rewrites);
    let skipped_rewrites = union_metadata(group, |item| &item.fingerprint.skipped_rewrites);
    let safety_warnings = union_metadata(group, |item| &item.fingerprint.safety_warnings);
    let type_evidence = union_metadata(group, |item| &item.fingerprint.type_evidence);
    let signals = semantic_signals(&rewrites, confidence, canonical_hashes.len());

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "semantic_hash".to_string(),
        serde_json::json!(&fingerprint.stable_hash_hex),
    );
    metadata.insert(
        "semantic_version".to_string(),
        serde_json::json!(&fingerprint.version),
    );
    metadata.insert(
        "semantic_rewrites".to_string(),
        serde_json::json!(&rewrites),
    );
    metadata.insert(
        "skipped_rewrites".to_string(),
        serde_json::json!(&skipped_rewrites),
    );
    metadata.insert(
        "safety_warnings".to_string(),
        serde_json::json!(&safety_warnings),
    );
    metadata.insert(
        "type_evidence".to_string(),
        serde_json::json!(&type_evidence),
    );
    metadata.insert(
        "canonical_hashes".to_string(),
        serde_json::json!(canonical_hashes.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert(
        "symbol_names".to_string(),
        serde_json::json!(names.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert(
        "qualified_names".to_string(),
        serde_json::json!(qualified_names),
    );
    metadata.insert(
        "definition_kinds".to_string(),
        serde_json::json!(kinds.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert("line_count".to_string(), serde_json::json!(line_count));
    metadata.insert(
        "token_estimate".to_string(),
        serde_json::json!(token_estimate),
    );
    metadata.insert(
        "confidence_floor".to_string(),
        serde_json::json!(confidence.to_string()),
    );
    metadata.insert("signals".to_string(), serde_json::json!(signals));

    Finding {
        finding_id: format!("{}:{}", SEMANTIC_FUNCTION_RULE, &baseline_key[..12]),
        baseline_key,
        rule_id: SEMANTIC_FUNCTION_RULE.to_string(),
        kind: FindingKind::SemanticCandidate,
        severity: Severity::Medium,
        confidence,
        message: format!(
            "{} definitions share a conservative semantic fingerprint.",
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
        explanation: "These definitions normalize to the same conservative semantic fingerprint after safe rewrites such as typed numeric operand ordering, equality operand ordering, comparison inversion, or boolean-return simplification. This is a semantic clone signal, not proof of identical runtime behavior."
            .to_string(),
        remediation: "Compare the intent and edge cases, then extract a shared helper, consolidate validation, keep the definitions separate with documentation, or suppress intentional duplication with a reason."
            .to_string(),
        detection_reason: "The detector applied only conservative semantic rewrites and grouped definitions by the resulting stable semantic hash. Unsafe rewrites involving calls, awaits, mutation, property reads, macros, unsafe blocks, or unproven dynamic operators are skipped."
            .to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: "Semantic duplicate candidates are not auto-fixed because refactoring can change APIs, imports, side effects, ownership, async behavior, and domain boundaries."
            .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn build_near_finding(
    features: &[NearFunctionFeatures],
    pair_scores: &[NearPairScore],
    group: &[usize],
    candidates: &LshCandidates,
) -> Finding {
    let group_set = group.iter().copied().collect::<BTreeSet<_>>();
    let mut group_features = group
        .iter()
        .map(|index| &features[*index])
        .collect::<Vec<_>>();
    group_features.sort_by(|left, right| {
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
    let group_pair_scores = pair_scores
        .iter()
        .filter(|pair| group_set.contains(&pair.left) && group_set.contains(&pair.right))
        .copied()
        .collect::<Vec<_>>();
    let similarity_score = average_pair_score(&group_pair_scores);
    let strongest_pair = group_pair_scores
        .iter()
        .max_by(|left, right| {
            left.score
                .cmp(&right.score)
                .then_with(|| right.left.cmp(&left.left))
                .then_with(|| right.right.cmp(&left.right))
        })
        .copied();
    let feature_hashes = group_features
        .iter()
        .map(|feature| feature.feature_hash.clone())
        .collect::<Vec<_>>();
    let near_group_hash = stable_near_group_hash(&feature_hashes);
    let qualified_names = group_features
        .iter()
        .map(|feature| feature.definition.qualified_name.clone())
        .collect::<Vec<_>>();
    let names = group_features
        .iter()
        .map(|feature| feature.definition.name.clone())
        .collect::<BTreeSet<_>>();
    let kinds = group_features
        .iter()
        .map(|feature| feature.definition.kind.label().to_string())
        .collect::<BTreeSet<_>>();
    let group_fingerprint = qualified_names.join("|");
    let baseline_key = stable_key(NEAR_FUNCTION_RULE, &near_group_hash, &group_fingerprint);
    let language = shared_near_language(&group_features);
    let framework = shared_near_framework(&group_features);
    let pair_score_json = group_pair_scores
        .iter()
        .map(|pair| {
            serde_json::json!({
                "left": &features[pair.left].definition.qualified_name,
                "right": &features[pair.right].definition.qualified_name,
                "score": pair.score,
                "tokenSimilarity": pair.token_similarity,
                "astSimilarity": pair.ast_similarity,
                "statementSimilarity": pair.statement_similarity,
                "statementCountSimilarity": pair.statement_count_similarity,
                "callSimilarity": pair.call_similarity,
                "signatureSimilarity": pair.signature_similarity,
                "signatureEstimate": pair.signature_estimate,
                "controlFlowSimilarity": pair.control_flow_similarity,
            })
        })
        .collect::<Vec<_>>();
    let signals = near_group_signals(&group_pair_scores, &group_features);
    let (similar_regions, differing_regions) = strongest_pair
        .map(|pair| similar_and_differing_regions(&features[pair.left], &features[pair.right]))
        .unwrap_or_default();
    let max_lines = group_features
        .iter()
        .map(|feature| feature.line_count)
        .max()
        .unwrap_or(0);
    let max_tokens = group_features
        .iter()
        .map(|feature| feature.token_count)
        .max()
        .unwrap_or(0);
    let max_statements = group_features
        .iter()
        .map(|feature| feature.statement_count)
        .max()
        .unwrap_or(0);

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "near_group_hash".to_string(),
        serde_json::json!(&near_group_hash),
    );
    metadata.insert(
        "near_version".to_string(),
        serde_json::json!(NEAR_DUPLICATE_VERSION),
    );
    metadata.insert(
        "similarity_score".to_string(),
        serde_json::json!(similarity_score),
    );
    metadata.insert(
        "similarity_percent".to_string(),
        serde_json::json!(similarity_score),
    );
    metadata.insert(
        "pair_scores".to_string(),
        serde_json::json!(pair_score_json),
    );
    metadata.insert("signals".to_string(), serde_json::json!(signals));
    metadata.insert(
        "symbol_names".to_string(),
        serde_json::json!(names.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert(
        "qualified_names".to_string(),
        serde_json::json!(qualified_names),
    );
    metadata.insert(
        "definition_kinds".to_string(),
        serde_json::json!(kinds.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert("line_count".to_string(), serde_json::json!(max_lines));
    metadata.insert("token_estimate".to_string(), serde_json::json!(max_tokens));
    metadata.insert(
        "statement_count".to_string(),
        serde_json::json!(max_statements),
    );
    metadata.insert(
        "token_similarity".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| pair.token_similarity)),
    );
    metadata.insert(
        "ast_similarity".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| pair.ast_similarity)),
    );
    metadata.insert(
        "statement_similarity".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| pair.statement_similarity)),
    );
    metadata.insert(
        "statement_count_similarity".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| {
            pair.statement_count_similarity
        })),
    );
    metadata.insert(
        "call_similarity".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| pair.call_similarity)),
    );
    metadata.insert(
        "signature_similarity".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| {
            pair.signature_similarity
        })),
    );
    metadata.insert(
        "signature_estimate".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| pair.signature_estimate)),
    );
    metadata.insert(
        "control_flow_similarity".to_string(),
        serde_json::json!(average_metric(&group_pair_scores, |pair| {
            pair.control_flow_similarity
        })),
    );
    metadata.insert(
        "similar_regions".to_string(),
        serde_json::json!(similar_regions),
    );
    metadata.insert(
        "differing_regions".to_string(),
        serde_json::json!(differing_regions),
    );
    metadata.insert(
        "candidate_limit_reached".to_string(),
        serde_json::json!(candidates.candidate_limit_reached),
    );
    metadata.insert(
        "skipped_large_buckets".to_string(),
        serde_json::json!(candidates.skipped_large_buckets),
    );
    metadata.insert(
        "feature_hashes".to_string(),
        serde_json::json!(feature_hashes),
    );

    Finding {
        finding_id: format!("{}:{}", NEAR_FUNCTION_RULE, &baseline_key[..12]),
        baseline_key,
        rule_id: NEAR_FUNCTION_RULE.to_string(),
        kind: FindingKind::NearDuplicate,
        severity: Severity::Medium,
        confidence: if similarity_score >= 90 {
            Confidence::High
        } else {
            Confidence::Medium
        },
        message: format!("{} definitions are suspiciously similar.", group_features.len()),
        locations: group_features
            .iter()
            .map(|feature| FindingLocation {
                path: feature.definition.file.clone(),
                span: feature.definition.body_span.map(|span| SourceSpan {
                    start: span.start,
                    end: span.end,
                }),
                start: feature.definition.body_span.map(|span| Location {
                    line: span.start_position.line,
                    column: span.start_position.column,
                    byte_offset: span.start,
                }),
                language: Some(feature.definition.language.label().to_string()),
            })
            .collect(),
        language,
        framework,
        explanation: "These definitions share a high near-duplicate score across normalized tokens, canonical AST path shingles, statements, calls, control-flow, and MinHash signatures. This is a suspicious clone signal, not proof that the behavior is the same."
            .to_string(),
        remediation: "Compare the domain intent, then extract a shared helper, consolidate validation logic, keep the definitions separate with a short comment, or suppress intentional duplication with a reason."
            .to_string(),
        detection_reason: "The detector used locality-sensitive hashing to find candidate pairs, then scored only those candidates with deterministic shingle and signature similarity metrics."
            .to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: "Near duplicates are not auto-fixed because extracting shared logic can change APIs, imports, error handling, ownership, and side effects."
            .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn vector_feature(
    definition: &Definition,
    fingerprint: &StructuralFingerprint,
    summary: FunctionEmbeddingSummary,
    vector: Vec<f32>,
) -> VectorFunctionFeature {
    let token_count = fingerprint
        .token_estimate
        .max(token_estimate(&summary.input));
    let ast_tokens = lexical_tokens(&fingerprint.serialization);
    let ast_shingles = simple_weighted_shingles(
        "vector_ast",
        &shingle_strings(&ast_tokens, near_ast_shingle_size(token_count)),
    );
    let call_shingles = simple_weighted_shingles("vector_call", &fingerprint.call_names);
    let name_tokens = split_identifier_words(&definition.name);
    let name_shingles = simple_weighted_shingles("vector_name", &name_tokens);
    let framework_shingles =
        simple_weighted_shingles("vector_framework", &fingerprint.framework_context);

    VectorFunctionFeature {
        definition: definition.clone(),
        summary,
        vector,
        line_count: structural_line_count(definition),
        token_estimate: token_count,
        canonical_hash: fingerprint.stable_hash_hex.clone(),
        signature_shape: NearSignatureShape {
            parameter_count: fingerprint.parameter_count,
            return_shape: fingerprint.return_shape.clone(),
            is_async: fingerprint.is_async,
            kind: definition.kind,
        },
        ast_shingles,
        call_shingles,
        name_shingles,
        framework_shingles,
    }
}

fn build_vector_candidate_finding(
    features: &[VectorFunctionFeature],
    pair_scores: &[VectorPairScore],
    group: &[usize],
    options: &VectorCandidateOptions,
) -> Finding {
    let group_set = group.iter().copied().collect::<BTreeSet<_>>();
    let mut group_features = group
        .iter()
        .map(|index| &features[*index])
        .collect::<Vec<_>>();
    group_features.sort_by(|left, right| {
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
    let group_pair_scores = pair_scores
        .iter()
        .filter(|pair| group_set.contains(&pair.left) && group_set.contains(&pair.right))
        .copied()
        .collect::<Vec<_>>();
    let vector_score = average_metric(&group_pair_scores, |pair| pair.vector_similarity);
    let rank_score = average_metric(&group_pair_scores, |pair| pair.rank_score);
    let summary_hashes = group_features
        .iter()
        .map(|feature| feature.summary.stable_hash_hex.clone())
        .collect::<Vec<_>>();
    let vector_group_hash = stable_vector_group_hash(&summary_hashes);
    let qualified_names = group_features
        .iter()
        .map(|feature| feature.definition.qualified_name.clone())
        .collect::<Vec<_>>();
    let names = group_features
        .iter()
        .map(|feature| feature.definition.name.clone())
        .collect::<BTreeSet<_>>();
    let kinds = group_features
        .iter()
        .map(|feature| feature.definition.kind.label().to_string())
        .collect::<BTreeSet<_>>();
    let group_fingerprint = qualified_names.join("|");
    let baseline_key = stable_key(
        SEMANTIC_VECTOR_CANDIDATE_RULE,
        &vector_group_hash,
        &group_fingerprint,
    );
    let language = shared_vector_language(&group_features);
    let framework = shared_vector_framework(&group_features);
    let pair_score_json = group_pair_scores
        .iter()
        .map(|pair| {
            serde_json::json!({
                "left": &features[pair.left].definition.qualified_name,
                "right": &features[pair.right].definition.qualified_name,
                "vectorSimilarity": pair.vector_similarity,
                "rankScore": pair.rank_score,
                "astSimilarity": pair.ast_similarity,
                "signatureSimilarity": pair.signature_similarity,
                "callSimilarity": pair.call_similarity,
                "nameSimilarity": pair.name_similarity,
                "frameworkSimilarity": pair.framework_similarity,
            })
        })
        .collect::<Vec<_>>();
    let signals = vector_group_signals(&group_pair_scores);
    let max_lines = group_features
        .iter()
        .map(|feature| feature.line_count)
        .max()
        .unwrap_or(0);
    let max_tokens = group_features
        .iter()
        .map(|feature| feature.token_estimate)
        .max()
        .unwrap_or(0);

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "vector_group_hash".to_string(),
        serde_json::json!(&vector_group_hash),
    );
    metadata.insert(
        "vector_version".to_string(),
        serde_json::json!(VECTOR_CANDIDATE_VERSION),
    );
    metadata.insert(
        "summary_version".to_string(),
        serde_json::json!(VECTOR_SUMMARY_VERSION),
    );
    metadata.insert(
        "embedding_provider".to_string(),
        serde_json::json!(&options.provider_id),
    );
    metadata.insert(
        "privacy_mode".to_string(),
        serde_json::json!(&options.privacy_mode),
    );
    metadata.insert("vector_score".to_string(), serde_json::json!(vector_score));
    metadata.insert("rank_score".to_string(), serde_json::json!(rank_score));
    metadata.insert(
        "deterministic_signals".to_string(),
        serde_json::json!(&signals),
    );
    metadata.insert(
        "pair_scores".to_string(),
        serde_json::json!(pair_score_json),
    );
    metadata.insert(
        "summary_hashes".to_string(),
        serde_json::json!(summary_hashes),
    );
    metadata.insert(
        "symbol_names".to_string(),
        serde_json::json!(names.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert(
        "qualified_names".to_string(),
        serde_json::json!(qualified_names),
    );
    metadata.insert(
        "definition_kinds".to_string(),
        serde_json::json!(kinds.iter().cloned().collect::<Vec<_>>()),
    );
    metadata.insert("line_count".to_string(), serde_json::json!(max_lines));
    metadata.insert("token_estimate".to_string(), serde_json::json!(max_tokens));
    metadata.insert(
        "candidate_limit".to_string(),
        serde_json::json!(options.candidate_limit),
    );
    metadata.insert(
        "candidate_limit_reached".to_string(),
        serde_json::json!(false),
    );

    Finding {
        finding_id: format!(
            "{}:{}",
            SEMANTIC_VECTOR_CANDIDATE_RULE,
            &baseline_key[..12]
        ),
        baseline_key,
        rule_id: SEMANTIC_VECTOR_CANDIDATE_RULE.to_string(),
        kind: FindingKind::SemanticCandidate,
        severity: Severity::Info,
        confidence: if rank_score >= 82 && vector_score >= 90 {
            Confidence::Medium
        } else {
            Confidence::Low
        },
        message: format!(
            "{} definitions are vector-discovered semantic candidates.",
            group_features.len()
        ),
        locations: group_features
            .iter()
            .map(|feature| FindingLocation {
                path: feature.definition.file.clone(),
                span: feature.definition.body_span.map(|span| SourceSpan {
                    start: span.start,
                    end: span.end,
                }),
                start: feature.definition.body_span.map(|span| Location {
                    line: span.start_position.line,
                    column: span.start_position.column,
                    byte_offset: span.start,
                }),
                language: Some(feature.definition.language.label().to_string()),
            })
            .collect(),
        language,
        framework,
        explanation: "These functions appear conceptually similar, but deterministic equivalence was not proven. The vector match was kept only because deterministic AST, signature, call, name, or framework signals also supported the candidate."
            .to_string(),
        remediation: "Compare intent and edge cases, then extract a shared helper, consolidate validation, keep the definitions separate with documentation, or suppress intentional duplication with a reason."
            .to_string(),
        detection_reason: "The detector embedded compact function summaries, searched deterministic vector LSH buckets, and ranked candidates with deterministic code similarity signals."
            .to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation: "Vector candidates are discovery-only and cannot be auto-fixed because embeddings do not prove behavior equivalence."
            .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn embedding_summary_for_definition(
    definition: &Definition,
    source_cache: &mut BTreeMap<PathBuf, String>,
) -> FunctionEmbeddingSummary {
    let fingerprint = definition.structural_fingerprint.as_ref();
    let calls = fingerprint
        .map(|fingerprint| fingerprint.call_names.clone())
        .unwrap_or_default();
    let framework_tags = fingerprint
        .map(|fingerprint| fingerprint.framework_context.clone())
        .unwrap_or_else(|| {
            definition
                .framework_tags
                .iter()
                .map(|tag| tag.label())
                .collect::<Vec<_>>()
        });
    let return_shape = fingerprint
        .map(|fingerprint| fingerprint.return_shape.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let ast_summary = fingerprint
        .map(|fingerprint| {
            format!(
                "canonical_hash={}, nodes={}, opaque={}, tokens={}, return_shape={}, async={}, unsafe={}",
                short_hash(&fingerprint.stable_hash_hex),
                fingerprint.node_count,
                fingerprint.opaque_node_count,
                fingerprint.token_estimate,
                fingerprint.return_shape,
                fingerprint.is_async,
                fingerprint.is_unsafe
            )
        })
        .unwrap_or_else(|| "canonical_hash=missing".to_string());
    let serialization = fingerprint
        .map(|fingerprint| fingerprint.serialization.as_str())
        .unwrap_or_default();
    let reads = summarized_reads(serialization);
    let writes = summarized_writes(serialization);
    let signature = signature_key(definition);
    let comment_context = comment_context(definition, source_cache);
    let input = compact_summary_input(CompactSummaryInput {
        definition,
        signature: &signature,
        ast_summary: &ast_summary,
        calls: &calls,
        reads: &reads,
        writes: &writes,
        return_shape: &return_shape,
        framework_tags: &framework_tags,
        comment_context: comment_context.as_deref(),
    });
    let stable_hash = Sha256::digest(format!("{VECTOR_SUMMARY_VERSION}|{input}").as_bytes());

    FunctionEmbeddingSummary {
        version: VECTOR_SUMMARY_VERSION.to_string(),
        language: definition.language.label().to_string(),
        kind: definition.kind.label().to_string(),
        name: sanitize_summary_text(&definition.name),
        qualified_name: sanitize_summary_text(&definition.qualified_name),
        signature: sanitize_summary_text(&signature),
        ast_summary,
        calls,
        reads,
        writes,
        return_shape,
        framework_tags,
        comment_context,
        input,
        stable_hash_hex: format!("{stable_hash:x}"),
    }
}

struct CompactSummaryInput<'a> {
    definition: &'a Definition,
    signature: &'a str,
    ast_summary: &'a str,
    calls: &'a [String],
    reads: &'a [String],
    writes: &'a [String],
    return_shape: &'a str,
    framework_tags: &'a [String],
    comment_context: Option<&'a str>,
}

fn compact_summary_input(parts: CompactSummaryInput<'_>) -> String {
    let mut lines = vec![
        format!("version: {VECTOR_SUMMARY_VERSION}"),
        format!("language: {}", parts.definition.language.label()),
        format!("kind: {}", parts.definition.kind.label()),
        format!("name: {}", sanitize_summary_text(&parts.definition.name)),
        format!("signature: {}", sanitize_summary_text(parts.signature)),
        format!("ast: {}", sanitize_summary_text(parts.ast_summary)),
        format!("calls: {}", sanitized_join(parts.calls)),
        format!("reads: {}", sanitized_join(parts.reads)),
        format!("writes: {}", sanitized_join(parts.writes)),
        format!(
            "return_shape: {}",
            sanitize_summary_text(parts.return_shape)
        ),
        format!("framework: {}", sanitized_join(parts.framework_tags)),
    ];
    if let Some(comment_context) = parts.comment_context {
        lines.push(format!(
            "comments: {}",
            sanitize_summary_text(comment_context)
        ));
    }
    lines.join("\n")
}

fn summarized_reads(serialization: &str) -> Vec<String> {
    let mut reads = BTreeSet::new();
    for token in lexical_tokens(serialization) {
        if token.starts_with("member") || token.starts_with("identifier") {
            reads.insert(token);
        }
    }
    reads.into_iter().take(16).collect()
}

fn summarized_writes(serialization: &str) -> Vec<String> {
    let assignment_count = serialization.matches("Assign(").count();
    if assignment_count == 0 {
        Vec::new()
    } else {
        vec![format!("assignments:{assignment_count}")]
    }
}

fn comment_context(
    definition: &Definition,
    source_cache: &mut BTreeMap<PathBuf, String>,
) -> Option<String> {
    if !source_cache.contains_key(&definition.file) {
        let source = fs::read_to_string(&definition.file).ok()?;
        source_cache.insert(definition.file.clone(), source);
    }
    let source = source_cache.get(&definition.file)?;
    let line_index = definition.span.start_position.line.saturating_sub(1);
    let lines = source.lines().collect::<Vec<_>>();
    let start = line_index.saturating_sub(5);
    let mut comments = Vec::new();
    for line in lines
        .get(start..line_index)
        .unwrap_or_default()
        .iter()
        .rev()
    {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if comments.is_empty() {
                continue;
            }
            break;
        }
        if let Some(comment) = trimmed
            .strip_prefix("///")
            .or_else(|| trimmed.strip_prefix("//"))
            .or_else(|| trimmed.strip_prefix("#"))
        {
            comments.push(comment.trim().to_string());
        } else {
            break;
        }
    }
    comments.reverse();
    let context = sanitize_summary_text(&comments.join(" "));
    (!context.is_empty()).then_some(context)
}

fn sanitize_summary_text(input: &str) -> String {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let lowered = collapsed.to_ascii_lowercase();
    if [
        "secret",
        "password",
        "api_key",
        "apikey",
        "token",
        "private_key",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        return "[REDACTED_SECRET]".to_string();
    }
    collapsed
        .split(' ')
        .map(|part| {
            if part.len() > 80 {
                format!("[LONG_TEXT:{}]", part.len())
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

fn sanitized_join(values: &[String]) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    values
        .iter()
        .map(|value| sanitize_summary_text(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn normalize_vector(vector: Vec<f32>) -> Option<Vec<f32>> {
    if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let norm = vector
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt();
    if norm <= f64::EPSILON {
        return None;
    }
    Some(
        vector
            .into_iter()
            .map(|value| (f64::from(value) / norm) as f32)
            .collect(),
    )
}

fn vector_lsh_candidate_pairs(
    features: &[VectorFunctionFeature],
    candidate_limit: usize,
) -> BTreeSet<(usize, usize)> {
    let mut buckets: BTreeMap<(Language, u8, u8), Vec<usize>> = BTreeMap::new();
    for (index, feature) in features.iter().enumerate() {
        let signature = vector_simhash(&feature.vector);
        for band in 0..8u8 {
            let bucket = ((signature >> (usize::from(band) * 8)) & 0xff) as u8;
            buckets
                .entry((feature.definition.language, band, bucket))
                .or_default()
                .push(index);
        }
    }

    let mut pairs = BTreeSet::new();
    for mut bucket in buckets.into_values() {
        bucket.sort_unstable();
        bucket.dedup();
        for left_index in 0..bucket.len() {
            for right_index in left_index + 1..bucket.len() {
                if pairs.len() >= candidate_limit {
                    return pairs;
                }
                pairs.insert((bucket[left_index], bucket[right_index]));
            }
        }
    }
    pairs
}

fn vector_simhash(vector: &[f32]) -> u64 {
    let mut accum = [0f64; 64];
    for (index, value) in vector.iter().enumerate() {
        let hash = xxh3_64(format!("dim:{index}").as_bytes());
        let weight = f64::from(value.abs());
        for (bit, slot) in accum.iter_mut().enumerate() {
            if ((hash >> bit) & 1) == 1 {
                *slot += weight;
            } else {
                *slot -= weight;
            }
        }
    }
    accum
        .iter()
        .enumerate()
        .fold(0u64, |signature, (bit, value)| {
            if *value >= 0.0 {
                signature | (1u64 << bit)
            } else {
                signature
            }
        })
}

fn vector_pair_score(
    left: usize,
    right: usize,
    left_feature: &VectorFunctionFeature,
    right_feature: &VectorFunctionFeature,
) -> VectorPairScore {
    let vector_similarity = cosine_percent(&left_feature.vector, &right_feature.vector);
    let ast_similarity = weighted_jaccard(&left_feature.ast_shingles, &right_feature.ast_shingles);
    let signature_similarity = signature_similarity(
        &left_feature.signature_shape,
        &right_feature.signature_shape,
    );
    let call_similarity =
        optional_weighted_jaccard(&left_feature.call_shingles, &right_feature.call_shingles);
    let name_similarity =
        weighted_jaccard(&left_feature.name_shingles, &right_feature.name_shingles);
    let framework_similarity = optional_weighted_jaccard(
        &left_feature.framework_shingles,
        &right_feature.framework_shingles,
    );
    let rank_score = weighted_average(&[
        (vector_similarity, 40),
        (ast_similarity, 25),
        (signature_similarity, 15),
        (call_similarity, 10),
        (name_similarity, 5),
        (framework_similarity, 5),
    ]);
    VectorPairScore {
        left,
        right,
        vector_similarity,
        rank_score,
        ast_similarity,
        signature_similarity,
        call_similarity,
        name_similarity,
        framework_similarity,
    }
}

fn vector_pair_has_deterministic_support(score: VectorPairScore) -> bool {
    score.ast_similarity >= 50
        || score.signature_similarity >= 60
        || score.call_similarity >= 50
        || score.name_similarity >= 60
        || score.framework_similarity >= 100
}

fn cosine_percent(left: &[f32], right: &[f32]) -> u8 {
    if left.len() != right.len() || left.is_empty() {
        return 0;
    }
    let dot = left
        .iter()
        .zip(right)
        .map(|(left, right)| f64::from(*left) * f64::from(*right))
        .sum::<f64>()
        .clamp(-1.0, 1.0);
    (((dot + 1.0) * 50.0).round() as usize)
        .try_into()
        .unwrap_or(100)
}

fn optional_weighted_jaccard(left: &WeightedShingles, right: &WeightedShingles) -> u8 {
    if left.is_empty() && right.is_empty() {
        0
    } else {
        weighted_jaccard(left, right)
    }
}

fn connected_vector_groups(pair_scores: &[VectorPairScore]) -> Vec<Vec<usize>> {
    let mut adjacency: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for pair in pair_scores {
        adjacency.entry(pair.left).or_default().insert(pair.right);
        adjacency.entry(pair.right).or_default().insert(pair.left);
    }
    let mut visited = BTreeSet::new();
    let mut groups = Vec::new();
    for start in adjacency.keys().copied().collect::<Vec<_>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![start];
        let mut group = BTreeSet::new();
        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }
            group.insert(node);
            if let Some(neighbors) = adjacency.get(&node) {
                for neighbor in neighbors.iter().rev() {
                    if !visited.contains(neighbor) {
                        stack.push(*neighbor);
                    }
                }
            }
        }
        if group.len() > 1 {
            groups.push(group.into_iter().collect());
        }
    }
    groups
}

fn vector_group_signals(pair_scores: &[VectorPairScore]) -> Vec<String> {
    let mut signals = Vec::new();
    if average_metric(pair_scores, |pair| pair.ast_similarity) >= 50 {
        signals.push("ast_similarity".to_string());
    }
    if average_metric(pair_scores, |pair| pair.signature_similarity) >= 60 {
        signals.push("signature_similarity".to_string());
    }
    if average_metric(pair_scores, |pair| pair.call_similarity) >= 50 {
        signals.push("call_similarity".to_string());
    }
    if average_metric(pair_scores, |pair| pair.name_similarity) >= 60 {
        signals.push("name_similarity".to_string());
    }
    if average_metric(pair_scores, |pair| pair.framework_similarity) >= 100 {
        signals.push("framework_context".to_string());
    }
    signals
}

fn simple_weighted_shingles(namespace: &str, values: &[String]) -> WeightedShingles {
    values
        .iter()
        .map(|value| (shingle_hash(namespace, value), 1u16))
        .collect()
}

fn split_identifier_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for character in value.chars() {
        if character == '_' || character == '-' {
            if !current.is_empty() {
                words.push(current.to_ascii_lowercase());
                current.clear();
            }
            continue;
        }
        if character.is_ascii_uppercase() && !current.is_empty() {
            words.push(current.to_ascii_lowercase());
            current.clear();
        }
        if character.is_ascii_alphanumeric() {
            current.push(character);
        }
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    if words.is_empty() {
        words.push(value.to_ascii_lowercase());
    }
    words
}

fn stable_vector_group_hash(summary_hashes: &[String]) -> String {
    let mut hashes = summary_hashes.to_vec();
    hashes.sort();
    let stable =
        Sha256::digest(format!("{}|{}", VECTOR_CANDIDATE_VERSION, hashes.join("|")).as_bytes());
    format!("{stable:x}")
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

struct VectorCache {
    enabled: bool,
    dir: PathBuf,
}

impl VectorCache {
    fn new(enabled: bool, dir: PathBuf) -> Self {
        Self { enabled, dir }
    }

    fn get(
        &self,
        provider_id: &str,
        privacy_mode: &str,
        summary: &FunctionEmbeddingSummary,
    ) -> Option<Vec<f32>> {
        if !self.enabled {
            return None;
        }
        let path = self.entry_path(provider_id, privacy_mode, summary);
        let raw = fs::read_to_string(path).ok()?;
        let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
        json.get("vector")?
            .as_array()?
            .iter()
            .map(|value| value.as_f64().map(|value| value as f32))
            .collect()
    }

    fn put(
        &mut self,
        provider_id: &str,
        privacy_mode: &str,
        summary: &FunctionEmbeddingSummary,
        vector: &[f32],
    ) {
        if !self.enabled || vector.is_empty() {
            return;
        }
        let dir = self.dir.join("vectors");
        if fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = self.entry_path(provider_id, privacy_mode, summary);
        let payload = serde_json::json!({
            "provider": provider_id,
            "privacyMode": privacy_mode,
            "summaryVersion": summary.version,
            "summaryHash": summary.stable_hash_hex,
            "vector": vector,
        });
        let _ = fs::write(
            path,
            serde_json::to_vec_pretty(&payload).unwrap_or_default(),
        );
    }

    fn entry_path(
        &self,
        provider_id: &str,
        privacy_mode: &str,
        summary: &FunctionEmbeddingSummary,
    ) -> PathBuf {
        let stable = Sha256::digest(
            format!(
                "{provider_id}|{}|{privacy_mode}|{}|{}",
                summary.version, summary.stable_hash_hex, summary.qualified_name
            )
            .as_bytes(),
        );
        self.dir.join("vectors").join(format!("{stable:x}.json"))
    }
}

fn structural_confidence_score(group: &[StructuralSymbolFingerprint]) -> u8 {
    let mut score = 65;
    let first = &group[0].fingerprint;

    if group
        .iter()
        .all(|item| item.fingerprint.parameter_count == first.parameter_count)
    {
        score += 10;
    }
    if group
        .iter()
        .all(|item| item.fingerprint.return_shape == first.return_shape)
    {
        score += 10;
    }
    if group
        .iter()
        .all(|item| item.fingerprint.call_names == first.call_names)
    {
        score += 5;
    }
    if group.iter().all(|item| {
        framework_for_definition(&item.definition) == framework_for_definition(&group[0].definition)
    }) {
        score += 5;
    }
    if first.opaque_node_count == 0 {
        score += 5;
    }

    score.min(100)
}

fn structural_signals(group: &[StructuralSymbolFingerprint]) -> Vec<String> {
    let first = &group[0].fingerprint;
    let mut signals = vec!["same_canonical_ast".to_string()];
    if group
        .iter()
        .all(|item| item.fingerprint.parameter_count == first.parameter_count)
    {
        signals.push("compatible_parameter_count".to_string());
    }
    if group
        .iter()
        .all(|item| item.definition.is_async == group[0].definition.is_async)
    {
        signals.push("same_asyncness".to_string());
    }
    if group
        .iter()
        .all(|item| item.fingerprint.return_shape == first.return_shape)
    {
        signals.push("same_return_shape".to_string());
    }
    if group
        .iter()
        .all(|item| item.fingerprint.call_names == first.call_names)
    {
        signals.push("same_call_names".to_string());
    }
    if group
        .iter()
        .any(|item| !item.fingerprint.framework_context.is_empty())
    {
        signals.push("framework_context".to_string());
    }
    signals
}

fn semantic_options_compatible(
    fingerprint: &SemanticFingerprint,
    options: SemanticDuplicateOptions,
) -> bool {
    if !options.normalize_boolean_returns
        && fingerprint.rewrites.iter().any(|rewrite| {
            matches!(
                rewrite.as_str(),
                "boolean_return_simplification" | "inverse_boolean_return_simplification"
            )
        })
    {
        return false;
    }
    if !options.normalize_commutative_ops
        && fingerprint.rewrites.iter().any(|rewrite| {
            matches!(
                rewrite.as_str(),
                "commutative_numeric_add"
                    | "commutative_numeric_multiply"
                    | "pure_boolean_operand_order"
                    | "equality_operand_order"
            )
        })
    {
        return false;
    }
    if !options.normalize_comparisons
        && fingerprint
            .rewrites
            .iter()
            .any(|rewrite| rewrite == "comparison_inversion")
    {
        return false;
    }
    true
}

fn selected_semantic_fingerprint(
    definition: &Definition,
    options: SemanticDuplicateOptions,
) -> Option<&SemanticFingerprint> {
    if options.property_reads_are_pure {
        definition
            .property_read_semantic_fingerprint
            .as_ref()
            .or(definition.semantic_fingerprint.as_ref())
    } else {
        definition.semantic_fingerprint.as_ref()
    }
}

fn semantic_token_estimate(fingerprint: &SemanticFingerprint) -> usize {
    token_estimate(&fingerprint.serialization)
}

fn semantic_signals(
    rewrites: &[String],
    confidence: Confidence,
    distinct_canonical_hashes: usize,
) -> Vec<String> {
    let mut signals = vec!["same_semantic_fingerprint".to_string()];
    signals.extend(rewrites.iter().map(|rewrite| format!("rewrite:{rewrite}")));
    if distinct_canonical_hashes > 1 {
        signals.push("different_structural_hashes".to_string());
    }
    if confidence >= Confidence::High {
        signals.push("typed_or_derived_evidence".to_string());
    }
    signals.sort();
    signals.dedup();
    signals
}

fn union_metadata<F>(group: &[SemanticSymbolFingerprint], accessor: F) -> Vec<String>
where
    F: Fn(&SemanticSymbolFingerprint) -> &Vec<String>,
{
    group
        .iter()
        .flat_map(|item| accessor(item).iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn literal_policy_label(policy: LiteralPolicy) -> &'static str {
    match policy {
        LiteralPolicy::Preserve => "preserve",
        LiteralPolicy::Normalize => "normalize",
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

fn shared_structural_language(group: &[StructuralSymbolFingerprint]) -> Option<String> {
    let first = group.first()?.definition.language;
    if group.iter().all(|item| item.definition.language == first) {
        Some(first.label().to_string())
    } else {
        None
    }
}

fn shared_semantic_language(group: &[SemanticSymbolFingerprint]) -> Option<String> {
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

fn shared_structural_framework(group: &[StructuralSymbolFingerprint]) -> Option<String> {
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

fn shared_semantic_framework(group: &[SemanticSymbolFingerprint]) -> Option<String> {
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

fn shared_vector_language(group: &[&VectorFunctionFeature]) -> Option<String> {
    let first = group.first()?.definition.language;
    if group
        .iter()
        .all(|feature| feature.definition.language == first)
    {
        Some(first.label().to_string())
    } else {
        None
    }
}

fn shared_vector_framework(group: &[&VectorFunctionFeature]) -> Option<String> {
    let frameworks = group
        .iter()
        .filter_map(|feature| framework_for_definition(&feature.definition))
        .collect::<BTreeSet<_>>();
    if frameworks.len() == 1 {
        frameworks.into_iter().next().map(str::to_string)
    } else {
        None
    }
}

fn shared_near_language(group: &[&NearFunctionFeatures]) -> Option<String> {
    let first = group.first()?.definition.language;
    if group
        .iter()
        .all(|feature| feature.definition.language == first)
    {
        Some(first.label().to_string())
    } else {
        None
    }
}

fn shared_near_framework(group: &[&NearFunctionFeatures]) -> Option<String> {
    let frameworks = group
        .iter()
        .filter_map(|feature| framework_for_definition(&feature.definition))
        .collect::<BTreeSet<_>>();
    if frameworks.len() == 1 {
        frameworks.into_iter().next().map(str::to_string)
    } else {
        None
    }
}

fn average_pair_score(scores: &[NearPairScore]) -> u8 {
    average_metric(scores, |score| score.score)
}

fn average_metric<T>(scores: &[T], metric: impl Fn(&T) -> u8) -> u8 {
    if scores.is_empty() {
        return 0;
    }
    let total = scores
        .iter()
        .map(|score| usize::from(metric(score)))
        .sum::<usize>();
    ((total + scores.len() / 2) / scores.len())
        .try_into()
        .unwrap_or(100)
}

fn near_group_signals(
    pair_scores: &[NearPairScore],
    group_features: &[&NearFunctionFeatures],
) -> Vec<String> {
    let mut signals = Vec::new();
    if average_metric(pair_scores, |pair| pair.token_similarity) >= 80 {
        signals.push("similar_tokens".to_string());
    }
    if average_metric(pair_scores, |pair| pair.ast_similarity) >= 80 {
        signals.push("similar_ast_paths".to_string());
    }
    if average_metric(pair_scores, |pair| pair.statement_similarity) >= 70 {
        signals.push("similar_statements".to_string());
    }
    if average_metric(pair_scores, |pair| pair.call_similarity) >= 70 {
        signals.push("similar_calls".to_string());
    }
    if average_metric(pair_scores, |pair| pair.control_flow_similarity) >= 70 {
        signals.push("similar_control_flow".to_string());
    }
    if average_metric(pair_scores, |pair| pair.signature_similarity) >= 80 {
        signals.push("compatible_signature".to_string());
    }
    if group_features
        .iter()
        .any(|feature| framework_for_definition(&feature.definition).is_some())
    {
        signals.push("framework_context".to_string());
    }
    signals.push("lsh_candidate".to_string());
    signals
}

fn similar_and_differing_regions(
    left: &NearFunctionFeatures,
    right: &NearFunctionFeatures,
) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let left_statements = left
        .statements
        .iter()
        .map(|statement| (statement.normalized.clone(), statement.line))
        .collect::<BTreeMap<_, _>>();
    let right_statements = right
        .statements
        .iter()
        .map(|statement| (statement.normalized.clone(), statement.line))
        .collect::<BTreeMap<_, _>>();

    let similar = left_statements
        .iter()
        .filter_map(|(statement, left_line)| {
            right_statements.get(statement).map(|right_line| {
                serde_json::json!({
                    "statement": statement,
                    "left": {
                        "symbol": &left.definition.qualified_name,
                        "line": left_line,
                    },
                    "right": {
                        "symbol": &right.definition.qualified_name,
                        "line": right_line,
                    },
                })
            })
        })
        .take(4)
        .collect::<Vec<_>>();

    let mut differing = Vec::new();
    for (statement, line) in left_statements
        .iter()
        .filter(|(statement, _)| !right_statements.contains_key(*statement))
        .take(2)
    {
        differing.push(serde_json::json!({
            "symbol": &left.definition.qualified_name,
            "line": line,
            "statement": statement,
        }));
    }
    for (statement, line) in right_statements
        .iter()
        .filter(|(statement, _)| !left_statements.contains_key(*statement))
        .take(2)
    {
        differing.push(serde_json::json!({
            "symbol": &right.definition.qualified_name,
            "line": line,
            "statement": statement,
        }));
    }

    (similar, differing)
}

fn near_feature_hash(
    language: Language,
    canonical_hash: &str,
    combined_shingles: &WeightedShingles,
) -> String {
    let shingles = combined_shingles
        .iter()
        .map(|(hash, weight)| format!("{hash}:{weight}"))
        .collect::<Vec<_>>()
        .join("|");
    let stable_hash = Sha256::digest(
        format!("{NEAR_DUPLICATE_VERSION}|{language}|{canonical_hash}|{shingles}").as_bytes(),
    );
    format!("{stable_hash:x}")
}

fn stable_near_group_hash(feature_hashes: &[String]) -> String {
    let mut hashes = feature_hashes.to_vec();
    hashes.sort();
    let stable_hash =
        Sha256::digest(format!("{NEAR_DUPLICATE_VERSION}|{}", hashes.join("|")).as_bytes());
    format!("{stable_hash:x}")
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

fn owner_context(definition: &Definition) -> String {
    definition
        .qualified_name
        .rsplit_once('.')
        .map(|(owner, _)| owner.to_string())
        .unwrap_or_default()
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
    let line_count = files.iter().map(|file| file.line_count).max().unwrap_or(0);
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "normalized_file_hash".to_string(),
        serde_json::json!(stable_hash),
    );
    metadata.insert("file_count".to_string(), serde_json::json!(files.len()));
    metadata.insert("line_count".to_string(), serde_json::json!(line_count));

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
        fixes: Vec::new(),
        metadata,
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
    use codehealth_parser::{LineColumn, Span};
    use codehealth_symbols::{Parameter, Signature};
    use std::cell::Cell;

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

    #[test]
    fn near_shingle_sizes_track_definition_size() {
        assert_eq!(near_shingle_size(20), 3);
        assert_eq!(near_shingle_size(120), 5);
        assert_eq!(near_shingle_size(400), 7);
        assert_eq!(near_statement_shingle_size(20), 1);
        assert_eq!(near_statement_shingle_size(120), 2);
        assert_eq!(near_statement_shingle_size(400), 3);
    }

    #[test]
    fn common_shingles_are_filtered_and_rare_shingles_are_weighted() {
        let mut frequency = BTreeMap::new();
        frequency.insert(shingle_hash("token", "common"), 20);
        frequency.insert(shingle_hash("token", "rare"), 1);
        let options = NearDuplicateOptions::default();

        let weighted = weighted_shingles(
            "token",
            &["common".to_string(), "rare".to_string()],
            &frequency,
            100,
            options,
        );

        assert!(!weighted.contains_key(&shingle_hash("token", "common")));
        assert!(weighted[&shingle_hash("token", "rare")] > 1);
    }

    #[test]
    fn minhash_estimate_is_deterministic_for_known_similarity() {
        let options = NearDuplicateOptions::default();
        let left = test_shingles(&["a", "b", "c", "d"]);
        let same = test_shingles(&["a", "b", "c", "d"]);
        let partial = test_shingles(&["a", "b", "x", "y"]);

        let left_signature = minhash_signature(&left, options);
        let same_signature = minhash_signature(&same, options);
        let partial_signature = minhash_signature(&partial, options);

        assert_eq!(minhash_estimate(&left_signature, &same_signature), 100);
        let estimate = minhash_estimate(&left_signature, &partial_signature);
        assert!((20..=60).contains(&estimate));
        assert_eq!(
            estimate,
            minhash_estimate(
                &minhash_signature(&left, options),
                &minhash_signature(&partial, options)
            )
        );
    }

    #[test]
    fn lsh_candidates_include_shape_bucket_without_all_pairs() {
        let options = NearDuplicateOptions {
            max_bucket_size: 10,
            ..NearDuplicateOptions::default()
        };
        let mut features = vec![
            test_near_feature(0, 75, &["shared", "left"]),
            test_near_feature(1, 76, &["shared", "right"]),
        ];
        for index in 2..42 {
            features.push(test_near_feature(
                index,
                100 + index * 25,
                &[&format!("unique-{index}")],
            ));
        }

        let candidates = lsh_candidate_pairs(&features, options);
        let all_pairs = features.len() * (features.len() - 1) / 2;

        assert!(candidates.pairs.contains(&(0, 1)));
        assert!(candidates.pairs.len() < all_pairs);
    }

    #[test]
    fn final_near_score_combines_similarity_signals() {
        let mut left = test_near_feature(0, 80, &["a", "b", "c"]);
        let mut right = test_near_feature(1, 82, &["a", "b", "d"]);
        let options = NearDuplicateOptions::default();
        left.minhash_signature = minhash_signature(&left.combined_shingles, options);
        right.minhash_signature = minhash_signature(&right.combined_shingles, options);

        let score = near_pair_score(0, 1, &left, &right);

        assert!(score.score >= 60);
        assert!(score.token_similarity > 0);
        assert_eq!(score.signature_similarity, 100);
    }

    #[test]
    fn embedding_summary_redacts_secrets_and_long_literals() {
        let dir = unique_test_dir("summary");
        fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("summary.ts");
        fs::write(
            &file,
            format!(
                "// API_KEY = super-secret\n// {}\nexport function check(value: number) {{ return value; }}\n",
                "x".repeat(90)
            ),
        )
        .expect("write source");
        let definition = test_vector_definition(
            0,
            "check",
            file.clone(),
            "Return(Identifier(PARAM_0))",
            "hash-check",
            1,
            "identifier",
            &[],
        );
        let mut source_cache = BTreeMap::new();

        let summary = embedding_summary_for_definition(&definition, &mut source_cache);

        assert!(summary.input.contains("[REDACTED_SECRET]"));
        assert_eq!(sanitize_summary_text(&"x".repeat(90)), "[LONG_TEXT:90]");
        assert!(!summary.input.contains("super-secret"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn noop_embedding_provider_produces_no_vector_candidates() {
        let index = SymbolIndex {
            definitions: vec![
                test_vector_definition(
                    0,
                    "normalizeUser",
                    "a.ts",
                    "Return(Call(validate,[Identifier(PARAM_0)]))",
                    "hash-a",
                    1,
                    "call",
                    &["validate"],
                ),
                test_vector_definition(
                    1,
                    "normalizeCustomer",
                    "b.ts",
                    "Return(Call(validate,[Identifier(PARAM_0)]))",
                    "hash-b",
                    1,
                    "call",
                    &["validate"],
                ),
            ],
            ..SymbolIndex::default()
        };

        let findings =
            find_vector_semantic_candidates(&index, &NoopEmbeddingProvider, vector_options());

        assert!(findings.is_empty());
    }

    #[test]
    fn vector_candidates_require_deterministic_support() {
        let index = SymbolIndex {
            definitions: vec![
                test_vector_definition(
                    0,
                    "alpha",
                    "a.ts",
                    "Return(Binary(+,Identifier(PARAM_0),Literal(Number(Some(\"1\"))))",
                    "hash-a",
                    1,
                    "binary",
                    &["leftCall"],
                ),
                test_vector_definition(
                    1,
                    "omega",
                    "b.ts",
                    "If(Identifier(PARAM_0),then=Return(Literal(String(Some(\"x\"))),else=None)",
                    "hash-b",
                    4,
                    "if",
                    &["rightCall"],
                ),
            ],
            ..SymbolIndex::default()
        };
        let provider = FixedEmbeddingProvider::new(vec![0.9, 0.1]);

        let findings = find_vector_semantic_candidates(&index, &provider, vector_options());

        assert!(findings.is_empty());
    }

    #[test]
    fn vector_candidates_report_when_deterministic_signals_support_them() {
        let index = SymbolIndex {
            definitions: vec![
                test_vector_definition(
                    0,
                    "normalizeUser",
                    "a.ts",
                    "Return(Call(validate,[Identifier(PARAM_0)]))",
                    "hash-a",
                    1,
                    "call",
                    &["validate"],
                ),
                test_vector_definition(
                    1,
                    "normalizeCustomer",
                    "b.ts",
                    "Return(Call(validate,[Identifier(PARAM_0)]))",
                    "hash-b",
                    1,
                    "call",
                    &["validate"],
                ),
            ],
            ..SymbolIndex::default()
        };
        let provider = FixedEmbeddingProvider::new(vec![0.9, 0.1]);

        let findings = find_vector_semantic_candidates(&index, &provider, vector_options());

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, SEMANTIC_VECTOR_CANDIDATE_RULE);
        assert_eq!(finding.kind, FindingKind::SemanticCandidate);
        assert_ne!(finding.confidence, Confidence::High);
        assert_eq!(
            finding.metadata["embedding_provider"],
            serde_json::json!("fixed")
        );
        assert!(finding.metadata["deterministic_signals"]
            .as_array()
            .expect("signals")
            .iter()
            .any(|signal| signal == "ast_similarity"));
    }

    #[test]
    fn vector_cache_reuses_stored_embeddings() {
        let dir = unique_test_dir("vector-cache");
        let index = SymbolIndex {
            definitions: vec![
                test_vector_definition(
                    0,
                    "normalizeUser",
                    "a.ts",
                    "Return(Call(validate,[Identifier(PARAM_0)]))",
                    "hash-a",
                    1,
                    "call",
                    &["validate"],
                ),
                test_vector_definition(
                    1,
                    "normalizeCustomer",
                    "b.ts",
                    "Return(Call(validate,[Identifier(PARAM_0)]))",
                    "hash-b",
                    1,
                    "call",
                    &["validate"],
                ),
            ],
            ..SymbolIndex::default()
        };
        let provider = CountingEmbeddingProvider::new(vec![0.9, 0.1]);
        let options = VectorCandidateOptions {
            cache_enabled: true,
            cache_dir: dir.clone(),
            ..vector_options()
        };

        let first = find_vector_semantic_candidates(&index, &provider, options.clone());
        let calls_after_first = provider.calls.get();
        let second = find_vector_semantic_candidates(&index, &provider, options);

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(calls_after_first, 2);
        assert_eq!(provider.calls.get(), calls_after_first);
        let _ = fs::remove_dir_all(dir);
    }

    fn test_shingles(values: &[&str]) -> WeightedShingles {
        values
            .iter()
            .map(|value| (shingle_hash("test", value), 1))
            .collect()
    }

    fn test_near_feature(
        index: usize,
        token_count: usize,
        shingles: &[&str],
    ) -> NearFunctionFeatures {
        let span = test_span(index + 1, index * 100, index * 100 + 80);
        let mut definition = Definition::new(
            Language::TypeScript,
            DefinitionKind::Function,
            format!("f{index}"),
            format!("f{index}"),
            format!("f{index}.ts"),
            span,
        );
        definition.body_span = Some(span);
        let combined_shingles = test_shingles(shingles);
        let options = NearDuplicateOptions::default();
        let minhash_signature = minhash_signature(&combined_shingles, options);

        NearFunctionFeatures {
            definition,
            line_count: 5,
            token_count,
            statement_count: 4,
            canonical_hash: format!("hash-{index}"),
            feature_hash: format!("feature-{index}"),
            signature_shape: NearSignatureShape {
                parameter_count: 1,
                return_shape: "identifier".to_string(),
                is_async: false,
                kind: DefinitionKind::Function,
            },
            statements: Vec::new(),
            token_shingles: combined_shingles.clone(),
            ast_shingles: combined_shingles.clone(),
            statement_shingles: combined_shingles.clone(),
            call_shingles: test_shingles(&["call"]),
            control_shingles: test_shingles(&["return"]),
            combined_shingles,
            minhash_signature,
        }
    }

    fn test_span(line: usize, start: usize, end: usize) -> Span {
        Span {
            start,
            end,
            start_position: LineColumn { line, column: 1 },
            end_position: LineColumn {
                line: line + 4,
                column: 1,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn test_vector_definition(
        index: usize,
        name: &str,
        file: impl Into<PathBuf>,
        serialization: &str,
        canonical_hash: &str,
        parameter_count: usize,
        return_shape: &str,
        calls: &[&str],
    ) -> Definition {
        let span = test_span(index + 1, index * 100, index * 100 + 80);
        let mut definition = Definition::new(
            Language::TypeScript,
            DefinitionKind::Function,
            name,
            name,
            file,
            span,
        );
        definition.body_span = Some(span);
        definition.signature = Signature {
            generic_parameters: Vec::new(),
            parameters: (0..parameter_count)
                .map(|index| Parameter {
                    name: format!("p{index}"),
                    type_annotation: Some("number".to_string()),
                    default_value: None,
                })
                .collect(),
            return_type: None,
        };
        definition.structural_fingerprint = Some(StructuralFingerprint {
            version: "test".to_string(),
            literal_policy: LiteralPolicy::Preserve,
            stable_hash_hex: canonical_hash.to_string(),
            serialization: serialization.to_string(),
            node_count: 12,
            opaque_node_count: 0,
            token_estimate: 20,
            parameter_count,
            is_async: false,
            is_generator: false,
            is_unsafe: false,
            return_shape: return_shape.to_string(),
            call_names: calls.iter().map(|call| (*call).to_string()).collect(),
            framework_context: Vec::new(),
            slot_bindings: Vec::new(),
            warnings: Vec::new(),
        });
        definition
    }

    fn vector_options() -> VectorCandidateOptions {
        VectorCandidateOptions {
            provider_id: "fixed".to_string(),
            privacy_mode: "local_only".to_string(),
            cache_enabled: false,
            similarity_threshold: 80,
            candidate_limit: 100,
            ..VectorCandidateOptions::default()
        }
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "codehealth-{label}-{}",
            xxh3_64(format!("{:?}", std::time::SystemTime::now()).as_bytes())
        ))
    }

    struct FixedEmbeddingProvider {
        vector: Vec<f32>,
    }

    impl FixedEmbeddingProvider {
        fn new(vector: Vec<f32>) -> Self {
            Self { vector }
        }
    }

    impl EmbeddingProvider for FixedEmbeddingProvider {
        fn embed(&self, _input: &str) -> Vec<f32> {
            self.vector.clone()
        }
    }

    struct CountingEmbeddingProvider {
        vector: Vec<f32>,
        calls: Cell<usize>,
    }

    impl CountingEmbeddingProvider {
        fn new(vector: Vec<f32>) -> Self {
            Self {
                vector,
                calls: Cell::new(0),
            }
        }
    }

    impl EmbeddingProvider for CountingEmbeddingProvider {
        fn embed(&self, _input: &str) -> Vec<f32> {
            self.calls.set(self.calls.get() + 1);
            self.vector.clone()
        }
    }
}
