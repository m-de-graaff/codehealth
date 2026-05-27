use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

pub const REPORT_SCHEMA_VERSION: u32 = 2;

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
pub enum FixApplicability {
    MachineApplicable,
    MaybeIncorrect,
    SuggestionOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    pub file: PathBuf,
    pub span: SourceSpan,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fix {
    pub title: String,
    pub safety: AutofixSafety,
    pub applicability: FixApplicability,
    pub edits: Vec<Edit>,
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
    pub fixes: Vec<Fix>,
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
    pub score: ScoreReport,
    pub stats: ScanStats,
    pub summary: SummaryMetrics,
    pub findings: Vec<Finding>,
}

impl ScanResult {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            root: root.into(),
            score: ScoreReport::enabled_clean(),
            stats: ScanStats::default(),
            summary: SummaryMetrics::default(),
            findings: Vec::new(),
        }
    }

    pub fn finalize(self) -> Self {
        self.finalize_with_score_options(&ScoreOptions::default())
    }

    pub fn finalize_with_score_options(mut self, options: &ScoreOptions) -> Self {
        sort_findings(&mut self.findings);
        self.score = calculate_score_report(&self.findings, options);
        self
    }

    pub fn has_blocking_findings(&self) -> bool {
        self.findings.iter().any(Finding::blocks_by_default)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreReport {
    pub enabled: bool,
    pub overall: Option<u8>,
    pub categories: ScoreCategories,
    pub top_contributors: Vec<ScoreContributor>,
    pub model: ScoreModel,
}

impl ScoreReport {
    pub fn enabled_clean() -> Self {
        Self {
            enabled: true,
            overall: Some(100),
            categories: ScoreCategories::clean(),
            top_contributors: Vec::new(),
            model: ScoreModel::default(),
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            overall: None,
            categories: ScoreCategories::disabled(),
            top_contributors: Vec::new(),
            model: ScoreModel::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreModel {
    pub version: String,
    pub base_score: u8,
    pub repeated_group_cap_multiplier: u8,
    pub generated_multiplier_percent: u8,
    pub test_fixture_multiplier_percent: u8,
}

impl Default for ScoreModel {
    fn default() -> Self {
        Self {
            version: "v1".to_string(),
            base_score: 100,
            repeated_group_cap_multiplier: 3,
            generated_multiplier_percent: 25,
            test_fixture_multiplier_percent: 50,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreCategories {
    pub duplication: ScoreCategoryScore,
    pub complexity: ScoreCategoryScore,
    pub style: ScoreCategoryScore,
    pub react: ScoreCategoryScore,
    pub fastapi: ScoreCategoryScore,
    pub rust_idiom: ScoreCategoryScore,
    pub maintainability: ScoreCategoryScore,
    pub ci_risk: ScoreCategoryScore,
}

impl ScoreCategories {
    fn clean() -> Self {
        Self {
            duplication: ScoreCategoryScore::clean(),
            complexity: ScoreCategoryScore::clean(),
            style: ScoreCategoryScore::clean(),
            react: ScoreCategoryScore::clean(),
            fastapi: ScoreCategoryScore::clean(),
            rust_idiom: ScoreCategoryScore::clean(),
            maintainability: ScoreCategoryScore::clean(),
            ci_risk: ScoreCategoryScore::clean(),
        }
    }

    fn disabled() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreCategoryScore {
    pub score: Option<u8>,
    pub penalty: u8,
    pub findings: usize,
}

impl ScoreCategoryScore {
    fn clean() -> Self {
        Self {
            score: Some(100),
            penalty: 0,
            findings: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreContributor {
    pub rule_id: String,
    pub message: String,
    pub category: String,
    pub penalty: u8,
    pub occurrences: usize,
    pub locations: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryMetrics {
    pub lines_scanned: usize,
    pub duplicate_groups: usize,
    pub duplicate_lines: usize,
    pub largest_functions: Vec<DefinitionMetric>,
    pub largest_react_components: Vec<DefinitionMetric>,
    pub most_duplicated_modules: Vec<ModuleDuplicateMetric>,
    pub most_complex_functions: Vec<ComplexityMetric>,
    pub most_suppressed_rules: Vec<SuppressedRuleMetric>,
    pub baseline: BaselineSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionMetric {
    pub name: String,
    pub path: PathBuf,
    pub line: usize,
    pub lines: usize,
    pub language: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDuplicateMetric {
    pub path: PathBuf,
    pub duplicate_findings: usize,
    pub duplicate_lines: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplexityMetric {
    pub name: String,
    pub path: PathBuf,
    pub line: usize,
    pub score: usize,
    pub lines: usize,
    pub language: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressedRuleMetric {
    pub rule_id: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub status: BaselineStatus,
    pub path: Option<PathBuf>,
    pub new_findings: Option<usize>,
    #[serde(default)]
    pub existing_findings: Option<usize>,
    #[serde(default)]
    pub changed_findings: Option<usize>,
    #[serde(default)]
    pub fixed_findings: Option<usize>,
}

impl Default for BaselineSummary {
    fn default() -> Self {
        Self {
            status: BaselineStatus::NotChecked,
            path: None,
            new_findings: None,
            existing_findings: None,
            changed_findings: None,
            fixed_findings: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    NotChecked,
    Missing,
    Compared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreOptions {
    pub enabled: bool,
    pub generated_paths: BTreeSet<PathBuf>,
    pub baseline_new_keys: BTreeSet<String>,
}

impl Default for ScoreOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            generated_paths: BTreeSet::new(),
            baseline_new_keys: BTreeSet::new(),
        }
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
    calculate_score_report(findings, &ScoreOptions::default())
        .overall
        .unwrap_or(100)
}

pub fn calculate_score_report(findings: &[Finding], options: &ScoreOptions) -> ScoreReport {
    if !options.enabled {
        return ScoreReport::disabled();
    }

    let overall = score_findings(findings, options, |_| true, None);

    ScoreReport {
        enabled: true,
        overall: Some(overall.score),
        categories: ScoreCategories {
            duplication: category_score(findings, options, ScoreCategory::Duplication),
            complexity: category_score(findings, options, ScoreCategory::Complexity),
            style: category_score(findings, options, ScoreCategory::Style),
            react: category_score(findings, options, ScoreCategory::React),
            fastapi: category_score(findings, options, ScoreCategory::FastApi),
            rust_idiom: category_score(findings, options, ScoreCategory::RustIdiom),
            maintainability: category_score(findings, options, ScoreCategory::Maintainability),
            ci_risk: category_score(findings, options, ScoreCategory::CiRisk),
        },
        top_contributors: overall.contributors,
        model: ScoreModel::default(),
    }
}

fn category_score(
    findings: &[Finding],
    options: &ScoreOptions,
    category: ScoreCategory,
) -> ScoreCategoryScore {
    let scored = score_findings(
        findings,
        options,
        |finding| finding_in_category(finding, category, options),
        Some(category.label()),
    );

    ScoreCategoryScore {
        score: Some(scored.score),
        penalty: scored.penalty,
        findings: scored.findings,
    }
}

#[derive(Debug)]
struct ScoredFindings {
    score: u8,
    penalty: u8,
    findings: usize,
    contributors: Vec<ScoreContributor>,
}

fn score_findings(
    findings: &[Finding],
    options: &ScoreOptions,
    include: impl Fn(&Finding) -> bool,
    category_label: Option<&'static str>,
) -> ScoredFindings {
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    let mut finding_count = 0;

    for finding in findings {
        if finding.is_suppressed || !include(finding) {
            continue;
        }

        finding_count += 1;
        groups
            .entry(score_group_key(finding))
            .or_default()
            .push(finding);
    }

    let mut total_tenths = 0_u16;
    let mut contributors = Vec::new();

    for group in groups.into_values() {
        let mut group = group;
        group.sort_by(|left, right| {
            left.rule_id
                .cmp(&right.rule_id)
                .then_with(|| left.message.cmp(&right.message))
                .then_with(|| left.finding_id.cmp(&right.finding_id))
        });

        let group_tenths = repeated_group_penalty_tenths(&group, options);
        total_tenths = total_tenths.saturating_add(group_tenths);

        if group_tenths > 0 {
            let representative = group[0];
            contributors.push(ScoreContributor {
                rule_id: representative.rule_id.clone(),
                message: representative.message.clone(),
                category: category_label
                    .unwrap_or_else(|| primary_score_category(representative, options).label())
                    .to_string(),
                penalty: tenths_to_points(group_tenths),
                occurrences: group.len(),
                locations: contributor_locations(&group),
            });
        }
    }

    contributors.sort_by(|left, right| {
        right
            .penalty
            .cmp(&left.penalty)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.message.cmp(&right.message))
    });
    contributors.truncate(5);

    let penalty = tenths_to_points(total_tenths).min(100);
    ScoredFindings {
        score: 100_u8.saturating_sub(penalty),
        penalty,
        findings: finding_count,
        contributors,
    }
}

fn contributor_locations(group: &[&Finding]) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    for finding in group {
        for location in &finding.locations {
            paths.insert(location.path.clone());
        }
    }
    paths.into_iter().take(5).collect()
}

fn repeated_group_penalty_tenths(group: &[&Finding], options: &ScoreOptions) -> u16 {
    let mut penalties = group
        .iter()
        .map(|finding| finding_penalty_tenths(finding, options))
        .filter(|penalty| *penalty > 0)
        .collect::<Vec<_>>();
    penalties.sort_by(|left, right| right.cmp(left));

    let Some(maximum) = penalties.first().copied() else {
        return 0;
    };

    let mut total = 0_u16;
    for (index, penalty) in penalties.into_iter().enumerate() {
        let weighted = match index {
            0 => penalty,
            1 | 2 => ceil_div_u16(penalty, 2),
            3..=9 => ceil_div_u16(penalty, 4),
            _ => 0,
        };
        total = total.saturating_add(weighted);
    }

    total.min(maximum.saturating_mul(3))
}

fn finding_penalty_tenths(finding: &Finding, options: &ScoreOptions) -> u16 {
    let severity = match finding.severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 3,
        Severity::High => 8,
        Severity::Critical => 15,
    };
    if severity == 0 {
        return 0;
    }

    let numerator = severity as u32
        * 10
        * u32::from(confidence_multiplier_percent(finding.confidence))
        * u32::from(context_multiplier_percent(finding, options));
    ceil_div_u32(numerator, 10_000)
        .try_into()
        .unwrap_or(u16::MAX)
}

fn confidence_multiplier_percent(confidence: Confidence) -> u16 {
    match confidence {
        Confidence::Low => 25,
        Confidence::Medium => 50,
        Confidence::High => 80,
        Confidence::Certain => 100,
    }
}

fn context_multiplier_percent(finding: &Finding, options: &ScoreOptions) -> u16 {
    if finding.locations.is_empty() {
        return 100;
    }

    let total = finding
        .locations
        .iter()
        .map(|location| path_multiplier_percent(&location.path, options))
        .sum::<u16>();
    total / finding.locations.len() as u16
}

fn path_multiplier_percent(path: &Path, options: &ScoreOptions) -> u16 {
    if options.generated_paths.contains(path) {
        return 25;
    }

    if is_test_or_fixture_path(path) {
        return 50;
    }

    100
}

fn is_test_or_fixture_path(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized.split('/').any(|part| {
        matches!(
            part,
            "test" | "tests" | "fixture" | "fixtures" | "__tests__" | "__fixtures__"
        )
    }) {
        return true;
    }

    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| {
            let stem = stem.to_ascii_lowercase();
            stem.ends_with(".test") || stem.ends_with(".spec")
        })
        .unwrap_or(false)
}

fn score_group_key(finding: &Finding) -> String {
    let key = finding
        .metadata
        .get("normalized_file_hash")
        .and_then(|value| value.as_str())
        .or_else(|| {
            finding
                .metadata
                .get("normalized_body_hash")
                .and_then(|value| value.as_str())
        })
        .or_else(|| {
            finding
                .metadata
                .get("canonical_hash")
                .and_then(|value| value.as_str())
        })
        .or_else(|| {
            finding
                .metadata
                .get("route")
                .and_then(|value| value.as_str())
        })
        .unwrap_or(&finding.message);

    format!("{}|{key}", finding.rule_id)
}

fn category_key(finding: &Finding, category: ScoreCategory, options: &ScoreOptions) -> bool {
    match category {
        ScoreCategory::Duplication => matches!(
            finding.kind,
            FindingKind::DuplicateName
                | FindingKind::ExactDuplicate
                | FindingKind::StructuralDuplicate
                | FindingKind::NearDuplicate
                | FindingKind::SemanticCandidate
        ),
        ScoreCategory::Complexity => {
            finding.rule_id.contains("complex")
                || finding.rule_id.contains("large.function")
                || finding.metadata.contains_key("complexity")
        }
        ScoreCategory::Style => finding.kind == FindingKind::Style,
        ScoreCategory::React => {
            finding.kind == FindingKind::React
                || finding
                    .framework
                    .as_deref()
                    .is_some_and(|framework| framework.eq_ignore_ascii_case("react"))
        }
        ScoreCategory::FastApi => {
            finding.kind == FindingKind::FastApi
                || finding
                    .framework
                    .as_deref()
                    .is_some_and(|framework| framework.eq_ignore_ascii_case("fastapi"))
        }
        ScoreCategory::RustIdiom => {
            finding.kind == FindingKind::Rust
                || finding.rule_id.starts_with("rust.")
                || finding
                    .language
                    .as_deref()
                    .is_some_and(|language| language.eq_ignore_ascii_case("rust"))
        }
        ScoreCategory::Maintainability => true,
        ScoreCategory::CiRisk => {
            finding.blocks_by_default() || options.baseline_new_keys.contains(&finding.baseline_key)
        }
    }
}

fn finding_in_category(finding: &Finding, category: ScoreCategory, options: &ScoreOptions) -> bool {
    category_key(finding, category, options)
}

fn primary_score_category(finding: &Finding, options: &ScoreOptions) -> ScoreCategory {
    [
        ScoreCategory::CiRisk,
        ScoreCategory::FastApi,
        ScoreCategory::React,
        ScoreCategory::RustIdiom,
        ScoreCategory::Duplication,
        ScoreCategory::Complexity,
        ScoreCategory::Style,
        ScoreCategory::Maintainability,
    ]
    .into_iter()
    .find(|category| finding_in_category(finding, *category, options))
    .unwrap_or(ScoreCategory::Maintainability)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScoreCategory {
    Duplication,
    Complexity,
    Style,
    React,
    FastApi,
    RustIdiom,
    Maintainability,
    CiRisk,
}

impl ScoreCategory {
    fn label(self) -> &'static str {
        match self {
            Self::Duplication => "duplication",
            Self::Complexity => "complexity",
            Self::Style => "style",
            Self::React => "react",
            Self::FastApi => "fastapi",
            Self::RustIdiom => "rust_idiom",
            Self::Maintainability => "maintainability",
            Self::CiRisk => "ci_risk",
        }
    }
}

fn tenths_to_points(tenths: u16) -> u8 {
    ceil_div_u16(tenths, 10).min(100).try_into().unwrap_or(100)
}

fn ceil_div_u16(value: u16, divisor: u16) -> u16 {
    if value == 0 {
        0
    } else {
        ((value - 1) / divisor) + 1
    }
}

fn ceil_div_u32(value: u32, divisor: u32) -> u32 {
    if value == 0 {
        0
    } else {
        ((value - 1) / divisor) + 1
    }
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
        assert_eq!(calculate_score(&[sample_finding("one")]), 92);
    }

    #[test]
    fn score_weights_confidence_and_test_fixture_context() {
        let mut finding = sample_finding("one");
        finding.confidence = Confidence::Medium;
        assert_eq!(calculate_score(&[finding]), 96);

        let mut fixture_finding = sample_finding("two");
        fixture_finding.locations = vec![FindingLocation {
            path: PathBuf::from("tests/fixture.ts"),
            span: None,
            start: None,
            language: Some("typescript".to_string()),
        }];
        assert_eq!(calculate_score(&[fixture_finding]), 96);
    }

    #[test]
    fn score_caps_repeated_identical_findings() {
        let findings = (0..20)
            .map(|index| sample_finding(&format!("finding-{index}")))
            .collect::<Vec<_>>();

        assert_eq!(calculate_score(&findings), 76);
    }

    #[test]
    fn disabled_score_has_no_overall_value() {
        let report = calculate_score_report(
            &[sample_finding("one")],
            &ScoreOptions {
                enabled: false,
                ..ScoreOptions::default()
            },
        );

        assert!(!report.enabled);
        assert_eq!(report.overall, None);
    }

    #[test]
    fn score_keeps_global_and_category_scores_separate() {
        let report = calculate_score_report(&[sample_finding("one")], &ScoreOptions::default());

        assert_eq!(report.overall, Some(92));
        assert_eq!(report.categories.duplication.score, Some(92));
        assert_eq!(report.categories.maintainability.score, Some(92));
        assert_eq!(report.categories.react.score, Some(100));
    }

    fn sample_finding(id: &str) -> Finding {
        Finding {
            finding_id: id.to_string(),
            baseline_key: id.to_string(),
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
            fixes: Vec::new(),
            metadata: BTreeMap::new(),
            is_suppressed: false,
            suppression: None,
        }
    }
}
