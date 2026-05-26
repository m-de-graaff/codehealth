use codehealth_core::{Confidence, Severity};
use codehealth_rules::{canonical_rule_id, rule_catalog};
use globset::{Glob, GlobSetBuilder};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

pub const DEFAULT_CONFIG_FILE: &str = "codehealth.toml";

pub fn default_config_toml() -> &'static str {
    r#"# codehealth configuration

[project]
languages = ["typescript", "tsx", "python", "rust"]
frameworks = ["react", "fastapi"]

[duplication]
enabled = true
detect_names = true
detect_exact = true
detect_structural = true
detect_near = false
detect_semantic_candidates = false
min_tokens = 40
min_lines = 5
min_confidence = "medium"

[style]
simplify_boolean_returns = true
prefer_expression_arrows = true
prefer_guard_clauses = false
autofix_safe_only = true

[react]
enabled = true
max_component_lines = 180
max_props = 8
detect_prop_drilling = true
prop_drilling_depth = 3

[fastapi]
enabled = true
detect_duplicate_routes = true
detect_blocking_async_calls = true
require_response_model = "warn"

[ci]
fail_on = ["new_high"]
baseline = ".codehealth/baseline.json"

[ignore]
paths = [
  "node_modules",
  "dist",
  "build",
  "target",
  ".venv",
]

[rules]
"duplicate.exact.file" = "error"
"duplicate.name.function" = "warn"
"duplicate.structural.function" = "error"
"style.boolean_return_simplifiable" = "warn"
"react.large.component" = "warn"
"fastapi.duplicate.route" = "error"

[rule_options."duplicate.exact.file"]
include_paths = []
exclude_paths = []

[report]
default_format = "text"
color = "auto"

[cache]
enabled = true
dir = ".codehealth/cache"
"#
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    pub config: CodehealthConfig,
    pub path: Option<PathBuf>,
    pub warnings: Vec<ConfigWarning>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CodehealthConfig {
    pub project: ProjectConfig,
    pub duplication: DuplicationConfig,
    pub style: StyleConfig,
    pub react: ReactConfig,
    pub fastapi: FastApiConfig,
    pub ci: CiConfig,
    pub ignore: IgnoreConfig,
    pub rules: BTreeMap<String, RuleLevel>,
    pub rule_options: BTreeMap<String, RuleOptions>,
    pub path_overrides: Vec<PathOverride>,
    pub report: ReportConfig,
    pub cache: CacheConfig,
}

impl CodehealthConfig {
    pub fn load(path: Option<&Path>, cwd: &Path) -> Result<Self, ConfigError> {
        Ok(Self::load_with_metadata(path, cwd)?.config)
    }

    pub fn load_with_metadata(
        path: Option<&Path>,
        cwd: &Path,
    ) -> Result<LoadedConfig, ConfigError> {
        let config_path = discover_config_path(path, cwd)?;

        let mut config = if let Some(config_path) = &config_path {
            let raw = std::fs::read_to_string(config_path).map_err(|source| ConfigError::Read {
                path: config_path.clone(),
                source,
            })?;

            Self::from_toml_str(&raw).map_err(|source| ConfigError::Parse {
                path: config_path.clone(),
                source: Box::new(source),
            })?
        } else {
            Self::default()
        };

        let warnings = config.normalize_and_validate()?;

        Ok(LoadedConfig {
            config,
            path: config_path,
            warnings,
        })
    }

    pub fn validate_path(path: Option<&Path>, cwd: &Path) -> Result<LoadedConfig, ConfigError> {
        Self::load_with_metadata(path, cwd)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }

    pub fn normalize_and_validate(&mut self) -> Result<Vec<ConfigWarning>, ConfigError> {
        validate_languages(&self.project.languages)?;
        validate_frameworks(&self.project.frameworks)?;
        validate_fail_on(&self.ci.fail_on)?;
        validate_response_model_level(&self.fastapi.require_response_model)?;

        self.rules = canonicalize_rule_map(&self.rules, "rules")?;
        self.rule_options = canonicalize_rule_options(&self.rule_options)?;

        for (index, override_config) in self.path_overrides.iter_mut().enumerate() {
            override_config.rules = canonicalize_rule_map(
                &override_config.rules,
                &format!("path_overrides[{index}].rules"),
            )?;
            validate_patterns(
                &override_config.paths,
                &format!("path_overrides[{index}].paths"),
            )?;
        }

        validate_patterns(&self.ignore.paths, "ignore.paths")?;

        for (rule_id, options) in &self.rule_options {
            validate_patterns(
                &options.include_paths,
                &format!("rule_options.{rule_id}.include_paths"),
            )?;
            validate_patterns(
                &options.exclude_paths,
                &format!("rule_options.{rule_id}.exclude_paths"),
            )?;
        }

        Ok(Vec::new())
    }

    pub fn level_for_rule(&self, rule_id: &str, root: &Path, paths: &[PathBuf]) -> RuleLevel {
        let canonical = canonical_rule_id(rule_id).unwrap_or(rule_id);
        let mut level = self
            .rules
            .get(canonical)
            .copied()
            .unwrap_or(RuleLevel::Inherit);

        for override_config in &self.path_overrides {
            if paths
                .iter()
                .any(|path| path_matches_any(root, path, &override_config.paths))
            {
                if let Some(override_level) = override_config.rules.get(canonical) {
                    level = *override_level;
                }
            }
        }

        level
    }

    pub fn rule_options_for(&self, rule_id: &str) -> Option<&RuleOptions> {
        canonical_rule_id(rule_id).and_then(|canonical| self.rule_options.get(canonical))
    }
}

pub fn discover_config_path(
    explicit: Option<&Path>,
    cwd: &Path,
) -> Result<Option<PathBuf>, ConfigError> {
    if let Some(explicit) = explicit {
        return Ok(Some(explicit.to_path_buf()));
    }

    let mut current = cwd.to_path_buf();
    loop {
        let candidate = current.join(DEFAULT_CONFIG_FILE);
        if candidate.exists() {
            return Ok(Some(candidate));
        }

        if !current.pop() {
            return Ok(None);
        }
    }
}

pub fn config_path(path: Option<&Path>, cwd: &Path) -> PathBuf {
    discover_config_path(path, cwd)
        .ok()
        .flatten()
        .unwrap_or_else(|| cwd.join(DEFAULT_CONFIG_FILE))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            languages: vec![
                "typescript".to_string(),
                "tsx".to_string(),
                "python".to_string(),
                "rust".to_string(),
            ],
            frameworks: vec!["react".to_string(), "fastapi".to_string()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct DuplicationConfig {
    pub enabled: bool,
    pub detect_names: bool,
    pub detect_exact: bool,
    pub detect_structural: bool,
    pub detect_near: bool,
    pub detect_semantic_candidates: bool,
    pub min_tokens: usize,
    pub min_lines: usize,
    pub min_confidence: Confidence,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_names: true,
            detect_exact: true,
            detect_structural: true,
            detect_near: false,
            detect_semantic_candidates: false,
            min_tokens: 40,
            min_lines: 5,
            min_confidence: Confidence::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct StyleConfig {
    pub simplify_boolean_returns: bool,
    pub prefer_expression_arrows: bool,
    pub prefer_guard_clauses: bool,
    pub autofix_safe_only: bool,
}

impl Default for StyleConfig {
    fn default() -> Self {
        Self {
            simplify_boolean_returns: true,
            prefer_expression_arrows: true,
            prefer_guard_clauses: false,
            autofix_safe_only: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ReactConfig {
    pub enabled: bool,
    pub max_component_lines: usize,
    pub max_props: usize,
    pub detect_prop_drilling: bool,
    pub prop_drilling_depth: usize,
}

impl Default for ReactConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_component_lines: 180,
            max_props: 8,
            detect_prop_drilling: true,
            prop_drilling_depth: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FastApiConfig {
    pub enabled: bool,
    pub detect_duplicate_routes: bool,
    pub detect_blocking_async_calls: bool,
    pub require_response_model: String,
}

impl Default for FastApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_duplicate_routes: true,
            detect_blocking_async_calls: true,
            require_response_model: "warn".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CiConfig {
    pub fail_on: Vec<String>,
    pub baseline: Option<PathBuf>,
    pub block_new_findings_only: bool,
}

impl Default for CiConfig {
    fn default() -> Self {
        Self {
            fail_on: Vec::new(),
            baseline: Some(PathBuf::from(".codehealth/baseline.json")),
            block_new_findings_only: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct IgnoreConfig {
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RuleOptions {
    pub min_tokens: Option<usize>,
    pub min_lines: Option<usize>,
    pub min_confidence: Option<Confidence>,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct PathOverride {
    pub paths: Vec<String>,
    pub rules: BTreeMap<String, RuleLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ReportConfig {
    pub default_format: String,
    pub color: String,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            default_format: "text".to_string(),
            color: "auto".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    pub enabled: bool,
    pub dir: PathBuf,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: PathBuf::from(".codehealth/cache"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLevel {
    Inherit,
    Off,
    Severity(Severity),
}

impl RuleLevel {
    pub fn severity(self) -> Option<Severity> {
        match self {
            Self::Inherit => None,
            Self::Off => None,
            Self::Severity(severity) => Some(severity),
        }
    }

    pub fn is_off(self) -> bool {
        matches!(self, Self::Off)
    }
}

impl<'de> Deserialize<'de> for RuleLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl Serialize for RuleLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::Inherit => "inherit",
            Self::Off => "off",
            Self::Severity(Severity::Info) => "info",
            Self::Severity(Severity::Low) => "low",
            Self::Severity(Severity::Medium) => "medium",
            Self::Severity(Severity::High) => "high",
            Self::Severity(Severity::Critical) => "critical",
        })
    }
}

impl FromStr for RuleLevel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "inherit" => Ok(Self::Inherit),
            "off" | "disabled" => Ok(Self::Off),
            "info" => Ok(Self::Severity(Severity::Info)),
            "low" => Ok(Self::Severity(Severity::Low)),
            "warn" | "warning" | "medium" => Ok(Self::Severity(Severity::Medium)),
            "high" | "error" => Ok(Self::Severity(Severity::High)),
            "critical" => Ok(Self::Severity(Severity::Critical)),
            other => Err(format!(
                "invalid rule level '{other}', expected off, info, low, warn, medium, high, error, or critical"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionKind {
    NextLine,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionDirective {
    pub rule_id: String,
    pub path: PathBuf,
    pub line: usize,
    pub target_start_line: usize,
    pub target_end_line: usize,
    pub kind: SuppressionKind,
    pub reason: Option<String>,
    pub warnings: Vec<String>,
}

impl SuppressionDirective {
    pub fn matches(&self, rule_id: &str, line: usize) -> bool {
        canonical_rule_id(rule_id).is_some_and(|canonical| {
            canonical == self.rule_id
                && line >= self.target_start_line
                && line <= self.target_end_line
        })
    }
}

pub fn parse_suppressions(path: &Path, source: &str) -> Vec<SuppressionDirective> {
    let mut suppressions = Vec::new();
    let lines = source.lines().collect::<Vec<_>>();
    let mut open_blocks: BTreeMap<String, Vec<SuppressionDirective>> = BTreeMap::new();

    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let Some(raw_directive) = directive_text(line) else {
            continue;
        };

        if let Some(rest) = raw_directive.strip_prefix("codehealth-ignore-next-line") {
            if let Some(mut directive) =
                parse_suppression_payload(path, line_number, rest, SuppressionKind::NextLine)
            {
                directive.target_start_line = line_number + 1;
                directive.target_end_line = line_number + 1;
                suppressions.push(directive);
            }
        } else if let Some(rest) = raw_directive.strip_prefix("codehealth-ignore-start") {
            if let Some(mut directive) =
                parse_suppression_payload(path, line_number, rest, SuppressionKind::Block)
            {
                directive.target_start_line = line_number + 1;
                directive.target_end_line = lines.len();
                open_blocks
                    .entry(directive.rule_id.clone())
                    .or_default()
                    .push(directive);
            }
        } else if let Some(rest) = raw_directive.strip_prefix("codehealth-ignore-end") {
            let rule_id = rest.split_whitespace().next().and_then(canonical_rule_id);
            if let Some(rule_id) = rule_id {
                if let Some(stack) = open_blocks.get_mut(rule_id) {
                    if let Some(mut directive) = stack.pop() {
                        directive.target_end_line = line_number.saturating_sub(1);
                        suppressions.push(directive);
                    }
                }
            }
        }
    }

    for stack in open_blocks.into_values() {
        suppressions.extend(stack);
    }

    suppressions
}

fn directive_text(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed
        .strip_prefix("//")
        .or_else(|| trimmed.strip_prefix('#'))?
        .trim_start();

    if trimmed.starts_with("codehealth-ignore-") {
        Some(trimmed)
    } else {
        None
    }
}

fn parse_suppression_payload(
    path: &Path,
    line: usize,
    rest: &str,
    kind: SuppressionKind,
) -> Option<SuppressionDirective> {
    let (rule_part, reason_part) = rest.split_once("--").unwrap_or((rest, ""));
    let rule_id = canonical_rule_id(rule_part.split_whitespace().next()?)?.to_string();
    let reason = reason_part.trim();
    let reason = (!reason.is_empty()).then(|| reason.to_string());
    let mut warnings = Vec::new();

    if reason.is_none() {
        warnings.push("suppression reason is missing".to_string());
    }

    Some(SuppressionDirective {
        rule_id,
        path: path.to_path_buf(),
        line,
        target_start_line: line,
        target_end_line: line,
        kind,
        reason,
        warnings,
    })
}

pub fn path_matches_any(root: &Path, path: &Path, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    let normalized = normalize_path(path);
    let relative = path
        .strip_prefix(root)
        .map(normalize_path)
        .unwrap_or_else(|_| normalized.clone());

    patterns
        .iter()
        .any(|pattern| path_matches_pattern(&relative, &normalized, pattern))
}

fn path_matches_pattern(relative: &str, normalized: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().replace('\\', "/");
    if pattern.is_empty() {
        return false;
    }

    if !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') {
        return relative == pattern
            || normalized == pattern
            || relative.starts_with(&format!("{pattern}/"))
            || normalized.ends_with(&format!("/{pattern}"))
            || normalized.contains(&format!("/{pattern}/"));
    }

    let mut builder = GlobSetBuilder::new();
    if let Ok(glob) = Glob::new(&pattern) {
        builder.add(glob);
    }
    if !pattern.starts_with("**/") {
        if let Ok(glob) = Glob::new(&format!("**/{pattern}")) {
            builder.add(glob);
        }
    }

    builder
        .build()
        .map(|set| set.is_match(relative) || set.is_match(normalized))
        .unwrap_or(false)
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn canonicalize_rule_map(
    rules: &BTreeMap<String, RuleLevel>,
    context: &str,
) -> Result<BTreeMap<String, RuleLevel>, ConfigError> {
    let mut canonical = BTreeMap::new();

    for (rule_id, level) in rules {
        let Some(canonical_rule) = canonical_rule_id(rule_id) else {
            return Err(ConfigError::from(vec![
                ConfigValidationError::UnknownRule {
                    context: context.to_string(),
                    rule_id: rule_id.clone(),
                    known_rules: known_rule_ids(),
                },
            ]));
        };
        canonical.insert(canonical_rule.to_string(), *level);
    }

    Ok(canonical)
}

fn canonicalize_rule_options(
    options: &BTreeMap<String, RuleOptions>,
) -> Result<BTreeMap<String, RuleOptions>, ConfigError> {
    let mut canonical = BTreeMap::new();

    for (rule_id, options) in options {
        let Some(canonical_rule) = canonical_rule_id(rule_id) else {
            return Err(ConfigError::from(vec![
                ConfigValidationError::UnknownRule {
                    context: "rule_options".to_string(),
                    rule_id: rule_id.clone(),
                    known_rules: known_rule_ids(),
                },
            ]));
        };
        canonical.insert(canonical_rule.to_string(), options.clone());
    }

    Ok(canonical)
}

fn validate_languages(languages: &[String]) -> Result<(), ConfigError> {
    let allowed = ["typescript", "tsx", "python", "rust"];
    validate_enum_list("project.languages", languages, &allowed)
}

fn validate_frameworks(frameworks: &[String]) -> Result<(), ConfigError> {
    let allowed = ["react", "fastapi"];
    validate_enum_list("project.frameworks", frameworks, &allowed)
}

fn validate_fail_on(values: &[String]) -> Result<(), ConfigError> {
    let allowed = ["high", "new_high", "new_medium"];
    validate_enum_list("ci.fail_on", values, &allowed)
}

fn validate_response_model_level(value: &str) -> Result<(), ConfigError> {
    let allowed = ["off", "warn", "error"];
    validate_enum_list(
        "fastapi.require_response_model",
        &[value.to_string()],
        &allowed,
    )
}

fn validate_enum_list(
    context: &str,
    values: &[String],
    allowed: &[&str],
) -> Result<(), ConfigError> {
    let errors = values
        .iter()
        .filter(|value| {
            !allowed
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(value))
        })
        .map(|value| ConfigValidationError::InvalidValue {
            context: context.to_string(),
            value: value.clone(),
            expected: allowed.iter().map(|value| (*value).to_string()).collect(),
        })
        .collect::<Vec<_>>();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::from(errors))
    }
}

fn validate_patterns(patterns: &[String], context: &str) -> Result<(), ConfigError> {
    let errors = patterns
        .iter()
        .filter(|pattern| pattern.contains('*') || pattern.contains('?') || pattern.contains('['))
        .filter_map(|pattern| {
            Glob::new(pattern)
                .err()
                .map(|source| ConfigValidationError::InvalidGlob {
                    context: context.to_string(),
                    pattern: pattern.clone(),
                    message: source.to_string(),
                })
        })
        .collect::<Vec<_>>();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::from(errors))
    }
}

fn known_rule_ids() -> Vec<String> {
    rule_catalog()
        .into_iter()
        .map(|rule| rule.code.to_string())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValidationError {
    UnknownRule {
        context: String,
        rule_id: String,
        known_rules: Vec<String>,
    },
    InvalidValue {
        context: String,
        value: String,
        expected: Vec<String>,
    },
    InvalidGlob {
        context: String,
        pattern: String,
        message: String,
    },
}

impl fmt::Display for ConfigValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRule {
                context,
                rule_id,
                known_rules,
            } => write!(
                formatter,
                "unknown rule id '{rule_id}' in {context}; known rules: {}",
                known_rules.join(", ")
            ),
            Self::InvalidValue {
                context,
                value,
                expected,
            } => write!(
                formatter,
                "invalid value '{value}' in {context}; expected one of: {}",
                expected.join(", ")
            ),
            Self::InvalidGlob {
                context,
                pattern,
                message,
            } => write!(
                formatter,
                "invalid glob '{pattern}' in {context}: {message}"
            ),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config at {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },

    #[error("invalid config: {0}")]
    Validation(ValidationErrors),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ConfigValidationError>);

impl From<Vec<ConfigValidationError>> for ValidationErrors {
    fn from(value: Vec<ConfigValidationError>) -> Self {
        Self(value)
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{error}")?;
        }

        Ok(())
    }
}

impl From<Vec<ConfigValidationError>> for ConfigError {
    fn from(value: Vec<ConfigValidationError>) -> Self {
        Self::Validation(ValidationErrors(value))
    }
}

impl From<ConfigValidationError> for ConfigError {
    fn from(value: ConfigValidationError) -> Self {
        Self::Validation(ValidationErrors(vec![value]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_default_config_returns_defaults() {
        let cwd = Path::new("target/does-not-exist-for-codehealth-config-test");
        let loaded = CodehealthConfig::load_with_metadata(None, cwd).expect("default config loads");

        assert!(loaded.path.is_none());
        assert_eq!(loaded.config.report.default_format, "text");
        assert_eq!(loaded.config.project.languages.len(), 4);
        assert!(loaded.config.ci.block_new_findings_only);
    }

    #[test]
    fn parses_full_default_config() {
        let mut config =
            CodehealthConfig::from_toml_str(default_config_toml()).expect("valid toml");

        config.normalize_and_validate().expect("valid default");

        assert_eq!(
            config.rules.get("duplicate.exact.file"),
            Some(&RuleLevel::Severity(Severity::High))
        );
    }

    #[test]
    fn canonicalizes_rule_aliases() {
        let raw = r#"
            [rules]
            "duplicate.exact_file" = "off"
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        config.normalize_and_validate().expect("valid aliases");

        assert_eq!(
            config.rules.get("duplicate.exact.file"),
            Some(&RuleLevel::Off)
        );
    }

    #[test]
    fn rejects_unknown_rule_ids() {
        let raw = r#"
            [rules]
            "unknown.rule" = "warn"
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        let error = config.normalize_and_validate().expect_err("unknown rule");

        assert!(error.to_string().contains("unknown rule id 'unknown.rule'"));
    }

    #[test]
    fn rejects_invalid_rule_levels() {
        let raw = r#"
            [rules]
            "duplicate.exact.file" = "sometimes"
        "#;

        let error = CodehealthConfig::from_toml_str(raw).expect_err("invalid level");

        assert!(error.to_string().contains("invalid rule level"));
    }

    #[test]
    fn path_matcher_matches_directory_names() {
        assert!(path_matches_any(
            Path::new("repo"),
            Path::new("repo/target/debug/main.rs"),
            &["target".to_string()]
        ));
    }

    #[test]
    fn parses_next_line_suppression_with_alias_and_warning() {
        let suppressions = parse_suppressions(
            Path::new("a.ts"),
            "// codehealth-ignore-next-line duplicate.exact_file\nexport const a = 1;",
        );

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_id, "duplicate.exact.file");
        assert_eq!(suppressions[0].target_start_line, 2);
        assert_eq!(
            suppressions[0].warnings,
            vec!["suppression reason is missing"]
        );
    }
}
