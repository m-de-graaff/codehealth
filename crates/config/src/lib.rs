use codehealth_core::{Confidence, Severity};
use codehealth_rules::{canonical_rule_id, rule_catalog};
use globset::{Glob, GlobSetBuilder};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
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
structural_normalize_literals = false
structural_min_nodes = 5
structural_max_opaque_percent = 25
near_similarity_threshold = 82
near_hash_functions = 96
near_lsh_bands = 24
near_lsh_rows = 4
near_common_shingle_max_percent = 5
near_common_shingle_min_occurrences = 20
near_max_bucket_size = 200
near_max_candidate_pairs = 250000
semantic_property_reads_are_pure = false
semantic_normalize_boolean_returns = true
semantic_normalize_commutative_ops = true
semantic_normalize_comparisons = true

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
blocking_call_allowlist = []
blocking_call_patterns = ["requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "time.sleep", "open(", ".read(", ".write("]

[rust]
enabled = true
clippy_enabled = false
clippy_command = "cargo"
clippy_args = ["clippy", "--message-format=json", "--all-targets", "--all-features"]
clippy_timeout_ms = 120000
max_function_lines = 80
max_params = 6
max_unwraps = 2
max_match_depth = 4

[scanner]
include = []
exclude = []
max_file_size_bytes = 1048576
follow_symlinks = false
include_generated = false
include_binary = false
detect_javascript = true

[ci]
fail_on = ["new_high"]
baseline = ".codehealth/baseline.json"
# baseline_owner = "platform"

[ignore]
paths = [
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  "target",
  ".venv",
  "venv",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".next",
  ".turbo",
]

[rules]
"duplicate.exact.body" = "error"
"duplicate.exact.file" = "error"
"duplicate.name.class" = "warn"
"duplicate.name.function" = "warn"
"duplicate.name.method" = "warn"
"duplicate.name.react_component" = "warn"
"duplicate.name.react_hook" = "warn"
"duplicate.name.fastapi_route_handler" = "warn"
"duplicate.name.rust_type" = "warn"
"duplicate.name.rust_impl_method" = "warn"
"duplicate.structural.function" = "warn"
"duplicate.near.function" = "warn"
"duplicate.semantic.function" = "warn"
"duplicate.semantic.vector_candidate" = "info"
"style.boolean_return_simplifiable" = "warn"
"style.expression_arrow_simplifiable" = "warn"
"style.unnecessary_else_after_return" = "info"
"style.nested_conditional" = "info"
"style.guard_clause" = "info"
"style.duplicated_literal" = "info"
"style.large_function" = "warn"
"style.high_parameter_count" = "warn"
"style.complex_condition" = "info"
"python.broad_exception" = "warn"
"python.repeated_validation_logic" = "info"
"python.duplicated_route_handler_business_logic" = "warn"
"rust.large_function" = "warn"
"rust.too_many_parameters" = "warn"
"rust.duplicate_free_function" = "warn"
"rust.duplicate_impl_method" = "warn"
"rust.duplicate_trait_method_implementation" = "warn"
"rust.repeated_match_arm_body" = "info"
"rust.suspicious_unwrap_policy" = "warn"
"rust.expect_without_context" = "info"
"rust.repeated_error_mapping" = "info"
"rust.manual_option_result_pattern_candidate" = "info"
"rust.deeply_nested_match" = "warn"
"rust.large_enum_variant_logic" = "info"
"rust.repeated_result_handling" = "info"
"rust.repeated_conversion_function" = "info"
"rust.repeated_validation_logic" = "info"
"rust.repeated_serde_glue" = "info"
"rust.clippy_unavailable" = "info"
"rust.clippy_run_failed" = "info"
"react.large_component" = "warn"
"react.too_many_props" = "warn"
"react.deeply_nested_jsx" = "warn"
"react.duplicate_component_shape" = "warn"
"react.repeated_hook_logic" = "warn"
"react.unnecessary_effect_candidate" = "info"
"react.derived_state_candidate" = "info"
"react.inline_component_inside_render" = "warn"
"react.unstable_list_key" = "warn"
"react.missing_key" = "warn"
"react.prop_drilling_candidate" = "warn"
"react.large_context_provider" = "warn"
"react.mixed_data_fetching_and_rendering" = "warn"
"react.component_too_many_responsibilities" = "warn"
"react.redundant_fragment" = "info"
"fastapi.duplicate.route" = "error"
"fastapi.route_conflict" = "error"
"fastapi.blocking_call_in_async_route" = "warn"
"fastapi.missing_response_model" = "warn"
"fastapi.large_route_handler" = "warn"
"fastapi.business_logic_in_route" = "warn"
"fastapi.repeated_dependency_logic" = "warn"
"fastapi.repeated_auth_logic" = "warn"
"fastapi.broad_exception_in_route" = "warn"
"fastapi.inconsistent_status_code" = "info"
"fastapi.duplicated_pydantic_model" = "info"
"fastapi.route_handler_duplicate_logic" = "warn"
"fastapi.sync_db_call_inside_async_route" = "warn"
"fastapi.requests_call_inside_async_route" = "warn"

[rule_options."duplicate.exact.file"]
include_paths = []
exclude_paths = []

[rule_options."duplicate.exact.body"]
min_tokens = 40
min_lines = 5
include_paths = []
exclude_paths = []

[rule_options."duplicate.structural.function"]
min_tokens = 5
min_lines = 1
include_paths = []
exclude_paths = []

[rule_options."duplicate.near.function"]
min_tokens = 40
min_lines = 5
min_confidence = "medium"
include_paths = []
exclude_paths = []

[rule_options."duplicate.semantic.function"]
min_tokens = 5
min_lines = 1
min_confidence = "medium"
include_paths = []
exclude_paths = []

[rule_options."style.large_function"]
max_lines = 80
include_paths = []
exclude_paths = []

[rule_options."style.high_parameter_count"]
max_params = 6
include_paths = []
exclude_paths = []

[rule_options."style.complex_condition"]
max_condition_terms = 3
include_paths = []
exclude_paths = []

[rule_options."style.duplicated_literal"]
max_literal_occurrences = 3
include_paths = []
exclude_paths = []

[rule_options."rust.large_function"]
max_lines = 80
include_paths = []
exclude_paths = []

[rule_options."rust.too_many_parameters"]
max_params = 6
include_paths = []
exclude_paths = []

[rule_options."rust.duplicate_free_function"]
min_lines = 3
min_tokens = 20
include_paths = []
exclude_paths = []

[rule_options."rust.duplicate_impl_method"]
min_lines = 3
min_tokens = 20
include_paths = []
exclude_paths = []

[rule_options."rust.duplicate_trait_method_implementation"]
min_lines = 3
min_tokens = 20
include_paths = []
exclude_paths = []

[rule_options."rust.suspicious_unwrap_policy"]
max_unwraps = 2
include_paths = []
exclude_paths = []

[rule_options."rust.deeply_nested_match"]
max_depth = 4
include_paths = []
exclude_paths = []

[rule_options."rust.large_enum_variant_logic"]
max_params = 6
include_paths = []
exclude_paths = []

[rule_options."rust.repeated_result_handling"]
min_nodes = 2
include_paths = []
exclude_paths = []

[rule_options."rust.repeated_error_mapping"]
min_nodes = 2
include_paths = []
exclude_paths = []

[rule_options."rust.repeated_conversion_function"]
min_lines = 3
min_tokens = 20
include_paths = []
exclude_paths = []

[rule_options."rust.repeated_validation_logic"]
min_nodes = 2
include_paths = []
exclude_paths = []

[rule_options."rust.repeated_serde_glue"]
min_lines = 3
min_tokens = 20
include_paths = []
exclude_paths = []

[rule_options."react.large_component"]
max_lines = 180
include_paths = []
exclude_paths = []

[rule_options."react.too_many_props"]
max_params = 8
include_paths = []
exclude_paths = []

[rule_options."react.deeply_nested_jsx"]
max_depth = 5
include_paths = []
exclude_paths = []

[rule_options."react.duplicate_component_shape"]
min_nodes = 3
include_paths = []
exclude_paths = []

[rule_options."react.prop_drilling_candidate"]
max_depth = 3
include_paths = []
exclude_paths = []

[rule_options."react.large_context_provider"]
max_context_values = 6
include_paths = []
exclude_paths = []

[rule_options."react.component_too_many_responsibilities"]
max_responsibilities = 5
include_paths = []
exclude_paths = []

[rule_options."fastapi.large_route_handler"]
max_lines = 80
include_paths = []
exclude_paths = []

[rule_options."fastapi.repeated_dependency_logic"]
min_nodes = 3
include_paths = []
exclude_paths = []

[rule_options."fastapi.repeated_auth_logic"]
min_nodes = 3
include_paths = []
exclude_paths = []

[rule_options."fastapi.duplicated_pydantic_model"]
min_nodes = 3
include_paths = []
exclude_paths = []

[rule_options."fastapi.route_handler_duplicate_logic"]
min_lines = 5
min_tokens = 40
include_paths = []
exclude_paths = []

[report]
default_format = "text"
color = "auto"

[scoring]
enabled = true

[embeddings]
enabled = false
provider = "none"
privacy_mode = "disabled"
similarity_threshold = 0.80
candidate_limit = 100
cache_vectors = true

[integrations]
eslint = false
biome = false
tsc = false
ruff = false
mypy = false
pyright = false
cargo_check = false
clippy = false
semgrep = false
fail_on_tool_error = false
timeout_ms = 120000
eslint_command = "eslint"
eslint_args = ["--format", "json", "."]
biome_command = "biome"
biome_args = ["ci", "--reporter=json"]
tsc_command = "tsc"
tsc_args = ["--noEmit", "--pretty", "false"]
ruff_command = "ruff"
ruff_args = ["check", "--output-format=json", "."]
mypy_command = "mypy"
mypy_args = ["--show-column-numbers", "--no-error-summary", "."]
pyright_command = "pyright"
pyright_args = ["--outputjson"]
cargo_check_command = "cargo"
cargo_check_args = ["check", "--message-format=json"]
clippy_command = "cargo"
clippy_args = ["clippy", "--message-format=json", "--all-targets", "--all-features"]
semgrep_command = "semgrep"
semgrep_args = ["scan", "--json"]

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
    pub rust: RustConfig,
    pub scanner: ScannerConfig,
    pub ci: CiConfig,
    pub ignore: IgnoreConfig,
    pub rules: BTreeMap<String, RuleLevel>,
    pub rule_options: BTreeMap<String, RuleOptions>,
    pub path_overrides: Vec<PathOverride>,
    pub report: ReportConfig,
    pub scoring: ScoringConfig,
    pub embeddings: EmbeddingsConfig,
    pub integrations: IntegrationsConfig,
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
        validate_report_format(&self.report.default_format)?;
        validate_embedding_provider(&self.embeddings.provider)?;
        validate_embedding_privacy_mode(&self.embeddings.privacy_mode)?;
        validate_similarity_threshold(
            self.embeddings.similarity_threshold,
            "embeddings.similarity_threshold",
        )?;
        validate_positive_usize(
            self.embeddings.candidate_limit,
            "embeddings.candidate_limit",
        )?;
        validate_positive_size(self.integrations.timeout_ms, "integrations.timeout_ms")?;
        validate_response_model_level(&self.fastapi.require_response_model)?;
        validate_patterns(&self.scanner.include, "scanner.include")?;
        validate_patterns(&self.scanner.exclude, "scanner.exclude")?;
        validate_positive_size(
            self.scanner.max_file_size_bytes,
            "scanner.max_file_size_bytes",
        )?;
        validate_percentage(
            self.duplication.structural_max_opaque_percent,
            "duplication.structural_max_opaque_percent",
        )?;
        validate_percentage(
            self.duplication.near_similarity_threshold,
            "duplication.near_similarity_threshold",
        )?;
        if self.duplication.near_similarity_threshold == 0 {
            return Err(ConfigValidationError::InvalidValue {
                context: "duplication.near_similarity_threshold".to_string(),
                value: self.duplication.near_similarity_threshold.to_string(),
                expected: vec!["integer from 1 through 100".to_string()],
            }
            .into());
        }
        validate_positive_usize(
            self.duplication.near_hash_functions,
            "duplication.near_hash_functions",
        )?;
        validate_positive_usize(
            self.duplication.near_lsh_bands,
            "duplication.near_lsh_bands",
        )?;
        validate_positive_usize(self.duplication.near_lsh_rows, "duplication.near_lsh_rows")?;
        validate_percentage(
            self.duplication.near_common_shingle_max_percent,
            "duplication.near_common_shingle_max_percent",
        )?;
        validate_positive_usize(
            self.duplication.near_common_shingle_min_occurrences,
            "duplication.near_common_shingle_min_occurrences",
        )?;
        validate_positive_usize(
            self.duplication.near_max_bucket_size,
            "duplication.near_max_bucket_size",
        )?;
        validate_positive_usize(
            self.duplication.near_max_candidate_pairs,
            "duplication.near_max_candidate_pairs",
        )?;
        let Some(expected_near_hash_functions) = self
            .duplication
            .near_lsh_bands
            .checked_mul(self.duplication.near_lsh_rows)
        else {
            return Err(ConfigValidationError::InvalidValue {
                context: "duplication.near_lsh_bands".to_string(),
                value: self.duplication.near_lsh_bands.to_string(),
                expected: vec![
                    "multiplication with duplication.near_lsh_rows must fit usize".to_string(),
                ],
            }
            .into());
        };
        if self.duplication.near_hash_functions != expected_near_hash_functions {
            return Err(ConfigValidationError::InvalidValue {
                context: "duplication.near_hash_functions".to_string(),
                value: self.duplication.near_hash_functions.to_string(),
                expected: vec![
                    "equal to duplication.near_lsh_bands * duplication.near_lsh_rows".to_string(),
                ],
            }
            .into());
        }

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
    pub structural_normalize_literals: bool,
    pub structural_min_nodes: usize,
    pub structural_max_opaque_percent: u8,
    pub near_similarity_threshold: u8,
    pub near_hash_functions: usize,
    pub near_lsh_bands: usize,
    pub near_lsh_rows: usize,
    pub near_common_shingle_max_percent: u8,
    pub near_common_shingle_min_occurrences: usize,
    pub near_max_bucket_size: usize,
    pub near_max_candidate_pairs: usize,
    pub semantic_property_reads_are_pure: bool,
    pub semantic_normalize_boolean_returns: bool,
    pub semantic_normalize_commutative_ops: bool,
    pub semantic_normalize_comparisons: bool,
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
            structural_normalize_literals: false,
            structural_min_nodes: 5,
            structural_max_opaque_percent: 25,
            near_similarity_threshold: 82,
            near_hash_functions: 96,
            near_lsh_bands: 24,
            near_lsh_rows: 4,
            near_common_shingle_max_percent: 5,
            near_common_shingle_min_occurrences: 20,
            near_max_bucket_size: 200,
            near_max_candidate_pairs: 250_000,
            semantic_property_reads_are_pure: false,
            semantic_normalize_boolean_returns: true,
            semantic_normalize_commutative_ops: true,
            semantic_normalize_comparisons: true,
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
    pub blocking_call_allowlist: Vec<String>,
    pub blocking_call_patterns: Vec<String>,
}

impl Default for FastApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_duplicate_routes: true,
            detect_blocking_async_calls: true,
            require_response_model: "warn".to_string(),
            blocking_call_allowlist: Vec::new(),
            blocking_call_patterns: vec![
                "requests.get".to_string(),
                "requests.post".to_string(),
                "requests.put".to_string(),
                "requests.patch".to_string(),
                "requests.delete".to_string(),
                "time.sleep".to_string(),
                "open(".to_string(),
                ".read(".to_string(),
                ".write(".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RustConfig {
    pub enabled: bool,
    pub clippy_enabled: bool,
    pub clippy_command: String,
    pub clippy_args: Vec<String>,
    pub clippy_timeout_ms: u64,
    pub max_function_lines: usize,
    pub max_params: usize,
    pub max_unwraps: usize,
    pub max_match_depth: usize,
}

impl Default for RustConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            clippy_enabled: false,
            clippy_command: "cargo".to_string(),
            clippy_args: vec![
                "clippy".to_string(),
                "--message-format=json".to_string(),
                "--all-targets".to_string(),
                "--all-features".to_string(),
            ],
            clippy_timeout_ms: 120_000,
            max_function_lines: 80,
            max_params: 6,
            max_unwraps: 2,
            max_match_depth: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ScannerConfig {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub max_file_size_bytes: u64,
    pub follow_symlinks: bool,
    pub include_generated: bool,
    pub include_binary: bool,
    pub detect_javascript: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            max_file_size_bytes: 1024 * 1024,
            follow_symlinks: false,
            include_generated: false,
            include_binary: false,
            detect_javascript: true,
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
    pub baseline_owner: Option<String>,
}

impl Default for CiConfig {
    fn default() -> Self {
        Self {
            fail_on: Vec::new(),
            baseline: Some(PathBuf::from(".codehealth/baseline.json")),
            block_new_findings_only: true,
            baseline_owner: None,
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
    pub max_lines: Option<usize>,
    pub max_params: Option<usize>,
    pub max_condition_terms: Option<usize>,
    pub max_literal_occurrences: Option<usize>,
    pub max_unwraps: Option<usize>,
    pub max_depth: Option<usize>,
    pub min_nodes: Option<usize>,
    pub max_context_values: Option<usize>,
    pub max_responsibilities: Option<usize>,
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
pub struct ScoringConfig {
    pub enabled: bool,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingsConfig {
    pub enabled: bool,
    pub provider: String,
    pub privacy_mode: String,
    pub similarity_threshold: SimilarityThreshold,
    pub candidate_limit: usize,
    pub cache_vectors: bool,
}

impl Default for EmbeddingsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "none".to_string(),
            privacy_mode: "disabled".to_string(),
            similarity_threshold: SimilarityThreshold::from_basis_points(8_000),
            candidate_limit: 100,
            cache_vectors: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct IntegrationsConfig {
    pub eslint: bool,
    pub biome: bool,
    pub tsc: bool,
    pub ruff: bool,
    pub mypy: bool,
    pub pyright: bool,
    pub cargo_check: bool,
    pub clippy: bool,
    pub semgrep: bool,
    pub fail_on_tool_error: bool,
    pub timeout_ms: u64,
    pub eslint_command: String,
    pub eslint_args: Vec<String>,
    pub biome_command: String,
    pub biome_args: Vec<String>,
    pub tsc_command: String,
    pub tsc_args: Vec<String>,
    pub ruff_command: String,
    pub ruff_args: Vec<String>,
    pub mypy_command: String,
    pub mypy_args: Vec<String>,
    pub pyright_command: String,
    pub pyright_args: Vec<String>,
    pub cargo_check_command: String,
    pub cargo_check_args: Vec<String>,
    pub clippy_command: String,
    pub clippy_args: Vec<String>,
    pub semgrep_command: String,
    pub semgrep_args: Vec<String>,
}

impl Default for IntegrationsConfig {
    fn default() -> Self {
        Self {
            eslint: false,
            biome: false,
            tsc: false,
            ruff: false,
            mypy: false,
            pyright: false,
            cargo_check: false,
            clippy: false,
            semgrep: false,
            fail_on_tool_error: false,
            timeout_ms: 120_000,
            eslint_command: "eslint".to_string(),
            eslint_args: vec!["--format".to_string(), "json".to_string(), ".".to_string()],
            biome_command: "biome".to_string(),
            biome_args: vec!["ci".to_string(), "--reporter=json".to_string()],
            tsc_command: "tsc".to_string(),
            tsc_args: vec![
                "--noEmit".to_string(),
                "--pretty".to_string(),
                "false".to_string(),
            ],
            ruff_command: "ruff".to_string(),
            ruff_args: vec![
                "check".to_string(),
                "--output-format=json".to_string(),
                ".".to_string(),
            ],
            mypy_command: "mypy".to_string(),
            mypy_args: vec![
                "--show-column-numbers".to_string(),
                "--no-error-summary".to_string(),
                ".".to_string(),
            ],
            pyright_command: "pyright".to_string(),
            pyright_args: vec!["--outputjson".to_string()],
            cargo_check_command: "cargo".to_string(),
            cargo_check_args: vec!["check".to_string(), "--message-format=json".to_string()],
            clippy_command: "cargo".to_string(),
            clippy_args: vec![
                "clippy".to_string(),
                "--message-format=json".to_string(),
                "--all-targets".to_string(),
                "--all-features".to_string(),
            ],
            semgrep_command: "semgrep".to_string(),
            semgrep_args: vec!["scan".to_string(), "--json".to_string()],
        }
    }
}

impl IntegrationsConfig {
    pub fn any_enabled(&self) -> bool {
        self.eslint
            || self.biome
            || self.tsc
            || self.ruff
            || self.mypy
            || self.pyright
            || self.cargo_check
            || self.clippy
            || self.semgrep
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SimilarityThreshold {
    basis_points: u16,
}

impl SimilarityThreshold {
    pub const fn from_basis_points(basis_points: u16) -> Self {
        Self { basis_points }
    }

    pub fn basis_points(self) -> u16 {
        self.basis_points
    }

    pub fn as_ratio(self) -> f32 {
        f32::from(self.basis_points) / 10_000.0
    }

    pub fn as_percent(self) -> u8 {
        ((usize::from(self.basis_points) + 50) / 100)
            .try_into()
            .unwrap_or(100)
    }
}

impl Default for SimilarityThreshold {
    fn default() -> Self {
        Self::from_basis_points(8_000)
    }
}

impl Serialize for SimilarityThreshold {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(f64::from(self.basis_points) / 10_000.0)
    }
}

impl<'de> Deserialize<'de> for SimilarityThreshold {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SimilarityThresholdVisitor)
    }
}

struct SimilarityThresholdVisitor;

impl<'de> Visitor<'de> for SimilarityThresholdVisitor {
    type Value = SimilarityThreshold;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a number from 0.0 through 1.0")
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !(0.0..=1.0).contains(&value) || !value.is_finite() {
            return Err(E::custom("expected a number from 0.0 through 1.0"));
        }
        Ok(SimilarityThreshold::from_basis_points(
            (value * 10_000.0).round() as u16,
        ))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_f64(value as f64)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_f64(value as f64)
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

fn validate_report_format(value: &str) -> Result<(), ConfigError> {
    let allowed = ["text", "json", "sarif", "html", "markdown", "md"];
    validate_enum_list("report.default_format", &[value.to_string()], &allowed)
}

fn validate_embedding_provider(value: &str) -> Result<(), ConfigError> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(());
    }

    let expected = if ["local", "external"]
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(value))
    {
        vec!["none (local and external providers are reserved for a future version)".to_string()]
    } else {
        vec!["none".to_string()]
    };

    Err(ConfigValidationError::InvalidValue {
        context: "embeddings.provider".to_string(),
        value: value.to_string(),
        expected,
    }
    .into())
}

fn validate_embedding_privacy_mode(value: &str) -> Result<(), ConfigError> {
    let allowed = ["disabled", "local_only", "external_opt_in"];
    validate_enum_list("embeddings.privacy_mode", &[value.to_string()], &allowed)
}

fn validate_similarity_threshold(
    value: SimilarityThreshold,
    context: &str,
) -> Result<(), ConfigError> {
    if value.basis_points() == 0 || value.basis_points() > 10_000 {
        return Err(ConfigValidationError::InvalidValue {
            context: context.to_string(),
            value: format!("{:.4}", value.as_ratio()),
            expected: vec!["number greater than 0.0 and at most 1.0".to_string()],
        }
        .into());
    }

    Ok(())
}

fn validate_response_model_level(value: &str) -> Result<(), ConfigError> {
    let allowed = ["off", "warn", "error"];
    validate_enum_list(
        "fastapi.require_response_model",
        &[value.to_string()],
        &allowed,
    )
}

fn validate_positive_size(value: u64, context: &str) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigValidationError::InvalidValue {
            context: context.to_string(),
            value: value.to_string(),
            expected: vec!["positive integer".to_string()],
        }
        .into());
    }

    Ok(())
}

fn validate_positive_usize(value: usize, context: &str) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigValidationError::InvalidValue {
            context: context.to_string(),
            value: value.to_string(),
            expected: vec!["positive integer".to_string()],
        }
        .into());
    }

    Ok(())
}

fn validate_percentage(value: u8, context: &str) -> Result<(), ConfigError> {
    if value > 100 {
        return Err(ConfigValidationError::InvalidValue {
            context: context.to_string(),
            value: value.to_string(),
            expected: vec!["integer from 0 through 100".to_string()],
        }
        .into());
    }

    Ok(())
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
        assert_eq!(loaded.config.scanner.max_file_size_bytes, 1024 * 1024);
        assert!(loaded.config.scanner.detect_javascript);
        assert!(loaded.config.ci.block_new_findings_only);
        assert!(loaded.config.scoring.enabled);
        assert!(!loaded.config.embeddings.enabled);
        assert_eq!(loaded.config.embeddings.provider, "none");
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
        assert!(config.scoring.enabled);
        assert_eq!(config.embeddings.similarity_threshold.basis_points(), 8_000);
        assert!(!config.integrations.any_enabled());
        assert_eq!(config.integrations.timeout_ms, 120_000);
        assert_eq!(
            config.rules.get("duplicate.semantic.vector_candidate"),
            Some(&RuleLevel::Severity(Severity::Info))
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
    fn parses_scoring_enabled_flag() {
        let raw = r#"
            [scoring]
            enabled = false
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        config
            .normalize_and_validate()
            .expect("valid scoring config");

        assert!(!config.scoring.enabled);
    }

    #[test]
    fn parses_embedding_config() {
        let raw = r#"
            [embeddings]
            enabled = true
            provider = "none"
            privacy_mode = "local_only"
            similarity_threshold = 0.75
            candidate_limit = 25
            cache_vectors = false
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        config
            .normalize_and_validate()
            .expect("valid embedding config");

        assert!(config.embeddings.enabled);
        assert_eq!(config.embeddings.privacy_mode, "local_only");
        assert_eq!(config.embeddings.similarity_threshold.basis_points(), 7_500);
        assert_eq!(config.embeddings.similarity_threshold.as_percent(), 75);
        assert_eq!(config.embeddings.candidate_limit, 25);
        assert!(!config.embeddings.cache_vectors);
    }

    #[test]
    fn parses_integrations_config() {
        let raw = r#"
            [integrations]
            eslint = true
            tsc = true
            fail_on_tool_error = true
            timeout_ms = 30000
            eslint_command = "pnpm"
            eslint_args = ["eslint", "--format", "json", "."]
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        config
            .normalize_and_validate()
            .expect("valid integrations config");

        assert!(config.integrations.eslint);
        assert!(config.integrations.tsc);
        assert!(config.integrations.fail_on_tool_error);
        assert_eq!(config.integrations.timeout_ms, 30_000);
        assert_eq!(config.integrations.eslint_command, "pnpm");
        assert_eq!(config.integrations.eslint_args[0], "eslint");
    }

    #[test]
    fn accepts_markdown_report_format() {
        let raw = r#"
            [report]
            default_format = "markdown"
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        config
            .normalize_and_validate()
            .expect("valid report format");

        assert_eq!(config.report.default_format, "markdown");
    }

    #[test]
    fn parses_baseline_owner() {
        let raw = r#"
            [ci]
            baseline_owner = "platform"
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        config.normalize_and_validate().expect("valid ci config");

        assert_eq!(config.ci.baseline_owner.as_deref(), Some("platform"));
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
    fn validates_scanner_options() {
        let raw = r#"
            [scanner]
            include = ["src/**"]
            exclude = ["target/**"]
            max_file_size_bytes = 0
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        let error = config
            .normalize_and_validate()
            .expect_err("invalid scanner");

        assert!(error.to_string().contains("scanner.max_file_size_bytes"));
    }

    #[test]
    fn validates_near_duplicate_lsh_options() {
        let raw = r#"
            [duplication]
            near_hash_functions = 95
            near_lsh_bands = 24
            near_lsh_rows = 4
        "#;
        let mut config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        let error = config
            .normalize_and_validate()
            .expect_err("invalid near duplicate config");

        assert!(error
            .to_string()
            .contains("duplication.near_hash_functions"));
    }

    #[test]
    fn rejects_reserved_embedding_providers() {
        for provider in ["local", "external"] {
            let raw = format!(
                r#"
                [embeddings]
                provider = "{provider}"
            "#
            );
            let mut config = CodehealthConfig::from_toml_str(&raw).expect("valid toml");

            let error = config
                .normalize_and_validate()
                .expect_err("reserved provider");

            assert!(error.to_string().contains("embeddings.provider"));
            assert!(error.to_string().contains("reserved"));
        }
    }

    #[test]
    fn validates_embedding_privacy_threshold_and_limit() {
        let invalid_privacy = r#"
            [embeddings]
            privacy_mode = "network"
        "#;
        let mut config = CodehealthConfig::from_toml_str(invalid_privacy).expect("valid toml");
        assert!(config
            .normalize_and_validate()
            .expect_err("invalid privacy")
            .to_string()
            .contains("embeddings.privacy_mode"));

        let invalid_threshold = r#"
            [embeddings]
            similarity_threshold = 0.0
        "#;
        let mut config = CodehealthConfig::from_toml_str(invalid_threshold).expect("valid toml");
        assert!(config
            .normalize_and_validate()
            .expect_err("invalid threshold")
            .to_string()
            .contains("embeddings.similarity_threshold"));

        let invalid_limit = r#"
            [embeddings]
            candidate_limit = 0
        "#;
        let mut config = CodehealthConfig::from_toml_str(invalid_limit).expect("valid toml");
        assert!(config
            .normalize_and_validate()
            .expect_err("invalid limit")
            .to_string()
            .contains("embeddings.candidate_limit"));
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
