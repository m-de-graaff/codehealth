use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const DEFAULT_CONFIG_FILE: &str = "codehealth.toml";

pub fn default_config_toml() -> &'static str {
    r#"# codehealth configuration

[scan]
include_extensions = []
follow_symlinks = false

[ci]
baseline = ".codehealth/baseline.json"
block_new_findings_only = true

[report]
default_format = "text"
color = "auto"

[cache]
enabled = true
dir = ".codehealth/cache"
"#
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CodehealthConfig {
    pub scan: ScanConfig,
    pub ci: CiConfig,
    pub report: ReportConfig,
    pub cache: CacheConfig,
}

impl CodehealthConfig {
    pub fn load(path: Option<&Path>, cwd: &Path) -> Result<Self, ConfigError> {
        let config_path = config_path(path, cwd);

        if path.is_none() && !config_path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(&config_path).map_err(|source| ConfigError::Read {
            path: config_path.clone(),
            source,
        })?;

        Self::from_toml_str(&raw).map_err(|source| ConfigError::Parse {
            path: config_path,
            source: Box::new(source),
        })
    }

    pub fn validate_path(path: &Path) -> Result<Self, ConfigError> {
        Self::load(Some(path), Path::new("."))
    }

    pub fn from_toml_str(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }
}

pub fn config_path(path: Option<&Path>, cwd: &Path) -> PathBuf {
    match path {
        Some(path) => path.to_path_buf(),
        None => cwd.join(DEFAULT_CONFIG_FILE),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    pub include_extensions: Vec<String>,
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CiConfig {
    pub baseline: Option<PathBuf>,
    pub block_new_findings_only: bool,
}

impl Default for CiConfig {
    fn default() -> Self {
        Self {
            baseline: Some(PathBuf::from(".codehealth/baseline.json")),
            block_new_findings_only: true,
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_default_config_returns_defaults() {
        let cwd = Path::new("target/does-not-exist-for-codehealth-config-test");
        let config = CodehealthConfig::load(None, cwd).expect("default config loads");

        assert_eq!(config.report.default_format, "text");
        assert!(config.ci.block_new_findings_only);
        assert_eq!(
            config.ci.baseline,
            Some(PathBuf::from(".codehealth/baseline.json"))
        );
    }

    #[test]
    fn parses_partial_config_with_defaults() {
        let raw = r#"
            [report]
            default_format = "json"
        "#;

        let config = CodehealthConfig::from_toml_str(raw).expect("valid toml");

        assert_eq!(config.report.default_format, "json");
        assert_eq!(config.report.color, "auto");
        assert!(!config.scan.follow_symlinks);
    }

    #[test]
    fn rejects_unknown_fields() {
        let raw = "unknown = true";

        assert!(CodehealthConfig::from_toml_str(raw).is_err());
    }
}
