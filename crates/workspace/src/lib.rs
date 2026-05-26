use codehealth_parser::{LanguageInfo, LanguageRegistry};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use serde_json::Value as JsonValue;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Take},
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

const SAMPLE_LIMIT_BYTES: u64 = 64 * 1024;
const CONFIG_READ_LIMIT_BYTES: u64 = 256 * 1024;

const BUILT_IN_IGNORES: &[&str] = &[
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
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceScan {
    pub root: PathBuf,
    pub files: Vec<WorkspaceFile>,
    pub discovery_files: Vec<DiscoveryFile>,
    pub config_files: Vec<WorkspaceConfigFile>,
    pub skipped: Vec<SkippedPath>,
    pub metadata: WorkspaceMetadata,
}

impl WorkspaceScan {
    pub fn files_discovered(&self) -> usize {
        self.files.len() + self.discovery_files.len() + self.config_files.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceFile {
    pub path: PathBuf,
    pub language: LanguageInfo,
    pub size_bytes: u64,
    pub generated_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryFile {
    pub path: PathBuf,
    pub kind: DiscoveryFileKind,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryFileKind {
    JavaScript,
    Jsx,
}

impl DiscoveryFileKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Jsx => "jsx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfigFile {
    pub path: PathBuf,
    pub kind: ConfigFileKind,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFileKind {
    PackageJson,
    TsconfigJson,
    PyprojectToml,
    CargoToml,
    RequirementsTxt,
    PoetryLock,
    UvLock,
    PackageLock,
    PnpmLock,
    YarnLock,
    BunLock,
}

impl ConfigFileKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::PackageJson => "package.json",
            Self::TsconfigJson => "tsconfig.json",
            Self::PyprojectToml => "pyproject.toml",
            Self::CargoToml => "Cargo.toml",
            Self::RequirementsTxt => "requirements.txt",
            Self::PoetryLock => "poetry.lock",
            Self::UvLock => "uv.lock",
            Self::PackageLock => "package-lock.json",
            Self::PnpmLock => "pnpm-lock.yaml",
            Self::YarnLock => "yarn.lock",
            Self::BunLock => "bun.lock",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedPath {
    pub path: PathBuf,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    Ignored,
    Excluded,
    NotIncluded,
    LanguageDisabled(String),
    TooLarge { size_bytes: u64, max_bytes: u64 },
    Binary,
    Generated(String),
    Minified(String),
    Symlink,
}

impl SkipReason {
    pub fn label(&self) -> String {
        match self {
            Self::Ignored => "ignored".to_string(),
            Self::Excluded => "excluded".to_string(),
            Self::NotIncluded => "not included".to_string(),
            Self::LanguageDisabled(language) => format!("language disabled: {language}"),
            Self::TooLarge {
                size_bytes,
                max_bytes,
            } => {
                format!("too large: {size_bytes} bytes > {max_bytes} bytes")
            }
            Self::Binary => "binary".to_string(),
            Self::Generated(reason) => format!("generated: {reason}"),
            Self::Minified(reason) => format!("minified: {reason}"),
            Self::Symlink => "symlink".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceScanOptions {
    pub ignore_paths: Vec<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub max_file_size_bytes: u64,
    pub follow_symlinks: bool,
    pub include_generated: bool,
    pub include_binary: bool,
    pub detect_javascript: bool,
    pub enabled_languages: Vec<String>,
}

impl Default for WorkspaceScanOptions {
    fn default() -> Self {
        Self {
            ignore_paths: Vec::new(),
            include: Vec::new(),
            exclude: Vec::new(),
            max_file_size_bytes: 1024 * 1024,
            follow_symlinks: false,
            include_generated: false,
            include_binary: false,
            detect_javascript: true,
            enabled_languages: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceMetadata {
    pub package_managers: BTreeSet<String>,
    pub python: PythonEnvironmentMetadata,
    pub rust: RustWorkspaceMetadata,
    pub react: ReactMetadata,
    pub fastapi: FastApiMetadata,
}

impl WorkspaceMetadata {
    pub fn frameworks(&self) -> Vec<&'static str> {
        let mut frameworks = Vec::new();
        if self.react.detected() {
            frameworks.push("react");
        }
        if self.fastapi.detected() {
            frameworks.push("fastapi");
        }
        frameworks
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PythonEnvironmentMetadata {
    pub has_pyproject_toml: bool,
    pub has_requirements_txt: bool,
    pub has_poetry_lock: bool,
    pub has_uv_lock: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RustWorkspaceMetadata {
    pub cargo_tomls: Vec<PathBuf>,
    pub workspace_members: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReactMetadata {
    pub via_dependency: bool,
    pub via_tsx_or_jsx: bool,
    pub via_next_dependency: bool,
    pub via_vite_dependency: bool,
}

impl ReactMetadata {
    pub fn detected(&self) -> bool {
        self.via_dependency
            || self.via_tsx_or_jsx
            || self.via_next_dependency
            || self.via_vite_dependency
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FastApiMetadata {
    pub via_dependency: bool,
    pub via_app_initialization: bool,
    pub via_router_initialization: bool,
}

impl FastApiMetadata {
    pub fn detected(&self) -> bool {
        self.via_dependency || self.via_app_initialization || self.via_router_initialization
    }
}

pub fn discover_files(
    root: impl AsRef<Path>,
    registry: &LanguageRegistry,
) -> Result<Vec<WorkspaceFile>, WorkspaceError> {
    Ok(scan_workspace(root, registry, WorkspaceScanOptions::default())?.files)
}

pub fn scan_workspace(
    root: impl AsRef<Path>,
    registry: &LanguageRegistry,
    options: WorkspaceScanOptions,
) -> Result<WorkspaceScan, WorkspaceError> {
    let root = root
        .as_ref()
        .canonicalize()
        .unwrap_or_else(|_| root.as_ref().to_path_buf());
    let built_in_matcher = Arc::new(PathMatcher::new(BUILT_IN_IGNORES)?);
    let ignore_matcher = Arc::new(PathMatcher::new(&options.ignore_paths)?);
    let include_matcher = PathMatcher::new(&options.include)?;
    let exclude_matcher = Arc::new(PathMatcher::new(&options.exclude)?);
    let mut scan = WorkspaceScan {
        root: root.clone(),
        files: Vec::new(),
        discovery_files: Vec::new(),
        config_files: Vec::new(),
        skipped: Vec::new(),
        metadata: WorkspaceMetadata::default(),
    };

    let mut builder = WalkBuilder::new(&root);
    builder
        .standard_filters(true)
        .require_git(false)
        .follow_links(options.follow_symlinks);

    let filter_root = root.clone();
    let filter_built_in = Arc::clone(&built_in_matcher);
    let filter_ignore = Arc::clone(&ignore_matcher);
    let filter_exclude = Arc::clone(&exclude_matcher);
    builder.filter_entry(move |entry| {
        if entry.path() == filter_root {
            return true;
        }
        if !entry
            .file_type()
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false)
        {
            return true;
        }

        !filter_built_in.matches(&filter_root, entry.path())
            && !filter_ignore.matches(&filter_root, entry.path())
            && !filter_exclude.matches(&filter_root, entry.path())
    });

    for entry in builder.build() {
        let entry = entry.map_err(WorkspaceError::Walk)?;
        let path = entry.path().to_path_buf();

        if entry
            .file_type()
            .map(|file_type| file_type.is_symlink())
            .unwrap_or(false)
        {
            scan.skipped.push(SkippedPath {
                path,
                reason: SkipReason::Symlink,
            });
            continue;
        }

        let is_file = entry
            .file_type()
            .map(|file_type| file_type.is_file())
            .unwrap_or(false);
        if !is_file {
            continue;
        }

        if built_in_matcher.matches(&root, &path) || ignore_matcher.matches(&root, &path) {
            scan.skipped.push(SkippedPath {
                path,
                reason: SkipReason::Ignored,
            });
            continue;
        }

        if exclude_matcher.matches(&root, &path) {
            scan.skipped.push(SkippedPath {
                path,
                reason: SkipReason::Excluded,
            });
            continue;
        }

        if !include_matcher.is_empty() && !include_matcher.matches(&root, &path) {
            scan.skipped.push(SkippedPath {
                path,
                reason: SkipReason::NotIncluded,
            });
            continue;
        }

        let metadata = std::fs::metadata(&path).map_err(|source| WorkspaceError::Metadata {
            path: path.clone(),
            source,
        })?;
        let size_bytes = metadata.len();

        if let Some(kind) = config_file_kind(&path) {
            let config_file = WorkspaceConfigFile {
                path: path.clone(),
                kind,
                size_bytes,
            };
            observe_config_file(&mut scan.metadata, &config_file)?;
            scan.config_files.push(config_file);
            continue;
        }

        if let Some(language) = registry.language_for_path(&path) {
            if !language_enabled(language.name, &options.enabled_languages) {
                scan.skipped.push(SkippedPath {
                    path,
                    reason: SkipReason::LanguageDisabled(language.name.to_string()),
                });
                continue;
            }

            let Some(inspection) = inspect_text_candidate(&path, size_bytes, &options)? else {
                continue;
            };
            if let Some(reason) = skip_reason_for_inspection(&inspection, &options) {
                scan.skipped.push(SkippedPath { path, reason });
                continue;
            }

            observe_source_file(
                &mut scan.metadata,
                &path,
                language.name,
                &inspection.text_sample,
            );
            scan.files.push(WorkspaceFile {
                path,
                language,
                size_bytes,
                generated_reason: inspection.generated_reason,
            });
            continue;
        }

        if options.detect_javascript {
            if let Some(kind) = javascript_kind(&path) {
                let Some(inspection) = inspect_text_candidate(&path, size_bytes, &options)? else {
                    continue;
                };
                if let Some(reason) = skip_reason_for_inspection(&inspection, &options) {
                    scan.skipped.push(SkippedPath { path, reason });
                    continue;
                }

                observe_discovery_file(&mut scan.metadata, kind);
                scan.discovery_files.push(DiscoveryFile {
                    path,
                    kind,
                    size_bytes,
                });
            }
        }
    }

    sort_scan(&mut scan);
    Ok(scan)
}

fn sort_scan(scan: &mut WorkspaceScan) {
    scan.files.sort_by(|left, right| left.path.cmp(&right.path));
    scan.discovery_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    scan.config_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    scan.skipped
        .sort_by(|left, right| left.path.cmp(&right.path));
    scan.metadata.rust.cargo_tomls.sort();
    scan.metadata.rust.workspace_members.sort();
}

fn language_enabled(language: &str, enabled_languages: &[String]) -> bool {
    enabled_languages.is_empty()
        || enabled_languages
            .iter()
            .any(|enabled| enabled.eq_ignore_ascii_case(language))
}

fn skip_reason_for_inspection(
    inspection: &FileInspection,
    options: &WorkspaceScanOptions,
) -> Option<SkipReason> {
    if inspection.too_large {
        return Some(SkipReason::TooLarge {
            size_bytes: inspection.size_bytes,
            max_bytes: options.max_file_size_bytes,
        });
    }
    if inspection.binary {
        return Some(SkipReason::Binary);
    }
    if let Some(reason) = &inspection.generated_reason {
        if !options.include_generated {
            return Some(SkipReason::Generated(reason.clone()));
        }
    }
    if let Some(reason) = &inspection.minified_reason {
        if !options.include_generated {
            return Some(SkipReason::Minified(reason.clone()));
        }
    }
    None
}

#[derive(Debug)]
struct FileInspection {
    size_bytes: u64,
    too_large: bool,
    binary: bool,
    generated_reason: Option<String>,
    minified_reason: Option<String>,
    text_sample: Option<String>,
}

fn inspect_text_candidate(
    path: &Path,
    size_bytes: u64,
    options: &WorkspaceScanOptions,
) -> Result<Option<FileInspection>, WorkspaceError> {
    if size_bytes > options.max_file_size_bytes {
        return Ok(Some(FileInspection {
            size_bytes,
            too_large: true,
            binary: false,
            generated_reason: None,
            minified_reason: None,
            text_sample: None,
        }));
    }

    let bytes = read_sample(path, SAMPLE_LIMIT_BYTES)?;
    let binary = bytes.contains(&0);
    let text_sample = if binary {
        None
    } else {
        std::str::from_utf8(&bytes).ok().map(str::to_string)
    };
    let binary = binary || text_sample.is_none();
    let generated_reason = text_sample
        .as_deref()
        .and_then(detect_generated_reason)
        .map(str::to_string);
    let minified_reason = text_sample
        .as_deref()
        .and_then(|sample| detect_minified_reason(path, sample))
        .map(str::to_string);

    Ok(Some(FileInspection {
        size_bytes,
        too_large: false,
        binary,
        generated_reason,
        minified_reason,
        text_sample,
    }))
}

fn read_sample(path: &Path, limit: u64) -> Result<Vec<u8>, WorkspaceError> {
    let file = File::open(path).map_err(|source| WorkspaceError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader: Take<File> = file.take(limit);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|source| WorkspaceError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes)
}

fn detect_generated_reason(sample: &str) -> Option<&'static str> {
    let lowered = sample.to_ascii_lowercase();
    if lowered.contains("@generated") {
        Some("@generated marker")
    } else if lowered.contains("code generated") {
        Some("code generated marker")
    } else if lowered.contains("do not edit") {
        Some("do not edit marker")
    } else if lowered.contains("generated by") {
        Some("generated by marker")
    } else {
        None
    }
}

fn detect_minified_reason(path: &Path, sample: &str) -> Option<&'static str> {
    let extension = normalized_extension(path)?;
    let is_js_like = matches!(
        extension.as_str(),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts"
    );
    let first_line_len = sample.lines().next().map(str::len).unwrap_or(0);
    let line_count = sample.lines().take(3).count();

    if first_line_len > 8_000 && line_count <= 1 {
        return Some("large one-line file");
    }

    if is_js_like && first_line_len > 2_000 && sample.contains('{') && sample.contains(';') {
        return Some("minified JavaScript/TypeScript");
    }

    None
}

fn config_file_kind(path: &Path) -> Option<ConfigFileKind> {
    let file_name = normalized_file_name(path)?;
    match file_name.as_str() {
        "package.json" => Some(ConfigFileKind::PackageJson),
        "tsconfig.json" => Some(ConfigFileKind::TsconfigJson),
        "pyproject.toml" => Some(ConfigFileKind::PyprojectToml),
        "cargo.toml" => Some(ConfigFileKind::CargoToml),
        "requirements.txt" => Some(ConfigFileKind::RequirementsTxt),
        "poetry.lock" => Some(ConfigFileKind::PoetryLock),
        "uv.lock" => Some(ConfigFileKind::UvLock),
        "package-lock.json" => Some(ConfigFileKind::PackageLock),
        "pnpm-lock.yaml" => Some(ConfigFileKind::PnpmLock),
        "yarn.lock" => Some(ConfigFileKind::YarnLock),
        "bun.lock" | "bun.lockb" => Some(ConfigFileKind::BunLock),
        _ => None,
    }
}

fn javascript_kind(path: &Path) -> Option<DiscoveryFileKind> {
    match normalized_extension(path)?.as_str() {
        "js" | "mjs" | "cjs" => Some(DiscoveryFileKind::JavaScript),
        "jsx" => Some(DiscoveryFileKind::Jsx),
        _ => None,
    }
}

fn normalized_extension(path: &Path) -> Option<String> {
    Some(path.extension()?.to_str()?.to_ascii_lowercase())
}

fn normalized_file_name(path: &Path) -> Option<String> {
    Some(path.file_name()?.to_str()?.to_ascii_lowercase())
}

fn observe_config_file(
    metadata: &mut WorkspaceMetadata,
    config_file: &WorkspaceConfigFile,
) -> Result<(), WorkspaceError> {
    match config_file.kind {
        ConfigFileKind::PackageJson => {
            let text = read_text_if_small(&config_file.path)?;
            observe_package_json(metadata, text.as_deref());
        }
        ConfigFileKind::PackageLock => {
            metadata.package_managers.insert("npm".to_string());
        }
        ConfigFileKind::PnpmLock => {
            metadata.package_managers.insert("pnpm".to_string());
        }
        ConfigFileKind::YarnLock => {
            metadata.package_managers.insert("yarn".to_string());
        }
        ConfigFileKind::BunLock => {
            metadata.package_managers.insert("bun".to_string());
        }
        ConfigFileKind::PyprojectToml => {
            metadata.python.has_pyproject_toml = true;
            let text = read_text_if_small(&config_file.path)?;
            if text
                .as_deref()
                .is_some_and(|text| text.to_ascii_lowercase().contains("fastapi"))
            {
                metadata.fastapi.via_dependency = true;
            }
        }
        ConfigFileKind::RequirementsTxt => {
            metadata.python.has_requirements_txt = true;
            let text = read_text_if_small(&config_file.path)?;
            if text.as_deref().is_some_and(requirements_contains_fastapi) {
                metadata.fastapi.via_dependency = true;
            }
        }
        ConfigFileKind::PoetryLock => {
            metadata.python.has_poetry_lock = true;
            let text = read_text_if_small(&config_file.path)?;
            if text
                .as_deref()
                .is_some_and(|text| text.to_ascii_lowercase().contains("fastapi"))
            {
                metadata.fastapi.via_dependency = true;
            }
        }
        ConfigFileKind::UvLock => {
            metadata.python.has_uv_lock = true;
            let text = read_text_if_small(&config_file.path)?;
            if text
                .as_deref()
                .is_some_and(|text| text.to_ascii_lowercase().contains("fastapi"))
            {
                metadata.fastapi.via_dependency = true;
            }
        }
        ConfigFileKind::CargoToml => {
            metadata.rust.cargo_tomls.push(config_file.path.clone());
            let text = read_text_if_small(&config_file.path)?;
            observe_cargo_toml(metadata, text.as_deref());
        }
        ConfigFileKind::TsconfigJson => {}
    }

    Ok(())
}

fn read_text_if_small(path: &Path) -> Result<Option<String>, WorkspaceError> {
    let metadata = std::fs::metadata(path).map_err(|source| WorkspaceError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > CONFIG_READ_LIMIT_BYTES {
        return Ok(None);
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|source| WorkspaceError::Read {
            path: path.to_path_buf(),
            source,
        })
}

fn observe_package_json(metadata: &mut WorkspaceMetadata, text: Option<&str>) {
    let Some(text) = text else {
        return;
    };
    let Ok(package_json) = serde_json::from_str::<JsonValue>(text) else {
        return;
    };

    if let Some(package_manager) = package_json
        .get("packageManager")
        .and_then(JsonValue::as_str)
        .and_then(|value| value.split('@').next())
    {
        if !package_manager.is_empty() {
            metadata
                .package_managers
                .insert(package_manager.to_string());
        }
    }

    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(dependencies) = package_json.get(section).and_then(JsonValue::as_object) else {
            continue;
        };
        if dependencies.contains_key("react") {
            metadata.react.via_dependency = true;
        }
        if dependencies.contains_key("next") {
            metadata.react.via_next_dependency = true;
        }
        if dependencies.contains_key("vite") {
            metadata.react.via_vite_dependency = true;
        }
    }
}

fn requirements_contains_fastapi(text: &str) -> bool {
    text.lines().any(|line| {
        let normalized = line.trim().to_ascii_lowercase();
        normalized == "fastapi"
            || normalized.starts_with("fastapi==")
            || normalized.starts_with("fastapi>=")
            || normalized.starts_with("fastapi[")
    })
}

fn observe_cargo_toml(metadata: &mut WorkspaceMetadata, text: Option<&str>) {
    let Some(text) = text else {
        return;
    };
    let Ok(cargo) = toml::from_str::<toml::Value>(text) else {
        return;
    };
    let Some(members) = cargo
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
    else {
        return;
    };

    metadata.rust.workspace_members.extend(
        members
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_string),
    );
}

fn observe_source_file(
    metadata: &mut WorkspaceMetadata,
    path: &Path,
    language: &str,
    text_sample: &Option<String>,
) {
    if language.eq_ignore_ascii_case("tsx") {
        metadata.react.via_tsx_or_jsx = true;
    }

    if language.eq_ignore_ascii_case("python") {
        if let Some(sample) = text_sample {
            if sample.contains("FastAPI(") {
                metadata.fastapi.via_app_initialization = true;
            }
            if sample.contains("APIRouter(") {
                metadata.fastapi.via_router_initialization = true;
            }
        }
    }

    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("jsx"))
    {
        metadata.react.via_tsx_or_jsx = true;
    }
}

fn observe_discovery_file(metadata: &mut WorkspaceMetadata, kind: DiscoveryFileKind) {
    if kind == DiscoveryFileKind::Jsx {
        metadata.react.via_tsx_or_jsx = true;
    }
}

struct PathMatcher {
    globset: GlobSet,
    literals: Vec<String>,
    is_empty: bool,
}

impl PathMatcher {
    fn new(patterns: &[impl AsRef<str>]) -> Result<Self, WorkspaceError> {
        let mut builder = GlobSetBuilder::new();
        let mut literals = Vec::new();
        let mut is_empty = true;

        for pattern in patterns {
            let pattern = normalize_pattern(pattern.as_ref());
            if pattern.is_empty() {
                continue;
            }
            is_empty = false;
            if has_glob_meta(&pattern) {
                builder.add(Glob::new(&pattern).map_err(|source| WorkspaceError::Glob {
                    pattern: pattern.clone(),
                    source,
                })?);
            } else {
                literals.push(pattern);
            }
        }

        let globset = builder.build().map_err(WorkspaceError::GlobSet)?;
        Ok(Self {
            globset,
            literals,
            is_empty,
        })
    }

    fn is_empty(&self) -> bool {
        self.is_empty
    }

    fn matches(&self, root: &Path, path: &Path) -> bool {
        if self.is_empty {
            return false;
        }

        let relative = relative_path(root, path);
        self.globset.is_match(Path::new(&relative))
            || self.literals.iter().any(|literal| {
                relative == *literal
                    || relative.starts_with(&format!("{literal}/"))
                    || (!literal.contains('/') && relative.split('/').any(|part| part == literal))
            })
    }
}

fn relative_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative.to_string_lossy().replace('\\', "/")
}

fn normalize_pattern(pattern: &str) -> String {
    pattern
        .trim()
        .trim_start_matches("./")
        .trim_matches('/')
        .replace('\\', "/")
}

fn has_glob_meta(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("failed to walk workspace")]
    Walk(#[source] ignore::Error),

    #[error("failed to read metadata for {path}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid glob '{pattern}'")]
    Glob {
        pattern: String,
        #[source]
        source: globset::Error,
    },

    #[error("failed to build glob set")]
    GlobSet(#[source] globset::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_parser::{LanguageAdapter, LanguageInfo};
    use std::fs;

    struct TestAdapter;

    impl LanguageAdapter for TestAdapter {
        fn info(&self) -> LanguageInfo {
            LanguageInfo {
                name: "typescript",
                extensions: &["ts", "mts", "cts"],
                tree_sitter_grammar: "tree-sitter-typescript",
            }
        }
    }

    struct PythonTestAdapter;

    impl LanguageAdapter for PythonTestAdapter {
        fn info(&self) -> LanguageInfo {
            LanguageInfo {
                name: "python",
                extensions: &["py", "pyi"],
                tree_sitter_grammar: "tree-sitter-python",
            }
        }
    }

    struct TsxTestAdapter;

    impl LanguageAdapter for TsxTestAdapter {
        fn info(&self) -> LanguageInfo {
            LanguageInfo {
                name: "tsx",
                extensions: &["tsx"],
                tree_sitter_grammar: "tree-sitter-typescript/tsx",
            }
        }
    }

    struct RustTestAdapter;

    impl LanguageAdapter for RustTestAdapter {
        fn info(&self) -> LanguageInfo {
            LanguageInfo {
                name: "rust",
                extensions: &["rs"],
                tree_sitter_grammar: "tree-sitter-rust",
            }
        }
    }

    #[test]
    fn discovers_registered_file_extensions() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/typescript");
        let mut registry = LanguageRegistry::new();
        registry.register(TestAdapter);

        let files = discover_files(fixture_root, &registry).expect("fixture discovery works");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language.name, "typescript");
    }

    #[test]
    fn scanner_filters_and_classifies_workspace_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        write(temp.path().join("src/a.ts"), "export const a = 1;\n");
        write(temp.path().join("src/b.mts"), "export const b = 1;\n");
        write(
            temp.path().join("src/component.tsx"),
            "export function App() { return <div />; }\n",
        );
        write(
            temp.path().join("src/app.py"),
            "from fastapi import FastAPI\napp = FastAPI()\n",
        );
        write(
            temp.path().join("src/lib.rs"),
            "pub fn value() -> i32 { 1 }\n",
        );
        write(
            temp.path().join("src/view.jsx"),
            "export const View = () => <main />;\n",
        );
        write(
            temp.path().join("node_modules/ignored.ts"),
            "export const ignored = 1;\n",
        );
        write(
            temp.path().join("src/generated.ts"),
            "// @generated\nexport const generated = 1;\n",
        );
        write(
            temp.path().join("src/minified.js"),
            &format!("function a(){{{};}}\n", "x=1;".repeat(600)),
        );
        write(temp.path().join("src/blob.ts"), "\0\0\0");
        write(
            temp.path().join("package.json"),
            r#"{"packageManager":"pnpm@9.0.0","dependencies":{"react":"latest","next":"latest"},"devDependencies":{"vite":"latest"}}"#,
        );
        write(
            temp.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n",
        );
        write(
            temp.path().join("pyproject.toml"),
            "[project]\ndependencies = [\"fastapi\"]\n",
        );
        write(
            temp.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(temp.path().join(".ignore"), "ignored-by-dotignore.ts\n");
        write(temp.path().join(".gitignore"), "gitignored.ts\n");
        write(
            temp.path().join("ignored-by-dotignore.ts"),
            "export const ignored = 1;\n",
        );
        write(
            temp.path().join("gitignored.ts"),
            "export const ignored = 1;\n",
        );

        let mut registry = LanguageRegistry::new();
        registry.register(TestAdapter);
        registry.register(TsxTestAdapter);
        registry.register(PythonTestAdapter);
        registry.register(RustTestAdapter);

        let scan = scan_workspace(
            temp.path(),
            &registry,
            WorkspaceScanOptions {
                enabled_languages: vec![
                    "typescript".to_string(),
                    "tsx".to_string(),
                    "python".to_string(),
                    "rust".to_string(),
                ],
                ..WorkspaceScanOptions::default()
            },
        )
        .expect("workspace scan");

        let source_paths = scan
            .files
            .iter()
            .map(|file| relative_path(&scan.root, &file.path))
            .collect::<Vec<_>>();
        assert_eq!(
            source_paths,
            vec![
                "src/a.ts",
                "src/app.py",
                "src/b.mts",
                "src/component.tsx",
                "src/lib.rs",
            ]
        );
        assert_eq!(scan.discovery_files.len(), 1);
        assert_eq!(scan.discovery_files[0].kind, DiscoveryFileKind::Jsx);
        assert!(scan
            .skipped
            .iter()
            .any(|skipped| matches!(skipped.reason, SkipReason::Generated(_))));
        assert!(scan
            .skipped
            .iter()
            .any(|skipped| matches!(skipped.reason, SkipReason::Binary)));
        assert!(scan
            .skipped
            .iter()
            .any(|skipped| matches!(skipped.reason, SkipReason::Minified(_))));
        assert!(scan.metadata.package_managers.contains("pnpm"));
        assert!(scan.metadata.react.detected());
        assert!(scan.metadata.fastapi.detected());
        assert_eq!(scan.metadata.rust.workspace_members, vec!["crates/*"]);
    }

    #[test]
    fn scanner_supports_include_exclude_size_and_language_filters() {
        let temp = tempfile::tempdir().expect("tempdir");
        write(temp.path().join("src/a.ts"), "export const a = 1;\n");
        write(temp.path().join("src/b.ts"), "export const b = 1;\n");
        write(temp.path().join("src/c.py"), "print('c')\n");

        let mut registry = LanguageRegistry::new();
        registry.register(TestAdapter);
        registry.register(PythonTestAdapter);

        let scan = scan_workspace(
            temp.path(),
            &registry,
            WorkspaceScanOptions {
                include: vec!["src/**".to_string()],
                exclude: vec!["src/b.ts".to_string()],
                max_file_size_bytes: 12,
                enabled_languages: vec!["typescript".to_string()],
                ..WorkspaceScanOptions::default()
            },
        )
        .expect("workspace scan");

        assert!(scan.files.is_empty());
        assert!(scan
            .skipped
            .iter()
            .any(|skipped| matches!(skipped.reason, SkipReason::TooLarge { .. })));
        assert!(scan
            .skipped
            .iter()
            .any(|skipped| matches!(skipped.reason, SkipReason::Excluded)));
        assert!(scan
            .skipped
            .iter()
            .any(|skipped| matches!(skipped.reason, SkipReason::LanguageDisabled(_))));
    }

    #[test]
    fn scanner_handles_many_files_deterministically() {
        let temp = tempfile::tempdir().expect("tempdir");
        for index in 0..1_000 {
            write(
                temp.path().join(format!("pkg/src/file_{index:04}.ts")),
                "export const value = 1;\n",
            );
        }

        let mut registry = LanguageRegistry::new();
        registry.register(TestAdapter);

        let scan = scan_workspace(
            temp.path(),
            &registry,
            WorkspaceScanOptions {
                enabled_languages: vec!["typescript".to_string()],
                ..WorkspaceScanOptions::default()
            },
        )
        .expect("workspace scan");

        assert_eq!(scan.files.len(), 1_000);
        assert!(relative_path(&scan.root, &scan.files[0].path).ends_with("file_0000.ts"));
        assert!(relative_path(&scan.root, &scan.files[999].path).ends_with("file_0999.ts"));
    }

    #[test]
    fn scanner_skips_symlinks_by_default_when_supported() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.ts");
        let link = temp.path().join("link.ts");
        write(target.clone(), "export const value = 1;\n");
        if create_file_symlink(&target, &link).is_err() {
            return;
        }

        let mut registry = LanguageRegistry::new();
        registry.register(TestAdapter);

        let scan = scan_workspace(
            temp.path(),
            &registry,
            WorkspaceScanOptions {
                enabled_languages: vec!["typescript".to_string()],
                ..WorkspaceScanOptions::default()
            },
        )
        .expect("workspace scan");

        assert_eq!(scan.files.len(), 1);
        assert!(scan
            .skipped
            .iter()
            .any(|skipped| matches!(skipped.reason, SkipReason::Symlink)));
    }

    fn write(path: PathBuf, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir");
        }
        fs::write(path, contents).expect("write fixture");
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
