use anyhow::{bail, Context};
use codehealth_core::{
    BaselineStatus, BaselineSummary, Confidence, Finding, FindingLocation, Severity,
};
use codehealth_duplication::normalize_source;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const BASELINE_SCHEMA_VERSION: &str = "1.0.0";
pub const DEFAULT_BASELINE_PATH: &str = ".codehealth/baseline.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingBaselineStatus {
    New,
    Existing,
    Changed,
    NotChecked,
}

impl FindingBaselineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Existing => "existing",
            Self::Changed => "changed",
            Self::NotChecked => "not_checked",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BaselineComparison {
    pub summary: BaselineSummary,
    pub new_keys: BTreeSet<String>,
    pub status_by_key: BTreeMap<String, FindingBaselineStatus>,
    pub fixed_entries: Vec<FixedBaselineEntry>,
    pub updated_entries: Vec<BaselineEntry>,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct FixedBaselineEntry {
    pub baseline_key: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub path: String,
    pub message: String,
    pub first_seen: u64,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineFile {
    pub schema_version: String,
    pub tool_version: String,
    pub workspace_root: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub config_hash: String,
    #[serde(default)]
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub baseline_key: String,
    pub rule_id: String,
    pub path: String,
    pub normalized_path: String,
    pub normalized_source_context_hash: String,
    #[serde(default)]
    pub related_locations: Vec<BaselineLocation>,
    pub first_seen: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub message: String,
    #[serde(default)]
    pub matching_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BaselineLocation {
    pub path: String,
    pub normalized_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_hash: Option<String>,
}

pub fn compare_findings(
    root: &Path,
    findings: &[Finding],
    baseline_path: Option<PathBuf>,
    owner: Option<&str>,
    _tool_version: &str,
    _config_hash: &str,
    treat_missing_as_empty: bool,
) -> anyhow::Result<BaselineComparison> {
    let now = unix_timestamp();
    let current_entries = findings
        .iter()
        .filter(|finding| !finding.is_suppressed)
        .map(|finding| entry_for_finding(root, finding, owner, now))
        .collect::<Vec<_>>();

    let Some(path) = baseline_path else {
        return Ok(BaselineComparison {
            summary: BaselineSummary::default(),
            new_keys: BTreeSet::new(),
            status_by_key: current_entries
                .iter()
                .map(|entry| {
                    (
                        entry.baseline_key.clone(),
                        FindingBaselineStatus::NotChecked,
                    )
                })
                .collect(),
            fixed_entries: Vec::new(),
            updated_entries: current_entries,
            path: None,
        });
    };

    if !path.exists() {
        let status_by_key = if treat_missing_as_empty {
            current_entries
                .iter()
                .map(|entry| (entry.baseline_key.clone(), FindingBaselineStatus::New))
                .collect()
        } else {
            current_entries
                .iter()
                .map(|entry| {
                    (
                        entry.baseline_key.clone(),
                        FindingBaselineStatus::NotChecked,
                    )
                })
                .collect()
        };
        let new_keys = if treat_missing_as_empty {
            current_entries
                .iter()
                .map(|entry| entry.baseline_key.clone())
                .collect()
        } else {
            BTreeSet::new()
        };
        return Ok(BaselineComparison {
            summary: BaselineSummary {
                status: BaselineStatus::Missing,
                path: Some(path.clone()),
                new_findings: treat_missing_as_empty.then_some(current_entries.len()),
                existing_findings: treat_missing_as_empty.then_some(0),
                changed_findings: treat_missing_as_empty.then_some(0),
                fixed_findings: treat_missing_as_empty.then_some(0),
            },
            new_keys,
            status_by_key,
            fixed_entries: Vec::new(),
            updated_entries: current_entries,
            path: Some(path),
        });
    }

    let baseline = read_baseline_file(&path, root)?;
    let matched = match_entries(&baseline.entries, current_entries);
    let summary = BaselineSummary {
        status: BaselineStatus::Compared,
        path: Some(path.clone()),
        new_findings: Some(matched.new_count),
        existing_findings: Some(matched.existing_count),
        changed_findings: Some(matched.changed_count),
        fixed_findings: Some(matched.fixed_entries.len()),
    };

    let mut updated_entries = matched.current_entries;
    updated_entries.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
            .then_with(|| left.path.cmp(&right.path))
    });

    Ok(BaselineComparison {
        summary,
        new_keys: matched.new_keys,
        status_by_key: matched.status_by_key,
        fixed_entries: matched.fixed_entries,
        updated_entries,
        path: Some(path),
    })
}

pub fn write_new_baseline(
    path: &Path,
    root: &Path,
    findings: &[Finding],
    owner: Option<&str>,
    tool_version: &str,
    config_hash: &str,
    force: bool,
) -> anyhow::Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; use --force-baseline to overwrite it",
            path.display()
        );
    }
    let now = unix_timestamp();
    let entries = findings
        .iter()
        .filter(|finding| !finding.is_suppressed)
        .map(|finding| entry_for_finding(root, finding, owner, now))
        .collect::<Vec<_>>();
    write_baseline_file(path, root, entries, tool_version, config_hash, now, now)
}

pub fn update_baseline(
    path: &Path,
    root: &Path,
    comparison: &BaselineComparison,
    tool_version: &str,
    config_hash: &str,
) -> anyhow::Result<()> {
    let created_at = if path.exists() {
        read_baseline_file(path, root)
            .map(|baseline| baseline.created_at)
            .unwrap_or_else(|_| unix_timestamp())
    } else {
        unix_timestamp()
    };
    write_baseline_file(
        path,
        root,
        comparison.updated_entries.clone(),
        tool_version,
        config_hash,
        created_at,
        unix_timestamp(),
    )
}

fn write_baseline_file(
    path: &Path,
    root: &Path,
    mut entries: Vec<BaselineEntry>,
    tool_version: &str,
    config_hash: &str,
    created_at: u64,
    updated_at: u64,
) -> anyhow::Result<()> {
    entries.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
            .then_with(|| left.path.cmp(&right.path))
    });
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    let file = BaselineFile {
        schema_version: BASELINE_SCHEMA_VERSION.to_string(),
        tool_version: tool_version.to_string(),
        workspace_root: root.to_string_lossy().replace('\\', "/"),
        created_at,
        updated_at,
        config_hash: config_hash.to_string(),
        entries,
    };
    let raw = serde_json::to_string_pretty(&file).context("failed to serialize baseline")?;
    std::fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))
}

fn read_baseline_file(path: &Path, root: &Path) -> anyhow::Result<BaselineFile> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse baseline {}", path.display()))?;

    if value.get("entries").is_some() {
        let mut file: BaselineFile = serde_json::from_value(value)
            .with_context(|| format!("failed to parse baseline {}", path.display()))?;
        for entry in &mut file.entries {
            normalize_entry(entry);
        }
        return Ok(file);
    }

    let findings = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .with_context(|| {
            format!(
                "baseline {} does not contain entries or findings",
                path.display()
            )
        })?;
    let now = unix_timestamp();
    let entries = findings
        .iter()
        .filter_map(|finding| legacy_entry_from_report_finding(root, finding, now))
        .collect::<Vec<_>>();
    Ok(BaselineFile {
        schema_version: BASELINE_SCHEMA_VERSION.to_string(),
        tool_version: value
            .get("toolVersion")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        workspace_root: value
            .get("workspaceRoot")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        created_at: now,
        updated_at: now,
        config_hash: value
            .get("configHash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        entries,
    })
}

#[derive(Debug)]
struct MatchResult {
    current_entries: Vec<BaselineEntry>,
    status_by_key: BTreeMap<String, FindingBaselineStatus>,
    new_keys: BTreeSet<String>,
    fixed_entries: Vec<FixedBaselineEntry>,
    new_count: usize,
    existing_count: usize,
    changed_count: usize,
}

fn match_entries(
    baseline_entries: &[BaselineEntry],
    current_entries: Vec<BaselineEntry>,
) -> MatchResult {
    let mut exact_index = BTreeMap::new();
    let mut key_index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, entry) in baseline_entries.iter().enumerate() {
        exact_index.insert(entry.fingerprint.clone(), index);
        for key in &entry.matching_keys {
            key_index.entry(key.clone()).or_default().push(index);
        }
    }

    let mut used_baseline = BTreeSet::new();
    let mut matched_entries = Vec::new();
    let mut status_by_key = BTreeMap::new();
    let mut new_keys = BTreeSet::new();
    let mut new_count = 0;
    let mut existing_count = 0;
    let mut changed_count = 0;

    for mut current in current_entries {
        let match_index = exact_index
            .get(&current.fingerprint)
            .copied()
            .filter(|index| !used_baseline.contains(index))
            .or_else(|| find_fuzzy_match(&current, &key_index, &used_baseline));

        if let Some(index) = match_index {
            used_baseline.insert(index);
            let baseline = &baseline_entries[index];
            let changed = entry_changed(baseline, &current);
            current.first_seen = baseline.first_seen;
            if baseline.owner.is_some() {
                current.owner = baseline.owner.clone();
            }
            let status = if changed {
                changed_count += 1;
                FindingBaselineStatus::Changed
            } else {
                existing_count += 1;
                FindingBaselineStatus::Existing
            };
            status_by_key.insert(current.baseline_key.clone(), status);
            matched_entries.push(current);
        } else {
            new_count += 1;
            new_keys.insert(current.baseline_key.clone());
            status_by_key.insert(current.baseline_key.clone(), FindingBaselineStatus::New);
            matched_entries.push(current);
        }
    }

    let fixed_entries = baseline_entries
        .iter()
        .enumerate()
        .filter(|(index, _)| !used_baseline.contains(index))
        .map(|(_, entry)| FixedBaselineEntry {
            baseline_key: entry.baseline_key.clone(),
            fingerprint: entry.fingerprint.clone(),
            rule_id: entry.rule_id.clone(),
            path: entry.path.clone(),
            message: entry.message.clone(),
            first_seen: entry.first_seen,
            owner: entry.owner.clone(),
        })
        .collect();

    MatchResult {
        current_entries: matched_entries,
        status_by_key,
        new_keys,
        fixed_entries,
        new_count,
        existing_count,
        changed_count,
    }
}

fn find_fuzzy_match(
    current: &BaselineEntry,
    key_index: &BTreeMap<String, Vec<usize>>,
    used_baseline: &BTreeSet<usize>,
) -> Option<usize> {
    current
        .matching_keys
        .iter()
        .filter(|key| {
            key.starts_with("legacy:")
                || key.contains("|content:")
                || key.contains("|route:")
                || key.contains("|context:")
                || key.contains("|group:")
        })
        .filter_map(|key| key_index.get(key))
        .flat_map(|indices| indices.iter().copied())
        .find(|index| !used_baseline.contains(index))
}

fn entry_changed(baseline: &BaselineEntry, current: &BaselineEntry) -> bool {
    baseline.path != current.path
        || baseline.related_locations != current.related_locations
        || baseline.message != current.message
        || baseline.severity != current.severity
        || baseline.confidence != current.confidence
}

fn entry_for_finding(
    root: &Path,
    finding: &Finding,
    owner: Option<&str>,
    first_seen: u64,
) -> BaselineEntry {
    let primary = finding.primary_location();
    let path = primary
        .map(|location| format_report_path(root, &location.path))
        .unwrap_or_default();
    let normalized_path = normalize_path_string(&path);
    let context_hash = primary
        .and_then(context_hash)
        .unwrap_or_else(|| "unknown".to_string());
    let related_locations = finding
        .locations
        .iter()
        .map(|location| baseline_location(root, location))
        .collect::<Vec<_>>();
    let semantic_key = semantic_key(finding, &context_hash);
    let fingerprint = stable_hash(&format!("{}|{semantic_key}", finding.rule_id));
    let matching_keys = matching_keys(
        finding,
        &fingerprint,
        &context_hash,
        &path,
        &related_locations,
    );

    BaselineEntry {
        fingerprint,
        baseline_key: finding.baseline_key.clone(),
        rule_id: finding.rule_id.clone(),
        path,
        normalized_path,
        normalized_source_context_hash: context_hash,
        related_locations,
        first_seen,
        owner: owner.map(str::to_string).filter(|value| !value.is_empty()),
        severity: finding.severity.to_string(),
        confidence: finding.confidence.to_string(),
        message: finding.message.clone(),
        matching_keys,
    }
}

fn semantic_key(finding: &Finding, context_hash: &str) -> String {
    metadata_string(finding, "semantic_hash")
        .map(|value| format!("content:{value}"))
        .or_else(|| {
            metadata_string(finding, "canonical_hash").map(|value| format!("content:{value}"))
        })
        .or_else(|| {
            metadata_string(finding, "vector_group_hash").map(|value| format!("content:{value}"))
        })
        .or_else(|| {
            metadata_string(finding, "near_group_hash").map(|value| format!("content:{value}"))
        })
        .or_else(|| {
            metadata_string(finding, "normalized_body_hash").map(|value| format!("content:{value}"))
        })
        .or_else(|| {
            metadata_string(finding, "normalized_file_hash").map(|value| format!("content:{value}"))
        })
        .or_else(|| metadata_string(finding, "route").map(|value| format!("route:{value}")))
        .unwrap_or_else(|| format!("legacy:{}|context:{context_hash}", finding.baseline_key))
}

fn matching_keys(
    finding: &Finding,
    fingerprint: &str,
    context_hash: &str,
    path: &str,
    related_locations: &[BaselineLocation],
) -> Vec<String> {
    let mut keys = BTreeSet::new();
    keys.insert(format!("fingerprint:{fingerprint}"));
    keys.insert(format!("legacy:{}", finding.baseline_key));
    keys.insert(format!("{}|context:{context_hash}", finding.rule_id));
    keys.insert(format!(
        "{}|path:{}|context:{context_hash}",
        finding.rule_id,
        normalize_path_string(path)
    ));
    if let Some(value) = metadata_string(finding, "semantic_hash")
        .or_else(|| metadata_string(finding, "canonical_hash"))
        .or_else(|| metadata_string(finding, "vector_group_hash"))
        .or_else(|| metadata_string(finding, "near_group_hash"))
        .or_else(|| metadata_string(finding, "normalized_body_hash"))
        .or_else(|| metadata_string(finding, "normalized_file_hash"))
    {
        keys.insert(format!("{}|content:{value}", finding.rule_id));
    }
    if let Some(route) = metadata_string(finding, "route") {
        keys.insert(format!("{}|route:{route}", finding.rule_id));
    }
    for name in metadata_string_array(finding, "qualified_names") {
        keys.insert(format!("{}|qualified:{name}", finding.rule_id));
    }
    let group_key = related_locations
        .iter()
        .filter_map(|location| location.context_hash.as_deref())
        .collect::<Vec<_>>()
        .join("|");
    if !group_key.is_empty() {
        keys.insert(format!("{}|group:{group_key}", finding.rule_id));
    }
    keys.into_iter().collect()
}

fn baseline_location(root: &Path, location: &FindingLocation) -> BaselineLocation {
    let path = format_report_path(root, &location.path);
    BaselineLocation {
        normalized_path: normalize_path_string(&path),
        path,
        line: location.start.map(|start| start.line),
        column: location.start.map(|start| start.column),
        context_hash: context_hash(location),
    }
}

fn context_hash(location: &FindingLocation) -> Option<String> {
    let source = std::fs::read_to_string(&location.path).ok()?;
    let context = if let Some(span) = location.span {
        if span.end <= source.len()
            && source.is_char_boundary(span.start)
            && source.is_char_boundary(span.end)
        {
            source[span.start..span.end].to_string()
        } else {
            String::new()
        }
    } else if let Some(start) = location.start {
        source
            .lines()
            .skip(start.line.saturating_sub(4))
            .take(7)
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        String::new()
    };
    let normalized = normalize_source(&context);
    (!normalized.is_empty()).then(|| stable_hash(&normalized))
}

fn legacy_entry_from_report_finding(
    root: &Path,
    finding: &serde_json::Value,
    first_seen: u64,
) -> Option<BaselineEntry> {
    let baseline_key = finding
        .get("baselineKey")
        .or_else(|| finding.get("baseline_key"))?
        .as_str()?
        .to_string();
    let rule_id = finding
        .get("ruleId")
        .or_else(|| finding.get("rule_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let locations = finding
        .get("locations")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let related_locations = locations
        .iter()
        .filter_map(|location| legacy_location(root, location))
        .collect::<Vec<_>>();
    let path = related_locations
        .first()
        .map(|location| location.path.clone())
        .unwrap_or_default();
    let normalized_source_context_hash = related_locations
        .first()
        .and_then(|location| location.context_hash.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let mut entry = BaselineEntry {
        fingerprint: stable_hash(&format!("{rule_id}|legacy:{baseline_key}")),
        baseline_key,
        rule_id,
        path: path.clone(),
        normalized_path: normalize_path_string(&path),
        normalized_source_context_hash,
        related_locations,
        first_seen,
        owner: None,
        severity: finding
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("info")
            .to_string(),
        confidence: finding
            .get("confidence")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("low")
            .to_string(),
        message: finding
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        matching_keys: Vec::new(),
    };
    normalize_entry(&mut entry);
    Some(entry)
}

fn legacy_location(root: &Path, value: &serde_json::Value) -> Option<BaselineLocation> {
    let raw_path = value.get("path")?.as_str()?;
    let path = normalize_report_path(root, Path::new(raw_path));
    Some(BaselineLocation {
        normalized_path: normalize_path_string(&path),
        path,
        line: value
            .get("line")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| value.try_into().ok()),
        column: value
            .get("column")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| value.try_into().ok()),
        context_hash: None,
    })
}

fn normalize_entry(entry: &mut BaselineEntry) {
    if entry.normalized_path.is_empty() {
        entry.normalized_path = normalize_path_string(&entry.path);
    }
    if entry.matching_keys.is_empty() {
        entry.matching_keys = vec![
            format!("fingerprint:{}", entry.fingerprint),
            format!("legacy:{}", entry.baseline_key),
        ];
    }
}

fn metadata_string(finding: &Finding, key: &str) -> Option<String> {
    finding
        .metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn metadata_string_array(finding: &Finding, key: &str) -> Vec<String> {
    finding
        .metadata
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn format_report_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn normalize_report_path(root: &Path, path: &Path) -> String {
    format_report_path(root, path)
}

fn normalize_path_string(path: &str) -> String {
    path.replace('\\', "/")
}

fn stable_hash(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    format!("{digest:x}")
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)]
fn _assert_status_strings_are_stable() {
    let _ = (Severity::High.to_string(), Confidence::Certain.to_string());
}
