use codehealth_core::{
    line_column_for_offset, slice_source, AutofixSafety, BaselineStatus, Finding, FindingKind,
    FindingLocation, Fix, FixApplicability, ScanResult, ScoreCategoryScore, Severity, SourceSpan,
};
use codehealth_rules::rule_catalog;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};
use thiserror::Error;

pub const JSON_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
    Sarif,
    Html,
    Markdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOptions {
    pub format: ReportFormat,
    pub use_color: bool,
}

impl ReportOptions {
    pub fn new(format: ReportFormat, use_color: bool) -> Self {
        Self { format, use_color }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportContext {
    pub tool_version: String,
    pub config_hash: String,
    pub timing: ReportTiming,
    pub new_finding_keys: BTreeSet<String>,
    pub baseline_status_by_key: BTreeMap<String, String>,
    pub fixed_findings: Vec<BaselineFixedFinding>,
}

impl Default for ReportContext {
    fn default() -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            config_hash: "unknown".to_string(),
            timing: ReportTiming::default(),
            new_finding_keys: BTreeSet::new(),
            baseline_status_by_key: BTreeMap::new(),
            fixed_findings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineFixedFinding {
    pub baseline_key: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub path: String,
    pub message: String,
    pub first_seen: u64,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportTiming {
    pub scan_ms: u64,
    pub report_ms: u64,
    pub total_ms: u64,
}

pub fn render_result(result: &ScanResult, options: ReportOptions) -> Result<String, ReporterError> {
    render_result_with_context(result, options, ReportContext::default())
}

pub fn render_result_with_context(
    result: &ScanResult,
    options: ReportOptions,
    mut context: ReportContext,
) -> Result<String, ReporterError> {
    let started = Instant::now();
    let _ = render_result_inner(result, options, &context)?;
    context.timing.report_ms = elapsed_millis(started.elapsed());
    context.timing.total_ms = context
        .timing
        .scan_ms
        .saturating_add(context.timing.report_ms);
    render_result_inner(result, options, &context)
}

fn render_result_inner(
    result: &ScanResult,
    options: ReportOptions,
    context: &ReportContext,
) -> Result<String, ReporterError> {
    match options.format {
        ReportFormat::Text => Ok(render_text(result, options.use_color, context)),
        ReportFormat::Json => serde_json::to_string_pretty(&build_report(result, context))
            .map_err(ReporterError::Json),
        ReportFormat::Sarif => render_sarif(result, context),
        ReportFormat::Html => render_html(result, context),
        ReportFormat::Markdown => Ok(render_markdown(result, context)),
    }
}

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportEnvelope {
    schema_version: &'static str,
    tool_version: String,
    config_hash: String,
    workspace_root: String,
    files_scanned: usize,
    score: ScoreReportDto,
    findings: Vec<FindingReport>,
    metrics: MetricsReport,
    timing: ReportTiming,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScoreReportDto {
    enabled: bool,
    overall: Option<u8>,
    categories: CategoryScoresDto,
    top_contributors: Vec<ScoreContributorDto>,
    model: ScoreModelDto,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CategoryScoresDto {
    duplication: CategoryScoreDto,
    complexity: CategoryScoreDto,
    style: CategoryScoreDto,
    react: CategoryScoreDto,
    fastapi: CategoryScoreDto,
    rust_idiom: CategoryScoreDto,
    maintainability: CategoryScoreDto,
    ci_risk: CategoryScoreDto,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CategoryScoreDto {
    score: Option<u8>,
    penalty: u8,
    findings: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScoreContributorDto {
    rule_id: String,
    message: String,
    category: String,
    penalty: u8,
    occurrences: usize,
    locations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScoreModelDto {
    version: String,
    base_score: u8,
    repeated_group_cap_multiplier: u8,
    generated_multiplier_percent: u8,
    test_fixture_multiplier_percent: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MetricsReport {
    files_discovered: usize,
    files_scanned: usize,
    files_skipped: usize,
    config_files: usize,
    files_parsed: usize,
    parse_errors: usize,
    definitions_indexed: usize,
    imports_indexed: usize,
    suppressed_findings: usize,
    lines_scanned: usize,
    duplicate_groups: usize,
    duplicate_lines: usize,
    largest_functions: Vec<DefinitionMetricDto>,
    largest_react_components: Vec<DefinitionMetricDto>,
    most_duplicated_modules: Vec<ModuleDuplicateMetricDto>,
    most_complex_functions: Vec<ComplexityMetricDto>,
    most_suppressed_rules: Vec<SuppressedRuleMetricDto>,
    baseline: BaselineDto,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DefinitionMetricDto {
    name: String,
    path: String,
    line: usize,
    lines: usize,
    language: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleDuplicateMetricDto {
    path: String,
    duplicate_findings: usize,
    duplicate_lines: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ComplexityMetricDto {
    name: String,
    path: String,
    line: usize,
    score: usize,
    lines: usize,
    language: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SuppressedRuleMetricDto {
    rule_id: String,
    count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineDto {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_findings: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    existing_findings: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed_findings: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_findings: Option<usize>,
    fixed: Vec<FixedFindingReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FixedFindingReport {
    baseline_key: String,
    fingerprint: String,
    rule_id: String,
    path: String,
    message: String,
    first_seen: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingReport {
    id: String,
    baseline_key: String,
    baseline_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_new: Option<bool>,
    rule_id: String,
    category: String,
    kind: String,
    severity: String,
    confidence: String,
    message: String,
    locations: Vec<LocationReport>,
    related_locations: Vec<LocationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    framework: Option<String>,
    explanation: String,
    remediation: String,
    detection_reason: String,
    autofix: String,
    autofix_explanation: String,
    fixes: Vec<FixReport>,
    metadata: BTreeMap<String, Value>,
    is_suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppression: Option<SuppressionReport>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LocationReport {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_end: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FixReport {
    title: String,
    safety: String,
    applicability: String,
    edits: Vec<EditReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EditReport {
    file: String,
    byte_start: usize,
    byte_end: usize,
    replacement: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SuppressionReport {
    rule_id: String,
    path: String,
    line: usize,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    warnings: Vec<String>,
}

fn build_report(result: &ScanResult, context: &ReportContext) -> ReportEnvelope {
    ReportEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        tool_version: context.tool_version.clone(),
        config_hash: context.config_hash.clone(),
        workspace_root: normalize_path(&result.root),
        files_scanned: result.stats.files_scanned,
        score: score_report(result),
        findings: result
            .findings
            .iter()
            .map(|finding| finding_report(result, finding, context, true))
            .collect(),
        metrics: metrics_report(result, context),
        timing: context.timing,
    }
}

fn score_report(result: &ScanResult) -> ScoreReportDto {
    ScoreReportDto {
        enabled: result.score.enabled,
        overall: result.score.overall,
        categories: CategoryScoresDto {
            duplication: category_score(&result.score.categories.duplication),
            complexity: category_score(&result.score.categories.complexity),
            style: category_score(&result.score.categories.style),
            react: category_score(&result.score.categories.react),
            fastapi: category_score(&result.score.categories.fastapi),
            rust_idiom: category_score(&result.score.categories.rust_idiom),
            maintainability: category_score(&result.score.categories.maintainability),
            ci_risk: category_score(&result.score.categories.ci_risk),
        },
        top_contributors: result
            .score
            .top_contributors
            .iter()
            .map(|contributor| ScoreContributorDto {
                rule_id: contributor.rule_id.clone(),
                message: contributor.message.clone(),
                category: contributor.category.clone(),
                penalty: contributor.penalty,
                occurrences: contributor.occurrences,
                locations: contributor
                    .locations
                    .iter()
                    .map(|path| format_report_path(&result.root, path))
                    .collect(),
            })
            .collect(),
        model: ScoreModelDto {
            version: result.score.model.version.clone(),
            base_score: result.score.model.base_score,
            repeated_group_cap_multiplier: result.score.model.repeated_group_cap_multiplier,
            generated_multiplier_percent: result.score.model.generated_multiplier_percent,
            test_fixture_multiplier_percent: result.score.model.test_fixture_multiplier_percent,
        },
    }
}

fn category_score(score: &ScoreCategoryScore) -> CategoryScoreDto {
    CategoryScoreDto {
        score: score.score,
        penalty: score.penalty,
        findings: score.findings,
    }
}

fn metrics_report(result: &ScanResult, context: &ReportContext) -> MetricsReport {
    MetricsReport {
        files_discovered: result.stats.files_discovered,
        files_scanned: result.stats.files_scanned,
        files_skipped: result.stats.files_skipped,
        config_files: result.stats.config_files,
        files_parsed: result.stats.files_parsed,
        parse_errors: result.stats.parse_errors,
        definitions_indexed: result.stats.definitions_indexed,
        imports_indexed: result.stats.imports_indexed,
        suppressed_findings: result.stats.suppressed_findings,
        lines_scanned: result.summary.lines_scanned,
        duplicate_groups: result.summary.duplicate_groups,
        duplicate_lines: result.summary.duplicate_lines,
        largest_functions: result
            .summary
            .largest_functions
            .iter()
            .map(|metric| DefinitionMetricDto {
                name: metric.name.clone(),
                path: format_report_path(&result.root, &metric.path),
                line: metric.line,
                lines: metric.lines,
                language: metric.language.clone(),
            })
            .collect(),
        largest_react_components: result
            .summary
            .largest_react_components
            .iter()
            .map(|metric| DefinitionMetricDto {
                name: metric.name.clone(),
                path: format_report_path(&result.root, &metric.path),
                line: metric.line,
                lines: metric.lines,
                language: metric.language.clone(),
            })
            .collect(),
        most_duplicated_modules: result
            .summary
            .most_duplicated_modules
            .iter()
            .map(|metric| ModuleDuplicateMetricDto {
                path: format_report_path(&result.root, &metric.path),
                duplicate_findings: metric.duplicate_findings,
                duplicate_lines: metric.duplicate_lines,
            })
            .collect(),
        most_complex_functions: result
            .summary
            .most_complex_functions
            .iter()
            .map(|metric| ComplexityMetricDto {
                name: metric.name.clone(),
                path: format_report_path(&result.root, &metric.path),
                line: metric.line,
                score: metric.score,
                lines: metric.lines,
                language: metric.language.clone(),
            })
            .collect(),
        most_suppressed_rules: result
            .summary
            .most_suppressed_rules
            .iter()
            .map(|metric| SuppressedRuleMetricDto {
                rule_id: metric.rule_id.clone(),
                count: metric.count,
            })
            .collect(),
        baseline: BaselineDto {
            status: baseline_status_value(result.summary.baseline.status).to_string(),
            path: result
                .summary
                .baseline
                .path
                .as_ref()
                .map(|path| format_report_path(&result.root, path)),
            new_findings: result.summary.baseline.new_findings,
            existing_findings: result.summary.baseline.existing_findings,
            changed_findings: result.summary.baseline.changed_findings,
            fixed_findings: result.summary.baseline.fixed_findings,
            fixed: context
                .fixed_findings
                .iter()
                .map(|entry| FixedFindingReport {
                    baseline_key: entry.baseline_key.clone(),
                    fingerprint: entry.fingerprint.clone(),
                    rule_id: entry.rule_id.clone(),
                    path: entry.path.clone(),
                    message: entry.message.clone(),
                    first_seen: entry.first_seen,
                    owner: entry.owner.clone(),
                })
                .collect(),
        },
    }
}

fn finding_report(
    result: &ScanResult,
    finding: &Finding,
    context: &ReportContext,
    include_snippets: bool,
) -> FindingReport {
    let locations = finding
        .locations
        .iter()
        .map(|location| location_report(&result.root, location, include_snippets))
        .collect::<Vec<_>>();
    let baseline_status = baseline_status_for(context, finding);

    FindingReport {
        id: finding.finding_id.clone(),
        baseline_key: finding.baseline_key.clone(),
        baseline_status: baseline_status.to_string(),
        is_new: (baseline_status != "not_checked").then_some(baseline_status == "new"),
        rule_id: finding.rule_id.clone(),
        category: category_value(finding).to_string(),
        kind: kind_value(finding.kind).to_string(),
        severity: finding.severity.to_string(),
        confidence: finding.confidence.to_string(),
        message: finding.message.clone(),
        related_locations: locations.iter().skip(1).cloned().collect(),
        locations,
        duplicate_group: duplicate_group_key(finding),
        language: finding.language.clone(),
        framework: finding.framework.clone(),
        explanation: finding.explanation.clone(),
        remediation: finding.remediation.clone(),
        detection_reason: finding.detection_reason.clone(),
        autofix: autofix_value(finding.autofix).to_string(),
        autofix_explanation: finding.autofix_explanation.clone(),
        fixes: finding
            .fixes
            .iter()
            .map(|fix| fix_report(result, fix))
            .collect(),
        metadata: finding.metadata.clone(),
        is_suppressed: finding.is_suppressed,
        suppression: finding
            .suppression
            .as_ref()
            .map(|suppression| SuppressionReport {
                rule_id: suppression.rule_id.clone(),
                path: format_report_path(&result.root, &suppression.path),
                line: suppression.line,
                kind: format!("{:?}", suppression.kind).to_ascii_lowercase(),
                reason: suppression.reason.clone(),
                warnings: suppression.warnings.clone(),
            }),
    }
}

fn location_report(
    root: &Path,
    location: &FindingLocation,
    include_snippet: bool,
) -> LocationReport {
    let source = if include_snippet || location.span.is_some() {
        std::fs::read_to_string(&location.path).ok()
    } else {
        None
    };
    let computed_start = location.span.and_then(|span| {
        source
            .as_deref()
            .and_then(|source| line_column_for_offset(source, span.start).ok())
    });
    let start = location.start.or(computed_start);
    let end = location.span.and_then(|span| {
        source
            .as_deref()
            .and_then(|source| line_column_for_offset(source, span.end).ok())
    });

    LocationReport {
        path: format_report_path(root, &location.path),
        line: start.map(|location| location.line),
        column: start.map(|location| location.column),
        end_line: end.map(|location| location.line),
        end_column: end.map(|location| location.column),
        byte_start: location.span.map(|span| span.start),
        byte_end: location.span.map(|span| span.end),
        language: location.language.clone(),
        snippet: include_snippet
            .then(|| source_snippet(source.as_deref(), location.span))
            .flatten(),
    }
}

fn fix_report(result: &ScanResult, fix: &Fix) -> FixReport {
    FixReport {
        title: fix.title.clone(),
        safety: autofix_value(fix.safety).to_string(),
        applicability: applicability_value(fix.applicability).to_string(),
        edits: fix
            .edits
            .iter()
            .map(|edit| EditReport {
                file: format_report_path(&result.root, &edit.file),
                byte_start: edit.span.start,
                byte_end: edit.span.end,
                replacement: edit.replacement.clone(),
            })
            .collect(),
    }
}

fn source_snippet(source: Option<&str>, span: Option<SourceSpan>) -> Option<String> {
    let source = source?;
    let span = span?;
    if span.is_empty() {
        return None;
    }
    let snippet = slice_source(source, span).ok()?.trim_end();
    if snippet.is_empty() {
        return None;
    }

    let mut lines = snippet.lines().take(12).collect::<Vec<_>>().join("\n");
    if snippet.lines().count() > 12 {
        lines.push_str("\n...");
    }
    if lines.len() > 2_000 {
        lines.truncate(2_000);
        lines.push_str("...");
    }
    Some(lines)
}

fn render_text(result: &ScanResult, use_color: bool, context: &ReportContext) -> String {
    let mut output = String::new();
    output.push_str("Code Health Report\n\n");
    output.push_str(&format!("Score: {}\n", score_text(result)));
    output.push_str(&format!(
        "Category scores: {}\n",
        category_scores_text(result)
    ));
    output.push_str(&format!("Files scanned: {}\n", result.stats.files_scanned));
    output.push_str(&format!(
        "Lines scanned: {}\n",
        result.summary.lines_scanned
    ));
    if result.stats.files_discovered > result.stats.files_scanned {
        output.push_str(&format!(
            "Files discovered: {}\n",
            result.stats.files_discovered
        ));
    }
    if result.stats.files_skipped > 0 {
        output.push_str(&format!("Files skipped: {}\n", result.stats.files_skipped));
    }
    if result.stats.config_files > 0 {
        output.push_str(&format!("Config files: {}\n", result.stats.config_files));
    }
    if result.stats.files_parsed > 0 {
        output.push_str(&format!("Files parsed: {}\n", result.stats.files_parsed));
    }
    if result.stats.parse_errors > 0 {
        output.push_str(&format!("Parse errors: {}\n", result.stats.parse_errors));
    }
    output.push_str(&format!(
        "Definitions indexed: {}\n",
        result.stats.definitions_indexed
    ));
    output.push_str(&format!(
        "Imports indexed: {}\n",
        result.stats.imports_indexed
    ));
    output.push_str(&format!("Findings: {}\n", result.findings.len()));
    output.push_str(&format!(
        "Suppressed findings: {}\n",
        result.stats.suppressed_findings
    ));
    output.push_str(&format!(
        "Duplicate groups: {}\n",
        result.summary.duplicate_groups
    ));
    output.push_str(&format!(
        "Duplicate lines: {}\n",
        result.summary.duplicate_lines
    ));
    output.push_str(&format!("Baseline: {}\n", baseline_text(result)));
    if let Some(new_findings) = result.summary.baseline.new_findings {
        output.push_str(&format!("New findings: {new_findings}\n"));
    }
    if let Some(existing) = result.summary.baseline.existing_findings {
        output.push_str(&format!("Existing findings: {existing}\n"));
    }
    if let Some(changed) = result.summary.baseline.changed_findings {
        output.push_str(&format!("Changed findings: {changed}\n"));
    }
    if let Some(fixed) = result.summary.baseline.fixed_findings {
        output.push_str(&format!("Fixed findings: {fixed}\n"));
    }

    push_top_contributors(&mut output, result);
    push_summary_metrics(&mut output, result);

    if result.findings.is_empty() {
        output.push('\n');
        return output;
    }

    output.push_str("\nFindings by severity\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let findings = result
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .collect::<Vec<_>>();
        if findings.is_empty() {
            continue;
        }

        output.push('\n');
        output.push_str(&format!(
            "{} ({})\n",
            color_severity(severity, use_color),
            findings.len()
        ));

        for group in duplicate_grouped_findings(&findings).into_values() {
            if group.len() > 1 || group[0].locations.len() > 1 {
                output.push_str(&format!(
                    "  Duplicate group: {} locations\n",
                    group
                        .iter()
                        .map(|finding| finding.locations.len())
                        .sum::<usize>()
                ));
            }
            for finding in group {
                push_text_finding(&mut output, result, finding, use_color, context);
            }
        }
    }

    if !context.fixed_findings.is_empty() {
        output.push_str("\nFixed findings\n");
        for fixed in &context.fixed_findings {
            output.push_str(&format!(
                "  FIXED  {}  {}  {}\n",
                fixed.rule_id, fixed.path, fixed.message
            ));
        }
    }

    output
}

fn push_top_contributors(output: &mut String, result: &ScanResult) {
    if result.score.top_contributors.is_empty() {
        return;
    }

    output.push_str("Top score contributors:\n");
    for contributor in &result.score.top_contributors {
        let locations = contributor
            .locations
            .iter()
            .map(|path| format_report_path(&result.root, path))
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "  -{}  {}  {}{}{}\n",
            contributor.penalty,
            contributor.rule_id,
            contributor.message,
            if contributor.occurrences > 1 {
                format!(" ({})", contributor.occurrences)
            } else {
                String::new()
            },
            if locations.is_empty() {
                String::new()
            } else {
                format!("  [{locations}]")
            }
        ));
    }
}

fn push_summary_metrics(output: &mut String, result: &ScanResult) {
    if !result.summary.largest_functions.is_empty() {
        output.push_str("Largest functions:\n");
        for metric in &result.summary.largest_functions {
            output.push_str(&format!(
                "  {}  {}:{}  {} lines\n",
                metric.name,
                format_report_path(&result.root, &metric.path),
                metric.line,
                metric.lines
            ));
        }
    }

    if !result.summary.largest_react_components.is_empty() {
        output.push_str("Largest React components:\n");
        for metric in &result.summary.largest_react_components {
            output.push_str(&format!(
                "  {}  {}:{}  {} lines\n",
                metric.name,
                format_report_path(&result.root, &metric.path),
                metric.line,
                metric.lines
            ));
        }
    }

    if !result.summary.most_duplicated_modules.is_empty() {
        output.push_str("Most duplicated modules:\n");
        for metric in &result.summary.most_duplicated_modules {
            output.push_str(&format!(
                "  {}  {} findings, {} lines\n",
                format_report_path(&result.root, &metric.path),
                metric.duplicate_findings,
                metric.duplicate_lines
            ));
        }
    }

    if !result.summary.most_complex_functions.is_empty() {
        output.push_str("Most complex functions:\n");
        for metric in &result.summary.most_complex_functions {
            output.push_str(&format!(
                "  {}  {}:{}  complexity {}, {} lines\n",
                metric.name,
                format_report_path(&result.root, &metric.path),
                metric.line,
                metric.score,
                metric.lines
            ));
        }
    }

    if !result.summary.most_suppressed_rules.is_empty() {
        output.push_str("Most suppressed rules:\n");
        for metric in &result.summary.most_suppressed_rules {
            output.push_str(&format!("  {}  {}\n", metric.rule_id, metric.count));
        }
    }
}

fn duplicate_grouped_findings<'a>(findings: &[&'a Finding]) -> BTreeMap<String, Vec<&'a Finding>> {
    let mut groups = BTreeMap::new();
    for finding in findings {
        groups
            .entry(
                duplicate_group_key(finding)
                    .unwrap_or_else(|| format!("{}|{}", finding.rule_id, finding.finding_id)),
            )
            .or_insert_with(Vec::new)
            .push(*finding);
    }
    groups
}

fn push_text_finding(
    output: &mut String,
    result: &ScanResult,
    finding: &Finding,
    use_color: bool,
    context: &ReportContext,
) {
    output.push_str(&format!(
        "  {}  {}{}\n",
        color_severity(finding.severity, use_color),
        finding.rule_id,
        if finding.is_suppressed {
            "  (suppressed)"
        } else {
            ""
        }
    ));
    output.push_str(&format!("    Confidence: {}\n", finding.confidence));
    output.push_str(&format!(
        "    Baseline status: {}\n",
        baseline_status_for(context, finding)
    ));
    output.push_str(&format!("    Message: {}\n", finding.message));

    for location in &finding.locations {
        output.push_str(&format!(
            "    {}\n",
            format_location(&result.root, location)
        ));
    }

    for line in metadata_lines(finding) {
        output.push_str(&format!("    {line}\n"));
    }
    output.push_str(&format!("    Explanation: {}\n", finding.explanation));
    output.push_str(&format!("    Remediation: {}\n", finding.remediation));
    output.push_str(&format!("    Why detected: {}\n", finding.detection_reason));
    output.push_str(&format!(
        "    Autofix: {}\n",
        autofix_text(finding.autofix, &finding.autofix_explanation)
    ));
    if !finding.fixes.is_empty() {
        for fix in &finding.fixes {
            output.push_str(&format!(
                "    Fix: {} ({} edits, {})\n",
                fix.title,
                fix.edits.len(),
                autofix_value(fix.safety)
            ));
        }
    }
    if let Some(suppression) = &finding.suppression {
        let reason = suppression.reason.as_deref().unwrap_or("missing reason");
        output.push_str(&format!(
            "    Suppressed by: {}:{} ({reason})\n",
            format_report_path(&result.root, &suppression.path),
            suppression.line
        ));
        for warning in &suppression.warnings {
            output.push_str(&format!("    Suppression warning: {warning}\n"));
        }
    } else {
        output.push_str(&format!("    Suppress: {}\n", suppression_hint(finding)));
    }
}

fn metadata_lines(finding: &Finding) -> Vec<String> {
    if finding.rule_id == "duplicate.exact.body" {
        let body_size = metadata_usize(finding, "body_size_bytes");
        let line_count = metadata_usize(finding, "line_count");
        let token_estimate = metadata_usize(finding, "token_estimate");
        let names = metadata_string_array(finding, "symbol_names");
        let names_differ = metadata_bool(finding, "names_differ");
        let signatures_differ = metadata_bool(finding, "signatures_differ");
        let mut lines = Vec::new();
        if !names.is_empty() {
            lines.push(format!("Symbols: {}", names.join(", ")));
        }
        if let (Some(body_size), Some(line_count), Some(token_estimate)) =
            (body_size, line_count, token_estimate)
        {
            lines.push(format!(
                "Body: {body_size} bytes, {line_count} lines, ~{token_estimate} tokens"
            ));
        }
        if let (Some(names_differ), Some(signatures_differ)) = (names_differ, signatures_differ) {
            lines.push(format!(
                "Names differ: {names_differ}; signatures differ: {signatures_differ}"
            ));
        }
        return lines;
    }

    if finding.rule_id == "duplicate.structural.function" {
        let hash = finding
            .metadata
            .get("canonical_hash")
            .and_then(|value| value.as_str())
            .map(|value| value.chars().take(12).collect::<String>());
        let node_count = metadata_usize(finding, "node_count");
        let opaque_node_count = metadata_usize(finding, "opaque_node_count");
        let names = metadata_string_array(finding, "symbol_names");
        let names_differ = metadata_bool(finding, "names_differ");
        let domain_warning = metadata_bool(finding, "domain_warning");
        let mut lines = Vec::new();
        if !names.is_empty() {
            lines.push(format!("Symbols: {}", names.join(", ")));
        }
        if let Some(hash) = hash {
            lines.push(format!("Canonical hash: {hash}"));
        }
        if let (Some(node_count), Some(opaque_node_count)) = (node_count, opaque_node_count) {
            lines.push(format!(
                "Canonical AST: {node_count} nodes, {opaque_node_count} opaque"
            ));
        }
        if let Some(names_differ) = names_differ {
            lines.push(format!("Names differ: {names_differ}"));
        }
        if domain_warning == Some(true) {
            lines.push(
                "Domain warning: same shape can still represent intentionally separate behavior"
                    .to_string(),
            );
        }
        return lines;
    }

    if finding.rule_id == "duplicate.near.function" {
        let similarity = metadata_usize(finding, "similarity_percent");
        let names = metadata_string_array(finding, "symbol_names");
        let signals = metadata_string_array(finding, "signals");
        let skipped_buckets = metadata_usize(finding, "skipped_large_buckets");
        let candidate_limit_reached = metadata_bool(finding, "candidate_limit_reached");
        let mut lines = Vec::new();
        if !names.is_empty() {
            lines.push(format!("Symbols: {}", names.join(", ")));
        }
        if let Some(similarity) = similarity {
            lines.push(format!("Similarity: {similarity}%"));
        }
        if !signals.is_empty() {
            lines.push(format!("Signals: {}", signals.join(", ")));
        }
        if skipped_buckets.unwrap_or(0) > 0 || candidate_limit_reached == Some(true) {
            lines.push(format!(
                "Search limits: skipped large buckets: {}; candidate limit reached: {}",
                skipped_buckets.unwrap_or(0),
                candidate_limit_reached.unwrap_or(false)
            ));
        }
        return lines;
    }

    if finding.rule_id == "duplicate.semantic.function" {
        let hash = finding
            .metadata
            .get("semantic_hash")
            .and_then(|value| value.as_str())
            .map(|value| value.chars().take(12).collect::<String>());
        let names = metadata_string_array(finding, "symbol_names");
        let rewrites = metadata_string_array(finding, "semantic_rewrites");
        let warnings = metadata_string_array(finding, "safety_warnings");
        let evidence = metadata_string_array(finding, "type_evidence");
        let mut lines = Vec::new();
        if !names.is_empty() {
            lines.push(format!("Symbols: {}", names.join(", ")));
        }
        if let Some(hash) = hash {
            lines.push(format!("Semantic hash: {hash}"));
        }
        if !rewrites.is_empty() {
            lines.push(format!("Semantic rewrites: {}", rewrites.join(", ")));
        }
        if !evidence.is_empty() {
            lines.push(format!("Type evidence: {}", evidence.join(", ")));
        }
        if !warnings.is_empty() {
            lines.push(format!("Caveats: {}", warnings.join("; ")));
        }
        return lines;
    }

    if finding.rule_id == "duplicate.semantic.vector_candidate" {
        let vector_score = metadata_usize(finding, "vector_score");
        let rank_score = metadata_usize(finding, "rank_score");
        let names = metadata_string_array(finding, "symbol_names");
        let signals = metadata_string_array(finding, "deterministic_signals");
        let provider = finding
            .metadata
            .get("embedding_provider")
            .and_then(|value| value.as_str());
        let privacy = finding
            .metadata
            .get("privacy_mode")
            .and_then(|value| value.as_str());
        let mut lines = Vec::new();
        if !names.is_empty() {
            lines.push(format!("Symbols: {}", names.join(", ")));
        }
        if let (Some(provider), Some(privacy)) = (provider, privacy) {
            lines.push(format!(
                "Embedding provider: {provider}; privacy: {privacy}"
            ));
        }
        if let (Some(vector_score), Some(rank_score)) = (vector_score, rank_score) {
            lines.push(format!(
                "Vector score: {vector_score}%; rank score: {rank_score}%"
            ));
        }
        if !signals.is_empty() {
            lines.push(format!("Deterministic signals: {}", signals.join(", ")));
        }
        return lines;
    }

    if finding.kind == FindingKind::DuplicateName {
        if let (Some(scope), Some(score)) = (
            finding
                .metadata
                .get("scope")
                .and_then(|value| value.as_str()),
            metadata_usize(finding, "score"),
        ) {
            return vec![format!("Scope: {scope}; duplicate-name score: {score}")];
        }
    }

    if finding.rule_id == "fastapi.duplicate.route" {
        if let Some(route) = finding
            .metadata
            .get("route")
            .and_then(|value| value.as_str())
        {
            return vec![format!("Route: {route}")];
        }
    }

    Vec::new()
}

fn score_text(result: &ScanResult) -> String {
    result
        .score
        .overall
        .map(|score| format!("{score}/100"))
        .unwrap_or_else(|| "disabled".to_string())
}

fn category_scores_text(result: &ScanResult) -> String {
    [
        ("duplication", &result.score.categories.duplication),
        ("complexity", &result.score.categories.complexity),
        ("style", &result.score.categories.style),
        ("react", &result.score.categories.react),
        ("fastapi", &result.score.categories.fastapi),
        ("rust", &result.score.categories.rust_idiom),
        ("maintainability", &result.score.categories.maintainability),
        ("ci", &result.score.categories.ci_risk),
    ]
    .into_iter()
    .map(|(label, score)| format!("{label} {}", category_score_text(score)))
    .collect::<Vec<_>>()
    .join(", ")
}

fn category_score_text(score: &ScoreCategoryScore) -> String {
    score
        .score
        .map(|value| format!("{value}/100"))
        .unwrap_or_else(|| "disabled".to_string())
}

fn baseline_text(result: &ScanResult) -> String {
    match result.summary.baseline.status {
        BaselineStatus::NotChecked => "not checked".to_string(),
        BaselineStatus::Missing => result
            .summary
            .baseline
            .path
            .as_ref()
            .map(|path| format!("unavailable ({})", format_report_path(&result.root, path)))
            .unwrap_or_else(|| "unavailable".to_string()),
        BaselineStatus::Compared => format!(
            "{} new findings compared with {}",
            result.summary.baseline.new_findings.unwrap_or(0),
            result
                .summary
                .baseline
                .path
                .as_ref()
                .map(|path| format_report_path(&result.root, path))
                .unwrap_or_else(|| "baseline".to_string())
        ),
    }
}

fn metadata_usize(finding: &Finding, key: &str) -> Option<usize> {
    finding
        .metadata
        .get(key)?
        .as_u64()
        .and_then(|value| value.try_into().ok())
}

fn metadata_bool(finding: &Finding, key: &str) -> Option<bool> {
    finding.metadata.get(key)?.as_bool()
}

fn metadata_string_array(finding: &Finding, key: &str) -> Vec<String> {
    finding
        .metadata
        .get(key)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn color_severity(severity: Severity, use_color: bool) -> String {
    let label = severity.label();
    if !use_color {
        return label.to_string();
    }

    let code = match severity {
        Severity::Critical => "\x1b[1;91m",
        Severity::High => "\x1b[31m",
        Severity::Medium => "\x1b[33m",
        Severity::Low => "\x1b[34m",
        Severity::Info => "\x1b[2;36m",
    };

    format!("{code}{label}\x1b[0m")
}

fn format_location(root: &Path, location: &FindingLocation) -> String {
    let path = format_report_path(root, &location.path);
    let mut rendered = if let Some(start) = location.start {
        format!("{path}:{}:{}", start.line, start.column)
    } else {
        path
    };

    if let Some(span) = location.span {
        rendered.push_str(&format!(" [bytes {}..{}]", span.start, span.end));
    }

    rendered
}

fn format_report_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn autofix_text(safety: AutofixSafety, explanation: &str) -> String {
    match safety {
        AutofixSafety::Unavailable => format!("Not available. {explanation}"),
        AutofixSafety::SuggestionOnly => format!("Suggestion only. {explanation}"),
        AutofixSafety::Safe => format!("Safe autofix available. {explanation}"),
    }
}

fn suppression_hint(finding: &Finding) -> String {
    let prefix = if finding
        .language
        .as_deref()
        .is_some_and(|language| language.eq_ignore_ascii_case("python"))
    {
        "#"
    } else {
        "//"
    };
    format!(
        "{prefix} codehealth-ignore-next-line {} -- reason",
        finding.rule_id
    )
}

fn render_sarif(result: &ScanResult, context: &ReportContext) -> Result<String, ReporterError> {
    let rules = sarif_rules(result);
    let results = result
        .findings
        .iter()
        .map(|finding| sarif_result(result, finding, context))
        .collect::<Vec<_>>();

    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "codehealth",
                    "version": &context.tool_version,
                    "informationUri": "https://github.com/m-de-graaff/codehealth",
                    "rules": rules,
                }
            },
            "originalUriBaseIds": {
                "SRCROOT": {
                    "uri": path_to_file_uri(&result.root)
                }
            },
            "results": results,
            "properties": {
                "schemaVersion": JSON_SCHEMA_VERSION,
                "configHash": &context.config_hash,
                "score": score_report(result),
                "metrics": metrics_report(result, context),
                "timing": context.timing,
            },
        }]
    }))
    .map_err(ReporterError::Json)
}

fn sarif_rules(result: &ScanResult) -> Vec<Value> {
    let catalog = rule_catalog()
        .into_iter()
        .map(|rule| (rule.code.to_string(), rule))
        .collect::<BTreeMap<_, _>>();
    let rule_ids = result
        .findings
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect::<BTreeSet<_>>();
    if rule_ids.is_empty() {
        return Vec::new();
    }

    rule_ids
        .iter()
        .map(|rule_id| {
            if let Some(rule) = catalog.get(rule_id) {
                json!({
                    "id": rule.code,
                    "name": rule.name,
                    "shortDescription": { "text": rule.name },
                    "fullDescription": { "text": rule.explanation },
                    "help": {
                        "text": rule.remediation,
                        "markdown": format!("{}\n\n{}", rule.explanation, rule.remediation),
                    },
                    "defaultConfiguration": {
                        "level": sarif_level(rule.default_severity),
                    },
                    "properties": {
                        "category": kind_value(rule.kind),
                        "defaultSeverity": rule.default_severity.to_string(),
                        "defaultConfidence": rule.default_confidence.to_string(),
                        "implemented": rule.implemented,
                        "language": rule.language,
                        "framework": rule.framework,
                    }
                })
            } else {
                let representative = result
                    .findings
                    .iter()
                    .find(|finding| finding.rule_id == *rule_id)
                    .expect("rule id came from findings");
                json!({
                    "id": &representative.rule_id,
                    "name": &representative.rule_id,
                    "shortDescription": { "text": &representative.message },
                    "fullDescription": { "text": &representative.explanation },
                    "help": { "text": &representative.remediation },
                    "defaultConfiguration": {
                        "level": sarif_level(representative.severity),
                    },
                })
            }
        })
        .collect()
}

fn sarif_result(result: &ScanResult, finding: &Finding, context: &ReportContext) -> Value {
    let baseline_status = baseline_status_for(context, finding);
    let primary = finding
        .locations
        .first()
        .map(|location| sarif_location(&result.root, location))
        .into_iter()
        .collect::<Vec<_>>();
    let related_locations = finding
        .locations
        .iter()
        .skip(1)
        .enumerate()
        .map(|(index, location)| {
            json!({
                "id": index + 1,
                "message": { "text": "Related duplicate location" },
                "physicalLocation": sarif_physical_location(&result.root, location),
            })
        })
        .collect::<Vec<_>>();

    let mut object = Map::new();
    object.insert("ruleId".to_string(), json!(&finding.rule_id));
    object.insert("level".to_string(), json!(sarif_level(finding.severity)));
    object.insert("message".to_string(), json!({ "text": &finding.message }));
    object.insert("locations".to_string(), json!(primary));
    object.insert(
        "partialFingerprints".to_string(),
        json!({ "codehealth/baselineKey": &finding.baseline_key }),
    );
    object.insert(
        "properties".to_string(),
        json!({
            "findingId": &finding.finding_id,
            "category": category_value(finding),
            "kind": kind_value(finding.kind),
            "confidence": finding.confidence.to_string(),
            "isSuppressed": finding.is_suppressed,
            "baselineStatus": baseline_status,
            "isNew": baseline_status == "new",
            "duplicateGroup": duplicate_group_key(finding),
            "metadata": &finding.metadata,
        }),
    );
    if !related_locations.is_empty() {
        object.insert("relatedLocations".to_string(), json!(related_locations));
    }
    let fixes = sarif_fixes(&result.root, finding);
    if !fixes.is_empty() {
        object.insert("fixes".to_string(), json!(fixes));
    }

    Value::Object(object)
}

fn sarif_fixes(root: &Path, finding: &Finding) -> Vec<Value> {
    finding
        .fixes
        .iter()
        .filter(|fix| fix.safety == AutofixSafety::Safe)
        .map(|fix| {
            let mut changes: BTreeMap<String, Vec<Value>> = BTreeMap::new();
            for edit in &fix.edits {
                let source = std::fs::read_to_string(&edit.file).unwrap_or_default();
                let start = line_column_for_offset(&source, edit.span.start).ok();
                let end = line_column_for_offset(&source, edit.span.end).ok();
                changes
                    .entry(format_report_path(root, &edit.file))
                    .or_default()
                    .push(json!({
                        "deletedRegion": {
                            "startLine": start.map(|location| location.line).unwrap_or(1),
                            "startColumn": start.map(|location| location.column).unwrap_or(1),
                            "endLine": end.map(|location| location.line).unwrap_or(1),
                            "endColumn": end.map(|location| location.column).unwrap_or(1),
                        },
                        "insertedContent": {
                            "text": &edit.replacement,
                        }
                    }));
            }
            let artifact_changes = changes
                .into_iter()
                .map(|(uri, replacements)| {
                    json!({
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "SRCROOT",
                        },
                        "replacements": replacements,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "description": { "text": &fix.title },
                "artifactChanges": artifact_changes,
            })
        })
        .collect()
}

fn sarif_location(root: &Path, location: &FindingLocation) -> Value {
    json!({
        "physicalLocation": sarif_physical_location(root, location)
    })
}

fn sarif_physical_location(root: &Path, location: &FindingLocation) -> Value {
    let report = location_report(root, location, false);
    let mut region = Map::new();
    region.insert("startLine".to_string(), json!(report.line.unwrap_or(1)));
    region.insert("startColumn".to_string(), json!(report.column.unwrap_or(1)));
    if let Some(end_line) = report.end_line {
        region.insert("endLine".to_string(), json!(end_line));
    }
    if let Some(end_column) = report.end_column {
        region.insert("endColumn".to_string(), json!(end_column));
    }

    json!({
        "artifactLocation": {
            "uri": format_report_path(root, &location.path),
            "uriBaseId": "SRCROOT",
        },
        "region": Value::Object(region),
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn path_to_file_uri(path: &Path) -> String {
    let normalized = normalize_path(path);
    if normalized.starts_with('/') {
        format!("file://{normalized}/")
    } else {
        format!("file:///{normalized}/")
    }
}

fn render_html(result: &ScanResult, context: &ReportContext) -> Result<String, ReporterError> {
    let report = build_report(result, context);
    let report_json = serde_json::to_string(&report)
        .map_err(ReporterError::Json)?
        .replace("</", "<\\/");
    let mut output = String::new();
    output.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    output.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    output.push_str("<title>Code Health Report</title>");
    output.push_str("<style>");
    output.push_str("body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;color:#18202a;background:#f6f7f9}main{max-width:1120px;margin:0 auto;padding:28px}h1{margin:0 0 6px}h2{margin:0 0 10px}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:18px 0}.metric,.finding,.filters{background:#fff;border:1px solid #d8dee8;border-radius:8px;padding:14px}.metric strong{display:block;font-size:12px;color:#5c6675;text-transform:uppercase}.metric span{font-size:22px;font-weight:650}.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}.filters label{font-size:12px;color:#5c6675}.filters select,.filters input{width:100%;box-sizing:border-box;margin-top:4px;padding:8px;border:1px solid #c8d0dc;border-radius:6px;background:#fff}.finding{margin:10px 0}.finding header{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.badge{border-radius:999px;padding:2px 8px;font-size:12px;font-weight:650;background:#edf0f5}.severity-critical,.severity-high{color:#a71d2a}.severity-medium{color:#8a5a00}.severity-low{color:#2457a6}.severity-info{color:#08708a}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}pre{white-space:pre-wrap;background:#101820;color:#edf2f7;border-radius:6px;padding:10px;overflow:auto}.locations{margin:10px 0;padding-left:20px}.hidden{display:none}details{margin-top:10px}.muted{color:#5c6675}</style>");
    output.push_str("</head><body><main>");
    output.push_str("<h1>Code Health Report</h1>");
    output.push_str(&format!(
        "<p class=\"muted\">Schema {} · Tool {} · Config {}</p>",
        JSON_SCHEMA_VERSION,
        escape_html(&context.tool_version),
        escape_html(&context.config_hash)
    ));
    output.push_str("<section class=\"summary\">");
    metric(&mut output, "Score", &score_text(result));
    metric(
        &mut output,
        "Files scanned",
        &result.stats.files_scanned.to_string(),
    );
    metric(
        &mut output,
        "Lines scanned",
        &result.summary.lines_scanned.to_string(),
    );
    metric(&mut output, "Findings", &result.findings.len().to_string());
    metric(
        &mut output,
        "Duplicate groups",
        &result.summary.duplicate_groups.to_string(),
    );
    metric(
        &mut output,
        "New findings",
        &result
            .summary
            .baseline
            .new_findings
            .map(|count| count.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
    );
    output.push_str("</section>");
    output.push_str("<section class=\"filters\" aria-label=\"Filters\">");
    output.push_str("<label>Severity<select id=\"filter-severity\"><option value=\"\">All</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select></label>");
    output.push_str("<label>Confidence<select id=\"filter-confidence\"><option value=\"\">All</option><option>certain</option><option>high</option><option>medium</option><option>low</option></select></label>");
    output.push_str(
        "<label>Rule<input id=\"filter-rule\" placeholder=\"duplicate.exact.file\"></label>",
    );
    output.push_str(
        "<label>Language<input id=\"filter-language\" placeholder=\"typescript\"></label>",
    );
    output
        .push_str("<label>Framework<input id=\"filter-framework\" placeholder=\"react\"></label>");
    output.push_str("</section>");
    output.push_str("<section id=\"findings\">");
    for finding in &report.findings {
        output.push_str(&format!(
            "<article class=\"finding\" data-severity=\"{}\" data-confidence=\"{}\" data-rule=\"{}\" data-language=\"{}\" data-framework=\"{}\">",
            escape_html(&finding.severity),
            escape_html(&finding.confidence),
            escape_html(&finding.rule_id),
            escape_html(finding.language.as_deref().unwrap_or("")),
            escape_html(finding.framework.as_deref().unwrap_or(""))
        ));
        output.push_str("<header>");
        output.push_str(&format!(
            "<span class=\"badge severity-{}\">{}</span><code>{}</code><strong>{}</strong>",
            escape_html(&finding.severity),
            escape_html(&finding.severity),
            escape_html(&finding.rule_id),
            escape_html(&finding.message)
        ));
        output.push_str("</header>");
        output.push_str("<ul class=\"locations\">");
        for location in &finding.locations {
            output.push_str(&format!(
                "<li><code>{}</code></li>",
                escape_html(&display_location_report(location))
            ));
        }
        output.push_str("</ul>");
        output.push_str(&format!(
            "<p><strong>Remediation:</strong> {}</p>",
            escape_html(&finding.remediation)
        ));
        if let Some(snippet) = finding
            .locations
            .iter()
            .find_map(|location| location.snippet.as_ref())
        {
            output.push_str(&format!("<pre>{}</pre>", escape_html(snippet)));
        }
        if let Some(group) = &finding.duplicate_group {
            output.push_str(&format!(
                "<details><summary>Duplicate group {}</summary><ul>",
                escape_html(group)
            ));
            for location in &finding.related_locations {
                output.push_str(&format!(
                    "<li><code>{}</code></li>",
                    escape_html(&display_location_report(location))
                ));
            }
            output.push_str("</ul></details>");
        }
        output.push_str("</article>");
    }
    output.push_str("</section>");
    output.push_str("<script>");
    output.push_str("window.CODEHEALTH_REPORT=");
    output.push_str(&report_json);
    output.push_str(";\n");
    output.push_str("const ids=['severity','confidence','rule','language','framework'];function value(id){return document.getElementById('filter-'+id).value.toLowerCase()}function apply(){document.querySelectorAll('.finding').forEach(el=>{const show=ids.every(id=>{const v=value(id);return !v||el.dataset[id].toLowerCase().includes(v)});el.classList.toggle('hidden',!show)})}ids.forEach(id=>document.getElementById('filter-'+id).addEventListener('input',apply));");
    output.push_str("</script>");
    output.push_str("</main></body></html>");
    Ok(output)
}

fn metric(output: &mut String, label: &str, value: &str) {
    output.push_str(&format!(
        "<div class=\"metric\"><strong>{}</strong><span>{}</span></div>",
        escape_html(label),
        escape_html(value)
    ));
}

fn display_location_report(location: &LocationReport) -> String {
    match (location.line, location.column) {
        (Some(line), Some(column)) => format!("{}:{line}:{column}", location.path),
        _ => location.path.clone(),
    }
}

fn render_markdown(result: &ScanResult, context: &ReportContext) -> String {
    let baseline_checked = result.summary.baseline.status != BaselineStatus::NotChecked;
    let findings = result
        .findings
        .iter()
        .filter(|finding| !baseline_checked || baseline_status_for(context, finding) == "new")
        .collect::<Vec<_>>();

    let mut output = String::new();
    output.push_str("# Code Health Summary\n\n");
    output.push_str(&format!("- Score: {}\n", score_text(result)));
    output.push_str(&format!(
        "- Files scanned: {}\n",
        result.stats.files_scanned
    ));
    output.push_str(&format!(
        "- Lines scanned: {}\n",
        result.summary.lines_scanned
    ));
    if baseline_checked {
        output.push_str(&format!("- New findings: {}\n", findings.len()));
        output.push_str(&format!(
            "- Changed findings: {}\n",
            result.summary.baseline.changed_findings.unwrap_or(0)
        ));
        output.push_str(&format!(
            "- Fixed findings: {}\n",
            result.summary.baseline.fixed_findings.unwrap_or(0)
        ));
    } else {
        output.push_str(&format!("- Findings: {}\n", findings.len()));
    }
    output.push('\n');

    if !result.score.top_contributors.is_empty() {
        output.push_str("## Top recommendations\n\n");
        for contributor in &result.score.top_contributors {
            output.push_str(&format!(
                "- `{}`: {} ({} point impact)\n",
                markdown_escape(&contributor.rule_id),
                markdown_escape(&contributor.message),
                contributor.penalty
            ));
        }
        output.push('\n');
    }

    if findings.is_empty() {
        output.push_str(if baseline_checked {
            "No new findings compared with the baseline.\n"
        } else {
            "No findings.\n"
        });
        push_markdown_fixed_findings(&mut output, context);
        return output;
    }

    let visible = findings
        .iter()
        .copied()
        .filter(|finding| finding.severity >= Severity::Medium)
        .take(10)
        .collect::<Vec<_>>();
    let collapsed = findings
        .iter()
        .copied()
        .filter(|finding| finding.severity < Severity::Medium)
        .collect::<Vec<_>>();

    output.push_str("## Findings\n\n");
    for finding in visible {
        push_markdown_finding(&mut output, result, finding);
    }

    if !collapsed.is_empty() {
        output.push_str(&format!(
            "<details><summary>Lower-severity findings ({})</summary>\n\n",
            collapsed.len()
        ));
        for finding in collapsed {
            push_markdown_finding(&mut output, result, finding);
        }
        output.push_str("</details>\n");
    }

    push_markdown_fixed_findings(&mut output, context);

    output
}

fn push_markdown_fixed_findings(output: &mut String, context: &ReportContext) {
    if context.fixed_findings.is_empty() {
        return;
    }

    output.push_str("\n## Fixed findings\n\n");
    for finding in &context.fixed_findings {
        output.push_str(&format!(
            "- `{}` at `{}`: {}\n",
            markdown_escape(&finding.rule_id),
            markdown_escape(&finding.path),
            markdown_escape(&finding.message)
        ));
    }
}

fn push_markdown_finding(output: &mut String, result: &ScanResult, finding: &Finding) {
    output.push_str(&format!(
        "- **{}** `{}` {}",
        finding.severity.label(),
        markdown_escape(&finding.rule_id),
        markdown_escape(&finding.message)
    ));
    if let Some(location) = finding.primary_location() {
        output.push_str(&format!(
            " at `{}`",
            markdown_escape(&format_location(&result.root, location))
        ));
    }
    output.push('\n');
    output.push_str(&format!(
        "  Remediation: {}\n",
        markdown_escape(&finding.remediation)
    ));
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn markdown_escape(value: &str) -> String {
    value.replace('|', "\\|")
}

fn category_value(finding: &Finding) -> &'static str {
    match finding.kind {
        FindingKind::DuplicateName
        | FindingKind::ExactDuplicate
        | FindingKind::StructuralDuplicate
        | FindingKind::NearDuplicate
        | FindingKind::SemanticCandidate => "duplication",
        FindingKind::Style => "style",
        FindingKind::React => "react",
        FindingKind::FastApi => "fastapi",
        FindingKind::Rust => "rust_idiom",
        FindingKind::ExternalTool => "external",
    }
}

fn kind_value(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::DuplicateName => "duplicate_name",
        FindingKind::ExactDuplicate => "exact_duplicate",
        FindingKind::StructuralDuplicate => "structural_duplicate",
        FindingKind::NearDuplicate => "near_duplicate",
        FindingKind::SemanticCandidate => "semantic_candidate",
        FindingKind::Style => "style",
        FindingKind::React => "react",
        FindingKind::FastApi => "fastapi",
        FindingKind::Rust => "rust",
        FindingKind::ExternalTool => "external_tool",
    }
}

fn baseline_status_value(status: BaselineStatus) -> &'static str {
    match status {
        BaselineStatus::NotChecked => "not_checked",
        BaselineStatus::Missing => "missing",
        BaselineStatus::Compared => "compared",
    }
}

fn baseline_status_for<'a>(context: &'a ReportContext, finding: &Finding) -> &'a str {
    context
        .baseline_status_by_key
        .get(&finding.baseline_key)
        .map(String::as_str)
        .unwrap_or("not_checked")
}

fn autofix_value(safety: AutofixSafety) -> &'static str {
    match safety {
        AutofixSafety::Unavailable => "unavailable",
        AutofixSafety::SuggestionOnly => "suggestion_only",
        AutofixSafety::Safe => "safe",
    }
}

fn applicability_value(applicability: FixApplicability) -> &'static str {
    match applicability {
        FixApplicability::MachineApplicable => "machine_applicable",
        FixApplicability::MaybeIncorrect => "maybe_incorrect",
        FixApplicability::SuggestionOnly => "suggestion_only",
    }
}

fn duplicate_group_key(finding: &Finding) -> Option<String> {
    if !is_duplicate_finding(finding) && finding.locations.len() <= 1 {
        return None;
    }

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
                .get("semantic_hash")
                .and_then(|value| value.as_str())
        })
        .or_else(|| {
            finding
                .metadata
                .get("vector_group_hash")
                .and_then(|value| value.as_str())
        })
        .or_else(|| {
            finding
                .metadata
                .get("near_group_hash")
                .and_then(|value| value.as_str())
        })
        .or_else(|| {
            finding
                .metadata
                .get("route")
                .and_then(|value| value.as_str())
        })
        .unwrap_or(&finding.baseline_key);

    Some(format!("{}|{key}", finding.rule_id))
}

fn is_duplicate_finding(finding: &Finding) -> bool {
    matches!(
        finding.kind,
        FindingKind::DuplicateName
            | FindingKind::ExactDuplicate
            | FindingKind::StructuralDuplicate
            | FindingKind::NearDuplicate
            | FindingKind::SemanticCandidate
    )
}

#[derive(Debug, Error)]
pub enum ReporterError {
    #[error("failed to serialize JSON report")]
    Json(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_core::{Confidence, FindingKind, Location, SourceSpan};
    use std::path::PathBuf;

    #[test]
    fn text_report_includes_counts() {
        let result = ScanResult::new("fixtures").finalize();

        let rendered =
            render_result(&result, ReportOptions::new(ReportFormat::Text, false)).expect("text");

        assert!(rendered.contains("Code Health Report"));
        assert!(rendered.contains("Files scanned: 0"));
        assert!(rendered.contains("Findings: 0"));
    }

    #[test]
    fn json_report_has_stable_schema_shape() {
        let result = ScanResult::new("fixtures").finalize();

        let rendered =
            render_result(&result, ReportOptions::new(ReportFormat::Json, false)).expect("json");
        let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(json["schemaVersion"], JSON_SCHEMA_VERSION);
        assert_eq!(json["toolVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["filesScanned"], 0);
        assert_eq!(json["score"]["enabled"], true);
        assert_eq!(json["score"]["overall"], 100);
        assert_eq!(json["metrics"]["linesScanned"], 0);
        assert!(json["findings"].as_array().expect("array").is_empty());
    }

    #[test]
    fn color_can_be_forced_for_text_output() {
        let mut result = ScanResult::new("fixtures");
        result.findings.push(sample_finding());
        let result = result.finalize();

        let rendered =
            render_result(&result, ReportOptions::new(ReportFormat::Text, true)).expect("text");

        assert!(rendered.contains("\u{1b}[31mHIGH\u{1b}[0m"));
    }

    #[test]
    fn sarif_includes_related_duplicate_locations() {
        let mut result = ScanResult::new("fixtures");
        let mut finding = sample_finding();
        finding.locations.push(FindingLocation {
            path: PathBuf::from("fixtures/b.ts"),
            span: Some(SourceSpan { start: 0, end: 1 }),
            start: Some(Location {
                line: 1,
                column: 1,
                byte_offset: 0,
            }),
            language: Some("typescript".to_string()),
        });
        result.findings.push(finding);
        let result = result.finalize();

        let rendered =
            render_result(&result, ReportOptions::new(ReportFormat::Sarif, false)).expect("sarif");
        let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        let result = &json["runs"][0]["results"][0];

        assert_eq!(json["version"], "2.1.0");
        assert_eq!(result["level"], "error");
        assert!(
            result["relatedLocations"]
                .as_array()
                .expect("related")
                .len()
                == 1
        );
    }

    fn sample_finding() -> Finding {
        Finding {
            finding_id: "id".to_string(),
            baseline_key: "baseline".to_string(),
            rule_id: "duplicate.exact.file".to_string(),
            kind: FindingKind::ExactDuplicate,
            severity: Severity::High,
            confidence: Confidence::Certain,
            message: "duplicate".to_string(),
            locations: vec![FindingLocation {
                path: PathBuf::from("fixtures/a.ts"),
                span: Some(SourceSpan { start: 0, end: 1 }),
                start: Some(Location {
                    line: 1,
                    column: 1,
                    byte_offset: 0,
                }),
                language: Some("typescript".to_string()),
            }],
            language: Some("typescript".to_string()),
            framework: None,
            explanation: "explanation".to_string(),
            remediation: "remediation".to_string(),
            detection_reason: "reason".to_string(),
            autofix: AutofixSafety::SuggestionOnly,
            autofix_explanation: "not safe".to_string(),
            fixes: Vec::new(),
            metadata: Default::default(),
            is_suppressed: false,
            suppression: None,
        }
    }
}
