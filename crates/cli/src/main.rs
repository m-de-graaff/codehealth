use anyhow::{bail, Context};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use codehealth_autofix::apply_safe_fixes;
use codehealth_config::{
    config_path, default_config_toml, parse_suppressions, path_matches_any, CodehealthConfig,
    LoadedConfig, SuppressionDirective, DEFAULT_CONFIG_FILE,
};
use codehealth_core::{
    BaselineSummary, ComplexityMetric, Confidence, DefinitionMetric, Finding, FindingFilters,
    FindingKind, ModuleDuplicateMetric, ScanMode, ScanResult, ScoreOptions, Severity,
    SummaryMetrics, SuppressedRuleMetric, Suppression, SuppressionKind,
};
use codehealth_duplication::{
    find_exact_body_duplicates, find_exact_file_duplicates, find_structural_duplicates,
    fingerprint_normalized_body, normalize_body_source, normalize_source, token_estimate,
    DuplicateInput, ExactBodyOptions, StructuralOptions,
};
use codehealth_parser::{run_query, LanguageRegistry, QueryKind, SourceFile, SyntaxTree};
use codehealth_reporters::{
    render_result_with_context, ReportContext, ReportFormat, ReportOptions, ReportTiming,
};
use codehealth_rules::{
    canonical_rule_id, find_rule, rule_catalog, RuleContext, RuleExecutionConfig,
    RuleOptionSettings, RuleReactWorkspaceMetadata, RuleRegistry as StyleRuleRegistry,
    RuleWorkspaceMetadata,
};
use codehealth_rules_react::react_rules;
use codehealth_symbols::{
    build_symbol_index, find_duplicate_fastapi_route_findings, find_duplicate_name_findings,
    Definition, DefinitionKind, Language as SymbolLanguage, SymbolIndex, SymbolInput,
    SymbolRegistry,
};
use codehealth_workspace::{
    scan_workspace, WorkspaceFile, WorkspaceMetadata, WorkspaceScan, WorkspaceScanOptions,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::IsTerminal,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

mod baseline;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> anyhow::Result<u8> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(0)
        }
        Some(Command::Scan(args)) => run_scan(args, ScanMode::All),
        Some(Command::Ci(args)) => run_ci(args),
        Some(Command::Dupes(args)) => run_scan(args, ScanMode::DuplicatesOnly),
        Some(Command::Rules(args)) => run_rules(args),
        Some(Command::Init(args)) => run_init(args),
        Some(Command::Config(command)) => run_config(command),
        Some(Command::Explain(args)) => run_explain(args),
        Some(Command::Debug(command)) => run_debug(command),
    }
}

#[derive(Debug, Parser)]
#[command(name = "codehealth")]
#[command(version)]
#[command(about = "Local-first code health and duplication detector")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan(RunArgs),
    Ci(RunArgs),
    Dupes(RunArgs),
    Rules(RulesArgs),
    Init(InitArgs),
    #[command(subcommand)]
    Config(ConfigCommand),
    Explain(ExplainArgs),
    #[command(hide = true)]
    #[command(subcommand)]
    Debug(DebugCommand),
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    #[arg(long, value_enum)]
    min_severity: Option<SeverityArg>,

    #[arg(long = "only", value_enum)]
    only_severity: Option<SeverityArg>,

    #[arg(long, value_enum)]
    min_confidence: Option<ConfidenceArg>,

    #[arg(long, value_enum)]
    language: Vec<LanguageArg>,

    #[arg(long, value_enum)]
    framework: Vec<FrameworkArg>,

    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    #[arg(long)]
    baseline: Option<PathBuf>,

    #[arg(long)]
    write_baseline: Option<PathBuf>,

    #[arg(long)]
    update_baseline: bool,

    #[arg(long)]
    force_baseline: bool,

    #[arg(long)]
    baseline_owner: Option<String>,

    #[arg(long, value_parser = parse_jobs)]
    jobs: Option<usize>,

    #[arg(long)]
    no_cache: bool,

    #[arg(long, default_value = ".codehealth/cache")]
    cache_dir: PathBuf,

    #[arg(long)]
    fix: bool,

    #[arg(long)]
    fix_safe: bool,

    #[arg(long)]
    dry_run: bool,

    #[arg(long)]
    show_suppressed: bool,

    #[arg(long)]
    no_score: bool,

    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RulesArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, default_value = DEFAULT_CONFIG_FILE)]
    path: PathBuf,

    #[arg(long)]
    force: bool,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Validate(ConfigValidateArgs),
}

#[derive(Debug, Args)]
struct ConfigValidateArgs {
    path: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    finding_code: String,
}

#[derive(Debug, Subcommand)]
enum DebugCommand {
    Parse(DebugFileArgs),
    Symbols(DebugFileArgs),
    Fingerprints(DebugFileArgs),
    Canonical(DebugCanonicalArgs),
    Ast(DebugFileArgs),
    Query(DebugQueryArgs),
    Workspace(DebugWorkspaceArgs),
}

#[derive(Debug, Args)]
struct DebugFileArgs {
    file: PathBuf,
}

#[derive(Debug, Args)]
struct DebugCanonicalArgs {
    file: PathBuf,

    #[arg(long)]
    symbol: Option<String>,

    #[arg(long, value_enum, default_value_t = DebugDumpFormat::Text)]
    format: DebugDumpFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DebugDumpFormat {
    Text,
    Json,
}

#[derive(Debug, Args)]
struct DebugQueryArgs {
    file: PathBuf,

    #[arg(long, value_enum, default_value_t = QueryKindArg::Definitions)]
    kind: QueryKindArg,
}

#[derive(Debug, Args)]
struct DebugWorkspaceArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
    Html,
    Markdown,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum QueryKindArg {
    Definitions,
    Imports,
}

impl From<QueryKindArg> for QueryKind {
    fn from(value: QueryKindArg) -> Self {
        match value {
            QueryKindArg::Definitions => Self::Definitions,
            QueryKindArg::Imports => Self::Imports,
        }
    }
}

impl OutputFormat {
    fn from_config(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "json" => Self::Json,
            "sarif" => Self::Sarif,
            "html" => Self::Html,
            "markdown" | "md" => Self::Markdown,
            _ => Self::Text,
        }
    }
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Text => Self::Text,
            OutputFormat::Json => Self::Json,
            OutputFormat::Sarif => Self::Sarif,
            OutputFormat::Html => Self::Html,
            OutputFormat::Markdown => Self::Markdown,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Info => Self::Info,
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfidenceArg {
    Low,
    Medium,
    High,
    Certain,
}

impl From<ConfidenceArg> for Confidence {
    fn from(value: ConfidenceArg) -> Self {
        match value {
            ConfidenceArg::Low => Self::Low,
            ConfidenceArg::Medium => Self::Medium,
            ConfidenceArg::High => Self::High,
            ConfidenceArg::Certain => Self::Certain,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LanguageArg {
    #[value(name = "typescript")]
    TypeScript,
    #[value(name = "tsx")]
    Tsx,
    #[value(name = "python")]
    Python,
    #[value(name = "rust")]
    Rust,
}

impl LanguageArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FrameworkArg {
    #[value(name = "react")]
    React,
    #[value(name = "fastapi")]
    FastApi,
}

impl FrameworkArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::React => "react",
            Self::FastApi => "fastapi",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOn {
    #[value(name = "high")]
    High,
    #[value(name = "new-high")]
    NewHigh,
    #[value(name = "new-medium")]
    NewMedium,
}

fn run_scan(args: RunArgs, mode: ScanMode) -> anyhow::Result<u8> {
    run_scan_with_options(args, mode, false)
}

fn run_ci(args: RunArgs) -> anyhow::Result<u8> {
    run_scan_with_options(args, ScanMode::All, true)
}

fn run_scan_with_options(args: RunArgs, mode: ScanMode, ci_mode: bool) -> anyhow::Result<u8> {
    let scan_started = Instant::now();
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    let loaded_config = CodehealthConfig::load_with_metadata(args.config.as_deref(), &cwd)
        .context("failed to load codehealth config")?;
    let config = &loaded_config.config;
    if args.write_baseline.is_some() && args.update_baseline {
        bail!("--write-baseline and --update-baseline cannot be used together");
    }
    let config_hash = config_hash(config).context("failed to hash effective config")?;
    let format = args
        .format
        .unwrap_or_else(|| OutputFormat::from_config(&config.report.default_format));
    let filters = filters_from_args(&args);
    let fail_on_values = effective_fail_on_values(args.fail_on, &loaded_config, ci_mode);

    let registry = build_language_registry();
    let workspace_scan = scan_workspace(
        &args.path,
        &registry,
        workspace_options_from_config(config, &args.language),
    )
    .context("failed to discover workspace files")?;
    let mut result = ScanResult::new(args.path.canonicalize().unwrap_or(args.path.clone()));
    result.stats.files_discovered = workspace_scan.files_discovered();
    result.stats.files_skipped = workspace_scan.skipped.len();
    result.stats.config_files = workspace_scan.config_files.len();
    let workspace_frameworks = workspace_scan.metadata.frameworks();
    let rule_workspace = rule_workspace_metadata(&workspace_scan.metadata);
    let files = workspace_scan.files;
    result.stats.files_scanned = files.len();
    let generated_paths = generated_source_paths(&files);

    let symbol_registry = build_symbol_registry();
    let should_index_symbols = mode == ScanMode::All
        || (config.duplication.enabled
            && (config.duplication.detect_names
                || config.duplication.detect_exact
                || config.duplication.detect_structural
                || (config.fastapi.enabled && config.fastapi.detect_duplicate_routes)));
    let symbol_index = if should_index_symbols {
        let build = build_symbol_index(
            &symbol_inputs_from_files(&files),
            &registry,
            &symbol_registry,
        );
        result.stats.files_parsed = build.files_parsed;
        result.stats.parse_errors = build.parse_errors;
        result.stats.definitions_indexed = build.index.definitions.len();
        result.stats.imports_indexed = build.index.imports.len();
        Some(build.index)
    } else {
        None
    };

    let _accepted_but_not_active_yet = (args.jobs, args.no_cache, &args.cache_dir);

    let mut findings = match mode {
        ScanMode::All | ScanMode::DuplicatesOnly => {
            run_duplicate_checks(&files, config, symbol_index.as_ref())?
        }
    };
    if mode == ScanMode::All {
        findings.extend(run_style_checks(
            &files,
            config,
            symbol_index.as_ref(),
            &registry,
            &result.root,
            &workspace_frameworks,
            &rule_workspace,
        )?);
    }

    let mut suppressed_rule_counts = BTreeMap::new();
    let policy_findings = apply_config_policy(
        findings,
        &result.root,
        config,
        &files,
        args.show_suppressed,
        &mut result.stats.suppressed_findings,
        &mut suppressed_rule_counts,
    )?;
    if args.fix || args.fix_safe {
        let summary = apply_safe_fixes(&policy_findings, &registry, args.dry_run)
            .context("failed to apply safe autofixes")?;
        if summary.planned_edits > 0 {
            if summary.dry_run {
                eprintln!(
                    "Would apply {} safe edits across {} files.",
                    summary.planned_edits, summary.files_touched
                );
            } else {
                eprintln!(
                    "Applied {} safe edits across {} files.",
                    summary.applied_edits, summary.files_touched
                );
            }
        }
    }
    result.findings = policy_findings
        .into_iter()
        .filter(|finding| filters.allows(finding))
        .collect();
    let baseline_path = effective_baseline_path(args.baseline.as_ref(), config, ci_mode);
    let baseline_owner = args
        .baseline_owner
        .as_deref()
        .or(config.ci.baseline_owner.as_deref());
    let baseline_comparison = baseline::compare_findings(
        &result.root,
        &result.findings,
        baseline_path.clone(),
        baseline_owner,
        env!("CARGO_PKG_VERSION"),
        &config_hash,
        ci_mode
            || fail_on_values
                .iter()
                .any(|fail_on| fail_on.is_new_findings_only()),
    )?;
    let report_new_finding_keys = baseline_comparison.new_keys.clone();
    result.summary = collect_summary_metrics(
        &files,
        symbol_index.as_ref(),
        &result.findings,
        suppressed_rule_counts,
        baseline_comparison.summary.clone(),
    )?;
    let score_options = ScoreOptions {
        enabled: config.scoring.enabled && !args.no_score,
        generated_paths,
        baseline_new_keys: baseline_comparison.new_keys.clone(),
    };
    let result = result.finalize_with_score_options(&score_options);

    if let Some(path) = args.write_baseline.as_ref() {
        baseline::write_new_baseline(
            path,
            &result.root,
            &result.findings,
            baseline_owner,
            env!("CARGO_PKG_VERSION"),
            &config_hash,
            args.force_baseline,
        )?;
        eprintln!("Wrote baseline to {}", path.display());
    }

    let output = render_result_with_context(
        &result,
        ReportOptions::new(format.into(), use_color(args.color)),
        ReportContext {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            config_hash: config_hash.clone(),
            timing: ReportTiming {
                scan_ms: elapsed_millis(scan_started.elapsed()),
                report_ms: 0,
                total_ms: 0,
            },
            new_finding_keys: report_new_finding_keys,
            baseline_status_by_key: baseline_comparison
                .status_by_key
                .iter()
                .map(|(key, status)| (key.clone(), status.as_str().to_string()))
                .collect(),
            fixed_findings: baseline_comparison
                .fixed_entries
                .iter()
                .map(|entry| codehealth_reporters::BaselineFixedFinding {
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
    )
    .context("failed to render report")?;
    write_or_print(args.output.as_deref(), &output)?;

    if args.update_baseline {
        let path = baseline_comparison
            .path
            .clone()
            .unwrap_or_else(|| PathBuf::from(baseline::DEFAULT_BASELINE_PATH));
        baseline::update_baseline(
            &path,
            &result.root,
            &baseline_comparison,
            env!("CARGO_PKG_VERSION"),
            &config_hash,
        )?;
        eprintln!("Updated baseline at {}", path.display());
    }

    if should_fail(&result, &fail_on_values, &baseline_comparison.status_by_key) {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn filters_from_args(args: &RunArgs) -> FindingFilters {
    FindingFilters {
        min_severity: args.min_severity.map(Into::into),
        only_severity: args.only_severity.map(Into::into),
        min_confidence: args.min_confidence.map(Into::into),
        languages: args
            .language
            .iter()
            .map(|language| language.as_str().to_string())
            .collect(),
        frameworks: args
            .framework
            .iter()
            .map(|framework| framework.as_str().to_string())
            .collect(),
    }
}

fn workspace_options_from_config(
    config: &CodehealthConfig,
    languages: &[LanguageArg],
) -> WorkspaceScanOptions {
    let enabled_languages = if languages.is_empty() {
        config.project.languages.clone()
    } else {
        languages
            .iter()
            .map(|language| language.as_str().to_string())
            .collect()
    };

    WorkspaceScanOptions {
        ignore_paths: config.ignore.paths.clone(),
        include: config.scanner.include.clone(),
        exclude: config.scanner.exclude.clone(),
        max_file_size_bytes: config.scanner.max_file_size_bytes,
        follow_symlinks: config.scanner.follow_symlinks,
        include_generated: config.scanner.include_generated,
        include_binary: config.scanner.include_binary,
        detect_javascript: config.scanner.detect_javascript,
        enabled_languages,
    }
}

fn run_duplicate_checks(
    files: &[WorkspaceFile],
    config: &CodehealthConfig,
    symbol_index: Option<&SymbolIndex>,
) -> anyhow::Result<Vec<Finding>> {
    if !config.duplication.enabled {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    if config.duplication.detect_exact {
        let inputs = files
            .iter()
            .map(|file| DuplicateInput {
                path: file.path.clone(),
                language: file.language.name.to_string(),
            })
            .collect::<Vec<_>>();
        findings.extend(
            find_exact_file_duplicates(&inputs).context("failed to detect exact duplicates")?,
        );
        if let Some(symbol_index) = symbol_index {
            findings.extend(
                find_exact_body_duplicates(symbol_index, exact_body_options(config))
                    .context("failed to detect exact body duplicates")?,
            );
        }
    }

    if config.duplication.detect_names {
        if let Some(symbol_index) = symbol_index {
            findings.extend(find_duplicate_name_findings(symbol_index));
        }
    }

    if config.duplication.detect_structural {
        if let Some(symbol_index) = symbol_index {
            findings.extend(find_structural_duplicates(
                symbol_index,
                structural_options(config),
            ));
        }
    }

    if config.fastapi.enabled && config.fastapi.detect_duplicate_routes {
        if let Some(symbol_index) = symbol_index {
            findings.extend(find_duplicate_fastapi_route_findings(symbol_index));
        }
    }

    Ok(findings)
}

fn run_style_checks(
    files: &[WorkspaceFile],
    config: &CodehealthConfig,
    symbol_index: Option<&SymbolIndex>,
    parser_registry: &LanguageRegistry,
    root: &Path,
    workspace_frameworks: &[&str],
    workspace: &RuleWorkspaceMetadata,
) -> anyhow::Result<Vec<Finding>> {
    let mut registry = StyleRuleRegistry::with_builtin_rules();
    for rule in react_rules() {
        registry.register_box(rule);
    }
    let mut findings = Vec::new();

    for file in files {
        let Some(parser) = parser_registry.adapter_for_path(&file.path) else {
            continue;
        };
        let source = match SourceFile::from_path(&file.path, file.language) {
            Ok(source) => source,
            Err(_) => continue,
        };
        let tree = match parser.parse(&source) {
            Ok(tree) => tree,
            Err(_) => continue,
        };
        if tree.has_error() {
            continue;
        }

        let rule_config = rule_execution_config_for_file(config, root, &file.path);
        let context = RuleContext {
            root,
            source_file: &tree.source,
            tree: &tree,
            symbols: symbol_index,
            config: &rule_config,
            workspace_frameworks,
            workspace,
        };
        findings.extend(registry.run(&context));
    }

    Ok(findings)
}

fn rule_workspace_metadata(metadata: &WorkspaceMetadata) -> RuleWorkspaceMetadata {
    RuleWorkspaceMetadata {
        react: RuleReactWorkspaceMetadata {
            detected: metadata.react.detected(),
            via_dependency: metadata.react.via_dependency,
            via_tsx_or_jsx: metadata.react.via_tsx_or_jsx,
            via_next_dependency: metadata.react.via_next_dependency,
            via_vite_dependency: metadata.react.via_vite_dependency,
            via_remix_dependency: metadata.react.via_remix_dependency,
            source_directories: metadata.react.source_directories.clone(),
        },
    }
}

fn rule_execution_config_for_file(
    config: &CodehealthConfig,
    root: &Path,
    path: &Path,
) -> RuleExecutionConfig {
    let paths = vec![path.to_path_buf()];
    let disabled_rules = rule_catalog()
        .into_iter()
        .filter(|rule| {
            config.level_for_rule(rule.code, root, &paths).is_off()
                || (!config.react.enabled && rule.framework == Some("react"))
        })
        .map(|rule| rule.code.to_string())
        .collect();
    let options = config
        .rule_options
        .iter()
        .map(|(rule_id, options)| (rule_id.clone(), rule_option_settings(options)))
        .collect();

    RuleExecutionConfig {
        simplify_boolean_returns: config.style.simplify_boolean_returns,
        prefer_expression_arrows: config.style.prefer_expression_arrows,
        prefer_guard_clauses: config.style.prefer_guard_clauses,
        react_enabled: config.react.enabled,
        react_max_component_lines: config.react.max_component_lines,
        react_max_props: config.react.max_props,
        react_prop_drilling_depth: config.react.prop_drilling_depth,
        disabled_rules,
        options,
    }
}

fn rule_option_settings(options: &codehealth_config::RuleOptions) -> RuleOptionSettings {
    RuleOptionSettings {
        min_tokens: options.min_tokens,
        min_lines: options.min_lines,
        min_confidence: options.min_confidence,
        max_lines: options.max_lines,
        max_params: options.max_params,
        max_condition_terms: options.max_condition_terms,
        max_literal_occurrences: options.max_literal_occurrences,
        max_unwraps: options.max_unwraps,
        max_depth: options.max_depth,
        min_nodes: options.min_nodes,
        max_context_values: options.max_context_values,
        max_responsibilities: options.max_responsibilities,
    }
}

fn exact_body_options(config: &CodehealthConfig) -> ExactBodyOptions {
    let overrides = config.rule_options_for(codehealth_duplication::EXACT_BODY_RULE);
    ExactBodyOptions {
        min_lines: overrides
            .and_then(|options| options.min_lines)
            .unwrap_or(config.duplication.min_lines),
        min_tokens: overrides
            .and_then(|options| options.min_tokens)
            .unwrap_or(config.duplication.min_tokens),
    }
}

fn structural_options(config: &CodehealthConfig) -> StructuralOptions {
    let overrides = config.rule_options_for(codehealth_duplication::STRUCTURAL_FUNCTION_RULE);
    StructuralOptions {
        min_lines: overrides
            .and_then(|options| options.min_lines)
            .unwrap_or(StructuralOptions::default().min_lines),
        min_tokens: overrides
            .and_then(|options| options.min_tokens)
            .unwrap_or(StructuralOptions::default().min_tokens),
        min_nodes: config.duplication.structural_min_nodes,
        max_opaque_percent: config.duplication.structural_max_opaque_percent,
        normalize_literals: config.duplication.structural_normalize_literals,
    }
}

fn symbol_inputs_from_files(files: &[WorkspaceFile]) -> Vec<SymbolInput> {
    files
        .iter()
        .map(|file| SymbolInput {
            path: file.path.clone(),
            language: file.language,
        })
        .collect()
}

fn generated_source_paths(files: &[WorkspaceFile]) -> BTreeSet<PathBuf> {
    files
        .iter()
        .filter(|file| file.generated_reason.is_some())
        .map(|file| file.path.clone())
        .collect()
}

fn collect_summary_metrics(
    files: &[WorkspaceFile],
    symbol_index: Option<&SymbolIndex>,
    findings: &[Finding],
    suppressed_rule_counts: BTreeMap<String, usize>,
    baseline: BaselineSummary,
) -> anyhow::Result<SummaryMetrics> {
    let lines_scanned = count_scanned_lines(files)?;
    let (duplicate_groups, duplicate_lines, most_duplicated_modules) = duplicate_summary(findings);
    let most_suppressed_rules = suppressed_rule_counts
        .into_iter()
        .map(|(rule_id, count)| SuppressedRuleMetric { rule_id, count })
        .collect::<Vec<_>>();

    let mut summary = SummaryMetrics {
        lines_scanned,
        duplicate_groups,
        duplicate_lines,
        most_duplicated_modules,
        most_suppressed_rules,
        baseline,
        ..SummaryMetrics::default()
    };
    sort_suppressed_rules(&mut summary.most_suppressed_rules);

    if let Some(index) = symbol_index {
        summary.largest_functions = largest_functions(index);
        summary.largest_react_components = largest_react_components(index);
        summary.most_complex_functions = most_complex_functions(index)?;
    }

    Ok(summary)
}

fn count_scanned_lines(files: &[WorkspaceFile]) -> anyhow::Result<usize> {
    let mut total = 0;
    for file in files {
        let source = std::fs::read_to_string(&file.path)
            .with_context(|| format!("failed to read {}", file.path.display()))?;
        total += source.lines().count();
    }
    Ok(total)
}

fn duplicate_summary(findings: &[Finding]) -> (usize, usize, Vec<ModuleDuplicateMetric>) {
    let mut groups = 0;
    let mut total_duplicate_lines = 0;
    let mut by_module: BTreeMap<PathBuf, (usize, usize)> = BTreeMap::new();

    for finding in findings {
        if finding.is_suppressed || !is_duplicate_finding(finding) {
            continue;
        }

        groups += 1;
        let line_count = metadata_usize(finding, "line_count").unwrap_or(0);
        let duplicate_lines = line_count.saturating_mul(finding.locations.len().saturating_sub(1));
        total_duplicate_lines += duplicate_lines;

        for location in &finding.locations {
            let entry = by_module.entry(location.path.clone()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += line_count;
        }
    }

    let mut modules = by_module
        .into_iter()
        .map(
            |(path, (duplicate_findings, duplicate_lines))| ModuleDuplicateMetric {
                path,
                duplicate_findings,
                duplicate_lines,
            },
        )
        .collect::<Vec<_>>();
    modules.sort_by(|left, right| {
        right
            .duplicate_lines
            .cmp(&left.duplicate_lines)
            .then_with(|| right.duplicate_findings.cmp(&left.duplicate_findings))
            .then_with(|| left.path.cmp(&right.path))
    });
    modules.truncate(5);

    (groups, total_duplicate_lines, modules)
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

fn metadata_usize(finding: &Finding, key: &str) -> Option<usize> {
    finding
        .metadata
        .get(key)?
        .as_u64()
        .and_then(|value| value.try_into().ok())
}

fn largest_functions(index: &SymbolIndex) -> Vec<DefinitionMetric> {
    let mut metrics = index
        .definitions
        .iter()
        .filter(|definition| is_function_metric_kind(definition.kind))
        .map(definition_metric)
        .collect::<Vec<_>>();
    sort_definition_metrics(&mut metrics);
    metrics.truncate(5);
    metrics
}

fn largest_react_components(index: &SymbolIndex) -> Vec<DefinitionMetric> {
    let mut metrics = index
        .definitions
        .iter()
        .filter(|definition| definition.kind == DefinitionKind::ReactComponent)
        .map(definition_metric)
        .collect::<Vec<_>>();
    sort_definition_metrics(&mut metrics);
    metrics.truncate(5);
    metrics
}

fn is_function_metric_kind(kind: DefinitionKind) -> bool {
    matches!(
        kind,
        DefinitionKind::Function
            | DefinitionKind::Method
            | DefinitionKind::ReactHook
            | DefinitionKind::FastApiRoute
            | DefinitionKind::FastApiDependency
    )
}

fn definition_metric(definition: &Definition) -> DefinitionMetric {
    DefinitionMetric {
        name: definition.qualified_name.clone(),
        path: definition.file.clone(),
        line: definition.span.start_position.line,
        lines: definition_line_count(definition),
        language: definition.language.label().to_string(),
    }
}

fn sort_definition_metrics(metrics: &mut [DefinitionMetric]) {
    metrics.sort_by(|left, right| {
        right
            .lines
            .cmp(&left.lines)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.name.cmp(&right.name))
    });
}

fn most_complex_functions(index: &SymbolIndex) -> anyhow::Result<Vec<ComplexityMetric>> {
    let mut source_cache = BTreeMap::new();
    let mut metrics = Vec::new();

    for definition in &index.definitions {
        if !is_function_metric_kind(definition.kind)
            && definition.kind != DefinitionKind::ReactComponent
        {
            continue;
        }

        let source = cached_source(&definition.file, &mut source_cache)?;
        let complexity = definition_complexity(definition, source);
        metrics.push(ComplexityMetric {
            name: definition.qualified_name.clone(),
            path: definition.file.clone(),
            line: definition.span.start_position.line,
            score: complexity,
            lines: definition_line_count(definition),
            language: definition.language.label().to_string(),
        });
    }

    metrics.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.lines.cmp(&left.lines))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.name.cmp(&right.name))
    });
    metrics.truncate(5);
    Ok(metrics)
}

fn cached_source<'a>(
    path: &Path,
    cache: &'a mut BTreeMap<PathBuf, String>,
) -> anyhow::Result<&'a str> {
    if !cache.contains_key(path) {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        cache.insert(path.to_path_buf(), source);
    }

    Ok(cache.get(path).expect("source was inserted").as_str())
}

fn definition_complexity(definition: &Definition, source: &str) -> usize {
    let span = definition.body_span.unwrap_or(definition.span);
    let snippet = if span.end <= source.len()
        && source.is_char_boundary(span.start)
        && source.is_char_boundary(span.end)
    {
        &source[span.start..span.end]
    } else {
        ""
    };

    lexical_complexity(snippet)
}

fn lexical_complexity(source: &str) -> usize {
    let lowered = source.to_ascii_lowercase();
    let mut score = 1;
    for token in
        lowered.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
    {
        if matches!(
            token,
            "if" | "elif" | "else" | "for" | "while" | "match" | "case" | "catch" | "except"
        ) {
            score += 1;
        }
    }
    score + lowered.matches("&&").count() + lowered.matches("||").count()
}

fn definition_line_count(definition: &Definition) -> usize {
    let span = definition.body_span.unwrap_or(definition.span);
    span.end_position
        .line
        .saturating_sub(span.start_position.line)
        + 1
}

fn sort_suppressed_rules(rules: &mut [SuppressedRuleMetric]) {
    rules.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
}

fn apply_config_policy(
    findings: Vec<Finding>,
    root: &Path,
    config: &CodehealthConfig,
    files: &[WorkspaceFile],
    show_suppressed: bool,
    suppressed_count: &mut usize,
    suppressed_rule_counts: &mut BTreeMap<String, usize>,
) -> anyhow::Result<Vec<Finding>> {
    let suppressions = collect_suppressions(files)?;
    let mut output = Vec::new();

    for mut finding in findings {
        let paths = finding
            .locations
            .iter()
            .map(|location| location.path.clone())
            .collect::<Vec<_>>();

        if !rule_options_allow(&finding, root, config) {
            continue;
        }

        let level = config.level_for_rule(&finding.rule_id, root, &paths);
        if level.is_off() {
            continue;
        }
        if let Some(severity) = level.severity() {
            finding.severity = severity;
        }

        if let Some(suppression) = find_suppression_for_finding(&finding, &suppressions) {
            for warning in &suppression.warnings {
                let path = suppression.path.to_string_lossy().replace('\\', "/");
                eprintln!("warning: {}:{}: {warning}", path, suppression.line);
            }
            finding.is_suppressed = true;
            finding.suppression = Some(Suppression {
                rule_id: suppression.rule_id.clone(),
                path: suppression.path.clone(),
                line: suppression.line,
                kind: match suppression.kind {
                    codehealth_config::SuppressionKind::NextLine => SuppressionKind::NextLine,
                    codehealth_config::SuppressionKind::Block => SuppressionKind::Block,
                },
                reason: suppression.reason.clone(),
                warnings: suppression.warnings.clone(),
            });
            *suppressed_count += 1;
            *suppressed_rule_counts
                .entry(finding.rule_id.clone())
                .or_insert(0) += 1;
        }

        if !finding.is_suppressed || show_suppressed {
            output.push(finding);
        }
    }

    Ok(output)
}

fn rule_options_allow(finding: &Finding, root: &Path, config: &CodehealthConfig) -> bool {
    let Some(options) = config.rule_options_for(&finding.rule_id) else {
        return true;
    };
    let paths = finding
        .locations
        .iter()
        .map(|location| location.path.as_path())
        .collect::<Vec<_>>();

    if !options.include_paths.is_empty()
        && !paths
            .iter()
            .any(|path| path_matches_any(root, path, &options.include_paths))
    {
        return false;
    }

    if paths
        .iter()
        .any(|path| path_matches_any(root, path, &options.exclude_paths))
    {
        return false;
    }

    if let Some(min_confidence) = options.min_confidence {
        if finding.confidence < min_confidence {
            return false;
        }
    }

    true
}

fn collect_suppressions(files: &[WorkspaceFile]) -> anyhow::Result<Vec<SuppressionDirective>> {
    let mut suppressions = Vec::new();

    for file in files {
        let source = std::fs::read_to_string(&file.path)
            .with_context(|| format!("failed to read {}", file.path.display()))?;
        suppressions.extend(parse_suppressions(&file.path, &source));
    }

    Ok(suppressions)
}

fn find_suppression_for_finding(
    finding: &Finding,
    suppressions: &[SuppressionDirective],
) -> Option<SuppressionDirective> {
    let canonical_rule = canonical_rule_id(&finding.rule_id)?;
    finding.locations.iter().find_map(|location| {
        let line = location.start.map(|start| start.line)?;
        suppressions
            .iter()
            .find(|suppression| {
                suppression.path == location.path && suppression.matches(canonical_rule, line)
            })
            .cloned()
    })
}

fn write_or_print(output_path: Option<&Path>, output: &str) -> anyhow::Result<()> {
    if let Some(output_path) = output_path {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create output directory {}", parent.display())
                })?;
            }
        }
        std::fs::write(output_path, output)
            .with_context(|| format!("failed to write report to {}", output_path.display()))?;
        println!("Wrote report to {}", output_path.display());
    } else {
        print!("{output}");
    }

    Ok(())
}

fn should_fail(
    result: &ScanResult,
    fail_on_values: &[FailOn],
    baseline_status_by_key: &BTreeMap<String, baseline::FindingBaselineStatus>,
) -> bool {
    for fail_on in fail_on_values {
        let should_fail = match fail_on {
            FailOn::High => result
                .findings
                .iter()
                .filter(|finding| !finding.is_suppressed)
                .any(|finding| finding.severity >= Severity::High),
            FailOn::NewHigh => {
                has_new_finding_at_or_above(result, Severity::High, baseline_status_by_key)
            }
            FailOn::NewMedium => {
                has_new_finding_at_or_above(result, Severity::Medium, baseline_status_by_key)
            }
        };

        if should_fail {
            return true;
        }
    }

    false
}

fn config_fail_on(value: &str) -> Option<FailOn> {
    match value {
        "high" => Some(FailOn::High),
        "new_high" => Some(FailOn::NewHigh),
        "new_medium" => Some(FailOn::NewMedium),
        _ => None,
    }
}

fn effective_fail_on_values(
    fail_on: Option<FailOn>,
    loaded_config: &LoadedConfig,
    ci_mode: bool,
) -> Vec<FailOn> {
    if let Some(fail_on) = fail_on {
        return vec![fail_on];
    }

    let configured = loaded_config
        .config
        .ci
        .fail_on
        .iter()
        .filter_map(|value| config_fail_on(value))
        .collect::<Vec<_>>();
    if !configured.is_empty() {
        return configured;
    }

    if ci_mode {
        vec![FailOn::NewHigh]
    } else {
        Vec::new()
    }
}

fn effective_baseline_path(
    baseline_path: Option<&PathBuf>,
    config: &CodehealthConfig,
    ci_mode: bool,
) -> Option<PathBuf> {
    baseline_path
        .cloned()
        .or_else(|| config.ci.baseline.clone())
        .or_else(|| ci_mode.then(|| PathBuf::from(baseline::DEFAULT_BASELINE_PATH)))
}

fn has_new_finding_at_or_above(
    result: &ScanResult,
    severity: Severity,
    baseline_status_by_key: &BTreeMap<String, baseline::FindingBaselineStatus>,
) -> bool {
    result
        .findings
        .iter()
        .filter(|finding| !finding.is_suppressed)
        .any(|finding| {
            finding.severity >= severity
                && baseline_status_by_key
                    .get(&finding.baseline_key)
                    .is_some_and(|status| *status == baseline::FindingBaselineStatus::New)
        })
}

impl FailOn {
    fn is_new_findings_only(self) -> bool {
        matches!(self, Self::NewHigh | Self::NewMedium)
    }
}

fn run_rules(args: RulesArgs) -> anyhow::Result<u8> {
    let rules = rule_catalog();

    match args.format {
        OutputFormat::Json => {
            let json = rules
                .iter()
                .map(|rule| {
                    serde_json::json!({
                        "code": rule.code,
                        "name": rule.name,
                        "implemented": rule.implemented,
                        "severity": rule.default_severity,
                        "confidence": rule.default_confidence,
                        "language": rule.language,
                        "framework": rule.framework,
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Sarif | OutputFormat::Html | OutputFormat::Markdown => {
            let color = use_color(args.color);
            println!("Codehealth Rules\n");
            for rule in rules {
                let status = if rule.implemented {
                    "implemented"
                } else {
                    "planned"
                };
                println!(
                    "{}  {}  {}",
                    color_rule_status(status, color),
                    rule.code,
                    rule.name
                );
            }
        }
    }

    Ok(0)
}

fn color_rule_status(status: &str, use_color: bool) -> String {
    if !use_color {
        return status.to_string();
    }

    match status {
        "implemented" => format!("\x1b[32m{status}\x1b[0m"),
        _ => format!("\x1b[2m{status}\x1b[0m"),
    }
}

fn run_init(args: InitArgs) -> anyhow::Result<u8> {
    if args.path.exists() && !args.force {
        bail!(
            "{} already exists; use --force to overwrite it",
            args.path.display()
        );
    }

    if let Some(parent) = args.path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    std::fs::write(&args.path, default_config_toml())
        .with_context(|| format!("failed to write {}", args.path.display()))?;
    println!("Created {}", args.path.display());
    Ok(0)
}

fn run_config(command: ConfigCommand) -> anyhow::Result<u8> {
    match command {
        ConfigCommand::Validate(args) => {
            let cwd = std::env::current_dir().context("failed to determine current directory")?;
            let loaded = CodehealthConfig::validate_path(args.path.as_deref(), &cwd)
                .context("invalid codehealth config")?;
            if let Some(path) = loaded.path {
                println!("Config valid: {}", path.display());
            } else {
                println!("Config valid: defaults (no codehealth.toml found)");
            }
            Ok(0)
        }
    }
}

fn run_explain(args: ExplainArgs) -> anyhow::Result<u8> {
    let rule = find_rule(&args.finding_code)
        .with_context(|| format!("unknown finding code {}", args.finding_code))?;

    println!("{}", rule.code);
    println!("Name: {}", rule.name);
    println!(
        "Status: {}",
        if rule.implemented {
            "implemented"
        } else {
            "planned"
        }
    );
    println!("Severity: {}", rule.default_severity);
    println!("Confidence: {}", rule.default_confidence);
    println!("Explanation: {}", rule.explanation);
    println!("Why detected: {}", rule.detection_reason);
    println!("Suggested action: {}", rule.remediation);
    println!("Autofix: {:?}", rule.autofix);
    println!("Why not auto-fixed: {}", rule.autofix_explanation);

    Ok(0)
}

fn run_debug(command: DebugCommand) -> anyhow::Result<u8> {
    match command {
        DebugCommand::Parse(args) => {
            let parsed = parse_debug_file(&args.file)?;
            println!("Language: {}", parsed.source.language.name);
            println!("Bytes: {}", parsed.source.byte_len());
            println!("Root: {}", parsed.root_kind());
            println!("Has errors: {}", parsed.has_error());
            println!("Diagnostics: {}", parsed.diagnostics().len());
            for diagnostic in parsed.diagnostics().iter().take(10) {
                println!(
                    "  {}:{}:{} {}",
                    args.file.display(),
                    diagnostic.span.start_position.line,
                    diagnostic.span.start_position.column,
                    diagnostic.message
                );
            }
        }
        DebugCommand::Ast(args) => {
            let parsed = parse_debug_file(&args.file)?;
            println!("{}", parsed.sexp());
        }
        DebugCommand::Fingerprints(args) => {
            let source = std::fs::read_to_string(&args.file)
                .with_context(|| format!("failed to read {}", args.file.display()))?;
            let fingerprint = fingerprint_normalized_body(&source);
            println!("File: {}", args.file.display());
            println!("Normalized bytes: {}", normalize_source(&source).len());
            println!("Fast hash: {}", fingerprint.fast_hash);
            println!("Stable hash: {}", fingerprint.stable_hash_hex);
            let parser_registry = build_language_registry();
            let symbol_registry = build_symbol_registry();
            if let Ok(tree) = parse_debug_file_with_registry(&args.file, &parser_registry) {
                if let Some(language) = SymbolLanguage::from_info(tree.source.language) {
                    if let Some(extractor) = symbol_registry.extractor_for_language(language) {
                        let symbols = extractor.extract(&tree);
                        let mut printed_header = false;
                        for definition in symbols.definitions {
                            let Some(body_span) = definition.body_span else {
                                continue;
                            };
                            if body_span.end > source.len()
                                || !source.is_char_boundary(body_span.start)
                                || !source.is_char_boundary(body_span.end)
                            {
                                continue;
                            }
                            let body = &source[body_span.start..body_span.end];
                            let normalized = normalize_body_source(body);
                            if normalized.is_empty() {
                                continue;
                            }
                            let body_fingerprint = fingerprint_normalized_body(&normalized);
                            if !printed_header {
                                println!("Symbol bodies:");
                                printed_header = true;
                            }
                            println!(
                                "  {}  {}  lines={}  tokens={}  hash={}",
                                definition.kind.label(),
                                definition.qualified_name,
                                body.lines().count().max(1),
                                token_estimate(&normalized),
                                body_fingerprint.stable_hash_hex
                            );
                        }
                    }
                }
            }
        }
        DebugCommand::Canonical(args) => {
            run_debug_canonical(args)?;
        }
        DebugCommand::Symbols(args) => {
            let parser_registry = build_language_registry();
            let symbol_registry = build_symbol_registry();
            let tree = parse_debug_file_with_registry(&args.file, &parser_registry)?;
            let language = SymbolLanguage::from_info(tree.source.language)
                .with_context(|| format!("unsupported source file {}", args.file.display()))?;
            let extractor = symbol_registry
                .extractor_for_language(language)
                .with_context(|| {
                    format!("no symbol extractor for {}", tree.source.language.name)
                })?;
            let symbols = extractor.extract(&tree);
            println!("File: {}", args.file.display());
            println!("Language: {}", tree.source.language.name);
            println!("Definitions: {}", symbols.definitions.len());
            for definition in &symbols.definitions {
                let tags = definition
                    .framework_tags
                    .iter()
                    .map(|tag| tag.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "  {}  {}  {}  {}:{}{}",
                    definition.kind.label(),
                    definition.qualified_name,
                    definition.visibility.label(),
                    args.file.display(),
                    definition.span.start_position.line,
                    if tags.is_empty() {
                        String::new()
                    } else {
                        format!("  [{tags}]")
                    }
                );
            }
            println!("Imports: {}", symbols.imports.len());
            for import in &symbols.imports {
                println!(
                    "  import  {}  {}:{}",
                    import.module,
                    args.file.display(),
                    import.span.start_position.line
                );
            }
        }
        DebugCommand::Query(args) => {
            let registry = build_language_registry();
            let adapter = registry
                .adapter_for_path(&args.file)
                .with_context(|| format!("unsupported source file {}", args.file.display()))?;
            let tree = parse_debug_file_with_registry(&args.file, &registry)?;
            let kind: QueryKind = args.kind.into();
            let spec = adapter.query_source(kind).with_context(|| {
                format!(
                    "no {} query for {}",
                    kind.label(),
                    tree.source.language.name
                )
            })?;
            let language = adapter.tree_sitter_language().with_context(|| {
                format!(
                    "missing tree-sitter grammar for {}",
                    tree.source.language.name
                )
            })?;
            let matches = run_query(language, &tree, spec)?;
            println!("Language: {}", tree.source.language.name);
            println!("Query: {} v{}", kind.label(), spec.version);
            println!("Matches: {}", matches.len());
            for query_match in matches {
                println!("match {}", query_match.pattern_index);
                for capture in query_match.captures {
                    println!(
                        "  @{} {}:{}:{} {:?}",
                        capture.name,
                        args.file.display(),
                        capture.span.start_position.line,
                        capture.span.start_position.column,
                        capture.text
                    );
                }
            }
        }
        DebugCommand::Workspace(args) => {
            let cwd = std::env::current_dir().context("failed to determine current directory")?;
            let loaded_config = CodehealthConfig::load_with_metadata(args.config.as_deref(), &cwd)
                .context("failed to load codehealth config")?;
            let registry = build_language_registry();
            let scan = scan_workspace(
                &args.path,
                &registry,
                workspace_options_from_config(&loaded_config.config, &[]),
            )
            .context("failed to discover workspace files")?;
            print_workspace_debug(&scan);
        }
    }

    Ok(0)
}

fn run_debug_canonical(args: DebugCanonicalArgs) -> anyhow::Result<()> {
    let parser_registry = build_language_registry();
    let symbol_registry = build_symbol_registry();
    let tree = parse_debug_file_with_registry(&args.file, &parser_registry)?;
    let language = SymbolLanguage::from_info(tree.source.language)
        .with_context(|| format!("unsupported source file {}", args.file.display()))?;
    let extractor = symbol_registry
        .extractor_for_language(language)
        .with_context(|| format!("no symbol extractor for {}", tree.source.language.name))?;
    let symbols = extractor.extract(&tree);
    let definitions = symbols
        .definitions
        .into_iter()
        .filter(|definition| {
            if let Some(symbol) = args.symbol.as_ref() {
                definition.name == *symbol || definition.qualified_name == *symbol
            } else {
                true
            }
        })
        .filter(|definition| definition.structural_fingerprint.is_some())
        .collect::<Vec<_>>();

    if definitions.is_empty() {
        bail!(
            "no canonical fingerprints found for {}{}",
            args.file.display(),
            args.symbol
                .as_ref()
                .map(|symbol| format!(" matching '{symbol}'"))
                .unwrap_or_default()
        );
    }

    match args.format {
        DebugDumpFormat::Text => {
            println!("File: {}", args.file.display());
            println!("Language: {}", tree.source.language.name);
            println!("Canonical symbols: {}", definitions.len());
            for definition in &definitions {
                let fingerprint = definition
                    .structural_fingerprint
                    .as_ref()
                    .expect("filtered above");
                println!(
                    "  {}  {}",
                    definition.kind.label(),
                    definition.qualified_name
                );
                println!("    Canonical hash: {}", fingerprint.stable_hash_hex);
                println!("    Version: {}", fingerprint.version);
                println!("    Literal policy: {:?}", fingerprint.literal_policy);
                println!(
                    "    Nodes: {} (opaque: {})",
                    fingerprint.node_count, fingerprint.opaque_node_count
                );
                println!("    Tokens: {}", fingerprint.token_estimate);
                println!("    Return shape: {}", fingerprint.return_shape);
                if !fingerprint.call_names.is_empty() {
                    println!("    Calls: {}", fingerprint.call_names.join(", "));
                }
                if !fingerprint.slot_bindings.is_empty() {
                    println!("    Slot bindings:");
                    for binding in &fingerprint.slot_bindings {
                        println!(
                            "      {} -> {} ({})",
                            binding.original, binding.slot, binding.role
                        );
                    }
                }
                if !fingerprint.warnings.is_empty() {
                    println!("    Warnings:");
                    for warning in &fingerprint.warnings {
                        println!("      {warning}");
                    }
                }
                println!("    Serialization:");
                println!("      {}", fingerprint.serialization);
            }
        }
        DebugDumpFormat::Json => {
            let json = definitions
                .iter()
                .filter_map(|definition| {
                    definition
                        .structural_fingerprint
                        .as_ref()
                        .map(|fingerprint| {
                            serde_json::json!({
                                "kind": definition.kind.label(),
                                "name": &definition.name,
                                "qualified_name": &definition.qualified_name,
                                "language": definition.language.label(),
                                "fingerprint": fingerprint,
                            })
                        })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}

fn print_workspace_debug(scan: &WorkspaceScan) {
    println!("Root: {}", scan.root.display());
    println!("Files scanned: {}", scan.files.len());
    println!("Discovery files: {}", scan.discovery_files.len());
    println!("Config files: {}", scan.config_files.len());
    println!("Skipped files: {}", scan.skipped.len());

    let package_managers = scan
        .metadata
        .package_managers
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Package managers: {}",
        if package_managers.is_empty() {
            "none"
        } else {
            &package_managers
        }
    );

    let frameworks = scan.metadata.frameworks().join(", ");
    println!(
        "Frameworks: {}",
        if frameworks.is_empty() {
            "none"
        } else {
            &frameworks
        }
    );

    if !scan.metadata.rust.workspace_members.is_empty() {
        println!(
            "Rust workspace members: {}",
            scan.metadata.rust.workspace_members.join(", ")
        );
    }

    if !scan.skipped.is_empty() {
        println!("Skipped:");
        for skipped in scan.skipped.iter().take(25) {
            println!(
                "  {} - {}",
                format_debug_path(&scan.root, &skipped.path),
                skipped.reason.label()
            );
        }
    }
}

fn format_debug_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn parse_debug_file(path: &Path) -> anyhow::Result<SyntaxTree> {
    let registry = build_language_registry();
    parse_debug_file_with_registry(path, &registry)
}

fn parse_debug_file_with_registry(
    path: &Path,
    registry: &LanguageRegistry,
) -> anyhow::Result<SyntaxTree> {
    let adapter = registry
        .adapter_for_path(path)
        .with_context(|| format!("unsupported source file {}", path.display()))?;
    let source = SourceFile::from_path(path, adapter.info())
        .with_context(|| format!("failed to read {}", path.display()))?;

    adapter
        .parse(&source)
        .with_context(|| format!("failed to parse {}", path.display()))
}

fn use_color(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Auto => std::io::stdout().is_terminal(),
        ColorChoice::Always => true,
        ColorChoice::Never => false,
    }
}

fn config_hash(config: &CodehealthConfig) -> anyhow::Result<String> {
    let raw = serde_json::to_vec(config)?;
    let digest = Sha256::digest(raw);
    Ok(format!("{digest:x}"))
}

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn parse_jobs(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "jobs must be a positive integer".to_string())?;
    if parsed == 0 {
        return Err("jobs must be greater than zero".to_string());
    }

    Ok(parsed)
}

fn build_language_registry() -> LanguageRegistry {
    let mut registry = LanguageRegistry::new();
    codehealth_language_typescript::register(&mut registry);
    codehealth_language_python::register(&mut registry);
    codehealth_language_rust::register(&mut registry);
    registry
}

fn build_symbol_registry() -> SymbolRegistry {
    let mut registry = SymbolRegistry::new();
    codehealth_language_typescript::register_symbols(&mut registry);
    codehealth_language_python::register_symbols(&mut registry);
    codehealth_language_rust::register_symbols(&mut registry);
    registry
}

#[allow(dead_code)]
fn default_config_path() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    Ok(config_path(None, &cwd))
}
