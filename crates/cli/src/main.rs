use anyhow::{bail, Context};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use codehealth_config::{
    config_path, default_config_toml, parse_suppressions, path_matches_any, CodehealthConfig,
    LoadedConfig, SuppressionDirective, DEFAULT_CONFIG_FILE,
};
use codehealth_core::{
    Confidence, Finding, FindingFilters, ScanMode, ScanResult, Severity, Suppression,
    SuppressionKind,
};
use codehealth_duplication::{
    find_exact_body_duplicates, find_exact_file_duplicates, fingerprint_normalized_body,
    normalize_body_source, normalize_source, token_estimate, DuplicateInput, ExactBodyOptions,
};
use codehealth_parser::{run_query, LanguageRegistry, QueryKind, SourceFile, SyntaxTree};
use codehealth_reporters::{render_result, ReportFormat, ReportOptions};
use codehealth_rules::{canonical_rule_id, find_rule, rule_catalog};
use codehealth_symbols::{
    build_symbol_index, find_duplicate_fastapi_route_findings, find_duplicate_name_findings,
    Language as SymbolLanguage, SymbolIndex, SymbolInput, SymbolRegistry,
};
use codehealth_workspace::{scan_workspace, WorkspaceFile, WorkspaceScan, WorkspaceScanOptions};
use std::{
    collections::BTreeSet,
    io::IsTerminal,
    path::{Path, PathBuf},
    process::ExitCode,
};

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
    Ast(DebugFileArgs),
    Query(DebugQueryArgs),
    Workspace(DebugWorkspaceArgs),
}

#[derive(Debug, Args)]
struct DebugFileArgs {
    file: PathBuf,
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
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    let loaded_config = CodehealthConfig::load_with_metadata(args.config.as_deref(), &cwd)
        .context("failed to load codehealth config")?;
    let config = &loaded_config.config;
    let format = args
        .format
        .unwrap_or_else(|| OutputFormat::from_config(&config.report.default_format));
    let filters = filters_from_args(&args);

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
    let files = workspace_scan.files;
    result.stats.files_scanned = files.len();

    let symbol_registry = build_symbol_registry();
    let should_index_symbols = mode == ScanMode::All
        || (config.duplication.enabled
            && (config.duplication.detect_names
                || config.duplication.detect_exact
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

    let _accepted_but_not_active_yet = (
        args.jobs,
        args.no_cache,
        &args.cache_dir,
        args.fix,
        args.fix_safe,
        args.dry_run,
    );

    let findings = match mode {
        ScanMode::All | ScanMode::DuplicatesOnly => {
            run_duplicate_checks(&files, config, symbol_index.as_ref())?
        }
    };

    result.findings = apply_config_policy(
        findings,
        &result.root,
        config,
        &files,
        args.show_suppressed,
        &mut result.stats.suppressed_findings,
    )?
    .into_iter()
    .filter(|finding| filters.allows(finding))
    .collect();
    let result = result.finalize();

    let output = render_result(
        &result,
        ReportOptions::new(format.into(), use_color(args.color)),
    )
    .context("failed to render report")?;
    write_or_print(args.output.as_deref(), &output)?;

    if should_fail(
        &result,
        args.fail_on,
        args.baseline.as_ref(),
        &loaded_config,
    )? {
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

    if config.fastapi.enabled && config.fastapi.detect_duplicate_routes {
        if let Some(symbol_index) = symbol_index {
            findings.extend(find_duplicate_fastapi_route_findings(symbol_index));
        }
    }

    Ok(findings)
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

fn symbol_inputs_from_files(files: &[WorkspaceFile]) -> Vec<SymbolInput> {
    files
        .iter()
        .map(|file| SymbolInput {
            path: file.path.clone(),
            language: file.language,
        })
        .collect()
}

fn apply_config_policy(
    findings: Vec<Finding>,
    root: &Path,
    config: &CodehealthConfig,
    files: &[WorkspaceFile],
    show_suppressed: bool,
    suppressed_count: &mut usize,
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
    fail_on: Option<FailOn>,
    baseline_path: Option<&PathBuf>,
    loaded_config: &LoadedConfig,
) -> anyhow::Result<bool> {
    let fail_on_values = if let Some(fail_on) = fail_on {
        vec![fail_on]
    } else if loaded_config.path.is_some() {
        loaded_config
            .config
            .ci
            .fail_on
            .iter()
            .filter_map(|value| config_fail_on(value))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    if fail_on_values.is_empty() {
        return Ok(false);
    }

    for fail_on in fail_on_values {
        let should_fail = match fail_on {
            FailOn::High => result
                .findings
                .iter()
                .filter(|finding| !finding.is_suppressed)
                .any(|finding| finding.severity >= Severity::High),
            FailOn::NewHigh => has_new_finding_at_or_above(
                result,
                Severity::High,
                baseline_path,
                &loaded_config.config,
            )?,
            FailOn::NewMedium => has_new_finding_at_or_above(
                result,
                Severity::Medium,
                baseline_path,
                &loaded_config.config,
            )?,
        };

        if should_fail {
            return Ok(true);
        }
    }

    Ok(false)
}

fn config_fail_on(value: &str) -> Option<FailOn> {
    match value {
        "high" => Some(FailOn::High),
        "new_high" => Some(FailOn::NewHigh),
        "new_medium" => Some(FailOn::NewMedium),
        _ => None,
    }
}

fn has_new_finding_at_or_above(
    result: &ScanResult,
    severity: Severity,
    baseline_path: Option<&PathBuf>,
    config: &CodehealthConfig,
) -> anyhow::Result<bool> {
    let baseline_path = baseline_path
        .cloned()
        .or_else(|| config.ci.baseline.clone())
        .unwrap_or_else(|| PathBuf::from(".codehealth/baseline.json"));
    let baseline = load_baseline_keys(&baseline_path)?;

    Ok(result
        .findings
        .iter()
        .filter(|finding| !finding.is_suppressed)
        .any(|finding| finding.severity >= severity && !baseline.contains(&finding.baseline_key)))
}

fn load_baseline_keys(path: &Path) -> anyhow::Result<BTreeSet<String>> {
    if !path.exists() {
        eprintln!(
            "warning: baseline {} does not exist; treating it as empty",
            path.display()
        );
        return Ok(BTreeSet::new());
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    let result: ScanResult = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse baseline {}", path.display()))?;

    Ok(result
        .findings
        .into_iter()
        .map(|finding| finding.baseline_key)
        .collect())
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
        OutputFormat::Text | OutputFormat::Sarif | OutputFormat::Html => {
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
