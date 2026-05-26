use anyhow::{bail, Context};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use codehealth_config::{config_path, default_config_toml, CodehealthConfig, DEFAULT_CONFIG_FILE};
use codehealth_core::{Confidence, Finding, FindingFilters, ScanMode, ScanResult, Severity};
use codehealth_duplication::{
    find_exact_file_duplicates, fingerprint_normalized_body, normalize_source, DuplicateInput,
};
use codehealth_parser::{LanguageRegistry, ParseInput};
use codehealth_reporters::{render_result, ReportFormat, ReportOptions};
use codehealth_rules::{find_rule, rule_catalog};
use codehealth_workspace::{discover_files, WorkspaceFile};
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
    #[arg(default_value = DEFAULT_CONFIG_FILE)]
    path: PathBuf,
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
}

#[derive(Debug, Args)]
struct DebugFileArgs {
    file: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
    Html,
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
    #[value(name = "new-medium")]
    NewMedium,
}

fn run_scan(args: RunArgs, mode: ScanMode) -> anyhow::Result<u8> {
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    let config = CodehealthConfig::load(args.config.as_deref(), &cwd)
        .context("failed to load codehealth config")?;
    let format = args
        .format
        .unwrap_or_else(|| OutputFormat::from_config(&config.report.default_format));
    let filters = filters_from_args(&args);

    let registry = build_language_registry();
    let files =
        discover_files(&args.path, &registry).context("failed to discover workspace files")?;
    let files = filter_files_by_language(files, &args.language);
    let mut result = ScanResult::new(args.path.canonicalize().unwrap_or(args.path.clone()));
    result.stats.files_scanned = files.len();

    let _accepted_but_not_active_yet = (
        args.jobs,
        args.no_cache,
        &args.cache_dir,
        args.fix,
        args.fix_safe,
        args.dry_run,
    );

    let findings = match mode {
        ScanMode::All | ScanMode::DuplicatesOnly => run_duplicate_checks(&files)?,
    };

    result.findings = findings
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

    if should_fail(&result, args.fail_on, args.baseline.as_ref(), &config)? {
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

fn filter_files_by_language(
    files: Vec<WorkspaceFile>,
    languages: &[LanguageArg],
) -> Vec<WorkspaceFile> {
    if languages.is_empty() {
        return files;
    }

    files
        .into_iter()
        .filter(|file| {
            languages
                .iter()
                .any(|language| language.as_str().eq_ignore_ascii_case(file.language.name))
        })
        .collect()
}

fn run_duplicate_checks(files: &[WorkspaceFile]) -> anyhow::Result<Vec<Finding>> {
    let inputs = files
        .iter()
        .map(|file| DuplicateInput {
            path: file.path.clone(),
            language: file.language.name.to_string(),
        })
        .collect::<Vec<_>>();

    find_exact_file_duplicates(&inputs).context("failed to detect exact duplicates")
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
    config: &CodehealthConfig,
) -> anyhow::Result<bool> {
    let Some(fail_on) = fail_on else {
        return Ok(false);
    };

    match fail_on {
        FailOn::High => Ok(result
            .findings
            .iter()
            .any(|finding| finding.severity >= Severity::High)),
        FailOn::NewMedium => {
            let baseline_path = baseline_path
                .cloned()
                .or_else(|| config.ci.baseline.clone())
                .unwrap_or_else(|| PathBuf::from(".codehealth/baseline.json"));
            let baseline = load_baseline_keys(&baseline_path)?;

            Ok(result.findings.iter().any(|finding| {
                finding.severity >= Severity::Medium && !baseline.contains(&finding.baseline_key)
            }))
        }
    }
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
            CodehealthConfig::validate_path(&args.path)
                .with_context(|| format!("invalid config {}", args.path.display()))?;
            println!("Config valid: {}", args.path.display());
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
            println!("Language: {}", parsed.language.name);
            println!("Bytes: {}", parsed.byte_len);
            println!("Root: {}", parsed.root_kind);
            println!("Has errors: {}", parsed.has_error);
        }
        DebugCommand::Ast(args) => {
            let parsed = parse_debug_file(&args.file)?;
            println!("{}", parsed.sexp);
        }
        DebugCommand::Fingerprints(args) => {
            let source = std::fs::read_to_string(&args.file)
                .with_context(|| format!("failed to read {}", args.file.display()))?;
            let fingerprint = fingerprint_normalized_body(&source);
            println!("File: {}", args.file.display());
            println!("Normalized bytes: {}", normalize_source(&source).len());
            println!("Fast hash: {}", fingerprint.fast_hash);
            println!("Stable hash: {}", fingerprint.stable_hash_hex);
        }
        DebugCommand::Symbols(args) => {
            let registry = build_language_registry();
            let language = registry
                .language_for_path(&args.file)
                .with_context(|| format!("unsupported source file {}", args.file.display()))?;
            println!("File: {}", args.file.display());
            println!("Language: {}", language.name);
            println!("Symbols: 0");
        }
    }

    Ok(0)
}

fn parse_debug_file(path: &Path) -> anyhow::Result<codehealth_parser::ParsedFile> {
    let registry = build_language_registry();
    let adapter = registry
        .adapter_for_path(path)
        .with_context(|| format!("unsupported source file {}", path.display()))?;
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    adapter
        .parse(ParseInput {
            path,
            source: &source,
        })
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

#[allow(dead_code)]
fn default_config_path() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    Ok(config_path(None, &cwd))
}
