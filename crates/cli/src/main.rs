use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use codehealth_config::CodehealthConfig;
use codehealth_core::ScanResult;
use codehealth_parser::LanguageRegistry;
use codehealth_reporters::{render_result, ReportFormat};
use codehealth_workspace::discover_files;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "codehealth")]
#[command(version)]
#[command(about = "Local-first code health and duplication detector")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan(ScanArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

impl From<OutputFormat> for ReportFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Text => Self::Text,
            OutputFormat::Json => Self::Json,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(args) => scan(args),
    }
}

fn scan(args: ScanArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    let _config = CodehealthConfig::load(args.config.as_deref(), &cwd)
        .context("failed to load codehealth config")?;

    let registry = build_language_registry();
    let files =
        discover_files(&args.path, &registry).context("failed to discover workspace files")?;
    let root = args.path.canonicalize().unwrap_or(args.path);
    let mut result = ScanResult::new(root);
    result.files_scanned = files.len();

    let output = render_result(&result, args.format.into()).context("failed to render report")?;
    print!("{output}");

    Ok(())
}

fn build_language_registry() -> LanguageRegistry {
    let mut registry = LanguageRegistry::new();
    codehealth_language_typescript::register(&mut registry);
    codehealth_language_python::register(&mut registry);
    codehealth_language_rust::register(&mut registry);
    registry
}
