use std::path::PathBuf;
use std::process::ExitCode;

use authmap_analysis::run_scan;
use authmap_config::{ScanPlan, load_config};
use authmap_core::ScanMode;
use authmap_report::{JsonReporter, MarkdownReporter, Reporter, write_atomic};
use clap::{Parser, Subcommand, ValueEnum};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Authorization coverage mapping for application code."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Scan {
        #[arg(default_value = ".")]
        target: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, value_enum)]
        mode: Option<ScanModeArg>,
    },
    Diff {
        range: String,
    },
    Explain {
        id: String,
    },
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Json,
    Markdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ScanModeArg {
    Advisory,
    Enforce,
}

impl From<ScanModeArg> for ScanMode {
    fn from(value: ScanModeArg) -> Self {
        match value {
            ScanModeArg::Advisory => ScanMode::Advisory,
            ScanModeArg::Enforce => ScanMode::Enforce,
        }
    }
}

#[derive(Debug, Subcommand)]
enum BaselineCommand {
    Create,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    Suggest,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => Err(CliError::NotImplemented("authmap init")),
        Command::Scan {
            target,
            format,
            output,
            config,
            mode,
        } => {
            let (config_path, mut config) = load_config(config).map_err(CliError::Config)?;
            if let Some(mode) = mode {
                config.mode = mode.into();
            }
            let plan = ScanPlan::new(vec![target], config_path, config);
            let document = run_scan(&plan).map_err(CliError::Scan)?;
            let rendered = match format {
                OutputFormat::Json => JsonReporter.render(&document).map_err(CliError::Report)?,
                OutputFormat::Markdown => MarkdownReporter
                    .render(&document)
                    .map_err(CliError::Report)?,
            };

            if let Some(output) = output {
                write_atomic(&output, &rendered).map_err(CliError::Report)?;
            } else {
                println!("{rendered}");
            }
            Ok(())
        }
        Command::Diff { range } => Err(CliError::NotImplementedWithArg("authmap diff", range)),
        Command::Explain { id } => Err(CliError::NotImplementedWithArg("authmap explain", id)),
        Command::Baseline {
            command: BaselineCommand::Create,
        } => Err(CliError::NotImplemented("authmap baseline create")),
        Command::Rules {
            command: RulesCommand::Suggest,
        } => Err(CliError::NotImplemented("authmap rules suggest")),
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    Config(#[from] authmap_config::ConfigError),
    #[error(transparent)]
    Scan(#[from] authmap_analysis::ScanError),
    #[error(transparent)]
    Report(#[from] authmap_report::ReportError),
    #[error("{0} is scaffolded but not implemented yet")]
    NotImplemented(&'static str),
    #[error("{0} is scaffolded but not implemented yet: {1}")]
    NotImplementedWithArg(&'static str, String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            CliError::Config(_) => 12,
            CliError::Scan(error) if error.is_target_unavailable() => 10,
            CliError::Scan(error) if error.is_empty_target() => 11,
            CliError::Scan(_) => 13,
            CliError::Report(_) => 14,
            CliError::NotImplemented(_) | CliError::NotImplementedWithArg(_, _) => 13,
        }
    }
}
