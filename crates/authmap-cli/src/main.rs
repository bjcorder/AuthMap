use std::path::PathBuf;

use authmap_analysis::run_scan;
use authmap_config::{ScanPlan, load_config};
use authmap_report::{JsonReporter, MarkdownReporter, Reporter, write_atomic};
use clap::{Parser, Subcommand, ValueEnum};
use miette::{IntoDiagnostic, Result};
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

#[derive(Debug, Subcommand)]
enum BaselineCommand {
    Create,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    Suggest,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => Err(CliError::NotImplemented("authmap init")).into_diagnostic(),
        Command::Scan {
            target,
            format,
            output,
            config,
        } => {
            let (config_path, config) = load_config(config).into_diagnostic()?;
            let plan = ScanPlan::new(vec![target], config_path, config);
            let document = run_scan(&plan).into_diagnostic()?;
            let rendered = match format {
                OutputFormat::Json => JsonReporter.render(&document).into_diagnostic()?,
                OutputFormat::Markdown => MarkdownReporter.render(&document).into_diagnostic()?,
            };

            if let Some(output) = output {
                write_atomic(&output, &rendered).into_diagnostic()?;
            } else {
                println!("{rendered}");
            }
            Ok(())
        }
        Command::Diff { range } => {
            Err(CliError::NotImplementedWithArg("authmap diff", range)).into_diagnostic()
        }
        Command::Explain { id } => {
            Err(CliError::NotImplementedWithArg("authmap explain", id)).into_diagnostic()
        }
        Command::Baseline {
            command: BaselineCommand::Create,
        } => Err(CliError::NotImplemented("authmap baseline create")).into_diagnostic(),
        Command::Rules {
            command: RulesCommand::Suggest,
        } => Err(CliError::NotImplemented("authmap rules suggest")).into_diagnostic(),
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("{0} is scaffolded but not implemented yet")]
    NotImplemented(&'static str),
    #[error("{0} is scaffolded but not implemented yet: {1}")]
    NotImplementedWithArg(&'static str, String),
}
