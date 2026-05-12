use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use authmap_analysis::run_scan;
use authmap_config::{ScanPlan, load_config};
use authmap_core::{ScanMode, diagnostic_codes};
use authmap_report::{JsonReporter, MarkdownReporter, Reporter, SarifReporter, write_atomic};
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
    Init {
        #[arg(long, default_value = "authmap.yml")]
        output: PathBuf,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        force: bool,
    },
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
    Sarif,
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
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error [{}]: {error}", error.diagnostic_code());
            ExitCode::from(error.exit_code())
        }
    }
}

fn run() -> Result<ExitCode, CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { output, yes, force } => run_init(&output, yes, force),
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
                OutputFormat::Sarif => SarifReporter.render(&document).map_err(CliError::Report)?,
            };

            if let Some(output) = output {
                write_atomic(&output, &rendered).map_err(CliError::Report)?;
            } else {
                println!("{rendered}");
            }
            if document.has_enforce_blocking_diagnostics() {
                Ok(ExitCode::from(20))
            } else {
                Ok(ExitCode::SUCCESS)
            }
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

fn run_init(output: &Path, yes: bool, force: bool) -> Result<ExitCode, CliError> {
    if output.exists() && !force {
        if yes {
            return Err(CliError::InitExists(output.to_path_buf()));
        }
        if !prompt_yes_no(
            &format!("{} already exists. Overwrite it? [y/N]", output.display()),
            false,
        )? {
            println!("Left {} unchanged.", output.display());
            return Ok(ExitCode::SUCCESS);
        }
    }

    let include_examples = if yes {
        true
    } else {
        prompt_yes_no("Include commented starter examples? [Y/n]", true)?
    };
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| CliError::InitWrite {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(output, starter_config(include_examples)).map_err(|source| CliError::InitWrite {
        path: output.to_path_buf(),
        source,
    })?;
    println!("Created {}.", output.display());
    Ok(ExitCode::SUCCESS)
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool, CliError> {
    print!("{prompt} ");
    io::stdout().flush().map_err(CliError::InitIo)?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(CliError::InitIo)?;
    match input.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default),
    }
}

fn starter_config(include_examples: bool) -> String {
    let mut config = r#"# AuthMap project configuration.
# See docs/CONFIGURATION.md for the full format.

mode: advisory

# Limit scanning to project-owned source files when needed.
include: []
exclude: []

limits:
  max_files: 50000
  max_file_size_bytes: 2097152

authorization:
  rules: []

sensitivity:
  routes: []
  resources: []
"#
    .to_string();

    if include_examples {
        config.push_str(
            r#"
# Starter examples:
#
# authorization:
#   rules:
#     - name: FastAPI auth dependency
#       evidence_type: authn
#       mechanism: fastapi_dependency
#       match:
#         exact: [require_user]
#         contains: [current_user]
#     - name: Express role middleware
#       evidence_type: role_check
#       mechanism: express_middleware
#       match:
#         exact: [requireRole]
#         contains: [role]
#     - name: custom permission guard
#       evidence_type: permission_check
#       mechanism: custom_permission_guard
#       confidence: high
#       match:
#         exact: [requireBillingPermission]
#         contains: [permission]
#       notes:
#         - Project-specific permission helper.
#
# sensitivity:
#   routes:
#     - name: account routes
#       labels: [account_data]
#       match:
#         contains: [/accounts]
#       methods: [GET, POST, PATCH, DELETE]
#       reviewer_questions:
#         - Should account routes require ownership or permission checks?
#   resources:
#     - name: invoice mutations
#       labels: [financial]
#       match:
#         exact: [Invoice]
#       reviewer_questions:
#         - Should invoice writes require finance approval?
"#,
        );
    }

    config
}

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    Config(#[from] authmap_config::ConfigError),
    #[error(transparent)]
    Scan(#[from] authmap_analysis::ScanError),
    #[error(transparent)]
    Report(#[from] authmap_report::ReportError),
    #[error("refusing to overwrite existing config {0}; pass --force to replace it")]
    InitExists(PathBuf),
    #[error("failed to read init prompt response: {0}")]
    InitIo(std::io::Error),
    #[error("failed to write init config {path}: {source}")]
    InitWrite {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{0} is scaffolded but not implemented yet")]
    NotImplemented(&'static str),
    #[error("{0} is scaffolded but not implemented yet: {1}")]
    NotImplementedWithArg(&'static str, String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            CliError::Config(_) => 12,
            CliError::Scan(error) if error.is_config_error() => 12,
            CliError::Scan(error) if error.is_target_unavailable() => 10,
            CliError::Scan(error) if error.is_empty_target() => 11,
            CliError::Scan(_) => 13,
            CliError::Report(_) => 14,
            CliError::InitExists(_) => 15,
            CliError::InitIo(_) | CliError::InitWrite { .. } => 14,
            CliError::NotImplemented(_) | CliError::NotImplementedWithArg(_, _) => 13,
        }
    }

    fn diagnostic_code(&self) -> &'static str {
        match self {
            CliError::Config(authmap_config::ConfigError::Read { .. }) => {
                diagnostic_codes::CONFIG_READ_FAILED
            }
            CliError::Config(authmap_config::ConfigError::Parse { .. }) => {
                diagnostic_codes::CONFIG_PARSE_FAILED
            }
            CliError::Config(authmap_config::ConfigError::Validate { .. }) => {
                diagnostic_codes::CONFIG_VALIDATION_FAILED
            }
            CliError::Scan(authmap_analysis::ScanError::Discovery(
                authmap_discovery::DiscoveryError::InvalidPattern { .. },
            )) => diagnostic_codes::CONFIG_INVALID_PATTERN,
            CliError::Scan(authmap_analysis::ScanError::Discovery(
                authmap_discovery::DiscoveryError::TargetUnavailable { .. }
                | authmap_discovery::DiscoveryError::UnsupportedTarget { .. },
            )) => diagnostic_codes::DISCOVERY_TARGET_UNAVAILABLE,
            CliError::Scan(authmap_analysis::ScanError::Discovery(
                authmap_discovery::DiscoveryError::EmptyTarget { .. },
            )) => diagnostic_codes::DISCOVERY_EMPTY_TARGET,
            CliError::Scan(authmap_analysis::ScanError::Discovery(
                authmap_discovery::DiscoveryError::Metadata { .. },
            )) => diagnostic_codes::DISCOVERY_METADATA_FAILED,
            CliError::Report(authmap_report::ReportError::Json(_)) => {
                diagnostic_codes::REPORT_RENDER_FAILED
            }
            CliError::Report(authmap_report::ReportError::Write { .. }) => {
                diagnostic_codes::REPORT_WRITE_FAILED
            }
            CliError::InitExists(_) => diagnostic_codes::CONFIG_VALIDATION_FAILED,
            CliError::InitIo(_) | CliError::InitWrite { .. } => {
                diagnostic_codes::REPORT_WRITE_FAILED
            }
            CliError::NotImplemented(_) | CliError::NotImplementedWithArg(_, _) => {
                diagnostic_codes::INTERNAL_SCAN_FAILED
            }
        }
    }
}
