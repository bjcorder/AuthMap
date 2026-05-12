use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use authmap_analysis::{run_scan, suggest_rules};
use authmap_config::{ScanConfig, ScanPlan, load_config};
use authmap_core::{AuthMapDocument, ScanMode, diagnostic_codes};
use authmap_report::{
    JsonReporter, MarkdownReporter, Reporter, SarifReporter, render_explain,
    render_rule_suggestions_json, render_rule_suggestions_markdown, write_atomic,
};
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
        #[arg(long)]
        max_files: Option<usize>,
        #[arg(long)]
        max_file_size_bytes: Option<u64>,
        #[arg(long)]
        max_total_bytes: Option<u64>,
        #[arg(long)]
        max_runtime_ms: Option<u64>,
    },
    Diff {
        range: String,
    },
    Explain {
        id: String,
        #[arg(long, default_value = "authmap.json")]
        input: PathBuf,
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
    Suggest {
        #[arg(default_value = ".")]
        target: PathBuf,
        #[arg(long, value_enum, default_value_t = RuleSuggestOutputFormat::Markdown)]
        format: RuleSuggestOutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        max_files: Option<usize>,
        #[arg(long)]
        max_file_size_bytes: Option<u64>,
        #[arg(long)]
        max_total_bytes: Option<u64>,
        #[arg(long)]
        max_runtime_ms: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RuleSuggestOutputFormat {
    Markdown,
    Json,
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
            max_files,
            max_file_size_bytes,
            max_total_bytes,
            max_runtime_ms,
        } => {
            let (config_path, mut config) = load_config(config).map_err(CliError::Config)?;
            if let Some(mode) = mode {
                config.mode = mode.into();
            }
            apply_limit_overrides(
                &mut config,
                LimitOverrides {
                    max_files,
                    max_file_size_bytes,
                    max_total_bytes,
                    max_runtime_ms,
                },
            )?;
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
        Command::Explain { id, input } => run_explain(&id, &input),
        Command::Baseline {
            command: BaselineCommand::Create,
        } => Err(CliError::NotImplemented("authmap baseline create")),
        Command::Rules {
            command:
                RulesCommand::Suggest {
                    target,
                    format,
                    output,
                    config,
                    max_files,
                    max_file_size_bytes,
                    max_total_bytes,
                    max_runtime_ms,
                },
        } => run_rules_suggest(
            target,
            format,
            output,
            config,
            LimitOverrides {
                max_files,
                max_file_size_bytes,
                max_total_bytes,
                max_runtime_ms,
            },
        ),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct LimitOverrides {
    max_files: Option<usize>,
    max_file_size_bytes: Option<u64>,
    max_total_bytes: Option<u64>,
    max_runtime_ms: Option<u64>,
}

fn apply_limit_overrides(
    config: &mut ScanConfig,
    overrides: LimitOverrides,
) -> Result<(), CliError> {
    if let Some(value) = overrides.max_files {
        if value == 0 {
            return Err(CliError::InvalidCliLimit(
                "max-files",
                "must be greater than zero",
            ));
        }
        config.limits.max_files = value;
    }
    if let Some(value) = overrides.max_file_size_bytes {
        if value == 0 {
            return Err(CliError::InvalidCliLimit(
                "max-file-size-bytes",
                "must be greater than zero",
            ));
        }
        config.limits.max_file_size_bytes = value;
    }
    if let Some(value) = overrides.max_total_bytes {
        if value == 0 {
            return Err(CliError::InvalidCliLimit(
                "max-total-bytes",
                "must be greater than zero",
            ));
        }
        config.limits.max_total_bytes = value;
    }
    if let Some(value) = overrides.max_runtime_ms {
        if value == 0 {
            return Err(CliError::InvalidCliLimit(
                "max-runtime-ms",
                "must be greater than zero",
            ));
        }
        config.limits.max_runtime_ms = value;
    }
    Ok(())
}

fn run_rules_suggest(
    target: PathBuf,
    format: RuleSuggestOutputFormat,
    output: Option<PathBuf>,
    config: Option<PathBuf>,
    limit_overrides: LimitOverrides,
) -> Result<ExitCode, CliError> {
    let (config_path, mut config) = load_config(config).map_err(CliError::Config)?;
    apply_limit_overrides(&mut config, limit_overrides)?;
    let plan = ScanPlan::new(vec![target], config_path, config);
    let suggestions = suggest_rules(&plan).map_err(CliError::Scan)?;
    let rendered = match format {
        RuleSuggestOutputFormat::Markdown => render_rule_suggestions_markdown(&suggestions),
        RuleSuggestOutputFormat::Json => {
            render_rule_suggestions_json(&suggestions).map_err(CliError::Report)?
        }
    };

    if let Some(output) = output {
        write_atomic(&output, &rendered).map_err(CliError::Report)?;
    } else {
        println!("{rendered}");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_explain(id: &str, input: &Path) -> Result<ExitCode, CliError> {
    let text = fs::read_to_string(input).map_err(|source| CliError::ExplainRead {
        path: input.to_path_buf(),
        source,
    })?;
    let document: AuthMapDocument =
        serde_json::from_str(&text).map_err(|source| CliError::ExplainParse {
            path: input.to_path_buf(),
            source,
        })?;
    let rendered = render_explain(&document, id).map_err(CliError::Explain)?;
    print!("{rendered}");
    Ok(ExitCode::SUCCESS)
}

fn run_init(output: &Path, yes: bool, force: bool) -> Result<ExitCode, CliError> {
    if output
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(CliError::InitSymlink(output.to_path_buf()));
    }
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
  max_total_bytes: 268435456
  max_runtime_ms: 120000

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
    #[error(transparent)]
    Explain(#[from] authmap_report::ExplainError),
    #[error("failed to read AuthMap input {path}: {source}")]
    ExplainRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse AuthMap JSON {path}: {source}")]
    ExplainParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("refusing to overwrite existing config {0}; pass --force to replace it")]
    InitExists(PathBuf),
    #[error("refusing to overwrite symlinked init config {0}")]
    InitSymlink(PathBuf),
    #[error("failed to read init prompt response: {0}")]
    InitIo(std::io::Error),
    #[error("failed to write init config {path}: {source}")]
    InitWrite {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid CLI limit --{0}: {1}")]
    InvalidCliLimit(&'static str, &'static str),
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
            CliError::ExplainRead { .. } => 10,
            CliError::ExplainParse { .. } => 12,
            CliError::Explain(_) => 13,
            CliError::InitExists(_) | CliError::InitSymlink(_) => 15,
            CliError::InitIo(_) | CliError::InitWrite { .. } => 14,
            CliError::InvalidCliLimit(_, _) => 2,
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
            CliError::ExplainRead { .. } => diagnostic_codes::CONFIG_READ_FAILED,
            CliError::ExplainParse { .. } => diagnostic_codes::CONFIG_PARSE_FAILED,
            CliError::Explain(_) => diagnostic_codes::REPORT_RENDER_FAILED,
            CliError::InitExists(_) | CliError::InitSymlink(_) => {
                diagnostic_codes::CONFIG_VALIDATION_FAILED
            }
            CliError::InitIo(_) | CliError::InitWrite { .. } => {
                diagnostic_codes::REPORT_WRITE_FAILED
            }
            CliError::InvalidCliLimit(_, _) => diagnostic_codes::CONFIG_VALIDATION_FAILED,
            CliError::NotImplemented(_) | CliError::NotImplementedWithArg(_, _) => {
                diagnostic_codes::INTERNAL_SCAN_FAILED
            }
        }
    }
}
