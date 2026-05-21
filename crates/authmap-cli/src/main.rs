use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use authmap_analysis::{
    DriftConfigMetadata, analyze_controls_with_config, analyze_drift_with_config, run_scan,
    suggest_rules,
};
use authmap_config::{DriftFailCategory, ScanConfig, ScanPlan, load_config};
use authmap_core::{AuthMapDocument, SCHEMA_VERSION, ScanMode, diagnostic_codes};
use authmap_report::{
    JsonReporter, MarkdownReporter, Reporter, SarifReporter, render_controls_json,
    render_controls_markdown, render_drift_json, render_drift_markdown, render_explain,
    render_routes_json, render_routes_markdown, render_rule_suggestions_json,
    render_rule_suggestions_markdown, render_tenants_json, render_tenants_markdown, write_atomic,
};
use clap::{Parser, Subcommand, ValueEnum};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    author,
    name = "authmap",
    version = CLI_VERSION,
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
    Routes {
        #[arg(default_value = ".")]
        target: PathBuf,
        #[arg(long, value_enum, default_value_t = RoutesOutputFormat::Markdown)]
        format: RoutesOutputFormat,
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
    Tenants {
        #[arg(default_value = ".")]
        target: PathBuf,
        #[arg(long, value_enum, default_value_t = RoutesOutputFormat::Markdown)]
        format: RoutesOutputFormat,
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
        range: Option<String>,
        #[arg(long)]
        base: Option<PathBuf>,
        #[arg(long)]
        head: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = DiffOutputFormat::Markdown)]
        format: DiffOutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, value_enum)]
        mode: Option<ScanModeArg>,
        #[arg(long, default_value = ".")]
        target: PathBuf,
        #[arg(long)]
        fail_on: Option<String>,
    },
    Controls {
        range: Option<String>,
        #[arg(long)]
        base: Option<PathBuf>,
        #[arg(long)]
        head: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = DiffOutputFormat::Markdown)]
        format: DiffOutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, value_enum)]
        mode: Option<ScanModeArg>,
        #[arg(long, default_value = ".")]
        target: PathBuf,
        #[arg(long)]
        fail_on: Option<String>,
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
enum RoutesOutputFormat {
    Markdown,
    Json,
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
    Create {
        #[arg(default_value = ".")]
        target: PathBuf,
        #[arg(long, default_value = "authmap.baseline.json")]
        output: PathBuf,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum DiffOutputFormat {
    Markdown,
    Json,
}

const CLI_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (schema 0.1.0)");
const MAX_AUTHMAP_INPUT_BYTES: u64 = 64 * 1024 * 1024;

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
        Command::Routes {
            target,
            format,
            output,
            config,
            mode,
            max_files,
            max_file_size_bytes,
            max_total_bytes,
            max_runtime_ms,
        } => run_routes(RoutesArgs {
            target,
            format,
            output,
            config,
            mode,
            max_files,
            max_file_size_bytes,
            max_total_bytes,
            max_runtime_ms,
        }),
        Command::Tenants {
            target,
            format,
            output,
            config,
            mode,
            max_files,
            max_file_size_bytes,
            max_total_bytes,
            max_runtime_ms,
        } => run_tenants(RoutesArgs {
            target,
            format,
            output,
            config,
            mode,
            max_files,
            max_file_size_bytes,
            max_total_bytes,
            max_runtime_ms,
        }),
        Command::Diff {
            range,
            base,
            head,
            format,
            output,
            config,
            mode,
            target,
            fail_on,
        } => run_diff(DiffArgs {
            range,
            base,
            head,
            format,
            output,
            config,
            mode,
            target,
            fail_on,
        }),
        Command::Controls {
            range,
            base,
            head,
            format,
            output,
            config,
            mode,
            target,
            fail_on,
        } => run_controls(DiffArgs {
            range,
            base,
            head,
            format,
            output,
            config,
            mode,
            target,
            fail_on,
        }),
        Command::Explain { id, input } => run_explain(&id, &input),
        Command::Baseline {
            command:
                BaselineCommand::Create {
                    target,
                    output,
                    config,
                    mode,
                    max_files,
                    max_file_size_bytes,
                    max_total_bytes,
                    max_runtime_ms,
                },
        } => run_baseline_create(
            target,
            output,
            config,
            mode,
            LimitOverrides {
                max_files,
                max_file_size_bytes,
                max_total_bytes,
                max_runtime_ms,
            },
        ),
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

#[derive(Clone, Debug)]
struct RoutesArgs {
    target: PathBuf,
    format: RoutesOutputFormat,
    output: Option<PathBuf>,
    config: Option<PathBuf>,
    mode: Option<ScanModeArg>,
    max_files: Option<usize>,
    max_file_size_bytes: Option<u64>,
    max_total_bytes: Option<u64>,
    max_runtime_ms: Option<u64>,
}

fn run_routes(args: RoutesArgs) -> Result<ExitCode, CliError> {
    let (config_path, mut config) = load_config(args.config).map_err(CliError::Config)?;
    if let Some(mode) = args.mode {
        config.mode = mode.into();
    }
    apply_limit_overrides(
        &mut config,
        LimitOverrides {
            max_files: args.max_files,
            max_file_size_bytes: args.max_file_size_bytes,
            max_total_bytes: args.max_total_bytes,
            max_runtime_ms: args.max_runtime_ms,
        },
    )?;
    let plan = ScanPlan::new(vec![args.target], config_path, config);
    let document = run_scan(&plan).map_err(CliError::Scan)?;
    let rendered = match args.format {
        RoutesOutputFormat::Markdown => render_routes_markdown(&document),
        RoutesOutputFormat::Json => render_routes_json(&document).map_err(CliError::Report)?,
    };

    if let Some(output) = args.output {
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

fn run_tenants(args: RoutesArgs) -> Result<ExitCode, CliError> {
    let (config_path, mut config) = load_config(args.config).map_err(CliError::Config)?;
    if let Some(mode) = args.mode {
        config.mode = mode.into();
    }
    apply_limit_overrides(
        &mut config,
        LimitOverrides {
            max_files: args.max_files,
            max_file_size_bytes: args.max_file_size_bytes,
            max_total_bytes: args.max_total_bytes,
            max_runtime_ms: args.max_runtime_ms,
        },
    )?;
    let plan = ScanPlan::new(vec![args.target], config_path, config);
    let document = run_scan(&plan).map_err(CliError::Scan)?;
    let rendered = match args.format {
        RoutesOutputFormat::Markdown => render_tenants_markdown(&document),
        RoutesOutputFormat::Json => render_tenants_json(&document).map_err(CliError::Report)?,
    };

    if let Some(output) = args.output {
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

#[derive(Clone, Debug)]
struct DiffArgs {
    range: Option<String>,
    base: Option<PathBuf>,
    head: Option<PathBuf>,
    format: DiffOutputFormat,
    output: Option<PathBuf>,
    config: Option<PathBuf>,
    mode: Option<ScanModeArg>,
    target: PathBuf,
    fail_on: Option<String>,
}

struct DiffInputContext {
    base_document: AuthMapDocument,
    head_document: AuthMapDocument,
    base_label: String,
    head_label: String,
    report_mode: ScanMode,
    fail_on: Vec<DriftFailCategory>,
    config_meta: DriftConfigMetadata,
}

fn run_baseline_create(
    target: PathBuf,
    output: PathBuf,
    config: Option<PathBuf>,
    mode: Option<ScanModeArg>,
    limit_overrides: LimitOverrides,
) -> Result<ExitCode, CliError> {
    let (config_path, mut config) = load_config(config).map_err(CliError::Config)?;
    if let Some(mode) = mode {
        config.mode = mode.into();
    }
    apply_limit_overrides(&mut config, limit_overrides)?;
    let plan = ScanPlan::new(vec![target], config_path, config);
    let document = run_scan(&plan).map_err(CliError::Scan)?;
    let rendered = JsonReporter.render(&document).map_err(CliError::Report)?;
    write_atomic(&output, &rendered).map_err(CliError::Report)?;
    if document.has_enforce_blocking_diagnostics() {
        Ok(ExitCode::from(20))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_diff(args: DiffArgs) -> Result<ExitCode, CliError> {
    let context = load_diff_input_context(&args)?;

    let report = analyze_drift_with_config(
        &context.base_document,
        &context.head_document,
        context.report_mode,
        &context.fail_on,
        context.base_label,
        context.head_label,
        context.config_meta,
    );
    let rendered = match args.format {
        DiffOutputFormat::Markdown => render_drift_markdown(&report),
        DiffOutputFormat::Json => render_drift_json(&report).map_err(CliError::Report)?,
    };

    if let Some(output) = args.output {
        write_atomic(&output, &rendered).map_err(CliError::Report)?;
    } else {
        println!("{rendered}");
    }

    if report.has_enforce_blocking_changes() {
        Ok(ExitCode::from(20))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_controls(args: DiffArgs) -> Result<ExitCode, CliError> {
    let context = load_diff_input_context(&args)?;

    let report = analyze_controls_with_config(
        &context.base_document,
        &context.head_document,
        context.report_mode,
        &context.fail_on,
        context.base_label,
        context.head_label,
        context.config_meta,
    );
    let rendered = match args.format {
        DiffOutputFormat::Markdown => render_controls_markdown(&report),
        DiffOutputFormat::Json => render_controls_json(&report).map_err(CliError::Report)?,
    };

    if let Some(output) = args.output {
        write_atomic(&output, &rendered).map_err(CliError::Report)?;
    } else {
        println!("{rendered}");
    }

    if report.has_enforce_blocking_findings() {
        Ok(ExitCode::from(20))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn load_diff_input_context(args: &DiffArgs) -> Result<DiffInputContext, CliError> {
    if args.base.is_some() != args.head.is_some() {
        return Err(CliError::InvalidDiffInput(
            "--base and --head must be provided together".to_string(),
        ));
    }
    if args.range.is_some() && (args.base.is_some() || args.head.is_some()) {
        return Err(CliError::InvalidDiffInput(
            "use either map-file diff or git range diff, not both".to_string(),
        ));
    }

    let context = if let (Some(base), Some(head)) = (&args.base, &args.head) {
        let (_config_path, mut config) =
            load_config(args.config.clone()).map_err(CliError::Config)?;
        if let Some(mode) = args.mode {
            config.mode = mode.into();
        }
        let fail_on = if let Some(fail_on) = args.fail_on.as_deref() {
            parse_fail_on(fail_on)?
        } else {
            config.drift.fail_on.clone()
        };
        let config_meta = args
            .config
            .as_ref()
            .map(|path| DriftConfigMetadata::external(path.display().to_string()))
            .unwrap_or_else(DriftConfigMetadata::none);
        DiffInputContext {
            base_document: read_authmap_document(base)?,
            head_document: read_authmap_document(head)?,
            base_label: base.display().to_string(),
            head_label: head.display().to_string(),
            report_mode: config.mode,
            fail_on,
            config_meta,
        }
    } else if let Some(range) = &args.range {
        validate_git_range_target(&args.target)?;
        let (base_ref, head_ref) = parse_git_range(range)?;
        let temp = tempfile::Builder::new()
            .prefix("authmap-diff-")
            .tempdir()
            .map_err(|source| CliError::TempDir {
                path: std::env::temp_dir(),
                source,
            })?;
        let base_dir = temp.path().join("base");
        let head_dir = temp.path().join("head");
        let archive_paths = git_diff_archive_paths(&args.target, args.config.as_deref())?;
        extract_git_ref(&base_ref, &base_dir, &archive_paths)?;
        extract_git_ref(&head_ref, &head_dir, &archive_paths)?;
        let (base_config_path, mut base_config, head_config_path, mut head_config, config_meta) =
            load_git_diff_configs(args.config.clone(), &base_dir, &head_dir)?;
        if let Some(mode) = args.mode {
            let mode = ScanMode::from(mode);
            base_config.mode = mode;
            head_config.mode = mode;
        }
        let report_mode = head_config.mode;
        let fail_on = if let Some(fail_on) = args.fail_on.as_deref() {
            parse_fail_on(fail_on)?
        } else {
            head_config.drift.fail_on.clone()
        };
        let base_document = run_scan(&ScanPlan::new(
            vec![base_dir.join(&args.target)],
            base_config_path,
            base_config,
        ))
        .map_err(CliError::Scan)?;
        let head_document = run_scan(&ScanPlan::new(
            vec![head_dir.join(&args.target)],
            head_config_path,
            head_config,
        ))
        .map_err(CliError::Scan)?;
        DiffInputContext {
            base_document,
            head_document,
            base_label: base_ref,
            head_label: head_ref,
            report_mode,
            fail_on,
            config_meta,
        }
    } else {
        return Err(CliError::InvalidDiffInput(
            "pass --base and --head map files, or a BASE...HEAD range".to_string(),
        ));
    };

    ensure_supported_document(&context.base_document, &context.base_label)?;
    ensure_supported_document(&context.head_document, &context.head_label)?;
    Ok(context)
}

fn validate_git_range_target(target: &Path) -> Result<(), CliError> {
    if target.is_absolute()
        || target
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CliError::InvalidDiffInput(
            "git range --target must be relative to the archived refs".to_string(),
        ));
    }
    Ok(())
}

fn validate_archive_relative_path(path: &Path, label: &str) -> Result<(), CliError> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CliError::InvalidDiffInput(format!(
            "git range {label} must be relative to the archived refs"
        )));
    }
    Ok(())
}

fn git_diff_archive_paths(target: &Path, config: Option<&Path>) -> Result<Vec<PathBuf>, CliError> {
    validate_archive_relative_path(target, "--target")?;
    let mut paths = vec![target.to_path_buf()];
    if let Some(config) = config
        && !config.is_absolute()
    {
        validate_archive_relative_path(config, "config")?;
        if !paths.iter().any(|path| path == config) {
            paths.push(config.to_path_buf());
        }
    }
    Ok(paths)
}

fn load_git_diff_configs(
    config: Option<PathBuf>,
    base_dir: &Path,
    head_dir: &Path,
) -> Result<
    (
        Option<PathBuf>,
        ScanConfig,
        Option<PathBuf>,
        ScanConfig,
        DriftConfigMetadata,
    ),
    CliError,
> {
    let Some(config) = config else {
        return Ok((
            None,
            ScanConfig::default(),
            None,
            ScanConfig::default(),
            DriftConfigMetadata::none(),
        ));
    };

    if config.is_absolute() {
        let (config_path, loaded) = load_config(Some(config.clone())).map_err(CliError::Config)?;
        return Ok((
            config_path.clone(),
            loaded.clone(),
            config_path,
            loaded,
            DriftConfigMetadata::external(config.display().to_string()),
        ));
    }

    validate_archive_relative_path(&config, "config")?;
    let (base_config_path, base_config) =
        load_config(Some(base_dir.join(&config))).map_err(CliError::Config)?;
    let (head_config_path, head_config) =
        load_config(Some(head_dir.join(&config))).map_err(CliError::Config)?;
    Ok((
        base_config_path,
        base_config,
        head_config_path,
        head_config,
        DriftConfigMetadata::per_ref(config.display().to_string()),
    ))
}

fn parse_fail_on(value: &str) -> Result<Vec<DriftFailCategory>, CliError> {
    let mut categories = Vec::new();
    for raw in value.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let category = match item {
            "added_high_risk_route" => DriftFailCategory::AddedHighRiskRoute,
            "added_review_required_route" => DriftFailCategory::AddedReviewRequiredRoute,
            "auth_downgrade" => DriftFailCategory::AuthDowngrade,
            "new_linked_mutation" => DriftFailCategory::NewLinkedMutation,
            "removed_authorization_evidence" => DriftFailCategory::RemovedAuthorizationEvidence,
            "policy_decision_change" => DriftFailCategory::PolicyDecisionChange,
            _ => return Err(CliError::InvalidDriftFailCategory(item.to_string())),
        };
        if !categories.contains(&category) {
            categories.push(category);
        }
    }
    Ok(categories)
}

fn parse_git_range(range: &str) -> Result<(String, String), CliError> {
    let Some((base, head)) = range.split_once("...") else {
        return Err(CliError::InvalidDiffInput(
            "git range must use BASE...HEAD".to_string(),
        ));
    };
    let base = validate_git_range_ref(base)?;
    let head = validate_git_range_ref(head)?;
    if base.is_empty() || head.is_empty() {
        return Err(CliError::InvalidDiffInput(
            "git range must include both BASE and HEAD".to_string(),
        ));
    }
    Ok((base.to_string(), head.to_string()))
}

fn validate_git_range_ref(ref_name: &str) -> Result<&str, CliError> {
    let trimmed = ref_name.trim();
    if trimmed.is_empty() {
        return Err(CliError::InvalidDiffInput(
            "git range must include both BASE and HEAD".to_string(),
        ));
    }
    if ref_name != trimmed
        || trimmed.starts_with('-')
        || ref_name
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(CliError::InvalidDiffInput(
            "git range refs must not start with '-' or contain whitespace/control characters"
                .to_string(),
        ));
    }
    Ok(trimmed)
}

fn read_authmap_document(path: &Path) -> Result<AuthMapDocument, CliError> {
    let text = read_authmap_input(path, |path, source| CliError::DiffRead { path, source })?;
    serde_json::from_str(&text).map_err(|source| CliError::DiffParse {
        path: path.to_path_buf(),
        source,
    })
}

fn read_authmap_input(
    path: &Path,
    read_error: impl Fn(PathBuf, std::io::Error) -> CliError,
) -> Result<String, CliError> {
    let metadata = fs::metadata(path).map_err(|source| read_error(path.to_path_buf(), source))?;
    if metadata.len() > MAX_AUTHMAP_INPUT_BYTES {
        return Err(CliError::InputTooLarge {
            path: path.to_path_buf(),
            limit: MAX_AUTHMAP_INPUT_BYTES,
        });
    }
    fs::read_to_string(path).map_err(|source| read_error(path.to_path_buf(), source))
}

fn ensure_supported_document(document: &AuthMapDocument, label: &str) -> Result<(), CliError> {
    if document.schema_version != SCHEMA_VERSION {
        return Err(CliError::InvalidDiffInput(format!(
            "{label} uses unsupported schema {}; expected {SCHEMA_VERSION}",
            document.schema_version
        )));
    }
    Ok(())
}

fn extract_git_ref(ref_name: &str, destination: &Path, paths: &[PathBuf]) -> Result<(), CliError> {
    fs::create_dir_all(destination).map_err(|source| CliError::TempDir {
        path: destination.to_path_buf(),
        source,
    })?;
    let mut archive_command = ProcessCommand::new("git");
    archive_command.args(["archive", "--format=tar", ref_name, "--"]);
    archive_command.args(paths);
    let mut archive = archive_command
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|source| CliError::GitArchive {
            ref_name: ref_name.to_string(),
            source,
        })?;
    let archive_stdout = archive
        .stdout
        .take()
        .ok_or_else(|| CliError::InvalidDiffInput("failed to capture git archive".to_string()))?;
    let status = ProcessCommand::new("tar")
        .arg("-xf")
        .arg("-")
        .arg("-C")
        .arg(destination)
        .stdin(Stdio::from(archive_stdout))
        .status()
        .map_err(|source| CliError::TarExtract {
            path: destination.to_path_buf(),
            source,
        })?;
    let archive_status = archive.wait().map_err(|source| CliError::GitArchive {
        ref_name: ref_name.to_string(),
        source,
    })?;
    if !archive_status.success() {
        return Err(CliError::InvalidDiffInput(format!(
            "git archive failed for ref {ref_name}"
        )));
    }
    if !status.success() {
        return Err(CliError::InvalidDiffInput(format!(
            "tar extraction failed for ref {ref_name}"
        )));
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
    let text = read_authmap_input(input, |path, source| CliError::ExplainRead { path, source })?;
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
    let overwrite = output.exists();

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
    write_init_config(output, &starter_config(include_examples), overwrite)?;
    println!("Created {}.", output.display());
    Ok(ExitCode::SUCCESS)
}

fn write_init_config(output: &Path, contents: &str, overwrite: bool) -> Result<(), CliError> {
    if overwrite {
        let metadata = output
            .symlink_metadata()
            .map_err(|source| CliError::InitWrite {
                path: output.to_path_buf(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::InitSymlink(output.to_path_buf()));
        }
        if !metadata.is_file() {
            return Err(CliError::InitWrite {
                path: output.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to overwrite non-regular file",
                ),
            });
        }
        fs::remove_file(output).map_err(|source| CliError::InitWrite {
            path: output.to_path_buf(),
            source,
        })?;
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|source| CliError::InitWrite {
            path: output.to_path_buf(),
            source,
        })?;
    file.write_all(contents.as_bytes())
        .map_err(|source| CliError::InitWrite {
            path: output.to_path_buf(),
            source,
        })
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

drift:
  fail_on:
    - added_high_risk_route
    - auth_downgrade
    - new_linked_mutation
    # Optional stricter semantic drift categories:
    # - removed_authorization_evidence
    # - policy_decision_change

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
# drift:
#   fail_on:
#     - added_high_risk_route
#     - added_review_required_route
#     - auth_downgrade
#     - new_linked_mutation
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
    #[error("failed to read AuthMap diff input {path}: {source}")]
    DiffRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse AuthMap diff input {path}: {source}")]
    DiffParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("AuthMap input {path} exceeds maximum size of {limit} bytes")]
    InputTooLarge { path: PathBuf, limit: u64 },
    #[error("invalid diff input: {0}")]
    InvalidDiffInput(String),
    #[error("invalid drift fail category {0}")]
    InvalidDriftFailCategory(String),
    #[error("failed to archive git ref {ref_name}: {source}")]
    GitArchive {
        ref_name: String,
        source: std::io::Error,
    },
    #[error("failed to extract git archive into {path}: {source}")]
    TarExtract {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to create temporary diff directory {path}: {source}")]
    TempDir {
        path: PathBuf,
        source: std::io::Error,
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
            CliError::DiffRead { .. } => 10,
            CliError::DiffParse { .. } => 12,
            CliError::InputTooLarge { .. } => 12,
            CliError::InvalidDiffInput(_) | CliError::InvalidDriftFailCategory(_) => 2,
            CliError::GitArchive { .. } | CliError::TarExtract { .. } => 13,
            CliError::TempDir { .. } => 14,
            CliError::InitExists(_) | CliError::InitSymlink(_) => 15,
            CliError::InitIo(_) | CliError::InitWrite { .. } => 14,
            CliError::InvalidCliLimit(_, _) => 2,
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
            CliError::DiffRead { .. } => diagnostic_codes::CONFIG_READ_FAILED,
            CliError::DiffParse { .. } => diagnostic_codes::CONFIG_PARSE_FAILED,
            CliError::InputTooLarge { .. } => diagnostic_codes::CONFIG_VALIDATION_FAILED,
            CliError::InvalidDiffInput(_) | CliError::InvalidDriftFailCategory(_) => {
                diagnostic_codes::CONFIG_VALIDATION_FAILED
            }
            CliError::GitArchive { .. } | CliError::TarExtract { .. } => {
                diagnostic_codes::INTERNAL_SCAN_FAILED
            }
            CliError::TempDir { .. } => diagnostic_codes::REPORT_WRITE_FAILED,
            CliError::InitExists(_) | CliError::InitSymlink(_) => {
                diagnostic_codes::CONFIG_VALIDATION_FAILED
            }
            CliError::InitIo(_) | CliError::InitWrite { .. } => {
                diagnostic_codes::REPORT_WRITE_FAILED
            }
            CliError::InvalidCliLimit(_, _) => diagnostic_codes::CONFIG_VALIDATION_FAILED,
        }
    }
}
