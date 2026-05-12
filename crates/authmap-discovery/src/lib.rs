use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use authmap_config::{ScanLimits, ScanPlan};
use authmap_core::{
    Diagnostic, DiagnosticCategory, DiagnosticSeverity, Language, ProjectHint, Recoverability,
    SkipReason, SourceFile, diagnostic_codes,
};
use ignore::overrides::{Override, OverrideBuilder};
use ignore::{DirEntry, WalkBuilder};
use thiserror::Error;

const HARD_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "coverage",
    ".authmap",
];

const HARD_EXCLUDED_FILES: &[&str] = &[
    "authmap.json",
    "authmap.md",
    "authmap.sarif",
    "authmap.sarif.json",
];

const MANIFEST_FILES: &[&str] = &[
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "manage.py",
];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryResult {
    pub files: Vec<SourceFile>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn discover_sources(plan: &ScanPlan) -> Result<DiscoveryResult, DiscoveryError> {
    let mut all_paths = Vec::new();
    let mut target_roots = Vec::new();
    let mut collection_capped = false;

    for target in &plan.targets {
        let metadata =
            fs::metadata(target).map_err(|source| DiscoveryError::TargetUnavailable {
                path: target.clone(),
                source,
            })?;

        if metadata.is_file() {
            all_paths.push(target.clone());
            target_roots.push(
                target
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
            );
            continue;
        }

        if !metadata.is_dir() {
            return Err(DiscoveryError::UnsupportedTarget {
                path: target.clone(),
            });
        }

        fs::read_dir(target).map_err(|source| DiscoveryError::TargetUnavailable {
            path: target.clone(),
            source,
        })?;

        target_roots.push(target.clone());
        let (walked_paths, capped) = walk_target(target, &plan.config.limits);
        collection_capped |= capped;
        all_paths.extend(walked_paths);
    }

    all_paths.sort();
    all_paths.dedup();

    let matchers = PatternMatchers::new(&plan.targets, &plan.config.include, &plan.config.exclude)?;

    let mut diagnostics = Vec::new();
    if collection_capped {
        diagnostics.push(diagnostic_with_severity(
            diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED,
            incomplete_scan_severity(plan.config.mode),
            format!(
                "discovery stopped after collecting a bounded sample of source and hint paths for limits.max_files={}",
                plan.config.limits.max_files
            ),
        ));
    }
    let mut candidates = Vec::new();
    let mut hint_paths = Vec::new();
    for path in all_paths {
        if is_hard_excluded_for_roots(&path, &target_roots) {
            continue;
        }
        if is_manifest_or_hint_file(&path) {
            hint_paths.push(path.clone());
        }
        if !is_supported_source(&path) || !matchers.is_included(&path) {
            continue;
        }
        if matchers.is_excluded(&path) {
            continue;
        }
        candidates.push(path);
    }

    if candidates.is_empty() {
        if plan.config.mode == authmap_core::ScanMode::Enforce {
            return Err(DiscoveryError::EmptyTarget {
                targets: plan.targets.clone(),
            });
        }
        diagnostics.push(diagnostic(
            diagnostic_codes::DISCOVERY_NO_CANDIDATE_SOURCES,
            format!(
                "scan targets contain no supported source files after discovery filters: {}",
                plan.targets
                    .iter()
                    .map(|path| normalize_path(path))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
        return Ok(DiscoveryResult {
            files: Vec::new(),
            diagnostics,
        });
    }

    let candidate_count = candidates.len();
    if candidate_count > plan.config.limits.max_files {
        diagnostics.push(diagnostic_with_severity(
            diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED,
            incomplete_scan_severity(plan.config.mode),
            format!(
                "discovered {candidate_count} candidate source files; scanning first {} after deterministic sorting",
                plan.config.limits.max_files
            ),
        ));
    }

    let mut candidate_records = Vec::new();
    let mut total_included_bytes = 0_u64;
    for (index, path) in candidates.into_iter().enumerate() {
        let metadata = fs::metadata(&path).map_err(|source| DiscoveryError::Metadata {
            path: path.clone(),
            source,
        })?;
        let skipped = if index >= plan.config.limits.max_files {
            Some(SkipReason {
                code: diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED.to_string(),
                message: format!(
                    "file was omitted because configured max_files is {}",
                    plan.config.limits.max_files
                ),
            })
        } else if metadata.len() > plan.config.limits.max_file_size_bytes {
            Some(SkipReason {
                code: diagnostic_codes::DISCOVERY_FILE_TOO_LARGE.to_string(),
                message: format!(
                    "file is {} bytes, exceeding configured max_file_size_bytes",
                    metadata.len()
                ),
            })
        } else if total_included_bytes.saturating_add(metadata.len())
            > plan.config.limits.max_total_bytes
        {
            Some(SkipReason {
                code: diagnostic_codes::DISCOVERY_TOTAL_BYTES_LIMIT_REACHED.to_string(),
                message: format!(
                    "including file would exceed configured max_total_bytes of {} bytes",
                    plan.config.limits.max_total_bytes
                ),
            })
        } else {
            total_included_bytes = total_included_bytes.saturating_add(metadata.len());
            None
        };
        if let Some(skip) = skipped.as_ref() {
            let code = skip.code.as_str();
            diagnostics.push(diagnostic_with_severity(
                code,
                incomplete_scan_severity(plan.config.mode),
                format!("{}: {}", normalize_path(&path), skip.message),
            ));
        }
        candidate_records.push((path, metadata.len(), skipped));
    }

    hint_paths.sort();
    hint_paths.dedup();
    hint_paths.truncate(plan.config.limits.max_files);
    hint_paths.extend(
        candidate_records
            .iter()
            .filter(|(_, _, skipped)| skipped.is_none())
            .map(|(path, _, _)| path.clone()),
    );
    hint_paths.sort();
    hint_paths.dedup();
    let target_hints = detect_project_hints(
        &target_roots,
        &hint_paths,
        plan.config.limits.max_file_size_bytes,
    );

    let mut files = Vec::new();
    for (path, size_bytes, skipped) in candidate_records {
        files.push(SourceFile {
            path: normalize_path(&path),
            language: detect_language(&path),
            size_bytes,
            sha256: None,
            project_hints: hints_for_path(&path, &target_hints),
            skipped,
        });
    }

    Ok(DiscoveryResult { files, diagnostics })
}

fn walk_target(target: &Path, limits: &ScanLimits) -> (Vec<PathBuf>, bool) {
    let mut paths = Vec::<PathBuf>::new();
    let collection_cap = discovery_collection_cap(limits);
    let mut builder = WalkBuilder::new(target);
    builder
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .parents(true);
    builder.sort_by_file_path(|left, right| left.cmp(right));
    builder.filter_entry(|entry| !is_hard_excluded_dir(entry));

    let mut capped = false;
    for entry in builder.build() {
        let Ok(entry) = entry else {
            continue;
        };
        if is_regular_file(&entry) && is_source_or_hint_path(entry.path()) {
            if paths.len() >= collection_cap {
                capped = true;
                break;
            }
            paths.push(entry.path().to_path_buf());
        }
    }

    (paths, capped)
}

fn discovery_collection_cap(limits: &ScanLimits) -> usize {
    limits
        .max_files
        .saturating_mul(2)
        .max(limits.max_files.saturating_add(1))
}

fn is_regular_file(entry: &DirEntry) -> bool {
    entry
        .file_type()
        .is_some_and(|file_type| file_type.is_file())
}

fn is_hard_excluded_dir(entry: &DirEntry) -> bool {
    entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir())
        && entry
            .file_name()
            .to_str()
            .is_some_and(|name| HARD_EXCLUDED_DIRS.contains(&name))
}

fn is_hard_excluded(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| HARD_EXCLUDED_DIRS.contains(&name))
    }) || path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| HARD_EXCLUDED_FILES.contains(&name))
}

fn is_hard_excluded_for_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let relative = roots
        .iter()
        .filter_map(|root| path.strip_prefix(root).ok())
        .min_by_key(|relative| relative.components().count())
        .unwrap_or(path);
    is_hard_excluded(relative)
}

fn is_source_or_hint_path(path: &Path) -> bool {
    is_supported_source(path) || is_manifest_or_hint_file(path)
}

fn is_manifest_or_hint_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            MANIFEST_FILES.contains(&name)
                || matches!(
                    name,
                    "next.config.js" | "next.config.mjs" | "next.config.ts"
                )
        })
}

fn is_supported_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("py" | "js" | "jsx" | "ts" | "tsx")
    )
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn detect_language(path: &Path) -> Language {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("py") => Language::Python,
        Some("js") => Language::JavaScript,
        Some("jsx") => Language::JavaScriptReact,
        Some("ts") => Language::TypeScript,
        Some("tsx") => Language::TypeScriptReact,
        _ => Language::Unknown,
    }
}

fn detect_project_hints(
    roots: &[PathBuf],
    discovered_paths: &[PathBuf],
    max_read_bytes: u64,
) -> BTreeMap<PathBuf, BTreeSet<ProjectHint>> {
    let mut hints = BTreeMap::<PathBuf, BTreeSet<ProjectHint>>::new();
    for root in roots {
        hints.entry(root.clone()).or_default();
    }

    for path in discovered_paths {
        let normalized = normalize_path(path);
        let lower = normalized.to_ascii_lowercase();
        let mut path_hints = BTreeSet::new();

        if lower.ends_with("/app/route.ts")
            || lower.ends_with("/app/route.tsx")
            || lower.ends_with("/app/route.js")
            || lower.ends_with("/app/route.jsx")
            || lower.contains("/app/")
                && matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("route.ts" | "route.tsx" | "route.js" | "route.jsx")
                )
            || matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("next.config.js" | "next.config.mjs" | "next.config.ts")
            )
        {
            path_hints.insert(ProjectHint::NextJs);
        }

        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| MANIFEST_FILES.contains(&name))
            && file_is_within_read_budget(path, max_read_bytes)
            && let Ok(text) = fs::read_to_string(path)
        {
            detect_manifest_hints(&text, &mut path_hints);
        }

        if is_supported_source(path)
            && file_is_within_read_budget(path, max_read_bytes)
            && let Ok(text) = fs::read_to_string(path)
        {
            detect_source_hints(&text, &mut path_hints);
        }

        if path_hints.is_empty() {
            continue;
        }

        let root = roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
            .unwrap_or_else(|| {
                path.parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf()
            });
        hints.entry(root).or_default().extend(path_hints);
    }

    hints
}

fn file_is_within_read_budget(path: &Path, max_read_bytes: u64) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.len() <= max_read_bytes)
}

fn detect_manifest_hints(text: &str, hints: &mut BTreeSet<ProjectHint>) {
    let lower = text.to_ascii_lowercase();
    if lower.contains("fastapi") {
        hints.insert(ProjectHint::FastApi);
    }
    if lower.contains("sqlalchemy") || lower.contains("sql-alchemy") {
        hints.insert(ProjectHint::SqlAlchemy);
    }
    if lower.contains("django") {
        hints.insert(ProjectHint::Django);
        hints.insert(ProjectHint::DjangoOrm);
    }
    if lower.contains("djangorestframework") || lower.contains("rest_framework") {
        hints.insert(ProjectHint::DjangoRestFramework);
    }
    if lower.contains("\"express\"") || lower.contains("'express'") || lower.contains(" express") {
        hints.insert(ProjectHint::Express);
    }
    if lower.contains("\"@prisma/client\"")
        || lower.contains("'@prisma/client'")
        || lower.contains("\"prisma\"")
        || lower.contains("'prisma'")
    {
        hints.insert(ProjectHint::Prisma);
    }
    if lower.contains("\"next\"") || lower.contains("'next'") || lower.contains(" next") {
        hints.insert(ProjectHint::NextJs);
    }
}

fn detect_source_hints(text: &str, hints: &mut BTreeSet<ProjectHint>) {
    let lower = text.to_ascii_lowercase();
    if lower.contains("from fastapi") || lower.contains("import fastapi") {
        hints.insert(ProjectHint::FastApi);
    }
    if lower.contains("from django") || lower.contains("import django") || lower.contains("django.")
    {
        hints.insert(ProjectHint::Django);
        hints.insert(ProjectHint::DjangoOrm);
    }
    if lower.contains("models.model")
        || lower.contains(".objects.")
        || lower.contains("from django.db import models")
    {
        hints.insert(ProjectHint::DjangoOrm);
    }
    if lower.contains("rest_framework") {
        hints.insert(ProjectHint::DjangoRestFramework);
    }
    if lower.contains("sqlalchemy")
        || lower.contains("from sqlalchemy")
        || lower.contains("import sqlalchemy")
    {
        hints.insert(ProjectHint::SqlAlchemy);
    }
    if lower.contains("@prisma/client")
        || lower.contains("prismaclient")
        || lower.contains("prisma.")
    {
        hints.insert(ProjectHint::Prisma);
    }
    if lower.contains("from \"express\"")
        || lower.contains("from 'express'")
        || lower.contains("require(\"express\")")
        || lower.contains("require('express')")
    {
        hints.insert(ProjectHint::Express);
    }
    if lower.contains("from \"next")
        || lower.contains("from 'next")
        || lower.contains("next/server")
    {
        hints.insert(ProjectHint::NextJs);
    }
}

fn hints_for_path(
    path: &Path,
    target_hints: &BTreeMap<PathBuf, BTreeSet<ProjectHint>>,
) -> Vec<ProjectHint> {
    let mut hints = BTreeSet::new();
    for (root, root_hints) in target_hints {
        if path.starts_with(root) {
            hints.extend(root_hints.iter().copied());
        }
    }
    if normalize_path(path).contains("/app/")
        && matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("route.ts" | "route.tsx" | "route.js" | "route.jsx")
        )
    {
        hints.insert(ProjectHint::NextJs);
    }
    hints.into_iter().collect()
}

fn diagnostic(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    diagnostic_with_severity(code, DiagnosticSeverity::Warning, message)
}

fn diagnostic_with_severity(
    code: impl Into<String>,
    severity: DiagnosticSeverity,
    message: impl Into<String>,
) -> Diagnostic {
    Diagnostic {
        category: DiagnosticCategory::Discovery,
        code: code.into(),
        severity,
        recoverability: Recoverability::Recoverable,
        span: None,
        message: message.into(),
    }
}

fn incomplete_scan_severity(mode: authmap_core::ScanMode) -> DiagnosticSeverity {
    match mode {
        authmap_core::ScanMode::Advisory => DiagnosticSeverity::Warning,
        authmap_core::ScanMode::Enforce => DiagnosticSeverity::Error,
    }
}

struct PatternMatchers {
    includes: Vec<Override>,
    excludes: Vec<Override>,
}

impl PatternMatchers {
    fn new(
        roots: &[PathBuf],
        include: &[String],
        exclude: &[String],
    ) -> Result<Self, DiscoveryError> {
        let includes = build_matchers(roots, include, "include")?;
        let excludes = build_matchers(roots, exclude, "exclude")?;
        Ok(Self { includes, excludes })
    }

    fn is_included(&self, path: &Path) -> bool {
        self.includes.is_empty()
            || self
                .includes
                .iter()
                .any(|matcher| matcher.matched(path, false).is_whitelist())
    }

    fn is_excluded(&self, path: &Path) -> bool {
        self.excludes
            .iter()
            .any(|matcher| matcher.matched(path, false).is_whitelist())
    }
}

fn build_matchers(
    roots: &[PathBuf],
    patterns: &[String],
    kind: &'static str,
) -> Result<Vec<Override>, DiscoveryError> {
    if patterns.is_empty() {
        return Ok(Vec::new());
    }

    let mut matchers = Vec::new();
    for root in roots {
        let base = if root.is_file() {
            root.parent().unwrap_or_else(|| Path::new("."))
        } else {
            root.as_path()
        };
        let mut builder = OverrideBuilder::new(base);
        for pattern in patterns {
            builder
                .add(pattern)
                .map_err(|source| DiscoveryError::InvalidPattern {
                    kind,
                    pattern: pattern.clone(),
                    source,
                })?;
        }
        matchers.push(
            builder
                .build()
                .map_err(|source| DiscoveryError::InvalidPattern {
                    kind,
                    pattern: patterns.join(", "),
                    source,
                })?,
        );
    }
    Ok(matchers)
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("scan target is missing or unreadable: {path}: {source}")]
    TargetUnavailable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("scan target is not a regular file or directory: {path}")]
    UnsupportedTarget { path: PathBuf },
    #[error("scan target contains no supported source files: {targets:?}")]
    EmptyTarget { targets: Vec<PathBuf> },
    #[error("invalid {kind} pattern {pattern:?}: {source}")]
    InvalidPattern {
        kind: &'static str,
        pattern: String,
        source: ignore::Error,
    },
    #[error("failed to read metadata for {path}: {source}")]
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use authmap_config::{ScanConfig, ScanLimits, ScanPlan};
    use authmap_core::{ScanMode, diagnostic_codes};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "authmap-discovery-test-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test temp directory should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("test fixture parent should be created");
        }
        fs::write(path, contents).expect("test fixture should be written");
    }

    fn plan(target: &Path) -> ScanPlan {
        ScanPlan::new(
            vec![target.to_path_buf()],
            None,
            ScanConfig {
                mode: ScanMode::Advisory,
                include: Vec::new(),
                exclude: Vec::new(),
                limits: ScanLimits::default(),
                authorization: authmap_config::AuthorizationConfig::default(),
                sensitivity: authmap_config::SensitivityConfig::default(),
            },
        )
    }

    fn names(result: &DiscoveryResult) -> Vec<String> {
        result
            .files
            .iter()
            .map(|file| {
                Path::new(&file.path)
                    .file_name()
                    .expect("file should have a name")
                    .to_string_lossy()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn default_exclusions_skip_dependency_build_and_generated_outputs() {
        let temp = TestDir::new("default-exclusions");
        for path in [
            ".git/config.ts",
            "node_modules/pkg/index.ts",
            ".venv/app.py",
            "venv/app.py",
            "dist/bundle.js",
            "build/bundle.js",
            "target/debug/build.ts",
            ".next/server/route.ts",
            "authmap.json",
            "authmap.md",
            "authmap.sarif",
            "authmap.sarif.json",
            "src/app.ts",
        ] {
            write_file(&temp.path().join(path), "const ok = true;\n");
        }

        let result = discover_sources(&plan(temp.path())).expect("discovery should succeed");

        assert_eq!(names(&result), vec!["app.ts"]);
    }

    #[test]
    fn hard_exclusions_are_relative_to_scan_root_not_absolute_ancestors() {
        let temp = TestDir::new("ancestor-build");
        let project = temp.path().join("build").join("project");
        write_file(&project.join("app.py"), "print('hello')\n");

        let result = discover_sources(&plan(&project)).expect("discovery should succeed");

        assert_eq!(names(&result), vec!["app.py"]);
    }

    #[test]
    fn hard_exclusions_cannot_be_reincluded_by_config() {
        let temp = TestDir::new("hard-exclude-include");
        write_file(
            &temp.path().join("node_modules/pkg/index.ts"),
            "export const ignored = true;\n",
        );
        let mut plan = plan(temp.path());
        plan.config.include = vec!["node_modules/**/*.ts".to_string()];

        let result =
            discover_sources(&plan).expect("advisory scan with only hard-excluded files warns");

        assert!(result.files.is_empty());
        assert_eq!(
            result.diagnostics[0].code,
            diagnostic_codes::DISCOVERY_NO_CANDIDATE_SOURCES
        );
    }

    #[test]
    fn single_supported_file_succeeds_and_unsupported_file_warns_in_advisory() {
        let temp = TestDir::new("single-file");
        let supported = temp.path().join("app.py");
        let unsupported = temp.path().join("README.md");
        write_file(&supported, "print('hello')\n");
        write_file(&unsupported, "# hello\n");

        let result = discover_sources(&plan(&supported)).expect("supported file should scan");
        assert_eq!(names(&result), vec!["app.py"]);

        let result =
            discover_sources(&plan(&unsupported)).expect("unsupported advisory file should warn");
        assert!(result.files.is_empty());
        assert_eq!(
            result.diagnostics[0].code,
            diagnostic_codes::DISCOVERY_NO_CANDIDATE_SOURCES
        );
    }

    #[test]
    fn include_and_exclude_patterns_use_exclude_precedence() {
        let temp = TestDir::new("patterns");
        write_file(&temp.path().join("src/a.ts"), "export const a = 1;\n");
        write_file(
            &temp.path().join("src/a.test.ts"),
            "export const test = 1;\n",
        );
        write_file(
            &temp.path().join("scripts/tool.ts"),
            "export const tool = 1;\n",
        );

        let mut plan = plan(temp.path());
        plan.config.include = vec!["src/**/*.ts".to_string()];
        plan.config.exclude = vec!["*.test.ts".to_string()];

        let result = discover_sources(&plan).expect("patterns should be valid");

        assert_eq!(names(&result), vec!["a.ts"]);
    }

    #[test]
    fn discovery_order_is_deterministic() {
        let temp = TestDir::new("deterministic");
        write_file(&temp.path().join("z.ts"), "export const z = 1;\n");
        write_file(&temp.path().join("a.py"), "print('a')\n");
        write_file(&temp.path().join("nested/m.js"), "export const m = 1;\n");

        let first = discover_sources(&plan(temp.path())).expect("first discovery should succeed");
        let second = discover_sources(&plan(temp.path())).expect("second discovery should succeed");

        assert_eq!(
            first
                .files
                .iter()
                .map(|file| &file.path)
                .collect::<Vec<_>>(),
            second
                .files
                .iter()
                .map(|file| &file.path)
                .collect::<Vec<_>>()
        );
        assert_eq!(names(&first), vec!["a.py", "m.js", "z.ts"]);
    }

    #[test]
    fn large_file_is_included_as_skipped_with_warning() {
        let temp = TestDir::new("large-file");
        write_file(&temp.path().join("app.py"), "print('this is too large')\n");
        let mut plan = plan(temp.path());
        plan.config.limits.max_file_size_bytes = 4;

        let result = discover_sources(&plan).expect("large file should be represented as skipped");

        assert_eq!(result.files.len(), 1);
        assert_eq!(
            result.files[0]
                .skipped
                .as_ref()
                .expect("file should be skipped")
                .code,
            diagnostic_codes::DISCOVERY_FILE_TOO_LARGE
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == diagnostic_codes::DISCOVERY_FILE_TOO_LARGE)
        );
    }

    #[test]
    fn enforce_large_file_marks_incomplete_discovery_as_error() {
        let temp = TestDir::new("large-file-enforce");
        write_file(&temp.path().join("app.py"), "print('this is too large')\n");
        let mut plan = plan(temp.path());
        plan.config.mode = ScanMode::Enforce;
        plan.config.limits.max_file_size_bytes = 4;

        let result = discover_sources(&plan).expect("large file should be represented as skipped");

        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::DISCOVERY_FILE_TOO_LARGE
                && diagnostic.severity == DiagnosticSeverity::Error
        }));
    }

    #[test]
    fn max_files_limit_truncates_after_sorting_and_warns() {
        let temp = TestDir::new("max-files");
        write_file(&temp.path().join("b.ts"), "export const b = 1;\n");
        write_file(&temp.path().join("a.ts"), "export const a = 1;\n");
        write_file(&temp.path().join("c.ts"), "export const c = 1;\n");
        let mut plan = plan(temp.path());
        plan.config.limits.max_files = 2;

        let result = discover_sources(&plan).expect("discovery should succeed");

        assert_eq!(names(&result), vec!["a.ts", "b.ts", "c.ts"]);
        assert!(result.files[0].skipped.is_none());
        assert!(result.files[1].skipped.is_none());
        assert_eq!(
            result.files[2]
                .skipped
                .as_ref()
                .expect("omitted sample should be represented as skipped")
                .code,
            diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED
        );
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED
        }));
    }

    #[test]
    fn collection_cap_stops_before_exhaustive_walk_and_reports_bounded_sample() {
        let temp = TestDir::new("collection-cap");
        for name in ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts"] {
            write_file(&temp.path().join(name), "export const value = 1;\n");
        }
        let mut plan = plan(temp.path());
        plan.config.limits.max_files = 1;

        let first = discover_sources(&plan).expect("discovery should succeed");
        let second = discover_sources(&plan).expect("discovery should be deterministic");

        assert_eq!(names(&first), vec!["a.ts", "b.ts"]);
        assert_eq!(names(&first), names(&second));
        assert!(first.files[0].skipped.is_none());
        assert_eq!(
            first.files[1]
                .skipped
                .as_ref()
                .expect("bounded omitted sample should be skipped")
                .code,
            diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED
        );
        assert!(first.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED
                && diagnostic
                    .message
                    .contains("bounded sample of source and hint paths")
        }));
    }

    #[test]
    fn max_total_bytes_skips_files_after_deterministic_budget() {
        let temp = TestDir::new("max-total-bytes");
        write_file(&temp.path().join("b.ts"), "bb\n");
        write_file(&temp.path().join("a.ts"), "aa\n");
        write_file(&temp.path().join("c.ts"), "cc\n");
        let mut plan = plan(temp.path());
        plan.config.limits.max_total_bytes = 6;

        let first = discover_sources(&plan).expect("discovery should succeed");
        let second = discover_sources(&plan).expect("discovery should be stable");

        assert_eq!(
            first
                .files
                .iter()
                .map(|file| (
                    &file.path,
                    file.skipped.as_ref().map(|skip| skip.code.as_str())
                ))
                .collect::<Vec<_>>(),
            second
                .files
                .iter()
                .map(|file| (
                    &file.path,
                    file.skipped.as_ref().map(|skip| skip.code.as_str())
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(names(&first), vec!["a.ts", "b.ts", "c.ts"]);
        assert!(first.files[0].skipped.is_none());
        assert!(first.files[1].skipped.is_none());
        assert_eq!(
            first.files[2]
                .skipped
                .as_ref()
                .expect("third file should exceed total budget")
                .code,
            diagnostic_codes::DISCOVERY_TOTAL_BYTES_LIMIT_REACHED
        );
        assert!(first.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::DISCOVERY_TOTAL_BYTES_LIMIT_REACHED
        }));
    }

    #[test]
    fn enforce_max_total_bytes_marks_incomplete_discovery_as_error() {
        let temp = TestDir::new("max-total-bytes-enforce");
        write_file(&temp.path().join("a.ts"), "aa\n");
        write_file(&temp.path().join("b.ts"), "bb\n");
        let mut plan = plan(temp.path());
        plan.config.mode = ScanMode::Enforce;
        plan.config.limits.max_total_bytes = 3;

        let result = discover_sources(&plan).expect("discovery should succeed");

        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::DISCOVERY_TOTAL_BYTES_LIMIT_REACHED
                && diagnostic.severity == DiagnosticSeverity::Error
        }));
    }

    #[test]
    fn enforce_max_files_limit_marks_incomplete_discovery_as_error() {
        let temp = TestDir::new("max-files-enforce");
        write_file(&temp.path().join("b.ts"), "export const b = 1;\n");
        write_file(&temp.path().join("a.ts"), "export const a = 1;\n");
        let mut plan = plan(temp.path());
        plan.config.mode = ScanMode::Enforce;
        plan.config.limits.max_files = 1;

        let result = discover_sources(&plan).expect("discovery should succeed");

        assert_eq!(names(&result), vec!["a.ts", "b.ts"]);
        assert!(result.files[0].skipped.is_none());
        assert_eq!(
            result.files[1]
                .skipped
                .as_ref()
                .expect("omitted sample should be represented as skipped")
                .code,
            diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED
        );
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED
                && diagnostic.severity == DiagnosticSeverity::Error
        }));
    }

    #[test]
    fn detects_project_hints_for_initial_frameworks() {
        let temp = TestDir::new("project-hints");
        write_file(
            &temp.path().join("requirements.txt"),
            "fastapi\ndjango\ndjangorestframework\n",
        );
        write_file(
            &temp.path().join("package.json"),
            r#"{ "dependencies": { "express": "^4", "next": "^15" } }"#,
        );
        write_file(
            &temp.path().join("app/main.py"),
            "from fastapi import FastAPI\n",
        );
        write_file(
            &temp.path().join("app/api/users/route.ts"),
            "import { NextRequest } from 'next/server';\n",
        );

        let result = discover_sources(&plan(temp.path())).expect("discovery should succeed");

        for file in result.files {
            assert!(file.project_hints.contains(&ProjectHint::FastApi));
            assert!(file.project_hints.contains(&ProjectHint::Django));
            assert!(
                file.project_hints
                    .contains(&ProjectHint::DjangoRestFramework)
            );
            assert!(file.project_hints.contains(&ProjectHint::Express));
            assert!(file.project_hints.contains(&ProjectHint::NextJs));
        }
    }

    #[test]
    fn oversized_hint_files_are_not_read_before_size_limits() {
        let temp = TestDir::new("oversized-hints");
        write_file(
            &temp.path().join("package.json"),
            r#"{ "dependencies": { "express": "^4" } }"#,
        );
        write_file(&temp.path().join("src/app.ts"), "export const ok = true;\n");
        let mut plan = plan(temp.path());
        plan.config.limits.max_file_size_bytes = 4;

        let result = discover_sources(&plan).expect("discovery should succeed");

        assert!(
            result.files[0].project_hints.is_empty(),
            "oversized manifests and sources should not be read for hints"
        );
    }

    #[test]
    fn invalid_patterns_are_reported() {
        let temp = TestDir::new("invalid-pattern");
        write_file(&temp.path().join("app.py"), "print('hello')\n");
        let mut plan = plan(temp.path());
        plan.config.include = vec!["[abc".to_string()];

        let error = discover_sources(&plan).expect_err("invalid pattern should fail");

        assert!(matches!(error, DiscoveryError::InvalidPattern { .. }));
    }
}
