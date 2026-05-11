use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use authmap_config::ScanPlan;
use authmap_core::{Language, ProjectHint, SkipReason, SourceFile};
use ignore::{DirEntry, WalkBuilder, WalkState};
use thiserror::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryResult {
    pub files: Vec<SourceFile>,
}

pub fn discover_sources(plan: &ScanPlan) -> Result<DiscoveryResult, DiscoveryError> {
    let paths = Arc::new(Mutex::new(Vec::<PathBuf>::new()));

    for target in &plan.targets {
        if target.is_file() {
            paths
                .lock()
                .expect("discovery path mutex poisoned")
                .push(target.clone());
            continue;
        }

        let mut builder = WalkBuilder::new(target);
        builder
            .hidden(false)
            .git_ignore(true)
            .git_exclude(true)
            .parents(true);

        let paths = Arc::clone(&paths);
        builder.build_parallel().run(|| {
            let paths = Arc::clone(&paths);
            Box::new(move |entry| {
                if let Ok(entry) = entry {
                    if is_ignored_directory(&entry) {
                        return WalkState::Skip;
                    }
                    if is_regular_file(&entry) {
                        paths
                            .lock()
                            .expect("discovery path mutex poisoned")
                            .push(entry.path().to_path_buf());
                    }
                }
                WalkState::Continue
            })
        });
    }

    let mut paths = Arc::try_unwrap(paths)
        .expect("all discovery workers should be complete")
        .into_inner()
        .expect("discovery path mutex poisoned");
    paths.sort();
    paths.dedup();

    let mut files = Vec::new();
    for path in paths.into_iter().take(plan.config.limits.max_files) {
        let metadata = fs::metadata(&path).map_err(|source| DiscoveryError::Metadata {
            path: path.clone(),
            source,
        })?;
        let skipped =
            (metadata.len() > plan.config.limits.max_file_size_bytes).then(|| SkipReason {
                code: "file_too_large".to_string(),
                message: format!(
                    "file is {} bytes, exceeding configured max_file_size_bytes",
                    metadata.len()
                ),
            });
        files.push(SourceFile {
            path: normalize_path(&path),
            language: detect_language(&path),
            size_bytes: metadata.len(),
            sha256: None,
            project_hints: detect_project_hints(&path),
            skipped,
        });
    }

    Ok(DiscoveryResult { files })
}

fn is_regular_file(entry: &DirEntry) -> bool {
    entry
        .file_type()
        .is_some_and(|file_type| file_type.is_file())
}

fn is_ignored_directory(entry: &DirEntry) -> bool {
    entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir())
        && matches!(
            entry.file_name().to_str(),
            Some(".git" | ".hg" | ".svn" | "node_modules" | "target" | ".venv")
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

fn detect_project_hints(path: &Path) -> Vec<ProjectHint> {
    let normalized = normalize_path(path);
    let mut hints = Vec::new();
    if normalized.ends_with("route.ts")
        || normalized.ends_with("route.tsx")
        || normalized.ends_with("route.js")
        || normalized.ends_with("route.jsx")
    {
        hints.push(ProjectHint::NextJs);
    }
    hints
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("failed to read metadata for {path}: {source}")]
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
}
