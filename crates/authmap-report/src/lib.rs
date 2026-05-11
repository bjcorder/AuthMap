use std::fs;
use std::path::{Path, PathBuf};

use authmap_core::AuthMapDocument;
use thiserror::Error;

pub trait Reporter: Send + Sync {
    fn format(&self) -> ReportFormat;
    fn render(&self, document: &AuthMapDocument) -> Result<String, ReportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Json,
    Markdown,
    Sarif,
    GithubSummary,
}

#[derive(Clone, Debug, Default)]
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Json
    }

    fn render(&self, document: &AuthMapDocument) -> Result<String, ReportError> {
        serde_json::to_string_pretty(document).map_err(ReportError::Json)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MarkdownReporter;

impl Reporter for MarkdownReporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Markdown
    }

    fn render(&self, document: &AuthMapDocument) -> Result<String, ReportError> {
        Ok(format!(
            "# AuthMap Report\n\n- Source files: {}\n- Routes: {}\n- Evidence entries: {}\n- Mutations: {}\n- Diagnostics: {}\n",
            document.source_files.len(),
            document.routes.len(),
            document.evidence.len(),
            document.mutations.len(),
            document.diagnostics.len()
        ))
    }
}

pub fn redact_sensitive_text(input: &str) -> String {
    input.replace("Authorization:", "Authorization: [REDACTED]")
}

pub fn write_atomic(path: &Path, contents: &str) -> Result<(), ReportError> {
    let temp_path = temp_path_for(path);
    fs::write(&temp_path, contents).map_err(|source| ReportError::Write {
        path: temp_path.clone(),
        source,
    })?;
    fs::rename(&temp_path, path).map_err(|source| ReportError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map_or_else(|| "tmp".to_string(), |ext| format!("{ext}.tmp"));
    temp.set_extension(extension);
    temp
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("failed to render JSON report: {0}")]
    Json(serde_json::Error),
    #[error("failed to write report {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}
