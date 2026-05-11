use std::fs;
use std::path::{Path, PathBuf};

use authmap_core::{AuthMapDocument, Diagnostic, DiagnosticSeverity, RiskLevel, SkipReason, Span};
use serde_json::{Value, json};
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
        let mut report = String::from("# AuthMap Report\n\n");

        let review_required = document
            .coverage
            .iter()
            .filter(|coverage| {
                matches!(coverage.risk, RiskLevel::High | RiskLevel::ReviewRequired)
                    || !coverage.uncertainty_reasons.is_empty()
            })
            .collect::<Vec<_>>();
        if !review_required.is_empty() {
            report.push_str("## Review Required\n\n");
            for coverage in review_required {
                report.push_str(&format!(
                    "- `{}`: risk `{}`, class `{}`\n",
                    coverage.route_id,
                    enum_value(&coverage.risk),
                    enum_value(&coverage.class)
                ));
                append_nested_lines(&mut report, "rationale", &coverage.rationale);
                append_nested_lines(&mut report, "uncertainty", &coverage.uncertainty_reasons);
                append_nested_lines(&mut report, "question", &coverage.reviewer_questions);
            }
            report.push('\n');
        }

        let skipped_files = document
            .source_files
            .iter()
            .filter_map(|file| file.skipped.as_ref().map(|skip| (&file.path, skip)))
            .collect::<Vec<(&String, &SkipReason)>>();
        if !skipped_files.is_empty() {
            report.push_str("## Skipped Files\n\n");
            for (path, skip) in skipped_files {
                report.push_str(&format!("- `{path}`: `{}` - {}\n", skip.code, skip.message));
            }
            report.push('\n');
        }

        if !document.diagnostics.is_empty() {
            report.push_str("## Diagnostics\n\n");
            for diagnostic in &document.diagnostics {
                report.push_str(&format!(
                    "- `{}` `{}` `{}`: {}{}\n",
                    enum_value(&diagnostic.severity),
                    enum_value(&diagnostic.category),
                    diagnostic.code,
                    diagnostic.message,
                    diagnostic
                        .span
                        .as_ref()
                        .map_or_else(String::new, |span| format!(" ({})", span_location(span)))
                ));
            }
            report.push('\n');
        }

        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "- Source files: {}\n- Routes: {}\n- Evidence entries: {}\n- Mutations: {}\n- Diagnostics: {}\n",
            document.source_files.len(),
            document.routes.len(),
            document.evidence.len(),
            document.mutations.len(),
            document.diagnostics.len()
        ));
        Ok(report)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SarifReporter;

impl Reporter for SarifReporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Sarif
    }

    fn render(&self, document: &AuthMapDocument) -> Result<String, ReportError> {
        let rules = diagnostic_rules(&document.diagnostics);
        let results = document
            .diagnostics
            .iter()
            .map(diagnostic_result)
            .collect::<Vec<_>>();
        let sarif = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AuthMap",
                            "semanticVersion": document.metadata.tool_version,
                            "informationUri": "https://github.com/Ozark-Security-Labs/AuthMap",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        });
        serde_json::to_string_pretty(&sarif).map_err(ReportError::Json)
    }
}

fn diagnostic_rules(diagnostics: &[Diagnostic]) -> Vec<Value> {
    let mut diagnostics = diagnostics.iter().collect::<Vec<_>>();
    diagnostics.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then(left.category.cmp(&right.category))
    });
    diagnostics.dedup_by(|left, right| left.code == right.code);
    diagnostics
        .into_iter()
        .map(|diagnostic| {
            json!({
                "id": diagnostic.code,
                "name": diagnostic.code,
                "shortDescription": {
                    "text": format!("{} diagnostic", enum_value(&diagnostic.category))
                },
                "properties": {
                    "category": enum_value(&diagnostic.category),
                    "recoverability": enum_value(&diagnostic.recoverability)
                }
            })
        })
        .collect()
}

fn diagnostic_result(diagnostic: &Diagnostic) -> Value {
    let mut result = json!({
        "ruleId": diagnostic.code,
        "level": sarif_level(diagnostic.severity),
        "message": {
            "text": diagnostic.message
        },
        "properties": {
            "category": enum_value(&diagnostic.category),
            "recoverability": enum_value(&diagnostic.recoverability)
        }
    });
    if let Some(span) = &diagnostic.span {
        result["locations"] = json!([{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": span.file
                },
                "region": sarif_region(span)
            }
        }]);
    }
    result
}

fn sarif_region(span: &Span) -> Value {
    let mut region = json!({
        "startLine": span.line,
        "startColumn": span.column
    });
    if let Some(range) = span.byte_range {
        region["byteOffset"] = json!(range.start);
        region["byteLength"] = json!(range.end.saturating_sub(range.start));
    }
    region
}

fn sarif_level(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "note",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

fn enum_value<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn span_location(span: &Span) -> String {
    format!("{}:{}:{}", span.file, span.line, span.column)
}

fn append_nested_lines(report: &mut String, label: &str, values: &[String]) {
    for value in values {
        report.push_str(&format!("  - {label}: {value}\n"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use authmap_core::{
        Coverage, CoverageClass, DiagnosticCategory, Recoverability, ScanMetadata, SourceFile,
        diagnostic_codes,
    };

    fn diagnostic() -> Diagnostic {
        Diagnostic {
            category: DiagnosticCategory::Parser,
            code: diagnostic_codes::PARSER_SOURCE_PARSE_RECOVERED.to_string(),
            severity: DiagnosticSeverity::Warning,
            recoverability: Recoverability::Recoverable,
            span: Some(Span {
                file: "src/app.py".to_string(),
                line: 3,
                column: 5,
                byte_range: None,
            }),
            message: "source parsed with syntax errors; partial tree is available".to_string(),
        }
    }

    fn document_with_review_data() -> AuthMapDocument {
        let mut document = AuthMapDocument::empty(ScanMetadata {
            target_roots: vec!["src".to_string()],
            ..ScanMetadata::default()
        });
        document.source_files.push(SourceFile {
            path: "src/large.py".to_string(),
            language: authmap_core::Language::Python,
            size_bytes: 100,
            sha256: None,
            project_hints: Vec::new(),
            skipped: Some(SkipReason {
                code: diagnostic_codes::DISCOVERY_FILE_TOO_LARGE.to_string(),
                message: "file exceeds max_file_size_bytes".to_string(),
            }),
        });
        document.coverage.push(Coverage {
            route_id: "route.accounts.delete".to_string(),
            class: CoverageClass::UnknownOrDynamic,
            risk: RiskLevel::ReviewRequired,
            rationale: vec!["authorization evidence was incomplete".to_string()],
            reviewer_questions: vec!["Should this route require ownership?".to_string()],
            uncertainty_reasons: vec!["dynamic dispatch was detected".to_string()],
            extensions: authmap_core::ExtensionMap::new(),
        });
        document.diagnostics.push(diagnostic());
        document
    }

    #[test]
    fn markdown_surfaces_review_skips_and_diagnostics_before_summary() {
        let markdown = MarkdownReporter
            .render(&document_with_review_data())
            .expect("markdown should render");

        let review_index = markdown.find("## Review Required").expect("review section");
        let skipped_index = markdown.find("## Skipped Files").expect("skipped section");
        let diagnostics_index = markdown
            .find("## Diagnostics")
            .expect("diagnostics section");
        let summary_index = markdown.find("## Summary").expect("summary section");

        assert!(review_index < summary_index);
        assert!(skipped_index < summary_index);
        assert!(diagnostics_index < summary_index);
        assert!(markdown.contains("parser.source_parse_recovered"));
        assert!(markdown.contains("discovery.file_too_large"));
        assert!(markdown.contains("dynamic dispatch was detected"));
    }

    #[test]
    fn sarif_maps_diagnostics_to_rules_results_and_locations() {
        let sarif: Value = serde_json::from_str(
            &SarifReporter
                .render(&document_with_review_data())
                .expect("SARIF should render"),
        )
        .expect("SARIF should be JSON");

        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "parser.source_parse_recovered"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["ruleId"],
            "parser.source_parse_recovered"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/app.py"
        );
    }
}
