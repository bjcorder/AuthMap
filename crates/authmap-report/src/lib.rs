use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use authmap_analysis::{
    DriftChange, DriftChangeKind, DriftChangeSeverity, DriftComparison, DriftReport,
    RuleSuggestionReport,
};
use authmap_core::{
    AuthMapDocument, Confidence, Coverage, CoverageClass, Diagnostic, DiagnosticSeverity, Evidence,
    EvidenceType, Framework, Mutation, MutationOperation, ReachabilityLink, RiskLevel,
    SCHEMA_VERSION, ScanMode, SourceFile, Span, SymbolRef,
};
use regex::{Captures, Regex};
use serde_json::{Map, Value, json};
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
        let mut value = serde_json::to_value(document).map_err(ReportError::Json)?;
        redact_json_value(&mut value);
        serde_json::to_string_pretty(&value).map_err(ReportError::Json)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MarkdownReporter;

impl Reporter for MarkdownReporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Markdown
    }

    fn render(&self, document: &AuthMapDocument) -> Result<String, ReportError> {
        Ok(render_markdown(document))
    }
}

fn render_markdown(document: &AuthMapDocument) -> String {
    let index = ReportIndex::new(document);
    let mut output = String::new();
    render_header(&mut output, document);
    render_summary(&mut output, document);
    render_review_required(&mut output, document, &index);
    render_route_inventory(&mut output, document, &index);
    render_data_mutations(&mut output, document);
    render_route_details(&mut output, document, &index);
    render_diagnostics(&mut output, document);
    render_skipped_files(&mut output, document);
    output
}

struct ReportIndex<'a> {
    coverage_by_route: BTreeMap<&'a str, &'a Coverage>,
    evidence_by_id: BTreeMap<&'a str, &'a Evidence>,
    mutation_by_id: BTreeMap<&'a str, &'a Mutation>,
    link_by_id: BTreeMap<&'a str, &'a ReachabilityLink>,
    evidence_by_route: BTreeMap<&'a str, Vec<&'a Evidence>>,
    mutations_by_route: BTreeMap<&'a str, Vec<&'a Mutation>>,
    links_by_route: BTreeMap<&'a str, Vec<&'a ReachabilityLink>>,
}

impl<'a> ReportIndex<'a> {
    fn new(document: &'a AuthMapDocument) -> Self {
        let mut coverage_by_route = BTreeMap::new();
        for coverage in &document.coverage {
            coverage_by_route.insert(coverage.route_id.as_str(), coverage);
        }

        let evidence_by_id = document
            .evidence
            .iter()
            .map(|evidence| (evidence.id.as_str(), evidence))
            .collect::<BTreeMap<_, _>>();
        let mutation_by_id = document
            .mutations
            .iter()
            .map(|mutation| (mutation.id.as_str(), mutation))
            .collect::<BTreeMap<_, _>>();
        let link_by_id = document
            .links
            .iter()
            .map(|link| (link.id.as_str(), link))
            .collect::<BTreeMap<_, _>>();

        let mut evidence_by_route: BTreeMap<&str, Vec<&Evidence>> = BTreeMap::new();
        for evidence in &document.evidence {
            if let Some(route_id) = &evidence.route_id {
                evidence_by_route
                    .entry(route_id.as_str())
                    .or_default()
                    .push(evidence);
            }
        }

        let mut mutations_by_route: BTreeMap<&str, Vec<&Mutation>> = BTreeMap::new();
        let mut links_by_route: BTreeMap<&str, Vec<&ReachabilityLink>> = BTreeMap::new();
        for link in &document.links {
            links_by_route
                .entry(link.route_id.as_str())
                .or_default()
                .push(link);
            if let Some(evidence_id) = &link.evidence_id
                && let Some(evidence) = evidence_by_id.get(evidence_id.as_str())
            {
                evidence_by_route
                    .entry(link.route_id.as_str())
                    .or_default()
                    .push(evidence);
            }
            if let Some(mutation_id) = &link.mutation_id
                && let Some(mutation) = mutation_by_id.get(mutation_id.as_str())
            {
                mutations_by_route
                    .entry(link.route_id.as_str())
                    .or_default()
                    .push(mutation);
            }
        }

        for evidence in evidence_by_route.values_mut() {
            dedup_evidence(evidence);
        }
        for mutations in mutations_by_route.values_mut() {
            dedup_mutations(mutations);
        }
        for links in links_by_route.values_mut() {
            dedup_links(links);
        }

        Self {
            coverage_by_route,
            evidence_by_id,
            mutation_by_id,
            link_by_id,
            evidence_by_route,
            mutations_by_route,
            links_by_route,
        }
    }
}

fn render_header(output: &mut String, document: &AuthMapDocument) {
    let _ = writeln!(output, "# AuthMap Report");
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "- Tool: {} {}",
        escape_inline(&document.metadata.tool_name),
        escape_inline(&document.metadata.tool_version)
    );
    let _ = writeln!(
        output,
        "- Schema: {}",
        escape_inline(&document.schema_version)
    );
    let _ = writeln!(output);
}

fn render_summary(output: &mut String, document: &AuthMapDocument) {
    let _ = writeln!(output, "## Summary");
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "- Mode: {}",
        scan_mode_label(document.metadata.mode)
    );
    let _ = writeln!(
        output,
        "- Targets: {}",
        list_or_none(
            document
                .metadata
                .target_roots
                .iter()
                .map(|target| escape_inline(target))
                .collect::<Vec<_>>()
        )
    );
    let _ = writeln!(output, "- Source files: {}", document.source_files.len());
    let _ = writeln!(output, "- Routes: {}", document.routes.len());
    let _ = writeln!(output, "- Evidence entries: {}", document.evidence.len());
    let _ = writeln!(output, "- Mutations: {}", document.mutations.len());
    let _ = writeln!(output, "- Diagnostics: {}", document.diagnostics.len());

    let framework_counts = framework_counts(document);
    if framework_counts.is_empty() {
        let _ = writeln!(output, "- Frameworks: none");
    } else {
        let rendered = framework_counts
            .iter()
            .map(|(framework, count)| format!("{framework}: {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(output, "- Frameworks: {rendered}");
    }
    let _ = writeln!(output);
}

fn render_review_required(
    output: &mut String,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    let _ = writeln!(output, "## Review Required");
    let _ = writeln!(output);

    let mut rows = Vec::new();
    for route in sorted_routes(document) {
        let mut reasons = Vec::new();
        if route.confidence != Confidence::High {
            reasons.push(format!(
                "confidence is {}",
                confidence_label(route.confidence)
            ));
        }
        if !route.notes.is_empty() {
            reasons.extend(route.notes.iter().cloned());
        }
        if let Some(coverage) = index.coverage_by_route.get(route.id.as_str()) {
            if matches!(coverage.risk, RiskLevel::High | RiskLevel::ReviewRequired) {
                reasons.push(format!("risk is {}", risk_label(coverage.risk)));
            }
            if coverage.class == CoverageClass::UnknownOrDynamic {
                reasons.push("coverage is unknown_or_dynamic".to_string());
            }
        }

        if !reasons.is_empty() {
            rows.push(vec![
                format!(
                    "[{}](#{})",
                    escape_table(&route.id),
                    route_anchor(&route.id)
                ),
                escape_table(&format!("{} {}", route.method, route.path)),
                escape_table(&reasons.join("; ")),
            ]);
        }
    }

    for diagnostic in sorted_diagnostics(document)
        .into_iter()
        .filter(|diagnostic| diagnostic.severity != DiagnosticSeverity::Info)
    {
        rows.push(vec![
            "diagnostic".to_string(),
            escape_table(diagnostic.code.as_str()),
            escape_table(&format!(
                "{} at {}",
                diagnostic.message,
                format_optional_span_table(diagnostic.span.as_ref())
            )),
        ]);
    }

    for file in skipped_files(document) {
        if let Some(skipped) = &file.skipped {
            rows.push(vec![
                "skipped_file".to_string(),
                escape_table(&file.path),
                escape_table(&format!("{}: {}", skipped.code, skipped.message)),
            ]);
        }
    }

    if rows.is_empty() {
        let _ = writeln!(output, "No review-required items were identified.");
        let _ = writeln!(output);
        return;
    }

    render_table(output, &["Item", "Subject", "Reason"], &rows);
    let _ = writeln!(output);
}

fn render_route_inventory(
    output: &mut String,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    let _ = writeln!(output, "## Route Inventory");
    let _ = writeln!(output);
    if document.routes.is_empty() {
        let _ = writeln!(output, "No routes were discovered.");
        let _ = writeln!(output);
        return;
    }

    let rows = sorted_routes(document)
        .into_iter()
        .map(|route| {
            let coverage = index.coverage_by_route.get(route.id.as_str());
            vec![
                format!(
                    "[{}](#{})",
                    escape_table(&route.id),
                    route_anchor(&route.id)
                ),
                framework_label(route.framework).to_string(),
                escape_table(&route.method),
                escape_table(&route.path),
                escape_table(&format_optional_symbol_table(route.handler.as_ref())),
                escape_table(&format_symbols_table(&route.middleware)),
                confidence_label(route.confidence).to_string(),
                coverage.map_or_else(
                    || "not classified".to_string(),
                    |coverage| coverage_class_label(coverage.class).to_string(),
                ),
                coverage.map_or_else(
                    || "not scored".to_string(),
                    |coverage| risk_label(coverage.risk).to_string(),
                ),
            ]
        })
        .collect::<Vec<_>>();

    render_table(
        output,
        &[
            "ID",
            "Framework",
            "Method",
            "Path",
            "Handler",
            "Middleware",
            "Confidence",
            "Coverage",
            "Risk",
        ],
        &rows,
    );
    let _ = writeln!(output);
}

fn render_data_mutations(output: &mut String, document: &AuthMapDocument) {
    let _ = writeln!(output, "## Data Mutations");
    let _ = writeln!(output);
    if document.mutations.is_empty() {
        let _ = writeln!(output, "No data mutations were detected.");
        let _ = writeln!(output);
        return;
    }

    let rows = sorted_mutations(document)
        .into_iter()
        .map(|mutation| {
            vec![
                escape_table(&mutation.id),
                mutation_operation_label(mutation.operation).to_string(),
                escape_table(mutation.library.as_deref().unwrap_or("unknown library")),
                escape_table(mutation.resource.as_deref().unwrap_or("unknown resource")),
                escape_table(&format_optional_span_table(mutation.span.as_ref())),
                confidence_label(mutation.confidence).to_string(),
                escape_table(&mutation_review_summary(mutation)),
            ]
        })
        .collect::<Vec<_>>();
    render_table(
        output,
        &[
            "ID",
            "Operation",
            "Library",
            "Resource",
            "Location",
            "Confidence",
            "Review",
        ],
        &rows,
    );
    let _ = writeln!(output);
}

fn render_route_details(output: &mut String, document: &AuthMapDocument, index: &ReportIndex<'_>) {
    let _ = writeln!(output, "## Route Details");
    let _ = writeln!(output);
    if document.routes.is_empty() {
        let _ = writeln!(output, "No route details are available.");
        let _ = writeln!(output);
        return;
    }

    for route in sorted_routes(document) {
        let _ = writeln!(output, "<a id=\"{}\"></a>", route_anchor(&route.id));
        let _ = writeln!(
            output,
            "### {} {} `{}`",
            escape_inline(&route.id),
            escape_inline(&route.method),
            escape_inline(&route.path)
        );
        let _ = writeln!(output);
        let _ = writeln!(output, "- Framework: {}", framework_label(route.framework));
        let _ = writeln!(
            output,
            "- Handler: {}",
            format_optional_symbol(route.handler.as_ref())
        );
        let _ = writeln!(
            output,
            "- Route location: {}",
            format_optional_span(route.span.as_ref())
        );
        let _ = writeln!(
            output,
            "- Middleware: {}",
            format_symbols(&route.middleware)
        );
        let _ = writeln!(
            output,
            "- Confidence: {}",
            confidence_label(route.confidence)
        );

        if let Some(coverage) = index.coverage_by_route.get(route.id.as_str()) {
            let _ = writeln!(
                output,
                "- Coverage: {} ({})",
                coverage_class_label(coverage.class),
                risk_label(coverage.risk)
            );
            if !coverage.rationale.is_empty() {
                let _ = writeln!(
                    output,
                    "- Coverage rationale: {}",
                    coverage
                        .rationale
                        .iter()
                        .map(|item| escape_inline(item))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
            }
            render_coverage_support(output, coverage);
            if !coverage.reviewer_questions.is_empty() {
                let _ = writeln!(output, "- Reviewer questions:");
                for question in &coverage.reviewer_questions {
                    let _ = writeln!(output, "  - {}", escape_inline(question));
                }
            }
            if !coverage.uncertainty_reasons.is_empty() {
                let _ = writeln!(output, "- Coverage uncertainty:");
                for reason in &coverage.uncertainty_reasons {
                    let _ = writeln!(output, "  - {}", escape_inline(reason));
                }
            }
        } else {
            let _ = writeln!(output, "- Coverage: not classified");
        }

        if !route.notes.is_empty() {
            let _ = writeln!(output, "- Uncertainty notes:");
            for note in &route.notes {
                let _ = writeln!(output, "  - {}", escape_inline(note));
            }
        }

        render_route_evidence(output, route.id.as_str(), index);
        render_route_mutations(output, route.id.as_str(), index);
        let _ = writeln!(output);
    }
}

fn render_coverage_support(output: &mut String, coverage: &Coverage) {
    let Some(support) = coverage.extensions.get("authmap.coverage") else {
        return;
    };
    let parts = [
        ("evidence", support_ids(support, "evidence_ids")),
        ("weak evidence", support_ids(support, "weak_evidence_ids")),
        ("mutations", support_ids(support, "mutation_ids")),
        ("links", support_ids(support, "link_ids")),
        ("sensitivity", support_ids(support, "sensitivity_reasons")),
    ]
    .into_iter()
    .filter_map(|(label, values)| {
        (!values.is_empty()).then(|| {
            format!(
                "{}: {}",
                label,
                values
                    .iter()
                    .map(|item| escape_inline(item))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    })
    .collect::<Vec<_>>();

    if !parts.is_empty() {
        let _ = writeln!(output, "- Coverage support: {}", parts.join("; "));
    }
}

fn support_ids(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn render_route_evidence(output: &mut String, route_id: &str, index: &ReportIndex<'_>) {
    let evidence = index.evidence_by_route.get(route_id);
    let Some(evidence) = evidence else {
        let _ = writeln!(output, "- Auth evidence: none");
        return;
    };
    if evidence.is_empty() {
        let _ = writeln!(output, "- Auth evidence: none");
        return;
    }

    let _ = writeln!(output, "- Auth evidence:");
    for evidence in evidence {
        let _ = writeln!(
            output,
            "  - {} `{}` at {} ({})",
            evidence_type_label(evidence.evidence_type),
            escape_inline(&evidence.mechanism),
            format_optional_span(evidence.span.as_ref()),
            confidence_label(evidence.confidence)
        );
        if let Some(symbol) = &evidence.symbol {
            let _ = writeln!(output, "    - Symbol: {}", format_symbol(symbol));
        }
        for note in &evidence.notes {
            let _ = writeln!(output, "    - Note: {}", escape_inline(note));
        }
    }
}

fn render_route_mutations(output: &mut String, route_id: &str, index: &ReportIndex<'_>) {
    let mutations = index.mutations_by_route.get(route_id);
    let Some(mutations) = mutations else {
        let _ = writeln!(output, "- Data mutations: none");
        return;
    };
    if mutations.is_empty() {
        let _ = writeln!(output, "- Data mutations: none");
        return;
    }

    let _ = writeln!(output, "- Data mutations:");
    for mutation in mutations {
        let resource = mutation.resource.as_deref().unwrap_or("unknown resource");
        let library = mutation.library.as_deref().unwrap_or("unknown library");
        let _ = writeln!(
            output,
            "  - {} `{}` via `{}` at {} ({})",
            mutation_operation_label(mutation.operation),
            escape_inline(resource),
            escape_inline(library),
            format_optional_span(mutation.span.as_ref()),
            confidence_label(mutation.confidence)
        );
        for note in &mutation.notes {
            let _ = writeln!(output, "    - Note: {}", escape_inline(note));
        }
    }
}

fn render_diagnostics(output: &mut String, document: &AuthMapDocument) {
    let _ = writeln!(output, "## Diagnostics");
    let _ = writeln!(output);
    if document.diagnostics.is_empty() {
        let _ = writeln!(output, "No diagnostics were emitted.");
        let _ = writeln!(output);
        return;
    }

    let rows = sorted_diagnostics(document)
        .into_iter()
        .map(|diagnostic| {
            vec![
                diagnostic_severity_label(diagnostic.severity).to_string(),
                escape_table(&diagnostic.code),
                escape_table(&format_optional_span_table(diagnostic.span.as_ref())),
                escape_table(&diagnostic.message),
            ]
        })
        .collect::<Vec<_>>();
    render_table(output, &["Severity", "Code", "Location", "Message"], &rows);
    let _ = writeln!(output);
}

fn render_skipped_files(output: &mut String, document: &AuthMapDocument) {
    let _ = writeln!(output, "## Skipped Files");
    let _ = writeln!(output);
    let skipped = skipped_files(document);
    if skipped.is_empty() {
        let _ = writeln!(output, "No files were skipped.");
        let _ = writeln!(output);
        return;
    }

    let rows = skipped
        .into_iter()
        .filter_map(|file| {
            let skipped = file.skipped.as_ref()?;
            Some(vec![
                escape_table(&file.path),
                escape_table(&skipped.code),
                escape_table(&skipped.message),
            ])
        })
        .collect::<Vec<_>>();
    render_table(output, &["File", "Code", "Message"], &rows);
    let _ = writeln!(output);
}

pub fn render_rule_suggestions_markdown(report: &RuleSuggestionReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# AuthMap Rule Suggestions");
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "- Note: Suggestions are local heuristics for reviewer consideration; they are not proof of security controls."
    );
    let _ = writeln!(
        output,
        "- Targets: {}",
        list_or_none(
            report
                .target_roots
                .iter()
                .map(|target| escape_inline(target))
                .collect::<Vec<_>>()
        )
    );
    let _ = writeln!(
        output,
        "- Source files scanned: {}",
        report.source_files_scanned
    );
    let _ = writeln!(output, "- Suggestions: {}", report.suggestions.len());
    let _ = writeln!(output);

    if report.suggestions.is_empty() {
        let _ = writeln!(
            output,
            "No custom authorization rule suggestions were found."
        );
        let _ = writeln!(output);
        render_rule_suggestion_diagnostics(&mut output, report);
        return output;
    }

    let _ = writeln!(output, "## Suggested Config");
    let _ = writeln!(output);
    let _ = writeln!(output, "```yaml");
    let _ = writeln!(output, "authorization:");
    let _ = writeln!(output, "  rules:");
    for suggestion in &report.suggestions {
        let _ = writeln!(output, "    - name: {}", yaml_string(&suggestion.name));
        let _ = writeln!(
            output,
            "      evidence_type: {}",
            evidence_type_label(suggestion.evidence_type)
        );
        let _ = writeln!(
            output,
            "      mechanism: {}",
            yaml_string(&suggestion.mechanism)
        );
        let _ = writeln!(
            output,
            "      confidence: {}",
            confidence_label(suggestion.confidence)
        );
        let _ = writeln!(output, "      match:");
        if !suggestion.matcher.exact.is_empty() {
            let _ = writeln!(
                output,
                "        exact: [{}]",
                suggestion
                    .matcher
                    .exact
                    .iter()
                    .map(|item| yaml_string(item))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !suggestion.matcher.contains.is_empty() {
            let _ = writeln!(
                output,
                "        contains: [{}]",
                suggestion
                    .matcher
                    .contains
                    .iter()
                    .map(|item| yaml_string(item))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !suggestion.rationale.is_empty() {
            let _ = writeln!(output, "      notes:");
            for rationale in &suggestion.rationale {
                let _ = writeln!(output, "        - {}", yaml_string(rationale));
            }
        }
    }
    let _ = writeln!(output, "```");
    let _ = writeln!(output);

    let _ = writeln!(output, "## Suggestion Details");
    let _ = writeln!(output);
    for suggestion in &report.suggestions {
        let _ = writeln!(
            output,
            "### {}",
            escape_inline(
                suggestion
                    .matcher
                    .exact
                    .first()
                    .or_else(|| suggestion.matcher.contains.first())
                    .map(String::as_str)
                    .unwrap_or(suggestion.name.as_str())
            )
        );
        let _ = writeln!(
            output,
            "- Evidence type: {}",
            evidence_type_label(suggestion.evidence_type)
        );
        let _ = writeln!(
            output,
            "- Mechanism: {}",
            escape_inline(&suggestion.mechanism)
        );
        let _ = writeln!(
            output,
            "- Confidence: {}",
            confidence_label(suggestion.confidence)
        );
        render_named_markdown_list(&mut output, "Rationale", &suggestion.rationale);
        let examples = suggestion
            .examples
            .iter()
            .map(|example| {
                format!(
                    "{} at {}:{}:{} ({})",
                    escape_inline(&example.symbol),
                    escape_inline(&example.file),
                    example.line,
                    example.column,
                    escape_inline(&example.context)
                )
            })
            .collect::<Vec<_>>();
        render_named_markdown_list(&mut output, "Examples", &examples);
        let _ = writeln!(output);
    }

    render_rule_suggestion_diagnostics(&mut output, report);
    output
}

pub fn render_rule_suggestions_json(report: &RuleSuggestionReport) -> Result<String, ReportError> {
    let mut value = serde_json::to_value(report).map_err(ReportError::Json)?;
    redact_json_value(&mut value);
    serde_json::to_string_pretty(&value).map_err(ReportError::Json)
}

pub fn render_drift_json(report: &DriftReport) -> Result<String, ReportError> {
    let mut value = serde_json::to_value(report).map_err(ReportError::Json)?;
    redact_json_value(&mut value);
    serde_json::to_string_pretty(&value).map_err(ReportError::Json)
}

pub fn render_drift_markdown(report: &DriftReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# AuthMap Drift Report");
    let _ = writeln!(output);
    let _ = writeln!(output, "- Mode: {}", scan_mode_label(report.metadata.mode));
    let _ = writeln!(
        output,
        "- Base: {}",
        escape_inline(&report.metadata.base.label)
    );
    let _ = writeln!(
        output,
        "- Head: {}",
        escape_inline(&report.metadata.head.label)
    );
    let _ = writeln!(
        output,
        "- Enforce fail-on: {}",
        list_or_none(
            report
                .metadata
                .fail_on
                .iter()
                .map(enum_value)
                .collect::<Vec<_>>()
        )
    );
    let _ = writeln!(
        output,
        "- Config source: {}",
        escape_inline(&report.metadata.config.source)
    );
    if let Some(path) = &report.metadata.config.path {
        let _ = writeln!(output, "- Config path: {}", escape_inline(path));
    }
    let _ = writeln!(output);

    let _ = writeln!(output, "## Summary");
    let _ = writeln!(output);
    let _ = writeln!(output, "- Total changes: {}", report.summary.total_changes);
    let _ = writeln!(output, "- Added routes: {}", report.summary.added_routes);
    let _ = writeln!(
        output,
        "- Removed routes: {}",
        report.summary.removed_routes
    );
    let _ = writeln!(
        output,
        "- Handler changes: {}",
        report.summary.handler_changes
    );
    let _ = writeln!(
        output,
        "- Evidence changes: {}",
        report.summary.evidence_changes
    );
    let _ = writeln!(
        output,
        "- Coverage changes: {}",
        report.summary.coverage_changes
    );
    let _ = writeln!(
        output,
        "- New linked mutations: {}",
        report.summary.new_linked_mutations
    );
    let _ = writeln!(
        output,
        "- Blocking changes: {}",
        report.summary.blocking_changes
    );
    let _ = writeln!(output);

    let _ = writeln!(output, "## Changes");
    let _ = writeln!(output);
    if report.changes.is_empty() {
        let _ = writeln!(output, "No authorization drift was detected.");
        let _ = writeln!(output);
        return output;
    }

    let rows = report
        .changes
        .iter()
        .map(drift_change_row)
        .collect::<Vec<_>>();
    render_table(
        &mut output,
        &[
            "ID",
            "Severity",
            "Kind",
            "Route",
            "Direction",
            "Fail Category",
            "Blocking",
            "Message",
        ],
        &rows,
    );
    let _ = writeln!(output);
    output
}

fn drift_change_row(change: &DriftChange) -> Vec<String> {
    vec![
        escape_table(&change.id),
        escape_table(drift_severity_label(change.severity)),
        escape_table(drift_kind_label(change.kind)),
        escape_table(&change.route_key),
        escape_table(change.direction.map_or("none", drift_comparison_label)),
        escape_table(
            &change
                .fail_category
                .as_ref()
                .map(enum_value)
                .unwrap_or_else(|| "none".to_string()),
        ),
        if change.enforcement_blocking {
            "yes".to_string()
        } else {
            "no".to_string()
        },
        escape_table(&change.message),
    ]
}

fn drift_kind_label(kind: DriftChangeKind) -> &'static str {
    match kind {
        DriftChangeKind::AddedRoute => "added_route",
        DriftChangeKind::RemovedRoute => "removed_route",
        DriftChangeKind::HandlerChanged => "handler_changed",
        DriftChangeKind::EvidenceChanged => "evidence_changed",
        DriftChangeKind::CoverageChanged => "coverage_changed",
        DriftChangeKind::NewLinkedMutation => "new_linked_mutation",
    }
}

fn drift_severity_label(severity: DriftChangeSeverity) -> &'static str {
    match severity {
        DriftChangeSeverity::Note => "note",
        DriftChangeSeverity::Warning => "warning",
        DriftChangeSeverity::Error => "error",
    }
}

fn drift_comparison_label(comparison: DriftComparison) -> &'static str {
    match comparison {
        DriftComparison::Upgrade => "upgrade",
        DriftComparison::Downgrade => "downgrade",
        DriftComparison::Changed => "changed",
    }
}

fn render_rule_suggestion_diagnostics(output: &mut String, report: &RuleSuggestionReport) {
    if report.diagnostics.is_empty() {
        return;
    }
    let _ = writeln!(output, "## Diagnostics");
    let _ = writeln!(output);
    for diagnostic in &report.diagnostics {
        let _ = writeln!(
            output,
            "- {} {} at {}: {}",
            diagnostic_severity_label(diagnostic.severity),
            escape_inline(&diagnostic.code),
            format_optional_span(diagnostic.span.as_ref()),
            escape_inline(&diagnostic.message)
        );
    }
    let _ = writeln!(output);
}

fn render_named_markdown_list(output: &mut String, label: &str, items: &[String]) {
    if items.is_empty() {
        let _ = writeln!(output, "- {label}: none");
        return;
    }
    let _ = writeln!(output, "- {label}:");
    for item in items {
        let _ = writeln!(output, "  - {}", escape_inline(item));
    }
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(&redact_sensitive_text(value)).unwrap_or_else(|_| "\"\"".to_string())
}

pub fn render_explain(document: &AuthMapDocument, id: &str) -> Result<String, ExplainError> {
    if document.schema_version != SCHEMA_VERSION {
        return Err(ExplainError::UnsupportedSchemaVersion {
            actual: document.schema_version.clone(),
            expected: SCHEMA_VERSION,
        });
    }

    let index = ReportIndex::new(document);
    let route = document.routes.iter().find(|route| route.id == id);
    let evidence = index.evidence_by_id.get(id).copied();
    let mutation = index.mutation_by_id.get(id).copied();
    let link = index.link_by_id.get(id).copied();

    let mut matches = Vec::new();
    if route.is_some() {
        matches.push("route");
    }
    if evidence.is_some() {
        matches.push("evidence");
    }
    if mutation.is_some() {
        matches.push("mutation");
    }
    if link.is_some() {
        matches.push("link");
    }

    if matches.is_empty() {
        return Err(ExplainError::UnknownId(id.to_string()));
    }
    if matches.len() > 1 {
        return Err(ExplainError::AmbiguousId {
            id: id.to_string(),
            matches: matches.join(", "),
        });
    }

    let mut output = String::new();
    render_explain_header(&mut output, document, id, matches[0]);
    match matches[0] {
        "route" => render_explain_route(
            &mut output,
            route.expect("route was matched"),
            document,
            &index,
        ),
        "evidence" => render_explain_evidence(
            &mut output,
            evidence.expect("evidence was matched"),
            document,
            &index,
        ),
        "mutation" => render_explain_mutation(
            &mut output,
            mutation.expect("mutation was matched"),
            document,
            &index,
        ),
        "link" => render_explain_link(
            &mut output,
            link.expect("link was matched"),
            document,
            &index,
        ),
        _ => unreachable!("matches only contains known kinds"),
    }
    Ok(output)
}

fn render_explain_header(output: &mut String, document: &AuthMapDocument, id: &str, kind: &str) {
    let _ = writeln!(output, "# AuthMap Explain");
    let _ = writeln!(output);
    let _ = writeln!(output, "- ID: {}", escape_inline(id));
    let _ = writeln!(output, "- Kind: {kind}");
    let _ = writeln!(
        output,
        "- Tool: {} {}",
        escape_inline(&document.metadata.tool_name),
        escape_inline(&document.metadata.tool_version)
    );
    let _ = writeln!(
        output,
        "- Schema: {}",
        escape_inline(&document.schema_version)
    );
    let _ = writeln!(
        output,
        "- Note: Risk levels are review priorities, not confirmed vulnerabilities."
    );
    let _ = writeln!(output);
}

fn render_explain_route(
    output: &mut String,
    route: &authmap_core::Route,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    render_explain_route_context(output, route, document, index);
}

fn render_explain_evidence(
    output: &mut String,
    evidence: &Evidence,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    let _ = writeln!(output, "## Selected Evidence");
    let _ = writeln!(output);
    render_explain_evidence_item(output, evidence, "- Evidence");
    let _ = writeln!(output);
    let routes = related_routes_for_evidence(evidence, document, index);
    if routes.is_empty() {
        render_related_routes(output, routes, document, index);
        render_explain_diagnostics(output, document, &context_files_for_evidence(evidence));
    } else {
        render_related_routes(output, routes, document, index);
    }
}

fn render_explain_mutation(
    output: &mut String,
    mutation: &Mutation,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    let _ = writeln!(output, "## Selected Mutation");
    let _ = writeln!(output);
    render_explain_mutation_item(output, mutation, "- Mutation");
    let _ = writeln!(output);
    let routes = related_routes_for_mutation(mutation, document, index);
    if routes.is_empty() {
        render_related_routes(output, routes, document, index);
        render_explain_diagnostics(output, document, &context_files_for_mutation(mutation));
    } else {
        render_related_routes(output, routes, document, index);
    }
}

fn render_explain_link(
    output: &mut String,
    link: &ReachabilityLink,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    let _ = writeln!(output, "## Selected Link");
    let _ = writeln!(output);
    render_explain_link_item(output, link, "- Link");
    let _ = writeln!(output);
    render_related_routes(
        output,
        related_routes_for_link(link, document),
        document,
        index,
    );
}

fn render_related_routes(
    output: &mut String,
    routes: Vec<&authmap_core::Route>,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    if routes.is_empty() {
        let _ = writeln!(output, "## Related Route Context");
        let _ = writeln!(output);
        let _ = writeln!(output, "- Related routes: none");
        let _ = writeln!(output);
        return;
    }

    for route in routes {
        render_explain_route_context(output, route, document, index);
    }
}

fn render_explain_route_context(
    output: &mut String,
    route: &authmap_core::Route,
    document: &AuthMapDocument,
    index: &ReportIndex<'_>,
) {
    let _ = writeln!(output, "## Route Context");
    let _ = writeln!(output);
    let _ = writeln!(output, "- Route ID: {}", escape_inline(&route.id));
    let _ = writeln!(
        output,
        "- Route: {} {}",
        escape_inline(&route.method),
        escape_inline(&route.path)
    );
    let _ = writeln!(output, "- Framework: {}", framework_label(route.framework));
    let _ = writeln!(
        output,
        "- Handler: {}",
        format_optional_symbol(route.handler.as_ref())
    );
    let _ = writeln!(
        output,
        "- Middleware: {}",
        format_symbols(&route.middleware)
    );
    let _ = writeln!(
        output,
        "- Route location: {}",
        format_optional_span(route.span.as_ref())
    );
    let _ = writeln!(
        output,
        "- Route confidence: {}",
        confidence_label(route.confidence)
    );
    render_explain_source_evidence(output, route);
    render_explain_coverage(output, route.id.as_str(), index);
    render_explain_route_evidence(output, route.id.as_str(), index);
    render_explain_route_mutations(output, route.id.as_str(), index);
    render_explain_route_links(output, route.id.as_str(), index);
    render_explain_diagnostics(output, document, &context_files_for_route(route, index));
    let _ = writeln!(output);
}

fn render_explain_source_evidence(output: &mut String, route: &authmap_core::Route) {
    if route.source_evidence.is_empty() {
        let _ = writeln!(output, "- Source evidence: none");
        return;
    }
    let _ = writeln!(output, "- Source evidence:");
    for item in &route.source_evidence {
        let _ = writeln!(
            output,
            "  - {} at {} ({})",
            escape_inline(&item.mechanism),
            format_optional_span(item.span.as_ref()),
            confidence_label(item.confidence)
        );
    }
}

fn render_explain_coverage(output: &mut String, route_id: &str, index: &ReportIndex<'_>) {
    let Some(coverage) = index.coverage_by_route.get(route_id) else {
        let _ = writeln!(output, "- Coverage: not classified");
        return;
    };

    let _ = writeln!(
        output,
        "- Coverage: {} ({})",
        coverage_class_label(coverage.class),
        risk_label(coverage.risk)
    );
    if coverage.rationale.is_empty() {
        let _ = writeln!(output, "- Coverage rationale: none");
    } else {
        let _ = writeln!(
            output,
            "- Coverage rationale: {}",
            coverage
                .rationale
                .iter()
                .map(|item| escape_inline(item))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    render_coverage_support(output, coverage);
    render_named_list(output, "Reviewer questions", &coverage.reviewer_questions);
    render_named_list(
        output,
        "Coverage uncertainty",
        &coverage.uncertainty_reasons,
    );
}

fn render_explain_route_evidence(output: &mut String, route_id: &str, index: &ReportIndex<'_>) {
    let Some(evidence) = index.evidence_by_route.get(route_id) else {
        let _ = writeln!(output, "- Auth evidence: none");
        return;
    };
    if evidence.is_empty() {
        let _ = writeln!(output, "- Auth evidence: none");
        return;
    }
    let _ = writeln!(output, "- Auth evidence:");
    for item in evidence {
        render_explain_evidence_item(output, item, "  -");
    }
}

fn render_explain_evidence_item(output: &mut String, evidence: &Evidence, prefix: &str) {
    let _ = writeln!(
        output,
        "{prefix} {}: {} `{}` at {} ({})",
        escape_inline(&evidence.id),
        evidence_type_label(evidence.evidence_type),
        escape_inline(&evidence.mechanism),
        format_optional_span(evidence.span.as_ref()),
        confidence_label(evidence.confidence)
    );
    if let Some(route_id) = &evidence.route_id {
        let _ = writeln!(output, "    - Route ID: {}", escape_inline(route_id));
    }
    if let Some(symbol) = &evidence.symbol {
        let _ = writeln!(output, "    - Symbol: {}", format_symbol(symbol));
    }
    for note in &evidence.notes {
        let _ = writeln!(output, "    - Note: {}", escape_inline(note));
    }
}

fn render_explain_route_mutations(output: &mut String, route_id: &str, index: &ReportIndex<'_>) {
    let Some(mutations) = index.mutations_by_route.get(route_id) else {
        let _ = writeln!(output, "- Data mutations: none");
        return;
    };
    if mutations.is_empty() {
        let _ = writeln!(output, "- Data mutations: none");
        return;
    }
    let _ = writeln!(output, "- Data mutations:");
    for mutation in mutations {
        render_explain_mutation_item(output, mutation, "  -");
    }
}

fn render_explain_mutation_item(output: &mut String, mutation: &Mutation, prefix: &str) {
    let resource = mutation.resource.as_deref().unwrap_or("unknown resource");
    let library = mutation.library.as_deref().unwrap_or("unknown library");
    let _ = writeln!(
        output,
        "{prefix} {}: {} `{}` via `{}` at {} ({})",
        escape_inline(&mutation.id),
        mutation_operation_label(mutation.operation),
        escape_inline(resource),
        escape_inline(library),
        format_optional_span(mutation.span.as_ref()),
        confidence_label(mutation.confidence)
    );
    for note in &mutation.notes {
        let _ = writeln!(output, "    - Note: {}", escape_inline(note));
    }
}

fn render_explain_route_links(output: &mut String, route_id: &str, index: &ReportIndex<'_>) {
    let Some(links) = index.links_by_route.get(route_id) else {
        let _ = writeln!(output, "- Reachability links: none");
        return;
    };
    if links.is_empty() {
        let _ = writeln!(output, "- Reachability links: none");
        return;
    }
    let _ = writeln!(output, "- Reachability links:");
    for link in links {
        render_explain_link_item(output, link, "  -");
    }
}

fn render_explain_link_item(output: &mut String, link: &ReachabilityLink, prefix: &str) {
    let _ = writeln!(
        output,
        "{prefix} {}: route={} evidence={} mutation={} ({})",
        escape_inline(&link.id),
        escape_inline(&link.route_id),
        link.evidence_id
            .as_deref()
            .map(escape_inline)
            .unwrap_or_else(|| "none".to_string()),
        link.mutation_id
            .as_deref()
            .map(escape_inline)
            .unwrap_or_else(|| "none".to_string()),
        confidence_label(link.confidence)
    );
    for note in &link.notes {
        let _ = writeln!(output, "    - Note: {}", escape_inline(note));
    }
}

fn render_explain_diagnostics(
    output: &mut String,
    document: &AuthMapDocument,
    context_files: &BTreeSet<String>,
) {
    let diagnostics = sorted_diagnostics(document)
        .into_iter()
        .filter(|diagnostic| {
            diagnostic
                .span
                .as_ref()
                .is_some_and(|span| context_files.contains(&span.file))
        })
        .collect::<Vec<_>>();

    if diagnostics.is_empty() {
        let _ = writeln!(output, "- Related diagnostics: none");
        return;
    }
    let _ = writeln!(output, "- Related diagnostics:");
    for diagnostic in diagnostics {
        let _ = writeln!(
            output,
            "  - {} {} at {}: {}",
            diagnostic_severity_label(diagnostic.severity),
            escape_inline(&diagnostic.code),
            format_optional_span(diagnostic.span.as_ref()),
            escape_inline(&diagnostic.message)
        );
    }
}

fn render_named_list(output: &mut String, label: &str, items: &[String]) {
    if items.is_empty() {
        let _ = writeln!(output, "- {label}: none");
        return;
    }
    let _ = writeln!(output, "- {label}:");
    for item in items {
        let _ = writeln!(output, "  - {}", escape_inline(item));
    }
}

fn related_routes_for_evidence<'a>(
    evidence: &Evidence,
    document: &'a AuthMapDocument,
    index: &ReportIndex<'a>,
) -> Vec<&'a authmap_core::Route> {
    let mut route_ids = BTreeSet::new();
    if let Some(route_id) = &evidence.route_id {
        route_ids.insert(route_id.as_str());
    }
    for links in index.links_by_route.values() {
        for link in links {
            if link.evidence_id.as_deref() == Some(evidence.id.as_str()) {
                route_ids.insert(link.route_id.as_str());
            }
        }
    }
    routes_by_id(document, route_ids)
}

fn related_routes_for_mutation<'a>(
    mutation: &Mutation,
    document: &'a AuthMapDocument,
    index: &ReportIndex<'a>,
) -> Vec<&'a authmap_core::Route> {
    let mut route_ids = BTreeSet::new();
    for links in index.links_by_route.values() {
        for link in links {
            if link.mutation_id.as_deref() == Some(mutation.id.as_str()) {
                route_ids.insert(link.route_id.as_str());
            }
        }
    }
    routes_by_id(document, route_ids)
}

fn related_routes_for_link<'a>(
    link: &ReachabilityLink,
    document: &'a AuthMapDocument,
) -> Vec<&'a authmap_core::Route> {
    routes_by_id(document, BTreeSet::from([link.route_id.as_str()]))
}

fn routes_by_id<'a>(
    document: &'a AuthMapDocument,
    route_ids: BTreeSet<&str>,
) -> Vec<&'a authmap_core::Route> {
    let mut routes = route_ids
        .into_iter()
        .filter_map(|route_id| document.routes.iter().find(|route| route.id == route_id))
        .collect::<Vec<_>>();
    routes.sort_by_key(|route| route_sort_key(route));
    routes
}

fn context_files_for_route(
    route: &authmap_core::Route,
    index: &ReportIndex<'_>,
) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    collect_span_file(&mut files, route.span.as_ref());
    if let Some(handler) = &route.handler {
        collect_span_file(&mut files, handler.span.as_ref());
    }
    for middleware in &route.middleware {
        collect_span_file(&mut files, middleware.span.as_ref());
    }
    for source in &route.source_evidence {
        collect_span_file(&mut files, source.span.as_ref());
        if let Some(symbol) = &source.symbol {
            collect_span_file(&mut files, symbol.span.as_ref());
        }
    }
    if let Some(evidence) = index.evidence_by_route.get(route.id.as_str()) {
        for item in evidence {
            collect_span_file(&mut files, item.span.as_ref());
            if let Some(symbol) = &item.symbol {
                collect_span_file(&mut files, symbol.span.as_ref());
            }
        }
    }
    if let Some(mutations) = index.mutations_by_route.get(route.id.as_str()) {
        for mutation in mutations {
            collect_span_file(&mut files, mutation.span.as_ref());
        }
    }
    files
}

fn context_files_for_evidence(evidence: &Evidence) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    collect_span_file(&mut files, evidence.span.as_ref());
    if let Some(symbol) = &evidence.symbol {
        collect_span_file(&mut files, symbol.span.as_ref());
    }
    files
}

fn context_files_for_mutation(mutation: &Mutation) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    collect_span_file(&mut files, mutation.span.as_ref());
    files
}

fn collect_span_file(files: &mut BTreeSet<String>, span: Option<&Span>) {
    if let Some(span) = span {
        files.insert(span.file.clone());
    }
}

fn render_table(output: &mut String, headers: &[&str], rows: &[Vec<String>]) {
    let _ = writeln!(
        output,
        "| {} |",
        headers
            .iter()
            .map(|header| escape_table(header))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    let _ = writeln!(
        output,
        "| {} |",
        headers
            .iter()
            .map(|_| "---")
            .collect::<Vec<_>>()
            .join(" | ")
    );
    for row in rows {
        let _ = writeln!(output, "| {} |", row.join(" | "));
    }
}

fn sorted_routes(document: &AuthMapDocument) -> Vec<&authmap_core::Route> {
    let mut routes = document.routes.iter().collect::<Vec<_>>();
    routes.sort_by_key(|route| route_sort_key(route));
    routes
}

fn sorted_mutations(document: &AuthMapDocument) -> Vec<&Mutation> {
    let mut mutations = document.mutations.iter().collect::<Vec<_>>();
    mutations.sort_by_key(|mutation| mutation_sort_key(mutation));
    mutations
}

fn sorted_diagnostics(document: &AuthMapDocument) -> Vec<&Diagnostic> {
    let mut diagnostics = document.diagnostics.iter().collect::<Vec<_>>();
    diagnostics.sort_by_key(|diagnostic| diagnostic_sort_key(diagnostic));
    diagnostics
}

fn skipped_files(document: &AuthMapDocument) -> Vec<&SourceFile> {
    let mut skipped = document
        .source_files
        .iter()
        .filter(|file| file.skipped.is_some())
        .collect::<Vec<_>>();
    skipped.sort_by(|left, right| left.path.cmp(&right.path));
    skipped
}

fn route_sort_key(route: &authmap_core::Route) -> (String, u32, String, String, String) {
    (
        route.id.clone(),
        route.span.as_ref().map_or(0, |span| span.line),
        route.method.clone(),
        route.path.clone(),
        route
            .handler
            .as_ref()
            .map_or_else(String::new, |handler| handler.name.clone()),
    )
}

fn mutation_sort_key(mutation: &Mutation) -> (String, u32, u32, MutationOperation, String, String) {
    (
        mutation
            .span
            .as_ref()
            .map_or_else(String::new, |span| span.file.clone()),
        mutation.span.as_ref().map_or(0, |span| span.line),
        mutation.span.as_ref().map_or(0, |span| span.column),
        mutation.operation,
        mutation.library.clone().unwrap_or_default(),
        mutation.resource.clone().unwrap_or_default(),
    )
}

fn diagnostic_sort_key(diagnostic: &Diagnostic) -> (String, u32, String, String) {
    (
        diagnostic_severity_label(diagnostic.severity).to_string(),
        diagnostic.span.as_ref().map_or(0, |span| span.line),
        diagnostic.code.clone(),
        diagnostic.message.clone(),
    )
}

fn framework_counts(document: &AuthMapDocument) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for route in &document.routes {
        *counts.entry(framework_label(route.framework)).or_default() += 1;
    }
    counts
}

fn dedup_evidence(evidence: &mut Vec<&Evidence>) {
    let mut seen = BTreeSet::new();
    evidence.retain(|item| seen.insert(item.id.as_str()));
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
}

fn dedup_mutations(mutations: &mut Vec<&Mutation>) {
    let mut seen = BTreeSet::new();
    mutations.retain(|item| seen.insert(item.id.as_str()));
    mutations.sort_by(|left, right| left.id.cmp(&right.id));
}

fn dedup_links(links: &mut Vec<&ReachabilityLink>) {
    let mut seen = BTreeSet::new();
    links.retain(|item| seen.insert(item.id.as_str()));
    links.sort_by(|left, right| left.id.cmp(&right.id));
}

fn route_anchor(id: &str) -> String {
    format!("route-{}", slug(id))
}

fn slug(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn format_optional_symbol(symbol: Option<&SymbolRef>) -> String {
    symbol.map_or_else(|| "unknown".to_string(), format_symbol)
}

fn format_optional_symbol_table(symbol: Option<&SymbolRef>) -> String {
    symbol.map_or_else(|| "unknown".to_string(), format_symbol_table)
}

fn format_symbol(symbol: &SymbolRef) -> String {
    format!(
        "`{}` ({})",
        escape_inline(&symbol.name),
        format_optional_span(symbol.span.as_ref())
    )
}

fn format_symbol_table(symbol: &SymbolRef) -> String {
    format!(
        "`{}` ({})",
        symbol.name,
        format_optional_span_table(symbol.span.as_ref())
    )
}

fn format_symbols(symbols: &[SymbolRef]) -> String {
    if symbols.is_empty() {
        return "none".to_string();
    }
    symbols
        .iter()
        .map(format_symbol)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_symbols_table(symbols: &[SymbolRef]) -> String {
    if symbols.is_empty() {
        return "none".to_string();
    }
    symbols
        .iter()
        .map(format_symbol_table)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_optional_span(span: Option<&Span>) -> String {
    span.map_or_else(|| "unknown".to_string(), format_span)
}

fn format_optional_span_table(span: Option<&Span>) -> String {
    span.map_or_else(|| "unknown".to_string(), format_span_table)
}

fn format_span(span: &Span) -> String {
    format!(
        "{}:{}:{}",
        escape_inline(&span.file),
        span.line,
        span.column
    )
}

fn format_span_table(span: &Span) -> String {
    format!("{}:{}:{}", span.file, span.line, span.column)
}

fn list_or_none(items: Vec<String>) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn escape_table(input: &str) -> String {
    escape_inline(input).replace('|', "\\|")
}

fn escape_inline(input: &str) -> String {
    let redacted = redact_sensitive_text(input);
    let mut sanitized = String::new();
    for ch in redacted.chars() {
        match ch {
            '\n' => sanitized.push_str("\\n"),
            '\r' => sanitized.push_str("\\r"),
            '\t' => sanitized.push(' '),
            '\u{1b}' => sanitized.push_str("\\x1b"),
            ch if ch.is_control() => {
                let _ = write!(sanitized, "\\u{{{:x}}}", ch as u32);
            }
            ch => sanitized.push(ch),
        }
    }
    if matches!(sanitized.chars().next(), Some('#' | '>' | '-' | '*' | '+')) {
        sanitized.insert(0, '\\');
    }
    sanitized
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('`', "\\`")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn scan_mode_label(mode: ScanMode) -> &'static str {
    match mode {
        ScanMode::Advisory => "advisory",
        ScanMode::Enforce => "enforce",
    }
}

fn framework_label(framework: Framework) -> &'static str {
    match framework {
        Framework::FastApi => "fast_api",
        Framework::Django => "django",
        Framework::DjangoRestFramework => "django_rest_framework",
        Framework::Express => "express",
        Framework::NextJs => "next_js",
        Framework::Unknown => "unknown",
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn coverage_class_label(class: CoverageClass) -> &'static str {
    match class {
        CoverageClass::PublicDeclared => "public_declared",
        CoverageClass::Unauthenticated => "unauthenticated",
        CoverageClass::AuthnOnly => "authn_only",
        CoverageClass::RoleGuarded => "role_guarded",
        CoverageClass::PermissionGuarded => "permission_guarded",
        CoverageClass::OwnershipGuarded => "ownership_guarded",
        CoverageClass::TenantGuarded => "tenant_guarded",
        CoverageClass::AdminGuarded => "admin_guarded",
        CoverageClass::UnknownOrDynamic => "unknown_or_dynamic",
    }
}

fn risk_label(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::ReviewRequired => "review_required",
    }
}

fn evidence_type_label(evidence_type: EvidenceType) -> &'static str {
    match evidence_type {
        EvidenceType::Authn => "authn",
        EvidenceType::RoleCheck => "role_check",
        EvidenceType::PermissionCheck => "permission_check",
        EvidenceType::OwnershipCheck => "ownership_check",
        EvidenceType::TenantCheck => "tenant_check",
        EvidenceType::AdminCheck => "admin_check",
        EvidenceType::ExplicitPublic => "explicit_public",
        EvidenceType::AuditLog => "audit_log",
        EvidenceType::UnknownDynamicCheck => "unknown_dynamic_check",
    }
}

fn mutation_operation_label(operation: MutationOperation) -> &'static str {
    match operation {
        MutationOperation::Create => "create",
        MutationOperation::Update => "update",
        MutationOperation::Delete => "delete",
        MutationOperation::Save => "save",
        MutationOperation::BulkUpdate => "bulk_update",
        MutationOperation::RawSqlMutation => "raw_sql_mutation",
        MutationOperation::UnknownMutation => "unknown_mutation",
    }
}

fn mutation_review_summary(mutation: &Mutation) -> String {
    let Some(metadata) = mutation.extensions.get("authmap.mutation") else {
        return "none".to_string();
    };
    if metadata
        .get("review_required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let detection = metadata
            .get("detection")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return format!("review_required ({detection})");
    }
    "none".to_string()
}

fn diagnostic_severity_label(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

#[derive(Clone, Debug, Default)]
pub struct SarifReporter;

impl Reporter for SarifReporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Sarif
    }

    fn render(&self, document: &AuthMapDocument) -> Result<String, ReportError> {
        let index = ReportIndex::new(document);
        let mut results = Vec::new();
        let mut coverage_rule_ids = BTreeSet::new();
        for route in sorted_routes(document) {
            let Some(coverage) = index.coverage_by_route.get(route.id.as_str()) else {
                continue;
            };
            let Some(rule_id) = coverage_sarif_rule_id(coverage) else {
                continue;
            };
            coverage_rule_ids.insert(rule_id);
            results.push(coverage_result(route, coverage, &index, rule_id));
        }
        results.extend(document.diagnostics.iter().map(diagnostic_result));

        let mut rules = coverage_rules(&coverage_rule_ids);
        rules.extend(diagnostic_rules(&document.diagnostics));
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
        let mut sarif = sarif;
        redact_json_value(&mut sarif);
        serde_json::to_string_pretty(&sarif).map_err(ReportError::Json)
    }
}

const SARIF_UNAUTHENTICATED_SENSITIVE: &str = "authmap.unauthenticated_sensitive";
const SARIF_AUTHN_ONLY_SENSITIVE: &str = "authmap.authn_only_sensitive";
const SARIF_UNKNOWN_DYNAMIC: &str = "authmap.unknown_dynamic";
const SARIF_MISSING_EXPLICIT_EVIDENCE: &str = "authmap.missing_explicit_evidence";

fn coverage_rules(rule_ids: &BTreeSet<&'static str>) -> Vec<Value> {
    rule_ids
        .iter()
        .map(|rule_id| {
            let (name, short, full, help) = coverage_rule_text(rule_id);
            json!({
                "id": rule_id,
                "name": name,
                "shortDescription": {
                    "text": short
                },
                "fullDescription": {
                    "text": full
                },
                "help": {
                    "text": help,
                    "markdown": help
                },
                "defaultConfiguration": {
                    "level": "warning"
                },
                "properties": {
                    "category": "authorization_coverage",
                    "precision": "medium",
                    "problem.severity": "warning"
                }
            })
        })
        .collect()
}

fn coverage_rule_text(rule_id: &str) -> (&'static str, &'static str, &'static str, &'static str) {
    match rule_id {
        SARIF_UNAUTHENTICATED_SENSITIVE => (
            "Unauthenticated sensitive route",
            "Sensitive route has no detected authorization evidence",
            "AuthMap found a sensitive route without detected authentication or authorization evidence.",
            "Review whether this route should have server-side authorization evidence. AuthMap reports this as an advisory coverage observation, not a confirmed vulnerability.",
        ),
        SARIF_AUTHN_ONLY_SENSITIVE => (
            "Authentication-only sensitive route",
            "Sensitive route appears guarded only by authentication",
            "AuthMap found a sensitive or mutation-linked route where the strongest detected coverage is authentication-only.",
            "Review whether this route needs resource-specific authorization such as role, permission, ownership, or tenant checks. AuthMap reports this as an advisory coverage observation.",
        ),
        SARIF_UNKNOWN_DYNAMIC => (
            "Unknown or dynamic authorization coverage",
            "Authorization evidence is weak, dynamic, or incomplete",
            "AuthMap found authorization evidence that could not be statically resolved with high confidence.",
            "Review the dynamic authorization path and confirm the intended guard behavior. AuthMap reports this as an advisory coverage observation.",
        ),
        SARIF_MISSING_EXPLICIT_EVIDENCE => (
            "Missing explicit authorization evidence",
            "Route needs explicit authorization review",
            "AuthMap found a high or review-required route where explicit resource-specific authorization evidence is incomplete.",
            "Review whether the detected evidence is sufficient for the route and any linked data mutations. AuthMap reports this as an advisory coverage observation.",
        ),
        _ => (
            "Authorization coverage review",
            "Route needs authorization review",
            "AuthMap found an authorization coverage observation that needs review.",
            "Review the route coverage details. AuthMap reports this as an advisory coverage observation.",
        ),
    }
}

fn coverage_sarif_rule_id(coverage: &Coverage) -> Option<&'static str> {
    match coverage.class {
        CoverageClass::Unauthenticated
            if matches!(
                coverage.risk,
                RiskLevel::Medium | RiskLevel::High | RiskLevel::ReviewRequired
            ) =>
        {
            Some(SARIF_UNAUTHENTICATED_SENSITIVE)
        }
        CoverageClass::UnknownOrDynamic => Some(SARIF_UNKNOWN_DYNAMIC),
        CoverageClass::AuthnOnly if coverage.risk == RiskLevel::ReviewRequired => {
            Some(SARIF_AUTHN_ONLY_SENSITIVE)
        }
        _ if matches!(coverage.risk, RiskLevel::High | RiskLevel::ReviewRequired) => {
            Some(SARIF_MISSING_EXPLICIT_EVIDENCE)
        }
        _ => None,
    }
}

fn coverage_result(
    route: &authmap_core::Route,
    coverage: &Coverage,
    index: &ReportIndex<'_>,
    rule_id: &str,
) -> Value {
    let evidence_ids = coverage_evidence_ids(route, coverage, index);
    let weak_evidence_ids = coverage_weak_evidence_ids(route, coverage, index);
    let mutation_ids = coverage_mutation_ids(route, coverage, index);
    let link_ids = coverage_link_ids(route, coverage, index);
    let sensitivity_reasons = coverage_support_strings(coverage, "sensitivity_reasons");

    let mut result = json!({
        "ruleId": rule_id,
        "level": "warning",
        "message": {
            "text": format!(
                "Review authorization coverage for {} {}: coverage is {}, risk is {}.",
                route.method,
                route.path,
                coverage_class_label(coverage.class),
                risk_label(coverage.risk)
            )
        },
        "partialFingerprints": {
            "authmapStable": sarif_stable_fingerprint(rule_id, route),
            "authmapRuleId": rule_id,
            "authmapFramework": framework_label(route.framework),
            "authmapMethod": route.method,
            "authmapPath": route.path
        },
        "properties": {
            "authmap.kind": "coverage",
            "route_id": route.id,
            "method": route.method,
            "path": route.path,
            "coverage_class": coverage_class_label(coverage.class),
            "risk": risk_label(coverage.risk),
            "rationale": coverage.rationale,
            "reviewer_questions": coverage.reviewer_questions,
            "uncertainty_reasons": coverage.uncertainty_reasons,
            "evidence_ids": evidence_ids,
            "weak_evidence_ids": weak_evidence_ids,
            "mutation_ids": mutation_ids,
            "link_ids": link_ids,
            "sensitivity_reasons": sensitivity_reasons
        }
    });

    if let Some(span) = coverage_location(route, coverage, index) {
        result["locations"] = json!([sarif_location(span)]);
    }

    result
}

fn sarif_stable_fingerprint(rule_id: &str, route: &authmap_core::Route) -> String {
    let handler_name = route
        .handler
        .as_ref()
        .map_or("", |handler| handler.name.as_str());
    let handler_file = route
        .handler
        .as_ref()
        .and_then(|handler| handler.span.as_ref())
        .map_or("", |span| span.file.as_str());
    format!(
        "{}|{}|{}|{}|{}|{}",
        rule_id,
        framework_label(route.framework),
        route.method,
        route.path,
        handler_name,
        handler_file
    )
}

fn coverage_location<'a>(
    route: &'a authmap_core::Route,
    coverage: &Coverage,
    index: &'a ReportIndex<'a>,
) -> Option<&'a Span> {
    if let Some(span) = route
        .handler
        .as_ref()
        .and_then(|handler| handler.span.as_ref())
    {
        return Some(span);
    }
    if let Some(span) = route.span.as_ref() {
        return Some(span);
    }
    for evidence_id in coverage_evidence_ids(route, coverage, index) {
        if let Some(span) = index
            .evidence_by_id
            .get(evidence_id.as_str())
            .and_then(|evidence| evidence.span.as_ref())
        {
            return Some(span);
        }
    }
    for mutation_id in coverage_mutation_ids(route, coverage, index) {
        if let Some(span) = index
            .mutation_by_id
            .get(mutation_id.as_str())
            .and_then(|mutation| mutation.span.as_ref())
        {
            return Some(span);
        }
    }
    None
}

fn coverage_evidence_ids(
    route: &authmap_core::Route,
    coverage: &Coverage,
    index: &ReportIndex<'_>,
) -> Vec<String> {
    let mut ids = coverage_support_strings(coverage, "evidence_ids");
    if ids.is_empty() {
        ids = index
            .evidence_by_route
            .get(route.id.as_str())
            .map(|items| items.iter().map(|item| item.id.clone()).collect())
            .unwrap_or_default();
    }
    sort_and_dedup_strings(&mut ids);
    ids
}

fn coverage_weak_evidence_ids(
    route: &authmap_core::Route,
    coverage: &Coverage,
    index: &ReportIndex<'_>,
) -> Vec<String> {
    let mut ids = coverage_support_strings(coverage, "weak_evidence_ids");
    if ids.is_empty() {
        ids = index
            .evidence_by_route
            .get(route.id.as_str())
            .map(|items| {
                items
                    .iter()
                    .filter(|item| {
                        item.confidence == Confidence::Low
                            || item.evidence_type == EvidenceType::UnknownDynamicCheck
                    })
                    .map(|item| item.id.clone())
                    .collect()
            })
            .unwrap_or_default();
    }
    sort_and_dedup_strings(&mut ids);
    ids
}

fn coverage_mutation_ids(
    route: &authmap_core::Route,
    coverage: &Coverage,
    index: &ReportIndex<'_>,
) -> Vec<String> {
    let mut ids = coverage_support_strings(coverage, "mutation_ids");
    if ids.is_empty() {
        ids = index
            .mutations_by_route
            .get(route.id.as_str())
            .map(|items| items.iter().map(|item| item.id.clone()).collect())
            .unwrap_or_default();
    }
    sort_and_dedup_strings(&mut ids);
    ids
}

fn coverage_link_ids(
    route: &authmap_core::Route,
    coverage: &Coverage,
    index: &ReportIndex<'_>,
) -> Vec<String> {
    let mut ids = coverage_support_strings(coverage, "link_ids");
    if ids.is_empty() {
        ids = index
            .links_by_route
            .get(route.id.as_str())
            .map(|items| items.iter().map(|item| item.id.clone()).collect())
            .unwrap_or_default();
    }
    sort_and_dedup_strings(&mut ids);
    ids
}

fn coverage_support_strings(coverage: &Coverage, key: &str) -> Vec<String> {
    coverage
        .extensions
        .get("authmap.coverage")
        .and_then(|value| value.get(key))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn sort_and_dedup_strings(items: &mut Vec<String>) {
    items.sort();
    items.dedup();
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
        result["locations"] = json!([sarif_location(span)]);
    }
    result
}

fn sarif_location(span: &Span) -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": redact_sensitive_text(&span.file)
            },
            "region": sarif_region(span)
        }
    })
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

pub fn redact_sensitive_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut redacted = input.to_string();
    for pattern in redaction_patterns() {
        redacted = pattern.apply(&redacted);
    }
    redacted
}

fn redact_json_value(value: &mut Value) {
    redact_json_value_for_key(value, None);
}

fn redact_json_value_for_key(value: &mut Value, key: Option<&str>) {
    match value {
        Value::String(text) => {
            if !is_stable_identifier_key(key) || contains_sensitive_marker(text) {
                *text = redact_sensitive_text(text);
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value_for_key(item, key);
            }
        }
        Value::Object(map) => redact_json_object(map),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn redact_json_object(map: &mut Map<String, Value>) {
    for (key, value) in map {
        let nested_key = Some(key.as_str());
        if is_numeric_location_key(key) {
            continue;
        }
        redact_json_value_for_key(value, nested_key);
    }
}

fn is_stable_identifier_key(key: Option<&str>) -> bool {
    matches!(
        key,
        Some(
            "id" | "route_id"
                | "base_route_id"
                | "head_route_id"
                | "evidence_id"
                | "mutation_id"
                | "link_id"
                | "evidence_ids"
                | "weak_evidence_ids"
                | "mutation_ids"
                | "link_ids"
                | "schema_version"
                | "tool_version"
        )
    )
}

fn is_numeric_location_key(key: &str) -> bool {
    matches!(key, "region")
}

fn contains_sensitive_marker(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    [
        "authorization",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "password",
        "passwd",
        "secret",
        "credential",
        "client_secret",
        "bearer ",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

struct RedactionPattern {
    regex: Regex,
    replacement: RedactionReplacement,
}

enum RedactionReplacement {
    Static(&'static str),
    SecretValue,
    QuotedSecretValue,
    Header,
    UrlCredential,
    QueryValue,
}

impl RedactionPattern {
    fn apply(&self, input: &str) -> String {
        match self.replacement {
            RedactionReplacement::Static(replacement) => {
                self.regex.replace_all(input, replacement).into_owned()
            }
            RedactionReplacement::SecretValue => self
                .regex
                .replace_all(input, |captures: &Captures<'_>| {
                    format!(
                        "{}[REDACTED]",
                        captures.get(1).map_or("", |item| item.as_str())
                    )
                })
                .into_owned(),
            RedactionReplacement::QuotedSecretValue => self
                .regex
                .replace_all(input, |captures: &Captures<'_>| {
                    format!(
                        "{}{}[REDACTED]{}",
                        captures.get(1).map_or("", |item| item.as_str()),
                        captures.get(2).map_or("", |item| item.as_str()),
                        captures.get(4).map_or("", |item| item.as_str())
                    )
                })
                .into_owned(),
            RedactionReplacement::Header => self
                .regex
                .replace_all(input, |captures: &Captures<'_>| {
                    format!(
                        "{}[REDACTED]",
                        captures.get(1).map_or("", |item| item.as_str())
                    )
                })
                .into_owned(),
            RedactionReplacement::UrlCredential => self
                .regex
                .replace_all(input, |captures: &Captures<'_>| {
                    format!(
                        "{}[REDACTED]@",
                        captures.get(1).map_or("", |item| item.as_str())
                    )
                })
                .into_owned(),
            RedactionReplacement::QueryValue => self
                .regex
                .replace_all(input, |captures: &Captures<'_>| {
                    format!(
                        "{}[REDACTED]",
                        captures.get(1).map_or("", |item| item.as_str())
                    )
                })
                .into_owned(),
        }
    }
}

fn redaction_patterns() -> &'static [RedactionPattern] {
    static PATTERNS: OnceLock<Vec<RedactionPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            RedactionPattern {
                regex: Regex::new(r"(?i)\b(authorization\s*:\s*)(?:bearer|basic)?\s*[^\s,;|]+")
                    .expect("authorization header redaction regex should compile"),
                replacement: RedactionReplacement::Header,
            },
            RedactionPattern {
                regex: Regex::new(r#"(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|passwd|pwd|credential|client[_-]?secret|access[_-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*)([\"'])([^\"']+)([\"'])"#)
                    .expect("quoted secret assignment redaction regex should compile"),
                replacement: RedactionReplacement::QuotedSecretValue,
            },
            RedactionPattern {
                regex: Regex::new(r#"(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|passwd|pwd|credential|client[_-]?secret|access[_-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*)[^\s,;&|/\"']+"#)
                    .expect("secret assignment redaction regex should compile"),
                replacement: RedactionReplacement::SecretValue,
            },
            RedactionPattern {
                regex: Regex::new(r"(?i)([?&](?:api[_-]?key|token|access_token|refresh_token|password|passwd|pwd|secret|client_secret)=)[^&#/\s]+")
                    .expect("query secret redaction regex should compile"),
                replacement: RedactionReplacement::QueryValue,
            },
            RedactionPattern {
                regex: Regex::new(r"\b([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@")
                    .expect("URL credential redaction regex should compile"),
                replacement: RedactionReplacement::UrlCredential,
            },
            RedactionPattern {
                regex: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                    .expect("JWT redaction regex should compile"),
                replacement: RedactionReplacement::Static("[REDACTED]"),
            },
            RedactionPattern {
                regex: Regex::new(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b")
                    .expect("known token redaction regex should compile"),
                replacement: RedactionReplacement::Static("[REDACTED]"),
            },
        ]
    })
}

pub fn write_atomic(path: &Path, contents: &str) -> Result<(), ReportError> {
    let temp_path = temp_path_for(path);
    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|source| ReportError::Write {
            path: temp_path.clone(),
            source,
        })?;
    temp_file
        .write_all(contents.as_bytes())
        .map_err(|source| ReportError::Write {
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
pub enum ExplainError {
    #[error("unsupported AuthMap schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        actual: String,
        expected: &'static str,
    },
    #[error("unknown AuthMap ID {0}")]
    UnknownId(String),
    #[error("ambiguous AuthMap ID {id}; matches: {matches}")]
    AmbiguousId { id: String, matches: String },
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
    use authmap_analysis::{
        RuleSuggestion, RuleSuggestionExample, RuleSuggestionMatch, RuleSuggestionReport,
    };
    use authmap_core::{
        AuthMapDocument, ByteRange, Confidence, Coverage, CoverageClass, Diagnostic,
        DiagnosticCategory, DiagnosticSeverity, Evidence, EvidenceType, ExtensionMap, Framework,
        Mutation, MutationOperation, ReachabilityLink, Recoverability, RiskLevel, Route,
        ScanMetadata, SkipReason, SourceFile, Span, SymbolRef, diagnostic_codes,
    };

    #[test]
    fn renders_empty_document_without_review_items() {
        let rendered = MarkdownReporter
            .render(&AuthMapDocument::empty(ScanMetadata::default()))
            .expect("markdown render should succeed");

        assert!(rendered.contains("# AuthMap Report"));
        assert!(rendered.contains("- Routes: 0"));
        assert!(rendered.contains("No review-required items were identified."));
        assert!(rendered.contains("No routes were discovered."));
    }

    #[test]
    fn renders_synthetic_evidence_mutations_and_questions() {
        let document = synthetic_document();
        let rendered = MarkdownReporter
            .render(&document)
            .expect("markdown render should succeed");

        assert!(rendered.contains("[route_0001](#route-route_0001)"));
        assert!(rendered.contains("/admin\\|users"));
        assert!(rendered.contains("requires_admin"));
        assert!(rendered.contains("update `user.disabled` via `sqlalchemy`"));
        assert!(rendered.contains("Should this require a tenant check?"));
        assert!(rendered.contains("risk is review_required"));
    }

    #[test]
    fn renders_rule_suggestions_markdown_and_json() {
        let report = rule_suggestion_report();

        let markdown = render_rule_suggestions_markdown(&report);
        assert!(markdown.contains("# AuthMap Rule Suggestions"));
        assert!(markdown.contains("Suggestions are local heuristics"));
        assert!(markdown.contains("authorization:"));
        assert!(markdown.contains("exact: [\"ensurePaidPlan\"]"));
        assert!(markdown.contains("name suggests a permission"));
        assert!(markdown.contains("src/app.js:4:10"));

        let json: Value = serde_json::from_str(
            &render_rule_suggestions_json(&report).expect("JSON should render"),
        )
        .expect("suggestion report should be JSON");
        assert_eq!(
            json["suggestions"][0]["match"]["exact"][0],
            "ensurePaidPlan"
        );
        assert_eq!(json["suggestions"][0]["evidence_type"], "permission_check");
    }

    #[test]
    fn inline_escaping_neutralizes_line_breaks_controls_and_markdown_markers() {
        assert_eq!(
            escape_inline("- forged\n\u{1b}[31m"),
            "\\- forged\\n\\x1b\\[31m"
        );
        assert_eq!(escape_inline("# heading\rnext"), "\\# heading\\rnext");
        assert_eq!(escape_table("a|b\nc"), "a\\|b\\nc");
    }

    #[test]
    fn redacts_common_secret_shapes_without_removing_review_context() {
        let cases = [
            (
                "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
                "Authorization: [REDACTED]",
            ),
            (
                "DATABASE_URL=postgres://alice:swordfish@db.internal/app",
                "DATABASE_URL=postgres://[REDACTED]@db.internal/app",
            ),
            (
                "api_key=sk-abcdefghijklmnopqrstuvwxyz",
                "api_key=[REDACTED]",
            ),
            (
                "GET /callback?token=abcdef1234567890&state=ok",
                "GET /callback?token=[REDACTED]&state=ok",
            ),
            (
                "password = 'correct horse battery staple'",
                "password = '[REDACTED]'",
            ),
            (
                "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturetoken",
                "jwt [REDACTED]",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(redact_sensitive_text(input), expected);
        }
        assert_eq!(
            redact_sensitive_text("GET /accounts/:accountId"),
            "GET /accounts/:accountId"
        );
    }

    #[test]
    fn redacts_sensitive_span_paths_in_json_and_sarif() {
        let mut document = synthetic_document();
        document.diagnostics.push(Diagnostic {
            category: DiagnosticCategory::Parser,
            code: "secret_path".to_string(),
            severity: DiagnosticSeverity::Warning,
            recoverability: Recoverability::Recoverable,
            span: Some(Span {
                file: "src/callback?access_token=super-secret-token/app.py".to_string(),
                line: 7,
                column: 3,
                byte_range: Some(ByteRange {
                    start: 100,
                    end: 120,
                }),
            }),
            message: "diagnostic with sensitive path".to_string(),
        });

        let json = JsonReporter.render(&document).expect("JSON should render");
        let sarif = SarifReporter
            .render(&document)
            .expect("SARIF should render");

        for output in [&json, &sarif] {
            assert!(output.contains("access_token=[REDACTED]"));
            assert!(!output.contains("super-secret-token"));
            assert!(output.contains("src/callback"));
            assert!(output.contains("app.py"));
            assert!(output.contains("7"));
        }
    }

    #[test]
    fn redacts_markdown_json_sarif_and_explain_outputs() {
        let mut document = document_with_sarif_coverage_data();
        let route = document
            .routes
            .iter_mut()
            .find(|route| route.id == "route.authn_only")
            .expect("authn-only route should exist");
        route.path = "/accounts?access_token=super-secret-token".to_string();
        route.notes = vec!["Authorization: Bearer abcdefghijklmnopqrstuvwxyz".to_string()];
        route.handler = Some(SymbolRef {
            name: "handlerWithApiKey".to_string(),
            span: Some(Span {
                file: "src/authn.py".to_string(),
                line: 20,
                column: 5,
                byte_range: None,
            }),
        });
        document.evidence.push(Evidence {
            id: "evidence.secret".to_string(),
            route_id: Some("route.authn_only".to_string()),
            evidence_type: EvidenceType::Authn,
            mechanism: "api_key=sk-abcdefghijklmnopqrstuvwxyz".to_string(),
            symbol: None,
            span: Some(Span {
                file: "src/authn.py".to_string(),
                line: 21,
                column: 9,
                byte_range: None,
            }),
            confidence: Confidence::High,
            notes: vec!["password = 'correct horse battery staple'".to_string()],
            extensions: ExtensionMap::new(),
        });
        document.diagnostics.push(Diagnostic {
            category: DiagnosticCategory::Parser,
            code: "secret_diagnostic".to_string(),
            severity: DiagnosticSeverity::Warning,
            recoverability: Recoverability::Recoverable,
            span: Some(Span {
                file: "src/authn.py".to_string(),
                line: 22,
                column: 1,
                byte_range: None,
            }),
            message: "DATABASE_URL=postgres://alice:swordfish@db.internal/app".to_string(),
        });

        let markdown = MarkdownReporter
            .render(&document)
            .expect("markdown should render");
        let json = JsonReporter.render(&document).expect("json should render");
        let sarif = SarifReporter
            .render(&document)
            .expect("sarif should render");
        let explain = render_explain(&document, "route.authn_only").expect("route should explain");

        for output in [&markdown, &json, &sarif, &explain] {
            assert!(
                output.contains("REDACTED"),
                "output should show redaction: {output}"
            );
            assert!(!output.contains("super-secret-token"));
            assert!(!output.contains("abcdefghijklmnopqrstuvwxyz"));
            assert!(!output.contains("swordfish"));
            assert!(!output.contains("correct horse battery staple"));
            assert!(output.contains("route.authn_only"));
            assert!(output.contains("src/authn.py"));
        }

        let json_value: Value = serde_json::from_str(&json).expect("redacted JSON should parse");
        let routes = json_value["routes"]
            .as_array()
            .expect("routes should remain an array");
        assert!(routes.iter().any(|route| route["id"] == "route.authn_only"));
    }

    #[test]
    fn redacts_drift_and_rule_suggestion_json_and_markdown() {
        let mut drift = DriftReport {
            schema_version: "authmap.diff/0.1.0".to_string(),
            report_type: "authmap.diff".to_string(),
            metadata: authmap_analysis::DriftMetadata {
                mode: ScanMode::Advisory,
                base: authmap_analysis::DriftInputMetadata {
                    label: "base".to_string(),
                    schema_version: SCHEMA_VERSION.to_string(),
                    target_roots: vec!["src".to_string()],
                },
                head: authmap_analysis::DriftInputMetadata {
                    label: "head".to_string(),
                    schema_version: SCHEMA_VERSION.to_string(),
                    target_roots: vec!["src".to_string()],
                },
                config: authmap_analysis::DriftConfigMetadata::none(),
                fail_on: Vec::new(),
            },
            summary: authmap_analysis::DriftSummary {
                total_changes: 1,
                ..authmap_analysis::DriftSummary::default()
            },
            changes: vec![DriftChange {
                id: "change_0001".to_string(),
                kind: DriftChangeKind::AddedRoute,
                severity: DriftChangeSeverity::Warning,
                route_key: "GET /callback?token=abcdef1234567890".to_string(),
                base_route_id: None,
                head_route_id: Some("route_0001".to_string()),
                message: "Added route GET /callback?token=abcdef1234567890".to_string(),
                direction: None,
                before: json!(null),
                after: json!({ "path": "/callback?token=abcdef1234567890" }),
                evidence_ids: Vec::new(),
                weak_evidence_ids: Vec::new(),
                mutation_ids: Vec::new(),
                link_ids: Vec::new(),
                sensitivity_reasons: Vec::new(),
                reviewer_questions: vec![
                    "Should password = 'correct horse battery staple' be stored?".to_string(),
                ],
                fail_category: None,
                enforcement_blocking: false,
            }],
            diagnostics: Vec::new(),
        };
        let mut suggestions = rule_suggestion_report();
        suggestions.suggestions[0].mechanism = "api_key=sk-abcdefghijklmnopqrstuvwxyz".to_string();
        suggestions.suggestions[0].rationale =
            vec!["Authorization: Bearer abcdefghijklmnopqrstuvwxyz".to_string()];

        let outputs = [
            render_drift_markdown(&drift),
            render_drift_json(&drift).expect("drift JSON should render"),
            render_rule_suggestions_markdown(&suggestions),
            render_rule_suggestions_json(&suggestions).expect("rule suggestion JSON should render"),
        ];

        for output in outputs {
            assert!(output.contains("REDACTED"));
            assert!(!output.contains("abcdef1234567890"));
            assert!(!output.contains("abcdefghijklmnopqrstuvwxyz"));
            assert!(!output.contains("correct horse battery staple"));
        }

        drift.changes[0].route_key = "GET /accounts/:accountId".to_string();
        assert!(render_drift_markdown(&drift).contains("/accounts/:accountId"));
    }

    #[test]
    fn explain_route_includes_classification_support_and_context() {
        let document = synthetic_document();
        let rendered = render_explain(&document, "route_0001").expect("route should explain");

        assert!(rendered.contains("# AuthMap Explain"));
        assert!(rendered.contains("- Kind: route"));
        assert!(rendered.contains("- Route: POST /admin|users"));
        assert!(rendered.contains("- Coverage: unknown_or_dynamic (review_required)"));
        assert!(rendered.contains("- Coverage rationale: dynamic policy branch"));
        assert!(rendered.contains("evidence_0001: admin_check `requires_admin`"));
        assert!(rendered.contains("mutation_0001: update `user.disabled` via `sqlalchemy`"));
        assert!(rendered.contains("link_0001: route=route_0001"));
        assert!(rendered.contains("Should this require a tenant check?"));
        assert!(rendered.contains("warning dynamic_policy"));
        assert!(rendered.contains("not confirmed vulnerabilities"));
    }

    #[test]
    fn explain_evidence_mutation_and_link_resolve_route_context() {
        let document = synthetic_document();

        let evidence = render_explain(&document, "evidence_0001").expect("evidence should explain");
        assert!(evidence.contains("## Selected Evidence"));
        assert!(evidence.contains("- Kind: evidence"));
        assert!(evidence.contains("Route ID: route_0001"));
        assert!(evidence.contains("## Route Context"));

        let mutation = render_explain(&document, "mutation_0001").expect("mutation should explain");
        assert!(mutation.contains("## Selected Mutation"));
        assert!(mutation.contains("- Kind: mutation"));
        assert!(mutation.contains("mutation_0001: update `user.disabled` via `sqlalchemy`"));
        assert!(mutation.contains("- Route ID: route_0001"));

        let link = render_explain(&document, "link_0001").expect("link should explain");
        assert!(link.contains("## Selected Link"));
        assert!(link.contains("- Kind: link"));
        assert!(
            link.contains(
                "link_0001: route=route_0001 evidence=evidence_0001 mutation=mutation_0001"
            )
        );
        assert!(link.contains("- Route: POST /admin|users"));
    }

    #[test]
    fn explain_errors_for_unknown_ambiguous_and_unsupported_ids() {
        let document = synthetic_document();
        let error = render_explain(&document, "missing").expect_err("unknown IDs should fail");
        assert!(matches!(error, ExplainError::UnknownId(id) if id == "missing"));

        let mut ambiguous = synthetic_document();
        ambiguous.evidence.push(Evidence {
            id: "route_0001".to_string(),
            route_id: Some("route_0001".to_string()),
            evidence_type: EvidenceType::Authn,
            mechanism: "session".to_string(),
            symbol: None,
            span: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: ExtensionMap::new(),
        });
        let error =
            render_explain(&ambiguous, "route_0001").expect_err("ambiguous IDs should fail");
        assert!(
            matches!(error, ExplainError::AmbiguousId { matches, .. } if matches == "route, evidence")
        );

        let mut unsupported = synthetic_document();
        unsupported.schema_version = "99.0.0".to_string();
        let error = render_explain(&unsupported, "route_0001")
            .expect_err("unsupported schemas should fail");
        assert!(matches!(
            error,
            ExplainError::UnsupportedSchemaVersion {
                actual,
                expected: SCHEMA_VERSION
            } if actual == "99.0.0"
        ));
    }

    #[test]
    fn explain_output_is_deterministic() {
        let document = synthetic_document();

        let first = render_explain(&document, "route_0001").expect("route should explain");
        let second = render_explain(&document, "route_0001").expect("route should explain");

        assert_eq!(first, second);
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

        assert!(summary_index < review_index);
        assert!(review_index < diagnostics_index);
        assert!(diagnostics_index < skipped_index);
        assert!(markdown.contains("parser.source_parse_recovered"));
        assert!(markdown.contains("discovery.file_too_large"));
        assert!(markdown.contains("discovery.file_limit_reached"));
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
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("SARIF rules should be an array");
        assert!(
            rules
                .iter()
                .any(|rule| rule["id"] == diagnostic_codes::PARSER_SOURCE_PARSE_RECOVERED)
        );
        let results = sarif["runs"][0]["results"]
            .as_array()
            .expect("SARIF results should be an array");
        let diagnostic = results
            .iter()
            .find(|result| result["ruleId"] == diagnostic_codes::PARSER_SOURCE_PARSE_RECOVERED)
            .expect("diagnostic result should be present");
        assert_eq!(
            diagnostic["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/app.py"
        );
    }

    #[test]
    fn sarif_maps_coverage_alerts_to_advisory_rules_and_locations() {
        let sarif: Value = serde_json::from_str(
            &SarifReporter
                .render(&document_with_sarif_coverage_data())
                .expect("SARIF should render"),
        )
        .expect("SARIF should be JSON");

        assert_valid_sarif(&sarif);

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("SARIF rules should be an array");
        for rule_id in [
            SARIF_UNAUTHENTICATED_SENSITIVE,
            SARIF_AUTHN_ONLY_SENSITIVE,
            SARIF_UNKNOWN_DYNAMIC,
            SARIF_MISSING_EXPLICIT_EVIDENCE,
        ] {
            let rule = rules
                .iter()
                .find(|rule| rule["id"] == rule_id)
                .unwrap_or_else(|| panic!("missing SARIF rule {rule_id}"));
            assert_eq!(rule["defaultConfiguration"]["level"], "warning");
            assert!(
                rule["help"]["text"]
                    .as_str()
                    .expect("help text should be present")
                    .contains("advisory")
            );
        }

        let results = sarif["runs"][0]["results"]
            .as_array()
            .expect("SARIF results should be an array");
        assert_eq!(results.len(), 5);
        for rule_id in [
            SARIF_UNAUTHENTICATED_SENSITIVE,
            SARIF_AUTHN_ONLY_SENSITIVE,
            SARIF_UNKNOWN_DYNAMIC,
            SARIF_MISSING_EXPLICIT_EVIDENCE,
        ] {
            let result = results
                .iter()
                .find(|result| result["ruleId"] == rule_id)
                .unwrap_or_else(|| panic!("missing SARIF result {rule_id}"));
            assert_eq!(result["level"], "warning");
            assert_eq!(result["properties"]["authmap.kind"], "coverage");
        }

        let authn_only = results
            .iter()
            .find(|result| result["ruleId"] == SARIF_AUTHN_ONLY_SENSITIVE)
            .expect("authn-only result should exist");
        assert_eq!(authn_only["properties"]["route_id"], "route.authn_only");
        assert_eq!(authn_only["properties"]["coverage_class"], "authn_only");
        assert_eq!(authn_only["properties"]["risk"], "review_required");
        assert_eq!(
            authn_only["properties"]["evidence_ids"],
            json!(["evidence.authn"])
        );
        assert_eq!(
            authn_only["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/authn.py"
        );
        assert_eq!(
            authn_only["locations"][0]["physicalLocation"]["region"]["startLine"],
            20
        );

        let unknown_dynamic = results
            .iter()
            .find(|result| result["ruleId"] == SARIF_UNKNOWN_DYNAMIC)
            .expect("unknown dynamic result should exist");
        assert_eq!(
            unknown_dynamic["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/dynamic.py"
        );
        assert_eq!(
            unknown_dynamic["properties"]["weak_evidence_ids"],
            json!(["evidence.dynamic"])
        );

        let missing_explicit = results
            .iter()
            .find(|result| result["ruleId"] == SARIF_MISSING_EXPLICIT_EVIDENCE)
            .expect("missing explicit evidence result should exist");
        assert_eq!(
            missing_explicit["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/service.py"
        );
        assert_eq!(
            missing_explicit["properties"]["mutation_ids"],
            json!(["mutation.account_delete"])
        );

        assert!(
            results
                .iter()
                .any(|result| result["ruleId"] == diagnostic_codes::PARSER_SOURCE_PARSE_RECOVERED)
        );
    }

    #[test]
    fn sarif_coverage_fingerprints_ignore_route_id_and_order() {
        let original: Value = serde_json::from_str(
            &SarifReporter
                .render(&document_with_sarif_coverage_data())
                .expect("SARIF should render"),
        )
        .expect("SARIF should be JSON");

        let mut reordered = document_with_sarif_coverage_data();
        reordered.routes.reverse();
        let route = reordered
            .routes
            .iter_mut()
            .find(|route| route.id == "route.authn_only")
            .expect("authn-only route should exist");
        route.id = "route.reordered_authn_only".to_string();
        for coverage in &mut reordered.coverage {
            if coverage.route_id == "route.authn_only" {
                coverage.route_id = "route.reordered_authn_only".to_string();
            }
        }
        for evidence in &mut reordered.evidence {
            if evidence.route_id.as_deref() == Some("route.authn_only") {
                evidence.route_id = Some("route.reordered_authn_only".to_string());
            }
        }

        let changed: Value = serde_json::from_str(
            &SarifReporter
                .render(&reordered)
                .expect("SARIF should render"),
        )
        .expect("SARIF should be JSON");
        let original_result = sarif_result(&original, SARIF_AUTHN_ONLY_SENSITIVE);
        let changed_result = sarif_result(&changed, SARIF_AUTHN_ONLY_SENSITIVE);

        assert_eq!(
            original_result["partialFingerprints"]["authmapStable"],
            changed_result["partialFingerprints"]["authmapStable"]
        );
        assert_ne!(
            original_result["properties"]["route_id"],
            changed_result["properties"]["route_id"]
        );
    }

    fn sarif_result<'a>(sarif: &'a Value, rule_id: &str) -> &'a Value {
        sarif["runs"][0]["results"]
            .as_array()
            .expect("SARIF results should be an array")
            .iter()
            .find(|result| result["ruleId"] == rule_id)
            .unwrap_or_else(|| panic!("missing SARIF result {rule_id}"))
    }

    fn assert_valid_sarif(sarif: &Value) {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../tests/schemas/sarif-2.1.0.schema.json"
        ))
        .expect("SARIF schema should parse");
        let validator = jsonschema::validator_for(&schema).expect("SARIF schema should compile");
        if let Err(error) = validator.validate(sarif) {
            panic!("SARIF should validate against the vendored SARIF schema: {error}");
        }
    }

    #[test]
    fn markdown_escapes_untrusted_report_fields() {
        let mut document = document_with_review_data();
        document.source_files[0].path = "src/evil`\n## forged.md".to_string();
        document.source_files[0]
            .skipped
            .as_mut()
            .expect("file should be skipped")
            .message = "<script>alert(1)</script>\n```".to_string();
        document.diagnostics[0].message = "[click](javascript:alert(1))\n# forged".to_string();
        document.coverage[0].rationale = vec!["**bold**\n## forged".to_string()];

        let markdown = MarkdownReporter
            .render(&document)
            .expect("markdown should render");

        assert!(!markdown.contains("\n## forged.md"));
        assert!(!markdown.contains("<script>"));
        assert!(!markdown.contains("```"));
        assert!(!markdown.contains("[click](javascript:alert(1))"));
        assert!(!markdown.contains("\n# forged"));
        assert!(markdown.contains("&lt;script&gt;alert"));
        assert!(markdown.contains("\\[click\\]"));
    }

    #[test]
    fn write_atomic_refuses_preexisting_temp_path() {
        let dir = std::env::temp_dir().join(format!(
            "authmap-report-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let output = dir.join("authmap.md");
        let temp = temp_path_for(&output);
        fs::write(&temp, "stale temp").expect("stale temp should be written");

        let error = write_atomic(&output, "new report").expect_err("temp path should be refused");

        assert!(matches!(error, ReportError::Write { .. }));
        assert!(!output.exists());
        let _ = fs::remove_dir_all(dir);
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
        document.source_files.push(SourceFile {
            path: "src/omitted_sample.py".to_string(),
            language: authmap_core::Language::Python,
            size_bytes: 100,
            sha256: None,
            project_hints: Vec::new(),
            skipped: Some(SkipReason {
                code: diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED.to_string(),
                message: "file was omitted because configured max_files is 1".to_string(),
            }),
        });
        document.routes.push(Route {
            id: "route.accounts.delete".to_string(),
            framework: Framework::Express,
            method: "DELETE".to_string(),
            path: "/accounts/:id".to_string(),
            name: None,
            tags: Vec::new(),
            middleware: Vec::new(),
            handler: Some(SymbolRef {
                name: "deleteAccount".to_string(),
                span: Some(Span {
                    file: "src/app.py".to_string(),
                    line: 2,
                    column: 1,
                    byte_range: None,
                }),
            }),
            span: Some(Span {
                file: "src/app.py".to_string(),
                line: 1,
                column: 1,
                byte_range: None,
            }),
            source_evidence: Vec::new(),
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: ExtensionMap::new(),
        });
        document.coverage.push(Coverage {
            route_id: "route.accounts.delete".to_string(),
            class: CoverageClass::UnknownOrDynamic,
            risk: RiskLevel::ReviewRequired,
            rationale: vec!["authorization evidence was incomplete".to_string()],
            reviewer_questions: vec!["Should this route require ownership?".to_string()],
            uncertainty_reasons: vec!["dynamic dispatch was detected".to_string()],
            extensions: ExtensionMap::new(),
        });
        document.diagnostics.push(diagnostic());
        document
    }

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

    fn document_with_sarif_coverage_data() -> AuthMapDocument {
        let mut document = AuthMapDocument::empty(ScanMetadata {
            target_roots: vec!["src".to_string()],
            ..ScanMetadata::default()
        });
        document.routes = vec![
            route(
                "route.unauthenticated",
                "DELETE",
                "/accounts/:id",
                Some(symbol("delete_account", "src/unauthenticated.py", 10, 5)),
                Some(span("src/unauthenticated.py", 9, 1)),
            ),
            route(
                "route.authn_only",
                "POST",
                "/accounts",
                Some(symbol("create_account", "src/authn.py", 20, 5)),
                Some(span("src/authn.py", 19, 1)),
            ),
            route("route.dynamic", "PATCH", "/accounts/:id", None, None),
            route(
                "route.missing_explicit",
                "POST",
                "/admin/accounts/:id/delete",
                None,
                None,
            ),
        ];
        document.evidence = vec![
            evidence(
                "evidence.authn",
                "route.authn_only",
                EvidenceType::Authn,
                Confidence::High,
                Some(span("src/authn.py", 18, 9)),
            ),
            evidence(
                "evidence.dynamic",
                "route.dynamic",
                EvidenceType::UnknownDynamicCheck,
                Confidence::Low,
                Some(span("src/dynamic.py", 30, 12)),
            ),
            evidence(
                "evidence.admin",
                "route.missing_explicit",
                EvidenceType::AdminCheck,
                Confidence::High,
                None,
            ),
        ];
        document.mutations = vec![Mutation {
            id: "mutation.account_delete".to_string(),
            operation: MutationOperation::Delete,
            library: Some("sqlalchemy".to_string()),
            resource: Some("accounts".to_string()),
            span: Some(span("src/service.py", 44, 7)),
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: ExtensionMap::new(),
        }];
        document.links = vec![ReachabilityLink {
            id: "link.account_delete".to_string(),
            route_id: "route.missing_explicit".to_string(),
            mutation_id: Some("mutation.account_delete".to_string()),
            evidence_id: Some("evidence.admin".to_string()),
            confidence: Confidence::Medium,
            notes: Vec::new(),
            extensions: ExtensionMap::new(),
        }];
        document.coverage = vec![
            coverage(
                "route.unauthenticated",
                CoverageClass::Unauthenticated,
                RiskLevel::High,
                json!({
                    "evidence_ids": [],
                    "weak_evidence_ids": [],
                    "mutation_ids": [],
                    "link_ids": [],
                    "sensitivity_reasons": ["unsafe_method"]
                }),
            ),
            coverage(
                "route.authn_only",
                CoverageClass::AuthnOnly,
                RiskLevel::ReviewRequired,
                json!({
                    "evidence_ids": ["evidence.authn"],
                    "weak_evidence_ids": [],
                    "mutation_ids": [],
                    "link_ids": [],
                    "sensitivity_reasons": ["account_path", "unsafe_method"]
                }),
            ),
            coverage(
                "route.dynamic",
                CoverageClass::UnknownOrDynamic,
                RiskLevel::ReviewRequired,
                json!({
                    "evidence_ids": ["evidence.dynamic"],
                    "weak_evidence_ids": ["evidence.dynamic"],
                    "mutation_ids": [],
                    "link_ids": [],
                    "sensitivity_reasons": ["account_path", "path_param", "unsafe_method"]
                }),
            ),
            coverage(
                "route.missing_explicit",
                CoverageClass::AdminGuarded,
                RiskLevel::ReviewRequired,
                json!({
                    "evidence_ids": ["evidence.admin"],
                    "weak_evidence_ids": [],
                    "mutation_ids": ["mutation.account_delete"],
                    "link_ids": ["link.account_delete"],
                    "sensitivity_reasons": ["admin_path", "linked_mutation", "unsafe_method"]
                }),
            ),
        ];
        document.diagnostics.push(diagnostic());
        document
    }

    fn span(file: &str, line: u32, column: u32) -> Span {
        Span {
            file: file.to_string(),
            line,
            column,
            byte_range: None,
        }
    }

    fn symbol(name: &str, file: &str, line: u32, column: u32) -> SymbolRef {
        SymbolRef {
            name: name.to_string(),
            span: Some(span(file, line, column)),
        }
    }

    fn route(
        id: &str,
        method: &str,
        path: &str,
        handler: Option<SymbolRef>,
        span: Option<Span>,
    ) -> Route {
        Route {
            id: id.to_string(),
            framework: Framework::FastApi,
            method: method.to_string(),
            path: path.to_string(),
            name: None,
            tags: Vec::new(),
            middleware: Vec::new(),
            handler,
            span,
            source_evidence: Vec::new(),
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: ExtensionMap::new(),
        }
    }

    fn evidence(
        id: &str,
        route_id: &str,
        evidence_type: EvidenceType,
        confidence: Confidence,
        span: Option<Span>,
    ) -> Evidence {
        Evidence {
            id: id.to_string(),
            route_id: Some(route_id.to_string()),
            evidence_type,
            mechanism: evidence_type_label(evidence_type).to_string(),
            symbol: None,
            span,
            confidence,
            notes: Vec::new(),
            extensions: ExtensionMap::new(),
        }
    }

    fn coverage(route_id: &str, class: CoverageClass, risk: RiskLevel, support: Value) -> Coverage {
        let mut extensions = ExtensionMap::new();
        extensions.insert("authmap.coverage".to_string(), support);
        Coverage {
            route_id: route_id.to_string(),
            class,
            risk,
            rationale: vec!["synthetic SARIF coverage rationale".to_string()],
            reviewer_questions: vec!["Should this route have explicit authorization?".to_string()],
            uncertainty_reasons: Vec::new(),
            extensions,
        }
    }

    fn rule_suggestion_report() -> RuleSuggestionReport {
        RuleSuggestionReport {
            target_roots: vec!["src".to_string()],
            source_files_scanned: 1,
            suggestions: vec![RuleSuggestion {
                name: "Suggested permission_check: ensurePaidPlan".to_string(),
                evidence_type: EvidenceType::PermissionCheck,
                mechanism: "suggested_permission_guard".to_string(),
                confidence: Confidence::Medium,
                matcher: RuleSuggestionMatch {
                    exact: vec!["ensurePaidPlan".to_string()],
                    contains: Vec::new(),
                },
                rationale: vec![
                    "name suggests a permission, entitlement, or access guard".to_string(),
                ],
                examples: vec![RuleSuggestionExample {
                    symbol: "ensurePaidPlan".to_string(),
                    file: "src/app.js".to_string(),
                    line: 4,
                    column: 10,
                    context: "Express middleware".to_string(),
                }],
            }],
            diagnostics: Vec::new(),
        }
    }

    fn synthetic_document() -> AuthMapDocument {
        let span = Span {
            file: "app/routes.py".to_string(),
            line: 42,
            column: 7,
            byte_range: None,
        };
        AuthMapDocument {
            schema_version: "0.1.0".to_string(),
            metadata: ScanMetadata::default(),
            source_files: vec![SourceFile {
                path: "large.py".to_string(),
                language: authmap_core::Language::Python,
                size_bytes: 10,
                sha256: None,
                project_hints: Vec::new(),
                skipped: Some(authmap_core::SkipReason {
                    code: "file_too_large".to_string(),
                    message: "too large".to_string(),
                }),
            }],
            routes: vec![Route {
                id: "route_0001".to_string(),
                framework: Framework::FastApi,
                method: "POST".to_string(),
                path: "/admin|users".to_string(),
                name: None,
                tags: Vec::new(),
                middleware: vec![SymbolRef {
                    name: "requires_admin".to_string(),
                    span: Some(span.clone()),
                }],
                handler: Some(SymbolRef {
                    name: "disable_user".to_string(),
                    span: Some(span.clone()),
                }),
                span: Some(span.clone()),
                source_evidence: Vec::new(),
                confidence: Confidence::Medium,
                notes: vec!["dynamic policy branch".to_string()],
                extensions: ExtensionMap::new(),
            }],
            evidence: vec![Evidence {
                id: "evidence_0001".to_string(),
                route_id: Some("route_0001".to_string()),
                evidence_type: EvidenceType::AdminCheck,
                mechanism: "requires_admin".to_string(),
                symbol: None,
                span: Some(span.clone()),
                confidence: Confidence::High,
                notes: Vec::new(),
                extensions: ExtensionMap::new(),
            }],
            mutations: vec![Mutation {
                id: "mutation_0001".to_string(),
                operation: MutationOperation::Update,
                library: Some("sqlalchemy".to_string()),
                resource: Some("user.disabled".to_string()),
                span: Some(span.clone()),
                confidence: Confidence::Medium,
                notes: Vec::new(),
                extensions: ExtensionMap::new(),
            }],
            links: vec![ReachabilityLink {
                id: "link_0001".to_string(),
                route_id: "route_0001".to_string(),
                mutation_id: Some("mutation_0001".to_string()),
                evidence_id: Some("evidence_0001".to_string()),
                confidence: Confidence::Medium,
                notes: Vec::new(),
                extensions: ExtensionMap::new(),
            }],
            coverage: vec![Coverage {
                route_id: "route_0001".to_string(),
                class: CoverageClass::UnknownOrDynamic,
                risk: RiskLevel::ReviewRequired,
                rationale: vec!["dynamic policy branch".to_string()],
                reviewer_questions: vec!["Should this require a tenant check?".to_string()],
                uncertainty_reasons: Vec::new(),
                extensions: ExtensionMap::new(),
            }],
            diagnostics: vec![Diagnostic {
                category: DiagnosticCategory::Policy,
                code: "dynamic_policy".to_string(),
                severity: DiagnosticSeverity::Warning,
                recoverability: Recoverability::Recoverable,
                span: Some(span),
                message: "dynamic policy branch".to_string(),
            }],
            extensions: ExtensionMap::new(),
        }
    }
}
