use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use authmap_core::{
    AuthMapDocument, Confidence, Coverage, CoverageClass, Diagnostic, DiagnosticSeverity, Evidence,
    EvidenceType, Framework, Mutation, MutationOperation, RiskLevel, ScanMode, SourceFile, Span,
    SymbolRef,
};
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
    render_route_details(&mut output, document, &index);
    render_diagnostics(&mut output, document);
    render_skipped_files(&mut output, document);
    output
}

struct ReportIndex<'a> {
    coverage_by_route: BTreeMap<&'a str, &'a Coverage>,
    evidence_by_route: BTreeMap<&'a str, Vec<&'a Evidence>>,
    mutations_by_route: BTreeMap<&'a str, Vec<&'a Mutation>>,
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
        for link in &document.links {
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

        Self {
            coverage_by_route,
            evidence_by_route,
            mutations_by_route,
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
    escape_inline(input)
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

fn escape_inline(input: &str) -> String {
    input
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

pub fn redact_sensitive_text(input: &str) -> String {
    input.replace("Authorization:", "Authorization: [REDACTED]")
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
        AuthMapDocument, Confidence, Coverage, CoverageClass, Diagnostic, DiagnosticCategory,
        DiagnosticSeverity, Evidence, EvidenceType, ExtensionMap, Framework, Mutation,
        MutationOperation, ReachabilityLink, Recoverability, RiskLevel, Route, ScanMetadata,
        SkipReason, SourceFile, Span, SymbolRef, diagnostic_codes,
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
