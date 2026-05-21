use std::collections::{BTreeMap, BTreeSet};

use authmap_config::DriftFailCategory;
use authmap_core::{
    AuthMapDocument, Coverage, CoverageClass, Diagnostic, Evidence, Framework, Mutation,
    PolicyCase, ReachabilityLink, RiskLevel, SCHEMA_VERSION, ScanMode, Span,
};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriftReport {
    pub schema_version: String,
    pub report_type: String,
    pub metadata: DriftMetadata,
    pub summary: DriftSummary,
    pub changes: Vec<DriftChange>,
    pub diagnostics: Vec<authmap_core::Diagnostic>,
}

impl DriftReport {
    pub fn has_enforce_blocking_changes(&self) -> bool {
        self.metadata.mode == ScanMode::Enforce
            && self
                .changes
                .iter()
                .any(|change| change.enforcement_blocking)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriftMetadata {
    pub mode: ScanMode,
    pub base: DriftInputMetadata,
    pub head: DriftInputMetadata,
    pub config: DriftConfigMetadata,
    pub fail_on: Vec<DriftFailCategory>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriftInputMetadata {
    pub label: String,
    pub schema_version: String,
    pub target_roots: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriftConfigMetadata {
    pub source: String,
    pub path: Option<String>,
}

impl DriftConfigMetadata {
    pub fn none() -> Self {
        Self {
            source: "none".to_string(),
            path: None,
        }
    }

    pub fn per_ref(path: impl Into<String>) -> Self {
        Self {
            source: "per_ref".to_string(),
            path: Some(path.into()),
        }
    }

    pub fn external(path: impl Into<String>) -> Self {
        Self {
            source: "external".to_string(),
            path: Some(path.into()),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DriftSummary {
    pub total_changes: usize,
    pub added_routes: usize,
    pub removed_routes: usize,
    pub handler_changes: usize,
    pub evidence_changes: usize,
    pub removed_evidence: usize,
    pub coverage_changes: usize,
    pub new_linked_mutations: usize,
    pub policy_changes: usize,
    pub blocking_changes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriftChange {
    pub id: String,
    pub kind: DriftChangeKind,
    pub severity: DriftChangeSeverity,
    pub route_key: String,
    pub base_route_id: Option<String>,
    pub head_route_id: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<DriftComparison>,
    pub before: Value,
    pub after: Value,
    pub evidence_ids: Vec<String>,
    pub weak_evidence_ids: Vec<String>,
    pub mutation_ids: Vec<String>,
    pub link_ids: Vec<String>,
    pub sensitivity_reasons: Vec<String>,
    pub reviewer_questions: Vec<String>,
    pub fail_category: Option<DriftFailCategory>,
    pub enforcement_blocking: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftChangeKind {
    AddedRoute,
    RemovedRoute,
    HandlerChanged,
    EvidenceChanged,
    RemovedEvidence,
    CoverageChanged,
    NewLinkedMutation,
    PolicyChanged,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftChangeSeverity {
    Note,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftComparison {
    Upgrade,
    Downgrade,
    Changed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlReport {
    pub schema_version: String,
    pub report_type: String,
    pub metadata: DriftMetadata,
    pub summary: ControlSummary,
    pub findings: Vec<ControlFinding>,
    pub diagnostics: Vec<authmap_core::Diagnostic>,
}

impl ControlReport {
    pub fn has_enforce_blocking_findings(&self) -> bool {
        self.metadata.mode == ScanMode::Enforce
            && self
                .findings
                .iter()
                .any(|finding| finding.enforcement_blocking)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ControlSummary {
    pub total_findings: usize,
    pub guard_changes: usize,
    pub route_guard_changes: usize,
    pub permission_changes: usize,
    pub tenant_changes: usize,
    pub ownership_changes: usize,
    pub admin_changes: usize,
    pub audit_changes: usize,
    pub policy_changes: usize,
    pub auth_relevant_header_changes: usize,
    pub review_required: usize,
    pub blocking_findings: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlFinding {
    pub id: String,
    pub control_type: ControlDriftKind,
    pub source_change_id: String,
    pub source_change_kind: DriftChangeKind,
    pub severity: DriftChangeSeverity,
    pub route_key: String,
    pub base_route_id: Option<String>,
    pub head_route_id: Option<String>,
    pub message: String,
    pub confidence: authmap_core::Confidence,
    pub location: Option<Span>,
    pub evidence_ids: Vec<String>,
    pub weak_evidence_ids: Vec<String>,
    pub mutation_ids: Vec<String>,
    pub link_ids: Vec<String>,
    pub reviewer_questions: Vec<String>,
    pub fail_category: Option<DriftFailCategory>,
    pub enforcement_blocking: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDriftKind {
    Guard,
    RouteGuard,
    PermissionMap,
    TenantHelper,
    OwnershipHelper,
    AdminGate,
    AuditControl,
    PolicyHelper,
    AuthRelevantHeader,
}

pub fn analyze_drift(
    base: &AuthMapDocument,
    head: &AuthMapDocument,
    mode: ScanMode,
    fail_on: &[DriftFailCategory],
    base_label: impl Into<String>,
    head_label: impl Into<String>,
) -> DriftReport {
    analyze_drift_with_config(
        base,
        head,
        mode,
        fail_on,
        base_label,
        head_label,
        DriftConfigMetadata::none(),
    )
}

pub fn analyze_drift_with_config(
    base: &AuthMapDocument,
    head: &AuthMapDocument,
    mode: ScanMode,
    fail_on: &[DriftFailCategory],
    base_label: impl Into<String>,
    head_label: impl Into<String>,
    config: DriftConfigMetadata,
) -> DriftReport {
    let fail_on = sorted_fail_categories(fail_on);
    let base_index = DriftIndex::new(base);
    let head_index = DriftIndex::new(head);
    let identities = base_index
        .routes
        .keys()
        .chain(head_index.routes.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut changes = Vec::new();
    for identity in identities.iter() {
        match (
            base_index.routes.get(identity),
            head_index.routes.get(identity),
        ) {
            (None, Some(head_route)) => {
                changes.push(added_route_change(head_route, &head_index, mode, &fail_on));
            }
            (Some(base_route), None) => {
                changes.push(removed_route_change(base_route, &base_index));
            }
            (Some(base_route), Some(head_route)) => {
                compare_route_pair(
                    base_route,
                    head_route,
                    &base_index,
                    &head_index,
                    mode,
                    &fail_on,
                    &mut changes,
                );
            }
            (None, None) => {}
        }
    }

    for (index, change) in changes.iter_mut().enumerate() {
        change.id = format!("drift_{:04}", index + 1);
    }

    let summary = summarize_changes(&changes);

    DriftReport {
        schema_version: SCHEMA_VERSION.to_string(),
        report_type: "authmap.diff".to_string(),
        metadata: DriftMetadata {
            mode,
            base: input_metadata(base, base_label),
            head: input_metadata(head, head_label),
            config,
            fail_on,
        },
        summary,
        changes,
        diagnostics: collect_diagnostics(base, head),
    }
}

pub fn analyze_controls_with_config(
    base: &AuthMapDocument,
    head: &AuthMapDocument,
    mode: ScanMode,
    fail_on: &[DriftFailCategory],
    base_label: impl Into<String>,
    head_label: impl Into<String>,
    config: DriftConfigMetadata,
) -> ControlReport {
    let drift =
        analyze_drift_with_config(base, head, mode, fail_on, base_label, head_label, config);
    let mut findings = drift
        .changes
        .iter()
        .filter_map(control_finding_from_change)
        .collect::<Vec<_>>();
    for (index, finding) in findings.iter_mut().enumerate() {
        finding.id = format!("control_{:04}", index + 1);
    }
    let summary = summarize_control_findings(&findings);
    ControlReport {
        schema_version: drift.schema_version,
        report_type: "authmap.controls".to_string(),
        metadata: drift.metadata,
        summary,
        findings,
        diagnostics: drift.diagnostics,
    }
}

#[derive(Clone, Debug)]
struct DriftIndex<'a> {
    routes: BTreeMap<String, &'a authmap_core::Route>,
    coverage_by_route: BTreeMap<&'a str, &'a Coverage>,
    evidence_by_route: BTreeMap<&'a str, Vec<&'a Evidence>>,
    mutations_by_route: BTreeMap<&'a str, Vec<&'a Mutation>>,
    links_by_route: BTreeMap<&'a str, Vec<&'a ReachabilityLink>>,
    policy_cases_by_route: BTreeMap<&'a str, Vec<&'a PolicyCase>>,
}

impl<'a> DriftIndex<'a> {
    fn new(document: &'a AuthMapDocument) -> Self {
        let mut key_counts = BTreeMap::<String, usize>::new();
        for route in &document.routes {
            *key_counts.entry(stable_route_key(route)).or_default() += 1;
        }

        let mut routes = BTreeMap::new();
        for route in &document.routes {
            let stable = stable_route_key(route);
            let identity = if key_counts.get(&stable).copied().unwrap_or(0) > 1 {
                format!("id:{}", route.id)
            } else {
                stable
            };
            routes.insert(identity, route);
        }

        let coverage_by_route = document
            .coverage
            .iter()
            .map(|coverage| (coverage.route_id.as_str(), coverage))
            .collect::<BTreeMap<_, _>>();
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

        let mut evidence_by_route = BTreeMap::<&str, Vec<&Evidence>>::new();
        for evidence in &document.evidence {
            if let Some(route_id) = &evidence.route_id {
                evidence_by_route
                    .entry(route_id.as_str())
                    .or_default()
                    .push(evidence);
            }
        }

        let mut mutations_by_route = BTreeMap::<&str, Vec<&Mutation>>::new();
        let mut links_by_route = BTreeMap::<&str, Vec<&ReachabilityLink>>::new();
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
            evidence
                .sort_by(|left, right| evidence_signature(left).cmp(&evidence_signature(right)));
            evidence.dedup_by(|left, right| left.id == right.id);
        }
        for mutations in mutations_by_route.values_mut() {
            mutations
                .sort_by(|left, right| mutation_signature(left).cmp(&mutation_signature(right)));
            mutations.dedup_by(|left, right| left.id == right.id);
        }
        for links in links_by_route.values_mut() {
            links.sort_by(|left, right| left.id.cmp(&right.id));
            links.dedup_by(|left, right| left.id == right.id);
        }
        let mut policy_cases_by_route = BTreeMap::<&str, Vec<&PolicyCase>>::new();
        for case in &document.policy_cases {
            policy_cases_by_route
                .entry(case.route_id.as_str())
                .or_default()
                .push(case);
        }
        for cases in policy_cases_by_route.values_mut() {
            cases.sort_by(|left, right| {
                policy_case_signature(left).cmp(&policy_case_signature(right))
            });
        }

        Self {
            routes,
            coverage_by_route,
            evidence_by_route,
            mutations_by_route,
            links_by_route,
            policy_cases_by_route,
        }
    }
}

fn compare_route_pair(
    base_route: &authmap_core::Route,
    head_route: &authmap_core::Route,
    base_index: &DriftIndex<'_>,
    head_index: &DriftIndex<'_>,
    mode: ScanMode,
    fail_on: &[DriftFailCategory],
    changes: &mut Vec<DriftChange>,
) {
    let route_key = stable_route_key(head_route);
    let base_handler = handler_signature(base_route);
    let head_handler = handler_signature(head_route);
    if base_handler != head_handler {
        changes.push(DriftChange {
            id: String::new(),
            kind: DriftChangeKind::HandlerChanged,
            severity: DriftChangeSeverity::Note,
            route_key: route_key.clone(),
            base_route_id: Some(base_route.id.clone()),
            head_route_id: Some(head_route.id.clone()),
            message: format!("Handler changed for {}", route_label(head_route)),
            direction: None,
            before: json!({ "handler": base_handler }),
            after: json!({ "handler": head_handler }),
            evidence_ids: Vec::new(),
            weak_evidence_ids: Vec::new(),
            mutation_ids: Vec::new(),
            link_ids: Vec::new(),
            sensitivity_reasons: sensitivity_reasons(head_route, head_index),
            reviewer_questions: reviewer_questions(head_route, head_index),
            fail_category: None,
            enforcement_blocking: false,
        });
    }

    let base_evidence = evidence_signatures(base_route, base_index);
    let head_evidence = evidence_signatures(head_route, head_index);
    if base_evidence != head_evidence {
        changes.push(DriftChange {
            id: String::new(),
            kind: DriftChangeKind::EvidenceChanged,
            severity: DriftChangeSeverity::Note,
            route_key: route_key.clone(),
            base_route_id: Some(base_route.id.clone()),
            head_route_id: Some(head_route.id.clone()),
            message: format!(
                "Authorization evidence changed for {}",
                route_label(head_route)
            ),
            direction: None,
            before: json!({ "evidence": base_evidence }),
            after: json!({ "evidence": head_evidence }),
            evidence_ids: evidence_ids(head_route, head_index),
            weak_evidence_ids: weak_evidence_ids(head_route, head_index),
            mutation_ids: Vec::new(),
            link_ids: link_ids(head_route, head_index),
            sensitivity_reasons: sensitivity_reasons(head_route, head_index),
            reviewer_questions: reviewer_questions(head_route, head_index),
            fail_category: None,
            enforcement_blocking: false,
        });
    }
    let base_evidence_by_signature = evidence_by_signature(base_route, base_index);
    for (signature, evidence) in &base_evidence_by_signature {
        if head_evidence.contains(signature) || !is_removed_control_evidence(evidence.evidence_type)
        {
            continue;
        }
        let fail_category = Some(DriftFailCategory::RemovedAuthorizationEvidence);
        let blocking = is_blocking(mode, fail_category, fail_on);
        changes.push(DriftChange {
            id: String::new(),
            kind: DriftChangeKind::RemovedEvidence,
            severity: severity_for(blocking, true),
            route_key: route_key.clone(),
            base_route_id: Some(base_route.id.clone()),
            head_route_id: Some(head_route.id.clone()),
            message: format!(
                "Removed {} evidence for {}: {}",
                evidence_type_label(evidence.evidence_type),
                route_label(head_route),
                evidence.mechanism
            ),
            direction: Some(DriftComparison::Downgrade),
            before: evidence_value(evidence),
            after: Value::Null,
            evidence_ids: vec![evidence.id.clone()],
            weak_evidence_ids: weak_evidence_ids(head_route, head_index),
            mutation_ids: mutation_ids(head_route, head_index),
            link_ids: link_ids(head_route, head_index),
            sensitivity_reasons: sensitivity_reasons(head_route, head_index),
            reviewer_questions: reviewer_questions(head_route, head_index),
            fail_category,
            enforcement_blocking: blocking,
        });
    }

    if let (Some(base_coverage), Some(head_coverage)) = (
        base_index.coverage_by_route.get(base_route.id.as_str()),
        head_index.coverage_by_route.get(head_route.id.as_str()),
    ) && (base_coverage.class != head_coverage.class || base_coverage.risk != head_coverage.risk)
    {
        let comparison = compare_coverage(base_coverage, head_coverage);
        let fail_category =
            (comparison == DriftComparison::Downgrade).then_some(DriftFailCategory::AuthDowngrade);
        let blocking = is_blocking(mode, fail_category, fail_on);
        changes.push(DriftChange {
            id: String::new(),
            kind: DriftChangeKind::CoverageChanged,
            severity: severity_for(blocking, comparison == DriftComparison::Downgrade),
            route_key: route_key.clone(),
            base_route_id: Some(base_route.id.clone()),
            head_route_id: Some(head_route.id.clone()),
            message: format!(
                "Coverage changed for {} from {} ({}) to {} ({})",
                route_label(head_route),
                coverage_class_label(base_coverage.class),
                risk_label(base_coverage.risk),
                coverage_class_label(head_coverage.class),
                risk_label(head_coverage.risk)
            ),
            direction: Some(comparison),
            before: coverage_value(base_coverage),
            after: coverage_value(head_coverage),
            evidence_ids: evidence_ids(head_route, head_index),
            weak_evidence_ids: weak_evidence_ids(head_route, head_index),
            mutation_ids: mutation_ids(head_route, head_index),
            link_ids: link_ids(head_route, head_index),
            sensitivity_reasons: sensitivity_reasons(head_route, head_index),
            reviewer_questions: reviewer_questions(head_route, head_index),
            fail_category,
            enforcement_blocking: blocking,
        });
    }

    let base_mutations = mutation_signatures(base_route, base_index);
    let head_mutations = mutation_signatures(head_route, head_index);
    for mutation in head_mutations.difference(&base_mutations) {
        let fail_category = Some(DriftFailCategory::NewLinkedMutation);
        let blocking = is_blocking(mode, fail_category, fail_on);
        changes.push(DriftChange {
            id: String::new(),
            kind: DriftChangeKind::NewLinkedMutation,
            severity: severity_for(blocking, true),
            route_key: route_key.clone(),
            base_route_id: Some(base_route.id.clone()),
            head_route_id: Some(head_route.id.clone()),
            message: format!(
                "New linked mutation for {}: {mutation}",
                route_label(head_route)
            ),
            direction: None,
            before: json!({ "linked_mutation": null }),
            after: json!({ "linked_mutation": mutation }),
            evidence_ids: evidence_ids(head_route, head_index),
            weak_evidence_ids: weak_evidence_ids(head_route, head_index),
            mutation_ids: mutation_ids(head_route, head_index),
            link_ids: link_ids(head_route, head_index),
            sensitivity_reasons: sensitivity_reasons(head_route, head_index),
            reviewer_questions: reviewer_questions(head_route, head_index),
            fail_category,
            enforcement_blocking: blocking,
        });
    }

    let base_policy = policy_signatures(base_route, base_index);
    let head_policy = policy_signatures(head_route, head_index);
    if base_policy != head_policy {
        let fail_category = Some(DriftFailCategory::PolicyDecisionChange);
        let blocking = is_blocking(mode, fail_category, fail_on);
        changes.push(DriftChange {
            id: String::new(),
            kind: DriftChangeKind::PolicyChanged,
            severity: severity_for(blocking, true),
            route_key,
            base_route_id: Some(base_route.id.clone()),
            head_route_id: Some(head_route.id.clone()),
            message: format!(
                "Policy decision cases changed for {}",
                route_label(head_route)
            ),
            direction: Some(DriftComparison::Changed),
            before: json!({ "policy_cases": base_policy }),
            after: json!({ "policy_cases": head_policy }),
            evidence_ids: evidence_ids(head_route, head_index),
            weak_evidence_ids: weak_evidence_ids(head_route, head_index),
            mutation_ids: mutation_ids(head_route, head_index),
            link_ids: link_ids(head_route, head_index),
            sensitivity_reasons: sensitivity_reasons(head_route, head_index),
            reviewer_questions: reviewer_questions(head_route, head_index),
            fail_category,
            enforcement_blocking: blocking,
        });
    }
}

fn added_route_change(
    route: &authmap_core::Route,
    index: &DriftIndex<'_>,
    mode: ScanMode,
    fail_on: &[DriftFailCategory],
) -> DriftChange {
    let coverage = index.coverage_by_route.get(route.id.as_str()).copied();
    let fail_category = coverage.and_then(|coverage| match coverage.risk {
        RiskLevel::High => Some(DriftFailCategory::AddedHighRiskRoute),
        RiskLevel::ReviewRequired => Some(DriftFailCategory::AddedReviewRequiredRoute),
        _ => None,
    });
    let blocking = is_blocking(mode, fail_category, fail_on);
    DriftChange {
        id: String::new(),
        kind: DriftChangeKind::AddedRoute,
        severity: severity_for(blocking, fail_category.is_some()),
        route_key: stable_route_key(route),
        base_route_id: None,
        head_route_id: Some(route.id.clone()),
        message: format!("Added route {}", route_label(route)),
        direction: None,
        before: Value::Null,
        after: route_value(route, coverage),
        evidence_ids: evidence_ids(route, index),
        weak_evidence_ids: weak_evidence_ids(route, index),
        mutation_ids: mutation_ids(route, index),
        link_ids: link_ids(route, index),
        sensitivity_reasons: sensitivity_reasons(route, index),
        reviewer_questions: reviewer_questions(route, index),
        fail_category,
        enforcement_blocking: blocking,
    }
}

fn removed_route_change(route: &authmap_core::Route, index: &DriftIndex<'_>) -> DriftChange {
    let coverage = index.coverage_by_route.get(route.id.as_str()).copied();
    DriftChange {
        id: String::new(),
        kind: DriftChangeKind::RemovedRoute,
        severity: DriftChangeSeverity::Note,
        route_key: stable_route_key(route),
        base_route_id: Some(route.id.clone()),
        head_route_id: None,
        message: format!("Removed route {}", route_label(route)),
        direction: None,
        before: route_value(route, coverage),
        after: Value::Null,
        evidence_ids: evidence_ids(route, index),
        weak_evidence_ids: weak_evidence_ids(route, index),
        mutation_ids: mutation_ids(route, index),
        link_ids: link_ids(route, index),
        sensitivity_reasons: sensitivity_reasons(route, index),
        reviewer_questions: reviewer_questions(route, index),
        fail_category: None,
        enforcement_blocking: false,
    }
}

fn input_metadata(document: &AuthMapDocument, label: impl Into<String>) -> DriftInputMetadata {
    DriftInputMetadata {
        label: label.into(),
        schema_version: document.schema_version.clone(),
        target_roots: document.metadata.target_roots.clone(),
    }
}

fn collect_diagnostics(base: &AuthMapDocument, head: &AuthMapDocument) -> Vec<Diagnostic> {
    let mut diagnostics = base.diagnostics.clone();
    diagnostics.extend(head.diagnostics.clone());
    diagnostics.sort_by(|left, right| diagnostic_key(left).cmp(&diagnostic_key(right)));
    diagnostics
}

fn diagnostic_key(diagnostic: &Diagnostic) -> (String, String, String, String) {
    (
        diagnostic.code.clone(),
        format!("{:?}", diagnostic.severity),
        diagnostic
            .span
            .as_ref()
            .map(span_signature)
            .unwrap_or_default(),
        diagnostic.message.clone(),
    )
}

fn span_signature(span: &Span) -> String {
    format!("{}:{}:{}", span.file, span.line, span.column)
}

fn summarize_changes(changes: &[DriftChange]) -> DriftSummary {
    let mut summary = DriftSummary {
        total_changes: changes.len(),
        ..DriftSummary::default()
    };
    for change in changes {
        match change.kind {
            DriftChangeKind::AddedRoute => summary.added_routes += 1,
            DriftChangeKind::RemovedRoute => summary.removed_routes += 1,
            DriftChangeKind::HandlerChanged => summary.handler_changes += 1,
            DriftChangeKind::EvidenceChanged => summary.evidence_changes += 1,
            DriftChangeKind::RemovedEvidence => summary.removed_evidence += 1,
            DriftChangeKind::CoverageChanged => summary.coverage_changes += 1,
            DriftChangeKind::NewLinkedMutation => summary.new_linked_mutations += 1,
            DriftChangeKind::PolicyChanged => summary.policy_changes += 1,
        }
        if change.enforcement_blocking {
            summary.blocking_changes += 1;
        }
    }
    summary
}

fn is_blocking(
    mode: ScanMode,
    category: Option<DriftFailCategory>,
    fail_on: &[DriftFailCategory],
) -> bool {
    mode == ScanMode::Enforce && category.is_some_and(|category| fail_on.contains(&category))
}

fn severity_for(blocking: bool, review_required: bool) -> DriftChangeSeverity {
    if blocking {
        DriftChangeSeverity::Error
    } else if review_required {
        DriftChangeSeverity::Warning
    } else {
        DriftChangeSeverity::Note
    }
}

fn compare_coverage(base: &Coverage, head: &Coverage) -> DriftComparison {
    let base_risk = risk_rank(base.risk);
    let head_risk = risk_rank(head.risk);
    if head_risk > base_risk || class_rank(head.class) < class_rank(base.class) {
        DriftComparison::Downgrade
    } else if head_risk < base_risk || class_rank(head.class) > class_rank(base.class) {
        DriftComparison::Upgrade
    } else {
        DriftComparison::Changed
    }
}

fn stable_route_key(route: &authmap_core::Route) -> String {
    format!(
        "{} {} {}",
        framework_label(route.framework),
        route.method,
        route.path
    )
}

fn route_label(route: &authmap_core::Route) -> String {
    format!("{} {}", route.method, route.path)
}

fn route_value(route: &authmap_core::Route, coverage: Option<&Coverage>) -> Value {
    json!({
        "id": route.id,
        "framework": framework_label(route.framework),
        "method": route.method,
        "path": route.path,
        "handler": handler_signature(route),
        "coverage": coverage.map(coverage_value),
    })
}

fn coverage_value(coverage: &Coverage) -> Value {
    json!({
        "class": coverage_class_label(coverage.class),
        "risk": risk_label(coverage.risk),
        "rationale": coverage.rationale,
        "reviewer_questions": coverage.reviewer_questions,
        "uncertainty_reasons": coverage.uncertainty_reasons,
    })
}

fn evidence_value(evidence: &Evidence) -> Value {
    json!({
        "id": evidence.id,
        "evidence_type": evidence_type_label(evidence.evidence_type),
        "mechanism": evidence.mechanism,
        "symbol": evidence.symbol,
        "location": evidence.span,
        "confidence": confidence_label(evidence.confidence),
        "notes": evidence.notes,
    })
}

fn evidence_signatures(route: &authmap_core::Route, index: &DriftIndex<'_>) -> BTreeSet<String> {
    index
        .evidence_by_route
        .get(route.id.as_str())
        .into_iter()
        .flatten()
        .map(|evidence| evidence_signature(evidence))
        .collect()
}

fn evidence_by_signature<'a>(
    route: &authmap_core::Route,
    index: &DriftIndex<'a>,
) -> BTreeMap<String, &'a Evidence> {
    index
        .evidence_by_route
        .get(route.id.as_str())
        .into_iter()
        .flatten()
        .map(|evidence| (evidence_signature(evidence), *evidence))
        .collect()
}

fn evidence_ids(route: &authmap_core::Route, index: &DriftIndex<'_>) -> Vec<String> {
    index
        .evidence_by_route
        .get(route.id.as_str())
        .map(|items| sorted_strings(items.iter().map(|item| item.id.clone())))
        .unwrap_or_default()
}

fn weak_evidence_ids(route: &authmap_core::Route, index: &DriftIndex<'_>) -> Vec<String> {
    if let Some(coverage) = index.coverage_by_route.get(route.id.as_str()) {
        let ids = coverage_support_strings(coverage, "weak_evidence_ids");
        if !ids.is_empty() {
            return ids;
        }
    }
    index
        .evidence_by_route
        .get(route.id.as_str())
        .map(|items| {
            sorted_strings(
                items
                    .iter()
                    .filter(|item| {
                        item.confidence == authmap_core::Confidence::Low
                            || item.evidence_type == authmap_core::EvidenceType::UnknownDynamicCheck
                    })
                    .map(|item| item.id.clone()),
            )
        })
        .unwrap_or_default()
}

fn mutation_signatures(route: &authmap_core::Route, index: &DriftIndex<'_>) -> BTreeSet<String> {
    index
        .mutations_by_route
        .get(route.id.as_str())
        .into_iter()
        .flatten()
        .map(|mutation| mutation_signature(mutation))
        .collect()
}

fn policy_signatures(route: &authmap_core::Route, index: &DriftIndex<'_>) -> BTreeSet<String> {
    index
        .policy_cases_by_route
        .get(route.id.as_str())
        .into_iter()
        .flatten()
        .map(|case| policy_case_signature(case))
        .collect()
}

fn mutation_ids(route: &authmap_core::Route, index: &DriftIndex<'_>) -> Vec<String> {
    index
        .mutations_by_route
        .get(route.id.as_str())
        .map(|items| sorted_strings(items.iter().map(|item| item.id.clone())))
        .unwrap_or_default()
}

fn link_ids(route: &authmap_core::Route, index: &DriftIndex<'_>) -> Vec<String> {
    if let Some(coverage) = index.coverage_by_route.get(route.id.as_str()) {
        let ids = coverage_support_strings(coverage, "link_ids");
        if !ids.is_empty() {
            return ids;
        }
    }
    index
        .links_by_route
        .get(route.id.as_str())
        .map(|items| sorted_strings(items.iter().map(|item| item.id.clone())))
        .unwrap_or_default()
}

fn sensitivity_reasons(route: &authmap_core::Route, index: &DriftIndex<'_>) -> Vec<String> {
    index
        .coverage_by_route
        .get(route.id.as_str())
        .map(|coverage| coverage_support_strings(coverage, "sensitivity_reasons"))
        .unwrap_or_default()
}

fn reviewer_questions(route: &authmap_core::Route, index: &DriftIndex<'_>) -> Vec<String> {
    index
        .coverage_by_route
        .get(route.id.as_str())
        .map(|coverage| sorted_strings(coverage.reviewer_questions.iter().cloned()))
        .unwrap_or_default()
}

fn coverage_support_strings(coverage: &Coverage, key: &str) -> Vec<String> {
    let mut values = coverage
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
        .unwrap_or_default();
    values.sort();
    values.dedup();
    values
}

fn sorted_strings(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut values = items.collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn evidence_signature(evidence: &Evidence) -> String {
    format!(
        "{}:{}:{}",
        evidence_type_label(evidence.evidence_type),
        evidence.mechanism,
        evidence
            .symbol
            .as_ref()
            .map_or("".to_string(), |symbol| symbol.name.clone())
    )
}

fn mutation_signature(mutation: &Mutation) -> String {
    format!(
        "{}:{}:{}",
        mutation_operation_label(mutation.operation),
        mutation.library.clone().unwrap_or_default(),
        mutation.resource.clone().unwrap_or_default()
    )
}

fn policy_case_signature(case: &PolicyCase) -> String {
    let branches = case
        .branches
        .iter()
        .map(|branch| {
            format!(
                "{}:{}:{}",
                branch.condition,
                policy_outcome_label(branch.outcome),
                branch.reachable
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    format!(
        "{}:{}:{}:{}",
        policy_case_kind_label(case.kind),
        case.summary,
        case.input_names.join(","),
        branches
    )
}

fn handler_signature(route: &authmap_core::Route) -> String {
    route
        .handler
        .as_ref()
        .map_or_else(String::new, |handler| handler.name.clone())
}

fn is_removed_control_evidence(evidence_type: authmap_core::EvidenceType) -> bool {
    !matches!(evidence_type, authmap_core::EvidenceType::ExplicitPublic)
}

fn control_finding_from_change(change: &DriftChange) -> Option<ControlFinding> {
    let (control_type, confidence) = match change.kind {
        DriftChangeKind::RemovedEvidence => (
            control_kind_from_evidence_value(&change.before).unwrap_or(ControlDriftKind::Guard),
            authmap_core::Confidence::High,
        ),
        DriftChangeKind::CoverageChanged
            if change.direction == Some(DriftComparison::Downgrade) =>
        {
            (
                ControlDriftKind::RouteGuard,
                authmap_core::Confidence::Medium,
            )
        }
        DriftChangeKind::PolicyChanged => (
            ControlDriftKind::PolicyHelper,
            authmap_core::Confidence::High,
        ),
        DriftChangeKind::NewLinkedMutation
            if change.evidence_ids.is_empty() || !change.weak_evidence_ids.is_empty() =>
        {
            (
                ControlDriftKind::RouteGuard,
                authmap_core::Confidence::Medium,
            )
        }
        _ => return None,
    };
    Some(ControlFinding {
        id: String::new(),
        control_type,
        source_change_id: change.id.clone(),
        source_change_kind: change.kind,
        severity: change.severity,
        route_key: change.route_key.clone(),
        base_route_id: change.base_route_id.clone(),
        head_route_id: change.head_route_id.clone(),
        message: change.message.clone(),
        confidence,
        location: location_from_change(change),
        evidence_ids: change.evidence_ids.clone(),
        weak_evidence_ids: change.weak_evidence_ids.clone(),
        mutation_ids: change.mutation_ids.clone(),
        link_ids: change.link_ids.clone(),
        reviewer_questions: change.reviewer_questions.clone(),
        fail_category: change.fail_category,
        enforcement_blocking: change.enforcement_blocking,
    })
}

fn control_kind_from_evidence_value(value: &Value) -> Option<ControlDriftKind> {
    match value.get("evidence_type").and_then(Value::as_str)? {
        "permission_check" => Some(ControlDriftKind::PermissionMap),
        "tenant_check" => Some(ControlDriftKind::TenantHelper),
        "ownership_check" => Some(ControlDriftKind::OwnershipHelper),
        "admin_check" => Some(ControlDriftKind::AdminGate),
        "audit_log" => Some(ControlDriftKind::AuditControl),
        "authn" | "role_check" | "unknown_dynamic_check" => Some(ControlDriftKind::Guard),
        _ => None,
    }
}

fn location_from_change(change: &DriftChange) -> Option<Span> {
    change
        .before
        .get("location")
        .or_else(|| change.after.get("location"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

fn summarize_control_findings(findings: &[ControlFinding]) -> ControlSummary {
    let mut summary = ControlSummary {
        total_findings: findings.len(),
        ..ControlSummary::default()
    };
    for finding in findings {
        match finding.control_type {
            ControlDriftKind::Guard => summary.guard_changes += 1,
            ControlDriftKind::RouteGuard => summary.route_guard_changes += 1,
            ControlDriftKind::PermissionMap => summary.permission_changes += 1,
            ControlDriftKind::TenantHelper => summary.tenant_changes += 1,
            ControlDriftKind::OwnershipHelper => summary.ownership_changes += 1,
            ControlDriftKind::AdminGate => summary.admin_changes += 1,
            ControlDriftKind::AuditControl => summary.audit_changes += 1,
            ControlDriftKind::PolicyHelper => summary.policy_changes += 1,
            ControlDriftKind::AuthRelevantHeader => summary.auth_relevant_header_changes += 1,
        }
        if finding.severity != DriftChangeSeverity::Note {
            summary.review_required += 1;
        }
        if finding.enforcement_blocking {
            summary.blocking_findings += 1;
        }
    }
    summary
}

fn sorted_fail_categories(categories: &[DriftFailCategory]) -> Vec<DriftFailCategory> {
    let mut values = categories.to_vec();
    values.sort();
    values.dedup();
    values
}

fn risk_rank(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::ReviewRequired => 2,
        RiskLevel::High => 3,
    }
}

fn class_rank(class: CoverageClass) -> u8 {
    match class {
        CoverageClass::Unauthenticated => 0,
        CoverageClass::UnknownOrDynamic => 1,
        CoverageClass::AuthnOnly => 2,
        CoverageClass::PublicDeclared => 2,
        CoverageClass::RoleGuarded => 3,
        CoverageClass::TenantGuarded => 4,
        CoverageClass::OwnershipGuarded => 4,
        CoverageClass::PermissionGuarded => 5,
        CoverageClass::AdminGuarded => 5,
    }
}

fn framework_label(framework: Framework) -> &'static str {
    match framework {
        Framework::FastApi => "fast_api",
        Framework::Django => "django",
        Framework::DjangoRestFramework => "django_rest_framework",
        Framework::Express => "express",
        Framework::NextJs => "next_js",
        Framework::Trpc => "trpc",
        Framework::Graphql => "graphql",
        Framework::Unknown => "unknown",
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

fn evidence_type_label(evidence_type: authmap_core::EvidenceType) -> &'static str {
    match evidence_type {
        authmap_core::EvidenceType::Authn => "authn",
        authmap_core::EvidenceType::RoleCheck => "role_check",
        authmap_core::EvidenceType::PermissionCheck => "permission_check",
        authmap_core::EvidenceType::OwnershipCheck => "ownership_check",
        authmap_core::EvidenceType::TenantCheck => "tenant_check",
        authmap_core::EvidenceType::AdminCheck => "admin_check",
        authmap_core::EvidenceType::ExplicitPublic => "explicit_public",
        authmap_core::EvidenceType::AuditLog => "audit_log",
        authmap_core::EvidenceType::UnknownDynamicCheck => "unknown_dynamic_check",
    }
}

fn confidence_label(confidence: authmap_core::Confidence) -> &'static str {
    match confidence {
        authmap_core::Confidence::High => "high",
        authmap_core::Confidence::Medium => "medium",
        authmap_core::Confidence::Low => "low",
    }
}

fn policy_case_kind_label(kind: authmap_core::PolicyCaseKind) -> &'static str {
    match kind {
        authmap_core::PolicyCaseKind::EffectiveProtection => "effective_protection",
        authmap_core::PolicyCaseKind::LinkedMutationProtection => "linked_mutation_protection",
        authmap_core::PolicyCaseKind::Conflict => "conflict",
        authmap_core::PolicyCaseKind::Duplicate => "duplicate",
        authmap_core::PolicyCaseKind::Unreachable => "unreachable",
        authmap_core::PolicyCaseKind::Dynamic => "dynamic",
    }
}

fn policy_outcome_label(outcome: authmap_core::PolicyOutcome) -> &'static str {
    match outcome {
        authmap_core::PolicyOutcome::Allow => "allow",
        authmap_core::PolicyOutcome::Deny => "deny",
        authmap_core::PolicyOutcome::Unknown => "unknown",
        authmap_core::PolicyOutcome::ReviewRequired => "review_required",
    }
}

fn mutation_operation_label(operation: authmap_core::MutationOperation) -> &'static str {
    match operation {
        authmap_core::MutationOperation::Create => "create",
        authmap_core::MutationOperation::Update => "update",
        authmap_core::MutationOperation::Delete => "delete",
        authmap_core::MutationOperation::Save => "save",
        authmap_core::MutationOperation::BulkUpdate => "bulk_update",
        authmap_core::MutationOperation::RawSqlMutation => "raw_sql_mutation",
        authmap_core::MutationOperation::UnknownMutation => "unknown_mutation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authmap_core::{
        Confidence, EvidenceType, MutationOperation, PolicyBranch, PolicyCase, PolicyCaseKind,
        PolicyOutcome, ReachabilityLink, Route, ScanMetadata, SymbolRef,
    };

    #[test]
    fn diff_covers_route_handler_evidence_coverage_and_mutation_drift() {
        let mut base = AuthMapDocument::empty(ScanMetadata::default());
        base.routes = vec![
            route("route_keep", "GET", "/accounts/{id}", "read_account"),
            route("route_removed", "GET", "/legacy", "legacy"),
            route("route_upgrade", "GET", "/reports", "reports"),
        ];
        base.evidence = vec![
            evidence(
                "evidence_keep",
                "route_keep",
                EvidenceType::PermissionCheck,
                "can_read",
            ),
            evidence(
                "evidence_upgrade",
                "route_upgrade",
                EvidenceType::Authn,
                "require_user",
            ),
        ];
        base.coverage = vec![
            coverage(
                "route_keep",
                CoverageClass::PermissionGuarded,
                RiskLevel::Low,
            ),
            coverage(
                "route_removed",
                CoverageClass::Unauthenticated,
                RiskLevel::Low,
            ),
            coverage(
                "route_upgrade",
                CoverageClass::AuthnOnly,
                RiskLevel::ReviewRequired,
            ),
        ];

        let mut head = AuthMapDocument::empty(ScanMetadata::default());
        head.routes = vec![
            route("route_keep", "GET", "/accounts/{id}", "read_account_v2"),
            route("route_added", "POST", "/admin/accounts", "create_account"),
            route("route_upgrade", "GET", "/reports", "reports"),
        ];
        head.evidence = vec![
            evidence(
                "evidence_keep",
                "route_keep",
                EvidenceType::Authn,
                "require_user",
            ),
            evidence(
                "evidence_upgrade",
                "route_upgrade",
                EvidenceType::PermissionCheck,
                "can_view",
            ),
        ];
        head.mutations = vec![Mutation {
            id: "mutation_0001".to_string(),
            operation: MutationOperation::Create,
            library: Some("sqlalchemy".to_string()),
            resource: Some("Account".to_string()),
            span: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: Default::default(),
        }];
        head.links = vec![ReachabilityLink {
            id: "link_0001".to_string(),
            route_id: "route_keep".to_string(),
            mutation_id: Some("mutation_0001".to_string()),
            evidence_id: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: Default::default(),
        }];
        head.coverage = vec![
            coverage(
                "route_keep",
                CoverageClass::AuthnOnly,
                RiskLevel::ReviewRequired,
            ),
            coverage(
                "route_added",
                CoverageClass::Unauthenticated,
                RiskLevel::High,
            ),
            coverage(
                "route_upgrade",
                CoverageClass::PermissionGuarded,
                RiskLevel::Low,
            ),
        ];

        let report = analyze_drift(
            &base,
            &head,
            ScanMode::Enforce,
            &[
                DriftFailCategory::AddedHighRiskRoute,
                DriftFailCategory::AuthDowngrade,
                DriftFailCategory::NewLinkedMutation,
            ],
            "base",
            "head",
        );

        assert_eq!(report.summary.added_routes, 1);
        assert_eq!(report.summary.removed_routes, 1);
        assert_eq!(report.summary.handler_changes, 1);
        assert_eq!(report.summary.evidence_changes, 2);
        assert_eq!(report.summary.coverage_changes, 2);
        assert_eq!(report.summary.new_linked_mutations, 1);
        assert_eq!(report.summary.blocking_changes, 3);
        assert!(report.has_enforce_blocking_changes());
        assert!(report.changes.iter().any(|change| {
            change.kind == DriftChangeKind::CoverageChanged
                && change.fail_category == Some(DriftFailCategory::AuthDowngrade)
        }));
        assert!(report.changes.iter().any(|change| {
            change.kind == DriftChangeKind::CoverageChanged
                && change.fail_category.is_none()
                && change.message.contains("permission_guarded")
        }));
    }

    #[test]
    fn semantic_diff_reports_removed_evidence_and_policy_decision_changes() {
        let mut base = AuthMapDocument::empty(ScanMetadata::default());
        base.routes = vec![route(
            "route_keep",
            "POST",
            "/accounts/{id}",
            "update_account",
        )];
        base.evidence = vec![
            evidence(
                "evidence_permission",
                "route_keep",
                EvidenceType::PermissionCheck,
                "can_write_account",
            ),
            evidence(
                "evidence_tenant",
                "route_keep",
                EvidenceType::TenantCheck,
                "tenant_scope",
            ),
        ];
        base.coverage = vec![coverage(
            "route_keep",
            CoverageClass::PermissionGuarded,
            RiskLevel::Low,
        )];
        base.policy_cases = vec![PolicyCase {
            id: "policy_case_0001".to_string(),
            route_id: "route_keep".to_string(),
            kind: PolicyCaseKind::EffectiveProtection,
            summary: "permission allows write".to_string(),
            evidence_ids: vec!["evidence_permission".to_string()],
            input_names: vec!["permission".to_string()],
            branches: vec![PolicyBranch {
                condition: "can_write_account".to_string(),
                outcome: PolicyOutcome::Allow,
                reachable: true,
                evidence_ids: vec!["evidence_permission".to_string()],
                span: None,
                confidence: Confidence::High,
                notes: Vec::new(),
            }],
            span: None,
            confidence: Confidence::High,
            reviewer_questions: Vec::new(),
            uncertainty_reasons: Vec::new(),
            extensions: Default::default(),
        }];

        let mut head = AuthMapDocument::empty(ScanMetadata::default());
        head.routes = base.routes.clone();
        head.evidence = vec![evidence(
            "evidence_tenant",
            "route_keep",
            EvidenceType::TenantCheck,
            "tenant_scope",
        )];
        head.coverage = vec![coverage(
            "route_keep",
            CoverageClass::TenantGuarded,
            RiskLevel::ReviewRequired,
        )];
        head.policy_cases = vec![PolicyCase {
            branches: vec![PolicyBranch {
                outcome: PolicyOutcome::ReviewRequired,
                ..base.policy_cases[0].branches[0].clone()
            }],
            ..base.policy_cases[0].clone()
        }];

        let report = analyze_drift(
            &base,
            &head,
            ScanMode::Enforce,
            &[
                DriftFailCategory::RemovedAuthorizationEvidence,
                DriftFailCategory::PolicyDecisionChange,
            ],
            "base",
            "head",
        );

        assert!(report.changes.iter().any(|change| {
            change.kind == DriftChangeKind::RemovedEvidence
                && change.fail_category == Some(DriftFailCategory::RemovedAuthorizationEvidence)
                && change.enforcement_blocking
        }));
        assert!(report.changes.iter().any(|change| {
            change.kind == DriftChangeKind::PolicyChanged
                && change.fail_category == Some(DriftFailCategory::PolicyDecisionChange)
                && change.enforcement_blocking
        }));
    }

    #[test]
    fn controls_report_focuses_on_authorization_control_drift() {
        let mut base = AuthMapDocument::empty(ScanMetadata::default());
        base.routes = vec![route(
            "route_keep",
            "POST",
            "/admin/accounts",
            "create_account",
        )];
        base.evidence = vec![evidence(
            "evidence_admin",
            "route_keep",
            EvidenceType::AdminCheck,
            "require_admin",
        )];
        base.coverage = vec![coverage(
            "route_keep",
            CoverageClass::AdminGuarded,
            RiskLevel::Low,
        )];

        let mut head = AuthMapDocument::empty(ScanMetadata::default());
        head.routes = base.routes.clone();
        head.coverage = vec![coverage(
            "route_keep",
            CoverageClass::Unauthenticated,
            RiskLevel::High,
        )];

        let report = analyze_controls_with_config(
            &base,
            &head,
            ScanMode::Advisory,
            &[DriftFailCategory::RemovedAuthorizationEvidence],
            "base",
            "head",
            DriftConfigMetadata::none(),
        );

        assert_eq!(report.report_type, "authmap.controls");
        assert_eq!(report.summary.total_findings, 2);
        assert!(report.findings.iter().any(|finding| {
            finding.control_type == ControlDriftKind::AdminGate
                && finding.source_change_kind == DriftChangeKind::RemovedEvidence
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.control_type == ControlDriftKind::RouteGuard
                && finding.source_change_kind == DriftChangeKind::CoverageChanged
        }));
    }

    fn route(id: &str, method: &str, path: &str, handler: &str) -> Route {
        Route {
            id: id.to_string(),
            framework: Framework::FastApi,
            method: method.to_string(),
            path: path.to_string(),
            name: None,
            tags: Vec::new(),
            middleware: Vec::new(),
            params: Vec::new(),
            declared_protection: Vec::new(),
            handler: Some(SymbolRef {
                name: handler.to_string(),
                span: None,
            }),
            span: None,
            source_evidence: Vec::new(),
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: Default::default(),
        }
    }

    fn evidence(
        id: &str,
        route_id: &str,
        evidence_type: EvidenceType,
        mechanism: &str,
    ) -> Evidence {
        Evidence {
            id: id.to_string(),
            route_id: Some(route_id.to_string()),
            evidence_type,
            mechanism: mechanism.to_string(),
            symbol: None,
            span: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: Default::default(),
        }
    }

    fn coverage(route_id: &str, class: CoverageClass, risk: RiskLevel) -> Coverage {
        Coverage {
            route_id: route_id.to_string(),
            class,
            risk,
            rationale: Vec::new(),
            reviewer_questions: Vec::new(),
            uncertainty_reasons: Vec::new(),
            extensions: Default::default(),
        }
    }
}
