use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::Instant;

use authmap_adapters::{AdapterContext, AdapterRegistry};
use authmap_config::{
    AuthorizationRule, AuthorizationRuleMatch, ResourceSensitivityRule, RouteSensitivityRule,
    ScanConfig, ScanPlan,
};
use authmap_core::{
    AuthMapDocument, Confidence, Coverage, CoverageClass, Diagnostic, DiagnosticCategory,
    DiagnosticSeverity, Evidence, EvidenceType, Framework, Mutation, MutationOperation,
    PolicyBranch, PolicyCase, PolicyCaseKind, PolicyOutcome, ReachabilityLink, Recoverability,
    RiskLevel, RouteParam, RouteProtection, RouteProtectionKind, ScanMetadata, Span, SymbolRef,
};
use authmap_discovery::discover_sources;
use authmap_parsers::{
    ParseError, ParsedFile, TreeSitterBackend, parse_files_in_parallel,
    parse_files_in_parallel_selective,
};
use serde::Serialize;
use thiserror::Error;
use tree_sitter::Node;

mod drift;

pub use drift::{
    ControlDriftKind, ControlFinding, ControlReport, ControlSummary, DriftChange, DriftChangeKind,
    DriftChangeSeverity, DriftComparison, DriftConfigMetadata, DriftInputMetadata, DriftMetadata,
    DriftReport, DriftSummary, analyze_controls_with_config, analyze_drift,
    analyze_drift_with_config,
};

pub trait EvidenceExtractor: Send + Sync {
    fn extract_evidence(&self, input: &AnalysisInput<'_>) -> AnalysisFacts;
}

pub trait MutationExtractor: Send + Sync {
    fn extract_mutations(&self, input: &AnalysisInput<'_>) -> AnalysisFacts;
}

pub trait ReachabilityLinker: Send + Sync {
    fn link_reachability(&self, input: &AnalysisInput<'_>) -> AnalysisFacts;
}

#[derive(Clone, Debug)]
pub struct AnalysisInput<'a> {
    pub routes: &'a [authmap_core::Route],
    pub parsed_files: &'a [ParsedFile],
    pub config: &'a ScanConfig,
    pub adapter_evidence: &'a [Evidence],
    pub mutations: &'a [Mutation],
}

#[derive(Clone, Debug, Default)]
pub struct AnalysisFacts {
    pub evidence: Vec<Evidence>,
    pub mutations: Vec<Mutation>,
    pub links: Vec<ReachabilityLink>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct RuleSuggestionReport {
    pub target_roots: Vec<String>,
    pub source_files_scanned: usize,
    pub suggestions: Vec<RuleSuggestion>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuleSuggestion {
    pub name: String,
    pub evidence_type: EvidenceType,
    pub mechanism: String,
    pub confidence: Confidence,
    #[serde(rename = "match")]
    pub matcher: RuleSuggestionMatch,
    pub rationale: Vec<String>,
    pub examples: Vec<RuleSuggestionExample>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RuleSuggestionMatch {
    pub exact: Vec<String>,
    pub contains: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuleSuggestionExample {
    pub symbol: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub context: String,
}

#[derive(Clone, Debug, Default)]
pub struct BuiltInEvidenceExtractor;

impl EvidenceExtractor for BuiltInEvidenceExtractor {
    fn extract_evidence(&self, input: &AnalysisInput<'_>) -> AnalysisFacts {
        let mut evidence = input.adapter_evidence.to_vec();
        let rules = EvidenceRules::new(input.config);
        let parsed_by_path = input
            .parsed_files
            .iter()
            .map(|parsed| (parsed.source.path.as_str(), parsed))
            .collect::<BTreeMap<_, _>>();
        let service_index = input
            .routes
            .iter()
            .any(route_supports_service_evidence)
            .then(|| ReachabilityIndex::new(input.parsed_files));
        let django_class_index = input
            .routes
            .iter()
            .any(|route| {
                matches!(
                    route.framework,
                    Framework::Django | Framework::DjangoRestFramework
                )
            })
            .then(|| PythonClassIndex::new(input.parsed_files));

        for route in input.routes {
            let mut route_evidence = match route.framework {
                Framework::Express => {
                    extract_express_route_evidence(route, &parsed_by_path, &rules)
                }
                Framework::FastApi => {
                    extract_fastapi_route_evidence(route, &parsed_by_path, &rules)
                }
                Framework::Django | Framework::DjangoRestFramework => {
                    if let Some(django_class_index) = &django_class_index {
                        extract_django_route_evidence(
                            route,
                            &parsed_by_path,
                            &rules,
                            django_class_index,
                        )
                    } else {
                        Vec::new()
                    }
                }
                Framework::NextJs => extract_nextjs_route_evidence(route, &parsed_by_path, &rules),
                Framework::Trpc => extract_trpc_route_evidence(route),
                Framework::Graphql => extract_graphql_route_evidence(route),
                _ => Vec::new(),
            };
            if let Some(service_index) = &service_index {
                route_evidence.extend(extract_service_call_evidence(
                    route,
                    &parsed_by_path,
                    &rules,
                    service_index,
                ));
            }
            evidence.append(&mut route_evidence);
        }

        dedup_evidence(&mut evidence);
        evidence.sort_by_key(evidence_sort_key);
        for (index, item) in evidence.iter_mut().enumerate() {
            item.id = format!("evidence_{:04}", index + 1);
        }

        AnalysisFacts {
            evidence,
            ..AnalysisFacts::default()
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BuiltInMutationExtractor;

impl MutationExtractor for BuiltInMutationExtractor {
    fn extract_mutations(&self, input: &AnalysisInput<'_>) -> AnalysisFacts {
        let mut mutations = input.mutations.to_vec();
        for parsed in input.parsed_files {
            let Some(root) = parsed.root_node() else {
                continue;
            };
            match parsed.language {
                authmap_core::Language::JavaScript
                | authmap_core::Language::JavaScriptReact
                | authmap_core::Language::TypeScript
                | authmap_core::Language::TypeScriptReact => {
                    mutations.extend(extract_prisma_mutations(parsed, root));
                }
                authmap_core::Language::Python => {
                    if python_may_contain_mutation(parsed) {
                        mutations.extend(extract_python_mutations(parsed, root));
                    }
                }
                authmap_core::Language::Unknown => {}
            }
        }

        dedup_mutations(&mut mutations);
        mutations.sort_by_key(mutation_sort_key);
        for (index, mutation) in mutations.iter_mut().enumerate() {
            mutation.id = format!("mutation_{:04}", index + 1);
        }

        AnalysisFacts {
            mutations,
            ..AnalysisFacts::default()
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BuiltInReachabilityLinker;

impl ReachabilityLinker for BuiltInReachabilityLinker {
    fn link_reachability(&self, input: &AnalysisInput<'_>) -> AnalysisFacts {
        if !input.routes.iter().any(|route| {
            matches!(
                route.framework,
                Framework::Express
                    | Framework::FastApi
                    | Framework::Django
                    | Framework::DjangoRestFramework
                    | Framework::NextJs
            )
        }) {
            return AnalysisFacts::default();
        }

        let index = ReachabilityIndex::new(input.parsed_files);
        let parsed_by_path = input
            .parsed_files
            .iter()
            .map(|parsed| (parsed.source.path.as_str(), parsed))
            .collect::<BTreeMap<_, _>>();

        let mut links = Vec::new();
        for route in input.routes {
            let Some(handler) = &route.handler else {
                continue;
            };
            let Some(parsed) =
                route_file(route).and_then(|file| parsed_by_path.get(file.as_str()).copied())
            else {
                continue;
            };
            let handler_node = match route.framework {
                Framework::Express => express_handler_node(parsed, handler).into_iter().collect(),
                Framework::FastApi => fastapi_handler_function_node(parsed, &handler.name)
                    .into_iter()
                    .collect(),
                Framework::Django | Framework::DjangoRestFramework => {
                    django_handler_nodes(parsed, route, handler)
                }
                Framework::NextJs => nextjs_handler_nodes(parsed, route, handler),
                _ => Vec::new(),
            };
            for handler_node in handler_node {
                links.extend(link_route_handler_mutations(
                    route,
                    parsed,
                    handler_node,
                    input.mutations,
                    &index,
                ));
            }
        }

        dedup_links(&mut links);
        links.sort_by_key(link_sort_key);
        for (index, link) in links.iter_mut().enumerate() {
            link.id = format!("link_{:04}", index + 1);
        }

        AnalysisFacts {
            links,
            ..AnalysisFacts::default()
        }
    }
}

pub fn run_scan(plan: &ScanPlan) -> Result<AuthMapDocument, ScanError> {
    run_scan_with_started_at(plan, Instant::now())
}

fn derive_policy_cases(
    routes: &[authmap_core::Route],
    evidence: &[Evidence],
    mutations: &[Mutation],
    links: &[ReachabilityLink],
    parsed_files: &[ParsedFile],
) -> (Vec<PolicyCase>, Vec<Diagnostic>) {
    let mut cases = Vec::new();
    let mut diagnostics = Vec::new();
    let mut evidence_by_route = BTreeMap::<&str, Vec<&Evidence>>::new();
    let evidence_by_id = evidence
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    for item in evidence {
        if let Some(route_id) = &item.route_id {
            evidence_by_route
                .entry(route_id.as_str())
                .or_default()
                .push(item);
        }
    }
    for link in links {
        if let Some(evidence_id) = &link.evidence_id
            && let Some(item) = evidence_by_id.get(evidence_id.as_str())
        {
            evidence_by_route
                .entry(link.route_id.as_str())
                .or_default()
                .push(item);
        }
    }
    for route_evidence in evidence_by_route.values_mut() {
        route_evidence.sort_by(|left, right| left.id.cmp(&right.id));
        route_evidence.dedup_by(|left, right| left.id == right.id);
    }
    let mutation_by_id = mutations
        .iter()
        .map(|mutation| (mutation.id.as_str(), mutation))
        .collect::<BTreeMap<_, _>>();
    let mut links_by_route = BTreeMap::<&str, Vec<&ReachabilityLink>>::new();
    for link in links {
        links_by_route
            .entry(link.route_id.as_str())
            .or_default()
            .push(link);
    }
    for route_links in links_by_route.values_mut() {
        route_links.sort_by(|left, right| left.id.cmp(&right.id));
    }

    for route in routes {
        let route_evidence = evidence_by_route
            .get(route.id.as_str())
            .cloned()
            .unwrap_or_default();
        let route_links = links_by_route
            .get(route.id.as_str())
            .cloned()
            .unwrap_or_default();

        if let Some(case) = effective_policy_case(route, &route_evidence, &route_links) {
            cases.push(case);
        }
        if let Some(case) = linked_mutation_policy_case(route, &route_links, &mutation_by_id) {
            cases.push(case);
        }
        if let Some((case, diagnostic)) = conflicting_policy_case(route, &route_evidence) {
            cases.push(case);
            diagnostics.push(diagnostic);
        }
        for (case, diagnostic) in duplicate_policy_cases(route, &route_evidence) {
            cases.push(case);
            diagnostics.push(diagnostic);
        }
        for case in dynamic_policy_cases(route, &route_evidence) {
            diagnostics.push(policy_diagnostic(
                authmap_core::diagnostic_codes::POLICY_DYNAMIC_BEHAVIOR,
                case.span.clone(),
                "Dynamic policy evidence requires review.".to_string(),
            ));
            cases.push(case);
        }
        for (case, diagnostic) in unreachable_policy_cases(route, &route_evidence, parsed_files) {
            cases.push(case);
            diagnostics.push(diagnostic);
        }
    }

    cases.sort_by_key(policy_case_sort_key);
    for (index, case) in cases.iter_mut().enumerate() {
        case.id = format!("policy_case_{:04}", index + 1);
    }
    sort_diagnostics(&mut diagnostics);
    diagnostics.dedup_by(|left, right| {
        left.code == right.code && left.span == right.span && left.message == right.message
    });
    (cases, diagnostics)
}

fn effective_policy_case(
    route: &authmap_core::Route,
    evidence: &[&Evidence],
    links: &[&ReachabilityLink],
) -> Option<PolicyCase> {
    let strong = evidence
        .iter()
        .copied()
        .filter(|item| item.confidence != Confidence::Low)
        .filter(|item| item.evidence_type != EvidenceType::UnknownDynamicCheck)
        .collect::<Vec<_>>();
    if strong
        .iter()
        .all(|item| item.evidence_type == EvidenceType::AuditLog)
    {
        return None;
    }
    let evidence_ids = sorted_ids(strong.iter().map(|item| item.id.as_str()));
    let mut mutation_ids = links
        .iter()
        .filter_map(|link| link.mutation_id.as_deref())
        .map(str::to_string)
        .collect::<Vec<_>>();
    mutation_ids.sort();
    mutation_ids.dedup();
    let strongest = strong
        .iter()
        .map(|item| item.confidence)
        .min()
        .unwrap_or(Confidence::Low);
    let labels = strong
        .iter()
        .map(|item| evidence_type_label(item.evidence_type).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut extensions = authmap_core::ExtensionMap::new();
    if !mutation_ids.is_empty() {
        extensions.insert(
            "authmap.policy".to_string(),
            serde_json::json!({ "mutation_ids": mutation_ids }),
        );
    }
    Some(PolicyCase {
        id: String::new(),
        route_id: route.id.clone(),
        kind: PolicyCaseKind::EffectiveProtection,
        summary: format!(
            "{} evidence support(s) route protection: {}.",
            strong.len(),
            labels.join(", ")
        ),
        evidence_ids: evidence_ids.clone(),
        input_names: policy_input_names(&strong),
        branches: vec![PolicyBranch {
            condition: "static authorization evidence present".to_string(),
            outcome: PolicyOutcome::Allow,
            reachable: true,
            evidence_ids,
            span: first_span(&strong).cloned().or_else(|| route.span.clone()),
            confidence: strongest,
            notes: Vec::new(),
        }],
        span: first_span(&strong).cloned().or_else(|| route.span.clone()),
        confidence: strongest,
        reviewer_questions: Vec::new(),
        uncertainty_reasons: Vec::new(),
        extensions,
    })
}

fn linked_mutation_policy_case(
    route: &authmap_core::Route,
    links: &[&ReachabilityLink],
    mutation_by_id: &BTreeMap<&str, &Mutation>,
) -> Option<PolicyCase> {
    let mutation_ids = sorted_ids(links.iter().filter_map(|link| link.mutation_id.as_deref()));
    if mutation_ids.is_empty() {
        return None;
    }
    let link_ids = sorted_ids(links.iter().map(|link| link.id.as_str()));
    let evidence_ids = sorted_ids(links.iter().filter_map(|link| link.evidence_id.as_deref()));
    let resources = mutation_ids
        .iter()
        .filter_map(|id| mutation_by_id.get(id.as_str()))
        .filter_map(|mutation| mutation.resource.as_deref())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut extensions = authmap_core::ExtensionMap::new();
    extensions.insert(
        "authmap.policy".to_string(),
        serde_json::json!({ "mutation_ids": mutation_ids, "link_ids": link_ids }),
    );
    Some(PolicyCase {
        id: String::new(),
        route_id: route.id.clone(),
        kind: PolicyCaseKind::LinkedMutationProtection,
        summary: format!(
            "Route reaches linked mutation(s): {}.",
            if resources.is_empty() {
                mutation_ids.join(", ")
            } else {
                format!("{} ({})", mutation_ids.join(", "), resources.join(", "))
            }
        ),
        evidence_ids: evidence_ids.clone(),
        input_names: resources,
        branches: vec![PolicyBranch {
            condition: "route-to-mutation reachability".to_string(),
            outcome: PolicyOutcome::ReviewRequired,
            reachable: true,
            evidence_ids,
            span: route.span.clone(),
            confidence: links
                .iter()
                .map(|link| link.confidence)
                .min()
                .unwrap_or(Confidence::Low),
            notes: Vec::new(),
        }],
        span: route.span.clone(),
        confidence: links
            .iter()
            .map(|link| link.confidence)
            .min()
            .unwrap_or(Confidence::Low),
        reviewer_questions: vec![
            "Should linked data mutations have resource-specific authorization evidence?"
                .to_string(),
        ],
        uncertainty_reasons: Vec::new(),
        extensions,
    })
}

fn conflicting_policy_case(
    route: &authmap_core::Route,
    evidence: &[&Evidence],
) -> Option<(PolicyCase, Diagnostic)> {
    let public = evidence
        .iter()
        .copied()
        .filter(|item| item.evidence_type == EvidenceType::ExplicitPublic)
        .collect::<Vec<_>>();
    let protected = evidence
        .iter()
        .copied()
        .filter(|item| {
            matches!(
                item.evidence_type,
                EvidenceType::Authn
                    | EvidenceType::RoleCheck
                    | EvidenceType::PermissionCheck
                    | EvidenceType::OwnershipCheck
                    | EvidenceType::TenantCheck
                    | EvidenceType::AdminCheck
            )
        })
        .collect::<Vec<_>>();
    if public.is_empty() || protected.is_empty() {
        return None;
    }
    let combined = public
        .iter()
        .chain(protected.iter())
        .copied()
        .collect::<Vec<_>>();
    let evidence_ids = sorted_ids(combined.iter().map(|item| item.id.as_str()));
    let span = first_span(&combined)
        .cloned()
        .or_else(|| route.span.clone());
    let message = "Route has explicit public evidence and authorization-required evidence; review intended behavior.".to_string();
    Some((
        PolicyCase {
            id: String::new(),
            route_id: route.id.clone(),
            kind: PolicyCaseKind::Conflict,
            summary: message.clone(),
            evidence_ids: evidence_ids.clone(),
            input_names: policy_input_names(&combined),
            branches: vec![PolicyBranch {
                condition: "explicit public marker conflicts with guard evidence".to_string(),
                outcome: PolicyOutcome::ReviewRequired,
                reachable: true,
                evidence_ids,
                span: span.clone(),
                confidence: Confidence::Medium,
                notes: Vec::new(),
            }],
            span: span.clone(),
            confidence: Confidence::Medium,
            reviewer_questions: vec!["Is this route intentionally public and guarded?".to_string()],
            uncertainty_reasons: vec![
                "Conflicting policy evidence requires reviewer confirmation.".to_string(),
            ],
            extensions: authmap_core::ExtensionMap::new(),
        },
        policy_diagnostic(
            authmap_core::diagnostic_codes::POLICY_CONFLICTING_EVIDENCE,
            span,
            message,
        ),
    ))
}

fn duplicate_policy_cases(
    route: &authmap_core::Route,
    evidence: &[&Evidence],
) -> Vec<(PolicyCase, Diagnostic)> {
    let mut groups = BTreeMap::<(EvidenceType, String, Option<String>), Vec<&Evidence>>::new();
    for item in evidence {
        groups
            .entry((
                item.evidence_type,
                item.mechanism.clone(),
                item.symbol.as_ref().map(|symbol| symbol.name.clone()),
            ))
            .or_default()
            .push(item);
    }
    let mut cases = Vec::new();
    for ((evidence_type, mechanism, symbol), mut items) in groups {
        if items.len() < 2 || evidence_type == EvidenceType::AuditLog {
            continue;
        }
        items.sort_by(|left, right| left.id.cmp(&right.id));
        let evidence_ids = sorted_ids(items.iter().map(|item| item.id.as_str()));
        let span = first_span(&items).cloned().or_else(|| route.span.clone());
        let label = symbol.unwrap_or(mechanism);
        let message = format!("Duplicate policy evidence `{label}` appears on the same route.");
        cases.push((
            PolicyCase {
                id: String::new(),
                route_id: route.id.clone(),
                kind: PolicyCaseKind::Duplicate,
                summary: message.clone(),
                evidence_ids: evidence_ids.clone(),
                input_names: policy_input_names(&items),
                branches: vec![PolicyBranch {
                    condition: format!("duplicate {label} evidence"),
                    outcome: PolicyOutcome::ReviewRequired,
                    reachable: true,
                    evidence_ids,
                    span: span.clone(),
                    confidence: Confidence::Medium,
                    notes: Vec::new(),
                }],
                span: span.clone(),
                confidence: Confidence::Medium,
                reviewer_questions: vec![
                    "Is duplicated guard evidence intentional or redundant?".to_string(),
                ],
                uncertainty_reasons: vec![
                    "Duplicated policy evidence may be safe but should be reviewed.".to_string(),
                ],
                extensions: authmap_core::ExtensionMap::new(),
            },
            policy_diagnostic(
                authmap_core::diagnostic_codes::POLICY_DUPLICATE_EVIDENCE,
                span,
                message,
            ),
        ));
    }
    cases
}

fn dynamic_policy_cases(route: &authmap_core::Route, evidence: &[&Evidence]) -> Vec<PolicyCase> {
    evidence
        .iter()
        .copied()
        .filter(|item| item.evidence_type == EvidenceType::UnknownDynamicCheck)
        .map(|item| PolicyCase {
            id: String::new(),
            route_id: route.id.clone(),
            kind: PolicyCaseKind::Dynamic,
            summary: "Dynamic policy behavior requires review.".to_string(),
            evidence_ids: vec![item.id.clone()],
            input_names: item
                .symbol
                .as_ref()
                .map(|symbol| vec![symbol.name.clone()])
                .unwrap_or_default(),
            branches: vec![PolicyBranch {
                condition: "dynamic policy dispatch".to_string(),
                outcome: PolicyOutcome::ReviewRequired,
                reachable: true,
                evidence_ids: vec![item.id.clone()],
                span: item.span.clone(),
                confidence: item.confidence,
                notes: item.notes.clone(),
            }],
            span: item.span.clone(),
            confidence: item.confidence,
            reviewer_questions: vec![
                "Can the dynamic authorization path be confirmed?".to_string(),
            ],
            uncertainty_reasons: vec![
                "Dynamic authorization evidence requires review.".to_string(),
            ],
            extensions: authmap_core::ExtensionMap::new(),
        })
        .collect()
}

fn unreachable_policy_cases(
    route: &authmap_core::Route,
    evidence: &[&Evidence],
    parsed_files: &[ParsedFile],
) -> Vec<(PolicyCase, Diagnostic)> {
    evidence
        .iter()
        .copied()
        .filter_map(|item| {
            let unreachable_span = item
                .span
                .as_ref()
                .is_some_and(|span| span_has_unreachable_false_guard(span, parsed_files))
                .then(|| item.span.clone())
                .flatten()
                .or_else(|| {
                    route.span.as_ref().and_then(|span| {
                        span_has_unreachable_false_guard(span, parsed_files).then(|| span.clone())
                    })
                });
            unreachable_span.map(|span| (item, span))
        })
        .map(|(item, span)| {
            let evidence_ids = vec![item.id.clone()];
            let message =
                "Policy evidence appears inside a statically unreachable branch.".to_string();
            (
                PolicyCase {
                    id: String::new(),
                    route_id: route.id.clone(),
                    kind: PolicyCaseKind::Unreachable,
                    summary: message.clone(),
                    evidence_ids: evidence_ids.clone(),
                    input_names: policy_input_names(&[item]),
                    branches: vec![PolicyBranch {
                        condition: "literal false branch".to_string(),
                        outcome: PolicyOutcome::ReviewRequired,
                        reachable: false,
                        evidence_ids,
                        span: Some(span.clone()),
                        confidence: Confidence::High,
                        notes: Vec::new(),
                    }],
                    span: Some(span.clone()),
                    confidence: Confidence::High,
                    reviewer_questions: vec![
                        "Is this policy branch reachable in the deployed code?".to_string(),
                    ],
                    uncertainty_reasons: Vec::new(),
                    extensions: authmap_core::ExtensionMap::new(),
                },
                policy_diagnostic(
                    authmap_core::diagnostic_codes::POLICY_UNREACHABLE_BRANCH,
                    Some(span),
                    message,
                ),
            )
        })
        .collect()
}

fn span_has_unreachable_false_guard(span: &Span, parsed_files: &[ParsedFile]) -> bool {
    let Some(parsed) = parsed_files
        .iter()
        .find(|parsed| parsed.source.path == span.file)
    else {
        return false;
    };
    let lines = parsed.text.lines().collect::<Vec<_>>();
    let line_index = span.line.saturating_sub(1) as usize;
    let start = line_index.saturating_sub(3);
    lines
        .get(start..=line_index.min(lines.len().saturating_sub(1)))
        .unwrap_or(&[])
        .iter()
        .any(|line| {
            let normalized = line
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase();
            normalized.contains("if(false)")
                || normalized.contains("iffalse:")
                || normalized.contains("if0:")
                || normalized.contains("if(0)")
        })
}

fn enrich_coverage_with_policy_cases(coverage: &mut [Coverage], policy_cases: &[PolicyCase]) {
    let mut cases_by_route = BTreeMap::<&str, Vec<&PolicyCase>>::new();
    for case in policy_cases {
        cases_by_route
            .entry(case.route_id.as_str())
            .or_default()
            .push(case);
    }
    for item in coverage {
        let Some(cases) = cases_by_route.get(item.route_id.as_str()) else {
            continue;
        };
        let policy_case_ids = sorted_ids(cases.iter().map(|case| case.id.as_str()));
        let support = item
            .extensions
            .entry("authmap.coverage".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if let Some(object) = support.as_object_mut() {
            object.insert(
                "policy_case_ids".to_string(),
                serde_json::json!(policy_case_ids),
            );
        }
        for case in cases {
            item.reviewer_questions
                .extend(case.reviewer_questions.iter().cloned());
            item.uncertainty_reasons
                .extend(case.uncertainty_reasons.iter().cloned());
        }
        item.reviewer_questions.sort();
        item.reviewer_questions.dedup();
        item.uncertainty_reasons.sort();
        item.uncertainty_reasons.dedup();
    }
}

fn policy_input_names(evidence: &[&Evidence]) -> Vec<String> {
    let mut inputs = evidence
        .iter()
        .filter_map(|item| match item.evidence_type {
            EvidenceType::Authn => Some("identity".to_string()),
            EvidenceType::RoleCheck => Some("role".to_string()),
            EvidenceType::PermissionCheck => Some("permission".to_string()),
            EvidenceType::OwnershipCheck => Some("ownership".to_string()),
            EvidenceType::TenantCheck => Some("tenant".to_string()),
            EvidenceType::AdminCheck => Some("admin".to_string()),
            EvidenceType::ExplicitPublic => Some("public_marker".to_string()),
            EvidenceType::UnknownDynamicCheck => {
                item.symbol.as_ref().map(|symbol| symbol.name.clone())
            }
            EvidenceType::AuditLog => None,
        })
        .collect::<Vec<_>>();
    inputs.sort();
    inputs.dedup();
    inputs
}

fn first_span<'a>(evidence: &'a [&Evidence]) -> Option<&'a Span> {
    evidence.iter().find_map(|item| item.span.as_ref())
}

fn policy_diagnostic(code: &str, span: Option<Span>, message: String) -> Diagnostic {
    Diagnostic {
        category: DiagnosticCategory::Policy,
        code: code.to_string(),
        severity: DiagnosticSeverity::Warning,
        recoverability: Recoverability::Recoverable,
        span,
        message,
    }
}

fn policy_case_sort_key(case: &PolicyCase) -> (String, u8, String, u32) {
    (
        case.route_id.clone(),
        policy_case_kind_rank(case.kind),
        case.span
            .as_ref()
            .map_or_else(String::new, |span| span.file.clone()),
        case.span.as_ref().map_or(0, |span| span.line),
    )
}

fn policy_case_kind_rank(kind: PolicyCaseKind) -> u8 {
    match kind {
        PolicyCaseKind::EffectiveProtection => 0,
        PolicyCaseKind::LinkedMutationProtection => 1,
        PolicyCaseKind::Conflict => 2,
        PolicyCaseKind::Duplicate => 3,
        PolicyCaseKind::Dynamic => 4,
        PolicyCaseKind::Unreachable => 5,
    }
}

fn source_needs_syntax_tree(
    language: authmap_core::Language,
    text: &str,
    config: &ScanConfig,
) -> bool {
    if !config.authorization.rules.is_empty() {
        return true;
    }
    match language {
        authmap_core::Language::Python => python_needs_syntax_tree(text),
        authmap_core::Language::JavaScript
        | authmap_core::Language::JavaScriptReact
        | authmap_core::Language::TypeScript
        | authmap_core::Language::TypeScriptReact
        | authmap_core::Language::Unknown => true,
    }
}

fn python_needs_syntax_tree(text: &str) -> bool {
    if contains_any(text, &["def ", "class ", "import ", "from "]) {
        return true;
    }
    if python_text_may_contain_mutation(text) {
        return true;
    }
    if contains_any(text, &["authorize(", "authorise("]) {
        return true;
    }
    if contains_any(
        text,
        &[
            "FastAPI(",
            "APIRouter(",
            "@app.",
            "@router.",
            "Depends(",
            "include_router(",
            "urlpatterns",
            "path(",
            "re_path(",
            "DefaultRouter(",
            ".register(",
            "@api_view",
            "APIView",
            "ViewSet",
            "BasePermission",
            "PermissionRequiredMixin",
            "permission_classes",
            "permission_required",
            "get_permissions",
            "get_queryset",
        ],
    ) {
        return true;
    }
    if text.contains("class ") && text.contains("View") {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "from fastapi",
            "import fastapi",
            "django.urls",
            "rest_framework",
            "django.views",
            "django.contrib.auth",
        ],
    )
}

fn enabled_frameworks_for_sources(parsed_files: &[ParsedFile]) -> Vec<String> {
    let mut frameworks = BTreeSet::<String>::new();
    for parsed in parsed_files {
        // Discovery records per-project `ProjectHint`s from manifests and imports.
        // Union them in so an adapter still runs when the in-file text heuristic misses
        // (aliased, wrapped, or re-exported framework imports).
        for hint in &parsed.source.project_hints {
            if let Some(name) = framework_name_for_hint(*hint) {
                frameworks.insert(name.to_string());
            }
        }

        match parsed.language {
            authmap_core::Language::Python => {
                if python_has_fastapi_route_indicators(&parsed.text) {
                    frameworks.insert("fastapi".to_string());
                }
                if python_has_django_route_indicators(&parsed.text) {
                    frameworks.insert("django".to_string());
                }
                if python_has_graphql_route_indicators(&parsed.text) {
                    frameworks.insert("graphql".to_string());
                }
            }
            authmap_core::Language::JavaScript
            | authmap_core::Language::JavaScriptReact
            | authmap_core::Language::TypeScript
            | authmap_core::Language::TypeScriptReact => {
                if js_has_express_route_indicators(&parsed.text) {
                    frameworks.insert("express".to_string());
                }
                if js_has_nextjs_route_indicators(parsed, &parsed.text) {
                    frameworks.insert("nextjs".to_string());
                }
                if js_has_trpc_route_indicators(&parsed.text) {
                    frameworks.insert("trpc".to_string());
                }
            }
            authmap_core::Language::Unknown => {}
        }
    }
    frameworks.into_iter().collect()
}

/// Maps a discovery `ProjectHint` to the adapter `name()` it should enable, when any.
/// ORM hints (SqlAlchemy, DjangoOrm, Prisma) do not map to a route adapter.
fn framework_name_for_hint(hint: authmap_core::ProjectHint) -> Option<&'static str> {
    match hint {
        authmap_core::ProjectHint::FastApi => Some("fastapi"),
        authmap_core::ProjectHint::Django | authmap_core::ProjectHint::DjangoRestFramework => {
            Some("django")
        }
        authmap_core::ProjectHint::Express => Some("express"),
        authmap_core::ProjectHint::NextJs => Some("nextjs"),
        authmap_core::ProjectHint::SqlAlchemy
        | authmap_core::ProjectHint::DjangoOrm
        | authmap_core::ProjectHint::Prisma => None,
    }
}

fn js_has_trpc_route_indicators(text: &str) -> bool {
    text.contains("Procedure")
        || text.contains("procedure")
        || text.contains("@trpc/server")
        || text.contains("createTRPCRouter")
        || text.contains("initTRPC")
}

fn python_has_fastapi_route_indicators(text: &str) -> bool {
    contains_any(
        text,
        &[
            "FastAPI(",
            "APIRouter(",
            "@app.",
            "@router.",
            "include_router(",
        ],
    ) || contains_any(
        &text.to_ascii_lowercase(),
        &["from fastapi", "import fastapi"],
    )
}

fn python_has_django_route_indicators(text: &str) -> bool {
    contains_any(
        text,
        &[
            "urlpatterns",
            "DefaultRouter(",
            "@api_view",
            "APIView",
            "ViewSet",
        ],
    ) || contains_any(&text.to_ascii_lowercase(), &["rest_framework.routers"])
}

fn python_has_graphql_route_indicators(text: &str) -> bool {
    contains_any(
        text,
        &[
            "graphene",
            "BaseMutation",
            "ModelMutation",
            "ModelDeleteMutation",
            "DeprecatedModelMutation",
        ],
    )
}

fn js_has_express_route_indicators(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "from \"express\"",
            "from 'express'",
            "require(\"express\")",
            "require('express')",
            "express.router(",
            "setupapiroute(",
            "setuppageroute(",
            "setupadminpageroute(",
            "app.use(",
            "router.use(",
        ],
    )
}

fn js_has_nextjs_route_indicators(parsed: &ParsedFile, text: &str) -> bool {
    let path = parsed.source.path.replace('\\', "/").to_ascii_lowercase();
    path.contains("/app/api/")
        || contains_any(
            &text.to_ascii_lowercase(),
            &["next/server", "from \"next", "from 'next"],
        )
}

fn run_scan_with_started_at(
    plan: &ScanPlan,
    started_at: Instant,
) -> Result<AuthMapDocument, ScanError> {
    let budget = RuntimeBudget::new(started_at, plan.config.limits.max_runtime_ms);
    let discovery = discover_sources(plan)?;
    let backend = TreeSitterBackend;
    let mut document = empty_document(plan);
    document.source_files = discovery.files.clone();
    document.diagnostics = discovery.diagnostics;
    if budget.is_exceeded() {
        push_runtime_limit_diagnostic(&mut document, plan);
        finalize_diagnostics(&mut document);
        return Ok(document);
    }

    let parse_output = parse_files_in_parallel_selective(
        &backend,
        &document.source_files,
        |file| {
            fs::read_to_string(&file.path).map_err(|source| ParseError::Read {
                path: file.path.clone(),
                message: source.to_string(),
            })
        },
        |file, text| source_needs_syntax_tree(file.language, text, &plan.config),
    );
    document.diagnostics.extend(parse_output.diagnostics);
    if budget.is_exceeded() {
        push_runtime_limit_diagnostic(&mut document, plan);
        finalize_diagnostics(&mut document);
        return Ok(document);
    }

    let adapter_registry = AdapterRegistry::built_in();
    let adapter_context = AdapterContext {
        enabled_frameworks: enabled_frameworks_for_sources(&parse_output.parsed_files),
    };
    let adapter_output =
        adapter_registry.discover_routes(&parse_output.parsed_files, &adapter_context);

    document.routes = adapter_output.routes;
    document.diagnostics.extend(adapter_output.diagnostics);
    document.routes.sort_by_key(route_sort_key);
    let route_id_remaps = route_id_remaps(&mut document.routes);
    let adapter_evidence = normalize_adapter_evidence(
        adapter_output.evidence,
        &document.routes,
        &route_id_remaps,
        &mut document.diagnostics,
    );
    if budget.is_exceeded() {
        push_runtime_limit_diagnostic(&mut document, plan);
        finalize_diagnostics(&mut document);
        return Ok(document);
    }

    let input = AnalysisInput {
        routes: &document.routes,
        parsed_files: &parse_output.parsed_files,
        config: &plan.config,
        adapter_evidence: &adapter_evidence,
        mutations: &adapter_output.mutations,
    };
    let facts = BuiltInEvidenceExtractor.extract_evidence(&input);
    let mutation_facts = BuiltInMutationExtractor.extract_mutations(&input);
    document.evidence = facts.evidence;
    enrich_route_metadata(&mut document.routes, &document.evidence);
    document.mutations = mutation_facts.mutations;
    document.diagnostics.extend(facts.diagnostics);
    document.diagnostics.extend(mutation_facts.diagnostics);
    if budget.is_exceeded() {
        push_runtime_limit_diagnostic(&mut document, plan);
        finalize_diagnostics(&mut document);
        return Ok(document);
    }

    let link_input = AnalysisInput {
        routes: &document.routes,
        parsed_files: &parse_output.parsed_files,
        config: &plan.config,
        adapter_evidence: &adapter_evidence,
        mutations: &document.mutations,
    };
    let link_facts = BuiltInReachabilityLinker.link_reachability(&link_input);
    document.links = link_facts.links;
    document.diagnostics.extend(link_facts.diagnostics);
    if budget.is_exceeded() {
        push_runtime_limit_diagnostic(&mut document, plan);
        finalize_diagnostics(&mut document);
        return Ok(document);
    }

    let (policy_cases, policy_diagnostics) = derive_policy_cases(
        &document.routes,
        &document.evidence,
        &document.mutations,
        &document.links,
        &parse_output.parsed_files,
    );
    document.policy_cases = policy_cases;
    document.diagnostics.extend(policy_diagnostics);
    if budget.is_exceeded() {
        push_runtime_limit_diagnostic(&mut document, plan);
        finalize_diagnostics(&mut document);
        return Ok(document);
    }

    document.coverage = classify_coverage(
        &document.routes,
        &document.evidence,
        &document.mutations,
        &document.links,
        &plan.config,
    );
    enrich_coverage_with_policy_cases(&mut document.coverage, &document.policy_cases);
    if budget.is_exceeded() {
        push_runtime_limit_diagnostic(&mut document, plan);
    }
    finalize_diagnostics(&mut document);
    Ok(document)
}

fn empty_document(plan: &ScanPlan) -> AuthMapDocument {
    AuthMapDocument::empty(ScanMetadata {
        mode: plan.config.mode,
        target_roots: plan
            .targets
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect(),
        config_path: plan
            .config_path
            .as_ref()
            .map(|path| path.to_string_lossy().replace('\\', "/")),
        ..ScanMetadata::default()
    })
}

#[derive(Clone, Copy, Debug)]
struct RuntimeBudget {
    started_at: Instant,
    max_runtime_ms: u64,
}

impl RuntimeBudget {
    fn new(started_at: Instant, max_runtime_ms: u64) -> Self {
        Self {
            started_at,
            max_runtime_ms,
        }
    }

    fn is_exceeded(self) -> bool {
        self.started_at.elapsed().as_millis() >= u128::from(self.max_runtime_ms)
    }
}

fn push_runtime_limit_diagnostic(document: &mut AuthMapDocument, plan: &ScanPlan) {
    if document.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == authmap_core::diagnostic_codes::INTERNAL_RUNTIME_LIMIT_REACHED
    }) {
        return;
    }
    document.diagnostics.push(runtime_limit_diagnostic(plan));
}

fn runtime_limit_diagnostic(plan: &ScanPlan) -> Diagnostic {
    Diagnostic {
        category: DiagnosticCategory::Internal,
        code: authmap_core::diagnostic_codes::INTERNAL_RUNTIME_LIMIT_REACHED.to_string(),
        severity: incomplete_scan_severity(plan.config.mode),
        recoverability: Recoverability::Recoverable,
        span: None,
        message: format!(
            "scan exceeded configured max_runtime_ms of {}; returning deterministic partial results",
            plan.config.limits.max_runtime_ms
        ),
    }
}

fn incomplete_scan_severity(mode: authmap_core::ScanMode) -> DiagnosticSeverity {
    match mode {
        authmap_core::ScanMode::Advisory => DiagnosticSeverity::Warning,
        authmap_core::ScanMode::Enforce => DiagnosticSeverity::Error,
    }
}

fn finalize_diagnostics(document: &mut AuthMapDocument) {
    sort_diagnostics(&mut document.diagnostics);
}

fn sort_diagnostics(diagnostics: &mut [Diagnostic]) {
    diagnostics.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });
}

fn route_id_remaps(routes: &mut [authmap_core::Route]) -> BTreeMap<String, BTreeSet<String>> {
    let mut remaps = BTreeMap::<String, BTreeSet<String>>::new();
    for (index, route) in routes.iter_mut().enumerate() {
        let old_id = route.id.clone();
        let new_id = format!("route_{:04}", index + 1);
        if !old_id.is_empty() {
            remaps.entry(old_id).or_default().insert(new_id.clone());
        }
        route.id = new_id;
    }
    remaps
}

fn enrich_route_metadata(routes: &mut [authmap_core::Route], evidence: &[Evidence]) {
    let evidence_by_route = evidence.iter().fold(
        BTreeMap::<&str, Vec<&Evidence>>::new(),
        |mut by_route, item| {
            if let Some(route_id) = item.route_id.as_deref() {
                by_route.entry(route_id).or_default().push(item);
            }
            by_route
        },
    );

    for route in routes {
        route.params = route_params(&route.path);
        route.declared_protection = route_protection(
            route,
            evidence_by_route
                .get(route.id.as_str())
                .map_or(&[], Vec::as_slice),
        );
    }
}

fn route_params(path: &str) -> Vec<RouteParam> {
    let mut params = Vec::new();
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b':' => {
                let start = index + 1;
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                if end > start {
                    params.push(route_param(
                        &path[start..end],
                        &path[index..end],
                        Confidence::High,
                    ));
                }
                index = end;
            }
            b'{' => {
                if let Some(relative_end) = path[index + 1..].find('}') {
                    let end = index + 1 + relative_end;
                    let raw = &path[index + 1..end];
                    let name = raw.split_once(':').map_or(raw, |(name, _)| name);
                    if !name.is_empty() {
                        params.push(route_param(name, &path[index..=end], Confidence::High));
                    }
                    index = end + 1;
                } else {
                    index += 1;
                }
            }
            b'<' => {
                if let Some(relative_end) = path[index + 1..].find('>') {
                    let end = index + 1 + relative_end;
                    let raw = &path[index + 1..end];
                    let name = raw.rsplit_once(':').map_or(raw, |(_, name)| name);
                    if !name.is_empty() && name != "dynamic" {
                        params.push(route_param(name, &path[index..=end], Confidence::Medium));
                    }
                    index = end + 1;
                } else {
                    index += 1;
                }
            }
            b'[' => {
                if let Some((end, raw)) = nextjs_param(path, index) {
                    let name = raw.trim_start_matches("...").trim_matches('.');
                    if !name.is_empty() {
                        params.push(route_param(name, &path[index..end], Confidence::Medium));
                    }
                    index = end;
                } else {
                    index += 1;
                }
            }
            _ => index += 1,
        }
    }

    let mut seen = BTreeSet::new();
    params.retain(|param| seen.insert((param.name.clone(), param.syntax.clone())));
    params
}

fn nextjs_param(path: &str, index: usize) -> Option<(usize, &str)> {
    if path[index..].starts_with("[[") {
        let relative_end = path[index + 2..].find("]]")?;
        let end = index + 2 + relative_end;
        Some((end + 2, &path[index + 2..end]))
    } else {
        let relative_end = path[index + 1..].find(']')?;
        let end = index + 1 + relative_end;
        Some((end + 1, &path[index + 1..end]))
    }
}

fn route_param(name: &str, syntax: &str, confidence: Confidence) -> RouteParam {
    RouteParam {
        name: name.to_string(),
        syntax: syntax.to_string(),
        span: None,
        confidence,
        notes: Vec::new(),
    }
}

fn route_protection(route: &authmap_core::Route, evidence: &[&Evidence]) -> Vec<RouteProtection> {
    let mut protections = Vec::new();
    for middleware in &route.middleware {
        let inherited = protection_is_inherited(route, middleware);
        let matching_evidence = evidence
            .iter()
            .copied()
            .filter(|item| {
                item.symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == middleware.name)
            })
            .filter(|item| middleware_evidence_is_auth_guard(item.evidence_type))
            .collect::<Vec<_>>();
        if matching_evidence.is_empty() {
            continue;
        }
        protections.push(RouteProtection {
            kind: if inherited {
                RouteProtectionKind::InheritedGuard
            } else {
                RouteProtectionKind::RouteGuard
            },
            mechanism: route_middleware_mechanism(route.framework).to_string(),
            symbol: Some(middleware.clone()),
            span: middleware.span.clone(),
            inherited,
            confidence: matching_evidence
                .iter()
                .map(|item| item.confidence)
                .min()
                .unwrap_or(route.confidence),
            evidence_ids: matching_evidence
                .iter()
                .map(|item| item.id.clone())
                .collect(),
            notes: Vec::new(),
        });
    }

    for item in evidence {
        if protections.iter().any(|protection| {
            protection
                .symbol
                .as_ref()
                .zip(item.symbol.as_ref())
                .is_some_and(|(left, right)| left.name == right.name)
        }) {
            continue;
        }
        if item.mechanism == "route_param_scope_signal" {
            continue;
        }
        let Some(kind) = protection_kind_for_evidence(item.evidence_type) else {
            continue;
        };
        protections.push(RouteProtection {
            kind,
            mechanism: item.mechanism.clone(),
            symbol: item.symbol.clone(),
            span: item.span.clone(),
            inherited: false,
            confidence: item.confidence,
            evidence_ids: vec![item.id.clone()],
            notes: item.notes.clone(),
        });
    }

    protections.sort_by_key(route_protection_sort_key);
    protections
}

fn middleware_evidence_is_auth_guard(evidence_type: EvidenceType) -> bool {
    matches!(
        evidence_type,
        EvidenceType::Authn
            | EvidenceType::RoleCheck
            | EvidenceType::PermissionCheck
            | EvidenceType::OwnershipCheck
            | EvidenceType::TenantCheck
            | EvidenceType::AdminCheck
    )
}

fn route_context_is_inherited(route: &authmap_core::Route) -> bool {
    route.source_evidence.iter().any(|item| {
        item.mechanism.contains("include")
            || item.mechanism.contains("mount")
            || item.mechanism.contains("router_registration")
    })
}

fn protection_is_inherited(route: &authmap_core::Route, symbol: &SymbolRef) -> bool {
    if route_context_is_inherited(route) {
        return true;
    }
    match (route.span.as_ref(), symbol.span.as_ref()) {
        (Some(route_span), Some(symbol_span)) => route_span.file != symbol_span.file,
        _ => false,
    }
}

fn route_middleware_mechanism(framework: Framework) -> &'static str {
    match framework {
        Framework::FastApi => "fastapi_dependency",
        Framework::Express => "express_middleware",
        Framework::Django | Framework::DjangoRestFramework => "django_decorator",
        Framework::NextJs => "nextjs_middleware",
        Framework::Trpc => "trpc_procedure",
        Framework::Graphql => "graphql_permissions",
        Framework::Unknown => "route_middleware",
    }
}

fn protection_kind_for_evidence(evidence_type: EvidenceType) -> Option<RouteProtectionKind> {
    match evidence_type {
        EvidenceType::ExplicitPublic => Some(RouteProtectionKind::PublicDeclared),
        EvidenceType::UnknownDynamicCheck => Some(RouteProtectionKind::UnknownDynamic),
        EvidenceType::Authn
        | EvidenceType::RoleCheck
        | EvidenceType::PermissionCheck
        | EvidenceType::OwnershipCheck
        | EvidenceType::TenantCheck
        | EvidenceType::AdminCheck => Some(RouteProtectionKind::RouteGuard),
        EvidenceType::AuditLog => None,
    }
}

fn route_protection_sort_key(item: &RouteProtection) -> (RouteProtectionKind, String, String) {
    (
        item.kind,
        item.mechanism.clone(),
        item.symbol
            .as_ref()
            .map(|symbol| symbol.name.clone())
            .unwrap_or_default(),
    )
}

fn normalize_adapter_evidence(
    evidence: Vec<Evidence>,
    routes: &[authmap_core::Route],
    route_id_remaps: &BTreeMap<String, BTreeSet<String>>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Evidence> {
    let final_route_ids = routes
        .iter()
        .map(|route| route.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut normalized = Vec::new();
    for mut item in evidence {
        let Some(route_id) = item.route_id.clone() else {
            normalized.push(item);
            continue;
        };
        if let Some(remapped) = route_id_remaps.get(&route_id) {
            if remapped.len() == 1 {
                item.route_id = remapped.iter().next().cloned();
                normalized.push(item);
            } else {
                diagnostics.push(internal_diagnostic(
                    item.span.clone(),
                    format!(
                        "Adapter evidence referenced ambiguous pre-final route ID {route_id}; evidence was dropped"
                    ),
                ));
            }
        } else if final_route_ids.contains(route_id.as_str()) {
            normalized.push(item);
        } else {
            diagnostics.push(internal_diagnostic(
                item.span.clone(),
                format!(
                    "Adapter evidence referenced unknown route ID {route_id}; evidence was dropped"
                ),
            ));
        }
    }
    normalized
}

fn internal_diagnostic(span: Option<Span>, message: String) -> Diagnostic {
    Diagnostic {
        category: DiagnosticCategory::Internal,
        code: "analysis.adapter_evidence_route_id".to_string(),
        severity: DiagnosticSeverity::Warning,
        recoverability: Recoverability::Recoverable,
        span,
        message,
    }
}

pub fn suggest_rules(plan: &ScanPlan) -> Result<RuleSuggestionReport, ScanError> {
    suggest_rules_with_started_at(plan, Instant::now())
}

fn suggest_rules_with_started_at(
    plan: &ScanPlan,
    started_at: Instant,
) -> Result<RuleSuggestionReport, ScanError> {
    let budget = RuntimeBudget::new(started_at, plan.config.limits.max_runtime_ms);
    let discovery = discover_sources(plan)?;
    let target_roots = plan
        .targets
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();
    let mut diagnostics = discovery.diagnostics.clone();
    if budget.is_exceeded() {
        diagnostics.push(runtime_limit_diagnostic(plan));
        sort_diagnostics(&mut diagnostics);
        return Ok(RuleSuggestionReport {
            target_roots,
            source_files_scanned: 0,
            suggestions: Vec::new(),
            diagnostics,
        });
    }

    let backend = TreeSitterBackend;
    let parse_output = parse_files_in_parallel(&backend, &discovery.files, |file| {
        fs::read_to_string(&file.path).map_err(|source| ParseError::Read {
            path: file.path.clone(),
            message: source.to_string(),
        })
    });
    diagnostics.extend(parse_output.diagnostics.clone());
    if budget.is_exceeded() {
        diagnostics.push(runtime_limit_diagnostic(plan));
        sort_diagnostics(&mut diagnostics);
        return Ok(RuleSuggestionReport {
            target_roots,
            source_files_scanned: parse_output.parsed_files.len(),
            suggestions: Vec::new(),
            diagnostics,
        });
    }

    let adapter_registry = AdapterRegistry::built_in();
    let adapter_output =
        adapter_registry.discover_routes(&parse_output.parsed_files, &AdapterContext::default());
    diagnostics.extend(adapter_output.diagnostics.clone());
    if budget.is_exceeded() {
        diagnostics.push(runtime_limit_diagnostic(plan));
        sort_diagnostics(&mut diagnostics);
        return Ok(RuleSuggestionReport {
            target_roots,
            source_files_scanned: parse_output.parsed_files.len(),
            suggestions: Vec::new(),
            diagnostics,
        });
    }

    let route_handlers = adapter_output
        .routes
        .iter()
        .filter_map(|route| route.handler.as_ref())
        .map(|handler| handler.name.as_str())
        .filter(|name| !name.starts_with('<'))
        .collect::<BTreeSet<_>>();
    let route_files = adapter_output
        .routes
        .iter()
        .filter_map(|route| {
            route
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .or(route.span.as_ref())
        })
        .map(|span| span.file.as_str())
        .collect::<BTreeSet<_>>();

    let rules = EvidenceRules::new(&plan.config);
    let mut candidates = BTreeMap::<String, RuleCandidate>::new();
    for parsed in &parse_output.parsed_files {
        collect_rule_candidates(
            parsed,
            &route_files,
            &route_handlers,
            &rules,
            &mut candidates,
        );
    }

    let mut suggestions = candidates
        .into_values()
        .map(RuleCandidate::into_suggestion)
        .collect::<Vec<_>>();
    suggestions.sort_by_key(rule_suggestion_sort_key);
    if budget.is_exceeded() {
        suggestions.clear();
        diagnostics.push(runtime_limit_diagnostic(plan));
    }
    sort_diagnostics(&mut diagnostics);

    Ok(RuleSuggestionReport {
        target_roots,
        source_files_scanned: parse_output.parsed_files.len(),
        suggestions,
        diagnostics,
    })
}

#[derive(Clone, Debug)]
struct RuleCandidate {
    symbol: String,
    evidence_type: EvidenceType,
    confidence: Confidence,
    rationale: BTreeSet<String>,
    examples: Vec<RuleSuggestionExample>,
}

impl RuleCandidate {
    fn into_suggestion(mut self) -> RuleSuggestion {
        self.examples.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then(left.line.cmp(&right.line))
                .then(left.column.cmp(&right.column))
                .then(left.context.cmp(&right.context))
                .then(left.symbol.cmp(&right.symbol))
        });
        self.examples.dedup_by(|left, right| {
            left.symbol == right.symbol
                && left.file == right.file
                && left.line == right.line
                && left.column == right.column
                && left.context == right.context
        });
        self.examples.truncate(5);

        RuleSuggestion {
            name: format!(
                "Suggested {}: {}",
                evidence_type_label(self.evidence_type),
                self.symbol
            ),
            evidence_type: self.evidence_type,
            mechanism: suggested_mechanism(self.evidence_type).to_string(),
            confidence: self.confidence,
            matcher: RuleSuggestionMatch {
                exact: vec![self.symbol],
                contains: Vec::new(),
            },
            rationale: self.rationale.into_iter().collect(),
            examples: self.examples,
        }
    }
}

fn collect_rule_candidates(
    parsed: &ParsedFile,
    route_files: &BTreeSet<&str>,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
    candidates: &mut BTreeMap<String, RuleCandidate>,
) {
    if !route_files.is_empty() && !route_files.contains(parsed.source.path.as_str()) {
        return;
    }
    let Some(root) = parsed.root_node() else {
        return;
    };

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "function_declaration" => {
                if let Some(name) = function_name(parsed, node) {
                    add_rule_candidate(
                        candidates,
                        parsed,
                        &name,
                        node,
                        "function declaration",
                        route_handlers,
                        rules,
                    );
                }
            }
            "variable_declarator" => {
                if let Some(name) = variable_function_name(parsed, node) {
                    add_rule_candidate(
                        candidates,
                        parsed,
                        &name,
                        node,
                        "function binding",
                        route_handlers,
                        rules,
                    );
                }
            }
            "decorator" => {
                collect_decorator_candidate(parsed, node, route_handlers, rules, candidates)
            }
            "call" | "call_expression" => {
                collect_call_candidate(parsed, node, route_handlers, rules, candidates)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
}

fn collect_decorator_candidate(
    parsed: &ParsedFile,
    decorator: Node<'_>,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
    candidates: &mut BTreeMap<String, RuleCandidate>,
) {
    let Some(text) = parsed.text_for(decorator) else {
        return;
    };
    let stripped = text.trim_start_matches('@').trim();
    let symbol = stripped.split('(').next().unwrap_or(stripped);
    add_rule_candidate(
        candidates,
        parsed,
        &terminal_symbol_name(symbol),
        decorator,
        "decorator",
        route_handlers,
        rules,
    );
}

fn collect_call_candidate(
    parsed: &ParsedFile,
    call: Node<'_>,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
    candidates: &mut BTreeMap<String, RuleCandidate>,
) {
    let Some(function) = call.child_by_field_name("function") else {
        return;
    };
    let function_text = parsed.text_for(function).unwrap_or_default();
    if is_framework_route_call(function_text) {
        collect_route_argument_candidates(parsed, call, route_handlers, rules, candidates);
        return;
    }

    if is_fastapi_depends(function_text) {
        if let Some(symbol) = first_symbol_argument(parsed, call) {
            add_rule_candidate(
                candidates,
                parsed,
                &symbol.name,
                call,
                "FastAPI dependency",
                route_handlers,
                rules,
            );
        }
        return;
    }

    add_rule_candidate(
        candidates,
        parsed,
        &terminal_symbol_name(function_text),
        function,
        "call expression",
        route_handlers,
        rules,
    );
}

fn collect_route_argument_candidates(
    parsed: &ParsedFile,
    call: Node<'_>,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
    candidates: &mut BTreeMap<String, RuleCandidate>,
) {
    let args = call_argument_nodes(call);
    if args.len() < 3 {
        return;
    }

    for arg in &args[1..args.len() - 1] {
        collect_symbol_argument(
            parsed,
            *arg,
            "Express middleware",
            route_handlers,
            rules,
            candidates,
        );
    }
}

fn collect_symbol_argument(
    parsed: &ParsedFile,
    node: Node<'_>,
    context: &str,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
    candidates: &mut BTreeMap<String, RuleCandidate>,
) {
    if node.kind() == "array" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor).filter(|child| child.is_named()) {
            collect_symbol_argument(parsed, child, context, route_handlers, rules, candidates);
        }
        return;
    }

    let name = match node.kind() {
        "identifier" | "member_expression" | "attribute" => parsed.text_for(node),
        "call" | "call_expression" => node
            .child_by_field_name("function")
            .and_then(|function| parsed.text_for(function)),
        _ => None,
    };
    if let Some(name) = name {
        add_rule_candidate(
            candidates,
            parsed,
            &terminal_symbol_name(name),
            node,
            context,
            route_handlers,
            rules,
        );
    }
}

fn add_rule_candidate(
    candidates: &mut BTreeMap<String, RuleCandidate>,
    parsed: &ParsedFile,
    symbol: &str,
    node: Node<'_>,
    context: &str,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
) {
    let symbol = symbol.trim();
    if should_skip_rule_candidate(parsed, symbol, context, route_handlers, rules) {
        return;
    }
    let Some((evidence_type, confidence, rationale)) = classify_rule_candidate(symbol, context)
    else {
        return;
    };
    let span = parsed.span_for(node);
    let entry = candidates
        .entry(symbol.to_string())
        .or_insert_with(|| RuleCandidate {
            symbol: symbol.to_string(),
            evidence_type,
            confidence,
            rationale: BTreeSet::new(),
            examples: Vec::new(),
        });
    if evidence_type < entry.evidence_type {
        entry.evidence_type = evidence_type;
    }
    if confidence > entry.confidence {
        entry.confidence = confidence;
    }
    entry.rationale.insert(rationale);
    entry.examples.push(RuleSuggestionExample {
        symbol: symbol.to_string(),
        file: span.file,
        line: span.line,
        column: span.column,
        context: context.to_string(),
    });
}

fn should_skip_rule_candidate(
    parsed: &ParsedFile,
    symbol: &str,
    context: &str,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
) -> bool {
    let lower = symbol.to_ascii_lowercase();
    let path = parsed.source.path.replace('\\', "/").to_ascii_lowercase();
    if context == "FastAPI dependency" && is_operational_dependency_symbol(&lower) {
        return true;
    }
    if symbol.is_empty()
        || symbol.starts_with('<')
        || route_handlers.contains(symbol)
        || rules.match_symbol(symbol).is_some()
        || path.contains("/tests/")
        || path.contains("/models/")
        || path.contains("/tables/")
        || path.contains("/forms/")
        || path.contains("/migrations/")
        || path.ends_with("_test.py")
        || path.ends_with(".test.js")
        || path.ends_with(".test.ts")
    {
        return true;
    }
    if context == "call expression"
        && (lower.ends_with("serializer")
            || lower.ends_with("serializer_")
            || lower.ends_with("panel")
            || lower.ends_with("panels")
            || lower.ends_with("table")
            || lower.ends_with("form"))
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "app"
            | "router"
            | "route"
            | "get"
            | "post"
            | "put"
            | "patch"
            | "delete"
            | "use"
            | "next"
            | "req"
            | "res"
            | "request"
            | "response"
            | "json"
            | "send"
            | "sendstatus"
            | "status"
            | "list"
            | "create"
            | "read"
            | "update"
            | "remove"
            | "index"
            | "handler"
            | "depends"
    )
}

fn is_operational_dependency_symbol(lower: &str) -> bool {
    let tokens = symbol_tokens(lower);
    if tokens.iter().any(|token| token == "db") {
        return true;
    }
    contains_any(
        lower,
        &[
            "database",
            "session_context",
            "api_version",
            "client_version",
            "minimum_version",
            "pagination",
            "page_size",
            "limit",
            "settings",
            "config",
            "configuration",
            "logger",
            "cache",
            "clock",
            "metrics",
            "telemetry",
            "request_id",
            "correlation_id",
        ],
    )
}

fn classify_rule_candidate(
    symbol: &str,
    context: &str,
) -> Option<(EvidenceType, Confidence, String)> {
    let lower = symbol.to_ascii_lowercase();
    let context_lower = context.to_ascii_lowercase();
    let guard_like = looks_guard_like(&lower)
        || context_lower.contains("middleware")
        || context_lower.contains("dependency");

    if contains_any(
        &lower,
        &["allowanonymous", "allow_anonymous", "anonymous", "public"],
    ) {
        return Some((
            EvidenceType::ExplicitPublic,
            Confidence::Medium,
            "name suggests an explicit public or anonymous access marker".to_string(),
        ));
    }
    if contains_any(
        &lower,
        &["audit", "securitylog", "logsecurity", "log_security"],
    ) {
        return Some((
            EvidenceType::AuditLog,
            Confidence::Medium,
            "name suggests audit or security logging behavior".to_string(),
        ));
    }
    if contains_any(&lower, &["admin", "superuser", "staff"]) {
        return Some((
            EvidenceType::AdminCheck,
            Confidence::Medium,
            "name suggests an admin or privileged-user guard".to_string(),
        ));
    }
    if contains_any(
        &lower,
        &["tenant", "workspace", "organization", "organisation"],
    ) {
        return Some((
            EvidenceType::TenantCheck,
            Confidence::Medium,
            "name suggests tenant or organization isolation".to_string(),
        ));
    }
    if contains_any(&lower, &["owner", "ownership", "owning"]) {
        return Some((
            EvidenceType::OwnershipCheck,
            Confidence::Medium,
            "name suggests owner or resource ownership checks".to_string(),
        ));
    }
    let tokens = symbol_tokens(symbol);
    if tokens.first().is_some_and(|token| token == "can")
        || contains_any(
            &lower,
            &[
                "permission",
                "permissions",
                "permit",
                "allowed",
                "access",
                "scope",
                "entitlement",
                "billing",
                "paid",
                "plan",
            ],
        )
    {
        return Some((
            EvidenceType::PermissionCheck,
            Confidence::Medium,
            "name suggests a permission, entitlement, or access guard".to_string(),
        ));
    }
    if lower.contains("role")
        || (lower.contains("group") && (guard_like || context_lower.contains("permission")))
    {
        return Some((
            EvidenceType::RoleCheck,
            Confidence::Medium,
            "name suggests a role or group guard".to_string(),
        ));
    }
    if contains_any(&lower, &["policy", "authorize", "authorise", "enforce"]) {
        return Some((
            EvidenceType::UnknownDynamicCheck,
            Confidence::Low,
            "name suggests dynamic policy or authorization dispatch".to_string(),
        ));
    }
    if guard_like
        && contains_any(
            &lower,
            &[
                "auth",
                "session",
                "login",
                "jwt",
                "token",
                "authenticated",
                "user",
            ],
        )
    {
        return Some((
            EvidenceType::Authn,
            Confidence::Medium,
            "name suggests authentication or session enforcement".to_string(),
        ));
    }
    None
}

fn looks_guard_like(lower: &str) -> bool {
    lower.starts_with("require")
        || lower.starts_with("ensure")
        || lower.starts_with("check")
        || lower.starts_with("verify")
        || lower.starts_with("validate")
        || lower.starts_with("guard")
        || lower.starts_with("authorize")
        || lower.starts_with("authorise")
        || lower.contains("guard")
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn call_argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .children(&mut cursor)
        .filter(|child| child.is_named())
        .collect()
}

fn extract_prisma_mutations(parsed: &ParsedFile, root: Node<'_>) -> Vec<Mutation> {
    let mut mutations = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "call_expression" | "call")
            && let Some(function) = node.child_by_field_name("function")
        {
            let function_text = parsed.text_for(function).unwrap_or_default();
            if let Some(mutation) = prisma_mutation_from_call(parsed, node, function_text) {
                mutations.push(mutation);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    mutations
}

fn prisma_mutation_from_call(
    parsed: &ParsedFile,
    call: Node<'_>,
    function_text: &str,
) -> Option<Mutation> {
    let parts = function_text.split('.').collect::<Vec<_>>();
    if parts.len() < 2 || parts.first().copied() != Some("prisma") {
        return None;
    }
    let method = parts.last().copied().unwrap_or_default();
    if matches!(method, "$executeRaw" | "$executeRawUnsafe" | "$queryRaw") {
        if method == "$queryRaw" && !call_has_mutating_sql(parsed, call) {
            return None;
        }
        return Some(raw_or_unknown_mutation(
            MutationOperation::RawSqlMutation,
            "prisma",
            raw_sql_resource(parsed, call),
            parsed.span_for(call),
            "raw_sql",
            "Prisma raw SQL mutation requires review",
        ));
    }

    if parts.len() < 3 {
        return None;
    }
    let resource = parts
        .get(parts.len() - 2)
        .copied()
        .filter(|item| !item.is_empty());
    let operation = match method {
        "create" | "createMany" => MutationOperation::Create,
        "update" => MutationOperation::Update,
        "updateMany" => MutationOperation::BulkUpdate,
        "delete" | "deleteMany" => MutationOperation::Delete,
        "upsert" => MutationOperation::UnknownMutation,
        _ => return None,
    };
    let confidence = if operation == MutationOperation::UnknownMutation {
        Confidence::Low
    } else {
        Confidence::High
    };
    let extensions = if operation == MutationOperation::UnknownMutation {
        review_required_extension(
            "unknown_operation",
            "Prisma upsert may create or update data and requires review",
        )
    } else {
        authmap_core::ExtensionMap::new()
    };
    Some(Mutation {
        id: String::new(),
        operation,
        library: Some("prisma".to_string()),
        resource: resource.map(str::to_string),
        span: Some(parsed.span_for(call)),
        confidence,
        notes: if operation == MutationOperation::UnknownMutation {
            vec!["Prisma upsert has create-or-update semantics; review required".to_string()]
        } else {
            Vec::new()
        },
        extensions,
    })
}

fn extract_python_mutations(parsed: &ParsedFile, root: Node<'_>) -> Vec<Mutation> {
    let mut mutations = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            mutations.extend(extract_python_function_mutations(parsed, node));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    mutations
}

fn python_may_contain_mutation(parsed: &ParsedFile) -> bool {
    python_text_may_contain_mutation(parsed.text.as_str())
}

fn python_text_may_contain_mutation(text: &str) -> bool {
    [
        ".save(",
        ".delete(",
        ".update(",
        ".create(",
        ".bulk_create(",
        ".bulk_update(",
        ".get_or_create(",
        ".update_or_create(",
        ".add(",
        ".merge(",
        ".execute(",
        ".objects.",
        "session.",
        "insert(",
        "update(",
        "delete(",
        "raw(",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn extract_python_function_mutations(parsed: &ParsedFile, function: Node<'_>) -> Vec<Mutation> {
    let mut mutations = Vec::new();
    let function_text = parsed.text_for(function).unwrap_or_default();
    if !python_text_may_contain_mutation(function_text) {
        return mutations;
    }
    let mut model_by_var = BTreeMap::<String, String>::new();
    let session_symbols = collect_python_session_symbols(parsed, function);
    collect_python_model_bindings(parsed, function, &session_symbols, &mut model_by_var);

    let mut stack = vec![function];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "call" => {
                if let Some(mutation) =
                    python_call_mutation(parsed, node, &model_by_var, &session_symbols)
                {
                    mutations.push(mutation);
                }
            }
            "assignment" => {
                if let Some(mutation) = sqlalchemy_assignment_mutation(parsed, node, &model_by_var)
                {
                    mutations.push(mutation);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    mutations
}

fn collect_python_model_bindings(
    parsed: &ParsedFile,
    function: Node<'_>,
    session_symbols: &BTreeSet<String>,
    model_by_var: &mut BTreeMap<String, String>,
) {
    let mut stack = vec![function];
    while let Some(node) = stack.pop() {
        if node.kind() == "assignment"
            && let Some((left, right)) = assignment_sides(parsed, node)
            && let Some(model) = python_model_binding_from_expression(&right, session_symbols)
        {
            model_by_var.insert(left, model);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
}

fn collect_python_session_symbols(parsed: &ParsedFile, function: Node<'_>) -> BTreeSet<String> {
    let mut symbols = BTreeSet::new();
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return symbols;
    };
    let Some(parameters_text) = parsed.text_for(parameters) else {
        return symbols;
    };

    for parameter in parameters_text
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(',')
    {
        let parameter = parameter.trim();
        let before_default = parameter
            .split_once('=')
            .map_or(parameter, |(left, _)| left);
        let Some((name, annotation)) = before_default.split_once(':') else {
            continue;
        };
        if annotation
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .any(|part| matches!(part, "Session" | "AsyncSession"))
        {
            let symbol = clean_symbol(name.trim_start_matches('*'));
            if !symbol.is_empty() {
                symbols.insert(symbol);
            }
        }
    }
    symbols
}

fn python_model_binding_from_expression(
    text: &str,
    session_symbols: &BTreeSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if let Some((receiver, rest)) = trimmed.split_once(".get(")
        && is_sqlalchemy_session_receiver(&terminal_symbol_name(receiver), session_symbols)
        && let Some(args) = rest.split_once(')').map(|(args, _)| args)
    {
        return args
            .split(',')
            .next()
            .map(clean_symbol)
            .filter(|item| !item.is_empty())
            .map(|model| format!("sqlalchemy:{model}"));
    }
    if let Some((model, _)) = trimmed.split_once(".objects.get(") {
        return Some(format!("django_orm:{}", clean_symbol(model)));
    }
    if let Some((model, _)) = trimmed.split_once(".objects.filter(") {
        return Some(format!("django_orm:{}", clean_symbol(model)));
    }
    trimmed
        .split_once('(')
        .map(|(name, _)| clean_symbol(name))
        .filter(|name| looks_like_model_name(name))
        .map(|model| format!("model:{model}"))
}

fn binding_model(binding: &str) -> String {
    binding
        .split_once(':')
        .map_or(binding, |(_, model)| model)
        .to_string()
}

fn binding_library(binding: &str) -> Option<&str> {
    binding.split_once(':').map(|(library, _)| library)
}

fn python_call_mutation(
    parsed: &ParsedFile,
    call: Node<'_>,
    model_by_var: &BTreeMap<String, String>,
    session_symbols: &BTreeSet<String>,
) -> Option<Mutation> {
    let function = call.child_by_field_name("function")?;
    let function_text = parsed.text_for(function).unwrap_or_default();

    if let Some(mutation) = django_call_mutation(parsed, call, function_text, model_by_var) {
        return Some(mutation);
    }
    sqlalchemy_call_mutation(parsed, call, function_text, model_by_var, session_symbols)
}

fn sqlalchemy_call_mutation(
    parsed: &ParsedFile,
    call: Node<'_>,
    function_text: &str,
    model_by_var: &BTreeMap<String, String>,
    session_symbols: &BTreeSet<String>,
) -> Option<Mutation> {
    let receiver = receiver_symbol(function_text)?;
    match function_text {
        text if text.ends_with(".add")
            && is_sqlalchemy_session_receiver(&receiver, session_symbols) =>
        {
            let resource = call_argument_nodes(call)
                .first()
                .and_then(|arg| parsed.text_for(*arg))
                .and_then(|text| {
                    model_by_var
                        .get(text.trim())
                        .map(|binding| binding_model(binding))
                        .or_else(|| {
                            python_model_binding_from_expression(text, session_symbols)
                                .map(|binding| binding_model(&binding))
                        })
                });
            let confidence = if resource.is_some() {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            Some(orm_mutation(
                MutationOperation::Create,
                "sqlalchemy",
                resource,
                parsed.span_for(call),
                confidence,
            ))
        }
        text if text.ends_with(".add_all")
            && is_sqlalchemy_session_receiver(&receiver, session_symbols) =>
        {
            Some(orm_mutation(
                MutationOperation::Create,
                "sqlalchemy",
                None,
                parsed.span_for(call),
                Confidence::Low,
            ))
        }
        text if text.ends_with(".delete")
            && is_sqlalchemy_session_receiver(&receiver, session_symbols) =>
        {
            let resource = call_argument_nodes(call)
                .first()
                .and_then(|arg| parsed.text_for(*arg))
                .and_then(|text| {
                    model_by_var
                        .get(text.trim())
                        .map(|binding| binding_model(binding))
                });
            Some(orm_mutation(
                MutationOperation::Delete,
                "sqlalchemy",
                resource,
                parsed.span_for(call),
                Confidence::Medium,
            ))
        }
        text if text.ends_with(".merge")
            && is_sqlalchemy_session_receiver(&receiver, session_symbols) =>
        {
            // session.merge() is an upsert (INSERT or UPDATE).
            let resource = call_argument_nodes(call)
                .first()
                .and_then(|arg| parsed.text_for(*arg))
                .and_then(|text| {
                    model_by_var
                        .get(text.trim())
                        .map(|binding| binding_model(binding))
                });
            Some(orm_mutation(
                MutationOperation::Update,
                "sqlalchemy",
                resource,
                parsed.span_for(call),
                Confidence::Medium,
            ))
        }
        text if text.ends_with(".execute")
            && is_sqlalchemy_session_receiver(&receiver, session_symbols) =>
        {
            sqlalchemy_execute_mutation(parsed, call)
        }
        _ => None,
    }
}

fn receiver_symbol(function_text: &str) -> Option<String> {
    function_text
        .rsplit_once('.')
        .map(|(receiver, _)| terminal_symbol_name(receiver))
        .filter(|receiver| !receiver.is_empty())
}

fn is_sqlalchemy_session_receiver(receiver: &str, session_symbols: &BTreeSet<String>) -> bool {
    if session_symbols.contains(receiver) {
        return true;
    }
    let lower = receiver.to_ascii_lowercase();
    matches!(lower.as_str(), "session" | "db" | "db_session")
        || lower.ends_with("session")
        || lower.contains("_session")
}

fn sqlalchemy_execute_mutation(parsed: &ParsedFile, call: Node<'_>) -> Option<Mutation> {
    let first_arg = call_argument_nodes(call).into_iter().next()?;
    let arg_text = parsed.text_for(first_arg).unwrap_or_default().trim();
    if let Some(resource) = call_resource(arg_text, "insert") {
        return Some(orm_mutation(
            MutationOperation::Create,
            "sqlalchemy",
            Some(resource),
            parsed.span_for(call),
            Confidence::High,
        ));
    }
    if let Some(resource) = call_resource(arg_text, "update") {
        return Some(orm_mutation(
            MutationOperation::Update,
            "sqlalchemy",
            Some(resource),
            parsed.span_for(call),
            Confidence::High,
        ));
    }
    if let Some(resource) = call_resource(arg_text, "delete") {
        return Some(orm_mutation(
            MutationOperation::Delete,
            "sqlalchemy",
            Some(resource),
            parsed.span_for(call),
            Confidence::High,
        ));
    }
    if arg_text.starts_with("text(") && raw_sql_is_mutating(arg_text) {
        return Some(raw_or_unknown_mutation(
            MutationOperation::RawSqlMutation,
            "sqlalchemy",
            raw_sql_resource_from_text(arg_text),
            parsed.span_for(call),
            "raw_sql",
            "SQLAlchemy raw SQL mutation requires review",
        ));
    }
    None
}

fn sqlalchemy_assignment_mutation(
    parsed: &ParsedFile,
    assignment: Node<'_>,
    model_by_var: &BTreeMap<String, String>,
) -> Option<Mutation> {
    let (left, _right) = assignment_sides(parsed, assignment)?;
    let (var, field) = left.split_once('.')?;
    let binding = model_by_var.get(var.trim())?;
    if binding_library(binding) != Some("sqlalchemy") {
        return None;
    }
    let model = binding_model(binding);
    Some(orm_mutation(
        MutationOperation::Update,
        "sqlalchemy",
        Some(format!("{}.{}", model, field.trim())),
        parsed.span_for(assignment),
        Confidence::Medium,
    ))
}

fn django_call_mutation(
    parsed: &ParsedFile,
    call: Node<'_>,
    function_text: &str,
    model_by_var: &BTreeMap<String, String>,
) -> Option<Mutation> {
    if let Some((model, method)) = django_objects_call(function_text) {
        let operation = match method {
            "create" | "get_or_create" | "update_or_create" | "bulk_create" => {
                MutationOperation::Create
            }
            "update" => MutationOperation::BulkUpdate,
            "bulk_update" => MutationOperation::BulkUpdate,
            "delete" => MutationOperation::Delete,
            _ => return None,
        };
        return Some(orm_mutation(
            operation,
            "django_orm",
            Some(model),
            parsed.span_for(call),
            Confidence::High,
        ));
    }
    if function_text.ends_with(".save") || function_text.ends_with(".delete") {
        let Some((var, method)) = function_text.rsplit_once('.') else {
            return None;
        };
        let binding = model_by_var.get(var.trim())?;
        if binding_library(binding) != Some("django_orm") {
            return None;
        }
        let model = binding_model(binding);
        let operation = if method == "save" {
            MutationOperation::Save
        } else {
            MutationOperation::Delete
        };
        return Some(orm_mutation(
            operation,
            "django_orm",
            Some(model),
            parsed.span_for(call),
            Confidence::Medium,
        ));
    }
    None
}

fn django_objects_call(function_text: &str) -> Option<(String, &str)> {
    let (model, rest) = function_text.split_once(".objects.")?;
    let method = function_text.rsplit('.').next()?;
    if matches!(
        method,
        "create"
            | "update"
            | "bulk_update"
            | "delete"
            | "get_or_create"
            | "update_or_create"
            | "bulk_create"
    ) && (rest.starts_with(method) || rest.contains(&format!(".{method}")))
    {
        return Some((clean_symbol(model), method));
    }
    None
}

fn assignment_sides(parsed: &ParsedFile, assignment: Node<'_>) -> Option<(String, String)> {
    let left = assignment
        .child_by_field_name("left")
        .or_else(|| assignment.child_by_field_name("target"))
        .and_then(|node| parsed.text_for(node))
        .map(str::trim)
        .map(str::to_string);
    let right = assignment
        .child_by_field_name("right")
        .and_then(|node| parsed.text_for(node))
        .map(str::trim)
        .map(str::to_string);
    left.zip(right).or_else(|| {
        let text = parsed.text_for(assignment)?;
        let (left, right) = text.split_once('=')?;
        Some((left.trim().to_string(), right.trim().to_string()))
    })
}

fn call_resource(text: &str, function_name: &str) -> Option<String> {
    let prefix = format!("{function_name}(");
    text.strip_prefix(&prefix)
        .and_then(|value| value.split_once(')').map(|(args, _)| args))
        .map(|args| args.split(',').next().unwrap_or(args))
        .map(clean_symbol)
        .filter(|item| !item.is_empty())
}

fn call_has_mutating_sql(parsed: &ParsedFile, call: Node<'_>) -> bool {
    let call_text = parsed.text_for(call).unwrap_or_default();
    raw_sql_is_mutating(call_text)
}

fn raw_sql_resource(parsed: &ParsedFile, call: Node<'_>) -> Option<String> {
    parsed.text_for(call).and_then(raw_sql_resource_from_text)
}

fn raw_sql_is_mutating(text: &str) -> bool {
    static MUTATING_SQL: &[&str] = &[
        "insert", "update", "delete", "merge", "truncate", "drop", "alter",
    ];
    let Some(sql) = first_static_string_like(text) else {
        return false;
    };
    let trimmed = sql.trim_start().to_ascii_lowercase();
    MUTATING_SQL
        .iter()
        .any(|keyword| trimmed.starts_with(keyword))
}

fn raw_sql_resource_from_text(text: &str) -> Option<String> {
    let sql = first_static_string_like(text)?;
    let words = sql
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | ';' | '(' | ')'))
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let first = words.first()?.to_ascii_lowercase();
    match first.as_str() {
        "insert" => words
            .windows(2)
            .find(|pair| pair[0].eq_ignore_ascii_case("into"))
            .map(|pair| pair[1].to_string()),
        "update" | "delete" | "truncate" | "drop" | "alter" => words.get(1).map(|item| {
            if item.eq_ignore_ascii_case("from") || item.eq_ignore_ascii_case("table") {
                words.get(2).copied().unwrap_or(*item).to_string()
            } else {
                (*item).to_string()
            }
        }),
        "merge" => words
            .windows(2)
            .find(|pair| pair[0].eq_ignore_ascii_case("into"))
            .map(|pair| pair[1].to_string()),
        _ => None,
    }
}

fn first_static_string_like(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for (index, ch) in text.char_indices() {
        if matches!(ch, '"' | '\'' | '`') {
            let previous = text[..index]
                .chars()
                .rev()
                .take_while(|item| item.is_ascii_alphabetic())
                .collect::<String>();
            if matches!(
                previous.chars().rev().collect::<String>().as_str(),
                "f" | "format"
            ) {
                continue;
            }
            let mut end = index + ch.len_utf8();
            while end < text.len() {
                let current = bytes[end] as char;
                if current == ch && bytes.get(end.wrapping_sub(1)).copied() != Some(b'\\') {
                    return Some(text[index + ch.len_utf8()..end].to_string());
                }
                end += current.len_utf8();
            }
        }
    }
    None
}

fn orm_mutation(
    operation: MutationOperation,
    library: &str,
    resource: Option<String>,
    span: Span,
    confidence: Confidence,
) -> Mutation {
    Mutation {
        id: String::new(),
        operation,
        library: Some(library.to_string()),
        resource,
        span: Some(span),
        confidence,
        notes: Vec::new(),
        extensions: authmap_core::ExtensionMap::new(),
    }
}

fn raw_or_unknown_mutation(
    operation: MutationOperation,
    library: &str,
    resource: Option<String>,
    span: Span,
    detection: &str,
    note: &str,
) -> Mutation {
    Mutation {
        id: String::new(),
        operation,
        library: Some(library.to_string()),
        resource,
        span: Some(span),
        confidence: Confidence::Low,
        notes: vec![note.to_string()],
        extensions: review_required_extension(detection, note),
    }
}

fn review_required_extension(detection: &str, reason: &str) -> authmap_core::ExtensionMap {
    let mut extensions = authmap_core::ExtensionMap::new();
    extensions.insert(
        "authmap.mutation".to_string(),
        serde_json::json!({
            "review_required": true,
            "uncertainty_reasons": [reason],
            "detection": detection,
        }),
    );
    extensions
}

fn dedup_mutations(mutations: &mut Vec<Mutation>) {
    let mut seen = BTreeSet::new();
    mutations.retain(|item| {
        seen.insert((
            item.operation,
            item.library.clone(),
            item.resource.clone(),
            item.span
                .as_ref()
                .map(|span| (span.file.clone(), span.line, span.column)),
        ))
    });
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

fn clean_symbol(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ' ' | '\n' | '\r' | '\t'))
        .rsplit('.')
        .next()
        .unwrap_or(value)
        .trim()
        .to_string()
}

fn looks_like_model_name(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
}

#[derive(Clone, Debug)]
struct ReachabilityIndex<'a> {
    functions: BTreeMap<(String, String), FunctionDef<'a>>,
    class_methods: BTreeMap<(String, String, String), FunctionDef<'a>>,
    imports: BTreeMap<(String, String), ImportTarget>,
    default_exports: BTreeMap<String, String>,
    parsed_by_file: BTreeMap<String, &'a ParsedFile>,
}

#[derive(Clone, Debug)]
struct FunctionDef<'a> {
    file: String,
    name: String,
    node: Node<'a>,
}

#[derive(Clone, Debug)]
struct ImportTarget {
    file: String,
    name: Option<String>,
}

#[derive(Clone, Debug)]
struct ResolvedFunction<'a> {
    def: FunctionDef<'a>,
    confidence: Confidence,
}

impl<'a> ReachabilityIndex<'a> {
    fn new(parsed_files: &'a [ParsedFile]) -> Self {
        let python_modules = build_python_module_index(parsed_files);
        let js_modules = build_js_module_index(parsed_files);
        let mut index = Self {
            functions: BTreeMap::new(),
            class_methods: BTreeMap::new(),
            imports: BTreeMap::new(),
            default_exports: BTreeMap::new(),
            parsed_by_file: parsed_files
                .iter()
                .map(|parsed| (parsed.source.path.clone(), parsed))
                .collect(),
        };

        for parsed in parsed_files {
            if let Some(root) = parsed.root_node() {
                collect_function_defs(parsed, root, &mut index.functions);
                collect_class_method_defs(parsed, root, &mut index.class_methods);
            }
            match parsed.language {
                authmap_core::Language::Python => {
                    collect_python_imports(parsed, &python_modules, &mut index.imports);
                }
                authmap_core::Language::JavaScript
                | authmap_core::Language::JavaScriptReact
                | authmap_core::Language::TypeScript
                | authmap_core::Language::TypeScriptReact => {
                    collect_js_imports(parsed, &js_modules, &mut index.imports);
                    collect_js_default_exports(parsed, &mut index.default_exports);
                }
                authmap_core::Language::Unknown => {}
            }
        }

        index
    }

    fn resolve_call(&self, source_file: &str, function_text: &str) -> Option<ResolvedFunction<'a>> {
        let trimmed = function_text.trim();
        if let Some((object, member)) = trimmed.rsplit_once('.') {
            let object = clean_symbol(object);
            if let Some(target) = self.imports.get(&(source_file.to_string(), object)) {
                let name = target.name.clone().unwrap_or_else(|| clean_symbol(member));
                return self
                    .functions
                    .get(&(target.file.clone(), name))
                    .cloned()
                    .map(|def| ResolvedFunction {
                        def,
                        confidence: Confidence::Medium,
                    });
            }
        }

        let name = terminal_symbol_name(trimmed);
        if let Some(def) = self
            .functions
            .get(&(source_file.to_string(), name.clone()))
            .cloned()
        {
            return Some(ResolvedFunction {
                def,
                confidence: Confidence::High,
            });
        }
        if let Some(target) = self.imports.get(&(source_file.to_string(), name)) {
            let target_name = target
                .name
                .clone()
                .or_else(|| self.default_exports.get(&target.file).cloned())?;
            return self
                .functions
                .get(&(target.file.clone(), target_name))
                .cloned()
                .map(|def| ResolvedFunction {
                    def,
                    confidence: Confidence::Medium,
                });
        }
        None
    }

    fn resolve_call_with_receiver_types(
        &self,
        source_file: &str,
        function_text: &str,
        receiver_types: &BTreeMap<String, String>,
    ) -> Option<ResolvedFunction<'a>> {
        let trimmed = function_text.trim();
        let (receiver, method) = trimmed.rsplit_once('.')?;
        let receiver = clean_symbol(receiver);
        let class_name = receiver_types.get(&receiver)?;
        let target = self
            .imports
            .get(&(source_file.to_string(), class_name.clone()))?;
        self.class_methods
            .get(&(
                target.file.clone(),
                target.name.clone().unwrap_or_else(|| class_name.clone()),
                clean_symbol(method),
            ))
            .cloned()
            .map(|def| ResolvedFunction {
                def,
                confidence: Confidence::Medium,
            })
    }
}

fn link_route_handler_mutations(
    route: &authmap_core::Route,
    parsed: &ParsedFile,
    handler_node: Node<'_>,
    mutations: &[Mutation],
    index: &ReachabilityIndex<'_>,
) -> Vec<ReachabilityLink> {
    let mut links = Vec::new();
    for mutation in mutations.iter().filter(|mutation| {
        mutation_inside_node_excluding_nested_scopes(
            parsed,
            &parsed.source.path,
            handler_node,
            mutation,
        )
    }) {
        links.push(reachability_link(
            route,
            Some(mutation),
            Confidence::High,
            vec!["Mutation is directly inside route handler".to_string()],
            authmap_core::ExtensionMap::new(),
        ));
    }

    for call in service_call_candidates(parsed, handler_node) {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        let function_text = parsed.text_for(function).unwrap_or_default();
        if should_skip_reachability_call(function_text) {
            continue;
        }
        if let Some(resolved) = index.resolve_call(&parsed.source.path, function_text) {
            let resolved_parsed = index
                .parsed_by_file
                .get(&resolved.def.file)
                .copied()
                .unwrap_or(parsed);
            for mutation in mutations.iter().filter(|mutation| {
                mutation_inside_node_excluding_nested_scopes(
                    resolved_parsed,
                    &resolved.def.file,
                    resolved.def.node,
                    mutation,
                )
            }) {
                let note = if resolved.confidence == Confidence::High {
                    format!(
                        "One-hop same-file service call `{}` reaches mutation",
                        terminal_symbol_name(function_text)
                    )
                } else {
                    format!(
                        "One-hop imported service call `{}` reaches `{}`",
                        terminal_symbol_name(function_text),
                        resolved.def.name
                    )
                };
                links.push(reachability_link(
                    route,
                    Some(mutation),
                    resolved.confidence,
                    vec![note],
                    authmap_core::ExtensionMap::new(),
                ));
            }
        } else if service_like_call(function_text) {
            let call_span = parsed.span_for(call);
            links.push(reachability_link(
                route,
                None,
                Confidence::Low,
                vec![format!(
                    "Service-like call `{}` could not be resolved statically",
                    function_text.trim()
                )],
                reachability_uncertainty_extension(
                    function_text.trim(),
                    &call_span,
                    "unresolved_service_call",
                ),
            ));
        }
    }
    links
}

fn reachability_link(
    route: &authmap_core::Route,
    mutation: Option<&Mutation>,
    confidence: Confidence,
    notes: Vec<String>,
    extensions: authmap_core::ExtensionMap,
) -> ReachabilityLink {
    ReachabilityLink {
        id: String::new(),
        route_id: route.id.clone(),
        mutation_id: mutation.map(|mutation| mutation.id.clone()),
        evidence_id: None,
        confidence,
        notes,
        extensions,
    }
}

fn reachability_uncertainty_extension(
    call_target: &str,
    call_span: &Span,
    reason: &str,
) -> authmap_core::ExtensionMap {
    let mut extensions = authmap_core::ExtensionMap::new();
    extensions.insert(
        "authmap.reachability".to_string(),
        serde_json::json!({
            "call_target": call_target,
            "call_span": call_span,
            "reason": reason,
        }),
    );
    extensions
}

fn service_call_candidates<'tree>(parsed: &ParsedFile, node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut calls = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "call" | "call_expression") {
            calls.push(current);
        }
        let mut cursor = current.walk();
        stack.extend(
            current
                .children(&mut cursor)
                .filter(|child| !is_nested_scope_node(*child)),
        );
    }
    calls
        .into_iter()
        .filter(|call| {
            call.child_by_field_name("function")
                .and_then(|function| parsed.text_for(function))
                .is_some_and(|function_text| !should_skip_reachability_call(function_text))
        })
        .collect()
}

fn should_skip_reachability_call(function_text: &str) -> bool {
    let trimmed = function_text.trim();
    let terminal = terminal_symbol_name(trimmed);
    let lower = terminal.to_ascii_lowercase();
    if is_framework_route_call(trimmed) || is_fastapi_depends(trimmed) {
        return true;
    }
    if looks_orm_call(trimmed) || looks_response_or_builtin_call(trimmed, &lower) {
        return true;
    }
    if looks_guard_like(&lower) || looks_dynamic_policy(trimmed) {
        return true;
    }
    false
}

fn looks_orm_call(function_text: &str) -> bool {
    let lower = function_text.to_ascii_lowercase();
    lower.starts_with("prisma.")
        || lower.contains(".objects.")
        || lower.starts_with("session.")
        || (function_text.contains('.')
            && matches!(
                terminal_symbol_name(function_text).as_str(),
                "update" | "delete" | "text"
            ))
}

fn looks_response_or_builtin_call(function_text: &str, terminal_lower: &str) -> bool {
    let lower = function_text.to_ascii_lowercase();
    lower.starts_with("res.")
        || lower.starts_with("req.")
        || lower.starts_with("request.")
        || lower.starts_with("response.")
        || matches!(
            terminal_lower,
            "json"
                | "send"
                | "sendstatus"
                | "status"
                | "commit"
                | "rollback"
                | "map"
                | "filter"
                | "includes"
                | "get"
                | "set"
                | "str"
                | "len"
                | "dict"
                | "list"
                | "print"
                | "date"
        )
}

fn service_like_call(function_text: &str) -> bool {
    let terminal = terminal_symbol_name(function_text);
    let lower = terminal.to_ascii_lowercase();
    let full_lower = function_text.to_ascii_lowercase();
    lower.starts_with("create")
        || lower.starts_with("update")
        || lower.starts_with("delete")
        || lower.starts_with("disable")
        || lower.starts_with("enable")
        || lower.starts_with("save")
        || lower.starts_with("remove")
        || lower.starts_with("archive")
        || lower.starts_with("grant")
        || lower.starts_with("revoke")
        || lower.starts_with("sync")
        || lower.starts_with("upsert")
        || full_lower.contains("service")
        || full_lower.contains("repository")
        || full_lower.contains("repo.")
        || full_lower.contains("client.")
}

fn mutation_inside_node(file: &str, node: Node<'_>, mutation: &Mutation) -> bool {
    let Some(span) = mutation.span.as_ref() else {
        return false;
    };
    if span.file != file {
        return false;
    }
    span.byte_range.as_ref().is_some_and(|range| {
        range.start >= node.start_byte() as u64 && range.end <= node.end_byte() as u64
    })
}

fn mutation_inside_node_excluding_nested_scopes(
    parsed: &ParsedFile,
    file: &str,
    node: Node<'_>,
    mutation: &Mutation,
) -> bool {
    if !mutation_inside_node(file, node, mutation) {
        return false;
    }
    mutation
        .span
        .as_ref()
        .is_none_or(|span| !span_is_inside_nested_scope(parsed, node, span))
}

fn span_is_inside_nested_scope(parsed: &ParsedFile, root: Node<'_>, span: &Span) -> bool {
    let Some(range) = span.byte_range.as_ref() else {
        return false;
    };
    let mut stack = Vec::new();
    let mut cursor = root.walk();
    stack.extend(root.children(&mut cursor));
    while let Some(current) = stack.pop() {
        if is_nested_scope_node(current)
            && range.start >= current.start_byte() as u64
            && range.end <= current.end_byte() as u64
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    let _ = parsed;
    false
}

fn is_nested_scope_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition"
            | "class_definition"
            | "lambda"
            | "function_declaration"
            | "method_definition"
            | "arrow_function"
            | "function"
            | "function_expression"
            | "class"
            | "class_declaration"
    )
}

fn collect_function_defs<'tree>(
    parsed: &'tree ParsedFile,
    root: Node<'tree>,
    functions: &mut BTreeMap<(String, String), FunctionDef<'tree>>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let name = match node.kind() {
            "function_definition" | "function_declaration" => function_name(parsed, node),
            "variable_declarator" => variable_function_name(parsed, node),
            _ => None,
        };
        if let Some(name) = name {
            functions.insert(
                (parsed.source.path.clone(), name.clone()),
                FunctionDef {
                    file: parsed.source.path.clone(),
                    name,
                    node,
                },
            );
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
}

fn collect_class_method_defs<'tree>(
    parsed: &'tree ParsedFile,
    root: Node<'tree>,
    methods: &mut BTreeMap<(String, String, String), FunctionDef<'tree>>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "class_definition"
            && let Some(class_name) = function_name(parsed, node)
        {
            for method in direct_class_methods(node) {
                if let Some(method_name) = function_name(parsed, method) {
                    methods.insert(
                        (
                            parsed.source.path.clone(),
                            class_name.clone(),
                            method_name.clone(),
                        ),
                        FunctionDef {
                            file: parsed.source.path.clone(),
                            name: method_name,
                            node: method,
                        },
                    );
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
}

fn direct_class_methods(class_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = class_node.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut methods = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor).filter(|child| child.is_named()) {
        if child.kind() == "function_definition" {
            methods.push(child);
        } else if child.kind() == "decorated_definition"
            && let Some(function) = find_direct_child_kind(child, "function_definition")
        {
            methods.push(function);
        }
    }
    methods
}

fn build_python_module_index(parsed_files: &[ParsedFile]) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for parsed in parsed_files
        .iter()
        .filter(|parsed| parsed.language == authmap_core::Language::Python)
    {
        let normalized = parsed.source.path.replace('\\', "/");
        if let Some(stem) = normalized.strip_suffix(".py") {
            let module_stem = stem.strip_suffix("/__init__").unwrap_or(stem);
            index.insert(module_stem.to_string(), parsed.source.path.clone());
            index.insert(module_stem.replace('/', "."), parsed.source.path.clone());
            if let Some((_, file_stem)) = module_stem.rsplit_once('/') {
                index.insert(file_stem.to_string(), parsed.source.path.clone());
            }
        }
    }
    index
}

fn collect_python_imports(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    imports: &mut BTreeMap<(String, String), ImportTarget>,
) {
    for line in parsed.text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("from ") else {
            continue;
        };
        let Some((module, imported)) = rest.split_once(" import ") else {
            continue;
        };
        let Some(module_file) = resolve_python_module(parsed, module_index, module.trim()) else {
            continue;
        };
        for part in imported.split(',') {
            let part = part.trim();
            if part.is_empty() || part == "*" {
                continue;
            }
            let (export_name, local_name) = part
                .split_once(" as ")
                .map_or((part, part), |(export_name, local_name)| {
                    (export_name.trim(), local_name.trim())
                });
            if let Some(imported_module_file) = resolve_python_module(
                parsed,
                module_index,
                &python_imported_module(module, export_name),
            ) {
                imports.insert(
                    (parsed.source.path.clone(), local_name.to_string()),
                    ImportTarget {
                        file: imported_module_file,
                        name: None,
                    },
                );
                continue;
            }
            imports.insert(
                (parsed.source.path.clone(), local_name.to_string()),
                ImportTarget {
                    file: module_file.clone(),
                    name: Some(export_name.to_string()),
                },
            );
        }
    }
}

fn python_imported_module(module: &str, export_name: &str) -> String {
    let module = module.trim();
    let export_name = export_name.trim();
    if module.chars().all(|ch| ch == '.') {
        format!("{module}{export_name}")
    } else {
        format!("{module}.{export_name}")
    }
}

fn resolve_python_module(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    module: &str,
) -> Option<String> {
    let normalized = parsed.source.path.replace('\\', "/");
    let current_dir = normalized.rsplit_once('/').map_or("", |(dir, _)| dir);
    if module.starts_with('.') {
        let is_absolute = current_dir.starts_with('/');
        let dots = module.chars().take_while(|ch| *ch == '.').count();
        let remainder = module.trim_start_matches('.');
        let mut parts = current_dir
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        for _ in 1..dots {
            parts.pop();
        }
        if !remainder.is_empty() {
            parts.extend(remainder.split('.').map(str::to_string));
        }
        let joined = parts.join("/");
        let key = if is_absolute {
            format!("/{joined}")
        } else {
            joined
        };
        return module_index.get(&key).cloned();
    }

    let candidate = module.replace('.', "/");
    module_index.get(&candidate).cloned().or_else(|| {
        module_index
            .iter()
            .find(|(key, _)| key.ends_with(&format!("/{candidate}")) || *key == &candidate)
            .map(|(_, path)| path.clone())
    })
}

fn build_js_module_index(parsed_files: &[ParsedFile]) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for parsed in parsed_files.iter().filter(|file| {
        matches!(
            file.language,
            authmap_core::Language::JavaScript
                | authmap_core::Language::JavaScriptReact
                | authmap_core::Language::TypeScript
                | authmap_core::Language::TypeScriptReact
        )
    }) {
        let normalized = parsed.source.path.replace('\\', "/");
        if let Some(stem) = strip_js_extension(&normalized) {
            index.insert(stem.to_string(), parsed.source.path.clone());
            if let Some(index_stem) = stem.strip_suffix("/index") {
                index.insert(index_stem.to_string(), parsed.source.path.clone());
            }
        }
    }
    index
}

fn collect_js_imports(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    imports: &mut BTreeMap<(String, String), ImportTarget>,
) {
    for line in parsed.text.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        collect_js_es_import(parsed, module_index, imports, trimmed);
        collect_js_require_import(parsed, module_index, imports, trimmed);
    }
}

fn collect_js_default_exports(parsed: &ParsedFile, default_exports: &mut BTreeMap<String, String>) {
    for line in parsed.text.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        if let Some(rest) = trimmed.strip_prefix("export default ") {
            let rest = rest.trim_start_matches("async ").trim();
            if let Some(name) = rest
                .strip_prefix("function ")
                .and_then(|value| value.split_once('(').map(|(name, _)| name.trim()))
                .filter(|name| !name.is_empty())
            {
                default_exports.insert(parsed.source.path.clone(), name.to_string());
                return;
            }
            let name = clean_symbol(rest);
            if !name.is_empty() {
                default_exports.insert(parsed.source.path.clone(), name);
                return;
            }
        }
        if let Some(name) = trimmed
            .strip_prefix("module.exports = ")
            .map(clean_symbol)
            .filter(|name| !name.is_empty())
        {
            default_exports.insert(parsed.source.path.clone(), name);
            return;
        }
    }
}

fn collect_js_es_import(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    imports: &mut BTreeMap<(String, String), ImportTarget>,
    line: &str,
) {
    let Some(rest) = line.strip_prefix("import ") else {
        return;
    };
    let Some((specifiers, module_part)) = rest.split_once(" from ") else {
        return;
    };
    let Some(module_file) = resolve_js_module(parsed, module_index, module_part.trim()) else {
        return;
    };
    let specifiers = specifiers.trim();
    if specifiers.starts_with('{') && specifiers.ends_with('}') {
        for part in specifiers[1..specifiers.len() - 1].split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (export_name, local_name) = part
                .split_once(" as ")
                .map_or((part, part), |(export_name, local_name)| {
                    (export_name.trim(), local_name.trim())
                });
            imports.insert(
                (parsed.source.path.clone(), local_name.to_string()),
                ImportTarget {
                    file: module_file.clone(),
                    name: Some(export_name.to_string()),
                },
            );
        }
    } else if let Some(local_name) = specifiers.strip_prefix("* as ") {
        imports.insert(
            (parsed.source.path.clone(), local_name.trim().to_string()),
            ImportTarget {
                file: module_file,
                name: None,
            },
        );
    } else if !specifiers.is_empty() {
        imports.insert(
            (parsed.source.path.clone(), specifiers.to_string()),
            ImportTarget {
                file: module_file,
                name: None,
            },
        );
    }
}

fn collect_js_require_import(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    imports: &mut BTreeMap<(String, String), ImportTarget>,
    line: &str,
) {
    let Some((left, right)) = line.split_once("require(") else {
        return;
    };
    let Some(module_literal) = right.split(')').next() else {
        return;
    };
    let Some(module_file) = resolve_js_module(parsed, module_index, module_literal.trim()) else {
        return;
    };
    let required_property = right
        .split_once(").")
        .map(|(_, property)| property.trim().to_string());
    let left = left
        .trim()
        .strip_prefix("const ")
        .or_else(|| left.trim().strip_prefix("let "))
        .or_else(|| left.trim().strip_prefix("var "));
    let Some(local) = left.and_then(|left| left.trim().strip_suffix('=')) else {
        return;
    };
    let local = local.trim();
    if local.starts_with('{') && local.ends_with('}') {
        for part in local[1..local.len() - 1].split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (export_name, local_name) = part
                .split_once(':')
                .map_or((part, part), |(export_name, local_name)| {
                    (export_name.trim(), local_name.trim())
                });
            imports.insert(
                (parsed.source.path.clone(), local_name.to_string()),
                ImportTarget {
                    file: module_file.clone(),
                    name: Some(export_name.to_string()),
                },
            );
        }
    } else {
        imports.insert(
            (parsed.source.path.clone(), local.to_string()),
            ImportTarget {
                file: module_file,
                name: required_property,
            },
        );
    }
}

fn resolve_js_module(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    module_literal: &str,
) -> Option<String> {
    let module = module_literal.trim().trim_matches('"').trim_matches('\'');
    if !module.starts_with('.') {
        return None;
    }
    let current = parsed.source.path.replace('\\', "/");
    let current_dir = current.rsplit_once('/').map_or("", |(dir, _)| dir);
    let candidate = normalize_module_path(current_dir, module, "/");
    module_index.get(&candidate).cloned()
}

fn normalize_module_path(current_dir: &str, module: &str, separator: &str) -> String {
    let is_absolute = current_dir.starts_with(separator);
    let mut parts = current_dir
        .split(separator)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for part in module.split(separator) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_string()),
        }
    }
    let joined = parts.join(separator);
    if is_absolute {
        format!("{separator}{joined}")
    } else {
        joined
    }
}

fn strip_js_extension(path: &str) -> Option<&str> {
    [".js", ".jsx", ".ts", ".tsx"]
        .iter()
        .find_map(|extension| path.strip_suffix(extension))
}

fn dedup_links(links: &mut Vec<ReachabilityLink>) {
    let mut seen = BTreeSet::new();
    links.retain(|item| {
        seen.insert((
            item.route_id.clone(),
            item.mutation_id.clone(),
            item.confidence,
            item.notes.clone(),
        ))
    });
}

fn link_sort_key(link: &ReachabilityLink) -> (String, String, Confidence, String) {
    (
        link.route_id.clone(),
        link.mutation_id.clone().unwrap_or_default(),
        link.confidence,
        link.notes.join("; "),
    )
}

fn rule_suggestion_sort_key(
    suggestion: &RuleSuggestion,
) -> (EvidenceType, String, String, u32, u32) {
    let first = suggestion.examples.first();
    (
        suggestion.evidence_type,
        suggestion
            .matcher
            .exact
            .first()
            .cloned()
            .unwrap_or_default(),
        first.map_or_else(String::new, |example| example.file.clone()),
        first.map_or(0, |example| example.line),
        first.map_or(0, |example| example.column),
    )
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

fn suggested_mechanism(evidence_type: EvidenceType) -> &'static str {
    match evidence_type {
        EvidenceType::Authn => "suggested_authn_guard",
        EvidenceType::RoleCheck => "suggested_role_guard",
        EvidenceType::PermissionCheck => "suggested_permission_guard",
        EvidenceType::OwnershipCheck => "suggested_ownership_guard",
        EvidenceType::TenantCheck => "suggested_tenant_guard",
        EvidenceType::AdminCheck => "suggested_admin_guard",
        EvidenceType::ExplicitPublic => "suggested_public_marker",
        EvidenceType::AuditLog => "suggested_audit_log",
        EvidenceType::UnknownDynamicCheck => "suggested_dynamic_policy",
    }
}

#[derive(Clone, Debug)]
struct EvidenceRuleSpec {
    evidence_type: EvidenceType,
    mechanism: String,
    confidence: Confidence,
    exact: Vec<String>,
    contains: Vec<String>,
    notes: Vec<String>,
    origin: EvidenceRuleOrigin,
}

#[derive(Clone, Debug)]
struct EvidenceRules {
    rules: Vec<EvidenceRuleSpec>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceRuleOrigin {
    BuiltIn,
    Config,
}

impl EvidenceRules {
    fn new(config: &ScanConfig) -> Self {
        let mut rules = builtin_rules();
        rules.extend(config.authorization.rules.iter().map(config_rule_to_spec));
        Self { rules }
    }

    fn match_symbol(&self, symbol: &str) -> Option<&EvidenceRuleSpec> {
        self.rules.iter().find(|rule| rule.matches(symbol))
    }
}

impl EvidenceRuleSpec {
    fn matches(&self, symbol: &str) -> bool {
        match self.origin {
            EvidenceRuleOrigin::BuiltIn => self.builtin_matches(symbol),
            EvidenceRuleOrigin::Config => {
                let symbol_lower = symbol.to_ascii_lowercase();
                self.exact.iter().any(|item| item == symbol)
                    || self
                        .contains
                        .iter()
                        .any(|item| symbol_lower.contains(&item.to_ascii_lowercase()))
            }
        }
    }

    fn builtin_matches(&self, symbol: &str) -> bool {
        let terminal = terminal_symbol_name(symbol);
        if self
            .exact
            .iter()
            .any(|item| item == symbol || item == &terminal)
        {
            return true;
        }
        let lower = terminal.to_ascii_lowercase();
        if !looks_guard_like(&lower)
            && !lower.contains("middleware")
            && !lower.contains("decorator")
            && !lower.ends_with("required")
        {
            return false;
        }
        let tokens = symbol_tokens(&terminal);
        self.contains.iter().any(|item| {
            let item_lower = item.to_ascii_lowercase();
            tokens.iter().any(|token| token == &item_lower)
        })
    }
}

fn symbol_tokens(symbol: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut previous_lowercase = false;
    for ch in symbol.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && previous_lowercase && !current.is_empty() {
                tokens.push(current.to_ascii_lowercase());
                current.clear();
            }
            previous_lowercase = ch.is_ascii_lowercase();
            current.push(ch);
        } else {
            if !current.is_empty() {
                tokens.push(current.to_ascii_lowercase());
                current.clear();
            }
            previous_lowercase = false;
        }
    }
    if !current.is_empty() {
        tokens.push(current.to_ascii_lowercase());
    }
    tokens
}

fn config_rule_to_spec(rule: &AuthorizationRule) -> EvidenceRuleSpec {
    EvidenceRuleSpec {
        evidence_type: rule.evidence_type,
        mechanism: rule.mechanism.clone(),
        confidence: rule.confidence.unwrap_or(Confidence::High),
        exact: rule.matcher.exact.clone(),
        contains: rule.matcher.contains.clone(),
        notes: rule.notes.clone(),
        origin: EvidenceRuleOrigin::Config,
    }
}

fn builtin_rules() -> Vec<EvidenceRuleSpec> {
    vec![
        rule(
            EvidenceType::ExplicitPublic,
            "public_marker",
            Confidence::High,
            &["allow_anonymous", "public_route", "publicRoute", "no_auth"],
            &["public"],
        ),
        rule(
            EvidenceType::AdminCheck,
            "admin_guard",
            Confidence::High,
            &[
                "requireAdmin",
                "require_admin",
                "admin_required",
                "is_admin",
            ],
            &["admin"],
        ),
        rule(
            EvidenceType::PermissionCheck,
            "permission_guard",
            Confidence::High,
            &[
                "requirePermission",
                "require_permission",
                "can_edit_account",
                "checkPrivileges",
                "canViewUsers",
                "canViewGroups",
                "canChat",
            ],
            &["permission", "permissions", "privilege", "privileges"],
        ),
        rule(
            EvidenceType::RoleCheck,
            "role_guard",
            Confidence::High,
            &["requireRole", "require_role", "roleGuard", "role_guard"],
            &["role"],
        ),
        rule(
            EvidenceType::TenantCheck,
            "tenant_guard",
            Confidence::High,
            &[
                "requireTenant",
                "require_tenant",
                "tenantGuard",
                "tenant_guard",
            ],
            &["tenant"],
        ),
        rule(
            EvidenceType::OwnershipCheck,
            "ownership_guard",
            Confidence::High,
            &["requireOwner", "require_owner", "ownerGuard", "owner_guard"],
            &["ownership", "owner"],
        ),
        rule(
            EvidenceType::Authn,
            "authn_guard",
            Confidence::High,
            &[
                "requireAuth",
                "require_auth",
                "requireUser",
                "require_user",
                "login_required",
                "current_user",
                "get_current_user",
                "getCurrentUser",
                "authenticateRequest",
                "ensureLoggedIn",
                "session",
                "auth",
                // Next.js / Auth.js / NextAuth / Clerk session helpers.
                "getServerSession",
                "getToken",
                "getAuth",
                "currentUser",
                "withAuth",
                "clerkMiddleware",
                "authMiddleware",
                "updateSession",
                "isAuthenticated",
            ],
            &["auth", "session", "authenticated", "logged"],
        ),
        rule(
            EvidenceType::AuditLog,
            "audit_log",
            Confidence::High,
            &[
                "audit",
                "auditLog",
                "audit_log",
                "securityLog",
                "security_log",
            ],
            &["audit", "securitylog", "security_log"],
        ),
        rule(
            EvidenceType::UnknownDynamicCheck,
            "dynamic_policy",
            Confidence::Low,
            &[
                "authorize",
                "authorise",
                "policy",
                "checkPolicy",
                "enforcePolicy",
                "dynamicPolicy",
            ],
            &["policy", "dynamic"],
        ),
    ]
}

fn rule(
    evidence_type: EvidenceType,
    mechanism: &str,
    confidence: Confidence,
    exact: &[&str],
    contains: &[&str],
) -> EvidenceRuleSpec {
    EvidenceRuleSpec {
        evidence_type,
        mechanism: mechanism.to_string(),
        confidence,
        exact: exact.iter().map(|item| (*item).to_string()).collect(),
        contains: contains.iter().map(|item| (*item).to_string()).collect(),
        notes: Vec::new(),
        origin: EvidenceRuleOrigin::BuiltIn,
    }
}

fn extract_express_route_evidence(
    route: &authmap_core::Route,
    parsed_by_path: &BTreeMap<&str, &ParsedFile>,
    rules: &EvidenceRules,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    for middleware in &route.middleware {
        if let Some(rule) = rules.match_symbol(&middleware.name) {
            evidence.push(evidence_from_rule(
                route,
                rule,
                Some(middleware.clone()),
                middleware.span.clone(),
            ));
        }
    }

    if let Some(handler) = &route.handler
        && let Some(parsed) =
            route_file(route).and_then(|file| parsed_by_path.get(file.as_str()).copied())
    {
        if let Some(node) = express_handler_node(parsed, handler) {
            evidence.extend(extract_calls_from_node(
                parsed,
                node,
                route,
                rules,
                "handler_call",
            ));
            evidence.extend(extract_guard_condition_evidence(
                parsed, node, route, handler,
            ));
            evidence.extend(extract_scoping_evidence_from_node(
                parsed,
                node,
                route,
                handler,
                "handler_scope",
                Confidence::High,
            ));
        }
    }
    evidence.extend(extract_route_param_scoping_evidence(route));
    evidence
}

fn extract_fastapi_route_evidence(
    route: &authmap_core::Route,
    parsed_by_path: &BTreeMap<&str, &ParsedFile>,
    rules: &EvidenceRules,
) -> Vec<Evidence> {
    let Some(handler) = &route.handler else {
        return Vec::new();
    };
    let Some(parsed) =
        route_file(route).and_then(|file| parsed_by_path.get(file.as_str()).copied())
    else {
        return Vec::new();
    };
    let Some(node) = fastapi_decorated_function_node(parsed, &handler.name) else {
        return Vec::new();
    };

    let mut evidence = extract_calls_from_node(parsed, node, route, rules, "handler_call");
    evidence.extend(extract_guard_condition_evidence(
        parsed, node, route, handler,
    ));
    evidence.extend(extract_scoping_evidence_from_node(
        parsed,
        node,
        route,
        handler,
        "handler_scope",
        Confidence::High,
    ));
    for dependency in &route.middleware {
        if let Some(rule) = rules.match_symbol(&dependency.name) {
            push_fastapi_dependency_evidence(&mut evidence, route, rule, dependency.clone());
        } else if looks_dynamic_policy(&dependency.name) {
            push_unique_symbol_evidence(
                &mut evidence,
                Evidence {
                    id: String::new(),
                    route_id: Some(route.id.clone()),
                    evidence_type: EvidenceType::UnknownDynamicCheck,
                    mechanism: "fastapi_dependency".to_string(),
                    symbol: Some(dependency.clone()),
                    span: dependency.span.clone(),
                    confidence: Confidence::Low,
                    notes: vec![
                    "FastAPI dependency looks policy-related but no specific guard type matched"
                        .to_string(),
                ],
                    extensions: authmap_core::ExtensionMap::new(),
                },
            );
        }
    }
    evidence.extend(extract_route_param_scoping_evidence(route));
    evidence
}

fn push_fastapi_dependency_evidence(
    evidence: &mut Vec<Evidence>,
    route: &authmap_core::Route,
    rule: &EvidenceRuleSpec,
    dependency: SymbolRef,
) {
    push_unique_symbol_evidence(
        evidence,
        evidence_from_rule(
            route,
            rule,
            Some(dependency.clone()),
            dependency.span.clone(),
        ),
    );
}

fn push_unique_symbol_evidence(evidence: &mut Vec<Evidence>, candidate: Evidence) {
    let candidate_symbol = candidate.symbol.as_ref().map(|symbol| symbol.name.as_str());
    if evidence.iter().any(|existing| {
        existing.evidence_type == candidate.evidence_type
            && existing.symbol.as_ref().map(|symbol| symbol.name.as_str()) == candidate_symbol
    }) {
        return;
    }
    evidence.push(candidate);
}

fn extract_django_route_evidence(
    route: &authmap_core::Route,
    parsed_by_path: &BTreeMap<&str, &ParsedFile>,
    rules: &EvidenceRules,
    class_index: &PythonClassIndex<'_>,
) -> Vec<Evidence> {
    let Some(handler) = &route.handler else {
        return Vec::new();
    };
    let Some(parsed) =
        route_file(route).and_then(|file| parsed_by_path.get(file.as_str()).copied())
    else {
        return Vec::new();
    };

    let is_function_handler = django_route_metadata(route)
        .and_then(|metadata| metadata.handler_kind)
        .is_none_or(|kind| kind == "function");

    let mut evidence = Vec::new();
    for node in django_handler_nodes(parsed, route, handler) {
        if is_function_handler {
            // Function-based views carry their guards as decorators
            // (`@login_required`, `@permission_required`, DRF `@permission_classes`),
            // which sit outside the function body scanned below.
            evidence.extend(extract_django_fbv_decorator_evidence(parsed, node, route));
        }
        evidence.extend(extract_calls_from_node(
            parsed,
            node,
            route,
            rules,
            "handler_call",
        ));
        evidence.extend(extract_guard_condition_evidence(
            parsed, node, route, handler,
        ));
        evidence.extend(extract_scoping_evidence_from_node(
            parsed,
            node,
            route,
            handler,
            "handler_scope",
            Confidence::High,
        ));
    }
    if let Some(metadata) = django_route_metadata(route)
        && let Some(class_name) = metadata.class_name.as_deref()
        && let Some(class_file) = handler.span.as_ref().map(|span| span.file.as_str())
    {
        evidence.extend(extract_django_class_evidence(
            route,
            rules,
            class_index,
            class_file,
            class_name,
        ));
    }
    evidence.extend(extract_route_param_scoping_evidence(route));
    evidence
}

fn extract_nextjs_route_evidence(
    route: &authmap_core::Route,
    parsed_by_path: &BTreeMap<&str, &ParsedFile>,
    rules: &EvidenceRules,
) -> Vec<Evidence> {
    let Some(handler) = &route.handler else {
        return Vec::new();
    };
    let Some(parsed) =
        route_file(route).and_then(|file| parsed_by_path.get(file.as_str()).copied())
    else {
        return Vec::new();
    };

    let mut evidence = Vec::new();
    // `middleware.ts` protection: the adapter records the matching middleware in
    // `route.middleware` named after the auth helper it delegates to. Match it
    // against rules exactly like Express route-level middleware.
    for middleware in &route.middleware {
        if let Some(rule) = rules.match_symbol(&middleware.name) {
            evidence.push(evidence_from_rule(
                route,
                rule,
                Some(middleware.clone()),
                middleware.span.clone(),
            ));
        }
    }
    if let Some(metadata) = nextjs_route_metadata(route)
        && let Some(wrapper) = metadata.wrapper.as_deref()
        && let Some(wrapper_evidence) = evidence_from_nextjs_wrapper(route, wrapper)
    {
        evidence.push(wrapper_evidence);
    }
    for node in nextjs_handler_nodes(parsed, route, handler) {
        evidence.extend(extract_calls_from_node(
            parsed,
            node,
            route,
            rules,
            "handler_call",
        ));
        evidence.extend(extract_guard_condition_evidence(
            parsed, node, route, handler,
        ));
        evidence.extend(extract_scoping_evidence_from_node(
            parsed,
            node,
            route,
            handler,
            "handler_scope",
            Confidence::High,
        ));
    }
    evidence.extend(extract_route_param_scoping_evidence(route));
    evidence
}

fn extract_trpc_route_evidence(route: &authmap_core::Route) -> Vec<Evidence> {
    let Some(value) = route.extensions.get("authmap.trpc") else {
        return Vec::new();
    };
    let root = value
        .get("procedure_root")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let lower = root.to_ascii_lowercase();
    let (evidence_type, mechanism) = if lower.contains("admin") {
        (EvidenceType::RoleCheck, "trpc_procedure")
    } else if lower.contains("authed") || lower.contains("protected") {
        (EvidenceType::Authn, "trpc_procedure")
    } else if lower.contains("public") {
        (EvidenceType::ExplicitPublic, "trpc_public_procedure")
    } else {
        return Vec::new();
    };
    vec![Evidence {
        id: String::new(),
        route_id: Some(route.id.clone()),
        evidence_type,
        mechanism: mechanism.to_string(),
        symbol: Some(SymbolRef {
            name: root.to_string(),
            span: route.span.clone(),
        }),
        span: route.span.clone(),
        confidence: Confidence::Medium,
        notes: Vec::new(),
        extensions: authmap_core::ExtensionMap::new(),
    }]
}

fn extract_graphql_route_evidence(route: &authmap_core::Route) -> Vec<Evidence> {
    let Some(value) = route.extensions.get("authmap.graphql") else {
        return Vec::new();
    };
    let Some(permissions) = value.get("permissions").and_then(serde_json::Value::as_str) else {
        return Vec::new();
    };
    if permissions.trim().is_empty() {
        return Vec::new();
    }
    let (evidence_type, mechanism) = if graphql_permissions_explicitly_public(permissions) {
        (EvidenceType::ExplicitPublic, "graphql_public_permissions")
    } else {
        (EvidenceType::PermissionCheck, "graphql_permissions")
    };
    vec![Evidence {
        id: String::new(),
        route_id: Some(route.id.clone()),
        evidence_type,
        mechanism: mechanism.to_string(),
        symbol: Some(SymbolRef {
            name: permissions.to_string(),
            span: route.span.clone(),
        }),
        span: route.span.clone(),
        confidence: Confidence::Medium,
        notes: Vec::new(),
        extensions: authmap_core::ExtensionMap::new(),
    }]
}

fn graphql_permissions_explicitly_public(permissions: &str) -> bool {
    let normalized = permissions
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ',')
        .collect::<String>()
        .to_ascii_lowercase();
    normalized.contains("permissions=()")
        || normalized.contains("permissions=[]")
        || normalized.contains("permissions={}")
}

fn route_supports_service_evidence(route: &authmap_core::Route) -> bool {
    matches!(
        route.framework,
        Framework::Express
            | Framework::FastApi
            | Framework::Django
            | Framework::DjangoRestFramework
            | Framework::NextJs
    )
}

fn extract_service_call_evidence(
    route: &authmap_core::Route,
    parsed_by_path: &BTreeMap<&str, &ParsedFile>,
    rules: &EvidenceRules,
    index: &ReachabilityIndex<'_>,
) -> Vec<Evidence> {
    let Some(handler) = &route.handler else {
        return Vec::new();
    };
    let Some(parsed) =
        route_file(route).and_then(|file| parsed_by_path.get(file.as_str()).copied())
    else {
        return Vec::new();
    };
    let handler_nodes = match route.framework {
        Framework::Express => express_handler_node(parsed, handler).into_iter().collect(),
        Framework::FastApi => fastapi_handler_function_node(parsed, &handler.name)
            .into_iter()
            .collect(),
        Framework::Django | Framework::DjangoRestFramework => {
            django_handler_nodes(parsed, route, handler)
        }
        Framework::NextJs => nextjs_handler_nodes(parsed, route, handler),
        _ => Vec::new(),
    };

    let mut evidence = Vec::new();
    for handler_node in handler_nodes {
        let receiver_types = python_receiver_type_bindings(parsed, handler_node);
        for call in service_call_candidates(parsed, handler_node) {
            let Some(function) = call.child_by_field_name("function") else {
                continue;
            };
            let function_text = parsed.text_for(function).unwrap_or_default();
            let resolved = index
                .resolve_call_with_receiver_types(
                    &parsed.source.path,
                    function_text,
                    &receiver_types,
                )
                .or_else(|| index.resolve_call(&parsed.source.path, function_text));
            let Some(resolved) = resolved else {
                continue;
            };
            let Some(resolved_parsed) = index.parsed_by_file.get(&resolved.def.file).copied()
            else {
                continue;
            };
            let mut service_evidence = extract_calls_from_node(
                resolved_parsed,
                resolved.def.node,
                route,
                rules,
                "service_call",
            );
            for item in &mut service_evidence {
                if item.confidence > resolved.confidence {
                    item.confidence = resolved.confidence;
                }
                item.notes.push(format!(
                    "One-hop service call `{}` reaches `{}`",
                    function_text.trim(),
                    resolved.def.name
                ));
            }
            evidence.extend(service_evidence);
            let mut scoping_evidence = extract_scoping_evidence_from_node(
                resolved_parsed,
                resolved.def.node,
                route,
                handler,
                "service_scope",
                resolved.confidence,
            );
            for item in &mut scoping_evidence {
                item.notes.push(format!(
                    "One-hop service call `{}` reaches `{}`",
                    function_text.trim(),
                    resolved.def.name
                ));
            }
            evidence.extend(scoping_evidence);
        }
    }
    evidence
}

fn python_receiver_type_bindings(
    parsed: &ParsedFile,
    function: Node<'_>,
) -> BTreeMap<String, String> {
    if parsed.language != authmap_core::Language::Python {
        return BTreeMap::new();
    }
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return BTreeMap::new();
    };
    let Some(text) = parsed.text_for(parameters) else {
        return BTreeMap::new();
    };
    let mut bindings = BTreeMap::new();
    for parameter in
        split_top_level_commas(text.trim().trim_start_matches('(').trim_end_matches(')'))
    {
        let Some((name, annotation)) = parameter.split_once(':') else {
            continue;
        };
        let name = name.trim().trim_start_matches('*').trim();
        if name.is_empty() {
            continue;
        }
        if let Some(class_name) = python_annotation_class_name(annotation) {
            bindings.insert(name.to_string(), class_name);
        }
    }
    bindings
}

fn split_top_level_commas(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    for (index, ch) in value.char_indices() {
        match ch {
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(value[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if start < value.len() {
        parts.push(value[start..].trim());
    }
    parts
}

fn python_annotation_class_name(annotation: &str) -> Option<String> {
    let annotation = annotation.split('=').next().unwrap_or(annotation).trim();
    let candidate = if let Some((_, rest)) = annotation.rsplit_once('[') {
        rest.trim_end_matches(']')
            .rsplit(',')
            .next()
            .unwrap_or(rest)
    } else {
        annotation
    };
    let class_name = terminal_symbol_name(candidate.trim());
    class_name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
        .then_some(class_name)
}

fn extract_calls_from_node(
    parsed: &ParsedFile,
    node: Node<'_>,
    route: &authmap_core::Route,
    rules: &EvidenceRules,
    default_mechanism: &str,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "call" | "call_expression") {
            let function = current.child_by_field_name("function");
            if let Some(function) = function {
                let function_text = parsed.text_for(function).unwrap_or_default();
                if is_framework_route_call(function_text) {
                    // Route declarations are not authorization evidence.
                } else if is_fastapi_depends(function_text) {
                    let dependency = first_symbol_argument(parsed, current);
                    if let Some(symbol) = dependency {
                        if let Some(rule) = rules.match_symbol(&symbol.name) {
                            evidence.push(evidence_from_rule(
                                route,
                                rule,
                                Some(symbol),
                                Some(parsed.span_for(current)),
                            ));
                        } else if looks_dynamic_policy(&symbol.name) {
                            evidence.push(Evidence {
                                id: String::new(),
                                route_id: Some(route.id.clone()),
                                evidence_type: EvidenceType::UnknownDynamicCheck,
                                mechanism: default_mechanism.to_string(),
                                symbol: Some(symbol),
                                span: Some(parsed.span_for(current)),
                                confidence: Confidence::Low,
                                notes: vec![
                                    "FastAPI dependency looks policy-related but no specific guard type matched"
                                        .to_string(),
                                ],
                                extensions: authmap_core::ExtensionMap::new(),
                            });
                        }
                    }
                } else if let Some(rule) = rules.match_symbol(function_text) {
                    evidence.push(evidence_from_rule(
                        route,
                        rule,
                        Some(SymbolRef {
                            name: terminal_symbol_name(function_text),
                            span: Some(parsed.span_for(function)),
                        }),
                        Some(parsed.span_for(current)),
                    ));
                } else if looks_dynamic_policy(function_text) {
                    evidence.push(Evidence {
                        id: String::new(),
                        route_id: Some(route.id.clone()),
                        evidence_type: EvidenceType::UnknownDynamicCheck,
                        mechanism: default_mechanism.to_string(),
                        symbol: Some(SymbolRef {
                            name: terminal_symbol_name(function_text),
                            span: Some(parsed.span_for(function)),
                        }),
                        span: Some(parsed.span_for(current)),
                        confidence: Confidence::Low,
                        notes: vec!["Dynamic or indirect policy call requires review".to_string()],
                        extensions: authmap_core::ExtensionMap::new(),
                    });
                }
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    evidence
}

fn extract_guard_condition_evidence(
    parsed: &ParsedFile,
    node: Node<'_>,
    route: &authmap_core::Route,
    symbol: &SymbolRef,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "if_statement" | "if")
            && let Some(condition) = condition_node(current)
            && guard_condition_needs_review(parsed, condition)
        {
            evidence.push(Evidence {
                id: String::new(),
                route_id: Some(route.id.clone()),
                evidence_type: EvidenceType::UnknownDynamicCheck,
                mechanism: "handler_condition".to_string(),
                symbol: Some(symbol.clone()),
                span: Some(parsed.span_for(condition)),
                confidence: Confidence::Low,
                notes: vec![
                    "Handler condition references user authorization attributes; review required"
                        .to_string(),
                ],
                extensions: authmap_core::ExtensionMap::new(),
            });
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    evidence
}

fn extract_route_param_scoping_evidence(route: &authmap_core::Route) -> Vec<Evidence> {
    route_params(&route.path)
        .iter()
        .filter_map(|param| {
            let evidence_type = scope_evidence_type(&param.name)?;
            Some(Evidence {
                id: String::new(),
                route_id: Some(route.id.clone()),
                evidence_type,
                mechanism: "route_param_scope_signal".to_string(),
                symbol: Some(SymbolRef {
                    name: param.name.clone(),
                    span: param.span.clone().or_else(|| route.span.clone()),
                }),
                span: param.span.clone().or_else(|| route.span.clone()),
                confidence: Confidence::Low,
                notes: vec![
                    "Route parameter name suggests tenant or ownership context but is not proof of scoping"
                        .to_string(),
                ],
                extensions: authmap_core::ExtensionMap::new(),
            })
        })
        .collect()
}

fn extract_scoping_evidence_from_node(
    parsed: &ParsedFile,
    node: Node<'_>,
    route: &authmap_core::Route,
    symbol: &SymbolRef,
    fallback_mechanism: &str,
    confidence_cap: Confidence,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if node_is_untrusted_text(current.kind()) {
            continue;
        }
        match current.kind() {
            "if" | "if_statement" => {
                if let Some(condition) = condition_node(current) {
                    push_scoping_evidence_for_text(
                        &mut evidence,
                        parsed,
                        route,
                        symbol,
                        condition,
                        "condition_scope",
                        confidence_cap,
                    );
                }
            }
            "call" | "call_expression" => {
                let mechanism = parsed
                    .text_for(current.child_by_field_name("function").unwrap_or(current))
                    .map(scope_call_mechanism)
                    .unwrap_or(fallback_mechanism);
                if mechanism != fallback_mechanism {
                    push_scoping_evidence_for_text(
                        &mut evidence,
                        parsed,
                        route,
                        symbol,
                        current,
                        mechanism,
                        confidence_cap,
                    );
                }
            }
            "assignment"
            | "assignment_expression"
            | "augmented_assignment_expression"
            | "pair"
            | "property_identifier" => {
                let mechanism = parsed
                    .text_for(current)
                    .map(|text| {
                        if contains_any(&text.to_ascii_lowercase(), &["filter", "where", "query"]) {
                            "query_scope"
                        } else {
                            "mutation_scope"
                        }
                    })
                    .unwrap_or("mutation_scope");
                push_scoping_evidence_for_text(
                    &mut evidence,
                    parsed,
                    route,
                    symbol,
                    current,
                    mechanism,
                    confidence_cap,
                );
            }
            _ => {}
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    evidence
}

fn push_scoping_evidence_for_text(
    evidence: &mut Vec<Evidence>,
    parsed: &ParsedFile,
    route: &authmap_core::Route,
    _symbol: &SymbolRef,
    node: Node<'_>,
    mechanism: &str,
    confidence_cap: Confidence,
) {
    let Some(text) = parsed.text_for(node) else {
        return;
    };
    let lower = text.to_ascii_lowercase();
    let Some(evidence_type) = scope_text_evidence_type(&lower) else {
        return;
    };
    if !scope_text_has_structure(&lower, mechanism) {
        return;
    }
    let confidence = std::cmp::min(Confidence::High, confidence_cap);
    push_unique_symbol_evidence(
        evidence,
        Evidence {
            id: String::new(),
            route_id: Some(route.id.clone()),
            evidence_type,
            mechanism: mechanism.to_string(),
            symbol: Some(SymbolRef {
                name: scope_symbol_name(text, evidence_type),
                span: Some(parsed.span_for(node)),
            }),
            span: Some(parsed.span_for(node)),
            confidence,
            notes: vec![scope_evidence_note(evidence_type, mechanism).to_string()],
            extensions: authmap_core::ExtensionMap::new(),
        },
    );
    if mechanism == "mutation_scope" && text.contains("owner") && text.contains("tenant") {
        push_unique_symbol_evidence(
            evidence,
            Evidence {
                id: String::new(),
                route_id: Some(route.id.clone()),
                evidence_type: EvidenceType::OwnershipCheck,
                mechanism: mechanism.to_string(),
                symbol: Some(SymbolRef {
                    name: "owner".to_string(),
                    span: Some(parsed.span_for(node)),
                }),
                span: Some(parsed.span_for(node)),
                confidence,
                notes: vec![
                    scope_evidence_note(EvidenceType::OwnershipCheck, mechanism).to_string(),
                ],
                extensions: authmap_core::ExtensionMap::new(),
            },
        );
    }
}

fn scope_call_mechanism(function_text: &str) -> &'static str {
    let lower = function_text.to_ascii_lowercase();
    if contains_any(
        &lower,
        &[
            "update",
            "delete",
            "create",
            "save",
            "add",
            "insert",
            "bulk_update",
        ],
    ) {
        "mutation_scope"
    } else if contains_any(
        &lower,
        &[
            "filter",
            "where",
            "find",
            "findunique",
            "findfirst",
            "get",
            "query",
        ],
    ) {
        "query_scope"
    } else {
        "handler_scope"
    }
}

fn scope_text_evidence_type(lower: &str) -> Option<EvidenceType> {
    if contains_tenant_token(lower) {
        Some(EvidenceType::TenantCheck)
    } else if contains_ownership_token(lower) {
        Some(EvidenceType::OwnershipCheck)
    } else {
        None
    }
}

fn scope_evidence_type(name: &str) -> Option<EvidenceType> {
    let lower = name.to_ascii_lowercase();
    if contains_tenant_token(&lower)
        || contains_any(
            &lower,
            &["account_id", "accountid", "project_id", "projectid"],
        )
    {
        Some(EvidenceType::TenantCheck)
    } else if contains_ownership_token(&lower) {
        Some(EvidenceType::OwnershipCheck)
    } else {
        None
    }
}

fn scope_text_has_structure(lower: &str, mechanism: &str) -> bool {
    match mechanism {
        "condition_scope" => {
            contains_any(lower, &["==", "!=", "===", "!==", " in ", ".includes"])
                && contains_subject_token(lower)
        }
        "query_scope" => {
            contains_any(lower, &["filter", "where", "find", "get", "query"])
                && contains_any(lower, &["=", ":", "=="])
        }
        "mutation_scope" => {
            contains_any(
                lower,
                &[
                    "=", ":", "where", "data", "update", "create", "delete", "add",
                ],
            ) && (contains_subject_token(lower)
                || contains_any(lower, &["req.params", "params.", "_id", "id:"]))
        }
        _ => false,
    }
}

fn contains_tenant_token(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "tenant_id",
            "tenantid",
            "tenant",
            "org_id",
            "orgid",
            "organization_id",
            "organizationid",
            "organisation_id",
            "workspace_id",
            "workspaceid",
            "workspace",
        ],
    )
}

fn contains_ownership_token(lower: &str) -> bool {
    contains_any(lower, &["owner_id", "ownerid", "owner", "ownership"])
}

fn contains_subject_token(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "req.user",
            "request.user",
            "current_user",
            "user.",
            "user[",
            "ctx.user",
            "session.user",
        ],
    )
}

fn node_is_untrusted_text(kind: &str) -> bool {
    matches!(
        kind,
        "comment" | "string" | "string_fragment" | "template_string"
    )
}

fn scope_symbol_name(text: &str, evidence_type: EvidenceType) -> String {
    for token in scope_symbol_tokens(evidence_type) {
        if text.to_ascii_lowercase().contains(token) {
            return token.to_string();
        }
    }
    evidence_type_label(evidence_type).to_string()
}

fn scope_symbol_tokens(evidence_type: EvidenceType) -> &'static [&'static str] {
    match evidence_type {
        EvidenceType::TenantCheck => &[
            "tenant_id",
            "tenant",
            "org_id",
            "organization_id",
            "workspace_id",
        ],
        EvidenceType::OwnershipCheck => &["owner_id", "owner"],
        _ => &[],
    }
}

fn scope_evidence_note(evidence_type: EvidenceType, mechanism: &str) -> &'static str {
    match (evidence_type, mechanism) {
        (EvidenceType::TenantCheck, "query_scope") => "Query filter includes tenant scoping",
        (EvidenceType::OwnershipCheck, "query_scope") => "Query filter includes ownership scoping",
        (EvidenceType::TenantCheck, "condition_scope") => {
            "Condition compares tenant context before continuing"
        }
        (EvidenceType::OwnershipCheck, "condition_scope") => {
            "Condition compares ownership context before continuing"
        }
        (EvidenceType::TenantCheck, "mutation_scope") => "Mutation input includes tenant scoping",
        (EvidenceType::OwnershipCheck, "mutation_scope") => {
            "Mutation input includes ownership scoping"
        }
        _ => "Tenant or ownership scoping evidence was detected",
    }
}

fn extract_django_class_evidence(
    route: &authmap_core::Route,
    rules: &EvidenceRules,
    class_index: &PythonClassIndex<'_>,
    class_file: &str,
    class_name: &str,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let chain = class_index.class_chain(class_file, class_name);
    let Some(route_class) = chain.first() else {
        return evidence;
    };

    for class in &chain {
        let inherited = class.file != route_class.file || class.name != route_class.name;
        evidence.extend(extract_django_base_evidence(route, class, inherited));
        evidence.extend(extract_django_class_attribute_evidence(
            route, class, inherited,
        ));
        for method_name in [
            "initial",
            "dispatch",
            "has_permission",
            "has_object_permission",
            "get_permissions",
            "check_permissions",
            "get_queryset",
        ] {
            if let Some(method) = python_class_method_node(class.node, class.parsed, method_name) {
                evidence.extend(extract_calls_from_node(
                    class.parsed,
                    method,
                    route,
                    rules,
                    if inherited {
                        "inherited_handler_call"
                    } else {
                        "handler_call"
                    },
                ));
                evidence.extend(extract_django_builtin_evidence_from_node(
                    route, class, method, inherited,
                ));
            }
        }
    }
    evidence
}

fn extract_django_base_evidence(
    route: &authmap_core::Route,
    class: &PythonClassDef<'_>,
    inherited: bool,
) -> Vec<Evidence> {
    class
        .bases
        .iter()
        .filter_map(|base| {
            let clean = terminal_symbol_name(base);
            let lower = clean.to_ascii_lowercase();
            let (evidence_type, mechanism) = if lower.contains("loginrequired") {
                (EvidenceType::Authn, "django_login_required_mixin")
            } else if lower.contains("permissionrequired") || lower.contains("objectpermission") {
                (EvidenceType::PermissionCheck, "django_permission_mixin")
            } else if lower.contains("userpassestest") {
                (EvidenceType::UnknownDynamicCheck, "django_user_test_mixin")
            } else {
                return None;
            };
            Some(Evidence {
                id: String::new(),
                route_id: Some(route.id.clone()),
                evidence_type,
                mechanism: mechanism.to_string(),
                symbol: Some(SymbolRef {
                    name: clean,
                    span: Some(class.span.clone()),
                }),
                span: Some(class.span.clone()),
                confidence: if inherited {
                    Confidence::Medium
                } else {
                    Confidence::High
                },
                notes: inherited_note(inherited, class),
                extensions: authmap_core::ExtensionMap::new(),
            })
        })
        .collect()
}

fn extract_django_class_attribute_evidence(
    route: &authmap_core::Route,
    class: &PythonClassDef<'_>,
    inherited: bool,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    for assignment in direct_class_assignments(class.node) {
        let Some((left, right)) = assignment_sides(class.parsed, assignment) else {
            continue;
        };
        let attr = left.trim();
        if attr != "permission_classes" && attr != "authentication_classes" {
            continue;
        }
        let lower = right.to_ascii_lowercase();
        let (evidence_type, mechanism, symbol_name) = if attr == "authentication_classes" {
            (
                EvidenceType::Authn,
                "django_authentication_classes",
                "authentication_classes".to_string(),
            )
        } else {
            classify_drf_permission_classes(&lower)
        };
        evidence.push(Evidence {
            id: String::new(),
            route_id: Some(route.id.clone()),
            evidence_type,
            mechanism: mechanism.to_string(),
            symbol: Some(SymbolRef {
                name: symbol_name,
                span: Some(class.parsed.span_for(assignment)),
            }),
            span: Some(class.parsed.span_for(assignment)),
            confidence: if inherited {
                Confidence::Medium
            } else {
                Confidence::High
            },
            notes: inherited_note(inherited, class),
            extensions: authmap_core::ExtensionMap::new(),
        });
    }
    evidence
}

/// Classifies a DRF `permission_classes` value (lowercased) into evidence.
/// Shared by class-attribute and function-based-view `@permission_classes`
/// detection. `IsAuthenticatedOrReadOnly` is surfaced as dynamic/review since
/// it makes the read path public while only authenticating writes.
fn classify_drf_permission_classes(lower: &str) -> (EvidenceType, &'static str, String) {
    if lower.contains("allowany") {
        (
            EvidenceType::ExplicitPublic,
            "drf_permission_classes",
            "AllowAny".to_string(),
        )
    } else if lower.contains("isadminuser") || lower.contains("issuperuser") {
        (
            EvidenceType::AdminCheck,
            "drf_permission_classes",
            "IsAdminUser".to_string(),
        )
    } else if lower.contains("isauthenticatedorreadonly") {
        (
            EvidenceType::UnknownDynamicCheck,
            "drf_permission_classes",
            "IsAuthenticatedOrReadOnly".to_string(),
        )
    } else if lower.contains("isauthenticated") {
        (
            EvidenceType::Authn,
            "drf_permission_classes",
            "IsAuthenticated".to_string(),
        )
    } else if lower.contains("permission") {
        (
            EvidenceType::PermissionCheck,
            "drf_permission_classes",
            "permission_classes".to_string(),
        )
    } else {
        (
            EvidenceType::UnknownDynamicCheck,
            "drf_permission_classes",
            "permission_classes".to_string(),
        )
    }
}

/// Extracts authorization evidence from the decorators of a function-based view.
/// `function_node` is the `function_definition`; its `decorated_definition`
/// parent holds the decorators (`@login_required`, `@permission_required(...)`,
/// `@api_view([...])` + `@permission_classes([...])`, etc.).
fn extract_django_fbv_decorator_evidence(
    parsed: &ParsedFile,
    function_node: Node<'_>,
    route: &authmap_core::Route,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let Some(parent) = function_node.parent() else {
        return evidence;
    };
    if parent.kind() != "decorated_definition" {
        return evidence;
    }
    let mut cursor = parent.walk();
    for decorator in parent.children(&mut cursor) {
        if decorator.kind() != "decorator" {
            continue;
        }
        let Some(expr) = decorator.named_child(0) else {
            continue;
        };
        let (name_node, args_text) = if expr.kind() == "call" {
            let function = expr.child_by_field_name("function");
            let args = expr
                .child_by_field_name("arguments")
                .and_then(|args| parsed.text_for(args))
                .unwrap_or_default();
            (function, args.to_string())
        } else {
            (Some(expr), String::new())
        };
        let Some(name) = name_node
            .and_then(|node| parsed.text_for(node))
            .map(terminal_symbol_name)
        else {
            continue;
        };
        if let Some(item) =
            django_decorator_evidence(route, &name, &args_text, parsed.span_for(decorator))
        {
            evidence.push(item);
        }
    }
    evidence
}

fn django_decorator_evidence(
    route: &authmap_core::Route,
    name: &str,
    args_text: &str,
    span: Span,
) -> Option<Evidence> {
    let (evidence_type, mechanism, symbol_name) = match name {
        "login_required" => (
            EvidenceType::Authn,
            "django_login_required",
            name.to_string(),
        ),
        "staff_member_required" => (
            EvidenceType::AdminCheck,
            "django_staff_member_required",
            name.to_string(),
        ),
        "permission_required" => (
            EvidenceType::PermissionCheck,
            "django_permission_required",
            name.to_string(),
        ),
        "user_passes_test" => (
            EvidenceType::UnknownDynamicCheck,
            "django_user_passes_test",
            name.to_string(),
        ),
        "authentication_classes" => (
            EvidenceType::Authn,
            "django_authentication_classes",
            "authentication_classes".to_string(),
        ),
        "permission_classes" => classify_drf_permission_classes(&args_text.to_ascii_lowercase()),
        _ => return None,
    };
    Some(Evidence {
        id: String::new(),
        route_id: Some(route.id.clone()),
        evidence_type,
        mechanism: mechanism.to_string(),
        symbol: Some(SymbolRef {
            name: symbol_name,
            span: Some(span.clone()),
        }),
        span: Some(span),
        confidence: Confidence::High,
        notes: Vec::new(),
        extensions: authmap_core::ExtensionMap::new(),
    })
}

fn extract_django_builtin_evidence_from_node(
    route: &authmap_core::Route,
    class: &PythonClassDef<'_>,
    node: Node<'_>,
    inherited: bool,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if let Some(text) = class.parsed.text_for(current) {
            let lower = text.to_ascii_lowercase();
            if current.kind() == "attribute" || current.kind() == "call" {
                if lower.contains("has_perm") || lower.contains("has_perms") {
                    evidence.push(django_builtin_evidence(
                        route,
                        class,
                        current,
                        EvidenceType::PermissionCheck,
                        "django_user_permission_call",
                        "has_perm",
                        inherited,
                    ));
                } else if lower.contains(".restrict") {
                    evidence.push(django_builtin_evidence(
                        route,
                        class,
                        current,
                        EvidenceType::PermissionCheck,
                        "django_queryset_restrict",
                        "restrict",
                        inherited,
                    ));
                } else if lower.contains("is_authenticated") {
                    evidence.push(django_builtin_evidence(
                        route,
                        class,
                        current,
                        EvidenceType::Authn,
                        "django_authenticated_user_check",
                        "is_authenticated",
                        inherited,
                    ));
                }
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    evidence
}

fn django_builtin_evidence(
    route: &authmap_core::Route,
    class: &PythonClassDef<'_>,
    node: Node<'_>,
    evidence_type: EvidenceType,
    mechanism: &str,
    symbol_name: &str,
    inherited: bool,
) -> Evidence {
    Evidence {
        id: String::new(),
        route_id: Some(route.id.clone()),
        evidence_type,
        mechanism: mechanism.to_string(),
        symbol: Some(SymbolRef {
            name: symbol_name.to_string(),
            span: Some(class.parsed.span_for(node)),
        }),
        span: Some(class.parsed.span_for(node)),
        confidence: if inherited {
            Confidence::Medium
        } else {
            Confidence::High
        },
        notes: inherited_note(inherited, class),
        extensions: authmap_core::ExtensionMap::new(),
    }
}

fn inherited_note(inherited: bool, class: &PythonClassDef<'_>) -> Vec<String> {
    if inherited {
        vec![format!(
            "Authorization evidence inherited from {}",
            class.name
        )]
    } else {
        Vec::new()
    }
}

fn condition_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("condition")
        .or_else(|| node.named_child(0))
}

fn guard_condition_needs_review(parsed: &ParsedFile, condition: Node<'_>) -> bool {
    let mut has_user_subject = false;
    let mut has_authz_attribute = false;
    let mut stack = vec![condition];
    while let Some(current) = stack.pop() {
        if !matches!(
            current.kind(),
            "string" | "string_fragment" | "comment" | "template_string"
        ) && let Some(text) = parsed.text_for(current)
        {
            let lower = text.to_ascii_lowercase();
            if lower.contains("req.user")
                || lower.contains("request.user")
                || lower.contains("current_user")
                || lower.contains("user.")
                || lower.contains("user[")
            {
                has_user_subject = true;
            }
            if contains_authz_token(&lower) {
                has_authz_attribute = true;
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    has_user_subject && has_authz_attribute
}

fn contains_authz_token(lower: &str) -> bool {
    lower.contains("role")
        || lower.contains("admin")
        || lower.contains("permission")
        || lower.contains("tenant")
        || lower.contains("owner")
        || lower.contains("ownership")
}

fn evidence_from_rule(
    route: &authmap_core::Route,
    rule: &EvidenceRuleSpec,
    symbol: Option<SymbolRef>,
    span: Option<Span>,
) -> Evidence {
    Evidence {
        id: String::new(),
        route_id: Some(route.id.clone()),
        evidence_type: rule.evidence_type,
        mechanism: rule.mechanism.clone(),
        symbol,
        span,
        confidence: rule.confidence,
        notes: rule.notes.clone(),
        extensions: authmap_core::ExtensionMap::new(),
    }
}

fn route_file(route: &authmap_core::Route) -> Option<String> {
    route
        .handler
        .as_ref()
        .and_then(|handler| handler.span.as_ref())
        .map(|span| span.file.clone())
        .or_else(|| route.span.as_ref().map(|span| span.file.clone()))
}

fn fastapi_decorated_function_node<'tree>(
    parsed: &'tree ParsedFile,
    handler_name: &str,
) -> Option<Node<'tree>> {
    let root = parsed.root_node()?;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "decorated_definition" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "function_definition"
                    && function_name(parsed, child).as_deref() == Some(handler_name)
                {
                    return Some(node);
                }
            }
        }
        if node.kind() == "function_definition"
            && function_name(parsed, node).as_deref() == Some(handler_name)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn fastapi_handler_function_node<'tree>(
    parsed: &'tree ParsedFile,
    handler_name: &str,
) -> Option<Node<'tree>> {
    let root = parsed.root_node()?;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition"
            && function_name(parsed, node).as_deref() == Some(handler_name)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn express_handler_node<'tree>(
    parsed: &'tree ParsedFile,
    handler: &SymbolRef,
) -> Option<Node<'tree>> {
    let root = parsed.root_node()?;
    if handler.name == "<inline_handler>" || handler.name == "<inline_middleware>" {
        return handler
            .span
            .as_ref()
            .and_then(|span| node_containing_span(root, span));
    }

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_declaration"
                if function_name(parsed, node).as_deref() == Some(&handler.name) =>
            {
                return Some(node);
            }
            "variable_declarator"
                if variable_function_name(parsed, node).as_deref() == Some(&handler.name) =>
            {
                return Some(node);
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn nextjs_handler_nodes<'tree>(
    parsed: &'tree ParsedFile,
    route: &authmap_core::Route,
    handler: &SymbolRef,
) -> Vec<Node<'tree>> {
    let Some(metadata) = nextjs_route_metadata(route) else {
        return js_function_or_value_node(parsed, &handler.name)
            .into_iter()
            .collect();
    };
    match metadata.export_kind.as_deref() {
        Some("function") => js_function_declaration_node(parsed, &metadata.export_name)
            .into_iter()
            .collect(),
        Some("const_function") => js_variable_function_value_node(parsed, &metadata.export_name)
            .into_iter()
            .collect(),
        Some("re_export") => js_function_or_value_node(parsed, &handler.name)
            .into_iter()
            .collect(),
        Some("wrapped") => nextjs_wrapped_handler_nodes(parsed, &metadata.export_name, handler),
        _ => Vec::new(),
    }
}

#[derive(Clone, Debug, Default)]
struct NextJsRouteMetadata {
    export_name: String,
    export_kind: Option<String>,
    wrapper: Option<String>,
}

fn nextjs_route_metadata(route: &authmap_core::Route) -> Option<NextJsRouteMetadata> {
    let value = route.extensions.get("authmap.nextjs")?;
    Some(NextJsRouteMetadata {
        export_name: value
            .get("export_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        export_kind: value
            .get("export_kind")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        wrapper: value
            .get("wrapper")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    })
}

fn evidence_from_nextjs_wrapper(route: &authmap_core::Route, wrapper: &str) -> Option<Evidence> {
    let clean = terminal_symbol_name(wrapper);
    let lower = clean.to_ascii_lowercase();
    let (evidence_type, mechanism, confidence) = if lower.contains("admin") {
        (
            EvidenceType::RoleCheck,
            "nextjs_auth_wrapper",
            Confidence::Medium,
        )
    } else if lower.contains("workspace")
        || lower.contains("permission")
        || lower.contains("tenant")
        || lower.contains("team")
    {
        (
            EvidenceType::PermissionCheck,
            "nextjs_auth_wrapper",
            Confidence::Medium,
        )
    } else if lower.contains("session") || lower.contains("auth") || lower.contains("user") {
        (
            EvidenceType::Authn,
            "nextjs_auth_wrapper",
            Confidence::Medium,
        )
    } else {
        (
            EvidenceType::UnknownDynamicCheck,
            "nextjs_unknown_wrapper",
            Confidence::Low,
        )
    };
    Some(Evidence {
        id: String::new(),
        route_id: Some(route.id.clone()),
        evidence_type,
        mechanism: mechanism.to_string(),
        symbol: Some(SymbolRef {
            name: clean,
            span: route
                .handler
                .as_ref()
                .and_then(|handler| handler.span.clone()),
        }),
        span: route.span.clone(),
        confidence,
        notes: vec!["Next.js route handler is wrapped by an auth-like helper".to_string()],
        extensions: authmap_core::ExtensionMap::new(),
    })
}

fn nextjs_wrapped_handler_nodes<'tree>(
    parsed: &'tree ParsedFile,
    export_name: &str,
    handler: &SymbolRef,
) -> Vec<Node<'tree>> {
    if handler.name != export_name
        && let Some(node) = js_function_or_value_node(parsed, &handler.name)
    {
        return vec![node];
    }
    if let Some(variable) = js_variable_declarator_node(parsed, export_name) {
        if let Some(value) = variable.child_by_field_name("value")
            && value.kind() == "call_expression"
        {
            return call_argument_nodes(value)
                .into_iter()
                .filter(|arg| {
                    matches!(
                        arg.kind(),
                        "arrow_function" | "function" | "function_expression"
                    )
                })
                .collect();
        }
    }
    Vec::new()
}

fn js_function_or_value_node<'tree>(parsed: &'tree ParsedFile, name: &str) -> Option<Node<'tree>> {
    js_function_declaration_node(parsed, name)
        .or_else(|| js_variable_function_value_node(parsed, name))
}

fn js_function_declaration_node<'tree>(
    parsed: &'tree ParsedFile,
    name: &str,
) -> Option<Node<'tree>> {
    let root = parsed.root_node()?;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_declaration"
            && function_name(parsed, node).as_deref() == Some(name)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn js_variable_function_value_node<'tree>(
    parsed: &'tree ParsedFile,
    name: &str,
) -> Option<Node<'tree>> {
    let variable = js_variable_declarator_node(parsed, name)?;
    variable.child_by_field_name("value").filter(|value| {
        matches!(
            value.kind(),
            "arrow_function" | "function" | "function_expression"
        )
    })
}

fn js_variable_declarator_node<'tree>(
    parsed: &'tree ParsedFile,
    name: &str,
) -> Option<Node<'tree>> {
    let root = parsed.root_node()?;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node != root
            && matches!(
                node.kind(),
                "arrow_function"
                    | "function"
                    | "function_expression"
                    | "class"
                    | "class_declaration"
            )
        {
            continue;
        }
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .and_then(|name_node| parsed.text_for(name_node))
                == Some(name)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

#[derive(Clone, Debug)]
struct PythonClassDef<'a> {
    parsed: &'a ParsedFile,
    file: String,
    name: String,
    span: Span,
    bases: Vec<String>,
    node: Node<'a>,
}

#[derive(Clone, Debug, Default)]
struct PythonClassIndex<'a> {
    classes: BTreeMap<(String, String), PythonClassDef<'a>>,
    imports: BTreeMap<(String, String), ImportTarget>,
    wildcard_imports: BTreeMap<String, Vec<String>>,
}

impl<'a> PythonClassIndex<'a> {
    fn new(parsed_files: &'a [ParsedFile]) -> Self {
        let module_index = build_python_module_index(parsed_files);
        let mut imports = BTreeMap::new();
        let mut wildcard_imports = BTreeMap::new();
        for parsed in parsed_files
            .iter()
            .filter(|parsed| parsed.language == authmap_core::Language::Python)
        {
            collect_python_imports(parsed, &module_index, &mut imports);
            collect_python_wildcard_imports(parsed, &module_index, &mut wildcard_imports);
        }
        let mut classes = BTreeMap::new();
        for parsed in parsed_files
            .iter()
            .filter(|parsed| parsed.language == authmap_core::Language::Python)
        {
            let Some(root) = parsed.root_node() else {
                continue;
            };
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                if node.kind() == "class_definition"
                    && let Some(name_node) = node.child_by_field_name("name")
                    && let Some(name) = parsed.text_for(name_node)
                {
                    classes.insert(
                        (parsed.source.path.clone(), name.to_string()),
                        PythonClassDef {
                            parsed,
                            file: parsed.source.path.clone(),
                            name: name.to_string(),
                            span: parsed.span_for(name_node),
                            bases: python_class_bases(parsed, node),
                            node,
                        },
                    );
                }
                let mut cursor = node.walk();
                stack.extend(node.children(&mut cursor));
            }
        }
        Self {
            classes,
            imports,
            wildcard_imports,
        }
    }

    fn class_chain(&self, file: &str, class_name: &str) -> Vec<PythonClassDef<'a>> {
        let mut chain = Vec::new();
        self.collect_class_chain(
            &(file.to_string(), class_name.to_string()),
            &mut BTreeSet::new(),
            &mut chain,
            0,
        );
        chain
    }

    fn collect_class_chain(
        &self,
        key: &(String, String),
        active: &mut BTreeSet<(String, String)>,
        chain: &mut Vec<PythonClassDef<'a>>,
        depth: usize,
    ) {
        if depth >= 64 || !active.insert(key.clone()) {
            return;
        }
        let Some(class) = self.classes.get(key) else {
            active.remove(key);
            return;
        };
        chain.push(class.clone());
        for base in &class.bases {
            if let Some(base_key) = self.resolve_class_key(&class.file, base) {
                self.collect_class_chain(&base_key, active, chain, depth + 1);
            }
        }
        active.remove(key);
    }

    fn resolve_class_key(&self, file: &str, symbol: &str) -> Option<(String, String)> {
        if let Some((object, member)) = symbol.rsplit_once('.')
            && let Some(target) = self.imports.get(&(file.to_string(), object.to_string()))
        {
            return self.resolve_exported_class(&target.file, &clean_symbol(member), 0);
        }
        let name = clean_symbol(symbol);
        let local_key = (file.to_string(), name.clone());
        if self.classes.contains_key(&local_key) {
            return Some(local_key);
        }
        if let Some(target) = self.imports.get(&(file.to_string(), name.clone())) {
            return self.resolve_exported_class(
                &target.file,
                &target.name.clone().unwrap_or(name),
                0,
            );
        }
        None
    }

    fn resolve_exported_class(
        &self,
        file: &str,
        name: &str,
        depth: usize,
    ) -> Option<(String, String)> {
        if depth >= 64 {
            return None;
        }
        let key = (file.to_string(), name.to_string());
        if self.classes.contains_key(&key) {
            return Some(key);
        }
        if let Some(target) = self.imports.get(&(file.to_string(), name.to_string()))
            && let Some(key) = self.resolve_exported_class(
                &target.file,
                target.name.as_deref().unwrap_or(name),
                depth + 1,
            )
        {
            return Some(key);
        }
        for target_file in self.wildcard_imports.get(file).into_iter().flatten() {
            if let Some(key) = self.resolve_exported_class(target_file, name, depth + 1) {
                return Some(key);
            }
        }
        None
    }
}

fn collect_python_wildcard_imports(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    wildcard_imports: &mut BTreeMap<String, Vec<String>>,
) {
    for line in parsed.text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("from ") else {
            continue;
        };
        let Some((module, imported)) = rest.split_once(" import ") else {
            continue;
        };
        if imported.trim() != "*" {
            continue;
        }
        if let Some(module_file) = resolve_python_module(parsed, module_index, module.trim()) {
            wildcard_imports
                .entry(parsed.source.path.clone())
                .or_default()
                .push(module_file);
        }
    }
}

fn python_class_bases(parsed: &ParsedFile, node: Node<'_>) -> Vec<String> {
    node.child_by_field_name("superclasses")
        .or_else(|| {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .find(|child| child.kind() == "argument_list")
        })
        .map(|bases| {
            let mut cursor = bases.walk();
            bases
                .children(&mut cursor)
                .filter(|base| base.is_named())
                .filter_map(|base| parsed.text_for(base).map(clean_python_base))
                .collect()
        })
        .unwrap_or_default()
}

fn clean_python_base(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ' ' | '\n' | '\r' | '\t'))
        .to_string()
}

fn direct_class_assignments(class_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = class_node.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut assignments = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor).filter(|child| child.is_named()) {
        if child.kind() == "assignment" {
            assignments.push(child);
        } else if child.kind() == "expression_statement"
            && let Some(assignment) = find_direct_child_kind(child, "assignment")
        {
            assignments.push(assignment);
        }
    }
    assignments
}

fn python_class_method_node<'tree>(
    class_node: Node<'tree>,
    parsed: &ParsedFile,
    method_name: &str,
) -> Option<Node<'tree>> {
    let body = class_node.child_by_field_name("body")?;
    let mut cursor = body.walk();
    for child in body.children(&mut cursor).filter(|child| child.is_named()) {
        let method = if child.kind() == "function_definition" {
            Some(child)
        } else if child.kind() == "decorated_definition" {
            find_direct_child_kind(child, "function_definition")
        } else {
            None
        };
        if let Some(method) = method
            && function_name(parsed, method).as_deref() == Some(method_name)
        {
            return Some(method);
        }
    }
    None
}

fn django_handler_nodes<'tree>(
    parsed: &'tree ParsedFile,
    route: &authmap_core::Route,
    handler: &SymbolRef,
) -> Vec<Node<'tree>> {
    let Some(metadata) = django_route_metadata(route) else {
        return python_function_node(parsed, &handler.name)
            .into_iter()
            .collect();
    };
    match metadata.handler_kind.as_deref() {
        Some("function") => python_function_node(parsed, &handler.name)
            .into_iter()
            .collect(),
        Some("class_based_view") => {
            let Some(class_name) = metadata.class_name.as_deref() else {
                return Vec::new();
            };
            django_class_method_nodes(parsed, class_name, &django_http_methods_for_route(route))
        }
        Some("viewset_standard") | Some("viewset_action") => {
            let Some(class_name) = metadata.class_name.as_deref() else {
                return Vec::new();
            };
            let Some(method_name) = metadata.method_name.as_deref() else {
                return Vec::new();
            };
            django_class_method_nodes(parsed, class_name, &[method_name.to_string()])
        }
        _ => Vec::new(),
    }
}

#[derive(Clone, Debug, Default)]
struct DjangoRouteMetadata {
    handler_kind: Option<String>,
    class_name: Option<String>,
    method_name: Option<String>,
}

fn django_route_metadata(route: &authmap_core::Route) -> Option<DjangoRouteMetadata> {
    let value = route.extensions.get("authmap.django")?;
    Some(DjangoRouteMetadata {
        handler_kind: value
            .get("handler_kind")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        class_name: value
            .get("class_name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        method_name: value
            .get("method_name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    })
}

fn django_http_methods_for_route(route: &authmap_core::Route) -> Vec<String> {
    if route.method == "ANY" {
        ["get", "post", "put", "patch", "delete"]
            .into_iter()
            .map(str::to_string)
            .collect()
    } else {
        vec![route.method.to_ascii_lowercase()]
    }
}

fn python_function_node<'tree>(
    parsed: &'tree ParsedFile,
    target_name: &str,
) -> Option<Node<'tree>> {
    let root = parsed.root_node()?;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition"
            && function_name(parsed, node).as_deref() == Some(target_name)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn django_class_method_nodes<'tree>(
    parsed: &'tree ParsedFile,
    class_name: &str,
    method_names: &[String],
) -> Vec<Node<'tree>> {
    let Some(class_node) = python_class_node(parsed, class_name) else {
        return Vec::new();
    };
    let wanted = method_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut nodes = Vec::new();
    let mut stack = vec![class_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition"
            && let Some(name) = function_name(parsed, node)
            && wanted.contains(name.as_str())
        {
            nodes.push(node);
        }
        if node != class_node && is_nested_scope_node(node) {
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    nodes
}

fn python_class_node<'tree>(parsed: &'tree ParsedFile, class_name: &str) -> Option<Node<'tree>> {
    let root = parsed.root_node()?;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "class_definition"
            && function_name(parsed, node).as_deref() == Some(class_name)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn node_containing_span<'tree>(node: Node<'tree>, span: &Span) -> Option<Node<'tree>> {
    let range = span.byte_range?;
    if node.start_byte() as u64 > range.start || (node.end_byte() as u64) < range.end {
        return None;
    }
    let mut best = node;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(candidate) = node_containing_span(child, span) {
            best = candidate;
        }
    }
    Some(best)
}

fn function_name(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|name| parsed.text_for(name).map(str::to_string))
}

fn variable_function_name(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    let value = node.child_by_field_name("value")?;
    if !matches!(
        value.kind(),
        "arrow_function" | "function" | "function_expression"
    ) {
        return None;
    }
    node.child_by_field_name("name")
        .and_then(|name| parsed.text_for(name).map(str::to_string))
}

fn first_symbol_argument(parsed: &ParsedFile, call: Node<'_>) -> Option<SymbolRef> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments
        .children(&mut cursor)
        .filter(|child| child.is_named())
    {
        let name = match child.kind() {
            "identifier" | "member_expression" | "attribute" => parsed.text_for(child),
            "call" | "call_expression" => child
                .child_by_field_name("function")
                .and_then(|function| parsed.text_for(function)),
            _ => None,
        };
        if let Some(name) = name {
            return Some(SymbolRef {
                name: terminal_symbol_name(name),
                span: Some(parsed.span_for(child)),
            });
        }
    }
    None
}

fn find_direct_child_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn terminal_symbol_name(text: &str) -> String {
    text.rsplit(['.', ':']).next().unwrap_or(text).to_string()
}

fn is_fastapi_depends(function_text: &str) -> bool {
    matches!(
        terminal_symbol_name(function_text).as_str(),
        "Depends" | "Security"
    )
}

fn is_framework_route_call(function_text: &str) -> bool {
    matches!(
        terminal_symbol_name(function_text).as_str(),
        "get"
            | "post"
            | "put"
            | "patch"
            | "delete"
            | "api_route"
            | "route"
            | "use"
            | "path"
            | "re_path"
            | "include"
            | "register"
            | "action"
    )
}

fn looks_dynamic_policy(function_text: &str) -> bool {
    let lower = function_text.to_ascii_lowercase();
    lower.contains("policy") || lower.contains("authorize_dynamic")
}

fn dedup_evidence(evidence: &mut Vec<Evidence>) {
    let mut seen = BTreeSet::new();
    evidence.retain(|item| {
        seen.insert((
            item.route_id.clone(),
            item.evidence_type,
            item.mechanism.clone(),
            item.symbol.as_ref().map(|symbol| symbol.name.clone()),
            item.span
                .as_ref()
                .map(|span| (span.file.clone(), span.line, span.column)),
        ))
    });
}

fn evidence_sort_key(evidence: &Evidence) -> (String, String, u32, u32, EvidenceType, String) {
    (
        evidence.route_id.clone().unwrap_or_default(),
        evidence
            .span
            .as_ref()
            .map_or_else(String::new, |span| span.file.clone()),
        evidence.span.as_ref().map_or(0, |span| span.line),
        evidence.span.as_ref().map_or(0, |span| span.column),
        evidence.evidence_type,
        evidence.mechanism.clone(),
    )
}

fn classify_coverage(
    routes: &[authmap_core::Route],
    evidence: &[Evidence],
    mutations: &[Mutation],
    links: &[ReachabilityLink],
    config: &ScanConfig,
) -> Vec<Coverage> {
    let index = CoverageIndex::new(evidence, mutations, links, config);
    routes
        .iter()
        .map(|route| classify_route(route, &index.route_facts(route)))
        .collect()
}

#[derive(Clone, Debug, Default)]
struct CoverageRouteFacts<'a> {
    evidence: Vec<&'a Evidence>,
    linked_mutations: Vec<&'a Mutation>,
    links: Vec<&'a ReachabilityLink>,
    configured_sensitivity_reasons: Vec<String>,
    configured_reviewer_questions: Vec<String>,
}

#[derive(Clone, Debug)]
struct CoverageIndex<'a> {
    evidence_by_route: BTreeMap<&'a str, Vec<&'a Evidence>>,
    mutations_by_id: BTreeMap<&'a str, &'a Mutation>,
    links_by_route: BTreeMap<&'a str, Vec<&'a ReachabilityLink>>,
    config: &'a ScanConfig,
}

impl<'a> CoverageIndex<'a> {
    fn new(
        evidence: &'a [Evidence],
        mutations: &'a [Mutation],
        links: &'a [ReachabilityLink],
        config: &'a ScanConfig,
    ) -> Self {
        let mut evidence_by_route = BTreeMap::<&str, Vec<&Evidence>>::new();
        for item in evidence {
            if let Some(route_id) = &item.route_id {
                evidence_by_route
                    .entry(route_id.as_str())
                    .or_default()
                    .push(item);
            }
        }
        for link in links {
            if let Some(evidence_id) = &link.evidence_id
                && let Some(item) = evidence.iter().find(|item| item.id == *evidence_id)
            {
                evidence_by_route
                    .entry(link.route_id.as_str())
                    .or_default()
                    .push(item);
            }
        }
        for evidence in evidence_by_route.values_mut() {
            evidence.sort_by(|left, right| left.id.cmp(&right.id));
            evidence.dedup_by(|left, right| left.id == right.id);
        }

        let mutations_by_id = mutations
            .iter()
            .map(|mutation| (mutation.id.as_str(), mutation))
            .collect::<BTreeMap<_, _>>();
        let mut links_by_route = BTreeMap::<&str, Vec<&ReachabilityLink>>::new();
        for link in links {
            links_by_route
                .entry(link.route_id.as_str())
                .or_default()
                .push(link);
        }
        for route_links in links_by_route.values_mut() {
            route_links.sort_by(|left, right| left.id.cmp(&right.id));
        }

        Self {
            evidence_by_route,
            mutations_by_id,
            links_by_route,
            config,
        }
    }

    fn route_facts(&self, route: &authmap_core::Route) -> CoverageRouteFacts<'a> {
        let evidence = self
            .evidence_by_route
            .get(route.id.as_str())
            .cloned()
            .unwrap_or_default();
        let links = self
            .links_by_route
            .get(route.id.as_str())
            .cloned()
            .unwrap_or_default();
        let mut linked_mutations = links
            .iter()
            .filter_map(|link| {
                link.mutation_id
                    .as_deref()
                    .and_then(|mutation_id| self.mutations_by_id.get(mutation_id).copied())
            })
            .collect::<Vec<_>>();
        linked_mutations.sort_by(|left, right| left.id.cmp(&right.id));
        linked_mutations.dedup_by(|left, right| left.id == right.id);
        let (configured_sensitivity_reasons, configured_reviewer_questions) =
            configured_sensitivity(route, &linked_mutations, self.config);

        CoverageRouteFacts {
            evidence,
            linked_mutations,
            links,
            configured_sensitivity_reasons,
            configured_reviewer_questions,
        }
    }
}

fn classify_route(route: &authmap_core::Route, facts: &CoverageRouteFacts<'_>) -> Coverage {
    let evidence = facts.evidence.as_slice();
    let coverage_evidence = evidence
        .iter()
        .copied()
        .filter(|item| item.evidence_type != EvidenceType::AuditLog)
        .collect::<Vec<_>>();
    let strong = coverage_evidence
        .iter()
        .copied()
        .filter(|item| item.confidence != Confidence::Low)
        .filter(|item| item.evidence_type != EvidenceType::UnknownDynamicCheck)
        .collect::<Vec<_>>();
    let weak = coverage_evidence
        .iter()
        .copied()
        .filter(|item| {
            item.confidence == Confidence::Low
                || item.evidence_type == EvidenceType::UnknownDynamicCheck
        })
        .collect::<Vec<_>>();
    let sensitivity = sensitivity_reasons(
        route,
        !facts.linked_mutations.is_empty(),
        &facts.configured_sensitivity_reasons,
    );
    let sensitive = !sensitivity.is_empty();
    let has_linked_mutations = !facts.linked_mutations.is_empty();

    let class = coverage_class(&strong, &coverage_evidence);
    let risk = coverage_risk(
        route,
        class,
        &coverage_evidence,
        &strong,
        &weak,
        sensitive,
        has_linked_mutations,
    );
    let tenant_review_reasons = tenant_review_reasons(route, &strong, &weak, &sensitivity, facts);
    let risk = if tenant_review_reasons.is_empty() {
        risk
    } else {
        RiskLevel::ReviewRequired
    };
    let mut reviewer_questions = reviewer_questions(
        route,
        class,
        sensitive,
        has_linked_mutations,
        &facts.configured_reviewer_questions,
    );
    if !tenant_review_reasons.is_empty() {
        reviewer_questions
            .push("Should this route require tenant or ownership scoping?".to_string());
    }
    if risk == RiskLevel::High && reviewer_questions.is_empty() {
        reviewer_questions
            .push("Should this route have server-side authorization evidence?".to_string());
    }
    reviewer_questions.sort();
    reviewer_questions.dedup();
    let mut rationale = coverage_rationale(
        class,
        risk,
        &strong,
        &weak,
        &sensitivity,
        has_linked_mutations,
    );
    if !tenant_review_reasons.is_empty() {
        rationale.push(format!(
            "Tenant isolation review required: {}.",
            tenant_review_reasons.join(", ")
        ));
    }
    let mut extensions = coverage_extensions(evidence, &weak, facts, &sensitivity);
    if !tenant_review_reasons.is_empty() {
        extensions.insert(
            "authmap.tenant_review".to_string(),
            serde_json::json!({
                "review_required": true,
                "reasons": tenant_review_reasons,
                "evidence_ids": sorted_ids(strong.iter().filter(|item| {
                    matches!(
                        item.evidence_type,
                        EvidenceType::TenantCheck | EvidenceType::OwnershipCheck
                    )
                }).map(|item| item.id.as_str())),
                "weak_evidence_ids": sorted_ids(weak.iter().filter(|item| {
                    matches!(
                        item.evidence_type,
                        EvidenceType::TenantCheck | EvidenceType::OwnershipCheck
                    )
                }).map(|item| item.id.as_str())),
            }),
        );
    }

    Coverage {
        route_id: route.id.clone(),
        class,
        risk,
        rationale,
        reviewer_questions,
        uncertainty_reasons: uncertainty_reasons(route, evidence),
        extensions,
    }
}

fn tenant_review_reasons(
    route: &authmap_core::Route,
    strong: &[&Evidence],
    weak: &[&Evidence],
    sensitivity: &[String],
    facts: &CoverageRouteFacts<'_>,
) -> Vec<String> {
    let has_strong_scope = strong.iter().any(|item| {
        matches!(
            item.evidence_type,
            EvidenceType::TenantCheck | EvidenceType::OwnershipCheck
        )
    });
    if has_strong_scope {
        return Vec::new();
    }

    let mut reasons = Vec::new();
    let has_scope_signal = weak.iter().any(|item| {
        matches!(
            item.evidence_type,
            EvidenceType::TenantCheck | EvidenceType::OwnershipCheck
        )
    });
    let tenant_like_path_param = route
        .params
        .iter()
        .any(|param| scope_evidence_type(&param.name).is_some());
    let has_path_param = !route.params.is_empty();
    let sensitive_for_tenants = !sensitivity.is_empty()
        || tenant_like_path_param
        || !facts.linked_mutations.is_empty()
        || unsafe_method(route);

    if sensitive_for_tenants && (!facts.linked_mutations.is_empty() || tenant_like_path_param) {
        reasons.push("missing_tenant_or_ownership_evidence".to_string());
    }
    if has_scope_signal {
        reasons.push("only_weak_tenant_or_ownership_signal".to_string());
    }
    if has_path_param && !facts.linked_mutations.is_empty() {
        reasons.push("route_param_mutation_without_scope".to_string());
    }
    if route.path.to_ascii_lowercase().contains("admin")
        && (!facts.linked_mutations.is_empty() || tenant_like_path_param)
    {
        reasons.push("admin_bypass_requires_tenant_review".to_string());
    }

    reasons.sort();
    reasons.dedup();
    reasons
}

fn coverage_class(strong: &[&Evidence], all_evidence: &[&Evidence]) -> CoverageClass {
    if has_type(strong, EvidenceType::ExplicitPublic) {
        CoverageClass::PublicDeclared
    } else if has_type(strong, EvidenceType::AdminCheck) {
        CoverageClass::AdminGuarded
    } else if has_type(strong, EvidenceType::PermissionCheck) {
        CoverageClass::PermissionGuarded
    } else if has_type(strong, EvidenceType::OwnershipCheck) {
        CoverageClass::OwnershipGuarded
    } else if has_type(strong, EvidenceType::TenantCheck) {
        CoverageClass::TenantGuarded
    } else if has_type(strong, EvidenceType::RoleCheck) {
        CoverageClass::RoleGuarded
    } else if has_type(strong, EvidenceType::Authn) {
        CoverageClass::AuthnOnly
    } else if all_evidence.is_empty() {
        CoverageClass::Unauthenticated
    } else {
        CoverageClass::UnknownOrDynamic
    }
}

fn coverage_risk(
    route: &authmap_core::Route,
    class: CoverageClass,
    all_evidence: &[&Evidence],
    strong: &[&Evidence],
    weak: &[&Evidence],
    sensitive: bool,
    has_linked_mutations: bool,
) -> RiskLevel {
    if strong.is_empty() && !weak.is_empty() {
        return RiskLevel::ReviewRequired;
    }
    if all_evidence.is_empty() {
        if has_linked_mutations || unsafe_method(route) {
            return RiskLevel::High;
        }
        if sensitive {
            return RiskLevel::Medium;
        }
        return RiskLevel::Low;
    }
    match class {
        CoverageClass::PublicDeclared if sensitive => RiskLevel::ReviewRequired,
        CoverageClass::AuthnOnly if sensitive || has_linked_mutations => RiskLevel::ReviewRequired,
        CoverageClass::UnknownOrDynamic => RiskLevel::ReviewRequired,
        CoverageClass::AdminGuarded
        | CoverageClass::RoleGuarded
        | CoverageClass::PermissionGuarded
        | CoverageClass::AuthnOnly
            if has_linked_mutations =>
        {
            RiskLevel::ReviewRequired
        }
        _ => RiskLevel::Low,
    }
}

fn has_type(evidence: &[&Evidence], evidence_type: EvidenceType) -> bool {
    evidence
        .iter()
        .any(|item| item.evidence_type == evidence_type)
}

fn sensitivity_reasons(
    route: &authmap_core::Route,
    has_linked_mutations: bool,
    configured_reasons: &[String],
) -> Vec<String> {
    let mut reasons = Vec::new();
    let lower_path = route.path.to_ascii_lowercase();
    if unsafe_method(route) {
        reasons.push("unsafe_method".to_string());
    }
    if route.method == "ANY" {
        reasons.push("any_method".to_string());
    }
    if lower_path.contains('{') || lower_path.contains(':') {
        reasons.push("path_param".to_string());
    }
    if lower_path.contains("admin") {
        reasons.push("admin_path".to_string());
    }
    if lower_path.contains("account") {
        reasons.push("account_path".to_string());
    }
    if lower_path.contains("user") {
        reasons.push("user_path".to_string());
    }
    if lower_path.contains("tenant") {
        reasons.push("tenant_path".to_string());
    }
    if has_linked_mutations {
        reasons.push("linked_mutation".to_string());
    }
    reasons.extend(configured_reasons.iter().cloned());
    reasons.sort();
    reasons.dedup();
    reasons
}

fn configured_sensitivity(
    route: &authmap_core::Route,
    linked_mutations: &[&Mutation],
    config: &ScanConfig,
) -> (Vec<String>, Vec<String>) {
    let mut reasons = Vec::new();
    let mut reviewer_questions = Vec::new();

    for rule in &config.sensitivity.routes {
        if route_sensitivity_matches(rule, route) {
            reasons.extend(
                rule.labels
                    .iter()
                    .map(|label| format!("config_route:{label}")),
            );
            reviewer_questions.extend(rule.reviewer_questions.iter().cloned());
        }
    }

    for mutation in linked_mutations {
        for rule in &config.sensitivity.resources {
            if resource_sensitivity_matches(rule, mutation) {
                reasons.extend(
                    rule.labels
                        .iter()
                        .map(|label| format!("config_resource:{label}")),
                );
                reviewer_questions.extend(rule.reviewer_questions.iter().cloned());
            }
        }
    }

    reasons.sort();
    reasons.dedup();
    reviewer_questions.sort();
    reviewer_questions.dedup();
    (reasons, reviewer_questions)
}

fn route_sensitivity_matches(rule: &RouteSensitivityRule, route: &authmap_core::Route) -> bool {
    if !rule.methods.is_empty()
        && !rule
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&route.method))
    {
        return false;
    }
    matcher_matches(&rule.matcher, &route.path)
}

fn resource_sensitivity_matches(rule: &ResourceSensitivityRule, mutation: &Mutation) -> bool {
    mutation
        .resource
        .as_deref()
        .is_some_and(|resource| matcher_matches(&rule.matcher, resource))
}

fn matcher_matches(matcher: &AuthorizationRuleMatch, value: &str) -> bool {
    let lower_value = value.to_ascii_lowercase();
    matcher.exact.iter().any(|item| item == value)
        || matcher
            .contains
            .iter()
            .any(|item| lower_value.contains(&item.to_ascii_lowercase()))
}

fn unsafe_method(route: &authmap_core::Route) -> bool {
    matches!(
        route.method.as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE" | "ANY"
    )
}

fn reviewer_questions(
    route: &authmap_core::Route,
    class: CoverageClass,
    sensitive: bool,
    has_linked_mutations: bool,
    configured_questions: &[String],
) -> Vec<String> {
    let mut questions = Vec::new();
    let lower_path = route.path.to_ascii_lowercase();
    if unsafe_method(route) {
        questions
            .push("Should this state-changing route require more than authentication?".to_string());
    }
    if lower_path.contains("admin") {
        questions.push("Should this route require an admin or role guard?".to_string());
    }
    if lower_path.contains("account")
        || lower_path.contains("user")
        || lower_path.contains('{')
        || lower_path.contains(':')
    {
        questions.push("Should this route require ownership or permission checks?".to_string());
    }
    if lower_path.contains("tenant") {
        questions.push("Should this route require tenant isolation checks?".to_string());
    }
    if has_linked_mutations {
        questions.push(
            "Should linked data mutations have resource-specific authorization evidence?"
                .to_string(),
        );
    }
    if class == CoverageClass::PublicDeclared && sensitive {
        questions.push("Is this sensitive route intentionally public?".to_string());
    }
    if class == CoverageClass::UnknownOrDynamic {
        questions.push("Can the dynamic authorization path be confirmed?".to_string());
    }
    questions.extend(configured_questions.iter().cloned());
    questions.sort();
    questions.dedup();
    questions
}

fn uncertainty_reasons(route: &authmap_core::Route, evidence: &[&Evidence]) -> Vec<String> {
    let mut reasons = Vec::new();
    if evidence
        .iter()
        .any(|item| item.confidence == Confidence::Low)
    {
        reasons.push("Low-confidence authorization evidence was detected.".to_string());
    }
    if evidence
        .iter()
        .any(|item| item.evidence_type == EvidenceType::UnknownDynamicCheck)
    {
        reasons.push("Dynamic authorization evidence requires review.".to_string());
    }
    if route.confidence != Confidence::High {
        reasons.push("Route inventory confidence is not high.".to_string());
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn coverage_rationale(
    class: CoverageClass,
    risk: RiskLevel,
    strong: &[&Evidence],
    weak: &[&Evidence],
    sensitivity: &[String],
    has_linked_mutations: bool,
) -> Vec<String> {
    let mut rationale = Vec::new();
    if strong.is_empty() && weak.is_empty() {
        rationale.push("No authorization evidence was detected.".to_string());
    } else if strong.is_empty() {
        rationale.push(format!(
            "{} weak or dynamic authorization evidence item(s) were detected.",
            weak.len()
        ));
    } else {
        rationale.push(format!(
            "{} strong authorization evidence item(s) support {} coverage.",
            strong.len(),
            coverage_class_slug(class)
        ));
    }
    if !sensitivity.is_empty() {
        rationale.push(format!(
            "Sensitive route modifier(s): {}.",
            sensitivity.join(", ")
        ));
    }
    if has_linked_mutations {
        rationale.push("Linked data mutation(s) increase review sensitivity.".to_string());
    }
    if risk == RiskLevel::High {
        rationale.push(
            "No strong authorization evidence was found for a high-sensitivity route.".to_string(),
        );
    }
    rationale
}

fn coverage_extensions(
    evidence: &[&Evidence],
    weak: &[&Evidence],
    facts: &CoverageRouteFacts<'_>,
    sensitivity: &[String],
) -> authmap_core::ExtensionMap {
    let mut extensions = authmap_core::ExtensionMap::new();
    extensions.insert(
        "authmap.coverage".to_string(),
        serde_json::json!({
            "evidence_ids": sorted_ids(evidence.iter().map(|item| item.id.as_str())),
            "weak_evidence_ids": sorted_ids(weak.iter().map(|item| item.id.as_str())),
            "mutation_ids": sorted_ids(facts.linked_mutations.iter().map(|item| item.id.as_str())),
            "link_ids": sorted_ids(facts.links.iter().map(|item| item.id.as_str())),
            "sensitivity_reasons": sensitivity,
        }),
    );
    extensions
}

fn sorted_ids<'a>(items: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut ids = items.map(str::to_string).collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn coverage_class_slug(class: CoverageClass) -> &'static str {
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

fn route_sort_key(route: &authmap_core::Route) -> (String, u32, String, String, String) {
    (
        route
            .span
            .as_ref()
            .map_or_else(String::new, |span| span.file.clone()),
        route.span.as_ref().map_or(0, |span| span.line),
        route.method.clone(),
        route.path.clone(),
        route
            .handler
            .as_ref()
            .map_or_else(String::new, |handler| handler.name.clone()),
    )
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error(transparent)]
    Discovery(#[from] authmap_discovery::DiscoveryError),
}

impl ScanError {
    pub fn is_target_unavailable(&self) -> bool {
        matches!(
            self,
            ScanError::Discovery(
                authmap_discovery::DiscoveryError::TargetUnavailable { .. }
                    | authmap_discovery::DiscoveryError::UnsupportedTarget { .. }
            )
        )
    }

    pub fn is_empty_target(&self) -> bool {
        matches!(
            self,
            ScanError::Discovery(authmap_discovery::DiscoveryError::EmptyTarget { .. })
        )
    }

    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            ScanError::Discovery(authmap_discovery::DiscoveryError::InvalidPattern { .. })
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use authmap_config::{ScanConfig, ScanPlan};
    use authmap_core::{
        Confidence, CoverageClass, Evidence, EvidenceType, Framework, Mutation, MutationOperation,
        PolicyCaseKind, ReachabilityLink, RiskLevel, Route, ScanMode, SourceFile, Span, SymbolRef,
        diagnostic_codes,
    };
    use authmap_parsers::{ParseStatus, ParsedFile};
    use authmap_testkit::fixture_path;

    use super::{
        classify_coverage, enabled_frameworks_for_sources, framework_name_for_hint,
        normalize_adapter_evidence, normalize_module_path, resolve_python_module, route_id_remaps,
        run_scan, run_scan_with_started_at, source_needs_syntax_tree, suggest_rules,
        suggest_rules_with_started_at,
    };

    #[test]
    fn route_params_normalize_fastapi_converter_names() {
        let params = super::route_params("/files/{file_path:path}");

        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "file_path");
        assert_eq!(params[0].syntax, "{file_path:path}");
    }

    #[test]
    fn route_protection_ignores_middleware_without_auth_evidence() {
        let mut route = route("route.audit", "GET", "/audit");
        route.middleware.push(SymbolRef {
            name: "audit".to_string(),
            span: None,
        });
        let audit_evidence = Evidence {
            id: "evidence.audit".to_string(),
            route_id: Some("route.audit".to_string()),
            evidence_type: EvidenceType::AuditLog,
            mechanism: "audit_log".to_string(),
            symbol: Some(SymbolRef {
                name: "audit".to_string(),
                span: None,
            }),
            span: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        };

        let protections = super::route_protection(&route, &[&audit_evidence]);

        assert!(protections.is_empty());
    }

    #[test]
    fn python_syntax_tree_relevance_keeps_tree_backed_patterns_only() {
        let config = ScanConfig::default();

        assert!(source_needs_syntax_tree(
            authmap_core::Language::Python,
            "from fastapi import FastAPI\napp = FastAPI()\n",
            &config
        ));
        assert!(source_needs_syntax_tree(
            authmap_core::Language::Python,
            "urlpatterns = [path('items/', view)]\n",
            &config
        ));
        assert!(source_needs_syntax_tree(
            authmap_core::Language::Python,
            "class AccountDetailView:\n    permission_required = 'accounts.view_account'\n",
            &config
        ));
        assert!(source_needs_syntax_tree(
            authmap_core::Language::Python,
            "def save_item(item):\n    item.save()\n",
            &config
        ));
        assert!(source_needs_syntax_tree(
            authmap_core::Language::Python,
            &format!(
                "class ProductCreate(BaseMutation):\n    class Meta:\n        permissions = ()\n{}",
                "# generated schema\n".repeat(80)
            ),
            &config
        ));
        assert!(source_needs_syntax_tree(
            authmap_core::Language::Python,
            &format!(
                "class Mutation(sgqlc.types.Type):\n    field = sgqlc.types.Field(String)\n{}",
                "# generated schema\n".repeat(80)
            ),
            &config
        ));
        assert!(source_needs_syntax_tree(
            authmap_core::Language::Python,
            &format!(
                "from django.urls import path\n\ndef require_permission(user):\n    return user.is_staff\n{}",
                "# ordinary module padding\n".repeat(80)
            ),
            &config
        ));
        assert!(!source_needs_syntax_tree(
            authmap_core::Language::Python,
            &"# generated metadata only\n".repeat(80),
            &config
        ));
    }

    #[test]
    fn adapter_gating_keeps_graphql_schema_helpers_out_of_django_discovery() {
        let parsed = ParsedFile {
            source: SourceFile {
                path: "schema.py".to_string(),
                language: authmap_core::Language::Python,
                size_bytes: 0,
                sha256: None,
                project_hints: Vec::new(),
                skipped: None,
            },
            language: authmap_core::Language::Python,
            text: "\
from django.urls import reverse

class ProductCreate(BaseMutation):
    class Meta:
        permissions = ()
"
            .to_string(),
            tree: None,
            status: ParseStatus::TextOnly,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            enabled_frameworks_for_sources(&[parsed]),
            vec!["graphql".to_string()]
        );
    }

    #[test]
    fn adapter_gating_keeps_express_helpers_in_mixed_projects() {
        let helper = ParsedFile {
            source: SourceFile {
                path: "routes.js".to_string(),
                language: authmap_core::Language::JavaScript,
                size_bytes: 0,
                sha256: None,
                project_hints: Vec::new(),
                skipped: None,
            },
            language: authmap_core::Language::JavaScript,
            text: "setupApiRoute(router, 'GET', '/items', requireAuth, listItems);\n".to_string(),
            tree: None,
            status: ParseStatus::TextOnly,
            diagnostics: Vec::new(),
        };
        let next = ParsedFile {
            source: SourceFile {
                path: "app/api/items/route.ts".to_string(),
                language: authmap_core::Language::TypeScript,
                size_bytes: 0,
                sha256: None,
                project_hints: Vec::new(),
                skipped: None,
            },
            language: authmap_core::Language::TypeScript,
            text: "import { NextResponse } from 'next/server';\n".to_string(),
            tree: None,
            status: ParseStatus::TextOnly,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            enabled_frameworks_for_sources(&[helper, next]),
            vec!["express".to_string(), "nextjs".to_string()]
        );
    }

    #[test]
    fn adapter_gating_uses_project_hints_when_text_heuristics_miss() {
        // Aliased import: the file has no `FastAPI(` literal, so the text heuristic
        // alone would not enable the adapter. The discovery-provided hint must.
        let parsed = ParsedFile {
            source: SourceFile {
                path: "main.py".to_string(),
                language: authmap_core::Language::Python,
                size_bytes: 0,
                sha256: None,
                project_hints: vec![authmap_core::ProjectHint::FastApi],
                skipped: None,
            },
            language: authmap_core::Language::Python,
            text: "\
from fastapi import FastAPI as API

app = API()


@app.get(\"/items\")
def list_items():
    return []
"
            .to_string(),
            tree: None,
            status: ParseStatus::TextOnly,
            diagnostics: Vec::new(),
        };

        assert!(
            enabled_frameworks_for_sources(&[parsed]).contains(&"fastapi".to_string()),
            "fastapi adapter should be enabled via project hint despite the aliased import"
        );
    }

    #[test]
    fn framework_name_for_hint_maps_route_adapters_and_ignores_orm_hints() {
        use authmap_core::ProjectHint;
        assert_eq!(
            framework_name_for_hint(ProjectHint::FastApi),
            Some("fastapi")
        );
        assert_eq!(framework_name_for_hint(ProjectHint::Django), Some("django"));
        assert_eq!(
            framework_name_for_hint(ProjectHint::DjangoRestFramework),
            Some("django")
        );
        assert_eq!(
            framework_name_for_hint(ProjectHint::Express),
            Some("express")
        );
        assert_eq!(framework_name_for_hint(ProjectHint::NextJs), Some("nextjs"));
        assert_eq!(framework_name_for_hint(ProjectHint::SqlAlchemy), None);
        assert_eq!(framework_name_for_hint(ProjectHint::DjangoOrm), None);
        assert_eq!(framework_name_for_hint(ProjectHint::Prisma), None);
    }

    #[test]
    fn classifier_covers_all_coverage_classes() {
        let routes = vec![
            route("route_public", "GET", "/public"),
            route("route_admin", "GET", "/admin"),
            route("route_permission", "GET", "/accounts"),
            route("route_ownership", "GET", "/accounts/{account_id}"),
            route("route_tenant", "GET", "/tenants/{tenant_id}"),
            route("route_role", "GET", "/reports"),
            route("route_authn", "GET", "/profile"),
            route("route_unknown", "GET", "/dynamic"),
            route("route_unauth", "GET", "/health"),
        ];
        let evidence = vec![
            evidence(
                "evidence_public",
                "route_public",
                EvidenceType::ExplicitPublic,
                Confidence::High,
            ),
            evidence(
                "evidence_admin",
                "route_admin",
                EvidenceType::AdminCheck,
                Confidence::High,
            ),
            evidence(
                "evidence_permission",
                "route_permission",
                EvidenceType::PermissionCheck,
                Confidence::High,
            ),
            evidence(
                "evidence_ownership",
                "route_ownership",
                EvidenceType::OwnershipCheck,
                Confidence::High,
            ),
            evidence(
                "evidence_tenant",
                "route_tenant",
                EvidenceType::TenantCheck,
                Confidence::High,
            ),
            evidence(
                "evidence_role",
                "route_role",
                EvidenceType::RoleCheck,
                Confidence::High,
            ),
            evidence(
                "evidence_authn",
                "route_authn",
                EvidenceType::Authn,
                Confidence::High,
            ),
            evidence(
                "evidence_dynamic",
                "route_unknown",
                EvidenceType::UnknownDynamicCheck,
                Confidence::Low,
            ),
        ];

        let coverage = classify_coverage(&routes, &evidence, &[], &[], &ScanConfig::default());

        assert_coverage(
            &coverage,
            "route_public",
            CoverageClass::PublicDeclared,
            RiskLevel::Low,
        );
        assert_coverage(
            &coverage,
            "route_admin",
            CoverageClass::AdminGuarded,
            RiskLevel::Low,
        );
        assert_coverage(
            &coverage,
            "route_permission",
            CoverageClass::PermissionGuarded,
            RiskLevel::Low,
        );
        assert_coverage(
            &coverage,
            "route_ownership",
            CoverageClass::OwnershipGuarded,
            RiskLevel::Low,
        );
        assert_coverage(
            &coverage,
            "route_tenant",
            CoverageClass::TenantGuarded,
            RiskLevel::Low,
        );
        assert_coverage(
            &coverage,
            "route_role",
            CoverageClass::RoleGuarded,
            RiskLevel::Low,
        );
        assert_coverage(
            &coverage,
            "route_authn",
            CoverageClass::AuthnOnly,
            RiskLevel::Low,
        );
        assert_coverage(
            &coverage,
            "route_unknown",
            CoverageClass::UnknownOrDynamic,
            RiskLevel::ReviewRequired,
        );
        assert_coverage(
            &coverage,
            "route_unauth",
            CoverageClass::Unauthenticated,
            RiskLevel::Low,
        );
    }

    #[test]
    fn classifier_applies_v1_risk_matrix() {
        let routes = vec![
            route("route_delete", "DELETE", "/health"),
            route("route_user_read", "GET", "/users/{user_id}"),
            route("route_dynamic", "GET", "/policy"),
            route("route_authn_sensitive", "GET", "/accounts/{account_id}"),
            route(
                "route_public_sensitive",
                "DELETE",
                "/public/accounts/{account_id}",
            ),
        ];
        let evidence = vec![
            evidence(
                "evidence_dynamic",
                "route_dynamic",
                EvidenceType::UnknownDynamicCheck,
                Confidence::Low,
            ),
            evidence(
                "evidence_authn",
                "route_authn_sensitive",
                EvidenceType::Authn,
                Confidence::High,
            ),
            evidence(
                "evidence_public",
                "route_public_sensitive",
                EvidenceType::ExplicitPublic,
                Confidence::High,
            ),
        ];

        let coverage = classify_coverage(&routes, &evidence, &[], &[], &ScanConfig::default());

        assert_coverage(
            &coverage,
            "route_delete",
            CoverageClass::Unauthenticated,
            RiskLevel::High,
        );
        assert_coverage(
            &coverage,
            "route_user_read",
            CoverageClass::Unauthenticated,
            RiskLevel::Medium,
        );
        assert_coverage(
            &coverage,
            "route_dynamic",
            CoverageClass::UnknownOrDynamic,
            RiskLevel::ReviewRequired,
        );
        assert_coverage(
            &coverage,
            "route_authn_sensitive",
            CoverageClass::AuthnOnly,
            RiskLevel::ReviewRequired,
        );
        assert_coverage(
            &coverage,
            "route_public_sensitive",
            CoverageClass::PublicDeclared,
            RiskLevel::ReviewRequired,
        );
    }

    #[test]
    fn policy_cases_flag_conflict_duplicate_dynamic_unreachable_and_linked_context() {
        let routes = vec![
            route("route_conflict", "POST", "/public/accounts/:id"),
            route("route_duplicate", "GET", "/profile"),
            route("route_dynamic", "GET", "/policy"),
            route("route_unreachable", "GET", "/admin/disabled"),
        ];
        let mut public = evidence(
            "evidence_public",
            "route_conflict",
            EvidenceType::ExplicitPublic,
            Confidence::High,
        );
        public.mechanism = "public_marker".to_string();
        let mut authn = evidence(
            "evidence_authn",
            "route_conflict",
            EvidenceType::Authn,
            Confidence::High,
        );
        authn.mechanism = "authn_guard".to_string();

        let mut duplicate_one = evidence(
            "evidence_duplicate_1",
            "route_duplicate",
            EvidenceType::Authn,
            Confidence::High,
        );
        duplicate_one.mechanism = "authn_guard".to_string();
        duplicate_one.symbol = Some(SymbolRef {
            name: "requireAuth".to_string(),
            span: Some(Span {
                file: "src/routes.ts".to_string(),
                line: 7,
                column: 3,
                byte_range: None,
            }),
        });
        let mut duplicate_two = evidence(
            "evidence_duplicate_2",
            "route_duplicate",
            EvidenceType::Authn,
            Confidence::High,
        );
        duplicate_two.mechanism = "authn_guard".to_string();
        duplicate_two.symbol = Some(SymbolRef {
            name: "requireAuth".to_string(),
            span: Some(Span {
                file: "src/routes.ts".to_string(),
                line: 8,
                column: 3,
                byte_range: None,
            }),
        });

        let dynamic = evidence(
            "evidence_dynamic",
            "route_dynamic",
            EvidenceType::UnknownDynamicCheck,
            Confidence::Low,
        );
        let mut unreachable = evidence(
            "evidence_unreachable",
            "route_unreachable",
            EvidenceType::AdminCheck,
            Confidence::High,
        );
        unreachable.span = Some(Span {
            file: "src/routes.ts".to_string(),
            line: 3,
            column: 5,
            byte_range: None,
        });

        let mutations = vec![Mutation {
            id: "mutation_account".to_string(),
            operation: MutationOperation::Update,
            library: Some("prisma".to_string()),
            resource: Some("Account".to_string()),
            span: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        }];
        let links = vec![ReachabilityLink {
            id: "link_account".to_string(),
            route_id: "route_conflict".to_string(),
            mutation_id: Some("mutation_account".to_string()),
            evidence_id: Some("evidence_authn".to_string()),
            confidence: Confidence::Medium,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        }];
        let parsed_files = vec![ParsedFile {
            source: SourceFile {
                path: "src/routes.ts".to_string(),
                language: authmap_core::Language::TypeScript,
                size_bytes: 128,
                sha256: None,
                project_hints: Vec::new(),
                skipped: None,
            },
            language: authmap_core::Language::TypeScript,
            text: "router.get('/admin/disabled', (req, res) => {\n  if (false) {\n    requireAdmin(req)\n  }\n})\n".to_string(),
            tree: None,
            status: ParseStatus::TextOnly,
            diagnostics: Vec::new(),
        }];
        let evidence = vec![
            public,
            authn,
            duplicate_one,
            duplicate_two,
            dynamic,
            unreachable,
        ];

        let (cases, diagnostics) =
            super::derive_policy_cases(&routes, &evidence, &mutations, &links, &parsed_files);

        assert!(cases.iter().any(|case| {
            case.route_id == "route_conflict"
                && case.kind == PolicyCaseKind::Conflict
                && case.evidence_ids == vec!["evidence_authn", "evidence_public"]
        }));
        assert!(cases.iter().any(|case| {
            case.route_id == "route_duplicate"
                && case.kind == PolicyCaseKind::Duplicate
                && case.evidence_ids == vec!["evidence_duplicate_1", "evidence_duplicate_2"]
        }));
        assert!(cases.iter().any(|case| {
            case.route_id == "route_dynamic" && case.kind == PolicyCaseKind::Dynamic
        }));
        assert!(cases.iter().any(|case| {
            case.route_id == "route_unreachable" && case.kind == PolicyCaseKind::Unreachable
        }));
        assert!(cases.iter().any(|case| {
            case.route_id == "route_conflict"
                && case.kind == PolicyCaseKind::LinkedMutationProtection
                && case.summary.contains("mutation_account")
        }));
        assert_eq!(
            cases
                .iter()
                .map(|case| case.id.as_str())
                .collect::<Vec<_>>(),
            (1..=cases.len())
                .map(|index| format!("policy_case_{index:04}"))
                .collect::<Vec<_>>()
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "policy.conflicting_evidence"
                && diagnostic.message.contains("explicit public")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "policy.duplicate_evidence"
                && diagnostic.message.contains("requireAuth")
        }));
    }

    #[test]
    fn policy_cases_include_audit_support_without_treating_audit_only_as_protection() {
        let routes = vec![
            route("route_auth_audit", "GET", "/profile"),
            route("route_audit_only", "GET", "/audit"),
        ];
        let evidence = vec![
            evidence(
                "evidence_authn",
                "route_auth_audit",
                EvidenceType::Authn,
                Confidence::High,
            ),
            evidence(
                "evidence_audit",
                "route_auth_audit",
                EvidenceType::AuditLog,
                Confidence::High,
            ),
            evidence(
                "evidence_audit_only",
                "route_audit_only",
                EvidenceType::AuditLog,
                Confidence::High,
            ),
        ];

        let (cases, diagnostics) = super::derive_policy_cases(&routes, &evidence, &[], &[], &[]);

        let auth_audit_case = cases
            .iter()
            .find(|case| {
                case.route_id == "route_auth_audit"
                    && case.kind == PolicyCaseKind::EffectiveProtection
            })
            .expect("auth plus audit evidence should produce an effective policy case");
        assert_eq!(
            auth_audit_case.evidence_ids,
            vec!["evidence_audit", "evidence_authn"]
        );
        assert!(auth_audit_case.summary.contains("audit_log"));
        assert!(auth_audit_case.summary.contains("authn"));
        assert_eq!(auth_audit_case.input_names, vec!["identity"]);

        assert!(!cases.iter().any(|case| {
            case.route_id == "route_audit_only" && case.kind == PolicyCaseKind::EffectiveProtection
        }));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn classifier_consumes_existing_linked_mutations_and_support_metadata() {
        let routes = vec![
            route("route_mutation", "GET", "/status"),
            route("route_role_mutation", "GET", "/admin/jobs"),
        ];
        let evidence = vec![evidence(
            "evidence_role",
            "route_role_mutation",
            EvidenceType::RoleCheck,
            Confidence::High,
        )];
        let mutations = vec![Mutation {
            id: "mutation_0001".to_string(),
            operation: MutationOperation::Delete,
            library: Some("sqlalchemy".to_string()),
            resource: Some("Account".to_string()),
            span: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        }];
        let links = vec![
            ReachabilityLink {
                id: "link_0001".to_string(),
                route_id: "route_mutation".to_string(),
                mutation_id: Some("mutation_0001".to_string()),
                evidence_id: None,
                confidence: Confidence::Medium,
                notes: Vec::new(),
                extensions: authmap_core::ExtensionMap::new(),
            },
            ReachabilityLink {
                id: "link_0002".to_string(),
                route_id: "route_role_mutation".to_string(),
                mutation_id: Some("mutation_0001".to_string()),
                evidence_id: Some("evidence_role".to_string()),
                confidence: Confidence::Medium,
                notes: Vec::new(),
                extensions: authmap_core::ExtensionMap::new(),
            },
        ];

        let coverage = classify_coverage(
            &routes,
            &evidence,
            &mutations,
            &links,
            &ScanConfig::default(),
        );
        let item = coverage
            .iter()
            .find(|coverage| coverage.route_id == "route_mutation")
            .expect("route should be classified");
        assert_eq!(item.class, CoverageClass::Unauthenticated);
        assert_eq!(item.risk, RiskLevel::ReviewRequired);
        let support = item
            .extensions
            .get("authmap.coverage")
            .expect("coverage support extension should exist");
        assert_eq!(
            support["mutation_ids"],
            serde_json::json!(["mutation_0001"])
        );
        assert_eq!(support["link_ids"], serde_json::json!(["link_0001"]));
        assert_eq!(
            support["sensitivity_reasons"],
            serde_json::json!(["linked_mutation"])
        );
        assert!(item.extensions.contains_key("authmap.tenant_review"));

        let role_item = coverage
            .iter()
            .find(|coverage| coverage.route_id == "route_role_mutation")
            .expect("role-guarded route should be classified");
        assert_eq!(role_item.class, CoverageClass::RoleGuarded);
        assert_eq!(role_item.risk, RiskLevel::ReviewRequired);
        let support = role_item
            .extensions
            .get("authmap.coverage")
            .expect("coverage support extension should exist");
        assert_eq!(
            support["evidence_ids"],
            serde_json::json!(["evidence_role"])
        );
        assert_eq!(
            support["mutation_ids"],
            serde_json::json!(["mutation_0001"])
        );
        assert_eq!(support["link_ids"], serde_json::json!(["link_0002"]));
    }

    #[test]
    fn configured_route_sensitivity_affects_risk_and_questions() {
        let routes = vec![route("route_reports", "GET", "/internal/reports")];
        let config: ScanConfig = serde_yaml::from_str(
            r#"
sensitivity:
  routes:
    - name: internal reports
      labels: [business_critical]
      match:
        contains: [/internal/reports]
      methods: [GET]
      reviewer_questions:
        - Should reports require a permission guard?
"#,
        )
        .expect("config should parse");

        let coverage = classify_coverage(&routes, &[], &[], &[], &config);
        let item = coverage
            .iter()
            .find(|coverage| coverage.route_id == "route_reports")
            .expect("route should be classified");

        assert_eq!(item.class, CoverageClass::Unauthenticated);
        assert_eq!(item.risk, RiskLevel::Medium);
        assert!(
            item.reviewer_questions
                .iter()
                .any(|question| { question == "Should reports require a permission guard?" })
        );
        let support = item
            .extensions
            .get("authmap.coverage")
            .expect("coverage support extension should exist");
        assert_eq!(
            support["sensitivity_reasons"],
            serde_json::json!(["config_route:business_critical"])
        );
    }

    #[test]
    fn configured_resource_sensitivity_uses_existing_mutation_links() {
        let routes = vec![route("route_invoice_job", "GET", "/jobs/invoice-sync")];
        let mutations = vec![Mutation {
            id: "mutation_0001".to_string(),
            operation: MutationOperation::Update,
            library: Some("sqlalchemy".to_string()),
            resource: Some("Invoice".to_string()),
            span: None,
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        }];
        let links = vec![ReachabilityLink {
            id: "link_0001".to_string(),
            route_id: "route_invoice_job".to_string(),
            mutation_id: Some("mutation_0001".to_string()),
            evidence_id: None,
            confidence: Confidence::Medium,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        }];
        let config: ScanConfig = serde_yaml::from_str(
            r#"
sensitivity:
  resources:
    - name: invoices
      labels: [financial]
      match:
        exact: [Invoice]
      reviewer_questions:
        - Should invoice writes require finance approval?
"#,
        )
        .expect("config should parse");

        let coverage = classify_coverage(&routes, &[], &mutations, &links, &config);
        let item = coverage
            .iter()
            .find(|coverage| coverage.route_id == "route_invoice_job")
            .expect("route should be classified");

        assert_eq!(item.class, CoverageClass::Unauthenticated);
        assert_eq!(item.risk, RiskLevel::ReviewRequired);
        assert_eq!(
            item.reviewer_questions,
            vec![
                "Should invoice writes require finance approval?".to_string(),
                "Should linked data mutations have resource-specific authorization evidence?"
                    .to_string(),
                "Should this route require tenant or ownership scoping?".to_string(),
            ]
        );
        let support = item
            .extensions
            .get("authmap.coverage")
            .expect("coverage support extension should exist");
        assert_eq!(
            support["sensitivity_reasons"],
            serde_json::json!(["config_resource:financial", "linked_mutation"])
        );
        assert_eq!(
            support["mutation_ids"],
            serde_json::json!(["mutation_0001"])
        );
        assert_eq!(support["link_ids"], serde_json::json!(["link_0001"]));
    }

    #[test]
    fn configured_reviewer_questions_are_deterministic_and_deduplicated() {
        let routes = vec![route("route_sensitive", "GET", "/admin/reports")];
        let config: ScanConfig = serde_yaml::from_str(
            r#"
sensitivity:
  routes:
    - name: admin reports
      labels: [admin_report]
      match:
        contains: [/admin]
      reviewer_questions:
        - Should this route require report-admin permission?
    - name: report paths
      labels: [admin_report]
      match:
        contains: [reports]
      reviewer_questions:
        - Should this route require report-admin permission?
"#,
        )
        .expect("config should parse");

        let first = classify_coverage(&routes, &[], &[], &[], &config);
        let second = classify_coverage(&routes, &[], &[], &[], &config);

        assert_eq!(first, second);
        let item = first
            .iter()
            .find(|coverage| coverage.route_id == "route_sensitive")
            .expect("route should be classified");
        assert_eq!(
            item.reviewer_questions
                .iter()
                .filter(|question| {
                    question.as_str() == "Should this route require report-admin permission?"
                })
                .count(),
            1
        );
        let support = item
            .extensions
            .get("authmap.coverage")
            .expect("coverage support extension should exist");
        assert_eq!(
            support["sensitivity_reasons"],
            serde_json::json!(["admin_path", "config_route:admin_report"])
        );
    }

    #[test]
    fn scan_pipeline_includes_fastapi_routes() {
        let target = fixture_path("fastapi");
        let plan = ScanPlan::new(vec![target], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_eq!(document.routes.len(), 26);
        assert_eq!(
            document.routes.first().map(|route| route.id.as_str()),
            Some("route_0001")
        );
        assert_eq!(
            document.routes.last().map(|route| route.id.as_str()),
            Some("route_0026")
        );
        assert!(document.routes.iter().any(|route| {
            route.method == "DELETE"
                && route.path == "/collection/items/{item_id}"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "delete_collection_item")
        }));
        assert!(document.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/factory/items"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "create_factory_item")
        }));
        assert!(document.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/factory/nested/status"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "nested_status")
        }));
        assert!(document.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/generated"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "generated_path")
        }));
        assert!(document.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/constant"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "constant_alias_path")
        }));
        assert!(document.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/factory/status"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "default_status_path")
        }));
        assert!(document.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/factory/ready"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "default_ready_path")
        }));
        assert!(document.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/v1/users/{user_id}"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "get_user")
        }));
        let shared_route = document
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/shared/variable/settings")
            .expect("shared dependency route should be discovered");
        assert_eq!(
            shared_route
                .middleware
                .iter()
                .map(|middleware| middleware.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "require_user",
                "can_edit_account",
                "provide_database_interface"
            ]
        );
        let service_route = document
            .routes
            .iter()
            .find(|route| route.method == "POST" && route.path == "/service/accounts")
            .expect("service route should be discovered");
        assert!(
            document
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fastapi_dynamic_api_route_methods")
        );
        assert_eq!(
            document
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "fastapi_dynamic_route_path")
                .count(),
            1
        );
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::AdminCheck
                && evidence.route_id.as_deref().is_some()
                && evidence.span.is_some()
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.route_id.as_deref() == Some(shared_route.id.as_str())
                && evidence.evidence_type == EvidenceType::Authn
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "require_user")
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.route_id.as_deref() == Some(shared_route.id.as_str())
                && evidence.evidence_type == EvidenceType::PermissionCheck
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "can_edit_account")
        }));
        assert!(!document.evidence.iter().any(|evidence| {
            evidence.route_id.as_deref() == Some(shared_route.id.as_str())
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "provide_database_interface")
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.route_id.as_deref() == Some(service_route.id.as_str())
                && evidence.evidence_type == EvidenceType::UnknownDynamicCheck
                && evidence
                    .notes
                    .iter()
                    .any(|note| note.contains("One-hop service call"))
        }));
        assert!(document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::PermissionGuarded && coverage.risk == RiskLevel::Low
        }));
    }

    #[test]
    fn scan_pipeline_includes_express_routes() {
        let target = fixture_path("express");
        let plan = ScanPlan::new(vec![target], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_eq!(document.routes.len(), 29);
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "POST"
                && route.path == "/accounts"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["requireAuth", "audit"]
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "POST"
                && route.path == "/admin/jobs"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["requireAuth", "requirePermission", "requireRole"]
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "GET"
                && route.path == "/{tenant}/reports"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["requireAuth"]
        }));
        assert!(document.policy_cases.iter().any(|case| {
            case.route_id
                == document
                    .routes
                    .iter()
                    .find(|route| route.method == "POST" && route.path == "/accounts")
                    .expect("/accounts route should exist")
                    .id
                && case.kind == PolicyCaseKind::EffectiveProtection
                && case.summary.contains("audit_log")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "GET"
                && route.path == "/public/status"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["publicRoute"]
        }));
        assert!(document.policy_cases.iter().any(|case| {
            case.kind == PolicyCaseKind::EffectiveProtection
                && case.summary.contains("explicit_public")
                && case.route_id
                    == document
                        .routes
                        .iter()
                        .find(|route| route.method == "GET" && route.path == "/public/status")
                        .expect("/public/status route should exist")
                        .id
        }));
        assert!(document.policy_cases.iter().any(|case| {
            case.kind == PolicyCaseKind::Conflict
                && case.route_id
                    == document
                        .routes
                        .iter()
                        .find(|route| route.method == "GET" && route.path == "/conflicting")
                        .expect("/conflicting route should exist")
                        .id
        }));
        assert!(document.policy_cases.iter().any(|case| {
            case.kind == PolicyCaseKind::Unreachable
                && case.route_id
                    == document
                        .routes
                        .iter()
                        .find(|route| route.method == "GET" && route.path == "/unreachable/admin")
                        .expect("/unreachable/admin route should exist")
                        .id
        }));
        let audit_only_route = document
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/child")
            .expect("/child route should exist");
        let audit_only_coverage = document
            .coverage
            .iter()
            .find(|coverage| coverage.route_id == audit_only_route.id)
            .expect("/child coverage should exist");
        assert_eq!(audit_only_coverage.class, CoverageClass::Unauthenticated);
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "GET"
                && route.path == "/api/profile"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["middleware.authenticateRequest", "requireAuth"]
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "GET"
                && route.path == "/api/direct"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["middleware.authenticateRequest", "requireAuth"]
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "GET"
                && route.path == "/api/mapped/factory"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["requireAuth"]
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "GET"
                && route.path == "/api/mapped/indexed"
                && route
                    .middleware
                    .iter()
                    .map(|middleware| middleware.name.as_str())
                    .collect::<Vec<_>>()
                    == vec!["requireAuth"]
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Express
                && route.method == "GET"
                && route.path == "/v1/:userId"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "<inline_handler>")
        }));
        assert!(
            document
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "express_dynamic_route_path")
        );
        assert_eq!(
            document
                .evidence
                .first()
                .map(|evidence| evidence.id.as_str()),
            Some("evidence_0001")
        );
        assert!(document.evidence.iter().all(|evidence| {
            evidence.route_id.is_some() && evidence.span.is_some() && !evidence.mechanism.is_empty()
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::RoleCheck
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "requireRole")
        }));
        assert!(document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::AuthnOnly
                && coverage.risk == RiskLevel::ReviewRequired
                && !coverage.reviewer_questions.is_empty()
        }));
    }

    #[test]
    fn scan_pipeline_includes_django_routes_evidence_and_links() {
        let target = fixture_path("django");
        let plan = ScanPlan::new(vec![target], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        // 34 original fixture routes + 4 from the `legacy` app (FBV decorators,
        // legacy `url()`, and `urlpatterns +=`).
        assert_eq!(document.routes.len(), 38);
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Django
                && route.method == "ANY"
                && route.path == "/accounts/users/<int:pk>/"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "AccountDetailView")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "POST"
                && route.path == "/accounts/api/users/{uuid}/disable"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "UserViewSet.disable")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "GET"
                && route.path == "/accounts/api/readonly/{pk}"
        }));
        assert!(!document.routes.iter().any(|route| {
            route.path.starts_with("/accounts/api/readonly")
                && matches!(route.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "POST"
                && route.path == "/accounts/readonly-api/audit/refresh"
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "GET"
                && route.path == "/accounts/api/custom-model"
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "POST"
                && route.path == "/accounts/api/custom-model/recalculate"
                && route.confidence == Confidence::Medium
        }));
        assert!(!document.routes.iter().any(|route| {
            route.path.starts_with("/accounts/api/custom-model")
                && matches!(route.method.as_str(), "PUT" | "PATCH" | "DELETE")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "DELETE"
                && route.path == "/accounts/api/inherited/{pk}"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "InheritedProjectViewSet.destroy")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "GET"
                && route.path == "/accounts/api/inherited-readonly/{pk}"
        }));
        assert!(!document.routes.iter().any(|route| {
            route.path.starts_with("/accounts/api/inherited-readonly")
                && matches!(route.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "POST"
                && route.path == "/accounts/api/mixin-backed"
        }));
        assert!(!document.routes.iter().any(|route| {
            route.path.starts_with("/accounts/api/mixin-backed")
                && matches!(route.method.as_str(), "PUT" | "PATCH" | "DELETE")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::DjangoRestFramework
                && route.method == "GET"
                && route.path == "/exported-api/exported/{pk}"
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Django
                && route.method == "ANY"
                && route.path == "/accounts/generated/<int:pk>/edit"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "GeneratedAccountEditView")
        }));
        let generated_detail = route_by_path(&document, "/accounts/generated/<int:pk>/edit");
        assert!(document.coverage.iter().any(|coverage| {
            coverage.route_id == generated_detail.id
                && coverage.class == CoverageClass::PermissionGuarded
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Django
                && route.method == "ANY"
                && route.path == "/legacy/{slug}/"
                && route.confidence == Confidence::Medium
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::PermissionCheck
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "require_permission")
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::Authn
                && evidence.mechanism == "drf_permission_classes"
                && evidence
                    .notes
                    .iter()
                    .any(|note| note.contains("ProjectModelViewSet"))
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::PermissionCheck
                && evidence.mechanism == "django_queryset_restrict"
                && evidence
                    .notes
                    .iter()
                    .any(|note| note.contains("ProjectModelViewSet"))
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::PermissionCheck
                && evidence.mechanism == "drf_permission_classes"
                && evidence
                    .notes
                    .iter()
                    .any(|note| note.contains("ProjectReadOnlyViewSet"))
        }));
        assert!(document.links.iter().any(|link| {
            document.routes.iter().any(|route| {
                route.id == link.route_id
                    && route.method == "POST"
                    && route.path == "/accounts/api/users"
            }) && link.mutation_id.as_ref().is_some_and(|mutation_id| {
                document.mutations.iter().any(|mutation| {
                    &mutation.id == mutation_id
                        && mutation.library.as_deref() == Some("django_orm")
                        && mutation.operation == MutationOperation::Create
                })
            })
        }));
        assert!(document.links.iter().any(|link| {
            link.route_id == route_by_path(&document, "/accounts").id.as_str()
                && link.confidence == Confidence::Medium
                && link.mutation_id.as_ref().is_some()
        }));
        for code in [
            "django_dynamic_include_helper",
            "django_dynamic_url_path",
            "django_urlpattern_context_uncertain",
            "drf_dynamic_router_prefix",
            "drf_dynamic_basename",
        ] {
            assert!(
                document
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "missing diagnostic {code}"
            );
        }
        assert!(
            !document
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "drf_unresolved_viewset_base")
        );
    }

    #[test]
    fn scan_pipeline_includes_nextjs_routes_evidence_and_links() {
        let target = fixture_path("nextjs");
        let plan = ScanPlan::new(vec![target], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_eq!(document.routes.len(), 17);
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::NextJs
                && route.method == "GET"
                && route.path == "/blog/[...slug]"
                && route.confidence == Confidence::Medium
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::NextJs
                && route.method == "PUT"
                && route.path == "/docs/[[...slug]]"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "updateDoc")
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::NextJs
                && route.method == "HEAD"
                && route.path == "/head"
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::NextJs
                && route.method == "OPTIONS"
                && route.path == "/options"
        }));
        assert!(
            !document
                .routes
                .iter()
                .any(|route| route.method == "DELETE" && route.path == "/tsx")
        );
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::NextJs
                && route.method == "GET"
                && route.path == "/modal"
                && route.confidence == Confidence::Medium
        }));
        assert!(document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::NextJs
                && route.method == "GET"
                && route.path == "/nested/app/users"
                && route.confidence == Confidence::Medium
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::PermissionCheck
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "requirePermission")
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::Authn
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "requireAuth")
        }));
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::Authn
                && evidence.mechanism == "nextjs_auth_wrapper"
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "withAuth")
                && evidence.route_id.as_ref().is_some_and(|route_id| {
                    document.routes.iter().any(|route| {
                        &route.id == route_id
                            && route.method == "DELETE"
                            && route.path == "/external"
                    })
                })
        }));
        assert!(document.links.iter().any(|link| {
            document.routes.iter().any(|route| {
                route.id == link.route_id && route.method == "PATCH" && route.path == "/users/[id]"
            }) && link.mutation_id.as_ref().is_some_and(|mutation_id| {
                document.mutations.iter().any(|mutation| {
                    &mutation.id == mutation_id
                        && mutation.library.as_deref() == Some("prisma")
                        && mutation.operation == MutationOperation::Update
                })
            })
        }));
        assert!(document.links.iter().any(|link| {
            document.routes.iter().any(|route| {
                route.id == link.route_id
                    && route.method == "PUT"
                    && route.path == "/docs/[[...slug]]"
            }) && link.confidence == Confidence::High
                && link.mutation_id.as_ref().is_some()
        }));
        assert!(document.links.iter().any(|link| {
            document.routes.iter().any(|route| {
                route.id == link.route_id && route.method == "POST" && route.path == "/external"
            }) && link.mutation_id.as_ref().is_some_and(|mutation_id| {
                document.mutations.iter().any(|mutation| {
                    &mutation.id == mutation_id
                        && mutation.library.as_deref() == Some("prisma")
                        && mutation.operation == MutationOperation::Create
                })
            })
        }));
        for code in [
            "nextjs_unusual_route_segment",
            "nextjs_dynamic_route_export",
            "nextjs_nested_app_segment",
            "nextjs_external_reexport_unresolved",
        ] {
            assert!(
                document
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "missing diagnostic {code}"
            );
        }
    }

    #[test]
    fn scan_pipeline_includes_trpc_and_graphql_operations() {
        let trpc_target = fixture_path("trpc");
        let trpc_plan = ScanPlan::new(vec![trpc_target], None, ScanConfig::default());
        let trpc_document = run_scan(&trpc_plan).expect("trpc scan should succeed");

        assert!(trpc_document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Trpc
                && route.method == "POST"
                && route.path == "/trpc/router/updateProfile"
        }));
        assert!(trpc_document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Trpc
                && route.method == "POST"
                && route.path == "/trpc/router/updateSettings"
        }));
        assert!(trpc_document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::AuthnOnly
                && trpc_document.routes.iter().any(|route| {
                    route.id == coverage.route_id && route.path == "/trpc/router/updateProfile"
                })
        }));
        assert!(trpc_document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::PublicDeclared
                && trpc_document.routes.iter().any(|route| {
                    route.id == coverage.route_id && route.path == "/trpc/router/publicInfo"
                })
        }));

        let graphql_target = fixture_path("graphql");
        let graphql_plan = ScanPlan::new(vec![graphql_target], None, ScanConfig::default());
        let graphql_document = run_scan(&graphql_plan).expect("graphql scan should succeed");

        assert!(graphql_document.routes.iter().any(|route| {
            route.framework == authmap_core::Framework::Graphql
                && route.method == "MUTATION"
                && route.path == "/graphql/productCreate"
        }));
        assert!(graphql_document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::PermissionGuarded
                && graphql_document.routes.iter().any(|route| {
                    route.id == coverage.route_id && route.path == "/graphql/productCreate"
                })
        }));
        assert!(graphql_document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::PublicDeclared
                && graphql_document.routes.iter().any(|route| {
                    route.id == coverage.route_id && route.path == "/graphql/createToken"
                })
        }));
        assert!(graphql_document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::Unauthenticated
                && graphql_document.routes.iter().any(|route| {
                    route.id == coverage.route_id && route.path == "/graphql/checkoutCreate"
                })
        }));
        assert!(!graphql_document.routes.iter().any(|route| {
            route.path == "/graphql/accountQueries"
                || route.path == "/graphql/accountMutations"
                || route.path == "/graphql/choiceValue"
                || route.path == "/graphql/baseMutation"
                || route.path == "/graphql/modelDeleteMutation"
        }));
    }

    #[test]
    fn scan_pipeline_detects_orm_data_mutations() {
        let target = fixture_path("mutations");
        let plan = ScanPlan::new(vec![target], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_eq!(document.routes.len(), 0);
        assert_eq!(document.links.len(), 0);
        // 21 original + SQLAlchemy insert()-via-execute and merge() (AsyncSession).
        assert_eq!(document.mutations.len(), 23);

        assert_mutation(
            &document.mutations,
            "prisma",
            MutationOperation::Create,
            Some("user"),
            Confidence::High,
        );
        assert_mutation(
            &document.mutations,
            "prisma",
            MutationOperation::BulkUpdate,
            Some("user"),
            Confidence::High,
        );
        assert_mutation(
            &document.mutations,
            "prisma",
            MutationOperation::Delete,
            Some("session"),
            Confidence::High,
        );
        assert_review_required_mutation(
            &document.mutations,
            "prisma",
            MutationOperation::UnknownMutation,
            "unknown_operation",
        );
        assert_review_required_mutation(
            &document.mutations,
            "prisma",
            MutationOperation::RawSqlMutation,
            "raw_sql",
        );

        assert_mutation(
            &document.mutations,
            "sqlalchemy",
            MutationOperation::Create,
            Some("User"),
            Confidence::Medium,
        );
        assert_mutation(
            &document.mutations,
            "sqlalchemy",
            MutationOperation::Update,
            Some("User.disabled"),
            Confidence::Medium,
        );
        assert_mutation(
            &document.mutations,
            "sqlalchemy",
            MutationOperation::Update,
            Some("User"),
            Confidence::High,
        );
        assert_mutation(
            &document.mutations,
            "sqlalchemy",
            MutationOperation::Delete,
            Some("SessionToken"),
            Confidence::High,
        );
        assert_review_required_mutation(
            &document.mutations,
            "sqlalchemy",
            MutationOperation::RawSqlMutation,
            "raw_sql",
        );
        // session.execute(insert(User)...) is detected as a Create.
        assert_mutation(
            &document.mutations,
            "sqlalchemy",
            MutationOperation::Create,
            Some("User"),
            Confidence::High,
        );
        // db_conn.merge(token) where db_conn: AsyncSession is an upsert (Update).
        assert_mutation(
            &document.mutations,
            "sqlalchemy",
            MutationOperation::Update,
            None,
            Confidence::Medium,
        );

        assert_mutation(
            &document.mutations,
            "django_orm",
            MutationOperation::Create,
            Some("Account"),
            Confidence::High,
        );
        assert_mutation(
            &document.mutations,
            "django_orm",
            MutationOperation::BulkUpdate,
            Some("Account"),
            Confidence::High,
        );
        assert_mutation(
            &document.mutations,
            "django_orm",
            MutationOperation::Save,
            Some("Account"),
            Confidence::Medium,
        );
        assert_mutation(
            &document.mutations,
            "django_orm",
            MutationOperation::Delete,
            Some("Account"),
            Confidence::High,
        );

        assert!(document.mutations.iter().all(|mutation| {
            !mutation
                .span
                .as_ref()
                .is_some_and(|span| span.file.contains("negative"))
        }));
    }

    #[test]
    fn scan_pipeline_links_routes_to_direct_and_service_mutations() {
        let target = fixture_path("linking");
        let plan = ScanPlan::new(vec![target], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_eq!(document.routes.len(), 8);
        assert_eq!(document.mutations.len(), 4);
        assert_eq!(document.links.len(), 6);
        assert_eq!(
            document.links.first().map(|link| link.id.as_str()),
            Some("link_0001")
        );

        assert_mutation_link(
            &document,
            "/express/direct",
            "prisma",
            Some("user"),
            Confidence::High,
        );
        assert_mutation_link(
            &document,
            "/express/service",
            "prisma",
            Some("session"),
            Confidence::Medium,
        );
        assert_mutation_link(
            &document,
            "/fastapi/direct",
            "sqlalchemy",
            Some("User"),
            Confidence::High,
        );
        assert_mutation_link(
            &document,
            "/fastapi/service",
            "sqlalchemy",
            Some("User"),
            Confidence::Medium,
        );
        assert_uncertainty_link(&document, "/express/dynamic", "serviceClient.deleteUser");
        assert_uncertainty_link(
            &document,
            "/fastapi/dynamic",
            "service_registry[\"create_user\"]",
        );

        for path in ["/express/read", "/fastapi/read"] {
            let route = route_by_path(&document, path);
            assert!(
                !document.links.iter().any(|link| link.route_id == route.id),
                "{path} should not have reachability links"
            );
        }

        for path in [
            "/express/direct",
            "/express/service",
            "/fastapi/direct",
            "/fastapi/service",
        ] {
            let route = route_by_path(&document, path);
            let coverage = coverage_for_route(&document, &route.id);
            assert_eq!(coverage.class, CoverageClass::AuthnOnly);
            assert_eq!(coverage.risk, RiskLevel::ReviewRequired);
            let support = coverage
                .extensions
                .get("authmap.coverage")
                .expect("coverage support should exist");
            assert!(
                support["mutation_ids"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty()),
                "{path} should include linked mutation support"
            );
            assert!(
                support["sensitivity_reasons"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item == "linked_mutation")),
                "{path} should include linked mutation sensitivity"
            );
        }

        for path in ["/express/dynamic", "/fastapi/dynamic"] {
            let route = route_by_path(&document, path);
            let coverage = coverage_for_route(&document, &route.id);
            let support = coverage
                .extensions
                .get("authmap.coverage")
                .expect("coverage support should exist");
            assert_eq!(support["mutation_ids"], serde_json::json!([]));
            assert!(
                support["link_ids"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty()),
                "{path} should retain uncertainty link support"
            );
        }
    }

    #[test]
    fn reachability_ignores_uncalled_nested_handler_mutations() {
        let temp = TestDir::new("nested-handler-mutation");
        write_file(
            &temp.path().join("app.py"),
            r#"
from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

app = FastAPI()

class User:
    pass

def require_user():
    return {"id": "user_1"}

@app.post("/noop")
def noop(session: Session, user=Depends(require_user)):
    def unused_delete():
        session.delete(User())
    return {"ok": True}
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");
        let route = route_by_path(&document, "/noop");
        let coverage = coverage_for_route(&document, &route.id);
        let support = coverage
            .extensions
            .get("authmap.coverage")
            .expect("coverage support should exist");

        assert!(document.mutations.iter().any(|mutation| {
            mutation.library.as_deref() == Some("sqlalchemy")
                && mutation.operation == MutationOperation::Delete
        }));
        assert!(
            !document.links.iter().any(|link| link.route_id == route.id),
            "unused nested function mutation should not be linked to route"
        );
        assert_eq!(support["mutation_ids"], serde_json::json!([]));
        assert!(
            support["sensitivity_reasons"]
                .as_array()
                .is_some_and(|items| !items.iter().any(|item| item == "linked_mutation"))
        );
    }

    #[test]
    fn reachability_resolves_typescript_default_imported_service_mutations() {
        let temp = TestDir::new("default-import-service");
        write_file(
            &temp.path().join("app.ts"),
            r#"
import express from "express";
import createSession from "./service";

const app = express();

function requireAuth(req, res, next) {
  next();
}

app.post("/sessions", requireAuth, async (req, res) => {
  await createSession(req.body.userId);
  res.json({ ok: true });
});
"#,
        );
        write_file(
            &temp.path().join("service.ts"),
            r#"
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export default async function createSession(userId: string) {
  return prisma.session.create({
    data: { userId },
  });
}
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_eq!(document.mutations.len(), 1);
        assert_mutation_link(
            &document,
            "/sessions",
            "prisma",
            Some("session"),
            Confidence::Medium,
        );
    }

    #[test]
    fn reachability_links_bare_update_service_call() {
        let temp = TestDir::new("bare-update-service");
        write_file(
            &temp.path().join("app.py"),
            r#"
from fastapi import Depends, FastAPI

from services import update_account

app = FastAPI()

def require_user():
    return {"id": "user_1"}

@app.post("/accounts/update")
def route(user=Depends(require_user)):
    return update_account("acct_1")
"#,
        );
        write_file(
            &temp.path().join("services.py"),
            r#"
from sqlalchemy.orm import Session

class Account:
    pass

def update_account(account_id: str):
    session = Session()
    account = Account()
    session.add(account)
    session.commit()
    return account
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_mutation_link(
            &document,
            "/accounts/update",
            "sqlalchemy",
            Some("Account"),
            Confidence::Medium,
        );
    }

    #[test]
    fn js_module_normalization_preserves_posix_absolute_roots() {
        assert_eq!(
            normalize_module_path("/tmp/authmap/project/routes", "./service", "/"),
            "/tmp/authmap/project/routes/service"
        );
        assert_eq!(
            normalize_module_path("/tmp/authmap/project/routes", "../service", "/"),
            "/tmp/authmap/project/service"
        );
    }

    #[test]
    fn python_relative_import_resolution_preserves_posix_absolute_roots() {
        let parsed = ParsedFile {
            source: SourceFile {
                path: "/home/runner/work/AuthMap/tests/fixtures/django/accounts/views.py"
                    .to_string(),
                language: authmap_core::Language::Python,
                size_bytes: 0,
                sha256: None,
                project_hints: Vec::new(),
                skipped: None,
            },
            language: authmap_core::Language::Python,
            text: String::new(),
            tree: None,
            status: ParseStatus::Parsed,
            diagnostics: Vec::new(),
        };
        let mut modules = std::collections::BTreeMap::new();
        modules.insert(
            "/home/runner/work/AuthMap/tests/fixtures/django/accounts/services".to_string(),
            "/home/runner/work/AuthMap/tests/fixtures/django/accounts/services.py".to_string(),
        );

        assert_eq!(
            resolve_python_module(&parsed, &modules, ".services").as_deref(),
            Some("/home/runner/work/AuthMap/tests/fixtures/django/accounts/services.py")
        );
    }

    #[test]
    fn scan_pipeline_emits_runtime_limit_partial_document() {
        let temp = TestDir::new("runtime-limit");
        write_file(&temp.path().join("app.py"), "print('hello')\n");
        let mut config = ScanConfig::default();
        config.limits.max_runtime_ms = 1;
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, config);
        let started_at = Instant::now() - Duration::from_millis(2);

        let document =
            run_scan_with_started_at(&plan, started_at).expect("partial scan should succeed");

        assert_eq!(document.metadata.mode, ScanMode::Advisory);
        assert_eq!(document.source_files.len(), 1);
        assert!(document.routes.is_empty());
        assert!(document.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::INTERNAL_RUNTIME_LIMIT_REACHED
                && diagnostic.severity == authmap_core::DiagnosticSeverity::Warning
        }));
    }

    #[test]
    fn enforce_runtime_limit_is_enforce_blocking() {
        let temp = TestDir::new("runtime-limit-enforce");
        write_file(&temp.path().join("app.py"), "print('hello')\n");
        let mut config = ScanConfig::default();
        config.mode = ScanMode::Enforce;
        config.limits.max_runtime_ms = 1;
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, config);
        let started_at = Instant::now() - Duration::from_millis(2);

        let document =
            run_scan_with_started_at(&plan, started_at).expect("partial scan should succeed");

        assert!(document.has_enforce_blocking_diagnostics());
        assert!(document.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::INTERNAL_RUNTIME_LIMIT_REACHED
                && diagnostic.severity == authmap_core::DiagnosticSeverity::Error
        }));
    }

    #[test]
    fn rules_suggest_emits_runtime_limit_partial_report() {
        let temp = TestDir::new("rules-runtime-limit");
        write_file(&temp.path().join("app.js"), "function requireUser() {}\n");
        let mut config = ScanConfig::default();
        config.limits.max_runtime_ms = 1;
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, config);
        let started_at = Instant::now() - Duration::from_millis(2);

        let report = suggest_rules_with_started_at(&plan, started_at)
            .expect("partial suggestions should succeed");

        assert_eq!(report.source_files_scanned, 0);
        assert!(report.suggestions.is_empty());
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == diagnostic_codes::INTERNAL_RUNTIME_LIMIT_REACHED
        }));
    }

    #[test]
    fn project_specific_authorization_rules_add_permission_evidence() {
        let temp = TestDir::new("custom-authorization-rules");
        write_file(
            &temp.path().join("app.js"),
            r#"
const express = require("express");
const app = express();

function ensurePaidPlan(req, res, next) {
  next();
}

function updateBilling(req, res) {
  res.sendStatus(204);
}

app.patch("/billing/:id", ensurePaidPlan, updateBilling);
module.exports = app;
"#,
        );
        let config: ScanConfig = serde_yaml::from_str(
            r#"
authorization:
  rules:
    - name: paid plan permission
      evidence_type: permission_check
      mechanism: billing_plan_guard
      confidence: medium
      match:
        exact: [ensurePaidPlan]
      notes:
        - configured guard
"#,
        )
        .expect("config should parse");
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, config);

        let document = run_scan(&plan).expect("scan should succeed");

        let evidence = document
            .evidence
            .iter()
            .find(|evidence| evidence.mechanism == "billing_plan_guard")
            .expect("custom rule should emit evidence");
        assert_eq!(evidence.evidence_type, EvidenceType::PermissionCheck);
        assert_eq!(evidence.confidence, Confidence::Medium);
        assert_eq!(evidence.notes, vec!["configured guard"]);
        assert!(evidence.span.is_some());
        assert!(document.coverage.iter().any(|coverage| {
            coverage.class == CoverageClass::PermissionGuarded && coverage.risk == RiskLevel::Low
        }));
    }

    #[test]
    fn fastapi_unmatched_dependencies_and_sessions_do_not_emit_authn() {
        let temp = TestDir::new("fastapi-unmatched-dependencies");
        write_file(
            &temp.path().join("app.py"),
            r#"
from fastapi import Depends, FastAPI

app = FastAPI()

class Session:
    pass

def get_db():
    return Session()

def require_user():
    return {"id": "user_1"}

@app.post("/items")
def create_item(db=Depends(get_db)):
    session = db
    return {"ok": True, "session": str(session)}

@app.get("/me")
def me(user=Depends(require_user)):
    return user
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let document = run_scan(&plan).expect("scan should succeed");

        let create_route = document
            .routes
            .iter()
            .find(|route| route.path == "/items")
            .expect("POST /items should exist");
        assert!(!document.evidence.iter().any(|evidence| {
            evidence.route_id.as_deref() == Some(create_route.id.as_str())
                && evidence.evidence_type == EvidenceType::Authn
        }));
        let coverage = document
            .coverage
            .iter()
            .find(|coverage| coverage.route_id == create_route.id)
            .expect("route should have coverage");
        assert_eq!(coverage.class, CoverageClass::Unauthenticated);
        assert_eq!(coverage.risk, RiskLevel::High);

        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::Authn
                && evidence
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| symbol.name == "require_user")
        }));
    }

    #[test]
    fn unresolved_fastapi_include_dependencies_emit_dynamic_context_only() {
        let temp = TestDir::new("fastapi-unresolved-include-dependencies");
        write_file(
            &temp.path().join("app.py"),
            r#"
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()

@router.get("/items")
def list_items():
    return []

app.include_router(router, dependencies=build_runtime_dependencies())
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let document = run_scan(&plan).expect("scan should succeed");

        let route = document
            .routes
            .iter()
            .find(|route| route.path == "/items")
            .expect("GET /items should exist");
        let evidence = document
            .evidence
            .iter()
            .find(|evidence| evidence.route_id.as_deref() == Some(route.id.as_str()))
            .expect("dynamic include dependency should emit review context");
        assert_eq!(evidence.evidence_type, EvidenceType::UnknownDynamicCheck);
        assert_eq!(evidence.confidence, Confidence::Low);
        assert_eq!(
            evidence.symbol.as_ref().map(|symbol| symbol.name.as_str()),
            Some("dynamic_policy_dependencies")
        );
        let coverage = document
            .coverage
            .iter()
            .find(|coverage| coverage.route_id == route.id)
            .expect("route should have coverage");
        assert_eq!(coverage.class, CoverageClass::UnknownOrDynamic);
        assert_eq!(coverage.risk, RiskLevel::ReviewRequired);
    }

    #[test]
    fn broad_symbols_comments_strings_and_plain_user_reads_do_not_emit_strong_evidence() {
        let temp = TestDir::new("express-false-positive-hardening");
        write_file(
            &temp.path().join("app.js"),
            r#"
const express = require("express");
const app = express();
const authorService = { load() { return []; } };
const publicationService = { list() { return []; } };

app.get("/authors", function listAuthors(req, res) {
  // admin role permission tenant owner public auth session
  const data = authorService.load();
  const publications = publicationService.list();
  res.json({ data, publications, role: "reader", user: req.user });
});

app.delete("/accounts/:id", function deleteAccount(req, res) {
  if (req.user.role !== "admin") {
    return res.sendStatus(403);
  }
  res.sendStatus(204);
});
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let document = run_scan(&plan).expect("scan should succeed");

        let authors_route = document
            .routes
            .iter()
            .find(|route| route.path == "/authors")
            .expect("GET /authors should exist");
        assert!(
            !document.evidence.iter().any(|evidence| {
                evidence.route_id.as_deref() == Some(authors_route.id.as_str())
            })
        );

        let delete_route = document
            .routes
            .iter()
            .find(|route| route.path == "/accounts/:id")
            .expect("DELETE /accounts/:id should exist");
        let dynamic = document
            .evidence
            .iter()
            .find(|evidence| evidence.route_id.as_deref() == Some(delete_route.id.as_str()))
            .expect("guard-like condition should require review");
        assert_eq!(dynamic.evidence_type, EvidenceType::UnknownDynamicCheck);
        assert_eq!(dynamic.confidence, Confidence::Low);
        let coverage = document
            .coverage
            .iter()
            .find(|coverage| coverage.route_id == delete_route.id)
            .expect("route should have coverage");
        assert_eq!(coverage.class, CoverageClass::UnknownOrDynamic);
        assert_eq!(coverage.risk, RiskLevel::ReviewRequired);
    }

    #[test]
    fn adapter_evidence_is_remapped_after_final_route_ids_or_dropped() {
        let mut routes = vec![route("adapter_route_7", "GET", "/status")];
        let remaps = route_id_remaps(&mut routes);
        let mut diagnostics = Vec::new();
        let normalized = normalize_adapter_evidence(
            vec![
                evidence(
                    "adapter_evidence",
                    "adapter_route_7",
                    EvidenceType::Authn,
                    Confidence::High,
                ),
                evidence(
                    "orphaned_evidence",
                    "missing_route",
                    EvidenceType::Authn,
                    Confidence::High,
                ),
            ],
            &routes,
            &remaps,
            &mut diagnostics,
        );

        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].route_id.as_deref(), Some("route_0001"));
        assert_eq!(diagnostics.len(), 1);
        assert!(
            diagnostics[0]
                .message
                .contains("unknown route ID missing_route")
        );
    }

    #[test]
    fn suggest_rules_finds_fastapi_custom_dependency() {
        let temp = TestDir::new("suggest-fastapi");
        write_file(
            &temp.path().join("app.py"),
            r#"
from fastapi import Depends, FastAPI

app = FastAPI()

def ensure_paid_plan():
    return True

def cancel():
    return True

@app.get("/billing")
def get_billing(user=Depends(ensure_paid_plan)):
    cancel()
    return {}
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let report = suggest_rules(&plan).expect("suggestions should run");

        let suggestion = report
            .suggestions
            .iter()
            .find(|suggestion| suggestion.matcher.exact == vec!["ensure_paid_plan"])
            .expect("custom FastAPI dependency should be suggested");
        assert_eq!(suggestion.evidence_type, EvidenceType::PermissionCheck);
        assert_eq!(suggestion.confidence, Confidence::Medium);
        assert!(
            suggestion
                .rationale
                .iter()
                .any(|item| item.contains("permission"))
        );
        assert!(
            suggestion
                .examples
                .iter()
                .any(|example| example.context == "FastAPI dependency")
        );
        assert!(
            report
                .suggestions
                .iter()
                .all(|suggestion| suggestion.matcher.exact != vec!["cancel"])
        );
    }

    #[test]
    fn suggest_rules_filters_operational_fastapi_dependencies() {
        let temp = TestDir::new("suggest-fastapi-operational");
        write_file(
            &temp.path().join("app.py"),
            r#"
from fastapi import APIRouter, Depends, FastAPI

app = FastAPI()
router = APIRouter(dependencies=[Depends(provide_database_interface)])

def provide_database_interface():
    return object()

def provide_request_api_version():
    return "1"

def ensure_workspace_access():
    return True

@router.get("/items", dependencies=[Depends(provide_request_api_version)])
def list_items():
    return []

app.include_router(router, dependencies=[Depends(ensure_workspace_access)])
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let report = suggest_rules(&plan).expect("suggestions should run");
        let symbols = report
            .suggestions
            .iter()
            .flat_map(|suggestion| suggestion.matcher.exact.iter().map(String::as_str))
            .collect::<Vec<_>>();

        assert!(symbols.contains(&"ensure_workspace_access"));
        assert!(!symbols.contains(&"provide_database_interface"));
        assert!(!symbols.contains(&"provide_request_api_version"));
        let suggestion = report
            .suggestions
            .iter()
            .find(|suggestion| suggestion.matcher.exact == vec!["ensure_workspace_access"])
            .expect("workspace dependency should be suggested");
        assert_eq!(suggestion.evidence_type, EvidenceType::TenantCheck);
        assert!(
            suggestion
                .examples
                .iter()
                .any(|example| example.context == "FastAPI dependency")
        );
    }

    #[test]
    fn suggest_rules_finds_express_custom_middleware() {
        let temp = TestDir::new("suggest-express");
        write_file(
            &temp.path().join("app.js"),
            r#"
const express = require("express");
const app = express();

function ensurePaidPlan(req, res, next) {
  next();
}

function updateBilling(req, res) {
  res.sendStatus(204);
}

app.patch("/billing/:id", ensurePaidPlan, updateBilling);
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let report = suggest_rules(&plan).expect("suggestions should run");

        let suggestion = report
            .suggestions
            .iter()
            .find(|suggestion| suggestion.matcher.exact == vec!["ensurePaidPlan"])
            .expect("custom Express middleware should be suggested");
        assert_eq!(suggestion.evidence_type, EvidenceType::PermissionCheck);
        assert!(
            suggestion
                .examples
                .iter()
                .any(|example| example.context == "Express middleware")
        );
    }

    #[test]
    fn suggest_rules_handles_empty_projects_and_filters_false_positives() {
        let empty = TestDir::new("suggest-empty");
        let empty_plan = ScanPlan::new(
            vec![empty.path().to_path_buf()],
            None,
            ScanConfig::default(),
        );
        let empty_report = suggest_rules(&empty_plan).expect("empty advisory project should run");
        assert!(empty_report.suggestions.is_empty());
        assert_eq!(empty_report.source_files_scanned, 0);

        let temp = TestDir::new("suggest-filter");
        write_file(
            &temp.path().join("app.js"),
            r#"
const express = require("express");
const app = express();

function listUsers(req, res) {
  res.json([]);
}

app.get("/users", listUsers);
"#,
        );
        std::fs::create_dir_all(temp.path().join("circuits/tests"))
            .expect("test fixture directory should be created");
        write_file(
            &temp.path().join("circuits/tests/test_api.py"),
            r#"
class CircuitGroup:
    pass

def test_groups():
    CircuitGroup()
"#,
        );
        write_file(
            &temp.path().join("serializers.py"),
            r#"
class ClusterGroupSerializer:
    pass

def build():
    ClusterGroupSerializer()
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());
        let report = suggest_rules(&plan).expect("suggestions should run");

        assert!(
            report
                .suggestions
                .iter()
                .all(|suggestion| suggestion.matcher.exact != vec!["listUsers"])
        );
        assert!(report.suggestions.iter().all(|suggestion| {
            suggestion.matcher.exact != vec!["CircuitGroup"]
                && suggestion.matcher.exact != vec!["ClusterGroupSerializer"]
        }));
    }

    #[test]
    fn suggest_rules_suppresses_existing_config_rules_and_is_stable() {
        let temp = TestDir::new("suggest-config");
        write_file(
            &temp.path().join("app.js"),
            r#"
const express = require("express");
const app = express();

function ensurePaidPlan(req, res, next) {
  next();
}

function updateBilling(req, res) {
  res.sendStatus(204);
}

app.patch("/billing/:id", ensurePaidPlan, updateBilling);
"#,
        );
        let config: ScanConfig = serde_yaml::from_str(
            r#"
authorization:
  rules:
    - name: paid plan permission
      evidence_type: permission_check
      mechanism: billing_plan_guard
      match:
        exact: [ensurePaidPlan]
"#,
        )
        .expect("config should parse");
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, config);

        let first = suggest_rules(&plan).expect("suggestions should run");
        let second = suggest_rules(&plan).expect("suggestions should run");

        assert_eq!(first, second);
        assert!(
            first
                .suggestions
                .iter()
                .all(|suggestion| suggestion.matcher.exact != vec!["ensurePaidPlan"])
        );
    }

    #[test]
    fn suggest_rules_covers_all_canonical_evidence_type_families() {
        let temp = TestDir::new("suggest-evidence-families");
        write_file(
            &temp.path().join("guards.js"),
            r#"
function ensureLogin(req, res, next) { next(); }
function roleGate(req, res, next) { next(); }
function paidAccess(req, res, next) { next(); }
function owningResource(req, res, next) { next(); }
function workspaceGate(req, res, next) { next(); }
function staffGate(req, res, next) { next(); }
function anonymousAccess(req, res, next) { next(); }
function recordAuditTrail(req, res, next) { next(); }
function authorizeRecord(req, res, next) { next(); }
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let report = suggest_rules(&plan).expect("suggestions should run");
        let types = report
            .suggestions
            .iter()
            .map(|suggestion| suggestion.evidence_type)
            .collect::<BTreeSet<_>>();

        for expected in [
            EvidenceType::Authn,
            EvidenceType::RoleCheck,
            EvidenceType::PermissionCheck,
            EvidenceType::OwnershipCheck,
            EvidenceType::TenantCheck,
            EvidenceType::AdminCheck,
            EvidenceType::ExplicitPublic,
            EvidenceType::AuditLog,
            EvidenceType::UnknownDynamicCheck,
        ] {
            assert!(types.contains(&expected), "missing {expected:?}");
        }
    }

    #[test]
    fn scan_pipeline_detects_structured_tenant_and_ownership_scoping() {
        let temp = TestDir::new("tenant-structured-scoping");
        write_file(
            &temp.path().join("app.py"),
            r#"
from fastapi import Depends, FastAPI

app = FastAPI()

def require_user():
    return {"id": "user_1", "org_id": "org_1"}

def get_db():
    return object()

@app.patch("/orgs/{org_id}/projects/{project_id}")
def update_project(org_id: str, project_id: str, user=Depends(require_user), db=Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.org_id == user["org_id"]).one()
    project.owner_id = user["id"]
    project.name = "renamed"
    db.add(project)
    return {"id": project_id}
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let document = run_scan(&plan).expect("scan should succeed");
        let route = route_by_path(&document, "/orgs/{org_id}/projects/{project_id}");
        let route_evidence = document
            .evidence
            .iter()
            .filter(|item| item.route_id.as_deref() == Some(route.id.as_str()))
            .collect::<Vec<_>>();

        assert!(
            route_evidence.iter().any(|item| {
                item.evidence_type == EvidenceType::TenantCheck
                    && item.confidence == Confidence::High
                    && item.mechanism == "query_scope"
            }),
            "tenant query scoping evidence should be detected"
        );
        assert!(
            route_evidence.iter().any(|item| {
                item.evidence_type == EvidenceType::OwnershipCheck
                    && item.confidence == Confidence::High
                    && item.mechanism == "mutation_scope"
            }),
            "ownership mutation scoping evidence should be detected"
        );
        let coverage = coverage_for_route(&document, &route.id);
        assert_eq!(coverage.class, CoverageClass::OwnershipGuarded);
    }

    #[test]
    fn scan_pipeline_reviews_linked_mutations_without_tenant_scope() {
        let temp = TestDir::new("tenant-missing-scope");
        write_file(
            &temp.path().join("app.ts"),
            r#"
import express from "express";

const app = express();

function requireUser(req, res, next) {
  next();
}

async function updateProject(req, res) {
  await prisma.project.update({
    where: { id: req.params.projectId },
    data: { name: req.body.name },
  });
  res.sendStatus(204);
}

app.patch("/orgs/:orgId/projects/:projectId", requireUser, updateProject);
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let document = run_scan(&plan).expect("scan should succeed");
        let route = route_by_path(&document, "/orgs/:orgId/projects/:projectId");
        let coverage = coverage_for_route(&document, &route.id);
        let tenant_review = coverage
            .extensions
            .get("authmap.tenant_review")
            .expect("missing tenant scope should add tenant review metadata");

        assert!(document.evidence.iter().any(|item| {
            item.route_id.as_deref() == Some(route.id.as_str())
                && item.evidence_type == EvidenceType::TenantCheck
                && item.mechanism == "route_param_scope_signal"
                && item.confidence == Confidence::Low
        }));
        assert_eq!(coverage.risk, RiskLevel::ReviewRequired);
        assert_eq!(tenant_review["review_required"], serde_json::json!(true));
        assert!(tenant_review["reasons"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item == "missing_tenant_or_ownership_evidence")
        }));
        assert!(
            coverage
                .reviewer_questions
                .iter()
                .any(|question| question.contains("tenant or ownership"))
        );
    }

    #[test]
    fn scan_pipeline_keeps_tenant_names_in_comments_and_strings_out_of_evidence() {
        let temp = TestDir::new("tenant-false-positives");
        write_file(
            &temp.path().join("app.js"),
            r#"
const express = require("express");
const app = express();

function requireUser(req, res, next) {
  next();
}

function listProjects(req, res) {
  // tenant_id owner_id org_id should not count from a comment
  const message = "workspace_id account_id organization_id should not count from a string";
  res.json({ message });
}

app.get("/projects", requireUser, listProjects);
"#,
        );
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());

        let document = run_scan(&plan).expect("scan should succeed");

        assert!(document.evidence.iter().all(|item| {
            !matches!(
                item.evidence_type,
                EvidenceType::TenantCheck | EvidenceType::OwnershipCheck
            )
        }));
    }

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
                "authmap-analysis-test-{name}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("test temp directory should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("test fixture parent should be created");
        }
        std::fs::write(path, contents).expect("test fixture should be written");
    }

    fn route(id: &str, method: &str, path: &str) -> Route {
        Route {
            id: id.to_string(),
            framework: Framework::Express,
            method: method.to_string(),
            path: path.to_string(),
            name: None,
            tags: Vec::new(),
            middleware: Vec::new(),
            params: Vec::new(),
            declared_protection: Vec::new(),
            handler: None,
            span: None,
            source_evidence: Vec::new(),
            confidence: Confidence::High,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        }
    }

    fn evidence(
        id: &str,
        route_id: &str,
        evidence_type: EvidenceType,
        confidence: Confidence,
    ) -> Evidence {
        Evidence {
            id: id.to_string(),
            route_id: Some(route_id.to_string()),
            evidence_type,
            mechanism: "test_guard".to_string(),
            symbol: None,
            span: None,
            confidence,
            notes: Vec::new(),
            extensions: authmap_core::ExtensionMap::new(),
        }
    }

    fn assert_mutation(
        mutations: &[Mutation],
        library: &str,
        operation: MutationOperation,
        resource: Option<&str>,
        confidence: Confidence,
    ) {
        assert!(
            mutations.iter().any(|mutation| {
                mutation.library.as_deref() == Some(library)
                    && mutation.operation == operation
                    && mutation.resource.as_deref() == resource
                    && mutation.confidence == confidence
                    && mutation.span.is_some()
            }),
            "missing {library} {operation:?} {resource:?} {confidence:?}"
        );
    }

    fn assert_review_required_mutation(
        mutations: &[Mutation],
        library: &str,
        operation: MutationOperation,
        detection: &str,
    ) {
        let mutation = mutations
            .iter()
            .find(|mutation| {
                mutation.library.as_deref() == Some(library) && mutation.operation == operation
            })
            .unwrap_or_else(|| panic!("missing {library} {operation:?}"));
        assert_eq!(mutation.confidence, Confidence::Low);
        let extension = mutation
            .extensions
            .get("authmap.mutation")
            .expect("review-required mutation should have metadata");
        assert_eq!(extension["review_required"], serde_json::json!(true));
        assert_eq!(extension["detection"], serde_json::json!(detection));
        assert!(
            extension["uncertainty_reasons"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
    }

    fn route_by_path<'a>(
        document: &'a authmap_core::AuthMapDocument,
        path: &str,
    ) -> &'a authmap_core::Route {
        document
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("missing route {path}"))
    }

    fn coverage_for_route<'a>(
        document: &'a authmap_core::AuthMapDocument,
        route_id: &str,
    ) -> &'a authmap_core::Coverage {
        document
            .coverage
            .iter()
            .find(|coverage| coverage.route_id == route_id)
            .unwrap_or_else(|| panic!("missing coverage for {route_id}"))
    }

    fn assert_mutation_link(
        document: &authmap_core::AuthMapDocument,
        route_path: &str,
        library: &str,
        resource: Option<&str>,
        confidence: Confidence,
    ) {
        let route = route_by_path(document, route_path);
        let link = document
            .links
            .iter()
            .find(|link| {
                link.route_id == route.id
                    && link.confidence == confidence
                    && link.mutation_id.as_ref().is_some_and(|mutation_id| {
                        document.mutations.iter().any(|mutation| {
                            &mutation.id == mutation_id
                                && mutation.library.as_deref() == Some(library)
                                && mutation.resource.as_deref() == resource
                        })
                    })
            })
            .unwrap_or_else(|| panic!("missing mutation link for {route_path}"));
        assert!(link.evidence_id.is_none());
        assert!(link.notes.iter().any(|note| {
            let lower = note.to_ascii_lowercase();
            lower.contains("mutation") || lower.contains("service call")
        }));
    }

    fn assert_uncertainty_link(
        document: &authmap_core::AuthMapDocument,
        route_path: &str,
        call_target: &str,
    ) {
        let route = route_by_path(document, route_path);
        let link = document
            .links
            .iter()
            .find(|link| {
                link.route_id == route.id
                    && link.mutation_id.is_none()
                    && link.confidence == Confidence::Low
            })
            .unwrap_or_else(|| panic!("missing uncertainty link for {route_path}"));
        let extension = link
            .extensions
            .get("authmap.reachability")
            .expect("uncertainty link should include reachability metadata");
        assert_eq!(
            extension["reason"],
            serde_json::json!("unresolved_service_call")
        );
        assert_eq!(extension["call_target"], serde_json::json!(call_target));
        assert!(extension.get("call_span").is_some());
    }

    fn assert_coverage(
        coverage: &[authmap_core::Coverage],
        route_id: &str,
        class: CoverageClass,
        risk: RiskLevel,
    ) {
        let item = coverage
            .iter()
            .find(|coverage| coverage.route_id == route_id)
            .unwrap_or_else(|| panic!("missing coverage for {route_id}"));
        assert_eq!(item.class, class, "{route_id} class");
        assert_eq!(item.risk, risk, "{route_id} risk");
    }
}
