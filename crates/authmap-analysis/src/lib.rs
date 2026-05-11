use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use authmap_adapters::{AdapterContext, AdapterRegistry};
use authmap_config::{AuthorizationRule, ScanConfig, ScanPlan};
use authmap_core::{
    AuthMapDocument, Confidence, Coverage, CoverageClass, Diagnostic, Evidence, EvidenceType,
    Framework, Mutation, RiskLevel, ScanMetadata, Span, SymbolRef,
};
use authmap_discovery::discover_sources;
use authmap_parsers::{ParseError, ParsedFile, TreeSitterBackend, parse_files_in_parallel};
use thiserror::Error;
use tree_sitter::Node;

pub trait EvidenceExtractor: Send + Sync {
    fn extract_evidence(&self, input: &AnalysisInput<'_>) -> AnalysisFacts;
}

pub trait MutationExtractor: Send + Sync {
    fn extract_mutations(&self, input: &AnalysisInput<'_>) -> AnalysisFacts;
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
    pub diagnostics: Vec<Diagnostic>,
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

        for route in input.routes {
            let mut route_evidence = match route.framework {
                Framework::Express => {
                    extract_express_route_evidence(route, &parsed_by_path, &rules)
                }
                Framework::FastApi => {
                    extract_fastapi_route_evidence(route, &parsed_by_path, &rules)
                }
                _ => Vec::new(),
            };
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

pub fn run_scan(plan: &ScanPlan) -> Result<AuthMapDocument, ScanError> {
    let discovery = discover_sources(plan)?;
    let backend = TreeSitterBackend;
    let parse_output = parse_files_in_parallel(&backend, &discovery.files, |file| {
        fs::read_to_string(&file.path).map_err(|source| ParseError::Read {
            path: file.path.clone(),
            message: source.to_string(),
        })
    });

    let adapter_registry = AdapterRegistry::built_in();
    let mut adapter_output =
        adapter_registry.discover_routes(&parse_output.parsed_files, &AdapterContext::default());

    let mut document = AuthMapDocument::empty(ScanMetadata {
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
    });
    document.source_files = discovery.files;
    document.diagnostics = discovery.diagnostics;
    document.diagnostics.extend(parse_output.diagnostics);
    document.routes = adapter_output.routes;
    document.diagnostics.extend(adapter_output.diagnostics);
    document.routes.sort_by_key(route_sort_key);
    for (index, route) in document.routes.iter_mut().enumerate() {
        route.id = format!("route_{:04}", index + 1);
    }
    let input = AnalysisInput {
        routes: &document.routes,
        parsed_files: &parse_output.parsed_files,
        config: &plan.config,
        adapter_evidence: &adapter_output.evidence,
        mutations: &adapter_output.mutations,
    };
    let facts = BuiltInEvidenceExtractor.extract_evidence(&input);
    document.evidence = facts.evidence;
    document.mutations.append(&mut adapter_output.mutations);
    document.diagnostics.extend(facts.diagnostics);
    document.coverage = classify_coverage(&document.routes, &document.evidence);
    document.diagnostics.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });
    Ok(document)
}

#[derive(Clone, Debug)]
struct EvidenceRuleSpec {
    evidence_type: EvidenceType,
    mechanism: String,
    confidence: Confidence,
    exact: Vec<String>,
    contains: Vec<String>,
    notes: Vec<String>,
}

#[derive(Clone, Debug)]
struct EvidenceRules {
    rules: Vec<EvidenceRuleSpec>,
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
        let symbol_lower = symbol.to_ascii_lowercase();
        self.exact.iter().any(|item| item == symbol)
            || self
                .contains
                .iter()
                .any(|item| symbol_lower.contains(&item.to_ascii_lowercase()))
    }
}

fn config_rule_to_spec(rule: &AuthorizationRule) -> EvidenceRuleSpec {
    EvidenceRuleSpec {
        evidence_type: rule.evidence_type,
        mechanism: rule.mechanism.clone(),
        confidence: rule.confidence.unwrap_or(Confidence::High),
        exact: rule.matcher.exact.clone(),
        contains: rule.matcher.contains.clone(),
        notes: rule.notes.clone(),
    }
}

fn builtin_rules() -> Vec<EvidenceRuleSpec> {
    vec![
        rule(
            EvidenceType::ExplicitPublic,
            "public_marker",
            Confidence::High,
            &["allow_anonymous", "public_route", "no_auth"],
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
            ],
            &["permission", "permissions"],
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
                "session",
                "auth",
            ],
            &["auth", "session", "current_user", "authenticated"],
        ),
        rule(
            EvidenceType::UnknownDynamicCheck,
            "dynamic_policy",
            Confidence::Low,
            &["policy", "checkPolicy", "enforcePolicy", "dynamicPolicy"],
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
            evidence.extend(extract_textual_body_evidence(
                parsed,
                node,
                route,
                handler,
                "handler_body",
            ));
        }
    }
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
    evidence.extend(extract_textual_body_evidence(
        parsed,
        node,
        route,
        handler,
        "handler_body",
    ));
    evidence
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
                        } else {
                            evidence.push(Evidence {
                                id: String::new(),
                                route_id: Some(route.id.clone()),
                                evidence_type: EvidenceType::Authn,
                                mechanism: "fastapi_dependency".to_string(),
                                symbol: Some(symbol),
                                span: Some(parsed.span_for(current)),
                                confidence: Confidence::Medium,
                                notes: vec![
                                    "FastAPI dependency was detected but no specific guard type matched"
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

fn extract_textual_body_evidence(
    parsed: &ParsedFile,
    node: Node<'_>,
    route: &authmap_core::Route,
    symbol: &SymbolRef,
    mechanism: &str,
) -> Vec<Evidence> {
    let Some(text) = parsed.text_for(node) else {
        return Vec::new();
    };
    let lower = text.to_ascii_lowercase();
    let mut evidence = Vec::new();
    let span = symbol.span.clone().or_else(|| Some(parsed.span_for(node)));

    if lower.contains("req.user")
        || lower.contains("request.user")
        || lower.contains("current_user")
        || lower.contains("session")
        || lower.contains("user=depends")
    {
        evidence.push(textual_evidence(
            route,
            EvidenceType::Authn,
            mechanism,
            "user/session reference",
            symbol.clone(),
            span.clone(),
            Confidence::Medium,
        ));
    }
    if lower.contains("permission") || lower.contains("permissions") {
        evidence.push(textual_evidence(
            route,
            EvidenceType::PermissionCheck,
            mechanism,
            "permission reference",
            symbol.clone(),
            span.clone(),
            Confidence::Medium,
        ));
    }
    if lower.contains("role") {
        evidence.push(textual_evidence(
            route,
            EvidenceType::RoleCheck,
            mechanism,
            "role reference",
            symbol.clone(),
            span.clone(),
            Confidence::Medium,
        ));
    }
    if lower.contains("admin") {
        evidence.push(textual_evidence(
            route,
            EvidenceType::AdminCheck,
            mechanism,
            "admin reference",
            symbol.clone(),
            span.clone(),
            Confidence::Medium,
        ));
    }
    if lower.contains("tenant") {
        evidence.push(textual_evidence(
            route,
            EvidenceType::TenantCheck,
            mechanism,
            "tenant reference",
            symbol.clone(),
            span.clone(),
            Confidence::Medium,
        ));
    }
    if lower.contains("owner") || lower.contains("ownership") {
        evidence.push(textual_evidence(
            route,
            EvidenceType::OwnershipCheck,
            mechanism,
            "ownership reference",
            symbol.clone(),
            span,
            Confidence::Medium,
        ));
    }
    evidence
}

fn textual_evidence(
    route: &authmap_core::Route,
    evidence_type: EvidenceType,
    mechanism: &str,
    note: &str,
    symbol: SymbolRef,
    span: Option<Span>,
    confidence: Confidence,
) -> Evidence {
    Evidence {
        id: String::new(),
        route_id: Some(route.id.clone()),
        evidence_type,
        mechanism: mechanism.to_string(),
        symbol: Some(symbol),
        span,
        confidence,
        notes: vec![note.to_string()],
        extensions: authmap_core::ExtensionMap::new(),
    }
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
        .span
        .as_ref()
        .map(|span| span.file.clone())
        .or_else(|| {
            route
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .map(|span| span.file.clone())
        })
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

fn terminal_symbol_name(text: &str) -> String {
    text.rsplit(['.', ':']).next().unwrap_or(text).to_string()
}

fn is_fastapi_depends(function_text: &str) -> bool {
    terminal_symbol_name(function_text) == "Depends"
}

fn is_framework_route_call(function_text: &str) -> bool {
    matches!(
        terminal_symbol_name(function_text).as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "api_route" | "route" | "use"
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

fn classify_coverage(routes: &[authmap_core::Route], evidence: &[Evidence]) -> Vec<Coverage> {
    let mut by_route = BTreeMap::<&str, Vec<&Evidence>>::new();
    for item in evidence {
        if let Some(route_id) = &item.route_id {
            by_route.entry(route_id.as_str()).or_default().push(item);
        }
    }

    routes
        .iter()
        .map(|route| {
            let evidence = by_route.get(route.id.as_str()).cloned().unwrap_or_default();
            classify_route(route, &evidence)
        })
        .collect()
}

fn classify_route(route: &authmap_core::Route, evidence: &[&Evidence]) -> Coverage {
    let strong = evidence
        .iter()
        .copied()
        .filter(|item| item.confidence != Confidence::Low)
        .filter(|item| item.evidence_type != EvidenceType::UnknownDynamicCheck)
        .collect::<Vec<_>>();
    let sensitive = sensitive_route(route);

    let mut uncertainty_reasons = Vec::new();
    if evidence
        .iter()
        .any(|item| item.confidence == Confidence::Low)
    {
        uncertainty_reasons.push("Low-confidence authorization evidence was detected.".to_string());
    }
    if evidence
        .iter()
        .any(|item| item.evidence_type == EvidenceType::UnknownDynamicCheck)
    {
        uncertainty_reasons.push("Dynamic authorization evidence requires review.".to_string());
    }
    if route.confidence != Confidence::High {
        uncertainty_reasons.push("Route inventory confidence is not high.".to_string());
    }

    if evidence.is_empty() {
        if sensitive {
            return Coverage {
                route_id: route.id.clone(),
                class: CoverageClass::UnknownOrDynamic,
                risk: RiskLevel::ReviewRequired,
                rationale: vec![
                    "No authorization evidence was detected for a sensitive-looking route."
                        .to_string(),
                ],
                reviewer_questions: expected_questions(route),
                uncertainty_reasons,
                extensions: authmap_core::ExtensionMap::new(),
            };
        }
        return Coverage {
            route_id: route.id.clone(),
            class: CoverageClass::Unauthenticated,
            risk: RiskLevel::Low,
            rationale: vec!["No authorization evidence was detected.".to_string()],
            reviewer_questions: Vec::new(),
            uncertainty_reasons,
            extensions: authmap_core::ExtensionMap::new(),
        };
    }

    if strong.is_empty() {
        return Coverage {
            route_id: route.id.clone(),
            class: CoverageClass::UnknownOrDynamic,
            risk: RiskLevel::ReviewRequired,
            rationale: vec![
                "Only weak or dynamic authorization evidence was detected.".to_string(),
            ],
            reviewer_questions: expected_questions(route),
            uncertainty_reasons,
            extensions: authmap_core::ExtensionMap::new(),
        };
    }

    let class = if has_type(&strong, EvidenceType::ExplicitPublic) {
        CoverageClass::PublicDeclared
    } else if has_type(&strong, EvidenceType::AdminCheck) {
        CoverageClass::AdminGuarded
    } else if has_type(&strong, EvidenceType::PermissionCheck) {
        CoverageClass::PermissionGuarded
    } else if has_type(&strong, EvidenceType::RoleCheck) {
        CoverageClass::RoleGuarded
    } else if has_type(&strong, EvidenceType::TenantCheck) {
        CoverageClass::TenantGuarded
    } else if has_type(&strong, EvidenceType::OwnershipCheck) {
        CoverageClass::OwnershipGuarded
    } else if has_type(&strong, EvidenceType::Authn) {
        CoverageClass::AuthnOnly
    } else {
        CoverageClass::UnknownOrDynamic
    };

    let mut reviewer_questions = Vec::new();
    let risk = match class {
        CoverageClass::PublicDeclared => RiskLevel::Low,
        CoverageClass::AuthnOnly if sensitive => {
            reviewer_questions = expected_questions(route);
            RiskLevel::ReviewRequired
        }
        CoverageClass::UnknownOrDynamic => {
            reviewer_questions = expected_questions(route);
            RiskLevel::ReviewRequired
        }
        _ => RiskLevel::Low,
    };

    Coverage {
        route_id: route.id.clone(),
        class,
        risk,
        rationale: vec![format!(
            "{} strong authorization evidence item(s) were detected.",
            strong.len()
        )],
        reviewer_questions,
        uncertainty_reasons,
        extensions: authmap_core::ExtensionMap::new(),
    }
}

fn has_type(evidence: &[&Evidence], evidence_type: EvidenceType) -> bool {
    evidence
        .iter()
        .any(|item| item.evidence_type == evidence_type)
}

fn sensitive_route(route: &authmap_core::Route) -> bool {
    let method = route.method.as_str();
    let lower_path = route.path.to_ascii_lowercase();
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE" | "ANY")
        || lower_path.contains("admin")
        || lower_path.contains("account")
        || lower_path.contains("user")
        || lower_path.contains("tenant")
        || lower_path.contains('{')
        || lower_path.contains(':')
}

fn expected_questions(route: &authmap_core::Route) -> Vec<String> {
    let mut questions = Vec::new();
    let lower_path = route.path.to_ascii_lowercase();
    if matches!(
        route.method.as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE" | "ANY"
    ) {
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
    questions.sort();
    questions.dedup();
    questions
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
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use authmap_config::{ScanConfig, ScanPlan};
    use authmap_core::{Confidence, CoverageClass, EvidenceType, RiskLevel};
    use authmap_testkit::fixture_path;

    use super::run_scan;

    #[test]
    fn scan_pipeline_includes_fastapi_routes() {
        let target = fixture_path("fastapi");
        let plan = ScanPlan::new(vec![target], None, ScanConfig::default());
        let document = run_scan(&plan).expect("scan should succeed");

        assert_eq!(document.routes.len(), 15);
        assert_eq!(
            document.routes.first().map(|route| route.id.as_str()),
            Some("route_0001")
        );
        assert_eq!(
            document.routes.last().map(|route| route.id.as_str()),
            Some("route_0015")
        );
        assert!(document.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/v1/users/{user_id}"
                && route
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.name == "get_user")
        }));
        assert!(
            document
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fastapi_dynamic_api_route_methods")
        );
        assert!(document.evidence.iter().any(|evidence| {
            evidence.evidence_type == EvidenceType::AdminCheck
                && evidence.route_id.as_deref().is_some()
                && evidence.span.is_some()
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

        assert_eq!(document.routes.len(), 16);
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
                    == vec!["requireAuth", "requireRole"]
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
}
