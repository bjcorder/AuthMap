use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use authmap_adapters::{AdapterContext, AdapterRegistry};
use authmap_config::{
    AuthorizationRule, AuthorizationRuleMatch, ResourceSensitivityRule, RouteSensitivityRule,
    ScanConfig, ScanPlan,
};
use authmap_core::{
    AuthMapDocument, Confidence, Coverage, CoverageClass, Diagnostic, Evidence, EvidenceType,
    Framework, Mutation, ReachabilityLink, RiskLevel, ScanMetadata, Span, SymbolRef,
};
use authmap_discovery::discover_sources;
use authmap_parsers::{ParseError, ParsedFile, TreeSitterBackend, parse_files_in_parallel};
use serde::Serialize;
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
    document.coverage = classify_coverage(
        &document.routes,
        &document.evidence,
        &document.mutations,
        &document.links,
        &plan.config,
    );
    document.diagnostics.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });
    Ok(document)
}

pub fn suggest_rules(plan: &ScanPlan) -> Result<RuleSuggestionReport, ScanError> {
    let discovery = discover_sources(plan)?;
    let backend = TreeSitterBackend;
    let parse_output = parse_files_in_parallel(&backend, &discovery.files, |file| {
        fs::read_to_string(&file.path).map_err(|source| ParseError::Read {
            path: file.path.clone(),
            message: source.to_string(),
        })
    });

    let adapter_registry = AdapterRegistry::built_in();
    let adapter_output =
        adapter_registry.discover_routes(&parse_output.parsed_files, &AdapterContext::default());
    let route_handlers = adapter_output
        .routes
        .iter()
        .filter_map(|route| route.handler.as_ref())
        .map(|handler| handler.name.as_str())
        .filter(|name| !name.starts_with('<'))
        .collect::<BTreeSet<_>>();

    let rules = EvidenceRules::new(&plan.config);
    let mut candidates = BTreeMap::<String, RuleCandidate>::new();
    for parsed in &parse_output.parsed_files {
        collect_rule_candidates(parsed, &route_handlers, &rules, &mut candidates);
    }

    let mut suggestions = candidates
        .into_values()
        .map(RuleCandidate::into_suggestion)
        .collect::<Vec<_>>();
    suggestions.sort_by_key(rule_suggestion_sort_key);

    let mut diagnostics = discovery.diagnostics;
    diagnostics.extend(parse_output.diagnostics);
    diagnostics.extend(adapter_output.diagnostics);
    diagnostics.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });

    Ok(RuleSuggestionReport {
        target_roots: plan
            .targets
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect(),
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
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
    candidates: &mut BTreeMap<String, RuleCandidate>,
) {
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
    if should_skip_rule_candidate(symbol, route_handlers, rules) {
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
    symbol: &str,
    route_handlers: &BTreeSet<&str>,
    rules: &EvidenceRules,
) -> bool {
    let lower = symbol.to_ascii_lowercase();
    if symbol.is_empty()
        || symbol.starts_with('<')
        || route_handlers.contains(symbol)
        || rules.match_symbol(symbol).is_some()
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
    if lower.starts_with("can")
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
    if contains_any(&lower, &["role", "group"]) {
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
    let strong = evidence
        .iter()
        .copied()
        .filter(|item| item.confidence != Confidence::Low)
        .filter(|item| item.evidence_type != EvidenceType::UnknownDynamicCheck)
        .collect::<Vec<_>>();
    let weak = evidence
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

    let class = coverage_class(&strong, evidence);
    let risk = coverage_risk(
        route,
        class,
        evidence,
        &strong,
        &weak,
        sensitive,
        has_linked_mutations,
    );
    let mut reviewer_questions = reviewer_questions(
        route,
        class,
        sensitive,
        has_linked_mutations,
        &facts.configured_reviewer_questions,
    );
    if risk == RiskLevel::High && reviewer_questions.is_empty() {
        reviewer_questions
            .push("Should this route have server-side authorization evidence?".to_string());
    }

    Coverage {
        route_id: route.id.clone(),
        class,
        risk,
        rationale: coverage_rationale(
            class,
            risk,
            &strong,
            &weak,
            &sensitivity,
            has_linked_mutations,
        ),
        reviewer_questions,
        uncertainty_reasons: uncertainty_reasons(route, evidence),
        extensions: coverage_extensions(evidence, &weak, facts, &sensitivity),
    }
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
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use authmap_config::{ScanConfig, ScanPlan};
    use authmap_core::{
        Confidence, CoverageClass, Evidence, EvidenceType, Framework, Mutation, MutationOperation,
        ReachabilityLink, RiskLevel, Route,
    };
    use authmap_testkit::fixture_path;

    use super::{classify_coverage, run_scan, suggest_rules};

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
        assert_eq!(item.risk, RiskLevel::High);
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
        assert_eq!(item.risk, RiskLevel::High);
        assert_eq!(
            item.reviewer_questions,
            vec![
                "Should invoice writes require finance approval?".to_string(),
                "Should linked data mutations have resource-specific authorization evidence?"
                    .to_string(),
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

@app.get("/billing")
def get_billing(user=Depends(ensure_paid_plan)):
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
        let plan = ScanPlan::new(vec![temp.path().to_path_buf()], None, ScanConfig::default());
        let report = suggest_rules(&plan).expect("suggestions should run");

        assert!(
            report
                .suggestions
                .iter()
                .all(|suggestion| suggestion.matcher.exact != vec!["listUsers"])
        );
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
