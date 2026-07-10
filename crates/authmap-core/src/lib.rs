use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: &str = "0.1.0";

pub type ExtensionMap = BTreeMap<String, Value>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthMapDocument {
    pub schema_version: String,
    pub metadata: ScanMetadata,
    pub source_files: Vec<SourceFile>,
    pub routes: Vec<Route>,
    pub evidence: Vec<Evidence>,
    pub mutations: Vec<Mutation>,
    pub links: Vec<ReachabilityLink>,
    pub coverage: Vec<Coverage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_cases: Vec<PolicyCase>,
    pub diagnostics: Vec<Diagnostic>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

impl AuthMapDocument {
    pub fn empty(metadata: ScanMetadata) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            metadata,
            source_files: Vec::new(),
            routes: Vec::new(),
            evidence: Vec::new(),
            mutations: Vec::new(),
            links: Vec::new(),
            coverage: Vec::new(),
            policy_cases: Vec::new(),
            diagnostics: Vec::new(),
            extensions: ExtensionMap::new(),
        }
    }

    pub fn has_enforce_blocking_diagnostics(&self) -> bool {
        self.metadata.mode == ScanMode::Enforce
            && self.diagnostics.iter().any(Diagnostic::is_enforce_blocking)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanMetadata {
    pub tool_name: String,
    pub tool_version: String,
    pub mode: ScanMode,
    pub target_roots: Vec<String>,
    pub config_path: Option<String>,
}

impl Default for ScanMetadata {
    fn default() -> Self {
        Self {
            tool_name: "authmap".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            mode: ScanMode::Advisory,
            target_roots: Vec::new(),
            config_path: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Advisory,
    Enforce,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceFile {
    pub path: String,
    pub language: Language,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub project_hints: Vec<ProjectHint>,
    pub skipped: Option<SkipReason>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    JavaScript,
    JavaScriptReact,
    TypeScript,
    TypeScriptReact,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectHint {
    FastApi,
    Django,
    DjangoRestFramework,
    Express,
    NextJs,
    SqlAlchemy,
    DjangoOrm,
    Prisma,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SkipReason {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Span {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub byte_range: Option<ByteRange>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Diagnostic {
    pub category: DiagnosticCategory,
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub recoverability: Recoverability,
    pub span: Option<Span>,
    pub message: String,
}

impl Diagnostic {
    pub fn is_enforce_blocking(&self) -> bool {
        self.severity == DiagnosticSeverity::Error || self.recoverability == Recoverability::Fatal
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    Config,
    Discovery,
    Parser,
    Adapter,
    Report,
    Internal,
    Policy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Recoverability {
    Recoverable,
    Fatal,
}

pub mod diagnostic_codes {
    pub const CONFIG_READ_FAILED: &str = "config.read_failed";
    pub const CONFIG_PARSE_FAILED: &str = "config.parse_failed";
    pub const CONFIG_VALIDATION_FAILED: &str = "config.validation_failed";
    pub const CONFIG_INVALID_PATTERN: &str = "config.invalid_pattern";

    pub const DISCOVERY_NO_CANDIDATE_SOURCES: &str = "discovery.no_candidate_sources";
    pub const DISCOVERY_FILE_TOO_LARGE: &str = "discovery.file_too_large";
    pub const DISCOVERY_FILE_LIMIT_REACHED: &str = "discovery.file_limit_reached";
    pub const DISCOVERY_TOTAL_BYTES_LIMIT_REACHED: &str = "discovery.total_bytes_limit_reached";
    pub const DISCOVERY_TARGET_UNAVAILABLE: &str = "discovery.target_unavailable";
    pub const DISCOVERY_EMPTY_TARGET: &str = "discovery.empty_target";
    pub const DISCOVERY_METADATA_FAILED: &str = "discovery.metadata_failed";

    pub const PARSER_SOURCE_LANGUAGE_UNSUPPORTED: &str = "parser.source_language_unsupported";
    pub const PARSER_SOURCE_PARSE_RECOVERED: &str = "parser.source_parse_recovered";
    pub const PARSER_SOURCE_READ_FAILED: &str = "parser.source_read_failed";
    pub const PARSER_SOURCE_PARSE_FAILED: &str = "parser.source_parse_failed";

    pub const ADAPTER_UNSUPPORTED_FRAMEWORK: &str = "adapter.unsupported_framework";
    pub const ADAPTER_PARTIAL_RESULT: &str = "adapter.partial_result";
    pub const DJANGO_CUSTOM_ROUTER: &str = "django_custom_router";
    pub const DJANGO_DYNAMIC_INCLUDE: &str = "django_dynamic_include";
    pub const DJANGO_DYNAMIC_INCLUDE_HELPER: &str = "django_dynamic_include_helper";
    pub const DJANGO_INCLUDE_DEPTH_EXCEEDED: &str = "django_include_depth_exceeded";
    pub const DJANGO_DYNAMIC_URL_PATH: &str = "django_dynamic_url_path";
    pub const DJANGO_UNRESOLVED_HANDLER: &str = "django_unresolved_handler";
    pub const DJANGO_UNRESOLVED_INCLUDE: &str = "django_unresolved_include";
    pub const DJANGO_URLPATTERN_CONTEXT_UNCERTAIN: &str = "django_urlpattern_context_uncertain";
    pub const DRF_DYNAMIC_BASENAME: &str = "drf_dynamic_basename";
    pub const DRF_DYNAMIC_ROUTER_PREFIX: &str = "drf_dynamic_router_prefix";
    pub const DRF_UNRESOLVED_VIEWSET: &str = "drf_unresolved_viewset";
    pub const DRF_UNRESOLVED_VIEWSET_BASE: &str = "drf_unresolved_viewset_base";
    pub const NEXTJS_DYNAMIC_ROUTE_EXPORT: &str = "nextjs_dynamic_route_export";
    pub const NEXTJS_EXTERNAL_REEXPORT_UNRESOLVED: &str = "nextjs_external_reexport_unresolved";
    pub const NEXTJS_NESTED_APP_SEGMENT: &str = "nextjs_nested_app_segment";
    pub const NEXTJS_UNUSUAL_ROUTE_SEGMENT: &str = "nextjs_unusual_route_segment";
    pub const NEXTJS_SERVER_ACTION_NOT_ANALYZED: &str = "nextjs_server_action_not_analyzed";

    pub const REPORT_RENDER_FAILED: &str = "report.render_failed";
    pub const REPORT_WRITE_FAILED: &str = "report.write_failed";

    pub const POLICY_CONFLICTING_EVIDENCE: &str = "policy.conflicting_evidence";
    pub const POLICY_DUPLICATE_EVIDENCE: &str = "policy.duplicate_evidence";
    pub const POLICY_UNREACHABLE_BRANCH: &str = "policy.unreachable_branch";
    pub const POLICY_DYNAMIC_BEHAVIOR: &str = "policy.dynamic_behavior";

    pub const INTERNAL_SCAN_FAILED: &str = "internal.scan_failed";
    pub const INTERNAL_RUNTIME_LIMIT_REACHED: &str = "internal.runtime_limit_reached";
}

pub const FIRST_PARTY_DIAGNOSTIC_CODES: &[(&str, DiagnosticCategory)] = &[
    (
        diagnostic_codes::CONFIG_READ_FAILED,
        DiagnosticCategory::Config,
    ),
    (
        diagnostic_codes::CONFIG_PARSE_FAILED,
        DiagnosticCategory::Config,
    ),
    (
        diagnostic_codes::CONFIG_VALIDATION_FAILED,
        DiagnosticCategory::Config,
    ),
    (
        diagnostic_codes::CONFIG_INVALID_PATTERN,
        DiagnosticCategory::Config,
    ),
    (
        diagnostic_codes::DISCOVERY_NO_CANDIDATE_SOURCES,
        DiagnosticCategory::Discovery,
    ),
    (
        diagnostic_codes::DISCOVERY_FILE_TOO_LARGE,
        DiagnosticCategory::Discovery,
    ),
    (
        diagnostic_codes::DISCOVERY_FILE_LIMIT_REACHED,
        DiagnosticCategory::Discovery,
    ),
    (
        diagnostic_codes::DISCOVERY_TOTAL_BYTES_LIMIT_REACHED,
        DiagnosticCategory::Discovery,
    ),
    (
        diagnostic_codes::DISCOVERY_TARGET_UNAVAILABLE,
        DiagnosticCategory::Discovery,
    ),
    (
        diagnostic_codes::DISCOVERY_EMPTY_TARGET,
        DiagnosticCategory::Discovery,
    ),
    (
        diagnostic_codes::DISCOVERY_METADATA_FAILED,
        DiagnosticCategory::Discovery,
    ),
    (
        diagnostic_codes::PARSER_SOURCE_LANGUAGE_UNSUPPORTED,
        DiagnosticCategory::Parser,
    ),
    (
        diagnostic_codes::PARSER_SOURCE_PARSE_RECOVERED,
        DiagnosticCategory::Parser,
    ),
    (
        diagnostic_codes::PARSER_SOURCE_READ_FAILED,
        DiagnosticCategory::Parser,
    ),
    (
        diagnostic_codes::PARSER_SOURCE_PARSE_FAILED,
        DiagnosticCategory::Parser,
    ),
    (
        diagnostic_codes::ADAPTER_UNSUPPORTED_FRAMEWORK,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::ADAPTER_PARTIAL_RESULT,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_CUSTOM_ROUTER,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_DYNAMIC_INCLUDE,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_DYNAMIC_INCLUDE_HELPER,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_INCLUDE_DEPTH_EXCEEDED,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_DYNAMIC_URL_PATH,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_UNRESOLVED_HANDLER,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_UNRESOLVED_INCLUDE,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DJANGO_URLPATTERN_CONTEXT_UNCERTAIN,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DRF_DYNAMIC_BASENAME,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DRF_DYNAMIC_ROUTER_PREFIX,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DRF_UNRESOLVED_VIEWSET,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::DRF_UNRESOLVED_VIEWSET_BASE,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::NEXTJS_DYNAMIC_ROUTE_EXPORT,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::NEXTJS_EXTERNAL_REEXPORT_UNRESOLVED,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::NEXTJS_NESTED_APP_SEGMENT,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::NEXTJS_UNUSUAL_ROUTE_SEGMENT,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::NEXTJS_SERVER_ACTION_NOT_ANALYZED,
        DiagnosticCategory::Adapter,
    ),
    (
        diagnostic_codes::REPORT_RENDER_FAILED,
        DiagnosticCategory::Report,
    ),
    (
        diagnostic_codes::REPORT_WRITE_FAILED,
        DiagnosticCategory::Report,
    ),
    (
        diagnostic_codes::POLICY_CONFLICTING_EVIDENCE,
        DiagnosticCategory::Policy,
    ),
    (
        diagnostic_codes::POLICY_DUPLICATE_EVIDENCE,
        DiagnosticCategory::Policy,
    ),
    (
        diagnostic_codes::POLICY_UNREACHABLE_BRANCH,
        DiagnosticCategory::Policy,
    ),
    (
        diagnostic_codes::POLICY_DYNAMIC_BEHAVIOR,
        DiagnosticCategory::Policy,
    ),
    (
        diagnostic_codes::INTERNAL_SCAN_FAILED,
        DiagnosticCategory::Internal,
    ),
    (
        diagnostic_codes::INTERNAL_RUNTIME_LIMIT_REACHED,
        DiagnosticCategory::Internal,
    ),
];

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Route {
    pub id: String,
    pub framework: Framework,
    pub method: String,
    pub path: String,
    pub name: Option<String>,
    pub tags: Vec<String>,
    pub middleware: Vec<SymbolRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<RouteParam>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_protection: Vec<RouteProtection>,
    pub handler: Option<SymbolRef>,
    pub span: Option<Span>,
    #[serde(default)]
    pub source_evidence: Vec<SourceEvidence>,
    pub confidence: Confidence,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    FastApi,
    Django,
    DjangoRestFramework,
    Express,
    NextJs,
    Trpc,
    Graphql,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SymbolRef {
    pub name: String,
    pub span: Option<Span>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteParam {
    pub name: String,
    pub syntax: String,
    pub span: Option<Span>,
    pub confidence: Confidence,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RouteProtection {
    pub kind: RouteProtectionKind,
    pub mechanism: String,
    pub symbol: Option<SymbolRef>,
    pub span: Option<Span>,
    pub inherited: bool,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteProtectionKind {
    PublicDeclared,
    RouteGuard,
    InheritedGuard,
    UnknownDynamic,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SourceEvidence {
    pub mechanism: String,
    pub symbol: Option<SymbolRef>,
    pub span: Option<Span>,
    pub confidence: Confidence,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Evidence {
    pub id: String,
    pub route_id: Option<String>,
    pub evidence_type: EvidenceType,
    pub mechanism: String,
    pub symbol: Option<SymbolRef>,
    pub span: Option<Span>,
    pub confidence: Confidence,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    Authn,
    RoleCheck,
    PermissionCheck,
    OwnershipCheck,
    TenantCheck,
    AdminCheck,
    ExplicitPublic,
    AuditLog,
    UnknownDynamicCheck,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Mutation {
    pub id: String,
    pub operation: MutationOperation,
    pub library: Option<String>,
    pub resource: Option<String>,
    pub span: Option<Span>,
    pub confidence: Confidence,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOperation {
    Create,
    Update,
    Delete,
    Save,
    BulkUpdate,
    RawSqlMutation,
    UnknownMutation,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReachabilityLink {
    pub id: String,
    pub route_id: String,
    pub mutation_id: Option<String>,
    pub evidence_id: Option<String>,
    pub confidence: Confidence,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Coverage {
    pub route_id: String,
    pub class: CoverageClass,
    pub risk: RiskLevel,
    pub rationale: Vec<String>,
    pub reviewer_questions: Vec<String>,
    #[serde(default)]
    pub uncertainty_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PolicyCase {
    pub id: String,
    pub route_id: String,
    pub kind: PolicyCaseKind,
    pub summary: String,
    pub evidence_ids: Vec<String>,
    pub input_names: Vec<String>,
    pub branches: Vec<PolicyBranch>,
    pub span: Option<Span>,
    pub confidence: Confidence,
    pub reviewer_questions: Vec<String>,
    pub uncertainty_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "ExtensionMap::is_empty")]
    pub extensions: ExtensionMap,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PolicyBranch {
    pub condition: String,
    pub outcome: PolicyOutcome,
    pub reachable: bool,
    pub evidence_ids: Vec<String>,
    pub span: Option<Span>,
    pub confidence: Confidence,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCaseKind {
    EffectiveProtection,
    LinkedMutationProtection,
    Conflict,
    Duplicate,
    Unreachable,
    Dynamic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Deny,
    Unknown,
    ReviewRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageClass {
    PublicDeclared,
    Unauthenticated,
    AuthnOnly,
    RoleGuarded,
    PermissionGuarded,
    OwnershipGuarded,
    TenantGuarded,
    AdminGuarded,
    UnknownOrDynamic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    ReviewRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}
