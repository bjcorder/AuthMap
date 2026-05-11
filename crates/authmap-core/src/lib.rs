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
            diagnostics: Vec::new(),
            extensions: ExtensionMap::new(),
        }
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
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub recoverability: Recoverability,
    pub span: Option<Span>,
    pub message: String,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Route {
    pub id: String,
    pub framework: Framework,
    pub method: String,
    pub path: String,
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
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SymbolRef {
    pub name: String,
    pub span: Option<Span>,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}
