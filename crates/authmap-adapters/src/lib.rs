use authmap_core::{Diagnostic, Evidence, Mutation, Route, Span};
use authmap_parsers::ParsedFile;
use tree_sitter::{Node, Tree};

#[derive(Clone, Debug, Default)]
pub struct AdapterContext {
    pub enabled_frameworks: Vec<String>,
}

pub struct AdapterInput<'a> {
    pub parsed: &'a ParsedFile,
    pub context: &'a AdapterContext,
}

impl<'a> AdapterInput<'a> {
    pub fn new(parsed: &'a ParsedFile, context: &'a AdapterContext) -> Self {
        Self { parsed, context }
    }

    pub fn source_text(&self) -> &'a str {
        &self.parsed.text
    }

    pub fn tree(&self) -> Option<&'a Tree> {
        self.parsed.tree()
    }

    pub fn span_for_node(&self, node: Node<'_>) -> Span {
        self.parsed.span_for_node(node)
    }

    pub fn snippet(&self, span: &Span) -> Option<&'a str> {
        self.parsed.snippet(span)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AdapterOutput {
    pub routes: Vec<Route>,
    pub evidence: Vec<Evidence>,
    pub mutations: Vec<Mutation>,
    pub diagnostics: Vec<Diagnostic>,
}

pub trait FrameworkAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze(&self, input: AdapterInput<'_>) -> AdapterOutput;
}

#[derive(Clone, Debug, Default)]
pub struct AdapterRegistry {
    adapters: Vec<&'static str>,
}

impl AdapterRegistry {
    pub fn built_in() -> Self {
        Self {
            adapters: vec!["fastapi", "express", "django_drf", "nextjs_app_router"],
        }
    }

    pub fn names(&self) -> &[&'static str] {
        &self.adapters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authmap_core::{
        Confidence, DiagnosticCategory, DiagnosticSeverity, EvidenceType, ExtensionMap, Framework,
        Language, MutationOperation, ProjectHint, Recoverability, SkipReason, SourceFile,
        diagnostic_codes,
    };
    use authmap_parsers::{ParserBackend, TreeSitterBackend};

    fn source(path: &str, language: Language) -> SourceFile {
        SourceFile {
            path: path.to_string(),
            language,
            size_bytes: 0,
            sha256: None,
            project_hints: Vec::<ProjectHint>::new(),
            skipped: None::<SkipReason>,
        }
    }

    #[derive(Default)]
    struct FakeAdapter;

    impl FrameworkAdapter for FakeAdapter {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn analyze(&self, input: AdapterInput<'_>) -> AdapterOutput {
            let root = input
                .tree()
                .expect("fake adapter expects a parse tree")
                .root_node();
            let route_span = input.span_for_node(root);
            AdapterOutput {
                routes: vec![Route {
                    id: "route.fake".to_string(),
                    framework: Framework::Express,
                    method: "GET".to_string(),
                    path: "/fake".to_string(),
                    handler: None,
                    span: Some(route_span.clone()),
                    source_evidence: Vec::new(),
                    confidence: Confidence::High,
                    notes: Vec::new(),
                    extensions: ExtensionMap::new(),
                }],
                evidence: vec![Evidence {
                    id: "evidence.fake.authn".to_string(),
                    route_id: Some("route.fake".to_string()),
                    evidence_type: EvidenceType::Authn,
                    mechanism: "fake_guard".to_string(),
                    symbol: None,
                    span: Some(route_span.clone()),
                    confidence: Confidence::Medium,
                    notes: Vec::new(),
                    extensions: ExtensionMap::new(),
                }],
                mutations: vec![Mutation {
                    id: "mutation.fake".to_string(),
                    operation: MutationOperation::UnknownMutation,
                    library: None,
                    resource: None,
                    span: Some(route_span.clone()),
                    confidence: Confidence::Low,
                    notes: Vec::new(),
                    extensions: ExtensionMap::new(),
                }],
                diagnostics: vec![Diagnostic {
                    category: DiagnosticCategory::Adapter,
                    code: diagnostic_codes::ADAPTER_PARTIAL_RESULT.to_string(),
                    severity: DiagnosticSeverity::Warning,
                    recoverability: Recoverability::Recoverable,
                    span: Some(route_span),
                    message: "fake adapter emitted partial facts".to_string(),
                }],
            }
        }
    }

    #[test]
    fn fake_adapter_can_emit_facts_and_diagnostics() {
        let parsed = TreeSitterBackend
            .parse(
                &source("src/routes.ts", Language::TypeScript),
                "export function route() { return true; }\n",
            )
            .expect("source should parse");
        let context = AdapterContext::default();
        let output = FakeAdapter.analyze(AdapterInput::new(&parsed, &context));

        assert_eq!(output.routes.len(), 1);
        assert_eq!(output.evidence.len(), 1);
        assert_eq!(output.mutations.len(), 1);
        assert_eq!(output.diagnostics.len(), 1);
    }

    #[test]
    fn adapter_diagnostics_do_not_discard_partial_facts() {
        let parsed = TreeSitterBackend
            .parse(
                &source("src/routes.ts", Language::TypeScript),
                "export function route() { return true; }\n",
            )
            .expect("source should parse");
        let context = AdapterContext::default();
        let output = FakeAdapter.analyze(AdapterInput::new(&parsed, &context));

        assert_eq!(
            output.diagnostics[0].code,
            diagnostic_codes::ADAPTER_PARTIAL_RESULT
        );
        assert_eq!(output.routes[0].id, "route.fake");
        assert_eq!(output.evidence[0].id, "evidence.fake.authn");
        assert_eq!(output.mutations[0].id, "mutation.fake");
    }

    #[test]
    fn registry_exposes_built_in_adapter_names() {
        assert_eq!(
            AdapterRegistry::built_in().names(),
            &["fastapi", "express", "django_drf", "nextjs_app_router"]
        );
    }
}
