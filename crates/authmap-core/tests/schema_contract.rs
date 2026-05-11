use std::path::{Path, PathBuf};

use authmap_core::{
    AuthMapDocument, Confidence, Coverage, CoverageClass, Evidence, EvidenceType, ExtensionMap,
    Framework, Mutation, MutationOperation, ReachabilityLink, RiskLevel, Route, SCHEMA_VERSION,
    ScanMetadata, SourceEvidence, Span, SymbolRef,
};
use serde_json::{Value, json};

fn repo_path(path: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn read_json(path: impl AsRef<Path>) -> Value {
    let path = repo_path(path);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn schema() -> Value {
    read_json("schemas/authmap.schema.json")
}

fn assert_valid(schema: &Value, instance: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    if let Err(error) = validator.validate(instance) {
        panic!("document should validate against AuthMap schema: {error}");
    }
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

#[test]
fn authmap_schema_is_valid_draft_2020_12() {
    let schema = schema();

    assert!(
        jsonschema::draft202012::meta::is_valid(&schema),
        "AuthMap schema should validate against the Draft 2020-12 metaschema"
    );
}

#[test]
fn examples_validate_and_deserialize() {
    let schema = schema();
    for example in [
        "examples/route-inventory.authmap.json",
        "examples/authorization-map.authmap.json",
    ] {
        let document = read_json(example);
        assert_valid(&schema, &document);
        serde_json::from_value::<AuthMapDocument>(document)
            .unwrap_or_else(|error| panic!("{example} should deserialize: {error}"));
    }
}

#[test]
fn rust_document_serialization_validates_against_schema() {
    let mut document = AuthMapDocument::empty(ScanMetadata {
        target_roots: vec!["src".to_string()],
        ..ScanMetadata::default()
    });
    document.extensions.insert(
        "authmap.test".to_string(),
        json!({ "description": "constructed in Rust" }),
    );
    document.routes.push(Route {
        id: "route.accounts.delete".to_string(),
        framework: Framework::Express,
        method: "DELETE".to_string(),
        path: "/accounts/:id".to_string(),
        handler: Some(symbol("deleteAccount", "src/routes/accounts.ts", 10, 14)),
        span: Some(span("src/routes/accounts.ts", 9, 1)),
        source_evidence: vec![SourceEvidence {
            mechanism: "express_router_method".to_string(),
            symbol: Some(symbol("router.delete", "src/routes/accounts.ts", 9, 1)),
            span: Some(span("src/routes/accounts.ts", 9, 1)),
            confidence: Confidence::High,
            notes: vec!["adapter source evidence".to_string()],
            extensions: ExtensionMap::new(),
        }],
        confidence: Confidence::High,
        notes: Vec::new(),
        extensions: ExtensionMap::new(),
    });
    document.evidence.push(Evidence {
        id: "evidence.accounts.authn".to_string(),
        route_id: Some("route.accounts.delete".to_string()),
        evidence_type: EvidenceType::Authn,
        mechanism: "middleware".to_string(),
        symbol: Some(symbol("requireUser", "src/routes/accounts.ts", 8, 8)),
        span: Some(span("src/routes/accounts.ts", 8, 8)),
        confidence: Confidence::High,
        notes: Vec::new(),
        extensions: ExtensionMap::new(),
    });
    document.mutations.push(Mutation {
        id: "mutation.accounts.delete".to_string(),
        operation: MutationOperation::Delete,
        library: Some("prisma".to_string()),
        resource: Some("Account".to_string()),
        span: Some(span("src/routes/accounts.ts", 20, 5)),
        confidence: Confidence::Medium,
        notes: Vec::new(),
        extensions: ExtensionMap::new(),
    });
    document.links.push(ReachabilityLink {
        id: "link.accounts.delete".to_string(),
        route_id: "route.accounts.delete".to_string(),
        mutation_id: Some("mutation.accounts.delete".to_string()),
        evidence_id: Some("evidence.accounts.authn".to_string()),
        confidence: Confidence::Medium,
        notes: Vec::new(),
        extensions: ExtensionMap::new(),
    });
    document.coverage.push(Coverage {
        route_id: "route.accounts.delete".to_string(),
        class: CoverageClass::AuthnOnly,
        risk: RiskLevel::ReviewRequired,
        rationale: vec!["Authentication evidence was detected.".to_string()],
        reviewer_questions: vec!["Should this route require ownership?".to_string()],
        uncertainty_reasons: vec!["Mutation reachability is approximate.".to_string()],
        extensions: ExtensionMap::new(),
    });

    assert_eq!(document.schema_version, SCHEMA_VERSION);
    let serialized = serde_json::to_value(document).expect("document should serialize");
    assert_valid(&schema(), &serialized);
}

#[test]
fn extension_keys_must_be_namespaced() {
    let schema = schema();
    let mut document = read_json("examples/route-inventory.authmap.json");

    document["extensions"] = json!({ "authmap.test": true });
    assert_valid(&schema, &document);

    document["extensions"] = json!({ "badkey": true });
    let validator = jsonschema::validator_for(&schema).expect("schema should compile");
    assert!(
        !validator.is_valid(&document),
        "un-namespaced extension keys should be rejected"
    );
}

#[test]
fn schema_lists_all_documented_evidence_types() {
    let schema = schema();
    let actual = schema["$defs"]["evidence_type"]["enum"]
        .as_array()
        .expect("evidence_type enum should be an array")
        .iter()
        .map(|value| value.as_str().expect("enum value should be a string"))
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            "authn",
            "role_check",
            "permission_check",
            "ownership_check",
            "tenant_check",
            "admin_check",
            "explicit_public",
            "audit_log",
            "unknown_dynamic_check"
        ]
    );
}
