use authmap_analysis::run_scan;
use authmap_config::{ScanConfig, ScanPlan};
use authmap_core::{AuthMapDocument, CoverageClass, DiagnosticSeverity, RiskLevel};
use authmap_testkit::{
    assert_snapshot_eq, fixture_path, golden_path, render_json, render_markdown,
};

#[test]
fn realistic_fastapi_json_and_markdown_match_goldens() {
    let document = scan_fixture("realistic/fastapi");
    assert_realistic_document(
        &document,
        RealisticExpectations {
            routes: 9,
            evidence: 14,
            mutations: 4,
            links: 5,
            diagnostic_codes: &[
                "fastapi_dynamic_include_router_prefix",
                "fastapi_dynamic_router_prefix",
            ],
        },
    );

    assert_golden_eq(render_json(&document), "json/realistic_fastapi.json");
    assert_golden_eq(render_markdown(&document), "markdown/realistic_fastapi.md");
}

#[test]
fn realistic_express_json_and_markdown_match_goldens() {
    let document = scan_fixture("realistic/express");
    assert_realistic_document(
        &document,
        RealisticExpectations {
            routes: 15,
            evidence: 37,
            mutations: 4,
            links: 10,
            diagnostic_codes: &[
                "express_dynamic_mount_prefix",
                "express_unresolved_mount_router",
            ],
        },
    );

    assert_golden_eq(render_json(&document), "json/realistic_express.json");
    assert_golden_eq(render_markdown(&document), "markdown/realistic_express.md");
}

struct RealisticExpectations<'a> {
    routes: usize,
    evidence: usize,
    mutations: usize,
    links: usize,
    diagnostic_codes: &'a [&'a str],
}

fn assert_realistic_document(document: &AuthMapDocument, expected: RealisticExpectations<'_>) {
    assert_eq!(document.routes.len(), expected.routes);
    assert_eq!(document.evidence.len(), expected.evidence);
    assert_eq!(document.mutations.len(), expected.mutations);
    assert_eq!(document.links.len(), expected.links);
    assert_eq!(document.coverage.len(), expected.routes);

    for code in expected.diagnostic_codes {
        assert!(
            document
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == *code
                    && diagnostic.severity == DiagnosticSeverity::Warning),
            "missing expected diagnostic {code}"
        );
    }

    assert!(
        document.links.iter().any(|link| link.mutation_id.is_none()),
        "realistic fixtures should include unresolved service-call reachability notes"
    );
    assert!(
        document
            .coverage
            .iter()
            .any(|coverage| coverage.risk == RiskLevel::ReviewRequired
                && coverage_has_mutation_support(coverage)),
        "realistic fixtures should include a review-required route with linked mutations"
    );
    assert!(
        document.coverage.iter().any(|coverage| matches!(
            coverage.class,
            CoverageClass::AdminGuarded
                | CoverageClass::PermissionGuarded
                | CoverageClass::TenantGuarded
        )),
        "realistic fixtures should include stronger authorization evidence than authn"
    );
}

fn coverage_has_mutation_support(coverage: &authmap_core::Coverage) -> bool {
    coverage
        .extensions
        .get("authmap.coverage")
        .and_then(|support| support.get("mutation_ids"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|ids| !ids.is_empty())
}

fn scan_fixture(name: &str) -> AuthMapDocument {
    let plan = ScanPlan::new(vec![fixture_path(name)], None, ScanConfig::default());
    run_scan(&plan).expect("fixture scan should succeed")
}

fn assert_golden_eq(actual: String, golden_name: &str) {
    let golden = golden_path(golden_name);
    if std::env::var_os("AUTHMAP_UPDATE_GOLDENS").is_some() {
        std::fs::create_dir_all(
            golden
                .parent()
                .expect("golden path should always include a parent"),
        )
        .unwrap_or_else(|error| panic!("failed to create golden directory {golden_name}: {error}"));
        std::fs::write(&golden, authmap_testkit::normalize_snapshot(&actual))
            .unwrap_or_else(|error| panic!("failed to update golden {golden_name}: {error}"));
        return;
    }

    let expected = std::fs::read_to_string(&golden)
        .unwrap_or_else(|error| panic!("failed to read golden {golden_name}: {error}"));
    assert_snapshot_eq(actual, expected);
}
