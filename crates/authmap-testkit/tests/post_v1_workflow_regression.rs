use authmap_analysis::{
    DriftConfigMetadata, analyze_controls_with_config, analyze_drift, run_scan,
};
use authmap_config::{DriftFailCategory, ScanConfig, ScanPlan};
use authmap_core::{AuthMapDocument, ScanMode};
use authmap_report::{
    render_controls_json, render_controls_markdown, render_drift_json, render_drift_markdown,
    render_tenants_json, render_tenants_markdown,
};
use authmap_testkit::{
    assert_snapshot_eq, fixture_path, golden_path, render_json, render_markdown,
};
use serde_json::Value;

#[test]
fn policy_explanation_workflow_matches_golden_and_cites_evidence() {
    let document = scan_fixture("realistic/express");

    assert!(
        document.policy_cases.iter().any(|case| {
            !case.evidence_ids.is_empty()
                && (!case.branches.is_empty() || !case.uncertainty_reasons.is_empty())
        }),
        "policy workflow should include evidence-backed policy cases"
    );
    assert!(
        document.coverage.iter().any(|coverage| {
            coverage
                .extensions
                .get("authmap.coverage")
                .and_then(|support| support.get("policy_case_ids"))
                .and_then(Value::as_array)
                .is_some_and(|ids| !ids.is_empty())
        }),
        "coverage should link policy case IDs for explanation workflows"
    );

    let markdown = render_markdown(&document);
    assert!(markdown.contains("PolicyLens"));
    assert!(markdown.contains("Dynamic policy behavior requires review"));

    assert_golden_eq(render_json(&document), "json/realistic_express.json");
    assert_golden_eq(markdown, "markdown/realistic_express.md");
}

#[test]
fn tenant_review_workflow_matches_focused_goldens() {
    let document = scan_fixture("realistic/express");

    assert!(
        document.coverage.iter().any(|coverage| {
            coverage
                .extensions
                .get("authmap.tenant_review")
                .and_then(|tenant| tenant.get("review_required"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }),
        "tenant workflow should include review-required tenant metadata"
    );

    let tenant_json = render_tenants_json(&document).expect("tenant JSON should render");
    let tenant_markdown = render_tenants_markdown(&document);
    assert!(tenant_json.contains("authmap.tenants"));
    assert!(tenant_markdown.contains("# AuthMap Tenant Review"));
    assert!(tenant_markdown.contains("Should this route require tenant"));

    assert_golden_eq(tenant_json, "json/tenant_realistic_express.json");
    assert_golden_eq(tenant_markdown, "markdown/tenant_realistic_express.md");
}

#[test]
fn semantic_diff_workflow_matches_goldens() {
    let base = scan_fixture("diff/base");
    let head = scan_fixture("diff/head");
    let report = analyze_drift(
        &base,
        &head,
        ScanMode::Enforce,
        &[
            DriftFailCategory::AddedHighRiskRoute,
            DriftFailCategory::AuthDowngrade,
            DriftFailCategory::RemovedAuthorizationEvidence,
            DriftFailCategory::PolicyDecisionChange,
            DriftFailCategory::NewLinkedMutation,
        ],
        "tests/fixtures/diff/base",
        "tests/fixtures/diff/head",
    );

    assert!(
        report.summary.added_routes >= 1,
        "diff fixture should cover added routes"
    );
    assert!(
        report.summary.coverage_changes >= 1,
        "diff fixture should cover coverage drift"
    );
    assert!(
        report.summary.removed_evidence >= 1,
        "diff fixture should cover removed authorization evidence"
    );
    assert!(
        report.summary.policy_changes >= 1,
        "diff fixture should cover policy decision drift"
    );
    assert!(
        report
            .changes
            .iter()
            .any(|change| !change.reviewer_questions.is_empty()),
        "diff snapshots should include reviewer questions where applicable"
    );
    assert!(report.has_enforce_blocking_changes());

    assert_golden_eq(
        render_drift_json(&report).expect("drift JSON should render"),
        "json/diff_semantic.json",
    );
    assert_golden_eq(render_drift_markdown(&report), "markdown/diff_semantic.md");

    let controls = analyze_controls_with_config(
        &base,
        &head,
        ScanMode::Enforce,
        &[
            DriftFailCategory::AddedHighRiskRoute,
            DriftFailCategory::AuthDowngrade,
            DriftFailCategory::RemovedAuthorizationEvidence,
            DriftFailCategory::PolicyDecisionChange,
            DriftFailCategory::NewLinkedMutation,
        ],
        "tests/fixtures/diff/base",
        "tests/fixtures/diff/head",
        DriftConfigMetadata::none(),
    );
    assert!(
        controls.summary.total_findings >= 1,
        "controls workflow should report auth-relevant control drift"
    );
    assert!(controls.has_enforce_blocking_findings());
    assert_golden_eq(
        render_controls_json(&controls).expect("controls JSON should render"),
        "json/controls_semantic.json",
    );
    assert_golden_eq(
        render_controls_markdown(&controls),
        "markdown/controls_semantic.md",
    );
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
