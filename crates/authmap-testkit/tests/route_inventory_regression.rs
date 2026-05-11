use authmap_analysis::run_scan;
use authmap_config::{ScanConfig, ScanPlan};
use authmap_core::{AuthMapDocument, ScanMetadata};
use authmap_testkit::{
    assert_snapshot_eq, fixture_path, golden_path, render_json, render_markdown,
};

#[test]
fn empty_json_matches_golden() {
    assert_golden_eq(
        render_json(&AuthMapDocument::empty(ScanMetadata::default())),
        "json/empty.json",
    );
}

#[test]
fn fastapi_json_matches_golden() {
    assert_golden_eq(render_json(&scan_fixture("fastapi")), "json/fastapi.json");
}

#[test]
fn express_json_matches_golden() {
    assert_golden_eq(render_json(&scan_fixture("express")), "json/express.json");
}

#[test]
fn frontend_only_json_matches_golden_and_has_no_backend_facts() {
    let document = scan_fixture("negative/frontend_only");

    assert!(document.routes.is_empty());
    assert!(document.evidence.is_empty());
    assert!(document.mutations.is_empty());
    assert!(document.links.is_empty());
    assert!(document.coverage.is_empty());
    assert_golden_eq(render_json(&document), "json/frontend_only.json");
}

#[test]
fn active_markdown_goldens_match_pipeline_output() {
    assert_golden_eq(
        render_markdown(&scan_fixture("fastapi")),
        "markdown/fastapi.md",
    );
    assert_golden_eq(
        render_markdown(&scan_fixture("express")),
        "markdown/express.md",
    );
}

#[test]
fn repeated_scans_are_stable() {
    let first = render_json(&scan_fixture("express"));
    let second = render_json(&scan_fixture("express"));

    assert_snapshot_eq(first, second);
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
