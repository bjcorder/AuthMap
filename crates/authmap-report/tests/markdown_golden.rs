use authmap_analysis::run_scan;
use authmap_config::{ScanConfig, ScanPlan};
use authmap_core::{AuthMapDocument, ScanMetadata};
use authmap_report::{MarkdownReporter, Reporter};
use authmap_testkit::fixture_path;

#[test]
fn empty_markdown_matches_golden() {
    let document = AuthMapDocument::empty(ScanMetadata::default());
    assert_markdown_eq(
        MarkdownReporter
            .render(&document)
            .expect("markdown render should succeed"),
        include_str!("../../../tests/golden/markdown/empty.md"),
    );
}

#[test]
fn fastapi_markdown_matches_golden() {
    let document = scan_fixture("fastapi");
    assert_markdown_eq(
        MarkdownReporter
            .render(&document)
            .expect("markdown render should succeed"),
        include_str!("../../../tests/golden/markdown/fastapi.md"),
    );
}

#[test]
fn express_markdown_matches_golden() {
    let document = scan_fixture("express");
    assert_markdown_eq(
        MarkdownReporter
            .render(&document)
            .expect("markdown render should succeed"),
        include_str!("../../../tests/golden/markdown/express.md"),
    );
}

fn scan_fixture(name: &str) -> AuthMapDocument {
    let plan = ScanPlan::new(vec![fixture_path(name)], None, ScanConfig::default());
    run_scan(&plan).expect("fixture scan should succeed")
}

fn assert_markdown_eq(actual: String, expected: &str) {
    assert_eq!(normalize(&actual), normalize(expected));
}

fn normalize(input: &str) -> String {
    let fixture_root = fixture_path("")
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string();
    input
        .replace("\r\n", "\n")
        .replace('\\', "/")
        .replace(&fixture_root, "tests/fixtures")
}
