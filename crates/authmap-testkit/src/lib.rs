use std::path::{Path, PathBuf};

use authmap_core::AuthMapDocument;
use authmap_report::{MarkdownReporter, Reporter};

pub fn fixture_root() -> PathBuf {
    repo_relative_path("../../tests/fixtures")
}

pub fn fixture_path(name: impl AsRef<Path>) -> PathBuf {
    fixture_root().join(name)
}

pub fn golden_root() -> PathBuf {
    repo_relative_path("../../tests/golden")
}

pub fn golden_path(name: impl AsRef<Path>) -> PathBuf {
    golden_root().join(name)
}

pub fn render_json(document: &AuthMapDocument) -> String {
    serde_json::to_string_pretty(document).expect("AuthMapDocument should render as JSON")
}

pub fn render_markdown(document: &AuthMapDocument) -> String {
    MarkdownReporter
        .render(document)
        .expect("AuthMapDocument should render as Markdown")
}

pub fn assert_snapshot_eq(actual: impl AsRef<str>, expected: impl AsRef<str>) {
    assert_eq!(
        normalize_snapshot(actual.as_ref()),
        normalize_snapshot(expected.as_ref())
    );
}

pub fn normalize_snapshot(input: &str) -> String {
    let fixture_root_path = fixture_root();
    let golden_root_path = golden_root();
    let repo_root_path = repo_relative_path("../..");
    let fixture_root = normalize_path(&fixture_root_path);
    let canonical_fixture_root = canonical_normalize_path(&fixture_root_path);
    let golden_root = normalize_path(&golden_root_path);
    let canonical_golden_root = canonical_normalize_path(&golden_root_path);
    let repo_root = normalize_path(&repo_root_path);
    let canonical_repo_root = canonical_normalize_path(&repo_root_path);

    input
        .replace("\r\n", "\n")
        .replace(&fixture_root, "tests/fixtures")
        .replace(&canonical_fixture_root, "tests/fixtures")
        .replace(&golden_root, "tests/golden")
        .replace(&canonical_golden_root, "tests/golden")
        .replace(&repo_root, ".")
        .replace(&canonical_repo_root, ".")
        .trim_end_matches('\n')
        .to_string()
}

fn repo_relative_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string()
}

fn canonical_normalize_path(path: &Path) -> String {
    path.canonicalize()
        .map(|path| normalize_path(&path))
        .unwrap_or_else(|_| normalize_path(path))
}
