use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

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
            "authmap-cli-test-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test temp directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn authmap(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_authmap"))
        .args(args)
        .output()
        .expect("authmap binary should run")
}

fn authmap_in_dir(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_authmap"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("authmap binary should run")
}

fn authmap_with_stdin(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_authmap"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("authmap binary should run");
    child
        .stdin
        .as_mut()
        .expect("stdin should be available")
        .write_all(stdin.as_bytes())
        .expect("stdin should be written");
    child
        .wait_with_output()
        .expect("authmap binary should finish")
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("test fixture parent should be created");
    }
    fs::write(path, contents).expect("test fixture should be written");
}

fn write_bytes(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("test fixture parent should be created");
    }
    fs::write(path, contents).expect("test fixture should be written");
}

fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_valid_authmap_document(document: &Value) {
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("schemas/authmap.schema.json");
    let schema_text = fs::read_to_string(&schema_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", schema_path.display()));
    let schema: Value = serde_json::from_str(&schema_text)
        .unwrap_or_else(|error| panic!("schema should parse: {error}"));
    let validator = jsonschema::validator_for(&schema).expect("schema should compile");
    if let Err(error) = validator.validate(document) {
        panic!("CLI output should validate against AuthMap schema: {error}");
    }
}

fn assert_valid_sarif(document: &Value) {
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/schemas/sarif-2.1.0.schema.json");
    let schema_text = fs::read_to_string(&schema_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", schema_path.display()));
    let schema: Value = serde_json::from_str(&schema_text)
        .unwrap_or_else(|error| panic!("schema should parse: {error}"));
    let validator = jsonschema::validator_for(&schema).expect("schema should compile");
    if let Err(error) = validator.validate(document) {
        panic!("CLI SARIF output should validate against SARIF schema: {error}");
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn explain_document_json() -> &'static str {
    r#"
{
  "schema_version": "0.1.0",
  "metadata": {
    "tool_name": "authmap",
    "tool_version": "0.1.0",
    "mode": "advisory",
    "target_roots": ["src"],
    "config_path": null
  },
  "source_files": [],
  "routes": [
    {
      "id": "route_0001",
      "framework": "fast_api",
      "method": "GET",
      "path": "/accounts",
      "name": null,
      "tags": [],
      "middleware": [],
      "handler": null,
      "span": null,
      "source_evidence": [],
      "confidence": "high",
      "notes": []
    }
  ],
  "evidence": [
    {
      "id": "evidence_0001",
      "route_id": "route_0001",
      "evidence_type": "authn",
      "mechanism": "session_lookup",
      "symbol": null,
      "span": null,
      "confidence": "high",
      "notes": []
    }
  ],
  "mutations": [],
  "links": [],
  "coverage": [
    {
      "route_id": "route_0001",
      "class": "authn_only",
      "risk": "low",
      "rationale": ["authentication evidence was detected"],
      "reviewer_questions": [],
      "uncertainty_reasons": []
    }
  ],
  "diagnostics": []
}
"#
}

fn ambiguous_explain_document_json() -> String {
    explain_document_json().replace("\"id\": \"evidence_0001\"", "\"id\": \"route_0001\"")
}

fn drift_head_document() -> Value {
    let mut document: Value =
        serde_json::from_str(explain_document_json()).expect("fixture JSON should parse");
    document["coverage"][0]["class"] = json!("unauthenticated");
    document["coverage"][0]["risk"] = json!("high");
    document["coverage"][0]["rationale"] =
        json!(["authentication evidence disappeared between baseline and head"]);
    document["routes"]
        .as_array_mut()
        .expect("routes should be an array")
        .push(json!({
            "id": "route_0002",
            "framework": "fast_api",
            "method": "POST",
            "path": "/admin",
            "name": null,
            "tags": [],
            "middleware": [],
            "handler": {
                "name": "create_admin",
                "span": {
                    "file": "app.py",
                    "line": 8,
                    "column": 1,
                    "byte_range": { "start": 120, "end": 160 }
                }
            },
            "span": {
                "file": "app.py",
                "line": 7,
                "column": 1,
                "byte_range": { "start": 100, "end": 119 }
            },
            "source_evidence": [],
            "confidence": "high",
            "notes": []
        }));
    document["coverage"]
        .as_array_mut()
        .expect("coverage should be an array")
        .push(json!({
            "route_id": "route_0002",
            "class": "unauthenticated",
            "risk": "high",
            "rationale": ["new sensitive route has no authorization evidence"],
            "reviewer_questions": ["Should this route require explicit authorization?"],
            "uncertainty_reasons": []
        }));
    document
}

fn write_rules_suggest_project(project: &Path) {
    write_file(
        &project.join("app.js"),
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
}

#[test]
fn root_help_works() {
    let output = authmap(&["--help"]);

    assert_exit(&output, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("scan"));
}

#[test]
fn scan_help_works() {
    let output = authmap(&["scan", "--help"]);

    assert_exit(&output, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--mode"));
    assert!(stdout.contains("--max-files"));
    assert!(stdout.contains("--max-file-size-bytes"));
    assert!(stdout.contains("--max-total-bytes"));
    assert!(stdout.contains("--max-runtime-ms"));
}

#[test]
fn rules_suggest_help_shows_limit_overrides() {
    let output = authmap(&["rules", "suggest", "--help"]);

    assert_exit(&output, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--max-files"));
    assert!(stdout.contains("--max-file-size-bytes"));
    assert!(stdout.contains("--max-total-bytes"));
    assert!(stdout.contains("--max-runtime-ms"));
}

#[test]
fn ci_workflow_defines_cross_platform_rust_matrix_and_install_smoke() {
    let root = repo_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/rust.yml"))
        .expect("rust workflow should exist");

    for runner in [
        "blacksmith-4vcpu-ubuntu-2404",
        "blacksmith-6vcpu-macos-latest",
        "blacksmith-4vcpu-windows-2025",
    ] {
        assert!(workflow.contains(runner), "missing runner {runner}");
    }
    for rust in ["\"1.95\"", "stable"] {
        assert!(workflow.contains(rust), "missing Rust toolchain {rust}");
    }
    assert!(workflow.contains("permissions:"));
    assert!(workflow.contains("contents: read"));
    assert!(workflow.contains("toolchain: ${{ matrix.rust }}"));
    assert!(workflow.contains("components: rustfmt"));
    assert!(workflow.contains("actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830"));
    assert!(workflow.contains("~/.cargo/registry"));
    assert!(workflow.contains("~/.cargo/git"));
    assert!(!workflow.contains("target/"));
    assert!(workflow.contains("cargo fmt --all -- --check"));
    assert!(workflow.contains("cargo check --workspace --locked"));
    assert!(workflow.contains("cargo test --workspace --all-targets --locked"));
    assert!(workflow.contains("cargo install --path crates/authmap-cli --locked"));
    assert!(workflow.contains("& $authmap --help"));
    assert!(workflow.contains("--format json --output $json"));
    assert!(workflow.contains("--format markdown --output $markdown"));
    assert!(workflow.contains("baseline create tests/fixtures/negative/frontend_only"));
    assert!(workflow.contains("diff --base $baseline --head $json"));
    assert!(workflow.contains("RUST_BACKTRACE: \"1\""));
    assert!(workflow.contains("CARGO_TERM_COLOR: always"));
}

#[test]
fn action_metadata_defines_expected_wrapper_contract() {
    let root = repo_root();
    let action = fs::read_to_string(root.join("action.yml")).expect("action.yml should exist");
    let script = fs::read_to_string(root.join(".github/actions/authmap/run.sh"))
        .expect("action runner should exist");

    for input in [
        "mode:",
        "output:",
        "target:",
        "config:",
        "baseline:",
        "fail-on:",
        "output-directory:",
        "upload-artifact:",
        "artifact-name:",
        "upload-sarif:",
        "sarif-category:",
    ] {
        assert!(action.contains(input), "missing action input {input}");
    }
    for output in [
        "json-path:",
        "markdown-path:",
        "sarif-path:",
        "diff-json-path:",
        "diff-markdown-path:",
        "output-directory:",
    ] {
        assert!(action.contains(output), "missing action output {output}");
    }
    assert!(action.contains("using: composite"));
    assert!(action.contains(".github/actions/authmap/run.sh"));
    assert!(action.contains("AUTHMAP_DEFER_EXIT"));
    assert!(action.contains("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"));
    assert!(
        action
            .contains("github/codeql-action/upload-sarif@68bde559dea0fdcac2102bfdf6230c5f70eb485e")
    );
    assert!(action.contains("Propagate AuthMap exit code"));
    assert!(script.contains("cargo run --locked"));
    assert!(script.contains("GITHUB_STEP_SUMMARY"));
    assert!(script.contains("authmap.diff.json"));
    assert!(script.contains("authmap.diff.md"));
    assert!(script.contains("--fail-on"));
    assert!(script.contains("AUTHMAP_DEFER_EXIT"));
    assert!(script.contains("exit-code"));
}

#[test]
fn action_runner_generates_reports_outputs_and_step_summary() {
    if cfg!(windows) {
        return;
    }

    let temp = TestDir::new("action-runner");
    let root = repo_root();
    let github_output = temp.path().join("github-output.txt");
    let step_summary = temp.path().join("summary.md");
    let output_dir = temp.path().join("reports");
    let baseline_path = temp.path().join("baseline.json");

    let baseline = authmap_in_dir(
        &[
            "scan",
            "tests/fixtures/negative/frontend_only",
            "--format",
            "json",
            "--output",
            baseline_path.to_str().expect("path should be UTF-8"),
        ],
        &root,
    );
    assert_exit(&baseline, 0);

    let output = Command::new("bash")
        .arg(root.join(".github/actions/authmap/run.sh"))
        .current_dir(&root)
        .env("GITHUB_ACTION_PATH", &root)
        .env("GITHUB_WORKSPACE", &root)
        .env("GITHUB_OUTPUT", &github_output)
        .env("GITHUB_STEP_SUMMARY", &step_summary)
        .env("INPUT_MODE", "advisory")
        .env("INPUT_OUTPUT", "markdown,json,sarif")
        .env("INPUT_TARGET", "tests/fixtures/negative/frontend_only")
        .env("INPUT_CONFIG", "")
        .env("INPUT_BASELINE", &baseline_path)
        .env("INPUT_FAIL_ON", "")
        .env("INPUT_OUTPUT_DIRECTORY", &output_dir)
        .env("INPUT_UPLOAD_SARIF", "false")
        .output()
        .expect("action runner should execute");

    assert_exit(&output, 0);
    let markdown_path = output_dir.join("authmap.md");
    let json_path = output_dir.join("authmap.json");
    let sarif_path = output_dir.join("authmap.sarif");
    let diff_json_path = output_dir.join("authmap.diff.json");
    let diff_markdown_path = output_dir.join("authmap.diff.md");
    assert!(markdown_path.exists());
    assert!(json_path.exists());
    assert!(sarif_path.exists());
    assert!(diff_json_path.exists());
    assert!(diff_markdown_path.exists());

    let json: Value = serde_json::from_str(
        &fs::read_to_string(&json_path).expect("JSON report should be readable"),
    )
    .expect("JSON report should parse");
    assert_valid_authmap_document(&json);
    let sarif: Value = serde_json::from_str(
        &fs::read_to_string(&sarif_path).expect("SARIF report should be readable"),
    )
    .expect("SARIF report should parse");
    assert_valid_sarif(&sarif);

    let summary = fs::read_to_string(step_summary).expect("summary should be written");
    assert!(summary.contains("# AuthMap Report"));
    assert!(summary.contains("# AuthMap Drift Report"));
    let outputs = fs::read_to_string(github_output).expect("GitHub outputs should be written");
    assert!(outputs.contains(&format!("json-path={}", json_path.display())));
    assert!(outputs.contains(&format!("markdown-path={}", markdown_path.display())));
    assert!(outputs.contains(&format!("sarif-path={}", sarif_path.display())));
    assert!(outputs.contains(&format!("diff-json-path={}", diff_json_path.display())));
    assert!(outputs.contains(&format!(
        "diff-markdown-path={}",
        diff_markdown_path.display()
    )));
    assert!(outputs.contains("exit-code=0"));
}

#[test]
fn baseline_create_writes_schema_compatible_authmap_json() {
    let temp = TestDir::new("baseline-create");
    let project = temp.path().join("project");
    let output_path = temp.path().join("authmap.baseline.json");
    write_file(
        &project.join("app.py"),
        r#"
from fastapi import FastAPI, Depends

app = FastAPI()

def require_user():
    return {"id": "user_1"}

@app.get("/accounts")
def read_accounts(user=Depends(require_user)):
    return []
"#,
    );

    let output = authmap(&[
        "baseline",
        "create",
        project.to_str().expect("path should be UTF-8"),
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("baseline should be valid JSON");
    assert_valid_authmap_document(&document);
    assert_eq!(document["schema_version"], "0.1.0");
    assert_eq!(document["metadata"]["mode"], "advisory");
}

#[test]
fn diff_map_files_emit_deterministic_json_markdown_and_enforce_policy() {
    let temp = TestDir::new("diff-map-files");
    let base_path = temp.path().join("base.json");
    let head_path = temp.path().join("head.json");
    let json_path = temp.path().join("authmap.diff.json");
    let markdown_path = temp.path().join("authmap.diff.md");
    let base_document: Value =
        serde_json::from_str(explain_document_json()).expect("fixture JSON should parse");
    let head_document = drift_head_document();
    assert_valid_authmap_document(&base_document);
    assert_valid_authmap_document(&head_document);
    write_file(
        &base_path,
        &serde_json::to_string_pretty(&base_document).expect("base should serialize"),
    );
    write_file(
        &head_path,
        &serde_json::to_string_pretty(&head_document).expect("head should serialize"),
    );

    let output = authmap(&[
        "diff",
        "--base",
        base_path.to_str().expect("path should be UTF-8"),
        "--head",
        head_path.to_str().expect("path should be UTF-8"),
        "--format",
        "json",
        "--output",
        json_path.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&output, 0);
    let report: Value =
        serde_json::from_str(&fs::read_to_string(&json_path).expect("diff JSON should exist"))
            .expect("diff JSON should parse");
    assert_eq!(report["report_type"], "authmap.diff");
    assert_eq!(report["summary"]["added_routes"], 1);
    assert_eq!(report["summary"]["coverage_changes"], 1);
    assert!(
        report["changes"]
            .as_array()
            .expect("changes should be an array")
            .iter()
            .any(|change| change["kind"] == "added_route"
                && change["fail_category"] == "added_high_risk_route")
    );
    assert!(
        report["changes"]
            .as_array()
            .expect("changes should be an array")
            .iter()
            .any(|change| change["kind"] == "coverage_changed"
                && change["before"]["direction"] == "downgrade")
    );

    let output = authmap(&[
        "diff",
        "--base",
        base_path.to_str().expect("path should be UTF-8"),
        "--head",
        head_path.to_str().expect("path should be UTF-8"),
        "--format",
        "markdown",
        "--output",
        markdown_path.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&output, 0);
    let markdown = fs::read_to_string(&markdown_path).expect("diff Markdown should exist");
    assert!(markdown.contains("# AuthMap Drift Report"));
    assert!(markdown.contains("added_high_risk_route"));

    let output = authmap(&[
        "diff",
        "--base",
        base_path.to_str().expect("path should be UTF-8"),
        "--head",
        head_path.to_str().expect("path should be UTF-8"),
        "--mode",
        "enforce",
        "--format",
        "json",
    ]);
    assert_exit(&output, 20);

    let output = authmap(&[
        "diff",
        "--base",
        base_path.to_str().expect("path should be UTF-8"),
        "--head",
        head_path.to_str().expect("path should be UTF-8"),
        "--mode",
        "enforce",
        "--fail-on",
        "new_linked_mutation",
        "--format",
        "json",
    ]);
    assert_exit(&output, 0);
}

#[test]
fn diff_git_range_scans_committed_refs_without_mutating_checkout() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }

    let temp = TestDir::new("diff-git-range");
    write_file(
        &temp.path().join("app.py"),
        r#"
from fastapi import FastAPI, Depends

app = FastAPI()

def require_user():
    return {"id": "user_1"}

@app.get("/accounts")
def read_accounts(user=Depends(require_user)):
    return []
"#,
    );
    for args in [
        vec!["init"],
        vec!["config", "user.email", "authmap@example.test"],
        vec!["config", "user.name", "AuthMap Test"],
        vec!["add", "."],
        vec!["commit", "-m", "base"],
    ] {
        let output = Command::new("git")
            .args(args)
            .current_dir(temp.path())
            .output()
            .expect("git should run");
        assert_exit(&output, 0);
    }
    write_file(
        &temp.path().join("app.py"),
        r#"
from fastapi import FastAPI, Depends

app = FastAPI()

def require_user():
    return {"id": "user_1"}

@app.get("/accounts")
def read_accounts(user=Depends(require_user)):
    return []

@app.post("/admin")
def create_admin():
    return {"ok": True}
"#,
    );
    for args in [vec!["add", "."], vec!["commit", "-m", "head"]] {
        let output = Command::new("git")
            .args(args)
            .current_dir(temp.path())
            .output()
            .expect("git should run");
        assert_exit(&output, 0);
    }

    let output = authmap_in_dir(&["diff", "HEAD~1...HEAD", "--format", "json"], temp.path());
    assert_exit(&output, 0);
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("git range diff should emit JSON");
    assert_eq!(report["report_type"], "authmap.diff");
    assert!(
        report["changes"]
            .as_array()
            .expect("changes should be an array")
            .iter()
            .any(|change| change["kind"] == "added_route")
    );
}

#[test]
fn explain_route_and_evidence_ids_from_explicit_input() {
    let temp = TestDir::new("explain-explicit");
    let input = temp.path().join("authmap.json");
    write_file(&input, explain_document_json());

    let route = authmap(&[
        "explain",
        "route_0001",
        "--input",
        input.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&route, 0);
    let stdout = String::from_utf8_lossy(&route.stdout);
    assert!(stdout.contains("# AuthMap Explain"));
    assert!(stdout.contains("- Kind: route"));
    assert!(stdout.contains("- Coverage: authn_only (low)"));
    assert!(stdout.contains("evidence_0001: authn `session_lookup`"));

    let evidence = authmap(&[
        "explain",
        "evidence_0001",
        "--input",
        input.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&evidence, 0);
    let stdout = String::from_utf8_lossy(&evidence.stdout);
    assert!(stdout.contains("- Kind: evidence"));
    assert!(stdout.contains("## Selected Evidence"));
    assert!(stdout.contains("- Route ID: route_0001"));
}

#[test]
fn explain_uses_default_authmap_json_in_current_directory() {
    let temp = TestDir::new("explain-default");
    write_file(&temp.path().join("authmap.json"), explain_document_json());

    let output = authmap_in_dir(&["explain", "route_0001"], temp.path());

    assert_exit(&output, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("- ID: route_0001"));
    assert!(stdout.contains("- Route: GET /accounts"));
}

#[test]
fn explain_missing_input_fails_nonzero() {
    let temp = TestDir::new("explain-missing");

    let output = authmap_in_dir(&["explain", "route_0001"], temp.path());

    assert_exit(&output, 10);
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to read AuthMap input"));
}

#[test]
fn explain_invalid_json_and_unsupported_schema_fail_nonzero() {
    let temp = TestDir::new("explain-invalid");
    let invalid = temp.path().join("invalid.json");
    let unsupported = temp.path().join("unsupported.json");
    write_file(&invalid, "{\n");
    write_file(
        &unsupported,
        &explain_document_json().replace(
            "\"schema_version\": \"0.1.0\"",
            "\"schema_version\": \"99.0.0\"",
        ),
    );

    let invalid_output = authmap(&[
        "explain",
        "route_0001",
        "--input",
        invalid.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&invalid_output, 12);
    assert!(
        String::from_utf8_lossy(&invalid_output.stderr).contains("failed to parse AuthMap JSON")
    );

    let unsupported_output = authmap(&[
        "explain",
        "route_0001",
        "--input",
        unsupported.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&unsupported_output, 13);
    assert!(
        String::from_utf8_lossy(&unsupported_output.stderr)
            .contains("unsupported AuthMap schema version")
    );
}

#[test]
fn explain_unknown_and_ambiguous_ids_fail_nonzero() {
    let temp = TestDir::new("explain-id-errors");
    let unknown_input = temp.path().join("unknown.json");
    let ambiguous_input = temp.path().join("ambiguous.json");
    write_file(&unknown_input, explain_document_json());
    write_file(&ambiguous_input, &ambiguous_explain_document_json());

    let unknown = authmap(&[
        "explain",
        "missing",
        "--input",
        unknown_input.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&unknown, 13);
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown AuthMap ID missing"));

    let ambiguous = authmap(&[
        "explain",
        "route_0001",
        "--input",
        ambiguous_input.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&ambiguous, 13);
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("ambiguous AuthMap ID route_0001"));
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("route, evidence"));
}

#[test]
fn init_yes_creates_valid_starter_config() {
    let temp = TestDir::new("init-yes");
    let config = temp.path().join("authmap.yml");

    let output = authmap(&[
        "init",
        "--yes",
        "--output",
        config.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let (_, loaded) =
        authmap_config::load_config(Some(config.clone())).expect("starter config should load");
    assert_eq!(loaded.mode, authmap_core::ScanMode::Advisory);
    let text = fs::read_to_string(config).expect("starter config should exist");
    assert!(text.contains("authorization:"));
    assert!(text.contains("sensitivity:"));
    assert!(text.contains("drift:"));
    assert!(text.contains("auth_downgrade"));
    assert!(text.contains("max_total_bytes: 268435456"));
    assert!(text.contains("max_runtime_ms: 120000"));
    assert!(text.contains("Starter examples:"));
}

#[test]
fn init_refuses_existing_config_without_force() {
    let temp = TestDir::new("init-no-force");
    let config = temp.path().join("authmap.yml");
    write_file(&config, "mode: enforce\n");

    let output = authmap(&[
        "init",
        "--yes",
        "--output",
        config.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 15);
    assert_eq!(
        fs::read_to_string(config).expect("config should exist"),
        "mode: enforce\n"
    );
}

#[test]
fn init_force_overwrites_existing_config() {
    let temp = TestDir::new("init-force");
    let config = temp.path().join("authmap.yml");
    write_file(&config, "mode: enforce\n");

    let output = authmap(&[
        "init",
        "--yes",
        "--force",
        "--output",
        config.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let text = fs::read_to_string(config).expect("config should exist");
    assert!(text.contains("mode: advisory"));
    assert!(text.contains("Starter examples:"));
}

#[test]
fn init_force_refuses_non_regular_output() {
    let temp = TestDir::new("init-force-directory");
    let config = temp.path().join("authmap.yml");
    fs::create_dir_all(&config).expect("directory output should be created");

    let output = authmap(&[
        "init",
        "--yes",
        "--force",
        "--output",
        config.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 14);
    assert!(config.is_dir());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to write init config"));
}

#[test]
fn init_refuses_symlink_output_even_with_force() {
    let temp = TestDir::new("init-symlink");
    let target = temp.path().join("target.yml");
    let link = temp.path().join("authmap.yml");
    write_file(&target, "mode: enforce\n");
    if create_file_symlink(&target, &link).is_err() {
        return;
    }

    let output = authmap(&[
        "init",
        "--yes",
        "--force",
        "--output",
        link.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 15);
    assert_eq!(
        fs::read_to_string(target).expect("target should remain readable"),
        "mode: enforce\n"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite symlinked"));
}

#[test]
fn init_interactive_overwrite_confirmation_handles_no_and_yes() {
    let temp = TestDir::new("init-interactive");
    let config = temp.path().join("authmap.yml");
    write_file(&config, "mode: enforce\n");

    let output = authmap_with_stdin(
        &[
            "init",
            "--output",
            config.to_str().expect("path should be UTF-8"),
        ],
        "n\n",
    );
    assert_exit(&output, 0);
    assert_eq!(
        fs::read_to_string(&config).expect("config should exist"),
        "mode: enforce\n"
    );

    let output = authmap_with_stdin(
        &[
            "init",
            "--output",
            config.to_str().expect("path should be UTF-8"),
        ],
        "y\nn\n",
    );
    assert_exit(&output, 0);
    let text = fs::read_to_string(config).expect("config should exist");
    assert!(text.contains("mode: advisory"));
    assert!(!text.contains("Starter examples:"));
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[test]
fn scan_writes_valid_placeholder_json() {
    let temp = TestDir::new("json-output");
    let project = temp.path().join("project");
    let output_path = temp.path().join("authmap.json");
    write_file(&project.join("app.py"), "print('hello')\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--format",
        "json",
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_valid_authmap_document(&document);
    assert_eq!(document["schema_version"], "0.1.0");
    assert_eq!(document["metadata"]["mode"], "advisory");
    assert!(
        document["source_files"]
            .as_array()
            .is_some_and(|files| !files.is_empty())
    );
    assert_eq!(
        document["routes"]
            .as_array()
            .expect("routes should be an array")
            .len(),
        0
    );
    assert_eq!(
        document["evidence"]
            .as_array()
            .expect("evidence should be an array")
            .len(),
        0
    );
    assert_eq!(
        document["mutations"]
            .as_array()
            .expect("mutations should be an array")
            .len(),
        0
    );
    assert_eq!(
        document["links"]
            .as_array()
            .expect("links should be an array")
            .len(),
        0
    );
    assert_eq!(
        document["coverage"]
            .as_array()
            .expect("coverage should be an array")
            .len(),
        0
    );
}

#[test]
fn scan_mode_flag_overrides_metadata() {
    let temp = TestDir::new("mode-enforce");
    let project = temp.path().join("project");
    let output_path = temp.path().join("authmap.json");
    write_file(&project.join("route.ts"), "export function GET() {}\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--mode",
        "enforce",
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_eq!(document["metadata"]["mode"], "enforce");
}

#[test]
fn enforce_mode_with_recoverable_warning_writes_report_and_exits_success() {
    let temp = TestDir::new("enforce-warning");
    let project = temp.path().join("project");
    let output_path = temp.path().join("authmap.json");
    write_file(&project.join("broken.py"), "def broken(:\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--mode",
        "enforce",
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert!(
        document["diagnostics"]
            .as_array()
            .expect("diagnostics should be an array")
            .iter()
            .any(
                |diagnostic| diagnostic["code"] == "parser.source_parse_recovered"
                    && diagnostic["severity"] == "warning"
            )
    );
}

#[test]
fn enforce_mode_with_error_diagnostic_writes_report_and_exits_enforcement_code() {
    let temp = TestDir::new("enforce-error");
    let project = temp.path().join("project");
    let output_path = temp.path().join("authmap.json");
    write_bytes(&project.join("invalid.py"), &[0xff, 0xfe, b'\n']);

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--mode",
        "enforce",
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 20);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_eq!(document["metadata"]["mode"], "enforce");
    assert!(
        document["diagnostics"]
            .as_array()
            .expect("diagnostics should be an array")
            .iter()
            .any(|diagnostic| diagnostic["category"] == "parser"
                && diagnostic["code"] == "parser.source_read_failed"
                && diagnostic["severity"] == "error")
    );
}

#[test]
fn enforce_mode_with_incomplete_discovery_writes_report_and_exits_enforcement_code() {
    let temp = TestDir::new("enforce-incomplete-discovery");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    let output_path = temp.path().join("authmap.json");
    write_file(
        &project.join("app.py"),
        "print('this file exceeds the configured limit')\n",
    );
    write_file(
        &config,
        "mode: enforce\nlimits:\n  max_file_size_bytes: 4\n",
    );

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 20);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert!(
        document["diagnostics"]
            .as_array()
            .expect("diagnostics should be an array")
            .iter()
            .any(
                |diagnostic| diagnostic["code"] == "discovery.file_too_large"
                    && diagnostic["severity"] == "error"
            )
    );
}

#[test]
fn enforce_mode_with_cli_total_byte_limit_writes_report_and_exits_enforcement_code() {
    let temp = TestDir::new("enforce-total-byte-limit");
    let project = temp.path().join("project");
    let output_path = temp.path().join("authmap.json");
    write_file(&project.join("a.py"), "print('a')\n");
    write_file(&project.join("b.py"), "print('b')\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--mode",
        "enforce",
        "--max-total-bytes",
        "12",
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 20);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert!(
        document["diagnostics"]
            .as_array()
            .expect("diagnostics should be an array")
            .iter()
            .any(
                |diagnostic| diagnostic["code"] == "discovery.total_bytes_limit_reached"
                    && diagnostic["severity"] == "error"
            )
    );
    assert!(
        document["source_files"]
            .as_array()
            .expect("source files should be an array")
            .iter()
            .any(|file| file["skipped"]["code"] == "discovery.total_bytes_limit_reached")
    );
}

#[test]
fn scan_writes_sarif_for_diagnostics() {
    let temp = TestDir::new("sarif-output");
    let project = temp.path().join("project");
    let output_path = temp.path().join("authmap.sarif.json");
    write_file(&project.join("broken.py"), "def broken(:\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--format",
        "sarif",
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid SARIF JSON");
    assert_eq!(document["version"], "2.1.0");
    assert!(
        document["runs"][0]["results"]
            .as_array()
            .expect("SARIF results should be an array")
            .iter()
            .any(|result| result["ruleId"] == "parser.source_parse_recovered")
    );
}

#[test]
fn scan_writes_sarif_for_coverage_alerts() {
    let temp = TestDir::new("sarif-coverage-output");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output_path = temp.path().join("authmap.sarif");

    let output = authmap_in_dir(
        &[
            "scan",
            "tests/fixtures/realistic/fastapi",
            "--format",
            "sarif",
            "--output",
            output_path.to_str().expect("path should be UTF-8"),
        ],
        &repo_root,
    );

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid SARIF JSON");
    assert_valid_sarif(&document);
    let results = document["runs"][0]["results"]
        .as_array()
        .expect("SARIF results should be an array");
    assert!(results.iter().any(|result| {
        result["ruleId"] == "authmap.authn_only_sensitive" && result["level"] == "warning"
    }));
    assert!(results.iter().any(|result| {
        result["ruleId"] == "authmap.missing_explicit_evidence" && result["level"] == "warning"
    }));
    let authn_only = results
        .iter()
        .find(|result| result["ruleId"] == "authmap.authn_only_sensitive")
        .expect("authn-only result should exist");
    assert_eq!(authn_only["properties"]["authmap.kind"], "coverage");
    assert_eq!(authn_only["properties"]["coverage_class"], "authn_only");
    assert_eq!(authn_only["properties"]["risk"], "review_required");
    let uri = authn_only["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .expect("coverage result should have a source URI");
    assert!(uri.ends_with("accounts.py"));
}

#[test]
fn config_mode_is_loaded_and_cli_mode_overrides_it() {
    let temp = TestDir::new("mode-precedence");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    let config_output = temp.path().join("config-mode.json");
    let override_output = temp.path().join("override-mode.json");
    write_file(&project.join("app.py"), "print('hello')\n");
    write_file(&config, "mode: enforce\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
        "--output",
        config_output.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(config_output).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_eq!(document["metadata"]["mode"], "enforce");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
        "--mode",
        "advisory",
        "--output",
        override_output.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(override_output).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_eq!(document["metadata"]["mode"], "advisory");
}

#[test]
fn cli_limit_flags_override_config_for_scan_and_rules_suggest() {
    let temp = TestDir::new("limit-precedence");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    let scan_output = temp.path().join("authmap.json");
    write_file(
        &project.join("app.py"),
        "print('large enough for config limit')\n",
    );
    write_file(&config, "limits:\n  max_file_size_bytes: 4\n");

    let scan = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
        "--max-file-size-bytes",
        "1024",
        "--output",
        scan_output.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&scan, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(scan_output).expect("output should exist"))
            .expect("scan output should be valid JSON");
    assert!(
        document["source_files"][0]["skipped"].is_null(),
        "CLI limit should override config file-size limit"
    );

    let rules = authmap(&[
        "rules",
        "suggest",
        project.to_str().expect("path should be UTF-8"),
        "--format",
        "json",
        "--config",
        config.to_str().expect("path should be UTF-8"),
        "--max-file-size-bytes",
        "1024",
    ]);
    assert_exit(&rules, 0);
    let report: Value = serde_json::from_slice(&rules.stdout).expect("rules output should parse");
    assert_eq!(report["source_files_scanned"], 1);
}

#[test]
fn config_authorization_rules_are_loaded_by_scan() {
    let temp = TestDir::new("auth-rules-config");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    let output_path = temp.path().join("authmap.json");
    write_file(
        &project.join("app.js"),
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
    write_file(
        &config,
        r#"
authorization:
  rules:
    - name: paid plan permission
      evidence_type: permission_check
      mechanism: billing_plan_guard
      match:
        exact: [ensurePaidPlan]
"#,
    );

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_valid_authmap_document(&document);
    assert!(
        document["evidence"]
            .as_array()
            .expect("evidence should be an array")
            .iter()
            .any(|evidence| evidence["evidence_type"] == "permission_check"
                && evidence["mechanism"] == "billing_plan_guard")
    );
}

#[test]
fn config_sensitivity_rules_are_loaded_by_scan() {
    let temp = TestDir::new("sensitivity-config");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    let output_path = temp.path().join("authmap.json");
    write_file(
        &project.join("app.js"),
        r#"
const express = require("express");
const app = express();

app.get("/reports", function listReports(req, res) {
  res.json([]);
});

module.exports = app;
"#,
    );
    write_file(
        &config,
        r#"
sensitivity:
  routes:
    - name: reports
      labels: [business_critical]
      match:
        exact: [/reports]
      methods: [GET]
      reviewer_questions:
        - Should reports require a permission guard?
"#,
    );

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_valid_authmap_document(&document);
    let coverage = document["coverage"]
        .as_array()
        .expect("coverage should be an array")
        .iter()
        .find(|coverage| coverage["route_id"] == "route_0001")
        .expect("route should have coverage");
    assert_eq!(coverage["risk"], "medium");
    assert!(
        coverage["reviewer_questions"]
            .as_array()
            .expect("reviewer questions should be an array")
            .iter()
            .any(|question| question == "Should reports require a permission guard?")
    );
    assert!(
        coverage["extensions"]["authmap.coverage"]["sensitivity_reasons"]
            .as_array()
            .expect("sensitivity reasons should be an array")
            .iter()
            .any(|reason| reason == "config_route:business_critical")
    );
}

#[test]
fn rules_suggest_prints_markdown_and_json() {
    let temp = TestDir::new("rules-suggest");
    let project = temp.path().join("project");
    write_rules_suggest_project(&project);

    let markdown = authmap(&[
        "rules",
        "suggest",
        project.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&markdown, 0);
    let stdout = String::from_utf8_lossy(&markdown.stdout);
    assert!(stdout.contains("# AuthMap Rule Suggestions"));
    assert!(stdout.contains("ensurePaidPlan"));
    assert!(stdout.contains("authorization:"));
    assert!(stdout.contains("Suggestions are local heuristics"));

    let json = authmap(&[
        "rules",
        "suggest",
        project.to_str().expect("path should be UTF-8"),
        "--format",
        "json",
    ]);
    assert_exit(&json, 0);
    let document: Value =
        serde_json::from_slice(&json.stdout).expect("rules suggestions should be JSON");
    assert!(
        document["suggestions"]
            .as_array()
            .expect("suggestions should be an array")
            .iter()
            .any(
                |suggestion| suggestion["match"]["exact"][0] == "ensurePaidPlan"
                    && suggestion["evidence_type"] == "permission_check"
            )
    );
}

#[test]
fn rules_suggest_writes_output_and_is_deterministic() {
    let temp = TestDir::new("rules-suggest-output");
    let project = temp.path().join("project");
    let first = temp.path().join("first.json");
    let second = temp.path().join("second.json");
    write_rules_suggest_project(&project);

    for output_path in [&first, &second] {
        let output = authmap(&[
            "rules",
            "suggest",
            project.to_str().expect("path should be UTF-8"),
            "--format",
            "json",
            "--output",
            output_path.to_str().expect("path should be UTF-8"),
        ]);
        assert_exit(&output, 0);
    }

    assert_eq!(
        fs::read_to_string(first).expect("first output should exist"),
        fs::read_to_string(second).expect("second output should exist")
    );
}

#[test]
fn rules_suggest_config_suppresses_duplicates() {
    let temp = TestDir::new("rules-suggest-config");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    write_rules_suggest_project(&project);
    write_file(
        &config,
        r#"
authorization:
  rules:
    - name: paid plan permission
      evidence_type: permission_check
      mechanism: billing_plan_guard
      match:
        exact: [ensurePaidPlan]
"#,
    );

    let output = authmap(&[
        "rules",
        "suggest",
        project.to_str().expect("path should be UTF-8"),
        "--format",
        "json",
        "--config",
        config.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_slice(&output.stdout).expect("rules suggestions should be JSON");
    assert!(
        document["suggestions"]
            .as_array()
            .expect("suggestions should be an array")
            .iter()
            .all(|suggestion| suggestion["match"]["exact"][0] != "ensurePaidPlan")
    );
}

#[test]
fn rules_suggest_reports_missing_targets_and_invalid_config() {
    let temp = TestDir::new("rules-suggest-errors");
    let missing = temp.path().join("missing");
    let config = temp.path().join("authmap.yml");
    write_file(&config, "unknown_key: true\n");

    let missing_output = authmap(&[
        "rules",
        "suggest",
        missing.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&missing_output, 10);
    assert!(String::from_utf8_lossy(&missing_output.stderr).contains("missing or unreadable"));

    let invalid_config = authmap(&[
        "rules",
        "suggest",
        temp.path().to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
    ]);
    assert_exit(&invalid_config, 12);
    assert!(String::from_utf8_lossy(&invalid_config.stderr).contains("failed to parse config"));
}

#[test]
fn unsupported_format_exits_with_clap_usage_code() {
    let output = authmap(&["scan", ".", "--format", "xml"]);

    assert_exit(&output, 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid value 'xml'"));
    assert!(stderr.contains("possible values"));
}

#[test]
fn zero_cli_limit_exits_with_usage_code() {
    let output = authmap(&["scan", ".", "--max-total-bytes", "0"]);

    assert_exit(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid CLI limit"));
}

#[test]
fn missing_target_exits_with_target_code() {
    let temp = TestDir::new("missing-target");
    let missing = temp.path().join("missing");

    let output = authmap(&["scan", missing.to_str().expect("path should be UTF-8")]);

    assert_exit(&output, 10);
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing or unreadable"));
}

#[test]
fn advisory_empty_directory_writes_empty_map_with_warning() {
    let temp = TestDir::new("empty-target");
    let output_path = temp.path().join("authmap.json");

    let output = authmap(&[
        "scan",
        temp.path().to_str().expect("path should be UTF-8"),
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 0);
    let document: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("output should exist"))
            .expect("output should be valid JSON");
    assert_eq!(
        document["source_files"]
            .as_array()
            .expect("source files should be an array")
            .len(),
        0
    );
    assert!(
        document["diagnostics"]
            .as_array()
            .expect("diagnostics should be an array")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "discovery.no_candidate_sources")
    );
}

#[test]
fn enforce_empty_directory_exits_with_empty_target_code() {
    let temp = TestDir::new("empty-target-enforce");

    let output = authmap(&[
        "scan",
        temp.path().to_str().expect("path should be UTF-8"),
        "--mode",
        "enforce",
    ]);

    assert_exit(&output, 11);
    assert!(String::from_utf8_lossy(&output.stderr).contains("no supported source files"));
}

#[test]
fn invalid_config_exits_with_config_code() {
    let temp = TestDir::new("invalid-config");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    write_file(&project.join("app.py"), "print('hello')\n");
    write_file(&config, "unknown_key: true\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 12);
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to parse config"));
}

#[test]
fn invalid_include_pattern_exits_with_config_code() {
    let temp = TestDir::new("invalid-include-pattern");
    let project = temp.path().join("project");
    let config = temp.path().join("authmap.yml");
    write_file(&project.join("app.py"), "print('hello')\n");
    write_file(&config, "include:\n  - \"[abc\"\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--config",
        config.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 12);
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid include pattern"));
}

#[test]
fn invalid_output_path_exits_with_report_code() {
    let temp = TestDir::new("invalid-output");
    let project = temp.path().join("project");
    let output_path = temp.path().join("missing-parent").join("authmap.json");
    write_file(&project.join("app.py"), "print('hello')\n");

    let output = authmap(&[
        "scan",
        project.to_str().expect("path should be UTF-8"),
        "--output",
        output_path.to_str().expect("path should be UTF-8"),
    ]);

    assert_exit(&output, 14);
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to write report"));
}
