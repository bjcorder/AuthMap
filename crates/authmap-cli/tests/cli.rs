use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

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
fn unsupported_format_exits_with_clap_usage_code() {
    let output = authmap(&["scan", ".", "--format", "xml"]);

    assert_exit(&output, 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid value 'xml'"));
    assert!(stderr.contains("possible values"));
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
