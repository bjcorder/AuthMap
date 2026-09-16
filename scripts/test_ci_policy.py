"""Behavioral checks for staged jobs, fail-closed gates, and event path handling."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from ci_policy import JOBS, REQUIRED_DOCS, changed_paths, check_gate, plan, validate_repository


class PolicyTests(unittest.TestCase):
    def enabled(self, event, branch, paths):
        policy = plan(event, branch, paths)
        return {job for job, enabled in policy["jobs"].items() if enabled}

    def test_development_code_runs_one_full_test_cell(self):
        policy = plan("pull_request", "develop", ["crates/authmap-core/src/lib.rs"])
        self.assertEqual(policy["matrix"]["include"], [{"os": "ubuntu-24.04", "rust": "stable"}])
        self.assertEqual(self.enabled("pull_request", "develop", ["src/lib.rs"]), {"rust"})

    def test_documentation_allowlist_and_empty_diff(self):
        self.assertEqual(self.enabled("pull_request", "develop", ["docs/a.rs", "README.md"]), set())
        for paths in [[], ["tests/golden/scan.md"], ["crates/README.md"], ["docs/a.md", "src/lib.rs"], ["a file\n.rs"]]:
            with self.subTest(paths=paths):
                self.assertIn("rust", self.enabled("pull_request", "develop", paths))

    def test_dependencies_do_not_enable_cross_platform_or_codeql(self):
        for path in ["Cargo.lock", "Cargo.toml", "crates/new/Cargo.toml", "tools/new/Cargo.toml"]:
            with self.subTest(path=path):
                policy = plan("pull_request", "develop", [path])
                self.assertEqual(self.enabled("pull_request", "develop", [path]), {"rust", "audit", "dependency_review", "determinism", "performance"})
                self.assertEqual(len(policy["matrix"]["include"]), 1)

    def test_action_changes_get_review_audit_and_smoke(self):
        for path in ["action.yml", ".github/actions/foo/action.yml", ".github/workflows/ci.yml"]:
            self.assertEqual(self.enabled("pull_request", "develop", [path]), {"rust", "audit", "dependency_review", "determinism", "action_smoke", "performance"})

    def test_performance_paths(self):
        for path in ["crates/authmap-parsers/src/lib.rs", "crates/authmap-analysis/src/lib.rs", "crates/authmap-discovery/src/lib.rs", "crates/authmap-adapters/src/lib.rs", "scripts/perf_guard.sh", "ci/perf-baseline.env", "crates/x/benches/scan.rs"]:
            self.assertEqual(self.enabled("pull_request", "develop", [path]), {"rust", "performance"})

    def test_release_manual_weekly_and_push(self):
        release = {"rust", "audit", "dependency_review", "determinism", "codeql", "action_smoke", "performance", "package"}
        self.assertEqual(self.enabled("pull_request", "main", ["README.md"]), release)
        for event in ["schedule", "workflow_dispatch"]:
            self.assertEqual(self.enabled(event, "develop", []), release - {"dependency_review"} | {"audit_main"})
        self.assertEqual(self.enabled("push", "main", []), {"main_smoke"})
        self.assertEqual(plan("pull_request", "main", [])['matrix']['include'], [
            {"os": "ubuntu-24.04", "rust": "stable"},
            {"os": "ubuntu-24.04", "rust": "1.95"},
            {"os": "macos-latest", "rust": "1.95"},
            {"os": "windows-2025", "rust": "1.95"},
        ])
        for event, branch in [("push", "develop"), ("pull_request", "other"), ("pull_request_target", "main")]:
            with self.assertRaises(ValueError):
                plan(event, branch, [])

    def needs(self, policy):
        return {"plan": {"result": "success", "outputs": {"policy": json.dumps(policy)}},
                **{job: {"result": "success" if enabled else "skipped"} for job, enabled in policy["jobs"].items()}}

    def test_gates_accept_only_exact_expected_results(self):
        for event, branch, paths in [
            ("pull_request", "develop", ["README.md"]),
            ("pull_request", "develop", ["action.yml"]),
            ("pull_request", "develop", ["src/lib.rs"]),
            ("pull_request", "main", []), ("schedule", "develop", []),
            ("workflow_dispatch", "develop", []), ("push", "main", []),
        ]:
            needs = self.needs(plan(event, branch, paths))
            check_gate(needs)
            for job in ("plan", *JOBS):
                for result in ["failure", "cancelled", "skipped", "success", "", "neutral"]:
                    if result == needs[job]["result"]:
                        continue
                    broken = copy.deepcopy(needs)
                    broken[job]["result"] = result
                    with self.subTest(event=event, paths=paths, job=job, result=result), self.assertRaises(ValueError):
                        check_gate(broken)
                broken = copy.deepcopy(needs)
                del broken[job]
                with self.assertRaises(ValueError):
                    check_gate(broken)

    def test_gate_rejects_missing_or_malformed_plan(self):
        for output in ["", "{}", "null", '{"jobs": {}}']:
            needs = self.needs(plan("pull_request", "develop", ["README.md"]))
            needs["plan"]["outputs"]["policy"] = output
            with self.assertRaises((ValueError, TypeError)):
                check_gate(needs)
        policy = plan("pull_request", "develop", ["README.md"])
        policy["jobs"]["rust"] = "false"
        with self.assertRaises(ValueError):
            check_gate(self.needs(policy))

    def test_git_paths_preserve_newlines_and_renamed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], text=True).strip()
            git("init", "-q")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "CI Test")
            (root / "source.rs").write_text("original")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (root / "docs").mkdir()
            (root / "source.rs").rename(root / "docs/source.md")
            (root / "space newline\n$(touch injected).rs").write_text("changed")
            git("add", ".")
            git("commit", "-qm", "head")
            head = git("rev-parse", "HEAD")
            before = Path.cwd()
            try:
                os.chdir(root)
                paths = changed_paths({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}})
            finally:
                os.chdir(before)
            self.assertCountEqual(paths, ["source.rs", "docs/source.md", "space newline\n$(touch injected).rs"])
            self.assertFalse((root / "injected").exists())
            self.assertIn("rust", self.enabled("pull_request", "develop", paths))

    def test_version_section_and_lock_consistency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in REQUIRED_DOCS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("docs")
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
            (root / "Cargo.lock").write_text('[[package]]\nname = "authmap-cli"\nversion = "0.1.0"\n')
            crate = root / "crates/authmap-cli/Cargo.toml"
            crate.parent.mkdir(parents=True)
            crate.write_text('[package]\nname = "authmap-cli"\nversion.workspace = true\n')
            changelog = root / "CHANGELOG.md"
            for content in ["## 0.1.0 - 2026-05-24\n\n- Released\n", "## [0.1.0]\n\n- Released\n"]:
                changelog.write_text(content)
                validate_repository(root, True)
            for content in ["## Unreleased\n- Entry\n", "## 0.1.0\n### Added\n\n## 0.0.9\n- Old entry\n"]:
                changelog.write_text(content)
                with self.assertRaises(ValueError):
                    validate_repository(root, True)
            changelog.write_text("## 0.1.0\n- Existing release\n")
            (root / "Cargo.lock").write_text('[[package]]\nname = "authmap-cli"\nversion = "0.2.0"\n')
            with self.assertRaises(ValueError):
                validate_repository(root, True)
            validate_repository(root, False)
            (root / "docs/RELEASES.md").write_text("  \n")
            with self.assertRaises(ValueError):
                validate_repository(root, False)
            (root / "docs/RELEASES.md").unlink()
            with self.assertRaises(ValueError):
                validate_repository(root, False)

    def test_command_outputs_drive_jobs_and_gate(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            output = Path(directory) / "outputs"
            event.write_text("{}")
            env = {**os.environ, "GITHUB_EVENT_PATH": str(event),
                   "GITHUB_OUTPUT": str(output), "GITHUB_EVENT_NAME": "push",
                   "GITHUB_REF_NAME": "main"}
            subprocess.run([sys.executable, "scripts/ci_policy.py", "plan"], cwd=root, env=env, check=True)
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
            policy = json.loads(outputs["policy"])
            self.assertEqual(json.loads(outputs["matrix"]), policy["matrix"])
            for job in JOBS:
                self.assertEqual(json.loads(outputs[job]), policy["jobs"][job])
            self.assertRegex(outputs["ref"], r"^[0-9a-f]{40}$")
            needs = self.needs(policy)
            env["CI_NEEDS"] = json.dumps(needs)
            subprocess.run([sys.executable, "scripts/ci_policy.py", "check-gate"], cwd=root, env=env, check=True)
            needs["plan"]["result"] = "failure"
            env["CI_NEEDS"] = json.dumps(needs)
            failed = subprocess.run([sys.executable, "scripts/ci_policy.py", "check-gate"], cwd=root, env=env, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)

    def test_workflow_wires_every_job_and_both_gates_to_policy(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        blocks = dict(re.findall(r"^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow.split("jobs:\n", 1)[1], re.M | re.S))
        self.assertEqual(set(blocks), {"plan", *JOBS, "development-gate", "release-gate"})
        for job in JOBS:
            self.assertIn(f"if: needs.plan.outputs.{job} == 'true'", blocks[job])
            self.assertIn(f"{job}: ${{{{ steps.plan.outputs.{job} }}}}", blocks["plan"])
        for gate in ["development-gate", "release-gate"]:
            self.assertIn("if: always()", blocks[gate])
            needs = re.search(r"needs: \[(.*?)\]", blocks[gate])[1].split(", ")
            self.assertEqual(set(needs), {"plan", *JOBS})
            self.assertIn("CI_NEEDS: ${{ toJSON(needs) }}", blocks[gate])
            self.assertIn("python3 scripts/ci_policy.py check-gate", blocks[gate])
        self.assertIn("python3 -m unittest discover", blocks['plan'])
        self.assertIn("fromJSON(needs.plan.outputs.matrix)", blocks['rust'])
        self.assertIn("security-events: write", blocks['codeql'])
        self.assertIn("ref: main", blocks['audit_main'])
        self.assertIn("&& 'develop' || github.sha", blocks['plan'])
        for job in JOBS:
            if job != 'audit_main':
                self.assertIn("ref: ${{ needs.plan.outputs.ref }}", blocks[job])


if __name__ == "__main__":
    unittest.main()
