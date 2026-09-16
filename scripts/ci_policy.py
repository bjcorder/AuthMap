#!/usr/bin/env python3
"""Dependency-free CI planner and gate validator."""
from __future__ import annotations
import argparse, json, sys

SENSITIVE = ("tree-sitter", "jsonschema", "criterion")
def plan(event: str, base: str, paths: list[str]) -> dict[str, bool]:
    docs = bool(paths) and all(p.startswith("docs/") or "/" not in p and p.endswith(".md") for p in paths)
    deps = any(p == "Cargo.lock" or p == "Cargo.toml" or p.startswith("crates/") and p.endswith("/Cargo.toml") for p in paths)
    action = any(p == "action.yml" or p.startswith(".github/actions/") or p.startswith(".github/workflows/") for p in paths)
    performance = any(p.startswith("scripts/perf") or p.startswith("ci/") or "criterion" in p for p in paths)
    full = event in ("schedule", "workflow_dispatch") or event == "pull_request" and base == "main"
    return {"rust": not docs, "full": full, "dependencies": deps, "action": action, "performance": performance}

def check_gate(results: dict[str, str], expected: list[str]) -> int:
    bad = [name for name in expected if results.get(name) != "success"]
    bad += [name for name, result in results.items() if name not in expected and result != "skipped"]
    if bad:
        print("CI gate failed: " + ", ".join(bad), file=sys.stderr)
        return 1
    return 0

def main() -> int:
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("plan"); q.add_argument("event"); q.add_argument("base"); q.add_argument("paths", nargs="*")
    g = sub.add_parser("check-gate"); g.add_argument("expected"); g.add_argument("results")
    t = sub.add_parser("test")
    a = p.parse_args()
    if a.cmd == "plan":
        for k, v in plan(a.event, a.base, a.paths).items(): print(f"{k}={'true' if v else 'false'}")
        return 0
    if a.cmd == "check-gate": return check_gate(json.loads(a.results), a.expected.split(",") if a.expected else [])
    assert plan("pull_request", "develop", ["docs/guide.md"])["rust"] is False
    assert plan("pull_request", "develop", ["crates/x/Cargo.toml"])["dependencies"] is True
    assert plan("pull_request", "develop", ["tests/golden/foo.md"])["rust"] is True
    assert plan("pull_request", "develop", ["a file.rs"])["rust"] is True
    assert plan("pull_request", "develop", ["action.yml"])["action"] is True
    assert plan("pull_request", "main", ["src/lib.rs"])["full"] is True
    assert plan("schedule", "", [])["full"] is True
    assert plan("workflow_dispatch", "", [])["full"] is True
    assert plan("push", "", [])["full"] is False
    assert check_gate({"rust":"success", "audit":"skipped"}, ["rust"]) == 0
    assert check_gate({"rust":"failure"}, ["rust"]) == 1
    return 0
if __name__ == "__main__": raise SystemExit(main())
