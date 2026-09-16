#!/usr/bin/env python3
"""Plan staged CI once, and fail closed against the actual GitHub job results."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

JOBS = (
    "rust", "audit", "audit_main", "dependency_review", "determinism",
    "codeql", "action_smoke", "performance", "package", "main_smoke",
)
SMALL_MATRIX = [{"os": "ubuntu-24.04", "rust": "stable"}]
FULL_MATRIX = SMALL_MATRIX + [
    {"os": "ubuntu-24.04", "rust": "1.95"},
    {"os": "macos-latest", "rust": "1.95"},
    {"os": "windows-2025", "rust": "1.95"},
]
REQUIRED_DOCS = (
    "README.md", "CONTRIBUTING.md", "RELEASING.md", "CHANGELOG.md",
    "docs/RELEASES.md", "docs/SCHEMA.md", "docs/CONFIGURATION.md",
    "docs/PRODUCT_BRIEF.md", "docs/ARCHITECTURE.md", "docs/GITHUB_ACTION.md",
    "docs/ROADMAP.md", "docs/SUPPLY_CHAIN.md", "SECURITY.md",
)


def plan(event: str, base: str, paths: list[str]) -> dict:
    if not (event in ("schedule", "workflow_dispatch") or
            event == "pull_request" and base in ("develop", "main") or
            event == "push" and base == "main"):
        raise ValueError(f"Unsupported CI event/branch: {event}/{base}")
    full = event in ("schedule", "workflow_dispatch") or base == "main" and event == "pull_request"
    pr = event == "pull_request"
    docs = bool(paths) and all(
        p.startswith("docs/") or "/" not in p and p.endswith(".md") for p in paths
    )
    actions = any(p == "action.yml" or p.startswith((".github/actions/", ".github/workflows/")) for p in paths)
    dependencies = actions or any(p == "Cargo.lock" or p == "Cargo.toml" or p.endswith("/Cargo.toml") for p in paths)
    perf = any(p.startswith((
        "crates/authmap-parsers/", "crates/authmap-analysis/",
        "crates/authmap-discovery/", "crates/authmap-adapters/",
        "scripts/perf", "ci/", "tests/fixtures/",
    )) or "/benches/" in p for p in paths)
    jobs = {
        "rust": full or pr and not docs,
        "audit": full or pr and dependencies,
        "audit_main": event in ("schedule", "workflow_dispatch"),
        "dependency_review": pr and (full or dependencies),
        "determinism": full or pr and dependencies,
        "codeql": full,
        "action_smoke": full or pr and actions,
        "performance": full or pr and (perf or dependencies),
        "package": full,
        "main_smoke": event == "push",
    }
    return {"jobs": jobs, "full": full, "matrix": {"include": FULL_MATRIX if full else SMALL_MATRIX}}


def changed_paths(event: dict) -> list[str]:
    """No shell, newline splitting, rename loss, or interpolation of PR filenames."""
    pr = event["pull_request"]
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    if not all(re.fullmatch(r"[0-9a-f]{40,64}", sha) for sha in (base, head)):
        raise ValueError("Expected commit SHAs in the pull request event")
    raw = subprocess.check_output([
        "git", "diff", "--name-only", "--no-renames", "-z", f"{base}...{head}", "--",
    ])
    return [os.fsdecode(p) for p in raw.split(b"\0") if p]


def validate_repository(root: Path, release: bool) -> None:
    for name in REQUIRED_DOCS:
        if not (root / name).is_file() or not (root / name).read_text().strip():
            raise ValueError(f"Required documentation missing: {name}")
    if not release:
        return
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    version = manifest["workspace"]["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError("Invalid workspace version")
    # Existing released versions are valid for promotions; a bump is not mandatory.
    changelog = (root / "CHANGELOG.md").read_text()
    section = re.search(
        rf"^##[ \t]+\[?{re.escape(version)}\]?(?:[ \t]+-[^\n]*)?[ \t]*\n(.*?)(?=^##[ \t]|\Z)",
        changelog, re.MULTILINE | re.DOTALL,
    )
    if not section or not any(line.strip() and not line.lstrip().startswith("#") for line in section[1].splitlines()):
        raise ValueError(f"CHANGELOG.md needs a nonempty section for {version}")
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    locked = {p["name"]: p["version"] for p in lock["package"] if "source" not in p}
    for path in (root / "crates").glob("*/Cargo.toml"):
        package = tomllib.loads(path.read_text())["package"]
        actual = version if package["version"] == {"workspace": True} else package["version"]
        if actual != version or locked.get(package["name"]) != version:
            raise ValueError(f"Workspace/lock version mismatch: {path}")


def check_gate(needs: dict) -> None:
    if set(needs) != {"plan", *JOBS}:
        raise ValueError("Gate needs must contain the plan and every controlled job")
    if needs["plan"].get("result") != "success":
        raise ValueError("CI plan did not succeed")
    policy = json.loads(needs["plan"]["outputs"]["policy"])
    if set(policy) != {"jobs", "full", "matrix"} or set(policy["jobs"]) != set(JOBS):
        raise ValueError("Missing or unknown CI plan fields")
    if type(policy["full"]) is not bool or any(type(v) is not bool for v in policy["jobs"].values()):
        raise ValueError("CI plan flags must be booleans")
    if policy["matrix"] != {"include": FULL_MATRIX if policy["full"] else SMALL_MATRIX}:
        raise ValueError("Invalid Rust matrix")
    bad = [name for name, enabled in policy["jobs"].items()
           if needs[name].get("result") != ("success" if enabled else "skipped")]
    if bad:
        raise ValueError("Unexpected CI job results: " + ", ".join(bad))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "check-gate"))
    args = parser.parse_args()
    try:
        if args.command == "check-gate":
            check_gate(json.loads(os.environ["CI_NEEDS"]))
        else:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
            name = os.environ["GITHUB_EVENT_NAME"]
            base = event["pull_request"]["base"]["ref"] if name == "pull_request" else os.environ.get("GITHUB_REF_NAME", "")
            policy = plan(name, base, changed_paths(event) if name == "pull_request" else [])
            validate_repository(Path.cwd(), policy["full"])
            outputs = {**policy["jobs"], "policy": policy, "matrix": policy["matrix"]}
            outputs["ref"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                for key, value in outputs.items():
                    stream.write(f"{key}={json.dumps(value, separators=(',', ':')) if not isinstance(value, str) else value}\n")
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print(f"CI policy failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
