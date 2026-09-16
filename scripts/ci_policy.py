#!/usr/bin/env python3
"""Small, dependency-free CI policy checks used by workflow gates."""
from __future__ import annotations
import argparse
import sys

def check_gate(pairs: list[str]) -> int:
    bad = []
    for pair in pairs:
        name, _, result = pair.partition("=")
        if not name or result != "success":
            bad.append(pair)
    if bad:
        print("CI gate failed: " + ", ".join(bad), file=sys.stderr)
        return 1
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    gate = sub.add_parser("check-gate")
    gate.add_argument("results", nargs="+")
    test = sub.add_parser("test")
    args = parser.parse_args()
    if args.command == "check-gate":
        return check_gate(args.results)
    assert check_gate(["rust=success"]) == 0
    assert check_gate(["rust=failure"]) == 1
    assert check_gate(["rust=cancelled"]) == 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
