# Contributing

This repository is early-stage and design-first. Contributions should preserve the core product-security boundary: defensive, authorized analysis of software you own or are permitted to assess.

## Useful contribution types

- Framework adapters
- Detection heuristics
- Documentation improvements
- False-positive reduction ideas
- Test fixtures for real-world application patterns
- Output/reporting improvements

Parser and adapter contributors should follow the shared contract in
[docs/PARSERS_AND_ADAPTERS.md](docs/PARSERS_AND_ADAPTERS.md).
Diagnostic categories and stable codes should follow
[docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md).

## Ground rules

- Do not add exploit automation, payload generation, credential theft, bypass instructions, or live attack workflows.
- Prefer evidence-bound findings over unsupported vulnerability claims.
- Keep outputs actionable for application developers and product-security reviewers.
- Add fixtures for new detection behavior where practical.

## Development status

The current repository contains the v0.1.0 foundation crates for the CLI,
schema/IR, discovery, parsing, diagnostics, and reporting. Framework-specific
adapter behavior and higher-level policy checks will land in later milestones.

## CI expectations

Pull requests run the Rust workspace on Linux, macOS, and Windows across the
declared MSRV (`1.95`) and current stable Rust. The matrix runs locked
workspace checks, the full test suite, and a clean `cargo install` smoke test
for the `authmap` CLI. Documentation-only checks stay in the separate docs
workflow.
