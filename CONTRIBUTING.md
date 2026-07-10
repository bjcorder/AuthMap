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

Dependency and workflow changes should follow the supply-chain policy in
[docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md). Release-facing changes should
follow the versioning and changelog policy in
[docs/RELEASES.md](docs/RELEASES.md). Keep dependency updates separate from
unrelated feature work when practical, include intentional `Cargo.lock`
changes, and review licenses, advisories, build behavior, and GitHub Actions
permissions before merge.

## Performance checks

AuthMap includes a Criterion benchmark harness for parser throughput, full-pipeline
fixture scans, and analysis-only extraction/linking:

```sh
cargo bench -p authmap-cli --bench performance
```

Pull requests also run a lightweight Ubuntu performance guard defined in
`.github/workflows/performance.yml`. The guard builds the release CLI, scans the
fixture configured in `ci/perf-baseline.env`, and fails if wall time exceeds the
stored baseline plus its threshold. The threshold is intentionally generous to
absorb hosted-runner variance; update the baseline only after reviewing local
`cargo bench` output and confirming the new number represents intentional
behavior.

Update [CHANGELOG.md](CHANGELOG.md) for user-visible CLI, schema,
configuration, report, GitHub Action, documentation, or release-process
changes. Call out schema compatibility notes when the AuthMap JSON contract or
schema-facing behavior changes.
