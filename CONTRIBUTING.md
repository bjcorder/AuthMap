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

## Branch and CI expectations

`develop` is the default integration branch. Feature and ordinary dependency
pull requests target `develop` and are squash-merged after the
`development-gate` passes. A promotion pull request merges `develop` into
`main` with a merge commit after the `release-gate` passes. After promotion,
merge `main` back into `develop` to keep the branches aligned. The merge need
not change the version for documentation or other maintenance work.

The consolidated `ci.yml` workflow stages checks by change type. Ordinary code
changes run on Linux stable with formatting, full locked workspace tests
(including all targets), and smoke tests of the existing CLI binary. The full
release gate and weekly integration matrix use four cells total (Linux stable, Linux 1.95, macOS 1.95, and
Windows 1.95), along with CodeQL, audit, dependency validation, performance,
action smoke, and clean package checks. Dependency, action, and performance
changes run targeted checks early. Docs-only changes
receive a successful evaluated gate while avoiding unneeded code work. Weekly
integration scans cover `develop` and explicitly audit `main`; pushes to `main`
run a lightweight verification smoke test.

Keep locked builds enabled in every applicable gate. Exact-tag release checks
retain artifact, checksum, provenance, and `main` reachability validation.

## Development flow

Keep feature branches short-lived and open them against `develop`. Squash
ordinary feature, dependency, and documentation pull requests into `develop`.
Promote reviewed integration with a merge commit from `develop` into `main`.
Sync the resulting `main` merge back into `develop` with a merge commit.

For an urgent fix, branch from `main`, satisfy the `release-gate`, merge into
`main`, and then merge `main` back into `develop`. Create a version tag only
after the validated merge is present on `main`; the tag must point at that
actual `main` commit.

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

Pull requests run the targeted performance check from the consolidated CI
workflow. The guard builds the release CLI, scans the fixture configured in
`ci/perf-baseline.env`, and fails if wall time exceeds the stored baseline plus
its threshold. Update the baseline only after reviewing local `cargo bench`
output and confirming the new number represents intentional behavior.

Update [CHANGELOG.md](CHANGELOG.md) for user-visible CLI, schema,
configuration, report, GitHub Action, documentation, or release-process
changes. Call out schema compatibility notes when the AuthMap JSON contract or
schema-facing behavior changes.
