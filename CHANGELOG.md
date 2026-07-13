# Changelog

All notable user-visible changes to AuthMap should be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and AuthMap uses semantic versioning as described in [docs/RELEASES.md](docs/RELEASES.md).

## Unreleased

### Added

- Added Express prefix-less middleware propagation with registration-order
  semantics and `app.all` catch-all route inventory.
- Added Knex query-builder, Prisma transaction-group, and repository-pattern
  mutation evidence for improved route-to-mutation analysis.
- Added configurable authorization guard synonym families and low-confidence,
  token-boundary guard classification heuristics.
- Added a Criterion performance benchmark harness and a CI performance
  regression guard for representative AuthMap scans.
- Added `authmap routes` for focused route inventory review with JSON and
  Markdown output.
- Added route metadata for normalized path parameters and declared protection
  context in the existing AuthMap schema version.

### Changed

- Reused Tree-sitter parsers per worker thread and added finer-grained runtime
  checks during parsing to reduce scan overhead and runtime-budget overshoot.
- Ported the release process to cargo-release-managed versioning, per-artifact
  checksums, source archives, SLSA provenance, and release verification docs.

## 0.1.0 - 2026-05-24

### Added

- Initial AuthMap workspace, CLI, schema, reports, configuration, GitHub Action, and defensive-use documentation.
- Documented AuthMap's versioning, changelog, compatibility, and release automation policy.
- Added release automation for tagged GitHub Releases with platform artifacts and SHA-256 checksums.
- Added publish-ready CLI package metadata, deterministic one-line `authmap --version` output, and package-content install verification guidance.

### Schema compatibility

- Initial AuthMap JSON schema version `0.1.0`.
