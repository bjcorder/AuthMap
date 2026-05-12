# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Snapshot

AuthMap is a defensive product-security tool for statically mapping authorization coverage across application routes, handlers, service methods, and data mutations. It should not execute target applications, connect to databases, or perform live attack workflows.

The repository is a Rust Cargo workspace. The canonical AuthMap JSON contract lives in `schemas/authmap.schema.json` and is documented in `docs/SCHEMA.md`.

## Safety Boundary

- Keep the project defensive and evidence-bound.
- Do not add exploit automation, payload generation, credential theft, bypass instructions, or live attack behavior.
- Prefer reviewable facts, diagnostics, uncertainty notes, and reviewer questions over unsupported vulnerability claims.
- Static analysis should remain local and non-invasive unless a task explicitly changes that scope.

## Workspace Layout

- `crates/authmap-core`: canonical IR, schema-facing data types, diagnostics, IDs.
- `crates/authmap-discovery`: deterministic source discovery and project hints.
- `crates/authmap-parsers`: Tree-sitter parsing and source spans.
- `crates/authmap-adapters`: framework route/evidence adapters.
- `crates/authmap-analysis`: scan orchestration, evidence rules, mutation extraction, linking, coverage classification.
- `crates/authmap-report`: Markdown, JSON-related presentation helpers, SARIF, and explain output.
- `crates/authmap-cli`: command-line interface.
- `crates/authmap-testkit`: regression and golden test support.
- `tests/fixtures`: active and pending source fixtures.
- `tests/golden`: reviewed JSON and Markdown snapshots.
- `docs`: schema, diagnostics, configuration, and contributor-facing design docs.

## Common Commands

Run these from the repository root:

```sh
cargo fmt
cargo test --workspace
cargo run -p authmap-cli -- --help
cargo run -p authmap-cli -- scan . --format json --output authmap.json
cargo run -p authmap-cli -- scan . --format markdown --output authmap.md
```

When changing user-visible report or scan behavior, run the full workspace tests. For focused development, run the relevant package or test first, then finish with `cargo test --workspace`.

## Fixture And Golden Expectations

- Add small, static fixtures for new detection behavior whenever practical.
- Active fixtures live under `tests/fixtures/*`; future or not-yet-supported snippets belong under `tests/fixtures/pending`.
- Negative fixtures should prove comments, strings, read-only calls, and unrelated helpers do not emit facts.
- Golden snapshots are reviewed artifacts. Regenerate them only when behavior intentionally changes:

```sh
AUTHMAP_UPDATE_GOLDENS=1 cargo test -p authmap-testkit --test route_inventory_regression
```

Review golden diffs carefully and keep only intentional output changes.

## Schema And Output Discipline

- Do not bump the schema version unless the issue explicitly requires it.
- Preserve the namespaced extension contract; extension keys should look like `authmap.feature`.
- Keep IDs, ordering, diagnostics, facts, links, and coverage support metadata deterministic.
- Prefer conservative detection with explicit uncertainty over guessing.
- When adding new facts, make sure JSON serialization, schema validation, Markdown/report visibility, and explain output remain coherent.

## Implementation Notes

- Use existing local patterns before introducing new abstractions.
- Tree-sitter spans are important: keep file, line, column, and byte ranges stable where possible.
- Detection code should avoid executing project code or requiring third-party app dependencies.
- For source discovery, respect include/exclude behavior and hard exclusions for dependency, build, VCS, cache, and generated output directories.
- Coverage classification should stay evidence-driven. Links with `mutation_id: null` may provide review context but should not raise linked-mutation risk by themselves.

## Before Finishing

- Run `cargo fmt`.
- Run the narrowest relevant tests during iteration.
- Run `cargo test --workspace` before handing off changes that affect Rust code, schema contracts, fixtures, reports, or CLI behavior.
- Check `git status --short` and summarize any uncommitted changes clearly.
