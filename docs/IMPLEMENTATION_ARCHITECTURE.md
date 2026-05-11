# Implementation Architecture

AuthMap is implemented as a Rust Cargo workspace around a deterministic
static-analysis pipeline:

```text
discover files
  -> parse source
  -> framework adapters
  -> evidence and mutation extraction
  -> reachability linking
  -> coverage classification
  -> reports
```

The workspace optimizes for three properties:

- predictable results across operating systems and worker counts
- bounded parallelism for large repositories
- small crate boundaries that keep framework-specific logic isolated

## Workspace Layout

```text
Cargo.toml
crates/
  authmap-cli/          # binary crate: clap commands, exit codes, user I/O
  authmap-core/         # shared IR: routes, evidence, mutations, diagnostics
  authmap-config/       # authmap.yml loading, validation, defaults
  authmap-discovery/    # file walking, ignores, project hints, scan limits
  authmap-parsers/      # parser facade over Python/JS/TS backends
  authmap-adapters/     # FastAPI, Express, Django/DRF, Next.js route adapters
  authmap-analysis/     # evidence extraction, mutation extraction, linking
  authmap-report/       # JSON, Markdown, SARIF, GitHub summary, redaction
  authmap-testkit/      # fixture helpers and snapshot utilities
schemas/
  authmap.schema.json
tests/
  fixtures/
  golden/
```

The CLI should stay thin. It loads arguments and config, builds a scan plan,
invokes the analysis pipeline, and writes reports. Analysis crates should not
perform terminal output, prompt users, or write report files.

## Core Contracts

`authmap-core` owns the stable intermediate representation:

- `AuthMapDocument`
- `ScanMetadata`
- `SourceFile`
- `Span`
- `Diagnostic`
- `Route`
- `Evidence`
- `Mutation`
- `ReachabilityLink`
- `Coverage`
- `Confidence`

Extension points are crate-local traits:

- `ParserBackend` in `authmap-parsers`
- `FrameworkAdapter` in `authmap-adapters`
- `EvidenceExtractor` and `MutationExtractor` in `authmap-analysis`
- `Reporter` in `authmap-report`

Adapters and extractors emit facts with spans, confidence, and diagnostics.
They must not assign final IDs, mutate global state, or write files. The scan
orchestrator performs deterministic sorting and ID assignment after all worker
results are collected.

## Concurrency Model

Safe parallel work:

- file discovery can use gitignore-aware parallel walking
- parsing can run per file with worker-local parser instances
- route, evidence, and mutation extraction can run over immutable parsed input
- coverage classification can run per route after linking indexes are built
- redaction should be a pure text transformation

Serial reduction points:

- normalize and sort discovered paths
- merge adapter and extractor outputs
- assign route, evidence, mutation, diagnostic, and finding IDs
- build handler, import, symbol, service-call, and mutation indexes
- render final reports
- write output files once, using a temp file followed by atomic rename

Race-condition rules:

- avoid shared mutable global caches in v1
- avoid concurrent maps unless profiling proves they are needed
- have workers return owned result structs
- accumulate diagnostics as data rather than relying on threaded logging
- make report output a single final step after the document is complete

## Dependency Defaults

Initial implementation dependencies:

- `clap` for CLI parsing
- `serde`, `serde_json`, and `serde_yaml` for schema and config data
- `ignore` for gitignore-aware discovery
- `rayon` for bounded CPU parallelism
- `tree-sitter` with Python, JavaScript, and TypeScript/TSX grammars behind
  `authmap-parsers` as the first parser facade backend
- `thiserror` and `miette` for structured errors and CLI diagnostics

Parser backends are hidden behind `authmap-parsers` so more precise libraries
such as `oxc`, `swc`, or Python-specific parsers can be added later without
rewiring adapters or reports.

Parser and adapter contributor contracts are documented in
[PARSERS_AND_ADAPTERS.md](PARSERS_AND_ADAPTERS.md).

## Testing Strategy

Required test classes:

- core IR serialization and schema compatibility
- config validation and diagnostic generation
- adapter fixtures for FastAPI, Express, Django/DRF, and Next.js
- golden JSON and Markdown snapshots
- determinism checks across repeated scans and different worker counts
- large-repository and skipped-file behavior under scan limits
- cross-platform CI on Linux, macOS, and Windows
