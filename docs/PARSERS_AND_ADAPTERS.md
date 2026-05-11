# Parsers And Adapters

AuthMap adapters run on static parse output. They must not execute target
application code, import target modules, call live services, or require the
target app to start.

## Parser Strategy

AuthMap v0.1.0 uses Tree-sitter as its initial parser layer:

- Python: `tree-sitter-python`
- JavaScript and JSX: `tree-sitter-javascript`
- TypeScript and TSX: `tree-sitter-typescript`

Tree-sitter is a good first fit because it is local, non-executing, incremental,
and tolerant of partial syntax errors. It exposes byte ranges and source points
that map cleanly into AuthMap spans. More specialized parsers can be added later
behind the same `authmap-parsers` facade.

Unsupported languages produce a recoverable diagnostic and no parse tree. Source
read failures produce diagnostics through the scan pipeline. Syntax-error trees
produce `parser.source_parse_recovered` diagnostics while still returning the
partial tree so adapters can emit any facts they can prove.

## Span Conventions

`Span` is the canonical location type:

- `file` is the normalized path emitted by discovery.
- `line` and `column` are 1-based.
- `byte_range.start` and `byte_range.end` are 0-based UTF-8 byte offsets.
- `byte_range.end` is exclusive.

Symbol spans should point to the smallest stable symbol token when practical.
Route or source-evidence spans should point to the framework declaration, call,
decorator, or exported handler that proves the route exists.

## Adapter Contract

Framework adapters implement `FrameworkAdapter` from `authmap-adapters`.
Adapters receive an `AdapterInput` with:

- the parsed file and original source text
- optional Tree-sitter tree access
- helper methods for snippets and Tree-sitter node spans
- adapter context for future scan/config constraints

Adapters return `AdapterOutput`, which may contain:

- `routes`
- `evidence`
- `mutations`
- `diagnostics`

Adapters should emit raw facts only. They should not assign final global IDs
beyond stable local IDs for emitted facts, perform reachability linking, classify
coverage, write reports, or print terminal output. Linking, deterministic merge
order, coverage classification, and report rendering stay in later pipeline
stages.

Diagnostics are data. If an adapter can prove one route and encounters ambiguity
elsewhere, it should return the route plus a diagnostic rather than failing the
whole scan. Use `confidence`, `notes`, `extensions`, and diagnostics to make
uncertainty explicit without overstating findings.

Diagnostic categories, stable codes, and enforce-mode exit behavior are defined
in [`docs/DIAGNOSTICS.md`](DIAGNOSTICS.md).

## Fixture Expectations

New adapters should include fixtures that cover:

- one minimal positive route example
- unsupported or ambiguous syntax that still returns partial facts when possible
- diagnostics for dynamic or unsupported framework patterns
- stable spans for route declarations and security-relevant symbols
- JSON/schema compatibility through the shared AuthMap document contract

Fixture tests should avoid live services, dependency installation, network
access, and executing the target application.

Issue #19 defines this shared contract. It does not add FastAPI, Express,
Django/DRF, or Next.js analyzer behavior.
