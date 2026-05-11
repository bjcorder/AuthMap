# AuthMap JSON Schema

AuthMap JSON output is a versioned authorization map for local static analysis.
The canonical machine-readable contract lives in
[`schemas/authmap.schema.json`](../schemas/authmap.schema.json).

## Document Layout

Every document contains:

- `schema_version`: the AuthMap schema version. v0.1.0 uses `"0.1.0"`.
- `metadata`: tool version, scan mode, targets, and optional config path.
- `source_files`: discovered files and project hints.
- `routes`: normalized externally reachable routes or handlers.
- `evidence`: authorization evidence observed on or near reachable paths.
- `mutations`: sensitive operations such as ORM writes or deletes.
- `links`: normalized relationships between routes, evidence, and mutations.
- `coverage`: review-oriented classification for routes.
- `diagnostics`: structured scan diagnostics with stable categories and codes.

The JSON schema is strict: misspelled core fields are rejected.

Diagnostic categories, severity semantics, and exit-code behavior are documented
in [`docs/DIAGNOSTICS.md`](DIAGNOSTICS.md).

## Locations And Relationships

`span` is the canonical location object for files, lines, columns, and optional
byte ranges. It is used for route declarations, handler symbols, authorization
evidence, mutations, and diagnostics.

Relationships are normalized. Evidence may name a `route_id` when it is clearly
associated with a route, but route-to-evidence and route-to-mutation structure
is represented by `links[]`. Mutation records do not duplicate route IDs, so the
same mutation fact can be reused by future linking improvements without changing
the mutation object.

Routes also include `source_evidence`, which records why an adapter believes a
route exists, such as a decorator, router call, or framework handler export.

## Confidence And Uncertainty

AuthMap is an evidence inventory, not a vulnerability oracle. `confidence`
indicates how strongly AuthMap believes a route, evidence item, mutation, or
link was detected. `coverage.rationale` explains the classification, while
`coverage.uncertainty_reasons` captures ambiguity such as dynamic dispatch,
reflection, or approximate reachability.

Coverage and risk fields should avoid overstating findings. When a check is
dynamic or incomplete, prefer `unknown_or_dynamic` or `review_required` with a
clear reviewer question.

## Extensions

Core objects are closed to catch typos and accidental contract drift. Forward
compatibility is provided through optional `extensions` objects on the document,
routes, route source evidence, evidence, mutations, links, and coverage entries.

Extension keys must be namespaced with at least one dot, such as
`authmap.sample`, `vendor.feature`, or `team.policy_hint`. Extension values may
be any JSON value.

## Examples

- [`examples/route-inventory.authmap.json`](../examples/route-inventory.authmap.json)
  shows a minimal route inventory without authorization findings.
- [`examples/authorization-map.authmap.json`](../examples/authorization-map.authmap.json)
  shows routes, all documented evidence types, mutations, links, coverage,
  uncertainty reasons, and namespaced extensions.
