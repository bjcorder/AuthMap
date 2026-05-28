# AuthMap JSON Consumer Contract

AuthMap JSON is the public, schema-backed authorization map produced by
`authmap scan --format json`. It is intended for downstream tools that need a
stable inventory of routes, authorization evidence, sensitive mutations,
reachability links, coverage classifications, diagnostics, confidence, and
review uncertainty without depending on AuthMap's Rust crate internals.

The canonical machine-readable schema is
[`schemas/authmap.schema.json`](../schemas/authmap.schema.json). Schema field
semantics are documented in [SCHEMA.md](SCHEMA.md), diagnostic behavior in
[DIAGNOSTICS.md](DIAGNOSTICS.md), and artifact sensitivity in
[DATA_HANDLING.md](DATA_HANDLING.md).

## Stable Document Shape

Consumers should treat these top-level collections as the stable public model:

- `schema_version` — compatibility version for the canonical AuthMap document.
- `metadata` — tool version, scan mode, scan roots, and optional config path.
- `source_files` — deterministic source inventory and project hints used by the scan.
- `routes` — externally reachable routes or handlers with normalized methods,
  paths, params, handler symbols, source evidence, and declared protection.
- `evidence` — authorization evidence such as authn, roles, permissions,
  ownership, tenant checks, admin gates, explicit public declarations, audit
  logs, and dynamic checks.
- `mutations` — sensitive data operations detected statically.
- `links` — relationships among routes, evidence, and mutations. A link with
  `mutation_id: null` preserves unresolved reachability context and should not
  be treated as a confirmed linked mutation.
- `coverage` — review-oriented route classification, risk, rationale,
  reviewer questions, uncertainty, and machine-readable support metadata.
- `policy_cases` — optional static policy summaries for effective protection,
  linked-mutation review, conflicting evidence, duplicate evidence, dynamic
  policy behavior, and unreachable branches.
- `diagnostics` — structured scan diagnostics with stable categories, severity,
  recoverability, source spans, and messages.

IDs are stable within a generated document and deterministic for the same input
and AuthMap version. Consumers should join objects by IDs rather than assuming
array position has domain meaning. Preserve unknown namespaced extension keys
when proxying or enriching AuthMap documents.

## Automation-Safe Fields

The following fields are appropriate for downstream automation because they are
schema-backed and intentionally normalized:

- route `id`, `framework`, `method`, `path`, `params`, `handler`, `span`, and
  `confidence`
- evidence `id`, `route_id`, `evidence_type`, `mechanism`, `symbol`, `span`,
  and `confidence`
- mutation `id`, `operation`, `library`, `resource`, `span`, and `confidence`
- link `id`, `route_id`, `mutation_id`, `evidence_id`, and `confidence`
- coverage `route_id`, `class`, `risk`, `rationale`, `reviewer_questions`,
  `uncertainty_reasons`, and `extensions["authmap.coverage"]`
- policy case `kind`, `summary`, `evidence_ids`, `input_names`, `branches`,
  reviewer questions, and uncertainty reasons
- diagnostic `category`, `code`, `severity`, `recoverability`, `span`, and
  `message`

Human-review fields such as rationale, notes, uncertainty reasons, diagnostic
messages, and reviewer questions may change wording over time while preserving
their conservative meaning. Use them for triage and display; do not build hard
security gates that depend on exact prose.

## Compatibility And Extensions

AuthMap uses semantic versioning for the CLI and a separate `schema_version` for
canonical JSON. Compatible releases may add optional fields, new diagnostics,
new namespaced extensions, or more precise evidence while keeping existing
schema semantics. Breaking changes require a schema-version change and release
notes per [RELEASES.md](RELEASES.md).

Core object fields are strict so typos fail schema validation. Forward
compatibility is provided through optional `extensions` objects. Extension keys
must be namespaced with at least one dot, for example `authmap.coverage`,
`authmap.tenant_review`, `vendor.policy`, or `team.review_hint`.

First-party `authmap.*` extensions may mature into documented public fields in
future schema versions. Non-AuthMap consumers should write their own extension
keys under a namespace they control and should not rely on crate-private Rust
types or enum names that are not represented in the JSON schema.

Focused reports such as `authmap routes`, `authmap tenants`, `authmap diff`,
and `authmap controls` have their own report contracts. They are useful for
review workflows, but the canonical downstream automation contract remains the
document emitted by `authmap scan --format json`.

## Consumer Workflow Examples

### Policy Expectations

1. Generate the canonical map:
   ```sh
   authmap scan . --config authmap.yml --format json --output authmap.json
   ```
2. Validate `authmap.json` against `schemas/authmap.schema.json`.
3. Join `routes[]` to `coverage[]` by `route_id`.
4. Compare coverage classes, risks, and `authmap.coverage.evidence_ids` against
   your expected policy for sensitive route families.
5. Surface reviewer questions instead of claiming a vulnerability when evidence
   is missing, weak, dynamic, or ambiguous.

### Policy Reasoning

Use `policy_cases[]` when present to explain why a route was classified or why
policy behavior needs review. A consumer can render each case's `kind`,
`summary`, `branches`, `evidence_ids`, and `uncertainty_reasons`, then link back
to source spans for code review. Dynamic, conflicting, duplicate, and
unreachable cases are review prompts, not runtime proofs.

### Finding Workflows

Finding systems can create review items from combinations such as:

- high-risk `coverage` with no strong evidence IDs
- review-required coverage on unsafe methods or path-parameter routes
- linked mutations where `links[].mutation_id` is present and coverage is weak
- diagnostics with error severity or fatal recoverability in enforce mode

Store the AuthMap IDs and spans with the finding so later scans can explain the
source evidence. Avoid collapsing uncertainty into confirmed vulnerability
language unless a human reviewer has verified the behavior.

### SARIF And Report Enrichment

SARIF consumers should use AuthMap SARIF as advisory code-scanning output and
can enrich SARIF results with canonical JSON details by matching route IDs,
evidence IDs, mutation IDs, and source spans. Markdown reports and focused
route, tenant, drift, and controls reports are optimized for humans and PR
summaries; use canonical JSON when a durable automation contract is required.

## Privacy And Sharing

AuthMap JSON can reveal route structure, authorization control names, source
paths, line numbers, data resources, drift priorities, and reviewer questions.
Treat JSON, Markdown, SARIF, baselines, and drift artifacts as sensitive review
material unless your organization has approved broader sharing. See
[DATA_HANDLING.md](DATA_HANDLING.md) for redaction limits, CI artifact guidance,
SARIF upload considerations, and safe sharing recommendations.

## Schema-Validated Examples

The committed examples are validated by `cargo test -p authmap-core
schema_contract`:

- [`examples/route-inventory.authmap.json`](../examples/route-inventory.authmap.json)
- [`examples/authorization-map.authmap.json`](../examples/authorization-map.authmap.json)

Use these examples as small fixtures for consumer parsers, but prefer generating
fresh JSON from your own codebase when testing policy-specific behavior.
