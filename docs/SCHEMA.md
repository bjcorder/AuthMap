# AuthMap JSON Schema

AuthMap JSON output is a versioned authorization map for local static analysis.
The canonical machine-readable contract lives in
[`schemas/authmap.schema.json`](../schemas/authmap.schema.json).

## Document Layout

Every document contains:

- `schema_version`: the AuthMap schema version. The v0.1.0 CLI emits schema `"0.1.0"`.
- `metadata`: tool version, scan mode, targets, and optional config path.
- `source_files`: discovered files and project hints.
- `routes`: normalized externally reachable routes or handlers.
- `evidence`: authorization evidence observed on or near reachable paths.
- `mutations`: sensitive operations such as ORM writes or deletes.
- `links`: normalized relationships between routes, evidence, and mutations.
- `coverage`: review-oriented classification for routes.
- `policy_cases`: optional static policy decision summaries for route review.
- `diagnostics`: structured scan diagnostics with stable categories and codes.

The JSON schema is strict: misspelled core fields are rejected.

Diagnostic categories, severity semantics, and exit-code behavior are documented
in [`docs/DIAGNOSTICS.md`](DIAGNOSTICS.md).
Project configuration is documented in
[`docs/CONFIGURATION.md`](CONFIGURATION.md).
Downstream consumer guidance, stable-field expectations, extension
compatibility, and automation workflow examples are documented in
[`docs/JSON_CONSUMERS.md`](JSON_CONSUMERS.md).

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
When available, routes include normalized `params` entries for path parameters
and `declared_protection` entries for declared public markers, route guards,
inherited guard context, or dynamic protection
signals. These entries are evidence metadata for review; coverage classification
still comes from `coverage[]`.

## Confidence And Uncertainty

AuthMap is an evidence inventory, not a vulnerability oracle. `confidence`
indicates how strongly AuthMap believes a route, evidence item, mutation, or
link was detected. `coverage.rationale` explains the classification, while
`coverage.uncertainty_reasons` captures ambiguity such as dynamic dispatch,
reflection, or approximate reachability.

Coverage and risk fields should avoid overstating findings. When a check is
dynamic or incomplete, prefer `unknown_or_dynamic` or `review_required` with a
clear reviewer question.

Coverage classification is deterministic and rule-based. AuthMap chooses the
most specific strong evidence class in this order: `public_declared`,
`admin_guarded`, `permission_guarded`, `ownership_guarded`, `tenant_guarded`,
`role_guarded`, `authn_only`, `unknown_or_dynamic`, then `unauthenticated`.
Low-confidence evidence and `unknown_dynamic_check` evidence require review
rather than proving a route safe.

Risk scoring uses route sensitivity modifiers and linked facts:

- `high`: no authorization evidence on unsafe methods, `ANY`, or routes with
  linked mutations.
- `medium`: no authorization evidence on sensitive read paths such as admin,
  account, user, tenant, or path-parameter routes.
- `review_required`: weak/dynamic-only evidence, sensitive public routes,
  sensitive authn-only routes, or linked mutations guarded only by non-resource
  evidence.
- `low`: non-sensitive public/unauthenticated routes and routes with strong
  resource-oriented authorization evidence.

Coverage entries include machine-readable support metadata in the namespaced
extension key `authmap.coverage`. The extension can contain `evidence_ids`,
`weak_evidence_ids`, `mutation_ids`, `link_ids`, `policy_case_ids`, and
`sensitivity_reasons`.

Tenant isolation review metadata can appear in
`coverage.extensions["authmap.tenant_review"]`. It is advisory metadata for
focused tenant reports and can include `review_required`, `reasons`,
`evidence_ids`, and `weak_evidence_ids`; it does not change the canonical schema
version.

Policy decision cases are optional static summaries, not runtime proofs. When
present, `policy_cases[]` entries cite route and evidence IDs, summarize
effective protection or review-required policy behavior, record observed inputs
and branches, and carry reviewer questions or uncertainty notes for dynamic,
conflicting, duplicated, unreachable, or linked-mutation policy evidence.

Raw or ambiguous mutation facts can include machine-readable review metadata in
`mutation.extensions["authmap.mutation"]`. The MVP uses `review_required`,
`detection`, and `uncertainty_reasons` fields for raw SQL and unknown mutation
operations while keeping the canonical mutation schema unchanged.

Unresolved service-like route calls can include machine-readable uncertainty
metadata in `link.extensions["authmap.reachability"]`. The v1 linker uses
`call_target`, `call_span`, and `reason` for low-confidence links whose
`mutation_id` is `null`; those links preserve review context without changing
linked-mutation risk scoring.

## Project Authorization Rules

Projects can extend built-in guard detection through `authmap.yml`:

```yaml
authorization:
  rules:
    - name: billing permission guard
      evidence_type: permission_check
      mechanism: billing_plan_guard
      confidence: medium
      match:
        exact: [ensurePaidPlan]
        contains: [permission]
      notes:
        - configured by project
```

Rule matching supports exact symbol names and case-insensitive substring
matches. Rules emit canonical evidence entries and keep the core output schema
unchanged. The complete config format and CLI helpers are documented in
[`docs/CONFIGURATION.md`](CONFIGURATION.md), including `authmap explain` and
the read-only `authmap rules suggest` workflow.

## Project Sensitivity Rules

Projects can label sensitive route families and linked mutation resources in
`authmap.yml` without changing the JSON schema:

```yaml
sensitivity:
  routes:
    - name: account routes
      labels: [account_data]
      match:
        contains: [/accounts]
      methods: [GET, PATCH, DELETE]
      reviewer_questions:
        - Should account routes require ownership or permission checks?
  resources:
    - name: invoice mutations
      labels: [financial]
      match:
        exact: [Invoice]
      reviewer_questions:
        - Should invoice writes require finance approval?
```

Route labels are emitted as `config_route:<label>` and resource labels as
`config_resource:<label>` in
`coverage.extensions["authmap.coverage"].sensitivity_reasons`. These labels
prioritize review and reviewer questions; they do not assert vulnerabilities.

## Extensions

Core objects are closed to catch typos and accidental contract drift. Forward
compatibility is provided through optional `extensions` objects on the document,
routes, route source evidence, evidence, mutations, links, and coverage entries.

Extension keys must be namespaced with at least one dot, such as
`authmap.sample`, `vendor.feature`, or `team.policy_hint`. Extension values may
be any JSON value.

## Examples

- [`examples/route-inventory.authmap.json`](../examples/route-inventory.authmap.json)
  shows a minimal route inventory with normalized path params and no
  authorization findings.
- [`examples/authorization-map.authmap.json`](../examples/authorization-map.authmap.json)
  shows routes, all documented evidence types, mutations, links, coverage,
  uncertainty reasons, and namespaced extensions.
