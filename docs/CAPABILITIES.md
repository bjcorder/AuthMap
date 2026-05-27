# AuthMap Capabilities And Workflows

AuthMap folds the RouteSentinel, PolicyLens, TenantFence, PermDiff, and
GuardRailDiff backlog themes into one product: a local, static authorization
map for routes, policies, tenants, semantic diffs, and authorization controls.
Users do not need to learn separate tools or repositories. Each capability is a
view over the same evidence-bound map and should preserve AuthMap's defensive
scope: no exploitation, no live application access, no credential handling, no
generic SAST sprawl, and no unsupported vulnerability claims.

## Folded Capability Model

| Capability area | AuthMap surface | Purpose | Current status |
| --- | --- | --- | --- |
| Route inventory | `authmap scan`, `authmap routes` | Discover reachable routes, handlers, params, declared protection, confidence, and coverage. | Implemented for supported frameworks; see [PARSERS_AND_ADAPTERS.md](PARSERS_AND_ADAPTERS.md). |
| Policy evidence and explanation | `authmap scan`, `authmap explain <id>` | Show guard, role, permission, ownership, tenant, admin, public, audit, and dynamic policy evidence with policy cases and reviewer questions. | Implemented as PolicyLens-style sections in reports and `policy_cases[]`. |
| Tenant and ownership review | `authmap tenants` | Focus review on tenant/ownership evidence, linked sensitive operations, missing or weak scoping signals, and uncertainty. | Implemented as focused Markdown/JSON reports. |
| Semantic authorization diffs | `authmap baseline create`, `authmap diff` | Compare AuthMap JSON baselines or committed git refs for route, evidence, coverage, policy, and linked-mutation drift. | Implemented as `authmap.diff` reports. |
| Authorization controls review | `authmap controls` | Narrow diffs to guards, route guards, permission maps, tenant/ownership helpers, admin gates, audit controls, policy helpers, and auth-relevant headers. | Implemented as `authmap.controls` reports. |
| CI and downstream integrations | GitHub Action, SARIF, canonical JSON | Publish review summaries, optional SARIF, baseline drift gates, and schema-backed JSON for consumers. | Implemented; see [GITHUB_ACTION.md](GITHUB_ACTION.md) and [JSON_CONSUMERS.md](JSON_CONSUMERS.md). |

Roadmap and fixture follow-up are tracked in the v1.5 milestone issues:
[#53](https://github.com/Ozark-Security-Labs/AuthMap/issues/53) documents the
JSON consumer contract,
[#54](https://github.com/Ozark-Security-Labs/AuthMap/issues/54) expands
post-v1 workflow fixtures, and
[#55](https://github.com/Ozark-Security-Labs/AuthMap/issues/55) documents this
folded model.

## Command Surface

- `authmap scan <target>` emits the full authorization map as Markdown, JSON,
  or SARIF. Use JSON when downstream automation needs the canonical schema.
- `authmap routes <target>` renders a focused route inventory using the same
  scan pipeline and configuration as `scan`.
- `authmap tenants <target>` renders tenant and ownership review prompts with
  evidence, linked mutations, confidence, uncertainty, and reviewer questions.
- `authmap explain <id> --input authmap.json` resolves a route, evidence,
  mutation, link, or policy case from a generated JSON document.
- `authmap baseline create <target>` writes a schema-compatible AuthMap JSON
  baseline for future comparison.
- `authmap diff --base base.json --head head.json` compares two AuthMap JSON
  documents; `authmap diff BASE...HEAD --target .` scans committed git refs via
  `git archive` without mutating the checkout.
- `authmap controls` accepts the same map-file or git-range inputs as `diff`
  and reports the authorization-control subset.
- The GitHub Action runs scans, writes requested reports, appends Markdown to
  the job summary, optionally uploads SARIF, and can enforce baseline drift
  policy after report artifacts are written.

## Workflow Examples

### Local Route And Policy Review

```sh
authmap init --output authmap.yml
authmap scan . --config authmap.yml --format markdown --output authmap.md
authmap scan . --config authmap.yml --format json --output authmap.json
authmap explain route_0001 --input authmap.json
```

Use the Markdown report to review route coverage, PolicyLens policy cases,
linked data mutations, diagnostics, uncertainty, and reviewer questions. Use
`explain` when a reviewer needs the source-backed context for one ID.

### Focused Tenant Review

```sh
authmap tenants . --config authmap.yml --format markdown --output authmap.tenants.md
authmap tenants . --config authmap.yml --format json --output authmap.tenants.json
```

Tenant findings are review prompts. Missing or weak tenant/ownership evidence
on route-param or mutation-linked flows should be confirmed against application
policy before it is described as a vulnerability.

### Pull Request Review In CI

```yaml
name: AuthMap
on:
  pull_request:

permissions:
  contents: read

jobs:
  authmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ozark-Security-Labs/AuthMap@v1
        with:
          mode: advisory
          output: markdown,json,sarif
          upload-sarif: "false"
```

The action writes generated reports under the configured output directory,
uploads report artifacts by default, and appends Markdown to the job summary.
Enable SARIF upload only when the workflow has `security-events: write` and the
code-scanning visibility is acceptable for your repository.

### Baseline Comparison And Enforce Mode

```sh
authmap baseline create . --output authmap.baseline.json
authmap scan . --format json --output authmap.json
authmap diff --base authmap.baseline.json --head authmap.json \
  --mode enforce \
  --fail-on added_high_risk_route,auth_downgrade,new_linked_mutation \
  --format markdown \
  --output authmap.diff.md
authmap controls --base authmap.baseline.json --head authmap.json \
  --format markdown \
  --output authmap.controls.md
```

Enforce mode writes the report first, then exits `20` when configured drift
categories are blocking. Drift and controls JSON reports have their own report
contracts and are not canonical AuthMap map documents.

### Downstream JSON Consumption

```sh
authmap scan . --format json --output authmap.json
```

Downstream tools should validate `authmap.json` against
[`schemas/authmap.schema.json`](../schemas/authmap.schema.json), join records by
IDs, preserve namespaced extensions, and use conservative language for weak or
dynamic evidence. See [JSON_CONSUMERS.md](JSON_CONSUMERS.md) for stable fields,
extension expectations, policy/finding workflows, SARIF enrichment, and privacy
guidance.

## Limitations And Reporting Language

AuthMap remains static and local. It does not execute target code, import
application modules, connect to databases, call services, generate payloads, or
try to bypass controls. Dynamic dispatch, reflection, dependency injection,
metaprogramming, generated code, unsupported frameworks, and code outside the
scan target can produce incomplete or uncertain evidence.

Per-framework detection scope and current limitations are listed in
[PARSERS_AND_ADAPTERS.md](PARSERS_AND_ADAPTERS.md). Two behaviors worth noting:
a route that carries both an explicit-public marker and guard evidence is
classified `unknown_or_dynamic` (review required) rather than `public_declared`;
and tRPC and GraphQL routes are inventoried with their declared protection but
are not yet linked to reachable data mutations.

Reports should be read as authorization inventory and review prioritization.
`high` and `review_required` risk values, drift findings, SARIF alerts, tenant
questions, and policy uncertainty are not confirmed vulnerabilities until a
human reviewer validates the intended authorization behavior.

For configuration, diagnostics, schema, and privacy details, see:

- [CONFIGURATION.md](CONFIGURATION.md)
- [DIAGNOSTICS.md](DIAGNOSTICS.md)
- [SCHEMA.md](SCHEMA.md)
- [JSON_CONSUMERS.md](JSON_CONSUMERS.md)
- [DATA_HANDLING.md](DATA_HANDLING.md)
