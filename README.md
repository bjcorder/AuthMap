# AuthMap

AuthMap is a defensive product-security tool for mapping authorization coverage across an application.

It answers a simple question:

> What protects each route, handler, service method, and data mutation?

AuthMap is intended for application security engineers, product-security teams, and developers who need a concrete inventory of where authentication, authorization, ownership checks, tenant isolation, and sensitive-operation controls actually live in a codebase.

## Problem

Most teams do not have a reliable map of authorization coverage. They may know that an app uses middleware, policies, guards, decorators, or service-layer checks, but they often cannot answer:

- Which routes require authentication?
- Which routes require a specific role?
- Which database mutations are reachable from public endpoints?
- Which paths rely on ownership checks?
- Which sensitive operations are protected only in the frontend?
- Which endpoints changed auth behavior in this pull request?

Traditional SAST tools often produce noisy vulnerability findings. AuthMap starts one layer earlier: build the map, attach evidence, and make coverage reviewable.

## Product thesis

Authorization bugs are often inventory failures before they are coding failures.

If reviewers can see the effective authorization surface of an application, they can spot missing checks, misplaced controls, and high-risk drift earlier.

## Initial scope

AuthMap will start as a local CLI and CI-friendly analyzer that produces a structured authorization map.

Initial targets:

- FastAPI
- Django and Django REST Framework
- Express
- Next.js route handlers
- Common middleware/decorator/guard patterns
- ORM mutation evidence for SQLAlchemy, Django ORM, and Prisma

Initial outputs:

- Markdown report
- JSON authorization map
- SARIF for code-scanning integration
- GitHub Actions summary

The canonical JSON contract is documented in [docs/SCHEMA.md](docs/SCHEMA.md)
and defined by [schemas/authmap.schema.json](schemas/authmap.schema.json).
Diagnostic categories, stable codes, and CI exit behavior are documented in
[docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md).
Project configuration, custom authorization rules, and sensitivity labels are
documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Example report shape

```text
Route: DELETE /accounts/:id
Handler: src/routes/accounts.ts:88
Auth evidence:
  - requiresAuthenticatedUser middleware
  - AccountPolicy.canDelete(user, account)
Data mutations:
  - prisma.account.delete(...)
Coverage: authn + ownership_check
Risk: low
```

```text
Route: POST /admin/users/:id/disable
Handler: app/api/admin/users/[id]/route.ts:41
Auth evidence:
  - session lookup detected
  - no role or privilege check detected before mutation
Data mutations:
  - db.user.update({ disabled: true })
Coverage: authn_only
Risk: review_required
Reviewer question:
  - Should this path require admin role evidence?
```

## Core concepts

### Authorization evidence

AuthMap does not simply look for function names like `authorize`. It collects typed evidence:

- authentication required
- role check
- permission check
- ownership check
- tenant isolation check
- admin/superuser gate
- policy object invocation
- audit/logging control
- explicit public route declaration

### Reachability

A control only matters if it is on a path that reaches the operation. AuthMap should distinguish between:

- middleware protecting a route
- decorator protecting a handler
- service-layer guard protecting an operation
- frontend-only checks that do not protect backend mutations

### Coverage classes

AuthMap should classify coverage in reviewable terms:

- public_declared
- unauthenticated
- authn_only
- role_guarded
- permission_guarded
- ownership_guarded
- tenant_guarded
- admin_guarded
- unknown_or_dynamic

## CLI sketch

```bash
authmap init
authmap scan --format markdown --output authmap.md
authmap scan --format json --output authmap.json
authmap baseline create . --output authmap.baseline.json
authmap diff --base authmap.baseline.json --head authmap.json
authmap diff main...HEAD --target .
authmap explain ROUTE_OR_FINDING_ID
authmap rules suggest
```

`authmap explain <id>` reads `authmap.json` by default, or another AuthMap JSON
document via `--input <path>`, and explains route, evidence, mutation, or link
IDs. It validates the schema version and treats risk as review priority rather
than a confirmed vulnerability.

`authmap rules suggest [target]` is a local read-only helper for discovering
project-specific guard names. It prints Markdown by default, supports
`--format json`, `--output <path>`, and `--config <path>`, and never modifies
`authmap.yml`.

## Local development

AuthMap is implemented as a Rust Cargo workspace. Useful local commands:

```bash
cargo run -p authmap-cli -- --help
cargo run -p authmap-cli -- scan . --format json --output authmap.json
cargo run -p authmap-cli -- scan . --format sarif --output authmap.sarif.json
cargo test --workspace
cargo install --path crates/authmap-cli
```

SARIF output is intended for GitHub code scanning. It emits advisory
authorization coverage alerts for routes that need review, plus scan
diagnostics. Coverage alerts are warnings by default; AuthMap risk and
classification details are included as SARIF result properties rather than
asserted as confirmed vulnerabilities.

`authmap scan` supports `--mode advisory|enforce`. In v0.1.0, enforce mode
writes the requested report and exits `20` when the completed document contains
any `error` or `fatal` diagnostic. Warnings remain non-blocking; incomplete
discovery conditions such as file truncation or oversized supported files are
promoted to error diagnostics in enforce mode.

`authmap baseline create [target] --output authmap.baseline.json` writes a
normal AuthMap JSON document for later comparison. `authmap diff` supports
map-file diffs with `--base` and `--head`, plus committed git ranges such as
`main...HEAD` using `git archive` into temporary directories so the checkout is
not mutated. Diff reports are available as Markdown or JSON; enforce mode exits
`20` only when drift matches the effective `drift.fail_on` policy. Git range
diffs require both `git` and `tar` on `PATH`.

Discovery honors gitignore-style `include` and `exclude` entries in
`authmap.yml`. Includes narrow the supported source-file set, excludes win over
includes, and AuthMap always skips dependency, build, VCS, cache, and generated
report output directories.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | CLI usage error, including unsupported `--format` values |
| 10 | Target path does not exist or is not readable |
| 11 | Enforce-mode target exists but contains no supported source files |
| 12 | Config file cannot be read, parsed, or validated |
| 13 | Scan pipeline failed for another reason |
| 14 | Report rendering or writing failed |
| 20 | Enforce-mode diagnostic or drift policy failure after the report was written |

## GitHub Action

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
      - uses: Ozark-Security-Labs/AuthMap@v0
        with:
          mode: advisory
          output: markdown,json
```

The action writes Markdown output to the job summary and uploads generated
reports as an artifact by default. SARIF upload is optional and requires
`security-events: write`:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: Ozark-Security-Labs/AuthMap@v0
    with:
      mode: advisory
      output: markdown,json,sarif
      upload-sarif: "true"
```

In enforce mode, AuthMap still writes requested reports first, then returns
exit code `20` when enforce-blocking diagnostics or baseline drift policy
matches are present:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: Ozark-Security-Labs/AuthMap@v0
    with:
      mode: enforce
      output: markdown,json
```

To review drift against a baseline in CI, provide `baseline`. The action
generates `authmap.diff.json` and `authmap.diff.md`, appends the drift Markdown
to the job summary, and honors `fail-on` in enforce mode:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: Ozark-Security-Labs/AuthMap@v0
    with:
      mode: enforce
      output: markdown,json
      baseline: authmap.baseline.json
      fail-on: added_high_risk_route,auth_downgrade,new_linked_mutation
```

See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) for all inputs, outputs, and
permission details.

## Relationship to adjacent projects

AuthMap can become a foundation for higher-level product-security tools:

- invariant regression detection
- tenant isolation checks
- API security diffing
- security control ledgers
- threat-model updates

It complements scanners by producing an evidence-backed map first, then allowing specific findings and policies to be layered on top.

## Non-goals

AuthMap is not intended to:

- exploit authorization bugs
- attack live systems
- replace human security review
- claim vulnerabilities without evidence
- require running the target application

## Status

This repository contains the v0.1.0 foundation work: Rust workspace crates for
the CLI, config loading, deterministic discovery, Tree-sitter parsing,
canonical schema/IR, and JSON/Markdown/SARIF reporting. Framework-specific
route and authorization adapters are still future milestone work.
