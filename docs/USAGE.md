# AuthMap Usage

AuthMap statically maps authorization coverage in local source code. It does not
run the target application, import target modules, connect to databases, call
services, or perform live attack workflows.

Use it for defensive, authorized review of code you own or are permitted to
assess. See [../SECURITY.md](../SECURITY.md) for the project safety boundary and
finding language, and [DATA_HANDLING.md](DATA_HANDLING.md) for privacy,
report-sensitivity, CI artifact, SARIF, baseline, and sharing guidance.

## Installation And Setup

From a tagged GitHub Release, download the archive for your platform, unpack it,
and place the `authmap` binary on your `PATH`. Verify the install with:

```sh
authmap --help
authmap --version
```

From the repository root, install the CLI locally for development:

```sh
cargo install --path crates/authmap-cli --locked
```

Cargo package artifacts are generated so maintainers can review package
contents before release. Registry publishing is not enabled yet, so install from
the workspace path during development and from GitHub Release archives for tagged
releases.

During development, run the CLI without installing it:

```sh
cargo run -p authmap-cli -- --help
cargo run -p authmap-cli -- --version
```

Create a starter configuration file:

```sh
authmap init --output authmap.yml
```

The config file is optional. It can set scan mode, include and exclude patterns,
scan limits, drift policy, custom authorization rules, and sensitivity labels.
The full format is documented in [CONFIGURATION.md](CONFIGURATION.md).

## Basic Scan

Generate a Markdown report for human review:

```sh
authmap scan . --config authmap.yml --format markdown --output authmap.md
```

Generate the canonical JSON authorization map for automation:

```sh
authmap scan . --config authmap.yml --format json --output authmap.json
```

Generate SARIF for advisory code-scanning integration:

```sh
authmap scan . --config authmap.yml --format sarif --output authmap.sarif
```

When `--output` is omitted, AuthMap prints the report to stdout. `--config` may
be omitted when no project config is needed.

## Scan Modes

AuthMap supports `advisory` and `enforce` modes:

```sh
authmap scan . --mode advisory --format markdown --output authmap.md
authmap scan . --mode enforce --format json --output authmap.json
```

Advisory mode prefers complete artifacts over failing fast. Recoverable
diagnostics do not fail the command.

Enforce mode still writes the requested report first. It exits `20` when the
completed document contains an error diagnostic or fatal diagnostic. Warnings
remain non-blocking. Diagnostic categories and exit behavior are documented in
[DIAGNOSTICS.md](DIAGNOSTICS.md).

## FastAPI Example

Run AuthMap against the repository's realistic FastAPI fixture:

```sh
cargo run -p authmap-cli -- scan tests/fixtures/realistic/fastapi \
  --format markdown --output authmap.fastapi.md
```

The report inventory includes routes such as:

```text
GET /api/accounts/{account_id} -> authn_only, review_required
POST /api/accounts -> authn_only, review_required, linked Account create
PATCH /api/accounts/{account_id} -> permission_guarded, review_required
DELETE /api/accounts/{account_id} -> admin_guarded, review_required
GET /health -> unauthenticated, low
```

Review-required routes are not confirmed vulnerabilities. They are routes where
AuthMap found sensitivity signals, linked mutations, weak or dynamic evidence,
or incomplete static context that should be reviewed by a human.

The same fixture can be scanned as JSON:

```sh
cargo run -p authmap-cli -- scan tests/fixtures/realistic/fastapi \
  --format json --output authmap.fastapi.json
```

Use `explain` to inspect a route, evidence item, mutation, or reachability link
from a JSON report:

```sh
authmap explain route_0001 --input authmap.fastapi.json
```

## Express Example

Run AuthMap against the repository's realistic Express fixture:

```sh
cargo run -p authmap-cli -- scan tests/fixtures/realistic/express \
  --format markdown --output authmap.express.md
```

The report inventory includes routes such as:

```text
GET /health -> unauthenticated, low
GET /api/:accountId -> authn_only, review_required
POST /api -> authn_only, review_required, linked account create
PATCH /api/:accountId -> permission_guarded, review_required
DELETE /api/:accountId -> admin_guarded, review_required
GET /api/tenant/:tenantId -> tenant_guarded, low
```

When Express mount prefixes or routers are dynamic, AuthMap emits diagnostics
and uncertainty notes instead of guessing. For example, a route may appear with
medium confidence when a mount prefix could not be resolved statically.

## Output Formats

Markdown is intended for reviewers. It includes:

- scan summary
- review-required table
- route inventory
- data mutation inventory
- route details with evidence, mutations, links, reviewer questions, and
  uncertainty notes
- diagnostics and skipped files

JSON is the canonical machine-readable AuthMap document. Its schema is
documented in [SCHEMA.md](SCHEMA.md) and defined by
[../schemas/authmap.schema.json](../schemas/authmap.schema.json).

SARIF is for GitHub code scanning and similar integrations. AuthMap SARIF emits
advisory authorization coverage alerts and diagnostics. SARIF results should be
treated as review priorities, not confirmed vulnerabilities.

AuthMap redacts obvious high-risk values before writing JSON, Markdown, SARIF,
drift reports, rule suggestions, and explain output. Redaction covers common
authorization headers, credentials in URLs, token-like query parameters,
secret-looking assignments, and common token shapes. Redaction is best-effort:
it reduces accidental exposure risk, but reports can still contain sensitive
application structure, route names, file paths, line numbers, symbol names,
classification rationale, and non-obvious secrets. Treat generated artifacts as
sensitive review material unless your organization has reviewed them. See
[DATA_HANDLING.md](DATA_HANDLING.md) for the complete data-handling guidance.

## Interpreting Coverage

Coverage classes describe the strongest reviewable authorization evidence AuthMap
can associate with a route:

- `public_declared`
- `unauthenticated`
- `authn_only`
- `role_guarded`
- `permission_guarded`
- `ownership_guarded`
- `tenant_guarded`
- `admin_guarded`
- `unknown_or_dynamic`

Risk levels prioritize review:

- `high`: no authorization evidence on unsafe methods, `ANY`, or routes with
  linked mutations
- `medium`: no authorization evidence on sensitive read paths such as admin,
  account, user, tenant, or path-parameter routes
- `review_required`: weak or dynamic evidence, sensitive public routes,
  sensitive `authn_only` routes, or linked mutations guarded only by
  non-resource-specific evidence
- `low`: non-sensitive public or unauthenticated routes and routes with strong
  resource-oriented authorization evidence

Confidence describes how strongly AuthMap believes a route, evidence item,
mutation, or link was detected. Low or medium confidence should be reviewed
against the source span and any uncertainty notes.

Reviewer questions are prompts. They are intended to guide code review and
policy discussion, not to assert that the route is exploitable.

## Configuration Basics

Use `authmap.yml` to narrow scan scope, tune limits, add project-specific guard
names, label sensitive route families, and configure drift enforcement.

Common examples:

```yaml
include:
  - app/**
  - src/**
exclude:
  - "**/*.test.ts"

authorization:
  rules:
    - name: billing permission guard
      evidence_type: permission_check
      mechanism: billing_plan_guard
      match:
        exact: [ensureBillingPermission]

sensitivity:
  routes:
    - name: account routes
      labels: [account_data]
      match:
        contains: [/accounts]
      methods: [GET, POST, PATCH, DELETE]
      reviewer_questions:
        - Should account routes require ownership or permission checks?
```

`authmap rules suggest` can help discover project-specific guard names without
editing the config file:

```sh
authmap rules suggest . --format markdown
```

Review suggestions before copying them into `authmap.yml`.

## Baselines And Diffs

Create a baseline:

```sh
authmap baseline create . --output authmap.baseline.json
```

Compare two AuthMap JSON reports:

```sh
authmap scan . --format json --output authmap.json
authmap diff --base authmap.baseline.json --head authmap.json --format markdown
```

Compare committed git refs:

```sh
authmap diff main...HEAD --target . --format json --output authmap.diff.json
```

Git range diffs use `git archive` into temporary directories. They do not
include uncommitted working-tree changes.

## GitHub Actions

Use the composite action for pull request review:

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
`security-events: write`. Baseline drift review is also supported. See
[DATA_HANDLING.md](DATA_HANDLING.md) before sharing generated CI artifacts or
enabling SARIF upload.

Full action inputs, outputs, permissions, SARIF upload, and failure behavior are
documented in [GITHUB_ACTION.md](GITHUB_ACTION.md).

## Limitations

AuthMap is static and evidence-bound. It can miss behavior that depends on
runtime values, dependency injection containers, reflection, monkey patching,
metaprogramming, generated code, framework plugins, custom routers, or code
loaded outside the scanned source tree.

Dynamic route construction can produce incomplete paths, medium-confidence
routes, or diagnostics. AuthMap reports the route facts it can support and adds
uncertainty rather than inventing a final route shape.

Dynamic authorization checks can be difficult to classify. AuthMap may emit
`unknown_dynamic_check`, `unknown_or_dynamic`, or `review_required` when a guard
is indirect or cannot be proven statically.

Custom frameworks and project-specific guard names may require configuration.
Use `authorization.rules[]` to map local helpers into canonical evidence types
and `sensitivity` rules to add project-specific review context.

Reachability linking is conservative and approximate. Direct handler mutations
and simple service calls are easier to link than dynamic dispatch, registries,
higher-order functions, decorators, or dependency-injected services. Links with
uncertainty preserve review context without proving exploitability.

False negatives are possible when AuthMap cannot discover a route, guard,
mutation, or link statically. False positives are possible when a symbol name or
source pattern resembles authorization evidence but the project uses it
differently. Treat reports as review inputs and verify important findings
against source evidence.

AuthMap does not replace human security review, threat modeling, tests, or
runtime authorization checks. It produces an authorization inventory and
evidence graph so reviewers can ask better questions.
