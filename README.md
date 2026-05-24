<p align="center">
  <img src="docs/assets/authmap-banner.svg" alt="AuthMap" width="640">
</p>

<p align="center"><strong>Authorization coverage mapping for application code.</strong></p>

<p align="center">
  <a href="https://github.com/Ozark-Security-Labs/AuthMap/actions/workflows/rust.yml"><img alt="CI" src="https://github.com/Ozark-Security-Labs/AuthMap/actions/workflows/rust.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/Ozark-Security-Labs/AuthMap/actions/workflows/security.yml"><img alt="Security" src="https://github.com/Ozark-Security-Labs/AuthMap/actions/workflows/security.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/Ozark-Security-Labs/AuthMap/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/Ozark-Security-Labs/AuthMap/actions/workflows/codeql.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Rust 1.95+" src="https://img.shields.io/badge/rust-1.95%2B-orange.svg">
  <a href="https://github.com/Ozark-Security-Labs/AuthMap/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/Ozark-Security-Labs/AuthMap?sort=semver&display_name=tag"></a>
</p>

---

AuthMap maps authorization coverage across the routes, handlers, service calls, and data mutations in your application. It answers a foundational appsec question — **what protects each endpoint, and the data it touches?** — by building a structured, reviewable auth map with typed evidence so missing checks, misplaced controls, and risky drift surface before they ship.

Authorization bugs are often inventory failures before they are coding failures. AuthMap gives you the inventory.

## Quickstart

Install from source:

```bash
cargo install --git https://github.com/Ozark-Security-Labs/AuthMap authmap-cli
```

Prebuilt binaries for Linux, macOS, and Windows are attached to each [GitHub Release](https://github.com/Ozark-Security-Labs/AuthMap/releases).

Then bootstrap a config and scan:

```bash
authmap init --output authmap.yml
authmap scan . --config authmap.yml --format markdown --output authmap.md
authmap routes . --config authmap.yml --format markdown --output authmap.routes.md
```

Use it in CI with the GitHub Action:

```yaml
- uses: actions/checkout@v4
- uses: Ozark-Security-Labs/AuthMap@v1.0.0
  with:
    mode: advisory
    output: markdown,json
```

## Sample output

A scan of an Express + Prisma service surfaces 15 routes, classifies each by coverage type, and flags routes that need human review:

```text
# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary
- Mode: advisory
- Routes: 15
- Evidence entries: 23
- Mutations: 4
- Frameworks: express: 15

## Route Inventory

| ID         | Method | Path                  | Middleware                         | Coverage           | Risk            |
| ---------- | ------ | --------------------- | ---------------------------------- | ------------------ | --------------- |
| route_0001 | GET    | /health               | none                               | unauthenticated    | low             |
| route_0005 | POST   | /api                  | requireAuth, audit                 | authn_only         | review_required |
| route_0007 | PATCH  | /api/:accountId       | requireAuth, requirePermission     | permission_guarded | review_required |
| route_0009 | DELETE | /api/:accountId       | requireAuth, requireAdmin          | admin_guarded      | review_required |
| route_0014 | GET    | /api/tenant/:tenantId | requireAuth, requireTenant         | tenant_guarded     | low             |
```

The same scan emits JSON for automation, including per-route coverage with linked evidence and reachable mutations:

```json
{
  "route_id": "route_0009",
  "class": "admin_guarded",
  "risk": "review_required",
  "rationale": [
    "1 strong authorization evidence item(s) support admin_guarded coverage.",
    "Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.",
    "Linked data mutation(s) increase review sensitivity."
  ],
  "extensions": {
    "authmap.coverage": {
      "evidence_ids": ["evidence_0014"],
      "mutation_ids": ["mutation_0004"],
      "link_ids": ["link_0004"],
      "sensitivity_reasons": ["account_path", "linked_mutation", "path_param", "unsafe_method"]
    }
  }
}
```

A SARIF report covering the same routes is available for GitHub code scanning.

## Supported frameworks

| Framework             | Language(s)          |
| --------------------- | -------------------- |
| FastAPI               | Python               |
| Django                | Python               |
| Django REST Framework | Python               |
| Express               | Node.js / TypeScript |
| Next.js (App Router)  | TypeScript           |
| tRPC                  | TypeScript           |
| GraphQL               | TypeScript / Node.js |

Plus ORM mutation evidence for **SQLAlchemy**, **Django ORM**, and **Prisma**, linked to the routes that can reach them.

Evidence sources include middleware, decorators, guards, policy objects, service-layer checks, ownership and tenant-isolation patterns, and ORM mutations. See [docs/PARSERS_AND_ADAPTERS.md](docs/PARSERS_AND_ADAPTERS.md) for the adapter contract.

## What you get

**Typed coverage classification.** Each route is placed into one of nine classes — `public_declared`, `unauthenticated`, `authn_only`, `role_guarded`, `permission_guarded`, `ownership_guarded`, `tenant_guarded`, `admin_guarded`, `unknown_or_dynamic` — with a risk label and a machine-readable rationale.

**Drift detection in CI.** Capture a baseline JSON document and diff future scans against it. AuthMap reports added or removed routes, evidence changes, coverage downgrades, and newly reachable mutations — with policy knobs to fail builds on specific drift categories.

```bash
authmap baseline create . --output authmap.baseline.json
authmap scan . --format json --output authmap.json
authmap diff --base authmap.baseline.json --head authmap.json --format markdown
```

**Rule suggestions.** `authmap rules suggest` is a local, read-only helper that scans for project-specific guard, role, and permission patterns and proposes additions to `authmap.yml`. It never modifies your config.

**Explainable findings.** `authmap explain <id>` resolves any route, evidence, mutation, or link ID against a generated report and prints the supporting context — useful for triage and PR review.

## Output formats

| Format   | Use it for                                                |
| -------- | --------------------------------------------------------- |
| Markdown | Human review, PR comments, GitHub Actions job summaries   |
| JSON     | Automation and downstream tooling (schema v0.1.0 contract) |
| SARIF    | GitHub / GitLab code scanning, advisory alerts            |

The canonical JSON contract is documented in [docs/SCHEMA.md](docs/SCHEMA.md) and defined by [schemas/authmap.schema.json](schemas/authmap.schema.json).

## CI integration

Run AuthMap on every pull request and gate enforcement on a baseline diff:

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
      - uses: Ozark-Security-Labs/AuthMap@v1.0.0
        with:
          mode: enforce
          output: markdown,json
          baseline: authmap.baseline.json
          fail-on: added_high_risk_route,auth_downgrade,new_linked_mutation
```

Enforce mode writes the requested reports first, then exits `20` when blocking diagnostics or baseline-drift policy matches are present. SARIF upload is optional and requires `security-events: write`. See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) for all inputs, outputs, and permission details.

### Exit codes

| Code | Meaning                                                                   |
| ---- | ------------------------------------------------------------------------- |
| 0    | Success                                                                   |
| 2    | CLI usage error                                                           |
| 10   | Target path does not exist or is unreadable                               |
| 11   | Enforce-mode target contains no supported source files                    |
| 12   | Config file cannot be read, parsed, or validated                          |
| 13   | Scan pipeline failed for another reason                                   |
| 14   | Report rendering or writing failed                                        |
| 20   | Enforce-mode diagnostic or drift policy failure (report was still written) |

## Project status

- **v1.0.0** — first stable release. Semantic versioning per [docs/RELEASES.md](docs/RELEASES.md).
- **JSON schema** — v0.1.0 contract; breaking changes ship via the documented compatibility policy.
- **Rust** — MSRV 1.95, edition 2024.
- **Platforms** — Linux, macOS, and Windows are tested in CI.

## Documentation

| Document                                                                       | Contents                                                              |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| [docs/USAGE.md](docs/USAGE.md)                                                 | End-to-end CLI usage, output interpretation, defensive-use guidance   |
| [docs/SCHEMA.md](docs/SCHEMA.md)                                               | JSON schema and contract                                              |
| [docs/JSON_CONSUMERS.md](docs/JSON_CONSUMERS.md)                               | Downstream JSON consumer contract and examples                        |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md)                                 | `authmap.yml`, custom authorization rules, sensitivity labels         |
| [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md)                                     | Diagnostic categories, stable codes, exit behavior                    |
| [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md)                                 | All Action inputs, outputs, and permissions                           |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)                                   | Layered design overview                                               |
| [docs/IMPLEMENTATION_ARCHITECTURE.md](docs/IMPLEMENTATION_ARCHITECTURE.md)     | Technical implementation patterns                                     |
| [docs/PARSERS_AND_ADAPTERS.md](docs/PARSERS_AND_ADAPTERS.md)                   | Adding new framework adapters                                         |
| [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md)                                 | Product framing and threat model                                      |
| [docs/ROADMAP.md](docs/ROADMAP.md)                                             | Future direction                                                      |
| [docs/RELEASES.md](docs/RELEASES.md)                                           | Versioning, changelog, and compatibility policy                       |
| [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md)                                   | Dependency, lockfile, and CI security policy                          |
| [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md)                                 | Report sensitivity and sharing guidance                               |

## Security

AuthMap is intended for authorized, defensive analysis of code that you own or are explicitly approved to review. Report vulnerabilities privately via GitHub Security Advisories — see [SECURITY.md](SECURITY.md).

Supply-chain posture:

- `Cargo.lock` is committed and reviewed.
- All GitHub Actions in workflows are pinned to a full commit SHA.
- CI runs `cargo audit`, GitHub dependency review, CodeQL, and dependency-determinism checks on every PR.

Details in [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).

## Contributing

Design-first contributions are welcome — new framework adapters, evidence detections, documentation, and reviewable detections.

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose and submit changes
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards
- [GOVERNANCE.md](GOVERNANCE.md) — maintainer and decision-making model
- [CHANGELOG.md](CHANGELOG.md) — what changed and when
- [SUPPORT.md](SUPPORT.md) — getting help

## Non-goals

AuthMap will not exploit authorization bugs, attack live systems, or claim vulnerabilities without evidence. It is not a replacement for human security review and does not require running the target application.

## License

AuthMap is licensed under the [MIT License](LICENSE).
