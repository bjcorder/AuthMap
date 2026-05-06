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
authmap diff main...HEAD
authmap explain ROUTE_OR_FINDING_ID
authmap baseline create
authmap rules suggest
```

## GitHub Action sketch

```yaml
name: AuthMap
on: [pull_request]

jobs:
  authmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bjcorder/AuthMap@v0
        with:
          mode: advisory
          output: markdown,sarif
```

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

This repository currently contains the initial product concept and documentation. Implementation milestones will be added next.
