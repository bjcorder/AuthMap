# Architecture

AuthMap is designed around a simple pipeline:

```text
source files
  -> framework adapters
  -> route inventory
  -> authorization evidence extraction
  -> reachability linking
  -> coverage classification
  -> reports
```

## Components

### 1. Framework adapters

Adapters discover externally reachable application entrypoints.

Initial adapters:

- FastAPI route decorators
- Django URL patterns and DRF viewsets
- Express router calls
- Next.js App Router route handlers

Adapter output should be normalized into a common route model.

### 2. Evidence extractors

Evidence extractors identify security controls on or near reachable paths.

Evidence types:

- authn
- role_check
- permission_check
- ownership_check
- tenant_check
- admin_check
- explicit_public
- audit_log
- unknown_dynamic_check

### 3. Reachability linker

The linker connects routes to handler functions, service calls, and data mutations. The MVP can use conservative static approximations. Precision can improve over time with language-specific parsers.

### 4. Coverage classifier

The classifier turns raw evidence into reviewable categories and risk levels.

Example categories:

- public_declared
- unauthenticated
- authn_only
- role_guarded
- permission_guarded
- ownership_guarded
- tenant_guarded
- admin_guarded
- unknown_or_dynamic

### 5. Reporters

Reporters should support:

- Markdown
- JSON
- SARIF
- GitHub Actions summary

## Trust boundary

AuthMap should be honest about confidence. Dynamic language behavior, reflection, metaprogramming, and custom frameworks may produce incomplete maps. Reports should expose uncertainty.

## Implementation architecture

The Rust workspace scaffold and concurrency model are documented in
[IMPLEMENTATION_ARCHITECTURE.md](IMPLEMENTATION_ARCHITECTURE.md).
