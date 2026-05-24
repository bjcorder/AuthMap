# Roadmap

## Phase 0: Repository foundation

- Product documentation
- Initial architecture notes
- Security policy
- Contribution guidelines

## Phase 1: Route inventory MVP

- FastAPI route discovery
- Express route discovery
- JSON route inventory output
- Markdown report output

## Phase 2: Authorization evidence MVP

- Middleware detection
- Decorator detection
- Common guard/policy call detection
- Coverage classification

## Phase 3: Sensitive operation linkage

- ORM mutation detection
- Route-to-service approximate call linking
- Sensitive operation labels

## Phase 4: CI integration

- GitHub Action wrapper
- PR summary
- SARIF output
- Advisory vs enforce mode

## Phase 5: Framework expansion

- Django/DRF
- Next.js
- SQLAlchemy/Django ORM/Prisma enrichment
- Baseline and diff mode

## Post-v1 folded capabilities

AuthMap folds the route, policy, tenant, diff, and control-review roadmap into
one defensive authorization map rather than separate tools. The public framing
stays simple: AuthMap maps authorization surfaces and shows how protection
changes over time.

- Route inventory and classification: focused route review, normalized params,
  declared protection metadata, adapter parity, and conservative diagnostics.
- Policy evidence: framework and project-specific guard, role, permission,
  ownership, tenant, public, audit, and dynamic-policy signals.
- Tenant and resource context: sensitivity labels and reviewer questions for
  route families and linked mutation resources.
- Diffs and controls: baseline drift reports, CI enforcement categories, SARIF,
  and advisory review priorities.
- Fixtures and documentation: small static regressions, known limitations, and
  evidence-bound usage guidance.

AuthMap remains local and non-invasive. Roadmap work must not add live
exploitation, payload generation, credential handling, or vulnerability claims
that are not supported by static evidence.

The user-facing folded model, command surface, workflow examples, limitations,
and implemented post-v1 milestone links are documented in
[CAPABILITIES.md](CAPABILITIES.md).
