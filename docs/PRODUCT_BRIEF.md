# Product Brief: AuthMap

## One-liner

Authorization coverage mapping for application routes, handlers, service calls, and data mutations.

## Target users

- Product-security engineers
- AppSec reviewers
- Security-minded application developers
- Engineering teams preparing for audits or large refactors

## Primary job to be done

When reviewing an application or pull request, show exactly where authorization is enforced and which sensitive operations lack clear server-side protection evidence.

## Why now

Modern web applications spread authorization across middleware, decorators, controllers, service layers, ORMs, feature flags, and frontend checks. Reviewers need a consolidated, evidence-backed map rather than scattered assumptions.

## Differentiator

AuthMap is not a general SAST scanner. It is a coverage inventory and evidence graph for authorization controls. This creates a stable substrate for later policy checks and invariant analysis.

## MVP success criteria

- Scans a representative FastAPI or Express app without running it.
- Lists all discovered routes and handlers.
- Classifies auth coverage for each route.
- Finds at least one reachable data mutation per sensitive route where present.
- Produces a useful Markdown report in CI.
- Emits machine-readable JSON for downstream tools.

## Open design questions

- Should route risk be rule-based only, or should configurable sensitivity labels drive prioritization?
- How should dynamic authorization patterns be represented without creating false certainty?
- Should framework adapters emit a common IR shared with Rulepath/SIA-style tools?
