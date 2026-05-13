# AuthMap Fixtures And Goldens

Run the full local regression suite with:

```sh
cargo test --workspace
```

Fixtures are intentionally small source snippets. They are scanned statically and never require live services, package installation, databases, or framework startup.
Large-repository budget behavior is covered with generated temporary projects in
the Rust tests instead of committed giant fixtures. Skipped-file auditability is
bounded by the discovery collection cap so limit tests remain deterministic
without turning omitted-file listing into another unbounded workload.

## Layout

- `fixtures/fastapi/`, `fixtures/django/`, and `fixtures/express/` are active route-inventory regression inputs.
- `fixtures/mutations/` contains active ORM/data mutation extraction coverage for Prisma, SQLAlchemy, and Django ORM.
- `fixtures/linking/` contains active route-to-mutation reachability coverage for direct handler mutations, one-hop service calls, and unresolved service-like calls.
- `fixtures/realistic/` contains compact end-to-end smoke applications that combine routers, imports, auth evidence, service calls, mutations, links, diagnostics, and coverage.
- `fixtures/negative/` contains source patterns that must not produce backend route, evidence, mutation, link, or coverage facts.
- `fixtures/pending/` contains representative snippets for future extractor work. These files are intentionally not active snapshot inputs until the matching extractor or classifier issue implements those facts.
- `golden/json/` stores normalized JSON snapshots from the full analysis pipeline.
- `golden/markdown/` stores normalized Markdown snapshots from the reporter.

## Updating Goldens

Golden files are reviewed source artifacts. When behavior intentionally changes, regenerate the affected report output with:

```sh
AUTHMAP_UPDATE_GOLDENS=1 cargo test -p authmap-testkit --test route_inventory_regression
```

Review the diff and keep only intentional changes.

Regression tests compare normalized output, including route IDs, ordering, uncertainty notes, diagnostics, evidence, mutations, links, and coverage. A changed snapshot should mean the user-visible inventory changed.

Realistic smoke goldens run in the separate `realistic_smoke_regression` test target so CI output clearly distinguishes broad integration fixture drift from smaller route-inventory regressions.
