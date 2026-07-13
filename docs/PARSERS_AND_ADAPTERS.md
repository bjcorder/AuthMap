# Parsers And Adapters

AuthMap adapters run on static parse output. They must not execute target
application code, import target modules, call live services, or require the
target app to start.

## Parser Strategy

AuthMap v0.1.0 uses Tree-sitter as its parser layer:

- Python (`.py`): `tree-sitter-python`
- JavaScript and JSX (`.js`, `.jsx`, `.mjs`, `.cjs`): `tree-sitter-javascript`
- TypeScript and TSX (`.ts`, `.tsx`, `.mts`, `.cts`): `tree-sitter-typescript`

Tree-sitter is a good first fit because it is local, non-executing, incremental,
and tolerant of partial syntax errors. It exposes byte ranges and source points
that map cleanly into AuthMap spans. More specialized parsers can be added later
behind the same `authmap-parsers` facade.

Unsupported languages produce a recoverable diagnostic and no parse tree. Source
read failures produce diagnostics through the scan pipeline. Syntax-error trees
produce `parser.source_parse_recovered` diagnostics while still returning the
partial tree so adapters can emit any facts they can prove.

## Span Conventions

`Span` is the canonical location type:

- `file` is the normalized path emitted by discovery.
- `line` and `column` are 1-based.
- `byte_range.start` and `byte_range.end` are 0-based UTF-8 byte offsets.
- `byte_range.end` is exclusive.

Symbol spans should point to the smallest stable symbol token when practical.
Route or source-evidence spans should point to the framework declaration, call,
decorator, or exported handler that proves the route exists.

## Adapter Contract

Framework adapters implement `FrameworkAdapter` from `authmap-adapters`.
Adapters receive an `AdapterInput` with:

- the parsed file and original source text
- optional Tree-sitter tree access
- helper methods for snippets and Tree-sitter node spans
- adapter context for future scan/config constraints

Adapters return `AdapterOutput`, which may contain:

- `routes`
- `evidence`
- `mutations`
- `diagnostics`

Adapters should emit raw facts only. They should not assign final global IDs
beyond stable local IDs for emitted facts, perform reachability linking, classify
coverage, write reports, or print terminal output. Linking, deterministic merge
order, coverage classification, and report rendering stay in later pipeline
stages.

Diagnostics are data. If an adapter can prove one route and encounters ambiguity
elsewhere, it should return the route plus a diagnostic rather than failing the
whole scan. Use `confidence`, `notes`, `extensions`, and diagnostics to make
uncertainty explicit without overstating findings.

Diagnostic categories, stable codes, and enforce-mode exit behavior are defined
in [`docs/DIAGNOSTICS.md`](DIAGNOSTICS.md).

## Fixture Expectations

New adapters should include fixtures that cover:

- one minimal positive route example
- unsupported or ambiguous syntax that still returns partial facts when possible
- diagnostics for dynamic or unsupported framework patterns
- stable spans for route declarations and security-relevant symbols
- JSON/schema compatibility through the shared AuthMap document contract

Fixture tests should avoid live services, dependency installation, network
access, and executing the target application.

## Detected Patterns And Known Limitations

Adapters are conservative: they emit a route or evidence only when a pattern is
statically recognizable, and emit diagnostics (or lower confidence) when it is
not. The notable detections and current limitations per framework:

**FastAPI** — route decorators (`get/post/put/patch/delete/options/head`),
`@app.websocket` (method `WS`), `api_route`, `APIRouter`/`include_router` with
prefix and `dependencies=`, and `Depends(...)`/`Security(...)` guards. SQLAlchemy
mutations include `session.add/delete/merge`, `session.execute(insert|update|
delete(...))`, raw SQL, and `AsyncSession` receivers. *Not yet:* `add_api_route`,
`app.add_middleware` / `@app.middleware("http")`, and `app.mount` sub-apps.

**Django / DRF** — `path`/`re_path`/legacy `url()`, `include()`, `urlpatterns =`
and `urlpatterns += [...]`, DRF routers and `@action`, CBV mixins and
`permission_classes`/`authentication_classes`, and function-based-view decorators
(`@login_required`, `@permission_required`, `@user_passes_test`,
`@staff_member_required`, `@api_view` + `@permission_classes`). Django ORM
mutations include `create/get_or_create/update_or_create/bulk_create/update/
bulk_update/delete/save`. *Not yet:* multi-line parenthesized imports,
settings-level `DEFAULT_PERMISSION_CLASSES`, `@method_decorator` on CBVs, and
per-`@action` `permission_classes` overrides.

**Express** — `app`/`router` method calls, mounted routers with prefix
composition, route-level and array middleware, route chaining, and
`options`/`head`/`all` terminal handlers. Prefix-less `router.use`/`app.use`
middleware applies to later registrations on the same receiver and propagates
through later mounts. *Not yet:* `app.param` and dynamic `app[method]` dispatch.

**Next.js** — App Router `route.ts` handlers (all export forms), Pages Router
`pages/api/**` default-export handlers, and `middleware.ts` whose `config.matcher`
covers a route (the middleware is classified by the auth helper it delegates to;
non-auth middleware leaves coverage unclaimed). *Not yet:* Server Actions
(`'use server'`, flagged via `nextjs_server_action_not_analyzed`) and
layout/page-level auth inheritance.

**tRPC** — the standard procedure builders plus any project-specific
`*Procedure`, and `query`/`mutation`/`subscription` operations. *Not yet:* `.use`
middleware chains, `mergeRouters` path composition, and `ctx`-based guards inside
handlers; tRPC routes are not yet linked to reachable mutations.

**GraphQL** — Python Graphene mutation/query classes, and JS/TS type-graphql
(`@Query`/`@Mutation`/`@Subscription` with `@Authorized`) and Apollo-style
resolver maps. *Not yet:* `graphql-shield` rules, SDL (`.graphql`)
`@auth`/`@hasRole` directives, and imperative resolver-body auth; GraphQL routes
are not yet linked to reachable mutations.

**ORM mutation evidence** — SQLAlchemy, Django ORM, and Prisma are first-class.
Sequelize, Mongoose, and TypeORM are detected for common method shapes
(capitalized-model `create`/`update`/`destroy` and repository-pattern receiver
names are reported at low confidence). Knex query-builder `insert`/`update`/
`del` chains are detected when rooted at a known Knex instance (or conservative
`knex`/`db` fallback), and Prisma transaction array/callback mutations retain a
shared transaction-group identifier. *Not yet:* transaction behavior beyond
directly analyzable Prisma client aliases.

Issue #19 defines this shared contract. It does not add FastAPI, Express,
Django/DRF, or Next.js analyzer behavior.
