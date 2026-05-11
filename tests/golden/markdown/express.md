# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/express
- Source files: 4
- Routes: 12
- Evidence entries: 0
- Mutations: 0
- Diagnostics: 4
- Frameworks: express: 12

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0003](#route-route_0003) | DELETE &lt;dynamic&gt; | confidence is low; Express route path is dynamic and was emitted as &lt;dynamic&gt; |
| [route_0006](#route-route_0006) | GET /child | confidence is medium; Express mount prefix is dynamic and was not included in the route path |
| diagnostic | express_dynamic_route_path | Express route path is dynamic and could not be resolved at tests/fixtures/express/app.js:29:1 |
| diagnostic | express_cyclic_mount_router | Express mounted router cycle was ignored at tests/fixtures/express/app.js:34:1 |
| diagnostic | express_dynamic_mount_prefix | Express mount prefix is dynamic and could not be resolved at tests/fixtures/express/app.js:41:9 |
| diagnostic | express_unresolved_mount_router | Express mounted router could not be resolved statically at tests/fixtures/express/app.js:42:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | express | GET | /health | \`&lt;inline_handler&gt;\` (tests/fixtures/express/app.js:24:33) | \`requireAuth\` (tests/fixtures/express/app.js:12:10) | high | not classified | not scored |
| [route_0002](#route-route_0002) | express | POST | /accounts | \`listAccounts\` (tests/fixtures/express/app.js:20:10) | \`requireAuth\` (tests/fixtures/express/app.js:12:10), \`audit\` (tests/fixtures/express/app.js:16:10) | high | not classified | not scored |
| [route_0003](#route-route_0003) | express | DELETE | &lt;dynamic&gt; | \`listAccounts\` (tests/fixtures/express/app.js:20:10) | \`requireAuth\` (tests/fixtures/express/app.js:12:10) | low | not classified | not scored |
| [route_0004](#route-route_0004) | express | PUT | /api/:id | \`listAccounts\` (tests/fixtures/express/app.js:20:10) | \`requireAuth\` (tests/fixtures/express/app.js:12:10) | high | not classified | not scored |
| [route_0005](#route-route_0005) | express | GET | /api/nested/child | \`listAccounts\` (tests/fixtures/express/app.js:20:10) | \`audit\` (tests/fixtures/express/app.js:16:10) | high | not classified | not scored |
| [route_0006](#route-route_0006) | express | GET | /child | \`listAccounts\` (tests/fixtures/express/app.js:20:10) | \`audit\` (tests/fixtures/express/app.js:16:10) | medium | not classified | not scored |
| [route_0007](#route-route_0007) | express | GET | /admin/dashboard | \`listAdmins\` (tests/fixtures/express/routes/admin.js:9:10) | \`requireAdmin\` (tests/fixtures/express/routes/admin.js:5:10) | high | not classified | not scored |
| [route_0008](#route-route_0008) | express | PATCH | /exported/audit | \`exportAudit\` (tests/fixtures/express/routes/exported.ts:9:10) | \`audit\` (tests/fixtures/express/routes/exported.ts:5:10) | high | not classified | not scored |
| [route_0009](#route-route_0009) | express | GET | /secure/:userId | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:15:21) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | not classified | not scored |
| [route_0010](#route-route_0010) | express | GET | /v1/:userId | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:15:21) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | not classified | not scored |
| [route_0011](#route-route_0011) | express | POST | /secure/:userId | \`updateUser\` (tests/fixtures/express/routes/users.ts:9:7) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | not classified | not scored |
| [route_0012](#route-route_0012) | express | POST | /v1/:userId | \`updateUser\` (tests/fixtures/express/routes/users.ts:9:7) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | not classified | not scored |

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/health`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/app.js:24:33)
- Route location: tests/fixtures/express/app.js:24:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 POST `/accounts`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:20:10)
- Route location: tests/fixtures/express/app.js:28:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10), `audit` (tests/fixtures/express/app.js:16:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 DELETE `&lt;dynamic&gt;`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:20:10)
- Route location: tests/fixtures/express/app.js:29:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Confidence: low
- Coverage: not classified
- Uncertainty notes:
  - Express route path is dynamic and was emitted as &lt;dynamic&gt;
- Auth evidence: none
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 PUT `/api/:id`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:20:10)
- Route location: tests/fixtures/express/app.js:31:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 GET `/api/nested/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:20:10)
- Route location: tests/fixtures/express/app.js:32:1
- Middleware: `audit` (tests/fixtures/express/app.js:16:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 GET `/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:20:10)
- Route location: tests/fixtures/express/app.js:32:1
- Middleware: `audit` (tests/fixtures/express/app.js:16:10)
- Confidence: medium
- Coverage: not classified
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence: none
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 GET `/admin/dashboard`

- Framework: express
- Handler: `listAdmins` (tests/fixtures/express/routes/admin.js:9:10)
- Route location: tests/fixtures/express/routes/admin.js:13:1
- Middleware: `requireAdmin` (tests/fixtures/express/routes/admin.js:5:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 PATCH `/exported/audit`

- Framework: express
- Handler: `exportAudit` (tests/fixtures/express/routes/exported.ts:9:10)
- Route location: tests/fixtures/express/routes/exported.ts:13:1
- Middleware: `audit` (tests/fixtures/express/routes/exported.ts:5:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 GET `/secure/:userId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:15:21)
- Route location: tests/fixtures/express/routes/users.ts:13:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 GET `/v1/:userId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:15:21)
- Route location: tests/fixtures/express/routes/users.ts:13:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 POST `/secure/:userId`

- Framework: express
- Handler: `updateUser` (tests/fixtures/express/routes/users.ts:9:7)
- Route location: tests/fixtures/express/routes/users.ts:13:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 POST `/v1/:userId`

- Framework: express
- Handler: `updateUser` (tests/fixtures/express/routes/users.ts:9:7)
- Route location: tests/fixtures/express/routes/users.ts:13:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | express_dynamic_route_path | tests/fixtures/express/app.js:29:1 | Express route path is dynamic and could not be resolved |
| warning | express_cyclic_mount_router | tests/fixtures/express/app.js:34:1 | Express mounted router cycle was ignored |
| warning | express_dynamic_mount_prefix | tests/fixtures/express/app.js:41:9 | Express mount prefix is dynamic and could not be resolved |
| warning | express_unresolved_mount_router | tests/fixtures/express/app.js:42:1 | Express mounted router could not be resolved statically |

## Skipped Files

No files were skipped.