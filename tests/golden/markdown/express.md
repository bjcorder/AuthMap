# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/express
- Source files: 3
- Routes: 9
- Evidence entries: 0
- Mutations: 0
- Diagnostics: 3
- Frameworks: express: 9

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0003](#route-route_0003) | DELETE <dynamic> | confidence is low; Express route path is dynamic and was emitted as <dynamic> |
| [route_0006](#route-route_0006) | GET /child | confidence is medium; Express mount prefix is dynamic and was not included in the route path |
| diagnostic | express_dynamic_mount_prefix | Express mount prefix is dynamic and could not be resolved at tests/fixtures/express/app.js:37:9 |
| diagnostic | express_dynamic_route_path | Express route path is dynamic and could not be resolved at tests/fixtures/express/app.js:28:1 |
| diagnostic | express_unresolved_mount_router | Express mounted router could not be resolved statically at tests/fixtures/express/app.js:38:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | express | GET | /health | \`<inline_handler>\` (tests/fixtures/express/app.js:23:33) | \`requireAuth\` (tests/fixtures/express/app.js:23:20) | high | not classified | not scored |
| [route_0002](#route-route_0002) | express | POST | /accounts | \`listAccounts\` (tests/fixtures/express/app.js:27:45) | \`requireAuth\` (tests/fixtures/express/app.js:27:24), \`audit\` (tests/fixtures/express/app.js:27:37) | high | not classified | not scored |
| [route_0003](#route-route_0003) | express | DELETE | <dynamic> | \`listAccounts\` (tests/fixtures/express/app.js:28:38) | \`requireAuth\` (tests/fixtures/express/app.js:28:25) | low | not classified | not scored |
| [route_0004](#route-route_0004) | express | PUT | /api/:id | \`listAccounts\` (tests/fixtures/express/app.js:30:38) | \`requireAuth\` (tests/fixtures/express/app.js:30:25) | high | not classified | not scored |
| [route_0005](#route-route_0005) | express | GET | /api/nested/child | \`listAccounts\` (tests/fixtures/express/app.js:31:34) | \`audit\` (tests/fixtures/express/app.js:31:27) | high | not classified | not scored |
| [route_0006](#route-route_0006) | express | GET | /child | \`listAccounts\` (tests/fixtures/express/app.js:31:34) | \`audit\` (tests/fixtures/express/app.js:31:27) | medium | not classified | not scored |
| [route_0007](#route-route_0007) | express | GET | /admin/dashboard | \`listAdmins\` (tests/fixtures/express/routes/admin.js:13:40) | \`requireAdmin\` (tests/fixtures/express/routes/admin.js:13:26) | high | not classified | not scored |
| [route_0008](#route-route_0008) | express | GET | /v1/:userId | \`<inline_handler>\` (tests/fixtures/express/routes/users.ts:15:21) | \`requireUser\` (tests/fixtures/express/routes/users.ts:15:8) | high | not classified | not scored |
| [route_0009](#route-route_0009) | express | POST | /v1/:userId | \`updateUser\` (tests/fixtures/express/routes/users.ts:18:22) | \`requireUser\` (tests/fixtures/express/routes/users.ts:18:9) | high | not classified | not scored |

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/health`

- Framework: express
- Handler: `<inline_handler>` (tests/fixtures/express/app.js:23:33)
- Route location: tests/fixtures/express/app.js:23:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:23:20)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 POST `/accounts`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:27:45)
- Route location: tests/fixtures/express/app.js:27:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:27:24), `audit` (tests/fixtures/express/app.js:27:37)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 DELETE `<dynamic>`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:28:38)
- Route location: tests/fixtures/express/app.js:28:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:28:25)
- Confidence: low
- Coverage: not classified
- Uncertainty notes:
  - Express route path is dynamic and was emitted as <dynamic>
- Auth evidence: none
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 PUT `/api/:id`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:30:38)
- Route location: tests/fixtures/express/app.js:30:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:30:25)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 GET `/api/nested/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:31:34)
- Route location: tests/fixtures/express/app.js:31:1
- Middleware: `audit` (tests/fixtures/express/app.js:31:27)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 GET `/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:31:34)
- Route location: tests/fixtures/express/app.js:31:1
- Middleware: `audit` (tests/fixtures/express/app.js:31:27)
- Confidence: medium
- Coverage: not classified
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence: none
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 GET `/admin/dashboard`

- Framework: express
- Handler: `listAdmins` (tests/fixtures/express/routes/admin.js:13:40)
- Route location: tests/fixtures/express/routes/admin.js:13:1
- Middleware: `requireAdmin` (tests/fixtures/express/routes/admin.js:13:26)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 GET `/v1/:userId`

- Framework: express
- Handler: `<inline_handler>` (tests/fixtures/express/routes/users.ts:15:21)
- Route location: tests/fixtures/express/routes/users.ts:13:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:15:8)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 POST `/v1/:userId`

- Framework: express
- Handler: `updateUser` (tests/fixtures/express/routes/users.ts:18:22)
- Route location: tests/fixtures/express/routes/users.ts:13:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:18:9)
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | express_dynamic_route_path | tests/fixtures/express/app.js:28:1 | Express route path is dynamic and could not be resolved |
| warning | express_dynamic_mount_prefix | tests/fixtures/express/app.js:37:9 | Express mount prefix is dynamic and could not be resolved |
| warning | express_unresolved_mount_router | tests/fixtures/express/app.js:38:1 | Express mounted router could not be resolved statically |

## Skipped Files

No files were skipped.

