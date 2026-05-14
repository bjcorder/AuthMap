# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/express
- Source files: 4
- Routes: 16
- Evidence entries: 19
- Mutations: 0
- Diagnostics: 4
- Frameworks: express: 16

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0002](#route-route_0002) | POST /accounts | risk is review_required |
| [route_0005](#route-route_0005) | DELETE &lt;dynamic&gt; | confidence is low; Express route path is dynamic and was emitted as &lt;dynamic&gt;; risk is review_required |
| [route_0006](#route-route_0006) | PUT /api/:id | risk is review_required |
| [route_0008](#route-route_0008) | GET /child | confidence is medium; Express mount prefix is dynamic and was not included in the route path |
| [route_0010](#route-route_0010) | PATCH /exported/audit | risk is high |
| [route_0011](#route-route_0011) | GET /secure/:userId | risk is review_required |
| [route_0012](#route-route_0012) | GET /v1/:userId | risk is review_required |
| [route_0013](#route-route_0013) | POST /secure/:userId | risk is review_required |
| [route_0014](#route-route_0014) | POST /v1/:userId | risk is review_required |
| diagnostic | express_dynamic_route_path | Express route path is dynamic and could not be resolved at tests/fixtures/express/app.js:58:1 |
| diagnostic | express_cyclic_mount_router | Express mounted router cycle was ignored at tests/fixtures/express/app.js:63:1 |
| diagnostic | express_dynamic_mount_prefix | Express mount prefix is dynamic and could not be resolved at tests/fixtures/express/app.js:70:9 |
| diagnostic | express_unresolved_mount_router | Express mounted router could not be resolved statically at tests/fixtures/express/app.js:71:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | express | GET | /health | \`&lt;inline_handler&gt;\` (tests/fixtures/express/app.js:46:33) | \`requireAuth\` (tests/fixtures/express/app.js:12:10) | high | authn_only | low |
| [route_0002](#route-route_0002) | express | POST | /accounts | \`listAccounts\` (tests/fixtures/express/app.js:42:10) | \`requireAuth\` (tests/fixtures/express/app.js:12:10), \`audit\` (tests/fixtures/express/app.js:34:10) | high | authn_only | review_required |
| [route_0003](#route-route_0003) | express | POST | /admin/jobs | \`listAccounts\` (tests/fixtures/express/app.js:42:10) | \`requireAuth\` (tests/fixtures/express/app.js:12:10), \`requireRole\` (tests/fixtures/express/app.js:16:10) | high | role_guarded | low |
| [route_0004](#route-route_0004) | express | PATCH | /accounts/:id/permissions | \`&lt;inline_handler&gt;\` (tests/fixtures/express/app.js:52:77) | \`requirePermission\` (tests/fixtures/express/app.js:25:10) | high | permission_guarded | low |
| [route_0005](#route-route_0005) | express | DELETE | &lt;dynamic&gt; | \`listAccounts\` (tests/fixtures/express/app.js:42:10) | \`requireAuth\` (tests/fixtures/express/app.js:12:10) | low | authn_only | review_required |
| [route_0006](#route-route_0006) | express | PUT | /api/:id | \`listAccounts\` (tests/fixtures/express/app.js:42:10) | \`requireAuth\` (tests/fixtures/express/app.js:12:10) | high | authn_only | review_required |
| [route_0007](#route-route_0007) | express | GET | /api/nested/child | \`listAccounts\` (tests/fixtures/express/app.js:42:10) | \`requireAuth\` (tests/fixtures/express/app.js:62:28), \`audit\` (tests/fixtures/express/app.js:34:10) | high | authn_only | low |
| [route_0008](#route-route_0008) | express | GET | /child | \`listAccounts\` (tests/fixtures/express/app.js:42:10) | \`audit\` (tests/fixtures/express/app.js:34:10) | medium | unauthenticated | low |
| [route_0009](#route-route_0009) | express | GET | /admin/dashboard | \`listAdmins\` (tests/fixtures/express/routes/admin.js:9:10) | \`requireAdmin\` (tests/fixtures/express/routes/admin.js:5:10) | high | admin_guarded | low |
| [route_0010](#route-route_0010) | express | PATCH | /exported/audit | \`exportAudit\` (tests/fixtures/express/routes/exported.ts:9:10) | \`audit\` (tests/fixtures/express/routes/exported.ts:5:10) | high | unauthenticated | high |
| [route_0011](#route-route_0011) | express | GET | /secure/:userId | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:22:21) | \`requireAuth\` (tests/fixtures/express/app.js:66:20), \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0012](#route-route_0012) | express | GET | /v1/:userId | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:22:21) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0013](#route-route_0013) | express | POST | /secure/:userId | \`updateUser\` (tests/fixtures/express/routes/users.ts:16:7) | \`requireAuth\` (tests/fixtures/express/app.js:66:20), \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0014](#route-route_0014) | express | POST | /v1/:userId | \`updateUser\` (tests/fixtures/express/routes/users.ts:16:7) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0015](#route-route_0015) | express | GET | /secure/:tenantId/settings | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:27:50) | \`requireAuth\` (tests/fixtures/express/app.js:66:20), \`requireTenant\` (tests/fixtures/express/routes/users.ts:9:10) | high | tenant_guarded | low |
| [route_0016](#route-route_0016) | express | GET | /v1/:tenantId/settings | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:27:50) | \`requireTenant\` (tests/fixtures/express/routes/users.ts:9:10) | high | tenant_guarded | low |

## Data Mutations

No data mutations were detected.

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/health`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/app.js:46:33)
- Route location: tests/fixtures/express/app.js:46:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0001
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:12:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 POST `/accounts`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:42:10)
- Route location: tests/fixtures/express/app.js:50:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10), `audit` (tests/fixtures/express/app.js:34:10)
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, unsafe_method.
- Coverage support: evidence: evidence_0002; sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:12:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 POST `/admin/jobs`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:42:10)
- Route location: tests/fixtures/express/app.js:51:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10), `requireRole` (tests/fixtures/express/app.js:16:10)
- Confidence: high
- Coverage: role_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support role_guarded coverage.; Sensitive route modifier(s): admin_path, unsafe_method.
- Coverage support: evidence: evidence_0003, evidence_0004; sensitivity: admin_path, unsafe_method
- Reviewer questions:
  - Should this route require an admin or role guard?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:12:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:12:10)
  - role_check `role_guard` at tests/fixtures/express/app.js:16:10 (high)
    - Symbol: `requireRole` (tests/fixtures/express/app.js:16:10)
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 PATCH `/accounts/:id/permissions`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/app.js:52:77)
- Route location: tests/fixtures/express/app.js:52:1
- Middleware: `requirePermission` (tests/fixtures/express/app.js:25:10)
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0005, evidence_0006; weak evidence: evidence_0006; sensitivity: account_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - permission_check `permission_guard` at tests/fixtures/express/app.js:25:10 (high)
    - Symbol: `requirePermission` (tests/fixtures/express/app.js:25:10)
  - unknown_dynamic_check `handler_call` at tests/fixtures/express/app.js:53:8 (low)
    - Symbol: `dynamicPolicyCheck` (tests/fixtures/express/app.js:53:8)
    - Note: Dynamic or indirect policy call requires review
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 DELETE `&lt;dynamic&gt;`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:42:10)
- Route location: tests/fixtures/express/app.js:58:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Confidence: low
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0007; sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express route path is dynamic and was emitted as &lt;dynamic&gt;
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:12:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 PUT `/api/:id`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:42:10)
- Route location: tests/fixtures/express/app.js:60:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method.
- Coverage support: evidence: evidence_0008; sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:12:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:12:10)
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 GET `/api/nested/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:42:10)
- Route location: tests/fixtures/express/app.js:61:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:62:28), `audit` (tests/fixtures/express/app.js:34:10)
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0009
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:62:28 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:62:28)
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 GET `/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:42:10)
- Route location: tests/fixtures/express/app.js:61:1
- Middleware: `audit` (tests/fixtures/express/app.js:34:10)
- Confidence: medium
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 GET `/admin/dashboard`

- Framework: express
- Handler: `listAdmins` (tests/fixtures/express/routes/admin.js:9:10)
- Route location: tests/fixtures/express/routes/admin.js:13:1
- Middleware: `requireAdmin` (tests/fixtures/express/routes/admin.js:5:10)
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): admin_path.
- Coverage support: evidence: evidence_0010; sensitivity: admin_path
- Reviewer questions:
  - Should this route require an admin or role guard?
- Auth evidence:
  - admin_check `admin_guard` at tests/fixtures/express/routes/admin.js:5:10 (high)
    - Symbol: `requireAdmin` (tests/fixtures/express/routes/admin.js:5:10)
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 PATCH `/exported/audit`

- Framework: express
- Handler: `exportAudit` (tests/fixtures/express/routes/exported.ts:9:10)
- Route location: tests/fixtures/express/routes/exported.ts:13:1
- Middleware: `audit` (tests/fixtures/express/routes/exported.ts:5:10)
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 GET `/secure/:userId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:22:21)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:66:20), `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: evidence: evidence_0011, evidence_0012; sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:66:20 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:66:20)
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 GET `/v1/:userId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:22:21)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: evidence: evidence_0013; sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 POST `/secure/:userId`

- Framework: express
- Handler: `updateUser` (tests/fixtures/express/routes/users.ts:16:7)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:66:20), `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method, user_path.
- Coverage support: evidence: evidence_0014, evidence_0015; sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:66:20 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:66:20)
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 POST `/v1/:userId`

- Framework: express
- Handler: `updateUser` (tests/fixtures/express/routes/users.ts:16:7)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method, user_path.
- Coverage support: evidence: evidence_0016; sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 GET `/secure/:tenantId/settings`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:27:50)
- Route location: tests/fixtures/express/routes/users.ts:27:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:66:20), `requireTenant` (tests/fixtures/express/routes/users.ts:9:10)
- Confidence: high
- Coverage: tenant_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Coverage support: evidence: evidence_0017, evidence_0018; sensitivity: path_param, tenant_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:66:20 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:66:20)
  - tenant_check `tenant_guard` at tests/fixtures/express/routes/users.ts:9:10 (high)
    - Symbol: `requireTenant` (tests/fixtures/express/routes/users.ts:9:10)
- Data mutations: none

<a id="route-route_0016"></a>
### route_0016 GET `/v1/:tenantId/settings`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:27:50)
- Route location: tests/fixtures/express/routes/users.ts:27:1
- Middleware: `requireTenant` (tests/fixtures/express/routes/users.ts:9:10)
- Confidence: high
- Coverage: tenant_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Coverage support: evidence: evidence_0019; sensitivity: path_param, tenant_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Auth evidence:
  - tenant_check `tenant_guard` at tests/fixtures/express/routes/users.ts:9:10 (high)
    - Symbol: `requireTenant` (tests/fixtures/express/routes/users.ts:9:10)
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | express_dynamic_route_path | tests/fixtures/express/app.js:58:1 | Express route path is dynamic and could not be resolved |
| warning | express_cyclic_mount_router | tests/fixtures/express/app.js:63:1 | Express mounted router cycle was ignored |
| warning | express_dynamic_mount_prefix | tests/fixtures/express/app.js:70:9 | Express mount prefix is dynamic and could not be resolved |
| warning | express_unresolved_mount_router | tests/fixtures/express/app.js:71:1 | Express mounted router could not be resolved statically |

## Skipped Files

No files were skipped.