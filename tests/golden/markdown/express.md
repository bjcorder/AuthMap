# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/express
- Source files: 5
- Routes: 26
- Evidence entries: 43
- Mutations: 0
- Diagnostics: 4
- Frameworks: express: 26

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0002](#route-route_0002) | POST /accounts | risk is review_required |
| [route_0004](#route-route_0004) | GET /{tenant}/reports | risk is review_required |
| [route_0006](#route-route_0006) | DELETE &lt;dynamic&gt; | confidence is low; Express route path is dynamic and was emitted as &lt;dynamic&gt;; risk is review_required |
| [route_0007](#route-route_0007) | PUT /api/:id | risk is review_required |
| [route_0009](#route-route_0009) | GET /child | confidence is medium; Express mount prefix is dynamic and was not included in the route path |
| [route_0020](#route-route_0020) | PATCH /exported/audit | risk is high |
| [route_0021](#route-route_0021) | GET /secure/:userId | risk is review_required |
| [route_0022](#route-route_0022) | GET /v1/:userId | risk is review_required |
| [route_0023](#route-route_0023) | POST /secure/:userId | risk is review_required |
| [route_0024](#route-route_0024) | POST /v1/:userId | risk is review_required |
| diagnostic | express_dynamic_route_path | Express route path is dynamic and could not be resolved at tests/fixtures/express/app.js:66:1 |
| diagnostic | express_cyclic_mount_router | Express mounted router cycle was ignored at tests/fixtures/express/app.js:71:1 |
| diagnostic | express_dynamic_mount_prefix | Express mount prefix is dynamic and could not be resolved at tests/fixtures/express/app.js:89:9 |
| diagnostic | express_unresolved_mount_router | Express mounted router could not be resolved statically at tests/fixtures/express/app.js:90:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | express | GET | /health | \`&lt;inline_handler&gt;\` (tests/fixtures/express/app.js:53:33) | \`requireAuth\` (tests/fixtures/express/app.js:14:10) | high | authn_only | low |
| [route_0002](#route-route_0002) | express | POST | /accounts | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:14:10), \`audit\` (tests/fixtures/express/app.js:36:10) | high | authn_only | review_required |
| [route_0003](#route-route_0003) | express | POST | /admin/jobs | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:51:19), \`requirePermission\` (tests/fixtures/express/app.js:51:32), \`requireRole\` (tests/fixtures/express/app.js:18:10) | high | permission_guarded | low |
| [route_0004](#route-route_0004) | express | GET | /{tenant}/reports | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:14:10) | high | authn_only | review_required |
| [route_0005](#route-route_0005) | express | PATCH | /accounts/:id/permissions | \`&lt;inline_handler&gt;\` (tests/fixtures/express/app.js:60:77) | \`requirePermission\` (tests/fixtures/express/app.js:27:10) | high | permission_guarded | low |
| [route_0006](#route-route_0006) | express | DELETE | &lt;dynamic&gt; | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:14:10) | low | authn_only | review_required |
| [route_0007](#route-route_0007) | express | PUT | /api/:id | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:14:10) | high | authn_only | review_required |
| [route_0008](#route-route_0008) | express | GET | /api/nested/child | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:70:28), \`audit\` (tests/fixtures/express/app.js:36:10) | high | authn_only | low |
| [route_0009](#route-route_0009) | express | GET | /child | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`audit\` (tests/fixtures/express/app.js:36:10) | medium | unauthenticated | low |
| [route_0010](#route-route_0010) | express | GET | /api/mapped/factory | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:14:10) | high | authn_only | low |
| [route_0011](#route-route_0011) | express | GET | /api/mapped/indexed | \`listAccounts\` (tests/fixtures/express/app.js:44:10) | \`requireAuth\` (tests/fixtures/express/app.js:14:10) | high | authn_only | low |
| [route_0012](#route-route_0012) | express | GET | /api/profile | \`getProfile\` (tests/fixtures/express/helpers/app.js:6:56) | \`middleware.authenticateRequest\` (tests/fixtures/express/helpers/app.js:6:1), \`requireAuth\` (tests/fixtures/express/helpers/app.js:6:42) | high | authn_only | low |
| [route_0013](#route-route_0013) | express | GET | /profile | \`getProfile\` (tests/fixtures/express/helpers/app.js:6:56) | \`middleware.authenticateRequest\` (tests/fixtures/express/helpers/app.js:6:1), \`requireAuth\` (tests/fixtures/express/helpers/app.js:6:42) | high | authn_only | low |
| [route_0014](#route-route_0014) | express | GET | /admin | \`getAdmin\` (tests/fixtures/express/helpers/app.js:7:60) | \`requireAuth\` (tests/fixtures/express/app.js:51:19), \`requirePermission\` (tests/fixtures/express/app.js:51:32), \`middleware.ensureLoggedIn\` (tests/fixtures/express/helpers/app.js:7:1), \`middleware.admin.checkPrivileges\` (tests/fixtures/express/helpers/app.js:7:1), \`requireAdmin\` (tests/fixtures/express/helpers/app.js:7:45) | high | admin_guarded | low |
| [route_0015](#route-route_0015) | express | GET | /api/admin | \`getAdmin\` (tests/fixtures/express/helpers/app.js:7:60) | \`middleware.ensureLoggedIn\` (tests/fixtures/express/helpers/app.js:7:1), \`middleware.admin.checkPrivileges\` (tests/fixtures/express/helpers/app.js:7:1), \`requireAdmin\` (tests/fixtures/express/helpers/app.js:7:45) | high | admin_guarded | low |
| [route_0016](#route-route_0016) | express | POST | /api/write | \`writeApi\` (tests/fixtures/express/helpers/app.js:8:71) | \`middleware.authenticateRequest\` (tests/fixtures/express/helpers/app.js:8:1), \`requirePermission\` (tests/fixtures/express/helpers/app.js:8:51) | high | permission_guarded | low |
| [route_0017](#route-route_0017) | express | GET | /api/direct | \`getProfile\` (tests/fixtures/express/helpers/app.js:9:47) | \`middleware.authenticateRequest\` (tests/fixtures/express/helpers/app.js:9:1), \`requireAuth\` (tests/fixtures/express/helpers/app.js:9:33) | high | authn_only | low |
| [route_0018](#route-route_0018) | express | GET | /direct | \`getProfile\` (tests/fixtures/express/helpers/app.js:9:47) | \`middleware.authenticateRequest\` (tests/fixtures/express/helpers/app.js:9:1), \`requireAuth\` (tests/fixtures/express/helpers/app.js:9:33) | high | authn_only | low |
| [route_0019](#route-route_0019) | express | GET | /admin/dashboard | \`listAdmins\` (tests/fixtures/express/routes/admin.js:9:10) | \`requireAuth\` (tests/fixtures/express/app.js:51:19), \`requirePermission\` (tests/fixtures/express/app.js:51:32), \`requireAdmin\` (tests/fixtures/express/routes/admin.js:5:10) | high | admin_guarded | low |
| [route_0020](#route-route_0020) | express | PATCH | /exported/audit | \`exportAudit\` (tests/fixtures/express/routes/exported.ts:9:10) | \`audit\` (tests/fixtures/express/routes/exported.ts:5:10) | high | unauthenticated | high |
| [route_0021](#route-route_0021) | express | GET | /secure/:userId | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:22:21) | \`requireAuth\` (tests/fixtures/express/app.js:85:20), \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0022](#route-route_0022) | express | GET | /v1/:userId | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:22:21) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0023](#route-route_0023) | express | POST | /secure/:userId | \`updateUser\` (tests/fixtures/express/routes/users.ts:16:7) | \`requireAuth\` (tests/fixtures/express/app.js:85:20), \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0024](#route-route_0024) | express | POST | /v1/:userId | \`updateUser\` (tests/fixtures/express/routes/users.ts:16:7) | \`requireUser\` (tests/fixtures/express/routes/users.ts:5:10) | high | authn_only | review_required |
| [route_0025](#route-route_0025) | express | GET | /secure/:tenantId/settings | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:27:50) | \`requireAuth\` (tests/fixtures/express/app.js:85:20), \`requireTenant\` (tests/fixtures/express/routes/users.ts:9:10) | high | tenant_guarded | low |
| [route_0026](#route-route_0026) | express | GET | /v1/:tenantId/settings | \`&lt;inline_handler&gt;\` (tests/fixtures/express/routes/users.ts:27:50) | \`requireTenant\` (tests/fixtures/express/routes/users.ts:9:10) | high | tenant_guarded | low |

## Data Mutations

No data mutations were detected.

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/health`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/app.js:53:33)
- Route location: tests/fixtures/express/app.js:53:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0001
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:14:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 POST `/accounts`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:57:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:14:10), `audit` (tests/fixtures/express/app.js:36:10)
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, unsafe_method.
- Coverage support: evidence: evidence_0002; sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:14:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 POST `/admin/jobs`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:58:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:51:19), `requirePermission` (tests/fixtures/express/app.js:51:32), `requireRole` (tests/fixtures/express/app.js:18:10)
- Declared protection: requireAuth, requirePermission, requireRole
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): admin_path, unsafe_method.
- Coverage support: evidence: evidence_0003, evidence_0004, evidence_0005; sensitivity: admin_path, unsafe_method
- Reviewer questions:
  - Should this route require an admin or role guard?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - role_check `role_guard` at tests/fixtures/express/app.js:18:10 (high)
    - Symbol: `requireRole` (tests/fixtures/express/app.js:18:10)
  - authn `authn_guard` at tests/fixtures/express/app.js:51:19 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:51:19)
  - permission_check `permission_guard` at tests/fixtures/express/app.js:51:32 (high)
    - Symbol: `requirePermission` (tests/fixtures/express/app.js:51:32)
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 GET `/{tenant}/reports`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:59:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Params: tenant (high)
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Coverage support: evidence: evidence_0006; sensitivity: path_param, tenant_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:14:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 PATCH `/accounts/:id/permissions`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/app.js:60:77)
- Route location: tests/fixtures/express/app.js:60:1
- Middleware: `requirePermission` (tests/fixtures/express/app.js:27:10)
- Params: id (high)
- Declared protection: requirePermission, dynamicPolicyCheck
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0007, evidence_0008; weak evidence: evidence_0008; sensitivity: account_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - permission_check `permission_guard` at tests/fixtures/express/app.js:27:10 (high)
    - Symbol: `requirePermission` (tests/fixtures/express/app.js:27:10)
  - unknown_dynamic_check `handler_call` at tests/fixtures/express/app.js:61:8 (low)
    - Symbol: `dynamicPolicyCheck` (tests/fixtures/express/app.js:61:8)
    - Note: Dynamic or indirect policy call requires review
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 DELETE `&lt;dynamic&gt;`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:66:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Declared protection: requireAuth
- Confidence: low
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0009; sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express route path is dynamic and was emitted as &lt;dynamic&gt;
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:14:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 PUT `/api/:id`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:68:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Params: id (high)
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method.
- Coverage support: evidence: evidence_0010; sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:14:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 GET `/api/nested/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:69:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:70:28), `audit` (tests/fixtures/express/app.js:36:10)
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0011
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:70:28 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:70:28)
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 GET `/child`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:69:1
- Middleware: `audit` (tests/fixtures/express/app.js:36:10)
- Confidence: medium
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence: none
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 GET `/api/mapped/factory`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:74:3
- Middleware: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0012
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:14:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 GET `/api/mapped/indexed`

- Framework: express
- Handler: `listAccounts` (tests/fixtures/express/app.js:44:10)
- Route location: tests/fixtures/express/app.js:79:3
- Middleware: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0013
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:14:10 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:14:10)
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 GET `/api/profile`

- Framework: express
- Handler: `getProfile` (tests/fixtures/express/helpers/app.js:6:56)
- Route location: tests/fixtures/express/helpers/app.js:6:1
- Middleware: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:6:1), `requireAuth` (tests/fixtures/express/helpers/app.js:6:42)
- Declared protection: middleware.authenticateRequest, requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0014, evidence_0015
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:6:1 (high)
    - Symbol: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:6:1)
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:6:42 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/helpers/app.js:6:42)
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 GET `/profile`

- Framework: express
- Handler: `getProfile` (tests/fixtures/express/helpers/app.js:6:56)
- Route location: tests/fixtures/express/helpers/app.js:6:1
- Middleware: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:6:1), `requireAuth` (tests/fixtures/express/helpers/app.js:6:42)
- Declared protection: middleware.authenticateRequest, requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0016, evidence_0017
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:6:1 (high)
    - Symbol: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:6:1)
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:6:42 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/helpers/app.js:6:42)
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 GET `/admin`

- Framework: express
- Handler: `getAdmin` (tests/fixtures/express/helpers/app.js:7:60)
- Route location: tests/fixtures/express/helpers/app.js:7:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:51:19), `requirePermission` (tests/fixtures/express/app.js:51:32), `middleware.ensureLoggedIn` (tests/fixtures/express/helpers/app.js:7:1), `middleware.admin.checkPrivileges` (tests/fixtures/express/helpers/app.js:7:1), `requireAdmin` (tests/fixtures/express/helpers/app.js:7:45)
- Declared protection: middleware.admin.checkPrivileges, middleware.ensureLoggedIn, requireAdmin, requireAuth, requirePermission
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 5 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): admin_path.
- Coverage support: evidence: evidence_0018, evidence_0019, evidence_0020, evidence_0021, evidence_0022; sensitivity: admin_path
- Reviewer questions:
  - Should this route require an admin or role guard?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:51:19 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:51:19)
  - permission_check `permission_guard` at tests/fixtures/express/app.js:51:32 (high)
    - Symbol: `requirePermission` (tests/fixtures/express/app.js:51:32)
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:7:1 (high)
    - Symbol: `middleware.ensureLoggedIn` (tests/fixtures/express/helpers/app.js:7:1)
  - permission_check `permission_guard` at tests/fixtures/express/helpers/app.js:7:1 (high)
    - Symbol: `middleware.admin.checkPrivileges` (tests/fixtures/express/helpers/app.js:7:1)
  - admin_check `admin_guard` at tests/fixtures/express/helpers/app.js:7:45 (high)
    - Symbol: `requireAdmin` (tests/fixtures/express/helpers/app.js:7:45)
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 GET `/api/admin`

- Framework: express
- Handler: `getAdmin` (tests/fixtures/express/helpers/app.js:7:60)
- Route location: tests/fixtures/express/helpers/app.js:7:1
- Middleware: `middleware.ensureLoggedIn` (tests/fixtures/express/helpers/app.js:7:1), `middleware.admin.checkPrivileges` (tests/fixtures/express/helpers/app.js:7:1), `requireAdmin` (tests/fixtures/express/helpers/app.js:7:45)
- Declared protection: middleware.admin.checkPrivileges, middleware.ensureLoggedIn, requireAdmin
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): admin_path.
- Coverage support: evidence: evidence_0023, evidence_0024, evidence_0025; sensitivity: admin_path
- Reviewer questions:
  - Should this route require an admin or role guard?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:7:1 (high)
    - Symbol: `middleware.ensureLoggedIn` (tests/fixtures/express/helpers/app.js:7:1)
  - permission_check `permission_guard` at tests/fixtures/express/helpers/app.js:7:1 (high)
    - Symbol: `middleware.admin.checkPrivileges` (tests/fixtures/express/helpers/app.js:7:1)
  - admin_check `admin_guard` at tests/fixtures/express/helpers/app.js:7:45 (high)
    - Symbol: `requireAdmin` (tests/fixtures/express/helpers/app.js:7:45)
- Data mutations: none

<a id="route-route_0016"></a>
### route_0016 POST `/api/write`

- Framework: express
- Handler: `writeApi` (tests/fixtures/express/helpers/app.js:8:71)
- Route location: tests/fixtures/express/helpers/app.js:8:1
- Middleware: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:8:1), `requirePermission` (tests/fixtures/express/helpers/app.js:8:51)
- Declared protection: middleware.authenticateRequest, requirePermission
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0026, evidence_0027; sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:8:1 (high)
    - Symbol: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:8:1)
  - permission_check `permission_guard` at tests/fixtures/express/helpers/app.js:8:51 (high)
    - Symbol: `requirePermission` (tests/fixtures/express/helpers/app.js:8:51)
- Data mutations: none

<a id="route-route_0017"></a>
### route_0017 GET `/api/direct`

- Framework: express
- Handler: `getProfile` (tests/fixtures/express/helpers/app.js:9:47)
- Route location: tests/fixtures/express/helpers/app.js:9:1
- Middleware: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:9:1), `requireAuth` (tests/fixtures/express/helpers/app.js:9:33)
- Declared protection: middleware.authenticateRequest, requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0028, evidence_0029
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:9:1 (high)
    - Symbol: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:9:1)
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:9:33 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/helpers/app.js:9:33)
- Data mutations: none

<a id="route-route_0018"></a>
### route_0018 GET `/direct`

- Framework: express
- Handler: `getProfile` (tests/fixtures/express/helpers/app.js:9:47)
- Route location: tests/fixtures/express/helpers/app.js:9:1
- Middleware: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:9:1), `requireAuth` (tests/fixtures/express/helpers/app.js:9:33)
- Declared protection: middleware.authenticateRequest, requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0030, evidence_0031
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:9:1 (high)
    - Symbol: `middleware.authenticateRequest` (tests/fixtures/express/helpers/app.js:9:1)
  - authn `authn_guard` at tests/fixtures/express/helpers/app.js:9:33 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/helpers/app.js:9:33)
- Data mutations: none

<a id="route-route_0019"></a>
### route_0019 GET `/admin/dashboard`

- Framework: express
- Handler: `listAdmins` (tests/fixtures/express/routes/admin.js:9:10)
- Route location: tests/fixtures/express/routes/admin.js:13:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:51:19), `requirePermission` (tests/fixtures/express/app.js:51:32), `requireAdmin` (tests/fixtures/express/routes/admin.js:5:10)
- Declared protection: requireAdmin, requireAuth, requirePermission
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): admin_path.
- Coverage support: evidence: evidence_0032, evidence_0033, evidence_0034; sensitivity: admin_path
- Reviewer questions:
  - Should this route require an admin or role guard?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:51:19 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:51:19)
  - permission_check `permission_guard` at tests/fixtures/express/app.js:51:32 (high)
    - Symbol: `requirePermission` (tests/fixtures/express/app.js:51:32)
  - admin_check `admin_guard` at tests/fixtures/express/routes/admin.js:5:10 (high)
    - Symbol: `requireAdmin` (tests/fixtures/express/routes/admin.js:5:10)
- Data mutations: none

<a id="route-route_0020"></a>
### route_0020 PATCH `/exported/audit`

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

<a id="route-route_0021"></a>
### route_0021 GET `/secure/:userId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:22:21)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:85:20), `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Params: userId (high)
- Declared protection: requireUser, requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: evidence: evidence_0035, evidence_0036; sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:85:20 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:85:20)
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0022"></a>
### route_0022 GET `/v1/:userId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:22:21)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Params: userId (high)
- Declared protection: requireUser
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: evidence: evidence_0037; sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0023"></a>
### route_0023 POST `/secure/:userId`

- Framework: express
- Handler: `updateUser` (tests/fixtures/express/routes/users.ts:16:7)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:85:20), `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Params: userId (high)
- Declared protection: requireUser, requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method, user_path.
- Coverage support: evidence: evidence_0038, evidence_0039; sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:85:20 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:85:20)
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0024"></a>
### route_0024 POST `/v1/:userId`

- Framework: express
- Handler: `updateUser` (tests/fixtures/express/routes/users.ts:16:7)
- Route location: tests/fixtures/express/routes/users.ts:20:1
- Middleware: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Params: userId (high)
- Declared protection: requireUser
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method, user_path.
- Coverage support: evidence: evidence_0040; sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/routes/users.ts:5:10 (high)
    - Symbol: `requireUser` (tests/fixtures/express/routes/users.ts:5:10)
- Data mutations: none

<a id="route-route_0025"></a>
### route_0025 GET `/secure/:tenantId/settings`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:27:50)
- Route location: tests/fixtures/express/routes/users.ts:27:1
- Middleware: `requireAuth` (tests/fixtures/express/app.js:85:20), `requireTenant` (tests/fixtures/express/routes/users.ts:9:10)
- Params: tenantId (high)
- Declared protection: requireTenant, requireAuth
- Confidence: high
- Coverage: tenant_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Coverage support: evidence: evidence_0041, evidence_0042; sensitivity: path_param, tenant_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/express/app.js:85:20 (high)
    - Symbol: `requireAuth` (tests/fixtures/express/app.js:85:20)
  - tenant_check `tenant_guard` at tests/fixtures/express/routes/users.ts:9:10 (high)
    - Symbol: `requireTenant` (tests/fixtures/express/routes/users.ts:9:10)
- Data mutations: none

<a id="route-route_0026"></a>
### route_0026 GET `/v1/:tenantId/settings`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/express/routes/users.ts:27:50)
- Route location: tests/fixtures/express/routes/users.ts:27:1
- Middleware: `requireTenant` (tests/fixtures/express/routes/users.ts:9:10)
- Params: tenantId (high)
- Declared protection: requireTenant
- Confidence: high
- Coverage: tenant_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Coverage support: evidence: evidence_0043; sensitivity: path_param, tenant_path
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
| warning | express_dynamic_route_path | tests/fixtures/express/app.js:66:1 | Express route path is dynamic and could not be resolved |
| warning | express_cyclic_mount_router | tests/fixtures/express/app.js:71:1 | Express mounted router cycle was ignored |
| warning | express_dynamic_mount_prefix | tests/fixtures/express/app.js:89:9 | Express mount prefix is dynamic and could not be resolved |
| warning | express_unresolved_mount_router | tests/fixtures/express/app.js:90:1 | Express mounted router could not be resolved statically |

## Skipped Files

No files were skipped.