# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/realistic/express
- Source files: 3
- Routes: 15
- Evidence entries: 23
- Mutations: 4
- Diagnostics: 2
- Frameworks: express: 15

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0002](#route-route_0002) | GET /:accountId | confidence is medium; Express mount prefix is dynamic and was not included in the route path; risk is review_required |
| [route_0003](#route-route_0003) | GET /api/:accountId | risk is review_required |
| [route_0004](#route-route_0004) | POST / | confidence is medium; Express mount prefix is dynamic and was not included in the route path; risk is review_required |
| [route_0005](#route-route_0005) | POST /api | risk is review_required |
| [route_0006](#route-route_0006) | PATCH /:accountId | confidence is medium; Express mount prefix is dynamic and was not included in the route path; risk is review_required |
| [route_0007](#route-route_0007) | PATCH /api/:accountId | risk is review_required |
| [route_0008](#route-route_0008) | DELETE /:accountId | confidence is medium; Express mount prefix is dynamic and was not included in the route path; risk is review_required |
| [route_0009](#route-route_0009) | DELETE /api/:accountId | risk is review_required |
| [route_0010](#route-route_0010) | POST /api/service | risk is review_required |
| [route_0011](#route-route_0011) | POST /service | confidence is medium; Express mount prefix is dynamic and was not included in the route path; risk is review_required |
| [route_0012](#route-route_0012) | POST /api/dynamic-service | risk is review_required |
| [route_0013](#route-route_0013) | POST /dynamic-service | confidence is medium; Express mount prefix is dynamic and was not included in the route path; risk is review_required |
| [route_0015](#route-route_0015) | GET /tenant/:tenantId | confidence is medium; Express mount prefix is dynamic and was not included in the route path |
| diagnostic | express_dynamic_mount_prefix | Express mount prefix is dynamic and could not be resolved at tests/fixtures/realistic/express/app.ts:43:9 |
| diagnostic | express_unresolved_mount_router | Express mounted router could not be resolved statically at tests/fixtures/realistic/express/app.ts:44:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | express | GET | /health | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/app.ts:38:20) | none | high | unauthenticated | low |
| [route_0002](#route-route_0002) | express | GET | /:accountId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:13:40) | \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:13:27) | medium | authn_only | review_required |
| [route_0003](#route-route_0003) | express | GET | /api/:accountId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:13:40) | \`requireAuth\` (tests/fixtures/realistic/express/app.ts:42:17), \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:13:27) | high | authn_only | review_required |
| [route_0004](#route-route_0004) | express | POST | / | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:17:38) | \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:17:18), \`audit\` (tests/fixtures/realistic/express/routes/accounts.ts:17:31) | medium | authn_only | review_required |
| [route_0005](#route-route_0005) | express | POST | /api | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:17:38) | \`requireAuth\` (tests/fixtures/realistic/express/app.ts:42:17), \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:17:18), \`audit\` (tests/fixtures/realistic/express/routes/accounts.ts:17:31) | high | authn_only | review_required |
| [route_0006](#route-route_0006) | express | PATCH | /:accountId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:27:3) | \`requirePermission\` (tests/fixtures/realistic/express/routes/accounts.ts:26:3) | medium | permission_guarded | review_required |
| [route_0007](#route-route_0007) | express | PATCH | /api/:accountId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:27:3) | \`requireAuth\` (tests/fixtures/realistic/express/app.ts:42:17), \`requirePermission\` (tests/fixtures/realistic/express/routes/accounts.ts:26:3) | high | permission_guarded | review_required |
| [route_0008](#route-route_0008) | express | DELETE | /:accountId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:36:44) | \`requireAdmin\` (tests/fixtures/realistic/express/routes/accounts.ts:36:30) | medium | admin_guarded | review_required |
| [route_0009](#route-route_0009) | express | DELETE | /api/:accountId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:36:44) | \`requireAuth\` (tests/fixtures/realistic/express/app.ts:42:17), \`requireAdmin\` (tests/fixtures/realistic/express/routes/accounts.ts:36:30) | high | admin_guarded | review_required |
| [route_0010](#route-route_0010) | express | POST | /api/service | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:41:38) | \`requireAuth\` (tests/fixtures/realistic/express/app.ts:42:17), \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:41:25) | high | authn_only | review_required |
| [route_0011](#route-route_0011) | express | POST | /service | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:41:38) | \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:41:25) | medium | authn_only | review_required |
| [route_0012](#route-route_0012) | express | POST | /api/dynamic-service | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:46:46) | \`requireAuth\` (tests/fixtures/realistic/express/app.ts:42:17), \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:46:33) | high | authn_only | review_required |
| [route_0013](#route-route_0013) | express | POST | /dynamic-service | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:46:46) | \`requireAuth\` (tests/fixtures/realistic/express/routes/accounts.ts:46:33) | medium | authn_only | review_required |
| [route_0014](#route-route_0014) | express | GET | /api/tenant/:tenantId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:50:48) | \`requireAuth\` (tests/fixtures/realistic/express/app.ts:42:17), \`requireTenant\` (tests/fixtures/realistic/express/routes/accounts.ts:50:33) | high | tenant_guarded | low |
| [route_0015](#route-route_0015) | express | GET | /tenant/:tenantId | \`&lt;inline_handler&gt;\` (tests/fixtures/realistic/express/routes/accounts.ts:50:48) | \`requireTenant\` (tests/fixtures/realistic/express/routes/accounts.ts:50:33) | medium | tenant_guarded | low |

## Data Mutations

| ID | Operation | Library | Resource | Location | Confidence | Review |
| --- | --- | --- | --- | --- | --- | --- |
| mutation_0001 | create | prisma | account | tests/fixtures/realistic/express/routes/accounts.ts:18:9 | high | none |
| mutation_0002 | create | prisma | account | tests/fixtures/realistic/express/services/accounts.ts:6:10 | high | none |
| mutation_0003 | update | prisma | account | tests/fixtures/realistic/express/services/accounts.ts:12:10 | high | none |
| mutation_0004 | delete | prisma | account | tests/fixtures/realistic/express/services/accounts.ts:19:10 | high | none |

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/health`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/app.ts:38:20)
- Route location: tests/fixtures/realistic/express/app.ts:38:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 GET `/:accountId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:13:40)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:13:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:13:27)
- Params: accountId (high)
- Declared protection: requireAuth
- Confidence: medium
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: evidence: evidence_0001; sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:13:27 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:13:27)
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 GET `/api/:accountId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:13:40)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:13:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17), `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:13:27)
- Params: accountId (high)
- Declared protection: requireAuth, requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: evidence: evidence_0002, evidence_0003; sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/app.ts:42:17 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17)
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:13:27 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:13:27)
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 POST `/`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:17:38)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:17:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:17:18), `audit` (tests/fixtures/realistic/express/routes/accounts.ts:17:31)
- Declared protection: audit, requireAuth
- Confidence: medium
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0004; mutations: mutation_0001; links: link_0001; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:17:18 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:17:18)
- Data mutations:
  - create `account` via `prisma` at tests/fixtures/realistic/express/routes/accounts.ts:18:9 (high)

<a id="route-route_0005"></a>
### route_0005 POST `/api`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:17:38)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:17:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17), `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:17:18), `audit` (tests/fixtures/realistic/express/routes/accounts.ts:17:31)
- Declared protection: audit, requireAuth, requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0005, evidence_0006; mutations: mutation_0001; links: link_0002; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/app.ts:42:17 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17)
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:17:18 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:17:18)
- Data mutations:
  - create `account` via `prisma` at tests/fixtures/realistic/express/routes/accounts.ts:18:9 (high)

<a id="route-route_0006"></a>
### route_0006 PATCH `/:accountId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:27:3)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:24:1
- Middleware: `requirePermission` (tests/fixtures/realistic/express/routes/accounts.ts:26:3)
- Params: accountId (high)
- Declared protection: requirePermission, dynamicPolicyCheck
- Confidence: medium
- Coverage: permission_guarded (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0007, evidence_0008; weak evidence: evidence_0008; mutations: mutation_0003; links: link_0003; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence:
  - permission_check `permission_guard` at tests/fixtures/realistic/express/routes/accounts.ts:26:3 (high)
    - Symbol: `requirePermission` (tests/fixtures/realistic/express/routes/accounts.ts:26:3)
  - unknown_dynamic_check `handler_call` at tests/fixtures/realistic/express/routes/accounts.ts:28:10 (low)
    - Symbol: `dynamicPolicyCheck` (tests/fixtures/realistic/express/routes/accounts.ts:28:10)
    - Note: Dynamic or indirect policy call requires review
- Data mutations:
  - update `account` via `prisma` at tests/fixtures/realistic/express/services/accounts.ts:12:10 (high)

<a id="route-route_0007"></a>
### route_0007 PATCH `/api/:accountId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:27:3)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:24:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17), `requirePermission` (tests/fixtures/realistic/express/routes/accounts.ts:26:3)
- Params: accountId (high)
- Declared protection: requirePermission, requireAuth, dynamicPolicyCheck
- Confidence: high
- Coverage: permission_guarded (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0009, evidence_0010, evidence_0011; weak evidence: evidence_0011; mutations: mutation_0003; links: link_0004; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/app.ts:42:17 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17)
  - permission_check `permission_guard` at tests/fixtures/realistic/express/routes/accounts.ts:26:3 (high)
    - Symbol: `requirePermission` (tests/fixtures/realistic/express/routes/accounts.ts:26:3)
  - unknown_dynamic_check `handler_call` at tests/fixtures/realistic/express/routes/accounts.ts:28:10 (low)
    - Symbol: `dynamicPolicyCheck` (tests/fixtures/realistic/express/routes/accounts.ts:28:10)
    - Note: Dynamic or indirect policy call requires review
- Data mutations:
  - update `account` via `prisma` at tests/fixtures/realistic/express/services/accounts.ts:12:10 (high)

<a id="route-route_0008"></a>
### route_0008 DELETE `/:accountId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:36:44)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:36:1
- Middleware: `requireAdmin` (tests/fixtures/realistic/express/routes/accounts.ts:36:30)
- Params: accountId (high)
- Declared protection: requireAdmin
- Confidence: medium
- Coverage: admin_guarded (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0012; mutations: mutation_0004; links: link_0005; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence:
  - admin_check `admin_guard` at tests/fixtures/realistic/express/routes/accounts.ts:36:30 (high)
    - Symbol: `requireAdmin` (tests/fixtures/realistic/express/routes/accounts.ts:36:30)
- Data mutations:
  - delete `account` via `prisma` at tests/fixtures/realistic/express/services/accounts.ts:19:10 (high)

<a id="route-route_0009"></a>
### route_0009 DELETE `/api/:accountId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:36:44)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:36:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17), `requireAdmin` (tests/fixtures/realistic/express/routes/accounts.ts:36:30)
- Params: accountId (high)
- Declared protection: requireAdmin, requireAuth
- Confidence: high
- Coverage: admin_guarded (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0013, evidence_0014; mutations: mutation_0004; links: link_0006; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/app.ts:42:17 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17)
  - admin_check `admin_guard` at tests/fixtures/realistic/express/routes/accounts.ts:36:30 (high)
    - Symbol: `requireAdmin` (tests/fixtures/realistic/express/routes/accounts.ts:36:30)
- Data mutations:
  - delete `account` via `prisma` at tests/fixtures/realistic/express/services/accounts.ts:19:10 (high)

<a id="route-route_0010"></a>
### route_0010 POST `/api/service`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:41:38)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:41:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17), `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:41:25)
- Declared protection: requireAuth, requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0015, evidence_0016; mutations: mutation_0002; links: link_0007; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/app.ts:42:17 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17)
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:41:25 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:41:25)
- Data mutations:
  - create `account` via `prisma` at tests/fixtures/realistic/express/services/accounts.ts:6:10 (high)

<a id="route-route_0011"></a>
### route_0011 POST `/service`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:41:38)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:41:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:41:25)
- Declared protection: requireAuth
- Confidence: medium
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0017; mutations: mutation_0002; links: link_0008; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:41:25 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:41:25)
- Data mutations:
  - create `account` via `prisma` at tests/fixtures/realistic/express/services/accounts.ts:6:10 (high)

<a id="route-route_0012"></a>
### route_0012 POST `/api/dynamic-service`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:46:46)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:46:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17), `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:46:33)
- Declared protection: requireAuth, requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0018, evidence_0019; links: link_0009; sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/app.ts:42:17 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17)
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:46:33 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:46:33)
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 POST `/dynamic-service`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:46:46)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:46:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:46:33)
- Declared protection: requireAuth
- Confidence: medium
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0020; links: link_0010; sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/routes/accounts.ts:46:33 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/routes/accounts.ts:46:33)
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 GET `/api/tenant/:tenantId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:50:48)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:50:1
- Middleware: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17), `requireTenant` (tests/fixtures/realistic/express/routes/accounts.ts:50:33)
- Params: tenantId (high)
- Declared protection: requireTenant, requireAuth
- Confidence: high
- Coverage: tenant_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Coverage support: evidence: evidence_0021, evidence_0022; sensitivity: path_param, tenant_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/express/app.ts:42:17 (high)
    - Symbol: `requireAuth` (tests/fixtures/realistic/express/app.ts:42:17)
  - tenant_check `tenant_guard` at tests/fixtures/realistic/express/routes/accounts.ts:50:33 (high)
    - Symbol: `requireTenant` (tests/fixtures/realistic/express/routes/accounts.ts:50:33)
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 GET `/tenant/:tenantId`

- Framework: express
- Handler: `&lt;inline_handler&gt;` (tests/fixtures/realistic/express/routes/accounts.ts:50:48)
- Route location: tests/fixtures/realistic/express/routes/accounts.ts:50:1
- Middleware: `requireTenant` (tests/fixtures/realistic/express/routes/accounts.ts:50:33)
- Params: tenantId (high)
- Declared protection: requireTenant
- Confidence: medium
- Coverage: tenant_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Coverage support: evidence: evidence_0023; sensitivity: path_param, tenant_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Express mount prefix is dynamic and was not included in the route path
- Auth evidence:
  - tenant_check `tenant_guard` at tests/fixtures/realistic/express/routes/accounts.ts:50:33 (high)
    - Symbol: `requireTenant` (tests/fixtures/realistic/express/routes/accounts.ts:50:33)
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | express_dynamic_mount_prefix | tests/fixtures/realistic/express/app.ts:43:9 | Express mount prefix is dynamic and could not be resolved |
| warning | express_unresolved_mount_router | tests/fixtures/realistic/express/app.ts:44:1 | Express mounted router could not be resolved statically |

## Skipped Files

No files were skipped.