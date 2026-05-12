# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/realistic/fastapi
- Source files: 4
- Routes: 9
- Evidence entries: 9
- Mutations: 4
- Diagnostics: 2
- Frameworks: fast_api: 9

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0001](#route-route_0001) | GET /api/accounts/{account_id} | risk is review_required |
| [route_0002](#route-route_0002) | POST /api/accounts | risk is review_required |
| [route_0003](#route-route_0003) | PATCH /api/accounts/{account_id} | risk is review_required |
| [route_0004](#route-route_0004) | DELETE /api/accounts/{account_id} | risk is review_required |
| [route_0005](#route-route_0005) | POST /api/accounts/service | risk is review_required |
| [route_0006](#route-route_0006) | POST /api/accounts/dynamic-service | risk is review_required |
| [route_0009](#route-route_0009) | GET /reports | confidence is medium; router prefix is dynamic and was not included in the route path; include_router prefix is dynamic and was not included in the route path |
| diagnostic | fastapi_dynamic_router_prefix | FastAPI router prefix is dynamic and could not be resolved at tests/fixtures/realistic/fastapi/main.py:7:18 |
| diagnostic | fastapi_dynamic_include_router_prefix | FastAPI include_router prefix is dynamic and could not be resolved at tests/fixtures/realistic/fastapi/main.py:44:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | fast_api | GET | /api/accounts/{account_id} | \`read_account\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:5) | none | high | authn_only | review_required |
| [route_0002](#route-route_0002) | fast_api | POST | /api/accounts | \`create_account_route\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:5) | none | high | authn_only | review_required |
| [route_0003](#route-route_0003) | fast_api | PATCH | /api/accounts/{account_id} | \`update_account_route\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:25:5) | none | high | permission_guarded | review_required |
| [route_0004](#route-route_0004) | fast_api | DELETE | /api/accounts/{account_id} | \`delete_account_route\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:32:5) | none | high | admin_guarded | review_required |
| [route_0005](#route-route_0005) | fast_api | POST | /api/accounts/service | \`service_create_account\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:5) | none | high | authn_only | review_required |
| [route_0006](#route-route_0006) | fast_api | POST | /api/accounts/dynamic-service | \`dynamic_service_create\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:42:5) | none | high | authn_only | review_required |
| [route_0007](#route-route_0007) | fast_api | GET | /health | \`health\` (tests/fixtures/realistic/fastapi/main.py:29:5) | none | high | unauthenticated | low |
| [route_0008](#route-route_0008) | fast_api | GET | /admin/audit | \`audit_log\` (tests/fixtures/realistic/fastapi/main.py:34:5) | none | high | admin_guarded | low |
| [route_0009](#route-route_0009) | fast_api | GET | /reports | \`dynamic_reports\` (tests/fixtures/realistic/fastapi/main.py:39:5) | none | medium | authn_only | low |

## Data Mutations

| ID | Operation | Library | Resource | Location | Confidence | Review |
| --- | --- | --- | --- | --- | --- | --- |
| mutation_0001 | create | sqlalchemy | Account | tests/fixtures/realistic/fastapi/app/routers/accounts.py:19:5 | medium | none |
| mutation_0002 | create | sqlalchemy | Account | tests/fixtures/realistic/fastapi/app/services/accounts.py:12:5 | medium | none |
| mutation_0003 | update | sqlalchemy | Account | tests/fixtures/realistic/fastapi/app/services/accounts.py:18:5 | high | none |
| mutation_0004 | delete | sqlalchemy | Account | tests/fixtures/realistic/fastapi/app/services/accounts.py:23:5 | high | none |

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/api/accounts/{account_id}`

- Framework: fast_api
- Handler: `read_account` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:11:2
- Middleware: none
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: evidence: evidence_0001; sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:40 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:48)
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 POST `/api/accounts`

- Framework: fast_api
- Handler: `create_account_route` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:16:2
- Middleware: none
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0002; mutations: mutation_0001; links: link_0001; sensitivity: account_path, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:49 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:57)
- Data mutations:
  - create `Account` via `sqlalchemy` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:19:5 (medium)

<a id="route-route_0003"></a>
### route_0003 PATCH `/api/accounts/{account_id}`

- Framework: fast_api
- Handler: `update_account_route` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:25:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:24:2
- Middleware: none
- Confidence: high
- Coverage: permission_guarded (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0003, evidence_0004; weak evidence: evidence_0004; mutations: mutation_0003; links: link_0002; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - permission_check `permission_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:25:48 (high)
    - Symbol: `can_edit_account` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:25:56)
  - unknown_dynamic_check `handler_call` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:26:12 (low)
    - Symbol: `dynamic_policy_check` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:26:12)
    - Note: Dynamic or indirect policy call requires review
- Data mutations:
  - update `Account` via `sqlalchemy` at tests/fixtures/realistic/fastapi/app/services/accounts.py:18:5 (high)

<a id="route-route_0004"></a>
### route_0004 DELETE `/api/accounts/{account_id}`

- Framework: fast_api
- Handler: `delete_account_route` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:32:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:31:2
- Middleware: none
- Confidence: high
- Coverage: admin_guarded (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0005; mutations: mutation_0004; links: link_0003; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - admin_check `admin_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:32:48 (high)
    - Symbol: `require_admin` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:32:56)
- Data mutations:
  - delete `Account` via `sqlalchemy` at tests/fixtures/realistic/fastapi/app/services/accounts.py:23:5 (high)

<a id="route-route_0005"></a>
### route_0005 POST `/api/accounts/service`

- Framework: fast_api
- Handler: `service_create_account` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:36:2
- Middleware: none
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0006; mutations: mutation_0002; links: link_0004; sensitivity: account_path, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:33 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:41)
- Data mutations:
  - create `Account` via `sqlalchemy` at tests/fixtures/realistic/fastapi/app/services/accounts.py:12:5 (medium)

<a id="route-route_0006"></a>
### route_0006 POST `/api/accounts/dynamic-service`

- Framework: fast_api
- Handler: `dynamic_service_create` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:42:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:41:2
- Middleware: none
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, unsafe_method.
- Coverage support: evidence: evidence_0007; links: link_0005; sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:42:33 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:42:41)
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 GET `/health`

- Framework: fast_api
- Handler: `health` (tests/fixtures/realistic/fastapi/main.py:29:5)
- Route location: tests/fixtures/realistic/fastapi/main.py:28:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 GET `/admin/audit`

- Framework: fast_api
- Handler: `audit_log` (tests/fixtures/realistic/fastapi/main.py:34:5)
- Route location: tests/fixtures/realistic/fastapi/main.py:33:2
- Middleware: none
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): admin_path.
- Coverage support: evidence: evidence_0008; sensitivity: admin_path
- Reviewer questions:
  - Should this route require an admin or role guard?
- Auth evidence:
  - admin_check `admin_guard` at tests/fixtures/realistic/fastapi/main.py:34:20 (high)
    - Symbol: `require_admin` (tests/fixtures/realistic/fastapi/main.py:34:28)
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 GET `/reports`

- Framework: fast_api
- Handler: `dynamic_reports` (tests/fixtures/realistic/fastapi/main.py:39:5)
- Route location: tests/fixtures/realistic/fastapi/main.py:38:2
- Middleware: none
- Confidence: medium
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0009
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - router prefix is dynamic and was not included in the route path
  - include_router prefix is dynamic and was not included in the route path
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/main.py:39:26 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/main.py:39:34)
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | fastapi_dynamic_router_prefix | tests/fixtures/realistic/fastapi/main.py:7:18 | FastAPI router prefix is dynamic and could not be resolved |
| warning | fastapi_dynamic_include_router_prefix | tests/fixtures/realistic/fastapi/main.py:44:1 | FastAPI include_router prefix is dynamic and could not be resolved |

## Skipped Files

No files were skipped.