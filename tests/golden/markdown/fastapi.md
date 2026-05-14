# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/fastapi
- Source files: 3
- Routes: 15
- Evidence entries: 4
- Mutations: 0
- Diagnostics: 4
- Frameworks: fast_api: 15

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0003](#route-route_0003) | PUT /relative/users/{user_id} | risk is high |
| [route_0004](#route-route_0004) | PUT /v1/users/{user_id} | risk is high |
| [route_0006](#route-route_0006) | POST /items | risk is high |
| [route_0010](#route-route_0010) | DELETE /api/local/{item_id} | risk is high |
| [route_0011](#route-route_0011) | GET /reports | confidence is medium; router prefix is dynamic and was not included in the route path; include_router prefix is dynamic and was not included in the route path |
| [route_0013](#route-route_0013) | POST /search | risk is high |
| [route_0014](#route-route_0014) | ANY /fallback | confidence is medium; api_route methods are dynamic or missing; emitted as ANY; risk is high |
| [route_0015](#route-route_0015) | GET &lt;dynamic&gt; | confidence is medium; route path is dynamic and was emitted as &lt;dynamic&gt;; route path is dynamic and was not fully resolved |
| diagnostic | fastapi_dynamic_router_prefix | FastAPI router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:8:18 |
| diagnostic | fastapi_dynamic_api_route_methods | FastAPI api_route methods are dynamic or missing at tests/fixtures/fastapi/main.py:71:2 |
| diagnostic | fastapi_dynamic_route_path | FastAPI route path is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:76:2 |
| diagnostic | fastapi_dynamic_include_router_prefix | FastAPI include_router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:83:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | fast_api | GET | /relative/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | none | high | unauthenticated | medium |
| [route_0002](#route-route_0002) | fast_api | GET | /v1/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | none | high | unauthenticated | medium |
| [route_0003](#route-route_0003) | fast_api | PUT | /relative/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | none | high | unauthenticated | high |
| [route_0004](#route-route_0004) | fast_api | PUT | /v1/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | none | high | unauthenticated | high |
| [route_0005](#route-route_0005) | fast_api | GET | /health | \`health\` (tests/fixtures/fastapi/main.py:30:5) | none | high | unauthenticated | low |
| [route_0006](#route-route_0006) | fast_api | POST | /items | \`create_item\` (tests/fixtures/fastapi/main.py:35:5) | none | high | unauthenticated | high |
| [route_0007](#route-route_0007) | fast_api | GET | /profile | \`profile\` (tests/fixtures/fastapi/main.py:40:5) | none | high | authn_only | low |
| [route_0008](#route-route_0008) | fast_api | DELETE | /admin/accounts/{account_id} | \`delete_account\` (tests/fixtures/fastapi/main.py:45:5) | none | high | admin_guarded | low |
| [route_0009](#route-route_0009) | fast_api | PATCH | /accounts/{account_id}/permissions | \`grant_permission\` (tests/fixtures/fastapi/main.py:50:5) | none | high | permission_guarded | low |
| [route_0010](#route-route_0010) | fast_api | DELETE | /api/local/{item_id} | \`delete_local\` (tests/fixtures/fastapi/main.py:57:5) | none | high | unauthenticated | high |
| [route_0011](#route-route_0011) | fast_api | GET | /reports | \`dynamic_reports\` (tests/fixtures/fastapi/main.py:62:5) | none | medium | unauthenticated | low |
| [route_0012](#route-route_0012) | fast_api | GET | /search | \`search\` (tests/fixtures/fastapi/main.py:67:5) | none | high | unauthenticated | low |
| [route_0013](#route-route_0013) | fast_api | POST | /search | \`search\` (tests/fixtures/fastapi/main.py:67:5) | none | high | unauthenticated | high |
| [route_0014](#route-route_0014) | fast_api | ANY | /fallback | \`fallback\` (tests/fixtures/fastapi/main.py:72:5) | none | medium | unauthenticated | high |
| [route_0015](#route-route_0015) | fast_api | GET | &lt;dynamic&gt; | \`generated_path\` (tests/fixtures/fastapi/main.py:77:5) | none | medium | unauthenticated | low |

## Data Mutations

No data mutations were detected.

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/relative/users/{user_id}`

- Framework: fast_api
- Handler: `get_user` (tests/fixtures/fastapi/app/routes/users.py:7:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:6:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 GET `/v1/users/{user_id}`

- Framework: fast_api
- Handler: `get_user` (tests/fixtures/fastapi/app/routes/users.py:7:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:6:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 PUT `/relative/users/{user_id}`

- Framework: fast_api
- Handler: `update_user` (tests/fixtures/fastapi/app/routes/users.py:12:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:11:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 PUT `/v1/users/{user_id}`

- Framework: fast_api
- Handler: `update_user` (tests/fixtures/fastapi/app/routes/users.py:12:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:11:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 GET `/health`

- Framework: fast_api
- Handler: `health` (tests/fixtures/fastapi/main.py:30:5)
- Route location: tests/fixtures/fastapi/main.py:29:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 POST `/items`

- Framework: fast_api
- Handler: `create_item` (tests/fixtures/fastapi/main.py:35:5)
- Route location: tests/fixtures/fastapi/main.py:34:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 GET `/profile`

- Framework: fast_api
- Handler: `profile` (tests/fixtures/fastapi/main.py:40:5)
- Route location: tests/fixtures/fastapi/main.py:39:2
- Middleware: none
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0001
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:40:18 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:40:26)
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 DELETE `/admin/accounts/{account_id}`

- Framework: fast_api
- Handler: `delete_account` (tests/fixtures/fastapi/main.py:45:5)
- Route location: tests/fixtures/fastapi/main.py:44:2
- Middleware: none
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, admin_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0002; sensitivity: account_path, admin_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require an admin or role guard?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - admin_check `admin_guard` at tests/fixtures/fastapi/main.py:44:59 (high)
    - Symbol: `require_admin` (tests/fixtures/fastapi/main.py:44:67)
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 PATCH `/accounts/{account_id}/permissions`

- Framework: fast_api
- Handler: `grant_permission` (tests/fixtures/fastapi/main.py:50:5)
- Route location: tests/fixtures/fastapi/main.py:49:2
- Middleware: none
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0003, evidence_0004; weak evidence: evidence_0004; sensitivity: account_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - permission_check `permission_guard` at tests/fixtures/fastapi/main.py:49:64 (high)
    - Symbol: `can_edit_account` (tests/fixtures/fastapi/main.py:49:72)
  - unknown_dynamic_check `handler_call` at tests/fixtures/fastapi/main.py:51:12 (low)
    - Symbol: `dynamic_policy_check` (tests/fixtures/fastapi/main.py:51:12)
    - Note: Dynamic or indirect policy call requires review
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 DELETE `/api/local/{item_id}`

- Framework: fast_api
- Handler: `delete_local` (tests/fixtures/fastapi/main.py:57:5)
- Route location: tests/fixtures/fastapi/main.py:56:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 GET `/reports`

- Framework: fast_api
- Handler: `dynamic_reports` (tests/fixtures/fastapi/main.py:62:5)
- Route location: tests/fixtures/fastapi/main.py:61:2
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - router prefix is dynamic and was not included in the route path
  - include_router prefix is dynamic and was not included in the route path
- Auth evidence: none
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 GET `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:67:5)
- Route location: tests/fixtures/fastapi/main.py:66:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 POST `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:67:5)
- Route location: tests/fixtures/fastapi/main.py:66:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 ANY `/fallback`

- Framework: fast_api
- Handler: `fallback` (tests/fixtures/fastapi/main.py:72:5)
- Route location: tests/fixtures/fastapi/main.py:71:2
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): any_method, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - api_route methods are dynamic or missing; emitted as ANY
- Auth evidence: none
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 GET `&lt;dynamic&gt;`

- Framework: fast_api
- Handler: `generated_path` (tests/fixtures/fastapi/main.py:77:5)
- Route location: tests/fixtures/fastapi/main.py:76:2
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - route path is dynamic and was emitted as &lt;dynamic&gt;
  - route path is dynamic and was not fully resolved
- Auth evidence: none
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | fastapi_dynamic_router_prefix | tests/fixtures/fastapi/main.py:8:18 | FastAPI router prefix is dynamic and could not be resolved |
| warning | fastapi_dynamic_api_route_methods | tests/fixtures/fastapi/main.py:71:2 | FastAPI api_route methods are dynamic or missing |
| warning | fastapi_dynamic_route_path | tests/fixtures/fastapi/main.py:76:2 | FastAPI route path is dynamic and could not be resolved |
| warning | fastapi_dynamic_include_router_prefix | tests/fixtures/fastapi/main.py:83:1 | FastAPI include_router prefix is dynamic and could not be resolved |

## Skipped Files

No files were skipped.