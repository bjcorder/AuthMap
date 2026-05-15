# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/fastapi
- Source files: 7
- Routes: 23
- Evidence entries: 6
- Mutations: 0
- Diagnostics: 4
- Frameworks: fast_api: 23

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0001](#route-route_0001) | DELETE /collection/items/{item_id} | risk is high |
| [route_0002](#route-route_0002) | POST /factory/items | risk is high |
| [route_0006](#route-route_0006) | PUT /relative/users/{user_id} | risk is high |
| [route_0007](#route-route_0007) | PUT /v1/users/{user_id} | risk is high |
| [route_0009](#route-route_0009) | POST /items | risk is high |
| [route_0013](#route-route_0013) | POST /service/accounts | risk is review_required; coverage is unknown_or_dynamic |
| [route_0014](#route-route_0014) | DELETE /api/local/{item_id} | risk is review_required |
| [route_0015](#route-route_0015) | GET /reports | confidence is medium; router prefix is dynamic and was not included in the route path; include_router prefix is dynamic and was not included in the route path |
| [route_0017](#route-route_0017) | POST /search | risk is high |
| [route_0018](#route-route_0018) | ANY /fallback | confidence is medium; api_route methods are dynamic or missing; emitted as ANY; risk is high |
| [route_0021](#route-route_0021) | GET &lt;dynamic&gt; | confidence is medium; route path is dynamic and was emitted as &lt;dynamic&gt;; route path is dynamic and was not fully resolved |
| diagnostic | fastapi_dynamic_router_prefix | FastAPI router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:14:18 |
| diagnostic | fastapi_dynamic_api_route_methods | FastAPI api_route methods are dynamic or missing at tests/fixtures/fastapi/main.py:83:2 |
| diagnostic | fastapi_dynamic_route_path | FastAPI route path is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:98:2 |
| diagnostic | fastapi_dynamic_include_router_prefix | FastAPI include_router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:122:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | fast_api | DELETE | /collection/items/{item_id} | \`delete_collection_item\` (tests/fixtures/fastapi/app/factories/collection.py:8:15) | none | high | unauthenticated | high |
| [route_0002](#route-route_0002) | fast_api | POST | /factory/items | \`create_factory_item\` (tests/fixtures/fastapi/app/factories/custom.py:14:15) | none | high | unauthenticated | high |
| [route_0003](#route-route_0003) | fast_api | GET | /factory/nested/status | \`nested_status\` (tests/fixtures/fastapi/app/factories/nested.py:8:15) | none | high | unauthenticated | low |
| [route_0004](#route-route_0004) | fast_api | GET | /relative/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | none | high | unauthenticated | medium |
| [route_0005](#route-route_0005) | fast_api | GET | /v1/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | none | high | unauthenticated | medium |
| [route_0006](#route-route_0006) | fast_api | PUT | /relative/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | none | high | unauthenticated | high |
| [route_0007](#route-route_0007) | fast_api | PUT | /v1/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | none | high | unauthenticated | high |
| [route_0008](#route-route_0008) | fast_api | GET | /health | \`health\` (tests/fixtures/fastapi/main.py:36:5) | none | high | unauthenticated | low |
| [route_0009](#route-route_0009) | fast_api | POST | /items | \`create_item\` (tests/fixtures/fastapi/main.py:41:5) | none | high | unauthenticated | high |
| [route_0010](#route-route_0010) | fast_api | GET | /profile | \`profile\` (tests/fixtures/fastapi/main.py:46:5) | none | high | authn_only | low |
| [route_0011](#route-route_0011) | fast_api | DELETE | /admin/accounts/{account_id} | \`delete_account\` (tests/fixtures/fastapi/main.py:51:5) | \`require_admin\` (tests/fixtures/fastapi/main.py:50:67) | high | admin_guarded | low |
| [route_0012](#route-route_0012) | fast_api | PATCH | /accounts/{account_id}/permissions | \`grant_permission\` (tests/fixtures/fastapi/main.py:56:5) | \`can_edit_account\` (tests/fixtures/fastapi/main.py:55:72) | high | permission_guarded | low |
| [route_0013](#route-route_0013) | fast_api | POST | /service/accounts | \`service_account\` (tests/fixtures/fastapi/main.py:63:5) | none | high | unknown_or_dynamic | review_required |
| [route_0014](#route-route_0014) | fast_api | DELETE | /api/local/{item_id} | \`delete_local\` (tests/fixtures/fastapi/main.py:69:5) | \`require_user\` (tests/fixtures/fastapi/main.py:116:71) | high | authn_only | review_required |
| [route_0015](#route-route_0015) | fast_api | GET | /reports | \`dynamic_reports\` (tests/fixtures/fastapi/main.py:74:5) | none | medium | unauthenticated | low |
| [route_0016](#route-route_0016) | fast_api | GET | /search | \`search\` (tests/fixtures/fastapi/main.py:79:5) | none | high | unauthenticated | low |
| [route_0017](#route-route_0017) | fast_api | POST | /search | \`search\` (tests/fixtures/fastapi/main.py:79:5) | none | high | unauthenticated | high |
| [route_0018](#route-route_0018) | fast_api | ANY | /fallback | \`fallback\` (tests/fixtures/fastapi/main.py:84:5) | none | medium | unauthenticated | high |
| [route_0019](#route-route_0019) | fast_api | GET | /generated | \`generated_path\` (tests/fixtures/fastapi/main.py:89:5) | none | high | unauthenticated | low |
| [route_0020](#route-route_0020) | fast_api | GET | /constant | \`constant_alias_path\` (tests/fixtures/fastapi/main.py:94:5) | none | high | unauthenticated | low |
| [route_0021](#route-route_0021) | fast_api | GET | &lt;dynamic&gt; | \`unresolved_runtime_path\` (tests/fixtures/fastapi/main.py:99:5) | none | medium | unauthenticated | low |
| [route_0022](#route-route_0022) | fast_api | GET | /factory/status | \`default_status_path\` (tests/fixtures/fastapi/main.py:108:9) | none | high | unauthenticated | low |
| [route_0023](#route-route_0023) | fast_api | GET | /factory/ready | \`default_ready_path\` (tests/fixtures/fastapi/main.py:112:9) | none | high | unauthenticated | low |

## Data Mutations

No data mutations were detected.

## Route Details

<a id="route-route_0001"></a>
### route_0001 DELETE `/collection/items/{item_id}`

- Framework: fast_api
- Handler: `delete_collection_item` (tests/fixtures/fastapi/app/factories/collection.py:8:15)
- Route location: tests/fixtures/fastapi/app/factories/collection.py:7:6
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

<a id="route-route_0002"></a>
### route_0002 POST `/factory/items`

- Framework: fast_api
- Handler: `create_factory_item` (tests/fixtures/fastapi/app/factories/custom.py:14:15)
- Route location: tests/fixtures/fastapi/app/factories/custom.py:13:6
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 GET `/factory/nested/status`

- Framework: fast_api
- Handler: `nested_status` (tests/fixtures/fastapi/app/factories/nested.py:8:15)
- Route location: tests/fixtures/fastapi/app/factories/nested.py:7:6
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 GET `/relative/users/{user_id}`

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

<a id="route-route_0005"></a>
### route_0005 GET `/v1/users/{user_id}`

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

<a id="route-route_0006"></a>
### route_0006 PUT `/relative/users/{user_id}`

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

<a id="route-route_0007"></a>
### route_0007 PUT `/v1/users/{user_id}`

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

<a id="route-route_0008"></a>
### route_0008 GET `/health`

- Framework: fast_api
- Handler: `health` (tests/fixtures/fastapi/main.py:36:5)
- Route location: tests/fixtures/fastapi/main.py:35:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 POST `/items`

- Framework: fast_api
- Handler: `create_item` (tests/fixtures/fastapi/main.py:41:5)
- Route location: tests/fixtures/fastapi/main.py:40:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 GET `/profile`

- Framework: fast_api
- Handler: `profile` (tests/fixtures/fastapi/main.py:46:5)
- Route location: tests/fixtures/fastapi/main.py:45:2
- Middleware: none
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0001
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:46:18 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:46:26)
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 DELETE `/admin/accounts/{account_id}`

- Framework: fast_api
- Handler: `delete_account` (tests/fixtures/fastapi/main.py:51:5)
- Route location: tests/fixtures/fastapi/main.py:50:2
- Middleware: `require_admin` (tests/fixtures/fastapi/main.py:50:67)
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, admin_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0002; sensitivity: account_path, admin_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require an admin or role guard?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - admin_check `admin_guard` at tests/fixtures/fastapi/main.py:50:59 (high)
    - Symbol: `require_admin` (tests/fixtures/fastapi/main.py:50:67)
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 PATCH `/accounts/{account_id}/permissions`

- Framework: fast_api
- Handler: `grant_permission` (tests/fixtures/fastapi/main.py:56:5)
- Route location: tests/fixtures/fastapi/main.py:55:2
- Middleware: `can_edit_account` (tests/fixtures/fastapi/main.py:55:72)
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
  - permission_check `permission_guard` at tests/fixtures/fastapi/main.py:55:64 (high)
    - Symbol: `can_edit_account` (tests/fixtures/fastapi/main.py:55:72)
  - unknown_dynamic_check `handler_call` at tests/fixtures/fastapi/main.py:57:12 (low)
    - Symbol: `dynamic_policy_check` (tests/fixtures/fastapi/main.py:57:12)
    - Note: Dynamic or indirect policy call requires review
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 POST `/service/accounts`

- Framework: fast_api
- Handler: `service_account` (tests/fixtures/fastapi/main.py:63:5)
- Route location: tests/fixtures/fastapi/main.py:62:2
- Middleware: none
- Confidence: high
- Coverage: unknown_or_dynamic (review_required)
- Coverage rationale: 1 weak or dynamic authorization evidence item(s) were detected.; Sensitive route modifier(s): account_path, unsafe_method.
- Coverage support: evidence: evidence_0005; weak evidence: evidence_0005; links: link_0001; sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Can the dynamic authorization path be confirmed?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - unknown_dynamic_check `dynamic_policy` at tests/fixtures/fastapi/app/services/account.py:7:9 (low)
    - Symbol: `authorize` (tests/fixtures/fastapi/app/services/account.py:7:9)
    - Note: One-hop service call \`service.execute\` reaches \`execute\`
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 DELETE `/api/local/{item_id}`

- Framework: fast_api
- Handler: `delete_local` (tests/fixtures/fastapi/main.py:69:5)
- Route location: tests/fixtures/fastapi/main.py:68:2
- Middleware: `require_user` (tests/fixtures/fastapi/main.py:116:71)
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method.
- Coverage support: evidence: evidence_0006; sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:116:71 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:116:71)
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 GET `/reports`

- Framework: fast_api
- Handler: `dynamic_reports` (tests/fixtures/fastapi/main.py:74:5)
- Route location: tests/fixtures/fastapi/main.py:73:2
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

<a id="route-route_0016"></a>
### route_0016 GET `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:79:5)
- Route location: tests/fixtures/fastapi/main.py:78:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0017"></a>
### route_0017 POST `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:79:5)
- Route location: tests/fixtures/fastapi/main.py:78:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0018"></a>
### route_0018 ANY `/fallback`

- Framework: fast_api
- Handler: `fallback` (tests/fixtures/fastapi/main.py:84:5)
- Route location: tests/fixtures/fastapi/main.py:83:2
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

<a id="route-route_0019"></a>
### route_0019 GET `/generated`

- Framework: fast_api
- Handler: `generated_path` (tests/fixtures/fastapi/main.py:89:5)
- Route location: tests/fixtures/fastapi/main.py:88:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0020"></a>
### route_0020 GET `/constant`

- Framework: fast_api
- Handler: `constant_alias_path` (tests/fixtures/fastapi/main.py:94:5)
- Route location: tests/fixtures/fastapi/main.py:93:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0021"></a>
### route_0021 GET `&lt;dynamic&gt;`

- Framework: fast_api
- Handler: `unresolved_runtime_path` (tests/fixtures/fastapi/main.py:99:5)
- Route location: tests/fixtures/fastapi/main.py:98:2
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

<a id="route-route_0022"></a>
### route_0022 GET `/factory/status`

- Framework: fast_api
- Handler: `default_status_path` (tests/fixtures/fastapi/main.py:108:9)
- Route location: tests/fixtures/fastapi/main.py:107:6
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0023"></a>
### route_0023 GET `/factory/ready`

- Framework: fast_api
- Handler: `default_ready_path` (tests/fixtures/fastapi/main.py:112:9)
- Route location: tests/fixtures/fastapi/main.py:111:6
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | fastapi_dynamic_router_prefix | tests/fixtures/fastapi/main.py:14:18 | FastAPI router prefix is dynamic and could not be resolved |
| warning | fastapi_dynamic_api_route_methods | tests/fixtures/fastapi/main.py:83:2 | FastAPI api_route methods are dynamic or missing |
| warning | fastapi_dynamic_route_path | tests/fixtures/fastapi/main.py:98:2 | FastAPI route path is dynamic and could not be resolved |
| warning | fastapi_dynamic_include_router_prefix | tests/fixtures/fastapi/main.py:122:1 | FastAPI include_router prefix is dynamic and could not be resolved |

## Skipped Files

No files were skipped.