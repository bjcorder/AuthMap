# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/fastapi
- Source files: 7
- Routes: 26
- Evidence entries: 12
- Mutations: 0
- Diagnostics: 4
- Frameworks: fast_api: 26

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0001](#route-route_0001) | DELETE /collection/items/{item_id} | risk is high |
| [route_0002](#route-route_0002) | POST /factory/items | risk is high |
| [route_0007](#route-route_0007) | PUT /relative/users/{user_id} | risk is high |
| [route_0009](#route-route_0009) | PUT /v1/users/{user_id} | risk is high |
| [route_0011](#route-route_0011) | POST /items | risk is high |
| [route_0015](#route-route_0015) | POST /service/accounts | risk is review_required; coverage is unknown_or_dynamic |
| [route_0016](#route-route_0016) | DELETE /api/local/{item_id} | risk is review_required |
| [route_0018](#route-route_0018) | GET /reports | confidence is medium; router prefix is dynamic and was not included in the route path; include_router prefix is dynamic and was not included in the route path |
| [route_0020](#route-route_0020) | POST /search | risk is high |
| [route_0021](#route-route_0021) | ANY /fallback | confidence is medium; api_route methods are dynamic or missing; emitted as ANY; risk is high |
| [route_0024](#route-route_0024) | GET &lt;dynamic&gt; | confidence is medium; route path is dynamic and was emitted as &lt;dynamic&gt;; route path is dynamic and was not fully resolved |
| diagnostic | fastapi_dynamic_router_prefix | FastAPI router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:14:18 |
| diagnostic | fastapi_dynamic_api_route_methods | FastAPI api_route methods are dynamic or missing at tests/fixtures/fastapi/main.py:95:2 |
| diagnostic | fastapi_dynamic_route_path | FastAPI route path is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:110:2 |
| diagnostic | fastapi_dynamic_include_router_prefix | FastAPI include_router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:140:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | fast_api | DELETE | /collection/items/{item_id} | \`delete_collection_item\` (tests/fixtures/fastapi/app/factories/collection.py:8:15) | none | high | unauthenticated | high |
| [route_0002](#route-route_0002) | fast_api | POST | /factory/items | \`create_factory_item\` (tests/fixtures/fastapi/app/factories/custom.py:14:15) | none | high | unauthenticated | high |
| [route_0003](#route-route_0003) | fast_api | GET | /factory/nested/status | \`nested_status\` (tests/fixtures/fastapi/app/factories/nested.py:8:15) | none | high | unauthenticated | low |
| [route_0004](#route-route_0004) | fast_api | GET | /relative/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | none | high | unauthenticated | medium |
| [route_0005](#route-route_0005) | fast_api | GET | /shared/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | \`require_user\` (tests/fixtures/fastapi/main.py:134:32), \`can_edit_account\` (tests/fixtures/fastapi/main.py:135:36), \`provide_database_interface\` (tests/fixtures/fastapi/main.py:136:36) | high | permission_guarded | low |
| [route_0006](#route-route_0006) | fast_api | GET | /v1/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | none | high | unauthenticated | medium |
| [route_0007](#route-route_0007) | fast_api | PUT | /relative/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | none | high | unauthenticated | high |
| [route_0008](#route-route_0008) | fast_api | PUT | /shared/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | \`require_user\` (tests/fixtures/fastapi/main.py:134:32), \`can_edit_account\` (tests/fixtures/fastapi/main.py:135:36), \`provide_database_interface\` (tests/fixtures/fastapi/main.py:136:36) | high | permission_guarded | low |
| [route_0009](#route-route_0009) | fast_api | PUT | /v1/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | none | high | unauthenticated | high |
| [route_0010](#route-route_0010) | fast_api | GET | /health | \`health\` (tests/fixtures/fastapi/main.py:40:5) | none | high | unauthenticated | low |
| [route_0011](#route-route_0011) | fast_api | POST | /items | \`create_item\` (tests/fixtures/fastapi/main.py:45:5) | none | high | unauthenticated | high |
| [route_0012](#route-route_0012) | fast_api | GET | /profile | \`profile\` (tests/fixtures/fastapi/main.py:50:5) | none | high | authn_only | low |
| [route_0013](#route-route_0013) | fast_api | DELETE | /admin/accounts/{account_id} | \`delete_account\` (tests/fixtures/fastapi/main.py:55:5) | \`require_admin\` (tests/fixtures/fastapi/main.py:54:67) | high | admin_guarded | low |
| [route_0014](#route-route_0014) | fast_api | PATCH | /accounts/{account_id}/permissions | \`grant_permission\` (tests/fixtures/fastapi/main.py:60:5) | \`can_edit_account\` (tests/fixtures/fastapi/main.py:59:72) | high | permission_guarded | low |
| [route_0015](#route-route_0015) | fast_api | POST | /service/accounts | \`service_account\` (tests/fixtures/fastapi/main.py:67:5) | none | high | unknown_or_dynamic | review_required |
| [route_0016](#route-route_0016) | fast_api | DELETE | /api/local/{item_id} | \`delete_local\` (tests/fixtures/fastapi/main.py:73:5) | \`require_user\` (tests/fixtures/fastapi/main.py:128:71) | high | authn_only | review_required |
| [route_0017](#route-route_0017) | fast_api | GET | /shared/variable/settings | \`variable_settings\` (tests/fixtures/fastapi/main.py:81:5) | \`require_user\` (tests/fixtures/fastapi/main.py:134:32), \`can_edit_account\` (tests/fixtures/fastapi/main.py:135:36), \`provide_database_interface\` (tests/fixtures/fastapi/main.py:136:36) | high | permission_guarded | low |
| [route_0018](#route-route_0018) | fast_api | GET | /reports | \`dynamic_reports\` (tests/fixtures/fastapi/main.py:86:5) | none | medium | unauthenticated | low |
| [route_0019](#route-route_0019) | fast_api | GET | /search | \`search\` (tests/fixtures/fastapi/main.py:91:5) | none | high | unauthenticated | low |
| [route_0020](#route-route_0020) | fast_api | POST | /search | \`search\` (tests/fixtures/fastapi/main.py:91:5) | none | high | unauthenticated | high |
| [route_0021](#route-route_0021) | fast_api | ANY | /fallback | \`fallback\` (tests/fixtures/fastapi/main.py:96:5) | none | medium | unauthenticated | high |
| [route_0022](#route-route_0022) | fast_api | GET | /generated | \`generated_path\` (tests/fixtures/fastapi/main.py:101:5) | none | high | unauthenticated | low |
| [route_0023](#route-route_0023) | fast_api | GET | /constant | \`constant_alias_path\` (tests/fixtures/fastapi/main.py:106:5) | none | high | unauthenticated | low |
| [route_0024](#route-route_0024) | fast_api | GET | &lt;dynamic&gt; | \`unresolved_runtime_path\` (tests/fixtures/fastapi/main.py:111:5) | none | medium | unauthenticated | low |
| [route_0025](#route-route_0025) | fast_api | GET | /factory/status | \`default_status_path\` (tests/fixtures/fastapi/main.py:120:9) | none | high | unauthenticated | low |
| [route_0026](#route-route_0026) | fast_api | GET | /factory/ready | \`default_ready_path\` (tests/fixtures/fastapi/main.py:124:9) | none | high | unauthenticated | low |

## Data Mutations

No data mutations were detected.

## Route Details

<a id="route-route_0001"></a>
### route_0001 DELETE `/collection/items/{item_id}`

- Framework: fast_api
- Handler: `delete_collection_item` (tests/fixtures/fastapi/app/factories/collection.py:8:15)
- Route location: tests/fixtures/fastapi/app/factories/collection.py:7:6
- Middleware: none
- Params: item_id (high)
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
- Params: user_id (high)
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 GET `/shared/users/{user_id}`

- Framework: fast_api
- Handler: `get_user` (tests/fixtures/fastapi/app/routes/users.py:7:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:6:2
- Middleware: `require_user` (tests/fixtures/fastapi/main.py:134:32), `can_edit_account` (tests/fixtures/fastapi/main.py:135:36), `provide_database_interface` (tests/fixtures/fastapi/main.py:136:36)
- Params: user_id (high)
- Declared protection: can_edit_account, provide_database_interface, require_user
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: evidence: evidence_0001, evidence_0002; sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:134:32 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:134:32)
  - permission_check `permission_guard` at tests/fixtures/fastapi/main.py:135:36 (high)
    - Symbol: `can_edit_account` (tests/fixtures/fastapi/main.py:135:36)
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 GET `/v1/users/{user_id}`

- Framework: fast_api
- Handler: `get_user` (tests/fixtures/fastapi/app/routes/users.py:7:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:6:2
- Middleware: none
- Params: user_id (high)
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, user_path.
- Coverage support: sensitivity: path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 PUT `/relative/users/{user_id}`

- Framework: fast_api
- Handler: `update_user` (tests/fixtures/fastapi/app/routes/users.py:12:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:11:2
- Middleware: none
- Params: user_id (high)
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
### route_0008 PUT `/shared/users/{user_id}`

- Framework: fast_api
- Handler: `update_user` (tests/fixtures/fastapi/app/routes/users.py:12:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:11:2
- Middleware: `require_user` (tests/fixtures/fastapi/main.py:134:32), `can_edit_account` (tests/fixtures/fastapi/main.py:135:36), `provide_database_interface` (tests/fixtures/fastapi/main.py:136:36)
- Params: user_id (high)
- Declared protection: can_edit_account, provide_database_interface, require_user
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): path_param, unsafe_method, user_path.
- Coverage support: evidence: evidence_0003, evidence_0004; sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:134:32 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:134:32)
  - permission_check `permission_guard` at tests/fixtures/fastapi/main.py:135:36 (high)
    - Symbol: `can_edit_account` (tests/fixtures/fastapi/main.py:135:36)
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 PUT `/v1/users/{user_id}`

- Framework: fast_api
- Handler: `update_user` (tests/fixtures/fastapi/app/routes/users.py:12:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:11:2
- Middleware: none
- Params: user_id (high)
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 GET `/health`

- Framework: fast_api
- Handler: `health` (tests/fixtures/fastapi/main.py:40:5)
- Route location: tests/fixtures/fastapi/main.py:39:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 POST `/items`

- Framework: fast_api
- Handler: `create_item` (tests/fixtures/fastapi/main.py:45:5)
- Route location: tests/fixtures/fastapi/main.py:44:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 GET `/profile`

- Framework: fast_api
- Handler: `profile` (tests/fixtures/fastapi/main.py:50:5)
- Route location: tests/fixtures/fastapi/main.py:49:2
- Middleware: none
- Declared protection: require_user
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0005
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:50:18 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:50:26)
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 DELETE `/admin/accounts/{account_id}`

- Framework: fast_api
- Handler: `delete_account` (tests/fixtures/fastapi/main.py:55:5)
- Route location: tests/fixtures/fastapi/main.py:54:2
- Middleware: `require_admin` (tests/fixtures/fastapi/main.py:54:67)
- Params: account_id (high)
- Declared protection: require_admin
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, admin_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0006; sensitivity: account_path, admin_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require an admin or role guard?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - admin_check `admin_guard` at tests/fixtures/fastapi/main.py:54:59 (high)
    - Symbol: `require_admin` (tests/fixtures/fastapi/main.py:54:67)
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 PATCH `/accounts/{account_id}/permissions`

- Framework: fast_api
- Handler: `grant_permission` (tests/fixtures/fastapi/main.py:60:5)
- Route location: tests/fixtures/fastapi/main.py:59:2
- Middleware: `can_edit_account` (tests/fixtures/fastapi/main.py:59:72)
- Params: account_id (high)
- Declared protection: can_edit_account, dynamic_policy_check
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
  - permission_check `permission_guard` at tests/fixtures/fastapi/main.py:59:64 (high)
    - Symbol: `can_edit_account` (tests/fixtures/fastapi/main.py:59:72)
  - unknown_dynamic_check `handler_call` at tests/fixtures/fastapi/main.py:61:12 (low)
    - Symbol: `dynamic_policy_check` (tests/fixtures/fastapi/main.py:61:12)
    - Note: Dynamic or indirect policy call requires review
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 POST `/service/accounts`

- Framework: fast_api
- Handler: `service_account` (tests/fixtures/fastapi/main.py:67:5)
- Route location: tests/fixtures/fastapi/main.py:66:2
- Middleware: none
- Declared protection: authorize
- Confidence: high
- Coverage: unknown_or_dynamic (review_required)
- Coverage rationale: 1 weak or dynamic authorization evidence item(s) were detected.; Sensitive route modifier(s): account_path, unsafe_method.
- Coverage support: evidence: evidence_0009; weak evidence: evidence_0009; links: link_0001; sensitivity: account_path, unsafe_method
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

<a id="route-route_0016"></a>
### route_0016 DELETE `/api/local/{item_id}`

- Framework: fast_api
- Handler: `delete_local` (tests/fixtures/fastapi/main.py:73:5)
- Route location: tests/fixtures/fastapi/main.py:72:2
- Middleware: `require_user` (tests/fixtures/fastapi/main.py:128:71)
- Params: item_id (high)
- Declared protection: require_user
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): path_param, unsafe_method.
- Coverage support: evidence: evidence_0010; sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:128:71 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:128:71)
- Data mutations: none

<a id="route-route_0017"></a>
### route_0017 GET `/shared/variable/settings`

- Framework: fast_api
- Handler: `variable_settings` (tests/fixtures/fastapi/main.py:81:5)
- Route location: tests/fixtures/fastapi/main.py:80:2
- Middleware: `require_user` (tests/fixtures/fastapi/main.py:134:32), `can_edit_account` (tests/fixtures/fastapi/main.py:135:36), `provide_database_interface` (tests/fixtures/fastapi/main.py:136:36)
- Declared protection: can_edit_account, provide_database_interface, require_user
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support permission_guarded coverage.
- Coverage support: evidence: evidence_0011, evidence_0012
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/fastapi/main.py:134:32 (high)
    - Symbol: `require_user` (tests/fixtures/fastapi/main.py:134:32)
  - permission_check `permission_guard` at tests/fixtures/fastapi/main.py:135:36 (high)
    - Symbol: `can_edit_account` (tests/fixtures/fastapi/main.py:135:36)
- Data mutations: none

<a id="route-route_0018"></a>
### route_0018 GET `/reports`

- Framework: fast_api
- Handler: `dynamic_reports` (tests/fixtures/fastapi/main.py:86:5)
- Route location: tests/fixtures/fastapi/main.py:85:2
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

<a id="route-route_0019"></a>
### route_0019 GET `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:91:5)
- Route location: tests/fixtures/fastapi/main.py:90:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0020"></a>
### route_0020 POST `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:91:5)
- Route location: tests/fixtures/fastapi/main.py:90:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0021"></a>
### route_0021 ANY `/fallback`

- Framework: fast_api
- Handler: `fallback` (tests/fixtures/fastapi/main.py:96:5)
- Route location: tests/fixtures/fastapi/main.py:95:2
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

<a id="route-route_0022"></a>
### route_0022 GET `/generated`

- Framework: fast_api
- Handler: `generated_path` (tests/fixtures/fastapi/main.py:101:5)
- Route location: tests/fixtures/fastapi/main.py:100:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0023"></a>
### route_0023 GET `/constant`

- Framework: fast_api
- Handler: `constant_alias_path` (tests/fixtures/fastapi/main.py:106:5)
- Route location: tests/fixtures/fastapi/main.py:105:2
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0024"></a>
### route_0024 GET `&lt;dynamic&gt;`

- Framework: fast_api
- Handler: `unresolved_runtime_path` (tests/fixtures/fastapi/main.py:111:5)
- Route location: tests/fixtures/fastapi/main.py:110:2
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

<a id="route-route_0025"></a>
### route_0025 GET `/factory/status`

- Framework: fast_api
- Handler: `default_status_path` (tests/fixtures/fastapi/main.py:120:9)
- Route location: tests/fixtures/fastapi/main.py:119:6
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0026"></a>
### route_0026 GET `/factory/ready`

- Framework: fast_api
- Handler: `default_ready_path` (tests/fixtures/fastapi/main.py:124:9)
- Route location: tests/fixtures/fastapi/main.py:123:6
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
| warning | fastapi_dynamic_api_route_methods | tests/fixtures/fastapi/main.py:95:2 | FastAPI api_route methods are dynamic or missing |
| warning | fastapi_dynamic_route_path | tests/fixtures/fastapi/main.py:110:2 | FastAPI route path is dynamic and could not be resolved |
| warning | fastapi_dynamic_include_router_prefix | tests/fixtures/fastapi/main.py:140:1 | FastAPI include_router prefix is dynamic and could not be resolved |

## Skipped Files

No files were skipped.