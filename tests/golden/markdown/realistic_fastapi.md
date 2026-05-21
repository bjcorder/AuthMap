# AuthMap Report

- Tool: authmap 1.0.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/realistic/fastapi
- Source files: 4
- Routes: 9
- Evidence entries: 14
- Mutations: 4
- Policy cases: 13
- Diagnostics: 3
- Frameworks: fast_api: 9

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0001](#route-route_0001) | GET /api/accounts/{account_id} | risk is review_required |
| [route_0003](#route-route_0003) | PATCH /api/accounts/{account_id} | risk is review_required |
| [route_0004](#route-route_0004) | DELETE /api/accounts/{account_id} | risk is review_required |
| [route_0006](#route-route_0006) | POST /api/accounts/dynamic-service | risk is review_required |
| [route_0009](#route-route_0009) | GET /reports | confidence is medium; router prefix is dynamic and was not included in the route path; include_router prefix is dynamic and was not included in the route path |
| diagnostic | fastapi_dynamic_router_prefix | FastAPI router prefix is dynamic and could not be resolved at tests/fixtures/realistic/fastapi/main.py:7:18 |
| diagnostic | policy.dynamic_behavior | Dynamic policy evidence requires review. at tests/fixtures/realistic/fastapi/app/routers/accounts.py:26:12 |
| diagnostic | fastapi_dynamic_include_router_prefix | FastAPI include_router prefix is dynamic and could not be resolved at tests/fixtures/realistic/fastapi/main.py:44:1 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | fast_api | GET | /api/accounts/{account_id} | \`read_account\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:5) | none | high | authn_only | review_required |
| [route_0002](#route-route_0002) | fast_api | POST | /api/accounts | \`create_account_route\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:5) | none | high | ownership_guarded | low |
| [route_0003](#route-route_0003) | fast_api | PATCH | /api/accounts/{account_id} | \`update_account_route\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:25:5) | none | high | permission_guarded | review_required |
| [route_0004](#route-route_0004) | fast_api | DELETE | /api/accounts/{account_id} | \`delete_account_route\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:32:5) | none | high | admin_guarded | review_required |
| [route_0005](#route-route_0005) | fast_api | POST | /api/accounts/service | \`service_create_account\` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:5) | none | high | ownership_guarded | low |
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
- Params: account_id (high)
- Declared protection: require_user
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, path_param.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal.
- Coverage support: evidence: evidence_0001, evidence_0002; weak evidence: evidence_0001; policy cases: policy_case_0001; sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
- Coverage uncertainty:
  - Low-confidence authorization evidence was detected.
- PolicyLens:
  - policy_case_0001: effective_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:40 (high)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0001
    - Cites evidence: evidence_0002
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:11:2 (low)
    - Symbol: `account_id` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:11:2)
    - Note: Route parameter name suggests tenant or ownership context but is not proof of scoping
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:40 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:12:48)
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 POST `/api/accounts`

- Framework: fast_api
- Handler: `create_account_route` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:16:2
- Middleware: none
- Declared protection: require_user, owner_id
- Confidence: high
- Coverage: ownership_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support ownership_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0003, evidence_0004; mutations: mutation_0001; links: link_0001; policy cases: policy_case_0002, policy_case_0003; sensitivity: account_path, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0002: effective_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:49 (high)
    - Summary: 2 evidence support(s) route protection: authn, ownership_check.
    - Cites coverage: route_0002
    - Cites evidence: evidence_0003, evidence_0004
    - Cites mutations: mutation_0001
    - Inputs: identity, ownership
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0003: linked_mutation_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:16:2 (high)
    - Summary: Route reaches linked mutation(s): mutation_0001 (Account).
    - Cites coverage: route_0002
    - Cites mutations: mutation_0001
    - Cites links: link_0001
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:49 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:17:57)
  - ownership_check `mutation_scope` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:18:5 (high)
    - Symbol: `owner_id` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:18:5)
    - Note: Mutation input includes ownership scoping
- Data mutations:
  - create `Account` via `sqlalchemy` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:19:5 (medium)

<a id="route-route_0003"></a>
### route_0003 PATCH `/api/accounts/{account_id}`

- Framework: fast_api
- Handler: `update_account_route` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:25:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:24:2
- Middleware: none
- Params: account_id (high)
- Declared protection: can_edit_account, dynamic_policy_check
- Confidence: high
- Coverage: permission_guarded (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal, route_param_mutation_without_scope.
- Coverage support: evidence: evidence_0005, evidence_0006, evidence_0007; weak evidence: evidence_0005, evidence_0007; mutations: mutation_0003; links: link_0002; policy cases: policy_case_0004, policy_case_0005, policy_case_0006; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Can the dynamic authorization path be confirmed?
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- PolicyLens:
  - policy_case_0004: effective_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:25:48 (high)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0003
    - Cites evidence: evidence_0006
    - Cites mutations: mutation_0003
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0005: linked_mutation_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:24:2 (medium)
    - Summary: Route reaches linked mutation(s): mutation_0003 (Account).
    - Cites coverage: route_0003
    - Cites mutations: mutation_0003
    - Cites links: link_0002
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
  - policy_case_0006: dynamic at tests/fixtures/realistic/fastapi/app/routers/accounts.py:26:12 (low)
    - Summary: Dynamic policy behavior requires review.
    - Cites coverage: route_0003
    - Cites evidence: evidence_0007
    - Inputs: dynamic_policy_check
    - Branch: dynamic policy dispatch -> review_required (reachable)
    - Question: Can the dynamic authorization path be confirmed?
    - Uncertainty: Dynamic authorization evidence requires review.
- Auth evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:24:2 (low)
    - Symbol: `account_id` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:24:2)
    - Note: Route parameter name suggests tenant or ownership context but is not proof of scoping
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
- Params: account_id (high)
- Declared protection: require_admin
- Confidence: high
- Coverage: admin_guarded (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal, route_param_mutation_without_scope.
- Coverage support: evidence: evidence_0008, evidence_0009; weak evidence: evidence_0008; mutations: mutation_0004; links: link_0003; policy cases: policy_case_0007, policy_case_0008; sensitivity: account_path, linked_mutation, path_param, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Low-confidence authorization evidence was detected.
- PolicyLens:
  - policy_case_0007: effective_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:32:48 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0004
    - Cites evidence: evidence_0009
    - Cites mutations: mutation_0004
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0008: linked_mutation_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:31:2 (medium)
    - Summary: Route reaches linked mutation(s): mutation_0004 (Account).
    - Cites coverage: route_0004
    - Cites mutations: mutation_0004
    - Cites links: link_0003
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:31:2 (low)
    - Symbol: `account_id` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:31:2)
    - Note: Route parameter name suggests tenant or ownership context but is not proof of scoping
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
- Declared protection: require_user, owner_id
- Confidence: high
- Coverage: ownership_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support ownership_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0010, evidence_0011; mutations: mutation_0002; links: link_0004; policy cases: policy_case_0009, policy_case_0010; sensitivity: account_path, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0009: effective_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:33 (medium)
    - Summary: 2 evidence support(s) route protection: authn, ownership_check.
    - Cites coverage: route_0005
    - Cites evidence: evidence_0010, evidence_0011
    - Cites mutations: mutation_0002
    - Inputs: identity, ownership
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0010: linked_mutation_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:36:2 (medium)
    - Summary: Route reaches linked mutation(s): mutation_0002 (Account).
    - Cites coverage: route_0005
    - Cites mutations: mutation_0002
    - Cites links: link_0004
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:33 (high)
    - Symbol: `require_user` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:37:41)
  - ownership_check `mutation_scope` at tests/fixtures/realistic/fastapi/app/services/accounts.py:11:5 (medium)
    - Symbol: `owner_id` (tests/fixtures/realistic/fastapi/app/services/accounts.py:11:5)
    - Note: Mutation input includes ownership scoping
    - Note: One-hop service call \`create_account\` reaches \`create_account\`
- Data mutations:
  - create `Account` via `sqlalchemy` at tests/fixtures/realistic/fastapi/app/services/accounts.py:12:5 (medium)

<a id="route-route_0006"></a>
### route_0006 POST `/api/accounts/dynamic-service`

- Framework: fast_api
- Handler: `dynamic_service_create` (tests/fixtures/realistic/fastapi/app/routers/accounts.py:42:5)
- Route location: tests/fixtures/realistic/fastapi/app/routers/accounts.py:41:2
- Middleware: none
- Declared protection: require_user
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, unsafe_method.
- Coverage support: evidence: evidence_0012; links: link_0005; policy cases: policy_case_0011; sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0011: effective_protection at tests/fixtures/realistic/fastapi/app/routers/accounts.py:42:33 (high)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0006
    - Cites evidence: evidence_0012
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
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
- Declared protection: require_admin
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): admin_path.
- Coverage support: evidence: evidence_0013; policy cases: policy_case_0012; sensitivity: admin_path
- Reviewer questions:
  - Should this route require an admin or role guard?
- PolicyLens:
  - policy_case_0012: effective_protection at tests/fixtures/realistic/fastapi/main.py:34:20 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0008
    - Cites evidence: evidence_0013
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
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
- Declared protection: require_user
- Confidence: medium
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0014; policy cases: policy_case_0013
- Coverage uncertainty:
  - Route inventory confidence is not high.
- PolicyLens:
  - policy_case_0013: effective_protection at tests/fixtures/realistic/fastapi/main.py:39:26 (high)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0009
    - Cites evidence: evidence_0014
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
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
| warning | policy.dynamic_behavior | tests/fixtures/realistic/fastapi/app/routers/accounts.py:26:12 | Dynamic policy evidence requires review. |
| warning | fastapi_dynamic_include_router_prefix | tests/fixtures/realistic/fastapi/main.py:44:1 | FastAPI include_router prefix is dynamic and could not be resolved |

## Skipped Files

No files were skipped.