# AuthMap Tenant Review

- Schema version: 0.1.0
- Routes: 15
- Relevant routes: 12
- Diagnostics: 4

## GET `/:accountId`

- Route ID: route_0002
- Framework: express
- Coverage: authn_only (review_required)
- Rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, path_param.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal.
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
- Uncertainty:
  - Low-confidence authorization evidence was detected.
  - Route inventory confidence is not high.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:13:1 (low)
- Linked mutations: none

## GET `/api/:accountId`

- Route ID: route_0003
- Framework: express
- Coverage: authn_only (review_required)
- Rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): account_path, path_param.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal.
- Reviewer questions:
  - Is duplicated guard evidence intentional or redundant?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
- Uncertainty:
  - Duplicated policy evidence may be safe but should be reviewed.
  - Low-confidence authorization evidence was detected.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:13:1 (low)
- Linked mutations: none

## POST `/`

- Route ID: route_0004
- Framework: express
- Coverage: ownership_guarded (low)
- Rationale: 2 strong authorization evidence item(s) support ownership_guarded coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Route inventory confidence is not high.
- Tenant evidence:
  - ownership_check `mutation_scope` at tests/fixtures/realistic/express/routes/accounts.ts:18:9 (high)
- Linked mutations:
  - mutation_0001 create `account`

## POST `/api`

- Route ID: route_0005
- Framework: express
- Coverage: ownership_guarded (low)
- Rationale: 3 strong authorization evidence item(s) support ownership_guarded coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.
- Reviewer questions:
  - Is duplicated guard evidence intentional or redundant?
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Duplicated policy evidence may be safe but should be reviewed.
- Tenant evidence:
  - ownership_check `mutation_scope` at tests/fixtures/realistic/express/routes/accounts.ts:18:9 (high)
- Linked mutations:
  - mutation_0001 create `account`

## PATCH `/:accountId`

- Route ID: route_0006
- Framework: express
- Coverage: permission_guarded (review_required)
- Rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal, route_param_mutation_without_scope.
- Reviewer questions:
  - Can the dynamic authorization path be confirmed?
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
  - Route inventory confidence is not high.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:24:1 (low)
- Linked mutations:
  - mutation_0003 update `account`

## PATCH `/api/:accountId`

- Route ID: route_0007
- Framework: express
- Coverage: permission_guarded (review_required)
- Rationale: 2 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal, route_param_mutation_without_scope.
- Reviewer questions:
  - Can the dynamic authorization path be confirmed?
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:24:1 (low)
- Linked mutations:
  - mutation_0003 update `account`

## DELETE `/:accountId`

- Route ID: route_0008
- Framework: express
- Coverage: admin_guarded (review_required)
- Rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal, route_param_mutation_without_scope.
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Low-confidence authorization evidence was detected.
  - Route inventory confidence is not high.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:36:1 (low)
- Linked mutations:
  - mutation_0004 delete `account`

## DELETE `/api/:accountId`

- Route ID: route_0009
- Framework: express
- Coverage: admin_guarded (review_required)
- Rationale: 2 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, only_weak_tenant_or_ownership_signal, route_param_mutation_without_scope.
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Low-confidence authorization evidence was detected.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:36:1 (low)
- Linked mutations:
  - mutation_0004 delete `account`

## POST `/api/service`

- Route ID: route_0010
- Framework: express
- Coverage: authn_only (review_required)
- Rationale: 2 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Reviewer questions:
  - Is duplicated guard evidence intentional or redundant?
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Duplicated policy evidence may be safe but should be reviewed.
- Tenant evidence: none
- Linked mutations:
  - mutation_0002 create `account`

## POST `/service`

- Route ID: route_0011
- Framework: express
- Coverage: authn_only (review_required)
- Rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Uncertainty:
  - Route inventory confidence is not high.
- Tenant evidence: none
- Linked mutations:
  - mutation_0002 create `account`

## GET `/api/tenant/:tenantId`

- Route ID: route_0014
- Framework: express
- Coverage: tenant_guarded (low)
- Rationale: 3 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Uncertainty:
  - Low-confidence authorization evidence was detected.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:50:1 (low)
  - tenant_check `tenant_guard` at tests/fixtures/realistic/express/routes/accounts.ts:50:33 (high)
  - tenant_check `mutation_scope` at tests/fixtures/realistic/express/routes/accounts.ts:51:14 (high)
- Linked mutations: none

## GET `/tenant/:tenantId`

- Route ID: route_0015
- Framework: express
- Coverage: tenant_guarded (low)
- Rationale: 2 strong authorization evidence item(s) support tenant_guarded coverage.; Sensitive route modifier(s): path_param, tenant_path.
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this route require tenant isolation checks?
- Uncertainty:
  - Low-confidence authorization evidence was detected.
  - Route inventory confidence is not high.
- Tenant evidence:
  - tenant_check `route_param_scope_signal` at tests/fixtures/realistic/express/routes/accounts.ts:50:1 (low)
  - tenant_check `tenant_guard` at tests/fixtures/realistic/express/routes/accounts.ts:50:33 (high)
  - tenant_check `mutation_scope` at tests/fixtures/realistic/express/routes/accounts.ts:51:14 (high)
- Linked mutations: none