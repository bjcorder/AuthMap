# AuthMap Controls Report

- Mode: enforce
- Base: tests/fixtures/diff/base
- Head: tests/fixtures/diff/head
- Enforce fail-on: added_high_risk_route, auth_downgrade, new_linked_mutation, removed_authorization_evidence, policy_decision_change

## Summary

- Total findings: 6
- Guard changes: 0
- Route guard changes: 2
- Permission changes: 1
- Tenant changes: 1
- Admin changes: 0
- Policy changes: 2
- Blocking findings: 6

## Findings

| ID | Severity | Control | Route | Source Change | Fail Category | Blocking | Message |
| --- | --- | --- | --- | --- | --- | --- | --- |
| control_0001 | error | tenant_helper | fast_api GET /accounts/{account_id} | removed_evidence | removed_authorization_evidence | yes | Removed tenant_check evidence for GET /accounts/{account_id}: tenant_guard |
| control_0002 | error | route_guard | fast_api GET /accounts/{account_id} | coverage_changed | auth_downgrade | yes | Coverage changed for GET /accounts/{account_id} from tenant_guarded (low) to authn_only (review_required) |
| control_0003 | error | policy_helper | fast_api GET /accounts/{account_id} | policy_changed | policy_decision_change | yes | Policy decision cases changed for GET /accounts/{account_id} |
| control_0004 | error | permission_map | fast_api PATCH /accounts/{account_id} | removed_evidence | removed_authorization_evidence | yes | Removed permission_check evidence for PATCH /accounts/{account_id}: permission_guard |
| control_0005 | error | route_guard | fast_api PATCH /accounts/{account_id} | coverage_changed | auth_downgrade | yes | Coverage changed for PATCH /accounts/{account_id} from permission_guarded (review_required) to authn_only (review_required) |
| control_0006 | error | policy_helper | fast_api PATCH /accounts/{account_id} | policy_changed | policy_decision_change | yes | Policy decision cases changed for PATCH /accounts/{account_id} |