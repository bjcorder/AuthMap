# AuthMap Drift Report

- Mode: enforce
- Base: tests/fixtures/diff/base
- Head: tests/fixtures/diff/head
- Enforce fail-on: added_high_risk_route, auth_downgrade, new_linked_mutation, removed_authorization_evidence, policy_decision_change
- Config source: none

## Summary

- Total changes: 9
- Added routes: 1
- Removed routes: 0
- Handler changes: 0
- Evidence changes: 2
- Removed evidence: 2
- Coverage changes: 2
- New linked mutations: 0
- Policy changes: 2
- Blocking changes: 6

## Changes

| ID | Severity | Kind | Route | Direction | Fail Category | Blocking | Message |
| --- | --- | --- | --- | --- | --- | --- | --- |
| drift_0001 | note | evidence_changed | fast_api GET /accounts/{account_id} | none | none | no | Authorization evidence changed for GET /accounts/{account_id} |
| drift_0002 | error | removed_evidence | fast_api GET /accounts/{account_id} | downgrade | removed_authorization_evidence | yes | Removed tenant_check evidence for GET /accounts/{account_id}: tenant_guard |
| drift_0003 | error | coverage_changed | fast_api GET /accounts/{account_id} | downgrade | auth_downgrade | yes | Coverage changed for GET /accounts/{account_id} from tenant_guarded (low) to authn_only (review_required) |
| drift_0004 | error | policy_changed | fast_api GET /accounts/{account_id} | changed | policy_decision_change | yes | Policy decision cases changed for GET /accounts/{account_id} |
| drift_0005 | note | evidence_changed | fast_api PATCH /accounts/{account_id} | none | none | no | Authorization evidence changed for PATCH /accounts/{account_id} |
| drift_0006 | error | removed_evidence | fast_api PATCH /accounts/{account_id} | downgrade | removed_authorization_evidence | yes | Removed permission_check evidence for PATCH /accounts/{account_id}: permission_guard |
| drift_0007 | error | coverage_changed | fast_api PATCH /accounts/{account_id} | downgrade | auth_downgrade | yes | Coverage changed for PATCH /accounts/{account_id} from permission_guarded (review_required) to authn_only (review_required) |
| drift_0008 | error | policy_changed | fast_api PATCH /accounts/{account_id} | changed | policy_decision_change | yes | Policy decision cases changed for PATCH /accounts/{account_id} |
| drift_0009 | warning | added_route | fast_api POST /accounts | none | added_review_required_route | no | Added route POST /accounts |