# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/django
- Source files: 5
- Routes: 18
- Evidence entries: 2
- Mutations: 7
- Diagnostics: 6
- Frameworks: django: 5, django_rest_framework: 13

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0001](#route-route_0001) | DELETE /accounts/api/users/{uuid} | risk is high |
| [route_0004](#route-route_0004) | PATCH /accounts/api/users/{uuid} | risk is high |
| [route_0005](#route-route_0005) | POST /accounts/api/users | risk is high |
| [route_0006](#route-route_0006) | POST /accounts/api/users/{uuid}/disable | risk is high |
| [route_0007](#route-route_0007) | PUT /accounts/api/users/{uuid} | risk is high |
| [route_0010](#route-route_0010) | GET &lt;dynamic&gt; | confidence is medium; DRF router prefix is dynamic and was emitted as &lt;dynamic&gt;; DRF router basename is dynamic |
| [route_0013](#route-route_0013) | POST /accounts/readonly-api/audit/refresh | risk is high |
| [route_0014](#route-route_0014) | ANY /accounts | risk is high |
| [route_0015](#route-route_0015) | ANY /accounts/users/&lt;int:pk&gt;/ | risk is review_required; coverage is unknown_or_dynamic |
| [route_0016](#route-route_0016) | ANY &lt;dynamic&gt; | confidence is medium; Django URL path is dynamic and was emitted as &lt;dynamic&gt;; risk is high |
| [route_0017](#route-route_0017) | ANY /status/ | risk is high |
| [route_0018](#route-route_0018) | ANY /^legacy/(?P&lt;slug&gt;\[-\w\]+)/$ | Django re_path regex literal preserved as route path; risk is high |
| diagnostic | drf_dynamic_basename | DRF router basename is dynamic and could not be resolved at tests/fixtures/django/accounts/urls.py:9:1 |
| diagnostic | drf_dynamic_router_prefix | DRF router registration prefix is dynamic and could not be resolved at tests/fixtures/django/accounts/urls.py:9:17 |
| diagnostic | django_dynamic_include | Django include target is dynamic and could not be resolved at tests/fixtures/django/project/urls.py:10:30 |
| diagnostic | django_custom_router | DRF custom router behavior could not be resolved statically at tests/fixtures/django/accounts/urls.py:11:17 |
| diagnostic | django_dynamic_url_path | Django URL path is dynamic and could not be resolved at tests/fixtures/django/accounts/urls.py:20:10 |
| diagnostic | django_urlpattern_context_uncertain | Django URL helper call is outside a statically recognized urlpatterns context at tests/fixtures/django/accounts/urls.py:29:5 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | django_rest_framework | DELETE | /accounts/api/users/{uuid} | \`UserViewSet.destroy\` (tests/fixtures/django/accounts/views.py:41:7) | none | high | unauthenticated | high |
| [route_0002](#route-route_0002) | django_rest_framework | GET | /accounts/api/users | \`UserViewSet.list\` (tests/fixtures/django/accounts/views.py:44:9) | none | high | permission_guarded | low |
| [route_0003](#route-route_0003) | django_rest_framework | GET | /accounts/api/users/{uuid} | \`UserViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:41:7) | none | high | unauthenticated | medium |
| [route_0004](#route-route_0004) | django_rest_framework | PATCH | /accounts/api/users/{uuid} | \`UserViewSet.partial_update\` (tests/fixtures/django/accounts/views.py:41:7) | none | high | unauthenticated | high |
| [route_0005](#route-route_0005) | django_rest_framework | POST | /accounts/api/users | \`UserViewSet.create\` (tests/fixtures/django/accounts/views.py:48:9) | none | high | unauthenticated | high |
| [route_0006](#route-route_0006) | django_rest_framework | POST | /accounts/api/users/{uuid}/disable | \`UserViewSet.disable\` (tests/fixtures/django/accounts/views.py:52:9) | none | high | unauthenticated | high |
| [route_0007](#route-route_0007) | django_rest_framework | PUT | /accounts/api/users/{uuid} | \`UserViewSet.update\` (tests/fixtures/django/accounts/views.py:41:7) | none | high | unauthenticated | high |
| [route_0008](#route-route_0008) | django_rest_framework | GET | /accounts/api/readonly | \`ReadOnlyAccountViewSet.list\` (tests/fixtures/django/accounts/views.py:56:7) | none | high | unauthenticated | medium |
| [route_0009](#route-route_0009) | django_rest_framework | GET | /accounts/api/readonly/{pk} | \`ReadOnlyAccountViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:56:7) | none | high | unauthenticated | medium |
| [route_0010](#route-route_0010) | django_rest_framework | GET | &lt;dynamic&gt; | \`DynamicViewSet.list\` (tests/fixtures/django/accounts/views.py:71:9) | none | medium | unauthenticated | low |
| [route_0011](#route-route_0011) | django_rest_framework | GET | /accounts/readonly-api/audit | \`ReadOnlyAuditViewSet.list\` (tests/fixtures/django/accounts/views.py:64:7) | none | high | unauthenticated | medium |
| [route_0012](#route-route_0012) | django_rest_framework | GET | /accounts/readonly-api/audit/{pk} | \`ReadOnlyAuditViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:64:7) | none | high | unauthenticated | medium |
| [route_0013](#route-route_0013) | django_rest_framework | POST | /accounts/readonly-api/audit/refresh | \`ReadOnlyAuditViewSet.refresh\` (tests/fixtures/django/accounts/views.py:66:9) | none | high | unauthenticated | high |
| [route_0014](#route-route_0014) | django | ANY | /accounts | \`index\` (tests/fixtures/django/accounts/views.py:20:5) | none | high | unauthenticated | high |
| [route_0015](#route-route_0015) | django | ANY | /accounts/users/&lt;int:pk&gt;/ | \`AccountDetailView\` (tests/fixtures/django/accounts/views.py:28:7) | none | high | unknown_or_dynamic | review_required |
| [route_0016](#route-route_0016) | django | ANY | &lt;dynamic&gt; | \`dynamic_view\` (tests/fixtures/django/accounts/views.py:24:5) | none | medium | unauthenticated | high |
| [route_0017](#route-route_0017) | django | ANY | /status/ | \`status\` (tests/fixtures/django/accounts/views.py:12:5) | none | high | unauthenticated | high |
| [route_0018](#route-route_0018) | django | ANY | /^legacy/(?P&lt;slug&gt;\[-\w\]+)/$ | \`legacy_detail\` (tests/fixtures/django/accounts/views.py:16:5) | none | high | unauthenticated | high |

## Data Mutations

| ID | Operation | Library | Resource | Location | Confidence | Review |
| --- | --- | --- | --- | --- | --- | --- |
| mutation_0001 | create | django_orm | Account | tests/fixtures/django/accounts/services.py:5:12 | high | none |
| mutation_0002 | save | django_orm | Account | tests/fixtures/django/accounts/views.py:34:9 | medium | none |
| mutation_0003 | delete | django_orm | Account | tests/fixtures/django/accounts/views.py:38:16 | high | none |
| mutation_0004 | create | django_orm | Account | tests/fixtures/django/accounts/views.py:49:16 | high | none |
| mutation_0005 | bulk_update | django_orm | Account | tests/fixtures/django/accounts/views.py:53:16 | high | none |
| mutation_0006 | delete | django_orm | Account | tests/fixtures/django/accounts/views.py:59:20 | high | none |
| mutation_0007 | bulk_update | django_orm | Account | tests/fixtures/django/accounts/views.py:67:16 | high | none |

## Route Details

<a id="route-route_0001"></a>
### route_0001 DELETE `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.destroy` (tests/fixtures/django/accounts/views.py:41:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 GET `/accounts/api/users`

- Framework: django_rest_framework
- Handler: `UserViewSet.list` (tests/fixtures/django/accounts/views.py:44:9)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, user_path.
- Coverage support: evidence: evidence_0001; sensitivity: account_path, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence:
  - permission_check `permission_guard` at tests/fixtures/django/accounts/views.py:45:9 (high)
    - Symbol: `require_permission` (tests/fixtures/django/accounts/views.py:45:9)
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 GET `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.retrieve` (tests/fixtures/django/accounts/views.py:41:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, user_path.
- Coverage support: sensitivity: account_path, path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 PATCH `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.partial_update` (tests/fixtures/django/accounts/views.py:41:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 POST `/accounts/api/users`

- Framework: django_rest_framework
- Handler: `UserViewSet.create` (tests/fixtures/django/accounts/views.py:48:9)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method, user_path.; Linked data mutation(s) increase review sensitivity.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: mutations: mutation_0004; links: link_0001; sensitivity: account_path, linked_mutation, unsafe_method, user_path
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations:
  - create `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:49:16 (high)

<a id="route-route_0006"></a>
### route_0006 POST `/accounts/api/users/{uuid}/disable`

- Framework: django_rest_framework
- Handler: `UserViewSet.disable` (tests/fixtures/django/accounts/views.py:52:9)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method, user_path.; Linked data mutation(s) increase review sensitivity.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: mutations: mutation_0005; links: link_0002; sensitivity: account_path, linked_mutation, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations:
  - bulk_update `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:53:16 (high)

<a id="route-route_0007"></a>
### route_0007 PUT `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.update` (tests/fixtures/django/accounts/views.py:41:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 GET `/accounts/api/readonly`

- Framework: django_rest_framework
- Handler: `ReadOnlyAccountViewSet.list` (tests/fixtures/django/accounts/views.py:56:7)
- Route location: tests/fixtures/django/accounts/urls.py:8:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path.
- Coverage support: sensitivity: account_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 GET `/accounts/api/readonly/{pk}`

- Framework: django_rest_framework
- Handler: `ReadOnlyAccountViewSet.retrieve` (tests/fixtures/django/accounts/views.py:56:7)
- Route location: tests/fixtures/django/accounts/urls.py:8:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 GET `&lt;dynamic&gt;`

- Framework: django_rest_framework
- Handler: `DynamicViewSet.list` (tests/fixtures/django/accounts/views.py:71:9)
- Route location: tests/fixtures/django/accounts/urls.py:9:1
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - DRF router prefix is dynamic and was emitted as &lt;dynamic&gt;
  - DRF router basename is dynamic
- Auth evidence: none
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 GET `/accounts/readonly-api/audit`

- Framework: django_rest_framework
- Handler: `ReadOnlyAuditViewSet.list` (tests/fixtures/django/accounts/views.py:64:7)
- Route location: tests/fixtures/django/accounts/urls.py:13:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path.
- Coverage support: sensitivity: account_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 GET `/accounts/readonly-api/audit/{pk}`

- Framework: django_rest_framework
- Handler: `ReadOnlyAuditViewSet.retrieve` (tests/fixtures/django/accounts/views.py:64:7)
- Route location: tests/fixtures/django/accounts/urls.py:13:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 POST `/accounts/readonly-api/audit/refresh`

- Framework: django_rest_framework
- Handler: `ReadOnlyAuditViewSet.refresh` (tests/fixtures/django/accounts/views.py:66:9)
- Route location: tests/fixtures/django/accounts/urls.py:13:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: mutations: mutation_0007; links: link_0003; sensitivity: account_path, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations:
  - bulk_update `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:67:16 (high)

<a id="route-route_0014"></a>
### route_0014 ANY `/accounts`

- Framework: django
- Handler: `index` (tests/fixtures/django/accounts/views.py:20:5)
- Route location: tests/fixtures/django/accounts/urls.py:16:5
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, any_method, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: mutations: mutation_0001; links: link_0004; sensitivity: account_path, any_method, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations:
  - create `Account` via `django_orm` at tests/fixtures/django/accounts/services.py:5:12 (high)

<a id="route-route_0015"></a>
### route_0015 ANY `/accounts/users/&lt;int:pk&gt;/`

- Framework: django
- Handler: `AccountDetailView` (tests/fixtures/django/accounts/views.py:28:7)
- Route location: tests/fixtures/django/accounts/urls.py:17:5
- Middleware: none
- Confidence: high
- Coverage: unknown_or_dynamic (review_required)
- Coverage rationale: 1 weak or dynamic authorization evidence item(s) were detected.; Sensitive route modifier(s): account_path, any_method, linked_mutation, path_param, unsafe_method, user_path.; Linked data mutation(s) increase review sensitivity.
- Coverage support: evidence: evidence_0002; weak evidence: evidence_0002; mutations: mutation_0002, mutation_0003; links: link_0005, link_0006, link_0007; sensitivity: account_path, any_method, linked_mutation, path_param, unsafe_method, user_path
- Reviewer questions:
  - Can the dynamic authorization path be confirmed?
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Dynamic authorization evidence requires review.
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - unknown_dynamic_check `handler_condition` at tests/fixtures/django/accounts/views.py:31:12 (low)
    - Symbol: `AccountDetailView` (tests/fixtures/django/accounts/views.py:28:7)
    - Note: Handler condition references user authorization attributes; review required
- Data mutations:
  - save `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:34:9 (medium)
  - delete `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:38:16 (high)

<a id="route-route_0016"></a>
### route_0016 ANY `&lt;dynamic&gt;`

- Framework: django
- Handler: `dynamic_view` (tests/fixtures/django/accounts/views.py:24:5)
- Route location: tests/fixtures/django/accounts/urls.py:20:5
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
  - Django URL path is dynamic and was emitted as &lt;dynamic&gt;
- Auth evidence: none
- Data mutations: none

<a id="route-route_0017"></a>
### route_0017 ANY `/status/`

- Framework: django
- Handler: `status` (tests/fixtures/django/accounts/views.py:12:5)
- Route location: tests/fixtures/django/project/urls.py:7:5
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): any_method, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0018"></a>
### route_0018 ANY `/^legacy/(?P&lt;slug&gt;\[-\w\]+)/$`

- Framework: django
- Handler: `legacy_detail` (tests/fixtures/django/accounts/views.py:16:5)
- Route location: tests/fixtures/django/project/urls.py:8:5
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): any_method, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Uncertainty notes:
  - Django re_path regex literal preserved as route path
- Auth evidence: none
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | drf_dynamic_basename | tests/fixtures/django/accounts/urls.py:9:1 | DRF router basename is dynamic and could not be resolved |
| warning | drf_dynamic_router_prefix | tests/fixtures/django/accounts/urls.py:9:17 | DRF router registration prefix is dynamic and could not be resolved |
| warning | django_dynamic_include | tests/fixtures/django/project/urls.py:10:30 | Django include target is dynamic and could not be resolved |
| warning | django_custom_router | tests/fixtures/django/accounts/urls.py:11:17 | DRF custom router behavior could not be resolved statically |
| warning | django_dynamic_url_path | tests/fixtures/django/accounts/urls.py:20:10 | Django URL path is dynamic and could not be resolved |
| warning | django_urlpattern_context_uncertain | tests/fixtures/django/accounts/urls.py:29:5 | Django URL helper call is outside a statically recognized urlpatterns context |

## Skipped Files

No files were skipped.