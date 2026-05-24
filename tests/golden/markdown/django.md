# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/django
- Source files: 9
- Routes: 34
- Evidence entries: 28
- Mutations: 7
- Policy cases: 19
- Diagnostics: 7
- Frameworks: django: 7, django_rest_framework: 27

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0003](#route-route_0003) | DELETE /accounts/api/users/{uuid} | risk is high |
| [route_0006](#route-route_0006) | PATCH /accounts/api/users/{uuid} | risk is high |
| [route_0007](#route-route_0007) | POST /accounts/api/users | risk is review_required |
| [route_0008](#route-route_0008) | POST /accounts/api/users/{uuid}/disable | risk is review_required |
| [route_0009](#route-route_0009) | PUT /accounts/api/users/{uuid} | risk is high |
| [route_0013](#route-route_0013) | POST /accounts/api/custom-model/recalculate | confidence is medium; DRF action url_path is dynamic; emitted method name as path; risk is high |
| [route_0023](#route-route_0023) | POST /accounts/api/mixin-backed | risk is high |
| [route_0024](#route-route_0024) | GET &lt;dynamic&gt; | confidence is medium; DRF router prefix is dynamic and was emitted as &lt;dynamic&gt;; DRF router basename is dynamic |
| [route_0027](#route-route_0027) | POST /accounts/readonly-api/audit/refresh | risk is review_required |
| [route_0028](#route-route_0028) | ANY /accounts | risk is review_required |
| [route_0029](#route-route_0029) | ANY /accounts/users/&lt;int:pk&gt;/ | risk is review_required; coverage is unknown_or_dynamic |
| [route_0030](#route-route_0030) | ANY &lt;dynamic&gt; | confidence is medium; Django URL path is dynamic and was emitted as &lt;dynamic&gt;; risk is high |
| [route_0031](#route-route_0031) | ANY /accounts/generated | confidence is medium; Route emitted from statically matched generated URL helper |
| [route_0032](#route-route_0032) | ANY /accounts/generated/&lt;int:pk&gt;/edit | confidence is medium; Route emitted from statically matched generated URL helper |
| [route_0033](#route-route_0033) | ANY /status/ | risk is high |
| [route_0034](#route-route_0034) | ANY /legacy/{slug}/ | confidence is medium; Django re_path regex literal normalized as route path; risk is high |
| diagnostic | django_dynamic_include_helper | Django include helper could not be expanded statically: helper=get_urlconf; positional=\[\]; keywords=\[\] at tests/fixtures/django/project/urls.py:11:30 |
| diagnostic | drf_dynamic_basename | DRF router basename is dynamic and could not be resolved at tests/fixtures/django/accounts/urls.py:13:1 |
| diagnostic | drf_dynamic_router_prefix | DRF router registration prefix is dynamic and could not be resolved at tests/fixtures/django/accounts/urls.py:13:17 |
| diagnostic | django_custom_router | DRF custom router behavior could not be resolved statically at tests/fixtures/django/accounts/urls.py:15:17 |
| diagnostic | django_dynamic_url_path | Django URL path is dynamic and could not be resolved at tests/fixtures/django/accounts/urls.py:26:10 |
| diagnostic | django_urlpattern_context_uncertain | Django URL helper call is outside a statically recognized urlpatterns context at tests/fixtures/django/accounts/urls.py:34:5 |
| diagnostic | policy.dynamic_behavior | Dynamic policy evidence requires review. at tests/fixtures/django/accounts/views.py:44:12 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | django_rest_framework | GET | /exported-api/exported | \`ProjectReadOnlyViewSet.list\` (tests/fixtures/django/accounts/views.py:120:7) | none | high | permission_guarded | low |
| [route_0002](#route-route_0002) | django_rest_framework | GET | /exported-api/exported/{pk} | \`ProjectReadOnlyViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:120:7) | none | high | permission_guarded | low |
| [route_0003](#route-route_0003) | django_rest_framework | DELETE | /accounts/api/users/{uuid} | \`UserViewSet.destroy\` (tests/fixtures/django/accounts/views.py:64:7) | none | high | unauthenticated | high |
| [route_0004](#route-route_0004) | django_rest_framework | GET | /accounts/api/users | \`UserViewSet.list\` (tests/fixtures/django/accounts/views.py:67:9) | none | high | permission_guarded | low |
| [route_0005](#route-route_0005) | django_rest_framework | GET | /accounts/api/users/{uuid} | \`UserViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:64:7) | none | high | unauthenticated | medium |
| [route_0006](#route-route_0006) | django_rest_framework | PATCH | /accounts/api/users/{uuid} | \`UserViewSet.partial_update\` (tests/fixtures/django/accounts/views.py:64:7) | none | high | unauthenticated | high |
| [route_0007](#route-route_0007) | django_rest_framework | POST | /accounts/api/users | \`UserViewSet.create\` (tests/fixtures/django/accounts/views.py:71:9) | none | high | unauthenticated | review_required |
| [route_0008](#route-route_0008) | django_rest_framework | POST | /accounts/api/users/{uuid}/disable | \`UserViewSet.disable\` (tests/fixtures/django/accounts/views.py:75:9) | none | high | unauthenticated | review_required |
| [route_0009](#route-route_0009) | django_rest_framework | PUT | /accounts/api/users/{uuid} | \`UserViewSet.update\` (tests/fixtures/django/accounts/views.py:64:7) | none | high | unauthenticated | high |
| [route_0010](#route-route_0010) | django_rest_framework | GET | /accounts/api/readonly | \`ReadOnlyAccountViewSet.list\` (tests/fixtures/django/accounts/views.py:79:7) | none | high | unauthenticated | medium |
| [route_0011](#route-route_0011) | django_rest_framework | GET | /accounts/api/readonly/{pk} | \`ReadOnlyAccountViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:79:7) | none | high | unauthenticated | medium |
| [route_0012](#route-route_0012) | django_rest_framework | GET | /accounts/api/custom-model | \`CustomModelBackedViewSet.list\` (tests/fixtures/django/accounts/views.py:98:9) | none | high | unauthenticated | medium |
| [route_0013](#route-route_0013) | django_rest_framework | POST | /accounts/api/custom-model/recalculate | \`CustomModelBackedViewSet.recalculate\` (tests/fixtures/django/accounts/views.py:102:9) | none | medium | unauthenticated | high |
| [route_0014](#route-route_0014) | django_rest_framework | DELETE | /accounts/api/inherited/{pk} | \`InheritedProjectViewSet.destroy\` (tests/fixtures/django/accounts/views.py:132:7) | none | high | permission_guarded | low |
| [route_0015](#route-route_0015) | django_rest_framework | GET | /accounts/api/inherited | \`InheritedProjectViewSet.list\` (tests/fixtures/django/accounts/views.py:132:7) | none | high | permission_guarded | low |
| [route_0016](#route-route_0016) | django_rest_framework | GET | /accounts/api/inherited/{pk} | \`InheritedProjectViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:132:7) | none | high | permission_guarded | low |
| [route_0017](#route-route_0017) | django_rest_framework | PATCH | /accounts/api/inherited/{pk} | \`InheritedProjectViewSet.partial_update\` (tests/fixtures/django/accounts/views.py:132:7) | none | high | permission_guarded | low |
| [route_0018](#route-route_0018) | django_rest_framework | POST | /accounts/api/inherited | \`InheritedProjectViewSet.create\` (tests/fixtures/django/accounts/views.py:132:7) | none | high | permission_guarded | low |
| [route_0019](#route-route_0019) | django_rest_framework | PUT | /accounts/api/inherited/{pk} | \`InheritedProjectViewSet.update\` (tests/fixtures/django/accounts/views.py:132:7) | none | high | permission_guarded | low |
| [route_0020](#route-route_0020) | django_rest_framework | GET | /accounts/api/inherited-readonly | \`InheritedReadOnlyProjectViewSet.list\` (tests/fixtures/django/accounts/views.py:136:7) | none | high | permission_guarded | low |
| [route_0021](#route-route_0021) | django_rest_framework | GET | /accounts/api/inherited-readonly/{pk} | \`InheritedReadOnlyProjectViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:136:7) | none | high | permission_guarded | low |
| [route_0022](#route-route_0022) | django_rest_framework | GET | /accounts/api/mixin-backed | \`MixinBackedProjectViewSet.list\` (tests/fixtures/django/accounts/views.py:140:7) | none | high | unauthenticated | medium |
| [route_0023](#route-route_0023) | django_rest_framework | POST | /accounts/api/mixin-backed | \`MixinBackedProjectViewSet.create\` (tests/fixtures/django/accounts/views.py:140:7) | none | high | unauthenticated | high |
| [route_0024](#route-route_0024) | django_rest_framework | GET | &lt;dynamic&gt; | \`DynamicViewSet.list\` (tests/fixtures/django/accounts/views.py:107:9) | none | medium | unauthenticated | low |
| [route_0025](#route-route_0025) | django_rest_framework | GET | /accounts/readonly-api/audit | \`ReadOnlyAuditViewSet.list\` (tests/fixtures/django/accounts/views.py:87:7) | none | high | unauthenticated | medium |
| [route_0026](#route-route_0026) | django_rest_framework | GET | /accounts/readonly-api/audit/{pk} | \`ReadOnlyAuditViewSet.retrieve\` (tests/fixtures/django/accounts/views.py:87:7) | none | high | unauthenticated | medium |
| [route_0027](#route-route_0027) | django_rest_framework | POST | /accounts/readonly-api/audit/refresh | \`ReadOnlyAuditViewSet.refresh\` (tests/fixtures/django/accounts/views.py:89:9) | none | high | unauthenticated | review_required |
| [route_0028](#route-route_0028) | django | ANY | /accounts | \`index\` (tests/fixtures/django/accounts/views.py:33:5) | none | high | unauthenticated | review_required |
| [route_0029](#route-route_0029) | django | ANY | /accounts/users/&lt;int:pk&gt;/ | \`AccountDetailView\` (tests/fixtures/django/accounts/views.py:41:7) | none | high | unknown_or_dynamic | review_required |
| [route_0030](#route-route_0030) | django | ANY | &lt;dynamic&gt; | \`dynamic_view\` (tests/fixtures/django/accounts/views.py:37:5) | none | medium | unauthenticated | high |
| [route_0031](#route-route_0031) | django | ANY | /accounts/generated | \`GeneratedAccountListView\` (tests/fixtures/django/accounts/views.py:55:7) | none | medium | permission_guarded | low |
| [route_0032](#route-route_0032) | django | ANY | /accounts/generated/&lt;int:pk&gt;/edit | \`GeneratedAccountEditView\` (tests/fixtures/django/accounts/views.py:60:7) | none | medium | permission_guarded | low |
| [route_0033](#route-route_0033) | django | ANY | /status/ | \`status\` (tests/fixtures/django/accounts/views.py:25:5) | none | high | unauthenticated | high |
| [route_0034](#route-route_0034) | django | ANY | /legacy/{slug}/ | \`legacy_detail\` (tests/fixtures/django/accounts/views.py:29:5) | none | medium | unauthenticated | high |

## Data Mutations

| ID | Operation | Library | Resource | Location | Confidence | Review |
| --- | --- | --- | --- | --- | --- | --- |
| mutation_0001 | create | django_orm | Account | tests/fixtures/django/accounts/services.py:5:12 | high | none |
| mutation_0002 | save | django_orm | Account | tests/fixtures/django/accounts/views.py:47:9 | medium | none |
| mutation_0003 | delete | django_orm | Account | tests/fixtures/django/accounts/views.py:51:16 | high | none |
| mutation_0004 | create | django_orm | Account | tests/fixtures/django/accounts/views.py:72:16 | high | none |
| mutation_0005 | bulk_update | django_orm | Account | tests/fixtures/django/accounts/views.py:76:16 | high | none |
| mutation_0006 | delete | django_orm | Account | tests/fixtures/django/accounts/views.py:82:20 | high | none |
| mutation_0007 | bulk_update | django_orm | Account | tests/fixtures/django/accounts/views.py:90:16 | high | none |

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/exported-api/exported`

- Framework: django_rest_framework
- Handler: `ProjectReadOnlyViewSet.list` (tests/fixtures/django/accounts/views.py:120:7)
- Route location: tests/fixtures/django/accounts/api_urls.py:6:1
- Middleware: none
- Declared protection: permission_classes
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.
- Coverage support: evidence: evidence_0001; policy cases: policy_case_0001
- PolicyLens:
  - policy_case_0001: effective_protection at tests/fixtures/django/accounts/views.py:121:5 (high)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0001
    - Cites evidence: evidence_0001
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - permission_check `drf_permission_classes` at tests/fixtures/django/accounts/views.py:121:5 (high)
    - Symbol: `permission_classes` (tests/fixtures/django/accounts/views.py:121:5)
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 GET `/exported-api/exported/{pk}`

- Framework: django_rest_framework
- Handler: `ProjectReadOnlyViewSet.retrieve` (tests/fixtures/django/accounts/views.py:120:7)
- Route location: tests/fixtures/django/accounts/api_urls.py:6:1
- Middleware: none
- Params: pk (high)
- Declared protection: permission_classes
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): path_param.
- Coverage support: evidence: evidence_0002; policy cases: policy_case_0002; sensitivity: path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- PolicyLens:
  - policy_case_0002: effective_protection at tests/fixtures/django/accounts/views.py:121:5 (high)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0002
    - Cites evidence: evidence_0002
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - permission_check `drf_permission_classes` at tests/fixtures/django/accounts/views.py:121:5 (high)
    - Symbol: `permission_classes` (tests/fixtures/django/accounts/views.py:121:5)
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 DELETE `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.destroy` (tests/fixtures/django/accounts/views.py:64:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Params: uuid (high)
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 GET `/accounts/api/users`

- Framework: django_rest_framework
- Handler: `UserViewSet.list` (tests/fixtures/django/accounts/views.py:67:9)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Declared protection: require_permission
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, user_path.
- Coverage support: evidence: evidence_0003; policy cases: policy_case_0003; sensitivity: account_path, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- PolicyLens:
  - policy_case_0003: effective_protection at tests/fixtures/django/accounts/views.py:68:9 (high)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0004
    - Cites evidence: evidence_0003
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - permission_check `permission_guard` at tests/fixtures/django/accounts/views.py:68:9 (high)
    - Symbol: `require_permission` (tests/fixtures/django/accounts/views.py:68:9)
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 GET `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.retrieve` (tests/fixtures/django/accounts/views.py:64:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Params: uuid (high)
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, user_path.
- Coverage support: sensitivity: account_path, path_param, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 PATCH `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.partial_update` (tests/fixtures/django/accounts/views.py:64:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Params: uuid (high)
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 POST `/accounts/api/users`

- Framework: django_rest_framework
- Handler: `UserViewSet.create` (tests/fixtures/django/accounts/views.py:71:9)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (review_required)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method, user_path.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: mutations: mutation_0004; links: link_0001; policy cases: policy_case_0004; sensitivity: account_path, linked_mutation, unsafe_method, user_path
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0004: linked_mutation_protection at tests/fixtures/django/accounts/urls.py:7:1 (high)
    - Summary: Route reaches linked mutation(s): mutation_0004 (Account).
    - Cites coverage: route_0007
    - Cites mutations: mutation_0004
    - Cites links: link_0001
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence: none
- Data mutations:
  - create `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:72:16 (high)

<a id="route-route_0008"></a>
### route_0008 POST `/accounts/api/users/{uuid}/disable`

- Framework: django_rest_framework
- Handler: `UserViewSet.disable` (tests/fixtures/django/accounts/views.py:75:9)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Params: uuid (high)
- Confidence: high
- Coverage: unauthenticated (review_required)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, linked_mutation, path_param, unsafe_method, user_path.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, route_param_mutation_without_scope.
- Coverage support: mutations: mutation_0005; links: link_0002; policy cases: policy_case_0005; sensitivity: account_path, linked_mutation, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0005: linked_mutation_protection at tests/fixtures/django/accounts/urls.py:7:1 (high)
    - Summary: Route reaches linked mutation(s): mutation_0005 (Account).
    - Cites coverage: route_0008
    - Cites mutations: mutation_0005
    - Cites links: link_0002
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence: none
- Data mutations:
  - bulk_update `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:76:16 (high)

<a id="route-route_0009"></a>
### route_0009 PUT `/accounts/api/users/{uuid}`

- Framework: django_rest_framework
- Handler: `UserViewSet.update` (tests/fixtures/django/accounts/views.py:64:7)
- Route location: tests/fixtures/django/accounts/urls.py:7:1
- Middleware: none
- Params: uuid (high)
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param, unsafe_method, user_path.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, path_param, unsafe_method, user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 GET `/accounts/api/readonly`

- Framework: django_rest_framework
- Handler: `ReadOnlyAccountViewSet.list` (tests/fixtures/django/accounts/views.py:79:7)
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

<a id="route-route_0011"></a>
### route_0011 GET `/accounts/api/readonly/{pk}`

- Framework: django_rest_framework
- Handler: `ReadOnlyAccountViewSet.retrieve` (tests/fixtures/django/accounts/views.py:79:7)
- Route location: tests/fixtures/django/accounts/urls.py:8:1
- Middleware: none
- Params: pk (high)
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 GET `/accounts/api/custom-model`

- Framework: django_rest_framework
- Handler: `CustomModelBackedViewSet.list` (tests/fixtures/django/accounts/views.py:98:9)
- Route location: tests/fixtures/django/accounts/urls.py:9:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path.
- Coverage support: sensitivity: account_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 POST `/accounts/api/custom-model/recalculate`

- Framework: django_rest_framework
- Handler: `CustomModelBackedViewSet.recalculate` (tests/fixtures/django/accounts/views.py:102:9)
- Route location: tests/fixtures/django/accounts/urls.py:9:1
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - DRF action url_path is dynamic; emitted method name as path
- Auth evidence: none
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 DELETE `/accounts/api/inherited/{pk}`

- Framework: django_rest_framework
- Handler: `InheritedProjectViewSet.destroy` (tests/fixtures/django/accounts/views.py:132:7)
- Route location: tests/fixtures/django/accounts/urls.py:10:1
- Middleware: none
- Params: pk (high)
- Declared protection: is_authenticated, restrict, IsAuthenticated
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0004, evidence_0005, evidence_0006; policy cases: policy_case_0006; sensitivity: account_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0006: effective_protection at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Summary: 3 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0014
    - Cites evidence: evidence_0004, evidence_0005, evidence_0006
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `drf_permission_classes` at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Symbol: `IsAuthenticated` (tests/fixtures/django/accounts/views.py:112:5)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - authn `django_authenticated_user_check` at tests/fixtures/django/accounts/views.py:115:12 (medium)
    - Symbol: `is_authenticated` (tests/fixtures/django/accounts/views.py:115:12)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - permission_check `django_queryset_restrict` at tests/fixtures/django/accounts/views.py:116:29 (medium)
    - Symbol: `restrict` (tests/fixtures/django/accounts/views.py:116:29)
    - Note: Authorization evidence inherited from ProjectModelViewSet
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 GET `/accounts/api/inherited`

- Framework: django_rest_framework
- Handler: `InheritedProjectViewSet.list` (tests/fixtures/django/accounts/views.py:132:7)
- Route location: tests/fixtures/django/accounts/urls.py:10:1
- Middleware: none
- Declared protection: is_authenticated, restrict, IsAuthenticated
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path.
- Coverage support: evidence: evidence_0007, evidence_0008, evidence_0009; policy cases: policy_case_0007; sensitivity: account_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- PolicyLens:
  - policy_case_0007: effective_protection at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Summary: 3 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0015
    - Cites evidence: evidence_0007, evidence_0008, evidence_0009
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `drf_permission_classes` at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Symbol: `IsAuthenticated` (tests/fixtures/django/accounts/views.py:112:5)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - authn `django_authenticated_user_check` at tests/fixtures/django/accounts/views.py:115:12 (medium)
    - Symbol: `is_authenticated` (tests/fixtures/django/accounts/views.py:115:12)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - permission_check `django_queryset_restrict` at tests/fixtures/django/accounts/views.py:116:29 (medium)
    - Symbol: `restrict` (tests/fixtures/django/accounts/views.py:116:29)
    - Note: Authorization evidence inherited from ProjectModelViewSet
- Data mutations: none

<a id="route-route_0016"></a>
### route_0016 GET `/accounts/api/inherited/{pk}`

- Framework: django_rest_framework
- Handler: `InheritedProjectViewSet.retrieve` (tests/fixtures/django/accounts/views.py:132:7)
- Route location: tests/fixtures/django/accounts/urls.py:10:1
- Middleware: none
- Params: pk (high)
- Declared protection: is_authenticated, restrict, IsAuthenticated
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: evidence: evidence_0010, evidence_0011, evidence_0012; policy cases: policy_case_0008; sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- PolicyLens:
  - policy_case_0008: effective_protection at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Summary: 3 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0016
    - Cites evidence: evidence_0010, evidence_0011, evidence_0012
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `drf_permission_classes` at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Symbol: `IsAuthenticated` (tests/fixtures/django/accounts/views.py:112:5)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - authn `django_authenticated_user_check` at tests/fixtures/django/accounts/views.py:115:12 (medium)
    - Symbol: `is_authenticated` (tests/fixtures/django/accounts/views.py:115:12)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - permission_check `django_queryset_restrict` at tests/fixtures/django/accounts/views.py:116:29 (medium)
    - Symbol: `restrict` (tests/fixtures/django/accounts/views.py:116:29)
    - Note: Authorization evidence inherited from ProjectModelViewSet
- Data mutations: none

<a id="route-route_0017"></a>
### route_0017 PATCH `/accounts/api/inherited/{pk}`

- Framework: django_rest_framework
- Handler: `InheritedProjectViewSet.partial_update` (tests/fixtures/django/accounts/views.py:132:7)
- Route location: tests/fixtures/django/accounts/urls.py:10:1
- Middleware: none
- Params: pk (high)
- Declared protection: is_authenticated, restrict, IsAuthenticated
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0013, evidence_0014, evidence_0015; policy cases: policy_case_0009; sensitivity: account_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0009: effective_protection at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Summary: 3 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0017
    - Cites evidence: evidence_0013, evidence_0014, evidence_0015
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `drf_permission_classes` at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Symbol: `IsAuthenticated` (tests/fixtures/django/accounts/views.py:112:5)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - authn `django_authenticated_user_check` at tests/fixtures/django/accounts/views.py:115:12 (medium)
    - Symbol: `is_authenticated` (tests/fixtures/django/accounts/views.py:115:12)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - permission_check `django_queryset_restrict` at tests/fixtures/django/accounts/views.py:116:29 (medium)
    - Symbol: `restrict` (tests/fixtures/django/accounts/views.py:116:29)
    - Note: Authorization evidence inherited from ProjectModelViewSet
- Data mutations: none

<a id="route-route_0018"></a>
### route_0018 POST `/accounts/api/inherited`

- Framework: django_rest_framework
- Handler: `InheritedProjectViewSet.create` (tests/fixtures/django/accounts/views.py:132:7)
- Route location: tests/fixtures/django/accounts/urls.py:10:1
- Middleware: none
- Declared protection: is_authenticated, restrict, IsAuthenticated
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, unsafe_method.
- Coverage support: evidence: evidence_0016, evidence_0017, evidence_0018; policy cases: policy_case_0010; sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0010: effective_protection at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Summary: 3 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0018
    - Cites evidence: evidence_0016, evidence_0017, evidence_0018
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `drf_permission_classes` at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Symbol: `IsAuthenticated` (tests/fixtures/django/accounts/views.py:112:5)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - authn `django_authenticated_user_check` at tests/fixtures/django/accounts/views.py:115:12 (medium)
    - Symbol: `is_authenticated` (tests/fixtures/django/accounts/views.py:115:12)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - permission_check `django_queryset_restrict` at tests/fixtures/django/accounts/views.py:116:29 (medium)
    - Symbol: `restrict` (tests/fixtures/django/accounts/views.py:116:29)
    - Note: Authorization evidence inherited from ProjectModelViewSet
- Data mutations: none

<a id="route-route_0019"></a>
### route_0019 PUT `/accounts/api/inherited/{pk}`

- Framework: django_rest_framework
- Handler: `InheritedProjectViewSet.update` (tests/fixtures/django/accounts/views.py:132:7)
- Route location: tests/fixtures/django/accounts/urls.py:10:1
- Middleware: none
- Params: pk (high)
- Declared protection: is_authenticated, restrict, IsAuthenticated
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param, unsafe_method.
- Coverage support: evidence: evidence_0019, evidence_0020, evidence_0021; policy cases: policy_case_0011; sensitivity: account_path, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0011: effective_protection at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Summary: 3 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0019
    - Cites evidence: evidence_0019, evidence_0020, evidence_0021
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `drf_permission_classes` at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Symbol: `IsAuthenticated` (tests/fixtures/django/accounts/views.py:112:5)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - authn `django_authenticated_user_check` at tests/fixtures/django/accounts/views.py:115:12 (medium)
    - Symbol: `is_authenticated` (tests/fixtures/django/accounts/views.py:115:12)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - permission_check `django_queryset_restrict` at tests/fixtures/django/accounts/views.py:116:29 (medium)
    - Symbol: `restrict` (tests/fixtures/django/accounts/views.py:116:29)
    - Note: Authorization evidence inherited from ProjectModelViewSet
- Data mutations: none

<a id="route-route_0020"></a>
### route_0020 GET `/accounts/api/inherited-readonly`

- Framework: django_rest_framework
- Handler: `InheritedReadOnlyProjectViewSet.list` (tests/fixtures/django/accounts/views.py:136:7)
- Route location: tests/fixtures/django/accounts/urls.py:11:1
- Middleware: none
- Declared protection: permission_classes
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path.
- Coverage support: evidence: evidence_0022; policy cases: policy_case_0012; sensitivity: account_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- PolicyLens:
  - policy_case_0012: effective_protection at tests/fixtures/django/accounts/views.py:121:5 (medium)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0020
    - Cites evidence: evidence_0022
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - permission_check `drf_permission_classes` at tests/fixtures/django/accounts/views.py:121:5 (medium)
    - Symbol: `permission_classes` (tests/fixtures/django/accounts/views.py:121:5)
    - Note: Authorization evidence inherited from ProjectReadOnlyViewSet
- Data mutations: none

<a id="route-route_0021"></a>
### route_0021 GET `/accounts/api/inherited-readonly/{pk}`

- Framework: django_rest_framework
- Handler: `InheritedReadOnlyProjectViewSet.retrieve` (tests/fixtures/django/accounts/views.py:136:7)
- Route location: tests/fixtures/django/accounts/urls.py:11:1
- Middleware: none
- Params: pk (high)
- Declared protection: permission_classes
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: evidence: evidence_0023; policy cases: policy_case_0013; sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- PolicyLens:
  - policy_case_0013: effective_protection at tests/fixtures/django/accounts/views.py:121:5 (medium)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0021
    - Cites evidence: evidence_0023
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - permission_check `drf_permission_classes` at tests/fixtures/django/accounts/views.py:121:5 (medium)
    - Symbol: `permission_classes` (tests/fixtures/django/accounts/views.py:121:5)
    - Note: Authorization evidence inherited from ProjectReadOnlyViewSet
- Data mutations: none

<a id="route-route_0022"></a>
### route_0022 GET `/accounts/api/mixin-backed`

- Framework: django_rest_framework
- Handler: `MixinBackedProjectViewSet.list` (tests/fixtures/django/accounts/views.py:140:7)
- Route location: tests/fixtures/django/accounts/urls.py:12:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path.
- Coverage support: sensitivity: account_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0023"></a>
### route_0023 POST `/accounts/api/mixin-backed`

- Framework: django_rest_framework
- Handler: `MixinBackedProjectViewSet.create` (tests/fixtures/django/accounts/views.py:140:7)
- Route location: tests/fixtures/django/accounts/urls.py:12:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: account_path, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0024"></a>
### route_0024 GET `&lt;dynamic&gt;`

- Framework: django_rest_framework
- Handler: `DynamicViewSet.list` (tests/fixtures/django/accounts/views.py:107:9)
- Route location: tests/fixtures/django/accounts/urls.py:13:1
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

<a id="route-route_0025"></a>
### route_0025 GET `/accounts/readonly-api/audit`

- Framework: django_rest_framework
- Handler: `ReadOnlyAuditViewSet.list` (tests/fixtures/django/accounts/views.py:87:7)
- Route location: tests/fixtures/django/accounts/urls.py:17:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path.
- Coverage support: sensitivity: account_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0026"></a>
### route_0026 GET `/accounts/readonly-api/audit/{pk}`

- Framework: django_rest_framework
- Handler: `ReadOnlyAuditViewSet.retrieve` (tests/fixtures/django/accounts/views.py:87:7)
- Route location: tests/fixtures/django/accounts/urls.py:17:1
- Middleware: none
- Params: pk (high)
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, path_param.
- Coverage support: sensitivity: account_path, path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0027"></a>
### route_0027 POST `/accounts/readonly-api/audit/refresh`

- Framework: django_rest_framework
- Handler: `ReadOnlyAuditViewSet.refresh` (tests/fixtures/django/accounts/views.py:89:9)
- Route location: tests/fixtures/django/accounts/urls.py:17:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (review_required)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: mutations: mutation_0007; links: link_0003; policy cases: policy_case_0014; sensitivity: account_path, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0014: linked_mutation_protection at tests/fixtures/django/accounts/urls.py:17:1 (high)
    - Summary: Route reaches linked mutation(s): mutation_0007 (Account).
    - Cites coverage: route_0027
    - Cites mutations: mutation_0007
    - Cites links: link_0003
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence: none
- Data mutations:
  - bulk_update `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:90:16 (high)

<a id="route-route_0028"></a>
### route_0028 ANY `/accounts`

- Framework: django
- Handler: `index` (tests/fixtures/django/accounts/views.py:33:5)
- Route location: tests/fixtures/django/accounts/urls.py:20:5
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (review_required)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): account_path, any_method, linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: mutations: mutation_0001; links: link_0004; policy cases: policy_case_0015; sensitivity: account_path, any_method, linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0015: linked_mutation_protection at tests/fixtures/django/accounts/urls.py:20:5 (medium)
    - Summary: Route reaches linked mutation(s): mutation_0001 (Account).
    - Cites coverage: route_0028
    - Cites mutations: mutation_0001
    - Cites links: link_0004
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence: none
- Data mutations:
  - create `Account` via `django_orm` at tests/fixtures/django/accounts/services.py:5:12 (high)

<a id="route-route_0029"></a>
### route_0029 ANY `/accounts/users/&lt;int:pk&gt;/`

- Framework: django
- Handler: `AccountDetailView` (tests/fixtures/django/accounts/views.py:41:7)
- Route location: tests/fixtures/django/accounts/urls.py:21:5
- Middleware: none
- Params: pk (medium)
- Declared protection: AccountDetailView
- Confidence: high
- Coverage: unknown_or_dynamic (review_required)
- Coverage rationale: 1 weak or dynamic authorization evidence item(s) were detected.; Sensitive route modifier(s): account_path, any_method, linked_mutation, path_param, unsafe_method, user_path.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, route_param_mutation_without_scope.
- Coverage support: evidence: evidence_0024; weak evidence: evidence_0024; mutations: mutation_0002, mutation_0003; links: link_0005, link_0006, link_0007; policy cases: policy_case_0016, policy_case_0017; sensitivity: account_path, any_method, linked_mutation, path_param, unsafe_method, user_path
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
  - policy_case_0016: linked_mutation_protection at tests/fixtures/django/accounts/urls.py:21:5 (low)
    - Summary: Route reaches linked mutation(s): mutation_0002, mutation_0003 (Account).
    - Cites coverage: route_0029
    - Cites mutations: mutation_0002, mutation_0003
    - Cites links: link_0005, link_0006, link_0007
    - Inputs: Account
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
  - policy_case_0017: dynamic at tests/fixtures/django/accounts/views.py:44:12 (low)
    - Summary: Dynamic policy behavior requires review.
    - Cites coverage: route_0029
    - Cites evidence: evidence_0024
    - Inputs: AccountDetailView
    - Branch: dynamic policy dispatch -> review_required (reachable)
    - Question: Can the dynamic authorization path be confirmed?
    - Uncertainty: Dynamic authorization evidence requires review.
- Auth evidence:
  - unknown_dynamic_check `handler_condition` at tests/fixtures/django/accounts/views.py:44:12 (low)
    - Symbol: `AccountDetailView` (tests/fixtures/django/accounts/views.py:41:7)
    - Note: Handler condition references user authorization attributes; review required
- Data mutations:
  - save `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:47:9 (medium)
  - delete `Account` via `django_orm` at tests/fixtures/django/accounts/views.py:51:16 (high)

<a id="route-route_0030"></a>
### route_0030 ANY `&lt;dynamic&gt;`

- Framework: django
- Handler: `dynamic_view` (tests/fixtures/django/accounts/views.py:37:5)
- Route location: tests/fixtures/django/accounts/urls.py:26:5
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

<a id="route-route_0031"></a>
### route_0031 ANY `/accounts/generated`

- Framework: django
- Handler: `GeneratedAccountListView` (tests/fixtures/django/accounts/views.py:55:7)
- Route location: tests/fixtures/django/accounts/views.py:54:2
- Middleware: none
- Declared protection: is_authenticated, restrict, IsAuthenticated
- Confidence: medium
- Coverage: permission_guarded (low)
- Coverage rationale: 3 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, any_method, unsafe_method.
- Coverage support: evidence: evidence_0025, evidence_0026, evidence_0027; policy cases: policy_case_0018; sensitivity: account_path, any_method, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- PolicyLens:
  - policy_case_0018: effective_protection at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Summary: 3 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0031
    - Cites evidence: evidence_0025, evidence_0026, evidence_0027
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Uncertainty notes:
  - Route emitted from statically matched generated URL helper
- Auth evidence:
  - authn `drf_permission_classes` at tests/fixtures/django/accounts/views.py:112:5 (medium)
    - Symbol: `IsAuthenticated` (tests/fixtures/django/accounts/views.py:112:5)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - authn `django_authenticated_user_check` at tests/fixtures/django/accounts/views.py:115:12 (medium)
    - Symbol: `is_authenticated` (tests/fixtures/django/accounts/views.py:115:12)
    - Note: Authorization evidence inherited from ProjectModelViewSet
  - permission_check `django_queryset_restrict` at tests/fixtures/django/accounts/views.py:116:29 (medium)
    - Symbol: `restrict` (tests/fixtures/django/accounts/views.py:116:29)
    - Note: Authorization evidence inherited from ProjectModelViewSet
- Data mutations: none

<a id="route-route_0032"></a>
### route_0032 ANY `/accounts/generated/&lt;int:pk&gt;/edit`

- Framework: django
- Handler: `GeneratedAccountEditView` (tests/fixtures/django/accounts/views.py:60:7)
- Route location: tests/fixtures/django/accounts/views.py:59:2
- Middleware: none
- Params: pk (medium)
- Declared protection: PermissionRequiredMixin
- Confidence: medium
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): account_path, any_method, path_param, unsafe_method.
- Coverage support: evidence: evidence_0028; policy cases: policy_case_0019; sensitivity: account_path, any_method, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- PolicyLens:
  - policy_case_0019: effective_protection at tests/fixtures/django/shared/generic/object_views.py:1:7 (medium)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0032
    - Cites evidence: evidence_0028
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
- Uncertainty notes:
  - Route emitted from statically matched generated URL helper
- Auth evidence:
  - permission_check `django_permission_mixin` at tests/fixtures/django/shared/generic/object_views.py:1:7 (medium)
    - Symbol: `PermissionRequiredMixin` (tests/fixtures/django/shared/generic/object_views.py:1:7)
    - Note: Authorization evidence inherited from ObjectEditView
- Data mutations: none

<a id="route-route_0033"></a>
### route_0033 ANY `/status/`

- Framework: django
- Handler: `status` (tests/fixtures/django/accounts/views.py:25:5)
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

<a id="route-route_0034"></a>
### route_0034 ANY `/legacy/{slug}/`

- Framework: django
- Handler: `legacy_detail` (tests/fixtures/django/accounts/views.py:29:5)
- Route location: tests/fixtures/django/project/urls.py:8:5
- Middleware: none
- Params: slug (high)
- Confidence: medium
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): any_method, path_param, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: any_method, path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Django re_path regex literal normalized as route path
- Auth evidence: none
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | django_dynamic_include_helper | tests/fixtures/django/project/urls.py:11:30 | Django include helper could not be expanded statically: helper=get_urlconf; positional=\[\]; keywords=\[\] |
| warning | drf_dynamic_basename | tests/fixtures/django/accounts/urls.py:13:1 | DRF router basename is dynamic and could not be resolved |
| warning | drf_dynamic_router_prefix | tests/fixtures/django/accounts/urls.py:13:17 | DRF router registration prefix is dynamic and could not be resolved |
| warning | django_custom_router | tests/fixtures/django/accounts/urls.py:15:17 | DRF custom router behavior could not be resolved statically |
| warning | django_dynamic_url_path | tests/fixtures/django/accounts/urls.py:26:10 | Django URL path is dynamic and could not be resolved |
| warning | django_urlpattern_context_uncertain | tests/fixtures/django/accounts/urls.py:34:5 | Django URL helper call is outside a statically recognized urlpatterns context |
| warning | policy.dynamic_behavior | tests/fixtures/django/accounts/views.py:44:12 | Dynamic policy evidence requires review. |

## Skipped Files

No files were skipped.