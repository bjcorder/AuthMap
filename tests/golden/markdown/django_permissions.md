# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/django_permissions
- Source files: 3
- Routes: 15
- Evidence entries: 13
- Mutations: 0
- Policy cases: 10
- Diagnostics: 0
- Frameworks: django: 6, django_rest_framework: 9

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0007](#route-route_0007) | POST /api/items/dynamic | risk is review_required; coverage is unknown_or_dynamic |
| [route_0008](#route-route_0008) | POST /api/items/public | risk is high |
| [route_0010](#route-route_0010) | ANY /settings/ | risk is review_required |
| [route_0011](#route-route_0011) | ANY /public-api/ | risk is high |
| [route_0012](#route-route_0012) | ANY /concrete/ | risk is review_required; coverage is unknown_or_dynamic |
| [route_0014](#route-route_0014) | ANY /aliased/ | risk is review_required |
| [route_0015](#route-route_0015) | ANY /ordinary/ | risk is high |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | django_rest_framework | DELETE | /api/items/{pk} | \`PermissionsViewSet.destroy\` (tests/fixtures/django_permissions/views.py:12:7) | none | high | admin_guarded | low |
| [route_0002](#route-route_0002) | django_rest_framework | GET | /api/items | \`PermissionsViewSet.list\` (tests/fixtures/django_permissions/views.py:15:9) | none | high | admin_guarded | low |
| [route_0003](#route-route_0003) | django_rest_framework | GET | /api/items/{pk} | \`PermissionsViewSet.retrieve\` (tests/fixtures/django_permissions/views.py:12:7) | none | high | admin_guarded | low |
| [route_0004](#route-route_0004) | django_rest_framework | PATCH | /api/items/{pk} | \`PermissionsViewSet.partial_update\` (tests/fixtures/django_permissions/views.py:12:7) | none | high | admin_guarded | low |
| [route_0005](#route-route_0005) | django_rest_framework | POST | /api/items | \`PermissionsViewSet.create\` (tests/fixtures/django_permissions/views.py:12:7) | none | high | admin_guarded | low |
| [route_0006](#route-route_0006) | django_rest_framework | POST | /api/items/auth_only | \`PermissionsViewSet.auth_only\` (tests/fixtures/django_permissions/views.py:23:9) | none | high | admin_guarded | low |
| [route_0007](#route-route_0007) | django_rest_framework | POST | /api/items/dynamic | \`PermissionsViewSet.dynamic\` (tests/fixtures/django_permissions/views.py:27:9) | none | high | unknown_or_dynamic | review_required |
| [route_0008](#route-route_0008) | django_rest_framework | POST | /api/items/public | \`PermissionsViewSet.public\` (tests/fixtures/django_permissions/views.py:19:9) | none | high | unauthenticated | high |
| [route_0009](#route-route_0009) | django_rest_framework | PUT | /api/items/{pk} | \`PermissionsViewSet.update\` (tests/fixtures/django_permissions/views.py:12:7) | none | high | admin_guarded | low |
| [route_0010](#route-route_0010) | django | ANY | /settings/ | \`SettingsView\` (tests/fixtures/django_permissions/views.py:31:7) | none | high | authn_only | review_required |
| [route_0011](#route-route_0011) | django | ANY | /public-api/ | \`public_api\` (tests/fixtures/django_permissions/views.py:41:5) | none | high | unauthenticated | high |
| [route_0012](#route-route_0012) | django | ANY | /concrete/ | \`ConcreteWrapped\` (tests/fixtures/django_permissions/views.py:46:7) | none | high | unknown_or_dynamic | review_required |
| [route_0013](#route-route_0013) | django | ANY | /dispatch/ | \`DispatchWrapped\` (tests/fixtures/django_permissions/views.py:54:7) | none | high | permission_guarded | low |
| [route_0014](#route-route_0014) | django | ANY | /aliased/ | \`AliasedView\` (tests/fixtures/django_permissions/views.py:71:7) | none | high | authn_only | review_required |
| [route_0015](#route-route_0015) | django | ANY | /ordinary/ | \`ordinary_view\` (tests/fixtures/django_permissions/views.py:76:5) | none | high | unauthenticated | high |

## Data Mutations

No data mutations were detected.

## Route Details

<a id="route-route_0001"></a>
### route_0001 DELETE `/api/items/{pk}`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.destroy` (tests/fixtures/django_permissions/views.py:12:7)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Params: pk (high)
- Declared protection: IsAdminUser
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): path_param, unsafe_method.
- Coverage support: evidence: evidence_0001; policy cases: policy_case_0001; sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0001: effective_protection at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0001
    - Cites evidence: evidence_0001
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - admin_check `drf_permission_classes` at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:13:5)
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 GET `/api/items`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.list` (tests/fixtures/django_permissions/views.py:15:9)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Declared protection: IsAdminUser
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.
- Coverage support: evidence: evidence_0002; policy cases: policy_case_0002
- PolicyLens:
  - policy_case_0002: effective_protection at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0002
    - Cites evidence: evidence_0002
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - admin_check `drf_permission_classes` at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:13:5)
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 GET `/api/items/{pk}`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.retrieve` (tests/fixtures/django_permissions/views.py:12:7)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Params: pk (high)
- Declared protection: IsAdminUser
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): path_param.
- Coverage support: evidence: evidence_0003; policy cases: policy_case_0003; sensitivity: path_param
- Reviewer questions:
  - Should this route require ownership or permission checks?
- PolicyLens:
  - policy_case_0003: effective_protection at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0003
    - Cites evidence: evidence_0003
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - admin_check `drf_permission_classes` at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:13:5)
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 PATCH `/api/items/{pk}`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.partial_update` (tests/fixtures/django_permissions/views.py:12:7)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Params: pk (high)
- Declared protection: IsAdminUser
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): path_param, unsafe_method.
- Coverage support: evidence: evidence_0004; policy cases: policy_case_0004; sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0004: effective_protection at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0004
    - Cites evidence: evidence_0004
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - admin_check `drf_permission_classes` at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:13:5)
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 POST `/api/items`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.create` (tests/fixtures/django_permissions/views.py:12:7)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Declared protection: IsAdminUser
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0005; policy cases: policy_case_0005; sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0005: effective_protection at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0005
    - Cites evidence: evidence_0005
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - admin_check `drf_permission_classes` at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:13:5)
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 POST `/api/items/auth_only`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.auth_only` (tests/fixtures/django_permissions/views.py:23:9)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Declared protection: \[SessionAuthentication\], IsAdminUser
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0006, evidence_0007; policy cases: policy_case_0006; sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0006: effective_protection at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Summary: 2 evidence support(s) route protection: admin_check, authn.
    - Cites coverage: route_0006
    - Cites evidence: evidence_0006, evidence_0007
    - Inputs: admin, identity
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - admin_check `drf_permission_classes` at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:13:5)
  - authn `drf_action_authentication_classes` at tests/fixtures/django_permissions/views.py:22:68 (high)
    - Symbol: `\[SessionAuthentication\]` (tests/fixtures/django_permissions/views.py:22:68)
    - Note: DRF authentication declaration: \[SessionAuthentication\]
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 POST `/api/items/dynamic`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.dynamic` (tests/fixtures/django_permissions/views.py:27:9)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Declared protection: IsAdminUser
- Confidence: high
- Coverage: unknown_or_dynamic (review_required)
- Coverage rationale: 1 weak or dynamic authorization evidence item(s) were detected.; Sensitive route modifier(s): unsafe_method.
- Coverage support: evidence: evidence_0008; weak evidence: evidence_0008; sensitivity: unsafe_method
- Reviewer questions:
  - Can the dynamic authorization path be confirmed?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - admin_check `drf_action_permission_classes` at tests/fixtures/django_permissions/views.py:26:64 (low)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:26:64)
    - Note: DRF permission declaration: \[IsAdminUser\] if FLAG else \[\]
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 POST `/api/items/public`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.public` (tests/fixtures/django_permissions/views.py:19:9)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 PUT `/api/items/{pk}`

- Framework: django_rest_framework
- Handler: `PermissionsViewSet.update` (tests/fixtures/django_permissions/views.py:12:7)
- Route location: tests/fixtures/django_permissions/urls.py:15:1
- Middleware: none
- Params: pk (high)
- Declared protection: IsAdminUser
- Confidence: high
- Coverage: admin_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support admin_guarded coverage.; Sensitive route modifier(s): path_param, unsafe_method.
- Coverage support: evidence: evidence_0009; policy cases: policy_case_0007; sensitivity: path_param, unsafe_method
- Reviewer questions:
  - Should this route require ownership or permission checks?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0007: effective_protection at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Summary: 1 evidence support(s) route protection: admin_check.
    - Cites coverage: route_0009
    - Cites evidence: evidence_0009
    - Inputs: admin
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - admin_check `drf_permission_classes` at tests/fixtures/django_permissions/views.py:13:5 (high)
    - Symbol: `IsAdminUser` (tests/fixtures/django_permissions/views.py:13:5)
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 ANY `/settings/`

- Framework: django
- Handler: `SettingsView` (tests/fixtures/django_permissions/views.py:31:7)
- Route location: tests/fixtures/django_permissions/urls.py:19:5
- Middleware: none
- Declared protection: IsAuthenticated
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): any_method, unsafe_method.
- Coverage support: evidence: evidence_0010; policy cases: policy_case_0008; sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0008: effective_protection at tests/fixtures/django_permissions/settings.py:2:35 (high)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0010
    - Cites evidence: evidence_0010
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `drf_settings_default_permission_classes` at tests/fixtures/django_permissions/settings.py:2:35 (high)
    - Symbol: `IsAuthenticated` (tests/fixtures/django_permissions/settings.py:2:35)
    - Note: DRF permission declaration: \["rest_framework.permissions.IsAuthenticated"\]
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 ANY `/public-api/`

- Framework: django
- Handler: `public_api` (tests/fixtures/django_permissions/views.py:41:5)
- Route location: tests/fixtures/django_permissions/urls.py:20:5
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): any_method, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 ANY `/concrete/`

- Framework: django
- Handler: `ConcreteWrapped` (tests/fixtures/django_permissions/views.py:46:7)
- Route location: tests/fixtures/django_permissions/urls.py:21:5
- Middleware: none
- Declared protection: login_required
- Confidence: high
- Coverage: unknown_or_dynamic (review_required)
- Coverage rationale: 1 weak or dynamic authorization evidence item(s) were detected.; Sensitive route modifier(s): any_method, unsafe_method.
- Coverage support: evidence: evidence_0011; weak evidence: evidence_0011; sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Can the dynamic authorization path be confirmed?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Low-confidence authorization evidence was detected.
- Auth evidence:
  - authn `django_login_required` at tests/fixtures/django_permissions/views.py:45:1 (low)
    - Symbol: `login_required` (tests/fixtures/django_permissions/views.py:45:1)
    - Note: method_decorator targets one concrete method; aggregate route coverage is uncertain
    - Note: Django method_decorator targets login_required on a concrete method
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 ANY `/dispatch/`

- Framework: django
- Handler: `DispatchWrapped` (tests/fixtures/django_permissions/views.py:54:7)
- Route location: tests/fixtures/django_permissions/urls.py:22:5
- Middleware: none
- Declared protection: permission_required
- Confidence: high
- Coverage: permission_guarded (low)
- Coverage rationale: 1 strong authorization evidence item(s) support permission_guarded coverage.; Sensitive route modifier(s): any_method, unsafe_method.
- Coverage support: evidence: evidence_0012; policy cases: policy_case_0009; sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0009: effective_protection at tests/fixtures/django_permissions/views.py:55:5 (high)
    - Summary: 1 evidence support(s) route protection: permission_check.
    - Cites coverage: route_0013
    - Cites evidence: evidence_0012
    - Inputs: permission
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - permission_check `django_permission_required` at tests/fixtures/django_permissions/views.py:55:5 (high)
    - Symbol: `permission_required` (tests/fixtures/django_permissions/views.py:55:5)
    - Note: Django method_decorator applies to class dispatch
- Data mutations: none

<a id="route-route_0014"></a>
### route_0014 ANY `/aliased/`

- Framework: django
- Handler: `AliasedView` (tests/fixtures/django_permissions/views.py:71:7)
- Route location: tests/fixtures/django_permissions/urls.py:23:5
- Middleware: none
- Declared protection: LoginRequiredMixin
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): any_method, unsafe_method.
- Coverage support: evidence: evidence_0013; policy cases: policy_case_0010; sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0010: effective_protection at tests/fixtures/django_permissions/views.py:63:7 (medium)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0014
    - Cites evidence: evidence_0013
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `django_login_required_mixin` at tests/fixtures/django_permissions/views.py:63:7 (medium)
    - Symbol: `LoginRequiredMixin` (tests/fixtures/django_permissions/views.py:63:7)
    - Note: Authorization evidence inherited from FirstMixin
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 ANY `/ordinary/`

- Framework: django
- Handler: `ordinary_view` (tests/fixtures/django_permissions/views.py:76:5)
- Route location: tests/fixtures/django_permissions/urls.py:24:5
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): any_method, unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: any_method, unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Auth evidence: none
- Data mutations: none

## Diagnostics

No diagnostics were emitted.

## Skipped Files

No files were skipped.