# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/nextjs
- Source files: 14
- Routes: 17
- Evidence entries: 7
- Mutations: 8
- Policy cases: 13
- Diagnostics: 4
- Frameworks: next_js: 17

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0001](#route-route_0001) | GET /modal | confidence is medium; Next.js route segment \`(.)modal\` uses an unusual routing convention and was normalized for review |
| [route_0002](#route-route_0002) | DELETE /reports | risk is review_required |
| [route_0003](#route-route_0003) | GET /blog/\[...slug\] | confidence is medium; Next.js route handler export is wrapped; wrapper behavior requires review |
| [route_0004](#route-route_0004) | PUT /docs/\[\[...slug\]\] | confidence is medium; Next.js route handler export is wrapped; wrapper behavior requires review; risk is review_required |
| [route_0005](#route-route_0005) | DELETE /dynamic-export | confidence is medium; Next.js route handler export value is dynamic or unsupported; review required; risk is high |
| [route_0006](#route-route_0006) | DELETE /external | confidence is medium; Next.js route handler export is wrapped; wrapper behavior requires review; risk is review_required |
| [route_0007](#route-route_0007) | POST /external | risk is review_required |
| [route_0008](#route-route_0008) | PUT /external | confidence is medium; Next.js route handler re-export target could not be analyzed statically; risk is high |
| [route_0010](#route-route_0010) | GET /nested/app/users | confidence is medium; Next.js route file path contains nested app segments; first app segment was used |
| [route_0013](#route-route_0013) | POST / | risk is review_required |
| [route_0016](#route-route_0016) | PATCH /users/\[id\] | risk is review_required |
| [route_0017](#route-route_0017) | PATCH /wrapped-named | confidence is medium; Next.js route handler export is wrapped; wrapper behavior requires review; risk is review_required |
| diagnostic | nextjs_external_reexport_unresolved | Next.js route handler re-export target could not be analyzed statically at tests/fixtures/nextjs/app/external/route.ts:1:1 |
| diagnostic | nextjs_nested_app_segment | Next.js route file path contains nested app segments at tests/fixtures/nextjs/app/nested/app/users/route.ts:1:1 |
| diagnostic | nextjs_unusual_route_segment | Next.js route segment uses an unusual routing convention; emitted path is normalized for review at tests/fixtures/nextjs/app/(.)modal/route.ts:1:1 |
| diagnostic | nextjs_dynamic_route_export | Next.js route handler export value is dynamic or unsupported at tests/fixtures/nextjs/app/dynamic-export/route.ts:3:14 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | next_js | GET | /modal | \`GET\` (tests/fixtures/nextjs/app/(.)modal/route.ts:1:17) | none | medium | unauthenticated | low |
| [route_0002](#route-route_0002) | next_js | DELETE | /reports | \`handleDelete\` (tests/fixtures/nextjs/app/(admin)/reports/route.ts:1:10) | none | high | unauthenticated | review_required |
| [route_0003](#route-route_0003) | next_js | GET | /blog/\[...slug\] | \`GET\` (tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:9:14) | none | medium | permission_guarded | low |
| [route_0004](#route-route_0004) | next_js | PUT | /docs/\[\[...slug\]\] | \`updateDoc\` (tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:9:32) | none | medium | authn_only | review_required |
| [route_0005](#route-route_0005) | next_js | DELETE | /dynamic-export | \`DELETE\` (tests/fixtures/nextjs/app/dynamic-export/route.ts:3:14) | none | medium | unauthenticated | high |
| [route_0006](#route-route_0006) | next_js | DELETE | /external | \`deleteExternal\` (tests/fixtures/nextjs/app/external/handler.ts:14:32) | none | medium | authn_only | review_required |
| [route_0007](#route-route_0007) | next_js | POST | /external | \`POST\` (tests/fixtures/nextjs/app/external/handler.ts:1:23) | none | high | authn_only | review_required |
| [route_0008](#route-route_0008) | next_js | PUT | /external | \`missing\` (tests/fixtures/nextjs/app/external/route.ts:1:1) | none | medium | unauthenticated | high |
| [route_0009](#route-route_0009) | next_js | HEAD | /head | \`HEAD\` (tests/fixtures/nextjs/app/head/route.js:1:17) | none | high | unauthenticated | low |
| [route_0010](#route-route_0010) | next_js | GET | /nested/app/users | \`GET\` (tests/fixtures/nextjs/app/nested/app/users/route.ts:1:17) | none | medium | unauthenticated | medium |
| [route_0011](#route-route_0011) | next_js | OPTIONS | /options | \`OPTIONS\` (tests/fixtures/nextjs/app/options/route.jsx:1:14) | none | high | unauthenticated | low |
| [route_0012](#route-route_0012) | next_js | GET | / | \`GET\` (tests/fixtures/nextjs/app/route.ts:5:23) | none | high | authn_only | low |
| [route_0013](#route-route_0013) | next_js | POST | / | \`POST\` (tests/fixtures/nextjs/app/route.ts:10:14) | none | high | unauthenticated | review_required |
| [route_0014](#route-route_0014) | next_js | GET | /tsx | \`GET\` (tests/fixtures/nextjs/app/tsx/route.tsx:1:14) | none | high | unauthenticated | low |
| [route_0015](#route-route_0015) | next_js | GET | /users/\[id\] | \`GET\` (tests/fixtures/nextjs/app/users/\[id\]/route.ts:1:23) | none | high | unauthenticated | medium |
| [route_0016](#route-route_0016) | next_js | PATCH | /users/\[id\] | \`PATCH\` (tests/fixtures/nextjs/app/users/\[id\]/route.ts:5:14) | none | high | unauthenticated | review_required |
| [route_0017](#route-route_0017) | next_js | PATCH | /wrapped-named | \`updateProfile\` (tests/fixtures/nextjs/app/wrapped-named/route.ts:9:34) | none | medium | authn_only | review_required |

## Data Mutations

| ID | Operation | Library | Resource | Location | Confidence | Review |
| --- | --- | --- | --- | --- | --- | --- |
| mutation_0001 | delete | prisma | report | tests/fixtures/nextjs/app/(admin)/reports/route.ts:2:10 | high | none |
| mutation_0002 | update | prisma | doc | tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:6:10 | high | none |
| mutation_0003 | create | prisma | external | tests/fixtures/nextjs/app/external/handler.ts:3:10 | high | none |
| mutation_0004 | delete | prisma | external | tests/fixtures/nextjs/app/external/handler.ts:11:10 | high | none |
| mutation_0005 | create | prisma | session | tests/fixtures/nextjs/app/route.ts:11:10 | high | none |
| mutation_0006 | delete | prisma | shadow | tests/fixtures/nextjs/app/tsx/route.tsx:2:24 | high | none |
| mutation_0007 | update | prisma | user | tests/fixtures/nextjs/app/users/\[id\]/route.ts:6:10 | high | none |
| mutation_0008 | update | prisma | profile | tests/fixtures/nextjs/app/wrapped-named/route.ts:6:10 | high | none |

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/modal`

- Framework: next_js
- Handler: `GET` (tests/fixtures/nextjs/app/(.)modal/route.ts:1:17)
- Route location: tests/fixtures/nextjs/app/(.)modal/route.ts:1:8
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Next.js route segment \`(.)modal\` uses an unusual routing convention and was normalized for review
- Auth evidence: none
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 DELETE `/reports`

- Framework: next_js
- Handler: `handleDelete` (tests/fixtures/nextjs/app/(admin)/reports/route.ts:1:10)
- Route location: tests/fixtures/nextjs/app/(admin)/reports/route.ts:5:1
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (review_required)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: mutations: mutation_0001; links: link_0001; policy cases: policy_case_0001; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0001: linked_mutation_protection at tests/fixtures/nextjs/app/(admin)/reports/route.ts:5:1 (high)
    - Summary: Route reaches linked mutation(s): mutation_0001 (report).
    - Cites coverage: route_0002
    - Cites mutations: mutation_0001
    - Cites links: link_0001
    - Inputs: report
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence: none
- Data mutations:
  - delete `report` via `prisma` at tests/fixtures/nextjs/app/(admin)/reports/route.ts:2:10 (high)

<a id="route-route_0003"></a>
### route_0003 GET `/blog/\[...slug\]`

- Framework: next_js
- Handler: `GET` (tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:9:14)
- Route location: tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:9:14
- Middleware: none
- Params: slug (medium)
- Declared protection: withAuth, requirePermission
- Confidence: medium
- Coverage: permission_guarded (low)
- Coverage rationale: 2 strong authorization evidence item(s) support permission_guarded coverage.
- Coverage support: evidence: evidence_0001, evidence_0002; policy cases: policy_case_0002
- Coverage uncertainty:
  - Route inventory confidence is not high.
- PolicyLens:
  - policy_case_0002: effective_protection at tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:9:14 (medium)
    - Summary: 2 evidence support(s) route protection: authn, permission_check.
    - Cites coverage: route_0003
    - Cites evidence: evidence_0001, evidence_0002
    - Inputs: identity, permission
    - Branch: static authorization evidence present -> allow (reachable)
- Uncertainty notes:
  - Next.js route handler export is wrapped; wrapper behavior requires review
- Auth evidence:
  - authn `nextjs_auth_wrapper` at tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:9:14 (medium)
    - Symbol: `withAuth` (tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:9:14)
    - Note: Next.js route handler is wrapped by an auth-like helper
  - permission_check `permission_guard` at tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:10:3 (high)
    - Symbol: `requirePermission` (tests/fixtures/nextjs/app/blog/\[...slug\]/route.ts:10:3)
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 PUT `/docs/\[\[...slug\]\]`

- Framework: next_js
- Handler: `updateDoc` (tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:9:32)
- Route location: tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:9:14
- Middleware: none
- Params: slug (medium)
- Declared protection: requireUser
- Confidence: medium
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, route_param_mutation_without_scope.
- Coverage support: evidence: evidence_0003; mutations: mutation_0002; links: link_0002; policy cases: policy_case_0003, policy_case_0004; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- PolicyLens:
  - policy_case_0003: effective_protection at tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:9:14 (medium)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0004
    - Cites evidence: evidence_0003
    - Cites mutations: mutation_0002
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0004: linked_mutation_protection at tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:9:14 (high)
    - Summary: Route reaches linked mutation(s): mutation_0002 (doc).
    - Cites coverage: route_0004
    - Cites mutations: mutation_0002
    - Cites links: link_0002
    - Inputs: doc
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Uncertainty notes:
  - Next.js route handler export is wrapped; wrapper behavior requires review
- Auth evidence:
  - authn `nextjs_auth_wrapper` at tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:9:14 (medium)
    - Symbol: `requireUser` (tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:9:32)
    - Note: Next.js route handler is wrapped by an auth-like helper
- Data mutations:
  - update `doc` via `prisma` at tests/fixtures/nextjs/app/docs/\[\[...slug\]\]/route.ts:6:10 (high)

<a id="route-route_0005"></a>
### route_0005 DELETE `/dynamic-export`

- Framework: next_js
- Handler: `DELETE` (tests/fixtures/nextjs/app/dynamic-export/route.ts:3:14)
- Route location: tests/fixtures/nextjs/app/dynamic-export/route.ts:3:14
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Next.js route handler export value is dynamic or unsupported; review required
- Auth evidence: none
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 DELETE `/external`

- Framework: next_js
- Handler: `deleteExternal` (tests/fixtures/nextjs/app/external/handler.ts:14:32)
- Route location: tests/fixtures/nextjs/app/external/route.ts:1:1
- Middleware: none
- Declared protection: withAuth
- Confidence: medium
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: evidence: evidence_0004; mutations: mutation_0004; links: link_0003; policy cases: policy_case_0005, policy_case_0006; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- PolicyLens:
  - policy_case_0005: effective_protection at tests/fixtures/nextjs/app/external/route.ts:1:1 (medium)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0006
    - Cites evidence: evidence_0004
    - Cites mutations: mutation_0004
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0006: linked_mutation_protection at tests/fixtures/nextjs/app/external/route.ts:1:1 (high)
    - Summary: Route reaches linked mutation(s): mutation_0004 (external).
    - Cites coverage: route_0006
    - Cites mutations: mutation_0004
    - Cites links: link_0003
    - Inputs: external
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Uncertainty notes:
  - Next.js route handler export is wrapped; wrapper behavior requires review
- Auth evidence:
  - authn `nextjs_auth_wrapper` at tests/fixtures/nextjs/app/external/route.ts:1:1 (medium)
    - Symbol: `withAuth` (tests/fixtures/nextjs/app/external/handler.ts:14:32)
    - Note: Next.js route handler is wrapped by an auth-like helper
- Data mutations:
  - delete `external` via `prisma` at tests/fixtures/nextjs/app/external/handler.ts:11:10 (high)

<a id="route-route_0007"></a>
### route_0007 POST `/external`

- Framework: next_js
- Handler: `POST` (tests/fixtures/nextjs/app/external/handler.ts:1:23)
- Route location: tests/fixtures/nextjs/app/external/route.ts:1:1
- Middleware: none
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: evidence: evidence_0005; mutations: mutation_0003; links: link_0004; policy cases: policy_case_0007, policy_case_0008; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0007: effective_protection at tests/fixtures/nextjs/app/external/handler.ts:2:3 (high)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0007
    - Cites evidence: evidence_0005
    - Cites mutations: mutation_0003
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0008: linked_mutation_protection at tests/fixtures/nextjs/app/external/route.ts:1:1 (high)
    - Summary: Route reaches linked mutation(s): mutation_0003 (external).
    - Cites coverage: route_0007
    - Cites mutations: mutation_0003
    - Cites links: link_0004
    - Inputs: external
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/nextjs/app/external/handler.ts:2:3 (high)
    - Symbol: `requireAuth` (tests/fixtures/nextjs/app/external/handler.ts:2:3)
- Data mutations:
  - create `external` via `prisma` at tests/fixtures/nextjs/app/external/handler.ts:3:10 (high)

<a id="route-route_0008"></a>
### route_0008 PUT `/external`

- Framework: next_js
- Handler: `missing` (tests/fixtures/nextjs/app/external/route.ts:1:1)
- Route location: tests/fixtures/nextjs/app/external/route.ts:1:1
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (high)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): unsafe_method.; No strong authorization evidence was found for a high-sensitivity route.
- Coverage support: sensitivity: unsafe_method
- Reviewer questions:
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Next.js route handler re-export target could not be analyzed statically
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 HEAD `/head`

- Framework: next_js
- Handler: `HEAD` (tests/fixtures/nextjs/app/head/route.js:1:17)
- Route location: tests/fixtures/nextjs/app/head/route.js:1:8
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0010"></a>
### route_0010 GET `/nested/app/users`

- Framework: next_js
- Handler: `GET` (tests/fixtures/nextjs/app/nested/app/users/route.ts:1:17)
- Route location: tests/fixtures/nextjs/app/nested/app/users/route.ts:1:8
- Middleware: none
- Confidence: medium
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): user_path.
- Coverage support: sensitivity: user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- Uncertainty notes:
  - Next.js route file path contains nested app segments; first app segment was used
- Auth evidence: none
- Data mutations: none

<a id="route-route_0011"></a>
### route_0011 OPTIONS `/options`

- Framework: next_js
- Handler: `OPTIONS` (tests/fixtures/nextjs/app/options/route.jsx:1:14)
- Route location: tests/fixtures/nextjs/app/options/route.jsx:1:14
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0012"></a>
### route_0012 GET `/`

- Framework: next_js
- Handler: `GET` (tests/fixtures/nextjs/app/route.ts:5:23)
- Route location: tests/fixtures/nextjs/app/route.ts:5:8
- Middleware: none
- Declared protection: requireAuth
- Confidence: high
- Coverage: authn_only (low)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.
- Coverage support: evidence: evidence_0006; policy cases: policy_case_0009
- PolicyLens:
  - policy_case_0009: effective_protection at tests/fixtures/nextjs/app/route.ts:6:3 (high)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0012
    - Cites evidence: evidence_0006
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
- Auth evidence:
  - authn `authn_guard` at tests/fixtures/nextjs/app/route.ts:6:3 (high)
    - Symbol: `requireAuth` (tests/fixtures/nextjs/app/route.ts:6:3)
- Data mutations: none

<a id="route-route_0013"></a>
### route_0013 POST `/`

- Framework: next_js
- Handler: `POST` (tests/fixtures/nextjs/app/route.ts:10:14)
- Route location: tests/fixtures/nextjs/app/route.ts:10:14
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (review_required)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: mutations: mutation_0005; links: link_0005; policy cases: policy_case_0010; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0010: linked_mutation_protection at tests/fixtures/nextjs/app/route.ts:10:14 (high)
    - Summary: Route reaches linked mutation(s): mutation_0005 (session).
    - Cites coverage: route_0013
    - Cites mutations: mutation_0005
    - Cites links: link_0005
    - Inputs: session
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence: none
- Data mutations:
  - create `session` via `prisma` at tests/fixtures/nextjs/app/route.ts:11:10 (high)

<a id="route-route_0014"></a>
### route_0014 GET `/tsx`

- Framework: next_js
- Handler: `GET` (tests/fixtures/nextjs/app/tsx/route.tsx:1:14)
- Route location: tests/fixtures/nextjs/app/tsx/route.tsx:1:14
- Middleware: none
- Confidence: high
- Coverage: unauthenticated (low)
- Coverage rationale: No authorization evidence was detected.
- Auth evidence: none
- Data mutations: none

<a id="route-route_0015"></a>
### route_0015 GET `/users/\[id\]`

- Framework: next_js
- Handler: `GET` (tests/fixtures/nextjs/app/users/\[id\]/route.ts:1:23)
- Route location: tests/fixtures/nextjs/app/users/\[id\]/route.ts:1:8
- Middleware: none
- Params: id (medium)
- Confidence: high
- Coverage: unauthenticated (medium)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): user_path.
- Coverage support: sensitivity: user_path
- Reviewer questions:
  - Should this route require ownership or permission checks?
- Auth evidence: none
- Data mutations: none

<a id="route-route_0016"></a>
### route_0016 PATCH `/users/\[id\]`

- Framework: next_js
- Handler: `PATCH` (tests/fixtures/nextjs/app/users/\[id\]/route.ts:5:14)
- Route location: tests/fixtures/nextjs/app/users/\[id\]/route.ts:5:14
- Middleware: none
- Params: id (medium)
- Confidence: high
- Coverage: unauthenticated (review_required)
- Coverage rationale: No authorization evidence was detected.; Sensitive route modifier(s): linked_mutation, unsafe_method, user_path.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence, route_param_mutation_without_scope.
- Coverage support: mutations: mutation_0007; links: link_0006; policy cases: policy_case_0011; sensitivity: linked_mutation, unsafe_method, user_path
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require ownership or permission checks?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- PolicyLens:
  - policy_case_0011: linked_mutation_protection at tests/fixtures/nextjs/app/users/\[id\]/route.ts:5:14 (high)
    - Summary: Route reaches linked mutation(s): mutation_0007 (user).
    - Cites coverage: route_0016
    - Cites mutations: mutation_0007
    - Cites links: link_0006
    - Inputs: user
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Auth evidence: none
- Data mutations:
  - update `user` via `prisma` at tests/fixtures/nextjs/app/users/\[id\]/route.ts:6:10 (high)

<a id="route-route_0017"></a>
### route_0017 PATCH `/wrapped-named`

- Framework: next_js
- Handler: `updateProfile` (tests/fixtures/nextjs/app/wrapped-named/route.ts:9:34)
- Route location: tests/fixtures/nextjs/app/wrapped-named/route.ts:9:14
- Middleware: none
- Declared protection: requireUser
- Confidence: medium
- Coverage: authn_only (review_required)
- Coverage rationale: 1 strong authorization evidence item(s) support authn_only coverage.; Sensitive route modifier(s): linked_mutation, unsafe_method.; Linked data mutation(s) increase review sensitivity.; Tenant isolation review required: missing_tenant_or_ownership_evidence.
- Coverage support: evidence: evidence_0007; mutations: mutation_0008; links: link_0007; policy cases: policy_case_0012, policy_case_0013; sensitivity: linked_mutation, unsafe_method
- Reviewer questions:
  - Should linked data mutations have resource-specific authorization evidence?
  - Should this route require tenant or ownership scoping?
  - Should this state-changing route require more than authentication?
- Coverage uncertainty:
  - Route inventory confidence is not high.
- PolicyLens:
  - policy_case_0012: effective_protection at tests/fixtures/nextjs/app/wrapped-named/route.ts:9:14 (medium)
    - Summary: 1 evidence support(s) route protection: authn.
    - Cites coverage: route_0017
    - Cites evidence: evidence_0007
    - Cites mutations: mutation_0008
    - Inputs: identity
    - Branch: static authorization evidence present -> allow (reachable)
  - policy_case_0013: linked_mutation_protection at tests/fixtures/nextjs/app/wrapped-named/route.ts:9:14 (high)
    - Summary: Route reaches linked mutation(s): mutation_0008 (profile).
    - Cites coverage: route_0017
    - Cites mutations: mutation_0008
    - Cites links: link_0007
    - Inputs: profile
    - Branch: route-to-mutation reachability -> review_required (reachable)
    - Question: Should linked data mutations have resource-specific authorization evidence?
- Uncertainty notes:
  - Next.js route handler export is wrapped; wrapper behavior requires review
- Auth evidence:
  - authn `nextjs_auth_wrapper` at tests/fixtures/nextjs/app/wrapped-named/route.ts:9:14 (medium)
    - Symbol: `requireUser` (tests/fixtures/nextjs/app/wrapped-named/route.ts:9:34)
    - Note: Next.js route handler is wrapped by an auth-like helper
- Data mutations:
  - update `profile` via `prisma` at tests/fixtures/nextjs/app/wrapped-named/route.ts:6:10 (high)

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | nextjs_external_reexport_unresolved | tests/fixtures/nextjs/app/external/route.ts:1:1 | Next.js route handler re-export target could not be analyzed statically |
| warning | nextjs_nested_app_segment | tests/fixtures/nextjs/app/nested/app/users/route.ts:1:1 | Next.js route file path contains nested app segments |
| warning | nextjs_unusual_route_segment | tests/fixtures/nextjs/app/(.)modal/route.ts:1:1 | Next.js route segment uses an unusual routing convention; emitted path is normalized for review |
| warning | nextjs_dynamic_route_export | tests/fixtures/nextjs/app/dynamic-export/route.ts:3:14 | Next.js route handler export value is dynamic or unsupported |

## Skipped Files

No files were skipped.