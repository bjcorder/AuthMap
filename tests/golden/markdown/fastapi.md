# AuthMap Report

- Tool: authmap 0.1.0
- Schema: 0.1.0

## Summary

- Mode: advisory
- Targets: tests/fixtures/fastapi
- Source files: 2
- Routes: 9
- Evidence entries: 0
- Mutations: 0
- Diagnostics: 4
- Frameworks: fast_api: 9

## Review Required

| Item | Subject | Reason |
| --- | --- | --- |
| [route_0006](#route-route_0006) | GET /reports | confidence is medium; router prefix is dynamic and was not included in the route path; include_router prefix is dynamic and was not included in the route path |
| [route_0009](#route-route_0009) | ANY /fallback | confidence is medium; api_route methods are dynamic or missing; emitted as ANY |
| diagnostic | fastapi_dynamic_api_route_methods | FastAPI api_route methods are dynamic or missing at tests/fixtures/fastapi/main.py:36:2 |
| diagnostic | fastapi_dynamic_include_router_prefix | FastAPI include_router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:48:1 |
| diagnostic | fastapi_dynamic_route_path | FastAPI route path is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:41:2 |
| diagnostic | fastapi_dynamic_router_prefix | FastAPI router prefix is dynamic and could not be resolved at tests/fixtures/fastapi/main.py:8:18 |

## Route Inventory

| ID | Framework | Method | Path | Handler | Middleware | Confidence | Coverage | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [route_0001](#route-route_0001) | fast_api | GET | /v1/users/{user_id} | \`get_user\` (tests/fixtures/fastapi/app/routes/users.py:7:5) | none | high | not classified | not scored |
| [route_0002](#route-route_0002) | fast_api | PUT | /v1/users/{user_id} | \`update_user\` (tests/fixtures/fastapi/app/routes/users.py:12:5) | none | high | not classified | not scored |
| [route_0003](#route-route_0003) | fast_api | GET | /health | \`health\` (tests/fixtures/fastapi/main.py:12:5) | none | high | not classified | not scored |
| [route_0004](#route-route_0004) | fast_api | POST | /items | \`create_item\` (tests/fixtures/fastapi/main.py:17:5) | none | high | not classified | not scored |
| [route_0005](#route-route_0005) | fast_api | DELETE | /api/local/{item_id} | \`delete_local\` (tests/fixtures/fastapi/main.py:22:5) | none | high | not classified | not scored |
| [route_0006](#route-route_0006) | fast_api | GET | /reports | \`dynamic_reports\` (tests/fixtures/fastapi/main.py:27:5) | none | medium | not classified | not scored |
| [route_0007](#route-route_0007) | fast_api | GET | /search | \`search\` (tests/fixtures/fastapi/main.py:32:5) | none | high | not classified | not scored |
| [route_0008](#route-route_0008) | fast_api | POST | /search | \`search\` (tests/fixtures/fastapi/main.py:32:5) | none | high | not classified | not scored |
| [route_0009](#route-route_0009) | fast_api | ANY | /fallback | \`fallback\` (tests/fixtures/fastapi/main.py:37:5) | none | medium | not classified | not scored |

## Route Details

<a id="route-route_0001"></a>
### route_0001 GET `/v1/users/{user_id}`

- Framework: fast_api
- Handler: `get_user` (tests/fixtures/fastapi/app/routes/users.py:7:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:6:2
- Middleware: none
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0002"></a>
### route_0002 PUT `/v1/users/{user_id}`

- Framework: fast_api
- Handler: `update_user` (tests/fixtures/fastapi/app/routes/users.py:12:5)
- Route location: tests/fixtures/fastapi/app/routes/users.py:11:2
- Middleware: none
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0003"></a>
### route_0003 GET `/health`

- Framework: fast_api
- Handler: `health` (tests/fixtures/fastapi/main.py:12:5)
- Route location: tests/fixtures/fastapi/main.py:11:2
- Middleware: none
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0004"></a>
### route_0004 POST `/items`

- Framework: fast_api
- Handler: `create_item` (tests/fixtures/fastapi/main.py:17:5)
- Route location: tests/fixtures/fastapi/main.py:16:2
- Middleware: none
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0005"></a>
### route_0005 DELETE `/api/local/{item_id}`

- Framework: fast_api
- Handler: `delete_local` (tests/fixtures/fastapi/main.py:22:5)
- Route location: tests/fixtures/fastapi/main.py:21:2
- Middleware: none
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0006"></a>
### route_0006 GET `/reports`

- Framework: fast_api
- Handler: `dynamic_reports` (tests/fixtures/fastapi/main.py:27:5)
- Route location: tests/fixtures/fastapi/main.py:26:2
- Middleware: none
- Confidence: medium
- Coverage: not classified
- Uncertainty notes:
  - router prefix is dynamic and was not included in the route path
  - include_router prefix is dynamic and was not included in the route path
- Auth evidence: none
- Data mutations: none

<a id="route-route_0007"></a>
### route_0007 GET `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:32:5)
- Route location: tests/fixtures/fastapi/main.py:31:2
- Middleware: none
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0008"></a>
### route_0008 POST `/search`

- Framework: fast_api
- Handler: `search` (tests/fixtures/fastapi/main.py:32:5)
- Route location: tests/fixtures/fastapi/main.py:31:2
- Middleware: none
- Confidence: high
- Coverage: not classified
- Auth evidence: none
- Data mutations: none

<a id="route-route_0009"></a>
### route_0009 ANY `/fallback`

- Framework: fast_api
- Handler: `fallback` (tests/fixtures/fastapi/main.py:37:5)
- Route location: tests/fixtures/fastapi/main.py:36:2
- Middleware: none
- Confidence: medium
- Coverage: not classified
- Uncertainty notes:
  - api_route methods are dynamic or missing; emitted as ANY
- Auth evidence: none
- Data mutations: none

## Diagnostics

| Severity | Code | Location | Message |
| --- | --- | --- | --- |
| warning | fastapi_dynamic_router_prefix | tests/fixtures/fastapi/main.py:8:18 | FastAPI router prefix is dynamic and could not be resolved |
| warning | fastapi_dynamic_api_route_methods | tests/fixtures/fastapi/main.py:36:2 | FastAPI api_route methods are dynamic or missing |
| warning | fastapi_dynamic_route_path | tests/fixtures/fastapi/main.py:41:2 | FastAPI route path is dynamic and could not be resolved |
| warning | fastapi_dynamic_include_router_prefix | tests/fixtures/fastapi/main.py:48:1 | FastAPI include_router prefix is dynamic and could not be resolved |

## Skipped Files

No files were skipped.

