# AuthMap Diagnostics

AuthMap diagnostics are structured scan events that explain incomplete input,
recoverable parser or adapter issues, configuration failures, report failures,
and future policy decisions. JSON reports include diagnostics in
`diagnostics[]`; Markdown and SARIF reports surface the same events for review
and CI systems.

## Fields

Each diagnostic contains:

- `category`: one of `config`, `discovery`, `parser`, `adapter`, `report`,
  `internal`, or `policy`.
- `code`: a stable namespaced identifier such as
  `discovery.no_candidate_sources` or `parser.source_parse_recovered`.
- `severity`: `info`, `warning`, or `error`.
- `recoverability`: `recoverable` when AuthMap can still emit a partial map, or
  `fatal` when the scan cannot continue safely.
- `span`: optional source location.
- `message`: human-readable context.

Most first-party codes are namespaced by category. Framework adapter diagnostics
may use stable framework-specific prefixes such as `django_`, `drf_`, or
`nextjs_`. New codes should be added to `authmap-core` before producers start
emitting them.

## Initial First-Party Codes

| Code | Meaning |
| --- | --- |
| `config.read_failed` | Config file could not be read |
| `config.parse_failed` | Config file could not be parsed |
| `config.validation_failed` | Config values failed validation |
| `config.invalid_pattern` | Include or exclude pattern is invalid |
| `discovery.no_candidate_sources` | No supported source files were discovered |
| `discovery.file_too_large` | Supported source file exceeded size limits |
| `discovery.file_limit_reached` | Supported source discovery or candidate count exceeded `limits.max_files` |
| `discovery.total_bytes_limit_reached` | Source byte budget exceeded `limits.max_total_bytes` |
| `discovery.target_unavailable` | Scan target is missing or unreadable |
| `discovery.empty_target` | Enforce-mode target has no supported sources |
| `discovery.metadata_failed` | File metadata could not be read |
| `parser.source_language_unsupported` | No parser is configured for the language |
| `parser.source_parse_recovered` | Parser recovered from source syntax errors |
| `parser.source_read_failed` | Source file could not be read as text |
| `parser.source_parse_failed` | Parser setup or tree creation failed |
| `adapter.unsupported_framework` | Adapter cannot handle the detected framework |
| `adapter.partial_result` | Adapter emitted partial facts with caveats |
| `django_custom_router` | DRF custom router behavior could not be resolved statically |
| `django_dynamic_include` | Django include target is dynamic or missing |
| `django_dynamic_include_helper` | Django include target is a helper call that could not be expanded statically |
| `django_include_depth_exceeded` | Django include chain exceeded the maximum static include depth |
| `django_dynamic_url_path` | Django URL path is dynamic and could not be resolved |
| `django_dynamic_settings_default` | DRF settings default is dynamic and emitted as review-only context |
| `django_unresolved_handler` | Django URL handler could not be resolved statically |
| `django_unresolved_include` | Django include module could not be resolved statically |
| `django_urlpattern_context_uncertain` | Django URL helper call was outside a recognized `urlpatterns` context |
| `drf_dynamic_basename` | DRF router basename is dynamic and could not be resolved |
| `drf_dynamic_router_prefix` | DRF router registration prefix is dynamic and could not be resolved |
| `drf_unresolved_viewset` | DRF router viewset could not be resolved statically |
| `drf_unresolved_viewset_base` | DRF viewset base class could not be resolved to a known framework base |
| `nextjs_dynamic_route_export` | Next.js route handler export value is dynamic or unsupported |
| `nextjs_external_reexport_unresolved` | Next.js route handler re-export target could not be resolved or analyzed statically |
| `nextjs_nested_app_segment` | Next.js route file path contains nested `app` segments |
| `nextjs_unusual_route_segment` | Next.js route segment uses an unusual routing convention |
| `nextjs_server_action_not_analyzed` | Next.js Server Action file (`'use server'`) was seen but not analyzed for routes or authorization |
| `report.render_failed` | Report rendering failed |
| `report.write_failed` | Report writing failed |
| `policy.conflicting_evidence` | Explicit public and authorization-required evidence both appear on a route |
| `policy.duplicate_evidence` | Duplicate guard or policy evidence appears on a route |
| `policy.unreachable_branch` | Policy evidence appears inside a statically unreachable branch |
| `policy.dynamic_behavior` | Dynamic policy evidence requires review |
| `internal.scan_failed` | Unexpected internal scan failure |
| `internal.runtime_limit_reached` | Scan exceeded cooperative runtime budget |

## Severity And Exit Behavior

Advisory mode prefers complete artifacts over failing fast. Recoverable
diagnostics, including parser and adapter errors, can still produce a valid map
and exit `0`.

Enforce mode also writes the requested artifact first. If the completed
document contains any diagnostic with `severity: "error"` or
`recoverability: "fatal"`, the CLI exits `20` after writing the report.
Warnings remain non-blocking. Discovery diagnostics that mean the scan is
incomplete, such as `discovery.file_limit_reached`,
`discovery.file_too_large`, `discovery.total_bytes_limit_reached`, and
`internal.runtime_limit_reached`, are warnings in advisory mode and errors in
enforce mode.

`discovery.file_limit_reached` can appear both as a scan diagnostic and as a
`source_files[].skipped.code` value for a deterministic bounded sample of
omitted files. AuthMap intentionally does not list every omitted file when
discovery itself has been capped, because doing so would defeat the memory
budget.

Hard process failures do not produce a report and use their dedicated exit
codes: CLI usage `2`, target unavailable `10`, empty enforce target `11`,
config `12`, internal scan `13`, and report render/write `14`.
