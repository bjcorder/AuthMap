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

First-party codes are namespaced by category. New codes should be added to
`authmap-core` before producers start emitting them.

## Initial First-Party Codes

| Code | Meaning |
| --- | --- |
| `config.read_failed` | Config file could not be read |
| `config.parse_failed` | Config file could not be parsed |
| `config.validation_failed` | Config values failed validation |
| `config.invalid_pattern` | Include or exclude pattern is invalid |
| `discovery.no_candidate_sources` | No supported source files were discovered |
| `discovery.file_too_large` | Supported source file exceeded size limits |
| `discovery.file_limit_reached` | Candidate count exceeded `limits.max_files` |
| `discovery.target_unavailable` | Scan target is missing or unreadable |
| `discovery.empty_target` | Enforce-mode target has no supported sources |
| `discovery.metadata_failed` | File metadata could not be read |
| `parser.source_language_unsupported` | No parser is configured for the language |
| `parser.source_parse_recovered` | Parser recovered from source syntax errors |
| `parser.source_read_failed` | Source file could not be read as text |
| `parser.source_parse_failed` | Parser setup or tree creation failed |
| `adapter.unsupported_framework` | Adapter cannot handle the detected framework |
| `adapter.partial_result` | Adapter emitted partial facts with caveats |
| `report.render_failed` | Report rendering failed |
| `report.write_failed` | Report writing failed |
| `internal.scan_failed` | Unexpected internal scan failure |

## Severity And Exit Behavior

Advisory mode prefers complete artifacts over failing fast. Recoverable
diagnostics, including parser and adapter errors, can still produce a valid map
and exit `0`.

Enforce mode also writes the requested artifact first. If the completed
document contains any diagnostic with `severity: "error"` or
`recoverability: "fatal"`, the CLI exits `20` after writing the report.
Warnings remain non-blocking.

Hard process failures do not produce a report and use their dedicated exit
codes: CLI usage `2`, target unavailable `10`, empty enforce target `11`,
config `12`, internal scan `13`, and report render/write `14`.
