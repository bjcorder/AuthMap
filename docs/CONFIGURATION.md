# AuthMap Configuration

AuthMap reads optional project settings from `authmap.yml` with `authmap scan
--config authmap.yml`. Run `authmap init` to generate a documented starter
file, or use `authmap init --yes --output authmap.yml --force` in scripts.

The output schema version is unchanged by configuration. Project rules only add
evidence, coverage support metadata, reviewer questions, and scan behavior.

## Top-Level Settings

```yaml
mode: advisory

include: []
exclude: []

limits:
  max_files: 50000
  max_file_size_bytes: 2097152
  max_total_bytes: 268435456
  max_runtime_ms: 120000
```

`mode` may be `advisory` or `enforce`. CLI `--mode` overrides the config value.
`include` and `exclude` use gitignore-style patterns. Includes narrow scanned
source files; excludes take precedence. Limits must be greater than zero.

`limits.max_files` caps supported source candidates after deterministic sorting.
`limits.max_file_size_bytes` skips individual source files that are too large to
read safely. `limits.max_total_bytes` bounds the total bytes AuthMap will read
from included source files; later files are represented as skipped partial input.
`limits.max_runtime_ms` is a cooperative wall-clock budget checked between scan
phases. It does not cancel an in-flight parser call.

Discovery also stops walking after collecting a bounded sample proportional to
`max_files`. AuthMap keeps deterministic ordering for the collected sample and
retains skipped-file entries for a bounded set of omitted supported files, but it
does not try to enumerate every omitted file in very large repositories. This is
intentional: full omitted-file audit logs would make the file limit itself a
memory risk.

The CLI can override scan limits without editing `authmap.yml`:

```sh
authmap scan . --max-files 10000 --max-total-bytes 134217728
authmap rules suggest . --max-file-size-bytes 1048576 --max-runtime-ms 60000
```

Memory usage is bounded indirectly by `max_files`, `max_file_size_bytes`,
`max_total_bytes`, and the discovery collection cap. The defaults are intended
for typical CI runners; lower them for constrained environments.

## Authorization Rules

Custom authorization rules convert project-specific guard names into canonical
evidence.

```yaml
authorization:
  rules:
    - name: billing permission guard
      evidence_type: permission_check
      mechanism: billing_plan_guard
      confidence: medium
      match:
        exact: [ensurePaidPlan]
        contains: [permission]
      notes:
        - configured by project
```

Supported `evidence_type` values are the canonical AuthMap evidence types:
`authn`, `role_check`, `permission_check`, `ownership_check`, `tenant_check`,
`admin_check`, `explicit_public`, `audit_log`, and `unknown_dynamic_check`.

Matching is intentionally conservative:

- `exact` matches the full symbol or path string.
- `contains` is case-insensitive substring matching.
- Regexes and globs are not supported in rule matchers.

Rule names, mechanisms, and matcher entries must be nonempty. Unknown fields are
rejected.

## Sensitivity Rules

Sensitivity rules label routes or linked mutation resources so coverage scoring
can ask the right review questions without claiming a vulnerability.

```yaml
sensitivity:
  routes:
    - name: account routes
      labels: [account_data, pii]
      match:
        contains: [/accounts]
      methods: [GET, POST, PATCH, DELETE]
      reviewer_questions:
        - Should account routes require ownership or permission checks?
      notes:
        - Project-specific sensitive route family.
  resources:
    - name: invoice mutations
      labels: [financial]
      match:
        exact: [Invoice]
      reviewer_questions:
        - Should invoice writes require finance approval?
```

Route rules match route paths and optional HTTP methods. Resource rules match
existing linked mutation `resource` values; they do not create mutations or
links by themselves.

Labels are emitted as coverage sensitivity reasons:

- Route labels become `config_route:<label>`.
- Resource labels become `config_resource:<label>`.

Configured reviewer questions are merged into `coverage.reviewer_questions`,
sorted, and deduplicated.

## Risk Semantics

Configured sensitivity is a prioritization signal. It can raise no-evidence
routes into `medium` or, when combined with unsafe methods or linked mutations,
`high` according to the v1 coverage rules. Weak, dynamic, public, or authn-only
coverage on sensitive routes becomes `review_required`.

AuthMap reports these as review prompts, not vulnerability findings.

## Command Helpers

`authmap explain <id>` reads a local AuthMap JSON document and prints a
deterministic terminal explanation. The default input is `authmap.json` in the
current directory; pass `--input <path>` to select another JSON report. The
command supports route IDs plus fact IDs from `evidence`, `mutations`, and
`links`. It validates the JSON schema version before rendering and fails
nonzero for missing files, invalid JSON, unsupported schema versions, unknown
IDs, and IDs that appear in multiple namespaces. Risk text is phrased as review
priority, not a confirmed vulnerability.

`authmap rules suggest [target]` scans local source and prints reviewable
starter `authorization.rules[]` suggestions. It is read-only: it does not edit
`authmap.yml` or apply suggestions automatically. Defaults are target `.`,
Markdown output, and stdout. Use `--format json` for machine-readable output,
`--output <path>` to write the report, and `--config <path>` to reuse
include/exclude limits and suppress suggestions already covered by custom
rules. Suggestions are heuristics and should be reviewed before copying into
configuration.
