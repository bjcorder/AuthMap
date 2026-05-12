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
```

`mode` may be `advisory` or `enforce`. CLI `--mode` overrides the config value.
`include` and `exclude` use gitignore-style patterns. Includes narrow scanned
source files; excludes take precedence. Limits must be greater than zero.

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

Supported `evidence_type` values are the canonical AuthMap evidence types such
as `authn`, `role_check`, `permission_check`, `ownership_check`, `tenant_check`,
`admin_check`, `policy_check`, `explicit_public`, and `unknown_dynamic_check`.

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
