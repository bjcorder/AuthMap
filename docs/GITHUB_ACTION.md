# GitHub Action

AuthMap provides a composite GitHub Action for pull request authorization
coverage review. The action runs the local AuthMap CLI against the checked-out
repository, writes requested reports, and appends Markdown output to the job
summary when Markdown is generated. When `baseline` is set, it also generates a
current JSON map, runs a map-file drift diff, and appends drift Markdown to the
same summary.

The action is defensive and local-only. It statically scans source files and
does not run target applications, connect to databases, or perform live attack
workflows. Privacy, report-sensitivity, artifact, SARIF, baseline, and sharing
guidance is documented in [DATA_HANDLING.md](DATA_HANDLING.md).

## Basic Pull Request Workflow

```yaml
name: AuthMap
on:
  pull_request:

permissions:
  contents: read

jobs:
  authmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ozark-Security-Labs/AuthMap@v1
        with:
          mode: advisory
          output: markdown,json
```

By default, generated reports are written to `.authmap` and uploaded as the
`authmap-results` artifact. The artifact upload is limited to the report files
generated during this action run, not the entire output directory. AuthMap
redacts obvious secrets before writing reports and job summaries, but artifacts
can still reveal sensitive application structure, routes, file paths, line
numbers, and review rationale. Treat uploaded reports as sensitive review
material unless your organization has approved broader sharing. Set
`upload-artifact: "false"` when generated reports should not be published as
workflow artifacts.

## Baseline Drift Review

Provide an AuthMap JSON baseline to review authorization drift in pull requests.
When a pull request base SHA is available, the action reads the baseline from
that trusted base commit instead of the PR checkout so a PR cannot mask drift by
changing its own baseline file. Set `baseline-ref` to a protected branch, tag, or
commit SHA when another trusted baseline source is required. The action writes
`authmap.diff.json` and `authmap.diff.md` into the output directory and uploads
them with the other reports when artifact upload is enabled.

```yaml
name: AuthMap drift
on:
  pull_request:

permissions:
  contents: read

jobs:
  authmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ozark-Security-Labs/AuthMap@v1
        with:
          mode: enforce
          output: markdown,json
          baseline: authmap.baseline.json
          fail-on: added_high_risk_route,auth_downgrade,new_linked_mutation
```

## SARIF Upload

SARIF upload is opt-in because GitHub code scanning requires
`security-events: write`. If `upload-sarif` is true, the action ensures SARIF is
generated even when it is not listed in `output`. Uploaded SARIF can expose
route, source-location, diagnostic, and review-priority details through
code-scanning surfaces.

```yaml
name: AuthMap
on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  authmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ozark-Security-Labs/AuthMap@v1
        with:
          mode: advisory
          output: markdown,json,sarif
          upload-sarif: "true"
          sarif-category: authmap
```

Pull requests from forks may not receive `security-events: write` depending on
repository settings. In those workflows, keep `upload-sarif` false and upload
the generated SARIF file as an artifact instead.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `mode` | `advisory` | AuthMap scan mode. Use `enforce` to return exit code `20` for enforce-blocking diagnostics after reports are written. |
| `output` | `markdown,json` | Comma-separated report formats. Supported values are `markdown`, `json`, and `sarif`. |
| `target` | `.` | Target path to scan, relative to the checked-out repository workspace. |
| `config` | empty | Optional `authmap.yml` path, relative to the checked-out repository workspace. |
| `baseline` | empty | Optional AuthMap JSON baseline path, relative to the checked-out repository workspace or trusted `baseline-ref`. When set, the action generates a current JSON map, runs `authmap diff --base ... --head ...`, and appends drift Markdown to the job summary. |
| `baseline-ref` | pull request base SHA when available | Optional trusted git ref used to read the baseline file, such as a protected branch, tag, or commit SHA. |
| `fail-on` | empty | Optional comma-separated drift categories that override `drift.fail_on` for baseline diffs. |
| `output-directory` | `.authmap` | Workspace-relative directory where generated reports are written. The workspace root itself is rejected. |
| `upload-artifact` | `true` | Upload generated reports with `actions/upload-artifact`. |
| `artifact-name` | `authmap-results` | Name for the uploaded report artifact. |
| `upload-sarif` | `false` | Upload SARIF to GitHub code scanning. Requires `security-events: write`. |
| `sarif-category` | `authmap` | Category name for GitHub code scanning SARIF upload. |

## Outputs

| Output | Description |
| --- | --- |
| `json-path` | Absolute path to `authmap.json` when JSON is generated. |
| `markdown-path` | Absolute path to `authmap.md` when Markdown is generated. |
| `sarif-path` | Absolute path to `authmap.sarif` when SARIF is generated. |
| `diff-json-path` | Absolute path to `authmap.diff.json` when `baseline` is set. |
| `diff-markdown-path` | Absolute path to `authmap.diff.md` when `baseline` is set. |
| `output-directory` | Absolute path to the report output directory. |

## Failure Behavior

Advisory mode prefers complete artifacts over failing fast. Recoverable scan
warnings do not fail the action.

Enforce mode writes each requested report before returning exit code `20` when
the completed AuthMap document contains enforce-blocking diagnostics. With a
baseline, enforce mode also returns `20` when drift matches the effective
`fail-on` policy. Supported fail-on categories include
`added_high_risk_route`, `added_review_required_route`, `auth_downgrade`,
`new_linked_mutation`, `removed_authorization_evidence`, and
`policy_decision_change`. Other CLI errors, such as invalid inputs, unreadable
targets, or missing baselines, fail with the CLI exit code.

Path-like action inputs (`target`, `config`, `baseline`, and
`output-directory`) are workspace-relative only. Absolute paths, parent
directory components, empty path components, control characters, and
`output-directory: .` are rejected before AuthMap runs. `baseline-ref` must be a
git ref, tag, or commit SHA without whitespace, control characters, or a leading
`-`. The baseline must be an existing AuthMap JSON document; create one with
`authmap baseline create . --output authmap.baseline.json` and commit or restore
it on the trusted baseline ref before the action runs.
