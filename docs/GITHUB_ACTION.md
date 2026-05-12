# GitHub Action

AuthMap provides a composite GitHub Action for pull request authorization
coverage review. The action runs the local AuthMap CLI against the checked-out
repository, writes requested reports, and appends Markdown output to the job
summary when Markdown is generated.

The action is defensive and local-only. It statically scans source files and
does not run target applications, connect to databases, or perform live attack
workflows.

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
      - uses: bjcorder/AuthMap@v0
        with:
          mode: advisory
          output: markdown,json
```

By default, generated reports are written to `.authmap` and uploaded as the
`authmap-results` artifact.

## SARIF Upload

SARIF upload is opt-in because GitHub code scanning requires
`security-events: write`. If `upload-sarif` is true, the action ensures SARIF is
generated even when it is not listed in `output`.

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
      - uses: bjcorder/AuthMap@v0
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
| `baseline` | empty | Reserved for future baseline/diff support. Currently accepted but ignored with a warning. |
| `output-directory` | `.authmap` | Directory where generated reports are written. |
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
| `output-directory` | Absolute path to the report output directory. |

## Failure Behavior

Advisory mode prefers complete artifacts over failing fast. Recoverable scan
warnings do not fail the action.

Enforce mode writes each requested report before returning exit code `20` when
the completed AuthMap document contains enforce-blocking diagnostics. Other CLI
errors, such as invalid inputs or unreadable targets, fail immediately with the
CLI exit code.
