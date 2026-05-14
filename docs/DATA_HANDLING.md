# Data Handling And Privacy

AuthMap performs local static analysis of source code. It does not run the
target application, import target modules, connect to databases, call services,
or perform live attack workflows.

## What AuthMap Reads

AuthMap reads local files needed to build an authorization map:

- supported source files under the scan target, subject to `include`, `exclude`,
  and scan limit settings
- optional `authmap.yml` configuration files
- optional AuthMap JSON inputs used by commands such as `explain`, `diff`, and
  baseline comparison
- committed git refs for `authmap diff <range>`; range diffs use `git archive`
  into temporary directories and do not include uncommitted working-tree changes

AuthMap does not need application credentials, database connections, service
accounts, runtime secrets, or a running copy of the target application.

## What AuthMap Writes

Depending on the command and options, AuthMap may write:

- Markdown reports for human review
- canonical AuthMap JSON documents
- SARIF files for code-scanning integrations
- drift JSON and Markdown reports
- baseline JSON documents
- rule suggestion output
- explain output
- diagnostics and skipped-file summaries inside reports

When `--output` is omitted, report content is printed to stdout. In GitHub
Actions, Markdown output may also be appended to the job summary.

## Report Sensitivity

AuthMap reports can contain security-sensitive application evidence, including:

- route paths, HTTP methods, and handler symbols
- file paths, line numbers, columns, and source spans
- authorization evidence names and mechanisms
- linked service calls and data mutations
- coverage classifications, risk priorities, rationale, uncertainty notes, and
  reviewer questions
- diagnostics about unsupported files, dynamic behavior, skipped files, and
  incomplete scans

Treat Markdown, JSON, SARIF, baseline, drift, rule-suggestion, and explain
outputs as sensitive review material unless your organization has approved
broader sharing.

## Redaction

AuthMap redacts obvious high-risk values before writing JSON, Markdown, SARIF,
drift reports, rule suggestions, and explain output. Redaction covers common
authorization headers, credentials in URLs, token-like query parameters,
secret-looking assignments, and common token shapes.

Redaction is best-effort. It reduces accidental exposure risk, but reports can
still contain sensitive application structure and non-obvious secrets. Review
artifacts before sharing them outside trusted project, security, or CI scopes.

## Network Transmission

AuthMap does not transmit source code, findings, reports, baselines, or telemetry
by default. Local CLI commands read local inputs and write local outputs or
stdout.

Integrations can introduce sharing when they upload or publish generated output.
For example, the GitHub Action can upload workflow artifacts, append Markdown to
step summaries, and optionally upload SARIF to GitHub code scanning. Those
integrations are controlled by workflow configuration and platform permissions,
not by a default AuthMap network submission path.

## CI And GitHub Actions

The composite GitHub Action runs AuthMap against the checked-out repository. By
default, it writes generated reports under `.authmap`, uploads generated report
files as the `authmap-results` artifact, and appends Markdown output to the job
summary when Markdown is generated.

CI users should consider:

- job summaries are visible to users who can view the workflow run
- uploaded artifacts are visible according to repository and workflow access
  rules
- SARIF upload is opt-in and requires `security-events: write`; uploaded SARIF
  becomes available through the platform's code-scanning surfaces
- baseline and drift artifacts may reveal authorization changes across releases
  or pull requests
- pull requests from forks can have different artifact, token, and
  code-scanning permission behavior depending on repository settings

Set `upload-artifact: "false"` when reports should stay only in the runner logs
or workspace, and keep `upload-sarif: "false"` unless code-scanning publication
is intended.

## Baselines And Diffs

Baselines are ordinary AuthMap JSON documents. They can preserve historical
route, evidence, mutation, coverage, diagnostic, and source-location details.
Store baselines where that level of application-structure disclosure is
acceptable.

Diff reports can highlight newly added routes, authorization downgrades, and new
linked mutations. Treat drift output as sensitive because it can reveal security
review priorities and recent authorization changes.

## Safe Handling Guidance

- Store generated reports and baselines in access-controlled locations.
- Avoid attaching raw reports to public issues, public pull requests, or support
  requests unless they have been reviewed and sanitized.
- Prefer minimal excerpts when discussing findings externally.
- Use repository or organization retention settings to limit CI artifact
  lifetime when appropriate.
- Review SARIF upload permissions and code-scanning visibility before enabling
  `upload-sarif`.
- Sanitize paths, route names, source snippets, and reviewer rationale before
  sharing outside trusted teams.
