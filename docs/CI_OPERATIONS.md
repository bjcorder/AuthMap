# CI operations

Verify staged CI after workflow or settings changes using this checklist.
See [CONTRIBUTING](../CONTRIBUTING.md) and [RELEASING](../RELEASING.md) for branch/release procedures.
Record live verification and timing evidence before claiming savings.

## Expected checks

| Event | Expected work and final gate |
| --- | --- |
| Docs-only PR to `develop` | Plan and documentation validation; successful `development-gate`; heavy jobs skipped. |
| Code PR to `develop` | Ubuntu stable formatting, locked all-target workspace tests, existing-binary smoke; `development-gate`. |
| Dependency/action/performance PR to `develop` | Code checks plus applicable audit, dependency review, remote dependency validation, action smoke, and performance checks. |
| Any PR to `main` | Linux stable/1.95, macOS 1.95, Windows 1.95; CodeQL, audit, dependency review/validation, performance, action smoke, clean installation/package and version/changelog checks; `release-gate`. |
| Weekly/manual validation | Full `develop` integration checks plus explicit `main` audit; no PR dependency review; `release-gate`. |
| Push to `main` | Lightweight binary smoke/version verification; `release-gate`. |

Gates reject failures, cancellations, and unexpected skips. No `develop` push run occurs; publication requires a version tag.

## Verify and measure

1. Capture repository settings, rulesets, open PR bases, and workflow run IDs
   before changing settings. Confirm explicit branch rules require the matching
   gate, strict up-to-date checks, and protection against force pushes/deletion.
2. Inspect a meaningful docs-only PR to `develop`: verify the evaluated gate
   succeeds and heavy jobs skip. Inspect a representative code PR separately;
   confirm the single Rust cell and applicable targeted checks actually run.
3. Inspect a `develop`-to-`main` promotion PR: require all four Rust cells and
   full checks, then verify the resulting `main` push smoke. Do not create a tag
   for migration verification. Follow the existing branch synchronization flow.
4. Export run/job metadata for each case, retaining commit SHA, event, runner,
   conclusion, attempt, and job start/completion timestamps. Sum job elapsed
   seconds and divide by 60; report workflow wall-clock time separately.
5. Compare medians across several successful runs of each change category.
   Record cache state, runner variance, retries, and sample size. Compare Rust
   jobs with the Rust baseline; include every workflow for total-CI comparisons.

The captured 2026-09-14 baseline contains three successful six-cell Rust PR
runs: `34887100241` = 736 seconds (12.27 aggregate job-minutes),
`34887088688` = 770 seconds (12.83), and `34886907693` = 848 seconds (14.13).
The median is **12.83 aggregate job-minutes**, derived from job timestamps in
the migration's `timing-baseline.json`. This excludes other workflows and queue
time. Aggregate elapsed job-minutes are not billed minutes or a cost estimate.

## Recover safely

Pause merges if checks disappear or gates fail unexpectedly. Repair or revert
through a reviewed PR, retaining required gates and branch/tag protections.
Restore captured default-branch/PR-base settings if needed; match required
check names to the restored workflow before resuming. Preserve
branch history and tags; do not force-push or reset shared branches.
