# Release Policy

AuthMap releases package the defensive CLI, JSON schema contract, report renderers, and composite GitHub Action behavior that users rely on in local review and CI. Releases should be reproducible from a signed or protected git tag and should include enough compatibility notes for users to decide whether to upgrade immediately.

## Versioning model

AuthMap uses semantic versioning for the workspace package version and release tags. Tags use the form `vMAJOR.MINOR.PATCH`, and the tag version must match the Cargo workspace package version.

Compatibility expectations are:

- **Major** releases may include breaking CLI, schema, configuration, report, or GitHub Action changes.
- **Minor** releases may add new commands, flags, schema fields, diagnostics, report sections, action inputs, or non-breaking behavior.
- **Patch** releases should contain bug fixes, dependency updates, documentation corrections, and release automation fixes.

## Compatibility expectations

### CLI

Documented commands, flags, exit-code meanings, and output-format names are user-facing behavior. Removing a command, renaming a flag, changing the meaning of an exit code, or changing default behavior requires a compatibility note. Additive flags and commands are non-breaking when existing invocations continue to work.

### JSON schema

The canonical AuthMap document schema is versioned independently in `schema_version`. Schema changes must update `schemas/authmap.schema.json`, `docs/SCHEMA.md`, examples or golden output when applicable, and the changelog.

Breaking schema changes include removing required fields, changing field types, changing enum values, or changing the meaning of existing fields. Additive fields are acceptable only through the documented extension points or through an intentional schema-version change.

Release notes should call out schema compatibility whenever the JSON contract, drift JSON contract, extension behavior, diagnostics, IDs, or deterministic ordering changes.

### Configuration

`authmap.yml` compatibility covers documented keys, default values, validation behavior, and project-rule semantics. Removing keys, changing default enforcement behavior, or changing rule interpretation requires a compatibility note. New optional keys are non-breaking when existing configuration files continue to load with the same meaning.

### Reports

Markdown and SARIF are user-facing review outputs. Markdown is optimized for humans and may receive additive sections in minor releases. SARIF output should remain suitable for advisory code-scanning integration. Changes to alert severity, result locations, rule IDs, or report failure behavior require release-note coverage.

### GitHub Action

The composite action follows the release tag. Existing documented inputs and outputs should remain stable within a major release after 1.0. New optional inputs are non-breaking. Removing inputs, changing defaults, changing artifact behavior, or requiring new workflow permissions requires a compatibility note.

## Changelog discipline

Every user-visible change should update `CHANGELOG.md` under `Unreleased` before merge. Release pull requests move entries from `Unreleased` into the new version section and add schema compatibility notes when relevant.

Use these categories when they fit:

- `Added`
- `Changed`
- `Deprecated`
- `Removed`
- `Fixed`
- `Security`

Keep changelog entries evidence-bound. Do not describe AuthMap findings as confirmed vulnerabilities unless the project can mechanically prove that claim.

## Release checklist

Before creating a release tag, maintainers should verify:

1. `CHANGELOG.md` has a dated section for the release and an empty `Unreleased` section.
2. The Cargo workspace version matches the intended tag.
3. Schema compatibility notes are present when schema-facing behavior changed.
4. The release commit has passed the normal Rust, docs, action smoke, security, and dependency determinism workflows.
5. `cargo test --workspace --all-targets --locked` passes locally or in CI.
6. `cargo package --list --manifest-path crates/authmap-cli/Cargo.toml --locked` shows only intended package contents.
7. A clean `cargo install --path crates/authmap-cli --locked` can run `authmap --help` and `authmap --version`.
8. Release artifacts do not include generated reports, local baselines, credentials, or scanned target source code beyond intended package contents.

## Automated release workflow

The release workflow runs on `v*` tags and can also be started manually by maintainers. It checks that the tag matches the workspace version, runs locked tests, builds platform binaries, generates SHA-256 checksums, and creates or updates a GitHub Release from the changelog section for that version.

The workflow publishes GitHub Release artifacts only. It does not publish crates to crates.io or any package registry. Cargo package artifacts are used to review package contents while AuthMap's internal crates remain unpublished. Registry publishing requires a separate reviewed policy and explicit maintainer approval.

Release artifacts should include:

- platform-specific `authmap` binaries packaged as archives;
- `SHA256SUMS`; and
- provenance metadata when GitHub artifact attestation support is available in the runner environment.

`authmap --version` prints one deterministic line containing the CLI package
version and AuthMap schema version.

## Supported versions

Supported release lines are documented in `SECURITY.md` and updated when support windows change.
