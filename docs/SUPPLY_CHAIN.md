# Supply Chain Security

AuthMap is a defensive security CLI that runs on developer machines and in CI. Dependency and workflow changes should keep that trust boundary conservative, reviewable, and reproducible.

## Dependency automation

Dependabot is configured for the Rust Cargo workspace and GitHub Actions workflows in [`.github/dependabot.yml`](../.github/dependabot.yml). It opens weekly dependency update pull requests with dependency labels so maintainers can review Cargo and workflow updates separately.

Dependency update pull requests should be reviewed like code changes:

- confirm the update is needed and within the expected dependency ecosystem;
- review release notes or changelogs for security, licensing, build-script, network, or behavior changes;
- verify the dependency still fits AuthMap's defensive, local-only scope;
- keep dependency changes separate from unrelated feature work whenever practical; and
- require the normal CI and security workflows to pass before merge.

## Lockfile policy

`Cargo.lock` is committed and is part of the reviewed supply-chain state. Pull requests that change resolved Rust dependencies should include the corresponding `Cargo.lock` diff.

Maintainers should not regenerate the lockfile solely to pick up unrelated transitive updates. When a lockfile change is necessary, the pull request should make the reason clear, such as a direct dependency update, a security advisory remediation, or a toolchain-compatible resolution change.

CI uses locked Cargo commands for workspace checks, tests, audits, and install smoke tests. A pull request with manifest changes but a stale lockfile should fail before release.

## CI security checks

The security workflow runs dependency checks on pull requests, pushes to `main`, and a weekly schedule:

- GitHub dependency review runs on pull requests to surface vulnerable, unexpected, or license-sensitive dependency changes.
- `cargo audit` checks Rust advisories against the committed lockfile.
- Dependency determinism runs separately and uploads SARIF so maintainers can review lockfile and registry consistency signals.
- CodeQL runs Rust analysis with the repository's pinned workflow actions.

Security-related dependency failures should be treated as release blockers unless maintainers document why the finding is not applicable to AuthMap's shipped CLI or composite action.

## GitHub Actions pinning and permissions

Repository workflows should use the least privilege required for each job. The default posture is `contents: read`; workflows may add permissions such as `security-events: write` only when a job uploads SARIF or otherwise requires that scope.

Third-party GitHub Actions used by repository workflows and the composite action should be pinned to full commit SHAs. Version tags are acceptable only in user-facing documentation examples where readability matters and the example is not executed by this repository's CI.

Dependabot tracks GitHub Actions updates, but maintainers should still review pinned-action updates for upstream ownership, expected behavior, and permission changes before merging.

## License review

Workspace packages declare the project license through Cargo metadata. Runtime dependency changes should be reviewed for license compatibility with AuthMap's MIT license and with anticipated public package distribution.

When adding a new direct dependency, reviewers should check the dependency's declared license, transitive dependency impact, and whether the crate introduces build scripts, native code, or network behavior. If the license or distribution impact is unclear, do not merge the dependency change until the concern is resolved or documented in the pull request.

## Release artifact sanity checks

The release process and compatibility policy are documented in [RELEASES.md](RELEASES.md). Before publishing public packages or release artifacts, maintainers should verify that CI has completed successfully on the release commit and that the locked install smoke test passes for the `authmap` CLI. The smoke test installs from `crates/authmap-cli`, runs `authmap --help`, and generates JSON, Markdown, baseline, and diff outputs against a static fixture.

For a manual pre-release check, run:

```sh
cargo test --workspace --all-targets --locked
cargo install --path crates/authmap-cli --locked --root /tmp/authmap-install --debug --force
/tmp/authmap-install/bin/authmap --help
cargo package --list --manifest-path crates/authmap-cli/Cargo.toml --locked
```

Tagged release automation should generate platform archives, `SHA256SUMS`, and provenance metadata when GitHub artifact attestation support is available. Release artifacts should not include generated reports, local baselines, credentials, or target application source code beyond what is intentionally packaged by Cargo.
