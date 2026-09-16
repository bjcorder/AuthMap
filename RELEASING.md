# Releasing AuthMap

This runbook cuts a new AuthMap GitHub Release. End-user artifact verification
instructions live in [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md).

AuthMap integrates on `develop` and releases from protected `main`. A release
preparation branch is rooted at `develop`; its version commit is squash-merged
into `develop`, then `develop` is promoted to `main` with a merge commit. The
release tag is created only after that promotion and points at the actual
validated `main` commit. Merging `main` does not publish by itself.

## One-time setup

```sh
cargo install cargo-release
gh auth status
```

For post-release provenance checks, install `slsa-verifier` from the upstream
release page or with Go:

```sh
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## Pre-flight

- `develop` is green and ready for promotion; the `release-gate` requirements
  are understood and available.
- You are on an up-to-date `develop`: `git switch develop && git pull --ff-only`.
- The working tree is clean.
- `CHANGELOG.md` has accurate user-facing notes under `## Unreleased`.
- No PR is mid-merge.

## Dry-run

```sh
cargo release patch --dry-run
```

Use `minor` or `major` instead of `patch` when the release scope requires it.
Read the version bump, changelog rewrite, commit message, and tag name before
continuing.

## Prepare the release commit

```sh
git switch -c "release/next"
cargo release patch --execute
VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
```

`release.toml` allows only `release/*` branches and sets cargo-release's
`tag = false`, `push = false`, and `publish = false`. The official
cargo-release reference documents `tag = false` as the configuration form of
`--no-tag`: [configuration reference](https://raw.githubusercontent.com/crate-ci/cargo-release/master/docs/reference.md).

Create the `release/*` preparation branch from `develop` before running the
command. The release config runs `cargo test --workspace --locked`, bumps the shared
workspace version, rewrites `CHANGELOG.md`, and creates the version commit. It
does not tag, push, or publish.

## Merge through develop and promote main

```sh
git push -u origin "release/next"

gh pr create --base develop --head "release/next" \
  --title "chore: release ${VERSION}" \
  --body "Release version commit. Squash into develop, then promote develop to main with a merge commit."
```

After the preparation PR passes `development-gate`, squash-merge it into
`develop`. Open the promotion PR from `develop` to `main` and merge it with a
merge commit after `release-gate` passes. Record the resulting `main` SHA.

## Create the immutable tag on main

After the PR merges:

```sh
git switch main
git pull --ff-only

MAIN_SHA=$(git rev-parse HEAD)
git show-ref --verify --quiet "refs/tags/v${VERSION}" \
  && { echo "tag already exists; published tags are immutable"; exit 1; } || true

git tag -a "v${VERSION}" "$MAIN_SHA" -m "Release v${VERSION}"
git push origin "v${VERSION}"
```

The tag push triggers the release workflow for
`Ozark-Security-Labs/AuthMap`.

## Watch and verify

Watch the release workflow:

```sh
gh run watch -R Ozark-Security-Labs/AuthMap
```

After the release publishes, verify at least one binary archive and the source
archive:

```sh
TAG=v1.0.1
gh release download "$TAG" -R Ozark-Security-Labs/AuthMap \
  -p '*.tar.gz' -p '*.zip' -p '*.sha256' -p '*.intoto.jsonl'

slsa-verifier verify-artifact \
  --provenance-path "authmap-${TAG#v}.intoto.jsonl" \
  --source-uri github.com/Ozark-Security-Labs/AuthMap \
  --source-tag "$TAG" \
  "authmap-${TAG#v}-source.tar.gz"
```

Unpack one platform archive and run:

```sh
authmap --help
authmap --version
```

## Rollback

Published release tags are immutable: repository rules block tag deletion and
force-push. If a release is wrong, fix the source on `main`, sync it back to
`develop`, and cut the next patch version. Do not reset a branch destructively
or reuse a published version number.
