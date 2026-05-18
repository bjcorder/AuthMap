# Verifying AuthMap Releases

AuthMap release artifacts include SHA-256 sidecars and SLSA provenance. Use
both before trusting a downloaded binary in a sensitive environment.

## What Verification Covers

SLSA verification confirms that an artifact digest appears in a Sigstore-signed
attestation for:

- source repo `github.com/Ozark-Security-Labs/AuthMap`;
- source tag `vX.Y.Z`;
- the release workflow at that tag; and
- GitHub Actions workflow identity recorded in the attestation.

It does not prove the source code is bug-free or that a scan result is a
confirmed vulnerability.

## Install Tools

Install `gh` and `slsa-verifier`. One option for `slsa-verifier` is:

```sh
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## Verify Checksums

```sh
TAG=v1.0.1

gh release download "$TAG" -R Ozark-Security-Labs/AuthMap \
  -p '*.tar.gz' -p '*.zip' -p '*.sha256' -p '*.intoto.jsonl'

sha256sum --check "authmap-${TAG#v}-source.tar.gz.sha256"
```

For macOS or Windows archives, check the matching `authmap-${TAG#v}-...`
`.sha256` file for your platform.

## Verify SLSA Provenance

```sh
slsa-verifier verify-artifact \
  --provenance-path "authmap-${TAG#v}.intoto.jsonl" \
  --source-uri github.com/Ozark-Security-Labs/AuthMap \
  --source-tag "$TAG" \
  "authmap-${TAG#v}-source.tar.gz"
```

Repeat the command for the platform archive you plan to run, for example:

```sh
slsa-verifier verify-artifact \
  --provenance-path "authmap-${TAG#v}.intoto.jsonl" \
  --source-uri github.com/Ozark-Security-Labs/AuthMap \
  --source-tag "$TAG" \
  "authmap-${TAG#v}-x86_64-unknown-linux-gnu.tar.gz"
```

A successful run ends with `PASSED: SLSA verification passed`.

## Smoke Test The Binary

Unpack the archive for your platform and run:

```sh
./authmap --help
./authmap --version
```

On Windows, run `authmap.exe --help` and `authmap.exe --version` from the
expanded archive.

If checksum or SLSA verification fails, do not run the artifact. Open an issue
with the verifier output.
