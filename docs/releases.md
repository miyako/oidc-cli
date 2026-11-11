# Releases and wrapper consumption

This repository is standalone; no component-template initializer is required.
Go **1.26** is required; CI pins toolchain **1.26.10**. Source CI tests/vets on Linux, macOS, and
Windows and builds the native CLI with `CGO_ENABLED=0`; Linux also runs the race
detector. A cross-compiled Windows
asset is not evidence that it has been executed on native Windows; only an
actual successful Windows CI run supplies that evidence.

## Bump and publish from GitHub

After the workflow is merged into `main`, open **Actions → Bump version →
Run workflow**, select `main`, choose the increment, and run it. **This publishes
a release**, not just a version-only commit. No local build tools or personal
access token are needed; it uses the repository's workflow token.

The canonical source version is `cmd/oidc-cli/version.txt`, embedded into normal
Go builds. The choices have these semantics:

| Choice | Current `0.1.0-rc.1` becomes | From stable `1.2.3` |
| --- | --- | --- |
| `prerelease` (default) | `0.1.0-rc.2` | `1.2.4-rc.1` |
| `patch` | `0.1.0` (promotes the RC) | `1.2.4` |
| `minor` | `0.2.0` | `1.3.0` |
| `major` | `1.0.0` | `2.0.0` |

The workflow commits that version on the default branch and atomically pushes
the commit and annotated `v<version>` tag, refusing existing tags and stale
dispatches. It then **calls** the release workflow with the exact bumped commit,
which tests on all three platforms, packages, verifies checksums, and publishes.
This explicit call is necessary: tags pushed by `GITHUB_TOKEN` do not trigger
another push workflow. Release versions are injected from the tag during
packaging; source builds report the embedded version.

The repository must permit Actions write access to contents and its branch
rules must allow this bot commit. If branch protection rejects the atomic push,
neither the commit nor tag is pushed; do not disable protection blindly. There
is no automatic policy bypass. If testing/building/publishing fails after a
successful bump, fix the failure and use **Re-run failed jobs** where applicable;
do not rerun the bump to recreate the same tag. A published version is immutable.
An advanced recovery path is to rerun the tag's existing failed release job or
push a new reviewed version; never move an existing release tag.

Local preview without editing or publishing:

```sh
python3 scripts/bump_version.py prerelease --dry-run
```

## Local packaging

```sh
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/package_release.py --version 1.2.3
```

The full packaging command requires macOS and `lipo`. It builds
`./cmd/oidc-cli` with `-trimpath`, no cgo, and
`-ldflags "-s -w -X main.version=1.2.3"`. For local cross-compilation checks
without universal assembly, select e.g.
`--targets darwin_arm64 darwin_amd64 windows_amd64`.
Output goes to `dist/` (or `--output PATH`); intermediate binaries are under
its `build/` directory. Packaging does not publish or create tags.

For version `1.2.3`, the release assets are:

* `oidc-cli_1.2.3_darwin_arm64.tar.gz`
* `oidc-cli_1.2.3_darwin_amd64.tar.gz`
* `oidc-cli_1.2.3_darwin_universal.tar.gz`
* `oidc-cli_1.2.3_windows_amd64.zip`
* `SHA256SUMS`

Each archive contains only `oidc-cli` (macOS, mode 0755) or `oidc-cli.exe`
(Windows) at its root. The universal Mach-O is assembled and architecture-checked
with `lipo`. The manifest has lowercase SHA-256 digests, two spaces, and exact
archive basenames. Archive metadata is normalized, but this is not a claim of
bit-for-bit reproducible Go toolchains or signed provenance.

Pushing a `v<version>` tag also triggers `.github/workflows/release.yml` directly;
this is an alternative to the bump button, not an additional required step.
Invalid versions fail packaging. The workflow requires the same three-platform
source CI first, packages on macOS,
then verifies checksums and creates a GitHub Release for the **existing** tag.
Semver prerelease tags are marked as prereleases on GitHub.
The release workflow itself never increments versions, commits changes, or
creates tags; the separate bump job does that. All test/package jobs have
read-only repository permissions. Only bump and publication need
`contents:write`. Third-party actions use verified full commit SHAs.
No release has been published merely by adding these files.

## Unsigned binaries

These are **unsigned and not notarized**. No Apple Developer ID, notarization,
Windows Authenticode, or associated verification is configured. macOS quarantine
or Gatekeeper and Windows reputation policies can block downloads. SHA-256
validation detects unexpected bytes relative to the selected manifest; it is
not publisher authentication if an attacker can replace both assets and the
manifest. Decide your distribution/signing trust policy before production use.

## Pinned wrapper contract

Wrappers must pin a release tag, asset basename, and expected SHA-256 in their
own reviewed configuration; do not download `latest` at runtime. Select
`darwin_arm64`, `darwin_amd64`, or `darwin_universal` from host architecture and
`windows_amd64` only for supported Windows x64 environments. Example URL:

```text
https://github.com/miyako/oidc-cli/releases/download/v1.2.3/oidc-cli_1.2.3_darwin_arm64.tar.gz
```

Download over HTTPS, verify the pinned archive digest **before extraction or
execution**, and extract only the expected root executable (reject extra entries
and path traversal). Keep the executable in a wrapper-owned location and preserve
its executable mode on macOS. Run `version` and check its protocol JSON before
using it; consumers must explicitly support `protocol_version:1`.

Invoke `authenticate` with one strict JSON request on stdin. Read one result JSON
object from stdout, independently drain stderr, and handle nonzero exit status
and protocol failure results. Do not persist tokens or diagnostic authorization
URLs. Set a bounded caller deadline longer than the requested authentication
timeout, and pass `parent_pid` when the wrapper should terminate authentication
on its own exit. Protocol details belong to the repository's protocol
documentation, not an inferred shell-output contract.
