# Releases and wrapper consumption

This repository is standalone; no component-template initializer is required.
Go **1.26** is required; CI pins toolchain **1.26.10**. Source CI tests/vets on Linux, macOS, and
Windows and builds the native CLI with `CGO_ENABLED=0`; Linux also runs the race
detector. A cross-compiled Windows
asset is not evidence that it has been executed on native Windows; only an
actual successful Windows CI run supplies that evidence.

## Build and publish

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

Only pushing a `v<version>` tag triggers `.github/workflows/release.yml`.
Invalid versions fail packaging. The workflow requires the same three-platform
source CI first, packages on macOS,
then verifies checksums and creates a GitHub Release for the **existing** tag.
Semver prerelease tags are marked as prereleases on GitHub.
It never increments versions, commits changes, or creates tags. All jobs have
read-only repository permissions except the isolated publication job, which
needs `contents:write`. Third-party actions use verified full commit SHAs.
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
