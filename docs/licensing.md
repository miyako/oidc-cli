# Licensing and v0.1.1 redistribution notices

Owner-authored oidc-cli code is licensed under the [MIT License](../LICENSE),
Copyright (c) 2026 Keisuke Miyako. The explicit
[existing-release grant](license-grant.md) includes the source at
`v0.1.1` commit `1c909c00e6aa4924c4755e325f8ba8bb25927b31` and the already-published
v0.1.1 binaries. It does not change the bytes of any release asset or tag.

## Exact-version inventory

| Component | Version | Terms / retained notices |
| --- | --- | --- |
| Go runtime, standard library and toolchain distribution | go1.26.10 | Go BSD-style `LICENSE`, `PATENTS`, applicable vendored/embedded license files |
| `github.com/coreos/go-oidc/v3` | v3.21.0 | Apache-2.0 `LICENSE` and CoreOS `NOTICE` |
| `github.com/go-jose/go-jose/v4` | v4.1.9 | Apache-2.0 root `LICENSE`; BSD-style `json/LICENSE` for the embedded JSON implementation |
| `golang.org/x/oauth2` | v0.38.0 | BSD-3-Clause `LICENSE` |

`go list -deps ./cmd/oidc-cli` confirms the three non-standard-library modules
above are linked. The module graph also lists
`cloud.google.com/go/compute/metadata v0.3.0`, but its packages are not linked by
this CLI; module-graph membership alone is not binary inclusion evidence.
CGO is disabled for release builds. The Go standard library also includes
vendored `golang.org/x/crypto`, `x/net`, `x/text` and platform-specific code.

[`THIRD_PARTY_NOTICES.txt`](../THIRD_PARTY_NOTICES.txt) provides the complete
collected license texts in a single redistributable file.
[`third_party/manifest.json`](../third_party/manifest.json) records each
component version, original relative path and SHA-256 of its exact license file.
It includes the Go root license and patent grant, standard-library vendor
licenses/patent grants and embedded third-party license files, plus the full
three module distributions' license/notice files.

The inventory is intentionally **conservative and overinclusive**: it collects
recognized license/copyright/notice/patent files from the complete pinned Go
toolchain distribution, including build tools and tests, not just linked
packages. Inclusion is not a claim that compiler/test code or every third-party
library is embedded in an executable. These license files are not relicensed
under MIT. The bundle preserves their text and attribution.

## Redistributing existing binaries

Keep all of the following with a redistribution (for example in a wrapper's
Resources/licenses directory):

* `LICENSE`
* `docs/license-grant.md`, especially for already-published v0.1.1 assets
* `THIRD_PARTY_NOTICES.txt`
* `third_party/manifest.json` and this inventory for provenance/scope

The original v0.1.1 archives contain only the executable. This supplemental
license/notice distribution does not modify or replace those archives, so
existing pinned digests, signatures and notarization remain valid. Fetch these
documents using an immutable **licensing commit SHA**, not the earlier v0.1.1
source tag (which predates the grant). Pin and verify their hashes separately.

To reproduce the checked-in notice bundle using the pinned toolchain and module
versions, without rebuilding or modifying any existing release:

```sh
python3 scripts/license_notices.py --check
# Maintainers updating reviewed notices deliberately:
python3 scripts/license_notices.py
```

Re-review the inventory when Go or module versions change. A different toolchain
version is rejected by the generator; Go is BSD-style licensed with its own
patent grant, not covered by the project's MIT owner grant.
