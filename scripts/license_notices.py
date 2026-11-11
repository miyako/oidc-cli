#!/usr/bin/env python3
"""Collect exact-version license texts without modifying existing release assets."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MODULES = {
    "github.com/coreos/go-oidc/v3": "v3.21.0",
    "github.com/go-jose/go-jose/v4": "v4.1.9",
    "golang.org/x/oauth2": "v0.38.0",
}
GO_VERSION = "go1.26.10"
LICENSE_NAMES = {
    "LICENSE", "LICENSE.txt", "LICENSE.md", "LICENSE-MIT", "LICENSE-APACHE",
    "COPYING", "COPYING.txt", "COPYRIGHT", "COPYRIGHT.txt",
    "NOTICE", "NOTICE.txt", "PATENTS", "AUTHORS", "CONTRIBUTORS",
}


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, timeout=120).strip()


def collect():
    if command("go", "env", "GOVERSION") != GO_VERSION:
        raise ValueError("notice generation requires " + GO_VERSION)
    roots = [("Go " + GO_VERSION, Path(command("go", "env", "GOROOT")),
              "https://github.com/golang/go/tree/" + GO_VERSION)]
    for module, version in MODULES.items():
        info = json.loads(command("go", "mod", "download", "-json", module + "@" + version))
        if info.get("Error") or not info.get("Dir") or info.get("Version") != version:
            raise ValueError("module unavailable: " + module + "@" + version)
        roots.append((module + "@" + version, Path(info["Dir"]), module + "@" + version))
    records = []
    texts = []
    for component, root, source in roots:
        files = sorted(path for path in root.rglob("*")
                       if path.is_file() and path.name in LICENSE_NAMES)
        for path in files:
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            text = data.decode("utf-8")
            records.append({
                "component": component, "path": relative, "source": source,
                "sha256": hashlib.sha256(data).hexdigest(),
            })
            texts.append(f"\n===== {component} :: {relative} =====\n" + text
                         + ("" if text.endswith("\n") else "\n"))
    if not records:
        raise ValueError("empty notice inventory")
    manifest = {
        "schema": 1,
        "release_scope": "v0.1.1",
        "source_commit": "1c909c00e6aa4924c4755e325f8ba8bb25927b31",
        "scope": "Conservative complete license-file inventory of the Go toolchain "
                 "and three linked module distributions, not a claim that every file is linked.",
        "files": records,
    }
    intro = (
        "THIRD-PARTY NOTICES FOR OIDC-CLI v0.1.1\n\n"
        "Owner-authored oidc-cli code is MIT; see LICENSE and docs/license-grant.md.\n"
        "Third-party terms below are preserved, not replaced by MIT.\n"
        "Exact upstream file contents follow each labeled boundary; terminal newlines\n"
        "are supplied when absent. third_party/manifest.json records original hashes.\n"
        "This conservative inventory includes unused tooling/tests/licenses and does\n"
        "not claim all listed source is present in any executable. See docs/licensing.md.\n"
    )
    return {
        ROOT / "THIRD_PARTY_NOTICES.txt": intro + "".join(texts),
        ROOT / "third_party/manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for path, content in collect().items():
        if args.check:
            if not path.is_file() or path.read_bytes() != content.encode("utf-8"):
                parser.error("notice bundle differs: " + str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode("utf-8"))


if __name__ == "__main__":
    main()
