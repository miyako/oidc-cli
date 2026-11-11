#!/usr/bin/env python3
"""Build unsigned, CGO-free release archives and their SHA-256 manifest."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("darwin_arm64", "darwin_amd64", "darwin_universal", "windows_amd64")


def valid_version(version):
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version,
    )
    if not match:
        return False
    return all(not (part.isdigit() and len(part) > 1 and part.startswith("0"))
               for part in (match.group(4) or "").split("."))


def archive_bytes(binary, name, windows=False):
    if windows:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o755 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, binary)
        return output.getvalue()
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            info = tarfile.TarInfo(name)
            info.size = len(binary)
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info, io.BytesIO(binary))
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Semver without a v prefix")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=list(TARGETS))
    args = parser.parse_args()
    if not valid_version(args.version):
        parser.error("--version must be a semantic version without a v prefix")
    if "darwin_universal" in args.targets and not shutil.which("lipo"):
        parser.error("darwin_universal requires lipo on macOS")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = output / "build"
    build.mkdir(exist_ok=True)
    targets = set(args.targets)
    if "darwin_universal" in targets:
        targets.update(("darwin_arm64", "darwin_amd64"))
    binaries = {}
    for target in sorted(targets - {"darwin_universal"}):
        goos, goarch = target.split("_")
        binary = build / (target + (".exe" if goos == "windows" else ""))
        subprocess.run(
            ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags",
             f"-s -w -X main.version={args.version}", "-o", str(binary), "./cmd/oidc-cli"],
            cwd=ROOT, env={**os.environ, "CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch},
            check=True,
        )
        binaries[target] = binary
    if "darwin_universal" in targets:
        binary = build / "darwin_universal"
        subprocess.run(["lipo", "-create", str(binaries["darwin_arm64"]),
                        str(binaries["darwin_amd64"]), "-output", str(binary)], check=True)
        subprocess.run(["lipo", str(binary), "-verify_arch", "arm64", "x86_64"], check=True)
        binaries["darwin_universal"] = binary
    checksums = []
    for target in sorted(set(args.targets)):
        windows = target.startswith("windows_")
        suffix = ".zip" if windows else ".tar.gz"
        name = f"oidc-cli_{args.version}_{target}{suffix}"
        data = archive_bytes(binaries[target].read_bytes(),
                             "oidc-cli.exe" if windows else "oidc-cli", windows)
        (output / name).write_bytes(data)
        checksums.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
    (output / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")


if __name__ == "__main__":
    main()
