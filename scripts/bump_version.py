#!/usr/bin/env python3
"""Advance the embedded source version; no commit, tag or publication locally."""

import argparse
from pathlib import Path

from package_release import valid_version


VERSION_FILE = Path(__file__).resolve().parents[1] / "cmd/oidc-cli/version.txt"
BUMPS = ("prerelease", "patch", "minor", "major")


def next_version(current, bump):
    if not valid_version(current):
        raise ValueError("source version is not valid SemVer")
    if bump not in BUMPS:
        raise ValueError("unsupported bump")
    core, _, prerelease = current.split("+", 1)[0].partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch if prerelease else patch + 1}"
    if prerelease:
        parts = prerelease.split(".")
        if parts[-1].isdigit():
            parts[-1] = str(int(parts[-1]) + 1)
        else:
            parts.append("1")
        return core + "-" + ".".join(parts)
    return f"{major}.{minor}.{patch + 1}-rc.1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bump", choices=BUMPS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        version = next_version(VERSION_FILE.read_text(encoding="utf-8").strip(), args.bump)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if not args.dry_run:
        VERSION_FILE.write_text(version + "\n", encoding="utf-8")
    print(version)


if __name__ == "__main__":
    main()
