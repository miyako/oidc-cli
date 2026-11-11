"""Fail-closed Developer ID signing/notarization for standalone macOS CLI assets."""

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import tarfile
import tempfile
import uuid
import zipfile


SECRET_NAMES = (
    "APPLE_DEVELOPER_ID_CERTIFICATE", "APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD",
    "KEYCHAIN_PASSWORD", "NOTARYTOOL_APPLE_ID", "NOTARYTOOL_TEAM_ID", "NOTARYTOOL_PASSWORD",
)
ARCHITECTURES = {
    "darwin_arm64": ("arm64",),
    "darwin_amd64": ("x86_64",),
    "darwin_universal": ("arm64", "x86_64"),
}
IDENTITY = re.compile(
    r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"Developer ID Application: .*\(([A-Z0-9]+)\)"\s*$'
)


class SigningError(ValueError):
    pass


def public_environment(env):
    return {key: value for key, value in env.items() if key not in SECRET_NAMES}


def require_environment(env=None):
    env = os.environ if env is None else env
    if platform.system() != "Darwin" or env.get("GITHUB_ACTIONS") != "true":
        raise SigningError("Apple release signing requires a macOS GitHub Actions runner")
    missing = [name for name in SECRET_NAMES if not env.get(name, "").strip()]
    if missing:
        raise SigningError("missing signing secrets: " + ", ".join(missing))
    if not env.get("RUNNER_TEMP"):
        raise SigningError("RUNNER_TEMP is required")


def run_tool(label, args, *, timeout=120, stdout_only=False):
    try:
        result = subprocess.run(
            [str(arg) for arg in args], check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
            env=public_environment(os.environ),
        )
    except (OSError, subprocess.SubprocessError):
        # Exception strings and tool diagnostics can contain credential-bearing argv.
        raise SigningError(label + ": tool launch failed or timed out") from None
    if result.returncode:
        raise SigningError(label + f": tool failed (exit {result.returncode})")
    return result.stdout if stdout_only else result.stdout + result.stderr


def select_identity(output, team):
    identities = [match.groups() for line in output.splitlines()
                  if (match := IDENTITY.fullmatch(line))]
    if len(identities) != 1:
        raise SigningError("expected exactly one valid Developer ID Application identity")
    fingerprint, actual_team = identities[0]
    if actual_team != team:
        raise SigningError("certificate team does not match the notarization team")
    return fingerprint


def verify_binary(path, target, team, *, notarized=False):
    args = ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures"]
    if notarized:
        args += ["--check-notarization", "--test-requirement", "notarized"]
    run_tool("notarized signature verification" if notarized else "signature verification",
             [*args, path])
    for architecture in ARCHITECTURES[target]:
        display = run_tool("signature inspection", [
            "/usr/bin/codesign", "--display", "--verbose=4", "--arch", architecture, path,
        ])
        if (not re.search(r"^Authority=Developer ID Application:", display, re.MULTILINE)
                or not re.search(r"^TeamIdentifier=" + re.escape(team) + r"$", display, re.MULTILINE)
                or not re.search(r"^Timestamp=.+$", display, re.MULTILINE)
                or re.search(r"^Timestamp=(?:none|not set)$", display, re.MULTILINE | re.IGNORECASE)
                or not re.search(r"^CodeDirectory .*flags=.*\([^)]*\bruntime\b", display, re.MULTILINE)
                or "Signature=adhoc" in display):
            raise SigningError("signature lacks the required Developer ID, team, timestamp or runtime")


def accepted_submission(output):
    try:
        result = json.loads(output)
        identifier = str(uuid.UUID(result["id"]))
    except (ValueError, KeyError, TypeError, AttributeError):
        raise SigningError("notarytool returned an invalid submission response") from None
    if result.get("status") != "Accepted":
        raise SigningError("notarization was not Accepted (submission " + identifier + ")")
    return identifier


def sign_and_notarize(binaries):
    require_environment()
    if not binaries or any(target not in ARCHITECTURES for target in binaries):
        raise SigningError("expected macOS release binaries")
    env = os.environ
    team = env["NOTARYTOOL_TEAM_ID"].strip()
    try:
        certificate = base64.b64decode(
            "".join(env["APPLE_DEVELOPER_ID_CERTIFICATE"].split()), validate=True
        )
    except (ValueError, binascii.Error):
        raise SigningError("signing certificate is not valid base64 PKCS#12") from None
    if not certificate:
        raise SigningError("signing certificate is empty")
    with tempfile.TemporaryDirectory(prefix="oidc-cli-signing-", dir=env["RUNNER_TEMP"]) as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        keychain = scratch / "release.keychain-db"
        p12 = scratch / "certificate.p12"
        previous = shlex.split(run_tool("read keychain search list", [
            "/usr/bin/security", "list-keychains", "-d", "user",
        ]))
        try:
            with p12.open("xb") as output:
                p12.chmod(0o600)
                output.write(certificate)
            password = env["KEYCHAIN_PASSWORD"]
            run_tool("create temporary keychain", [
                "/usr/bin/security", "create-keychain", "-p", password, keychain,
            ])
            run_tool("unlock temporary keychain", [
                "/usr/bin/security", "unlock-keychain", "-p", password, keychain,
            ])
            run_tool("configure temporary keychain", [
                "/usr/bin/security", "set-keychain-settings", "-lut", "3600", keychain,
            ])
            run_tool("import signing certificate", [
                "/usr/bin/security", "import", p12, "-k", keychain,
                "-P", env["APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD"], "-T", "/usr/bin/codesign",
            ])
            p12.unlink()
            run_tool("authorize signing key", [
                "/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
                "-s", "-k", password, keychain,
            ])
            identity = select_identity(run_tool("find imported identity", [
                "/usr/bin/security", "find-identity", "-v", "-p", "codesigning", keychain,
            ]), team)
            for target, binary in sorted(binaries.items()):
                run_tool("sign " + target, [
                    "/usr/bin/codesign", "--force", "--sign", identity, "--timestamp",
                    "--options", "runtime", "--identifier", "io.github.miyako.oidc-cli",
                    "--keychain", keychain, binary,
                ])
                verify_binary(binary, target, team)
            run_tool("store temporary notarization credentials", [
                "/usr/bin/xcrun", "notarytool", "store-credentials", "oidc-cli",
                "--apple-id", env["NOTARYTOOL_APPLE_ID"], "--team-id", team,
                "--password", env["NOTARYTOOL_PASSWORD"], "--keychain", keychain,
            ])
            submission = scratch / "signed-cli.zip"
            with zipfile.ZipFile(submission, "w", zipfile.ZIP_DEFLATED) as archive:
                for target, binary in sorted(binaries.items()):
                    archive.write(binary, target + "/oidc-cli")
            identifier = accepted_submission(run_tool("submit notarization", [
                "/usr/bin/xcrun", "notarytool", "submit", submission,
                "--keychain-profile", "oidc-cli", "--keychain", keychain,
                "--wait", "--timeout", "20m", "--output-format", "json",
            ], timeout=1260, stdout_only=True))
            for target, binary in sorted(binaries.items()):
                verify_binary(binary, target, team, notarized=True)
            return {
                "schema": 1, "status": "Accepted", "submission_id": identifier,
                "binaries": {target: hashlib.sha256(path.read_bytes()).hexdigest()
                             for target, path in sorted(binaries.items())},
            }
        finally:
            try:
                run_tool("restore keychain search list", [
                    "/usr/bin/security", "list-keychains", "-d", "user", "-s", *previous,
                ])
            finally:
                if keychain.exists():
                    run_tool("delete temporary keychain", [
                        "/usr/bin/security", "delete-keychain", keychain,
                    ])


def verify_archive(archive_path, target, receipt):
    # Verify the exact extracted payload, not just its pre-packaging source binary.
    with tempfile.TemporaryDirectory(prefix="oidc-cli-verify-") as temporary:
        binary = Path(temporary) / "oidc-cli"
        with tarfile.open(archive_path, "r:gz") as archive:
            entries = archive.getmembers()
            if len(entries) != 1 or entries[0].name != "oidc-cli" or not entries[0].isfile():
                raise SigningError("unexpected signed archive layout")
            data = archive.extractfile(entries[0]).read()
            if entries[0].mode != 0o755:
                raise SigningError("signed archive executable permissions changed")
        if hashlib.sha256(data).hexdigest() != receipt["binaries"][target]:
            raise SigningError("signed executable changed during packaging")
        binary.write_bytes(data)
        binary.chmod(0o755)
        verify_binary(binary, target, os.environ["NOTARYTOOL_TEAM_ID"].strip(), notarized=True)
