import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

import sign_release as signing


TEAM = "TESTTEAM01"
FINGERPRINT = "A" * 40
IDENTITY = f'  1) {FINGERPRINT} "Developer ID Application: Fixture ({TEAM})"'
SUBMISSION = "11111111-2222-4333-8444-555555555555"
DISPLAY = (
    "Authority=Developer ID Application: Fixture\n"
    f"TeamIdentifier={TEAM}\nTimestamp=Nov 11, 2026\n"
    "CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1\n"
)


class SigningTests(unittest.TestCase):
    def test_final_archive_preserves_signed_bytes_and_is_verified(self):
        from package_release import archive_bytes

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.tar.gz"
            payload = b"signed-fixture"
            path.write_bytes(archive_bytes(payload, "oidc-cli"))
            receipt = {"binaries": {"darwin_arm64": hashlib.sha256(payload).hexdigest()}}
            with mock.patch.dict(os.environ, {"NOTARYTOOL_TEAM_ID": TEAM}), \
                    mock.patch.object(signing, "verify_binary") as verify:
                signing.verify_archive(path, "darwin_arm64", receipt)
                self.assertEqual(verify.call_args.args[1:], ("darwin_arm64", TEAM))
                self.assertTrue(verify.call_args.kwargs["notarized"])
                receipt["binaries"]["darwin_arm64"] = "0" * 64
                with self.assertRaises(signing.SigningError):
                    signing.verify_archive(path, "darwin_arm64", receipt)
                path.write_bytes(archive_bytes(payload, "../oidc-cli"))
                with self.assertRaises(signing.SigningError):
                    signing.verify_archive(path, "darwin_arm64", receipt)

    def test_identity_is_unique_developer_id_and_team_bound(self):
        self.assertEqual(signing.select_identity(IDENTITY, TEAM), FINGERPRINT)
        for value, team in (("", TEAM), (IDENTITY + "\n" + IDENTITY, TEAM),
                            (IDENTITY, "WRONGTEAM"), ("Signature=adhoc", TEAM),
                            (IDENTITY.replace("Developer ID Application", "Apple Development"), TEAM)):
            with self.subTest(value=value), self.assertRaises(signing.SigningError):
                signing.select_identity(value, team)

    def test_notary_acceptance_and_submission_id_are_required(self):
        self.assertEqual(
            signing.accepted_submission(json.dumps({"id": SUBMISSION, "status": "Accepted"})),
            SUBMISSION,
        )
        for response in ("private-notary-response", "[]", "{}",
                         json.dumps({"id": "invalid", "status": "Accepted"}),
                         json.dumps({"id": SUBMISSION, "status": "Invalid", "message": "secret"})):
            with self.subTest(response=response), self.assertRaises(signing.SigningError) as raised:
                signing.accepted_submission(response)
            self.assertNotIn("secret", str(raised.exception))
            self.assertNotIn("private-notary-response", str(raised.exception))

    def test_tool_failures_never_echo_credentials(self):
        secret = "sensitive-signing-value"
        failures = [
            subprocess.CompletedProcess(["tool", secret], 1, secret, secret),
            subprocess.TimeoutExpired(["tool", secret], 1, output=secret, stderr=secret),
            OSError(secret),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(signing.subprocess, "run") as run:
                    if isinstance(failure, BaseException):
                        run.side_effect = failure
                    else:
                        run.return_value = failure
                    with self.assertRaises(signing.SigningError) as raised:
                        signing.run_tool("signing stage", ["tool", secret])
                self.assertNotIn(secret, str(raised.exception))

    def test_secret_values_are_not_in_child_environment(self):
        env = {name: "private" for name in signing.SECRET_NAMES}
        env["PATH"] = "/usr/bin"
        self.assertEqual(signing.public_environment(env), {"PATH": "/usr/bin"})

    def test_missing_credentials_fail_closed(self):
        with mock.patch.object(signing.platform, "system", return_value="Darwin"):
            with self.assertRaises(signing.SigningError) as raised:
                signing.require_environment({"GITHUB_ACTIONS": "true", "RUNNER_TEMP": "/tmp"})
            for name in signing.SECRET_NAMES:
                self.assertIn(name, str(raised.exception))
        with self.assertRaises(signing.SigningError):
            signing.require_environment({})

    def test_all_universal_slices_require_runtime_timestamp_and_team(self):
        with mock.patch.object(signing, "run_tool", side_effect=["", DISPLAY, DISPLAY]) as run:
            signing.verify_binary(Path("fixture"), "darwin_universal", TEAM, notarized=True)
            self.assertIn("--check-notarization", run.call_args_list[0].args[1])
            self.assertIn("notarized", run.call_args_list[0].args[1])
            inspected = [call.args[1] for call in run.call_args_list[1:]]
            self.assertTrue(any("arm64" in args for args in inspected))
            self.assertTrue(any("x86_64" in args for args in inspected))
        for invalid in (
            DISPLAY.replace("Timestamp=", "Missing="),
            DISPLAY.replace(TEAM, "WRONGTEAM"),
            DISPLAY.replace("(runtime)", "(none)"),
            DISPLAY + "Signature=adhoc\n",
        ):
            with self.subTest(display=invalid):
                with mock.patch.object(signing, "run_tool", side_effect=["", invalid]):
                    with self.assertRaises(signing.SigningError):
                        signing.verify_binary(Path("fixture"), "darwin_arm64", TEAM)

    def test_full_flow_signs_before_submit_and_always_cleans_keychain(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binaries = {}
                for target in signing.ARCHITECTURES:
                    binaries[target] = root / target
                    binaries[target].write_bytes(b"fixture-mach-o")
                env = {name: "private-fixture" for name in signing.SECRET_NAMES}
                env.update({
                    "APPLE_DEVELOPER_ID_CERTIFICATE": base64.b64encode(b"fixture-p12").decode(),
                    "NOTARYTOOL_TEAM_ID": TEAM,
                    "GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(root),
                })
                labels = []

                def tool(label, args, **kwargs):
                    labels.append(label)
                    if label == "read keychain search list":
                        return '"/original.keychain-db"'
                    if label == "create temporary keychain":
                        Path(args[-1]).touch()
                    if label == "import signing certificate":
                        p12 = Path(args[2])
                        self.assertEqual(p12.read_bytes(), b"fixture-p12")
                        self.assertEqual(p12.stat().st_mode & 0o777, 0o600)
                    if label == "find imported identity":
                        return IDENTITY
                    if label == "signature inspection":
                        return DISPLAY
                    if label == "submit notarization":
                        with zipfile.ZipFile(args[3]) as archive:
                            self.assertEqual(
                                sorted(archive.namelist()),
                                sorted(target + "/oidc-cli" for target in binaries),
                            )
                        return json.dumps({"id": SUBMISSION,
                                           "status": "Accepted" if accepted else "Invalid"})
                    if label == "delete temporary keychain":
                        Path(args[-1]).unlink()
                    return ""

                with mock.patch.dict(os.environ, env, clear=True), \
                        mock.patch.object(signing.platform, "system", return_value="Darwin"), \
                        mock.patch.object(signing, "run_tool", side_effect=tool):
                    if accepted:
                        receipt = signing.sign_and_notarize(binaries)
                        self.assertEqual(receipt["status"], "Accepted")
                        self.assertEqual(set(receipt["binaries"]), set(binaries))
                    else:
                        with self.assertRaises(signing.SigningError):
                            signing.sign_and_notarize(binaries)
                submit = labels.index("submit notarization")
                for target in binaries:
                    self.assertLess(labels.index("sign " + target), submit)
                self.assertEqual(labels[-2:], ["restore keychain search list", "delete temporary keychain"])
                self.assertEqual(list(root.glob("oidc-cli-signing-*")), [])


if __name__ == "__main__":
    unittest.main()
