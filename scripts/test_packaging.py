import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

import package_release
from package_release import archive_bytes, valid_version


class ArchiveTests(unittest.TestCase):
    def test_signed_manifest_is_written_only_after_archive_verification(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "SHA256SUMS").write_text("stale manifest", encoding="utf-8")
                receipt = {"status": "Accepted", "binaries": {}}

                def build(args, **kwargs):
                    Path(args[args.index("-o") + 1]).write_bytes(b"signed-fixture")

                def verify(*args):
                    self.assertFalse((root / "SHA256SUMS").exists())
                    if not accepted:
                        raise package_release.sign_release.SigningError("verification failed")

                with mock.patch("sys.argv", [
                    "package_release.py", "--version", "1.2.3", "--output", str(root),
                    "--targets", "darwin_arm64", "--apple-signing",
                ]), mock.patch.object(package_release.subprocess, "run", side_effect=build), \
                        mock.patch.object(package_release.sign_release, "require_environment"), \
                        mock.patch.object(package_release.sign_release, "sign_and_notarize",
                                          return_value=receipt), \
                        mock.patch.object(package_release.sign_release, "verify_archive",
                                          side_effect=verify):
                    if accepted:
                        package_release.main()
                        data = (root / "APPLE_NOTARIZATION.json").read_bytes()
                        self.assertEqual(json.loads(data), receipt)
                        self.assertIn(
                            hashlib.sha256(data).hexdigest() + "  APPLE_NOTARIZATION.json",
                            (root / "SHA256SUMS").read_text(encoding="utf-8"),
                        )
                    else:
                        with self.assertRaises(package_release.sign_release.SigningError):
                            package_release.main()
                        self.assertFalse((root / "SHA256SUMS").exists())
                        self.assertFalse((root / "APPLE_NOTARIZATION.json").exists())

    def test_release_versions(self):
        for value in ("0.0.0", "1.2.3", "1.2.3-rc.1", "1.2.3+build.1"):
            with self.subTest(value=value):
                self.assertTrue(valid_version(value))
        for value in ("v1.2.3", "1.2", "01.2.3", "1.2.3-..", "1.2.3-01",
                      "../escape", "1.2.3\n"):
            with self.subTest(value=value):
                self.assertFalse(valid_version(value))

    def test_tar_is_repeatable_and_executable(self):
        data = archive_bytes(b"fixture", "oidc-cli")
        self.assertEqual(data, archive_bytes(b"fixture", "oidc-cli"))
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            self.assertEqual(archive.getnames(), ["oidc-cli"])
            self.assertEqual(archive.getmember("oidc-cli").mode, 0o755)
            self.assertEqual(archive.extractfile("oidc-cli").read(), b"fixture")

    def test_zip_is_repeatable(self):
        data = archive_bytes(b"fixture", "oidc-cli.exe", True)
        self.assertEqual(hashlib.sha256(data).digest(),
                         hashlib.sha256(archive_bytes(b"fixture", "oidc-cli.exe", True)).digest())
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.namelist(), ["oidc-cli.exe"])
            self.assertEqual(archive.read("oidc-cli.exe"), b"fixture")


if __name__ == "__main__":
    unittest.main()
