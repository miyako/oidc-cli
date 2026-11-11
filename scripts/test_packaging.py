import hashlib
import io
import tarfile
import unittest
import zipfile

from package_release import archive_bytes, valid_version


class ArchiveTests(unittest.TestCase):
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
