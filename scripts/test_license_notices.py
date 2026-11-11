import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import license_notices


class NoticeTests(unittest.TestCase):
    def test_exact_text_hashes_and_nested_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "LICENSE").write_bytes(b"Example license\n")
            (root / "json").mkdir()
            (root / "json" / "NOTICE").write_bytes(b"Embedded attribution")

            def command(*args):
                if args == ("go", "env", "GOVERSION"):
                    return license_notices.GO_VERSION
                if args == ("go", "env", "GOROOT"):
                    return str(root)
                version = args[-1].rsplit("@", 1)[1]
                return json.dumps({"Dir": str(root), "Version": version})

            with mock.patch.object(license_notices, "command", side_effect=command):
                outputs = license_notices.collect()
            manifest = json.loads(outputs[license_notices.ROOT / "third_party/manifest.json"])
            self.assertEqual(len(manifest["files"]), 8)
            for record in manifest["files"]:
                data = (root / record["path"]).read_bytes()
                self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
            text = outputs[license_notices.ROOT / "THIRD_PARTY_NOTICES.txt"]
            self.assertIn("Example license\n", text)
            self.assertIn("json/NOTICE =====\nEmbedded attribution\n", text)

    def test_wrong_go_version_is_rejected(self):
        with mock.patch.object(license_notices, "command", return_value="go1.25.0"):
            with self.assertRaisesRegex(ValueError, "requires go1.26.10"):
                license_notices.collect()

    def test_module_download_error_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            def command(*args):
                if args == ("go", "env", "GOVERSION"):
                    return license_notices.GO_VERSION
                if args == ("go", "env", "GOROOT"):
                    return temporary
                return json.dumps({"Error": "unavailable"})

            with mock.patch.object(license_notices, "command", side_effect=command):
                with self.assertRaisesRegex(ValueError, "module unavailable"):
                    license_notices.collect()


if __name__ == "__main__":
    unittest.main()
