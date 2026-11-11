import unittest

from bump_version import next_version


class BumpTests(unittest.TestCase):
    def test_bump_rules(self):
        cases = [
            ("0.1.0-rc.1", "prerelease", "0.1.0-rc.2"),
            ("0.1.0-rc.9", "prerelease", "0.1.0-rc.10"),
            ("1.2.3-beta", "prerelease", "1.2.3-beta.1"),
            ("1.2.3", "prerelease", "1.2.4-rc.1"),
            ("0.1.0-rc.1", "patch", "0.1.0"),
            ("1.2.3", "patch", "1.2.4"),
            ("0.1.0-rc.1", "minor", "0.2.0"),
            ("1.2.3", "minor", "1.3.0"),
            ("0.1.0-rc.1", "major", "1.0.0"),
            ("1.2.3+build.1", "patch", "1.2.4"),
        ]
        for current, bump, expected in cases:
            with self.subTest(current=current, bump=bump):
                self.assertEqual(next_version(current, bump), expected)

    def test_invalid_input(self):
        for current, bump in [("v1.2.3", "patch"), ("01.2.3", "patch"),
                              ("1.2.3", "custom"), ("1.2.3-01", "patch")]:
            with self.subTest(current=current, bump=bump):
                with self.assertRaises(ValueError):
                    next_version(current, bump)


if __name__ == "__main__":
    unittest.main()
