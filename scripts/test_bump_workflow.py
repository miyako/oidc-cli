import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == "nt", "Exercises the Ubuntu workflow's bash/git transaction")
class BumpWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oidc-cli-bump-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote.git"
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.git_env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "--bare", str(self.remote))
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "scripts").mkdir()
        for name in ("bump_version.py", "package_release.py"):
            shutil.copyfile(ROOT / "scripts" / name, self.repo / "scripts" / name)
        version_file = self.repo / "cmd/oidc-cli/version.txt"
        version_file.parent.mkdir(parents=True)
        version_file.write_text("0.1.0-rc.1\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "Fixture")
        self.initial_sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "HEAD:refs/heads/main")
        workflow = (ROOT / ".github/workflows/bump.yml").read_text(encoding="utf-8")
        self.script = textwrap.dedent(
            workflow.split("id: commit\n        run: |\n", 1)[1].split("\n  release:", 1)[0]
        )
        self.env = {
            **self.git_env,
            "DEFAULT_BRANCH": "main",
            "DISPATCH_SHA": self.initial_sha,
            "BUMP": "prerelease",
            "GITHUB_OUTPUT": str(self.root / "outputs"),
        }

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              env=self.git_env, text=True, capture_output=True, timeout=15)

    def run_bump(self):
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", self.script],
                              cwd=self.repo, env=self.env, text=True,
                              capture_output=True, timeout=30)

    def remote_sha(self, ref):
        return self.git("--git-dir", str(self.remote), "rev-parse", ref).stdout.strip()

    def test_bump_commits_tags_and_exports_exact_sha(self):
        result = self.run_bump()
        self.assertEqual(result.returncode, 0, result.stderr)
        bumped_sha = self.remote_sha("refs/heads/main")
        self.assertNotEqual(bumped_sha, self.initial_sha)
        self.assertEqual(self.remote_sha("refs/tags/v0.1.0-rc.2^{}"), bumped_sha)
        self.assertEqual(self.git("show", "HEAD:cmd/oidc-cli/version.txt").stdout,
                         "0.1.0-rc.2\n")
        self.assertEqual((self.root / "outputs").read_text(encoding="utf-8"),
                         f"tag=v0.1.0-rc.2\nsha={bumped_sha}\n")

    def test_existing_tag_is_not_overwritten(self):
        self.git("tag", "v0.1.0-rc.2")
        self.git("push", "origin", "refs/tags/v0.1.0-rc.2")
        result = self.run_bump()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stdout)
        self.assertEqual(self.remote_sha("refs/heads/main"), self.initial_sha)
        self.assertEqual(self.remote_sha("refs/tags/v0.1.0-rc.2"), self.initial_sha)

    def test_stale_dispatch_is_rejected(self):
        self.env["DISPATCH_SHA"] = "0" * 40
        result = self.run_bump()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("advanced", result.stdout)
        self.assertEqual(self.remote_sha("refs/heads/main"), self.initial_sha)

    def test_branch_rejection_also_prevents_remote_tag(self):
        hook = self.remote / "hooks/pre-receive"
        hook.write_text(
            '#!/bin/sh\nwhile read -r old new ref; do\n'
            '  if [ "$ref" = "refs/heads/main" ]; then exit 1; fi\n'
            'done\n', encoding="utf-8",
        )
        hook.chmod(0o755)
        result = self.run_bump()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.remote_sha("refs/heads/main"), self.initial_sha)
        self.assertEqual(self.git("--git-dir", str(self.remote), "tag", "--list").stdout, "")


if __name__ == "__main__":
    unittest.main()
