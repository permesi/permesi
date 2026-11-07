"""Verify the documented Better Auth setup recipe executes against the fixture package."""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tools" / "better_auth_interop"


class RecipeTests(unittest.TestCase):
    def test_better_auth_setup_recipe_targets_the_fixture_package(self):
        """The recipe must run in one shell against the fixture directory, never the root."""
        for tool in ("just", "npm"):
            self.assertTrue(shutil.which(tool), f"{tool} must run the documented recipe")
        result = subprocess.run(
            ["just", "oauth-scenario-better-auth-setup"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=600,
        )
        self.assertEqual(result.returncode, 0, "documented setup recipe must succeed")
        self.assertTrue(
            (FIXTURE / "node_modules" / "better-auth" / "package.json").is_file(),
            "recipe must install the pinned fixture dependencies",
        )
        self.assertFalse(
            (ROOT / "node_modules").exists(),
            "recipe must not install at the repository root",
        )


if __name__ == "__main__":
    unittest.main()
