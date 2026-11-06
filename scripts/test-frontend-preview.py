#!/usr/bin/env python3
"""Exercise the preview publisher's real branch resolver without deploying files."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


def run_resolver(ref_name, input_branch=""):
    """Render the workflow input as an environment value and execute its actual shell."""
    source = (ROOT / ".github/workflows/frontend.yml").read_text()
    step = source.split("      - name: 'Deploy: Resolve Cloudflare Branch'\n", 1)[1]
    block = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
    block = block.replace("${{ inputs.deploy_branch }}", "${INPUT_DEPLOY_BRANCH}")
    with tempfile.TemporaryDirectory(prefix="permesi-frontend-preview-") as directory:
        output = Path(directory) / "environment"
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", block],
            capture_output=True, text=True, check=False,
            env={**os.environ, "GITHUB_REF_NAME": ref_name,
                 "INPUT_DEPLOY_BRANCH": input_branch, "GITHUB_ENV": str(output)},
        )
        return result, output.read_text() if output.exists() else ""


class FrontendPreviewTests(unittest.TestCase):
    def test_preview_rejects_production_and_candidate_branches(self):
        for branch in ("main", "release"):
            for ref_name, input_branch in ((branch, ""), ("sandbox", branch)):
                with self.subTest(ref=ref_name, input=input_branch):
                    result, output = run_resolver(ref_name, input_branch)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("release workflow", result.stdout + result.stderr)
                    self.assertEqual(output, "")

    def test_preview_preserves_development_branches_and_explicit_overrides(self):
        cases = [
            ("develop", "", "develop"),
            ("sandbox", "", "sandbox"),
            ("feature/console", "", "feature-console"),
            ("sandbox", "develop", "develop"),
            ("sandbox", "preview/console", "preview-console"),
        ]
        for ref_name, input_branch, expected in cases:
            with self.subTest(ref=ref_name, input=input_branch):
                result, output = run_resolver(ref_name, input_branch)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(output, f"DEPLOY_BRANCH={expected}\n")


if __name__ == "__main__":
    unittest.main()
