#!/usr/bin/env python3
"""Check the application-to-chart handoff stays behind all successful producer gates."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class SandboxHandoff(unittest.TestCase):
    def test_chart_resolution_follows_successful_application_ci(self):
        """A chart push during app CI must still qualify the final pair without operator intervention."""
        build = yaml.safe_load((ROOT / ".github/workflows/build.yml").read_text())["jobs"]
        receiver = yaml.safe_load((ROOT / ".github/workflows/containment.yml").read_text())["jobs"]
        self.assertEqual(set(build["containment"]["needs"]), {"ci-ok", "coverage", "sandbox-images"})
        self.assertEqual(build["containment"]["uses"], "./.github/workflows/containment.yml")
        self.assertNotIn("helm_sha", build["sandbox-images"]["outputs"])
        resolve, checkout, source = receiver["images"]["steps"]
        self.assertIn("repos/permesi/permesi-helm/git/ref/heads/sandbox", resolve["run"])
        self.assertEqual(checkout["with"]["ref"], "${{ steps.charts.outputs.sha }}")
        self.assertEqual(source["uses"], "./.github/actions/containment-source")
        profile_checkout, profile = receiver["qualify"]["steps"]
        self.assertEqual(profile_checkout["with"]["ref"], "${{ needs.images.outputs.helm_sha }}")
        self.assertEqual(profile["uses"], "./.github/actions/containment-profile")
        self.assertEqual(set(receiver["qualify"]["strategy"]["matrix"]["profile"]), {"shared", "isolated"})


if __name__ == "__main__":
    unittest.main()
