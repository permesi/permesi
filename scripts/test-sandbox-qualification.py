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
        # Qualification starts with the images; only the record waits for every gate.
        self.assertEqual(set(build["containment"]["needs"]), {"sandbox-images"})
        self.assertEqual(build["containment"]["uses"], "./.github/workflows/containment.yml")
        self.assertNotIn("statuses", build["containment"]["permissions"])
        record = build["containment-record"]
        self.assertEqual(set(record["needs"]), {"ci-ok", "coverage", "containment"})
        self.assertNotIn("always()", record["if"])
        self.assertEqual(record["permissions"], {"contents": "read", "statuses": "write"})
        self.assertNotIn("record", receiver)
        self.assertNotIn("helm_sha", build["sandbox-images"]["outputs"])
        resolve, checkout, source = receiver["images"]["steps"]
        self.assertIn("repos/permesi/permesi-helm/git/ref/heads/sandbox", resolve["run"])
        self.assertEqual(checkout["with"]["ref"], "${{ steps.charts.outputs.sha }}")
        self.assertEqual(source["uses"], "./.github/actions/containment-source")
        profile_checkout, profile = receiver["qualify"]["steps"]
        self.assertEqual(profile_checkout["with"]["ref"], "${{ needs.images.outputs.helm_sha }}")
        self.assertEqual(profile["uses"], "./.github/actions/containment-profile")
        self.assertEqual(set(receiver["qualify"]["strategy"]["matrix"]["profile"]), {"shared", "isolated"})

    def test_record_names_the_qualified_pair_only_while_both_sandboxes_still_hold_it(self):
        """The release guard trusts this status, so it must describe exactly what was qualified."""
        build = yaml.safe_load((ROOT / ".github/workflows/build.yml").read_text())["jobs"]
        outputs = yaml.safe_load((ROOT / ".github/workflows/containment.yml").read_text())[True]["workflow_call"]["outputs"]
        for name in ("app_sha", "helm_sha", "artifact_id"):
            self.assertEqual(outputs[name]["value"], "${{ jobs.images.outputs.%s }}" % name)
        step, = build["containment-record"]["steps"]
        self.assertEqual(step["env"]["HELM_SHA"], "${{ needs.containment.outputs.helm_sha }}")
        script = step["run"]
        self.assertIn('"$APP_SHA" == "$GITHUB_SHA"', script)
        self.assertIn('repos/permesi/permesi/git/ref/heads/sandbox --jq .object.sha)" == "$APP_SHA"', script)
        self.assertIn('repos/permesi/permesi-helm/git/ref/heads/sandbox --jq .object.sha)" == "$HELM_SHA"', script)
        self.assertIn('context="containment/$GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT"', script)
        self.assertIn('description="Helm $HELM_SHA, OCI artifact $ARTIFACT_ID"', script)

    def test_publishing_jobs_still_wait_for_the_tests(self):
        """Builds run alongside the tests; nothing may be published from a commit that fails them."""
        build = yaml.safe_load((ROOT / ".github/workflows/build.yml").read_text())["jobs"]
        for job in ("deploy-frontend", "package"):
            self.assertIn("test", build[job]["needs"], job)
        for job in ("test", "build", "frontend-build", "scenario-build", "oauth-scenarios", "browser-tests", "sandbox-images"):
            self.assertIn(job, build["ci-ok"]["needs"], job)


if __name__ == "__main__":
    unittest.main()
