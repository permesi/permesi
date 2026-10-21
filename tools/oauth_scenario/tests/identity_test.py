"""Reject stale/mixed CI binaries before any service or local dependency starts."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "target/debug/permesi-oauth-scenario"


class IdentityTests(unittest.TestCase):
    def test_mismatched_commit_blocks_all_selected_cases_without_startup(self):
        """The real runner writes failed reports without launching substituted services."""
        with tempfile.TemporaryDirectory(prefix="scenario-identity-") as temporary:
            directory = Path(temporary) / "quoted' fixture path"
            directory.mkdir()
            (directory / "web").mkdir()
            (directory / "web/index.html").write_text("fixture")
            (directory / "web/fixture.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
            marker = directory / "service-started"
            for service in ("permesi", "genesis"):
                binary = directory / service
                binary.write_text(
                    '#!/bin/sh\nif [ "$1" = "--version" ]; then\n'
                    f'  printf "%s\\n" "{service} 0.0.0 - unknown"\n'
                    f'else\n  touch {shlex.quote(str(marker))}\n  exit 97\nfi\n'
                )
                binary.chmod(0o700)
            # Both the explicit flag and the CI environment policy must reject before startup.
            for policy in ("flag", "environment"):
                reports = directory / policy
                environment = os.environ.copy()
                environment.pop("PERMESI_SCENARIO_EXPECTED_COMMIT", None)
                arguments = []
                if policy == "flag":
                    arguments = ["--expected-commit", "a" * 40]
                else:
                    environment["PERMESI_SCENARIO_EXPECTED_COMMIT"] = "a" * 40
                result = subprocess.run(
                    [str(RUNNER), *arguments, "--case", "authorization.consent", "--repeat", "2",
                     "--report-dir", str(reports), "--permesi-bin", str(directory / "permesi"),
                     "--genesis-bin", str(directory / "genesis"), "--web-dist", str(directory / "web")],
                    cwd=ROOT, env=environment, capture_output=True, timeout=30,
                )
                self.assertEqual(result.returncode, 1)
                paths = list(reports.glob("*/report.json"))
                self.assertEqual(len(paths), 1)
                report = json.loads(paths[0].read_text())
                self.assertEqual(report["infrastructure_failure"]["message"],
                                 "Scenario artifacts do not match the expected commit and workspace version.")
                self.assertEqual(len(report["cases"]), 2)
                self.assertTrue(all(case["status"] == "blocked" for case in report["cases"]))
                self.assertFalse(list(reports.glob("*/ownership-*.json")))
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
