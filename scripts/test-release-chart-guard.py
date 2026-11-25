#!/usr/bin/env python3
"""Exercise the release chart guard on synthetic API data, without GitHub access."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("guard", Path(__file__).with_name("release-chart-guard.py"))
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)

APP = "a" * 40
OLD, NEW = "1" * 40, "2" * 40


def status(chart=NEW, run=7, state="success", creator="github-actions[bot]", description=None, context=None):
    """One commit status as the API returns it; the caller lists them newest first."""
    return {
        "context": context or f"containment/{run}/1",
        "state": state,
        "description": description if description is not None else f"Helm {chart}, OCI artifact 42",
        "creator": {"login": creator},
    }


def comparing(state, ahead=0):
    """A comparison of <chart>...main that records which revision was asked about."""
    asked = []

    def compare(base):
        asked.append(base)
        return {"status": state, "ahead_by": ahead}

    return compare, asked


class QualifiedChart(unittest.TestCase):
    def test_newest_trusted_status_names_the_chart(self):
        self.assertEqual(GUARD.qualified_chart([status(NEW, run=9), status(OLD, run=8)]), NEW)

    def test_untrusted_or_unrelated_statuses_never_qualify(self):
        for forged in (
            status(creator="someone"),
            status(creator=None) | {"creator": None},
            status(state="failure"),
            status(state="pending"),
            status(description="Helm main, OCI artifact 42"),
            status(description=f"Helm {NEW}, OCI artifact 42; rm -rf"),
            status(description=f"App {NEW}, OCI artifact 42"),
            status(description=""),
            status(context="containment/7"),
            status(context="containment/7/1/extra"),
            status(context="CI OK"),
        ):
            self.assertIsNone(GUARD.qualified_chart([forged]), forged)
        self.assertIsNone(GUARD.qualified_chart([]))

    def test_newer_entry_of_one_context_shadows_its_older_success(self):
        """A run whose status was later overwritten as failed no longer qualifies."""
        statuses = [status(NEW, run=9, state="failure"), status(NEW, run=9), status(OLD, run=8)]
        self.assertEqual(GUARD.qualified_chart(statuses), OLD)

    def test_forged_newer_status_does_not_hide_the_recorded_one(self):
        statuses = [status(OLD, run=10, creator="someone"), status(NEW, run=9)]
        self.assertEqual(GUARD.qualified_chart(statuses), NEW)


class Check(unittest.TestCase):
    def test_release_proceeds_only_when_chart_main_contains_the_revision(self):
        for state, ahead in (("identical", 0), ("ahead", 3)):
            compare, asked = comparing(state, ahead)
            self.assertEqual(GUARD.check(APP, [status(NEW)], compare), (NEW, ahead))
            self.assertEqual(asked, [NEW])

    def test_release_is_refused_when_chart_main_lacks_the_revision(self):
        for state in ("behind", "diverged", None, "unexpected"):
            compare, _ = comparing(state)
            with self.assertRaises(GUARD.Refused) as refused:
                GUARD.check(APP, [status(NEW)], compare)
            self.assertIn(NEW, str(refused.exception))
            self.assertIn("sandbox into main", str(refused.exception))

    def test_release_is_refused_without_a_qualification_and_asks_nothing(self):
        compare, asked = comparing("identical")
        with self.assertRaises(GUARD.Refused) as refused:
            GUARD.check(APP, [status(creator="someone")], compare)
        self.assertIn("no containment qualification", str(refused.exception))
        self.assertEqual(asked, [])


class Wiring(unittest.TestCase):
    def test_the_workflow_guard_runs_before_anything_is_built(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        guard_job = workflow.split("\n  guard:\n", 1)[1].split("\n  # ", 1)[0]
        self.assertIn('python3 scripts/release-chart-guard.py "${GITHUB_SHA}"', guard_job)
        self.assertIn("statuses: read", guard_job)

    def test_the_recipe_checks_before_dispatching_the_release(self):
        recipe = (ROOT / ".justfiles/core.just").read_text().split("\nrelease:\n", 1)[1]
        guard = recipe.index("scripts/release-chart-guard.py")
        self.assertLess(guard, recipe.index("gh workflow run release.yml"))

    def test_the_recorded_status_format_is_the_one_the_guard_reads(self):
        record = (ROOT / ".github/workflows/build.yml").read_text().split("\n  containment-record:\n", 1)[1]
        self.assertIn('context="containment/$GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT"', record)
        self.assertIn('description="Helm $HELM_SHA, OCI artifact $ARTIFACT_ID"', record)


if __name__ == "__main__":
    unittest.main()
