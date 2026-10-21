#!/usr/bin/env python3
"""Exercise timing boundaries using synthetic API metadata and no GitHub access."""

import argparse
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("ci_timings", Path(__file__).with_name("ci-timings.py"))
TIMINGS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TIMINGS)


def job(identifier=1, created="2026-10-21T10:00:05Z", start="2026-10-21T10:00:10Z"):
    """Include misleading API job started_at to require actual step evidence."""
    return {
        "id": identifier, "name": "test / Unit Tests", "created_at": created,
        "started_at": created, "completed_at": "2026-10-21T10:01:10Z",
        "status": "completed", "conclusion": "success", "runner_name": "runner-1",
        "labels": ["self-hosted"], "steps": [
            {"name": "test", "status": "completed", "conclusion": "success",
             "started_at": start, "completed_at": "2026-10-21T10:01:10Z"},
        ],
    }


def metadata(attempt=1):
    """Bound an attempt independently of any earlier run or manual retry delay."""
    return {"run_attempt": attempt, "run_started_at": "2026-10-21T10:00:00Z",
            "updated_at": "2026-10-21T10:01:15Z", "status": "completed", "conclusion": "success"}


class TimingTests(unittest.TestCase):
    def test_release_assignment_and_execution_are_distinct(self):
        report = TIMINGS.job_report(job(), metadata()["run_started_at"])
        self.assertEqual((report["released_after_s"], report["assignment_delay_s"],
                          report["execution_s"]), (5, 5, 60))

    def test_parallel_jobs_are_not_summed_as_wall_time(self):
        report = TIMINGS.attempt_report(metadata(), [{"jobs": [job(), job(2)]}])
        self.assertEqual(report["wall_s"], 75)
        self.assertEqual(sum(row["execution_s"] for row in report["jobs"]), 120)

    def test_queued_job_started_at_does_not_prove_execution(self):
        queued = job()
        queued.update(status="queued", conclusion=None, steps=[], completed_at=None, runner_name=None)
        report = TIMINGS.job_report(queued, metadata()["run_started_at"])
        self.assertIsNone(report["assignment_delay_s"])
        self.assertIsNone(report["execution_s"])

    def test_skipped_job_has_no_measured_runner_execution(self):
        skipped = job()
        skipped.update(conclusion="skipped", steps=[], runner_name=None)
        self.assertIsNone(TIMINGS.job_report(skipped, metadata()["run_started_at"])["execution_s"])
        skipped["steps"] = job()["steps"]
        skipped["steps"][0]["conclusion"] = "skipped"
        report = TIMINGS.job_report(skipped, metadata()["run_started_at"])
        self.assertIsNone(report["execution_s"])
        self.assertIsNone(report["steps"][0]["seconds"])

    def test_partial_rerun_excludes_old_success_even_when_api_relabels_attempt(self):
        old = job(start="2026-10-21T09:00:10Z")
        old["run_attempt"] = 2
        old["completed_at"] = "2026-10-21T09:01:10Z"
        old["steps"][0]["completed_at"] = old["completed_at"]
        report = TIMINGS.attempt_report(metadata(2), [{"jobs": [old, job(2)]}])
        self.assertEqual(report["carried_jobs_excluded"], 1)
        self.assertEqual([row["id"] for row in report["jobs"]], [2])

    def test_partial_rerun_excludes_carried_skipped_job_without_steps(self):
        old = job()
        old.update(conclusion="skipped", steps=[], completed_at="2026-10-21T09:01:10Z")
        report = TIMINGS.attempt_report(metadata(2), [{"jobs": [old, job(2)]}])
        self.assertEqual(report["carried_jobs_excluded"], 1)

    def test_timezone_offsets_measure_actual_elapsed_time(self):
        self.assertEqual(TIMINGS.duration("2026-10-21T10:00:00Z", "2026-10-21T12:00:05+02:00"), 5)

    def test_fetch_uses_selected_attempt_and_every_jobs_page(self):
        run = {"run_attempt": 2, "html_url": "https://github.com/permesi/permesi/actions/runs/1",
               "head_sha": "a" * 40, "event": "push", "path": ".github/workflows/build.yml",
               "status": "completed", "conclusion": "success"}
        with mock.patch.object(TIMINGS, "api", side_effect=[run, metadata(2), [{"jobs": [job()]}]]) as api:
            report = TIMINGS.run_report("permesi/permesi", 1, 2)
        self.assertEqual(len(report["attempts"]), 1)
        self.assertEqual(api.call_args_list[-1], mock.call(
            "repos/permesi/permesi/actions/runs/1/attempts/2/jobs?per_page=100", paginated=True))
        with mock.patch.object(TIMINGS, "api", return_value=run):
            with self.assertRaises(ValueError):
                TIMINGS.run_report("permesi/permesi", 1, 3)

    def test_all_pages_are_collected_and_runners_remain_distinct(self):
        second = job(2)
        second["runner_name"] = "runner-2"
        report = TIMINGS.attempt_report(metadata(), [{"jobs": [job()]}, {"jobs": [second]}])
        self.assertEqual(report["runners"], ["runner-1", "runner-2"])
        self.assertEqual(len(report["jobs"]), 2)

    def test_incomplete_attempt_has_no_final_duration_or_success(self):
        active = metadata()
        active.update(status="in_progress", conclusion=None)
        report = TIMINGS.attempt_report(active, [{"jobs": [job()]}])
        self.assertIsNone(report["wall_s"])
        self.assertIsNone(report["conclusion"])

    def test_missing_time_is_unknown_and_invalid_time_is_rejected(self):
        self.assertIsNone(TIMINGS.duration(None, "2026-10-21T10:00:00Z"))
        with self.assertRaises(ValueError):
            TIMINGS.duration("2026-10-21T10:00:01Z", "2026-10-21T10:00:00Z")
        with self.assertRaises(ValueError):
            TIMINGS.timestamp("2026-10-21T10:00:00")

    def test_paths_reject_options_urls_and_traversal(self):
        for value in ("--help", "0", "1/../2", "1?x=2", "1\n2"):
            with self.assertRaises(argparse.ArgumentTypeError):
                TIMINGS.positive_integer(value)
        for value in ("https://github.com/a/b", "a/../b", "../b", "a/b?x=2"):
            with self.assertRaises(argparse.ArgumentTypeError):
                TIMINGS.repository_name(value)

    def test_api_is_bounded_read_only_paginated_and_does_not_use_shell(self):
        with mock.patch.object(TIMINGS.subprocess, "run", return_value=mock.Mock(stdout="[]")) as run:
            self.assertEqual(TIMINGS.api("repos/permesi/permesi/actions/runs/1/jobs", True), [])
        args, kwargs = run.call_args
        self.assertEqual(args[0][:7], ["gh", "api", "--hostname", "github.com", "--method", "GET",
                                       "repos/permesi/permesi/actions/runs/1/jobs"])
        self.assertEqual(args[0][-2:], ["--paginate", "--slurp"])
        self.assertEqual(kwargs["timeout"], 120)
        self.assertNotIn("shell", kwargs)

    def test_cli_failure_does_not_print_sensitive_cli_diagnostics(self):
        error = subprocess.CalledProcessError(1, "gh", stderr="synthetic credential sentinel")
        with mock.patch.object(TIMINGS.sys, "argv", ["ci-timings.py", "1"]), \
                mock.patch.object(TIMINGS, "api", side_effect=error), \
                mock.patch("sys.stderr") as stderr:
            self.assertEqual(TIMINGS.main(), 1)
        self.assertNotIn("sentinel", str(stderr.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
