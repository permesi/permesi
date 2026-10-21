#!/usr/bin/env python3
"""Report GitHub job/step timings without downloading logs or changing CI.

Flow: fetch run and attempt metadata with the authenticated GitHub CLI, collect
every jobs page, exclude results carried from an earlier attempt, then emit JSON.
Release delay includes dependency/scheduling time; assignment delay includes the
runner queue/setup boundary. Neither is presented as pure runner queue time.
Parallel job durations are never added together to claim workflow wall time.
"""

import argparse
from datetime import datetime, timezone
import json
import re
import subprocess
import sys


def timestamp(value):
    """Require timezone-aware API timestamps rather than assume a local timezone."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("API timestamp has no timezone")
    return parsed


def duration(start, end):
    """Preserve unavailable measurements and reject backwards timestamp pairs."""
    if not start or not end:
        return None
    elapsed = (timestamp(end) - timestamp(start)).total_seconds()
    if elapsed < 0:
        raise ValueError("API timestamps are out of order")
    return round(elapsed, 3)


def api(endpoint, paginated=False):
    """Read metadata from github.com; never print CLI stderr or response bodies on failure."""
    result = subprocess.run(
        ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint,
         *(["--paginate", "--slurp"] if paginated else [])],
        check=True, capture_output=True, text=True, timeout=120,
    )
    return json.loads(result.stdout)


def first_step_start(job):
    """Find actual step execution; synthetic job starts and skipped steps are not evidence."""
    starts = [step["started_at"] for step in job.get("steps", [])
              if step.get("started_at") and step.get("conclusion") != "skipped"]
    return min(starts, key=timestamp) if starts else None


def belongs_to_attempt(job, origin):
    """Use execution evidence because partial reruns can rewrite old job creation/attempt fields."""
    evidence = first_step_start(job) or job.get("completed_at") or job["created_at"]
    return timestamp(evidence) >= timestamp(origin)


def job_report(job, origin):
    """Measure executed steps; queued/skipped jobs cannot establish runner execution."""
    steps = job.get("steps", [])
    first_step = first_step_start(job)
    completed = job["status"] == "completed"
    return {
        "id": job["id"], "name": job["name"], "status": job["status"],
        "conclusion": job.get("conclusion"), "runner": job.get("runner_name"),
        "labels": job.get("labels", []),
        "released_after_s": duration(origin, job["created_at"]),
        "assignment_delay_s": duration(job["created_at"], first_step),
        "execution_s": duration(first_step, job.get("completed_at")) if completed else None,
        "steps": [
            {"name": step["name"], "conclusion": step.get("conclusion"),
             "seconds": duration(step.get("started_at"), step.get("completed_at"))
             if step["status"] == "completed" and step.get("conclusion") != "skipped" else None}
            for step in steps
        ],
    }


def attempt_report(metadata, pages):
    """Exclude pre-attempt jobs returned by GitHub after a partial rerun."""
    origin = metadata["run_started_at"]
    jobs = [job for page in pages for job in page["jobs"]]
    current = [job for job in jobs if belongs_to_attempt(job, origin)]
    reports = [job_report(job, origin) for job in current]
    return {
        "attempt": metadata["run_attempt"], "status": metadata["status"],
        "conclusion": metadata.get("conclusion"), "started_at": origin,
        "wall_s": duration(origin, metadata["updated_at"])
        if metadata["status"] == "completed" else None,
        "carried_jobs_excluded": len(jobs) - len(current),
        "runners": sorted({job["runner"] for job in reports if job["runner"]}),
        "jobs": reports,
    }


def run_report(repository, run_id, attempt=None):
    """Fetch each attempt independently so retries never inherit successful old work."""
    endpoint = f"repos/{repository}/actions/runs/{run_id}"
    run = api(endpoint)
    latest = run["run_attempt"]
    if attempt is not None and attempt > latest:
        raise ValueError("Requested attempt does not exist")
    attempts = [attempt] if attempt is not None else range(1, latest + 1)
    reports = []
    for number in attempts:
        path = f"{endpoint}/attempts/{number}"
        metadata = api(path)
        pages = api(f"{path}/jobs?per_page=100", paginated=True)
        reports.append(attempt_report(metadata, pages))
    return {
        "run_id": run_id, "url": run["html_url"], "head_sha": run["head_sha"],
        "event": run["event"], "workflow": run["path"],
        "status": run["status"], "conclusion": run.get("conclusion"),
        "attempts": reports,
    }


def positive_integer(value):
    """Keep run/attempt identifiers numeric before constructing API paths."""
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError("Expected a positive decimal integer")
    return int(value)


def repository_name(value):
    """Accept an owner/repository pair, never a URL or API path traversal."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", value):
        raise argparse.ArgumentTypeError("Expected owner/repository")
    return value


def main():
    """Print metadata-only JSON; errors and incomplete runs never imply passing CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_ids", type=positive_integer, nargs="+")
    parser.add_argument("--repo", type=repository_name, default="permesi/permesi")
    parser.add_argument("--attempt", type=positive_integer)
    args = parser.parse_args()
    try:
        runs = [run_report(args.repo, run_id, args.attempt) for run_id in args.run_ids]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        print(f"Cannot collect CI timing metadata ({type(error).__name__}).", file=sys.stderr)
        return 1
    print(json.dumps({"schema_version": 1, "repository": args.repo,
                      "sampled_at": datetime.now(timezone.utc).isoformat(), "runs": runs}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
