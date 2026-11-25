#!/usr/bin/env python3
"""Refuse a release whose qualified chart revision is not on the chart repository's main.

Flow: read the commit statuses of the application commit being released, take the
newest successful `containment/<run>/<attempt>` status that sandbox CI recorded (its
description names the chart revision the images were qualified with), then ask GitHub
whether the chart repository's `main` contains that revision.

Why: the release dispatches its image digests to `permesi/permesi-helm`, which builds
the chart bump from its `main`. The charts that were tested with these images live on
that repository's `sandbox` until the operator merges them. Without this check a
release pairs new images with whatever older charts `main` still holds. The guard
fails closed: no qualification, or a qualified revision that `main` lacks, stops the
release before anything is built or tagged.

Only statuses written by the Actions bot count; a status is otherwise something any
collaborator can set. The chart repository is public, so the comparison needs no
extra credentials.
"""

import argparse
import json
import re
import subprocess
import sys

APP_REPO = "permesi/permesi"
CHART_REPO = "permesi/permesi-helm"
CONTEXT = re.compile(r"containment/[0-9]+/[0-9]+")
DESCRIPTION = re.compile(r"Helm ([0-9a-f]{40}), OCI artifact [0-9]+")
RECORDER = "github-actions[bot]"


class Refused(Exception):
    """The release must not proceed; the message tells the operator what to do."""


def qualified_chart(statuses):
    """Return the chart revision of the newest trusted containment status, or None.

    GitHub lists statuses newest first. A context can be re-recorded, so only the
    newest entry of each context counts, and it must be a success from the Actions bot.
    """
    seen = set()
    for status in statuses:
        context = status.get("context", "")
        if not CONTEXT.fullmatch(context) or context in seen:
            continue
        seen.add(context)
        match = DESCRIPTION.fullmatch(status.get("description") or "")
        creator = (status.get("creator") or {}).get("login")
        if status.get("state") == "success" and creator == RECORDER and match:
            return match.group(1)
    return None


def check(commit, statuses, compare):
    """Decide from API data alone; `compare(base)` returns the comparison of base...main."""
    chart = qualified_chart(statuses)
    if chart is None:
        raise Refused(
            f"{commit} has no containment qualification. Push it to sandbox, wait for "
            "'containment / record' to pass, fast-forward develop, then release."
        )
    comparison = compare(chart)
    state = comparison.get("status")
    if state not in ("identical", "ahead"):
        raise Refused(
            f"{CHART_REPO} main does not contain chart revision {chart}, which these images "
            f"were qualified with (main is {state}). Merge that repository's sandbox into "
            "main, then release."
        )
    return chart, int(comparison.get("ahead_by") or 0)


def api(path):
    """Read one GitHub API resource with the authenticated CLI."""
    result = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", path],
        check=True, capture_output=True, text=True,
    )
    pages = json.loads(result.stdout)
    if pages and all(isinstance(page, list) for page in pages):
        return [item for page in pages for item in page]
    return pages[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("commit", help="full SHA of the application commit to release")
    commit = parser.parse_args().commit
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        parser.error("commit must be a full 40-character SHA")
    try:
        chart, ahead = check(
            commit,
            api(f"repos/{APP_REPO}/commits/{commit}/statuses?per_page=100"),
            lambda base: api(f"repos/{CHART_REPO}/compare/{base}...main"),
        )
    except Refused as refused:
        print(f"::error::{refused}", file=sys.stderr)
        return 1
    except (subprocess.CalledProcessError, ValueError, KeyError, IndexError) as error:
        print(f"::error::Could not verify the qualified chart revision: {error}", file=sys.stderr)
        return 1
    print(f"Chart revision {chart} was qualified with {commit} and is on {CHART_REPO} main.")
    if ahead:
        print(
            f"::warning::{CHART_REPO} main has {ahead} commit(s) after the qualified "
            f"revision {chart}; they were not part of this qualification."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
