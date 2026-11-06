#!/usr/bin/env python3
"""Reject mutable remote action references in workflows and composite actions."""

from pathlib import Path
import re
import sys


def unpinned_references(content):
    """Local actions use the checkout; every remote action must name an immutable digest."""
    for number, line in enumerate(content.splitlines(), 1):
        match = re.match(r"^\s*(?:-\s*)?uses:\s*(.*?)\s*$", line)
        if not match:
            continue
        reference = match[1].split(" #", 1)[0].strip("\"'")
        if reference.startswith("./"):
            continue
        if re.fullmatch(r"[^\s@]+@[0-9a-f]{40}", reference):
            continue
        if re.fullmatch(r"docker://[^\s@]+@sha256:[0-9a-f]{64}", reference):
            continue
        yield number, reference


def main():
    """Check both workflow jobs and steps nested in repository-owned actions."""
    root = Path(__file__).resolve().parents[1]
    errors = []
    for path in sorted((root / ".github").rglob("*")):
        if path.suffix not in {".yml", ".yaml"}:
            continue
        for number, reference in unpinned_references(path.read_text()):
            errors.append(f"{path.relative_to(root)}:{number}: unpinned action {reference}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("All remote GitHub Actions use immutable commit or image digests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
