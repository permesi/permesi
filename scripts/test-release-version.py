#!/usr/bin/env python3
"""Exercise the actual release version readers with streamed, oversized manifests."""

import base64
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.4.4"


def manifest(version=VERSION):
    """Exceed pipe buffers and include a later version that must never be selected."""
    header = f'[workspace.package]\nversion = "{version}"\n' if version else "[workspace]\n"
    footer = '[workspace.metadata.fixture]\nversion = "9.9.9"\n' if version else ""
    return (header + "# fixture padding\n" * 150_000 + footer).encode()


def guard_version_block():
    """Run the workflow's real parser and mismatch rejection, without network access."""
    lines = (ROOT / ".github/workflows/deploy.yml").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if 'version="$(gh api ' in line)
    end = next(i for i in range(start + 1, len(lines)) if 'passed="$(gh run list ' in lines[i])
    return textwrap.dedent("\n".join(lines[start:end]))


def run_guard(response, block=None):
    """Stub only the API bytes; execute the checked-in shell under CI's pipefail mode."""
    with tempfile.TemporaryDirectory(prefix="permesi-release-version-") as directory:
        fixture = Path(directory) / "response.b64"
        fixture.write_bytes(response)
        script = r'''
set -euo pipefail
repo=fixture/project
commit=1111111111111111111111111111111111111111
TAG=0.4.4
gh() {
  [[ "$1" == api && "$2" == "repos/${repo}/contents/Cargo.toml?ref=${commit}" && "$3" == --jq && "$4" == .content ]] || return 42
  cat "${RELEASE_TEST_RESPONSE}"
}
'''
        script += (guard_version_block() if block is None else block)
        script += '\nprintf "accepted=%s\\n" "$version"\n'
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True,
            env={**os.environ, "RELEASE_TEST_RESPONSE": str(fixture)}, check=False,
        )


def run_latest(versions, *, corrupt=False, api_failure=False):
    """Execute the complete latest-release action with isolated API responses."""
    source = (ROOT / ".github/actions/release-is-latest/action.yml").read_text()
    block = textwrap.dedent(source.split("      run: |\n", 1)[1])
    with tempfile.TemporaryDirectory(prefix="permesi-release-latest-") as directory:
        root = Path(directory)
        (root / "tags").write_text("\n".join(versions) + "\n")
        for version, contents in versions.items():
            encoded = base64.encodebytes(contents) + (b"!invalid!" if corrupt else b"")
            (root / (version + ".b64")).write_bytes(encoded)
        script = r'''
set -euo pipefail
gh() {
  [[ "$RELEASE_TEST_API_FAILURE" != true && "$1" == api ]] || return 42
  if [[ "$2" == --paginate ]]; then cat "$RELEASE_TEST_RESPONSES/tags"; return; fi
  case "$2" in
    */git/ref/tags/*) printf 'tag %040d\n' 1 ;;
    */git/tags/*) printf 'true\n' ;;
    */commits/refs/tags/0.4.4) printf '%040d\n' 4 ;;
    */commits/refs/tags/0.4.5) printf '%040d\n' 5 ;;
    */compare/*) printf 'ahead\n' ;;
    */contents/Cargo.toml\?ref=0000000000000000000000000000000000000004)
      cat "$RELEASE_TEST_RESPONSES/0.4.4.b64" ;;
    */contents/Cargo.toml\?ref=0000000000000000000000000000000000000005)
      cat "$RELEASE_TEST_RESPONSES/0.4.5.b64" ;;
    *) return 42 ;;
  esac
}
'''
        output = root / "output"
        result = subprocess.run(
            ["bash", "-c", script + block], capture_output=True, text=True, check=False,
            env={**os.environ, "GITHUB_REPOSITORY": "fixture/project", "TAG": VERSION,
                 "GITHUB_OUTPUT": str(output), "RELEASE_TEST_RESPONSES": directory,
                 "RELEASE_TEST_API_FAILURE": str(api_failure).lower()},
        )
        return result, output.read_text() if output.exists() else ""


class ReleaseVersionTests(unittest.TestCase):
    def test_all_api_manifest_readers_consume_large_streams(self):
        readers = []
        for path in (ROOT / ".github").rglob("*"):
            if path.suffix not in {".yml", ".yaml"}:
                continue
            for line in path.read_text().splitlines():
                if 'version="$(gh api ' in line and "Cargo.toml" in line:
                    readers.append((path.relative_to(ROOT), line.strip()))
        self.assertTrue(readers)
        for path, assignment in readers:
            with self.subTest(path=str(path)):
                result = run_guard(base64.encodebytes(manifest()), assignment)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, f"accepted={VERSION}\n")

    def test_latest_action_preserves_version_and_rollback_checks(self):
        cases = [
            ({VERSION: manifest()}, "true", VERSION),
            ({VERSION: manifest(), "0.4.5": manifest("0.4.5")}, "false", "0.4.5"),
            ({VERSION: manifest("0.4.3")}, "false", ""),
            ({VERSION: manifest(None)}, "false", ""),
        ]
        for versions, latest, highest in cases:
            with self.subTest(latest=latest, highest=highest):
                result, output = run_latest(versions)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(output, f"latest={latest}\nhighest={highest}\n")

    def test_latest_action_fails_closed_on_corrupt_or_unavailable_evidence(self):
        for options in [{"corrupt": True}, {"api_failure": True}]:
            with self.subTest(options=options):
                result, output = run_latest({VERSION: manifest()}, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")

    def test_guard_consumes_large_stream_and_selects_first_version(self):
        result = run_guard(base64.encodebytes(manifest()))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, f"accepted={VERSION}\n")

    def test_guard_rejects_missing_or_mismatched_version(self):
        for version in [None, "0.4.3"]:
            with self.subTest(version=version):
                result = run_guard(base64.encodebytes(manifest(version)))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("does not match the workspace version", result.stdout)
                self.assertNotIn("accepted=", result.stdout)

    def test_guard_rejects_invalid_base64_even_after_valid_version(self):
        result = run_guard(base64.encodebytes(manifest()) + b"!invalid!")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("accepted=", result.stdout)

    def test_git_reader_consumes_large_manifest_and_preserves_git_failure(self):
        source = (ROOT / "scripts/release").read_text()
        function = re.search(r"(?ms)^version_at\(\) \{\n.*?^\}", source)
        self.assertIsNotNone(function)
        with tempfile.TemporaryDirectory(prefix="permesi-release-git-version-") as directory:
            subprocess.run(
                ["git", "-c", "init.defaultBranch=fixture", "-c", "init.templateDir=",
                 "init", "--quiet", directory], check=True, capture_output=True,
            )
            (Path(directory) / "Cargo.toml").write_bytes(manifest())
            subprocess.run(["git", "add", "Cargo.toml"], cwd=directory, check=True, capture_output=True)
            subprocess.run(
                ["git", "-c", "user.name=Release Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "--quiet", "-m", "Create version fixture"],
                cwd=directory, check=True, capture_output=True,
            )
            for ref, expected in [("HEAD", VERSION), ("missing-ref", None)]:
                result = subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n" + function[0] + '\nversion_at "$1"',
                     "release-version-test", ref], cwd=directory,
                    capture_output=True, text=True, check=False,
                )
                if expected:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, expected + "\n")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
