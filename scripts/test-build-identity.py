#!/usr/bin/env python3
"""Exercise actual service build scripts across cached environment/Git transitions.

Tiny disposable crates copy the product build scripts and effective-identity
constant. They reuse dependency compilation, but never the development .git or
service targets. No network, production services or global Git configuration is
needed. A nonzero build or stale identity fails the check.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ("permesi", "genesis")
TARGET = ROOT / "target/build-identity-regression"


def command(arguments, directory, environment=None):
    """Run bounded local tooling and retain diagnostics for test failures only."""
    return subprocess.run(
        arguments, cwd=directory, env=environment, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300,
    ).stdout.strip()


def fixture_environment():
    """Remove caller repository redirection and isolate global Git configuration."""
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("GIT_", "BUILT_OVERRIDE_"))}
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return environment


def prepare(directory):
    """Copy the real build scripts and identity selection into Git-less tiny crates."""
    dependencies = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["dependencies"]
    (directory / "services").mkdir()
    shutil.copyfile(ROOT / "services/build_identity.rs", directory / "services/build_identity.rs")
    shutil.copyfile(ROOT / "Cargo.lock", directory / "Cargo.lock")
    (directory / "Cargo.toml").write_text(
        '[workspace]\nresolver = "3"\nmembers = ["services/permesi", "services/genesis"]\n'
    )
    for service in SERVICES:
        package = directory / "services" / service
        (package / "src").mkdir(parents=True)
        shutil.copyfile(ROOT / f"services/{service}/build.rs", package / "build.rs")
        (package / "Cargo.toml").write_text(
            f'[package]\nname = "{service}_identity_fixture"\nversion = "0.0.0"\nedition = "2024"\n'
            f'[build-dependencies]\nbuilt = {{ version = "{dependencies["built"]["version"]}", features = ["git2"] }}\n'
            f'git2 = {{ version = "{dependencies["git2"]["version"]}", default-features = false }}\n'
        )
        original = (ROOT / f"services/{service}/src/lib.rs").read_text()
        identity = original.split("pub const GIT_COMMIT_HASH:", 1)[1].split("};", 1)[0]
        (package / "src/main.rs").write_text(
            'mod built_info { include!(concat!(env!("OUT_DIR"), "/built.rs")); }\n'
            f'pub const GIT_COMMIT_HASH:{identity}}};\n'
            'fn main() { println!("{}|{}", GIT_COMMIT_HASH, built_info::GIT_COMMIT_HASH.unwrap_or("unknown")); }\n'
        )


def build(directory, override, locked=True):
    """Reuse the same Cargo target across explicit-hash addition/change/removal."""
    environment = fixture_environment()
    environment.pop("BUILD_GIT_COMMIT_HASH", None)
    if override is not None:
        environment["BUILD_GIT_COMMIT_HASH"] = override
    command(
        ["cargo", "build", "--offline", *(["--locked"] if locked else []),
         "--target-dir", str(TARGET)], directory, environment,
    )
    return [command([str(TARGET / "debug" / f"{service}_identity_fixture")], directory).split("|")
            for service in SERVICES]


def git(directory, *arguments):
    """Operate only on the disposable repository, bypassing global signing policy."""
    return command(
        ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Identity test",
         "-c", "user.email=identity@example.invalid", *arguments], directory, fixture_environment(),
    )


class BuildIdentityTests(unittest.TestCase):
    def test_git_environment_cannot_redirect_fixture_mutations(self):
        """Caller Git state must remain untouched even with explicit redirection variables."""
        with tempfile.TemporaryDirectory(prefix="permesi-git-isolation-") as temporary:
            root = Path(temporary)
            foreign = root / "foreign"
            fixture = root / "fixture"
            foreign.mkdir()
            fixture.mkdir()
            git(foreign, "init", "-b", "foreign")
            (foreign / "sentinel").write_text("protected")
            git(foreign, "add", "sentinel")
            git(foreign, "commit", "-m", "Protect foreign fixture")
            protected = {name: (foreign / ".git" / name).read_bytes()
                         for name in ("HEAD", "config", "index", "refs/heads/foreign")}
            with mock.patch.dict(os.environ, {
                "GIT_DIR": str(foreign / ".git"),
                "GIT_WORK_TREE": str(foreign),
                "GIT_INDEX_FILE": str(foreign / ".git/index"),
                "GIT_COMMON_DIR": str(foreign / ".git"),
                "GIT_OBJECT_DIRECTORY": str(foreign / ".git/objects"),
            }):
                git(fixture, "init", "-b", "fixture")
                self.assertTrue((fixture / ".git").is_dir(), "Git escaped the fixture directory")
                (fixture / "sample").write_text("fixture only")
                git(fixture, "add", "sample")
                git(fixture, "commit", "-m", "Commit only inside fixture")
                self.assertEqual(Path(git(fixture, "rev-parse", "--absolute-git-dir")), fixture / ".git")
            for name, before in protected.items():
                self.assertEqual((foreign / ".git" / name).read_bytes(), before)
            self.assertEqual((foreign / "sentinel").read_text(), "protected")

    def test_gitless_cached_environment_changes_and_removal(self):
        """The actual scripts must rerun without touching source or cleaning targets."""
        with tempfile.TemporaryDirectory(prefix="permesi-build-identity-") as temporary:
            directory = Path(temporary)
            prepare(directory)
            self.assertEqual(build(directory, None, locked=False), [["unknown", "unknown"]] * 2)
            for override in ["a" * 40, "b" * 40, "", "unknown", None]:
                expected = override if override and override != "unknown" else "unknown"
                self.assertEqual(build(directory, override), [[expected, "unknown"]] * 2)

    def test_git_refs_detached_head_and_linked_worktree_invalidate_cached_identity(self):
        """Environment tracking must not suppress loose/packed/worktree Git tracking."""
        with tempfile.TemporaryDirectory(prefix="permesi-build-identity-") as temporary:
            root = Path(temporary)
            directory = root / "repository"
            directory.mkdir()
            prepare(directory)
            git(directory, "init", "-b", "identity-test")
            git(directory, "add", ".")
            git(directory, "commit", "-m", "Create identity fixture")
            first = git(directory, "rev-parse", "HEAD")
            self.assertEqual(build(directory, None, locked=False), [[first, first]] * 2)
            git(directory, "commit", "--allow-empty", "-m", "Advance identity fixture")
            second = git(directory, "rev-parse", "HEAD")
            self.assertNotEqual(first, second)
            self.assertEqual(build(directory, None), [[second, second]] * 2)
            git(directory, "pack-refs", "--all", "--prune")
            self.assertEqual(build(directory, None), [[second, second]] * 2)
            # A packed-file-only change must work without a newly created loose ref.
            packed = directory / ".git/packed-refs"
            packed_text = packed.read_text()
            self.assertIn(second, packed_text)
            packed.write_text(packed_text.replace(second, first))
            self.assertEqual(git(directory, "rev-parse", "HEAD"), first)
            self.assertEqual(build(directory, None), [[first, first]] * 2)
            packed.write_text(packed_text)
            self.assertEqual(build(directory, None), [[second, second]] * 2)
            # Also cover creation of a loose ref after packing.
            git(directory, "reset", "--soft", first)
            self.assertEqual(build(directory, None), [[first, first]] * 2)
            git(directory, "checkout", "--detach", second)
            self.assertEqual(build(directory, None), [[second, second]] * 2)
            worktree = root / "worktree"
            git(directory, "worktree", "add", "--detach", str(worktree), first)
            self.assertEqual(build(worktree, None, locked=False), [[first, first]] * 2)
            git(worktree, "checkout", "--detach", second)
            self.assertEqual(build(worktree, None), [[second, second]] * 2)
            git(worktree, "checkout", "-b", "linked-identity", first)
            self.assertEqual(build(worktree, None), [[first, first]] * 2)
            git(worktree, "commit", "--allow-empty", "-m", "Advance linked identity fixture")
            third = git(worktree, "rev-parse", "HEAD")
            self.assertNotEqual(first, third)
            self.assertEqual(build(worktree, None), [[third, third]] * 2)


if __name__ == "__main__":
    unittest.main()
