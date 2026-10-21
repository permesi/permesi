#!/usr/bin/env python3
"""Exercise runner provisioning decisions without sudo, package changes or network access."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("runtime.sh")


class MuslToolchainTests(unittest.TestCase):
    def setUp(self):
        """Isolate executable lookup so missing/privileged tools are deterministic."""
        self.temporary = tempfile.TemporaryDirectory(prefix="permesi-musl-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.trace = self.root / "trace"
        self.environment = {**os.environ, "PATH": str(self.bin), "RUNNER_TEMP": str(self.root),
                            "TRACE": str(self.trace)}
        for name in ("mktemp", "rm"):
            (self.bin / name).symlink_to(shutil.which(name))
        self.stub("id", "printf '1000\\n'")

    def stub(self, name, body):
        """Create an owned executable substitute; no host package manager is invoked."""
        path = self.bin / name
        path.write_text(f'#!/bin/sh\nprintf "%s\\n" "{name} $*" >> "$TRACE"\n{body}\n')
        path.chmod(0o700)

    def run_script(self):
        """Bound execution and retain only synthetic test diagnostics."""
        return subprocess.run(["/bin/bash", str(SCRIPT)], env=self.environment,
                              text=True, capture_output=True, timeout=5, check=False)

    def test_preinstalled_compiler_never_calls_sudo_or_package_manager(self):
        self.stub("musl-gcc", "exit 0")
        self.stub("sudo", "exit 99")
        self.stub("apt-get", "exit 99")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.trace.read_text().splitlines()
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("musl-gcc -static -x c - -o "))
        self.assertFalse(list(self.root.glob("permesi-musl.*")))

    def test_missing_compiler_without_package_manager_fails_with_provisioning_help(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Provision musl-dev and musl-tools", result.stdout)

    def test_denied_sudo_is_noninteractive_and_never_falls_back(self):
        self.stub("apt-get", "exit 99")
        self.stub("sudo", "exit 1")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sudo -n -- apt-get install -y musl-dev musl-tools", self.trace.read_text())
        self.assertNotIn("apt-get install", self.trace.read_text().replace(
            "sudo -n -- apt-get install -y musl-dev musl-tools", ""))

    def test_nonroot_without_sudo_never_invokes_package_manager_directly(self):
        self.stub("apt-get", "exit 99")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MUSL tooling is unavailable", result.stdout)
        self.assertNotIn("apt-get", self.trace.read_text())

    def test_nonroot_installs_only_through_existing_noninteractive_sudo_policy(self):
        self.stub("apt-get", "exit 99")
        self.stub("sudo", 'printf "#!/bin/sh\\nexit 0\\n" > "$PATH/musl-gcc"\n/bin/chmod 700 "$PATH/musl-gcc"')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sudo -n -- apt-get install -y musl-dev musl-tools", self.trace.read_text())

    def test_broken_preinstalled_compiler_fails_probe_without_reinstalling(self):
        self.stub("musl-gcc", "exit 1")
        self.stub("sudo", "exit 99")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot compile and statically link", result.stdout)
        self.assertNotIn("sudo", self.trace.read_text())
        self.assertFalse(list(self.root.glob("permesi-musl.*")))

    def test_root_install_still_requires_compiler_after_successful_package_command(self):
        self.stub("id", "printf '0\\n'")
        self.stub("apt-get", "exit 0")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("apt-get install -y musl-dev musl-tools", self.trace.read_text())
        self.assertIn("MUSL tooling is unavailable", result.stdout)


if __name__ == "__main__":
    unittest.main()
