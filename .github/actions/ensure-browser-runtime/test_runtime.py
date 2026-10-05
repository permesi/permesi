"""Verify browser selection, fail-closed readiness and probe cleanup without a browser."""

import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import unittest


class BrowserRuntimeTests(unittest.TestCase):
    """An installed binary or version response cannot substitute for usable DevTools."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="permesi-browser-runtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            PATH=str(self.bin),
            RUNNER_TEMP=str(self.runner),
            GITHUB_PATH=str(self.root / "github-path"),
            BROWSER_RUNTIME_TEST_ROOT=str(self.root),
            BROWSER_RUNTIME_TEST_HTTP_FAILURE="0",
        )
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash)
        for command in ["bash", "mkdir", "mktemp", "timeout", "sleep", "rm", "ln", "cat"]:
            executable = shutil.which(command)
            self.assertIsNotNone(executable)
            (self.bin / command).symlink_to(executable)
        self.fake("curl", '''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "${BROWSER_RUNTIME_TEST_ROOT}/http"
if [[ -n "${http_proxy:-}" && "$*" != *'--noproxy *'* ]]; then exit 1; fi
[[ "${BROWSER_RUNTIME_TEST_HTTP_FAILURE}" == 0 ]]
''')

    def fake(self, name, content):
        """Own each fixture executable; PATH excludes installed host browsers."""
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def browser(self, name, working=True, port="9222", newline=True, lifetime=30, ignore_term=False):
        """A version-capable but failed launch reproduces the original CI selection defect."""
        self.fake(name, f'''#!/usr/bin/env bash
if [[ "${{1:-}}" == --version ]]; then echo 'Fixture {name}'; exit 0; fi
printf '%s\\n' '{name}' >> "${{BROWSER_RUNTIME_TEST_ROOT}}/launches"
printf '%s\\n' "$$" >> "${{BROWSER_RUNTIME_TEST_ROOT}}/pids"
for argument in "$@"; do
    if [[ "$argument" == --user-data-dir=* ]]; then profile="${{argument#--user-data-dir=}}"; fi
done
printf '%s\\n' "$profile" >> "${{BROWSER_RUNTIME_TEST_ROOT}}/profiles"
if [[ '{working}' != True ]]; then echo 'Fixture startup rejected'; exit 1; fi
printf '%s' '{port}' > "$profile/DevToolsActivePort"
if [[ '{newline}' == True ]]; then printf '\\n/devtools/browser/fixture\\n' >> "$profile/DevToolsActivePort"; fi
if [[ '{ignore_term}' == True ]]; then trap '' TERM; fi
exec sleep {lifetime}
''')

    def run_setup(self):
        """Execute the helper and require each owned profile and browser process to retire."""
        result = subprocess.run(
            [self.bash, str(Path(__file__).with_name("runtime.sh"))],
            env=self.env, text=True, capture_output=True, timeout=45,
        )
        profiles = self.root / "profiles"
        if profiles.exists():
            for profile in profiles.read_text().splitlines():
                self.assertFalse(Path(profile).exists(), result.stdout + result.stderr)
        pids = self.root / "pids"
        if pids.exists():
            for value in pids.read_text().splitlines():
                pid = int(value)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                os.kill(pid, signal.SIGTERM)
                self.fail(f"Owned browser process {pid} survived setup")
        return result

    def assert_selected(self, result, name):
        """Publish only the successful browser through a private, job-local alias."""
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        alias_dir = self.runner / "browser-test-bin"
        self.assertEqual((alias_dir / "chromium").resolve(), self.bin / name)
        self.assertEqual(alias_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / "github-path").read_text(), str(alias_dir) + "\n")
        self.assertIn("http://127.0.0.1:9222/json/version", (self.root / "http").read_text())

    def test_native_chrome_precedes_unusable_chromium(self):
        self.browser("chromium", working=False)
        self.browser("google-chrome")
        self.assert_selected(self.run_setup(), "google-chrome")
        self.assertEqual((self.root / "launches").read_text(), "google-chrome\n")

    def test_failed_chrome_falls_back_to_stable_chrome(self):
        self.browser("google-chrome", working=False)
        self.browser("google-chrome-stable")
        self.assert_selected(self.run_setup(), "google-chrome-stable")
        self.assertEqual((self.root / "launches").read_text(), "google-chrome\ngoogle-chrome-stable\n")

    def test_chromium_fallback_works_without_chrome(self):
        self.browser("chromium")
        self.assert_selected(self.run_setup(), "chromium")

    def test_browser_ignoring_termination_is_reaped_before_return(self):
        self.browser("chromium", ignore_term=True)
        self.assert_selected(self.run_setup(), "chromium")

    def test_loopback_probe_bypasses_configured_proxy(self):
        self.browser("chromium")
        self.env["http_proxy"] = "http://127.0.0.1:1"
        self.assert_selected(self.run_setup(), "chromium")

    def test_unterminated_port_file_falls_back_without_aborting(self):
        self.browser("google-chrome", port="invalid", newline=False, lifetime=0.3)
        self.browser("google-chrome-stable")
        result = self.run_setup()
        self.assert_selected(result, "google-chrome-stable")
        self.assertIn("::warning::google-chrome", result.stdout)
        self.assertEqual((self.root / "launches").read_text(), "google-chrome\ngoogle-chrome-stable\n")

    def test_version_success_without_headless_readiness_is_rejected(self):
        self.browser("chromium", working=False)
        result = self.run_setup()
        self.assertEqual(result.returncode, 1)
        self.assertIn("No installed Chromium-compatible browser passed headless startup", result.stdout)
        self.assertFalse((self.root / "github-path").exists())

    def test_missing_browsers_fail_closed(self):
        result = self.run_setup()
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.runner / "browser-test-bin/chromium").exists())
        self.assertFalse((self.root / "github-path").exists())

    def test_invalid_devtools_port_does_not_issue_http_request(self):
        for port in ["attacker.example:80", "0x50", "1+80", "0", "65536"]:
            with self.subTest(port=port):
                self.browser("chromium", port=port, lifetime=0.3)
                result = self.run_setup()
                self.assertEqual(result.returncode, 1)
                self.assertFalse((self.root / "http").exists())
                self.assertFalse((self.root / "github-path").exists())
                shutil.rmtree(self.runner / "browser-test-bin")

    def test_port_file_without_http_readiness_is_rejected(self):
        self.browser("chromium")
        self.env["BROWSER_RUNTIME_TEST_HTTP_FAILURE"] = "1"
        result = self.run_setup()
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.root / "github-path").exists())


if __name__ == "__main__":
    unittest.main()
