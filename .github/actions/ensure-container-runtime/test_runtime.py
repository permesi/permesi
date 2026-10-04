"""Exercise CI runtime setup without changing the host's container engine."""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import unittest


class RuntimeSetupTests(unittest.TestCase):
    """Local engine health must never substitute for exported API readiness."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="permesi-runtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            GITHUB_ENV=str(self.root / "github-env"),
            RUNNER_ENVIRONMENT="self-hosted",
            RUNNER_TEMP=str(self.runtime),
            TEST_ROOT=str(self.root),
        )
        self.script = Path(__file__).with_name("runtime.sh").read_text()
        # Redirect runtime directories into the fixture, including a stale socket.
        self.script = self.script.replace(
            "/run/user/${runtime_uid}", str(self.runtime)
        )
        (self.runtime / "podman").mkdir()
        with socket.socket(socket.AF_UNIX) as stale:
            stale.bind(str(self.runtime / "podman/podman.sock"))
        docker_socket = self.runtime / "docker.sock"
        with socket.socket(socket.AF_UNIX) as docker:
            docker.bind(str(docker_socket))
        self.script = self.script.replace("/var/run/docker.sock", str(docker_socket))
        self.fake(
            "docker",
            '''#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == --host ]] || exit 1
if [[ "$3" == info && "${TEST_FAIL_DOCKER:-0}" == 1 ]]; then exit 1; fi
''',
        )
        self.fake(
            "podman",
            r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${TEST_ROOT}/calls"
if [[ "${1:-}" == --remote=false ]]; then shift; fi
if [[ "${1:-}" == info ]]; then exit 0; fi
if [[ "${1:-}" == system && "${2:-}" == service ]]; then
    if [[ "${TEST_FAIL_SERVICE:-0}" == 1 ]]; then exit 1; fi
    endpoint="${4}"
    printf '%s\n' "$$" >> "${TEST_ROOT}/pids"
    touch "${endpoint#unix://}.ready"
    trap 'exit 0' TERM
    while :; do sleep 0.1; done
fi
if [[ "${1:-}" == --url ]]; then
    [[ -f "${2#unix://}.ready" ]] || exit 1
    exit 0
fi
echo 'Unexpected shared runtime mutation' >&2
exit 1
''',
        )
        self.addCleanup(self.stop_services)

    def fake(self, name, source):
        executable = self.bin / name
        executable.write_text(source)
        executable.chmod(0o755)

    def stop_services(self):
        pids = self.root / "pids"
        if pids.exists():
            for pid in pids.read_text().splitlines():
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass

    def run_setup(self, extra_env=None):
        run_env = self.env | (extra_env or {})
        result = subprocess.run(
            ["bash"],
            input=self.script,
            text=True,
            capture_output=True,
            env=run_env,
            timeout=10,
            check=False,
        )
        env_file = Path(run_env["GITHUB_ENV"])
        exports = (
            dict(line.split("=", 1) for line in env_file.read_text().splitlines())
            if env_file.exists()
            else {}
        )
        return result, exports

    def test_stale_shared_socket_exports_a_verified_job_api(self):
        result, exports = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        endpoint = exports["DOCKER_HOST"]
        self.assertNotEqual(endpoint, f"unix://{self.runtime}/podman/podman.sock")
        probe = subprocess.run(
            ["podman", "--url", endpoint, "info"], env=self.env, check=False
        )
        self.assertEqual(probe.returncode, 0)
        calls = (self.root / "calls").read_text()
        self.assertNotIn("system migrate", calls)
        self.assertIn(f"--url {endpoint} info", calls)

    def test_local_engine_success_with_failed_api_fails_setup(self):
        result, exports = self.run_setup({"TEST_FAIL_SERVICE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DOCKER_HOST", exports)
        self.assertIn("Job Podman API did not become ready", result.stdout)

    def test_jobs_do_not_reuse_or_remove_each_others_socket(self):
        with ThreadPoolExecutor(max_workers=2) as workers:
            job_a = workers.submit(
                self.run_setup, {"GITHUB_ENV": str(self.root / "job-a-env")}
            )
            job_b = workers.submit(
                self.run_setup, {"GITHUB_ENV": str(self.root / "job-b-env")}
            )
            first, exports_a = job_a.result()
            second, exports_b = job_b.result()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(exports_a["DOCKER_HOST"], exports_b["DOCKER_HOST"])
        self.assertTrue(Path(f"{exports_a['DOCKER_HOST'][7:]}.ready").exists())
        self.assertTrue(Path(f"{exports_b['DOCKER_HOST'][7:]}.ready").exists())

    def test_hosted_runner_verifies_the_system_docker_api(self):
        result, exports = self.run_setup({"RUNNER_ENVIRONMENT": "github-hosted"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exports["CONTAINER_TOOL"], "docker")
        self.assertEqual(
            exports["DOCKER_HOST"], f"unix://{self.runtime}/docker.sock"
        )
        self.assertFalse((self.root / "calls").exists())

    def test_hosted_runner_fails_before_exporting_an_unhealthy_api(self):
        result, exports = self.run_setup(
            {"RUNNER_ENVIRONMENT": "github-hosted", "TEST_FAIL_DOCKER": "1"}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DOCKER_HOST", exports)


if __name__ == "__main__":
    unittest.main()
