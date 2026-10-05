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
        self.stores = self.root / "stores"
        self.stores.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            GITHUB_ENV=str(self.root / "github-env"),
            GITHUB_STATE=str(self.root / "github-state"),
            RUNNER_ENVIRONMENT="self-hosted",
            # Each case chooses its runtime policy independently of the calling CI job.
            PERMESI_TEST_REQUIRE_PODMAN="0",
            RUNNER_TEMP=str(self.stores),
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
        (self.runtime / "systemd").mkdir()
        for path in [self.runtime / "bus", self.runtime / "systemd/private"]:
            with socket.socket(socket.AF_UNIX) as bus:
                bus.bind(str(path))
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
        self.fake("umount", '''#!/usr/bin/env bash
printf '%s\n' "$*" >> "${TEST_ROOT}/unmounts"
''')
        self.fake(
            "podman",
            r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s|%s\n' "${XDG_RUNTIME_DIR:-}" "$*" >> "${TEST_ROOT}/calls"
engine_root=""
while [[ "${1:-}" == --remote=false || "${1:-}" == --root || "${1:-}" == --runroot || "${1:-}" == --tmpdir || "${1:-}" == --network-config-dir ]]; do
    if [[ "$1" == --remote=false ]]; then shift; continue; fi
    if [[ "$1" == --root ]]; then engine_root="$2"; fi
    shift 2
done
if [[ "${1:-}" == info ]]; then
    if [[ "${TEST_FAIL_SHARED:-0}" == 1 && -z "${engine_root}" ]]; then exit 1; fi
    exit 0
fi
if [[ "${1:-}" == system && "${2:-}" == service ]]; then
    if [[ "${TEST_FAIL_SERVICE:-0}" == 1 ]]; then exit 1; fi
    endpoint="${4}"
    printf '%s\n' "$$" >> "${TEST_ROOT}/pids"
    touch "${endpoint#unix://}.ready"
    trap 'exit 0' TERM
    if [[ "${TEST_IGNORE_SERVICE_TERM:-0}" == 1 ]]; then trap '' TERM; fi
    while :; do sleep 0.1; done
fi
if [[ "${1:-}" == --url ]]; then
    [[ -f "${2#unix://}.ready" ]] || exit 1
    if [[ "${3:-}" == pull ]]; then
        if [[ "${TEST_FAIL_PULL:-}" == permanent ]]; then exit 1; fi
        if [[ "${TEST_FAIL_PULL:-}" == transient && ! -f "${TEST_ROOT}/failed-pull" ]]; then
            touch "${TEST_ROOT}/failed-pull"
            exit 1
        fi
    fi
    exit 0
fi
if [[ "${1:-}" =~ ^(container|volume|image)$ && "${2:-}" == rm && "${3:-}" == --all && -n "${engine_root}" ]]; then
    if [[ "${TEST_FAIL_CLEANUP:-0}" == 1 ]]; then exit 1; fi
    exit 0
fi
if [[ "${1:-}" == network && "${2:-}" == prune && "${3:-}" == --force && -n "${engine_root}" ]]; then exit 0; fi
if [[ "${1:-}" == unshare && -n "${engine_root}" ]]; then shift; exec "$@"; fi
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
        self.assertIn(f"--url {endpoint} pull docker.io/library/postgres:18", calls)
        self.assertIn(f"--url {endpoint} pull docker.io/hashicorp/vault:1.17.3", calls)

    def test_shared_pause_process_failure_does_not_affect_job_engine(self):
        result, exports = self.run_setup({"TEST_FAIL_SHARED": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        job_dir = Path(exports["DOCKER_HOST"].removeprefix("unix://")).parent
        states = self.saved_state()
        store_dir = Path(states["STATE_service_dir"])
        self.assertEqual(job_dir.parent, self.runtime)
        self.assertEqual(store_dir.parent, self.stores)
        self.assertEqual(exports["CONTAINER_HOST"], exports["DOCKER_HOST"])
        self.assertEqual(exports["XDG_RUNTIME_DIR"], str(job_dir))
        calls = (self.root / "calls").read_text()
        self.assertIn(f"--root {store_dir}/storage", calls)
        self.assertIn(f"--runroot {job_dir}/runroot", calls)
        self.assertIn(f"--tmpdir {job_dir}/libpod", calls)
        self.assertIn(f"--network-config-dir {store_dir}/networks", calls)
        for name in ["bus", "systemd/private"]:
            self.assertFalse((job_dir / name).is_symlink())
            self.assertTrue(os.path.samefile(job_dir / name, self.runtime / name))

    def saved_state(self):
        """Read only this action's cleanup handles from the fixture state file."""
        state_file = Path(self.env["GITHUB_STATE"])
        return {
            f"STATE_{key}": value
            for key, value in (
                line.split("=", 1) for line in state_file.read_text().splitlines()
            )
        } if state_file.exists() else {}

    def run_cleanup(self, states, extra_env=None):
        """Exercise the post hook against the fake, explicitly scoped engine."""
        return subprocess.run(
            ["bash", str(Path(__file__).with_name("cleanup.sh"))],
            env=self.env | states | (extra_env or {}),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def test_cleanup_removes_only_the_recorded_job_engine(self):
        result, _ = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        states = self.saved_state()
        foreign_store = self.stores / "pci.foreign"
        foreign_store.mkdir()
        (foreign_store / "sentinel").write_text("another job")
        cleanup = self.run_cleanup(states)
        self.assertEqual(cleanup.returncode, 0, cleanup.stderr)
        self.assertFalse(Path(states["STATE_service_dir"]).exists())
        self.assertFalse(Path(states["STATE_runtime_dir"]).exists())
        self.assertEqual((foreign_store / "sentinel").read_text(), "another job")
        self.assert_service_stopped(states["STATE_service_pid"])
        unmounts = (self.root / "unmounts").read_text().splitlines()
        self.assertEqual(unmounts, [
            f"-l {states['STATE_service_dir']}/storage/overlay",
            f"-l {states['STATE_runtime_dir']}/netns",
        ])
        calls = (self.root / "calls").read_text()
        self.assertNotIn("system reset", calls)
        self.assertIn("network prune --force", calls)
        self.assertIn(
            f"unshare bash -s -- {states['STATE_service_dir']} {states['STATE_runtime_dir']}",
            calls,
        )
        self.assertIn(f"--root {states['STATE_service_dir']}/storage", calls)

    def assert_service_stopped(self, pid):
        """Treat a reaped or zombie fixture process as stopped, without PID signals."""
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except FileNotFoundError:
            return
        self.assertEqual(cmdline, b"")

    def test_cleanup_continues_after_a_resource_command_fails(self):
        result, _ = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        states = self.saved_state()
        cleanup = self.run_cleanup(states, {"TEST_FAIL_CLEANUP": "1"})
        self.assertNotEqual(cleanup.returncode, 0)
        self.assert_service_stopped(states["STATE_service_pid"])
        self.assertFalse(Path(states["STATE_service_dir"]).exists())
        self.assertFalse(Path(states["STATE_runtime_dir"]).exists())

    def test_cleanup_leaves_a_nonmatching_recorded_pid_alive(self):
        result, _ = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        with subprocess.Popen(["sleep", "10"]) as foreign:
            states = self.saved_state() | {"STATE_service_pid": str(foreign.pid)}
            cleanup = self.run_cleanup(states)
            self.assertEqual(cleanup.returncode, 0, cleanup.stderr)
            self.assertIsNone(foreign.poll())
            foreign.terminate()

    def test_cleanup_escalates_only_the_job_service_that_ignores_sigterm(self):
        result, _ = self.run_setup({"TEST_IGNORE_SERVICE_TERM": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        states = self.saved_state()
        cleanup = self.run_cleanup(states)
        self.assertEqual(cleanup.returncode, 0, cleanup.stderr)
        self.assert_service_stopped(states["STATE_service_pid"])

    def test_cleanup_rejects_paths_outside_saved_job_directory_shape(self):
        result = self.run_cleanup({
            "STATE_service_dir": str(self.stores),
            "STATE_runtime_dir": str(self.runtime),
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.stores.exists())
        self.assertTrue(self.runtime.exists())
        self.assertFalse((self.root / "calls").exists())

    def test_cleanup_with_no_owned_engine_is_a_noop(self):
        result = self.run_cleanup({})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "calls").exists())

    def test_transient_image_pull_failure_is_retried(self):
        result, exports = self.run_setup({"TEST_FAIL_PULL": "transient"})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / "calls").read_text()
        self.assertEqual(calls.count("pull docker.io/library/postgres:18"), 2)
        self.assertIn("DOCKER_HOST", exports)

    def test_unavailable_required_image_fails_without_exporting_runtime(self):
        result, exports = self.run_setup({"TEST_FAIL_PULL": "permanent"})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DOCKER_HOST", exports)
        self.assertEqual(
            (self.root / "calls").read_text().count("pull docker.io/library/postgres:18"),
            3,
        )
        cleanup = self.run_cleanup(self.saved_state())
        self.assertEqual(cleanup.returncode, 0, cleanup.stderr)

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
        self.assertNotEqual(exports_a["XDG_RUNTIME_DIR"], exports_b["XDG_RUNTIME_DIR"])
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

    def test_hosted_runner_can_require_a_private_podman_api(self):
        """The scenario job's opt-in must bypass even an unhealthy system Docker API."""
        result, exports = self.run_setup({
            "RUNNER_ENVIRONMENT": "github-hosted",
            "PERMESI_TEST_REQUIRE_PODMAN": "1",
            "TEST_FAIL_DOCKER": "1",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exports["CONTAINER_TOOL"], "podman")
        self.assertNotEqual(exports["DOCKER_HOST"], f"unix://{self.runtime}/docker.sock")
        self.assertEqual(exports["CONTAINER_HOST"], exports["DOCKER_HOST"])
        self.assertIn("--root", (self.root / "calls").read_text())


if __name__ == "__main__":
    unittest.main()
