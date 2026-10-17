#!/usr/bin/env python3
"""Exercise the standalone runner's real process/container ownership boundaries.

No product accounts/sessions are seeded. Failed startup, interruption, repeat and
parallel cases run on disposable local dependencies. Subprocess output stays
private; only fixed check names are printed. A cleanup fault is injected once,
then only resources listed in that run's ownership record are recovered.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "target/debug/permesi-oauth-scenario"
REPLICAS = 3
RUNNER_COMMAND = [str(RUNNER), "--replicas", str(REPLICAS)]
PODMAN = shutil.which("podman")
ENGINE = [PODMAN, "--url", os.environ["DOCKER_HOST"]] if os.environ.get("DOCKER_HOST") else [PODMAN, "--remote=false"]


def check(condition):
    if not condition:
        raise RuntimeError("Scenario harness invariant failed.")


def command(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240, **kwargs)


def report(directory):
    paths = list(directory.glob("*/report.json"))
    check(len(paths) == 1)
    value = json.loads(paths[0].read_text())
    junit = ET.parse(paths[0].with_name("junit.xml")).getroot()
    check(int(junit.attrib["tests"]) >= len(value["cases"]))
    return value


def ownership(directory):
    return [json.loads(path.read_text()) for path in directory.glob("*/ownership-*.json")]


def no_resources(directory):
    for owned in ownership(directory):
        for resource in ("ps", "network"):
            args = ENGINE + (["ps", "--all"] if resource == "ps" else ["network", "ls"])
            result = command(args + ["--filter", f"label=io.permesi.scenario={owned['run_id']}", "--format", "{{.Names}}" if resource == "ps" else "{{.Name}}"])
            check(result.returncode == 0 and not result.stdout.strip())
        check(not Path(owned["private_directory"]).exists())
        check(all(not same_process(owned, process) for process in owned.get("processes", [])))


def same_process(owned, process):
    """PID reuse alone can never authorize termination of an unrelated process."""
    try:
        root = Path('/proc') / str(process['pid'])
        ticks = int((root / 'stat').read_text().rsplit(')', 1)[1].split()[19])
        return ticks == process['start_ticks'] and owned['private_directory'].encode() in (root / 'cmdline').read_bytes()
    except (OSError, ValueError):
        return False


def owned_private_directory(owned):
    """Bind file cleanup to the private directory's owner marker, type and current UID."""
    private = Path(owned["private_directory"])
    if not private.exists() and not private.is_symlink():
        return None
    check(private.parent.resolve() == Path(tempfile.gettempdir()).resolve())
    check(private.name.startswith("permesi-scenario-"))
    uuid.UUID(private.name.removeprefix("permesi-scenario-"))
    metadata = private.lstat()
    check(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid())
    check(stat.S_IMODE(metadata.st_mode) == 0o700)
    check((private / "owner").read_text() == owned["run_id"])
    return private


def recover(directory, additional_processes=()):
    # Records name only; validate the ownership label before any forced removal.
    for owned in ownership(directory):
        private = owned_private_directory(owned)
        processes = [*owned.get("processes", []), *additional_processes]
        for process in processes:
            kill_owned_process(owned, process)
        for name in owned["containers"]:
            label = command(ENGINE + ["inspect", "--format", '{{index .Config.Labels "io.permesi.scenario"}}', name])
            if label.returncode == 0:
                check(label.stdout.decode().strip() == owned["run_id"])
                check(command(ENGINE + ["rm", "--force", name]).returncode == 0)
        label = command(ENGINE + ["network", "inspect", "--format", '{{index .Labels "io.permesi.scenario"}}', owned["network"]])
        if label.returncode == 0:
            check(label.stdout.decode().strip() == owned["run_id"])
            check(command(ENGINE + ["network", "rm", owned["network"]]).returncode == 0)
        deadline = time.monotonic() + 5
        while any(same_process(owned, process) for process in processes) and time.monotonic() < deadline:
            time.sleep(.05)
        check(all(not same_process(owned, process) for process in processes))
        if private is not None:
            shutil.rmtree(private)


def kill_owned_process(owned, process):
    """Pin a process incarnation before checking ownership; never signal a recycled PID."""
    try:
        descriptor = os.pidfd_open(process["pid"])
    except ProcessLookupError:
        return
    try:
        if same_process(owned, process):
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        os.close(descriptor)


def verify_journal(owned, children, initial):
    """Independent observed children must all be recoverable from the persisted record alone."""
    current = {(item["pid"], item["start_ticks"]) for item in owned["processes"]}
    observed = {(item["pid"], item["start_ticks"]) for item in children}
    check(observed <= current and (observed - initial))


def failed_start(directory, fake, env=None, extra=None):
    result = command([*RUNNER_COMMAND, "--case", "authorization.consent", "--report-dir", str(directory), "--permesi-bin", str(fake),  ] + (extra or ["--readiness-seconds", "2"]), env=env)
    check(result.returncode != 0)
    value = report(directory)
    check(value["infrastructure_failure"] and all(case["status"] == "blocked" for case in value["cases"]))
    return value


def interrupted(directory, fake):
    process = subprocess.Popen([*RUNNER_COMMAND, "--case", "authorization.consent", "--report-dir", str(directory), "--permesi-bin", str(fake)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 120
        started = False
        while time.monotonic() < deadline and process.poll() is None:
            for key, _ in selector.select(1):
                if "Starting real Genesis" in key.fileobj.readline():
                    started = True
                    break
            if started:
                break
        check(started)
        process.send_signal(signal.SIGTERM)
        cleaning = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and process.poll() is None:
            for key, _ in selector.select(.1):
                if "Cleaning up owned" in key.fileobj.readline():
                    cleaning = True
                    break
            if cleaning:
                break
        check(cleaning)
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=60)
        check(process.returncode != 0)
        value = report(directory)
        check(value["infrastructure_failure"] and not value["cleanup_failures"])
        no_resources(directory)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        recover(directory)


def freeze_owned_children(process, directory):
    """Freeze only our runner and independently observe its direct owned service children."""
    process.send_signal(signal.SIGSTOP)
    deadline = time.monotonic() + 5
    root = Path("/proc") / str(process.pid)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return []
        status = (root / "status").read_text()
        if any(line.startswith("State:") and line.split()[1] == "T" for line in status.splitlines()):
            break
        time.sleep(.01)
    else:
        raise RuntimeError("Owned runner did not stop.")
    records = ownership(directory)
    if not records:
        return []
    check(len(records) == 1)
    owned = records[0]
    owned_private_directory(owned)
    pids = set()
    for task in (root / "task").iterdir():
        try:
            pids.update(int(value) for value in (task / "children").read_text().split())
        except FileNotFoundError:
            continue
    children = []
    for pid in pids:
        try:
            ticks = int((Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])
        except FileNotFoundError:
            continue
        identity = {"pid": pid, "start_ticks": ticks}
        if same_process(owned, identity):
            children.append(identity)
    return children


def interrupted_restart(directory):
    """SIGKILL after a real replacement must leave its new incarnation recoverable."""
    process = subprocess.Popen([*RUNNER_COMMAND, "--case", "ha.rolling_restart", "--report-dir", str(directory)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    initial = None
    children = []
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 180
        replaced = False
        pending = b""
        while time.monotonic() < deadline and process.poll() is None:
            for key, _ in selector.select(.1):
                pending += os.read(key.fd, 65536)
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if b"Registering and authenticating" in line:
                        records = ownership(directory)
                        check(len(records) == 1 and len(records[0]["processes"]) == REPLICAS + 2)
                        initial = {(item["pid"], item["start_ticks"]) for item in records[0]["processes"]}
                    if b"Restarted Permesi replica 1/" in line:
                        replaced = True
                        break
            if replaced:
                break
        check(replaced and initial)
        children = freeze_owned_children(process, directory)
        process.kill()
        process.communicate(timeout=10)
        records = ownership(directory)
        check(len(records) == 1 and len(records[0]["processes"]) >= REPLICAS + 1)
        verify_journal(records[0], children, initial)
        check(any(same_process(records[0], item) for item in records[0]["processes"] if (item["pid"], item["start_ticks"]) not in initial))
        recover(directory)
        check(all(not same_process(records[0], item) for item in children))
        no_resources(directory)
    finally:
        try:
            if process.poll() is None:
                children = kill_runner(process, directory)
        finally:
            recover(directory, children)


def kill_runner(process, directory):
    """Always reap our runner, even when independent child discovery fails."""
    try:
        return freeze_owned_children(process, directory)
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def main():
    check(RUNNER.is_file() and PODMAN)
    with tempfile.TemporaryDirectory(prefix="scenario-harness-") as temporary:
        base = Path(temporary)
        fake = base / "failed-service"
        version = command([str(ROOT / "target/debug/permesi"), "--version"]).stdout.decode().strip()
        # Trusted fixture wrapper returns the expected identity, then exits before serving.
        fake.write_text("#!/usr/bin/env python3\nimport sys\nif '--version' in sys.argv: print(" + repr(version) + ")\nelse: sys.exit(1)\n")
        fake.chmod(0o700)
        check(command([*RUNNER_COMMAND, "--list"]).returncode == 0)
        remote_env = os.environ | {"DOCKER_HOST": "tcp://127.0.0.1:1"}
        failed_start(base / "remote", fake, remote_env)
        print("PASS harness.reject_remote_engine")
        directory = base / "partial"
        try:
            check(not failed_start(directory, fake)["cleanup_failures"])
            no_resources(directory)
        finally:
            recover(directory)
        print("PASS harness.partial_startup_cleanup")
        interrupted(base / "interrupt", fake)
        print("PASS harness.repeated_interrupt_cleanup")
        # An unavailable service outlives the total deadline; the report must stay blocked/nonzero.
        timeout = base / "timeout"
        try:
            value = failed_start(timeout, fake, extra=["--readiness-seconds", "90", "--timeout-seconds", "30"])
            check(not value["cleanup_failures"])
            no_resources(timeout)
        finally:
            recover(timeout)
        print("PASS harness.total_deadline_cleanup")
        # A trusted engine shim rejects exactly the first owned removal, then delegates unchanged.
        shim = base / "shim"
        shim.mkdir()
        marker = base / "cleanup-fault"
        wrapper = shim / "podman"
        wrapper.write_text("#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\nmarker=Path(" + repr(str(marker)) + ")\nargs=sys.argv[1:]\nif 'rm' in args and 'container' in args and not marker.exists():\n marker.touch(); sys.exit(1)\nos.execv(" + repr(PODMAN) + ", [" + repr(PODMAN) + "]+args)\n")
        wrapper.chmod(0o700)
        fault = base / "cleanup"
        try:
            result = command([*RUNNER_COMMAND, "--case", "authorization.consent", "--report-dir", str(fault)], env=os.environ | {"PATH": str(shim) + os.pathsep + os.environ['PATH']})
            check(result.returncode != 0 and marker.exists())
            value = report(fault)
            check(all(case['status'] == 'passed' for case in value['cases']) and value['cleanup_failures'])
        finally:
            recover(fault)
        no_resources(fault)
        print("PASS harness.cleanup_failure_is_not_green")
        # Real healthy runs exercise fresh-stack repetitions and simultaneous port/network allocation.
        repeat = base / "repeat"
        try:
            check(command([*RUNNER_COMMAND, "--case", "authorization.consent", "--repeat", "2", "--report-dir", str(repeat)]).returncode == 0)
        finally:
            recover(repeat)
        value = report(repeat)
        check(len(value["cases"]) == 2 and {case["repetition"] for case in value["cases"]} == {1, 2})
        no_resources(repeat)
        print("PASS harness.fresh_repetitions")
        parallel = [base / "parallel-a", base / "parallel-b"]
        processes = [subprocess.Popen([*RUNNER_COMMAND, "--case", "authorization.consent", "--report-dir", str(path)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for path in parallel]
        try:
            for process in processes:
                process.communicate(timeout=240)
                check(process.returncode == 0)
            check(report(parallel[0])["run_id"] != report(parallel[1])["run_id"])
            for path in parallel:
                no_resources(path)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
            for path in parallel:
                recover(path)
        print("PASS harness.concurrent_runs")
        interrupted_restart(base / "restart-recovery")
        print("PASS harness.restart_recovery")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate owned scenario cleanup and recovery")
    parser.add_argument("--replicas", type=int, choices=range(3, 6), default=3)
    REPLICAS = parser.parse_args().replicas
    RUNNER_COMMAND = [str(RUNNER), "--replicas", str(REPLICAS)]
    try:
        main()
    except Exception:
        print("FAIL scenario harness validation")
        raise SystemExit(1) from None
