"""Verify recovery rejects foreign files/processes and reaps a failed observer's runner."""
from pathlib import Path
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

import harness


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = Path(tempfile.mkdtemp(prefix="permesi-scenario-"))
        self.private = temporary.with_name("permesi-scenario-" + str(uuid.uuid4()))
        temporary.rename(self.private)
        self.addCleanup(shutil.rmtree, self.private)
        self.owned = {"private_directory": str(self.private), "run_id": "owned-test-run"}
        (self.private / "owner").write_text(self.owned["run_id"])

    def test_private_marker_and_permissions_are_required_before_cleanup(self):
        self.assertEqual(harness.owned_private_directory(self.owned), self.private)
        protected = self.private / "protected"
        protected.write_text("preserve")
        for mode, marker in ((0o700, "foreign-run"), (0o755, self.owned["run_id"])):
            self.private.chmod(mode)
            (self.private / "owner").write_text(marker)
            with self.assertRaises(RuntimeError):
                harness.owned_private_directory(self.owned)
            with patch.object(harness, "ownership", return_value=[self.owned]), patch.object(harness, "command") as command:
                with self.assertRaises(RuntimeError):
                    harness.recover(Path("unused"))
                command.assert_not_called()
            self.assertEqual(protected.read_text(), "preserve")

    def test_private_symlink_cannot_authorize_file_removal(self):
        link = self.private.parent / ("permesi-scenario-" + str(uuid.uuid4()))
        link.symlink_to(self.private, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(RuntimeError):
            harness.owned_private_directory(self.owned | {"private_directory": str(link)})
        self.assertTrue((self.private / "owner").is_file())
        self.assertTrue(link.is_symlink())

    def test_birth_ticks_and_private_command_path_both_bind_process_ownership(self):
        process = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)", str(self.private)])
        self.addCleanup(self.reap, process)
        ticks = int((Path("/proc") / str(process.pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])
        identity = {"pid": process.pid, "start_ticks": ticks}
        self.assertTrue(harness.same_process(self.owned, identity))
        self.assertFalse(harness.same_process(self.owned, identity | {"start_ticks": ticks + 1}))
        self.assertFalse(harness.same_process(self.owned | {"private_directory": "/unrelated-private-path"}, identity))
        harness.kill_owned_process(self.owned, identity | {"start_ticks": ticks + 1})
        self.assertIsNone(process.poll())
        harness.kill_owned_process(self.owned, identity)
        self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)

    def test_recovery_pins_identity_before_validation_and_never_signals_a_numeric_pid(self):
        events = []
        identity = {"pid": 123, "start_ticks": 456}
        for exited in (False, True):
            events.clear()

            def send(descriptor, sig):
                events.append(("signal", descriptor, sig))
                if exited:
                    raise ProcessLookupError()

            with (
                patch.object(os, "pidfd_open", side_effect=lambda pid: events.append(("open", pid)) or 42),
                patch.object(harness, "same_process", side_effect=lambda *args: events.append(("verify",)) or True),
                patch.object(signal, "pidfd_send_signal", side_effect=send),
                patch.object(os, "close", side_effect=lambda fd: events.append(("close", fd))),
                patch.object(os, "kill") as numeric_kill,
            ):
                harness.kill_owned_process(self.owned, identity)
                numeric_kill.assert_not_called()
            self.assertEqual(events, [("open", 123), ("verify",), ("signal", 42, signal.SIGKILL), ("close", 42)])

    def test_missing_journal_child_cannot_be_hidden_by_out_of_band_cleanup(self):
        initial = {(1, 10)}
        replacement = {"pid": 2, "start_ticks": 20}
        other = {"pid": 3, "start_ticks": 30}
        harness.verify_journal({"processes": [replacement, other]}, [replacement, other], initial)
        with self.assertRaises(RuntimeError):
            harness.verify_journal({"processes": [replacement]}, [replacement, other], initial)
        with self.assertRaises(RuntimeError):
            harness.verify_journal({"processes": [{"pid": 1, "start_ticks": 10}]}, [{"pid": 1, "start_ticks": 10}], initial)

    def test_failed_child_observation_still_kills_and_reaps_runner(self):
        process = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
        self.addCleanup(self.reap, process)
        with patch.object(harness, "freeze_owned_children", side_effect=RuntimeError("observation failed")):
            with self.assertRaisesRegex(RuntimeError, "observation failed"):
                harness.kill_runner(process, self.private)
        self.assertIsNotNone(process.poll())

    @staticmethod
    def reap(process):
        """Never leave a test-owned child running when an ownership assertion fails."""
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
