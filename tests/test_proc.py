"""Lifecycle tests for drkvl.proc — process start/stop with real (harmless)
processes, no root and no network.

These complement TestProcFixes in tests/test_fixes.py (which covers
_comm/_alive, the tun2socks loglevel fallback and the O_NOFOLLOW log refusal)
by exercising the real _start/_stop lifecycle and the pidfile bookkeeping.

Every spawned process is recorded and SIGKILL'd + reaped in tearDown so no
stray children leak out of the test run.
"""
import sys; from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
import shutil
import signal
import tempfile
import unittest
import warnings
from unittest import mock

from drkvl import proc, paths


# ---------------------------------------------------------------------------
# _read_pid
# ---------------------------------------------------------------------------

class TestReadPid(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.mkdtemp()
        self.p = Path(self._d) / "x.pid"

    def tearDown(self):
        shutil.rmtree(self._d, ignore_errors=True)

    def test_valid_pidfile_parsed(self):
        self.p.write_text("424242\n")
        self.assertEqual(proc._read_pid(self.p), 424242)

    def test_malformed_pidfile_returns_none(self):
        self.p.write_text("not-a-pid")
        self.assertIsNone(proc._read_pid(self.p))

    def test_missing_pidfile_returns_none(self):
        self.assertFalse(self.p.exists())
        self.assertIsNone(proc._read_pid(self.p))


# ---------------------------------------------------------------------------
# _start / _stop lifecycle + running queries
# ---------------------------------------------------------------------------

class TestProcLifecycle(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.mkdtemp()
        self.tmp = Path(self._d)
        self.pidf = self.tmp / "x.pid"
        self.logf = self.tmp / "x.log"
        self._pids = []
        # keep everything off the real ~/.config/drkvl dir
        self._patchers = [
            mock.patch.object(paths, "HOME", self.tmp),
            mock.patch.object(proc, "XRAY_PID", self.tmp / "xray.pid"),
            mock.patch.object(proc, "TUN2SOCKS_PID", self.tmp / "tun2socks.pid"),
            mock.patch.object(proc, "XRAY_LOG", self.tmp / "xray.log"),
            mock.patch.object(proc, "TUN2SOCKS_LOG", self.tmp / "tun2socks.log"),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for pid in self._pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self._reap(pid)
        for p in reversed(self._patchers):
            p.stop()
        shutil.rmtree(self._d, ignore_errors=True)

    # -- helpers ----------------------------------------------------------
    def _start_proc(self, name, argv, pidf=None, logf=None):
        """Call proc._start, record the pid for cleanup, and swallow the
        ResourceWarning Python emits when _start's internal (still-running)
        Popen object is garbage-collected."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            pid = proc._start(name, argv, pidf or self.pidf, logf or self.logf)
        self._pids.append(pid)
        return pid

    def _reap(self, pid):
        # this test process is the parent of the spawned child, so after the
        # child dies it lingers as a zombie until we wait() on it; a real
        # short-lived drkvl CLI exits and lets init reap instead.
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    # -- tests ------------------------------------------------------------
    def test_start_writes_pidfile_and_process_is_alive(self):
        pid = self._start_proc("sleep", ["sleep", "30"])
        self.assertTrue(pid > 0)
        self.assertTrue(self.pidf.exists())
        self.assertEqual(self.pidf.read_text().strip(), str(pid))
        # alive AND really the process we started (comm matches "sleep")
        self.assertTrue(proc._alive(pid, "sleep"))

    def test_stop_terminates_process_and_removes_pidfile(self):
        pid = self._start_proc("sleep", ["sleep", "30"])
        self.assertTrue(proc._alive(pid, "sleep"))

        killed = proc._stop(self.pidf, "sleep")
        self.assertTrue(killed, "_stop should report it signalled a process")
        self.assertFalse(self.pidf.exists(), "_stop must remove the pidfile")

        self._reap(pid)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)  # truly gone, not merely SIGTERM-ignored

    def test_start_raises_when_already_running(self):
        pid = self._start_proc("sleep", ["sleep", "30"])
        with self.assertRaises(RuntimeError) as cm:
            # second start sees a live, name-matching pidfile
            proc._start("sleep", ["sleep", "30"], self.pidf, self.logf)
        self.assertIn("already running", str(cm.exception))
        # the original process and its pidfile are untouched
        self.assertEqual(self.pidf.read_text().strip(), str(pid))

    def test_start_raises_for_missing_binary(self):
        with self.assertRaises(RuntimeError) as cm:
            proc._start("ghost", ["drkvl_no_such_binary_zzz", "run"],
                        self.pidf, self.logf)
        self.assertIn("not found in PATH", str(cm.exception))
        self.assertFalse(self.pidf.exists())

    def test_start_raises_and_writes_no_pidfile_when_process_exits_immediately(self):
        # "true" exits 0 right away; poll() reaps it so there is no zombie.
        with self.assertRaises(RuntimeError) as cm:
            proc._start("true", ["true"], self.pidf, self.logf)
        self.assertIn("exited immediately", str(cm.exception))
        self.assertFalse(self.pidf.exists(),
                         "no pidfile may be written for a process that died")

    def test_stop_returns_false_when_pidfile_missing(self):
        self.assertFalse(self.pidf.exists())
        self.assertFalse(proc._stop(self.pidf, "sleep"))

    def test_xray_running_false_when_pidfile_missing(self):
        self.assertFalse(proc.XRAY_PID.exists())
        self.assertFalse(proc.xray_running())

    def test_tun2socks_running_false_when_pidfile_missing(self):
        self.assertFalse(proc.TUN2SOCKS_PID.exists())
        self.assertFalse(proc.tun2socks_running())


if __name__ == "__main__":
    unittest.main()
