"""Tests for clash.py — stopping / restoring competing proxy services.

Pure-unit tests (no root / no network). The systemd and iproute2 boundaries
(`_systemctl`, `_is_active`, `subprocess.run`) are mocked; the assertions
exercise clash.py's own control flow and the argv it constructs.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import clash


class _FakeProc:
    """Minimal stand-in for subprocess.CompletedProcess (only .returncode used)."""
    def __init__(self, returncode: int = 1):
        self.returncode = returncode


class _ClashBase(unittest.TestCase):
    def setUp(self):
        # keep the run clean: clash.info/warn print to std streams.
        for name in ("info", "warn"):
            p = mock.patch.object(clash, name, lambda *a, **k: None)
            p.start()
            self.addCleanup(p.stop)


# ---------------------------------------------------------------------------
# active_units()
# ---------------------------------------------------------------------------

class TestActiveUnits(_ClashBase):
    def test_returns_only_active_subset_in_candidate_order(self):
        active = {"mihomo.service", "clash.service"}
        with mock.patch.object(clash, "_is_active", lambda u: u in active):
            self.assertEqual(
                clash.active_units(),
                ["mihomo.service", "clash.service"],
            )

    def test_empty_when_nothing_active(self):
        with mock.patch.object(clash, "_is_active", lambda u: False):
            self.assertEqual(clash.active_units(), [])

    def test_preserves_candidate_order_not_check_order(self):
        # the last candidate is active alongside the first -> order follows
        # CANDIDATES, not insertion/discovery order.
        active = {"clash-meta.service", "clash-verge.service"}
        with mock.patch.object(clash, "_is_active", lambda u: u in active):
            self.assertEqual(
                clash.active_units(),
                ["clash-verge.service", "clash-meta.service"],
            )


# ---------------------------------------------------------------------------
# stop_active()
# ---------------------------------------------------------------------------

class TestStopActive(_ClashBase):
    def test_stops_each_active_unit_and_returns_them(self):
        active = ["clash-verge.service", "mihomo.service"]
        calls = []

        def fake_sysctl(*args):
            calls.append(args)
            return 0

        with mock.patch.object(clash, "_is_active", lambda u: u in active), \
             mock.patch.object(clash, "_systemctl", fake_sysctl), \
             mock.patch.object(clash, "_clean_leftovers") as clean:
            result = clash.stop_active()

        self.assertEqual(result, active)
        self.assertEqual(calls, [("stop", "clash-verge.service"),
                                 ("stop", "mihomo.service")])
        self.assertTrue(clean.called, "must wipe leftover routing after stop")

    def test_no_units_returns_empty_but_still_cleans_leftovers(self):
        cmds = []

        def fake_run(cmd, *a, **k):
            cmds.append(cmd)
            return _FakeProc(returncode=1)

        sysctl_calls = []

        with mock.patch.object(clash, "_is_active", lambda u: False), \
             mock.patch.object(clash, "_systemctl",
                               lambda *a: sysctl_calls.append(a) or 0), \
             mock.patch.object(clash.subprocess, "run", fake_run):
            result = clash.stop_active()

        self.assertEqual(result, [])
        # nothing was stopped...
        self.assertEqual(sysctl_calls, [])
        # ...but the real _clean_leftovers still ran its iproute2 teardown.
        self.assertIn(["ip", "route", "flush", "table", "2022"], cmds)
        self.assertIn(["ip", "link", "del", "Mihomo"], cmds)


# ---------------------------------------------------------------------------
# start()
# ---------------------------------------------------------------------------

class TestStart(_ClashBase):
    def test_none_makes_no_systemctl_calls(self):
        calls = []
        with mock.patch.object(clash, "_systemctl",
                               lambda *a: calls.append(a) or 0):
            clash.start(None)
        self.assertEqual(calls, [])

    def test_empty_list_makes_no_systemctl_calls(self):
        calls = []
        with mock.patch.object(clash, "_systemctl",
                               lambda *a: calls.append(a) or 0):
            clash.start([])
        self.assertEqual(calls, [])

    def test_starts_each_unit_in_order(self):
        units = ["mihomo.service", "clash.service"]
        calls = []
        with mock.patch.object(clash, "_systemctl",
                               lambda *a: calls.append(a) or 0):
            clash.start(units)
        self.assertEqual(calls, [("start", "mihomo.service"),
                                 ("start", "clash.service")])


# ---------------------------------------------------------------------------
# _clean_leftovers()
# ---------------------------------------------------------------------------

class TestCleanLeftovers(_ClashBase):
    def test_issues_full_iproute2_teardown(self):
        cmds = []

        def fake_run(cmd, *a, **k):
            cmds.append(cmd)
            # non-zero so the per-priority retry loop breaks after one attempt.
            return _FakeProc(returncode=1)

        with mock.patch.object(clash.subprocess, "run", fake_run):
            clash._clean_leftovers()

        # one `ip rule del priority <p>` per configured priority.
        for prio in clash.RULE_PRIOS:
            self.assertIn(["ip", "rule", "del", "priority", prio], cmds)
        self.assertIn(["ip", "route", "flush", "table", clash.TABLE], cmds)
        self.assertIn(["ip", "link", "del", clash.DEV], cmds)

    def test_retries_rule_del_until_failure(self):
        # while `ip rule del` keeps succeeding (rc=0), it is retried for the
        # same priority (rules stack); a failure stops the loop.
        seq = {p: [0, 0, 1] for p in clash.RULE_PRIOS}  # 2 successes then fail
        cmds = []

        def fake_run(cmd, *a, **k):
            cmds.append(cmd)
            if cmd[:3] == ["ip", "rule", "del"]:
                prio = cmd[4]
                return _FakeProc(returncode=seq[prio].pop(0))
            return _FakeProc(returncode=0)

        with mock.patch.object(clash.subprocess, "run", fake_run):
            clash._clean_leftovers()

        first_prio = clash.RULE_PRIOS[0]
        rule_dels = [c for c in cmds
                     if c == ["ip", "rule", "del", "priority", first_prio]]
        self.assertEqual(len(rule_dels), 3,
                         "should retry while rc==0 then stop on the failure")


if __name__ == "__main__":
    unittest.main()
