"""Argv-construction and parsing tests for drkvl.tun (routing-table layer).

No root / no network: the single subprocess chokepoint is ``tun._run`` (and
``tun.ip`` which calls it). Every test replaces ``tun._run`` with a recorder
that captures the exact argv and returns canned ``(rc, stdout, stderr)``, so we
assert what *the module* would issue without ever touching ``ip``/``iptables``.

Not duplicated here (already covered in tests/test_fixes.py):
  - _check_server_ip accept/reject           -> TestTunStructure
  - _backup_resolv / _restore_resolv          -> TestTunResolv
  - block_ipv6 / sysctl fallback              -> TestTunIPv6
  - _route_get-duplicate-removed              -> TestTunStructure
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import tun, paths, storage


class FakeRun:
    """Stand-in for tun._run: records every cmd, returns canned (rc, out, err).

    With an explicit ``ret`` it always returns that tuple (for parsing tests).
    Otherwise it returns (1, '', '') for delete-style commands so the module's
    own cleanup loops (_del_rule_prio, _iptables_del_all) terminate after one
    pass, and (0, '', '') for everything else.
    """

    def __init__(self, ret=None):
        self.calls = []
        self.ret = ret

    def __call__(self, cmd, check=False):
        self.calls.append(list(cmd))
        if self.ret is not None:
            return self.ret
        if "del" in cmd or "-D" in cmd:
            return (1, "", "")
        return (0, "", "")

    @property
    def argv(self):
        return [tuple(c) for c in self.calls]


# ---------------------------------------------------------------------------
# default_route() / route_to() / dev_exists()
# ---------------------------------------------------------------------------

class TestTunRouteQueries(unittest.TestCase):
    def _patch(self, fake):
        return mock.patch.object(tun, "_run", fake)

    def test_default_route_skips_drkvl0_returns_real_nic(self):
        payload = (
            '[{"dst":"default","gateway":"10.10.0.2","dev":"drkvl0"},'
            ' {"dst":"default","gateway":"192.168.1.1","dev":"eth0"}]'
        )
        fake = FakeRun(ret=(0, payload, ""))
        with self._patch(fake):
            r = tun.default_route()
        self.assertEqual(r, {"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"})
        # and it queried via the JSON form
        self.assertIn(("ip", "-j", "route", "show", "default"), fake.argv)

    def test_default_route_none_when_only_drkvl0(self):
        payload = '[{"dst":"default","gateway":"10.10.0.2","dev":"drkvl0"}]'
        with self._patch(FakeRun(ret=(0, payload, ""))):
            self.assertIsNone(tun.default_route())

    def test_default_route_none_on_nonzero_rc(self):
        with self._patch(FakeRun(ret=(2, "", "boom"))):
            self.assertIsNone(tun.default_route())

    def test_default_route_none_on_bad_json(self):
        with self._patch(FakeRun(ret=(0, "{ not json", ""))):
            self.assertIsNone(tun.default_route())

    def test_route_to_returns_first_route_dict(self):
        payload = '[{"dst":"203.0.113.7","dev":"eth0","gateway":"192.168.1.1"},{"dev":"x"}]'
        fake = FakeRun(ret=(0, payload, ""))
        with self._patch(fake):
            r = tun.route_to("203.0.113.7")
        self.assertEqual(r, {"dst": "203.0.113.7", "dev": "eth0", "gateway": "192.168.1.1"})
        self.assertIn(("ip", "-j", "route", "get", "203.0.113.7"), fake.argv)

    def test_route_to_none_on_empty_array(self):
        with self._patch(FakeRun(ret=(0, "[]", ""))):
            self.assertIsNone(tun.route_to("203.0.113.7"))

    def test_route_to_none_on_nonzero_rc(self):
        with self._patch(FakeRun(ret=(1, "", ""))):
            self.assertIsNone(tun.route_to("203.0.113.7"))

    def test_route_to_none_on_bad_json(self):
        with self._patch(FakeRun(ret=(0, "not-json", ""))):
            self.assertIsNone(tun.route_to("203.0.113.7"))

    def test_dev_exists_true_on_rc_zero(self):
        fake = FakeRun(ret=(0, "", ""))
        with self._patch(fake):
            self.assertTrue(tun.dev_exists())
        self.assertIn(("ip", "link", "show", tun.DEV), fake.argv)

    def test_dev_exists_false_on_nonzero_rc(self):
        with self._patch(FakeRun(ret=(1, "", "does not exist"))):
            self.assertFalse(tun.dev_exists())


# ---------------------------------------------------------------------------
# _add_main_rule() / _del_main_rule()
# ---------------------------------------------------------------------------

class TestTunMainRule(unittest.TestCase):
    def test_add_main_rule_issues_from_all_lookup_main_prio9(self):
        fake = FakeRun()
        with mock.patch.object(tun, "_run", fake):
            tun._add_main_rule()
        self.assertIn(
            ("ip", "rule", "add", "from", "all", "lookup", "main", "priority", "9"),
            fake.argv,
        )
        # the add is preceded by an idempotent delete of the same priority
        self.assertIn(("ip", "rule", "del", "priority", "9"), fake.argv)

    def test_del_main_rule_deletes_priority9(self):
        fake = FakeRun()
        with mock.patch.object(tun, "_run", fake):
            tun._del_main_rule()
        self.assertIn(("ip", "rule", "del", "priority", "9"), fake.argv)
        # _del_main_rule must NOT add anything
        self.assertFalse(any(c[:3] == ["ip", "rule", "add"] for c in fake.calls))


# ---------------------------------------------------------------------------
# _setup_direct_table() / _teardown_direct_table()
# ---------------------------------------------------------------------------

class TestTunDirectTable(unittest.TestCase):
    FWMARK_HEX = "0xdd0de"  # hex(tun.DIRECT_FWMARK)

    def test_fwmark_hex_assumption(self):
        self.assertEqual(hex(tun.DIRECT_FWMARK), self.FWMARK_HEX)

    def test_setup_direct_table_route_rule_and_iptables(self):
        fake = FakeRun()
        with mock.patch.object(tun, "_run", fake):
            tun._setup_direct_table("192.168.1.1", "eth0")
        argv = fake.argv

        # default route for the bypass goes into table 100 via the real gw/dev
        self.assertIn(
            ("ip", "route", "add", "default", "via", "192.168.1.1",
             "dev", "eth0", "table", tun.DIRECT_TABLE),
            argv,
        )
        # fwmark policy rule: marked traffic -> table 100 at prio 8
        self.assertIn(
            ("ip", "rule", "add", "fwmark", self.FWMARK_HEX,
             "lookup", tun.DIRECT_TABLE, "priority", tun.DIRECT_RULE_PRIO),
            argv,
        )
        # conntrack mark-save rule installed in mangle/OUTPUT (append)
        save = [
            c for c in fake.calls
            if c[:6] == ["iptables", "-w", "-t", "mangle", "-A", "OUTPUT"]
            and "--save-mark" in c
        ]
        self.assertEqual(len(save), 1)
        self.assertIn(self.FWMARK_HEX, save[0])

    def test_teardown_direct_table_flushes_and_removes(self):
        fake = FakeRun()
        with mock.patch.object(tun, "_run", fake):
            tun._teardown_direct_table()
        argv = fake.argv

        self.assertIn(("ip", "route", "flush", "table", tun.DIRECT_TABLE), argv)
        self.assertIn(("ip", "rule", "del", "priority", tun.DIRECT_RULE_PRIO), argv)
        # mangle rules are removed (delete), never re-appended
        self.assertTrue(any(
            c[:5] == ["iptables", "-w", "-t", "mangle", "-D"] for c in fake.calls))
        self.assertFalse(any(
            c[:5] == ["iptables", "-w", "-t", "mangle", "-A"] for c in fake.calls))


# ---------------------------------------------------------------------------
# snapshot()
# ---------------------------------------------------------------------------

class TestTunSnapshot(unittest.TestCase):
    def test_snapshot_builds_state_and_persists_to_backup(self):
        default = {"dev": "eth0", "gateway": "192.168.1.1"}
        srv_route = {"dst": "203.0.113.7", "dev": "eth0"}
        resolv = {"kind": "none"}

        with mock.patch.object(tun, "default_route", return_value=default), \
             mock.patch.object(tun, "route_to", return_value=srv_route), \
             mock.patch.object(tun, "_backup_resolv", return_value=resolv), \
             mock.patch.object(storage, "write_json") as mock_write:
            snap = tun.snapshot("203.0.113.7")

        # shape of the persisted/returned snapshot
        self.assertEqual(
            set(snap),
            {"default", "server_route", "resolv", "stopped_resolved", "server_ip"},
        )
        self.assertEqual(snap["default"], default)
        self.assertEqual(snap["server_route"], srv_route)
        self.assertEqual(snap["resolv"], resolv)
        self.assertFalse(snap["stopped_resolved"])
        self.assertEqual(snap["server_ip"], "203.0.113.7")

        # persisted to paths.BACKUP, exactly once, with the same dict
        mock_write.assert_called_once()
        args, _ = mock_write.call_args
        self.assertEqual(args[0], paths.BACKUP)
        self.assertEqual(args[1], snap)


if __name__ == "__main__":
    unittest.main()
