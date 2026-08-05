"""Tests for parallel profile speed-testing (drkvl/speed.py). subprocess mocked."""
import io
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import speed, display, cli, storage, tun
from drkvl.link import Vless
from drkvl.speed import Result

V = Vless(uuid="u", host="h.example.com", port=443)


def _cp(rc, out=""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=out, stderr="")


class TestCurl(unittest.TestCase):
    def test_ok_parses_latency_ms(self):
        with mock.patch.object(speed.subprocess, "run", return_value=_cp(0, "0.1234")):
            status, ms = speed._curl(1090)
        self.assertEqual(status, "ok")
        self.assertAlmostEqual(ms, 123.4, places=1)

    def test_curl_argv_uses_socks_and_timeout(self):
        with mock.patch.object(speed.subprocess, "run", return_value=_cp(0, "0.1")) as m:
            speed._curl(1095)
        argv = m.call_args.args[0]
        self.assertIn("-x", argv)
        # socks5h:// -> DNS resolved through the proxy (the tunnel), not locally
        self.assertIn("socks5h://127.0.0.1:1095", argv)
        # time_starttransfer = real round-trip to the server, not just local handshake
        self.assertIn("%{time_starttransfer}", argv)
        self.assertIn("--connect-timeout", argv)
        self.assertIn(speed.PING_URL, argv)

    def test_timeout_returncode_28(self):
        with mock.patch.object(speed.subprocess, "run", return_value=_cp(28)):
            self.assertEqual(speed._curl(1090), ("timeout", None))

    def test_other_returncode_is_error(self):
        with mock.patch.object(speed.subprocess, "run", return_value=_cp(7)):
            self.assertEqual(speed._curl(1090), ("error", None))

    def test_subprocess_timeout_is_error(self):
        with mock.patch.object(speed.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("curl", 5)):
            self.assertEqual(speed._curl(1090), ("error", None))

    def test_curl_missing_is_error(self):
        with mock.patch.object(speed.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(speed._curl(1090), ("error", None))

    def test_unparseable_output_is_error(self):
        with mock.patch.object(speed.subprocess, "run", return_value=_cp(0, "")):
            self.assertEqual(speed._curl(1090), ("error", None))


class TestCurlDirect(unittest.TestCase):
    def test_direct_has_no_proxy_arg(self):
        with mock.patch.object(speed.subprocess, "run", return_value=_cp(0, "0.05")) as m:
            status, ms = speed.curl_direct()
        self.assertEqual(status, "ok")
        self.assertAlmostEqual(ms, 50.0, places=1)
        argv = m.call_args.args[0]
        self.assertNotIn("-x", argv)          # goes through the default route (the TUN)
        self.assertIn("%{time_starttransfer}", argv)
        self.assertIn(speed.PING_URL, argv)

    def test_direct_timeout(self):
        with mock.patch.object(speed.subprocess, "run", return_value=_cp(28)):
            self.assertEqual(speed.curl_direct()[0], "timeout")

    def test_direct_error(self):
        with mock.patch.object(speed.subprocess, "run", side_effect=OSError):
            self.assertEqual(speed.curl_direct(), ("error", None))


class TestTestOne(unittest.TestCase):
    def test_error_when_xray_does_not_start(self):
        with mock.patch.object(speed, "_run_xray", return_value=None):
            r = speed._test_one(0, "p", V)
        self.assertEqual(r.status, "error")
        self.assertIsNone(r.latency_ms)
        self.assertEqual(r.host, "h.example.com")
        self.assertEqual(r.port, 443)

    def test_ok_path_kills_xray(self):
        fake = mock.MagicMock()
        with mock.patch.object(speed, "_run_xray", return_value=fake), \
             mock.patch.object(speed, "_curl", return_value=("ok", 88.0)), \
             mock.patch.object(speed, "_kill") as kill:
            r = speed._test_one(2, "p", V)
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.latency_ms, 88.0)
        kill.assert_called_once_with(fake)

    def test_uses_distinct_socks_port_per_index(self):
        seen = {}

        def fake_run_xray(cfg_path, socks_port):
            seen["port"] = socks_port
            return None

        with mock.patch.object(speed, "_run_xray", side_effect=fake_run_xray):
            speed._test_one(7, "p", V)
        self.assertEqual(seen["port"], speed.BASE_PORT + 7)

    def test_builds_geo_free_config(self):
        # the throwaway xray gets no XRAY_LOCATION_ASSET, so its config must
        # not reference any geoip/geosite .dat (else xray fails to start)
        kw = {}
        real_build = speed.config.build

        def capture(v, **kwargs):
            kw.update(kwargs)
            return real_build(v, **kwargs)

        with mock.patch.object(speed.config, "build", side_effect=capture), \
             mock.patch.object(speed, "_run_xray", return_value=None):
            speed._test_one(0, "p", V)
        self.assertFalse(kw.get("geo", True), "speed config must pass geo=False")
        self.assertFalse(kw.get("bypass", True),
                         "speed config must pass bypass=False (no custom bypass lists)")


class TestRunXrayDeath(unittest.TestCase):
    def test_returns_none_fast_when_process_dies(self):
        dead = mock.MagicMock()
        dead.poll.return_value = 23          # xray exited immediately
        with mock.patch.object(speed.subprocess, "Popen", return_value=dead), \
             mock.patch.object(speed, "port_open", return_value=False), \
             mock.patch.object(speed, "_kill") as kill:
            self.assertIsNone(speed._run_xray("cfg", 1090))
        kill.assert_called_once_with(dead)

    def test_popen_oserror_returns_none(self):
        with mock.patch.object(speed.subprocess, "Popen", side_effect=OSError):
            self.assertIsNone(speed._run_xray("cfg", 1090))


class TestKill(unittest.TestCase):
    def test_sigkill_branch_reaps(self):
        p = mock.MagicMock()
        p.wait.side_effect = [subprocess.TimeoutExpired("xray", 2), None]
        speed._kill(p)
        p.terminate.assert_called_once()
        p.kill.assert_called_once()
        self.assertEqual(p.wait.call_count, 2)   # waited again after kill -> no zombie


class TestRunTestsSorting(unittest.TestCase):
    def test_sorted_ok_by_latency_then_failures(self):
        profiles = [("a", V), ("b", V), ("c", V), ("d", V)]
        canned = {
            0: Result("a", "h", 443, 200.0, "ok"),
            1: Result("b", "h", 443, None, "timeout"),
            2: Result("c", "h", 443, 50.0, "ok"),
            3: Result("d", "h", 443, None, "error"),
        }
        with mock.patch.object(speed, "_test_one",
                               side_effect=lambda i, n, v: canned[i]):
            results = speed.run_tests(profiles)
        self.assertEqual([r.name for r in results], ["c", "a", "b", "d"])

    def test_exception_becomes_error_result(self):
        with mock.patch.object(speed, "_test_one", side_effect=RuntimeError("boom")):
            results = speed.run_tests([("a", V)])
        self.assertEqual(results[0].status, "error")


class TestSpeedTable(unittest.TestCase):
    def test_table_has_header_and_rows(self):
        results = [
            Result("fast", "a.com", 443, 50.0, "ok"),
            Result("slow", "b.com", 8443, None, "timeout"),
        ]
        lines = display.speed_table(results)
        self.assertIn("profile", lines[0])
        self.assertIn("latency", lines[0])
        self.assertEqual(len(lines), 3)
        self.assertIn("fast", lines[1])
        self.assertIn("50ms", lines[1])
        self.assertIn("a.com", lines[1])
        self.assertIn("-", lines[2])      # no latency for timeout

    def test_color_flag_wraps_status(self):
        results = [Result("p", "h", 443, 10.0, "ok")]
        plain = display.speed_table(results, color=False)[1]
        colored = display.speed_table(results, color=True)[1]
        self.assertNotIn("\033[", plain)
        self.assertIn("\033[", colored)


class TestCliIntegration(unittest.TestCase):
    def test_cmd_speedtest_prints_table(self):
        res = [Result("a", "h.com", 443, 12.0, "ok")]
        with mock.patch.object(cli.storage, "list_all", return_value=[("a", V)]), \
             mock.patch.object(cli, "have", return_value=True), \
             mock.patch.object(cli.speed, "run_tests", return_value=res), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            rc = cli.cmd_speedtest(None)
        self.assertEqual(rc, 0)
        self.assertIn("a", out.getvalue())
        self.assertIn("ok", out.getvalue())

    def test_cmd_speedtest_no_profiles(self):
        with mock.patch.object(cli.storage, "list_all", return_value=[]), \
             mock.patch.object(cli, "err"):
            self.assertEqual(cli.cmd_speedtest(None), 1)

    def _up_args(self):
        return types.SimpleNamespace(fallback=True, name=None, no_bypass=True)

    def test_fallback_no_responder_errors(self):
        res = [Result("a", "h", 443, None, "error")]
        with mock.patch.object(cli, "_require_root", return_value=True), \
             mock.patch.object(cli.proc, "xray_running", return_value=False), \
             mock.patch.object(cli.proc, "tun2socks_running", return_value=False), \
             mock.patch.object(cli, "port_open", return_value=False), \
             mock.patch.object(cli.storage, "list_all", return_value=[("a", V)]), \
             mock.patch.object(cli, "have", return_value=True), \
             mock.patch.object(cli.speed, "run_tests", return_value=res), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = cli.cmd_up(self._up_args())
        self.assertEqual(rc, 1)

    def test_fallback_orders_candidates_fastest_first(self):
        # run_tests returns fastest-first (sorted); cmd_up must hand ALL
        # responders to _select_working in that order (real fallback, not just one)
        res = [Result("fast", "h", 443, 30.0, "ok"),
               Result("slow", "h", 443, 200.0, "ok"),
               Result("dead", "h", 443, None, "error")]
        captured = {}

        def fake_select(candidates, attempt):
            captured["names"] = [n for n, _ in candidates]
            return None

        with mock.patch.object(cli, "_require_root", return_value=True), \
             mock.patch.object(cli.proc, "xray_running", return_value=False), \
             mock.patch.object(cli.proc, "tun2socks_running", return_value=False), \
             mock.patch.object(cli, "port_open", return_value=False), \
             mock.patch.object(cli.storage, "list_all", return_value=[("slow", V), ("fast", V), ("dead", V)]), \
             mock.patch.object(cli, "have", return_value=True), \
             mock.patch.object(cli.speed, "run_tests", return_value=res), \
             mock.patch.object(cli.storage, "load", side_effect=lambda n: (n, V)), \
             mock.patch.object(cli.tun, "default_route", return_value={"dev": "eth0", "gateway": "1.1.1.1"}), \
             mock.patch.object(cli, "_select_working", side_effect=fake_select), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            cli.cmd_up(self._up_args())
        # only responders, fastest first, dead excluded
        self.assertEqual(captured.get("names"), ["fast", "slow"])


class TestFullTest(unittest.TestCase):
    def test_full_success_and_teardown(self):
        with mock.patch.object(cli, "resolve_host", return_value="9.9.9.9"), \
             mock.patch.object(cli.config, "build", return_value={}), \
             mock.patch.object(cli.config, "dump"), \
             mock.patch.object(cli.ownership, "ensure_dirs"), \
             mock.patch.object(cli.ownership, "chown_user"), \
             mock.patch.object(cli.proc, "start_xray"), \
             mock.patch.object(cli.proc, "stop_xray") as stopx, \
             mock.patch.object(cli, "_await_socks", return_value=True), \
             mock.patch.object(cli.tun, "apply_up"), \
             mock.patch.object(cli.tun, "apply_down") as adown, \
             mock.patch.object(cli.tun, "load_snapshot", return_value={}), \
             mock.patch.object(cli.speed, "curl_direct", return_value=("ok", 42.0)):
            r = cli._full_test_one("p", V, True, None)
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.latency_ms, 42.0)
        stopx.assert_called()       # xray torn down
        adown.assert_called()       # routes torn down

    def test_full_xray_fail_skips_applyup(self):
        with mock.patch.object(cli, "resolve_host", return_value="9.9.9.9"), \
             mock.patch.object(cli.config, "build", return_value={}), \
             mock.patch.object(cli.config, "dump"), \
             mock.patch.object(cli.ownership, "ensure_dirs"), \
             mock.patch.object(cli.ownership, "chown_user"), \
             mock.patch.object(cli.proc, "start_xray", side_effect=RuntimeError("boom")), \
             mock.patch.object(cli.tun, "apply_up") as aup:
            r = cli._full_test_one("p", V, True, None)
        self.assertEqual(r.status, "error")
        aup.assert_not_called()

    def test_full_applyup_fail_tears_down(self):
        with mock.patch.object(cli, "resolve_host", return_value="9.9.9.9"), \
             mock.patch.object(cli.config, "build", return_value={}), \
             mock.patch.object(cli.config, "dump"), \
             mock.patch.object(cli.ownership, "ensure_dirs"), \
             mock.patch.object(cli.ownership, "chown_user"), \
             mock.patch.object(cli.proc, "start_xray"), \
             mock.patch.object(cli.proc, "stop_xray") as stopx, \
             mock.patch.object(cli, "_await_socks", return_value=True), \
             mock.patch.object(cli.tun, "apply_up", side_effect=RuntimeError("route")), \
             mock.patch.object(cli.tun, "apply_down") as adown, \
             mock.patch.object(cli.tun, "load_snapshot", return_value={}):
            r = cli._full_test_one("p", V, True, None)
        self.assertEqual(r.status, "error")
        stopx.assert_called()
        adown.assert_called()

    def test_full_passes_resolved_server_ip_to_config_build(self):
        # so xray's dns.hosts can pin the server's domain — resolving it
        # would otherwise require the `proxy` outbound it's dialing (deadlock).
        with mock.patch.object(cli, "resolve_host", return_value="9.9.9.9"), \
             mock.patch.object(cli.config, "build", return_value={}) as build, \
             mock.patch.object(cli.config, "dump"), \
             mock.patch.object(cli.ownership, "ensure_dirs"), \
             mock.patch.object(cli.ownership, "chown_user"), \
             mock.patch.object(cli.proc, "start_xray"), \
             mock.patch.object(cli.proc, "stop_xray"), \
             mock.patch.object(cli, "_await_socks", return_value=True), \
             mock.patch.object(cli.tun, "apply_up"), \
             mock.patch.object(cli.tun, "apply_down"), \
             mock.patch.object(cli.tun, "load_snapshot", return_value={}), \
             mock.patch.object(cli.speed, "curl_direct", return_value=("ok", 42.0)):
            cli._full_test_one("p", V, True, None)
        self.assertEqual(build.call_args.kwargs.get("server_ip"), "9.9.9.9")


class TestAttemptServerIpWiring(unittest.TestCase):
    def test_attempt_passes_resolved_server_ip_to_config_build(self):
        # same deadlock as _full_test_one: `up`'s real xray also dials the
        # server domain through `proxy`, so it needs the dns.hosts pin too.
        with mock.patch.object(cli, "resolve_host", return_value="9.9.9.9"), \
             mock.patch.object(cli.config, "build", return_value={}) as build, \
             mock.patch.object(cli.config, "dump"), \
             mock.patch.object(cli.ownership, "ensure_dirs"), \
             mock.patch.object(cli.ownership, "chown_user"), \
             mock.patch.object(cli.proc, "start_xray"), \
             mock.patch.object(cli, "_await_socks", return_value=True):
            r = cli._attempt("p", V, True, None, 30)
        self.assertEqual(r, "9.9.9.9")
        self.assertEqual(build.call_args.kwargs.get("server_ip"), "9.9.9.9")

    def test_speedtest_full_requires_root(self):
        args = types.SimpleNamespace(full=True)
        with mock.patch.object(cli.storage, "list_all", return_value=[("a", V)]), \
             mock.patch.object(cli, "have", return_value=True), \
             mock.patch.object(cli, "_require_root", return_value=False):
            self.assertEqual(cli.cmd_speedtest(args), 1)


if __name__ == "__main__":
    unittest.main()
