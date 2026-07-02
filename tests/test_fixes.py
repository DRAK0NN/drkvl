"""Tests for fixes from the security + code-quality reviews.

Pure-unit tests (no root / no network) — each was written before its fix
following TDD. Live routing/IPv6/firewall behaviour can't be unit-tested in
this sandbox; those fixes are exercised by argv-construction tests instead.
"""
import inspect
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import (link, profile, config, stats, proc, geo, util, tun, cli,
                   tui, paths, ownership, storage, state, display, bypass)
from drkvl.link import Vless


# ---------------------------------------------------------------------------
# link.py
# ---------------------------------------------------------------------------

class TestLinkParserFixes(unittest.TestCase):
    def test_query_value_decoded_once_not_twice(self):
        # parse_qs already percent-decodes; g() must not unquote a second time.
        # %252Fws -> (parse_qs) -> %2Fws  ; a second unquote would wrongly give /ws
        v = link.parse("vless://uid@h:443?type=ws&path=%252Fws%2520x#n")
        self.assertEqual(v.path, "%2Fws%20x")

    def test_query_value_single_percent_preserved(self):
        v = link.parse("vless://uid@h:443?type=ws&path=%2Fa%2520b#n")
        self.assertEqual(v.path, "/a%20b")

    def test_blank_type_defaults_to_tcp(self):
        v = link.parse("vless://uid@h:443?type=#x")
        self.assertEqual(v.network, "tcp")

    def test_absent_type_still_tcp(self):
        v = link.parse("vless://uid@h:443#x")
        self.assertEqual(v.network, "tcp")

    def test_non_numeric_port_friendly_message(self):
        with self.assertRaises(ValueError) as cm:
            link.parse("vless://uid@h:abc#x")
        msg = str(cm.exception).lower()
        self.assertNotIn("cast", msg)            # not urllib's raw wording
        self.assertIn("port", msg)

    def test_port_upper_bound_reachable(self):
        # urlparse rejects >65535 itself; confirm we still raise a ValueError
        with self.assertRaises(ValueError):
            link.parse("vless://uid@h:99999#x")


# ---------------------------------------------------------------------------
# profile.py
# ---------------------------------------------------------------------------

class TestProfileFixes(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = (paths.HOME, paths.PROFILES, paths.DEFAULT)
        paths.HOME = Path(self._tmp)
        paths.PROFILES = paths.HOME / "profiles"
        paths.DEFAULT = paths.HOME / "default"

    def tearDown(self):
        paths.HOME, paths.PROFILES, paths.DEFAULT = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_digit_name_loadable_by_name(self):
        # a profile whose name is all-digits must be reachable by name,
        # not shadowed by index lookup.
        profile.save(link.parse("vless://uid@h:443#a"))   # index 0
        profile.save(link.parse("vless://uid@h:444#b"), name="5")  # name "5"
        n, v = profile.load("5")
        self.assertEqual(n, "5")
        self.assertEqual(v.port, 444)

    def test_index_still_works(self):
        profile.save(link.parse("vless://uid@h:443#a"))
        profile.save(link.parse("vless://uid@h:444#b"))
        _, v = profile.load("1")
        self.assertEqual(v.port, 444)

    def test_read_json_warns_on_corrupt_not_missing(self):
        bad = paths.HOME / "active.json"
        paths.HOME.mkdir(parents=True, exist_ok=True)
        bad.write_text("{ not json")
        with mock.patch("drkvl.util.warn") as w:
            self.assertIsNone(profile.read_json(bad))
        self.assertTrue(w.called, "corrupt json should warn")
        # missing file must NOT warn
        with mock.patch("drkvl.util.warn") as w2:
            self.assertIsNone(profile.read_json(paths.HOME / "nope.json"))
        self.assertFalse(w2.called, "missing file must be silent")

    def test_write_json_default_mode_0600(self):
        p = paths.HOME / "x.json"
        profile.write_json(p, {"a": 1})
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_ensure_dirs_private(self):
        profile.ensure_dirs()
        self.assertEqual(stat.S_IMODE(os.stat(paths.HOME).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(paths.PROFILES).st_mode), 0o700)

    def test_list_all_warns_and_skips_corrupt(self):
        profile.save(link.parse("vless://uid@h:443#good"))
        (paths.PROFILES / "bad.json").write_text("{oops")
        with mock.patch("drkvl.util.warn") as w:
            items = profile.list_all()
        names = [n for n, _ in items]
        self.assertIn("good", names)
        self.assertNotIn("bad", names)
        self.assertTrue(w.called)

    def test_write_json_refuses_symlink(self):
        # O_NOFOLLOW: writing through a planted symlink must fail, not follow.
        target = paths.HOME / "victim"
        paths.HOME.mkdir(parents=True, exist_ok=True)
        target.write_text("important")
        link_path = paths.HOME / "active.json"
        os.symlink(target, link_path)
        with self.assertRaises(OSError):
            profile.write_json(link_path, {"x": 1})
        self.assertEqual(target.read_text(), "important")


# ---------------------------------------------------------------------------
# config.py + stats.py
# ---------------------------------------------------------------------------

class TestConfigStatsFixes(unittest.TestCase):
    def test_dump_refuses_symlink(self):
        d = tempfile.mkdtemp()
        try:
            victim = Path(d) / "victim"
            victim.write_text("important")
            sl = Path(d) / "cfg.json"
            os.symlink(victim, sl)
            with self.assertRaises(OSError):
                config.dump({"a": 1}, sl)
            self.assertEqual(victim.read_text(), "important")
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def test_build_drops_dead_bind_interface(self):
        with self.assertRaises(TypeError):
            config.build(Vless(uuid="u", host="h", port=443),
                         bind_interface="eth0")

    def test_stats_api_uses_config_port(self):
        self.assertEqual(stats.API, f"127.0.0.1:{config.API_PORT}")

    def test_geo_false_strips_all_geo_refs(self):
        # speed-test configs must not reference geoip/geosite (no .dat needed)
        cfg = config.build(Vless(uuid="u", host="h", port=443),
                           bypass=False, geo=False)
        blob = json.dumps(cfg)
        self.assertNotIn("geoip", blob)
        self.assertNotIn("geosite", blob)

    def test_default_keeps_geoip_private(self):
        cfg = config.build(Vless(uuid="u", host="h", port=443))
        self.assertIn("geoip:private", json.dumps(cfg))

    def _direct_rule(self, cfg, marker):
        # return the 'direct' rule's list that contains ``marker`` (skips the
        # geoip:private rule, which is also direct+ip)
        key = "domain" if marker.startswith("geosite") else "ip"
        for r in cfg["routing"]["rules"]:
            if r.get("outboundTag") == "direct" and marker in r.get(key, []):
                return r[key]
        return None

    def test_bypass_merges_custom_domains_and_ips(self):
        with mock.patch.object(bypass, "load_domains", return_value=["avito.st", "2gis.com"]), \
             mock.patch.object(bypass, "load_ips", return_value=["1.2.3.0/24", "5.6.7.8"]):
            cfg = config.build(Vless(uuid="u", host="h", port=443), bypass=True)
        domains = self._direct_rule(cfg, "geosite:category-ru")
        self.assertIn("domain:avito.st", domains)
        self.assertIn("domain:2gis.com", domains)
        ips = self._direct_rule(cfg, "geoip:ru")
        self.assertIn("1.2.3.0/24", ips)
        self.assertIn("5.6.7.8", ips)

    def test_bypass_without_custom_is_geo_only(self):
        with mock.patch.object(bypass, "load_domains", return_value=[]), \
             mock.patch.object(bypass, "load_ips", return_value=[]):
            cfg = config.build(Vless(uuid="u", host="h", port=443), bypass=True)
        self.assertEqual(self._direct_rule(cfg, "geosite:category-ru"), ["geosite:category-ru"])
        self.assertEqual(self._direct_rule(cfg, "geoip:ru"), ["geoip:ru"])

    # bug 2: dns-out must carry the direct fwmark so DNS egresses via the side
    # table instead of looping back through the tun
    def _dns_out(self, cfg):
        return [o for o in cfg["outbounds"] if o["tag"] == "dns-out"][0]

    def test_dns_out_has_direct_mark(self):
        cfg = config.build(Vless(uuid="u", host="h", port=443), direct_mark=0xDD0DE)
        dns = self._dns_out(cfg)
        self.assertEqual(dns.get("streamSettings", {}).get("sockopt", {}).get("mark"),
                         0xDD0DE)

    def test_dns_out_no_mark_when_zero(self):
        cfg = config.build(Vless(uuid="u", host="h", port=443), direct_mark=0)
        self.assertNotIn("streamSettings", self._dns_out(cfg))

    # bug 3: speed-test configs (bypass=False) must NOT load the custom bypass
    # lists (10k+ IPs) — that made every temp xray fail
    def test_bypass_false_does_not_load_lists(self):
        with mock.patch.object(bypass, "load_domains") as ld, \
             mock.patch.object(bypass, "load_ips") as li:
            cfg = config.build(Vless(uuid="u", host="h", port=443),
                               bypass=False, geo=False)
        ld.assert_not_called()
        li.assert_not_called()
        blob = json.dumps(cfg)
        self.assertNotIn("geoip:ru", blob)
        self.assertNotIn("geosite", blob)


# ---------------------------------------------------------------------------
# proc.py
# ---------------------------------------------------------------------------

class TestProcFixes(unittest.TestCase):
    def test_comm_self_not_none(self):
        self.assertIsNotNone(proc._comm(os.getpid()))

    def test_alive_true_with_matching_name(self):
        self.assertTrue(proc._alive(os.getpid(), proc._comm(os.getpid())))

    def test_alive_false_on_name_mismatch(self):
        # PID alive but a different process now owns it -> not ours.
        self.assertFalse(proc._alive(os.getpid(), "xx-not-this-proc-xx"))

    def test_alive_true_without_name(self):
        self.assertTrue(proc._alive(os.getpid()))

    def test_tun2socks_surfaces_non_loglevel_error(self):
        with mock.patch.object(proc, "_start",
                               side_effect=RuntimeError("tun2socks not found in PATH")) as m:
            with self.assertRaises(RuntimeError):
                proc.start_tun2socks("dev", 1080)
        self.assertEqual(m.call_count, 1, "must not retry a non-loglevel failure")

    def test_tun2socks_retries_on_loglevel_rejection(self):
        d = tempfile.mkdtemp()
        try:
            logp = Path(d) / "t2s.log"
            logp.write_text('unrecognized level: "warn"')
            with mock.patch.object(proc, "TUN2SOCKS_LOG", logp), \
                 mock.patch.object(proc, "_start",
                                   side_effect=[RuntimeError("tun2socks exited immediately (see x)"), 4242]) as m:
                pid = proc.start_tun2socks("dev", 1080)
            self.assertEqual(pid, 4242)
            self.assertEqual(m.call_count, 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_tun2socks_no_retry_on_real_crash(self):
        d = tempfile.mkdtemp()
        try:
            logp = Path(d) / "t2s.log"
            logp.write_text("create tun: operation not permitted")
            with mock.patch.object(proc, "TUN2SOCKS_LOG", logp), \
                 mock.patch.object(proc, "_start",
                                   side_effect=RuntimeError("tun2socks exited immediately (see x)")) as m:
                with self.assertRaises(RuntimeError):
                    proc.start_tun2socks("dev", 1080)
            self.assertEqual(m.call_count, 1, "real crash must not be retried/masked")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_start_refuses_symlink_log(self):
        d = tempfile.mkdtemp()
        try:
            victim = Path(d) / "victim"
            victim.write_text("keep")
            logsl = Path(d) / "x.log"
            os.symlink(victim, logsl)
            pidf = Path(d) / "x.pid"
            with mock.patch.object(paths, "HOME", Path(d)):
                with self.assertRaises(OSError):
                    proc._start("t", ["true"], pidf, logsl)
            self.assertEqual(victim.read_text(), "keep")
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# geo.py + util.py
# ---------------------------------------------------------------------------

class TestGeoUtilFixes(unittest.TestCase):
    def test_geo_download_passes_timeout(self):
        d = tempfile.mkdtemp()
        try:
            uo = mock.MagicMock()
            uo.return_value.__enter__ = mock.Mock(side_effect=lambda: io.BytesIO(b"GEODATA"))
            uo.return_value.__exit__ = mock.Mock(return_value=False)
            with mock.patch.object(paths, "ASSETS", Path(d) / "assets"), \
                 mock.patch.object(ownership, "chown_user", lambda p: None), \
                 mock.patch.object(geo, "info", lambda s: None), \
                 mock.patch("urllib.request.urlopen", uo):
                geo.ensure()
            self.assertTrue(uo.called)
            for c in uo.call_args_list:
                self.assertIn("timeout", c.kwargs,
                              "every download must pass a timeout")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_resolve_host_message_no_raw_errno(self):
        with mock.patch("socket.gethostbyname",
                        side_effect=socket.gaierror(-2, "Name or service not known")):
            with self.assertRaises(RuntimeError) as cm:
                util.resolve_host("nonexistent.invalid")
        msg = str(cm.exception)
        self.assertIn("nonexistent.invalid", msg)
        self.assertNotIn("-2", msg)
        self.assertNotIn("gaierror", msg)


# ---------------------------------------------------------------------------
# tun.py
# ---------------------------------------------------------------------------

class TestTunStructure(unittest.TestCase):
    def test_route_get_duplicate_removed(self):
        self.assertFalse(hasattr(tun, "_route_get"),
                         "_route_get duplicates route_to and should be gone")

    def test_verify_pin_no_unused_param(self):
        params = inspect.signature(tun._verify_pin).parameters
        self.assertEqual(list(params), ["server_ip"])

    def test_check_server_ip_accepts_ipv4(self):
        tun._check_server_ip("1.2.3.4")  # must not raise

    def test_check_server_ip_rejects_option_like(self):
        for bad in ("-x", "--help", "evil.com"):
            with self.assertRaises(RuntimeError):
                tun._check_server_ip(bad)


class TestTunResolv(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.mkdtemp()
        self._orig_resolv = tun.RESOLV
        self._orig_bak = paths.RESOLV_BAK
        tun.RESOLV = Path(self._d) / "resolv.conf"
        paths.RESOLV_BAK = Path(self._d) / "resolv.conf.bak"

    def tearDown(self):
        tun.RESOLV = self._orig_resolv
        paths.RESOLV_BAK = self._orig_bak
        shutil.rmtree(self._d, ignore_errors=True)

    def test_symlink_preserved_across_backup_restore(self):
        target = Path(self._d) / "run-resolv"
        target.write_text("nameserver 9.9.9.9\n")
        os.symlink(target, tun.RESOLV)
        meta = tun._backup_resolv()
        # simulate apply_up replacing the symlink with the placeholder file
        tun._write_resolv(tun.DEFAULT_DNS)
        self.assertFalse(tun.RESOLV.is_symlink())
        tun._restore_resolv(meta)
        self.assertTrue(tun.RESOLV.is_symlink(), "symlink must be restored")
        self.assertEqual(os.readlink(tun.RESOLV), str(target))

    def test_regular_file_roundtrip(self):
        tun.RESOLV.write_text("nameserver 9.9.9.9\n")
        meta = tun._backup_resolv()
        tun._write_resolv(tun.DEFAULT_DNS)
        tun._restore_resolv(meta)
        self.assertEqual(tun.RESOLV.read_text(), "nameserver 9.9.9.9\n")

    def test_backup_does_not_clobber_existing(self):
        paths.RESOLV_BAK.write_text("FIRST")
        tun.RESOLV.write_text("nameserver 9.9.9.9\n")
        tun._backup_resolv()
        self.assertEqual(paths.RESOLV_BAK.read_text(), "FIRST")

    def test_backup_skips_own_placeholder(self):
        tun.RESOLV.write_bytes(tun.DEFAULT_DNS)
        meta = tun._backup_resolv()
        self.assertEqual(meta.get("kind"), "none")
        self.assertFalse(paths.RESOLV_BAK.exists())


class TestTunIPv6(unittest.TestCase):
    def test_block_ipv6_drops_via_ip6tables(self):
        calls = []
        with mock.patch.object(tun, "have", lambda b: True), \
             mock.patch.object(tun, "_run", lambda cmd, **k: calls.append(cmd) or (0, "", "")):
            tun.block_ipv6()
        joined = [" ".join(c) for c in calls]
        self.assertTrue(any("ip6tables" in c and "DROP" in c for c in joined),
                        "must install an ip6tables egress DROP")

    def test_block_ipv6_sysctl_fallback(self):
        calls = []
        with mock.patch.object(tun, "have", lambda b: False), \
             mock.patch.object(tun, "_run", lambda cmd, **k: calls.append(cmd) or (0, "", "")):
            tun.block_ipv6()
        joined = [" ".join(c) for c in calls]
        self.assertTrue(any("disable_ipv6=1" in c for c in joined),
                        "fallback must disable IPv6 via sysctl")


# ---------------------------------------------------------------------------
# cli.py
# ---------------------------------------------------------------------------

class TestCliFixes(unittest.TestCase):
    def test_status_without_started_key_no_crash(self):
        active = {"name": "p", "host": "h", "port": 443}  # no 'started'
        with mock.patch.object(state, "read_active", return_value=active), \
             mock.patch.object(proc, "xray_running", return_value=True), \
             mock.patch.object(proc, "tun2socks_running", return_value=True), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = cli.cmd_status(None)
        self.assertEqual(rc, 0)

    def test_await_socks_true_when_port_open(self):
        with mock.patch.object(cli, "port_open", return_value=True):
            self.assertTrue(cli._await_socks(1080, attempts=3, delay=0))

    def test_await_socks_false_when_xray_dead(self):
        with mock.patch.object(cli, "port_open", return_value=False), \
             mock.patch.object(cli.proc, "xray_running", return_value=False):
            self.assertFalse(cli._await_socks(1080, attempts=3, delay=0))

    def test_await_socks_false_on_timeout(self):
        with mock.patch.object(cli, "port_open", return_value=False), \
             mock.patch.object(cli.proc, "xray_running", return_value=True):
            self.assertFalse(cli._await_socks(1080, attempts=2, delay=0))


# ---------------------------------------------------------------------------
# tui.py + profile.count
# ---------------------------------------------------------------------------

class TestTuiFixes(unittest.TestCase):
    def test_re_imported_at_module_top(self):
        import re as _re
        self.assertIs(tui.re, _re)

    def test_dead_color_helpers_removed(self):
        self.assertFalse(hasattr(tui, "_white"))
        self.assertFalse(hasattr(tui, "_orange"))


class TestProfileCount(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.mkdtemp()
        self._orig = (paths.HOME, paths.PROFILES)
        paths.HOME = Path(self._d)
        paths.PROFILES = paths.HOME / "profiles"

    def tearDown(self):
        paths.HOME, paths.PROFILES = self._orig
        shutil.rmtree(self._d, ignore_errors=True)

    def test_count_matches_files_without_parsing(self):
        for i in range(3):
            profile.save(link.parse(f"vless://uid@h:{443 + i}#p{i}"))
        # a corrupt file is still a profile file and must not raise
        (paths.PROFILES / "bad.json").write_text("{oops")
        self.assertEqual(profile.count(), 4)

    def test_count_zero_when_no_dir(self):
        self.assertEqual(profile.count(), 0)


# ---------------------------------------------------------------------------
# display.vpn_ip — show egress IP through the socks proxy after `up`
# ---------------------------------------------------------------------------

class TestVpnIp(unittest.TestCase):
    def test_vpn_ip_success_and_argv(self):
        cp = subprocess.CompletedProcess(args=[], returncode=0,
                                         stdout="203.0.113.5\n", stderr="")
        with mock.patch.object(display.subprocess, "run", return_value=cp) as m:
            ip = display.vpn_ip(1080)
        self.assertEqual(ip, "203.0.113.5")
        argv = m.call_args.args[0]
        self.assertIn("--socks5", argv)
        self.assertIn("127.0.0.1:1080", argv)
        self.assertIn("ifconfig.me/ip", argv)
        self.assertIn("--max-time", argv)

    def test_vpn_ip_none_on_nonzero_returncode(self):
        cp = subprocess.CompletedProcess(args=[], returncode=7, stdout="", stderr="")
        with mock.patch.object(display.subprocess, "run", return_value=cp):
            self.assertIsNone(display.vpn_ip(1080))

    def test_vpn_ip_none_on_timeout(self):
        with mock.patch.object(display.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("curl", 5)):
            self.assertIsNone(display.vpn_ip(1080))

    def test_vpn_ip_none_when_curl_missing(self):
        with mock.patch.object(display.subprocess, "run",
                               side_effect=FileNotFoundError):
            self.assertIsNone(display.vpn_ip(1080))

    def test_vpn_ip_rejects_junk_response(self):
        cp = subprocess.CompletedProcess(args=[], returncode=0,
                                         stdout="<html>blocked</html>", stderr="")
        with mock.patch.object(display.subprocess, "run", return_value=cp):
            self.assertIsNone(display.vpn_ip(1080))

    def test_vpn_ip_line_success_plain(self):
        with mock.patch.object(display, "vpn_ip", return_value="1.2.3.4"):
            self.assertEqual(display.vpn_ip_line(1080), "VPN IP: 1.2.3.4")

    def test_vpn_ip_line_failure_hint(self):
        with mock.patch.object(display, "vpn_ip", return_value=None):
            self.assertEqual(display.vpn_ip_line(1080),
                             "VPN IP: check manually (curl ifconfig.me)")


# ---------------------------------------------------------------------------
# bug 1: CONNMARK restore-mark must be inserted at PREROUTING position 1
# (before the nixos rpfilter rule), not appended
# ---------------------------------------------------------------------------

class TestConnmarkPrerouting(unittest.TestCase):
    def test_prerouting_restore_inserted_at_top(self):
        calls = []

        def fake_run(cmd, **k):
            calls.append(cmd)
            return (1 if "-D" in cmd else 0, "", "")   # -D loops break immediately

        with mock.patch.object(tun, "_run", side_effect=fake_run):
            tun._install_mark_rules()

        adds = [c for c in calls if "-A" in c or "-I" in c]
        pre = [c for c in adds if "PREROUTING" in c]
        self.assertEqual(len(pre), 1)
        c = pre[0]
        self.assertNotIn("-A", c)                       # must not append
        i = c.index("-I")
        self.assertEqual(c[i:i + 3], ["-I", "PREROUTING", "1"])
        self.assertIn("--restore-mark", c)

    def test_output_savemark_still_appended(self):
        calls = []
        with mock.patch.object(tun, "_run",
                               side_effect=lambda cmd, **k: calls.append(cmd) or (1 if "-D" in cmd else 0, "", "")):
            tun._install_mark_rules()
        out = [c for c in calls if ("-A" in c or "-I" in c) and "OUTPUT" in c]
        self.assertEqual(len(out), 1)
        self.assertIn("--save-mark", out[0])


# ---------------------------------------------------------------------------
# state.set_default_name — must use the same safe write as storage.write_json
# ---------------------------------------------------------------------------

class TestSetDefaultNameSafeWrite(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = (paths.HOME, paths.DEFAULT)
        paths.HOME = Path(self._tmp)
        paths.DEFAULT = paths.HOME / "default"

    def tearDown(self):
        paths.HOME, paths.DEFAULT = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_writes_name_and_chowns(self):
        with mock.patch.object(ownership, "chown_user") as ch:
            state.set_default_name("myprofile")
        self.assertEqual(paths.DEFAULT.read_text(), "myprofile")
        ch.assert_called_once_with(paths.DEFAULT)   # so a root-written default is user-owned

    def test_refuses_symlink(self):
        paths.HOME.mkdir(parents=True, exist_ok=True)
        victim = paths.HOME / "victim"
        victim.write_text("keep")
        os.symlink(victim, paths.DEFAULT)
        with self.assertRaises(OSError):
            state.set_default_name("x")
        self.assertEqual(victim.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
