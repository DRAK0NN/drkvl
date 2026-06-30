"""Compatibility and integration tests for drkvl."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import link, config, profile, paths
from drkvl.link import Vless


# ---------------------------------------------------------------------------
# 1. tun2socks loglevel detection
# ---------------------------------------------------------------------------

class TestTun2socksLoglevel(unittest.TestCase):
    def test_tun2socks_available(self):
        self.assertIsNotNone(shutil.which("tun2socks"),
                             "tun2socks not in PATH")

    def test_version_parseable(self):
        r = subprocess.run(["tun2socks", "-version"],
                           capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        self.assertTrue(len(out) > 0, "tun2socks -version produced no output")

    def test_loglevel_fallback(self):
        """proc.start_tun2socks tries 'warn' then 'warning'."""
        from drkvl import proc
        # just verify the function exists and has the fallback structure
        import inspect
        src = inspect.getsource(proc.start_tun2socks)
        self.assertIn("warn", src)
        self.assertIn("warning", src)

    def test_accepted_loglevel(self):
        """At least one of 'warn'/'warning' is accepted without crash."""
        for level in ("warn", "warning"):
            r = subprocess.run(
                ["tun2socks", "-device", "tun://drkvl_test_noop",
                 "-proxy", "socks5://127.0.0.1:19999",
                 "-loglevel", level],
                capture_output=True, text=True, timeout=3,
            )
            stderr = r.stderr.lower()
            if "not a valid" not in stderr and "unrecognized" not in stderr:
                return  # at least one worked
        self.fail("neither 'warn' nor 'warning' accepted by tun2socks")


# ---------------------------------------------------------------------------
# 2. xray version >= 26.5
# ---------------------------------------------------------------------------

class TestXrayVersion(unittest.TestCase):
    def test_xray_available(self):
        self.assertIsNotNone(shutil.which("xray"), "xray not in PATH")

    def test_xray_version_sufficient(self):
        r = subprocess.run(["xray", "version"], capture_output=True, text=True)
        out = r.stdout + r.stderr
        # parse "Xray X.Y.Z" or similar
        import re
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
        self.assertIsNotNone(m, f"cannot parse xray version from: {out!r}")
        major, minor = int(m.group(1)), int(m.group(2))
        self.assertTrue(
            (major > 26) or (major == 26 and minor >= 5),
            f"xray {major}.{minor} < 26.5 (no xhttp support)"
        )


# ---------------------------------------------------------------------------
# 3. ip route / ip rule available
# ---------------------------------------------------------------------------

class TestIproute2(unittest.TestCase):
    def test_ip_available(self):
        self.assertIsNotNone(shutil.which("ip"), "ip (iproute2) not in PATH")

    def test_ip_route_works(self):
        r = subprocess.run(["ip", "route", "show"], capture_output=True)
        self.assertEqual(r.returncode, 0, "ip route show failed")

    def test_ip_rule_works(self):
        r = subprocess.run(["ip", "rule", "show"], capture_output=True)
        self.assertEqual(r.returncode, 0, "ip rule show failed")


# ---------------------------------------------------------------------------
# 4. /etc/resolv.conf write + restore
# ---------------------------------------------------------------------------

class TestResolvConf(unittest.TestCase):
    def test_resolv_readable(self):
        self.assertTrue(Path("/etc/resolv.conf").exists(),
                        "/etc/resolv.conf missing")

    @unittest.skipUnless(os.geteuid() == 0, "needs root")
    def test_resolv_write_restore(self):
        resolv = Path("/etc/resolv.conf")
        original = resolv.read_bytes()
        test_data = b"nameserver 1.2.3.4\n"
        try:
            if resolv.is_symlink():
                resolv.unlink()
            resolv.write_bytes(test_data)
            self.assertEqual(resolv.read_bytes(), test_data)
        finally:
            if resolv.is_symlink():
                resolv.unlink()
            resolv.write_bytes(original)
        self.assertEqual(resolv.read_bytes(), original,
                         "resolv.conf not restored")


# ---------------------------------------------------------------------------
# 5. config.build() correctness
# ---------------------------------------------------------------------------

_DUMMY = Vless(
    uuid="00000000-0000-0000-0000-000000000000",
    host="example.com", port=443,
    network="xhttp", security="reality",
    pbk="testkey", sid="aa", sni="sni.example.com",
)


class TestConfigBuild(unittest.TestCase):
    def _build(self, **kw):
        return config.build(_DUMMY, **kw)

    def test_basic_structure(self):
        cfg = self._build()
        for key in ("log", "dns", "inbounds", "outbounds", "routing"):
            self.assertIn(key, cfg)

    def test_socks_inbound(self):
        cfg = self._build()
        socks = [i for i in cfg["inbounds"] if i["tag"] == "socks-in"]
        self.assertEqual(len(socks), 1)
        self.assertEqual(socks[0]["listen"], "127.0.0.1")
        self.assertEqual(socks[0]["port"], 1080)

    def test_proxy_outbound(self):
        cfg = self._build()
        proxy = [o for o in cfg["outbounds"] if o["tag"] == "proxy"]
        self.assertEqual(len(proxy), 1)
        vnext = proxy[0]["settings"]["vnext"][0]
        self.assertEqual(vnext["address"], "example.com")
        self.assertEqual(vnext["port"], 443)

    def test_dns_tcp(self):
        cfg = self._build()
        servers = cfg["dns"]["servers"]
        self.assertTrue(all(s.startswith("tcp://") for s in servers))

    def test_dns_out_outbound(self):
        cfg = self._build()
        tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertIn("dns-out", tags)

    def test_dns_routing_rule(self):
        cfg = self._build()
        rules = cfg["routing"]["rules"]
        dns_rules = [r for r in rules if r.get("outboundTag") == "dns-out"]
        self.assertTrue(len(dns_rules) >= 1)
        self.assertIn("socks-in", dns_rules[0].get("inboundTag", []))

    def test_mark_only(self):
        cfg = self._build(mark=0xDD0DE)
        proxy = [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0]
        sockopt = proxy["streamSettings"].get("sockopt", {})
        self.assertEqual(sockopt.get("mark"), 0xDD0DE)

    def test_direct_mark_only(self):
        cfg = self._build(direct_mark=0xDD0DE)
        direct = [o for o in cfg["outbounds"] if o["tag"] == "direct"][0]
        sockopt = direct.get("streamSettings", {}).get("sockopt", {})
        self.assertEqual(sockopt.get("mark"), 0xDD0DE)

    def test_both_marks(self):
        cfg = self._build(mark=0xDD0DE, direct_mark=0xDD0DE)
        proxy = [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0]
        direct = [o for o in cfg["outbounds"] if o["tag"] == "direct"][0]
        self.assertEqual(
            proxy["streamSettings"]["sockopt"]["mark"], 0xDD0DE)
        self.assertEqual(
            direct["streamSettings"]["sockopt"]["mark"], 0xDD0DE)

    def test_no_marks(self):
        cfg = self._build(mark=0, direct_mark=0)
        proxy = [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0]
        direct = [o for o in cfg["outbounds"] if o["tag"] == "direct"][0]
        self.assertNotIn("sockopt", proxy["streamSettings"])
        self.assertNotIn("streamSettings", direct)

    def test_bypass_on(self):
        cfg = self._build(bypass=True)
        rules = cfg["routing"]["rules"]
        tags = [r.get("outboundTag") for r in rules]
        self.assertIn("direct", tags)
        self.assertEqual(cfg["routing"]["domainStrategy"], "IPIfNonMatch")

    def test_bypass_off(self):
        cfg = self._build(bypass=False)
        rules = cfg["routing"]["rules"]
        direct_geo = [r for r in rules
                      if r.get("outboundTag") == "direct"
                      and ("geosite" in str(r) or "geoip:ru" in str(r))]
        self.assertEqual(len(direct_geo), 0)
        self.assertEqual(cfg["routing"]["domainStrategy"], "AsIs")

    def test_reality_settings(self):
        cfg = self._build()
        proxy = [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0]
        ss = proxy["streamSettings"]
        self.assertEqual(ss["security"], "reality")
        rs = ss["realitySettings"]
        self.assertEqual(rs["publicKey"], "testkey")
        self.assertEqual(rs["shortId"], "aa")

    def test_xhttp_settings(self):
        cfg = self._build()
        proxy = [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0]
        ss = proxy["streamSettings"]
        self.assertEqual(ss["network"], "xhttp")
        self.assertIn("xhttpSettings", ss)
        self.assertIn("xmux", ss["xhttpSettings"])

    def test_dump_permissions(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp = f.name
        try:
            cfg = self._build()
            config.dump(cfg, tmp)
            mode = oct(os.stat(tmp).st_mode & 0o777)
            self.assertEqual(mode, "0o600")
            with open(tmp) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["dns"], cfg["dns"])
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# 6. link.py edge cases
# ---------------------------------------------------------------------------

class TestLinkParser(unittest.TestCase):
    def test_minimal(self):
        v = link.parse("vless://uuid@host:443#name")
        self.assertEqual(v.uuid, "uuid")
        self.assertEqual(v.host, "host")
        self.assertEqual(v.port, 443)
        self.assertEqual(v.name, "name")
        self.assertEqual(v.network, "tcp")
        self.assertEqual(v.security, "none")

    def test_xhttp_reality(self):
        v = link.parse(
            "vless://uid@h:443?type=xhttp&security=reality"
            "&pbk=key&sid=ab&sni=s.com&fp=chrome#x"
        )
        self.assertEqual(v.network, "xhttp")
        self.assertEqual(v.security, "reality")
        self.assertEqual(v.pbk, "key")
        self.assertEqual(v.sid, "ab")

    def test_ws_tls(self):
        v = link.parse(
            "vless://uid@h:443?type=ws&security=tls"
            "&path=%2Fws&host=cdn.com&sni=cdn.com#ws"
        )
        self.assertEqual(v.network, "ws")
        self.assertEqual(v.security, "tls")
        self.assertEqual(v.path, "/ws")
        self.assertEqual(v.h_host, "cdn.com")

    def test_grpc(self):
        v = link.parse(
            "vless://uid@h:443?type=grpc&serviceName=svc"
            "&authority=auth.com&security=reality&pbk=k&sid=00#g"
        )
        self.assertEqual(v.network, "grpc")
        self.assertEqual(v.service_name, "svc")
        self.assertEqual(v.authority, "auth.com")

    def test_httpupgrade(self):
        v = link.parse(
            "vless://uid@h:443?type=httpupgrade&path=/up&host=h.com"
            "&security=tls&sni=h.com#hu"
        )
        self.assertEqual(v.network, "httpupgrade")
        self.assertEqual(v.path, "/up")

    def test_raw_becomes_tcp(self):
        v = link.parse("vless://uid@h:443?type=raw#r")
        self.assertEqual(v.network, "tcp")

    def test_splithttp_becomes_xhttp(self):
        """config.build treats splithttp as xhttp."""
        v = link.parse("vless://uid@h:443?type=splithttp#s")
        self.assertEqual(v.network, "splithttp")
        cfg = config.build(v)
        proxy = [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0]
        self.assertEqual(proxy["streamSettings"]["network"], "xhttp")

    def test_flow(self):
        v = link.parse(
            "vless://uid@h:443?flow=xtls-rprx-vision&security=reality"
            "&pbk=k&sid=0#f"
        )
        self.assertEqual(v.flow, "xtls-rprx-vision")

    def test_pqv(self):
        v = link.parse("vless://uid@h:443?pqv=mldsaverify&security=reality&pbk=k&sid=0#pq")
        self.assertEqual(v.pqv, "mldsaverify")

    def test_alpn(self):
        v = link.parse("vless://uid@h:443?security=tls&alpn=h2,http/1.1&sni=h#a")
        self.assertEqual(v.alpn, "h2,http/1.1")

    def test_no_name(self):
        v = link.parse("vless://uid@h:443")
        self.assertEqual(v.name, "")

    def test_encoded_uuid(self):
        v = link.parse("vless://a%20b@h:443#enc")
        self.assertEqual(v.uuid, "a b")

    def test_encoded_fragment(self):
        v = link.parse("vless://uid@h:443#hello%20world")
        self.assertEqual(v.name, "hello world")

    def test_port_1(self):
        v = link.parse("vless://uid@h:1#low")
        self.assertEqual(v.port, 1)

    def test_port_65535(self):
        v = link.parse("vless://uid@h:65535#high")
        self.assertEqual(v.port, 65535)

    def test_reject_no_scheme(self):
        with self.assertRaises(ValueError):
            link.parse("https://example.com")

    def test_reject_no_uuid(self):
        with self.assertRaises(ValueError):
            link.parse("vless://host:443")

    def test_reject_no_host(self):
        with self.assertRaises(ValueError):
            link.parse("vless://uuid@:443")

    def test_reject_no_port(self):
        with self.assertRaises(ValueError):
            link.parse("vless://uuid@host")

    def test_reject_port_zero(self):
        with self.assertRaises(ValueError):
            link.parse("vless://uid@h:0#z")

    def test_extra_json(self):
        v = link.parse('vless://uid@h:443?type=xhttp&extra={"noGRPC":true}#e')
        self.assertIn("noGRPC", v.extra)

    def test_empty_security_defaults_none(self):
        v = link.parse("vless://uid@h:443?security=#s")
        self.assertEqual(v.security, "none")

    def test_mode(self):
        v = link.parse("vless://uid@h:443?type=xhttp&mode=packet-up#m")
        self.assertEqual(v.mode, "packet-up")

    def test_to_dict_from_dict_roundtrip(self):
        v = link.parse(
            "vless://uid@h:443?type=xhttp&security=reality"
            "&pbk=k&sid=0&path=/x&mode=auto#rt"
        )
        d = v.to_dict()
        v2 = Vless.from_dict(d)
        self.assertEqual(v, v2)


# ---------------------------------------------------------------------------
# 7. profile save/load roundtrip
# ---------------------------------------------------------------------------

class TestProfileRoundtrip(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_home = paths.HOME
        self._orig_profiles = paths.PROFILES
        self._orig_default = paths.DEFAULT
        paths.HOME = Path(self._tmpdir)
        paths.PROFILES = paths.HOME / "profiles"
        paths.DEFAULT = paths.HOME / "default"

    def tearDown(self):
        paths.HOME = self._orig_home
        paths.PROFILES = self._orig_profiles
        paths.DEFAULT = self._orig_default
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_save_load(self):
        v = link.parse(
            "vless://myuuid@example.com:443?type=xhttp&security=reality"
            "&pbk=pk&sid=ab#test-profile"
        )
        name = profile.save(v)
        loaded_name, loaded_v = profile.load(name)
        self.assertEqual(loaded_name, name)
        self.assertEqual(loaded_v.uuid, "myuuid")
        self.assertEqual(loaded_v.host, "example.com")
        self.assertEqual(loaded_v.port, 443)
        self.assertEqual(loaded_v.network, "xhttp")

    def test_save_sets_default(self):
        v = link.parse("vless://uid@h:443#first")
        name = profile.save(v)
        self.assertTrue(paths.DEFAULT.exists())
        self.assertEqual(paths.DEFAULT.read_text().strip(), name)

    def test_list_all(self):
        for i in range(3):
            profile.save(link.parse(f"vless://uid@h:{443+i}#p{i}"))
        items = profile.list_all()
        self.assertEqual(len(items), 3)

    def test_remove(self):
        v = link.parse("vless://uid@h:443#removeme")
        name = profile.save(v)
        profile.remove(name)
        items = profile.list_all()
        self.assertEqual(len(items), 0)

    def test_load_by_index(self):
        profile.save(link.parse("vless://uid@h:443#a"))
        profile.save(link.parse("vless://uid@h:444#b"))
        _, v = profile.load("1")
        self.assertEqual(v.port, 444)

    def test_file_permissions(self):
        v = link.parse("vless://uid@h:443#perms")
        name = profile.save(v)
        p = paths.PROFILES / f"{name}.json"
        mode = oct(os.stat(p).st_mode & 0o777)
        self.assertEqual(mode, "0o600")

    def test_slug_sanitization(self):
        v = link.parse("vless://uid@h:443#../../etc/passwd")
        name = profile.save(v)
        self.assertNotIn("/", name)
        self.assertNotIn("..", name)

    def test_duplicate_name(self):
        v = link.parse("vless://uid@h:443#dup")
        n1 = profile.save(v)
        n2 = profile.save(v)
        self.assertNotEqual(n1, n2)
        self.assertEqual(len(profile.list_all()), 2)


# ---------------------------------------------------------------------------
# 8. tui.py loads without crash
# ---------------------------------------------------------------------------

class TestTuiImport(unittest.TestCase):
    def test_import(self):
        from drkvl import tui
        self.assertTrue(hasattr(tui, "run"))
        self.assertTrue(hasattr(tui, "_banner"))

    def test_banner_no_crash(self):
        from drkvl import tui
        import io
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            tui._banner()
        output = mock_out.getvalue()
        self.assertIn("DRAK0NN", output)
        self.assertIn("vpn:", output)

    def test_title_lines(self):
        from drkvl.tui import _TITLE
        self.assertEqual(len(_TITLE), 6)
        widths = [len(l) for l in _TITLE]
        self.assertEqual(len(set(widths)), 1,
                         f"title lines have unequal widths: {widths}")

    def test_completer(self):
        from drkvl.tui import _completer
        self.assertEqual(_completer("li", 0), "list")
        self.assertIsNone(_completer("zzz", 0))


if __name__ == "__main__":
    unittest.main()
