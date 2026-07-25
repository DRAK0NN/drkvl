"""Hysteria2 (native xray outbound) support: link parsing, config generation,
persistence dispatch, subscriptions.

The config-schema test actually runs `xray run -test` against a generated
hysteria config, so it guards the exact field names (protocol "hysteria",
version 2, hysteriaSettings.udphop, tlsSettings.pinnedPeerCertSha256,
udpmasks/salamander) against a future xray that changes them.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import link, config, storage, sub, paths
from drkvl.link import Vless, Hy2


# ---------------------------------------------------------------------------
# 1. hysteria2:// / hy2:// link parsing
# ---------------------------------------------------------------------------

class TestHy2Parser(unittest.TestCase):
    def test_full(self):
        v = link.parse_hy2(
            "hysteria2://s3cret@vpn.example.com:443?sni=peer.example.com"
            "&obfs=salamander&obfs-password=obfspw&insecure=1#node")
        self.assertEqual(v.kind, "hy2")
        self.assertEqual(v.auth, "s3cret")
        self.assertEqual(v.host, "vpn.example.com")
        self.assertEqual(v.port, 443)
        self.assertEqual(v.name, "node")
        self.assertEqual(v.sni, "peer.example.com")
        self.assertEqual(v.obfs, "salamander")
        self.assertEqual(v.obfs_password, "obfspw")
        self.assertTrue(v.insecure)
        self.assertEqual(v.network, "hysteria")
        self.assertEqual(v.security, "tls")

    def test_hy2_alias_minimal(self):
        v = link.parse_hy2("hy2://pw@1.2.3.4:8443")
        self.assertEqual(v.auth, "pw")
        self.assertEqual(v.host, "1.2.3.4")
        self.assertEqual(v.port, 8443)
        self.assertEqual(v.obfs, "")
        self.assertFalse(v.insecure)

    def test_auth_userpass(self):
        v = link.parse_hy2("hysteria2://user:pass@h:443")
        self.assertEqual(v.auth, "user:pass")

    def test_auth_from_query(self):
        v = link.parse_hy2("hysteria2://h:443?auth=qpw&sni=s")
        self.assertEqual(v.auth, "qpw")

    def test_percent_encoded_auth(self):
        v = link.parse_hy2("hysteria2://a%40b@h:443")
        self.assertEqual(v.auth, "a@b")

    def test_mport_udphop(self):
        v = link.parse_hy2("hysteria2://pw@h:443?mport=20000-40000&hopInterval=30")
        self.assertEqual(v.ports, "20000-40000")
        self.assertEqual(v.hop_interval, 30)

    def test_pin_colon_hex_passthrough(self):
        pin = ":".join(["9f"] * 32)
        v = link.parse_hy2(f"hysteria2://pw@h:443?pinSHA256={pin}")
        self.assertEqual(v.pin_sha256, pin)

    def test_pin_base64_to_hex(self):
        raw = bytes(range(32))
        b64 = base64.b64encode(raw).decode()
        v = link.parse_hy2(f"hysteria2://pw@h:443?pinSHA256={b64}")
        self.assertEqual(v.pin_sha256, raw.hex())

    def test_pin_uppercase_hex_passthrough(self):
        # xray hex-decodes case-insensitively and strips colons -> keep as-is
        v = link.parse_hy2("hysteria2://pw@h:443?pinSHA256=" + "AB" * 32)
        self.assertEqual(v.pin_sha256, "AB" * 32)

    def test_reject_wrong_scheme(self):
        with self.assertRaises(ValueError):
            link.parse_hy2("vless://uid@h:443")

    def test_reject_missing_auth(self):
        with self.assertRaises(ValueError):
            link.parse_hy2("hysteria2://h:443?sni=s")

    def test_reject_missing_port(self):
        with self.assertRaises(ValueError):
            link.parse_hy2("hysteria2://pw@h")

    def test_reject_bad_port(self):
        with self.assertRaises(ValueError):
            link.parse_hy2("hysteria2://pw@h:0")

    def test_roundtrip(self):
        v = link.parse_hy2(
            "hysteria2://pw@h:443?sni=s&obfs=salamander&obfs-password=o"
            "&mport=20000-40000#n")
        v2 = Hy2.from_dict(v.to_dict())
        self.assertEqual(v, v2)


# ---------------------------------------------------------------------------
# 2. dispatchers: parse_any + from_dict
# ---------------------------------------------------------------------------

class TestDispatch(unittest.TestCase):
    def test_parse_any_vless(self):
        v = link.parse_any("vless://uid@h:443#x")
        self.assertIsInstance(v, Vless)
        self.assertEqual(v.kind, "vless")

    def test_parse_any_hysteria2(self):
        v = link.parse_any("hysteria2://pw@h:443#x")
        self.assertIsInstance(v, Hy2)

    def test_parse_any_hy2_alias(self):
        v = link.parse_any("hy2://pw@h:443")
        self.assertIsInstance(v, Hy2)

    def test_parse_any_uppercase_scheme(self):
        # scheme dispatch must be case-insensitive (RFC-3986) to match the
        # subscription gate, else an uppercase-scheme link is misrouted/dropped
        self.assertIsInstance(link.parse_any("HYSTERIA2://pw@h:443#x"), Hy2)
        self.assertIsInstance(link.parse_any("HY2://pw@h:443#x"), Hy2)
        self.assertIsInstance(link.parse_any("Vless://uid@h:443#x"), Vless)

    def test_from_dict_hy2(self):
        v = link.parse_hy2("hysteria2://pw@h:443")
        rebuilt = link.from_dict(v.to_dict())
        self.assertIsInstance(rebuilt, Hy2)
        self.assertEqual(rebuilt.auth, "pw")

    def test_from_dict_vless_default(self):
        # a legacy dict with no "kind" must reconstruct as Vless
        v = Vless(uuid="u", host="h", port=443)
        d = v.to_dict()
        d.pop("kind", None)
        rebuilt = link.from_dict(d)
        self.assertIsInstance(rebuilt, Vless)


# ---------------------------------------------------------------------------
# 3. config.build() hysteria outbound
# ---------------------------------------------------------------------------

_HY = Hy2(auth="s3cret", host="vpn.example.com", port=443,
          sni="peer.example.com", obfs="salamander", obfs_password="obfspw")


class TestHy2Config(unittest.TestCase):
    def _proxy(self, v, **kw):
        cfg = config.build(v, **kw)
        return [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0], cfg

    def test_protocol_and_settings(self):
        proxy, _ = self._proxy(_HY)
        self.assertEqual(proxy["protocol"], "hysteria")
        self.assertNotIn("vnext", proxy["settings"])
        self.assertEqual(proxy["settings"]["version"], 2)
        self.assertEqual(proxy["settings"]["address"], "vpn.example.com")
        self.assertEqual(proxy["settings"]["port"], 443)

    def test_stream_tls_h3(self):
        proxy, _ = self._proxy(_HY)
        ss = proxy["streamSettings"]
        self.assertEqual(ss["network"], "hysteria")
        self.assertEqual(ss["security"], "tls")
        self.assertEqual(ss["tlsSettings"]["serverName"], "peer.example.com")
        self.assertEqual(ss["tlsSettings"]["alpn"], ["h3"])

    def test_hysteria_settings_auth(self):
        proxy, _ = self._proxy(_HY)
        hy = proxy["streamSettings"]["hysteriaSettings"]
        self.assertEqual(hy["version"], 2)
        self.assertEqual(hy["auth"], "s3cret")

    def test_salamander_finalmask_udp(self):
        # salamander lives under streamSettings.finalmask.udp[] (a []conf.Mask);
        # the stream-level "udpmasks" key is silently dropped by xray.
        proxy, _ = self._proxy(_HY)
        udp = proxy["streamSettings"]["finalmask"]["udp"]
        self.assertEqual(udp[0]["type"], "salamander")
        self.assertEqual(udp[0]["settings"]["password"], "obfspw")
        self.assertNotIn("udpmasks", proxy["streamSettings"])

    def test_no_obfs_no_finalmask(self):
        v = Hy2(auth="pw", host="h", port=443)
        proxy, _ = self._proxy(v)
        self.assertNotIn("finalmask", proxy["streamSettings"])
        self.assertNotIn("udpmasks", proxy["streamSettings"])

    def test_pin(self):
        pin = "aa" * 32
        v = Hy2(auth="pw", host="h", port=443, pin_sha256=pin)
        proxy, _ = self._proxy(v)
        self.assertEqual(proxy["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"], pin)

    def test_udphop_in_finalmask_quicparams(self):
        # port-hopping lives under finalmask.quicParams.udpHop; the
        # hysteriaSettings.udphop location is deprecated (xray only warns).
        v = Hy2(auth="pw", host="h", port=443, ports="20000-40000", hop_interval=30)
        proxy, _ = self._proxy(v)
        hop = proxy["streamSettings"]["finalmask"]["quicParams"]["udpHop"]
        self.assertEqual(hop["ports"], "20000-40000")
        self.assertEqual(hop["interval"], 30)   # seconds
        self.assertNotIn("udphop", proxy["streamSettings"]["hysteriaSettings"])

    def test_udphop_interval_below_min_omitted(self):
        # xray rejects interval < 5 (seconds) at load; below that we omit it
        # and let xray fall back to its 30s default instead of failing.
        v = Hy2(auth="pw", host="h", port=443, ports="20000-40000", hop_interval=3)
        proxy, _ = self._proxy(v)
        hop = proxy["streamSettings"]["finalmask"]["quicParams"]["udpHop"]
        self.assertEqual(hop["ports"], "20000-40000")
        self.assertNotIn("interval", hop)

    def test_quicparams_carries_only_udphop(self):
        # never emit congestion/brutal/bandwidth (server runs ignoreClientBandwidth)
        v = Hy2(auth="pw", host="h", port=443, ports="20000-40000")
        proxy, _ = self._proxy(v)
        qp = proxy["streamSettings"]["finalmask"]["quicParams"]
        self.assertEqual(set(qp.keys()), {"udpHop"})

    def test_sni_defaults_to_host(self):
        v = Hy2(auth="pw", host="h.example", port=443)
        proxy, _ = self._proxy(v)
        self.assertEqual(proxy["streamSettings"]["tlsSettings"]["serverName"], "h.example")

    def test_mark(self):
        proxy, _ = self._proxy(_HY, mark=0xDD0DE)
        self.assertEqual(proxy["streamSettings"]["sockopt"]["mark"], 0xDD0DE)

    def test_no_mark(self):
        proxy, _ = self._proxy(_HY, mark=0)
        self.assertNotIn("sockopt", proxy["streamSettings"])

    def test_insecure_not_emitted(self):
        # allowInsecure was removed from xray; it must never appear
        v = Hy2(auth="pw", host="h", port=443, insecure=True)
        proxy, _ = self._proxy(v)
        self.assertNotIn("allowInsecure", proxy["streamSettings"]["tlsSettings"])

    def test_plain_valid_cert_tls_minimal(self):
        # plain path (valid server cert): no pin, no insecure -> tlsSettings is
        # exactly serverName + alpn h3, with NO allowInsecure / pinnedPeerCertSha256
        v = Hy2(auth="pw", host="vpn.example.com", port=443, sni="sni.example.com")
        proxy, _ = self._proxy(v)
        ss = proxy["streamSettings"]
        self.assertEqual(ss["security"], "tls")
        tls = ss["tlsSettings"]
        self.assertEqual(tls["serverName"], "sni.example.com")
        self.assertEqual(tls["alpn"], ["h3"])
        self.assertEqual(set(tls.keys()), {"serverName", "alpn"})
        self.assertNotIn("allowInsecure", tls)
        self.assertNotIn("pinnedPeerCertSha256", tls)

    @unittest.skipUnless(shutil.which("xray"), "xray not in PATH")
    def test_plain_valid_cert_passes_xray_test(self):
        # the plain (no pin / no obfs / no hop) config must validate on real xray
        v = Hy2(auth="s3cret", host="vpn.example.com", port=443, sni="sni.example.com")
        cfg = config.build(v, bypass=False, geo=False)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            tmp = f.name
        try:
            r = subprocess.run(["xray", "run", "-test", "-c", tmp],
                               capture_output=True, text=True, timeout=15)
            self.assertIn("Configuration OK", r.stdout + r.stderr,
                          msg=(r.stdout + r.stderr)[-500:])
        finally:
            os.unlink(tmp)

    def test_shared_parts_unchanged(self):
        # routing/dns/dns-out are engine-agnostic and must be identical to vless
        _, cfg = self._proxy(_HY, direct_mark=0xDD0DE, bypass=True)
        tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertEqual(set(tags), {"proxy", "direct", "block", "dns-out"})
        direct = [o for o in cfg["outbounds"] if o["tag"] == "direct"][0]
        self.assertEqual(direct["streamSettings"]["sockopt"]["mark"], 0xDD0DE)
        rule_tags = [r.get("outboundTag") for r in cfg["routing"]["rules"]]
        self.assertIn("proxy", rule_tags)
        self.assertIn("direct", rule_tags)   # bypass rules present

    @unittest.skipUnless(shutil.which("xray"), "xray not in PATH")
    def test_generated_config_passes_xray_test(self):
        """The generated hysteria config must be accepted by the real xray."""
        v = Hy2(auth="s3cret", host="vpn.example.com", port=443,
                sni="peer.example.com", obfs="salamander", obfs_password="obfspw",
                pin_sha256="aa" * 32, ports="20000-40000", hop_interval=30)
        # asset-free config (no geosite/geoip .dat needed), like a speed-test xray
        cfg = config.build(v, mark=0xDD0DE, direct_mark=0xDD0DE,
                           bypass=False, geo=False)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            tmp = f.name
        try:
            r = subprocess.run(["xray", "run", "-test", "-c", tmp],
                               capture_output=True, text=True, timeout=15)
            self.assertIn("Configuration OK", r.stdout + r.stderr,
                          msg=(r.stdout + r.stderr)[-500:])
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# 4. persistence dispatch (storage reconstructs Hy2)
# ---------------------------------------------------------------------------

class TestHy2Storage(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._save = (paths.HOME, paths.PROFILES, paths.DEFAULT)
        paths.HOME = Path(self._tmp)
        paths.PROFILES = paths.HOME / "profiles"
        paths.DEFAULT = paths.HOME / "default"

    def tearDown(self):
        paths.HOME, paths.PROFILES, paths.DEFAULT = self._save
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_save_and_reconstruct_hy2(self):
        v = link.parse_hy2("hysteria2://pw@h.example:443?obfs=salamander&obfs-password=o#n")
        name = storage.save(v)
        items = storage.list_all()
        self.assertEqual(len(items), 1)
        _, loaded = items[0]
        self.assertIsInstance(loaded, Hy2)
        self.assertEqual(loaded.auth, "pw")
        self.assertEqual(loaded.obfs, "salamander")

    def test_mixed_profiles(self):
        storage.save(link.parse_any("vless://uid@h:443#v"))
        storage.save(link.parse_any("hysteria2://pw@h:443#h"))
        kinds = sorted(type(v).__name__ for _, v in storage.list_all())
        self.assertEqual(kinds, ["Hy2", "Vless"])


# ---------------------------------------------------------------------------
# 5. subscriptions accept hysteria2 links
# ---------------------------------------------------------------------------

class TestHy2Sub(unittest.TestCase):
    def test_parse_links_mixed(self):
        body = ("vless://uid@h:443#v\n"
                "hysteria2://pw@h:443#h\n"
                "hy2://pw2@h:8443#h2\n"
                "trojan://x@h:443#t\n")
        profiles, skipped = sub.parse_links(body)
        kinds = sorted(type(p).__name__ for p in profiles)
        self.assertEqual(kinds, ["Hy2", "Hy2", "Vless"])
        self.assertEqual(skipped, 1)   # trojan skipped

    def test_parse_links_uppercase_scheme(self):
        profiles, skipped = sub.parse_links("HYSTERIA2://pw@h:443#h\n")
        self.assertEqual(len(profiles), 1)
        self.assertEqual(skipped, 0)


# ---------------------------------------------------------------------------
# 6. guards: xray version floor + insecure-without-pin refusal
# ---------------------------------------------------------------------------

class TestHy2Guards(unittest.TestCase):
    def test_xray_version_parse(self):
        from drkvl import proc
        self.assertEqual(proc.parse_xray_version("Xray 26.5.9 (Xray...)"), (26, 5, 9))
        self.assertEqual(proc.parse_xray_version("1.2.3 foo"), (1, 2, 3))
        self.assertIsNone(proc.parse_xray_version("no version here"))

    def test_hysteria_min_floor(self):
        from drkvl import proc
        self.assertEqual(proc.HYSTERIA_MIN, (26, 3))

    def test_block_reason_insecure_no_pin(self):
        from drkvl import cli
        v = link.parse_hy2("hysteria2://pw@h:443?insecure=1")
        r = cli._profile_block_reason(v)
        self.assertIsNotNone(r)
        self.assertIn("pinSHA256", r)

    def test_block_reason_insecure_with_pin_ok(self):
        from drkvl import cli
        v = link.parse_hy2("hysteria2://pw@h:443?insecure=1&pinSHA256=" + "aa" * 32)
        self.assertIsNone(cli._profile_block_reason(v))

    def test_block_reason_vless_never_blocked(self):
        from drkvl import cli
        self.assertIsNone(cli._profile_block_reason(link.parse("vless://u@h:443")))

    def test_block_reason_plain_no_pin_not_blocked(self):
        # a plain valid-cert profile (no pin, not insecure) must NEVER be blocked
        from drkvl import cli
        v = link.parse_hy2("hysteria2://pw@vpn.example.com:443?sni=sni.example.com")
        self.assertFalse(v.insecure)
        self.assertEqual(v.pin_sha256, "")
        self.assertIsNone(cli._profile_block_reason(v))

    def test_block_reason_only_insecure_without_pin(self):
        # block insecure+no-pin ONLY; allow no-insecure/no-pin and insecure+pin
        from drkvl import cli
        self.assertIsNotNone(cli._profile_block_reason(
            link.parse_hy2("hysteria2://pw@h:443?insecure=1")))
        self.assertIsNone(cli._profile_block_reason(
            link.parse_hy2("hysteria2://pw@h:443")))
        self.assertIsNone(cli._profile_block_reason(
            link.parse_hy2("hysteria2://pw@h:443?insecure=1&pinSHA256=" + "aa" * 32)))

    def test_add_warns_on_low_hop_interval(self):
        import io
        import shutil
        import tempfile
        from contextlib import redirect_stderr, redirect_stdout
        from drkvl import cli, paths
        saved = (paths.HOME, paths.PROFILES, paths.DEFAULT)
        tmp = Path(tempfile.mkdtemp())
        paths.HOME, paths.PROFILES, paths.DEFAULT = tmp, tmp / "profiles", tmp / "default"
        try:
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(out):
                cli.main(["add", "hysteria2://pw@h:443?mport=20000-40000&hopInterval=3#x"])
            self.assertIn("ignored", out.getvalue())
        finally:
            paths.HOME, paths.PROFILES, paths.DEFAULT = saved
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
