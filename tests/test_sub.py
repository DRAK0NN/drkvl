"""Tests for subscription support (drkvl/sub.py)."""
import base64
import io
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import sub, paths, storage, link, cli

LINKS = (
    "vless://uid@a.example.com:443?type=ws&security=tls&sni=a#one\n"
    "vless://uid@b.example.com:8443?type=grpc#two\n"
)


def _b64(s: str) -> bytes:
    return base64.b64encode(s.encode())


class TestDecodeBody(unittest.TestCase):
    def test_base64_list_decoded(self):
        out = sub.decode_body(_b64(LINKS))
        self.assertIn("vless://uid@a.example.com:443", out)
        self.assertEqual(out.count("vless://"), 2)

    def test_plain_text_links_passthrough(self):
        out = sub.decode_body(LINKS.encode())
        self.assertEqual(out.count("vless://"), 2)

    def test_urlsafe_base64(self):
        body = "vless://uid@h:443?path=" + "a" * 4 + "#x\n"
        raw = base64.urlsafe_b64encode(body.encode())
        self.assertIn("vless://", sub.decode_body(raw))

    def test_invalid_base64_raises(self):
        with self.assertRaises(ValueError):
            sub.decode_body(b"!!! definitely not base64 or links !!!")

    def test_valid_base64_without_links_raises(self):
        # decodes fine, but yields no links -> not a usable subscription
        with self.assertRaises(ValueError):
            sub.decode_body(base64.b64encode(b"just some plain text, no links"))

    def test_empty_is_empty(self):
        self.assertEqual(sub.decode_body(b"   "), "")


class TestFetch(unittest.TestCase):
    def _urlopen(self, body: bytes):
        cm = mock.MagicMock()
        cm.__enter__.return_value.read.return_value = body
        cm.__exit__.return_value = False
        return cm

    def test_fetch_decodes(self):
        with mock.patch("urllib.request.urlopen", return_value=self._urlopen(_b64(LINKS))):
            out = sub.fetch("http://x/sub")
        self.assertEqual(out.count("vless://"), 2)

    def test_fetch_passes_timeout(self):
        with mock.patch("urllib.request.urlopen", return_value=self._urlopen(_b64(LINKS))) as m:
            sub.fetch("http://x/sub")
        self.assertEqual(m.call_args.kwargs.get("timeout"), sub.TIMEOUT)

    def test_empty_response_raises(self):
        with mock.patch("urllib.request.urlopen", return_value=self._urlopen(b"   ")):
            with self.assertRaises(RuntimeError):
                sub.fetch("http://x/sub")

    def test_network_error_raises_runtime(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("timed out")):
            with self.assertRaises(RuntimeError):
                sub.fetch("http://x/sub")

    def test_rejects_non_http_scheme(self):
        # file:// / ftp:// must not be opened at all
        with mock.patch("urllib.request.urlopen") as m:
            with self.assertRaises(RuntimeError):
                sub.fetch("file:///etc/passwd")
        self.assertFalse(m.called, "must not open a non-http(s) URL")

    def test_rejects_oversized_body(self):
        big = b"vless://x\n" * (sub.MAX_BYTES // 5)   # > MAX_BYTES
        with mock.patch("urllib.request.urlopen", return_value=self._urlopen(big)):
            with self.assertRaises(RuntimeError):
                sub.fetch("http://x/sub")


class TestParseLinks(unittest.TestCase):
    def test_vless_only(self):
        vlesses, skipped = sub.parse_links(LINKS)
        self.assertEqual(len(vlesses), 2)
        self.assertEqual(skipped, 0)

    def test_mixed_protocols_skip_non_vless(self):
        body = (
            "vless://uid@h:443#ok\n"
            "vmess://eyJ2IjoiMiJ9\n"
            "trojan://pass@h:443#t\n"
            "ss://YWVzOnBhc3M@h:8388#s\n"
        )
        with mock.patch.object(sub, "warn") as w:
            vlesses, skipped = sub.parse_links(body)
        self.assertEqual(len(vlesses), 1)
        self.assertEqual(skipped, 3)
        self.assertTrue(w.called)

    def test_malformed_vless_skipped(self):
        body = "vless://\nvless://uid@h:443#ok\n"
        with mock.patch.object(sub, "warn"):
            vlesses, skipped = sub.parse_links(body)
        self.assertEqual(len(vlesses), 1)
        self.assertEqual(skipped, 1)

    def test_duplicate_links_deduped(self):
        body = "vless://uid@h:443#a\nvless://uid@h:443#a\nvless://uid@h:444#b\n"
        vlesses, _ = sub.parse_links(body)
        self.assertEqual(len(vlesses), 2)


class TestProfileNamingAndMap(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = (paths.HOME, paths.PROFILES, paths.DEFAULT, paths.SUBSCRIPTIONS)
        paths.HOME = Path(self._tmp)
        paths.PROFILES = paths.HOME / "profiles"
        paths.DEFAULT = paths.HOME / "default"
        paths.SUBSCRIPTIONS = paths.HOME / "subscriptions.json"

    def tearDown(self):
        paths.HOME, paths.PROFILES, paths.DEFAULT, paths.SUBSCRIPTIONS = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_add_profiles_named_sub_n(self):
        vlesses, _ = sub.parse_links(LINKS)
        names = sub.add_profiles(vlesses)
        self.assertEqual(names, ["sub-0", "sub-1"])

    def test_next_index_continues(self):
        vlesses, _ = sub.parse_links(LINKS)
        sub.add_profiles(vlesses)
        self.assertEqual(sub.next_index(), 2)
        more = sub.add_profiles(vlesses)
        self.assertEqual(more, ["sub-2", "sub-3"])

    def test_remove_all_only_sub_profiles(self):
        storage.save(link.parse("vless://uid@h:443#manual"))   # non-sub
        vlesses, _ = sub.parse_links(LINKS)
        sub.add_profiles(vlesses)
        removed = sub.remove_all()
        self.assertEqual(removed, 2)
        remaining = [n for n, _ in storage.list_all()]
        self.assertNotIn("sub-0", remaining)
        self.assertIn("manual", remaining)

    def test_map_roundtrip(self):
        sub.set_url_profiles("http://x/sub", ["sub-0", "sub-1"])
        self.assertEqual(sub.url_profiles("http://x/sub"), ["sub-0", "sub-1"])
        self.assertEqual(sub.saved_urls(), ["http://x/sub"])
        sub.forget_url("http://x/sub")
        self.assertEqual(sub.saved_urls(), [])


class TestSubCommands(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = (paths.HOME, paths.PROFILES, paths.DEFAULT, paths.SUBSCRIPTIONS)
        paths.HOME = Path(self._tmp)
        paths.PROFILES = paths.HOME / "profiles"
        paths.DEFAULT = paths.HOME / "default"
        paths.SUBSCRIPTIONS = paths.HOME / "subscriptions.json"
        self._quiet = [mock.patch.object(cli, n, lambda *a, **k: None)
                       for n in ("info", "warn", "err")]
        for p in self._quiet:
            p.start()

    def tearDown(self):
        for p in self._quiet:
            p.stop()
        paths.HOME, paths.PROFILES, paths.DEFAULT, paths.SUBSCRIPTIONS = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_resubscribe_replaces_old_profiles(self):
        ns = types.SimpleNamespace(url="http://x/sub")
        with mock.patch.object(sub, "fetch", return_value="vless://uid@h:443#a\n"):
            cli.cmd_sub(ns)
        with mock.patch.object(sub, "fetch",
                               return_value="vless://uid@h:443#a\nvless://uid@h:444#b\n"):
            cli.cmd_sub(ns)
        names = [n for n, _ in storage.list_all()]
        self.assertEqual(len(names), 2)                      # replaced, not appended
        self.assertEqual(sub.url_profiles("http://x/sub"), names)

    def test_update_keeps_profiles_when_one_fetch_fails(self):
        with mock.patch.object(sub, "fetch", return_value="vless://uid@a:443#a\n"):
            cli.cmd_sub(types.SimpleNamespace(url="http://A"))
        with mock.patch.object(sub, "fetch", return_value="vless://uid@b:443#b\n"):
            cli.cmd_sub(types.SimpleNamespace(url="http://B"))
        before = {n for n, _ in storage.list_all()}
        self.assertEqual(len(before), 2)

        def flaky(url, *a, **k):
            if url == "http://A":
                raise RuntimeError("network blip")
            return "vless://uid@b2:443#b2\n"

        with mock.patch.object(sub, "fetch", side_effect=flaky):
            cli.cmd_sub_update(types.SimpleNamespace(url=None))   # update all
        hosts = {v.host for _, v in storage.list_all()}
        self.assertIn("a", hosts, "A's profile must survive its failed refresh")
        self.assertIn("b2", hosts, "B must be refreshed")
        # A's map entry must still point at a real, A-owned profile
        a_names = set(sub.url_profiles("http://A"))
        on_disk = {n for n, _ in storage.list_all()}
        self.assertTrue(a_names and a_names <= on_disk)


class TestFallbackSelection(unittest.TestCase):
    V = link.Vless(uuid="u", host="h", port=443)

    def test_picks_first_working_and_stops(self):
        tried = []

        def attempt(name, v):
            tried.append(name)
            return "9.9.9.9" if name == "c" else None

        cands = [("a", self.V), ("b", self.V), ("c", self.V), ("d", self.V)]
        with mock.patch.object(cli, "info", lambda s: None):
            res = cli._select_working(cands, attempt)
        self.assertIsNotNone(res)
        self.assertEqual(res[0], "c")
        self.assertEqual(res[2], "9.9.9.9")
        self.assertEqual(tried, ["a", "b", "c"])  # stopped at c; d never tried

    def test_returns_none_when_all_fail(self):
        with mock.patch.object(cli, "info", lambda s: None):
            res = cli._select_working([("a", self.V), ("b", self.V)],
                                      lambda n, v: None)
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
