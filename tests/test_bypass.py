"""Tests for custom bypass-list support (drkvl/bypass.py)."""
import io
import json
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import bypass, paths, cli, display


class TestRootDomain(unittest.TestCase):
    def test_collapses_deep_subdomain(self):
        self.assertEqual(bypass.root_domain("0001bottlgrm2.msk.mts.ru"), "mts.ru")

    def test_collapses_two_level_subdomain(self):
        self.assertEqual(bypass.root_domain("001.corp.mail.ru"), "mail.ru")

    def test_simple_subdomain(self):
        self.assertEqual(bypass.root_domain("007.megafon.ru"), "megafon.ru")

    def test_non_ru_tld(self):
        self.assertEqual(bypass.root_domain("00.img.avito.st"), "avito.st")

    def test_already_root(self):
        self.assertEqual(bypass.root_domain("mts.ru"), "mts.ru")

    def test_wildcard_stripped(self):
        self.assertEqual(bypass.root_domain("*.mts.ru"), "mts.ru")

    def test_multi_part_suffix_kept(self):
        # com.ru / msk.ru are public suffixes -> keep one more label
        self.assertEqual(bypass.root_domain("shop.example.com.ru"), "example.com.ru")
        self.assertEqual(bypass.root_domain("city.msk.ru"), "city.msk.ru")

    def test_case_insensitive(self):
        self.assertEqual(bypass.root_domain("WWW.MTS.RU"), "mts.ru")

    def test_single_label_is_none(self):
        self.assertIsNone(bypass.root_domain("localhost"))

    def test_empty_is_none(self):
        self.assertIsNone(bypass.root_domain(""))

    def test_strips_port(self):
        self.assertEqual(bypass.root_domain("app.games.s3.yandex.net:443"), "yandex.net")

    def test_strips_path(self):
        self.assertEqual(bypass.root_domain("a.mts.ru/path"), "mts.ru")

    def test_ip_literal_is_none(self):
        self.assertIsNone(bypass.root_domain("1.2.3.4"))

    def test_bare_public_suffix_is_none(self):
        # emitting gov.ru / com.ru as a bypass domain would route the whole suffix direct
        self.assertIsNone(bypass.root_domain("gov.ru"))
        self.assertIsNone(bypass.root_domain("com.ru"))
        self.assertIsNone(bypass.root_domain("msk.ru"))


class TestFilterIp(unittest.TestCase):
    def test_single_ip_kept_bare(self):
        self.assertEqual(bypass.filter_ip("185.12.152.144"), "185.12.152.144")

    def test_cidr_24_kept(self):
        self.assertEqual(bypass.filter_ip("1.2.3.0/24"), "1.2.3.0/24")

    def test_cidr_16_kept(self):
        self.assertEqual(bypass.filter_ip("10.20.0.0/16"), "10.20.0.0/16")

    def test_cidr_broader_than_16_skipped(self):
        self.assertIsNone(bypass.filter_ip("10.0.0.0/8"))
        self.assertIsNone(bypass.filter_ip("10.0.0.0/15"))
        self.assertIsNone(bypass.filter_ip("0.0.0.0/0"))

    def test_invalid_ip_skipped(self):
        self.assertIsNone(bypass.filter_ip("not-an-ip"))
        self.assertIsNone(bypass.filter_ip(""))

    def test_host_bits_tolerated(self):
        self.assertEqual(bypass.filter_ip("1.2.3.5/24"), "1.2.3.0/24")

    def test_broad_ipv6_skipped(self):
        self.assertIsNone(bypass.filter_ip("::/0"))
        self.assertIsNone(bypass.filter_ip("2000::/3"))

    def test_narrow_ipv6_kept(self):
        self.assertEqual(bypass.filter_ip("2001:db8::/64"), "2001:db8::/64")


class TestImportAndFiles(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = (paths.HOME, paths.BYPASS_DOMAINS, paths.BYPASS_IPS)
        paths.HOME = Path(self._tmp)
        paths.BYPASS_DOMAINS = paths.HOME / "bypass_domains.txt"
        paths.BYPASS_IPS = paths.HOME / "bypass_ips.txt"

    def tearDown(self):
        paths.HOME, paths.BYPASS_DOMAINS, paths.BYPASS_IPS = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, entries):
        p = Path(self._tmp) / "in.json"
        p.write_text(json.dumps(entries))
        return str(p)

    def test_import_dedups_and_filters(self):
        src = self._write([
            {"hostname": "a.mts.ru", "ip": ""},
            {"hostname": "b.mts.ru", "ip": ""},          # dup root
            {"hostname": "avito.st", "ip": ""},
            {"hostname": "x.corp.mail.ru", "ip": "185.12.152.144"},
            {"hostname": "", "ip": "1.2.3.0/24"},
            {"hostname": "", "ip": "10.0.0.0/8"},        # broad -> skip
            {"hostname": "", "ip": "junk"},              # invalid -> skip
            {"hostname": "", "ip": ""},                  # nothing
        ])
        stats = bypass.import_file(src)
        self.assertEqual(stats["domains"], 3)            # mts.ru, avito.st, mail.ru
        self.assertEqual(stats["ips"], 2)                # 185.12.152.144, 1.2.3.0/24
        self.assertEqual(stats["skipped"], 2)            # broad + invalid IPs
        self.assertEqual(sorted(bypass.load_domains()), ["avito.st", "mail.ru", "mts.ru"])
        self.assertIn("1.2.3.0/24", bypass.load_ips())
        self.assertIn("185.12.152.144", bypass.load_ips())

    def test_files_written_sorted_one_per_line(self):
        bypass.import_file(self._write([
            {"hostname": "z.ru", "ip": ""},
            {"hostname": "a.ru", "ip": ""},
        ]))
        self.assertEqual(paths.BYPASS_DOMAINS.read_text().splitlines(), ["a.ru", "z.ru"])

    def test_load_empty_when_absent(self):
        self.assertEqual(bypass.load_domains(), [])
        self.assertEqual(bypass.load_ips(), [])

    def test_stats_and_clear(self):
        bypass.import_file(self._write([
            {"hostname": "a.ru", "ip": "1.1.1.1"},
        ]))
        self.assertEqual(bypass.stats(), (1, 1))
        bypass.clear()
        self.assertFalse(paths.BYPASS_DOMAINS.exists())
        self.assertFalse(paths.BYPASS_IPS.exists())
        self.assertEqual(bypass.stats(), (0, 0))

    def test_bad_json_raises_runtime(self):
        p = Path(self._tmp) / "bad.json"
        p.write_text("{ not json")
        with self.assertRaises(RuntimeError):
            bypass.import_file(str(p))

    def test_missing_file_raises_runtime(self):
        with self.assertRaises(RuntimeError):
            bypass.import_file(str(Path(self._tmp) / "nope.json"))

    def test_import_ensures_private_dirs(self):
        # first run under sudo must create ~/.config/drkvl 0700 + chowned
        with mock.patch.object(bypass.ownership, "ensure_dirs") as ed:
            bypass.import_file(self._write([{"hostname": "a.ru", "ip": ""}]))
        ed.assert_called_once()

    def test_ip_literal_hostname_makes_no_domain(self):
        bypass.import_file(self._write([{"hostname": "1.2.3.4", "ip": ""}]))
        self.assertEqual(bypass.load_domains(), [])


class TestDisplay(unittest.TestCase):
    def test_import_line(self):
        line = display.bypass_import_line({"domains": 5, "ips": 3, "skipped": 2})
        self.assertIn("+5", line)
        self.assertIn("+3", line)
        self.assertIn("2 skipped", line)

    def test_status_lines_empty_hint(self):
        lines = display.bypass_status_lines(0, 0)
        self.assertEqual(len(lines), 1)
        self.assertIn("import one", lines[0])

    def test_status_lines_counts(self):
        lines = display.bypass_status_lines(7, 9)
        self.assertIn("7", lines[0])
        self.assertIn("9", lines[0])


class TestCliCommands(unittest.TestCase):
    def test_bypass_import_prints_stats(self):
        st = {"domains": 4, "ips": 6, "skipped": 1}
        with mock.patch.object(cli.bypass, "import_file", return_value=st), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            rc = cli.cmd_bypass_import(types.SimpleNamespace(file="x.json"))
        self.assertEqual(rc, 0)
        self.assertIn("+4", out.getvalue())
        self.assertIn("+6", out.getvalue())

    def test_bypass_import_error_returns_1(self):
        with mock.patch.object(cli.bypass, "import_file",
                               side_effect=RuntimeError("bad file")), \
             mock.patch.object(cli, "err"):
            self.assertEqual(cli.cmd_bypass_import(types.SimpleNamespace(file="x")), 1)

    def test_bypass_list_prints_status(self):
        with mock.patch.object(cli.bypass, "stats", return_value=(12, 34)), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            rc = cli.cmd_bypass_list(None)
        self.assertEqual(rc, 0)
        self.assertIn("12", out.getvalue())
        self.assertIn("34", out.getvalue())

    def test_bypass_clear_calls_clear(self):
        with mock.patch.object(cli.bypass, "clear") as clr, \
             mock.patch.object(cli, "info"):
            rc = cli.cmd_bypass_clear(None)
        self.assertEqual(rc, 0)
        clr.assert_called_once()


if __name__ == "__main__":
    unittest.main()
