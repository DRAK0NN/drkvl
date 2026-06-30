"""Unit tests for drkvl.geo — geo asset discovery + download.

No root, no network: urllib/ownership/info boundaries are mocked and
paths.ASSETS / geo.SYSTEM_DIRS point at temp dirs so the real
/usr/.../xray locations never interfere. The timeout-kwarg behaviour is
already covered by tests/test_fixes.py::TestGeoUtilFixes, so it is not
duplicated here.
"""
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drkvl import geo, ownership, paths


def _write_both(d: Path, data: bytes = b"GEO"):
    d.mkdir(parents=True, exist_ok=True)
    for n in geo.NAMES:
        (d / n).write_bytes(data)


def _urlopen_mock(payload: bytes = b"GEODATA"):
    """A urlopen replacement: each call yields a fresh BytesIO context manager."""
    uo = mock.MagicMock()
    uo.return_value.__enter__ = mock.Mock(side_effect=lambda: io.BytesIO(payload))
    uo.return_value.__exit__ = mock.Mock(return_value=False)
    return uo


# ---------------------------------------------------------------------------
# _has_all
# ---------------------------------------------------------------------------

class TestHasAll(unittest.TestCase):
    def setUp(self):
        self._d = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._d, ignore_errors=True)

    def test_true_when_both_present_and_nonempty(self):
        _write_both(self._d)
        self.assertTrue(geo._has_all(self._d))

    def test_false_when_one_missing(self):
        (self._d / "geosite.dat").write_bytes(b"x")  # only one of the two
        self.assertFalse(geo._has_all(self._d))

    def test_false_when_one_zero_length(self):
        (self._d / "geosite.dat").write_bytes(b"x")
        (self._d / "geoip.dat").write_bytes(b"")  # exists but empty
        self.assertFalse(geo._has_all(self._d))

    def test_false_when_dir_empty(self):
        self.assertFalse(geo._has_all(self._d))


# ---------------------------------------------------------------------------
# find
# ---------------------------------------------------------------------------

class TestFind(unittest.TestCase):
    def setUp(self):
        self._d = Path(tempfile.mkdtemp())
        self._assets = self._d / "assets"

    def tearDown(self):
        shutil.rmtree(self._d, ignore_errors=True)

    def test_returns_assets_when_it_holds_both(self):
        _write_both(self._assets)
        with mock.patch.object(paths, "ASSETS", self._assets), \
             mock.patch.object(geo, "SYSTEM_DIRS", []):
            self.assertEqual(geo.find(), self._assets)

    def test_none_when_no_candidate_has_them(self):
        # assets dir exists but is empty; system dirs neutralised
        self._assets.mkdir(parents=True, exist_ok=True)
        with mock.patch.object(paths, "ASSETS", self._assets), \
             mock.patch.object(geo, "SYSTEM_DIRS", []):
            self.assertIsNone(geo.find())

    def test_finds_in_system_dir_when_assets_absent(self):
        sysdir = self._d / "sysxray"
        _write_both(sysdir)
        with mock.patch.object(paths, "ASSETS", self._assets), \
             mock.patch.object(geo, "SYSTEM_DIRS", [sysdir]):
            self.assertEqual(geo.find(), sysdir)


# ---------------------------------------------------------------------------
# ensure
# ---------------------------------------------------------------------------

class TestEnsure(unittest.TestCase):
    def setUp(self):
        self._d = Path(tempfile.mkdtemp())
        self._assets = self._d / "assets"

    def tearDown(self):
        shutil.rmtree(self._d, ignore_errors=True)

    def test_present_returns_assets_without_download(self):
        _write_both(self._assets)
        uo = _urlopen_mock()
        with mock.patch.object(paths, "ASSETS", self._assets), \
             mock.patch.object(geo, "SYSTEM_DIRS", []), \
             mock.patch.object(ownership, "chown_user", lambda p: None), \
             mock.patch.object(geo, "info", lambda s: None), \
             mock.patch("urllib.request.urlopen", uo):
            result = geo.ensure()
        self.assertEqual(result, self._assets)
        self.assertFalse(uo.called, "must not download when assets already present")

    def test_absent_downloads_and_writes_both_files(self):
        uo = _urlopen_mock(b"GEODATA")
        with mock.patch.object(paths, "ASSETS", self._assets), \
             mock.patch.object(geo, "SYSTEM_DIRS", []), \
             mock.patch.object(ownership, "chown_user", lambda p: None), \
             mock.patch.object(geo, "info", lambda s: None), \
             mock.patch("urllib.request.urlopen", uo):
            result = geo.ensure()
        self.assertEqual(result, self._assets)
        for n in geo.NAMES:
            target = self._assets / n
            self.assertTrue(target.exists(), f"{n} must be written")
            self.assertEqual(target.read_bytes(), b"GEODATA")
        # one download per missing asset, each carrying a timeout-less .part rename
        self.assertEqual(uo.call_count, len(geo.NAMES))
        # no leftover temp files
        self.assertEqual(list(self._assets.glob("*.part")), [])

    def test_download_failure_raises_and_cleans_part(self):
        # seed a stale .part to prove ensure()'s except-block unlink removes it
        self._assets.mkdir(parents=True, exist_ok=True)
        stale = self._assets / (geo.NAMES[0] + ".part")
        stale.write_bytes(b"partial-leftover")

        def boom(*a, **k):
            raise OSError("connection refused")

        with mock.patch.object(paths, "ASSETS", self._assets), \
             mock.patch.object(geo, "SYSTEM_DIRS", []), \
             mock.patch.object(ownership, "chown_user", lambda p: None), \
             mock.patch.object(geo, "info", lambda s: None), \
             mock.patch("urllib.request.urlopen", side_effect=boom):
            with self.assertRaises(RuntimeError):
                geo.ensure()
        self.assertFalse(stale.exists(), ".part temp file must be cleaned up")
        self.assertEqual(list(self._assets.glob("*.part")), [])


if __name__ == "__main__":
    unittest.main()
