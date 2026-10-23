"""Taint sonuç önbelleği (taint_cache): JSON, 0700/0600, içerik anahtarı, bozuk kayıt, önbellekli == önbelleksiz."""
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import taint_cache
import taint_flow
import taint_models

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "taint_bench"


def _project():
    files = {p.name: p.read_text(encoding="utf-8") for p in sorted(FIXTURES.glob("py_*.py"))}
    files["pkg/__init__.py"] = ""
    files["pkg/ayar.py"] = "AYAR = {}\ndef kaydet(v):\n    AYAR['son'] = v\n"
    files["pkg/gorunum.py"] = (
        "import os\nfrom flask import request\nfrom pkg.ayar import kaydet, AYAR\n"
        "@app.post('/a')\ndef a():\n    kaydet(request.form['v'])\n    return 'ok'\n"
        "def b():\n    os.system(AYAR['son'])\n"
    )
    files["bozuk.py"] = "def (:\n"
    return files


def _plain(results):
    return {relpath: (a.language, [f for f in a.flows], sorted(a.evaluated_sinks), sorted(a.uncertain_sinks))
            for relpath, a in results.items()}


class TaintCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": self.temp.name, "SNIPER_TAINT_CACHE": "1"})
        self.env.start()
        os.environ.pop("SNIPER_TAINT_MODELS", None)
        taint_models._load.cache_clear()
        self.cache = Path(self.temp.name) / "taint-cache"

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()
        taint_models._load.cache_clear()

    def _entries(self):
        return sorted(self.cache.glob("*.json"))

    def test_cached_equals_uncached_and_permissions(self):
        files = _project()
        uncached = taint_flow._analyze_python_files_uncached(files, None)
        first = taint_flow.analyze_python_files(files)
        self.assertEqual(_plain(first), _plain(uncached))
        self.assertTrue(any(f.cross_file for a in first.values() for f in a.flows))
        entries = self._entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(entries[0].stat().st_mode), 0o600)
        document = json.loads(entries[0].read_text())
        self.assertEqual(document["format"], taint_cache.CACHE_FORMAT)
        with mock.patch.object(taint_flow, "_analyze_python_files_uncached", side_effect=AssertionError("önbellek kullanılmadı")):
            second = taint_flow.analyze_python_files(files)
        self.assertEqual(_plain(second), _plain(uncached))

    def test_content_change_and_pii_bypass(self):
        files = _project()
        taint_flow.analyze_python_files(files)
        changed = dict(files, **{"pkg/gorunum.py": files["pkg/gorunum.py"] + "\n# değişti\n"})
        taint_flow.analyze_python_files(changed)
        self.assertEqual(len(self._entries()), 2)
        taint_flow.analyze_python_files(files, pii=lambda name: False)
        self.assertEqual(len(self._entries()), 2)
        # Kök dizin anahtarda değil: aynı içerik aynı kayıt.
        taint_flow.analyze_python_files(dict(files))
        self.assertEqual(len(self._entries()), 2)

    def test_model_change_changes_key(self):
        files = _project()
        settings = {"x": 1}
        before = taint_cache.project_key("python", files, settings)
        model = Path(self.temp.name) / "ek-model.json"
        model.write_text(json.dumps({"format": taint_models.MODEL_FORMAT, "propagators": ["ek.yayici"]}))
        with mock.patch.dict(os.environ, {"SNIPER_TAINT_MODELS": str(model)}):
            self.assertNotEqual(taint_cache.project_key("python", files, settings), before)
        self.assertNotEqual(taint_cache.project_key("python", files, {"x": 2}), before)

    def test_corrupt_or_foreign_entries_are_ignored(self):
        files = _project()
        expected = _plain(taint_flow._analyze_python_files_uncached(files, None))
        taint_flow.analyze_python_files(files)
        entry = self._entries()[0]
        for garbage in ("{bozuk", json.dumps({"format": "baska", "key": entry.stem, "payload": {}}),
                        json.dumps({"format": taint_cache.CACHE_FORMAT, "key": entry.stem,
                                    "payload": {"py_flask_app.py": {"language": "python", "flows": [[1, 2]]}}}),
                        json.dumps({"format": taint_cache.CACHE_FORMAT, "key": entry.stem,
                                    "payload": {"/etc/passwd": {"language": "python"}}})):
            entry.write_text(garbage)
            os.chmod(entry, 0o600)
            self.assertEqual(_plain(taint_flow.analyze_python_files(files)), expected)
        entry.write_text(garbage)
        os.chmod(entry, 0o644)  # grup/diğerleri okuyabiliyor: güvenilmez
        self.assertIsNone(taint_cache.load(entry.stem))

    def test_unsafe_or_missing_directory_disables_cache(self):
        files = _project()
        self.cache.mkdir(mode=0o755)
        os.chmod(self.cache, 0o755)
        self.assertIsNone(taint_cache.cache_dir())
        taint_flow.analyze_python_files(files)
        self.assertEqual(self._entries(), [])
        with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": ""}):
            self.assertIsNone(taint_cache.cache_dir())
        with mock.patch.dict(os.environ, {"SNIPER_TAINT_CACHE": "0"}):
            os.chmod(self.cache, 0o700)
            self.assertIsNone(taint_cache.cache_dir())

    def test_lru_bound_and_stale_temp_cleanup(self):
        self.cache.mkdir(mode=0o700)
        stale = self.cache / ".kayit-eski.tmp"
        stale.write_text("x")
        os.utime(stale, (time.time() - 7200, time.time() - 7200))
        with mock.patch.object(taint_cache, "MAX_ENTRIES", 3):
            for index in range(5):
                self.assertTrue(taint_cache.store(f"{index:064x}", {"i": index}))
                os.utime(self.cache / f"{index:064x}.json", (time.time() - 100 + index, time.time() - 100 + index))
        self.assertEqual(len(self._entries()), 3)
        self.assertIsNone(taint_cache.load(f"{0:064x}"))
        self.assertEqual(taint_cache.load(f"{4:064x}"), {"i": 4})
        self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
