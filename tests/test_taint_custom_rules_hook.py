"""Özel taint kuralları motor kancası: kayıtlı kural kendiliğinden yüklenir; model kaynakları (sources)."""
import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import taint_flow
import taint_models
import taint_rules_dsl as dsl

RULE = """
format: sniper-taint-rules-v1
name: sirket-kaynak
language: python
description: Şirket içi girdi ve sorgu yardımcıları
sources:
  - calls: [sirket.http.girdi]
  - attributes: ["*.ham_govde"]
    label: stored
sinks:
  - kind: sql
    calls: [sirket.db.ham_sorgu]
    args: [0]
sanitizers:
  - calls: [sirket.db.kacis]
    kinds: [sql]
"""

CODE = textwrap.dedent("""
    import sirket.db
    import sirket.http
    from sirket.http import girdi

    def ara(istek):
        q = sirket.http.girdi("q")
        sirket.db.ham_sorgu("SELECT * FROM t WHERE a = " + q)
        sirket.db.ham_sorgu("SELECT 1 WHERE b = " + girdi("b"))
        sirket.db.ham_sorgu("SELECT 2 WHERE c = " + istek.ham_govde)
        sirket.db.ham_sorgu("SELECT 3 WHERE d = " + sirket.db.kacis(girdi("d")))
        sirket.db.ham_sorgu("SELECT 4 WHERE e = " + istek.govde)
""")


def _sql(analysis):
    return sorted((f.line, f.source_label) for f in analysis.flows if f.sink_kind == "sql")


class CustomRulesHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": self.temp.name})
        self.env.start()
        os.environ.pop("SNIPER_TAINT_MODELS", None)
        taint_models._load.cache_clear()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()
        taint_models._load.cache_clear()

    def test_hook_flag(self):
        self.assertTrue(taint_models.CUSTOM_RULES_HOOK)
        self.assertTrue(dsl.status().get("active") or not dsl.list_rules())

    def test_saved_rule_activates_sources_and_sinks_without_env(self):
        self.assertEqual(_sql(taint_flow.analyze_source(CODE, "ornek.py")), [])
        dsl.save_rule(RULE)
        # Önbellek temizlenmeden: compiled dizininin mtime'ı anahtarda olduğu için yeni kural görülür.
        self.assertEqual(_sql(taint_flow.analyze_source(CODE, "ornek.py")),
                         [(8, "request"), (9, "request"), (10, "stored")])
        status = taint_models.model_status()["python"]
        self.assertGreaterEqual(status["sources"], 2)
        dsl.delete_rule("sirket-kaynak")
        self.assertEqual(_sql(taint_flow.analyze_source(CODE, "ornek.py")), [])

    def test_unsafe_compiled_file_is_ignored(self):
        dsl.save_rule(RULE)
        compiled = Path(dsl.custom_model_paths()[0])
        os.chmod(compiled, 0o666)
        taint_models._load.cache_clear()
        self.assertEqual(_sql(taint_flow.analyze_source(CODE, "ornek.py")), [])
        os.chmod(compiled, 0o600)
        os.chmod(compiled.parent.parent, 0o755)  # güvensiz dizin: kurallar hiç yüklenmez
        taint_models._load.cache_clear()
        self.assertEqual(_sql(taint_flow.analyze_source(CODE, "ornek.py")), [])

    def test_no_data_dir_side_effect(self):
        taint_models.models_for("python")
        self.assertFalse((Path(self.temp.name) / "custom-rules").exists())


class ModelSourcesApiTests(unittest.TestCase):
    def _models(self, data):
        models = taint_models.LanguageModels()
        taint_models._merge(models, {"format": taint_models.MODEL_FORMAT, **data}, "test")
        return models

    def test_source_lookup(self):
        models = self._models({"sources": [
            {"names": ["a.b.girdi", "oku()"]},
            {"calls": ["*.kullanici_girdisi"], "label": "pii"},
            {"attributes": ["istek.govde", "*.ham"], "label": "stored"},
        ]})
        self.assertEqual(models.source_for("a.b.girdi"), "request")
        self.assertEqual(models.source_for("oku"), "request")
        self.assertEqual(models.source_for("x.y.kullanici_girdisi"), "pii")
        self.assertIsNone(models.source_for("kullanici_girdisi"))
        self.assertIsNone(models.source_for("a.b.baska"))
        self.assertEqual(models.attribute_source_for("istek.govde"), "stored")
        self.assertEqual(models.attribute_source_for("self.ham"), "stored")
        self.assertIsNone(models.attribute_source_for("istek.baslik"))

    def test_invalid_sources_rejected(self):
        for bad in ({"label": "kotu", "names": ["x"]}, {"names": []}, "metin", {"names": [3]}):
            with self.assertRaises(ValueError):
                self._models({"sources": [bad]})


if __name__ == "__main__":
    unittest.main()
