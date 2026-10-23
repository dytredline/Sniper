"""İşletmecinin özel kuralı (taint_rules_dsl) sabitli Opengrep taramasına katılır."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import semgrep_active
import taint_rules_dsl

RULE = (
    "format: sniper-taint-rules-v1\nname: sirket-db\nlanguage: python\nsinks:\n"
    "  - kind: sql\n    calls: [sirket.db.ham_sorgu]\n    args: [0]\n    cwe: CWE-89\n    severity: high\n"
)


def _engine_ready() -> bool:
    try:
        engine, binary, rules = semgrep_active.active_engine()
    except Exception:
        return False
    return engine == "opengrep" and bool(binary) and bool(rules)


@unittest.skipUnless(_engine_ready(), "sabitli Opengrep yok")
class CustomOpengrepRuleTests(unittest.TestCase):
    def test_custom_sink_is_scanned_with_default_sources(self):
        home = Path.home()
        with tempfile.TemporaryDirectory(dir=home / ".local" / "state") as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            (root / "data").mkdir(mode=0o700)
            (root / "proj").mkdir(mode=0o700)
            (root / "proj" / "app.py").write_text(
                "import sirket\nfrom flask import request\ndef f():\n    q = request.args['q']\n"
                "    sirket.db.ham_sorgu(q)\n    sirket.db.ham_sorgu('sabit')\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(root / "data")}):
                taint_rules_dsl.save_rule(RULE)
                report = semgrep_active.run_local_semgrep(str(root / "proj"))
        self.assertEqual(report.get("custom_rule_count"), 1)
        lines = [f.get("line") for f in report.get("findings", []) if str(f.get("rule_id", "")).startswith("sniper-custom-")]
        self.assertEqual(lines, [5])

    def test_insecure_compiled_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": tmp}):
            compiled = taint_rules_dsl.rules_dir() / "compiled"
            compiled.mkdir(parents=True, exist_ok=True)
            target = compiled / "opengrep-custom.yaml"
            target.write_text('{"rules": []}', encoding="utf-8")
            os.chmod(target, 0o666)
            self.assertIsNone(semgrep_active._custom_opengrep_rules())


if __name__ == "__main__":
    unittest.main()
