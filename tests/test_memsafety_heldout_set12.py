"""Faz 3.3 — Bağımsız Heldout Set 12 C/C++ Bellek Motoru Doğrulama Paketi."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import memsafety_engine
from tests.test_faz3_memsafety_set12_and_dynamic import (
    HELDOUT_SET_12_SAFE,
    HELDOUT_SET_12_VULNERABLE,
)


class TestMemsafetyHeldoutSet12(unittest.TestCase):
    def test_memsafety_engine_heldout_set12_gate(self) -> None:
        result = memsafety_engine.evaluate_heldout_set_recall_and_fp(
            HELDOUT_SET_12_VULNERABLE,
            HELDOUT_SET_12_SAFE,
        )
        self.assertEqual(result["format"], "sniper-memsafety-heldout-eval/1")
        self.assertEqual(result["vulnerable_total"], 6)
        self.assertEqual(result["vulnerable_detected"], 6)
        self.assertGreaterEqual(result["recall"], 0.90)
        self.assertEqual(result["false_positives"], 0)
        self.assertTrue(result["gate_passed"])


if __name__ == "__main__":
    unittest.main()
