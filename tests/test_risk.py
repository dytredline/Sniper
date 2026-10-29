import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from risk import calculate_cvss31, normalize_cwe  # noqa: E402


class RiskClassificationTests(unittest.TestCase):
    def test_calculates_cvss31_base_score(self):
        vector, score = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(score, 9.8)

    def test_rejects_incomplete_vector(self):
        with self.assertRaises(ValueError):
            calculate_cvss31("CVSS:3.1/AV:N/AC:L")

    def test_normalizes_cwe(self):
        self.assertEqual(normalize_cwe("79"), "CWE-79")
        self.assertEqual(normalize_cwe("cwe639"), "CWE-639")
        with self.assertRaises(ValueError):
            normalize_cwe("SQL injection")
