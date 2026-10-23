import json
from pathlib import Path
import unittest

from cvss40 import compute_cvss40, cvss40_severity, parse_cvss40_vector
from cvss40_tables import CVSS_LOOKUP, SOURCE_COMMIT


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cvss40_first_reference_scores.json"


class Cvss40ReferenceTests(unittest.TestCase):
    def test_matches_official_first_calculator_outputs(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertIn(SOURCE_COMMIT, data["source"])
        self.assertGreaterEqual(len(data["vectors"]), 150)
        for vector, expected in data["vectors"]:
            with self.subTest(vector=vector):
                self.assertEqual(compute_cvss40(vector)["score"], float(expected))

    def test_well_known_values(self):
        cases = {
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": 10.0,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.3,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N": 0.0,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(compute_cvss40(vector)["score"], expected)

    def test_threat_and_environmental_metrics_change_score(self):
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        unreported = compute_cvss40(base + "/E:U")
        self.assertLess(unreported["score"], compute_cvss40(base)["score"])
        self.assertEqual(unreported["macro_vector"][4], "2")
        safety = compute_cvss40(base + "/MSI:S")
        self.assertEqual(safety["macro_vector"][3], "0")
        self.assertEqual(compute_cvss40(base + "/E:X")["score"], compute_cvss40(base)["score"])

    def test_lookup_table_complete(self):
        self.assertEqual(len(CVSS_LOOKUP), 270)
        self.assertTrue(all(0.0 <= value <= 10.0 for value in CVSS_LOOKUP.values()))

    def test_severity_bands(self):
        self.assertEqual(cvss40_severity(0.0), "None")
        self.assertEqual(cvss40_severity(3.9), "Low")
        self.assertEqual(cvss40_severity(4.0), "Medium")
        self.assertEqual(cvss40_severity(7.0), "High")
        self.assertEqual(cvss40_severity(9.0), "Critical")

    def test_invalid_vectors_raise(self):
        for bad in (
            "",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
            "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/E:A",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/E:A",
            "CVSS:4.0/AV:n/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/",
        ):
            with self.subTest(vector=bad):
                with self.assertRaises(ValueError):
                    compute_cvss40(bad)
        with self.assertRaises(ValueError):
            parse_cvss40_vector(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
