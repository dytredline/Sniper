"""Burp sitemap durum kodu yalnız ASCII ondalık 100..599 (tam üç rakam) olmalı."""

from __future__ import annotations

import unittest

from tool_report_burp_sitemap import parse_burp_sitemap_summary


def report(status: str) -> str:
    return "<items><item><status>" + status + "</status></item></items>"


class BurpStatusAsciiDecimalTests(unittest.TestCase):
    def test_exported_ascii_decimal_statuses_are_aggregated(self):
        for raw in ("100", "200", "404", "599"):
            with self.subTest(raw=raw):
                summary = parse_burp_sitemap_summary(report(raw))
                self.assertEqual(summary["status_counts"], {raw: 1})
                self.assertEqual(summary["item_count"], 1)

    def test_surrounding_xml_whitespace_is_trimmed(self):
        for raw in (" 200", "200 ", " 404 ", "\n200\n"):
            with self.subTest(raw=repr(raw)):
                summary = parse_burp_sitemap_summary(report(raw))
                self.assertEqual(summary["status_counts"], {raw.strip(): 1})

    def test_alternative_numeric_spellings_are_rejected(self):
        for raw in (
            "٢٠٠",  # Arapça-Hint rakamları "٢٠٠"
            "２００",  # tam genişlik "２００"
            "+200",
            "-200",
            "2_00",
            "0200",
            "200.0",
            "",
            " ",
            "2 00",
            "\u00a0200",
        ):
            with self.subTest(raw=repr(raw)):
                with self.assertRaises(ValueError) as cm:
                    parse_burp_sitemap_summary(report(raw))
                self.assertEqual(str(cm.exception), "Geçersiz XML.")

    def test_out_of_range_three_digit_statuses_are_rejected(self):
        for raw in ("099", "600", "999", "99", "1000"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_burp_sitemap_summary(report(raw))


if __name__ == "__main__":
    unittest.main()
