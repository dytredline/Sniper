"""Japanese, Korean and Simplified Chinese language-pack contract."""
from __future__ import annotations

from pathlib import Path
import re
import unittest

import auth_routes
import i18n_server


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
LOCALES = {
    "ja": ("スキャンレポート", "保存"),
    "ko": ("스캔 보고서", "저장"),
    "zh-CN": ("扫描报告", "保存"),
}
LOCALIZED_DATES = {
    "ja": "2026年9月19日 13:00",
    "ko": "2026년 9월 19일 13:00",
    "zh-CN": "2026年9月19日 13:00",
}


class MultilingualServerTests(unittest.TestCase):
    def test_language_aliases_normalize_to_supported_locales(self) -> None:
        self.assertEqual(i18n_server.normalize_lang("JA"), "ja")
        self.assertEqual(i18n_server.normalize_lang("ko_KR"), "ko")
        self.assertEqual(i18n_server.normalize_lang("zh"), "zh-CN")
        self.assertEqual(i18n_server.normalize_lang("zh-hans"), "zh-CN")
        self.assertEqual(i18n_server.normalize_lang("de"), "tr")

    def test_language_packs_translate_reports_and_preserve_code(self) -> None:
        source = '<html lang="tr"><body><h1>Tarama raporu</h1><button title="Kaydet">Kaydet</button><code>Kaydet</code></body></html>'
        for locale, (report, save) in LOCALES.items():
            with self.subTest(locale=locale):
                out = i18n_server.localize_html(source, locale)
                self.assertIn(f'<html lang="{locale}">', out)
                self.assertIn(f"<h1>{report}</h1>", out)
                self.assertIn(f'title="{save}"', out)
                self.assertIn(f">{save}</button>", out)
                self.assertIn("<code>Kaydet</code>", out)

    def test_turkish_formatted_dates_follow_selected_cjk_locale(self) -> None:
        for locale, expected in LOCALIZED_DATES.items():
            with self.subTest(locale=locale):
                self.assertEqual(i18n_server.translator(locale).text("19 Eyl 2026 13:00"), expected)

    def test_language_pack_shape_and_placeholder_integrity(self) -> None:
        for locale in LOCALES:
            with self.subTest(locale=locale):
                path = STATIC / f"i18n-{locale}.tsv"
                text = path.read_text(encoding="utf-8")
                self.assertTrue(text.startswith(f"# sniper-i18n/1\t{locale}\n"))
                rows = [line.split("\t") for line in text.splitlines()[1:] if line]
                self.assertGreaterEqual(len(rows), 220)
                self.assertTrue(all(len(row) == 3 and row[0] in {"S", "P", "F"} for row in rows))
                sources = [row[1] for row in rows]
                self.assertEqual(len(sources), len(set(sources)), "duplicate source key")
                self.assertTrue(all(row[1] and row[2] for row in rows))
                self.assertTrue(all(not re.search(r"<[^>]+>", row[2]) for row in rows))
                data = i18n_server.parse_dictionary(text)
                self.assertGreaterEqual(
                    len(data["strings"]) + len(data["patterns"]) + len(data["fragments"]),
                    220,
                )
                for source, target in data["patterns"]:
                    self.assertEqual(
                        sorted(re.findall(r"\{\d+\}", source)),
                        sorted(re.findall(r"\{\d+\}", target)),
                        source,
                    )

    def test_login_gate_exposes_every_language_pack(self) -> None:
        for locale in LOCALES:
            self.assertIn(f"i18n-{locale}.tsv", auth_routes.LOGIN_ASSETS)


if __name__ == "__main__":
    unittest.main()
