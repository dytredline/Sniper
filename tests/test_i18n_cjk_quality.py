"""Quality gates for the Japanese, Simplified Chinese and Korean UI overlays."""
from __future__ import annotations

from pathlib import Path
import re
import unicodedata
import unittest

import i18n_server


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
LOCALES = ("ja", "zh-CN", "ko")

# These strings are visible before a user opens a feature panel.  They must be
# native translations, not English fallback, in every advertised CJK locale.
LAUNCH_SURFACE = {
    "Sniper — Yerel güvenlik stüdyosu",
    "Sniper ana sayfa",
    "YEREL GÜVENLİK STÜDYOSU",
    "Sniper, düşük etkili kontroller yapar. DoS trafiği veya parola listesi çalıştırmaz.",
    "BAĞIMSIZ GÜVENLİK GÖRÜNÜMÜ",
    "Riskleri erken görün,",
    "kontrol sizde kalsın.",
    "Eklediğiniz web varlıklarında temel güvenlik kontrollerini tek merkezden yönetin ve iyileştirmeleri ölçün.",
    "Hızlı erişim",
    "En fazla 3 GET isteği, sömürü yok, parola denemesi yok.",
    "KAPSAM YÖNETİMİ",
    "Web adresini ekleyin; alan adı sahiplik dosyası veya ayrı doğrulama adımı gerekmez.",
    "＋ Yeni hedef",
    "Alan adı ara…",
    "Web varlığı",
    "Son puan",
    "Taramalar",
    "İlk hedefinizi ekleyin",
    "Web adresini kaydettikten sonra güvenli temel taramayı doğrudan başlatabilirsiniz.",
    "Yeni hedef ekle",
    "Sniper — Giriş",
    "Doğrulama kodu (6 hane)",
    "ya da kurtarma kodu",
    "Hesabınızı kaybettiyseniz yönetici, sunucuda",
    "ile sıfırlayabilir.",
}

COMPACT_CONTROLS = {
    "Kaydet",
    "Kapat",
    "Taramayı başlat",
    "Analizi başlat",
    "Hedef seçin",
    "＋ Yeni hedef",
    "Yeni hedef ekle",
    "Oturum aç",
    "Giriş yap",
    "Doğrula",
    "Doğrulama kodu (6 hane)",
    "ya da kurtarma kodu",
}


def _rows(locale: str) -> list[tuple[int, str, str, str]]:
    text = (STATIC / f"i18n-{locale}.tsv").read_text(encoding="utf-8")
    rows: list[tuple[int, str, str, str]] = []
    for line_number, line in enumerate(text.splitlines()[1:], 2):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise AssertionError(f"{locale}:{line_number}: malformed TSV row")
        rows.append((line_number, fields[0], fields[1], fields[2]))
    return rows


def _display_width(value: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in {"W", "F", "A"} else 1 for char in value)


class CjkDictionaryQualityTests(unittest.TestCase):
    def test_rows_are_nonempty_unique_and_placeholder_safe(self) -> None:
        for locale in LOCALES:
            rows = _rows(locale)
            identities = [(kind, source) for _, kind, source, _ in rows]
            self.assertEqual(len(identities), len(set(identities)), f"{locale}: duplicate key")
            for line_number, kind, source, target in rows:
                with self.subTest(locale=locale, line=line_number, source=source):
                    self.assertIn(kind, {"S", "P", "F"})
                    self.assertTrue(source.strip())
                    self.assertTrue(target.strip())
                    self.assertEqual(source, source.strip())
                    self.assertEqual(target, target.strip())
                    self.assertEqual(
                        sorted(re.findall(r"\{\d+\}", source)),
                        sorted(re.findall(r"\{\d+\}", target)),
                    )
                    self.assertNotRegex(target, r"<[^>]+>")
                    self.assertNotRegex(target, r"[çğıöşüÇĞİÖŞÜ]")

    def test_launch_and_login_surfaces_never_fall_back_to_english(self) -> None:
        english = i18n_server.translator("en")
        for locale in LOCALES:
            local = i18n_server.parse_dictionary(
                (STATIC / f"i18n-{locale}.tsv").read_text(encoding="utf-8")
            )["strings"]
            for source in LAUNCH_SURFACE:
                with self.subTest(locale=locale, source=source):
                    self.assertIn(source, local)
                    self.assertNotEqual(local[source], english.text(source))

    def test_packs_do_not_contain_another_cjk_writing_system(self) -> None:
        forbidden = {
            "ja": re.compile(r"[\uac00-\ud7af]"),
            "zh-CN": re.compile(r"[\u3040-\u30ff\uac00-\ud7af]"),
            "ko": re.compile(r"[\u3040-\u30ff]"),
        }
        for locale in LOCALES:
            for line_number, _, source, target in _rows(locale):
                with self.subTest(locale=locale, line=line_number, source=source):
                    self.assertNotRegex(target, forbidden[locale])

    def test_login_help_keeps_the_command_and_uses_natural_local_segments(self) -> None:
        source = (
            '<html lang="tr"><p>Hesabınızı kaybettiyseniz yönetici, sunucuda '
            '<code>cli_reports.py users reset-password</code> ile sıfırlayabilir.</p></html>'
        )
        expected = {
            "ja": "アカウントにアクセスできない場合、管理者はサーバー上で <code>cli_reports.py users reset-password</code> を使ってリセットできます。",
            "zh-CN": "如果您无法访问帐户，管理员可以在服务器上使用 <code>cli_reports.py users reset-password</code> 进行重置。",
            "ko": "계정에 접근할 수 없는 경우 관리자가 서버에서 <code>cli_reports.py users reset-password</code> 명령으로 재설정할 수 있습니다.",
        }
        for locale, sentence in expected.items():
            with self.subTest(locale=locale):
                localized = i18n_server.localize_html(source, locale)
                self.assertIn(sentence, localized)
                self.assertNotIn("If you lost access", localized)

    def test_compact_control_translations_fit_the_wrapping_contract(self) -> None:
        for locale in LOCALES:
            local = i18n_server.parse_dictionary(
                (STATIC / f"i18n-{locale}.tsv").read_text(encoding="utf-8")
            )["strings"]
            for source in COMPACT_CONTROLS:
                with self.subTest(locale=locale, source=source):
                    self.assertIn(source, local)
                    self.assertLessEqual(_display_width(local[source]), 32)


if __name__ == "__main__":
    unittest.main()
