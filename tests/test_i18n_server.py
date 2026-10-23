"""İngilizce dil desteği: HTML raporların ?lang=en çevirisi, sözlük dosyası ve giriş sayfası varlıkları."""
from __future__ import annotations

from pathlib import Path
import re
import unittest

import auth_routes
import i18n_server

APP = Path(__file__).resolve().parents[1]
STATIC = APP / "static"


class LocalizeHtmlTests(unittest.TestCase):
    def test_turkish_and_unknown_language_leave_document_untouched(self):
        doc = '<html lang="tr"><body><h1>Tarama raporu</h1></body></html>'
        self.assertIs(i18n_server.localize_html(doc, "tr"), doc)
        self.assertIs(i18n_server.localize_html(doc, None), doc)
        self.assertIs(i18n_server.localize_html(doc, "de"), doc)

    def test_english_translates_text_attributes_and_lang(self):
        doc = ('<html lang="tr"><head><title>Tarama raporu</title><style>.a{content:"Kaydet"}</style></head>'
               '<body><h1 title="Kapat">Tarama raporu</h1><p>Önem: Yüksek</p><code>Kaydet</code>'
               '<p>app/models.py</p><li>• Bu sonuç statik ve düşük etkili bir ön incelemedir; çalışan uygulama davranışını kanıtlamaz.</li></body></html>')
        out = i18n_server.localize_html(doc, "en")
        self.assertIn('<html lang="en">', out)
        self.assertIn("<title>Scan report</title>", out)
        self.assertIn('title="Close"', out)
        self.assertIn("<p>Severity: High</p>", out)
        self.assertIn('content:"Kaydet"', out, "style içeriği çevrilmez")
        self.assertIn("<code>Kaydet</code>", out, "kod içeriği çevrilmez")
        self.assertIn("<p>app/models.py</p>", out, "sözlükte olmayan veri olduğu gibi kalır")
        self.assertIn("• This result is a static, low-impact pre-review", out)

    def test_patterns_dates_and_escaping(self):
        tr = i18n_server.translator()
        self.assertEqual(tr.text("İstek 503 durum koduyla başarısız oldu."), "Request failed with status code 503.")
        self.assertEqual(tr.text("Veri 31 günlük · 19 Eyl 2026 13:00 · 2 bulgu"), "Data 31 days · 19 Sep 2026 13:00 · 2 findings")
        self.assertEqual(tr.text("12 sn"), "12 s")
        self.assertEqual(tr.text("Yarın sn"), "Yarın sn")
        out = i18n_server.localize_html("<p>Henüz ölçüm yok. scripts/eval_pipeline.py --config &lt;yapılandırma&gt; ile ilk ölçümü çalıştırın.</p>", "en")
        self.assertIn("&lt;configuration&gt;", out, "çeviri HTML olarak kaçışlanır")

    def test_flow_titles_and_free_form_evidence(self):
        tr = i18n_server.translator()
        self.assertEqual(
            tr.text("Olası veri akışı (dosyalar arası, 2 çağrı): istek girdisi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)"),
            "Possible data flow (cross-file, 2 calls): request input reaches an SQL query (SQL injection)")
        self.assertEqual(
            tr.text("Yetkili bağlamda veri akışı (yönetici yetkisi gerekli): istek/URL girdisi HTML bağlamına ulaşıyor (XSS)"),
            "Data flow in a privileged context (administrator privileges required): request/URL input reaches an HTML context (XSS)")
        self.assertEqual(
            tr.text("Doğrulanmış veri akışı (kayıtlı veri): veritabanından okunan veri HTML bağlamına ulaşıyor (XSS)"),
            "Verified data flow (stored data): data read from the database reaches an HTML context (XSS)")
        evidence = ("Veri akışı: $_POST['id'] (wp-admin/a.php satır 12) → anonim fonksiyon() → echo/print (satır 30); "
                    "kaynak satır içeriği kaydedilmedi. Akış yetki/nonce denetimi yapılan bir yöntemde: yalnız yetkili "
                    "(yönetici) kullanıcı tetikleyebilir.")
        out = tr.text(evidence)
        self.assertNotRegex(out, "[çğıöşüÇĞİÖŞÜ]")
        self.assertIn("$_POST['id'] (wp-admin/a.php line 12) → anonymous function() → echo/print (line 30)", out)
        self.assertEqual(tr.text("dosya_adı.py"), "dosya_adı.py", "parça içermeyen veri değişmez")

    def test_notification_prefix_comma_list_and_container_titles(self):
        # 22. tur QA: bildirim satırları "[critical] Başlık — yer" ve "N kritik, M yüksek" listeleri tam çevrilir.
        tr = i18n_server.translator()
        self.assertEqual(tr.text("pygoat analizi tamamlandı (14 kritik, 19 yüksek, 15 orta, 18 düşük)."),
                         "pygoat analysis completed (14 critical, 19 high, 15 medium, 18 low).")
        self.assertEqual(tr.text("[high] Açıklı dil paketi: lodash 4.17.15 (GHSA-x) — app/package.json"),
                         "[high] Vulnerable language package: lodash 4.17.15 (GHSA-x) — app/package.json")
        self.assertEqual(tr.text("Elma, armut ve kiraz"), "Elma, armut ve kiraz")
        self.assertEqual(tr.text("İzinli hedef, seçili kapsam spider ve site-aktif profilleri"),
                         "Authorized target, selected-scope spider and site-active profiles")

    def test_truncated_threat_model_labels(self):
        # Tehdit modeli SVG etiketleri kırpılmış gelir ("…"); arayüzdeki lookupTruncated ile aynı kural.
        tr = i18n_server.translator()
        self.assertEqual(tr.text("Kullanıcı / istemci…"), "User / client (Inte…")
        self.assertEqual(tr.text("Ortam değişkenleri /…"), "Environment variable…")
        self.assertEqual(tr.text("Üçüncü taraf HTTP…"), "Third-party HTTP…")
        self.assertEqual(tr.text("Bilinmeyen kırpık…"), "Bilinmeyen kırpık…")

    def test_report_helper_uses_request_language(self):
        import server

        class Handler:
            _report_lang = "en"
        doc = '<html lang="tr"><body><h2>Yönetici özeti</h2></body></html>'
        self.assertIn("Executive summary", server._localized_report(doc, Handler()))
        self.assertEqual(server._localized_report(doc, object()), doc)


class DictionaryAndAssetsTests(unittest.TestCase):
    def test_dictionary_shape(self):
        text = (STATIC / "i18n-en.tsv").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# sniper-i18n/1\ten\n"))
        data = i18n_server.parse_dictionary(text)
        self.assertGreater(len(data["strings"]), 3000)
        for src, dst in data["patterns"]:
            self.assertEqual(sorted(re.findall(r"\{\d+\}", src)), sorted(re.findall(r"\{\d+\}", dst)), src)

    def test_self_analysis_does_not_scan_dictionary_text(self):
        # Sözlükteki kural açıklamaları (.json olsaydı) proje analizinde bulgu üretirdi; .tsv analiz dışıdır.
        import project_analyzer
        self.assertNotIn(".tsv", project_analyzer.SOURCE_EXTENSIONS)
        self.assertFalse((STATIC / "i18n-en.json").exists())

    def test_login_page_can_load_language_layer_without_session(self):
        self.assertIn("i18n.js", auth_routes.LOGIN_ASSETS)
        self.assertIn("i18n-en.tsv", auth_routes.LOGIN_ASSETS)
        self.assertIn("ui-refresh.css", auth_routes.LOGIN_ASSETS)  # giriş sayfası Codex stili oturumsuz yüklenir

    def test_pages_load_language_layer_first_and_have_selector(self):
        # index.html: auth.js (fetch sarmalayıcı) ilk betik kalır; dil katmanı ondan hemen sonra, panel betiklerinden önce.
        for page, first_app_script in (("index.html", "/job_queue.js"), ("login.html", "/login.js")):
            html = (STATIC / page).read_text(encoding="utf-8")
            self.assertLess(html.index('src="/i18n.js'), html.index(f'src="{first_app_script}'), page)
            self.assertIn("data-i18n-lang-select", html)
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>", "satır içi betik yok (CSP)")


if __name__ == "__main__":
    unittest.main()
