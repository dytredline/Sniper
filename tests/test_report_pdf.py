"""PDF rapor (17. tur): ?format=pdf rotaları, hata iletileri, sınırlar ve (pinli bwrap + Node + Chromium +
playwright-core varsa) gerçek, ağsız uçtan uca üretim. Bileşenler yoksa gerçek testler atlanır."""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import auth  # noqa: E402
import project_analyzer  # noqa: E402
import report_pdf  # noqa: E402

VULN = 'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n'
PDFTOTEXT = shutil.which("pdftotext")


def _ready() -> str | None:
    state = report_pdf.readiness()
    return None if state["available"] else state["reason"]


def _pdf_text(pdf: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".pdf") as handle:
        handle.write(pdf)
        handle.flush()
        return subprocess.run([PDFTOTEXT, handle.name, "-"], capture_output=True, text=True, timeout=30,
                              check=True).stdout


class _DataDir(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="sbx-pdf-")
        self.data = Path(self.tmp.name) / "data"
        self.data.mkdir(mode=0o700)
        self.env_patch = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data),
                                                      "SNIPER_SANDBOX_LAUNCH": "direct"})
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()


class UnitTests(unittest.TestCase):
    def test_filename_and_validation(self) -> None:
        self.assertEqual(report_pdf.filename_for("sniper-project-prj_1.html"), "sniper-project-prj_1.pdf")
        self.assertEqual(report_pdf.filename_for('a"b;c.html'), "a_b_c.pdf")
        with self.assertRaises(ValueError):
            report_pdf.render_pdf("<p>x</p>", page_format="A0")
        with self.assertRaises(report_pdf.ReportPdfError) as caught:
            report_pdf.render_pdf("x" * (report_pdf.MAX_HTML_BYTES + 1))
        self.assertEqual(caught.exception.reason, "rapor_cok_buyuk")

    def test_unavailable_components_reported(self) -> None:
        with mock.patch.object(report_pdf, "readiness", return_value={"available": False, "reason": "chromium_yok"}):
            with self.assertRaises(report_pdf.ReportPdfUnavailable) as caught:
                report_pdf.render_pdf("<p>x</p>")
        self.assertEqual(caught.exception.reason, "chromium_yok")

    def test_reader_role_can_download(self) -> None:
        for path in ("/api/scans/scan_1/report.html", "/api/project-audits/prj_1/report.html",
                     "/api/project-audits/prj_1/executive-summary.html"):
            self.assertEqual(auth.required_level("GET", path), "read")

    def test_timeout_bounds(self) -> None:
        with mock.patch.dict(os.environ, {"SNIPER_PDF_TIMEOUT_SECONDS": "9999"}):
            self.assertEqual(report_pdf._timeout(), report_pdf.MAX_TIMEOUT)
        with mock.patch.dict(os.environ, {"SNIPER_PDF_TIMEOUT_SECONDS": "x"}):
            self.assertEqual(report_pdf._timeout(), report_pdf.DEFAULT_TIMEOUT)


class ServerRouteTests(_DataDir):
    def setUp(self) -> None:
        super().setUp()
        import server
        from storage import Store

        self.server = server
        self.root = Path(self.tmp.name) / "proj"
        self.root.mkdir()
        (self.root / "app.py").write_text(VULN)
        self.previous = (server.STORE, server.LIMITER)
        server.STORE = Store(self.data / "sniper-test.db")
        server.LIMITER = server.RateLimiter(limit=100000)
        patch = mock.patch.object(project_analyzer, "_allowed_roots", return_value=(Path(self.tmp.name),))
        patch.start()
        self.addCleanup(patch.stop)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.audit = self.call("POST", "/api/project-audits", {"project_path": str(self.root)})[2]

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE, self.server.LIMITER = self.previous
        super().tearDown()

    def call(self, method: str, path: str, body=None):
        request = urllib.request.Request(self.base + path, method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read()
                kind = response.headers.get("Content-Type", "")
                return response.status, response.headers, (json.loads(raw) if "json" in kind else raw)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, json.loads(exc.read() or b"{}")

    def test_pdf_route_passes_localized_html_and_headers(self) -> None:
        seen = []

        def fake(document, page_format="A4"):
            seen.append(document)
            return b"%PDF-1.4 sahte"
        with mock.patch.object(report_pdf, "render_pdf", side_effect=fake):
            status, headers, body = self.call("GET", f"/api/project-audits/{self.audit['id']}/report.html?format=pdf&lang=en")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "application/pdf")
            self.assertIn(f'filename="sniper-project-{self.audit["id"]}.pdf"', headers["Content-Disposition"])
            self.assertEqual(body, b"%PDF-1.4 sahte")
            self.assertIn('lang="en"', seen[-1])
            status, headers, _ = self.call("GET", f"/api/project-audits/{self.audit['id']}/executive-summary.html?format=pdf")
            self.assertEqual(status, 200)
            self.assertIn("sniper-executive-", headers["Content-Disposition"])
            self.assertIn('lang="tr"', seen[-1])
        # HTML davranışı değişmedi; bilinmeyen biçim reddedilir.
        status, headers, _ = self.call("GET", f"/api/project-audits/{self.audit['id']}/report.html")
        self.assertEqual((status, headers["Content-Type"]), (200, "text/html; charset=utf-8"))
        self.assertEqual(self.call("GET", f"/api/project-audits/{self.audit['id']}/report.html?format=docx")[0], 400)

    def _completed_scan(self) -> dict:
        from scanner import normalize_target
        store = self.server.STORE
        target = store.create_target(normalize_target("https://pdf-test.example.com"))
        scan = store.create_scan(target["id"])
        store.mark_scan_running(scan["id"])
        store.complete_scan(scan["id"], {"score": 80, "grade": "B", "counts": {"medium": 1}, "metadata": {}, "scope": {},
                                         "findings": [{"id": "f1", "severity": "medium", "title": "Eksik başlık"}]})
        return store.get_scan(scan["id"])

    def test_scan_report_pdf_route(self) -> None:
        scan = self._completed_scan()
        with mock.patch.object(report_pdf, "render_pdf", return_value=b"%PDF-1.4 tarama") as fake:
            status, headers, body = self.call("GET", f"/api/scans/{scan['id']}/report.html?format=pdf&lang=en")
        self.assertEqual((status, headers["Content-Type"], body), (200, "application/pdf", b"%PDF-1.4 tarama"))
        self.assertIn(f'filename="sniper-{scan["id"]}.pdf"', headers["Content-Disposition"])
        self.assertIn("pdf-test.example.com", fake.call_args.args[0])
        self.assertEqual(self.call("GET", f"/api/scans/{scan['id']}/report.html?format=x")[0], 400)
        self.assertEqual(self.call("GET", f"/api/scans/{scan['id']}/report.html")[0], 200)

    def test_error_messages(self) -> None:
        path = f"/api/project-audits/{self.audit['id']}/report.html?format=pdf"
        cases = [(report_pdf.ReportPdfUnavailable("chromium_yok"), 503, "hazır değil (chromium_yok)"),
                 (report_pdf.ReportPdfBusy("mesgul"), 503, "Başka bir PDF"),
                 (report_pdf.ReportPdfError("rapor_cok_buyuk"), 413, "çok büyük"),
                 (report_pdf.ReportPdfError("sure_asildi"), 500, "sure_asildi")]
        for exc, code, text in cases:
            with self.subTest(code=code), mock.patch.object(report_pdf, "render_pdf", side_effect=exc):
                status, _, body = self.call("GET", path)
                self.assertEqual(status, code)
                self.assertIn(text, body["error"])

    @unittest.skipIf(_ready() is not None, f"PDF sandbox bileşenleri yok: {_ready()}")
    def test_real_project_report_pdf(self) -> None:
        status, headers, body = self.call("GET", f"/api/project-audits/{self.audit['id']}/report.html?format=pdf&lang=en")
        self.assertEqual(status, 200, body)
        self.assertTrue(body.startswith(b"%PDF-"))
        if PDFTOTEXT:
            text = _pdf_text(body)
            self.assertIn("proj", text)
            self.assertNotIn("Doğrulanmış veri akışı", text)  # İngilizce


class _Beacon(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self) -> None:
        type(self).hits += 1
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args) -> None:
        pass


@unittest.skipIf(_ready() is not None, f"PDF sandbox bileşenleri yok: {_ready()}")
class RealRenderTests(_DataDir):
    def test_isolated_render_without_network_or_scripts(self) -> None:
        beacon = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Beacon)
        threading.Thread(target=beacon.serve_forever, daemon=True).start()
        self.addCleanup(beacon.server_close)
        self.addCleanup(beacon.shutdown)
        port = beacon.server_address[1]
        document = (
            "<!doctype html><html lang='tr'><head><meta charset='utf-8'><title>Deneme</title>"
            f"<link rel='stylesheet' href='http://127.0.0.1:{port}/a.css'></head><body>"
            "<h1>Sniper raporu ğüşıöç İŞĞ</h1>"
            f"<img src='http://127.0.0.1:{port}/b.png'><img src='file:///etc/passwd'>"
            "<iframe src='file:///etc/passwd'></iframe>"
            "<script>document.body.insertAdjacentText('beforeend','BETIKCALISTI')</script>"
            + "<p>satır</p>" * 400 + "</body></html>")
        pdf = report_pdf.render_pdf(document)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertEqual(_Beacon.hits, 0, "sandbox dışına (yerel porta) istek gitmemeli")
        if PDFTOTEXT:
            text = _pdf_text(pdf)
            self.assertIn("Sniper raporu ğüşıöç İŞĞ", text)
            self.assertNotIn("BETIKCALISTI", text)
            self.assertNotIn("root:", text)
        # İş dizini temizlenir; kilit bırakılır (ikinci üretim de çalışır).
        self.assertEqual(list((self.data / "sandbox-runs").glob("pdf-*")), [])
        self.assertTrue(report_pdf.render_pdf("<p>ikinci</p>").startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
