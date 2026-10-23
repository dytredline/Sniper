import hashlib
import json
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class BurpSitemapSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def request_json(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method="GET" if payload is None else "POST",
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read())
        except HTTPError as e:
            raise e

    def test_burp_summary_benign_dtd(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ELEMENT item (status, mimetype?)>
<!ELEMENT status (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
]>
<items>
  <item>
    <status>200</status>
    <mimetype>HTML</mimetype>
  </item>
  <item>
    <status>404</status>
    <mimetype>JSON</mimetype>
  </item>
</items>'''
        result = self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(result["format"], "burp-sitemap-xml")
        self.assertEqual(result["item_count"], 2)
        self.assertEqual(result["status_counts"], {"200": 1, "404": 1})
        self.assertEqual(result["mimetype_counts"], {"HTML": 1, "JSON": 1, "XML": 0, "OTHER": 0, "UNKNOWN": 0})
        self.assertIn("report_sha256", result)

    def test_burp_summary_empty_items(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
]>
<items/>'''
        result = self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(result["item_count"], 0)
        self.assertEqual(result["status_counts"], {})
        self.assertEqual(result["mimetype_counts"], {"HTML": 0, "JSON": 0, "XML": 0, "OTHER": 0, "UNKNOWN": 0})

    def test_burp_summary_missing_mimetype_maps_unknown(self):
        xml = '''<?xml version="1.0"?>
<items>
  <item>
    <status>200</status>
  </item>
</items>'''
        result = self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(result["item_count"], 1)
        self.assertEqual(result["mimetype_counts"]["UNKNOWN"], 1)

    def test_burp_summary_non_html_json_xml_maps_other(self):
        xml = '''<?xml version="1.0"?>
<items>
  <item>
    <status>200</status>
    <mimetype>image/png</mimetype>
  </item>
</items>'''
        result = self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(result["mimetype_counts"]["OTHER"], 1)

    def test_burp_summary_entity_declaration_rejected_http_400(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE items [
<!ENTITY foo "bar">
]>
<items/>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("foo", error_body)

    def test_burp_summary_external_dtd_rejected_http_400(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE items SYSTEM "http://example.com/dtd">
<items/>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_too_many_items_http_400(self):
        items = "".join(["<item><status>200</status></item>" for _ in range(501)])
        xml = f"<items>{items}</items>"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_wrong_root_http_400(self):
        xml = "<root/>"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_missing_status_http_400(self):
        xml = "<items><item/></items>"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_invalid_status_http_400(self):
        xml = "<items><item><status>99</status></item></items>"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_exact_output_keys(self):
        xml = "<items><item><status>200</status></item></items>"
        result = self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(set(result.keys()), {"format", "item_count", "status_counts", "mimetype_counts", "report_sha256"})

    def test_burp_summary_report_sha256_correct(self):
        xml = "<items><item><status>200</status></item></items>"
        result = self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        expected = {
            "item_count": 1,
            "status_counts": {"200": 1},
            "mimetype_counts": {"HTML": 0, "JSON": 0, "XML": 0, "OTHER": 0, "UNKNOWN": 1}
        }
        canonical = json.dumps(expected, sort_keys=True, separators=(",", ":"))
        expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.assertEqual(result["report_sha256"], expected_sha)

    def test_burp_summary_non_string_report_http_400(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": ["not-a-string"]})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_duplicate_status_across_items_allowed(self):
        xml = "<items><item><status>200</status></item><item><status>200</status></item></items>"
        result = self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(result["item_count"], 2)
        self.assertEqual(result["status_counts"], {"200": 2})

    def test_burp_summary_duplicate_direct_status_http_400(self):
        xml = "<items><item><status>200</status><status>200</status></item></items>"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_duplicate_direct_mimetype_http_400(self):
        xml = "<items><item><status>200</status><mimetype>HTML</mimetype><mimetype>HTML</mimetype></item></items>"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)

    def test_burp_summary_report_over_60k_http_400(self):
        large_body = "x" * 60_001
        xml = f"<items><item><status>200</status><mimetype>HTML</mimetype></item></items>{large_body}"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/burp-sitemap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
