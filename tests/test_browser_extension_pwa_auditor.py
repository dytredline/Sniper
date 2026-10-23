import json
from pathlib import Path
import tempfile
import unittest

from browser_extension_pwa_auditor import (
    audit_extension_manifest_inline,
    audit_extension_pwa_project,
    audit_extension_script_inline,
    audit_service_worker_inline,
)


def _pairs(report):
    return {(item["control_id"], item["severity"], item["cwe"]) for item in report["findings"]}


RISKY_MV2_MANIFEST = json.dumps(
    {
        "manifest_version": 2,
        "name": "Risky Helper",
        "version": "1.0",
        "permissions": ["<all_urls>", "cookies", "debugger", "webRequest", "webRequestBlocking"],
        "content_security_policy": "script-src 'self' 'unsafe-eval' https://cdn.example.com; object-src 'self'",
        "externally_connectable": {"matches": ["*://*/*"]},
        "web_accessible_resources": ["*"],
        "background": {"scripts": ["bg.js"], "persistent": True},
        "update_url": "http://updates.example.com/ext.xml",
    },
    indent=2,
)

SAFE_MV3_MANIFEST = json.dumps(
    {
        "manifest_version": 3,
        "name": "Safe Notes",
        "version": "1.0.0",
        "permissions": ["storage"],
        "host_permissions": ["https://api.example.com/*"],
        "background": {"service_worker": "background.js"},
        "content_security_policy": {"extension_pages": "script-src 'self'; object-src 'self'"},
    },
    indent=2,
)

CLEAN_SERVICE_WORKER = """const STATIC_ASSETS = ['/', '/index.html', '/styles.css', '/app.js'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open('static-v1').then((cache) => cache.addAll(STATIC_ASSETS)));
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') {
    return;
  }
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request).then((response) => {
      if (!response || !response.ok || response.type !== 'basic') {
        return response;
      }
      const copy = response.clone();
      caches.open('static-v1').then((cache) => cache.put(event.request, copy));
      return response;
    }))
  );
});
"""


class ExtensionManifestTests(unittest.TestCase):
    def test_risky_mv2_manifest_findings(self):
        report = audit_extension_manifest_inline(RISKY_MV2_MANIFEST)
        self.assertEqual(report["format"], "sniper-browser-extension-manifest-audit-v1")
        self.assertEqual(report["manifest_version"], 2)
        self.assertEqual(report["extension_name"], "Risky Helper")
        self.assertEqual(report["host_permissions"], ["<all_urls>"])
        self.assertEqual(report["risk_permissions"], ["cookies", "debugger", "webRequestBlocking"])
        pairs = _pairs(report)
        self.assertIn(("SNIPER-EXT-05", "medium", "CWE-1104"), pairs)
        self.assertIn(("SNIPER-EXT-01", "high", "CWE-250"), pairs)
        self.assertIn(("SNIPER-EXT-02", "high", "CWE-95"), pairs)
        self.assertIn(("SNIPER-EXT-02", "high", "CWE-829"), pairs)
        self.assertIn(("SNIPER-EXT-03", "high", "CWE-346"), pairs)
        self.assertIn(("SNIPER-EXT-04", "medium", "CWE-200"), pairs)
        self.assertIn(("SNIPER-EXT-05", "low", "CWE-400"), pairs)
        self.assertIn(("SNIPER-EXT-05", "high", "CWE-494"), pairs)
        cookie_findings = [f for f in report["findings"] if "cookies" in str(f) and f["control_id"] == "SNIPER-EXT-01"]
        self.assertTrue(cookie_findings)
        self.assertTrue(all(f["severity"] == "high" for f in cookie_findings))
        for finding in report["findings"]:
            self.assertGreaterEqual(finding["line"], 1)

    def test_cookies_without_broad_hosts_is_medium(self):
        manifest = json.dumps(
            {
                "manifest_version": 3,
                "name": "Cookie Reader",
                "permissions": ["cookies"],
                "host_permissions": ["https://app.example.com/*"],
            }
        )
        report = audit_extension_manifest_inline(manifest)
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["severity"], "medium")
        self.assertEqual(report["findings"][0]["control_id"], "SNIPER-EXT-01")

    def test_safe_mv3_manifest_is_clean(self):
        report = audit_extension_manifest_inline(SAFE_MV3_MANIFEST)
        self.assertEqual(report["finding_count"], 0, report["findings"])
        self.assertEqual(report["manifest_version"], 3)
        self.assertEqual(report["permissions"], ["storage"])
        self.assertEqual(report["host_permissions"], ["https://api.example.com/*"])
        self.assertEqual(report["risk_permissions"], [])

    def test_mv3_content_scripts_all_urls_with_all_frames(self):
        manifest = json.dumps(
            {
                "manifest_version": 3,
                "name": "Everywhere",
                "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"], "all_frames": True}],
                "web_accessible_resources": [{"resources": ["img/logo.png"], "matches": ["<all_urls>"]}],
            },
            indent=2,
        )
        report = audit_extension_manifest_inline(manifest)
        pairs = _pairs(report)
        self.assertIn(("SNIPER-EXT-01", "high", "CWE-250"), pairs)
        self.assertIn(("SNIPER-EXT-01", "low", "CWE-1021"), pairs)
        self.assertIn(("SNIPER-EXT-04", "medium", "CWE-200"), pairs)

    def test_invalid_manifest_json_raises_value_error(self):
        with self.assertRaises(ValueError):
            audit_extension_manifest_inline("{ not json")
        with self.assertRaises(ValueError):
            audit_extension_manifest_inline("[1, 2, 3]")
        with self.assertRaises(ValueError):
            audit_extension_manifest_inline("   ")

    def test_line_comment_manifest_is_tolerated(self):
        manifest = '{\n  // comment\n  "manifest_version": 3,\n  "name": "Commented"\n}\n'
        report = audit_extension_manifest_inline(manifest)
        self.assertEqual(report["manifest_version"], 3)
        self.assertEqual(report["finding_count"], 0)


class ExtensionScriptTests(unittest.TestCase):
    def test_external_listener_without_sender_check_is_high(self):
        source = (
            "chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {\n"
            "  chrome.storage.local.get('profile', (data) => sendResponse(data));\n"
            "  return true;\n"
            "});\n"
        )
        report = audit_extension_script_inline(source)
        self.assertEqual(report["format"], "sniper-browser-extension-script-audit-v1")
        self.assertIn(("SNIPER-EXT-03", "high", "CWE-346"), _pairs(report))

    def test_external_listener_with_sender_check_is_clean(self):
        source = (
            "const ALLOWED_ID = 'abcdefghijklmnopabcdefghijklmnop';\n"
            "chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {\n"
            "  if (sender.id !== ALLOWED_ID) {\n"
            "    return false;\n"
            "  }\n"
            "  sendResponse({ ok: true });\n"
            "  return true;\n"
            "});\n"
        )
        report = audit_extension_script_inline(source)
        self.assertEqual(report["finding_count"], 0, report["findings"])

    def test_window_message_without_origin_check_is_medium(self):
        source = (
            "window.addEventListener('message', (event) => {\n"
            "  chrome.runtime.sendMessage(event.data);\n"
            "});\n"
        )
        report = audit_extension_script_inline(source, filename="content.js")
        self.assertIn(("SNIPER-EXT-03", "medium", "CWE-345"), _pairs(report))

    def test_eval_innerhtml_and_sync_token_storage(self):
        source = (
            "chrome.runtime.onMessage.addListener((message) => {\n"
            "  eval(message.code);\n"
            "  panel.innerHTML = message.html;\n"
            "  chrome.storage.sync.set({ authToken: message.token });\n"
            "});\n"
        )
        report = audit_extension_script_inline(source)
        pairs = _pairs(report)
        self.assertIn(("SNIPER-EXT-02", "high", "CWE-95"), pairs)
        self.assertIn(("SNIPER-EXT-02", "medium", "CWE-79"), pairs)
        self.assertIn(("SNIPER-EXT-06", "medium", "CWE-312"), pairs)

    def test_tabs_execute_script_with_code_is_medium(self):
        source = "chrome.tabs.executeScript(tabId, { code: 'document.title = ' + JSON.stringify(t) });\n"
        report = audit_extension_script_inline(source)
        self.assertIn(("SNIPER-EXT-02", "medium", "CWE-94"), _pairs(report))


class ServiceWorkerTests(unittest.TestCase):
    def test_cross_origin_and_http_import_scripts_are_high(self):
        source = (
            "importScripts('https://cdn.example.com/workbox-sw.js');\n"
            "importScripts('http://cdn.example.com/legacy.js');\n"
        )
        report = audit_service_worker_inline(source)
        self.assertEqual(report["format"], "sniper-pwa-service-worker-audit-v1")
        hits = [f for f in report["findings"] if f["control_id"] == "SNIPER-PWA-01"]
        self.assertEqual({f["line"] for f in hits}, {1, 2})
        self.assertTrue(all(f["severity"] == "high" and f["cwe"] == "CWE-829" for f in hits))

    def test_precaching_api_paths_is_high(self):
        source = (
            "self.addEventListener('install', (event) => {\n"
            "  event.waitUntil(caches.open('v1').then((c) => c.addAll([\n"
            "    '/index.html',\n"
            "    '/api/me',\n"
            "  ])));\n"
            "});\n"
        )
        report = audit_service_worker_inline(source)
        self.assertIn(("SNIPER-PWA-02", "high", "CWE-524"), _pairs(report))

    def test_workbox_cache_first_api_route_is_high(self):
        source = (
            "workbox.routing.registerRoute(\n"
            "  ({ url }) => url.pathname.startsWith('/api/'),\n"
            "  new workbox.strategies.CacheFirst()\n"
            ");\n"
        )
        report = audit_service_worker_inline(source)
        self.assertIn(("SNIPER-PWA-02", "high", "CWE-524"), _pairs(report))

    def test_caching_authorized_request_is_high(self):
        source = (
            "self.addEventListener('fetch', (event) => {\n"
            "  if (event.request.headers.get('Authorization')) {\n"
            "    event.respondWith(fetch(event.request).then((response) => {\n"
            "      caches.open('v1').then((cache) => cache.put(event.request, response.clone()));\n"
            "      return response;\n"
            "    }));\n"
            "  }\n"
            "});\n"
        )
        report = audit_service_worker_inline(source)
        hits = [f for f in report["findings"] if f["control_id"] == "SNIPER-PWA-02"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "high")
        self.assertEqual(hits[0]["line"], 4)
        self.assertIn("Authorization", str(hits[0]))

    def test_unchecked_runtime_caching_is_medium(self):
        source = (
            "self.addEventListener('fetch', (event) => {\n"
            "  event.respondWith(fetch(event.request).then((response) => {\n"
            "    const copy = response.clone();\n"
            "    caches.open('runtime').then((cache) => cache.put(event.request, copy));\n"
            "    return response;\n"
            "  }));\n"
            "});\n"
        )
        report = audit_service_worker_inline(source)
        self.assertIn(("SNIPER-PWA-02", "medium", "CWE-524"), _pairs(report))

    def test_clean_static_service_worker_has_no_findings(self):
        report = audit_service_worker_inline(CLEAN_SERVICE_WORKER)
        self.assertEqual(report["finding_count"], 0, report["findings"])

    def test_empty_service_worker_raises(self):
        with self.assertRaises(ValueError):
            audit_service_worker_inline("")


class ExtensionPwaProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.project = self.base / "web-suite"
        self.project.mkdir()
        self.allowed = (self.base.resolve(),)

    def tearDown(self):
        self.temp.cleanup()

    def test_project_scan_discovers_extension_and_service_worker(self):
        ext_dir = self.project / "extension"
        ext_dir.mkdir()
        (ext_dir / "manifest.json").write_text(RISKY_MV2_MANIFEST, encoding="utf-8")
        (ext_dir / "bg.js").write_text("eval(message.code);\n", encoding="utf-8")
        web_dir = self.project / "web"
        web_dir.mkdir()
        (web_dir / "manifest.json").write_text(
            json.dumps({"name": "PWA", "start_url": "/", "display": "standalone"}),
            encoding="utf-8",
        )
        (web_dir / "sw.js").write_text("importScripts('http://cdn.example.com/x.js');\n", encoding="utf-8")
        (web_dir / "app.js").write_text("eval(userInput);\n", encoding="utf-8")

        report = audit_extension_pwa_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(report["format"], "sniper-browser-extension-pwa-audit-v1")
        self.assertEqual(report["extension_manifest_count"], 1)
        self.assertEqual(report["service_worker_count"], 1)
        self.assertEqual(report["extension_script_count"], 1)
        files = {item["file"] for item in report["findings"]}
        self.assertIn(str(Path("extension") / "manifest.json"), files)
        self.assertIn(str(Path("extension") / "bg.js"), files)
        self.assertIn(str(Path("web") / "sw.js"), files)
        self.assertNotIn(str(Path("web") / "app.js"), files)
        self.assertNotIn(str(Path("web") / "manifest.json"), files)

    def test_project_outside_allowed_roots_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_extension_pwa_project(str(self.project), allowed_roots=(self.project.resolve(),))


if __name__ == "__main__":
    unittest.main()
