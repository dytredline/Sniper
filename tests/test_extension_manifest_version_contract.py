import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from browser_extension_pwa_auditor import audit_extension_manifest_inline
from storage import Store


class ExtensionManifestVersionContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "data" / "sniper.db")
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

    def post_payload(self, payload: dict) -> tuple[int, dict]:
        request = Request(
            self.base_url + "/api/browser-extension-pwa/audit",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read().decode("utf-8"))
            finally:
                error.close()

    def post_manifest(self, manifest: dict) -> tuple[int, dict]:
        return self.post_payload(
            {
                "audit_mode": "manifest",
                "filename": "manifest.json",
                "raw_content": json.dumps(manifest),
            }
        )

    def test_supported_manifest_versions_pass_runtime_control(self):
        for manifest_version in (2, 3):
            with self.subTest(manifest_version=manifest_version):
                status, body = self.post_manifest(
                    {
                        "manifest_version": manifest_version,
                        "name": "Bounded",
                        "version": "1.0",
                    }
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    body["format"], "sniper-browser-extension-manifest-audit-v1"
                )
                self.assertEqual(body["manifest_version"], manifest_version)

    def test_invalid_manifest_versions_are_rejected_by_engine(self):
        for invalid in (True, "3", 3.0, 4, None):
            with self.subTest(manifest_version=invalid):
                with self.assertRaisesRegex(ValueError, "manifest_version"):
                    audit_extension_manifest_inline(
                        json.dumps(
                            {
                                "manifest_version": invalid,
                                "name": "Malformed",
                                "version": "1.0",
                            }
                        )
                    )

    def test_invalid_or_missing_manifest_version_is_rejected_by_runtime_api(self):
        for invalid in (True, "3", 3.0, 4, None):
            with self.subTest(manifest_version=invalid):
                status, body = self.post_manifest(
                    {
                        "manifest_version": invalid,
                        "name": "Malformed",
                        "version": "1.0",
                    }
                )
                self.assertEqual(status, 400)
                self.assertIn("error", body)

        status, body = self.post_manifest({"name": "Missing", "version": "1.0"})
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_invalid_project_manifest_version_is_rejected_by_runtime_api(self):
        project = Path(self.temp.name) / "extension-project"
        project.mkdir()
        (project / "manifest.json").write_text(
            json.dumps(
                {
                    "manifest_version": "3",
                    "name": "Malformed",
                    "version": "1.0",
                }
            ),
            encoding="utf-8",
        )
        (project / "bg.js").write_text("eval(message.code);\n", encoding="utf-8")

        status, body = self.post_payload(
            {"project_path": str(project), "confirm_local": True}
        )

        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_missing_project_manifest_version_is_rejected_for_extension_fields(self):
        project = Path(self.temp.name) / "missing-version-extension"
        project.mkdir()
        (project / "manifest.json").write_text(
            json.dumps(
                {
                    "name": "Malformed Extension",
                    "version": "1.0",
                    "permissions": ["cookies"],
                    "background": {"scripts": ["bg.js"]},
                }
            ),
            encoding="utf-8",
        )
        (project / "bg.js").write_text("eval(message.code);\n", encoding="utf-8")

        status, body = self.post_payload(
            {"project_path": str(project), "confirm_local": True}
        )

        self.assertEqual(status, 400)
        self.assertIn("manifest_version", body["error"])

    def test_escaped_invalid_project_manifest_version_is_rejected(self):
        project = Path(self.temp.name) / "escaped-invalid-extension"
        project.mkdir()
        (project / "manifest.json").write_text(
            '{"manifest\\u005fversion":"3","name":"Malformed","version":"1.0"}',
            encoding="utf-8",
        )
        (project / "bg.js").write_text("eval(message.code);\n", encoding="utf-8")

        status, body = self.post_payload(
            {"project_path": str(project), "confirm_local": True}
        )

        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_escaped_supported_project_manifest_version_is_audited(self):
        project = Path(self.temp.name) / "escaped-valid-extension"
        project.mkdir()
        (project / "manifest.json").write_text(
            '{"manifest\\u005fversion":3,"name":"Bounded","version":"1.0"}',
            encoding="utf-8",
        )
        (project / "bg.js").write_text("console.log('bounded');\n", encoding="utf-8")

        status, body = self.post_payload(
            {"project_path": str(project), "confirm_local": True}
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["extension_manifest_count"], 1)
        self.assertEqual(body["extension_script_count"], 1)

    def test_unsupported_audit_mode_is_rejected_without_script_fallback(self):
        status, body = self.post_payload(
            {
                "audit_mode": "typo",
                "filename": "manifest.json",
                "raw_content": json.dumps(
                    {
                        "manifest_version": "3",
                        "name": "Malformed",
                        "version": "1.0",
                    }
                ),
            }
        )

        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_explicit_script_mode_remains_supported(self):
        status, body = self.post_payload(
            {
                "audit_mode": "script",
                "filename": "content.js",
                "raw_content": "console.log('bounded');\n",
            }
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "sniper-browser-extension-script-audit-v1")


if __name__ == "__main__":
    unittest.main()
