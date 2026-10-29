from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store
from tool_runtime_readiness import _runtime_check


class SyftGrypeActiveApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_syft_grype_")
        self.root = Path(self.temp.name)
        self.project = self.root / "private-project-marker"
        self.project.mkdir()
        (self.project / "package-lock.json").write_text("{}", encoding="utf-8")
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.syft = self.runtime / "syft"
        self.grype = self.runtime / "grype"
        self._write_fake_syft()
        self._write_fake_grype()
        self.db_root = self.root / "grype-db"
        db_dir = self.db_root / "6"
        db_dir.mkdir(parents=True)
        self.db = db_dir / "vulnerability.db"
        self.db.write_bytes(b"pinned synthetic grype database")
        self.db.chmod(0o600)

        self.old_env = os.environ.copy()
        os.environ.update({
            "SNIPER_DATA_DIR": str(self.data),
            "SNIPER_SYFT_BINARY": str(self.syft),
            "SNIPER_SYFT_BINARY_SHA256": hashlib.sha256(self.syft.read_bytes()).hexdigest(),
            "SNIPER_GRYPE_BINARY": str(self.grype),
            "SNIPER_GRYPE_BINARY_SHA256": hashlib.sha256(self.grype.read_bytes()).hexdigest(),
            "SNIPER_GRYPE_DB_ROOT": str(self.db_root),
            "SNIPER_GRYPE_DB_PATH": str(self.db),
            "SNIPER_GRYPE_DB_SHA256": hashlib.sha256(self.db.read_bytes()).hexdigest(),
            "SNIPER_GRYPE_DB_SCHEMA": "v6.1.10",
            "SNIPER_GRYPE_DB_BUILT": "2026-10-29T06:23:34Z",
        })

        self.previous_store = server.STORE
        server.STORE = Store(self.root / "sniper.db")
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
        os.environ.clear()
        os.environ.update(self.old_env)
        self.temp.cleanup()

    def _write_fake_syft(self):
        self.syft.write_text(
            """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
assert os.environ.get("HTTP_PROXY", "") == ""
assert os.environ.get("HTTPS_PROXY", "") == ""
out = next(value.split("=", 1)[1] for value in sys.argv if value.startswith("syft-json="))
source = next(value for value in sys.argv if value.startswith("dir:"))
report = {
  "artifacts": [{"id": "a1", "name": "demo", "version": "1.0.0", "type": "npm",
                 "purl": "pkg:npm/demo@1.0.0", "locations": [{"path": source + "/private-file"}]}],
  "artifactRelationships": [], "files": [],
  "source": {"type": "directory", "metadata": {"path": source}},
  "descriptor": {"name": "syft", "version": "1.55.0"},
  "schema": {"version": "16.1.11"}
}
Path(out).write_text(json.dumps(report), encoding="utf-8")
""",
            encoding="utf-8",
        )
        self.syft.chmod(0o755)

    def _write_fake_grype(self):
        self.grype.write_text(
            """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
assert os.environ["GRYPE_DB_AUTO_UPDATE"] == "false"
assert os.environ["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
assert os.environ.get("HTTP_PROXY", "") == ""
assert os.environ.get("HTTPS_PROXY", "") == ""
assert Path(os.environ["GRYPE_DB_CACHE_DIR"]).is_dir()
out = Path(sys.argv[sys.argv.index("--file") + 1])
report = {"matches": [{
  "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "namespace": "npm",
                    "fix": {"state": "fixed", "versions": ["1.0.1"]}},
  "artifact": {"name": "demo", "version": "1.0.0", "type": "npm",
               "purl": "pkg:npm/demo@1.0.0", "locations": [{"path": "/private/input/path"}]},
  "matchDetails": []
}], "ignoredMatches": [], "source": {"type": "sbom", "target": sys.argv[1]},
"descriptor": {"name": "grype", "version": "0.121.0"}}
out.write_text(json.dumps(report), encoding="utf-8")
""",
            encoding="utf-8",
        )
        self.grype.chmod(0o755)

    def request_json(self, payload: dict) -> tuple[int, dict]:
        request = Request(
            self.base_url + "/api/tool-runs/syft-grype",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_local_project_produces_redacted_sbom_and_vulnerability_summary(self):
        status, body = self.request_json({"confirm_local": True, "project_path": str(self.project)})
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "syft-json+grype-json-summary")
        self.assertEqual(body["profile"], "local-sbom-vulnerability-v1")
        self.assertEqual(body["package_count"], 1)
        self.assertEqual(body["relationship_count"], 0)
        self.assertEqual(body["vulnerability_count"], 1)
        self.assertEqual(body["severity_counts"]["high"], 1)
        self.assertEqual(body["fix_state_counts"]["fixed"], 1)
        self.assertEqual(body["findings"], [{
            "vulnerability_id": "CVE-2026-0001",
            "severity": "high",
            "package": "demo",
            "version": "1.0.0",
            "type": "npm",
            "fix_state": "fixed",
            "fixed_versions": ["1.0.1"],
        }])
        self.assertEqual(body["database"], {
            "schema": "v6.1.10",
            "built": "2026-10-29T06:23:34Z",
        })
        self.assertRegex(body["sbom_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(body["report_sha256"], r"^[0-9a-f]{64}$")
        encoded = json.dumps(body, sort_keys=True)
        self.assertNotIn(str(self.project), encoded)
        self.assertNotIn("private/input/path", encoded)

    def test_route_requires_exact_local_consent_payload(self):
        status, _body = self.request_json({
            "confirm_local": True,
            "project_path": str(self.project),
            "command": "ignored",
        })
        self.assertEqual(status, 400)

    def test_symlinked_manifest_is_not_copied_or_disclosed(self):
        outside = self.root / "outside-private-marker"
        outside.write_text("do-not-copy", encoding="utf-8")
        (self.project / "poetry.lock").symlink_to(outside)
        status, body = self.request_json({"confirm_local": True, "project_path": str(self.project)})
        self.assertEqual(status, 200)
        self.assertEqual(body["manifest_count"], 1)
        self.assertNotIn("outside-private-marker", json.dumps(body, sort_keys=True))
        self.assertNotIn("do-not-copy", json.dumps(body, sort_keys=True))

    def test_binary_digest_mismatch_fails_closed_before_execution(self):
        os.environ["SNIPER_SYFT_BINARY_SHA256"] = "0" * 64
        status, body = self.request_json({"confirm_local": True, "project_path": str(self.project)})
        self.assertEqual(status, 503)
        self.assertNotIn(str(self.syft), json.dumps(body, sort_keys=True))

    def test_runtime_readiness_reports_pinned_binaries_and_database(self):
        self.assertEqual(
            _runtime_check("syft-grype", "/api/tool-runs/syft-grype"),
            (True, "pinned_binaries_and_offline_database_found"),
        )


if __name__ == "__main__":
    unittest.main()
