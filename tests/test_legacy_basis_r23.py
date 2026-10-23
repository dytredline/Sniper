"""23. tur: eski (M01–M52) üretici uçların gerçek veriye bağlanması ve veri dayanağı (data_basis) sözleşmesi."""
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from project_analyzer import analyze_project
from storage import Store

import quality_gate
import supply_chain_slsa_auditor
import threat_model_generator

FLASK_APP = (
    "import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    "@app.route('/user')\ndef user():\n    uid = request.args.get('id')\n    db = sqlite3.connect('x.db')\n"
    "    return str(db.execute(\"SELECT * FROM u WHERE id = '\" + uid + \"'\").fetchall())\n"
)
EXPRESS_APP = (
    "const express = require('express');\nconst cp = require('child_process');\nconst app = express();\n"
    "app.get('/run', function (req, res) {\n  cp.exec('ls ' + req.query.dir, (e, out) => res.send(out));\n});\n"
    "app.listen(3000);\n"
)

LEGACY_ROUTES = (
    "/api/attack-paths/correlate",
    "/api/quality-gate/evaluate",
    "/api/remediation/auto-patch",
    "/api/reports/executive-pentest",
    "/api/blue-team/synthesize-rules",
    "/api/threat-model/generate",
    "/api/supply-chain-slsa/audit",
)


class LegacyBasisHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        if hasattr(server, "LIMITER") and hasattr(server.LIMITER, "_events"):
            server.LIMITER._events.clear()
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

    def post_json(self, path: str, payload: dict) -> tuple[int, dict]:
        req = Request(self.base_url + path, data=json.dumps(payload).encode("utf-8"), method="POST",
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            try:
                return err.code, json.loads(err.read().decode("utf-8"))
            finally:
                err.close()

    def _real_audit(self) -> dict:
        project = self.base / "proje"
        project.mkdir()
        (project / "app.py").write_text(FLASK_APP, encoding="utf-8")
        (project / "server.js").write_text(EXPRESS_APP, encoding="utf-8")
        return server.STORE.create_project_audit(analyze_project(str(project)))

    def test_no_source_returns_400_on_every_legacy_route(self):
        for route in LEGACY_ROUTES:
            with self.subTest(route=route):
                status, body = self.post_json(route, {})
                self.assertEqual(status, 400, body)
                self.assertNotIn("format", body)

    def test_template_outputs_require_flag_and_are_labelled(self):
        unmatched = [{"category": "misc", "severity": "low", "title": "Zzz qqq", "reference": "none"}]
        status, body = self.post_json("/api/blue-team/synthesize-rules", {"findings": unmatched})
        self.assertEqual(status, 200)
        self.assertEqual(body["rule_count"], 0)
        self.assertEqual(body["data_basis"]["kind"], "real")
        status, body = self.post_json("/api/blue-team/synthesize-rules", {"findings": unmatched, "include_baseline": True})
        self.assertEqual(status, 200)
        self.assertGreater(body["rule_count"], 0)
        self.assertEqual(body["data_basis"]["kind"], "template")

        status, body = self.post_json("/api/remediation/auto-patch", {"findings": unmatched})
        self.assertEqual(status, 200)
        self.assertEqual(body["patch_count"], 0)
        self.assertEqual(body["template_patch_count"], 0)
        status, body = self.post_json("/api/remediation/auto-patch", {"findings": unmatched, "include_templates": True})
        self.assertEqual(status, 200)
        self.assertGreater(body["template_patch_count"], 0)
        self.assertEqual(body["data_basis"]["kind"], "template")
        self.assertTrue(all(p["basis"] == "template" for p in body["patches"]))

    def test_real_project_audit_feeds_every_legacy_route(self):
        audit = self._real_audit()
        ref = {"project_audit_id": audit["id"]}

        status, body = self.post_json("/api/attack-paths/correlate", ref)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data_basis"]["kind"], "real")
        entries = {(c["entry_point"], c["flow"]["sink_kind"]) for c in body["route_chains"]}
        self.assertEqual(entries, {("GET /user", "sql"), ("GET /run", "command")})
        self.assertEqual(body["route_chain_count"], 2)

        status, body = self.post_json("/api/quality-gate/evaluate", ref)
        self.assertEqual(status, 200, body)
        self.assertFalse(body["ci_policy"]["passed"])
        self.assertGreaterEqual(body["ci_policy"]["failing_count"], 2)
        self.assertFalse(body["passed"])
        self.assertTrue(any(r.startswith("CI politikası: ") for r in body["blocking_reasons"]))
        status, body = self.post_json("/api/quality-gate/evaluate", {**ref, "policy": {"bilinmeyen": 1}})
        self.assertEqual(status, 400)

        status, body = self.post_json("/api/remediation/auto-patch", ref)
        self.assertEqual(status, 200, body)
        candidates = {(c["file"], c["kind"]) for c in body["verified_fix_candidates"]}
        self.assertEqual(candidates, {("app.py", "sql"), ("server.js", "command")})
        self.assertTrue(all(c["verify_url"].startswith(f"/api/project-audits/{audit['id']}/findings/")
                            for c in body["verified_fix_candidates"]))

        status, body = self.post_json("/api/reports/executive-pentest", ref)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data_basis"]["kind"], "real")
        self.assertTrue(body["sections"])

        status, body = self.post_json("/api/threat-model/generate", ref)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data_basis"]["kind"], "real")
        self.assertEqual(body["boundaries_basis"], "template")
        self.assertEqual(body["project_threat_model"]["route_count"], 2)
        self.assertEqual(body["project_threat_model"]["svg_url"], f"/api/project-audits/{audit['id']}/threat-model")

    def test_confirm_missing_is_400_not_403(self):
        status, _ = self.post_json("/api/notification-settings", {"enabled": True})
        self.assertEqual(status, 400)
        status, _ = self.post_json("/api/sandbox-targets", {"name": "x", "base_url": "http://127.0.0.1:1"})
        self.assertEqual(status, 400)


class LegacyBasisUnitTests(unittest.TestCase):
    def test_ci_policy_fails_on_malicious_dependency(self):
        decision = quality_gate._ci_policy_decision(
            {"findings": []}, [{"severity": "low", "title": "MAL-2026-1", "vulnerability_id": "MAL-2026-1"}], None)
        self.assertFalse(decision["passed"])
        self.assertEqual(decision["policy"]["source"], "varsayılan")

    def test_threat_model_no_findings_is_not_called_hardened(self):
        model = threat_model_generator.generate_threat_model(
            findings=[{"category": "ssrf", "severity": "high", "title": "SSRF", "reference": "CWE-918"}])
        statuses = {b["status"] for b in model["trust_boundaries"]}
        self.assertNotIn("hardened", statuses)
        self.assertIn("no_findings", statuses)
        self.assertIsNone(model["project_threat_model"])
        with self.assertRaises(ValueError):
            threat_model_generator.generate_threat_model(findings=[])

    def test_slsa_reads_real_provenance_sbom_and_release_manifest(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp) / "p"
            (root / "dist").mkdir(parents=True)
            (root / "package.json").write_text('{"dependencies": {"lodash": "4.17.21"}}', encoding="utf-8")
            allowed = (Path(tmp),)
            bare = supply_chain_slsa_auditor.audit_supply_chain_slsa(str(root), allowed_roots=allowed)
            self.assertFalse(bare["has_provenance"])
            self.assertTrue(any("SBOM" in f["title"] for f in bare["findings"]))

            (root / "bom.cdx.json").write_text("{}", encoding="utf-8")
            (root / "dist" / "app.intoto.jsonl").write_text("{}", encoding="utf-8")
            (root / "dist" / "MANIFEST.json").write_text(
                json.dumps({"format": "sniper-release/1", "version": "1.2.3", "files": [{"path": "a"}]}), encoding="utf-8")
            (root / "dist" / "MANIFEST.json.sig").write_text("c2ln", encoding="utf-8")
            (root / "evil-link.intoto.jsonl").symlink_to(root / "package.json")
            result = supply_chain_slsa_auditor.audit_supply_chain_slsa(str(root), allowed_roots=allowed)
            self.assertTrue(result["has_provenance"])
            self.assertEqual(result["provenance_files"]["sbom"], ["bom.cdx.json"])
            self.assertEqual(result["provenance_files"]["provenance"], ["dist/app.intoto.jsonl"])
            self.assertEqual(result["release_manifest"]["version"], "1.2.3")
            self.assertTrue(result["release_manifest"]["signed"])
            self.assertFalse(any("SBOM" in f["title"] for f in result["findings"]))
            self.assertEqual(result["data_basis"]["kind"], "real")

        with self.assertRaises(ValueError):
            supply_chain_slsa_auditor.audit_supply_chain_slsa(components=[], workflow_content="  ")


if __name__ == "__main__":
    unittest.main()
