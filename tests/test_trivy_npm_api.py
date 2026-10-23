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


class TrivyNpmApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_npm_test_")
        self.base = Path(self.tmp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        self.lockfile = self.project / "package-lock.json"
        self.lockfile.write_text(json.dumps({"name":"fixture", "lockfileVersion":3, "packages":{"":{"dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}))
        self.cache = self.base / "cache"
        (self.cache / "db").mkdir(parents=True)
        (self.cache / "db" / "metadata.json").write_text("{}")
        (self.cache / "db" / "trivy.db").write_bytes(b"pinned test db")
        self.fake = self.base / "fake-trivy"
        self.fake.write_text('''#!/usr/bin/env python3
import json, pathlib, sys
args=sys.argv[1:]
required=['fs','--scanners','vuln','--offline-scan','--skip-db-update','--skip-java-db-update','--skip-check-update','--skip-version-check','--config=','--ignorefile=']
if any(x not in args for x in required): sys.exit(5)
root=pathlib.Path(args[-1])
if sorted(x.name for x in root.iterdir())!=['package-lock.json']: sys.exit(6)
lock=json.loads((root/'package-lock.json').read_text())
vulnerable=lock['packages'].get('node_modules/lodash',{}).get('version')=='4.17.20'
report={'SchemaVersion':2,'Results':[]}
if vulnerable:
 report['Results']=[{'Target':'PRIVATE_PACKAGE_MARKER','Class':'lang-pkgs','Type':'npm','Vulnerabilities':[{'VulnerabilityID':'PRIVATE_CVE_MARKER','Severity':'HIGH','PkgName':'PRIVATE_PACKAGE_MARKER'}]}]
pathlib.Path(args[args.index('--output')+1]).write_text(json.dumps(report))
''')
        self.fake.chmod(0o755)
        self.keys = {k: os.environ.get(k) for k in ("SNIPER_TRIVY_BINARY", "SNIPER_TRIVY_BINARY_SHA256", "SNIPER_DATA_DIR", "SNIPER_TRIVY_VULN_CACHE_DIR", "SNIPER_TRIVY_VULN_DB_SHA256")}
        os.environ.update({"SNIPER_TRIVY_BINARY":str(self.fake), "SNIPER_TRIVY_BINARY_SHA256":hashlib.sha256(self.fake.read_bytes()).hexdigest(), "SNIPER_DATA_DIR":str(self.base), "SNIPER_TRIVY_VULN_CACHE_DIR":str(self.cache), "SNIPER_TRIVY_VULN_DB_SHA256":hashlib.sha256(b"pinned test db").hexdigest()})
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown(); self.httpd.server_close(); self.thread.join(timeout=2)
        server.STORE = self.previous_store
        for key, value in self.keys.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value
        self.tmp.cleanup()

    def call(self, payload):
        req = Request(self.url + "/api/tool-runs/trivy-npm-vulnerability", data=json.dumps(payload).encode(), method="POST", headers={"Content-Type":"application/json"})
        try:
            with urlopen(req, timeout=8) as response:
                return response.status, json.loads(response.read())
        except HTTPError as response:
            return response.code, json.loads(response.read())

    def consent(self):
        return {"confirm_local":True,"project_path":str(self.project)}

    def test_vulnerable_runtime_result_is_aggregate_only(self):
        code, data = self.call(self.consent())
        self.assertEqual(code, 200)
        self.assertEqual(data["profile"], "local-npm-package-lock-v1")
        self.assertEqual(data["finding_counts"]["vulnerabilities"], 1)
        self.assertEqual(data["vuln_counts"]["high"], 1)
        self.assertEqual(len(data["report_sha256"]), 64)
        self.assertNotIn("PRIVATE_PACKAGE_MARKER", json.dumps(data))
        self.assertNotIn("PRIVATE_CVE_MARKER", json.dumps(data))
        self.assertNotIn(str(self.project), json.dumps(data))

    def test_clean_runtime_result_zero(self):
        self.lockfile.write_text(json.dumps({"name":"fixture", "lockfileVersion":3, "packages":{"":{"dependencies":{"is-number":"7.0.0"}},"node_modules/is-number":{"version":"7.0.0"}}}))
        code, data = self.call(self.consent())
        self.assertEqual(code, 200)
        self.assertEqual(data["finding_counts"]["vulnerabilities"], 0)

    def test_consent_and_exact_schema_required(self):
        for payload in ({"confirm_local":False,"project_path":str(self.project)}, {"project_path":str(self.project)}, {**self.consent(),"extra":"x"}):
            code, _ = self.call(payload)
            self.assertEqual(code, 400)

    def test_missing_and_symlink_lockfile_rejected(self):
        self.lockfile.unlink()
        self.assertEqual(self.call(self.consent())[0], 400)
        self.lockfile.symlink_to(self.base / "outside")
        self.assertEqual(self.call(self.consent())[0], 400)

    def test_invalid_lockfile_rejected_before_scanner(self):
        for contents in ("not-json", "{}", '{"lockfileVersion":3}', '{"lockfileVersion":4,"packages":{}}'):
            self.lockfile.write_text(contents)
            self.assertEqual(self.call(self.consent())[0], 400)

    def test_oversize_lockfile_rejected(self):
        self.lockfile.write_bytes(b"{" + b" " * 5_000_000 + b"}")
        self.assertEqual(self.call(self.consent())[0], 400)

    def test_database_pin_failure_is_unavailable(self):
        os.environ["SNIPER_TRIVY_VULN_DB_SHA256"] = "0" * 64
        self.assertEqual(self.call(self.consent())[0], 503)

    def test_does_not_scan_other_project_files(self):
        (self.project / "secret.txt").write_text("PRIVATE_SECRET_MARKER")
        self.assertEqual(self.call(self.consent())[0], 200)


if __name__ == "__main__":
    unittest.main()
