import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store


class ZapSelfPassiveApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.root / "data" / "sniper.db")
        self.previous_port = server.PORT
        self.previous_host = server.HOST
        server.HOST = "127.0.0.1"
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        server.PORT = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.env = patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.root / "data")})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        server.PORT = self.previous_port
        server.HOST = self.previous_host
        self.temp.cleanup()

    def post(self, payload):
        request = Request(
            f"http://127.0.0.1:{self.httpd.server_address[1]}/api/tool-runs/zap-self-passive",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())

    def test_requires_exact_local_confirmation_and_no_target_override(self):
        for payload in ({}, {"confirm_local": False}, {"confirm_local": True, "target": "example.com"}):
            with self.subTest(payload=payload):
                with self.assertRaises(HTTPError) as result:
                    self.post(payload)
                self.assertEqual(result.exception.code, 400)

    def test_fake_runtime_receives_one_health_get_and_returns_sanitized_summary(self):
        try:
            import zap_passive_active
        except ImportError:
            self.skipTest("ZAP runtime module is not present in the old source")
        fake = self.root / "fake-systemd-run"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "assert args[:4] == ['--user', '--wait', '--collect', '--pipe']\n"
            "assert any(x.startswith('--unit=sniper-zap-') for x in args)\n"
            "assert 'PrivateTmp=yes' in args and 'ProtectSystem=strict' in args\n"
            "assert 'ProtectHome=read-only' in args and 'NoNewPrivileges=yes' in args\n"
            "assert 'MemoryMax=2G' in args and 'TasksMax=256' in args\n"
            "assert 'RuntimeMaxSec=240' in args and '-Xmx1024m' in args\n"
            "assert '--network=host' not in args and 'docker' not in str(args)\n"
            "root = pathlib.Path(args[-1]).parent\n"
            f"assert root.is_relative_to({str(self.root / 'data')!r})\n"
            "plan = (root / 'plan.yaml').read_text()\n"
            "assert plan.count('type: requestor') == 1\n"
            "assert plan.count('method: GET') == 1\n"
            "assert 'type: passiveScan-wait' in plan\n"
            "assert 'type: spider' not in plan and 'type: activeScan' not in plan\n"
            "assert '/api/health' in plan and 'example.com' not in plan\n"
            "(root / 'report.json').write_text(json.dumps({'site':[{'alerts':[{'riskcode':'1','count':'1','secret':'do-not-echo'}]}]}))\n",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        with patch("zap_passive_active._trusted_runtime", return_value=(str(fake), self.root)):
            status, result = self.post({"confirm_local": True})
        self.assertEqual(status, 200)
        self.assertEqual(result["format"], "zap-self-passive-v1")
        self.assertEqual(result["profile"], "single-health-get-passive-v1")
        self.assertEqual(result["risk_counts"]["low"], 1)
        self.assertEqual(result["instance_count"], 1)
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("do-not-echo", json.dumps(result))
        self.assertEqual(list((self.root / "data").glob("sniper_zap_*")), [])

    def test_api_exposes_sanitized_runtime_summary(self):
        expected = {
            "format": "zap-self-passive-v1",
            "profile": "single-health-get-passive-v1",
            "site_count": 1,
            "alert_type_count": 1,
            "instance_count": 1,
            "risk_counts": {"informational": 0, "low": 1, "medium": 0, "high": 0},
            "report_sha256": "a" * 64,
        }
        with patch.object(server, "run_zap_self_passive", create=True, return_value=expected):
            status, result = self.post({"confirm_local": True})
        self.assertEqual(status, 200)
        self.assertEqual(result, expected)

    def test_missing_runtime_fails_closed(self):
        if not hasattr(server, "ZapUnavailable"):
            self.skipTest("ZAP runtime module is not present in the old source")
        with patch("zap_passive_active._trusted_runtime", side_effect=server.ZapUnavailable("not installed")):
            with self.assertRaises(HTTPError) as result:
                self.post({"confirm_local": True})
        self.assertEqual(result.exception.code, 503)


if __name__ == "__main__":
    unittest.main()
