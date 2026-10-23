import fcntl
import hashlib
import json
import os
import stat
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

import server
from storage import Store


class TestTestsslFullActiveScanApi(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.env = os.environ.copy()
        self.store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        os.environ["SNIPER_DATA_DIR"] = str(self.base / "data")
        os.environ["SNIPER_HOST"] = "127.0.0.1"
        self.calls = self.base / "calls.txt"
        os.environ["TESTSSL_TEST_CALLS"] = str(self.calls)
        self.binary = self.base / "fake_testssl"
        self.binary.write_text("#!" + __import__("sys").executable + "\n" +
            "import json,os,sys\n"
            "from pathlib import Path\n"
            "args=sys.argv[1:]\n"
            "assert args.count('--full')+args.count('--protocols')==1\n"
            "assert '--nodns' in args and args[args.index('--nodns')+1]=='none'\n"
            "assert '--phone-out' not in args\n"
            "assert args[-1].startswith('127.0.0.1:')\n"
            "Path(os.environ['TESTSSL_TEST_CALLS']).open('a').write('full\\n' if '--full' in args else 'protocols\\n')\n"
            "report=[{'id':'1','ip':'127.0.0.1','port':'443','severity':'OK','finding':'TLSv1.3','cve':'','cwe':'','hint':''},"
            "{'id':'2','ip':'127.0.0.1','port':'443','severity':'HIGH','finding':'PRIVATE_CIPHER_MARKER','cve':'','cwe':'','hint':''}]\n"
            "Path(args[args.index('--jsonfile')+1]).write_text(json.dumps(report))\n"
            "sys.exit(int(os.environ.get('TESTSSL_TEST_EXIT_CODE', '0')))\n")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        os.environ["SNIPER_TESTSSL_BINARY"] = str(self.binary)
        os.environ["SNIPER_TESTSSL_SHA256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.http.daemon_threads = True
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.http.server_port}"
        self.opener = build_opener(ProxyHandler({}))

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.store
        os.environ.clear()
        os.environ.update(self.env)
        self.temp.cleanup()

    def post(self, path, payload):
        request = Request(self.url + path, data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener.open(request, timeout=8) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            with error:
                return error.code, json.loads(error.read())

    def test_full_and_existing_protocols_are_distinct_runtime_profiles(self):
        payload = {"confirm_local": True, "target": "127.0.0.1:443"}
        full_status, full = self.post("/api/tool-runs/testssl-full", payload)
        protocol_status, protocol = self.post("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual((full_status, protocol_status), (200, 200))
        self.assertEqual((full["format"], protocol["format"]),
                         ("testssl-loopback-full-v1", "testssl-loopback-v1"))
        self.assertEqual(full["record_count"], 2)
        self.assertIs(full["scan_complete"], True)
        self.assertEqual(full["scanner_exit_code"], 0)
        self.assertEqual(full["severity_counts"]["HIGH"], 1)
        self.assertEqual(self.calls.read_text().splitlines(), ["full", "protocols"])
        self.assertNotIn("PRIVATE_CIPHER_MARKER", json.dumps(full))
        self.assertNotIn("127.0.0.1", json.dumps(full))

    def test_nonzero_full_exit_with_valid_report_is_labeled_partial(self):
        os.environ["TESTSSL_TEST_EXIT_CODE"] = "7"
        payload = {"confirm_local": True, "target": "127.0.0.1:443"}
        status, full = self.post("/api/tool-runs/testssl-full", payload)
        self.assertEqual(status, 200)
        self.assertEqual(full["record_count"], 2)
        self.assertIs(full["scan_complete"], False)
        self.assertEqual(full["scanner_exit_code"], 7)
        self.assertNotIn("PRIVATE_CIPHER_MARKER", json.dumps(full))
        protocol_status, _ = self.post("/api/tool-runs/testssl-protocols", payload)
        self.assertEqual(protocol_status, 502)

    def test_rejects_external_target_missing_consent_and_custom_options_before_execution(self):
        invalid = [
            {"confirm_local": True, "target": "192.0.2.1:443"},
            {"confirm_local": False, "target": "127.0.0.1:443"},
            {"confirm_local": True, "target": "127.0.0.1:443", "flags": "--phone-out"},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                status, _ = self.post("/api/tool-runs/testssl-full", payload)
                self.assertEqual(status, 400)
                self.assertFalse(self.calls.exists())

    def test_profiles_share_the_same_single_scan_lock(self):
        lock = self.base / "data" / "testssl-protocols.lock"
        lock.parent.mkdir(parents=True, exist_ok=True)
        with lock.open("w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            status, _ = self.post("/api/tool-runs/testssl-full",
                                  {"confirm_local": True, "target": "127.0.0.1:443"})
            self.assertEqual(status, 503)
            self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
