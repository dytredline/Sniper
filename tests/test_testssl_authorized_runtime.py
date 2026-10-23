import hashlib
import json
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from testssl_authorized_active import (
    normalize_authorized_testssl_target,
    resolve_authorized_testssl_ip,
    run_testssl_authorized,
)


class TestsslAuthorizedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_env = os.environ.copy()
        os.environ["SNIPER_DATA_DIR"] = str(self.base / "data")
        os.environ["TESTSSL_CAPTURE"] = str(self.base / "arguments.json")
        self.binary = self.base / "testssl-fixture"
        self.binary.write_text(
            "#!" + __import__("sys").executable + "\n"
            "import json,os,sys\n"
            "from pathlib import Path\n"
            "args=sys.argv[1:]\n"
            "Path(os.environ['TESTSSL_CAPTURE']).write_text(json.dumps(args))\n"
            "assert args.count('--protocols') == 1\n"
            "assert args[args.index('--nodns')+1] == 'none'\n"
            "assert args[args.index('--ip')+1] == '127.0.0.1'\n"
            "assert '--phone-out' not in args and '--proxy' not in args\n"
            "assert os.environ.get('PHONE_OUT') == 'false'\n"
            "assert os.environ.get('DNS_VIA_PROXY') == 'false'\n"
            "assert args[-1] == 'example.test:443'\n"
            "report=[{'id':'protocols','ip':'127.0.0.1','port':'443','severity':'OK',"
            "'finding':'PRIVATE_RUNTIME_MARKER','cve':'','cwe':'','hint':''}]\n"
            "Path(args[args.index('--jsonfile')+1]).write_text(json.dumps(report))\n"
        )
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        os.environ["SNIPER_TESTSSL_BINARY"] = str(self.binary)
        os.environ["SNIPER_TESTSSL_SHA256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        os.environ["PHONE_OUT"] = "true"
        os.environ["DNS_VIA_PROXY"] = "true"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.previous_env)
        self.temp.cleanup()

    def test_normalizes_hostname_ipv4_ipv6_and_rejects_injected_targets(self):
        self.assertEqual(
            normalize_authorized_testssl_target(" Example.COM.:0443 "),
            ("example.com", 443, "example.com:443"),
        )
        self.assertEqual(
            normalize_authorized_testssl_target("[2001:0db8::1]:8443"),
            ("2001:db8::1", 8443, "[2001:db8::1]:8443"),
        )
        for target in (
            "https://example.com:443", "example.com", "example.com:0", "example.com:65536",
            "-flag:443", "example.com:443 --phone-out", "2001:db8::1:443", "[127.0.0.1]:443",
            "192.0.2.010:443",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_authorized_testssl_target(target)

    def test_hostname_is_resolved_once_and_runtime_is_pinned_to_that_ip(self):
        answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
        ]
        with patch("testssl_authorized_active.socket.getaddrinfo", return_value=answers) as lookup:
            result = run_testssl_authorized(" Example.TEST.:443 ", profile="protocols")
        lookup.assert_called_once_with(
            "example.test", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
        arguments = json.loads((self.base / "arguments.json").read_text())
        self.assertEqual(arguments[arguments.index("--ip") + 1], "127.0.0.1")
        self.assertEqual(arguments[-1], "example.test:443")
        self.assertEqual(result["format"], "testssl-authorized-v1")
        self.assertEqual(result["profile"], "authorized-protocols-v1")
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["target_sha256"], hashlib.sha256(b"example.test:443").hexdigest())
        self.assertEqual(result["resolved_ip_sha256"], hashlib.sha256(b"127.0.0.1").hexdigest())
        serialized = json.dumps(result)
        self.assertNotIn("example.test", serialized)
        self.assertNotIn("127.0.0.1", serialized)
        self.assertNotIn("PRIVATE_RUNTIME_MARKER", serialized)

    def test_ip_literal_skips_dns_and_invalid_profile_stops_before_execution(self):
        with patch("testssl_authorized_active.socket.getaddrinfo") as lookup:
            self.assertEqual(resolve_authorized_testssl_ip("127.0.0.1", 443), "127.0.0.1")
        lookup.assert_not_called()
        with self.assertRaises(ValueError):
            run_testssl_authorized("127.0.0.1:443", profile="custom")
        self.assertFalse((self.base / "arguments.json").exists())


if __name__ == "__main__":
    unittest.main()
