import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import nmap_active


class NmapServiceVersionProfileTests(unittest.TestCase):
    def test_default_service_version_false_preserves_exact_flags_and_fields(self):
        args = nmap_active._build_args("203.0.113.10", False)
        self.assertNotIn("-sV", args)
        self.assertNotIn("--version-light", args)
        self.assertNotIn("--version-intensity", args)
        self.assertEqual(args[-1], "203.0.113.10")

        xml = (
            '<nmaprun><host><status state="up"/><ports>'
            '<port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http" product="OpenSSH" version="9.6"/></port>'
            '</ports></host></nmaprun>'
        )
        completed = subprocess.CompletedProcess([], 0, stdout=xml.encode("utf-8"), stderr=b"")
        with patch("nmap_active.resolve_public_ips", return_value=["203.0.113.10"]), \
                patch("nmap_active._find_nmap_binary", return_value=Path("/fake/nmap")), \
                patch("nmap_active.subprocess.run", return_value=completed) as run_mock:
            result = nmap_active.run_bounded_tcp_connect_scan(
                target_id="t-1",
                engagement_id="e-1",
                hostname="example.com",
                port=80,
            )

        called_argv = run_mock.call_args.args[0]
        self.assertNotIn("-sV", called_argv)
        self.assertNotIn("service_version_enabled", result)
        self.assertNotIn("service_versions", result)
        self.assertEqual(result["open_ports"], [80])

    def test_service_version_true_adds_bounded_sv_flags_and_parses_service_metadata(self):
        xml = (
            '<nmaprun><host><status state="up"/><ports>'
            '<port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="http" product="OpenSSH" version="9.6"/></port>'
            '<port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http" product="  " version="  ' + ("1" * 80) + '  "/></port>'
            '<port protocol="tcp" portid="443"><state state="closed"/>'
            '<service name="https" product="nginx" version="1.25"/></port>'
            '</ports></host></nmaprun>'
        )
        completed = subprocess.CompletedProcess([], 0, stdout=xml.encode("utf-8"), stderr=b"")
        with patch("nmap_active.resolve_public_ips", return_value=["203.0.113.10"]), \
                patch("nmap_active._find_nmap_binary", return_value=Path("/fake/nmap")), \
                patch("nmap_active.subprocess.run", return_value=completed) as run_mock:
            result = nmap_active.run_bounded_tcp_connect_scan(
                target_id="t-1",
                engagement_id="e-1",
                hostname="example.com",
                port=22,
                service_version=True,
            )

        called_argv = run_mock.call_args.args[0]
        self.assertIn("-sV", called_argv)
        self.assertIn("--version-light", called_argv)
        self.assertIn("--version-intensity", called_argv)
        sv_idx = called_argv.index("-sV")
        self.assertEqual(
            called_argv[sv_idx:sv_idx + 4],
            ["-sV", "--version-light", "--version-intensity", "2"],
        )
        self.assertLess(sv_idx + 3, called_argv.index("203.0.113.10"))

        self.assertIs(result.get("service_version_enabled"), True)
        self.assertEqual(result["open_ports"], [22, 80])
        self.assertEqual(
            result["service_versions"],
            [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "OpenSSH",
                    "version": "9.6",
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "version": "1" * 64,
                },
            ],
        )

    def test_non_boolean_service_version_raises_value_error(self):
        for invalid in ("yes", "true", "false", 1, 0, None, [True], {"service_version": True}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    nmap_active._build_args("203.0.113.10", False, service_version=invalid)
                with self.assertRaises(ValueError):
                    nmap_active._run_nmap("203.0.113.10", False, service_version=invalid)
                with self.assertRaises(ValueError):
                    nmap_active.run_bounded_tcp_connect_scan(
                        target_id="t-1",
                        engagement_id="e-1",
                        hostname="example.com",
                        port=80,
                        service_version=invalid,
                    )


if __name__ == "__main__":
    unittest.main()
