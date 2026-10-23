import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from host_cis_hardening_auditor import (  # noqa: E402
    audit_host_config_inline,
    audit_host_config_project,
    detect_config_type,
)

HARDENED_SSHD = (
    "Protocol 2\n"
    "PermitRootLogin no\n"
    "PasswordAuthentication no\n"
    "PermitEmptyPasswords no\n"
    "X11Forwarding no\n"
    "AllowTcpForwarding no\n"
    "MaxAuthTries 3\n"
    "ClientAliveInterval 300\n"
    "LoginGraceTime 30\n"
    "PermitUserEnvironment no\n"
    "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
    "MACs hmac-sha2-512-etm@openssh.com\n"
    "KexAlgorithms curve25519-sha256\n"
)

HARDENED_SERVICE = (
    "[Unit]\nDescription=app\n[Service]\nUser=app\nExecStart=/usr/bin/app\n"
    "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n"
    "CapabilityBoundingSet=\nRestrictAddressFamilies=AF_INET AF_INET6\n"
)


def _controls(result):
    return {(f["control_id"], f["severity"]) for f in result["findings"]}


class HostCisHardeningTests(unittest.TestCase):
    def test_insecure_sshd_flags_root_login_and_empty_passwords(self):
        result = audit_host_config_inline(
            "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\nCiphers aes128-cbc\n"
        )
        self.assertEqual(result["format"], "sniper-host-cis-hardening-inline-v1")
        self.assertEqual(result["config_type"], "sshd")
        self.assertIn(("SNIPER-CONF-09", "high"), _controls(result))
        self.assertIn(("SNIPER-CONF-09", "critical"), _controls(result))
        self.assertTrue(any("Ciphers" in f["title"] for f in result["findings"]))

    def test_hardened_sshd_and_service_have_no_findings(self):
        self.assertEqual(audit_host_config_inline(HARDENED_SSHD)["finding_count"], 0)
        service = audit_host_config_inline(HARDENED_SERVICE, filename="app.service")
        self.assertEqual(service["config_type"], "systemd")
        self.assertEqual(service["finding_count"], 0)

    def test_match_block_override_is_not_treated_as_global(self):
        content = HARDENED_SSHD + "Match User backup\n    PermitRootLogin yes\n"
        self.assertEqual(audit_host_config_inline(content)["finding_count"], 0)

    def test_sysctl_sudoers_and_cron_rules(self):
        sysctl = audit_host_config_inline("kernel.randomize_va_space = 0\n", filename="sysctl.conf")
        self.assertIn(("SNIPER-CONF-11", "high"), _controls(sysctl))
        sudo = audit_host_config_inline("deploy ALL=(ALL) NOPASSWD: ALL\nDefaults !authenticate\n", filename="sudoers")
        self.assertIn(("SNIPER-AUTHZ-05", "high"), _controls(sudo))
        self.assertIn(("SNIPER-AUTHZ-05", "critical"), _controls(sudo))
        cron = audit_host_config_inline("*/5 * * * * root /tmp/run.sh\n", filename="crontab")
        self.assertIn(("SNIPER-CONF-12", "high"), _controls(cron))

    def test_detect_config_type_and_empty_input(self):
        self.assertEqual(detect_config_type("sshd_config", ""), "sshd")
        self.assertEqual(detect_config_type("web.service", ""), "systemd")
        self.assertEqual(detect_config_type("notes.txt", "hello"), "unknown")
        with self.assertRaises(ValueError):
            audit_host_config_inline("   ")

    def test_project_scan_only_reads_known_config_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            project = base / "infra"
            (project / "etc" / "ssh").mkdir(parents=True)
            (project / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin yes\n", encoding="utf-8")
            (project / "README.md").write_text("PermitRootLogin yes\n", encoding="utf-8")
            result = audit_host_config_project(str(project), allowed_roots=(base,))
        self.assertEqual(result["format"], "sniper-host-cis-hardening-audit-v1")
        self.assertEqual(result["scanned_files"], 1)
        self.assertIn("sshd", result["config_types_detected"])
        self.assertIn(("SNIPER-CONF-09", "high"), _controls(result))


if __name__ == "__main__":
    unittest.main()
