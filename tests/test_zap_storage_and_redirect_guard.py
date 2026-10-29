from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import normalize_target
from storage import Store
import zap_target_active
from zap_target_active import (
    RedirectOriginError,
    check_redirect_origin_guard,
    full_origin_scope_authorized,
    run_zap_target_active,
    validate_redirect_chain,
    validate_redirect_target,
    verify_redirect_origin,
)


class ZapWalApprovalStoreAndRedirectGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_zap_wal_guard_")
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(mode=0o700)
        self.db_path = self.data_dir / "sniper.db"
        self.store = Store(self.db_path)
        self.env = patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()

        self.root_target = self.store.create_target(normalize_target("https://target.example/"))
        self.sub_target = self.store.create_target(normalize_target("https://target.example/app"))
        self.window = "2026-10-17T10:00:00Z/2026-10-17T14:00:00Z"
        self.engagement = self.store.create_engagement(
            target_id=self.root_target["id"],
            name="WAL Authorized Engagement",
            authorization_ref="AUTH-WAL-2026-01",
            scope_notes="FULL_ORIGIN_ACTIVE_SCAN https://target.example",
            out_of_scope="",
            test_window=self.window,
            special_approvals={},
        )
        self.sub_engagement = self.store.create_engagement(
            target_id=self.sub_target["id"],
            name="Subpath Engagement",
            authorization_ref="AUTH-SUB-2026-02",
            scope_notes="Scoped subpath /app",
            out_of_scope="",
            test_window=self.window,
            special_approvals={},
        )

    def tearDown(self) -> None:
        self.env.stop()
        self.temp.cleanup()

    def test_wal_approval_store_lifecycle_generation_and_actor_binding(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0].lower()
        self.assertEqual(mode, "wal")

        auth1 = self.store.create_zap_scan_authorization(
            engagement_id=self.engagement["id"],
            target_id=self.root_target["id"],
            requester_principal_id="actor.sec_lead:01",
            approved_by="ciso-approver",
            allowed_paths=["/app", "/api"],
            excluded_paths=["/app/admin"],
            approved_ips=["93.184.216.34"],
            not_before="2026-10-17T10:05:00Z",
            expires_at="2026-10-17T10:35:00Z",
            allow_query=True,
            job_id="job-wal-001",
        )
        self.assertEqual(auth1["id"], "job-wal-001")
        self.assertEqual(auth1["lease_generation"], 1)
        self.assertTrue(auth1["active"])
        self.assertEqual(auth1["requester_principal_id"], "actor.sec_lead:01")
        self.assertEqual(auth1["allowed_paths"], ["/app", "/api"])
        self.assertEqual(auth1["excluded_paths"], ["/app/admin"])
        self.assertEqual(auth1["approved_ips"], ["93.184.216.34"])

        verified = self.store.verify_zap_scan_authorization(
            "job-wal-001",
            expected_actor="actor.sec_lead:01",
            expected_generation=1,
            now_iso="2026-10-17T10:15:00Z",
        )
        self.assertEqual(verified["id"], "job-wal-001")
        self.assertEqual(verified["lease_generation"], 1)

        # Actor mismatch fails closed.
        with self.assertRaisesRegex(ValueError, "requester_principal_id uyuşmuyor"):
            self.store.verify_zap_scan_authorization(
                "job-wal-001",
                expected_actor="actor.other:02",
                now_iso="2026-10-17T10:15:00Z",
            )

        # Generation mismatch fails closed.
        with self.assertRaisesRegex(ValueError, "lease_generation uyuşmuyor"):
            self.store.verify_zap_scan_authorization(
                "job-wal-001",
                expected_actor="actor.sec_lead:01",
                expected_generation=2,
                now_iso="2026-10-17T10:15:00Z",
            )

        # Issuing a second authorization on the same engagement bumps generation and deactivates prior job.
        auth2 = self.store.create_zap_scan_authorization(
            engagement_id=self.engagement["id"],
            target_id=self.root_target["id"],
            requester_principal_id="actor.sec_lead:01",
            approved_by="ciso-approver",
            allowed_paths=["/app"],
            approved_ips=["93.184.216.34"],
            not_before="2026-10-17T10:10:00Z",
            expires_at="2026-10-17T10:40:00Z",
            job_id="job-wal-002",
        )
        self.assertEqual(auth2["lease_generation"], 2)
        with self.assertRaisesRegex(ValueError, "etkin değil ya da yetkisiz"):
            self.store.verify_zap_scan_authorization(
                "job-wal-001",
                expected_actor="actor.sec_lead:01",
                now_iso="2026-10-17T10:15:00Z",
            )

        # Revoking job-wal-002 increments generation and marks it inactive.
        revoked = self.store.revoke_zap_scan_authorization("job-wal-002", revoked_by="sec-ops")
        self.assertIsNotNone(revoked)
        self.assertFalse(revoked["active"])
        self.assertEqual(revoked["lease_generation"], 3)
        with self.assertRaisesRegex(ValueError, "etkin değil ya da yetkisiz"):
            self.store.verify_zap_scan_authorization(
                "job-wal-002",
                expected_actor="actor.sec_lead:01",
                now_iso="2026-10-17T10:15:00Z",
            )

    def test_wal_approval_store_rejects_out_of_scope_paths_private_ips_and_bad_windows(self) -> None:
        # Subpath target (/app) cannot authorize root (/) or sibling (/outside)
        for bad_paths in (["/"], ["/outside"], ["/app/../outside"], ["//app"], ["/app%2fadmin"]):
            with self.subTest(bad_paths=bad_paths):
                with self.assertRaises(ValueError):
                    self.store.create_zap_scan_authorization(
                        engagement_id=self.sub_engagement["id"],
                        target_id=self.sub_target["id"],
                        requester_principal_id="actor-1",
                        approved_by="approver",
                        allowed_paths=bad_paths,
                        approved_ips=["93.184.216.34"],
                        not_before="2026-10-17T10:05:00Z",
                        expires_at="2026-10-17T10:35:00Z",
                    )

        # Private/loopback/CGNAT IPs rejected
        for bad_ips in (["127.0.0.1"], ["10.0.0.1"], ["100.64.0.1"], ["not-an-ip"], []):
            with self.subTest(bad_ips=bad_ips):
                with self.assertRaises(ValueError):
                    self.store.create_zap_scan_authorization(
                        engagement_id=self.sub_engagement["id"],
                        target_id=self.sub_target["id"],
                        requester_principal_id="actor-1",
                        approved_by="approver",
                        allowed_paths=["/app/v1"],
                        approved_ips=bad_ips,
                        not_before="2026-10-17T10:05:00Z",
                        expires_at="2026-10-17T10:35:00Z",
                    )

        # Lease exceeding engagement window or > 3600s rejected
        for nb, exp in (
            ("2026-10-17T09:55:00Z", "2026-10-17T10:25:00Z"),
            ("2026-10-17T10:00:00Z", "2026-10-17T11:00:01Z"),
            ("2026-10-17T13:50:00Z", "2026-10-17T14:05:00Z"),
        ):
            with self.subTest(nb=nb, exp=exp):
                with self.assertRaises(ValueError):
                    self.store.create_zap_scan_authorization(
                        engagement_id=self.sub_engagement["id"],
                        target_id=self.sub_target["id"],
                        requester_principal_id="actor-1",
                        approved_by="approver",
                        allowed_paths=["/app"],
                        approved_ips=["93.184.216.34"],
                        not_before=nb,
                        expires_at=exp,
                    )

    def test_redirect_origin_guard_enforces_origin_port_scope_and_ip_pins(self) -> None:
        source = "https://target.example/app"
        self.assertEqual(
            validate_redirect_target(
                source,
                "/app/login?next=1",
                allowed_paths=["/app"],
                excluded_paths=["/app/admin"],
                approved_ips=["93.184.216.34"],
                resolved_ips=["93.184.216.34"],
            ),
            "https://target.example/app/login?next=1",
        )
        self.assertEqual(
            verify_redirect_origin(source, "https://target.example/app/dashboard"),
            "https://target.example/app/dashboard",
        )
        self.assertTrue(check_redirect_origin_guard(source, "/app/sub"))
        self.assertFalse(check_redirect_origin_guard(source, "/outside"))

        rejected_locations = (
            "https://evil.example/app",
            "http://target.example/app",
            "https://target.example:8443/app",
            "//evil.example/app",
            "/outside",
            "https://target.example/outside",
            "/app/../outside",
            "/app/%2e%2e/outside",
            "/app%2f../outside",
            "/app\\..\\outside",
            "/app;jsessionid=123",
            "/app/admin/settings",
            "https://user:pass@target.example/app",
            "javascript:alert(1)",
            "/app/login#frag",
        )
        for loc in rejected_locations:
            with self.subTest(location=loc):
                with self.assertRaises(RedirectOriginError):
                    validate_redirect_target(
                        source,
                        loc,
                        allowed_paths=["/app"],
                        excluded_paths=["/app/admin"],
                        approved_ips=["93.184.216.34"],
                    )

        # DNS rebinding on redirect fails closed (different public IP and non-public IP)
        with self.assertRaisesRegex(RedirectOriginError, "sabitlenmiş genel IP kümesinden farklı"):
            validate_redirect_target(
                source,
                "/app/step2",
                approved_ips=["93.184.216.34"],
                resolved_ips=["1.1.1.1"],
            )
        with self.assertRaisesRegex(RedirectOriginError, "genel olmayan bir IP"):
            validate_redirect_target(
                source,
                "/app/step2",
                approved_ips=["93.184.216.34"],
                resolved_ips=["127.0.0.1"],
            )

        # Redirect chain validation
        hops = validate_redirect_chain(
            source,
            ["/app/step1", "https://target.example/app/step2"],
            allowed_paths=["/app"],
            approved_ips=["93.184.216.34"],
        )
        self.assertEqual(
            hops,
            ["https://target.example/app/step1", "https://target.example/app/step2"],
        )
        with self.assertRaises(RedirectOriginError):
            validate_redirect_chain(
                source,
                ["/app/step1", "/outside"],
                allowed_paths=["/app"],
            )

    def test_full_origin_scope_guard_and_runner_redirect_enforcement(self) -> None:
        self.assertTrue(full_origin_scope_authorized(self.root_target, self.engagement))
        self.assertFalse(full_origin_scope_authorized(self.sub_target, self.sub_engagement))
        self.assertFalse(
            full_origin_scope_authorized(
                self.root_target,
                {**self.engagement, "out_of_scope": "/admin"},
            )
        )

        fake_systemd = self.root / "fake-systemd-run"
        fake_systemd.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "root = pathlib.Path(sys.argv[-1]).parent\n"
            "(root / 'report.json').write_text(json.dumps({'site':[{'alerts':[{'riskcode':'1','count':'1'}]}]}))\n",
            encoding="utf-8",
        )
        fake_systemd.chmod(0o700)

        with patch.object(zap_target_active, "resolve_public_ips", return_value=["93.184.216.34"]), \
             patch.object(zap_target_active, "_trusted_runtime", return_value=(str(fake_systemd), self.root)):
            res_v2 = run_zap_target_active(
                self.root_target,
                engagement=self.engagement,
                redirect_locations=["/login", "https://target.example/dashboard"],
            )
            self.assertEqual(res_v2["format"], "zap-target-active-v2")
            self.assertEqual(res_v2["profile"], "full-origin-active-v2")

            with self.assertRaisesRegex(ValueError, "Aktif tarama açık bir tam köken kapsamı gerektirir"):
                run_zap_target_active(self.sub_target, engagement=self.sub_engagement)

            with self.assertRaises(RedirectOriginError):
                run_zap_target_active(
                    self.sub_target,
                    redirect_locations=["https://target.example/outside"],
                )


if __name__ == "__main__":
    unittest.main()
