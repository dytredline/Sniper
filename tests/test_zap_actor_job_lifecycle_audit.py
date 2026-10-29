import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import normalize_target
import zap_target_active
from zap_actor_job_lease import (
    ActorJobLeaseStore,
    ZapLeaseError,
    verify_actor_job_lease,
)


class ZapActorJobLifecycleAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zap_lifecycle_audit_")
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(mode=0o700)
        self.store_path = self.data_dir / "zap_lifecycle_leases.json"
        self.env = patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        normalized = normalize_target("https://target.example/")
        self.target = {
            "id": "target-audit-1",
            "url": normalized.url,
            "scheme": normalized.scheme,
            "hostname": normalized.hostname,
            "port": normalized.port,
            "path": normalized.path,
        }

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_sequential_and_multi_actor_revocation_blocks_active_and_spider_before_subprocess(self):
        store = ActorJobLeaseStore(self.store_path)
        now = 1_700_100_000.0

        lease_a = store.issue_lease(
            actor_id="actor-a",
            job_id="job-a-1",
            target_origin="https://target.example/",
            ttl_seconds=120.0,
            now=now,
        )
        self.assertEqual(lease_a.generation, 1)

        # Revoking Actor A bumps generation to 2 and invalidates Actor A's in-flight lease.
        gen_after_revoke_a = store.revoke_actor("actor-a")
        self.assertEqual(gen_after_revoke_a, 2)

        with patch.object(subprocess, "Popen") as popen_mock, \
             patch.object(zap_target_active, "resolve_public_ips") as dns_mock, \
             patch.object(zap_target_active, "_trusted_runtime") as runtime_mock:
            with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
                zap_target_active.run_zap_target_active(self.target, actor_lease=lease_a)
            with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
                zap_target_active.run_zap_target_spider(self.target, ["/admin"], actor_lease=lease_a)
            popen_mock.assert_not_called()
            dns_mock.assert_not_called()
            runtime_mock.assert_not_called()

        # Issue a new lease to Actor B (generation 3); Actor A's lease remains invalid.
        lease_b = store.issue_lease(
            actor_id="actor-b",
            job_id="job-b-1",
            target_origin="https://target.example/",
            ttl_seconds=120.0,
            now=now + 5.0,
        )
        self.assertEqual(lease_b.generation, 3)

        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease_a,
                expected_actor="actor-a",
                expected_job_id="job-a-1",
                expected_target="https://target.example/",
                store_path=self.store_path,
                now=now + 6.0,
            )

        verified_b = verify_actor_job_lease(
            lease_b,
            expected_actor="actor-b",
            expected_job_id="job-b-1",
            expected_target="https://target.example/",
            store_path=self.store_path,
            now=now + 6.0,
        )
        self.assertEqual(verified_b["generation"], 3)

        # Revoking Actor B's job bumps generation to 4 and blocks execution before subprocess.
        gen_after_revoke_b = store.revoke_job("job-b-1")
        self.assertEqual(gen_after_revoke_b, 4)
        with patch.object(subprocess, "Popen") as popen_mock:
            with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
                zap_target_active.run_zap_target_active(self.target, actor_lease=lease_b)
            with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
                zap_target_active.run_zap_target_spider(self.target, ["/admin"], actor_lease=lease_b)
            popen_mock.assert_not_called()

    def test_persistence_across_store_reloads_preserves_0600_mode_and_monotonic_generation(self):
        store_1 = ActorJobLeaseStore(self.store_path)
        self.assertEqual(store_1.current_generation(), 0)
        self.assertEqual(stat.S_IMODE(self.store_path.lstat().st_mode), 0o600)

        now = 1_700_200_000.0
        lease_1 = store_1.issue_lease(
            actor_id="actor-persist-1",
            job_id="job-persist-1",
            target_origin="https://target.example/",
            ttl_seconds=300.0,
            now=now,
        )
        self.assertEqual(lease_1.generation, 1)
        self.assertEqual(stat.S_IMODE(self.store_path.lstat().st_mode), 0o600)

        # Reload store from disk in a second instance; verify lease_1 and issue lease_2.
        store_2 = ActorJobLeaseStore(self.store_path)
        self.assertEqual(store_2.current_generation(), 1)
        verified_1 = store_2.verify_lease(
            lease_1,
            expected_actor="actor-persist-1",
            expected_job_id="job-persist-1",
            expected_target="https://target.example/",
            now=now + 10.0,
        )
        self.assertEqual(verified_1["generation"], 1)

        lease_2 = store_2.issue_lease(
            actor_id="actor-persist-2",
            job_id="job-persist-2",
            target_origin="https://target.example/",
            ttl_seconds=300.0,
            now=now + 20.0,
        )
        self.assertEqual(lease_2.generation, 2)
        self.assertEqual(stat.S_IMODE(self.store_path.lstat().st_mode), 0o600)

        # Reload a third instance; lease_1 is now stale while lease_2 is active until revoked.
        store_3 = ActorJobLeaseStore(self.store_path)
        self.assertEqual(store_3.current_generation(), 2)
        with self.assertRaises(ZapLeaseError):
            store_3.verify_lease(
                lease_1,
                expected_actor="actor-persist-1",
                expected_job_id="job-persist-1",
                expected_target="https://target.example/",
                now=now + 25.0,
            )
        verified_2 = store_3.verify_lease(
            lease_2,
            expected_actor="actor-persist-2",
            expected_job_id="job-persist-2",
            expected_target="https://target.example/",
            now=now + 25.0,
        )
        self.assertEqual(verified_2["generation"], 2)

        gen_3 = store_3.revoke(job_id="job-persist-2")
        self.assertEqual(gen_3, 3)
        self.assertEqual(stat.S_IMODE(self.store_path.lstat().st_mode), 0o600)

    def test_tampered_hmac_token_or_tampered_disk_json_fails_closed(self):
        store = ActorJobLeaseStore(self.store_path)
        now = 1_700_300_000.0
        lease = store.issue_lease(
            actor_id="actor-integrity",
            job_id="job-integrity-1",
            target_origin="https://target.example/",
            ttl_seconds=300.0,
            now=now,
        )

        # 1. Tamper with in-memory HMAC token on the lease object.
        tampered_lease = lease.copy()
        object.__setattr__(tampered_lease, "_lease_token", "0" * 64)
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                tampered_lease,
                expected_actor="actor-integrity",
                expected_job_id="job-integrity-1",
                expected_target="https://target.example/",
                store_path=self.store_path,
                now=now + 5.0,
            )
        with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
            zap_target_active.run_zap_target_active(self.target, actor_lease=tampered_lease)

        # 2. Tamper with stored HMAC token on disk while preserving 0600 permissions.
        raw_state = json.loads(self.store_path.read_text(encoding="utf-8"))
        tampered_disk_token = json.loads(json.dumps(raw_state))
        tampered_disk_token["leases"]["job-integrity-1"]["token"] = "f" * 64
        self.store_path.write_text(json.dumps(tampered_disk_token), encoding="utf-8")
        self.store_path.chmod(0o600)
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-integrity",
                expected_job_id="job-integrity-1",
                expected_target="https://target.example/",
                store_path=self.store_path,
                now=now + 5.0,
            )

        # 3. Tamper with on-disk generation (rollback below high-water mark).
        rollback_state = json.loads(json.dumps(raw_state))
        rollback_state["generation"] = 0
        self.store_path.write_text(json.dumps(rollback_state), encoding="utf-8")
        self.store_path.chmod(0o600)
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-integrity",
                expected_job_id="job-integrity-1",
                expected_target="https://target.example/",
                store_path=self.store_path,
                now=now + 5.0,
            )

        # 4. Corrupt on-disk JSON syntax completely.
        self.store_path.write_text("{corrupted-json", encoding="utf-8")
        self.store_path.chmod(0o600)
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-integrity",
                expected_job_id="job-integrity-1",
                expected_target="https://target.example/",
                store_path=self.store_path,
                now=now + 5.0,
            )
        with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
            zap_target_active.run_zap_target_active(self.target, actor_lease=lease)


if __name__ == "__main__":
    unittest.main()
