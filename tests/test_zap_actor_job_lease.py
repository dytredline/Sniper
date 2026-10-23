import json
import os
import stat
import sys
import tempfile
import time
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


class ZapActorJobLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zap_lease_test_")
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(mode=0o700)
        self.store_path = self.data_dir / "zap_leases.json"
        self.env = patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        normalized = normalize_target("https://example.test/")
        self.target = {
            "id": "target-1",
            "url": normalized.url,
            "scheme": normalized.scheme,
            "hostname": normalized.hostname,
            "port": normalized.port,
            "path": normalized.path,
        }

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_valid_lease_issuance_and_verification(self):
        store = ActorJobLeaseStore(self.store_path)
        self.assertEqual(store.current_generation(), 0)
        info = self.store_path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)

        now = 1_700_000_000.0
        lease = store.issue_lease(
            actor_id="actor.sec_01:lead-a",
            job_id="job:zap_active-01",
            target_origin="https://example.test/",
            ttl_seconds=180.0,
            now=now,
        )
        self.assertEqual(store.current_generation(), 1)
        self.assertEqual(
            set(lease.keys()),
            {"actor_id", "job_id", "target_origin", "generation", "expires_at_epoch"},
        )
        self.assertEqual(lease.actor_id, "actor.sec_01:lead-a")
        self.assertEqual(lease.job_id, "job:zap_active-01")
        self.assertEqual(lease.target_origin, "https://example.test/")
        self.assertEqual(lease.generation, 1)
        self.assertEqual(lease.expires_at_epoch, now + 180.0)

        verified = verify_actor_job_lease(
            lease,
            expected_actor="actor.sec_01:lead-a",
            expected_job_id="job:zap_active-01",
            expected_target="https://example.test/",
            store_path=self.store_path,
            now=now + 30.0,
        )
        self.assertEqual(verified["generation"], 1)
        self.assertEqual(verified["actor_id"], "actor.sec_01:lead-a")
        self.assertEqual(verified["job_id"], "job:zap_active-01")

    def test_rebinding_old_approval_to_another_job_actor_or_target_fails_closed(self):
        store = ActorJobLeaseStore(self.store_path)
        now = time.time()
        lease = store.issue_lease(
            actor_id="actor-alpha",
            job_id="job-100",
            target_origin="https://example.test/",
            now=now,
        )

        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-alpha",
                expected_job_id="job-200",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 1.0,
            )

        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-beta",
                expected_job_id="job-100",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 1.0,
            )

        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-alpha",
                expected_job_id="job-100",
                expected_target="https://other.example/",
                store_path=self.store_path,
                now=now + 1.0,
            )

        rebound_job = lease.copy()
        rebound_job["job_id"] = "job-200"
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                rebound_job,
                expected_actor="actor-alpha",
                expected_job_id="job-200",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 1.0,
            )

        rebound_actor = lease.copy()
        rebound_actor["actor_id"] = "actor-beta"
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                rebound_actor,
                expected_actor="actor-beta",
                expected_job_id="job-100",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 1.0,
            )

        rebound_target = lease.copy()
        rebound_target["target_origin"] = "https://other.example/"
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                rebound_target,
                expected_actor="actor-alpha",
                expected_job_id="job-100",
                expected_target="https://other.example/",
                store_path=self.store_path,
                now=now + 1.0,
            )

        # Issuing a second lease advances store generation and invalidates the prior lease.
        lease2 = store.issue_lease(
            actor_id="actor-alpha",
            job_id="job-200",
            target_origin="https://example.test/",
            now=now + 2.0,
        )
        self.assertEqual(lease2["generation"], 2)
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-alpha",
                expected_job_id="job-100",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 3.0,
            )

    def test_direct_unissued_dict_forged_generation_revoked_and_expired_leases_fail_closed(self):
        store = ActorJobLeaseStore(self.store_path)
        now = 1_700_000_000.0
        lease = store.issue_lease(
            actor_id="actor-1",
            job_id="job-1",
            target_origin="https://example.test/",
            ttl_seconds=60.0,
            now=now,
        )

        # Plain unissued dictionary with identical fields must fail closed.
        unissued_dict = {
            "actor_id": "actor-1",
            "job_id": "job-1",
            "target_origin": "https://example.test/",
            "generation": 1,
            "expires_at_epoch": now + 60.0,
        }
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                unissued_dict,
                expected_actor="actor-1",
                expected_job_id="job-1",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 5.0,
            )

        # Invalid/forged/non-positive/boolean generations must fail closed.
        for bad_gen in (0, -1, -100, True, False, "1", 1.0, None, 2, 999, 1 << 63):
            with self.subTest(bad_gen=bad_gen):
                forged = lease.copy()
                forged["generation"] = bad_gen
                with self.assertRaises(ZapLeaseError):
                    verify_actor_job_lease(
                        forged,
                        expected_actor="actor-1",
                        expected_job_id="job-1",
                        expected_target="https://example.test/",
                        store_path=self.store_path,
                        now=now + 5.0,
                    )

        # Invalid actor_id / job_id formats must fail closed on issuance.
        for bad_id in ("", " ", "actor/1", "actor id", "a" * 65, "../etc", "actor\n1"):
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(ZapLeaseError):
                    store.issue_lease(
                        actor_id=bad_id,
                        job_id="job-ok",
                        target_origin="https://example.test/",
                        now=now,
                    )
                with self.assertRaises(ZapLeaseError):
                    store.issue_lease(
                        actor_id="actor-ok",
                        job_id=bad_id,
                        target_origin="https://example.test/",
                        now=now,
                    )

        # Expired lease fails closed.
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-1",
                expected_job_id="job-1",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 60.0,
            )

        # Revoking job or actor increments generation and immediately invalidates lease.
        new_gen = store.revoke_job("job-1")
        self.assertEqual(new_gen, 2)
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease,
                expected_actor="actor-1",
                expected_job_id="job-1",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 10.0,
            )

        lease_actor_revoke = store.issue_lease(
            actor_id="actor-1",
            job_id="job-2",
            target_origin="https://example.test/",
            ttl_seconds=60.0,
            now=now,
        )
        self.assertEqual(lease_actor_revoke["generation"], 3)
        gen_after_actor_revoke = store.revoke_actor("actor-1")
        self.assertEqual(gen_after_actor_revoke, 4)
        with self.assertRaises(ZapLeaseError):
            verify_actor_job_lease(
                lease_actor_revoke,
                expected_actor="actor-1",
                expected_job_id="job-2",
                expected_target="https://example.test/",
                store_path=self.store_path,
                now=now + 10.0,
            )

    def test_non_regular_files_and_symlinks_rejected(self):
        fifo_path = self.data_dir / "fifo.json"
        os.mkfifo(fifo_path, 0o600)
        with self.assertRaises(ZapLeaseError):
            ActorJobLeaseStore(fifo_path)

        real_file = self.data_dir / "real.json"
        real_file.write_text("{}", encoding="utf-8")
        real_file.chmod(0o600)
        symlink_path = self.data_dir / "link.json"
        symlink_path.symlink_to(real_file)
        with self.assertRaises(ZapLeaseError):
            ActorJobLeaseStore(symlink_path)

        bad_mode_path = self.data_dir / "bad_mode.json"
        bad_mode_path.write_text("{}", encoding="utf-8")
        bad_mode_path.chmod(0o644)
        with self.assertRaises(ZapLeaseError):
            ActorJobLeaseStore(bad_mode_path)

    def test_integration_with_zap_target_active_and_spider(self):
        store = ActorJobLeaseStore(self.store_path)
        lease = store.issue_lease(
            actor_id="actor-runner",
            job_id="job-active-1",
            target_origin="https://example.test/",
        )

        fake_systemd = self.root / "fake-systemd-run"
        fake_systemd.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "root = pathlib.Path(sys.argv[-1]).parent\n"
            "(root / 'report.json').write_text(json.dumps({'site':[{'alerts':[{'riskcode':'2','count':'1'}]}]}))\n",
            encoding="utf-8",
        )
        fake_systemd.chmod(0o700)

        with patch.object(zap_target_active, "resolve_public_ips", return_value=["93.184.216.34"]), \
             patch.object(zap_target_active, "_trusted_runtime", return_value=(str(fake_systemd), self.root)):
            summary = zap_target_active.run_zap_target_active(self.target, actor_lease=lease)
            self.assertEqual(summary["format"], "zap-target-active-v1")
            self.assertEqual(summary["risk_counts"]["medium"], 1)

            # Preserves existing behavior when actor_lease is None.
            summary_no_lease = zap_target_active.run_zap_target_active(self.target)
            self.assertEqual(summary_no_lease["format"], "zap-target-active-v1")

        # Revoking the lease prevents scanner execution before DNS or runtime lookup.
        store.revoke_actor("actor-runner")
        with patch.object(zap_target_active, "resolve_public_ips") as dns_mock, \
             patch.object(zap_target_active, "_trusted_runtime") as runtime_mock:
            with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
                zap_target_active.run_zap_target_active(self.target, actor_lease=lease)
            dns_mock.assert_not_called()
            runtime_mock.assert_not_called()

        # Re-binding a valid lease to another target or spidering with an invalid lease fails closed.
        lease2 = store.issue_lease(
            actor_id="actor-runner",
            job_id="job-spider-1",
            target_origin="https://example.test/",
        )
        other_norm = normalize_target("https://other.example/")
        other_target = {
            "id": "target-2",
            "url": other_norm.url,
            "scheme": other_norm.scheme,
            "hostname": other_norm.hostname,
            "port": other_norm.port,
            "path": other_norm.path,
        }
        with patch.object(zap_target_active, "resolve_public_ips") as dns_mock:
            with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
                zap_target_active.run_zap_target_active(other_target, actor_lease=lease2)
            dns_mock.assert_not_called()

        with patch("zap_target_spider.run_zap_target_spider", return_value={"format": "zap-target-spider-v1"}) as spider_mock:
            res = zap_target_active.run_zap_target_spider(self.target, ["/admin"], actor_lease=lease2)
            self.assertEqual(res["format"], "zap-target-spider-v1")
            spider_mock.assert_called_once_with(self.target, ["/admin"])

            store.revoke_job("job-spider-1")
            with self.assertRaisesRegex(ValueError, "Geçersiz ZAP aktör-iş kiralaması"):
                zap_target_active.run_zap_target_spider(self.target, ["/admin"], actor_lease=lease2)
            self.assertEqual(spider_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
