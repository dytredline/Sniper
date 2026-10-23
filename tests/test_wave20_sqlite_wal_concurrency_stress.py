from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from unittest.mock import patch

from scanner import normalize_target, utc_now
from storage import Store


class Wave20SqliteWalConcurrencyStressTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="sniper_wave20_wal_stress_")
        self.root = Path(self._tmp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(mode=0o700)
        self.db_path = self.data_dir / "stress.db"
        self.env = patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.store = Store(self.db_path)

    def tearDown(self) -> None:
        self.env.stop()
        self._tmp.cleanup()

    def _assert_wal_and_integrity_ok(self) -> None:
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0]).lower()
        self.assertEqual(journal_mode, "wal")
        self.assertEqual(integrity, "ok")

    def test_01_16_thread_concurrent_target_scan_writes_and_anchor_pinned_pagination(self) -> None:
        seed_target = self.store.create_target(normalize_target("https://seed.example.local"))
        seeded_scan_ids: list[str] = []
        for idx in range(8):
            scan = self.store.create_scan(seed_target["id"])
            self.store.complete_scan(
                scan["id"],
                {
                    "score": 95 - idx,
                    "grade": "A",
                    "findings": [{"id": f"SEED-{idx}", "title": f"Seed {idx}", "severity": "low"}],
                },
            )
            seeded_scan_ids.append(scan["id"])

        first_page = self.store.list_scans_page(limit=4, offset=0)
        anchor = first_page["anchor"]
        expected_page_1 = list(reversed(seeded_scan_ids[4:8]))
        expected_page_2 = list(reversed(seeded_scan_ids[0:4]))
        self.assertEqual([s["id"] for s in first_page["scans"]], expected_page_1)

        barrier = threading.Barrier(16)

        def writer_worker(worker_id: int) -> int:
            local_store = Store(self.db_path)
            barrier.wait(timeout=15.0)
            created = 0
            for step in range(4):
                target = local_store.create_target(
                    normalize_target(f"https://w{worker_id}-s{step}.example.local")
                )
                scan = local_store.create_scan(target["id"])
                local_store.mark_scan_running(scan["id"])
                local_store.complete_scan(
                    scan["id"],
                    {
                        "score": 80,
                        "grade": "B",
                        "findings": [
                            {
                                "id": f"W{worker_id}-{step}",
                                "title": "Concurrent scan finding",
                                "severity": "medium",
                            }
                        ],
                    },
                )
                created += 1
            return created

        def reader_worker(worker_id: int) -> int:
            local_store = Store(self.db_path)
            barrier.wait(timeout=15.0)
            checks = 0
            for _ in range(6):
                p1 = local_store.list_scans_page(limit=4, offset=0, anchor=anchor)
                p2 = local_store.list_scans_page(limit=4, offset=4, anchor=anchor)
                if [s["id"] for s in p1["scans"]] != expected_page_1:
                    raise AssertionError(f"Reader {worker_id} saw mutated page 1 under anchor")
                if [s["id"] for s in p2["scans"]] != expected_page_2:
                    raise AssertionError(f"Reader {worker_id} saw mutated page 2 under anchor")
                if p2["has_more"] is not False:
                    raise AssertionError("Page 2 under seed anchor must not report has_more=True")
                dash = local_store.dashboard()
                if dash["scan_count"] < 8:
                    raise AssertionError("Dashboard scan_count dropped below seed count")
                checks += 1
            return checks

        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = []
            for wid in range(8):
                futures.append(pool.submit(writer_worker, wid))
            for rid in range(8):
                futures.append(pool.submit(reader_worker, rid))
            results = [f.result(timeout=30.0) for f in as_completed(futures)]

        self.assertEqual(len(results), 16)
        all_scans_page = self.store.list_scans_page(limit=200, offset=0)
        # 8 seed scans + 8 writers * 4 scans = 40 scans total
        self.assertEqual( len(all_scans_page["scans"]), 40)
        self._assert_wal_and_integrity_ok()

    def test_02_16_thread_zap_authorization_lease_generation_and_revocation_races(self) -> None:
        target = self.store.create_target(normalize_target("https://example.test/"))
        window = "2026-10-17T10:00:00Z/2026-10-17T14:00:00Z"
        engagement = self.store.create_engagement(
            target_id=target["id"],
            name="Wave 20 Concurrent ZAP Lease Stress",
            authorization_ref="AUTH-W20-ZAP-01",
            scope_notes="FULL_ORIGIN_ACTIVE_SCAN https://example.test",
            out_of_scope="",
            test_window=window,
            special_approvals={},
        )
        eng_id = engagement["id"]
        target_id = target["id"]
        barrier = threading.Barrier(16)

        def zap_lease_worker(worker_id: int) -> list[int]:
            local_store = Store(self.db_path)
            barrier.wait(timeout=15.0)
            generations: list[int] = []
            for step in range(3):
                job_id = f"job-w{worker_id:02d}-s{step:02d}"
                auth = local_store.create_zap_scan_authorization(
                    engagement_id=eng_id,
                    target_id=target_id,
                    requester_principal_id=f"actor.worker:{worker_id:02d}",
                    approved_by="ciso-stress-approver",
                    allowed_paths=["/app", "/api"],
                    excluded_paths=["/app/admin"],
                    approved_ips=["93.184.216.34"],
                    not_before="2026-10-17T10:05:00Z",
                    expires_at="2026-10-17T10:35:00Z",
                    allow_query=True,
                    job_id=job_id,
                )
                generations.append(int(auth["lease_generation"]))
                fetched = local_store.get_zap_scan_authorization(job_id)
                if fetched is None or fetched["id"] != job_id:
                    raise AssertionError(f"Missing authorization record for {job_id}")
                if worker_id % 2 == 0 and step == 1:
                    revoked = local_store.revoke_zap_scan_authorization(
                        job_id,
                        revoked_by=f"revoker-{worker_id:02d}",
                    )
                    if revoked is None or revoked["active"] is not False:
                        raise AssertionError(f"Revocation failed for {job_id}")
                    generations.append(int(revoked["lease_generation"]))
            return generations

        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(zap_lease_worker, wid) for wid in range(16)]
            all_gen_lists = [f.result(timeout=30.0) for f in as_completed(futures)]

        flat_generations = [g for sub in all_gen_lists for g in sub]
        # 16 threads * 3 creates = 48 creates, plus 8 revokes = 56 generation increments
        self.assertEqual(len(flat_generations), 56)
        self.assertEqual(max(flat_generations), 56)

        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            active_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM zap_scan_authorizations WHERE engagement_id = ? AND active = 1",
                    (eng_id,),
                ).fetchone()[0]
            )
            total_rows = int(
                conn.execute(
                    "SELECT COUNT(*) FROM zap_scan_authorizations WHERE engagement_id = ?",
                    (eng_id,),
                ).fetchone()[0]
            )
        self.assertEqual(total_rows, 48)
        self.assertLessEqual(active_count, 1)
        self._assert_wal_and_integrity_ok()

    def test_03_16_thread_manual_findings_risk_accepted_and_project_audit_triage(self) -> None:
        target = self.store.create_target(normalize_target("https://manual-stress.example.local"))
        engagement = self.store.create_engagement(
            target_id=target["id"],
            name="Wave 20 Manual & Triage Stress",
            authorization_ref="AUTH-W20-MAN-01",
            scope_notes="In-scope manual stress",
            out_of_scope="",
            test_window="2026-10-17/2026-10-24",
            special_approvals={
                "controlled_lockout": False,
                "staging_capacity": False,
                "redacted_data_proof": True,
            },
        )
        eng_id = engagement["id"]

        audit = self.store.create_project_audit(
            {
                "created_at": utc_now(),
                "project_path": "/tmp/wave20-synthetic",
                "project_name": "wave20-synthetic",
                "score": 75,
                "grade": "C",
                "file_count": 16,
                "bytes_scanned": 4096,
                "findings": [
                    {
                        "severity": "medium",
                        "title": f"Synthetic Finding {i}",
                        "file": f"mod_{i}.py",
                        "line": i + 1,
                    }
                    for i in range(16)
                ],
            }
        )
        audit_id = audit["id"]
        barrier = threading.Barrier(16)

        def mixed_worker(worker_id: int) -> str:
            local_store = Store(self.db_path)
            barrier.wait(timeout=15.0)
            finding = local_store.create_manual_finding(
                eng_id,
                {
                    "severity": "high" if worker_id % 2 == 0 else "low",
                    "title": f"Worker {worker_id} Manual Finding",
                    "affected_asset": f"/api/v1/resource/{worker_id}",
                    "description": "Concurrent manual finding creation test",
                    "impact": "Controlled synthetic impact",
                    "evidence": f"Trace-{worker_id}",
                    "reproduction": f"GET /api/v1/resource/{worker_id}",
                    "recommendation": "Validate authorization",
                    "status": "open",
                },
            )
            if worker_id % 2 == 1:
                updated = local_store.update_manual_finding(
                    finding["id"],
                    {
                        "status": "risk_accepted",
                        "resolution_notes": f"Risk accepted by worker {worker_id}",
                    },
                )
                if updated is None or updated["status"] != "risk_accepted":
                    raise AssertionError("Failed to transition manual finding to risk_accepted")

            disposition = "confirmed" if worker_id % 2 == 0 else "accepted_risk"
            local_store.update_project_audit_finding_triage(
                audit_id,
                worker_id,
                disposition=disposition,
                note=f"Triaged by worker {worker_id}",
            )
            # Concurrent filtered reads
            _ = local_store.list_manual_findings(eng_id, status="risk_accepted")
            _ = local_store.list_manual_findings(eng_id, status="active")
            return finding["id"]

        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(mixed_worker, wid) for wid in range(16)]
            finding_ids = [f.result(timeout=30.0) for f in as_completed(futures)]

        self.assertEqual(len(set(finding_ids)), 16)
        risk_accepted = self.store.list_manual_findings(eng_id, status="risk_accepted")
        active_only = self.store.list_manual_findings(eng_id, status="active")
        all_manual = self.store.list_manual_findings(eng_id, status="all")
        self.assertEqual(len(risk_accepted), 8)
        self.assertEqual(len(active_only), 8)
        self.assertEqual(len(all_manual), 16)

        final_audit = self.store.get_project_audit(audit_id)
        self.assertIsNotNone(final_audit)
        for idx, item in enumerate(final_audit["findings"]):
            expected_disp = "confirmed" if idx % 2 == 0 else "accepted_risk"
            self.assertEqual(item["triage"]["disposition"], expected_disp)
            self.assertEqual(item["triage"]["note"], f"Triaged by worker {idx}")

        self._assert_wal_and_integrity_ok()


if __name__ == "__main__":
    unittest.main()
