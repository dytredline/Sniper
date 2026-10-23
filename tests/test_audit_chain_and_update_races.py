"""Kalıcı denetim günlüğü hash zinciri ve kayıp güncelleme yarışı testleri.

Tümü geçici (tempfile) SQLite veritabanı kullanır; canlı veriye dokunmaz.
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_chain_verifier import GENESIS_HASH, compute_audit_entry_hash  # noqa: E402
from audit_integrity import compute_hmac_entry_hash, load_key  # noqa: E402
from scanner import normalize_target  # noqa: E402
from storage import Store  # noqa: E402


def _raw(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


class AuditChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "audit_chain.db"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _ids(self) -> list[int]:
        with _raw(self.db_path) as db:
            return [row["id"] for row in db.execute("SELECT id FROM audit_log ORDER BY id ASC")]

    def _store_with_events(self, count: int = 5) -> Store:
        store = Store(self.db_path)
        for index in range(count):
            store.log("test.event", f"ent_{index}", {"sira": index, "not": "ğüşiöç"})
        return store

    def test_new_entries_are_chained_and_verify(self) -> None:
        store = self._store_with_events(5)
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], True)
        self.assertEqual(result["format"], "sniper-audit-chain-verification-v1")
        self.assertEqual(result["event_count"], 5)
        self.assertEqual(result["chained_count"], 5)
        self.assertEqual(result["legacy_unchained"], 0)
        self.assertIsNone(result["first_broken_id"])
        self.assertEqual(result["tampered_ids"], [])
        with _raw(self.db_path) as db:
            rows = db.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        self.assertEqual(rows[0]["prev_hash"], GENESIS_HASH)
        for previous, current in zip(rows, rows[1:]):
            self.assertEqual(current["prev_hash"], previous["entry_hash"])
        last = rows[-1]
        fields = (last["prev_hash"], last["occurred_at"], last["action"], last["entity_id"], last["details_json"])
        key_state = load_key(db_path=self.db_path)
        if key_state.usable:
            # Anahtar varsa yeni kayıtlar HMAC'li (hmac1:) zincirlenir.
            self.assertEqual(last["entry_hash"], compute_hmac_entry_hash(key_state.key, *fields))
        else:
            self.assertEqual(last["entry_hash"], compute_audit_entry_hash(*fields))
        self.assertEqual(result["head_hash"], last["entry_hash"])

    def test_modified_entry_fails_with_its_id(self) -> None:
        store = self._store_with_events(5)
        target_id = self._ids()[2]
        with _raw(self.db_path) as db:
            db.execute("UPDATE audit_log SET details_json = ? WHERE id = ?", ('{"sira": 999}', target_id))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_id"], target_id)
        self.assertEqual(result["first_broken_reason"], "entry_hash_mismatch")
        # Tek değişiklik yalnız o kaydı bozuk gösterir.
        self.assertEqual(result["tampered_ids"], [target_id])

    def test_modified_action_or_timestamp_fails(self) -> None:
        for column, value in (("action", "sahte.eylem"), ("occurred_at", "2000-01-01T00:00:00Z"), ("entity_id", "x")):
            with self.subTest(column=column):
                self.tearDown()
                self.setUp()
                store = self._store_with_events(3)
                target_id = self._ids()[1]
                with _raw(self.db_path) as db:
                    db.execute(f"UPDATE audit_log SET {column} = ? WHERE id = ?", (value, target_id))
                result = store.verify_audit_chain()
                self.assertIs(result["verified"], False)
                self.assertEqual(result["first_broken_id"], target_id)

    def test_deleted_entry_fails_at_next_id(self) -> None:
        store = self._store_with_events(5)
        ids = self._ids()
        with _raw(self.db_path) as db:
            db.execute("DELETE FROM audit_log WHERE id = ?", (ids[2],))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_id"], ids[3])
        self.assertEqual(result["first_broken_reason"], "prev_hash_mismatch")

    def test_deleted_first_chained_entry_fails(self) -> None:
        store = self._store_with_events(3)
        ids = self._ids()
        with _raw(self.db_path) as db:
            db.execute("DELETE FROM audit_log WHERE id = ?", (ids[0],))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_id"], ids[1])

    def test_reordered_entry_fails(self) -> None:
        store = self._store_with_events(4)
        ids = self._ids()
        with _raw(self.db_path) as db:
            db.execute("UPDATE audit_log SET id = ? WHERE id = ?", (ids[-1] + 100, ids[1]))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_id"], ids[2])

    def test_unchained_insert_after_chain_start_fails(self) -> None:
        store = self._store_with_events(3)
        with _raw(self.db_path) as db:
            cursor = db.execute(
                "INSERT INTO audit_log(occurred_at, action, entity_id, details_json) VALUES (?, ?, ?, ?)",
                ("2026-10-19T00:00:00Z", "sahte.kayit", "ent_x", "{}"),
            )
            injected_id = cursor.lastrowid
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_id"], injected_id)
        self.assertEqual(result["first_broken_reason"], "unchained_after_chain_start")

    def test_stripping_hashes_of_first_entry_is_detected(self) -> None:
        store = self._store_with_events(3)
        ids = self._ids()
        with _raw(self.db_path) as db:
            db.execute("UPDATE audit_log SET prev_hash = NULL, entry_hash = NULL WHERE id = ?", (ids[0],))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_id"], ids[1])

    def test_legacy_rows_then_new_rows_verify_with_legacy_count(self) -> None:
        # Göç öncesi şema: hash sütunları yok.
        with _raw(self.db_path) as db:
            db.execute(
                """CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )"""
            )
            for index in range(3):
                db.execute(
                    "INSERT INTO audit_log(occurred_at, action, entity_id, details_json) VALUES (?, ?, ?, ?)",
                    (f"2026-01-0{index + 1}T00:00:00Z", "legacy.event", f"old_{index}", '{"eski": true}'),
                )
        store = Store(self.db_path)
        # Göç idempotent olmalı.
        store = Store(self.db_path)
        with _raw(self.db_path) as db:
            columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_log)")}
            legacy_rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        self.assertTrue({"prev_hash", "entry_hash"} <= columns)
        self.assertEqual(len(legacy_rows), 3)
        self.assertEqual(legacy_rows[0]["action"], "legacy.event")
        self.assertIsNone(legacy_rows[0]["prev_hash"])
        self.assertIsNone(legacy_rows[0]["entry_hash"])

        only_legacy = store.verify_audit_chain()
        self.assertIs(only_legacy["verified"], True)
        self.assertEqual(only_legacy["legacy_unchained"], 3)
        self.assertEqual(only_legacy["chained_count"], 0)

        for index in range(2):
            store.log("new.event", f"new_{index}", {"i": index})
        mixed = store.verify_audit_chain()
        self.assertIs(mixed["verified"], True)
        self.assertEqual(mixed["legacy_unchained"], 3)
        self.assertEqual(mixed["chained_count"], 2)
        self.assertEqual(mixed["event_count"], 5)
        with _raw(self.db_path) as db:
            first_chained = db.execute(
                "SELECT prev_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id LIMIT 1"
            ).fetchone()
        self.assertEqual(first_chained["prev_hash"], GENESIS_HASH)

        # Legacy kayıt değişikliği zinciri bozmaz (kapsam dışı), ama hash'li bölüm bozulursa yakalanır.
        ids = self._ids()
        with _raw(self.db_path) as db:
            db.execute("UPDATE audit_log SET details_json = '{}' WHERE id = ?", (ids[4],))
        broken = store.verify_audit_chain()
        self.assertIs(broken["verified"], False)
        self.assertEqual(broken["first_broken_id"], ids[4])
        self.assertEqual(broken["legacy_unchained"], 3)

    def test_paged_scan_matches_and_crosses_page_boundaries(self) -> None:
        store = self._store_with_events(7)
        full = store.verify_audit_chain(page_size=1000)
        paged = store.verify_audit_chain(page_size=2)
        self.assertEqual(full, paged)
        self.assertIs(paged["verified"], True)
        self.assertEqual(paged["event_count"], 7)
        ids = self._ids()
        with _raw(self.db_path) as db:
            db.execute("DELETE FROM audit_log WHERE id = ?", (ids[4],))  # sayfa sınırı (2|2|2|1) karşısında
        broken = store.verify_audit_chain(page_size=2)
        self.assertIs(broken["verified"], False)
        self.assertEqual(broken["first_broken_id"], ids[5])

    def test_concurrent_logging_keeps_single_linear_chain(self) -> None:
        store = Store(self.db_path)
        errors: list[BaseException] = []

        def worker(prefix: str) -> None:
            try:
                for index in range(20):
                    store.log("concurrent.event", f"{prefix}_{index}", {"i": index})
            except BaseException as exc:  # pragma: no cover - teşhis için
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"t{n}",)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertEqual(errors, [])
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], True)
        self.assertEqual(result["chained_count"], 80)
        with _raw(self.db_path) as db:
            distinct_prev = db.execute("SELECT COUNT(DISTINCT prev_hash) FROM audit_log").fetchone()[0]
        self.assertEqual(distinct_prev, 80)  # çatallanma yok

    def test_recent_audit_log_exposes_id_and_old_verifier_stays_compatible(self) -> None:
        from audit_chain_verifier import verify_audit_log_chain

        store = self._store_with_events(2)
        events = store.recent_audit_log(limit=5)
        self.assertEqual(len(events), 2)
        self.assertGreater(events[0]["id"], events[1]["id"])  # liste görünümü DESC kalır
        self.assertNotIn("entry_hash", events[0])
        self.assertEqual(events[0]["details"]["sira"], 1)
        # server.py henüz yamalanmadıysa eski uç nokta yanlış alarm üretmemeli.
        self.assertIs(verify_audit_log_chain(events)["verified"], True)

    def test_append_helper_requires_transaction(self) -> None:
        store = Store(self.db_path)
        with store._connect() as db:
            with self.assertRaises(sqlite3.ProgrammingError):
                store._append_audit_log(db, "x", "y", "{}")


class _PauseHook:
    """Yalnız belirli bir thread'in bağlantısında, verilen SQL ifadesi başlarken bekletir.

    Bekleme `release` olayına (en çok `timeout` sn) kadar sürer. Düzeltilmiş kodda karşı thread yazma
    kilidinde bekleyeceği için `release` hiç gelmez ve zaman aşımıyla devam edilir; düzeltilmemiş
    kodda karşı thread işini bitirir, ardından bekletilen thread eski veriyle yazar (yarış yeniden üretilir).
    """

    def __init__(self, store: Store, thread_name: str, sql_prefix: str, release: threading.Event, timeout: float) -> None:
        self.reached = threading.Event()
        self._fired = False
        original = store._connect

        @contextmanager
        def hooked():
            with original() as db:
                if threading.current_thread().name == thread_name:
                    def trace(statement: str) -> None:
                        if not self._fired and statement.lstrip().upper().startswith(sql_prefix):
                            self._fired = True
                            self.reached.set()
                            release.wait(timeout)

                    db.set_trace_callback(trace)
                yield db

        store._connect = hooked  # type: ignore[method-assign]


class LostUpdateRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self._tmp.name) / "race.db")
        target = self.store.create_target(normalize_target("https://race.example.com"))
        self.engagement = self.store.create_engagement(
            target_id=target["id"], name="Yarış testi", authorization_ref="SO-RACE-1",
            scope_notes="eski kapsam", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_pair(self, paused_call, other_call, sql_prefix: str) -> None:
        other_done = threading.Event()
        hook = _PauseHook(self.store, "paused-writer", sql_prefix, other_done, timeout=1.5)
        errors: list[BaseException] = []

        def wrap(call, done: threading.Event | None = None):
            def run() -> None:
                try:
                    call()
                except BaseException as exc:  # pragma: no cover - teşhis için
                    errors.append(exc)
                finally:
                    if done is not None:
                        done.set()
            return run

        paused = threading.Thread(target=wrap(paused_call), name="paused-writer")
        paused.start()
        self.assertTrue(hook.reached.wait(10), "bekletme noktasına ulaşılamadı")
        other = threading.Thread(target=wrap(other_call, other_done), name="other-writer")
        other.start()
        paused.join(30)
        other.join(30)
        self.assertFalse(paused.is_alive() or other.is_alive())
        self.assertEqual(errors, [])

    def test_engagement_pause_is_not_overwritten_by_concurrent_scope_update(self) -> None:
        engagement_id = self.engagement["id"]
        self._run_pair(
            lambda: self.store.update_engagement(engagement_id, {"scope_notes": "yeni kapsam"}),
            lambda: self.store.update_engagement(engagement_id, {"status": "paused"}),
            "UPDATE ENGAGEMENTS",
        )
        final = self.store.get_engagement(engagement_id)
        self.assertEqual(final["status"], "paused")
        self.assertEqual(final["scope_notes"], "yeni kapsam")
        self.assertIs(self.store.verify_audit_chain()["verified"], True)

    def _create_finding(self) -> dict:
        return self.store.create_manual_finding(self.engagement["id"], {
            "severity": "high", "title": "Yarış bulgusu", "affected_asset": "/api/x",
            "description": "d", "impact": "i", "evidence": "e", "reproduction": "r", "recommendation": "rec",
        })

    def test_manual_finding_status_history_uses_in_transaction_value(self) -> None:
        finding = self._create_finding()
        self._run_pair(
            lambda: self.store.update_manual_finding(finding["id"], {"status": "in_progress"}),
            lambda: self.store.update_manual_finding(finding["id"], {"status": "resolved"}),
            "UPDATE MANUAL_FINDINGS",
        )
        with _raw(self.store.path) as db:
            final = db.execute("SELECT status, resolved_at FROM manual_findings WHERE id = ?", (finding["id"],)).fetchone()
            history = [
                (row["from_status"], row["to_status"])
                for row in db.execute(
                    "SELECT from_status, to_status FROM manual_finding_status_history WHERE finding_id = ? ORDER BY id",
                    (finding["id"],),
                )
            ]
        self.assertEqual(final["status"], "resolved")
        self.assertIsNotNone(final["resolved_at"])
        self.assertEqual(history, [("open", "in_progress"), ("in_progress", "resolved")])

    def test_manual_finding_field_update_does_not_revert_concurrent_status(self) -> None:
        finding = self._create_finding()
        self._run_pair(
            lambda: self.store.update_manual_finding(finding["id"], {"title": "Yeni başlık"}),
            lambda: self.store.update_manual_finding(finding["id"], {"status": "risk_accepted"}),
            "UPDATE MANUAL_FINDINGS",
        )
        with _raw(self.store.path) as db:
            final = db.execute("SELECT status, title FROM manual_findings WHERE id = ?", (finding["id"],)).fetchone()
        self.assertEqual(final["status"], "risk_accepted")
        self.assertEqual(final["title"], "Yeni başlık")

    def test_manual_test_tested_at_computed_inside_transaction(self) -> None:
        control_id = self.engagement["tests"][0]["control_id"]
        engagement_id = self.engagement["id"]
        self._run_pair(
            lambda: self.store.update_manual_test(engagement_id, control_id, status="passed", notes="A", evidence="a"),
            lambda: self.store.update_manual_test(engagement_id, control_id, status="failed", notes="B", evidence="b"),
            "UPDATE MANUAL_TESTS",
        )
        with _raw(self.store.path) as db:
            row = db.execute(
                "SELECT status, notes, tested_at FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement_id, control_id),
            ).fetchone()
        # İkinci yazan (other-writer) birinci yazanın sonucunu işlem içinde görüp üzerine yazar.
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["notes"], "B")
        self.assertIsNotNone(row["tested_at"])

    def test_invalid_manual_test_status_rejected_before_db(self) -> None:
        control_id = self.engagement["tests"][0]["control_id"]
        with self.assertRaises(ValueError):
            self.store.update_manual_test(self.engagement["id"], control_id, status="bogus", notes="", evidence="")


if __name__ == "__main__":
    unittest.main()
