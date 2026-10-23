"""Anahtarlı (HMAC) denetim zinciri ve veritabanı dışı çapa testleri.

Anahtar ve çapalar her testte geçici dizindedir; kullanıcının ~/.config dizinine dokunulmaz.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit_integrity  # noqa: E402
from audit_chain_verifier import GENESIS_HASH, compute_audit_entry_hash  # noqa: E402
from storage import Store  # noqa: E402


def _raw(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


class AuditHmacAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.key_dir = root / "config" / "sniper"
        self.key_file = self.key_dir / "audit.key"
        self.anchor_dir = root / "config" / "sniper" / "audit-anchors"
        self.db_path = root / "data" / "sniper.db"
        self._env = mock.patch.dict(os.environ, {
            "SNIPER_AUDIT_KEY_FILE": str(self.key_file),
            "SNIPER_AUDIT_ANCHOR_DIR": str(self.anchor_dir),
        })
        self._env.start()
        os.environ.pop("SNIPER_AUDIT_HMAC", None)

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def _store(self, count: int = 4) -> Store:
        store = Store(self.db_path)
        for index in range(count):
            store.log("hmac.event", f"ent_{index}", {"i": index})
        return store

    def _rows(self) -> list[sqlite3.Row]:
        with _raw(self.db_path) as db:
            return db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()

    def _anchor_file(self) -> Path:
        return audit_integrity.anchor_path_for(self.db_path)

    # --- anahtar oluşturma ve kayıt şeması ---------------------------------------------------

    def test_key_created_private_and_entries_are_hmac(self) -> None:
        store = self._store(3)
        info = os.stat(self.key_file)
        self.assertEqual(info.st_mode & 0o777, 0o600)
        self.assertEqual(info.st_size, 32)
        self.assertEqual(os.stat(self.key_dir).st_mode & 0o777, 0o700)
        rows = self._rows()
        self.assertEqual(rows[0]["prev_hash"], GENESIS_HASH)
        self.assertTrue(all(row["entry_hash"].startswith("hmac1:") for row in rows))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], True, result)
        self.assertEqual(result["integrity"], "hmac_anchored")
        self.assertEqual(result["hmac"]["status"], "ok")
        self.assertEqual(result["hmac"]["hmac_entries"], 3)
        self.assertEqual(result["anchor"]["status"], "ok")
        self.assertIs(result["anchor"]["authenticated"], True)
        self.assertIs(result["anchor"]["head_matches"], True)
        # Anahtar baytları hiçbir çıktıda yer almaz.
        key_bytes = self.key_file.read_bytes()
        serialized = json.dumps(result).encode()
        self.assertNotIn(key_bytes.hex().encode(), serialized)
        self.assertNotIn(key_bytes.hex().encode(), self._anchor_file().read_bytes())
        self.assertNotIn(key_bytes.hex(), repr(audit_integrity.load_key()))

    def test_recomputed_plain_sha_chain_is_rejected(self) -> None:
        """Saldırgan anahtarsız zinciri baştan hesaplarsa (şema düşürme) yakalanır."""
        store = self._store(3)
        target = self._rows()[1]["id"]
        with _raw(self.db_path) as db:
            db.execute("UPDATE audit_log SET details_json = ? WHERE id = ?", ('{"i": 99}', target))
            prev = GENESIS_HASH
            for row in db.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
                entry = compute_audit_entry_hash(prev, row["occurred_at"], row["action"], row["entity_id"],
                                                 row["details_json"])
                db.execute("UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?", (prev, entry, row["id"]))
                prev = entry
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["integrity"], "broken")
        self.assertIn("anchor_head_mismatch", result["integrity_problems"])

    def test_tampered_hmac_entry_detected(self) -> None:
        store = self._store(4)
        target = self._rows()[2]["id"]
        with _raw(self.db_path) as db:
            db.execute("UPDATE audit_log SET action = 'sahte' WHERE id = ?", (target,))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_id"], target)
        self.assertEqual(result["first_broken_reason"], "entry_hash_mismatch")
        self.assertEqual(result["tampered_ids"], [target])

    def test_tail_deletion_detected_by_anchor(self) -> None:
        store = self._store(5)
        last = self._rows()[-1]["id"]
        with _raw(self.db_path) as db:
            db.execute("DELETE FROM audit_log WHERE id = ?", (last,))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_reason"], "anchor_tail_truncated")
        self.assertIs(result["anchor"]["head_matches"], False)

    def test_rollback_to_backup_detected(self) -> None:
        store = self._store(3)
        backup = self.db_path.with_suffix(".bak")
        with _raw(self.db_path) as src, sqlite3.connect(backup) as dst:
            src.backup(dst)
        store.log("hmac.event", "after_backup", {"i": 3})
        store.log("hmac.event", "after_backup", {"i": 4})
        with _raw(backup) as src, sqlite3.connect(self.db_path) as dst:
            src.backup(dst)
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertIn("anchor_tail_truncated", result["integrity_problems"])

    def test_rewritten_tail_with_same_count_detected(self) -> None:
        store = self._store(3)
        last = self._rows()[-1]
        with _raw(self.db_path) as db:
            db.execute("DELETE FROM audit_log WHERE id = ?", (last["id"],))
        # Aynı id'ye anahtarsız ama zincire uyumlu sahte kayıt.
        fake = compute_audit_entry_hash(last["prev_hash"], last["occurred_at"], "sahte", "x", "{}")
        with _raw(self.db_path) as db:
            db.execute("""INSERT INTO audit_log(id, occurred_at, action, entity_id, details_json, prev_hash, entry_hash)
                          VALUES (?, ?, 'sahte', 'x', '{}', ?, ?)""",
                       (last["id"], last["occurred_at"], last["prev_hash"], fake))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertIn("anchor_head_mismatch", result["integrity_problems"])
        self.assertEqual(result["first_broken_reason"], "scheme_downgrade")

    # --- çapa kurcalama -----------------------------------------------------------------------

    def test_forged_anchor_mac_detected(self) -> None:
        store = self._store(3)
        path = self._anchor_file()
        data = json.loads(path.read_text())
        data["last_id"] = 1
        data["chained_count"] = 1
        path.write_text(json.dumps(data))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertIn("anchor_mac_invalid", result["integrity_problems"])

    def test_unauthenticated_anchor_rejected_when_key_present(self) -> None:
        store = self._store(3)
        path = self._anchor_file()
        data = json.loads(path.read_text())
        data["mac"] = None
        path.write_text(json.dumps(data))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertIn("anchor_unauthenticated", result["integrity_problems"])

    def test_missing_anchor_with_hmac_chain_fails(self) -> None:
        store = self._store(2)
        self._anchor_file().unlink()
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertIn("anchor_missing", result["integrity_problems"])

    def test_anchor_lag_is_reported_not_failed(self) -> None:
        store = self._store(2)
        anchored = json.loads(self._anchor_file().read_text())
        with mock.patch("storage.write_audit_anchor", return_value="anchor_write_failed"):
            store.log("hmac.event", "lag", {})
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], True, result)
        self.assertEqual(result["anchor"]["last_id"], anchored["last_id"])
        self.assertEqual(result["anchor"]["entries_after_anchor"], 1)

    def test_rolled_back_transaction_does_not_advance_anchor(self) -> None:
        store = self._store(2)
        before = self._anchor_file().read_bytes()
        with self.assertRaises(RuntimeError):
            with store._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                store._append_audit_log(db, "geri.alinacak", "x", "{}")
                raise RuntimeError("iptal")
        self.assertEqual(self._anchor_file().read_bytes(), before)
        self.assertIs(store.verify_audit_chain()["verified"], True)

    def test_anchors_are_per_database(self) -> None:
        self._store(3)
        other_db = Path(self._tmp.name) / "other" / "sniper.db"
        other = Store(other_db)
        other.log("other.event", "o", {})
        self.assertNotEqual(audit_integrity.anchor_path_for(other_db), self._anchor_file())
        self.assertIs(other.verify_audit_chain()["verified"], True)
        self.assertIs(Store(self.db_path).verify_audit_chain()["verified"], True)

    # --- anahtar sorunları --------------------------------------------------------------------

    def test_wrong_key_fails(self) -> None:
        store = self._store(3)
        os.chmod(self.key_file, 0o600)
        self.key_file.write_bytes(os.urandom(32))
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["first_broken_reason"], "entry_hash_mismatch")
        self.assertIn("anchor_mac_invalid", result["integrity_problems"])

    def test_missing_key_is_unverifiable_and_not_silently_regenerated(self) -> None:
        store = self._store(3)
        self.key_file.unlink()
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["integrity"], "unverifiable")
        self.assertEqual(result["hmac"]["status"], "missing")
        self.assertEqual(result["tampered_ids"], [])
        # Yeni kayıt çökmeden eklenir ama anahtar yeniden üretilmez; anahtarsız kayıt düşürme sayılır.
        store.log("after.key.loss", "x", {})
        self.assertFalse(self.key_file.exists())
        after = store.verify_audit_chain()
        self.assertIs(after["verified"], False)
        self.assertEqual(after["first_broken_reason"], "scheme_downgrade")

    def test_insecure_key_permissions_not_used(self) -> None:
        store = self._store(2)
        os.chmod(self.key_file, 0o644)
        state = audit_integrity.load_key()
        self.assertEqual(state.status, "insecure")
        self.assertIsNone(state.key)
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], False)
        self.assertEqual(result["hmac"]["status"], "insecure")
        os.chmod(self.key_file, 0o600)
        os.chmod(self.key_dir, 0o777)
        try:
            self.assertEqual(audit_integrity.load_key().status, "insecure")
        finally:
            os.chmod(self.key_dir, 0o700)

    def test_symlinked_or_wrong_size_key_rejected(self) -> None:
        self._store(1)
        real = self.key_dir / "real.key"
        os.replace(self.key_file, real)
        os.symlink(real, self.key_file)
        self.assertEqual(audit_integrity.load_key().status, "insecure")
        os.unlink(self.key_file)
        fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, b"kisa")
        os.close(fd)
        self.assertEqual(audit_integrity.load_key().status, "invalid")

    def test_unwritable_key_dir_does_not_crash_logging(self) -> None:
        with mock.patch.dict(os.environ, {"SNIPER_AUDIT_KEY_FILE": "/proc/sniper-yok/audit.key",
                                          "SNIPER_AUDIT_ANCHOR_DIR": "/proc/sniper-yok/anchors"}):
            store = self._store(2)
            result = store.verify_audit_chain()
        self.assertIs(result["verified"], True)
        self.assertEqual(result["integrity"], "unkeyed")
        self.assertEqual(result["hmac"]["status"], "missing")

    # --- eski kayıt uyumu ---------------------------------------------------------------------

    def test_legacy_and_plain_chain_then_hmac_verifies(self) -> None:
        with mock.patch.dict(os.environ, {"SNIPER_AUDIT_HMAC": "0"}):
            store = Store(self.db_path)
            with _raw(self.db_path) as db:
                db.execute("INSERT INTO audit_log(occurred_at, action, entity_id, details_json) VALUES "
                           "('2026-01-01T00:00:00Z', 'legacy', 'l', '{}')")
            # Zincir öncesi kayıt: hash sütunları boş.
            store.log("plain.event", "p1", {})
            store.log("plain.event", "p2", {})
        self.assertFalse(self.key_file.exists())
        plain_rows = self._rows()
        self.assertFalse(plain_rows[-1]["entry_hash"].startswith("hmac1:"))
        store.log("hmac.event", "h1", {})
        store.log("hmac.event", "h2", {})
        self.assertTrue(self.key_file.exists())
        result = store.verify_audit_chain()
        self.assertIs(result["verified"], True, result)
        self.assertEqual(result["legacy_unchained"], 1)
        self.assertEqual(result["hmac"]["plain_entries"], 2)
        self.assertEqual(result["hmac"]["hmac_entries"], 2)
        self.assertEqual(result["integrity"], "hmac_anchored")

    def test_concurrent_appends_keep_chain_and_anchor_consistent(self) -> None:
        store = Store(self.db_path)
        errors: list[BaseException] = []

        def worker(prefix: str) -> None:
            try:
                for index in range(15):
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
        self.assertIs(result["verified"], True, result)
        self.assertEqual(result["chained_count"], 60)
        anchor = json.loads(self._anchor_file().read_text())
        self.assertEqual(anchor["last_id"], self._rows()[-1]["id"])
        self.assertEqual(anchor["chained_count"], 60)
        self.assertEqual(os.stat(self._anchor_file()).st_mode & 0o777, 0o600)


    def test_audit_key_cli_init_status_and_refusal_after_key_loss(self) -> None:
        import subprocess
        script = Path(__file__).resolve().parents[1] / "scripts" / "audit_key.py"

        def run(command: str) -> subprocess.CompletedProcess:
            return subprocess.run([sys.executable, str(script), command], capture_output=True, text=True,
                                  timeout=60, env=dict(os.environ))

        self.assertEqual(run("status").returncode, 1)
        init = run("init")
        self.assertEqual(init.returncode, 0, init.stderr)
        self.assertEqual(json.loads(init.stdout)["status"], "ok")
        self.assertNotIn(self.key_file.read_bytes().hex(), init.stdout)
        self._store(2)  # imzalı çapa oluşur
        self.key_file.unlink()
        refused = run("init")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("çapalar var", refused.stderr)
        self.assertFalse(self.key_file.exists())


    def test_temp_dir_databases_never_touch_user_config_without_explicit_env(self) -> None:
        with tempfile.TemporaryDirectory() as fake_home, mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": fake_home}):
            os.environ.pop("SNIPER_AUDIT_KEY_FILE", None)
            os.environ.pop("SNIPER_AUDIT_ANCHOR_DIR", None)
            store = self._store(2)  # self.db_path sistem geçici dizininde
            self.assertEqual(list(Path(fake_home).iterdir()), [])
            key = audit_integrity.key_path(self.db_path)
            self.assertTrue(str(key).startswith(tempfile.gettempdir()))
            self.assertIs(store.verify_audit_chain()["verified"], True)
            # Kalıcı (geçici dizin dışı) bir veritabanı yolu için varsayılan ~/.config/sniper'dır.
            self.assertEqual(audit_integrity.key_path(Path.home() / "x" / "sniper.db"),
                             Path(fake_home) / "sniper" / "audit.key")


if __name__ == "__main__":
    unittest.main()
