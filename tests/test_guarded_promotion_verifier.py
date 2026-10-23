from __future__ import annotations

import hashlib
import json
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path

from guarded_promotion_verifier import (
    RECEIPT_FORMAT,
    verify_guarded_promotion_state,
)


class GuardedPromotionVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.candidate_dir = self.root / "candidate"
        self.installed_dir = self.root / "installed"
        self.candidate_dir.mkdir()
        self.installed_dir.mkdir()

        for target in (self.candidate_dir, self.installed_dir):
            (target / "server.py").write_text("print('sniper-ready')\n", encoding="utf-8")
            static_dir = target / "static"
            static_dir.mkdir()
            (static_dir / "app.js").write_text("const ready = true;\n", encoding="utf-8")

        # Ignored runtime/cache directories should not cause divergence
        (self.candidate_dir / "__pycache__").mkdir()
        (self.candidate_dir / "__pycache__" / "server.cpython-312.pyc").write_bytes(b"pyc-a")
        (self.installed_dir / "data").mkdir()
        (self.installed_dir / "data" / "runtime.log").write_text("ignored\n", encoding="utf-8")

        self.db_path = self.root / "sniper.db"
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT NOT NULL);")
            conn.execute("INSERT INTO projects (name) VALUES ('local-workspace');")
            conn.commit()
        finally:
            conn.close()
        self.pre_db_sha256 = hashlib.sha256(self.db_path.read_bytes()).hexdigest()

        self.backup_archive = self.root / "sniper-backup.tar.gz"
        payload_file = self.root / "backup_payload.bin"
        incompressible = b"".join(
            hashlib.sha256(f"sniper-block-{idx}".encode("utf-8")).digest()
            for idx in range(128)
        )
        payload_file.write_bytes(incompressible)
        with tarfile.open(self.backup_archive, "w:gz") as tar:
            tar.add(payload_file, arcname="backup_payload.bin")
            tar.add(self.db_path, arcname="sniper.db")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_verify_guarded_promotion_state_passes_on_matching_trees_and_intact_db(self) -> None:
        receipt = verify_guarded_promotion_state(
            candidate_dir=self.candidate_dir,
            installed_dir=self.installed_dir,
            backup_archive=self.backup_archive,
            sqlite_db_path=self.db_path,
            pre_db_sha256=self.pre_db_sha256,
        )

        self.assertEqual(receipt["format"], RECEIPT_FORMAT)
        self.assertIs(receipt["true_live_db_write"], False)
        self.assertIs(receipt["candidate_installed_match"], True)
        self.assertEqual(receipt["sqlite_integrity_check"], "ok")
        self.assertEqual(receipt["sqlite_db_sha256"], self.pre_db_sha256)
        self.assertEqual(receipt["verified_file_count"], 2)
        self.assertGreater(int(receipt["backup_archive_size_bytes"]), 1024)
        self.assertEqual(
            receipt["backup_archive_sha256"],
            hashlib.sha256(self.backup_archive.read_bytes()).hexdigest(),
        )
        self.assertEqual(len(str(receipt["manifest_sha256"])), 64)
        self.assertEqual(len(str(receipt["receipt_sha256"])), 64)
        self.assertNotIn("/home/", json.dumps(receipt))

    def test_fails_closed_when_sqlite_db_hash_changes(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("INSERT INTO projects (name) VALUES ('unexpected-write');")
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(ValueError):
            verify_guarded_promotion_state(
                candidate_dir=self.candidate_dir,
                installed_dir=self.installed_dir,
                backup_archive=self.backup_archive,
                sqlite_db_path=self.db_path,
                pre_db_sha256=self.pre_db_sha256,
            )

    def test_fails_closed_when_installed_file_diverges(self) -> None:
        (self.installed_dir / "static" / "app.js").write_text(
            "const ready = false;\n", encoding="utf-8"
        )
        with self.assertRaises(ValueError):
            verify_guarded_promotion_state(
                candidate_dir=self.candidate_dir,
                installed_dir=self.installed_dir,
                backup_archive=self.backup_archive,
                sqlite_db_path=self.db_path,
                pre_db_sha256=self.pre_db_sha256,
            )

    def test_fails_closed_when_backup_archive_is_missing_symlink_or_too_small(self) -> None:
        missing_backup = self.root / "missing.tar.gz"
        with self.assertRaises(ValueError):
            verify_guarded_promotion_state(
                candidate_dir=self.candidate_dir,
                installed_dir=self.installed_dir,
                backup_archive=missing_backup,
                sqlite_db_path=self.db_path,
                pre_db_sha256=self.pre_db_sha256,
            )

        symlink_backup = self.root / "symlink.tar.gz"
        symlink_backup.symlink_to(self.backup_archive)
        with self.assertRaises(ValueError):
            verify_guarded_promotion_state(
                candidate_dir=self.candidate_dir,
                installed_dir=self.installed_dir,
                backup_archive=symlink_backup,
                sqlite_db_path=self.db_path,
                pre_db_sha256=self.pre_db_sha256,
            )

        tiny_backup = self.root / "tiny.tar.gz"
        tiny_backup.write_bytes(b"too-small")
        with self.assertRaises(ValueError):
            verify_guarded_promotion_state(
                candidate_dir=self.candidate_dir,
                installed_dir=self.installed_dir,
                backup_archive=tiny_backup,
                sqlite_db_path=self.db_path,
                pre_db_sha256=self.pre_db_sha256,
            )


if __name__ == "__main__":
    unittest.main()
