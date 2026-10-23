"""TOTP secrets are encrypted outside auth.db with rotation and recovery behavior."""
from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import time
import unittest
from unittest import mock


import auth


STRONG = "doğru-at-pil-zımba-42"


def _rotation_worker(data_dir: str, key_file: str, queue) -> None:
    try:
        result = auth.AuthManager(Path(data_dir), key_file=Path(key_file)).rotate_totp_field_key()
        queue.put(("ok", result["active_key_id"]))
    except Exception as exc:  # pragma: no cover - parent asserts this path stays unused
        queue.put(("error", f"{type(exc).__name__}:{exc}"))


class AuthFieldEncryptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.key_file = self.root / "config" / "auth-field-keys.json"
        self.manager = auth.AuthManager(self.data, key_file=self.key_file)
        self.user = self.manager.create_admin_and_enable("yonetici", STRONG)

    def _row(self):
        with sqlite3.connect(self.manager.path) as db:
            return db.execute(
                "SELECT totp_secret, totp_pending FROM auth_users WHERE id = ?", (self.user["id"],)
            ).fetchone()

    def _format_row(self):
        with sqlite3.connect(self.manager.path) as db:
            return db.execute(
                "SELECT totp_secret_format, totp_pending_format FROM auth_users WHERE id = ?", (self.user["id"],)
            ).fetchone()

    def _enroll(self) -> str:
        started = self.manager.totp_begin(self.user["id"])
        secret = started["secret"]
        self.manager.totp_confirm(self.user["id"], auth.totp_code(secret, int(time.time() // 30)))
        return secret

    def test_new_totp_seed_is_not_plaintext_in_database_and_runtime_still_works(self) -> None:
        started = self.manager.totp_begin(self.user["id"])
        secret = started["secret"]
        _stored_secret, pending = self._row()
        self.assertNotEqual(pending, secret)
        self.assertTrue(pending.startswith("enc1:"), pending)
        self.assertTrue(self.key_file.is_file())
        self.assertEqual(self.key_file.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(secret, self.manager.path.read_bytes().decode("latin1"))

        now_step = int(time.time() // 30)
        self.manager.totp_confirm(self.user["id"], auth.totp_code(secret, now_step))
        stored, pending = self._row()
        self.assertIsNone(pending)
        self.assertTrue(stored.startswith("enc1:"), stored)
        state, challenge = self.manager.authenticate("yonetici", STRONG, "local")
        self.assertEqual(state, "totp")
        completed = self.manager.complete_totp(
            challenge["challenge"], auth.totp_code(secret, now_step + 1), None, "local"
        )
        self.assertEqual(completed["id"], self.user["id"])

    def test_rotation_migrates_legacy_plaintext_and_retains_old_key_for_recovery(self) -> None:
        secret = self._enroll()
        before, _ = self._row()
        with sqlite3.connect(self.manager.path) as db:
            db.execute("UPDATE auth_users SET totp_secret = ? WHERE id = ?", (secret, self.user["id"]))
            db.execute("DELETE FROM auth_settings WHERE key IN (?, ?)",
                       ("totp_field_encryption_state", "totp_legacy_migration_deadline"))
        self.manager.open_totp_legacy_migration_window(300)
        old_keyring = json.loads(self.key_file.read_text(encoding="utf-8"))

        result = self.manager.rotate_totp_field_key()

        after, _ = self._row()
        new_keyring = json.loads(self.key_file.read_text(encoding="utf-8"))
        self.assertTrue(after.startswith("enc1:"), after)
        self.assertNotEqual(after, before)
        self.assertEqual(result["fields_reencrypted"], 1)
        self.assertNotEqual(old_keyring["active_key_id"], new_keyring["active_key_id"])
        self.assertIn(old_keyring["active_key_id"], new_keyring["keys"])
        self.assertIn(new_keyring["active_key_id"], new_keyring["keys"])

        state, challenge = self.manager.authenticate("yonetici", STRONG, "local")
        self.assertEqual(state, "totp")
        code = auth.totp_code(secret, int(time.time() // 30) + 1)
        self.assertEqual(self.manager.complete_totp(challenge["challenge"], code, None, "local")["id"], self.user["id"])

    def test_plaintext_downgrade_of_a_sealed_row_fails_closed(self) -> None:
        secret = self._enroll()
        self.assertEqual(self._format_row()[0], "enc1")
        with sqlite3.connect(self.manager.path) as db:
            db.execute("UPDATE auth_users SET totp_secret = ? WHERE id = ?", (secret, self.user["id"]))

        state, challenge = self.manager.authenticate("yonetici", STRONG, "downgrade")
        self.assertEqual(state, "totp")
        with self.assertRaisesRegex(auth.AuthError, "şifreli alan"):
            self.manager.complete_totp(
                challenge["challenge"], auth.totp_code(secret, int(time.time() // 30) + 1), None, "downgrade"
            )

    def test_legacy_plaintext_requires_an_explicit_bounded_migration_window(self) -> None:
        secret = self._enroll()
        with sqlite3.connect(self.manager.path) as db:
            db.execute("UPDATE auth_users SET totp_secret = ? WHERE id = ?", (secret, self.user["id"]))
            db.execute("DELETE FROM auth_settings WHERE key IN (?, ?)",
                       ("totp_field_encryption_state", "totp_legacy_migration_deadline"))

        state, challenge = self.manager.authenticate("yonetici", STRONG, "legacy")
        self.assertEqual(state, "totp")
        code = auth.totp_code(secret, int(time.time() // 30) + 1)
        with self.assertRaisesRegex(auth.AuthError, "geçiş"):
            self.manager.complete_totp(challenge["challenge"], code, None, "legacy")

        opened = self.manager.open_totp_legacy_migration_window(300)
        self.assertEqual(opened["state"], "legacy-window")
        self.assertEqual(opened["legacy_fields"], 1)
        self.assertEqual(self.manager.complete_totp(challenge["challenge"], code, None, "legacy")["id"], self.user["id"])
        status = self.manager.totp_legacy_migration_status()
        self.assertEqual(status["state"], "sealed-v1")
        self.assertEqual(status["legacy_fields"], 0)

    def test_concurrent_cross_process_rotations_serialize_and_use_the_explicit_new_key(self) -> None:
        self._enroll()
        context = multiprocessing.get_context("spawn")
        queue = context.Queue()
        processes = [
            context.Process(target=_rotation_worker, args=(str(self.data), str(self.key_file), queue))
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        results = [queue.get(timeout=2) for _ in processes]
        self.assertTrue(all(status == "ok" for status, _value in results), results)

        keyring = json.loads(self.key_file.read_text(encoding="utf-8"))
        stored, _pending = self._row()
        self.assertEqual(stored.split(":", 2)[1], keyring["active_key_id"])
        self.assertGreaterEqual(len(keyring["keys"]), 3)

    def test_rotation_fault_keeps_old_ciphertext_recoverable(self) -> None:
        secret = self._enroll()
        before, _pending = self._row()
        with mock.patch.object(
            self.manager.field_keys, "seal_with_key",
            side_effect=auth.auth_field_keys.FieldEncryptionError("fault-injected"),
        ):
            with self.assertRaisesRegex(auth.AuthError, "fault-injected"):
                self.manager.rotate_totp_field_key()
        after, _pending = self._row()
        self.assertEqual(after, before)

        state, challenge = self.manager.authenticate("yonetici", STRONG, "fault")
        self.assertEqual(state, "totp")
        code = auth.totp_code(secret, int(time.time() // 30) + 1)
        self.assertEqual(self.manager.complete_totp(challenge["challenge"], code, None, "fault")["id"], self.user["id"])

    def test_keyring_replace_is_durable_to_the_parent_directory(self) -> None:
        self._enroll()
        fsync_kinds: list[str] = []
        real_fsync = os.fsync

        def record(fd: int) -> None:
            fsync_kinds.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            real_fsync(fd)

        with mock.patch.object(auth.auth_field_keys.os, "fsync", side_effect=record):
            self.manager.rotate_totp_field_key()

        self.assertIn("file", fsync_kinds)
        self.assertIn("directory", fsync_kinds)

    def test_keyring_inside_application_source_is_rejected(self) -> None:
        with self.assertRaisesRegex(auth.AuthError, "uygulama"):
            auth.AuthManager(self.data, key_file=Path(auth.__file__).resolve().parent / "keyring.json")

    def test_existing_keyring_parent_must_be_owner_only_not_0755(self) -> None:
        unsafe_parent = self.root / "world-readable-keyring-parent"
        unsafe_parent.mkdir(mode=0o755)
        unsafe_parent.chmod(0o755)

        with self.assertRaisesRegex(auth.AuthError, "dizini güvenli değil"):
            manager = auth.AuthManager(self.data, key_file=unsafe_parent / "keyring.json")
            user = manager.create_admin_and_enable("unsafe-parent-admin", STRONG)
            manager.totp_begin(user["id"])

    def test_default_source_tree_keyring_is_routed_outside_the_application_boundary(self) -> None:
        application_root = Path(auth.__file__).resolve().parent
        with mock.patch.dict(os.environ, {}, clear=True):
            key_path = auth.auth_field_keys.default_key_path(application_root / "data" / "auth.db")

        self.assertFalse(auth.auth_field_keys._is_within(key_path, application_root))
        self.assertEqual(key_path.parent.name, ".sniper-secrets")

    def test_missing_key_fails_closed_and_restoring_keyring_recovers(self) -> None:
        secret = self._enroll()
        backup = self.root / "auth-field-keys.recovery.json"
        shutil.copyfile(self.key_file, backup)
        self.key_file.unlink()
        state, challenge = self.manager.authenticate("yonetici", STRONG, "local")
        self.assertEqual(state, "totp")
        code = auth.totp_code(secret, int(time.time() // 30) + 1)
        with self.assertRaisesRegex(auth.AuthError, "şifreleme anahtarı"):
            self.manager.complete_totp(challenge["challenge"], code, None, "local")

        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(backup, self.key_file)
        os.chmod(self.key_file, 0o600)
        self.assertEqual(self.manager.complete_totp(challenge["challenge"], code, None, "local")["id"], self.user["id"])


if __name__ == "__main__":
    unittest.main()
