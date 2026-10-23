"""Versioned AES-GCM keyring for reversible authentication fields.

The keyring is deliberately outside SQLite.  Every ciphertext is bound to its
user id and column name through AEAD associated data.  Rotation writes the new
key before database rows are re-encrypted and retains old keys, so a database
rollback remains recoverable with the same keyring backup.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYRING_FORMAT = "sniper-auth-field-keys/1"
CIPHERTEXT_PREFIX = "enc1"
MAX_KEYRING_BYTES = 64 * 1024
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
CRYPTOGRAPHY_RUNTIME_VERSION = "41.0.7"
APPLICATION_ROOT = Path(__file__).resolve().parent

if cryptography.__version__ != CRYPTOGRAPHY_RUNTIME_VERSION:
    raise RuntimeError(
        f"Sniper cryptography runtime must be {CRYPTOGRAPHY_RUNTIME_VERSION}; found {cryptography.__version__}."
    )


class FieldEncryptionError(ValueError):
    """Keyring or ciphertext is unavailable, unsafe or invalid."""


def _crypto():
    return AESGCM, InvalidTag


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def default_key_path(db_path: Path) -> Path:
    configured = os.environ.get("SNIPER_AUTH_FIELD_KEY_FILE", "").strip()
    if configured:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            raise FieldEncryptionError("TOTP şifreleme anahtarı yolu mutlak olmalıdır.")
        return path
    db_path = Path(db_path)
    # Keep the key outside SQLite under a dedicated 0700 sidecar directory. A
    # source-tree development database is special: its key must still remain
    # outside the application/package boundary instead of being distributable.
    candidate = db_path.parent / ".auth-field-keys" / "keyring.json"
    if _is_within(candidate, APPLICATION_ROOT):
        candidate = APPLICATION_ROOT.parent / ".sniper-secrets" / "auth-field-keys.json"
    return candidate


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 4096 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise FieldEncryptionError("TOTP şifreli alanı geçersiz.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise FieldEncryptionError("TOTP şifreli alanı geçersiz.") from exc


def _new_key() -> tuple[str, bytes]:
    key = os.urandom(32)
    return hashlib.sha256(key).hexdigest()[:16], key


def _private_parent(path: Path) -> None:
    missing: list[Path] = []
    current = path.parent
    while not current.exists() and current != current.parent:
        missing.append(current)
        current = current.parent
    try:
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        info = os.lstat(path.parent)
    except OSError as exc:
        raise FieldEncryptionError("TOTP şifreleme anahtarı dizini hazırlanamadı.") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise FieldEncryptionError("TOTP şifreleme anahtarı dizini güvenli değil.")


class FieldKeyStore:
    def __init__(self, path: Path, *, reject_application_path: bool = True) -> None:
        self.path = Path(path).expanduser()
        if not self.path.is_absolute():
            raise FieldEncryptionError("TOTP şifreleme anahtarı yolu mutlak olmalıdır.")
        if reject_application_path and _is_within(self.path, APPLICATION_ROOT):
            raise FieldEncryptionError("TOTP şifreleme anahtarı uygulama/kaynak ağacının dışında olmalıdır.")

    @contextlib.contextmanager
    def _locked(self):
        lock_path = self.path.with_name(self.path.name + ".lock")
        _private_parent(lock_path)
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            raise FieldEncryptionError("TOTP şifreleme anahtarı kilidi açılamadı.") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise FieldEncryptionError("TOTP şifreleme anahtarı kilidi güvenli değil (0600 gerekli).")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _read(self, *, missing_ok: bool = False) -> dict[str, Any] | None:
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise FieldEncryptionError("TOTP şifreleme anahtarı bulunamadı; anahtar yedeğini geri yükleyin.") from None
        except OSError as exc:
            raise FieldEncryptionError("TOTP şifreleme anahtarı okunamadı.") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise FieldEncryptionError("TOTP şifreleme anahtarı dosya izinleri güvenli değil (0600 gerekli).")
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as handle:
                opened = os.fstat(handle.fileno())
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(opened.st_mode):
                    raise FieldEncryptionError("TOTP şifreleme anahtarı dosyası okuma sırasında değişti.")
                raw = handle.read(MAX_KEYRING_BYTES + 1)
        except OSError as exc:
            raise FieldEncryptionError("TOTP şifreleme anahtarı okunamadı.") from exc
        if len(raw) > MAX_KEYRING_BYTES:
            raise FieldEncryptionError("TOTP şifreleme anahtarı dosyası çok büyük.")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise FieldEncryptionError("TOTP şifreleme anahtarı dosyası bozuk.") from exc
        if not isinstance(value, dict) or set(value) != {"format", "active_key_id", "keys"} \
                or value.get("format") != KEYRING_FORMAT or not isinstance(value.get("keys"), dict):
            raise FieldEncryptionError("TOTP şifreleme anahtarı dosyası biçimi geçersiz.")
        active = value.get("active_key_id")
        if not isinstance(active, str) or not _KEY_ID_RE.fullmatch(active) or active not in value["keys"]:
            raise FieldEncryptionError("TOTP şifreleme anahtarı etkin kimliği geçersiz.")
        decoded: dict[str, bytes] = {}
        for key_id, encoded in value["keys"].items():
            if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
                raise FieldEncryptionError("TOTP şifreleme anahtarı kimliği geçersiz.")
            key = _b64d(encoded)
            if len(key) != 32 or hashlib.sha256(key).hexdigest()[:16] != key_id:
                raise FieldEncryptionError("TOTP şifreleme anahtarı materyali geçersiz.")
            decoded[key_id] = key
        return {"format": KEYRING_FORMAT, "active_key_id": active, "keys": decoded}

    def _write(self, state: dict[str, Any]) -> None:
        _private_parent(self.path)
        serializable = {
            "format": KEYRING_FORMAT,
            "active_key_id": state["active_key_id"],
            "keys": {name: _b64e(key) for name, key in sorted(state["keys"].items())},
        }
        raw = (json.dumps(serializable, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")
        temp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            info = os.lstat(self.path)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise FieldEncryptionError("TOTP şifreleme anahtarı dosyası güvenli yazılamadı.")
            directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise FieldEncryptionError("TOTP şifreleme anahtarı yazılamadı.") from exc

    def ensure_active(self) -> tuple[str, bytes]:
        with self._locked():
            state = self._read(missing_ok=True)
            if state is None:
                key_id, key = _new_key()
                state = {"format": KEYRING_FORMAT, "active_key_id": key_id, "keys": {key_id: key}}
                self._write(state)
            return state["active_key_id"], state["keys"][state["active_key_id"]]

    def rotate(self) -> tuple[str | None, str]:
        with self.rotation() as rotation:
            return rotation["old_key_id"], rotation["new_key_id"]

    @contextlib.contextmanager
    def rotation(self):
        """Hold the cross-process key lock through the caller's database transaction."""
        with self._locked():
            state = self._read(missing_ok=True)
            old = state["active_key_id"] if state else None
            if state is None:
                state = {"format": KEYRING_FORMAT, "active_key_id": "", "keys": {}}
            key_id, key = _new_key()
            while key_id in state["keys"]:
                key_id, key = _new_key()
            state["keys"][key_id] = key
            state["active_key_id"] = key_id
            self._write(state)
            yield {"old_key_id": old, "new_key_id": key_id, "new_key": key}

    @staticmethod
    def _aad(user_id: str, field: str) -> bytes:
        return f"sniper-auth-field/1\0{user_id}\0{field}".encode("utf-8")

    def seal(self, value: str, *, user_id: str, field: str) -> str:
        if not isinstance(value, str) or not value:
            raise FieldEncryptionError("TOTP şifrelenecek alan boş olamaz.")
        key_id, key = self.ensure_active()
        nonce = os.urandom(12)
        AESGCM, _invalid_tag = _crypto()
        ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), self._aad(user_id, field))
        return f"{CIPHERTEXT_PREFIX}:{key_id}:{_b64e(nonce)}:{_b64e(ciphertext)}"

    def seal_with_key(self, value: str, *, user_id: str, field: str, key_id: str, key: bytes) -> str:
        """Seal under the explicit rotation key; never re-read a racing active key."""
        if not isinstance(value, str) or not value or not _KEY_ID_RE.fullmatch(key_id) or len(key) != 32 \
                or hashlib.sha256(key).hexdigest()[:16] != key_id:
            raise FieldEncryptionError("TOTP şifreleme rotasyon anahtarı geçersiz.")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), self._aad(user_id, field))
        return f"{CIPHERTEXT_PREFIX}:{key_id}:{_b64e(nonce)}:{_b64e(ciphertext)}"

    def open(self, value: str, *, user_id: str, field: str, allow_legacy: bool = False) -> tuple[str, bool]:
        if allow_legacy and isinstance(value, str) and not value.startswith(CIPHERTEXT_PREFIX + ":"):
            return value, True
        parts = value.split(":") if isinstance(value, str) else []
        if len(parts) != 4 or parts[0] != CIPHERTEXT_PREFIX or not _KEY_ID_RE.fullmatch(parts[1]):
            raise FieldEncryptionError("TOTP şifreli alanı geçersiz.")
        state = self._read()
        key = state["keys"].get(parts[1])
        if key is None:
            raise FieldEncryptionError("TOTP şifreleme anahtarı bulunamadı; eşleşen anahtar yedeğini geri yükleyin.")
        nonce, ciphertext = _b64d(parts[2]), _b64d(parts[3])
        if len(nonce) != 12:
            raise FieldEncryptionError("TOTP şifreli alanı geçersiz.")
        AESGCM, InvalidTag = _crypto()
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, self._aad(user_id, field)).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise FieldEncryptionError("TOTP şifreli alanı doğrulanamadı; veri veya anahtar eşleşmiyor.") from exc
        return plaintext, False

    def status(self) -> dict[str, Any]:
        state = self._read(missing_ok=True)
        return {
            "format": KEYRING_FORMAT,
            "path": str(self.path),
            "exists": state is not None,
            "active_key_id": state["active_key_id"] if state else None,
            "key_count": len(state["keys"]) if state else 0,
        }
