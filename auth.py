"""İsteğe bağlı arayüz girişi, oturumlar, roller ve iki adımlı doğrulama (TOTP).

Varsayılan: kapalı. Kapalıyken hiçbir dosya oluşturulmaz, Sniper eskisi gibi yalnız yerel (127.0.0.1 / SSH tüneli)
çalışır. Etkinleştirme tek seferlik kurulumla olur: CLI (``cli_reports.py users create-admin``) ya da yerel arayüz
+ veri dizinine 0600 yazılan kurulum belirteci dosyası. Durum ``$SNIPER_DATA_DIR/auth.db`` (0600) içinde tutulur;
ana ``sniper.db`` şemasına dokunulmaz. Kurtarma yolu her zaman yerel işletim sistemi kullanıcısındadır
(``users disable-auth`` / ``users reset-password``).

Güvenlik kararları:
* Parola: ``hashlib.scrypt`` (n=2^15, r=8, p=1) + 16 bayt tuz, sabit zamanlı karşılaştırma; parola hiçbir
  yanıta ya da günlüğe yazılmaz. Olmayan kullanıcıda da aynı maliyet harcanır (kullanıcı adı sızdırmaz).
* Kilitleme: art arda 5 başarısız girişte 15 dk (her 5'te ikiye katlanır, en çok 24 sa) + IP başına bellek içi sınır.
* Oturum: ``secrets.token_urlsafe(32)``; veritabanında yalnız SHA-256 özeti. Boşta ve mutlak zaman aşımı; parola
  değişince/kullanıcı kapatılınca eski oturumlar geçersiz.
* CSRF: oturuma bağlı eşleştirme belirteci (``X-Sniper-CSRF`` başlığı = ``sniper_csrf`` çerezi, sunucuda özeti).
* TOTP: RFC 6238 (SHA-1, 30 sn, 6 hane, ±1 adım), aynı adımın tekrar kullanımı reddedilir; kurtarma kodları özetli.
* Roller: ``reader`` (okuyucu, yalnız GET), ``analyst`` (analist), ``admin`` (yönetici). Rota → düzey eşlemesi
  :func:`required_level`; eşlenmemiş durum değiştiren istek yöneticiye düşer (güvenli varsayılan).
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import threading
import time
from typing import Any, Iterator
from urllib.parse import quote

import auth_field_keys

AUTH_DB_NAME = "auth.db"
SETUP_TOKEN_NAME = "auth-setup-token"
SESSION_COOKIE = "sniper_session"
CSRF_COOKIE = "sniper_csrf"
CSRF_HEADER = "X-Sniper-CSRF"

ROLES = ("reader", "analyst", "admin")
ROLE_LABELS = {"reader": "okuyucu", "analyst": "analist", "admin": "yönetici"}
ROLE_LEVEL = {"reader": 0, "analyst": 1, "admin": 2}
# Düzeyler: public (oturumsuz), self (her oturumlu kullanıcı, okuyucu dahil), read, analyst, admin.
LEVEL_RANK = {"public": -1, "self": 0, "read": 0, "analyst": 1, "admin": 2}

PASSWORD_MIN = 12
PASSWORD_MAX = 256
USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}\Z")
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
LOCK_THRESHOLD = 5
LOCK_BASE_SECONDS = 15 * 60
LOCK_MAX_SECONDS = 24 * 3600
IP_WINDOW_SECONDS = 600
IP_MAX_FAILURES = 20
CHALLENGE_SECONDS = 300
CHALLENGE_MAX_ATTEMPTS = 5
SETUP_TOKEN_SECONDS = 30 * 60
TOTP_STEP = 30
TOTP_DIGITS = 6
RECOVERY_CODE_COUNT = 10
TOTP_ENCRYPTION_STATE_KEY = "totp_field_encryption_state"
TOTP_MIGRATION_DEADLINE_KEY = "totp_legacy_migration_deadline"
TOTP_STATE_SEALED = "sealed-v1"
TOTP_STATE_REQUIRED = "migration-required"
TOTP_STATE_WINDOW = "legacy-window"


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(os.environ.get(name, default))))
    except ValueError:
        return default


def session_idle_seconds() -> int:
    return 60 * _env_int("SNIPER_SESSION_IDLE_MINUTES", 30, 5, 24 * 60)


def session_max_seconds() -> int:
    return 3600 * _env_int("SNIPER_SESSION_MAX_HOURS", 12, 1, 7 * 24)


class AuthError(ValueError):
    """Kullanıcıya gösterilebilir (sır içermeyen) kimlik doğrulama hatası."""

    status = 400


class AuthDenied(AuthError):
    status = 401


class AuthLocked(AuthError):
    status = 429


def _now() -> float:
    return time.time()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Parola
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=SCRYPT_MAXMEM, dklen=32)
    return "scrypt${}${}${}${}${}".format(SCRYPT_N, SCRYPT_R, SCRYPT_P, base64.b64encode(salt).decode(),
                                          base64.b64encode(digest).decode())


_DUMMY_HASH: str | None = None


def verify_password(password: str, encoded: str | None) -> bool:
    """Sabit zamanlı doğrulama; ``encoded`` yoksa da aynı maliyetle sahte özet hesaplanır."""
    global _DUMMY_HASH
    if encoded is None:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password(secrets.token_hex(16))
        encoded, real = _DUMMY_HASH, False
    else:
        real = True
    try:
        scheme, n, r, p, salt_b64, digest_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt_b64), n=int(n), r=int(r),
                                p=int(p), maxmem=SCRYPT_MAXMEM, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected) and real


def validate_password(password: Any, username: str = "") -> str:
    if not isinstance(password, str) or not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise AuthError(f"Parola {PASSWORD_MIN}–{PASSWORD_MAX} karakter olmalıdır.")
    if username and password.casefold() == username.casefold():
        raise AuthError("Parola kullanıcı adıyla aynı olamaz.")
    if len(set(password)) < 5:
        raise AuthError("Parola çok tekrarlı; daha çeşitli karakterler kullanın.")
    return password


def validate_username(username: Any) -> str:
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise AuthError("Kullanıcı adı 3–64 karakter; harf, rakam, nokta, alt çizgi ve tire olabilir.")
    return username


def validate_role(role: Any) -> str:
    if role not in ROLES:
        raise AuthError("Rol reader, analyst veya admin olmalıdır.")
    return role


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) ve kurtarma kodları
# ---------------------------------------------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32decode(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def totp_code(secret: str, step: int) -> str:
    digest = hmac.new(_b32decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def totp_match(secret: str, code: Any, *, now: float | None = None, last_step: int | None = None) -> int | None:
    """Eşleşen adım (±1); yeniden kullanılan ya da eşleşmeyen kodda ``None``."""
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code.strip()):
        return None
    code = code.strip()
    current = int((now if now is not None else _now()) // TOTP_STEP)
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp_code(secret, step), code):
            if last_step is not None and step <= last_step:
                return None
            return step
    return None


def otpauth_uri(secret: str, username: str, issuer: str = "Sniper") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def new_recovery_codes() -> list[str]:
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        return raw[:5] + "-" + raw[5:]
    return [one() for _ in range(RECOVERY_CODE_COUNT)]


def _normalize_recovery(code: str) -> str:
    return re.sub(r"[^a-z0-9]", "", code.casefold())


# ---------------------------------------------------------------------------
# Rota → gerekli düzey
# ---------------------------------------------------------------------------
_PUBLIC_POST = frozenset({"/api/auth/login", "/api/auth/login/totp", "/api/auth/setup/begin", "/api/auth/setup/complete"})
_SELF_POST = frozenset({"/api/auth/logout", "/api/auth/password", "/api/auth/totp/begin", "/api/auth/totp/confirm",
                        "/api/auth/totp/disable", "/api/auth/sessions/revoke-all"})
_PUBLIC_GET = frozenset({"/api/auth/status", "/api/health"})
# 17. tur (W3-OPS): yedek listesi ve saklama planı yönetici (dosya adları, yollar, silme önizlemesi).
# POST /api/system/backups, /api/system/retention/policy ve /run hiçbir analist listesinde olmadığı için yönetici.
_ADMIN_GET_PREFIXES = (
    "/api/auth/users", "/api/system/backups", "/api/system/retention",
    # Onay kuyruğu istek sahiplerini ve kayıtlı yetkili hedef kataloğunu içerir; yalnız yönetici UI'si görür.
    "/api/mcp-scan-requests",
)
# Okuyucunun göremeyeceği GET'ler (16. tur): öz sağlık raporu yapılandırma/güvenlik ayrıntısı içerir.
_ANALYST_GET = frozenset({"/api/system/health-report",
                          # 17. tur: bulgu dışa aktarımı (DefectDojo/Jira/CSV) analist; pano ve SLA politikasını okuyucu görür,
                          # SLA politikasını (POST /api/portfolio/sla-policy[/apply]) yalnız yönetici değiştirir.
                          "/api/portfolio/export"})
# Analist: proje analizi, temel taramalar, manuel test kayıtları, statik denetçiler, rapor ayrıştırma, triyaj.
_ANALYST_POST_EXACT = frozenset({
    "/api/project-audits", "/api/project-audits/diff", "/api/scans", "/api/targets", "/api/engagements",
    "/api/lab-runs", "/api/cvss-ssvc/prioritize", "/api/quality-gate/evaluate", "/api/reports/executive-pentest",
    "/api/threat-model/generate", "/api/attack-paths/correlate", "/api/blue-team/synthesize-rules",
    # 13. tur birleştirmesi: bildirimleri okundu işaretleme. Zamanlanmış taramalar (/api/schedules) yönetici:
    # plan, elle yalnız yöneticinin çalıştırabildiği araçları (gitleaks, TruffleHog) da zamanlayabilir.
    "/api/notifications",
    # 18. tur: konteyner imajı / rootfs paket taraması (SBOM GET'i okuyucuya açık).
    "/api/container-images",
    # 25. tur: toplu depo taraması (keşif önizlemesi dosya sistemini gezer; GET listesi okuyucuya açık).
    "/api/bulk-scans",
})
_ANALYST_POST_PREFIXES = (
    "/api/project-audits/", "/api/targets/", "/api/scans/", "/api/engagements/", "/api/dependency-security/",
    "/api/tool-reports/", "/api/mobile-security/",
    # Bulgu takibi: /<id>/status, /<id>/assign, /<id>/due, /<id>/comments ve /<id>/comments/<n>/delete analist
    # düzeyindedir; başkasının yorumunu silme rota içinde ayrıca yöneticiyle sınırlanır (backfill: yönetici).
    "/api/finding-tracking/",
    "/api/bulk-scans/",  # 25. tur: /discover ve /<id>/cancel (iptal ayrıca sahibine/yöneticiye)
)
_ANALYST_AUDIT_SUFFIX = "/audit"  # /api/<denetçi>/audit: yerel statik denetçiler
# Analist önekleri içinde bile yönetici isteyenler. Not: /api/license-policy POST hiçbir analist listesinde
# olmadığı için yönetici düzeyindedir (GET okuyucuya açık).
_ADMIN_POST_OVERRIDES = frozenset({"/api/finding-tracking/backfill"})


def required_level(method: str, path: str) -> str:
    method = method.upper()
    if method in {"GET", "HEAD"}:
        if path in _PUBLIC_GET:
            return "public"
        if path == "/api/auth/me":
            return "self"
        if any(path == p or path.startswith(p + "/") for p in _ADMIN_GET_PREFIXES):
            return "admin"
        if path in _ANALYST_GET:
            return "analyst"
        return "read"
    if method == "OPTIONS":
        return "public"
    if path in _PUBLIC_POST:
        return "public"
    if path in _SELF_POST:
        return "self"
    if path in _ADMIN_POST_OVERRIDES:
        return "admin"
    if path in _ANALYST_POST_EXACT or path.startswith(_ANALYST_POST_PREFIXES):
        return "analyst"
    parts = [part for part in path.split("/") if part]
    if len(parts) == 3 and parts[0] == "api" and path.endswith(_ANALYST_AUDIT_SUFFIX):
        return "analyst"
    if path == "/api/jobs" or path.startswith("/api/jobs/"):
        return "analyst"  # iç rota ayrıca denetlenir; iptal sahibine/yöneticiye
    return "admin"


def role_allows(role: str | None, level: str) -> bool:
    if level == "public":
        return True
    if role not in ROLE_LEVEL:
        return False
    return ROLE_LEVEL[role] >= LEVEL_RANK[level]


# ---------------------------------------------------------------------------
# Depo
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    password_changed_at REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    totp_secret TEXT,
    totp_pending TEXT,
    totp_secret_format TEXT NOT NULL DEFAULT 'enc1',
    totp_pending_format TEXT NOT NULL DEFAULT 'enc1',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER,
    last_login_at REAL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    csrf_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    client TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(user_id);
CREATE TABLE IF NOT EXISTS auth_recovery_codes (
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at REAL,
    PRIMARY KEY (user_id, code_hash)
);
CREATE TABLE IF NOT EXISTS auth_challenges (
    challenge_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
"""


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class AuthManager:
    def __init__(self, data_dir: Path, *, key_file: Path | None = None) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / AUTH_DB_NAME
        try:
            self.field_keys = auth_field_keys.FieldKeyStore(
                Path(key_file) if key_file is not None else auth_field_keys.default_key_path(self.path),
                reject_application_path=True,
            )
        except auth_field_keys.FieldEncryptionError as exc:
            raise AuthError(str(exc)) from exc
        self._ip_failures: dict[str, list[float]] = {}
        self._ip_lock = threading.Lock()

    def _seal_totp(self, user_id: str, field: str, value: str) -> str:
        try:
            return self.field_keys.seal(value, user_id=user_id, field=field)
        except auth_field_keys.FieldEncryptionError as exc:
            raise AuthError(str(exc)) from exc

    @staticmethod
    def _setting(db: sqlite3.Connection, key: str) -> str | None:
        row = db.execute("SELECT value FROM auth_settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    @staticmethod
    def _put_setting(db: sqlite3.Connection, key: str, value: str) -> None:
        db.execute(
            "INSERT INTO auth_settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value),
        )

    def _ensure_totp_encryption_schema(self, db: sqlite3.Connection) -> None:
        columns = {row[1] for row in db.execute("PRAGMA table_info(auth_users)")}
        if "totp_secret_format" not in columns:
            db.execute("ALTER TABLE auth_users ADD COLUMN totp_secret_format TEXT NOT NULL DEFAULT 'enc1'")
        if "totp_pending_format" not in columns:
            db.execute("ALTER TABLE auth_users ADD COLUMN totp_pending_format TEXT NOT NULL DEFAULT 'enc1'")
        state = self._setting(db, TOTP_ENCRYPTION_STATE_KEY)
        if state is None:
            legacy = db.execute(
                "SELECT COUNT(*) FROM auth_users WHERE "
                "(totp_secret IS NOT NULL AND totp_secret NOT LIKE 'enc1:%') OR "
                "(totp_pending IS NOT NULL AND totp_pending NOT LIKE 'enc1:%')"
            ).fetchone()[0]
            self._put_setting(db, TOTP_ENCRYPTION_STATE_KEY, TOTP_STATE_REQUIRED if legacy else TOTP_STATE_SEALED)
            self._put_setting(db, TOTP_MIGRATION_DEADLINE_KEY, "0")

    def _open_totp_value(self, db: sqlite3.Connection, user_id: str, field: str,
                         value: str, marker: str) -> tuple[str, bool]:
        state = self._setting(db, TOTP_ENCRYPTION_STATE_KEY) or TOTP_STATE_REQUIRED
        if marker == "legacy":
            deadline_raw = self._setting(db, TOTP_MIGRATION_DEADLINE_KEY) or "0"
            try:
                deadline = float(deadline_raw)
            except ValueError:
                deadline = 0
            if state != TOTP_STATE_WINDOW or deadline <= _now():
                raise AuthError("TOTP düz metin geçiş penceresi kapalı veya süresi doldu.")
            allow_legacy = True
        elif marker == "enc1":
            if not value.startswith(auth_field_keys.CIPHERTEXT_PREFIX + ":") and state == TOTP_STATE_REQUIRED:
                raise AuthError("TOTP düz metin geçişi yönetici tarafından açıkça başlatılmalıdır.")
            allow_legacy = False
        else:
            raise AuthError("TOTP şifreli alan biçim işareti geçersiz.")
        try:
            return self.field_keys.open(
                value, user_id=user_id, field=field, allow_legacy=allow_legacy,
            )
        except auth_field_keys.FieldEncryptionError as exc:
            raise AuthError(str(exc)) from exc

    def _maybe_finalize_totp_migration(self, db: sqlite3.Connection) -> None:
        legacy = db.execute(
            "SELECT COUNT(*) FROM auth_users WHERE "
            "(totp_secret IS NOT NULL AND totp_secret_format = 'legacy') OR "
            "(totp_pending IS NOT NULL AND totp_pending_format = 'legacy')"
        ).fetchone()[0]
        if legacy == 0 and self._setting(db, TOTP_ENCRYPTION_STATE_KEY) == TOTP_STATE_WINDOW:
            self._put_setting(db, TOTP_ENCRYPTION_STATE_KEY, TOTP_STATE_SEALED)
            self._put_setting(db, TOTP_MIGRATION_DEADLINE_KEY, "0")

    # -- bağlantı ---------------------------------------------------------
    @contextlib.contextmanager
    def _connect(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        if not create and not self.path.is_file():
            raise AuthError("Giriş etkin değil.")
        if create:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            if self.path.is_symlink():
                raise AuthError("auth.db sembolik bağ olamaz.")
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                if create:
                    connection.executescript(_SCHEMA)
                self._ensure_totp_encryption_schema(connection)
                connection.commit()
                yield connection
        finally:
            connection.close()
            if create:
                _restrict(self.path)

    def enabled(self) -> bool:
        """Kapalıyken yalnız ``stat``: dosya oluşturmaz, ana veritabanını açmaz."""
        if not self.path.is_file():
            return False
        try:
            connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5)
            try:
                row = connection.execute("SELECT value FROM auth_settings WHERE key = 'enabled'").fetchone()
            finally:
                connection.close()
        except sqlite3.Error:
            # Okunamayan durum: güvenli tarafta kal (giriş etkin say) — dosya varsa birisi etkinleştirmiştir.
            return True
        return bool(row and row[0] == "1")

    def _set_enabled(self, db: sqlite3.Connection, value: bool) -> None:
        db.execute("INSERT INTO auth_settings(key, value) VALUES ('enabled', ?) "
                   "ON CONFLICT(key) DO UPDATE SET value = excluded.value", ("1" if value else "0",))

    # -- kullanıcılar -----------------------------------------------------
    @staticmethod
    def _public_user(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "username": row["username"], "role": row["role"],
            "role_label": ROLE_LABELS.get(row["role"], row["role"]), "disabled": bool(row["disabled"]),
            "totp_enabled": bool(row["totp_enabled"]), "created_at": row["created_at"],
            "last_login_at": row["last_login_at"], "locked": row["locked_until"] > _now(),
        }

    def _insert_user(self, db: sqlite3.Connection, username: str, password: str, role: str) -> dict[str, Any]:
        username = validate_username(username)
        validate_role(role)
        validate_password(password, username)
        if db.execute("SELECT 1 FROM auth_users WHERE username = ?", (username,)).fetchone():
            raise AuthError("Bu kullanıcı adı zaten var.")
        now = _now()
        user_id = "usr_" + secrets.token_hex(8)
        db.execute("INSERT INTO auth_users(id, username, role, password_hash, created_at, password_changed_at) "
                   "VALUES (?, ?, ?, ?, ?, ?)", (user_id, username, role, hash_password(password), now, now))
        return self._public_user(db.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,)).fetchone())

    def create_admin_and_enable(self, username: str, password: str) -> dict[str, Any]:
        """İlk yönetici (ya da kurtarma için ek yönetici) + girişi etkinleştir."""
        with self._connect(create=True) as db:
            user = self._insert_user(db, username, password, "admin")
            self._set_enabled(db, True)
        return user

    def create_user(self, username: str, password: str, role: str) -> dict[str, Any]:
        with self._connect() as db:
            return self._insert_user(db, username, password, role)

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [self._public_user(row) for row in db.execute("SELECT * FROM auth_users ORDER BY username")]

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,)).fetchone()
            return self._public_user(row) if row else None

    def _active_admins(self, db: sqlite3.Connection, excluding: str | None = None) -> int:
        return db.execute("SELECT COUNT(*) FROM auth_users WHERE role = 'admin' AND disabled = 0 AND id != ?",
                          (excluding or "",)).fetchone()[0]

    def update_user(self, user_id: str, *, role: Any = None, disabled: Any = None, password: Any = None,
                    unlock: bool = False, reset_totp: bool = False) -> dict[str, Any]:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                raise AuthError("Kullanıcı bulunamadı.")
            losing_admin = (role is not None and role != "admin") or disabled is True
            if row["role"] == "admin" and not row["disabled"] and losing_admin and not self._active_admins(db, user_id):
                raise AuthError("Son etkin yönetici kaldırılamaz ya da kapatılamaz.")
            if role is not None:
                db.execute("UPDATE auth_users SET role = ? WHERE id = ?", (validate_role(role), user_id))
            if disabled is not None:
                if not isinstance(disabled, bool):
                    raise AuthError("disabled true/false olmalıdır.")
                db.execute("UPDATE auth_users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
                if disabled:
                    db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
            if password is not None:
                validate_password(password, row["username"])
                db.execute("UPDATE auth_users SET password_hash = ?, password_changed_at = ?, failed_count = 0, "
                           "locked_until = 0 WHERE id = ?", (hash_password(password), _now(), user_id))
                db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
            if unlock:
                db.execute("UPDATE auth_users SET failed_count = 0, locked_until = 0 WHERE id = ?", (user_id,))
            if reset_totp:
                db.execute("UPDATE auth_users SET totp_enabled = 0, totp_secret = NULL, totp_pending = NULL, "
                           "totp_secret_format = 'enc1', totp_pending_format = 'enc1', "
                           "totp_last_step = NULL WHERE id = ?", (user_id,))
                db.execute("DELETE FROM auth_recovery_codes WHERE user_id = ?", (user_id,))
            if role is not None and role != row["role"]:
                db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
            return self._public_user(db.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,)).fetchone())

    def find_user_id(self, username: str) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT id FROM auth_users WHERE username = ?", (username,)).fetchone()
            return row["id"] if row else None

    def disable_auth(self) -> None:
        with self._connect() as db:
            self._set_enabled(db, False)
            db.execute("DELETE FROM auth_sessions")
            db.execute("DELETE FROM auth_challenges")

    def enable_auth(self) -> None:
        with self._connect() as db:
            if not self._active_admins(db):
                raise AuthError("Etkin yönetici yok; önce yönetici oluşturun.")
            self._set_enabled(db, True)

    # -- giriş ------------------------------------------------------------
    def _ip_blocked(self, client: str) -> bool:
        cutoff = _now() - IP_WINDOW_SECONDS
        with self._ip_lock:
            entries = [t for t in self._ip_failures.get(client, []) if t > cutoff]
            self._ip_failures[client] = entries
            return len(entries) >= IP_MAX_FAILURES

    def _ip_fail(self, client: str) -> None:
        with self._ip_lock:
            self._ip_failures.setdefault(client, []).append(_now())
            if len(self._ip_failures) > 10_000:
                self._ip_failures.pop(next(iter(self._ip_failures)))

    def authenticate(self, username: Any, password: Any, client: str) -> tuple[str, dict[str, Any]]:
        """``("session", user)`` ya da ``("totp", {"challenge": ...})``. Hata mesajı hangi alanın yanlış olduğunu söylemez."""
        if self._ip_blocked(client):
            raise AuthLocked("Çok fazla başarısız giriş; bir süre sonra yeniden deneyin.")
        if not isinstance(username, str) or not isinstance(password, str) or len(password) > PASSWORD_MAX \
                or len(username) > 64:
            verify_password("x" * 12, None)
            self._ip_fail(client)
            raise AuthDenied("Kullanıcı adı veya parola hatalı.")
        # Hata, başarısız deneme sayacı kalıcılaştıktan sonra (işlem bloğunun dışında) fırlatılır.
        error: AuthError | None = None
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM auth_users WHERE username = ?", (username,)).fetchone()
            ok = verify_password(password, row["password_hash"] if row else None)
            now = _now()
            if row and row["locked_until"] > now:
                error = AuthLocked("Hesap geçici olarak kilitli; bir süre sonra yeniden deneyin.")
            elif not row or not ok or row["disabled"]:
                if row and not ok:
                    failed = row["failed_count"] + 1
                    locked_until = 0.0
                    if failed % LOCK_THRESHOLD == 0:
                        locked_until = now + min(LOCK_MAX_SECONDS, LOCK_BASE_SECONDS * 2 ** (failed // LOCK_THRESHOLD - 1))
                    db.execute("UPDATE auth_users SET failed_count = ?, locked_until = ? WHERE id = ?",
                               (failed, locked_until, row["id"]))
                self._ip_fail(client)
                error = AuthDenied("Kullanıcı adı veya parola hatalı.")
            if error is None:
                return self._login_success(db, row, now)
        raise error

    def _login_success(self, db: sqlite3.Connection, row: sqlite3.Row, now: float) -> tuple[str, dict[str, Any]]:
        """authenticate() işlemi içinde: sayaçları sıfırla; TOTP etkinse ikinci adım için kısa ömürlü çağrı üret."""
        db.execute("UPDATE auth_users SET failed_count = 0, locked_until = 0 WHERE id = ?", (row["id"],))
        if row["totp_enabled"]:
            challenge = secrets.token_urlsafe(32)
            db.execute("DELETE FROM auth_challenges WHERE expires_at < ?", (now,))
            db.execute("INSERT INTO auth_challenges(challenge_hash, user_id, expires_at) VALUES (?, ?, ?)",
                       (_sha256(challenge), row["id"], now + CHALLENGE_SECONDS))
            return "totp", {"challenge": challenge, "user_id": row["id"]}
        db.execute("UPDATE auth_users SET last_login_at = ? WHERE id = ?", (now, row["id"]))
        return "session", self._public_user(row)

    def complete_totp(self, challenge: Any, code: Any, recovery_code: Any, client: str) -> dict[str, Any]:
        if self._ip_blocked(client):
            raise AuthLocked("Çok fazla başarısız deneme; bir süre sonra yeniden deneyin.")
        if not isinstance(challenge, str) or len(challenge) > 128:
            raise AuthDenied("Doğrulama oturumu geçersiz veya süresi doldu.")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = _now()
            item = db.execute("SELECT * FROM auth_challenges WHERE challenge_hash = ?", (_sha256(challenge),)).fetchone()
            if not item or item["expires_at"] < now or item["attempts"] >= CHALLENGE_MAX_ATTEMPTS:
                raise AuthDenied("Doğrulama oturumu geçersiz veya süresi doldu.")
            row = db.execute("SELECT * FROM auth_users WHERE id = ?", (item["user_id"],)).fetchone()
            if not row or row["disabled"] or not row["totp_enabled"]:
                raise AuthDenied("Doğrulama oturumu geçersiz veya süresi doldu.")
            ok = False
            if isinstance(recovery_code, str) and recovery_code.strip():
                code_hash = _sha256(_normalize_recovery(recovery_code))
                hit = db.execute("SELECT 1 FROM auth_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
                                 (row["id"], code_hash)).fetchone()
                if hit:
                    db.execute("UPDATE auth_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ?",
                               (now, row["id"], code_hash))
                    ok = True
            else:
                secret, legacy = self._open_totp_value(
                    db, row["id"], "totp_secret", row["totp_secret"], row["totp_secret_format"]
                )
                step = totp_match(secret, code, now=now, last_step=row["totp_last_step"])
                if step is not None:
                    if legacy:
                        db.execute("UPDATE auth_users SET totp_secret = ?, totp_secret_format = 'enc1', "
                                   "totp_last_step = ? WHERE id = ?",
                                   (self._seal_totp(row["id"], "totp_secret", secret), step, row["id"]))
                        self._maybe_finalize_totp_migration(db)
                    else:
                        db.execute("UPDATE auth_users SET totp_last_step = ? WHERE id = ?", (step, row["id"]))
                    ok = True
            if ok:
                db.execute("DELETE FROM auth_challenges WHERE challenge_hash = ?", (_sha256(challenge),))
                db.execute("UPDATE auth_users SET last_login_at = ? WHERE id = ?", (now, row["id"]))
                return self._public_user(row)
            # Deneme sayacı kalıcılaşsın diye hata işlem bloğundan sonra fırlatılır.
            db.execute("UPDATE auth_challenges SET attempts = attempts + 1 WHERE challenge_hash = ?",
                       (_sha256(challenge),))
            self._ip_fail(client)
        raise AuthDenied("Doğrulama kodu hatalı.")

    # -- oturum -----------------------------------------------------------
    def create_session(self, user_id: str, client: str) -> tuple[str, str]:
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = _now()
        with self._connect() as db:
            db.execute("DELETE FROM auth_sessions WHERE last_seen < ? OR created_at < ?",
                       (now - session_idle_seconds(), now - session_max_seconds()))
            db.execute("INSERT INTO auth_sessions(token_hash, user_id, csrf_hash, created_at, last_seen, client) "
                       "VALUES (?, ?, ?, ?, ?, ?)", (_sha256(token), user_id, _sha256(csrf), now, now, client[:64]))
        return token, csrf

    def lookup_session(self, token: str | None) -> dict[str, Any] | None:
        """Geçerli oturum → ``{"user": ..., "csrf_hash": ..., "token_hash": ...}``; süresi dolmuşsa siler."""
        if not token or len(token) > 128:
            return None
        token_hash = _sha256(token)
        now = _now()
        with self._connect() as db:
            row = db.execute(
                "SELECT s.*, u.username, u.role, u.disabled, u.password_changed_at, u.totp_enabled, u.created_at AS u_created, "
                "u.last_login_at, u.locked_until, u.id AS uid FROM auth_sessions s JOIN auth_users u ON u.id = s.user_id "
                "WHERE s.token_hash = ?", (token_hash,)).fetchone()
            if not row:
                return None
            expired = (row["last_seen"] < now - session_idle_seconds() or row["created_at"] < now - session_max_seconds()
                       or row["disabled"] or row["password_changed_at"] > row["created_at"])
            if expired:
                db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
                return None
            if now - row["last_seen"] > 60:
                db.execute("UPDATE auth_sessions SET last_seen = ? WHERE token_hash = ?", (now, token_hash))
            user = {"id": row["uid"], "username": row["username"], "role": row["role"],
                    "role_label": ROLE_LABELS.get(row["role"], row["role"]), "totp_enabled": bool(row["totp_enabled"])}
            return {"user": user, "csrf_hash": row["csrf_hash"], "token_hash": token_hash}

    @staticmethod
    def csrf_ok(session: dict[str, Any], header_value: str | None) -> bool:
        if not header_value or len(header_value) > 128:
            return False
        return hmac.compare_digest(_sha256(header_value), session["csrf_hash"])

    def revoke_session(self, token_hash: str) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))

    def revoke_user_sessions(self, user_id: str, *, except_hash: str | None = None) -> int:
        with self._connect() as db:
            cursor = db.execute("DELETE FROM auth_sessions WHERE user_id = ? AND token_hash != ?", (user_id, except_hash or ""))
            return cursor.rowcount

    def change_own_password(self, user_id: str, current: Any, new: Any) -> None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,)).fetchone()
        if not row or not isinstance(current, str) or not verify_password(current, row["password_hash"]):
            raise AuthDenied("Mevcut parola hatalı.")
        if isinstance(new, str) and verify_password(new, row["password_hash"]):
            raise AuthError("Yeni parola eskisiyle aynı olamaz.")
        self.update_user(user_id, password=new)

    # -- TOTP kaydı -------------------------------------------------------
    def totp_begin(self, user_id: str) -> dict[str, str]:
        secret = new_totp_secret()
        with self._connect() as db:
            row = db.execute("SELECT username, totp_enabled FROM auth_users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                raise AuthError("Kullanıcı bulunamadı.")
            if row["totp_enabled"]:
                raise AuthError("İki adımlı doğrulama zaten etkin.")
            sealed = self._seal_totp(user_id, "totp_pending", secret)
            db.execute("UPDATE auth_users SET totp_pending = ?, totp_pending_format = 'enc1' WHERE id = ?",
                       (sealed, user_id))
        return {"secret": secret, "otpauth_uri": otpauth_uri(secret, row["username"])}

    def totp_confirm(self, user_id: str, code: Any) -> list[str]:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT totp_pending, totp_pending_format FROM auth_users WHERE id = ?",
                             (user_id,)).fetchone()
            if not row or not row["totp_pending"]:
                raise AuthError("Önce iki adımlı doğrulama kurulumunu başlatın.")
            secret, _legacy = self._open_totp_value(
                db, user_id, "totp_pending", row["totp_pending"], row["totp_pending_format"]
            )
            step = totp_match(secret, code)
            if step is None:
                raise AuthError("Doğrulama kodu hatalı.")
            codes = new_recovery_codes()
            sealed = self._seal_totp(user_id, "totp_secret", secret)
            db.execute("UPDATE auth_users SET totp_secret = ?, totp_secret_format = 'enc1', "
                       "totp_pending = NULL, totp_pending_format = 'enc1', totp_enabled = 1, "
                       "totp_last_step = ? WHERE id = ?", (sealed, step, user_id))
            db.execute("DELETE FROM auth_recovery_codes WHERE user_id = ?", (user_id,))
            db.executemany("INSERT INTO auth_recovery_codes(user_id, code_hash) VALUES (?, ?)",
                           [(user_id, _sha256(_normalize_recovery(c))) for c in codes])
            db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        return codes

    def totp_disable(self, user_id: str, password: Any, code: Any) -> None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,)).fetchone()
            if not row or not isinstance(password, str) or not verify_password(password, row["password_hash"]):
                raise AuthDenied("Parola hatalı.")
            if row["totp_enabled"]:
                secret, _legacy = self._open_totp_value(
                    db, row["id"], "totp_secret", row["totp_secret"], row["totp_secret_format"]
                )
                if totp_match(secret, code, last_step=row["totp_last_step"]) is None:
                    raise AuthDenied("Doğrulama kodu hatalı.")
        self.update_user(user_id, reset_totp=True)

    def open_totp_legacy_migration_window(self, seconds: int = 900) -> dict[str, Any]:
        """Explicitly allow only rows discovered during a bounded legacy migration."""
        if isinstance(seconds, bool) or not isinstance(seconds, int) or not 60 <= seconds <= 3600:
            raise AuthError("TOTP geçiş penceresi 60–3600 saniye olmalıdır.")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            state = self._setting(db, TOTP_ENCRYPTION_STATE_KEY)
            if state != TOTP_STATE_REQUIRED:
                raise AuthError("TOTP düz metin geçişi gerektiren başlangıç durumu yok.")
            db.execute(
                "UPDATE auth_users SET totp_secret_format = 'legacy' "
                "WHERE totp_secret IS NOT NULL AND totp_secret NOT LIKE 'enc1:%'"
            )
            db.execute(
                "UPDATE auth_users SET totp_pending_format = 'legacy' "
                "WHERE totp_pending IS NOT NULL AND totp_pending NOT LIKE 'enc1:%'"
            )
            legacy_fields = db.execute(
                "SELECT COALESCE(SUM((totp_secret IS NOT NULL AND totp_secret_format = 'legacy') + "
                "(totp_pending IS NOT NULL AND totp_pending_format = 'legacy')), 0) FROM auth_users"
            ).fetchone()[0]
            if not legacy_fields:
                self._put_setting(db, TOTP_ENCRYPTION_STATE_KEY, TOTP_STATE_SEALED)
                self._put_setting(db, TOTP_MIGRATION_DEADLINE_KEY, "0")
                raise AuthError("Geçirilecek eski TOTP düz metin alanı yok.")
            deadline = _now() + seconds
            self._put_setting(db, TOTP_ENCRYPTION_STATE_KEY, TOTP_STATE_WINDOW)
            self._put_setting(db, TOTP_MIGRATION_DEADLINE_KEY, str(deadline))
            return {"format": "sniper-totp-legacy-migration/1", "state": TOTP_STATE_WINDOW,
                    "legacy_fields": int(legacy_fields), "deadline": deadline}

    def totp_legacy_migration_status(self) -> dict[str, Any]:
        with self._connect() as db:
            legacy_fields = db.execute(
                "SELECT COALESCE(SUM((totp_secret IS NOT NULL AND totp_secret_format = 'legacy') + "
                "(totp_pending IS NOT NULL AND totp_pending_format = 'legacy')), 0) FROM auth_users"
            ).fetchone()[0]
            state = self._setting(db, TOTP_ENCRYPTION_STATE_KEY) or TOTP_STATE_REQUIRED
            deadline = float(self._setting(db, TOTP_MIGRATION_DEADLINE_KEY) or "0")
            return {"format": "sniper-totp-legacy-migration/1", "state": state,
                    "legacy_fields": int(legacy_fields), "deadline": deadline}

    def rotate_totp_field_key(self) -> dict[str, Any]:
        """Rotate the external key and re-encrypt TOTP fields in one DB transaction.

        Old keys remain in the keyring for recovery of a rolled-back auth.db.  A
        separately backed up keyring is therefore part of the database recovery
        set and must not be pruned until old database backups expire.
        """
        if not self.path.is_file():
            raise AuthError("Giriş etkin değil; döndürülecek auth.db bulunamadı.")
        changed = 0
        try:
            with self.field_keys.rotation() as rotation:
                old_key_id = rotation["old_key_id"]
                new_key_id = rotation["new_key_id"]
                new_key = rotation["new_key"]
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    rows = db.execute(
                        "SELECT id, totp_secret, totp_pending, totp_secret_format, totp_pending_format "
                        "FROM auth_users WHERE totp_secret IS NOT NULL OR totp_pending IS NOT NULL"
                    ).fetchall()
                    for row in rows:
                        secret_value = row["totp_secret"]
                        pending_value = row["totp_pending"]
                        if row["totp_secret"]:
                            plain, _legacy = self._open_totp_value(
                                db, row["id"], "totp_secret", row["totp_secret"], row["totp_secret_format"]
                            )
                            secret_value = self.field_keys.seal_with_key(
                                plain, user_id=row["id"], field="totp_secret",
                                key_id=new_key_id, key=new_key,
                            )
                            changed += 1
                        if row["totp_pending"]:
                            plain, _legacy = self._open_totp_value(
                                db, row["id"], "totp_pending", row["totp_pending"], row["totp_pending_format"]
                            )
                            pending_value = self.field_keys.seal_with_key(
                                plain, user_id=row["id"], field="totp_pending",
                                key_id=new_key_id, key=new_key,
                            )
                            changed += 1
                        db.execute(
                            "UPDATE auth_users SET totp_secret = ?, totp_pending = ?, "
                            "totp_secret_format = 'enc1', totp_pending_format = 'enc1' WHERE id = ?",
                            (secret_value, pending_value, row["id"]),
                        )
                    self._maybe_finalize_totp_migration(db)
        except auth_field_keys.FieldEncryptionError as exc:
            raise AuthError(str(exc)) from exc
        return {
            "format": "sniper-auth-field-key-rotation/1",
            "old_key_id": old_key_id,
            "active_key_id": new_key_id,
            "fields_reencrypted": changed,
            "keyring": str(self.field_keys.path),
        }

    def totp_field_key_status(self) -> dict[str, Any]:
        try:
            return self.field_keys.status()
        except auth_field_keys.FieldEncryptionError as exc:
            raise AuthError(str(exc)) from exc

    def recovery_codes_left(self, user_id: str) -> int:
        with self._connect() as db:
            return db.execute("SELECT COUNT(*) FROM auth_recovery_codes WHERE user_id = ? AND used_at IS NULL",
                              (user_id,)).fetchone()[0]

    # -- kurulum belirteci ------------------------------------------------
    def setup_token_path(self) -> Path:
        return self.data_dir / SETUP_TOKEN_NAME

    def setup_begin(self) -> Path:
        """Yalnız giriş kapalıyken: 0600 belirteç dosyası (içerik yanıtla dönmez; yerel kullanıcı okur)."""
        if self.enabled():
            raise AuthError("Giriş zaten etkin.")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path = self.setup_token_path()
        token = secrets.token_urlsafe(24)
        data = json.dumps({"token": token, "expires_at": _now() + SETUP_TOKEN_SECONDS}).encode()
        tmp = path.with_name(f".{SETUP_TOKEN_NAME}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        return path

    def setup_complete(self, token: Any, username: Any, password: Any) -> dict[str, Any]:
        if self.enabled():
            raise AuthError("Giriş zaten etkin.")
        path = self.setup_token_path()
        try:
            if path.is_symlink():
                raise AuthDenied("Kurulum belirteci geçersiz veya süresi doldu.")
            stored = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise AuthDenied("Kurulum belirteci geçersiz veya süresi doldu.") from None
        if not isinstance(token, str) or not isinstance(stored, dict) or stored.get("expires_at", 0) < _now() \
                or not hmac.compare_digest(token.strip(), str(stored.get("token", ""))):
            raise AuthDenied("Kurulum belirteci geçersiz veya süresi doldu.")
        user = self.create_admin_and_enable(username, password)
        try:
            path.unlink()
        except OSError:
            pass
        return user


_MANAGERS: dict[str, AuthManager] = {}
_MANAGERS_LOCK = threading.Lock()


def manager_for(data_dir: Path) -> AuthManager:
    key = str(Path(data_dir))
    with _MANAGERS_LOCK:
        manager = _MANAGERS.get(key)
        if manager is None:
            manager = _MANAGERS[key] = AuthManager(Path(data_dir))
        return manager


def parse_cookies(header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in (header or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name and name not in cookies:
            cookies[name] = value.strip()
    return cookies


def session_cookie_headers(token: str, csrf: str, *, secure: bool) -> list[str]:
    flags = "; Path=/; SameSite=Strict" + ("; Secure" if secure else "")
    return [f"{SESSION_COOKIE}={token}; HttpOnly{flags}", f"{CSRF_COOKIE}={csrf}{flags}"]


def clear_cookie_headers(*, secure: bool) -> list[str]:
    flags = "; Path=/; SameSite=Strict; Max-Age=0" + ("; Secure" if secure else "")
    return [f"{SESSION_COOKIE}=; HttpOnly{flags}", f"{CSRF_COOKIE}={flags}"]
