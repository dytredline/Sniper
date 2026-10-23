"""Denetim günlüğü için anahtarlı (HMAC) bütünlük ve veritabanı dışı zincir başı çapası.

Anahtarsız SHA-256 zinciri, veritabanına yazabilen birinin tüm zinciri baştan hesaplamasını
engellemez. Burada:

* Anahtar veritabanı dışında, yalnız sahibinin okuyabildiği bir dosyada durur
  (`${XDG_CONFIG_HOME:-~/.config}/sniper/audit.key`, `SNIPER_AUDIT_KEY_FILE` ile değişir).
  Yalnız zincirde henüz HMAC'li kayıt yokken, O_EXCL ile 0600 ve 32 rastgele bayt olarak
  oluşturulur; HMAC'li kayıtlar varken kaybolan anahtar sessizce yenilenmez.
* Yeni kayıtların entry_hash'i ``hmac1:<hex>`` biçimindedir (HMAC-SHA256). Eski SHA-256 zincirli
  ve zincir öncesi kayıtlar aynen doğrulanmaya devam eder.
* Her eklemeden sonra zincir başı (son id, entry_hash, zincirli kayıt sayısı) veritabanı dışında
  anahtarla imzalı bir çapa dosyasına atomik yazılır; doğrulama kuyruk silinmesini ve geri
  sarmayı bununla görür.

Sınır: Sniper ile aynı kullanıcı yetkisine sahip bir saldırgan anahtarı da okuyabilir; bu
katman yalnız veritabanının tek başına değiştirilmesine/geri yüklenmesine karşı korur. Eski
ama geçerli bir çapanın yeniden konması (replay) da bu katmanla tespit edilemez.

Anahtar baytları hiçbir zaman günlüğe, hata mesajına ya da API çıktısına yazılmaz; dışarıya
yalnız tek yönlü bir ``key_id`` parmak izi verilir.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any

KEY_BYTES = 32
HMAC_PREFIX = "hmac1:"
HMAC_ENTRY_SCHEME = "sniper-audit-entry-v2-hmac"
ANCHOR_FORMAT = "sniper-audit-anchor-v1"
_MAX_ANCHOR_BYTES = 16_384

KEY_STATUS_MESSAGES = {
    "ok": "Denetim anahtarı kullanılabilir.",
    "missing": "Denetim anahtarı bulunamadı; HMAC'li kayıtlar doğrulanamaz, yeni kayıtlar anahtarsız zincirlenir.",
    "insecure": "Denetim anahtarı veya dizininin izinleri gevşek ya da sahibi farklı; anahtar kullanılmadı.",
    "unreadable": "Denetim anahtarı okunamadı; anahtar kullanılmadı.",
    "invalid": "Denetim anahtarı dosyası geçersiz (32 bayt bekleniyor); anahtar kullanılmadı.",
    "disabled": "Anahtarlı denetim zinciri SNIPER_AUDIT_HMAC=0 ile kapatıldı.",
}


@dataclass(frozen=True)
class KeyState:
    status: str
    path: str
    key: bytes | None = field(default=None, repr=False, compare=False)

    @property
    def usable(self) -> bool:
        return self.status == "ok" and self.key is not None

    @property
    def message(self) -> str:
        return KEY_STATUS_MESSAGES.get(self.status, self.status)

    @property
    def key_id(self) -> str:
        if not self.usable:
            return ""
        assert self.key is not None
        return hashlib.sha256(b"sniper-audit-key-id-v1|" + self.key).hexdigest()[:16]

    def public(self) -> dict[str, Any]:
        return {"status": self.status, "message": self.message, "key_id": self.key_id, "path": self.path}


def _config_dir() -> Path:
    raw = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(raw) if raw and Path(raw).is_absolute() else Path.home() / ".config"
    return base / "sniper"


def _is_ephemeral_db(db_path: Path | str | None) -> bool:
    """Sistem geçici dizinindeki (testler, duman testi) veritabanı mı?"""
    if db_path is None:
        return False
    try:
        resolved = Path(db_path).expanduser().resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
    except (OSError, RuntimeError):
        return False
    return temp_root in resolved.parents


def _ephemeral_dir() -> Path:
    return Path(tempfile.gettempdir()) / f"sniper-audit-integrity-{os.getuid()}"


def key_path(db_path: Path | str | None = None) -> Path:
    """Anahtar dosyası. Açık ayar yoksa ve veritabanı geçici dizindeyse anahtar da geçici dizinde
    tutulur: testler kullanıcının gerçek ~/.config/sniper anahtarını üretmez ya da kullanmaz."""
    raw = os.environ.get("SNIPER_AUDIT_KEY_FILE", "").strip()
    if raw:
        return Path(raw).expanduser()
    if _is_ephemeral_db(db_path):
        return _ephemeral_dir() / "audit.key"
    return _config_dir() / "audit.key"


def anchor_dir(db_path: Path | str | None = None) -> Path:
    raw = os.environ.get("SNIPER_AUDIT_ANCHOR_DIR", "").strip()
    return Path(raw).expanduser() if raw else key_path(db_path).parent / "audit-anchors"


def anchor_path_for(db_path: Path | str) -> Path:
    """Her veritabanının kendi çapası olur (testler/aday kopyalar canlı çapayı ezmesin)."""
    resolved = str(Path(db_path).expanduser().resolve())
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:32]
    return anchor_dir(db_path) / f"{digest}.json"


def _hmac_disabled() -> bool:
    return os.environ.get("SNIPER_AUDIT_HMAC", "").strip() == "0"


def _dir_is_safe(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022)


def _ensure_private_dir(path: Path) -> bool:
    # Path.mkdir(parents=True) ara dizinleri umask'lı varsayılan izinle (ör. 0775) oluşturur; anahtar
    # dizininin üst dizini sonradan "gevşek" görünmesin diye eksik her bileşen 0700 oluşturulur.
    missing: list[Path] = []
    current = path
    while not current.exists() and current != current.parent:
        missing.append(current)
        current = current.parent
    try:
        for component in reversed(missing):
            try:
                component.mkdir(mode=0o700)
            except FileExistsError:
                pass
    except OSError:
        return False
    return _dir_is_safe(path)


def _read_key(path: Path) -> KeyState:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return KeyState("missing", str(path))
    except OSError as exc:
        # O_NOFOLLOW sembolik bağda ELOOP verir: bağ üzerinden anahtar kabul edilmez.
        return KeyState("insecure" if exc.errno == errno.ELOOP else "unreadable", str(path))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return KeyState("insecure", str(path))
        if not _dir_is_safe(path.parent):
            return KeyState("insecure", str(path))
        if info.st_size != KEY_BYTES:
            return KeyState("invalid", str(path))
        data = os.read(fd, KEY_BYTES + 1)
    except OSError:
        return KeyState("unreadable", str(path))
    finally:
        os.close(fd)
    if len(data) != KEY_BYTES:
        return KeyState("invalid", str(path))
    return KeyState("ok", str(path), data)


def _create_key(path: Path) -> None:
    if not _ensure_private_dir(path.parent):
        return
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        return  # Eşzamanlı oluşturan kazandı; aşağıda okunur.
    except OSError:
        return
    try:
        os.write(fd, secrets.token_bytes(KEY_BYTES))
        os.fsync(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        return
    os.close(fd)


def load_key(*, create: bool = False, db_path: Path | str | None = None) -> KeyState:
    """Anahtarı oku; `create` yalnız zincirde HMAC'li kayıt yokken verilmelidir."""
    path = key_path(db_path)
    if _hmac_disabled():
        return KeyState("disabled", str(path))
    state = _read_key(path)
    if state.status == "missing" and create:
        _create_key(path)
        state = _read_key(path)
    return state


def _subkey(key: bytes, label: bytes) -> bytes:
    return hmac.new(key, b"sniper-subkey-v1|" + label, hashlib.sha256).digest()


def compute_hmac_entry_hash(
    key: bytes, prev_hash: str, occurred_at: str, action: str, entity_id: str, details_json: str
) -> str:
    material = json.dumps(
        {
            "scheme": HMAC_ENTRY_SCHEME,
            "prev_hash": str(prev_hash),
            "occurred_at": str(occurred_at),
            "action": str(action),
            "entity_id": str(entity_id),
            "details_json": str(details_json),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hmac.new(_subkey(key, b"audit-entry"), material.encode("utf-8"), hashlib.sha256).hexdigest()
    return HMAC_PREFIX + digest


def is_hmac_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(HMAC_PREFIX)


def document_mac(key: bytes, label: str, document: dict[str, Any]) -> str:
    """Bir JSON belgesinin (``mac`` alanı hariç) amaca özel alt anahtarla HMAC'i.

    Aynı yerel anahtar farklı amaçlarda (ör. OSV manifesti) kullanılır; alt anahtar etiketi
    amaçlar arasında imza taşınmasını engeller.
    """
    body = {name: value for name, value in document.items() if name != "mac"}
    material = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hmac.new(_subkey(key, b"doc|" + label.encode("utf-8")), material.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def verify_document_mac(key_state: KeyState, label: str, document: dict[str, Any]) -> bool:
    mac = document.get("mac")
    if not key_state.usable or not key_state.key or not isinstance(mac, str):
        return False
    if document.get("key_id") != key_state.key_id:
        return False
    return hmac.compare_digest(mac, document_mac(key_state.key, label, document))


# --- Çapa ---------------------------------------------------------------------------------------

_ANCHOR_FIELDS = ("format", "db_id", "last_id", "head_hash", "chained_count", "updated_at", "key_id")


def _db_id(db_path: Path | str) -> str:
    return anchor_path_for(db_path).stem


def _anchor_mac(key: bytes, payload: dict[str, Any]) -> str:
    material = json.dumps({name: payload.get(name) for name in _ANCHOR_FIELDS},
                          ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hmac.new(_subkey(key, b"audit-anchor"), material.encode("utf-8"), hashlib.sha256).hexdigest()


def _read_anchor_file(path: Path) -> dict[str, Any] | None | str:
    """Ham çapa: None = yok, str = hata durumu, dict = içerik."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        return "unreadable"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > _MAX_ANCHOR_BYTES:
            return "insecure"
        raw = os.read(fd, _MAX_ANCHOR_BYTES + 1)
    except OSError:
        return "unreadable"
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return "invalid"
    if not isinstance(data, dict) or data.get("format") != ANCHOR_FORMAT:
        return "invalid"
    if type(data.get("last_id")) is not int or type(data.get("chained_count")) is not int:
        return "invalid"
    if not isinstance(data.get("head_hash"), str):
        return "invalid"
    return data


def write_anchor(db_path: Path | str, *, last_id: int, head_hash: str, chained_count: int,
                 updated_at: str, key_state: KeyState) -> str:
    """Zincir başını çapaya yaz. Asla istisna fırlatmaz; durum kodu döner.

    Aynı veritabanına eşzamanlı yazan süreçler arasında çapa geri gitmesin diye kilit altında
    yalnız daha ileri bir `last_id` yazılır.
    """
    path = anchor_path_for(db_path)
    if not _ensure_private_dir(path.parent):
        return "anchor_dir_insecure"
    lock_path = path.with_suffix(".lock")
    try:
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        return "anchor_lock_failed"
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        existing = _read_anchor_file(path)
        if isinstance(existing, dict) and existing["last_id"] >= last_id:
            return "anchor_not_advanced"
        payload: dict[str, Any] = {
            "format": ANCHOR_FORMAT,
            "db_id": _db_id(db_path),
            "last_id": int(last_id),
            "head_hash": str(head_hash),
            "chained_count": int(chained_count),
            "updated_at": str(updated_at),
            "key_id": key_state.key_id,
        }
        payload["mac"] = _anchor_mac(key_state.key, payload) if key_state.usable and key_state.key else None
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, ensure_ascii=False, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return "anchor_write_failed"
        return "anchor_written"
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def read_anchor(db_path: Path | str, key_state: KeyState) -> dict[str, Any]:
    """Çapayı oku ve imzasını denetle. Dönen sözlük: status + (varsa) last_id/head_hash/chained_count."""
    path = anchor_path_for(db_path)
    raw = _read_anchor_file(path)
    if raw is None:
        return {"status": "missing", "path": str(path)}
    if isinstance(raw, str):
        return {"status": raw, "path": str(path)}
    result = {
        "status": "ok",
        "path": str(path),
        "last_id": raw["last_id"],
        "head_hash": raw["head_hash"],
        "chained_count": raw["chained_count"],
        "updated_at": str(raw.get("updated_at") or ""),
        "authenticated": False,
    }
    if raw.get("db_id") != _db_id(db_path):
        result["status"] = "db_mismatch"
        return result
    mac = raw.get("mac")
    if mac is None:
        result["status"] = "unauthenticated"
        return result
    if not key_state.usable or not key_state.key:
        result["status"] = "unverifiable"
        return result
    if raw.get("key_id") != key_state.key_id or not isinstance(mac, str) or \
            not hmac.compare_digest(mac, _anchor_mac(key_state.key, raw)):
        result["status"] = "mac_invalid"
        return result
    result["authenticated"] = True
    return result
