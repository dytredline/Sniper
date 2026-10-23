"""ZAP V6 actor-job lease issuance, monotonic generation binding, and revocation guard.

Issues, binds, verifies, and revokes short-lived actor-job leases backed by an
owner-only atomic 0600 non-symlink JSON state file or in-memory monotonic
generation registry. Any unissued struct/dict, forged or non-positive
generation, stale/revoked generation, expired lease, or cross-job/actor/target
rebinding attempt fails closed with ``ZapLeaseError``.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path

from scanner import TargetRejected, normalize_target

SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}\Z", re.ASCII)
MAX_GENERATION = (1 << 63) - 1
DEFAULT_LEASE_TTL_SECONDS = 300.0
MAX_LEASE_TTL_SECONDS = 86400.0
MAX_STATE_BYTES = 1_048_576

_ALLOWED_LEASE_KEYS = frozenset({
    "actor_id",
    "job_id",
    "target_origin",
    "generation",
    "expires_at_epoch",
})

_REGISTRY_LOCK = threading.RLock()
_MEMORY_STATE: dict[str, object] = {
    "generation": 0,
    "secret": secrets.token_hex(32),
    "leases": {},
}
_HIGH_WATER_GENERATIONS: dict[str, int] = {}
_ISSUED_STORE_PATHS: dict[tuple[str, str, int], Path | None] = {}
_LAST_STORE_PATH: Path | None = None


class ZapLeaseError(ValueError):
    """Raised when a ZAP actor-job lease or store state fails validation."""


class ActorJobLease(dict):
    """Dictionary representation of an issued actor-job lease with attribute access."""

    def __init__(
        self,
        data: dict[str, object],
        *,
        lease_token: str | None = None,
        store_path: Path | None = None,
    ) -> None:
        super().__init__(data)
        object.__setattr__(self, "_lease_token", lease_token)
        object.__setattr__(self, "_store_path", store_path)

    @property
    def actor_id(self) -> str:
        return str(self["actor_id"])

    @property
    def job_id(self) -> str:
        return str(self["job_id"])

    @property
    def target_origin(self) -> str:
        return str(self["target_origin"])

    @property
    def generation(self) -> int:
        return int(self["generation"])

    @property
    def expires_at_epoch(self) -> float:
        return float(self["expires_at_epoch"])

    def copy(self) -> ActorJobLease:
        return ActorJobLease(
            dict(self),
            lease_token=getattr(self, "_lease_token", None),
            store_path=getattr(self, "_store_path", None),
        )

    def __copy__(self) -> ActorJobLease:
        return self.copy()

    def __deepcopy__(self, memo: object) -> ActorJobLease:
        return ActorJobLease(
            copy.deepcopy(dict(self), memo),
            lease_token=getattr(self, "_lease_token", None),
            store_path=getattr(self, "_store_path", None),
        )


def _validate_id(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID_RE.fullmatch(value) is None:
        raise ZapLeaseError(f"Geçersiz {label}.")
    return value


def _validate_generation(value: object) -> int:
    if type(value) is not int or not (1 <= value <= MAX_GENERATION):
        raise ZapLeaseError("Kiralama nesli kesin olarak pozitif bir tamsayı olmalı.")
    return value


def _validate_timestamp(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ZapLeaseError(f"Geçersiz {label}.")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise ZapLeaseError(f"Geçersiz {label}.")
    return result


def _canonical_target(raw: object) -> str:
    if isinstance(raw, dict):
        raw = raw.get("url") or raw.get("target_origin")
    if not isinstance(raw, str):
        raise ZapLeaseError("Geçersiz hedef kökeni.")
    candidate = raw.strip()
    if not candidate or candidate != raw:
        raise ZapLeaseError("Geçersiz hedef kökeni.")
    if not (candidate.startswith("http://") or candidate.startswith("https://")):
        raise ZapLeaseError("Hedef köken açık http veya https şeması kullanmalı.")
    try:
        normalized = normalize_target(candidate)
    except TargetRejected as exc:
        raise ZapLeaseError("Geçersiz hedef kökeni.") from exc
    if "//" in normalized.path or any(part in (".", "..") for part in normalized.path.split("/")):
        raise ZapLeaseError("Geçersiz hedef köken yolu.")
    if normalized.path == "/":
        if candidate not in (normalized.url, normalized.url.rstrip("/")):
            raise ZapLeaseError("Kanonik olmayan hedef kökeni.")
    elif candidate != normalized.url:
        raise ZapLeaseError("Kanonik olmayan hedef URL'si.")
    return normalized.url


def _compute_token(
    secret: str,
    actor_id: str,
    job_id: str,
    target_origin: str,
    generation: int,
    expires_at_epoch: float,
) -> str:
    payload = f"{actor_id}\0{job_id}\0{target_origin}\0{generation}\0{expires_at_epoch:.6f}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _check_no_symlinks(path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ZapLeaseError("Kiralama deposu yolu mutlak bir Path olmalı.")
    parts = path.parts
    if len(parts) < 2 or any(part in ("", ".", "..") for part in parts[1:]):
        raise ZapLeaseError("Kanonik olmayan kiralama deposu yolu.")
    current = Path("/")
    for part in parts[1:]:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ZapLeaseError("Kiralama deposu yoluna erişilemiyor.") from exc
        if stat.S_ISLNK(st.st_mode):
            raise ZapLeaseError("Kiralama deposu yolu sembolik bağ içermemeli.")


def _validate_existing_store_file(path: Path) -> bytes:
    _check_no_symlinks(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ZapLeaseError("Kiralama deposu dosyası yok.") from exc
    except OSError as exc:
        raise ZapLeaseError("Kiralama deposu dosyası güvenli biçimde açılamadı.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ZapLeaseError("Kiralama deposu yolu normal bir dosya olmalı.")
        if info.st_uid != os.getuid():
            raise ZapLeaseError("Kiralama deposu dosyasının sahibi uyuşmuyor.")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ZapLeaseError("Kiralama deposu dosyasının izni 0600 olmalı.")
        if info.st_size > MAX_STATE_BYTES:
            raise ZapLeaseError("Kiralama deposu dosyası azami boyutu aşıyor.")
        chunks: list[bytes] = []
        remaining = MAX_STATE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_STATE_BYTES:
            raise ZapLeaseError("Kiralama deposu dosyası azami boyutu aşıyor.")
        return data
    finally:
        os.close(fd)


class ActorJobLeaseStore:
    """Atomic 0600 JSON-backed or in-memory monotonic generation lease registry."""

    def __init__(self, store_path: Path | str | None = None, *, _create_if_missing: bool = True) -> None:
        if store_path is not None:
            if isinstance(store_path, str):
                store_path = Path(store_path)
            if not isinstance(store_path, Path) or not store_path.is_absolute():
                raise ZapLeaseError("Kiralama deposu yolu mutlak bir Path olmalı.")
            _check_no_symlinks(store_path)
            parent = store_path.parent
            if parent.exists():
                parent_stat = os.lstat(parent)
                if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid():
                    raise ZapLeaseError("Kiralama deposunun üst dizini geçersiz.")
            elif _create_if_missing:
                parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            else:
                raise ZapLeaseError("Kiralama deposu dizini yok.")
            if self._path_exists_or_special(store_path):
                self._read_file_state(store_path)
            elif _create_if_missing:
                initial = {
                    "generation": 0,
                    "secret": secrets.token_hex(32),
                    "leases": {},
                }
                self._write_file_state(store_path, initial)
            else:
                raise ZapLeaseError("Kiralama deposu dosyası yok.")
        self.store_path: Path | None = store_path

    @staticmethod
    def _path_exists_or_special(path: Path) -> bool:
        try:
            os.lstat(path)
            return True
        except FileNotFoundError:
            return False

    def _lock_file_fd(self, path: Path) -> int:
        lock_path = path.with_name(path.name + ".lock")
        _check_no_symlinks(lock_path)
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        old_umask = os.umask(0o177)
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise ZapLeaseError("Kiralama deposu kilit dosyası kullanılamıyor.") from exc
        finally:
            os.umask(old_umask)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                os.close(fd)
                raise ZapLeaseError("Geçersiz kiralama deposu kilit dosyası.")
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            return fd
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _read_file_state(self, path: Path) -> dict[str, object]:
        raw = _validate_existing_store_file(path)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ZapLeaseError("Bozuk kiralama deposu JSON'u.") from exc
        if not isinstance(parsed, dict):
            raise ZapLeaseError("Geçersiz kiralama deposu durum yapısı.")
        gen = parsed.get("generation")
        secret = parsed.get("secret")
        leases = parsed.get("leases")
        if (
            type(gen) is not int
            or not (0 <= gen <= MAX_GENERATION)
            or not isinstance(secret, str)
            or len(secret) < 32
            or not isinstance(leases, dict)
        ):
            raise ZapLeaseError("Geçersiz kiralama deposu meta verisi.")
        key = str(path)
        high_water = _HIGH_WATER_GENERATIONS.get(key, 0)
        if gen < high_water:
            raise ZapLeaseError("Kiralama deposu nesil geri sarması tespit edildi.")
        _HIGH_WATER_GENERATIONS[key] = gen
        return parsed

    def _write_file_state(self, path: Path, state: dict[str, object]) -> None:
        _check_no_symlinks(path)
        parent = path.parent
        parent_stat = os.lstat(parent)
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid():
            raise ZapLeaseError("Kiralama deposunun üst dizini geçersiz.")
        if self._path_exists_or_special(path):
            existing = os.lstat(path)
            if not stat.S_ISREG(existing.st_mode) or existing.st_uid != os.getuid():
                raise ZapLeaseError("Kiralama deposu hedefi sahip olunan normal bir dosya değil.")
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        tmp_path = parent / f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        old_umask = os.umask(0o177)
        try:
            fd = os.open(tmp_path, flags, 0o600)
        except OSError as exc:
            raise ZapLeaseError("Geçici kiralama durumu dosyası oluşturulamadı.") from exc
        finally:
            os.umask(old_umask)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload)
            os.fsync(fd)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        os.close(fd)
        try:
            os.replace(tmp_path, path)
        except OSError as exc:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise ZapLeaseError("Kiralama durumu dosyası atomik olarak değiştirilemedi.") from exc
        _HIGH_WATER_GENERATIONS[str(path)] = int(state["generation"])

    def _load_state(self) -> dict[str, object]:
        if self.store_path is None:
            return _MEMORY_STATE
        return self._read_file_state(self.store_path)

    def _save_state(self, state: dict[str, object]) -> None:
        if self.store_path is None:
            _MEMORY_STATE.clear()
            _MEMORY_STATE.update(state)
            return
        self._write_file_state(self.store_path, state)

    @property
    def generation(self) -> int:
        return self.current_generation()

    def current_generation(self) -> int:
        with _REGISTRY_LOCK:
            state = self._load_state()
            return int(state["generation"])

    def issue_lease(
        self,
        actor_id: str,
        job_id: str,
        target_origin: str,
        *,
        ttl_seconds: float = DEFAULT_LEASE_TTL_SECONDS,
        expires_at_epoch: float | None = None,
        now: float | None = None,
    ) -> ActorJobLease:
        global _LAST_STORE_PATH
        clean_actor = _validate_id(actor_id, "actor_id")
        clean_job = _validate_id(job_id, "job_id")
        clean_target = _canonical_target(target_origin)
        current_now = time.time() if now is None else _validate_timestamp(now, "now")
        if expires_at_epoch is None:
            clean_ttl = _validate_timestamp(ttl_seconds, "ttl_seconds")
            if clean_ttl > MAX_LEASE_TTL_SECONDS:
                raise ZapLeaseError("Kiralama TTL değeri izin verilen azami süreyi aşıyor.")
            expiry = current_now + clean_ttl
        else:
            expiry = _validate_timestamp(expires_at_epoch, "expires_at_epoch")
            if expiry <= current_now or (expiry - current_now) > MAX_LEASE_TTL_SECONDS:
                raise ZapLeaseError("Kiralama bitiş penceresi geçersiz.")

        with _REGISTRY_LOCK:
            lock_fd = self._lock_file_fd(self.store_path) if self.store_path is not None else None
            try:
                state = self._load_state()
                next_gen = int(state["generation"]) + 1
                if next_gen > MAX_GENERATION:
                    raise ZapLeaseError("Kiralama nesli taştı.")
                secret = str(state["secret"])
                token = _compute_token(secret, clean_actor, clean_job, clean_target, next_gen, expiry)
                leases = dict(state["leases"])
                for existing_record in leases.values():
                    if isinstance(existing_record, dict):
                        existing_record["active"] = False
                leases[clean_job] = {
                    "actor_id": clean_actor,
                    "job_id": clean_job,
                    "target_origin": clean_target,
                    "generation": next_gen,
                    "expires_at_epoch": expiry,
                    "active": True,
                    "token": token,
                }
                new_state = {
                    "generation": next_gen,
                    "secret": secret,
                    "leases": leases,
                }
                self._save_state(new_state)
                _ISSUED_STORE_PATHS[(clean_actor, clean_job, next_gen)] = self.store_path
                _LAST_STORE_PATH = self.store_path
                return ActorJobLease(
                    {
                        "actor_id": clean_actor,
                        "job_id": clean_job,
                        "target_origin": clean_target,
                        "generation": next_gen,
                        "expires_at_epoch": expiry,
                    },
                    lease_token=token,
                    store_path=self.store_path,
                )
            finally:
                if lock_fd is not None:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(lock_fd)

    issue = issue_lease

    def bind_lease(
        self,
        lease_or_actor: object,
        job_id: str | None = None,
        target_origin: str | None = None,
        *,
        actor_id: str | None = None,
        expected_actor: str | None = None,
        expected_job_id: str | None = None,
        expected_target: str | None = None,
        ttl_seconds: float = DEFAULT_LEASE_TTL_SECONDS,
        expires_at_epoch: float | None = None,
        now: float | None = None,
    ) -> dict[str, object]:
        if isinstance(lease_or_actor, str):
            if job_id is None or target_origin is None:
                raise ZapLeaseError("Yeni kiralama bağlamak için actor_id, job_id ve target_origin gerekli.")
            return self.issue_lease(
                lease_or_actor,
                job_id,
                target_origin,
                ttl_seconds=ttl_seconds,
                expires_at_epoch=expires_at_epoch,
                now=now,
            )
        target_actor = expected_actor or actor_id or (
            lease_or_actor.get("actor_id") if isinstance(lease_or_actor, dict) else getattr(lease_or_actor, "actor_id", "")
        )
        target_job = expected_job_id or job_id or (
            lease_or_actor.get("job_id") if isinstance(lease_or_actor, dict) else getattr(lease_or_actor, "job_id", "")
        )
        target_url = expected_target or target_origin or (
            lease_or_actor.get("target_origin") if isinstance(lease_or_actor, dict) else getattr(lease_or_actor, "target_origin", "")
        )
        return self.verify_lease(
            lease_or_actor,
            expected_actor=str(target_actor or ""),
            expected_job_id=str(target_job or ""),
            expected_target=str(target_url or ""),
            now=now,
        )

    def revoke_actor(self, actor_id: str) -> int:
        clean_actor = _validate_id(actor_id, "actor_id")
        return self._revoke_matching(actor_id=clean_actor, job_id=None)

    def revoke_job(self, job_id: str) -> int:
        clean_job = _validate_id(job_id, "job_id")
        return self._revoke_matching(actor_id=None, job_id=clean_job)

    def revoke_lease(self, lease_or_job_id: object) -> int:
        if isinstance(lease_or_job_id, str):
            return self.revoke_job(lease_or_job_id)
        if isinstance(lease_or_job_id, dict):
            job = _validate_id(lease_or_job_id.get("job_id"), "job_id")
            actor = _validate_id(lease_or_job_id.get("actor_id"), "actor_id")
            return self._revoke_matching(actor_id=actor, job_id=job)
        raise ZapLeaseError("İptal için geçersiz kiralama.")

    def revoke(
        self,
        target: object | None = None,
        *,
        actor_id: str | None = None,
        job_id: str | None = None,
    ) -> int:
        if target is not None:
            if isinstance(target, dict):
                return self.revoke_lease(target)
            if isinstance(target, str):
                clean = _validate_id(target, "revocation_target")
                return self._revoke_matching(actor_id=clean, job_id=clean, match_any=True)
            raise ZapLeaseError("Geçersiz iptal hedefi.")
        clean_actor = _validate_id(actor_id, "actor_id") if actor_id is not None else None
        clean_job = _validate_id(job_id, "job_id") if job_id is not None else None
        return self._revoke_matching(actor_id=clean_actor, job_id=clean_job)

    def _revoke_matching(
        self,
        *,
        actor_id: str | None,
        job_id: str | None,
        match_any: bool = False,
    ) -> int:
        with _REGISTRY_LOCK:
            lock_fd = self._lock_file_fd(self.store_path) if self.store_path is not None else None
            try:
                state = self._load_state()
                next_gen = int(state["generation"]) + 1
                if next_gen > MAX_GENERATION:
                    raise ZapLeaseError("Kiralama nesli taştı.")
                leases = dict(state["leases"])
                for key, record in list(leases.items()):
                    if not isinstance(record, dict):
                        continue
                    if actor_id is None and job_id is None:
                        record["active"] = False
                    elif match_any:
                        if record.get("actor_id") == actor_id or record.get("job_id") == job_id or key == job_id:
                            record["active"] = False
                    else:
                        if (actor_id is None or record.get("actor_id") == actor_id) and (
                            job_id is None or record.get("job_id") == job_id or key == job_id
                        ):
                            record["active"] = False
                new_state = {
                    "generation": next_gen,
                    "secret": str(state["secret"]),
                    "leases": leases,
                }
                self._save_state(new_state)
                return next_gen
            finally:
                if lock_fd is not None:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(lock_fd)

    def verify_lease(
        self,
        lease: object,
        *,
        expected_actor: str,
        expected_job_id: str,
        expected_target: str,
        now: float | None = None,
    ) -> dict[str, object]:
        clean_expected_actor = _validate_id(expected_actor, "expected_actor")
        clean_expected_job = _validate_id(expected_job_id, "expected_job_id")
        clean_expected_target = _canonical_target(expected_target)
        current_now = time.time() if now is None else _validate_timestamp(now, "now")

        if isinstance(lease, dict):
            unknown_keys = set(lease.keys()) - _ALLOWED_LEASE_KEYS
            if unknown_keys or not _ALLOWED_LEASE_KEYS.issubset(lease.keys()):
                raise ZapLeaseError("Bozuk ZAP aktör-iş kiralaması alanları.")
            raw_actor = lease.get("actor_id")
            raw_job = lease.get("job_id")
            raw_target = lease.get("target_origin")
            raw_generation = lease.get("generation")
            raw_expires = lease.get("expires_at_epoch")
            lease_token = getattr(lease, "_lease_token", None)
        else:
            raise ZapLeaseError("ZAP aktör-iş kiralaması verilmiş bir kiralama eşlemesi olmalı.")

        actor_id = _validate_id(raw_actor, "actor_id")
        job_id = _validate_id(raw_job, "job_id")
        target_origin = _canonical_target(raw_target)
        generation = _validate_generation(raw_generation)
        expires_at_epoch = _validate_timestamp(raw_expires, "expires_at_epoch")

        if actor_id != clean_expected_actor:
            raise ZapLeaseError("ZAP kiralaması aktörü uyuşmuyor.")
        if job_id != clean_expected_job:
            raise ZapLeaseError("ZAP kiralaması işi uyuşmuyor.")
        if target_origin != clean_expected_target:
            raise ZapLeaseError("ZAP kiralaması hedefi uyuşmuyor.")
        if current_now >= expires_at_epoch:
            raise ZapLeaseError("ZAP kiralamasının süresi doldu.")

        with _REGISTRY_LOCK:
            state = self._load_state()
            store_generation = int(state["generation"])
            if store_generation < 1 or generation != store_generation:
                raise ZapLeaseError("ZAP kiralama nesli bayat veya sahte.")
            leases = state.get("leases")
            if not isinstance(leases, dict):
                raise ZapLeaseError("Kiralama deposu durumu geçersiz.")
            stored = leases.get(job_id)
            if not isinstance(stored, dict) or stored.get("active") is not True:
                raise ZapLeaseError("ZAP kiralaması verilmemiş veya iptal edilmiş.")
            if (
                stored.get("actor_id") != actor_id
                or stored.get("job_id") != job_id
                or _canonical_target(stored.get("target_origin")) != target_origin
                or type(stored.get("generation")) is not int
                or stored.get("generation") != generation
            ):
                raise ZapLeaseError("ZAP kiralaması kayıtlı onay bağlamıyla eşleşmiyor.")
            stored_expires = _validate_timestamp(stored.get("expires_at_epoch"), "stored_expires_at_epoch")
            if abs(stored_expires - expires_at_epoch) > 1e-6 or current_now >= stored_expires:
                raise ZapLeaseError("ZAP kiralaması bitişi uyuşmuyor veya süresi dolmuş.")
            expected_token = _compute_token(
                str(state["secret"]),
                actor_id,
                job_id,
                target_origin,
                generation,
                stored_expires,
            )
            stored_token = stored.get("token")
            if not isinstance(stored_token, str) or not hmac.compare_digest(stored_token, expected_token):
                raise ZapLeaseError("Kayıtlı ZAP kiralaması bütünlük denetimi başarısız oldu.")
            if not isinstance(lease_token, str) or not hmac.compare_digest(lease_token, expected_token):
                raise ZapLeaseError("Doğrudan verilmemiş veya sahte ZAP kiralaması reddedildi.")

        return {
            "actor_id": actor_id,
            "job_id": job_id,
            "target_origin": target_origin,
            "generation": generation,
            "expires_at_epoch": expires_at_epoch,
        }

    verify = verify_lease


def verify_actor_job_lease(
    lease: object,
    *,
    expected_actor: str,
    expected_job_id: str,
    expected_target: str,
    store_path: Path | None = None,
    now: float | None = None,
) -> dict[str, object]:
    """Verify an issued actor-job lease against the monotonic generation store."""
    resolved_path = store_path
    if resolved_path is None:
        lease_store_path = getattr(lease, "_store_path", None)
        if isinstance(lease_store_path, Path):
            resolved_path = lease_store_path
        elif isinstance(lease, dict):
            key = (
                lease.get("actor_id") if isinstance(lease.get("actor_id"), str) else "",
                lease.get("job_id") if isinstance(lease.get("job_id"), str) else "",
                lease.get("generation") if type(lease.get("generation")) is int else -1,
            )
            if key in _ISSUED_STORE_PATHS:
                resolved_path = _ISSUED_STORE_PATHS[key]
            elif os.environ.get("SNIPER_ZAP_LEASE_STORE"):
                resolved_path = Path(os.environ["SNIPER_ZAP_LEASE_STORE"])
            elif _LAST_STORE_PATH is not None:
                resolved_path = _LAST_STORE_PATH
    store = ActorJobLeaseStore(resolved_path, _create_if_missing=False)
    return store.verify_lease(
        lease,
        expected_actor=expected_actor,
        expected_job_id=expected_job_id,
        expected_target=expected_target,
        now=now,
    )
