"""Consent-gated, offline OSV-Scanner analysis of one home-local npm lockfile.

The scanner sees only a bounded lockfile snapshot and a pinned offline npm DB.
A pinned seccomp launcher denies network syscalls before executing the scanner.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from npm_audit_active import _read_lockfile
from project_analyzer import validate_project_path


class OSVUnavailable(Exception):
    pass


class OSVBusy(Exception):
    pass


class OSVExecutionError(Exception):
    pass


MAX_REPORT_BYTES = 2_000_000
MAX_PACKAGES = 2_000
MAX_DB_AGE = timedelta(days=7)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


_DIGEST_CACHE: dict[str, tuple[tuple[int, int, int, int, int], str]] = {}
_DIGEST_CACHE_LOCK = threading.Lock()


def _sha256_file(path: Path) -> str:
    """SHA-256; aynı (dev, ino, boyut, mtime_ns, ctime_ns) için önbellekten.

    Hazır olma denetimi 200 MB'lık çevrimdışı veritabanını her çağrıda yeniden özetlemesin. Dosyaya
    yapılan her yazma ctime'ı değiştirir, bu yüzden değişen içerik önbellekten dönmez.
    """
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        key = str(path)
        with _DIGEST_CACHE_LOCK:
            cached = _DIGEST_CACHE.get(key)
        if cached and cached[0] == identity:
            return cached[1]
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) == identity[2:]:
        with _DIGEST_CACHE_LOCK:
            if len(_DIGEST_CACHE) > 256:
                _DIGEST_CACHE.clear()
            _DIGEST_CACHE[key] = (identity, digest)
    return digest


def _regular_pinned(path_key: str, sha_key: str, *, executable: bool) -> Path:
    raw = os.environ.get(path_key, "")
    expected = os.environ.get(sha_key, "")
    path = Path(raw)
    if not raw or not path.is_absolute() or not _HEX64.fullmatch(expected or ""):
        raise OSVUnavailable("OSV-Scanner çalışma zamanı yapılandırılmamış.")
    try:
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise OSVUnavailable("OSV-Scanner çalışma zamanı yolu güvenli değil.")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or (executable and not os.access(path, os.X_OK)):
            raise OSVUnavailable("OSV-Scanner çalışma zamanı kullanılamıyor.")
        if _sha256_file(path) != expected:
            raise OSVUnavailable("OSV-Scanner çalışma zamanı sabitlemesi uyuşmuyor.")
    except OSError as exc:
        raise OSVUnavailable("OSV-Scanner çalışma zamanı kullanılamıyor.") from exc
    return path


def _trusted_binary() -> Path:
    return _regular_pinned("SNIPER_OSV_SCANNER_BINARY", "SNIPER_OSV_SCANNER_SHA256", executable=True)


def _trusted_launcher() -> Path:
    """The guard is code, so require its own immutable deployment pin."""
    return _regular_pinned("SNIPER_OSV_SECCOMP_LAUNCHER", "SNIPER_OSV_SECCOMP_LAUNCHER_SHA256", executable=False)


_MAX_MANIFEST_BYTES = 65_536


def _trusted_manifest() -> dict[str, Any]:
    """Manifesti tek seferde (O_NOFOLLOW) oku; pin ya da yerel anahtarla imza ile güven.

    Güven yolları: (1) systemd/ortamdaki SNIPER_OSV_DB_MANIFEST_SHA256 okunan baytlarla eşleşir;
    (2) manifest `scripts/osv_refresh.py` tarafından yerel denetim anahtarıyla imzalanmıştır — böylece
    haftalık güncelleme sonrası pin eskise de servis yeniden başlatılmadan yeni veriye güvenilir.
    """
    raw_path = os.environ.get("SNIPER_OSV_DB_MANIFEST", "")
    path = Path(raw_path)
    if not raw_path or not path.is_absolute():
        raise OSVUnavailable("OSV-Scanner çalışma zamanı yapılandırılmamış.")
    try:
        if any(part.is_symlink() for part in path.parents):
            raise OSVUnavailable("OSV-Scanner çalışma zamanı yolu güvenli değil.")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise OSVUnavailable("OSV-Scanner çalışma zamanı kullanılamıyor.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_MANIFEST_BYTES:
            raise OSVUnavailable("OSV-Scanner çalışma zamanı kullanılamıyor.")
        raw = os.read(fd, _MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise OSVUnavailable("OSV-Scanner çalışma zamanı kullanılamıyor.") from exc
    finally:
        os.close(fd)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı manifesti geçersiz.") from exc
    if not isinstance(manifest, dict):
        raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı manifesti geçersiz.")
    expected = os.environ.get("SNIPER_OSV_DB_MANIFEST_SHA256", "")
    if _HEX64.fullmatch(expected or "") and hashlib.sha256(raw).hexdigest() == expected:
        return manifest
    from audit_integrity import load_key, verify_document_mac
    from osv_db_refresh import MANIFEST_MAC_LABEL
    if verify_document_mac(load_key(create=False), MANIFEST_MAC_LABEL, manifest):
        return manifest
    if not _HEX64.fullmatch(expected or ""):
        raise OSVUnavailable("OSV-Scanner çalışma zamanı yapılandırılmamış.")
    raise OSVUnavailable("OSV-Scanner çalışma zamanı sabitlemesi uyuşmuyor.")


def _trusted_db() -> tuple[Path, Path, str, str]:
    manifest = _trusted_manifest()
    try:
        retrieved_text = manifest["retrieved_utc"]
        retrieved = datetime.fromisoformat(retrieved_text)
        db_path = Path(manifest["scanner_cache_path"])
        expected = manifest["sha256"]
        size = manifest["bytes"]
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı manifesti geçersiz.") from exc
    now = datetime.now(timezone.utc)
    if (manifest.get("schema") != "SNIPER_OSV_NPM_OFFLINE_DB_V2" or
            manifest.get("network") != "none" or manifest.get("zip_test") != "PASS" or
            retrieved.tzinfo is None or not timedelta() <= now - retrieved <= MAX_DB_AGE or
            not db_path.is_absolute() or db_path.parts[-3:] != ("osv-scalibr", "npm", "all.zip") or
            not _HEX64.fullmatch(expected or "") or type(size) is not int or size <= 0):
        raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı güvenilmez veya bayat.")
    try:
        if any(part.is_symlink() for part in (db_path, *db_path.parents)):
            raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı yolu güvenli değil.")
        info = db_path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != size or _sha256_file(db_path) != expected:
            raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı sabitlemesi uyuşmuyor.")
        cache_root = db_path.parents[2]
        if not cache_root.is_dir() or cache_root.stat().st_uid != os.getuid():
            raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı önbelleği kullanılamıyor.")
    except OSError as exc:
        raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı kullanılamıyor.") from exc
    return cache_root, db_path, expected, retrieved_text


def _data_directory() -> Path:
    raw = os.environ.get("SNIPER_DATA_DIR", "")
    path = Path(raw)
    if not raw or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise OSVUnavailable("OSV-Scanner veri dizini kullanılamıyor.")
    if path.stat().st_uid != os.getuid():
        raise OSVUnavailable("OSV-Scanner veri dizini kullanılamıyor.")
    return path


def _snapshot_lockfile(root: Path, work: Path) -> tuple[Path, set[tuple[str, str]]]:
    # The shared validator uses O_NOFOLLOW/fstat, a 5 MB/2,000-entry cap,
    # and rejects linked/foreign-registry packages before this snapshot.
    lock, _manifest = _read_lockfile(root)
    packages = lock["packages"]
    if len(packages) <= 1 or len(packages) > MAX_PACKAGES:
        raise ValueError("Kök npm kilit dosyasında sınırlı bir paket kümesi yok.")
    expected: set[tuple[str, str]] = set()
    for key, entry in packages.items():
        if not key:
            continue
        resolved = entry.get("resolved")
        version = entry.get("version")
        if (not isinstance(resolved, str) or not resolved.startswith("https://registry.npmjs.org/") or
                not isinstance(version, str) or not version or any(ord(ch) < 33 for ch in version)):
            raise ValueError("Her paketin olağan resmi kayıt defteri sürümü ve çözümlemesi olmalı.")
        name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
        if not isinstance(name, str) or not name or len(name) > 214:
            raise ValueError("Kök npm kilit dosyası geçersiz bir paket adı içeriyor.")
        expected.add((name, version))
    if len(expected) != len(packages) - 1:
        raise ValueError("Yinelenen paket kimlikleri tam kapsam sağlayamaz.")
    snapshot = work / "package-lock.json"
    snapshot.write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    snapshot.chmod(0o600)
    return snapshot, expected


def _summarize_report(raw: bytes, expected: set[tuple[str, str]], exit_code: int,
                      db_sha256: str, retrieved_utc: str, snapshot: Path) -> dict[str, Any]:
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OSVExecutionError("OSV-Scanner geçersiz JSON döndürdü.") from exc
    if not isinstance(report, dict) or report.get("errors"):
        raise OSVExecutionError("OSV-Scanner eksik bir rapor döndürdü.")
    results = report.get("results")
    if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict):
        raise OSVExecutionError("OSV-Scanner eksik bir rapor döndürdü.")
    result = results[0]
    if result.get("source") != {"path": str(snapshot), "type": "lockfile"}:
        raise OSVExecutionError("OSV-Scanner kaynak kimliği uyuşmuyor.")
    packages = result.get("packages")
    if not isinstance(packages, list) or len(packages) != len(expected):
        raise OSVExecutionError("OSV-Scanner paket kapsamı eksik.")
    observed: set[tuple[str, str]] = set()
    affected = groups_total = 0
    for item in packages:
        if not isinstance(item, dict) or not isinstance(item.get("package"), dict):
            raise OSVExecutionError("OSV-Scanner geçersiz bir paket döndürdü.")
        package = item["package"]
        name, version = package.get("name"), package.get("version")
        if package.get("ecosystem") != "npm" or not isinstance(name, str) or not isinstance(version, str):
            raise OSVExecutionError("OSV-Scanner geçersiz bir paket döndürdü.")
        if package.get("purl") != f"pkg:npm/{name}@{version}?source=PUBLIC_REGISTRY":
            raise OSVExecutionError("OSV-Scanner paket kapsamı eksik.")
        observed.add((name, version))
        groups = item.get("groups", [])
        if not isinstance(groups, list):
            raise OSVExecutionError("OSV-Scanner geçersiz bulgular döndürdü.")
        for group in groups:
            if (not isinstance(group, dict) or not isinstance(group.get("ids"), list) or not group["ids"] or
                    not all(isinstance(value, str) and value for value in group["ids"])):
                raise OSVExecutionError("OSV-Scanner geçersiz bulgular döndürdü.")
        affected += bool(groups)
        groups_total += len(groups)
    if observed != expected or (groups_total == 0 and exit_code != 0) or (groups_total > 0 and exit_code != 1):
        raise OSVExecutionError("OSV-Scanner paket kapsamı veya çıkış durumu kilit dosyasıyla uyuşmuyor.")
    return {
        "format": "osv-scanner-json",
        "profile": "local-npm-lock-osv-offline-v1",
        "coverage": "public-registry-lockfile",
        "package_count": len(packages),
        "affected_package_count": affected,
        "vulnerability_group_count": groups_total,
        "offline_db_sha256": db_sha256,
        "offline_db_retrieved_utc": retrieved_utc,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _stage_db(db_path: Path, expected_sha256: str, work: Path) -> Path:
    if shutil.disk_usage(work).free < db_path.stat().st_size + 100_000_000:
        raise OSVUnavailable("OSV-Scanner geçici alanı yetersiz.")
    cache_root = work / "db-cache"
    target = cache_root / "osv-scalibr" / "npm" / "all.zip"
    target.parent.mkdir(parents=True)
    try:
        shutil.copyfile(db_path, target)
        target.chmod(0o600)
        if _sha256_file(target) != expected_sha256 or _sha256_file(db_path) != expected_sha256:
            raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı hazırlama sırasında değişti.")
    except OSError as exc:
        raise OSVUnavailable("OSV-Scanner çevrimdışı veritabanı hazırlanamadı.") from exc
    return cache_root


def _quarantine(data_dir: Path) -> None:
    marker = data_dir / "osv-scanner-quarantine"
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return
    except OSError as exc:
        raise OSVUnavailable("OSV-Scanner temizliği doğrulanamadı ve karantina kaydedilemedi.") from exc
    with os.fdopen(fd, "w") as stream:
        stream.write("OSV process cleanup unverified; inspect process state before clearing this marker.\n")


def _scanner_env(work: Path, cache_root: Path) -> dict[str, str]:
    # Exclude proxy/LD_*/user environment and keep scanner cache inside the
    # service-writable scratch tree. Seccomp, not environment, enforces egress.
    return {"HOME": str(work), "TMPDIR": str(work), "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache_root)}


def _run_bounded(cmd: list[str], work: Path, cache_root: Path, *, timeout_seconds: float = 30) -> tuple[int, bytes]:
    try:
        process = subprocess.Popen(cmd, cwd=work, env=_scanner_env(work, cache_root),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, close_fds=True,
                                   start_new_session=True)
    except OSError as exc:
        raise OSVExecutionError("OSV-Scanner çalıştırması başarısız oldu.") from exc
    deadline = time.monotonic() + timeout_seconds
    raw = bytearray()
    try:
        assert process.stdout is not None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSVExecutionError("OSV-Scanner çalıştırması zaman aşımına uğradı.")
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if not ready:
                raise OSVExecutionError("OSV-Scanner çalıştırması zaman aşımına uğradı.")
            chunk = os.read(process.stdout.fileno(), min(65536, MAX_REPORT_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_REPORT_BYTES:
                raise OSVExecutionError("OSV-Scanner raporu çok büyük.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSVExecutionError("OSV-Scanner çalıştırması zaman aşımına uğradı.")
        code = process.wait(timeout=remaining)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise OSVExecutionError("OSV-Scanner süreç temizliği doğrulanamadı.")
        return code, bytes(raw)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OSVExecutionError("OSV-Scanner çalıştırması başarısız oldu.") from exc
    finally:
        # Kill the whole scanner process group, including descendants, even
        # if the immediate process already exited. The seccomp filter is
        # inherited, but a lingering child must never outlive the request.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        if process.stdout is not None:
            process.stdout.close()


def run_local_osv_scanner(project_path: str) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    data_dir = _data_directory()
    lock_path = data_dir / "osv-scanner.lock"
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            os.close(lock_fd)
            raise OSVUnavailable("OSV-Scanner kilidi kullanılamıyor.")
    except OSError as exc:
        raise OSVUnavailable("OSV-Scanner kilidi kullanılamıyor.") from exc
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise OSVBusy("Başka bir OSV-Scanner çalıştırması sürüyor.") from exc
        quarantine = data_dir / "osv-scanner-quarantine"
        if quarantine.exists() or quarantine.is_symlink():
            raise OSVUnavailable("OSV-Scanner doğrulanamayan temizlik sonrası karantinada.")
        scanner = _trusted_binary()
        launcher = _trusted_launcher()
        _source_cache, db_path, db_sha256, retrieved_utc = _trusted_db()
        with tempfile.TemporaryDirectory(prefix="sniper_osv_", dir=data_dir) as scratch:
            work = Path(scratch)
            snapshot, expected = _snapshot_lockfile(root, work)
            cache_root = _stage_db(db_path, db_sha256, work)
            cmd = [
                sys.executable, "-I", "-S", str(launcher), str(scanner),
                "scan", "source", "--offline", "--no-resolve", "--format", "json",
                "--all-packages", "--lockfile", str(snapshot),
            ]
            try:
                return_code, raw = _run_bounded(cmd, work, cache_root)
            except OSVExecutionError:
                # Any timeout, oversized output, or uncertain process-group
                # cleanup stays quarantined until manual inspection.
                _quarantine(data_dir)
                raise
            if return_code not in (0, 1):
                # A denied process-creation attempt or other abnormal scanner
                # exit must not leave the active profile reusable unchecked.
                _quarantine(data_dir)
                raise OSVExecutionError("OSV-Scanner çalıştırması başarısız oldu.")
            if _sha256_file(db_path) != db_sha256 or _sha256_file(cache_root / "osv-scalibr" / "npm" / "all.zip") != db_sha256:
                raise OSVExecutionError("OSV-Scanner çevrimdışı veritabanı analiz sırasında değişti.")
            return _summarize_report(raw, expected, return_code, db_sha256, retrieved_utc, snapshot)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
