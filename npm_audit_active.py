"""Explicitly consented npm audit of one local package-lock via the official registry."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from process_group_runner import run_in_process_group
from project_analyzer import validate_project_path
from project_tree import ProjectTree, ProjectTreeError
from tool_report_npm_audit import parse_npm_audit_v2_summary
from tool_pins import open_pinned
from verified_exec import VerificationError


class NpmAuditUnavailable(Exception):
    pass


class NpmAuditBusy(Exception):
    pass


class NpmAuditExecutionError(Exception):
    pass


MAX_LOCK_BYTES = 5_000_000
MAX_REPORT_BYTES = 2_000_000
MAX_PACKAGES = 2_000
REGISTRY = "https://registry.npmjs.org"
_SPEC = re.compile(r"^[0-9A-Za-z.*^~<>=| \-]+$")
_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _pinned_runtime(path_key: str, sha_key: str, *, executable: bool) -> Path:
    raw = os.environ.get(path_key, "")
    expected = os.environ.get(sha_key, "")
    path = Path(raw)
    if not raw or not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise NpmAuditUnavailable("npm audit çalışma zamanı yapılandırılmamış.")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise NpmAuditUnavailable("npm audit çalışma zamanı sabitlemesi yapılandırılmamış.")
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or (executable and not os.access(path, os.X_OK)):
            raise NpmAuditUnavailable("npm audit çalışma zamanı kullanılamıyor.")
        if _sha256_file(path) != expected:
            raise NpmAuditUnavailable("npm audit çalışma zamanı sabitlemesi uyuşmuyor.")
    except OSError as exc:
        raise NpmAuditUnavailable("npm audit çalışma zamanı kullanılamıyor.") from exc
    return path


def _read_lockfile(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        with ProjectTree(root) as tree:
            walker = tree.walk(reject_unsafe=False)
            try:
                entry = next(walker)
            finally:
                walker.close()
            source = next((item for item in entry.files if item.path.as_posix() == "package-lock.json"), None)
            if source is None:
                raise ValueError("Kök package-lock.json eksik veya anlık görüntü sırasında değişti.")
            if source.size > MAX_LOCK_BYTES:
                raise ValueError("Kök package-lock.json en fazla 5 MB büyüklüğünde normal bir dosya olmalı.")
            raw = tree.read_bytes(source, MAX_LOCK_BYTES, allow_empty=True)
    except ProjectTreeError as exc:
        raise ValueError("Kök package-lock.json güvenli biçimde açılamıyor.") from exc
    try:
        lock = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("package-lock.json geçerli JSON içermeli.") from exc
    if not isinstance(lock, dict) or type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] not in (2, 3):
        raise ValueError("Yalnız npm package-lock sürüm 2 veya 3 desteklenir.")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or "" not in packages or not isinstance(packages[""], dict):
        raise ValueError("package-lock.json bir kök paket içermeli.")
    if len(packages) > MAX_PACKAGES:
        raise ValueError("package-lock.json çok fazla paket girdisi içeriyor.")
    for key, entry in packages.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            raise ValueError("package-lock.json geçersiz bir paket girdisi içeriyor.")
        if key and (not key.startswith("node_modules/") or ".." in key or "\\" in key):
            raise ValueError("Yerel veya çalışma alanı paket girdileri desteklenmiyor.")
        if entry.get("link") is True:
            raise ValueError("Bağlantılı paketler desteklenmiyor.")
        resolved = entry.get("resolved")
        if resolved is not None and (
            not isinstance(resolved, str) or not resolved.startswith(REGISTRY + "/")
        ):
            raise ValueError("Yalnız resmi npm kayıt defteri paketleri desteklenir.")
    # v2 also carries a legacy dependency tree. Reject alternate download
    # origins there as well; npm audit must never be pointed at arbitrary hosts.
    pending = [lock.get("dependencies", {})]
    seen = 0
    while pending:
        tree = pending.pop()
        if not isinstance(tree, dict):
            raise ValueError("package-lock.json geçersiz eski bağımlılıklar içeriyor.")
        for entry in tree.values():
            seen += 1
            if seen > MAX_PACKAGES or not isinstance(entry, dict) or entry.get("link") is True:
                raise ValueError("package-lock.json geçersiz eski bağımlılıklar içeriyor.")
            resolved = entry.get("resolved")
            if resolved is not None and (
                not isinstance(resolved, str) or not resolved.startswith(REGISTRY + "/")
            ):
                raise ValueError("Yalnız resmi npm kayıt defteri paketleri desteklenir.")
            version = entry.get("version")
            if version is not None and (not isinstance(version, str) or not _SPEC.fullmatch(version)):
                raise ValueError("Yalnız olağan npm kayıt defteri sürümleri desteklenir.")
            pending.append(entry.get("dependencies", {}))
    root_entry = packages[""]
    manifest: dict[str, Any] = {"name": "sniper-audit-snapshot", "version": "1.0.0", "private": True}
    for section in _SECTIONS:
        values = root_entry.get(section, {})
        if not isinstance(values, dict) or len(values) > MAX_PACKAGES:
            raise ValueError("package-lock.json geçersiz kök bağımlılıklar içeriyor.")
        checked = {}
        for name, spec in values.items():
            if (
                not isinstance(name, str) or not name or len(name) > 214 or
                any(ord(c) < 33 or ord(c) == 127 for c in name) or
                not isinstance(spec, str) or len(spec) > 512 or not _SPEC.fullmatch(spec)
            ):
                raise ValueError("Yalnız olağan npm kayıt defteri bağımlılık tanımları desteklenir.")
            checked[name] = spec
        if checked:
            manifest[section] = checked
    if not any(section in manifest for section in _SECTIONS):
        raise ValueError("package-lock.json kök bağımlılık içermiyor.")
    lock["name"] = manifest["name"]
    lock["version"] = manifest["version"]
    root_entry["name"] = manifest["name"]
    root_entry["version"] = manifest["version"]
    return lock, manifest


def run_local_npm_audit_local(project_path: str) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    data_dir_raw = os.environ.get("SNIPER_DATA_DIR", "")
    data_dir = Path(data_dir_raw)
    if not data_dir_raw or not data_dir.is_absolute() or data_dir.is_symlink() or not data_dir.is_dir():
        raise NpmAuditUnavailable("npm audit veri dizini kullanılamıyor.")
    lock_file = data_dir / "npm-audit.lock"
    try:
        lock_fd = os.open(lock_file, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            os.close(lock_fd)
            raise NpmAuditUnavailable("npm audit kilidi kullanılamıyor.")
    except OSError as exc:
        raise NpmAuditUnavailable("npm audit kilidi kullanılamıyor.") from exc
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NpmAuditBusy("Başka bir npm audit çalışıyor.") from exc
        lock, manifest = _read_lockfile(root)
        try:
            node = open_pinned("node")
        except VerificationError as exc:
            raise NpmAuditUnavailable(f"npm audit Node çalışma zamanı doğrulanamadı ({exc.reason}).") from exc
        npm_cli = _pinned_runtime("SNIPER_NPM_CLI", "SNIPER_NPM_CLI_SHA256", executable=False)
        with node, tempfile.TemporaryDirectory(prefix="sniper_npm_audit_") as scratch:
            work = Path(scratch)
            (work / "package-lock.json").write_text(json.dumps(lock, separators=(",", ":")))
            (work / "package.json").write_text(json.dumps(manifest, separators=(",", ":")))
            cache = work / "cache"
            cache.mkdir()
            (work / "user.npmrc").write_text("")
            (work / "global.npmrc").write_text("")
            report = work / "audit.json"
            env = {
                "PATH": str(Path(node.path).parent) + ":/usr/bin:/bin",
                "HOME": str(work),
                "NPM_CONFIG_CACHE": str(cache),
                "NPM_CONFIG_USERCONFIG": str(work / "user.npmrc"),
                "NPM_CONFIG_GLOBALCONFIG": str(work / "global.npmrc"),
                "NPM_CONFIG_REGISTRY": REGISTRY,
                "NPM_CONFIG_UPDATE_NOTIFIER": "false",
                "NPM_CONFIG_FUND": "false",
                "CI": "true",
                "LANG": "C.UTF-8",
            }
            cmd = [
                node.argv0, "--jitless", str(npm_cli), "audit", "--json", "--package-lock-only",
                "--ignore-scripts", "--audit-level=none",
                "--registry=" + REGISTRY, "--fetch-retries=0",
                "--fetch-timeout=30000", "--no-update-notifier", "--no-fund",
            ]
            try:
                with report.open("wb") as output:
                    completed = run_in_process_group(cmd, timeout=90, check=False, **node.popen_kwargs(
                        cwd=work, env=env, stdout=output, stderr=subprocess.DEVNULL, close_fds=True,
                    ))
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise NpmAuditExecutionError("npm audit çalıştırması başarısız oldu.") from exc
            if completed.returncode != 0 or report.stat().st_size > MAX_REPORT_BYTES:
                raise NpmAuditExecutionError("npm audit çalıştırması başarısız oldu.")
            try:
                audit = json.loads(report.read_text(encoding="utf-8"))
                if not isinstance(audit, dict) or type(audit.get("auditReportVersion")) is not int:
                    raise ValueError("Geçersiz npm audit raporu")
                summary = parse_npm_audit_v2_summary(audit)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise NpmAuditExecutionError("npm audit geçersiz bir rapor döndürdü.") from exc
            summary["profile"] = "local-npm-audit-v1"
            return summary
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
