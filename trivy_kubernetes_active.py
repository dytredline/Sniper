"""Run a bounded local Kubernetes manifest check with pinned Trivy rules."""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import tempfile
from pathlib import Path

from project_analyzer import validate_project_path
from tool_report_trivy import parse_trivy_native_json_summary
from trivy_config_active import (
    TrivyConfigExecutionError,
    _scan_lock,
    _trusted_binary,
)


MAX_MANIFEST_BYTES = 1_000_000
MAX_REPORT_BYTES = 2_000_000
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,123}\.ya?ml\Z")


def _read_manifest(project_root: Path, manifest_name: str) -> bytes:
    if not isinstance(manifest_name, str) or not _NAME.fullmatch(manifest_name) or ".." in manifest_name:
        raise ValueError("manifest_name kök düzeyde bir YAML dosya adı olmalı.")
    path = project_root / manifest_name
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("manifest_name normal bir yerel dosyayı göstermeli.") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_MANIFEST_BYTES:
            raise ValueError("Manifest en fazla 1 MB büyüklüğünde, boş olmayan normal bir dosya olmalı.")
        data = bytearray()
        while len(data) <= MAX_MANIFEST_BYTES:
            chunk = os.read(fd, min(65536, MAX_MANIFEST_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) != before.st_size or (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("Manifest hazırlama sırasında değişti.")
        return bytes(data)
    finally:
        os.close(fd)


def run_local_trivy_kubernetes(project_path: str, manifest_name: str) -> dict:
    """Scan one explicit root-level YAML file; return only aggregate findings."""
    project_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    source = _read_manifest(project_root, manifest_name)
    binary = _trusted_binary()
    lock = _scan_lock()
    try:
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_kubernetes_") as directory:
            scratch = Path(directory)
            staged = scratch / "input"
            staged.mkdir()
            (staged / "manifest.yaml").write_bytes(source)
            report = scratch / "report.json"
            environment = {
                "HOME": str(scratch),
                "XDG_CACHE_HOME": str(scratch / "cache"),
                "TMPDIR": str(scratch),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            command = [
                str(binary), "config", "--misconfig-scanners", "kubernetes",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "30s", str(staged),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                )
                try:
                    exit_code = process.wait(timeout=40)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    raise TrivyConfigExecutionError("Trivy Kubernetes taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise TrivyConfigExecutionError("Trivy Kubernetes taraması başarısız oldu.") from exc
            if exit_code != 0 or report.is_symlink() or not report.is_file():
                raise TrivyConfigExecutionError("Trivy Kubernetes taraması başarısız oldu.")
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise TrivyConfigExecutionError("Trivy Kubernetes raporu boyut sınırını aştı.")
            try:
                document = json.loads(report.read_text(encoding="utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("geçersiz rapor")
                rows = document.get("Results", [])
                if not isinstance(rows, list) or len(rows) != 1:
                    raise ValueError("beklenmeyen sonuç sayısı")
                row = rows[0]
                if not isinstance(row, dict) or row.get("Target") != "manifest.yaml":
                    raise ValueError("beklenmeyen hedef")
                if row.get("Class") != "config" or row.get("Type") != "kubernetes":
                    raise ValueError("beklenmeyen tarayıcı")
                if any(row.get(key) for key in ("Vulnerabilities", "Secrets", "Licenses")):
                    raise ValueError("beklenmeyen bulgu türü")
                findings = row.get("Misconfigurations", [])
                counters = row.get("MisconfSummary")
                if not isinstance(counters, dict):
                    raise ValueError("yanlış yapılandırma özeti eksik")
                count = counters.get("Failures")
                if not isinstance(findings, list) or type(count) is not int or count != len(findings):
                    raise ValueError("yanlış yapılandırma sayıları tutarsız")
                summary = parse_trivy_native_json_summary(document)
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise TrivyConfigExecutionError("Trivy Kubernetes raporu doğrulamadan geçemedi.") from exc
            summary["profile"] = "local-kubernetes-manifest-config-v1"
            return summary
    finally:
        os.close(lock)


def run_local_trivy_kubernetes_batch(project_path: str, manifest_names: list[str]) -> dict:
    """Scan up to 8 root-level YAML files in one Trivy invocation; return aggregate findings."""
    if not isinstance(manifest_names, list) or not (1 <= len(manifest_names) <= 8):
        raise ValueError("manifest_names en fazla 8 öğelik boş olmayan bir liste olmalı.")
    if len(set(manifest_names)) != len(manifest_names):
        raise ValueError("manifest_names benzersiz öğeler içermeli.")
    for name in manifest_names:
        if not isinstance(name, str):
            raise ValueError("Her manifest_name bir metin olmalı.")
        if not _NAME.fullmatch(name) or ".." in name:
            raise ValueError("Her manifest_name kök düzeyde bir YAML dosya adı olmalı.")

    project_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))

    staged_total = 0
    staged_files = []
    for name in manifest_names:
        source = _read_manifest(project_root, name)
        staged_total += len(source)
        if staged_total > 8_000_000:
            raise ValueError("Hazırlanan toplam manifest boyutu 8 MB'ı aştı.")
        staged_files.append((name, source))

    binary = _trusted_binary()
    lock = _scan_lock()
    try:
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_kubernetes_batch_") as directory:
            scratch = Path(directory)
            staged_dir = scratch / "input"
            staged_dir.mkdir()
            for name, source in staged_files:
                (staged_dir / name).write_bytes(source)
            report = scratch / "report.json"
            environment = {
                "HOME": str(scratch),
                "XDG_CACHE_HOME": str(scratch / "cache"),
                "TMPDIR": str(scratch),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            command = [
                str(binary), "config", "--misconfig-scanners", "kubernetes",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "30s", str(staged_dir),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                )
                try:
                    exit_code = process.wait(timeout=40)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    raise TrivyConfigExecutionError("Trivy Kubernetes toplu taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise TrivyConfigExecutionError("Trivy Kubernetes toplu taraması başarısız oldu.") from exc
            if exit_code != 0 or report.is_symlink() or not report.is_file():
                raise TrivyConfigExecutionError("Trivy Kubernetes toplu taraması başarısız oldu.")
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise TrivyConfigExecutionError("Trivy Kubernetes toplu raporu boyut sınırını aştı.")
            try:
                document = json.loads(report.read_text(encoding="utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("geçersiz rapor")
                results = document.get("Results", [])
                if not isinstance(results, list):
                    raise ValueError("beklenmeyen sonuçlar")
                if len(results) != len(manifest_names):
                    raise ValueError("beklenmeyen sonuç sayısı")
                result_map = {}
                for row in results:
                    if not isinstance(row, dict):
                        raise ValueError("geçersiz sonuç satırı")
                    target = row.get("Target")
                    if not isinstance(target, str) or target not in manifest_names:
                        raise ValueError("beklenmeyen hedef")
                    if row.get("Class") != "config" or row.get("Type") != "kubernetes":
                        raise ValueError("beklenmeyen tarayıcı")
                    if any(row.get(key) for key in ("Vulnerabilities", "Secrets", "Licenses")):
                        raise ValueError("beklenmeyen bulgu türü")
                    findings = row.get("Misconfigurations", [])
                    counters = row.get("MisconfSummary")
                    if not isinstance(counters, dict):
                        raise ValueError("yanlış yapılandırma özeti eksik")
                    count = counters.get("Failures")
                    if not isinstance(findings, list) or type(count) is not int or count != len(findings):
                        raise ValueError("yanlış yapılandırma sayıları tutarsız")
                    result_map[target] = row
                for name in manifest_names:
                    if name not in result_map:
                        raise ValueError("hazırlanan manifest için sonuç eksik")
                summary = parse_trivy_native_json_summary(document)
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise TrivyConfigExecutionError("Trivy Kubernetes toplu raporu doğrulamadan geçemedi.") from exc
            summary["profile"] = "local-kubernetes-manifest-config-batch-v1"
            return summary
    finally:
        os.close(lock)
