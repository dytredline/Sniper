"""One-click local/portable tool runtime auto-discovery and zero-setup bundle manifest.

Scans trusted local and portable bundle directories for installed security tool
binaries, rulepacks, template catalogs, and offline databases; verifies regular
non-symlink files and SHA-256 digests; and binds SNIPER_* environment variables
in-memory without exposing raw local filesystem paths in HTTP responses.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
from pathlib import Path, PurePosixPath
from typing import Any

from community_tool_installer import (
    INSTALL_MANIFEST,
    InstallError,
    current_platform_key,
    load_lock,
)
from tool_pins import PINS
from tool_runtime_readiness import runtime_readiness_payload


# Keşif ve ortam uygulaması tek seferde bir iş parçacığında yapılır (istek iş parçacıkları
# ile başlangıç keşfi aynı anda os.environ'u değiştirmesin).
_BIND_LOCK = threading.Lock()
PINS_FILE = "runtime-bindings-pins.json"
PINS_FORMAT = "sniper-runtime-bindings-pins-v1"
_MAX_PINS_BYTES = 64_000
_MAX_INSTALL_MANIFEST_BYTES = 1_000_000


def _pins_path() -> Path | None:
    data_dir = os.environ.get("SNIPER_DATA_DIR", "")
    if not data_dir:
        return None
    path = Path(data_dir)
    return path / PINS_FILE if _is_regular_dir(path) else None


def _load_pins(path: Path | None) -> dict[str, str] | None:
    """Onaylanmış bağlamaları oku (yalnız süreç sahibine ait, başkasınca yazılamaz normal dosya)."""
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            return None
        raw = os.read(fd, _MAX_PINS_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > _MAX_PINS_BYTES:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    bindings = data.get("bindings") if isinstance(data, dict) and data.get("format") == PINS_FORMAT else None
    if not isinstance(bindings, dict):
        return None
    return {
        str(k): str(v) for k, v in bindings.items()
        if isinstance(k, str) and k.startswith("SNIPER_") and isinstance(v, str) and len(v) <= 4096
    }


def _save_pins(path: Path | None, bindings: dict[str, str]) -> bool:
    if path is None:
        return False
    try:
        fd, tmp = tempfile.mkstemp(prefix=".pins-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"format": PINS_FORMAT, "bindings": bindings}, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    except OSError:
        return False


_ENV_LINE_RE = re.compile(r"^Environment=(?:([A-Za-z0-9_]+)=(.*)|\"([A-Za-z0-9_]+)=(.*)\")\Z")


def _is_regular_file(path: Path, *, executable: bool = False) -> bool:
    try:
        return (
            path.is_absolute()
            and not path.is_symlink()
            and path.is_file()
            and (not executable or os.access(path, os.X_OK))
        )
    except OSError:
        return False


def _is_regular_dir(path: Path) -> bool:
    try:
        return path.is_absolute() and not path.is_symlink() and path.is_dir()
    except OSError:
        return False


def _sha256_file(path: Path) -> str | None:
    if not _is_regular_file(path):
        return None
    try:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError:
        return None


def _first_valid_file(candidates: list[Path], *, executable: bool = False) -> Path | None:
    for candidate in candidates:
        if _is_regular_file(candidate, executable=executable):
            return candidate
    return None


def _first_valid_unrevoked_executable(
    candidates: list[Path], revoked_digests: frozenset[str]
) -> tuple[Path | None, str | None]:
    """İlk güvenli çalıştırılabilir ikiliyi ve özetini döndür; bilinen geri çekilmiş özetleri atla."""
    for candidate in candidates:
        if not _is_regular_file(candidate, executable=True):
            continue
        digest = _sha256_file(candidate)
        if digest is not None and digest not in revoked_digests:
            return candidate, digest
    return None, None


def _first_valid_dir(candidates: list[Path]) -> Path | None:
    for candidate in candidates:
        if _is_regular_dir(candidate):
            return candidate
    return None


def _safe_relative_path(value: Any) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts \
            or any(part in {"", ".", ".."} for part in relative.parts):
        return None
    return relative


def _load_secure_install_manifest(root: Path) -> dict[str, Any] | None:
    """Read an owner-controlled installer manifest without following a leaf symlink."""
    path = root / INSTALL_MANIFEST
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            return None
        raw = os.read(fd, _MAX_INSTALL_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if not raw or len(raw) > _MAX_INSTALL_MANIFEST_BYTES:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _trusted_runtime_member(root: Path, relative: PurePosixPath) -> Path | None:
    """Resolve a runtime member only when every existing component is non-symlink."""
    try:
        if root.resolve(strict=True) != root.absolute() or not _is_regular_dir(root):
            return None
    except OSError:
        return None
    current = root
    for part in relative.parts:
        current = current / part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return None
        except OSError:
            return None
    return current if _is_regular_file(current, executable=True) else None


def _verified_community_runtimes(
    app_dir: Path, roots: list[Path]
) -> dict[str, tuple[Path, str]]:
    """Bind installer-managed Community tools only when lock and manifest provenance agree."""
    lock_path = app_dir / "COMMUNITY-TOOLS.lock.json"
    lock_digest = _sha256_file(lock_path)
    if lock_digest is None:
        return {}
    try:
        lock = load_lock(lock_path)
        platform_key = current_platform_key()
    except InstallError:
        return {}
    selected = lock.get("profiles", {}).get("local")
    if not isinstance(selected, list) or any(not isinstance(item, str) for item in selected):
        return {}

    verified: dict[str, tuple[Path, str]] = {}
    for root in roots:
        if len(verified) == len(selected):
            break
        manifest = _load_secure_install_manifest(root)
        if manifest is None or manifest.get("schema") != lock.get("schema") \
                or manifest.get("lock_sha256") != lock_digest:
            continue
        records = manifest.get("tools")
        if not isinstance(records, dict):
            continue
        for tool_id in selected:
            if tool_id in verified:
                continue
            tool = lock.get("tools", {}).get(tool_id)
            record = records.get(tool_id)
            if not isinstance(tool, dict) or not isinstance(record, dict):
                continue
            artifact = tool.get("platforms", {}).get(platform_key)
            destination = _safe_relative_path(tool.get("destination"))
            binary_rel = _safe_relative_path(tool.get("binary"))
            if not isinstance(artifact, dict) or destination is None or binary_rel is None:
                continue
            installed_rel = destination / binary_rel
            if record.get("platform") != platform_key \
                    or record.get("version") != tool.get("version") \
                    or record.get("license") != tool.get("license") \
                    or record.get("artifact_sha256") != artifact.get("sha256") \
                    or record.get("binary") != str(installed_rel) \
                    or record.get("env_binary") != tool.get("env_binary") \
                    or record.get("env_sha256") != tool.get("env_sha256"):
                continue
            binary = _trusted_runtime_member(root, installed_rel)
            digest = _sha256_file(binary) if binary is not None else None
            if digest is None or digest != record.get("binary_sha256"):
                continue
            verified[tool_id] = (binary, digest)
    return verified


def _read_systemd_dropin_defaults(dropin_dir: Path) -> dict[str, str]:
    discovered: dict[str, str] = {}
    if not _is_regular_dir(dropin_dir):
        return discovered
    try:
        entries = sorted(dropin_dir.iterdir())
    except OSError:
        return discovered
    for entry in entries:
        if entry.suffix != ".conf" or not _is_regular_file(entry):
            continue
        try:
            text = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            match = _ENV_LINE_RE.match(line)
            if not match:
                continue
            key = match.group(1) or match.group(3)
            val = match.group(2) if match.group(1) else match.group(4)
            if key and val is not None and key.startswith("SNIPER_"):
                discovered[key] = val
    return discovered


def autodiscover_and_bind_runtimes(*, apply_env: bool = True, persist: bool = True,
                                   trust_disk: bool = False,
                                   include_readiness: bool = True) -> dict[str, Any]:
    """Yerel/taşınabilir araç çalışma zamanlarını keşfet, SHA-256 değerlerini hesapla, ortamı bağla.

    Güven modeli: diskten hesaplanan hash'ler yalnız açık onayla (``trust_disk=True``, ör.
    ``POST /api/tooling/autodiscover`` + ``confirm_bind``) veya hiç onaylı kayıt yokken ilk
    başlangıçta kabul edilir ve veri dizinine (``runtime-bindings-pins.json``, 0600) kaydedilir.
    Sonraki başlangıçlarda kayıtlı değerler kullanılır; diskteki değer farklıysa bağlama
    uygulanmaz ve ``pin_mismatches`` içinde raporlanır (sessiz yeniden sabitleme yok).
    Operatörün verdiği değerler (systemd drop-in, kabuk ortamı) hiçbir zaman ezilmez.
    """
    with _BIND_LOCK:
        return _autodiscover_locked(
            apply_env=apply_env,
            persist=persist,
            trust_disk=trust_disk,
            include_readiness=include_readiness,
        )


def _discover_bindings() -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Diskteki araçları bul ve bağlanacak değerleri (yol, SHA-256) hesapla; ortama dokunmaz."""
    app_dir = Path(__file__).resolve().parent
    sniper_root = app_dir.parent
    home = Path.home().resolve()

    portable_roots = [
        app_dir / "runtimes",
        sniper_root / "runtimes",
        home / ".local" / "state" / "sniper-tool-runtimes",
    ]
    env_portable = os.environ.get("SNIPER_PORTABLE_RUNTIMES_DIR", "").strip()
    if env_portable:
        portable_roots.insert(0, Path(env_portable))

    community_runtimes = _verified_community_runtimes(app_dir, portable_roots)

    dropin_defaults = _read_systemd_dropin_defaults(
        home / ".config" / "systemd" / "user" / "sniper.service.d"
    )

    bindings: dict[str, str] = {}
    tool_results: list[dict[str, Any]] = []

    # 1. Opengrep / Semgrep
    opengrep_runtime = community_runtimes.get("opengrep")
    opengrep_bin = opengrep_runtime[0] if opengrep_runtime else None
    opengrep_sha = opengrep_runtime[1] if opengrep_runtime else None
    if opengrep_bin and opengrep_sha:
        bindings["SNIPER_OPENGREP_BINARY"] = str(opengrep_bin)
        bindings["SNIPER_OPENGREP_SHA256"] = opengrep_sha
    tool_results.append({
        "id": "semgrep",
        "bound": bool(opengrep_bin and opengrep_sha),
        "mode": "locked_community_opengrep",
    })

    # 2. Trivy binary; the offline vulnerability DB is an optional, separately pinned input.
    trivy_runtime = community_runtimes.get("trivy")
    trivy_bin = trivy_runtime[0] if trivy_runtime else None
    trivy_cache = _first_valid_dir(
        ([Path(dropin_defaults["SNIPER_TRIVY_VULN_CACHE_DIR"])] if "SNIPER_TRIVY_VULN_CACHE_DIR" in dropin_defaults else [])
        + [r / "trivy-db" / "cache" for r in portable_roots]
        + [r / "trivy-vulnerability-db-20261012T1218Z" / "cache" for r in portable_roots]
        + [r / "trivy-vulnerability-db-20261011" / "cache" for r in portable_roots]
    )
    trivy_db_sha: str | None = None
    if trivy_cache:
        trivy_db_sha = _sha256_file(trivy_cache / "db" / "trivy.db")
    if trivy_bin:
        bindings["SNIPER_TRIVY_BINARY"] = str(trivy_bin)
        trivy_sha = trivy_runtime[1]
        if trivy_sha:
            bindings["SNIPER_TRIVY_BINARY_SHA256"] = trivy_sha
            bindings["SNIPER_TRIVY_SHA256"] = trivy_sha
    if trivy_cache and trivy_db_sha:
        bindings["SNIPER_TRIVY_VULN_CACHE_DIR"] = str(trivy_cache)
        bindings["SNIPER_TRIVY_VULN_DB_SHA256"] = trivy_db_sha
    tool_results.append({
        "id": "trivy",
        "bound": bool(trivy_bin),
        "mode": "local_binary_with_optional_offline_db",
    })

    # 2b. Syft + Grype binaries; Grype analysis is enabled only with the exact
    # separately pinned offline database snapshot accepted by the product.
    syft_runtime = community_runtimes.get("syft")
    grype_runtime = community_runtimes.get("grype")
    syft_bin = syft_runtime[0] if syft_runtime else None
    grype_bin = grype_runtime[0] if grype_runtime else None
    if syft_bin and syft_runtime:
        bindings["SNIPER_SYFT_BINARY"] = str(syft_bin)
        bindings["SNIPER_SYFT_BINARY_SHA256"] = syft_runtime[1]
    if grype_bin and grype_runtime:
        bindings["SNIPER_GRYPE_BINARY"] = str(grype_bin)
        bindings["SNIPER_GRYPE_BINARY_SHA256"] = grype_runtime[1]
    # The vulnerability DB is several GiB.  Startup discovery must never hash it:
    # an explicit operator binding is verified once, in-process, by the active
    # Syft/Grype readiness gate immediately before use.
    tool_results.append({
        "id": "syft-grype",
        "bound": bool(syft_bin and grype_bin),
        "database_bound": False,
        "database_binding": "explicit_runtime_configuration_required",
        "mode": "two_locked_binaries_with_optional_offline_db",
    })

    # 3. Gitleaks
    gitleaks_runtime = community_runtimes.get("gitleaks")
    gitleaks_bin = gitleaks_runtime[0] if gitleaks_runtime else None
    if gitleaks_bin:
        bindings["SNIPER_GITLEAKS_BINARY"] = str(gitleaks_bin)
        gitleaks_sha = gitleaks_runtime[1]
        if gitleaks_sha:
            bindings["SNIPER_GITLEAKS_SHA256"] = gitleaks_sha
    tool_results.append({
        "id": "gitleaks",
        "bound": bool(gitleaks_bin),
        "mode": "single_static_binary",
    })

    # 4. TruffleHog
    trufflehog_runtime = community_runtimes.get("trufflehog")
    trufflehog_bin = trufflehog_runtime[0] if trufflehog_runtime else None
    if trufflehog_bin:
        bindings["SNIPER_TRUFFLEHOG_BINARY"] = str(trufflehog_bin)
        trufflehog_sha = trufflehog_runtime[1]
        if trufflehog_sha:
            bindings["SNIPER_TRUFFLEHOG_SHA256"] = trufflehog_sha
    tool_results.append({
        "id": "trufflehog",
        "bound": bool(trufflehog_bin),
        "mode": "single_static_binary",
    })

    # 5. testssl.sh
    testssl_bin = _first_valid_file(
        ([Path(dropin_defaults["SNIPER_TESTSSL_BINARY"])] if "SNIPER_TESTSSL_BINARY" in dropin_defaults else [])
        + [r / "testssl" / "testssl.sh" for r in portable_roots]
        + [r / "testssl-3.2.4" / "testssl.sh" for r in portable_roots],
        executable=True,
    )
    testssl_sha = _sha256_file(testssl_bin) if testssl_bin else None
    if testssl_bin and testssl_sha:
        bindings["SNIPER_TESTSSL_BINARY"] = str(testssl_bin)
        bindings["SNIPER_TESTSSL_SHA256"] = testssl_sha
    tool_results.append({
        "id": "testssl",
        "bound": bool(testssl_bin and testssl_sha),
        "mode": "portable_script_bundle",
    })

    # 6. Nuclei
    nuclei_runtime = community_runtimes.get("nuclei")
    nuclei_bin = nuclei_runtime[0] if nuclei_runtime else None
    nuclei_sha = nuclei_runtime[1] if nuclei_runtime else None
    if nuclei_bin and nuclei_sha:
        bindings["SNIPER_NUCLEI_BINARY"] = str(nuclei_bin)
        bindings["SNIPER_NUCLEI_SHA256"] = nuclei_sha
    tool_results.append({
        "id": "nuclei",
        "bound": bool(nuclei_bin and nuclei_sha),
        "mode": "single_static_binary_and_templates",
    })

    # 7. Nmap
    nmap_bin = _first_valid_file(
        ([Path(dropin_defaults["SNIPER_NMAP_BINARY"])] if "SNIPER_NMAP_BINARY" in dropin_defaults else [])
        + [r / "nmap" / "bin" / "nmap" for r in portable_roots]
        + [sniper_root / "tools" / "nmap-7.94" / "bin" / "nmap", Path("/usr/bin/nmap"), Path("/usr/local/bin/nmap")],
        executable=True,
    )
    if nmap_bin:
        bindings["SNIPER_NMAP_BINARY"] = str(nmap_bin)
    tool_results.append({
        "id": "nmap",
        "bound": bool(nmap_bin),
        "mode": "local_or_bundled_binary",
    })

    # 8. OpenSSL Loopback
    openssl_bin = Path("/usr/bin/openssl")
    openssl_bin_sha = _sha256_file(openssl_bin) if _is_regular_file(openssl_bin, executable=True) else None
    data_dir_raw = os.environ.get("SNIPER_DATA_DIR", str(sniper_root / "data"))
    ca_file = Path(data_dir_raw) / "openssl-trust-ca.pem"
    ca_sha = _sha256_file(ca_file) or dropin_defaults.get("SNIPER_OPENSSL_CA_SHA256")
    if openssl_bin_sha:
        bindings["SNIPER_OPENSSL_BINARY_SHA256"] = openssl_bin_sha
    if ca_sha:
        bindings["SNIPER_OPENSSL_CA_SHA256"] = ca_sha
    tool_results.append({
        "id": "openssl",
        "bound": bool(openssl_bin_sha and ca_sha),
        "mode": "system_binary_and_trust_ca",
    })

    # 9. Node + npm audit
    node_bin, node_sha = _first_valid_unrevoked_executable(
        ([Path(dropin_defaults["SNIPER_NODE_BINARY"])] if "SNIPER_NODE_BINARY" in dropin_defaults else [])
        + [r / "node" / "bin" / "node" for r in portable_roots]
        + [home / ".local" / "opt" / "node-v22.23.4-linux-arm64" / "bin" / "node", Path("/usr/bin/node")],
        PINS["node"].revoked_digests,
    )
    matching_npm = node_bin.parent.parent / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js" if node_bin else None
    npm_cli = _first_valid_file(
        ([matching_npm] if matching_npm is not None else [])
        + ([Path(dropin_defaults["SNIPER_NPM_CLI"])] if "SNIPER_NPM_CLI" in dropin_defaults else [])
        + [r / "node" / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js" for r in portable_roots]
        + [home / ".local" / "opt" / "node-v22.23.4-linux-arm64" / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"],
        executable=False,
    )
    npm_sha = _sha256_file(npm_cli) if npm_cli else None
    if node_bin and npm_cli and node_sha and npm_sha:
        bindings["SNIPER_NODE_BINARY"] = str(node_bin)
        bindings["SNIPER_NODE_SHA256"] = node_sha
        bindings["SNIPER_NPM_CLI"] = str(npm_cli)
        bindings["SNIPER_NPM_CLI_SHA256"] = npm_sha
    tool_results.append({
        "id": "npm-audit",
        "bound": bool(node_bin and npm_cli and node_sha and npm_sha),
        "mode": "portable_node_runtime",
    })

    # 10. OSV-Scanner Offline
    osv_bin = _first_valid_file(
        ([Path(dropin_defaults["SNIPER_OSV_SCANNER_BINARY"])] if "SNIPER_OSV_SCANNER_BINARY" in dropin_defaults else [])
        + [r / "osv-scanner" / "osv-scanner" for r in portable_roots],
        executable=True,
    )
    osv_launcher = _first_valid_file([app_dir / "osv_seccomp_launcher.py"], executable=False)
    osv_manifest = _first_valid_file(
        ([Path(dropin_defaults["SNIPER_OSV_DB_MANIFEST"])] if "SNIPER_OSV_DB_MANIFEST" in dropin_defaults else [])
        + [r / "osv-db" / "NPM-OFFLINE-DB-MANIFEST-v2.json" for r in portable_roots],
        executable=False,
    )
    osv_bin_sha = _sha256_file(osv_bin) if osv_bin else None
    osv_launcher_sha = _sha256_file(osv_launcher) if osv_launcher else None
    osv_manifest_sha = _sha256_file(osv_manifest) if osv_manifest else None
    if osv_bin and osv_bin_sha and osv_launcher and osv_launcher_sha and osv_manifest and osv_manifest_sha:
        bindings["SNIPER_OSV_SCANNER_BINARY"] = str(osv_bin)
        bindings["SNIPER_OSV_SCANNER_SHA256"] = osv_bin_sha
        bindings["SNIPER_OSV_SECCOMP_LAUNCHER"] = str(osv_launcher)
        bindings["SNIPER_OSV_SECCOMP_LAUNCHER_SHA256"] = osv_launcher_sha
        bindings["SNIPER_OSV_DB_MANIFEST"] = str(osv_manifest)
        bindings["SNIPER_OSV_DB_MANIFEST_SHA256"] = osv_manifest_sha
    tool_results.append({
        "id": "osv-scanner",
        "bound": bool(osv_bin and osv_bin_sha and osv_manifest and osv_manifest_sha),
        "mode": "single_static_binary_and_offline_db",
    })

    # 11. Schemathesis Local & Loopback.  A fixture/port configuration alone is
    # not a bound scanner: the exact, owner-controlled CLI must also be present.
    from schemathesis_active import ST_EXECUTABLE_SHA256
    st_bin = _first_valid_file(
        ([Path(dropin_defaults["SNIPER_SCHEMATHESIS_BINARY"])]
         if "SNIPER_SCHEMATHESIS_BINARY" in dropin_defaults else [])
        + [r / "schemathesis-4.31.0" / "venv" / "bin" / "st" for r in portable_roots]
        + [r / "schemathesis" / "venv" / "bin" / "st" for r in portable_roots],
        executable=True,
    )
    st_sha = _sha256_file(st_bin) if st_bin else None
    st_secure = False
    if st_bin and st_sha == ST_EXECUTABLE_SHA256:
        try:
            metadata = st_bin.stat()
            st_secure = metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022
        except OSError:
            st_secure = False
    if st_secure and st_bin:
        bindings["SNIPER_SCHEMATHESIS_BINARY"] = str(st_bin)
    st_origin = dropin_defaults.get("SNIPER_SCHEMATHESIS_LOCAL_ORIGIN", "http://127.0.0.1:8788")
    st_ports = dropin_defaults.get("SNIPER_SCHEMATHESIS_ALLOWED_PORTS", "8788")
    bindings["SNIPER_SCHEMATHESIS_LOCAL_ORIGIN"] = st_origin
    bindings["SNIPER_SCHEMATHESIS_EPHEMERAL_FIXTURE"] = "1"
    bindings["SNIPER_SCHEMATHESIS_ALLOWED_PORTS"] = st_ports
    tool_results.append({
        "id": "schemathesis",
        "bound": st_secure,
        "mode": "pinned_cli_synthetic_fixture_and_loopback",
    })

    # 12. OWASP ZAP (already pinned via zap_passive_active.py)
    zap_dir = _first_valid_dir(
        [r / "zap" for r in portable_roots]
        + [r / "zap-2.17.0-arm64" for r in portable_roots]
    )
    tool_results.append({
        "id": "owasp-zap",
        "bound": bool(zap_dir),
        "mode": "portable_java_and_zap_runtime",
    })
    return bindings, tool_results


def _autodiscover_locked(*, apply_env: bool, persist: bool, trust_disk: bool,
                         include_readiness: bool) -> dict[str, Any]:
    bindings, tool_results = _discover_bindings()
    pin_mismatches: list[str] = []
    pins_recorded = False
    if apply_env:
        pins_path = _pins_path() if persist else None
        stored = _load_pins(pins_path)
        if stored is not None and not trust_disk:
            effective: dict[str, str] = {}
            for key, value in bindings.items():
                if key in stored and stored[key] != value:
                    # Onaylı kayıttan farklı: diskteki dosya değişmiş olabilir; uygulanmaz.
                    pin_mismatches.append(key)
                    effective[key] = stored[key]
                else:
                    effective[key] = value
            bindings_to_apply = effective
            new_keys = {k: v for k, v in bindings.items() if k not in stored}
            if new_keys:
                pins_recorded = _save_pins(pins_path, {**stored, **new_keys})
        else:
            bindings_to_apply = dict(bindings)
            if persist:
                pins_recorded = _save_pins(pins_path, {**(stored or {}), **bindings})
        # Operatörün verdiği değerler (systemd drop-in, kabuk ortamı) asla ezilmez.
        for key, value in bindings_to_apply.items():
            if not os.environ.get(key):
                os.environ[key] = value

    persisted = False
    if persist:
        data_dir_str = os.environ.get("SNIPER_DATA_DIR", "")
        if data_dir_str:
            data_dir = Path(data_dir_str)
            if _is_regular_dir(data_dir):
                manifest_file = data_dir / "runtime-bindings-status.json"
                try:
                    manifest_file.write_text(
                        json.dumps(
                            {
                                "format": "sniper-runtime-bindings-status-v1",
                                "bound_env_count": len(bindings),
                                "tools": tool_results,
                            },
                            indent=2,
                            sort_keys=True,
                        ),
                        encoding="utf-8",
                    )
                    persisted = True
                except OSError:
                    persisted = False

    readiness = runtime_readiness_payload() if include_readiness else {
        "tools": [],
        "deferred": True,
    }
    ready_profiles = sum(
        1
        for tool in readiness.get("tools", [])
        for prof in tool.get("profiles", [])
        if prof.get("runtime") == "precheck_passed"
    )
    bound_count = sum(1 for item in tool_results if item["bound"])

    return {
        "format": "sniper-runtime-autodiscover-v1",
        "status": "bound",
        "bound_tool_count": bound_count,
        "total_discoverable_tools": len(tool_results),
        "bound_env_var_count": len(bindings),
        "ready_profile_count": ready_profiles,
        "persisted_status": persisted,
        "pins_recorded": pins_recorded,
        "pin_mismatches": sorted(pin_mismatches),
        "tools": tool_results,
        "readiness": readiness,
    }


def portable_bundle_manifest() -> dict[str, Any]:
    """Return an honest portable-bundle specification for this checkout and host."""
    readiness = runtime_readiness_payload()
    ready_by_tool: dict[str, bool] = {}
    for tool in readiness.get("tools", []):
        tid = str(tool.get("id", ""))
        profiles = tool.get("profiles", [])
        active_profiles = [p for p in profiles if p.get("mode") in {"built_in", "local", "authorized"}]
        ready_by_tool[tid] = bool(active_profiles) and any(
            p.get("runtime") == "precheck_passed" for p in active_profiles
        )

    app_dir = Path(__file__).resolve().parent
    configured_root = os.environ.get("SNIPER_PORTABLE_RUNTIMES_DIR", "").strip()
    roots = [app_dir / "runtimes", Path.home() / ".local" / "state" / "sniper-tool-runtimes"]
    if configured_root:
        roots.insert(0, Path(configured_root).expanduser())
    verified = _verified_community_runtimes(app_dir, roots)

    components = [
        {
            "id": "sniper-core",
            "name": "Sniper Çekirdek Motoru (Web/TLS/HTTP, Kaynak Denetimi, SBOM, 161 OWASP Kontrolü, 15+ Rapor Ayrıştırıcı)",
            "bundle_relpath": "app/",
            "packaging_type": "pure_python_builtin",
            "requires_separate_install": False,
            "requires_docker": False,
            "approx_size_mb": 5,
            "ready_on_this_host": True,
            "bundle_present": True,
        },
        {
            "id": "nuclei",
            "name": "Nuclei 3.11.1 + Sniper'ın Yerleşik Sabitlenmiş Loopback Şablonu",
            "bundle_relpath": "runtimes/nuclei-3.11.1/nuclei + templates/nuclei/local-powered-by.yaml",
            "packaging_type": "single_static_binary_and_builtin_loopback_template",
            "requires_separate_install": False,
            "requires_docker": False,
            "approx_size_mb": 95,
            "ready_on_this_host": ready_by_tool.get("nuclei", False),
            "bundle_present": "nuclei" in verified,
        },
        {
            "id": "trivy",
            "name": "Trivy 0.75.0 (Yapılandırma; zafiyet profilleri ayrıca sabitlenmiş çevrimdışı DB ister)",
            "bundle_relpath": "runtimes/trivy-0.75.0/trivy",
            "packaging_type": "single_static_binary_optional_offline_db",
            "requires_separate_install": False,
            "requires_docker": False,
            "approx_size_mb": 160,
            "ready_on_this_host": ready_by_tool.get("trivy", False),
            "bundle_present": "trivy" in verified,
        },
        {
            "id": "syft-grype",
            "name": "Syft 1.55.0 + Grype 0.121.0 (SBOM; zafiyet analizi ayrıca sabitlenmiş çevrimdışı DB ister)",
            "bundle_relpath": "runtimes/syft-1.55.0/syft + runtimes/grype-0.121.0/grype",
            "packaging_type": "two_static_binaries_optional_offline_db",
            "requires_separate_install": False,
            "requires_docker": False,
            "approx_size_mb": 250,
            "ready_on_this_host": ready_by_tool.get("syft-grype", False),
            "bundle_present": "syft" in verified and "grype" in verified,
        },
        {
            "id": "gitleaks",
            "name": "Gitleaks 8.30.1 (Yerel Dosya ve Git Geçmişi Sır Tarayıcı)",
            "bundle_relpath": "runtimes/gitleaks-8.30.1-stdlib/gitleaks",
            "packaging_type": "single_static_binary",
            "requires_separate_install": False,
            "requires_docker": False,
            "approx_size_mb": 18,
            "ready_on_this_host": ready_by_tool.get("gitleaks", False),
            "bundle_present": "gitleaks" in verified,
        },
        {
            "id": "trufflehog",
            "name": "TruffleHog 3.99.0 (Yerel Dosya ve Git Geçmişi Sır Tarayıcı)",
            "bundle_relpath": "runtimes/trufflehog-3.99.0-unpacked/trufflehog",
            "packaging_type": "single_static_binary",
            "requires_separate_install": False,
            "requires_docker": False,
            "approx_size_mb": 85,
            "ready_on_this_host": ready_by_tool.get("trufflehog", False),
            "bundle_present": "trufflehog" in verified,
        },
        {
            "id": "semgrep",
            "name": "Opengrep 1.30.1 + Sniper Yerel Güvenlik Kural Paketi",
            "bundle_relpath": "runtimes/opengrep-1.30.1/opengrep + rules/opengrep/sniper-core.yaml",
            "packaging_type": "single_static_binary_and_builtin_rulepack",
            "requires_separate_install": False,
            "requires_docker": False,
            "approx_size_mb": 140,
            "ready_on_this_host": ready_by_tool.get("semgrep", False),
            "bundle_present": "opengrep" in verified,
        },
    ]

    for component in components:
        if component["id"] != "sniper-core":
            component["requires_separate_install"] = not bool(component["bundle_present"])

    return {
        "format": "sniper-portable-bundle-manifest-v1",
        "zero_setup_supported": all(
            bool(component["bundle_present"]) and bool(component["ready_on_this_host"])
            for component in components
        ),
        "requires_manual_env_configuration": False,
        "requires_docker_for_core_and_local_tools": False,
        "installer_command": (
            "python3 scripts/install-community-tools --profile local "
            "--accept-third-party-licenses"
        ),
        "license_acceptance_required": True,
        "total_estimated_bundle_mb": sum(int(c["approx_size_mb"]) for c in components),
        "components": components,
    }
