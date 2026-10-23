"""Rootless installer for SHA-256 locked Sniper Community tool runtimes.

The installer downloads only artifacts declared in ``COMMUNITY-TOOLS.lock.json``,
verifies the complete artifact before extraction, copies only the declared
regular executable member, and never executes the installed tool.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import tarfile
import tempfile
from typing import Any, BinaryIO
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import zipfile


LOCK_SCHEMA = "sniper-community-tools-lock-v1"
INSTALL_MANIFEST = "SNIPER-COMMUNITY-TOOLS-MANIFEST.json"
_HEX64 = frozenset("0123456789abcdef")
_MAX_LOCK_BYTES = 1_000_000
_READ_CHUNK = 1024 * 1024


class InstallError(RuntimeError):
    pass


def current_platform_key() -> str:
    if platform.system().lower() != "linux":
        raise InstallError("Only locked Linux runtime artifacts are available in Community v1.")
    machine = {"arm64": "aarch64", "amd64": "x86_64", "x64": "x86_64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    if machine not in {"aarch64", "x86_64"}:
        raise InstallError(f"Unsupported Linux architecture: {machine}")
    return f"linux-{machine}"


def _regular_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def _sha256(path: Path) -> str:
    if not _regular_file(path):
        raise InstallError(f"Artifact is not a regular file: {path.name}")
    try:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise InstallError(f"Artifact cannot be read: {path.name}") from exc


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise InstallError(f"Invalid {label} in tool lock")
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise InstallError(f"Unsafe {label} in tool lock")
    return relative


def _load_json_regular(path: Path, *, maximum: int) -> Any:
    if not _regular_file(path):
        raise InstallError(f"Required regular file is unavailable: {path.name}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InstallError(f"Cannot read {path.name}") from exc
    if not 1 <= len(raw) <= maximum:
        raise InstallError(f"Invalid size for {path.name}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"Invalid JSON in {path.name}") from exc


def load_lock(path: Path) -> dict[str, Any]:
    payload = _load_json_regular(path, maximum=_MAX_LOCK_BYTES)
    if not isinstance(payload, dict) or payload.get("schema") != LOCK_SCHEMA:
        raise InstallError("Unsupported Community tool lock schema")
    profiles, tools = payload.get("profiles"), payload.get("tools")
    if not isinstance(profiles, dict) or not isinstance(tools, dict) or not profiles or not tools:
        raise InstallError("Community tool lock is incomplete")
    return payload


def _copy_limited(source: BinaryIO, destination: BinaryIO, maximum: int) -> int:
    total = 0
    while True:
        chunk = source.read(_READ_CHUNK)
        if not chunk:
            return total
        total += len(chunk)
        if total > maximum:
            raise InstallError("Artifact exceeds its locked size limit")
        destination.write(chunk)


def _obtain_artifact(spec: dict[str, Any], target: Path, cache_dir: Path | None) -> None:
    asset_name = spec.get("asset_name")
    maximum = spec.get("max_bytes")
    url = spec.get("url")
    if not isinstance(asset_name, str) or Path(asset_name).name != asset_name:
        raise InstallError("Invalid asset name in tool lock")
    if type(maximum) is not int or not 1 <= maximum <= 4_000_000_000:
        raise InstallError("Invalid artifact size limit in tool lock")
    if not isinstance(url, str) or urlparse(url).scheme != "https":
        raise InstallError("Tool artifacts must use HTTPS")

    cached = cache_dir / asset_name if cache_dir is not None else None
    try:
        with target.open("xb") as destination:
            if cached is not None and _regular_file(cached):
                with cached.open("rb") as source:
                    _copy_limited(source, destination, maximum)
            else:
                request = Request(url, headers={"User-Agent": "Sniper-Community-tool-installer/1.0"})
                try:
                    with urlopen(request, timeout=60) as source:  # noqa: S310 - URL is lock-validated HTTPS.
                        _copy_limited(source, destination, maximum)
                except OSError as exc:
                    raise InstallError(f"Download failed for {asset_name}") from exc
            destination.flush()
            os.fsync(destination.fileno())
    except FileExistsError as exc:
        raise InstallError("Installer staging collision") from exc


def _extract_locked_member(artifact: Path, spec: dict[str, Any], destination: Path) -> None:
    kind = spec.get("kind")
    member_path = _safe_relative(spec.get("member"), "archive member") if kind != "raw" else None
    maximum = int(spec["max_bytes"])
    try:
        with destination.open("xb") as output:
            if kind == "raw":
                with artifact.open("rb") as source:
                    _copy_limited(source, output, maximum)
            elif kind == "zip":
                with zipfile.ZipFile(artifact) as bundle:
                    try:
                        info = bundle.getinfo(member_path.as_posix())
                    except KeyError as exc:
                        raise InstallError("Locked member is absent from ZIP artifact") from exc
                    mode = info.external_attr >> 16
                    if info.is_dir() or stat.S_ISLNK(mode) or info.file_size > maximum:
                        raise InstallError("Locked ZIP member is not a bounded regular file")
                    with bundle.open(info) as source:
                        copied = _copy_limited(source, output, maximum)
                    if copied != info.file_size:
                        raise InstallError("Locked ZIP member was only partially read")
            elif kind == "tar.gz":
                with tarfile.open(artifact, mode="r:gz") as bundle:
                    try:
                        info = bundle.getmember(member_path.as_posix())
                    except KeyError as exc:
                        raise InstallError("Locked member is absent from tar artifact") from exc
                    if not info.isreg() or not 0 <= info.size <= maximum:
                        raise InstallError("Locked tar member is not a bounded regular file")
                    source = bundle.extractfile(info)
                    if source is None:
                        raise InstallError("Locked tar member cannot be read")
                    with source:
                        copied = _copy_limited(source, output, maximum)
                    if copied != info.size:
                        raise InstallError("Locked tar member was only partially read")
            else:
                raise InstallError("Unsupported artifact type in tool lock")
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o555)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        if isinstance(exc, InstallError):
            raise
        raise InstallError("Locked tool artifact could not be extracted") from exc


def _existing_manifest(root: Path) -> dict[str, Any]:
    path = root / INSTALL_MANIFEST
    if not path.exists():
        return {"schema": LOCK_SCHEMA, "tools": {}}
    payload = _load_json_regular(path, maximum=_MAX_LOCK_BYTES)
    if not isinstance(payload, dict) or payload.get("schema") != LOCK_SCHEMA \
            or not isinstance(payload.get("tools"), dict):
        raise InstallError("Existing runtime install manifest is invalid")
    return payload


def _write_manifest(root: Path, payload: dict[str, Any]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".community-tools-", dir=root)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, root / INSTALL_MANIFEST)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def install_profile(
    lock_path: Path,
    install_root: Path,
    *,
    profile: str = "local",
    platform_key: str | None = None,
    cache_dir: Path | None = None,
    accept_licenses: bool = False,
) -> dict[str, Any]:
    if not accept_licenses:
        raise InstallError("Third-party license acceptance is required")
    lock = load_lock(Path(lock_path))
    selected = lock["profiles"].get(profile)
    if not isinstance(selected, list) or not selected or any(not isinstance(item, str) for item in selected):
        raise InstallError(f"Unknown or invalid tool profile: {profile}")
    platform_key = platform_key or current_platform_key()

    root_input = Path(install_root).expanduser()
    if root_input.exists() and root_input.is_symlink():
        raise InstallError("Runtime install root cannot be a symbolic link")
    root = root_input.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    cache = Path(cache_dir).expanduser().resolve() if cache_dir is not None else None
    if cache is not None and (not cache.is_dir() or cache.is_symlink()):
        raise InstallError("Artifact cache must be a regular directory")

    manifest = _existing_manifest(root)
    records = manifest["tools"]
    installed: list[str] = []
    already_installed: list[str] = []

    for tool_id in selected:
        tool = lock["tools"].get(tool_id)
        if not isinstance(tool, dict):
            raise InstallError(f"Tool is missing from lock: {tool_id}")
        artifact = tool.get("platforms", {}).get(platform_key)
        if not isinstance(artifact, dict):
            raise InstallError(f"{tool_id} has no locked artifact for {platform_key}")
        expected_archive = artifact.get("sha256")
        if not isinstance(expected_archive, str) or len(expected_archive) != 64 \
                or any(char not in _HEX64 for char in expected_archive):
            raise InstallError(f"{tool_id} has an invalid locked SHA-256")
        destination_rel = _safe_relative(tool.get("destination"), "destination")
        binary_rel = _safe_relative(tool.get("binary"), "binary path")
        destination = root.joinpath(*destination_rel.parts)
        binary = destination.joinpath(*binary_rel.parts)
        record = records.get(tool_id)
        if destination.exists():
            if not isinstance(record, dict) or not _regular_file(binary) \
                    or record.get("artifact_sha256") != expected_archive \
                    or record.get("binary_sha256") != _sha256(binary):
                raise InstallError(f"Existing {tool_id} runtime is untracked or modified")
            already_installed.append(tool_id)
            continue

        with tempfile.TemporaryDirectory(prefix=f".install-{tool_id}-", dir=root) as temporary:
            staging = Path(temporary)
            artifact_path = staging / str(artifact["asset_name"])
            _obtain_artifact(artifact, artifact_path, cache)
            if _sha256(artifact_path) != expected_archive:
                raise InstallError(f"SHA-256 mismatch for {tool_id}")
            component = staging / "component"
            component.mkdir(mode=0o700)
            staged_binary = component.joinpath(*binary_rel.parts)
            staged_binary.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _extract_locked_member(artifact_path, artifact, staged_binary)
            binary_sha = _sha256(staged_binary)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.replace(component, destination)

        records[tool_id] = {
            "version": tool.get("version"),
            "license": tool.get("license"),
            "platform": platform_key,
            "artifact_sha256": expected_archive,
            "binary": str(destination_rel / binary_rel),
            "binary_sha256": binary_sha,
            "env_binary": tool.get("env_binary"),
            "env_sha256": tool.get("env_sha256"),
        }
        _write_manifest(root, manifest)
        installed.append(tool_id)

    return {
        "format": "sniper-community-tool-install-result-v1",
        "status": "installed" if installed else "already_installed",
        "profile": profile,
        "platform": platform_key,
        "installed": installed,
        "already_installed": already_installed,
        "tool_count": len(selected),
    }
