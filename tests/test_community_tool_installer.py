from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import zipfile

import pytest

import community_tool_installer as installer


def _lock(tmp_path: Path, artifact: Path, *, member: str = "bin/demo") -> Path:
    payload = {
        "schema": "sniper-community-tools-lock-v1",
        "profiles": {"local": ["demo"]},
        "tools": {
            "demo": {
                "version": "1.0.0",
                "license": "Apache-2.0",
                "destination": "demo-1.0.0",
                "binary": "demo",
                "env_binary": "SNIPER_DEMO_BINARY",
                "env_sha256": "SNIPER_DEMO_SHA256",
                "platforms": {
                    "linux-aarch64": {
                        "url": "https://example.invalid/releases/demo.zip",
                        "asset_name": artifact.name,
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "kind": "zip",
                        "member": member,
                        "max_bytes": 1_000_000,
                    }
                },
            }
        },
    }
    path = tmp_path / "tools.lock.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_cached_pinned_artifact_installs_once_and_writes_runtime_manifest(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        info = zipfile.ZipInfo("bin/demo")
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        bundle.writestr(info, b"#!/bin/sh\necho demo\n")
    lock = _lock(tmp_path, archive)
    output = tmp_path / "runtimes"

    report = installer.install_profile(
        lock,
        output,
        profile="local",
        platform_key="linux-aarch64",
        cache_dir=cache,
        accept_licenses=True,
    )

    binary = output / "demo-1.0.0" / "demo"
    assert report["status"] == "installed"
    assert report["installed"] == ["demo"]
    assert binary.read_bytes() == b"#!/bin/sh\necho demo\n"
    assert stat.S_IMODE(binary.stat().st_mode) == 0o555
    manifest = json.loads((output / installer.INSTALL_MANIFEST).read_text(encoding="utf-8"))
    assert manifest["lock_sha256"] == hashlib.sha256(lock.read_bytes()).hexdigest()
    assert manifest["tools"]["demo"]["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert "/home/" not in json.dumps(report)

    repeated = installer.install_profile(
        lock,
        output,
        profile="local",
        platform_key="linux-aarch64",
        cache_dir=cache,
        accept_licenses=True,
    )
    assert repeated["installed"] == []
    assert repeated["already_installed"] == ["demo"]


def test_checksum_mismatch_is_rejected_without_partial_install(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bin/demo", b"demo")
    lock = _lock(tmp_path, archive)
    archive.write_bytes(archive.read_bytes() + b"tampered")
    output = tmp_path / "runtimes"

    with pytest.raises(installer.InstallError, match="SHA-256"):
        installer.install_profile(
            lock,
            output,
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )

    assert not (output / "demo-1.0.0").exists()


def test_explicit_cache_never_falls_back_to_network_when_asset_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    reference = tmp_path / "demo.zip"
    with zipfile.ZipFile(reference, "w") as bundle:
        bundle.writestr("bin/demo", b"demo")
    lock = _lock(tmp_path, reference)
    reference.unlink()
    monkeypatch.setattr(
        installer,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network fallback")),
    )

    with pytest.raises(installer.InstallError, match="absent from the offline cache"):
        installer.install_profile(
            lock,
            tmp_path / "runtimes",
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )


def test_existing_runtime_without_execute_bits_is_rejected(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bin/demo", b"demo")
    lock = _lock(tmp_path, archive)
    output = tmp_path / "runtimes"
    installer.install_profile(
        lock,
        output,
        profile="local",
        platform_key="linux-aarch64",
        cache_dir=cache,
        accept_licenses=True,
    )
    binary = output / "demo-1.0.0" / "demo"
    binary.chmod(0o444)

    with pytest.raises(installer.InstallError, match="untracked or modified"):
        installer.install_profile(
            lock,
            output,
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )


def test_existing_runtime_through_symlinked_destination_is_rejected(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bin/demo", b"demo")
    lock = _lock(tmp_path, archive)
    output = tmp_path / "runtimes"
    installer.install_profile(
        lock,
        output,
        profile="local",
        platform_key="linux-aarch64",
        cache_dir=cache,
        accept_licenses=True,
    )
    destination = output / "demo-1.0.0"
    escaped = tmp_path / "escaped-runtime"
    destination.rename(escaped)
    destination.symlink_to(escaped, target_is_directory=True)

    with pytest.raises(installer.InstallError, match="symbolic link"):
        installer.install_profile(
            lock,
            output,
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )


def test_dangling_symlink_install_root_is_rejected_without_creating_target(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bin/demo", b"demo")
    lock = _lock(tmp_path, archive)
    escaped = tmp_path / "outside-runtime"
    output = tmp_path / "runtimes"
    output.symlink_to(escaped, target_is_directory=True)

    with pytest.raises(installer.InstallError, match="symbolic link"):
        installer.install_profile(
            lock,
            output,
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )

    assert output.is_symlink()
    assert not escaped.exists()


def test_symlinked_artifact_cache_is_rejected(tmp_path: Path) -> None:
    real_cache = tmp_path / "real-cache"
    real_cache.mkdir()
    archive = real_cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bin/demo", b"demo")
    lock = _lock(tmp_path, archive)
    cache = tmp_path / "cache"
    cache.symlink_to(real_cache, target_is_directory=True)

    with pytest.raises(installer.InstallError, match="cache must be a regular directory"):
        installer.install_profile(
            lock,
            tmp_path / "runtimes",
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )


@pytest.mark.parametrize(
    "field",
    ("platform", "version", "license", "binary", "env_binary", "env_sha256"),
)
def test_existing_runtime_requires_complete_manifest_record(tmp_path: Path, field: str) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bin/demo", b"demo")
    lock = _lock(tmp_path, archive)
    output = tmp_path / "runtimes"
    installer.install_profile(
        lock,
        output,
        profile="local",
        platform_key="linux-aarch64",
        cache_dir=cache,
        accept_licenses=True,
    )
    manifest_path = output / installer.INSTALL_MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tools"]["demo"][field] = "tampered"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(installer.InstallError, match="untracked or modified"):
        installer.install_profile(
            lock,
            output,
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )


def test_unsafe_archive_member_and_missing_license_acceptance_fail_closed(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../demo", b"demo")
    lock = _lock(tmp_path, archive, member="../demo")

    with pytest.raises(installer.InstallError, match="license"):
        installer.install_profile(lock, tmp_path / "no-consent", profile="local", cache_dir=cache)
    with pytest.raises(installer.InstallError, match="member"):
        installer.install_profile(
            lock,
            tmp_path / "unsafe",
            profile="local",
            platform_key="linux-aarch64",
            cache_dir=cache,
            accept_licenses=True,
        )
