import hashlib
import json
from pathlib import Path

import community_tool_installer as installer
import tool_runtime_autodiscover as discovery


def _write_lock_and_manifest(app_dir: Path, runtimes: Path, binaries: dict[str, Path]) -> None:
    platform_key = installer.current_platform_key()
    tool_contracts = {
        "nuclei": ("3.11.1", "nuclei-3.11.1", "nuclei", "SNIPER_NUCLEI_BINARY", "SNIPER_NUCLEI_SHA256"),
        "trivy": ("0.75.0", "trivy-0.75.0", "trivy", "SNIPER_TRIVY_BINARY", "SNIPER_TRIVY_BINARY_SHA256"),
        "gitleaks": ("8.30.1", "gitleaks-8.30.1-stdlib", "gitleaks", "SNIPER_GITLEAKS_BINARY", "SNIPER_GITLEAKS_SHA256"),
        "trufflehog": ("3.99.0", "trufflehog-3.99.0-unpacked", "trufflehog", "SNIPER_TRUFFLEHOG_BINARY", "SNIPER_TRUFFLEHOG_SHA256"),
        "opengrep": ("1.30.1", "opengrep-1.30.1", "opengrep", "SNIPER_OPENGREP_BINARY", "SNIPER_OPENGREP_SHA256"),
    }
    lock: dict[str, object] = {
        "schema": installer.LOCK_SCHEMA,
        "profiles": {"local": list(tool_contracts)},
        "tools": {},
    }
    records: dict[str, object] = {}
    for index, (tool_id, contract) in enumerate(tool_contracts.items(), start=1):
        version, destination, binary_name, env_binary, env_sha256 = contract
        artifact_sha = f"{index:064x}"
        binary = binaries[f"SNIPER_{tool_id.upper() if tool_id != 'opengrep' else 'OPENGREP'}"]
        lock["tools"][tool_id] = {
            "version": version,
            "license": "MIT",
            "destination": destination,
            "binary": binary_name,
            "env_binary": env_binary,
            "env_sha256": env_sha256,
            "platforms": {
                platform_key: {
                    "url": f"https://example.invalid/{tool_id}",
                    "asset_name": f"{tool_id}.archive",
                    "sha256": artifact_sha,
                    "kind": "raw",
                    "max_bytes": 1000,
                }
            },
        }
        records[tool_id] = {
            "version": version,
            "license": "MIT",
            "platform": platform_key,
            "artifact_sha256": artifact_sha,
            "binary": f"{destination}/{binary_name}",
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "env_binary": env_binary,
            "env_sha256": env_sha256,
        }
    app_dir.mkdir(parents=True, exist_ok=True)
    lock_path = app_dir / "COMMUNITY-TOOLS.lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    manifest = {
        "schema": installer.LOCK_SCHEMA,
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "tools": records,
    }
    manifest_path = runtimes / installer.INSTALL_MANIFEST
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.chmod(0o600)


def test_public_runtime_discovery_never_probes_private_migration_workspaces(monkeypatch, tmp_path: Path) -> None:
    """Community discovery may use portable/configured roots, never a developer migration tree."""
    observed: list[Path] = []

    def first_file(candidates, *, executable=False):
        observed.extend(Path(item) for item in candidates)
        return None

    def first_exec(candidates, revoked_digests):
        observed.extend(Path(item) for item in candidates)
        return None, None

    def first_dir(candidates):
        observed.extend(Path(item) for item in candidates)
        return None

    monkeypatch.setattr(discovery.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(discovery, "_first_valid_file", first_file)
    monkeypatch.setattr(discovery, "_first_valid_unrevoked_executable", first_exec)
    monkeypatch.setattr(discovery, "_first_valid_dir", first_dir)
    monkeypatch.setattr(discovery, "_read_systemd_dropin_defaults", lambda _path: {})
    monkeypatch.setattr(discovery, "_is_regular_file", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(discovery, "_sha256_file", lambda _path: None)

    bindings, tools = discovery._discover_bindings()

    assert set(bindings) == {
        "SNIPER_SCHEMATHESIS_ALLOWED_PORTS",
        "SNIPER_SCHEMATHESIS_EPHEMERAL_FIXTURE",
        "SNIPER_SCHEMATHESIS_LOCAL_ORIGIN",
    }
    assert tools
    rendered = "\n".join(str(path) for path in observed)
    assert "/runtime-prereqs/" not in rendered
    assert "osv-local-active-analysis-" not in rendered


def test_portable_manifest_never_claims_absent_runtimes_are_zero_setup(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(discovery.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(
        discovery,
        "runtime_readiness_payload",
        lambda: {"tools": []},
    )

    manifest = discovery.portable_bundle_manifest()

    assert manifest["zero_setup_supported"] is False
    assert manifest["installer_command"] == (
        "python3 scripts/install-community-tools --profile local --accept-third-party-licenses"
    )
    assert manifest["license_acceptance_required"] is True
    by_id = {item["id"]: item for item in manifest["components"]}
    assert set(by_id) == {"sniper-core", "nuclei", "trivy", "gitleaks", "trufflehog", "semgrep"}
    assert by_id["sniper-core"]["requires_separate_install"] is False
    for tool_id in ("nuclei", "trivy", "gitleaks", "trufflehog", "semgrep"):
        assert by_id[tool_id]["requires_separate_install"] is True
        assert by_id[tool_id]["bundle_present"] is False


def test_portable_manifest_reports_zero_setup_only_for_complete_verified_profile(
    monkeypatch, tmp_path: Path
) -> None:
    runtimes = tmp_path / "runtimes"
    binaries = {
        "SNIPER_NUCLEI": runtimes / "nuclei-3.11.1" / "nuclei",
        "SNIPER_TRIVY": runtimes / "trivy-0.75.0" / "trivy",
        "SNIPER_GITLEAKS": runtimes / "gitleaks-8.30.1-stdlib" / "gitleaks",
        "SNIPER_TRUFFLEHOG": runtimes / "trufflehog-3.99.0-unpacked" / "trufflehog",
        "SNIPER_OPENGREP": runtimes / "opengrep-1.30.1" / "opengrep",
    }
    for name, binary in binaries.items():
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(f"#!/bin/sh\n# {name}\n".encode())
        binary.chmod(0o555)
    app_dir = tmp_path / "app"
    _write_lock_and_manifest(app_dir, runtimes, binaries)

    monkeypatch.setattr(discovery, "__file__", str(app_dir / "tool_runtime_autodiscover.py"))
    monkeypatch.setattr(discovery.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv("SNIPER_PORTABLE_RUNTIMES_DIR", str(runtimes))
    monkeypatch.setattr(
        discovery,
        "runtime_readiness_payload",
        lambda: {
            "tools": [
                {"id": tool_id, "profiles": [{"mode": "local", "runtime": "precheck_passed"}]}
                for tool_id in ("nuclei", "trivy", "gitleaks", "trufflehog", "semgrep")
            ]
        },
    )

    manifest = discovery.portable_bundle_manifest()

    assert manifest["zero_setup_supported"] is True
    by_id = {item["id"]: item for item in manifest["components"]}
    assert set(by_id) == {"sniper-core", "nuclei", "trivy", "gitleaks", "trufflehog", "semgrep"}
    assert all(item["bundle_present"] for item in manifest["components"])
    assert all(item["ready_on_this_host"] for item in manifest["components"])


def test_installed_local_profile_binds_each_binary_to_its_computed_digest(
    monkeypatch, tmp_path: Path
) -> None:
    runtimes = tmp_path / "runtimes"
    binaries = {
        "SNIPER_NUCLEI": runtimes / "nuclei-3.11.1" / "nuclei",
        "SNIPER_TRIVY": runtimes / "trivy-0.75.0" / "trivy",
        "SNIPER_GITLEAKS": runtimes / "gitleaks-8.30.1-stdlib" / "gitleaks",
        "SNIPER_TRUFFLEHOG": runtimes / "trufflehog-3.99.0-unpacked" / "trufflehog",
        "SNIPER_OPENGREP": runtimes / "opengrep-1.30.1" / "opengrep",
    }
    for name, binary in binaries.items():
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(f"#!/bin/sh\n# {name}\n".encode())
        binary.chmod(0o555)

    app_dir = tmp_path / "app"
    _write_lock_and_manifest(app_dir, runtimes, binaries)
    monkeypatch.setattr(discovery, "__file__", str(app_dir / "tool_runtime_autodiscover.py"))
    monkeypatch.setattr(discovery.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv("SNIPER_PORTABLE_RUNTIMES_DIR", str(runtimes))
    bindings, tools = discovery._discover_bindings()

    expected = {
        "SNIPER_NUCLEI_BINARY": binaries["SNIPER_NUCLEI"],
        "SNIPER_TRIVY_BINARY": binaries["SNIPER_TRIVY"],
        "SNIPER_GITLEAKS_BINARY": binaries["SNIPER_GITLEAKS"],
        "SNIPER_TRUFFLEHOG_BINARY": binaries["SNIPER_TRUFFLEHOG"],
        "SNIPER_OPENGREP_BINARY": binaries["SNIPER_OPENGREP"],
    }
    for env_name, binary in expected.items():
        assert bindings[env_name] == str(binary)
    assert bindings["SNIPER_NUCLEI_SHA256"] == hashlib.sha256(
        binaries["SNIPER_NUCLEI"].read_bytes()
    ).hexdigest()
    assert bindings["SNIPER_TRIVY_BINARY_SHA256"] == hashlib.sha256(
        binaries["SNIPER_TRIVY"].read_bytes()
    ).hexdigest()
    assert bindings["SNIPER_TRIVY_SHA256"] == bindings["SNIPER_TRIVY_BINARY_SHA256"]
    assert bindings["SNIPER_GITLEAKS_SHA256"] == hashlib.sha256(
        binaries["SNIPER_GITLEAKS"].read_bytes()
    ).hexdigest()
    assert bindings["SNIPER_TRUFFLEHOG_SHA256"] == hashlib.sha256(
        binaries["SNIPER_TRUFFLEHOG"].read_bytes()
    ).hexdigest()
    assert bindings["SNIPER_OPENGREP_SHA256"] == hashlib.sha256(
        binaries["SNIPER_OPENGREP"].read_bytes()
    ).hexdigest()
    by_id = {item["id"]: item for item in tools}
    assert by_id["trivy"] == {
        "id": "trivy",
        "bound": True,
        "mode": "local_binary_with_optional_offline_db",
    }


def test_untracked_portable_profile_is_not_bound(monkeypatch, tmp_path: Path) -> None:
    runtimes = tmp_path / "runtimes"
    nuclei = runtimes / "nuclei-3.11.1" / "nuclei"
    nuclei.parent.mkdir(parents=True)
    nuclei.write_bytes(b"untracked")
    nuclei.chmod(0o555)

    monkeypatch.setattr(discovery.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv("SNIPER_PORTABLE_RUNTIMES_DIR", str(runtimes))
    bindings, _tools = discovery._discover_bindings()

    assert "SNIPER_NUCLEI_BINARY" not in bindings
    assert "SNIPER_NUCLEI_SHA256" not in bindings


def test_manifest_tracked_binary_is_rejected_after_content_change(monkeypatch, tmp_path: Path) -> None:
    runtimes = tmp_path / "runtimes"
    binaries = {
        "SNIPER_NUCLEI": runtimes / "nuclei-3.11.1" / "nuclei",
        "SNIPER_TRIVY": runtimes / "trivy-0.75.0" / "trivy",
        "SNIPER_GITLEAKS": runtimes / "gitleaks-8.30.1-stdlib" / "gitleaks",
        "SNIPER_TRUFFLEHOG": runtimes / "trufflehog-3.99.0-unpacked" / "trufflehog",
        "SNIPER_OPENGREP": runtimes / "opengrep-1.30.1" / "opengrep",
    }
    for name, binary in binaries.items():
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(f"#!/bin/sh\n# {name}\n".encode())
        binary.chmod(0o555)
    app_dir = tmp_path / "app"
    _write_lock_and_manifest(app_dir, runtimes, binaries)
    binaries["SNIPER_NUCLEI"].chmod(0o755)
    binaries["SNIPER_NUCLEI"].write_bytes(b"tampered")
    binaries["SNIPER_NUCLEI"].chmod(0o555)

    monkeypatch.setattr(discovery, "__file__", str(app_dir / "tool_runtime_autodiscover.py"))
    monkeypatch.setattr(discovery.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv("SNIPER_PORTABLE_RUNTIMES_DIR", str(runtimes))
    bindings, _tools = discovery._discover_bindings()

    assert "SNIPER_NUCLEI_BINARY" not in bindings
    assert "SNIPER_NUCLEI_SHA256" not in bindings
    assert bindings["SNIPER_TRIVY_BINARY"] == str(binaries["SNIPER_TRIVY"])
