import hashlib
from pathlib import Path

import tool_runtime_autodiscover as discovery


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
    assert by_id["sniper-core"]["requires_separate_install"] is False
    for tool_id in ("nuclei", "trivy", "gitleaks", "trufflehog", "semgrep"):
        assert by_id[tool_id]["requires_separate_install"] is True
        assert by_id[tool_id]["bundle_present"] is False


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
