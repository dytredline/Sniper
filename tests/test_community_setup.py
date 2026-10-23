from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

import community_setup as setup


def _fixture_repo(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "requirements-runtime.lock").write_text("PyYAML==6.0.3\n", encoding="utf-8")
    installer = root / "scripts" / "install-community-tools"
    installer.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    installer.chmod(0o755)
    for entrypoint in ("sniper-mcp", "sniper-project-audit"):
        path = root / "scripts" / entrypoint
        path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        path.chmod(0o755)
    venv = root / ".venv"
    (venv / "bin").mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python.chmod(0o755)
    return root, venv


def test_setup_installs_locked_runtime_and_local_tools_without_starting_sniper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, venv = _fixture_repo(tmp_path)
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append([str(item) for item in command])
        assert kwargs["cwd"] == root
        assert kwargs["check"] is True
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    result = setup.setup_community(
        root,
        venv_dir=venv,
        accept_third_party_licenses=True,
    )

    python = str(venv / "bin" / "python")
    assert calls == [
        [python, "-m", "pip", "install", "-r", str(root / "requirements-runtime.lock")],
        [
            python,
            str(root / "scripts" / "install-community-tools"),
            "--profile",
            "local",
            "--install-dir",
            str(root / "runtimes"),
            "--accept-third-party-licenses",
        ],
        [python, str(root / "scripts" / "sniper-mcp"), "--help"],
        [python, str(root / "scripts" / "sniper-project-audit"), "--help"],
    ]
    assert result == {
        "format": "sniper-community-setup-result-v1",
        "status": "ready",
        "venv": ".venv",
        "tools_profile": "local",
        "verified_entrypoints": ["scripts/sniper-mcp", "scripts/sniper-project-audit"],
    }


def test_setup_requires_explicit_license_acceptance_before_any_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, venv = _fixture_repo(tmp_path)
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("command started")),
    )

    with pytest.raises(setup.SetupError, match="license"):
        setup.setup_community(root, venv_dir=venv, accept_third_party_licenses=False)


def test_setup_rejects_symlinked_environment(tmp_path: Path) -> None:
    root, venv = _fixture_repo(tmp_path)
    target = tmp_path / "outside"
    target.mkdir()
    for child in sorted(venv.rglob("*"), reverse=True):
        child.unlink() if child.is_file() else child.rmdir()
    venv.rmdir()
    venv.symlink_to(target, target_is_directory=True)

    with pytest.raises(setup.SetupError, match="symbolic link"):
        setup.setup_community(root, venv_dir=venv, accept_third_party_licenses=True)


def test_setup_creates_missing_environment_and_uses_an_offline_wheelhouse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, venv = _fixture_repo(tmp_path)
    (venv / "bin" / "python").unlink()
    (venv / "bin").rmdir()
    venv.rmdir()
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    calls: list[list[str]] = []

    def run(command, **kwargs):
        rendered = [str(item) for item in command]
        calls.append(rendered)
        if rendered[1:3] == ["-m", "venv"]:
            python = venv / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python.chmod(0o755)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    setup.setup_community(
        root,
        venv_dir=venv,
        wheelhouse=wheelhouse,
        accept_third_party_licenses=True,
    )

    assert calls[0][1:3] == ["-m", "venv"]
    assert calls[1][3:7] == ["install", "--no-index", "--find-links", str(wheelhouse)]
