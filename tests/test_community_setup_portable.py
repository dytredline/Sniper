from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

import community_setup as setup


def _repo(tmp_path: Path, *, windows: bool, installer: bool = False) -> tuple[Path, Path, Path]:
    root = tmp_path / "repo"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (root / "requirements-runtime.lock").write_text("PyYAML==6.0.3\n", encoding="utf-8")
    if installer:
        path = scripts / "install-community-tools"
        path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        path.chmod(0o755)
    for name in ("sniper-mcp", "sniper-project-audit"):
        # Core-only Windows must not depend on a POSIX executable bit; Python opens these files.
        (scripts / name).write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    environment = root / ".venv"
    python = environment / ("Scripts/python.exe" if windows else "bin/python")
    python.parent.mkdir(parents=True)
    python.write_bytes(b"portable test interpreter")
    python.chmod(0o755)
    return root, environment, python


def _probe(command: list[str], environment: Path) -> subprocess.CompletedProcess[str]:
    (environment.parent / "base-python").mkdir(exist_ok=True)
    return subprocess.CompletedProcess(
        command,
        0,
        stdout=json.dumps({
            "implementation": "cpython",
            "version": [3, 12, 3],
            "prefix": str(environment),
            "base_prefix": str(environment.parent / "base-python"),
        }),
        stderr="",
    )


def test_core_only_windows_keeps_scripts_python_without_posix_exec_bit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, environment, python = _repo(tmp_path, windows=True)
    monkeypatch.setattr(setup, "_platform_system", lambda: "Windows")

    def run(command, **_kwargs):
        if [str(item) for item in command][1:3] == ["-I", "-c"]:
            return _probe(command, environment)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    result = setup.setup_community(root, venv_dir=environment, core_only=True)

    assert result["tools_profile"] == "core"
    assert result["support_level"] == "supported"
    assert result["platform_tested"] is False
    assert setup._trusted_venv_python(environment) == python


def test_full_profile_windows_fails_with_actionable_route_before_any_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, environment, _python = _repo(tmp_path, windows=True, installer=True)
    monkeypatch.setattr(setup, "_platform_system", lambda: "Windows")
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("command started")),
    )

    with pytest.raises(setup.SetupError, match="requires Linux.*--core-only.*WSL2/Docker"):
        setup.setup_community(
            root,
            venv_dir=environment,
            accept_third_party_licenses=True,
        )


def test_core_only_unknown_platform_fails_before_any_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, environment, _python = _repo(tmp_path, windows=False)
    monkeypatch.setattr(setup, "_platform_system", lambda: "FreeBSD")
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("command started")),
    )

    with pytest.raises(setup.SetupError, match="Unsupported native platform: freebsd.*Linux container"):
        setup.setup_community(root, venv_dir=environment, core_only=True)


def test_core_only_darwin_keeps_standard_bin_python(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, environment, python = _repo(tmp_path, windows=False)
    monkeypatch.setattr(setup, "_platform_system", lambda: "Darwin")

    def run(command, **_kwargs):
        if [str(item) for item in command][1:3] == ["-I", "-c"]:
            return _probe(command, environment)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    result = setup.setup_community(root, venv_dir=environment, core_only=True)

    assert result["tools_profile"] == "core"
    assert result["support_level"] == "supported"
    assert result["platform_tested"] is True
    assert setup._trusted_venv_python(environment) == python


def test_core_only_rejects_tool_cache_before_any_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, environment, _python = _repo(tmp_path, windows=False)
    cache = tmp_path / "tools"
    cache.mkdir()
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("command started")),
    )

    with pytest.raises(setup.SetupError, match="tool cache.*core-only"):
        setup.setup_community(root, venv_dir=environment, core_only=True, cache_dir=cache)


def test_default_linux_profile_still_invokes_locked_tool_installer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, environment, python = _repo(tmp_path, windows=False, installer=True)
    for name in ("sniper-mcp", "sniper-project-audit"):
        (root / "scripts" / name).chmod(0o755)
    monkeypatch.setattr(setup, "_platform_system", lambda: "Linux")
    calls: list[list[str]] = []

    def run(command, **_kwargs):
        rendered = [str(item) for item in command]
        calls.append(rendered)
        if rendered[1:3] == ["-I", "-c"]:
            return _probe(command, environment)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    result = setup.setup_community(
        root,
        venv_dir=environment,
        accept_third_party_licenses=True,
    )

    assert result["tools_profile"] == "local"
    assert [
        str(python), str(root / setup.TOOL_INSTALLER), "--profile", "local",
        "--install-dir", str(root / "runtimes"), "--accept-third-party-licenses",
    ] in calls


def test_non_linux_full_profile_fails_before_creating_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, environment, _python = _repo(tmp_path, windows=False, installer=True)
    monkeypatch.setattr(setup, "_platform_system", lambda: "Darwin")
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("command started")),
    )

    with pytest.raises(setup.SetupError, match="requires Linux.*--core-only"):
        setup.setup_community(
            root,
            venv_dir=environment,
            accept_third_party_licenses=True,
        )


def test_core_only_real_venv_smoke_uses_no_tool_or_network(tmp_path: Path) -> None:
    root = tmp_path / "real-core"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (root / setup.RUNTIME_LOCK).write_text("# empty offline smoke lock\n", encoding="utf-8")
    entrypoint = "import argparse; argparse.ArgumentParser().parse_args()\n"
    for name in ("sniper-mcp", "sniper-project-audit"):
        (scripts / name).write_text(entrypoint, encoding="utf-8")

    result = setup.setup_community(root, core_only=True)

    assert result["status"] == "ready"
    assert result["optional_tools"] == {"status": "skipped", "reason": "core_only"}
    assert result["support_level"] == "supported"
    assert result["platform_tested"] is True
    assert (root / ".venv" / "bin" / "python").exists()
    assert not (root / "runtimes").exists()


def test_setup_cli_advertises_explicit_core_only_mode() -> None:
    completed = subprocess.run(
        [str(Path(setup.sys.executable)), "scripts/setup-community", "--help"],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--core-only" in completed.stdout

