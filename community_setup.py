"""Rootless one-command setup orchestration for a Sniper Community checkout."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from typing import Any


MINIMUM_PYTHON = (3, 12)
RUNTIME_LOCK = "requirements-runtime.lock"
TOOL_INSTALLER = Path("scripts/install-community-tools")
VERIFIED_ENTRYPOINTS = (Path("scripts/sniper-mcp"), Path("scripts/sniper-project-audit"))


class SetupError(RuntimeError):
    pass


def _regular_file(path: Path, *, executable: bool = False) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and (
            not executable or os.access(path, os.X_OK)
        )
    except OSError:
        return False


def _absolute_from(root: Path, value: Path) -> Path:
    candidate = value.expanduser()
    return candidate if candidate.is_absolute() else root / candidate


def _run(command: list[str], *, root: Path, stage: str) -> None:
    try:
        subprocess.run(command, cwd=root, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SetupError(f"Community setup failed during {stage}") from exc


def setup_community(
    repo_root: Path,
    *,
    venv_dir: Path = Path(".venv"),
    install_dir: Path = Path("runtimes"),
    cache_dir: Path | None = None,
    wheelhouse: Path | None = None,
    accept_third_party_licenses: bool = False,
) -> dict[str, Any]:
    """Install runtime dependencies/tools and verify side-effect-free entrypoint help."""
    if not accept_third_party_licenses:
        raise SetupError("Explicit third-party license acceptance is required")
    if sys.version_info < MINIMUM_PYTHON:
        raise SetupError("Sniper Community setup requires Python 3.12 or newer")

    root_input = Path(repo_root).expanduser()
    if root_input.is_symlink() or not root_input.is_dir():
        raise SetupError("Repository root must be a normal directory, not a symbolic link")
    root = root_input.resolve()
    lock = root / RUNTIME_LOCK
    installer = root / TOOL_INSTALLER
    if not _regular_file(lock) or not _regular_file(installer, executable=True):
        raise SetupError("Community runtime lock or tool installer is unavailable")
    for relative in VERIFIED_ENTRYPOINTS:
        if not _regular_file(root / relative, executable=True):
            raise SetupError(f"Required Community entrypoint is unavailable: {relative.as_posix()}")

    environment = _absolute_from(root, Path(venv_dir))
    if environment.is_symlink():
        raise SetupError("Virtual environment cannot be a symbolic link")
    environment_python = environment / "bin" / "python"
    if not _regular_file(environment_python, executable=True):
        if environment.exists():
            raise SetupError("Existing virtual environment is incomplete")
        _run([sys.executable, "-m", "venv", str(environment)], root=root, stage="venv creation")
        if not _regular_file(environment_python, executable=True):
            raise SetupError("Virtual environment did not provide an executable Python")

    pip_command = [
        str(environment_python), "-m", "pip", "install",
    ]
    if wheelhouse is not None:
        wheels = _absolute_from(root, Path(wheelhouse))
        if wheels.is_symlink() or not wheels.is_dir():
            raise SetupError("Offline wheelhouse must be a normal directory")
        pip_command.extend(["--no-index", "--find-links", str(wheels)])
    pip_command.extend(["-r", str(lock)])
    _run(pip_command, root=root, stage="runtime dependency installation")

    runtime_root = _absolute_from(root, Path(install_dir))
    if runtime_root.is_symlink():
        raise SetupError("Tool runtime directory cannot be a symbolic link")
    tool_command = [
        str(environment_python), str(installer), "--profile", "local",
        "--install-dir", str(runtime_root), "--accept-third-party-licenses",
    ]
    if cache_dir is not None:
        cache = _absolute_from(root, Path(cache_dir))
        if cache.is_symlink() or not cache.is_dir():
            raise SetupError("Offline tool cache must be a normal directory")
        tool_command.extend(["--cache-dir", str(cache)])
    _run(tool_command, root=root, stage="locked tool installation")

    for relative in VERIFIED_ENTRYPOINTS:
        _run(
            [str(environment_python), str(root / relative), "--help"],
            root=root,
            stage=f"{relative.name} verification",
        )

    try:
        displayed_venv = environment.relative_to(root).as_posix()
    except ValueError:
        displayed_venv = environment.name
    return {
        "format": "sniper-community-setup-result-v1",
        "status": "ready",
        "venv": displayed_venv,
        "tools_profile": "local",
        "verified_entrypoints": [path.as_posix() for path in VERIFIED_ENTRYPOINTS],
    }
