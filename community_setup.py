"""Rootless one-command setup orchestration for a Sniper Community checkout."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any


MINIMUM_PYTHON = (3, 12)
RUNTIME_LOCK = "requirements-runtime.lock"
TOOL_INSTALLER = Path("scripts/install-community-tools")
VERIFIED_ENTRYPOINTS = (Path("scripts/sniper-mcp"), Path("scripts/sniper-project-audit"))
PYTHON_PROBE = (
    "import json,sys;"
    "print(json.dumps({'implementation':sys.implementation.name,"
    "'version':list(sys.version_info[:3]),'prefix':sys.prefix,"
    "'base_prefix':sys.base_prefix}))"
)


class SetupError(RuntimeError):
    pass


def _platform_system() -> str:
    """Small injection seam for the platform-specific venv/tool policy."""
    return platform.system()


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


def _trusted_venv_python(environment: Path) -> Path | None:
    """Accept a regular venv Python or its standard link to this interpreter's base executable."""
    candidate = environment / "bin" / "python"
    try:
        if not candidate.exists() or not os.access(candidate, os.X_OK):
            return None
        if not candidate.is_symlink():
            return candidate if candidate.is_file() else None
        resolved = candidate.resolve(strict=True)
        allowed = {
            Path(sys.executable).resolve(strict=True),
            Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True),
        }
        return candidate if resolved in allowed and resolved.is_file() else None
    except (OSError, RuntimeError):
        return None


def _run(command: list[str], *, root: Path, stage: str) -> None:
    try:
        subprocess.run(command, cwd=root, check=True, stdout=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SetupError(f"Community setup failed during {stage}") from exc


def _verify_venv_python(python: Path, environment: Path, *, root: Path) -> None:
    """Fail closed unless the selected executable is CPython 3.12+ in this venv."""
    try:
        completed = subprocess.run(
            [str(python), "-I", "-c", PYTHON_PROBE],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        payload = json.loads(completed.stdout)
        version = tuple(payload["version"])
        prefix = Path(payload["prefix"]).resolve(strict=True)
        base_prefix = Path(payload["base_prefix"]).resolve(strict=True)
        expected_prefix = environment.resolve(strict=True)
        if (
            payload["implementation"] != "cpython"
            or len(version) != 3
            or not all(isinstance(part, int) for part in version)
            or version < MINIMUM_PYTHON
            or prefix != expected_prefix
            or base_prefix == prefix
        ):
            raise ValueError("unexpected interpreter identity")
    except (OSError, subprocess.CalledProcessError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SetupError(
            "Virtual environment must provide CPython 3.12 or newer from its own prefix"
        ) from exc


def setup_community(
    repo_root: Path,
    *,
    venv_dir: Path = Path(".venv"),
    install_dir: Path = Path("runtimes"),
    cache_dir: Path | None = None,
    wheelhouse: Path | None = None,
    accept_third_party_licenses: bool = False,
    core_only: bool = False,
) -> dict[str, Any]:
    """Install the portable core or Linux tool profile, then verify side-effect-free help."""
    platform_system = _platform_system().lower()
    if platform_system == "windows":
        raise SetupError("Native Windows is unavailable; use the Linux core through WSL2 or Docker")
    if platform_system not in {"linux", "darwin"}:
        raise SetupError(f"Unsupported native platform: {platform_system or 'unknown'}; use a Linux container")
    if not core_only and not accept_third_party_licenses:
        raise SetupError("Explicit third-party license acceptance is required")
    if core_only and cache_dir is not None:
        raise SetupError("Offline tool cache cannot be used with core-only setup")
    if not core_only and platform_system != "linux":
        raise SetupError("The locked local tool profile requires Linux; use --core-only on this platform")
    if sys.version_info < MINIMUM_PYTHON:
        raise SetupError("Sniper Community setup requires Python 3.12 or newer")

    root_input = Path(repo_root).expanduser()
    if root_input.is_symlink() or not root_input.is_dir():
        raise SetupError("Repository root must be a normal directory, not a symbolic link")
    root = root_input.resolve()
    lock = root / RUNTIME_LOCK
    installer = root / TOOL_INSTALLER
    if not _regular_file(lock) or (not core_only and not _regular_file(installer, executable=True)):
        raise SetupError("Community runtime lock or tool installer is unavailable")
    for relative in VERIFIED_ENTRYPOINTS:
        if not _regular_file(root / relative, executable=not core_only):
            raise SetupError(f"Required Community entrypoint is unavailable: {relative.as_posix()}")

    runtime_root: Path | None = None
    if not core_only:
        runtime_root = _absolute_from(root, Path(install_dir))
        expected_runtime_root = root / "runtimes"
        if runtime_root != expected_runtime_root:
            raise SetupError("One-command setup must use the discoverable repository runtimes directory")
        if runtime_root.is_symlink():
            raise SetupError("Tool runtime directory cannot be a symbolic link")

    environment = _absolute_from(root, Path(venv_dir))
    if environment.is_symlink():
        raise SetupError("Virtual environment cannot be a symbolic link")
    environment_python = _trusted_venv_python(environment)
    if environment_python is None:
        if environment.exists():
            raise SetupError("Existing virtual environment is incomplete")
        _run([sys.executable, "-m", "venv", str(environment)], root=root, stage="venv creation")
        environment_python = _trusted_venv_python(environment)
        if environment_python is None:
            raise SetupError("Virtual environment did not provide an executable Python")

    _verify_venv_python(environment_python, environment, root=root)

    pip_command = [
        str(environment_python), "-m", "pip", "install", "--no-deps",
    ]
    if wheelhouse is not None:
        wheels = _absolute_from(root, Path(wheelhouse))
        if wheels.is_symlink() or not wheels.is_dir():
            raise SetupError("Offline wheelhouse must be a normal directory")
        pip_command.extend(["--no-index", "--find-links", str(wheels)])
    pip_command.extend(["-r", str(lock)])
    _run(pip_command, root=root, stage="runtime dependency installation")
    _run(
        [str(environment_python), "-m", "pip", "check"],
        root=root,
        stage="runtime dependency verification",
    )

    if not core_only:
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
    result: dict[str, Any] = {
        "format": "sniper-community-setup-result-v1",
        "status": "ready",
        "venv": displayed_venv,
        "tools_profile": "core" if core_only else "local",
        "verified_entrypoints": [path.as_posix() for path in VERIFIED_ENTRYPOINTS],
    }
    if core_only:
        result["optional_tools"] = {"status": "skipped", "reason": "core_only"}
        result["support_level"] = "supported" if platform_system in {"linux", "darwin"} else "experimental"
        result["platform_tested"] = platform_system in {"linux", "darwin"}
    return result
