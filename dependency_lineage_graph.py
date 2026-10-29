"""Yerel depolar arasında exact-pinned PyPI dependency version lineage."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterable


FORMAT = "sniper-dependency-lineage-graph-v1"
MAX_REPOSITORIES = 300
MAX_REQUIREMENTS_FILES_PER_REPO = 100
MAX_REQUIREMENTS_BYTES = 1_000_000
MAX_PINS_PER_REPO = 10_000
MAX_EDGES = 1_000
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__",
})
_REPO_NAME_RE = re.compile(r"[^A-Za-z0-9._/\-]+")
_PIN_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[A-Za-z0-9,._\-]+\])?\s*==\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_\-]{0,127})(?P<tail>.*)$"
)
_HASH_TOKEN_RE = re.compile(r"--hash=sha256:[0-9a-fA-F]{64}\Z")


@dataclass(frozen=True)
class _Pin:
    repository: str
    package: str
    version: str
    file: str
    line: int


def _repository_name(value: str, root: Path) -> str:
    normalized = _REPO_NAME_RE.sub("-", str(value).replace("\\", "/")).strip("-/")[:160]
    return normalized or _REPO_NAME_RE.sub("-", root.name).strip("-")[:160] or "repository"


def _package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _requirements_file(path: Path) -> bool:
    lower = path.name.casefold()
    return (
        path.suffix.casefold() in {".txt", ".in"}
        and (lower.startswith("requirements") or "requirements" in {part.casefold() for part in path.parts})
    )


def _walk(root: Path) -> tuple[list[Path], bool]:
    found: list[Path] = []
    try:
        for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
            directories[:] = sorted(
                name for name in directories
                if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink()
            )
            for name in sorted(files):
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file() or not _requirements_file(path.relative_to(root)):
                    continue
                if len(found) >= MAX_REQUIREMENTS_FILES_PER_REPO:
                    return found, True
                found.append(path)
    except (OSError, ValueError):
        return found, False
    return found, False


def _read(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REQUIREMENTS_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None


def _parse_line(raw: str) -> tuple[str, str] | None:
    line = raw.strip()
    if not line or line.startswith(("#", "-", ".")) or ";" in line or " @ " in line:
        return None
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    match = _PIN_RE.fullmatch(line)
    if match is None:
        return None
    tail = match.group("tail").strip()
    if tail:
        tokens = tail.split()
        if not tokens or any(_HASH_TOKEN_RE.fullmatch(token) is None for token in tokens):
            return None
    return _package_name(match.group("name")), match.group("version")


def _pins(repository: str, root: Path) -> tuple[list[_Pin], bool]:
    pins: list[_Pin] = []
    files, truncated = _walk(root)
    for path in files:
        text = _read(path)
        if text is None:
            continue
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            parsed = _parse_line(line)
            if parsed is None:
                continue
            if len(pins) >= MAX_PINS_PER_REPO:
                return pins, True
            package, version = parsed
            pins.append(_Pin(repository, package, version, relative, number))
    return sorted(set(pins), key=lambda pin: (pin.package, pin.version, pin.file, pin.line)), truncated


def build(repositories: Iterable[tuple[str, Path]]) -> dict:
    """Farklı yerel depolardaki aynı PyPI kimliğinin kesin sürüm drift kenarlarını üretir."""
    normalized: list[tuple[str, Path]] = []
    truncated = False
    for raw_name, raw_root in repositories:
        if len(normalized) >= MAX_REPOSITORIES:
            truncated = True
            break
        root = Path(raw_root)
        try:
            if root.is_symlink() or not root.is_dir():
                continue
        except OSError:
            continue
        name = _repository_name(str(raw_name), root)
        if all(existing != name for existing, _path in normalized):
            normalized.append((name, root))

    pins: list[_Pin] = []
    for name, root in normalized:
        repo_pins, repo_truncated = _pins(name, root)
        pins.extend(repo_pins)
        truncated = truncated or repo_truncated

    by_repo_package: dict[tuple[str, str], list[_Pin]] = {}
    for pin in pins:
        by_repo_package.setdefault((pin.repository, pin.package), []).append(pin)
    unambiguous: dict[tuple[str, str], _Pin] = {}
    for key, values in by_repo_package.items():
        versions = {value.version for value in values}
        if len(versions) == 1:
            unambiguous[key] = values[0]

    edges: list[dict] = []
    repositories_sorted = sorted(name for name, _root in normalized)
    packages = sorted({package for _repository, package in unambiguous})
    for package in packages:
        for left_index, left_repo in enumerate(repositories_sorted):
            left_pin = unambiguous.get((left_repo, package))
            if left_pin is None:
                continue
            for right_repo in repositories_sorted[left_index + 1:]:
                right_pin = unambiguous.get((right_repo, package))
                if right_pin is None or left_pin.version == right_pin.version:
                    continue
                if len(edges) >= MAX_EDGES:
                    truncated = True
                    break
                edges.append({
                    "left": "repo:" + left_repo,
                    "right": "repo:" + right_repo,
                    "ecosystem": "pypi",
                    "package": package,
                    "relation": "version-drift",
                    "versions": {"left": left_pin.version, "right": right_pin.version},
                    "evidence": {
                        "left": {"file": left_pin.file, "line": left_pin.line},
                        "right": {"file": right_pin.file, "line": right_pin.line},
                    },
                })
            if len(edges) >= MAX_EDGES:
                break
        if len(edges) >= MAX_EDGES:
            break

    repo_ids = sorted({edge[side][5:] for edge in edges for side in ("left", "right")})
    nodes = [{"id": "repo:" + repository, "repository": repository} for repository in repo_ids]
    return {
        "format": FORMAT,
        "summary": {
            "repositories": len(normalized),
            "nodes": len(nodes),
            "edges": len(edges),
            "packages_with_drift": len({edge["package"] for edge in edges}),
            "truncated": truncated,
        },
        "nodes": nodes,
        "edges": edges,
    }
