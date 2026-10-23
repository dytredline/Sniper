from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path

EXCLUDED_DIR_NAMES = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git"}
)
_REMOTE_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash|dash|zsh)\b",
    re.IGNORECASE,
)
_ROOT_SPECS = frozenset({"root", "0"})


def _join_dockerfile_logical_lines(dockerfile_text: str) -> list[str]:
    logical_lines: list[str] = []
    current: list[str] = []
    for raw_line in dockerfile_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current.append(stripped[:-1].strip())
        else:
            current.append(stripped)
            logical_lines.append(" ".join(part for part in current if part))
            current = []
    if current:
        logical_lines.append(" ".join(part for part in current if part))
    return logical_lines


def _validate_dockerfile(dockerfile_text: str) -> str:
    logical_lines = _join_dockerfile_logical_lines(dockerfile_text)
    if not logical_lines:
        raise ValueError("Dockerfile boş")

    has_from = False
    user_specs: list[str] = []

    for line in logical_lines:
        parts = line.split(None, 1)
        if not parts:
            continue
        instruction = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""

        if instruction == "FROM":
            if not rest:
                raise ValueError("Dockerfile'da geçersiz FROM talimatı")
            has_from = True
        elif instruction == "ADD":
            lowered_rest = rest.lower()
            if "http://" in lowered_rest or "https://" in lowered_rest or "ftp://" in lowered_rest:
                raise ValueError("Dockerfile'da sabitlenmemiş uzak ADD URL'si yasak")
        elif instruction == "USER":
            if not rest:
                raise ValueError("Dockerfile'da boş USER talimatı")
            user_specs.append(rest)

        if _REMOTE_PIPE_RE.search(line):
            raise ValueError("Dockerfile'da uzak kabuk borusu çalıştırma yasak")

    if not has_from:
        raise ValueError("Dockerfile geçerli bir FROM talimatı içermeli")
    if not user_specs:
        raise ValueError("Dockerfile root olmayan bir USER talimatı bildirmeli")

    final_user_spec = user_specs[-1].strip()
    user_group_parts = [part.strip().lower() for part in final_user_spec.split(":", 1)]
    primary_user = user_group_parts[0]
    if not primary_user or primary_user in _ROOT_SPECS:
        raise ValueError("Dockerfile son USER değeri root olmamalı")
    if len(user_group_parts) > 1 and user_group_parts[1] in _ROOT_SPECS:
        raise ValueError("Dockerfile son USER grubu root olmamalı")

    return final_user_spec


def _is_excluded_relative_file(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    if any(part in EXCLUDED_DIR_NAMES for part in parts):
        return True
    filename = parts[-1]
    if filename.endswith((".pyc", ".pyo")):
        return True
    if parts[0] == "data" and fnmatch.fnmatch(filename, "*.db*"):
        return True
    return False


def build_offline_candidate_image_manifest(
    app_dir: Path | str,
) -> dict[str, object]:
    """Validate candidate app_dir & Dockerfile and compute a reproducible offline image manifest."""
    if isinstance(app_dir, str):
        if not app_dir.strip():
            raise ValueError("app_dir boş olmayan bir yol olmalı")
        root_path = Path(app_dir)
    elif isinstance(app_dir, Path):
        root_path = app_dir
    else:
        raise ValueError("app_dir bir Path veya str olmalı")

    if not root_path.is_absolute():
        raise ValueError("app_dir mutlak bir yol olmalı")
    if root_path.is_symlink() or not root_path.exists() or not root_path.is_dir():
        raise ValueError("app_dir mevcut, sembolik bağ olmayan bir dizin olmalı")

    dockerfile_path = root_path / "Dockerfile"
    server_path = root_path / "server.py"
    for required_path, label in ((dockerfile_path, "Dockerfile"), (server_path, "server.py")):
        if required_path.is_symlink() or not required_path.exists() or not required_path.is_file():
            raise ValueError(f"Gerekli normal dosya eksik veya sembolik bağlı: {label}")

    dockerfile_bytes = dockerfile_path.read_bytes()
    try:
        dockerfile_text = dockerfile_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Dockerfile geçerli UTF-8 olmalı") from exc

    runtime_user = _validate_dockerfile(dockerfile_text)
    dockerfile_sha256 = hashlib.sha256(dockerfile_bytes).hexdigest()

    file_records: list[dict[str, str]] = []
    for current_root, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
        current_path = Path(current_root)
        kept_dirs: list[str] = []
        for dname in sorted(dirnames):
            if dname in EXCLUDED_DIR_NAMES:
                continue
            dpath = current_path / dname
            if dpath.is_symlink():
                raise ValueError("Aday app_dir içinde sembolik bağlı dizine izin verilmiyor")
            kept_dirs.append(dname)
        dirnames[:] = kept_dirs

        for fname in sorted(filenames):
            fpath = current_path / fname
            rel_posix = fpath.relative_to(root_path).as_posix()
            if _is_excluded_relative_file(rel_posix):
                continue
            if fpath.is_symlink():
                raise ValueError("Aday app_dir içinde sembolik bağlı dosyaya izin verilmiyor")
            if not fpath.is_file():
                continue
            digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
            file_records.append({"path": rel_posix, "sha256": digest})

    file_records.sort(key=lambda item: item["path"])
    canonical_tree = json.dumps(file_records, sort_keys=True, separators=(",", ":"))
    tree_sha256 = hashlib.sha256(canonical_tree.encode("utf-8")).hexdigest()

    return {
        "schema": "SNIPER_OFFLINE_CANDIDATE_IMAGE_MANIFEST_V1",
        "nonroot_user_enforced": True,
        "networkless_build_compatible": True,
        "runtime_user": runtime_user,
        "dockerfile_sha256": dockerfile_sha256,
        "file_count": len(file_records),
        "tree_sha256": tree_sha256,
    }
