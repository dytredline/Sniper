"""Monorepo alt proje tespiti ve alt proje başına özet (yalnız yerel dosyalar; ağ yok, yazma yok).

Bildirimli çalışma alanları (önce bunlara bakılır):
* npm/yarn ``package.json`` ``workspaces`` (dizi ya da ``{"packages": [...]}``), ``pnpm-workspace.yaml``, ``lerna.json``
* Go ``go.work`` (``use``), Cargo ``[workspace] members``/``exclude``
* Maven ``<modules>``, Gradle ``settings.gradle(.kts)`` ``include``, .NET çözüm dosyası (``*.sln``)

Bildirim yoksa: kökün dışında (derinlik ≤2) bağımlılık bildirimi olan en az iki ayrı dizin "örtük" alt proje sayılır
(ör. ``frontend/package.json`` + ``backend/requirements.txt``).

Özet: her dosya en uzun önek eşleşmesiyle tek alt projeye düşer (eşleşmeyen dosyalar "kök"). Alt proje başına dosya
sayısı, diller, önem dağılımı, bildirim dosyaları ve bağımlılık envanteri (dependency_security.discover_inventory;
alt proje dizininin kendi kilit/bildirim dosyaları) verilir. Desen genişletme yalnız kök altında, sembolik bağ
izlemeden, varsayılan atlanan dizinlere (node_modules, vendor, .git …) girmeden ve sınırlı derinlikte yapılır.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tomllib
from typing import Any, Iterable

import scan_scope

MAX_SUBPROJECTS = 200
MAX_DEP_INVENTORY = 100
MAX_SCAN_DIRS = 20_000
MAX_DEPTH = 5
MAX_READ = 512_000
SEVERITIES = ("critical", "high", "medium", "low", "info")
ROOT_KEY = "."
# Örtük alt proje tespitinde sayılan bağımlılık bildirimleri (docker-compose, CI dosyaları sayılmaz).
DEPENDENCY_MANIFESTS = frozenset({
    "package.json", "requirements.txt", "pyproject.toml", "pipfile", "setup.py", "cargo.toml", "go.mod", "gemfile",
    "composer.json", "pom.xml", "build.gradle", "build.gradle.kts", "pubspec.yaml", "podfile",
})


def _read(path: Path) -> str | None:
    """Kök altındaki düzenli dosyayı sınırlı oku (sembolik bağ yok)."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_READ:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _clean_rel(value: str) -> str | None:
    rel = value.strip().strip("\"'").replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    rel = rel.rstrip("/")
    if not rel or rel == "." or rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts) or None


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


class _Tree:
    """Kök altındaki dizinlerin (göreli, POSIX) sınırlı listesi; desen genişletme için bir kez yürünür."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.dirs: list[str] = []
        skip = scan_scope.DEFAULT_SKIP_DIRS
        for current, directories, _files in os.walk(root, followlinks=False):
            rel = Path(current).relative_to(root)
            depth = len(rel.parts)
            kept = []
            for name in sorted(directories):
                if name.casefold() in skip or name.startswith(".") or (Path(current) / name).is_symlink():
                    continue
                kept.append(name)
                self.dirs.append((rel / name).as_posix())
            directories[:] = kept if depth + 1 < MAX_DEPTH else []
            if len(self.dirs) >= MAX_SCAN_DIRS:
                break

    def expand(self, patterns: Iterable[str], marker: str | None = None) -> list[str]:
        include: list[re.Pattern[str]] = []
        exclude: list[re.Pattern[str]] = []
        for raw in patterns:
            if not isinstance(raw, str):
                continue
            negate = raw.strip().startswith("!")
            rel = _clean_rel(raw.strip().lstrip("!"))
            if rel is None:
                continue
            (exclude if negate else include).append(_pattern_regex(rel))
        found = []
        for rel in self.dirs:
            if any(p.match(rel) for p in include) and not any(p.match(rel) for p in exclude):
                if marker is None or (self.root / rel / marker).is_file():
                    found.append(rel)
        return found


def _npm_patterns(root: Path) -> list[str]:
    patterns: list[str] = []
    text = _read(root / "package.json")
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        workspaces = data.get("workspaces") if isinstance(data, dict) else None
        if isinstance(workspaces, dict):
            workspaces = workspaces.get("packages")
        if isinstance(workspaces, list):
            patterns += [w for w in workspaces if isinstance(w, str)]
    text = _read(root / "pnpm-workspace.yaml") or _read(root / "pnpm-workspace.yml")
    if text:
        in_packages = False
        for line in text.splitlines():
            if re.match(r"^packages\s*:", line):
                in_packages = True
                continue
            if in_packages:
                m = re.match(r"^\s*-\s*['\"]?([^'\"#]+?)['\"]?\s*(?:#.*)?$", line)
                if m:
                    patterns.append(m.group(1).strip())
                elif line.strip() and not line.startswith((" ", "\t", "-")):
                    in_packages = False
    text = _read(root / "lerna.json")
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("packages"), list):
            patterns += [w for w in data["packages"] if isinstance(w, str)]
    return patterns


def _go_work(root: Path) -> list[str]:
    text = _read(root / "go.work")
    if not text:
        return []
    text = re.sub(r"//[^\n]*", "", text)
    uses: list[str] = []
    for block in re.findall(r"\buse\s*\(([^)]*)\)", text):
        uses += block.split()
    uses += re.findall(r"^\s*use\s+([^\s(]+)\s*$", text, re.M)
    return [u for u in (_clean_rel(u) for u in uses) if u]


def _cargo(root: Path) -> tuple[list[str], list[str]]:
    text = _read(root / "Cargo.toml")
    if not text:
        return [], []
    try:
        workspace = tomllib.loads(text).get("workspace")
    except (tomllib.TOMLDecodeError, ValueError):
        return [], []
    if not isinstance(workspace, dict):
        return [], []
    members = [m for m in workspace.get("members") or [] if isinstance(m, str)]
    exclude = [m for m in workspace.get("exclude") or [] if isinstance(m, str)]
    return members, exclude


def _maven(root: Path) -> list[str]:
    text = _read(root / "pom.xml")
    if not text:
        return []
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    return [m for m in (_clean_rel(x) for x in re.findall(r"<module>\s*([^<]+?)\s*</module>", text)) if m]


def _gradle(root: Path) -> list[str]:
    text = _read(root / "settings.gradle") or _read(root / "settings.gradle.kts")
    if not text:
        return []
    text = re.sub(r"//[^\n]*", "", text)
    found: list[str] = []
    for args in re.findall(r"\binclude(?!Build)\b\s*\(?([^\n)]*)\)?", text):
        for name in re.findall(r"['\"]([^'\"]+)['\"]", args):
            rel = _clean_rel(name.strip(":").replace(":", "/"))
            if rel:
                found.append(rel)
    return found


def _dotnet(root: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    try:
        solutions = sorted(p for p in root.iterdir() if p.suffix.casefold() == ".sln" and p.is_file() and not p.is_symlink())
    except OSError:
        return []
    for sln in solutions[:5]:
        text = _read(sln) or ""
        for name, project in re.findall(r'^Project\("[^"]*"\)\s*=\s*"([^"]+)"\s*,\s*"([^"]+\.(?:cs|fs|vb)proj)"', text, re.M):
            rel = _clean_rel(project)
            if rel and "/" in rel:
                found.append((rel.rsplit("/", 1)[0], name))
    return found


def detect(root: Path, manifests: Iterable[str] = ()) -> dict[str, Any] | None:
    """Alt projeleri bul: [{path, kind, name}] (en çok MAX_SUBPROJECTS). Bulunamazsa None."""
    root = Path(root)
    tree: _Tree | None = None

    def get_tree() -> _Tree:
        nonlocal tree
        if tree is None:
            tree = _Tree(root)
        return tree

    found: dict[str, dict[str, str]] = {}
    kinds: list[str] = []

    def add(rel: str, kind: str, name: str = "") -> None:
        if rel in found or len(found) >= MAX_SUBPROJECTS:
            return
        path = root / rel
        try:
            if path.is_symlink() or not path.is_dir() or not path.resolve().is_relative_to(root.resolve()):
                return
        except OSError:
            return
        if any(part.casefold() in scan_scope.DEFAULT_SKIP_DIRS for part in Path(rel).parts):
            return
        found[rel] = {"path": rel, "kind": kind, "name": name or Path(rel).name}
        if kind not in kinds:
            kinds.append(kind)

    npm = _npm_patterns(root)
    if npm:
        for rel in get_tree().expand(npm, "package.json"):
            add(rel, "npm")
    for rel in _go_work(root):
        add(rel, "go")
    members, exclude = _cargo(root)
    if members:
        excluded = set(get_tree().expand(exclude)) if exclude else set()
        for rel in get_tree().expand(members, "Cargo.toml"):
            if rel not in excluded:
                add(rel, "cargo")
    for rel in _maven(root):
        add(rel, "maven")
    for rel in _gradle(root):
        add(rel, "gradle")
    for rel, name in _dotnet(root):
        add(rel, "dotnet", name)
    declared = bool(found)
    if not declared:
        dirs = set()
        for manifest in manifests:
            rel = Path(str(manifest).replace("\\", "/"))
            if rel.name.casefold() not in DEPENDENCY_MANIFESTS:
                continue
            parent = rel.parent.as_posix()
            if parent in ("", ".") or len(rel.parent.parts) > 2:
                continue
            if any(part.casefold() in scan_scope.DEFAULT_SKIP_DIRS for part in rel.parent.parts):
                continue
            dirs.add(parent)
        # iç içe dizinlerde yalnız en üstteki (ör. "web" varken "web/admin" ayrı sayılmaz)
        tops = sorted(d for d in dirs if not any(d != o and d.startswith(o + "/") for o in dirs))
        if len(tops) >= 2:
            for rel in tops:
                add(rel, "implicit")
    if not found:
        return None
    return {"declared": declared, "kinds": kinds, "subprojects": sorted(found.values(), key=lambda s: s["path"])}


def _owner(rel_file: str, prefixes: list[str]) -> str:
    for prefix in prefixes:  # en uzun önek önce
        if rel_file == prefix or rel_file.startswith(prefix + "/"):
            return prefix
    return ROOT_KEY


def _dependencies(root: Path, rel: str) -> dict[str, Any] | None:
    try:
        import dependency_security

        _root, components, _skipped = dependency_security.discover_inventory(str(root / rel), allowed_roots=(root,))
    except Exception:  # noqa: BLE001 - bağımlılık envanteri alt proje özetini durdurmaz
        return None
    by_ecosystem: dict[str, int] = {}
    dev = 0
    for component in components:
        eco = str(component.get("ecosystem") or "?")
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
        if component.get("scope") in ("dev", "development", "optional"):
            dev += 1
    return {"component_count": len(components), "by_ecosystem": dict(sorted(by_ecosystem.items())), "dev_count": dev}


def summarize(root: Path, manifests: Iterable[str], file_index: Iterable[tuple[str, str]],
              findings: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """Proje analizine eklenen alt proje özeti; tek projeli depolarda None."""
    manifests = list(manifests)
    detected = detect(root, manifests)
    if detected is None:
        return None
    subs = detected["subprojects"]
    prefixes = sorted((s["path"] for s in subs), key=len, reverse=True)
    rows: dict[str, dict[str, Any]] = {
        s["path"]: {**s, "file_count": 0, "languages": {}, "finding_counts": {k: 0 for k in SEVERITIES},
                    "finding_count": 0, "manifests": []}
        for s in subs
    }
    root_row = {"path": ROOT_KEY, "kind": "root", "name": "(kök)", "file_count": 0, "languages": {},
                "finding_counts": {k: 0 for k in SEVERITIES}, "finding_count": 0, "manifests": []}

    def row_for(rel: str) -> dict[str, Any]:
        return rows.get(_owner(rel, prefixes), root_row)

    for rel, language in file_index:
        row = row_for(rel)
        row["file_count"] += 1
        if language:
            row["languages"][language] = row["languages"].get(language, 0) + 1
    for finding in findings:
        rel = str(finding.get("file") or "").replace("\\", "/")
        row = row_for(rel) if rel and rel != "Proje geneli" else root_row
        severity = finding.get("severity")
        if severity in row["finding_counts"]:
            row["finding_counts"][severity] += 1
        row["finding_count"] += 1
    for manifest in manifests:
        rel = str(manifest).replace("\\", "/")
        row_for(rel)["manifests"].append(rel)
    ordered = [rows[s["path"]] for s in subs]
    for index, row in enumerate(ordered):
        row["languages"] = dict(sorted(row["languages"].items(), key=lambda item: (-item[1], item[0]))[:6])
        row["manifests"] = sorted(row["manifests"])[:20]
        row["dependencies"] = _dependencies(Path(root), row["path"]) if index < MAX_DEP_INVENTORY else None
    root_row["languages"] = dict(sorted(root_row["languages"].items(), key=lambda item: (-item[1], item[0]))[:6])
    root_row["manifests"] = sorted(root_row["manifests"])[:20]
    return {
        "format": 1,
        "declared": detected["declared"],
        "kinds": detected["kinds"],
        "count": len(ordered),
        "subprojects": ordered,
        "root": root_row,
        "truncated": len(ordered) >= MAX_SUBPROJECTS,
    }
