"""Yalnız değişenler: git tabanlı artımlı proje analizi ve "bu değişiklik yeni açık getirdi mi" karşılaştırması.

Güvenlik: taranan depo güvenilmezdir. git yalnız nesne veritabanını okuyan komutlarla çalıştırılır
(``rev-parse``, ``ls-tree``, ``cat-file``, ``ls-files``); çalışma ağacı ile taban sürüm Sniper tarafından ham
blob özetleriyle karşılaştırılır. Böylece deponun ``.git/config``/``.gitattributes`` ile tanımlayabileceği
clean/smudge süzgeçleri, textconv/harici diff ya da fsmonitor komutları hiç çalışmaz. Kabuk kullanılmaz,
genel/sistem git yapılandırması okunmaz, ağ protokolleri kapalıdır.
"""
from __future__ import annotations

from collections import Counter
import dataclasses
import difflib
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Iterable

import project_analyzer
from project_analyzer import ProjectRejected
import scan_scope
from scanner import utc_now

GIT_TIMEOUT_SECONDS = 60
MAX_LISTED_CHANGED = 500
MAX_LISTED_FIXED = 100
_SHA_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ChangedScanError(ProjectRejected):
    """git tabanlı artımlı tarama yapılamadı (depo yok, başvuru çözülemedi, git yok…)."""


# ---------------------------------------------------------------------------
# git (yalnız okuma, güvenli ortam)
# ---------------------------------------------------------------------------
def _git_binary() -> str:
    for candidate in ("/usr/bin/git", "/bin/git"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("git")
    if not found:
        raise ChangedScanError("git bulunamadı; yalnız değişenler modu kullanılamıyor.")
    return found


def _git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1",
    }


def _git(cwd: Path, *args: str, stdin: bytes | None = None) -> bytes:
    command = [
        _git_binary(),
        # Komut satırı ayarları depo yapılandırmasını geçersiz kılar: kanca/fsmonitor/ağ yok.
        "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.allow=never", "-c", "core.quotePath=false",
        "-C", str(cwd), *args,
    ]
    try:
        completed = subprocess.run(
            command, input=stdin, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, env=_git_env(), check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ChangedScanError("git komutu çalıştırılamadı veya süre aşıldı.") from exc
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        hint = message[-1][:200] if message else ""
        if "dubious ownership" in hint:
            hint = "depo başka bir kullanıcıya ait (git safe.directory)"
        raise ChangedScanError(f"git başarısız ({args[0]}): {hint}".strip())
    return completed.stdout


@dataclasses.dataclass
class BaseTree:
    repo_root: Path
    prefix: str  # projenin depo içindeki yolu ("" ya da "alt/dizin/")
    commit: str
    object_format: str
    blobs: dict[str, tuple[str, int]]  # proje köküne göre yol → (blob, boyut)


def resolve_base(project_root: Path, base_ref: str) -> BaseTree:
    """Projenin bulunduğu depoyu ve ``base_ref`` commit'ini çöz; taban ağacın proje altındaki blob'larını listele."""
    if not base_ref or base_ref.startswith("-") or ".." in base_ref:
        raise ChangedScanError("Geçersiz taban başvurusu.")
    top = _git(project_root, "rev-parse", "--show-toplevel").decode("utf-8", "replace").strip()
    if not top:
        raise ChangedScanError("Proje bir git deposu içinde değil.")
    repo_root = Path(top).resolve()
    try:
        prefix = project_root.resolve().relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise ChangedScanError("Proje dizini depo kökü altında değil.") from exc
    prefix = "" if prefix == "." else prefix.rstrip("/") + "/"
    try:
        object_format = _git(repo_root, "rev-parse", "--show-object-format").decode().strip() or "sha1"
    except ChangedScanError:
        object_format = "sha1"
    if object_format not in {"sha1", "sha256"}:
        raise ChangedScanError("Desteklenmeyen git nesne biçimi.")
    try:
        commit = _git(repo_root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{base_ref}^{{commit}}").decode().strip()
    except ChangedScanError:
        commit = ""
    if not _SHA_RE.fullmatch(commit):
        raise ChangedScanError(f"Taban başvurusu çözülemedi: {base_ref}")
    listing = _git(repo_root, "ls-tree", "-r", "-z", "-l", "--full-tree", commit)
    blobs: dict[str, tuple[str, int]] = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        parts = meta.split()
        if len(parts) != 4 or parts[1] != b"blob" or parts[0] not in (b"100644", b"100755"):
            continue  # sembolik bağ, alt modül, ağaç
        path = raw_path.decode("utf-8", "surrogateescape")
        if prefix and not path.startswith(prefix):
            continue
        rel = path[len(prefix):]
        if not _safe_relpath(rel):
            continue
        try:
            size = int(parts[3])
        except ValueError:
            continue
        blobs[rel] = (parts[2].decode(), size)
    return BaseTree(repo_root, prefix, commit, object_format, blobs)


def _safe_relpath(rel: str) -> bool:
    if not rel or rel.startswith("/") or "\\" in rel or "\0" in rel:
        return False
    return all(part not in ("", ".", "..", ".git") for part in rel.split("/"))


def _open_worktree_file(root: Path, rel: str) -> int | None:
    """Open a regular worktree file without following any path component.

    ``_walk_worktree`` deliberately yields names rather than open descriptors.  A
    hostile working tree can replace a yielded file or one of its parent
    directories before the consumer reads it.  Walking from a pinned root
    directory descriptor closes that check/use gap.
    """
    if not _safe_relpath(rel):
        return None
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(root, directory_flags)
    except (OSError, TypeError, ValueError):
        return None
    try:
        parts = rel.split("/")
        for part in parts[:-1]:
            try:
                child_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except OSError:
                return None
            os.close(directory_fd)
            directory_fd = child_fd
        try:
            fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                return None
        except OSError:
            os.close(fd)
            return None
        return fd
    finally:
        os.close(directory_fd)


def _read_worktree_bytes(
    root: Path,
    rel: str,
    max_bytes: int,
    *,
    truncate: bool = False,
) -> tuple[bytes, int] | None:
    """Read from one verified descriptor, returning ``(data, fstat_size)``.

    With ``truncate`` only the safe prefix is needed.  Otherwise a file that is
    already too large or grows beyond the budget is rejected.
    """
    if max_bytes < 0:
        return None
    fd = _open_worktree_file(root, rel)
    if fd is None:
        return None
    try:
        info = os.fstat(fd)
        if not truncate and info.st_size > max_bytes:
            return None
        limit = max_bytes if truncate else max_bytes + 1
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            try:
                chunk = os.read(fd, min(65536, limit - total))
            except OSError:
                return None
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if not truncate and total > max_bytes:
            return None
        return b"".join(chunks), info.st_size
    finally:
        os.close(fd)


def _read_worktree_text(root: Path, rel: str, max_bytes: int, *, truncate: bool = False) -> str | None:
    result = _read_worktree_bytes(root, rel, max_bytes, truncate=truncate)
    return None if result is None else result[0].decode("utf-8", errors="replace")


def _ignored_paths(base: BaseTree) -> tuple[set[str], tuple[str, ...]]:
    """Çalışma ağacında .gitignore ile yok sayılan izlenmeyen dosya/dizinler (proje köküne göre)."""
    raw = _git(base.repo_root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
    files: set[str] = set()
    dirs: list[str] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        path = item.decode("utf-8", "surrogateescape")
        if base.prefix and not path.startswith(base.prefix):
            if base.prefix.startswith(path) and path.endswith("/"):
                dirs.append("")  # projenin kendisi yok sayılan bir dizinde
            continue
        rel = path[len(base.prefix):]
        if rel.endswith("/"):
            dirs.append(rel)
        else:
            files.add(rel)
    return files, tuple(dirs)


def read_blobs(base: BaseTree, shas: Iterable[str]) -> dict[str, bytes]:
    """Ham blob içerikleri (``cat-file --batch``; süzgeç/smudge uygulanmaz)."""
    wanted = sorted(set(shas))
    if not wanted:
        return {}
    out = _git(base.repo_root, "cat-file", "--batch", stdin=("\n".join(wanted) + "\n").encode())
    blobs: dict[str, bytes] = {}
    pos = 0
    while pos < len(out):
        end = out.index(b"\n", pos)
        header = out[pos:end].split()
        pos = end + 1
        if len(header) != 3 or header[1] != b"blob":
            continue  # "missing"
        size = int(header[2])
        blobs[header[0].decode()] = out[pos:pos + size]
        pos += size + 1
    return blobs


def _blob_id(data: bytes, object_format: str) -> str:
    # git nesne kimliği (depo biçimi gereği SHA-1/SHA-256); güvenlik amaçlı özet değil.
    digest = hashlib.sha256() if object_format == "sha256" else hashlib.sha1(usedforsecurity=False)
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Değişiklik kümesi
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class ChangeSet:
    base: BaseTree
    added: set[str]
    modified: set[str]
    deleted: set[str]
    renamed: dict[str, str]  # yeni yol → eski yol (içerik aynı)
    current_blobs: dict[str, str]

    @property
    def changed(self) -> set[str]:
        return self.added | self.modified


def _walk_worktree(root: Path, skip_dirs: frozenset[str]) -> Iterable[str]:
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name != ".git" and name.casefold() not in skip_dirs and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            yield path.relative_to(root).as_posix()


def compute_changes(project_root: Path, base: BaseTree, scope: scan_scope.ScanScope) -> ChangeSet:
    ignored_files, ignored_dirs = _ignored_paths(base)
    skip_dirs = scope.skip_dirs
    current: dict[str, str] = {}
    added: set[str] = set()
    modified: set[str] = set()
    for rel in _walk_worktree(project_root, skip_dirs):
        tracked = base.blobs.get(rel)
        if tracked is None and (rel in ignored_files or any(rel.startswith(d) for d in ignored_dirs)):
            continue
        opened = _read_worktree_bytes(
            project_root,
            rel,
            max(scope.max_file_bytes, project_analyzer.MAX_FILE_BYTES),
        )
        if opened is None:
            continue
        data, size = opened
        if tracked is not None and tracked[1] != size:
            modified.add(rel)
            continue
        blob = _blob_id(data, base.object_format)
        current[rel] = blob
        if tracked is None:
            added.add(rel)
        elif tracked[0] != blob:
            modified.add(rel)
    present = set(current) | modified
    deleted = {
        rel for rel in base.blobs
        if rel not in present and not (project_root / rel).exists()
        and not any(part.casefold() in skip_dirs for part in rel.split("/")[:-1])
    }
    # İçeriği aynı kalan yeniden adlandırmalar değişiklik sayılmaz.
    deleted_by_blob = {base.blobs[rel][0]: rel for rel in deleted}
    renamed = {rel: deleted_by_blob[current[rel]] for rel in added if current.get(rel) in deleted_by_blob}
    added -= set(renamed)
    deleted -= set(renamed.values())
    return ChangeSet(base, added, modified, deleted, renamed, current)


def changed_lines(old: bytes | None, new_text: str) -> set[int] | None:
    """Yeni sürümde eklenen/değişen satırlar (1 tabanlı). ``old`` yoksa (yeni dosya) ``None`` = tüm dosya."""
    if old is None:
        return None
    a = old.decode("utf-8", "replace").splitlines()
    b = new_text.splitlines()
    lines: set[int] = set()
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "insert"):
            lines.update(range(j1 + 1, j2 + 1))
    return lines


# ---------------------------------------------------------------------------
# Dosyalar arası bağlam: içe aktarma komşuluğu
# ---------------------------------------------------------------------------
PY_SUFFIX = ".py"
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts")
FORWARD_DEPTH = 2
CONTEXT_MAX_SHARE = 0.6
_PY_IMPORT_RE = re.compile(r"^[ \t]*(?:from[ \t]+(\.*[\w.]*)[ \t]+import[ \t]+\(?([^#\n]*)|import[ \t]+([^#\n]+))", re.M)
_JS_SPEC_RE = re.compile(r"""(?:require\(\s*|\bfrom\s+|\bimport\s*\(\s*|^\s*import\s+)['"](\.{1,2}/[^'"\n]+)['"]""", re.M)


def _py_module_names(rel: str) -> list[str]:
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return []
    names = [".".join(parts)]
    for strip in (1, 2):  # alt kaynak kökü (app/, src/) takma adları
        if len(parts) - strip >= 1:
            names.append(".".join(parts[strip:]))
    return names


def _py_imports(rel: str, text: str) -> set[str]:
    package = rel[:-3].split("/")[:-1] if not rel.endswith("__init__.py") else rel.split("/")[:-1]
    found: set[str] = set()
    for match in _PY_IMPORT_RE.finditer(text):
        module, names, plain = match.groups()
        if plain is not None:
            found.update(item.split(" as ")[0].strip() for item in plain.split(",") if item.strip())
            continue
        dots = len(module) - len(module.lstrip("."))
        base = module.lstrip(".")
        if dots:
            anchor = package[: len(package) - (dots - 1)] if dots - 1 <= len(package) else []
            base = ".".join([*anchor, base] if base else anchor)
        if base:
            found.add(base)
        for item in (names or "").replace(")", "").split(","):
            name = item.split(" as ")[0].strip()
            if name and name != "*" and name.isidentifier():
                found.add(f"{base}.{name}" if base else name)
    return found


def _js_imports(rel: str, text: str, files: set[str]) -> set[str]:
    directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
    found: set[str] = set()
    for spec in _JS_SPEC_RE.findall(text):
        joined = os.path.normpath(os.path.join(directory, spec)).replace(os.sep, "/")
        if joined.startswith("../") or joined == "..":
            continue
        for candidate in (joined, *(joined + ext for ext in JS_SUFFIXES), *(f"{joined}/index{ext}" for ext in JS_SUFFIXES)):
            if candidate in files:
                found.add(candidate)
                break
    return found


def import_context(project_root: Path, changed: set[str], scope: scan_scope.ScanScope) -> frozenset[str] | None:
    """Değişen kaynak dosyalar + ileri (en çok FORWARD_DEPTH adım) içe aktardıkları + onları (geçişli) içe
    aktaranlar. Bağlam projenin büyük kısmını kapsıyorsa ``None`` (tüm proje)."""
    sources = [rel for rel in _walk_worktree(project_root, scope.skip_dirs)
               if rel.endswith(PY_SUFFIX) or rel.endswith(JS_SUFFIXES)]
    files = set(sources)
    by_module: dict[str, set[str]] = {}
    for rel in sources:
        if rel.endswith(PY_SUFFIX):
            for name in _py_module_names(rel):
                by_module.setdefault(name, set()).add(rel)
    forward: dict[str, set[str]] = {}
    for rel in sources:
        text = _read_worktree_text(project_root, rel, 4_000_000, truncate=True)
        if text is None:
            continue
        text = text[:1_000_000]
        if rel.endswith(PY_SUFFIX):
            targets = set().union(*(by_module.get(name, set()) for name in _py_imports(rel, text)))
        else:
            targets = _js_imports(rel, text, files)
        targets.discard(rel)
        if targets:
            forward[rel] = targets
    reverse: dict[str, set[str]] = {}
    for rel, targets in forward.items():
        for target in targets:
            reverse.setdefault(target, set()).add(rel)
    seeds = {rel for rel in changed if rel in files}
    context = set(seeds)
    frontier = set(seeds)
    for _ in range(FORWARD_DEPTH):
        frontier = set().union(*(forward.get(rel, set()) for rel in frontier)) - context
        context |= frontier
    frontier = set(seeds)
    while frontier:
        frontier = set().union(*(reverse.get(rel, set()) for rel in frontier)) - context
        context |= frontier
    if files and len(context) > CONTEXT_MAX_SHARE * len(files):
        return None
    return frozenset(context)


# ---------------------------------------------------------------------------
# Satır kaymasına dayanıklı parmak izi
# ---------------------------------------------------------------------------
def _line_text(lines: list[str], line: Any) -> str:
    try:
        index = int(line) - 1
    except (TypeError, ValueError):
        return ""
    if 0 <= index < len(lines):
        return " ".join(lines[index].split())
    return ""


def context_fingerprints(findings: list[dict[str, Any]], root: Path) -> list[str]:
    """Kural + kategori + dosya + başlık + bulgu satırının normalize metni (+ aynı anahtarlı sıra numarası).

    Satır numarası kullanılmaz; kod satırı yalnız özetlenir (rapora kopyalanmaz)."""
    cache: dict[str, list[str]] = {}
    keys: list[str] = []
    for finding in findings:
        rel = str(finding.get("file") or "")
        if rel and rel not in cache:
            text = _read_worktree_text(root, rel, scan_scope.HARD_MAX_FILE_BYTES)
            cache[rel] = text.splitlines() if text is not None else []
        text = _line_text(cache.get(rel, []), finding.get("line"))
        rule = str(finding.get("reference") or finding.get("cwe") or "")
        keys.append("\x1f".join((rule, str(finding.get("category") or ""), rel, str(finding.get("title") or ""), text)))
    seen: Counter[str] = Counter()
    order = sorted(range(len(findings)), key=lambda i: (keys[i], int(findings[i].get("line") or 0)))
    result = [""] * len(findings)
    for index in order:
        seen[keys[index]] += 1
        result[index] = hashlib.sha256(f"{keys[index]}\x1f{seen[keys[index]]}".encode("utf-8", "surrogatepass")).hexdigest()[:32]
    return result


# ---------------------------------------------------------------------------
# Analiz
# ---------------------------------------------------------------------------
def _empty_result(root: Path, scope: scan_scope.ScanScope, message: str) -> dict[str, Any]:
    return {
        "created_at": utc_now(),
        "project_path": str(root),
        "project_name": root.name,
        "score": 100,
        "grade": "A",
        "file_count": 0,
        "bytes_scanned": 0,
        "skipped_files": {},
        "warnings": [message],
        "scope": scope.public(),
        "languages": {},
        "manifests": [],
        "finding_counts": {severity: 0 for severity in project_analyzer.SEVERITY_WEIGHT},
        "findings": [],
        "checks": [],
        "limitations": ["Yalnız değişen dosyalar incelendi; proje geneli denetimler bu modda çalışmaz."],
    }


def _extract_base(base: BaseTree, dest: Path, scope: scan_scope.ScanScope, context: frozenset[str] | None = None) -> None:
    """Taban sürümün analiz edilebilir dosyalarını ``dest`` altına ham blob olarak yaz (bütçe sınırlı).

    ``context`` verilirse kaynak dosyalardan yalnız bağlamdakiler çıkarılır (bildirimler/yapılandırma her zaman)."""
    wanted: dict[str, str] = {}
    budget = scope.max_total_bytes
    for rel, (sha, size) in sorted(base.blobs.items()):
        if context is not None and (rel.endswith(PY_SUFFIX) or rel.endswith(JS_SUFFIXES)) and rel not in context:
            continue
        parts = rel.split("/")
        if any(part.casefold() in scope.skip_dirs for part in parts[:-1]) or size > scope.max_file_bytes:
            continue
        name = parts[-1].casefold()
        if (Path(name).suffix not in project_analyzer.SOURCE_EXTENSIONS and name not in project_analyzer.MANIFEST_NAMES
                and name != ".htaccess" and not project_analyzer._is_containerfile_name(name)):
            continue
        if size > budget:
            continue
        budget -= size
        wanted[rel] = sha
    data = read_blobs(base, wanted.values())
    for rel, sha in wanted.items():
        if sha not in data:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data[sha])
        finally:
            os.close(fd)


def _tmp_parent() -> Path | None:
    data_dir = os.environ.get("SNIPER_DATA_DIR", "")
    if data_dir and Path(data_dir).is_dir():
        path = Path(data_dir) / "changed-scan-tmp"
        path.mkdir(mode=0o700, exist_ok=True)
        return path
    return None


def analyze_changed(
    value: str,
    *,
    allowed_roots: tuple[Path, ...] | None,
    max_files: int | None,
    scope: scan_scope.ScanScope,
) -> dict[str, Any]:
    """``scope.base_ref``'e göre değişen dosyaları analiz et ve taban sürümle karşılaştırarak yeni bulguları işaretle."""
    root = project_analyzer.validate_project_path(value, allowed_roots)
    if scope.base_ref.startswith("prj_"):
        raise ChangedScanError("Analiz kimliğiyle karşılaştırma yalnız API/CLI üzerinden yapılır (analyze_against_audit).")
    base = resolve_base(root, scope.base_ref)
    changes = compute_changes(root, base, scope)
    changed = changes.changed
    summary: dict[str, Any] = {
        "mode": "git",
        "base_ref": scope.base_ref,
        "base_commit": base.commit,
        "changed_files": sorted(changed)[:MAX_LISTED_CHANGED],
        "added_count": len(changes.added),
        "modified_count": len(changes.modified),
        "deleted_count": len(changes.deleted),
        "renamed_count": len(changes.renamed),
        "compared": False,
        "new_findings": 0,
        "fixed": [],
    }
    context = import_context(root, changed, scope)
    summary["context_files"] = len(context) if context is not None else "tüm proje"
    narrowed = dataclasses.replace(scope, only_paths=frozenset(changed), context_paths=context)
    if not changed:
        result = _empty_result(root, narrowed, f"Yalnız değişenler: {scope.base_ref} ({base.commit[:7]}) sonrasında değişen dosya yok.")
        result["changed_scan"] = summary
        return result
    try:
        result = project_analyzer.analyze_project(str(root), allowed_roots=allowed_roots, max_files=max_files, scope=narrowed)
    except ProjectRejected as exc:
        if "Değişen dosyalar arasında" not in str(exc):
            raise
        result = _empty_result(root, narrowed, f"Yalnız değişenler: {len(changed)} dosya değişti, analiz edilebilir kaynak yok.")
        result["changed_scan"] = summary
        return result

    findings = result.get("findings") or []
    current_fps = context_fingerprints(findings, root)

    # Taban sürüm: değişen dosyaların eski hâllerini (tüm proje bağlamıyla) geçici dizinde analiz et.
    base_paths = frozenset(changes.modified & set(base.blobs))
    base_findings: list[dict[str, Any]] = []
    base_fps: list[str] = []
    old_blobs = read_blobs(base, [base.blobs[rel][0] for rel in changes.modified if rel in base.blobs])
    with tempfile.TemporaryDirectory(prefix="sniper-changed-", dir=_tmp_parent()) as tmp:
        base_root = Path(tmp) / root.name
        base_root.mkdir(mode=0o700)
        if base_paths:
            _extract_base(base, base_root, scope, context)
            try:
                base_result = project_analyzer.analyze_project(
                    str(base_root), allowed_roots=(Path(tmp),), max_files=max_files,
                    scope=dataclasses.replace(scope, only_paths=base_paths, context_paths=context),
                )
                base_findings = base_result.get("findings") or []
            except ProjectRejected:
                base_findings = []
            base_fps = context_fingerprints(base_findings, base_root)

    remaining = Counter(base_fps)
    new_count = 0
    line_cache: dict[str, set[int] | None] = {}
    for finding, fingerprint in zip(findings, current_fps):
        rel = str(finding.get("file") or "")
        finding["context_fingerprint"] = fingerprint
        if remaining[fingerprint] > 0:
            remaining[fingerprint] -= 1
            finding["is_new"] = False
        else:
            finding["is_new"] = True
            new_count += 1
        if rel not in line_cache:
            old = old_blobs.get(base.blobs[rel][0]) if rel in changes.modified and rel in base.blobs else None
            text = _read_worktree_text(root, rel, scan_scope.HARD_MAX_FILE_BYTES) or ""
            line_cache[rel] = changed_lines(old, text) if rel in changes.modified else None
        lines = line_cache[rel]
        finding["in_changed_lines"] = lines is None or int(finding.get("line") or 0) in lines
    fixed = []  # tabanda olup artık bulunmayan bulgular
    for f, fp in zip(base_findings, base_fps):
        if remaining[fp] > 0:
            remaining[fp] -= 1
            fixed.append({"title": f.get("title"), "file": f.get("file"), "line": f.get("line"), "severity": f.get("severity")})
    summary.update({"compared": True, "new_findings": new_count, "fixed_count": len(fixed), "fixed": fixed[:MAX_LISTED_FIXED]})
    result["changed_scan"] = summary
    result.setdefault("warnings", []).insert(
        0,
        f"Yalnız değişenler: {scope.base_ref} ({base.commit[:7]}) ile karşılaştırıldı; {len(changed)} dosya değişti, "
        f"{new_count} yeni bulgu, {len(fixed)} bulgu düzeldi. Proje geneli eksiklik denetimleri bu modda çalışmaz.",
    )
    return result


def analyze_against_audit(
    value: str,
    base_audit: dict[str, Any],
    *,
    allowed_roots: tuple[Path, ...] | None = None,
    max_files: int | None = None,
    scope: scan_scope.ScanScope,
) -> dict[str, Any]:
    """Taban olarak kayıtlı bir proje analizi: tam analiz yapılır, bulgular kayıtlı analizle karşılaştırılır.

    Eski kayıtlarda kod bağlamı yoktur; eşleme kural + kategori + dosya + başlık çoklu kümesiyle yapılır."""
    plain = dataclasses.replace(scope, changed_only=False, base_ref="", only_paths=None)
    result = project_analyzer.analyze_project(value, allowed_roots=allowed_roots, max_files=max_files, scope=plain)
    if base_audit.get("project_path") != result.get("project_path"):
        raise ChangedScanError("Taban analiz başka bir projeye ait.")

    def key(f: dict[str, Any]) -> tuple[str, str, str, str]:
        return (str(f.get("reference") or f.get("cwe") or ""), str(f.get("category") or ""), str(f.get("file") or ""), str(f.get("title") or ""))

    remaining = Counter(key(f) for f in base_audit.get("findings") or [] if isinstance(f, dict))
    new_count = 0
    for finding in result.get("findings") or []:
        k = key(finding)
        if remaining[k] > 0:
            remaining[k] -= 1
            finding["is_new"] = False
        else:
            finding["is_new"] = True
            new_count += 1
    fixed = []
    for f in base_audit.get("findings") or []:
        if isinstance(f, dict) and remaining[key(f)] > 0:
            remaining[key(f)] -= 1
            fixed.append({"title": f.get("title"), "file": f.get("file"), "line": f.get("line"), "severity": f.get("severity")})
    result["scope"] = scope.public()
    result["compared_audit_id"] = base_audit.get("id")
    result["changed_scan"] = {
        "mode": "audit", "base_ref": scope.base_ref, "compared": True, "new_findings": new_count,
        "fixed_count": len(fixed), "fixed": fixed[:MAX_LISTED_FIXED],
    }
    result.setdefault("warnings", []).insert(
        0, f"Kayıtlı analiz {base_audit.get('id')} ile karşılaştırıldı: {new_count} yeni bulgu, {len(fixed)} bulgu düzeldi.",
    )
    return result


def gate_findings(result: dict[str, Any], fail_on: str) -> list[dict[str, Any]]:
    """CI eşiği: karşılaştırma yapıldıysa yalnız yeni bulgular, yapılmadıysa tümü; önem ``fail_on`` ve üstü."""
    threshold = SEVERITY_RANK[fail_on]
    compared = bool((result.get("changed_scan") or {}).get("compared"))
    out = []
    for finding in result.get("findings") or []:
        triage = finding.get("triage") if isinstance(finding.get("triage"), dict) else {}
        if triage.get("disposition") in {"false_positive", "risk_accepted"}:
            continue
        if compared and not finding.get("is_new"):
            continue
        if SEVERITY_RANK.get(str(finding.get("severity") or "info"), 4) <= threshold:
            out.append(finding)
    return out
