"""Tedarik zinciri denetimleri (20. tur) — yalnız yerel dosyalar, statik okuma; kod ÇALIŞTIRILMAZ, ağa çıkılmaz.

1. Kötü amaçlı paket: proje envanteri (``dependency_security.discover_inventory``) yerel OSV veritabanındaki OpenSSF
   ``MAL-`` kayıtlarıyla eşlenir (``osv_offline.malicious_components``). Kritik, CWE-506; öneri kaldırma + kimlik
   bilgisi döndürme. Veritabanı yoksa ya da güvenilmezse sessizce atlanır (uyarı döner).
2. npm kurulum betikleri: kilit dosyasındaki ``hasInstallScript`` paketleri (bilgi) ve yerel ``node_modules``
   paketlerinin preinstall/install/postinstall betikleri; betikte ya da betiğin çağırdığı yerel JS dosyasında şüpheli
   kalıp (ağdan indirip kabuğa verme, base64 çözüp çalıştırma, ağ + süreç başlatma, kimlik bilgisi dosyası + ağ)
   varsa önem yükselir.
3. Bağımlılık karışıklığı ipuçları (düşük): kapsamsız iç adlı paketler, özel kayıt deposu yapılandırmasının varlığı
   (dosya İÇERİĞİ okunmaz — gizli değer içerebilir) ve kilit dosyasında aynı paketin farklı kayıt depolarından ya da iç
   adlı paketin herkese açık depodan çözülmesi. Adreslerden yalnız ana makine adı gösterilir (kullanıcı/parola atılır).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Iterable
from urllib.parse import urlsplit

from project_tree import ProjectFile, ProjectTree, ProjectTreeError
from safe_file_read import read_text_bounded

CATEGORY = "supply_chain"
MAX_LOCK_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_JSON_BYTES = 512 * 1024
MAX_HOOK_FILE_BYTES = 256 * 1024
MAX_NODE_MODULES = 4000
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
PUBLIC_REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com", "pypi.org",
                     "files.pythonhosted.org", "repo.maven.apache.org", "repo1.maven.org", "api.nuget.org",
                     "rubygems.org", "crates.io", "static.crates.io", "packagist.org"}
REGISTRY_CONFIG_FILES = (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".pypirc", "settings.xml",
                         ".mvn/settings.xml", "nuget.config", "NuGet.Config", "NuGet.config", ".gemrc",
                         ".cargo/config.toml", ".cargo/config", "poetry.toml")
INTERNAL_TOKENS = {"internal", "private", "intranet", "corp", "inhouse", "confidential", "staging", "backoffice", "infra"}
GENERIC_PREFIXES = {"node", "react", "vue", "angular", "app", "web", "api", "my", "the", "test", "demo", "example",
                    "server", "client", "core", "lib", "js", "ts", "py", "go", "frontend", "backend", "service",
                    "project", "sample", "simple", "express", "next", "nuxt", "svelte", "eslint", "babel", "webpack",
                    "jest", "types", "vite", "electron", "ui", "data", "mobile", "admin", "website", "site"}

# Şüpheli kurulum betiği kalıpları (statik; ad → düzenli ifade). Ağdan çekip kabuğa verme ya da çözüp çalıştırma.
SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ağdan indirilen betiğin kabuğa verilmesi (curl/wget | sh)",
     re.compile(r"\b(?:curl|wget)\b[^\n|;&]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", re.I)),
    ("PowerShell ile uzak betik (iwr/irm | iex)",
     re.compile(r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b.{0,300}\b(?:iex|Invoke-Expression)\b",
                re.I | re.S)),
    ("base64 çözülen verinin çalıştırılması",
     re.compile(r"(?:base64\s+(?:-d|--decode)|atob\s*\(|Buffer\.from\s*\([^)]{0,400}['\"]base64['\"]|b64decode)"
                r"[\s\S]{0,400}?(?:\beval\s*\(|new\s+Function\s*\(|\bexec(?:Sync)?\s*\(|\|\s*(?:ba)?sh\b|\bspawn\s*\()",
                re.I)),
    ("hex veya sıkıştırılmış verinin çözülüp çalıştırılması",
     re.compile(r"(?:(?:Buffer\.from\s*\([^)]{0,400}['\"]hex['\"]|zlib\.(?:inflate|gunzip|unzip)(?:Sync)?\s*\()"
                r"[\s\S]{0,400}?(?:\beval\s*\(|new\s+Function\s*\(|\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\(|\bvm\.runIn)"
                r"|(?:\beval\s*\(|new\s+Function\s*\(|\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\(|\bvm\.runIn)"
                r"[\s\S]{0,400}?(?:Buffer\.from\s*\([^)]{0,400}['\"]hex['\"]|zlib\.(?:inflate|gunzip|unzip)(?:Sync)?\s*\())",
                re.I)),
    ("ağ isteği ile süreç başlatma bir arada",
     re.compile(r"\A(?=[\s\S]*\brequire\s*\(\s*['\"](?:https?|net|dns|node:https?|node:net)['\"]\s*\))"
                r"(?=[\s\S]*\b(?:child_process|node:child_process)\b)[\s\S]*\b(?:exec|execSync|spawn|spawnSync|"
                r"execFile)\s*\(", re.I)),
    ("kimlik bilgisi dosyaları ya da ortam değişkenlerinin ağa gönderilmesi",
     re.compile(r"\A(?=[\s\S]*(?:\.npmrc|\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.git-credentials|"
                r"\.kube[/\\]config|\.docker[/\\]config\.json|gcloud[/\\]|serviceaccount[/\\]token|"
                r"JSON\.stringify\s*\(\s*process\.env\s*\)))"
                r"[\s\S]*\b(?:https?\.(?:get|request)|fetch\s*\(|axios|undici|got|net\.connect|tls\.connect|dgram|XMLHttpRequest|dns\.(?:lookup|resolve))", re.I)),
)
_NODE_FILE_RE = re.compile(r"\bnode\s+(?:-[-\w=]+\s+)*['\"]?([\w./\\-]+\.(?:c|m)?js)\b")


def _finding(severity: str, title: str, file: str, evidence: str, recommendation: str,
             reference: str) -> dict[str, Any]:
    return {"category": CATEGORY, "severity": severity, "title": title, "file": file, "line": 0,
            "evidence": evidence, "recommendation": recommendation, "reference": reference}


def _read_json(
    path: Path,
    limit: int,
    *,
    project_tree: ProjectTree | None = None,
    project_file: ProjectFile | None = None,
) -> Any:
    try:
        if project_tree is None:
            text = read_text_bounded(path, limit)
        else:
            target: str | ProjectFile = project_file or path.relative_to(project_tree.root).as_posix()
            text = project_tree.read_text(target, limit)
        if text is None:
            return None
        return json.loads(text)
    except (OSError, ValueError, RecursionError, ProjectTreeError):
        return None


def _host(url: str) -> str:
    """Adresin yalnız ana makine adı (kullanıcı adı/parola/port/yol atılır; gizli değer sızmaz)."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _names(items: Iterable[str], limit: int = 10) -> str:
    items = sorted(set(items))
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit})" if len(items) > limit else "")


# ---------------------------------------------------------------------------------------------
# 1) Kötü amaçlı paketler
# ---------------------------------------------------------------------------------------------

def malicious_findings(
    root: Path,
    *,
    osv_root: Path | None = None,
    project_tree: ProjectTree | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    import dependency_security
    import osv_offline

    warnings: list[str] = []
    try:
        _root, components, _skipped = dependency_security.discover_inventory(
            str(root), allowed_roots=(root.parent,), lenient=True, warnings=warnings,
            project_tree=project_tree)  # kök zaten doğrulandı
    except Exception as exc:  # noqa: BLE001 — envanter kurulamazsa denetim atlanır
        return [], [f"Kötü amaçlı paket denetimi atlandı: {type(exc).__name__}"]
    if not components:
        return [], []
    result = osv_offline.malicious_components(components, root=osv_root)
    lock = _read_json(root / "package-lock.json", MAX_LOCK_BYTES, project_tree=project_tree) \
        if result["matches"] else None
    hosts = _lock_hosts(lock) if isinstance(lock, dict) else {}
    out = []
    for match in result["matches"]:
        aliases = ", ".join(match["aliases"][:3])
        resolved = hosts.get(match["name"], set()) if match["ecosystem"] == "npm" else set()
        if resolved and not resolved & PUBLIC_REGISTRIES:
            # Paket özel depodan çözülüyor; herkese açık depodaki aynı adlı paket kötü amaçlı (bağımlılık karışıklığı
            # saldırısı için yayımlanmış). Kurulu paket büyük olasılıkla iç pakettir; risk, depo sırası bozulursa.
            out.append(_finding(
                "high", f"Herkese açık depoda aynı adlı kötü amaçlı paket: {match['name']} ({match['id']})",
                match.get("manifest") or "",
                f"{match['name']}@{match['version']} kilit dosyasında özel depodan çözülüyor ({_names(resolved, 3)}); "
                f"herkese açık depodaki aynı adlı paket kötü amaçlı kayıtlı ({match['id']}).",
                "Bu ad bağımlılık karışıklığı saldırısında kullanılmış. Paketi kuruluş kapsamına (@kurum/…) taşıyın, "
                "kapsamı yalnız iç depoya eşleyin ve CI'da kilit dosyasından (`npm ci`) kurulum yapın; `resolved` "
                "adreslerinin iç depoyu gösterdiğini doğrulayın.",
                "CWE-427"))
            continue
        out.append(_finding(
            "critical", f"{dependency_security.MALICIOUS_TITLE}: {match['name']} {match['version']} ({match['id']})",
            match.get("manifest") or "",
            f"{match['ecosystem']} {match['name']}@{match['version']} — {match['id']}"
            + (f" / {aliases}" if aliases else "") + (f": {match['summary']}" if match.get("summary") else "")
            + (f" Etkilenmeyen sürüm: ≥ {', '.join(match['fixed'])}." if match.get("fixed") else
               " Kayıt tüm sürümleri kapsıyor."),
            dependency_security.MALICIOUS_RECOMMENDATION, dependency_security.MALICIOUS_CWE))
    return out, warnings[:5] + result["warnings"][:5]


# ---------------------------------------------------------------------------------------------
# 2) npm kurulum betikleri
# ---------------------------------------------------------------------------------------------

def _lock_install_scripts(lock: dict[str, Any]) -> list[str]:
    names: list[str] = []
    packages = lock.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if key and isinstance(meta, dict) and meta.get("hasInstallScript") is True and not meta.get("link"):
                names.append(key.rsplit("node_modules/", 1)[-1])
    return names


def suspicious_hits(text: str) -> list[str]:
    return [label for label, pattern in SUSPICIOUS_PATTERNS if pattern.search(text)]


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _directory_entries(directory_fd: int) -> list[tuple[str, os.stat_result]]:
    try:
        with os.scandir(directory_fd) as entries:
            observed = []
            for entry in entries:
                try:
                    observed.append((entry.name, entry.stat(follow_symlinks=False)))
                except OSError:
                    continue
            return sorted(observed, key=lambda item: item[0])
    except OSError:
        return []


def _open_child_directory(directory_fd: int, name: str, expected: os.stat_result) -> int | None:
    try:
        if not stat.S_ISDIR(expected.st_mode):
            return None
        child_fd = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
        actual = os.fstat(child_fd)
        if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            os.close(child_fd)
            return None
        return child_fd
    except OSError:
        return None


def _node_module_dirs(project_tree: ProjectTree) -> Iterable[PurePosixPath]:
    count = 0
    try:
        node_modules_fd = os.open("node_modules", _DIR_FLAGS, dir_fd=project_tree.fileno())
    except OSError:
        return
    try:
        for entry_name, entry_info in _directory_entries(node_modules_fd):
            if count >= MAX_NODE_MODULES:
                return
            if entry_name.startswith("."):
                continue
            entry_fd = _open_child_directory(node_modules_fd, entry_name, entry_info)
            if entry_fd is None:
                continue
            if entry_name.startswith("@"):
                try:
                    for sub_name, sub_info in _directory_entries(entry_fd):
                        if count >= MAX_NODE_MODULES:
                            return
                        sub_fd = _open_child_directory(entry_fd, sub_name, sub_info)
                        if sub_fd is None:
                            continue
                        os.close(sub_fd)
                        count += 1
                        yield PurePosixPath("node_modules") / entry_name / sub_name
                finally:
                    os.close(entry_fd)
            else:
                os.close(entry_fd)
                count += 1
                yield PurePosixPath("node_modules") / entry_name
    finally:
        os.close(node_modules_fd)


def _hook_file_text(project_tree: ProjectTree, package_dir: PurePosixPath, command: str) -> str:
    """Betik ``node dosya.js`` çağırıyorsa paket içindeki o dosyanın metni (paket dışına çıkılmaz)."""
    match = _NODE_FILE_RE.search(command)
    if not match:
        return ""
    raw = match.group(1).replace("\\", "/")
    parts = PurePosixPath(raw).parts
    if not parts or raw.startswith("/") or any(part in ("", ".", "..") for part in parts):
        return ""
    try:
        return project_tree.read_text(package_dir.joinpath(*parts).as_posix(), MAX_HOOK_FILE_BYTES) or ""
    except ProjectTreeError:
        return ""


def _find_files(root: Path, filename: str, skip_dirs: Iterable[str] = (), *, max_depth: int = 6,
                max_dirs: int = 3000, project_tree: ProjectTree) -> list[ProjectFile]:
    """Sabit proje descriptor'ünde ad eşleşen düzenli dosyalar (sınırlı)."""
    del root
    skip = set(skip_dirs) | {"node_modules"}
    found: list[ProjectFile] = []
    visited = 0
    try:
        for walked in project_tree.walk(
            skip_dirs=skip,
            max_entries=min(10_000_000, max(100_000, max_dirs * 100)),
            reject_unsafe=False,
        ):
            parts = () if walked.directory.as_posix() == "." else walked.directory.parts
            if len(parts) > max_depth or any(part.startswith(".") for part in parts):
                continue
            visited += 1
            found.extend(observed for observed in walked.files if observed.name == filename)
            if visited >= max_dirs:
                break
    except ProjectTreeError:
        pass
    return sorted(found, key=lambda observed: observed.path.as_posix())


def install_script_findings(root: Path, skip_dirs: Iterable[str] = (), *,
                            project_tree: ProjectTree | None = None) -> list[dict[str, Any]]:
    root = Path(root).absolute()
    if project_tree is None:
        try:
            with ProjectTree(root) as owned_tree:
                return install_script_findings(root, skip_dirs, project_tree=owned_tree)
        except ProjectTreeError:
            return []
    out: list[dict[str, Any]] = []
    for lock_file in _find_files(root, "package-lock.json", skip_dirs, project_tree=project_tree)[:20]:
        rel = lock_file.path
        lock = _read_json(root / rel, MAX_LOCK_BYTES, project_tree=project_tree, project_file=lock_file)
        if not isinstance(lock, dict):
            continue
        names = _lock_install_scripts(lock)
        if names:
            out.append(_finding(
                "info", "Kurulumda betik çalıştıran npm bağımlılıkları", rel.as_posix(),
                f"{len(set(names))} paket kurulumda betik çalıştırıyor (hasInstallScript): {_names(names)}.",
                "Kurulum betikleri geliştirici ve CI makinelerinde paket koduyla çalışır. CI'da `npm ci --ignore-scripts` "
                "kullanıp gerçekten gereken paketlere izin verin (pnpm `onlyBuiltDependencies`, Yarn `enableScripts`); "
                "yeni eklenen betikli paketleri gözden geçirin.",
                "CWE-829"))
    for package_dir in _node_module_dirs(project_tree):
        manifest_path = package_dir / "package.json"
        manifest = _read_json(root / manifest_path, MAX_PACKAGE_JSON_BYTES, project_tree=project_tree)
        scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
        if not isinstance(scripts, dict):
            continue
        hooks = {hook: str(scripts[hook])[:4000] for hook in INSTALL_HOOKS if isinstance(scripts.get(hook), str)}
        if not hooks:
            continue
        hits: list[str] = []
        for command in hooks.values():
            hits += suspicious_hits(command)
            hits += suspicious_hits(_hook_file_text(project_tree, package_dir, command))
        if not hits:
            continue
        name = str(manifest.get("name") or package_dir.name)[:214]
        version = str(manifest.get("version") or "")[:64]
        rel = manifest_path.as_posix()
        out.append(_finding(
            "high", f"Şüpheli npm kurulum betiği: {name} {version}".strip(), rel,
            f"{', '.join(sorted(hooks))} betiğinde: {'; '.join(sorted(set(hits)))}.",
            "Paketi kaldırın ya da sürümünü doğrulanmış güvenli bir sürüme sabitleyin; betiğin ne yaptığını inceleyin. "
            "Paket zaten kurulduysa makinedeki kimlik bilgilerini ve belirteçleri döndürün. Kurulumları "
            "`--ignore-scripts` ile yapın.",
            "CWE-506"))
    return out


# ---------------------------------------------------------------------------------------------
# 3) Bağımlılık karışıklığı ipuçları
# ---------------------------------------------------------------------------------------------

def _tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[-_.]", name.lower()) if t]


def looks_internal(name: str, company_prefix: str = "") -> bool:
    if name.startswith("@"):
        return False  # kapsamlı paket: kapsam sahibi kayıt deposunda ayrılmıştır
    tokens = _tokens(name)
    if any(t in INTERNAL_TOKENS for t in tokens):
        return True
    return bool(company_prefix) and len(tokens) > 1 and tokens[0] == company_prefix


def _company_prefix(root_manifest: dict[str, Any] | None) -> str:
    if not isinstance(root_manifest, dict):
        return ""
    name = str(root_manifest.get("name") or "")
    if name.startswith("@") or not name:
        return ""
    first = _tokens(name)[0] if _tokens(name) else ""
    return first if len(first) >= 4 and first not in GENERIC_PREFIXES and len(_tokens(name)) > 1 else ""


def _registry_host(url: str) -> str:
    """Yalnız kayıt deposu paket arşivi adresleri (npm biçimi ``…/<ad>/-/<ad>-<sürüm>.tgz``); git/GitHub/yerel
    kaynaklar kayıt deposu sayılmaz (tutarsızlık ipucu üretmez)."""
    if not isinstance(url, str) or not url.startswith(("https://", "http://")) or "/-/" not in url:
        return ""
    return _host(url)


def _lock_hosts(lock: dict[str, Any]) -> dict[str, set[str]]:
    hosts: dict[str, set[str]] = {}
    packages = lock.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if key and isinstance(meta, dict) and isinstance(meta.get("resolved"), str):
                host = _registry_host(meta["resolved"])
                if host:
                    hosts.setdefault(str(meta.get("name") or key.rsplit("node_modules/", 1)[-1]), set()).add(host)
    deps = lock.get("dependencies")
    stack = [deps] if isinstance(deps, dict) else []
    while stack:
        level = stack.pop()
        for name, meta in level.items():
            if isinstance(meta, dict):
                if _registry_host(meta.get("resolved")):
                    hosts.setdefault(name, set()).add(_registry_host(meta["resolved"]))
                if isinstance(meta.get("dependencies"), dict) and len(stack) < 10000:
                    stack.append(meta["dependencies"])
    return hosts


def _regular_exists(project_tree: ProjectTree, relative: str) -> bool:
    try:
        # ``truncate=True`` ve sıfır bütçe içeriği okumadan normal dosya/no-follow kontrolü yapar.
        project_tree.read_bytes(relative, 0, allow_empty=True, truncate=True)
        return True
    except ProjectTreeError:
        return False


def _root_files(project_tree: ProjectTree) -> tuple[ProjectFile, ...]:
    walker = project_tree.walk(reject_unsafe=False)
    try:
        first = next(walker, None)
        return first.files if first is not None and first.directory.as_posix() == "." else ()
    except ProjectTreeError:
        return ()
    finally:
        walker.close()


def dependency_confusion_findings(root: Path, *,
                                  project_tree: ProjectTree | None = None) -> list[dict[str, Any]]:
    root = Path(root).absolute()
    if project_tree is None:
        try:
            with ProjectTree(root) as owned_tree:
                return dependency_confusion_findings(root, project_tree=owned_tree)
        except ProjectTreeError:
            return []
    out: list[dict[str, Any]] = []
    configs = [rel for rel in REGISTRY_CONFIG_FILES if _regular_exists(project_tree, rel)]
    root_manifest = _read_json(root / "package.json", MAX_PACKAGE_JSON_BYTES, project_tree=project_tree)
    prefix = _company_prefix(root_manifest)
    direct: set[str] = set()
    if isinstance(root_manifest, dict):
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            if isinstance(root_manifest.get(field), dict):
                direct.update(str(n) for n in root_manifest[field])
    requirements = sorted(
        (observed for observed in _root_files(project_tree)
         if observed.name.startswith("requirements") and observed.name.endswith(".txt")),
        key=lambda observed: observed.name,
    )[:10]
    for req in requirements:
        try:
            text = project_tree.read_text(req, MAX_LOCK_BYTES)
        except ProjectTreeError:
            continue
        for line in text.splitlines()[:5000]:
            match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if match and not line.lstrip().startswith(("#", "-")):
                direct.add(match.group(1))
    internal = sorted(n for n in direct if looks_internal(n, prefix))
    if internal:
        out.append(_finding(
            "low", "Kapsamsız iç adlı bağımlılık (bağımlılık karışıklığı riski)", "package.json" if root_manifest else "",
            f"İç paket gibi görünen kapsamsız adlar: {_names(internal)}."
            + (f" Özel kayıt deposu yapılandırması var: {', '.join(configs)}." if configs else ""),
            "İç paketleri kuruluşunuzun kapsamına (@kurum/paket) taşıyın ve kapsamı yalnız iç kayıt deposuna eşleyin; "
            "herkese açık depoda aynı adı rezerve edin. pip'te `--extra-index-url` yerine tek iç dizin (proxy) kullanın; "
            "Maven/NuGet'te depo sırasını ve kaynak eşlemesini (package source mapping) sabitleyin.",
            "CWE-427"))
    lock = _read_json(root / "package-lock.json", MAX_LOCK_BYTES, project_tree=project_tree)
    if isinstance(lock, dict):
        hosts = _lock_hosts(lock)
        all_hosts = {h for hs in hosts.values() for h in hs}
        if len(all_hosts) > 1:
            mixed = sorted(n for n, hs in hosts.items() if len(hs) > 1)
            internal_public = sorted(n for n, hs in hosts.items()
                                     if looks_internal(n, prefix) and hs & PUBLIC_REGISTRIES)
            private_hosts = sorted(all_hosts - PUBLIC_REGISTRIES)
            if mixed or internal_public or private_hosts:
                detail = [f"kayıt depoları: {_names(all_hosts, 6)}"]
                if mixed:
                    detail.append(f"birden çok depodan çözülen paketler: {_names(mixed)}")
                if internal_public:
                    detail.append(f"herkese açık depodan çözülen iç adlı paketler: {_names(internal_public)}")
                out.append(_finding(
                    "low", "Kilit dosyasında kayıt deposu tutarsızlığı (bağımlılık karışıklığı ipucu)", "package-lock.json",
                    "; ".join(detail) + ".",
                    "Her paketin beklenen kayıt deposundan çözüldüğünü doğrulayın; iç paketleri kapsamlı ada taşıyıp "
                    "kapsamı iç depoya eşleyin, kilit dosyasını yeniden üretip `resolved`/`integrity` alanlarını gözden "
                    "geçirin.",
                    "CWE-427"))
    return out


# ---------------------------------------------------------------------------------------------
# Toplu giriş
# ---------------------------------------------------------------------------------------------

def analyze(root: Path, *, skip_dirs: Iterable[str] = (), osv_root: Path | None = None,
            malicious: bool | None = None) -> dict[str, Any]:
    """Proje analizi kancası: bulgular + özet. ``malicious`` None ise SNIPER_SUPPLY_CHAIN_OSV (varsayılan açık)."""
    root = Path(root).absolute()
    if malicious is None:
        malicious = os.environ.get("SNIPER_SUPPLY_CHAIN_OSV", "1") != "0"
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        with ProjectTree(root) as project_tree:
            if malicious:
                mal, mal_warnings = malicious_findings(root, osv_root=osv_root, project_tree=project_tree)
                findings += mal
                warnings += mal_warnings
            findings += install_script_findings(root, skip_dirs, project_tree=project_tree)
            findings += dependency_confusion_findings(root, project_tree=project_tree)
    except ProjectTreeError:
        warnings.append("Tedarik zinciri denetimi atlandı: proje ağacı güvenli biçimde okunamadı.")
    return {
        "findings": findings,
        "summary": {
            "malicious": sum(1 for f in findings if f["severity"] == "critical"),
            "suspicious_install_scripts": sum(1 for f in findings if f["title"].startswith("Şüpheli npm")),
            "confusion_hints": sum(1 for f in findings if f["reference"] == "CWE-427"),
            "malicious_check": "on" if malicious else "off",
        },
        "warnings": warnings,
    }
