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
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

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
INTERNAL_TOKENS = {"internal", "private", "intranet", "corp", "inhouse"}
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
    ("ağ isteği ile süreç başlatma bir arada",
     re.compile(r"\A(?=[\s\S]*\brequire\s*\(\s*['\"](?:https?|net|dns|node:https?|node:net)['\"]\s*\))"
                r"(?=[\s\S]*\b(?:child_process|node:child_process)\b)[\s\S]*\b(?:exec|execSync|spawn|spawnSync|"
                r"execFile)\s*\(", re.I)),
    ("kimlik bilgisi dosyaları ya da ortam değişkenlerinin ağa gönderilmesi",
     re.compile(r"\A(?=[\s\S]*(?:\.npmrc|\.ssh[/\\]|id_rsa|\.aws[/\\]credentials|\.git-credentials|"
                r"JSON\.stringify\s*\(\s*process\.env\s*\)))"
                r"[\s\S]*\b(?:https?\.(?:get|request)|fetch\s*\(|axios|XMLHttpRequest|dns\.(?:lookup|resolve))", re.I)),
)
_NODE_FILE_RE = re.compile(r"\bnode\s+(?:-[-\w=]+\s+)*['\"]?([\w./\\-]+\.(?:c|m)?js)\b")


def _finding(severity: str, title: str, file: str, evidence: str, recommendation: str,
             reference: str) -> dict[str, Any]:
    return {"category": CATEGORY, "severity": severity, "title": title, "file": file, "line": 0,
            "evidence": evidence, "recommendation": recommendation, "reference": reference}


def _read_json(path: Path, limit: int) -> Any:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError):
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

def malicious_findings(root: Path, *, osv_root: Path | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    import dependency_security
    import osv_offline

    warnings: list[str] = []
    try:
        _root, components, _skipped = dependency_security.discover_inventory(
            str(root), allowed_roots=(root.parent,), lenient=True, warnings=warnings)  # kök zaten doğrulandı
    except Exception as exc:  # noqa: BLE001 — envanter kurulamazsa denetim atlanır
        return [], [f"Kötü amaçlı paket denetimi atlandı: {type(exc).__name__}"]
    if not components:
        return [], []
    result = osv_offline.malicious_components(components, root=osv_root)
    lock = _read_json(root / "package-lock.json", MAX_LOCK_BYTES) if result["matches"] else None
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


def _node_module_dirs(node_modules: Path) -> Iterable[Path]:
    count = 0
    try:
        entries = sorted(node_modules.iterdir())
    except OSError:
        return
    for entry in entries:
        if count >= MAX_NODE_MODULES:
            return
        if entry.is_symlink() or not entry.is_dir() or entry.name.startswith("."):
            continue
        if entry.name.startswith("@"):
            try:
                scoped = sorted(entry.iterdir())
            except OSError:
                continue
            for sub in scoped:
                if not sub.is_symlink() and sub.is_dir():
                    count += 1
                    yield sub
        else:
            count += 1
            yield entry


def _hook_file_text(package_dir: Path, command: str) -> str:
    """Betik ``node dosya.js`` çağırıyorsa paket içindeki o dosyanın metni (paket dışına çıkılmaz)."""
    match = _NODE_FILE_RE.search(command)
    if not match:
        return ""
    target = (package_dir / match.group(1)).resolve()
    try:
        target.relative_to(package_dir.resolve())
        if target.is_symlink() or not target.is_file() or target.stat().st_size > MAX_HOOK_FILE_BYTES:
            return ""
        return target.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _find_files(root: Path, filename: str, skip_dirs: Iterable[str] = (), *, max_depth: int = 6,
                max_dirs: int = 3000) -> list[Path]:
    """Ad eşleşen dosyalar; node_modules, gizli ve atlanan dizinlere inilmez, sembolik bağ izlenmez (sınırlı)."""
    skip = set(skip_dirs) | {"node_modules"}
    found: list[Path] = []
    visited = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        visited += 1
        depth = len(Path(current).relative_to(root).parts)
        dirs[:] = sorted(d for d in dirs if d not in skip and not d.startswith(".") and depth < max_depth)
        if filename in files and not (Path(current) / filename).is_symlink():
            found.append(Path(current) / filename)
        if visited >= max_dirs:
            break
    return sorted(found)


def install_script_findings(root: Path, skip_dirs: Iterable[str] = ()) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for lock_path in _find_files(root, "package-lock.json", skip_dirs)[:20]:
        rel = lock_path.relative_to(root)
        lock = _read_json(lock_path, MAX_LOCK_BYTES)
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
    node_modules = root / "node_modules"
    if node_modules.is_dir() and not node_modules.is_symlink():
        for package_dir in _node_module_dirs(node_modules):
            manifest = _read_json(package_dir / "package.json", MAX_PACKAGE_JSON_BYTES)
            scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
            if not isinstance(scripts, dict):
                continue
            hooks = {hook: str(scripts[hook])[:4000] for hook in INSTALL_HOOKS if isinstance(scripts.get(hook), str)}
            if not hooks:
                continue
            hits: list[str] = []
            for command in hooks.values():
                hits += suspicious_hits(command)
                hits += suspicious_hits(_hook_file_text(package_dir, command))
            if not hits:
                continue
            name = str(manifest.get("name") or package_dir.name)[:214]
            version = str(manifest.get("version") or "")[:64]
            rel = (package_dir / "package.json").relative_to(root).as_posix()
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


def dependency_confusion_findings(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    configs = [rel for rel in REGISTRY_CONFIG_FILES if (root / rel).is_file() and not (root / rel).is_symlink()]
    root_manifest = _read_json(root / "package.json", MAX_PACKAGE_JSON_BYTES)
    prefix = _company_prefix(root_manifest)
    direct: set[str] = set()
    if isinstance(root_manifest, dict):
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            if isinstance(root_manifest.get(field), dict):
                direct.update(str(n) for n in root_manifest[field])
    for req in sorted(root.glob("requirements*.txt"))[:10]:
        try:
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines()[:5000]:
                match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if match and not line.lstrip().startswith(("#", "-")):
                    direct.add(match.group(1))
        except OSError:
            continue
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
    lock = _read_json(root / "package-lock.json", MAX_LOCK_BYTES)
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
    root = Path(root)
    if malicious is None:
        malicious = os.environ.get("SNIPER_SUPPLY_CHAIN_OSV", "1") != "0"
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    if malicious:
        mal, mal_warnings = malicious_findings(root, osv_root=osv_root)
        findings += mal
        warnings += mal_warnings
    findings += install_script_findings(root, skip_dirs)
    findings += dependency_confusion_findings(root)
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
