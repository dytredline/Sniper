"""Bağımlılık zafiyetleri için VEX (Vulnerability Exploitability eXchange): CycloneDX 1.5 VEX ve OpenVEX 0.2.0.

Her bağımlılık bulgusu için bir "etkilenme" kararı üretilir:

* ``affected``            — açıklı fonksiyon kodda kullanılıyor (sembol erişilebilirliği ``reachable``) ya da risk kabul
                            edilmiş; düzeltme önerisi (``action_statement``) eklenir.
* ``fixed``               — bulgu son içe aktarmada artık bildirilmiyor (``resolved``).
* ``not_affected``        — YALNIZ kanıtlanabilen durumlarda: analist kararı (gerekçe + etki açıklaması zorunlu), içe
                            aktarılan tedarikçi VEX'i ya da paketin tam kilit dosyasında hiç bulunmaması
                            (``component_not_present``).
* ``under_investigation`` — geri kalan her şey (şüphede).

Neden otomatik "not_affected" bu kadar dar: Sniper'ın sembol erişilebilirliği yalnız projenin kendi kaynağına bakar;
başka bir bağımlılık açıklı fonksiyonu kendi içinden çağırabilir (bağımlılık kodu analiz edilmez). Bu yüzden "açıklı
fonksiyon kaynakta çağrılmıyor" bilgisi yalnız ``impact_statement`` notu olur, karar "inceleniyor" kalır. Yanlış
"not_affected" bir tedarikçi belgesinde müşteriyi açığı yamamamaya yönlendirir; hedef sıfır.

Ağ erişimi yoktur; belgeler deterministik kimlikle (içerik özetinden UUIDv5) üretilir.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import uuid
from typing import Any, Iterable

FORMATS = ("cyclonedx", "openvex")
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
# OpenVEX 0.2.0 gerekçe etiketleri (CISA "Minimum Requirements for VEX" ile aynı).
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)
STATUS_LABELS = {
    "not_affected": "Etkilenmiyor",
    "affected": "Etkileniyor",
    "fixed": "Düzeltildi",
    "under_investigation": "İnceleniyor",
}
JUSTIFICATION_LABELS = {
    "component_not_present": "Bileşen üründe yok",
    "vulnerable_code_not_present": "Açıklı kod üründe yok",
    "vulnerable_code_not_in_execute_path": "Açıklı kod çalışma yolunda değil",
    "vulnerable_code_cannot_be_controlled_by_adversary": "Açıklı kod saldırgan tarafından denetlenemez",
    "inline_mitigations_already_exist": "Kod içi önlem mevcut",
}
BASIS_LABELS = {"auto": "otomatik", "analyst": "analist kararı", "imported": "içe aktarılan VEX", "scanner": "tarayıcı",
                "policy": "politika"}
# Aynı açık + paket için birden çok kaynak (OSV ve Trivy) bulgusu tek ifadede birleşir; çelişkide temkinli olan kalır.
_STATUS_CAUTION = {"affected": 0, "under_investigation": 1, "not_affected": 2, "fixed": 3}
_BASIS_RANK = {"analyst": 0, "imported": 1, "policy": 2, "auto": 3, "scanner": 4}

_CDX_STATE = {"not_affected": "not_affected", "affected": "exploitable", "fixed": "resolved",
              "under_investigation": "in_triage"}
_CDX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}
# CycloneDX → OpenVEX (içe aktarma)
_CDX_STATE_BACK = {"not_affected": "not_affected", "false_positive": "not_affected", "exploitable": "affected",
                   "resolved": "fixed", "resolved_with_pedigree": "fixed", "in_triage": "under_investigation"}
_CDX_JUSTIFICATION_BACK = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_runtime": "inline_mitigations_already_exist",
    "protected_at_perimeter": "inline_mitigations_already_exist",
    "protected_by_mitigating_control": "inline_mitigations_already_exist",
}
_CDX_SEVERITIES = {"critical", "high", "medium", "low", "info", "none", "unknown"}
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
MAX_TEXT = 2_000
MAX_IMPORT_STATEMENTS = 5_000
_VEX_NAMESPACE = uuid.UUID("6f0c1c1e-7e2b-5d55-9a1b-5e3f0d1a1e17")

# Kilit dosyası projenin TÜM (dolaylı dahil) paketlerini listeler; yalnız bunlarda "paket yok" kanıt sayılır.
# requirements.txt / pyproject.toml / pom.xml / go.mod yalnız doğrudan (ya da eksik) liste verebilir.
COMPLETE_LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm",
    "poetry.lock": "pypi", "pipfile.lock": "pypi", "cargo.lock": "cargo", "gemfile.lock": "rubygems",
    "composer.lock": "packagist", "pubspec.lock": "pub",
}
_LOCKFILE_ECOSYSTEM = {
    **COMPLETE_LOCKFILES, "requirements.txt": "pypi", "pyproject.toml": "pypi", "go.mod": "golang",
    "go.sum": "golang", "pom.xml": "maven", "gradle.lockfile": "maven", "podfile.lock": "cocoapods",
    "package.json": "npm", "package.resolved": "swift",
}
_ECOSYSTEM_ALIASES = {
    "pypi": "pypi", "pip": "pypi", "python": "pypi", "python-pkg": "pypi", "poetry": "pypi", "pipenv": "pypi",
    "npm": "npm", "node-pkg": "npm", "yarn": "npm", "pnpm": "npm", "golang": "golang", "go": "golang",
    "gomod": "golang", "gobinary": "golang", "cargo": "cargo", "crates.io": "cargo", "rust-binary": "cargo",
    "maven": "maven", "gradle": "maven", "jar": "maven", "pom": "maven", "rubygems": "rubygems", "gem": "rubygems",
    "bundler": "rubygems", "gemspec": "rubygems", "packagist": "packagist", "composer": "packagist", "pub": "pub",
    "cocoapods": "cocoapods", "swift": "swift", "swifturl": "swift",
}
_PURL_TYPES = {"pypi": "pypi", "npm": "npm", "golang": "golang", "cargo": "cargo", "maven": "maven",
               "rubygems": "gem", "packagist": "composer", "pub": "pub", "cocoapods": "cocoapods", "swift": "swift"}
_PURL_TYPE_BACK = {"pypi": "pypi", "npm": "npm", "golang": "golang", "cargo": "cargo", "maven": "maven",
                   "gem": "rubygems", "composer": "packagist", "pub": "pub", "cocoapods": "cocoapods", "swift": "swift"}


class VexError(ValueError):
    """Geçersiz VEX kararı ya da belgesi."""


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------
def _text(value: Any, limit: int = MAX_TEXT) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value or "")).strip()
    return text[:limit]


def normalize_ecosystem(value: Any) -> str:
    key = str(value or "").strip().casefold()
    if key in _ECOSYSTEM_ALIASES:
        return _ECOSYSTEM_ALIASES[key]
    base = key.rsplit("/", 1)[-1].split(" ", 1)[0]  # "app/package-lock.json (npm)" → "package-lock.json"
    if base in _LOCKFILE_ECOSYSTEM:
        return _LOCKFILE_ECOSYSTEM[base]
    paren = re.search(r"\(([a-z0-9._-]+)\)\s*$", key)
    if paren and paren.group(1) in _ECOSYSTEM_ALIASES:
        return _ECOSYSTEM_ALIASES[paren.group(1)]
    return ""


def package_url(ecosystem: str, name: str, version: str) -> str:
    """Package URL (purl). Maven ``grup:eser`` ad alanına, npm kapsamı (@a/b) ad alanına bölünür."""
    eco = normalize_ecosystem(ecosystem) or "generic"
    purl_type = _PURL_TYPES.get(eco, "generic")
    name = str(name or "").strip()
    namespace = ""
    if purl_type == "maven" and ":" in name:
        namespace, name = name.split(":", 1)
    elif purl_type in {"npm", "golang", "composer", "swift"} and "/" in name:
        namespace, name = name.rsplit("/", 1)
    elif purl_type == "pypi":
        name = re.sub(r"[-_.]+", "-", name).casefold()
    quote = lambda part: urllib.parse.quote(part, safe="")  # noqa: E731
    ns = "/".join(quote(p) for p in namespace.split("/") if p) if namespace else ""
    purl = f"pkg:{purl_type}/" + (f"{ns}/" if ns else "") + quote(name)
    if version:
        purl += "@" + urllib.parse.quote(str(version), safe="+")
    return purl


def parse_purl(purl: str) -> dict[str, str] | None:
    """``pkg:tür/ad-alanı/ad@sürüm?…#…`` → {ecosystem, name, version}. Tanınmayan biçimde ``None``."""
    match = re.fullmatch(r"pkg:([a-zA-Z][a-zA-Z0-9.+-]*)/([^@?#]+)(?:@([^?#]*))?(?:\?[^#]*)?(?:#.*)?", str(purl or "").strip())
    if not match:
        return None
    purl_type = match.group(1).casefold()
    parts = [urllib.parse.unquote(p) for p in match.group(2).split("/") if p]
    if not parts:
        return None
    eco = _PURL_TYPE_BACK.get(purl_type, purl_type)
    if purl_type == "maven" and len(parts) >= 2:
        name = f"{'.'.join(parts[:-1]) if len(parts) > 2 else parts[0]}:{parts[-1]}"
    else:
        name = "/".join(parts)
    return {"ecosystem": eco, "name": name, "version": urllib.parse.unquote(match.group(3) or "")}


def _name_key(ecosystem: str, name: str) -> str:
    name = str(name or "").strip().casefold()
    if normalize_ecosystem(ecosystem) == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    return name


def _severity(value: Any) -> str:
    text = str(value or "").strip().casefold()
    text = {"moderate": "medium", "informational": "info", "negligible": "low"}.get(text, text)
    return text if text in _CDX_SEVERITIES else "unknown"


def _source_name(vulnerability_id: str, source: str) -> str:
    vid = vulnerability_id.upper()
    if vid.startswith("CVE-"):
        return "NVD"
    if vid.startswith("GHSA-"):
        return "GitHub"
    if vid.startswith("GO-"):
        return "Go Vulnerability Database"
    if vid.startswith("PYSEC-"):
        return "PyPA"
    if vid.startswith("RUSTSEC-"):
        return "RustSec"
    return "OSV" if str(source).casefold() == "osv" else (str(source) or "OSV")


def _aliases(finding: dict[str, Any]) -> list[str]:
    """Bulgunun başvurularından tanınan zafiyet kimlikleri (CVE/GHSA/GO/PYSEC/RUSTSEC)."""
    found: list[str] = []
    vid = str(finding.get("vulnerability_id") or "").upper()
    for ref in finding.get("references") or []:
        for token in re.findall(r"\b(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d{4}|"
                                r"PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d{4})\b", str(ref), re.I):
            token = token.upper() if not token.lower().startswith("ghsa") else "GHSA" + token[4:].lower()
            if token.upper() != vid and token not in found:
                found.append(token)
    return found[:10]


# ---------------------------------------------------------------------------
# Envanter eşleştirme (purl ve "paket yok" kanıtı)
# ---------------------------------------------------------------------------
class Inventory:
    """``dependency_security.discover_inventory`` bileşenlerinden ad/sürüm dizini."""

    def __init__(self, components: Iterable[dict[str, Any]] | None) -> None:
        self.by_name: dict[str, list[dict[str, Any]]] = {}
        self.complete_ecosystems: set[str] = set()
        for component in components or []:
            eco = normalize_ecosystem(component.get("ecosystem"))
            self.by_name.setdefault(_name_key(eco, component.get("name")), []).append({**component, "_eco": eco})
            manifest = str(component.get("manifest") or "").rsplit("/", 1)[-1].casefold()
            if manifest in COMPLETE_LOCKFILES and COMPLETE_LOCKFILES[manifest] == eco:
                self.complete_ecosystems.add(eco)

    def match(self, name: str, version: str, ecosystem_hint: str = "") -> dict[str, Any] | None:
        candidates = self.by_name.get(name.strip().casefold()) or self.by_name.get(_name_key("pypi", name)) or []
        if ecosystem_hint:
            candidates = [c for c in candidates if c["_eco"] == ecosystem_hint] or candidates
        exact = [c for c in candidates if str(c.get("version") or "") == str(version or "")]
        return (exact or candidates or [None])[0]

    def absent_in_complete_lock(self, name: str, ecosystem: str) -> bool:
        """Paket, ekosisteminin TAM kilit dosyasında hiçbir sürümüyle yok mu? Kilit dosyası yoksa ``False``."""
        return bool(ecosystem) and ecosystem in self.complete_ecosystems and not any(
            c["_eco"] == ecosystem for c in self.by_name.get(_name_key(ecosystem, name), []))


# ---------------------------------------------------------------------------
# Karar
# ---------------------------------------------------------------------------
def validate_decision(payload: dict[str, Any]) -> dict[str, str]:
    """Analist kararı: not_affected → gerekçe + etki açıklaması (≥10 karakter); affected → eylem (≥5 karakter)."""
    if not isinstance(payload, dict):
        raise VexError("Karar bir JSON nesnesi olmalı.")
    status = str(payload.get("status") or "")
    if status not in STATUSES:
        raise VexError(f"Geçersiz VEX durumu: {status!r} (izinli: {', '.join(STATUSES)}).")
    justification = str(payload.get("justification") or "")
    impact = _text(payload.get("impact_statement"))
    action = _text(payload.get("action_statement"))
    notes = _text(payload.get("status_notes"))
    if status == "not_affected":
        if justification not in JUSTIFICATIONS:
            raise VexError("'Etkilenmiyor' kararı için geçerli bir gerekçe seçin.")
        if len(impact) < 10:
            raise VexError("'Etkilenmiyor' kararı için en az 10 karakterlik etki açıklaması yazın (neden etkilenmiyor?).")
    elif justification:
        raise VexError("Gerekçe yalnız 'Etkilenmiyor' kararında kullanılır.")
    if status == "affected" and len(action) < 5:
        raise VexError("'Etkileniyor' kararı için yapılacak eylemi yazın (ör. yükseltme sürümü).")
    return {"status": status, "justification": justification, "impact_statement": impact,
            "action_statement": action, "status_notes": notes}


def decide(finding: dict[str, Any], reach: dict[str, Any] | None, override: dict[str, Any] | None,
           inventory: Inventory | None = None, ecosystem: str = "", *, dev_only: bool = False,
           dev_not_affected: bool = False) -> dict[str, Any]:
    """Tek bulgu için VEX kararı (durum, gerekçe, açıklamalar, dayanak).

    ``dev_only``: paket kilit dosyasında yalnız geliştirme bağımlılığı (npm ``dev: true``, Pipfile ``develop``).
    Varsayılan olarak yalnız not düşülür; ``dev_not_affected`` (kullanıcı seçimi) ile "üretim yapıtında yok" sayılır."""
    package = str(finding.get("package_name") or "")
    fixed_version = str(finding.get("fixed_version") or "").strip()
    life = str(finding.get("status") or "open")
    reach = reach or {}
    verdict = str(reach.get("verdict") or "")
    evidence = [e for e in reach.get("evidence") or [] if isinstance(e, dict)][:5]
    upgrade = (f"{package} paketini {fixed_version} ya da üstüne yükseltin." if fixed_version else
               "Düzeltilmiş sürüm bildirilmemiş; paketi değiştirin ya da kullanımını sınırlayıp izleyin.")
    if override:
        result = {key: str(override.get(key) or "") for key in
                  ("status", "justification", "impact_statement", "action_statement", "status_notes")}
        result.update(basis=str(override.get("basis") or "analyst"), author=str(override.get("author") or ""),
                      decided_at=str(override.get("decided_at") or ""), source_name=str(override.get("source_name") or ""))
        result["evidence"] = evidence
        return result
    base = {"justification": "", "impact_statement": "", "action_statement": "", "status_notes": "", "basis": "auto",
            "author": "", "decided_at": "", "source_name": "", "evidence": evidence}
    if life == "resolved":
        return {**base, "status": "fixed", "basis": "scanner",
                "status_notes": "Son bağımlılık raporu bu paket sürümü için açığı artık bildirmiyor."}
    if str(finding.get("vulnerability_id") or "").startswith("MAL-"):
        # 20. tur: kötü amaçlı paket — kurulum anında çalışabilir; geliştirme bağımlılığı ya da erişilebilirlik
        # politikası "etkilenmiyor" kararı vermez (yalnız analist kararı ya da paketin kilitte hiç olmaması).
        if (inventory is not None and ecosystem and inventory.absent_in_complete_lock(package, ecosystem)):
            return {**base, "status": "not_affected", "justification": "component_not_present",
                    "impact_statement": f"{package} projenin tam kilit dosyasında ({ecosystem}) yer almıyor."}
        return {**base, "status": "affected",
                "action_statement": ("Kötü amaçlı paketi derhal kaldırın; kurulduğu makinelerdeki kimlik bilgilerini "
                                     "döndürün ve sistemleri inceleyin."),
                "impact_statement": "OpenSSF kötü amaçlı paket kaydı: paket kurulduğunda zararlı kod çalıştırabilir.",
                "status_notes": "Geliştirme bağımlılığı olsa bile kurulum betikleri geliştirici/CI ortamında çalışır."}
    # "Paket yok" yalnız kaynak da paketi kullanmıyorsa (ya da erişilebilirlik bilinmiyorsa) ve tam kilit dosyası varsa.
    if (inventory is not None and ecosystem and verdict in {"", "not_imported"}
            and inventory.absent_in_complete_lock(package, ecosystem)):
        return {**base, "status": "not_affected", "justification": "component_not_present",
                "impact_statement": (f"{package} projenin tam kilit dosyasında ({ecosystem}) hiçbir sürümüyle yer almıyor; "
                                     "bulgu eski bir rapordan kalmış. Yeni rapor içe aktarılınca doğrulanır.")}
    if life == "risk_accepted":
        notes = _text(finding.get("resolution_notes"), 500)
        return {**base, "status": "affected",
                "action_statement": "Risk kabul edildi" + (f": {notes}" if notes else "; düzeltme planlanmadı."),
                "status_notes": "Kabul eden: bağımlılık bulgusu yaşam döngüsü (risk_accepted)."}
    if verdict == "reachable":
        symbols = ", ".join(reach.get("matched_symbols") or [])[:300]
        return {**base, "status": "affected", "action_statement": upgrade,
                "impact_statement": (f"Açıklı fonksiyon(lar) kodda kullanılıyor: {symbols}." if symbols else
                                     "Açıklı fonksiyon kodda kullanılıyor.")}
    dev_note = "Yalnız geliştirme bağımlılığı (kilit dosyasında dev); üretim kurulumuna girmez."
    if dev_only and dev_not_affected:
        return {**base, "status": "not_affected", "justification": "component_not_present",
                "impact_statement": dev_note + " Politika: geliştirme bağımlılıkları üretim yapıtında yok sayılır.",
                "basis": "policy"}
    notes = {
        "imported_not_called": ("Paket içe aktarılıyor ama danışmadaki açıklı fonksiyon(lar) proje kaynağında çağrılmıyor "
                                f"({', '.join((reach.get('symbols') or [])[:8])}). Başka bir bağımlılığın bunları kendi "
                                "içinden çağırıp çağırmadığı analiz edilmediğinden 'etkilenmiyor' denmedi."),
        "not_imported": ("Paket doğrudan bildirilmiş ama proje kaynağında kullanılmıyor; kurulu olduğu için (yükleme "
                         "betikleri, dinamik yükleme, başka paketlerin kullanımı) 'etkilenmiyor' denmedi, karar inceleniyor."
                         if reach.get("usage") == "unused" else
                         "Paket proje kaynağında doğrudan içe aktarılmıyor; dolaylı bağımlılık olarak başka bir paket "
                         "tarafından kullanılabileceği için karar inceleniyor."),
        "unknown": str(reach.get("priority_reason") or "Paket kullanılıyor; açıklı fonksiyon bilgisi yok."),
    }.get(verdict, "Sembol düzeyi erişilebilirlik analizi yapılamadı.")
    if dev_only:
        notes = dev_note + " " + notes
    return {**base, "status": "under_investigation", "status_notes": notes, "action_statement": ""}


def build_statements(findings: Iterable[dict[str, Any]], reachability: dict[str, Any] | None,
                     overrides: dict[str, dict[str, Any]] | None = None,
                     components: Iterable[dict[str, Any]] | None = None, *,
                     dev_not_affected: bool = False) -> list[dict[str, Any]]:
    """Bulgular (+ erişilebilirlik sonucu + analist/içe aktarılan kararlar) → normalleştirilmiş VEX ifadeleri."""
    overrides = overrides or {}
    inventory = Inventory(components) if components is not None else None
    reach_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in (reachability or {}).get("items") or []:
        if isinstance(item, dict):
            key = (str(item.get("package_name") or "").casefold(), str(item.get("installed_version") or ""),
                   str(item.get("vulnerability_id") or item.get("id") or "").casefold())
            reach_by_key[key] = item.get("reachability") or {}
    statements: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        package = str(finding.get("package_name") or "").strip()
        vid = str(finding.get("vulnerability_id") or "").strip()
        if not package or not vid:
            continue
        version = str(finding.get("installed_version") or "")
        hint = normalize_ecosystem(finding.get("target")) or normalize_ecosystem(finding.get("ecosystem"))
        component = inventory.match(package, version, hint) if inventory else None
        ecosystem = (component or {}).get("_eco") or hint
        purl = (component or {}).get("purl") if component and str(component.get("version") or "") == version else None
        purl = purl or package_url(ecosystem, package, version)
        reach = reach_by_key.get((package.casefold(), version, vid.casefold())) or \
            reach_by_key.get((package.casefold(), "", vid.casefold()))
        dev_only = bool(component and component.get("scope") == "optional")
        decision = decide(finding, reach, overrides.get(str(finding.get("id") or "")), inventory, ecosystem,
                          dev_only=dev_only, dev_not_affected=dev_not_affected)
        statements.append({
            "finding_id": str(finding.get("id") or ""),
            "vulnerability_id": vid,
            "aliases": _aliases(finding),
            "source": _source_name(vid, str(finding.get("source") or "")),
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "purl": purl,
            "severity": _severity(finding.get("severity")),
            "title": _text(finding.get("title"), 300),
            "fixed_version": str(finding.get("fixed_version") or ""),
            "reachability": str((reach or {}).get("verdict") or ""),
            "dev_only": dev_only,
            "finding_ids": [str(finding.get("id") or "")],
            **decision,
        })
    statements = _dedupe(statements)
    statements.sort(key=lambda s: (STATUSES.index(s["status"]) if s["status"] in STATUSES else 9,
                                   s["package"].casefold(), s["vulnerability_id"]))
    return statements


def _dedupe(statements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aynı (açık, purl) için tek ifade: analist/içe aktarılan karar önce; yoksa en temkinli durum (etkileniyor >
    inceleniyor > etkilenmiyor > düzeltildi). Birleşen bulgu kimlikleri ``finding_ids`` alanında tutulur."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for st in statements:
        key = (st["vulnerability_id"].casefold(), st["purl"])
        current = merged.get(key)
        if current is None:
            merged[key] = st
            continue
        rank = lambda x: (_BASIS_RANK.get(x["basis"], 9) if x["basis"] in {"analyst", "imported"} else 5,  # noqa: E731
                          _STATUS_CAUTION.get(x["status"], 9))
        keep, other = (st, current) if rank(st) < rank(current) else (current, st)
        keep["finding_ids"] = list(dict.fromkeys(current["finding_ids"] + st["finding_ids"]))
        keep["aliases"] = list(dict.fromkeys(current["aliases"] + st["aliases"]))[:10]
        merged[key] = keep
    return list(merged.values())


def summary(statements: Iterable[dict[str, Any]]) -> dict[str, Any]:
    counts = {status: 0 for status in STATUSES}
    bases: dict[str, int] = {}
    for st in statements:
        counts[st["status"]] = counts.get(st["status"], 0) + 1
        bases[st["basis"]] = bases.get(st["basis"], 0) + 1
    return {"statuses": counts, "basis": bases, "total": sum(counts.values())}


# ---------------------------------------------------------------------------
# Belgeler
# ---------------------------------------------------------------------------
def _doc_uuid(kind: str, project: str, statements: list[dict[str, Any]]) -> str:
    canonical = json.dumps([kind, project, [[s["vulnerability_id"], s["purl"], s["status"], s["justification"],
                                             s["impact_statement"], s["action_statement"]] for s in statements]],
                           ensure_ascii=False, sort_keys=True)
    return str(uuid.uuid5(_VEX_NAMESPACE, canonical))


def cyclonedx_vex(statements: list[dict[str, Any]], *, project_name: str, timestamp: str,
                  tool_version: str = "") -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}
    vulnerabilities = []
    for index, st in enumerate(statements, start=1):
        components.setdefault(st["purl"], {"type": "library", "bom-ref": st["purl"], "name": st["package"],
                                           **({"version": st["version"]} if st["version"] else {}), "purl": st["purl"]})
        analysis: dict[str, Any] = {"state": _CDX_STATE[st["status"]]}
        if st["justification"]:
            analysis["justification"] = _CDX_JUSTIFICATION[st["justification"]]
        response = []
        if st["status"] == "affected":
            response.append("will_not_fix" if st["action_statement"].startswith("Risk kabul edildi") else "update")
        if response:
            analysis["response"] = response
        detail = " ".join(x for x in (st["impact_statement"], st["status_notes"]) if x)
        if detail:
            analysis["detail"] = detail[:MAX_TEXT]
        if st.get("decided_at"):
            analysis["lastUpdated"] = st["decided_at"]
        vuln: dict[str, Any] = {
            "bom-ref": f"vex-{index}",
            "id": st["vulnerability_id"],
            "source": {"name": st["source"]},
            "ratings": [{"severity": st["severity"], "method": "other"}],
            "analysis": analysis,
            "affects": [{"ref": st["purl"], "versions": [{"version": st["version"] or "*",
                                                          "status": "unaffected" if st["status"] in {"not_affected", "fixed"}
                                                          else "affected" if st["status"] == "affected" else "unknown"}]}],
            "properties": [{"name": "sniper:vex-basis", "value": st["basis"]}]
            + ([{"name": "sniper:reachability", "value": st["reachability"]}] if st["reachability"] else []),
        }
        if st["title"]:
            vuln["description"] = st["title"]
        if st["action_statement"]:
            vuln["recommendation"] = st["action_statement"]
        if st["aliases"]:
            vuln["references"] = [{"id": alias, "source": {"name": _source_name(alias, "")}} for alias in st["aliases"]]
        vulnerabilities.append(vuln)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{_doc_uuid('cyclonedx', project_name, statements)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "Sniper", **({"version": tool_version} if tool_version else {})}]},
            "component": {"type": "application", "bom-ref": "sniper-project", "name": project_name},
        },
        "components": list(components.values()),
        "vulnerabilities": vulnerabilities,
    }


def openvex(statements: list[dict[str, Any]], *, project_name: str, timestamp: str, author: str = "Sniper",
            tool_version: str = "") -> dict[str, Any]:
    out = []
    for st in statements:
        statement: dict[str, Any] = {
            "vulnerability": {"name": st["vulnerability_id"], **({"aliases": st["aliases"]} if st["aliases"] else {})},
            "products": [{"@id": st["purl"]}],
            "status": st["status"],
        }
        if st["status"] == "not_affected":
            statement["justification"] = st["justification"]
            if st["impact_statement"]:
                statement["impact_statement"] = st["impact_statement"]
        elif st["impact_statement"]:
            statement["status_notes"] = st["impact_statement"]
        if st["status"] == "affected":
            statement["action_statement"] = st["action_statement"] or "Paketi düzeltilmiş sürüme yükseltin."
        if st["status_notes"]:
            statement["status_notes"] = " ".join(x for x in (statement.get("status_notes"), st["status_notes"]) if x)[:MAX_TEXT]
        if st.get("decided_at"):
            statement["timestamp"] = st["decided_at"]
        out.append(statement)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{_doc_uuid('openvex', project_name, statements)}",
        "author": author or "Sniper",
        "role": "Document Creator",
        "timestamp": timestamp,
        "version": 1,
        "tooling": "Sniper" + (f" {tool_version}" if tool_version else ""),
        "statements": out,
    }


def render(statements: list[dict[str, Any]], fmt: str, *, project_name: str, timestamp: str, author: str = "",
           tool_version: str = "") -> dict[str, Any]:
    if fmt == "cyclonedx":
        return cyclonedx_vex(statements, project_name=project_name, timestamp=timestamp, tool_version=tool_version)
    if fmt == "openvex":
        return openvex(statements, project_name=project_name, timestamp=timestamp, author=author or "Sniper",
                       tool_version=tool_version)
    raise VexError(f"Geçersiz VEX biçimi: {fmt!r} (izinli: {', '.join(FORMATS)}).")


# ---------------------------------------------------------------------------
# İçe aktarma (tedarikçi / üst proje VEX'i)
# ---------------------------------------------------------------------------
def parse_document(document: Any) -> tuple[str, str, list[dict[str, Any]]]:
    """OpenVEX ya da CycloneDX VEX → (biçim, kaynak adı, ifadeler). İfade: ids, products(purl ayrıştırılmış), karar."""
    if not isinstance(document, dict):
        raise VexError("VEX belgesi bir JSON nesnesi olmalı.")
    statements: list[dict[str, Any]] = []
    if str(document.get("@context") or "").startswith("https://openvex.dev/ns"):
        fmt, source = "openvex", _text(document.get("author") or document.get("@id") or "OpenVEX", 200)
        for raw in (document.get("statements") or [])[:MAX_IMPORT_STATEMENTS]:
            if not isinstance(raw, dict):
                continue
            vuln = raw.get("vulnerability") or {}
            ids = [str(vuln.get("name") or vuln.get("@id") or "")] if isinstance(vuln, dict) else [str(vuln)]
            ids += [str(a) for a in (vuln.get("aliases") or [])] if isinstance(vuln, dict) else []
            products = []
            for product in raw.get("products") or []:
                ref = product.get("@id") if isinstance(product, dict) else product
                ident = (product.get("identifiers") or {}).get("purl") if isinstance(product, dict) else None
                parsed = parse_purl(str(ident or ref or ""))
                if parsed:
                    products.append(parsed)
            statements.append({"ids": ids, "products": products, "status": str(raw.get("status") or ""),
                               "justification": str(raw.get("justification") or ""),
                               "impact_statement": _text(raw.get("impact_statement")),
                               "action_statement": _text(raw.get("action_statement")),
                               "status_notes": _text(raw.get("status_notes"))})
    elif str(document.get("bomFormat") or "") == "CycloneDX" and isinstance(document.get("vulnerabilities"), list):
        fmt = "cyclonedx"
        source = _text(((document.get("metadata") or {}).get("component") or {}).get("name") or document.get("serialNumber")
                       or "CycloneDX VEX", 200)
        refs = {str(c.get("bom-ref")): str(c.get("purl") or "") for c in document.get("components") or []
                if isinstance(c, dict) and c.get("bom-ref")}
        for raw in document["vulnerabilities"][:MAX_IMPORT_STATEMENTS]:
            if not isinstance(raw, dict):
                continue
            analysis = raw.get("analysis") or {}
            state = _CDX_STATE_BACK.get(str(analysis.get("state") or ""), "")
            justification = _CDX_JUSTIFICATION_BACK.get(str(analysis.get("justification") or ""), "")
            if state == "not_affected" and not justification:
                justification = ("vulnerable_code_not_present" if analysis.get("state") == "false_positive"
                                 else "vulnerable_code_not_in_execute_path")
            ids = [str(raw.get("id") or "")] + [str(r.get("id") or "") for r in raw.get("references") or [] if isinstance(r, dict)]
            products = []
            for affect in raw.get("affects") or []:
                ref = str((affect or {}).get("ref") or "")
                ref = refs.get(ref.split("#", 1)[-1], refs.get(ref, ref))
                parsed = parse_purl(ref)
                if parsed:
                    products.append(parsed)
            detail = _text(analysis.get("detail"))
            statements.append({"ids": ids, "products": products, "status": state, "justification": justification,
                               "impact_statement": detail if state == "not_affected" else "",
                               "action_statement": _text(raw.get("recommendation")) if state == "affected" else "",
                               "status_notes": "" if state == "not_affected" else detail})
    else:
        raise VexError("Tanınmayan VEX belgesi: OpenVEX (@context openvex.dev) ya da CycloneDX (vulnerabilities) bekleniyor.")
    return fmt, source, statements


def match_imported(statements: list[dict[str, Any]], findings: Iterable[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], int]:
    """İçe aktarılan ifadeleri bulgulara eşler: kimlik (ya da takma ad) + paket adı (+ purl sürümü varsa sürüm).

    Döndürür: (bulgu kimliği → karar, eşleşmeyen ifade sayısı). Geçersiz ifadeler (ör. gerekçesiz not_affected)
    eşleşse bile alınmaz."""
    by_vuln: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        ids = {str(finding.get("vulnerability_id") or "").casefold()} | {a.casefold() for a in _aliases(finding)}
        for vid in ids - {""}:
            by_vuln.setdefault(vid, []).append(finding)
    decisions: dict[str, dict[str, Any]] = {}
    unmatched = 0
    for st in statements:
        try:
            decision = validate_decision({k: st.get(k) for k in ("status", "justification", "impact_statement",
                                                                  "action_statement", "status_notes")}
                                         if st.get("status") != "not_affected" or st.get("impact_statement") else
                                         {**st, "impact_statement": "İçe aktarılan VEX belgesindeki karar (açıklama yok)."})
        except VexError:
            unmatched += 1
            continue
        hit = False
        for vid in {i.casefold() for i in st.get("ids") or [] if i}:
            for finding in by_vuln.get(vid, []):
                name = str(finding.get("package_name") or "")
                version = str(finding.get("installed_version") or "")
                eco = normalize_ecosystem(finding.get("target"))
                for product in st.get("products") or []:
                    same_name = _name_key(product["ecosystem"], product["name"]) == _name_key(eco or product["ecosystem"], name)
                    if same_name and (not product["version"] or product["version"] == version):
                        decisions[str(finding["id"])] = decision
                        hit = True
                        break
        if not hit:
            unmatched += 1
    return decisions, unmatched


def document_hash(document: Any) -> str:
    return hashlib.sha256(json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Proje düzeyi: depolanan bulgular + erişilebilirlik + envanter + kararlar → belge
# ---------------------------------------------------------------------------
def project_findings(store: Any, project_path: str, allowed_roots: Any = None) -> tuple[str, list[dict[str, Any]]]:
    """Proje yolunu doğrular; depodaki bağımlılık bulgularını (çözülmüş ya da yazıldığı biçimdeki yolla) döndürür."""
    from project_analyzer import validate_project_path

    root = validate_project_path(project_path, allowed_roots)
    findings = store.dependency_findings_for_project(str(root))
    if not findings and str(project_path).strip() != str(root):
        findings = store.dependency_findings_for_project(str(project_path).strip())
    return str(root), findings


def generate_for_project(store: Any, project_path: str, fmt: str, *, author: str = "",
                         allowed_roots: Any = None, timestamp: str | None = None,
                         dev_not_affected: bool = False) -> dict[str, Any]:
    if fmt not in FORMATS:
        raise VexError(f"Geçersiz VEX biçimi: {fmt!r} (izinli: {', '.join(FORMATS)}).")
    from dependency_security import analyze_vulnerability_reachability, discover_inventory
    from scanner import utc_now
    from version import __version__

    root, findings = project_findings(store, project_path, allowed_roots)
    if not findings:
        raise VexError("Bu proje için kayıtlı bağımlılık bulgusu yok; önce OSV/Trivy raporu içe aktarın.")
    active = [f for f in findings if f.get("status") != "resolved"]
    reachability = analyze_vulnerability_reachability(root, findings=active, allowed_roots=allowed_roots) if active else {}
    try:
        _, components, _ = discover_inventory(root, allowed_roots=allowed_roots)
    except Exception:  # noqa: BLE001 — envanter okunamazsa "paket yok" kanıtı kullanılmaz
        components = None
    overrides = store.vex_decisions([str(f["id"]) for f in findings])
    statements = build_statements(findings, reachability, overrides, components, dev_not_affected=dev_not_affected)
    name = root.rstrip("/").rsplit("/", 1)[-1]
    document = render(statements, fmt, project_name=name, timestamp=timestamp or utc_now(), author=author,
                      tool_version=__version__)
    return {"format": fmt, "project_path": root, "project_name": name, "summary": summary(statements),
            "statements": statements, "document": document, "dev_not_affected": dev_not_affected}


def import_for_project(store: Any, project_path: str, document: Any, *, overwrite_analyst: bool = False,
                       allowed_roots: Any = None) -> dict[str, Any]:
    fmt, source, statements = parse_document(document)
    root, findings = project_findings(store, project_path, allowed_roots)
    if not findings:
        raise VexError("Bu proje için kayıtlı bağımlılık bulgusu yok; içe aktarılacak eşleşme bulunamaz.")
    decisions, unmatched = match_imported(statements, findings)
    digest = document_hash(document)
    applied = skipped = 0
    for finding_id, decision in decisions.items():
        result = store.set_vex_decision(finding_id, decision, basis="imported", source_name=source, source_hash=digest,
                                        overwrite_analyst=overwrite_analyst)
        if result and result.get("skipped"):
            skipped += 1
        elif result:
            applied += 1
    store.log("dependency_vex.imported", digest[:16], {"format": fmt, "source": source, "statements": len(statements),
                                                       "applied": applied, "skipped_analyst": skipped,
                                                       "unmatched": unmatched})
    return {"format": fmt, "source": source, "project_path": root, "statements": len(statements), "applied": applied,
            "skipped_analyst": skipped, "unmatched": unmatched, "document_sha256": digest}
