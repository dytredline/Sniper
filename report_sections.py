"""Rapor bölümleri (21. tur): her bulguyu tek bir alana yerleştirir ve alan başına sayıları, en önemli 5 maddeyi ve
önerilen eylemi üretir. Yönetici özeti, proje HTML/PDF raporu ve portföy aynı sınıflandırmayı kullanır; böylece önem
sayıları tek kaynaktan hesaplanır ve bir bulgu iki alanda birden sayılmaz.

Kaynaklar:
* proje analizinden gelen bulgular (bulgu takibindeki etkin kayıtlar ya da tek analizin bulguları),
* çevrimdışı bağımlılık taraması (``dependency_findings``; bulgu takibinde değildir, ayrı kümedir).
Kötü amaçlı paket hem proje analizinde (tedarik zinciri kancası) hem bağımlılık taramasında çıkabilir; aynı paket@sürüm
bir kez sayılır.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

SECTION_ORDER = ("code", "dependencies", "license", "iac", "container", "api", "supply_chain")
SECTION_LABELS = {
    "code": "Kod (veri akışı ve desen bulguları)",
    "dependencies": "Bağımlılıklar",
    "license": "Lisans",
    "iac": "Altyapı (IaC)",
    "container": "Konteyner",
    "api": "API sözleşmesi ve erişim denetimi",
    "supply_chain": "Tedarik zinciri",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
DEPENDENCY_ACTIVE = frozenset({"open", "in_progress", "retest_required", "reopened"})
_IAC_TITLE = re.compile(r"^(Terraform|Kubernetes|Helm|Dockerfile|docker-compose|Compose|Konteyner (imajı|açıkça|ayrıcalıklı)|"
                        r"GitHub Actions|GitLab CI|CI )")
_MALICIOUS_TITLE = "Kötü amaçlı paket"
_MAL_PKG = re.compile(r"^Kötü amaçlı paket: (?P<name>\S+) (?P<version>\S+)")


def is_malicious(finding: dict[str, Any]) -> bool:
    title = str(finding.get("title") or "")
    ref = str(finding.get("reference") or finding.get("vulnerability_id") or "")
    return (finding.get("malicious") is True or title.startswith(_MALICIOUS_TITLE + ":") or ref.startswith("MAL-")
            or (str(finding.get("cwe") or "") == "CWE-506" and str(finding.get("category") or "") == "supply_chain"))


def section_of(finding: dict[str, Any]) -> str:
    """Bulgunun rapor alanı. ``finding`` proje analizi bulgusu ya da bulgu takibi satırıdır (``finding`` alanı varsa
    tam bulgu kullanılır)."""
    if finding.get("section") in SECTION_LABELS:
        return finding["section"]  # bulgu takibi satırında önceden hesaplanmış
    full = finding.get("finding") if isinstance(finding.get("finding"), dict) and finding.get("finding") else finding
    category = str(full.get("category") or finding.get("category") or "").strip().lower()
    if is_malicious(full) or is_malicious(finding):
        return "dependencies"
    if category in ("container_os", "container_lang"):
        return "container"
    if category == "sbom_component":
        package = full.get("package") if isinstance(full.get("package"), dict) else {}
        return "container" if str(package.get("type") or "") in ("deb", "apk", "rpm") else "dependencies"
    if full.get("iac") or category == "supplychain":
        return "iac"
    if category in ("container", "iac", "cloud", "kubernetes", "terraform", "dockerfile", "helm"):
        return "iac"
    if category == "license":
        return "license"
    if category in ("api", "authz"):
        return "api"
    if category == "supply_chain":
        return "supply_chain"
    if category == "components":
        return "dependencies"
    # Tam bulgusu olmayan eski takip satırları: IaC başlıkları
    if not isinstance(finding.get("finding"), dict) and _IAC_TITLE.match(str(finding.get("title") or "")):
        return "iac"
    return "code"


def _sev(value: Any) -> str:
    value = str(value or "").lower()
    return value if value in SEVERITIES else "unknown"


def _malicious_key(item: dict[str, Any]) -> tuple[str, str] | None:
    if item.get("package_name"):
        return (str(item["package_name"]).lower(), str(item.get("installed_version") or ""))
    match = _MAL_PKG.match(str(item.get("title") or ""))
    return (match["name"].lower(), match["version"]) if match else None


def _empty() -> dict[str, Any]:
    return {"active": 0, "by_severity": {s: 0 for s in SEVERITIES}, "items": [], "malicious": 0, "verified_flows": 0}


def _action(key: str, entry: dict[str, Any]) -> str:
    sev = entry["by_severity"]
    if not entry["active"]:
        return "Etkin bulgu yok; sonraki analizlerde izlemeyi sürdürün."
    if key == "code":
        if entry["verified_flows"]:
            return ("Doğrulanmış veri akışlarını (kaynaktan hedefe izlenen) önce düzeltin; desen bulgularını gözden "
                    "geçirip yanlış alarmları işaretleyin.")
        return "Desen bulgularını gözden geçirin; gerçek olanları düzeltin, diğerlerini yanlış alarm olarak işaretleyin."
    if key == "dependencies":
        if entry["malicious"]:
            return ("Kötü amaçlı paketleri derhal kaldırın, bu paketin kurulduğu makinelerde ve CI'da kullanılan kimlik "
                    "bilgilerini döndürün; ardından 'önce düzelt' listesindeki paketleri yükseltin.")
        if entry.get("fix_first"):
            return "'Önce düzelt' listesindeki paketleri düzeltilmiş sürüme yükseltin; kullanılmayan bağımlılıkları kaldırın."
        return "Açıklı paketleri düzeltilmiş sürümlere yükseltin; sürüm sabitleme ve kilit dosyası kullanın."
    if key == "license":
        return "Yasak ve dikkat gerektiren lisansları hukuk/uyum ekibiyle gözden geçirin; gerekirse paketi değiştirin."
    if key == "iac":
        if sev["critical"] or sev["high"]:
            return "Herkese açık erişim ve ayrıcalıklı yapılandırmaları önce kapatın; ardından şifreleme ve günlüklemeyi açın."
        return "Varsayılan ayar ve sertleştirme notlarını altyapı kodunda düzeltin."
    if key == "container":
        return "Temel imajı güncelleyip imajı yeniden derleyin; düzeltmesi olmayan paketleri kaldırmayı değerlendirin."
    if key == "api":
        return "Korumasız rotalara kimlik doğrulama/yetki ekleyin; API sözleşmesini kodla eşitleyin (gölge uçları belgeleyin ya da kaldırın)."
    if key == "supply_chain":
        return "Kurulum betiklerini ve kayıt deposu yapılandırmasını gözden geçirin; iç paketleri kapsamlı (scoped) adlarla yayımlayın."
    return ""


def _item(finding: dict[str, Any], *, source: str) -> dict[str, Any]:
    full = finding.get("finding") if isinstance(finding.get("finding"), dict) else finding
    if source == "dependency":
        return {
            "source": source, "severity": _sev(finding.get("severity")), "title": str(finding.get("title") or "")[:300],
            "package": finding.get("package_name"), "version": finding.get("installed_version"),
            "fixed_version": finding.get("fixed_version") or "", "reference": finding.get("vulnerability_id"),
            "priority_score": finding.get("priority_score"), "priority_tier": finding.get("priority_tier") or "",
            "usage": finding.get("usage_state") or "", "status": finding.get("status"),
            "malicious": is_malicious(finding),
        }
    return {
        "source": source, "severity": _sev(finding.get("severity")), "title": str(finding.get("title") or "")[:300],
        "file": finding.get("file") or "", "line": finding.get("line") or 0, "reference": finding.get("reference") or "",
        "status_label": finding.get("status_label") or "", "id": finding.get("id"),
        "verified_flow": (bool(finding["verified_flow"]) if "verified_flow" in finding else
                          bool(full.get("taint_flow")) and str(full.get("title") or "").startswith("Doğrulanmış")),
        "malicious": bool(finding.get("malicious")) or is_malicious(full),
        "assignee_name": finding.get("assignee_name") or "", "due_date": finding.get("due_date") or "",
        "overdue": bool(finding.get("overdue")),
    }


def _sort_key(item: dict[str, Any]) -> tuple:
    return (0 if item.get("malicious") else 1, SEVERITY_RANK.get(item["severity"], 5),
            -(item.get("priority_score") or 0), str(item.get("title") or ""), str(item.get("file") or ""),
            int(item.get("line") or 0))


def build_sections(findings: Iterable[dict[str, Any]], dependency_findings: Iterable[dict[str, Any]] = (), *,
                   licenses: dict[str, Any] | None = None, api_contract: dict[str, Any] | None = None,
                   supply_chain: dict[str, Any] | None = None, container: dict[str, Any] | None = None,
                   top: int = 5) -> dict[str, Any]:
    """Alanlara göre özet. ``findings``: etkin proje bulguları (bastırılmış/düzelmiş olmayanlar); ``dependency_findings``:
    projenin kayıtlı bağımlılık bulguları (yalnız etkin durumdakiler sayılır). Dönen ``totals`` iki kümenin
    çakışmasız toplamıdır."""
    sections = {key: _empty() for key in SECTION_ORDER}
    malicious_seen: set[tuple[str, str]] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = section_of(finding)
        item = _item(finding, source="project")
        entry = sections[key]
        if item["malicious"]:
            mk = _malicious_key(finding)
            if mk:
                malicious_seen.add(mk)
            entry["malicious"] += 1
        entry["active"] += 1
        if item["severity"] in entry["by_severity"]:
            entry["by_severity"][item["severity"]] += 1
        else:
            entry["by_severity"]["unknown"] = entry["by_severity"].get("unknown", 0) + 1
        entry["verified_flows"] += int(item["verified_flow"])
        entry["items"].append(item)
    dep = sections["dependencies"]
    dep["fix_first"] = 0
    dep["scanned"] = 0
    for finding in dependency_findings:
        if not isinstance(finding, dict):
            continue
        dep["scanned"] += 1
        if str(finding.get("status") or "open") not in DEPENDENCY_ACTIVE:
            continue
        item = _item(finding, source="dependency")
        if item["malicious"]:
            mk = _malicious_key(finding)
            if mk and mk in malicious_seen:
                continue  # proje analizinde zaten sayıldı (aynı paket@sürüm)
            if mk:
                malicious_seen.add(mk)
            dep["malicious"] += 1
        dep["active"] += 1
        if item["severity"] in dep["by_severity"]:
            dep["by_severity"][item["severity"]] += 1
        else:
            dep["by_severity"]["unknown"] = dep["by_severity"].get("unknown", 0) + 1
        if item["priority_tier"] == "fix_first":
            dep["fix_first"] += 1
        dep["items"].append(item)
    out_sections = []
    totals = {"active": 0, "by_severity": {s: 0 for s in SEVERITIES}}
    for key in SECTION_ORDER:
        entry = sections[key]
        items = sorted(entry.pop("items"), key=_sort_key)
        entry.update({
            "key": key, "label": SECTION_LABELS[key], "top": items[:top], "action": _action(key, entry),
            "critical_high": entry["by_severity"]["critical"] + entry["by_severity"]["high"],
        })
        totals["active"] += entry["active"]
        for sev, n in entry["by_severity"].items():
            totals["by_severity"][sev] = totals["by_severity"].get(sev, 0) + n
        out_sections.append(entry)
    context: dict[str, Any] = {}
    if isinstance(licenses, dict) and licenses:
        cats = licenses.get("by_category") or {}
        project_license = licenses.get("project_license")
        context["license"] = {"components": int(licenses.get("component_count") or 0),
                              "project_license": (project_license.get("expression") if isinstance(project_license, dict)
                                                  else project_license) or "",
                              **{k: int(cats.get(k) or 0) for k in ("allowed", "caution", "denied", "review")}}
    if isinstance(api_contract, dict) and api_contract.get("summary"):
        summary = api_contract["summary"]
        context["api"] = {k: int(summary.get(k) or 0) for k in ("specs", "spec_operations", "matched_operations",
                                                                "code_routes", "shadow_routes", "missing_in_code",
                                                                "auth_mismatch", "doc_auth_drift", "param_gaps")}
    if isinstance(supply_chain, dict) and isinstance(supply_chain.get("summary"), dict):
        context["supply_chain"] = {k: v for k, v in supply_chain["summary"].items() if isinstance(v, (int, str))}
    if isinstance(container, dict) and container:
        os_info = container.get("os") or {}
        context["container"] = {"os": os_info.get("pretty_name") or os_info.get("id") or "",
                                "packages": int(container.get("package_count") or 0),
                                "fixable": int(container.get("fixable_findings") or 0)}
    return {"sections": out_sections, "totals": totals, "context": context}


def section_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Portföy için alan başına etkin bulgu sayısı (rows: section_of'a verilebilen kayıtlar)."""
    counts = {key: 0 for key in SECTION_ORDER}
    for row in rows:
        counts[section_of(row)] += 1
    return counts
