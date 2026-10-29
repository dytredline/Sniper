"""CI/CD politika kapısı ve rapor üreticileri (21. tur).

Tek çalıştırmada (ağsız) şunları birleştirir:
* proje analizi (taint akışları, desen kuralları, IaC, lisans, tedarik zinciri/kötü amaçlı paket, API sözleşmesi),
* çevrimdışı çok ekosistemli SCA (yerel OSV) + kullanım/erişilebilirlik önceliği ("Önce düzelt" katmanı),
* SARIF 2.1.0 (GitHub code scanning), GitLab ``gl-sast-report.json`` ve ``gl-dependency-scanning-report.json``,
* politika (``.sniper-policy.json|yml``) ile karar, Markdown özeti ($GITHUB_STEP_SUMMARY uyumlu).

Çıkış kodları (``EXIT_*``): 0 geçti · 1 politika ihlali · 2 yapılandırma/kullanım hatası · 3 analiz hatası.
Kötü amaçlı paket her zaman başarısızdır; istisna ve eşik ayarı bunu değiştiremez.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

import finding_tracking

EXIT_PASS = 0
EXIT_POLICY = 1
EXIT_CONFIG = 2
EXIT_ERROR = 3

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
GITLAB_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

# Politika kategorileri (bulgunun "grubu"). Eşik her grup için ayrı verilebilir.
GROUPS = ("code", "iac", "sca", "malicious", "license", "supply_chain", "container", "api")
GROUP_LABELS = {
    "code": "Kod (SAST)", "iac": "Altyapı (IaC)", "sca": "Bağımlılık açığı (SCA)", "malicious": "Kötü amaçlı paket",
    "license": "Lisans", "supply_chain": "Tedarik zinciri", "container": "Konteyner", "api": "API sözleşmesi",
}
POLICY_FILES = (".sniper-policy.json", ".sniper-policy.yml", ".sniper-policy.yaml")
DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "fail_on": {"default": "high"},
    "new_only": False,
    "license_denied": True,
    "sla_breach": False,
    "sca_fix_first": False,
    "iac_fix_first": False,
    "require_osv": False,
    "exceptions": [],
}
_POLICY_KEYS = set(DEFAULT_POLICY) | {"baseline"}
_ID_RE = re.compile(r"[A-Za-z0-9_.:/@+\-]{1,200}\Z")
_TOOL_NAME = "Sniper"
_INFO_URI = "https://owasp.org/www-project-web-security-testing-guide/"
MAX_SARIF_RESULTS = 25_000  # GitHub code scanning sınırı


class PolicyError(ValueError):
    """Politika dosyası geçersiz (çıkış kodu 2)."""


# ---------------------------------------------------------------------------
# Politika
# ---------------------------------------------------------------------------
def _severity_or_none(value: Any, where: str) -> str | None:
    if value is None or value == "none":
        return None
    if value not in SEVERITIES:
        raise PolicyError(f"{where}: önem şunlardan biri olmalı: {', '.join(SEVERITIES)} ya da none.")
    return value


def _parse_date(value: Any, where: str) -> dt.date:
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        raise PolicyError(f"{where}: tarih YYYY-AA-GG biçiminde olmalı.") from None


def validate_policy(raw: Any) -> dict[str, Any]:
    """Politikayı doğrula ve varsayılanlarla birleştir. Bilinmeyen anahtar hatadır (yazım hatası sessiz geçmesin)."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError("Politika bir nesne olmalı.")
    unknown = set(raw) - _POLICY_KEYS
    if unknown:
        raise PolicyError("Bilinmeyen politika anahtarı: " + ", ".join(sorted(unknown)))
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    if raw.get("version", 1) != 1:
        raise PolicyError("Desteklenen politika sürümü: 1.")
    fail_on = raw.get("fail_on", policy["fail_on"])
    if isinstance(fail_on, str) or fail_on is None:
        fail_on = {"default": fail_on}
    if not isinstance(fail_on, dict):
        raise PolicyError("fail_on bir önem ya da {grup: önem} nesnesi olmalı.")
    clean_fail: dict[str, str | None] = {}
    for key, value in fail_on.items():
        if key != "default" and key not in GROUPS:
            raise PolicyError(f"fail_on: bilinmeyen grup '{key}' (gruplar: default, {', '.join(GROUPS)}).")
        if key == "malicious":
            raise PolicyError("fail_on.malicious ayarlanamaz: kötü amaçlı paket her zaman başarısızdır.")
        clean_fail[key] = _severity_or_none(value, f"fail_on.{key}")
    clean_fail.setdefault("default", "high")
    policy["fail_on"] = clean_fail
    for flag in ("new_only", "license_denied", "sla_breach", "sca_fix_first", "iac_fix_first", "require_osv"):
        if flag in raw:
            if not isinstance(raw[flag], bool):
                raise PolicyError(f"{flag} true ya da false olmalı.")
            policy[flag] = raw[flag]
    baseline = raw.get("baseline")
    if baseline is not None:
        if not isinstance(baseline, dict) or not set(baseline) <= {"sarif", "audit_id", "git_ref"} or len(baseline) != 1:
            raise PolicyError("baseline yalnız tek anahtar içerir: sarif, audit_id ya da git_ref.")
        (kind, value), = baseline.items()
        if not isinstance(value, str) or not value.strip() or len(value) > 512:
            raise PolicyError("baseline değeri boş olmayan bir metin olmalı.")
        policy["baseline"] = {kind: value.strip()}
    exceptions = raw.get("exceptions", [])
    if not isinstance(exceptions, list) or len(exceptions) > 500:
        raise PolicyError("exceptions en çok 500 öğelik bir liste olmalı.")
    clean_exc = []
    for index, item in enumerate(exceptions):
        where = f"exceptions[{index}]"
        if not isinstance(item, dict) or not set(item) <= {"id", "reason", "expires", "path"}:
            raise PolicyError(f"{where}: yalnız id, reason, expires, path alanları.")
        ident, reason = item.get("id"), item.get("reason")
        if not isinstance(ident, str) or not _ID_RE.fullmatch(ident.strip()):
            raise PolicyError(f"{where}.id: parmak izi, kural/CWE, açık kimliği (GHSA/CVE) ya da package:<ad>.")
        if not isinstance(reason, str) or len(reason.strip()) < 10 or len(reason) > 500:
            raise PolicyError(f"{where}.reason: en az 10 karakterlik gerekçe zorunlu.")
        if "expires" not in item:
            raise PolicyError(f"{where}.expires: süresiz istisna yok; bitiş tarihi zorunlu.")
        path = item.get("path")
        if path is not None and (not isinstance(path, str) or len(path) > 300):
            raise PolicyError(f"{where}.path: dosya kalıbı metin olmalı.")
        clean_exc.append({"id": ident.strip(), "reason": reason.strip(),
                          "expires": _parse_date(item["expires"], f"{where}.expires").isoformat(), "path": path})
    policy["exceptions"] = clean_exc
    return policy


def load_policy(path: Path | None, project_root: Path | None = None) -> tuple[dict[str, Any], str]:
    """Açık yol > proje kökündeki .sniper-policy.* > varsayılan. Dönen: (politika, kaynak açıklaması)."""
    candidate = path
    if candidate is None and project_root is not None:
        candidate = next((project_root / name for name in POLICY_FILES if (project_root / name).is_file()), None)
    if candidate is None:
        return validate_policy({}), "varsayılan"
    try:
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 256_000:
            raise PolicyError(f"Politika dosyası okunamıyor: {candidate.name}")
        text = candidate.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"Politika dosyası okunamıyor: {candidate.name}") from exc
    if candidate.suffix.casefold() in {".yml", ".yaml"}:
        try:
            import yaml
        except ImportError:  # pragma: no cover - ortamda PyYAML yoksa
            raise PolicyError("YAML politikası için PyYAML gerekli; .sniper-policy.json kullanın.") from None
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"YAML ayrıştırılamadı: {exc.__class__.__name__}") from None
    else:
        try:
            raw = json.loads(text)
        except ValueError:
            raise PolicyError("JSON politikası ayrıştırılamadı.") from None
    return validate_policy(raw), candidate.name


# ---------------------------------------------------------------------------
# Birleşik bulgu listesi
# ---------------------------------------------------------------------------
def group_of(finding: dict[str, Any]) -> str:
    """Bulgunun politika grubu."""
    import dependency_security

    if finding.get("_kind") == "sca":
        return "malicious" if finding.get("malicious") else "sca"
    category = str(finding.get("category") or "")
    if category == "supply_chain" and (str(finding.get("cwe") or "") == "CWE-506"
                                       or str(finding.get("title") or "").startswith(dependency_security.MALICIOUS_TITLE + ":")):
        return "malicious"
    if category in {"supply_chain", "license", "api"}:
        return category
    if category in {"container_os", "container_lang"}:
        return "container"
    if isinstance(finding.get("iac"), dict):
        return "iac"
    return "code"


def _rule_id(finding: dict[str, Any]) -> str:
    """Kararlı kural kimliği: grup + (IaC denetim kimliği | CWE | başvuru | başlık özeti)."""
    group = group_of(finding)
    if finding.get("_kind") == "sca":
        vuln_id = str(finding.get("vulnerability_id") or finding.get("title") or "sca")
        return f"sniper/{group}/{vuln_id}"[:255]
    iac = finding.get("iac") if isinstance(finding.get("iac"), dict) else {}
    flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else {}
    if iac.get("check"):
        base = str(iac["check"])
    elif flow.get("sink_kind"):
        base = f"taint-{flow['sink_kind']}"
    else:
        base = str(finding.get("cwe") or finding.get("reference") or "")
        if not base:
            base = "t-" + hashlib.sha256(finding_tracking._norm(finding.get("title")).encode("utf-8")).hexdigest()[:12]
    base = re.sub(r"[^A-Za-z0-9_.\-]+", "-", base).strip("-") or "kural"
    return f"sniper/{group}/{base}"[:255]


def _manifest_line(root: Path, manifest: str, package: str, cache: dict[str, list[str]]) -> int:
    """Bağımlılığın bildirim/kilit dosyasındaki satırı (bulunamazsa 1)."""
    if not manifest or not package:
        return 1
    if manifest not in cache:
        try:
            candidate = (root / manifest).resolve()
            if root.resolve() not in candidate.parents or not candidate.is_file() or candidate.stat().st_size > 20_000_000:
                cache[manifest] = []
            else:
                cache[manifest] = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[manifest] = []
    lowered = package.casefold()
    short = lowered.rsplit(":", 1)[-1] if ":" in lowered else lowered  # maven grup:artefakt → artefakt
    patterns = [re.compile(r'(?<![\w.@/-])' + re.escape(token) + r'(?![\w-])', re.IGNORECASE) for token in {lowered, short}]
    for number, line in enumerate(cache[manifest], start=1):
        if any(p.search(line) for p in patterns):
            return number
    return 1


def collect_sca(project_root: Path, *, allowed_roots: tuple[Path, ...] | None = None) -> dict[str, Any]:
    """Çevrimdışı OSV ile paket açıkları + kullanım/öncelik. Veritabanı yoksa ``available`` False (uyarıyla)."""
    import dependency_security as ds
    import osv_offline

    warnings: list[str] = []
    try:
        root, components, _skipped = ds.discover_inventory(str(project_root), allowed_roots=allowed_roots, lenient=True,
                                                           warnings=warnings)
    except ds.DependencySecurityError as exc:
        return {"available": False, "findings": [], "warnings": [str(exc)], "coverage": [], "component_count": 0}
    if not components:
        return {"available": True, "findings": [], "warnings": warnings, "coverage": [], "component_count": 0}
    result = osv_offline.match_components(components)
    warnings += result.get("warnings") or []
    available = any(c.get("status") in ("ok", "stale") for c in result.get("coverage") or [])
    meta: dict[tuple[str, str], dict[str, Any]] = {}
    for res in result["document"].get("results", []):
        for entry in res.get("packages", []):
            package = entry.get("package") or {}
            for vuln in entry.get("vulnerabilities") or []:
                meta[(str(package.get("name")), str(vuln.get("id")))] = {
                    "manifest": package.get("manifest") or "", "ecosystem": package.get("ecosystem") or "",
                    "aliases": [str(a) for a in vuln.get("aliases") or []],
                    "malicious": ds.is_malicious_vulnerability(vuln),
                }
    findings = ds.parse_osv(result["document"], str(root))
    priorities: dict[tuple[str, str], dict[str, Any]] = {}
    if findings:
        try:
            reach = ds.analyze_vulnerability_reachability(str(root), findings=findings, allowed_roots=allowed_roots)
            for item in reach.get("items") or []:
                priorities[(str(item.get("package_name")), str(item.get("vulnerability_id")))] = item
        except (ds.DependencySecurityError, ValueError, OSError):
            warnings.append("Erişilebilirlik/öncelik analizi yapılamadı; SCA bulguları önem sırasıyla değerlendirildi.")
    lines: dict[str, list[str]] = {}
    out = []
    for finding in findings:
        key = (str(finding.get("package_name")), str(finding.get("vulnerability_id")))
        info = meta.get(key, {})
        item = priorities.get(key, {})
        priority = item.get("priority") if isinstance(item.get("priority"), dict) else {}
        manifest = str(info.get("manifest") or "")
        malicious = bool(info.get("malicious")) or ds.is_malicious_finding(finding)
        severity = "critical" if malicious else str(finding.get("severity") or "medium").lower()
        out.append({
            "_kind": "sca",
            "category": "dependency",
            "severity": severity if severity in SEVERITY_RANK else "medium",
            "title": str(finding.get("title") or key[1]),
            "file": manifest,
            "line": _manifest_line(root, manifest, key[0], lines),
            "package_name": key[0],
            "installed_version": str(finding.get("installed_version") or ""),
            "ecosystem": str(info.get("ecosystem") or finding.get("target") or ""),
            "vulnerability_id": key[1],
            "aliases": info.get("aliases") or [],
            "fixed_version": str(finding.get("fixed_version") or ""),
            "malicious": malicious,
            "cwe": "CWE-506" if malicious else "CWE-1395",
            "recommendation": (ds.MALICIOUS_RECOMMENDATION if malicious else
                               (f"{key[0]} paketini {finding.get('fixed_version')} ya da üstüne yükseltin."
                                if finding.get("fixed_version") else f"{key[0]} için düzeltilmiş sürüm yok; telafi edici kontrol değerlendirin.")),
            "priority": priority,
            "usage": (item.get("usage") or {}).get("state") if isinstance(item.get("usage"), dict) else None,
        })
    out.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["package_name"], f["vulnerability_id"]))
    return {"available": available, "findings": out, "warnings": warnings, "coverage": result.get("coverage") or [],
            "component_count": len(components)}


def sca_fingerprint(finding: dict[str, Any]) -> str:
    """SCA bulgusunun sürümden bağımsız olmayan, satırdan bağımsız parmak izi (ekosistem+paket+sürüm+açık)."""
    parts = ["sca", str(finding.get("ecosystem")).casefold(), str(finding.get("package_name")).casefold(),
             str(finding.get("installed_version")), str(finding.get("vulnerability_id"))]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def fingerprint_of(finding: dict[str, Any]) -> str:
    return sca_fingerprint(finding) if finding.get("_kind") == "sca" else finding_tracking.fingerprint(finding)


# ---------------------------------------------------------------------------
# Taban (yalnız yeni bulgular)
# ---------------------------------------------------------------------------
def baseline_fingerprints_from_sarif(path: Path) -> set[str]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"Taban SARIF okunamadı: {path.name}") from exc
    out: set[str] = set()
    for run in doc.get("runs") or []:
        for result in run.get("results") or []:
            fps = result.get("partialFingerprints") or {}
            value = fps.get("sniperTrack/v1")
            if isinstance(value, str):
                out.add(value)
    return out


def mark_new(findings: list[dict[str, Any]], baseline: set[str]) -> None:
    for finding in findings:
        finding["is_new"] = fingerprint_of(finding) not in baseline


# ---------------------------------------------------------------------------
# İstisnalar ve karar
# ---------------------------------------------------------------------------
def _ids_of(finding: dict[str, Any]) -> set[str]:
    ids = {fingerprint_of(finding), _rule_id(finding), _rule_id(finding).rsplit("/", 1)[-1]}
    for key in ("cwe", "reference", "vulnerability_id"):
        if finding.get(key):
            ids.add(str(finding[key]))
    ids.update(str(a) for a in finding.get("aliases") or [])
    if finding.get("package_name"):
        ids.add("package:" + str(finding["package_name"]))
    iac = finding.get("iac") if isinstance(finding.get("iac"), dict) else {}
    for key in ("check", "checkov"):
        if iac.get(key):
            ids.add(str(iac[key]))
    return {i.casefold() for i in ids if i}


def apply_exceptions(findings: list[dict[str, Any]], exceptions: list[dict[str, Any]], today: dt.date) -> dict[str, Any]:
    """Süresi geçmemiş istisnaları uygular (kötü amaçlı paket muaf tutulamaz)."""
    used: dict[str, int] = {}
    expired = [e for e in exceptions if dt.date.fromisoformat(e["expires"]) < today]
    active = [e for e in exceptions if e not in expired]
    for finding in findings:
        if group_of(finding) == "malicious":
            continue
        ids = _ids_of(finding)
        for exc in active:
            if exc["id"].casefold() not in ids:
                continue
            if exc.get("path") and not fnmatch.fnmatch(str(finding.get("file") or ""), exc["path"]):
                continue
            finding["exception"] = {"id": exc["id"], "reason": exc["reason"], "expires": exc["expires"]}
            used[exc["id"]] = used.get(exc["id"], 0) + 1
            break
    return {"used": used, "expired": [e["id"] for e in expired],
            "unused": [e["id"] for e in active if e["id"] not in used]}


def _triaged_out(finding: dict[str, Any]) -> bool:
    triage = finding.get("triage") if isinstance(finding.get("triage"), dict) else {}
    if triage.get("disposition") in {"false_positive", "risk_accepted", "accepted_risk"}:
        return True
    if finding.get("disposition") in {"false_positive", "risk_accepted", "accepted_risk"}:
        return True
    tracking = finding.get("tracking") if isinstance(finding.get("tracking"), dict) else {}
    return tracking.get("status") in {"false_positive", "risk_accepted"}


def evaluate(findings: list[dict[str, Any]], policy: dict[str, Any], *, compared: bool,
             sla_breaches: int | None = None) -> dict[str, Any]:
    """Politika kararı. ``compared`` True ise ``new_only`` politikasında yalnız yeni bulgular sayılır."""
    reasons: list[str] = []
    failing: list[dict[str, Any]] = []
    new_only = bool(policy.get("new_only")) and compared
    for finding in findings:
        if finding.get("exception") or _triaged_out(finding):
            continue
        group = group_of(finding)
        why = None
        if group == "malicious":
            why = "kötü amaçlı paket (her zaman başarısız)"
        elif new_only and not finding.get("is_new", True):
            continue
        else:
            threshold = policy["fail_on"].get(group, policy["fail_on"].get("default"))
            severity = str(finding.get("severity") or "info")
            if threshold is not None and SEVERITY_RANK.get(severity, 9) <= SEVERITY_RANK[threshold]:
                why = f"{GROUP_LABELS[group]}: {severity} ≥ {threshold}"
            elif group == "license" and policy.get("license_denied") and str(finding.get("severity")) == "high":
                why = "yasak lisans"  # lisans uyumu "yasak" kategorisini high önemle üretir
            elif group == "sca" and policy.get("sca_fix_first") and (finding.get("priority") or {}).get("tier") == "fix_first":
                why = "SCA 'Önce düzelt' katmanı"
            elif group == "iac" and policy.get("iac_fix_first") and severity in {"critical", "high"} \
                    and "(varsayılan ayar)" not in str(finding.get("title") or ""):
                why = "IaC 'Önce düzelt' (yüksek/kritik, açıkça yazılmış ayar)"
        if why:
            failing.append({**finding, "_why": why})
    if failing:
        reasons.append(f"{len(failing)} bulgu politika eşiğini aşıyor.")
    if policy.get("sla_breach") and sla_breaches:
        reasons.append(f"{sla_breaches} bulgu SLA süresini aştı.")
    return {"passed": not reasons, "failing": failing, "reasons": reasons, "new_only_applied": new_only}


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------
def _location(uri: str, line: int, message: str | None = None) -> dict[str, Any]:
    loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": uri or "."},
                                                "region": {"startLine": max(1, int(line or 1))}}}
    if message:
        loc["message"] = {"text": message[:300]}
    return loc


def _relative(uri: Any, root: Path | None) -> str:
    text = str(uri or "").replace("\\", "/")
    if root is not None and text.startswith(str(root).replace("\\", "/") + "/"):
        text = text[len(str(root)) + 1:]
    return text or "."


def _cwe_tag(cwe: Any) -> str | None:
    match = re.search(r"CWE-(\d{1,5})", str(cwe or ""), re.IGNORECASE)
    return f"external/cwe/cwe-{match.group(1)}" if match else None


def build_sarif(findings: list[dict[str, Any]], *, root: Path | None = None, version: str = "2.0.1",
                automation_id: str | None = None) -> dict[str, Any]:
    from project_audit_diff import _sarif_code_flow

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings[:MAX_SARIF_RESULTS]:
        group = group_of(finding)
        rule_id = _rule_id(finding)
        severity = str(finding.get("severity") or "low")
        title = str(finding.get("title") or rule_id)
        recommendation = str(finding.get("recommendation") or "")
        cwe_tag = _cwe_tag(finding.get("cwe") or finding.get("reference"))
        if rule_id not in rules:
            tags = ["security", group] + ([cwe_tag] if cwe_tag else [])
            rules[rule_id] = {
                "id": rule_id, "name": re.sub(r"[^A-Za-z0-9]+", "", rule_id.title())[:120] or "SniperRule",
                "shortDescription": {"text": title[:200]},
                "fullDescription": {"text": (str(finding.get("evidence") or title))[:1000]},
                "help": {"text": recommendation or title, "markdown": recommendation or title},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(severity, "note")},
                "properties": {"tags": tags, "precision": "high" if finding.get("taint_flow") else "medium",
                               "security-severity": SECURITY_SEVERITY.get(severity, "3.0"),
                               "problem.severity": "error" if severity in {"critical", "high"} else "warning"},
            }
        else:  # aynı kural farklı önemde: en yüksek önem kalır
            current = rules[rule_id]["properties"]["security-severity"]
            if float(SECURITY_SEVERITY.get(severity, "3.0")) > float(current):
                rules[rule_id]["properties"]["security-severity"] = SECURITY_SEVERITY[severity]
        uri = _relative(finding.get("file"), root)
        line = int(finding.get("line") or 1) if str(finding.get("line") or "1").isdigit() else 1
        if group in {"sca", "malicious"} and finding.get("_kind") == "sca":
            text = (f"{finding['package_name']} {finding['installed_version']}: {title} ({finding['vulnerability_id']})"
                    + (f" · Düzeltme: {finding['fixed_version']}" if finding.get("fixed_version") else ""))
        else:
            text = title + (f" — {str(finding.get('evidence'))[:300]}" if finding.get("evidence") else "")
        if recommendation:
            text += f" | Öneri: {recommendation[:400]}"
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": SARIF_LEVEL.get(severity, "note"),
            "message": {"text": text[:4000]},
            "locations": [_location(uri, line)],
            "partialFingerprints": {"sniperTrack/v1": fingerprint_of(finding)},
            "properties": {"severity": severity, "group": group, "category": str(finding.get("category") or ""),
                           "security-severity": SECURITY_SEVERITY.get(severity, "3.0")},
        }
        if finding.get("_kind") == "sca":
            result["properties"].update({
                "package": finding["package_name"], "version": finding["installed_version"],
                "ecosystem": finding.get("ecosystem"), "aliases": finding.get("aliases") or [],
                "priority": (finding.get("priority") or {}).get("tier"), "usage": finding.get("usage"),
            })
        if isinstance(finding.get("iac"), dict):
            result["properties"]["iac"] = {k: finding["iac"].get(k) for k in ("check", "framework", "resource", "checkov")}
        if isinstance(finding.get("is_new"), bool):
            result["baselineState"] = "new" if finding["is_new"] else "unchanged"
        if finding.get("exception"):
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": f"{finding['exception']['reason']} (bitiş {finding['exception']['expires']})"}]
        flow = finding.get("taint_flow")
        if isinstance(flow, dict):
            flow = dict(flow, source_file=_relative(flow.get("source_file") or uri, root))
            result["codeFlows"] = [_sarif_code_flow(flow, uri, line)]
        results.append(result)
    run: dict[str, Any] = {
        "tool": {"driver": {"name": _TOOL_NAME, "version": version, "semanticVersion": version.split("-")[0],
                            "informationUri": _INFO_URI, "rules": list(rules.values())}},
        "results": results,
        "columnKind": "unicodeCodePoints",
        "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}} if root is None else {"%SRCROOT%": {"uri": root.as_uri() + "/"}},
    }
    if automation_id:
        run["automationDetails"] = {"id": automation_id}
    for res in results:  # göreli yollar %SRCROOT%'a bağlanır
        for loc in res["locations"]:
            loc["physicalLocation"]["artifactLocation"]["uriBaseId"] = "%SRCROOT%"
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}


def validate_sarif(doc: Any) -> list[str]:
    """SARIF 2.1.0 yapısal doğrulaması (çevrimdışı; resmî şemanın GitHub'ın kullandığı zorunlu alt kümesi)."""
    errors: list[str] = []
    if not isinstance(doc, dict) or doc.get("version") != "2.1.0":
        return ["version '2.1.0' olmalı"]
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        return ["runs boş olmayan dizi olmalı"]
    for r, run in enumerate(runs):
        driver = ((run or {}).get("tool") or {}).get("driver") if isinstance(run, dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str) or not driver["name"]:
            errors.append(f"runs[{r}].tool.driver.name zorunlu")
            continue
        rules = driver.get("rules") or []
        rule_ids = [rule.get("id") for rule in rules if isinstance(rule, dict)]
        if len(rule_ids) != len(set(rule_ids)):
            errors.append(f"runs[{r}]: yinelenen kural kimliği")
        for i, rule in enumerate(rules):
            if not isinstance(rule.get("id"), str) or not rule["id"]:
                errors.append(f"runs[{r}].rules[{i}].id zorunlu")
            sev = (rule.get("properties") or {}).get("security-severity")
            if sev is not None:
                try:
                    if not 0.0 <= float(sev) <= 10.0:
                        raise ValueError
                except (TypeError, ValueError):
                    errors.append(f"runs[{r}].rules[{i}] security-severity 0–10 sayısal metin olmalı")
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"runs[{r}].results dizi olmalı")
            continue
        if len(results) > MAX_SARIF_RESULTS:
            errors.append(f"runs[{r}]: sonuç sayısı {MAX_SARIF_RESULTS}'i aşıyor")
        for j, res in enumerate(results):
            where = f"runs[{r}].results[{j}]"
            if not isinstance(res, dict):
                errors.append(f"{where} nesne olmalı")
                continue
            if not isinstance((res.get("message") or {}).get("text"), str):
                errors.append(f"{where}.message.text zorunlu")
            if res.get("level") not in (None, "none", "note", "warning", "error"):
                errors.append(f"{where}.level geçersiz")
            if res.get("ruleId") not in rule_ids:
                errors.append(f"{where}.ruleId kurallarda yok")
            if "ruleIndex" in res and not (isinstance(res["ruleIndex"], int) and 0 <= res["ruleIndex"] < len(rule_ids)
                                           and rule_ids[res["ruleIndex"]] == res.get("ruleId")):
                errors.append(f"{where}.ruleIndex ruleId ile uyuşmuyor")
            for k, loc in enumerate(res.get("locations") or []):
                phys = (loc or {}).get("physicalLocation") or {}
                if not isinstance((phys.get("artifactLocation") or {}).get("uri"), str):
                    errors.append(f"{where}.locations[{k}] artifactLocation.uri zorunlu")
                start = (phys.get("region") or {}).get("startLine")
                if start is not None and (not isinstance(start, int) or start < 1):
                    errors.append(f"{where}.locations[{k}] startLine ≥ 1 olmalı")
            fps = res.get("partialFingerprints")
            if fps is not None and not (isinstance(fps, dict) and all(isinstance(v, str) for v in fps.values())):
                errors.append(f"{where}.partialFingerprints metin değerli nesne olmalı")
            for cf in res.get("codeFlows") or []:
                for tf in (cf or {}).get("threadFlows") or []:
                    if not isinstance(tf.get("locations"), list) or not tf["locations"]:
                        errors.append(f"{where}.codeFlows threadFlow.locations boş olamaz")
            if res.get("baselineState") not in (None, "new", "unchanged", "updated", "absent"):
                errors.append(f"{where}.baselineState geçersiz")
    return errors


# ---------------------------------------------------------------------------
# GitLab raporları (güvenlik raporu şeması 15.x)
# ---------------------------------------------------------------------------
GITLAB_SCHEMA_VERSION = "15.0.7"


def _gl_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _gl_scan(kind: str, start: dt.datetime, end: dt.datetime, version: str) -> dict[str, Any]:
    tool = {"id": "sniper", "name": _TOOL_NAME, "version": version, "vendor": {"name": _TOOL_NAME}}
    return {"analyzer": tool, "scanner": dict(tool), "type": kind, "start_time": _gl_time(start),
            "end_time": _gl_time(end), "status": "success"}


def _gl_identifiers(finding: dict[str, Any]) -> list[dict[str, Any]]:
    ids: list[dict[str, Any]] = []
    rule = _rule_id(finding)
    ids.append({"type": "sniper_rule", "name": rule, "value": rule})
    match = re.search(r"CWE-(\d{1,5})", str(finding.get("cwe") or finding.get("reference") or ""), re.IGNORECASE)
    if match:
        ids.append({"type": "cwe", "name": f"CWE-{match.group(1)}", "value": match.group(1),
                    "url": f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"})
    owasp = str(finding.get("owasp") or "").strip()
    if owasp:
        ids.append({"type": "owasp", "name": owasp, "value": owasp})
    for value in [finding.get("vulnerability_id")] + list(finding.get("aliases") or []):
        if not value:
            continue
        kind = "cve" if str(value).startswith("CVE-") else "ghsa" if str(value).startswith("GHSA-") else "osv"
        ids.append({"type": kind, "name": str(value), "value": str(value),
                    "url": f"https://osv.dev/vulnerability/{value}"})
    seen, unique = set(), []
    for item in ids:
        if (item["type"], item["value"]) not in seen:
            seen.add((item["type"], item["value"]))
            unique.append(item)
    return unique


def _gl_id(finding: dict[str, Any]) -> str:
    digest = hashlib.sha256(("gitlab|" + fingerprint_of(finding)).encode("utf-8")).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def build_gitlab_sast(findings: list[dict[str, Any]], *, root: Path | None, start: dt.datetime, end: dt.datetime,
                      version: str = "2.0.1") -> dict[str, Any]:
    vulns = []
    for finding in findings:
        if finding.get("_kind") == "sca" or group_of(finding) in {"container"} or finding.get("exception"):
            continue
        severity = str(finding.get("severity") or "info")
        line = int(finding.get("line") or 1) if str(finding.get("line") or "1").isdigit() else 1
        vulns.append({
            "id": _gl_id(finding), "category": "sast", "name": str(finding.get("title") or "")[:255],
            "message": str(finding.get("title") or "")[:255],
            "description": (str(finding.get("evidence") or "") + ("\n\nÖneri: " + str(finding["recommendation"])
                                                                   if finding.get("recommendation") else ""))[:15000],
            "severity": GITLAB_SEVERITY.get(severity, "Unknown"), "confidence": "High" if finding.get("taint_flow") else "Medium",
            "scanner": {"id": "sniper", "name": _TOOL_NAME},
            "location": {"file": _relative(finding.get("file"), root), "start_line": max(1, line), "end_line": max(1, line)},
            "identifiers": _gl_identifiers(finding),
        })
    return {"version": GITLAB_SCHEMA_VERSION, "vulnerabilities": vulns, "scan": _gl_scan("sast", start, end, version)}


_GL_PACKAGE_MANAGER = {"npm": "npm", "pypi": "pip", "python": "pip", "pip": "pip", "go": "go", "golang": "go",
                       "maven": "maven", "rubygems": "bundler", "bundler": "bundler", "packagist": "composer",
                       "composer": "composer", "nuget": "nuget", "crates.io": "cargo", "cargo": "cargo", "pub": "pub",
                       "hex": "mix", "swifturl": "swift", "swift": "swift", "github actions": "github-actions",
                       "actions": "github-actions", "erlang": "rebar3"}


def build_gitlab_dependency(findings: list[dict[str, Any]], *, start: dt.datetime, end: dt.datetime,
                            version: str = "2.0.1") -> dict[str, Any]:
    vulns = []
    files: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.get("_kind") != "sca" or finding.get("exception"):
            continue
        manifest = str(finding.get("file") or ".")
        dep = {"package": {"name": finding["package_name"]}, "version": finding["installed_version"]}
        entry = files.setdefault(manifest, {"path": manifest, "package_manager": _GL_PACKAGE_MANAGER.get(
            str(finding.get("ecosystem")).casefold(), str(finding.get("ecosystem")).casefold() or "unknown"), "dependencies": []})
        if dep not in entry["dependencies"]:
            entry["dependencies"].append(dep)
        vulns.append({
            "id": _gl_id(finding), "category": "dependency_scanning",
            "name": str(finding.get("title") or finding["vulnerability_id"])[:255],
            "message": f"{finding['package_name']} {finding['installed_version']}: {finding['vulnerability_id']}"[:255],
            "description": str(finding.get("recommendation") or "")[:15000],
            "severity": GITLAB_SEVERITY.get(str(finding.get("severity")), "Unknown"),
            "solution": (f"{finding['package_name']} → {finding['fixed_version']}" if finding.get("fixed_version")
                         else str(finding.get("recommendation") or ""))[:7000],
            "scanner": {"id": "sniper", "name": _TOOL_NAME},
            "location": {"file": manifest, "dependency": dep},
            "identifiers": _gl_identifiers(finding),
        })
    return {"version": GITLAB_SCHEMA_VERSION, "vulnerabilities": vulns, "dependency_files": list(files.values()),
            "scan": _gl_scan("dependency_scanning", start, end, version)}


def validate_gitlab(doc: Any, kind: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict) or not isinstance(doc.get("version"), str):
        return ["version zorunlu"]
    scan = doc.get("scan") or {}
    for key in ("analyzer", "scanner", "type", "start_time", "end_time", "status"):
        if key not in scan:
            errors.append(f"scan.{key} zorunlu")
    if scan.get("type") != kind:
        errors.append(f"scan.type '{kind}' olmalı")
    for key in ("start_time", "end_time"):
        if key in scan and not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", str(scan[key])):
            errors.append(f"scan.{key} YYYY-AA-GGTSS:DD:ss biçiminde olmalı")
    for i, vuln in enumerate(doc.get("vulnerabilities") or []):
        for key in ("id", "identifiers", "location", "severity"):
            if key not in vuln:
                errors.append(f"vulnerabilities[{i}].{key} zorunlu")
        if not vuln.get("identifiers"):
            errors.append(f"vulnerabilities[{i}].identifiers boş olamaz")
        if vuln.get("severity") not in {"Critical", "High", "Medium", "Low", "Info", "Unknown"}:
            errors.append(f"vulnerabilities[{i}].severity geçersiz")
        if kind == "dependency_scanning" and "dependency" not in (vuln.get("location") or {}):
            errors.append(f"vulnerabilities[{i}].location.dependency zorunlu")
    return errors


# ---------------------------------------------------------------------------
# Markdown özeti
# ---------------------------------------------------------------------------
def _md(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")[:200]


def markdown_summary(report: dict[str, Any]) -> str:
    decision = report["decision"]
    lines = [f"## Sniper güvenlik kapısı: {'✅ GEÇTİ' if decision['passed'] else '❌ BAŞARISIZ'}", ""]
    lines.append(f"Proje: `{_md(report['project_name'])}` · Politika: {_md(report['policy_source'])} · "
                 f"Taban: {_md(report.get('baseline') or 'yok')}")
    lines += ["", "| Grup | Kritik | Yüksek | Orta | Düşük | Bilgi |", "|---|---|---|---|---|---|"]
    for group, counts in report["counts"].items():
        if any(counts.values()):
            lines.append(f"| {GROUP_LABELS[group]} | " + " | ".join(str(counts.get(s, 0)) for s in SEVERITIES) + " |")
    if decision["reasons"]:
        lines += ["", "**Nedenler:** " + " ".join(_md(r) for r in decision["reasons"])]
    if decision["failing"]:
        lines += ["", "| Önem | Grup | Konum | Bulgu | Neden |", "|---|---|---|---|---|"]
        for f in decision["failing"][:30]:
            where = f"{_md(f.get('file'))}:{f.get('line') or 1}"
            label = (f"{f['package_name']} {f['installed_version']} ({f['vulnerability_id']})" if f.get("_kind") == "sca"
                     else f.get("title"))
            lines.append(f"| {f.get('severity')} | {GROUP_LABELS[group_of(f)]} | `{where}` | {_md(label)} | {_md(f['_why'])} |")
        if len(decision["failing"]) > 30:
            lines.append(f"\n… ve {len(decision['failing']) - 30} bulgu daha.")
    exc = report.get("exceptions") or {}
    if exc.get("used") or exc.get("expired"):
        lines += ["", f"İstisnalar: kullanılan {sum(exc.get('used', {}).values())}, süresi geçen "
                      f"{len(exc.get('expired', []))} ({', '.join(_md(e) for e in exc.get('expired', [])[:10])})"]
    if report.get("warnings"):
        lines += ["", "<details><summary>Uyarılar</summary>", ""] + [f"- {_md(w)}" for w in report["warnings"][:20]] + ["", "</details>"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Ana akış
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class CiOptions:
    project: str
    policy_path: Path | None = None
    sarif: Path | None = None
    gitlab_dir: Path | None = None
    summary: Path | None = None
    baseline_sarif: Path | None = None
    baseline_audit: str | None = None
    baseline_ref: str | None = None
    sca: bool = True
    store: bool = False
    db_path: Path | None = None
    allowed_roots: tuple[Path, ...] | None = None
    max_files: int = 10_000
    today: dt.date | None = None


def _sla_breaches(store: Any, project_path: str, today: dt.date) -> int | None:
    import portfolio

    try:
        with store._connect() as db:  # noqa: SLF001 - salt okunur sorgu
            rows = db.execute("SELECT * FROM tracked_findings WHERE project_path = ? AND status IN "
                              "('open','in_progress','reopened')", (project_path,)).fetchall()
    except Exception:  # noqa: BLE001 - takip tablosu yoksa SLA bilinmez
        return None
    if not rows:
        return None
    policy, _custom = portfolio.load_policy()
    return sum(1 for row in rows if portfolio._breached(row, policy, today))  # noqa: SLF001


def run(options: CiOptions) -> tuple[int, dict[str, Any]]:
    """CI çalıştırması. Dönen: (çıkış kodu, rapor)."""
    import changed_scan
    import project_analyzer
    import scan_scope

    started = dt.datetime.now(dt.timezone.utc)
    today = options.today or dt.date.today()
    try:
        root = project_analyzer.validate_project_path(options.project, options.allowed_roots)
    except project_analyzer.ProjectRejected as exc:
        return EXIT_ERROR, {"error": str(exc)}
    try:
        policy, policy_source = load_policy(options.policy_path, root)
    except PolicyError as exc:
        return EXIT_CONFIG, {"error": str(exc)}
    baseline_cfg = dict(policy.get("baseline") or {})
    if options.baseline_sarif:
        baseline_cfg = {"sarif": str(options.baseline_sarif)}
    elif options.baseline_audit:
        baseline_cfg = {"audit_id": options.baseline_audit}
    elif options.baseline_ref:
        baseline_cfg = {"git_ref": options.baseline_ref}

    warnings: list[str] = []
    store = None
    compared = False
    baseline_label = None
    changed_files: set[str] | None = None
    try:
        scope = scan_scope.parse_scope(None)
        if "audit_id" in baseline_cfg:
            from storage import Store
            import cli_reports

            store = Store(options.db_path or cli_reports.resolve_db_path())
            base_audit = store.get_project_audit(baseline_cfg["audit_id"])
            if not base_audit:
                return EXIT_CONFIG, {"error": f"Taban analiz bulunamadı: {baseline_cfg['audit_id']}"}
            result = changed_scan.analyze_against_audit(str(root), base_audit, allowed_roots=options.allowed_roots,
                                                        max_files=options.max_files, scope=scope)
            compared, baseline_label = True, f"analiz {baseline_cfg['audit_id']}"
        else:
            result = project_analyzer.analyze_project(str(root), allowed_roots=options.allowed_roots,
                                                      max_files=options.max_files, scope=scope)
            if "git_ref" in baseline_cfg:
                # Git tabanı: değişen dosyalardaki bulgular "yeni"; tam analiz (proje geneli akışlar kaçmasın).
                ref = baseline_cfg["git_ref"]
                base = changed_scan.resolve_base(root, ref)
                changes = changed_scan.compute_changes(root, base, scope)
                changed_files = set(changes.changed)
                for finding in result.get("findings") or []:
                    finding["is_new"] = str(finding.get("file") or "") in changed_files
                compared, baseline_label = True, f"git {ref} ({len(changed_files)} değişen dosya)"
    except changed_scan.ChangedScanError as exc:
        return EXIT_CONFIG, {"error": str(exc)}
    except project_analyzer.ProjectRejected as exc:
        return EXIT_ERROR, {"error": str(exc)}
    warnings += list(result.get("warnings") or [])[:20]
    findings: list[dict[str, Any]] = [dict(f) for f in result.get("findings") or [] if isinstance(f, dict)]

    sca: dict[str, Any] = {"available": False, "findings": [], "warnings": [], "component_count": 0}
    if options.sca:
        try:
            sca = collect_sca(root, allowed_roots=options.allowed_roots)
        except Exception as exc:  # noqa: BLE001 - SCA hatası kod analizini geçersiz kılmaz
            sca = {"available": False, "findings": [], "warnings": [f"SCA yapılamadı: {exc.__class__.__name__}"],
                   "component_count": 0}
        warnings += sca["warnings"][:20]
        if not sca["available"] and sca.get("component_count"):
            warnings.append("Yerel OSV veritabanı yok/güvenilmez: bağımlılık açıkları denetlenmedi.")
            if policy.get("require_osv"):
                return EXIT_ERROR, {"error": "require_osv: yerel OSV veritabanı gerekli ama kullanılamıyor."}
        # Proje analizindeki kötü amaçlı paket bulgusu SCA'da da varsa tek kez sayılır (SCA'daki kalır).
        sca_malicious = {(f["package_name"].casefold(), f["installed_version"]) for f in sca["findings"] if f["malicious"]}
        if sca_malicious:
            findings = [f for f in findings if not (group_of(f) == "malicious" and any(
                f"{name} {version}".casefold() in str(f.get("title") or "").casefold() for name, version in sca_malicious))]
        findings += sca["findings"]
    if "sarif" in baseline_cfg:
        try:
            mark_new(findings, baseline_fingerprints_from_sarif(Path(baseline_cfg["sarif"])))
        except PolicyError as exc:
            return EXIT_CONFIG, {"error": str(exc)}
        compared, baseline_label = True, f"SARIF {Path(baseline_cfg['sarif']).name}"
    elif changed_files is not None:
        for finding in sca["findings"]:
            finding["is_new"] = str(finding.get("file") or "") in changed_files
    elif compared:
        for finding in sca["findings"]:
            finding.setdefault("is_new", True)

    exceptions = apply_exceptions(findings, policy["exceptions"], today)
    for exc_id in exceptions["expired"]:
        warnings.append(f"Süresi geçmiş istisna uygulanmadı: {exc_id}")
    sla = None
    if policy.get("sla_breach"):
        if store is None:
            from storage import Store
            import cli_reports

            try:
                store = Store(options.db_path or cli_reports.resolve_db_path())
            except Exception:  # noqa: BLE001
                store = None
        sla = _sla_breaches(store, str(root), today) if store is not None else None
        if sla is None:
            warnings.append("SLA verisi yok (proje bulgu takibinde değil); SLA kuralı uygulanmadı.")
    decision = evaluate(findings, policy, compared=compared, sla_breaches=sla)

    saved_id = None
    if options.store:
        from storage import Store
        import cli_reports

        store = store or Store(options.db_path or cli_reports.resolve_db_path())
        saved_id = store.create_project_audit(result)["id"]
    counts = {group: {s: 0 for s in SEVERITIES} for group in GROUPS}
    for finding in findings:
        if not finding.get("exception") and not _triaged_out(finding):
            counts[group_of(finding)][str(finding.get("severity") or "info") if finding.get("severity") in SEVERITY_RANK else "info"] += 1
    ended = dt.datetime.now(dt.timezone.utc)
    report = {
        "project_name": root.name, "project_path": str(root), "policy_source": policy_source,
        "baseline": baseline_label, "compared": compared, "decision": decision, "counts": counts,
        "exceptions": exceptions, "warnings": warnings, "sca_available": sca["available"],
        "component_count": sca.get("component_count", 0), "finding_count": len(findings), "saved_audit_id": saved_id,
        "sla_breaches": sla,
    }
    version = _product_version()
    if options.sarif:
        sarif = build_sarif(findings, root=root, version=version, automation_id=f"sniper/{root.name}/")
        problems = validate_sarif(sarif)
        if problems:
            return EXIT_ERROR, {"error": "Üretilen SARIF geçersiz: " + "; ".join(problems[:5])}
        _write_json(options.sarif, sarif)
        report["sarif"] = str(options.sarif)
    if options.gitlab_dir:
        sast = build_gitlab_sast(findings, root=root, start=started, end=ended, version=version)
        dep = build_gitlab_dependency(findings, start=started, end=ended, version=version)
        problems = validate_gitlab(sast, "sast") + validate_gitlab(dep, "dependency_scanning")
        if problems:
            return EXIT_ERROR, {"error": "Üretilen GitLab raporu geçersiz: " + "; ".join(problems[:5])}
        _write_json(options.gitlab_dir / "gl-sast-report.json", sast)
        _write_json(options.gitlab_dir / "gl-dependency-scanning-report.json", dep)
        report["gitlab"] = str(options.gitlab_dir)
    summary_text = markdown_summary(report)
    summary_path = options.summary or (Path(os.environ["GITHUB_STEP_SUMMARY"])
                                       if os.environ.get("GITHUB_STEP_SUMMARY") else None)
    if summary_path is not None:
        try:
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            with summary_path.open("a", encoding="utf-8") as handle:
                handle.write(summary_text)
            report["summary_path"] = str(summary_path)
        except OSError:
            warnings.append("Markdown özeti yazılamadı.")
    report["summary_markdown"] = summary_text
    return (EXIT_PASS if decision["passed"] else EXIT_POLICY), report


def _write_json(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _product_version() -> str:
    """Kurulu paketin sürümü (RELEASE.json), yoksa version.py."""
    app_root = Path(__file__).resolve().parent
    try:
        info = json.loads((app_root / "RELEASE.json").read_text(encoding="utf-8"))
        if isinstance(info, dict) and isinstance(info.get("version"), str) and info["version"]:
            return info["version"][:64]
    except (OSError, ValueError):
        pass
    match = re.search(r'__version__\s*=\s*"([^"]+)"', (app_root / "version.py").read_text(encoding="utf-8")
                      if (app_root / "version.py").is_file() else "")
    return match.group(1) if match else "0.0.0"


def console_lines(code: int, report: dict[str, Any]) -> Iterable[str]:
    """CLI için kısa stdout özeti."""
    if "error" in report:
        yield f"HATA: {report['error']}"
        return
    decision = report["decision"]
    yield (f"Sniper CI: {report['project_name']} · {report['finding_count']} bulgu · bileşen {report['component_count']}"
           f" · politika {report['policy_source']} · taban {report.get('baseline') or 'yok'}")
    for group, counts in report["counts"].items():
        if any(counts.values()):
            yield f"  {GROUP_LABELS[group]}: " + ", ".join(f"{s} {counts[s]}" for s in SEVERITIES if counts[s])
    for finding in decision["failing"][:20]:
        where = f"{finding.get('file') or '.'}:{finding.get('line') or 1}"
        label = (f"{finding['package_name']} {finding['installed_version']} {finding['vulnerability_id']}"
                 if finding.get("_kind") == "sca" else finding.get("title"))
        yield f"  ✗ [{finding.get('severity')}] {where} {label} — {finding['_why']}"
    for reason in decision["reasons"]:
        yield f"  Neden: {reason}"
    for warning in report.get("warnings", [])[:5]:
        yield f"  Uyarı: {warning}"
    yield f"Sonuç: {'GEÇTİ' if code == EXIT_PASS else 'BAŞARISIZ'} (çıkış kodu {code})"


def evaluate_enterprise_v2_ci_gate(
    audit: dict[str, Any],
    *,
    block_on_attack_chains: bool = True,
    block_on_ssvc_act: bool = True,
) -> dict[str, Any]:
    """Wave-9 Item #7: Saldırı zinciri (attack chain) ve CISA SSVC 'Act' odaklı kurumsal CI/CD kapısı."""
    import attack_path_correlator
    import cvss_ssvc_prioritizer

    triage_obj = audit.get("deterministic_triage") if isinstance(audit.get("deterministic_triage"), dict) else None
    verified_keys: set[tuple[str, int]] | None = None
    if isinstance(triage_obj, dict) and isinstance(triage_obj.get("verified_production_findings"), list):
        verified_keys = {
            (str(it.get("file") or "").strip().lstrip("./"), int(it.get("line") or 0))
            for it in triage_obj.get("verified_production_findings") or []
            if isinstance(it, dict)
        }
    findings = [
        f
        for f in (audit.get("findings") or [])
        if isinstance(f, dict)
        and f.get("scope_tier", "production") == "production"
        and f.get("exploitability", "") != "hardening_only"
        and f.get("triage_verdict", "verified_true_positive") == "verified_true_positive"
        and (
            verified_keys is None
            or (str(f.get("file") or "").strip().lstrip("./"), int(f.get("line") or 0)) in verified_keys
        )
    ]
    ag = attack_path_correlator.synthesize_multi_hop_exploit_chains(findings)
    ssvc = cvss_ssvc_prioritizer.evaluate_cisa_ssvc_decisions(findings)

    attack_chain_count = int(ag.get("chain_count", 0))
    ssvc_act_count = int((ssvc.get("summary") or {}).get("Act", 0))
    critical_count = sum(1 for f in findings if str(f.get("severity") or "").lower() == "critical")

    blocking_reasons: list[str] = []
    if block_on_attack_chains and attack_chain_count > 0:
        blocking_reasons.append(f"{attack_chain_count} çok adımlı saldırı zinciri (multi-hop exploit chain) tespit edildi.")
    if block_on_ssvc_act and ssvc_act_count > 0:
        blocking_reasons.append(f"{ssvc_act_count} bulgu CISA SSVC 'Act' (derhal müdahale) kararında.")
    if critical_count > 0:
        blocking_reasons.append(f"{critical_count} kritik üretim (production) bulgusu mevcut.")

    passed = len(blocking_reasons) == 0
    verdict = "PASS" if passed else "BLOCK"
    return {
        "format": "sniper-enterprise-v2-ci-gate/1",
        "verdict": verdict,
        "passed": passed,
        "blocking_reasons": blocking_reasons,
        "attack_chain_count": attack_chain_count,
        "ssvc_act_count": ssvc_act_count,
        "critical_production_count": critical_count,
        "pr_comment_markdown": (
            f"## Sniper Enterprise v2 CI Gate: **{verdict}**\n"
            f"- Attack Chains: {attack_chain_count}\n"
            f"- CISA SSVC Act: {ssvc_act_count}\n"
            f"- Critical Findings: {critical_count}\n"
        ),
    }

