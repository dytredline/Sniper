"""Dış SBOM dosyasını çevrimdışı tarama (20. tur).

CycloneDX (JSON/XML) ya da SPDX (JSON/tag-value) dosyasındaki bileşenler purl'lerine göre ayrılır:
dil paketleri çevrimdışı çok ekosistemli OSV (``osv_offline``), işletim sistemi paketleri (``pkg:deb``/``apk``/``rpm``
+ ``distro`` niteleyicisi) konteyner taramasının OSV dizini (``container_scan``) ile eşlenir. Ağ kullanılmaz.

Sonuç proje analizi biçimindedir (``audit_kind: sbom``): bulgu takibine ve portföye girer; bağımlılık
biçimindeki bulgular (``sbom.dependency_findings``) VEX üretiminde kullanılır.
"""
from __future__ import annotations

import collections
import hashlib
import time
from pathlib import Path
from typing import Any

import sbom_formats
from safe_file_read import read_bytes_bounded

FORMAT = "sniper-sbom-scan-v1"
CATEGORY = "sbom_component"
CWE = "CWE-1395"
MAX_FINDINGS = 20_000
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


class SbomScanError(ValueError):
    """Kullanıcıya gösterilebilir hata."""


def _utc_now() -> str:
    from scanner import utc_now

    return utc_now()


def validate_sbom_path(value: str, allowed_roots: tuple[Path, ...] | None = None) -> Path:
    """Yerel SBOM dosyası: normal dosya, sembolik bağ değil, izinli kökler altında (proje analizi kuralı)."""
    import os

    import project_analyzer

    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise SbomScanError("Geçerli bir yerel SBOM dosyası yolu girin.")
    candidate = Path(os.path.expandvars(os.path.expanduser(value.strip())))
    if candidate.is_symlink():
        raise SbomScanError("SBOM yolu sembolik bağ olamaz.")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SbomScanError("SBOM dosyası bulunamadı veya okunamıyor.") from exc
    if not resolved.is_file():
        raise SbomScanError("SBOM yolu normal bir dosya olmalı.")
    roots = allowed_roots if allowed_roots is not None else project_analyzer._allowed_roots()
    if not any(resolved != root and Path(root).resolve() in resolved.parents for root in roots):
        raise SbomScanError("SBOM yalnız izin verilen yerel dizinlerden okunabilir.")
    if resolved.stat().st_size > sbom_formats.MAX_SBOM_BYTES:
        raise SbomScanError("SBOM dosyası boyut sınırını aşıyor.")
    return resolved


def _purl_parts(purl: str) -> dict[str, str] | None:
    import urllib.parse

    from vex_export import parse_purl

    parsed = parse_purl(purl)
    if not parsed:
        return None
    qualifiers = {}
    if "?" in purl:
        query = purl.split("?", 1)[1].split("#", 1)[0]
        for part in query.split("&"):
            key, _, value = part.partition("=")
            if key:
                qualifiers[key.casefold()] = urllib.parse.unquote(value)
    parsed["qualifiers"] = qualifiers  # type: ignore[assignment]
    parsed["type"] = purl[4:].split("/", 1)[0].casefold()
    return parsed


def _os_release_from_distro(purl_type: str, namespace_os: str, distro: str) -> dict[str, str]:
    """``distro=debian-12`` / ``ubuntu-22.04`` / ``alpine-3.19`` (ya da yalnız sürüm) → os-release benzeri sözlük."""
    distro = distro.casefold()
    os_id = namespace_os.casefold()
    version = distro
    for name in ("debian", "ubuntu", "alpine", "almalinux", "rocky", "wolfi", "chainguard"):
        if distro.startswith(name):
            os_id, version = name, distro[len(name):].lstrip("-")
            break
    if os_id == "debian" and version and not version[0].isdigit():
        version = {"bookworm": "12", "bullseye": "11", "buster": "10", "trixie": "13"}.get(version, version)
    return {"ID": os_id, "VERSION_ID": version}


def _language_findings(components: list[dict[str, Any]], label: str, osv_root: Path | None
                       ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    import dependency_security
    import osv_offline

    if not components:
        return [], [], [], []
    result = osv_offline.match_components([{k: c[k] for k in ("ecosystem", "name", "version")} for c in components],
                                          root=osv_root)
    dep_rows = dependency_security.parse_osv(result["document"], label)
    aliases: dict[tuple[str, str, str], list[str]] = {}
    for res in result["document"].get("results", []):
        for entry in res.get("packages", []):
            pkg = entry.get("package") or {}
            for vuln in entry.get("vulnerabilities") or []:
                aliases[(str(pkg.get("name")), str(pkg.get("version")), str(vuln.get("id")))] = \
                    [str(a) for a in vuln.get("aliases") or []][:10]
    purl_of = {(c["name"], c["version"]): c.get("purl", "") for c in components}
    findings = []
    for index, row in enumerate(dep_rows[:MAX_FINDINGS]):
        name, version, vid = row["package_name"], row["installed_version"], row["vulnerability_id"]
        row["id"] = "sbomdep_" + hashlib.sha256(f"{label}|{name}|{version}|{vid}".encode()).hexdigest()[:16]
        row["references"] = list(row.get("references") or []) + aliases.get((name, version, vid), [])
        fix = row.get("fixed_version") or None
        findings.append({
            "category": CATEGORY,
            "severity": row.get("severity") or "medium",
            "title": f"Açıklı bileşen (SBOM): {name} {version} ({vid})",
            "file": label,
            "line": 0,
            "reference": vid,
            "cwe": CWE,
            "evidence": f"{row.get('target') or 'paket'}: {name} {version} — {purl_of.get((name, version), '')}"[:500],
            "recommendation": (f"{name} bileşenini {fix} ya da üstüne yükseltin." if fix else
                               f"{name} için düzeltilmiş sürüm bildirilmemiş; bileşeni değiştirmeyi ya da telafi edici "
                               "kontrolü değerlendirin."),
            "package": {"type": row.get("target") or "", "source": name, "installed_version": version,
                        "binaries": [name]},
            "vulnerability": {"id": vid, "aliases": aliases.get((name, version, vid), []),
                              "summary": row.get("title", ""), "severity_source": "osv"},
            "fixed_version": fix,
            "fix_state": "fixed" if fix else "not_fixed",
            "label": vid,
        })
    return findings, dep_rows, result.get("coverage") or [], list(result.get("warnings") or [])


def _os_findings(groups: dict[tuple[str, str], list[dict[str, Any]]], label: str, osv_root: Path | None
                 ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    import container_scan
    import osv_db_refresh

    findings: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    warnings: list[str] = []
    for (ecosystem, package_type), packages in sorted(groups.items()):
        entry = {"ecosystem": ecosystem, "components": len(packages)}
        try:
            index, info = container_scan.load_index(ecosystem, root=osv_root)
        except (FileNotFoundError, osv_db_refresh.OSVRefreshError):
            entry["status"] = "unavailable"
            warnings.append(f"{ecosystem} için çevrimdışı OSV veritabanı yok; {len(packages)} işletim sistemi paketi "
                            "denetlenmedi.")
            coverage.append(entry)
            continue
        matched = container_scan.match_packages(packages, index, package_type)
        for item in matched:
            item = dict(item)
            item["category"] = CATEGORY
            item["file"] = label
            item["title"] = item["title"].replace("Açıklı işletim sistemi paketi", "Açıklı işletim sistemi paketi (SBOM)")
            findings.append(item)
        entry.update({"status": "ok", "vulnerabilities": len(matched),
                      "db_retrieved_utc": (info or {}).get("retrieved_utc")})
        coverage.append(entry)
    return findings, coverage, warnings


def scan_sbom(path_value: str, *, osv_root: Path | None = None,
              allowed_roots: tuple[Path, ...] | None = None) -> dict[str, Any]:
    """SBOM dosyasını tarar; sonuç proje analizi biçimindedir (``audit_kind: sbom``)."""
    import container_scan

    started = time.monotonic()
    path = validate_sbom_path(path_value, allowed_roots)
    data = read_bytes_bounded(path, sbom_formats.MAX_SBOM_BYTES)
    if data is None:
        raise SbomScanError("SBOM dosyası okunamadı.")
    try:
        parsed = sbom_formats.parse_sbom_bytes(data, path.name)
    except sbom_formats.SbomError as exc:
        raise SbomScanError(str(exc)) from exc
    label = path.name
    warnings: list[str] = []
    language: list[dict[str, Any]] = []
    os_groups: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    unsupported = collections.Counter()
    ecosystems = collections.Counter()
    for comp in parsed["components"]:
        purl = comp.get("purl") or ""
        parts = _purl_parts(purl) if purl else None
        if not parts:
            unsupported["purl_yok"] += 1
            continue
        version = comp.get("version") or parts.get("version") or ""
        ptype = parts["type"]
        if ptype in ("deb", "apk", "rpm"):
            namespace_os = purl[4:].split("/", 2)[1] if purl.count("/") >= 2 else ""
            distro = parts["qualifiers"].get("distro", "")  # type: ignore[union-attr]
            ecosystem, package_type = container_scan.os_ecosystem(_os_release_from_distro(ptype, namespace_os, distro))
            if not ecosystem or package_type != ptype:
                unsupported[f"{ptype}:dağıtım_bilinmiyor"] += 1
                continue
            name = parts["name"].rsplit("/", 1)[-1]
            upstream = parts["qualifiers"].get("upstream") or name  # type: ignore[union-attr]
            source = upstream.split("@", 1)[0]
            os_groups[(ecosystem, package_type)].append({
                "type": ptype, "name": name, "version": version, "source": source, "source_version": version,
                "arch": parts["qualifiers"].get("arch", ""), "db": label, "line": 0})  # type: ignore[union-attr]
            ecosystems[ecosystem] += 1
            continue
        import osv_offline

        osv_eco = osv_offline.osv_ecosystem(parts["ecosystem"])
        if not osv_eco or not version:
            unsupported[f"{ptype}" + ("" if version else ":sürüm_yok")] += 1
            continue
        language.append({"ecosystem": osv_eco, "name": parts["name"], "version": version, "purl": purl})
        ecosystems[osv_eco] += 1
    lang_findings, dep_rows, lang_coverage, lang_warnings = _language_findings(language, label, osv_root)
    os_findings, os_coverage, os_warnings = _os_findings(os_groups, label, osv_root)
    warnings += lang_warnings + os_warnings
    if unsupported:
        warnings.append(f"{sum(unsupported.values())} bileşen eşlenemedi (purl yok ya da desteklenmeyen tür): "
                        + ", ".join(f"{k} {v}" for k, v in unsupported.most_common(6)))
    findings = (lang_findings + os_findings)[:MAX_FINDINGS]
    weights = {"critical": 24, "high": 14, "medium": 7, "low": 3, "info": 0}
    penalty = sum(weights.get(f["severity"], 0) for f in findings[:5]) + min(40, max(0, len(findings) - 5))
    score = max(0, 100 - min(100, penalty))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    findings.sort(key=lambda f: (_SEVERITY_ORDER[::-1].index(f["severity"]) if f["severity"] in _SEVERITY_ORDER else 9,
                                 f["title"]))
    counts = collections.Counter(f["severity"] for f in findings)
    any_db = any(c.get("status") in ("ok", "stale") for c in lang_coverage + os_coverage)
    return {
        "created_at": _utc_now(),
        "audit_kind": "sbom",
        "project_path": str(path),
        "project_name": (parsed.get("name") or path.stem)[:200],
        "score": score,
        "grade": grade,
        "file_count": len(parsed["components"]),
        "bytes_scanned": len(data),
        "findings": findings,
        "finding_counts": {s: counts.get(s, 0) for s in _SEVERITY_ORDER[::-1]},
        "languages": {},
        "manifests": [],
        "checks": [{"id": "sbom_components", "label": "SBOM bileşen açıkları",
                    "status": "review" if findings else ("pass" if any_db else "na")}],
        "skipped_files": {},
        "warnings": warnings,
        "sbom": {
            "format": FORMAT,
            "source_format": parsed["format"],
            "spec_version": parsed["spec_version"],
            "component_count": len(parsed["components"]),
            "matched_components": len(language) + sum(len(v) for v in os_groups.values()),
            "ecosystems": dict(ecosystems),
            "unsupported": dict(unsupported),
            "coverage": lang_coverage + os_coverage,
            "covered_files": [label],
            "seconds": round(time.monotonic() - started, 2),
            "dependency_findings": dep_rows[:MAX_FINDINGS],
        },
        "components": [{k: c.get(k, "") for k in ("name", "version", "purl", "license")}
                       for c in parsed["components"]][:sbom_formats.MAX_COMPONENTS],
    }


def vex_for_audit(audit: dict[str, Any], fmt: str, *, author: str = "") -> dict[str, Any]:
    """Kayıtlı SBOM taramasından VEX (OpenVEX / CycloneDX VEX). Kaynak kod olmadığı için erişilebilirlik ve
    "paket yok" kanıtı kullanılmaz; analist kararı yoksa durum ``under_investigation`` ya da ``affected``dır."""
    import vex_export
    from version import __version__

    rows = ((audit.get("sbom") or {}).get("dependency_findings")) or []
    statements = vex_export.build_statements(rows, None, None, None)
    name = str(audit.get("project_name") or "sbom")
    document = vex_export.render(statements, fmt, project_name=name, timestamp=str(audit.get("created_at") or _utc_now()),
                                 author=author, tool_version=__version__)
    return {"format": fmt, "project_name": name, "summary": vex_export.summary(statements), "document": document}
