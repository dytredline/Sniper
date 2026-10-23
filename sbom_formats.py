"""SBOM biçimleri (20. tur): CycloneDX 1.5 ↔ SPDX 2.3 JSON, kilit dosyalarından bağımlılık ilişkileri, yapısal
doğrulama ve dış SBOM dosyalarını (CycloneDX JSON/XML, SPDX JSON/tag-value) güvenli okuma.

Ağ kullanılmaz. XML yalnız DOCTYPE/ENTITY içermiyorsa ayrıştırılır (XXE ve "milyar gülüş" kapalı). Boyut ve bileşen
sayısı sınırlıdır. Şema doğrulaması yapısaldır: resmî JSON Schema'lar ($ref zinciri, jsf/spdx alt şemaları) ve
``jsonschema`` paketi çevrimdışı kurulu değil; zorunlu alanlar, türler, kimlik biçimleri ve başvuru bütünlüğü
denetlenir.
"""
from __future__ import annotations

import hashlib
import json
import re
import tomllib
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from safe_file_read import read_text_bounded

MAX_SBOM_BYTES = 32 * 1024 * 1024
MAX_COMPONENTS = 50_000
MAX_EDGES = 250_000
MAX_LOCK_BYTES = 64 * 1024 * 1024
TOOL_NAME = "Sniper"
ROOT_REF = "sniper-root"

_SPDX_ID_RE = re.compile(r"SPDXRef-[A-Za-z0-9.-]+\Z")
_LICENSE_REF_RE = re.compile(r"[^A-Za-z0-9.-]+")


class SbomError(ValueError):
    """Kullanıcıya gösterilebilir SBOM hatası (yol/sır içermez)."""


# ---------------------------------------------------------------------------
# Bağımlılık ilişkileri (kilit dosyalarındaki ağaç; bilinebildiği kadar)
# ---------------------------------------------------------------------------
def _purl(ecosystem: str, name: str, version: str) -> str:
    from dependency_security import _package_url

    return _package_url(ecosystem, name, version)


def _read(path: Path) -> str | None:
    return read_text_bounded(path, MAX_LOCK_BYTES)


def _resolve_npm(packages: dict[str, Any], from_path: str, dep: str) -> str | None:
    """Node çözümlemesi: from_path/node_modules/dep, sonra üst node_modules dizinleri, en son kök."""
    base = from_path
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


def _npm_edges(text: str) -> tuple[dict[str, set[str]], set[str]]:
    try:
        lock = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return {}, set()
    if not isinstance(lock, dict):
        return {}, set()
    edges: dict[str, set[str]] = {}
    direct: set[str] = set()
    packages = lock.get("packages")
    if isinstance(packages, dict) and packages:
        def ref(path: str) -> str | None:
            item = packages.get(path)
            if not isinstance(item, dict) or item.get("link") or not item.get("version"):
                return None
            name = item.get("name") if isinstance(item.get("name"), str) else path.rsplit("node_modules/", 1)[-1]
            return _purl("npm", name, str(item["version"]))

        for path, item in list(packages.items())[:MAX_COMPONENTS]:
            if not isinstance(item, dict):
                continue
            names: set[str] = set()
            for key in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
                if key == "devDependencies" and path:
                    continue  # yalnız kökün geliştirme bağımlılıkları kurulur
                value = item.get(key)
                if isinstance(value, dict):
                    names.update(n for n in value if isinstance(n, str))
            children = {r for r in (ref(p) for p in (_resolve_npm(packages, path, n) for n in sorted(names)) if p) if r}
            if path == "":
                direct |= children
            else:
                parent = ref(path)
                if parent and children:
                    edges.setdefault(parent, set()).update(children)
        return edges, direct
    # package-lock v1: iç içe "dependencies" ağacı, "requires" adları kapsamda yukarı doğru çözülür.
    tree = lock.get("dependencies")
    if not isinstance(tree, dict):
        return {}, set()

    def walk(node: dict[str, Any], scopes: list[dict[str, Any]], depth: int) -> None:
        if depth > 64:
            return
        for name, item in list(node.items())[:MAX_COMPONENTS]:
            if not isinstance(item, dict) or not item.get("version"):
                continue
            parent = _purl("npm", name, str(item["version"]))
            if depth == 0:
                direct.add(parent)
            inner = item.get("dependencies") if isinstance(item.get("dependencies"), dict) else {}
            chain = [inner] + scopes
            for dep in sorted((item.get("requires") or {}) if isinstance(item.get("requires"), dict) else {}):
                for scope in chain:
                    target = scope.get(dep)
                    if isinstance(target, dict) and target.get("version"):
                        edges.setdefault(parent, set()).add(_purl("npm", dep, str(target["version"])))
                        break
            if inner:
                walk(inner, chain, depth + 1)

    walk(tree, [tree], 0)
    return edges, direct


def _cargo_edges(text: str) -> tuple[dict[str, set[str]], set[str]]:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}, set()
    packages = [p for p in lock.get("package") or [] if isinstance(p, dict) and isinstance(p.get("name"), str)]
    versions: dict[str, list[str]] = {}
    for p in packages:
        versions.setdefault(p["name"], []).append(str(p.get("version") or ""))
    edges: dict[str, set[str]] = {}
    direct: set[str] = set()
    for p in packages:
        workspace_member = not p.get("source")
        parent = _purl("cargo", p["name"], str(p.get("version") or ""))
        for dep in p.get("dependencies") or []:
            parts = str(dep).split(" ")
            name = parts[0]
            version = parts[1] if len(parts) > 1 else (versions.get(name) or [""])[0]
            child = _purl("cargo", name, version)
            if workspace_member:
                direct.add(child)
            else:
                edges.setdefault(parent, set()).add(child)
    return edges, direct


def _by_name_edges(items: list[tuple[str, str, Iterable[str]]], ecosystem: str,
                   direct_names: set[str] | None) -> tuple[dict[str, set[str]], set[str]]:
    """(ad, sürüm, bağımlılık adları) listesi → kenarlar; ad başına tek sürüm varsayılır (kilit dosyası)."""
    version_of: dict[str, str] = {}
    for name, version, _deps in items:
        version_of.setdefault(name.casefold(), version)
    edges: dict[str, set[str]] = {}
    depended: set[str] = set()
    for name, version, deps in items:
        parent = _purl(ecosystem, name, version)
        for dep in deps:
            key = dep.casefold()
            if key in version_of:
                depended.add(key)
                edges.setdefault(parent, set()).add(_purl(ecosystem, dep, version_of[key]))
    if direct_names is None:  # kök bildirimi yoksa: başka paketin bağımlılığı olmayanlar doğrudan sayılır
        direct_names = {n.casefold() for n, _v, _d in items} - depended
    direct = {_purl(ecosystem, n, v) for n, v, _d in items if n.casefold() in {d.casefold() for d in direct_names}}
    return edges, direct


def _poetry_edges(text: str) -> tuple[dict[str, set[str]], set[str]]:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}, set()
    items = []
    for p in lock.get("package") or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            deps = p.get("dependencies") if isinstance(p.get("dependencies"), dict) else {}
            items.append((p["name"], str(p.get("version") or ""), [str(d) for d in deps]))
    return _by_name_edges(items, "PyPI", None)


def _composer_edges(text: str, manifest_dir: Path) -> tuple[dict[str, set[str]], set[str]]:
    try:
        lock = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return {}, set()
    if not isinstance(lock, dict):
        return {}, set()
    items = []
    for section in ("packages", "packages-dev"):
        for p in lock.get(section) or [] if isinstance(lock.get(section), list) else []:
            if isinstance(p, dict) and isinstance(p.get("name"), str):
                req = p.get("require") if isinstance(p.get("require"), dict) else {}
                items.append((p["name"], str(p.get("version") or ""), [d for d in req if "/" in d]))
    direct_names: set[str] | None = None
    root_text = _read(manifest_dir / "composer.json")
    if root_text:
        try:
            root_doc = json.loads(root_text)
            if isinstance(root_doc, dict):
                direct_names = {d for key in ("require", "require-dev") if isinstance(root_doc.get(key), dict)
                                for d in root_doc[key] if "/" in d}
        except (json.JSONDecodeError, RecursionError):
            direct_names = None
    return _by_name_edges(items, "Packagist", direct_names)


def _gemfile_edges(text: str) -> tuple[dict[str, set[str]], set[str]]:
    items: list[tuple[str, str, list[str]]] = []
    direct_names: set[str] = set()
    section = ""
    current: list[str] | None = None
    for line in text.splitlines()[:200_000]:
        if line and not line.startswith(" "):
            section = line.strip()
            current = None
            continue
        if section == "DEPENDENCIES":
            match = re.match(r"\s{2}([A-Za-z0-9_.-]+)", line)
            if match:
                direct_names.add(match.group(1))
            continue
        if section not in ("GEM", "GIT", "PATH"):
            continue
        spec = re.match(r"\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$", line)
        if spec:
            version = spec.group(2).split("-", 1)[0] if re.search(r"-(x86|arm|aarch|java|universal|x64)", spec.group(2)) else spec.group(2)
            current = []
            items.append((spec.group(1), version, current))
            continue
        dep = re.match(r"\s{6}([A-Za-z0-9_.-]+)", line)
        if dep and current is not None:
            current.append(dep.group(1))
    return _by_name_edges(items, "RubyGems", direct_names or None)


def _gomod_direct(text: str) -> set[str]:
    direct: set[str] = set()
    for match in re.finditer(r"^\s*(?:require\s+)?([A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)\s+(v[^\s]+)(\s*//\s*indirect)?\s*$",
                             text, re.M):
        if not match.group(3):
            direct.add(_purl("Golang", match.group(1), match.group(2)))
    return direct


_LOCK_PARSERS = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "cargo.lock": "cargo", "poetry.lock": "poetry",
    "composer.lock": "composer", "gemfile.lock": "gem", "go.mod": "go",
}


def dependency_graph(root: Path, components: list[dict[str, Any]]) -> tuple[dict[str, set[str]], set[str], list[str]]:
    """Bileşenlerin manifest dosyalarından (kenarlar: üst purl → alt purl'ler, doğrudan bağımlılık purl'leri,
    ilişkisi bilinen kilit dosyaları). Bilinmeyen biçimlerde bileşenler köke doğrudan bağlanır (çağıran karar verir)."""
    root = Path(root)
    manifests = sorted({str(c.get("manifest") or "") for c in components if c.get("manifest")})
    edges: dict[str, set[str]] = {}
    direct: set[str] = set()
    used: list[str] = []
    for rel in manifests:
        base = rel.rsplit("/", 1)[-1].split(" ", 1)[0]
        kind = _LOCK_PARSERS.get(base.casefold())
        if not kind or ".." in Path(rel).parts:
            continue
        path = root / rel.split(" ", 1)[0]
        text = _read(path)
        if text is None:
            continue
        if kind == "npm":
            found_edges, found_direct = _npm_edges(text)
        elif kind == "cargo":
            found_edges, found_direct = _cargo_edges(text)
        elif kind == "poetry":
            found_edges, found_direct = _poetry_edges(text)
        elif kind == "composer":
            found_edges, found_direct = _composer_edges(text, path.parent)
        elif kind == "gem":
            found_edges, found_direct = _gemfile_edges(text)
        else:
            found_edges, found_direct = {}, _gomod_direct(text)
        for parent, children in found_edges.items():
            edges.setdefault(parent, set()).update(children)
        direct |= found_direct
        used.append(rel)
        if sum(len(v) for v in edges.values()) > MAX_EDGES:
            break
    return edges, direct, used


def cyclonedx_dependencies(components: list[dict[str, Any]], edges: dict[str, set[str]], direct: set[str],
                           root_ref: str = ROOT_REF) -> list[dict[str, Any]]:
    """CycloneDX ``dependencies``: yalnız belgede bulunan başvurular; kökü bilinmeyen bileşen köke bağlanır."""
    refs = {c["bom-ref"] for c in components}
    children_known = {child for kids in edges.values() for child in kids if child in refs}
    # Doğrudan bağımlılıklar + hiçbir paketin alt bağımlılığı olarak bilinmeyenler (ilişkisi bilinmeyen manifestler)
    root_children = sorted((direct & refs) | (refs - children_known))
    out = [{"ref": root_ref, "dependsOn": root_children}]
    for ref in sorted(refs):
        kids = sorted(k for k in edges.get(ref, ()) if k in refs and k != ref)
        out.append({"ref": ref, "dependsOn": kids})
    return out


# ---------------------------------------------------------------------------
# CycloneDX → SPDX 2.3
# ---------------------------------------------------------------------------
def _spdx_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9.-]+", "-", value.split("@", 1)[0].rsplit("/", 1)[-1])[:40].strip("-.") or "pkg"
    return f"SPDXRef-{prefix}-{stem}-{digest}"


def _spdx_license(licenses: Any, extracted: dict[str, dict[str, str]]) -> str:
    if not isinstance(licenses, list) or not licenses:
        return "NOASSERTION"
    parts: list[str] = []
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str):
            parts.append(entry["expression"] if len(licenses) == 1 else f"({entry['expression']})")
            continue
        lic = entry.get("license") if isinstance(entry.get("license"), dict) else {}
        if isinstance(lic.get("id"), str):
            parts.append(lic["id"])
        elif isinstance(lic.get("name"), str) and lic["name"].strip():
            name = lic["name"].strip()[:200]
            ref = "LicenseRef-" + (_LICENSE_REF_RE.sub("-", name).strip("-.")[:60] or "custom")
            extracted.setdefault(ref, {"licenseId": ref, "name": name,
                                       "extractedText": f"Bildirilen lisans adı: {name}"})
            parts.append(ref)
    if not parts:
        return "NOASSERTION"
    return parts[0] if len(parts) == 1 else " AND ".join(parts)


def cyclonedx_to_spdx(cdx: dict[str, Any], *, created: str | None = None, namespace_seed: str = "") -> dict[str, Any]:
    """CycloneDX 1.4/1.5 belgesi → SPDX 2.3 JSON (paketler, purl dış başvuruları, lisanslar, ilişkiler)."""
    if not isinstance(cdx, dict) or cdx.get("bomFormat") != "CycloneDX":
        raise SbomError("Dönüştürülecek belge CycloneDX değil.")
    metadata = cdx.get("metadata") if isinstance(cdx.get("metadata"), dict) else {}
    main = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    name = str(main.get("name") or "proje")[:200]
    created = created or str(metadata.get("timestamp") or "") or "1970-01-01T00:00:00Z"
    created = re.sub(r"\.\d+", "", created).replace("+00:00", "Z")
    if not created.endswith("Z"):
        created += "Z" if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", created) else ""
    serial = str(cdx.get("serialNumber") or "")
    namespace_hash = hashlib.sha256(f"{serial}|{namespace_seed}|{name}".encode()).hexdigest()
    extracted: dict[str, dict[str, str]] = {}
    root_id = "SPDXRef-Package-root"
    packages: list[dict[str, Any]] = [{
        "SPDXID": root_id, "name": name, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "CONTAINER" if main.get("type") == "container" else "APPLICATION",
    }]
    ref_to_id: dict[str, str] = {}
    seen_ids: set[str] = {root_id}
    for comp in (cdx.get("components") or [])[:MAX_COMPONENTS]:
        if not isinstance(comp, dict) or not comp.get("name"):
            continue
        ref = str(comp.get("bom-ref") or comp.get("purl") or f"{comp.get('name')}@{comp.get('version', '')}")
        spdx_id = _spdx_id("Package", ref)
        if spdx_id in seen_ids:
            continue
        seen_ids.add(spdx_id)
        ref_to_id[ref] = spdx_id
        package: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": str(comp["name"])[:400],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _spdx_license(comp.get("licenses"), extracted),
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
        }
        if comp.get("version"):
            package["versionInfo"] = str(comp["version"])[:200]
        if comp.get("purl"):
            package["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                        "referenceLocator": str(comp["purl"])}]
        if comp.get("scope") == "optional":
            package["comment"] = "Geliştirme/isteğe bağlı bağımlılık (CycloneDX scope: optional)."
        packages.append(package)
    relationships: list[dict[str, str]] = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    main_ref = str(main.get("bom-ref") or ROOT_REF)
    deps = cdx.get("dependencies") if isinstance(cdx.get("dependencies"), list) else None
    if deps:
        for entry in deps:
            if not isinstance(entry, dict):
                continue
            parent = root_id if entry.get("ref") == main_ref else ref_to_id.get(str(entry.get("ref")))
            if not parent:
                continue
            for child_ref in entry.get("dependsOn") or []:
                child = ref_to_id.get(str(child_ref))
                if child and child != parent:
                    relationships.append({"spdxElementId": parent, "relationshipType": "DEPENDS_ON",
                                          "relatedSpdxElement": child})
    else:
        relationships += [{"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": i}
                          for i in ref_to_id.values()]
    tools = metadata.get("tools")
    tool_version = ""
    if isinstance(tools, list) and tools and isinstance(tools[0], dict):
        tool_version = str(tools[0].get("version") or "")
    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-sbom",
        "documentNamespace": f"https://sniper.invalid/spdx/{urllib.parse.quote(name, safe='')}-{namespace_hash[:32]}",
        "creationInfo": {"created": created, "creators": [f"Tool: {TOOL_NAME}" + (f"-{tool_version}" if tool_version else ""),
                                                          "Organization: Sniper (yerel)"]},
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": relationships,
    }
    if extracted:
        doc["hasExtractedLicensingInfos"] = sorted(extracted.values(), key=lambda e: e["licenseId"])
    return doc


# ---------------------------------------------------------------------------
# Yapısal doğrulama
# ---------------------------------------------------------------------------
def validate_cyclonedx(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["Kök bir JSON nesnesi değil."]
    if doc.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat 'CycloneDX' olmalı.")
    if doc.get("specVersion") not in ("1.4", "1.5", "1.6"):
        errors.append("specVersion 1.4/1.5/1.6 olmalı.")
    if "serialNumber" in doc and not re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                                                  str(doc["serialNumber"])):
        errors.append("serialNumber urn:uuid biçiminde olmalı.")
    comps = doc.get("components", [])
    if not isinstance(comps, list):
        return errors + ["components bir dizi olmalı."]
    refs: set[str] = set()
    for i, comp in enumerate(comps):
        if not isinstance(comp, dict) or not isinstance(comp.get("name"), str) or not comp.get("type"):
            errors.append(f"components[{i}]: name ve type zorunlu.")
            continue
        ref = comp.get("bom-ref")
        if ref is not None:
            if ref in refs:
                errors.append(f"components[{i}]: yinelenen bom-ref.")
            refs.add(ref)
        if "purl" in comp and not str(comp["purl"]).startswith("pkg:"):
            errors.append(f"components[{i}]: purl 'pkg:' ile başlamalı.")
        for lic in comp.get("licenses") or []:
            if not isinstance(lic, dict) or not (("license" in lic and isinstance(lic["license"], dict) and
                                                  ("id" in lic["license"] or "name" in lic["license"])) or "expression" in lic):
                errors.append(f"components[{i}]: licenses öğesi license.id/name ya da expression içermeli.")
                break
    main = (doc.get("metadata") or {}).get("component") if isinstance(doc.get("metadata"), dict) else None
    if isinstance(main, dict) and main.get("bom-ref"):
        refs.add(main["bom-ref"])
    for i, dep in enumerate(doc.get("dependencies") or []):
        if not isinstance(dep, dict) or dep.get("ref") not in refs:
            errors.append(f"dependencies[{i}]: ref belgede yok.")
            continue
        missing = [d for d in dep.get("dependsOn") or [] if d not in refs]
        if missing:
            errors.append(f"dependencies[{i}]: {len(missing)} dependsOn başvurusu belgede yok.")
    return errors


def validate_spdx(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["Kök bir JSON nesnesi değil."]
    for key, expected in (("spdxVersion", "SPDX-2.3"), ("dataLicense", "CC0-1.0"), ("SPDXID", "SPDXRef-DOCUMENT")):
        if doc.get(key) != expected:
            errors.append(f"{key} '{expected}' olmalı.")
    for key in ("name", "documentNamespace"):
        if not isinstance(doc.get(key), str) or not doc[key]:
            errors.append(f"{key} zorunlu.")
    if isinstance(doc.get("documentNamespace"), str) and ("#" in doc["documentNamespace"] or "://" not in doc["documentNamespace"]):
        errors.append("documentNamespace '#' içermeyen bir URI olmalı.")
    info = doc.get("creationInfo")
    if not isinstance(info, dict) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", str(info.get("created") or "")) \
            or not isinstance(info.get("creators"), list) or not info["creators"]:
        errors.append("creationInfo.created (YYYY-MM-DDThh:mm:ssZ) ve creators zorunlu.")
    ids = {"SPDXRef-DOCUMENT"}
    license_refs = {e.get("licenseId") for e in doc.get("hasExtractedLicensingInfos") or [] if isinstance(e, dict)}
    for i, pkg in enumerate(doc.get("packages") or []):
        if not isinstance(pkg, dict):
            errors.append(f"packages[{i}]: nesne değil.")
            continue
        sid = str(pkg.get("SPDXID") or "")
        if not _SPDX_ID_RE.fullmatch(sid):
            errors.append(f"packages[{i}]: SPDXID biçimi geçersiz.")
        if sid in ids:
            errors.append(f"packages[{i}]: yinelenen SPDXID.")
        ids.add(sid)
        for key in ("name", "downloadLocation"):
            if not pkg.get(key):
                errors.append(f"packages[{i}]: {key} zorunlu.")
        for key in ("licenseConcluded", "licenseDeclared"):
            value = str(pkg.get(key) or "NOASSERTION")
            for ref in re.findall(r"LicenseRef-[A-Za-z0-9.-]+", value):
                if ref not in license_refs:
                    errors.append(f"packages[{i}]: {ref} hasExtractedLicensingInfos içinde yok.")
        for ref in pkg.get("externalRefs") or []:
            if not isinstance(ref, dict) or not all(ref.get(k) for k in ("referenceCategory", "referenceType", "referenceLocator")):
                errors.append(f"packages[{i}]: externalRefs öğesi eksik.")
    for i, rel in enumerate(doc.get("relationships") or []):
        if not isinstance(rel, dict) or rel.get("spdxElementId") not in ids or rel.get("relatedSpdxElement") not in ids \
                or not rel.get("relationshipType"):
            errors.append(f"relationships[{i}]: öğe kimlikleri belgede yok ya da tür eksik.")
    return errors


# ---------------------------------------------------------------------------
# Dış SBOM okuma
# ---------------------------------------------------------------------------
def _component(name: Any, version: Any, purl: Any, license_value: Any = None) -> dict[str, str] | None:
    name = str(name or "").strip()
    purl = str(purl or "").strip()
    if not name and not purl:
        return None
    item = {"name": name[:400], "version": str(version or "").strip()[:200], "purl": purl[:2000]}
    if license_value:
        item["license"] = str(license_value)[:300]
    return item


def _cdx_json_components(doc: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    stack = list(doc.get("components") or [])
    while stack and len(out) < MAX_COMPONENTS:
        comp = stack.pop(0)
        if not isinstance(comp, dict):
            continue
        if isinstance(comp.get("components"), list):
            stack.extend(comp["components"][:MAX_COMPONENTS])
        lic = None
        for entry in comp.get("licenses") or []:
            if isinstance(entry, dict):
                lic = entry.get("expression") or (entry.get("license") or {}).get("id") or (entry.get("license") or {}).get("name")
                if lic:
                    break
        name = comp.get("name")
        if comp.get("group") and comp.get("name") and not comp.get("purl"):
            name = f"{comp['group']}:{comp['name']}"
        item = _component(name, comp.get("version"), comp.get("purl"), lic)
        if item:
            out.append(item)
    return out


def _reject_dtd(text: str) -> None:
    # 22. tur güvenlik: yalnız ilk 200 KB'ye bakılıyordu; uzun bir yorum ya da işleme yönergesi önekiyle DOCTYPE bu
    # pencerenin dışına itilebiliyordu. Tüm metin taranır (en çok MAX_SBOM_BYTES).
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise SbomError("XML SBOM DOCTYPE/ENTITY içeremez (dış varlık ve genişleme saldırıları kapalı).")


def _forbid_dtd(*_args) -> None:
    raise SbomError("XML SBOM DOCTYPE/ENTITY içeremez (dış varlık ve genişleme saldırıları kapalı).")


def _safe_xml_root(text: str):
    """Metin denetimine ek olarak ayrıştırıcı düzeyinde de DTD/varlık bildirimi reddedilir (defusedxml yaklaşımı):
    önce yalnız bildirim işleyicileri kurulu bir expat geçişi, sonra ElementTree (C hızlandırıcısı expat'ı açmaz)."""
    from xml.parsers import expat

    guard = expat.ParserCreate()
    guard.StartDoctypeDeclHandler = _forbid_dtd
    guard.EntityDeclHandler = _forbid_dtd
    guard.UnparsedEntityDeclHandler = _forbid_dtd
    guard.ExternalEntityRefHandler = _forbid_dtd
    try:
        guard.Parse(text, True)
    except expat.ExpatError as exc:
        raise ET.ParseError(str(exc)) from exc
    return ET.fromstring(text)


def _cdx_xml_components(text: str) -> tuple[list[dict[str, str]], str]:
    _reject_dtd(text)
    try:
        root = _safe_xml_root(text)
    except ET.ParseError as exc:
        raise SbomError("CycloneDX XML ayrıştırılamadı.") from exc
    if not root.tag.endswith("}bom") and root.tag != "bom":
        raise SbomError("XML belgesi bir CycloneDX bom değil.")
    ns = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
    q = (lambda t: f"{{{ns}}}{t}") if ns else (lambda t: t)  # noqa: E731
    version = ns.rsplit("/", 1)[-1] if ns else ""
    out: list[dict[str, str]] = []
    components_el = root.find(q("components"))
    if components_el is None:
        return out, version
    for comp in components_el.iter(q("component")):
        if len(out) >= MAX_COMPONENTS:
            break
        name = (comp.findtext(q("name")) or "").strip()
        group = (comp.findtext(q("group")) or "").strip()
        purl = (comp.findtext(q("purl")) or "").strip()
        lic = None
        lic_el = comp.find(q("licenses"))
        if lic_el is not None:
            lic = (lic_el.findtext(q("expression")) or lic_el.findtext(f"{q('license')}/{q('id')}")
                   or lic_el.findtext(f"{q('license')}/{q('name')}"))
        item = _component(f"{group}:{name}" if group and not purl else name, comp.findtext(q("version")), purl, lic)
        if item:
            out.append(item)
    return out, version


def _spdx_json_components(doc: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    described = set(doc.get("documentDescribes") or [])
    for pkg in (doc.get("packages") or [])[:MAX_COMPONENTS]:
        if not isinstance(pkg, dict):
            continue
        purl = next((r.get("referenceLocator") for r in pkg.get("externalRefs") or []
                     if isinstance(r, dict) and str(r.get("referenceType", "")).casefold() == "purl"), "")
        if pkg.get("SPDXID") in described and not purl:
            continue  # belgenin tanımladığı kök paket (uygulamanın kendisi)
        lic = pkg.get("licenseConcluded") if pkg.get("licenseConcluded") not in (None, "NOASSERTION", "NONE") else pkg.get("licenseDeclared")
        item = _component(pkg.get("name"), pkg.get("versionInfo"), purl,
                          lic if lic not in (None, "NOASSERTION", "NONE") else None)
        if item:
            out.append(item)
    return out


def _spdx_tag_components(text: str) -> tuple[list[dict[str, str]], str, str]:
    out: list[dict[str, str]] = []
    current: dict[str, Any] | None = None
    doc_name = ""
    version = ""
    in_text = False

    def flush() -> None:
        if current is not None and len(out) < MAX_COMPONENTS:
            item = _component(current.get("name"), current.get("version"), current.get("purl"), current.get("license"))
            if item:
                out.append(item)

    for line in text.splitlines()[:2_000_000]:
        if in_text:
            if "</text>" in line:
                in_text = False
            continue
        if "<text>" in line and "</text>" not in line:
            in_text = True
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "SPDXVersion":
            version = value
        elif key == "DocumentName" and current is None:
            doc_name = value
        elif key == "PackageName":
            flush()
            current = {"name": value}
        elif current is not None and key == "PackageVersion":
            current["version"] = value
        elif current is not None and key == "ExternalRef":
            parts = value.split()
            if len(parts) >= 3 and parts[1].casefold() == "purl":
                current["purl"] = parts[2]
        elif current is not None and key in ("PackageLicenseConcluded", "PackageLicenseDeclared"):
            if value not in ("NOASSERTION", "NONE") and not current.get("license"):
                current["license"] = value
    flush()
    return out, doc_name, version


def parse_sbom_bytes(data: bytes, filename: str = "") -> dict[str, Any]:
    """Dış SBOM içeriği → {format, spec_version, name, components[{name, version, purl, license?}]}."""
    if len(data) > MAX_SBOM_BYTES:
        raise SbomError(f"SBOM dosyası {MAX_SBOM_BYTES // (1024 * 1024)} MB sınırını aşıyor.")
    text = data.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise SbomError("SBOM geçerli JSON değil.") from exc
        if not isinstance(doc, dict):
            raise SbomError("SBOM kökü bir JSON nesnesi olmalı.")
        if doc.get("bomFormat") == "CycloneDX":
            meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
            name = str(((meta.get("component") or {}) if isinstance(meta.get("component"), dict) else {}).get("name") or "")
            return {"format": "cyclonedx-json", "spec_version": str(doc.get("specVersion") or ""), "name": name,
                    "components": _cdx_json_components(doc)}
        if str(doc.get("spdxVersion") or "").startswith("SPDX-"):
            return {"format": "spdx-json", "spec_version": str(doc["spdxVersion"]), "name": str(doc.get("name") or ""),
                    "components": _spdx_json_components(doc)}
        raise SbomError("JSON belgesi CycloneDX ya da SPDX değil.")
    if stripped.startswith("<"):
        components, version = _cdx_xml_components(stripped)
        return {"format": "cyclonedx-xml", "spec_version": version, "name": "", "components": components}
    if re.search(r"^SPDXVersion:\s*SPDX-", text, re.M):
        components, name, version = _spdx_tag_components(text)
        return {"format": "spdx-tag", "spec_version": version, "name": name, "components": components}
    raise SbomError("Tanınmayan SBOM biçimi (CycloneDX JSON/XML ya da SPDX JSON/tag-value bekleniyor).")


def new_uuid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
