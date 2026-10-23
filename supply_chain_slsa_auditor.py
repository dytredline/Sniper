from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib
from typing import Any

from dependency_security import discover_components
import legacy_basis
from project_analyzer import validate_project_path
from safe_file_read import read_text_bounded
from scanner import calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups


POPULAR_PACKAGES: tuple[str, ...] = (
    "requests",
    "urllib3",
    "cryptography",
    "fastapi",
    "django",
    "flask",
    "pydantic",
    "sqlalchemy",
    "numpy",
    "pandas",
    "torch",
    "openai",
    "anthropic",
    "lodash",
    "express",
    "axios",
    "react",
    "next",
    "chalk",
    "commander",
    "moment",
    "jsonwebtoken",
    "tokio",
    "serde",
    "reqwest",
    "hyper",
    "spring-boot",
    "jackson-databind",
)

POPULAR_SET = frozenset(POPULAR_PACKAGES)

KNOWN_SAFE_PACKAGES = frozenset({
    *POPULAR_PACKAGES,
    "nuxt",
    "preact",
    "pytest",
    "uvicorn",
    "starlette",
    "httpx",
    "aiohttp",
    "boto3",
    "botocore",
    "scipy",
    "matplotlib",
    "celery",
    "redis",
    "alembic",
    "click",
    "typer",
    "rich",
    "gunicorn",
    "attrs",
    "cattrs",
    "idna",
    "certifi",
    "six",
    "pyyaml",
    "jinja2",
    "werkzeug",
    "markupsafe",
    "itsdangerous",
    "blinker",
    "anyio",
    "sniffio",
    "h11",
    "hyperscan",
    "hypercorn",
    "serde_json",
    "serde_derive",
})

INTERNAL_PACKAGE_PATTERN = re.compile(
    r"(?:^|[-_.])(internal|private|corp|intranet|confidential)(?:$|[-_.])",
    re.IGNORECASE,
)

USES_ACTION_PATTERN = re.compile(
    r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?",
    re.MULTILINE,
)

SHA40_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")

RESTRICTIVE_LICENSE_PATTERN = re.compile(
    r"(?<![A-Za-z])(?:AGPL(?:-?\d+(?:\.\d+)?)?|GPL(?:-?[23](?:\.\d+)?)?|SSPL(?:-?\d+(?:\.\d+)?)?|BUSL(?:-?\d+(?:\.\d+)?)?)(?:-(?:only|or-later))?(?![A-Za-z])",
    re.IGNORECASE,
)


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return abs(len(a) - len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _is_adjacent_transposition(a: str, b: str) -> bool:
    if len(a) != len(b) or a == b:
        return False
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
        i = diffs[0]
        return a[i] == b[i + 1] and a[i + 1] == b[i]
    return False


def _detect_typosquat(pkg_name: str) -> tuple[str, str] | None:
    raw = pkg_name.strip().casefold()
    if not raw or raw.startswith("@"):
        return None
    if ":" in raw:
        raw = raw.rsplit(":", 1)[-1]
    if raw in KNOWN_SAFE_PACKAGES:
        return None
    normalized_collapsed = re.sub(r"[-_.]", "", raw)
    for target in POPULAR_PACKAGES:
        if raw == target:
            continue
        if _is_adjacent_transposition(raw, target):
            return target, f"Adjacent character transposition of popular package '{target}'"
        if _levenshtein_distance(raw, target) == 1:
            return target, f"Edit distance 1 from popular package '{target}'"
        target_collapsed = re.sub(r"[-_.]", "", target)
        if normalized_collapsed == target_collapsed:
            return target, f"Hyphen/separator spoofing of popular package '{target}'"
    return None


def _read_manifest_licenses(root: Path) -> list[tuple[str, str]]:
    discovered: list[tuple[str, str]] = []
    pkg_json = root / "package.json"
    pkg_json_text = read_text_bounded(pkg_json, 1_000_000, errors="ignore", allow_empty=True)
    if pkg_json_text is not None:
        try:
            data = json.loads(pkg_json_text)
            if isinstance(data, dict):
                lic = data.get("license")
                name = str(data.get("name") or "package.json")
                if isinstance(lic, str) and lic.strip():
                    discovered.append((name, lic.strip()))
        except Exception:
            pass

    pyproject = root / "pyproject.toml"
    pyproject_text = read_text_bounded(pyproject, 1_000_000, errors="ignore", allow_empty=True)
    if pyproject_text is not None:
        try:
            data = tomllib.loads(pyproject_text)
            if isinstance(data, dict):
                proj = data.get("project")
                if isinstance(proj, dict):
                    name = str(proj.get("name") or "pyproject.toml")
                    lic = proj.get("license")
                    if isinstance(lic, str) and lic.strip():
                        discovered.append((name, lic.strip()))
                    elif isinstance(lic, dict):
                        text = str(lic.get("text") or lic.get("file") or "").strip()
                        if text:
                            discovered.append((name, text))
        except Exception:
            pass

    cargo = root / "Cargo.toml"
    cargo_text = read_text_bounded(cargo, 1_000_000, errors="ignore", allow_empty=True)
    if cargo_text is not None:
        try:
            data = tomllib.loads(cargo_text)
            if isinstance(data, dict):
                pkg = data.get("package")
                if isinstance(pkg, dict):
                    name = str(pkg.get("name") or "Cargo.toml")
                    lic = pkg.get("license")
                    if isinstance(lic, str) and lic.strip():
                        discovered.append((name, lic.strip()))
        except Exception:
            pass

    return discovered


# 23. tur: proje klasöründe aranan kaynak/imza/SBOM/VEX artefaktları (en çok 2 düzey derinlik, sembolik bağ yok).
_PROVENANCE_SCAN_SKIP = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", "dist-packages", "data"})
_PROVENANCE_MAX_ENTRIES = 5_000


def _classify_provenance_file(name: str) -> str | None:
    low = name.casefold()
    if low.endswith((".intoto.jsonl", ".intoto.json")) or ("provenance" in low and low.endswith((".json", ".jsonl"))):
        return "provenance"
    if low.endswith((".sig", ".asc", ".sigstore", ".sigstore.json")) or low in {"cosign.pub", "release-signing.pub"}:
        return "signature"
    if low.endswith((".vex.json", ".openvex.json")) or low.startswith(("vex.", "openvex")) or low.endswith(".csaf.json"):
        return "vex"
    if (low.endswith((".cdx.json", ".cdx.xml", ".spdx.json", ".spdx", ".spdx.xml"))
            or (low.startswith(("bom.", "sbom")) and low.endswith((".json", ".xml")))):
        return "sbom"
    if low == "sha256sums" or low.endswith(".sha256"):
        return "checksum"
    return None


def _project_provenance_signals(root: Path) -> dict[str, Any]:
    """Projede gerçekten bulunan sürüm manifesti, imza, SBOM ve VEX dosyaları."""
    found: dict[str, list[str]] = {"provenance": [], "signature": [], "sbom": [], "vex": [], "checksum": []}
    release_manifest: dict[str, Any] | None = None
    seen = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack and seen < _PROVENANCE_MAX_ENTRIES:
        current, depth = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen >= _PROVENANCE_MAX_ENTRIES:
                break
            if entry.is_symlink():
                continue
            rel = entry.relative_to(root).as_posix()
            if entry.is_dir():
                if depth < 2 and entry.name not in _PROVENANCE_SCAN_SKIP:
                    stack.append((entry, depth + 1))
                continue
            if entry.name == "MANIFEST.json" and release_manifest is None:
                text = read_text_bounded(entry, 4_000_000, errors="ignore", allow_empty=True)
                try:
                    data = json.loads(text) if text else None
                except ValueError:
                    data = None
                if isinstance(data, dict) and str(data.get("format") or "").startswith("sniper-release/"):
                    sig = entry.with_name("MANIFEST.json.sig")
                    release_manifest = {
                        "path": rel, "format": data.get("format"), "version": str(data.get("version") or ""),
                        "file_count": len(data.get("files") or []),
                        "signed": sig.is_file() and not sig.is_symlink(),
                    }
                continue
            kind = _classify_provenance_file(entry.name)
            if kind and len(found[kind]) < 20:
                found[kind].append(rel)
    return {"files": found, "release_manifest": release_manifest}


def _vex_status(store: Any, project_path: str, allowed_roots: tuple[Path, ...] | None) -> dict[str, Any] | None:
    """Depodaki bağımlılık bulguları için kayıtlı VEX kararlarının sayısı."""
    if store is None or not hasattr(store, "dependency_findings_for_project"):
        return None
    try:
        import vex_export
        _, dep_findings = vex_export.project_findings(store, project_path, allowed_roots)
        ids = [str(f.get("id")) for f in dep_findings if f.get("id") is not None]
        decisions = store.vex_decisions(ids) if ids and hasattr(store, "vex_decisions") else {}
    except Exception:
        return None
    return {"dependency_findings": len(dep_findings), "vex_decisions": len(decisions),
            "undecided": max(0, len(dep_findings) - len(decisions))}


def audit_supply_chain_slsa(
    project_path: str | None = None,
    *,
    components: list[dict[str, Any]] | None = None,
    workflow_content: str | None = None,
    license_policy: str = "commercial",
    allowed_roots: tuple[Path, ...] | None = None,
    store: Any = None,
) -> dict[str, Any]:
    has_components = isinstance(components, list) and any(isinstance(c, dict) for c in components)
    has_workflow = isinstance(workflow_content, str) and bool(workflow_content.strip())
    if project_path is None and not has_components and not has_workflow:
        raise legacy_basis.NoSourceError(
            "Tedarik zinciri denetimi için proje klasörü (project_path), bileşen listesi (components) "
            "ya da CI iş akışı içeriği (workflow_content) gönderin.")
    comp_list: list[dict[str, Any]] = []
    provenance: dict[str, Any] = {"files": {}, "release_manifest": None}
    vex_state: dict[str, Any] | None = None
    workflows: list[tuple[str, str]] = []
    manifest_licenses: list[tuple[str, str]] = []
    root: Path | None = None

    if project_path is not None:
        root = validate_project_path(project_path, allowed_roots)
        try:
            _, discovered = discover_components(str(root), allowed_roots=allowed_roots)
            comp_list.extend(discovered)
        except Exception:
            pass
        manifest_licenses.extend(_read_manifest_licenses(root))
        provenance = _project_provenance_signals(root)
        vex_state = _vex_status(store, str(root), allowed_roots)
        wf_dir = root / ".github" / "workflows"
        if wf_dir.is_dir() and not wf_dir.is_symlink():
            for wf_path in sorted(wf_dir.iterdir()):
                if wf_path.suffix.casefold() not in {".yml", ".yaml"}:
                    continue
                wf_text = read_text_bounded(wf_path, 1_000_000, errors="ignore", allow_empty=True)
                if wf_text is None:
                    continue
                workflows.append((f".github/workflows/{wf_path.name}", wf_text))

    if isinstance(components, list):
        for item in components:
            if isinstance(item, dict):
                comp_list.append(dict(item))

    if isinstance(workflow_content, str) and workflow_content.strip():
        workflows.append((".github/workflows/inline.yml", workflow_content))

    typos: list[dict[str, Any]] = []
    confusion: list[dict[str, Any]] = []
    unpinned: list[dict[str, Any]] = []
    licenses: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    seen_typos: set[str] = set()
    seen_confusion: set[str] = set()
    seen_licenses: set[tuple[str, str]] = set()

    # 1 & 2 & 4: Component checks (Typosquatting, Dependency Confusion, License Risk)
    for comp in comp_list:
        raw_name = str(comp.get("name") or comp.get("package") or "").strip()
        if not raw_name:
            continue
        ecosystem = str(comp.get("ecosystem") or "generic").strip()
        manifest = str(comp.get("manifest") or "manifest").strip()
        version = str(comp.get("version") or "").strip()

        typo_match = _detect_typosquat(raw_name)
        if typo_match is not None and raw_name.casefold() not in seen_typos:
            seen_typos.add(raw_name.casefold())
            target_pkg, reason = typo_match
            typos.append({
                "package": raw_name,
                "version": version,
                "suspected_target": target_pkg,
                "ecosystem": ecosystem,
                "manifest": manifest,
                "reason": reason,
            })
            findings.append({
                "severity": "critical",
                "category": "supplychain",
                "title": f"Olası typosquatting paketi tespit edildi: {raw_name} (hedef: {target_pkg})",
                "summary": f"'{raw_name}' paket adı popüler '{target_pkg}' paketine çok yakın ({reason}).",
                "evidence": f"{manifest}: {raw_name}@{version or '*'}",
                "recommendation": f"Paket adını '{target_pkg}' olarak doğrulayın ve şüpheli paketi derhal kaldırın.",
                "reference": "CWE-829",
                "control_id": "SNIPER-SUPP-01",
            })

        if (
            not raw_name.startswith("@")
            and ":" not in raw_name
            and INTERNAL_PACKAGE_PATTERN.search(raw_name)
            and raw_name.casefold() not in seen_confusion
        ):
            seen_confusion.add(raw_name.casefold())
            confusion.append({
                "package": raw_name,
                "version": version,
                "ecosystem": ecosystem,
                "manifest": manifest,
                "reason": "Kapsamsız, iç paket gibi görünen ad bağımlılık karışıklığına açık",
            })
            findings.append({
                "severity": "high",
                "category": "supplychain",
                "title": f"Dependency Confusion riski taşıyan kapsamsız iç paket adı: {raw_name}",
                "summary": "Kapsamsız (unscoped) iç paket adları genel paket kayıtlarında gölgelenerek uzaktan kod çalıştırmaya yol açabilir.",
                "evidence": f"{manifest}: {raw_name}",
                "recommendation": "İç paketlerde organizasyon kapsamı (@corp/pkg) kullanın ve kayıt defteri önceliğini sabitleyin.",
                "reference": "CWE-427",
                "control_id": "SNIPER-SUPP-01",
            })

        raw_lic = comp.get("license") or comp.get("licenses") or ""
        if isinstance(raw_lic, list):
            raw_lic = ", ".join(str(x) for x in raw_lic)
        lic_str = str(raw_lic).strip()
        if lic_str:
            manifest_licenses.append((raw_name, lic_str))

    if license_policy.strip().casefold() == "commercial":
        for pkg_name, lic_str in manifest_licenses:
            if "lgpl" in lic_str.casefold() and not re.search(r"(?<![lL])gpl", lic_str):
                continue
            if RESTRICTIVE_LICENSE_PATTERN.search(lic_str):
                key = (pkg_name.casefold(), lic_str.upper())
                if key not in seen_licenses:
                    seen_licenses.add(key)
                    licenses.append({
                        "package": pkg_name,
                        "license": lic_str,
                        "policy": license_policy,
                    })
                    findings.append({
                        "severity": "medium",
                        "category": "supplychain",
                        "title": f"Ticari politikayla uyumsuz kısıtlayıcı lisans: {pkg_name} ({lic_str})",
                        "summary": f"'{pkg_name}' bileşeni '{lic_str}' copyleft/kısıtlayıcı lisansını kullanıyor.",
                        "evidence": f"{pkg_name}: license={lic_str}",
                        "recommendation": "Ticari dağıtım politikasına uygun (MIT, Apache-2.0, BSD-3-Clause) bir alternatif kullanın veya hukuki inceleme yapın.",
                        "reference": "CWE-1104",
                        "control_id": "SNIPER-SUPP-01",
                    })

    # 3: SLSA v1.0 Provenance & GitHub Actions Commit SHA Pinning
    has_provenance = False
    provenance_tokens = (
        "attest-build-provenance",
        "slsa-github-generator",
        "slsa-framework",
        "cosign",
        "sigstore",
    )

    for wf_name, content in workflows:
        low_content = content.casefold()
        if any(tok in low_content for tok in provenance_tokens):
            has_provenance = True
        for match in USES_ACTION_PATTERN.finditer(content):
            action_spec = match.group(1).strip()
            if action_spec.startswith(("./", ".\\", "docker://")):
                continue
            if "@" not in action_spec:
                continue
            repo_part, ref_part = action_spec.rsplit("@", 1)
            if SHA40_PATTERN.fullmatch(ref_part):
                continue
            sev = "high" if ref_part.casefold() in {"main", "master", "head", "latest"} else "medium"
            unpinned.append({
                "action": action_spec,
                "repository": repo_part,
                "ref": ref_part,
                "workflow": wf_name,
            })
            findings.append({
                "severity": sev,
                "category": "supplychain",
                "title": f"SHA ile sabitlenmemiş GitHub Action kullanımı: {action_spec}",
                "summary": f"CI/CD iş akışında değiştirilebilir '{ref_part}' etiketi/dalı kullanılıyor; SLSA v1.0 40 karakterlik commit SHA sabitlemesi gerektirir.",
                "evidence": f"{wf_name}: uses: {action_spec}",
                "recommendation": f"'{repo_part}' eylemini tam 40 karakterlik git commit SHA özeti ile sabitleyin.",
                "reference": "CWE-829",
                "control_id": "SNIPER-SUPP-05",
            })

    # Projede gerçekten bulunan imzalı sürüm manifesti / in-toto kaydı da kaynak kanıtıdır.
    prov_files = provenance.get("files") or {}
    release_manifest = provenance.get("release_manifest")
    if prov_files.get("provenance") or (release_manifest and release_manifest.get("signed")):
        has_provenance = True
    if root is not None and not prov_files.get("sbom"):
        findings.append({
            "severity": "low",
            "category": "supplychain",
            "title": "Projede SBOM (CycloneDX/SPDX) dosyası yok",
            "summary": "Sürümle birlikte yayımlanan bir SBOM, bileşen envanterinin alıcı tarafından doğrulanmasını sağlar.",
            "evidence": "bom.json / *.cdx.json / *.spdx.json bulunamadı (2 düzey derinlik)",
            "recommendation": "CI'da CycloneDX SBOM üretip sürüm artefaktına ekleyin (Sniper: SBOM dışa aktarma).",
            "reference": "CWE-1104",
            "control_id": "SNIPER-SUPP-02",
        })

    if has_provenance and len(unpinned) == 0 and len(workflows) > 0:
        slsa_level = 3
    elif has_provenance or (len(workflows) > 0 and len(unpinned) == 0):
        slsa_level = 2
    elif len(workflows) > 0 or len(comp_list) > 0:
        slsa_level = 1
    else:
        slsa_level = 0

    score, grade, _ = calculate_score(findings)

    return {
        "format": "sniper-supply-chain-slsa-audit-v1",
        "component_count": len(comp_list),
        "estimated_slsa_level": slsa_level,
        "typosquatting_suspects": typos,
        "dependency_confusion_risks": confusion,
        "unpinned_actions": unpinned,
        "license_risks": licenses,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": ["SNIPER-SUPP-01", "SNIPER-SUPP-02", "SNIPER-SUPP-05"],
        "has_provenance": has_provenance,
        "provenance_files": prov_files,
        "release_manifest": release_manifest,
        "vex_status": vex_state,
        "slsa_level_note": ("Tahmini düzey yalnız iş akışı, imza/in-toto dosyaları ve SHA sabitlemesine dayanır; "
                            "derleme ortamının yalıtımı statik olarak doğrulanamaz."),
        "data_basis": legacy_basis.data_basis("real", [
            "proje klasörü" if root is not None else "",
            f"istekteki {len(components)} bileşen" if has_components else "",
            "istekteki iş akışı" if has_workflow else "",
            "depodaki VEX kararları" if vex_state else "",
        ]),
    }
