"""Doğruluk ölçümü: zemin gerçeği, eşleştirme, CodeQL karşılaştırması, ölçüm geçmişi ve regresyon.

``scripts/eval_pipeline.py`` bu modülle ölçüm setlerini puanlar ve sonucu
``$SNIPER_DATA_DIR/eval-history/<zaman>-<etiket>.json`` dosyasına yazar. Sunucu yalnız okur
(``/api/eval/*``); proje analizi son ölçümden sınıf başına ölçülmüş kesinliği bulgulara not eder.

Zemin gerçeği biçimi (``sniper-ground-truth/1``)::

    {"format": "sniper-ground-truth/1",
     "meta": {...},
     "projects": {"<proje>": [{"file": "a/b.py", "lines": [10, 12], "class": "sql",
                               "kind": "direct|stored|second_order|client|config", "note": "...",
                               "alt": [["şablon.html", 28, 28]]}]},
     "adjudicated": {"<proje>": [{"file": "...", "line": 30, "class": "path",
                                  "verdict": "true_positive|false_positive|disputed", "note": "..."}]}}

``adjudicated``: zemin gerçeğinde olmayan araç bulgularının elle verilen kararı (belgelenmemiş gerçek açık
ya da yanlış alarm). Eşleşme kuralı: aynı proje + aynı dosya (veya ``alt`` konumu) + aynı sınıf + satır ±3.
Kaynak satır içeriği hiçbir sonuçta saklanmaz.
"""
from __future__ import annotations

import collections
import glob
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Iterable

from safe_file_read import read_text_bounded

GT_FORMAT = "sniper-ground-truth/1"
HISTORY_FORMAT = "sniper-eval-history/1"
MAX_GROUND_TRUTH_BYTES = 64_000_000
MAX_CODEQL_SARIF_BYTES = 64_000_000
MAX_CORROBORATION_EVIDENCE = 20_000
MAX_CORROBORATION_PATH = 4096
MAX_CORROBORATION_LABEL = 256
MAX_CORROBORATION_CLASSES = 32
MAX_RULE_FEEDBACK_ROWS = 100_000
LINE_SLACK = 3
CLASSES = ("sql", "nosql", "cmd", "code", "deser", "path", "ssrf", "xss", "redirect", "ssti", "xxe", "xpath", "proto", "ldap",
           "mem", "fmt", "iac")
# 9. set: altyapı-kod (IaC) yanlış yapılandırmaları tek sınıf ("iac"); CWE'den değil bulgu kategorisinden/kural kimliğinden.
IAC_CATEGORIES = frozenset({"container", "iac", "cloud", "kubernetes", "terraform", "dockerfile", "helm"})
IAC_RULE_PREFIXES = ("iac.", "iac_", "IAC", "CKV", "CIS-K8S", "CIS-DOCKER")

# Sniper bulgu referansı (CWE) → sınıf.
CWE_CLASSES: dict[str, frozenset[str]] = {
    "89": frozenset({"sql"}), "943": frozenset({"nosql"}), "78": frozenset({"cmd"}), "77": frozenset({"cmd"}),
    # Şablon motoruna verilen girdi (SSTI) motorda kod enjeksiyonu (CWE-94/95) olarak da raporlanır; CodeQL
    # code-injection → {code, ssti} eşlemesiyle simetrik.
    "94": frozenset({"code", "ssti"}), "95": frozenset({"code", "ssti"}), "502": frozenset({"deser"}),
    "22": frozenset({"path"}), "23": frozenset({"path"}), "73": frozenset({"path"}), "918": frozenset({"ssrf"}),
    "79": frozenset({"xss"}), "80": frozenset({"xss"}), "601": frozenset({"redirect"}), "1336": frozenset({"ssti"}),
    "611": frozenset({"xxe"}), "643": frozenset({"xpath"}), "1321": frozenset({"proto"}), "90": frozenset({"ldap"}),
    # C/C++ bellek güvenliği (8. set): taşma, sınır dışı okuma/yazma, serbest bırakılmış bellek, tehlikeli işlevler; biçim dizgesi.
    **{cwe: frozenset({"mem"}) for cwe in ("119", "120", "121", "122", "124", "125", "126", "127", "131", "170", "190",
                                            "242", "415", "416", "676", "680", "787", "788", "805", "806",
                                            # 26. tur: dizi indeksi (taint memory_index), off-by-one, öbek dışı/kaydırılmış
                                            # işaretçinin serbest bırakılması, ayırma/serbest bırakma uyumsuzluğu
                                            "129", "193", "590", "761", "762")},
    "134": frozenset({"fmt"}),
}
# CodeQL kural adı (dil/ önekinden sonra) → sınıf.
CODEQL_CLASSES: dict[str, frozenset[str]] = {
    "sql-injection": frozenset({"sql", "nosql"}), "nosql-injection": frozenset({"nosql"}),
    "command-line-injection": frozenset({"cmd"}), "shell-command-injection-from-environment": frozenset({"cmd"}),
    "code-injection": frozenset({"code", "ssti"}), "unsafe-deserialization": frozenset({"deser"}),
    "path-injection": frozenset({"path"}), "zipslip": frozenset({"path"}), "tainted-path": frozenset({"path"}),
    "request-forgery": frozenset({"ssrf"}), "full-ssrf": frozenset({"ssrf"}), "partial-ssrf": frozenset({"ssrf"}),
    "reflected-xss": frozenset({"xss"}), "reflective-xss": frozenset({"xss"}), "xss": frozenset({"xss"}),
    "stored-xss": frozenset({"xss"}), "xss-through-dom": frozenset({"xss"}), "xss-through-exception": frozenset({"xss"}),
    "url-redirection": frozenset({"redirect"}), "server-side-unvalidated-url-redirection": frozenset({"redirect"}),
    "client-side-unvalidated-url-redirection": frozenset({"redirect"}),
    "template-injection": frozenset({"ssti"}), "template-object-injection": frozenset({"ssti", "xss"}),
    "xxe": frozenset({"xxe"}), "xpath-injection": frozenset({"xpath"}),
    "prototype-pollution": frozenset({"proto"}), "prototype-pollution-utility": frozenset({"proto"}),
    "prototype-polluting-assignment": frozenset({"proto"}), "ldap-injection": frozenset({"ldap"}),
    "angular/disabling-sce": frozenset({"xss"}),
    # 16. tur ölçüm düzeltmesi: dile özgü adı farklı olan taint kuralları (önceki setlerde eşlenmiyordu → CodeQL eksik sayılıyordu).
    "command-injection": frozenset({"cmd"}), "shell-command-constructed-from-input": frozenset({"cmd"}),
    "kernel-open": frozenset({"cmd"}), "non-constant-kernel-open": frozenset({"cmd"}),
    "ssrf": frozenset({"ssrf"}), "unvalidated-url-redirection": frozenset({"redirect"}),
    "xml/xpath-injection": frozenset({"xpath"}), "unsafe-deserialization-untrusted-input": frozenset({"deser"}),
    "concatenated-sql-query": frozenset({"sql"}), "server-side-template-injection": frozenset({"ssti"}),
    "html-constructed-from-input": frozenset({"xss"}), "web/xss": frozenset({"xss"}),
    "web/unvalidated-url-redirection": frozenset({"redirect"}), "xml/insecure-dtd-handling": frozenset({"xxe"}),
    # C/C++ (cpp/ öneki): bellek güvenliği ve biçim dizgesi kuralları.
    **{rule: frozenset({"mem"}) for rule in (
        "unbounded-write", "overflow-buffer", "overrunning-write", "overrunning-write-with-float", "very-likely-overrunning-write",
        "badly-bounded-write", "static-buffer-overflow", "overflow-destination", "dangerous-function-overflow", "dangerous-cin",
        "use-after-free", "double-free", "no-space-for-terminator", "allocation-too-small", "suspicious-allocation-size",
        "overflow-calculated", "uncontrolled-allocation-size", "tainted-arithmetic", "uncontrolled-arithmetic",
        "integer-overflow-tainted", "comparison-with-wider-type", "unsafe-strncat", "unsafe-strcat", "strncpy-flippedargs",
        "invalid-pointer-deref", "out-of-bounds-write", "access-out-of-bounds", "late-negative-test", "missing-negativity-test")},
    "tainted-format-string": frozenset({"fmt"}), "tainted-format-string-through-global": frozenset({"fmt"}),
    "non-constant-format": frozenset({"fmt"}),
}
CODEQL_NOISY_RULES = frozenset({"js/xss-through-dom"})

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


class EvalError(ValueError):
    """Geçersiz ölçüm yapılandırması veya zemin gerçeği."""


# ---------------------------------------------------------------------------
# Sınıflar
# ---------------------------------------------------------------------------
def sniper_classes(reference: str | None) -> frozenset[str]:
    if not isinstance(reference, str):
        return frozenset()
    match = _CWE_RE.fullmatch(reference.strip())
    return CWE_CLASSES.get(match.group(1), frozenset()) if match else frozenset()


def codeql_classes(rule_id: str) -> frozenset[str]:
    name = rule_id.split("/", 1)[1] if "/" in rule_id else rule_id
    return CODEQL_CLASSES.get(name, frozenset())


VERIFIED_PREFIXES = ("Doğrulanmış veri akışı", "Doğrulanmış bellek hatası")
_MULTI_CLASS_SINK_CLASSES = {
    "code": "code",
    "eval": "code",
    "ssti": "ssti",
    "template_object": "ssti",
}


def is_verified_flow(finding: dict[str, Any]) -> bool:
    """Doğrulanmış (istek/kayıtlı veri kaynaklı) veri akışı bulgusu ya da yerel bellek motorunun kesin bulgusu
    (sabit/simgesel boyutlarla her yolda oluşan taşma, kesin use-after-free/double free, dış girdinin denetimsiz
    sabit tampona ulaşması); ikinci derece/kısmi ve "olası" bulgular ayrı izlenir."""
    return str(finding.get("title", "")).startswith(VERIFIED_PREFIXES)


def is_second_order_flow(finding: dict[str, Any]) -> bool:
    return str(finding.get("title", "")).startswith("İkinci derece veri akışı")


# ---------------------------------------------------------------------------
# Zemin gerçeği
# ---------------------------------------------------------------------------
def normalize_ground_truth(raw: Any) -> dict[str, Any]:
    """Eski biçimi (``meta`` + ``projects``) dahil zemin gerçeğini ``sniper-ground-truth/1`` biçimine getir ve doğrula."""
    if not isinstance(raw, dict) or not isinstance(raw.get("projects"), dict):
        raise EvalError("Zemin gerçeği 'projects' sözlüğü içermeli.")
    fmt = raw.get("format", GT_FORMAT)
    if fmt != GT_FORMAT:
        raise EvalError(f"Desteklenmeyen zemin gerçeği biçimi: {fmt}")
    projects: dict[str, list[dict[str, Any]]] = {}
    for project, items in raw["projects"].items():
        if not isinstance(items, list):
            raise EvalError(f"{project}: açık listesi olmalı.")
        normalized = []
        for index, item in enumerate(items):
            try:
                lines = [int(item["lines"][0]), int(item["lines"][1])]
                entry = {"file": str(item["file"]), "lines": lines, "class": str(item["class"]),
                         "kind": str(item.get("kind", "direct")), "note": str(item.get("note", ""))[:300],
                         "alt": [[str(a[0]), int(a[1]), int(a[2])] for a in item.get("alt", [])]}
            except (KeyError, TypeError, ValueError, IndexError) as exc:
                raise EvalError(f"{project}[{index}]: geçersiz açık kaydı ({exc}).") from exc
            if entry["class"] not in CLASSES:
                raise EvalError(f"{project}[{index}]: bilinmeyen sınıf {entry['class']}.")
            normalized.append(entry)
        projects[str(project)] = normalized
    adjudicated: dict[str, list[dict[str, Any]]] = {}
    for project, items in (raw.get("adjudicated") or {}).items():
        rows = []
        for item in items:
            verdict = item.get("verdict")
            if verdict not in {"true_positive", "false_positive", "disputed"}:
                raise EvalError(f"{project}: karar true_positive/false_positive/disputed olmalı.")
            rows.append({"file": str(item["file"]), "line": int(item["line"]), "class": str(item["class"]),
                         "verdict": verdict, "note": str(item.get("note", ""))[:300]})
        adjudicated[str(project)] = rows
    return {"format": GT_FORMAT, "meta": dict(raw.get("meta") or {}), "projects": projects, "adjudicated": adjudicated}


def load_ground_truth(path: str | Path) -> dict[str, Any]:
    try:
        text = read_text_bounded(path, MAX_GROUND_TRUTH_BYTES, errors="strict")
        if text is None:
            raise EvalError(f"Zemin gerçeği okunamadı veya {MAX_GROUND_TRUTH_BYTES} bayt sınırını aştı.")
        raw = json.loads(text)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvalError):
            raise
        raise EvalError(f"Zemin gerçeği okunamadı: {exc}") from exc
    return normalize_ground_truth(raw)


def _near(line: int | None, start: int, end: int) -> bool:
    return line is not None and start - LINE_SLACK <= line <= end + LINE_SLACK


def match_ground_truth(gt: dict[str, Any], project: str, file: str, line: int | None, classes: Iterable[str]) -> list[int]:
    classes = set(classes)
    hits = []
    for index, entry in enumerate(gt["projects"].get(project, [])):
        if entry["class"] not in classes:
            continue
        locations = [[entry["file"], *entry["lines"]], *entry["alt"]]
        if any(file == loc_file and _near(line, start, end) for loc_file, start, end in locations):
            hits.append(index)
    return hits


def adjudication(gt: dict[str, Any], project: str, file: str, line: int | None, classes: Iterable[str]) -> str | None:
    classes = set(classes)
    for row in gt.get("adjudicated", {}).get(project, []):
        if row["file"] == file and row["class"] in classes and _near(line, row["line"], row["line"]):
            return row["verdict"]
    return None


# ---------------------------------------------------------------------------
# Puanlama
# ---------------------------------------------------------------------------
def finding_key(project: str, file: str, line: int | None, cls: str) -> str:
    return f"{project}|{file}:{line}|{cls}"


def score_items(gt: dict[str, Any] | None, items: list[tuple[str, str, int | None, frozenset[str], str]]) -> dict[str, Any]:
    """Araç bulgularını (proje, dosya, satır, sınıflar, etiket) zemin gerçeğine göre puanla.

    Zemin gerçeği yoksa yalnız bulgu anahtarları ve sınıf sayıları döner."""
    by_class: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    keys = sorted({finding_key(p, f, l, min(c)) for p, f, l, c, _t in items if c})
    if gt is None:
        for _p, _f, _l, classes, _t in items:
            for cls in classes:
                by_class[cls]["findings"] += 1
        return {"findings": len(items), "keys": keys, "by_class": {k: dict(v) for k, v in sorted(by_class.items())}}
    found: dict[str, set[int]] = collections.defaultdict(set)
    unmatched: list[dict[str, Any]] = []
    extra_true = false_pos = 0
    for project, file, line, classes, tag in items:
        hits = match_ground_truth(gt, project, file, line, classes)
        cls = min(classes)
        if hits:
            found[project].update(hits)
            by_class[gt["projects"][project][hits[0]]["class"]]["tp_findings"] += 1
            continue
        verdict = adjudication(gt, project, file, line, classes)
        if verdict == "true_positive":
            extra_true += 1
            by_class[cls]["tp_findings"] += 1
        elif verdict in {"false_positive", "disputed"}:
            false_pos += 1
            by_class[cls]["fp"] += 1
        else:
            by_class[cls]["unclassified"] += 1
        unmatched.append({"key": finding_key(project, file, line, cls), "project": project, "file": file, "line": line,
                          "classes": sorted(classes), "verdict": verdict or "unclassified", "tag": tag[:80]})
    total = sum(len(v) for v in gt["projects"].values())
    tp = sum(len(v) for v in found.values())
    missed = collections.Counter(
        entry["class"] + ("/" + entry["kind"] if entry["kind"] != "direct" else "")
        for project, entries in gt["projects"].items() for index, entry in enumerate(entries)
        if index not in found.get(project, set()))
    per_project = {project: {"tp": len(found.get(project, ())), "total": len(entries)} for project, entries in gt["projects"].items()}
    for project, entries in gt["projects"].items():
        for index, entry in enumerate(entries):
            by_class[entry["class"]]["gt_total"] += 1
            if index in found.get(project, set()):
                by_class[entry["class"]]["gt_found"] += 1
    unclassified = sum(1 for row in unmatched if row["verdict"] == "unclassified")
    matched_findings = len(items) - len(unmatched)
    correct = matched_findings + extra_true
    judged = correct + false_pos
    return {
        "findings": len(items),
        "tp": tp, "total": total, "fn": total - tp,
        "recall": round(tp / total, 4) if total else None,
        "precision": round(correct / judged, 4) if judged else None,
        "precision_lower_bound": round(correct / len(items), 4) if items else None,
        "correct_findings": correct, "false_positives": false_pos, "unclassified": unclassified,
        "found": {k: sorted(v) for k, v in sorted(found.items())},
        "missed_classes": dict(missed.most_common()),
        "per_project": per_project,
        "unmatched": unmatched,
        "keys": keys,
        "by_class": {k: dict(v) for k, v in sorted(by_class.items())},
    }


# ---------------------------------------------------------------------------
# SCA (bağımlılık açığı) ölçümü — 10. set (paket@sürüm düzeyi)
# ---------------------------------------------------------------------------
SCA_GT_FORMAT = "sniper-sca-ground-truth/1"
_SCA_ECOSYSTEMS = {"npm": "npm", "pypi": "pypi", "maven": "maven", "go": "go", "golang": "go", "packagist": "packagist",
                   "composer": "packagist", "crates.io": "crates.io", "cargo": "crates.io", "rust": "crates.io",
                   "rubygems": "rubygems", "gem": "rubygems", "nuget": "nuget", "pub": "pub"}


def load_sca_ground_truth(path: str | Path) -> dict[str, Any]:
    try:
        text = read_text_bounded(path, MAX_GROUND_TRUTH_BYTES, errors="strict")
        if text is None:
            raise EvalError(f"SCA zemin gerçeği okunamadı veya {MAX_GROUND_TRUTH_BYTES} bayt sınırını aştı.")
        raw = json.loads(text)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvalError):
            raise
        raise EvalError(f"SCA zemin gerçeği okunamadı: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("format") != SCA_GT_FORMAT or not isinstance(raw.get("projects"), dict):
        raise EvalError(f"SCA zemin gerçeği {SCA_GT_FORMAT} biçiminde olmalı.")
    projects: dict[str, list[dict[str, Any]]] = {}
    for project, items in raw["projects"].items():
        rows = []
        for index, item in enumerate(items or []):
            try:
                rows.append({"ecosystem": sca_ecosystem(item["ecosystem"]), "package": str(item["package"]),
                             "version": str(item["version"]), "ids": [str(i).upper() for i in item.get("ids") or []],
                             "kind": str(item.get("kind", "direct")), "manifest": str(item.get("manifest", ""))})
            except (KeyError, TypeError) as exc:
                raise EvalError(f"{project}[{index}]: geçersiz SCA kaydı ({exc}).") from exc
        projects[str(project)] = rows
    return {"format": SCA_GT_FORMAT, "projects": projects}


def sca_ecosystem(value: Any) -> str:
    text = str(value or "").strip().lower()
    return _SCA_ECOSYSTEMS.get(text, text)


def sca_name(ecosystem: str, name: Any) -> str:
    text = str(name or "").strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", text).lower()
    if ecosystem in {"maven", "packagist", "crates.io", "nuget"}:
        return text.lower()
    return text


def sca_version(value: Any) -> str:
    text = str(value or "").strip()
    text = text[1:] if text[:1] in {"v", "V"} and text[1:2].isdigit() else text
    return text.split("+", 1)[0]


def sniper_sca_findings(project_path: str, allowed_root: Path) -> tuple[list[dict[str, Any]], str]:
    """Ürünün çevrimdışı bağımlılık açığı çıktısı.

    Sözleşme: ``dependency_security.offline_vulnerability_findings(project_path, allowed_roots=(...))`` →
    ``[{"ecosystem", "name", "version", "ids": [kimlik ve takma adlar]}]``. Ürün bu işlevi sağlamıyorsa
    'unsupported' döner (17. tur canlı: yalnız npm için sayı veren osv_active; paket/danışma listesi yok)."""
    import dependency_security as ds

    fn = getattr(ds, "offline_vulnerability_findings", None)
    if fn is None:
        return [], "unsupported"
    rows = []
    for item in fn(project_path, allowed_roots=(allowed_root,)) or []:
        eco = sca_ecosystem(item.get("ecosystem"))
        rows.append({"ecosystem": eco, "name": sca_name(eco, item.get("name") or item.get("package")),
                     "version": sca_version(item.get("version")),
                     "ids": sorted({str(i).upper() for i in (item.get("ids") or []) + (item.get("aliases") or [])
                                    + ([item["id"]] if item.get("id") else [])})})
    return rows, "ok"


def score_sca(gt: dict[str, Any], findings: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Paket düzeyi duyarlılık: kayıt, aynı ekosistem + ad + sürümde bir bulgu varsa bulunmuş sayılır;
    kimliklerden biri kesişirse ayrıca 'id_match'. Kesinlik hesaplanmaz (zemin gerçeği kapsamlı danışma listesi değil)."""
    found: dict[str, set[int]] = collections.defaultdict(set)
    id_match = 0
    missed: collections.Counter = collections.Counter()
    per_project = {}
    for project, records in gt["projects"].items():
        rows = findings.get(project) or []
        for index, rec in enumerate(records):
            name = sca_name(rec["ecosystem"], rec["package"])
            version = sca_version(rec["version"])
            hits = [r for r in rows if r["ecosystem"] == rec["ecosystem"] and r["name"] == name and r["version"] == version]
            if hits:
                found[project].add(index)
                if set(rec["ids"]) & {i for r in hits for i in r["ids"]}:
                    id_match += 1
            else:
                missed[rec["ecosystem"]] += 1
        per_project[project] = {"tp": len(found.get(project, ())), "total": len(records)}
    total = sum(len(v) for v in gt["projects"].values())
    tp = sum(len(v) for v in found.values())
    return {"findings": sum(len(v) for v in findings.values()), "tp": tp, "total": total, "fn": total - tp,
            "recall": round(tp / total, 4) if total else None, "id_match": id_match,
            "precision": None, "precision_lower_bound": None, "correct_findings": tp, "false_positives": 0,
            "unclassified": 0, "found": {k: sorted(v) for k, v in sorted(found.items())},
            "missed_classes": {f"sca/{k}": n for k, n in missed.most_common()}, "per_project": per_project,
            "unmatched": [], "keys": [], "by_class": {}}


def is_iac_finding(finding: dict[str, Any]) -> bool:
    """Altyapı-kod (Terraform/Kubernetes/Helm/Dockerfile/compose) yanlış yapılandırma bulgusu mu?"""
    if str(finding.get("category", "")).lower() in IAC_CATEGORIES:
        return True
    rule = str(finding.get("rule_id") or finding.get("check_id") or finding.get("id") or "")
    return rule.startswith(IAC_RULE_PREFIXES)


def sniper_items(project: str, findings: list[dict[str, Any]], *, verified_only: bool) -> list[tuple]:
    rows = []
    for finding in findings:
        if finding.get("privileged"):
            continue  # yetkili bağlam notu (yönetici yetkisi gerekli): ölçüm ve kesinlik hesabına girmez
        if verified_only and not is_verified_flow(finding):
            continue
        if not verified_only and is_iac_finding(finding):
            rows.append((project, str(finding.get("file", "")), finding.get("line"), frozenset({"iac"}),
                         str(finding.get("title", ""))))
            continue
        classes = sniper_classes(finding.get("reference"))
        if len(classes) > 1:
            flow = finding.get("taint_flow")
            sink = str(flow.get("sink_kind") or "").casefold() if isinstance(flow, dict) else ""
            exact = _MULTI_CLASS_SINK_CLASSES.get(sink)
            if exact in classes:
                classes = frozenset({exact})
        if classes:
            rows.append((project, str(finding.get("file", "")), finding.get("line"), classes, str(finding.get("title", ""))))
    return rows


def codeql_items(sarif_dir: str | Path, projects: Iterable[str] | None = None) -> list[tuple]:
    """``<proje>-<dil>.sarif`` dosyalarından sınıflı CodeQL sonuçları."""
    wanted = set(projects) if projects is not None else None
    rows = []
    for sarif in sorted(glob.glob(str(Path(sarif_dir) / "*.sarif"))):
        project = os.path.basename(sarif)[: -len(".sarif")].rsplit("-", 1)[0]
        if wanted is not None and project not in wanted:
            continue
        try:
            text = read_text_bounded(sarif, MAX_CODEQL_SARIF_BYTES, errors="strict")
            if text is None:
                continue
            data = json.loads(text)
        except (OSError, UnicodeDecodeError, ValueError, RecursionError):
            continue
        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule = str(result.get("ruleId", ""))
                classes = codeql_classes(rule)
                if not classes or not result.get("locations"):
                    continue
                location = result["locations"][0].get("physicalLocation", {})
                rows.append((project, location.get("artifactLocation", {}).get("uri", ""),
                             location.get("region", {}).get("startLine"), classes, rule))
    return rows


def agreement(left: list[tuple], right: list[tuple]) -> dict[str, int]:
    """Zemin gerçeği olmayan setlerde iki aracın örtüşmesi (aynı dosya + ortak sınıf + satır ±3)."""
    def overlaps(a, b):
        return a[0] == b[0] and a[1] == b[1] and a[3] & b[3] and a[2] is not None and b[2] is not None \
            and abs(a[2] - b[2]) <= LINE_SLACK
    both = sum(1 for a in left if any(overlaps(a, b) for b in right))
    only_right = sum(1 for b in right if not any(overlaps(a, b) for a in left))
    return {"both": both, "only_sniper": len(left) - both, "only_codeql": only_right}


# ---------------------------------------------------------------------------
# Geçmiş
# ---------------------------------------------------------------------------
MAX_HISTORY_FILES = 5_000
MAX_HISTORY_BYTES = 8_000_000
MAX_HISTORY_TOTAL_BYTES = 64_000_000


class HistoryPaths(list[Path]):
    def __init__(self, values=(), *, analysis_complete: bool = True, warning: str = "") -> None:
        super().__init__(values)
        self.analysis_complete = analysis_complete
        self.warning = warning

def history_dir(environ: dict[str, str] | None = None) -> Path | None:
    env = os.environ if environ is None else environ
    explicit = env.get("SNIPER_EVAL_HISTORY_DIR", "")
    if explicit:
        return Path(explicit)
    data = env.get("SNIPER_DATA_DIR", "")
    return Path(data) / "eval-history" if data else None


def _safe_label(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-.")[:40]
    return cleaned or "olcum"


def write_history(record: dict[str, Any], directory: Path, *, target: Path | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    if target is not None:
        path = Path(target)
        if path.parent != directory or path.suffix != ".json" or path.name.startswith("."):
            raise ValueError("gecersiz olcum gecmisi hedefi")
    else:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(record.get("created_epoch", time.time())))
        # Saniye duyarlikli eski ad ayni etiketli hizli iki kosuda onceki
        # regresyon temelini eziyordu. Yazma zamani+PID eki siralanabilir ve pratikte
        # benzersiz bir ad verir; tarih oneki geriye donuk liste siralamasini korur.
        nonce = f"{time.time_ns():020d}-{os.getpid()}"
        path = directory / f"{stamp}-{nonce}-{_safe_label(str(record.get('label', '')))}.json"
    tmp = path.with_name("." + path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(record, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return path


def list_history(directory: Path | None) -> HistoryPaths:
    if directory is None or not directory.is_dir() or directory.is_symlink():
        return HistoryPaths()
    found: list[Path] = []
    total_bytes = 0
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name.startswith(".") or not entry.name.endswith(".json"):
                    continue
                try:
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        continue
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                if size > MAX_HISTORY_BYTES:
                    return HistoryPaths(
                        analysis_complete=False,
                        warning=f"Ölçüm geçmişi kayıt boyutu sınırını ({MAX_HISTORY_BYTES}) aştı; "
                                "geçmiş güven notu kullanılmadı.",
                    )
                total_bytes += size
                if total_bytes > MAX_HISTORY_TOTAL_BYTES:
                    return HistoryPaths(
                        analysis_complete=False,
                        warning=f"Ölçüm geçmişi toplam boyut sınırını ({MAX_HISTORY_TOTAL_BYTES}) aştı; "
                                "geçmiş güven notu kullanılmadı.",
                    )
                found.append(Path(entry.path))
                if len(found) > MAX_HISTORY_FILES:
                    return HistoryPaths(
                        analysis_complete=False,
                        warning=f"Ölçüm geçmişi dosya sınırını ({MAX_HISTORY_FILES}) aştı; geçmiş güven notu kullanılmadı.",
                    )
    except OSError:
        return HistoryPaths()
    return HistoryPaths(sorted(found))


def read_history(path: Path) -> dict[str, Any] | None:
    fd = None
    try:
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_size > MAX_HISTORY_BYTES:
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_HISTORY_BYTES:
            chunk = os.read(fd, min(1 << 20, MAX_HISTORY_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_HISTORY_BYTES:
            return None
        data = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(data, dict) or data.get("format") != HISTORY_FORMAT:
        return None
    sets = data.get("sets")
    if sets is not None:
        if not isinstance(sets, dict):
            return None
        for name, row in sets.items():
            if not isinstance(name, str) or not isinstance(row, dict):
                return None
            verified = row.get("verified")
            projects = row.get("projects")
            codeql = row.get("codeql")
            if verified is not None and not isinstance(verified, dict):
                return None
            if projects is not None and (
                    not isinstance(projects, dict)
                    or any(not isinstance(project, str) or not isinstance(value, dict)
                           for project, value in projects.items())):
                return None
            if codeql is not None and not isinstance(codeql, dict):
                return None
            unmatched = verified.get("unmatched") if isinstance(verified, dict) else None
            if unmatched is not None and (
                    not isinstance(unmatched, list)
                    or any(not isinstance(item, dict) for item in unmatched)):
                return None
            if row.get("new_flows_vs_baseline") is not None \
                    and not isinstance(row["new_flows_vs_baseline"], list):
                return None
    class_rows = data.get("class_precision")
    if class_rows is not None and (
            not isinstance(class_rows, dict)
            or any(not isinstance(name, str) or not isinstance(row, dict)
                   for name, row in class_rows.items())):
        return None
    for key, expected in (("benchmarks", dict), ("regressions", list), ("warnings", list)):
        if data.get(key) is not None and not isinstance(data[key], expected):
            return None
    return data


def previous_record(directory: Path | None, config_name: str, exclude: Path | None = None) -> dict[str, Any] | None:
    paths = list_history(directory)
    if not paths.analysis_complete:
        return None
    eligible = [path for path in paths if exclude is None or path != exclude]
    selected = _latest_valid_history(
        eligible,
        predicate=lambda record: record.get("config_name") == config_name,
    )
    return selected[1] if selected is not None else None


def summarize(record: dict[str, Any]) -> dict[str, Any]:
    """Pano/geçmiş listesi için kısa özet (bulgu listeleri olmadan)."""
    sets = {}
    for name, data in (record.get("sets") or {}).items():
        verified = data.get("verified") or {}
        row = {"kind": data.get("kind"), "projects": len(data.get("projects") or {}),
               "verified_flows": verified.get("findings"), "seconds": data.get("seconds")}
        for key in ("tp", "total", "recall", "precision", "precision_lower_bound", "false_positives", "unclassified"):
            if key in verified:
                row[key] = verified[key]
        codeql = data.get("codeql") or {}
        if codeql:
            row["codeql"] = {k: codeql.get(k) for k in ("tp", "total", "recall", "both", "only_sniper", "only_codeql",
                                                        "unmatched_non_noisy") if k in codeql}
        if data.get("new_flows_vs_baseline") is not None:
            row["new_flows_vs_baseline"] = len(data["new_flows_vs_baseline"])
        sets[name] = row
    return {"file": record.get("file"), "created_at": record.get("created_at"), "label": record.get("label"),
            "config_name": record.get("config_name"), "engine": record.get("engine"), "sets": sets,
            "benchmarks": record.get("benchmarks") or {}, "class_precision": record.get("class_precision") or {},
            "regressions": len(record.get("regressions") or []), "warnings": len(record.get("warnings") or [])}


# ---------------------------------------------------------------------------
# Sınıf başına ölçülmüş kesinlik
# ---------------------------------------------------------------------------
def class_precision(sets: dict[str, Any]) -> dict[str, dict[str, Any]]:
    totals: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for data in sets.values():
        if not isinstance(data, dict):
            continue
        verified = data.get("verified")
        by_class = verified.get("by_class") if isinstance(verified, dict) else None
        if not isinstance(by_class, dict):
            continue
        for cls, counts in by_class.items():
            if not isinstance(cls, str) or not isinstance(counts, dict) \
                    or not ({"tp_findings", "fp", "gt_total"} & counts.keys()):
                continue
            relevant = {key: counts[key] for key in (
                "tp_findings", "fp", "unclassified", "gt_found", "gt_total",
            ) if key in counts}
            # A row is one measurement unit. Partially accepting corrupt values
            # can turn booleans or negative counters into five apparent samples.
            if any(type(value) is not int or value < 0 for value in relevant.values()) \
                    or relevant.get("gt_found", 0) > relevant.get("gt_total", 0):
                continue
            totals[cls].update(relevant)
    result = {}
    for cls, counts in sorted(totals.items()):
        judged = counts["tp_findings"] + counts["fp"]
        result[cls] = {
            "precision": round(counts["tp_findings"] / judged, 4) if judged else None,
            "judged": judged, "unclassified": counts["unclassified"],
            "recall": round(counts["gt_found"] / counts["gt_total"], 4) if counts["gt_total"] else None,
            "gt_total": counts["gt_total"],
        }
    return result


_CONFIDENCE_CACHE: dict[str, Any] = {"key": None, "value": None}
MIN_CONFIDENCE_SAMPLES = 5
MAX_CONFIDENCE_HISTORY_AGE_SECONDS = 90 * 24 * 60 * 60
def _latest_valid_history(
    paths: list[Path],
    *,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
) -> tuple[Path, dict[str, Any]] | None:
    """Select the newest valid record; same-second labels use created_epoch."""
    index = len(paths) - 1
    while index >= 0:
        match = re.match(r"^\d{8}T\d{6}", paths[index].name)
        prefix = match.group(0) if match else paths[index].name
        start = index
        while start > 0:
            previous = re.match(r"^\d{8}T\d{6}", paths[start - 1].name)
            previous_prefix = previous.group(0) if previous else paths[start - 1].name
            if previous_prefix != prefix:
                break
            start -= 1
        candidates: list[tuple[tuple[float, int, str], Path, dict[str, Any]]] = []
        for path in paths[start:index + 1]:
            record = read_history(path)
            if record is None or (predicate is not None and not predicate(record)):
                continue
            epoch = record.get("created_epoch")
            precise = not isinstance(epoch, bool) and isinstance(epoch, (int, float)) and math.isfinite(float(epoch))
            try:
                mtime = path.stat().st_mtime_ns
            except OSError:
                mtime = -1
            candidates.append(((float(epoch) if precise else float("-inf"), mtime, path.name), path, record))
        if candidates:
            _order, path, record = max(candidates, key=lambda item: item[0])
            return path, record
        index = start - 1
    return None


def latest_class_precision(environ: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Son ölçümün sınıf kesinlikleri (dosya değişmedikçe önbellekten)."""
    paths = list_history(history_dir(environ))
    if not paths or not paths.analysis_complete:
        return None
    selected = _latest_valid_history(paths)
    if selected is None:
        return None
    latest, _selected_record = selected
    # Kayit, secim sirasindaki okuma ile stat arasinda atomik olarak degisebilir.
    # Eski icerigi yeni inode/ctime anahtarina baglamak kalici bir bayat cache
    # olusturur. Ayni kimlik oncesi/sonrasi gorulene kadar sinirli yeniden oku.
    record = None
    key = None
    for _attempt in range(3):
        try:
            before = latest.stat()
            before_key = (str(latest), before.st_dev, before.st_ino, before.st_size,
                          before.st_mtime_ns, before.st_ctime_ns)
            fresh = read_history(latest)
            after = latest.stat()
            after_key = (str(latest), after.st_dev, after.st_ino, after.st_size,
                         after.st_mtime_ns, after.st_ctime_ns)
        except OSError:
            return None
        if fresh is not None and before_key == after_key:
            record, key = fresh, after_key
            break
    if record is None or key is None:
        return None
    # Anahtar ve değeri tek bir anlık görüntüden oku. Başka bir proje iki satır
    # arasında global önbelleği değiştirse bile bu çağrı onun değerini döndürmez.
    cached = _CONFIDENCE_CACHE.copy()
    if cached.get("key") != key:
        value = None
        value = {"label": record.get("label"), "created_at": record.get("created_at"),
                 "classes": record.get("class_precision") or {}}
        # Eski kayıtlar created_epoch taşımayabilir. Yeni biçimde zaman damgasını
        # güven notunun yaş sınırını uygulamak için koru. Tarih metni olmayan eski
        # fixture/kayıtları geriye dönük biçimde yaşsız kabul et.
        created_at = record.get("created_at")
        created_epoch = record.get("created_epoch")
        if isinstance(created_at, str) and re.match(r"^\d{4}-\d\d-\d\dT", created_at) \
                and not isinstance(created_epoch, bool) and isinstance(created_epoch, (int, float)):
            value["created_epoch"] = created_epoch
        _CONFIDENCE_CACHE.update(key=key, value=value)
        return value
    return cached.get("value")


def annotate_confidence(findings: list[dict[str, Any]], environ: dict[str, str] | None = None) -> None:
    """Doğrulanmış akış bulgularına sınıfın ölçülmüş kesinliğini ekle (yeterli örnek varsa)."""
    latest = latest_class_precision(environ)
    if latest and "created_epoch" in latest:
        created_epoch = latest.get("created_epoch")
        if isinstance(created_epoch, bool) or not isinstance(created_epoch, (int, float)) \
                or not math.isfinite(float(created_epoch)) \
                or not -86_400 <= time.time() - float(created_epoch) <= MAX_CONFIDENCE_HISTORY_AGE_SECONDS:
            latest = None
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        existing = finding.get("confidence")
        if isinstance(existing, dict) and "measured_precision" in existing:
            for key in ("class", "measured_precision", "samples", "basis", "note"):
                existing.pop(key, None)
            if not existing:
                finding.pop("confidence", None)
        if not is_verified_flow(finding):
            continue
        if not latest or not isinstance(latest.get("classes"), dict):
            continue
        classes = sniper_classes(finding.get("reference"))
        if len(classes) > 1:
            flow = finding.get("taint_flow")
            sink = str(flow.get("sink_kind") or "").casefold() if isinstance(flow, dict) else ""
            exact = _MULTI_CLASS_SINK_CLASSES.get(sink)
            # Some CWE references intentionally map to more than one evaluation
            # class.  Without the producer's sink identity, selecting the first
            # alphabetic class would attach an unrelated precision measurement.
            classes = frozenset({exact}) if exact in classes else frozenset()
        for cls in sorted(classes):
            row = latest["classes"].get(cls)
            if not isinstance(row, dict):
                continue
            precision, judged = row.get("precision"), row.get("judged")
            if isinstance(precision, bool) or not isinstance(precision, (int, float)) or not 0 <= precision <= 1 \
                    or type(judged) is not int or judged < MIN_CONFIDENCE_SAMPLES:
                continue
            percent = round(precision * 100)
            confidence = finding.get("confidence")
            if not isinstance(confidence, dict):
                confidence = {}
                finding["confidence"] = confidence
            confidence.update({
                "class": cls, "measured_precision": precision, "samples": judged,
                "basis": f"ölçüm {latest.get('label') or ''} ({latest.get('created_at') or ''})".strip(),
                "note": f"Bu sınıfın ölçülmüş kesinliği %{percent} ({judged} değerlendirilmiş bulgu).",
            })
            break


_CORROBORATION_CATEGORY_CLASSES = {
    "data_query": {"sql", "nosql"}, "data-query": {"sql", "nosql"}, "sql-injection": {"sql"}, "sql": {"sql"},
    "command_data": {"cmd"}, "command-data": {"cmd"}, "command-injection": {"cmd"},
    "os-command-injection": {"cmd"}, "command": {"cmd"},
    "cross-site-scripting": {"xss"}, "xss": {"xss"}, "deserialization": {"deser"},
    "path-traversal": {"path"}, "file-path-traversal": {"path"}, "directory-traversal": {"path"},
    "arbitrary-file-read": {"path"}, "path": {"path"},
    "ssrf": {"ssrf"}, "server-side-request-forgery": {"ssrf"},
    "redirect": {"redirect"}, "open-redirect": {"redirect"}, "url-redirection": {"redirect"},
    "unvalidated-redirect": {"redirect"},
    "code": {"code"}, "eval": {"code"}, "code-injection": {"code"},
    "ssti": {"ssti"}, "template-injection": {"ssti"}, "server-side-template-injection": {"ssti"},
    "template_object": {"ssti"}, "template-object": {"ssti"}, "template-object-injection": {"ssti"},
    "nosql-injection": {"nosql"},
    "xxe": {"xxe"}, "xml-external-entity": {"xxe"},
    "xpath": {"xpath"}, "xpath-injection": {"xpath"},
    "ldap": {"ldap"}, "ldap-injection": {"ldap"},
    "memory_safety": {"mem"}, "memory-safety": {"mem"}, "format-string": {"fmt"},
}


def _finding_location(finding: dict[str, Any]) -> tuple[str, int] | None:
    path = str(finding.get("file") or finding.get("path") or "").replace("\\", "/")
    if len(path) > MAX_CORROBORATION_PATH or any(ord(char) < 32 for char in path):
        return None
    while path.startswith("./"):
        path = path[2:]
    line = finding.get("line")
    parts = path.split("/")
    if not path or path.startswith("/") or re.match(r"^[A-Za-z]:/", path) or any(part == ".." for part in parts) \
            or isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    normalized = "/".join(part for part in parts if part not in {"", "."})
    return (normalized, line) if normalized else None


def _finding_classes(finding: dict[str, Any]) -> set[str]:
    values: list[Any] = []
    for raw in (finding.get("reference"), finding.get("cwe")):
        for value in (raw if isinstance(raw, (list, tuple, set)) else (raw,)):
            if len(values) >= MAX_CORROBORATION_CLASSES:
                break
            values.append(value)
        if len(values) >= MAX_CORROBORATION_CLASSES:
            break
    classes = set().union(*(sniper_classes(value) for value in values))
    flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else {}
    raw_kind = str(flow.get("sink_kind") or "")
    raw_category = str(finding.get("category") or "")
    kind = raw_kind.casefold() if len(raw_kind) <= MAX_CORROBORATION_LABEL else ""
    category = re.sub(r"[\s_]+", "-", raw_category.strip().casefold()) \
        if len(raw_category) <= MAX_CORROBORATION_LABEL else ""
    hints: set[str] = set()
    if kind:
        exact = _MULTI_CLASS_SINK_CLASSES.get(kind)
        hints |= {exact} if exact else _CORROBORATION_CATEGORY_CLASSES.get(
            kind, {kind} if kind in CLASSES else set()
        )
    hints |= _CORROBORATION_CATEGORY_CLASSES.get(category, set())
    if len(classes) > 1:
        compatible = classes & hints
        if len(compatible) == 1 and len(hints) == 1:
            return compatible
    if not classes:
        classes |= hints
    return classes


def _same_finding(left: dict[str, Any], right: dict[str, Any]) -> bool:
    loc_left, loc_right = _finding_location(left), _finding_location(right)
    if not loc_left or not loc_right or loc_left[0] != loc_right[0] \
            or abs(loc_left[1] - loc_right[1]) > LINE_SLACK:
        return False
    left_classes, right_classes = _finding_classes(left), _finding_classes(right)
    return bool(left_classes and right_classes and left_classes & right_classes)


def _bounded_corroboration_rows(rows: Any) -> tuple[list[dict[str, Any]], bool]:
    """Materialize external engine evidence with an explicit item budget."""
    selected: list[dict[str, Any]] = []
    try:
        for index, row in enumerate(rows):
            if index >= MAX_CORROBORATION_EVIDENCE:
                return selected, True
            if isinstance(row, dict):
                selected.append(row)
    except Exception:
        # Evidence can come from optional external parser adapters. Preserve
        # already validated rows but make the partial input explicit.
        return selected, True
    return selected, False


def _corroboration_index(rows: Iterable[dict[str, Any]]) -> set[tuple[str, str, int]]:
    index: set[tuple[str, str, int]] = set()
    for row in rows:
        location = _finding_location(row)
        if location is None:
            continue
        path, line = location
        for cls in _finding_classes(row):
            index.add((path, cls, line))
    return index


def _index_matches_finding(index: set[tuple[str, str, int]], finding: dict[str, Any]) -> bool:
    location = _finding_location(finding)
    classes = _finding_classes(finding)
    if location is None or not classes:
        return False
    path, line = location
    return any((path, cls, candidate_line) in index
               for cls in classes
               for candidate_line in range(max(1, line - LINE_SLACK), line + LINE_SLACK + 1))


def _confirmed_runtime_proof(value: Any) -> tuple[bool, bool]:
    """Return (confirmed, limited) for the stored JSON proof array."""
    if not isinstance(value, list):
        return False, False
    limited = len(value) > MAX_CORROBORATION_EVIDENCE
    for index, proof in enumerate(value):
        if index >= MAX_CORROBORATION_EVIDENCE:
            break
        if isinstance(proof, dict) and proof.get("verdict") == "confirmed":
            return True, limited
    return False, limited


def annotate_corroboration(
    findings: list[dict[str, Any]], *, semgrep_findings: Iterable[dict[str, Any]] = (),
    joern_findings: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Aynı sınıf ve konumdaki bağımsız motor kanıtlarını bulguya toplu olarak ekle.

    Kaynak satır, rapor mesajı veya çalışma zamanı gövdesi kopyalanmaz. Satır eşleşmesi ölçüm hattıyla aynı ±3
    toleransı kullanır; sınıfı bilinmeyen ya da farklı olan kayıtlar yalnız konuma bakılarak eşleştirilmez.
    """
    semgrep, semgrep_limited = _bounded_corroboration_rows(semgrep_findings)
    joern, joern_limited = _bounded_corroboration_rows(joern_findings)
    semgrep_index = _corroboration_index(semgrep)
    joern_index = _corroboration_index(joern)
    corroborated = strong = 0
    analyzed_findings = 0
    runtime_limited = False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        analyzed_findings += 1
        if _finding_location(finding) is None or not _finding_classes(finding):
            finding.pop("corroboration", None)
            continue
        control = str(finding.get("control_id") or "")
        declared_engine = str(finding.get("engine") or "").strip().casefold()
        primary_engine = declared_engine if declared_engine in {"sniper", "semgrep", "joern", "runtime"} \
            else ("joern" if control.startswith("SNIPER-JOERN-") else "sniper")
        engines = {primary_engine}
        if primary_engine == "joern" and (
                finding.get("fast_engine_match") is True
                or finding.get("also_in_project_analysis") is True):
            engines.add("sniper")
        # Producer-supplied semgrep_match/corroborating_engines labels are
        # claims rather than evidence. Semgrep and Joern count only when the
        # corresponding bounded external row matches below.
        runtime_confirmed, finding_runtime_limited = _confirmed_runtime_proof(finding.get("runtime_proofs"))
        runtime_limited = runtime_limited or finding_runtime_limited
        if runtime_confirmed:
            engines.add("runtime")
        if _index_matches_finding(semgrep_index, finding):
            engines.add("semgrep")
        if _index_matches_finding(joern_index, finding):
            engines.add("joern")
        if len(engines) < 2:
            finding.pop("corroboration", None)
            continue
        strength = "strong" if len(engines) >= 3 or "runtime" in engines else "corroborated"
        finding["corroboration"] = {
            "engines": sorted(engines), "independent_engine_count": len(engines), "strength": strength,
            "note": f"Aynı bulgu {len(engines)} bağımsız kanıt kaynağıyla doğrulandı.",
        }
        corroborated += 1
        strong += strength == "strong"
    summary: dict[str, Any] = {"findings": analyzed_findings, "corroborated": corroborated, "strong": strong}
    limited_inputs = ((["semgrep"] if semgrep_limited else [])
                      + (["joern"] if joern_limited else [])
                      + (["runtime"] if runtime_limited else []))
    if limited_inputs:
        summary["limited_inputs"] = limited_inputs
    return summary


def annotate_rule_feedback(findings: list[dict[str, Any]], rules: Iterable[dict[str, Any]], *,
                           min_samples: int = MIN_CONFIDENCE_SAMPLES) -> None:
    """Kullanıcı triyajından ölçülen kural kesinliğini, yeterli örnek varsa bulgulara ekle."""
    threshold = (min_samples if type(min_samples) is int and min_samples >= MIN_CONFIDENCE_SAMPLES
                 else MIN_CONFIDENCE_SAMPLES)
    # Every call replaces the previous snapshot. Clear stale annotations even
    # when the new input is malformed or exceeds its explicit work budget.
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        existing = finding.get("confidence")
        if isinstance(existing, dict) and "rule_feedback" in existing:
            existing.pop("rule_feedback", None)
            if not existing:
                finding.pop("confidence", None)
    bounded_rules: list[dict[str, Any]] = []
    try:
        for index, row in enumerate(rules):
            if index >= MAX_RULE_FEEDBACK_ROWS:
                return
            if isinstance(row, dict):
                bounded_rules.append(row)
    except Exception:
        # Optional feedback adapters may fail during iteration. A partial
        # snapshot must not restore a stale or order-dependent confidence note.
        return
    by_rule: dict[tuple[str, str, str], dict[str, Any]] = {}
    ambiguous: set[tuple[str, str, str]] = set()
    for row in bounded_rules:
        if type(row.get("reviewed")) is not int or row["reviewed"] < threshold:
            continue
        rate = row.get("false_positive_rate")
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0 <= float(rate) <= 1:
            continue
        counter_keys = ("false_positive", "confirmed", "accepted_risk")
        if any(key in row for key in counter_keys):
            counters = [row.get(key) for key in counter_keys]
            if any(type(value) is not int or value < 0 for value in counters) \
                    or sum(counters) != row["reviewed"] \
                    or round(counters[0] / row["reviewed"], 4) != round(float(rate), 4):
                continue
        reference, rule = row.get("reference"), row.get("rule")
        if not isinstance(reference, str) or not isinstance(rule, str):
            continue
        reference_classes = sniper_classes(reference)
        scope = ""
        if len(reference_classes) > 1:
            row_class = row.get("class")
            if not isinstance(row_class, str) or row_class.strip().casefold() not in reference_classes:
                # Historical aggregates without a sink class may combine
                # unrelated outcomes for a multi-class CWE.  They cannot be
                # applied safely to either class.
                continue
            scope = row_class.strip().casefold()
        key = (reference.strip().casefold(), rule.strip().casefold(), scope)
        if not all(key[:2]):
            continue
        normalized = {"reviewed": row["reviewed"], "false_positive_rate": float(rate)}
        previous = by_rule.get(key)
        if key in ambiguous:
            continue
        if previous is not None and previous != normalized:
            # There is no snapshot identity with which to order contradictory
            # aggregates. Suppress the note instead of selecting by input order.
            by_rule.pop(key, None)
            ambiguous.add(key)
            continue
        by_rule[key] = normalized
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        reference, title = finding.get("reference"), finding.get("title")
        if not isinstance(reference, str) or not isinstance(title, str):
            continue
        reference_classes = sniper_classes(reference)
        scope = ""
        if len(reference_classes) > 1:
            exact_classes = _finding_classes(finding)
            if len(exact_classes) != 1:
                continue
            scope = next(iter(exact_classes))
            if scope not in reference_classes:
                continue
        key = (reference.strip().casefold(), _rule_title(title).strip().casefold(), scope)
        if not all(key[:2]):
            continue
        row = by_rule.get(key)
        if row is None:
            continue
        confidence = finding.get("confidence")
        if not isinstance(confidence, dict):
            confidence = {}
            finding["confidence"] = confidence
        confidence["rule_feedback"] = {
            "samples": int(row["reviewed"]), "false_positive_rate": float(row["false_positive_rate"]),
            "user_precision": round(1.0 - float(row["false_positive_rate"]), 4),
            "basis": "kullanıcı triyaj kararları",
        }


# ---------------------------------------------------------------------------
# Regresyon
# ---------------------------------------------------------------------------
def compare_records(current: dict[str, Any], previous: dict[str, Any] | None, *,
                    slowdown_ratio: float = 1.5, slowdown_min_seconds: float = 2.0) -> tuple[list[dict], list[dict]]:
    """(regresyonlar, uyarılar). Regresyon: TP kaybı, yeni sınıflandırılmamış/yanlış bulgu, olgun projede yeni
    akış, kaybolan akış (zemin gerçeği olmayan sette), analiz hatası, kıyas puanı düşüşü. Uyarı: yavaşlama, yeni akış."""
    regressions: list[dict] = []
    warnings: list[dict] = []
    for name, data in (current.get("sets") or {}).items():
        for project, row in (data.get("projects") or {}).items():
            if row.get("error"):
                regressions.append({"set": name, "project": project, "type": "analysis_error", "detail": row["error"]})
        for project in data.get("new_flows_vs_baseline") or []:
            regressions.append({"set": name, "type": "benign_new_flow", "detail": project})
    if previous is None:
        return regressions, warnings
    for name, data in (current.get("sets") or {}).items():
        old = (previous.get("sets") or {}).get(name)
        if not old:
            continue
        cur_v, old_v = data.get("verified") or {}, old.get("verified") or {}
        if "found" in cur_v and "found" in old_v:
            for project, indexes in old_v["found"].items():
                lost = sorted(set(indexes) - set(cur_v["found"].get(project, [])))
                if lost:
                    regressions.append({"set": name, "project": project, "type": "tp_lost", "detail": lost})
            old_unmatched = {row["key"] for row in old_v.get("unmatched", [])}
            for row in cur_v.get("unmatched", []):
                if row["key"] not in old_unmatched and row["verdict"] != "true_positive":
                    regressions.append({"set": name, "project": row["project"], "type": "new_unmatched_finding",
                                        "detail": row["key"], "verdict": row["verdict"]})
        elif data.get("kind") == "benign":
            new = sorted(set(cur_v.get("keys", [])) - set(old_v.get("keys", [])))
            for key in new:
                regressions.append({"set": name, "type": "benign_new_flow", "detail": key})
        else:
            lost = sorted(set(old_v.get("keys", [])) - set(cur_v.get("keys", [])))
            new = sorted(set(cur_v.get("keys", [])) - set(old_v.get("keys", [])))
            for key in lost:
                regressions.append({"set": name, "type": "flow_lost", "detail": key})
            for key in new:
                warnings.append({"set": name, "type": "flow_new", "detail": key})
        for project, row in (data.get("projects") or {}).items():
            before = ((old.get("projects") or {}).get(project) or {}).get("seconds")
            now = row.get("seconds")
            if isinstance(before, (int, float)) and isinstance(now, (int, float)) \
                    and now > before * slowdown_ratio and now - before >= slowdown_min_seconds:
                warnings.append({"set": name, "project": project, "type": "slowdown", "detail": f"{before}s → {now}s"})
    for name, value in (current.get("benchmarks") or {}).items():
        before = (previous.get("benchmarks") or {}).get(name)
        if isinstance(value, dict) and isinstance(before, dict):
            for key in ("score", "correct"):
                if isinstance(value.get(key), (int, float)) and isinstance(before.get(key), (int, float)) \
                        and value[key] < before[key] - 1e-6:
                    regressions.append({"benchmark": name, "type": "benchmark_drop", "detail": f"{key} {before[key]} → {value[key]}"})
    return regressions, warnings


# ---------------------------------------------------------------------------
# Triyaj: kural bazlı yanlış alarm oranı (salt okunur)
# ---------------------------------------------------------------------------
MAX_TRIAGE_DECISIONS = 100_000
MAX_TRIAGE_JSON_BYTES = 64_000_000


def triage_rule_stats(db_path: str | Path, *, limit_audits: int = 500) -> dict[str, Any]:
    """Kullanıcı triyaj kararlarından kural (referans + başlık) başına yanlış alarm oranı.

    Veritabanı salt okunur açılır; kural ayarı değiştirilmez. Bulgu metinleri (kanıt) döndürülmez."""
    import sqlite3

    empty = {"rules": [], "reviewed": 0, "audits": 0}

    def limited(reason: str) -> dict[str, Any]:
        return {**empty, "limited": True, "warnings": [reason]}

    if type(limit_audits) is not int or not 1 <= limit_audits <= 5_000:
        return empty
    try:
        path = Path(db_path)
        if not path.is_file():
            return empty
    except (OSError, TypeError, ValueError):
        return empty
    con = None
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=0.25)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        # Pin the size preflight, audit documents, and triage decisions to one
        # read snapshot. Otherwise a concurrent audit insert can move the
        # LIMIT window between queries and bypass the preflighted input set.
        con.execute("BEGIN")
        names = {row[0] for row in con.execute("select name from sqlite_master where type='table'")}
        if not {"project_audit_finding_triage", "project_audits"} <= names:
            return empty
        recent = list(con.execute(
            "SELECT id, length(CAST(findings_json AS BLOB)) AS json_bytes FROM project_audits "
            "ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit_audits,)))
        total_json = sum(max(0, int(row["json_bytes"] or 0)) for row in recent)
        if total_json > MAX_TRIAGE_JSON_BYTES:
            return limited(
                f"Triyaj bulgu verisi {MAX_TRIAGE_JSON_BYTES} bayt sınırını aştı; kural güven notu kullanılmadı.")
        ids = [str(row["id"]) for row in recent]
        audit_json = {
            str(row["id"]): row["findings_json"] or "[]"
            for row in con.execute(
                "SELECT p.id, p.findings_json FROM project_audits AS p "
                "JOIN (SELECT id FROM project_audits ORDER BY created_at DESC, rowid DESC LIMIT ?) AS recent "
                "ON recent.id = p.id",
                (limit_audits,),
            )
        }
        triage = collections.defaultdict(dict)
        audits_with_triage: set[str] = set()
        ambiguous_triage: set[tuple[str, int]] = set()
        rows = list(con.execute(
            "SELECT t.audit_id, t.finding_index, t.disposition FROM project_audit_finding_triage AS t "
            "JOIN (SELECT id FROM project_audits ORDER BY created_at DESC, rowid DESC LIMIT ?) AS recent "
            "ON recent.id = t.audit_id LIMIT ?",
            (limit_audits, MAX_TRIAGE_DECISIONS + 1),
        ))
        if len(rows) > MAX_TRIAGE_DECISIONS:
            return limited(
                f"Triyaj kararı sayısı {MAX_TRIAGE_DECISIONS} sınırını aştı; kural güven notu kullanılmadı.")
        for row in rows:
            index, disposition = row["finding_index"], row["disposition"]
            if type(index) is int and index >= 0 and disposition in {
                    "false_positive", "confirmed", "accepted_risk", "needs_review"}:
                audit_id = str(row["audit_id"])
                audits_with_triage.add(audit_id)
                key = (audit_id, index)
                if key in ambiguous_triage:
                    continue
                previous = triage[audit_id].get(index)
                if previous is not None and previous != disposition:
                    triage[audit_id].pop(index, None)
                    ambiguous_triage.add(key)
                    continue
                triage[audit_id][index] = disposition
        stats: dict[tuple[str, str, str], collections.Counter] = collections.defaultdict(collections.Counter)
        display_identities: dict[tuple[str, str, str], tuple[str, str, str]] = {}
        audits = 0
        for audit_id in ids:
            if audit_id not in audits_with_triage:
                continue
            decisions = triage.get(audit_id, {})
            audits += 1
            try:
                findings = json.loads(audit_json.get(audit_id, "[]"))
            except (ValueError, RecursionError):
                continue
            if not isinstance(findings, list):
                continue
            for index, disposition in decisions.items():
                if not 0 <= index < len(findings) or disposition == "needs_review":
                    continue
                finding = findings[index]
                if not isinstance(finding, dict):
                    continue
                reference, title = finding.get("reference"), finding.get("title")
                if not isinstance(reference, str) or not isinstance(title, str):
                    continue
                reference_classes = sniper_classes(reference)
                scope = ""
                if len(reference_classes) > 1:
                    exact_classes = _finding_classes(finding)
                    if len(exact_classes) != 1:
                        continue
                    scope = next(iter(exact_classes))
                    if scope not in reference_classes:
                        continue
                display_key = (reference.strip(), _rule_title(title).strip(), scope)
                key = tuple(value.casefold() for value in display_key)
                if not all(key[:2]):
                    continue
                # Match annotate_rule_feedback's identity rules before applying
                # the sample threshold.  Otherwise harmless casing differences
                # split one rule into several undersized aggregates.
                display_identities[key] = min(display_identities.get(key, display_key), display_key)
                stats[key][disposition] += 1
    except (sqlite3.Error, OSError, TypeError, ValueError, KeyError, IndexError, AttributeError):
        return empty
    finally:
        if con is not None:
            con.close()
    rules = []
    for key, counts in stats.items():
        reference, title, scope = display_identities[key]
        reviewed = counts["false_positive"] + counts["confirmed"] + counts["accepted_risk"]
        row = {"reference": reference, "rule": title, "reviewed": reviewed,
               "false_positive": counts["false_positive"], "confirmed": counts["confirmed"],
               "accepted_risk": counts["accepted_risk"],
               "false_positive_rate": round(counts["false_positive"] / reviewed, 4) if reviewed else None}
        if scope:
            row["class"] = scope
        rules.append(row)
    rules.sort(key=lambda r: (-(r["false_positive_rate"] or 0), -r["reviewed"], r["reference"]))
    return {"rules": rules, "reviewed": sum(r["reviewed"] for r in rules), "audits": audits}


def _rule_title(title: str) -> str:
    """Başlıktan kural adı (dosyaya/değere özgü kuyruk olmadan, sınırlı uzunluk)."""
    return title.split(" — ")[0][:120]
