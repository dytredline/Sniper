"""Düzeltme doğrulama ve toplu düzeltme (kullanıcının projesine yazılmaz).

Önerilen yama (taint_autofix) proje ağacının geçici bir kopyasına uygulanır ve aynı motorla
yeniden analiz edilir:

* hedef bulgu kayboldu mu (satır kaymasına dayanıklı eşleme: kategori + CWE + başlık + dosya,
  satırlar ``difflib`` eşlemesiyle yamalı dosyaya taşınır),
* yeni bulgu doğdu mu (aynı eşleme; düşük önemliler yalnız not),
* yamalı dosya hâlâ ayrıştırılabiliyor mu (Python ``ast``, JS Babel köprüsü ya da temel
  parantez dengesi denetimi).

Sonuç: ``verified`` (doğrulandı) / ``partial`` (kısmen) / ``failed`` (başarısız) + gerekçeler ve
indirilebilir birleşik fark (.patch). Geçici dizin 0700 açılır ve iş bitince silinir.

Toplu düzeltme: aynı kalıptaki (aynı hedef türü + CWE + havuz API'si) bulgular için yamalar sırayla
aynı metne uygulanır (her adımda satırlar yeniden eşlenir) ve tek doğrulama turu yapılır.
"""

from __future__ import annotations

import ast
import dataclasses
import difflib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import threading
import time
from typing import Any, Callable

import scan_scope
import taint_autofix as ta
from taint_autofix import AutofixError

FORMAT = "sniper-fix-verification-v1"
VERDICT_LABELS = {"verified": "doğrulandı", "partial": "kısmen", "failed": "başarısız"}
SCOPE_NOTE = ("Doğrulama güvenlik bulgusu ve sözdizimi içindir; işlevsel davranış (uygulamanın kendi testleri) "
              "denetlenmez. Yamayı uygulamadan önce gözden geçirip testlerinizi çalıştırın.")
# Kopyalanan bağlam sınırları: aşılırsa kopya kısmi kalır (iki analiz de aynı kopyada yapıldığından
# karşılaştırma tutarlıdır; sonuçta "bağlam sınırlı" notu verilir).
MAX_CONTEXT_FILES = 6_000
MAX_CONTEXT_BYTES = 80_000_000
MAX_BULK_FINDINGS = 50
# Düşük önemli yeni bulgular (ör. düzeltmenin eklediği subprocess içe aktarımı) sonucu düşürmez, not olur.
_BLOCKING_SEVERITIES = {"critical", "high", "medium"}
# Koruma (guard) ekleyen stratejiler: realpath+commonpath, ana makine allowlist'i, göreli yönlendirme.
# Analiz motoru bu korumaları her zaman arındırıcı saymaz; bulgu kalırsa sonuç "kısmen" + elle gözden geçirme.
GUARD_KINDS = frozenset({"path", "ssrf", "redirect"})
_JS_SUFFIX_RE = re.compile(r"\.(?:[cm]?[jt]sx?)$")
_SLOTS = threading.BoundedSemaphore(2)


class VerificationBusy(AutofixError):
    """Aynı anda çok fazla doğrulama çalışıyor."""


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------


def _audit_scope(audit: dict[str, Any]) -> scan_scope.ScanScope:
    """Analizin kapsamı (dahil edilen dizinler, sınırlar); ek tarama modları (yalnız atlananlar/değişenler) kapatılır."""
    raw = audit.get("scope")
    if not isinstance(raw, dict):
        return scan_scope.current()
    cleaned = {key: value for key, value in raw.items()
               if key in {"include_dirs", "include_generated", "include_non_utf8", "max_file_mb", "max_total_mb", "max_files"}}
    try:
        scope = scan_scope.parse_scope(cleaned)
    except scan_scope.ScopeError:
        scope = scan_scope.DEFAULT_SCOPE
    return dataclasses.replace(scope, skipped_only=False) if scope.skipped_only else scope


def _norm_title(value: Any) -> str:
    return re.sub(r"\d+", "#", str(value or "")).strip()


def finding_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    """Satır numarası içermeyen eşleme anahtarı."""
    return (str(finding.get("file") or ""), str(finding.get("category") or ""),
            str(finding.get("reference") or ""), _norm_title(finding.get("title")))


def _line(finding: dict[str, Any]) -> int:
    try:
        return max(0, int(finding.get("line") or 0))
    except (TypeError, ValueError):
        return 0


def line_map(old: str, new: str) -> Callable[[int], tuple[int, int]]:
    """Eski dosyadaki 1 tabanlı satırı yeni dosyadaki (en düşük, en yüksek) aralığa eşler."""
    ops = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False).get_opcodes()

    def mapped(line: int) -> tuple[int, int]:
        index = line - 1
        for tag, i1, i2, j1, j2 in ops:
            if i1 <= index < i2:
                if tag == "equal":
                    target = j1 + (index - i1) + 1
                    return target, target
                return j1 + 1, max(j1 + 1, j2)
        return line, line

    return mapped


def _identity(line: int) -> tuple[int, int]:
    return line, line


def match_findings(before: list[dict[str, Any]], after: list[dict[str, Any]],
                   maps: dict[str, Callable[[int], tuple[int, int]]]) -> tuple[dict[int, int], list[int], list[int]]:
    """(önce→sonra eşleşmeleri, yalnız sonradakiler [yeni], yalnız öncekiler [kaybolan])."""
    by_key: dict[tuple[str, str, str, str], list[int]] = {}
    for index, finding in enumerate(after):
        by_key.setdefault(finding_key(finding), []).append(index)
    matched: dict[int, int] = {}
    used: set[int] = set()
    for b_index, finding in enumerate(before):
        candidates = [a for a in by_key.get(finding_key(finding), []) if a not in used]
        if not candidates:
            continue
        line = _line(finding)
        if line == 0:
            pick = next((a for a in candidates if _line(after[a]) == 0), None)
        else:
            low, high = maps.get(str(finding.get("file") or ""), _identity)(line)
            near = [a for a in candidates if low - 2 <= _line(after[a]) <= high + 2]
            pick = min(near, key=lambda a: min(abs(_line(after[a]) - low), abs(_line(after[a]) - high))) if near else None
        if pick is not None:
            matched[b_index] = pick
            used.add(pick)
    new = [index for index in range(len(after)) if index not in used]
    gone = [index for index in range(len(before)) if index not in matched]
    return matched, new, gone


def _locate_target(baseline: list[dict[str, Any]], finding: dict[str, Any], kind: str, line: int) -> int | None:
    """Kayıtlı bulgunun güncel kopyadaki karşılığı (aynı anahtar, en yakın satır; yoksa aynı dosya + tür)."""
    key = finding_key(finding)
    exact = [i for i, item in enumerate(baseline) if finding_key(item) == key and abs(_line(item) - line) <= 3]
    if exact:
        return min(exact, key=lambda i: abs(_line(baseline[i]) - line))
    loose = [i for i, item in enumerate(baseline)
             if str(item.get("file") or "") == key[0] and ta.finding_kind(item) == kind and abs(_line(item) - line) <= 3]
    return min(loose, key=lambda i: abs(_line(baseline[i]) - line)) if loose else None


def _bracket_delta(text: str) -> tuple[int, int, int]:
    return text.count("(") - text.count(")"), text.count("[") - text.count("]"), text.count("{") - text.count("}")


def parse_check(relpath: str, old: str, new: str) -> dict[str, Any]:
    """Yamalı dosya ayrıştırılabiliyor mu? {ok: True/False/None, checker, detail}."""
    if relpath.endswith(".py"):
        try:
            ast.parse(new)
        except SyntaxError as exc:
            return {"ok": False, "checker": "python-ast", "detail": f"Python sözdizimi hatası (satır {exc.lineno})."}
        return {"ok": True, "checker": "python-ast", "detail": ""}
    if _JS_SUFFIX_RE.search(relpath):
        # Babel köprüsü eksik kapanış parantezini bir kez tamamlayarak dener; dengeyi ayrıca karşılaştır.
        if _bracket_delta(new) != _bracket_delta(old):
            return {"ok": False, "checker": "parantez-dengesi", "detail": "Yama parantez dengesini bozuyor."}
        try:
            import taint_js_ast

            if taint_js_ast.available():
                parsed = taint_js_ast.parse_files({relpath: new})
                if relpath not in parsed:
                    return {"ok": False, "checker": "babel", "detail": "JavaScript/TypeScript ayrıştırılamadı."}
                return {"ok": True, "checker": "babel", "detail": ""}
        except Exception:  # köprü hatası: temel denetimle yetin
            pass
        return {"ok": True, "checker": "parantez-dengesi", "detail": "Babel köprüsü yok; yalnız temel denge denetimi."}
    if _bracket_delta(new) != _bracket_delta(old):
        return {"ok": False, "checker": "parantez-dengesi", "detail": "Yama parantez dengesini bozuyor."}
    return {"ok": None, "checker": "yok", "detail": "Bu dil için ayrıştırma denetimi yok; temel denge korunuyor."}


def _public_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return {key: finding.get(key) for key in ("title", "file", "line", "severity", "reference", "category")}


def _write(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, text.encode("utf-8", errors="surrogatepass"))
    finally:
        os.close(fd)


def _copy_context(root: Path, dest: Path, scope: scan_scope.ScanScope) -> dict[str, Any]:
    """Analizin göreceği dosyaları (aynı kapsamla) geçici kopyaya yaz; .env türü dosyalar kopyalanmaz."""
    import project_analyzer as pa

    files = 0
    total = 0
    limited = False
    try:
        for path, text, kind in pa._iter_files(root, max_files=max(scope.max_files, pa.MAX_FILES), skipped={}, scope=scope):
            if kind == "secret_file" or text is None:
                continue
            size = len(text.encode("utf-8", errors="surrogatepass"))
            if files >= MAX_CONTEXT_FILES or total + size > MAX_CONTEXT_BYTES:
                limited = True
                break
            _write(dest.joinpath(*path.relative_to(root).parts), text)
            files += 1
            total += size
    except pa.ProjectRejected:
        limited = True
    return {"files": files, "bytes": total, "limited": limited}


def _analyze_copy(path: Path, scope: scan_scope.ScanScope) -> list[dict[str, Any]]:
    import project_analyzer as pa

    try:
        return list(pa.analyze_project(str(path), allowed_roots=(path.parent,), scope=scope).get("findings") or [])
    except pa.ProjectRejected:
        return []


def _patch_text(patches: dict[str, tuple[str, str]]) -> str:
    parts = []
    for relpath in sorted(patches):
        old, new = patches[relpath]
        parts.append("".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                                  fromfile=f"a/{relpath}", tofile=f"b/{relpath}", n=3)))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Doğrulama çekirdeği
# ---------------------------------------------------------------------------


def _verify(audit: dict[str, Any], root: Path, patches: dict[str, tuple[str, str]],
            targets: list[dict[str, Any]], *, work_root: str | None = None) -> dict[str, Any]:
    """``targets``: [{index, finding, kind, line}] — line yamasız dosyadaki satırdır."""
    if not _SLOTS.acquire(blocking=False):
        raise VerificationBusy("Şu anda başka düzeltme doğrulamaları çalışıyor; biraz sonra yeniden deneyin.")
    started = time.monotonic()
    base = Path(tempfile.mkdtemp(prefix="sniper-fixverify-", dir=work_root))
    try:
        os.chmod(base, 0o700)
        project = base / "proje"
        project.mkdir(mode=0o700)
        scope = _audit_scope(audit)
        context = _copy_context(root, project, scope)
        for relpath, (old, _new) in patches.items():  # güncel ve tam metin (bağlam sınırı ya da kapsam dışı olsa da)
            _write(project.joinpath(*PurePosixPath(relpath).parts), old)
        with scan_scope.scan_scope(scope):
            baseline = _analyze_copy(project, scope)
            for relpath, (_old, new) in patches.items():
                _write(project.joinpath(*PurePosixPath(relpath).parts), new)
            after = _analyze_copy(project, scope)
        parse = {relpath: parse_check(relpath, old, new) for relpath, (old, new) in patches.items()}
    finally:
        shutil.rmtree(base, ignore_errors=True)
        _SLOTS.release()

    maps = {relpath: line_map(old, new) for relpath, (old, new) in patches.items()}
    matched, new_indices, gone = match_findings(baseline, after, maps)
    target_rows = []
    located: set[int] = set()
    for target in targets:
        b_index = _locate_target(baseline, target["finding"], target["kind"], target["line"])
        row = {"index": target["index"], "file": target["finding"].get("file"), "line": target["line"],
               "title": target["finding"].get("title"), "applied": target.get("applied", True)}
        if b_index is None:
            row.update(closed=False, reason="Bulgu güncel kopyada yeniden üretilemedi (dosya değişmiş ya da motor sürümü farklı).")
        elif b_index in located:
            row.update(closed=b_index in gone, reason="Aynı satırdaki bulguyla birlikte değerlendirildi.")
        else:
            located.add(b_index)
            closed = b_index in gone
            row.update(closed=closed, reason="" if closed else "Yamadan sonra bulgu hâlâ raporlanıyor.")
            if not closed and target["kind"] in GUARD_KINDS and target.get("applied", True):
                row.update(guarded=True, reason="Yama bir koruma ekliyor; analiz motoru bu korumayı arındırıcı saymadığı için "
                                                "bulgu hâlâ raporlanıyor. Korumanın doğruluğunu elle gözden geçirin.")
        if not row["applied"]:
            row["reason"] = target.get("reason") or "Bu bulgu için otomatik yama üretilemedi."
        target_rows.append(row)

    new_findings = [_public_finding(after[i]) for i in new_indices]
    blocking_new = [f for f in new_findings if str(f.get("severity")) in _BLOCKING_SEVERITIES]
    notes_new = [f for f in new_findings if str(f.get("severity")) not in _BLOCKING_SEVERITIES]
    also_closed = [_public_finding(baseline[i]) for i in gone if i not in located]
    parse_failed = [relpath for relpath, check in parse.items() if check["ok"] is False]
    closed_count = sum(1 for row in target_rows if row["closed"])
    guarded_count = sum(1 for row in target_rows if row.get("guarded"))

    reasons: list[str] = []
    if parse_failed:
        reasons.extend(f"{relpath}: {parse[relpath]['detail']}" for relpath in parse_failed)
    if closed_count + guarded_count == 0:
        reasons.append("Hedef bulgu(lar) yamadan sonra kapanmadı.")
    elif closed_count < len(target_rows):
        reasons.append(f"{len(target_rows)} hedeften {closed_count} tanesi kapandı"
                       + (f", {guarded_count} tanesine koruma eklendi (elle gözden geçirme gerekli)." if guarded_count else "."))
    if blocking_new:
        reasons.append(f"Yama {len(blocking_new)} yeni orta/yüksek önemli bulgu doğurdu.")
    if parse_failed or closed_count + guarded_count == 0:
        verdict = "failed"
    elif closed_count < len(target_rows) or blocking_new:
        verdict = "partial"
    else:
        verdict = "verified"
        reasons.append("Hedef bulgu(lar) kapandı, yeni orta/yüksek önemli bulgu yok, dosya ayrıştırılabiliyor.")
    if notes_new:
        reasons.append(f"{len(notes_new)} yeni düşük önemli not (ör. eklenen içe aktarım) bilgi amaçlı listelendi.")
    if context["limited"]:
        reasons.append("Bağlam sınırlı: projenin tamamı kopyalanmadı; dosyalar arası etkiler eksik değerlendirilmiş olabilir.")

    return {
        "format": FORMAT,
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict],
        "reasons": reasons,
        "targets": target_rows,
        "new_findings": blocking_new,
        "new_notes": notes_new,
        "also_closed": also_closed,
        "parse": parse,
        "diff": _patch_text(patches),
        "files": sorted(patches),
        "context": context,
        "engine_counts": {"before": len(baseline), "after": len(after)},
        "duration_ms": int((time.monotonic() - started) * 1000),
        "applied_to_project": False,
        "scope_note": SCOPE_NOTE,
    }


# ---------------------------------------------------------------------------
# Tek bulgu
# ---------------------------------------------------------------------------


def verify_finding_fix(audit: dict[str, Any], index: int, *, allowed_roots: tuple[Path, ...] | None = None,
                       work_root: str | None = None) -> dict[str, Any]:
    finding, kind = ta.finding_at(audit, index)
    relpath = str(finding.get("file") or "")
    ta.safe_relative(relpath)
    root = ta.project_root(audit, allowed_roots)
    text = ta.read_project_file(root, relpath)
    line = _line(finding)
    flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else None
    suggestion, new_text = ta.compute_fix(text, relpath, line, kind, flow=flow)
    header = {"finding_index": index, "title": str(finding.get("title") or ""), "strategy": suggestion.get("strategy"),
              "confidence": suggestion.get("confidence"), "notes": suggestion.get("notes", []),
              "patch_filename": f"sniper-fix-{audit.get('id', 'analiz')}-{index}.patch"}
    if new_text is None:
        return {"format": FORMAT, "verdict": "failed", "verdict_label": VERDICT_LABELS["failed"],
                "reasons": ["Otomatik yama üretilemedi; yalnız metinsel öneri var."], "targets": [], "new_findings": [],
                "new_notes": [], "also_closed": [], "parse": {}, "diff": "", "files": [], "snippet": suggestion.get("snippet", ""),
                "applied_to_project": False, **header}
    result = _verify(audit, root, {relpath: (text, new_text)},
                     [{"index": index, "finding": finding, "kind": kind, "line": line}], work_root=work_root)
    result.update(header)
    return result


def patch_for_finding(audit: dict[str, Any], index: int, *, allowed_roots: tuple[Path, ...] | None = None) -> str:
    """İndirilebilir .patch (doğrulama yapmadan); yama üretilemezse AutofixError."""
    finding, kind = ta.finding_at(audit, index)
    relpath = str(finding.get("file") or "")
    ta.safe_relative(relpath)
    root = ta.project_root(audit, allowed_roots)
    text = ta.read_project_file(root, relpath)
    flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else None
    _suggestion, new_text = ta.compute_fix(text, relpath, _line(finding), kind, flow=flow)
    if new_text is None:
        raise AutofixError("Bu bulgu için otomatik yama üretilemedi.")
    return _patch_text({relpath: (text, new_text)})


# ---------------------------------------------------------------------------
# Toplu düzeltme
# ---------------------------------------------------------------------------


def _sink_api(finding: dict[str, Any]) -> str:
    flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else {}
    sink = str(flow.get("sink") or "")
    return sink.rsplit(".", 1)[-1] if sink else ""


def _group_key(finding: dict[str, Any], kind: str) -> str:
    return "|".join((kind, str(finding.get("reference") or ""), _sink_api(finding) or _norm_title(finding.get("title"))))


def fix_groups(audit: dict[str, Any]) -> list[dict[str, Any]]:
    """Otomatik yama üretilebilir dillerde (Python, JS/TS) aynı kalıptaki ≥2 bulgunun grupları."""
    findings = audit.get("findings") if isinstance(audit.get("findings"), list) else []
    groups: dict[str, dict[str, Any]] = {}
    for index, finding in enumerate(findings):
        kind = ta.finding_kind(finding)
        relpath = str(finding.get("file") or "")
        if kind is None or not (relpath.endswith(".py") or _JS_SUFFIX_RE.search(relpath)) or _line(finding) < 1:
            continue
        key = _group_key(finding, kind)
        group = groups.setdefault(key, {"key": key, "kind": kind, "reference": str(finding.get("reference") or ""),
                                        "api": _sink_api(finding), "title": str(finding.get("title") or ""),
                                        "strategy": ta.STRATEGIES.get(kind, {}).get("title", ""), "indices": [], "files": set()})
        group["indices"].append(index)
        group["files"].add(relpath)
    result = []
    for group in groups.values():
        if len(group["indices"]) >= 2:
            result.append({**group, "files": sorted(group["files"]), "count": len(group["indices"])})
    return sorted(result, key=lambda g: (-g["count"], g["key"]))


def verify_bulk_fix(audit: dict[str, Any], *, group: str | None = None, indices: list[int] | None = None,
                    allowed_roots: tuple[Path, ...] | None = None, work_root: str | None = None) -> dict[str, Any]:
    findings = audit.get("findings") if isinstance(audit.get("findings"), list) else []
    if group is not None:
        match = next((g for g in fix_groups(audit) if g["key"] == group), None)
        if match is None:
            raise AutofixError("Toplu düzeltme grubu bulunamadı.")
        selected = list(match["indices"])
    elif indices is not None:
        if (not isinstance(indices, list) or not indices
                or not all(isinstance(i, int) and not isinstance(i, bool) for i in indices)):
            raise AutofixError("indices negatif olmayan tamsayılardan oluşan bir liste olmalı.")
        selected = sorted(set(indices))
    else:
        raise AutofixError("group ya da indices gerekli.")
    if len(selected) > MAX_BULK_FINDINGS:
        raise AutofixError(f"Toplu düzeltme en çok {MAX_BULK_FINDINGS} bulgu içerebilir.")
    root = ta.project_root(audit, allowed_roots)

    by_file: dict[str, list[tuple[int, dict[str, Any], str]]] = {}
    for index in selected:
        finding, kind = ta.finding_at(audit, index)
        relpath = str(finding.get("file") or "")
        ta.safe_relative(relpath)
        by_file.setdefault(relpath, []).append((index, finding, kind))

    patches: dict[str, tuple[str, str]] = {}
    targets: list[dict[str, Any]] = []
    for relpath, items in sorted(by_file.items()):
        original = ta.read_project_file(root, relpath)
        current = original
        for index, finding, kind in sorted(items, key=lambda item: _line(item[1])):
            line = _line(finding)
            mapper = line_map(original, current)
            mapped = mapper(line)[0] if line else 0
            flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else None
            if flow and isinstance(flow.get("source_line"), int):
                flow = {**flow, "source_line": mapper(flow["source_line"])[0]}
            try:
                _suggestion, new_text = ta.compute_fix(current, relpath, mapped, kind, flow=flow)
            except AutofixError:
                new_text = None
            target = {"index": index, "finding": finding, "kind": kind, "line": line, "applied": new_text is not None}
            if new_text is None:
                target["reason"] = "Bu bulgu için otomatik yama üretilemedi (yalnız metinsel öneri)."
            else:
                current = new_text
            targets.append(target)
        if current != original:
            patches[relpath] = (original, current)

    header = {"group": group, "selected": selected, "patch_filename": f"sniper-bulk-fix-{audit.get('id', 'analiz')}.patch"}
    if not patches:
        return {"format": FORMAT, "verdict": "failed", "verdict_label": VERDICT_LABELS["failed"],
                "reasons": ["Seçilen bulguların hiçbiri için otomatik yama üretilemedi."],
                "targets": [{"index": t["index"], "file": t["finding"].get("file"), "line": t["line"],
                             "title": t["finding"].get("title"), "applied": False, "closed": False, "reason": t.get("reason", "")}
                            for t in targets],
                "new_findings": [], "new_notes": [], "also_closed": [], "parse": {}, "diff": "", "files": [],
                "applied_to_project": False, **header}
    result = _verify(audit, root, patches, targets, work_root=work_root)
    result.update(header)
    result["closed_indices"] = [row["index"] for row in result["targets"] if row["closed"]]
    return result
