"""OpenAPI/Swagger sözleşmesi ↔ koddaki rota envanteri karşılaştırması (17. tur).

Proje analizinde bulunan sözleşme dosyaları (``openapi``/``swagger`` üst düzey anahtarı olan JSON/YAML) ile
``authz_routes`` rota envanteri eşleştirilir:

* gölge uç nokta: kodda olup sözleşmede olmayan rota (yalnız sözleşmenin o uygulamayı büyük ölçüde kapsadığı
  durumda; aksi halde sözleşme başka bir servisi ya da alt kümeyi anlatıyor olabilir),
* kodda bulunmayan uç nokta: sözleşmede olup kodda eşleşmeyen işlem (eski belge / başka servis; özet bulgu),
* kimlik doğrulama uyuşmazlığı: sözleşme kimlik doğrulama istiyor ama kodda denetim görülmüyor (CWE-306) ya da
  sözleşme açık diyor ama kod korumalı (belge sapması; özet bulgu),
* parametre şeması eksikleri: türü/şeması olmayan parametreler, tanımlanmamış yol şablonu parametreleri.

Sözleşme güdümlü çatılar (connexion, express-openapi vb.) rotaları koddan değil sözleşmeden kurar: bu durumda işlem
``operationId`` ile projedeki işleve eşlenir ("operationId ile uygulanmış"). Yalnız statik analiz; ağ yok.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

MAX_SPEC_BYTES = 2_000_000
MAX_SPECS = 8
MAX_SHADOW_FINDINGS = 15
MAX_AUTH_FINDINGS = 20
MAX_EXAMPLES = 8
MAX_LISTED = 200
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
SPEC_SUFFIXES = (".json", ".yaml", ".yml")

_YAML_SPEC_RE = re.compile(r"(?m)^[\"']?(openapi|swagger)[\"']?\s*:\s*[\"']?[23]\.")
_JSON_SPEC_RE = re.compile(r"\"(openapi|swagger)\"\s*:\s*\"[23]\.")
# Belge/statik yollar gölge uç nokta sayılmaz (sözleşmenin kendisini sunan rota vb.).
_DOC_PATH_RE = re.compile(r"(?i)(openapi|swagger|api-?docs|redoc|(^|/)docs?(/|$)|static|assets|favicon|robots\.txt)")
_ADMIN_PATH_RE = re.compile(r"(?i)(^|/)(admin|manage|management|internal|debug|console|superuser|staff|backoffice|ops)(/|$|[-_])")
_PARAM_SEG_RE = re.compile(
    r"^(\{[^}]*\}|:[A-Za-z_][\w]*\??(\(.*\))?|<[^>]+>|\(\?P<[^>]+>.*\)|\(.*\)|\*+|\[[^\]]+\])$"
)
_PY_DEF_LINE_RE = re.compile(r"(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")


# ---------------------------------------------------------------------------
# Sözleşme bulma ve ayrıştırma
# ---------------------------------------------------------------------------
def _replace_braced_segments(value: str, replacement: str = "x") -> str:
    """Replace non-overlapping ``{...}`` segments in one forward pass."""
    parts: list[str] = []
    cursor = 0
    while True:
        start = value.find("{", cursor)
        if start < 0:
            parts.append(value[cursor:])
            break
        end = value.find("}", start + 1)
        if end < 0:
            parts.append(value[cursor:])
            break
        parts.extend((value[cursor:start], replacement))
        cursor = end + 1
    return "".join(parts)


def _braced_values(value: str):
    """Yield non-empty values from non-overlapping ``{...}`` segments."""
    cursor = 0
    while True:
        start = value.find("{", cursor)
        if start < 0:
            return
        end = value.find("}", start + 1)
        if end < 0:
            return
        if end > start + 1:
            yield value[start + 1:end]
        cursor = end + 1


def looks_like_spec(relpath: str, text: str) -> bool:
    """Hızlı ön süzgeç: JSON/YAML dosyasında üst düzey ``openapi: 3.x`` / ``swagger: "2.0"`` anahtarı."""
    if not relpath.lower().endswith(SPEC_SUFFIXES) or not text or len(text) > MAX_SPEC_BYTES:
        return False
    head = text[:6000]
    if relpath.lower().endswith(".json"):
        return bool(_JSON_SPEC_RE.search(head))
    return bool(_YAML_SPEC_RE.search(head))


def _load(relpath: str, text: str) -> dict[str, Any] | None:
    doc: Any = None
    if relpath.lower().endswith(".json"):
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            return None
    else:
        try:
            from openapi_contract_auditor import _parse_simple_yaml  # PyYAML varsa safe_load, yoksa basit ayrıştırıcı
            doc = _parse_simple_yaml(text)
        except Exception:  # noqa: BLE001 — bozuk sözleşme analizi durdurmaz
            return None
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc) or not isinstance(doc.get("paths"), dict):
        return None
    return doc


def _url_path(url: str) -> str:
    url = str(url or "").strip()
    url = _replace_braced_segments(url) if "://" in url else url
    m = re.match(r"^[a-zA-Z][\w+.-]*://[^/]*(/.*)?$", url)
    if m:
        url = m.group(1) or ""
    return url.split("?", 1)[0].rstrip("/")


def _security_state(requirements: Any) -> str:
    """``required`` | ``optional`` | ``none`` (boş liste)."""
    if not isinstance(requirements, list):
        return "required"
    if not requirements:
        return "none"
    if any(isinstance(item, dict) and not item for item in requirements):
        return "optional"
    return "required"


def _line_of(text: str, path: str) -> int:
    for needle in (f'"{path}"', f"'{path}'", f"{path}:"):
        index = text.find(needle)
        if index >= 0:
            return text.count("\n", 0, index) + 1
    return 1


def parse_spec(relpath: str, text: str) -> dict[str, Any] | None:
    doc = _load(relpath, text)
    if doc is None:
        return None
    oas3 = "openapi" in doc
    bases: set[str] = set()
    if oas3:
        for server in doc.get("servers") or []:
            if isinstance(server, dict):
                base = _url_path(server.get("url", ""))
                if base:
                    bases.add(base)
    else:
        base = _url_path(doc.get("basePath", ""))
        if base:
            bases.add(base)
    components = doc.get("components") if isinstance(doc.get("components"), dict) else {}
    schemes = (components or {}).get("securitySchemes") if oas3 else doc.get("securityDefinitions")
    has_schemes = isinstance(schemes, dict) and bool(schemes)
    global_security = doc.get("security")
    operations: list[dict[str, Any]] = []
    param_gaps: list[str] = []
    for raw_path, item in doc["paths"].items():
        if not isinstance(item, dict):
            continue
        path = str(raw_path)
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        controller = item.get("x-openapi-router-controller")
        for method, op in item.items():
            if str(method).lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            if "security" in op:
                security = _security_state(op.get("security"))
            elif isinstance(global_security, list):
                security = _security_state(global_security)
            else:
                security = "none" if has_schemes else "undeclared"
            params = [p for p in shared + (op.get("parameters") if isinstance(op.get("parameters"), list) else [])
                      if isinstance(p, dict)]
            declared = {str(p.get("name")) for p in params if p.get("in") == "path"}
            loc = f"{str(method).upper()} {path}"
            for name in _braced_values(path):
                if name not in declared and not any("$ref" in p for p in params):
                    param_gaps.append(f"{loc}: yol parametresi '{name}' tanımlanmamış")
            for p in params:
                if "$ref" in p or p.get("in") not in {"path", "query", "header", "cookie"}:
                    continue
                typed = isinstance(p.get("schema"), dict) or "content" in p if oas3 else bool(p.get("type"))
                if not typed:
                    param_gaps.append(f"{loc}: '{p.get('name')}' parametresinin türü/şeması yok")
            operations.append({
                "method": str(method).upper(), "path": path, "norm": norm_path(path), "security": security,
                "operation_id": str(op.get("operationId") or ""),
                "controller": str(op.get("x-openapi-router-controller") or controller or ""),
            })
    return {
        "file": relpath, "format": "openapi3" if oas3 else "swagger2", "bases": sorted(bases),
        "base_norms": [norm_path(b) for b in sorted(bases)], "operations": operations, "has_schemes": has_schemes,
        "param_gaps": param_gaps, "text": text,
    }


# ---------------------------------------------------------------------------
# Yol normalleştirme ve eşleştirme
# ---------------------------------------------------------------------------
def _split_django_regex(path: str) -> list[str]:
    # (?P<ad>[^/]+) gibi grupların içindeki "/" bölmeyi bozmasın: önce grupları yer tutucuya çevir.
    out, depth, buf = [], 0, ""
    for ch in path:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "/" and depth == 0:
            out.append(buf)
            buf = ""
        else:
            buf += ch
    out.append(buf)
    return out


def norm_path(path: str) -> tuple[str, ...]:
    """Parametreli bölümler ``{}`` olur; sabit bölümler küçük harfe çevrilir; baş/son ``/`` ve Django çapaları atılır."""
    path = str(path or "").strip()  # rota/sözleşme yollarında sorgu dizgesi olmaz; "?" Django (?P<…>) ve Express :id? içindir
    path = path.lstrip("^").rstrip("$")
    segments: list[str] = []
    for seg in _split_django_regex(path):
        seg = seg.strip()
        if not seg:
            continue
        if _PARAM_SEG_RE.match(seg) or ("{" in seg and "}" in seg) or "(?P<" in seg or seg.startswith(":"):
            segments.append("{}")
        else:
            segments.append(seg.lower().rstrip("$"))
    return tuple(segments)


def _suffix_match(a: tuple[str, ...], b: tuple[str, ...]) -> int | None:
    """``a`` ile ``b`` aynıysa 0; biri diğerinin sonekiyse ve fazlalık en çok 3 sabit bölümse fazlalık sayısı."""
    if a == b:
        return 0
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    if not short or len(long_) - len(short) > 3 or long_[len(long_) - len(short):] != short:
        return None
    if all(seg == "{}" for seg in short):
        return None  # yalnız parametreden oluşan kısa yol ("/{id}/") her şeyin sonekidir: eşleştirme anlamsız
    extra = long_[: len(long_) - len(short)]
    if any(seg == "{}" for seg in extra):
        return None
    return len(extra)


def _method_ok(route_methods: Iterable[str], method: str, framework: str) -> bool:
    methods = {m.upper() for m in route_methods}
    return not methods or "ALL" in methods or method in methods or (framework == "django" and method in {"GET", "POST", "HEAD"})


def _python_class_name(source_line: str) -> str | None:
    """Return a Python class name using one forward pass over a stripped line."""
    if not source_line.startswith("class"):
        return None
    cursor = len("class")
    if cursor >= len(source_line) or not source_line[cursor].isspace():
        return None
    while cursor < len(source_line) and source_line[cursor].isspace():
        cursor += 1
    if cursor >= len(source_line) or not (
        source_line[cursor] == "_" or source_line[cursor].isascii() and source_line[cursor].isalpha()
    ):
        return None
    start = cursor
    cursor += 1
    while cursor < len(source_line) and (
        source_line[cursor] == "_" or source_line[cursor].isalnum()
    ):
        cursor += 1
    if source_line.find(":", cursor) < 0:
        return None
    return source_line[start:cursor]


def _function_index(sources: Iterable[tuple]) -> tuple[set[str], set[str]]:
    """Sözleşme güdümlü çatılar için işlev dizini: (nitelikli 'modül.işlev', çıplak ad)."""
    qualified: set[str] = set()
    bare: set[str] = set()
    for item in sources:
        rel, text = item[0], item[1]
        if rel.endswith(".py"):
            module = rel[:-3].replace("/", ".")
            if module.endswith(".__init__"):
                module = module[: -len(".__init__")]
            current_class: str | None = None
            for source_line in text.splitlines():
                stripped = source_line.lstrip(" \t")
                if not stripped:
                    continue
                indented = len(stripped) != len(source_line)
                if not indented:
                    current_class = None
                    class_name = _python_class_name(stripped)
                    if class_name is not None:
                        current_class = class_name
                        continue
                    function_match = _PY_DEF_LINE_RE.match(stripped)
                    if function_match is None:
                        continue
                    name = function_match.group(1)
                    bare.add(name)
                    parts = module.split(".")
                    for i in range(len(parts)):  # paket kökü bilinmiyor: her önek kırpımı
                        qualified.add(".".join(parts[i:] + [name]))
                elif current_class is not None:
                    function_match = _PY_DEF_LINE_RE.match(stripped)
                    if function_match is not None:
                        qualified.add(f"{current_class}.{function_match.group(1)}")
        else:
            for name in re.findall(r"(?:function\s+([A-Za-z_$][\w$]*)|(?:exports|module\.exports)\.([A-Za-z_$][\w$]*)\s*=)", text):
                bare.add(name[0] or name[1])
    return qualified, bare


def _operation_implemented(op: dict[str, Any], qualified: set[str], bare: set[str]) -> bool:
    """Sözleşme güdümlü yönlendirme: operationId (gerekirse x-openapi-router-controller önekiyle) projedeki bir işlev mi?"""
    op_id = op.get("operation_id") or ""
    if not op_id:
        return False
    candidates = {op_id}
    if op.get("controller"):
        candidates.add(f"{op['controller']}.{op_id}")
    if any(c in qualified for c in candidates):
        return True
    return "." not in op_id and op_id in bare


# ---------------------------------------------------------------------------
# Karşılaştırma
# ---------------------------------------------------------------------------
def compare(specs: list[dict[str, Any]], routes: list[Any], sources: Iterable[tuple] = ()) -> dict[str, Any]:
    """``routes``: authz_routes.Route listesi. Dönüş: özet, listeler ve bulgu adayları (proje analizi ekler)."""
    import authz_routes

    qualified, bare = _function_index(sources)
    findings: list[dict[str, Any]] = []
    route_keys = [(route, norm_path(route.path)) for route in routes if route.path]
    matched_routes: set[int] = set()
    spec_reports: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    auth_gaps: list[dict[str, Any]] = []
    drift: list[dict[str, Any]] = []
    group_protected: dict[str, int] = {}
    for route in routes:
        if route.protection:
            group_protected[route.group] = group_protected.get(route.group, 0) + 1
    for spec in specs:
        matched = by_operation_id = 0
        spec_missing: list[dict[str, Any]] = []
        for op in spec["operations"]:
            candidates = [op["norm"]] + [base + op["norm"] for base in spec["base_norms"] if base]
            best: tuple[int, Any] | None = None
            for route, key in route_keys:
                if not _method_ok(route.methods, op["method"], route.framework):
                    continue
                for cand in candidates:
                    extra = _suffix_match(cand, key)
                    if extra is not None and (best is None or extra < best[0]):
                        best = (extra, route)
            if best is not None:
                route = best[1]
                matched += 1
                matched_routes.add(id(route))
                public = route.public_mark or authz_routes._is_public_path(route)
                if op["security"] == "required" and not route.protection and not public \
                        and group_protected.get(route.group, 0) >= 1:
                    if not any(g["route"] is route for g in auth_gaps):  # aynı rotanın GET/POST'u tek bulgu
                        auth_gaps.append({"op": op, "route": route, "ops": []})
                    next(g for g in auth_gaps if g["route"] is route)["ops"].append(op)
                elif op["security"] in {"none", "undeclared"} and route.protection:
                    drift.append({"op": op, "route": route})
                continue
            if _operation_implemented(op, qualified, bare):
                matched += 1
                by_operation_id += 1
                continue
            spec_missing.append(op)
        total = len(spec["operations"])
        coverage = matched / total if total else 0.0
        spec_reports.append({
            "file": spec["file"], "format": spec["format"], "bases": spec["bases"], "operations": total,
            "matched": matched, "matched_by_operation_id": by_operation_id, "coverage": round(coverage, 2),
            "param_gaps": len(spec["param_gaps"]),
        })
        spec["_coverage"] = coverage
        spec["_matched"] = matched
        if matched >= 3 and coverage >= 0.5 and spec_missing:
            missing.extend({"spec": spec["file"], "method": op["method"], "path": op["path"]} for op in spec_missing)
            examples = ", ".join(f"{op['method']} {op['path']}" for op in spec_missing[:MAX_EXAMPLES])
            findings.append(_finding(
                "api", "info", spec["file"], _line_of(spec["text"], spec_missing[0]["path"]),
                "API sözleşmesindeki uç nokta kodda bulunamadı (eski belge ya da başka servis olabilir)",
                f"{len(spec_missing)} / {total} işlem koddaki rotalarla eşleşmedi: {examples}"
                + (" …" if len(spec_missing) > MAX_EXAMPLES else ""),
                "Sözleşmeyi koddan üretin ya da kaldırılan uç noktaları belgeden çıkarın; istemciler ve güvenlik testleri "
                "belgeye güvenir.", "OWASP API9:2023"))
        if spec["param_gaps"]:
            gaps = spec["param_gaps"]
            findings.append(_finding(
                "api", "low", spec["file"], 1,
                "API sözleşmesinde parametre şeması eksik (doğrulama ve test kapsamı zayıflar)",
                f"{len(gaps)} eksik: " + "; ".join(gaps[:MAX_EXAMPLES]) + (" …" if len(gaps) > MAX_EXAMPLES else ""),
                "Her parametreye tür/şema (ve uygunsa maxLength, pattern, enum, minimum/maximum) tanımlayın; yol "
                "şablonundaki her parametreyi parameters altında bildirin.", "OWASP API8:2023"))

    # Gölge uç noktalar: yalnız sözleşmenin bu rota grubunu büyük ölçüde kapsadığı gruplarda.
    shadow: list[Any] = []
    if specs:
        groups: dict[str, list[Any]] = {}
        for route, key in route_keys:
            if not key or _DOC_PATH_RE.search(route.path or ""):
                continue  # kök rota ("/"): bağlama öneki (include/mount) bilinmediği için eşleştirilemez
            groups.setdefault(route.group, []).append(route)
        for group_routes in groups.values():
            hit = [r for r in group_routes if id(r) in matched_routes]
            if len(hit) < 3 or len(hit) * 2 < len(group_routes):
                continue
            shadow.extend(r for r in group_routes if id(r) not in matched_routes)
    shadow.sort(key=lambda r: (not _ADMIN_PATH_RE.search(r.path or ""), r.file, r.line))
    for route in shadow[:MAX_SHADOW_FINDINGS]:
        admin = bool(_ADMIN_PATH_RE.search(route.path or ""))
        findings.append(_finding(
            "api", "medium" if admin else "low", route.file, route.line,
            "Belgelenmemiş (gölge) API uç noktası: sözleşmede yok (gözden geçirme)",
            f"{'/'.join(route.methods)} {route.path} ({route.framework}, {route.handler}) API sözleşmesinde tanımlı değil; "
            f"aynı uygulamanın rotaları sözleşmede büyük ölçüde belgelenmiş."
            + (" Yönetim/iç yol." if admin else "") + (" Korumasız." if not route.protection else ""),
            "Uç nokta kasıtlıysa sözleşmeye ekleyin (güvenlik şemasıyla); kullanılmıyorsa kaldırın. Belgelenmemiş uç "
            "noktalar güvenlik testlerinde ve ağ geçidi kurallarında gözden kaçar.", "OWASP API9:2023"))
    for gap in auth_gaps[:MAX_AUTH_FINDINGS]:
        op, route = gap["op"], gap["route"]
        findings.append(_finding(
            "authz", "medium", route.file, route.line,
            "Sözleşme kimlik doğrulama istiyor, kodda denetim görülmedi (gözden geçirme)",
            f"{', '.join(o['method'] + ' ' + o['path'] for o in gap['ops'])} sözleşmede güvenlik şemasıyla tanımlı; koddaki {'/'.join(route.methods)} "
            f"{route.path} ({route.handler}) için dekoratör/ara katman/satır içi kimlik denetimi bulunamadı. Aynı "
            "uygulamada korunan başka rotalar var; ağ geçidinde doğrulama yapılıyorsa bilerek kabul edin.",
            "Rotaya uygulamanın kimlik doğrulama denetimini ekleyin ya da sözleşmeyi gerçek davranışa göre düzeltin.",
            "CWE-306"))
    if drift:
        first = drift[0]
        examples = ", ".join(f"{d['op']['method']} {d['op']['path']}" for d in drift[:MAX_EXAMPLES])
        spec_file = next((s["file"] for s in specs if any(o is first["op"] for o in s["operations"])), specs[0]["file"])
        spec_text = next((s["text"] for s in specs if s["file"] == spec_file), "")
        findings.append(_finding(
            "api", "low", spec_file, _line_of(spec_text, first["op"]["path"]),
            "API sözleşmesinde kimlik doğrulama tanımı eksik (kod korumalı; belge sapması)",
            f"{len(drift)} işlem sözleşmede güvenliksiz/tanımsız ama kodda korumalı: {examples}"
            + (" …" if len(drift) > MAX_EXAMPLES else ""),
            "securitySchemes ve security alanlarını tanımlayın; istemci üreticileri, ağ geçitleri ve DAST araçları "
            "kimlik doğrulamayı sözleşmeden okur.", "OWASP API9:2023"))

    def _listed(route: Any) -> dict[str, Any]:
        return {"method": "/".join(route.methods), "path": route.path, "file": route.file, "line": route.line,
                "protected": bool(route.protection)}

    summary = {
        "specs": len(specs),
        "spec_operations": sum(r["operations"] for r in spec_reports),
        "matched_operations": sum(r["matched"] for r in spec_reports),
        "matched_by_operation_id": sum(r["matched_by_operation_id"] for r in spec_reports),
        "code_routes": len(route_keys),
        "shadow_routes": len(shadow),
        "missing_in_code": len(missing),
        "auth_mismatch": len(auth_gaps),
        "doc_auth_drift": len(drift),
        "param_gaps": sum(r["param_gaps"] for r in spec_reports),
    }
    return {
        "summary": summary,
        "specs": spec_reports,
        "shadow": [_listed(r) for r in shadow[:MAX_LISTED]],
        "missing": missing[:MAX_LISTED],
        "auth_mismatch": [{"method": g["op"]["method"], "path": g["op"]["path"], "file": g["route"].file,
                           "line": g["route"].line} for g in auth_gaps[:MAX_LISTED]],
        "findings": findings,
    }


def _finding(category: str, severity: str, file: str, line: int, title: str, evidence: str, recommendation: str,
             reference: str) -> dict[str, Any]:
    return {"category": category, "severity": severity, "file": file, "line": int(line or 1), "title": title,
            "evidence": evidence, "recommendation": recommendation, "reference": reference}


def analyze(spec_sources: list[tuple[str, str]], routes: list[Any], sources: Iterable[tuple] = ()) -> dict[str, Any] | None:
    """Proje analizinin giriş noktası. Sözleşme yoksa ``None``."""
    import hashlib

    specs = []
    seen: set[str] = set()
    for rel, text in spec_sources[: MAX_SPECS * 4]:
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        if digest in seen:
            continue  # aynı sözleşmenin kopyası (ör. başka servise gömülü)
        seen.add(digest)
        spec = parse_spec(rel, text)
        if spec and spec["operations"]:
            specs.append(spec)
        if len(specs) >= MAX_SPECS:
            break
    if not specs:
        return None
    result = compare(specs, routes, sources)
    for spec in specs:
        spec.pop("text", None)
    return result
