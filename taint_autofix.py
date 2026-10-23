"""Doğrulanmış veri akışı ve tehlikeli API bulguları için otomatik düzeltme önerisi (yalnız önizleme).

Kaynak satırları bulgu kaydında tutulmaz; öneri istendiğinde dosya proje kökünden (yeniden
doğrulanarak, sembolik bağ izlenmeden) okunur. Hiçbir dosyaya yazılmaz: çıktı birleşik fark
(unified diff) ve/veya metinsel öneridir.

Python için AST tabanlı dönüşümler (parametreli SQL, argüman listesi + shell=False,
ast.literal_eval, safe_load, kaçış/escape, yol ve yönlendirme korumaları …); JavaScript/TypeScript
için satır düzeyinde metin dönüşümleri. Dönüşüm güvenle yapılamıyorsa metinsel öneri döner.
"""

from __future__ import annotations

import ast
import copy
import difflib
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable

from safe_file_read import read_text_bounded

AUTOFIX_FORMAT = "sniper-autofix-v1"
MAX_SOURCE_BYTES = 1_000_000

CWE_TO_KIND = {
    "CWE-89": "sql", "CWE-78": "command", "CWE-95": "eval", "CWE-94": "eval", "CWE-79": "html", "CWE-22": "path",
    "CWE-918": "ssrf", "CWE-502": "deserialize", "CWE-601": "redirect", "CWE-90": "ldap", "CWE-643": "xpath",
    "CWE-611": "xxe", "CWE-501": "session", "CWE-117": "log", "CWE-1333": "regex", "CWE-614": "cookie",
    "CWE-330": "weakrand", "CWE-338": "weakrand",
}

STRATEGIES: dict[str, dict[str, str]] = {
    "sql": {"title": "Parametreli sorgu", "cwe": "CWE-89",
            "explanation": "Sorgu metnini sabit tutun, değerleri sürücünün yer tutucularıyla (? / %s / $1) ayrı parametre olarak geçirin."},
    "command": {"title": "Kabuksuz argüman listesi", "cwe": "CWE-78",
                "explanation": "Komutu kabuk yorumlamadan (shell=False / execFile) argüman listesiyle çalıştırın; argümanları allowlist ile sınırlandırın."},
    "eval": {"title": "Kod yerine veri ayrıştırma", "cwe": "CWE-95",
             "explanation": "eval yerine yalnız değişmezleri çözen ast.literal_eval (Python) veya JSON.parse (JS) kullanın."},
    "deserialize": {"title": "Güvenli serileştirme", "cwe": "CWE-502",
                    "explanation": "pickle/marshal/yaml.load yerine JSON veya yaml.safe_load kullanın; güvenilmeyen veriyi nesneye dönüştürmeyin."},
    "html": {"title": "Çıktı kaçışı", "cwe": "CWE-79",
             "explanation": "Kullanıcı verisini HTML'e yazmadan önce kaçışlayın (html.escape / escapeHtml) veya textContent kullanın."},
    "path": {"title": "Kök dizin sınırı", "cwe": "CWE-22",
             "explanation": "Yolu realpath ile çözüp izinli kök dizin altında kaldığını (commonpath) doğrulayın; dosya adını basename ile indirgeyin."},
    "ssrf": {"title": "Ana makine allowlist'i", "cwe": "CWE-918",
             "explanation": "Giden isteğin ana makinesini izinli listeye göre doğrulayın; iç ağ/meta veri adreslerini engelleyin."},
    "redirect": {"title": "Yalnız göreli yönlendirme", "cwe": "CWE-601",
                 "explanation": "Yalnız '/' ile başlayan (// olmayan) göreli yollara yönlendirin; diğerlerinde varsayılan sayfaya dönün."},
    "ldap": {"title": "LDAP filtre kaçışı", "cwe": "CWE-90",
             "explanation": "Filtreye giren değerleri escape_filter_chars ile kaçışlayın."},
    "xpath": {"title": "XPath değişken bağlama", "cwe": "CWE-643",
              "explanation": "İfadeyi sabit tutup değeri XPath değişkeni ($ad) olarak bağlayın."},
    "xxe": {"title": "Dış varlıkları kapatma", "cwe": "CWE-611",
            "explanation": "Dış varlık çözümünü kapatın (feature_external_ges False, resolve_entities=False) veya defusedxml kullanın."},
    "session": {"title": "Oturuma doğrulanmış veri", "cwe": "CWE-501",
                "explanation": "Oturuma yazmadan önce değeri doğrulayın/normalize edin (tür, uzunluk, allowlist)."},
    "log": {"title": "Günlük enjeksiyonu önleme", "cwe": "CWE-117",
            "explanation": "Kullanıcı verisini günlüğe repr (%r / !r) ile veya satır sonlarını temizleyerek yazın."},
    "regex": {"title": "Desen kaçışı", "cwe": "CWE-1333",
              "explanation": "Kullanıcı verisini düzenli ifadeye re.escape / escapeRegExp ile kaçışlayarak ekleyin."},
    "cookie": {"title": "Güvenli çerez bayrakları", "cwe": "CWE-614",
               "explanation": "Çerezde secure=True, httponly=True ve samesite ayarlayın."},
    "weakrand": {"title": "Kriptografik rastgelelik", "cwe": "CWE-330",
                 "explanation": "Oturum/çerez/belirteç değerleri için secrets modülünü (veya SystemRandom) kullanın."},
}


class AutofixError(ValueError):
    """Öneri üretilemedi (Türkçe, kullanıcıya gösterilir)."""


# ---------------------------------------------------------------------------
# Giriş noktaları
# ---------------------------------------------------------------------------


def finding_kind(finding: dict[str, Any]) -> str | None:
    flow = finding.get("taint_flow")
    if isinstance(flow, dict) and flow.get("sink_kind") in STRATEGIES:
        if flow.get("source_label") == "weakrand":
            return "weakrand"
        return str(flow["sink_kind"])
    reference = str(finding.get("reference") or finding.get("cwe") or "")
    match = re.search(r"CWE-\d+", reference)
    return CWE_TO_KIND.get(match.group(0)) if match else None


def project_root(audit: dict[str, Any], allowed_roots: tuple[Path, ...] | None = None) -> Path:
    """Analizin proje kökünü yeniden doğrula (sembolik bağ / izinli kök denetimi)."""
    from project_analyzer import ProjectRejected, validate_project_path

    try:
        return validate_project_path(str(audit.get("project_path") or ""), allowed_roots)
    except ProjectRejected as exc:
        raise AutofixError(f"Proje klasörü doğrulanamadı: {exc}") from exc


def finding_at(audit: dict[str, Any], index: int) -> tuple[dict[str, Any], str]:
    """(bulgu, hedef türü); bulgu yoksa ya da türü düzeltilemiyorsa AutofixError."""
    findings = audit.get("findings") if isinstance(audit.get("findings"), list) else []
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(findings):
        raise AutofixError("Bulgu bulunamadı.")
    finding = findings[index]
    kind = finding_kind(finding)
    if kind is None:
        raise AutofixError("Bu bulgu türü için otomatik düzeltme önerisi yok.")
    return finding, kind


def safe_relative(relative: str) -> PurePosixPath:
    pure = PurePosixPath(relative)
    if not relative or pure.is_absolute() or ".." in pure.parts or "\x00" in relative:
        raise AutofixError("Bulgunun dosya yolu geçersiz.")
    return pure


def read_project_file(root: Path, relative: str) -> str:
    """Proje kökü altındaki dosyayı güvenle oku (göreli yol, '..' yok, sembolik bağ izlenmez, boyut sınırı)."""
    pure = safe_relative(relative)
    path = root.joinpath(*pure.parts)
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise AutofixError("Bulgunun dosyası artık yok.") from exc
    if parent != root and root not in parent.parents:
        raise AutofixError("Dosya proje kökü dışında.")
    text = read_text_bounded(parent / path.name, MAX_SOURCE_BYTES)  # O_NOFOLLOW, normal dosya, boyut sınırı
    if text is None:
        raise AutofixError("Dosya okunamadı (sembolik bağ, normal olmayan dosya veya boyut sınırı).")
    return text


def suggest_for_finding(audit: dict[str, Any], index: int, *, allowed_roots: tuple[Path, ...] | None = None) -> dict[str, Any]:
    finding, kind = finding_at(audit, index)
    relative = str(finding.get("file") or "")
    safe_relative(relative)
    root = project_root(audit, allowed_roots)
    text = read_project_file(root, relative)
    line = int(finding.get("line") or 0)
    flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else None
    result = suggest_for_source(text, relative, line, kind, flow=flow)
    result["finding_index"] = index
    result["title"] = str(finding.get("title") or "")
    return result


def suggest_for_source(text: str, relpath: str, line: int, kind: str, *, flow: dict[str, Any] | None = None) -> dict[str, Any]:
    return compute_fix(text, relpath, line, kind, flow=flow)[0]


def compute_fix(text: str, relpath: str, line: int, kind: str, *,
                flow: dict[str, Any] | None = None) -> tuple[dict[str, Any], str | None]:
    """(öneri, düzeltilmiş tam metin); otomatik fark üretilemediyse metin ``None``. Hiçbir dosyaya yazmaz."""
    strategy = STRATEGIES.get(kind)
    if strategy is None:
        raise AutofixError("Bu hedef türü için öneri yok.")
    language = "python" if relpath.endswith(".py") else ("javascript" if re.search(r"\.(?:[cm]?[jt]sx?)$", relpath) else "")
    result: dict[str, Any] = {
        "format": AUTOFIX_FORMAT, "file": relpath, "line": line, "sink_kind": kind, "language": language or "bilinmiyor",
        "strategy": dict(strategy), "mode": "text", "diff": "", "snippet": TEXT_SNIPPETS.get((language or "python", kind), ""),
        "notes": [], "confidence": "düşük", "applied": False,
    }
    if line < 1:
        result["notes"].append("Satır bilgisi yok; yalnız genel öneri verildi.")
        return result, None
    lines = text.splitlines(keepends=True)
    if line > len(lines):
        result["notes"].append("Dosya bulgudan sonra değişmiş (satır yok); yalnız genel öneri verildi.")
        return result, None
    try:
        if language == "python":
            new_lines, notes, confidence = _python_fix(text, lines, line, kind, flow)
        elif language == "javascript":
            new_lines, notes, confidence = _js_fix(text, lines, line, kind)
        else:
            new_lines, notes, confidence = None, ["Bu dil için yalnız metinsel öneri var."], "düşük"
    except (SyntaxError, ValueError, RecursionError) as exc:
        new_lines, notes, confidence = None, [f"Dönüşüm yapılamadı: {type(exc).__name__}."], "düşük"
    result["notes"].extend(notes)
    if new_lines is not None and new_lines != lines:
        diff = "".join(difflib.unified_diff(lines, new_lines, fromfile=f"a/{relpath}", tofile=f"b/{relpath}", n=3))
        result.update(mode="diff", diff=diff, confidence=confidence)
        return result, "".join(new_lines)
    return result, None


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _parents(tree: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _statement_of(node: ast.AST, parents: dict[int, ast.AST]) -> ast.stmt | None:
    current: ast.AST | None = node
    while current is not None and not isinstance(current, ast.stmt):
        current = parents.get(id(current))
    return current  # type: ignore[return-value]


def _calls_on_line(tree: ast.AST, line: int) -> list[ast.Call]:
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno <= line <= (n.end_lineno or n.lineno)]
    # En içteki (en dar) çağrılar önce.
    return sorted(calls, key=lambda c: ((c.end_lineno or c.lineno) - c.lineno, -c.col_offset), reverse=False)


def _replace_segment(lines: list[str], node: ast.AST, new_source: str) -> list[str]:
    """Düğümün tam kaynak parçasını değiştir (sütunlar UTF-8 bayt konumudur); biçim korunur."""
    start_line, end_line = node.lineno - 1, (node.end_lineno or node.lineno) - 1
    first, last = lines[start_line], lines[end_line]
    start = len(first.encode("utf-8")[: node.col_offset].decode("utf-8", errors="ignore"))
    end = len(last.encode("utf-8")[: node.end_col_offset].decode("utf-8", errors="ignore"))
    return [*lines[:start_line], first[:start] + new_source + last[end:], *lines[end_line + 1:]]


def _insert_before(lines: list[str], stmt: ast.stmt, new_lines: list[str]) -> list[str]:
    index = stmt.lineno - 1
    indent = re.match(r"\s*", lines[index]).group(0)
    return [*lines[:index], *[f"{indent}{text}\n" for text in new_lines], *lines[index:]]


def _has_import(tree: ast.Module, module: str, name: str | None = None) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name == module and a.asname is None for a in node.names):
            return True
        if name and isinstance(node, ast.ImportFrom) and node.module == module and any(a.name == name for a in node.names):
            return True
    return False


def _insert_top(lines: list[str], tree: ast.Module, statement: str) -> list[str]:
    """İçe aktarmaları/üst düzey sabiti son üst düzey import'tan (yoksa docstring'den) sonra ekle."""
    index = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        index = body[0].end_lineno or 0
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            index = node.end_lineno or index
    return [*lines[:index], statement + "\n", *lines[index:]]


def _with_import(lines: list[str], tree: ast.Module, module: str, name: str | None = None) -> tuple[list[str], int]:
    if _has_import(tree, module, name):
        return lines, 0
    statement = f"from {module} import {name}" if name else f"import {module}"
    return _insert_top(lines, tree, statement), 1


_PLACEHOLDER_QUOTES = ("'", '"')


def _parameterize(expr: ast.AST, placeholder: str) -> tuple[str, list[ast.expr]] | None:
    """Dize birleştirme/biçimlendirme ifadesini (sorgu metni, parametreler) çiftine çevir."""
    parts: list[str | ast.expr] = []
    if isinstance(expr, ast.JoinedStr):
        for value in expr.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append(value.value)
            else:
                return None
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        stack: list[ast.AST] = [expr]
        flat: list[ast.AST] = []
        while stack:
            node = stack.pop()
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                stack.extend([node.right, node.left])
            else:
                flat.append(node)
        for node in flat:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                parts.append(node.value)
            elif isinstance(node, ast.JoinedStr):
                inner = _parameterize(node, "\x00")
                if inner is None:
                    return None
                pieces = inner[0].split("\x00")
                for i, piece in enumerate(pieces):
                    parts.append(piece)
                    if i < len(inner[1]):
                        parts.append(inner[1][i])
            elif isinstance(node, ast.expr):
                parts.append(node)
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod) and isinstance(expr.left, ast.Constant) \
            and isinstance(expr.left.value, str):
        values = list(expr.right.elts) if isinstance(expr.right, ast.Tuple) else [expr.right]
        chunks = re.split(r"(%[sdr])", expr.left.value)
        position = 0
        for chunk in chunks:
            if re.fullmatch(r"%[sdr]", chunk):
                if position >= len(values):
                    return None
                parts.append(values[position])
                position += 1
            else:
                parts.append(chunk.replace("%%", "%"))
        if position != len(values):
            return None
    elif isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format" \
            and isinstance(expr.func.value, ast.Constant) and isinstance(expr.func.value.value, str) and not expr.keywords:
        chunks = re.split(r"(\{\d*\})", expr.func.value.value)
        auto = 0
        for chunk in chunks:
            match = re.fullmatch(r"\{(\d*)\}", chunk)
            if match:
                index = int(match.group(1)) if match.group(1) else auto
                auto += 1
                if index >= len(expr.args):
                    return None
                parts.append(expr.args[index])
            else:
                parts.append(chunk)
    else:
        return None
    query = ""
    params: list[ast.expr] = []
    for i, part in enumerate(parts):
        if isinstance(part, str):
            query += part
            continue
        # '{x}' → ? : değeri saran tırnakları kaldır.
        nxt = parts[i + 1] if i + 1 < len(parts) and isinstance(parts[i + 1], str) else ""
        if query.endswith(_PLACEHOLDER_QUOTES) and nxt[:1] == query[-1]:
            query = query[:-1]
            parts[i + 1] = nxt[1:]  # type: ignore[index]
        query += placeholder
        params.append(part)
    if not params:
        return None
    return query, params


def _sql_placeholder(tree: ast.Module, call: ast.Call) -> str:
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    return "?" if "sqlite3" in imported or "sqlite" in _dotted(call.func).lower() else "%s"


def _assignment_before(tree: ast.Module, parents: dict[int, ast.AST], name: str, call: ast.Call) -> ast.Assign | None:
    stmt = _statement_of(call, parents)
    container: ast.AST | None = parents.get(id(stmt)) if stmt is not None else None
    while container is not None and not isinstance(container, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        container = parents.get(id(container))
    best: ast.Assign | None = None
    for node in ast.walk(container or tree):
        if isinstance(node, ast.Assign) and node.lineno < call.lineno and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name:
            if best is None or node.lineno > best.lineno:
                best = node
    return best


def _fix_sql(tree, lines, parents, call: ast.Call):
    if not call.args or len(call.args) > 1 or call.keywords:
        return None, ["Çağrı zaten parametre alıyor veya biçimi tanınmadı; metinsel öneri verildi."]
    placeholder = _sql_placeholder(tree, call)
    query_node = call.args[0]
    if isinstance(query_node, ast.Name):
        assign = _assignment_before(tree, parents, query_node.id, call)
        if assign is None:
            return None, ["Sorgu değişkeninin atandığı satır bulunamadı."]
        converted = _parameterize(assign.value, placeholder)
        if converted is None:
            return None, ["Sorgu ifadesi parametreli biçime çevrilemedi."]
        query, params = converted
        params_name = f"{query_node.id}_params"
        new_call = copy.deepcopy(call)
        new_call.args.append(ast.Name(params_name, ast.Load()))
        out = _replace_segment(lines, call, ast.unparse(new_call))  # önce sonraki satır
        out = _replace_segment(out, assign.value, ast.unparse(ast.Constant(query)))
        indent = re.match(r"\s*", out[assign.lineno - 1]).group(0)
        params_line = f"{indent}{params_name} = {ast.unparse(ast.Tuple(params, ast.Load()))}\n"
        end = assign.end_lineno or assign.lineno
        out = [*out[:end], params_line, *out[end:]]
        return out, [f"Yer tutucu '{placeholder}' seçildi; sürücünüz farklıysa (ör. psycopg %s, sqlite ?) uyarlayın."]
    converted = _parameterize(query_node, placeholder)
    if converted is None:
        return None, ["Sorgu ifadesi parametreli biçime çevrilemedi."]
    query, params = converted
    new_call = copy.deepcopy(call)
    new_call.args = [ast.Constant(query), ast.Tuple(params, ast.Load())]
    return _replace_segment(lines, call, ast.unparse(new_call)), [f"Yer tutucu '{placeholder}' seçildi; sürücünüze göre uyarlayın."]


_SHELL_META = re.compile(r"[|;&<>$`\\*?(){}\[\]!~\n]")


def _argv_from_template(expr: ast.AST) -> list[ast.expr] | None:
    """'convert {a} out.png' → ['convert', a, 'out.png']; yer tutucular tek başına simge olmalı."""
    parameterized = _parameterize(expr, "\x00")
    if parameterized is None:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str) and not _SHELL_META.search(expr.value):
            return [ast.Constant(token) for token in expr.value.split()]
        return None
    template, values = parameterized
    if _SHELL_META.search(template.replace("\x00", "")) or "'" in template or '"' in template:
        return None
    argv: list[ast.expr] = []
    value_index = 0
    for token in template.split():
        if token == "\x00":
            argv.append(values[value_index])
            value_index += 1
        elif "\x00" in token:
            return None  # yer tutucu bir simgenin parçası: güvenli bölünemez
        else:
            argv.append(ast.Constant(token))
    return argv if value_index == len(values) else None


def _fix_command(tree, lines, parents, call: ast.Call):
    name = _dotted(call.func)
    if not call.args:
        return None, []
    argv = _argv_from_template(call.args[0])
    if argv is None:
        return None, ["Komut metni güvenle argüman listesine bölünemedi (kabuk işleçleri veya bitişik değerler); elle düzeltin."]
    node = copy.deepcopy(call)
    notes = ["Kabuk kullanılmıyor: yönlendirme/boru (|, >) gerekiyorsa Python ile yapın."]
    if name in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}:
        node.func = ast.Attribute(ast.Name("subprocess", ast.Load()), "run", ast.Load())
        node.args = [ast.List(argv, ast.Load())]
        node.keywords = [ast.keyword("check", ast.Constant(False))]
        notes.append("os.system dönüş değeri yerine subprocess.run(...).returncode kullanılmalı.")
    else:
        node.args = [ast.List(argv, ast.Load()), *node.args[1:]]
        node.keywords = [k for k in node.keywords if k.arg != "shell"]
    out = _replace_segment(lines, call, ast.unparse(node))
    out, added = _with_import(out, tree, "subprocess")
    return out, notes


def _wrap_values(expr: ast.AST, wrap: Callable[[ast.expr], ast.expr]) -> ast.AST | None:
    """f-string/birleştirme içindeki değişken parçaları sarmala."""
    expr = copy.deepcopy(expr)
    changed = False
    if isinstance(expr, ast.JoinedStr):
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                value.value = wrap(value.value)
                changed = True
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        def walk(node: ast.AST) -> ast.AST:
            nonlocal changed
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                node.left = walk(node.left)  # type: ignore[assignment]
                node.right = walk(node.right)  # type: ignore[assignment]
                return node
            if isinstance(node, ast.Constant) or isinstance(node, ast.JoinedStr):
                if isinstance(node, ast.JoinedStr):
                    inner = _wrap_values(node, wrap)
                    if inner is not None:
                        changed = True
                        return inner
                return node
            changed = True
            return wrap(node)  # type: ignore[arg-type]
        expr = walk(expr)
    elif isinstance(expr, ast.expr) and not isinstance(expr, ast.Constant):
        return wrap(expr)
    return expr if changed else None


def _call(dotted: str, *args: ast.expr, **keywords: ast.expr) -> ast.Call:
    parts = dotted.split(".")
    func: ast.expr = ast.Name(parts[0], ast.Load())
    for part in parts[1:]:
        func = ast.Attribute(func, part, ast.Load())
    return ast.Call(func, list(args), [ast.keyword(k, v) for k, v in keywords.items()])


def _fix_simple_call(tree, lines, parents, call: ast.Call, transform: Callable[[ast.Call], list[str] | None],
                     imports: list[tuple[str, str | None]]):
    node = copy.deepcopy(call)
    notes = transform(node)
    if notes is None:
        return None, []
    out = _replace_segment(lines, call, ast.unparse(node))
    for module, name in imports:
        out, _ = _with_import(out, ast.parse("".join(out)), module, name)
    return out, notes


def _guard_before(tree, lines, parents, call: ast.Call, guard: list[str], arg_index: int, new_arg: str,
                  imports: list[tuple[str, str | None]], top: str | None = None):
    stmt = _statement_of(call, parents)
    node = copy.deepcopy(call)
    if arg_index < len(node.args):
        node.args[arg_index] = ast.Name(new_arg, ast.Load())
    out = _replace_segment(lines, call, ast.unparse(node))
    out = _insert_before(out, stmt, guard)
    for module, name in imports:
        out, _ = _with_import(out, ast.parse("".join(out)), module, name)
    if top and top.split("=")[0].strip() not in "".join(out):
        out = _insert_top(out, ast.parse("".join(out)), top)
    return out


_PY_SINK_PREDICATES: dict[str, Callable[[str, ast.Call], bool]] = {
    "sql": lambda n, c: n.rsplit(".", 1)[-1] in {"execute", "executemany", "raw", "read_sql", "read_sql_query", "executescript"},
    "command": lambda n, c: n in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
    or (n.rsplit(".", 1)[-1] in {"run", "call", "Popen", "check_output", "check_call"} and n.startswith(("subprocess", "run", "call", "Popen", "check_"))),
    "eval": lambda n, c: n in {"eval", "exec", "builtins.eval"},
    "deserialize": lambda n, c: n in {"pickle.loads", "pickle.load", "cPickle.loads", "dill.loads", "jsonpickle.decode",
                                      "yaml.load", "yaml.unsafe_load", "yaml.full_load", "numpy.load", "np.load", "torch.load",
                                      "marshal.loads"},
    "regex": lambda n, c: n.split(".")[0] in {"re", "regex"},
    "path": lambda n, c: n in {"open", "io.open", "codecs.open", "os.open", "send_file", "flask.send_file", "FileResponse",
                               "os.remove", "os.unlink", "shutil.rmtree", "os.path.exists", "os.listdir"} or n.endswith(".open"),
    "ssrf": lambda n, c: n.split(".")[0] in {"requests", "httpx", "urllib", "urlopen", "aiohttp"} or n == "urlopen",
    "redirect": lambda n, c: n.rsplit(".", 1)[-1] in {"redirect", "HttpResponseRedirect", "RedirectResponse"},
    "ldap": lambda n, c: n.rsplit(".", 1)[-1] in {"search", "search_s", "search_ext_s", "search_st"},
    "xpath": lambda n, c: n.rsplit(".", 1)[-1] in {"xpath", "XPath"},
    "log": lambda n, c: n.rsplit(".", 1)[-1] in {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"} or n == "print",
    "html": lambda n, c: n.rsplit(".", 1)[-1] in {"Markup", "mark_safe", "render_template_string", "make_response", "HTMLResponse"},
    "cookie": lambda n, c: n.endswith("set_cookie"),
}

_WEAK_RANDOM_REPLACEMENTS = {
    "random": "secrets.SystemRandom().random", "getrandbits": "secrets.randbits", "randbytes": "secrets.token_bytes",
    "choice": "secrets.choice", "randint": "secrets.SystemRandom().randint", "randrange": "secrets.randbelow",
    "uniform": "secrets.SystemRandom().uniform", "normalvariate": "secrets.SystemRandom().normalvariate",
    "sample": "secrets.SystemRandom().sample", "shuffle": "secrets.SystemRandom().shuffle",
}


def _python_fix(text: str, lines: list[str], line: int, kind: str, flow: dict[str, Any] | None):
    tree = ast.parse(text)
    parents = _parents(tree)
    if kind == "weakrand":
        target_line = int((flow or {}).get("source_line") or line)
        for call in _calls_on_line(tree, target_line):
            name = _dotted(call.func)
            if name.startswith("random.") and name.split(".", 1)[1] in _WEAK_RANDOM_REPLACEMENTS:
                replacement = _WEAK_RANDOM_REPLACEMENTS[name.split(".", 1)[1]]

                def swap(node: ast.Call, replacement: str = replacement) -> list[str]:
                    if replacement == "secrets.randbelow" and len(node.args) == 2:
                        return None  # randrange(a, b) karşılığı yok
                    node.func = ast.parse(replacement, mode="eval").body
                    return ["random modülü yerine secrets (CSPRNG) kullanıldı."]
                out, notes = _fix_simple_call(tree, lines, parents, call, swap, [("secrets", None)])
                if out is not None:
                    return out, notes, "yüksek"
        return None, ["random çağrısı kaynak satırda bulunamadı."], "düşük"
    if kind == "xxe":
        for index, raw in enumerate(lines):
            if re.search(r"setFeature\([^,]*feature_external_(?:ges|pes)\s*,\s*True\s*\)", raw):
                fixed = list(lines)
                fixed[index] = re.sub(r"(feature_external_(?:ges|pes)\s*,\s*)True", r"\1False", raw)
                return fixed, ["Dış genel/parametre varlıkları kapatıldı; mümkünse defusedxml kullanın."], "yüksek"
        for index, raw in enumerate(lines):
            if "resolve_entities=True" in raw or "no_network=False" in raw:
                fixed = list(lines)
                fixed[index] = raw.replace("resolve_entities=True", "resolve_entities=False").replace("no_network=False", "no_network=True")
                return fixed, ["lxml ayrıştırıcısında varlık çözümü kapatıldı."], "yüksek"
        return None, ["Ayrıştırıcı yapılandırması bulunamadı; defusedxml.ElementTree kullanın."], "düşük"
    if kind == "session":
        return None, ["Oturum için otomatik dönüşüm yok: değeri doğrulayan bir kontrol ekleyin."], "düşük"
    predicate = _PY_SINK_PREDICATES.get(kind)
    candidates = [c for c in _calls_on_line(tree, line) if predicate is None or predicate(_dotted(c.func), c)]
    # Rota dönüşü (return "<p>" + x) gibi çağrısız HTML hedefleri.
    if kind == "html":
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and node.lineno == line and node.value is not None:
                wrapped = _wrap_values(node.value, lambda e: _call("html.escape", e))
                if wrapped is not None:
                    out = _replace_segment(lines, node.value, ast.unparse(wrapped))
                    out, _ = _with_import(out, ast.parse("".join(out)), "html")
                    return out, ["Değişken parçalar html.escape ile kaçışlandı."], "yüksek"
    if not candidates:
        return None, ["Hedef çağrı bulgu satırında bulunamadı (dosya değişmiş olabilir)."], "düşük"
    call = candidates[0]
    name = _dotted(call.func)
    if kind == "sql":
        out, notes = _fix_sql(tree, lines, parents, call)
        return out, notes, "yüksek" if out else "düşük"
    if kind == "command":
        out, notes = _fix_command(tree, lines, parents, call)
        return out, notes, "orta" if out else "düşük"
    if kind == "eval":
        if name == "exec":
            return None, ["exec için güvenli karşılık yok: kodu veriyle değil, açık bir eşlemeyle seçin."], "düşük"

        def to_literal(node: ast.Call) -> list[str]:
            node.func = ast.Attribute(ast.Name("ast", ast.Load()), "literal_eval", ast.Load())
            node.args = node.args[:1]
            return ["Yalnız Python değişmezleri (sayı, dize, liste, sözlük) çözülür; ifade/kod çalışmaz."]
        out, notes = _fix_simple_call(tree, lines, parents, call, to_literal, [("ast", None)])
        return out, notes, "yüksek"
    if kind == "deserialize":
        def to_safe(node: ast.Call) -> list[str] | None:
            dotted = _dotted(node.func)
            if dotted.startswith("yaml."):
                node.func = ast.Attribute(ast.Name("yaml", ast.Load()), "safe_load", ast.Load())
                node.keywords = [k for k in node.keywords if k.arg != "Loader"]
                node.args = node.args[:1]
                return ["yaml.safe_load yalnız temel YAML türlerini oluşturur."]
            if dotted in {"numpy.load", "np.load"}:
                node.keywords = [k for k in node.keywords if k.arg != "allow_pickle"] + [ast.keyword("allow_pickle", ast.Constant(False))]
                return ["allow_pickle=False ile nesne dizileri reddedilir."]
            if dotted == "torch.load":
                node.keywords = [k for k in node.keywords if k.arg != "weights_only"] + [ast.keyword("weights_only", ast.Constant(True))]
                return ["weights_only=True yalnız tensör/ağırlık yükler."]
            if dotted.split(".")[0] in {"pickle", "cPickle", "dill", "jsonpickle"}:
                node.func = ast.Attribute(ast.Name("json", ast.Load()), "load" if dotted.endswith(".load") else "loads", ast.Load())
                node.args = node.args[:1]
                node.keywords = []
                return ["Veri biçimi JSON'a geçmeli: üreten taraf da json.dumps kullanmalı (biçim değişikliği)."]
            return None
        out, notes = _fix_simple_call(tree, lines, parents, call, to_safe, [("json", None)] if name.split(".")[0] in {"pickle", "cPickle", "dill", "jsonpickle"} else [])
        return out, notes, "orta" if out else "düşük"
    if kind == "regex":
        def escape(node: ast.Call) -> list[str] | None:
            if not node.args:
                return None
            node.args[0] = _call("re.escape", node.args[0])
            return ["Desen değişmez metin olarak aranır (özel karakterler kaçışlandı)."]
        out, notes = _fix_simple_call(tree, lines, parents, call, escape, [("re", None)])
        return out, notes, "yüksek" if out else "düşük"
    if kind == "log":
        def repr_values(node: ast.Call) -> list[str] | None:
            offset = 1 if _dotted(node.func).endswith(".log") else 0
            if len(node.args) <= offset:
                return None
            fmt = node.args[offset]
            if isinstance(fmt, ast.JoinedStr):
                for value in fmt.values:
                    if isinstance(value, ast.FormattedValue):
                        value.conversion = ord("r")
                return ["Değerler !r ile yazılır (satır sonu ve kontrol karakterleri kaçışlanır)."]
            if isinstance(fmt, ast.Constant) and isinstance(fmt.value, str) and "%s" in fmt.value:
                node.args[offset] = ast.Constant(fmt.value.replace("%s", "%r"))
                return ["%s yerine %r: değerler repr ile yazılır."]
            wrapped = _wrap_values(fmt, lambda e: _call("repr", e))
            if wrapped is None:
                return None
            node.args[offset] = wrapped  # type: ignore[assignment]
            return ["Değişken parçalar repr ile yazılır."]
        out, notes = _fix_simple_call(tree, lines, parents, call, repr_values, [])
        return out, notes, "yüksek" if out else "düşük"
    if kind == "html":
        def escape_html(node: ast.Call) -> list[str] | None:
            last = _dotted(node.func).rsplit(".", 1)[-1]
            if last in {"Markup", "mark_safe"} and node.args:
                node.args[0] = _call("html.escape", node.args[0])
                return ["Değer işaretlenmeden önce kaçışlandı."]
            if node.args:
                wrapped = _wrap_values(node.args[0], lambda e: _call("html.escape", e))
                if wrapped is not None:
                    node.args[0] = wrapped  # type: ignore[assignment]
                    return ["Değişken parçalar html.escape ile kaçışlandı."]
            return None
        out, notes = _fix_simple_call(tree, lines, parents, call, escape_html, [("html", None)])
        if out is None and name.endswith("render_template_string"):
            notes = ["render_template_string yerine sabit şablon dosyası + render_template(bağlam) kullanın."]
        return out, notes, "orta" if out else "düşük"
    if kind == "cookie":
        def secure(node: ast.Call) -> list[str]:
            node.keywords = [k for k in node.keywords if k.arg not in {"secure", "httponly", "samesite"}]
            node.keywords += [ast.keyword("secure", ast.Constant(True)), ast.keyword("httponly", ast.Constant(True)),
                              ast.keyword("samesite", ast.Constant("Lax"))]
            return ["Çerez yalnız HTTPS ile gönderilir ve betiklerden okunamaz."]
        out, notes = _fix_simple_call(tree, lines, parents, call, secure, [])
        return out, notes, "yüksek"
    if kind == "ldap":
        index = 1 if _dotted(call.func).rsplit(".", 1)[-1] in {"search", "search_paged"} else 2

        def escape_filter(node: ast.Call) -> list[str] | None:
            if index >= len(node.args):
                return None
            wrapped = _wrap_values(node.args[index], lambda e: _call("escape_filter_chars", e))
            if wrapped is None:
                return None
            node.args[index] = wrapped  # type: ignore[assignment]
            return ["Filtre değerleri escape_filter_chars ile kaçışlandı (python-ldap: ldap.filter.escape_filter_chars)."]
        out, notes = _fix_simple_call(tree, lines, parents, call, escape_filter, [("ldap3.utils.conv", "escape_filter_chars")])
        return out, notes, "yüksek" if out else "düşük"
    if kind == "xpath":
        def bind(node: ast.Call) -> list[str] | None:
            if not node.args or not isinstance(node.args[0], ast.JoinedStr) or not _dotted(node.func).endswith(".xpath"):
                return None
            parameterized = _parameterize(node.args[0], "\x00")
            if parameterized is None:
                return None
            template, values = parameterized
            pieces = template.split("\x00")
            expr = ""
            for i, piece in enumerate(pieces):
                expr += piece
                if i < len(values):
                    expr += f"$p{i}"
                    node.keywords.append(ast.keyword(f"p{i}", values[i]))
            node.args[0] = ast.Constant(expr)
            return ["Değerler XPath değişkeni olarak bağlandı (lxml .xpath(..., ad=değer))."]
        out, notes = _fix_simple_call(tree, lines, parents, call, bind, [])
        if out is None:
            notes = ["XPath ifadesini sabit tutup değeri değişken olarak bağlayın (lxml) veya kaçışlayın."]
        return out, notes, "yüksek" if out else "düşük"
    if kind == "path":
        arg = call.args[0] if call.args else None
        base: ast.expr | None = None
        if isinstance(arg, ast.Call) and _dotted(arg.func) in {"os.path.join", "posixpath.join"} and len(arg.args) >= 2:
            base = arg.args[0]
        elif isinstance(arg, ast.JoinedStr) and arg.values and isinstance(arg.values[0], ast.FormattedValue):
            base = arg.values[0].value
        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Div):
            base = arg.left
        if arg is None or base is None:
            return None, ["Kök dizin belirlenemedi; yolu realpath ile çözüp izinli kök altında olduğunu doğrulayın."], "düşük"
        base_src, arg_src = ast.unparse(base), ast.unparse(arg)
        guard = [
            f"_guvenli_kok = os.path.realpath({base_src})",
            f"_guvenli_yol = os.path.realpath({arg_src})",
            "if os.path.commonpath([_guvenli_kok, _guvenli_yol]) != _guvenli_kok:",
            "    raise ValueError('İzin verilen dizin dışında dosya yolu')",
        ]
        out = _guard_before(tree, lines, parents, call, guard, 0, "_guvenli_yol", [("os", None)])
        return out, ["Çözümlenmiş yol kök dizin dışındaysa istek reddedilir."], "orta"
    if kind == "ssrf":
        arg = call.args[1] if _dotted(call.func).endswith(".request") and len(call.args) > 1 else (call.args[0] if call.args else None)
        if arg is None:
            url_kw = next((k.value for k in call.keywords if k.arg == "url"), None)
            if url_kw is None:
                return None, ["URL argümanı bulunamadı."], "düşük"
            arg = url_kw
        guard = [
            f"_hedef_url = {ast.unparse(arg)}",
            "if urllib.parse.urlsplit(_hedef_url).hostname not in IZINLI_ANA_MAKINELER:",
            "    raise ValueError('İzin verilmeyen hedef ana makine')",
        ]
        index = 1 if _dotted(call.func).endswith(".request") and len(call.args) > 1 else 0
        if not call.args:
            return None, ["URL anahtar sözcük olarak verilmiş; korumayı elle ekleyin."], "düşük"
        out = _guard_before(tree, lines, parents, call, guard, index, "_hedef_url", [("urllib.parse", None)],
                            top="IZINLI_ANA_MAKINELER = frozenset({'api.ornek.com'})  # TODO: gerçek izinli ana makineler")
        return out, ["IZINLI_ANA_MAKINELER listesini gerçek hedeflerle doldurun; DNS sonrası iç adres denetimi de önerilir."], "orta"
    if kind == "redirect":
        if not call.args:
            return None, [], "düşük"
        guard = [
            f"_hedef = {ast.unparse(call.args[0])}",
            "if not isinstance(_hedef, str) or not _hedef.startswith('/') or _hedef.startswith('//') or urllib.parse.urlsplit(_hedef).netloc:",
            "    _hedef = '/'",
        ]
        out = _guard_before(tree, lines, parents, call, guard, 0, "_hedef", [("urllib.parse", None)])
        return out, ["Yalnız aynı sitedeki göreli yollara yönlendirilir."], "yüksek"
    return None, [], "düşük"


# ---------------------------------------------------------------------------
# JavaScript / TypeScript (satır düzeyi)
# ---------------------------------------------------------------------------


def _split_template(literal: str) -> tuple[list[str], list[str]] | None:
    """`a ${x} b` → (['a ', ' b'], ['x'])."""
    if not (literal.startswith("`") and literal.endswith("`")):
        return None
    body = literal[1:-1]
    texts: list[str] = []
    exprs: list[str] = []
    current = ""
    i = 0
    while i < len(body):
        if body.startswith("${", i):
            depth, j = 1, i + 2
            while j < len(body) and depth:
                depth += {"{": 1, "}": -1}.get(body[j], 0)
                j += 1
            if depth:
                return None
            texts.append(current)
            exprs.append(body[i + 2:j - 1].strip())
            current = ""
            i = j
        else:
            current += body[i]
            i += 1
    texts.append(current)
    return texts, exprs


def _find_call_args(line: str, names: tuple[str, ...]) -> tuple[int, int, str] | None:
    """Satırdaki ilk eşleşen çağrının argüman metni (başlangıç, bitiş, metin)."""
    match = re.search(r"(?:\.|\b)(" + "|".join(re.escape(n) for n in names) + r")\s*\(", line)
    if not match:
        return None
    start = match.end()
    depth, i, quote = 1, start, ""
    while i < len(line) and depth:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        i += 1
    if depth:
        return None
    return start, i - 1, line[start:i - 1]


def _first_arg(args: str) -> tuple[str, str]:
    depth, quote = 0, ""
    for i, ch in enumerate(args):
        if quote:
            if ch == quote and args[i - 1] != "\\":
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return args[:i].strip(), args[i:]
    return args.strip(), ""


def _js_parameterize(arg: str, numbered: bool) -> tuple[str, list[str]] | None:
    template = _split_template(arg)
    if template is None:
        parts = [p.strip() for p in re.split(r"\s\+\s", arg)]
        texts, exprs = [], []
        current = ""
        for part in parts:
            if re.fullmatch(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", part):
                current += part[1:-1]
            else:
                texts.append(current)
                exprs.append(part)
                current = ""
        texts.append(current)
        if not exprs:
            return None
    else:
        texts, exprs = template
        if not exprs:
            return None
    texts = list(texts)
    for i in range(len(exprs)):
        # '${x}' → ? : yer tutucuyu saran tırnakları kaldır.
        if texts[i].endswith(("'", '"')) and texts[i + 1][:1] == texts[i][-1]:
            texts[i] = texts[i][:-1]
            texts[i + 1] = texts[i + 1][1:]
    query = ""
    for i, text in enumerate(texts):
        query += text
        if i < len(exprs):
            query += f"${i + 1}" if numbered else "?"
    return query, exprs


def _js_fix(text: str, lines: list[str], line: int, kind: str):
    raw = lines[line - 1]
    newline = "\n" if raw.endswith("\n") else ""
    body = raw[:-1] if newline else raw
    indent = re.match(r"\s*", body).group(0)
    out = list(lines)
    if kind == "sql":
        found = _find_call_args(body, ("query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe"))
        if found is None:
            return None, ["Sorgu çağrısı satırda bulunamadı."], "düşük"
        start, end, args = found
        first, rest = _first_arg(args)
        numbered = bool(re.search(r"require\(['\"]pg['\"]\)|from ['\"]pg['\"]|postgres", text))
        converted = _js_parameterize(first, numbered)
        # Kalan argüman yalnız geri çağrıysa (query(sql, cb)) değerler araya eklenir: query(sql, [..], cb).
        # İkinci argüman zaten dizi/nesne ise sorgu parametre alıyordur; dokunulmaz.
        tail = rest.strip()
        callback_only = tail.startswith(",") and not tail[1:].lstrip().startswith(("[", "{"))
        if converted is None or (tail and not callback_only):
            return None, ["Sorgu parametreli biçime çevrilemedi (zaten parametre alıyor olabilir)."], "düşük"
        query, exprs = converted
        replacement = f"{_js_quote(query)}, [{', '.join(exprs)}]" + (rest if callback_only else "")
        out[line - 1] = body[:start] + replacement + body[end:] + newline
        return out, [f"Yer tutucular: {'$1, $2 (pg)' if numbered else '? (mysql/sqlite)'}; sürücünüze göre uyarlayın."], "yüksek"
    if kind == "command":
        found = _find_call_args(body, ("execSync", "exec"))
        if found is None:
            return None, ["exec çağrısı bulunamadı."], "düşük"
        start, end, args = found
        first, rest = _first_arg(args)
        template = _split_template(first)
        if template is None:
            return None, ["Komut şablonu çözülemedi; execFile ile argüman dizisi kullanın."], "düşük"
        texts, exprs = template
        joined = "\x00".join(texts)
        if _SHELL_META.search(joined.replace("\x00", "")) or "'" in joined or '"' in joined:
            return None, ["Kabuk işleçleri var; elle execFile'a çevirin."], "düşük"
        tokens = joined.split()
        argv: list[str] = []
        index = 0
        for token in tokens:
            if token == "\x00":
                argv.append(exprs[index]); index += 1
            elif "\x00" in token:
                return None, ["Değer bir simgenin parçası; güvenli bölünemez."], "düşük"
            else:
                argv.append(_js_quote(token))
        if index != len(exprs) or not argv or not argv[0].startswith("'"):
            return None, ["Program adı sabit değil; elle düzeltin."], "düşük"
        name_start = body.rfind("exec", 0, start)
        sync = body[name_start:start].startswith("execSync")
        func = "execFileSync" if sync else "execFile"
        out[line - 1] = body[:name_start] + f"{func}({argv[0]}, [{', '.join(argv[1:])}]{rest})" + body[end + 1:] + newline
        return out, [f"child_process.{func} kabuk kullanmaz; içe aktarmaya {func} ekleyin."], "orta"
    if kind == "html":
        if re.search(r"\.innerHTML\s*=", body):
            out[line - 1] = re.sub(r"\.innerHTML(\s*=)", r".textContent\1", body, count=1) + newline
            return out, ["HTML yerine düz metin atanır."], "yüksek"
        found = _find_call_args(body, ("send", "write", "end"))
        if found is not None:
            start, end, args = found
            first, rest = _first_arg(args)
            template = _split_template(first)
            if template is not None and template[1]:
                texts, exprs = template
                literal = "`" + "".join(t + (f"${{escapeHtml({e})}}" if i < len(exprs) else "") for i, (t, e) in
                                        enumerate(zip(texts, [*exprs, ""]))) + "`"
                out[line - 1] = body[:start] + literal + rest + body[end:] + newline
                return out, ["escapeHtml için 'escape-html' paketini içe aktarın."], "orta"
        return None, ["HTML hedefi otomatik çevrilemedi; textContent veya DOMPurify kullanın."], "düşük"
    if kind == "eval":
        if re.search(r"\beval\s*\(", body):
            out[line - 1] = re.sub(r"\beval\s*\(", "JSON.parse(", body, count=1) + newline
            return out, ["Yalnız JSON verisi çözülür; kod çalışmaz."], "yüksek"
        return None, ["eval/Function için güvenli karşılık: açık eşleme veya JSON.parse."], "düşük"
    if kind == "deserialize":
        if re.search(r"\bunserialize\s*\(", body):
            out[line - 1] = re.sub(r"(?:\w+\.)?unserialize\s*\(", "JSON.parse(", body, count=1) + newline
            return out, ["node-serialize yerine JSON (işlev içeren veri reddedilir)."], "yüksek"
        return None, [], "düşük"
    if kind == "path":
        joined = re.search(r"path\.join\(([^,()]+),\s*([^()]+?)\)", body)
        if joined:
            out[line - 1] = body[:joined.start()] + f"path.join({joined.group(1)}, path.basename({joined.group(2).strip()}))" + body[joined.end():] + newline
            return out, ["Dosya adı basename ile indirgenir; alt dizin gerekiyorsa realpath + kök kontrolü ekleyin."], "orta"
        return None, ["Kök dizin belirlenemedi; path.resolve ile kökün altında kaldığını doğrulayın."], "düşük"
    if kind == "redirect":
        found = _find_call_args(body, ("redirect",))
        if found is None:
            return None, [], "düşük"
        start, end, args = found
        first, rest = _first_arg(args)
        target = first if not rest else _first_arg(rest[1:])[0]
        guard = [f"{indent}const hedef = {target};\n",
                 f"{indent}if (typeof hedef !== 'string' || !/^\\/(?!\\/)/.test(hedef)) {{ return res.status(400).send('Geçersiz yönlendirme'); }}\n"]
        new_args = args.replace(target, "hedef", 1)
        out[line - 1:line] = [*guard, body[:start] + new_args + body[end:] + newline]
        return out, ["Yalnız aynı sitedeki göreli yollara yönlendirilir."], "orta"
    if kind == "ssrf":
        found = _find_call_args(body, ("fetch", "get", "post", "request", "axios"))
        if found is None:
            return None, [], "düşük"
        start, end, args = found
        first, rest = _first_arg(args)
        guard = [f"{indent}const hedefUrl = new URL({first});\n",
                 f"{indent}if (!IZINLI_ANA_MAKINELER.has(hedefUrl.hostname)) {{ throw new Error('İzin verilmeyen hedef ana makine'); }}\n"]
        out[line - 1:line] = [*guard, body[:start] + "hedefUrl.toString()" + rest + body[end:] + newline]
        return out, ["IZINLI_ANA_MAKINELER = new Set(['api.ornek.com']) tanımını ekleyin."], "orta"
    return None, ["Bu tür için JS'te otomatik dönüşüm yok; genel öneriyi uygulayın."], "düşük"


def _js_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


TEXT_SNIPPETS: dict[tuple[str, str], str] = {
    ("python", "sql"): "cursor.execute(\"SELECT * FROM kullanici WHERE ad = ?\", (ad,))",
    ("python", "command"): "subprocess.run([\"convert\", dosya, \"cikti.png\"], check=True)",
    ("python", "eval"): "deger = ast.literal_eval(metin)",
    ("python", "deserialize"): "veri = json.loads(govde)  # veya yaml.safe_load(govde)",
    ("python", "html"): "return f\"<p>{html.escape(ad)}</p>\"",
    ("python", "path"): "yol = os.path.realpath(os.path.join(KOK, os.path.basename(ad)))\nif os.path.commonpath([KOK, yol]) != KOK:\n    raise ValueError('geçersiz yol')",
    ("python", "ssrf"): "if urllib.parse.urlsplit(url).hostname not in IZINLI_ANA_MAKINELER:\n    raise ValueError('izin verilmeyen hedef')",
    ("python", "redirect"): "if not hedef.startswith('/') or hedef.startswith('//'):\n    hedef = '/'",
    ("python", "ldap"): "filtre = f\"(uid={escape_filter_chars(kullanici)})\"",
    ("python", "xpath"): "kok.xpath(\"//kullanici[@id=$kimlik]\", kimlik=deger)",
    ("python", "xxe"): "import defusedxml.ElementTree as ET\nagac = ET.fromstring(xml_metni)",
    ("python", "session"): "if not re.fullmatch(r\"[A-Za-z0-9_-]{1,64}\", deger):\n    abort(400)\nsession['kullanici'] = deger",
    ("python", "log"): "logger.info(\"kullanıcı: %r\", ad)",
    ("python", "regex"): "re.search(re.escape(aranan), metin)",
    ("python", "cookie"): "yanit.set_cookie('oturum', deger, secure=True, httponly=True, samesite='Lax')",
    ("python", "weakrand"): "belirtec = secrets.token_urlsafe(32)",
    ("javascript", "sql"): "await pool.query('SELECT * FROM kullanici WHERE ad = $1', [ad]);",
    ("javascript", "command"): "execFile('convert', [dosya, 'cikti.png'], callback);",
    ("javascript", "eval"): "const deger = JSON.parse(metin);",
    ("javascript", "html"): "el.textContent = deger;",
    ("javascript", "path"): "const yol = path.resolve(KOK, path.basename(ad));\nif (!yol.startsWith(KOK + path.sep)) throw new Error('geçersiz yol');",
    ("javascript", "redirect"): "if (!/^\\/(?!\\/)/.test(hedef)) return res.status(400).end();\nres.redirect(hedef);",
    ("javascript", "ssrf"): "const u = new URL(adres);\nif (!IZINLI.has(u.hostname)) throw new Error('izin verilmeyen hedef');",
    ("javascript", "deserialize"): "const veri = JSON.parse(govde);",
}
