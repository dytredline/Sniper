"""Sunucu tarafı görünüm şablonları (EJS / Pug / Handlebars / Nunjucks): kaçışsız çıktı alanları ve görünüm adı çözümü.

``res.render('urunler', { q })`` çağrısında şablon dosyası görünüm adından bulunur ve şablonda kaçışsız
basılan (EJS ``<%- x %>``, Pug ``!{x}`` / ``etiket!= x``, Handlebars ``{{{x}}}``, Nunjucks ``{{ x | safe }}``) yerel değişken yolları
çıkarılır; taint motoru (:mod:`taint_js_ast`) bu yolların değerini ``render`` argümanından izler.
Kaçışlı çıktı (``<%= %>``, ``#{}`` / ``=``, ``{{ }}``) HTML bağlamında güvenlidir ve raporlanmaz; yalnız
``<script>`` öğesi içinde tırnak dışında kalan kaçışlı çıktı (HTML kaçışı JavaScript'i korumaz) raporlanır.

Şablon metni çalıştırılmaz; yalnız düzenli ifadelerle okunur.
"""

from __future__ import annotations

from pathlib import PurePosixPath
import posixpath
import re

TEMPLATE_EXTS = (".ejs", ".pug", ".jade", ".hbs", ".handlebars", ".njk", ".nunjucks")
# Nunjucks çoğunlukla .html uzantılı şablon kullanır: yalnız projede nunjucks motoru görülürse görünüm sayılır.
NUNJUCKS_HTML_EXTS = (".html", ".htm")
MAX_OUTPUTS = 200

_EJS_RAW_RE = re.compile(r"<%-(.*?)[-_]?%>", re.S)
_PUG_RAW_INLINE_RE = re.compile(r"!\{([^}\n]*)\}")
# `h1!= ifade`, `p.sinif#kimlik(oznitelik)!= ifade`, `!= ifade` (koşul satırlarındaki `a != b` eşleşmez:
# etiket adı ile `!=` arasında boşluk olamaz).
_PUG_RAW_LINE_RE = re.compile(r"^[ \t]*(?:[A-Za-z][\w:-]*)?(?:[#.][\w-]+)*(?:\([^)\n]*\))?!=[ \t]*(\S.*)$", re.M)
_HBS_RAW_RE = re.compile(r"\{\{\{~?(.*?)~?\}\}\}", re.S)
# Nunjucks: {{ ifade | safe }} (son süzgeç safe) kaçışsız basar; {% autoescape false %} bloğu tümüyle kaçışsızdır.
_NJK_OUT_RE = re.compile(r"\{\{-?(.*?)-?\}\}", re.S)
_NJK_AUTOESCAPE_OFF_RE = re.compile(r"\{%-?\s*autoescape\s+false\s*-?%\}(.*?)\{%-?\s*endautoescape\s*-?%\}", re.S)
# Betik (script) öğesi içindeki KAÇIŞLI çıktı: HTML kaçışı JavaScript bağlamını korumaz (``script #{x}`` →
# alert(1) gibi metin HTML özel karakteri içermeden kod olur). Tırnak içindeki değer (var a = "<%= x %>")
# kaçış tırnakları da kodladığı için dizeden çıkamaz; yalnız tırnak dışı konumlar raporlanır.
_PUG_SCRIPT_LINE_RE = re.compile(r"^([ \t]*)script(?:[#.][\w-]+)*(?:\([^)\n]*\))?(\.?)[ \t]*(.*)$", re.M)
_PUG_ESC_INLINE_RE = re.compile(r"#\{([^}\n]*)\}")
_SCRIPT_BLOCK_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)(?![^>]*type\s*=\s*[\"']?(?:text/(?:template|x-template|html)|application/(?:ld\+)?json))[^>]*>(.*?)</script\s*>", re.S | re.I)
_EJS_ESC_RE = re.compile(r"<%=(.*?)[-_]?%>", re.S)
_HBS_ESC_RE = re.compile(r"(?<!\{)\{\{(?!\{)~?([^{}]*?)~?\}\}(?!\})")
_STRING_RE = re.compile(r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\])*`")
# Kök ad + nokta zinciri; başka bir ifadenin özelliği (`a.b` içindeki `b`, `x[i].ad`) kök sayılmaz.
_PATH_RE = re.compile(r"(?<![\w$.\])])\s*([A-Za-z_$][\w$]*)((?:\s*\.\s*[A-Za-z_$][\w$]*)*)")
_SAFE_CALL_RE = re.compile(r"(?i)(?:escape\w*|encode\w*|sanitiz\w*|purify|xss|htmlEscape|DOMPurify\.\w+|JSON\.stringify|\w*[Ss]afe\w*)\s*\(")
_WORDS = frozenset({
    "typeof", "true", "false", "null", "undefined", "this", "new", "in", "instanceof", "void", "if", "else",
    "return", "function", "var", "let", "const", "of", "and", "or", "not", "each", "with", "unless", "lookup",
    "locals", "include", "includes",
})
# Sayı/boolean döndüren üyeler: değer HTML taşıyamaz.
_NUMERIC_MEMBERS = frozenset({
    "length", "size", "byteLength", "includes", "startsWith", "endsWith", "indexOf", "lastIndexOf", "test", "has",
    "toFixed", "getTime", "valueOf",
})


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def expression_paths(expression: str) -> list[tuple[str, ...]]:
    """Şablon ifadesindeki yerel değişken yolları: ``a.b + c`` → [("a", "b"), ("c",)]."""
    stripped = _STRING_RE.sub(" ", expression)
    if _SAFE_CALL_RE.search(stripped):
        return []
    paths: list[tuple[str, ...]] = []
    for match in _PATH_RE.finditer(stripped):
        root = match.group(1)
        if root in _WORDS:
            continue
        rest = [part.strip() for part in match.group(2).split(".")[1:]]
        parts = (root, *rest)
        if any(part in _NUMERIC_MEMBERS for part in parts[1:]):
            continue
        tail = stripped[match.end():].lstrip()
        if tail.startswith("(") and not rest:
            continue  # yardımcı fonksiyon adı (ör. marked(...)): argümanları ayrıca eşleşir
        if tail.startswith("(") and rest:
            parts = parts[:-1]  # q.trim() → q
        if parts and parts not in paths:
            paths.append(parts)
    return paths


def _hbs_paths(expression: str) -> list[tuple[str, ...]]:
    stripped = _STRING_RE.sub(" ", expression.strip())
    if not stripped or stripped[0] in "#/^!>&" or stripped.startswith("else"):
        return []
    paths: list[tuple[str, ...]] = []
    tokens = stripped.split()
    if len(tokens) > 1 and re.fullmatch(r"(?i)\w*(?:escape|encode|sanitiz|purify|safe)\w*", tokens[0]):
        return []
    for token in tokens:
        if "=" in token:
            token = token.split("=", 1)[1]
        token = token.strip("()")
        if token.startswith("@root."):
            token = token[len("@root."):]
        while token.startswith("../"):
            token = token[3:]
        if token.startswith("this."):
            token = token[5:]
        if not re.fullmatch(r"[A-Za-z_$][\w$-]*(?:\.[A-Za-z_$][\w$-]*)*", token) or token in _WORDS:
            continue
        parts = tuple(token.split("."))
        if any(part in _NUMERIC_MEMBERS for part in parts[1:]):
            continue
        if parts not in paths:
            paths.append(parts)
    return paths


def unescaped_outputs(relpath: str, text: str) -> list[tuple[int, str, list[tuple[str, ...]]]]:
    """Kaçışsız çıktı alanları: [(satır, kısa gösterim, yerel değişken yolları)]."""
    suffix = PurePosixPath(relpath).suffix.lower()
    found: list[tuple[int, str, list[tuple[str, ...]]]] = []

    def add(offset: int, shown: str, paths: list[tuple[str, ...]]) -> None:
        if paths and len(found) < MAX_OUTPUTS:
            found.append((_line_at(text, offset), shown, paths))

    def unquoted(line_text: str, column: int) -> bool:
        """Konumdan önceki satır parçasında açık (kapanmamış) tırnak yoksa True."""
        before = _STRING_RE.sub("", line_text[:column])
        return not any(quote in before for quote in "'\"`")

    if suffix == ".ejs":
        for block in _SCRIPT_BLOCK_RE.finditer(text):
            for match in _EJS_ESC_RE.finditer(block.group(1)):
                offset = block.start(1) + match.start()
                line_start = text.rfind("\n", 0, offset) + 1
                if unquoted(text[line_start:offset], offset - line_start):
                    expression = match.group(1).strip()
                    add(offset, "<script> … <%= " + expression[:50] + " %>", expression_paths(expression))
        for match in _EJS_RAW_RE.finditer(text):
            expression = match.group(1).strip()
            if re.match(r"(?:include|partial|block|layout)\b", expression):
                continue
            add(match.start(), "<%- " + expression[:60] + " %>", expression_paths(expression))
    elif suffix in {".pug", ".jade"}:
        for match in _PUG_RAW_INLINE_RE.finditer(text):
            add(match.start(), "!{" + match.group(1).strip()[:60] + "}", expression_paths(match.group(1)))
        for match in _PUG_RAW_LINE_RE.finditer(text):
            expression = match.group(1)
            add(match.start(1), "!= " + expression.strip()[:60], expression_paths(expression))
        lines = text.split("\n")
        offsets = [0]
        for line_text in lines[:-1]:
            offsets.append(offsets[-1] + len(line_text) + 1)
        for match in _PUG_SCRIPT_LINE_RE.finditer(text):
            indent, block, inline = match.group(1), match.group(2), match.group(3)
            first = _line_at(text, match.start()) - 1
            body = [(first, match.start(3) - offsets[first], inline)] if inline and not block else []
            if block:
                for index in range(first + 1, len(lines)):
                    current = lines[index]
                    if current.strip() and len(current) - len(current.lstrip()) <= len(indent):
                        break
                    body.append((index, 0, current))
            for index, start, line_text in body:
                for inner in _PUG_ESC_INLINE_RE.finditer(line_text):
                    if unquoted(line_text, inner.start()):
                        add(offsets[index] + start + inner.start(), "script #{" + inner.group(1).strip()[:50] + "}",
                            expression_paths(inner.group(1)))
    elif suffix in {".njk", ".nunjucks"} or suffix in NUNJUCKS_HTML_EXTS:
        off = [(m.start(1), m.end(1)) for m in _NJK_AUTOESCAPE_OFF_RE.finditer(text)]
        for match in _NJK_OUT_RE.finditer(text):
            filters = [part.strip() for part in _STRING_RE.sub(" ", match.group(1)).split("|")]
            raw = filters[-1] == "safe" if len(filters) > 1 else False
            if not raw and not any(lo <= match.start() < hi for lo, hi in off):
                continue
            expression = match.group(1).split("|", 1)[0]
            add(match.start(), "{{ " + match.group(1).strip()[:60] + " }}", expression_paths(expression))
    elif suffix in {".hbs", ".handlebars"}:
        for match in _HBS_RAW_RE.finditer(text):
            expression = match.group(1)
            add(match.start(), "{{{" + expression.strip()[:60] + "}}}", _hbs_paths(expression))
        for block in _SCRIPT_BLOCK_RE.finditer(text):
            for match in _HBS_ESC_RE.finditer(block.group(1)):
                offset = block.start(1) + match.start()
                line_start = text.rfind("\n", 0, offset) + 1
                if unquoted(text[line_start:offset], offset - line_start):
                    add(offset, "<script> … {{" + match.group(1).strip()[:50] + "}}", _hbs_paths(match.group(1)))
    return found


def _normal(path: str) -> str | None:
    normal = posixpath.normpath(path.strip("/") or ".")
    if normal == "." or normal == ".." or normal.startswith("../"):
        return None
    return normal


def resolve_view(view: str, module_relpath: str, inventory: frozenset[str], view_dirs: list[str],
                 engines: list[str]) -> str | None:
    """Görünüm adı → şablonun proje içi göreli yolu (bulunamaz ya da belirsizse None).

    ``view_dirs``: ``app.set('views', …)`` ile bildirilen proje köküne göre dizinler; yoksa ``views``/
    ``templates`` adlı dizinlerde aranır. Birden çok aday kalırsa çağıran modüle en yakın olan seçilir."""
    if not view or view.startswith(("/", "\\")) or "\0" in view or len(view) > 200:
        return None
    suffix = PurePosixPath(view).suffix.lower()
    if suffix in TEMPLATE_EXTS:
        names = [view]
    else:
        exts = [("." + engine.lstrip(".")).lower() for engine in engines if engine]
        exts += [ext for ext in TEMPLATE_EXTS if ext not in exts]
        names = [view + ext for ext in exts]
        if suffix in NUNJUCKS_HTML_EXTS:
            if "nunjucks" not in engines:
                return None
            names = [view]
    for directory in view_dirs:
        for name in names:
            candidate = _normal(f"{directory}/{name}")
            if candidate is not None and candidate in inventory:
                return candidate
    for name in names:
        normal_name = _normal(name)
        if normal_name is None:
            return None
        matches = sorted(
            path for path in inventory
            if path == f"views/{normal_name}" or path.endswith(f"/views/{normal_name}")
            or path == f"templates/{normal_name}" or path.endswith(f"/templates/{normal_name}")
        )
        if not matches:
            continue
        if len(matches) == 1:
            return matches[0]
        module_parts = PurePosixPath(module_relpath).parent.parts

        def closeness(path: str) -> int:
            # Şablon dizininin (views/templates) üst dizini modülün atası olmalı; en derin ata kazanır.
            parts = PurePosixPath(path).parts
            base = parts[: parts.index("views") if "views" in parts else parts.index("templates")]
            return len(base) if module_parts[: len(base)] == base else -1

        best = max(closeness(path) for path in matches)
        top = [path for path in matches if closeness(path) == best]
        return top[0] if len(top) == 1 and best >= 0 else None
    return None
