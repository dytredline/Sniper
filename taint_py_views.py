"""Python sunucu tarafı şablonları (Django / Jinja2): kaçışsız çıktı alanları ve şablon adı çözümü.

Django ve Flask/Jinja2 şablonları HTML bağlamında varsayılan olarak kaçışlıdır; yalnız açıkça kaçışı kapatan
çıktılar raporlanır:

* ``{{ x|safe }}`` / ``{{ x|safeseq }}`` (Django ve Jinja2),
* ``{% autoescape off %}`` (Django) / ``{% autoescape false %}`` (Jinja2) bloğu içindeki ``{{ x }}``,
* kaçışlı ama değerin tamamı ``href``/``src``/``action`` gibi URL özniteliği olan çıktı (``javascript:`` adresi):
  yalnız istek verisi için (``url_attribute`` işaretli; çağıran saklı veride kullanmaz).

``escape``/``force_escape``/``urlencode``/``escapejs``/``json_script``/sayısal süzgeçlerden geçen değer
güvenli sayılır. Şablon metni çalıştırılmaz; yalnız düzenli ifadelerle okunur. ``{% extends %}`` ve
``{% include %}`` ile bağlanan şablonların çıktıları da (en çok 6 düzey) toplanır.
"""

from __future__ import annotations

from pathlib import PurePosixPath
import posixpath
import re

TEMPLATE_EXTS = (".html", ".htm", ".jinja", ".jinja2", ".j2", ".djhtml", ".xml", ".txt")
TEMPLATE_DIR_NAMES = frozenset({"templates", "jinja2", "template"})
MAX_OUTPUTS = 300
MAX_DEPTH = 6

_TOKEN_RE = re.compile(r"\{%-?\s*(.*?)\s*-?%\}|\{\{-?\s*(.*?)\s*-?\}\}|\{#.*?#\}", re.S)
_STRING_RE = re.compile(r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"")
_SUBSCRIPT_KEY_RE = re.compile(r"\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]")
_SUBSCRIPT_RE = re.compile(r"\[[^\[\]]*\]")
_KWARG_RE = re.compile(r"\b[A-Za-z_]\w*\s*=(?!=)")
_PATH_RE = re.compile(r"(?<![\w.\])'\"])([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*|\.\d+)*)")
_URL_ATTR_RE = re.compile(r"(?i)\b(?:href|src|action|formaction|data|poster|xlink:href)\s*=\s*[\"']?\s*$")
# Kaçışlayan ya da değeri HTML taşıyamayan (sayı/tarih/boolean) süzgeçler.
_ESCAPING_FILTERS = frozenset({
    "escape", "e", "force_escape", "escapejs", "urlencode", "iriencode", "json_script", "tojson", "length", "count",
    "wordcount", "date", "time", "timesince", "timeuntil", "filesizeformat", "floatformat", "int", "float", "round",
    "yesno", "pluralize", "intcomma", "intword", "naturaltime", "naturalday", "ordinal", "abs", "add_class",
    "slugify", "first_letter", "divisibleby", "get_digit", "length_is", "phone2numeric", "xmlattr", "filesize",
})
_RAW_FILTERS = frozenset({"safe", "safeseq"})
_WORDS = frozenset({
    "and", "or", "not", "in", "is", "if", "else", "elif", "true", "false", "none", "True", "False", "None",
    "loop", "forloop", "block", "super", "self", "varargs", "kwargs", "caller", "range", "dict", "lipsum",
    "csrf_token", "csrf_input", "static", "url_for", "url", "config", "g", "get_flashed_messages", "perms",
    "messages", "LANGUAGE_CODE", "LANGUAGE_BIDI", "STATIC_URL", "MEDIA_URL", "debug", "sql_queries",
})
_NUMERIC_MEMBERS = frozenset({"id", "pk", "count", "length", "size", "is_authenticated", "is_staff", "is_superuser",
                              "is_active", "created", "updated", "created_at", "updated_at", "date", "year", "month"})
_FOR_RE = re.compile(r"for\s+([A-Za-z_][\w\s,()]*?)\s+in\s+(.+?)(?:\s+if\s+.*|\s+recursive)?$", re.S)
_WITH_PAIR_RE = re.compile(r"([A-Za-z_]\w*)\s*=\s*([^\s=]+(?:\s*\|\s*[^\s=]+)*)")
_WITH_AS_RE = re.compile(r"(.+?)\s+as\s+([A-Za-z_]\w*)$")
_SET_RE = re.compile(r"set\s+([A-Za-z_]\w*)\s*=\s*(.+)$", re.S)
_NAME_ARG_RE = re.compile(r"^(?:extends|include)\s+(['\"])([^'\"]+)\1")

Path = tuple[str, ...]
Output = tuple[str, int, str, list[Path], bool]  # (şablon, satır, gösterim, yollar, yalnız URL özniteliği)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _split_filters(expression: str) -> tuple[str, list[str]]:
    """``a.b|default:'x'|safe`` → ("a.b", ["default", "safe"]); dizelerdeki | yok sayılır."""
    masked = _STRING_RE.sub(lambda m: "\0" * len(m.group(0)), expression)
    parts: list[str] = []
    start = 0
    for index, char in enumerate(masked):
        if char == "|" and not masked[index:index + 2] == "||" and not masked[max(0, index - 1):index + 1] == "||":
            parts.append(expression[start:index])
            start = index + 1
    parts.append(expression[start:])
    base = parts[0].strip()
    filters = []
    for part in parts[1:]:
        name = re.split(r"[:(\s]", part.strip(), maxsplit=1)[0]
        if name:
            filters.append(name)
    return base, filters


def expression_paths(expression: str) -> list[Path]:
    """Şablon ifadesindeki bağlam değişkeni yolları: ``post.title ~ x[1]`` → [("post", "title"), ("x",)]."""
    stripped = _STRING_RE.sub(" ", expression)
    stripped = _KWARG_RE.sub(" ", stripped)  # url_for('x', filename=...) → anahtar sözcük adı değişken değil
    stripped = _SUBSCRIPT_KEY_RE.sub(r".\1", stripped)
    previous = None
    while previous != stripped:
        previous = stripped
        stripped = _SUBSCRIPT_RE.sub("", stripped)
    paths: list[Path] = []
    for match in _PATH_RE.finditer(stripped):
        root = match.group(1)
        if root in _WORDS:
            continue
        rest = tuple(part for part in match.group(2).split(".")[1:] if part and not part.isdigit())
        tail = stripped[match.end():].lstrip()
        if tail.startswith("(") and not rest:
            continue  # makro/fonksiyon adı: argümanları ayrıca eşleşir
        parts = (root, *rest)
        if tail.startswith("(") and rest:
            parts = parts[:-1]  # x.strip() → x
        if any(part in _NUMERIC_MEMBERS for part in parts[1:]):
            continue
        if parts not in paths:
            paths.append(parts)
    return paths


def _alias(path: Path, aliases: dict[str, Path]) -> Path:
    seen = 0
    while path and path[0] in aliases and seen < 8:
        path = aliases[path[0]] + path[1:]
        seen += 1
    return path


def parse_template(relpath: str, text: str) -> tuple[list[Output], list[str]]:
    """Tek şablonun kaçışsız çıktıları ve bağlı (extends/include) şablon adları."""
    outputs: list[Output] = []
    linked: list[str] = []
    autoescape: list[bool] = [True]
    alias_stack: list[dict[str, Path]] = [{}]

    def aliases() -> dict[str, Path]:
        merged: dict[str, Path] = {}
        for frame in alias_stack:
            merged.update(frame)
        return merged

    for match in _TOKEN_RE.finditer(text):
        tag, output = match.group(1), match.group(2)
        if tag is not None:
            words = tag.split()
            if not words:
                continue
            head = words[0]
            if head == "autoescape" and len(words) > 1:
                autoescape.append(words[1].lower() not in {"off", "false"})
            elif head == "endautoescape" and len(autoescape) > 1:
                autoescape.pop()
            elif head == "for":
                frame: dict[str, Path] = {}
                found = _FOR_RE.match(tag)
                if found:
                    names = [n.strip() for n in found.group(1).replace("(", " ").replace(")", " ").split(",") if n.strip()]
                    sources = expression_paths(_split_filters(found.group(2))[0])
                    if sources:
                        source = _alias(sources[0], aliases())
                        for name in names:
                            frame[name] = source
                alias_stack.append(frame)
            elif head == "endfor" and len(alias_stack) > 1:
                alias_stack.pop()
            elif head == "with":
                frame = {}
                body = tag[len("with"):].strip()
                as_match = _WITH_AS_RE.match(body)
                if as_match:
                    sources = expression_paths(_split_filters(as_match.group(1))[0])
                    if sources:
                        frame[as_match.group(2)] = _alias(sources[0], aliases())
                else:
                    for name, value in _WITH_PAIR_RE.findall(body):
                        sources = expression_paths(_split_filters(value)[0])
                        if sources:
                            frame[name] = _alias(sources[0], aliases())
                alias_stack.append(frame)
            elif head == "endwith" and len(alias_stack) > 1:
                alias_stack.pop()
            elif head == "set":
                found = _SET_RE.match(tag)
                if found:
                    sources = expression_paths(_split_filters(found.group(2))[0])
                    if sources:
                        alias_stack[0][found.group(1)] = _alias(sources[0], aliases())
            elif head in {"extends", "include"}:
                found = _NAME_ARG_RE.match(tag)
                if found and found.group(2) not in linked:
                    linked.append(found.group(2))
            continue
        if output is None or len(outputs) >= MAX_OUTPUTS:
            continue
        base, filters = _split_filters(output)
        escaped_filter = any(name in _ESCAPING_FILTERS for name in filters)
        raw = (any(name in _RAW_FILTERS for name in filters) or not autoescape[-1]) and not escaped_filter
        url_only = False
        if not raw:
            # Kaçışlı çıktı URL özniteliğinin tamamıysa javascript: adresi (yalnız istek verisi için).
            prefix = text[max(0, match.start() - 60):match.start()]
            if escaped_filter or not _URL_ATTR_RE.search(prefix):
                continue
            url_only = True
        current = aliases()
        paths = [_alias(path, current) for path in expression_paths(base)]
        if paths:
            shown = "{{ " + output.strip()[:60] + " }}"
            outputs.append((relpath, _line_at(text, match.start()), shown, paths, url_only))
    return outputs, linked


def _normal(path: str) -> str | None:
    normal = posixpath.normpath(path.strip("/") or ".")
    if normal in {".", ".."} or normal.startswith("../"):
        return None
    return normal


def resolve_template(name: str, module_relpath: str, inventory: frozenset[str]) -> str | None:
    """Şablon adı → proje içi göreli yol. Aday ``templates``/``jinja2`` dizini altında ``<ad>`` olmalı;
    birden çok aday varsa şablon dizininin üstü modülün atası olan en derin aday seçilir, eşitlikte None."""
    if not name or name.startswith(("/", "\\")) or "\0" in name or len(name) > 200:
        return None
    normal = _normal(name)
    if normal is None:
        return None
    candidates: list[tuple[str, tuple[str, ...]]] = []
    for path in inventory:
        if path != normal and not path.endswith("/" + normal):
            continue
        prefix = PurePosixPath(path[: len(path) - len(normal)].rstrip("/")).parts if path != normal else ()
        if not prefix or prefix[-1].lower() not in TEMPLATE_DIR_NAMES:
            continue
        candidates.append((path, prefix[:-1]))
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0][0]
    module_parts = PurePosixPath(module_relpath).parent.parts

    def closeness(base: tuple[str, ...]) -> int:
        return len(base) if module_parts[: len(base)] == base else -1

    best = max(closeness(base) for _, base in candidates)
    top = [path for path, base in candidates if closeness(base) == best]
    return top[0] if len(top) == 1 and best >= 0 else None


def template_outputs(relpath: str, module_relpath: str, inventory: frozenset[str],
                     read: "callable", cache: dict[str, tuple[list[Output], list[str]]]) -> list[Output]:
    """Şablon ve bağlı (extends/include) şablonlarının kaçışsız çıktıları."""
    found: list[Output] = []
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(relpath, 0)]
    while queue:
        current, depth = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        if current not in cache:
            text = read(current)
            cache[current] = parse_template(current, text) if text else ([], [])
        outputs, linked = cache[current]
        found.extend(outputs)
        if depth >= MAX_DEPTH:
            continue
        for name in linked:
            target = resolve_template(name, module_relpath, inventory) or resolve_template(name, current, inventory)
            if target is not None and target not in seen:
                queue.append((target, depth + 1))
    return found[:MAX_OUTPUTS]
