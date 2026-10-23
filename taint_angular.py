"""Angular bileşen şablonları için taint yardımcıları (JS/TS AST motoru kullanır).

Şablondaki HTML bağlamaları (``[innerHTML]="x"``, ``bind-innerHTML``, ``innerHTML="{{ x }}"``,
``[outerHTML]``, ``[srcdoc]``) bileşen sınıfının alanına/metoduna eşlenir. Alanın taint'i sınıf
metotlarının (ngOnInit, abonelik geri çağrıları …) ``this.alan = …`` yazımlarından gelir; bu
bilgiyi :mod:`taint_js_ast` özetleri sağlar. Bu modül yalnız şablon metnini ayrıştırır ve şablon
dosyasını proje kökü içinde güvenle okur; kod çalıştırmaz.

Angular ``[innerHTML]`` değerini varsayılan olarak arındırır (betik/olay öznitelikleri atılır):
DomSanitizer atlatılmadıysa akış düşük önemli HTML enjeksiyonu olarak raporlanır. Değer
``bypassSecurityTrust*`` ile işaretlenmişse (ya da bunu yapan bir boru/pipe kullanıldıysa)
arındırma yoktur ve akış XSS olarak raporlanır.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re

from safe_file_read import read_text_bounded

MAX_TEMPLATE_BYTES = 512 * 1024
MAX_BINDINGS = 400

# Arındırılan HTML bağlamları (DomSanitizer HTML bağlamı).
HTML_PROPERTIES = frozenset({"innerhtml", "outerhtml", "srcdoc"})

_BOUND_ATTR_RE = re.compile(
    r"""(?:\[(?P<prop>(?:attr\.)?[A-Za-z][\w.-]*)\]|bind-(?P<bprop>[A-Za-z][\w-]*))\s*=\s*(?P<q>["'])(?P<expr>.*?)(?P=q)""",
    re.DOTALL,
)
_INTERP_ATTR_RE = re.compile(
    r"""(?<![\w\[\]-])(?P<prop>innerHTML|innerHtml|outerHTML|srcdoc)\s*=\s*(?P<q>["'])\s*\{\{(?P<expr>.*?)\}\}\s*(?P=q)""",
    re.DOTALL,
)
_NGFOR_RE = re.compile(r"""\*ngFor\s*=\s*(["'])\s*let\s+([A-Za-z_$][\w$]*)\s+of\s+([^;"']+)""")
_FOR_BLOCK_RE = re.compile(r"""@for\s*\(\s*([A-Za-z_$][\w$]*)\s+of\s+([^;)]+)""")
_LET_AS_RE = re.compile(r"""\*ngIf\s*=\s*(["'])([^;"']+?)\s+as\s+([A-Za-z_$][\w$]*)""")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_TEMPLATE_URL_RE = re.compile(r"^(?:\./)?[\w./-]+\.html?$")


@dataclass(frozen=True)
class Binding:
    prop: str        # bağlanan özellik (innerHTML …)
    root: str        # ifadenin kök adı (alan / metot / şablon değişkeni)
    call: bool       # kök bir metot çağrısı mı (getHtml())
    pipes: tuple[str, ...]
    line: int        # şablon içindeki satır (1 tabanlı)


def _split_pipes(expr: str) -> tuple[str, tuple[str, ...]]:
    """`a.b | safeHtml: x | other` → ('a.b', ('safeHtml', 'other')); `||` boru değildir."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "|" and depth == 0:
            if i + 1 < len(expr) and expr[i + 1] == "|":
                current.append("||")
                i += 2
                continue
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    parts.append("".join(current))
    head = parts[0].strip()
    pipes = tuple(m.group(0) for p in parts[1:] if (m := _IDENT_RE.search(p.split(":", 1)[0])))
    return head, pipes


def _root(expr: str) -> tuple[str, bool]:
    """İfadenin kök adı ve kökün çağrı olup olmadığı (`this.` öneki atılır)."""
    expr = expr.strip()
    if expr.startswith("this."):
        expr = expr[5:]
    match = _IDENT_RE.match(expr)
    if not match:
        return "", False
    rest = expr[match.end():].lstrip()
    return match.group(0), rest.startswith("(")


def template_aliases(text: str) -> dict[str, str]:
    """Şablon değişkenleri → kaynak kök adı (`*ngFor="let p of posts"` → p: posts)."""
    aliases: dict[str, str] = {}
    for match in _NGFOR_RE.finditer(text):
        root, _ = _root(_split_pipes(match.group(3))[0])
        if root:
            aliases[match.group(2)] = root
    for match in _FOR_BLOCK_RE.finditer(text):
        root, _ = _root(_split_pipes(match.group(2))[0])
        if root:
            aliases[match.group(1)] = root
    for match in _LET_AS_RE.finditer(text):
        root, _ = _root(_split_pipes(match.group(2))[0])
        if root:
            aliases[match.group(3)] = root
    return aliases


def html_bindings(text: str) -> list[Binding]:
    """Şablondaki HTML bağlamaları (ifade kökü, borular, satır)."""
    bindings: list[Binding] = []
    aliases = template_aliases(text)
    matches = [(m, m.group("prop") or m.group("bprop") or "") for m in _BOUND_ATTR_RE.finditer(text)]
    matches += [(m, m.group("prop")) for m in _INTERP_ATTR_RE.finditer(text)]
    for match, prop in sorted(matches, key=lambda item: item[0].start()):
        name = prop.removeprefix("attr.")
        if name.lower() not in HTML_PROPERTIES:
            continue
        head, pipes = _split_pipes(match.group("expr"))
        root, call = _root(head)
        seen: set[str] = set()
        while root in aliases and root not in seen:
            seen.add(root)
            root = aliases[root]
            call = False
        if not root:
            continue
        bindings.append(Binding(name, root, call, pipes, text.count("\n", 0, match.start()) + 1))
        if len(bindings) >= MAX_BINDINGS:
            break
    return bindings


_ELEMENT_SELECTOR_RE = re.compile(r"^[a-zA-Z][\w-]*$")


def element_selectors(selector: str) -> tuple[str, ...]:
    """@Component selector'ındaki öğe adları (`app-a, app-b` → ('app-a', 'app-b')); öznitelik seçiciler atlanır."""
    return tuple(part.strip().lower() for part in selector.split(",") if _ELEMENT_SELECTOR_RE.match(part.strip()))


def element_input_bindings(text: str, tag: str) -> list[Binding]:
    """`<tag … [girdi]="ifade">` özellik bağlamaları (alt bileşenin @Input alanlarına giden değerler)."""
    if not _ELEMENT_SELECTOR_RE.match(tag):
        return []
    aliases = template_aliases(text)
    tag_re = re.compile(r"<" + re.escape(tag) + r"""(?=[\s/>])(?P<attrs>(?:[^>"']|"[^"]*"|'[^']*')*)>""", re.IGNORECASE)
    bindings: list[Binding] = []
    for element in tag_re.finditer(text):
        attrs = element.group("attrs")
        for match in _BOUND_ATTR_RE.finditer(attrs):
            prop = match.group("prop") or match.group("bprop") or ""
            if "." in prop:  # attr./class./style. bağlamaları girdi değildir
                continue
            head, pipes = _split_pipes(match.group("expr"))
            root, call = _root(head)
            seen: set[str] = set()
            while root in aliases and root not in seen:
                seen.add(root)
                root = aliases[root]
                call = False
            if root:
                line = text.count("\n", 0, element.start("attrs") + match.start()) + 1
                bindings.append(Binding(prop, root, call, pipes, line))
            if len(bindings) >= MAX_BINDINGS:
                return bindings
    return bindings


def resolve_template_path(component_relpath: str, template_url: str) -> str | None:
    """Bileşen dosyasına göreli templateUrl → proje içi göreli yol (kök dışına çıkamaz)."""
    if not template_url or not _TEMPLATE_URL_RE.match(template_url) or template_url.startswith("/"):
        return None
    parts: list[str] = []
    for part in (PurePosixPath(component_relpath).parent / template_url).parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part not in {".", ""}:
            parts.append(part)
    return "/".join(parts) or None


def read_template(root: Path, relpath: str) -> str | None:
    """Şablonu proje kökü içinden oku: sembolik bağlantı/kök dışı yol/aşırı büyük dosya reddedilir."""
    try:
        base = Path(root).resolve()
        candidate = base / relpath
        current = base
        for part in PurePosixPath(relpath).parts:
            current = current / part
            if current.is_symlink():
                return None
        if not os.path.realpath(candidate).startswith(str(base) + os.sep):
            return None
    except (OSError, ValueError):
        return None
    return read_text_bounded(candidate, MAX_TEMPLATE_BYTES)
