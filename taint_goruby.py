"""Go ve Ruby (Rails/Sinatra) için hızlı, dosyalar arası veri akışı (taint) analizi.

Python (``ast``) ve JavaScript (Babel) motorlarının karşılığı; harici ayrıştırıcı ya da ikili gerektirmez.
Saf Python belirteçleyici + yapısal ayrıştırma:

* Go: dilin otomatik noktalı virgül kuralıyla deyim sınırları, ``if/for/switch`` blokları, fonksiyon
  sabitleri (``func(w, r) {...}``), tür bilgili parametreler (``*http.Request``, ``*gin.Context`` ...).
* Ruby: ``def``/``end`` derinliği (değiştirici ``if``/``unless`` ayrımıyla), dize içi ``#{}``, heredoc,
  ``%`` sabitleri, parantezsiz çağrılar, blok parametreleri, Rails ``scope`` lambdaları ve ERB görünümleri
  (denetleyici eyleminin ``@değişken``leri → ``<%== %>``, ``raw``, ``html_safe``).

Dosyalar arası: fonksiyon özetleri (parametre → hedef, parametre → dönüş, içsel kaynak → dönüş) sabit
noktaya kadar yinelenir. Atamalar iç bloklarda zayıf güncellenir (birleşim), yalnız fonksiyon gövdesinin
üst düzeyinde güçlü güncellenir; dallı arındırma yanlış "temiz" hükmü üretmez. Go'da iç bloktaki ``:=``/``var``
yeni değişken bildirir (blok ya da ``case`` yan tümcesi bitince dıştaki değer geri gelir).

İşlev değerleri (14. tur): Go'da yapı alanlarında (``Handler: f``), eşlem/dilim değişmezlerinde, paket düzeyi
değişkenlerde, parametrelerde ve fabrika dönüşlerinde saklanan işlevler bağlam duyarsız "yuvalarda" toplanır;
``s.Handler(x)``, ``handlers[k](x)``, ``fn(x)`` çağrıları argüman sayısı uyan adaylara çözülür. Fonksiyon
değişmezleri ayrıca özetlenir. Ruby'de yerel/sabit lambda, proc ve ``method(:ad)`` nesneleri ``.call`` ile
çağrıldığında gövde argüman iziyle değerlendirilir.

Kesinlik önceliklidir: bilinmeyen yöntem çağrılarında argüman izi yalnız bilinen dize dönüştürücülerinde
taşınır; veritabanı/model sorgularının sonucu istek verisi sayılmaz; ``Flow`` yalnız modellenmiş bir
kaynaktan modellenmiş bir hedefe arındırılmadan ulaşan izler için üretilir.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import PurePosixPath
import re
from typing import Any, Callable, Iterable

GO_SUFFIXES = frozenset({".go"})
RUBY_SUFFIXES = frozenset({".rb", ".erb", ".haml"})
GORUBY_SUFFIXES = GO_SUFFIXES | RUBY_SUFFIXES

MAX_FIXPOINT_ROUNDS = 5
MAX_FLOWS_PER_FILE = 200
MAX_SLOT_FUNCS = 256  # bir işlev değeri yuvasında tutulan en çok işlev
MAX_SLOT_CALLEES = 40  # (argüman sayısı süzgecinden sonra) bundan fazla adayı olan yuva çağrısı çözülmez
MAX_GO_TYPE_DEPTH = 6  # tür takma adı / gömülü yöntem çözümleme derinliği
MAX_GO_RECEIVER_TYPES = 256  # tek yöntem seçiminde gezilen gömülü alıcı türleri


def language_for(filename: str) -> str | None:
    lowered = filename.lower()
    if lowered.endswith(".go"):
        return "go"
    if lowered.endswith((".rb", ".erb", ".haml")):
        return "ruby"
    return None


# ---------------------------------------------------------------------------
# Ortak yapılar
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Origin:
    label: str  # "request" ya da "§param"
    source: str
    line: int
    file: str
    via: tuple[str, ...] = ()
    cleaned: frozenset[str] = frozenset()


PARAM = "§param"
STORE_KIND = "§store"  # tabloya yazma (kayıtlı veri) yan etkisi: hedef değil, sabit noktada tablo izi
# ActiveRecord yazma/okuma yöntemleri (kayıtlı veri modeli, 17. tur)
_RB_AR_WRITES = frozenset({"create", "create!", "new", "insert", "insert!", "upsert", "find_or_create_by",
                           "find_or_create_by!", "update", "update!", "update_attribute", "update_attributes",
                           "update_columns", "update_column", "assign_attributes"})
_RB_AR_READS = frozenset({"find", "find_by", "find_by!", "where", "all", "first", "last", "take", "order", "limit",
                          "find_each", "includes", "joins", "select", "find_by_sql", "page", "recent", "each", "map"})
Taint = frozenset
EMPTY: frozenset = frozenset()
ALL_KINDS = frozenset({"sql", "command", "eval", "html", "path", "redirect", "ssrf", "ssrf_partial", "deserialize",
                       "xxe"})


def _clean(taint: Iterable[Origin], kinds: frozenset[str]) -> frozenset:
    if not kinds:
        return frozenset(taint)
    return frozenset(Origin(o.label, o.source, o.line, o.file, o.via, o.cleaned | kinds) for o in taint)


def _okey(o: Origin) -> tuple:
    """Köken sıralama anahtarı (determinizm): frozenset yinelemesi PYTHONHASHSEED'e bağlıdır; dosya başı akış
    sınırı ve "ilk gelen" seçimleri çalıştırmadan çalıştırmaya değişmesin diye kararlı sırayla yinelenir."""
    return (o.file, o.line, o.source, o.label, o.via, tuple(sorted(o.cleaned)))


def _osorted(taint: Iterable[Origin]) -> list[Origin]:
    return sorted(taint, key=_okey)


def _pskey(ps: "ParamSink") -> tuple:
    return (ps.index, ps.kind, ps.sink, ps.file, ps.line, ps.via)


def _flow_key(f: Any) -> tuple:
    return (f.line, f.sink_kind, f.source_line, f.source_file or "", f.source, f.source_label, tuple(f.via), f.sink)


def _via(taint: Iterable[Origin], step: str) -> frozenset:
    out = []
    for o in taint:
        via = o.via if (o.via and o.via[-1] == step) or len(o.via) >= 6 else o.via + (step,)
        out.append(Origin(o.label, o.source, o.line, o.file, via, o.cleaned))
    return frozenset(out)


@dataclass
class Tok:
    kind: str  # id, const, ivar, gvar, str, xstr, sym, label, num, regex, op, nl
    value: str
    line: int
    sp: bool = False  # öncesinde boşluk var mı
    interp: tuple = ()  # dize içi ifadeler (her biri belirteç listesi)


@dataclass(frozen=True)
class ParamSink:
    index: int
    kind: str
    sink: str
    file: str
    line: int
    via: tuple[str, ...]


@dataclass
class Summary:
    param_sinks: set = field(default_factory=set)  # ParamSink
    ret_params: dict = field(default_factory=dict)  # indeks → frozenset[frozenset[str]] (arındırılan türler)
    ret_intrinsic: frozenset = EMPTY  # gerçek kaynaklı dönüş izi
    ivars: dict = field(default_factory=dict)  # Ruby denetleyici eylemi: @ad → iz

    def key(self) -> tuple:
        return (
            frozenset(self.param_sinks),
            frozenset((k, v) for k, v in self.ret_params.items()),
            self.ret_intrinsic,
            frozenset((k, v) for k, v in self.ivars.items()),
        )


class FlowSink:
    """Bir proje analizinde üretilen akışların toplayıcısı (dosya bazında)."""

    def __init__(self) -> None:
        self.flows: dict[str, dict[tuple, Any]] = {}
        self.truncated = False

    def emit(self, language: str, kind: str, sink: str, file: str, line: int, origin: Origin, via: tuple[str, ...]) -> None:
        from taint_flow import Flow

        per_file = self.flows.setdefault(file, {})
        key = (kind, line, origin.file, origin.line, origin.source)
        if key in per_file:
            return
        if len(per_file) >= MAX_FLOWS_PER_FILE:
            self.truncated = True
            return
        # Aynı kaynaktan aynı türde dosya başına en çok iki hedef: rapordaki bulgu sınırı (başlık başına 4)
        # tek bir girdinin tekrarlarıyla dolup başka işleyicilerin akışlarını gizlemesin.
        steps = tuple(dict.fromkeys(step for step in (*origin.via, *via) if step))[:6]
        # sınır, hedefi içeren son adım (işlev) başına uygulanır: işlev değeriyle dağıtılan farklı işleyiciler gizlenmesin
        tail = steps[-1:]
        same = sum(1 for k, f in per_file.items() if k[0] == kind and k[2:] == key[2:] and f.via[-1:] == tail)
        if same >= 2:
            return
        per_file[key] = Flow(
            language=language, sink_kind=kind, sink=sink, line=line, source=origin.source,
            source_label="stored" if origin.label == "stored" else "request", source_line=origin.line, via=steps,
            file=file, source_file=origin.file,
        )


def _match(toks: list[Tok], i: int, end: int | None = None) -> int:
    """Açılış parantezinin (``( [ {``) eşini döndür; bulunamazsa son indeks."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = toks[i].value
    closer = pairs[opener]
    depth = 0
    limit = len(toks) if end is None else end
    j = i
    while j < limit:
        value = toks[j].value
        kind = toks[j].kind
        if kind == "op":
            if value == opener:
                depth += 1
            elif value == closer:
                depth -= 1
                if depth == 0:
                    return j
        j += 1
    return limit - 1 if limit else i


def _split_top(toks: list[Tok], a: int, b: int, sep: str = ",") -> list[tuple[int, int]]:
    parts: list[tuple[int, int]] = []
    depth = 0
    start = a
    for j in range(a, b):
        t = toks[j]
        if t.kind != "op":
            continue
        if t.value in ("(", "[", "{"):
            depth += 1
        elif t.value in (")", "]", "}"):
            depth -= 1
        elif t.value == sep and depth == 0:
            parts.append((start, j))
            start = j + 1
    if start < b:
        parts.append((start, b))
    return [(x, y) for x, y in parts if any(toks[k].kind != "nl" for k in range(x, y))]


def _span_text(toks: list[Tok], a: int, b: int, limit: int = 48) -> str:
    out = []
    for t in toks[a:b]:
        if t.kind == "nl":
            continue
        if t.kind == "str":
            out.append('"…"')
        elif t.kind == "sym":
            out.append(":" + t.value)
        else:
            out.append(t.value)
    text = "".join(out)
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Go belirteçleyici
# ---------------------------------------------------------------------------
_GO_OPS = sorted([
    "<<=", ">>=", "&^=", "...", "&&", "||", "<-", "++", "--", "==", "!=", "<=", ">=", ":=", "+=", "-=", "*=",
    "/=", "%=", "&=", "|=", "^=", "<<", ">>", "&^",
], key=len, reverse=True)
# _GO_OPS uzundan kısaya sıralı; seçenekler soldan denendiği için startswith döngüsüyle aynı sonuç.
_GO_OP_RE = re.compile("|".join(re.escape(op) for op in _GO_OPS))
_IDENT_START = re.compile(r"[A-Za-z_\u0080-￿]")
_IDENT = re.compile(r"[A-Za-z0-9_\u0080-￿]*")
_NUMBER = re.compile(r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)i?")


def tokenize_go(text: str) -> list[Tok]:
    toks: list[Tok] = []
    i = 0
    n = len(text)
    line = 1
    space = False
    while i < n:
        c = text[i]
        if c == "\n":
            toks.append(Tok("nl", "\n", line))
            line += 1
            i += 1
            space = True
            continue
        if c in " \t\r\f\v":
            i += 1
            space = True
            continue
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            seg = text[i: n if j < 0 else j + 2]
            count = seg.count("\n")
            if count:
                toks.append(Tok("nl", "\n", line))
            line += count
            i = n if j < 0 else j + 2
            space = True
            continue
        start_line = line
        if c == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"' and text[j] != "\n":
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j: j + 2])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            toks.append(Tok("str", "".join(buf), start_line, space))
            i = j + 1
            space = False
            continue
        if c == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            body = text[i + 1: j]
            toks.append(Tok("str", body, start_line, space))
            line += body.count("\n")
            i = j + 1
            space = False
            continue
        if c == "'":
            j = i + 1
            while j < n and text[j] != "'" and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            toks.append(Tok("num", text[i: j + 1], start_line, space))
            i = j + 1
            space = False
            continue
        if c.isdigit() or (c == "." and i + 1 < n and text[i + 1].isdigit()):
            m = _NUMBER.match(text, i)
            j = m.end() if m and m.end() > i else i + 1
            toks.append(Tok("num", text[i:j], start_line, space))
            i = j
            space = False
            continue
        if _IDENT_START.match(c):
            m = _IDENT.match(text, i + 1)
            j = m.end()
            toks.append(Tok("id", text[i:j], start_line, space))
            i = j
            space = False
            continue
        m = _GO_OP_RE.match(text, i)  # 19. tur hız: _GO_OPS döngüsüyle aynı ilk (en uzun) eşleşme
        if m is not None:
            op = m.group()
            toks.append(Tok("op", op, start_line, space))
            i += len(op)
        else:
            toks.append(Tok("op", c, start_line, space))
            i += 1
        space = False
    return toks


# ---------------------------------------------------------------------------
# Ruby belirteçleyici
# ---------------------------------------------------------------------------
_RB_OPS = sorted([
    "**=", "<=>", "===", "...", "<<=", ">>=", "&&=", "||=", "**", "==", "!=", ">=", "<=", "&&", "||", "<<", ">>",
    "=~", "!~", "=>", "->", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "::", "..", "&.",
], key=len, reverse=True)
_RB_OP_RE = re.compile("|".join(re.escape(op) for op in _RB_OPS))
_RB_KEYWORDS = frozenset({
    "alias", "and", "begin", "break", "case", "class", "def", "defined?", "do", "else", "elsif", "end", "ensure",
    "false", "for", "if", "in", "module", "next", "nil", "not", "or", "redo", "rescue", "retry", "return", "self",
    "super", "then", "true", "undef", "unless", "until", "when", "while", "yield", "__FILE__", "__LINE__",
})
_RB_VALUE_END = frozenset({")", "]", "}"})
_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}


class _RubyLexer:
    def __init__(self, text: str, line: int = 1) -> None:
        self.text = text
        self.n = len(text)
        self.i = 0
        self.line = line
        self.toks: list[Tok] = []
        self.heredocs: list[tuple[str, bool, bool, Tok]] = []  # (bitiş, girintili, enterpolasyon, belirteç)
        self.space = False

    # Dize gövdesi: ``#{}`` ifadelerini ayrı belirteç listesi olarak çıkar.
    def _interp_body(self, body: str, line: int, interpolate: bool) -> tuple:
        if not interpolate or "#{" not in body:
            return ()
        parts = []
        k = 0
        while True:
            k = body.find("#{", k)
            if k < 0:
                break
            if k > 0 and body[k - 1] == "\\":
                k += 2
                continue
            depth = 0
            m = k + 1
            while m < len(body):
                ch = body[m]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                m += 1
            inner = body[k + 2: m]
            inner_line = line + body.count("\n", 0, k)
            parts.append(tuple(_RubyLexer(inner, inner_line).run()))
            k = m + 1
        return tuple(parts)

    def _delimited(self, start: int, opener: str) -> tuple[str, int]:
        """``opener`` sonrasından eşleşen kapanışa kadar (iç içe parantez sayılır)."""
        closer = _PAIRS.get(opener, opener)
        depth = 1
        j = start
        text = self.text
        while j < self.n:
            ch = text[j]
            if ch == "\\":
                j += 2
                continue
            if opener != closer and ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return text[start:j], j + 1
            j += 1
        return text[start:], self.n

    def _prev_value_like(self) -> bool:
        """Önceki belirteç bir değerle bitiyor mu (bölme / ikili işleç bağlamı)?"""
        if not self.toks:
            return False
        prev = self.toks[-1]
        if prev.kind in ("num", "str", "xstr", "sym", "ivar", "gvar", "const", "regex"):
            return True
        if prev.kind == "id":
            return prev.value not in _RB_KEYWORDS or prev.value in ("end", "self", "true", "false", "nil")
        return prev.kind == "op" and prev.value in _RB_VALUE_END

    def add(self, kind: str, value: str, line: int, interp: tuple = ()) -> None:
        self.toks.append(Tok(kind, value, line, self.space, interp))
        self.space = False

    def run(self) -> list[Tok]:
        text = self.text
        n = self.n
        at_line_start = True
        while self.i < n:
            i = self.i
            c = text[i]
            if c == "\n":
                self.add("nl", "\n", self.line)
                self.line += 1
                self.i += 1
                self.space = True
                at_line_start = True
                if self.heredocs:
                    self._consume_heredocs()
                continue
            if c in " \t\r\f\v":
                self.i += 1
                self.space = True
                continue
            if c == "\\" and i + 1 < n and text[i + 1] == "\n":  # satır devamı
                self.i += 2
                self.line += 1
                self.space = True
                continue
            if at_line_start and text.startswith("=begin", i):
                j = text.find("\n=end", i)
                seg = text[i: n if j < 0 else j + 5]
                self.line += seg.count("\n")
                k = text.find("\n", (j + 5) if j >= 0 else n)
                self.i = n if k < 0 else k
                continue
            if at_line_start and text.startswith("__END__", i):
                break
            at_line_start = False
            if c == "#":
                j = text.find("\n", i)
                self.i = n if j < 0 else j
                continue
            line = self.line
            if c in "\"'`":
                body, end = self._delimited(i + 1, c)
                interpolate = c != "'"
                kind = "xstr" if c == "`" else "str"
                if c in "\"'" and end < n and text[end] == ":" and (end + 1 >= n or text[end + 1] in " \t\n,)") \
                        and not (self.toks and self.toks[-1].kind == "op" and self.toks[-1].value == "?"):
                    kind = "label"  # "anahtar": değer (dize sembol anahtarı)
                    end += 1
                self.add(kind, body, line, self._interp_body(body, line, interpolate))
                self.line += text.count("\n", i, end)
                self.i = end
                continue
            if c == "%" and i + 1 < n and not self._prev_value_like():
                m = re.match(r"%([qQwWiIrsx]?)([^\w\s])", text[i:])
                if m:
                    flavor, opener = m.group(1), m.group(2)
                    body, end = self._delimited(i + m.end(), opener)
                    interpolate = flavor in ("", "Q", "W", "I", "r", "x")
                    kind = {"x": "xstr", "r": "regex", "s": "sym"}.get(flavor, "str")
                    self.add(kind, body, line, self._interp_body(body, line, interpolate))
                    self.line += text.count("\n", i, end)
                    self.i = end
                    continue
            if c == "<" and text.startswith("<<", i) and not self._prev_value_like_heredoc():
                m = re.match(r"<<([~-]?)(['\"`]?)([A-Za-z_][A-Za-z0-9_]*)\2", text[i:])
                if m:
                    tok = Tok("xstr" if m.group(2) == "`" else "str", "", line, self.space)
                    self.toks.append(tok)
                    self.space = False
                    self.heredocs.append((m.group(3), bool(m.group(1)), m.group(2) != "'", tok))
                    self.i = i + m.end()
                    continue
            if c == "/" and not self._prev_value_like_regex(i):
                body, end = self._delimited(i + 1, "/")
                while end < n and text[end] in "imxounse":
                    end += 1
                self.add("regex", body, line, self._interp_body(body, line, True))
                self.line += text.count("\n", i, end)
                self.i = end
                continue
            if c == "@":
                m = re.match(r"@@?[A-Za-z_][A-Za-z0-9_]*", text[i:])
                if m:
                    self.add("ivar", m.group(0), line)
                    self.i = i + m.end()
                    continue
            if c == "$":
                m = re.match(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|.)", text[i:])
                if m:
                    self.add("gvar", m.group(0), line)
                    self.i = i + m.end()
                    continue
            if c == ":" and i + 1 < n and text[i + 1] != ":" and (not self.toks or self.space or not self._prev_value_like()):
                if text[i + 1] in "\"'":
                    body, end = self._delimited(i + 2, text[i + 1])
                    self.add("sym", body, line)
                    self.i = end
                    continue
                m = re.match(r":([A-Za-z_][A-Za-z0-9_]*[?!=]?|\[\]=?|[+\-*/%<>=!~^&|]+)", text[i:])
                if m:
                    self.add("sym", m.group(1), line)
                    self.i = i + m.end()
                    continue
            if c == "?" and i + 2 <= n and re.match(r"\?[A-Za-z0-9_](?![A-Za-z0-9_])", text[i:]) and not self._prev_value_like():
                self.add("str", text[i + 1], line)
                self.i = i + 2
                continue
            if c.isdigit():
                m = re.match(r"0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?[ri]?", text[i:])
                self.add("num", m.group(0), line)
                self.i = i + m.end()
                continue
            if c.isalpha() or c == "_" or ord(c) > 127:
                m = re.match(r"[A-Za-z_\u0080-￿][A-Za-z0-9_\u0080-￿]*", text[i:])
                word = m.group(0)
                j = i + m.end()
                if j < n and text[j] in "?!" and not text.startswith("==", j + 1) and (j + 1 >= n or text[j + 1] != "=" or text.startswith("==", j + 1)):
                    if not (text[j] == "?" and j + 1 < n and text[j + 1] == ":"):
                        word += text[j]
                        j += 1
                # Etiket (anahtar sözcük argümanı / karma anahtarı): ``ad: değer``
                if (j < n and text[j] == ":" and (j + 1 >= n or text[j + 1] in " \t\r\n,)")
                        and not (self.toks and self.toks[-1].kind == "op" and self.toks[-1].value == "?")):
                    self.add("label", word, line)
                    self.i = j + 1
                    continue
                kind = "const" if word[0].isupper() else "id"
                self.add(kind, word, line)
                self.i = j
                continue
            m = _RB_OP_RE.match(text, i)  # 19. tur hız: _RB_OPS döngüsüyle aynı ilk (en uzun) eşleşme
            if m is not None:
                op = m.group()
                self.add("op", op, line)
                self.i = i + len(op)
            else:
                self.add("op", c, line)
                self.i = i + 1
        return self.toks

    def _prev_value_like_heredoc(self) -> bool:
        # ``x << y`` (ekleme) ile ``<<~SQL`` (heredoc) ayrımı: değer sonrası ve boşluklu ``<< ad`` eklemedir.
        if not self._prev_value_like():
            return False
        rest = self.text[self.i + 2: self.i + 3]
        prev = self.toks[-1]
        if prev.kind == "id" and prev.value not in _RB_KEYWORDS and self.space and rest and rest in "~-" + "\"'":
            return False  # ``puts <<~EOS``
        return True

    def _prev_value_like_regex(self, i: int) -> bool:
        if not self._prev_value_like():
            return False
        prev = self.toks[-1]
        nxt = self.text[i + 1: i + 2]
        # ``split /,/`` biçimi: tanımlayıcıdan sonra boşluk + bitişik ``/x``
        if prev.kind == "id" and prev.value not in _RB_KEYWORDS and self.space and nxt and nxt not in " =":
            return False
        return True

    def _consume_heredocs(self) -> None:
        text = self.text
        for terminator, squiggly, interpolate, tok in self.heredocs:
            start = self.i
            body_lines = []
            start_line = self.line
            while self.i < self.n:
                j = text.find("\n", self.i)
                end = self.n if j < 0 else j
                raw = text[self.i:end]
                self.i = end + 1 if j >= 0 else self.n
                self.line += 1
                if (raw.strip() if squiggly else raw) == terminator:
                    break
                body_lines.append(raw)
            body = "\n".join(body_lines)
            tok.value = body
            tok.interp = self._interp_body(body, start_line, interpolate)
            del start
        self.heredocs = []
        # Heredoc sonrası satır sonu belirteci zaten eklendi; bir sonraki satıra geçildi.


def tokenize_ruby(text: str, line: int = 1) -> list[Tok]:
    return _RubyLexer(text, line).run()


def erb_segments(text: str) -> list[tuple[str, str, int]]:
    """ERB kod parçaları: (tür, kod, satır); tür '=' (kaçışlı çıktı), '==' (ham çıktı) ya da '' (kod)."""
    out = []
    i = 0
    n = len(text)
    while True:
        k = text.find("<%", i)
        if k < 0:
            break
        if text.startswith("<%%", k):
            i = k + 3
            continue
        j = text.find("%>", k + 2)
        if j < 0:
            break
        body = text[k + 2: j]
        line = text.count("\n", 0, k) + 1
        i = j + 2
        if body.startswith("#"):
            continue
        kind = ""
        if body.startswith("=="):
            kind, body = "==", body[2:]
        elif body.startswith("="):
            kind, body = "=", body[1:]
        elif body.startswith("-"):
            body = body[1:]
        if body.endswith("-"):
            body = body[:-1]
        out.append((kind, body, line))
    del n
    return out


def haml_segments(text: str) -> list[tuple[str, str, int]]:
    """HAML Ruby fragments as ERB-compatible segment kinds.

    ``!=`` is raw output, ``=`` is escaped output, and ``-`` is a code line.
    Attribute hashes and plain interpolation remain escaped by HAML and are
    intentionally not promoted to raw sinks.
    """
    out: list[tuple[str, str, int]] = []
    for line, raw in enumerate(text.splitlines(), 1):
        body = raw.strip()
        if not body or body.startswith("-#") or body.startswith("/"):
            continue
        if body.startswith("- "):
            out.append(("", body[2:].strip(), line))
            continue
        match = re.match(r"^(?:[%#.][\w:-]+(?:\([^)]*\)|\{[^}]*\})?\s*)?(!?=)\s*(.+)$", body)
        if match:
            out.append(("==" if match.group(1) == "!=" else "=", match.group(2), line))
    return out


# ---------------------------------------------------------------------------
# Ortak çözümleyici tabanı (özet uygulama, hedef denetimi)
# ---------------------------------------------------------------------------
class _FuncBase:
    language = ""

    def __init__(self, proj: "_ProjectBase", func: Any) -> None:
        self.proj = proj
        self.func = func
        self.file = func.file
        self.toks: list[Tok] = func.file.toks
        self.env: dict[str, frozenset] = {}
        self.summary = Summary()
        self.funclit_depth = 0

    # -- yayım ------------------------------------------------------------
    def emit(self, kind: str, sink: str, line: int, origin: Origin, via: tuple[str, ...] = (), file: str | None = None) -> None:
        target = file or self.file.rel
        if origin.label == PARAM:
            try:
                index = int(origin.source)
            except ValueError:
                return
            self.summary.param_sinks.add(ParamSink(index, kind, sink, target, line, (origin.via + via)[:6]))
            return
        if kind == STORE_KIND:
            self.proj.note_table_write(sink, origin)
            return
        self.proj.flowsink.emit(self.language, kind, sink, target, line, origin, via)

    def sink(self, kind: str, sink: str, taint: Iterable[Origin], line: int) -> None:
        for origin in _osorted(taint):
            if kind in origin.cleaned or (kind == "ssrf_partial" and "ssrf" in origin.cleaned):
                continue
            self.emit(kind, sink, line, origin)

    def _stored_reaches(self, kind: str, sink: str, origin: Origin) -> bool:
        return True  # alt sınıflar (Ruby) kayıtlı verinin hangi hedeflere ulaştığını sınırlar

    def add_return(self, taint: Iterable[Origin]) -> None:
        if self.funclit_depth:
            return
        intrinsic = set(self.summary.ret_intrinsic)
        for origin in taint:
            if origin.label == PARAM:
                try:
                    index = int(origin.source)
                except ValueError:
                    continue
                current = self.summary.ret_params.get(index, frozenset())
                self.summary.ret_params[index] = current | {origin.cleaned}
            else:
                intrinsic.add(origin)
        if len(intrinsic) > 24:
            intrinsic = set(sorted(intrinsic, key=_okey)[:24])
        self.summary.ret_intrinsic = frozenset(intrinsic)

    def apply_summary(self, callees: list, arg_taints: list[frozenset], kw_taints: dict[str, frozenset], line: int) -> frozenset:
        result: set[Origin] = set()
        for callee in callees:
            summary = self.proj.summaries.get(callee.key)
            if summary is None:
                continue
            step = callee.display

            def arg(index: int) -> frozenset:
                taints: set[Origin] = set()
                if callee.variadic is not None and index >= callee.variadic:
                    for t in arg_taints[callee.variadic:]:
                        taints |= t
                elif index < len(arg_taints):
                    taints |= arg_taints[index]
                if index < len(callee.param_names):
                    taints |= kw_taints.get(callee.param_names[index], EMPTY)
                return frozenset(taints)

            for ps in sorted(summary.param_sinks, key=_pskey):
                for origin in _osorted(arg(ps.index)):
                    if ps.kind in origin.cleaned or (ps.kind == "ssrf_partial" and "ssrf" in origin.cleaned):
                        continue
                    if origin.label == "stored" and not self._stored_reaches(ps.kind, ps.sink, origin):
                        # A whole ActiveRecord instance carries unresolved
                        # ``Model#field`` origins.  If a helper routes it to an
                        # explicitly raw sink, resolve that selected stored
                        # value before applying the second-order policy.
                        head = origin.source.split(" ", 1)[0]
                        if "#" not in head:
                            continue
                        origin = Origin(origin.label, origin.source.replace("#", ".", 1), origin.line,
                                        origin.file, origin.via, origin.cleaned)
                        if not self._stored_reaches(ps.kind, ps.sink, origin):
                            continue
                    via = (step, *ps.via)
                    if origin.label == PARAM:
                        try:
                            index = int(origin.source)
                        except ValueError:
                            continue
                        self.summary.param_sinks.add(ParamSink(index, ps.kind, ps.sink, ps.file, ps.line, (origin.via + via)[:6]))
                    elif ps.kind == STORE_KIND:
                        self.proj.note_table_write(ps.sink, origin)  # yardımcı işlev istek verisini tabloya yazıyor
                    else:
                        self.proj.flowsink.emit(self.language, ps.kind, ps.sink, ps.file, ps.line, origin, via)
            for index, cleaned_sets in summary.ret_params.items():
                taint = _via(arg(index), step)
                for cleaned in cleaned_sets:
                    result |= _clean(taint, cleaned)
            result |= _via(summary.ret_intrinsic, step)
        return frozenset(result)


class _ProjectBase:
    def __init__(self) -> None:
        self.summaries: dict[str, Summary] = {}
        self.flowsink = FlowSink()
        # Kayıtlı (ikinci derece) veri: istek verisi yazılan tablo/model → "stored" kökenleri ve yazılan sütunlar
        # (None = bilinmiyor). Sabit noktada yalnız büyür; değişirse bir tur daha çalışılır.
        self.table_taint: dict[str, frozenset] = {}
        self.table_cols: dict[str, frozenset | None] = {}
        self.tables_changed = False
        self.limitations: set[str] = set()

    def note_table_write(self, spec: str, origin: Origin) -> None:
        """İstek verisi ``tablo|s1,s2`` (ya da ``tablo|*``) tablosuna yazılıyor: o tablodan okunan satırlar kayıtlı veri."""
        if origin.label != "request":
            return
        table, _, cols = spec.partition("|")
        if not table:
            return
        stored = Origin("stored", f"{table.removeprefix('gorm:')} tablosu (kayıtlı veri)", origin.line, origin.file, (),
                        origin.cleaned - {"sql"})
        current = self.table_taint.get(table, EMPTY)
        if stored not in current and len(current) < 8:
            self.table_taint[table] = current | {stored}
            self.tables_changed = True
        written = None if cols in ("", "*") else frozenset(cols.split(","))
        if table in self.table_cols and self.table_cols[table] is None:
            return
        merged = None if written is None else (self.table_cols.get(table) or frozenset()) | written
        if self.table_cols.get(table, ...) != merged:
            self.table_cols[table] = merged
            self.tables_changed = True

    def stored_for(self, table: str | None, cols: frozenset | None = None) -> frozenset:
        """Okunan tablo: istek verisi yazılmışsa kayıtlı veri kökenleri. Okunan ve yazılan sütunlar ikisi de biliniyor
        ve kesişmiyorsa (başka sütunlar) kayıtlı veri sayılmaz."""
        taint = self.table_taint.get(table or "", EMPTY)
        if not taint:
            return EMPTY
        written = self.table_cols.get(table)
        if cols and written and not (written & cols):
            return EMPTY
        return taint


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------
_GO_REQ_FIELDS = frozenset({
    "URL", "Form", "PostForm", "Header", "Body", "MultipartForm", "RequestURI", "Host", "Trailer", "RemoteAddr",
    "Method", "Proto", "TransferEncoding",
})
_GO_OBJ_SOURCES = {
    "req": frozenset({"FormValue", "PostFormValue", "PathValue", "BasicAuth", "Cookie", "Cookies", "FormFile", "Referer", "UserAgent",
                      "MultipartReader"}),
    "gin": frozenset({"Query", "DefaultQuery", "GetQuery", "QueryArray", "GetQueryArray", "QueryMap", "GetQueryMap",
                      "Param", "PostForm", "DefaultPostForm", "GetPostForm", "PostFormArray", "GetPostFormArray",
                      "PostFormMap", "GetPostFormMap", "FormFile", "MultipartForm", "Cookie", "GetHeader", "GetRawData",
                      "ClientIP", "ContentType"}),
    "echo": frozenset({"QueryParam", "QueryParams", "QueryString", "Param", "ParamValues", "FormValue", "FormParams",
                       "FormFile", "MultipartForm", "Cookie", "Cookies", "RealIP", "Scheme"}),
    "fiber": frozenset({"Query", "Queries", "Params", "AllParams", "FormValue", "FormFile", "Body", "BodyRaw", "Cookies",
                        "Get", "GetReqHeaders", "OriginalURL", "Hostname", "IP", "IPs", "Protocol"}),
    "hparams": frozenset({"ByName"}),
    "fiber_bind": frozenset(),
}
_GO_OBJ_BINDS = {
    "gin": frozenset({"Bind", "BindJSON", "BindQuery", "BindXML", "BindYAML", "BindTOML", "BindPlain",
                      "BindUri", "BindHeader", "BindWith",
                      "MustBindWith", "ShouldBind", "ShouldBindJSON", "ShouldBindQuery", "ShouldBindXML", "ShouldBindYAML",
                      "ShouldBindUri", "ShouldBindHeader", "ShouldBindWith", "ShouldBindBodyWith", "ShouldBindTOML",
                      "ShouldBindPlain",
                      "ShouldBindBodyWithJSON", "ShouldBindBodyWithXML", "ShouldBindBodyWithYAML",
                      "ShouldBindBodyWithTOML", "ShouldBindBodyWithPlain"}),
    "echo": frozenset({"Bind"}),
    "fiber": frozenset({"BodyParser", "QueryParser", "ParamsParser", "ReqHeaderParser", "CookieParser", "Bind"}),
    "fiber_bind": frozenset({"Body", "Query", "URI", "Header", "Cookie", "All"}),
}
_GO_SHELLS = frozenset({"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh", "cmd", "cmd.exe",
                        "powershell", "powershell.exe", "pwsh"})
_GO_SQL_METHODS = {"Query": 0, "QueryRow": 0, "Exec": 0, "QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1,
                   "Prepare": 0, "PrepareContext": 1, "Queryx": 0, "QueryRowx": 0, "MustExec": 0, "NamedExec": 0,
                   "NamedQuery": 0, "Select": 1, "Get": 1, "Raw": 0}
_GO_GORM_METHODS = {"Where": 0, "Or": 0, "Not": 0, "Order": 0, "Group": 0, "Having": 0, "Joins": 0, "Select": 0,
                    "Raw": 0, "Exec": 0, "Pluck": 0, "Distinct": 0, "Table": 0}
_GO_OS_PATH = frozenset({"Open", "OpenFile", "ReadFile", "Create", "WriteFile", "Remove", "RemoveAll", "Mkdir",
                         "MkdirAll", "ReadDir", "Rename", "Truncate", "Chmod", "Chown", "Lstat", "Stat", "Symlink",
                         "Link", "DirFS"})
_GO_METHOD_ARG_PROP = frozenset({
    "ReplaceAllString", "ReplaceAllLiteralString", "ReplaceAll", "ReplaceAllLiteral", "ReplaceAllStringFunc",
    "Replace", "FindString", "FindAllString", "FindStringSubmatch", "FindAllStringSubmatch", "Expand", "ExpandString",
    "Sprintf", "Join", "JoinPath", "ResolveReference", "Parse", "EncodeToString", "DecodeString",
})
# Yapılandırılmış çıktı üreten serileştiriciler: HTML özel karakterleri kaçışlanır (XSS için temiz).
_GO_HTML_SAFE_TRANSFORMS = frozenset({"ToRss", "ToAtom", "ToJSON", "ToXML", "Marshal", "MarshalIndent", "EncodeToString"})
_GO_ERROR_RETURNING = frozenset({"Decode", "Unmarshal", "Encode", "Scan", "ParseForm", "ParseMultipartForm", "Bind",
                                 "BindJSON", "ShouldBind", "ShouldBindJSON", "BodyParser", "Validate", "Struct"})
_GO_CLEAN_METHODS = frozenset({
    "MatchString", "Match", "Len", "Error", "Close", "Err", "Contains", "HasPrefix", "HasSuffix", "Index", "Count",
    "EqualFold", "Compare", "Equal", "IsZero", "Size", "Seconds", "Unix", "Int", "Int64", "Float64", "Bool", "Before",
    "After", "Valid", "Exists", "Next", "Scan", "RowsAffected", "LastInsertId", "Method", "Context", "Status",
    "StatusCode",
})
_GO_BUILTINS = frozenset({"make", "new", "len", "cap", "append", "copy", "delete", "panic", "print", "println",
                          "complex", "real", "imag", "close", "recover", "min", "max", "clear"})
_GO_NUMERIC = frozenset({"int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
                         "uintptr", "float32", "float64", "bool", "byte", "rune", "complex64", "complex128"})
_GO_ASSIGN = frozenset({":=", "=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>=", "&^="})
_GO_TERMINATING_WORDS = frozenset({"break", "continue", "fallthrough", "return"})
_GO_NO_VALUE = frozenset({"nil", "true", "false", "iota"})
_SAFE_REDIRECT = re.compile(r"^/(?![/\\])")
# Kayıtlı (ikinci derece) veri — Go: istek verisi INSERT/UPDATE ile ya da GORM Create/Save ile tabloya yazılıyorsa o
# tablodan okunan satırlar (rows.Scan, QueryRow().Scan, sqlx Select/Get, GORM Find/First) "stored" kaynaktır.
# şema önekli adlar (vulnapp.posts): tablo son parçadır
_SQL_WRITE_RE = re.compile(r"(?is)^\s*(?:insert\s+(?:ignore\s+)?into|replace\s+into|update)\s+(?:[`\"\[]?\w+[`\"\]]?\.)?[`\"\[]?(\w+)")
_SQL_READ_RE = re.compile(r"(?is)^\s*select\b.*?\bfrom\s+(?:[`\"\[]?\w+[`\"\]]?\.)?[`\"\[]?(\w+)")
_SQL_INSERT_COLS_RE = re.compile(r"(?is)\binsert\s+(?:ignore\s+)?into\s+[`\"\[]?[\w.]+[`\"\]]?\s*\(([^)]*)\)")
_SQL_SET_RE = re.compile(r"(?is)\bset\b(.*?)(?:\bwhere\b|$)")
_SQL_SELECT_COLS_RE = re.compile(r"(?is)\bselect\s+(.*?)\s+from\b")
_GO_SQL_READ_METHODS = {"Query": 0, "QueryRow": 0, "QueryContext": 1, "QueryRowContext": 1, "Queryx": 0,
                        "QueryRowx": 0}
_GO_SQLX_BIND_READS = {"Select": 1, "Get": 1}  # sqlx: ilk argüman hedef, sonraki sorgu
_GO_SQL_WRITE_METHODS = {"Exec": 0, "ExecContext": 1, "MustExec": 0, "MustExecContext": 1, "NamedExec": 0,
                         "Query": 0, "QueryRow": 0, "QueryContext": 1, "QueryRowContext": 1}
_GO_GORM_WRITES = frozenset({"Create", "Save", "Updates", "FirstOrCreate", "CreateInBatches"})
_GO_GORM_READS = frozenset({"Find", "First", "Last", "Take"})
# Kayıtlı veri bu türlerdeki hedeflere bağlanmaz (sayı/zaman HTML taşımaz).
_GO_STORED_INERT = frozenset({"time.Time", "sql.NullInt64", "sql.NullInt32", "sql.NullInt16", "sql.NullFloat64",
                              "sql.NullBool", "sql.NullTime", "sql.NullByte", "uuid.UUID"})
# Konak kısmı isteğin kendi Host değeri olan adres ("//"+r.Host+…, Sprintf("https://%s%s", r.Host, …)):
# yönlendirme yine aynı konağa gider (HTTP→HTTPS, sondaki eğik çizgi) — açık yönlendirme değil.
_HOST_FIRST = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:)?//(?:%s|%v)?$")
_FIXED_HOST = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/%{}#?\s]+/")


def _go_type_class(text: str) -> str | None:
    t = text.replace(" ", "")
    if re.search(r"(?:^|[*.])(?:http\.)?Request$", t) and "http.Request" in t:
        return "req"
    if "gin.Context" in t:
        return "gin"
    if "echo.Context" in t:
        return "echo"
    if "fiber.Ctx" in t:
        return "fiber"
    if "httprouter.Params" in t:
        return "hparams"
    if "http.ResponseWriter" in t:
        return "writer"
    if re.search(r"http\.Client$", t):
        return "client"
    if re.search(r"sql\.Stmt|sqlx\.(?:Stmt|NamedStmt)", t):
        return "stmt"
    if re.search(r"(?:sql\.(?:DB|Tx|Conn)|sqlx\.|gorm\.DB|pgx|pgxpool|bun\.DB|xorm)", t):
        return "db"
    if re.search(r"url\.URL$", t):
        return "url"
    return None


# Yolu istekten gelen dosyanın içeriği HTML bağlamında saldırgan verisi sayılmaz (W2-XSS; JS/Python/Java'da da böyle).
_FILE_CONTENT_CLEAN = frozenset({"html"})


def _go_sanitizer(path: str, fn: str) -> frozenset | str | None:
    if path == "strconv":
        return "all" if fn.startswith(("Atoi", "Parse", "Itoa", "Format", "Quote", "Append")) else None
    if path == "html" and fn == "EscapeString":
        return frozenset({"html"})
    if path in ("html/template", "text/template") and fn in ("HTMLEscapeString", "JSEscapeString", "HTMLEscaper",
                                                             "JSEscaper", "URLQueryEscaper", "HTMLEscape", "JSEscape"):
        return frozenset({"html"})
    if path == "net/url" and fn in ("QueryEscape", "PathEscape"):
        return frozenset({"html", "ssrf_partial", "redirect", "command", "sql"})
    if path in ("path/filepath", "path") and fn == "Base":
        return frozenset({"path"})
    if path == "strings" and fn in ("Contains", "ContainsAny", "ContainsRune", "HasPrefix", "HasSuffix", "Index",
                                    "IndexAny", "LastIndex", "Count", "EqualFold", "Compare"):
        return "all"
    if path == "regexp" and fn in ("MatchString", "Match", "QuoteMeta"):
        return "all" if fn != "QuoteMeta" else None
    if path.endswith("uuid") and fn in ("Parse", "MustParse"):
        return "all"
    if path == "unicode/utf8" or (path == "errors" and fn in ("Is", "As")):
        return "all"
    return None


@dataclass
class GoFunc:
    name: str
    file: "GoFile"
    params: list  # [(ad, tür)]
    body: tuple  # (a, b) — süslü parantezlerin içi
    line: int
    recv: tuple | None = None
    variadic: int | None = None
    anon: bool = False  # fonksiyon değişmezi (func(...) {...}); ad "func#<belirteç sırası>"
    results: tuple = ()  # 19. tur: adlandırılmış sonuçlar (çıplak "return" bunları döndürür)

    @property
    def key(self) -> str:
        recv = self.recv[1].lstrip("*") if self.recv else ""
        return f"go:{self.file.rel}:{recv}.{self.name}:{self.line}"

    @property
    def display(self) -> str:
        return "anonim fonksiyon()" if self.anon else f"{self.name}()"

    @property
    def param_names(self) -> list:
        return [p[0] for p in self.params]


@dataclass
class GoFile:
    rel: str
    toks: list
    pkg: str = ""
    imports: dict = field(default_factory=dict)  # takma ad → yol
    funcs: list = field(default_factory=list)
    var_types: dict = field(default_factory=dict)
    funclits: dict = field(default_factory=dict)  # "func" belirteç sırası → GoFunc (anon)
    var_inits: list = field(default_factory=list)  # paket düzeyi (ad, ifade başı, ifade sonu)

    @property
    def dir(self) -> str:
        cached = self.__dict__.get("_dir")
        if cached is None:
            cached = self.__dict__["_dir"] = str(PurePosixPath(self.rel).parent)
        return cached

    def imports_path(self, needle: str) -> bool:
        return any(path == needle or path.startswith(needle + "/") or needle in path for path in self.imports.values())

    @property
    def grpc_server_types(self) -> frozenset:
        """18. tur: ``Unimplemented…Server`` gömen yapı türleri (gRPC hizmet uygulaması)."""
        cached = self.__dict__.get("_grpc")
        if cached is None:
            names = set()
            toks = self.toks
            for i in range(len(toks) - 3):
                if toks[i].kind == "id" and toks[i].value == "type" and toks[i + 1].kind == "id" and \
                        toks[i + 2].kind == "id" and toks[i + 2].value == "struct":
                    j, depth = i + 3, 0
                    while j < len(toks) and j < i + 400:
                        v = toks[j].value
                        if v == "{":
                            depth += 1
                        elif v == "}":
                            depth -= 1
                            if depth <= 0:
                                break
                        elif toks[j].kind == "id" and re.fullmatch(r"Unimplemented\w*Server", str(v)):
                            names.add(toks[i + 1].value)
                            break
                        j += 1
            cached = self.__dict__["_grpc"] = frozenset(names)
        return cached


def _go_params(toks: list[Tok], a: int, b: int) -> tuple[list, int | None]:
    groups = []
    for x, y in _split_top(toks, a, b):
        items = [t for t in toks[x:y] if t.kind != "nl"]
        if items:
            groups.append(items)
    named = any(len(g) >= 2 and g[0].kind == "id" and not (g[1].kind == "op" and g[1].value == ".") for g in groups)
    params: list = []
    variadic = None
    pending: list[str] = []
    for g in groups:
        if named:
            if len(g) == 1 and g[0].kind == "id":
                pending.append(g[0].value)
                continue
            name = g[0].value
            type_text = "".join(t.value for t in g[1:])
            for p in pending:
                params.append((p, type_text))
            pending = []
            if type_text.startswith("..."):
                variadic = len(params)
            params.append((name, type_text))
        else:
            type_text = "".join(t.value for t in g)
            if type_text.startswith("..."):
                variadic = len(params)
            params.append(("_", type_text))
    for p in pending:
        params.append((p, ""))
    return params, variadic


def parse_go_file(rel: str, text: str) -> GoFile:
    toks = tokenize_go(text)
    gf = GoFile(rel, toks)
    n = len(toks)
    i = 0
    depth = 0
    while i < n:
        t = toks[i]
        if t.kind == "op":
            if t.value in ("{", "(", "["):
                depth += 1
            elif t.value in ("}", ")", "]"):
                depth -= 1
            i += 1
            continue
        if t.kind != "id" or depth != 0:
            i += 1
            continue
        if t.value == "package" and i + 1 < n:
            gf.pkg = toks[i + 1].value
            i += 2
            continue
        if t.value == "import":
            j = i + 1
            if j < n and toks[j].value == "(":
                k = _match(toks, j)
                specs = range(j + 1, k)
                i = k + 1
            else:
                specs = range(j, min(n, j + 3))
                i = j + 1
            alias = None
            for m in specs:
                tk = toks[m]
                if tk.kind == "nl":
                    alias = None
                    continue
                if tk.kind == "id" or (tk.kind == "op" and tk.value in ("_", ".")):
                    alias = tk.value
                elif tk.kind == "str":
                    path = tk.value
                    name = alias
                    if not name:
                        parts = [p for p in path.split("/") if p]
                        name = parts[-1] if parts else path
                        if re.fullmatch(r"v\d+", name) and len(parts) > 1:
                            name = parts[-2]
                        name = re.sub(r"^go-|\.v\d+$|-go$", "", name).replace("-", "")
                    if name not in ("_", "."):
                        gf.imports[name] = path
                    alias = None
                    if not (j < n and toks[j].value == "("):
                        break
            continue
        if t.value == "var" and i + 1 < n:
            # paket düzeyi değişken türleri (ör. var DB *sql.DB)
            j = i + 1
            if toks[j].value == "(":
                k = _match(toks, j)
                lines: dict[int, list[Tok]] = {}
                for m in range(j + 1, k):
                    if toks[m].kind != "nl":
                        lines.setdefault(toks[m].line, []).append(toks[m])
                for items in lines.values():
                    if len(items) >= 2 and items[0].kind == "id":
                        gf.var_types[items[0].value] = "".join(x.value for x in items[1:]).split("=")[0]
                m = j + 1
                while m < k:
                    if toks[m].kind == "nl" or toks[m].value == ";":
                        m += 1
                        continue
                    end = _go_decl_end(toks, m, k)
                    _go_var_init(gf, toks, m, end)
                    m = max(end, m + 1)
                i = k + 1
                continue
            items = []
            m = j
            while m < n and toks[m].kind != "nl":
                items.append(toks[m])
                m += 1
            if len(items) >= 2 and items[0].kind == "id":
                gf.var_types[items[0].value] = "".join(x.value for x in items[1:]).split("=")[0]
            end = _go_decl_end(toks, j, n)
            _go_var_init(gf, toks, j, end)
            i = max(m, end)
            continue
        if t.value == "func":
            j = i + 1
            recv = None
            if j < n and toks[j].value == "(":
                k = _match(toks, j)
                rparams, _ = _go_params(toks, j + 1, k)
                if rparams:
                    recv = rparams[0]
                j = k + 1
            if j >= n or toks[j].kind != "id":
                i += 1
                continue
            name = toks[j].value
            line = toks[j].line
            j += 1
            if j < n and toks[j].value == "[":  # tür parametreleri
                j = _match(toks, j) + 1
            if j >= n or toks[j].value != "(":
                i += 1
                continue
            k = _match(toks, j)
            params, variadic = _go_params(toks, j + 1, k)
            m = k + 1
            pdepth = 0
            while m < n:
                tv = toks[m]
                if tv.kind == "op" and tv.value in ("(", "["):
                    pdepth += 1
                elif tv.kind == "op" and tv.value in (")", "]"):
                    pdepth -= 1
                elif tv.kind == "op" and tv.value == "{" and pdepth == 0:
                    # sonuç türü "struct{...}"/"interface{}" ise atla
                    if m > 0 and toks[m - 1].kind == "id" and toks[m - 1].value in ("struct", "interface"):
                        m = _match(toks, m) + 1
                        continue
                    break
                elif tv.kind == "nl" and pdepth == 0:
                    m = n  # gövdesiz bildirim
                    break
                m += 1
            if m >= n:
                i = k + 1
                continue
            close = _match(toks, m)
            results: tuple = ()
            if k + 1 < m and toks[k + 1].kind == "op" and toks[k + 1].value == "(":
                rk = _match(toks, k + 1)
                if rk < m:
                    named, _ = _go_params(toks, k + 2, rk)
                    results = tuple(nm for nm, typ in named if nm not in ("", "_") and typ)
            gf.funcs.append(GoFunc(name, gf, params, (m + 1, close), line, recv, variadic, results=results))
            i = close + 1
            continue
        i += 1
    _go_collect_funclits(gf)
    return gf


# Fonksiyon değişmezinden önce gelebilen belirteçler (ifade konumu); bildirim/tür konumundaki "func" bunlardan sonra gelmez.
_GO_FUNCLIT_PREV = frozenset({"=", ":=", ",", "(", ":", "{", "return", "go", "defer", "&&", "||", "!", "<-", "&"})


def _go_decl_end(toks: list[Tok], i: int, n: int) -> int:
    """Paket düzeyi bildirimin sonu: derinlik 0'da satır sonu (devam işleçlerinden sonra değil) ya da ';'."""
    depth = 0
    j = i
    while j < n:
        t = toks[j]
        if t.kind == "op":
            if t.value in ("(", "[", "{"):
                depth += 1
            elif t.value in (")", "]", "}"):
                if depth == 0:
                    return j
                depth -= 1
            elif t.value == ";" and depth == 0:
                return j
        elif t.kind == "nl" and depth == 0 and j > i:
            prev = toks[j - 1]
            if not (prev.kind == "op" and prev.value in ("=", ",", "+", "(", "{", "[", ".", "&&", "||")):
                return j
        j += 1
    return j


def _go_var_init(gf: GoFile, toks: list[Tok], a: int, b: int) -> None:
    """``ad [tür] = ifade`` → (ad, ifade aralığı); yalnız tek adlı bildirimler (işlev değeri bağlamaları için)."""
    if a >= b or toks[a].kind != "id":
        return
    eq = next((j for j in range(a, b) if toks[j].kind == "op" and toks[j].value == "="), None)
    if eq is None or eq + 1 >= b:
        return
    if any(toks[j].kind == "op" and toks[j].value == "," for j in range(a, eq)):
        return
    gf.var_inits.append((toks[a].value, eq + 1, b))


def _go_funclit_bounds(toks: list[Tok], i: int, n: int) -> tuple | None:
    """``func(...) sonuç {`` → (parametre kapanışı, gövde açılışı, gövde kapanışı); gövdesizse (işlev türü) None."""
    j = i + 1
    if j >= n or toks[j].value != "(":
        return None
    k = _match(toks, j)
    m = k + 1
    depth = 0
    while m < n:
        t = toks[m]
        if t.kind == "op" and t.value in ("(", "["):
            depth += 1
        elif t.kind == "op" and t.value in (")", "]"):
            if depth <= 0:
                return None
            depth -= 1
        elif t.kind == "op" and t.value == "{" and depth == 0:
            if toks[m - 1].kind == "id" and toks[m - 1].value in ("struct", "interface"):
                m = _match(toks, m) + 1
                continue
            return k, m, _match(toks, m)
        elif t.kind == "op" and t.value in (",", ";") and depth <= 0:
            return None
        m += 1
    return None


def _go_collect_funclits(gf: GoFile) -> None:
    """Fonksiyon gövdelerindeki ve paket düzeyi başlatıcılardaki fonksiyon değişmezlerini ayrı (anonim) işlev olarak kaydet;
    işlev değeri olarak saklanıp sonradan çağrıldıklarında (alan, eşlem, parametre) özetleri uygulanabilsin."""
    toks = gf.toks
    n = len(toks)
    for i in range(n - 1):
        t = toks[i]
        if t.kind != "id" or t.value != "func" or toks[i + 1].value != "(":
            continue
        p = i - 1
        while p >= 0 and toks[p].kind == "nl":
            p -= 1
        if p < 0 or toks[p].value not in _GO_FUNCLIT_PREV:
            continue
        bounds = _go_funclit_bounds(toks, i, n)
        if bounds is None:
            continue
        k, m, close = bounds
        params, variadic = _go_params(toks, i + 2, k)
        gf.funclits[i] = GoFunc(f"func#{i}", gf, params, (m + 1, close), t.line, None, variadic, anon=True)


class GoAnalyzer(_FuncBase):
    language = "go"

    def __init__(self, proj: "GoProject", func: GoFunc) -> None:
        super().__init__(proj, func)
        self.types: dict[str, str] = {}
        self.ct_safe = False  # Content-Type HTML dışı bir değere ayarlandı mı
        self.fvars: dict[str, frozenset] = {}  # yerel işlev değeri değişkenleri → işlev anahtarları
        # İç bloklarda ":=" / "var" yeni değişken bildirir; blok (ya da case yan tümcesi) bitince dıştaki değer geri gelir.
        self.scopes: list[dict] = []
        self.lit_params: list[set] = []  # satır içi analiz edilen değişmezlerin parametre adları (dış parametreyi gölgeler)
        self.decl_types: dict[str, str] = {}  # yerel ad → bildirilen tür metni (kayıtlı veri: model adı / sayısal tür)
        self.struct_values: dict[str, dict[str, frozenset]] = {}  # yapı değişmezi alanları, sibling FP'lerini önler
        self.struct_func_values: dict[str, dict[str, frozenset]] = {}  # örnek başına işlev alanları

    def _body_ids(self) -> frozenset:
        """İşlev gövdesindeki tanımlayıcılar (işlev düzeyi koruma sezgileri için; bir kez hesaplanır)."""
        ids = getattr(self, "_ids_cache", None)
        if ids is None:
            a, b = self.func.body
            ids = frozenset(str(t.value) for t in self.toks[a:b] if t.kind == "id")
            self._ids_cache = ids
        return ids

    def sink(self, kind: str, sink: str, taint, line: int) -> None:
        ids = self._body_ids()
        # 17. tur: işlev düzeyi koruma sezgileri (C# GetFullPath + StartsWith ile aynı yaklaşım):
        # filepath.Clean/Abs/EvalSymlinks/Rel + strings.HasPrefix → yol aşımı denetimi;
        # url.Parse + .Host karşılaştırması → yönlendirme/SSRF ana makine denetimi.
        if kind == "path" and "HasPrefix" in ids and ids & {"Clean", "Abs", "EvalSymlinks", "Rel"}:
            return
        if kind in ("redirect", "ssrf", "ssrf_partial") and "Parse" in ids and ids & {"Host", "Hostname"} \
                and self._host_compared():
            return
        super().sink(kind, sink, taint, line)

    def _host_compared(self) -> bool:
        a, b = self.func.body
        toks = self.toks
        for i in range(a, b - 2):
            if toks[i].kind == "id" and toks[i].value in ("Host", "Hostname") and i + 1 < b:
                nxt = toks[i + 1] if toks[i + 1].value != "(" else (toks[i + 3] if i + 3 < b else toks[i + 1])
                prev = toks[i - 2] if i >= 2 else toks[i]
                if (nxt.kind == "op" and nxt.value in ("==", "!=")) or (prev.kind == "op" and prev.value in ("==", "!=")):
                    return True
        return False

    def shadow(self, name: str) -> None:
        if self.scopes and name not in self.scopes[-1]:
            self.scopes[-1][name] = (self.env.get(name), self.types.get(name), self.fvars.get(name),
                                          self.struct_values.get(name), self.struct_func_values.get(name))

    def restore_scope(self, scope: dict) -> None:
        for name, saved in scope.items():
            for table, value in zip(
                    (self.env, self.types, self.fvars, self.struct_values, self.struct_func_values), saved):
                if value is None:
                    table.pop(name, None)
                else:
                    table[name] = value
        scope.clear()

    def package_inits(self) -> None:
        """Paket düzeyi ``var ad = ifade`` başlatıcıları: bileşik değişmezlerdeki alan bağlamaları ve işlev değişkenleri."""
        for name, a, b in self.file.var_inits:
            try:
                self.eval(a, b)
                fv = self.funcvals(a, b)
            except RecursionError:
                continue
            if fv:
                self.proj.bind(("var", self.file.dir, name), fv)

    # -- işlev değerleri ------------------------------------------------------
    def local_funcvals(self, name: str) -> frozenset:
        if name in self.fvars:
            return self.fvars[name]
        if any(name in names for names in self.lit_params):
            return EMPTY
        if name in self.func.param_names:
            return self.proj.slot(("param", self.func.key, self.func.param_names.index(name)))
        return EMPTY

    def _methods_named(self, name: str, recv_type: str | tuple[str, str] | None = None) -> list:
        candidates = self.proj.methods.get(name, [])
        if recv_type:
            key = self.proj.resolve_type_key(self.file, recv_type)
            accepted = self.proj.method_receiver_keys(key) \
                if key in self.proj.qualified_struct_fields else frozenset({key})
            candidates = [
                f for f in candidates
                if f.recv and self.proj.resolve_type_key(f.file, f.recv[1]) in accepted
            ]
        return self.proj.conservative_methods(candidates)

    def _ret_funcvals(self, callees: list) -> frozenset:
        out: set = set()
        for callee in callees:
            out |= self.proj.slot(("ret", callee.key))
        return frozenset(out)

    def funcvals(self, a: int, b: int, _depth: int = 0) -> frozenset:
        """İfadenin değeri olabilecek proje işlevleri (işlev değeri): ad, paket.Ad, yöntem değeri, değişmez,
        fabrika çağrısı, tür dönüşümü (http.HandlerFunc(f)), eşlem/dilim değişmezi ve indeksleme."""
        toks = self.toks
        while a < b and toks[a].kind == "nl":
            a += 1
        while b > a and toks[b - 1].kind == "nl":
            b -= 1
        while a < b and toks[a].kind == "op" and toks[a].value in ("&", "*"):
            a += 1
        if a >= b or _depth > 6:
            return EMPTY
        t = toks[a]
        proj = self.proj
        if t.kind == "op" and t.value == "(":
            k = _match(toks, a)
            return self.funcvals(a + 1, k, _depth + 1) if k == b - 1 else EMPTY
        if (t.kind == "op" and t.value == "[") or (t.kind == "id" and t.value == "map" and a + 1 < b and toks[a + 1].value == "["):
            # []T{...} / map[K]T{...}: öğe değerleri
            depth = 0
            for j in range(a, b):
                v = toks[j].value
                if toks[j].kind != "op":
                    continue
                if v in ("[", "("):
                    depth += 1
                elif v in ("]", ")"):
                    depth -= 1
                elif v == "{" and depth == 0:
                    if toks[j - 1].kind == "id" and toks[j - 1].value in ("struct", "interface"):
                        continue
                    close = _match(toks, j)
                    out: set = set()
                    for x, y in _split_top(toks, j + 1, close):
                        colon = next((m for m in range(x, y) if toks[m].kind == "op" and toks[m].value == ":"
                                      and not any(toks[q].value in ("(", "[", "{") for q in range(x, m))), None)
                        out |= self.funcvals(colon + 1 if colon is not None else x, y, _depth + 1)
                    return frozenset(out)
            return EMPTY
        if t.kind != "id":
            return EMPTY
        if t.value == "func":
            lit = self.file.funclits.get(a)
            if lit is None:
                return EMPTY
            close = lit.body[1]
            if close + 1 >= b:
                return frozenset({lit.key})
            if toks[close + 1].value == "(" and _match(toks, close + 1) == b - 1:
                return proj.slot(("ret", lit.key))  # hemen çağrılan fabrika
            return EMPTY
        # ad zinciri: ad (. seçici | [indeks] | (argümanlar) | {bileşik})*
        name = t.value
        j = a + 1
        segs: list = [("id", name)]
        while j < b:
            tv = toks[j]
            if tv.kind == "op" and tv.value == ".":
                nxt = j + 1
                while nxt < b and toks[nxt].kind == "nl":  # satır sonunda biten zincir
                    nxt += 1
                if nxt < b and toks[nxt].kind == "id":
                    segs.append(("sel", toks[nxt].value))
                    j = nxt + 1
                elif nxt < b and toks[nxt].value == "(":
                    j = _match(toks, nxt) + 1  # tür iddiası
                else:
                    return EMPTY
            elif tv.kind == "op" and tv.value == "[":
                k = _match(toks, j)
                segs.append(("index", None))
                j = k + 1
            elif tv.kind == "op" and tv.value == "(":
                k = _match(toks, j)
                segs.append(("call", (j + 1, k)))
                j = k + 1
            elif tv.kind == "op" and tv.value == "{":
                k = _match(toks, j)
                segs.append(("lit", None))
                j = k + 1
            else:
                return EMPTY  # ikili işlem vb.: işlev değeri değil
        return self._chain_funcvals(segs, _depth)

    def _chain_funcvals(self, segs: list, depth: int) -> frozenset:
        proj = self.proj
        gf = self.file
        while segs and segs[-1][0] == "index":
            segs = segs[:-1]  # kap[k] → kabın işlevleri
        if not segs:
            return EMPTY
        kind, last = segs[-1]
        if kind == "call":
            head = segs[:-1]
            callees: list = []
            if len(head) == 1:
                name = head[0][1]
                local = self.local_funcvals(name)
                if local:
                    callees = proj.slot_funcs(local)
                elif name not in self.env and name not in self.types:
                    callees = proj.resolve(gf, [name], None, name, False)
            elif len(head) == 2 and head[1][0] == "sel":
                if head[0][1] in gf.imports and head[0][1] not in self.env and head[0][1] not in self.types:
                    callees = proj.resolve(gf, [head[0][1]], head[1][1], None, True)
                else:
                    callees = self._methods_named(head[1][1])
            if callees:
                return self._ret_funcvals(callees)
            x, y = last
            spans = _split_top(self.toks, x, y)
            if len(spans) == 1:
                return self.funcvals(spans[0][0], spans[0][1], depth + 1)  # tür dönüşümü / sarmalayıcı
            return EMPTY
        if kind == "lit":
            return EMPTY
        if len(segs) == 1:
            name = segs[0][1]
            local = self.local_funcvals(name)
            if local or name in self.env or name in self.types:
                return local
            funcs = proj.by_dir.get(gf.dir, {}).get(name, [])
            if funcs:
                return frozenset(f.key for f in funcs)
            return proj.slot(("var", gf.dir, name))
        if kind != "sel":
            return EMPTY
        root = segs[0][1]
        if len(segs) == 2 and root in gf.imports and root not in self.env and root not in self.types:
            d = proj._dir_for_import(gf.imports.get(root, ""))
            if d is None:
                return EMPTY
            funcs = proj.by_dir.get(d, {}).get(last, [])
            return frozenset(f.key for f in funcs) if funcs else proj.slot(("var", d, last))
        # yöntem değeri (T{}.m, x.m) ya da işlev türlü alan okuması (s.Handler)
        recv_type = None
        if len(segs) >= 3 and segs[-2][0] == "lit":
            recv_type = self.proj.receiver_type_key(self.file, segs[-3][1])
        elif len(segs) >= 2:
            recv_type = self._struct_type_of(root)
        out = {f.key for f in self._methods_named(last, recv_type)}
        if len(segs) >= 2:
            struct = self._struct_type_of(root)
            owner = self.proj.function_field_owner(struct, last) if struct else None
            if owner:
                out |= proj.slot(("field", owner, last))
            elif recv_type is None:
                out |= proj.slot(("field", last))
        return frozenset(out)

    def bind_composite(self, a: int, b: int, model: str | None = None) -> None:
        """Bind function-valued composite fields without crossing struct types."""
        toks = self.toks
        spans = _split_top(toks, a, b)
        positional = bool(model) and all(
            not any(toks[i].kind == "op" and toks[i].value == ":" for i in range(x, y))
            for x, y in spans
        )
        positional_names = list(self.proj.struct_fields_for(model)) if positional else []
        if positional and len(positional_names) != len(spans):
            positional_names = []
        for index, (x, y) in enumerate(spans):
            while x < y and toks[x].kind == "nl":
                x += 1
            field = ""
            value_at = x
            if x + 2 <= y and toks[x].kind == "id" and toks[x + 1].kind == "op" and toks[x + 1].value == ":":
                field = toks[x].value
                value_at = x + 2
            elif positional_names:
                field = positional_names[index]
            if not field:
                continue
            fv = self.funcvals(value_at, y)
            if fv:
                slot = ("field", model, field) if model else ("field", field)
                self.proj.bind(slot, fv)

    def bind_target(self, x: int, y: int, fv: frozenset, strong: bool) -> None:
        """Atama hedefine işlev değeri: yerel ad, x.Alan, kap[k] (yerel ya da paket düzeyi)."""
        toks = self.toks
        while x < y and toks[x].kind == "op" and toks[x].value in ("*", "&"):
            x += 1
        if x >= y or toks[x].kind != "id":
            return
        name = toks[x].value
        local = name in self.fvars or name in self.env or name in self.types or not self._package_var(name)
        if y - x == 1:
            if local:
                self.fvars[name] = fv if strong else self.fvars.get(name, EMPTY) | fv
            else:
                self.proj.bind(("var", self.file.dir, name), fv)
            return
        if toks[y - 1].kind == "id" and y - 2 > x and toks[y - 2].kind == "op" and toks[y - 2].value == ".":
            field = toks[y - 1].value
            struct = self._struct_type_of(name)
            owner = self.proj.function_field_owner(struct, field) if struct else None
            slot = ("field", owner, field) if owner else ("field", field)
            self.proj.bind(slot, fv)
            return
        if toks[y - 1].kind == "op" and toks[y - 1].value == "]" and toks[x + 1].value == "[":
            if local:
                self.fvars[name] = self.fvars.get(name, EMPTY) | fv
            else:
                self.proj.bind(("var", self.file.dir, name), fv)

    def _package_var(self, name: str) -> bool:
        return name in self.file.var_types or any(n == name for n, _, _ in self.file.var_inits)

    def _type_class(self, text: str) -> str | None:
        """Classify known external Go types after resolving import aliases."""
        direct = _go_type_class(text)
        if direct:
            return direct
        normalized = str(text)
        for alias, path in self.file.imports.items():
            if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(alias)}\s*\.", normalized):
                continue
            parts = [part for part in path.split("/") if part]
            package = parts[-1] if parts else alias
            if re.fullmatch(r"v[0-9]+", package) and len(parts) >= 2:
                package = parts[-2]
            normalized = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(alias)}(\s*\.)", package + r"\1", normalized,
            )
        return _go_type_class(normalized)

    # -- giriş -----------------------------------------------------------------
    def run(self) -> Summary:
        for name in self.func.results:
            self.env.setdefault(name, EMPTY)  # adlandırılmış sonuçlar işlevin yerel değişkenleridir
        for index, (name, type_text) in enumerate(self.func.params):
            if name in ("_", ""):
                continue
            self.decl_types[name] = type_text.replace(" ", "")
            cls = self._type_class(type_text)
            if cls:
                self.types[name] = cls
            else:
                self.env[name] = frozenset({Origin(PARAM, str(index), 0, "", ())})
        if self.func.recv and self.func.recv[0] not in ("_", ""):
            cls = self._type_class(self.func.recv[1])
            if cls:
                self.types[self.func.recv[0]] = cls
        if self.func.recv and self.func.recv[1].replace("*", "").strip() in self.file.grpc_server_types and \
                self.func.params and "context.Context" in self.func.params[0][1].replace(" ", ""):
            # 18. tur: gRPC hizmet yöntemi (ctx, in *pb.İleti): istek iletisi istemciden gelir
            for name, type_text in self.func.params[1:]:
                if name not in ("_", "") and type_text.strip().startswith("*"):
                    self.env[name] = frozenset({Origin("request", f"gRPC isteği {name}", self.func.line, self.file.rel, ())})
        a, b = self.func.body
        try:
            self.block(a, b, 0)
        except RecursionError:
            pass
        return self.summary

    # -- deyimler -----------------------------------------------------------
    def block(self, a: int, b: int, depth: int) -> None:
        toks = self.toks
        i = a
        guard = 0
        scope: dict = {}
        if depth > 0:
            self.scopes.append(scope)
        try:
            while i < b:
                t = toks[i]
                if t.kind == "nl" or (t.kind == "op" and t.value in (";", "}")):
                    i += 1
                    continue
                j = self.statement(i, b, depth)
                i = j if j > i else i + 1
                guard += 1
                if guard > 200_000:
                    break
        finally:
            if depth > 0:
                self.scopes.pop()
                self.restore_scope(scope)

    def _terminates(self, j: int) -> bool:
        k = j - 1
        toks = self.toks
        while k >= 0 and toks[k].kind == "nl":
            k -= 1
        if k < 0:
            return True
        prev = toks[k]
        if prev.kind in ("num", "str"):
            return True
        if prev.kind == "id":
            return True
        return prev.kind == "op" and prev.value in (")", "]", "}", "++", "--")

    def simple_end(self, i: int, b: int) -> int:
        toks = self.toks
        depth = 0
        j = i
        while j < b:
            t = toks[j]
            if t.kind == "op":
                if t.value in ("(", "[", "{"):
                    depth += 1
                elif t.value in (")", "]", "}"):
                    if depth == 0:
                        return j
                    depth -= 1
                elif t.value == ";" and depth == 0:
                    return j
            elif t.kind == "nl" and depth == 0 and j > i and self._terminates(j):
                return j
            j += 1
        return j

    def header_brace(self, a: int, b: int) -> int | None:
        toks = self.toks
        depth = 0
        j = a
        while j < b:
            t = toks[j]
            if t.kind == "op":
                if t.value in ("(", "["):
                    depth += 1
                elif t.value in (")", "]"):
                    depth -= 1
                elif t.value == "{" and depth == 0:
                    prev = toks[j - 1] if j > a else None
                    prev2 = toks[j - 2] if j - 2 >= a else None
                    composite = prev is not None and prev.kind == "id" and prev2 is not None and (
                        (prev2.kind == "op" and prev2.value == "]")
                        or (prev2.kind == "op" and prev2.value == "." and j - 4 >= a and toks[j - 4].value == "]"))
                    if prev is not None and prev.kind == "id" and prev.value in ("struct", "interface"):
                        composite = True
                    if composite:
                        j = _match(toks, j) + 1
                        continue
                    return j
            elif t.kind == "id" and t.value == "func" and depth == 0 and j > a:
                j = self.skip_funclit(j, b)
                continue
            j += 1
        return None

    def statement(self, i: int, b: int, depth: int) -> int:
        toks = self.toks
        t = toks[i]
        if t.kind == "op" and t.value == "{":
            close = _match(toks, i)
            self.block(i + 1, close, depth + 1)
            return close + 1
        word = t.value if t.kind == "id" else None
        if word in ("if", "for", "switch", "select"):
            brace = self.header_brace(i + 1, b)
            if brace is None:
                end = self.simple_end(i, b)
                self.eval(i + 1, end)
                return end
            self.header(word, i + 1, brace, depth)
            close = _match(toks, brace)
            if word in ("switch", "select"):
                self.cases(brace + 1, close, depth + 1)
            else:
                self.block(brace + 1, close, depth + 1)
            j = close + 1
            if word == "if" and j < b and toks[j].kind == "id" and toks[j].value == "else":
                if j + 1 < b and toks[j + 1].kind == "id" and toks[j + 1].value == "if":
                    return self.statement(j + 1, b, depth)
                if j + 1 < b and toks[j + 1].value == "{":
                    close2 = _match(toks, j + 1)
                    self.block(j + 2, close2, depth + 1)
                    return close2 + 1
            return j
        if word in ("go", "defer"):
            end = self.simple_end(i + 1, b)
            self.eval(i + 1, end)
            return end
        if word == "return":
            end = self.simple_end(i + 1, b)
            bare_return = all(toks[x].kind == "nl" or (toks[x].kind == "op" and toks[x].value in (";", "}"))
                              for x in range(i + 1, end))
            if bare_return and self.func.results and not self.funclit_depth:
                # çıplak return: adlandırılmış sonuçların o anki izi döner
                self.add_return(frozenset().union(*(self.env.get(nm, EMPTY) for nm in self.func.results)))
            elif end > i + 1:
                self.add_return(self.eval(i + 1, end))
                if not self.funclit_depth:
                    for x, y in _split_top(toks, i + 1, end):
                        fv = self.funcvals(x, y)
                        if fv:
                            self.proj.bind(("ret", self.func.key), fv)
            return end
        if word in ("var", "const"):
            if i + 1 < b and toks[i + 1].value == "(":
                close = _match(toks, i + 1)
                j = i + 2
                while j < close:
                    if toks[j].kind == "nl" or toks[j].value == ";":
                        j += 1
                        continue
                    end = self.simple_end(j, close)
                    self.declaration(j, end, depth)
                    j = max(end, j + 1)
                return close + 1
            end = self.simple_end(i + 1, b)
            self.declaration(i + 1, end, depth)
            return end
        if word in ("type", "break", "continue", "goto", "fallthrough"):
            return self.simple_end(i, b)
        if word in ("case", "default"):
            colon = self.find_colon(i + 1, b)
            if self.scopes:
                self.restore_scope(self.scopes[-1])  # her case yan tümcesi ayrı kapsam
            if word == "case":
                self.eval(i + 1, colon)
            return colon + 1
        if t.kind == "id" and i + 1 < b and toks[i + 1].kind == "op" and toks[i + 1].value == ":":
            return i + 2  # etiket
        end = self.simple_end(i, b)
        self.simple(i, end, depth)
        return end

    def find_colon(self, a: int, b: int) -> int:
        depth = 0
        for j in range(a, b):
            t = self.toks[j]
            if t.kind == "op":
                if t.value in ("(", "[", "{"):
                    depth += 1
                elif t.value in (")", "]", "}"):
                    depth -= 1
                elif t.value == ":" and depth == 0:
                    return j
        return b

    def cases(self, a: int, b: int, depth: int) -> None:
        self.block(a, b, depth)

    def header(self, word: str, a: int, brace: int, depth: int) -> None:
        toks = self.toks
        parts = _split_top(toks, a, brace, ";")
        if word == "for":
            range_at = next((j for j in range(a, brace) if toks[j].kind == "id" and toks[j].value == "range"), None)
            if range_at is not None:
                taint = self.eval(range_at + 1, brace)
                op_at = next((j for j in range(a, range_at) if toks[j].kind == "op" and toks[j].value in (":=", "=")), None)
                if op_at is not None:
                    names = [toks[x].value for x, y in _split_top(toks, a, op_at) if toks[x].kind == "id"]
                    for index, name in enumerate(names):
                        if name == "_":
                            continue
                        # anahtar (dilim/dizi indeksi) için iz taşınmaz; değer ve eşlem anahtarları taşır
                        self.assign(name, taint, strong=False)
                    if len(names) >= 2 and names[1] != "_":
                        fv = self.funcvals(range_at + 1, brace)  # for _, f := range işleyiciler
                        if fv:
                            self.fvars[names[1]] = self.fvars.get(names[1], EMPTY) | fv
                return
            for x, y in parts:
                self.simple(x, y, depth + 1)
            return
        for index, (x, y) in enumerate(parts):
            if index < len(parts) - 1 or self.has_assign(x, y):
                self.simple(x, y, depth + 1 if word != "if" else depth + 1)
            else:
                self.eval(x, y)

    def has_assign(self, a: int, b: int) -> bool:
        depth = 0
        for j in range(a, b):
            t = self.toks[j]
            if t.kind == "op":
                if t.value in ("(", "[", "{"):
                    depth += 1
                elif t.value in (")", "]", "}"):
                    depth -= 1
                elif depth == 0 and t.value in _GO_ASSIGN:
                    return True
        return False

    def declaration(self, a: int, b: int, depth: int) -> None:
        toks = self.toks
        eq = next((j for j in range(a, b) if toks[j].kind == "op" and toks[j].value == "="), None)
        names = []
        j = a
        while j < (eq if eq is not None else b) and toks[j].kind == "id":
            names.append(toks[j].value)
            j += 1
            if j < b and toks[j].kind == "op" and toks[j].value == ",":
                j += 1
                continue
            break
        type_text = "".join(t.value for t in toks[j: eq if eq is not None else b] if t.kind != "nl")
        cls = self._type_class(type_text) if type_text else None
        if type_text:
            for name in names:
                self.decl_types[name] = type_text
        if eq is not None:
            rhs = _split_top(toks, eq + 1, b)
            taints = [self.eval_typed(x, y) for x, y in rhs]
            if len(rhs) == len(names):
                for name, (x, y) in zip(names, rhs):
                    fv = self.funcvals(x, y)
                    if fv:
                        if depth > 0:
                            self.shadow(name)
                        self.fvars[name] = fv
            for index, name in enumerate(names):
                taint, objtype = taints[index] if len(taints) == len(names) else (
                    frozenset().union(*(t for t, _ in taints)) if taints else EMPTY, None)
                if depth > 0:
                    self.shadow(name)
                self.assign(name, taint, strong=True, objtype=cls or objtype)
                if index < len(rhs):
                    model_raw = self._composite_type(rhs[index])
                    model = self.proj.struct_key(self.file, model_raw)
                    fields = self._composite_field_taints(*rhs[index], model=model) if model is not None else None
                    if model_raw:
                        self.decl_types[name] = model_raw
                    if fields is not None:
                        self.struct_values[name] = fields
                    if model is not None:
                        function_fields = self._composite_field_funcvals(*rhs[index], model=model)
                        if function_fields:
                            self.struct_func_values[name] = function_fields
        else:
            for name in names:
                if depth > 0:
                    self.shadow(name)
                    self.env.pop(name, None)
                    self.fvars.pop(name, None)
                if cls:
                    self.types[name] = cls

    def assign(self, name: str, taint: frozenset, strong: bool, objtype: str | None = None) -> None:
        if not name or name == "_":
            return
        if strong:
            if taint:
                self.env[name] = taint
            else:
                self.env.pop(name, None)
            if objtype:
                self.types[name] = objtype
            else:
                self.types.pop(name, None)
        else:
            if taint:
                self.env[name] = self.env.get(name, EMPTY) | taint
            if objtype and name not in self.types:
                self.types[name] = objtype

    def simple(self, a: int, b: int, depth: int) -> None:
        toks = self.toks
        k = None
        d = 0
        for j in range(a, b):
            t = toks[j]
            if t.kind == "op":
                if t.value in ("(", "[", "{"):
                    d += 1
                elif t.value in (")", "]", "}"):
                    d -= 1
                elif d == 0 and t.value in _GO_ASSIGN:
                    k = j
                    break
                elif d == 0 and t.value == "<-" and j > a:
                    # kanal gönderimi: ch <- x
                    taint = self.eval(j + 1, b)
                    if toks[a].kind == "id":
                        self.assign(toks[a].value, taint, strong=False)
                    return
        if k is None:
            self.eval(a, b)
            return
        op = toks[k].value
        lhs = _split_top(toks, a, k)
        rhs = _split_top(toks, k + 1, b)
        typed = [self.eval_typed(x, y) for x, y in rhs]
        declare = op == ":=" and depth > 0  # iç blokta yeni değişken (dıştakini gölgeler)
        if declare:
            for x, y in lhs:
                if y - x == 1 and toks[x].kind == "id":
                    self.shadow(toks[x].value)
        if op in (":=", "="):
            for index, (x, y) in enumerate(lhs):
                if len(rhs) == len(lhs) or (len(rhs) == 1 and index == 0):
                    rx, ry = rhs[index] if len(rhs) == len(lhs) else rhs[0]
                    fv = self.funcvals(rx, ry)
                    if fv:
                        self.bind_target(x, y, fv, strong=depth == 0 or declare)
        for index, (x, y) in enumerate(lhs):
            if len(typed) == len(lhs):
                taint, objtype = typed[index]
            else:
                taint = frozenset().union(*(t for t, _ in typed)) if typed else EMPTY
                objtype = typed[0][1] if len(typed) == 1 and index == 0 else None
                last = toks[y - 1].value if y > x else ""
                if index > 0 and (last in ("err", "ok", "found", "exists") or last.endswith(("Err", "Error"))):
                    taint = EMPTY  # çoklu dönüşte hata/bayrak değeri
            x0 = x
            while x0 < y and toks[x0].kind == "op" and toks[x0].value in ("*", "&"):
                x0 += 1
            if x0 >= y or toks[x0].kind != "id":
                continue
            name = toks[x0].value
            simple_ident = y - x0 == 1
            if not simple_ident and y - x0 > 1:
                # x.alan = ... / x[i] = ... : indeks ifadesindeki hedefleri değerlendir
                for m in range(x0, y):
                    if toks[m].kind == "op" and toks[m].value == "[":
                        close = _match(toks, m)
                        self.eval(m + 1, close)
                        break
            strong = simple_ident and ((op in (":=", "=") and depth == 0) or declare)
            if simple_ident and op in (":=", "=") and strong and len(rhs) == len(lhs):
                model_raw = self._composite_type(rhs[index])
                if model_raw:
                    self.decl_types[name] = model_raw
            if op not in (":=", "="):
                taint = taint | self.env.get(name, EMPTY)
            self.assign(name, taint, strong, objtype if simple_ident else None)
            if simple_ident and index < len(rhs):
                model_raw = self._composite_type(rhs[index])
                model = self.proj.struct_key(self.file, model_raw)
                fields = self._composite_field_taints(*rhs[index], model=model) if model is not None else None
                if fields is not None:
                    self.struct_values[name] = fields
                elif strong:
                    self.struct_values.pop(name, None)
                function_fields = self._composite_field_funcvals(*rhs[index], model=model) if model is not None else {}
                if function_fields:
                    self.struct_func_values[name] = function_fields
                elif rhs[index][1] - rhs[index][0] == 1 and toks[rhs[index][0]].kind == "id" \
                        and toks[rhs[index][0]].value in self.struct_func_values:
                    self.struct_func_values[name] = dict(self.struct_func_values[toks[rhs[index][0]].value])
                elif strong:
                    self.struct_func_values.pop(name, None)
            elif not simple_ident and y - x0 == 3 and toks[x0 + 1].value == "." and toks[x0 + 2].kind == "id":
                if name in self.struct_values:
                    field = toks[x0 + 2].value
                    old = self.struct_values[name].get(field, EMPTY)
                    self.struct_values[name][field] = taint if op in (":=", "=") else old | taint
                if index < len(rhs):
                    fv = self.funcvals(*rhs[index])
                    if fv:
                        self.struct_func_values.setdefault(name, {})[str(toks[x0 + 2].value)] = fv

    # -- ifadeler -------------------------------------------------------------
    def eval(self, a: int, b: int) -> frozenset:
        return self.eval_typed(a, b)[0]

    def _host_pinned(self, a: int, b: int) -> bool:
        """``"//" + r.Host + …`` ya da ``fmt.Sprintf("https://%s…", r.Host, …)``: konak isteğin kendi Host'u."""
        toks = self.toks
        items = [k for k in range(a, b) if toks[k].kind != "nl"]
        if len(items) < 4:
            return False

        def is_host(k: int) -> bool:
            return (k + 2 < b and toks[k].kind == "id" and self.types.get(toks[k].value) == "req"
                    and toks[k + 1].value == "." and toks[k + 2].value == "Host")

        x = items[0]
        if toks[x].kind == "str" and toks[x].value.endswith("//") and _HOST_FIRST.match(toks[x].value):
            y = items[1]
            return toks[y].value == "+" and is_host(items[2])
        if (toks[x].kind == "id" and self.file.imports.get(toks[x].value) == "fmt" and toks[items[1]].value == "."
                and toks[items[2]].value == "Sprintf" and toks[items[3]].value == "("):
            close = _match(toks, items[3])
            spans = _split_top(toks, items[3] + 1, close)
            if len(spans) >= 2:
                fmt_lit = self._literal(spans[0])
                if fmt_lit and _HOST_FIRST.match(fmt_lit[:fmt_lit.find("%") + 2] if "%" in fmt_lit else fmt_lit):
                    hx = spans[1][0]
                    while hx < spans[1][1] and toks[hx].kind == "nl":
                        hx += 1
                    return is_host(hx) and spans[1][1] - hx == 3
        return False

    def eval_typed(self, a: int, b: int) -> tuple[frozenset, str | None]:
        if a < b and self.toks[a].kind in ("str", "id") and self._host_pinned(a, b):
            taint, _ = self._eval_typed(a, b)
            return _clean(taint, frozenset({"redirect"})), None
        return self._eval_typed(a, b)

    def _eval_typed(self, a: int, b: int) -> tuple[frozenset, str | None]:
        toks = self.toks
        result: set[Origin] = set()
        objtype = None
        chains = 0
        i = a
        while i < b:
            t = toks[i]
            if t.kind == "id":
                if t.value == "map" and i + 1 < b and toks[i + 1].value == "[":
                    k = _match(toks, i + 1)
                    m = k + 1
                    while m < b and not (toks[m].kind == "op" and toks[m].value in ("{", ")", ",", ";")) and toks[m].kind != "nl":
                        m += 1
                    if m < b and toks[m].value == "{":
                        close = _match(toks, m)
                        result |= self.eval(m + 1, close)
                        self.bind_composite(m + 1, close)
                        i = close + 1
                    else:
                        i = m
                    continue
                if t.value in ("struct", "interface") and i + 1 < b and toks[i + 1].value == "{":
                    i = _match(toks, i + 1) + 1
                    continue
                if t.value == "chan":
                    i += 1
                    continue
                j, taint, otype = self.chain(i, b)
                result |= taint
                objtype = otype
                chains += 1
                i = max(j, i + 1)
                continue
            if t.kind == "op":
                if t.value == "(":
                    k = _match(toks, i)
                    result |= self.eval(i + 1, k)
                    i = k + 1
                    continue
                if t.value == "[":
                    k = _match(toks, i)
                    if k == i + 1 and k + 2 < b and toks[k + 1].kind == "id" and toks[k + 1].value in ("byte", "rune") \
                            and toks[k + 2].kind == "op" and toks[k + 2].value == "(":
                        # 25. tur: []byte(x) / []rune(x) dönüşümü içeriği taşır (sayısal byte(x) dönüşümünden farklı)
                        m = _match(toks, k + 2)
                        result |= self.eval(k + 3, m)
                        i = m + 1
                        continue
                    i = k + 1  # dilim türü []T
                    continue
                if t.value == "{":
                    k = _match(toks, i)
                    result |= self.eval(i + 1, k)
                    self.bind_composite(i + 1, k)
                    i = k + 1
                    continue
            i += 1
        return frozenset(result), (objtype if chains == 1 else None)

    def skip_funclit(self, i: int, b: int) -> int:
        toks = self.toks
        j = i + 1
        if j < b and toks[j].value == "(":
            j = _match(toks, j) + 1
        depth = 0
        while j < b:
            t = toks[j]
            if t.kind == "op" and t.value in ("(", "["):
                depth += 1
            elif t.kind == "op" and t.value in (")", "]"):
                depth -= 1
            elif t.kind == "op" and t.value == "{" and depth == 0:
                if toks[j - 1].kind == "id" and toks[j - 1].value in ("struct", "interface"):
                    j = _match(toks, j) + 1
                    continue
                return _match(toks, j) + 1
            elif t.kind == "op" and t.value in (",", ")", ";") and depth <= 0:
                return j  # fonksiyon türü (gövdesiz)
            j += 1
        return j

    def funclit(self, i: int, b: int) -> int:
        toks = self.toks
        j = i + 1
        if j >= b or toks[j].value != "(":
            return i + 1
        k = _match(toks, j)
        params, _ = _go_params(toks, j + 1, k)
        m = k + 1
        depth = 0
        while m < b:
            t = toks[m]
            if t.kind == "op" and t.value in ("(", "["):
                depth += 1
            elif t.kind == "op" and t.value in (")", "]"):
                depth -= 1
            elif t.kind == "op" and t.value == "{" and depth == 0:
                if toks[m - 1].kind == "id" and toks[m - 1].value in ("struct", "interface"):
                    m = _match(toks, m) + 1
                    continue
                break
            elif t.kind == "op" and t.value in (",", ")", ";") and depth <= 0:
                return m
            m += 1
        if m >= b:
            return m
        close = _match(toks, m)
        saved_env = {name: self.env.get(name) for name, _ in params}
        saved_types = {name: self.types.get(name) for name, _ in params}
        for name, type_text in params:
            if name in ("_", ""):
                continue
            self.env.pop(name, None)
            cls = self._type_class(type_text)
            if cls:
                self.types[name] = cls
            else:
                self.types.pop(name, None)
        saved_ct = self.ct_safe
        self.ct_safe = False
        self.funclit_depth += 1
        self.lit_params.append({name for name, _ in params})
        try:
            self.block(m + 1, close, 1)
        finally:
            self.lit_params.pop()
            self.funclit_depth -= 1
            self.ct_safe = saved_ct
            for name, value in saved_env.items():
                if value is None:
                    self.env.pop(name, None)
                else:
                    self.env[name] = value
            for name, value in saved_types.items():
                if value is None:
                    self.types.pop(name, None)
                else:
                    self.types[name] = value
        return close + 1

    def source(self, text: str, line: int) -> frozenset:
        return frozenset({Origin("request", text[:60], line, self.file.rel, ())})

    def bind_args(self, callees: list, spans: list) -> None:
        """İşlev değeri argümanları → çağrılan işlevin parametre yuvası (makeHandler(view, ...) → fn(...))."""
        for index, (x, y) in enumerate(spans):
            fv = self.funcvals(x, y)
            if not fv:
                continue
            for callee in callees:
                target = index if callee.variadic is None or index < callee.variadic else callee.variadic
                if target < len(callee.params):
                    self.proj.bind(("param", callee.key, target), fv)

    def chain(self, i: int, b: int) -> tuple[int, frozenset, str | None]:
        toks = self.toks
        t = toks[i]
        name = t.value
        line = t.line
        j = i + 1
        if name in _GO_NO_VALUE:
            return j, EMPTY, None
        if name == "func":
            end = self.funclit(i, b)
            literal = self.file.funclits.get(i)
            if literal is not None and end < b and toks[end].kind == "op" and toks[end].value == "(":
                close = _match(toks, end)
                if close < b:
                    spans = _split_top(toks, end + 1, close)
                    taints = [self.eval(x, y) for x, y in spans]
                    self.bind_args([literal], spans)
                    return close + 1, self.apply_summary([literal], taints, {}, line), None
            return end, EMPTY, None
        if name in self.env or name in self.types or name in self.fvars:
            local = True
        else:
            local = False
        if not local and j < b and toks[j].kind == "op" and toks[j].value == "(" and (name in _GO_BUILTINS or name in _GO_NUMERIC):
            k = _match(toks, j)
            spans = _split_top(toks, j + 1, k)
            taints = [self.eval(x, y) for x, y in spans]
            if name == "append":
                return k + 1, frozenset().union(*taints) if taints else EMPTY, None
            if name == "copy" and len(spans) == 2 and toks[spans[0][0]].kind == "id":
                self.assign(toks[spans[0][0]].value, taints[1], strong=False)
            return k + 1, EMPTY, None
        is_pkg = not local and name in self.file.imports
        taint = self.env.get(name, EMPTY) if local else EMPTY
        objtype = self.types.get(name) if local else self._type_class(self.file.var_types.get(name, "")) if name in self.file.var_types else None
        if not local and not is_pkg and name in self.file.var_types and objtype is None:
            objtype = "db" if re.search(r"(?i)\bdb\b|sql", self.file.var_types.get(name, "")) else None
        segs = [name]
        while j < b:
            tv = toks[j]
            if tv.kind == "op" and tv.value == ".":
                # satır sonundaki nokta: zincir sonraki satırda sürer (q := x.\n    Set(...).\n    Where(...));
                # j, sonraki anlamlı belirtecin hemen öncesine kaydırılır
                while j + 1 < b and toks[j + 1].kind == "nl":
                    j += 1
                if j + 1 < b and toks[j + 1].kind == "op" and toks[j + 1].value == "(":  # tür iddiası .(T)
                    k = _match(toks, j + 1)
                    asserted = "".join(x.value for x in toks[j + 2:k] if x.kind != "nl")
                    objtype = self._type_class(asserted) if asserted != "type" else objtype
                    j = k + 1
                    continue
                if j + 1 >= b or toks[j + 1].kind != "id":
                    break
                sel = toks[j + 1].value
                sline = toks[j + 1].line
                j += 2
                if j < b and toks[j].kind == "op" and toks[j].value == "(":
                    k = _match(toks, j)
                    spans = _split_top(toks, j + 1, k)
                    taint, objtype = self.call(segs, taint, objtype, sel, spans, sline, is_pkg and len(segs) == 1, None)
                    segs.append(sel + "()")
                    j = k + 1
                else:
                    if is_pkg and len(segs) == 1:
                        path = self.file.imports.get(name, "")
                        objtype = "client" if (path == "net/http" and sel == "DefaultClient") else None
                        taint = EMPTY
                    else:
                        taint, objtype = self.select(taint, objtype, sel, segs, sline)
                    segs.append(sel)
                continue
            if tv.kind == "op" and tv.value == "(" and len(segs) == 1:
                k = _match(toks, j)
                spans = _split_top(toks, j + 1, k)
                if local:
                    taints = [self.eval(x, y) for x, y in spans]
                    callees = self.proj.slot_funcs(self.local_funcvals(name), len(spans))
                    taint = taint.union(*taints) if taints else taint  # fonksiyon değeri: argüman izi taşınır
                    if callees:
                        self.bind_args(callees, spans)
                        taint = taint | self.apply_summary(callees, taints, {}, line)
                    objtype = None
                else:
                    taint, objtype = self.call(segs, EMPTY, None, None, spans, line, False, name)
                segs.append("()")
                j = k + 1
                continue
            if tv.kind == "op" and tv.value == "[":
                k = _match(toks, j)
                if k > j + 1:
                    self.eval(j + 1, k)
                j = k + 1
                objtype = None
                continue
            if tv.kind == "op" and tv.value == "{" and all(not s.endswith(")") for s in segs) and (segs[-1][:1].isupper() or is_pkg):
                k = _match(toks, j)
                taint = self.eval(j + 1, k)
                type_name = ".".join(segs)
                model = self.proj.struct_key(self.file, type_name)
                self.bind_composite(j + 1, k, model)
                objtype = self._type_class(type_name)
                j = k + 1
                continue
            break
        return j, taint, objtype

    def _composite_types(self) -> dict[str, str]:
        """İşlevdeki ``ad := Tür{…}`` / ``ad := &Tür{…}`` / ``var ad Tür`` bildirimleri (bir kez hesaplanır)."""
        cached = getattr(self, "_ctypes_cache", None)
        if cached is not None:
            return cached
        out: dict[str, str] = {}
        a, b = self.func.body
        toks = self.toks
        for j in range(a, min(b, len(toks)) - 3):
            t = toks[j]
            if t.kind == "id" and toks[j + 1].kind == "op" and toks[j + 1].value in (":=", "="):
                k = j + 2
                if toks[k].kind == "op" and toks[k].value == "&":
                    k += 1
                if k + 1 < b and toks[k].kind == "id" and toks[k + 1].kind == "op" and toks[k + 1].value == "{" \
                        and self.proj.struct_key(self.file, str(toks[k].value)) is not None:
                    out.setdefault(str(t.value), str(toks[k].value))
            elif t.kind == "id" and t.value == "var" and toks[j + 1].kind == "id" and toks[j + 2].kind == "id" \
                    and self.proj.struct_key(self.file, str(toks[j + 2].value)) is not None:
                out.setdefault(str(toks[j + 1].value), str(toks[j + 2].value))
        self._ctypes_cache = out
        return out

    def _struct_type_of(self, name: str) -> tuple[str, str] | None:
        typ = self.decl_types.get(name)
        if typ is None and self.func.recv and self.func.recv[0] == name:
            typ = self.func.recv[1]
        if typ is None:
            typ = self._composite_types().get(name)
        if not typ:
            return None
        return self.proj.receiver_type_key(self.file, typ)

    def select(self, taint: frozenset, objtype: str | None, sel: str, segs: list, line: int) -> tuple[frozenset, str | None]:
        if objtype is None and len(segs) == 1:
            struct = self._struct_type_of(segs[0])
            if struct:
                cls = self._type_class(self.proj.struct_fields_for(struct).get(sel, ""))
                if cls in ("req", "writer", "gin", "echo", "fiber"):
                    return EMPTY, cls  # 19. tur: yardımcı yapının istek/yanıt alanı (h.r *http.Request)
                fields = self.struct_values.get(segs[0])
                if fields is not None and sel in fields:
                    return fields[sel], cls
        if objtype == "req":
            if sel in _GO_REQ_FIELDS:
                return self.source(f"{segs[0]}.{sel}", line), ("url" if sel == "URL" else None)
            return EMPTY, None
        if objtype == "gin" and sel == "Request":
            return EMPTY, "req"
        if objtype == "gin" and sel == "Writer":
            return EMPTY, "writer"
        if objtype in ("gin", "echo", "fiber", "writer", "client", "hparams", "db"):
            return EMPTY, None
        if objtype == "url":
            return taint, None
        return taint, None

    # -- çağrılar -------------------------------------------------------------
    def _literal(self, span: tuple[int, int]) -> str | None:
        x, y = span
        items = [t for t in self.toks[x:y] if t.kind != "nl"]
        if len(items) == 1 and items[0].kind == "str":
            return items[0].value
        return None

    def _leading_literal(self, span: tuple[int, int]) -> str | None:
        """Adres/yol ifadesinin baştaki sabit kısmı: "sabit" + x, fmt.Sprintf("sabit%s", x)."""
        x, y = span
        toks = self.toks
        while x < y and toks[x].kind == "nl":
            x += 1
        if x >= y:
            return None
        if toks[x].kind == "str":
            return toks[x].value
        if (toks[x].kind == "id" and x + 3 < y and toks[x + 1].value == "." and toks[x + 2].value == "Sprintf"
                and toks[x + 3].value == "(" and x + 4 < y and toks[x + 4].kind == "str"):
            return toks[x + 4].value
        return None

    def _stringish(self, span: tuple[int, int]) -> bool:
        x, y = span
        toks = self.toks
        while x < y and toks[x].kind == "nl":
            x += 1
        if x >= y:
            return False
        if toks[x].kind == "op" and toks[x].value == "&":
            return False
        for m in range(x, y):
            if toks[m].kind == "op" and toks[m].value == "{":
                return False
        return True

    def _is_writer(self, span: tuple[int, int]) -> bool:
        x, y = span
        toks = self.toks
        items = [t for t in toks[x:y] if t.kind != "nl"]
        if len(items) == 1 and items[0].kind == "id":
            return self.types.get(items[0].value) == "writer"
        if len(items) == 3 and items[0].kind == "id" and items[2].value == "Writer":
            return self.types.get(items[0].value) in ("gin", "echo")
        return False

    def _ssrf(self, name: str, spans: list, taints: list, index: int, line: int) -> None:
        if index >= len(taints):
            return
        lead = self._leading_literal(spans[index])
        kind = "ssrf_partial" if lead is not None and _FIXED_HOST.match(lead) else "ssrf"
        self.sink(kind, name, taints[index], line)

    def _redirect(self, name: str, spans: list, taints: list, index: int, line: int) -> None:
        if index >= len(taints):
            return
        lead = self._leading_literal(spans[index])
        if lead is not None and (_SAFE_REDIRECT.match(lead) or _FIXED_HOST.match(lead)):
            return
        self.sink("redirect", name, taints[index], line)

    def _bind_targets(self, spans: list, taint: frozenset, skip: int = 0) -> None:
        for x, y in spans[skip:]:
            items = [t for t in self.toks[x:y] if t.kind != "nl"]
            if len(items) >= 2 and items[0].kind == "op" and items[0].value == "&" and items[1].kind == "id":
                self.assign(items[1].value, taint, strong=False)
            elif len(items) == 1 and items[0].kind == "id" and items[0].value in self.env:
                self.assign(items[0].value, taint, strong=False)

    def call(self, segs: list, recv_taint: frozenset, recv_type: str | None, method: str | None, spans: list,
             line: int, is_pkg: bool, direct: str | None) -> tuple[frozenset, str | None]:
        taints = [self.eval(x, y) for x, y in spans]
        all_taint = frozenset().union(*taints) if taints else EMPTY
        path = self.file.imports.get(segs[0], "") if is_pkg else ""
        fn = method if is_pkg else None
        label = f"{segs[0]}.{method}" if method else (direct or "")
        # 1) kaynaklar ve bağlama
        if method and recv_type in _GO_OBJ_SOURCES:
            if method in _GO_OBJ_SOURCES[recv_type]:
                text = f"{segs[0]}.{method}" if len(segs) == 1 else f"{'.'.join(segs)}.{method}"
                return self.source(text, line), None
            if recv_type == "fiber" and method == "Bind" and not spans:
                return EMPTY, "fiber_bind"
            if recv_type in _GO_OBJ_BINDS and method in _GO_OBJ_BINDS[recv_type]:
                self._bind_targets(spans, self.source(f"{segs[0]}.{method}", line))
                return EMPTY, None
            if recv_type == "echo" and method == "Request":
                return EMPTY, "req"
        if method in ("Clone", "WithContext") and recv_type == "req" and len(spans) == 1:
            # net/http returns another *Request; preserve its receiver type so
            # request sources remain available on the cloned/contextual value.
            return EMPTY, "req"
        if is_pkg:
            if (path.endswith("gorilla/mux") and fn == "Vars") or ("go-chi/chi" in path and fn in ("URLParam", "URLParamFromCtx")) \
                    or (path.endswith("julienschmidt/httprouter") and fn == "ParamsFromContext"):
                return self.source(f"{segs[0]}.{fn}", line), ("hparams" if fn == "ParamsFromContext" else None)
            if fn == "ReadFile" and path in ("os", "io/ioutil"):
                # Dosya içeriği: yol istekten gelse de içerik saldırganın yazdığı HTML değildir (yol aşımı ayrı hedef).
                self.sinks(segs, recv_type, method, path, fn, spans, taints, line, label)
                return _clean(all_taint, _FILE_CONTENT_CLEAN), None
            cleaned = _go_sanitizer(path, fn)
            if cleaned == "all":
                return EMPTY, None
            if isinstance(cleaned, frozenset):
                return _clean(all_taint, cleaned), None
        if method and not is_pkg:
            stored = self._stored_io(segs, recv_taint, recv_type, method, spans, taints, line)
            if stored is not None:
                self.sinks(segs, recv_type, method, path, fn, spans, taints, line, label)
                return stored, None
            if method in ("Sanitize", "SanitizeBytes", "SanitizeReader") and len(spans) == 1:
                return _clean(all_taint, frozenset({"html"})), None  # bluemonday ilkesi: HTML arındırıcısı
        if method and not is_pkg and method in _GO_CLEAN_METHODS:
            self.sinks(segs, recv_type, method, path, fn, spans, taints, line, label)
            return EMPTY, None
        # 2) hedefler
        self.sinks(segs, recv_type, method, path, fn, spans, taints, line, label)
        # 3) yan etkiler (bağlama/çözme/yazma)
        if is_pkg and fn == "Unmarshal" and spans:
            self._bind_targets(spans, taints[0], skip=1)
        elif is_pkg and path == "fmt" and fn in ("Sscanf", "Sscan", "Sscanln") and spans:
            self._bind_targets(spans, taints[0], skip=1)
        elif is_pkg and path == "fmt" and fn in ("Fprintf", "Fprint", "Fprintln") and spans and not self._is_writer(spans[0]):
            self._bind_targets(spans[:1], frozenset().union(*taints[1:]) if len(taints) > 1 else EMPTY)
        elif method in ("Decode", "Unmarshal") and not is_pkg and (recv_taint or all_taint):
            self._bind_targets(spans, recv_taint | all_taint)
        elif method in ("Write", "WriteString", "WriteByte", "WriteRune") and not is_pkg and len(segs) == 1 and recv_type != "writer":
            if all_taint:
                self.assign(segs[0], all_taint, strong=False)
        if method in ("Prepare", "PrepareContext", "Preparex", "PrepareNamed") and not is_pkg:
            return EMPTY, "stmt"
        # 4) proje fonksiyonları
        field_slot_known = False
        callees: list[GoFunc] = []
        if method and not is_pkg and segs:
            struct = self._struct_type_of(segs[0])
            owner = self.proj.function_field_owner(struct, method) if struct else None
            field_slot_known = owner is not None
            if field_slot_known:
                local_values = self.struct_func_values.get(segs[0], {}).get(method)
                callees = self.proj.slot_funcs(
                    local_values if local_values is not None else self.proj.slot(("field", owner, method)),
                    len(spans),
                )
        if not field_slot_known:
            # A statically known local receiver type selects methods only from
            # that package.  Equal simple type names in sibling packages are
            # distinct in Go and must never share summaries.
            if method and not is_pkg and segs and (struct := self._struct_type_of(segs[0])) is not None:
                callees = self._methods_named(method, struct)
            else:
                callees = self.proj.resolve(self.file, segs, method, direct, is_pkg, len(spans))
        if callees:
            self.bind_args(callees, spans)
            return self.apply_summary(callees, taints, {}, line), None
        # 5) varsayılan yayılım
        if method in _GO_ERROR_RETURNING and not is_pkg:
            return EMPTY, None  # hata değeri döner
        if method in _GO_HTML_SAFE_TRANSFORMS:
            return _clean(recv_taint | all_taint, frozenset({"html"})), None
        if direct or is_pkg:
            if is_pkg and path == "encoding/json" and fn == "NewDecoder":
                return all_taint, None
            if is_pkg and path == "net/http" and fn in ("Get", "Post", "Head", "PostForm", "NewRequest", "NewRequestWithContext"):
                return EMPTY, None
            if is_pkg and path in ("database/sql",):
                return EMPTY, None
            if is_pkg and ((path == "os" and fn in ("ReadFile", "Open", "OpenFile", "ReadDir", "Stat", "Lstat", "DirFS"))
                           or (path == "io/ioutil" and fn in ("ReadFile", "ReadDir"))):
                # 17. tur: dosya içeriği/tanıtıcısı yolu seçen istemcinin denetiminde değildir (yol aşımı ayrı hedef)
                return EMPTY, None
            if is_pkg and re.match(r"(?:Write|Render|Respond|Send|Serve|Execute|Encode|Log|Print|Fprint|Error)", fn or ""):
                return EMPTY, None  # yanıt yazıcıları / günlük: hata döner
            return all_taint, None
        result = recv_taint if method not in _GO_CLEAN_METHODS else EMPTY
        if method in _GO_METHOD_ARG_PROP:
            result = result | all_taint
        return result, None

    def sinks(self, segs: list, recv_type: str | None, method: str | None, path: str, fn: str | None,
              spans: list, taints: list, line: int, label: str) -> None:
        def check(kind: str, index: int, name: str) -> None:
            if index < len(taints):
                self.sink(kind, name, taints[index], line)

        if fn and path:
            if path == "os/exec" and fn in ("Command", "CommandContext"):
                off = 1 if fn == "CommandContext" else 0
                if off < len(spans):
                    literal = self._literal(spans[off])
                    if literal is None:
                        check("command", off, f"exec.{fn}")
                    elif literal in _GO_SHELLS or literal.rsplit("/", 1)[-1] in _GO_SHELLS:
                        for index in range(off + 1, len(spans)):
                            check("command", index, f"exec.{fn}")
                return
            if path == "syscall" and fn in ("Exec", "ForkExec"):
                check("command", 0, f"syscall.{fn}")
                return
            if path == "os" and fn == "StartProcess":
                check("command", 0, "os.StartProcess")
                return
            if path in ("html/template",) and fn in ("HTML", "JS", "HTMLAttr", "CSS", "URL", "JSStr", "Srcset"):
                check("html", 0, f"template.{fn}")
                return
            if path == "net/http":
                if fn in ("Get", "Head", "Post", "PostForm"):
                    self._ssrf(f"http.{fn}", spans, taints, 0, line)
                elif fn == "NewRequest":
                    self._ssrf("http.NewRequest", spans, taints, 1, line)
                elif fn == "NewRequestWithContext":
                    self._ssrf("http.NewRequestWithContext", spans, taints, 2, line)
                elif fn == "Redirect":
                    self._redirect("http.Redirect", spans, taints, 2, line)
                elif fn == "ServeFile":
                    check("path", 2, "http.ServeFile")
                return
            if path == "os" and fn in _GO_OS_PATH:
                check("path", 0, f"os.{fn}")
                if fn in ("Rename", "Symlink", "Link"):
                    check("path", 1, f"os.{fn}")
                return
            if path == "io/ioutil" and fn in ("ReadFile", "WriteFile", "ReadDir"):
                check("path", 0, f"ioutil.{fn}")
                return
            if path == "io" and fn == "WriteString" and spans and self._is_writer(spans[0]) and not self.ct_safe:
                check("html", 1, "io.WriteString(http.ResponseWriter)")
                return
            if path == "fmt" and fn in ("Fprintf", "Fprint", "Fprintln") and spans and self._is_writer(spans[0]) and not self.ct_safe:
                for index in range(1, len(spans)):
                    check("html", index, f"fmt.{fn}(http.ResponseWriter)")
                return
            return
        if not method:
            return
        # Content-Type başlığı (yanıt yazımı XSS'inin bağlamı)
        if method in ("Set", "Add") and "Header()" in segs and len(spans) == 2:
            name = (self._literal(spans[0]) or "").lower()
            x1, y1 = spans[1]
            literals = " ".join(t.value for t in self.toks[x1:y1] if t.kind == "str").lower()
            if name == "content-type" and "html" not in literals:
                self.ct_safe = True  # açıkça ayarlanmış HTML dışı içerik türü
            elif name == "content-disposition" and literals.strip().strip('"`').startswith("attachment"):
                self.ct_safe = True  # ek olarak indirilir: tarayıcı belgeyi işlemez
            return
        if recv_type in ("gin", "echo") and method == "Header" and len(spans) == 2:
            header = (self._literal(spans[0]) or "").lower()
            if header == "content-type" and "html" not in (self._literal(spans[1]) or "html").lower():
                self.ct_safe = True
            elif header == "content-disposition" and (self._literal(spans[1]) or "").strip().lower().startswith("attachment"):
                self.ct_safe = True
        if method in _GO_SQL_METHODS and self._db_receiver(segs, recv_type):
            index = _GO_SQL_METHODS[method]
            if method in ("Select", "Get") and recv_type != "db" and not self._db_name(segs):
                return
            if index < len(spans) and self._stringish(spans[index]):
                check("sql", index, f"{segs[-1] if len(segs) > 1 else segs[0]}.{method}")
            return
        if method in _GO_GORM_METHODS and self.file.imports_path("gorm") and self._db_receiver(segs, recv_type):
            index = _GO_GORM_METHODS[method]
            if index < len(spans) and self._stringish(spans[index]) and self._has_string_part(spans[index]):
                check("sql", index, f"gorm.{method}")
            return
        if recv_type == "writer" and method in ("Write", "WriteString") and not self.ct_safe:
            check("html", 0, f"http.ResponseWriter.{method}")
            return
        if len(segs) >= 2 and segs[-1] == "Writer" and method in ("Write", "WriteString") and self.types.get(segs[0]) == "gin" and not self.ct_safe:
            check("html", 0, f"gin.Context.Writer.{method}")
            return
        if recv_type in ("gin", "echo") and method == "Redirect":
            self._redirect(f"{recv_type}.Redirect", spans, taints, 1, line)
            return
        if recv_type == "fiber" and method == "Redirect":
            self._redirect("fiber.Redirect", spans, taints, 0, line)
            return
        if recv_type in ("gin", "echo") and method in ("File", "FileAttachment", "Attachment", "Inline"):
            check("path", 0, f"{recv_type}.{method}")
            return
        if recv_type == "fiber" and method in ("SendFile", "Download"):
            check("path", 0, f"fiber.{method}")
            return
        if recv_type == "gin" and method == "Data" and len(spans) >= 3 and "html" in (self._literal(spans[1]) or "").lower():
            check("html", 2, "gin.Context.Data(text/html)")
            return
        if recv_type == "echo" and method in ("HTML", "HTMLBlob"):
            check("html", 1, f"echo.Context.{method}")
            return
        if recv_type == "client" and method in ("Get", "Head", "Post", "PostForm"):
            self._ssrf(f"http.Client.{method}", spans, taints, 0, line)
            return
        if method == "Parse" and self.file.imports.get(segs[0], "").endswith("template"):
            check("eval", 0, "template.Parse (şablon enjeksiyonu)")
            return
        if method in ("Execute", "ExecuteTemplate") and self.file.imports_path("text/template") \
                and not self.file.imports_path("html/template") and spans and self._is_writer(spans[0]):
            check("html", 1 if method == "Execute" else 2, f"text/template.{method}")

    # -- kayıtlı (ikinci derece) veri -----------------------------------------
    def _sql_text(self, span: tuple[int, int]) -> str:
        x, y = span
        return " ".join(t.value for t in self.toks[x:y] if t.kind == "str")

    @staticmethod
    def _write_cols(text: str) -> str:
        m = _SQL_INSERT_COLS_RE.search(text)
        if m:
            cols = [c.strip(" `\"[]").lower() for c in m.group(1).split(",") if c.strip()]
            return ",".join(cols) if cols and all(re.fullmatch(r"\w+", c) for c in cols) else "*"
        if re.match(r"(?is)\s*update\b", text):
            m = _SQL_SET_RE.search(text)
            cols = re.findall(r"[`\"\[]?(\w+)[`\"\]]?\s*=", m.group(1)) if m else []
            return ",".join(c.lower() for c in cols) or "*"
        return "*"

    @staticmethod
    def _read_cols(text: str) -> frozenset | None:
        m = _SQL_SELECT_COLS_RE.search(text)
        if not m or "*" in m.group(1) or "(" in m.group(1):
            return None
        cols = set()
        for part in m.group(1).split(","):
            part = re.sub(r"(?is)\s+as\s+\w+\s*$", "", part.strip())
            names = re.findall(r"\w+", part.split()[0] if part.split() else "")
            if not names:
                return None
            cols.add(names[-1].lower())
        return frozenset(cols) or None

    def _composite_type(self, span: tuple[int, int]) -> str | None:
        """``T{…}`` / ``&pkg.T{…}`` / ``new(T)`` / ``[]T{}`` → named type text."""
        items = [t for t in self.toks[span[0]:span[1]] if t.kind != "nl"]
        if len(items) >= 4 and items[0].value == "new" and items[1].value == "(":
            items = items[2:]
        elif items and items[0].kind == "op" and items[0].value == "&":
            items = items[1:]
        while len(items) >= 2 and items[0].value == "[" and items[1].value == "]":
            items = items[2:]
        prefix = ""
        if len(items) >= 3 and items[0].kind == "id" and items[1].value == "." and items[2].kind == "id":
            prefix = f"{items[0].value}."
            items = items[2:]
        if len(items) >= 2 and items[0].kind == "id" and items[0].value[:1].isupper() and items[1].value in ("{", ")"):
            return prefix + items[0].value
        return None

    def _composite_field_taints(self, a: int, b: int, *, model: str | None = None) -> dict[str, frozenset] | None:
        """Return keyed or positional struct literal fields without sibling merging."""
        toks = self.toks
        open_at = next((i for i in range(a, b) if toks[i].kind == "op" and toks[i].value == "{"), None)
        if open_at is None:
            return None
        close = _match(toks, open_at)
        if close >= b:
            return None
        spans = _split_top(toks, open_at + 1, close)
        fields: dict[str, frozenset] = {}
        positional: list[frozenset] = []
        keyed = False
        for x, y in spans:
            while x < y and toks[x].kind == "nl":
                x += 1
            colon = next((i for i in range(x, y) if toks[i].kind == "op" and toks[i].value == ":"), None)
            if colon is None:
                if keyed:
                    return None
                positional.append(self.eval(x, y))
                continue
            if positional or colon != x + 1 or toks[x].kind != "id":
                return None
            keyed = True
            fields[toks[x].value] = self.eval(colon + 1, y)
        if positional:
            names = list(self.proj.struct_fields_for(model))
            if len(positional) != len(names):
                return None
            return dict(zip(names, positional))
        return fields

    def _composite_field_funcvals(self, a: int, b: int, *, model: str | None = None,
                                  depth: int = 0) -> dict[str, frozenset]:
        """Resolve direct and promoted function fields for one composite value."""
        if depth > 5:
            return {}
        toks = self.toks
        open_at = next((i for i in range(a, b) if toks[i].kind == "op" and toks[i].value == "{"), None)
        if open_at is None:
            return {}
        close = _match(toks, open_at)
        if close >= b:
            return {}
        spans = _split_top(toks, open_at + 1, close)
        positional_names = list(self.proj.struct_fields_for(model))
        keyed = any(
            x + 1 < y and toks[x].kind == "id" and toks[x + 1].kind == "op" and toks[x + 1].value == ":"
            for x, y in spans
        )
        if not keyed and len(positional_names) != len(spans):
            positional_names = []
        result: dict[str, frozenset] = {}
        for index, (x, y) in enumerate(spans):
            while x < y and toks[x].kind == "nl":
                x += 1
            if x >= y:
                continue
            if x + 1 < y and toks[x].kind == "id" and toks[x + 1].value == ":":
                field, value_at = str(toks[x].value), x + 2
            elif positional_names:
                field, value_at = positional_names[index], x
            else:
                continue
            values = self.funcvals(value_at, y)
            if values:
                result[field] = values
                continue
            if model and field in self.proj.embedded_fields_for(model):
                nested_raw = self._composite_type((value_at, y))
                nested_model = self.proj.struct_key(self.file, nested_raw)
                if nested_model is not None:
                    result.update(self._composite_field_funcvals(
                        value_at, y, model=nested_model, depth=depth + 1
                    ))
        return result

    def _model_of(self, span: tuple[int, int]) -> str | None:
        """GORM hedefi (``&x`` / ``x``) → model adı: bildirilen türden ya da bileşik değişmezden."""
        items = [t for t in self.toks[span[0]:span[1]] if t.kind != "nl"]
        if items and items[0].kind == "op" and items[0].value == "&":
            items = items[1:]
        if len(items) == 1 and items[0].kind == "id":
            raw = self.decl_types.get(items[0].value, "")
            raw = re.sub(r"^(?:\[\d*\]|\*)+", "", raw).rsplit(".", 1)[-1]
            return raw if re.fullmatch(r"[A-Z]\w*", raw or "") else None
        composite = self._composite_type(span)
        return composite.rsplit(".", 1)[-1] if composite else None

    def _bind_stored(self, spans: list, stored: frozenset) -> None:
        """Okunan satırı hedeflere bağla (rows.Scan(&a, &b)); sayısal/zaman türlü hedefler atlanır."""
        for x, y in spans:
            items = [t for t in self.toks[x:y] if t.kind != "nl"]
            if items and items[0].kind == "op" and items[0].value == "&":
                items = items[1:]
            if not items or items[0].kind != "id":
                continue
            name = items[0].value
            if len(items) == 1:
                raw = self.decl_types.get(name, "").lstrip("*")
                if raw in _GO_NUMERIC or raw in _GO_STORED_INERT:
                    continue
            self.assign(name, stored, strong=False)

    def _stored_io(self, segs: list, recv_taint: frozenset, recv_type: str | None, method: str, spans: list,
                   taints: list, line: int) -> frozenset | None:
        """Kayıtlı veri: tabloya yazma (yan etki) ve tablodan okuma. Okumada çağrının değerini döndürür, yoksa None."""
        if method == "Scan" and len(segs) >= 1:
            stored = frozenset(o for o in recv_taint if o.label == "stored")
            if stored:
                self._bind_stored(spans, stored)
                return EMPTY
            return None
        gorm = self.file.imports_path("gorm")
        if gorm and (method in _GO_GORM_WRITES or method in _GO_GORM_READS) and spans and self._db_receiver(segs, recv_type):
            model = self._model_of(spans[0])
            if not model:
                return None
            if method in _GO_GORM_WRITES:
                self.sink(STORE_KIND, f"gorm:{model}|*", taints[0], line)
                return None
            stored = self.proj.stored_for(f"gorm:{model}")
            if stored:
                self._bind_stored(spans[:1], stored)
            return None
        if not self._db_receiver(segs, recv_type):
            return None
        if method in _GO_SQLX_BIND_READS and len(spans) > 1 and (recv_type == "db" or self._db_name(segs)):
            text = self._sql_text(spans[1])
            m = _SQL_READ_RE.match(text)
            if m:
                stored = self.proj.stored_for(m.group(1).lower(), self._read_cols(text))
                if stored:
                    self._bind_stored(spans[:1], stored)
            return None
        if method in _GO_SQL_WRITE_METHODS:
            index = _GO_SQL_WRITE_METHODS[method]
            if index < len(spans):
                text = self._sql_text(spans[index])
                m = _SQL_WRITE_RE.match(text)
                if m:
                    written = frozenset().union(*taints[index:]) if taints[index:] else EMPTY
                    self.sink(STORE_KIND, f"{m.group(1).lower()}|{self._write_cols(text)}", written, line)
                    return None
        if method in _GO_SQL_READ_METHODS:
            index = _GO_SQL_READ_METHODS[method]
            if index < len(spans):
                text = self._sql_text(spans[index])
                m = _SQL_READ_RE.match(text)
                if m:
                    stored = self.proj.stored_for(m.group(1).lower(), self._read_cols(text))
                    return stored if stored else None
        return None

    def _has_string_part(self, span: tuple[int, int]) -> bool:
        x, y = span
        return any(t.kind == "str" or (t.kind == "op" and t.value == "+") or (t.kind == "id" and t.value == "Sprintf")
                   for t in self.toks[x:y]) or all(t.kind in ("id", "nl") for t in self.toks[x:y])

    @staticmethod
    def _db_name(segs: list) -> bool:
        root = segs[0].lower()
        return bool(re.search(r"db|tx|conn|sql|database|pool|store|repo", root)) and "stmt" not in root

    def _db_receiver(self, segs: list, recv_type: str | None) -> bool:
        if recv_type in ("req", "gin", "echo", "fiber", "url", "writer", "client", "hparams", "stmt"):
            return False
        if self.types.get(segs[0]) == "stmt" or "stmt" in segs[0].lower():
            return False  # hazır ifade: argümanlar bağlanan parametrelerdir
        if recv_type == "db" or self.types.get(segs[0]) == "db":
            return True
        if segs[0] in self.file.imports:
            return False
        if self._db_name(segs) or any(re.search(r"(?i)db|tx\b|conn|sql", s) for s in segs[1:]):
            return True
        return False


_GO_STRUCT_RE = re.compile(r"\btype\s+([A-Za-z_]\w*)\s+struct\s*\{(.*?)\}", re.S)
_GO_FUNC_TYPE_RE = re.compile(r"(?m)^\s*type\s+([A-Za-z_]\w*)\s*(?:=\s*)?func\s*\(")
_GO_TYPE_BLOCK_RE = re.compile(r"(?ms)^\s*type\s*\(\s*(.*?)^\s*\)")
_GO_GROUP_FUNC_TYPE_RE = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*(?:=\s*)?func\s*\(")
_GO_DIRECT_ALIAS_RE = re.compile(
    r"(?m)^\s*type\s+([A-Za-z_]\w*)\s*(?:=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*(?://.*)?$"
)
_GO_GROUP_ALIAS_RE = re.compile(
    r"(?m)^\s*([A-Za-z_]\w*)\s*(?:=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*(?://.*)?$"
)
_GO_EXACT_ALIAS_RE = re.compile(
    r"(?m)^\s*type\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*(?://.*)?$"
)
_GO_GROUP_EXACT_ALIAS_RE = re.compile(
    r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*(?://.*)?$"
)


def _go_function_types(text: str) -> set[str]:
    """Collect named function types and alias chains, including ``type (...)`` groups."""
    result = set(_GO_FUNC_TYPE_RE.findall(text))
    aliases = list(_GO_DIRECT_ALIAS_RE.findall(text))
    for block in _GO_TYPE_BLOCK_RE.findall(text):
        result.update(_GO_GROUP_FUNC_TYPE_RE.findall(block))
        aliases.extend(_GO_GROUP_ALIAS_RE.findall(block))
    reverse: dict[str, set[str]] = {}
    for name, target in aliases:
        reverse.setdefault(target.rsplit(".", 1)[-1], set()).add(name)
    pending = list(result)
    while pending:
        for name in reverse.get(pending.pop(), ()):
            if name not in result:
                result.add(name)
                pending.append(name)
    return result


def _go_struct_fields(text: str) -> dict[str, dict[str, str]]:
    """19. tur: yapı alanı türleri (ad → {alan: tür}); istek/yanıt nesnesini taşıyan sarmalayıcılar
    (type yardımcı struct { w http.ResponseWriter; r *http.Request }) için."""
    out: dict[str, dict[str, str]] = {}
    for m in _GO_STRUCT_RE.finditer(text):
        fields: dict[str, str] = {}
        for line in re.split(r"[;\n]", m.group(2)):
            line = line.split("//", 1)[0].strip()
            fm = re.match(r"^([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+([*\w.\[\]]+)", line)
            if fm:
                for name in fm.group(1).split(","):
                    fields[name.strip()] = fm.group(2)
                continue
            embedded = re.fullmatch(r"\*?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)", line)
            if embedded:
                # Anonymous fields promote their members (Job{Base}.Run).
                # Keep the ordinary field name/type as well so positional
                # composite literals retain declaration order.
                raw = embedded.group(1)
                fields[raw.rsplit(".", 1)[-1]] = line
        out[m.group(1)] = fields
    return out


def _go_embedded_struct_fields(text: str) -> dict[str, set[str]]:
    """Return anonymous struct field names, separate from named same-type fields."""
    out: dict[str, set[str]] = {}
    for match in _GO_STRUCT_RE.finditer(text):
        names: set[str] = set()
        for raw_line in re.split(r"[;\n]", match.group(2)):
            line = raw_line.split("//", 1)[0].strip()
            embedded = re.fullmatch(r"\*?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)", line)
            if embedded:
                names.add(embedded.group(1).rsplit(".", 1)[-1])
        if names:
            out[match.group(1)] = names
    return out


class GoProject(_ProjectBase):
    def __init__(self, files: dict[str, str]) -> None:
        super().__init__()
        self.files: list[GoFile] = []
        self.struct_fields: dict[str, dict[str, str]] = {}
        self.embedded_struct_fields: dict[str, set[str]] = {}
        self.function_types: set[str] = set()
        go_type_sources: list[str] = []
        for rel, text in files.items():
            if not rel.endswith(".go"):
                continue
            go_type_sources.append(text)
            if "struct" in text:
                for name, fields in _go_struct_fields(text).items():
                    self.struct_fields.setdefault(name, {}).update(fields)
                for name, fields in _go_embedded_struct_fields(text).items():
                    self.embedded_struct_fields.setdefault(name, set()).update(fields)
        self.function_types.update(_go_function_types("\n".join(go_type_sources)))
        module = ""
        for rel, text in files.items():
            if rel.endswith("go.mod"):
                m = re.search(r"^module\s+(\S+)", text, re.M)
                if m:
                    module = m.group(1)
        self.module = module
        for rel, text in files.items():
            if not rel.endswith(".go"):
                continue
            try:
                self.files.append(parse_go_file(rel, text))
            except (RecursionError, IndexError, ValueError):
                continue
        # Package-qualified identity for user-defined Go types.  The legacy
        # simple-name tables above remain useful as a conservative fallback,
        # but they must not merge two real packages that both declare Task,
        # Runner, and similar common names.
        self.dirs = {gf.dir for gf in self.files}
        self.qualified_struct_fields: dict[tuple[str, str], dict[str, str]] = {}
        self.qualified_embedded_struct_fields: dict[tuple[str, str], set[str]] = {}
        self.struct_files: dict[tuple[str, str], GoFile] = {}
        self.function_type_keys: set[tuple[str, str]] = set()
        aliases: list[tuple[GoFile, str, str]] = []
        exact_aliases: list[tuple[GoFile, str, str]] = []
        text_by_rel = {rel: text for rel, text in files.items() if rel.endswith(".go")}
        for gf in self.files:
            text = text_by_rel.get(gf.rel, "")
            for name, fields in _go_struct_fields(text).items():
                key = (gf.dir, name)
                self.qualified_struct_fields.setdefault(key, {}).update(fields)
                self.struct_files.setdefault(key, gf)
            for name, fields in _go_embedded_struct_fields(text).items():
                self.qualified_embedded_struct_fields.setdefault((gf.dir, name), set()).update(fields)
            direct = set(_GO_FUNC_TYPE_RE.findall(text))
            exact_aliases.extend((gf, name, target) for name, target in _GO_EXACT_ALIAS_RE.findall(text))
            for block in _GO_TYPE_BLOCK_RE.findall(text):
                direct.update(_GO_GROUP_FUNC_TYPE_RE.findall(block))
                aliases.extend((gf, name, target) for name, target in _GO_GROUP_ALIAS_RE.findall(block))
                exact_aliases.extend(
                    (gf, name, target) for name, target in _GO_GROUP_EXACT_ALIAS_RE.findall(block)
                )
            self.function_type_keys.update((gf.dir, name) for name in direct)
            aliases.extend((gf, name, target) for name, target in _GO_DIRECT_ALIAS_RE.findall(text))
        self.type_aliases: dict[tuple[str, str], tuple[str, str]] = {
            (gf.dir, name): self.type_key(gf, target)
            for gf, name, target in exact_aliases
        }
        # Resolve local and imported alias chains to their declaring package.
        for _round in range(16):
            changed = False
            for gf, name, target in aliases:
                target_key = self.type_key(gf, target)
                key = (gf.dir, name)
                if target_key in self.function_type_keys and key not in self.function_type_keys:
                    self.function_type_keys.add(key)
                    changed = True
            if not changed:
                break
        self.by_dir: dict[str, dict[str, list[GoFunc]]] = {}
        self.methods: dict[str, list[GoFunc]] = {}
        self.method_receiver_types: set[tuple[str, str]] = set()
        self.funcs: list[GoFunc] = []
        self.func_by_key: dict[str, GoFunc] = {}
        # İşlev değeri yuvaları: ("field", Alan) | ("var", dizin, ad) | ("param", işlev, sıra) | ("ret", işlev)
        # → orada saklanan/oradan dönen işlevlerin anahtarları. Bağlam duyarsız; sabit noktada büyür.
        self.slots: dict[tuple, set] = {}
        self.slots_changed = False
        for gf in self.files:
            for f in gf.funcs:
                self.funcs.append(f)
                self.func_by_key[f.key] = f
                if f.recv:
                    self.methods.setdefault(f.name, []).append(f)
                    self.method_receiver_types.add(self.resolve_type_key(f.file, f.recv[1]))
                else:
                    self.by_dir.setdefault(gf.dir, {}).setdefault(f.name, []).append(f)
            for lit in gf.funclits.values():
                self.func_by_key[lit.key] = lit
                # Ayrı özet yalnız türü bilinmeyen (veri taşıyabilen) parametresi olan değişmezler için gerekir;
                # parametresizler ve yalnız istek/yanıt türlü olanlar zaten çevreleyen işlevle birlikte analiz edilir.
                if any(name not in ("_", "") and _go_type_class(type_text) is None for name, type_text in lit.params):
                    self.funcs.append(lit)
        self.dirs |= set(self.by_dir)

    def type_key(self, gf: GoFile, raw: str) -> tuple[str, str]:
        """Return a stable package/type key for a local or imported named type."""
        value = re.sub(r"^(?:\[\d*\]|\*)+", "", str(raw).replace(" ", ""))
        value = re.sub(r"\[[^\]]*\]$", "", value)
        if "." in value:
            alias, name = value.rsplit(".", 1)
            directory = self._dir_for_import(gf.imports.get(alias, ""))
            if directory is not None:
                return directory, name
            # Unknown external packages stay isolated from local simple names.
            return f"@{gf.imports.get(alias, alias)}", name
        return gf.dir, value

    def struct_key(self, gf: GoFile, raw: str | tuple[str, str] | None) -> tuple[str, str] | None:
        if not raw:
            return None
        key = self.resolve_type_key(gf, raw)
        return key if key in self.qualified_struct_fields else None

    def resolve_type_key(self, gf: GoFile, raw: str | tuple[str, str]) -> tuple[str, str]:
        """Resolve only real ``type A = B`` aliases, with a deterministic depth bound."""
        key = raw if isinstance(raw, tuple) else self.type_key(gf, raw)
        seen: set[tuple[str, str]] = set()
        for _depth in range(MAX_GO_TYPE_DEPTH + 1):
            target = self.type_aliases.get(key)
            if target is None:
                return key
            if key in seen:
                self.limitations.add("go-method-receivers")
                return key
            seen.add(key)
            key = target
        if key in self.type_aliases:
            self.limitations.add("go-method-receivers")
        return key

    def receiver_type_key(self, gf: GoFile, raw: str | tuple[str, str] | None) -> tuple[str, str] | None:
        """Known concrete receiver identity; interface-only declarations remain conservative."""
        if not raw:
            return None
        key = self.resolve_type_key(gf, raw)
        if key in self.qualified_struct_fields or key in self.method_receiver_types:
            return key
        return None

    def struct_fields_for(self, key: str | tuple[str, str] | None) -> dict[str, str]:
        if isinstance(key, tuple):
            return self.qualified_struct_fields.get(key, {})
        return self.struct_fields.get(key or "", {})

    def embedded_fields_for(self, key: str | tuple[str, str] | None) -> set[str]:
        if isinstance(key, tuple):
            return self.qualified_embedded_struct_fields.get(key, set())
        return self.embedded_struct_fields.get(key or "", set())

    def function_field_owner(self, struct: str | tuple[str, str] | None, field: str, depth: int = 0,
                             seen: frozenset = frozenset()) -> str | tuple[str, str] | None:
        """Resolve a direct or promoted function-valued field to its declaring struct."""
        if not struct or depth > 6 or struct in seen:
            return None
        field_type = self.struct_fields_for(struct).get(field, "")
        normalized_type = field_type.replace("*", "").replace(" ", "").rsplit(".", 1)[-1]
        owner_file = self.struct_files.get(struct) if isinstance(struct, tuple) else None
        named_key = self.type_key(owner_file, field_type) if owner_file is not None and field_type else None
        if field_type.lstrip().startswith("func") or named_key in self.function_type_keys or (
                owner_file is None and normalized_type in self.function_types):
            return struct
        visited = seen | {struct}
        for embedded in sorted(self.embedded_fields_for(struct)):
            raw = self.struct_fields_for(struct).get(embedded, embedded)
            child = self.struct_key(owner_file, raw) if owner_file is not None else \
                raw.replace("*", "").replace(" ", "").rsplit(".", 1)[-1]
            owner = self.function_field_owner(child, field, depth + 1, frozenset(visited))
            if owner is not None:
                return owner
        return None

    def method_receiver_keys(self, struct: tuple[str, str]) -> frozenset[tuple[str, str]]:
        """Receiver plus anonymously embedded receiver types used by promoted Go methods."""
        found: set[tuple[str, str]] = set()
        pending: list[tuple[tuple[str, str], int]] = [(self.resolve_type_key(self.struct_files.get(struct), struct), 0)]
        while pending:
            key, depth = pending.pop()
            if key in found:
                continue
            if len(found) >= MAX_GO_RECEIVER_TYPES:
                self.limitations.add("go-method-receivers")
                break
            found.add(key)
            embedded = self.embedded_fields_for(key)
            if not embedded:
                continue
            if depth >= MAX_GO_TYPE_DEPTH:
                self.limitations.add("go-method-receivers")
                continue
            owner_file = self.struct_files.get(key)
            if owner_file is None:
                continue
            fields = self.struct_fields_for(key)
            for name in sorted(embedded, reverse=True):
                raw = fields.get(name, name)
                pending.append((self.resolve_type_key(owner_file, raw), depth + 1))
        return frozenset(found)

    # -- işlev değeri yuvaları ----------------------------------------------
    def bind(self, slot: tuple, keys: Iterable[str]) -> None:
        current = self.slots.setdefault(slot, set())
        for key in keys:
            if key in current:
                continue
            keep = len(current) < MAX_SLOT_FUNCS
            if not keep:
                summary = self.summaries.get(key)
                security_relevant = summary is not None and (
                    summary.param_sinks or summary.ret_params or summary.ret_intrinsic or summary.ivars
                )
                retained_security = sum(
                    1 for existing in current
                    if (existing_summary := self.summaries.get(existing)) is not None
                    and (existing_summary.param_sinks or existing_summary.ret_params
                         or existing_summary.ret_intrinsic or existing_summary.ivars)
                )
                keep = bool(security_relevant and retained_security < MAX_SLOT_CALLEES)
            if keep:
                current.add(key)
                self.slots_changed = True
            else:
                self.limitations.add("slot-functions")

    def slot(self, slot: tuple) -> frozenset:
        return frozenset(self.slots.get(slot, ()))

    def slot_funcs(self, keys: Iterable[str], arity: int | None = None) -> list[GoFunc]:
        """Yuvadaki işlevler; çağrı argüman sayısı verilirse imzası uymayanlar elenir (Go'da çağrı türü kesin)."""
        funcs = [self.func_by_key[k] for k in sorted(keys) if k in self.func_by_key]
        if arity is not None:
            funcs = [f for f in funcs if (len(f.params) == arity if f.variadic is None else arity >= f.variadic)]
        return self.conservative_methods(funcs)

    def conservative_methods(self, candidates: list[GoFunc]) -> list[GoFunc]:
        """Bound no-op interface fan-out without silently losing taint effects.

        The first bounded group keeps fixed-point discovery deterministic.  Once
        summaries exist, every implementation that returns taint, reaches a sink,
        or writes an instance variable remains a target even beyond that group.
        """
        if len(candidates) <= MAX_SLOT_CALLEES:
            return candidates
        self.limitations.add("slot-callees")
        selected = list(candidates[:MAX_SLOT_CALLEES])
        selected_keys = {func.key for func in selected}
        for func in candidates[MAX_SLOT_CALLEES:]:
            summary = self.summaries.get(func.key)
            if summary is not None and (summary.param_sinks or summary.ret_params
                                        or summary.ret_intrinsic or summary.ivars) \
                    and func.key not in selected_keys:
                selected.append(func)
                selected_keys.add(func.key)
        return selected

    def _dir_for_import(self, path: str) -> str | None:
        cache = self.__dict__.setdefault("_import_dirs", {})
        if path not in cache:
            cache[path] = self._dir_for_import_uncached(path)
        return cache[path]

    def _dir_for_import_uncached(self, path: str) -> str | None:
        if self.module and (path == self.module or path.startswith(self.module + "/")):
            rel = path[len(self.module):].lstrip("/") or "."
            if rel in self.dirs:
                return rel
        parts = path.split("/")
        for n in range(min(4, len(parts)), 0, -1):
            suffix = "/".join(parts[-n:])
            matches = [d for d in self.dirs if d == suffix or d.endswith("/" + suffix)]
            if len(matches) == 1:
                return matches[0]
        return None

    def resolve(self, gf: GoFile, segs: list, method: str | None, direct: str | None, is_pkg: bool,
                arity: int | None = None) -> list[GoFunc]:
        if direct:
            found = self.by_dir.get(gf.dir, {}).get(direct, [])
            # paket düzeyi işlev değişkeni: var h = f / var handlers = map[...]func{...}
            return found or self.slot_funcs(self.slot(("var", gf.dir, direct)), arity)
        if is_pkg and method:
            d = self._dir_for_import(gf.imports.get(segs[0], ""))
            if d is None:
                return []
            return self.by_dir.get(d, {}).get(method, []) or self.slot_funcs(self.slot(("var", d, method)), arity)
        if method:
            candidates = self.methods.get(method, [])
            if candidates:
                return self.conservative_methods(candidates)
            if not candidates and arity is not None:
                # aynı adlı yöntem yoksa: işlev türlü yapı alanı çağrısı (s.Handler(...))
                return self.slot_funcs(self.slot(("field", method)), arity)
        return []

    def analyze(self) -> dict[str, Any]:
        from taint_flow import Analysis

        converged = False
        for round_index in range(MAX_FIXPOINT_ROUNDS):
            self.flowsink = FlowSink()
            self.slots_changed = False
            self.tables_changed = False
            for gf in self.files:
                if gf.var_inits:
                    GoAnalyzer(self, GoFunc("<paket>", gf, [], (0, 0), 0)).package_inits()
            changed = False
            for func in self.funcs:
                previous = self.summaries.get(func.key)
                summary = GoAnalyzer(self, func).run()
                if previous is None or previous.key() != summary.key():
                    changed = True
                self.summaries[func.key] = summary
            if not changed and not self.slots_changed and not self.tables_changed and round_index > 0:
                converged = True
                break
        if not converged:
            self.limitations.add("fixed-point")
        if self.flowsink.truncated:
            self.limitations.add("flow-count")
        results = {}
        for gf in self.files:
            flows = list(self.flowsink.flows.get(gf.rel, {}).values())
            result = Analysis(language="go", flows=sorted(flows, key=_flow_key))
            if self.limitations:
                result.mark_incomplete(*sorted(self.limitations))
            results[gf.rel] = result
        return results



# ---------------------------------------------------------------------------
# Ruby / Rails
# ---------------------------------------------------------------------------
_RB_OPENERS = frozenset({"if", "unless", "while", "until", "case", "begin", "for"})
_RB_MODIFIERS = frozenset({"if", "unless", "while", "until", "rescue"})
_RB_EXPR_OPENER_PREV = frozenset({"=", "(", ",", "||", "&&", "||=", "&&=", "+=", "-=", "<<", "[", "{", "?", ":", "=>",
                                  "return", "and", "or", "not", "!", "then", "do", "else", "puts", "|"})
_RB_REQUEST_TAINTED = frozenset({
    "params", "parameters", "query_string", "body", "raw_post", "headers", "env", "referer", "referrer", "url",
    "original_url", "fullpath", "original_fullpath", "path", "path_info", "host", "user_agent", "cookies",
    "query_parameters", "request_parameters", "path_parameters", "POST", "GET", "authorization", "content_type",
    "accept", "filtered_parameters", "x_forwarded_host", "host_with_port", "domain", "subdomain", "subdomains",
    "ip", "remote_ip", "remote_addr", "forwarded_for", "request_id", "uuid", "media_type", "content_mime_type",
    "format", "formats", "protocol", "scheme", "port", "server_protocol", "server_name", "get_header", "fetch_header",
})
_RB_CLEAN_METHODS = frozenset({
    "to_i", "to_f", "to_r", "to_c", "to_d", "length", "size", "count", "hash", "object_id", "class", "id", "to_bool",
    "bytesize", "ord", "abs", "round", "floor", "ceil", "presence_in",
})
_RB_ARG_PROP = frozenset({
    "join", "gsub", "sub", "gsub!", "sub!", "concat", "prepend", "insert", "merge", "merge!", "push", "append",
    "unshift", "+", "format", "sprintf", "%", "center", "ljust", "rjust", "zip", "tap", "then", "reverse_merge",
    "with_indifferent_access", "fetch", "dig", "values_at", "replace", "update",
})
_RB_CONST_PROP = {
    "Base64": {"decode64", "strict_decode64", "urlsafe_decode64", "encode64", "strict_encode64", "urlsafe_encode64"},
    "CGI": {"unescape", "unescapeHTML", "unescape_html"},
    "URI": {"parse", "join", "decode_www_form_component", "decode_www_form", "decode", "unescape", "extract"},
    "JSON": {"parse"}, "ActiveSupport::JSON": {"decode"}, "Oj": set(), "MultiJson": {"load", "decode"},
    "File": {"join", "expand_path", "dirname", "absolute_path", "realpath"},
    "Pathname": {"new"}, "String": {"new"}, "Array": {"wrap", "new"}, "Rack::Utils": {"parse_query", "parse_nested_query", "unescape"},
    "Addressable::URI": {"parse", "join", "unescape"}, "Rails.root": {"join"}, "Shellwords": {"split", "shellsplit"},
    "ERB::Util": set(), "Nokogiri": {"HTML", "XML"}, "Nokogiri::HTML": {"parse"},
}
_RB_NON_MODEL_CONSTS = frozenset({
    "File", "Dir", "IO", "Open3", "Kernel", "URI", "Net::HTTP", "JSON", "YAML", "Psych", "Marshal", "Base64", "CGI",
    "ERB", "Rails", "Time", "Date", "DateTime", "Struct", "OpenStruct", "Hash", "Array", "String", "Integer", "Float",
    "FileUtils", "Pathname", "Process", "PTY", "HTTParty", "Faraday", "RestClient", "Excon", "Typhoeus", "HTTP", "Oj",
    "Digest", "OpenSSL", "SecureRandom", "Logger", "ActiveSupport", "Rack", "Shellwords", "Nokogiri", "Addressable",
    "BCrypt", "Set", "Regexp", "Math", "Object", "Module", "Class", "Thread", "Mutex", "Timeout", "Benchmark",
    "ActiveRecord::Base", "ApplicationRecord", "Zlib", "StringIO", "Tempfile", "Socket", "TCPSocket",
})
_RB_SQL_METHODS = {
    "where": 0, "not": 0, "rewhere": 0, "order": 0, "reorder": 0, "group": 0, "having": 0, "joins": 0, "select": 0,
    "from": 0, "pluck": 0, "find_by": 0, "find_by!": 0, "exists?": 0, "calculate": 1, "lock": 0, "update_all": 0,
    "delete_all": 0, "find_by_sql": 0, "count_by_sql": 0, "average": 0, "minimum": 0, "maximum": 0, "sum": 0,
    "distinct_on": 0, "in_order_of": 0, "find_or_create_by": 0, "find_or_create_by!": 0, "find_or_initialize_by": 0,
    "delete_by": 0, "destroy_by": 0, "unscope": 0, "or": 0, "references": 0,
}
_RB_SQL_ALL_ARGS = frozenset({"select", "pluck", "group", "order", "reorder", "distinct_on", "references"})
_RB_SQL_CONN_METHODS = frozenset({"execute", "exec_query", "exec_update", "exec_delete", "exec_insert", "select_all",
                                  "select_one", "select_value", "select_values", "select_rows", "query", "exec"})
_RB_COMMON_METHODS = frozenset({
    "new", "call", "save", "save!", "update", "update!", "destroy", "create", "create!", "find", "where", "each", "map",
    "to_s", "to_h", "to_a", "to_json", "as_json", "initialize", "name", "id", "valid?", "errors", "run", "perform",
    "execute", "process", "build", "show", "index", "edit", "delete", "get", "set", "[]", "==", "inspect", "value",
    "render", "send", "include?", "present?", "blank?", "params", "request", "logger", "authenticate", "login",
    "permit", "require", "user", "current_user", "data", "text", "body", "title", "url", "path", "parse", "load",
})
_RB_SINATRA_VERBS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "link", "unlink", "route"})
_RB_SHELLS = frozenset({"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "cmd", "cmd.exe", "powershell", "pwsh"})
# İzin listesi koruması: LISTE.include?(x), x.in?(LISTE), template_exists?(x) ...
_RB_GUARD_PREDICATES = frozenset({"include?", "member?", "key?", "has_key?", "value?", "has_value?", "in?",
                                  "template_exists?", "exists_in?"})
_RB_HASH_METHODS = frozenset({"permit", "permit!", "to_hash", "to_h", "to_unsafe_h", "to_unsafe_hash", "symbolize_keys",
                              "stringify_keys", "slice", "except", "with_indifferent_access", "deep_symbolize_keys",
                              "merge", "reverse_merge", "expect", "compact", "compact_blank", "reject", "transform_values"})
_RB_DANGEROUS_URL_KEYS = frozenset({"host", "domain", "subdomain", "protocol", "port", "user", "password", "only_path"})


@dataclass
class RubyFunc:
    name: str
    file: "RubyFile"
    cls: str
    class_method: bool
    params: list  # konumsal adlar
    kwparams: list
    body: tuple  # (a, b)
    line: int
    sources_ok: bool
    kind: str = "def"  # def | scope | main | view
    variadic: int | None = None
    super_cls: str = ""
    excluded: tuple = ()  # (a, b) aralıkları (ana gövdede iç def'ler)
    visibility: str = "public"  # public | protected | private
    conditional: bool = False  # koşullu yüklenen tanımlar önceki etkin adayı tamamen ezmez
    definition_certainty: str = "always"  # always | maybe | never
    definition_branch_group: int | None = None
    definition_branch_arm: int | None = None
    definition_group_parent_certainty: str = "always"
    definition_group_exhaustive: bool = False
    definition_group_arms: tuple[int, ...] = ()
    visibility_options: tuple[str, ...] = ()

    @property
    def possible_visibilities(self) -> tuple[str, ...]:
        return self.visibility_options or (self.visibility,)

    @property
    def key(self) -> str:
        return f"rb:{self.file.rel}:{self.cls}.{'self.' if self.class_method else ''}{self.name}:{self.line}"

    @property
    def display(self) -> str:
        return f"{self.cls.split('::')[-1] + '.' if self.class_method and self.cls else ''}{self.name}"

    @property
    def param_names(self) -> list:
        return list(self.params) + list(self.kwparams)


@dataclass
class RubyFile:
    rel: str
    toks: list
    funcs: list = field(default_factory=list)
    sinatra: bool = False
    view_segments: list = field(default_factory=list)  # ERB: (tür, belirteçler, satır)
    callbacks: dict = field(default_factory=dict)  # sınıf → [(faz/sıra, yöntem, only, except, koşul, satır)]
    includes: dict = field(default_factory=dict)  # sınıf → [(dahil edilen concern/modül, satır)]
    classes: list = field(default_factory=list)  # [(tam ad, üst sınıf, sınıf mı)]; boş sınıfları da korur


def _rb_params(toks: list[Tok], a: int, b: int) -> tuple[list, list, int | None]:
    positional: list[str] = []
    keywords: list[str] = []
    variadic = None
    for x, y in _split_top(toks, a, b):
        items = [t for t in toks[x:y] if t.kind != "nl"]
        if not items:
            continue
        head = items[0]
        if head.kind == "label":
            keywords.append(head.value)
            continue
        if head.kind == "op" and head.value in ("*", "**", "&"):
            if head.value == "*" and len(items) > 1 and items[1].kind == "id":
                variadic = len(positional)
                positional.append(items[1].value)
            continue
        if head.kind == "id":
            positional.append(head.value)
    return positional, keywords, variadic


# 25. tur: Rails oturum/flash anahtar-değer depoları (istek verisi yazılan anahtar sonraki istekte okunur).
_RB_KV_STORES = frozenset({"flash", "session"})


def _rb_kv_key(toks: list, a: int, b: int) -> str:
    """flash[:error] / flash.now[:notice] / session["ad"] → ":error" / ":notice" / ":ad"; çözülemezse "*"."""
    for j in range(a, b):
        t = toks[j]
        if t.kind == "op" and t.value == "[":
            if j + 2 < len(toks) and toks[j + 2].kind == "op" and toks[j + 2].value == "]" \
                    and toks[j + 1].kind in ("sym", "str") and not getattr(toks[j + 1], "interp", None):
                return ":" + str(toks[j + 1].value).lstrip(":")
            return "*"
    return "*"


def _rb_camel_singular(name: str) -> str:
    """ilişki adı → model adı: comments → Comment, line_items → LineItem, categories → Category, author → Author."""
    base = name
    if base.endswith("ies") and len(base) > 3:
        base = base[:-3] + "y"
    elif base.endswith(("ses", "xes", "ches", "shes")):
        base = base[:-2]
    elif base.endswith("s") and not base.endswith("ss"):
        base = base[:-1]
    return "".join(part.capitalize() for part in base.split("_") if part)


def _rb_sources_ok(rel: str, cls: str, super_cls: str, sinatra: bool) -> bool:
    if re.search(r"(?:^|/)(?:spec|test|tests|features)/", rel) or rel.endswith(("_spec.rb", "_test.rb")):
        return False
    if sinatra:
        return True
    if re.search(r"(?:^|/)app/(?:controllers|helpers|views|api)/", rel) or re.search(r"(?:^|/)controllers?/", rel):
        return True
    if re.search(r"(?:^|/)(?:app|slices/\w+|apps/\w+)/actions/", rel):
        return True  # 19. tur: Hanami eylemleri
    if cls.endswith("Controller") or re.search(r"Controller|ActionController|Sinatra|Grape::API|Roda|Hanami", super_cls):
        return True
    return False


def _rb_block_close(toks: list[Tok], do_at: int, n: int) -> int:
    """``do`` (ya da başka bir açıcı) ile başlayan bloğun ``end`` sırası; bulunamazsa n."""
    depth = 0
    for j in range(do_at, n):
        t = toks[j]
        if t.kind != "id" or (j > 0 and toks[j - 1].kind == "op" and toks[j - 1].value in (".", "&.", "::")):
            continue
        prev = toks[j - 1] if j > 0 else None
        stmt_start = prev is None or prev.kind == "nl" or (prev.kind == "op" and prev.value in ("=", "(", "||=", ";"))
        if t.value in ("do", "def", "class", "module") or (t.value in _RB_OPENERS and stmt_start):
            depth += 1
        elif t.value == "end":
            depth -= 1
            if depth == 0:
                return j
    return n


def _rb_lambda(toks: list[Tok], x: int, y: int, *, allow_trailing: bool = False) -> tuple | None:
    """İfade bir lambda/proc değişmezi ya da yöntem nesnesiyse tanımı:
    ("lam", parametreler, gövde başı, gövde sonu) | ("meth", ad). ``y`` ötesine (do … end gövdesi) bakılabilir."""
    n = len(toks)
    while x < y and toks[x].kind == "nl":
        x += 1
    if x >= y:
        return None
    t = toks[x]
    params: list[str] = []
    j = x + 1
    if t.kind == "op" and t.value == "->":
        if j < n and toks[j].kind == "op" and toks[j].value == "(":
            k = _match(toks, j, n)
            params = [tk.value for tk in toks[j + 1:k] if tk.kind == "id"]
            j = k + 1
        else:
            while j < n and toks[j].kind == "id" and toks[j].value != "do":
                params.append(toks[j].value)
                j += 1
                if j < n and toks[j].kind == "op" and toks[j].value == ",":
                    j += 1
    elif t.kind == "id" and t.value in ("lambda", "proc"):
        pass
    elif t.kind == "const" and t.value == "Proc" and j + 1 < n and toks[j].value == "." and toks[j + 1].value == "new":
        j += 2
    elif t.kind == "id" and t.value == "method" and j + 2 < n and toks[j].value == "(" and toks[j + 1].kind == "sym" \
            and toks[j + 2].value == ")":
        return ("meth", toks[j + 1].value)
    else:
        return None
    if j >= n:
        return None
    opener = toks[j]
    if opener.kind == "op" and opener.value == "{":
        close = _match(toks, j, n)
    elif opener.kind == "id" and opener.value == "do":
        close = _rb_block_close(toks, j, n)
    else:
        return None
    a = j + 1
    if a < close and toks[a].kind == "op" and toks[a].value == "|":
        m = a + 1
        while m < close and not (toks[m].kind == "op" and toks[m].value == "|"):
            m += 1
        params = params or [tk.value for tk in toks[a + 1:m] if tk.kind == "id"]
        a = m + 1
    if not allow_trailing and opener.value == "{" and close + 1 < y \
            and any(tk.kind != "nl" for tk in toks[close + 1:y]):
        return None  # lambda { … }.call(x) gibi: değer değil
    return ("lam", tuple(params), a, close)


def _rb_lambdas_in(toks: list[Tok], x: int, y: int) -> list:
    """Lambda değişmezi ya da değerleri lambda olan karma/dizi değişmezi → tanımlar."""
    while x < y and toks[x].kind == "nl":
        x += 1
    if x >= y:
        return []
    single = _rb_lambda(toks, x, y)
    if single:
        return [single]
    t = toks[x]
    if t.kind == "op" and t.value in ("{", "[") and _match(toks, x, len(toks)) >= y - 1:
        close = _match(toks, x, len(toks))
        out = []
        for ex, ey in _split_top(toks, x + 1, close):
            arrow = next((m for m in range(ex, ey) if toks[m].kind == "op" and toks[m].value == "=>"), None)
            if arrow is None and ex < ey and toks[ex].kind == "label":
                arrow = ex
            item = _rb_lambda(toks, (arrow + 1) if arrow is not None else ex, ey)
            if item:
                out.append(item)
        return out
    return []


def _rb_const_lambdas(rf: "RubyFile") -> dict:
    """Dosyadaki ``SABİT = lambda/karma`` atamaları → tanımlar (aynı dosyadaki çağrılar için)."""
    toks = rf.toks
    out: dict[str, list] = {}
    n = len(toks)
    for i in range(n - 2):
        t = toks[i]
        if t.kind != "const" or toks[i + 1].kind != "op" or toks[i + 1].value != "=":
            continue
        if i > 0 and toks[i - 1].kind not in ("nl",) and not (toks[i - 1].kind == "op" and toks[i - 1].value == ";"):
            continue
        end = i + 2
        depth = 0
        while end < n:
            tk = toks[end]
            if tk.kind == "op" and tk.value in ("(", "[", "{"):
                depth += 1
            elif tk.kind == "op" and tk.value in (")", "]", "}"):
                depth -= 1
            elif tk.kind == "nl" and depth <= 0:
                break
            end += 1
        found = _rb_lambdas_in(toks, i + 2, end)
        if found:
            out[t.value] = found
    return out


def parse_ruby_file(rel: str, text: str) -> RubyFile:
    if rel.endswith((".erb", ".haml")):
        rf = RubyFile(rel, [])
        segments = haml_segments(text) if rel.endswith(".haml") else erb_segments(text)
        for kind, code, line in segments:
            rf.view_segments.append((kind, tokenize_ruby(code, line), line))
        rf.funcs.append(RubyFunc("<view>", rf, "", False, [], [], (0, 0), 1, True, "view"))
        return rf
    toks = tokenize_ruby(text)
    rf = RubyFile(rel, toks)
    rf.sinatra = bool(re.search(r"require\s+['\"]sinatra|Sinatra::(?:Base|Application)|<\s*Grape::API|Roda\b", text))
    n = len(toks)
    stack: list[tuple] = []  # (tür, veri)
    branch_groups: dict[int, dict] = {}
    next_branch_group = 0
    classes: list[tuple[str, str]] = []  # (ad, üst)
    singleton = 0
    instance_visibility = ("public",)
    singleton_visibility = ("public",)
    next_method_visibility: tuple[tuple[str, ...], bool] | None = None  # (görünürlükler, yalnız sınıf yöntemi)
    excluded: list[tuple[int, int]] = []
    callable_constants: dict[tuple[str, str], list[tuple]] = {}
    loop_do_line = -1
    i = 0

    def stmt_start(k: int) -> bool:
        m = k - 1
        while m >= 0 and toks[m].kind == "nl" and False:
            m -= 1
        if m < 0:
            return True
        prev = toks[m]
        if prev.kind == "nl" or (prev.kind == "op" and prev.value in (";",)):
            return True
        if prev.kind == "op" and prev.value in _RB_EXPR_OPENER_PREV:
            return True
        if prev.kind == "id" and prev.value in _RB_EXPR_OPENER_PREV:
            return True
        return False

    def literal_callback_condition(start: int) -> bool | None:
        """Recognize only an entire literal callback condition expression."""
        values: list[str] = []
        depth = 0
        k = start
        while k < n and toks[k].kind != "nl":
            value = toks[k].value
            if value == "," and depth == 0:
                break
            if value in ("(", "[", "{"):
                depth += 1
            elif value in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            values.append(value)
            k += 1
        patterns = {
            ("true",): True,
            ("false",): False,
            ("->", "{", "true", "}"): True,
            ("->", "{", "false", "}"): False,
            ("->", "(", ")", "{", "true", "}"): True,
            ("->", "(", ")", "{", "false", "}"): False,
            ("lambda", "{", "true", "}"): True,
            ("lambda", "{", "false", "}"): False,
            ("proc", "{", "true", "}"): True,
            ("proc", "{", "false", "}"): False,
        }
        return patterns.get(tuple(values))

    def literal_branch_condition(start: int) -> bool | None:
        """Return an exact boolean only for a complete literal branch condition."""
        values: list[str] = []
        depth = 0
        k = start
        while k < n and toks[k].kind != "nl":
            value = str(toks[k].value)
            if depth == 0 and (value == ";" or (toks[k].kind == "id" and value == "then")):
                break
            if value in ("(", "[", "{"):
                depth += 1
            elif value in (")", "]", "}"):
                depth -= 1
            values.append(value)
            k += 1
        while len(values) >= 2 and values[0] == "(" and values[-1] == ")":
            values = values[1:-1]
        if values == ["true"]:
            return True
        if values == ["false"]:
            return False
        return None

    def postfix_condition_certainty(start: int) -> str:
        """Return certainty for a top-level postfix if/unless on one statement."""
        depth = 0
        k = start + 1
        while k < n and toks[k].kind != "nl":
            value = str(toks[k].value)
            if value == ";" and depth == 0:
                break
            if value in ("(", "[", "{"):
                depth += 1
            elif value in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and toks[k].kind == "id" and value in ("if", "unless"):
                literal = literal_branch_condition(k + 1)
                if literal is None:
                    return "maybe"
                taken = literal if value == "if" else not literal
                return "always" if taken else "never"
            k += 1
        return "always"

    def definition_certainty() -> str:
        certainty = "always"
        for kind, data in stack:
            if kind in {"class", "sclass"}:
                continue
            state = data[1] if kind == "kw" and isinstance(data, tuple) else "maybe"
            if state == "never":
                return "never"
            if state == "maybe":
                certainty = "maybe"
        return certainty

    def certainty_not(value: str) -> str:
        return "never" if value == "always" else ("always" if value == "never" else "maybe")

    def certainty_and(left: str, right: str) -> str:
        if "never" in (left, right):
            return "never"
        if left == "always":
            return right
        if right == "always":
            return left
        return "maybe"

    def normalize_visibilities(values) -> tuple[str, ...]:
        present = set(values)
        return tuple(value for value in ("public", "protected", "private") if value in present)

    def method_reachable_in_active_arms(func: RubyFunc) -> bool:
        if func.definition_branch_group is None:
            return True
        for kind, data in stack:
            if kind == "kw" and isinstance(data, tuple) and data[0] == "branch" \
                    and data[4] == func.definition_branch_group:
                return data[5] == func.definition_branch_arm
        return True

    def capture_visibility_arm(group: dict, certainty: str) -> None:
        if certainty == "never":
            return
        named = {
            marker: func.possible_visibilities
            for marker, func in group["named_funcs"].items()
        }
        group["visibility_exits"].append((instance_visibility, singleton_visibility, named))

    def restore_visibility_baseline(group: dict) -> None:
        nonlocal instance_visibility, singleton_visibility
        instance_visibility, singleton_visibility = group["visibility_baseline"]
        for marker, func in group["named_funcs"].items():
            options = group["named_baseline"][marker]
            func.visibility_options = options
            func.visibility = options[0]

    def finish_visibility_group(group: dict, current: str, remaining: str) -> None:
        nonlocal instance_visibility, singleton_visibility
        capture_visibility_arm(group, current)
        exits = list(group["visibility_exits"])
        if remaining != "never":
            baseline_instance, baseline_singleton = group["visibility_baseline"]
            exits.append((baseline_instance, baseline_singleton, dict(group["named_baseline"])))
        if not exits:
            restore_visibility_baseline(group)
            return
        instance_visibility = normalize_visibilities(
            option for state, _singleton, _named in exits for option in state
        )
        singleton_visibility = normalize_visibilities(
            option for _instance, state, _named in exits for option in state
        )
        for marker, func in group["named_funcs"].items():
            options = normalize_visibilities(
                option for _instance, _singleton, named in exits for option in named[marker]
            )
            func.visibility_options = options
            func.visibility = options[0]

    def active_branch() -> tuple[int | None, int | None]:
        for kind, data in reversed(stack):
            if kind == "kw" and isinstance(data, tuple) and data[0] == "branch":
                return data[4], data[5]
        return None, None

    while i < n:
        t = toks[i]
        if t.kind == "const" and stmt_start(i) and i + 1 < n and toks[i + 1].kind == "op" \
                and toks[i + 1].value == "=" and not any(kind == "def" for kind, _ in stack):
            end = i + 2
            depth = 0
            while end < n:
                token = toks[end]
                if token.kind == "op" and token.value in ("(", "[", "{"):
                    depth += 1
                elif token.kind == "op" and token.value in (")", "]", "}"):
                    depth -= 1
                elif token.kind == "nl" and depth <= 0:
                    break
                end += 1
            owner = classes[-1][0] if classes else ""
            key = (owner, str(t.value))
            definitions = _rb_lambdas_in(toks, i + 2, end)
            conditional = any(kind not in {"class", "sclass"} for kind, _ in stack)
            if definitions:
                if conditional:
                    existing = callable_constants.get(key, [])
                    callable_constants[key] = existing + [item for item in definitions if item not in existing]
                else:
                    callable_constants[key] = definitions
            elif not conditional:
                callable_constants.pop(key, None)
            i += 1
            continue
        if t.kind != "id":
            i += 1
            continue
        prev = toks[i - 1] if i > 0 else None
        if prev is not None and prev.kind == "op" and prev.value in (".", "&.", "::"):
            i += 1
            continue
        word = t.value
        if word == "class":
            if i + 1 < n and toks[i + 1].kind == "op" and toks[i + 1].value == "<<":
                stack.append(("sclass", singleton_visibility))
                singleton_visibility = ("public",)
                singleton += 1
                i += 2
                continue
            j = i + 1
            name_parts = []
            while j < n and (toks[j].kind == "const" or (toks[j].kind == "op" and toks[j].value == "::")):
                if toks[j].kind == "const":
                    name_parts.append(toks[j].value)
                j += 1
            super_parts = []
            if j < n and toks[j].kind == "op" and toks[j].value == "<":
                j += 1
                while j < n and (toks[j].kind == "const" or (toks[j].kind == "op" and toks[j].value == "::")):
                    if toks[j].kind == "const":
                        super_parts.append(toks[j].value)
                    j += 1
            outer = classes[-1][0] if classes else ""
            name = "::".join(name_parts)
            full = f"{outer}::{name}" if outer and name else (name or outer)
            rf.classes.append((full, "::".join(super_parts), True))
            classes.append((full, "::".join(super_parts)))
            stack.append(("class", (instance_visibility, singleton_visibility)))
            instance_visibility = ("public",)
            singleton_visibility = ("public",)
            i = j
            continue
        if word == "module":
            j = i + 1
            name_parts = []
            while j < n and (toks[j].kind == "const" or (toks[j].kind == "op" and toks[j].value == "::")):
                if toks[j].kind == "const":
                    name_parts.append(toks[j].value)
                j += 1
            outer = classes[-1][0] if classes else ""
            name = "::".join(name_parts)
            full = f"{outer}::{name}" if outer else name
            rf.classes.append((full, "", False))
            classes.append((full, ""))
            stack.append(("class", (instance_visibility, singleton_visibility)))
            instance_visibility = ("public",)
            singleton_visibility = ("public",)
            i = j
            continue
        if word in ("public", "protected", "private", "public_class_method", "private_class_method") \
                and classes and stmt_start(i) and not any(kind == "def" for kind, _ in stack):
            # Ruby visibility is lexical state for subsequent definitions.  Named
            # modifiers instead update methods already defined in this class.
            # Keep singleton visibility separate: a bare ``private`` outside
            # ``class << self`` does not make a later ``def self.x`` private.
            j = i + 1
            names: set[str] = set()
            while j < n and toks[j].kind != "nl":
                if toks[j].kind == "op" and toks[j].value == ";":
                    break
                if toks[j].kind == "id" and toks[j].value in ("if", "unless"):
                    break
                if toks[j].kind in ("sym", "str") and not getattr(toks[j], "interp", None) \
                        and re.fullmatch(r"[A-Za-z_]\w*[!?=]?", str(toks[j].value)):
                    names.add(str(toks[j].value))
                j += 1
            class_modifier = word.endswith("_class_method")
            visibility = "private" if word.startswith("private") else (
                "protected" if word == "protected" else "public"
            )
            modifier_certainty = postfix_condition_certainty(i)
            wraps_definition = i + 1 < n and toks[i + 1].kind == "id" and toks[i + 1].value == "def"
            if modifier_certainty == "never":
                i += 1
                continue
            if names:
                owner = classes[-1][0]
                class_method = class_modifier or singleton > 0
                for existing in rf.funcs:
                    if existing.cls == owner and existing.class_method == class_method and existing.name in names \
                            and method_reachable_in_active_arms(existing):
                        options = (visibility,) if modifier_certainty == "always" else \
                            normalize_visibilities((*existing.possible_visibilities, visibility))
                        existing.visibility = options[0]
                        existing.visibility_options = options
            elif wraps_definition:
                next_method_visibility = ((visibility,), class_modifier)
            elif not class_modifier:
                if singleton > 0:
                    singleton_visibility = (visibility,) if modifier_certainty == "always" else \
                        normalize_visibilities((*singleton_visibility, visibility))
                else:
                    instance_visibility = (visibility,) if modifier_certainty == "always" else \
                        normalize_visibilities((*instance_visibility, visibility))
            i += 1
            continue
        if word == "def":
            certainty = definition_certainty()
            conditional_definition = certainty == "maybe"
            branch_group, branch_arm = active_branch()
            j = i + 1
            class_method = singleton > 0
            if j + 1 < n and toks[j].kind in ("id", "const") and toks[j + 1].kind == "op" and toks[j + 1].value == ".":
                class_method = class_method or toks[j].value == "self" or toks[j].kind == "const"
                j += 2
            if j >= n:
                break
            name = toks[j].value
            line = toks[j].line
            j += 1
            if j < n and toks[j].kind == "op" and toks[j].value == "=" and not toks[j].sp and j + 1 < n and toks[j + 1].value == "(":
                name += "="
                j += 1
            params: list = []
            kwparams: list = []
            variadic = None
            if j < n and toks[j].kind == "op" and toks[j].value == "(":
                k = _match(toks, j)
                params, kwparams, variadic = _rb_params(toks, j + 1, k)
                j = k + 1
            else:
                k = j
                while k < n and toks[k].kind != "nl" and not (toks[k].kind == "op" and toks[k].value in (";", "=")):
                    k += 1
                params, kwparams, variadic = _rb_params(toks, j, k)
                j = k
            cls, super_cls = classes[-1] if classes else ("", "")
            sources_ok = _rb_sources_ok(rel, cls, super_cls, rf.sinatra)
            visibility_options = singleton_visibility if singleton > 0 else (
                ("public",) if class_method else instance_visibility
            )
            if next_method_visibility is not None:
                pending_visibilities, class_only = next_method_visibility
                if not class_only or class_method:
                    visibility_options = pending_visibilities
                next_method_visibility = None
            visibility = visibility_options[0]
            if j < n and toks[j].kind == "op" and toks[j].value == "=":  # sonsuz tanım: def x = ifade
                k = j + 1
                while k < n and toks[k].kind != "nl":
                    k += 1
                rf.funcs.append(RubyFunc(name, rf, cls, class_method, params, kwparams, (j + 1, k), line, sources_ok,
                                         "def", variadic, super_cls, visibility=visibility,
                                         conditional=conditional_definition, definition_certainty=certainty,
                                         definition_branch_group=branch_group,
                                         definition_branch_arm=branch_arm,
                                         visibility_options=visibility_options))
                excluded.append((i, k))
                i = k
                continue
            func = RubyFunc(name, rf, cls, class_method, params, kwparams, (j, j), line, sources_ok, "def",
                            variadic, super_cls, visibility=visibility, conditional=conditional_definition,
                            definition_certainty=certainty, definition_branch_group=branch_group,
                            definition_branch_arm=branch_arm, visibility_options=visibility_options)
            stack.append(("def", (func, i)))
            i = j
            continue
        if word in ("while", "until", "for") and stmt_start(i):
            stack.append(("kw", (word, "maybe")))
            loop_do_line = t.line
            i += 1
            continue
        if word in ("if", "unless") and stmt_start(i):
            group_id = next_branch_group
            next_branch_group += 1
            parent_certainty = definition_certainty()
            literal = literal_branch_condition(i + 1)
            if literal is None:
                current = "maybe"
            else:
                taken = literal if word == "if" else not literal
                current = "always" if taken else "never"
            remaining = certainty_not(current)
            branch_groups[group_id] = {
                "parent": parent_certainty,
                "arms": {0: current},
                "remaining": remaining,
                "visibility_baseline": (instance_visibility, singleton_visibility),
                "named_funcs": {id(func): func for func in rf.funcs},
                "named_baseline": {id(func): func.possible_visibilities for func in rf.funcs},
                "visibility_exits": [],
            }
            stack.append(("kw", ("branch", current, remaining, certainty_not(remaining), group_id, 0)))
            i += 1
            continue
        if word in ("else", "elsif") and stmt_start(i):
            for stack_index in range(len(stack) - 1, -1, -1):
                kind, data = stack[stack_index]
                if kind != "kw":
                    continue
                # Do not cross another keyword block (for example a nested
                # case/else) and accidentally mutate an outer if-chain.
                if not isinstance(data, tuple) or data[0] != "branch":
                    break
                remaining = data[2]
                group_id = data[4]
                arm_id = data[5] + 1
                capture_visibility_arm(branch_groups[group_id], data[1])
                restore_visibility_baseline(branch_groups[group_id])
                if word == "else":
                    current = remaining
                    next_remaining = "never"
                else:
                    literal = literal_branch_condition(i + 1)
                    branch = "maybe" if literal is None else ("always" if literal else "never")
                    current = certainty_and(remaining, branch)
                    next_remaining = certainty_and(remaining, certainty_not(branch))
                cumulative_taken = certainty_not(next_remaining)
                branch_groups[group_id]["arms"][arm_id] = current
                branch_groups[group_id]["remaining"] = next_remaining
                stack[stack_index] = (
                    "kw", ("branch", current, next_remaining, cumulative_taken, group_id, arm_id)
                )
                break
            i += 1
            continue
        if word in _RB_OPENERS and stmt_start(i):
            stack.append(("kw", (word, "always" if word == "begin" else "maybe")))
            i += 1
            continue
        if word == "do":
            if t.line == loop_do_line:
                loop_do_line = -1
                i += 1
                continue
            stack.append(("do", None))
            i += 1
            continue
        if word == "end":
            if stack:
                kind, data = stack.pop()
                if kind == "def":
                    func, start = data
                    func.body = (func.body[0], i)
                    rf.funcs.append(func)
                    excluded.append((start, i + 1))
                elif kind == "class" and classes:
                    classes.pop()
                    instance_visibility, singleton_visibility = data
                elif kind == "sclass":
                    singleton -= 1
                    singleton_visibility = data
                elif kind == "kw" and isinstance(data, tuple) and data[0] == "branch":
                    finish_visibility_group(branch_groups[data[4]], data[1], data[2])
            i += 1
            continue
        if word == "include" and classes and stmt_start(i) \
                and not any(kind == "def" for kind, _ in stack):
            j = i + 1
            parts: list[str] = []
            while j < n and (toks[j].kind == "const" or (
                    toks[j].kind == "op" and toks[j].value == "::")):
                if toks[j].kind == "const":
                    parts.append(str(toks[j].value))
                j += 1
            if parts:
                module = "::".join(parts)
                targets = rf.includes.setdefault(classes[-1][0], [])
                if not any(item[0] == module for item in targets):
                    targets.append((module, t.line))
            i = max(j, i + 1)
            continue
        if word in (
                    "before_action", "before_filter", "prepend_before_action", "prepend_before_filter",
                    "append_before_action", "append_before_filter", "skip_before_action", "skip_before_filter",
                    "after_action", "after_filter", "prepend_after_action", "prepend_after_filter",
                    "append_after_action", "append_after_filter", "skip_after_action", "skip_after_filter",
                    "around_action", "around_filter", "prepend_around_action", "prepend_around_filter",
                    "append_around_action", "append_around_filter", "skip_around_action", "skip_around_filter",
                    ) \
                and classes and stmt_start(i) and not any(kind == "def" for kind, _ in stack):
            j = i + 1
            callback_parens = 0
            if j < n and toks[j].kind == "op" and toks[j].value == "(":
                callback_parens = 1
                j += 1
            names: list[str] = []
            only: set[str] = set()
            exclude: set[str] = set()
            condition: bool | None = None
            mode = None
            block_at: int | None = None
            callable_blocks: list[tuple[int, int, int, list[str], str | None]] = []
            k = j
            while k < n and toks[k].kind != "nl":
                tk = toks[k]
                # Rails accepts callable filter objects as positional callback
                # arguments (``before_action -> { ... }`` / ``proc { ... }``).
                # Option callables such as ``if: -> { ... }`` are predicates,
                # not callbacks, so only collect these before an option mode.
                if mode is None and (
                        (tk.kind == "op" and tk.value == "->")
                        or (tk.kind == "id" and tk.value in ("lambda", "proc"))
                        or (tk.kind == "const" and tk.value == "Proc")
                ):
                    callable_def = _rb_lambda(toks, k, n, allow_trailing=True)
                    if callable_def is not None and callable_def[0] == "lam":
                        _tag, params, body_at, close = callable_def
                        callable_blocks.append((k, body_at, close, list(params), None))
                        k = close + 1
                        continue
                if tk.kind == "op" and tk.value == "(":
                    callback_parens += 1
                elif tk.kind == "op" and tk.value == ")":
                    callback_parens = max(0, callback_parens - 1)
                elif tk.kind == "op" and tk.value == "{" and callback_parens == 0 and not (
                        k > 0 and toks[k - 1].value in ("->", "lambda", "proc")):
                    block_at = k
                    break
                if tk.kind == "label" and tk.value in ("only", "except", "if", "unless"):
                    mode = tk.value
                    if mode in ("if", "unless"):
                        value = literal_callback_condition(k + 1)
                        if value is not None:
                            condition = value if mode == "if" else not value
                elif tk.kind == "sym" and k + 1 < n and toks[k + 1].kind == "op" and toks[k + 1].value == "=>" \
                        and tk.value in ("only", "except", "if", "unless"):
                    mode = tk.value
                    if mode in ("if", "unless"):
                        value = literal_callback_condition(k + 2)
                        if value is not None:
                            condition = value if mode == "if" else not value
                    k += 1
                elif tk.kind == "sym":
                    if mode == "only":
                        only.add(tk.value)
                    elif mode == "except":
                        exclude.add(tk.value)
                    elif mode is None:
                        names.append(tk.value)
                elif tk.kind == "const" and mode is None:
                    definitions = callable_constants.get((classes[-1][0], str(tk.value))) or \
                        callable_constants.get(("", str(tk.value)))
                    lambda_definitions = [definition for definition in definitions or () if definition[0] == "lam"]
                    alternative_group = f"__sniper_alt_callback_{t.line}_{k}" \
                        if len(lambda_definitions) > 1 else None
                    for definition in lambda_definitions:
                        _tag, params, body_at, close = definition
                        callable_blocks.append((k, body_at, close, list(params), alternative_group))
                elif tk.kind == "str" and mode in ("only", "except"):
                    # Rails accepts strings and %i/%w arrays for callback
                    # action filters.  The bounded lexer represents both as a
                    # string token (percent arrays are space separated).
                    values = {value for value in tk.value.split() if re.fullmatch(r"\w+", value)}
                    if mode == "only":
                        only.update(values)
                    else:
                        exclude.update(values)
                elif tk.kind == "id" and tk.value == "do" and callback_parens == 0:
                    block_at = k
                    break
                k += 1
            phase = "around" if "around" in word else ("after" if "after" in word else "before")
            if word.startswith("skip"):
                kind = f"skip:{phase}"
            elif word.startswith("prepend"):
                kind = f"prepend:{phase}"
            else:
                kind = phase
            cls = classes[-1][0]
            block_close: int | None = None
            if block_at is not None and not kind.startswith("skip:"):
                block_close = _match(toks, block_at, n) if toks[block_at].value == "{" \
                    else _rb_block_close(toks, block_at, n)
                if block_close < n:
                    body_at = block_at + 1
                    params: list[str] = []
                    if body_at < block_close and toks[body_at].kind == "op" and toks[body_at].value == "|":
                        pipe = body_at + 1
                        while pipe < block_close and not (
                                toks[pipe].kind == "op" and toks[pipe].value == "|"):
                            pipe += 1
                        params = [tk.value for tk in toks[body_at + 1:pipe] if tk.kind == "id"]
                        body_at = min(pipe + 1, block_close)
                    callable_blocks.append((block_at, body_at, block_close, params, None))
            if not kind.startswith("skip:"):
                alternative_groups: set[str] = set()
                for callback_at, body_at, callback_close, params, alternative_group in callable_blocks:
                    synthetic = f"{alternative_group}_{body_at}" if alternative_group else \
                        f"__sniper_callback_{t.line}_{callback_at}_{body_at}"
                    super_cls = classes[-1][1]
                    rf.funcs.append(RubyFunc(
                        synthetic, rf, cls, False, params, [], (body_at, callback_close), t.line,
                        _rb_sources_ok(rel, cls, super_cls, rf.sinatra), "def", None, super_cls,
                    ))
                    excluded.append((callback_at, callback_close + 1))
                    if alternative_group:
                        alternative_groups.add(alternative_group)
                    else:
                        names.append(synthetic)
                names.extend(sorted(alternative_groups))
            for name in names:
                rf.callbacks.setdefault(cls, []).append(
                    (kind, name, frozenset(only), frozenset(exclude), condition, t.line)
                )
            i = block_close + 1 if block_close is not None else max(i + 1, k)
            continue
        if word == "scope" and classes and stmt_start(i) and i + 2 < n and toks[i + 1].kind == "sym":
            # scope :ad, ->(a, b) { gövde }  |  scope :ad, lambda { |a| gövde }
            name = toks[i + 1].value
            j = i + 2
            while j < n and toks[j].kind != "nl" and not (toks[j].kind == "op" and toks[j].value == "->") and \
                    not (toks[j].kind == "id" and toks[j].value in ("lambda", "proc")):
                j += 1
            if j < n and toks[j].kind != "nl":
                params: list = []
                kwparams: list = []
                variadic = None
                k = j + 1
                if k < n and toks[k].kind == "op" and toks[k].value == "(":
                    close = _match(toks, k)
                    params, kwparams, variadic = _rb_params(toks, k + 1, close)
                    k = close + 1
                if k < n and toks[k].kind == "op" and toks[k].value == "{":
                    close = _match(toks, k)
                    body_a = k + 1
                    if body_a < close and toks[body_a].kind == "op" and toks[body_a].value == "|":
                        m = body_a + 1
                        while m < close and not (toks[m].kind == "op" and toks[m].value == "|"):
                            m += 1
                        params, kwparams, variadic = _rb_params(toks, body_a + 1, m)
                        body_a = m + 1
                    cls, super_cls = classes[-1]
                    rf.funcs.append(RubyFunc(name, rf, cls, True, params, kwparams, (body_a, close), toks[i].line,
                                             False, "scope", variadic, super_cls))
                    excluded.append((k, close + 1))
                    i = close + 1
                    continue
        i += 1
    for func in rf.funcs:
        group_id = func.definition_branch_group
        if group_id is None or group_id not in branch_groups:
            continue
        group = branch_groups[group_id]
        func.definition_group_parent_certainty = group["parent"]
        func.definition_group_exhaustive = group["remaining"] == "never"
        func.definition_group_arms = tuple(
            arm for arm, certainty in sorted(group["arms"].items()) if certainty != "never"
        )
    # Ana gövde (Sinatra rotaları; denetleyici sınıf gövdesindeki bloklu geri çağrılar, ör.
    # before_filter do ... end): iç def gövdeleri hariç.
    if rf.sinatra or _rb_sources_ok(rel, "", "", False) and rel.endswith("_controller.rb"):
        rf.funcs.append(RubyFunc("<main>", rf, "", False, [], [], (0, n), 1, True, "main", excluded=tuple(excluded)))
    return rf


class RubyAnalyzer(_FuncBase):
    language = "ruby"

    def __init__(self, proj: "RubyProject", func: RubyFunc, ivar_env: dict | None = None,
                 sinatra_view: bool = False) -> None:
        super().__init__(proj, func)
        self.locals: set[str] = set()
        self.depth = 0
        self.clean_ivars: set[str] = set()
        self.guards: list[tuple[int, dict]] = []
        self.exit_guards: list[list] = []  # [açılış derinliği, adlar, çıkış görüldü mü]
        self.hash_vars: set[str] = set()
        self.lambdas: dict[str, list] = {}  # yerel ad → lambda/proc/yöntem nesnesi tanımları
        self.active_lambdas: set = set()  # özyineleme koruması
        # 19. tur Sinatra: rota bloğu durumu (yanıt türü JSON mu) ve görünümün Sinatra ERB'i olup olmadığı
        self.in_route = False
        self.route_json = False
        self.sinatra_view = sinatra_view
        if ivar_env:
            self.env.update(ivar_env)
        if func.kind == "def" and func.sources_ok and not func.class_method:
            for name, taint in proj.callback_ivars(func).items():
                if taint:
                    self.env[name] = taint
                else:
                    self.env.pop(name, None)

    # -- giriş -----------------------------------------------------------------
    _STORED_SINKS = frozenset({".html_safe", "raw()", "<%== %> (kaçışsız ERB çıktısı)", "render text: (HTML yanıtı)"})

    # 25. tur (ortak kalıcı depo modeli): istek verisiyle yazıldığı kanıtlanan öznitelik ikinci derece hedeflerde de
    # kaynaktır (kayıtlı ad → ham SQL, komut, yol…). HTML'de yalnız kaçışsız çıktı (ERB varsayılan olarak kaçışlar).
    _STORED_SECOND_ORDER = frozenset({"sql", "command", "eval", "deserialize", "ssti", "path", "nosql"})

    def _stored_reaches(self, kind: str, sink: str, origin: Origin) -> bool:
        # 17. tur: kayıtlı veri (ActiveRecord) kaçışsız HTML çıktısında kaynaktır (kayıtlı XSS); öznitelik
        # erişimiyle çözülmemiş ilişki/sorgu nesnesi (Model#öz) hiçbir hedefe ulaşmaz.
        head = origin.source.split(" ", 1)[0]
        if "#" in head:
            return False
        if kind != "html" and re.search(r"\.(?:username|login|slug|email|uuid|handle|\w*_token|\w*_digest)$", head):
            # 25. tur: kimlik niteliğindeki sütunlar (kullanıcı adı, slug, e-posta) modelde biçim doğrulamasından
            # geçer; ikinci derece hedeflerde (yol/SQL/komut) kaynak sayılmaz (HTML'de sayılmaya devam eder).
            return False
        return (kind == "html" and sink in self._STORED_SINKS) or kind in self._STORED_SECOND_ORDER

    def emit(self, kind: str, sink: str, line: int, origin: Origin, via: tuple[str, ...] = (), file: str | None = None) -> None:
        if origin.label == "stored" and not self._stored_reaches(kind, sink, origin):
            return
        super().emit(kind, sink, line, origin, via, file)

    def _hanami_action(self) -> bool:
        func = self.func
        return func.kind == "def" and func.name in ("handle", "call") and bool(
            re.search(r"(?:^|::)Action$|Hanami::Action", func.super_cls or "")) or (
            func.kind == "def" and func.name == "call" and bool(func.cls) and
            re.search(r"(?:^|/)(?:app|apps/\w+)/actions/", func.file.rel) is not None)

    def run(self) -> Summary:
        func = self.func
        hanami = self._hanami_action()
        if func.cls in self.proj.serializer_classes and not func.class_method:
            # ActiveModel::Serializer exposes its wrapped record as `object`.
            # The constructor receiver is mapped to symbolic parameter zero.
            self.env["object"] = frozenset({Origin(PARAM, "0", 0, "", ())})
        for index, name in enumerate(func.params):
            if hanami and name in ("request", "req", "params", "response", "res"):
                continue  # 19. tur Hanami: request.params / params istek nesnesidir (çatı bağlar), parametre değil
            self.env[name] = frozenset({Origin(PARAM, str(index), 0, "", ())})
            self.locals.add(name)
        for offset, name in enumerate(func.kwparams):
            self.env[name] = frozenset({Origin(PARAM, str(len(func.params) + offset), 0, "", ())})
            self.locals.add(name)
        try:
            if func.kind == "view":
                for kind, toks, line in func.file.view_segments:
                    self.view_segment(kind, toks)
            elif func.kind == "scope":
                self.add_return(self.eval(self.toks, *func.body))
            else:
                self.body(self.toks, func.body[0], func.body[1], func.excluded)
        except RecursionError:
            pass
        if func.kind in {"def", "callback_prefix"} and func.sources_ok:
            ivars = {k: frozenset(o for o in v if o.label != PARAM) for k, v in self.env.items() if k.startswith("@")}
            for name in self.clean_ivars:
                ivars.setdefault(name, EMPTY)
            self.summary.ivars = {k: v for k, v in ivars.items() if v or k in self.clean_ivars}
        return self.summary

    def view_segment(self, kind: str, toks: list[Tok]) -> None:
        if not toks:
            return
        if kind in ("=", "=="):
            # bloklu çıktı: <%= form_for x do |f| %>
            end = len(toks)
            for j, t in enumerate(toks):
                if t.kind == "id" and t.value == "do":
                    end = j
                    break
            taint = self.eval(toks, 0, end)
            if kind == "==":
                self.sink("html", "<%== %> (kaçışsız ERB çıktısı)", taint, toks[0].line)
            elif self.sinatra_view and not self.proj.sinatra_escape_html:
                # Sinatra'nın ERB'i (Rails'ten farklı olarak) <%= %> çıktısını varsayılan olarak kaçışlamaz
                self.sink("html", "<%= %> (Sinatra ERB varsayılan olarak kaçışsız)", taint, toks[0].line)
            return
        self.body(toks, 0, len(toks), ())

    # -- deyimler -----------------------------------------------------------
    def statements(self, toks: list[Tok], a: int, b: int, excluded: tuple) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        depth = 0
        start = a
        closing_pipes: set[int] = set()
        j = a
        ex = sorted(excluded)
        while j < b:
            skip = next((y for x, y in ex if x <= j < y), None)
            if skip is not None:
                if start < j:
                    out.append((start, j))
                j = skip
                start = j
                continue
            t = toks[j]
            if t.kind == "op":
                if t.value in ("(", "[", "{"):
                    depth += 1
                    if t.value == "{" and j + 1 < b and toks[j + 1].kind == "op" and toks[j + 1].value == "|":
                        m = j + 2
                        while m < b and not (toks[m].kind == "op" and toks[m].value == "|"):
                            m += 1
                        closing_pipes.add(m)
                elif t.value in (")", "]", "}"):
                    depth = max(0, depth - 1)
                elif t.value == ";" and depth == 0:
                    out.append((start, j))
                    start = j + 1
            elif t.kind == "id" and t.value == "do" and j + 1 < b and toks[j + 1].kind == "op" and toks[j + 1].value == "|":
                m = j + 2
                while m < b and not (toks[m].kind == "op" and toks[m].value == "|"):
                    m += 1
                closing_pipes.add(m)
            elif t.kind == "nl" and depth == 0:
                k = j - 1
                while k >= start and toks[k].kind == "nl":
                    k -= 1
                prev = toks[k] if k >= start else None
                nxt = j + 1
                while nxt < b and toks[nxt].kind == "nl":
                    nxt += 1
                cont = False
                if prev is not None and prev.kind == "op" and prev.value not in (")", "]", "}") and k not in closing_pipes:
                    cont = True
                if prev is not None and prev.kind == "id" and prev.value in ("and", "or", "not"):
                    cont = True
                if nxt < b and toks[nxt].kind == "op" and toks[nxt].value in (".", "&."):
                    cont = True
                if not cont:
                    if start < j:
                        out.append((start, j))
                    start = j + 1
            j += 1
        if start < b:
            out.append((start, b))
        return [(x, y) for x, y in out if any(toks[m].kind != "nl" for m in range(x, y))]

    def body(self, toks: list[Tok], a: int, b: int, excluded: tuple) -> None:
        stmts = self.statements(toks, a, b, excluded)
        for index, (x, y) in enumerate(stmts):
            while x < y and toks[x].kind == "nl":
                x += 1
            if x >= y:
                continue
            nxt = stmts[index + 1] if index + 1 < len(stmts) else None
            tail = nxt is None or (toks[nxt[0]].kind == "id" and toks[nxt[0]].value in ("end", "else", "elsif", "when", "in", "rescue", "ensure"))
            self.statement(toks, x, y, tail)

    def _depth_delta(self, toks: list[Tok], a: int, b: int) -> int:
        delta = 0
        for j in range(a, b):
            t = toks[j]
            if t.kind != "id":
                continue
            if j > a and toks[j - 1].kind == "op" and toks[j - 1].value in (".", "&.", "::"):
                continue
            if t.value == "do" or (t.value in _RB_OPENERS and (j == a or (toks[j - 1].kind == "op" and toks[j - 1].value in ("=", "(", "||=")))):
                delta += 1
            elif t.value == "end":
                delta -= 1
        return delta

    def statement(self, toks: list[Tok], a: int, b: int, tail: bool) -> None:
        first = toks[a]
        delta = self._depth_delta(toks, a, b)
        # if/elsif bloğu izin listesi koruması: blok sonunda (else/elsif/end) eski iz geri yüklenir
        if first.kind == "id" and first.value in ("else", "elsif", "end") and self.exit_guards and self.exit_guards[-1][0] == self.depth - 1:
            # unless LISTE.include?(x) ... return ... end → sonrası x izin listesinde
            _, names, saw_exit = self.exit_guards.pop()
            if saw_exit and first.value == "end" and self.depth - 1 == 0:
                for n in names:
                    self.env.pop(n, None)
        if first.kind == "id" and first.value in ("return", "raise", "fail") and self.exit_guards \
                and self.exit_guards[-1][0] == self.depth - 1:
            self.exit_guards[-1][2] = True
        if first.kind == "id" and first.value in ("else", "elsif", "end") and self.guards and self.guards[-1][0] == self.depth - 1:
            _, saved = self.guards.pop()
            for name, value in saved.items():
                if value is None:
                    self.env.pop(name, None)
                else:
                    self.env[name] = value
        if self.func.file.sinatra and self.func.kind != "view":
            if self.depth == 0 and first.kind == "id" and first.value in _RB_SINATRA_VERBS and delta >= 1:
                # yeni rota = yeni istek: önceki rotaların @değişkenleri bu rotaya/görünüme taşınmaz
                for name in [k for k in self.env if k.startswith("@")]:
                    self.env.pop(name, None)
                self.in_route, self.route_json = True, False
            elif self.in_route and self.depth == 1 and tail and first.kind == "str" and "<" in str(first.value) \
                    and not self.route_json:
                # rota bloğunun son ifadesi yanıt gövdesidir (varsayılan içerik türü text/html)
                self.sink("html", "Sinatra rota yanıtı (HTML dizesi)", self.eval(toks, a, b), first.line)
        try:
            self._statement(toks, a, b, tail)
        finally:
            if first.kind == "id" and first.value in ("if", "elsif") and delta >= 0:
                guarded = self._guarded_names(toks, a + 1, b)
                negated = any((t.kind == "op" and t.value == "!") or (t.kind == "id" and t.value == "not") for t in toks[a + 1:b])
                if guarded and first.value == "if" and not negated:
                    self.guards.append((self.depth, {n: self.env.get(n) for n in guarded}))
                    for n in guarded:
                        self.env.pop(n, None)
                elif guarded and first.value == "if" and negated:
                    self.exit_guards.append([self.depth, guarded, False])
            if first.kind == "id" and first.value == "unless" and delta >= 1:
                guarded = self._guarded_names(toks, a + 1, b)
                if guarded:
                    self.exit_guards.append([self.depth, guarded, False])
            self.depth = max(0, self.depth + delta)

    def _statement(self, toks: list[Tok], a: int, b: int, tail: bool) -> None:
        first = toks[a]
        if first.kind == "id":
            word = first.value
            if word in ("else", "ensure", "begin", "end", "then"):
                if a + 1 < b and word == "end" and toks[a + 1].kind == "op" and toks[a + 1].value in (".", "&."):
                    self.eval(toks, a + 1, b)
                return
            if word == "for":
                self._statement_core(toks, a, b, tail)  # 19. tur: döngü değişkeni bağlanır
                return
            if word in ("if", "unless", "while", "until", "elsif", "when", "case", "in"):
                self.eval(toks, a + 1, b)
                return
            if word == "rescue":
                return
            if word in ("next", "break", "redo", "retry", "alias", "undef", "require", "require_relative", "include",
                        "extend", "attr_accessor", "attr_reader", "attr_writer", "private", "protected", "public"):
                return
        main_b = self._modifier(toks, a, b)
        if main_b < b:
            mod = toks[main_b].value
            guarded = self._guarded_names(toks, main_b + 1, b)
            negated = any(t.kind == "op" and t.value == "!" or (t.kind == "id" and t.value == "not") for t in toks[main_b + 1:b])
            exits = first.kind == "id" and first.value in ("return", "raise", "fail", "redirect_to", "head", "render", "next", "break") \
                or any(t.kind == "id" and t.value in ("return", "raise", "fail") for t in toks[a:main_b])
            if guarded and exits and ((mod == "unless" and not negated) or (mod == "if" and negated)):
                # return ... unless LISTE.include?(x): sonraki deyimlerde x izin listesinde
                self._statement_core(toks, a, main_b, tail)
                if self.depth == 0:
                    for n in guarded:
                        self.env.pop(n, None)
                return
            if guarded and mod == "if" and not negated:
                saved = {n: self.env.get(n) for n in guarded}
                for n in guarded:
                    self.env.pop(n, None)
                try:
                    self._statement_core(toks, a, main_b, tail)
                finally:
                    for n, value in saved.items():
                        if value is not None:
                            self.env[n] = value
                return
        self._statement_core(toks, a, main_b, tail)

    def _statement_core(self, toks: list[Tok], a: int, main_b: int, tail: bool) -> None:
        first = toks[a]
        if first.kind == "id" and first.value == "for":
            # 19. tur: for x in koleksiyon … end — döngü değişkeni koleksiyonun izini taşır
            k = next((j for j in range(a + 1, main_b) if toks[j].kind == "id" and toks[j].value == "in"), None)
            if k is not None:
                end = next((j for j in range(k + 1, main_b) if toks[j].kind == "id" and toks[j].value == "do"), main_b)
                value = self.eval(toks, k + 1, end)
                for t in toks[a + 1:k]:
                    if t.kind == "id":
                        self.locals.add(t.value)
                        self.env[t.value] = value
                return
        if first.kind == "id" and first.value in ("return", "raise", "fail"):
            if first.value == "return" and a + 1 < main_b:
                self.add_return(self.eval(toks, a + 1, main_b))
            else:
                self.eval(toks, a + 1, main_b)
            return
        # blok: ... do |a, b|
        do_at = None
        depth = 0
        for j in range(a, main_b):
            t = toks[j]
            if t.kind == "op" and t.value in ("(", "[", "{"):
                depth += 1
            elif t.kind == "op" and t.value in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and t.kind == "id" and t.value == "do":
                do_at = j
                break
        expr_b = do_at if do_at is not None else main_b
        value = self.assignment_or_eval(toks, a, expr_b, tail)
        if do_at is not None:
            names = self._block_params(toks, do_at + 1, main_b)
            route = toks[a].kind == "id" and toks[a].value in _RB_SINATRA_VERBS and self.func.sources_ok
            for name in names:
                taint = self.source(f"{toks[a].value} rota parametresi", toks[a].line) if route else value
                self.locals.add(name)
                if taint:
                    self.env[name] = self.env.get(name, EMPTY) | taint

    @staticmethod
    def _guarded_names(toks: list[Tok], a: int, b: int) -> set[str]:
        """Koşuldaki izin listesi denetimlerinin sınırladığı değişkenler."""
        names: set[str] = set()
        for j in range(a, b):
            t = toks[j]
            if t.kind != "id" or t.value not in _RB_GUARD_PREDICATES:
                continue
            if t.value == "in?" and j >= 2 and toks[j - 1].value in (".", "&.") and toks[j - 2].kind in ("id", "ivar"):
                names.add(toks[j - 2].value)
                continue
            k = j + 1
            if k < b and toks[k].kind == "op" and toks[k].value == "(":
                k += 1
            if k < b and toks[k].kind in ("id", "ivar"):
                after = toks[k + 1] if k + 1 < b else None
                if after is None or after.kind == "nl" or (after.kind == "op" and after.value in (")", ",")) or after.kind == "id":
                    names.add(toks[k].value)
        return names

    def _modifier(self, toks: list[Tok], a: int, b: int) -> int:
        depth = 0
        for j in range(a + 1, b):
            t = toks[j]
            if t.kind == "op" and t.value in ("(", "[", "{"):
                depth += 1
            elif t.kind == "op" and t.value in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and t.kind == "id" and t.value in _RB_MODIFIERS and not (
                    toks[j - 1].kind == "op" and toks[j - 1].value in (".", "&.", "=", "(", "||=")):
                self.eval(toks, j + 1, b)
                return j
        return b

    def _block_params(self, toks: list[Tok], a: int, b: int) -> list[str]:
        if a < b and toks[a].kind == "op" and toks[a].value == "|":
            m = a + 1
            while m < b and not (toks[m].kind == "op" and toks[m].value == "|"):
                m += 1
            return [t.value for t in toks[a + 1:m] if t.kind == "id"]
        return []

    def assignment_or_eval(self, toks: list[Tok], a: int, b: int, tail: bool) -> frozenset:
        depth = 0
        op_at = None
        for j in range(a, b):
            t = toks[j]
            if t.kind != "op":
                continue
            if t.value in ("(", "[", "{"):
                depth += 1
            elif t.value in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and t.value in ("=", "||=", "&&=", "+=", "-=", "<<=", "*=", "|=", "<<"):
                op_at = j
                break
        if op_at is None or op_at == a:
            value = self.eval(toks, a, b)
            if tail:
                self.add_return(value)
            return value
        op = toks[op_at].value
        lhs = _split_top(toks, a, op_at)
        if op == "<<":
            items = [t for t in toks[a:op_at] if t.kind != "nl"]
            if not (len(items) == 1 and items[0].kind in ("id", "ivar")):
                value = self.eval(toks, a, b)
                if tail:
                    self.add_return(value)
                return value
        rhs_taint = self.eval(toks, op_at + 1, b)
        for x, y in lhs:
            items = [t for t in toks[x:y] if t.kind != "nl"]
            if not items:
                continue
            head = items[0]
            if head.kind == "op" and head.value == "*" and len(items) > 1:
                head = items[1]
                items = items[1:]
            if head.kind not in ("id", "ivar", "gvar", "const"):
                continue
            if head.kind == "id" and head.value == "self" and len(items) >= 3:
                head = items[2]
            name = head.value
            simple = len(items) == 1
            if not simple:
                # x[...] = / x.attr = : indeks ifadesindeki hedefler
                for m in range(x, y):
                    if toks[m].kind == "op" and toks[m].value == "[":
                        self.eval(toks, m + 1, _match(toks, m, y + 1))
                        break
            strong = simple and op == "=" and self.depth == 0
            if head.kind == "id" and not simple and name in _RB_KV_STORES and name not in self.env \
                    and name not in self.locals:
                # 25. tur: oturum/flash anahtar-değer deposuna yazım (flash[:error] = "… #{params[:u]}")
                self._note_stored(f"§{name}", [], {_rb_kv_key(toks, x, y): rhs_taint})
                continue
            if head.kind == "id" and simple:
                self.locals.add(name)
            elif head.kind == "id" and name not in self.env and name not in self.locals:
                continue  # params[:x] = ... / obj.attr = ... : yerel değişken değil
            if simple and op == "=":
                if self._returns_hash_expression(toks, op_at + 1, b):
                    self.hash_vars.add(name)
                elif strong:
                    self.hash_vars.discard(name)
                if head.kind == "id" and len(lhs) == 1:
                    lams = _rb_lambdas_in(toks, op_at + 1, b)
                    if lams:
                        self.lambdas[name] = lams if strong else self.lambdas.get(name, []) + lams
                    elif strong:
                        self.lambdas.pop(name, None)
            if head.kind == "ivar" and strong and not rhs_taint:
                self.clean_ivars.add(name)
            elif head.kind == "ivar":
                self.clean_ivars.discard(name)
            taint = rhs_taint
            if op not in ("=",):
                taint = taint | self.env.get(name, EMPTY)
            if strong:
                if taint:
                    self.env[name] = taint
                else:
                    self.env.pop(name, None)
            elif taint:
                self.env[name] = self.env.get(name, EMPTY) | taint
        if tail:
            self.add_return(rhs_taint)
        return rhs_taint

    # -- ifadeler -------------------------------------------------------------
    def source(self, text: str, line: int) -> frozenset:
        return frozenset({Origin("request", text[:60], line, self.file.rel, ())})

    def eval(self, toks: list[Tok], a: int, b: int) -> frozenset:
        result: set[Origin] = set()
        boolean = False
        i = a
        guard = 0
        while i < b:
            guard += 1
            if guard > 50_000:
                break
            t = toks[i]
            kind = t.kind
            if kind in ("str", "xstr", "regex", "sym"):
                taint = EMPTY
                if t.interp:
                    parts = [self.eval(list(part), 0, len(part)) for part in t.interp]
                    taint = frozenset().union(*parts) if parts else EMPTY
                if kind == "xstr":
                    self.sink("command", "`...` / %x (kabuk komutu)", taint, t.line)
                if kind != "regex":
                    # dize üzerinde yöntem zinciri: "...".html_safe
                    j, chained = self.chain_from(toks, i + 1, b, taint, ("value", t.value), t.line)
                    result |= chained
                    i = max(j, i + 1)
                    continue
                i += 1
                continue
            if kind == "id" and t.value in ("if", "unless", "case", "when", "while", "until", "elsif"):
                self.eval(toks, i + 1, b)  # koşul: hedefler denetlenir, izi değere geçmez
                break
            if kind in ("id", "const", "ivar", "gvar"):
                if kind == "id" and t.value in _RB_KEYWORDS and t.value not in ("self", "nil", "true", "false", "defined?", "super", "yield"):
                    i += 1
                    continue
                j, taint = self.chain(toks, i, b)
                result |= taint
                i = max(j, i + 1)
                continue
            if kind == "op":
                if t.value == "?":  # üçlü işleç: koşulun izi değere geçmez
                    result = set()
                    boolean = False
                    i += 1
                    continue
                if t.value in ("==", "!=", "===", "=~", "!~", "<", ">", "<=", ">=", "<=>"):
                    boolean = True
                if t.value in ("(", "["):
                    k = _match(toks, i, b)
                    inner = self.eval(toks, i + 1, k)
                    j, chained = self.chain_from(toks, k + 1, b, inner, ("value", ""), t.line)
                    result |= chained
                    i = max(j, k + 1)
                    continue
                if t.value == "{":
                    k = _match(toks, i, b)
                    inner_a = i + 1
                    if inner_a < k and toks[inner_a].kind == "op" and toks[inner_a].value == "|":
                        m = inner_a + 1
                        while m < k and not (toks[m].kind == "op" and toks[m].value == "|"):
                            m += 1
                        inner_a = m + 1
                    result |= self.eval(toks, inner_a, k)
                    i = k + 1
                    continue
                if t.value in ("||", "&&", "or", "and"):
                    if boolean:  # (a == b) || c
                        result = set()
                        boolean = False
                if t.value == "->":
                    j = i + 1
                    if j < b and toks[j].value == "(":
                        j = _match(toks, j, b) + 1
                    if j < b and toks[j].value == "{":
                        k = _match(toks, j, b)
                        self.eval(toks, j + 1, k)
                        i = k + 1
                        continue
            i += 1
        return EMPTY if boolean else frozenset(result)

    def _args(self, toks: list[Tok], a: int, b: int) -> tuple[list, dict]:
        positional: list[tuple[int, int]] = []
        keywords: dict[str, tuple[int, int]] = {}
        for x, y in _split_top(toks, a, b):
            while x < y and toks[x].kind == "nl":
                x += 1
            if x >= y:
                continue
            if toks[x].kind == "label":
                keywords[toks[x].value] = (x + 1, y)
                continue
            arrow = next((m for m in range(x, y) if toks[m].kind == "op" and toks[m].value == "=>"), None)
            if arrow is not None and toks[x].kind in ("sym", "str") and arrow == x + 1:
                keywords[toks[x].value] = (arrow + 1, y)
                continue
            if toks[x].kind == "op" and toks[x].value == "&":
                continue
            positional.append((x, y))
        return positional, keywords

    def _parenless_end(self, toks: list[Tok], a: int, b: int) -> int:
        depth = 0
        for j in range(a, b):
            t = toks[j]
            if t.kind == "op":
                if t.value in ("(", "[", "{"):
                    if depth == 0 and t.value == "{" and j > a and toks[j - 1].kind in ("id", "const") and False:
                        return j
                    depth += 1
                elif t.value in (")", "]", "}"):
                    if depth == 0:
                        return j
                    depth -= 1
            elif t.kind == "nl" and depth == 0:
                return j
            elif depth == 0 and t.kind == "id" and t.value in ("if", "unless", "while", "until", "rescue", "do", "and", "or", "then"):
                return j
        return b

    def _arg_start(self, toks: list[Tok], j: int, b: int) -> bool:
        if j >= b:
            return False
        t = toks[j]
        if not t.sp or t.kind == "nl":
            return False
        if t.kind in ("str", "xstr", "sym", "num", "const", "ivar", "gvar", "label", "regex"):
            return True
        if t.kind == "id":
            return t.value not in _RB_KEYWORDS or t.value in ("self", "nil", "true", "false", "not", "defined?", "super")
        if t.kind == "op" and t.value in ("[", "->", "::", "!", "("):
            return True  # 18. tur: "send_file ('./' + x)" — boşluklu parantez ilk argümanın kendisidir
        if t.kind == "op" and t.value in ("*", "&", "-", ":", "**") and j + 1 < b and not toks[j + 1].sp:
            return True
        return False

    def chain(self, toks: list[Tok], i: int, b: int) -> tuple[int, frozenset]:
        t = toks[i]
        line = t.line
        j = i + 1
        if t.kind == "ivar":
            return self.chain_from(toks, j, b, self.env.get(t.value, EMPTY), ("var", t.value), line)
        if t.kind == "gvar":
            return self.chain_from(toks, j, b, EMPTY, ("value", t.value), line)
        if t.kind == "const":
            parts = [t.value]
            while j + 1 < b and toks[j].kind == "op" and toks[j].value == "::" and toks[j + 1].kind == "const":
                parts.append(toks[j + 1].value)
                j += 2
            name = "::".join(parts)
            if j < b and toks[j].kind == "op" and toks[j].value == "(" and not toks[j].sp:  # Kernel#Integer(x) / URI(x)
                k = _match(toks, j, b)
                positional, keywords = self._args(toks, j + 1, k)
                taint = self.call(toks, None, None, name, positional, keywords, line, bare=True)
                return self.chain_from(toks, k + 1, b, taint, ("value", name), line)
            return self.chain_from(toks, j, b, EMPTY, ("const", name), line)
        name = t.value
        if name in ("self",):
            return self.chain_from(toks, j, b, EMPTY, ("self", "self"), line)
        if name in ("nil", "true", "false"):
            return j, EMPTY
        if name in ("defined?",):
            if j < b and toks[j].value == "(":
                return _match(toks, j, b) + 1, EMPTY
            return j, EMPTY
        if name in self.env or name in self.locals:
            return self.chain_from(toks, j, b, self.env.get(name, EMPTY), ("var", name), line)
        if self.func.sources_ok and name in ("params", "cookies") and not (j < b and toks[j].kind == "op" and toks[j].value == "(" and not toks[j].sp):
            return self.chain_from(toks, j, b, self.source(name, line), ("source", name), line)
        if self.func.sources_ok and name == "request":
            return self.chain_from(toks, j, b, EMPTY, ("request", name), line)
        if name in _RB_KV_STORES and self.proj.stored.get(f"§{name}") \
                and not (j < b and toks[j].kind == "op" and toks[j].value == "(" and not toks[j].sp):
            # 25. tur: oturum/flash deposundan okuma: istek verisi yazılan anahtar(lar) kayıtlı veri kaynağıdır
            key = _rb_kv_key(toks, i, b) if j < b and toks[j].kind == "op" and toks[j].value == "[" else None
            taint = frozenset(Origin("stored", f"{name}[{k}] (kayıtlı veri)", o.line, o.file, (), o.cleaned)
                              for k, origins in self.proj.stored[f"§{name}"].items()
                              if key is None or k in (key, "*") or key == "*"
                              for o in _osorted(origins)[:1])
            return self.chain_from(toks, j, b, taint, ("var", name), line)
        # çıplak yöntem çağrısı
        if j < b and toks[j].kind == "op" and toks[j].value == "(" and not toks[j].sp:
            k = _match(toks, j, b)
            positional, keywords = self._args(toks, j + 1, k)
            taint = self.call(toks, None, None, name, positional, keywords, line, bare=True)
            return self.chain_from(toks, k + 1, b, taint, ("value", name), line)
        if self._arg_start(toks, j, b):
            end = self._parenless_end(toks, j, b)
            positional, keywords = self._args(toks, j, end)
            taint = self.call(toks, None, None, name, positional, keywords, line, bare=True)
            return end, taint
        taint = self.call(toks, None, None, name, [], {}, line, bare=True)
        return self.chain_from(toks, j, b, taint, ("value", name), line)

    def chain_from(self, toks: list[Tok], j: int, b: int, taint: frozenset, base: tuple, line: int) -> tuple[int, frozenset]:
        recv = base
        while j < b:
            t = toks[j]
            if t.kind == "op" and t.value in (".", "&.") and j + 1 < b and toks[j + 1].kind in ("id", "const", "label"):
                mt = toks[j + 1]
                method = mt.value
                mline = mt.line
                j += 2
                if mt.kind == "label":  # x.y: (sonraki etiket) — ayrıştırma artığı
                    break
                if j < b and toks[j].kind == "op" and toks[j].value == "(" and not toks[j].sp:
                    k = _match(toks, j, b)
                    positional, keywords = self._args(toks, j + 1, k)
                    taint = self.call(toks, taint, recv, method, positional, keywords, mline)
                    j = k + 1
                elif j < b and toks[j].kind == "op" and toks[j].value == "=" and toks[j].sp and False:
                    break
                elif self._arg_start(toks, j, b):
                    end = self._parenless_end(toks, j, b)
                    positional, keywords = self._args(toks, j, end)
                    taint = self.call(toks, taint, recv, method, positional, keywords, mline)
                    j = end
                else:
                    taint = self.call(toks, taint, recv, method, [], {}, mline)
                recv = ("value", method)
                continue
            if t.kind == "op" and t.value == "::" and j + 1 < b and toks[j + 1].kind in ("id", "const"):
                j += 2
                continue
            if t.kind == "op" and t.value == "[" and not t.sp:
                k = _match(toks, j, b)
                index_taint = self.eval(toks, j + 1, k)
                if recv[0] == "const" and recv[1] in ("ENV",):
                    taint = EMPTY
                elif recv[0] == "source" and recv[1] == "cookies":
                    taint = taint
                del index_taint
                j = k + 1
                recv = ("value", recv[1])
                continue
            if t.kind == "op" and t.value == "{" and recv[0] == "value":
                # blok: x.each { |a| ... } — blok parametreleri alıcı izini alır
                k = _match(toks, j, b)
                inner_a = j + 1
                if inner_a < k and toks[inner_a].kind == "op" and toks[inner_a].value == "|":
                    m = inner_a + 1
                    while m < k and not (toks[m].kind == "op" and toks[m].value == "|"):
                        m += 1
                    for p in toks[inner_a + 1:m]:
                        if p.kind == "id":
                            self.locals.add(p.value)
                            if taint:
                                self.env[p.value] = self.env.get(p.value, EMPTY) | taint
                    inner_a = m + 1
                self.eval(toks, inner_a, k)
                j = k + 1
                continue
            break
        return j, taint

    # -- çağrılar -------------------------------------------------------------
    def _lead(self, toks: list[Tok], span: tuple[int, int]) -> str | None:
        x, y = span
        while x < y and toks[x].kind == "nl":
            x += 1
        if x < y and toks[x].kind == "str":
            body = toks[x].value
            k = body.find("#{")
            return body if k < 0 else body[:k]
        return None

    def _sqlish(self, toks: list[Tok], span: tuple[int, int]) -> bool:
        x, y = span
        while x < y and toks[x].kind == "nl":
            x += 1
        if x >= y:
            return False
        head = toks[x]
        if head.kind in ("sym", "label", "num"):
            return False
        if head.kind == "op" and head.value in ("[", "{", ":"):
            return False
        # params.permit(...) / params.require(:x).permit(...) karma döndürür:
        # where/find_by(karma) güvenli. Rails 8 ``expect`` ise sembol
        # verildiğinde skaler, etiketli/hash argüman verildiğinde karma döner.
        if self._returns_hash_expression(toks, x, y):
            return False
        items = [t for t in toks[x:y] if t.kind != "nl"]
        if len(items) == 1 and items[0].kind in ("id", "ivar") and items[0].value in self.hash_vars:
            return False
        return True

    @staticmethod
    def _ends_with_call(toks: list[Tok], x: int, y: int, names: tuple) -> bool:
        k = y - 1
        while k >= x and toks[k].kind == "nl":
            k -= 1
        if k >= x and toks[k].kind == "op" and toks[k].value == ")":
            depth = 0
            while k >= x:
                if toks[k].kind == "op" and toks[k].value == ")":
                    depth += 1
                elif toks[k].kind == "op" and toks[k].value == "(":
                    depth -= 1
                    if depth == 0:
                        k -= 1
                        break
                k -= 1
        return k >= x + 1 and toks[k].kind == "id" and toks[k].value in names and toks[k - 1].kind == "op" \
            and toks[k - 1].value in (".", "&.")

    @staticmethod
    def _expect_returns_hash(toks: list[Tok], x: int, y: int) -> bool:
        """Whether a final Rails 8 ``params.expect``/``expect!`` call has hash-shaped input."""
        close = y - 1
        while close >= x and toks[close].kind == "nl":
            close -= 1
        if close >= x and toks[close].kind == "op" and toks[close].value == ")":
            depth = 0
            open_at = close
            while open_at >= x:
                token = toks[open_at]
                if token.kind == "op" and token.value == ")":
                    depth += 1
                elif token.kind == "op" and token.value == "(":
                    depth -= 1
                    if depth == 0:
                        break
                open_at -= 1
            if open_at >= x + 3 and toks[open_at - 1].kind == "id" \
                    and toks[open_at - 1].value in ("expect", "expect!") \
                    and toks[open_at - 2].kind == "op" and toks[open_at - 2].value in (".", "&.") \
                    and toks[open_at - 3].kind == "id" and toks[open_at - 3].value == "params":
                first = open_at + 1
                while first < close and toks[first].kind == "nl":
                    first += 1
                return first < close and (
                    toks[first].kind == "label"
                    or (toks[first].kind == "op" and toks[first].value == "{")
                )
            return False

        # Ruby permits parentheses to be omitted: ``params.expect user: [:name]``.
        # Restrict the shape trust to the real Rails params receiver; arbitrary
        # application methods named ``expect`` do not implement strong parameters.
        for expect_at in range(x + 2, close + 1):
            if toks[expect_at].kind != "id" or toks[expect_at].value not in ("expect", "expect!") \
                    or toks[expect_at - 1].kind != "op" or toks[expect_at - 1].value not in (".", "&.") \
                    or toks[expect_at - 2].kind != "id" or toks[expect_at - 2].value != "params":
                continue
            first = expect_at + 1
            while first <= close and toks[first].kind == "nl":
                first += 1
            return first <= close and (
                toks[first].kind == "label"
                or (toks[first].kind == "op" and toks[first].value == "{")
            )
        return False

    def _returns_hash_expression(self, toks: list[Tok], x: int, y: int) -> bool:
        hash_methods = tuple(name for name in _RB_HASH_METHODS if name != "expect")
        return self._ends_with_call(toks, x, y, hash_methods) \
            or self._expect_returns_hash(toks, x, y)

    def _sql_value_taint(self, toks: list[Tok], x: int, y: int) -> frozenset:
        """SQL parçası değeri: dizi koşulunda (["a = ?", v]) yalnız ilk öğe, karmada yalnız anahtarlar."""
        while x < y and toks[x].kind == "nl":
            x += 1
        if x >= y:
            return EMPTY
        if toks[x].kind == "op" and toks[x].value == "[":
            close = _match(toks, x, y + 1)
            parts = _split_top(toks, x + 1, close)
            return self.eval(toks, *parts[0]) if parts else EMPTY
        if toks[x].kind == "op" and toks[x].value == "{" or toks[x].kind in ("sym", "label"):
            return EMPTY
        return self.eval(toks, x, y)

    @staticmethod
    def _top_arrow(toks: list[Tok], x: int, y: int) -> int | None:
        depth = 0
        for k in range(x, y):
            t = toks[k]
            if t.kind == "op" and t.value in ("(", "[", "{"):
                depth += 1
            elif t.kind == "op" and t.value in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and t.kind == "op" and t.value == "=>":
                return k
        return None

    def _hash_keys(self, toks: list[Tok], x: int, y: int) -> dict:
        """İfadedeki (iç içe ``merge(...)`` dahil) karma anahtarları → değer aralıkları."""
        keys: dict[str, tuple[int, int]] = {}
        k = x
        while k < y:
            t = toks[k]
            if t.kind == "op" and t.value in ("(", "{"):
                close = _match(toks, k, y + 1)
                for a, b in _split_top(toks, k + 1, close):
                    while a < b and toks[a].kind == "nl":
                        a += 1
                    if a < b and toks[a].kind == "label":
                        keys[toks[a].value] = (a + 1, b)
                    elif a + 1 < b and toks[a].kind in ("sym", "str") and toks[a + 1].kind == "op" and toks[a + 1].value == "=>":
                        keys[toks[a].value] = (a + 2, b)
                k = close + 1
                continue
            k += 1
        return keys

    def _check_at(self, kind: str, name: str, taints: list, index: int, line: int) -> None:
        if index < len(taints):
            self.sink(kind, name, taints[index], line)

    def call(self, toks: list[Tok], recv_taint: frozenset | None, recv: tuple | None, method: str,
             positional: list, keywords: dict, line: int, bare: bool = False) -> frozenset:
        taints = [self.eval(toks, x, y) for x, y in positional]
        kw_taints = {k: self.eval(toks, x, y) for k, (x, y) in keywords.items()}
        all_taint = frozenset().union(*taints, *kw_taints.values()) if (taints or kw_taints) else EMPTY
        recv_taint = recv_taint or EMPTY
        recv_kind, recv_name = recv if recv else (None, None)

        # 0) lambda/proc/yöntem nesnesi çağrısı: r.call(x), EYLEMLER[k].call(x)
        if method in ("call", "()", "yield") and recv_kind in ("var", "value", "const") and recv_name:
            lams = self.lambdas.get(recv_name) or self.proj.const_lambdas.get((self.file.rel, recv_name))
            if lams:
                self.invoke_lambdas(toks, lams, taints, kw_taints, line)

        # 0b) ActiveRecord kayıtlı veri (17. tur): Model.create(öz: istek) yazar; Model.find/where/… okur
        models = self.proj.models
        model_name = self.proj.model_constant(self.func, recv_name) if recv_kind == "const" else None
        if model_name is not None:
            if method in _RB_AR_WRITES:
                self._note_stored(model_name, taints, kw_taints)
                if method in ("new", "create", "create!", "build"):
                    # 18. tur: toplu atamayla kurulan kayıt (Rider.new(params[:rider])) aynı istekte öznitelikleri
                    # istek verisini yansıtır (raw @rider.name → yansıtılmış XSS).
                    # Kaydın kendisi redirect_to'ya verilirse Rails modelin iç adresini üretir (polimorfik rota):
                    # açık yönlendirme değildir (redirect_to @user) — nesne bu hedef için temiz işaretlenir.
                    return frozenset(Origin(o.label, o.source, o.line, o.file, o.via, o.cleaned | {"redirect"})
                                     for o in all_taint if o.label == "request")
            elif method in _RB_AR_READS and not getattr(self, "_in_ar_read", False):
                attrs = self.proj.stored.get(model_name)
                if attrs:
                    # "Model#öz" henüz öznitelik erişimiyle çözülmemiş kayıt; erişilince "Model.öz" olur. Okuma
                    # yönteminin kendi hedefleri (where("…#{params}…")) de denetlensin diye normal yol da çalışır.
                    self._in_ar_read = True
                    try:
                        base = self.call(toks, recv_taint, recv, method, positional, keywords, line, bare)
                    finally:
                        self._in_ar_read = False
                    return base | frozenset(Origin("stored", f"{model_name}#{a} (kayıtlı veri)", o.line, o.file, (),
                                                   o.cleaned - {"sql"})
                                            for a, origins in attrs.items() for o in _osorted(origins)[:1])
        serializer_name = self.proj.serializer_constant(self.func, recv_name) if recv_kind == "const" else None
        if method == "new" and serializer_name is not None:
            marker = f"§serializer:{serializer_name}"
            return frozenset(Origin(o.label, o.source, o.line, o.file, o.via, o.cleaned | {marker}) for o in all_taint)
        serializer_names = {
            item.removeprefix("§serializer:")
            for origin in recv_taint for item in origin.cleaned if item.startswith("§serializer:")
        }
        if serializer_names and not bare:
            callees = [
                callee for cls in sorted(serializer_names)
                for callee in self.proj.by_class.get((cls, False), {}).get(method, [])
            ]
            if callees:
                result = self.apply_summary(callees, [recv_taint], {}, line)
                return frozenset(
                    Origin(o.label, o.source.replace("#", ".", 1), o.line, o.file, o.via, o.cleaned)
                    if o.label == "stored" and f"#{method} " in o.source else o
                    for o in result
                )
        # 19. tur: ilişki gezinmesi (rider.comments / post.author): ilişki adının tekil CamelCase'i istek verisiyle
        # yazılan bir modelse, dönen kayıtlar o modelin kayıtlı verisidir (raw comment.body → kayıtlı XSS).
        if not bare and not positional and not keywords and recv_kind in ("var", "ivar", "value") \
                and re.fullmatch(r"[a-z_]\w*", method) and method not in self.proj.by_name \
                and not any(o.label == "stored" and "#" in o.source.split(" ", 1)[0] for o in recv_taint or ()):
            assoc = _rb_camel_singular(method)
            attrs = self.proj.stored.get(assoc) if assoc in models else None
            if attrs:
                return frozenset(Origin("stored", f"{assoc}#{a} (kayıtlı veri)", o.line, o.file, (), o.cleaned - {"sql"})
                                 for a, origins in attrs.items() for o in _osorted(origins)[:1])
        # 25. tur: ilişki üzerinden yazım (post.comments.create!(body: istek), current_user.reports.build(...)):
        # ilişki adının tekil CamelCase'i bir modelse o modele istek verisi yazılıyor demektir.
        if not bare and method in _RB_AR_WRITES and recv_kind == "value" and recv_name \
                and re.fullmatch(r"[a-z_]\w*", recv_name) and _rb_camel_singular(recv_name) in models:
            self._note_stored(_rb_camel_singular(recv_name), taints, kw_taints)
        pending = [o for o in _osorted(recv_taint or ()) if o.label == "stored" and "#" in o.source.split(" ", 1)[0]]
        if pending and not bare and method in _RB_AR_WRITES:
            self._note_stored(pending[0].source.split("#", 1)[0], taints, kw_taints)  # kayıt.update(öz: istek)
        if pending and not bare and not positional and not keywords and re.fullmatch(r"[a-z_]\w*", method) \
                and any(method in self.proj.assocs.get(o.source.split("#", 1)[0], ()) for o in pending):
            # 25. tur: kayıttan bildirilmiş ilişki gezinmesi (has_many :comments → rider.comments): dönen kayıtlar
            # ilişkili modelin kayıtlı verisidir; üst kaydın toplu yazımından ("*") türetilmez. İlişkili modele
            # istek verisi yazılmadıysa temizdir.
            assoc = self.proj.assocs_target.get(method) or _rb_camel_singular(method)
            keep = frozenset(o for o in recv_taint if o not in pending)
            return keep | frozenset(Origin("stored", f"{assoc}#{a} (kayıtlı veri)", o.line, o.file, (), o.cleaned - {"sql"})
                                    for a, origins in self.proj.stored.get(assoc, {}).items()
                                    for o in _osorted(origins)[:1])
        if pending and not bare and not positional and not keywords and re.fullmatch(r"[a-z_]\w*", method) \
                and not any(self.proj.by_class.get((o.source.split("#", 1)[0], False), {}).get(method)
                            for o in pending) \
                and method not in _RB_AR_READS and method not in _RB_ARG_PROP and method not in _RB_CLEAN_METHODS \
                and method not in ("html_safe", "to_s", "to_str", "inspect", "strip", "downcase", "upcase", "presence"):
            # kayıt.öznitelik: yalnız o özniteliğe (ya da toplu yazmaya "*") istek verisi yazıldıysa kaynak
            keep = frozenset(o for o in recv_taint if o not in pending)
            for o in pending:
                model, _, attr = o.source.split(" ", 1)[0].partition("#")
                if attr == method or (attr == "*" and not re.search(r"(?:^id|_id|_at|_on|_count|_type|_token|"
                                                                  r"_digest|^username|^email|^slug|^uuid)$", method)):
                    keep |= {Origin("stored", f"{model}.{method} (kayıtlı veri)", o.line, o.file, o.via, o.cleaned)}
            return keep
        # 1) kaynaklar
        if recv_kind == "request":
            if method in _RB_REQUEST_TAINTED:
                return self.source(f"request.{method}", line)
            return EMPTY
        if recv_kind == "source" and recv_name == "cookies" and method in ("signed", "encrypted", "permanent"):
            return EMPTY if method != "permanent" else recv_taint

        # 2) alıcıdaki iz üzerinde arındırma/kalıp
        if recv_taint and not bare:
            if method in _RB_CLEAN_METHODS or (method.endswith("?") and method not in ("send",)):
                return EMPTY
            if method == "html_safe":
                self.sink("html", ".html_safe", recv_taint, line)
                return _clean(recv_taint, frozenset({"html"}))
            if method in ("constantize", "safe_constantize"):
                self.sink("eval", f".{method} (güvensiz yansıma)", recv_taint, line)
                return recv_taint
            if method in ("shellescape",):
                return _clean(recv_taint, frozenset({"command"}))
            if method in ("to_json",):  # Rails JSON'da <, >, & kaçışlanır
                return _clean(recv_taint, frozenset({"html"}))

        # 2b) Statik yansıtmalı çağrı. Ruby ``send``/``__send__`` görünürlük
        # denetimini atlayabilir; ``public_send`` yalnız public yöntemleri
        # çağırabilir. ActiveSupport ``try``/``try!`` farklı nil/arity/block
        # semantiklerine sahip olduğundan burada eşdeğer kabul edilmez.
        if method in ("send", "public_send", "__send__") and positional:
            x0, y0 = positional[0]
            while x0 < y0 and toks[x0].kind == "nl":
                x0 += 1
            literal_method = x0 < y0 and y0 - x0 == 1 and (
                toks[x0].kind == "sym" or (toks[x0].kind == "str" and not toks[x0].interp)
            )
            if literal_method and re.fullmatch(r"[A-Za-z_]\w*[!?=]?", toks[x0].value):
                if method == "public_send":
                    if not bare and recv_kind not in ("self", "const"):
                        return EMPTY
                    callees = [
                        callee for callee in self.proj.resolve(
                            self.func, recv_kind, recv_name, toks[x0].value, bare
                        )
                        if "public" in callee.possible_visibilities
                    ]
                    if callees:
                        return self.apply_summary(callees, taints[1:], kw_taints, line)
                    return EMPTY
                return self.call(toks, recv_taint if not bare else None, recv if not bare else None, toks[x0].value,
                                 positional[1:], keywords, line, bare=bare)

        # 3) hedefler
        self.sinks(toks, recv_taint, recv_kind, recv_name, method, positional, keywords, taints, kw_taints, line, bare)

        # 4) adlandırılmış arındırıcılar ve çevirmenler
        if bare:
            if method == "sanitize":  # ActionView#sanitize (HTML) / ActiveRecord sanitize (alıntılama)
                return _clean(all_taint, frozenset({"html", "sql"}))
            if method in ("h", "html_escape", "escape_once", "escape_javascript", "j", "json_escape", "sanitize_css",
                          "u", "url_encode"):
                return _clean(all_taint, frozenset({"html"}))
            if method in ("Integer", "Float", "Rational", "Complex"):
                return EMPTY
            if method in ("sanitize_sql", "sanitize_sql_array", "sanitize_sql_for_conditions", "quote", "sanitize_sql_like"):
                return _clean(all_taint, frozenset({"sql"}))
            if re.search(r"_(?:path|url)$", method):
                return EMPTY
            if method == "url_for":
                if not positional:
                    return EMPTY
                x0, y0 = positional[0]
                items = [t for t in toks[x0:y0] if t.kind != "nl"]
                direct = items and ((items[0].kind == "id" and items[0].value in ("params", "request", "cookies")
                                     and not self._ends_with_call(toks, x0, y0, tuple(_RB_HASH_METHODS)))
                                    or (items[0].kind == "str" and items[0].interp)
                                    or (len(items) == 1 and items[0].kind in ("id", "ivar") and items[0].value in self.env
                                        and items[0].value not in self.hash_vars))
                if not direct:
                    return EMPTY  # url_for(karma / yol yardımcısı)
        if recv_kind == "const":
            cleaned = self._const_sanitizer(recv_name, method)
            if cleaned == "all":
                return EMPTY
            if cleaned:
                return _clean(all_taint, cleaned)

        # 5) proje yöntemleri
        callees = self.proj.resolve(self.func, recv_kind, recv_name, method, bare)
        if callees:
            return self.apply_summary(callees, taints, kw_taints, line) | (recv_taint if not bare and method in _RB_ARG_PROP else EMPTY)

        # 6) varsayılan yayılım
        if bare:
            if method in ("send", "public_send", "__send__", "eval", "system", "exec", "spawn", "render", "redirect_to",
                          "send_file", "raise", "puts", "print", "p", "logger", "respond_with", "head", "flash"):
                return EMPTY
            return all_taint
        if recv_kind == "const":
            props = _RB_CONST_PROP.get(recv_name or "")
            if props is not None and method in props:
                return all_taint
            if recv_name == "File" and method == "basename":
                return _clean(all_taint, frozenset({"path"}))
            return EMPTY
        result = recv_taint
        if method in _RB_ARG_PROP:
            result = result | all_taint
        return result

    def _note_stored(self, model: str, taints: list, kw_taints: dict) -> None:
        if self.funclit_depth or not model:
            return
        bucket = self.proj.stored.setdefault(model, {})
        for name, taint in kw_taints.items():
            req = frozenset(o for o in taint if o.label == "request")
            if req:
                bucket[name] = bucket.get(name, EMPTY) | req
        for taint in taints:
            req = frozenset(o for o in taint if o.label == "request")
            if req:
                bucket["*"] = bucket.get("*", EMPTY) | req  # Model.create(post_params): toplu öznitelik yazımı
        if not bucket:
            self.proj.stored.pop(model, None)

    def invoke_lambdas(self, toks: list[Tok], lams: list, taints: list, kw_taints: dict, line: int) -> None:
        """Saklanan lambda gövdelerini çağrı argümanlarının iziyle satır içi değerlendir (yalnız hedefler için;
        dönüş değeri çevreleyen yöntemin özetine karışmaz)."""
        for lam in lams:
            if lam[0] == "meth":
                callees = self.proj.resolve(self.func, "self", None, lam[1], True)
                if callees:
                    self.apply_summary(callees, taints, kw_taints, line)
                continue
            _, params, a, b = lam
            key = (id(toks), a)
            if key in self.active_lambdas or len(self.active_lambdas) > 4:
                continue
            saved = {name: self.env.get(name) for name in params}
            saved_locals = set(self.locals)
            for index, name in enumerate(params):
                taint = taints[index] if index < len(taints) else EMPTY
                self.locals.add(name)
                if taint:
                    self.env[name] = taint
                else:
                    self.env.pop(name, None)
            self.active_lambdas.add(key)
            self.funclit_depth += 1
            saved_depth = self.depth
            try:
                self.body(toks, a, b, ())
            finally:
                self.depth = saved_depth
                self.funclit_depth -= 1
                self.active_lambdas.discard(key)
                for name, value in saved.items():
                    if value is None:
                        self.env.pop(name, None)
                    else:
                        self.env[name] = value
                self.locals = saved_locals

    def _const_sanitizer(self, const: str | None, method: str) -> frozenset | str | None:
        const = const or ""
        if (const, method) in (("CGI", "escapeHTML"), ("CGI", "escape_html"), ("ERB::Util", "html_escape"),
                               ("ERB::Util", "h"), ("Rack::Utils", "escape_html"), ("ActionController::Base", "helpers")):
            return frozenset({"html"})
        if (const, method) in (("Shellwords", "escape"), ("Shellwords", "shellescape"), ("Shellwords", "join"),
                               ("Shellwords", "shelljoin")):
            return frozenset({"command"})
        if (const, method) == ("File", "basename"):
            return frozenset({"path"})
        if (const, method) in (("CGI", "escape"), ("ERB::Util", "url_encode"), ("URI", "encode_www_form_component"),
                               ("URI", "encode_uri_component"), ("Rack::Utils", "escape")):
            return frozenset({"html", "ssrf_partial", "redirect", "command", "sql"})
        if method in ("sanitize_sql", "sanitize_sql_array", "sanitize_sql_for_conditions", "quote", "sanitize_sql_like"):
            return frozenset({"sql"})
        if const in ("Integer", "Float") or (const, method) in (("Date", "parse"), ("Time", "parse"), ("DateTime", "parse")):
            return "all"
        return None

    def sinks(self, toks, recv_taint, recv_kind, recv_name, method, positional, keywords, taints, kw_taints, line, bare) -> None:
        const = recv_name if recv_kind == "const" else None
        chain_text = recv_name or ""

        def lead(index: int) -> str | None:
            return self._lead(toks, positional[index]) if index < len(positional) else None

        # -- komut
        if (bare or const in ("Kernel", "Process")) and method in ("system", "exec", "spawn"):
            if len(positional) == 1:
                self._check_at("command", method, taints, 0, line)
            elif positional:
                literal = lead(0)
                if literal is None or literal.strip() in _RB_SHELLS:
                    for index in range(len(positional)):
                        self._check_at("command", method, taints, index, line)
            return
        if const == "Open3" or (const == "IO" and method == "popen") or (const == "PTY" and method == "spawn"):
            if len(positional) == 1:
                self._check_at("command", f"{const}.{method}", taints, 0, line)
            elif positional and (lead(0) is None or (lead(0) or "").strip() in _RB_SHELLS):
                for index in range(len(positional)):
                    self._check_at("command", f"{const}.{method}", taints, index, line)
            return
        if (bare and method == "open") or (const == "Kernel" and method == "open"):
            literal = lead(0)
            if not literal:  # baştaki sabit yok: "|komut" verilebilir
                self._check_at("command", "Kernel#open", taints, 0, line)
            self._check_at("path", "Kernel#open", taints, 0, line)
            return
        # -- kod
        if bare and method == "eval" or method in ("instance_eval", "class_eval", "module_eval") and positional:
            self._check_at("eval", method, taints, 0, line)
            return
        if method in ("send", "public_send", "__send__") and positional:
            self._check_at("eval", f".{method} (dinamik yöntem çağrısı)", taints, 0, line)
            return
        if bare and self.func.file.sinatra and self.func.kind != "view":
            if method == "content_type" and positional and lead(0) is None and \
                    any(t.kind in ("sym", "str") and "json" in str(t.value) for t in toks[positional[0][0]:positional[0][1]]):
                self.route_json = True
            elif method == "redirect" and positional:
                literal = lead(0)
                x0, y0 = positional[0]
                helper_rel = (y0 - x0 >= 3 and toks[x0].kind == "id" and toks[x0 + 1].kind == "op"
                              and toks[x0 + 1].value == "(" and toks[x0 + 2].kind == "str"
                              and not re.match(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:|//|\\\\|#\{)", str(toks[x0 + 2].value)))
                # url("/x"), to("…"), u("queues/#{id}"): uygulama kökünü öneken yol yardımcıları — aynı site
                if not helper_rel and not (literal is not None and (_SAFE_REDIRECT.match(literal) or _FIXED_HOST.match(literal))):
                    self._check_at("redirect", "redirect (Sinatra)", taints, 0, line)
                return EMPTY
            elif method == "erb" and positional and toks[positional[0][0]].kind in ("sym", "str") \
                    and positional[0][1] - positional[0][0] == 1:
                name = str(toks[positional[0][0]].value)
                stem = str(PurePosixPath(self.func.file.rel).parent / "views" / name)
                env = self.proj.sinatra_views.setdefault(stem, {})
                for k, v in self.env.items():
                    if k.startswith("@") and v:
                        env[k] = env.get(k, EMPTY) | _via(frozenset(o for o in v if o.label != PARAM), f"erb :{name}")
        if const == "ERB" and method == "new":
            self._check_at("eval", "ERB.new (şablon enjeksiyonu)", taints, 0, line)
            return
        if bare and method == "render":
            if "inline" in kw_taints:
                self.sink("eval", "render inline: (şablon enjeksiyonu)", kw_taints["inline"], line)
            if self.func.kind != "view" and not positional and "text" in kw_taints:
                self.sink("html", "render text: (HTML yanıtı)", kw_taints["text"], line)
            for key in ("file", "template", "partial", "action"):
                if key in kw_taints:
                    self.sink("path", f"render {key}:", kw_taints[key], line)
            single_obj = positional and positional[0][1] - positional[0][0] == 1 and \
                toks[positional[0][0]].kind == "ivar"  # 18. tur: render @post — model nesnesi (kısmi), yol değil
            if positional and not single_obj and self._sqlish(toks, positional[0]) and lead(0) is None:
                self.sink("path", "render (dinamik şablon yolu)", taints[0], line)
            return
        if bare and method in ("load", "require", "require_dependency", "autoload") and positional:
            self._check_at("path", f"{method} (dosya yükleme)", taints, 0, line)
            return
        if const in ("YAML", "Psych", "CSV", "JSON") and method in ("load_file", "parse_file", "safe_load_file",
                                                                     "unsafe_load_file", "read", "foreach", "open", "readlines"):
            self._check_at("path", f"{const}.{method}", taints, 0, line)
            return
        # 19. tur: Nokogiri XML dış varlıkları açık (NOENT/DTDLOAD seçeneği ya da do |config| config.noent bloğu)
        if ((const in ("Nokogiri", "Nokogiri::XML", "Nokogiri::XML::Document") and method in ("XML", "parse"))
                or (bare and method == "Nokogiri::XML")) and positional:
            end = positional[-1][1]
            window = toks[end:min(len(toks), end + 60)]
            stop = next((i for i, t in enumerate(window) if t.kind == "id" and t.value == "end"), len(window))
            opts = [t for t in toks[positional[0][1]:end] if t.kind in ("id", "const", "sym")] + window[:stop]
            if any(str(t.value).lower() in ("noent", "dtdload", "dtdattr") or str(t.value).upper().endswith(("NOENT", "DTDLOAD"))
                   for t in opts):
                self._check_at("xxe", f"{const}.{method} (dış varlık açık)", taints, 0, line)
        if const == "CSV" and method == "load":
            self._check_at("deserialize", "CSV.load", taints, 0, line)
            return
        if method in ("qualified_const_get", "const_get") and positional:
            self._check_at("eval", f"{method} (güvensiz yansıma)", taints, 0, line)
            return
        # -- HTML
        if bare and method == "raw":
            self._check_at("html", "raw()", taints, 0, line)
            return
        # -- yönlendirme
        if not bare and method == "redirect_to" and recv_name in ("response", "res") and positional:
            literal = lead(0)
            if not (literal is not None and (_SAFE_REDIRECT.match(literal) or _FIXED_HOST.match(literal))):
                self._check_at("redirect", "response.redirect_to (Hanami)", taints, 0, line)
            return
        if bare and method == "redirect_to" and positional:
            allow = keywords.get("allow_other_host")
            allow_true = allow is not None and any(t.kind == "id" and t.value == "true" for t in toks[allow[0]:allow[1]])
            if allow is not None and not allow_true:
                return  # allow_other_host: false
            if self.proj.rails_redirect_protected and not allow_true:
                return  # Rails 7+: raise_on_open_redirects dış sunucuya yönlendirmeyi engeller
            literal = lead(0)
            if literal is not None and (_SAFE_REDIRECT.match(literal) or _FIXED_HOST.match(literal)):
                return
            x0, y0 = positional[0]
            hashy = self._ends_with_call(toks, x0, y0, ("merge", "permit", "slice", "to_unsafe_h", "to_unsafe_hash")) \
                or (toks[x0].kind == "op" and toks[x0].value == "{")
            if keywords.get("only_path") is not None and hashy:
                return
            if self._ends_with_call(toks, x0, y0, ("permit", "slice")):
                keys = {t.value for t in toks[x0:y0] if t.kind == "sym"}
                if not keys & _RB_DANGEROUS_URL_KEYS:
                    return
            hash_keys = self._hash_keys(toks, x0, y0)
            if "only_path" in hash_keys:
                return
            if "host" in hash_keys:
                hx, hy = hash_keys["host"]
                self.sink("redirect", "redirect_to (host:)", self.eval(toks, hx, hy), line)
                return
            self._check_at("redirect", "redirect_to", taints, 0, line)
            return
        # -- yol
        if bare and method in ("send_file",):
            self._check_at("path", "send_file", taints, 0, line)
            return
        if const in ("File", "IO") and method in ("open", "read", "readlines", "binread", "write", "binwrite", "delete",
                                                  "unlink", "foreach", "new", "rename", "readlink", "truncate"):
            self._check_at("path", f"{const}.{method}", taints, 0, line)
            if method == "rename":
                self._check_at("path", f"{const}.{method}", taints, 1, line)
            return
        if const == "FileUtils":
            for index in range(min(2, len(positional))):
                self._check_at("path", f"FileUtils.{method}", taints, index, line)
            return
        # -- SSRF
        if const in ("Net::HTTP",) and method in ("get", "get_response", "post", "post_form", "start", "new", "get_print"):
            self._ssrf_check(toks, positional, taints, 0, f"Net::HTTP.{method}", line)
            return
        if (const == "URI" and method == "open") or (const in ("HTTParty", "Faraday", "RestClient", "Excon", "Typhoeus", "HTTP", "HTTPX")
                                                      and method in ("get", "post", "put", "patch", "delete", "head", "new", "request", "options")):
            if positional:
                self._ssrf_check(toks, positional, taints, 0, f"{const}.{method}", line)
            elif "url" in kw_taints:
                self.sink("ssrf", f"{const}.{method}", kw_taints["url"], line)
            return
        if const in ("Typhoeus::Request", "RestClient::Request") and method in ("new", "execute"):
            if positional:
                self._ssrf_check(toks, positional, taints, 0, f"{const}.{method}", line)
            if "url" in kw_taints:
                self.sink("ssrf", f"{const}.{method}", kw_taints["url"], line)
            return
        # -- seri çözme
        if const in ("YAML", "Psych") and method in ("load", "load_stream") and "safe" in keywords:
            x0, y0 = keywords["safe"]
            if any(t.kind == "id" and t.value == "true" for t in toks[x0:y0]):
                return
        if const == "Oj" and method == "load" and "mode" in keywords:
            x0, y0 = keywords["mode"]
            if any(t.kind == "sym" and t.value in ("strict", "compat", "null", "json", "rails", "wab") for t in toks[x0:y0]):
                return
        if (const in ("Marshal",) and method in ("load", "restore")) or (const in ("YAML", "Psych") and method in ("load", "unsafe_load", "load_stream")) \
                or (const == "Oj" and method in ("load", "object_load")) or (const == "JSON" and method == "load"):
            self._check_at("deserialize", f"{const}.{method}", taints, 0, line)
            return
        if const == "Arel" and method == "sql":
            self._check_at("sql", "Arel.sql", taints, 0, line)
            return
        if bare and method == "link_to" and positional:
            index = 1 if len(positional) >= 2 else 0
            literal = lead(index)
            x0, y0 = positional[index]
            while x0 < y0 and toks[x0].kind == "nl":
                x0 += 1
            head = toks[x0] if x0 < y0 else None
            helper = head is not None and head.kind == "id" and head.value not in self.env and head.value not in self.locals \
                and head.value not in ("params", "cookies", "request", "url_for", "h", "html_escape") \
                and x0 + 1 < y0 and (toks[x0 + 1].value == "(" or toks[x0 + 1].sp)
            hashy = self._ends_with_call(toks, x0, y0, tuple(_RB_HASH_METHODS))
            trusted_prefix = False
            if head is not None and head.kind == "str" and head.interp and y0 - x0 == 1 and not literal:
                first_part = head.interp[0]
                trusted_prefix = not self.eval(list(first_part), 0, len(first_part)) and head.value.startswith("#{")
            if not literal and not helper and not hashy and not trusted_prefix:
                raw = self.eval(toks, x0, y0)
                uncleaned = frozenset(Origin(o.label, o.source, o.line, o.file, o.via, o.cleaned - {"html"}) for o in raw)
                self.sink("html", "link_to (href: javascript: URL)", uncleaned, line)
            return
        # -- SQL
        if method in _RB_SQL_METHODS and not bare or (bare and method in ("find_by_sql", "where", "order", "select")
                                                         and self.func.cls and not self.func.sources_ok):
            if const and (const in _RB_NON_MODEL_CONSTS or const.split("::")[0] in _RB_NON_MODEL_CONSTS):
                return
            if recv_kind in ("source", "request"):
                return
            if self.func.kind == "view" and recv_kind != "const":
                return
            if recv_kind == "var" and recv_name in ("f", "form", "builder", "ff", "fields", "form_builder"):
                return
            if method in ("select", "sum") and not positional:
                return
            index = _RB_SQL_METHODS.get(method, 0)
            indexes = range(len(positional)) if method in _RB_SQL_ALL_ARGS else [index]
            for k in indexes:
                if k >= len(positional) or not self._sqlish(toks, positional[k]):
                    continue
                x0, y0 = positional[k]
                if method == "exists?" and self._ends_with_call(toks, x0, y0, ("to_s", "to_i")):
                    continue  # exists?("1") birincil anahtar aramasıdır
                arrow = self._top_arrow(toks, x0, y0)
                taint = self.eval(toks, x0, arrow) if arrow is not None else taints[k]
                self.sink("sql", f".{method}", taint, line)
            return
        if recv_kind == "const" and const and const not in _RB_NON_MODEL_CONSTS and method in (
                "find", "first", "last", "all", "count", "calculate", "sum", "minimum", "maximum", "average", "exists?",
                "update_all", "delete_all", "destroy_all", "find_each", "paginate", "scoped", "with_scope"):
            for key in ("conditions", "order", "group", "having", "joins", "select", "from", "lock", "limit", "offset"):
                if key in keywords:
                    x0, y0 = keywords[key]
                    self.sink("sql", f".{method}(:{key} => …)", self._sql_value_taint(toks, x0, y0), line)
        if method in ("update_all", "delete_all") and len(positional) >= 2 and not bare:
            x0, y0 = positional[1]
            self.sink("sql", f".{method} (koşul)", self._sql_value_taint(toks, x0, y0), line)
        if method in _RB_SQL_CONN_METHODS and positional and (
                "connection" in chain_text or const in ("ActiveRecord::Base",) or re.search(r"(?i)conn|db|connection", chain_text or "")):
            self._check_at("sql", f"connection.{method}", taints, 0, line)
            return
        # 19. tur: Sequel (Roda/Hanami/Sinatra) — DB.fetch("… #{x}") / DB.run / Sequel.lit("… #{x}")
        if method in ("fetch", "run", "with_sql", "execute_dui", "execute_insert") and positional and \
                re.search(r"(?i)\bdb\b|database|sequel|conn", chain_text or "") and self._sqlish(toks, positional[0]):
            self._check_at("sql", f"Sequel {method}", taints, 0, line)
            return
        if const == "Sequel" and method in ("lit", "Literal") and positional and self._sqlish(toks, positional[0]):
            self._check_at("sql", "Sequel.lit", taints, 0, line)
            return
        if method in ("connection",):
            return

    def _ssrf_check(self, toks, positional, taints, index, name, line) -> None:
        if index >= len(positional):
            return
        literal = self._lead(toks, positional[index])
        kind = "ssrf_partial" if literal is not None and _FIXED_HOST.match(literal) else "ssrf"
        self.sink(kind, name, taints[index], line)


class RubyProject(_ProjectBase):
    def __init__(self, files: dict[str, str]) -> None:
        super().__init__()
        self.files: list[RubyFile] = []
        for rel, text in files.items():
            if not rel.endswith((".rb", ".erb", ".haml")):
                continue
            try:
                self.files.append(parse_ruby_file(rel, text))
            except (RecursionError, IndexError, ValueError):
                continue
        self.funcs: list[RubyFunc] = [
            f for rf in self.files for f in rf.funcs
            if f.kind != "view" and f.definition_certainty != "never"
        ]
        # SABİT = lambda / { "a" => ->(x) { … } } : aynı dosyada SABİT[k].call(x) çağrıları için
        self.const_lambdas: dict[tuple[str, str], list] = {}
        for rf in self.files:
            for name, items in _rb_const_lambdas(rf).items():
                self.const_lambdas[(rf.rel, name)] = items
        self.views: list[RubyFunc] = [f for rf in self.files for f in rf.funcs if f.kind == "view"]
        # 17. tur: ActiveRecord modelleri ve istek verisiyle yazılan öznitelikleri (kayıtlı veri; okunduğu yerde kaynak)
        self.models: set[str] = set()
        self.model_classes: set[str] = set()
        self.serializer_classes: set[str] = set()
        self.serializer_class_names: set[str] = set()
        self.class_names: set[str] = {
            cls for rf in self.files for cls, _super_cls, _is_class in rf.classes if cls
        }
        class_parents: dict[str, str] = {}
        for rf in self.files:
            for cls, super_cls, is_class in rf.classes:
                if not is_class or not cls:
                    continue
                class_parents.setdefault(cls, super_cls)
                if super_cls in {"ApplicationRecord", "ActiveRecord::Base"}:
                    self.model_classes.add(cls)
                if super_cls == "ActiveModel::Serializer" or super_cls.split("::")[-1] == "ApplicationSerializer":
                    self.serializer_class_names.add(cls)
        for rel, text in files.items():
            if rel.endswith(".rb"):
                detected_models = set(re.findall(
                    r"^\s*class\s+([A-Z]\w*)\s*<\s*(?:ApplicationRecord|ActiveRecord::Base)\b", text, re.M,
                ))
                flat_models = detected_models & self.class_names
                self.model_classes.update(flat_models)
                self.models.update(detected_models)
                detected_serializers = set(re.findall(
                    r"^\s*class\s+([A-Z]\w*)\s*<\s*(?:ActiveModel::Serializer|ApplicationSerializer)\b",
                    text, re.M,
                ))
                flat_serializers = detected_serializers & self.class_names
                self.serializer_class_names.update(flat_serializers)
                self.serializer_classes.update(detected_serializers)
        # Rails applications commonly put domain models and serializers below
        # custom abstract bases.  Classify the complete declared inheritance
        # chain before resolving writes/reads; cap traversal so hostile class
        # graphs cannot make project setup unbounded.
        for _depth in range(min(len(class_parents), 64)):
            changed = False
            for cls, raw_parent in sorted(class_parents.items()):
                parent = self._lexical_constant(cls, raw_parent, self.class_names) or raw_parent
                if cls not in self.model_classes and parent in self.model_classes:
                    self.model_classes.add(cls)
                    changed = True
                if cls not in self.serializer_class_names and parent in self.serializer_class_names:
                    self.serializer_class_names.add(cls)
                    changed = True
            if not changed:
                break
        for cls in self.model_classes:
            self.models.update({cls, cls.split("::")[-1]})
        for cls in self.serializer_class_names:
            self.serializer_classes.update({cls, cls.split("::")[-1]})
        self.stored: dict[str, dict[str, frozenset]] = {}  # model → {öznitelik ya da "*": kaynak izleri}
        # 25. tur: model → bildirilmiş ilişki adları (has_many :comments, belongs_to :author, class_name: "User")
        self.assocs: dict[str, set[str]] = {}
        self.assocs_target: dict[str, str] = {}
        for rel, text in files.items():
            if not rel.endswith(".rb"):
                continue
            for cm in re.finditer(r"^\s*class\s+([A-Z]\w*)\s*<[^\n]*\n(.*?)(?=^\s*class\s|\Z)", text, re.M | re.S):
                if cm.group(1) not in self.models:
                    continue
                for am in re.finditer(r"^\s*(?:has_many|has_one|belongs_to|has_and_belongs_to_many)\s+:(\w+)([^\n]*)",
                                      cm.group(2), re.M):
                    self.assocs.setdefault(cm.group(1), set()).add(am.group(1))
                    target = re.search(r"class_name:?\s*(?:=>\s*)?[\"'](\w+)[\"']", am.group(2))
                    if target:
                        self.assocs_target[am.group(1)] = target.group(1)
        self.by_class: dict[tuple[str, bool], dict[str, list[RubyFunc]]] = {}
        self.by_name: dict[str, list[RubyFunc]] = {}
        self.callbacks: dict[str, list] = {}
        self.includes: dict[str, list[str]] = {}
        self.supers: dict[str, str] = {}
        self.rails_redirect_protected = False
        # 19. tur Sinatra: erb :ad ile işlenen görünümlere rota @değişkenleri; escape_html açıksa <%= %> kaçışlı
        self.sinatra_views: dict[str, dict[str, frozenset]] = {}
        self.sinatra_escape_html = any(rf.sinatra for rf in self.files) and any(
            re.search(r"escape_html\s*(?:=>|:|,)\s*true|Rack::Protection::EscapedParams|Erubi::Handler|erubi.*escape", text)
            for rel, text in files.items() if rel.endswith(".rb"))
        for rel, text in files.items():
            if rel.endswith("config/application.rb"):
                m = re.search(r"config\.load_defaults\s+['\"]?(\d+)\.(\d+)", text)
                if m and int(m.group(1)) >= 7:
                    self.rails_redirect_protected = True
        redirect_override: bool | None = None
        for rel, text in files.items():
            if not (rel.startswith("config/initializers/") or rel.startswith("config/environments/")
                    or rel == "config/application.rb"):
                continue
            if "raise_on_open_redirects" not in text:
                continue
            values = re.findall(
                r"^\s*(?:Rails\.application\.)?config\.action_controller\.raise_on_open_redirects"
                r"\s*=\s*(true|false)\s*(?:#.*)?$", text, re.M,
            )
            if "false" in values:
                redirect_override = False
            elif values and redirect_override is None:
                redirect_override = True
        if redirect_override is not None:
            self.rails_redirect_protected = redirect_override
        for rf in self.files:
            for cls, items in rf.callbacks.items():
                self.callbacks.setdefault(cls, []).extend(items)
            for cls, items in rf.includes.items():
                targets = self.includes.setdefault(cls, [])
                for module, line in items:
                    resolved = self._lexical_constant(cls, module, self.class_names) or module
                    if not any(old[0] == resolved for old in targets):
                        targets.append((resolved, line))
        for f in self.funcs:
            if f.cls and f.super_cls:
                resolved = self._lexical_constant(f.cls, f.super_cls, self.class_names) or f.super_cls
                self.supers.setdefault(f.cls, resolved)
        active_methods: dict[tuple[str, bool, str], list[RubyFunc]] = {}
        ordered_funcs = [
            f
            for rf in self.files
            for f in sorted((item for item in rf.funcs if item.kind != "view"), key=lambda item: item.line)
        ]
        branch_members: dict[tuple[int, int], list[RubyFunc]] = {}
        for f in ordered_funcs:
            if f.definition_branch_group is not None:
                branch_members.setdefault((id(f.file), f.definition_branch_group), []).append(f)
        processed_groups: set[tuple[int, int]] = set()

        def index_one(f: RubyFunc) -> None:
            if f.kind == "main":
                return
            if f.definition_certainty == "never":
                return
            key = (f.cls, f.class_method, f.name)
            if f.definition_certainty == "maybe":
                active_methods.setdefault(key, []).append(f)
            else:
                active_methods[key] = [f]

        for f in ordered_funcs:
            group_id = f.definition_branch_group
            group_key = (id(f.file), group_id) if group_id is not None else None
            if group_key is None or not f.definition_group_exhaustive \
                    or f.definition_group_parent_certainty != "always":
                index_one(f)
                continue
            if group_key in processed_groups:
                continue
            processed_groups.add(group_key)
            members = branch_members[group_key]
            reachable_arms = set(f.definition_group_arms)
            by_method: dict[tuple[str, bool, str], dict[int, RubyFunc]] = {}
            for member in members:
                if member.kind == "main" or member.definition_certainty == "never" \
                        or member.definition_branch_arm is None:
                    continue
                key = (member.cls, member.class_method, member.name)
                # Ruby's last unconditional definition in one branch wins in
                # that branch; different arms remain alternative candidates.
                by_method.setdefault(key, {})[member.definition_branch_arm] = member
            covered: set[tuple[str, bool, str]] = set()
            for key, definitions_by_arm in by_method.items():
                if reachable_arms and reachable_arms.issubset(definitions_by_arm):
                    active_methods[key] = [
                        definitions_by_arm[arm] for arm in sorted(reachable_arms)
                    ]
                    covered.add(key)
            for member in members:
                key = (member.cls, member.class_method, member.name)
                if key not in covered:
                    index_one(member)
        for (cls, class_method, name), funcs in active_methods.items():
            short = cls.split("::")[-1] if cls else ""
            for cls_key in {cls, short}:
                self.by_class.setdefault((cls_key, class_method), {}).setdefault(name, []).extend(funcs)
            if not class_method:
                self.by_name.setdefault(name, []).extend(funcs)

    @staticmethod
    def _lexical_constant(owner: str, name: str, declared: set[str]) -> str | None:
        """Resolve an unqualified Ruby constant through the owner's lexical modules."""
        if not name:
            return None
        if "::" in name:
            return name if name in declared else None
        namespace = owner.split("::")[:-1]
        for size in range(len(namespace), 0, -1):
            candidate = "::".join([*namespace[:size], name])
            if candidate in declared:
                return candidate
        if name in declared:
            return name
        matches = sorted(item for item in declared if item.rsplit("::", 1)[-1] == name)
        return matches[0] if len(matches) == 1 else None

    def model_constant(self, func: RubyFunc, name: str | None) -> str | None:
        return self._lexical_constant(func.cls, name or "", self.model_classes)

    def serializer_constant(self, func: RubyFunc, name: str | None) -> str | None:
        return self._lexical_constant(func.cls, name or "", self.serializer_class_names)

    def resolve(self, func: RubyFunc, recv_kind: str | None, recv_name: str | None, method: str, bare: bool) -> list[RubyFunc]:
        if bare or recv_kind == "self":
            for class_method in (func.class_method, not func.class_method):
                found = self.by_class.get((func.cls, class_method), {}).get(method)
                if found:
                    return found
            if func.super_cls:
                found = self.by_class.get((func.super_cls.split("::")[-1], func.class_method), {}).get(method)
                if found:
                    return found
            candidates = [c for c in self.by_name.get(method, [])
                          if not c.cls.endswith(("Controller", "Job", "Mailer", "Worker", "Component"))
                          or re.search(r"/(?:concerns|helpers)/", c.file.rel)]
            if len(candidates) == 1 and method not in _RB_COMMON_METHODS:
                return candidates
            return []
        if recv_kind == "const" and recv_name:
            canonical = self._lexical_constant(func.cls, recv_name, self.class_names)
            if canonical is None:
                return []
            found = self.by_class.get((canonical, True), {}).get(method)
            return found or []
        candidates = [c for c in self.by_name.get(method, [])
                      if not c.cls.endswith(("Controller", "Job", "Mailer", "Worker")) and "/controllers/" not in c.file.rel]
        if 0 < len(candidates) <= 2 and method not in _RB_COMMON_METHODS:
            return candidates
        return []

    def _callback_items(self, cls: str, seen: frozenset[str] = frozenset()) -> list[tuple]:
        """Expand concern callbacks at the exact source position of ``include``."""
        if not cls or cls in seen or len(seen) > 16:
            return []
        visited = seen | {cls}
        events: list[tuple[int, int, Any]] = []
        for order, item in enumerate(self.callbacks.get(cls, ())):
            events.append((item[5], order, item))
        offset = len(events)
        for order, (module, line) in enumerate(self.includes.get(cls, ())):
            events.append((line, offset + order, module))
        expanded: list[tuple] = []
        for _line, _order, value in sorted(events, key=lambda item: (item[0], item[1])):
            if isinstance(value, str):
                expanded.extend(self._callback_items(value, frozenset(visited)))
            else:
                expanded.append(value)
        return expanded

    def _included_classes(self, cls: str, seen: frozenset[str] = frozenset()) -> list[str]:
        if not cls or cls in seen or len(seen) > 16:
            return []
        visited = seen | {cls}
        found: list[str] = []
        for module, _line in self.includes.get(cls, ()):
            if module not in found:
                found.append(module)
            found.extend(item for item in self._included_classes(module, frozenset(visited)) if item not in found)
        return found

    def callback_ivars(self, func: RubyFunc) -> dict[str, frozenset]:
        """Return the instance-variable state present when the action renders.

        Before callbacks and the pre-yield half of around callbacks run before
        implicit rendering.  After callbacks and the post-yield half run after
        the rendered response and cannot retroactively populate its view.
        """
        classes = []
        cls = func.cls
        seen = set()
        while cls and cls not in seen:
            seen.add(cls)
            classes.append(cls)
            cls = self.supers.get(cls, "")
        prepends: list = []
        appends: list = []
        skips: set[tuple[str, str]] = set()
        for cls in reversed(classes):  # üst sınıftan alta, concern'ler kaynak sırasındaki include konumunda
            for kind, name, only, exclude, condition, _line in self._callback_items(cls):
                if condition is False:
                    continue
                applies = (not only or func.name in only) and func.name not in exclude
                if not applies:
                    continue
                if kind.startswith("skip:"):
                    skips.add((kind.split(":", 1)[1], name))
                    continue
                phase = kind.split(":", 1)[-1]
                if phase == "after":
                    continue
                item = (phase, name)
                if kind.startswith("prepend:"):
                    prepends.insert(0, item)
                else:
                    appends.append(item)
        env: dict[str, frozenset] = {}
        resolution_classes = list(classes)
        for owner in classes:
            resolution_classes.extend(
                item for item in self._included_classes(owner) if item not in resolution_classes
            )
        for phase, name in [*prepends, *appends]:
            if (phase, name) in skips:
                continue
            alternatives = name.startswith("__sniper_alt_callback_")
            if alternatives:
                owner_order = list(dict.fromkeys([func.cls, *resolution_classes]))
                callees = [
                    callee
                    for owner in owner_order
                    for callback_name, functions in self.by_class.get((owner, False), {}).items()
                    if callback_name.startswith(f"{name}_")
                    for callee in functions
                ]
            else:
                callees = self.by_class.get((func.cls, False), {}).get(name, []) or \
                    [f for c in resolution_classes
                     for f in self.by_class.get((c, False), {}).get(name, [])][:1]
            alternative_ivars: dict[str, frozenset] = {}
            for callee in callees:
                summary = self._around_prefix_summary(callee, env) if phase == "around" \
                    else self.summaries.get(callee.key)
                if summary is None:
                    continue
                for ivar, taint in summary.ivars.items():
                    value = _via(taint, name) if taint else EMPTY
                    if alternatives:
                        alternative_ivars[ivar] = alternative_ivars.get(ivar, EMPTY) | value
                    else:
                        env[ivar] = value
                if not alternatives:
                    break
            for ivar, taint in alternative_ivars.items():
                env[ivar] = env.get(ivar, EMPTY) | taint
        return env

    def _around_prefix_summary(self, func: RubyFunc, env: dict[str, frozenset]) -> Summary | None:
        """Analyze only statements before an around callback invokes its action."""
        a, b = func.body
        cutoff = b
        params = set(func.params)
        toks = func.file.toks
        for index in range(a, b):
            token = toks[index]
            if token.kind == "id" and token.value == "yield":
                cutoff = index
                break
            if token.kind == "id" and (token.value in params or token.value in {"action", "block", "callback"}) \
                    and index + 2 < b \
                    and toks[index + 1].kind == "op" and toks[index + 1].value in (".", "&.") \
                    and toks[index + 2].kind == "id" and toks[index + 2].value == "call":
                cutoff = index
                break
        # Without an action boundary this is not a usable around callback.  It
        # may terminate the request, but cannot establish a rendered view env.
        if cutoff == b:
            return None
        prefix = RubyFunc(
            func.name, func.file, func.cls, func.class_method, func.params, func.kwparams,
            (a, cutoff), func.line, func.sources_ok, "callback_prefix", func.variadic,
            func.super_cls, func.excluded, func.visibility, func.conditional, func.definition_certainty,
            func.definition_branch_group, func.definition_branch_arm,
            func.definition_group_parent_certainty, func.definition_group_exhaustive,
            func.definition_group_arms, func.visibility_options,
        )
        return RubyAnalyzer(self, prefix, env).run()

    def _views_for(self, func: RubyFunc) -> list[str]:
        rel = func.file.rel
        m = re.match(r"(?P<prefix>.*?)app/controllers/(?P<path>.+)_controller\.rb$", rel)
        if not m or func.class_method or func.kind != "def":
            return []
        prefix, ctrl = m.group("prefix"), m.group("path")
        names = {f"{prefix}app/views/{ctrl}/{func.name}"}
        toks = func.file.toks
        a, b = func.body
        for j in range(a, b):
            t = toks[j]
            if t.kind == "id" and t.value == "render" and j + 1 < b:
                nt = toks[j + 1]
                if nt.kind == "op" and nt.value == "(" and j + 2 < b:
                    nt = toks[j + 2]
                if nt.kind in ("sym", "str") and nt.value and "#{" not in nt.value:
                    target = nt.value
                    names.add(f"{prefix}app/views/{target}" if "/" in target else f"{prefix}app/views/{ctrl}/{target}")
                elif nt.kind == "label" and nt.value in ("action", "template") and j + 3 < b:
                    vt = toks[j + 3] if toks[j + 2].kind == "nl" else toks[j + 2]
                    if vt.kind in ("sym", "str"):
                        target = vt.value
                        names.add(f"{prefix}app/views/{target}" if "/" in target else f"{prefix}app/views/{ctrl}/{target}")
        return sorted(names)

    def analyze(self) -> dict[str, Any]:
        from taint_flow import Analysis

        converged = False
        for round_index in range(MAX_FIXPOINT_ROUNDS):
            self.flowsink = FlowSink()
            stored_before = {m: dict(a) for m, a in self.stored.items()}
            changed = False
            for func in self.funcs:
                previous = self.summaries.get(func.key)
                summary = RubyAnalyzer(self, func).run()
                if previous is None or previous.key() != summary.key():
                    changed = True
                self.summaries[func.key] = summary
            if self.stored != stored_before:
                changed = True  # kayıtlı veri okumaları yazmalardan önce görülmüş olabilir
            if not changed and round_index > 0:
                converged = True
                break
        if not converged:
            self.limitations.add("fixed-point")
        # Görünümler: denetleyici eyleminin @değişkenleri (son özetlerden)
        view_env: dict[str, dict[str, frozenset]] = {}
        for func in self.funcs:
            summary = self.summaries.get(func.key)
            if not summary or not summary.ivars:
                continue
            for stem in self._views_for(func):
                env = view_env.setdefault(stem, {})
                for name, taint in summary.ivars.items():
                    env[name] = env.get(name, EMPTY) | _via(taint, f"{func.name} eylemi")
        for view in self.views:
            rel = view.file.rel
            stem = rel.split(".", 1)[0] if "." in PurePosixPath(rel).name else rel
            stem = str(PurePosixPath(rel).parent / PurePosixPath(rel).name.split(".", 1)[0])
            if stem in self.sinatra_views:
                RubyAnalyzer(self, view, self.sinatra_views[stem], sinatra_view=True).run()
            else:
                env = view_env.get(stem)
                part = PurePosixPath(stem).name
                if part.startswith("_") and len(part) > 1:
                    # 25. tur: Rails kısmi görünümü (_post.html.erb ← render @post / render @posts) nesnesini kısmi
                    # adındaki yerel değişkenle alır; model istek verisiyle yazıldıysa yerel kayıtlı veridir.
                    local = part[1:]
                    model = _rb_camel_singular(local)
                    attrs = self.stored.get(model) if model in self.models else None
                    if attrs:
                        env = dict(env or {})
                        env[local] = env.get(local, EMPTY) | frozenset(
                            Origin("stored", f"{model}#{a} (kayıtlı veri)", o.line, o.file, (), o.cleaned - {"sql"})
                            for a, origins in attrs.items() for o in _osorted(origins)[:1])
                RubyAnalyzer(self, view, env).run()
        if self.flowsink.truncated:
            self.limitations.add("flow-count")
        results = {}
        for rf in self.files:
            flows = list(self.flowsink.flows.get(rf.rel, {}).values())
            result = Analysis(language="ruby", flows=sorted(flows, key=_flow_key))
            if self.limitations:
                result.mark_incomplete(*sorted(self.limitations))
            results[rf.rel] = result
        return results


def analyze_files(files: dict[str, str], language: str) -> dict[str, Any]:
    """Proje dosyalarını (göreli yol → metin) analiz et; dosya başına :class:`taint_flow.Analysis`."""
    if language == "go":
        return GoProject(files).analyze()
    if language == "ruby":
        return RubyProject(files).analyze()
    return {}
