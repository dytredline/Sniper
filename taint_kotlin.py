"""Kotlin → Java benzeri metin çevirici (taint_clike hızlı motorunun Kotlin ön ucu).

Saf Python; Kotlin derleyicisi ya da JVM gerektirmez. Amaç tam dilbilgisi değil, Java motorunun (taint_clike) veri
akışı analizi için yeterli, satır numaraları korunmuş Java benzeri metindir (JSP → Java çevirisinin karşılığı):

* Bildirimler: ``fun`` → Java yöntemi (ifade gövdesi ``return``), ``val``/``var`` → yerel/alan bildirimi, birincil
  kurucu parametreleri → alanlar + kurucu, ``object``/``companion object`` → sınıf/üyeler, ek açıklamalar korunur
  (Spring ``@GetMapping`` / ``@RequestParam`` uç nokta ve kaynak tespiti Java motorundaki gibi çalışır).
* Deyimler: satır sonu deyim sonudur (Kotlin kuralı: işleç/nokta ile süren satırlar hariç); ``when`` → ``if``
  zinciri, ``for (x in xs)`` → ``for (var x : xs)``, ``if``/``when``/``try`` ifadeleri → üçlü işleç.
* Dize şablonları (``"a $x ${y.z}"``) → birleştirme; ``?.`` → ``.``, ``!!`` atılır, ``?:`` → PHP ``?:`` biçimi
  (sol ∪ sağ), ``?: return``/``throw`` dalları atılır; büyük harfle başlayan çağrılar kurucu (``new``) sayılır.
* Lambdalar (Ktor/Javalin yönlendirme blokları, ``let``/``also``/``apply``/``run``/``use``, ``map``/``forEach`` …)
  yerinde açılır: gövde, parametresi alıcıya (ya da öğeye) bağlanmış bir blok olarak çağrıdan önce çalıştırılır ve
  son ifadesi geçici bir değişkene yazılır. Böylece işleyici lambdaları içindeki akışlar analiz edilir.
* Çatı kaynak/hedefleri için motorun tanıdığı yardımcılar üretilir: ``__kt_sink("tür", "açıklama", …)``
  (Ktor ``respondText(…, ContentType.Text.Html)``, ``respondRedirect``, kotlinx.html ``unsafe { +x }`` …).
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Any

KT_SUFFIXES = frozenset({".kt"})


@dataclass(slots=True)
class KTok:
    kind: str  # id | str | chr | num | op | nl
    value: Any  # str: parça listesi (str | list[KTok])
    line: int


_OPS = ["===", "!==", "..<", "?.", "?:", "!!", "->", "::", "..", "&&", "||", "==", "!=", "<=", ">=", "+=", "-=",
        "*=", "/=", "%=", "++", "--"]
_TOKEN_RE = re.compile(
    r"(?P<nl>\n)|(?P<ws>[ \t\r\f\v﻿]+)|(?P<lc>//[^\n]*)|(?P<bc>/\*)|(?P<raw>\"\"\")|(?P<dq>\")"
    r"|(?P<chr>'(?:\\u[0-9a-fA-F]{4}|\\.|[^'\\\n])')"
    r"|(?P<num>0[xX][0-9a-fA-F_]+[uUlL]*|0[bB][01_]+[uUlL]*|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?[fFdDlLuU]*|\.\d[\d_]*(?:[eE][+-]?\d+)?[fF]?)"
    r"|(?P<id>[A-Za-z_\u0080-￿][\w\u0080-￿]*)|(?P<bt>`[^`\n]+`)"
    r"|(?P<op>" + "|".join(re.escape(o) for o in _OPS) + r"|[{}()\[\];,.<>=+\-*/%!~?:&|^@#$\\])|(?P<other>.)",
    re.S,
)
_IDENT_START = re.compile(r"[A-Za-z_\u0080-￿]")
_IDENT = re.compile(r"[A-Za-z_\u0080-￿][\w\u0080-￿]*")


def tokenize(text: str, line: int = 1) -> list[KTok]:
    toks: list[KTok] = []
    pos, end = 0, len(text)
    while pos < end:
        m = _TOKEN_RE.match(text, pos)
        if m is None:  # pragma: no cover - "other" her karakteri yakalar
            break
        kind = m.lastgroup
        value = m.group()
        if kind == "nl":
            toks.append(KTok("nl", "\n", line))
            line += 1
            pos = m.end()
            continue
        if kind in ("ws", "lc", "other"):
            pos = m.end()
            continue
        if kind == "bc":
            depth, k = 1, m.end()
            while k < end and depth:
                if text.startswith("/*", k):
                    depth, k = depth + 1, k + 2
                elif text.startswith("*/", k):
                    depth, k = depth - 1, k + 2
                else:
                    if text[k] == "\n":
                        line += 1
                    k += 1
            pos = k
            continue
        if kind in ("dq", "raw"):
            tok, pos, line = _scan_string(text, m.end(), line, raw=kind == "raw")
            toks.append(tok)
            continue
        if kind == "bt":
            toks.append(KTok("id", re.sub(r"\W", "_", value[1:-1]) or "_", line))
        elif kind == "chr":
            toks.append(KTok("chr", value, line))
        elif kind == "num":
            toks.append(KTok("num", value, line))
        elif kind == "id":
            toks.append(KTok("id", value, line))
        else:
            toks.append(KTok("op", value, line))
        pos = m.end()
    return toks


def _scan_string(text: str, pos: int, line: int, raw: bool) -> tuple[KTok, int, int]:
    """``"…"`` / ``\"\"\"…\"\"\"`` dizesi; ``$ad`` ve ``${ifade}`` şablon parçaları alt belirteç listesi olur."""
    start_line = line
    parts: list[Any] = []
    buf: list[str] = []
    end = len(text)
    k = pos
    while k < end:
        c = text[k]
        if raw and text.startswith('"""', k):
            k += 3
            while k < end and text[k] == '"':  # """" …: fazla tırnaklar içeriğe aittir
                buf.append('"')
                k += 1
            break
        if not raw and c == '"':
            k += 1
            break
        if not raw and c == "\n":  # kapanmamış dize
            break
        if not raw and c == "\\" and k + 1 < end:
            nxt = text[k + 1]
            if nxt == "u" and re.match(r"[0-9a-fA-F]{4}", text[k + 2:k + 6]):
                buf.append(chr(int(text[k + 2:k + 6], 16)))
                k += 6
            else:
                buf.append({"n": "\n", "t": "\t", "r": "\r", "b": "\b", "0": "\0"}.get(nxt, nxt))
                k += 2
            continue
        if c == "$" and k + 1 < end and text[k + 1] == "{":
            depth, j = 1, k + 2
            in_str = False
            while j < end and depth:
                ch = text[j]
                if in_str:
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == '"':
                        in_str = False
                elif ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if buf:
                parts.append("".join(buf))
                buf = []
            inner = text[k + 2:j]
            parts.append(tokenize(inner, line) or [])
            line += inner.count("\n")
            k = j + 1
            continue
        if c == "$" and k + 1 < end and _IDENT_START.match(text[k + 1]):
            m = _IDENT.match(text, k + 1)
            if buf:
                parts.append("".join(buf))
                buf = []
            parts.append([KTok("id", m.group(), line)])
            k = m.end()
            continue
        if c == "\n":
            line += 1
        buf.append(c)
        k += 1
    if buf or not parts:
        parts.append("".join(buf))
    return KTok("str", parts, start_line), k, line


def match_pairs(toks: list[KTok]) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    opens = {"(": ")", "[": "]", "{": "}"}
    for i, t in enumerate(toks):
        if t.kind != "op":
            continue
        if t.value in opens:
            stack.append(i)
        elif t.value in (")", "]", "}"):
            # Uyumsuz kapanış: yığından eşleşen açılışı ara (bozuk dosyada ilerleyebilmek için)
            for depth in range(len(stack) - 1, -1, -1):
                if opens[toks[stack[depth]].value] == t.value:
                    o = stack[depth]
                    del stack[depth:]
                    pairs[o] = i
                    pairs[i] = o
                    break
    return pairs


# ---------------------------------------------------------------------------
# Çeviri
# ---------------------------------------------------------------------------
Piece = tuple[str, int]

_MODIFIERS = frozenset({
    "public", "private", "protected", "internal", "open", "final", "abstract", "override", "suspend", "inline",
    "data", "lateinit", "operator", "infix", "tailrec", "external", "sealed", "inner", "const", "enum",
    "annotation", "companion", "reified", "crossinline", "noinline", "vararg", "actual", "expect", "value", "fun",
    "out", "in", "static",
})
_JAVA_MODS = {"private": "private", "protected": "protected", "public": "public", "abstract": "abstract",
              "override": "override"}
_PRIMS = {"Int": "int", "Long": "long", "Short": "short", "Byte": "byte", "Double": "double", "Float": "float",
          "Boolean": "boolean", "Char": "char", "Unit": "void", "Nothing": "void", "Any": "Object",
          "UInt": "int", "ULong": "long", "Number": "Number"}
# Satır sonunda biterse deyim sürer (ikili işleçler, nokta, virgül …)
_CONT_AFTER_OPS = frozenset({".", "?.", ",", "=", "+=", "-=", "*=", "/=", "%=", "+", "-", "*", "/", "%", "&&", "||",
                             "?:", "->", "==", "!=", "===", "!==", "<=", ">=", "..", "..<", "!", "::", ":", "?", "@",
                             "("})
_CONT_AFTER_IDS = frozenset({"as", "is", "in", "if", "else", "when", "try", "while", "for", "do", "val", "var",
                             "fun", "class", "object", "interface", "throw", "catch", "finally"})
# Sonraki satır bunlarla başlarsa deyim sürer
_CONT_BEFORE_OPS = frozenset({".", "?.", "?:", "&&", "||", ")", "]", "::", "!!"})
_CONT_BEFORE_IDS = frozenset({"else", "catch", "finally", "as"})
_KEYWORDS = frozenset({"if", "else", "when", "try", "catch", "finally", "for", "while", "do", "return", "throw",
                       "break", "continue", "val", "var", "fun", "class", "object", "interface", "is", "in", "as",
                       "this", "super", "null", "true", "false", "typealias", "package", "import", "init",
                       "constructor", "by", "where", "get", "set"})
# Alıcıyı döndüren kapsam/koleksiyon işlevleri (lambda sonucu değil alıcı akar)
_RET_RECEIVER = frozenset({"also", "apply", "onEach", "filter", "filterNot", "filterTo", "filterIsInstance",
                           "takeIf", "takeUnless", "sortedBy", "sortedByDescending", "sortedWith", "distinctBy",
                           "forEach", "forEachIndexed", "onSuccess", "onFailure", "ifEmpty", "ifBlank", "takeWhile",
                           "dropWhile", "filterIndexed", "partition", "groupBy", "first", "firstOrNull", "last",
                           "lastOrNull", "find", "findLast", "single", "singleOrNull", "minByOrNull", "maxByOrNull",
                           "minBy", "maxBy", "chunked", "windowed",
                           # kotlinx.coroutines Flow / Reactor: öğe lambdaya bağlanır (gRPC akış istekleri, WebFlux)
                           "collect", "collectLatest", "collectIndexed", "doOnNext", "subscribe"})
# Lambda sonucunu döndüren işlevler (alıcı ya da öğe lambdaya bağlanır)
_RET_LAMBDA = frozenset({"let", "run", "use", "map", "mapNotNull", "mapIndexed", "mapIndexedNotNull", "flatMap",
                         "associate", "associateBy", "associateWith", "fold", "reduce", "sumOf", "mapValues",
                         "mapKeys", "flatten", "getOrElse", "getOrPut", "fold", "runCatching", "mapCatching",
                         "map", "with", "also", "transform", "flatMapConcat", "flatMapMerge", "flatMapLatest",
                         "flatMapMany", "concatMap", "switchMap"})
_BOOL_LAMBDA = frozenset({"any", "all", "none", "count", "contains"})
_HTML_KTOR = re.compile(r"\bHtml\b|text/html")


class _Ctx:
    """Çeviri bağlamı: lambda sonucu değişkeni, ``it`` adı, örtük alıcı (buildString)."""

    __slots__ = ("result", "it", "sb", "unsafe")

    def __init__(self, result: str | None = None, it: str | None = None, sb: str | None = None,
                 unsafe: bool = False) -> None:
        self.result = result
        self.it = it
        self.sb = sb
        self.unsafe = unsafe

    def child(self, **kw: Any) -> "_Ctx":
        c = _Ctx(self.result, self.it, self.sb, self.unsafe)
        for k, v in kw.items():
            setattr(c, k, v)
        return c


class Translator:
    def __init__(self, text: str) -> None:
        self.t = tokenize(text)
        self.p = match_pairs(self.t)
        self.n = len(self.t)
        self.counter = 0
        self.max_line = text.count("\n") + 1
        # Bir islev govdesindeki degistirilemez ve tam adli ``val f = ::method``
        # baglari. Dinamik/bound reference ve ``var`` degerleri bilerek girmez.
        self.callable_refs: dict[str, str] = {}

    # -- yardımcılar --------------------------------------------------------
    def tmp(self, prefix: str) -> str:
        self.counter += 1
        return f"__{prefix}{self.counter}"

    def nn(self, i: int, j: int) -> int:
        """``i``'den itibaren satır sonu olmayan ilk belirteç (yoksa j)."""
        while i < j and self.t[i].kind == "nl":
            i += 1
        return i

    def is_op(self, i: int, *values: str) -> bool:
        return 0 <= i < self.n and self.t[i].kind == "op" and self.t[i].value in values

    def is_id(self, i: int, *values: str) -> bool:
        return 0 <= i < self.n and self.t[i].kind == "id" and (not values or self.t[i].value in values)

    def line(self, i: int) -> int:
        if i < self.n:
            return self.t[i].line
        return self.t[-1].line if self.t else 1

    def atom(self, tok: KTok) -> list[Piece]:
        """Tek belirteç → Java parçası (ek açıklama argümanları için; şablonlar düz metne indirgenir)."""
        if tok.kind == "str":
            return [(_jstr("".join(p for p in tok.value if isinstance(p, str))), tok.line)]
        if tok.kind == "op" and tok.value in ("?.", "!!"):
            return [(".", tok.line)] if tok.value == "?." else []
        return [(str(tok.value), tok.line)]

    def close(self, i: int) -> int:
        """Açılış belirtecinin eşi (yoksa i)."""
        return self.p.get(i, i)

    def stmt_end(self, i: int, j: int) -> int:
        """Basit deyimin sonu (``;`` ya da sonlandıran satır sonu; dışlayıcı)."""
        k = i
        last = -1
        while k < j:
            t = self.t[k]
            if t.kind == "nl":
                if last >= 0 and not self._continues(last, k, j):
                    return k
                k += 1
                continue
            if t.kind == "op":
                if t.value == ";":
                    return k
                if t.value in ("(", "[", "{") and k in self.p and self.p[k] < j:
                    last = self.p[k]
                    k = self.p[k] + 1
                    continue
                if t.value in (")", "]", "}"):
                    return k
            last = k
            k += 1
        return j

    def _continues(self, last: int, nl: int, j: int) -> bool:
        lt = self.t[last]
        if lt.kind == "op" and lt.value in _CONT_AFTER_OPS:
            return True
        if lt.kind == "id" and lt.value in _CONT_AFTER_IDS:
            return True
        nx = self.nn(nl, j)
        if nx >= j:
            return False
        t = self.t[nx]
        if t.kind == "op" and t.value in _CONT_BEFORE_OPS:
            return True
        if t.kind == "id" and t.value in _CONT_BEFORE_IDS:
            return True
        return False

    # -- giriş ----------------------------------------------------------------
    def translate(self) -> str:
        pieces = self.decls(0, self.n, None, _Ctx())
        # Sıra korunur; satır numarası geri gidemez (öne alınan lambda gövdesinden sonra gelen çağrı parçaları
        # gövdenin son satırına düşer). Hedef/kaynak belirteçleri kendi satırlarında kalır.
        out: list[str] = []
        current = 1
        row: list[str] = []
        for text, line in pieces:
            if line > current:
                out.append(" ".join(row))
                out.extend([""] * (line - current - 1))
                row = []
                current = line
            row.append(text)
        out.append(" ".join(row))
        while len(out) < self.max_line:
            out.append("")
        return "\n".join(out)

    # -- bildirimler ------------------------------------------------------------
    def _annotation(self, i: int, j: int) -> tuple[list[Piece], int]:
        """``@Ad``, ``@Ad(…)``, ``@field:Ad``, ``@[A B]`` → Java ek açıklaması."""
        line = self.line(i)
        k = i + 1
        if self.is_op(k, "[") and k in self.p:  # @[A B]
            out: list[Piece] = []
            for x in range(k + 1, self.p[k]):
                if self.t[x].kind == "id":
                    out += [("@", line), (self.t[x].value, line)]
            return out, self.p[k] + 1
        if self.is_id(k) and self.is_op(k + 1, ":") and not self.is_op(k + 1, "::"):
            if self.t[k].value == "file":  # dosya ek açıklaması
                k += 2
                while k < j and (self.t[k].kind == "id" or self.is_op(k, ".")):
                    k += 1
                if self.is_op(k, "(") and k in self.p:
                    k = self.p[k] + 1
                return [], k
            k += 2  # @field: / @get: / @param:
        names: list[str] = []
        while k < j and self.t[k].kind == "id":
            names.append(self.t[k].value)
            if self.is_op(k + 1, "."):
                k += 2
                continue
            k += 1
            break
        if not names:
            return [], i + 1
        out = [("@", line), (".".join(names), line)]
        if self.is_op(k, "<") :  # @Ann<T>
            g = self._generic_end(k, j)
            if g:
                k = g
        if self.is_op(k, "(") and k in self.p:
            c = self.p[k]
            out.append(("(", line))
            for x in range(k + 1, c):
                tok = self.t[x]
                if tok.kind == "nl":
                    continue
                if tok.kind == "op" and tok.value == "[":
                    out.append(("{", tok.line))
                elif tok.kind == "op" and tok.value == "]":
                    out.append(("}", tok.line))
                else:
                    out += self.atom(tok)
            out.append((")", self.line(c)))
            k = c + 1
        return out, k

    def _generic_end(self, i: int, j: int) -> int | None:
        """``<`` … ``>`` tür argümanları (yalnız tür belirteçleri) → sonraki indis; değilse None."""
        if not self.is_op(i, "<"):
            return None
        depth = 0
        k = i
        while k < j:
            t = self.t[k]
            if t.kind == "op":
                if t.value == "<":
                    depth += 1
                elif t.value == ">":
                    depth -= 1
                    if depth == 0:
                        return k + 1
                elif t.value in (",", ".", "?", "*", ":", "->"):
                    pass
                elif t.value == "(" and k in self.p:
                    k = self.p[k] + 1
                    continue
                elif t.value == "@":
                    pass
                else:
                    return None
            elif t.kind == "id":
                pass
            elif t.kind == "nl":
                pass
            else:
                return None
            k += 1
        return None

    def jtype(self, i: int, j: int) -> str:
        """Kotlin tür belirteçleri [i, j) → Java tür metni."""
        toks = [t for t in self.t[i:j] if t.kind != "nl"]
        while toks and toks[0].kind == "op" and toks[0].value == "@":  # tür ek açıklaması
            toks = toks[2:]
        while toks and toks[0].kind == "id" and toks[0].value in ("suspend", "out", "in"):
            toks = toks[1:]
        if not toks:
            return "Object"
        if toks[0].kind == "op" and toks[0].value == "(":
            return "Object"  # işlev türü / parantezli tür
        if any(t.kind == "op" and t.value == "->" for t in toks):
            return "Object"
        names: list[str] = []
        k = 0
        while k < len(toks) and toks[k].kind == "id":
            names.append(toks[k].value)
            if k + 1 < len(toks) and toks[k + 1].kind == "op" and toks[k + 1].value == ".":
                k += 2
                continue
            k += 1
            break
        if not names:
            return "Object"
        base = names[-1] if len(names) == 1 else ".".join(names)
        simple = names[-1]
        if simple in _PRIMS and len(names) == 1:
            base = _PRIMS[simple]
        args: list[str] = []
        if k < len(toks) and toks[k].kind == "op" and toks[k].value == "<":
            depth, start = 0, k + 1
            parts: list[list[KTok]] = [[]]
            for x in range(k, len(toks)):
                t = toks[x]
                if t.kind == "op" and t.value == "<":
                    depth += 1
                    if depth == 1:
                        continue
                elif t.kind == "op" and t.value == ">":
                    depth -= 1
                    if depth == 0:
                        break
                if depth == 1 and t.kind == "op" and t.value == ",":
                    parts.append([])
                    continue
                parts[-1].append(t)
            del start
            for part in parts:
                sub = Translator.__new__(Translator)
                sub.t, sub.p, sub.n = part, match_pairs(part), len(part)
                at = sub.jtype(0, len(part)) if part else "Object"
                args.append({"int": "Integer", "long": "Long", "boolean": "Boolean", "double": "Double",
                             "float": "Float", "char": "Character", "short": "Short", "byte": "Byte",
                             "void": "Object"}.get(at, at) if not (part and part[0].kind == "op" and part[0].value == "*") else "Object")
        if simple == "Array" and args:
            return args[0] + "[]"
        if args:
            return f"{base}<{', '.join(args)}>"
        return base

    def _type_end(self, i: int, j: int) -> int:
        """Tür ifadesinin sonu (``=``, ``{``, ``,``, ``)``, satır sonu, ``by``, ``where`` …)."""
        k = i
        while k < j:
            t = self.t[k]
            if t.kind == "nl":
                # Tür satır sonuyla biter (devam işleci yoksa)
                if k > i and not (self.t[k - 1].kind == "op" and self.t[k - 1].value in (".", "<", ",", "->", "?")):
                    return k
                k += 1
                continue
            if t.kind == "op":
                if t.value == "(" and k in self.p:
                    k = self.p[k] + 1
                    continue
                if t.value == "<":
                    g = self._generic_end(k, j)
                    if g:
                        k = g
                        continue
                    return k
                if t.value in ("=", "{", ",", ")", ";", "}", "]"):
                    return k
            elif t.kind == "id" and t.value in ("by", "where", "get", "set") and k > i:
                return k
            k += 1
        return j

    def decls(self, i: int, j: int, cls: str | None, ctx: _Ctx) -> list[Piece]:
        """Dosya ya da sınıf gövdesindeki bildirimler."""
        out: list[Piece] = []
        guard = 0
        while i < j and guard < 200_000:
            guard += 1
            i = self.nn(i, j)
            if i >= j:
                break
            t = self.t[i]
            if t.kind == "op" and t.value == ";":
                i += 1
                continue
            if t.kind == "id" and t.value in ("package", "import"):
                k = i
                while k < j and self.t[k].kind != "nl" and not self.is_op(k, ";"):
                    k += 1
                i = k + 1
                continue
            pieces, ni = self.decl(i, j, cls, ctx)
            out += pieces
            i = max(ni, i + 1)
        return out

    def _modifiers(self, i: int, j: int) -> tuple[list[Piece], set[str], int]:
        anns: list[Piece] = []
        mods: set[str] = set()
        while i < j:
            i = self.nn(i, j)
            if i >= j:
                break
            if self.is_op(i, "@"):
                a, i = self._annotation(i, j)
                anns += a
                continue
            if self.is_id(i) and self.t[i].value in _MODIFIERS and self.t[i].value != "fun" and not (
                    self.t[i].value in ("enum", "annotation", "data", "value", "sealed", "inner", "open", "abstract",
                                        "companion", "inline", "out", "in", "const", "lateinit", "override",
                                        "private", "public", "protected", "internal", "suspend", "operator",
                                        "infix", "external", "tailrec", "actual", "expect", "final", "vararg",
                                        "crossinline", "noinline", "reified", "static")
                    and self._modifier_is_name(i, j)):
                mods.add(self.t[i].value)
                i += 1
                continue
            break
        return anns, mods, i

    def _modifier_is_name(self, i: int, j: int) -> bool:
        """``value = 3`` / ``data.x`` gibi değiştirici sözcüğünün ad olarak kullanımı."""
        k = i + 1
        if k >= j:
            return True
        t = self.t[k]
        return t.kind == "op" and t.value in ("=", ".", "?.", "(", ")", ",", ":", "[", "+=", "-=", "!!", "::")

    def decl(self, i: int, j: int, cls: str | None, ctx: _Ctx) -> tuple[list[Piece], int]:
        anns, mods, k = self._modifiers(i, j)
        if k >= j:
            return anns, k
        t = self.t[k]
        jm = [(_JAVA_MODS[m], self.line(k)) for m in sorted(mods) if m in _JAVA_MODS]
        if t.kind == "id":
            v = t.value
            if v == "object" and "companion" in mods:
                return self.class_decl(k, j, anns, jm, mods, ctx, companion=True)
            if v in ("class", "interface") or (v == "object" and not self.is_op(self.nn(k + 1, j), ":")):
                if "annotation" in mods:
                    return [], self._skip_decl(k, j)
                return self.class_decl(k, j, anns, jm, mods, ctx)
            if v == "fun" and self.is_id(k + 1, "interface"):  # fun interface X { … }
                return self.class_decl(k + 1, j, anns, jm, mods, ctx)
            if v == "fun":
                return self.fun_decl(k, j, anns, jm, cls, ctx)
            if v in ("val", "var"):
                return self.prop_decl(k, j, anns, jm, cls, ctx)
            if v == "init" and self.is_op(self.nn(k + 1, j), "{"):
                b = self.nn(k + 1, j)
                name = self.tmp("init")
                line = self.line(k)
                body = self.block_body(b + 1, self.close(b), ctx.child(result=None))
                return [("void", line), (name, line), ("(", line), (")", line), ("{", line)] + body + \
                    [("}", self.line(self.close(b)))], self.close(b) + 1
            if v == "constructor" and cls:
                return self.ctor_decl(k, j, anns, jm, cls, ctx)
            if v == "typealias":
                return [], self.stmt_end(k, j) + 1
        # Bilinmeyen üst düzey içerik (betik deyimi vb.): deyim olarak atla
        if cls is None and t.kind != "op":
            return [], self.stmt_end(k, j) + 1
        if t.kind == "op" and t.value == "{" and k in self.p:
            return [], self.p[k] + 1
        return [], self.stmt_end(k, j) + 1

    def _skip_decl(self, k: int, j: int) -> int:
        e = k
        while e < j and not self.is_op(e, "{"):
            if self.t[e].kind == "nl" and not self._continues(e - 1, e, j):
                return e
            if self.is_op(e, "(") and e in self.p:
                e = self.p[e]
            e += 1
        return self.close(e) + 1 if e < j else j

    def class_decl(self, k: int, j: int, anns: list[Piece], jm: list[Piece], mods: set[str], ctx: _Ctx,
                   companion: bool = False) -> tuple[list[Piece], int]:
        kind = self.t[k].value
        line = self.line(k)
        i = k + 1
        name = None
        if self.is_id(i) and self.t[i].value not in ("by",):
            name = self.t[i].value
            i += 1
        if name is None:
            name = self.tmp("Companion" if companion else "Obj")
        if self.is_op(i, "<"):
            g = self._generic_end(i, j)
            if g:
                i = g
        # birincil kurucu
        i2 = self.nn(i, j)
        ctor_params: list[tuple[str, str, list[Piece], bool, int]] = []  # (ad, tür, ek açıklamalar, alan mı, satır)
        while self.is_id(i2) and self.t[i2].value in _MODIFIERS | {"constructor"}:
            i2 += 1
        if self.is_op(i2, "@"):
            while self.is_op(i2, "@"):
                _a, i2 = self._annotation(i2, j)
                i2 = self.nn(i2, j)
            while self.is_id(i2) and self.t[i2].value in _MODIFIERS:
                i2 += 1
            if self.is_id(i2, "constructor"):
                i2 += 1
        elif self.is_id(i2, "constructor"):
            i2 += 1
        if self.is_op(i2, "(") and i2 in self.p:
            ctor_params = self.params(i2 + 1, self.p[i2], ctx, fields=True)
            i = self.p[i2] + 1
        # üst türler
        supers: list[str] = []
        i3 = self.nn(i, j)
        if self.is_op(i3, ":"):
            x = i3 + 1
            while x < j:
                x = self.nn(x, j)
                if x >= j or self.is_op(x, "{") or self.is_id(x, "where"):
                    break
                if self.t[x].kind == "nl":
                    break
                if self.t[x].kind == "id":
                    ns = [self.t[x].value]
                    while self.is_op(x + 1, ".") and self.is_id(x + 2):
                        ns.append(self.t[x + 2].value)
                        x += 2
                    supers.append(ns[-1])
                    x += 1
                    if self.is_op(x, "<"):
                        g = self._generic_end(x, j)
                        x = g or x + 1
                    if self.is_op(x, "(") and x in self.p:
                        x = self.p[x] + 1
                    if self.is_id(x, "by"):  # arayüz yetkilendirmesi: I by temsilci
                        x += 1
                        while x < j and not self.is_op(x, ",", "{") and self.t[x].kind != "nl":
                            if self.is_op(x, "(", "[") and x in self.p:
                                x = self.p[x]
                            x += 1
                    continue
                if self.is_op(x, ","):
                    x += 1
                    continue
                if self.is_op(x, "{"):
                    break
                if self.t[x].kind == "nl":
                    break
                x += 1
            i = x
        i4 = self.nn(i, j)
        if self.is_id(i4, "where"):
            while i4 < j and not self.is_op(i4, "{") and self.t[i4].kind != "nl":
                i4 += 1
            i4 = self.nn(i4, j) if self.is_op(self.nn(i4, j), "{") else i4
        body_open = i4 if self.is_op(i4, "{") and i4 in self.p else None
        out: list[Piece] = []
        if not companion:
            out += anns + jm
            out += [("class" if kind != "interface" else "interface", line), (name, line)]
            if supers:
                out += [("extends", line)] + [p for s in supers for p in ((s, line), (",", line))][:-1]
            out.append(("{", line))
        else:
            out += [("{", line)] if False else []
        # alanlar ve kurucu
        for pname, ptype, panns, is_field, pline in ctor_params:
            if is_field:
                out += [(ptype, pline), (pname, pline), (";", pline)]
        if ctor_params and not companion:
            out += [(name, line), ("(", line)]
            for n_, (pname, ptype, panns, _f, pline) in enumerate(ctor_params):
                if n_:
                    out.append((",", pline))
                out += panns + [(ptype, pline), (pname, pline)]
            out += [(")", line), ("{", line)]
            for pname, ptype, panns, is_field, pline in ctor_params:
                if is_field:
                    out += [("this", pline), (".", pline), (pname, pline), ("=", pline), (pname, pline), (";", pline)]
            out.append(("}", line))
        end = self.p[body_open] + 1 if body_open is not None else max(i4, k + 1)
        if body_open is not None:
            body_close = self.p[body_open]
            start = body_open + 1
            if kind == "class" and "enum" in mods:
                start = self._enum_entries_end(start, body_close)
            out += self.decls(start, body_close, name, ctx)
        if not companion:
            out.append(("}", self.line(end - 1) if body_open is not None else line))
        return out, end

    def _enum_entries_end(self, i: int, j: int) -> int:
        k = i
        while k < j:
            if self.is_op(k, ";"):
                return k + 1
            if self.is_op(k, "(", "{", "[") and k in self.p:
                k = self.p[k] + 1
                continue
            k += 1
        return j

    def params(self, i: int, j: int, ctx: _Ctx, fields: bool = False) -> list[tuple[str, str, list[Piece], bool, int]]:
        """``[@Ek] [val|var|vararg] ad: Tür [= varsayılan]`` listesi."""
        out = []
        for a, b in self.split(i, j, ","):
            a = self.nn(a, b)
            anns: list[Piece] = []
            is_field = False
            vararg = False
            while a < b:
                a = self.nn(a, b)
                if self.is_op(a, "@"):
                    an, a = self._annotation(a, b)
                    anns += an
                    continue
                if self.is_id(a) and self.t[a].value in ("val", "var"):
                    is_field = True
                    a += 1
                    continue
                if self.is_id(a) and self.t[a].value in _MODIFIERS and not self.is_op(a + 1, ":"):
                    vararg = vararg or self.t[a].value == "vararg"
                    a += 1
                    continue
                break
            if not self.is_id(a):
                continue
            name = self.t[a].value
            ptype = "Object"
            if self.is_op(a + 1, ":"):
                te = self._type_end(a + 2, b)
                ptype = self.jtype(a + 2, te)
            if vararg:
                ptype += "..."
            out.append((name, ptype, anns, is_field and fields, self.line(a)))
        return out

    def split(self, i: int, j: int, sep: str) -> list[tuple[int, int]]:
        out = []
        start = k = i
        while k < j:
            t = self.t[k]
            if t.kind == "op":
                if t.value in ("(", "[", "{") and k in self.p and self.p[k] < j:
                    k = self.p[k] + 1
                    continue
                if t.value == "<":
                    g = self._generic_end(k, j)
                    if g:
                        k = g
                        continue
                if t.value == sep:
                    out.append((start, k))
                    start = k + 1
            k += 1
        if start < j:
            out.append((start, j))
        return [(a, b) for a, b in out if self.nn(a, b) < b]

    def fun_decl(self, k: int, j: int, anns: list[Piece], jm: list[Piece], cls: str | None,
                 ctx: _Ctx) -> tuple[list[Piece], int]:
        line = self.line(k)
        i = k + 1
        if self.is_op(i, "<"):
            g = self._generic_end(i, j)
            i = g or i + 1
        # alıcı türü ve ad: Recv.ad / ad
        name_idx = None
        x = i
        while x < j and not self.is_op(x, "("):
            if self.is_id(x):
                name_idx = x
            elif self.is_op(x, "<"):
                g = self._generic_end(x, j)
                if g:
                    x = g
                    continue
            elif not self.is_op(x, ".", "?"):
                break
            x += 1
        if name_idx is None or not self.is_op(x, "(") or x not in self.p:
            return [], self.stmt_end(k, j) + 1
        name = self.t[name_idx].value
        pclose = self.p[x]
        params = self.params(x + 1, pclose, ctx)
        y = pclose + 1
        ret = None
        y2 = self.nn(y, j)
        if self.is_op(y2, ":"):
            te = self._type_end(y2 + 1, j)
            ret = self.jtype(y2 + 1, te)
            if ret == "Object":  # Kotlin Any: nesne (JSON) dönüşü; dize dönüşü kuralına girmez
                ret = "Any"
            y = te
        y = self.nn(y, j)
        if self.is_id(y, "where"):
            while y < j and not self.is_op(y, "{", "="):
                y += 1
        head: list[Piece] = anns + jm
        sig = [(name, self.line(name_idx)), ("(", line)]
        for n_, (pname, ptype, panns, _f, pline) in enumerate(params):
            if n_:
                sig.append((",", pline))
            sig += panns + [(ptype, pline), (pname, pline)]
        sig.append((")", self.line(pclose)))
        fctx = ctx.child(result=None, it=None, sb=None, unsafe=False)
        if self.is_op(y, "{") and y in self.p:
            c = self.p[y]
            outer_refs = self.callable_refs
            self.callable_refs = {}
            try:
                body = self.block_body(y + 1, c, fctx)
            finally:
                self.callable_refs = outer_refs
            return head + [(ret or "void", line)] + sig + [("{", self.line(y))] + body + [("}", self.line(c))], c + 1
        if self.is_op(y, "="):
            e = self.stmt_end(y + 1, j)
            expr, pre = self.expr(y + 1, e, fctx)
            ln = self.line(y)
            if ret is None:  # çıkarımlı tür: dize/şablon ifadesi → String, değilse Any
                ret = "String" if self.t[self.nn(y + 1, e)].kind == "str" else "Any"
            return head + [(ret, line)] + sig + [("{", ln)] + pre + [("return", ln)] + expr + \
                [(";", self.line(e - 1)), ("}", self.line(e - 1))], e
        # gövdesiz (soyut / arayüz)
        return head + [(ret or "void", line)] + sig + [(";", line)], y

    def ctor_decl(self, k: int, j: int, anns: list[Piece], jm: list[Piece], cls: str,
                  ctx: _Ctx) -> tuple[list[Piece], int]:
        line = self.line(k)
        x = k + 1
        if not self.is_op(x, "(") or x not in self.p:
            return [], self.stmt_end(k, j) + 1
        params = self.params(x + 1, self.p[x], ctx)
        y = self.nn(self.p[x] + 1, j)
        if self.is_op(y, ":"):  # : this(…) / super(…)
            y += 1
            while y < j and not self.is_op(y, "{") and self.t[y].kind != "nl":
                if self.is_op(y, "(") and y in self.p:
                    y = self.p[y]
                y += 1
            y = self.nn(y, j)
        sig = [(cls, line), ("(", line)]
        for n_, (pname, ptype, panns, _f, pline) in enumerate(params):
            if n_:
                sig.append((",", pline))
            sig += panns + [(ptype, pline), (pname, pline)]
        sig.append((")", line))
        if self.is_op(y, "{") and y in self.p:
            c = self.p[y]
            return anns + jm + sig + [("{", line)] + self.block_body(y + 1, c, ctx.child(result=None)) + \
                [("}", self.line(c))], c + 1
        return anns + jm + sig + [("{", line), ("}", line)], y

    def prop_decl(self, k: int, j: int, anns: list[Piece], jm: list[Piece], cls: str | None,
                  ctx: _Ctx) -> tuple[list[Piece], int]:
        """Sınıf/dosya düzeyi özellik → alan (yalnız sınıf içinde; başlatıcı lambdası açılmaz)."""
        line = self.line(k)
        e = self.stmt_end(k, j)
        # get()/set() erişimcileri sonraki satırlarda olabilir: atla
        nxt = self.nn(e, j)
        while nxt < j and (self.is_id(nxt, "get", "set") or (
                self.is_id(nxt, "private", "public", "protected", "internal") and self.is_id(nxt + 1, "get", "set"))):
            e2 = self.stmt_end(nxt, j)
            if e2 <= nxt:
                break
            e = e2
            nxt = self.nn(e, j)
        if cls is None:
            return [], e + 1 if self.is_op(e, ";") else e
        x = k + 1
        if self.is_op(x, "<"):
            x = self._generic_end(x, j) or x + 1
        # alıcı türlü uzantı özelliği: atla
        if not self.is_id(x):
            return [], e
        if self.is_op(x + 1, "."):
            return [], e
        name = self.t[x].value
        ptype = "Object"
        y = x + 1
        if self.is_op(y, ":"):
            te = self._type_end(y + 1, e)
            ptype = self.jtype(y + 1, te)
            y = te
        out = anns + jm + [(ptype, line), (name, self.line(x))]
        if self.is_op(y, "=") and y + 1 < e:
            expr, pre = self.expr(y + 1, e, ctx.child(result=None))
            if not pre:
                out += [("=", self.line(y))] + expr
        out.append((";", self.line(e - 1)))
        return out, e

    # -- deyimler ----------------------------------------------------------------
    def block_body(self, i: int, j: int, ctx: _Ctx, want_value: bool = False) -> list[Piece]:
        """Blok içi deyimler; ``want_value`` ise son ifade ``ctx.result`` değişkenine yazılır."""
        outer_refs = self.callable_refs
        self.callable_refs = dict(outer_refs)
        try:
            return self._block_body(i, j, ctx, want_value)
        finally:
            self.callable_refs = outer_refs

    def _block_body(self, i: int, j: int, ctx: _Ctx, want_value: bool = False) -> list[Piece]:
        stmts: list[tuple[int, int]] = []
        k = i
        guard = 0
        while k < j and guard < 100_000:
            guard += 1
            k = self.nn(k, j)
            if k >= j:
                break
            if self.is_op(k, ";"):
                k += 1
                continue
            e = self.stmt_span(k, j)
            stmts.append((k, e))
            k = max(e, k + 1)
        out: list[Piece] = []
        for n_, (a, b) in enumerate(stmts):
            last = want_value and n_ == len(stmts) - 1
            out += self.stmt(a, b, ctx, last)
        return out

    def stmt_span(self, i: int, j: int) -> int:
        """Deyimin [i, e) aralığı (denetim deyimleri gövdeleriyle birlikte)."""
        k = i
        # ek açıklama / etiket
        while True:
            k = self.nn(k, j)
            if self.is_op(k, "@") :
                _a, k = self._annotation(k, j)
                continue
            if self.is_id(k) and self.is_op(k + 1, "@") and k + 2 < j and (
                    self.is_id(k + 2, "for", "while", "do") or self.is_op(k + 2, "{")):
                k += 2
                continue
            break
        if k >= j:
            return j
        t = self.t[k]
        if t.kind == "id":
            v = t.value
            if v == "if":
                return self._if_span(k, j)
            if v in ("for", "while") and self.is_op(k + 1, "(") and (k + 1) in self.p:
                b = self.nn(self.p[k + 1] + 1, j)
                if b >= j:
                    return b
                return self.stmt_span(b, j) if not self.is_op(b, ";") else b + 1
            if v == "do":
                b = self.nn(k + 1, j)
                e = self.stmt_span(b, j)
                w = self.nn(e, j)
                if self.is_id(w, "while") and self.is_op(w + 1, "(") and (w + 1) in self.p:
                    return self.p[w + 1] + 1
                return e
            if v == "try":
                return self._try_span(k, j)
            if v == "when":
                x = k + 1
                if self.is_op(x, "(") and x in self.p:
                    x = self.p[x] + 1
                x = self.nn(x, j)
                if self.is_op(x, "{") and x in self.p:
                    return self._expr_tail(self.p[x] + 1, j)
            if v in ("fun", "class", "interface", "object") or (v in ("data", "enum", "private", "inline", "sealed")
                                                                 and self.is_id(k + 1)):
                if v in ("fun",) or self.is_id(k + 1):
                    x = k
                    while x < j and not self.is_op(x, "{", "="):
                        if self.t[x].kind == "nl" and not self._continues(x - 1, x, j):
                            return x
                        if self.is_op(x, "(") and x in self.p:
                            x = self.p[x]
                        x += 1
                    if self.is_op(x, "{") and x in self.p:
                        return self.p[x] + 1
                    return self.stmt_end(x + 1, j)
        if t.kind == "op" and t.value == "{" and k in self.p:
            return self._expr_tail(self.p[k] + 1, j)
        return self.stmt_end(i, j)

    def _expr_tail(self, k: int, j: int) -> int:
        """Blok/lambda sonrası aynı satırda süren ifade (``.let {…}`` vb.) varsa deyimin sonu."""
        x = k
        while x < j and self.t[x].kind != "nl":
            if self.is_op(x, ";", "}"):
                return x
            if self.is_op(x, "(", "[", "{") and x in self.p:
                x = self.p[x] + 1
                continue
            x += 1
        if x < j and self.t[x].kind == "nl" and x > k and self._continues(x - 1, x, j):
            return self.stmt_end(x, j)
        nx = self.nn(x, j)
        if x < j and nx < j and self.t[nx].kind == "op" and self.t[nx].value in _CONT_BEFORE_OPS - {")", "]"}:
            return self.stmt_end(nx, j)
        return x

    def _body_span(self, i: int, j: int) -> int:
        b = self.nn(i, j)
        if b >= j:
            return b
        if self.is_op(b, "{") and b in self.p:
            return self.p[b] + 1
        return self.stmt_span(b, j)

    def _if_span(self, k: int, j: int) -> int:
        if not (self.is_op(k + 1, "(") and (k + 1) in self.p):
            return self.stmt_end(k, j)
        e = self._body_span(self.p[k + 1] + 1, j)
        x = self.nn(e, j)
        if self.is_op(x, ";"):
            y = self.nn(x + 1, j)
            if self.is_id(y, "else"):
                x = y
        if self.is_id(x, "else"):
            y = self.nn(x + 1, j)
            if self.is_id(y, "if"):
                return self._if_span(y, j)
            return self._body_span(x + 1, j)
        return self._expr_tail(e, j) if e < j and not self.is_op(e - 1, "}") else e

    def _try_span(self, k: int, j: int) -> int:
        e = self._body_span(k + 1, j)
        while True:
            x = self.nn(e, j)
            if self.is_id(x, "catch") and self.is_op(x + 1, "(") and (x + 1) in self.p:
                e = self._body_span(self.p[x + 1] + 1, j)
                continue
            if self.is_id(x, "finally"):
                e = self._body_span(x + 1, j)
                continue
            return e

    def body_stmt(self, i: int, j: int, ctx: _Ctx) -> list[Piece]:
        """Denetim deyimi gövdesi: blok ya da tek deyim → Java bloğu."""
        b = self.nn(i, j)
        line = self.line(b)
        if b >= j:
            return [("{", line), ("}", line)]
        if self.is_op(b, "{") and b in self.p:
            c = self.p[b]
            return [("{", line)] + self.block_body(b + 1, c, ctx) + [("}", self.line(c))]
        return [("{", line)] + self.stmt(b, j, ctx, False) + [("}", self.line(j - 1))]

    def stmt(self, i: int, j: int, ctx: _Ctx, last: bool) -> list[Piece]:
        i = self.nn(i, j)
        # ek açıklamalar / etiketler
        while i < j:
            if self.is_op(i, "@"):
                _a, i = self._annotation(i, j)
                i = self.nn(i, j)
                continue
            if self.is_id(i) and self.is_op(i + 1, "@") and i + 2 < j and (
                    self.is_id(i + 2, "for", "while", "do") or self.is_op(i + 2, "{")):
                i += 2
                continue
            break
        if i >= j:
            return []
        t = self.t[i]
        line = t.line
        if t.kind == "id":
            v = t.value
            if v == "if" and not last:
                return self.if_stmt(i, j, ctx)
            if v == "when" and not last:
                return self.when_stmt(i, j, ctx)
            if v == "try" and not last:
                return self.try_stmt(i, j, ctx)
            if v == "for" and self.is_op(i + 1, "(") and (i + 1) in self.p:
                return self.for_stmt(i, j, ctx)
            if v == "while" and self.is_op(i + 1, "(") and (i + 1) in self.p:
                c = self.p[i + 1]
                cond, pre = self.expr(i + 2, c, ctx)
                return pre + [("while", line), ("(", line)] + cond + [(")", self.line(c))] + \
                    self.body_stmt(c + 1, j, ctx)
            if v == "do":
                b = self.nn(i + 1, j)
                e = self._body_span(b, j)
                body = self.body_stmt(b, e, ctx)
                w = self.nn(e, j)
                out = [("do", line)] + body
                if self.is_id(w, "while") and self.is_op(w + 1, "(") and (w + 1) in self.p:
                    c = self.p[w + 1]
                    cond, pre = self.expr(w + 2, c, ctx)
                    out = pre + out + [("while", self.line(w)), ("(", self.line(w))] + cond + \
                        [(")", self.line(c)), (";", self.line(c))]
                else:
                    out += [("while", line), ("(", line), ("false", line), (")", line), (";", line)]
                return out
            if v in ("return", "throw"):
                x = i + 1
                label = False
                if v == "return" and self.is_op(x, "@") and self.is_id(x + 1):
                    x += 2
                    label = True
                e = j
                if x >= e or self.t[x].kind == "nl":
                    if label and ctx.result:
                        return []
                    return [(v, line), (";", line)]
                expr, pre = self.expr(x, e, ctx)
                if label and ctx.result:
                    return pre + [(ctx.result, line), ("=", line)] + expr + [(";", self.line(e - 1))]
                return pre + [(v, line)] + expr + [(";", self.line(e - 1))]
            if v in ("break", "continue"):
                return [(v, line), (";", line)]
            if v in ("val", "var"):
                return self.local_decl(i, j, ctx)
            if v == "fun":
                pieces, _e = self.fun_decl(i, j, [], [], None, ctx)
                return pieces
            if v in ("class", "interface", "object", "data", "enum", "sealed", "inline") and (
                    self.is_id(i + 1) or v in ("class", "interface")):
                pieces, _e = self.decl(i, j, None, ctx)
                return pieces
        if t.kind == "op" and t.value == "+" and ctx.unsafe:
            expr, pre = self.expr(i + 1, j, ctx)  # kotlinx.html unsafe { +metin }: kaçışsız HTML
            return pre + [("__kt_sink", line), ("(", line), ('"html"', line), (",", line),
                          (_jstr("kotlinx.html unsafe { +… }"), line), (",", line)] + expr + [(")", line), (";", line)]
        if t.kind == "op" and t.value == "{" and i in self.p and self.p[i] + 1 >= self.nn(j, j):
            # Çıplak blok deyim olarak (Kotlin'de lambda değeridir; çalıştırılmış sayılır)
            c = self.p[i]
            return [("{", line)] + self.block_body(i + 1, c, ctx, want_value=last) + [("}", self.line(c))]
        expr, pre = self.expr(i, j, ctx)
        if not expr:
            return pre
        if last and ctx.result and not self._is_assignment(i, j):
            return pre + [(ctx.result, line), ("=", line)] + expr + [(";", self.line(j - 1))]
        return pre + expr + [(";", self.line(j - 1))]

    def _is_assignment(self, i: int, j: int) -> bool:
        k = i
        while k < j:
            if self.is_op(k, "(", "[", "{") and k in self.p:
                k = self.p[k] + 1
                continue
            if self.is_op(k, "=", "+=", "-=", "*=", "/=", "%="):
                return True
            k += 1
        return False

    def if_stmt(self, i: int, j: int, ctx: _Ctx) -> list[Piece]:
        line = self.line(i)
        if not (self.is_op(i + 1, "(") and (i + 1) in self.p):
            expr, pre = self.expr(i, j, ctx)
            return pre + expr + [(";", line)]
        c = self.p[i + 1]
        cond, pre = self.expr(i + 2, c, ctx)
        e = self._body_span(c + 1, j)
        out = pre + [("if", line), ("(", line)] + cond + [(")", self.line(c))] + self.body_stmt(c + 1, e, ctx)
        x = self.nn(e, j)
        if self.is_op(x, ";"):
            y = self.nn(x + 1, j)
            if self.is_id(y, "else"):
                x = y
        if self.is_id(x, "else") and x < j:
            y = self.nn(x + 1, j)
            out.append(("else", self.line(x)))
            if self.is_id(y, "if"):
                inner = self.if_stmt(y, j, ctx)
                # pre parçaları if'ten önce gelir: else dalında bloğa sar
                out += [("{", self.line(y))] + inner + [("}", self.line(j - 1))]
            else:
                out += self.body_stmt(x + 1, j, ctx)
        return out

    def try_stmt(self, i: int, j: int, ctx: _Ctx) -> list[Piece]:
        line = self.line(i)
        e = self._body_span(i + 1, j)
        out = [("try", line)] + self.body_stmt(i + 1, e, ctx)
        while True:
            x = self.nn(e, j)
            if self.is_id(x, "catch") and self.is_op(x + 1, "(") and (x + 1) in self.p and x < j:
                c = self.p[x + 1]
                ps = self.params(x + 2, c, ctx)
                e = self._body_span(c + 1, j)
                pn, pt = (ps[0][0], ps[0][1]) if ps else ("__e", "Exception")
                out += [("catch", self.line(x)), ("(", self.line(x)), (pt, self.line(x)), (pn, self.line(x)),
                        (")", self.line(c))] + self.body_stmt(c + 1, e, ctx)
                continue
            if self.is_id(x, "finally") and x < j:
                e = self._body_span(x + 1, j)
                out += [("finally", self.line(x))] + self.body_stmt(x + 1, e, ctx)
                continue
            break
        if not any(p[0] in ("catch", "finally") for p in out):
            out += [("finally", line), ("{", line), ("}", line)]
        return out

    def for_stmt(self, i: int, j: int, ctx: _Ctx) -> list[Piece]:
        line = self.line(i)
        c = self.p[i + 1]
        a = self.nn(i + 2, c)
        if self.is_id(a, "val", "var"):
            a += 1
        names: list[str] = []
        if self.is_op(a, "(") and a in self.p:
            names = [self.t[x].value for x in range(a + 1, self.p[a]) if self.is_id(x) and not self.is_op(x - 1, ":")]
            a = self.p[a] + 1
        elif self.is_id(a):
            names = [self.t[a].value]
            a += 1
        x = a
        while x < c and not self.is_id(x, "in"):
            x += 1
        if x >= c or not names:
            cond, pre = self.expr(i + 2, c, ctx)
            return pre + [("while", line), ("(", line)] + cond + [(")", line)] + self.body_stmt(c + 1, j, ctx)
        it_expr, pre = self.expr(x + 1, c, ctx)
        if len(names) == 1:
            return pre + [("for", line), ("(", line), ("var", line), (names[0], line), (":", line)] + it_expr + \
                [(")", self.line(c))] + self.body_stmt(c + 1, j, ctx)
        tmp = self.tmp("kp")
        head = [("for", line), ("(", line), ("var", line), (tmp, line), (":", line)] + it_expr + [(")", self.line(c))]
        binds: list[Piece] = []
        for nm in names:
            if nm != "_":
                binds += [("var", line), (nm, line), ("=", line), (tmp, line), (";", line)]
        body = self.body_stmt(c + 1, j, ctx)
        return pre + head + [("{", line)] + binds + body + [("}", line)]

    def local_decl(self, i: int, j: int, ctx: _Ctx) -> list[Piece]:
        line = self.line(i)
        x = i + 1
        if self.is_op(x, "(") and x in self.p:  # val (a, b) = e
            names = [self.t[y].value for y in range(x + 1, self.p[x]) if self.is_id(y) and not self.is_op(y - 1, ":")]
            y = self.nn(self.p[x] + 1, j)
            if not self.is_op(y, "="):
                return []
            expr, pre = self.expr(y + 1, j, ctx)
            tmp = self.tmp("kd")
            out = pre + [("var", line), (tmp, line), ("=", line)] + expr + [(";", line)]
            for nm in names:
                if nm != "_":
                    out += [("var", line), (nm, line), ("=", line), (tmp, line), (";", line)]
            return out
        if not self.is_id(x):
            return []
        name = self.t[x].value
        if self.is_op(x + 1, "."):  # uzantı özelliği
            return []
        jt = "var"
        y = x + 1
        if self.is_op(y, ":"):
            te = self._type_end(y + 1, j)
            jt = self.jtype(y + 1, te)
            y = te
        y = self.nn(y, j)
        if self.is_id(y, "by"):  # by lazy { … }
            z = self.nn(y + 1, j)
            if self.is_id(z, "lazy"):
                z = self.nn(z + 1, j)
                if self.is_op(z, "(") and z in self.p:
                    z = self.nn(self.p[z] + 1, j)
                if self.is_op(z, "{") and z in self.p:
                    res = self.tmp("kl")
                    body = self.block_body(z + 1, self.p[z], ctx.child(result=res), want_value=True)
                    return [("var", line), (res, line), ("=", line), ("null", line), (";", line), ("{", line)] + \
                        body + [("}", line), (jt, line), (name, line), ("=", line), (res, line), (";", line)]
            expr, pre = self.expr(y + 1, j, ctx)
            return pre + [(jt, line), (name, line), ("=", line)] + expr + [(";", line)]
        if self.is_op(y, "=") and y + 1 < j:
            ref = self._exact_callable_ref(y + 1, j)
            if self.t[i].value == "val" and ref:
                self.callable_refs[name] = ref
            else:
                self.callable_refs.pop(name, None)
            expr, pre = self.expr(y + 1, j, ctx)
            return pre + [(jt, line), (name, line), ("=", line)] + expr + [(";", self.line(j - 1))]
        self.callable_refs.pop(name, None)
        return [(jt if jt != "var" else "Object", line), (name, line), (";", line)]

    def _exact_callable_ref(self, i: int, j: int) -> str | None:
        """Yalniz ``::method`` bicimindeki sabit, niteliksiz callable reference.

        ``obj::method``, ``Type::method`` ve ifade ile uretilen adlar alici/tur
        baglamini gerektirir; yanlis hedef uydurmamak icin bu dar cozucuya girmez.
        """
        indexes = [k for k in range(i, j) if self.t[k].kind != "nl"]
        if len(indexes) != 2:
            return None
        colon, name = indexes
        if not self.is_op(colon, "::") or not self.is_id(name) or self.t[name].value == "class":
            return None
        return self.t[name].value

    def when_stmt(self, i: int, j: int, ctx: _Ctx) -> list[Piece]:
        """``when`` deyimi → if/else zinciri (öznesi geçici değişkene)."""
        line = self.line(i)
        x = i + 1
        pre: list[Piece] = []
        subj: str | None = None
        if self.is_op(x, "(") and x in self.p:
            c = self.p[x]
            a = self.nn(x + 1, c)
            if self.is_id(a, "val", "var") and self.is_id(a + 1):
                subj = self.t[a + 1].value
                eq = a + 2
                while eq < c and not self.is_op(eq, "="):
                    eq += 1
                expr, p2 = self.expr(eq + 1, c, ctx)
            else:
                subj = self.tmp("ws")
                expr, p2 = self.expr(x + 1, c, ctx)
            pre += p2 + [("var", line), (subj, line), ("=", line)] + expr + [(";", line)]
            x = c + 1
        x = self.nn(x, j)
        if not (self.is_op(x, "{") and x in self.p):
            return pre
        branches = self.when_branches(x + 1, self.p[x])
        out: list[Piece] = []
        first = True
        for conds, body_a, body_b in branches:
            bl = self.line(body_a)
            if conds is None:  # else
                if first:
                    out += self.body_stmt(body_a, body_b, ctx)
                else:
                    out += [("else", bl)] + self.body_stmt(body_a, body_b, ctx)
                break
            cond_pieces: list[Piece] = []
            for n_, (ca, cb) in enumerate(conds):
                if n_:
                    cond_pieces.append(("||", bl))
                cp, p3 = self.when_cond(ca, cb, subj, ctx)
                pre += p3
                cond_pieces += [("(", bl)] + cp + [(")", bl)]
            out += ([] if first else [("else", bl)]) + [("if", bl), ("(", bl)] + cond_pieces + [(")", bl)] + \
                self.body_stmt(body_a, body_b, ctx)
            first = False
        return pre + out

    def when_branches(self, i: int, j: int) -> list[tuple[list[tuple[int, int]] | None, int, int]]:
        out = []
        k = i
        guard = 0
        while k < j and guard < 10_000:
            guard += 1
            k = self.nn(k, j)
            if k >= j:
                break
            if self.is_op(k, ";"):
                k += 1
                continue
            # koşul(lar) -> gövde
            arrow = k
            while arrow < j and not self.is_op(arrow, "->"):
                if self.is_op(arrow, "(", "[", "{") and arrow in self.p:
                    arrow = self.p[arrow] + 1
                    continue
                arrow += 1
            if arrow >= j:
                break
            conds = None if self.is_id(self.nn(k, arrow), "else") else self.split(k, arrow, ",")
            b = self.nn(arrow + 1, j)
            if self.is_op(b, "{") and b in self.p:
                e = self._expr_tail(self.p[b] + 1, j)
            else:
                e = self.stmt_span(b, j)
            out.append((conds, b, e))
            k = max(e, k + 1)
        return out

    def when_cond(self, a: int, b: int, subj: str | None, ctx: _Ctx) -> tuple[list[Piece], list[Piece]]:
        a = self.nn(a, b)
        line = self.line(a)
        neg = self.is_op(a, "!") and self.is_id(a + 1, "is", "in")
        if neg:
            a += 1
        if self.is_id(a, "is"):
            tname = self.jtype(a + 1, b)
            if subj:
                return [(subj, line), ("instanceof", line), (tname, line)], []
            return [("true", line)], []
        if self.is_id(a, "in"):
            expr, pre = self.expr(a + 1, b, ctx)
            if subj:
                return [(subj, line), ("==", line), ("(", line)] + expr + [(")", line)], pre
            return expr, pre
        expr, pre = self.expr(a, b, ctx)
        if subj:
            return [(subj, line), ("==", line), ("(", line)] + expr + [(")", line)], pre
        return expr, pre

    # -- ifadeler -------------------------------------------------------------------
    def expr(self, i: int, j: int, ctx: _Ctx) -> tuple[list[Piece], list[Piece]]:
        """İfade [i, j) → (Java parçaları, önce çalıştırılacak deyimler)."""
        out: list[Piece] = []
        pre: list[Piece] = []
        chain = 0  # out içinde geçerli işlenenin başlangıcı
        k = i
        guard = 0
        while k < j and guard < 200_000:
            guard += 1
            t = self.t[k]
            if t.kind == "nl":
                k += 1
                continue
            line = t.line
            if t.kind == "str":
                out += self.string(t, ctx, pre)
                k += 1
                continue
            if t.kind in ("num", "chr"):
                out.append((t.value, line))
                k += 1
                continue
            if t.kind == "op":
                v = t.value
                if v == "?:":
                    # elvis: sağ taraf return/throw/break/continue ise yalnız sol taraf
                    r = self.nn(k + 1, j)
                    if self.is_id(r, "return", "throw", "break", "continue"):
                        # sağ tarafın kendisi değerlendirilir (throw X(girdi) vb. yan etkisiz sayılır)
                        k = j
                        continue
                    out += [("?", line), (":", line)]
                    chain = len(out)
                    k += 1
                    continue
                if v == "!!":
                    k += 1
                    continue
                if v == "?.":
                    out.append((".", line))
                    k += 1
                    continue
                if v in ("===", "!=="):
                    out.append((v[:2], line))
                    chain = len(out)
                    k += 1
                    continue
                if v in ("..", "..<"):
                    out.append(("+", line))
                    chain = len(out)
                    k += 1
                    continue
                if v == "::":
                    # işlev başvurusu: Foo::bar / ::bar / x::class
                    x = k + 1
                    if self.is_id(x) and self.t[x].value == "class":
                        k = x + 1
                        continue
                    del out[chain:]
                    out.append(("null", line))
                    k = x + 1 if self.is_id(x) else x
                    continue
                if v == "@":
                    if self.is_id(k + 1) and k > i and self.is_id(k - 1) and self.t[k - 1].value in ("this", "super"):
                        k += 2  # this@Dış
                        continue
                    if k > i and self.is_id(k - 1) and self.t[k - 1].value in ("return",):
                        k += 2
                        continue
                    _a, k = self._annotation(k, j)
                    continue
                if v == "(" and k in self.p:
                    c = self.p[k]
                    inner, p2 = self.expr(k + 1, c, ctx)
                    pre += p2
                    out += [("(", line)] + inner + [(")", self.line(c))]
                    k = c + 1
                    k = self._postfix_lambda(k, j, out, pre, chain, None, ctx, line)
                    continue
                if v == "[" and k in self.p:
                    c = self.p[k]
                    is_index = bool(out) and (out[-1][0] not in _OPERATOR_TEXTS)
                    inner, p2 = self.args(k + 1, c, ctx)
                    pre += p2
                    if is_index:
                        out += [("[", line)] + inner + [("]", self.line(c))]
                    else:  # koleksiyon değişmezi (ek açıklama dışı) → listOf(…)
                        out += [("listOf", line), ("(", line)] + inner + [(")", self.line(c))]
                    k = c + 1
                    continue
                if v == "{" and k in self.p:
                    # bağımsız lambda değeri
                    res = self.lambda_block(k, None, None, ctx, pre, value=True)
                    out.append((res, line))
                    k = self.p[k] + 1
                    continue
                if v in ("=",) and out:
                    out.append(("=", line))
                    chain = len(out)
                    k += 1
                    continue
                if v in (")", "]", "}"):
                    k += 1
                    continue
                if v == "<" and out and out[-1][0] not in _OPERATOR_TEXTS:
                    g = self._generic_end(k, j)
                    if g and (self.is_op(g, "(", "{", "::") or (g < j and self.is_op(g, ".") and False)):
                        k = g  # çağrı tür argümanları
                        continue
                out.append((v, line))
                if v not in (".",):
                    chain = len(out)
                k += 1
                continue
            # tanımlayıcı
            v = t.value
            if v == "if" and self.is_op(k + 1, "(") and (k + 1) in self.p:
                pieces, k = self.if_expr(k, j, ctx, pre)
                out += pieces
                continue
            if v == "when":
                pieces, k = self.when_expr(k, j, ctx, pre)
                out += pieces
                continue
            if v == "try":
                pieces, k = self.try_expr(k, j, ctx, pre)
                out += pieces
                continue
            if v == "object" and self.is_op(self.nn(k + 1, j), ":", "{"):
                pieces, k = self.object_expr(k, j, ctx)
                out += pieces
                continue
            if v in ("is", "as", "in") or (v == "!" and False):
                prev_neg = out and out[-1][0] == "!" and v in ("is", "in")
                if prev_neg:
                    out.pop()
                if v == "as":
                    if self.is_op(k + 1, "?"):
                        k += 1
                    te = self._type_end(k + 1, j)
                    k = te
                    continue
                if v == "is":
                    te = self._type_end(k + 1, j)
                    out += [("instanceof", line), (self.jtype(k + 1, te), line)]
                    k = te
                    chain = len(out)
                    continue
                out.append(("==", line))
                chain = len(out)
                k += 1
                continue
            if v in ("return", "throw") and k > i:
                # ifade içinde return/throw (ör. if dalı): değeri ifade olarak ele al
                k += 1
                if self.is_op(k, "@") and self.is_id(k + 1):
                    k += 2
                continue
            if v in ("break", "continue"):
                k += 1
                continue
            if v == "it" and ctx.it:
                out.append((ctx.it, line))
                k += 1
                continue
            if v == "this" and self.is_op(k + 1, "@"):
                out.append(("this", line))
                k += 3
                continue
            prev_dot = out and out[-1][0] == "."
            # infix işlev çağrısı: a to b, x until y, a and b …
            if out and not prev_dot and out[-1][0] not in _OPERATOR_TEXTS and v not in _KEYWORDS and \
                    k + 1 < j and self._starts_operand(k + 1) and not self.is_op(k + 1, "(", "{", "<", ".") and \
                    self.t[k + 1].kind != "nl" and not (self.is_op(k - 1, ".", "?.")):
                out.append(("+", line))
                chain = len(out)
                k += 1
                continue
            k = self.call_or_ident(k, j, ctx, out, pre, chain, prev_dot)
        return out, pre

    def _starts_operand(self, k: int) -> bool:
        t = self.t[k]
        if t.kind in ("id", "str", "num", "chr"):
            return t.kind != "id" or t.value not in ("else", "in", "is", "as", "by", "where")
        return t.kind == "op" and t.value in ("(", "!", "-", "+", "[", "::")

    def args(self, i: int, j: int, ctx: _Ctx) -> tuple[list[Piece], list[Piece]]:
        out: list[Piece] = []
        pre: list[Piece] = []
        for n_, (a, b) in enumerate(self.split(i, j, ",")):
            a = self.nn(a, b)
            if n_:
                out.append((",", self.line(a)))
            # adlandırılmış argüman: ad = ifade → ad: ifade (motor C# biçimini tanır)
            if self.is_id(a) and self.is_op(a + 1, "=") and a + 2 < b:
                out += [(self.t[a].value, self.line(a)), (":", self.line(a))]
                a += 2
            if self.is_op(a, "*"):  # yayma
                a += 1
            e, p = self.expr(a, b, ctx)
            pre += p
            out += e
        return out, pre

    def call_or_ident(self, k: int, j: int, ctx: _Ctx, out: list[Piece], pre: list[Piece], chain: int,
                      prev_dot: bool) -> int:
        t = self.t[k]
        name = t.value
        line = t.line
        x = k + 1
        if self.is_op(x, "<"):
            g = self._generic_end(x, j)
            if g and (self.is_op(g, "(", "{") or (g < j and self.is_op(g, "::"))):
                x = g
        has_paren = self.is_op(x, "(") and x in self.p
        if has_paren and not prev_dot and name in self.callable_refs:
            name = self.callable_refs[name]
        lam = None
        after = self.p[x] + 1 if has_paren else x
        # lambda etiketi: foo@{ … }
        if self.is_id(after) and self.is_op(after + 1, "@") and self.is_op(after + 2, "{"):
            after += 2
        if self.is_op(after, "{") and after in self.p and (has_paren or name not in _KEYWORDS):
            lam = after
        if not has_paren and lam is None:
            # düz tanımlayıcı
            if ctx.sb and not prev_dot and name in ("append", "appendLine", "appendln"):
                out += [(ctx.sb, line), (".", line)]
            out.append((name, line))
            return x
        args: list[Piece] = []
        if has_paren:
            args, p2 = self.args(x + 1, self.p[x], ctx)
            pre += p2
        end = (self.p[lam] + 1) if lam is not None else after
        # alıcı (zincirdeki önceki parçalar)
        recv_pieces = out[chain:-1] if prev_dot else []
        recv_text = "".join(p[0] for p in recv_pieces)
        # Ktor / Javalin yanıt hedefleri
        sink = self._framework_sink(name, recv_text, x, has_paren, args, lam, prev_dot)
        if lam is not None:
            res = self._lambda_call(name, recv_pieces, prev_dot, lam, ctx, pre, out, chain, line, sink, args)
            if res is not None:
                return end
            args = args + ([(",", line)] if args else []) + [(self._last_lambda, line)]
        if sink is not None:
            kind, desc = sink
            if prev_dot:
                del out[chain:]
            out += [("__kt_sink", line), ("(", line), (f'"{kind}"', line), (",", line), (_jstr(desc), line)]
            if args:
                out += [(",", line)] + args
            out.append((")", line))
            return end
        if ctx.sb and not prev_dot and name in ("append", "appendLine", "appendln", "insert"):
            out += [(ctx.sb, line), (".", line)]
        if ctx.unsafe and not prev_dot and name == "raw":
            out += [("__kt_sink", line), ("(", line), ('"html"', line), (",", line),
                    (_jstr("kotlinx.html unsafe { raw() }"), line), (",", line)] + args + [(")", line)]
            return end
        if not prev_dot and name[:1].isupper() and (not out or out[-1][0] != "new"):
            out.append(("new", line))
        elif prev_dot and name[:1].isupper() and 0 <= chain < len(out) and out[chain][0] != "new" and \
                re.fullmatch(r"(?:java|javax|kotlin|kotlinx|android|androidx|org|com|io|net)(?:\.[a-z_][a-z0-9_]*)*\.",
                             "".join(piece[0] for piece in out[chain:])):
            out.insert(chain, ("new", line))  # paket nitelikli kurucu: java.io.File(x) → new java.io.File(x)
        out += [(name, line), ("(", line)] + args + [(")", line)]
        return end

    def _framework_sink(self, name: str, recv_text: str, x: int, has_paren: bool, args: list[Piece],
                        lam: int | None, prev_dot: bool) -> tuple[str, str] | None:
        recv = recv_text.lower()
        arg_text = "".join(p[0] for p in args)
        if name == "respondText" and ("call" in recv or not prev_dot):
            if _HTML_KTOR.search(arg_text):
                return "html", "call.respondText(…, ContentType.Text.Html)"
            return None
        if name == "respondRedirect" and ("call" in recv or not prev_dot):
            return "redirect", "call.respondRedirect()"
        if name == "respondFile" and ("call" in recv or not prev_dot):
            return "path", "call.respondFile()"
        if name == "html" and prev_dot and recv in ("ctx", "context", "it") and has_paren:
            return "html", "ctx.html()"
        if name == "redirect" and prev_dot and recv in ("ctx", "context") and has_paren:
            return "redirect", "ctx.redirect()"
        return None

    def _lambda_call(self, name: str, recv_pieces: list[Piece], prev_dot: bool, lam: int, ctx: _Ctx,
                     pre: list[Piece], out: list[Piece], chain: int, line: int,
                     sink: tuple[str, str] | None, args: list[Piece]) -> str | None:
        """Lambdalı çağrı: gövde öne açılır, çağrı yerine sonuç ifadesi yazılır."""
        if name == "buildString" and not prev_dot:
            sb = self.tmp("ksb")
            res = self.tmp("kl")
            pre += [("StringBuilder", line), (sb, line), ("=", line), ("new", line), ("StringBuilder", line),
                    ("(", line), (")", line), (";", line), ("var", line), (res, line), ("=", line), ("null", line),
                    (";", line), ("{", line)]
            pre += self.block_body(lam + 1, self.p[lam], ctx.child(result=res, sb=sb)) if not self._has_params(lam) \
                else self._lambda_inner(lam, ctx.child(result=res, sb=sb), [])
            pre += [("}", line)]
            out += [(sb, line), (".", line), ("toString", line), ("(", line), (")", line)]
            return res
        if name == "unsafe" and not prev_dot:
            res = self.lambda_block(lam, None, None, ctx.child(unsafe=True), pre, value=False)
            out.append(("null", line))
            return res
        if prev_dot and recv_pieces and (name in _RET_RECEIVER or name in _RET_LAMBDA or name in _BOOL_LAMBDA):
            # alıcıyı geçici değişkene al
            rtmp = self.tmp("kr")
            pre += [("var", line), (rtmp, line), ("=", line)] + recv_pieces + [(";", line)]
            res = self.lambda_block(lam, rtmp, None, ctx, pre, value=name not in _RET_RECEIVER)
            del out[chain:]
            if name in _RET_RECEIVER:
                out.append((rtmp, line))
            elif name in _BOOL_LAMBDA:
                out.append(("false", line))
            else:
                out.append((res, line))
            return res
        if name == "with" and not prev_dot:
            # with(x) { … }: x örtük alıcı; it yok
            res = self.lambda_block(lam, None, None, ctx, pre, value=True)
            del out[chain:]
            out.append((res, line))
            return res
        # Diğer: yönlendirme blokları (get("/x") { … }), transaction { … }, runBlocking { … }, kullanıcı işlevleri
        res = self.lambda_block(lam, None, name, ctx, pre, value=True)
        self._last_lambda = res
        if sink is not None:
            return None  # hedef çağrısı ayrıca yazılır; lambda sonucu son argüman olarak eklenir
        if not prev_dot and name[:1].isupper():
            out.append(("new", line))
        out += [(name, line), ("(", line)] + args + ([(",", line)] if args else []) + [(res, line), (")", line)]
        return res

    def _has_params(self, lam: int) -> bool:
        return self._lambda_params(lam)[1] is not None

    def _lambda_params(self, lam: int) -> tuple[list[str], int | None]:
        """``{ a, (b, c) -> …}`` parametre adları ve ``->`` indisi (yoksa None)."""
        c = self.p[lam]
        k = self.nn(lam + 1, c)
        names: list[str] = []
        x = k
        while x < c:
            if self.is_op(x, "->"):
                return names, x
            if self.is_id(x):
                if not self.is_op(x - 1, ":", ".") or self.is_op(x - 1, ","):
                    names.append(self.t[x].value)
                x += 1
                continue
            if self.is_op(x, "(") and x in self.p:
                for y in range(x + 1, self.p[x]):
                    if self.is_id(y) and not self.is_op(y - 1, ":", "."):
                        names.append(self.t[y].value)
                x = self.p[x] + 1
                continue
            if self.is_op(x, ",", ":", ".", "?", "<", ">") or self.t[x].kind == "nl":
                x += 1
                continue
            return [], None
        return [], None

    def lambda_block(self, lam: int, bind: str | None, callee: str | None, ctx: _Ctx, pre: list[Piece],
                     value: bool) -> str:
        """Lambda gövdesini ``pre``'ye blok olarak yazar; sonuç değişkeninin adını döndürür."""
        line = self.line(lam)
        res = self.tmp("kl")
        pre += [("var", line), (res, line), ("=", line), ("null", line), (";", line), ("{", line)]
        binds: list[Piece] = []
        names, _arrow = self._lambda_params(lam)
        it_name = None
        if names:
            for nm in names:
                if nm == "_":
                    continue
                binds += [("var", line), (nm, line), ("=", line), (bind or "null", line), (";", line)]
        else:
            it_name = self.tmp("it")
            binds += [("var", line), (it_name, line), ("=", line), (bind or "null", line), (";", line)]
        inner_ctx = ctx.child(result=res, it=it_name if it_name else ctx.it if names else None)
        if it_name is None and names:
            inner_ctx.it = ctx.it if "it" not in names else None
        pre += self._lambda_inner(lam, inner_ctx, binds, value=value)
        pre += [("}", self.line(self.p[lam]))]
        del callee
        return res

    def _lambda_inner(self, lam: int, ctx: _Ctx, binds: list[Piece], value: bool = True) -> list[Piece]:
        c = self.p[lam]
        _names, arrow = self._lambda_params(lam)
        start = arrow + 1 if arrow is not None else lam + 1
        return binds + self.block_body(start, c, ctx, want_value=value)

    def _postfix_lambda(self, k: int, j: int, out: list[Piece], pre: list[Piece], chain: int, name: str | None,
                        ctx: _Ctx, line: int) -> int:
        """``(ifade) { … }`` gibi parantez sonrası lambda: değer olarak açılır."""
        if self.is_op(k, "{") and k in self.p and False:
            res = self.lambda_block(k, None, name, ctx, pre, value=True)
            out.append((res, line))
            return self.p[k] + 1
        return k

    def if_expr(self, k: int, j: int, ctx: _Ctx, pre: list[Piece]) -> tuple[list[Piece], int]:
        line = self.line(k)
        c = self.p[k + 1]
        cond, p1 = self.expr(k + 2, c, ctx)
        pre += p1
        then_a = self.nn(c + 1, j)
        # then dalı: blok ya da else'e kadar ifade
        if self.is_op(then_a, "{") and then_a in self.p:
            then_b = self.p[then_a] + 1
            tv = self.block_value(then_a, ctx, pre)
        else:
            then_b = self._find_else(then_a, j)
            tv, p2 = self.expr(then_a, then_b, ctx)
            pre += p2
        x = self.nn(then_b, j)
        ev: list[Piece] = [("null", line)]
        end = then_b
        if self.is_id(x, "else"):
            ea = self.nn(x + 1, j)
            if self.is_op(ea, "{") and ea in self.p:
                ev = self.block_value(ea, ctx, pre)
                end = self.p[ea] + 1
            else:
                ev, p3 = self.expr(ea, j, ctx)
                pre += p3
                end = j
        return [("(", line), ("(", line)] + cond + [(")", line), ("?", line), ("(", line)] + (tv or [("null", line)]) + \
            [(")", line), (":", line), ("(", line)] + (ev or [("null", line)]) + [(")", line), (")", line)], end

    def _find_else(self, i: int, j: int) -> int:
        k = i
        depth_if = 0
        while k < j:
            if self.is_op(k, "(", "[", "{") and k in self.p:
                k = self.p[k] + 1
                continue
            if self.is_id(k, "if"):
                depth_if += 1
            elif self.is_id(k, "else"):
                if depth_if == 0:
                    return k
                depth_if -= 1
            k += 1
        return j

    def block_value(self, b: int, ctx: _Ctx, pre: list[Piece]) -> list[Piece]:
        """``{ deyimler; son }`` → deyimler pre'ye, son ifade değişkene; değişken parçası döner."""
        line = self.line(b)
        res = self.tmp("kv")
        pre += [("var", line), (res, line), ("=", line), ("null", line), (";", line), ("{", line)]
        pre += self.block_body(b + 1, self.p[b], ctx.child(result=res), want_value=True)
        pre += [("}", self.line(self.p[b]))]
        return [(res, line)]

    def when_expr(self, k: int, j: int, ctx: _Ctx, pre: list[Piece]) -> tuple[list[Piece], int]:
        line = self.line(k)
        x = k + 1
        subj = None
        if self.is_op(x, "(") and x in self.p:
            c = self.p[x]
            a = self.nn(x + 1, c)
            if self.is_id(a, "val", "var") and self.is_id(a + 1):
                subj = self.t[a + 1].value
                eq = a + 2
                while eq < c and not self.is_op(eq, "="):
                    eq += 1
                e, p = self.expr(eq + 1, c, ctx)
            else:
                subj = self.tmp("ws")
                e, p = self.expr(x + 1, c, ctx)
            pre += p + [("var", line), (subj, line), ("=", line)] + e + [(";", line)]
            x = c + 1
        x = self.nn(x, j)
        if not (self.is_op(x, "{") and x in self.p):
            return [("null", line)], x
        end = self.p[x] + 1
        branches = self.when_branches(x + 1, self.p[x])
        values: list[tuple[list[Piece] | None, list[Piece]]] = []
        for conds, a, b in branches:
            if self.is_op(a, "{") and a in self.p:
                v = self.block_value(a, ctx, pre)
            else:
                v, p = self.expr(a, b, ctx)
                pre += p
            cond_pieces = None
            if conds is not None:
                cond_pieces = []
                for n_, (ca, cb) in enumerate(conds):
                    if n_:
                        cond_pieces.append(("||", line))
                    cp, p3 = self.when_cond(ca, cb, subj, ctx)
                    pre += p3
                    cond_pieces += [("(", line)] + cp + [(")", line)]
            values.append((cond_pieces, v or [("null", line)]))
        out: list[Piece] = [("(", line)]
        closes = 0
        for cond_pieces, v in values:
            if cond_pieces is None:
                out += [("(", line)] + v + [(")", line)]
                break
            out += [("(", line)] + cond_pieces + [(")", line), ("?", line), ("(", line)] + v + [(")", line), (":", line)]
            closes += 1
        else:
            out.append(("null", line))
        out.append((")", line))
        return out, end

    def try_expr(self, k: int, j: int, ctx: _Ctx, pre: list[Piece]) -> tuple[list[Piece], int]:
        line = self.line(k)
        b = self.nn(k + 1, j)
        if not (self.is_op(b, "{") and b in self.p):
            return [("null", line)], k + 1
        vals = [self.block_value(b, ctx, pre)]
        e = self.p[b] + 1
        while True:
            x = self.nn(e, j)
            if self.is_id(x, "catch") and self.is_op(x + 1, "(") and (x + 1) in self.p:
                cb = self.nn(self.p[x + 1] + 1, j)
                if self.is_op(cb, "{") and cb in self.p:
                    vals.append(self.block_value(cb, ctx, pre))
                    e = self.p[cb] + 1
                    continue
            if self.is_id(x, "finally"):
                fb = self.nn(x + 1, j)
                if self.is_op(fb, "{") and fb in self.p:
                    pre += [("{", line)] + self.block_body(fb + 1, self.p[fb], ctx.child(result=None)) + [("}", line)]
                    e = self.p[fb] + 1
                    continue
            break
        out: list[Piece] = [("(", line)]
        for n_, v in enumerate(vals):
            if n_:
                out.append(("+", line))
            out += v
        out.append((")", line))
        return out, e

    def object_expr(self, k: int, j: int, ctx: _Ctx) -> tuple[list[Piece], int]:
        """``object : Arayüz { … }`` → ``new Arayüz() { … }``."""
        line = self.line(k)
        x = self.nn(k + 1, j)
        base = "Object"
        if self.is_op(x, ":"):
            y = x + 1
            while y < j and not self.is_op(y, "{"):
                if self.is_id(y) and base == "Object":
                    base = self.t[y].value
                if self.is_op(y, "(") and y in self.p:
                    y = self.p[y]
                y += 1
            x = y
        if not (self.is_op(x, "{") and x in self.p):
            return [("null", line)], x
        body = self.decls(x + 1, self.p[x], base, ctx)
        return [("new", line), (base, line), ("(", line), (")", line), ("{", line)] + body + \
            [("}", self.line(self.p[x]))], self.p[x] + 1

    def string(self, tok: KTok, ctx: _Ctx, pre: list[Piece]) -> list[Piece]:
        parts = tok.value
        line = tok.line
        if len(parts) == 1 and isinstance(parts[0], str):
            return [(_jstr(parts[0]), line)]
        out: list[Piece] = [("(", line)]
        first = True
        for part in parts:
            if not first:
                out.append(("+", line))
            first = False
            if isinstance(part, str):
                out.append((_jstr(part), line))
            else:
                sub = Translator.__new__(Translator)
                sub.t, sub.p, sub.n, sub.counter, sub.max_line = part, match_pairs(part), len(part), self.counter, 0
                e, p = sub.expr(0, len(part), ctx)
                self.counter = sub.counter
                pre += p
                out += [("(", line)] + (e or [('""', line)]) + [(")", line)]
        if isinstance(parts[0], str) is False:
            out.insert(1, ('""', line))
            out.insert(2, ("+", line))
        out.append((")", line))
        return out


_OPERATOR_TEXTS = frozenset({"=", "+", "-", "*", "/", "%", "&&", "||", "!", "?", ":", "==", "!=", "<", ">", "<=", ">=",
                             "(", ",", "+=", "-=", "*=", "/=", "%=", "return", "throw", "->", "[", "instanceof",
                             "new", "{", ";"})


def _jstr(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 32:
            out.append(" ")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def kotlin_to_java(text: str) -> str:
    """Kotlin kaynak metni → satır numaraları korunmuş Java benzeri metin (taint_clike Java ön ucu için)."""
    try:
        return Translator(text).translate()
    except Exception:  # noqa: BLE001 - çevrilemeyen dosya analiz dışı kalır (boş metin), proje analizi sürer
        if os.environ.get("SNIPER_KT_DEBUG") == "1":
            raise
        return "\n" * text.count("\n")
