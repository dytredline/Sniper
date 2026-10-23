"""Hizmet reddi (DoS) dayanıklılığı ve yapısal ReDoS denetimi.

Yalnızca çevrimdışı kaynak metni üzerinde statik analiz yapar. Düzenli ifadeler
ASLA derlenip saldırı dizgileriyle çalıştırılmaz: ReDoS analizi deseni kendi
ayrıştırıcımızla soyut sözdizimi ağacına çevirip yapısal olarak inceler.
Ağ erişimi, alt süreç veya veritabanı yazımı yoktur.
"""
from __future__ import annotations

import bisect
import os
from pathlib import Path
import re
import unicodedata
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from safe_file_read import read_text_bounded
import taint_flow
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500
REDOS_MAX_PATTERN_CHARS = 5_000
REDOS_MAX_GROUP_DEPTH = 100
_REDOS_PATTERN_PREVIEW = 300
_REDOS_MAX_EXTRA_SAMPLES = 256
_MAX_REGEX_PER_FILE = 500

DOS_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-DOS-01",
    "SNIPER-DOS-02",
    "SNIPER-DOS-03",
    "SNIPER-DOS-04",
    "SNIPER-DOS-05",
    "SNIPER-DOS-06",
]

DOS_EXTENSIONS: set[str] = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go",
    ".java", ".kt", ".rb", ".php", ".cs",
}
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


# ======================================================================================
# Yapısal ReDoS analizörü (düzenli ifade ÇALIŞTIRILMAZ)
# ======================================================================================

class _RegexParseError(Exception):
    def __init__(self, message: str, position: int) -> None:
        super().__init__(message)
        self.message = message
        self.position = position


def _class_matches(code: str, char: str) -> bool:
    if code == "d":
        return char.isdecimal()
    if code == "D":
        return not char.isdecimal()
    if code == "w":
        return char.isalnum() or char == "_"
    if code == "W":
        return not (char.isalnum() or char == "_")
    if code == "s":
        return char.isspace()
    if code == "S":
        return not char.isspace()
    return True  # 'u': Unicode özellik sınıfı vb.; muhafazakâr olarak her karakterle örtüşür


class _CharSet:
    __slots__ = ("items", "negated", "mask")

    def __init__(self, items: list[tuple[str, ...]], negated: bool = False) -> None:
        self.items = tuple(items)
        self.negated = negated
        self.mask = 0

    def matches(self, char: str) -> bool:
        hit = False
        for item in self.items:
            kind = item[0]
            if kind == "lit":
                hit = char == item[1]
            elif kind == "range":
                hit = item[1] <= char <= item[2]
            elif kind == "cls":
                hit = _class_matches(item[1], char)
            else:  # "any" (nokta)
                hit = char != "\n"
            if hit:
                break
        return (not hit) if self.negated else hit

    def literals(self) -> list[str]:
        values: list[str] = []
        for item in self.items:
            if item[0] == "lit":
                values.append(item[1])
            elif item[0] == "range":
                values.extend((item[1], item[2]))
        return values


class _Node:
    __slots__ = (
        "kind", "pos", "charset", "alts", "zero_width", "atomic",
        "qmin", "qmax", "lazy", "possessive", "quant_pos",
    )

    def __init__(
        self,
        kind: str,
        pos: int,
        *,
        charset: _CharSet | None = None,
        alts: list[list["_Node"]] | None = None,
        zero_width: bool = False,
        atomic: bool = False,
    ) -> None:
        self.kind = kind  # set | group | anchor | backref
        self.pos = pos
        self.charset = charset
        self.alts = alts or []
        self.zero_width = zero_width
        self.atomic = atomic
        self.qmin = 1
        self.qmax: int | None = 1
        self.lazy = False
        self.possessive = False
        self.quant_pos = pos


_BRACE_QUANT_RE = re.compile(r"\{(\d{0,6})(?:(,)(\d{0,6}))?\}")
_INLINE_FLAGS_RE = re.compile(r"\?([aiLmsux]*)(?:-([imsx]+))?([:)])")
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "a": "\a", "e": "\x1b"}
_POSIX_CLASSES: dict[str, list[tuple[str, ...]]] = {
    "alpha": [("range", "a", "z"), ("range", "A", "Z")],
    "digit": [("cls", "d")],
    "alnum": [("range", "a", "z"), ("range", "A", "Z"), ("range", "0", "9")],
    "upper": [("range", "A", "Z")],
    "lower": [("range", "a", "z")],
    "space": [("cls", "s")],
    "blank": [("lit", " "), ("lit", "\t")],
    "xdigit": [("range", "0", "9"), ("range", "a", "f"), ("range", "A", "F")],
    "word": [("cls", "w")],
    "punct": [("range", "!", "/"), ("range", ":", "@"), ("range", "[", "`"), ("range", "{", "~")],
    "cntrl": [("range", "\x00", "\x1f"), ("lit", "\x7f")],
    "print": [("range", " ", "~")],
    "graph": [("range", "!", "~")],
}


class _RegexParser:
    """Python re / PCRE / JS sözdiziminin ortak alt kümesi için özyinelemeli iniş ayrıştırıcı."""

    def __init__(self, pattern: str, verbose: bool = False) -> None:
        self.p = pattern
        self.n = len(pattern)
        self.i = 0
        self.verbose = verbose
        self.charsets: list[_CharSet] = []

    # --- yapı ---------------------------------------------------------------------
    def parse(self) -> _Node:
        alts = self._parse_alternation(0)
        if self.i < self.n:
            raise _RegexParseError("Eşleşmeyen kapanış parantezi ')'.", self.i)
        return _Node("group", 0, alts=alts)

    def _parse_alternation(self, depth: int) -> list[list[_Node]]:
        if depth > REDOS_MAX_GROUP_DEPTH:
            raise _RegexParseError("Grup iç içe geçme derinliği güvenli sınırı aşıyor.", self.i)
        alts = [self._parse_sequence(depth)]
        while self.i < self.n and self.p[self.i] == "|":
            self.i += 1
            alts.append(self._parse_sequence(depth))
        return alts

    def _parse_sequence(self, depth: int) -> list[_Node]:
        sequence: list[_Node] = []
        while self.i < self.n:
            char = self.p[self.i]
            if char in "|)":
                break
            if self.verbose and (char.isspace() or char == "#"):
                if char == "#":
                    newline = self.p.find("\n", self.i)
                    self.i = self.n if newline < 0 else newline + 1
                else:
                    self.i += 1
                continue
            node = self._parse_atom(depth)
            if node is None:
                continue
            self._parse_quantifier(node)
            sequence.append(node)
        return sequence

    def _new_set(self, items: list[tuple[str, ...]], pos: int, negated: bool = False) -> _Node:
        charset = _CharSet(items, negated)
        self.charsets.append(charset)
        return _Node("set", pos, charset=charset)

    def _parse_atom(self, depth: int) -> _Node | None:
        start = self.i
        char = self.p[start]
        if char == "(":
            return self._parse_group(depth)
        if char == "[":
            items, negated = self._parse_class()
            return self._new_set(items, start, negated)
        if char == ".":
            self.i += 1
            return self._new_set([("any",)], start)
        if char in "^$":
            self.i += 1
            return _Node("anchor", start)
        if char in "*+?":
            raise _RegexParseError("Tekrarlanacak öğe yok (niceleyici başta).", start)
        if char == "{" and self._match_brace(start) is not None:
            raise _RegexParseError("Tekrarlanacak öğe yok (niceleyici başta).", start)
        if char == "\\":
            return self._parse_escape(start)
        self.i += 1
        return self._new_set([("lit", char)], start)

    # --- niceleyiciler ------------------------------------------------------------
    def _match_brace(self, pos: int) -> tuple[int, int | None, int] | None:
        match = _BRACE_QUANT_RE.match(self.p, pos)
        if not match:
            return None
        low, comma, high = match.group(1), match.group(2), match.group(3)
        if not low and not high:
            return None
        qmin = int(low) if low else 0
        if comma is None:
            qmax: int | None = qmin
        else:
            qmax = int(high) if high else None
        return qmin, qmax, match.end()

    def _skip_verbose(self) -> None:
        while self.verbose and self.i < self.n:
            char = self.p[self.i]
            if char.isspace():
                self.i += 1
            elif char == "#":
                newline = self.p.find("\n", self.i)
                self.i = self.n if newline < 0 else newline + 1
            else:
                break

    def _parse_quantifier(self, node: _Node) -> None:
        self._skip_verbose()
        if self.i >= self.n:
            return
        char = self.p[self.i]
        qpos = self.i
        if char == "*":
            qmin, qmax, end = 0, None, self.i + 1
        elif char == "+":
            qmin, qmax, end = 1, None, self.i + 1
        elif char == "?":
            qmin, qmax, end = 0, 1, self.i + 1
        elif char == "{":
            brace = self._match_brace(self.i)
            if brace is None:
                return
            qmin, qmax, end = brace
            if qmax is not None and qmin > qmax:
                raise _RegexParseError("Niceleyici aralığı geçersiz (en az > en çok).", qpos)
        else:
            return
        if node.kind == "anchor":
            raise _RegexParseError("Tekrarlanacak öğe yok (çapa niceleyiciyle kullanılamaz).", qpos)
        self.i = end
        lazy = possessive = False
        if self.i < self.n and self.p[self.i] == "?":
            lazy = True
            self.i += 1
        elif self.i < self.n and self.p[self.i] == "+":
            possessive = True  # Python 3.11+ / PCRE / Java: geri izleme yapmaz
            self.i += 1
        node.qmin = qmin
        node.qmax = qmax
        node.lazy = lazy
        node.possessive = possessive
        node.quant_pos = qpos
        if self.i < self.n:
            following = self.p[self.i]
            if following in "*+?" or (following == "{" and self._match_brace(self.i) is not None):
                raise _RegexParseError("Art arda niceleyici (multiple repeat).", self.i)

    # --- kaçış dizileri -------------------------------------------------------------
    def _read_octal(self, pos: int) -> tuple[str, int]:
        end = pos
        while end < self.n and end < pos + 3 and self.p[end] in "01234567":
            end += 1
        if end == pos:
            return self.p[pos], pos + 1
        return chr(int(self.p[pos:end], 8)), end

    def _chr_hex(self, digits: str, pos: int) -> str:
        if not digits or len(digits) > 8 or any(c not in "0123456789abcdefABCDEF" for c in digits):
            raise _RegexParseError("Geçersiz onaltılık kaçış dizisi.", pos)
        value = int(digits, 16)
        if value > 0x10FFFF:
            raise _RegexParseError("Onaltılık kaçış Unicode aralığı dışında.", pos)
        return chr(value)

    def _escape_literal(self, char: str, pos: int) -> str:
        """`char` ters eğik çizgiden sonraki karakterdir; self.i onun hemen sonrasını gösterir."""
        p = self.p
        if char in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[char]
        if char in "xu" and self.i < self.n and p[self.i] == "{":
            end = p.find("}", self.i)
            if end < 0:
                raise _RegexParseError("Kapanmamış \\x{...} / \\u{...} kaçışı.", pos)
            digits = p[self.i + 1:end]
            self.i = end + 1
            return self._chr_hex(digits, pos)
        width = {"x": 2, "u": 4, "U": 8}.get(char)
        if width:
            digits = p[self.i:self.i + width]
            if len(digits) != width:
                raise _RegexParseError("Eksik onaltılık kaçış dizisi.", pos)
            self.i += width
            return self._chr_hex(digits, pos)
        if char == "N" and self.i < self.n and p[self.i] == "{":
            end = p.find("}", self.i)
            if end < 0:
                raise _RegexParseError("Kapanmamış \\N{...} kaçışı.", pos)
            name = p[self.i + 1:end]
            self.i = end + 1
            try:
                return unicodedata.lookup(name)
            except KeyError as exc:
                raise _RegexParseError("Bilinmeyen Unicode karakter adı.", pos) from exc
        if char == "c" and self.i < self.n:
            control = p[self.i]
            self.i += 1
            return chr(ord(control) % 32)
        return char

    def _consume_property(self, pos: int) -> None:
        if self.i < self.n and self.p[self.i] == "{":
            end = self.p.find("}", self.i)
            if end < 0:
                raise _RegexParseError("Kapanmamış Unicode özellik sınıfı.", pos)
            self.i = end + 1
        elif self.i < self.n:
            self.i += 1
        else:
            raise _RegexParseError("Eksik Unicode özellik sınıfı.", pos)

    def _parse_escape(self, start: int) -> _Node:
        p = self.p
        if start + 1 >= self.n:
            raise _RegexParseError("Desen tek bir ters eğik çizgiyle bitiyor.", start)
        char = p[start + 1]
        self.i = start + 2
        if char in "dDwWsS":
            return self._new_set([("cls", char)], start)
        if char in "bBAZzGK":
            return _Node("anchor", start)
        if char in "pP":
            self._consume_property(start)
            return self._new_set([("cls", "u")], start)
        if char == "0":
            literal, self.i = self._read_octal(start + 1)
            return self._new_set([("lit", literal)], start)
        if char.isdigit():
            end = self.i
            while end < self.n and end < start + 3 and p[end].isdigit():
                end += 1
            self.i = end
            return _Node("backref", start)
        if char == "k" and self.i < self.n and p[self.i] in "<{'":
            closing = {"<": ">", "{": "}", "'": "'"}[p[self.i]]
            end = p.find(closing, self.i + 1)
            if end < 0:
                raise _RegexParseError("Kapanmamış adlandırılmış geri başvuru.", start)
            self.i = end + 1
            return _Node("backref", start)
        literal = self._escape_literal(char, start)
        return self._new_set([("lit", literal)], start)

    # --- karakter sınıfları ---------------------------------------------------------
    def _class_escape(self, pos: int, class_start: int) -> tuple[tuple[str, ...], int]:
        if pos + 1 >= self.n:
            raise _RegexParseError("Kapanmamış karakter sınıfı '['.", class_start)
        char = self.p[pos + 1]
        self.i = pos + 2
        if char in "dDwWsS":
            return ("cls", char), self.i
        if char in "pP":
            self._consume_property(pos)
            return ("cls", "u"), self.i
        if char == "b":
            return ("lit", "\x08"), self.i
        if char in "01234567":
            literal, end = self._read_octal(pos + 1)
            return ("lit", literal), end
        literal = self._escape_literal(char, pos)
        return ("lit", literal), self.i

    def _parse_class(self) -> tuple[list[tuple[str, ...]], bool]:
        p = self.p
        start = self.i
        i = start + 1
        negated = False
        if i < self.n and p[i] == "^":
            negated = True
            i += 1
        items: list[tuple[str, ...]] = []
        first = True
        while True:
            if i >= self.n:
                raise _RegexParseError("Kapanmamış karakter sınıfı '['.", start)
            char = p[i]
            if char == "]" and not first:
                i += 1
                break
            first = False
            if char == "[" and i + 1 < self.n and p[i + 1] == ":":
                end = p.find(":]", i + 2)
                if end > 0:
                    posix = _POSIX_CLASSES.get(p[i + 2:end].lower())
                    if posix is not None:
                        items.extend(posix)
                        i = end + 2
                        continue
            if char == "\\":
                item, i = self._class_escape(i, start)
            else:
                item = ("lit", char)
                i += 1
            if item[0] != "lit":
                items.append(item)
                continue
            low = item[1]
            if i + 1 < self.n and p[i] == "-" and p[i + 1] != "]":
                j = i + 1
                if p[j] == "\\":
                    high_item, after = self._class_escape(j, start)
                    if high_item[0] != "lit":
                        items.extend((("lit", low), ("lit", "-"), high_item))
                        i = after
                        continue
                    high = high_item[1]
                    i = after
                elif p[j] == "[" and j + 1 < self.n and p[j + 1] == ":":
                    items.extend((("lit", low), ("lit", "-")))
                    i = j
                    continue
                else:
                    high = p[j]
                    i = j + 1
                if high < low:
                    raise _RegexParseError("Karakter sınıfında geçersiz aralık.", start)
                items.append(("range", low, high))
            else:
                items.append(("lit", low))
        self.i = i
        return items, negated

    # --- gruplar --------------------------------------------------------------------
    def _parse_group(self, depth: int) -> _Node | None:
        p = self.p
        start = self.i
        i = start + 1
        zero_width = False
        atomic = False
        if p.startswith("?", i):
            if p.startswith("?:", i):
                i += 2
            elif p.startswith("?P<", i):
                end = p.find(">", i + 3)
                if end < 0:
                    raise _RegexParseError("Kapanmamış grup adı.", start)
                i = end + 1
            elif p.startswith("?P=", i):
                end = p.find(")", i + 3)
                if end < 0:
                    raise _RegexParseError("Kapanmamış adlandırılmış geri başvuru.", start)
                self.i = end + 1
                return _Node("backref", start)
            elif p.startswith("?=", i) or p.startswith("?!", i):
                zero_width = True
                i += 2
            elif p.startswith("?<=", i) or p.startswith("?<!", i):
                zero_width = True
                i += 3
            elif p.startswith("?<", i) or p.startswith("?'", i):
                closing = ">" if p[i + 1] == "<" else "'"
                end = p.find(closing, i + 2)
                if end < 0:
                    raise _RegexParseError("Kapanmamış grup adı.", start)
                i = end + 1
            elif p.startswith("?>", i):
                atomic = True
                i += 2
            elif p.startswith("?#", i):
                end = p.find(")", i)
                if end < 0:
                    raise _RegexParseError("Kapanmamış yorum grubu.", start)
                self.i = end + 1
                return None
            elif p.startswith("?(", i):
                raise _RegexParseError("Koşullu gruplar yapısal analizde desteklenmiyor.", start)
            else:
                match = _INLINE_FLAGS_RE.match(p, i)
                if not match or (not match.group(1) and not match.group(2)):
                    raise _RegexParseError("Tanınmayan grup sözdizimi '(?'.", start)
                if "x" in (match.group(1) or ""):
                    self.verbose = True
                if match.group(3) == ")":
                    self.i = match.end()
                    return None
                i = match.end()
        self.i = i
        alts = self._parse_alternation(depth + 1)
        if self.i >= self.n or p[self.i] != ")":
            raise _RegexParseError("Kapanmamış grup '('.", start)
        self.i += 1
        return _Node("group", start, alts=alts, zero_width=zero_width, atomic=atomic)


# Örtüşme hesabı için örnek karakter evreni: ASCII + temsilî Unicode + desendeki literaller.
_SAMPLE_EXTRAS = "\u00a0\u00e7\u00f6\u00fc\u011f\u0131\u0130\u015f\u00e9\u00df\u0430\u0663\u2028\u3000\u4e00\U0001F600"


def _assign_masks(charsets: list[_CharSet]) -> int:
    universe = [chr(code) for code in range(128)]
    universe.extend(_SAMPLE_EXTRAS)
    seen = set(universe)
    extras = 0
    for charset in charsets:
        for literal in charset.literals():
            if literal not in seen and extras < _REDOS_MAX_EXTRA_SAMPLES:
                seen.add(literal)
                universe.append(literal)
                extras += 1
    cache: dict[tuple[tuple[tuple[str, ...], ...], bool], int] = {}
    for charset in charsets:
        key = (charset.items, charset.negated)
        mask = cache.get(key)
        if mask is None:
            mask = 0
            bit = 1
            for char in universe:
                if charset.matches(char):
                    mask |= bit
                bit <<= 1
            cache[key] = mask
        charset.mask = mask
    return (1 << len(universe)) - 1


class _RedosAnalyzer:
    def __init__(self, pattern: str, full_mask: int) -> None:
        self.pattern = pattern
        self.full = full_mask
        self.issues: list[dict[str, Any]] = []
        self._seen: set[tuple[str, int]] = set()
        self._mask_cache: dict[int, int] = {}
        self._empty_cache: dict[int, bool] = {}
        self._first_cache: dict[int, int] = {}
        self._last_cache: dict[int, int] = {}
        self._unbounded_inside_cache: dict[int, bool] = {}

    # --- yardımcılar --------------------------------------------------------------
    @staticmethod
    def unbounded(node: _Node) -> bool:
        return node.qmax is None and not node.possessive

    def snippet(self, position: int) -> str:
        return self.pattern[position:position + 40]

    def add(self, kind: str, risk: str, position: int, detail: str) -> None:
        key = (kind, position)
        if key in self._seen:
            return
        self._seen.add(key)
        self.issues.append({"kind": kind, "risk": risk, "detail": detail, "position": position})

    def node_mask(self, node: _Node) -> int:
        key = id(node)
        cached = self._mask_cache.get(key)
        if cached is not None:
            return cached
        if node.kind == "set" and node.charset is not None:
            mask = node.charset.mask
        elif node.kind == "backref":
            mask = self.full
        elif node.kind == "group" and not node.zero_width:
            mask = 0
            for alt in node.alts:
                for child in alt:
                    mask |= self.node_mask(child)
        else:
            mask = 0
        self._mask_cache[key] = mask
        return mask

    def can_be_empty(self, node: _Node) -> bool:
        key = id(node)
        cached = self._empty_cache.get(key)
        if cached is not None:
            return cached
        if node.qmin == 0 or node.kind in ("anchor", "backref"):
            result = True
        elif node.kind == "group":
            result = node.zero_width or any(
                all(self.can_be_empty(child) for child in alt) for alt in node.alts
            )
        else:
            result = False
        self._empty_cache[key] = result
        return result

    def seq_first(self, sequence: list[_Node]) -> int:
        mask = 0
        for node in sequence:
            mask |= self.node_first(node)
            if not self.can_be_empty(node):
                break
        return mask

    def seq_last(self, sequence: list[_Node]) -> int:
        mask = 0
        for node in reversed(sequence):
            mask |= self.node_last(node)
            if not self.can_be_empty(node):
                break
        return mask

    def node_first(self, node: _Node) -> int:
        if node.kind == "set" and node.charset is not None:
            return node.charset.mask
        if node.kind == "backref":
            return self.full
        if node.kind != "group" or node.zero_width:
            return 0
        key = id(node)
        cached = self._first_cache.get(key)
        if cached is None:
            cached = 0
            for alt in node.alts:
                cached |= self.seq_first(alt)
            self._first_cache[key] = cached
        return cached

    def node_last(self, node: _Node) -> int:
        if node.kind == "set" and node.charset is not None:
            return node.charset.mask
        if node.kind == "backref":
            return self.full
        if node.kind != "group" or node.zero_width:
            return 0
        key = id(node)
        cached = self._last_cache.get(key)
        if cached is None:
            cached = 0
            for alt in node.alts:
                cached |= self.seq_last(alt)
            self._last_cache[key] = cached
        return cached

    def contains_unbounded(self, node: _Node) -> bool:
        key = id(node)
        cached = self._unbounded_inside_cache.get(key)
        if cached is not None:
            return cached
        if self.unbounded(node):
            result = True
        elif node.kind == "group" and not node.atomic and not node.zero_width:
            result = any(self.contains_unbounded(child) for alt in node.alts for child in alt)
        else:
            result = False
        self._unbounded_inside_cache[key] = result
        return result

    # --- denetimler -----------------------------------------------------------------
    def check_group(self, node: _Node) -> None:
        if node.zero_width or node.atomic or not self.unbounded(node):
            return
        # (1) İç içe sınırsız niceleyici: (a+)+, (a*)*, ([a-z]+)*, (\w+\s?)+
        for alt in node.alts:
            inner = [child for child in alt if self.contains_unbounded(child)]
            if not inner:
                continue
            inner_ids = {id(child) for child in inner}
            inner_mask = 0
            for child in inner:
                inner_mask |= self.node_mask(child)
            pinned = False
            for child in alt:
                if id(child) in inner_ids or self.can_be_empty(child):
                    continue
                child_mask = self.node_mask(child)
                # Zorunlu ve iç niceleyiciyle ayrık bir ayraç (ör. (\d+\.)* içindeki '.')
                # yineleme sınırlarını sabitler; belirsizlik oluşmaz.
                if child_mask and not (child_mask & inner_mask):
                    pinned = True
                    break
            if not pinned:
                self.add(
                    "nested_quantifier",
                    "high",
                    node.pos,
                    f"İç içe sınırsız niceleyici: konum {node.pos} ('{self.snippet(node.pos)}') grubu "
                    "kendi içinde '+'/'*' barındırıyor ve kendisi de sınırsız tekrarlanıyor; eşleşmeyen "
                    "girdide üstel geri izleme oluşabilir.",
                )
                break
        # (2) Sınırsız tekrar altında örtüşen alternatifler: (a|a)*, (a|ab)*, (\w|\d)+, (.|\s)*
        if len(node.alts) >= 2:
            seen_mask = 0
            for alt in node.alts:
                first = self.seq_first(alt)
                if first & seen_mask:
                    self.add(
                        "overlapping_alternation",
                        "high",
                        node.pos,
                        f"Örtüşen alternatifler: konum {node.pos} ('{self.snippet(node.pos)}') grubundaki "
                        "seçenekler aynı karakterle başlayabiliyor ve grup sınırsız tekrarlanıyor; aynı "
                        "girdi çok sayıda yoldan eşleşebildiği için üstel geri izleme riski var.",
                    )
                    break
                seen_mask |= first

    def check_adjacent(self, sequence: list[_Node]) -> None:
        # (3) Ardışık, örtüşen sınırsız niceleyiciler: \d+\d+, \w*\w*, .*.*=.*
        count = len(sequence)
        for index, first in enumerate(sequence):
            if not self.unbounded(first):
                continue
            first_all = self.node_mask(first)
            if not first_all:
                continue
            first_last = self.node_last(first)
            j = index + 1
            while j < count:
                other = sequence[j]
                if self.unbounded(other):
                    if (first_last & self.node_mask(other)) and (self.node_first(other) & first_all):
                        self.add(
                            "adjacent_overlap",
                            "medium",
                            first.pos,
                            f"Ardışık örtüşen niceleyiciler: konum {first.pos} ('{self.snippet(first.pos)}') "
                            f"ve konum {other.pos} aynı karakterleri tüketebiliyor; eşleşmeyen girdide "
                            "polinom (ör. O(n²)) geri izleme oluşabilir.",
                        )
                        break
                if not self.can_be_empty(other):
                    break
                j += 1

    def walk(self, sequence: list[_Node]) -> None:
        self.check_adjacent(sequence)
        for node in sequence:
            if node.kind == "group":
                self.check_group(node)
                for alt in node.alts:
                    self.walk(alt)

    def star_height(self, node: _Node) -> int:
        inner = 0
        if node.kind == "group":
            for alt in node.alts:
                for child in alt:
                    inner = max(inner, self.star_height(child))
        return inner + (1 if node.qmax is None else 0)


def _redos_parse_error(preview: str, message: str, position: int) -> dict[str, Any]:
    return {
        "pattern": preview,
        "vulnerable": False,
        "risk": "none",
        "issues": [
            {
                "kind": "parse_error",
                "risk": "none",
                "detail": f"Desen yapısal olarak çözümlenemedi: {message}",
                "position": int(position),
            }
        ],
        "star_height": 0,
    }


def analyze_regex_redos(pattern: str, *, verbose: bool = False) -> dict[str, Any]:
    """Düzenli ifadeyi ÇALIŞTIRMADAN yapısal ReDoS analizi yapar.

    Hatalı desenlerde istisna fırlatmaz; ``parse_error`` sorunu ile vulnerable=False döner.
    5.000 karakterden uzun desenler ve metin olmayan girdiler ValueError üretir.
    """
    if not isinstance(pattern, str):
        raise ValueError("Düzenli ifade deseni metin (str) olmalıdır.")
    if len(pattern) > REDOS_MAX_PATTERN_CHARS:
        raise ValueError(
            f"Düzenli ifade deseni güvenli uzunluk sınırını ({REDOS_MAX_PATTERN_CHARS} karakter) aşıyor."
        )
    preview = pattern[:_REDOS_PATTERN_PREVIEW]
    try:
        parser = _RegexParser(pattern, verbose=bool(verbose))
        root = parser.parse()
        full_mask = _assign_masks(parser.charsets)
        analyzer = _RedosAnalyzer(pattern, full_mask)
        analyzer.walk([root])
        star_height = analyzer.star_height(root)
    except _RegexParseError as exc:
        return _redos_parse_error(preview, exc.message, exc.position)
    except Exception as exc:  # savunma amaçlı: hatalı desen asla istisna sızdırmamalı
        return _redos_parse_error(preview, f"Beklenmeyen çözümleme hatası ({type(exc).__name__}).", 0)

    issues = sorted(analyzer.issues, key=lambda item: (item["position"], item["kind"]))
    if any(issue["risk"] == "high" for issue in issues):
        risk = "high"
    elif any(issue["risk"] == "medium" for issue in issues):
        risk = "medium"
    else:
        risk = "none"
    return {
        "pattern": preview,
        "vulnerable": risk != "none",
        "risk": risk,
        "issues": issues,
        "star_height": star_height,
    }


# ======================================================================================
# Kaynak kod denetimi yardımcıları
# ======================================================================================

def _language_for(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in _JS_EXTENSIONS:
        return "js"
    return {
        ".py": "python",
        ".go": "go",
        ".java": "jvm",
        ".kt": "jvm",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
    }.get(ext, "any")


def _lang(language: str, *targets: str) -> bool:
    return language == "any" or language in targets


def _is_comment_line(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith(("#", "//", "/*", "*"))


class _LineIndex:
    def __init__(self, content: str) -> None:
        self.starts = [0]
        position = content.find("\n")
        while position >= 0:
            self.starts.append(position + 1)
            position = content.find("\n", position + 1)

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, max(0, offset))


def _call_text(content: str, open_index: int, max_lines: int = 8, max_chars: int = 4_000) -> tuple[str, bool]:
    """Açılış parantezinden eşleşen kapanışa kadar metni döndürür (dizgeler atlanır)."""
    depth = 0
    index = open_index
    newlines = 0
    quote: str | None = None
    limit = min(len(content), open_index + max_chars)
    while index < limit:
        char = content[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote or (char == "\n" and quote != "`"):
                quote = None
        elif char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth <= 0:
                return content[open_index:index + 1], True
        if char == "\n":
            newlines += 1
            if newlines >= max_lines:
                break
        index += 1
    return content[open_index:index], False


def _top_level_commas(call: str) -> int:
    depth = 0
    quote: str | None = None
    count = 0
    index = 0
    while index < len(call):
        char = call[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 1:
            count += 1
        index += 1
    return count


def _read_string_literal(
    content: str,
    start: int,
    quote: str,
    *,
    verbatim: bool = False,
    max_chars: int = REDOS_MAX_PATTERN_CHARS * 2,
) -> tuple[str, int] | None:
    """`start` açılış tırnağının hemen sonrasıdır. (değer, bitiş_konumu) döndürür."""
    length = len(content)
    index = start
    triple = len(quote) == 3
    limit = min(length, start + max_chars)
    while index < limit:
        char = content[index]
        if verbatim:
            if char == '"':
                if index + 1 < length and content[index + 1] == '"':
                    index += 2
                    continue
                return content[start:index], index + 1
            index += 1
            continue
        if char == "\\" and quote != "`":
            index += 2
            continue
        if char == "\n" and not triple and quote != "`":
            return None
        if content.startswith(quote, index):
            return content[start:index], index + len(quote)
        index += 1
    return None


_STRING_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)
_STRING_ESCAPES = {"\\": "\\", "'": "'", '"': '"', "`": "`", "/": "/", "n": "\n", "t": "\t", "r": "\r"}


def _unescape_string(value: str) -> str:
    return _STRING_ESCAPE_RE.sub(lambda m: _STRING_ESCAPES.get(m.group(1), "\\" + m.group(1)), value)


_PHP_DELIMITER_PAIRS = {"(": ")", "{": "}", "[": "]", "<": ">"}


def _strip_php_delimiters(value: str) -> tuple[str, str] | None:
    text = value.strip()
    if len(text) < 2:
        return None
    opener = text[0]
    if opener.isalnum() or opener.isspace() or opener == "\\":
        return None
    closer = _PHP_DELIMITER_PAIRS.get(opener, opener)
    end = text.rfind(closer)
    if end <= 0:
        return None
    return text[1:end], text[end + 1:]


# Düzenli ifade çıkarımı
_PY_RE_CALL = re.compile(
    r"\b(?:re|regex)\.(?:compile|match|search|fullmatch|sub|subn|findall|finditer|split)\s*\(\s*"
    r"(?P<prefix>[rRbBuUfF]{0,2})(?P<quote>'''|\"\"\"|'|\")"
)
_PY_VERBOSE_FLAG_RE = re.compile(r"\bre\.(?:X|VERBOSE)\b")
_JS_REGEXP_CTOR = re.compile(r"\b(?:new\s+)?RegExp\s*\(\s*(?P<quote>['\"`])")
_GO_REGEXP = re.compile(
    r"\bregexp\.(?:MustCompile|Compile|MatchString|Match|MustCompilePOSIX|CompilePOSIX)\s*\(\s*(?P<quote>[`\"])"
)
_JAVA_PATTERN = re.compile(r"\bPattern\.(?:compile|matches)\s*\(\s*(?P<quote>\"\"\"|\")")
_DOTNET_KOTLIN_REGEX = re.compile(r"\b(?:new\s+)?Regex\s*\(\s*(?P<verbatim>@?)(?P<quote>\"\"\"|\")")
_DOTNET_STATIC_REGEX = re.compile(
    r"\bRegex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\(\s*[^,()\n]+,\s*(?P<verbatim>@?)(?P<quote>\")"
)
_RUBY_REGEXP = re.compile(r"\bRegexp\.new\s*\(\s*(?P<quote>['\"])")
_PHP_PREG = re.compile(r"\bpreg_(?:match_all|match|replace_callback|replace|split|grep)\s*\(\s*(?P<quote>['\"])")


def _has_concat_tail(content: str, offset: int) -> bool:
    """Return whether a literal is followed by concatenation or another literal."""
    cursor = offset
    while cursor < len(content) and content[cursor].isspace():
        cursor += 1
    if cursor < len(content) and content[cursor] in "+%":
        return True
    if content.startswith(".format", cursor):
        end = cursor + len(".format")
        if end == len(content) or not (content[end].isalnum() or content[end] == "_"):
            return True
    prefix = cursor
    while prefix < len(content) and prefix < cursor + 2 and content[prefix] in "rRbBuUfF":
        prefix += 1
    return prefix < len(content) and content[prefix] in "'\""


def _iter_js_regex_literals(content: str):
    """Yield JavaScript regex literal bodies with a single forward-only scan."""
    length = len(content)
    cursor = 0
    while cursor < length:
        prefix_end = -1
        char = content[cursor]
        if char in "[=(,:":
            prefix_end = cursor + 1
        elif content.startswith("return", cursor):
            before_ok = cursor == 0 or not (content[cursor - 1].isalnum() or content[cursor - 1] == "_")
            word_end = cursor + len("return")
            after_ok = word_end == length or not (content[word_end].isalnum() or content[word_end] == "_")
            if before_ok and after_ok:
                prefix_end = word_end
        if prefix_end < 0:
            cursor += 1
            continue

        slash = prefix_end
        while slash < length and content[slash].isspace():
            slash += 1
        if slash >= length or content[slash] != "/" or (slash + 1 < length and content[slash + 1] in "/*"):
            cursor = prefix_end
            continue

        body_start = slash + 1
        scan = body_start
        has_body = False
        closed = False
        while scan < length:
            current = content[scan]
            if current == "\n" or current == "\r":
                break
            if current == "\\":
                if scan + 1 >= length or content[scan + 1] in "\r\n":
                    break
                has_body = True
                scan += 2
                continue
            if current == "[":
                class_cursor = scan + 1
                while class_cursor < length:
                    class_char = content[class_cursor]
                    if class_char in "\r\n":
                        break
                    if class_char == "\\":
                        if class_cursor + 1 >= length or content[class_cursor + 1] in "\r\n":
                            break
                        class_cursor += 2
                        continue
                    if class_char == "]":
                        has_body = True
                        scan = class_cursor + 1
                        break
                    class_cursor += 1
                else:
                    scan = length
                    break
                if scan == class_cursor + 1:
                    continue
                scan = class_cursor
                break
            if current == "/":
                if has_body:
                    flags_end = scan + 1
                    while flags_end < length and "a" <= content[flags_end] <= "z":
                        flags_end += 1
                    yield body_start, content[body_start:scan]
                    cursor = flags_end
                    closed = True
                break
            has_body = True
            scan += 1

        if not closed:
            newline = content.find("\n", max(scan, body_start))
            cursor = length if newline < 0 else newline + 1


def _extract_regex_literals(content: str, language: str) -> list[tuple[int, str, bool, str]]:
    """(konum, desen, verbose, motor) listesi döndürür; motor 'backtracking' veya 're2'."""
    found: list[tuple[int, str, bool, str]] = []

    def read(match: re.Match[str], *, verbatim: bool = False) -> tuple[str, int] | None:
        literal = _read_string_literal(content, match.end(), match.group("quote"), verbatim=verbatim)
        if literal is None:
            return None
        value, end = literal
        if _has_concat_tail(content, end):
            return None  # birleştirilmiş/dinamik desen; parça analizi yanıltıcı olur
        return value, end

    if _lang(language, "python"):
        for match in _PY_RE_CALL.finditer(content):
            prefix = match.group("prefix").lower()
            if "f" in prefix:
                continue
            literal = read(match)
            if literal is None:
                continue
            value, end = literal
            pattern = value if "r" in prefix else _unescape_string(value)
            call_tail = content[end:end + 160].split(")", 1)[0]
            found.append((match.start(), pattern, bool(_PY_VERBOSE_FLAG_RE.search(call_tail)), "backtracking"))

    if _lang(language, "js"):
        for match in _JS_REGEXP_CTOR.finditer(content):
            literal = read(match)
            if literal is None:
                continue
            value, _end = literal
            if match.group("quote") == "`" and "${" in value:
                continue
            found.append((match.start(), _unescape_string(value), False, "backtracking"))
    if language == "js":
        for offset, body in _iter_js_regex_literals(content):
            found.append((offset, body, False, "backtracking"))

    if _lang(language, "go"):
        for match in _GO_REGEXP.finditer(content):
            literal = read(match)
            if literal is None:
                continue
            value, _end = literal
            pattern = value if match.group("quote") == "`" else _unescape_string(value)
            found.append((match.start(), pattern, False, "re2"))

    if _lang(language, "jvm"):
        for match in _JAVA_PATTERN.finditer(content):
            literal = read(match)
            if literal is None:
                continue
            found.append((match.start(), _unescape_string(literal[0]), False, "backtracking"))

    if _lang(language, "jvm", "csharp"):
        for regex in (_DOTNET_KOTLIN_REGEX, _DOTNET_STATIC_REGEX):
            for match in regex.finditer(content):
                verbatim = match.group("verbatim") == "@"
                literal = read(match, verbatim=verbatim)
                if literal is None:
                    continue
                value = literal[0]
                raw = verbatim or match.group("quote") == '"""'
                found.append((match.start(), value if raw else _unescape_string(value), False, "backtracking"))

    if _lang(language, "ruby"):
        for match in _RUBY_REGEXP.finditer(content):
            literal = read(match)
            if literal is None:
                continue
            found.append((match.start(), _unescape_string(literal[0]), False, "backtracking"))

    if _lang(language, "php"):
        for match in _PHP_PREG.finditer(content):
            literal = read(match)
            if literal is None:
                continue
            stripped = _strip_php_delimiters(_unescape_string(literal[0]))
            if stripped is None:
                continue
            pattern, modifiers = stripped
            found.append((match.start(), pattern, "x" in modifiers, "backtracking"))

    found.sort(key=lambda item: item[0])
    return found


def _make_dos_finding(
    *,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
    discriminator: str = "",
) -> dict[str, Any]:
    clean_ev = (evidence or "").strip()[:320]
    reference = f"OWASP API4:2023 Unrestricted Resource Consumption · {cwe}"
    item = _finding(
        severity,
        "availability",
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, discriminator or cwe),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    item["owasp"] = "OWASP API4:2023"
    return item


class _DosContext:
    def __init__(self, content: str, filename: str, language: str) -> None:
        self.content = content
        self.filename = filename
        self.language = language
        self.lines = content.split("\n")
        self.index = _LineIndex(content)
        self.findings: list[dict[str, Any]] = []
        self._seen: set[tuple[str, str, int, str]] = set()

    def line_text(self, line_no: int) -> str:
        if 0 < line_no <= len(self.lines):
            return self.lines[line_no - 1].rstrip("\r")
        return ""

    def code_line(self, offset: int) -> int | None:
        line_no = self.index.line(offset)
        if _is_comment_line(self.line_text(line_no)):
            return None
        return line_no

    def window(self, line_no: int, before: int, after: int) -> str:
        start = max(0, line_no - 1 - before)
        return "\n".join(self.lines[start:line_no + after])

    def emit(
        self,
        *,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        cwe: str,
        control_id: str,
        line_no: int,
        discriminator: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        key = (control_id, cwe, int(line_no), discriminator)
        if key in self._seen:
            return
        self._seen.add(key)
        finding = _make_dos_finding(
            severity=severity,
            title=title,
            description=description,
            evidence=self.line_text(line_no),
            recommendation=recommendation,
            cwe=cwe,
            control_id=control_id,
            filename=self.filename,
            line=int(line_no),
            discriminator=discriminator,
        )
        if extra:
            finding.update(extra)
        self.findings.append(finding)


# --------------------------------------------------------------------------------------
# 1. ReDoS (SNIPER-DOS-01, CWE-1333)
# --------------------------------------------------------------------------------------

def _detect_redos(ctx: _DosContext) -> None:
    analyzed = 0
    for offset, pattern, verbose, engine in _extract_regex_literals(ctx.content, ctx.language):
        if analyzed >= _MAX_REGEX_PER_FILE:
            break
        line_no = ctx.code_line(offset)
        if line_no is None:
            continue
        analyzed += 1
        try:
            analysis = analyze_regex_redos(pattern, verbose=verbose)
        except ValueError:
            continue
        if not analysis["vulnerable"]:
            continue
        details = " ".join(
            issue["detail"] for issue in analysis["issues"] if issue["kind"] != "parse_error"
        )[:700]
        severity = "high" if analysis["risk"] == "high" else "medium"
        description = (
            f"Desen `{analysis['pattern'][:120]}` yapısal olarak felaket geri izlemeye açık. {details} "
            "Saldırgan kontrollü kısa bir girdi, eşleştirme sırasında CPU'yu uzun süre kilitleyebilir."
        )
        if engine == "re2":
            severity = "info"
            description += (
                " Not: Go regexp paketi RE2 tabanlıdır ve doğrusal zamanda çalışır; risk yalnızca desen "
                "geri izlemeli bir motora (PCRE, Java, JS, Python) taşınırsa ortaya çıkar."
            )
        ctx.emit(
            severity=severity,
            title="Felaket geri izlemeye açık düzenli ifade (ReDoS)",
            description=description,
            recommendation=(
                "İç içe/örtüşen niceleyicileri kaldırın (ör. (a+)+ yerine a+), alternatifleri ayrık yapın, "
                "girdi uzunluğunu eşleştirmeden önce sınırlayın; mümkünse RE2 tabanlı motor, atomik grup veya "
                "possessive niceleyici kullanın ve eşleştirmeye zaman aşımı uygulayın."
            ),
            cwe="CWE-1333",
            control_id="SNIPER-DOS-01",
            line_no=line_no,
            discriminator=analysis["pattern"][:80],
            extra={
                "redos": {
                    "pattern": analysis["pattern"],
                    "risk": analysis["risk"],
                    "star_height": analysis["star_height"],
                    "engine": engine,
                    "regex_issues": analysis["issues"],
                }
            },
        )


def _detect_dynamic_regex(ctx: _DosContext) -> None:
    """Kullanıcı girdisinden oluşturulan desen: yapısal analiz yapılamaz, akış izlenir."""
    analysis = taint_flow.analyze_source(ctx.content, ctx.filename)
    if analysis is None:
        return
    for flow in analysis.flows_of("regex", "request"):
        ctx.emit(
            severity="high",
            title="Kullanıcı girdisinden dinamik düzenli ifade oluşturuluyor (ReDoS / regex enjeksiyonu)",
            description=(
                "İstek verisi kaçışlanmadan düzenli ifade desenine dönüştürülüyor. Saldırgan felaket geri "
                "izlemeye yol açan bir desen (ör. (a+)+$) göndererek CPU'yu kilitleyebilir veya desen "
                f"anlamını değiştirebilir. Veri akışı: {flow.describe()}."
            ),
            recommendation=(
                "Kullanıcı girdisini desen olarak kullanmayın; gerekiyorsa re.escape() / escapeRegExp ile "
                "kaçışlayın, uzunluğu sınırlayın ve RE2 gibi doğrusal zamanlı bir motor tercih edin."
            ),
            cwe="CWE-1333",
            control_id="SNIPER-DOS-01",
            line_no=flow.line,
            discriminator=f"taint:{flow.source}",
            extra={"taint_flow": flow.as_dict()},
        )


# --------------------------------------------------------------------------------------
# 2. HTTP istemci zaman aşımı (SNIPER-DOS-02, CWE-400)
# --------------------------------------------------------------------------------------

_PY_HTTP_CALL = re.compile(
    r"\b(?P<lib>requests|httpx)\.(?P<verb>get|post|put|patch|delete|head|options|request|stream)\s*\("
)
_PY_HTTPX_CLIENT = re.compile(r"\bhttpx\.(?:Async)?Client\s*\(")
_PY_URLOPEN = re.compile(r"(?<![\w.])(?:urllib\.request\.|request\.)?urlopen\s*\(")
_GO_HTTP_DEFAULT = re.compile(r"\bhttp\.(?:Get|Post|PostForm|Head)\s*\(")
_GO_HTTP_CLIENT = re.compile(r"\bhttp\.Client\s*\{")
_JS_AXIOS_CREATE = re.compile(r"\baxios\.create\s*\(")
_TIMEOUT_KW_RE = re.compile(r"\btimeout\s*=")
_TIMEOUT_NONE_RE = re.compile(r"\btimeout\s*=\s*None\b")

_HTTP_TIMEOUT_TITLE = "HTTP isteğinde zaman aşımı (timeout) tanımlı değil"
_HTTP_TIMEOUT_RECOMMENDATION = (
    "Her dış HTTP çağrısına bağlantı ve okuma zaman aşımı verin (ör. requests.get(url, timeout=(3.05, 10))); "
    "istemci düzeyinde varsayılan zaman aşımı ve devre kesici kullanın."
)


def _detect_http_timeouts(ctx: _DosContext) -> None:
    content = ctx.content
    control = "SNIPER-DOS-02"
    cwe = "CWE-400"
    if _lang(ctx.language, "python"):
        for match in _PY_HTTP_CALL.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            call, _closed = _call_text(content, match.end() - 1)
            if "**" in call:
                continue
            lib = match.group("lib")
            target = f"{lib}.{match.group('verb')}"
            if _TIMEOUT_NONE_RE.search(call):
                ctx.emit(
                    severity="medium",
                    title=_HTTP_TIMEOUT_TITLE,
                    description=f"{target}(..., timeout=None) zaman aşımını açıkça kapatıyor; yavaş/yanıt vermeyen uzak sunucu iş parçacıklarını süresiz bloke eder.",
                    recommendation=_HTTP_TIMEOUT_RECOMMENDATION,
                    cwe=cwe,
                    control_id=control,
                    line_no=line_no,
                )
            elif not _TIMEOUT_KW_RE.search(call):
                if lib == "requests":
                    ctx.emit(
                        severity="medium",
                        title=_HTTP_TIMEOUT_TITLE,
                        description=f"{target}() çağrısında timeout yok; requests varsayılan olarak süresiz bekler ve yavaş bir uç nokta çalışan havuzunu tüketerek hizmet reddine yol açar.",
                        recommendation=_HTTP_TIMEOUT_RECOMMENDATION,
                        cwe=cwe,
                        control_id=control,
                        line_no=line_no,
                    )
                else:
                    ctx.emit(
                        severity="low",
                        title=_HTTP_TIMEOUT_TITLE,
                        description=f"{target}() çağrısında açık timeout yok. httpx varsayılan 5 sn zaman aşımı uygular; iş yüküne uygun açık değer önerilir.",
                        recommendation=_HTTP_TIMEOUT_RECOMMENDATION,
                        cwe=cwe,
                        control_id=control,
                        line_no=line_no,
                    )
        for match in _PY_HTTPX_CLIENT.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            call, _closed = _call_text(content, match.end() - 1)
            if "**" in call:
                continue
            if _TIMEOUT_NONE_RE.search(call):
                ctx.emit(
                    severity="medium",
                    title=_HTTP_TIMEOUT_TITLE,
                    description="httpx istemcisi timeout=None ile oluşturulmuş; tüm istekler süresiz bekleyebilir.",
                    recommendation=_HTTP_TIMEOUT_RECOMMENDATION,
                    cwe=cwe,
                    control_id=control,
                    line_no=line_no,
                )
            elif not _TIMEOUT_KW_RE.search(call):
                ctx.emit(
                    severity="low",
                    title=_HTTP_TIMEOUT_TITLE,
                    description="httpx.Client/AsyncClient açık timeout= olmadan oluşturulmuş (varsayılan 5 sn); istemci düzeyinde bilinçli bir değer belirleyin.",
                    recommendation=_HTTP_TIMEOUT_RECOMMENDATION,
                    cwe=cwe,
                    control_id=control,
                    line_no=line_no,
                )
        if "urllib" in content:
            for match in _PY_URLOPEN.finditer(content):
                line_no = ctx.code_line(match.start())
                if line_no is None:
                    continue
                call, _closed = _call_text(content, match.end() - 1)
                if "**" in call or _TIMEOUT_KW_RE.search(call) or _top_level_commas(call) >= 2:
                    continue
                ctx.emit(
                    severity="medium",
                    title=_HTTP_TIMEOUT_TITLE,
                    description="urllib.request.urlopen() timeout olmadan çağrılıyor; küresel soket varsayılanı süresizdir.",
                    recommendation=_HTTP_TIMEOUT_RECOMMENDATION,
                    cwe=cwe,
                    control_id=control,
                    line_no=line_no,
                )
    if _lang(ctx.language, "go"):
        if "DefaultClient.Timeout" not in content:
            for match in _GO_HTTP_DEFAULT.finditer(content):
                line_no = ctx.code_line(match.start())
                if line_no is None:
                    continue
                ctx.emit(
                    severity="medium",
                    title=_HTTP_TIMEOUT_TITLE,
                    description=f"{match.group(0).rstrip('( ')}() http.DefaultClient kullanır ve DefaultClient'ın zaman aşımı yoktur.",
                    recommendation="Timeout alanı ayarlanmış özel bir http.Client{Timeout: 10 * time.Second} kullanın.",
                    cwe=cwe,
                    control_id=control,
                    line_no=line_no,
                )
        for match in _GO_HTTP_CLIENT.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            body, _closed = _call_text(content, match.end() - 1)
            if "Timeout" in body:
                continue
            ctx.emit(
                severity="medium",
                title=_HTTP_TIMEOUT_TITLE,
                description="http.Client{} Timeout alanı olmadan oluşturulmuş; istekler süresiz bekleyebilir.",
                recommendation="http.Client{Timeout: 10 * time.Second} gibi açık bir zaman aşımı tanımlayın.",
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )
    if _lang(ctx.language, "js"):
        for match in _JS_AXIOS_CREATE.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            call, _closed = _call_text(content, match.end() - 1)
            if "timeout" in call:
                continue
            ctx.emit(
                severity="low",
                title=_HTTP_TIMEOUT_TITLE,
                description="axios.create() timeout olmadan çağrılıyor; axios varsayılan olarak süresiz bekler (timeout: 0).",
                recommendation="axios.create({ timeout: 10000 }) gibi açık bir zaman aşımı tanımlayın.",
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )


# --------------------------------------------------------------------------------------
# 3. Sıkıştırma bombası (SNIPER-DOS-03, CWE-409)
# --------------------------------------------------------------------------------------

_SIZE_GUARD_RE = re.compile(
    r"\bfile_size\b|\bcompress_size\b|\bMAX_[A-Z0-9_]+|"
    r"\bmax_(?:size|bytes|length|output|uncompressed|decompressed|file|total)\w*|"
    r"\b(?:size_limit|limit_bytes)\b|\bLimitReader\b|\bMaxBytesReader\b|\bmaxOutputLength\b|"
    r"\bUncompressedSize64\b|\bgetSize\s*\("
)
_PY_DECOMPRESS = re.compile(r"\b(?:zlib|gzip|bz2|lzma)\.decompress\s*\(")
_PY_COMPRESSED_OPEN_READ = re.compile(r"\b(?:gzip|bz2|lzma)\.open\s*\([^)\n]*\)\s*\.read\s*\(\s*\)")
_PY_WITH_COMPRESSED_OPEN = re.compile(r"\bwith\s+(?:gzip|bz2|lzma)\.open\s*\(")
_PY_ARCHIVE_OPEN = re.compile(r"\b(?:zipfile\.)?ZipFile\s*\(|\btarfile\.open\s*\(")
_ARCHIVE_EXTRACT_RE = re.compile(r"\.(?:extractall|extract|read)\s*\(")
_READ_ALL_RE = re.compile(r"\.read\s*\(\s*\)")
_JS_ZLIB_SYNC = re.compile(r"\bzlib\.(?:gunzipSync|inflateSync|inflateRawSync|unzipSync|brotliDecompressSync)\s*\(")
_GO_DECOMPRESS = re.compile(r"\b(?:gzip|zlib|flate|zip)\.(?:NewReader|OpenReader)\s*\(")
_GO_READ_ALL = re.compile(r"\b(?:io|ioutil)\.(?:ReadAll|Copy)\s*\(")
_JAVA_DECOMPRESS = re.compile(r"\bnew\s+(?:GZIPInputStream|ZipInputStream|InflaterInputStream)\s*\(")
_JAVA_READ_ALL = re.compile(r"\.readAllBytes\s*\(|\.transferTo\s*\(|\bIOUtils\.(?:toByteArray|copy)\s*\(")

_BOMB_TITLE = "Sıkıştırma bombası (Zip/Gzip Bomb) boyut sınırı yok"
_BOMB_RECOMMENDATION = (
    "Açılmış çıktı boyutuna üst sınır koyun: zlib.decompressobj().decompress(veri, max_length) ile parça parça "
    "açın, ZipInfo.file_size / oran kontrolü yapın, Go'da io.LimitReader, Node'da maxOutputLength kullanın."
)


def _detect_decompression(ctx: _DosContext) -> None:
    content = ctx.content
    control = "SNIPER-DOS-03"
    cwe = "CWE-409"

    def guarded(line_no: int) -> bool:
        return bool(_SIZE_GUARD_RE.search(ctx.window(line_no, 10, 10)))

    def emit(line_no: int, description: str) -> None:
        ctx.emit(
            severity="medium",
            title=_BOMB_TITLE,
            description=description,
            recommendation=_BOMB_RECOMMENDATION,
            cwe=cwe,
            control_id=control,
            line_no=line_no,
        )

    if _lang(ctx.language, "python"):
        for match in _PY_DECOMPRESS.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None or guarded(line_no):
                continue
            emit(line_no, f"{match.group(0).rstrip('( ')}() çıktı boyutu sınırı olmadan tüm veriyi belleğe açar; birkaç KB'lık sıkıştırılmış girdi GB'larca belleğe genişleyebilir.")
        for match in _PY_COMPRESSED_OPEN_READ.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None or guarded(line_no):
                continue
            emit(line_no, "Sıkıştırılmış dosya boyut argümanı olmadan .read() ile tamamen belleğe açılıyor.")
        for match in _PY_WITH_COMPRESSED_OPEN.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None or guarded(line_no):
                continue
            if not _READ_ALL_RE.search(ctx.window(line_no, 0, 10)):
                continue
            emit(line_no, "Sıkıştırılmış dosya açıldıktan sonra boyut sınırı olmadan .read() ile tamamen belleğe okunuyor.")
        for match in _PY_ARCHIVE_OPEN.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None or guarded(line_no):
                continue
            if not _ARCHIVE_EXTRACT_RE.search(ctx.window(line_no, 0, 10)):
                continue
            emit(line_no, "Arşiv üyeleri file_size/compress_size veya toplam boyut kontrolü yapılmadan çıkarılıyor/okunuyor (zip/tar bombası).")
    if _lang(ctx.language, "js"):
        for match in _JS_ZLIB_SYNC.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            call, _closed = _call_text(content, match.end() - 1)
            if "maxOutputLength" in call or guarded(line_no):
                continue
            emit(line_no, f"{match.group(0).rstrip('( ')}() maxOutputLength olmadan çağrılıyor; olay döngüsü ve bellek sıkıştırma bombasıyla tüketilebilir.")
    if _lang(ctx.language, "go") and _GO_READ_ALL.search(content) and not _SIZE_GUARD_RE.search(content):
        for match in _GO_DECOMPRESS.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            emit(line_no, "Sıkıştırılmış akış io.LimitReader/boyut kontrolü olmadan io.ReadAll/io.Copy ile tamamen açılıyor.")
    if _lang(ctx.language, "jvm") and _JAVA_READ_ALL.search(content):
        for match in _JAVA_DECOMPRESS.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None or guarded(line_no):
                continue
            emit(line_no, "Sıkıştırılmış akış boyut sınırı olmadan readAllBytes/transferTo ile tamamen belleğe açılıyor.")


# --------------------------------------------------------------------------------------
# 4. XML varlık genişletme (SNIPER-DOS-04, CWE-776)
# --------------------------------------------------------------------------------------

_DEFUSEDXML_RE = re.compile(r"\bdefusedxml\b")
_RESOLVE_ENTITIES_FALSE_RE = re.compile(r"\bresolve_entities\s*=\s*False\b")
_PY_XML_ET = re.compile(
    r"\b(?:ET|ElementTree|etree|cElementTree)\.(?:fromstring|parse|XML|iterparse|fromstringlist)\s*\("
)
_PY_XML_MINIDOM = re.compile(r"\b(?:minidom|pulldom)\.(?:parseString|parse)\s*\(")
_PY_XML_SAX = re.compile(r"\bsax\.(?:parse|parseString|make_parser)\s*\(")
_PY_LXML_PARSER = re.compile(r"\betree\.XMLParser\s*\(")
_JAVA_XML_FACTORY = re.compile(r"\b(?:DocumentBuilderFactory|SAXParserFactory)\.newInstance\s*\(")

_XML_TITLE = "XML varlık genişletme (Billion Laughs) koruması yok"
_XML_RECOMMENDATION = (
    "Güvenilmeyen XML için defusedxml kullanın; lxml'de XMLParser(resolve_entities=False, no_network=True), "
    "Java'da 'http://apache.org/xml/features/disallow-doctype-decl' özelliğini true yapın."
)


def _detect_xml_entity_expansion(ctx: _DosContext) -> None:
    content = ctx.content
    control = "SNIPER-DOS-04"
    cwe = "CWE-776"
    if _lang(ctx.language, "python") and not _DEFUSEDXML_RE.search(content):
        lxml_safe = bool(_RESOLVE_ENTITIES_FALSE_RE.search(content))
        for regex in (_PY_XML_ET, _PY_XML_MINIDOM, _PY_XML_SAX):
            for match in regex.finditer(content):
                if regex is _PY_XML_ET and lxml_safe:
                    continue
                line_no = ctx.code_line(match.start())
                if line_no is None:
                    continue
                ctx.emit(
                    severity="medium",
                    title=_XML_TITLE,
                    description=(
                        f"{match.group(0).rstrip('( ')}() defusedxml olmadan çağrılıyor. İç içe varlık tanımları "
                        "(Billion Laughs) eski expat/lxml yapılandırmalarında belleği ve CPU'yu üstel olarak tüketir."
                    ),
                    recommendation=_XML_RECOMMENDATION,
                    cwe=cwe,
                    control_id=control,
                    line_no=line_no,
                )
        for match in _PY_LXML_PARSER.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            call, _closed = _call_text(content, match.end() - 1)
            if _RESOLVE_ENTITIES_FALSE_RE.search(call):
                continue
            ctx.emit(
                severity="medium",
                title=_XML_TITLE,
                description="lxml XMLParser resolve_entities=False olmadan oluşturulmuş; varlık genişletme açık kalır.",
                recommendation=_XML_RECOMMENDATION,
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )
    if _lang(ctx.language, "jvm") and "disallow-doctype-decl" not in content:
        for match in _JAVA_XML_FACTORY.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            ctx.emit(
                severity="medium",
                title=_XML_TITLE,
                description=f"{match.group(0).rstrip('( ')}() DOCTYPE yasaklanmadan kullanılıyor; DTD tabanlı varlık genişletme mümkündür.",
                recommendation=_XML_RECOMMENDATION,
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )


# --------------------------------------------------------------------------------------
# 5. Sınırsız istek gövdesi / yükleme (SNIPER-DOS-05, CWE-770)
# --------------------------------------------------------------------------------------

_FLASK_IMPORT_RE = re.compile(r"^[ \t]*(?:from[ \t]+flask[ \t]+import\b|import[ \t]+flask\b)", re.MULTILINE)
_FLASK_BODY_RE = re.compile(r"\brequest\.(?:files\b|get_data\s*\(|data\b)")
_EXPRESS_BODY_RE = re.compile(r"\b(?:express|bodyParser)\.(?:json|urlencoded|text|raw)\s*\(")
_MULTER_RE = re.compile(r"\bmulter\s*\(")
_DJANGO_UPLOAD_NONE_RE = re.compile(
    r"^[ \t]*(?:FILE_UPLOAD_MAX_MEMORY_SIZE|DATA_UPLOAD_MAX_MEMORY_SIZE|DATA_UPLOAD_MAX_NUMBER_FIELDS|"
    r"DATA_UPLOAD_MAX_NUMBER_FILES)[ \t]*=[ \t]*None\b",
    re.MULTILINE,
)
_GO_READALL_BODY_RE = re.compile(r"\b(?:io|ioutil)\.ReadAll\s*\(\s*\w+\.Body\s*\)")
_GO_BODY_LIMIT_RE = re.compile(r"\b(?:MaxBytesReader|LimitReader)\b")

_BODY_TITLE = "İstek gövdesi / dosya yükleme boyutu sınırsız"


def _detect_body_limits(ctx: _DosContext) -> None:
    content = ctx.content
    control = "SNIPER-DOS-05"
    cwe = "CWE-770"
    if _lang(ctx.language, "python"):
        if _FLASK_IMPORT_RE.search(content) and "MAX_CONTENT_LENGTH" not in content:
            for match in _FLASK_BODY_RE.finditer(content):
                line_no = ctx.code_line(match.start())
                if line_no is None:
                    continue
                ctx.emit(
                    severity="medium",
                    title=_BODY_TITLE,
                    description="Flask uygulaması istek gövdesini/dosyaları okuyor ancak dosyada MAX_CONTENT_LENGTH tanımlı değil; çok büyük gövdeler belleği ve diski tüketebilir.",
                    recommendation="app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 gibi bir üst sınır tanımlayın ve ters vekilde de gövde sınırı uygulayın.",
                    cwe=cwe,
                    control_id=control,
                    line_no=line_no,
                )
                break
        for match in _DJANGO_UPLOAD_NONE_RE.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            ctx.emit(
                severity="medium",
                title=_BODY_TITLE,
                description="Django yükleme/gövde sınırı None yapılarak devre dışı bırakılmış; sınırsız istek gövdesi bellek tüketimine yol açar.",
                recommendation="Django varsayılanlarını (2.5 MB, 1000 alan) koruyun veya iş ihtiyacına uygun sayısal bir sınır verin.",
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )
    if _lang(ctx.language, "js"):
        for match in _EXPRESS_BODY_RE.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            call, _closed = _call_text(content, match.end() - 1)
            if "limit" in call:
                continue
            ctx.emit(
                severity="low",
                title=_BODY_TITLE,
                description=f"{match.group(0).rstrip('( ')}() açık 'limit' olmadan kullanılıyor (varsayılan 100kb); uç nokta ihtiyacına göre bilinçli bir sınır belirleyin.",
                recommendation="express.json({ limit: '100kb' }) gibi uç noktaya uygun açık bir sınır tanımlayın.",
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )
        for match in _MULTER_RE.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            call, _closed = _call_text(content, match.end() - 1)
            if "limits" in call:
                continue
            ctx.emit(
                severity="medium",
                title=_BODY_TITLE,
                description="multer() 'limits' olmadan yapılandırılmış; dosya boyutu ve sayısı sınırsızdır, disk/bellek tüketilebilir.",
                recommendation="multer({ limits: { fileSize: 5 * 1024 * 1024, files: 5 } }) gibi sınırlar tanımlayın.",
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )
    if _lang(ctx.language, "go") and not _GO_BODY_LIMIT_RE.search(content):
        for match in _GO_READALL_BODY_RE.finditer(content):
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            ctx.emit(
                severity="medium",
                title=_BODY_TITLE,
                description="İstek gövdesi http.MaxBytesReader olmadan io.ReadAll ile tamamen belleğe okunuyor.",
                recommendation="r.Body = http.MaxBytesReader(w, r.Body, 1<<20) ile gövdeyi sınırlayın.",
                cwe=cwe,
                control_id=control,
                line_no=line_no,
            )


# --------------------------------------------------------------------------------------
# 6. Derin özyineleme / sonsuz döngü (SNIPER-DOS-06, CWE-674 / CWE-835)
# --------------------------------------------------------------------------------------

_RECURSION_LIMIT_RE = re.compile(r"\bsys\.setrecursionlimit\s*\(\s*(?P<value>\d[\d_]*)\s*\)")
_JSON_LOADS_RE = re.compile(r"\bjson\.loads?\s*\(")
_REQUEST_DATA_HINT_RE = re.compile(r"\brequest\b|\brecv\s*\(|\brfile\b|\bbody\b")
_INFINITE_LOOP_RE = re.compile(
    r"^[ \t]*(?:while[ \t]+(?:True|1)[ \t]*:|while[ \t]*\([ \t]*(?:true|1)[ \t]*\)|"
    r"for[ \t]*\{[ \t\r]*$|for[ \t]*\([ \t]*;[ \t]*;[ \t]*\))",
    re.MULTILINE,
)
_NET_READ_RE = re.compile(r"\.(?:recv|recv_into|recvfrom|read|readline|readinto|Read|ReadString|ReadBytes)\s*\(")
_LOOP_EXIT_RE = re.compile(r"\b(?:break|return|raise|throw|exit|goto)\b")
_TIMEOUT_HINT_RE = re.compile(r"[Tt]imeout|SetDeadline|SetReadDeadline|setSoTimeout")


def _detect_recursion_and_loops(ctx: _DosContext) -> None:
    content = ctx.content
    control = "SNIPER-DOS-06"
    if _lang(ctx.language, "python") and _JSON_LOADS_RE.search(content) and _REQUEST_DATA_HINT_RE.search(content):
        for match in _RECURSION_LIMIT_RE.finditer(content):
            try:
                value = int(match.group("value").replace("_", ""))
            except ValueError:
                continue
            if value <= 10_000:
                continue
            line_no = ctx.code_line(match.start())
            if line_no is None:
                continue
            ctx.emit(
                severity="low",
                title="Özyineleme sınırı yükseltilmiş; derin iç içe JSON yığın taşmasına yol açabilir",
                description=f"sys.setrecursionlimit({value}) istek verisini json.loads ile çözen kodla birlikte kullanılıyor; derin iç içe girdiler C yığınını taşırıp süreci çökertebilir.",
                recommendation="Varsayılan özyineleme sınırını koruyun; istek boyutunu ve JSON iç içe geçme derinliğini ayrıştırmadan önce sınırlayın.",
                cwe="CWE-674",
                control_id=control,
                line_no=line_no,
            )
    for match in _INFINITE_LOOP_RE.finditer(content):
        line_no = ctx.code_line(match.start())
        if line_no is None:
            continue
        body = ctx.window(line_no, 0, 15)
        if not _NET_READ_RE.search(body):
            continue
        if _LOOP_EXIT_RE.search(body) or _TIMEOUT_HINT_RE.search(ctx.window(line_no, 15, 15)):
            continue
        ctx.emit(
            severity="low",
            title="Çıkış koşulu veya zaman aşımı olmayan ağ okuma döngüsü",
            description="Sonsuz döngü ağdan/akıştan okuyor ancak yakınında break/return veya zaman aşımı yok; kapanan bağlantıda (boş okuma) CPU'yu %100 tüketen dönüşe ya da süresiz bloklanmaya yol açabilir.",
            recommendation="Boş okumada (EOF) döngüden çıkın, sokete zaman aşımı (settimeout/SetReadDeadline) verin ve en fazla yineleme/süre sınırı koyun.",
            cwe="CWE-835",
            control_id=control,
            line_no=line_no,
        )


# ======================================================================================
# Genel API
# ======================================================================================

def audit_dos_resilience_inline(
    raw_content: str,
    *,
    filename: str = "app.py",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek kaynak kod içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "app.py"
    clean_filename = filename.strip()[:512]
    ctx = _DosContext(raw_content, clean_filename, _language_for(clean_filename))

    _detect_redos(ctx)
    _detect_dynamic_regex(ctx)
    _detect_http_timeouts(ctx)
    _detect_decompression(ctx)
    _detect_xml_entity_expansion(ctx)
    _detect_body_limits(ctx)
    _detect_recursion_and_loops(ctx)

    findings = sorted(ctx.findings, key=lambda item: (int(item["line"]), item["control_id"]))
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    return {
        "format": "sniper-dos-resilience-inline-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(DOS_CONTROLS_EVALUATED),
    }


@project_scan_scope
@taint_flow.project_context
def audit_dos_resilience_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    taint_flow.activate_project_js_handlers(root, SKIP_DIRS)
    findings: list[dict[str, Any]] = []
    scanned_files = 0

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            if scanned_files >= MAX_PROJECT_FILES:
                break
            file_path = Path(current) / name
            if file_path.is_symlink():
                continue
            if file_path.suffix.lower() not in DOS_EXTENSIONS:
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip():
                continue
            rel_name = file_path.relative_to(root).as_posix()
            scanned_files += 1
            file_report = audit_dos_resilience_inline(content, filename=rel_name)
            findings.extend(file_report["findings"])
        if scanned_files >= MAX_PROJECT_FILES:
            break

    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, PROJECT_FINDING_LIMIT)
    return {
        "format": "sniper-dos-resilience-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(DOS_CONTROLS_EVALUATED),
    }
