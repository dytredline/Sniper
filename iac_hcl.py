"""Hafif, hoşgörülü HCL (Terraform) ayrıştırıcısı — IaC motoru için.

Amaç Terraform'u değerlendirmek değil, kaynak bloklarındaki *değişmez* değerleri satır numaralarıyla okumaktır:
dizge/sayı/bool, liste, nesne, ``jsonencode({...})`` gibi çağrılar ve iç içe bloklar. Değişken, başvuru, koşul,
for ifadesi ve ara değer (``${...}``) içeren her şey ``Unknown`` olur; denetimler bilinmeyen değerde susar
(yanlış alarm yerine kaçırma). Kod çalıştırılmaz, dosya dışına bakılmaz.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MAX_TOKENS = 400_000  # 1 MB'lık dosyada bile yeter; aşılırsa ayrıştırma bırakılır (eski desen kuralları devreye girer)


class HclError(ValueError):
    pass


@dataclass(frozen=True)
class Unknown:
    """Değerlendirilemeyen ifade (değişken, başvuru, koşul, ara değerli dizge…). ``toks`` ifadenin belirteçleri:
    proje bağlamında (değişken varsayılanları, locals, modül girdileri) yeniden değerlendirmek için (19. tur)."""
    raw: str = ""
    toks: tuple = field(default=(), compare=False, repr=False)

    def __bool__(self) -> bool:  # bilinmeyen değer hiçbir koşulu sağlamaz
        return False


@dataclass
class Call:
    name: str
    args: list[Any]


@dataclass
class Attr:
    value: Any
    line: int


@dataclass
class Block:
    type: str
    labels: list[str]
    line: int
    attrs: dict[str, Attr] = field(default_factory=dict)
    blocks: list["Block"] = field(default_factory=list)

    def children(self, name: str) -> list["Block"]:
        return [b for b in self.blocks if b.type == name]


@dataclass
class Tok:
    kind: str  # id, str, num, heredoc, p (noktalama), nl, eof
    value: Any
    line: int
    interp: bool = False  # dizge/heredoc içinde ${ } ya da %{ } var mı


def _lex_string(text: str, i: int, line: int) -> tuple[int, str, bool, int]:
    """``i`` açılış tırnağı. Dönüş: (bitiş indeksi, değer, ara değer var mı, satır)."""
    n = len(text)
    out: list[str] = []
    interp = False
    i += 1
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
            continue
        if ch == '"':
            return i + 1, "".join(out), interp, line
        if ch == "\n":
            raise HclError(f"satır {line}: kapanmamış dizge")
        if ch in "$%" and i + 1 < n and text[i + 1] == "{":
            if i + 2 < n and text[i + 2] == "{":  # kaçış: $${ → düz metin
                pass
            interp = True
            depth = 0
            j = i + 1
            while j < n:
                c = text[j]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                elif c == '"':
                    j, _, _, line = _lex_string(text, j, line)
                    continue
                elif c == "\n":
                    line += 1
                j += 1
            out.append(text[i:j + 1])
            i = j + 1
            continue
        out.append(ch)
        i += 1
    raise HclError(f"satır {line}: kapanmamış dizge")


def tokenize(text: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n, line = 0, len(text), 1
    while i < n:
        if len(toks) > MAX_TOKENS:
            raise HclError("belirteç sınırı aşıldı")
        ch = text[i]
        if ch == "\n":
            toks.append(Tok("nl", "\n", line))
            line += 1
            i += 1
        elif ch in " \t\r﻿":
            i += 1
        elif ch == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise HclError(f"satır {line}: kapanmamış yorum")
            line += text.count("\n", i, j)
            i = j + 2
        elif ch == '"':
            start_line = line
            i, value, interp, line = _lex_string(text, i, line)
            toks.append(Tok("str", value, start_line, interp))
        elif text.startswith("<<", i) and (i + 2 < n and (text[i + 2].isalpha() or text[i + 2] == "-")):
            j = i + 2
            indent = text[j] == "-"
            if indent:
                j += 1
            k = j
            while k < n and (text[k].isalnum() or text[k] == "_"):
                k += 1
            marker = text[j:k]
            eol = text.find("\n", k)
            if not marker or eol < 0:
                raise HclError(f"satır {line}: bozuk heredoc")
            start_line = line
            body_lines: list[str] = []
            pos = eol + 1
            line += 1
            while True:
                if pos >= n:
                    raise HclError(f"satır {start_line}: kapanmamış heredoc")
                nl = text.find("\n", pos)
                raw = text[pos:] if nl < 0 else text[pos:nl]
                if raw.strip() == marker:
                    pos = n if nl < 0 else nl
                    break
                body_lines.append(raw)
                line += 1
                pos = n if nl < 0 else nl + 1
            body = "\n".join(body_lines)
            toks.append(Tok("heredoc", body, start_line, "${" in body or "%{" in body))
            i = pos
        elif ch.isdigit():
            j = i
            while j < n and (text[j].isalnum() or text[j] in "._"):
                j += 1
            raw = text[i:j]
            try:
                value: Any = int(raw)
            except ValueError:
                try:
                    value = float(raw)
                except ValueError:
                    value = raw
            toks.append(Tok("num", value, line))
            i = j
        elif ch.isalpha() or ch == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_-"):
                j += 1
            toks.append(Tok("id", text[i:j], line))
            i = j
        else:
            two = text[i:i + 2]
            if two in ("==", "!=", "<=", ">=", "&&", "||", "=>", "..."):
                toks.append(Tok("p", two if two != "..." else "...", line))
                i += 3 if two == "..." else 2
            else:
                toks.append(Tok("p", ch, line))
                i += 1
    toks.append(Tok("eof", None, line))
    return toks


_OPEN = {"{": "}", "[": "]", "(": ")"}


class _Parser:
    def __init__(self, toks: list[Tok]):
        self.toks = toks
        self.i = 0

    def peek(self, k: int = 0) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def body(self, closing: str | None) -> tuple[dict[str, Attr], list[Block]]:
        attrs: dict[str, Attr] = {}
        blocks: list[Block] = []
        while True:
            tok = self.peek()
            if tok.kind == "nl":
                self.i += 1
                continue
            if tok.kind == "eof":
                if closing is not None:
                    raise HclError("beklenmeyen dosya sonu")
                return attrs, blocks
            if tok.kind == "p" and tok.value == "}" and closing == "}":
                self.i += 1
                return attrs, blocks
            if tok.kind == "id" and self.peek(1).kind == "p" and self.peek(1).value == "=" \
                    and not (self.peek(2).kind == "p" and self.peek(2).value in ("=", ">")):
                self.i += 2
                attrs[tok.value] = Attr(self.expr(stop_newline=True), tok.line)
                continue
            if tok.kind == "id":
                labels: list[str] = []
                j = 1
                while self.peek(j).kind in ("str", "id"):
                    labels.append(str(self.peek(j).value))
                    j += 1
                if self.peek(j).kind == "p" and self.peek(j).value == "{":
                    self.i += j + 1
                    sub_attrs, sub_blocks = self.body("}")
                    blocks.append(Block(tok.value, labels, tok.line, sub_attrs, sub_blocks))
                    continue
            # Tanınmayan deyim: satır sonuna kadar (parantez dengesiyle) atla.
            self._skip_statement()

    def _skip_statement(self) -> None:
        depth = 0
        while True:
            tok = self.peek()
            if tok.kind == "eof":
                return
            if tok.kind == "p" and tok.value in _OPEN:
                depth += 1
            elif tok.kind == "p" and tok.value in ")]}":
                if depth == 0:
                    # Eşleşmemiş bir kapama belirteci tanınmayan deyimin ilk
                    # belirteci olabilir. Onu tüketmeden dönmek ``body``nin
                    # aynı konumda sonsuza dek yeniden denemesine yol açar.
                    self.i += 1
                    return
                depth -= 1
            elif tok.kind == "nl" and depth == 0:
                self.i += 1
                return
            self.i += 1

    def expr(self, stop_newline: bool) -> Any:
        """Durak belirtecine kadar olan dilimi toplar, sonra yorumlar."""
        start = self.i
        depth = 0
        while True:
            tok = self.peek()
            if tok.kind == "eof":
                break
            if tok.kind == "p" and tok.value in _OPEN:
                depth += 1
            elif tok.kind == "p" and tok.value in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and ((tok.kind == "nl" and stop_newline) or (tok.kind == "p" and tok.value == ",")):
                break
            self.i += 1
        return interpret(self.toks[start:self.i])


def _split(toks: list[Tok], seps: tuple[str, ...]) -> list[list[Tok]]:
    """Derinlik 0'da ayırıcıya (',' ya da yeni satır) göre böl; boş parçaları at."""
    parts: list[list[Tok]] = []
    cur: list[Tok] = []
    depth = 0
    for tok in toks:
        if tok.kind == "p" and tok.value in _OPEN:
            depth += 1
        elif tok.kind == "p" and tok.value in ")]}":
            depth -= 1
        if depth == 0 and ((tok.kind == "p" and tok.value in seps) or (tok.kind == "nl" and "nl" in seps)):
            if cur:
                parts.append(cur)
            cur = []
            continue
        cur.append(tok)
    if cur:
        parts.append(cur)
    return [[t for t in p if t.kind != "nl"] or p for p in parts if any(t.kind != "nl" for t in p)]


def _matching(toks: list[Tok], start: int) -> int:
    depth = 0
    for k in range(start, len(toks)):
        tok = toks[k]
        if tok.kind == "p" and tok.value in _OPEN:
            depth += 1
        elif tok.kind == "p" and tok.value in ")]}":
            depth -= 1
            if depth == 0:
                return k
    return -1


def _raw(toks: list[Tok]) -> str:
    return " ".join(str(t.value) for t in toks if t.kind != "nl")[:200]


def interpret(toks: list[Tok]) -> Any:
    toks = [t for t in toks]
    while toks and toks[0].kind == "nl":
        toks.pop(0)
    while toks and toks[-1].kind == "nl":
        toks.pop()
    if not toks:
        return Unknown("")
    first = toks[0]
    if len(toks) == 1:
        if first.kind in ("str", "heredoc"):
            return Unknown(str(first.value), (first,)) if first.interp else first.value
        if first.kind == "num":
            return first.value
        if first.kind == "id":
            if first.value == "true":
                return True
            if first.value == "false":
                return False
            if first.value == "null":
                return None
        return Unknown(_raw(toks), tuple(toks))
    if len(toks) == 2 and first.kind == "p" and first.value == "-" and toks[1].kind == "num" \
            and isinstance(toks[1].value, (int, float)):
        return -toks[1].value
    if first.kind == "p" and first.value in ("[", "{") and _matching(toks, 0) == len(toks) - 1:
        inner = toks[1:-1]
        if first.value == "[":
            if inner and inner[0].kind == "id" and inner[0].value == "for":
                return Unknown(_raw(toks), tuple(toks))
            return [interpret(p) for p in _split(inner, (",", "nl"))]
        if inner and inner[0].kind == "id" and inner[0].value == "for":
            return Unknown(_raw(toks), tuple(toks))
        obj: dict[str, Any] = {}
        for part in _split(inner, (",", "nl")):
            eq = next((k for k, t in enumerate(part) if t.kind == "p" and t.value in ("=", ":")), -1)
            if eq <= 0:
                continue
            key_toks = part[:eq]
            if len(key_toks) == 1 and key_toks[0].kind in ("id", "str") and not key_toks[0].interp:
                key = str(key_toks[0].value)
            elif len(key_toks) == 3 and key_toks[0].value == "(" and key_toks[2].value == ")":
                key = str(key_toks[1].value)
            else:
                continue
            obj[key] = interpret(part[eq + 1:])
        return obj
    if first.kind == "id" and len(toks) >= 3 and toks[1].kind == "p" and toks[1].value == "(" \
            and _matching(toks, 1) == len(toks) - 1:
        return Call(first.value, [interpret(p) for p in _split(toks[2:-1], (",",))])
    return Unknown(_raw(toks), tuple(toks))


def parse(text: str) -> Block:
    """Dosyanın tamamını kök blok olarak döndürür; ayrıştırılamazsa HclError."""
    parser = _Parser(tokenize(text))
    attrs, blocks = parser.body(None)
    return Block("<root>", [], 1, attrs, blocks)


def is_unknown(value: Any) -> bool:
    return isinstance(value, (Unknown, Call))
