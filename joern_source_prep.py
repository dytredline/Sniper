"""Joern ön uçlarına verilmeden önce kaynak dosyalara uygulanan, anlamı koruyan ön işlemler.

C#: csharpsrc2cpg (Joern 4.0.647) süslü parantezsiz denetim yapısı gövdelerini CPG'ye hiç koymuyor:
``if (x) Sink(x);``, ``if (x == null) return;``, ``foreach (var v in xs) Sink(v);`` … gövdeler boş blok
olarak görünür. Bu hem açık kaçırmaya (gövdedeki hedef yok) hem de yanlış alarma (``return``/``throw``
korumaları görünmüyor) yol açar. ``brace_csharp_bodies`` bu gövdeleri ``{ … }`` ile sarar; yalnız aynı
satıra karakter eklenir, satır numaraları değişmez. Ayrıştırma belirsizse metin olduğu gibi döner.

Aynı ön uç ``lock (x) { … }`` gövdesini süslü parantezli olsa bile düşürür. ``lock (x) G`` deyimi, derleyicinin
ürettiği karşılığa yakın biçimde ``System.Threading.Monitor.Enter(x); G`` olur (yalnız aynı satıra ekleme;
``_ = (x);`` biçimi ön uçta sorgu betiğini bozan düğüm üretti). Gövde ayrı bir blok olarak analize girer.
"""

from __future__ import annotations

import re

# Gövdesi parantezli bir başlıktan sonra gelen yapılar.
_HEADED = frozenset({"if", "for", "foreach", "while", "using", "lock", "fixed"})
_IDENT = re.compile(r"[@]?[A-Za-z_À-￿][\wÀ-￿]*")


class _Unparsable(Exception):
    pass


def _is_string_start(text: str, i: int) -> bool:
    """text[i] bir C# dize değişmezi (\"...\", @\"...\", $\"...\", $$+\"\"\"...\"\"\") başlangıcı mı?"""
    n = len(text)
    if i >= n:
        return False
    if text[i] == '"':
        return True
    if text[i] not in "@$":
        return False
    j = i
    while j < n and text[j] in "@$":
        j += 1
    return j < n and text[j] == '"'


def _skip_string(text: str, i: int) -> int:
    """text[i] bir dize başlangıcı (önekleriyle: @, $, $@, @$, ham \"\"\"). Dizenin bitişinden sonraki konum."""
    n = len(text)
    j = i
    interpolated = verbatim = False
    while j < n and text[j] in "@$":
        if text[j] == "$":
            interpolated = True
        else:
            verbatim = True
        j += 1
    if j >= n or text[j] != '"':
        raise _Unparsable("dize")
    quotes = 0
    while j + quotes < n and text[j + quotes] == '"':
        quotes += 1
    if quotes >= 3:   # ham dize: aynı sayıda tırnakla biter
        end = text.find('"' * quotes, j + quotes)
        if end < 0:
            raise _Unparsable("ham dize")
        return end + quotes
    j += 1
    depth = 0
    while j < n:
        c = text[j]
        if depth == 0:
            if c == '"':
                if verbatim and j + 1 < n and text[j + 1] == '"':
                    j += 2
                    continue
                return j + 1
            if c == "\\" and not verbatim:
                j += 2
                continue
            if c == "\n" and not verbatim:
                raise _Unparsable("satır sonu")
            if interpolated and c == "{":
                if j + 1 < n and text[j + 1] == "{":
                    j += 2
                    continue
                depth = 1
            elif interpolated and c == "}" and j + 1 < n and text[j + 1] == "}":
                j += 2
                continue
            j += 1
        else:   # ara değer ifadesi
            if _is_string_start(text, j):
                j = _skip_string(text, j)
                continue
            if c == "'":
                j = _skip_char(text, j)
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            j += 1
    raise _Unparsable("kapanmamış dize")


def _skip_char(text: str, i: int) -> int:
    j = i + 1
    while j < len(text) and j - i < 12:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "'":
            return j + 1
        if text[j] == "\n":
            break
        j += 1
    raise _Unparsable("karakter")


def _tokens(text: str) -> list[tuple[str, int, int]]:
    """(metin, başlangıç, bitiş) anlamlı belirteçleri; boşluk, yorum ve ön işlemci satırları atlanır."""
    out: list[tuple[str, int, int]] = []
    i, n = 0, len(text)
    line_start = True
    while i < n:
        c = text[i]
        if c == "\n":
            line_start = True
            i += 1
            continue
        if c in " \t\r\f\v﻿":
            i += 1
            continue
        if line_start and c == "#":   # #if/#region …: satır sonuna kadar
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        line_start = False
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise _Unparsable("yorum")
            i = end + 2
            continue
        if _is_string_start(text, i):
            end = _skip_string(text, i)
            out.append(('""', i, end))
            i = end
            continue
        if c == "'":
            end = _skip_char(text, i)
            out.append(("''", i, end))
            i = end
            continue
        m = _IDENT.match(text, i)
        if m:
            out.append((m.group(0), i, m.end()))
            i = m.end()
            continue
        out.append((c, i, i + 1))
        i += 1
    return out


def brace_csharp_bodies(text: str) -> str:
    """Süslü parantezsiz denetim yapısı gövdelerini { } ile sar (satır numaraları korunur)."""
    try:
        toks = _tokens(text)
    except _Unparsable:
        return text
    words = [t[0] for t in toks]
    n = len(words)
    closing = {")": "(", "]": "[", "}": "{"}

    def match(i: int) -> int:
        """words[i] açılış parantezi; eşleşen kapanışın dizini."""
        stack = [words[i]]
        j = i + 1
        while j < n:
            w = words[j]
            if w in "([{" and len(w) == 1:
                stack.append(w)
            elif w in closing:
                if stack[-1] != closing[w]:
                    raise _Unparsable("parantez")
                stack.pop()
                if not stack:
                    return j
            j += 1
        raise _Unparsable("kapanmamış parantez")

    def stmt_end(i: int) -> int:
        """words[i]'de başlayan deyimin son belirtecinin dizini."""
        if i >= n:
            raise _Unparsable("deyim yok")
        w = words[i]
        if w == "{":
            return match(i)
        if w == ";":
            return i
        if w == "await" and i + 2 < n and words[i + 1] in ("foreach", "using") and words[i + 2] == "(":
            return stmt_end(match(i + 2) + 1)
        if w in _HEADED and i + 1 < n and words[i + 1] == "(":
            end = stmt_end(match(i + 1) + 1)
            if w == "if" and end + 1 < n and words[end + 1] == "else":
                end = stmt_end(end + 2)
            return end
        if w == "do":
            end = stmt_end(i + 1)
            if end + 1 >= n or words[end + 1] != "while" or end + 2 >= n or words[end + 2] != "(":
                raise _Unparsable("do-while")
            close = match(end + 2)
            if close + 1 >= n or words[close + 1] != ";":
                raise _Unparsable("do-while ;")
            return close + 1
        if w in ("switch",) and i + 1 < n and words[i + 1] == "(":
            j = match(i + 1) + 1
            if j >= n or words[j] != "{":
                raise _Unparsable("switch")
            return match(j)
        if w in ("checked", "unchecked", "unsafe") and i + 1 < n and words[i + 1] == "{":
            return match(i + 1)
        if w == "try":
            end = stmt_end(i + 1)
            while end + 1 < n and words[end + 1] in ("catch", "finally"):
                j = end + 2
                if words[end + 1] == "catch" and j < n and words[j] == "(":
                    j = match(j) + 1
                if words[end + 1] == "catch" and j < n and words[j] == "when":
                    j = match(j + 1) + 1
                if j >= n or words[j] != "{":
                    raise _Unparsable("catch")
                end = match(j)
            return end
        # Basit deyim: derinlik 0'daki ';' (lambda gövdeleri ve nesne başlatıcıları içeride kalır).
        depth = 0
        j = i
        while j < n:
            x = words[j]
            if x in ("(", "[", "{"):
                depth += 1
            elif x in (")", "]", "}"):
                depth -= 1
                if depth < 0:
                    raise _Unparsable("deyim kapanmadan blok bitti")
            elif x == ";" and depth == 0:
                return j
            j += 1
        raise _Unparsable("deyim sonu yok")

    pairs: list[tuple[int, int]] = []   # (gövde ilk belirteci, gövde son belirteci)
    locks: list[tuple[int, int]] = []   # ("lock" belirteci, başlığın kapanış parantezi)

    def body(i: int) -> None:
        if i >= n or words[i] in ("{", ";"):
            return
        pairs.append((i, stmt_end(i)))

    try:
        for i, w in enumerate(words):
            if w in _HEADED and i + 1 < n and words[i + 1] == "(":
                # do-while'ın while'ı ve boş gövdeli while(x); sarılmaz (body ';' görür).
                close = match(i + 1)
                body(close + 1)
                if w == "lock":
                    locks.append((i, close))
            elif w == "else" and not (i + 1 < n and words[i + 1] == "if"):
                body(i + 1)
            elif w == "do":
                body(i + 1)
    except (_Unparsable, IndexError, RecursionError):
        return text
    if not pairs and not locks:
        return text
    # Eklemeler: aynı konumda açılışlarda dıştaki önce, kapanışlarda içteki önce.
    inserts: list[tuple[int, int, int, str]] = []
    if locks:
        # "lock" dört boşluk olur (konumlar değişmez); çağrı adı "lock"un yerine, aynı konumdaki "{ "
        # açılışlarından sonra (tür 2) eklenir; ";" başlığın ")" sonrasına, gövde açılışından önce gelir.
        chars = list(text)
        for keyword, close in locks:
            start = toks[keyword][1]
            chars[start:start + 4] = list("    ")
            inserts.append((start, 2, 0, "System.Threading.Monitor.Enter"))
            inserts.append((toks[close][2], 0, -1, ";"))
        text = "".join(chars)
    for first, last in set(pairs):
        start, end = toks[first][1], toks[last][2]
        inserts.append((start, 1, -(end - start), "{ "))
        inserts.append((end, 0, end - start, " }"))
    inserts.sort()
    pieces: list[str] = []
    cursor = 0
    for offset, _kind, _span, piece in inserts:
        pieces.append(text[cursor:offset])
        pieces.append(piece)
        cursor = offset
    pieces.append(text[cursor:])
    return "".join(pieces)


def prepare_source(language: str, data: bytes) -> bytes:
    """Dile özgü ön işlem; kod çözülemeyen veya değişmeyen içerik olduğu gibi döner."""
    if language != "csharp":
        return data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    result = brace_csharp_bodies(text)
    return data if result == text else result.encode("utf-8")
