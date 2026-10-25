"""Rust ``unsafe`` bellek güvenliği kalıpları (belirteç düzeyi, düşük öncelikli; yalnız "olası" bulgu).

Kalıplar (yalnız ``unsafe`` blok/işlev içinde):
  * ``slice::from_raw_parts(X.as_ptr(), n)``: ``n`` aynı dilimin ``X.len()``'i değil ve ``.min(..)`` ile
    kısıtlanmamış → sınır dışı okuma (CWE-125). Uzunluk ve işaretçinin ikisi de parametre olan FFI geri
    çağırmaları (``extern "C" fn``) olağan sözleşmedir, raporlanmaz.
  * ``get_unchecked(i)`` / ``get_unchecked_mut(i)``: fonksiyonda ``i`` hiçbir ``len()`` ile karşılaştırılmıyor
    (``assert!``/``if``/``min``) → sınır dışı erişim (CWE-125/787).
  * ``Box::from_raw(p)`` / ``Vec::from_raw_parts(p, ..)`` / ``String::from_raw_parts(p, ..)`` aynı işaretçiyle iki kez
    → çift serbest bırakma (CWE-415); ``drop(..)`` sonrası ``*p`` → serbest bırakılmış bellek kullanımı (CWE-416).
  * 27. tur — ``ptr::copy``/``ptr::copy_nonoverlapping``/``.copy_from``/``.copy_to``/``write_bytes``: kopya uzunluğu
    hedef ya da kaynak dilimin ``len()``'i değil ve onunla karşılaştırılmıyor/``min`` ile kısıtlanmıyor → sınır dışı
    yazma/okuma (CWE-787/125); uzunluk iletideki bir uzunluk alanından (``declared_len``, ``payload_size``,
    ``u32::from_be_bytes``…) geliyorsa kanıtta belirtilir (CWE-130 bağlamı).
  * ``get_unchecked(..n)`` / ``get_unchecked(a..b)`` aralıkları: uç ``len()`` ile karşılaştırılmıyor → sınır dışı erişim.
  * ``Vec::set_len(n)``: ``n`` ``capacity()``/``len()`` ile denetlenmiyor → başlatılmamış/sınır dışı bellek (CWE-908/787).
Güvenli (``unsafe`` olmayan) kodda ``buf[..declared_len]`` dilimlemesi sınır dışı erişim değil, panik (DoS) olduğu
için bellek bulgusu üretilmez. Dış girdiden gelen uzunluk/indeks (istek → ``from_raw_parts``/``get_unchecked``)
``taint_rust`` tarafından doğrulanmış akış olarak raporlanır; bu modül onu tekrarlamaz (aynı satır proje analizinde
birleşir).
"""
from __future__ import annotations

import re

import memsafety_c
import taint_native_core as core
from taint_native_core import match_close, split_args

SUFFIXES = frozenset({".rs"})
MAX_FILE_BYTES = 2_000_000
_FN_RE_EXTERN = re.compile(r"extern\s+\"C\"\s+fn")


def _unsafe_regions(toks) -> list[tuple[int, int]]:
    """``unsafe { .. }`` blokları ve ``unsafe fn`` gövdeleri (belirteç aralıkları)."""
    out = []
    n = len(toks)
    i = 0
    while i < n:
        t = toks[i]
        if t.kind == "id" and t.text == "unsafe":
            j = i + 1
            if j < n and toks[j].text == "{":
                out.append((j, match_close(toks, j)))
            elif j < n and toks[j].text in ("fn", "extern", "impl"):
                k = j
                while k < n and toks[k].text not in ("{", ";"):
                    k += 1
                if k < n and toks[k].text == "{":
                    out.append((k, match_close(toks, k)))
        i += 1
    return out


def _fn_ranges(toks) -> list[tuple[int, int, int, bool]]:
    """(gövde başı, gövde sonu, fn belirteci, extern "C" mi)."""
    out = []
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind == "id" and t.text == "fn" and i + 1 < n and toks[i + 1].kind == "id":
            k = i + 2
            depth = 0
            while k < n:
                x = toks[k].text
                if x in ("(", "<", "["):
                    depth += 1
                elif x in (")", ">", "]"):
                    depth -= 1
                elif x == "{" and depth <= 0:
                    break
                elif x == ";" and depth <= 0:
                    k = -1
                    break
                k += 1
            if k < 0 or k >= n:
                continue
            ext = i >= 2 and toks[i - 1].kind == "str" and toks[i - 2].text == "extern"
            out.append((k, match_close(toks, k), i, ext))
    return out


def _text(toks, a: int, b: int) -> str:
    """Belirteçleri birleştir; art arda iki sözcük belirteci arasına boşluk (\b eşleşmesi için)."""
    out = []
    prev_word = False
    for q in range(a, b):
        t = toks[q]
        word = t.kind in ("id", "num")
        if word and prev_word:
            out.append(" ")
        out.append(t.text)
        prev_word = word
    return "".join(out)


def analyze_text(text: str, path: str) -> list[memsafety_c.MemFinding]:
    if len(text) > MAX_FILE_BYTES or "unsafe" not in text:
        return []
    try:
        toks = core.tokenize(text, rust=True)
    except (RecursionError, IndexError, ValueError):
        return []
    regions = _unsafe_regions(toks)
    if not regions:
        return []
    fns = _fn_ranges(toks)
    findings: dict[tuple[str, int], memsafety_c.MemFinding] = {}

    def in_unsafe(q: int) -> bool:
        return any(a <= q <= b for a, b in regions)

    def fn_of(q: int):
        best = None
        for f in fns:
            if f[0] <= q <= f[1] and (best is None or f[0] > best[0]):
                best = f
        return best

    def add(kind: str, line: int, detail: str, fname: str) -> None:
        cwe = {"overread": "CWE-125", "overflow": "CWE-787", "double_free": "CWE-415", "uaf": "CWE-416"}[kind]
        f = memsafety_c.MemFinding(kind=kind, cwe=cwe, line=line, certain=False, severity="medium",
                                   title=memsafety_c.title_for(kind, False), evidence=f"Rust unsafe: {detail}",
                                   function=fname, engine="sniper-memsafety-rust")
        findings.setdefault((kind, line), f)

    def bounded(length: str, bases: list[str], body_txt: str) -> bool:
        """Uzunluk ifadesi dilim uzunluğuna bağlı ya da onunla karşılaştırılıyor/min ile kısıtlanıyor mu?"""
        if ".min(" in length or "min(" in length or ".len()" in length or length.isdigit() or \
                "size_of" in length:
            return True
        if bases and not any(
            re.search(
                rf"\b{re.escape(b)}\.len\(\)|\b{re.escape(b)}\[[^\]]*\.\.|\b{re.escape(b)}(:\w+)?=&?\w+\[[^\]]*\.\.",
                body_txt,
            )
            for b in bases
        ):
            return False
        var = re.split(r"[^\w]", length)[0] if length else ""
        if not var:
            return False
        if re.search(rf"\b{re.escape(var)}(:\w+)?=[^;]*(\.min\(|min\(|\.len\(\)|size_of)", body_txt):
            return True
        if re.search(rf"\b{re.escape(var)}(<=|<|>=|>|==)(?!0\b)", body_txt) or \
                re.search(rf"(?<!\b0)(<=|<|>=|>|==)[&*]?{re.escape(var)}\b", body_txt):
            return True
        if re.search(rf"assert!?\([^;]*\b{re.escape(var)}\b", body_txt):
            return True
        return False

    def len_field_note(length: str, body_txt: str) -> str:
        var = re.split(r"[^\w.]", length)[0]
        last = var.split(".")[-1]
        if re.search(r"(?i)(len|size|count|length)", last) and (
                "." in var or re.search(rf"\b{re.escape(var)}(:\w+)?=[^;]*(from_be_bytes|from_le_bytes|"
                                        rf"from_ne_bytes|read_u\d+|get_u\d+|u\d+::from)", body_txt)):
            return f"; uzunluk `{var}` iletideki bir uzunluk alanından geliyor ve doğrulanmıyor (CWE-130)"
        return ""

    def ptr_base(expr: str) -> str:
        m = re.match(r"(\w+(?:\.\w+)*)\.as_(?:mut_)?ptr\(\)", expr)
        return m.group(1) if m else ""

    n = len(toks)
    from_raw_seen: dict[tuple[int, str], int] = {}
    for i, t in enumerate(toks):
        if t.kind == "id" and i + 1 < n and toks[i + 1].text == "=" and from_raw_seen:
            for key in [k for k in from_raw_seen if k[1] == t.text]:
                del from_raw_seen[key]  # işaretçi yeniden atandı (into_raw ile yeni sahip)
        if t.kind != "id" or i + 1 >= n or toks[i + 1].text != "(" or not in_unsafe(i):
            continue
        name = t.text
        close = match_close(toks, i + 1)
        args = split_args(toks, i + 2, close)
        fn = fn_of(i)
        fname = toks[fn[2] + 1].text if fn else ""
        body = (fn[0], fn[1]) if fn else (0, n)
        if name in ("from_raw_parts", "from_raw_parts_mut") and len(args) == 2 and \
                i >= 2 and toks[i - 1].text == "::" and toks[i - 2].text in ("slice",):
            ptr, ln = _text(toks, *args[0]), _text(toks, *args[1])
            m = re.fullmatch(r"(\w+(?:\.\w+)*)\.as_(?:mut_)?ptr\(\)", ptr)
            if m is None:
                continue  # ham işaretçi parametresi (FFI sözleşmesi) — değerlendirilmez
            base = m.group(1)
            if ln == f"{base}.len()" or ".min(" in ln or "min(" in ln:
                continue
            # uzunluk bu fonksiyonda dilimin len()'inden türetiliyor ya da onunla karşılaştırılıyor mu?
            body_txt = _text(toks, *body)
            lnv = ln.split(".")[0]
            if re.search(rf"\b{re.escape(lnv)}\s*=\s*{re.escape(base)}\.len\(\)", body_txt) or \
                    re.search(rf"\b{re.escape(lnv)}(:\w+)?=[^;]*(\.min\(|min\()", body_txt) or \
                    re.search(rf"{re.escape(lnv)}(<=|<|>=|>)[^;]*{re.escape(base)}\.len\(\)", body_txt) or \
                    re.search(rf"{re.escape(base)}\.len\(\)(<=|<|>=|>)[^;]*{re.escape(lnv)}\b", body_txt):
                continue
            add("overread", t.line, f"slice::{name}({base}.as_ptr(), {ln}): uzunluk `{base}.len()` ile "
                                    "sınırlandırılmıyor; sınır dışı okuma olası", fname)
        elif name in ("copy", "copy_nonoverlapping", "write_bytes") and i >= 2 and toks[i - 1].text == "::" and \
                toks[i - 2].text == "ptr" and len(args) == 3:
            a0, a1, ln = (_text(toks, *r) for r in args)
            body_txt = _text(toks, *body)
            dst_expr = a0 if name == "write_bytes" else a1
            bases = [b for b in (ptr_base(a0), ptr_base(a1)) if b]
            if bounded(ln, bases, body_txt):
                continue
            kind = "overflow"
            add(kind, t.line, f"ptr::{name}(…, {ln}): kopya uzunluğu hedef/kaynak dilimin len()'i ile "
                              f"sınırlandırılmıyor (hedef `{dst_expr}`){len_field_note(ln, body_txt)}", fname)
        elif name in ("copy_from", "copy_from_nonoverlapping", "copy_to", "copy_to_nonoverlapping") and \
                i >= 1 and toks[i - 1].text == "." and len(args) == 2:
            ln = _text(toks, *args[1])
            body_txt = _text(toks, *body)
            if bounded(ln, [], body_txt):
                continue
            add("overflow", t.line, f".{name}(…, {ln}): kopya uzunluğu dilim uzunluğuyla sınırlandırılmıyor"
                                    f"{len_field_note(ln, body_txt)}", fname)
        elif name == "set_len" and i >= 1 and toks[i - 1].text == "." and len(args) == 1:
            ln = _text(toks, *args[0])
            body_txt = _text(toks, *body)
            note = len_field_note(ln, body_txt)
            if bounded(ln, [], body_txt) or "capacity()" in body_txt or not note:
                continue  # yalnız iletideki uzunluk alanıyla (olgun kodda set_len(n) çoğunlukla belgelenmiş sözleşme)
            add("overread", t.line, f".set_len({ln}): yeni uzunluk capacity()/len() ile denetlenmiyor; başlatılmamış "
                                    f"ya da ayrılmamış bellek dilime giriyor{note}", fname)
        elif name in ("get_unchecked", "get_unchecked_mut") and len(args) == 1 and i >= 1 and toks[i - 1].text == "." \
                and ".." in _text(toks, *args[0]):
            rng = _text(toks, *args[0])
            end = rng.split("..", 1)[1].lstrip("=")
            body_txt = _text(toks, *body)
            note = len_field_note(end, body_txt)
            if not end or end.isdigit() or bounded(end, [], body_txt) or not note:
                continue  # yalnız uzunluk alanı (hdr.payload_size, from_be_bytes) ile sınırlanan aralıklar
            add("overflow" if name.endswith("_mut") else "overread", t.line,
                f".{name}({rng}): aralık sonu hiçbir len() ile karşılaştırılmıyor{note}", fname)
        elif name in ("get_unchecked", "get_unchecked_mut") and len(args) == 1 and i >= 1 and toks[i - 1].text == ".":
            idx = _text(toks, *args[0])
            if not re.fullmatch(r"\w+", idx) or idx.isdigit():
                continue
            body_txt = _text(toks, *body)
            if re.search(rf"\b{re.escape(idx)}\s*(<|<=)\s*[\w.]*len\(\)", body_txt) or \
                    re.search(rf"len\(\)\s*(>|>=)\s*{re.escape(idx)}\b", body_txt) or \
                    re.search(rf"\b{re.escape(idx)}\s*=\s*[^;]*\.min\(", body_txt) or \
                    re.search(rf"for\s*{re.escape(idx)}\s*in\s*0\s*\.\.", body_txt):
                continue
            add("overflow" if name.endswith("_mut") else "overread", t.line,
                f".{name}({idx}): indeks hiçbir len() ile karşılaştırılmıyor", fname)
        elif name in ("from_raw", "from_raw_parts") and i >= 2 and toks[i - 1].text == "::" and \
                toks[i - 2].text in ("Box", "Vec", "String", "Rc", "Arc", "CString") and args:
            ptr = _text(toks, *args[0])
            if not re.fullmatch(r"\w+", ptr):
                continue
            key = (body[0], ptr)
            if key in from_raw_seen:
                add("double_free", t.line, f"{toks[i - 2].text}::{name}({ptr}) aynı işaretçiyle ikinci kez "
                                           f"(satır {from_raw_seen[key]}); iki sahip aynı belleği serbest bırakır", fname)
            else:
                from_raw_seen[key] = t.line
    return sorted(findings.values(), key=lambda f: (f.line, f.kind))
