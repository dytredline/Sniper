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

from dataclasses import dataclass
import re
from typing import Any

import memsafety_c
import taint_native_core as core
from taint_native_core import match_close, split_args

SUFFIXES = frozenset({".rs"})
MAX_FILE_BYTES = 2_000_000
_FN_RE_EXTERN = re.compile(r"extern\s+\"C\"\s+fn")
_COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")


@dataclass
class RustMemFinding(memsafety_c.MemFinding):
    soundness_bug: bool = False
    pub_safe_api: bool = False
    proof_status: str = "unguarded_path_proven"

    def as_dict(self) -> dict[str, Any]:
        d = super().as_dict()
        d["soundness_bug"] = self.soundness_bug
        d["pub_safe_api"] = self.pub_safe_api
        d["proof_status"] = self.proof_status
        return d


def _norm_slice_var(slice_var: str) -> str:
    s = (slice_var or "").strip()
    s = re.sub(r"^(?:&\s*(?:mut\s+)?)?", "", s)
    s = re.sub(r"\.\s*as_(?:mut_)?ptr\s*\(\s*\)(?:\s*\.\s*(?:add|offset|wrapping_add|wrapping_offset)\s*\([^)]*\))*$", "", s)
    return s.strip()


def _has_fn_interval_guard(fn_window: str, slice_var: str) -> bool:
    """Fonksiyon gövdesinde ``unsafe`` noktadan önce dilim boyutu / aralık / taşma muhafazası var mı?"""
    sv = re.escape(_norm_slice_var(slice_var))
    if not sv or not fn_window:
        return False
    # 1. assert! / debug_assert! / ensure! ile <slice_var>.len() veya .capacity() denetimi
    if re.search(
        rf"\b(?:(?:debug_)?assert(?:_eq|_ne)?|ensure)\s*!\s*\([^;]*?\b{sv}\s*\.\s*(?:len|capacity)\s*\(\s*\)",
        fn_window,
        re.DOTALL,
    ):
        return True
    # 2. Erken dönüşlü (early-return / bail / panic) sınır muhafazası:
    #    if <slice_var>.len() < ... { return ... } veya if ... > / >= <slice_var>.len() { return ... }
    if re.search(
        rf"\bif\b[^{{;]*?(?:\b{sv}\s*\.\s*(?:len|capacity)\s*\(\s*\)\s*(?:<|<=|>|>=|!=|==)|"
        rf"(?:<|<=|>|>=|!=|==)\s*[^;{{]*?\b{sv}\s*\.\s*(?:len|capacity)\s*\(\s*\))[^{{;]*\{{[^}}]*?"
        rf"\b(?:return|bail\s*!|panic\s*!|unreachable\s*!|continue|break)\b",
        fn_window,
        re.DOTALL,
    ):
        return True
    # Pozitif kapsayıcı koşul: if <slice_var>.len() >= ... { unsafe { ... } } veya if ... <= <slice_var>.len() {
    if re.search(
        rf"\bif\b[^{{;]*?(?:\b{sv}\s*\.\s*(?:len|capacity)\s*\(\s*\)\s*(?:>=|>|==)|"
        rf"(?:<=|<|==)\s*[^;{{]*?\b{sv}\s*\.\s*(?:len|capacity)\s*\(\s*\))[^{{;]*\{{",
        fn_window,
        re.DOTALL,
    ):
        return True
    # 3. Boyutlarda taşma denetimli aritmetik (.checked_mul / .checked_add / .checked_sub) + .len() veya .get(..)
    if re.search(r"\.\s*checked_(?:mul|add|sub)\s*\(", fn_window) and (
        re.search(rf"\b{sv}\s*\.\s*(?:len|capacity)\s*\(\s*\)", fn_window)
        or re.search(rf"\b{sv}\s*\.\s*get(?:_mut)?\s*\(", fn_window)
    ):
        return True
    # Güvenli alt dilim / aralık erişimi (.get(..), .split_at(..)) veya .min(<slice_var>.len())
    if re.search(rf"\b{sv}\s*\.\s*(?:get(?:_mut)?|split_at(?:_mut)?)\s*\(", fn_window):
        return True
    if re.search(
        rf"\.\s*min\s*\(\s*{sv}\s*\.\s*len\s*\(\s*\)\s*\)|\b{sv}\s*\.\s*len\s*\(\s*\)\s*\.\s*min\s*\(",
        fn_window,
    ):
        return True
    return False


def _has_slice_len_guard(window: str, slice_var: str) -> bool:
    """Yerel pencere içinde dilim uzunluğu (``<slice_var>.len()``) denetimi veya kısıtlaması var mı?"""
    if _has_fn_interval_guard(window, slice_var):
        return True
    sv = re.escape(_norm_slice_var(slice_var))
    if not sv or not window:
        return False
    return bool(
        re.search(
            rf"\b{sv}\s*\.\s*len\s*\(\s*\)\s*(?:<|<=|>|>=|==|!=)|"
            rf"(?:<|<=|>|>=|==|!=)\s*{sv}\s*\.\s*len\s*\(\s*\)|"
            rf"\b{sv}\s*\[[^\]]*\.\.=?\s*[^\]]+\]",
            window,
        )
    )


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


def analyze_text(text: str, path: str = "") -> list[RustMemFinding]:
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
    lines = text.splitlines()
    findings: dict[tuple[str, int], RustMemFinding] = {}

    def in_unsafe(q: int) -> bool:
        return any(a <= q <= b for a, b in regions)

    def fn_of(q: int):
        best = None
        for f in fns:
            if f[0] <= q <= f[1] and (best is None or f[0] > best[0]):
                best = f
        return best

    def add(
        kind: str,
        line: int,
        detail: str,
        fname: str,
        *,
        soundness_bug: bool = False,
        pub_safe_api: bool = False,
        proof_status: str = "unguarded_path_proven",
    ) -> None:
        cwe = {"overread": "CWE-125", "overflow": "CWE-787", "double_free": "CWE-415", "uaf": "CWE-416"}[kind]
        soundness_suffix = (
            " (Safe Rust soundness kusuru: güvenli `pub fn` API içinde denetlenmemiş `unsafe` blok)"
            if pub_safe_api
            else (" (Safe Rust soundness kusuru: güvenli fonksiyon içinde denetlenmemiş `unsafe` blok)" if soundness_bug else "")
        )
        f = RustMemFinding(
            kind=kind,
            cwe=cwe,
            line=line,
            certain=False,
            severity="medium",
            title=memsafety_c.title_for(kind, False),
            evidence=f"Rust unsafe: {detail}{soundness_suffix}",
            function=fname,
            engine="sniper-memsafety-rust",
            soundness_bug=soundness_bug,
            pub_safe_api=pub_safe_api,
            proof_status=proof_status,
        )
        findings.setdefault((kind, line), f)

    def bounded(length: str, bases: list[str], body_txt: str, fn_back: str = "", back: str = "") -> bool:
        """Uzunluk ifadesi dilim uzunluğuna bağlı ya da onunla karşılaştırılıyor/min ile kısıtlanıyor mu?"""
        if ".min(" in length or "min(" in length or ".len()" in length or length.isdigit() or \
                "size_of" in length:
            return True
        if bases and any(_has_slice_len_guard(back, b) or _has_fn_interval_guard(fn_back, b) for b in bases):
            return True
        if bases and not any(
            re.search(
                rf"\b{re.escape(b)}\.len\(\)|\b{re.escape(b)}\[[^\]]*\.\.=?\s*[^\]]+\]|\b{re.escape(b)}(:\w+)?=&?\w+\[[^\]]*\.\.=?\s*[^\]]+\]",
                body_txt,
            )
            for b in bases
        ):
            return False
        var = re.split(r"[^\w]", length)[0] if length else ""
        if not var:
            return False
        if re.search(rf"\b{re.escape(var)}(:\w+)?=[^;]*(\.min\(|min\(|\.len\(\)|size_of|checked_mul|checked_add)", body_txt):
            return True
        if re.search(rf"\b{re.escape(var)}(<=|<|>=|>|==)(?!0\b)", body_txt) or \
                re.search(rf"(?<!\b0)(<=|<|>=|>|==)[&*]?{re.escape(var)}\b", body_txt):
            return True
        if re.search(rf"\b(?:(?:debug_)?assert(?:_eq|_ne)?|ensure)!?\([^;]*\b{re.escape(var)}\b", body_txt):
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

    def ptr_base(expr: str, body_txt: str = "") -> str:
        m = re.search(r"(\w+(?:\.\w+)*)(?:\[[^\]]*\])?\.as_(?:mut_)?ptr\(\)", expr)
        if m:
            return m.group(1)
        if body_txt and re.fullmatch(r"\w+", expr):
            m_var = re.search(
                rf"\b{re.escape(expr)}(?::[^=;]+)?=\s*(?:unsafe\s*\{{)?\s*(\w+(?:\.\w+)*)(?:\[[^\]]*\])?\.as_(?:mut_)?ptr\(\)",
                body_txt,
            )
            if m_var:
                return m_var.group(1)
        return ""

    n = len(toks)
    from_raw_seen: dict[tuple[int, str], int] = {}
    dropped_ptrs: dict[tuple[int, str], int] = {}
    for i, t in enumerate(toks):
        if t.kind == "id" and i + 1 < n and toks[i + 1].text == "=" and (from_raw_seen or dropped_ptrs):
            for key in [k for k in from_raw_seen if k[1] == t.text]:
                del from_raw_seen[key]  # işaretçi yeniden atandı (into_raw ile yeni sahip)
            for key in [k for k in dropped_ptrs if k[1] == t.text]:
                del dropped_ptrs[key]
        if t.kind != "id" or i + 1 >= n or toks[i + 1].text != "(" or not in_unsafe(i):
            continue
        name = t.text
        close = match_close(toks, i + 1)
        args = split_args(toks, i + 2, close)
        fn = fn_of(i)
        fname = toks[fn[2] + 1].text if fn else ""
        body = (fn[0], fn[1]) if fn else (0, n)
        fn_start_line = toks[fn[2]].line if fn else 1
        fn_back = (
            _COMMENT_RE.sub("", "\n".join(lines[max(0, fn_start_line - 1):max(0, t.line - 1)]))
            + "\n"
            + _text(toks, body[0], i)
        )
        back = (
            _COMMENT_RE.sub("", "\n".join(lines[max(fn_start_line - 1 if fn else 0, t.line - 8):max(0, t.line - 1)]))
            + "\n"
            + _text(toks, max(body[0], i - 40), i)
        )
        is_unsafe_fn = bool(
            fn and (fn[3] or any(toks[p].text == "unsafe" for p in range(max(0, fn[2] - 3), fn[2])))
        )
        is_pub_fn = bool(
            fn and any(toks[p].text == "pub" for p in range(max(0, fn[2] - 5), fn[2]))
        )
        soundness_kw = {
            "soundness_bug": bool(fn and not is_unsafe_fn),
            "pub_safe_api": bool(fn and not is_unsafe_fn and is_pub_fn),
            "proof_status": "unguarded_path_proven",
        }
        if name in ("from_raw_parts", "from_raw_parts_mut") and len(args) == 2 and \
                i >= 2 and toks[i - 1].text == "::" and toks[i - 2].text in ("slice",):
            ptr, ln = _text(toks, *args[0]), _text(toks, *args[1])
            body_txt = _text(toks, *body)
            base = ptr_base(ptr, body_txt)
            if not base:
                continue  # ham işaretçi parametresi (FFI sözleşmesi) — değerlendirilmez
            if ln == f"{base}.len()" or ".min(" in ln or "min(" in ln:
                continue
            if _has_slice_len_guard(back, base) or _has_fn_interval_guard(fn_back, base) or bounded(ln, [base], body_txt, fn_back, back):
                continue
            # uzunluk bu fonksiyonda dilimin len()'inden türetiliyor ya da onunla karşılaştırılıyor mu?
            lnv = ln.split(".")[0]
            if re.search(rf"\b{re.escape(lnv)}\s*=\s*{re.escape(base)}\.len\(\)", body_txt) or \
                    re.search(rf"\b{re.escape(lnv)}(:\w+)?=[^;]*(\.min\(|min\()", body_txt) or \
                    re.search(rf"{re.escape(lnv)}(<=|<|>=|>)[^;]*{re.escape(base)}\.len\(\)", body_txt) or \
                    re.search(rf"{re.escape(base)}\.len\(\)(<=|<|>=|>)[^;]*{re.escape(lnv)}\b", body_txt):
                continue
            add("overread", t.line, f"slice::{name}({base}.as_ptr(), {ln}): uzunluk `{base}.len()` ile "
                                    "sınırlandırılmıyor; sınır dışı okuma olası", fname, **soundness_kw)
        elif name in ("copy", "copy_nonoverlapping", "write_bytes") and i >= 2 and toks[i - 1].text == "::" and \
                toks[i - 2].text == "ptr" and len(args) == 3:
            a0, a1, ln = (_text(toks, *r) for r in args)
            body_txt = _text(toks, *body)
            dst_expr = a0 if name == "write_bytes" else a1
            bases = [b for b in (ptr_base(a0, body_txt), ptr_base(a1, body_txt)) if b]
            if any(_has_slice_len_guard(back, b) or _has_fn_interval_guard(fn_back, b) for b in bases):
                continue
            if bounded(ln, bases, body_txt, fn_back, back):
                continue
            kind = "overflow"
            add(kind, t.line, f"ptr::{name}(…, {ln}): kopya uzunluğu hedef/kaynak dilimin len()'i ile "
                              f"sınırlandırılmıyor (hedef `{dst_expr}`){len_field_note(ln, body_txt)}", fname, **soundness_kw)
        elif name in ("copy_from", "copy_from_nonoverlapping", "copy_to", "copy_to_nonoverlapping") and \
                i >= 1 and toks[i - 1].text == "." and len(args) == 2:
            a0, ln = _text(toks, *args[0]), _text(toks, *args[1])
            body_txt = _text(toks, *body)
            recv_expr = _text(toks, max(body[0], i - 8), i - 1)
            bases = [b for b in (ptr_base(a0, body_txt), ptr_base(recv_expr, body_txt)) if b]
            if any(_has_slice_len_guard(back, b) or _has_fn_interval_guard(fn_back, b) for b in bases):
                continue
            if bounded(ln, bases, body_txt, fn_back, back):
                continue
            add("overflow", t.line, f".{name}(…, {ln}): kopya uzunluğu dilim uzunluğuyla sınırlandırılmıyor"
                                    f"{len_field_note(ln, body_txt)}", fname, **soundness_kw)
        elif name == "set_len" and i >= 1 and toks[i - 1].text == "." and len(args) == 1:
            ln = _text(toks, *args[0])
            body_txt = _text(toks, *body)
            recv_var = toks[i - 2].text if i >= 2 and toks[i - 2].kind == "id" else ""
            note = len_field_note(ln, body_txt)
            if (recv_var and (_has_slice_len_guard(back, recv_var) or _has_fn_interval_guard(fn_back, recv_var))) or \
                    bounded(ln, [recv_var] if recv_var else [], body_txt, fn_back, back) or "capacity()" in body_txt or not note:
                continue  # yalnız iletideki uzunluk alanıyla (olgun kodda set_len(n) çoğunlukla belgelenmiş sözleşme)
            add("overread", t.line, f".set_len({ln}): yeni uzunluk capacity()/len() ile denetlenmiyor; başlatılmamış "
                                    f"ya da ayrılmamış bellek dilime giriyor{note}", fname, **soundness_kw)
        elif name in ("get_unchecked", "get_unchecked_mut") and len(args) == 1 and i >= 1 and toks[i - 1].text == "." \
                and ".." in _text(toks, *args[0]):
            rng = _text(toks, *args[0])
            end = rng.split("..", 1)[1].lstrip("=")
            body_txt = _text(toks, *body)
            recv_var = toks[i - 2].text if i >= 2 and toks[i - 2].kind == "id" else ""
            note = len_field_note(end, body_txt)
            if (recv_var and (_has_slice_len_guard(back, recv_var) or _has_fn_interval_guard(fn_back, recv_var))) or \
                    not end or end.isdigit() or bounded(end, [recv_var] if recv_var else [], body_txt, fn_back, back) or not note:
                continue  # yalnız uzunluk alanı (hdr.payload_size, from_be_bytes) ile sınırlanan aralıklar
            add("overflow" if name.endswith("_mut") else "overread", t.line,
                f".{name}({rng}): aralık sonu hiçbir len() ile karşılaştırılmıyor{note}", fname, **soundness_kw)
        elif name in ("get_unchecked", "get_unchecked_mut") and len(args) == 1 and i >= 1 and toks[i - 1].text == ".":
            idx = _text(toks, *args[0])
            if not re.fullmatch(r"\w+", idx) or idx.isdigit():
                continue
            body_txt = _text(toks, *body)
            recv_var = toks[i - 2].text if i >= 2 and toks[i - 2].kind == "id" else ""
            if recv_var and (_has_slice_len_guard(back, recv_var) or _has_fn_interval_guard(fn_back, recv_var)):
                continue
            if re.search(rf"\b{re.escape(idx)}\s*(<|<=|>=|>)\s*[\w.]*len\(\)", body_txt) or \
                    re.search(rf"len\(\)\s*(>|>=|<|<=)\s*{re.escape(idx)}\b", body_txt) or \
                    re.search(rf"\b{re.escape(idx)}\s*=\s*[^;]*\.min\(", body_txt) or \
                    re.search(rf"for\s*{re.escape(idx)}\s*in\s*0\s*\.\.", body_txt):
                continue
            add("overflow" if name.endswith("_mut") else "overread", t.line,
                f".{name}({idx}): indeks hiçbir len() ile karşılaştırılmıyor", fname, **soundness_kw)
        elif name in ("from_raw", "from_raw_parts") and i >= 2 and toks[i - 1].text == "::" and \
                toks[i - 2].text in ("Box", "Vec", "String", "Rc", "Arc", "CString", "Weak", "OsString") and args:
            ptr = _text(toks, *args[0])
            if not re.fullmatch(r"\w+", ptr):
                continue
            key = (body[0], ptr)
            if key in from_raw_seen:
                add("double_free", t.line, f"{toks[i - 2].text}::{name}({ptr}) aynı işaretçiyle ikinci kez "
                                           f"(satır {from_raw_seen[key]}); iki sahip aynı belleği serbest bırakır", fname)
            else:
                from_raw_seen[key] = t.line
        elif name in ("drop_in_place", "dealloc") and args:
            ptr = _text(toks, *args[0])
            if not re.fullmatch(r"\w+", ptr):
                continue
            key = (body[0], ptr)
            if key in from_raw_seen:
                add("double_free", t.line, f"{name}({ptr}) daha önce serbest bırakılan/sahiplenilen işaretçi "
                                           f"üzerinde çağrılıyor (satır {from_raw_seen[key]})", fname)
            else:
                from_raw_seen[key] = t.line
            dropped_ptrs[key] = t.line
        elif name in ("read", "read_volatile", "read_unaligned", "write", "write_volatile", "write_unaligned") and \
                i >= 2 and toks[i - 1].text == "::" and toks[i - 2].text == "ptr" and args:
            ptr = _text(toks, *args[0])
            key = (body[0], ptr)
            if key in dropped_ptrs:
                add("uaf", t.line, f"ptr::{name}({ptr}) serbest bırakılmış işaretçiyi (satır {dropped_ptrs[key]}) "
                                   f"kullanıyor (use-after-free)", fname)
    return sorted(findings.values(), key=lambda f: (f.line, f.kind))


analyze_rust = analyze_text

_RUST_AUDIT_FN_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?"
    r"fn\s+(?P<name>[A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\((?P<params>[^)]*)\)(?P<ret>[^{;]*)\{",
    re.DOTALL,
)
_RUST_PARSER_FN_NAME_RE = re.compile(
    r"(?:^|_)(?:parse|from_bytes|from_slice|deserialize|decode|read|unpack|unmarshal)(?:_|$)"
)


def _iter_rust_functions(cleaned: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
    n = len(cleaned)
    for m in _RUST_AUDIT_FN_RE.finditer(cleaned):
        fn_name = m.group("name")
        params = m.group("params")
        brace_open = m.end() - 1
        depth = 0
        k = brace_open
        while k < n:
            ch = cleaned[k]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    out.append((fn_name, params, cleaned[brace_open : k + 1], brace_open))
                    break
            k += 1
    return out


def audit_rust_binary_parser_and_stride_hazards(
    text: str,
    *,
    filename: str = "lib.rs",
) -> dict[str, Any]:
    """Wave-5 Rust ikili ayrıştırıcı (Panic-DoS) ve çok boyutlu çerçeve/düzlem stride (CWE-190) denetçisi:
    - SNIPER-RUST-STRIDE-01 (CWE-190): `copy_nonoverlapping` / `from_raw_parts` ile çerçeve/düzlem (BGRA/NV12)
      kopyalamasında `checked_mul`/`checked_add`, `stride < row_bytes` veya ikincil düzlem (`uv.len()`)
      doğrulamasının eksikliği.
    - SNIPER-RUST-PANIC-02 (CWE-248): Ağ/akış ikili ayrıştırıcısında (`parse_*`, `from_bytes`, `deserialize`,
      `decode`, `read_*`) sınır denetimsiz dilimleme (`&data[offset..offset + len]`) veya `.unwrap()`/`.expect()`
      ile uzaktan tetiklenebilir Panic-DoS.
    """
    if not text:
        return {
            "format": "sniper-rust-parser-stride-audit/1",
            "filename": filename,
            "finding_count": 0,
            "findings": [],
        }

    cleaned = _COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    for fn_name, params, body, brace_open in _iter_rust_functions(cleaned):
        # 1. SNIPER-RUST-STRIDE-01
        m_copy = re.search(r"\b(?:copy_nonoverlapping|from_raw_parts(?:_mut)?)\s*\(", body)
        has_stride_context = bool(
            re.search(r"\b(?:[a-z_]*stride|row_bytes|pitch|Nv12)\b", params + " " + body)
            or re.search(r"\b(?:row|y|r)\s*\*\s*[A-Za-z_]\w*|\b[A-Za-z_]\w*\s*\*\s*\(\s*(?:h|height)\s*-\s*1\s*\)", body)
        )
        if m_copy and has_stride_context:
            has_checked_mul = ".checked_mul(" in body
            has_checked_add = ".checked_add(" in body
            has_nv12_or_uv = bool(
                re.search(r"\b(?:Nv12|uv_stride|uv)\b", params + " " + body)
            )
            if has_nv12_or_uv and "y_stride" in (params + " " + body) and "uv_stride" in (params + " " + body):
                has_stride_guard = bool(
                    re.search(r"\by_stride\b\s*(?:<|>=)\s*\b(?:w|width|row_bytes)\b|\b(?:w|width|row_bytes)\b\s*(?:>|<=)\s*\by_stride\b", body)
                    and re.search(r"\buv_stride\b\s*(?:<|>=)\s*\b(?:w|width|row_bytes|uv_row_bytes)\b|\b(?:w|width|row_bytes|uv_row_bytes)\b\s*(?:>|<=)\s*\buv_stride\b", body)
                )
            else:
                has_stride_guard = bool(
                    re.search(
                        r"\b(?:[a-z_]*stride|pitch)\b\s*(?:<|>=)\s*\b(?:row_bytes|w|width|row_len)\b"
                        r"|\b(?:row_bytes|w|width|row_len)\b\s*(?:>|<=)\s*\b(?:[a-z_]*stride|pitch)\b"
                        r"|\b(?:[a-z_]*stride|pitch)\b\s*<\s*\b(?:w|width)\b\s*\*\s*\d+",
                        body,
                    )
                )

            if has_nv12_or_uv:
                has_plane_len_guard = bool(
                    re.search(r"\by\s*\.\s*len\s*\(\s*\)\s*(?:<|<=|>=|>)|(?:<|<=|>=|>)\s*\by\s*\.\s*len\s*\(\s*\)", body)
                    and re.search(r"\buv\s*\.\s*len\s*\(\s*\)\s*(?:<|<=|>=|>)|(?:<|<=|>=|>)\s*\buv\s*\.\s*len\s*\(\s*\)", body)
                )
            else:
                has_plane_len_guard = bool(
                    re.search(r"\.\s*len\s*\(\s*\)\s*(?:<|<=|>=|>)|(?:<|<=|>=|>)\s*[A-Za-z_]\w*\s*\.\s*len\s*\(\s*\)", body)
                )

            if not (has_checked_mul and has_checked_add and has_stride_guard and has_plane_len_guard):
                missing_parts: list[str] = []
                if not (has_checked_mul and has_checked_add):
                    missing_parts.append("checked_mul/checked_add taşma denetimi")
                if not has_stride_guard:
                    missing_parts.append("stride < row_bytes alt sınır doğrulaması")
                if not has_plane_len_guard:
                    missing_parts.append("düzlem tampon uzunluğu (.len()) doğrulaması")
                sink_line = cleaned.count("\n", 0, brace_open + m_copy.start()) + 1
                key = ("SNIPER-RUST-STRIDE-01", sink_line)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "rule_id": "SNIPER-RUST-STRIDE-01",
                            "id": "SNIPER-RUST-STRIDE-01",
                            "kind": "rust_stride_plane_overflow",
                            "cwe": "CWE-190",
                            "severity": "high",
                            "category": "memory_safety",
                            "title": "Rust çok boyutlu çerçeve/düzlem kopyalamasında (copy_nonoverlapping) denetimsiz stride/boyut çarpımı ve sınır aşımı",
                            "function": fn_name,
                            "line": sink_line,
                            "sink_line": sink_line,
                            "filename": filename,
                            "evidence": (
                                f"SNIPER-RUST-STRIDE-01: `{fn_name}` içinde `copy_nonoverlapping`/`from_raw_parts` "
                                f"öncesinde {', '.join(missing_parts)} eksik (CWE-190)"
                            ),
                        }
                    )

        # 2. SNIPER-RUST-PANIC-02
        is_parser_fn = bool(
            _RUST_PARSER_FN_NAME_RE.search(fn_name)
            and re.search(r"&\s*(?:mut\s+)?\[\s*u8\s*\]|\bCursor\b|\bBytes\b|\bVec\s*<\s*u8\s*>", params)
        )
        if is_parser_fn:
            panic_sink_pos: int | None = None
            panic_reason = ""

            for m_slice in re.finditer(r"\b(?P<svar>[A-Za-z_]\w*)\s*\[\s*(?P<rng>[^\]]*\.\.[^\]]*)\]", body):
                svar = m_slice.group("svar")
                rng = m_slice.group("rng").strip()
                pre_slice = body[: m_slice.start()]
                svar_esc = re.escape(svar)
                has_var_in_rng = bool(re.search(r"[A-Za-z_]\w*", rng))
                has_unchecked_plus = "+" in rng
                if has_unchecked_plus:
                    panic_sink_pos = m_slice.start()
                    panic_reason = f"`{svar}[{rng}]` dilimlemesinde `checked_add` ve sınır denetimi yok"
                    break
                if has_var_in_rng:
                    bound_vars = [
                        v for v in re.findall(r"[A-Za-z_]\w*", rng)
                        if v not in ("usize", "u32", "u64", "u16", "u8")
                    ]
                    guarded = any(
                        re.search(
                            rf"\b{svar_esc}\s*\.\s*len\s*\(\s*\)\s*(?:<|<=|>=|>)\s*[^;{{}}]*\b{re.escape(bv)}\b"
                            rf"|\b{re.escape(bv)}\b\s*(?:>|>=|<|<=)\s*{svar_esc}\s*\.\s*len\s*\(\s*\)",
                            pre_slice,
                        )
                        for bv in bound_vars
                    )
                    if not guarded:
                        panic_sink_pos = m_slice.start()
                        panic_reason = f"`{svar}[{rng}]` dinamik dilimlemesi `{svar}.len()` veya `.get(..)` ile doğrulanmıyor"
                        break
                else:
                    has_len_check = bool(
                        re.search(
                            rf"\b{svar_esc}\s*\.\s*len\s*\(\s*\)\s*(?:<|<=|>=|>)"
                            rf"|(?:<|<=|>=|>)\s*{svar_esc}\s*\.\s*len\s*\(\s*\)",
                            pre_slice,
                        )
                    )
                    if not has_len_check:
                        panic_sink_pos = m_slice.start()
                        panic_reason = f"`{svar}[{rng}]` sabit dilimlemesi öncesinde `{svar}.len()` denetimi yok"
                        break

            if panic_sink_pos is None:
                m_unwrap = re.search(r"\.\s*(?:unwrap|expect)\s*\(|\bassert(?:_eq|_ne)?\s*!\s*\(", body)
                if m_unwrap:
                    pre_unwrap = body[: m_unwrap.start()]
                    if not (
                        ".get(" in pre_unwrap
                        or re.search(r"\.\s*len\s*\(\s*\)\s*(?:<|<=|>=|>)", pre_unwrap)
                    ):
                        panic_sink_pos = m_unwrap.start()
                        panic_reason = "doğrulanmamış girdi üzerinde `.unwrap()`/`.expect()`/`assert!()` çağrısı"

            if panic_sink_pos is not None:
                sink_line = cleaned.count("\n", 0, brace_open + panic_sink_pos) + 1
                key = ("SNIPER-RUST-PANIC-02", sink_line)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "rule_id": "SNIPER-RUST-PANIC-02",
                            "id": "SNIPER-RUST-PANIC-02",
                            "kind": "rust_parser_panic_dos",
                            "cwe": "CWE-248",
                            "severity": "high",
                            "category": "dos",
                            "title": "Rust ağ/akış ikili ayrıştırıcısında doğrulanmamış dilimleme veya unwrap/expect ile uzaktan Panic-DoS",
                            "function": fn_name,
                            "line": sink_line,
                            "sink_line": sink_line,
                            "filename": filename,
                            "evidence": (
                                f"SNIPER-RUST-PANIC-02: `{fn_name}` ayrıştırıcısında {panic_reason}; "
                                f"bozuk/kısa paketle uzaktan Panic-DoS tetiklenebilir (CWE-248)"
                            ),
                        }
                    )

    return {
        "format": "sniper-rust-parser-stride-audit/1",
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }

