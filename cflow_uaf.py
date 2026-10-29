"""27. tur — C/C++ fonksiyonlar ve dosyalar arası serbest bırakılmış bellek kullanımı (use-after-free / double free).

Kalıp: küresel bir yuvadaki (``notes[i]``, ``users[i]->bio``, ``session->buf``) işaretçi bir işleyicide ``free`` edilir
ama yuva temizlenmez (NULL atanmaz, üzerine yazılmaz, sayaç azaltılmaz); başka bir işleyici aynı yuvayı
okur/yazar/yeniden serbest bırakır. Her iki işleyiciyi de çağıran ortak bir dağıtıcı (menü döngüsü, yönlendirme
tablosu) varsa ve yuva indeksi her iki tarafta da dış girdiden seçilebiliyorsa (ya da sabit/aynıysa) bulgu "kesin",
aksi halde "olası" sayılır. Belirteç düzeyindedir (taint_cfamily birimleri üzerinde); derleyici gerekmez.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from taint_native_core import FileUnit, Func, Tok, match_close, split_args

_FREE_FUNCS = frozenset({
    "free", "g_free", "kfree", "xfree", "cfree", "sqlite3_free", "OPENSSL_free",
    "efree", "vfree", "av_free", "CRYPTO_free", "zfree", "vPortFree",
    "HeapFree", "LocalFree", "GlobalFree", "xmlFree", "curl_free",
    "CoTaskMemFree", "free_sized", "free_aligned_sized",
})
_INPUT_NUM = frozenset({
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "strtoimax", "strtoumax", "stoi", "stol", "stoll", "stoul",
    "scanf", "sscanf", "fscanf", "read", "recv", "getchar", "fgetc", "getc",
})
_CHECK_PREV = frozenset({"!", "(", "&&", "||", "?"})
MAX_FINDINGS = 40


@dataclass
class Slot:
    base: str
    field: str
    indexed: bool


@dataclass
class Access:
    file: str
    line: int
    func: str
    kind: str  # free | use | write
    idx: str
    idx_chosen: bool
    pos: int


@dataclass
class Dangling:
    file: str
    line: int
    func: str
    kind: str  # uaf | double_free
    slot: str
    free_file: str
    free_line: int
    free_func: str
    certain: bool
    dispatcher: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _globals_of(units: list[FileUnit]) -> set[str]:
    """Dosya düzeyinde bildirilen değişken adları (yapı tanımı gövdeleri, prototipler ve typedef'ler hariç)."""
    out: set[str] = set()
    for u in units:
        toks = u.toks
        n = len(toks)
        bodies = sorted(f.body for f in u.funcs)
        b = 0
        i = 0
        stmt: list[Tok] = []
        while i < n:
            if b < len(bodies) and i >= bodies[b][0]:
                i = bodies[b][1] + 1
                b += 1
                stmt = []
                continue
            t = toks[i]
            if t.kind == "op" and t.text == "{":
                close = match_close(toks, i)
                if stmt and stmt[-1].text == "=":
                    stmt.append(Tok("op", "{}", t.line))  # küme ilk değeri: bildirim sürer
                elif any(x.text in ("struct", "union", "enum") for x in stmt):
                    stmt.append(Tok("op", "{}", t.line))  # struct T { … } ad; biçimi
                else:
                    stmt = []
                i = close + 1
                continue
            if t.kind == "op" and t.text in (";", "}"):
                if stmt and stmt[0].text not in ("typedef", "using", "namespace", "template", "return"):
                    depth = 0
                    names: list[str] = []
                    for k, x in enumerate(stmt):
                        if x.text in ("(", "["):
                            depth += 1
                        elif x.text in (")", "]"):
                            depth -= 1
                        elif depth == 0 and x.kind == "id" and k + 1 <= len(stmt) and \
                                (k + 1 == len(stmt) or stmt[k + 1].text in ("[", "=", ",")) and k > 0:
                            names.append(x.text)
                        if depth == 0 and x.text == "=":
                            break
                    proto = any(x.text == "(" for x in stmt) and not any(
                        stmt[k].text == "(" and k + 1 < len(stmt) and stmt[k + 1].text == "*" for k in range(len(stmt)))
                    if not proto:
                        out |= set(names)
                stmt = []
                i += 1
                continue
            stmt.append(t)
            i += 1
    return out


def _slot_at(toks: list[Tok], j: int, hi: int) -> tuple[Slot, int, str] | None:
    """``G[e]``, ``G[e]->f``, ``G[e].f``, ``G->f``, ``G.f`` (j: G belirteci) → (yuva, erişim sonu, indeks metni)."""
    base = toks[j].text
    k = j + 1
    idx = ""
    indexed = False
    if k < hi and toks[k].text == "[":
        c = match_close(toks, k, hi)
        idx = " ".join(t.text for t in toks[k + 1:c])
        indexed = True
        k = c + 1
    fld = ""
    if k + 1 < hi and toks[k].text in ("->", ".") and toks[k + 1].kind == "id":
        fld = toks[k + 1].text
        k += 2
        if k < hi and toks[k].text == "[":
            return None  # alanın içindeki dizi: yuva değil
    if not indexed and not fld:
        return None
    if k < hi and toks[k].text == "(":
        return None  # işlev işaretçisi çağrısı
    return Slot(base, fld, indexed), k, idx


def _chosen_index(toks: list[Tok], fn: Func, idx: str, before: int) -> bool:
    """İndeks dış girdiden seçilebiliyor mu: parametre, girdi okuma/sayıya çevirme çağrısının sonucu, scanf hedefi."""
    if not idx:
        return False
    if idx.isdigit():
        return True
    if " " in idx:
        return False
    if any(p.name == idx for p in fn.params):
        return True
    lo, hi = fn.body
    for q in range(lo + 1, min(before, hi) - 2):
        t = toks[q]
        if t.kind == "id" and t.text == idx and toks[q + 1].text == "=" and toks[q + 2].kind == "id":
            nxt = toks[q + 2].text
            if nxt in _INPUT_NUM or (q + 3 < hi and toks[q + 3].text == "(" and nxt not in ("sizeof", "strlen", "rand")):
                return True
        if t.kind == "op" and t.text == "&" and toks[q + 1].kind == "id" and toks[q + 1].text == idx:
            # scanf("%d", &idx)
            k = q
            while k > lo and toks[k].text not in (";", "{", "}"):
                if toks[k].kind == "id" and toks[k].text in ("scanf", "sscanf", "fscanf", "read", "recv"):
                    return True
                k -= 1
    return False


def _classify(toks: list[Tok], j: int, end: int, hi: int) -> str:
    """Erişim bağlamı: write (``= …`` sol taraf), check (yalnız NULL denetimi), use."""
    nxt = toks[end].text if end < hi else ""
    if nxt == "=":
        return "write"
    prev = toks[j - 1].text if j > 0 else ""
    if nxt in ("==", "!=") and end + 1 < hi and toks[end + 1].text in ("NULL", "0", "nullptr"):
        return "check"
    if prev == "!" or (prev in ("(", "&&", "||") and nxt in (")", "&&", "||", "?")):
        if not (j >= 2 and toks[j - 2].kind == "id" and toks[j - 2].text not in ("if", "while", "return")):
            return "check"
    if prev == "&" and not (j >= 2 and toks[j - 2].kind in ("id", "num") or (j >= 2 and toks[j - 2].text in (")", "]"))):
        return "addr"
    if prev == "sizeof" or (j >= 2 and toks[j - 2].text == "sizeof"):
        return "check"
    return "use"


def analyze(units: list[FileUnit], calls: dict[str, set[str]]) -> list[Dangling]:
    """Proje birimleri ve çağrı kenarları (çağıran → çağrılanlar; dolaylı çağrılar dahil) → sarkan yuva bulguları."""
    globs = _globals_of(units)
    if not globs:
        return []
    by_key: dict[tuple[str, str], list[Access]] = {}
    cleared: dict[tuple[str, str, str], list[int]] = {}  # (fonksiyon, taban, alan) → yazma konumları
    counters: dict[str, list[int]] = {}  # fonksiyon → küresel tamsayı güncelleme konumları
    funcs_by_name: dict[str, tuple[FileUnit, Func]] = {}
    for u in units:
        toks = u.toks
        for fn in u.funcs:
            funcs_by_name.setdefault(fn.name, (u, fn))
            lo, hi = fn.body
            local_names = {p.name for p in fn.params}
            for q in range(lo + 1, hi - 1):
                x = toks[q]
                if x.kind == "id" and x.text in globs and toks[q - 1].kind == "id" and \
                        toks[q - 1].text not in ("return", "case", "else", "goto", "sizeof") and \
                        toks[q + 1].text in ("[", "=", ";", ","):
                    local_names.add(x.text)  # aynı adlı yerel bildirim (gölgeleme)
                elif x.kind == "id" and x.text in globs and toks[q - 1].text == "*" and toks[q - 2].kind == "id" and \
                        toks[q - 2].text not in ("return",) and toks[q - 3].text in (";", "{", "}", "(", ","):
                    local_names.add(x.text)
            j = lo + 1
            while j < hi:
                t = toks[j]
                if t.kind == "id" and t.text in globs and t.text not in local_names and \
                        (j == 0 or toks[j - 1].text not in (".", "->")):
                    got = _slot_at(toks, j, hi)
                    if got is not None:
                        slot, end, idx = got
                        key = (slot.base, slot.field)
                        ctx = _classify(toks, j, end, hi)
                        # free(G[i]) / free(G[i]->f)
                        is_free = j >= 2 and toks[j - 1].text == "(" and toks[j - 2].kind == "id" and \
                            toks[j - 2].text in _FREE_FUNCS and end < hi and toks[end].text == ")"
                        if ctx == "write":
                            cleared.setdefault((fn.name, slot.base, slot.field), []).append(j)
                            # alan yazımı yuvayı (G[i]) da yeniden kullanır
                            if slot.field:
                                cleared.setdefault((fn.name, slot.base, ""), []).append(j)
                        elif is_free or ctx == "use":
                            by_key.setdefault(key, []).append(Access(
                                u.path, t.line, fn.name, "free" if is_free else "use", idx,
                                _chosen_index(toks, fn, idx, j), j))
                        j = end
                        continue
                    # küresel sayaç güncellemesi: n--, --n, n -= …, n = …
                    nx = toks[j + 1].text if j + 1 < hi else ""
                    pv = toks[j - 1].text if j > 0 else ""
                    if nx in ("--", "-=", "=") or pv == "--":
                        if not (j + 1 < hi and toks[j + 1].text == "[") and nx != "==":
                            counters.setdefault(fn.name, []).append(j)
                if t.kind == "id" and t.text in ("memset", "memmove", "memcpy", "bzero") and j + 2 < hi and \
                        toks[j + 1].text == "(":
                    c = match_close(toks, j + 1, hi)
                    args = split_args(toks, j + 2, c)
                    if args:
                        names = [x.text for x in toks[args[0][0]:args[0][1]] if x.kind == "id"]
                        for nm in names[:1]:
                            if nm in globs:
                                cleared.setdefault((fn.name, nm, ""), []).append(j)
                j += 1
    # ortak dağıtıcı: çağıranların (en çok 4 adım) kesişimi
    callers: dict[str, set[str]] = {}
    for caller, callees in calls.items():
        for c in callees:
            callers.setdefault(c, set()).add(caller)

    def ancestors(name: str) -> set[str]:
        seen: set[str] = set()
        frontier = {name}
        for _ in range(4):
            nxt: set[str] = set()
            for x in frontier:
                for c in callers.get(x, ()):
                    if c not in seen:
                        seen.add(c)
                        nxt.add(c)
            frontier = nxt
            if not frontier:
                break
        return seen

    out: list[Dangling] = []
    seen_use: set[tuple[str, int]] = set()
    for key, accs in sorted(by_key.items()):
        frees = [a for a in accs if a.kind == "free"]
        if not frees:
            continue
        for fr in frees:
            # yuva aynı fonksiyonda free sonrasında temizleniyor mu / küresel sayaç güncelleniyor mu?
            clr = [p for p in cleared.get((fr.func, key[0], key[1]), []) if p > fr.pos] + \
                [p for p in cleared.get((fr.func, key[0], ""), []) if p > fr.pos]
            cnt = [p for p in counters.get(fr.func, []) if p > fr.pos]
            if clr or cnt:
                continue
            anc_f = ancestors(fr.func)
            for us in accs:
                if us.func == fr.func or (us.file, us.line) in seen_use:
                    continue
                # kullanan fonksiyon yuvayı kullanmadan önce yeniden atıyor mu?
                pre = [p for p in cleared.get((us.func, key[0], key[1]), []) + cleared.get((us.func, key[0], ""), [])
                       if p < us.pos]
                if pre:
                    continue
                common = sorted(anc_f & ancestors(us.func))
                if not common:
                    continue
                same_slot = (not fr.idx and not us.idx) or (fr.idx_chosen and us.idx_chosen) or \
                    (fr.idx == us.idx and fr.idx.isdigit())
                kind = "double_free" if us.kind == "free" else "uaf"
                slot = f"{key[0]}[]" if fr.idx else key[0]
                if key[1]:
                    slot += f"->{key[1]}"
                out.append(Dangling(us.file, us.line, us.func, kind, slot, fr.file, fr.line, fr.func,
                                    certain=same_slot, dispatcher=common[0]))
                seen_use.add((us.file, us.line))
                if len(out) >= MAX_FINDINGS:
                    return out
    return out
