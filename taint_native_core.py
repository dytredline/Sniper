"""Rust ve C/C++ hızlı taint motorlarının ortak çekirdeği (saf Python, belirteç tabanlı).

İçerik: belirteç ayrıştırıcı (Rust ham dizgeleri/yaşam süreleri, C önişlemcisi ve nesne biçimli makrolar),
fonksiyon modeli, kaynak kökenleri (``Origin``), fonksiyon özetleri ve dosyalar arası sabit nokta sürücüsü.
Dile özgü kaynak/hedef/ayrıştırma kuralları ``taint_rust`` ve ``taint_cfamily`` modüllerindedir.

Yaklaşım taint_goruby ile aynıdır: her fonksiyon bir kez simgesel parametre kökenleriyle (``param:i``) ve
gerçek kaynaklarla birlikte yürütülür; hedefe ulaşan parametre kökenleri fonksiyon özetine (param → hedef,
param → dönüş, param → çıkış parametresi) yazılır, gerçek kökenler akış üretir. Özetler ve küresel değişken
kirliliği birkaç turda sabit noktaya getirilir. Akışa duyarsızdır (dal birleşimi yok, sıralı güçlü güncelleme).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from taint_flow import Analysis, Flow

# Bir dosyada en çok bu kadar belirteç işlenir (çok büyük üretilmiş dosyalar atlanır).
MAX_TOKENS_PER_FILE = 400_000
# Sabit nokta turu üst sınırı (özetler + küresel kirlilik).
MAX_ROUNDS = 5
# Ad tabanlı çağrı çözümlemesinde en çok aday.
MAX_CANDIDATES = 3
# Özet zinciri (via) uzunluğu üst sınırı.
MAX_VIA = 6
# Kanıt zinciri (hops) adım üst sınırı.
MAX_HOPS = 7
# Özet başına en çok bu kadar parametre → yapı alanı yazımı (yardımcı fonksiyon zincirlerinde patlamayı sınırlar).
MAX_FIELD_WRITES = 24


# ---------------------------------------------------------------------------
# Belirteçler
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Tok:
    kind: str  # id | str | num | op | chr | life
    text: str  # dizgede ayıklanmış içerik (tırnaksız, kaçışlar kaba çözülmüş)
    line: int


_OPS3 = ("<<=", ">>=", "...", "..=", "->*")
_OPS2 = ("::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "^=", "|=", "&=",
         "<<", ">>", "..", "++", "--", "##")
_IDENT_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789")
_DIGITS = frozenset("0123456789")


def _unescape(raw: str) -> str:
    """Kaba kaçış çözümü: yalnız içerik denetimleri (\"-c\", \"text/html\", \"%s\") için yeterli."""
    if "\\" not in raw:
        return raw
    out, i, n = [], 0, len(raw)
    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"'}
    while i < n:
        ch = raw[i]
        if ch == "\\" and i + 1 < n:
            nxt = raw[i + 1]
            out.append(simple.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def tokenize(text: str, *, rust: bool, skip_ranges: list[tuple[int, int]] | None = None) -> list[Tok]:
    """Rust ya da C/C++ kaynağını belirteçlere ayırır. ``skip_ranges``: atlanacak (başlangıç, bitiş) karakter aralıkları
    (C önişlemcisinin devre dışı bıraktığı bölgeler)."""
    toks: list[Tok] = []
    i, n, line = 0, len(text), 1
    skips = sorted(skip_ranges or [])
    skip_idx = 0
    append = toks.append
    while i < n:
        if skips and skip_idx < len(skips) and i >= skips[skip_idx][0]:
            start, end = skips[skip_idx]
            skip_idx += 1
            if i < end:
                line += text.count("\n", i, end)
                i = end
                continue
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r\f\v":
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            if nxt == "*":
                if rust:  # Rust blok yorumları iç içe olabilir
                    depth, j = 1, i + 2
                    while j < n and depth:
                        if text.startswith("/*", j):
                            depth += 1
                            j += 2
                        elif text.startswith("*/", j):
                            depth -= 1
                            j += 2
                        else:
                            j += 1
                else:
                    j = text.find("*/", i + 2)
                    j = n if j < 0 else j + 2
                line += text.count("\n", i, j)
                i = j
                continue
        if ch in _IDENT_START:
            j = i + 1
            while j < n and text[j] in _IDENT_CHARS:
                j += 1
            word = text[i:j]
            # Dizge önekleri: Rust r"..", r#".."#, b"..", br"..", b'x'; C/C++ L"..", u8"..", u"..", U"..", R"d(..)d"
            if j < n and text[j] in "\"'#" and word in ({"r", "b", "br", "rb"} if rust else {"L", "u8", "u", "U", "R", "LR", "u8R", "uR", "UR"}):
                if rust and word in {"r", "br", "rb"} and text[j] in "#\"":
                    k = j
                    while k < n and text[k] == "#":
                        k += 1
                    if k < n and text[k] == '"':
                        hashes = k - j
                        closing = '"' + "#" * hashes
                        end = text.find(closing, k + 1)
                        end = n if end < 0 else end
                        append(Tok("str", text[k + 1:end], line))
                        line += text.count("\n", i, end)
                        i = end + len(closing)
                        continue
                elif not rust and word.endswith("R") and text[j] == '"':
                    paren = text.find("(", j + 1)
                    if 0 < paren - j <= 17:
                        delim = text[j + 1:paren]
                        closing = ")" + delim + '"'
                        end = text.find(closing, paren + 1)
                        end = n if end < 0 else end
                        append(Tok("str", text[paren + 1:end], line))
                        line += text.count("\n", i, end)
                        i = end + len(closing)
                        continue
                elif text[j] in "\"'":
                    i = j  # önek atılır, dizge/karakter aşağıda okunur
                    continue
            append(Tok("id", word, line))
            i = j
            continue
        if ch in _DIGITS or (ch == "." and i + 1 < n and text[i + 1] in _DIGITS and not (toks and toks[-1].text == ".")):
            j = i + 1
            while j < n and (text[j] in _IDENT_CHARS or (text[j] == "." and j + 1 < n and text[j + 1] in _DIGITS)
                             or (text[j] in "+-" and text[j - 1] in "eEpP" and not text[i:j].startswith(("0x", "0X")))
                             or text[j] == "'"):
                if text[j] == "'" and not (j + 1 < n and text[j + 1] in _IDENT_CHARS):
                    break
                j += 1
            append(Tok("num", text[i:j], line))
            i = j
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                c = text[j]
                if c == "\\":
                    j += 2
                    continue
                if c == '"':
                    break
                if c == "\n" and not rust:
                    break
                j += 1
            raw = text[i + 1:j]
            append(Tok("str", _unescape(raw), line))
            line += raw.count("\n")
            i = j + 1
            continue
        if ch == "'":
            # Rust: karakter değişmezi mi yaşam süresi/etiket mi?
            if rust:
                if i + 2 < n and text[i + 1] == "\\":
                    end = text.find("'", i + 2)
                    if end > 0 and end - i <= 12:
                        append(Tok("chr", _unescape(text[i + 1:end]), line))
                        i = end + 1
                        continue
                if i + 2 < n and text[i + 2] == "'":
                    append(Tok("chr", text[i + 1], line))
                    i += 3
                    continue
                # çok baytlı karakter: 'ğ'
                if i + 1 < n and text[i + 1] not in _IDENT_CHARS:
                    end = text.find("'", i + 1)
                    if 0 < end - i <= 6:
                        append(Tok("chr", text[i + 1:end], line))
                        i = end + 1
                        continue
                j = i + 1
                while j < n and text[j] in _IDENT_CHARS:
                    j += 1
                append(Tok("life", text[i:j], line))
                i = j
                continue
            j = i + 1
            while j < n and text[j] != "'" and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            append(Tok("chr", _unescape(text[i + 1:j]), line))
            i = j + 1
            continue
        three = text[i:i + 3]
        if three in _OPS3:
            append(Tok("op", three, line))
            i += 3
            continue
        two = text[i:i + 2]
        if two in _OPS2:
            append(Tok("op", two, line))
            i += 2
            continue
        append(Tok("op", ch, line))
        i += 1
        if len(toks) > MAX_TOKENS_PER_FILE:
            break
    return toks


def match_close(toks: list[Tok], i: int, hi: int | None = None) -> int:
    """``toks[i]`` açılış ayracının ((, [, {) kapanış dizinini döndürür; bulunamazsa ``hi``/son dizin."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = toks[i].text
    closer = pairs.get(opener)
    if closer is None:
        return i
    hi = len(toks) if hi is None else hi
    depth = 0
    for j in range(i, hi):
        t = toks[j]
        if t.kind != "op":
            continue
        if t.text in "([{":
            depth += 1
        elif t.text in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return hi - 1 if hi > i else i


def split_args(toks: list[Tok], lo: int, hi: int, *, angle: bool = False) -> list[tuple[int, int]]:
    """``[lo, hi)`` aralığını üst düzey virgüllerden böler (parantez/köşeli/küme; ``angle`` ile <> da)."""
    out: list[tuple[int, int]] = []
    depth = 0
    start = lo
    for j in range(lo, hi):
        t = toks[j]
        if t.kind != "op":
            continue
        x = t.text
        if x in "([{":
            depth += 1
        elif x in ")]}":
            depth -= 1
        elif angle and x == "<":
            depth += 1
        elif angle and x == ">":
            depth -= 1
        elif angle and x == ">>":
            depth -= 2
        elif x == "," and depth == 0:
            out.append((start, j))
            start = j + 1
    if start < hi:
        out.append((start, hi))
    return out


# ---------------------------------------------------------------------------
# Kökenler ve değerler
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Origin:
    """Bir değerin kirlilik kökeni. ``label``: request | local | param. ``param`` yalnız simgesel kökende."""

    label: str
    source: str
    line: int
    file: str
    via: tuple[str, ...] = ()
    numeric: bool = False  # sayısal dönüşümden geçti (dize hedeflerinde etkisiz; dizi indeksi/uzunlukta etkili)
    param: int = -1
    fixed_host: bool = False  # URL sabit şema+ana makineyle başlıyor (kısmi SSRF)
    # 27. tur (C): kirli dizginin saldırganca ulaşılabilir en büyük uzunluğu — verinin geçtiği en küçük sabit kabın
    # boyutu (recv uzunluğu, ``char val[256]`` …). None: bilinmiyor; -1: doğası gereği sınırsız (argv, getenv, gets).
    cap: int | None = None
    # 27. tur (C): kanıt zinciri adımları ("dosya:satır açıklama"; çağrı yeri, yapı alanı yazımı, yönlendirme tablosu)
    hops: tuple[str, ...] = ()
    # 27. tur düzeltmesi (C): zincirde modelce kanıtlanmamış adım var mı (belirsiz ad çözümlemesi, işlev işaretçisi,
    # bilinmeyen işlevden geçiş, küresel/yapı alanı modeli, yalnız ad örüntüsüyle tanınan soket). Yalnız kanıt izleyen
    # motorlar (``BodyAnalyzer.TRACK_PROOF``) doldurur.
    weak: bool = False
    # via içindeki "aktarım" adımı sayısı: değer yardımcı fonksiyondan dönüş/çıkış parametresiyle geri geldi (çağrı
    # derinliği değil; özet çağrı yerinin gerçek argümanlarıyla uygulanır).
    xfer: int = 0

    def _copy(self, **kw: Any) -> "Origin":
        vals = {"label": self.label, "source": self.source, "line": self.line, "file": self.file, "via": self.via,
                "numeric": self.numeric, "param": self.param, "fixed_host": self.fixed_host, "cap": self.cap,
                "hops": self.hops, "weak": self.weak, "xfer": self.xfer}
        vals.update(kw)
        return Origin(**vals)

    def as_numeric(self) -> "Origin":
        return self if self.numeric else self._copy(numeric=True)

    def with_host(self) -> "Origin":
        return self if self.fixed_host else self._copy(fixed_host=True)

    def with_cap(self, cap: int | None) -> "Origin":
        """Kap boyutu sınırı: bilinen sınırlar arasında küçüğü (sınırsız/bilinmeyen kökende verilen sınır)."""
        if cap is None or cap < 0:
            return self
        new = cap if self.cap is None or self.cap < 0 else min(self.cap, cap)
        if new == self.cap:
            return self
        return self._copy(cap=new)

    def with_hop(self, hop: str) -> "Origin":
        if not hop or (self.hops and self.hops[-1] == hop):
            return self
        return self._copy(hops=_push_hop(self.hops, hop))

    def weakened(self) -> "Origin":
        return self if self.weak else self._copy(weak=True)

    def through(self, name: str, hop: str = "", *, xfer: bool = False, weak: bool = False) -> "Origin":
        weak = weak or self.weak
        if len(self.via) >= MAX_VIA or (self.via and self.via[-1] == name):
            # zincir dolu ya da aynı adım: via büyümez, ama kanıtsız adım bilgisi kaybolmaz
            return self if weak == self.weak else self._copy(weak=weak)
        hops = _push_hop(self.hops, hop) if hop else self.hops
        return self._copy(via=self.via + (name,), hops=hops, weak=weak, xfer=self.xfer + (1 if xfer else 0))


def weaken(t: frozenset) -> frozenset:
    """Kökenleri "modelce kanıtlanmamış adımdan geçti" olarak işaretler."""
    if not t or all(o.weak for o in t):
        return t
    return frozenset(o.weakened() for o in t)


def _push_hop(hops: tuple[str, ...], hop: str) -> tuple[str, ...]:
    """Kanıt zinciri adımı ekler; sınırda en eski çağrı adımı atılır (alan yazımları ve tablo kayıtları korunur)."""
    if len(hops) < MAX_HOPS:
        return hops + (hop,)
    for i, h in enumerate(hops):
        if h.endswith("()"):
            return hops[:i] + hops[i + 1:] + (hop,)
    return hops[1:] + (hop,)


Taint = frozenset  # frozenset[Origin]
EMPTY: frozenset = frozenset()


def numeric(t: frozenset) -> frozenset:
    return frozenset(o.as_numeric() for o in t) if t else t


def strings_only(t: frozenset) -> frozenset:
    return frozenset(o for o in t if not o.numeric) if t else t


def with_host(t: frozenset) -> frozenset:
    return frozenset(o.with_host() for o in t) if t else t


def okey(o: Origin) -> tuple:
    """Köken için tam, kararlı sıralama anahtarı (determinizm: frozenset yinelemesi PYTHONHASHSEED'e bağlıdır)."""
    return (o.file, o.line, o.source, o.label, o.via, o.numeric, o.param, o.fixed_host,
            -2 if o.cap is None else o.cap, o.hops, o.weak, o.xfer)


def osorted(t: Iterable[Origin]) -> list[Origin]:
    return sorted(t, key=okey)


def _rank(o: Origin) -> tuple:
    # 19. tur: eşitlikte karma sırası yerine tam anahtar (sınır 6'da hangi kökenlerin kaldığı kararlı olsun)
    # kanıtlı (weak=False) köken aynı etiket/tür içinde önce tutulur
    return (0 if o.label == "request" else 1 if o.label == "local" else 2, o.numeric, o.weak, o.line) + okey(o)


def compact(t: Iterable[Origin], limit: int = 6) -> frozenset:
    """Değer başına köken sayısını sınırlar (istek > yerel > param; aynı param tek)."""
    unique = t if isinstance(t, (set, frozenset)) else set(t)
    if len(unique) <= 1:  # 19. tur hız: boş/tek köken için sıralama gereksiz (aynı sonuç)
        return frozenset(unique)
    items = sorted(unique, key=_rank)
    out: list[Origin] = []
    seen_params: set[tuple[int, bool]] = set()
    for o in items:
        if o.label == "param":
            key = (o.param, o.numeric)
            if key in seen_params:
                continue
            seen_params.add(key)
        out.append(o)
        if len(out) >= limit:
            break
    return frozenset(out)


# ---------------------------------------------------------------------------
# Fonksiyon modeli ve özetler
# ---------------------------------------------------------------------------


@dataclass
class Param:
    name: str
    type_text: str
    index: int
    names: tuple[str, ...] = ()  # desen bağlamaları (Path(id) → id)


@dataclass
class Func:
    name: str
    qual: str
    file: str
    params: list[Param]
    body: tuple[int, int]  # belirteç aralığı: '{' dizini, '}' dizini
    line: int
    cls: str = ""
    is_static: bool = False
    is_handler: bool = False
    has_self: bool = False
    attrs: str = ""
    ret_type: str = ""

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.file, self.qual, self.line)


@dataclass(frozen=True, slots=True)
class SinkHit:
    """Özet içindeki param → hedef kaydı (hedef çağrılan fonksiyonda, ``file``:``line``)."""

    kind: str
    sink: str
    line: int
    file: str
    param: int
    via: tuple[str, ...]
    # "str": dize hedefi (sayısal köken etkisiz); "num": sayısal hedef, parametre ham kullanılmış (çağıran köken
    # sayısal olmalı); "any": sayısal hedef, parametre çağrılan içinde sayıya çevrilmiş (her köken geçerli)
    mode: str
    # 27. tur düzeltmesi (C): parametreden hedefe giden yolda kanıtsız adım / via içindeki aktarım adımı sayısı
    weak: bool = False
    xfer: int = 0


# Özet başına en çok bu kadar param → hedef kaydı (yardımcı fonksiyonlarda geçişli hedef patlamasını sınırlar).
MAX_SUMMARY_SINKS = 48


@dataclass
class Summary:
    sinks: dict[tuple, SinkHit] = field(default_factory=dict)

    def add_sink(self, hit: SinkHit) -> None:
        key = (hit.kind, hit.line, hit.file, hit.param, hit.mode)
        old = self.sinks.get(key)
        if old is not None:
            # kanıtlı yol, kanıtsız olanın yerini alır (aynı hedef, aynı parametre)
            if old.weak and not hit.weak:
                self.sinks[key] = hit
            return
        if len(self.sinks) >= MAX_SUMMARY_SINKS:
            return
        self.sinks[key] = hit

    ret_params: set[tuple[int, bool]] = field(default_factory=set)  # (param, sayısal mı)
    # 27. tur düzeltmesi (C): dönüşe yalnız kanıtsız adımla ulaşan parametreler
    ret_weak: set[int] = field(default_factory=set)
    ret_sources: set[Origin] = field(default_factory=set)
    out_params: dict[int, set[Origin]] = field(default_factory=dict)  # çıkış parametresine yazılan kökenler
    # Çıkış parametresi her yürütmede doğrudan ``*out = ...`` ile güçlü biçimde yazılıyorsa çağırandaki eski
    # değer korunmaz. Bu bilgi olmazsa ``set(out, temiz)`` sonrasında önceki kir yanlış pozitif üretir.
    out_overwrite: set[int] = field(default_factory=set)
    # 27. tur (C): parametre → yapı alanı yazımı (alan duyarlı küresel kirlilik anahtarı → parametre dizinleri)
    field_writes: dict[tuple, set[int]] = field(default_factory=dict)
    # C: yapı alıcısı da bir parametre olduğunda etki çağrı yerindeki somut nesneye özelleştirilebilir.
    # Anahtar: (alıcı parametre dizini, tür düzeyi alan anahtarı); değer: alana yazılan kökenler.
    receiver_field_writes: dict[tuple[int, tuple], set[Origin]] = field(default_factory=dict)
    receiver_field_sites: dict[tuple[int, tuple], tuple[str, int | None]] = field(default_factory=dict)

    def signature(self) -> tuple:
        return (frozenset(self.sinks.values()), frozenset(self.ret_params), frozenset(self.ret_weak),
                frozenset(self.ret_sources),
                frozenset((k, frozenset(v)) for k, v in self.out_params.items()),
                frozenset(self.out_overwrite),
                frozenset((k, frozenset(v)) for k, v in self.field_writes.items()),
                frozenset((k, frozenset(v)) for k, v in self.receiver_field_writes.items()))


@dataclass
class FileUnit:
    path: str
    toks: list[Tok]
    funcs: list[Func] = field(default_factory=list)
    macros: dict[str, Tok] = field(default_factory=dict)
    info: dict[str, Any] = field(default_factory=dict)


class Program:
    """Proje genelinde fonksiyonlar, özetler ve küresel kirlilik."""

    def __init__(self, units: list[FileUnit]):
        self.units = units
        self.by_name: dict[str, list[Func]] = {}
        for unit in units:
            for fn in unit.funcs:
                self.by_name.setdefault(fn.name, []).append(fn)
        self.classes = {f.cls for fs in self.by_name.values() for f in fs if f.cls}
        self.summaries: dict[tuple, Summary] = {}
        self.globals: dict[tuple[str, str], frozenset] = {}
        self.global_names: set[str] = set()
        self.limitations: set[str] = set()

    def summary(self, fn: Func) -> Summary:
        s = self.summaries.get(fn.key)
        if s is None:
            s = self.summaries[fn.key] = Summary()
        return s

    def resolve(self, name: str, file: str, nargs: int | None, *, method: bool = False, cls: str = "",
                strict: bool = False) -> list[Func]:
        cands = self.by_name.get(name)
        if not cands:
            return []
        if method:
            pool = [f for f in cands if f.has_self or f.cls]
        else:
            pool = [f for f in cands if not f.has_self]
        if cls:
            exact = [f for f in pool if f.cls == cls]
            if exact:
                pool = exact
            elif strict:
                return []
        if nargs is not None:
            fit = [f for f in pool if len(f.params) == nargs or (f.params and f.params[-1].type_text.strip() == "...")]
            if fit:
                pool = fit
            elif pool and not method:
                return []
        same = [f for f in pool if f.file == file]
        if same:
            if len(same) > MAX_CANDIDATES:
                self.limitations.add("call-candidates")
            return same[:MAX_CANDIDATES]
        others = [f for f in pool if not f.is_static]
        if len(others) > MAX_CANDIDATES:
            self.limitations.add("call-candidates")
            return []
        return others


def make_flow(language: str, kind: str, sink: str, sink_line: int, sink_file: str, o: Origin,
              extra_via: tuple[str, ...] = (), *, extra_xfer: int = 0, extra_weak: bool = False) -> Flow:
    via = o.via + extra_via
    if len(via) > MAX_VIA:
        via = via[:MAX_VIA]
    return Flow(language, kind, sink, sink_line, o.source, o.label, o.line, via, sink_file,
                o.file if o.file != sink_file else "", tuple(o.hops), weak=o.weak or extra_weak,
                xfer=min(len(via), o.xfer + extra_xfer))


@dataclass
class Collector:
    """Dosya başına analiz çıktısı (akışlar, değerlendirilen/belirsiz hedefler)."""

    analyses: dict[str, Analysis]
    language_of: dict[str, str]
    seen: set[tuple] = field(default_factory=set)
    # 27. tur (C): dosyalar arası model olguları (bellek motoru bunları dış girdi bilgisi olarak kullanır)
    facts: dict[str, Any] = field(default_factory=dict)

    def analysis(self, path: str) -> Analysis:
        a = self.analyses.get(path)
        if a is None:
            a = self.analyses[path] = Analysis(language=self.language_of.get(path, "c"))
        return a

    def flow(self, flow: Flow) -> None:
        key = (flow.file, flow.line, flow.sink_kind, flow.source_line, flow.source_file, flow.source_label)
        if key in self.seen:
            if not flow.weak:
                # 27. tur düzeltmesi: aynı kaynak→hedef için kanıtlı zincir, önce bulunan kanıtsız zincirin yerini alır
                flows = self.analysis(flow.file).flows
                for i, f in enumerate(flows):
                    if f.weak and (f.file, f.line, f.sink_kind, f.source_line, f.source_file, f.source_label) == key:
                        flows[i] = flow
                        break
            return
        # Aynı hedef satırında aynı türden en çok 2 farklı kaynak.
        same = [k for k in self.seen if k[0] == flow.file and k[1] == flow.line and k[2] == flow.sink_kind]
        if len(same) >= 2:
            return
        self.seen.add(key)
        self.analysis(flow.file).flows.append(flow)

    def evaluated(self, path: str, kind: str, line: int) -> None:
        self.analysis(path).evaluated_sinks.add((kind, line))

    def uncertain(self, path: str, kind: str, line: int) -> None:
        self.analysis(path).uncertain_sinks.add((kind, line))


def iter_param_origins(t: frozenset) -> Iterator[Origin]:
    for o in t:
        if o.label == "param":
            yield o


def real_origins(t: frozenset) -> list[Origin]:
    return [o for o in t if o.label != "param"]


# ---------------------------------------------------------------------------
# Fonksiyon gövdesi yürütücüsü (dile özgü kancalarla)
# ---------------------------------------------------------------------------

# Yerel girdinin (komut satırı, ortam, standart girdi) raporlandığı hedef türleri: bu türlerde yerel girdi de
# bellek güvenliği/biçim dizgesi hatasıdır; komut/yol/SQL gibi türlerde CLI aracının olağan davranışıdır.
LOCAL_KINDS = frozenset({"format_string", "memory", "memory_index", "memory_len"})
# Bellek güvenliği hedef türleri (taşma, kopyalama uzunluğu, dizi indeksi).
MEMORY_KINDS = frozenset({"memory", "memory_len", "memory_index"})
# Sayısal kökenin geçerli olduğu hedefler (dizi indeksi / kopyalama uzunluğu).
NUMERIC_KINDS = frozenset({"memory_index", "memory_len"})
# Yerel girdi akışlarında en çok bu kadar fonksiyon sınırı (bağlama duyarsız uzun zincirler gerçek kodda yanıltıcı).
LOCAL_MAX_VIA = 2
# Ağ/istek kökenli akışlarda en çok bu kadar fonksiyon sınırı (daha uzun bağlama duyarsız zincirler raporlanmaz).
REMOTE_MAX_VIA = 3
_BOOL_OPS = frozenset({"==", "!=", "<=", ">=", "&&", "||"})


class BodyAnalyzer:
    """Tek fonksiyon gövdesini yürütür. Alt sınıflar: ``RustBody`` (taint_rust), ``CBody`` (taint_cfamily)."""

    LANG = ""
    # 27. tur düzeltmesi: kanıt izleme (Origin.weak / xfer). Açık olan motorda yardımcı fonksiyonun dönüşünden/çıkış
    # parametresinden geri gelen değer ("aktarım") çağrı derinliğine sayılmaz — ancak köken kanıtlıysa.
    TRACK_PROOF = False
    BLOCK_KEYWORDS: frozenset[str] = frozenset()
    SKIP_KEYWORDS: frozenset[str] = frozenset()

    def __init__(self, prog: Program, unit: FileUnit, fn: Func, collector: Collector, final: bool) -> None:
        self.prog = prog
        self.unit = unit
        self.toks = unit.toks
        self.fn = fn
        self.file = unit.path
        self.col = collector
        self.final = final
        self.lang = collector.language_of.get(unit.path, self.LANG)
        self.env: dict[str, frozenset] = {}
        self.locals: set[str] = set()
        self.param_index: dict[str, int] = {}
        self.var_info: dict[str, dict[str, Any]] = {}
        self.guards: set[str] = set()
        self.ret: set[Origin] = set()
        self.summary = Summary()
        self.aliases: dict[str, str] = {}
        self.closure_ctx: frozenset = EMPTY
        self.chain: dict[str, Any] | None = None
        self.depth = 0
        self.deps: set[tuple] = set()
        self.gdeps: set[tuple[str, str]] = set()

    # -- yardımcılar --------------------------------------------------------

    def src(self, label: str, source: str, line: int, *, numeric_: bool = False, cap: int | None = None) -> frozenset:
        return frozenset({Origin(label, source, line, self.file, (), numeric_, cap=cap)})

    def var_taint(self, name: str) -> frozenset:
        if name in self.env:
            return self.env[name]
        if name in self.locals or name in self.param_index:
            return EMPTY
        return self.global_taint(name)

    def global_key(self, name: str) -> tuple[str, str]:
        return (self.fn.cls, name) if self.fn.cls else ("", name)

    def global_taint(self, name: str) -> frozenset:
        key = self.global_key(name)
        self.gdeps.add(key)
        t = self.prog.globals.get(key)
        if t is None and self.fn.cls and key[0] == self.fn.cls:
            self.gdeps.add(("", name))
            t = self.prog.globals.get(("", name))
        return t or EMPTY

    BRANCH_KEYWORDS = frozenset({"if", "else", "switch", "case", "default", "match", "while", "for", "loop", "do",
                                 "catch", "try"})
    pending_branch = False
    branch_depth = 0

    def set_var(self, name: str, taint: frozenset, *, strong: bool) -> None:
        if not name:
            return
        if strong and self.branch_depth and name not in self.fresh:
            strong = False
        if name in self.locals or name in self.param_index or self.is_local_decl_context:
            if strong:
                self.env[name] = compact(taint)
            elif taint:
                self.env[name] = compact(self.env.get(name, EMPTY) | taint)
            return
        if not taint:
            return
        key = self.global_key(name)
        old = self.prog.globals.get(key, EMPTY)
        real = frozenset(o for o in taint if o.label != "param")
        if real and not real <= old:
            self.prog.globals[key] = compact(old | real)
        self.env[name] = compact(self.env.get(name, EMPTY) | taint)

    is_local_decl_context = False

    fresh: set[str] = frozenset()

    def declare(self, name: str) -> None:
        if name and name not in self.param_index:
            self.locals.add(name)
            if self.branch_depth:
                if not isinstance(self.fresh, set):
                    self.fresh = set()
                self.fresh.add(name)

    def line_of(self, i: int) -> int:
        return self.toks[i].line if 0 <= i < len(self.toks) else self.fn.line

    # -- hedef bildirimi -----------------------------------------------------

    def chain_depth(self, via_len: int, xfer: int, weak: bool, kind: str = "", label: str = "request") -> int:
        """Bağlama duyarsız çağrı zinciri derinliği. Kanıt izleyen motorda kanıtlı (weak=False) istek kökenli ve dize
        sınıfı (komut/yol/SQL/HTML …) akışta aktarım adımları (yardımcının dönüşü/çıkış parametresi; özet çağrı yerinin
        gerçek argümanlarıyla uygulanır) sayılmaz. Bellek sınıfları ve yerel girdi eski (tam via) sınırında kalır:
        onlar zaten doğrulanmış sayılmayacağından uzun zincirleri yalnız gürültü ekler."""
        if self.TRACK_PROOF and not weak and label == "request" and kind not in MEMORY_KINDS:
            return via_len - xfer
        return via_len

    def sink(self, kind: str, desc: str, line: int, taint: frozenset) -> None:
        self.col.evaluated(self.file, kind, line)
        allow_local = kind in LOCAL_KINDS
        num_kind = kind in NUMERIC_KINDS
        for o in osorted(taint):
            if o.label == "param":
                mode = ("any" if o.numeric else "num") if num_kind else "str"
                if mode == "str" and o.numeric:
                    continue
                self.summary.add_sink(SinkHit(kind, desc, line, self.file, o.param, o.via, mode, o.weak, o.xfer))
                continue
            if o.numeric != num_kind:
                continue  # dize hedefinde sayısal köken / sayısal hedefte dize köken etkisiz
            if kind == "ssrf" and o.fixed_host:
                self.sink("ssrf_partial", desc, line, frozenset({o}))
                continue
            depth = self.chain_depth(len(o.via), o.xfer, o.weak, kind, o.label)
            if (o.label == "local" and (not allow_local or depth > LOCAL_MAX_VIA)) or depth > REMOTE_MAX_VIA:
                self.col.uncertain(self.file, kind, line)
                continue
            if self.final:
                self.col.flow(make_flow(self.lang, kind, desc, line, self.file, o))

    # -- özet uygulama --------------------------------------------------------

    def apply(self, cands: list[Func], arg_taints: list[frozenset], line: int, name: str,
              arg_ranges: list[tuple[int, int]] | None = None) -> frozenset:
        res: set[Origin] = set()
        hop = self.call_hop(line, name)
        cweak = self.call_weak(cands, name)
        xf = self.TRACK_PROOF
        for fn in cands:
            if fn.key == self.fn.key:
                continue
            self.deps.add(fn.key)
            s = self.prog.summary(fn)
            self.note_call(fn, arg_taints, line, arg_ranges)
            for key, params in s.field_writes.items():
                if not self.field_key_ok(key):
                    continue
                for p in params:
                    num = p < 0  # sayısal dönüşümden geçmiş parametre: -(dizin + 1)
                    pi = -p - 1 if num else p
                    t = arg_taints[pi] if pi < len(arg_taints) else EMPTY
                    if num:
                        t = numeric(t)
                    for o in t:
                        if o.label == "param":
                            if key in self.summary.field_writes or len(self.summary.field_writes) < MAX_FIELD_WRITES:
                                self.summary.field_writes.setdefault(key, set()).add(
                                    -(o.param + 1) if o.numeric else o.param)
                            site = (getattr(s, "field_sites", None) or {}).get(key)
                            if site is not None:
                                mine = getattr(self.summary, "field_sites", None)
                                if mine is None:
                                    mine = self.summary.field_sites = {}
                                mine.setdefault(key, site)
                        else:
                            self.apply_field_write(key, o, fn, hop, s)
            for hit in list(s.sinks.values()):
                t = arg_taints[hit.param] if hit.param < len(arg_taints) else EMPTY
                if t and self.sink_arg_guarded(hit.kind, hit.param, arg_ranges, line):
                    self.col.evaluated(hit.file, hit.kind, hit.line)
                    continue
                for o in osorted(t):
                    if hit.mode == "str" and o.numeric:
                        continue
                    if hit.mode == "num" and not o.numeric and o.label != "param":
                        continue
                    if hit.kind == "ssrf" and o.fixed_host:
                        kind = "ssrf_partial"
                    else:
                        kind = hit.kind
                    if o.label == "param":
                        if hit.mode == "num" and not o.numeric:
                            mode = "num"
                        elif hit.mode == "str":
                            mode = "str"
                        else:
                            mode = "any"
                        via = (o.via + (fn.name,) + hit.via)[:MAX_VIA]
                        hw = o.weak or hit.weak or cweak
                        self.summary.add_sink(SinkHit(kind, hit.sink, hit.line, hit.file, o.param, via, mode, hw,
                                                      min(len(via), o.xfer + hit.xfer)))
                        continue
                    self.col.evaluated(hit.file, kind, hit.line)
                    chain_len = len(o.via) + 1 + len(hit.via)
                    fw = o.weak or hit.weak or cweak
                    depth = self.chain_depth(chain_len, o.xfer + hit.xfer, fw, kind, o.label)
                    if (o.label == "local" and (kind not in LOCAL_KINDS or depth > LOCAL_MAX_VIA)) or depth > REMOTE_MAX_VIA:
                        self.col.uncertain(hit.file, kind, hit.line)
                        continue
                    if self.final:
                        self.col.flow(make_flow(self.lang, kind, hit.sink, hit.line, hit.file,
                                                o.through(fn.name, hop, weak=cweak), hit.via,
                                                extra_xfer=hit.xfer, extra_weak=hit.weak))
            for p, num in s.ret_params:
                t = arg_taints[p] if p < len(arg_taints) else EMPTY
                if t:
                    w = cweak or p in s.ret_weak
                    t = frozenset(o.through(fn.name, hop, xfer=xf, weak=w) for o in t)
                    res |= numeric(t) if num else t
            for o in s.ret_sources:
                res.add(o.through(fn.name, hop, xfer=xf, weak=cweak))
            if arg_ranges is not None:
                for p in set(s.out_params) | set(s.out_overwrite):
                    if p >= len(arg_ranges):
                        continue
                    origins = s.out_params.get(p, ())
                    add: set[Origin] = set()
                    for o in origins:
                        if o.label == "param":
                            if o.numeric and self.TRACK_PROOF:
                                # yardımcı içinde sayıya çevrilmiş parametre (snprintf(dst, n, "%d", atoi(src))):
                                # çıkış argümanı dize olarak kirli değildir. Sayısal köken olarak da taşınmaz (önceki
                                # davranış: sayısal hedeflere hiç ulaşmıyordu; karma/sayaç değerleri indeks hedeflerinde
                                # olgun projelerde yalnız gürültü üretiyor).
                                continue
                            if o.param < len(arg_taints):
                                add |= {x.through(fn.name, hop, xfer=xf, weak=cweak or o.weak)
                                        for x in arg_taints[o.param]}
                        else:
                            add.add(o.through(fn.name, hop, xfer=xf, weak=cweak))
                    if add or p in s.out_overwrite:
                        # Belirsiz/işaretçi üzerinden çözülen bir çağrıda adaylardan birinin güçlü yazımı diğer
                        # olası hedeflerin eski değeri koruyabileceği gerçeğini silemez.
                        self.taint_target(*arg_ranges[p], frozenset(add),
                                          strong=p in s.out_overwrite and not cweak)
        return compact(res)

    # -- 27. tur kancaları (C dosyalar arası model) ----------------------------

    def call_weak(self, cands: list[Func], name: str) -> bool:
        """Çağrı çözümlemesi modelce kanıtsız mı (kanıt izleyen motor belirler)."""
        return False

    def sink_arg_guarded(self, kind: str, param: int, arg_ranges: list[tuple[int, int]] | None, line: int) -> bool:
        """Çağrı yerindeki argüman bu hedef türü için doğrulanmış/arındırılmış mı (C: izin listesi doğrulayıcısı)."""
        return False

    def call_hop(self, line: int, name: str) -> str:
        """Kanıt zinciri adımı (yalnız C motoru üretir)."""
        return ""

    def note_call(self, fn: Func, arg_taints: list[frozenset], line: int,
                  arg_ranges: list[tuple[int, int]] | None) -> None:
        """Çağrı yeri gözlemi (C motoru: parametreye ulaşan gerçek kökenler ve parametre kenarları)."""

    def field_key_ok(self, key: tuple) -> bool:
        return True

    def apply_field_write(self, key: tuple, o: Origin, fn: Func, hop: str, summary: Summary) -> None:
        self.write_global_key(key, frozenset({o.through(fn.name, hop)}))

    def write_global_key(self, key: tuple, taint: frozenset) -> None:
        old = self.prog.globals.get(key, EMPTY)
        real = frozenset(o for o in taint if o.label != "param")
        if real and not real <= old:
            self.prog.globals[key] = compact(old | real)

    # -- hedef değişkeni (çıkış argümanı) -------------------------------------

    def base_ident(self, lo: int, hi: int) -> str:
        """``&buf``, ``(char *)(data + n)``, ``*p``, ``s.field``, ``arr[i]`` → temel değişken adı."""
        toks = self.toks
        i = lo
        while i < hi:
            t = toks[i]
            if t.kind == "id":
                if t.text in self.SKIP_KEYWORDS or t.text in {"mut", "const", "struct", "unsigned", "signed"}:
                    i += 1
                    continue
                # tür dönüşümü "(char *)": parantez içindeki tür adları atlanır
                j = i
                while j + 2 < hi and toks[j + 1].text == "::" and toks[j + 2].kind == "id":
                    j += 2
                if j + 1 < hi and toks[j + 1].text == ")" and self._inside_cast(i, lo):
                    i = j + 2
                    continue
                if j + 1 < hi and toks[j + 1].text == "(":
                    return ""  # çağrı sonucu: hedef değişken yok
                if t.text == "this" and j + 2 < hi and toks[j + 1].text in ("->", "."):
                    return toks[j + 2].text if toks[j + 2].kind == "id" else ""
                return t.text
            i += 1
        return ""

    def _inside_cast(self, i: int, lo: int) -> bool:
        # i'den geriye '(' ile başlayan ve yalnız tür belirteçleri içeren grup mu?
        j = i - 1
        while j >= lo and self.toks[j].kind == "id":
            j -= 1
        return j >= lo and self.toks[j].text == "(" and self.toks[j].kind == "op"

    def taint_target(self, lo: int, hi: int, taint: frozenset, *, strong: bool = False) -> None:
        name = self.base_ident(lo, hi)
        if name:
            self.set_var(name, taint, strong=strong)

    # -- ifade değerlendirme ---------------------------------------------------

    def evaluate(self, lo: int, hi: int) -> frozenset:
        toks = self.toks
        if lo >= hi:
            return EMPTY
        self.depth += 1
        try:
            if self.depth > 60:
                return self.scan_idents(lo, hi)
            parts: list[tuple[int, int]] = []
            depth, start = 0, lo
            for j in range(lo, hi):
                t = toks[j]
                if t.kind != "op":
                    continue
                if t.text in "([{":
                    depth += 1
                elif t.text in ")]}":
                    depth -= 1
                elif depth == 0 and t.text in _BOOL_OPS:
                    parts.append((start, j))
                    start = j + 1
            if parts:
                parts.append((start, hi))
                for a, b in parts:
                    self._eval_seq(a, b)  # yan etkiler (hedefler) için
                return EMPTY
            return self._eval_seq(lo, hi)
        finally:
            self.depth -= 1

    def _eval_seq(self, lo: int, hi: int) -> frozenset:
        toks = self.toks
        out: set[Origin] = set()
        i = lo
        first = True
        host = False
        while i < hi:
            t = toks[i]
            if first and t.kind == "str" and self.fixed_host_literal(t.text):
                host = True
            first = False
            if t.kind == "op" and t.text in ("|", "||") and self.closure_start(i, lo):
                i = self.closure(i, hi)
                continue
            if t.kind == "id" and t.text == "as" and i + 1 < hi:
                j = i + 1
                if toks[j].kind == "id" and toks[j].text in self.NUMERIC_TYPES:
                    out = set(numeric(frozenset(out)))
                i = j + 1
                continue
            if t.kind == "op" and t.text not in "([{":
                i += 1
                continue
            i, val = self.primary(i, hi)
            out |= val
        res = compact(out)
        return with_host(res) if host else res

    NUMERIC_TYPES: frozenset[str] = frozenset()

    def fixed_host_literal(self, text: str) -> bool:
        if not text.startswith(("http://", "https://")):
            return False
        rest = text.split("://", 1)[1]
        cut = min([p for p in (rest.find("{"), rest.find("%")) if p >= 0] or [len(rest)])
        head = rest[:cut]
        return "/" in head and len(head.split("/", 1)[0]) > 0

    def scan_idents(self, lo: int, hi: int) -> frozenset:
        out: set[Origin] = set()
        toks = self.toks
        for j in range(lo, hi):
            t = toks[j]
            if t.kind == "id" and (j == lo or toks[j - 1].text not in (".", "->", "::")) and \
                    (j + 1 >= hi or toks[j + 1].text not in ("(", "::", "!")):
                out |= self.var_taint(t.text)
        return compact(out)

    def closure_start(self, i: int, lo: int) -> bool:
        return False

    def closure(self, i: int, hi: int) -> int:
        return i + 1

    def primary(self, i: int, hi: int) -> tuple[int, frozenset]:
        toks = self.toks
        t = toks[i]
        if t.kind in ("str", "num", "chr", "life"):
            return self.postfix(i + 1, hi, EMPTY, None)
        if t.kind == "op":
            x = t.text
            if x in "([":
                j = match_close(toks, i, hi)
                inner = self.evaluate(i + 1, j)
                return self.postfix(j + 1, hi, inner, None)
            if x == "{":
                j = match_close(toks, i, hi)
                return j + 1, self.scan_idents(i + 1, j)
            return i + 1, EMPTY
        word = t.text
        if word in self.SKIP_KEYWORDS:
            if word in ("sizeof", "alignof", "_Alignof", "offsetof", "decltype", "typeid") and i + 1 < hi and toks[i + 1].text == "(":
                return match_close(toks, i + 1, hi) + 1, EMPTY
            return i + 1, EMPTY
        parts = [word]
        j = i
        while j + 2 < hi and toks[j + 1].text == "::" and toks[j + 2].kind == "id":
            parts.append(toks[j + 2].text)
            j += 2
        k = j + 1
        turbofish = ""
        if k + 1 < hi and toks[k].text == "::" and toks[k + 1].text == "<":
            end = self.skip_angle(k + 1, hi)
            turbofish = " ".join(x.text for x in toks[k + 2:end])
            k = end + 1
        if k + 1 < hi and toks[k].text == "!" and toks[k + 1].text in ("(", "[", "{"):
            close = match_close(toks, k + 1, hi)
            res = self.macro(parts, k + 2, close, j)
            return self.postfix(close + 1, hi, res, None)
        if k < hi and toks[k].text == "(":
            close = match_close(toks, k, hi)
            self.chain = None
            res = self.call(parts, k, close, j, turbofish)
            return self.postfix(close + 1, hi, res, None)
        if k < hi and toks[k].text == "{" and self.is_struct_literal(parts, k):
            close = match_close(toks, k, hi)
            return self.postfix(close + 1, hi, self.eval_struct_literal(k + 1, close), None)
        self.chain = None
        if len(parts) == 1:
            res = self.var_taint(word)
            info = self.var_info.get(word)
            if info and "chain" in info:
                self.chain = info["chain"]
            return self.postfix(k, hi, res, word)
        return self.postfix(k, hi, self.path_value(parts), None)

    def skip_angle(self, i: int, hi: int) -> int:
        depth = 0
        toks = self.toks
        for j in range(i, hi):
            x = toks[j].text
            if toks[j].kind != "op":
                continue
            if x == "<":
                depth += 1
            elif x == ">":
                depth -= 1
            elif x == ">>":
                depth -= 2
            elif x in (";", "{", "}"):
                return j - 1
            if depth <= 0:
                return j
        return hi - 1

    def path_value(self, parts: list[str]) -> frozenset:
        return EMPTY

    def is_struct_literal(self, parts: list[str], k: int) -> bool:
        return False

    def eval_struct_literal(self, lo: int, hi: int) -> frozenset:
        return self.scan_idents(lo, hi)

    def postfix(self, i: int, hi: int, cur: frozenset, base: str | None) -> tuple[int, frozenset]:
        toks = self.toks
        while i < hi:
            t = toks[i]
            if t.kind == "op" and t.text in (".", "->") and i + 1 < hi and toks[i + 1].kind in ("id", "num"):
                m = toks[i + 1].text
                k = i + 2
                turbofish = ""
                if k + 1 < hi and toks[k].text == "::" and toks[k + 1].text == "<":
                    end = self.skip_angle(k + 1, hi)
                    turbofish = " ".join(x.text for x in toks[k + 2:end])
                    k = end + 1
                if k < hi and toks[k].text == "(":
                    close = match_close(toks, k, hi)
                    cur = self.method(m, i, k, close, cur, base, turbofish)
                    base = None
                    i = close + 1
                    continue
                if m == "await":
                    i = k
                    continue
                cur = self.field(cur, base, m, t.text)
                base = None
                i = k
                continue
            if t.kind == "op" and t.text == "[":
                close = match_close(toks, i, hi)
                cur = self.index(cur, base, i + 1, close)
                base = None
                i = close + 1
                continue
            if t.kind == "op" and t.text == "?":
                i += 1
                continue
            if t.kind == "op" and t.text == "(" and base is not None:
                # işlev işaretçisi/kapanış değişkeni çağrısı: f(x)
                close = match_close(toks, i, hi)
                cur = self.call([base], i, close, i - 1, "")
                base = None
                i = close + 1
                continue
            break
        return i, cur

    def field(self, cur: frozenset, base: str | None, name: str, op: str) -> frozenset:
        return cur

    def index(self, cur: frozenset, base: str | None, lo: int, hi: int) -> frozenset:
        self.evaluate(lo, hi)
        return cur

    def macro(self, parts: list[str], lo: int, hi: int, name_idx: int) -> frozenset:
        return self.args_union(lo, hi)

    def args_union(self, lo: int, hi: int) -> frozenset:
        out: set[Origin] = set()
        for a, b in split_args(self.toks, lo, hi):
            out |= self.evaluate(a, b)
        return compact(out)

    def arg_taints(self, ranges: list[tuple[int, int]]) -> list[frozenset]:
        return [self.evaluate(a, b) for a, b in ranges]

    # Alt sınıflar: call / method; varsayılan: bilinen proje fonksiyonu özeti ya da argüman birleşimi.
    def call(self, parts: list[str], open_: int, close: int, name_idx: int, turbofish: str) -> frozenset:
        ranges = split_args(self.toks, open_ + 1, close)
        taints = self.arg_taints(ranges)
        return self.default_call(parts[-1], ranges, taints, self.toks[name_idx].line)

    def default_call(self, name: str, ranges: list[tuple[int, int]], taints: list[frozenset], line: int,
                     *, method: bool = False, cls: str = "", strict: bool = False) -> frozenset:
        target = self.aliases.get(name, name)
        cands = self.prog.resolve(target, self.file, len(taints), method=method, cls=cls, strict=strict)
        if cands:
            return self.apply(cands, taints, line, target, ranges)
        out: set[Origin] = set()
        for t in taints:
            out |= t
        # bilinmeyen işlev: dönüşün argümanlardan türediği varsayımdır (kanıtsız adım)
        return weaken(compact(out)) if self.TRACK_PROOF else compact(out)

    def method(self, name: str, dot: int, open_: int, close: int, recv: frozenset, base: str | None,
               turbofish: str) -> frozenset:
        ranges = split_args(self.toks, open_ + 1, close)
        saved = self.closure_ctx
        self.closure_ctx = recv
        try:
            taints = self.arg_taints(ranges)
        finally:
            self.closure_ctx = saved
        out = set(recv)
        for t in taints:
            out |= t
        return compact(out)

    # -- deyimler -------------------------------------------------------------

    def run(self) -> None:
        lo, hi = self.fn.body
        self.prepare()
        self.block(lo + 1, hi)
        self.finish()

    def prepare(self) -> None:
        for p in self.fn.params:
            for name in p.names or (p.name,):
                if not name:
                    continue
                self.param_index[name] = p.index
                self.env[name] = frozenset({Origin("param", name, self.fn.line, self.file, (), False, p.index)})

    def finish(self) -> None:
        strong_ret = {(o.param, o.numeric) for o in self.ret if o.label == "param" and not o.weak}
        for o in self.ret:
            if o.label == "param":
                self.summary.ret_params.add((o.param, o.numeric))
                if self.TRACK_PROOF and o.weak and (o.param, o.numeric) not in strong_ret:
                    self.summary.ret_weak.add(o.param)
            else:
                self.summary.ret_sources.add(o)
        for p in self.fn.params:
            if not self.out_param(p):
                continue
            t = EMPTY
            for name in p.names or (p.name,):
                t = t | self.env.get(name, EMPTY)
            outs = {o for o in t if not (o.label == "param" and o.param == p.index)}
            if outs:
                self.summary.out_params[p.index] = set(compact(outs))

    def out_param(self, p: Param) -> bool:
        return False

    def block(self, lo: int, hi: int) -> None:
        toks = self.toks
        i = lo
        guard = 0
        while i < hi:
            guard += 1
            if guard > 200_000:
                return
            t = toks[i]
            if t.kind == "op":
                if t.text == ";" or t.text == "}" or t.text == ",":
                    i += 1
                    continue
                if t.text == "{":
                    j = match_close(toks, i, hi)
                    branch = self.pending_branch
                    self.pending_branch = False
                    self.branch_depth += branch
                    try:
                        self.enter_block(i, j)
                    finally:
                        self.branch_depth -= branch
                    i = j + 1
                    continue
            j, header = self.stmt_end(i, hi)
            if j <= i:
                j = i + 1
            tail = (not header) and (j >= hi or toks[j].text == "}")
            self.pending_branch = False
            self.statement(i, j, header=header, tail=tail)
            if header:
                # koşullu dal gövdesi: içerideki atamalar zayıf güncellemedir (dal birleşimi yaklaşımı)
                self.pending_branch = toks[i].kind == "id" and toks[i].text in self.BRANCH_KEYWORDS
            i = j + 1 if (j < hi and toks[j].text == ";") else j

    def enter_block(self, lo: int, hi: int) -> None:
        self.block(lo + 1, hi)

    def stmt_end(self, i: int, hi: int) -> tuple[int, bool]:
        """Deyim sonu: (bitiş dizini, başlık mı). Başlık deyimleri (if/for/while/match…) '{' önünde biter."""
        toks = self.toks
        first = toks[i].text if toks[i].kind == "id" else ""
        header_kw = first in self.BLOCK_KEYWORDS
        depth = 0
        j = i
        while j < hi:
            t = toks[j]
            if t.kind == "op":
                x = t.text
                if x in "([":
                    j = match_close(toks, j, hi) + 1
                    continue
                if x == "{":
                    if header_kw and depth == 0:
                        return j, True
                    j = match_close(toks, j, hi) + 1
                    continue
                if x == ";":
                    return j, False
                if x == "}":
                    return j, False
            j += 1
        return hi, False

    def statement(self, lo: int, hi: int, *, header: bool, tail: bool) -> None:
        self.expression_statement(lo, hi)
        self.nested_blocks(lo, hi)

    def expression_statement(self, lo: int, hi: int) -> None:
        self.evaluate(lo, hi)

    def nested_blocks(self, lo: int, hi: int) -> None:
        """Deyimin içindeki kapanış/blok gövdelerini ayrı deyim dizisi olarak işler."""
        toks = self.toks
        j = lo
        while j < hi:
            t = toks[j]
            if t.kind == "op" and t.text == "{":
                close = match_close(toks, j, hi)
                if close - j > 1:
                    self.block(j + 1, close)
                j = close + 1
                continue
            j += 1

    def assignment_split(self, lo: int, hi: int) -> tuple[int, str] | None:
        """Üst düzey atama işleci dizini ve işleç (=, +=, …)."""
        toks = self.toks
        depth = 0
        for j in range(lo, hi):
            t = toks[j]
            if t.kind != "op":
                continue
            x = t.text
            if x in "([{":
                depth += 1
            elif x in ")]}":
                depth -= 1
            elif depth == 0 and x in ("=", "+=", "-=", "|=", "&=", "^=", "<<=", ">>=", "*=", "/=", "%="):
                return j, x
        return None


def run_program(units: list[FileUnit], body_cls_for: Any, collector: Collector, *, rounds: int = MAX_ROUNDS,
                prog: "Program | None" = None) -> "Program":
    """Özetleri ve küresel kirliliği sabit noktaya getirir (yalnız bağımlılığı değişen fonksiyonlar yeniden
    yürütülür); son turda tüm fonksiyonlar akış toplamak için bir kez daha yürütülür."""
    prog = prog if prog is not None else Program(units)
    funcs = [(u, f) for u in units for f in u.funcs]
    deps: dict[tuple, tuple[set, set]] = {}
    dirty = {f.key for _, f in funcs}
    for _ in range(rounds):
        if not dirty:
            break
        before_globals = dict(prog.globals)
        changed: set[tuple] = set()
        for unit, fn in funcs:
            if fn.key not in dirty:
                continue
            body = body_cls_for(unit)(prog, unit, fn, collector, False)
            try:
                body.run()
            except (RecursionError, IndexError):
                continue
            old = prog.summaries.get(fn.key)
            if old is None or old.signature() != body.summary.signature():
                changed.add(fn.key)
            prog.summaries[fn.key] = body.summary
            deps[fn.key] = (body.deps, body.gdeps)
        changed_globals = {k for k, v in prog.globals.items() if before_globals.get(k) != v}
        dirty = {key for key, (fdeps, gdeps) in deps.items() if (fdeps & changed) or (gdeps & changed_globals)}
    if dirty:
        prog.limitations.add("fixed-point")
    for unit, fn in funcs:
        body = body_cls_for(unit)(prog, unit, fn, collector, True)
        try:
            body.run()
        except (RecursionError, IndexError):
            continue
    return prog
