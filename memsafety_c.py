"""C/C++ bellek güvenliği motoru (saf Python, belirteç tabanlı; derleyici gerekmez).

Yöntem: ``taint_cfamily`` önişlemcisi ve fonksiyon çıkarımı üzerine, her fonksiyon gövdesi küçük bir soyut
yorumlayıcıyla yürütülür (fonksiyon içi, akışa duyarlı; if/else, döngü, switch, goto ileri atlama).

İzlenen soyut durum:
  * Nesneler: yığın dizileri (``char b[50]``), öbek ayırmaları (``malloc/calloc/realloc/new[]/alloca/strdup``), yapı
    dizi alanları (``req->filename``), dizgi değişmezleri, ``argv``/``getenv`` nesneleri — bayt cinsinden kapasite
    (sabit, aralık ya da ``strlen(s)+k`` biçiminde simgesel), serbest bırakılma durumu (hayır/olası/kesin) ve içerik
    dizgi uzunluğu aralığı (``memset``+sonlandırıcı, değişmez kopyası, ``fgets`` sınırı) ile dış girdi kirliliği.
  * Değişkenler: işaretçi hedefleri (nesne, bayt ofseti), tamsayı aralığı, dış girdiden gelen sayı (``atoi``,
    ``scanf %d``) ve karşılaştırmayla denetlenmiş olma.
  * Koşullar sabit katlanır (``if(5==5)``, ``switch(6)``, dosyada hiç değiştirilmeyen ``static int x = 1``).

Hedefler (CWE): sabit tampona sığmayan kopyalama/yazma (121/122/787), dış girdinin sınırsız kopyası (120), bir fazla
yazma (193), tampon öncesine yazma/okuma (124/127), sınır ötesi okuma (126), serbest bırakılmış bellek kullanımı (416),
çift serbest bırakma (415), yığın belleğin free edilmesi (590), başlangıcı olmayan işaretçinin free edilmesi (761),
malloc/delete uyumsuzluğu (762), ayırma boyutunda tamsayı taşması (680/190), dış girdili biçim dizgesi (134).

Fonksiyonlar arası (aynı dosya): fonksiyon özetleri — parametreyi serbest bırakan sarmalayıcılar, parametreden sabit
yerel tampona sınırsız kopya, parametre tampona parametre uzunluğuyla yazan döngüler (``url_decode(src, dst, max)``),
parametre biçim dizgesi. Özet işlemleri çağrı yerindeki gerçek argümanlarla değerlendirilir; bulgu hedef satırında,
kaynak çağrı satırıyla raporlanır.

"Kesin" (doğrulanmış) bulgu: boyutlar/uzunluklar sabit ya da simgesel olarak karşılaştırılabilir ve taşma her
koşulda oluşur, ya da dış girdi (argv, stdin, dosya, ağ, ortam) denetimsiz olarak sabit tampona ulaşır. Koşula bağlı
(yalnız bazı yollarda) durumlar "olası" olarak düşük önemde raporlanır. Kaynak satır içeriği hiçbir sonuçta saklanmaz.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

import taint_cfamily as cf
import taint_native_core as core
from taint_native_core import Tok, match_close, split_args

SUFFIXES = frozenset(cf.SUFFIXES | {".ino", ".pde"})
MAX_FILE_BYTES = 4_000_000
FILE_BUDGET_S = 8.0
FUNC_STEP_BUDGET = 40_000
MAX_FINDINGS_PER_FILE = 60
MAX_FUNC_TOKENS = 60_000

INT32_MAX = 2**31 - 1
_BIG = 1 << 62

# ---------------------------------------------------------------------------
# Tür boyutları (LP64)
# ---------------------------------------------------------------------------
_SIZES = {
    "char": 1, "bool": 1, "_Bool": 1, "int8_t": 1, "uint8_t": 1, "u8": 1, "s8": 1, "BYTE": 1, "CHAR": 1,
    "UCHAR": 1, "gchar": 1, "guchar": 1, "u_char": 1, "uchar": 1, "byte": 1, "char8_t": 1, "TCHAR": 1,
    "short": 2, "int16_t": 2, "uint16_t": 2, "u16": 2, "s16": 2, "WORD": 2, "char16_t": 2, "u_short": 2,
    "int": 4, "unsigned": 4, "signed": 4, "int32_t": 4, "uint32_t": 4, "float": 4, "wchar_t": 4, "DWORD": 4,
    "UINT": 4, "u32": 4, "s32": 4, "char32_t": 4, "u_int": 4, "uint": 4, "INT": 4, "LONG": 4, "ULONG": 4,
    "socklen_t": 4, "BOOL": 4, "mode_t": 4, "pid_t": 4, "uid_t": 4, "gid_t": 4, "wint_t": 4,
    "long": 8, "size_t": 8, "ssize_t": 8, "int64_t": 8, "uint64_t": 8, "double": 8, "off_t": 8, "intptr_t": 8,
    "uintptr_t": 8, "ptrdiff_t": 8, "u64": 8, "s64": 8, "time_t": 8, "SIZE_T": 8, "__int64": 8, "off64_t": 8,
    "intmax_t": 8, "uintmax_t": 8, "ULONGLONG": 8, "LONGLONG": 8,
}
_INT_TYPES = frozenset(k for k in _SIZES if k not in ("float", "double"))
_TYPE_QUALS = frozenset({"const", "volatile", "static", "extern", "register", "auto", "inline", "restrict",
                         "__restrict", "unsigned", "signed", "struct", "union", "enum", "class", "typename",
                         "constexpr", "thread_local", "mutable", "__thread", "_Thread_local", "__inline",
                         "__extension__"})
_CONSTS = {"INT_MAX": INT32_MAX, "INT_MIN": -2**31, "UINT_MAX": 2**32 - 1, "SHRT_MAX": 32767, "USHRT_MAX": 65535,
           "CHAR_MAX": 127, "UCHAR_MAX": 255, "CHAR_BIT": 8, "LONG_MAX": 2**63 - 1, "LLONG_MAX": 2**63 - 1,
           "SIZE_MAX": 2**64 - 1, "ULONG_MAX": 2**64 - 1, "SCHAR_MAX": 127, "INT32_MAX": INT32_MAX,
           "UINT32_MAX": 2**32 - 1, "INT16_MAX": 32767, "UINT16_MAX": 65535, "INT8_MAX": 127, "UINT8_MAX": 255,
           "INT64_MAX": 2**63 - 1, "true": 1, "false": 0, "TRUE": 1, "FALSE": 0, "NULL": 0, "nullptr": 0,
           "EOF": -1, "BUFSIZ": 8192, "PATH_MAX": 4096, "FILENAME_MAX": 4096, "STDIN_FILENO": 0}

# ---------------------------------------------------------------------------
# Kütüphane modelleri
# ---------------------------------------------------------------------------
_ALLOC = {"malloc", "xmalloc", "g_malloc", "emalloc", "kmalloc", "vmalloc", "av_malloc", "OPENSSL_malloc",
          "CRYPTO_malloc", "zmalloc", "sqlite3_malloc", "sqlite3_malloc64", "pvPortMalloc", "_alloca", "alloca",
          "ALLOCA", "__builtin_alloca", "HeapAlloc", "LocalAlloc", "GlobalAlloc", "kzalloc", "malloc_usable"}
_STACK_ALLOC = frozenset({"alloca", "_alloca", "ALLOCA", "__builtin_alloca"})
_CALLOC = {"calloc", "xcalloc", "g_malloc0_n", "kcalloc", "zcalloc", "sqlite3_malloc0"}
_REALLOC = {"realloc", "xrealloc", "g_realloc", "erealloc", "krealloc", "zrealloc", "sqlite3_realloc",
            "sqlite3_realloc64", "OPENSSL_realloc", "reallocf"}
_FREE = {"free", "g_free", "efree", "kfree", "vfree", "av_free", "OPENSSL_free", "CRYPTO_free", "zfree",
         "sqlite3_free", "vPortFree", "xfree", "cfree", "HeapFree", "LocalFree", "GlobalFree"}
_TERMINATE = frozenset({"exit", "_exit", "_Exit", "abort", "quick_exit", "longjmp", "siglongjmp", "ExitProcess",
                        "__builtin_unreachable", "__assert_fail", "err", "errx", "verr", "verrx", "panic",
                        "pthread_exit", "__builtin_trap", "std::exit", "std::abort", "die", "fatal", "BUG"})
_DUP = {"strdup", "_strdup", "wcsdup", "_wcsdup", "xstrdup", "g_strdup", "estrdup", "strndup", "OPENSSL_strdup"}
# Hedefi değiştirmeyen (okuyan) yaygın çağrılar: içerik uzunluğu bilgisi korunur.
_READONLY = re.compile(r"^(print|log|puts|fputs|printf|fprintf|wprintf|fwprintf|strlen|wcslen|strcmp|strncmp|"
                       r"strcasecmp|strncasecmp|wcscmp|memcmp|strchr|strrchr|strstr|atoi|atol|strtol|strtoul|"
                       r"assert|syslog|perror|write|send|fwrite|debug|trace|warn|info|error|_?ASSERT)", re.I)
_PRINTF = {"printf": 0, "vprintf": 0, "wprintf": 0, "vwprintf": 0, "fprintf": 1, "vfprintf": 1, "fwprintf": 1,
           "vfwprintf": 1, "dprintf": 1, "vdprintf": 1, "sprintf": 1, "vsprintf": 1, "swprintf": 2,
           "vswprintf": 2, "snprintf": 2, "vsnprintf": 2, "_snprintf": 2, "_vsnprintf": 2, "_snwprintf": 2,
           "_vsnwprintf": 2, "asprintf": 1, "vasprintf": 1, "syslog": 1, "vsyslog": 1, "err": 1, "errx": 1,
           "warn": 0, "warnx": 0, "printw": 0, "wsprintfA": 1, "wsprintfW": 1, "wsprintf": 1}
_UNBOUNDED_CPY = {"strcpy": 1, "wcscpy": 4, "_mbscpy": 1, "lstrcpyA": 1, "lstrcpyW": 2, "lstrcpy": 1,
                  "stpcpy": 1, "StrCpyA": 1, "_tcscpy": 1}
_UNBOUNDED_CAT = {"strcat": 1, "wcscat": 4, "_mbscat": 1, "lstrcatA": 1, "lstrcatW": 2, "lstrcat": 1,
                  "StrCatA": 1, "_tcscat": 1}
_MEMCPY = {"memcpy": 1, "memmove": 1, "wmemcpy": 4, "wmemmove": 4, "CopyMemory": 1, "RtlCopyMemory": 1,
           "MoveMemory": 1, "__builtin_memcpy": 1, "__builtin_memmove": 1, "mempcpy": 1}
_NCPY = {"strncpy": 1, "wcsncpy": 4, "_mbsncpy": 1, "lstrcpynA": 1}
_NCAT = {"strncat": 1, "wcsncat": 4, "_mbsncat": 1}
_SNPRINTF = {"snprintf": 1, "_snprintf": 1, "vsnprintf": 1, "_vsnprintf": 1, "swprintf": 4, "_snwprintf": 4,
             "vswprintf": 4, "_vsnwprintf": 4}
_SPRINTF = {"sprintf": 1, "vsprintf": 1, "wsprintfA": 1, "wsprintf": 1}
_MEMSET = {"memset": 1, "wmemset": 4, "__builtin_memset": 1, "bzero": 1, "explicit_bzero": 1, "ZeroMemory": 1,
           "SecureZeroMemory": 1}
_STRLEN = {"strlen", "wcslen", "_mbslen", "lstrlenA", "lstrlenW", "lstrlen", "_tcslen", "strnlen", "wcsnlen"}
_NUM_CONV = {"atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "_wtoi", "_wtol", "wcstol",
             "wcstoul", "stoi", "stol", "stoul", "stoll", "stoull", "ntohl", "ntohs", "strtoimax", "strtoumax"}
_SCANF = {"scanf": (None, 0), "fscanf": (0, 1), "sscanf": (0, 1), "wscanf": (None, 0), "fwscanf": (0, 1),
          "swscanf": (0, 1), "vscanf": (None, 0), "vfscanf": (0, 1), "vsscanf": (0, 1), "__isoc99_scanf": (None, 0),
          "__isoc99_fscanf": (0, 1), "__isoc99_sscanf": (0, 1), "scanf_s": (None, 0), "fscanf_s": (0, 1)}
_NET_READ = {"recv": (1, 2), "recvfrom": (1, 2), "SSL_read": (1, 2), "BIO_read": (1, 2), "recvmsg": (None, None)}
_FILE_READ = {"read": (1, 2), "_read": (1, 2), "pread": (1, 2), "fread": (0, None)}
_GETS = {"gets": 1, "_getws": 4, "getws": 4}
_FGETS = {"fgets": 1, "fgetws": 4}
_SIZE_NAME = re.compile(r"(?i)(len|size|max|^n$|^sz$|cnt|count|cap|limit|bytes|room|space|avail|remain)")
# Argümanını kesin olarak okuyan/yazan (işaretçiyi izleyen) kütüphane çağrıları
_DEREF_CALL = re.compile(r"^(str|wcs|mem|wmem|_mbs|lstr|puts|fputs|fwrite|fread|fgets|send|write|read|atoi|atol|"
                         r"strto|sscanf|fprintf|printf|sprintf|snprintf|vsnprintf|qsort|bsearch)")
_PRINTF_CONV = re.compile(r"%(?:%|([-+ #0']*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|j|z|t|L|q|I64|I32)?([diouxXeEfFgGaAcspn]))")
_SCANF_CONV = re.compile(r"%(\*)?(\d+)?(hh|h|ll|l|j|z|t|L|m)?([diouxXeEfgGaAcspn\[%])")


# ---------------------------------------------------------------------------
# Veri yapıları
# ---------------------------------------------------------------------------
@dataclass
class MemFinding:
    kind: str
    cwe: str
    line: int
    certain: bool
    severity: str
    title: str
    evidence: str
    function: str = ""
    buffer: str = ""
    buffer_line: int = 0
    capacity: str = ""
    source: str = ""
    source_line: int = 0
    engine: str = "sniper-memsafety"
    source_file: str = ""
    chain: tuple = ()

    def as_dict(self) -> dict[str, Any]:
        d = {"kind": self.kind, "cwe": self.cwe, "sink_line": self.line, "certain": self.certain,
             "function": self.function, "buffer": self.buffer, "buffer_line": self.buffer_line,
             "capacity": self.capacity, "source": self.source, "source_line": self.source_line,
             "engine": self.engine}
        if self.source_file:
            d["source_file"] = self.source_file
        if self.chain:
            d["chain"] = list(self.chain)
        return d


_TITLES = {
    "overflow": "sabit boyutlu tampona sığmayan yazma (arabellek taşması)",
    "overflow_taint": "dış girdi sabit boyutlu tampona sınır denetimsiz kopyalanıyor (arabellek taşması)",
    "off_by_one": "tampon sınırının bir ötesine yazma (off-by-one)",
    "underwrite": "tampon başlangıcından önceye yazma (buffer underwrite)",
    "overread": "tampon sınırı dışından okuma (buffer over-read)",
    "underread": "tampon başlangıcından önceden okuma (buffer under-read)",
    "uaf": "serbest bırakılmış belleğin kullanımı (use-after-free)",
    "double_free": "belleğin iki kez serbest bırakılması (double free)",
    "free_nonheap": "öbekte olmayan belleğin serbest bırakılması (free of non-heap memory)",
    "free_offset": "ayırmanın başını göstermeyen işaretçinin serbest bırakılması",
    "mismatch_free": "ayırma ve serbest bırakma işlevleri uyumsuz (malloc/delete, new/free)",
    "alloc_overflow": "ayırma boyutu hesabında tamsayı taşması (küçük tampon ayrılır)",
    "format": "dış girdi printf biçim dizgesine ulaşıyor (biçim dizgesi açığı)",
}
_RECOMMEND = {
    "overflow": "Kopyalama/yazma uzunluğunu hedef tamponun boyutuyla sınırlandırın (snprintf, strlcpy, "
                "memcpy öncesi n <= sizeof(hedef) denetimi); döngü sınırını hedef dizinin eleman sayısına göre yazın.",
    "overflow_taint": "Dış girdiyi sabit tampona kopyalamadan önce uzunluğunu denetleyin; strcpy/strcat/sprintf/gets "
                      "yerine snprintf/strlcpy/fgets kullanın, scanf'te genişlik belirtin (%63s).",
    "off_by_one": "Dizi indeksinin üst sınırını '<' ile (<= değil) yazın; sonlandırıcı için sizeof(tampon) - 1 "
                  "konumunu kullanın; strncat'e kalan alanı (sizeof - strlen - 1) verin.",
    "underwrite": "İşaretçi aritmetiğinde ve indekste alt sınırı (>= 0) denetleyin; tampon başlangıcından önceyi "
                  "gösteren işaretçi kullanmayın.",
    "overread": "Okuma uzunluğunu kaynak tamponun boyutuyla sınırlandırın; indeksin üst sınırını denetleyin.",
    "underread": "İşaretçi ve indeksin tampon başlangıcından önceye gitmediğini denetleyin.",
    "uaf": "free/delete sonrasında işaretçiyi NULL yapın ve bir daha kullanmayın; sahipliği tek yerde tutun.",
    "double_free": "Belleği tek bir yerde serbest bırakın ve free sonrasında işaretçiyi NULL yapın.",
    "free_nonheap": "Yalnız malloc/calloc/realloc ile ayrılmış belleği free ile serbest bırakın.",
    "free_offset": "free'ye ayırmadan dönen özgün işaretçiyi verin; ilerletilmiş işaretçiyi ayrı değişkende tutun.",
    "mismatch_free": "malloc→free, new→delete, new[]→delete[] eşleşmesini koruyun.",
    "alloc_overflow": "Çarpımdan önce sayının üst sınırını denetleyin (n > SIZE_MAX / sizeof(T)), calloc ya da "
                      "taşma denetimli yardımcı (reallocarray, __builtin_mul_overflow) kullanın.",
    "format": "Biçim dizgesini sabit tutun: printf(\"%s\", veri); kullanıcı verisini biçim argümanı yapmayın "
              "(-Wformat-security ile derleyin).",
}
_CWE = {"overflow_taint": "CWE-120", "off_by_one": "CWE-193", "underwrite": "CWE-124", "overread": "CWE-126",
        "underread": "CWE-127", "uaf": "CWE-416", "double_free": "CWE-415", "free_nonheap": "CWE-590",
        "free_offset": "CWE-761", "mismatch_free": "CWE-762", "alloc_overflow": "CWE-680", "format": "CWE-134"}
_LABELS = {"argv": "komut satırı argümanı (argv)", "stdin": "standart girdi", "file": "dosya içeriği",
           "net": "ağ girdisi", "env": "ortam değişkeni", "cin": "standart girdi (std::cin)"}


def title_for(kind: str, certain: bool) -> str:
    prefix = "Doğrulanmış bellek hatası" if certain else "Olası bellek hatası"
    return f"{prefix}: {_TITLES.get(kind, kind)}"


def recommendation_for(kind: str) -> str:
    return _RECOMMEND.get(kind, _RECOMMEND["overflow"])


ALL_TITLES = tuple(title_for(k, c) for k in _TITLES for c in (True, False))


@dataclass
class ObjInfo:
    name: str
    kind: str  # stack | heap | static | literal | param | input | field | scalar
    cap_lo: int | None
    cap_hi: int | None
    cap_lin: tuple | None  # (anahtar, çarpan, sabit): kapasite = çarpan × simge + sabit (bayt)
    es: int
    line: int
    alloc: str = ""  # malloc | new | new[] | alloca


@dataclass
class Taint:
    label: str
    line: int
    desc: str
    # 27. tur: dosyalar arası model kökenleri — kaynak dosyası, kanıt zinciri ve sınırsızlık iddiasının güvenilirliği
    # (exact=False: dizginin en büyük uzunluğu bilinmiyor; "sınırsız kopya" yalnız "olası" raporlanır)
    file: str = ""
    chain: tuple = ()
    exact: bool = True
    # yapı alanına başka yerde temiz/sabit değer de yazılıyor (alan duyarlı modelde bağlam karışık): kesin sayılmaz
    weak: bool = False


@dataclass
class Op:
    """Fonksiyon özetindeki ertelenmiş işlem (parametreye bağlı; çağrı yerinde değerlendirilir)."""
    kind: str  # src_into | write | fmt | free
    line: int
    param: int
    param2: int = -1
    need: int | None = None
    avail_lo: int | None = None
    avail_hi: int | None = None
    buffer: str = ""
    buffer_line: int = 0
    extra: int = 1  # src_into: sonlandırıcı (1) + mevcut içerik
    es: int = 1
    via: str = ""
    func: str = ""
    must: bool = True


class AV:
    """Soyut değer."""
    __slots__ = ("lo", "hi", "lin", "ptrs", "it", "lv", "s", "es", "pv", "lenof", "mulv", "idx", "name", "chk")

    def __init__(self, lo=None, hi=None, lin=None, ptrs=frozenset(), it=None, lv=None, s=None, es=None, pv=-1,
                 lenof=None, mulv=None, idx=None, name=None, chk=None):
        self.lo = lo
        self.hi = hi
        self.lin = lin
        self.ptrs = ptrs
        self.it = it
        self.lv = lv
        self.s = s
        self.es = es
        self.pv = pv
        self.lenof = lenof
        self.mulv = mulv
        self.idx = idx
        self.name = name
        self.chk = chk

    def exact(self) -> int | None:
        return self.lo if self.lo is not None and self.lo == self.hi else None


UNK = AV()
# Bilinmeyen işaretçi hedefi (bilinmeyen çağrı dönüşü, çıkış parametresi): "tek hedef" kesinliğini bozar.
UNKP = (("?",), None)


def _const(v: int) -> AV:
    return AV(lo=v, hi=v)


# Durum: vars: ad → (ptrs, lo, hi, lin, it, pv); objs: oid → (freed 0/1/2, free_line, clo, chi, ctaint, cset)
# cset: içerik bilgisi var mı (False: hiç bilgi yok — başlatılmamış)
class State:
    __slots__ = ("vars", "objs", "checked", "nulled")

    def __init__(self, vars_=None, objs=None, checked=frozenset(), nulled=frozenset()):
        self.vars = vars_ if vars_ is not None else {}
        self.objs = objs if objs is not None else {}
        self.checked = checked
        self.nulled = nulled

    def copy(self) -> "State":
        return State(dict(self.vars), dict(self.objs), self.checked, self.nulled)


def _mmin(a, b):
    return a if b is None else b if a is None else min(a, b)


def _join_var(a, b):
    if a == b:
        return a
    ptrs = a[0] | b[0]
    lo = None if a[1] is None or b[1] is None else min(a[1], b[1])
    hi = None if a[2] is None or b[2] is None else max(a[2], b[2])
    lin = a[3] if a[3] == b[3] else None
    it = a[4] or b[4]
    pv = a[5] if a[5] == b[5] else -1
    return (ptrs, lo, hi, lin, it, pv)


def _join_obj(a, b):
    if a == b:
        return a
    # -1: bu yolda nesne yok (işaretçi NULL dalı) — birleşimde etkisiz eleman
    if a[0] == -1:
        return b
    if b[0] == -1:
        return a
    fa, fb = a[0], b[0]
    freed = fa if fa == fb else 1
    fline = a[1] if fa else b[1]
    if not a[5]:
        clo, chi, cset = b[2], b[3], b[5]
    elif not b[5]:
        clo, chi, cset = a[2], a[3], a[5]
    else:
        clo = min(a[2], b[2])
        chi = None if a[3] is None or b[3] is None else max(a[3], b[3])
        cset = True
    return (freed, fline, clo, chi, a[4] or b[4], cset)


def _gc_freed(st: State, live=None) -> dict:
    """Serbest bırakılmış ve hiçbir (canlı) değişkenin göstermediği nesneler bu yolda erişilemez: birleşimde etkisiz (-1)."""
    freed = [k for k, v in st.objs.items() if v[0] > 0]
    if not freed:
        return st.objs
    ref = set()
    for name, v in st.vars.items():
        if live is not None and not live(name):
            continue
        for o, _ in v[0]:
            ref.add(o)
    objs = st.objs
    for k in freed:
        if k not in ref:
            if objs is st.objs:
                objs = dict(st.objs)
            v = objs[k]
            objs[k] = (-1, v[1], v[2], v[3], v[4], v[5])
    return objs


def merge(a: State | None, b: State | None, live=None) -> State | None:
    if a is None:
        return b
    if b is None:
        return a
    a = State(a.vars, _gc_freed(a, live), a.checked, a.nulled)
    b = State(b.vars, _gc_freed(b, live), b.checked, b.nulled)
    vars_ = dict(a.vars)
    for k, v in b.vars.items():
        w = vars_.get(k)
        vars_[k] = v if w is None else _join_var(w, v)
    objs = dict(a.objs)
    _fresh = (0, 0, 0, None, None, False)
    for k, v in b.objs.items():
        w = objs.get(k)
        objs[k] = v if w is None else _join_obj(w, v)
    for k, w in a.objs.items():
        if k not in b.objs and w[0] > 0:
            objs[k] = _join_obj(w, _fresh)
    return State(vars_, objs, a.checked & b.checked, a.nulled & b.nulled)


class _Abort(Exception):
    pass


class _ParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# Sabit ifadeler (makro gövdeleri, dosya düzeyi sabitler)
# ---------------------------------------------------------------------------
def _parse_num(text: str) -> int | None:
    t = text.rstrip("uUlL").replace("'", "")
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t.lower().startswith("0b"):
            return int(t[2:], 2)
        if len(t) > 1 and t.startswith("0") and t.isdigit():
            return int(t, 8)
        if t.isdigit():
            return int(t)
    except ValueError:
        return None
    return None


_DEFINE_RE = re.compile(r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(?![\w(])[ \t]*((?:[^\n\\]|\\\n|\\.)*)$")


def _collect_defines(text: str) -> dict[str, list[Tok]]:
    out: dict[str, list[Tok]] = {}
    for m in _DEFINE_RE.finditer(text):
        body = m.group(2).replace("\\\n", " ")
        body = re.sub(r"/\*.*?\*/|//.*$", "", body).strip()
        if not body or len(body) > 200 or '"' in body:
            continue
        toks = core.tokenize(body, rust=False)
        if toks and all(t.kind in ("num", "op", "id", "chr") for t in toks):
            out.setdefault(m.group(1), toks)
    return out


# ---------------------------------------------------------------------------
# Dosya modeli
# ---------------------------------------------------------------------------
@dataclass
class FieldInfo:
    name: str
    es: int | None
    count: int | None  # dizi ise eleman sayısı
    ptr: bool
    struct: str = ""
    pes: int | None = None  # işaretçi alanının gösterdiği eleman boyutu


@dataclass
class FileModel:
    path: str
    unit: Any
    defines: dict[str, list[Tok]]
    consts: dict[str, int] = field(default_factory=dict)
    typedefs: dict[str, str] = field(default_factory=dict)  # ad → temel tür / yapı adı
    structs: dict[str, dict[str, FieldInfo]] = field(default_factory=dict)
    struct_sizes: dict[str, int | None] = field(default_factory=dict)
    globals_: dict[str, tuple] = field(default_factory=dict)  # ad → (taban, ptr, dims, struct)
    funcs: dict[str, Any] = field(default_factory=dict)
    ref_protos: dict[str, set[int]] = field(default_factory=dict)
    unions: set[str] = field(default_factory=set)
    summaries: dict[str, list[Op]] = field(default_factory=dict)
    frees: dict[str, dict[int, bool]] = field(default_factory=dict)  # fonksiyon → {param: kesin mi}
    # `release(&p)` biçimindeki sahiplik sarmalayıcıları normal `free(p)`
    # özetinden ayrı tutulur.  İlki argümanın kendisini değil, gösterdiği
    # işaretçiyi serbest bırakır ve isteğe bağlı olarak NULL yapar.
    deref_frees: dict[str, dict[int, bool]] = field(default_factory=dict)
    deref_nulls: dict[str, set[int]] = field(default_factory=dict)
    facts: "ModelFacts | None" = None  # 27. tur: dosyalar arası kirlilik modeli (taint_cfamily)


def _const_eval(fm: FileModel, toks: list[Tok], depth: int = 0) -> int | None:
    """Yan etkisiz sabit ifade (makro gövdesi ya da başlangıç değeri)."""
    if depth > 8 or not toks:
        return None
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def primary():
        t = peek()
        if t is None:
            raise _ParseError
        pos[0] += 1
        if t.kind == "num":
            v = _parse_num(t.text)
            if v is None:
                raise _ParseError
            return v
        if t.kind == "chr":
            return ord(t.text[0]) if t.text else 0
        if t.text == "(":
            # tür dönüşümü mü?
            j = pos[0]
            k = j
            while k < len(toks) and toks[k].text != ")":
                k += 1
            inner = [x.text for x in toks[j:k]]
            if inner and all(w in _SIZES or w in _TYPE_QUALS or w == "*" or w in fm.typedefs for w in inner) \
                    and k + 1 < len(toks) and toks[k + 1].text not in (")", "+", "-", "*", "/", "%", "<<", ">>", "|", "&"):
                pos[0] = k + 1
                return unary()
            v = expr(0)
            if peek() is None or peek().text != ")":
                raise _ParseError
            pos[0] += 1
            return v
        if t.kind == "id":
            if t.text == "sizeof":
                if peek() is not None and peek().text == "(":
                    close = pos[0]
                    d = 0
                    while close < len(toks):
                        if toks[close].text == "(":
                            d += 1
                        elif toks[close].text == ")":
                            d -= 1
                            if d == 0:
                                break
                        close += 1
                    words = [x.text for x in toks[pos[0] + 1:close]]
                    pos[0] = close + 1
                    s = _type_size_words(fm, words)
                    if s is None:
                        raise _ParseError
                    return s
                raise _ParseError
            if t.text in fm.consts:
                return fm.consts[t.text]
            if t.text in _CONSTS:
                return _CONSTS[t.text]
            if t.text in fm.defines:
                v = _const_eval(fm, fm.defines[t.text], depth + 1)
                if v is None:
                    raise _ParseError
                return v
        raise _ParseError

    def unary():
        t = peek()
        if t is not None and t.kind == "op" and t.text in ("-", "+", "~", "!"):
            pos[0] += 1
            v = unary()
            return -v if t.text == "-" else v if t.text == "+" else (~v if t.text == "~" else int(not v))
        return primary()

    prec = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "<": 7, ">": 7, "<=": 7, ">=": 7,
            "<<": 8, ">>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10}

    def expr(minp):
        lhs = unary()
        while True:
            t = peek()
            if t is None or t.kind != "op" or t.text not in prec or prec[t.text] < minp:
                if t is not None and t.text == "?" and minp == 0:
                    pos[0] += 1
                    a = expr(0)
                    if peek() is None or peek().text != ":":
                        raise _ParseError
                    pos[0] += 1
                    b = expr(0)
                    lhs = a if lhs else b
                    continue
                return lhs
            op = t.text
            pos[0] += 1
            rhs = expr(prec[op] + 1)
            lhs = _arith(op, lhs, rhs)
            if lhs is None:
                raise _ParseError

    try:
        v = expr(0)
    except (_ParseError, RecursionError, IndexError, ValueError, ZeroDivisionError, OverflowError):
        return None
    if pos[0] != len(toks):
        return None
    return v


def _arith(op: str, a: int, b: int) -> int | None:
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "/":
        return None if b == 0 else int(a / b)
    if op == "%":
        return None if b == 0 else a - int(a / b) * b
    if op == "<<":
        return a << b if 0 <= b < 64 else None
    if op == ">>":
        return a >> b if 0 <= b < 64 else None
    if op == "&":
        return a & b
    if op == "|":
        return a | b
    if op == "^":
        return a ^ b
    if op == "==":
        return int(a == b)
    if op == "!=":
        return int(a != b)
    if op == "<":
        return int(a < b)
    if op == ">":
        return int(a > b)
    if op == "<=":
        return int(a <= b)
    if op == ">=":
        return int(a >= b)
    if op == "&&":
        return int(bool(a) and bool(b))
    if op == "||":
        return int(bool(a) or bool(b))
    return None


def _type_size_words(fm: FileModel, words: list[str]) -> int | None:
    """``sizeof(tür sözcükleri)`` — işaretçi 8; bilinmeyen tür None."""
    if not words:
        return None
    if "*" in words:
        return 8
    core_words = [w for w in words if w not in _TYPE_QUALS or w in ("unsigned", "signed")]
    if "struct" in words or "union" in words or "class" in words:
        names = [w for w in words if w not in _TYPE_QUALS]
        return fm.struct_sizes.get(names[-1]) if names else None
    if not core_words:
        return None
    if "long" in core_words:
        return 8 if "double" not in core_words else 16
    if "short" in core_words:
        return 2
    if "char" in core_words:
        return 1
    name = core_words[-1]
    if name in ("unsigned", "signed"):
        return 4
    if name not in _SIZES and name not in fm.typedefs and name in fm.defines:
        name = _type_macro(fm, name)
    if name in _SIZES:
        return _SIZES[name]
    t = fm.typedefs.get(name)
    if t is not None:
        if t.endswith("*"):
            return 8
        if t in _SIZES:
            return _SIZES[t]
        return fm.struct_sizes.get(t)
    return fm.struct_sizes.get(name)


def _type_macro(fm: FileModel, name: str) -> str:
    """``#define json_char char`` gibi tür makrosunu çöz (tek sözcüklü gövde)."""
    for _ in range(3):
        body = fm.defines.get(name)
        if not body or len(body) != 1 or body[0].kind != "id":
            break
        name = body[0].text
    return name


def _base_size(fm: FileModel, base: str) -> int | None:
    if not base:
        return None
    if base not in _SIZES and base not in fm.typedefs and base in fm.defines:
        base = _type_macro(fm, base)
    if base in _SIZES:
        return _SIZES[base]
    t = fm.typedefs.get(base)
    if t is not None:
        if t.endswith("*"):
            return 8
        if t in _SIZES:
            return _SIZES[t]
        return fm.struct_sizes.get(t)
    return fm.struct_sizes.get(base)


def _is_type_word(fm: FileModel, w: str) -> bool:
    return (w in _SIZES or w in _TYPE_QUALS or w in fm.typedefs or w in fm.structs or w == "void"
            or (w.endswith("_t") and len(w) > 2) or w in ("FILE", "string", "std", "wstring", "DIR"))


def _parse_type_head(fm: FileModel, words: list[str]) -> tuple[str, str]:
    """Bildirim başı sözcükleri → (temel tür adı, yapı adı)."""
    base, struct = "", ""
    ws = [w for w in words if w not in ("const", "volatile", "static", "extern", "register", "auto", "inline",
                                         "restrict", "__restrict", "constexpr", "mutable", "thread_local")]
    if any(w in ("struct", "union", "class") for w in ws):
        names = [w for w in ws if w not in ("struct", "union", "class", "enum")]
        if names:
            struct = names[-1]
            base = struct
        return base, struct
    if "long" in ws:
        return ("double" if "double" in ws else "long"), ""
    if "short" in ws:
        return "short", ""
    if "char" in ws:
        return "char", ""
    names = [w for w in ws if w not in ("unsigned", "signed", "enum")]
    if not names:
        return ("int" if ws else ""), ""
    base = names[-1]
    if base == "::" and len(names) > 1:
        base = names[-2]
    t = fm.typedefs.get(base)
    if t is not None and t in fm.structs:
        struct = t
    elif base in fm.structs:
        struct = base
    return base, struct


def _collect_file_model(fm: FileModel) -> None:
    toks = fm.unit.toks
    n = len(toks)
    bodies = sorted(f.body for f in fm.unit.funcs)
    # typedef'ler ve yapılar
    i = 0
    while i < n:
        t = toks[i]
        if t.kind == "id" and t.text in ("struct", "union", "class") and i + 1 < n:
            j = i + 1
            name = ""
            if toks[j].kind == "id":
                name = toks[j].text
                j += 1
            while j < n and toks[j].text not in ("{", ";", "(", ")", "=", ",") and j - i < 12:
                j += 1
            if j < n and toks[j].text == "{":
                close = match_close(toks, j)
                fields = _parse_fields(fm, toks, j + 1, close)
                tname = name
                # typedef struct {...} Ad;
                k = i - 1
                is_typedef = k >= 0 and toks[k].text == "typedef"
                if is_typedef and close + 1 < n and toks[close + 1].kind == "id":
                    alias = toks[close + 1].text
                    if not tname:
                        tname = alias
                    fm.typedefs[alias] = tname
                if tname:
                    fm.structs[tname] = fields
                    if t.text == "union":
                        fm.unions.add(tname)
                i = close + 1
                continue
        if t.kind == "id" and t.text == "typedef":
            end = i + 1
            depth = 0
            while end < n and not (toks[end].text == ";" and depth == 0):
                if toks[end].text in ("{", "("):
                    depth += 1
                elif toks[end].text in ("}", ")"):
                    depth -= 1
                end += 1
            seg = toks[i + 1:end]
            if any(x.text == "{" for x in seg):
                i += 1  # typedef struct {...} Ad; — yapı dalı işler
                continue
            if seg and "(" not in [x.text for x in seg]:
                alias = seg[-1].text if seg[-1].kind == "id" else ""
                words = [x.text for x in seg[:-1]]
                if alias:
                    if "*" in words:
                        fm.typedefs[alias] = "*"
                    else:
                        b, s = _parse_type_head(fm, words)
                        fm.typedefs[alias] = s or b
            i = end + 1
            continue
        i += 1
    for name in list(fm.structs):
        fm.struct_sizes[name] = _struct_size(fm, name, 0)
    # dosya düzeyi bildirimler (fonksiyon gövdeleri dışı); "hiç değiştirilmeyen" denetimi yalnız gövdelerde
    assigned: set[str] = set()
    for lo_, hi_ in bodies:
        assigned |= _assigned_names(toks[lo_:hi_ + 1])
    i, b = 0, 0
    start = 0
    while i < n:
        if b < len(bodies) and i >= bodies[b][0]:
            i = bodies[b][1] + 1
            start = i
            b += 1
            continue
        t = toks[i]
        if t.text == "{":
            close = match_close(toks, i)
            if i > 0 and toks[i - 1].text == "=":
                i = close + 1
                continue
            i += 1
            start = i
            continue
        if t.text in (";", "}"):
            seg = toks[start:i]
            if seg and seg[0].text not in ("typedef", "using", "namespace", "template", "return") and \
                    not any(x.text == "(" for x in seg[:4]):
                for name, base, ptr, dims, struct, init in _split_decl(fm, seg):
                    fm.globals_[name] = (base, ptr, dims, struct)
                    if not ptr and not dims and init is not None and (base in _INT_TYPES or base in fm.typedefs) and \
                            (name not in assigned or "const" in [x.text for x in seg[:6]]):
                        v = _const_eval(fm, init)
                        if v is not None:
                            fm.consts[name] = v
            # enum { A = 1, B }
            start = i + 1
        i += 1
    _collect_enums(fm)
    _collect_ref_protos(fm)


def _collect_ref_protos(fm: FileModel) -> None:
    """C++: ``void f(int &x);`` prototipleri ve tanımları — referans parametre dizinleri."""
    toks = fm.unit.toks
    if not any(t.text == "&" for t in toks[:200000]):
        return
    n = len(toks)
    for i in range(1, n - 2):
        t = toks[i]
        if t.kind != "id" or toks[i + 1].text != "(" or toks[i - 1].kind != "id" and toks[i - 1].text not in ("*", "&"):
            continue
        close = match_close(toks, i + 1)
        if close + 1 >= n or toks[close + 1].text not in (";", "{", "const"):
            continue
        refs = set()
        for k, (a, b) in enumerate(split_args(toks, i + 2, close)):
            if any(toks[q].text == "&" for q in range(a, b)) and not any(toks[q].text == "const" for q in range(a, b)):
                refs.add(k)
        if refs:
            fm.ref_protos.setdefault(t.text, refs)


def _collect_enums(fm: FileModel) -> None:
    toks = fm.unit.toks
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind != "id" or t.text != "enum":
            continue
        j = i + 1
        while j < n and toks[j].text not in ("{", ";", "(") and j - i < 5:
            j += 1
        if j >= n or toks[j].text != "{":
            continue
        close = match_close(toks, j)
        val = -1
        for a, b in split_args(toks, j + 1, close):
            if a >= b or toks[a].kind != "id":
                continue
            if b - a >= 3 and toks[a + 1].text == "=":
                v = _const_eval(fm, toks[a + 2:b])
                if v is None:
                    val = None
                    continue
                val = v
            else:
                if val is None:
                    continue
                val += 1
            fm.consts.setdefault(toks[a].text, val)


def _assigned_names(toks: list[Tok]) -> set[str]:
    out: set[str] = set()
    for i in range(1, len(toks) - 1):
        t = toks[i]
        if t.kind != "id":
            continue
        nx = toks[i + 1].text
        pv = toks[i - 1].text
        if nx in ("=", "+=", "-=", "*=", "/=", "|=", "&=", "^=", "<<=", ">>=", "%=", "++", "--") or pv in ("++", "--", "&"):
            out.add(t.text)
    return out


def _parse_fields(fm: FileModel, toks: list[Tok], lo: int, hi: int) -> dict[str, FieldInfo]:
    fields = _parse_fields0(fm, toks, lo, hi)
    if fields:
        last = list(fields.values())[-1]
        if last.count is not None and last.count <= 1 and not last.ptr:
            last.count = None  # struct hack: char data[1] / data[0] — ayırmayla büyütülen son alan
    return fields


def _parse_fields0(fm: FileModel, toks: list[Tok], lo: int, hi: int) -> dict[str, FieldInfo]:
    fields: dict[str, FieldInfo] = {}
    start = lo
    i = lo
    while i < hi:
        t = toks[i]
        if t.text == "{":
            i = match_close(toks, i, hi) + 1
            continue
        if t.text == ";":
            seg = toks[start:i]
            if seg and not any(x.text == "(" for x in seg):
                for name, base, ptr, dims, struct, _init in _split_decl(fm, seg):
                    es = 8 if ptr else _base_size(fm, base)
                    count = None
                    if dims:
                        count = 1
                        for d in dims:
                            count = None if d is None or d < 0 or count is None else count * d
                    pes = None
                    if ptr:
                        pes = 8 if ptr >= 2 else _base_size(fm, base)
                    fields[name] = FieldInfo(name, es, count, bool(ptr) and not dims, struct, pes)
            start = i + 1
        i += 1
    return fields


def _struct_size(fm: FileModel, name: str, depth: int) -> int | None:
    if depth > 6:
        return None
    if name in fm.struct_sizes and fm.struct_sizes[name] is not None:
        return fm.struct_sizes[name]
    fields = fm.structs.get(name)
    if not fields:
        return None
    off, align = 0, 1
    is_union = name in fm.unions
    for f in fields.values():
        es = f.es
        if es is None and f.struct:
            es = _struct_size(fm, f.struct, depth + 1)
        if es is None:
            return None
        a = min(es, 8) if es in (1, 2, 4, 8) else 8 if f.struct else 1
        if f.struct:
            a = 8 if es >= 8 else 4 if es >= 4 else 1
        size = es * (f.count if f.count is not None else 1) if not (f.count is None and f.ptr is False and False) else es
        if f.count is None and not f.ptr and _is_array_field_unknown(f):
            return None
        off = max(off, size) if is_union else (off + a - 1) // a * a + size
        align = max(align, a)
    return (off + align - 1) // align * align


def _is_array_field_unknown(f: FieldInfo) -> bool:
    return False


def _split_decl(fm: FileModel, seg: list[Tok]) -> list[tuple]:
    """Bildirim belirteçleri → [(ad, temel tür, işaretçi derinliği, boyutlar, yapı, ilk değer belirteçleri)]."""
    if len(seg) < 2 or seg[0].kind != "id":
        return []
    # tür başı: ilk bildirici adına kadar
    k = 0
    words: list[str] = []
    while k < len(seg):
        x = seg[k]
        if x.kind == "id" and (x.text in _TYPE_QUALS or x.text in _SIZES or (k == 0) or
                               (words and words[-1] in ("struct", "union", "enum", "class")) or
                               (k + 1 < len(seg) and seg[k + 1].kind == "id" and x.text not in _TYPE_QUALS
                                and not words) or x.text == "void"):
            if k + 1 < len(seg) and seg[k + 1].text in ("=", "[", ";", ",", ")") and words:
                break
            words.append(x.text)
            k += 1
            continue
        if x.text == "::" and k + 1 < len(seg):
            words.append("::")
            k += 1
            continue
        if x.text == "<":
            d = 0
            while k < len(seg):
                if seg[k].text == "<":
                    d += 1
                elif seg[k].text == ">":
                    d -= 1
                elif seg[k].text == ">>":
                    d -= 2
                k += 1
                if d <= 0:
                    break
            continue
        break
    if not words:
        return []
    if not any(_is_type_word(fm, w) for w in words) and len(words) < 2:
        # "T ad" (iki tanımlayıcı art arda) bildirimdir; "T *ad" yalnız ardından = ; , [ geliyorsa
        if not (k < len(seg) and seg[k].kind == "id"):
            q = k
            while q < len(seg) and seg[q].text == "*":
                q += 1
            if not (q > k and q + 1 < len(seg) and seg[q].kind == "id" and seg[q + 1].text in ("=", ";", ",", "[")) and \
                    not (q > k and q + 1 == len(seg) and seg[q].kind == "id"):
                return []
    base, struct = _parse_type_head(fm, words)
    out = []
    for a, b in split_args(seg, k, len(seg)):
        part = seg[a:b]
        if not part:
            continue
        ptr = 0
        q = 0
        while q < len(part) and part[q].text in ("*", "&", "&&", "const", "volatile", "restrict", "__restrict"):
            if part[q].text == "*":
                ptr += 1
            q += 1
        if q >= len(part) or part[q].kind != "id":
            continue
        name = part[q].text
        q += 1
        dims: list[int | None] = []
        while q < len(part) and part[q].text == "[":
            close = q + 1
            d = 1
            while close < len(part):
                if part[close].text == "[":
                    d += 1
                elif part[close].text == "]":
                    d -= 1
                    if d == 0:
                        break
                close += 1
            dims.append(_const_eval(fm, part[q + 1:close]) if close > q + 1 else -1)
            q = close + 1
        init = None
        if q < len(part) and part[q].text == "=":
            init = part[q + 1:]
        elif q < len(part) and part[q].text not in ("(", "{", ":"):
            continue
        out.append((name, base, ptr, dims, struct, init))
    return out


# ---------------------------------------------------------------------------
# Fonksiyon yorumlayıcısı
# ---------------------------------------------------------------------------
_ASSIGN_OPS = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^="})
_BINPREC = {"||": 4, "&&": 5, "|": 6, "^": 7, "&": 8, "==": 9, "!=": 9, "<": 10, "<=": 10, ">": 10, ">=": 10,
            "<<": 11, ">>": 11, "+": 12, "-": 12, "*": 13, "/": 13, "%": 13}
_CMP = frozenset({"<", "<=", ">", ">=", "==", "!="})


MAX_INLINE_DEPTH = 2
MAX_INLINES_PER_ROOT = 60
MAX_INLINE_TOKENS = 4000


_UNSIGNED_MAX = {"uint8_t": 255, "u8": 255, "unsigned char": 255, "uchar": 255, "u_char": 255, "BYTE": 255,
                 "UCHAR": 255, "uint16_t": 65535, "u16": 65535, "unsigned short": 65535, "u_short": 65535,
                 "WORD": 65535, "USHORT": 65535, "bool": 1, "_Bool": 1}


def _type_max(tname: str) -> int | None:
    return _UNSIGNED_MAX.get(tname)


def _type_min(tname: str) -> int | None:
    return 0 if tname in _UNSIGNED_MAX or tname.startswith(("unsigned", "uint", "size_t", "u")) else None


_FIELD_HOP_RE = re.compile(r" (\w+)\.(\w+) alanına yazım$")


class ModelFacts:
    """``taint_cfamily`` proje olgularının (dosyalar arası, yapı alanı duyarlı kirlilik modeli) bellek motoru görünümü.

    param_in: (dosya, fonksiyon, parametre) → çağıranlardan ulaşan dış girdi kökenleri (yönlendirme tabloları ve çatı
    geri çağırmaları dahil); fields: (yapı, alan) → kökenler; call_ret / call_out: çağrı yerindeki dönüş ve çıkış
    argümanı kirliliği; globals: küresel değişkenler. Her köken ``cap`` (saldırganca ulaşılabilir en büyük uzunluk;
    -1 sınırsız, None bilinmiyor) ve ``hops`` (dosya:satır kanıt zinciri) taşır."""

    def __init__(self, raw: dict[str, Any]):
        self.param_in = raw.get("param_in") or {}
        self.fields = raw.get("fields") or {}
        self.call_ret = raw.get("call_ret") or {}
        self.call_out = raw.get("call_out") or {}
        self.globals = raw.get("globals") or {}
        self.structs = raw.get("structs") or {}
        self.dangling = raw.get("dangling") or []
        self.file_programs = raw.get("file_programs") or {}
        self.guarded_fields = raw.get("guarded_fields") or set()
        self.stdin_service = bool(raw.get("stdin_service"))
        self.mixed_fields = raw.get("clean_field_writes") or set()

    def field_origins(self, key: tuple, path: str):
        """Alan kökenleri — yalnız okuyan dosyayla aynı programa (main) ait kaynaklardan."""
        origins = self.fields.get(key)
        if not origins or not self.file_programs:
            return origins
        mine = self.file_programs.get(path)
        if not mine:
            return origins
        return [o for o in origins if not self.file_programs.get(o.file) or self.file_programs[o.file] & mine]

    def global_origins(self, path: str, name: str):
        return self.globals.get((path, name)) or self.globals.get(("", name))

    def taint_of(self, origins, numeric: bool, weak: bool = False):
        """En güçlü kanıtlı köken → (Taint, en büyük uzunluk | None). Ağ kökeni önce; sınırsız/bilinen uzunluk önce.
        Fonksiyonlar arası modelde yalnız ağ/istek kökenleri kullanılır (yerel stdin yalnız inetd tarzı hizmette;
        komut satırı/ortam kökenleri bağlama duyarsız birleşmede araç kodunu kirletir)."""
        if not origins:
            return None
        cands = [o for o in origins if bool(o.numeric) == numeric and (
            o.label == "request" or (self.stdin_service and o.label == "local" and o.source.startswith("standart girdi")))]
        if not cands:
            return None

        def rank(o):
            return (0 if o.label == "request" else 1, 0 if o.cap == -1 else 1 if o.cap is not None else 2,
                    -(o.cap or 0), o.file, o.line, o.source)

        o = sorted(cands, key=rank)[0]
        if not weak and self.mixed_fields:
            for h in o.hops:
                m = _FIELD_HOP_RE.search(h)
                if m and (m.group(1), m.group(2)) in self.mixed_fields:
                    weak = True  # zincirdeki alana başka yerde temiz değer de yazılıyor
                    break
        if o.label == "request":
            label = "net"
        elif "argv" in o.source:
            label = "argv"
        elif "ortam" in o.source:
            label = "env"
        elif "dosya" in o.source:
            label = "file"
        else:
            label = "stdin"
        hi = o.cap if o.cap is not None and o.cap >= 0 else None
        return Taint(label, o.line, o.source, o.file, tuple(o.hops), o.cap is not None, weak), hi


class FuncAnalyzer:
    def __init__(self, fm: FileModel, func: Any, sink: "Sink", summary_mode: bool = True,
                 parent: "FuncAnalyzer | None" = None):
        self.fm = fm
        self.f = func
        self.toks = fm.unit.toks
        self.sink = sink
        self.parent = parent
        self.depth = 0 if parent is None else parent.depth + 1
        self.stack = (func.name,) if parent is None else parent.stack + (func.name,)
        self.budget = [0] if parent is None else parent.budget
        self.inlines = [0] if parent is None else parent.inlines
        self.gen = [0] if parent is None else parent.gen
        self.objinfo: dict[Any, ObjInfo] = {} if parent is None else parent.objinfo
        # realloc sonucu nesne -> (eski nesnelerin çağrı öncesi durumları, çağrı satırı).
        # İlişki kök analizörle paylaşılır: realloc bir yardımcı içinde çalışıp yeni işaretçi
        # çağırana döndürüldüğünde de başarı/başarısızlık dalı eski takma adları daraltabilsin.
        self.realloc_old: dict[Any, tuple[dict[Any, tuple], int, bool, bool]] = {} \
            if parent is None else parent.realloc_old
        self.ret_vals: list[AV] = []
        self.cpp = cf.language_of(fm.path) == "cpp" or fm.path.lower().endswith(".ino")
        self.fptr: dict[str, str] = {}
        self.call_line = 0
        self.puses: set[int] = set()
        self.vtypes: dict[str, tuple] = {}  # ad → (taban, ptr, dims, struct)
        self.arrays: dict[str, Any] = {}  # dizi adı → oid
        self.ctx: list[list] = []  # [tür, breaks, continues]
        self.gotos: dict[str, list[State]] = {}
        self.ret_states: list[State] = []
        self.steps = 0
        self.loop_depth = 0
        self.loop_vars: dict[str, bool] = {}  # döngü değişkeni → tam yürüyor mu
        self.loop_conds: list[set[str]] = []
        self.loop_ranges: list[tuple[int, int]] = []
        self.ops: list[Op] = []
        self.param_idx: dict[str, int] = {}
        self.summary_mode = summary_mode
        self.st: State = State()
        self.pos = 0
        self.end = 0
        self.cond_depth = 0
        self.lhs_next = False
        self._argtexts: list[str] = []
        self._pending_index = None
        self._pending_deref = None
        # Yerel T** takma adı → gösterdiği sahip değişken veya çağıran parametresinin sembolik pointee'si.
        # ``char **a = out`` ve ``char **a = &p`` biçimleri doğrudan ``*out`` ile aynı sahiplik özetini taşır.
        self.pp_owners: dict[str, str | tuple[str, int]] = {}

    # -- yardımcılar -------------------------------------------------------
    def tick(self) -> None:
        self.budget[0] += 1
        if self.budget[0] > FUNC_STEP_BUDGET:
            raise _Abort

    def es_of_name(self, name: str) -> int | None:
        vt = self.vtypes.get(name) or self.fm.globals_.get(name)
        if vt is None:
            return None
        base, ptr, dims, struct = vt
        if ptr >= 2 or (ptr == 1 and dims):
            return 8
        return _base_size(self.fm, base)

    def new_obj(self, key: Any, info: ObjInfo, *, cont=None, taint=None) -> Any:
        self.objinfo[key] = info
        if cont is None:
            self.st.objs[key] = (0, 0, 0, None, taint, False)
        else:
            self.st.objs[key] = (0, 0, cont[0], cont[1], taint, True)
        return key

    def heap_key(self, line: int) -> tuple:
        """Öbek ayırma nesnesi: her yürütmede yeni kuşak (döngü/yeniden çağrıda eski örnekle karışmaz)."""
        self.gen[0] += 1
        return ("H", line, self.pos, self.gen[0])

    def obj_state(self, oid):
        return self.st.objs.get(oid) or (0, 0, 0, None, None, False)

    def set_cont(self, oid, lo, hi, taint=None, keep_taint=False):
        if oid == ("?",):
            return
        s = self.obj_state(oid)
        t = taint if taint is not None else (s[4] if keep_taint else None)
        self.st.objs[oid] = (s[0], s[1], max(0, lo), hi, t, True)

    # -- giriş -------------------------------------------------------------
    def run(self) -> None:
        f = self.f
        st = State()
        self.st = st
        is_main = f.name in ("main", "wmain", "_tmain")
        for p in f.params:
            if not p.name:
                continue
            self.param_idx[p.name] = p.index
            base, ptr, struct = self._param_type(p)
            self.vtypes[p.name] = (base, ptr, [], struct)
            if is_main and p.index == 1 and ptr >= 2:
                key = ("ARGV",)
                self.new_obj(key, ObjInfo("argv", "input", None, None, None, 1, f.line), cont=(0, None),
                             taint=Taint("argv", f.line, "argv"))
                st.vars[p.name] = (frozenset({(("ARGVV",), 0)}), None, None, None, None, -1)
                self.objinfo[("ARGVV",)] = ObjInfo("argv", "input", None, None, None, 8, f.line)
                continue
            mt = self._model_param(p, base, ptr, struct) if self.fm.facts is not None else None
            if ptr >= 1 or self.fm.typedefs.get(base) == "*":
                key = ("P", p.index)
                es = 8 if ptr >= 2 else (_base_size(self.fm, base) or 1)
                self.new_obj(key, ObjInfo(p.name, "param", None, None, None, es, f.line),
                             cont=None if mt is None else (0, mt[1]), taint=None if mt is None else mt[0])
                st.vars[p.name] = (frozenset({(key, 0)}), None, None, None, None, p.index)
                if ptr >= 2:
                    # Bir T** parametresinin isimsiz pointee'si özet çıkarımında
                    # ayrı bir sembolik nesnedir.  Böylece free(*out) ile *out=NULL
                    # tüm dönüş yollarında ayrı ayrı izlenebilir.
                    dkey = ("PD", p.index)
                    self.new_obj(dkey, ObjInfo("*" + p.name, "param", None, None, None,
                                               _base_size(self.fm, base) or 1, f.line))
                    st.vars[("PDV", p.index)] = (frozenset({(dkey, 0)}), None, None, None, None, -1)
                    self.pp_owners[p.name] = ("param", p.index)
            else:
                st.vars[p.name] = (frozenset(), None if mt is None else mt[2], None if mt is None else mt[1],
                                   None, None if mt is None else mt[0], p.index)
        lo, hi = f.body
        try:
            end = self.exec_block(lo + 1, hi, st)
        except (_Abort, RecursionError):
            return
        if end is not None:
            self.ret_states.append(end)
        self.finish_summary()

    def _param_type(self, p) -> tuple[str, int, str]:
        words = p.type_text.replace("*", " * ").replace("[", " [ ").replace("&", " & ").split()
        ptr = words.count("*") + (1 if "[" in words else 0)
        tw = [w for w in words if w not in ("*", "[", "]", p.name, "&", "&&") and not w.isdigit()]
        base, struct = _parse_type_head(self.fm, tw)
        return base, ptr, struct

    def _pp_owner_name(self, name: str | None) -> str | tuple[str, int] | None:
        """T** ifadesinin değiştirdiği gerçek işaretçiyi sekiz adımda çöz."""
        if not name:
            return None
        if name.startswith("&") and len(name) > 1:
            return name[1:]
        current: str | tuple[str, int] | None = name
        seen: set[str] = set()
        mapped = False
        for _ in range(8):
            if isinstance(current, tuple):
                return current if mapped else None
            if not isinstance(current, str) or current in seen:
                return None
            seen.add(current)
            nxt = self.pp_owners.get(current)
            if nxt is None:
                return current if mapped else None
            mapped = True
            current = nxt
        return None

    def _remember_pp_owner(self, name: str, ptr: int, value: AV) -> None:
        if ptr < 2:
            self.pp_owners.pop(name, None)
            return
        owner = self._pp_owner_name(value.name or value.lv)
        if owner is None and value.name and value.name.startswith("&"):
            owner = value.name[1:]
        if owner is None:
            self.pp_owners.pop(name, None)
        else:
            self.pp_owners[name] = owner

    def _owner_state(self, owner: str | tuple[str, int] | None):
        if isinstance(owner, tuple) and owner[:1] == ("param",):
            return self.st.vars.get(("PDV", owner[1]))
        if isinstance(owner, str):
            return self.st.vars.get(owner)
        return None

    def _set_owner_state(self, owner: str | tuple[str, int] | None, value: tuple) -> None:
        if isinstance(owner, tuple) and owner[:1] == ("param",):
            self.st.vars[("PDV", owner[1])] = value
        elif isinstance(owner, str):
            self.st.vars[owner] = value

    def run_inline(self, st: State) -> State | None:
        self.st = st
        entry = set(st.objs)
        entry_states = dict(st.objs)
        lo, hi = self.f.body
        end = self.exec_block(lo + 1, hi, st)
        if end is not None:
            self.ret_states.append(end)
        out = None
        for s_ in self.ret_states:
            # çağrılanın kendi ayırıp bu yolda serbest bıraktığı nesne (hata yolu temizliği) çağırana ulaşmaz
            for k, v in list(s_.objs.items()):
                if k not in entry and v[0] > 0:
                    s_.objs[k] = (-1, v[1], v[2], v[3], v[4], v[5])
            out = merge(out, s_)
        if out is not None:
            # çağrılanın yalnız bazı yollarda serbest bıraktığı (koşullu) çağıran nesneleri: durum korunur
            for k, v in list(out.objs.items()):
                e = entry_states.get(k)
                if e is not None and v[0] == 1 and e[0] <= 0:
                    out.objs[k] = e
        return out

    def _interesting(self, a: AV) -> bool:
        if a.it is not None:
            return True
        for o, off in a.ptrs:
            info = self.objinfo.get(o)
            if info is None or info.kind == "param":
                continue
            s_ = self.st.objs.get(o)
            if s_ is not None and (s_[0] > 0 or s_[4] is not None or s_[5]):
                return True
            if info.cap_hi is not None or info.cap_lin is not None or info.kind == "input":
                return True
        return False

    def _can_inline(self, callee: Any, avs: list[AV]) -> bool:
        if self.depth >= MAX_INLINE_DEPTH or callee.name in self.stack or self.inlines[0] >= MAX_INLINES_PER_ROOT:
            return False
        if callee.body[1] - callee.body[0] > MAX_INLINE_TOKENS:
            return False
        if any(self._interesting(a) for a in avs):
            return True
        return not callee.params and any(k in self.fm.globals_ for k in self.st.vars)

    def inline(self, callee: Any, avs: list[AV], line: int) -> AV:
        self.inlines[0] += 1
        child = FuncAnalyzer(self.fm, callee, self.sink, summary_mode=False, parent=self)
        child.call_line = line
        st = State({}, dict(self.st.objs), frozenset(), frozenset())
        for k, v in self.st.vars.items():
            if k in self.fm.globals_ and k not in self.vtypes:
                st.vars[k] = v
        refs = []
        for p in callee.params:
            if not p.name:
                continue
            base, ptr, struct = child._param_type(p)
            child.vtypes[p.name] = (base, ptr, [], struct)
            a = avs[p.index] if p.index < len(avs) else UNK
            st.vars[p.name] = (a.ptrs, a.lo, a.hi, a.lin, a.it, -1)
            if "&" in p.type_text and a.lv and not a.lv.startswith("*"):
                refs.append((p.name, a.lv))
        out = child.run_inline(st)
        for a in avs:
            if a.name and a.name.startswith("&") and a.name[1:] in self.st.vars:
                vn = a.name[1:]
                s_ = self.st.vars[vn]
                vt = self.vtypes.get(vn)
                if out is not None:
                    self.st.vars[vn] = (frozenset({UNKP}) if vt is not None and vt[1] >= 1 else frozenset(),
                                        None, None, None, s_[4], -1)
        if out is None:
            return AV()
        self.st.objs = out.objs
        for k, v in out.vars.items():
            if k in self.fm.globals_ and k not in self.vtypes and k not in child.vtypes:
                self.st.vars[k] = v
        for pname, lv in refs:
            if pname in out.vars:
                self.st.vars[lv] = out.vars[pname]
        r = None
        ptr_ret = "*" in (callee.ret_type or "")
        for v in child.ret_vals:
            if ptr_ret and not v.ptrs and v.exact() != 0:
                v = _copy_av(v)
                v.ptrs = frozenset({UNKP})  # bilinmeyen işaretçi dönüşü (ör. dış işlev sonucu)
            r = v if r is None else _join_av(r, v)
        if r is None:
            return AV()
        r = _copy_av(r)
        r.lv = None
        r.name = None
        return r

    def finish_summary(self) -> None:
        frees: dict[int, bool] = {}
        deref_frees: dict[int, bool] = {}
        deref_nulls: set[int] = set()
        if self.ret_states:
            for p, idx in self.param_idx.items():
                key = ("P", idx)
                states = [s.objs.get(key, (0,))[0] for s in self.ret_states]
                if all(x == 2 for x in states):
                    frees[idx] = True
                elif any(x > 0 for x in states):
                    frees[idx] = False
                vt = self.vtypes.get(p)
                if vt is not None and vt[1] >= 2:
                    dkey = ("PD", idx)
                    dstates = [s.objs.get(dkey, (0,))[0] for s in self.ret_states]
                    if all(x == 2 for x in dstates):
                        deref_frees[idx] = True
                    elif any(x > 0 for x in dstates):
                        deref_frees[idx] = False
                    vals = [s.vars.get(("PDV", idx)) for s in self.ret_states]
                    if vals and all(v is not None and not v[0] and v[1] == 0 and v[2] == 0 for v in vals):
                        deref_nulls.add(idx)
        self.sink.frees[self.f.name] = frees
        self.sink.deref_frees[self.f.name] = deref_frees
        self.sink.deref_nulls[self.f.name] = deref_nulls
        self.sink.summaries[self.f.name] = self.ops
        self.sink.puses[self.f.name] = self.puses

    # -- deyimler ------------------------------------------------------------
    def exec_block(self, lo: int, hi: int, st: State | None) -> State | None:
        i = lo
        while i < hi:
            st, i = self.exec_stmt(i, hi, st)
        return st

    def stmt_end(self, i: int, hi: int) -> int:
        toks = self.toks
        while i < hi:
            x = toks[i].text
            if x == ";":
                return i
            if x in ("(", "[", "{"):
                i = match_close(toks, i, hi) + 1
                continue
            if x == "}":
                return i
            i += 1
        return hi

    def skip_stmt(self, i: int, hi: int) -> int:
        """Tek deyimin kapsamını (yürütmeden) atla; dönen: sonraki deyimin başı."""
        _, j = self.exec_stmt(i, hi, None)
        return j

    def exec_stmt(self, i: int, hi: int, st: State | None) -> tuple[State | None, int]:
        toks = self.toks
        self.tick()
        t = toks[i]
        x = t.text
        if x == "{":
            j = match_close(toks, i, hi)
            return self.exec_block(i + 1, j, st), j + 1
        if x == ";":
            return st, i + 1
        if t.kind == "id":
            if x == "if":
                return self.exec_if(i, hi, st)
            if x in ("while", "for"):
                return self.exec_loop(i, hi, st)
            if x == "do":
                return self.exec_do(i, hi, st)
            if x == "switch":
                return self.exec_switch(i, hi, st)
            if x in ("case", "default"):
                j = i + 1
                depth = 0
                while j < hi:
                    if toks[j].text in ("(", "["):
                        depth += 1
                    elif toks[j].text in (")", "]"):
                        depth -= 1
                    elif toks[j].text == ":" and depth == 0:
                        break
                    elif toks[j].text == "::":
                        pass
                    j += 1
                val = None
                if x == "case":
                    val = _const_eval(self.fm, toks[i + 1:j])
                return self.on_case(x == "default", val, st), j + 1
            if x == "return" or x == "co_return":
                end = self.stmt_end(i, hi)
                if st is not None:
                    self.st = st
                    if end > i + 1:
                        try:
                            v = self.eval_range(i + 1, end)
                        except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
                            v = AV()
                        self.use(v, t.line, "return")
                        self.ret_vals.append(v)
                    self.ret_states.append(self.st)
                return None, end + 1
            if x in ("break", "continue"):
                end = self.stmt_end(i, hi)
                if st is not None:
                    for c in reversed(self.ctx):
                        if x == "break":
                            c[1].append(st)
                            break
                        if c[0] == "loop":
                            c[2].append(st)
                            break
                return None, end + 1
            if x == "goto":
                end = self.stmt_end(i, hi)
                if st is not None and i + 1 < end and toks[i + 1].kind == "id":
                    self.gotos.setdefault(toks[i + 1].text, []).append(st)
                return None, end + 1
            if x == "try":
                j = i + 1
                if j < hi and toks[j].text == "{":
                    close = match_close(toks, j, hi)
                    entry = st
                    st = self.exec_block(j + 1, close, st.copy() if st is not None else None)
                    j = close + 1
                    while j < hi and toks[j].text == "catch":
                        pc = match_close(toks, j + 1, hi)
                        if pc + 1 < hi and toks[pc + 1].text == "{":
                            bc = match_close(toks, pc + 1, hi)
                            c = self.exec_block(pc + 2, bc, merge(entry, st).copy() if merge(entry, st) else None)
                            st = merge(st, c)
                            j = bc + 1
                        else:
                            break
                    return st, j
            if x == "else":
                return st, i + 1
            if i + 1 < hi and toks[i + 1].text == ":" and x not in ("public", "private", "protected", "default"):
                pend = self.gotos.pop(x, [])
                for p in pend:
                    st = merge(st, p)
                if st is not None and x in self._back_labels():
                    # geri atlama hedefi (döngü gibi): tamsayılar ve işaretçi ofsetleri bilinmez
                    st = st.copy()
                    for k, v in list(st.vars.items()):
                        st.vars[k] = (frozenset((o, None) for o, _ in v[0]), None, None, None, v[4], v[5])
                return st, i + 2
            if x in ("public", "private", "protected") and i + 1 < hi and toks[i + 1].text == ":":
                return st, i + 2
            if x in ("struct", "union", "enum", "class") and i + 2 < hi:
                # yerel yapı tanımı
                j = i + 1
                while j < hi and toks[j].text not in ("{", ";", "="):
                    j += 1
                if j < hi and toks[j].text == "{":
                    close = match_close(toks, j, hi)
                    end = self.stmt_end(close + 1, hi)
                    if st is not None and end > close + 1:
                        self.st = st
                        self.simple(close + 1, end, prefix=toks[i:j])
                        st = self.st
                    return st, end + 1
        end = self.stmt_end(i, hi)
        if st is None:
            return None, end + 1
        self.st = st
        try:
            self.simple(i, end)
        except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
            self.havoc_range(i, end)
        st = self.st
        if self._terminates(i, end):
            return None, end + 1
        return st, end + 1

    def live_fn(self, pos: int):
        """pos sonrasında (ya da içinde bulunulan döngüde) adı geçen değişkenler canlı sayılır."""
        lu = getattr(self, "_lastuse", None)
        if lu is None:
            lu = {}
            toks = self.toks
            lo, hi = self.f.body
            for q in range(lo, hi):
                if toks[q].kind == "id":
                    lu[toks[q].text] = q
            self._lastuse = lu
        loops = self.loop_ranges
        lr = loops[-1] if loops else None

        def live(name: str) -> bool:
            root = name.split("->")[0].split(".")[0].split("[")[0]
            if root in self.fm.globals_ and root not in self.vtypes:
                return True
            q = lu.get(root)
            if q is None:
                return False
            if q >= pos:
                return True
            if lr is not None:
                toks = self.toks
                return any(toks[x].text == root for x in range(lr[0], lr[1]))
            return False
        return live

    def _back_labels(self) -> set[str]:
        bl = getattr(self, "_bl", None)
        if bl is None:
            toks = self.toks
            lo, hi = self.f.body
            labels: dict[str, int] = {}
            bl = set()
            for q in range(lo, hi - 1):
                t = toks[q]
                if t.kind == "id" and toks[q + 1].text == ":" and toks[q - 1].text in (";", "{", "}", ":") and \
                        t.text not in ("default", "public", "private", "protected"):
                    labels.setdefault(t.text, q)
            for q in range(lo, hi - 1):
                if toks[q].text == "goto" and toks[q + 1].kind == "id":
                    lq = labels.get(toks[q + 1].text)
                    if lq is not None and lq < q:
                        bl.add(toks[q + 1].text)
            self._bl = bl
        return bl

    def _terminates(self, i: int, end: int) -> bool:
        toks = self.toks
        t = toks[i]
        if t.kind == "id" and (t.text in _TERMINATE or (t.text == "std" and i + 2 < end and toks[i + 2].text in ("exit", "abort"))) \
                and i + 1 < end and toks[i + 1].text in ("(", "::"):
            return True
        if t.text == "throw":
            return True
        return False

    def havoc_range(self, lo: int, hi: int) -> None:
        toks = self.toks
        for k in range(lo, min(hi, len(toks) - 1)):
            if toks[k].kind == "id" and toks[k + 1].text in _ASSIGN_OPS and toks[k].text in self.st.vars:
                v = self.st.vars[toks[k].text]
                self.st.vars[toks[k].text] = (frozenset(), None, None, None, v[4], -1)

    def cond_truth(self, lo: int, hi: int, st: State) -> tuple[bool | None, State]:
        self.st = st
        self.cond_depth += 1
        try:
            v = self.eval_range(lo, hi)
        except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
            v = UNK
        finally:
            self.cond_depth -= 1
        e = v.exact()
        truth = None
        if e is not None:
            truth = bool(e)
        elif v.lo is not None and v.lo > 0:
            truth = True
        elif v.hi is not None and v.hi < 0:
            truth = True
        return truth, self.st

    def exec_if(self, i: int, hi: int, st: State | None) -> tuple[State | None, int]:
        toks = self.toks
        j = i + 1
        if j < hi and toks[j].text == "constexpr":
            j += 1
        if j >= hi or toks[j].text != "(":
            return st, self.stmt_end(i, hi) + 1
        close = match_close(toks, j, hi)
        truth = None
        if st is not None:
            truth, st = self.cond_truth(j + 1, close, st)
        then_in = None if st is None or truth is False else self.refine(j + 1, close, st.copy(), True)
        s1, k = self.exec_stmt(close + 1, hi, then_in)
        if k < hi and toks[k].text == "else":
            else_in = None if st is None or truth is True else self.refine(j + 1, close, st.copy(), False)
            s2, k2 = self.exec_stmt(k + 1, hi, else_in)
            return merge(s1, s2, self.live_fn(k2)), k2
        if truth is True:
            return s1, k
        return merge(s1, self.refine(j + 1, close, st, False) if st is not None else None, self.live_fn(k)), k

    def _split_top(self, lo: int, hi: int, op: str) -> list[tuple[int, int]]:
        toks = self.toks
        parts = []
        a = lo
        depth = 0
        for q in range(lo, hi):
            x = toks[q].text
            if x in ("(", "[", "{"):
                depth += 1
            elif x in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and x == op:
                parts.append((a, q))
                a = q + 1
            elif depth == 0 and x in ("?",):
                return [(lo, hi)]
        parts.append((a, hi))
        return parts

    def refine(self, lo: int, hi: int, st: State, branch: bool) -> State:
        """Koşul daraltma: NULL denetimi (p, !p, p == NULL) ve takma ad eşitsizliği (p != q)."""
        toks = self.toks
        while hi - lo >= 2 and toks[lo].text == "(" and match_close(toks, lo, hi) == hi - 1:
            lo, hi = lo + 1, hi - 1
        atoms = self._split_top(lo, hi, "&&" if branch else "||")
        if len(atoms) == 1 and atoms[0] == (lo, hi):
            other = self._split_top(lo, hi, "||" if branch else "&&")
            if len(other) > 1:
                return st
        for a, b in atoms:
            if self._refine_atom(a, b, st, branch) is False:
                return None  # koşul bu dalda sağlanamaz (aralık çelişkisi): dal ölü
        return st

    def _path_at(self, a: int, b: int) -> str | None:
        toks = self.toks
        if b - a == 1 and toks[a].kind == "id":
            return toks[a].text
        if b - a >= 3 and toks[a].kind == "id" and all(
                (toks[q].text in (".", "->")) if (q - a) % 2 == 1 else toks[q].kind == "id" for q in range(a, b)):
            return "".join(toks[q].text for q in range(a, b))
        return None

    def _refine_atom(self, a: int, b: int, st: State, truth: bool) -> None:
        toks = self.toks
        while b - a >= 2 and toks[a].text == "(" and match_close(toks, a, b) == b - 1:
            a, b = a + 1, b - 1
        if a >= b:
            return
        if toks[a].text == "!" and b - a >= 2:
            self._refine_atom(a + 1, b, st, not truth)
            return
        p = self._path_at(a, b)
        if p is not None:
            if not truth:
                self._set_null(p, st)
            else:
                value = st.vars.get(p)
                if value is not None:
                    self._set_realloc_outcome(value, st, success=True)
            return
        depth = 0
        cmp_ops = []
        for q in range(a, b):
            x = toks[q].text
            if x in ("(", "["):
                depth += 1
            elif x in (")", "]"):
                depth -= 1
            elif depth == 0 and x in ("<", "<=", ">", ">=", "==", "!="):
                cmp_ops.append(q)
        if len(cmp_ops) == 1 and toks[cmp_ops[0]].text in ("<", "<=", ">", ">=", "==", "!="):
            r = self._refine_range(a, cmp_ops[0], b, st, truth)
            if r is False:
                return False
        ops = [q for q in cmp_ops if toks[q].text in ("==", "!=")]
        if len(ops) != 1:
            return
        q = ops[0]
        r0 = q + 1
        if r0 < b and toks[r0].text == "(":
            c = match_close(toks, r0, b)
            if c + 1 < b and all(toks[x].kind == "id" or toks[x].text in ("*", "const") for x in range(r0 + 1, c)):
                r0 = c + 1
        lhs, rhs = self._path_at(a, q), self._path_at(r0, b)
        eq = toks[q].text == "=="
        nulls = ("NULL", "nullptr", "0", "__null")
        if lhs is not None and q + 1 == b - 1 and toks[b - 1].text in nulls:
            if eq == truth:
                self._set_null(lhs, st)
            else:
                value = st.vars.get(lhs)
                if value is not None:
                    self._set_realloc_outcome(value, st, success=True)
            return
        if rhs is not None and q == a + 1 and toks[a].text in nulls:
            if eq == truth:
                self._set_null(rhs, st)
            else:
                value = st.vars.get(rhs)
                if value is not None:
                    self._set_realloc_outcome(value, st, success=True)
            return
        if lhs is not None and rhs is not None and eq != truth:
            lv, rv = st.vars.get(lhs), st.vars.get(rhs)
            rptrs = rv[0] if rv is not None else (frozenset({(self.arrays[rhs], 0)}) if rhs in self.arrays else frozenset())
            if lv is not None and len(rptrs) == 1 and lv[0]:
                (ro, _), = rptrs
                keep = frozenset(x for x in lv[0] if x[0] != ro)
                st.vars[lhs] = (keep, lv[1], lv[2], lv[3], lv[4], lv[5])

    _FLIP = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
    _SWAP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}

    def _refine_range(self, a: int, q: int, b: int, st: State, truth: bool):
        """Tamsayı aralığı daraltma: ``v < K``, ``K >= v`` …; çelişkide False (dal ölü)."""
        toks = self.toks
        op = toks[q].text
        var = self._path_at(a, q)
        other = (q + 1, b)
        if var is None:
            var = self._path_at(q + 1, b)
            other = (a, q)
            op = self._SWAP[op]
        if var is None or var not in st.vars:
            return None
        cur = st.vars[var]
        if cur[0]:
            return None  # işaretçi
        save, saved_pos = self.st, (self.pos, self.end)
        self.st = st.copy()
        try:
            k = self.eval_range(*other).exact()
        except (_ParseError, IndexError, ValueError, TypeError, AttributeError, _Abort):
            k = None
        finally:
            self.st = save
            self.pos, self.end = saved_pos
        if k is None:
            return None
        if not truth:
            op = self._FLIP[op]
        lo, hi = cur[1], cur[2]
        if op == "<":
            hi = k - 1 if hi is None else min(hi, k - 1)
        elif op == "<=":
            hi = k if hi is None else min(hi, k)
        elif op == ">":
            lo = k + 1 if lo is None else max(lo, k + 1)
        elif op == ">=":
            lo = k if lo is None else max(lo, k)
        elif op == "==":
            if (lo is not None and k < lo) or (hi is not None and k > hi):
                return False
            lo = hi = k
        else:
            return None
        if lo is not None and hi is not None and lo > hi:
            return False
        st.vars[var] = (cur[0], lo, hi, cur[3], cur[4], cur[5])
        return None

    def _set_null(self, name: str, st: State) -> None:
        v = st.vars.get(name)
        if v is None or not v[0]:
            return
        self._set_realloc_outcome(v, st, success=False)
        if len(v[0]) == 1:
            (o, _), = v[0]
            info = self.objinfo.get(o)
            s_ = st.objs.get(o)
            if info is not None and info.kind == "heap" and s_ is not None:
                st.objs[o] = (-1, s_[1], s_[2], s_[3], s_[4], s_[5])
        st.vars[name] = (frozenset(), v[1], v[2], v[3], v[4], v[5])

    def _set_realloc_outcome(self, value: tuple, st: State, *, success: bool) -> None:
        """Bir realloc sonucunun dalda NULL / NULL-dışı olduğu kanıtlandığında eski nesneyi daralt.

        Başarısız realloc eski ayırmayı canlı bırakır. Başarılı realloc ise adres aynı kalsa bile
        eski nesnenin yaşam süresini bitirir; eski işaretçi veya takma ad kullanımı UAF'tır.
        """
        for new_object, _offset in value[0]:
            relation = self.realloc_old.get(new_object)
            if relation is None:
                continue
            old_states, line, size_may_be_zero, failure_frees = relation
            for old_object, before in old_states.items():
                if success or failure_frees:
                    if before[0] <= 0:
                        st.objs[old_object] = (2, line, before[2], before[3], before[4], before[5])
                elif not size_may_be_zero:
                    st.objs[old_object] = before

    def _loop_assigned(self, lo: int, hi: int) -> set[str]:
        return _assigned_names(self.toks[max(0, lo - 1):hi + 1])

    def exec_loop(self, i: int, hi: int, st: State | None) -> tuple[State | None, int]:
        toks = self.toks
        is_for = toks[i].text == "for"
        j = i + 1
        if j >= hi or toks[j].text != "(":
            return st, self.stmt_end(i, hi) + 1
        close = match_close(toks, j, hi)
        body_lo = close + 1
        body_end = self.skip_stmt(body_lo, hi)
        if st is None:
            return None, body_end
        init = cond = step = None
        if is_for:
            parts = []
            a = j + 1
            depth = 0
            for q in range(j + 1, close):
                tx = toks[q].text
                if tx in ("(", "[", "{"):
                    depth += 1
                elif tx in (")", "]", "}"):
                    depth -= 1
                elif tx == ";" and depth == 0:
                    parts.append((a, q))
                    a = q + 1
            parts.append((a, close))
            if len(parts) != 3:
                # aralık tabanlı for: değişkenleri bilinmeyen yap
                self.st = st
                self.havoc_range(body_lo, body_end)
                parts = []
                cond = None
            else:
                init, cond, step = parts
        else:
            cond = (j + 1, close)
        self.st = st
        if init and init[1] > init[0]:
            try:
                self.simple(init[0], init[1])
            except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
                self.havoc_range(init[0], init[1])
        st = self.st
        # döngüde değişen değişkenler: tamsayı değerleri bilinmez, işaretçi ofsetleri kaybolur
        changed = self._loop_assigned(body_lo, body_end)
        if step:
            changed |= self._loop_assigned(step[0], step[1])
        loopvar = None
        full = False
        rng = None
        if cond and cond[1] > cond[0] and step:
            loopvar, rng, full = self._for_range(cond, step, body_lo, body_end, st)
        cond_names = {toks[q].text for q in range(cond[0], cond[1]) if toks[q].kind == "id"} if cond else set()
        cond_ok = bool(cond and cond[1] > cond[0])
        truth0 = None
        if cond_ok:
            truth0, st = self.cond_truth(cond[0], cond[1], st)
        if truth0 is False:
            return (self.refine(cond[0], cond[1], st, False) if cond_ok else st), body_end
        exits: list[State] = []
        if truth0 is None and cond_ok:
            exits.append(self.refine(cond[0], cond[1], st.copy(), False))
        entry = st.copy()
        for name in changed:
            v = entry.vars.get(name)
            if v is not None and name != loopvar:
                entry.vars[name] = (v[0] if not v[0] else frozenset((o, None) for o, _ in v[0]), None, None, None, v[4], v[5] if v[5] >= 0 else -1)
        if loopvar is not None:
            v = entry.vars.get(loopvar, (frozenset(), None, None, None, None, -1))
            entry.vars[loopvar] = (v[0], rng[0], rng[1], None, v[4], -1)
        self.loop_depth += 1
        self.loop_conds.append(cond_names)
        self.loop_ranges.append((i, body_end))
        if loopvar is not None:
            self.loop_vars[loopvar] = full
        out_breaks: list[State] = []
        cur = entry
        last = None
        iters = 2 if self.loop_depth <= 2 else 1
        if full and rng is not None and rng[1] == rng[0]:
            iters = 1
        try:
            for it in range(iters):
                self.ctx.append(["loop", [], []])
                body_in = cur.copy()
                if cond_ok and loopvar is None:
                    body_in = self.refine(cond[0], cond[1], body_in, True)
                body_out = self.exec_block(body_lo, body_end, body_in) if toks[body_lo].text != "{" else \
                    self.exec_stmt(body_lo, body_end, body_in)[0]
                c = self.ctx.pop()
                out_breaks += c[1]
                tail = body_out
                for s_ in c[2]:
                    tail = merge(tail, s_)
                if tail is not None and step and step[1] > step[0] and loopvar is None:
                    self.st = tail
                    try:
                        self.simple(step[0], step[1])
                    except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
                        pass
                    tail = self.st
                if tail is not None and cond_ok and loopvar is None:
                    # koşul her turda yeniden değerlendirilir (yan etkileri: while ((p = malloc(n))))
                    t2, tail = self.cond_truth(cond[0], cond[1], tail)
                    if t2 is not True:
                        exits.append(self.refine(cond[0], cond[1], tail.copy(), False))
                    if t2 is False:
                        tail = None
                last = tail
                if tail is None:
                    break
                cur = merge(entry, tail).copy()
                if loopvar is not None:
                    v = cur.vars.get(loopvar)
                    if v is not None:
                        cur.vars[loopvar] = (v[0], rng[0], rng[1], None, v[4], -1)
        finally:
            self.loop_depth -= 1
            self.loop_conds.pop()
            self.loop_ranges.pop()
            if loopvar is not None:
                self.loop_vars.pop(loopvar, None)
        if loopvar is not None or not cond_ok:
            out = None if truth0 is True else merge(entry, last)
            if truth0 is True and last is not None and loopvar is not None:
                out = last
            if not cond_ok and loopvar is None:
                out = None  # for(;;) / koşulsuz: yalnız break ile çıkılır
        else:
            out = None
            for e in exits:
                out = merge(out, e)
            if last is not None and iters >= 2:
                out = merge(out, self.refine(cond[0], cond[1], last.copy(), False))
        for b in out_breaks:
            out = merge(out, b)
        if out is not None and loopvar is not None:
            v = out.vars.get(loopvar)
            if v is not None:
                out.vars[loopvar] = (v[0], None, None, None, v[4], -1)
        return out, body_end

    def _for_range(self, cond, step, body_lo, body_end, st):
        """for (i = A; i < B; i++) → (ad, (A, B-1), tam yürüyor mu)."""
        toks = self.toks
        c0, c1 = cond
        s0, s1 = step
        stext = [toks[q].text for q in range(s0, s1)]
        if len(stext) == 2 and stext[1] in ("++",) and toks[s0].kind == "id":
            var = stext[0]
        elif len(stext) == 2 and stext[0] == "++" and toks[s0 + 1].kind == "id":
            var = stext[1]
        elif len(stext) == 3 and stext[1] == "+=" and stext[2] == "1":
            var = stext[0]
        else:
            return None, None, False
        if not (toks[c0].kind == "id" and toks[c0].text == var and c0 + 1 < c1 and toks[c0 + 1].text in ("<", "<=", "!=")):
            return None, None, False
        op = toks[c0 + 1].text
        self.st = st
        save = self.cond_depth
        self.cond_depth += 1
        try:
            bound = self.eval_range(c0 + 2, c1)
        except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
            return None, None, False
        finally:
            self.cond_depth = save
        cur = st.vars.get(var)
        start = cur[1] if cur is not None and cur[1] is not None and cur[1] == cur[2] else None
        if start is None:
            start = 0 if cur is not None and cur[1] is not None and cur[1] >= 0 else None
        if bound.hi is None or start is None:
            return None, None, False
        top = bound.hi - (0 if op == "<=" else 1)
        if top < start:
            return var, (start, start), False
        full = bound.lo == bound.hi and cur is not None and cur[1] == cur[2] and \
            not any(toks[q].text in ("break", "return", "goto", "throw") or toks[q].text in _TERMINATE
                    for q in range(body_lo, body_end)) and \
            var not in _assigned_names(toks[body_lo:body_end])
        if bound.lo != bound.hi and (bound.lo is None or bound.lo < bound.hi):
            full = False
        return var, (start, top), full

    def exec_do(self, i: int, hi: int, st: State | None) -> tuple[State | None, int]:
        toks = self.toks
        body_end = self.skip_stmt(i + 1, hi)
        k = body_end
        if k < hi and toks[k].text == "while" and k + 1 < hi and toks[k + 1].text == "(":
            close = match_close(toks, k + 1, hi)
            end = close + 1
            if end < hi and toks[end].text == ";":
                end += 1
        else:
            close = None
            end = body_end
        if st is None:
            return None, end
        changed = self._loop_assigned(i + 1, body_end)
        cur = st
        out_breaks: list[State] = []
        last = None
        self.loop_depth += 1
        self.loop_conds.append(set())
        self.loop_ranges.append((i, end))
        try:
            for it in range(2):
                if it == 1:
                    cur = cur.copy()
                    for name in changed:
                        v = cur.vars.get(name)
                        if v is not None:
                            cur.vars[name] = (frozenset((o, None) for o, _ in v[0]), None, None, None, v[4], -1)
                self.ctx.append(["loop", [], []])
                body_out = self.exec_stmt(i + 1, body_end, cur.copy())[0]
                c = self.ctx.pop()
                out_breaks += c[1]
                tail = body_out
                for s in c[2]:
                    tail = merge(tail, s)
                truth = None
                if tail is not None and close is not None:
                    truth, tail = self.cond_truth(k + 2, close, tail)
                if it == 0 and truth is False:
                    last = tail
                    break
                last = merge(last, tail) if it else tail
                if tail is None:
                    break
                cur = tail
        finally:
            self.loop_depth -= 1
            self.loop_conds.pop()
            self.loop_ranges.pop()
        out = last
        for b in out_breaks:
            out = merge(out, b)
        return out, end

    def exec_switch(self, i: int, hi: int, st: State | None) -> tuple[State | None, int]:
        toks = self.toks
        j = i + 1
        if j >= hi or toks[j].text != "(":
            return st, self.stmt_end(i, hi) + 1
        close = match_close(toks, j, hi)
        if close + 1 >= hi or toks[close + 1].text != "{":
            return st, self.skip_stmt(close + 1, hi)
        bclose = match_close(toks, close + 1, hi)
        if st is None:
            self.ctx.append(["switch", [], [], None, None, False, False])
            self.exec_block(close + 2, bclose, None)
            self.ctx.pop()
            return None, bclose + 1
        val = None
        self.st = st
        try:
            v = self.eval_range(j + 1, close)
            val = v.exact()
        except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
            val = None
        st = self.st
        # sabit değerde eşleşen case var mı?
        labels = self._case_values(close + 2, bclose)
        has_default = any(d for d, _ in labels)
        matched = val is not None and any(not d and v_ == val for d, v_ in labels)
        # ctx: [tür, breaks, continues, giriş durumu, sabit değer, eşleşme var mı, varsayılan var mı]
        self.ctx.append(["switch", [], [], st, val, matched, has_default])
        try:
            end_state = self.exec_block(close + 2, bclose, None)
        finally:
            c = self.ctx.pop()
        out = end_state
        for b in c[1]:
            out = merge(out, b)
        if not has_default and (val is None or not matched):
            out = merge(out, st)
        return out, bclose + 1

    def _case_values(self, lo: int, hi: int) -> list[tuple[bool, int | None]]:
        toks = self.toks
        out = []
        i = lo
        depth = 0
        while i < hi:
            x = toks[i].text
            if x == "{":
                depth += 1
            elif x == "}":
                depth -= 1
            elif x == "switch" and toks[i].kind == "id":
                # iç içe switch: atla
                k = i + 1
                if k < hi and toks[k].text == "(":
                    k = match_close(toks, k, hi) + 1
                    if k < hi and toks[k].text == "{":
                        i = match_close(toks, k, hi) + 1
                        continue
            elif depth >= 0 and toks[i].kind == "id" and x in ("case", "default"):
                if x == "default":
                    out.append((True, None))
                else:
                    j = i + 1
                    while j < hi and toks[j].text != ":":
                        j += 1
                    out.append((False, _const_eval(self.fm, toks[i + 1:j])))
            i += 1
        return out

    def on_case(self, is_default: bool, val: int | None, st: State | None) -> State | None:
        ctx = next((c for c in reversed(self.ctx) if c[0] == "switch"), None)
        if ctx is None:
            return st
        entry, sval, matched, _has_default = ctx[3], ctx[4], ctx[5], ctx[6]
        if entry is None:
            return st
        if sval is None:
            return merge(st, entry.copy())
        if (not is_default and val == sval) or (is_default and not matched):
            return merge(st, entry.copy())
        if not is_default and val is None:
            return merge(st, entry.copy())
        return st

    # -- basit deyim -----------------------------------------------------------
    def simple(self, lo: int, hi: int, prefix: list[Tok] | None = None) -> None:
        if lo >= hi:
            return
        toks = self.toks
        seg = toks[lo:hi]
        decl = None
        t0 = toks[lo]
        if t0.kind == "id" and t0.text not in self.st.vars and t0.text not in ("return", "sizeof") and \
                not (self.cpp and t0.text in ("delete", "new")) \
                and not (lo + 1 < hi and toks[lo + 1].text in ("(", "=", "[", ".", "->", "++", "--", "+=", "-=", "<<", ">>", "::"))\
                and t0.text not in self.vtypes:
            decl = _split_decl(self.fm, list(prefix or []) + seg)
        elif t0.kind == "id" and lo + 2 < hi and toks[lo + 1].text == "::" and t0.text not in self.st.vars:
            decl = _split_decl(self.fm, seg)
            if decl and toks[lo + 3].text == "(" if lo + 3 < hi else False:
                decl = None
        if decl:
            static = any(x.text == "static" for x in seg[:4])
            for name, base, ptr, dims, struct, init in decl:
                self.declare(name, base, ptr, dims, struct, init, static, t0.line, lo, hi)
            return
        self.eval_range(lo, hi)

    def declare(self, name, base, ptr, dims, struct, init, static, line, lo, hi) -> None:
        self.vtypes[name] = (base, ptr, dims, struct)
        st = self.st
        init_lo = None
        if init is not None:
            # init belirteçlerinin konumu
            for q in range(lo, hi):
                if self.toks[q] is init[0]:
                    init_lo = q
                    break
        if dims:
            es = 8 if ptr else _base_size(self.fm, base)
            count = 1
            for d in dims:
                count = None if d is None or d < 0 or count is None else count * d
            str_init = None
            if init is not None and len(init) >= 1 and init[0].kind == "str":
                str_init = "".join(x.text for x in init if x.kind == "str")
            if count is None and dims and dims[0] == -1 and str_init is not None and len(dims) == 1:
                count = len(str_init) + 1
            if count is None and dims and dims[0] == -1 and init is not None and init[0].text == "{":
                close = match_close(init, 0)
                count = len(split_args(init, 1, close)) if close > 1 else None
            cap = None if count is None or es is None else count * es
            cap_lin = ("sizeof:" + base, count, 0) if cap is None and count is not None and es is None and base else None
            key = ("A", name, line, lo)
            kind = "static" if static else "stack"
            cont = None
            if str_init is not None:
                cont = (len(str_init), len(str_init))
            elif init is not None and init and init[0].text == "{":
                cont = (0, 0) if len(dims) == 1 else None
            elif static:
                cont = (0, 0)
            self.new_obj(key, ObjInfo(name, kind, cap, cap, cap_lin, es or 1, line), cont=cont)
            self.arrays[name] = key
            st.vars.pop(name, None)
            return
        self.arrays.pop(name, None)
        if init is not None and init_lo is not None:
            if init and init[0].text == "{":
                st.vars[name] = (frozenset(), None, None, None, None, -1)
                return
            v = self.eval_range(init_lo, hi if init_lo + len(init) >= hi else init_lo + len(init))
            st = self.st
            ptrs = v.ptrs
            if not ptrs and ptr >= 1 and v.exact() != 0:
                ptrs = frozenset({UNKP})
            st.vars[name] = (ptrs, v.lo, v.hi, v.lin, v.it, v.pv)
            self._remember_pp_owner(name, ptr, v)
            if v.lenof:
                pass
            return
        if struct and not ptr and struct in self.fm.structs:
            st.vars[name] = (frozenset(), None, None, None, None, -1)
            return
        st.vars[name] = (frozenset(), None, None, None, None, -1)

    # -- ifade değerlendirici ----------------------------------------------------
    def eval_range(self, lo: int, hi: int) -> AV:
        if lo >= hi:
            return UNK
        save = (self.pos, self.end)
        self.pos, self.end = lo, hi
        try:
            v = self.e_comma()
        finally:
            self.pos, self.end = save
        return v

    def peek(self) -> Tok | None:
        return self.toks[self.pos] if self.pos < self.end else None

    def e_comma(self) -> AV:
        v = self.e_assign()
        while self.pos < self.end and self.toks[self.pos].text == ",":
            self.pos += 1
            v = self.e_assign()
        return v

    def e_assign(self) -> AV:
        self.tick()
        start = self.pos
        lhs = self.e_ternary()
        t = self.peek()
        if t is not None and t.kind == "op" and t.text in _ASSIGN_OPS:
            op = t.text
            self.pos += 1
            rhs = self.e_assign()
            return self.assign(lhs, op, rhs, t.line, start)
        return lhs

    def e_ternary(self) -> AV:
        c = self.e_bin(4)
        t = self.peek()
        if t is not None and t.text == "?":
            self.pos += 1
            e = c.exact()
            save_state = self.st
            sa = save_state.copy()
            self.st = sa
            a = self.e_assign()
            sa = self.st
            t2 = self.peek()
            if t2 is None or t2.text != ":":
                raise _ParseError
            self.pos += 1
            sb = save_state.copy()
            self.st = sb
            b = self.e_assign()
            sb = self.st
            if e is not None:
                self.st = sa if e else sb
                return a if e else b
            self.st = merge(sa, sb)
            return _join_av(a, b)
        return c

    def e_bin(self, minp: int) -> AV:
        lhs = self.e_unary()
        while True:
            t = self.peek()
            if t is None or t.kind != "op":
                return lhs
            p = _BINPREC.get(t.text)
            if p is None or p < minp:
                return lhs
            op = t.text
            self.pos += 1
            if op in ("&&", "||"):
                e = lhs.exact()
                if e is not None and ((op == "&&" and not e) or (op == "||" and e)):
                    # kısa devre: sağ taraf yürütülmez
                    save = self.st
                    self.st = save.copy()
                    self.e_bin(p + 1)
                    self.st = save
                    lhs = _const(0 if op == "&&" else 1)
                    continue
                if e is None:
                    # sağ taraf koşullu yürür
                    save = self.st
                    self.st = save.copy()
                    rhs = self.e_bin(p + 1)
                    self.st = merge(save, self.st) if not self.cond_depth else self.st
                    re_ = rhs.exact()
                    if op == "&&" and re_ == 0:
                        lhs = _const(0)
                    elif op == "||" and re_ is not None and re_:
                        lhs = _const(1)
                    else:
                        lhs = AV(lo=0, hi=1)
                    continue
            rhs = self.e_bin(p + 1)
            lhs = self.binop(op, lhs, rhs, t.line)

    def binop(self, op: str, a: AV, b: AV, line: int) -> AV:
        if op in _CMP:
            self.mark_checked(a)
            self.mark_checked(b)
            ea, eb = a.exact(), b.exact()
            if ea is not None and eb is not None:
                return _const(_arith(op, ea, eb))
            # aralıklar ayrık mı?
            if a.lo is not None and a.hi is not None and b.lo is not None and b.hi is not None:
                if op in ("<", "<=", ">", ">="):
                    lt_always = a.hi < b.lo if op == "<" else a.hi <= b.lo if op == "<=" else None
                    if op == "<":
                        if a.hi < b.lo:
                            return _const(1)
                        if a.lo >= b.hi:
                            return _const(0)
                    elif op == "<=":
                        if a.hi <= b.lo:
                            return _const(1)
                        if a.lo > b.hi:
                            return _const(0)
                    elif op == ">":
                        if a.lo > b.hi:
                            return _const(1)
                        if a.hi <= b.lo:
                            return _const(0)
                    elif op == ">=":
                        if a.lo >= b.hi:
                            return _const(1)
                        if a.hi < b.lo:
                            return _const(0)
                    del lt_always
            if op in ("==", "!=") and a.ptrs and not b.ptrs and eb == 0:
                return AV(lo=0, hi=1)
            return AV(lo=0, hi=1)
        if op in ("<<", ">>") and (a.name in ("cin", "std::cin", "wcin", "std::wcin")) and op == ">>":
            self.cin_read(b, line)
            return a
        if op == "<<":
            ea, eb = a.exact(), b.exact()
            if ea is not None and eb is not None and 0 <= eb < 64:
                return _const(ea << eb)
            return AV(it=a.it)
        # işaretçi aritmetiği
        if op in ("+", "-") and a.ptrs and not b.ptrs:
            es = a.es
            k = b.exact()
            if k is not None and es:
                d = k * es if op == "+" else -k * es
                ptrs = frozenset((o, None if off is None else off + d) for o, off in a.ptrs)
            else:
                ptrs = frozenset((o, None) for o, _ in a.ptrs)
            return AV(ptrs=ptrs, es=a.es, name=a.name)
        if op == "+" and b.ptrs and not a.ptrs:
            return self.binop("+", b, a, line)
        if op == "-" and a.ptrs and b.ptrs:
            return AV()
        it = a.it or b.it
        ea, eb = a.exact(), b.exact()
        if ea is not None and eb is not None:
            r = _arith(op, ea, eb)
            if r is None:
                return AV(it=it)
            v = _const(r)
            v.it = it
            if op == "*":
                v.mulv = (a.mulv or ()) + (b.mulv or ())
                v.chk = _mul_overflow_const(a, b)
            return v
        lo = hi = None
        if a.lo is not None and a.hi is not None and b.lo is not None and b.hi is not None:
            if op == "+":
                lo, hi = a.lo + b.lo, a.hi + b.hi
            elif op == "-":
                lo, hi = a.lo - b.hi, a.hi - b.lo
            elif op == "*" and min(a.lo, b.lo) >= 0:
                lo, hi = a.lo * b.lo, a.hi * b.hi
            elif op == "/" and b.lo > 0 and a.lo >= 0:
                lo, hi = a.lo // b.hi, a.hi // b.lo
            elif op == "%" and b.lo > 0 and a.lo >= 0:
                lo, hi = 0, b.hi - 1
            elif op == "&" and a.lo >= 0 and b.lo >= 0:
                lo, hi = 0, min(a.hi, b.hi)
        elif op == "%" and b.lo is not None and b.lo > 0 and b.hi is not None:
            lo, hi = -(b.hi - 1), b.hi - 1
        elif op == "&" and eb is not None and eb >= 0:
            lo, hi = 0, eb
        v = AV(lo=lo, hi=hi, it=it)
        # simgesel doğrusal: x + k
        if op in ("+", "-"):
            if a.lin is not None and eb is not None:
                v.lin = (a.lin[0], a.lin[1], a.lin[2] + (eb if op == "+" else -eb))
            elif b.lin is not None and ea is not None and op == "+":
                v.lin = (b.lin[0], b.lin[1], b.lin[2] + ea)
        if op == "*":
            names = tuple(x for x in ((a.name if ea is None else None), (b.name if eb is None else None)) if x)
            v.mulv = names + (a.mulv or ()) + (b.mulv or ())
            v.chk = _mul_overflow_const(a, b)
            # "n * sizeof(T)": sabit çarpan
            if a.lin is not None and eb is not None and eb > 0:
                v.lin = (a.lin[0], a.lin[1] * eb, a.lin[2] * eb)
            elif b.lin is not None and ea is not None and ea > 0:
                v.lin = (b.lin[0], b.lin[1] * ea, b.lin[2] * ea)
        if op in ("+", "-") and (a.mulv or b.mulv):
            v.mulv = (a.mulv or ()) + (b.mulv or ())
        if op == "+" and (a.name or b.name):
            v.mulv = (v.mulv or ()) + tuple(x for x in (("+" + a.name) if a.name and ea is None else None,
                                                       ("+" + b.name) if b.name and eb is None else None) if x)
        return v

    def mark_checked(self, v: AV) -> None:
        names = []
        if v.name:
            names.append(v.name)
        if v.lenof:
            names.append("len:" + v.lenof)
        if v.lin is not None and v.lin[0].startswith("strlen:"):
            names.append("len:" + v.lin[0][7:])
        if v.mulv:
            names += [m.lstrip("+") for m in v.mulv]
            # toplam denetimi: (a + 1 + n + 1) < sizeof(buf), n = strlen(s) → s'nin uzunluğu denetlenmiş
            for m in v.mulv:
                s_ = self.st.vars.get(m.lstrip("+"))
                if s_ is not None and s_[3] is not None and str(s_[3][0]).startswith("strlen:"):
                    names.append("len:" + s_[3][0][7:])
        if names:
            self.st.checked = self.st.checked | frozenset(names)

    def e_unary(self) -> AV:
        t = self.peek()
        if t is None:
            raise _ParseError
        x = t.text
        if t.kind == "op":
            if x in ("-", "+", "!", "~"):
                self.pos += 1
                v = self.e_unary()
                e = v.exact()
                if e is not None:
                    r = -e if x == "-" else e if x == "+" else (int(not e) if x == "!" else ~e)
                    out = _const(r)
                    out.it = v.it
                    return out
                if x == "!":
                    return AV(lo=0, hi=1)
                if x == "-" and v.lo is not None and v.hi is not None:
                    return AV(lo=-v.hi, hi=-v.lo, it=v.it)
                return AV(it=v.it)
            if x == "*":
                self.pos += 1
                v = self.e_unary()
                write = self._next_is_write()
                self.use(v, t.line, "deref")
                self.deref_access(v, 0, write, t.line)
                if write:
                    self._pending_deref = v
                return self.load(v, t.line)
            if x == "&":
                self.pos += 1
                v = self.e_unary()
                return self.address_of(v)
            if x in ("++", "--"):
                self.pos += 1
                v = self.e_unary()
                self.incdec(v, x, t.line)
                if v.lv and v.lv in self.st.vars:
                    s_ = self.st.vars[v.lv]
                    nv = AV(lo=s_[1], hi=s_[2], ptrs=s_[0], it=s_[4], lv=v.lv, es=v.es, name=v.name)
                    return nv
                return AV(it=v.it, es=v.es)
            if x == "(":
                c = self._cast_end(self.pos)
                if c is not None:
                    es = self._cast_es(self.pos + 1, c)
                    self.pos = c + 1
                    v = self.e_unary()
                    if es is not None and (v.ptrs or v.es is None):
                        v = _copy_av(v)
                        v.es = es
                    return v
            if x == "::":
                self.pos += 1
                return self.e_unary()
        if t.kind == "id":
            if x == "sizeof":
                return self.e_sizeof()
            if x == "new" and self.cpp:
                return self.e_new(t.line)
            if x == "delete" and self.cpp:
                self.pos += 1
                arr = False
                if self.peek() is not None and self.peek().text == "[":
                    self.pos += 2
                    arr = True
                v = self.e_unary()
                self.do_free(v, t.line, "delete[]" if arr else "delete")
                return UNK
            if x in ("static_cast", "reinterpret_cast", "const_cast", "dynamic_cast") and \
                    self.pos + 1 < self.end and self.toks[self.pos + 1].text == "<":
                k = self.pos + 1
                d = 0
                while k < self.end:
                    if self.toks[k].text == "<":
                        d += 1
                    elif self.toks[k].text == ">":
                        d -= 1
                        if d == 0:
                            break
                    elif self.toks[k].text == ">>":
                        d -= 2
                        if d <= 0:
                            break
                    k += 1
                es = self._cast_es(self.pos + 2, k)
                self.pos = k + 1
                v = self.e_postfix()
                if es is not None and v.ptrs:
                    v = _copy_av(v)
                    v.es = es
                return v
            if x in ("throw",):
                self.pos += 1
                if self.pos < self.end:
                    return self.e_assign()
                return UNK
        return self.e_postfix()

    def _next_is_write(self) -> bool:
        t = self.peek()
        return t is not None and t.text in _ASSIGN_OPS or (t is not None and t.text in ("++", "--"))

    def _cast_end(self, i: int) -> int | None:
        toks = self.toks
        close = match_close(toks, i, self.end)
        if close >= self.end or close <= i + 1:
            return None
        words = [toks[q].text for q in range(i + 1, close)]
        if not words:
            return None
        if not all(toks[q].kind == "id" or toks[q].text in ("*", "&", "::", "<", ">", ",") for q in range(i + 1, close)):
            return None
        ids = [w for w in words if w not in ("*", "&", "::", "<", ">", ",")]
        if not ids:
            return None
        typeish = all(_is_type_word(self.fm, w) or w in ("std",) for w in ids) or words[-1] == "*" or \
            (len(ids) == 1 and ids[0][:1].isupper() and ids[0] not in self.st.vars and ids[0] not in self.fm.consts
             and ids[0] not in self.fm.defines and ids[0] not in _CONSTS and close + 1 < self.end
             and toks[close + 1].kind in ("id", "num") )
        if not typeish:
            return None
        if any(w in self.st.vars or w in self.vtypes for w in ids) and words[-1] != "*":
            return None
        nxt = toks[close + 1] if close + 1 < self.end else None
        if nxt is None or (nxt.kind == "op" and nxt.text not in ("(", "*", "&", "-", "!", "~", "++", "--", "::", "+")):
            return None
        return close

    def _cast_es(self, lo: int, hi: int) -> int | None:
        words = [self.toks[q].text for q in range(lo, hi)]
        stars = words.count("*")
        if stars == 0:
            return None
        if stars >= 2:
            return 8
        tw = [w for w in words if w not in ("*", "&")]
        base, _s = _parse_type_head(self.fm, tw)
        return _base_size(self.fm, base)

    def e_sizeof(self) -> AV:
        toks = self.toks
        self.pos += 1
        t = self.peek()
        if t is not None and t.text == "...":
            self.pos += 1
            t = self.peek()
        if t is not None and t.text == "(":
            close = match_close(toks, self.pos, self.end)
            words = [toks[q].text for q in range(self.pos + 1, close)]
            self.pos = close + 1
            if len(words) == 1 and (words[0] in self.arrays or words[0] in self.vtypes or words[0] in self.fm.globals_):
                return self._sizeof_var(words[0])
            if len(words) >= 3 and words[1] in (".", "->") and len(words) == 3:
                fi = self._field_info(words[0], words[2])
                if fi is not None and fi.es is not None:
                    return _const(fi.es * (fi.count or 1)) if fi.count or not fi.ptr else _const(8)
            if words and words[0] == "*" and len(words) == 2:
                es = self.es_of_name(words[1])
                return _const(es) if es else UNK
            if len(words) >= 4 and words[1] == "[" and words[-1] == "]" and words[0] in self.arrays:
                info = self.objinfo.get(self.arrays[words[0]])
                if info is not None and info.es:
                    return _const(info.es)
            if any(w in (".", "->", "[", "(", "+", "-", "&") for w in words) or \
                    (words and (words[0] in self.st.vars or words[0] in self.vtypes or words[0] in self.arrays)):
                return UNK  # çözülemeyen ifade: tür sanılmaz (sizeof(ifp->ip) ≠ sizeof(struct ip))
            s = _type_size_words(self.fm, words)
            if s is not None:
                return _const(s)
            tw = [w for w in words if w not in _TYPE_QUALS]
            if len(tw) == 1 and tw[0][:1].isalpha():
                return AV(lin=("sizeof:" + tw[0], 1, 0))
            return UNK
        if t is not None and t.kind == "id":
            self.pos += 1
            name = t.text
            if self.peek() is not None and self.peek().text in (".", "->"):
                self.pos += 2
                return UNK
            return self._sizeof_var(name)
        if t is not None and t.text == "*":
            self.pos += 1
            if self.peek() is not None and self.peek().kind == "id":
                name = self.peek().text
                self.pos += 1
                es = self.es_of_name(name)
                return _const(es) if es else UNK
        return UNK

    def _sizeof_var(self, name: str) -> AV:
        oid = self.arrays.get(name)
        if oid is not None:
            info = self.objinfo.get(oid)
            if info is not None and info.cap_lo is not None and info.cap_lo == info.cap_hi:
                return _const(info.cap_lo)
            if info is not None and info.cap_lin is not None:
                return AV(lin=info.cap_lin)
            return UNK
        vt = self.vtypes.get(name) or self.fm.globals_.get(name)
        if vt is None:
            return UNK
        base, ptr, dims, struct = vt
        if dims:
            es = 8 if ptr else _base_size(self.fm, base)
            count = 1
            for d in dims:
                count = None if d is None or d < 0 or count is None else count * d
            return _const(es * count) if es and count else UNK
        if ptr:
            return _const(8)
        s = _base_size(self.fm, base)
        if s:
            return _const(s)
        return AV(lin=("sizeof:" + base, 1, 0)) if base else UNK

    def e_new(self, line: int) -> AV:
        toks = self.toks
        self.pos += 1
        t = self.peek()
        if t is not None and t.text == "(":
            # yerleşimli new: new (yer) T
            close = match_close(toks, self.pos, self.end)
            self.pos = close + 1
            while self.pos < self.end and toks[self.pos].text not in (";", ")", ","):
                self.pos += 1
            return UNK
        words = []
        while self.pos < self.end and (toks[self.pos].kind == "id" or toks[self.pos].text in ("::", "*")):
            words.append(toks[self.pos].text)
            self.pos += 1
        if self.pos < self.end and toks[self.pos].text == "<":
            d = 0
            while self.pos < self.end:
                if toks[self.pos].text == "<":
                    d += 1
                elif toks[self.pos].text == ">":
                    d -= 1
                self.pos += 1
                if d <= 0:
                    break
        base, _s = _parse_type_head(self.fm, [w for w in words if w != "*"])
        es = 8 if "*" in words else (_base_size(self.fm, base) or None)
        t = self.peek()
        if t is not None and t.text == "[":
            close = match_close(toks, self.pos, self.end)
            n = self.eval_range(self.pos + 1, close)
            self.pos = close + 1
            if self.peek() is not None and self.peek().text in ("(", "{"):
                c2 = match_close(toks, self.pos, self.end)
                self.pos = c2 + 1
            self.check_alloc_size(n, es or 1, line, "new[]", count_mode=True)
            cap_lo = cap_hi = None
            if es is not None and n.lo is not None and n.hi is not None:
                cap_lo, cap_hi = n.lo * es, n.hi * es
            lin = None
            if n.lin is not None and es:
                lin = (n.lin[0], n.lin[1] * es, n.lin[2] * es)
            elif es is None and n.exact() is not None and base:
                lin = ("sizeof:" + base, n.exact(), 0)
            key = self.heap_key(line)
            self.new_obj(key, ObjInfo(f"new {base}[]", "heap", cap_lo, cap_hi, lin, es or 1, line, "new[]"))
            return AV(ptrs=frozenset({(key, 0)}), es=es)
        if t is not None and t.text in ("(", "{"):
            close = match_close(toks, self.pos, self.end)
            args = split_args(toks, self.pos + 1, close)
            for a, b in args:
                self.eval_range(a, b)
            self.pos = close + 1
        size = _base_size(self.fm, base) if "*" not in words else 8
        key = self.heap_key(line)
        self.new_obj(key, ObjInfo(f"new {base}", "heap", size, size, None, es or 1, line, "new"))
        return AV(ptrs=frozenset({(key, 0)}), es=es)

    def _site(self) -> int:
        return self.pos

    def e_postfix(self) -> AV:
        v = self.e_primary()
        toks = self.toks
        while self.pos < self.end:
            t = toks[self.pos]
            x = t.text
            if x == "(":
                close = match_close(toks, self.pos, self.end)
                args = split_args(toks, self.pos + 1, close) if close > self.pos + 1 else []
                name = v.name or ""
                self.pos = close + 1
                v = self.call(name, args, t.line, v)
                continue
            if x == "[":
                close = match_close(toks, self.pos, self.end)
                idx = self.eval_range(self.pos + 1, close)
                self.pos = close + 1
                write = self._next_is_write()
                v = self.index(v, idx, write, t.line)
                continue
            if x in (".", "->"):
                if self.pos + 1 >= self.end:
                    raise _ParseError
                fname = toks[self.pos + 1].text
                if x == "->":
                    self.use(v, t.line, "deref")
                self.pos += 2
                if self.pos < self.end and toks[self.pos].text == "<":
                    pass
                v = self.field(v, fname, x, t.line)
                continue
            if x in ("++", "--"):
                self.pos += 1
                self.incdec(v, x, t.line)
                continue
            break
        return v

    def e_primary(self) -> AV:
        toks = self.toks
        t = self.peek()
        if t is None:
            raise _ParseError
        self.pos += 1
        if t.kind == "num":
            n = _parse_num(t.text)
            return _const(n) if n is not None else UNK
        if t.kind == "chr":
            # belirteç çözücü kaçışları kaba çözer ('\b' → 'b'); yalnız NUL kesin, diğerleri sıfırdan farklı
            if not t.text or t.text == "\x00":
                return _const(0)
            return AV(lo=1, hi=255)
        if t.kind == "str":
            s = t.text
            while self.pos < self.end and toks[self.pos].kind == "str":
                s += toks[self.pos].text
                self.pos += 1
            key = ("S", t.line, self.pos)
            n = len(s)
            if key not in self.objinfo:
                self.objinfo[key] = ObjInfo("dizgi değişmezi", "literal", n + 1, n + 1, None, 1, t.line)
            self.st.objs[key] = (0, 0, n, n, None, True)
            return AV(ptrs=frozenset({(key, 0)}), s=s, es=1)
        if t.text == "(":
            close = match_close(toks, self.pos - 1, self.end)
            v = self.eval_range(self.pos, close)
            self.pos = close + 1
            return v
        if t.text == "{":
            close = match_close(toks, self.pos - 1, self.end)
            self.pos = close + 1
            return UNK
        if t.text == "[":
            # C++ lambda: [..](..){..}
            close = match_close(toks, self.pos - 1, self.end)
            self.pos = close + 1
            if self.pos < self.end and toks[self.pos].text == "(":
                self.pos = match_close(toks, self.pos, self.end) + 1
            while self.pos < self.end and toks[self.pos].text not in ("{",):
                self.pos += 1
            if self.pos < self.end:
                self.pos = match_close(toks, self.pos, self.end) + 1
            return UNK
        if t.kind != "id":
            raise _ParseError
        name = t.text
        # nitelikli ad: std::cin, ns::f
        while self.pos + 1 < self.end and toks[self.pos].text == "::" and toks[self.pos + 1].kind == "id":
            name = name + "::" + toks[self.pos + 1].text
            self.pos += 2
        if self.pos < self.end and toks[self.pos].text == "<" and name not in self.st.vars and \
                name not in self.vtypes and not name[:1].islower() is False and self._template_args():
            pass
        short = name.rsplit("::", 1)[-1]
        if name in self.st.vars:
            v = self.st.vars[name]
            av = AV(lo=v[1], hi=v[2], lin=v[3], ptrs=v[0], it=v[4], lv=name, es=self.es_of_name(name), pv=v[5],
                    name=name)
            if av.lin is None and v[1] is None and not v[0] and self.vtypes.get(name, ("",))[0] in _INT_TYPES:
                av.lin = ("v:" + name, 1, 0)
            return av
        if name in self.arrays:
            oid = self.arrays[name]
            return AV(ptrs=frozenset({(oid, 0)}), es=self.objinfo[oid].es, name=name, lv=None)
        if name in self.fm.consts and name not in self.vtypes:
            return _const(self.fm.consts[name])
        if name in _CONSTS:
            return _const(_CONSTS[name])
        if name in self.fm.defines:
            c = _const_eval(self.fm, self.fm.defines[name])
            if c is not None:
                return _const(c)
            return AV(name=name)
        if name in self.fm.globals_:
            base, ptr, dims, struct = self.fm.globals_[name]
            if dims:
                key = ("G", name)
                if key not in self.objinfo:
                    es = 8 if ptr else _base_size(self.fm, base)
                    count = 1
                    for d in dims:
                        count = None if d is None or d < 0 or count is None else count * d
                    cap = None if count is None or es is None else count * es
                    self.objinfo[key] = ObjInfo(name, "static", cap, cap, None, es or 1, 0)
                    if self.fm.facts is not None and (es or 1) == 1:
                        mt = self.fm.facts.taint_of(self.fm.facts.global_origins(self.fm.path, name), False)
                        if mt is not None and key not in self.st.objs:
                            hi = mt[1] if cap is None else (cap - 1 if mt[1] is None else min(mt[1], cap - 1))
                            self.st.objs[key] = (0, 0, 0, hi, mt[0], True)
                return AV(ptrs=frozenset({(key, 0)}), es=self.objinfo[key].es, name=name)
            self.vtypes.setdefault(name, (base, ptr, dims, struct))
            return AV(name=name, lv=name, es=self.es_of_name(name))
        return AV(name=short if name.startswith(("std::",)) and short in ("cin", "wcin") else name, lv=name)

    def _template_args(self) -> bool:
        return False

    # -- erişimler -------------------------------------------------------------
    def load(self, v: AV, line: int) -> AV:
        """*p değeri: işaretçi dizisinden okunan işaretçi bilinmez."""
        if v.ptrs and any(o == ("ARGVV",) for o, _ in v.ptrs):
            return AV(ptrs=frozenset({(("ARGV",), 0)}), es=1)
        if v.name:
            name = v.name.lstrip("*")
            owner = self._pp_owner_name(name)
            s = self._owner_state(owner)
            if s is not None:
                base = self.vtypes.get(name, ("", 0, [], ""))[0]
                return AV(ptrs=s[0], lo=s[1], hi=s[2], lin=s[3], it=s[4], pv=s[5],
                          lv="*" + name, name="*" + name, es=_base_size(self.fm, base) or 1)
            vt = self.vtypes.get(name)
            pidx = self.param_idx.get(name)
            if vt is not None and vt[1] >= 2 and pidx is not None:
                s = self.st.vars.get(("PDV", pidx))
                if s is not None:
                    return AV(ptrs=s[0], lo=s[1], hi=s[2], lin=s[3], it=s[4], pv=s[5],
                              lv="*" + name, name="*" + name,
                              es=_base_size(self.fm, vt[0]) or 1)
        return AV(lv=("*" + v.lv) if v.lv else None, name=("*" + v.name) if v.name else None)

    def address_of(self, v: AV) -> AV:
        if v.idx is not None:
            base_ptrs, ilo, ihi, es = v.idx
            if ilo is not None and ilo == ihi and es:
                return AV(ptrs=frozenset((o, None if off is None else off + ilo * es) for o, off in base_ptrs), es=es)
            return AV(ptrs=frozenset((o, None) for o, _ in base_ptrs), es=es)
        if v.ptrs and v.lv is None:
            return v  # &dizi
        name = v.lv
        if name and not name.startswith("*"):
            vt = self.vtypes.get(name) or self.fm.globals_.get(name)
            size = None
            if vt is not None:
                base, ptr, dims, struct = vt
                size = 8 if ptr else _base_size(self.fm, base)
            key = ("V", name, size)
            if key not in self.objinfo:
                self.objinfo[key] = ObjInfo(name, "scalar", size, size, None, size or 1, 0)
            return AV(ptrs=frozenset({(key, 0)}), es=None, name="&" + name)
        return UNK

    def index(self, base: AV, idx: AV, write: bool, line: int) -> AV:
        es = base.es or 1
        if base.ptrs and any(o == ("ARGVV",) for o, _ in base.ptrs):
            return AV(ptrs=frozenset({(("ARGV",), 0)}), es=1, name="argv[]")
        self.use(base, line, "index")
        if base.ptrs and base.es is not None:
            self.bounds(base, idx, base.es, write, line, base.name or "")
            if write and self.summary_mode and idx.pv >= 0:
                pass
            if write:
                self.note_write_param(base, line)
                self.content_index_write(base, idx)
        out = AV(lv=(base.name + "[]") if base.name else None, name=None)
        out.idx = (base.ptrs, idx.lo, idx.hi, base.es)
        if not write and es == 1 and len(base.ptrs) == 1 and self.fm.facts is not None:
            # 27. tur: dış girdili tampondan okunan bayt saldırganın seçtiği sayıdır (uzunluk baytı: buf[0] << 8 | buf[1])
            (o, _off), = base.ptrs
            s_ = self.st.objs.get(o)
            if s_ is not None and s_[4] is not None and (s_[4].label == "net" or (
                    s_[4].label == "stdin" and self.fm.facts.stdin_service)):
                out.it = s_[4]
                out.hi = 255
        return out

    def content_index_write(self, base: AV, idx: AV) -> None:
        # sonraki atamanın değeri bilinmiyor; NUL ise assign() düzeltir
        self._pending_index = (base, idx)

    def deref_access(self, v: AV, k: int, write: bool, line: int) -> None:
        if not v.ptrs or v.es is None:
            if write:
                self.note_write_param(v, line)
            return
        self.bounds(v, _const(0), v.es, write, line, v.name or "")
        if write:
            self.note_write_param(v, line)

    def note_write_param(self, v: AV, line: int) -> None:
        """Özet: döngüde parametre tampona parametre uzunluğuyla sınırlı yazma (url_decode(src, dst, max))."""
        if not self.summary_mode or not self.loop_depth or not v.ptrs or (v.es or 1) != 1:
            return
        cond_names = set().union(*self.loop_conds) if self.loop_conds else set()
        for o, off in v.ptrs:
            if isinstance(o, tuple) and o and o[0] == "P":
                for nm in cond_names:
                    pidx = self.param_idx.get(nm)
                    if pidx is None or pidx == o[1] or not _SIZE_NAME.search(nm):
                        continue
                    vt = self.vtypes.get(nm)
                    if vt is None or vt[1] or (vt[0] and vt[0] not in _INT_TYPES and vt[0] not in self.fm.typedefs):
                        continue
                    if any(op.kind == "write" and op.param == o[1] and op.param2 == pidx for op in self.ops):
                        return
                    self.ops.append(Op("write", line, o[1], param2=pidx, es=v.es or 1, func=self.f.name,
                                       via="döngü"))
                    return

    def bounds(self, base: AV, idx: AV, es: int, write: bool, line: int, bname: str) -> None:
        if idx.lo is None and idx.hi is None:
            return
        if self._back_labels():
            return  # goto ile kurulmuş döngü (ör. bison ayrıştırıcısı): ofsetler güvenilmez
        full = idx.exact() is not None or bool(idx.name and self.loop_vars.get(idx.name, False))
        if len(base.ptrs) > 1:
            # birden çok olası hedef/ofset (yol birleşimi): yalnız hepsi kesin taşıyorsa raporla
            for o, off in base.ptrs:
                info = self.objinfo.get(o)
                if info is None or off is None or info.cap_hi is None or idx.hi is None or not full or \
                        off + idx.hi * es + es <= info.cap_hi:
                    return
            base = AV(ptrs=frozenset([max(base.ptrs, key=lambda x: (x[1] or 0))]), es=base.es, name=base.name)
        for o, off in base.ptrs:
            info = self.objinfo.get(o)
            if info is None or off is None or info.kind in ("param", "input", "scalar"):
                continue
            if not write and (info.kind == "literal" or len(base.ptrs) != 1):
                continue
            if full and idx.hi is not None and info.cap_hi is not None:
                hi_b = off + idx.hi * es
                if hi_b + es > info.cap_hi:
                    over = hi_b + es - info.cap_hi
                    kind = ("off_by_one" if over == es else "overflow") if write else "overread"
                    detail = (f"`{bname or info.name}` dizisine {'yazma' if write else 'okuma'}: indeks en çok "
                              f"{idx.hi}, eleman boyutu {es} bayt; tampon {info.cap_hi} bayt")
                    self.report(kind, line, len(base.ptrs) == 1, info, detail, write=write)
                    continue
            if idx.lo is not None:
                lo_b = off + idx.lo * es
                if lo_b < 0 and (full or off < 0):
                    kind = "underwrite" if write else "underread"
                    detail = (f"`{bname or info.name}` için başlangıçtan {-lo_b} bayt önceye "
                              f"{'yazma' if write else 'okuma'}")
                    self.report(kind, line, len(base.ptrs) == 1, info, detail, write=write)

    def field(self, v: AV, fname: str, op: str, line: int) -> AV:
        base = v.lv or v.name
        if not base or "[]" in base or base.startswith("*"):
            return AV()
        path = f"{base}.{fname}" if op == "." else f"{base}->{fname}"
        if path in self.st.vars:
            s = self.st.vars[path]
            fi_ = self._field_info(base, fname)
            return AV(lo=s[1], hi=s[2], lin=s[3], ptrs=s[0], it=s[4], lv=path, name=path,
                      es=(fi_.pes if fi_ is not None and fi_.ptr else None))
        if self.fm.facts is not None:
            mv = self._model_field(base, fname, path, line)
            if mv is not None:
                return mv
        fi = self._field_info(base, fname)
        if fi is not None and fi.count is not None and fi.es is not None:
            key = ("F", path, fi.count, fi.es, self._struct_of_root(base))
            if key not in self.objinfo:
                cap = fi.count * fi.es
                self.objinfo[key] = ObjInfo(path.replace("->", "."), "field", cap, cap, None, fi.es, 0)
            return AV(ptrs=frozenset({(key, 0)}), es=fi.es, name=path)
        es = None
        if fi is not None and fi.ptr:
            es = fi.pes
        return AV(lv=path, name=path, es=es)

    def _struct_of_root(self, base: str) -> str:
        vt = self.vtypes.get(base) or self.fm.globals_.get(base)
        if vt is None:
            return ""
        return vt[3] or self.fm.typedefs.get(vt[0], "") or vt[0]

    def _field_es(self, base: str, fname: str) -> int | None:
        fi = self._field_info(base, fname)
        if fi is None:
            return None
        return None if fi.ptr else fi.es

    def _field_info(self, base: str, fname: str) -> FieldInfo | None:
        root = base.split(".")[0].split("->")[0].lstrip("*&")
        if root != base:
            return None
        vt = self.vtypes.get(root) or self.fm.globals_.get(root)
        if vt is None:
            return None
        struct = vt[3] or self.fm.typedefs.get(vt[0], "")
        fields = self.fm.structs.get(struct)
        if not fields:
            return None
        return fields.get(fname)

    def incdec(self, v: AV, op: str, line: int) -> None:
        name = v.lv
        if not name or name not in self.st.vars:
            return
        s = self.st.vars[name]
        if s[0]:
            ptrs = frozenset((o, None if (off is None or self.loop_depth or not v.es) else off + v.es * (1 if op == "++" else -1))
                             for o, off in s[0])
            self.st.vars[name] = (ptrs, None, None, None, s[4], s[5])
        else:
            d = 1 if op == "++" else -1
            lo = None if s[1] is None else s[1] + d
            hi = None if s[2] is None else s[2] + d
            if self.loop_depth:
                lo = hi = None
            self.st.vars[name] = (s[0], lo, hi, None, s[4], s[5])

    def assign(self, lhs: AV, op: str, rhs: AV, line: int, start: int) -> AV:
        name = lhs.lv
        pend = getattr(self, "_pending_index", None)
        self._pending_index = None
        if lhs.idx is not None and pend is not None:
            base, idx = pend
            k = idx.exact()
            val = rhs.exact()
            for o, off in base.ptrs:
                if off is None:
                    continue
                es = base.es or 1
                s = self.obj_state(o)
                if k is not None and val == 0:
                    pos = off // es + k
                    if s[5]:
                        self.set_cont(o, min(s[2], pos), pos if s[3] is None else min(s[3], pos), keep_taint=True)
                    else:
                        self.set_cont(o, 0 if pos > 0 else 0, pos)
                elif s[5]:
                    self._char_write(o, s, None if k is None else off // es + k, rhs)
            return rhs
        pd = getattr(self, "_pending_deref", None)
        self._pending_deref = None
        if pd is not None and name and name.startswith("*"):
            pname = name[1:]
            pvt = self.vtypes.get(pname)
            owner = self._pp_owner_name(pname)
            if op == "=" and owner is not None and pvt is not None and pvt[1] >= 2:
                ptrs = rhs.ptrs
                if not ptrs and rhs.exact() != 0 and rhs.s is None:
                    ptrs = frozenset({UNKP})
                self._set_owner_state(owner, (ptrs, rhs.lo, rhs.hi, rhs.lin, rhs.it, rhs.pv))
            val = rhs.exact()
            for o, off in pd.ptrs:
                s = self.st.objs.get(o)
                if s is None or not s[5]:
                    continue
                es = pd.es or 1
                pos = None if off is None else off // es
                if val == 0 and pos is not None:
                    self.set_cont(o, min(s[2], pos), pos if s[3] is None else min(s[3], pos), keep_taint=True)
                else:
                    self._char_write(o, s, pos, rhs)
            return rhs
        if not name or name.startswith("*") or name.endswith("[]"):
            return rhs
        if name.startswith("&"):
            return rhs
        if op == "=":
            if "->" not in name and "." not in name:
                pre1, pre2 = name + "->", name + "."
                for k in [k for k in self.st.vars if k.startswith(pre1) or k.startswith(pre2)]:
                    del self.st.vars[k]
            ptrs = rhs.ptrs
            if not ptrs and rhs.exact() != 0 and rhs.s is None:
                vt = self.vtypes.get(name) or self.fm.globals_.get(name)
                if vt is not None and vt[1] >= 1:
                    ptrs = frozenset({UNKP})
            self.st.vars[name] = (ptrs, rhs.lo, rhs.hi, rhs.lin, rhs.it, rhs.pv)
            vt = self.vtypes.get(name) or self.fm.globals_.get(name)
            self._remember_pp_owner(name, vt[1] if vt is not None else 0, rhs)
            if name in self.st.checked and not rhs.it:
                pass
            elif rhs.it and name in self.st.checked:
                self.st.checked = self.st.checked - {name}
            if name not in self.vtypes and "." not in name and "->" not in name and name not in self.fm.globals_:
                self.vtypes[name] = ("", 1 if rhs.ptrs else 0, [], "")
            return rhs
        cur = self.st.vars.get(name, (frozenset(), None, None, None, None, -1))
        a = AV(lo=cur[1], hi=cur[2], lin=cur[3], ptrs=cur[0], it=cur[4], es=lhs.es, name=name)
        r = self.binop(op[:-1], a, rhs, line)
        if r.ptrs and self.loop_depth:
            r.ptrs = frozenset((o, None) for o, _ in r.ptrs)
        if self.loop_depth and not r.ptrs:
            r = AV(it=r.it)
        self.st.vars[name] = (r.ptrs, r.lo, r.hi, r.lin, r.it, -1)
        return r

    def _char_write(self, o, s, pos: int | None, rhs: AV) -> None:
        """Sıfır olmadığı bilinmeyen/sıfırdan farklı bir eleman yazımı: konum dizgi uzunluğunun altındaysa uzunluk
        değişmez, değilse (ya da konum bilinmiyorsa) uzunluk bilgisi kaybolur (eski NUL ezilmiş olabilir)."""
        if pos is not None and s[2] is not None and pos < s[2] and (rhs.lo is not None and rhs.lo > 0):
            return
        self.set_cont(o, 0, None, keep_taint=True)

    def cin_read(self, b: AV, line: int) -> None:
        for o, off in b.ptrs:
            info = self.objinfo.get(o)
            if info is not None and (b.es or info.es) == 1 and info.kind in ("stack", "static", "heap", "field") and \
                    info.cap_hi is not None:
                self.report("overflow_taint", line, True, info,
                            f"std::cin >> `{b.name or info.name}`: genişlik sınırı olmadan {info.cap_hi} baytlık tampona okuma",
                            source=Taint("cin", line, "std::cin"))
            self.set_cont(o, 0, None, Taint("cin", line, "std::cin"))
        if b.lv and not b.ptrs and b.lv in self.st.vars:
            s = self.st.vars[b.lv]
            self.st.vars[b.lv] = (s[0], None, None, None, Taint("cin", line, "std::cin"), -1)
        elif b.lv and not b.ptrs:
            self.st.vars[b.lv] = (frozenset(), None, None, None, Taint("cin", line, "std::cin"), -1)

    # -- kullanım / serbest bırakma ----------------------------------------------
    def use(self, v: AV, line: int, how: str, certain_ok: bool = True) -> None:
        if not v.ptrs:
            return
        if self.summary_mode:
            for o, _ in v.ptrs:
                if isinstance(o, tuple) and o and o[0] == "P":
                    self.puses.add(o[1])
        seen: set = set()
        for o, off in v.ptrs:
            if o in seen:
                continue
            seen.add(o)
            s = self.st.objs.get(o)
            if s is None or s[0] <= 0:
                continue
            info = self.objinfo.get(o)
            if info is None:
                continue
            certain = s[0] == 2 and _nobj(v.ptrs) == 1 and certain_ok and how != "return"
            if not certain and s[1] >= line:
                continue  # önceki döngü turundan kalan olası durum (çoğunlukla ölü eski takma ad)
            what = {"return": "döndürülüyor", "deref": "işaretçiden erişiliyor", "index": "indeksleniyor",
                    "call": "çağrıya argüman olarak veriliyor", "copy": "kopyalamada kullanılıyor"}.get(how, how)
            self.report("uaf", line, certain, info,
                        f"`{v.name or info.name}` satır {s[1]}'de serbest bırakıldıktan sonra {what}",
                        source=Taint("free", s[1], "free()"))

    def do_free(self, v: AV, line: int, how: str) -> None:
        if not v.ptrs:
            return
        single = _nobj(v.ptrs) == 1
        seen: set = set()
        for o, off in sorted(v.ptrs, key=lambda x: (str(x[0]), x[1] is None, x[1] or 0)):
            if o in seen:
                continue
            seen.add(o)
            info = self.objinfo.get(o)
            if info is None:
                continue
            s = self.obj_state(o)
            if s[0] > 0:
                certain = s[0] == 2 and single
                if not certain and s[1] >= line:
                    s = (0,) + s[1:]
                    certain = None
                if certain is not None:
                    self.report("double_free", line, certain, info,
                                f"`{v.name or info.name}` satır {s[1]}'de zaten serbest bırakıldı; satır {line}'de yeniden {how}",
                                source=Taint("free", s[1], "free()"))
            elif info.kind in ("stack", "static", "literal", "scalar") and how in ("free", "delete", "delete[]") and single:
                what = {"stack": "yığın dizisi", "scalar": "değişkenin adresi (yığın/statik)"}.get(info.kind, "statik bellek")
                if info.alloc == "alloca":
                    what = "alloca() belleği"
                # alloca/malloc seçimi çoğu zaman önişlemci koşuluna bağlı (#ifdef USE_ALLOCA): olası. Satır içi
                # yürütülen çağrılandaki free çoğunlukla bir alan/bayrak koşuluna bağlıdır (yığın nesnesi için
                # sıfırlanmış alan): olası.
                self.report("free_nonheap", line, single and info.alloc != "alloca" and self.depth == 0, info,
                            f"`{v.name or info.name}` {what}; {how} ile serbest bırakılamaz")
            elif off is not None and off != 0 and info.kind == "heap":
                self.report("free_offset", line, single, info,
                            f"`{v.name or info.name}` ayırmanın başından {off} bayt ilerde; {how} geçersiz")
            elif info.kind == "heap" and info.alloc:
                bad = (info.alloc in ("malloc",) and how in ("delete", "delete[]")) or \
                      (info.alloc in ("new", "new[]") and how == "free") or \
                      (info.alloc == "new[]" and how == "delete") or (info.alloc == "new" and how == "delete[]")
                if bad:
                    self.report("mismatch_free", line, single, info,
                                f"`{v.name or info.name}` {info.alloc} ile ayrıldı, {how} ile serbest bırakılıyor")
            if info.kind in ("stack", "static", "literal", "scalar", "field"):
                continue  # free bu belleği geri vermez; durum izlenmez (hata yukarıda raporlandı)
            self.st.objs[o] = (2 if single else max(1, s[0]), line, s[2], s[3], s[4], s[5] if s[0] >= 0 else False)

    # -- çağrılar ------------------------------------------------------------------
    def call(self, name: str, args: list[tuple[int, int]], line: int, fv: AV) -> AV:
        short = name.rsplit("::", 1)[-1] if name else ""
        if short.startswith("__builtin___") and short.endswith("_chk"):
            short = short[len("__builtin___"):-4]
        if short in ("sizeof",):
            return UNK
        self._argtexts = [self._argtext(r) for r in args[:4]]
        avs: list[AV] = []
        for a, b in args:
            if a >= b:
                avs.append(UNK)
                continue
            try:
                avs.append(self.eval_range(a, b))
            except (_ParseError, IndexError, ValueError, TypeError, AttributeError):
                avs.append(UNK)
        n = len(avs)
        # serbest bırakma
        if short in _FREE and n >= 1:
            self.do_free(avs[0] if short not in ("HeapFree",) else (avs[2] if n > 2 else UNK), line, "free")
            return UNK
        if short in _ALLOC and n >= 1:
            sz = avs[0] if short not in ("HeapAlloc", "LocalAlloc", "GlobalAlloc") else avs[-1]
            kind = "alloca" if short in _STACK_ALLOC else "malloc"
            self.check_alloc_size(sz, 1, line, short)
            return self.alloc(sz, line, kind)
        if short in _CALLOC and n >= 2:
            a0, a1 = avs[0], avs[1]
            sz = AV()
            if a0.lo is not None and a0.hi is not None and a1.lo is not None and a1.hi is not None and a0.lo >= 0 and a1.lo >= 0:
                sz = AV(lo=a0.lo * a1.lo, hi=a0.hi * a1.hi)
            return self.alloc(sz, line, "malloc")
        if short in _REALLOC and n >= 2:
            self.use(avs[0], line, "call")
            self.check_alloc_size(avs[1], 1, line, short)
            old = avs[0]
            old_states = {o: self.st.objs[o] for o, _off in old.ptrs if o in self.st.objs}
            # Sonuç denetlenmeden önce iki yürütme olasılığı vardır: başarı eski ayırmanın yaşamını bitirir,
            # başarısızlık eski ayırmayı canlı bırakır. Sonuç NULL / NULL-dışı dalında yukarıdaki ilişki kesinleşir.
            for o, before in old_states.items():
                if before[0] <= 0:
                    self.st.objs[o] = (1, line, before[2], before[3], before[4], before[5])
            r = self.alloc(avs[1], line, "malloc")
            size_may_be_zero = avs[1].lo is None or avs[1].lo <= 0
            for new_object, _off in r.ptrs:
                self.realloc_old[new_object] = (old_states, line, size_may_be_zero, short == "reallocf")
            # içerik korunur
            for o, off in old.ptrs:
                s = self.obj_state(o)
                if s[5]:
                    for no, _ in r.ptrs:
                        self.set_cont(no, s[2], s[3], s[4])
            return r
        if short in _DUP and n >= 1:
            src = avs[0]
            self.use(src, line, "call")
            lo, hi, tnt = self.content(src)
            if short == "strndup" and n >= 2 and avs[1].hi is not None:
                hi = avs[1].hi if hi is None else min(hi, avs[1].hi)
            key = self.heap_key(line)
            cap_lo = None if lo is None else lo + 1
            cap_hi = None if hi is None else hi + 1
            key_ = src.name or self._argtext(args[0])
            lin = ("strlen:" + key_, 1, 1) if key_ else None
            self.new_obj(key, ObjInfo(f"{short}()", "heap", cap_lo, cap_hi, lin, 1, line, "malloc"),
                         cont=(lo or 0, hi), taint=tnt)
            return AV(ptrs=frozenset({(key, 0)}), es=1)
        if short in _STRLEN and n >= 1:
            src = avs[0]
            self.use(src, line, "call")
            lo, hi, tnt = self.content(src)
            if short in ("strnlen", "wcsnlen") and n >= 2 and avs[1].hi is not None:
                hi = avs[1].hi if hi is None else min(hi, avs[1].hi)
                lo = None if lo is None else min(lo, avs[1].hi)
            v = AV(lo=lo, hi=hi)
            key_ = src.name or self._argtext(args[0])
            if key_:
                v.lin = ("strlen:" + key_, 1, 0)
                v.lenof = key_
            if tnt is not None and hi is None:
                v.it = None
            return v
        if short in _NUM_CONV and n >= 1:
            src = avs[0]
            self.use(src, line, "call")
            lo, hi, tnt = self.content(src)
            it = tnt if tnt is not None else src.it
            return AV(it=it)
        if short == "getenv" and n >= 1:
            key = ("E", line, self.pos)
            self.new_obj(key, ObjInfo("getenv()", "input", None, None, None, 1, line), cont=(0, None),
                         taint=Taint("env", line, "getenv"))
            return AV(ptrs=frozenset({(key, 0)}), es=1, name="getenv()")
        if short in ("rand", "random"):
            return AV(lo=0, hi=INT32_MAX)
        # bellek/dizgi işlevleri
        if short in _GETS and n >= 1:
            self.input_write(avs[0], None, line, Taint("stdin", line, short), unbounded=True, fn=short, es=_GETS[short])
            return avs[0]
        if short in _FGETS and n >= 3:
            label = "stdin" if self._is_stdin(args[2]) else "file"
            nlen = avs[1]
            self.input_write(avs[0], nlen, line, Taint(label, line, f"{short}({'stdin' if label == 'stdin' else 'dosya'})"),
                             unbounded=False, fn=short, es=_FGETS[short], elems=True)
            return avs[0]
        if short in _FILE_READ or short in _NET_READ:
            spec = _FILE_READ.get(short) or _NET_READ.get(short)
            if short == "fread" and n >= 4:
                sz = avs[1]
                cnt = avs[2]
                total = AV()
                if sz.lo is not None and cnt.lo is not None and sz.hi is not None and cnt.hi is not None:
                    total = AV(lo=sz.lo * cnt.lo, hi=sz.hi * cnt.hi)
                if sz.exact() == 1 and cnt.lin is not None:
                    total.lin = cnt.lin
                elif cnt.exact() == 1 and sz.lin is not None:
                    total.lin = sz.lin
                label = "stdin" if self._is_stdin(args[3]) else "file"
                self.input_write(avs[0], total, line, Taint(label, line, f"fread({'stdin' if label == 'stdin' else 'dosya'})"),
                                 unbounded=False, fn=short, es=1, raw=True)
                return AV(lo=0, hi=total.hi)
            if spec and spec[0] is not None and n > spec[1]:
                label = "net" if short in _NET_READ or self._sockish(args[0]) else "file"
                if short in ("read", "_read", "pread") and self._is_stdin(args[0]):
                    label = "stdin"
                self.input_write(avs[spec[0]], avs[spec[1]], line, Taint(label, line, short), unbounded=False, fn=short,
                                 es=1, raw=True)
                return AV(lo=-1, hi=avs[spec[1]].hi)
            return UNK
        if short in _SCANF:
            self.scanf(short, args, avs, line)
            return UNK
        if short == "getline" and n >= 3:
            label = "stdin" if self._is_stdin(args[2]) else "file"
            p = avs[0]
            if p.ptrs:
                for o, _ in p.ptrs:
                    if o in self.objinfo and self.objinfo[o].kind == "scalar":
                        vname = self.objinfo[o].name
                        key = self.heap_key(line)
                        self.new_obj(key, ObjInfo("getline()", "heap", None, None, None, 1, line, "malloc"),
                                     cont=(0, None), taint=Taint(label, line, "getline"))
                        s = self.st.vars.get(vname, (frozenset(), None, None, None, None, -1))
                        self.st.vars[vname] = (frozenset({(key, 0)}), None, None, None, None, -1)
            return AV()
        if short in _UNBOUNDED_CPY and n >= 2:
            self.copy_op(avs[0], avs[1], line, short, cat=False, es=_UNBOUNDED_CPY[short])
            return avs[0]
        if short in _UNBOUNDED_CAT and n >= 2:
            self.copy_op(avs[0], avs[1], line, short, cat=True, es=_UNBOUNDED_CAT[short])
            return avs[0]
        if short in _NCPY and n >= 3:
            self.ncopy_op(avs[0], avs[1], avs[2], line, short, cat=False, es=_NCPY[short])
            return avs[0]
        if short in _NCAT and n >= 3:
            self.ncopy_op(avs[0], avs[1], avs[2], line, short, cat=True, es=_NCAT[short])
            return avs[0]
        if short in ("strlcpy", "strlcat", "wcslcpy", "g_strlcpy", "g_strlcat") and n >= 3:
            self.sized_write(avs[0], avs[2], line, short, 1, elems=False)
            self.use(avs[1], line, "copy")
            lo, hi, tnt = self.content(avs[1])
            nh = avs[2].hi
            for o, off in avs[0].ptrs:
                self.set_cont(o, 0, None if nh is None else max(0, nh - 1), tnt)
            return UNK
        if short in _MEMCPY and n >= 3:
            self.memcpy_op(avs[0], avs[1], avs[2], line, short, _MEMCPY[short])
            return avs[0]
        if short == "bcopy" and n >= 3:
            self.memcpy_op(avs[1], avs[0], avs[2], line, short, 1)
            return UNK
        if short in _MEMSET and n >= 2:
            if short in ("bzero", "explicit_bzero", "ZeroMemory", "SecureZeroMemory"):
                self.memset_op(avs[0], _const(0), avs[1], line, short, 1)
            elif n >= 3:
                self.memset_op(avs[0], avs[1], avs[2], line, short, _MEMSET[short])
            return avs[0]
        if short in _SNPRINTF and n >= 3:
            self.snprintf_op(avs, line, short, _SNPRINTF[short])
            self.fmt_check(short, args, avs, line, 2)
            return AV()
        if short in _SPRINTF and n >= 2:
            self.sprintf_op(avs, line, short)
            self.fmt_check(short, args, avs, line, 1)
            return AV()
        if short in _PRINTF:
            idx = _PRINTF[short]
            if n > idx:
                self.fmt_check(short, args, avs, line, idx)
            for a in avs:
                self.use(a, line, "call")
            return AV()
        if short in ("strtok", "strtok_r", "strsep"):
            for a in avs[:1]:
                self.use(a, line, "call")
            src = avs[0]
            return AV(ptrs=frozenset((o, None) for o, _ in src.ptrs), es=1)
        if short in ("strchr", "strrchr", "strstr", "strpbrk", "memchr", "strcasestr", "wcschr", "wcsrchr", "wcsstr"):
            for a in avs:
                self.use(a, line, "call")
            src = avs[0]
            return AV(ptrs=frozenset((o, None) for o, _ in src.ptrs), es=src.es)
        if short in _TERMINATE:
            for a in avs:
                self.use(a, line, "call")
            return UNK
        # aynı dosyadaki fonksiyon: satır içi yürütme ya da özet
        target = self.fptr.get(name) or short
        callee = self.fm.funcs.get(target)
        deref_frees = self.sink.deref_frees.get(target)
        deref_nulls = self.sink.deref_nulls.get(target)
        if callee is not None and not deref_frees and not deref_nulls and self._can_inline(callee, avs):
            r = self.inline(callee, avs, line)
            wops = [op for op in self.sink.summaries.get(target, ()) if op.kind == "write" and op.param2 >= 0]
            if wops:
                self.apply_summary(target, wops, avs, line)
            return r
        short = target
        summ = self.sink.summaries.get(short)
        frees = self.sink.frees.get(short)
        deref_frees = self.sink.deref_frees.get(short)
        deref_nulls = self.sink.deref_nulls.get(short)
        puses = self.sink.puses.get(short)
        for i_, a in enumerate(avs):
            if (frees and i_ in frees) or (deref_frees and i_ in deref_frees):
                continue
            if callee is not None and puses is not None and i_ not in puses:
                continue
            # dosya dışı bilinmeyen işlev: serbest bırakılmış işaretçiyi kullanıp kullanmadığı bilinmez → olası
            self.use(a, line, "call", certain_ok=callee is not None or bool(_DEREF_CALL.match(short)))
        if frees:
            for i_, must in frees.items():
                if i_ < n:
                    v = avs[i_]
                    if not must:
                        # yalnız bazı yollarda serbest bırakan çağrılan: çağıran durumu değişmez (bayrak ilişkili
                        # temizlik deyimleri çok yaygın; satır içi yürütmeyle aynı ilke)
                        pass
                    else:
                        self.do_free(v, line, f"{short}() içinde free")
        if deref_frees:
            for i_, must in deref_frees.items():
                if i_ >= n or not must:
                    continue
                arg = avs[i_]
                owner = self._pp_owner_name(arg.name or arg.lv)
                s_ = self._owner_state(owner)
                if s_ is not None:
                    self.do_free(AV(ptrs=s_[0], lo=s_[1], hi=s_[2], lin=s_[3], it=s_[4], pv=s_[5],
                                    lv=owner if isinstance(owner, str) else None,
                                    name=owner if isinstance(owner, str) else "*param",
                                    es=self.es_of_name(owner) if isinstance(owner, str) else None),
                                 line, f"{short}() içinde free(*param)")
        if deref_nulls:
            for i_ in deref_nulls:
                if i_ >= n:
                    continue
                arg = avs[i_]
                owner = self._pp_owner_name(arg.name or arg.lv)
                old = self._owner_state(owner)
                if old is not None:
                    self._set_owner_state(owner, (frozenset(), 0, 0, None, None, old[5]))
        if summ:
            self.apply_summary(short, summ, avs, line)
        refs = self.fm.ref_protos.get(short)
        if refs:
            for i_ in refs:
                if i_ < n and avs[i_].lv and avs[i_].lv in self.st.vars:
                    s_ = self.st.vars[avs[i_].lv]
                    self.st.vars[avs[i_].lv] = (frozenset(), None, None, None, s_[4], -1)
        # bilinmeyen çağrı: işaretçi argümanlarının içerik alt sınırı kaybolur
        if callee is None or not (summ or frees or deref_frees or deref_nulls):
            keep = bool(_READONLY.match(short))
            for a in avs:
                if a.ptrs and not keep:
                    for o, off in a.ptrs:
                        s = self.st.objs.get(o)
                        if s is not None and s[5]:
                            self.st.objs[o] = (s[0], s[1], 0, s[3], s[4], s[5])
                if a.name and a.name.startswith("&"):
                    vn = a.name[1:]
                    if vn in self.st.vars:
                        s = self.st.vars[vn]
                        vt = self.vtypes.get(vn)
                        self.st.vars[vn] = (s[0] | frozenset({UNKP}) if vt is not None and vt[1] >= 1 else s[0],
                                            None, None, None, s[4], -1)
        if self.fm.facts is not None:
            return self._model_call(short, line, avs)
        return AV()

    def apply_summary(self, fname: str, ops: list[Op], avs: list[AV], line: int) -> None:
        for op in ops:
            if op.param >= len(avs):
                continue
            arg = avs[op.param]
            if op.kind == "src_into":
                lo, hi, tnt = self.content(arg)
                # çağıranın kendi parametresiyse özete taşı
                if self.summary_mode and self._param_of(arg) is not None and tnt is None and lo == 0 and hi is None:
                    p = self._param_of(arg)
                    if not any(o.kind == "src_into" and o.line == op.line and o.param == p for o in self.ops):
                        self.ops.append(Op("src_into", op.line, p, avail_lo=op.avail_lo, avail_hi=op.avail_hi,
                                           buffer=op.buffer, buffer_line=op.buffer_line, extra=op.extra, es=op.es,
                                           via=f"{fname}()", func=op.func))
                    continue
                info = ObjInfo(op.buffer, "stack", op.avail_lo, op.avail_hi, None, op.es, op.buffer_line)
                need_lo = None if lo is None else (lo + op.extra) * op.es
                if need_lo is not None and op.avail_hi is not None and need_lo > op.avail_hi and lo > 0:
                    self.report("overflow", op.line, True, info,
                                f"{fname}() çağrısı (satır {line}) {lo} karakterlik dizgiyi {op.avail_hi} baytlık "
                                f"`{op.buffer}` tamponuna kopyalatıyor", func=op.func, src_line=line)
                elif tnt is not None and op.avail_hi is not None and (hi is None or (hi + op.extra) * op.es > op.avail_hi):
                    self.report("overflow_taint", op.line, hi is not None or tnt.exact, info,
                                f"{_LABELS.get(tnt.label, tnt.label)} (satır {tnt.line}) {fname}() çağrısıyla (satır {line}) "
                                f"{op.avail_hi} baytlık `{op.buffer}` tamponuna sınırsız kopyalanıyor",
                                source=tnt, func=op.func, src_line=line)
            elif op.kind == "write":
                nv = avs[op.param2] if 0 <= op.param2 < len(avs) else None
                need = op.need
                if nv is not None:
                    if self.summary_mode and nv.pv >= 0 and self._param_of(arg) is not None:
                        p = self._param_of(arg)
                        if not any(o.kind == "write" and o.line == op.line for o in self.ops):
                            self.ops.append(Op("write", op.line, p, param2=nv.pv, es=op.es, via=f"{fname}()", func=op.func))
                        continue
                    need = None if nv.lo is None else nv.lo * op.es
                if need is None:
                    continue
                for o, off in arg.ptrs:
                    info = self.objinfo.get(o)
                    if info is None or off is None or info.cap_hi is None or info.kind in ("param", "input", "scalar"):
                        continue
                    avail = info.cap_hi - off
                    if need > avail:
                        self.report("overflow", op.line, len(arg.ptrs) == 1, info,
                                    f"{fname}() (satır {line}'den çağrılıyor) `{arg.name or info.name}` tamponuna en çok "
                                    f"{need} bayt yazabiliyor; tampon {avail} bayt", func=op.func, src_line=line)
            elif op.kind == "fmt":
                lo, hi, tnt = self.content(arg)
                if self.summary_mode and self._param_of(arg) is not None and tnt is None:
                    p = self._param_of(arg)
                    if not any(o.kind == "fmt" and o.line == op.line for o in self.ops):
                        self.ops.append(Op("fmt", op.line, p, via=f"{fname}()", func=op.func))
                    continue
                if tnt is not None and tnt.label != "free":
                    self.report("format", op.line, True, None,
                                f"{_LABELS.get(tnt.label, tnt.label)} (satır {tnt.line}) {fname}() çağrısıyla (satır {line}) "
                                f"biçim dizgesi olarak kullanılıyor", source=tnt, func=op.func, src_line=line)

    def _argtext(self, r: tuple[int, int]) -> str:
        a, b = r
        if b - a > 12 or b <= a:
            return ""
        return "".join(self.toks[q].text for q in range(a, b))

    def _param_of(self, v: AV) -> int | None:
        if not v.ptrs or len(v.ptrs) != 1:
            return None
        (o, off), = v.ptrs
        if isinstance(o, tuple) and o and o[0] == "P":
            return o[1]
        return None

    def _is_stdin(self, r: tuple[int, int]) -> bool:
        a, b = r
        txt = [self.toks[q].text for q in range(a, b)]
        return txt in (["stdin"], ["0"], ["STDIN_FILENO"], ["std", "::", "cin"])

    def _sockish(self, r: tuple[int, int]) -> bool:
        a, b = r
        return b - a == 1 and bool(cf._SOCKISH.search(self.toks[a].text))

    # -- 27. tur: dosyalar arası kirlilik modeli ---------------------------------------
    _CHARISH = frozenset({"char", "unsigned char", "signed char", "uint8_t", "int8_t", "u8", "u_char", "uchar",
                          "BYTE", "UCHAR", "gchar", "guchar", "void", "wchar_t", "TCHAR", "CHAR"})

    def _model_param(self, p, base: str, ptr: int, struct: str):
        """Çağıranlardan bu parametreye ulaşan dış girdi: (Taint, en büyük uzunluk | None, alt sınır) ya da None."""
        mf = self.fm.facts
        origins = mf.param_in.get((self.fm.path, self.f.name, p.index))
        if not origins:
            return None
        if ptr == 1 and not struct and (base in self._CHARISH or base.split()[-1:] == ["char"]) and \
                self.fm.typedefs.get(base, "") not in self.fm.structs:
            mt = mf.taint_of(origins, False)
            return None if mt is None else mt + (None,)
        if ptr == 0 and base in _INT_TYPES:
            mt = mf.taint_of(origins, True)
            if mt is not None:
                return (mt[0], _type_max(base), _type_min(base))
        return None

    def _path_struct(self, base: str) -> str:
        """``req`` / ``c->req`` / ``s.inner`` yolunun yapı türü (dosya modeli ya da proje modeli tanımlarıyla)."""
        parts = re.split(r"->|\.", base)
        root = parts[0].lstrip("*&")
        vt = self.vtypes.get(root) or self.fm.globals_.get(root)
        if vt is None:
            return ""
        stype = vt[3] or self.fm.typedefs.get(vt[0], "") or vt[0]
        for f in parts[1:]:
            fields = self.fm.structs.get(stype)
            fi = fields.get(f) if fields else None
            if fi is None or not fi.struct:
                mfs = (self.fm.facts.structs.get(stype) or {}).get(f) if self.fm.facts is not None else None
                if not mfs:
                    return ""
                nxt = ""
                for w in reversed(re.findall(r"[A-Za-z_]\w*", mfs[0])):
                    if w in self.fm.facts.structs:
                        nxt = w
                        break
                if not nxt:
                    return ""
                stype = nxt
                continue
            stype = fi.struct
        return stype

    def _model_field(self, base: str, fname: str, path: str, line: int) -> AV | None:
        mf = self.fm.facts
        stype = self._path_struct(base)
        if not stype:
            return None
        origins = mf.field_origins((stype, fname), self.fm.path)
        if not origins:
            return None
        weak = (stype, fname) in mf.mixed_fields
        fields = self.fm.structs.get(stype) or {}
        fi = fields.get(fname)
        mfs = (mf.structs.get(stype) or {}).get(fname)
        if fi is not None and fi.count is not None and fi.es is not None and not fi.ptr:
            if fi.es != 1:
                return None
            mt = mf.taint_of(origins, False, weak)
            if mt is None:
                return None
            key = ("F", path, fi.count, fi.es, stype)
            if key not in self.objinfo:
                cap = fi.count * fi.es
                self.objinfo[key] = ObjInfo(path.replace("->", "."), "field", cap, cap, None, fi.es, 0)
            s_ = self.st.objs.get(key)
            if s_ is None or not s_[5]:
                cap = fi.count * fi.es
                hi = cap - 1 if mt[1] is None else min(mt[1], cap - 1)
                self.st.objs[key] = (0, 0, 0, hi, mt[0], True)
            return AV(ptrs=frozenset({(key, 0)}), es=fi.es, name=path)
        ptr = fi.ptr if fi is not None else bool(mfs and mfs[2])
        if ptr:
            pes = fi.pes if fi is not None else None
            if pes not in (None, 1):
                return None
            mt = mf.taint_of(origins, False, weak)
            if mt is None:
                return None
            key = ("TF", path)
            if key not in self.objinfo:
                self.objinfo[key] = ObjInfo(path.replace("->", "."), "input", None, None, None, 1, line)
            if key not in self.st.objs:
                self.st.objs[key] = (0, 0, 0, mt[1], mt[0], True)
            return AV(ptrs=frozenset({(key, 0)}), es=1, name=path, lv=path)
        typ = mfs[0] if mfs else ""
        words = [w for w in typ.split() if w not in ("const", "volatile", "struct")]
        tname = " ".join(words)
        if tname in _INT_TYPES or (words and words[-1] in _INT_TYPES):
            if fname in mf.guarded_fields:
                return None  # alan projede bir yerde sınırla karşılaştırılıyor (doğrulanmış uzunluk)
            mt = mf.taint_of(origins, True, weak)
            if mt is None:
                return None
            return AV(it=mt[0], name=path, lv=path, lo=_type_min(tname), hi=_type_max(tname))
        return None

    def _model_call(self, short: str, line: int, avs: list[AV]) -> AV:
        mf = self.fm.facts
        for i_, a in enumerate(avs):
            out = mf.call_out.get((self.fm.path, line, short, i_))
            if not out:
                continue
            mt = mf.taint_of(out, False)
            if mt is None:
                continue
            for o, off in a.ptrs:
                info = self.objinfo.get(o)
                if info is None or off is None:
                    continue
                a_lo, a_hi, _ = self.avail(o, off)
                hi = mt[1]
                if a_hi is not None:
                    hi = a_hi - 1 if hi is None else min(hi, a_hi - 1)
                self.set_cont(o, 0, hi, mt[0])
        ret = mf.call_ret.get((self.fm.path, line, short))
        if not ret:
            return AV()
        mt = mf.taint_of(ret, False)
        if mt is not None:
            key = ("TR", line, self.pos)
            if key not in self.objinfo:
                self.objinfo[key] = ObjInfo(f"{short}()", "input", None, None, None, 1, line)
            self.st.objs[key] = (0, 0, 0, mt[1], mt[0], True)
            return AV(ptrs=frozenset({(key, 0)}), es=1, name=f"{short}()")
        mt = mf.taint_of(ret, True)
        if mt is not None:
            return AV(it=mt[0])
        return AV()

    # -- içerik --------------------------------------------------------------------
    def content(self, v: AV) -> tuple[int | None, int | None, Taint | None]:
        """İşaretçinin gösterdiği dizginin uzunluk aralığı (alt, üst) ve kirlilik."""
        if v.s is not None:
            n = len(v.s)
            return n, n, None
        if not v.ptrs:
            return None, None, None
        los, his, tnt = [], [], None
        for o, off in v.ptrs:
            s = self.st.objs.get(o)
            info = self.objinfo.get(o)
            if s is None or not s[5]:
                if info is not None and info.kind in ("param",):
                    los.append(0)
                    his.append(None)
                    continue
                if info is not None and info.cap_hi is not None and info.kind in ("stack", "static", "heap", "field"):
                    # başlatılmamış tampon: içerik bilinmez
                    los.append(None)
                    his.append(None)
                    continue
                los.append(None)
                his.append(None)
                continue
            es = info.es if info is not None else 1
            shift = 0 if off is None or not es else off // es
            lo = s[2] - shift if off is not None else 0
            hi = None if s[3] is None else (s[3] - shift if off is not None else s[3])
            los.append(max(0, lo) if lo is not None else 0)
            his.append(None if hi is None else max(0, hi))
            tnt = tnt or s[4]
        lo = None if any(x is None for x in los) else min(los)
        hi = None if any(x is None for x in his) else max(his)
        return lo, hi, tnt

    def avail(self, o, off) -> tuple[int | None, int | None, tuple | None]:
        info = self.objinfo.get(o)
        if info is None or off is None or info.kind in ("param", "input"):
            return None, None, None
        if info.cap_hi is None and info.cap_lin is None:
            return None, None, None
        lo = None if info.cap_lo is None else info.cap_lo - off
        hi = None if info.cap_hi is None else info.cap_hi - off
        lin = None if info.cap_lin is None else (info.cap_lin[0], info.cap_lin[1], info.cap_lin[2] - off)
        return lo, hi, lin

    def _mark_safe(self, dst: AV, need_hi: int | None, line: int) -> None:
        """Tüm hedeflerde yazılabilecek en çok bayt ≤ kullanılabilir alan: satır kanıtlanmış güvenli (desen kuralı için)."""
        if need_hi is None or not dst.ptrs:
            return
        for o, off in dst.ptrs:
            info = self.objinfo.get(o)
            if info is None or off is None or off < 0 or info.kind not in ("stack", "static", "heap", "field"):
                return
            a_lo, a_hi, _ = self.avail(o, off)
            if a_lo is None or need_hi > a_lo:
                return
        self.sink.safe.add(line)

    def _report_write(self, dst: AV, need_lo: int | None, need_lin: tuple | None, tnt: Taint | None,
                      tnt_need_hi: int | None, line: int, fn: str, what: str, *, unbounded_taint: bool = False,
                      nterm_es: int = 1) -> None:
        """Hedef tampona en az need_lo bayt yazılıyor (kesin); kirli içerikte en çok tnt_need_hi (None: sınırsız)."""
        n = len(dst.ptrs)
        for o, off in dst.ptrs:
            info = self.objinfo.get(o)
            if info is None:
                continue
            if info.kind == "param":
                continue
            bname = dst.name or info.name
            if off is not None and off < 0 and info.kind not in ("param", "input", "scalar"):
                self.report("underwrite", line, n == 1, info,
                            f"{fn}: `{bname}` hedefi tampon başından {-off} bayt önce başlıyor")
                continue
            a_lo, a_hi, a_lin = self.avail(o, off)
            if a_hi is None and a_lin is None:
                continue
            if need_lo is not None and a_hi is not None and need_lo > a_hi:
                over = need_lo - a_hi
                kind = "off_by_one" if over == nterm_es and not fn.startswith(("mem", "wmem")) else "overflow"
                self.report(kind, line, n == 1, info,
                            f"{fn}: `{bname}` tamponuna en az {need_lo} bayt yazılıyor; tampon {a_hi} bayt{what}")
                continue
            if need_lin is not None and a_lin is not None and need_lin[0] == a_lin[0] and \
                    ((need_lin[1] == a_lin[1] and need_lin[2] > a_lin[2]) or
                     (need_lin[1] > a_lin[1] and need_lin[2] >= a_lin[2])):
                over = need_lin[2] - a_lin[2]
                kind = "off_by_one" if need_lin[1] == a_lin[1] and over == nterm_es and fn in _UNBOUNDED_CPY else "overflow"
                self.report(kind, line, n == 1, info,
                            f"{fn}: `{bname}` tamponu {_lin_text(a_lin)} bayt; yazılan {_lin_text(need_lin)} bayt{what}")
                continue
            if tnt is not None and a_hi is not None and (tnt_need_hi is None or tnt_need_hi > a_hi):
                if info.kind == "heap" and (a_lo is None or a_lo != a_hi):
                    continue
                self.report("overflow_taint", line, n == 1 and (tnt_need_hi is not None or tnt.exact), info,
                            f"{_LABELS.get(tnt.label, tnt.label)} (satır {tnt.line}) {fn} ile {a_hi} baytlık `{bname}` "
                            f"tamponuna {'sınırsız' if tnt_need_hi is None else f'en çok {tnt_need_hi} bayt'} kopyalanıyor{what}",
                            source=tnt)

    def copy_op(self, dst: AV, src: AV, line: int, fn: str, cat: bool, es: int) -> None:
        self.use(dst, line, "copy")
        self.use(src, line, "copy")
        lo, hi, tnt = self.content(src)
        self._src_underread(src, line, fn)
        es = dst.es or es if es == 1 else es
        dlo, dhi = 0, 0
        if cat:
            dl, dh, dt = self.content(dst)
            dlo = dl or 0
            dhi = dh
            tnt = tnt or dt
        need_lo = None if lo is None else (dlo + lo + 1) * es
        need_hi = None if hi is None or (cat and dhi is None) else ((dhi or 0) + hi + 1) * es
        need_lin = None
        skey = src.name or (self._argtexts[1] if len(self._argtexts) > 1 else "")
        if skey and not cat:
            need_lin = ("strlen:" + skey, 1, 1)
        if tnt is not None and ("len:" + skey) in self.st.checked:
            tnt = None
        if lo is not None and lo == 0 and hi is not None and hi == 0 and not cat:
            need_lo = es
        self._report_write(dst, need_lo, need_lin, tnt if (hi is None or tnt is not None) else None,
                           need_hi, line, fn, "", nterm_es=es)
        self._mark_safe(dst, need_hi, line)
        # özet: parametreden sabit yerel tampona kopya
        if self.summary_mode:
            p = self._param_of(src)
            if p is not None and tnt is None:
                for o, off in dst.ptrs:
                    a_lo, a_hi, _ = self.avail(o, off)
                    info = self.objinfo.get(o)
                    if a_hi is not None and info is not None and info.kind in ("stack", "static", "field"):
                        if not any(x.kind == "src_into" and x.line == line for x in self.ops):
                            self.ops.append(Op("src_into", line, p, avail_lo=a_lo, avail_hi=a_hi, buffer=dst.name or info.name,
                                               buffer_line=info.line, extra=dlo + 1, es=es, func=self.f.name))
            pd = self._param_of(dst)
            if pd is not None and lo is not None and lo > 0 and not cat:
                if not any(x.kind == "write" and x.line == line for x in self.ops):
                    self.ops.append(Op("write", line, pd, need=(lo + 1) * es, func=self.f.name))
        for o, off in dst.ptrs:
            if off is None:
                self.set_cont(o, 0, None, keep_taint=True)  # konumu bilinmeyen yazma: uzunluk bilgisi kaybolur
                continue
            if cat:
                dl, dh, dt = self.content(AV(ptrs=frozenset({(o, off)})))
                if dl is None and dh is None and not self.obj_state(o)[5]:
                    self.set_cont(o, lo or 0, hi, tnt)
                else:
                    self.set_cont(o, (dl or 0) + (lo or 0), None if dh is None or hi is None else dh + hi, tnt)
            else:
                self.set_cont(o, lo or 0, hi, tnt)

    def _src_underread(self, src: AV, line: int, fn: str) -> None:
        for o, off in src.ptrs:
            info = self.objinfo.get(o)
            if info is not None and off is not None and off < 0 and info.kind not in ("param", "input", "scalar"):
                self.report("underread", line, len(src.ptrs) == 1, info,
                            f"{fn}: `{src.name or info.name}` kaynağı tampon başından {-off} bayt önce başlıyor")

    def ncopy_op(self, dst: AV, src: AV, nv: AV, line: int, fn: str, cat: bool, es: int) -> None:
        self.use(dst, line, "copy")
        self.use(src, line, "copy")
        self._src_underread(src, line, fn)
        lo, hi, tnt = self.content(src)
        if cat:
            dl, dh, dt = self.content(dst)
            # strncat: dst uzunluğu + min(n, strlen(src)) + 1
            dlo = dl or 0
            if nv.lo is not None:
                copied_lo = nv.lo if lo is None else min(nv.lo, lo)
                if lo is None and tnt is None:
                    copied_lo = 0
                need_lo = (dlo + copied_lo + 1) * es
                if copied_lo > 0 or dlo > 0:
                    self._report_write(dst, need_lo, None, None, None, line, fn,
                                       f" (strncat sınırı {nv.lo}, mevcut uzunluk {dlo})", nterm_es=es)
                elif nv.lo is not None:
                    # strncat(buf, s, sizeof buf): kalan alan yerine toplam boyut — klasik off-by-one
                    for o, off in dst.ptrs:
                        a_lo, a_hi, _ = self.avail(o, off)
                        info = self.objinfo.get(o)
                        if a_hi is not None and info is not None and nv.lo * es >= a_hi and tnt is not None:
                            self.report("off_by_one", line, len(dst.ptrs) == 1, info,
                                        f"{fn} sınırı {nv.lo}: `{dst.name or info.name}` ({a_hi} bayt) için kalan alan "
                                        f"ve sonlandırıcı hesaba katılmamış", source=tnt)
            for o, off in dst.ptrs:
                if off is not None:
                    self.set_cont(o, dlo, None, tnt or dt)
            return
        # strncpy: tam n bayt yazar
        need_lo = None if nv.lo is None else nv.lo * es
        need_lin = None if nv.lin is None else (nv.lin[0], nv.lin[1] * es, nv.lin[2] * es)
        self._report_write(dst, need_lo, need_lin, None, None, line, fn, "", nterm_es=es)
        if nv.it is not None and "len:" + (src.name or "") not in self.st.checked and nv.name not in self.st.checked:
            pass
        if self.summary_mode:
            pd = self._param_of(dst)
            if pd is not None:
                if nv.pv >= 0:
                    if not any(x.kind == "write" and x.line == line for x in self.ops):
                        self.ops.append(Op("write", line, pd, param2=nv.pv, es=es, func=self.f.name))
                elif nv.lo is not None:
                    if not any(x.kind == "write" and x.line == line for x in self.ops):
                        self.ops.append(Op("write", line, pd, need=nv.lo * es, func=self.f.name))
        nhi = nv.hi
        for o, off in dst.ptrs:
            if off is None:
                self.set_cont(o, 0, None, keep_taint=True)  # konumu bilinmeyen yazma: uzunluk bilgisi kaybolur
                continue
            if lo is not None and nv.hi is not None and hi is not None and hi < nv.lo if nv.lo is not None else False:
                self.set_cont(o, lo, hi, tnt)
            else:
                self.set_cont(o, 0 if lo is None or nv.lo is None else min(lo, nv.lo),
                              None if nhi is None or hi is None or hi >= (nv.lo or 0) else min(hi, nhi), tnt)

    def sized_write(self, dst: AV, nv: AV, line: int, fn: str, es: int, elems: bool) -> None:
        self.use(dst, line, "copy")
        need_lo = None if nv.lo is None else nv.lo * es
        self._report_write(dst, need_lo, nv.lin if es == 1 else None, None, None, line, fn, " (boyut argümanı tampondan büyük)",
                           nterm_es=-1)
        if self.summary_mode:
            pd = self._param_of(dst)
            if pd is not None and nv.pv >= 0:
                if not any(x.kind == "write" and x.line == line for x in self.ops):
                    self.ops.append(Op("write", line, pd, param2=nv.pv, es=es, func=self.f.name))

    def memcpy_op(self, dst: AV, src: AV, nv: AV, line: int, fn: str, es: int) -> None:
        self.use(dst, line, "copy")
        self.use(src, line, "copy")
        need_lo = None if nv.lo is None else nv.lo * es
        need_lin = None if nv.lin is None else (nv.lin[0], nv.lin[1] * es, nv.lin[2] * es)
        self._report_write(dst, need_lo, need_lin, None, None, line, fn, "", nterm_es=-1)
        # kaynak sınır ötesi okuma
        for o, off in src.ptrs:
            info = self.objinfo.get(o)
            a_lo, a_hi, a_lin = self.avail(o, off)
            if info is None or info.kind in ("literal", "field", "param", "input"):
                continue  # dizgi değişmezi genişliği (L"..") bilinmez; yapı alanları arası kopya yaygın deyim
            if a_hi is not None and need_lo is not None and need_lo > a_hi and info is not None:
                self.report("overread", line, len(src.ptrs) == 1, info,
                            f"{fn}: `{src.name or info.name}` kaynağından {need_lo} bayt okunuyor; kaynak {a_hi} bayt")
            elif off is not None and off < 0 and info is not None:
                self.report("underread", line, len(src.ptrs) == 1, info,
                            f"{fn}: `{src.name or info.name}` kaynağı tampon başından {-off} bayt önce başlıyor")
        for o, off in dst.ptrs:
            if off is not None and off < 0:
                info = self.objinfo.get(o)
                if info is not None:
                    self.report("underwrite", line, len(dst.ptrs) == 1, info,
                                f"{fn}: `{dst.name or info.name}` hedefi tampon başından {-off} bayt önce başlıyor")
        # kirli uzunluk (denetimsiz)
        if nv.it is not None and not self._checked(nv):
            for o, off in dst.ptrs:
                a_lo, a_hi, _ = self.avail(o, off)
                info = self.objinfo.get(o)
                if a_hi is not None and info is not None and (nv.hi is None or nv.hi * es > a_hi):
                    self.report("overflow_taint", line, len(dst.ptrs) == 1, info,
                                f"{fn}: kopyalama uzunluğu {_LABELS.get(nv.it.label, nv.it.label)} (satır {nv.it.line}) "
                                f"kaynaklı ve denetlenmiyor; `{dst.name or info.name}` {a_hi} bayt", source=nv.it)
        if self.summary_mode:
            pd = self._param_of(dst)
            if pd is not None and nv.pv >= 0 and not any(x.kind == "write" and x.line == line for x in self.ops):
                self.ops.append(Op("write", line, pd, param2=nv.pv, es=es, func=self.f.name))
            elif pd is not None and nv.lo is not None and nv.lo > 0 and not any(x.kind == "write" and x.line == line for x in self.ops):
                self.ops.append(Op("write", line, pd, need=nv.lo * es, func=self.f.name))
        lo, hi, tnt = self.content(src)
        for o, off in dst.ptrs:
            if off is None:
                self.set_cont(o, 0, None, keep_taint=True)  # konumu bilinmeyen yazma: uzunluk bilgisi kaybolur
                continue
            if lo is not None and nv.lo is not None and hi is not None and nv.lo > hi * es:
                self.set_cont(o, lo, hi, tnt)
            else:
                self.set_cont(o, 0, None, tnt)

    def memset_op(self, dst: AV, cv: AV, nv: AV, line: int, fn: str, es: int) -> None:
        self.use(dst, line, "copy")
        need_lo = None if nv.lo is None else nv.lo * es
        self._report_write(dst, need_lo, nv.lin if es == 1 else None, None, None, line, fn, "", nterm_es=-1)
        if self.summary_mode:
            pd = self._param_of(dst)
            if pd is not None and nv.pv >= 0 and not any(x.kind == "write" and x.line == line for x in self.ops):
                self.ops.append(Op("write", line, pd, param2=nv.pv, es=es, func=self.f.name))
        c = cv.exact()
        if c is None and cv.lo is not None and cv.lo > 0:
            c = cv.lo
        for o, off in dst.ptrs:
            if off is None or off != 0:
                if c != 0:
                    self.set_cont(o, 0, None, keep_taint=True)
                continue
            info = self.objinfo.get(o)
            ees = (dst.es or (info.es if info else 1)) or 1
            if c == 0:
                self.set_cont(o, 0, 0)
            elif c is not None and nv.lo is not None and nv.lo == nv.hi:
                n_el = nv.lo * es // ees if ees else nv.lo
                s = self.obj_state(o)
                if s[5] and s[3] is not None and s[3] <= n_el and s[2] == s[3] and False:
                    pass
                self.set_cont(o, n_el, None)
            else:
                self.set_cont(o, 0, None)

    def fmt_out_len(self, fmt_s: str, avs: list[AV], argi: int, line: int) -> tuple[int, int | None, Taint | None, bool]:
        """Biçim dizgesinin üreteceği çıktı uzunluğu (sonlandırıcısız): (alt, üst|None, kirlilik, bilinmeyen %s var mı)."""
        lo_total = 0
        hi_total: int | None = 0
        tnt = None
        unknown = False
        lit = len(fmt_s)
        for m in _PRINTF_CONV.finditer(fmt_s):
            lit -= len(m.group(0))
            if m.group(0) == "%%":
                lit += 1
                continue
            width, prec, conv = m.group(2), m.group(3), m.group(5)
            if width == "*":
                argi += 1
            if prec == "*":
                argi += 1
            a = avs[argi] if argi < len(avs) else UNK
            argi += 1
            w = int(width) if width and width.isdigit() else 0
            if conv == "s":
                lo, hi, t = self.content(a)
                self.use(a, line, "copy")
                if prec and prec.isdigit():
                    p_ = int(prec)
                    lo = None if lo is None else min(lo, p_)
                    hi = p_ if hi is None else min(hi, p_)
                if lo is None:
                    unknown = True
                    lo = 0
                lo_total += max(lo, w)
                hi_total = None if hi is None or hi_total is None else hi_total + max(hi, w)
                tnt = tnt or t
            elif conv == "c":
                lo_total += max(1, w)
                hi_total = None if hi_total is None else hi_total + max(1, w)
            elif conv in "diouxX":
                e = a.exact()
                k = len(str(e)) if e is not None else 1
                lo_total += max(k, w)
                hi_total = None if hi_total is None else hi_total + max(k if e is not None else 20, w)
            else:
                lo_total += max(1, w)
                hi_total = None if hi_total is None else hi_total + max(24, w)
        lo_total += lit
        if hi_total is not None:
            hi_total += lit
        return lo_total, hi_total, tnt, unknown

    def sprintf_op(self, avs: list[AV], line: int, fn: str) -> None:
        dst, fmt = avs[0], avs[1]
        self.use(dst, line, "copy")
        if fmt.s is None:
            return
        lo_total, hi_total, tnt, unknown = self.fmt_out_len(fmt.s, avs, 2, line)
        need_hi = None if hi_total is None else hi_total + 1
        self._report_write(dst, lo_total + 1 if not unknown or lo_total > 0 else None, None, tnt, need_hi, line, fn, "",
                           nterm_es=-1)
        self._mark_safe(dst, need_hi, line)
        for o, off in dst.ptrs:
            if off is not None:
                self.set_cont(o, lo_total, hi_total, tnt)
            else:
                self.set_cont(o, 0, None, keep_taint=True)

    def snprintf_op(self, avs: list[AV], line: int, fn: str, es: int) -> None:
        dst, nv = avs[0], avs[1]
        self.use(dst, line, "copy")
        fmt = avs[2]
        out_lo, out_hi, tnt = 0, None, None
        if fmt.s is not None:
            out_lo, out_hi, tnt, _unk = self.fmt_out_len(fmt.s, avs, 3, line)
        else:
            for a in avs[3:]:
                tnt = tnt or self.content(a)[2]
        if nv.lo is not None:
            n_lo = nv.lo * es
            for o, off in dst.ptrs:
                info = self.objinfo.get(o)
                if info is None or info.kind in ("param", "input", "scalar"):
                    continue
                a_lo, a_hi, _ = self.avail(o, off)
                if a_hi is None or n_lo <= a_hi:
                    continue
                written_lo = min(n_lo, (out_lo + 1) * es)
                if written_lo > a_hi:
                    self.report("overflow", line, len(dst.ptrs) == 1, info,
                                f"{fn}: boyut argümanı {n_lo} bayt, `{dst.name or info.name}` {a_hi} bayt; "
                                f"en az {written_lo} bayt yazılıyor")
                elif out_hi is None or (out_hi + 1) * es > a_hi:
                    self.report("overflow", line, False, info,
                                f"{fn}: boyut argümanı ({n_lo} bayt) `{dst.name or info.name}` tamponundan ({a_hi} bayt) büyük")
        if self.summary_mode:
            pd = self._param_of(dst)
            if pd is not None and nv.pv >= 0:
                if not any(x.kind == "write" and x.line == line for x in self.ops):
                    self.ops.append(Op("write", line, pd, param2=nv.pv, es=es, func=self.f.name))
        nh = nv.hi
        for o, off in dst.ptrs:
            hi = None if nh is None else max(0, nh - 1)
            if out_hi is not None:
                hi = out_hi if hi is None else min(hi, out_hi)
            lo = out_lo if nv.lo is not None and out_lo < nv.lo else 0
            self.set_cont(o, lo, hi, tnt)

    def input_write(self, dst: AV, nv: AV | None, line: int, tnt: Taint, *, unbounded: bool, fn: str, es: int,
                    elems: bool = False, raw: bool = False) -> None:
        self.use(dst, line, "copy")
        if unbounded:
            for o, off in dst.ptrs:
                info = self.objinfo.get(o)
                a_lo, a_hi, _ = self.avail(o, off)
                if info is not None and a_hi is not None:
                    self.report("overflow_taint", line, len(dst.ptrs) == 1, info,
                                f"{fn}() uzunluk sınırı olmadan {_LABELS.get(tnt.label, tnt.label)} okuyor; `{dst.name or info.name}` "
                                f"{a_hi} bayt", source=tnt)
                self.set_cont(o, 0, None, tnt)
            return
        need_lo = None
        if nv is not None and nv.lo is not None:
            need_lo = nv.lo * es
        self._report_write(dst, need_lo, nv.lin if (nv is not None and es == 1) else None, None, None, line, fn,
                           " (okuma uzunluğu tampondan büyük)", nterm_es=-1)
        if nv is not None and nv.it is not None and not self._checked(nv):
            for o, off in dst.ptrs:
                a_lo, a_hi, _ = self.avail(o, off)
                info = self.objinfo.get(o)
                if a_hi is not None and info is not None:
                    self.report("overflow_taint", line, len(dst.ptrs) == 1, info,
                                f"{fn}: okuma uzunluğu {_LABELS.get(nv.it.label, nv.it.label)} (satır {nv.it.line}) kaynaklı "
                                f"ve denetlenmiyor; `{dst.name or info.name}` {a_hi} bayt", source=nv.it)
        if self.summary_mode:
            pd = self._param_of(dst)
            if pd is not None and nv is not None and nv.pv >= 0 and not any(x.kind == "write" and x.line == line for x in self.ops):
                self.ops.append(Op("write", line, pd, param2=nv.pv, es=es, func=self.f.name))
        for o, off in dst.ptrs:
            if off is None:
                self.set_cont(o, 0, None, keep_taint=True)  # konumu bilinmeyen yazma: uzunluk bilgisi kaybolur
                continue
            if raw:
                self.set_cont(o, 0, None, tnt)
            else:
                hi = None if nv is None or nv.hi is None else max(0, nv.hi - 1)
                self.set_cont(o, 0, hi, tnt)

    def scanf(self, fn: str, args, avs: list[AV], line: int) -> None:
        src_i, fmt_i = _SCANF[fn]
        if fmt_i >= len(avs):
            return
        fmt = avs[fmt_i].s
        if fmt is None:
            return
        if src_i is None:
            label = "stdin"
        elif fn.startswith(("sscanf", "swscanf", "__isoc99_sscanf", "vsscanf")):
            label = None
        else:
            label = "stdin" if self._is_stdin(args[src_i]) else "file"
        src_t = None
        src_hi = None
        if label is None and src_i is not None:
            lo, hi, src_t = self.content(avs[src_i])
            src_hi = hi
        tnt = Taint(label, line, fn) if label else src_t
        argi = fmt_i + 1
        for m in _SCANF_CONV.finditer(fmt):
            star, width, length, conv = m.groups()
            if conv == "%":
                continue
            if star:
                continue
            a = avs[argi] if argi < len(avs) else UNK
            argi += 1
            if conv in ("s", "["):
                w = int(width) if width else None
                es = 4 if length == "l" else 1
                if length == "m":
                    continue
                for o, off in a.ptrs:
                    info = self.objinfo.get(o)
                    a_lo, a_hi, _ = self.avail(o, off)
                    if info is None or a_hi is None:
                        self.set_cont(o, 0, None if w is None else w, tnt)
                        continue
                    if w is not None and (w + 1) * es > a_hi:
                        self.report("off_by_one" if (w + 1) * es - a_hi == es else "overflow", line, len(a.ptrs) == 1, info,
                                    f"{fn} %{w}{conv}: {w + 1} bayt yazılabilir; `{a.name or info.name}` {a_hi} bayt")
                    elif w is None:
                        if tnt is not None or label is not None:
                            if src_hi is not None and label is None and (src_hi + 1) * es <= a_hi:
                                pass
                            else:
                                self.report("overflow_taint", line, len(a.ptrs) == 1, info,
                                            f"{fn} genişliksiz %{conv}: {_LABELS.get(tnt.label, tnt.label) if tnt else 'girdi'} "
                                            f"`{a.name or info.name}` ({a_hi} bayt) tamponuna sınırsız okunuyor",
                                            source=tnt or Taint("stdin", line, fn))
                    self.set_cont(o, 0, None if w is None else w, tnt)
            elif conv in "diouxX" and a.name and a.name.startswith("&"):
                vn = a.name[1:]
                s = self.st.vars.get(vn, (frozenset(), None, None, None, None, -1))
                self.st.vars[vn] = (s[0], None, None, None, tnt, -1)
                if vn in self.st.checked:
                    self.st.checked = self.st.checked - {vn}
            elif conv == "c":
                pass

    def fmt_check(self, fn: str, args, avs: list[AV], line: int, idx: int) -> None:
        if idx >= len(avs):
            return
        f = avs[idx]
        if f.s is not None:
            return
        self.use(f, line, "call")
        lo, hi, tnt = self.content(f)
        if tnt is not None:
            self.report("format", line, True, None,
                        f"{fn}: biçim argümanı {_LABELS.get(tnt.label, tnt.label)} (satır {tnt.line}) içeriği",
                        source=tnt)
            return
        if self.summary_mode:
            p = self._param_of(f)
            if p is not None:
                if not any(x.kind == "fmt" and x.line == line for x in self.ops):
                    self.ops.append(Op("fmt", line, p, func=self.f.name))

    def _checked(self, v: AV) -> bool:
        names = set()
        if v.name:
            names.add(v.name)
        if v.mulv:
            names |= {m.lstrip("+") for m in v.mulv}
        if v.lenof:
            names.add("len:" + v.lenof)
        return bool(names & self.st.checked)

    # -- ayırma ----------------------------------------------------------------------
    def alloc(self, sz: AV, line: int, kind: str) -> AV:
        key = self.heap_key(line)
        lin = sz.lin
        self.new_obj(key, ObjInfo("malloc()" if kind != "alloca" else "alloca()", "heap" if kind != "alloca" else "stack",
                                  sz.lo, sz.hi, lin, 1, line, kind))
        return AV(ptrs=frozenset({(key, 0)}), es=None)

    def check_alloc_size(self, sz: AV, es: int, line: int, fn: str, count_mode: bool = False) -> None:
        """Ayırma boyutu: dış girdili sayı × sabit (denetimsiz) ya da sabit çarpımın 32 bit taşması."""
        names = [m for m in (sz.mulv or ()) if not m.startswith("+")]
        if count_mode and sz.name:
            names.append(sz.name)
        tainted = None
        if sz.it is not None:
            for nm in names or ([sz.name] if sz.name else []):
                if nm and nm not in self.st.checked:
                    tainted = nm
                    break
            if not names and not sz.name and sz.mulv is None and not count_mode:
                tainted = None
        if tainted is not None and (names or count_mode):
            self.report("alloc_overflow", line, True, None,
                        f"{fn}: ayırma boyutu {_LABELS.get(sz.it.label, sz.it.label)} (satır {sz.it.line}) kaynaklı `{tainted}` "
                        f"ile çarpılıyor ve üst sınır denetlenmiyor", source=sz.it)
            return
        if sz.chk:
            self.report("alloc_overflow", line, False, None,
                        f"{fn}: sabit ayırma boyutu çarpımı 32 bit tamsayı sınırını aşıyor ({sz.chk})")
        elif count_mode and sz.exact() is not None and es and sz.exact() * es > INT32_MAX and sz.exact() <= INT32_MAX:
            self.report("alloc_overflow", line, False, None,
                        f"{fn}: {sz.exact()} eleman × {es} bayt 32 bit tamsayı sınırını aşıyor")

    # -- raporlama ---------------------------------------------------------------------
    def report(self, kind: str, line: int, certain: bool, info: ObjInfo | None, detail: str, *,
               source: Taint | None = None, write: bool = True, func: str = "", src_line: int = 0) -> None:
        if self.summary_mode is None:
            return
        if self.call_line and self.parent is not None:
            detail += f" [{self.parent.f.name}() satır {self.call_line} çağrısıyla]"
            src_line = src_line or self.call_line
        cwe = _CWE.get(kind)
        if kind == "overflow":
            cwe = "CWE-121" if info is not None and info.kind == "stack" else "CWE-122" if info is not None and info.kind == "heap" else "CWE-787"
        if source is not None and source.weak:
            certain = False
        src_file = ""
        if source is not None and source.file and source.file != self.fm.path:
            src_file = source.file
            detail = detail.replace(f"(satır {source.line})", f"({src_file} satır {source.line})", 1)
        self.sink.add(MemFinding(
            kind=kind, cwe=cwe or "CWE-787", line=line, certain=certain, severity="",
            title=title_for(kind, certain), evidence=detail, function=func or self.f.name,
            buffer=(info.name if info else ""), buffer_line=(info.line if info else 0),
            capacity=("" if info is None or info.cap_hi is None else f"{info.cap_hi} bayt"),
            source=(source.desc if source else ""), source_line=(source.line if source else src_line),
            source_file=src_file, chain=(source.chain if source is not None else ()),
        ))


def _mul_overflow_const(a: AV, b: AV) -> str | None:
    ea, eb = a.exact(), b.exact()
    if ea is None or eb is None:
        return None
    if a.name is None and b.name is None:
        return None
    p = ea * eb
    if p > INT32_MAX and abs(ea) <= INT32_MAX and abs(eb) <= INT32_MAX and min(ea, eb) >= 0:
        return f"{ea} × {eb}"
    return None


def _nobj(ptrs) -> int:
    return len({o for o, _ in ptrs})


def _copy_av(v: AV) -> AV:
    return AV(v.lo, v.hi, v.lin, v.ptrs, v.it, v.lv, v.s, v.es, v.pv, v.lenof, v.mulv, v.idx, v.name, v.chk)


def _join_av(a: AV, b: AV) -> AV:
    return AV(lo=None if a.lo is None or b.lo is None else min(a.lo, b.lo),
              hi=None if a.hi is None or b.hi is None else max(a.hi, b.hi),
              ptrs=a.ptrs | b.ptrs, it=a.it or b.it, es=a.es if a.es == b.es else None)


def _lin_text(lin: tuple) -> str:
    key, m, k = lin
    base = key.split(":", 1)[1] if ":" in key else key
    expr = f"strlen({base})" if key.startswith("strlen:") else f"sizeof({base})" if key.startswith("sizeof:") else base
    if m != 1:
        expr = f"{m} × {expr}"
    return expr if k == 0 else f"{expr} {'+' if k > 0 else '-'} {abs(k)}"


# ---------------------------------------------------------------------------
# Toplayıcı ve giriş noktaları
# ---------------------------------------------------------------------------
class Sink:
    def __init__(self, fm: FileModel):
        self.fm = fm
        self.findings: dict[tuple[str, int], MemFinding] = {}
        self.summaries = fm.summaries
        self.frees = fm.frees
        self.deref_frees = fm.deref_frees
        self.deref_nulls = fm.deref_nulls
        self.puses: dict[str, set[int]] = {}
        self.safe: set[int] = set()
        self.unsafe: set[int] = set()
        self.collect = True

    def add(self, f: MemFinding) -> None:
        self.unsafe.add(f.line)
        if not self.collect:
            return
        key = (f.kind, f.line)
        old = self.findings.get(key)
        if old is None or (f.certain and not old.certain):
            self.findings[key] = f


def _remote_source(f: MemFinding) -> bool:
    return bool(f.source) and (f.source.startswith(("recv", "SSL", "BIO")) or f.source.startswith(
        ("ağdan okunan", "HTTP", "CGI", "libmicrohttpd", "mongoose", "ulfius", "onion", "FastCGI")))


def _severity(f: MemFinding) -> str:
    if f.kind == "format":
        return "high" if _remote_source(f) else "medium" if f.certain else "low"
    if not f.certain:
        return "medium" if f.kind in ("uaf", "double_free", "overflow", "overflow_taint", "off_by_one") else "low"
    if f.kind in ("overflow_taint",) and (f.source in ("recv", "recvfrom", "SSL_read", "BIO_read") or _remote_source(f)):
        return "critical"
    if f.kind in ("free_nonheap", "free_offset", "mismatch_free", "overread", "underread", "alloc_overflow"):
        return "medium" if f.kind != "alloc_overflow" else "high"
    return "high"


def analyze_text(text: str, path: str, *, deadline: float | None = None,
                 headers: Iterable[tuple[str, str]] = (), facts: dict[str, Any] | None = None) -> list[MemFinding]:
    """Tek C/C++ dosyası → bellek güvenliği bulguları (satıra göre sıralı)."""
    return analyze_text_ex(text, path, deadline=deadline, headers=headers, facts=facts)[0]


_HEADER_CACHE: dict[tuple[str, int, int], FileModel] = {}
INCLUDE_RE = re.compile(r'(?m)^[ \t]*#[ \t]*include[ \t]*"([^"]+)"')


def header_model(path: str, text: str) -> FileModel | None:
    """Proje başlık dosyasının makro/typedef/yapı/sabit modeli (fonksiyon gövdeleri hariç; önbellekli)."""
    key = (path, len(text), hash(text))
    fm = _HEADER_CACHE.get(key)
    if fm is not None:
        return fm
    if len(text) > MAX_FILE_BYTES:
        return None
    try:
        unit = cf.build_unit(path, text)
        fm = FileModel(path, unit, _collect_defines(text))
        _collect_file_model(fm)
    except (RecursionError, IndexError, ValueError):
        return None
    if len(_HEADER_CACHE) > 512:
        _HEADER_CACHE.clear()
    _HEADER_CACHE[key] = fm
    return fm


def _merge_header(fm: FileModel, hm: FileModel) -> None:
    for k, v in hm.defines.items():
        fm.defines.setdefault(k, v)
    for k, v in hm.typedefs.items():
        fm.typedefs.setdefault(k, v)
    for k, v in hm.structs.items():
        fm.structs.setdefault(k, v)
    for k, v in hm.struct_sizes.items():
        if fm.struct_sizes.get(k) is None:
            fm.struct_sizes[k] = v
    fm.unions |= hm.unions
    for k, v in hm.consts.items():
        fm.consts.setdefault(k, v)
    for k, v in hm.globals_.items():
        fm.globals_.setdefault(k, v)


def _run_guarded(fm: FileModel, f: Any, sink: Sink) -> None:
    """Fonksiyon çözümlemesi; beklenmeyen bir ayrıştırma durumu yalnız o fonksiyonu atlatır (dosya analizi sürer)."""
    try:
        FuncAnalyzer(fm, f, sink).run()
    except (TypeError, KeyError, AttributeError, ValueError, IndexError, ZeroDivisionError):
        return


def analyze_text_ex(text: str, path: str, *, deadline: float | None = None,
                    headers: Iterable[tuple[str, str]] = (), facts: dict[str, Any] | ModelFacts | None = None,
                    ) -> tuple[list[MemFinding], set[int]]:
    """Bulgular ve kanıtlanmış güvenli kopyalama satırları (hedef boyutu ve yazılan uzunluk üst sınırı bilinen).
    ``headers``: dosyanın ``#include "..."`` ettiği proje başlıkları (yol, metin) — makro/yapı/typedef tanımları."""
    if len(text) > MAX_FILE_BYTES:
        return [], set()
    started = time.monotonic()
    deadline = deadline if deadline is not None else started + FILE_BUDGET_S
    try:
        unit = cf.build_unit(path, text)
    except (RecursionError, IndexError, ValueError):
        return [], set()
    fm = FileModel(path, unit, _collect_defines(text))
    if facts:
        fm.facts = facts if isinstance(facts, ModelFacts) else ModelFacts(facts)
    hms = []
    for hpath, htext in headers:
        hm = header_model(hpath, htext)
        if hm is not None:
            hms.append(hm)
            for k, v in hm.typedefs.items():
                fm.typedefs.setdefault(k, v)
            for k, v in hm.defines.items():
                fm.defines.setdefault(k, v)
    try:
        _collect_file_model(fm)
    except (RecursionError, IndexError, ValueError):
        pass
    for hm in hms:
        _merge_header(fm, hm)
    funcs = [f for f in unit.funcs if f.body[1] - f.body[0] <= MAX_FUNC_TOKENS]
    for f in funcs:
        fm.funcs.setdefault(f.name, f)
    sink = Sink(fm)
    # 1. geçiş: tüm fonksiyonlar (özetler + yerel bulgular)
    for f in funcs:
        if time.monotonic() > deadline:
            break
        _run_guarded(fm, f, sink)
    # 2. geçiş: özeti dolu fonksiyonları çağıranlar yeniden (zincir: 2 tur)
    for _round in range(2):
        active = ({name for name, ops in fm.summaries.items() if ops}
                  | {name for name, fr in fm.frees.items() if fr}
                  | {name for name, fr in fm.deref_frees.items() if fr}
                  | {name for name, ns in fm.deref_nulls.items() if ns})
        if not active:
            break
        changed = False
        for f in funcs:
            if time.monotonic() > deadline:
                break
            lo, hi = f.body
            calls = False
            toks = unit.toks
            for q in range(lo, hi):
                if toks[q].kind == "id" and toks[q].text in active and q + 1 < hi and toks[q + 1].text == "(":
                    calls = True
                    break
            if not calls:
                continue
            before = (len(fm.summaries.get(f.name, ())), len(fm.frees.get(f.name, {})),
                      len(fm.deref_frees.get(f.name, {})), len(fm.deref_nulls.get(f.name, ())))
            _run_guarded(fm, f, sink)
            after = (len(fm.summaries.get(f.name, ())), len(fm.frees.get(f.name, {})),
                     len(fm.deref_frees.get(f.name, {})), len(fm.deref_nulls.get(f.name, ())))
            changed = changed or before != after
        if not changed:
            break
    if fm.facts is not None:
        for d in fm.facts.dangling:
            if d.file != path:
                continue
            where = d.free_file if d.free_file != path else ""
            detail = (f"`{d.slot}` {d.free_func}() içinde serbest bırakılıyor ({where + ' ' if where else ''}satır "
                      f"{d.free_line}) ama yuva NULL yapılmıyor/temizlenmiyor; {d.func}() bu yuvayı "
                      f"{'yeniden serbest bırakıyor' if d.kind == 'double_free' else 'kullanıyor'} (ortak çağıran: "
                      f"{d.dispatcher}()" + ("" if d.certain else "; aynı yuvaya ulaşıldığı kanıtlanamadı") + ")")
            sink.add(MemFinding(kind=d.kind, cwe=_CWE[d.kind], line=d.line, certain=d.certain, severity="",
                                title=title_for(d.kind, d.certain), evidence=detail, function=d.func,
                                source="free()", source_line=d.free_line, source_file=where,
                                chain=(f"{d.free_file}:{d.free_line} free ({d.free_func})",
                                       f"{d.file}:{d.line} {'free' if d.kind == 'double_free' else 'kullanım'} ({d.func})")))
    out = sorted(sink.findings.values(), key=lambda x: (x.line, x.kind))
    for f in out:
        f.severity = _severity(f)
    return out[:MAX_FINDINGS_PER_FILE], sink.safe - sink.unsafe


def is_c_family(path: str) -> bool:
    low = path.lower()
    return any(low.endswith(s) for s in SUFFIXES)
