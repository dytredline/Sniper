"""C/C++ hızlı taint motoru (saf Python, belirteç tabanlı; Joern gerektirmez).

Kaynaklar:
  * ağ (``request``): recv/recvfrom/SSL_read/BIO_read, soket adlı tanımlayıcıdan read()/pread(), CGI ortam değişkenleri
    (QUERY_STRING, REQUEST_URI, HTTP_*, …) ve CGI'da standart girdiden fread;
  * yerel (``local``): argv, getenv, stdin'den fgets/gets/scanf/getline, std::cin ve yerel dosya/tanımlayıcıdan
    read/pread/fgets/fread/fscanf ile std::ifstream çıkarma/getline/read. Yerel girdi yalnız bellek güvenliği ve biçim dizgesi hedeflerinde raporlanır
    (komut/yol hedeflerinde CLI aracının olağan davranışıdır).
Hedefler: komut (system/popen/exec*/spawn*/CreateProcess), biçim dizgesi (printf ailesi; biçim argümanı kirli),
bellek (strcpy/strcat/sprintf %s/gets/scanf %s; memcpy/strncpy uzunluğu; dizi indeksi — üst sınır denetimi yoksa),
SQL (sqlite3_exec/prepare, mysql_query, PQexec, SQLExecDirect), yol (fopen/open/ifstream…; yalnız ağ girdisi),
SSRF (curl_easy_setopt CURLOPT_URL), LDAP arama filtresi, CGI çıktısında XSS.
Önişlemci: _WIN32/_MSC_VER dalları kapalı, bilinmeyen koşullarda ilk dal; tek belirteçli nesne makroları yerine konur.
"""
from __future__ import annotations

import bisect
from pathlib import Path
import re
from typing import Any

import taint_native_core as core
from taint_native_core import EMPTY, BodyAnalyzer, Collector, FileUnit, Func, Origin, Param, Tok, compact, \
    match_close, numeric, split_args, strings_only
from taint_flow import Analysis

C_SUFFIXES = frozenset({".c", ".h"})
# Sabit nokta turu (alan duyarlı küresel kirlilik ve işlev işaretçisi zincirleri için Rust'tan bir fazla)
C_ROUNDS = 6
# Bir kökenin geçebileceği en çok yapı alanı yazımı (alan → alan → alan zincirleri büyük kod tabanlarında yanıltıcı)
MAX_FIELD_HOPS = 2
# A local function pointer may accumulate alternatives through conditional
# assignments.  Keep that union bounded before it can be copied through alias
# chains or passed to callback wrappers.
MAX_FUNCTION_ALIAS_CANDIDATES = 16
CPP_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp", ".inl"})
SUFFIXES = C_SUFFIXES | CPP_SUFFIXES

_KEYWORDS = frozenset("""if else for while do switch case default return break continue goto sizeof typeof
alignof _Alignof offsetof decltype typeid static_assert _Static_assert new delete throw try catch
struct union enum class namespace template typename using operator public private protected friend virtual
const volatile static extern inline register auto unsigned signed restrict __restrict __inline __attribute__
noexcept override final constexpr consteval constinit mutable explicit asm __asm__ defined""".split())

_FALSE_DEFINES = frozenset({"_WIN32", "WIN32", "_WIN64", "_MSC_VER", "__MINGW32__", "_WINDOWS", "__CYGWIN__",
                            "OS_WINDOWS", "__APPLE__", "__VMS", "__OS400__", "__amigaos4__", "MSDOS", "__DJGPP__"})

# --- kaynaklar ---
_CGI_REMOTE_ENV = re.compile(r"^(QUERY_STRING|REQUEST_URI|PATH_INFO|PATH_TRANSLATED|SCRIPT_NAME|CONTENT_TYPE|"
                             r"CONTENT_LENGTH|HTTP_[A-Z0-9_]+|REQUEST_METHOD|REMOTE_USER|AUTH_TYPE)$")
_RECV_OUT = {"recv": 1, "recvfrom": 1, "SSL_read": 1, "SSL_read_ex": 1, "SSL_peek": 1,
             "SSL_peek_ex": 1, "SSL_read_early_data": 1, "gnutls_record_recv": 1, "mbedtls_ssl_read": 1,
             "wolfSSL_read": 1, "wolfSSL_peek": 1, "wolfSSL_read_ex": 1, "wolfSSL_peek_ex": 1,
             "wolfSSL_read_early_data": 1, "wolfSSL_recv": 1,
             "mbedtls_ssl_read_early_data": 1, "gnutls_record_recv_early_data": 1, "gnutls_record_recv_seq": 1,
             "BIO_read": 1, "BIO_read_ex": 1, "BIO_gets": 1, "WSARecv": 1}
_SOCKISH = re.compile(r"(?i)sock|conn|client|peer|accept|remote|^comm|^cli_?fd$|^cfd$|^sd$|^new_?fd$|^nfd$|^acc_?fd$")
# Dönüşü bir soket tanımlayıcısı olan çağrılar: ``fd = accept(...)`` → read(fd, …) ağ girdisidir.
_SOCKET_CALLS = frozenset({"accept", "accept4", "WSAAccept", "socket"})
# Dönüşü ilk argümanın içini gösteren işaretçi olan çağrılar (işaretçi takma adı).
_PTR_INTO_ARG0 = frozenset({"strchr", "strrchr", "strstr", "strpbrk", "memchr", "memrchr", "index", "rindex",
                            "strcasestr", "strchrnul"})
# Okuma çağrıları: ad → (hedef tampon argümanı, uzunluk argümanları). Kirli sayısal uzunluk → memory_len.
_READ_LEN = {"read": (1, (2,)), "_read": (1, (2,)), "pread": (1, (2,)), "pread64": (1, (2,)),
             "recv": (1, (2,)), "recvfrom": (1, (2,)), "SSL_read": (1, (2,)), "SSL_read_ex": (1, (2,)),
             "SSL_peek": (1, (2,)), "SSL_peek_ex": (1, (2,)),
             "SSL_read_early_data": (1, (2,)), "gnutls_record_recv": (1, (2,)), "mbedtls_ssl_read": (1, (2,)),
             "wolfSSL_read": (1, (2,)), "wolfSSL_peek": (1, (2,)), "wolfSSL_read_ex": (1, (2,)),
             "wolfSSL_peek_ex": (1, (2,)), "wolfSSL_read_early_data": (1, (2,)), "wolfSSL_recv": (1, (2,)),
             "mbedtls_ssl_read_early_data": (1, (2,)), "gnutls_record_recv_early_data": (1, (2,)),
             "gnutls_record_recv_seq": (1, (2,)),
             "BIO_read": (1, (2,)), "BIO_read_ex": (1, (2,)), "fread": (0, (1, 2)),
             "BIO_gets": (1, (2,)),
             "fgets": (0, (1,)), "fgetws": (0, (1,))}
_SNPRINTF = frozenset({"snprintf", "_snprintf", "vsnprintf", "_vsnprintf", "_snwprintf", "_vsnwprintf"})
# Ham değeri tamsayıya taşıyan (çağrı sayılmayan) dönüşümler: ``uint16_t n = ntohs(h.len)``.
_RAW_OK_CALLS = frozenset({"ntohs", "ntohl", "be16toh", "be32toh", "be64toh", "le16toh", "le32toh", "le64toh",
                           "bswap_16", "bswap_32", "bswap_64", "__builtin_bswap16", "__builtin_bswap32",
                           "__builtin_bswap64", "sizeof"})
_INT_TYPE_RE = re.compile(r"\b(int|long|short|unsigned|signed|size_t|ssize_t|off_t|off64_t|socklen_t|u?int\d+_t|"
                          r"u_int\d+_t|__u\d+|__s\d+|__be\d+|__le\d+|u8|u16|u32|u64|s8|s16|s32|s64|uint|ushort|ulong|"
                          r"DWORD|WORD|BYTE|UINT|ULONG|USHORT|LONG|INT|SIZE_T|uint\d+|int\d+)\b")
_NOT_INT_RE = re.compile(r"\b(float|double|bool|_Bool|enum)\b")
# stdin'den okuyan ve çıkış argümanına yazan çağrılar: ad → (çıkış argümanı, akış argümanı)
_STDIN_OUT = {"fgets": (0, 2), "fgetws": (0, 2), "getline": (0, 2), "getdelim": (0, 3), "getwline": (0, 2)}
_NUM_CONV = frozenset({"atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof",
                       "strtold", "strtoimax", "strtoumax", "_wtoi", "_wtol", "_wtoi64", "_atoi64", "wcstol", "wcstoul",
                       "wcstoll", "wcstoull", "wcstod", "stoi", "stol", "stoll", "stoul", "stoull", "stof", "stod",
                       "ntohl", "ntohs", "be16toh", "be32toh", "be64toh", "le16toh", "le32toh", "le64toh"})
_CLEAN_CALLS = frozenset({"sizeof", "strlen", "wcslen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp",
                          "memcmp", "wcscmp", "isdigit", "isalpha", "isalnum", "isspace", "isupper", "islower",
                          "isxdigit", "isprint", "toupper", "tolower", "abs", "labs", "rand", "time", "fileno",
                          "PQescapeLiteral", "PQescapeIdentifier", "sqlite3_mprintf_q", "basename", "free", "close",
                          "fclose", "strchr", "strrchr", "strstr", "strspn", "strcspn", "memchr", "socket", "connect",
                          "bind", "listen", "accept", "htons", "htonl", "inet_addr", "inet_pton",
                          # 27. tur düzeltmesi: kütüphane kaçışlama işlevleri (çıktı tırnaklı/kodlanmış)
                          "g_shell_quote", "g_markup_escape_text", "curl_easy_escape", "curl_escape",
                          "g_uri_escape_string", "xmlEncodeSpecialChars", "xmlEncodeEntitiesReentrant"})

# --- hedefler ---
_SHELL_RE = re.compile(r"(?i)(^|[\\/])(sh|bash|zsh|dash|ksh|csh|cmd(\.exe)?|powershell(\.exe)?)$")
_SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command", "/k", "/K"})
_EXEC_L = {"execl": 0, "execlp": 0, "execle": 0, "_execl": 0, "_execlp": 0, "_wexecl": 0, "_wexeclp": 0,
           "_spawnl": 1, "_spawnlp": 1, "_wspawnl": 1, "_wspawnlp": 1}
_EXEC_V = {"execv": 0, "execvp": 0, "execve": 0, "execvpe": 0, "_execv": 0, "_execvp": 0, "_wexecv": 0, "_wexecvp": 0,
           "_spawnv": 1, "_spawnvp": 1, "_wspawnv": 1, "_wspawnvp": 1}
_CMD_DIRECT = {"system": 0, "_wsystem": 0, "popen": 0, "_popen": 0, "_wpopen": 0, "WinExec": 0,
               "CreateProcessA": 1, "CreateProcessW": 1, "CreateProcess": 1, "ShellExecuteA": 2, "ShellExecuteW": 2,
               "ShellExecute": 2}
# printf ailesi: ad → biçim argümanı dizini
_FMT = {"printf": 0, "vprintf": 0, "wprintf": 0, "vwprintf": 0, "fprintf": 1, "vfprintf": 1, "fwprintf": 1,
        "vfwprintf": 1, "dprintf": 1, "vdprintf": 1, "sprintf": 1, "vsprintf": 1, "swprintf": 2, "vswprintf": 2,
        "snprintf": 2, "vsnprintf": 2, "_snprintf": 2, "_vsnprintf": 2, "_snwprintf": 2, "_vsnwprintf": 2,
        "asprintf": 1, "vasprintf": 1, "syslog": 1, "vsyslog": 1, "err": 1, "errx": 1, "verr": 1, "verrx": 1,
        "warn": 0, "warnx": 0, "vwarn": 0, "vwarnx": 0, "printw": 0, "wsprintfA": 1, "wsprintfW": 1, "wsprintf": 1}
# sınırsız kopyalama: ad → (hedef, kaynak)
_UNBOUNDED_COPY = {"strcpy": (0, 1), "wcscpy": (0, 1), "_mbscpy": (0, 1), "lstrcpyA": (0, 1), "lstrcpyW": (0, 1),
                   "lstrcpy": (0, 1), "strcat": (0, 1), "wcscat": (0, 1), "_mbscat": (0, 1), "lstrcatA": (0, 1),
                   "lstrcatW": (0, 1), "lstrcat": (0, 1), "StrCpyA": (0, 1), "StrCatA": (0, 1), "stpcpy": (0, 1)}
# uzunluklu kopyalama: ad → (hedef, kaynak, uzunluk)
_BOUNDED_COPY = {"memcpy": (0, 1, 2), "memmove": (0, 1, 2), "wmemcpy": (0, 1, 2), "wmemmove": (0, 1, 2),
                 "strncpy": (0, 1, 2), "wcsncpy": (0, 1, 2), "strncat": (0, 1, 2), "wcsncat": (0, 1, 2),
                 "CopyMemory": (0, 1, 2), "RtlCopyMemory": (0, 1, 2), "memccpy": (0, 1, 3), "bcopy": (1, 0, 2),
                 "strlcpy": (0, 1, 2), "strlcat": (0, 1, 2)}
_SQL = {"sqlite3_exec": 1, "sqlite3_prepare": 1, "sqlite3_prepare_v2": 1, "sqlite3_prepare_v3": 1,
        "sqlite3_prepare16": 1, "sqlite3_prepare16_v2": 1, "mysql_query": 1, "mysql_real_query": 1,
        "mysql_send_query": 1, "PQexec": 1, "PQsendQuery": 1, "PQexecParams": 1, "PQprepare": 2,
        "SQLExecDirect": 1, "SQLExecDirectA": 1, "SQLExecDirectW": 1, "SQLPrepare": 1, "SQLPrepareA": 1,
        "SQLPrepareW": 1, "executeQuery": 0, "executeUpdate": 0, "prepareStatement": 0}
_PATH = {"fopen": 0, "_wfopen": 0, "fopen64": 0, "freopen": 0, "open": 0, "open64": 0, "_open": 0, "_wopen": 0,
         "openat": 1, "creat": 0, "unlink": 0, "_unlink": 0, "_wunlink": 0, "remove": 0, "_wremove": 0, "rmdir": 0,
         "rename": 0, "opendir": 0, "chmod": 0, "chown": 0, "truncate": 0, "CreateFileA": 0, "CreateFileW": 0,
         "CreateFile": 0, "DeleteFileA": 0, "DeleteFileW": 0, "DeleteFile": 0, "ifstream": 0, "ofstream": 0,
         "fstream": 0, "wifstream": 0, "wofstream": 0}
_LDAP = {"ldap_search_s": 3, "ldap_search_st": 3, "ldap_search_ext": 3, "ldap_search_ext_s": 3, "ldap_search": 3,
         "ldap_search_sA": 3, "ldap_search_sW": 3, "ldap_search_ext_sA": 3, "ldap_search_ext_sW": 3}
_CGI_HTML_RE = re.compile(r"(?i)content-type:\s*text/html")
_UNBOUNDED_S = re.compile(r"%(?![0-9]*\.[0-9*]+)[-+ #0]*[0-9]*(?:l|h|ll|L)?[sS]")
_SCANF_NUM = re.compile(r"%[*]?[0-9]*(?:hh|h|l|ll|j|z|t|L)?[diouxXfeEgGaA]")
_SCANF_STR_UNBOUNDED = re.compile(r"%(?:l)?[sS\[]")
_CPP_STD_NUM = frozenset({"int", "long", "short", "unsigned", "size_t", "ssize_t", "double", "float", "bool",
                          "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                          "char"})


# ---------------------------------------------------------------------------
# Önişlemci
# ---------------------------------------------------------------------------


def _word_character(character: str) -> bool:
    return character == "_" or character.isalnum()


def _strip_c_comments(value: str, *, line_comments_each_line: bool = True) -> str:
    """Remove closed block comments and line comments in one forward pass."""
    output: list[str] = []
    line_start = 0
    while line_start < len(value):
        newline = value.find("\n", line_start)
        line_end = len(value) if newline < 0 else newline
        remove_line_comment = line_comments_each_line or newline < 0 or newline == len(value) - 1
        cursor = line_start
        while cursor < line_end:
            block_start = value.find("/*", cursor, line_end)
            block_end = value.find("*/", block_start + 2, line_end) if block_start >= 0 else -1
            if block_end < 0:
                block_start = -1
            comment_start = value.find("//", cursor, line_end) if remove_line_comment else -1
            if block_start < 0 and comment_start < 0:
                output.append(value[cursor:line_end])
                break
            if comment_start >= 0 and (block_start < 0 or comment_start < block_start):
                output.append(value[cursor:comment_start])
                break
            output.append(value[cursor:block_start])
            cursor = block_end + 2
        if newline < 0:
            break
        output.append("\n")
        line_start = newline + 1
    return "".join(output)


def _parse_defined_expression(expr: str) -> tuple[str, bool] | None:
    cursor = 0
    negated = cursor < len(expr) and expr[cursor] == "!"
    if negated:
        cursor += 1
    while cursor < len(expr) and expr[cursor].isspace():
        cursor += 1
    if not expr.startswith("defined", cursor):
        return None
    cursor += len("defined")
    while cursor < len(expr) and expr[cursor].isspace():
        cursor += 1
    if cursor < len(expr) and expr[cursor] == "(":
        cursor += 1
    while cursor < len(expr) and expr[cursor].isspace():
        cursor += 1
    start = cursor
    while cursor < len(expr) and _word_character(expr[cursor]):
        cursor += 1
    if cursor == start:
        return None
    name = expr[start:cursor]
    while cursor < len(expr) and expr[cursor].isspace():
        cursor += 1
    if cursor < len(expr) and expr[cursor] == ")":
        cursor += 1
    return (name, negated) if cursor == len(expr) else None


def _parse_comparison(expr: str) -> tuple[str, str, str] | None:
    def operand(cursor: int) -> tuple[str, int] | None:
        start = cursor
        if cursor < len(expr) and expr[cursor] == "-":
            cursor += 1
            digit_start = cursor
            while cursor < len(expr) and expr[cursor].isdecimal():
                cursor += 1
            return (expr[start:cursor], cursor) if cursor > digit_start else None
        while cursor < len(expr) and _word_character(expr[cursor]):
            cursor += 1
        return (expr[start:cursor], cursor) if cursor > start else None

    left = operand(0)
    if left is None:
        return None
    left_value, cursor = left
    while cursor < len(expr) and expr[cursor].isspace():
        cursor += 1
    operator = expr[cursor:cursor + 2]
    if operator not in {"==", "!="}:
        return None
    cursor += 2
    while cursor < len(expr) and expr[cursor].isspace():
        cursor += 1
    right = operand(cursor)
    if right is None:
        return None
    right_value, cursor = right
    return (left_value, operator, right_value) if cursor == len(expr) else None


def _parse_directive(directive: str) -> tuple[str, str] | None:
    cursor = 0
    while cursor < len(directive) and directive[cursor].isspace():
        cursor += 1
    if cursor >= len(directive) or directive[cursor] != "#":
        return None
    cursor += 1
    while cursor < len(directive) and directive[cursor].isspace():
        cursor += 1
    start = cursor
    while cursor < len(directive) and _word_character(directive[cursor]):
        cursor += 1
    if cursor == start:
        return None
    word = directive[start:cursor]
    while cursor < len(directive) and directive[cursor].isspace():
        cursor += 1
    return word, directive[cursor:]


def _parse_function_macro(value: str) -> tuple[str, str, str] | None:
    if not value or not (value[0] == "_" or value[0].isascii() and value[0].isalpha()):
        return None
    cursor = 1
    while cursor < len(value) and _word_character(value[cursor]):
        cursor += 1
    name = value[:cursor]
    if cursor >= len(value) or value[cursor] != "(":
        return None
    close = value.find(")", cursor + 1)
    if close < 0 or "(" in value[cursor + 1:close]:
        return None
    params = value[cursor + 1:close]
    cursor = close + 1
    while cursor < len(value) and value[cursor].isspace():
        cursor += 1
    return name, params, value[cursor:]


def _simple_macro_value(value: str) -> bool:
    if value and (value[0] == "_" or value[0].isascii() and value[0].isalpha()) \
            and all(_word_character(character) for character in value[1:]):
        return True
    number = value[1:] if value.startswith("-") else value
    if number and all(character.isdecimal() for character in number):
        return True
    prefix_length = 2 if value.startswith('L"') else 1 if value.startswith('"') else 0
    if prefix_length == 0:
        return False
    cursor = prefix_length
    while cursor < len(value):
        character = value[cursor]
        if character == '"':
            return cursor == len(value) - 1
        if character == "\\":
            cursor += 1
            if cursor >= len(value) or value[cursor] == "\n":
                return False
        cursor += 1
    return False


def _cond_value(kind: str, expr: str, defined: set[str] | None = None,
                undefined: set[str] | None = None, values: dict[str, str] | None = None) -> bool | None:
    expr = expr.strip()
    defined = defined or set()
    undefined = undefined or set()
    values = values or {}
    expr = _strip_c_comments(expr, line_comments_each_line=False).strip()
    if kind == "ifdef":
        return True if expr in defined else False if expr in undefined or expr in _FALSE_DEFINES else None
    if kind == "ifndef":
        return False if expr in defined else True if expr in undefined or expr in _FALSE_DEFINES else None
    if expr in ("0", "(0)", "false"):
        return False
    if expr in ("1", "(1)", "true"):
        return True
    # Bounded three-valued boolean evaluation for common build guards. Unknown terms stay unknown; a known false
    # term still closes &&, a known true term closes ||.
    while len(expr) >= 2 and expr[0] == "(" and expr[-1] == ")":
        depth = 0
        closes = -1
        for pos, ch in enumerate(expr):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0:
                closes = pos; break
        if closes != len(expr) - 1:
            break
        expr = expr[1:-1].strip()

    def split_top(op: str) -> list[str]:
        depth = 0
        start = 0
        parts: list[str] = []
        i = 0
        while i < len(expr) - 1:
            depth += expr[i] == "("
            depth -= expr[i] == ")"
            if depth == 0 and expr.startswith(op, i):
                parts.append(expr[start:i]); start = i + len(op); i += len(op); continue
            i += 1
        if parts:
            parts.append(expr[start:])
        return parts

    for op in ("||", "&&"):
        parts = split_top(op)
        if parts:
            vals = [_cond_value("if", part, defined, undefined, values) for part in parts]
            if op == "||":
                return True if True in vals else False if all(v is False for v in vals) else None
            return False if False in vals else True if all(v is True for v in vals) else None
    if expr.startswith("!") and not expr.startswith("!="):
        val = _cond_value("if", expr[1:], defined, undefined, values)
        return None if val is None else not val
    defined_expr = _parse_defined_expression(expr)
    if defined_expr is not None:
        name, negated = defined_expr
        if name in defined:
            return not negated
        if name in undefined or name in _FALSE_DEFINES:
            return negated
    m = re.fullmatch(r"(\w+)", expr)
    if m:
        if m.group(1) in defined:
            raw = values.get(m.group(1), "1").strip()
            try:
                return int(raw, 0) != 0
            except ValueError:
                # Tanımlı olmak ``#if NAME`` için otomatik olarak doğru olmak değildir. Derleyici profilindeki
                # desteklenmeyen bir ifade bilinmiyorsa dal seçimini uydurma bir 1 ile değiştirme.
                return None
        if m.group(1) in undefined or m.group(1) in _FALSE_DEFINES:
            return False
    comparison = _parse_comparison(expr)
    if comparison is not None:
        def number(raw: str) -> int | None:
            value = values.get(raw, raw) if raw in defined else raw
            try:
                return int(value, 0)
            except ValueError:
                return 0 if raw in undefined else None
        left_raw, operator, right_raw = comparison
        left, right = number(left_raw), number(right_raw)
        if left is not None and right is not None:
            return (left == right) if operator == "==" else (left != right)
    return None


def preprocess(text: str, external_defines: dict[str, str] | None = None,
               external_undefines: set[str] | None = None,
               function_macros: dict[str, tuple[tuple[str, ...], list[Tok]]] | None = None,
               ) -> tuple[list[tuple[int, int]], dict[str, str]]:
    """Yönergeleri ve kapalı dalları atlanacak aralık olarak döndürür; tek belirteçli nesne makroları."""
    skips: list[tuple[int, int]] = []
    macros: dict[str, str] = dict(external_defines or {})
    known_defined = set(macros) | set(function_macros or ())
    known_undefined = set(external_undefines or ()) - known_defined
    # yığın: (bu dal etkin mi, önceki dallardan biri alındı mı, üst etkin mi, koşul bilinmiyor mu)
    stack: list[list[Any]] = []
    active = True
    pos = 0
    n = len(text)
    off_start = -1
    while pos < n:
        end = text.find("\n", pos)
        end = n if end < 0 else end
        line = text[pos:end]
        stripped = line.lstrip()
        if stripped.startswith("#"):
            # devam satırları
            dend = end
            while text[pos:dend].rstrip("\r").endswith("\\") and dend < n:
                nxt = text.find("\n", dend + 1)
                dend = n if nxt < 0 else nxt
            directive = text[pos:dend].replace("\\\n", " ")
            parsed_directive = _parse_directive(directive)
            word, rest = parsed_directive if parsed_directive is not None else ("", "")
            prev_active = active
            if word in ("if", "ifdef", "ifndef"):
                val = _cond_value(word, rest, known_defined, known_undefined, macros)
                take = True if val is None else val
                stack.append([take, take, active, val is None])
                active = active and take
            elif word == "elif" and stack:
                top = stack[-1]
                val = _cond_value("if", rest, known_defined, known_undefined, macros)
                if top[1] or top[3]:
                    take = False  # bilinmeyen koşulda yalnız ilk dal
                else:
                    take = True if val is None else val
                top[0] = take
                top[1] = top[1] or take
                active = top[2] and take
            elif word == "else" and stack:
                top = stack[-1]
                take = (not top[1]) and not top[3]
                top[0] = take
                top[1] = True
                active = top[2] and take
            elif word == "endif" and stack:
                top = stack.pop()
                active = top[2]
            elif word == "define" and active:
                parsed_function = _parse_function_macro(rest.strip())
                if parsed_function is not None and function_macros is not None:
                    macro_name, raw_params, raw_body = parsed_function
                    params = tuple(x.strip() for x in raw_params.split(",") if x.strip())
                    body = raw_body.strip()
                    if len(params) <= 8 and len(params) == len(set(params)) and all(
                            re.fullmatch(r"[A-Za-z_]\w*", x) for x in params) and body and len(body) <= 400 \
                            and "#" not in body and "__VA_ARGS__" not in body:
                        bt = core.tokenize(body, rust=False)
                        if 0 < len(bt) <= 96:
                            function_macros[macro_name] = (params, bt)
                    known_defined.add(macro_name); known_undefined.discard(macro_name)
                dm = re.match(r"(\w+)(\(?)\s*(.*)", rest.strip(), re.S)
                if dm and not dm.group(2):
                    body = _strip_c_comments(dm.group(3)).strip()
                    if _simple_macro_value(body):
                        macros[dm.group(1)] = body
                    elif dm.group(1) in macros:
                        macros.pop(dm.group(1), None)
                    known_defined.add(dm.group(1)); known_undefined.discard(dm.group(1))
            elif word == "undef" and active:
                undef = rest.strip().split()[0] if rest.strip() else ""
                macros.pop(undef, None)
                if function_macros is not None:
                    function_macros.pop(undef, None)
                known_defined.discard(undef); known_undefined.add(undef)
            # yönerge satırı her durumda atlanır; kapanan/açılan dal aralıkları ayrıca eklenir
            skips.append((pos, dend))
            if prev_active and not active:
                off_start = dend
            elif not prev_active and active:
                if off_start >= 0:
                    skips.append((off_start, pos))
                off_start = -1
            pos = dend + 1
            continue
        pos = end + 1
    if off_start >= 0:
        skips.append((off_start, n))
    # örtüşmeleri birleştir
    skips.sort()
    merged: list[tuple[int, int]] = []
    for a, b in skips:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged, macros


def _substitute(toks: list[Tok], macros: dict[str, str]) -> list[Tok]:
    if not macros:
        return toks
    out: list[Tok] = []
    for t in toks:
        if t.kind == "id" and t.text in macros:
            body = macros[t.text]
            depth = 0
            while re.fullmatch(r"[A-Za-z_]\w*", body) and body in macros and depth < 4 and macros[body] != body:
                body = macros[body]
                depth += 1
            if body.startswith(("\"", "L\"")):
                out.append(Tok("str", core._unescape(body[body.index('"') + 1:-1]), t.line))
            elif re.fullmatch(r"-?\d+", body):
                out.append(Tok("num", body, t.line))
            elif re.fullmatch(r"[A-Za-z_]\w*", body):
                out.append(Tok("id", body, t.line))
            else:
                # Derleme veritabanından gelen bounded fakat bu küçük önişlemcinin çözemediği ifadeyi tek bir sahte
                # tanımlayıcıya çevirmek yerine özgün belirteci bırak. Koşul değerlendiricisi bunu bilinmiyor sayar.
                out.append(t)
        else:
            out.append(t)
    return out


def _expand_function_macros(toks: list[Tok],
                            macros: dict[str, tuple[tuple[str, ...], list[Tok]]],
                            limitations: set[str] | None = None) -> list[Tok]:
    """Basit fonksiyon biçimli makroları en çok dört tur aç.

    ``#``/``##``/variadic makrolar toplanmaz. Böylece hedef ve sarmalayıcı özetleri görünür olurken tam C
    önişlemcisi taklit edilmez; büyüme dosya belirteç sınırında durur.
    """
    if not macros:
        return toks
    current = toks
    for _ in range(4):
        out: list[Tok] = []
        changed = False
        i = 0
        while i < len(current):
            tok = current[i]
            spec = macros.get(tok.text) if tok.kind == "id" and i + 1 < len(current) \
                and current[i + 1].text == "(" else None
            if spec is None:
                out.append(tok); i += 1; continue
            close = match_close(current, i + 1, len(current))
            ranges = split_args(current, i + 2, close)
            params, body = spec
            if len(ranges) != len(params):
                out.append(tok); i += 1; continue
            values = {p: current[a:b] for p, (a, b) in zip(params, ranges)}
            expanded: list[Tok] = []
            for item in body:
                if item.kind == "id" and item.text in values:
                    expanded.extend(Tok(x.kind, x.text, tok.line) for x in values[item.text])
                else:
                    expanded.append(Tok(item.kind, item.text, tok.line))
            if len(out) + len(expanded) + len(current) - close > core.MAX_TOKENS_PER_FILE:
                if limitations is not None:
                    limitations.add("macro-token")
                return current
            out.extend(expanded)
            i = close + 1
            changed = True
        current = out
        if not changed:
            break
    return current


# ---------------------------------------------------------------------------
# Fonksiyon çıkarımı
# ---------------------------------------------------------------------------

_QUALIFIERS = frozenset({"const", "noexcept", "override", "final", "volatile", "throw", "mutable", "try"})


def extract_functions(unit: FileUnit) -> None:
    toks = unit.toks
    n = len(toks)

    def scan(lo: int, hi: int, cls: str) -> None:
        i = lo
        while i < hi:
            t = toks[i]
            if t.kind == "op" and t.text == "{":
                # sınıf/ad alanı/extern bloğu mu?
                head = _item_head(toks, i, lo)
                close = match_close(toks, i, hi)
                kind, name = _block_kind(head)
                if kind == "ns":
                    scan(i + 1, close, cls)
                elif kind == "class":
                    scan(i + 1, close, name or cls)
                i = close + 1
                continue
            if t.kind == "id" and t.text not in _KEYWORDS and i + 1 < hi and toks[i + 1].text == "(" and \
                    (i == lo or toks[i - 1].text not in (".", "->", "=", "return", "(", ",", "!", "&&", "||")):
                close = match_close(toks, i + 1, hi)
                j = close + 1
                # niteleyiciler, throw(...), __attribute__((...)), -> dönüş türü, kurucu ilk değer listesi
                while j < hi:
                    x = toks[j]
                    if x.kind == "id" and x.text in _QUALIFIERS:
                        j += 1
                        if j < hi and toks[j].text == "(":
                            j = match_close(toks, j, hi) + 1
                        continue
                    if x.kind == "id" and x.text in ("__attribute__", "__declspec", "alignas") and j + 1 < hi and toks[j + 1].text == "(":
                        j = match_close(toks, j + 1, hi) + 1
                        continue
                    if x.kind == "op" and x.text in ("&", "&&") and j + 1 < hi and toks[j + 1].text in ("{", ";", "const"):
                        j += 1
                        continue
                    if x.kind == "op" and x.text == "->":
                        j += 1
                        while j < hi and toks[j].text not in ("{", ";", "="):
                            j += 1
                        continue
                    if x.kind == "op" and x.text == ":" and (j + 1 < hi and toks[j + 1].kind == "id"):
                        # kurucu ilk değer listesi
                        k = j + 1
                        while k < hi and toks[k].text != "{" and toks[k].text != ";":
                            if toks[k].text == "(":
                                k = match_close(toks, k, hi) + 1
                                continue
                            if toks[k].text == "{" :
                                break
                            k += 1
                        # m{x} biçimi ilk değerler: '{' sonrası ',' ya da başka '{' gelirse atla
                        while k < hi and toks[k].text == "{":
                            kc = match_close(toks, k, hi)
                            if kc + 1 < hi and toks[kc + 1].text in (",",):
                                k = kc + 2
                                while k < hi and toks[k].text not in ("{", ";", "("):
                                    k += 1
                                if k < hi and toks[k].text == "(":
                                    k = match_close(toks, k, hi) + 1
                                continue
                            break
                        j = k
                        break
                    break
                if j < hi and toks[j].text == "{":
                    body_close = match_close(toks, j, hi)
                    fn = _make_func(unit, i, close, j, body_close, cls, lo)
                    if fn is not None:
                        unit.funcs.append(fn)
                    i = body_close + 1
                    continue
                i = close + 1
                continue
            i += 1

    scan(0, n, "")


def _item_head(unit_toks: list[Tok], brace: int, lo: int) -> list[Tok]:
    toks = []
    j = brace - 1
    while j >= lo and len(toks) < 12:
        t = unit_toks[j]
        if t.kind == "op" and t.text in (";", "}", "{"):
            break
        toks.append(t)
        j -= 1
    toks.reverse()
    return toks

def _block_kind(head: list[Tok]) -> tuple[str, str]:
    words = [t.text for t in head]
    if not words:
        return "other", ""
    if "namespace" in words or (words[0] == "extern" and len(words) >= 2 and head[1].kind == "str"):
        return "ns", ""
    for kw in ("class", "struct", "union"):
        if kw in words:
            k = words.index(kw)
            # struct X { ... } ya da class X : public Y { ... }
            if "=" in words or "(" in words[:k]:
                return "other", ""
            name = ""
            for t in head[k + 1:]:
                if t.kind == "id" and t.text not in _KEYWORDS and t.text not in ("final",):
                    name = t.text
                    break
                if t.text == ":":
                    break
            return "class", name
    return "other", ""


def _make_func(unit: FileUnit, name_idx: int, pclose: int, body_open: int, body_close: int, cls: str,
               scope_lo: int) -> Func | None:
    toks = unit.toks
    name = toks[name_idx].text
    qual_parts = [name]
    j = name_idx
    # A::B::name, A::~A
    while j - 2 >= scope_lo and toks[j - 1].text in ("::", "~"):
        if toks[j - 1].text == "~":
            qual_parts[0] = "~" + qual_parts[0]
            j -= 1
            continue
        if toks[j - 2].kind == "id":
            qual_parts.insert(0, toks[j - 2].text)
            j -= 2
        else:
            break
    owner = qual_parts[-2] if len(qual_parts) >= 2 else cls
    fname = qual_parts[-1]
    # dönüş türü/belirteçler (static?)
    k = j - 1
    head_words: list[str] = []
    while k >= scope_lo and toks[k].text not in (";", "}", "{", ")") and len(head_words) < 12:
        if toks[k].text == "]" or toks[k].text == "#":
            break
        head_words.append(toks[k].text)
        k -= 1
    if any(w in ("=", "return", ",") for w in head_words):
        return None
    params: list[Param] = []
    if pclose > name_idx + 2:
        for idx, (a, b) in enumerate(split_args(toks, name_idx + 2, pclose, angle=True)):
            ptoks = toks[a:b]
            text = " ".join(t.text for t in ptoks)
            if text in ("void",):
                continue
            # parametre adı: '=' (varsayılan) öncesindeki son tanımlayıcı; işlev işaretçisi (*ad)
            stop = b
            for q in range(a, b):
                if toks[q].text == "=":
                    stop = q
                    break
            pname = ""
            fp = [q for q in range(a, stop) if toks[q].text == "(" and q + 2 < stop and toks[q + 1].text == "*"]
            if fp:
                pname = toks[fp[0] + 2].text if toks[fp[0] + 2].kind == "id" else ""
            else:
                for q in range(stop - 1, a - 1, -1):
                    if toks[q].text == "]":
                        continue
                    if toks[q].kind == "id" and toks[q].text not in _KEYWORDS and toks[q].text not in _CPP_STD_NUM:
                        if q > a:  # yalnız tür adı değil
                            pname = toks[q].text
                        break
                    if toks[q].kind == "op" and toks[q].text not in ("*", "&", "&&", "[", "]"):
                        if toks[q].kind == "num":
                            continue
                        break
            params.append(Param(pname, text, len(params), (pname,) if pname else ()))
    return Func(fname, "::".join(qual_parts), unit.path, params, (body_open, body_close), toks[name_idx].line,
                cls=owner if len(qual_parts) >= 2 else cls, is_static="static" in head_words,
                has_self=False, ret_type=" ".join(reversed(head_words)))


# ---------------------------------------------------------------------------
# Gövde yürütücüsü
# ---------------------------------------------------------------------------



def _brace_ends(toks: list, lo: int, hi: int) -> list[int]:
    """ends[q - lo]: q'yu içeren en içteki eşleşmiş {…} çiftinin kapanış indeksi (yoksa hi).

    19. tur hız: önceki sürüm her kapanışta tüm aralığı geziyordu (O(n·derinlik)); tek geçişte yığının tepesi
    kaydedilip sonra çözülür. Kapanmayan açılışlar yığının dibinde kalır (üstlerindekiler kapanmadan alttaki
    kapanamaz), bu yüzden tepesi kapanmamış olan konumların eşleşmiş çifti yoktur → hi (önceki sonuçla aynı)."""
    stack: list[int] = []
    close_of: dict[int, int] = {}
    top_at = [-1] * (hi - lo + 1)
    for j in range(lo, hi + 1):
        t = toks[j]
        if t.kind == "op" and t.text == "{":
            stack.append(j)
            top_at[j - lo] = j
        elif t.kind == "op" and t.text == "}" and stack:
            close_of[stack.pop()] = j
            top_at[j - lo] = -2  # kapanışın kendisi: kendi çifti onu içerir
        elif stack:
            top_at[j - lo] = stack[-1]
    ends = [hi] * (hi - lo + 1)
    for q in range(hi - lo + 1):
        top = top_at[q]
        if top == -2:
            ends[q] = q + lo
        elif top >= 0:
            ends[q] = close_of.get(top, hi)
    return ends

class CBody(BodyAnalyzer):
    LANG = "c"
    TRACK_PROOF = True
    BLOCK_KEYWORDS = frozenset({"if", "else", "for", "while", "do", "switch", "try", "catch", "case", "default"})
    SKIP_KEYWORDS = frozenset(_KEYWORDS - {"defined"}) | frozenset({"NULL", "nullptr", "true", "false"})
    NUMERIC_TYPES = frozenset()

    def prepare(self) -> None:
        super().prepare()
        # Yerel, somut yapı örneği → alan kirliliği. Tür düzeyi proje özeti ayrıca korunur; bu örtü aynı türdeki iki
        # stack nesnesinin birbirini kirletmesini önler ve çözülemeyen işaretçilerde eski güvenli fallback'i bırakır.
        self.instance_fields: dict[tuple[str, tuple], frozenset] = {}
        # Bir işlev işaretçisi koşullu dallarda farklı hedeflere atanırsa tek bir son hedefe indirgenemez.
        # Böyle adlar çağrı yerinde proje indeksindeki aday kümesiyle çözülür.
        self.ambiguous_function_aliases: set[str] = set()
        self.function_alias_candidates: dict[str, set[str]] = {}
        self.overflow_function_aliases: set[str] = set()
        # A strong assignment from an unresolved callback value invalidates any
        # earlier exact target for that local.  Keep the state explicit so the
        # project-wide syntactic index cannot resurrect a stale assignment.
        self.unknown_function_aliases: set[str] = set()
        toks = self.toks
        lo, hi = self.fn.body
        # main(argc, argv): argv yerel kaynak
        if self.fn.name in ("main", "wmain", "_tmain") and len(self.fn.params) >= 2:
            argv = self.fn.params[1].name
            if argv:
                self.env[argv] = frozenset({Origin("local", "komut satırı argümanı (argv)", self.fn.line, self.file,
                                                   cap=-1)})
        # 27. tur: çağıranlardan soket tanımlayıcısı/akışı alan parametreler ve yereller (int x = *(int *)arg)
        for nm, kind in self.cindex().sock_locals.get(self.fn.key, {}).items():
            if kind in ("fd", "stream"):
                self.var_info.setdefault(nm, {})["socket" if kind == "fd" else "sockstream"] = True
        for pi, kind in self.cindex().sock_params.get(self.fn.name, {}).items():
            if pi < len(self.fn.params) and self.fn.params[pi].name:
                pn = self.fn.params[pi].name
                self.var_info.setdefault(pn, {})["socket" if kind == "fd" else "sockstream" if kind == "stream"
                                                  else "sockptr"] = True
        # çatı geri çağırması (MHD_start_daemon, mg_http_listen, …): istek parametreleri kaynak
        spec = self.cindex().callbacks.get(self.fn.name)
        if spec:
            hop = self.cindex().table_hops.get(self.fn.name, "")
            for p in self.fn.params:
                desc = spec.get(p.index)
                if desc and p.name:
                    o = Origin("request", desc, self.fn.line, self.file, cap=HTTP_FRAMEWORK_CAP)
                    self.env[p.name] = frozenset({o.with_hop(hop) if hop else o})
        # üst/alt sınır denetimleri: (değişken → [(başlangıç, bitiş)] belirteç bölgeleri). Denetim, karşılaştırmanın
        # bulunduğu en içteki bloğun sonuna kadar geçerlidir (if/else dallarının ayrı denetimleri karışmaz).
        self.upper: dict[str, list[tuple[int, int]]] = {}
        self.lower: dict[str, list[tuple[int, int]]] = {}
        for p in self.fn.params:
            if p.name:
                self.var_info.setdefault(p.name, {})["type"] = p.type_text
        # soket tanımlayıcıları: fd = accept(...) / socket(...) (koşul içindeki atamalar dahil)
        calls = self.unit.info.get("sockcalls")
        if calls is None:
            calls = self.unit.info["sockcalls"] = [j for j, t in enumerate(toks) if t.kind == "id" and t.text in _SOCKET_CALLS]
        for j in calls[bisect.bisect_left(calls, lo + 2):bisect.bisect_left(calls, hi - 1)]:
            if toks[j - 1].text == "=" and toks[j - 2].kind == "id" and toks[j + 1].text == "(":
                self.var_info.setdefault(toks[j - 2].text, {})["socket"] = True
        block_end: list[int] = []
        ends = _brace_ends(toks, lo, hi)
        for j in range(lo, hi):
            t = toks[j]
            if t.kind == "id" and t.text in ("MIN", "min", "CURLMIN", "MINIMUM", "minimum") and toks[j + 1].text == "(":
                close = match_close(toks, j + 1, hi)
                for a, b in split_args(toks, j + 2, close):
                    for q in range(a, b):
                        if toks[q].kind == "id":
                            self.upper.setdefault(toks[q].text, []).append((j, ends[j - lo]))
                continue
            if t.kind != "op" or t.text not in ("<", "<=", ">", ">="):
                continue
            left = self._operand_name(j - 1, back=True)
            right = self._operand_name(j + 1, back=False)
            lval = self._operand_literal(j - 1, back=True)
            rval = self._operand_literal(j + 1, back=False)
            region = self._guard_region(j, lo, hi, ends)
            # 0/-1 ile karşılaştırma alt sınır, diğerleri üst sınır denetimidir
            if left and rval != "NULL":
                (self.lower if rval in ("0", "-1") else self.upper).setdefault(left, []).append(region)
            if right and lval != "NULL":
                (self.lower if lval in ("0", "-1") else self.upper).setdefault(right, []).append(region)
        self.cgi = bool(self.unit.info.get("cgi_html"))
        # 27. tur: inetd/xinetd tarzı hizmette standart girdi ağ bağlantısıdır (kaynak etiketi request)
        self.inetd = not self.cgi and self.cindex().stdin_service
        # 27. tur: dizin geçişi denetimi — if (strstr(x, "..") / strchr(x, '/')) { return; } → x'ten türeyen yol arınmış
        self.path_guards: list[tuple[int, int, str]] = []  # (ilk satır, son satır, denetlenen değişken)
        # 27. tur düzeltmesi: komut/kod hedefleri için doğrulayıcı (is_valid_x) ve izin listesi denetimleri
        # (strspn(x, IZINLI) == strlen(x), strcmp(x, "sabit") == 0); ".." denetimi komut için arındırıcı değildir.
        self.cmd_guards: list[tuple[int, int, str]] = []
        gpos = self.unit.info.get("guardcalls")
        if gpos is None:
            gpos = self.unit.info["guardcalls"] = [
                j for j, t in enumerate(toks) if t.kind == "id" and (t.text in (
                    "strstr", "strchr", "strrchr", "strpbrk", "strcasestr") or _VALIDATOR_RE.search(t.text))]
        for j in gpos[bisect.bisect_left(gpos, lo):bisect.bisect_left(gpos, max(lo, hi - 4))]:
            t = toks[j]
            if toks[j + 1].text != "(":
                continue
            close = match_close(toks, j + 1, hi)
            args = split_args(toks, j + 2, close)
            validator = t.text not in ("strstr", "strchr", "strrchr", "strpbrk", "strcasestr")
            if validator:
                if not args:
                    continue
            elif len(args) != 2:
                continue
            else:
                lit = toks[args[1][0]]
                if args[1][1] - args[1][0] != 1 or lit.kind not in ("str", "chr") or not (
                        "/" in lit.text or ".." in lit.text or "\\" in lit.text):
                    continue
            var = self.base_ident(*args[0])
            if not var and validator and toks[args[0][0]].kind == "id" and args[0][0] + 1 < args[0][1] and \
                    toks[args[0][0] + 1].text == "(":
                # doğrulayıcıya sarmalayıcı çağrıyla verilen değişken: mg_path_is_sane(mg_str_n(buf, n))
                inner = split_args(toks, args[0][0] + 2, match_close(toks, args[0][0] + 1, args[0][1]))
                var = self.base_ident(*inner[0]) if inner else ""
            if not var:
                continue
            # koşul içinde mi ve gövde çıkış mı?
            q = j - 1
            depth = 0
            while q > lo:
                x = toks[q]
                if x.text == ")":
                    depth += 1
                elif x.text == "(":
                    if depth == 0:
                        if toks[q - 1].kind == "id" and toks[q - 1].text in ("if", "while"):
                            break
                    else:
                        depth -= 1
                elif x.text in (";", "{", "}"):
                    q = lo
                    break
                q -= 1
            if q <= lo:
                continue
            cclose = match_close(toks, q, hi)
            body = cclose + 1
            bend = match_close(toks, body, hi) if body < hi and toks[body].text == "{" else body
            while bend < hi and toks[bend].text not in (";", "}") and toks[body].text != "{":
                bend += 1
            # kutup: koşul doğruysa yol "tehlikeli" mi (strstr(x, "..") / !check(x)) yoksa "güvenli" mi
            # (strstr(x, "..") == NULL, !strstr(..), check(x))
            neg_prefix = toks[j - 1].text == "!" or (j >= 2 and toks[j - 1].text == "==" and toks[j - 2].text in
                                                        ("NULL", "0", "nullptr"))
            cmp_null = close + 2 < hi and toks[close + 1].text in ("==", "!=") and toks[close + 2].text in (
                "NULL", "0", "nullptr")
            safe_when_true = (toks[close + 1].text == "==" if cmp_null else neg_prefix) if not \
                (j >= 2 and toks[j - 1].text == "==") else True
            if validator:
                safe_when_true = not safe_when_true
            func_end = toks[hi].line if hi < len(toks) else toks[hi - 1].line
            body_lines = (toks[body].line, toks[min(bend, hi - 1)].line)
            region = None
            if safe_when_true:
                region = (body_lines[0], body_lines[1], var)
            elif any(toks[x].kind == "id" and toks[x].text in self._EXITS for x in range(body, min(bend + 1, hi))):
                region = (t.line, func_end, var)
            elif bend + 1 < hi and toks[bend + 1].text == "else":
                e = bend + 2
                eend = match_close(toks, e, hi) if e < hi and toks[e].text == "{" else e
                while eend < hi and toks[eend].text not in (";", "}") and toks[e].text != "{":
                    eend += 1
                region = (toks[e].line, toks[min(eend, hi - 1)].line, var)
            if region is not None:
                self.path_guards.append(region)
                if validator:
                    self.cmd_guards.append(region)
        for region in self._allowlist_guards(lo, hi):
            self.path_guards.append(region)
            self.cmd_guards.append(region)

    _ALLOW_CMP = frozenset({"strcmp", "strcasecmp", "_stricmp", "stricmp", "wcscmp", "_wcsicmp", "g_strcmp0",
                            "g_str_equal", "g_ascii_strcasecmp"})

    def _if_context(self, j: int, lo: int, hi: int) -> tuple[int, int, int, int] | None:
        """``j`` bir if koşulunun içindeyse: (koşul '(' dizini, koşul ')' dizini, gövde başı, gövde sonu)."""
        toks = self.toks
        q = j - 1
        depth = 0
        while q > lo:
            x = toks[q]
            if x.text == ")":
                depth += 1
            elif x.text == "(":
                if depth == 0:
                    if toks[q - 1].kind == "id" and toks[q - 1].text == "if":
                        break
                else:
                    depth -= 1
            elif x.text in (";", "{", "}"):
                return None
            q -= 1
        if q <= lo:
            return None
        cclose = match_close(toks, q, hi)
        body = cclose + 1
        if body >= hi:
            return None
        bend = match_close(toks, body, hi) if toks[body].text == "{" else body
        while bend < hi and toks[bend].text not in (";", "}") and toks[body].text != "{":
            bend += 1
        return q, cclose, body, bend

    def _cond_terms(self, a: int, b: int) -> tuple[str, list[tuple[int, int]]]:
        """Koşulu üst düzey && / || terimlerine böler: ("and"|"or"|"one"|"mixed", [(başlangıç, bitiş)])."""
        toks = self.toks
        while b - a >= 2 and toks[a].text == "(" and match_close(toks, a, b) == b - 1:
            a, b = a + 1, b - 1
        terms, ops = [], set()
        depth, start = 0, a
        for k in range(a, b):
            x = toks[k]
            if x.kind != "op":
                continue
            if x.text in "([":
                depth += 1
            elif x.text in ")]":
                depth -= 1
            elif depth == 0 and x.text in ("&&", "||"):
                ops.add(x.text)
                terms.append((start, k))
                start = k + 1
        terms.append((start, b))
        out = []
        for ta, tb in terms:
            while tb - ta >= 2 and toks[ta].text == "(" and match_close(toks, ta, tb) == tb - 1:
                ta, tb = ta + 1, tb - 1
            out.append((ta, tb))
        kind = "one" if not ops else "mixed" if len(ops) > 1 else ("and" if "&&" in ops else "or")
        return kind, out

    def _allow_term(self, a: int, b: int) -> tuple[str, bool] | None:
        """İzin listesi terimi: (değişken, koşul doğruyken değişken güvenli mi). ``strcmp(x, "a") == 0`` / ``!strcmp``
        → eşit (güvenli); ``!= 0`` / çıplak çağrı → eşit değil. ``strspn(x, IZINLI) == strlen(x)`` → güvenli;
        ``!=`` / ``<`` → güvensiz; ``x[strspn(x, IZINLI)] != '\\0'`` → güvensiz."""
        toks = self.toks
        neg = False
        k = a
        if toks[k].text == "!":
            neg, k = True, k + 1
        # x[strspn(x, A)] karşılaştırması
        if k + 2 < b and toks[k].kind == "id" and toks[k + 1].text == "[" and toks[k + 2].text == "strspn":
            rb = match_close(toks, k + 1, b)
            inner = toks[k + 3].text == "(" and match_close(toks, k + 3, rb)
            if not inner:
                return None
            args = split_args(toks, k + 4, inner)
            if len(args) != 2 or self.base_ident(*args[0]) != toks[k].text:
                return None
            rest = toks[rb + 1:b]
            if not rest:
                bad = not neg
            elif len(rest) == 2 and rest[0].text in ("==", "!=") and (
                    (rest[1].kind == "num" and rest[1].text == "0") or
                    (rest[1].kind == "chr" and rest[1].text in ("\x00", "x00"))) and not neg:
                bad = rest[0].text == "!="
            else:
                return None
            return toks[k].text, not bad
        if toks[k].kind != "id" or k + 1 >= b or toks[k + 1].text != "(":
            return None
        name = toks[k].text
        close = match_close(toks, k + 1, b)
        args = split_args(toks, k + 2, close)
        if len(args) != 2:
            return None
        rest = toks[close + 1:b]
        if name in self._ALLOW_CMP:
            lit = [i for i, r in enumerate(args) if r[1] - r[0] == 1 and toks[r[0]].kind == "str"]
            if len(lit) != 1:
                return None
            var = self.base_ident(*args[1 - lit[0]])
            if not var:
                return None
            eq_true = name in ("g_str_equal",)
            if not rest:
                equal = neg if not eq_true else not neg
            elif len(rest) == 2 and rest[0].text in ("==", "!=") and rest[1].text == "0" and not neg and not eq_true:
                equal = rest[0].text == "=="
            else:
                return None
            return var, equal
        if name == "strspn":
            var = self.base_ident(*args[0])
            if not var or neg or len(rest) < 3 or rest[0].text not in ("==", "!=", "<", ">=") or \
                    rest[1].text not in ("strlen", "strnlen"):
                return None
            rclose = match_close(toks, close + 3, b) if toks[close + 3].text == "(" else -1
            if rclose < 0 or self.base_ident(close + 4, rclose) != var:
                return None
            return var, rest[0].text in ("==", ">=")
        return None

    def _allowlist_guards(self, lo: int, hi: int) -> list[tuple[int, int, str]]:
        """İzin listesi denetimleri: erken çıkışlı (``if (strcmp(x, "a") && strcmp(x, "b")) return;``) ya da güvenli
        gövdeli (``if (strspn(x, IZINLI) == strlen(x)) { … }``) koşullar → x'in güvenli olduğu satır bölgeleri."""
        toks = self.toks
        pos = self.unit.info.get("allowcalls")
        if pos is None:
            pos = self.unit.info["allowcalls"] = [j for j, t in enumerate(toks) if t.kind == "id" and (
                t.text in self._ALLOW_CMP or t.text == "strspn")]
        out: list[tuple[int, int, str]] = []
        done: set[int] = set()
        func_end = toks[hi].line if hi < len(toks) else toks[hi - 1].line
        for j in pos[bisect.bisect_left(pos, lo):bisect.bisect_left(pos, max(lo, hi - 4))]:
            ctx = self._if_context(j, lo, hi)
            if ctx is None or ctx[0] in done:
                continue
            q, cclose, body, bend = ctx
            done.add(q)
            kind, terms = self._cond_terms(q + 1, cclose)
            if kind == "mixed":
                continue
            info = [self._allow_term(a, b) for a, b in terms]
            exits = any(toks[x].kind == "id" and toks[x].text in self._EXITS for x in range(body, min(bend + 1, hi)))
            body_lines = (toks[body].line, toks[min(bend, hi - 1)].line)
            for var in {x[0] for x in info if x}:
                safe = [x is not None and x[0] == var and x[1] for x in info]
                bad = [x is not None and x[0] == var and not x[1] for x in info]
                # koşul doğruyken güvenli: tek terim / && içinde biri / || içinde hepsi
                if (kind in ("one", "and") and any(safe)) or (kind == "or" and all(safe)):
                    out.append((body_lines[0], body_lines[1], var))
                # koşul yanlışken güvenli: tek terim / || içinde biri / && içinde hepsi
                if (kind in ("one", "or") and any(bad)) or (kind == "and" and all(bad)):
                    if exits:
                        out.append((toks[q].line, func_end, var))
                    elif bend + 1 < hi and toks[bend + 1].text == "else":
                        e = bend + 2
                        eend = match_close(toks, e, hi) if e < hi and toks[e].text == "{" else e
                        while eend < hi and toks[eend].text not in (";", "}") and toks[e].text != "{":
                            eend += 1
                        out.append((toks[e].line, toks[min(eend, hi - 1)].line, var))
        return out

    def global_key(self, name: str) -> tuple[str, str]:
        root = name.split(".", 1)[0]
        info = self.unit.info
        if root in info.get("statics", ()):
            return (self.file, name)
        if root in info.get("globals", ()):
            return ("", name)
        return (self.fn.cls, name) if self.fn.cls else ("", name)

    def src(self, label: str, source: str, line: int, *, numeric_: bool = False, cap: int | None = None) -> frozenset:
        t = super().src(label, source, line, numeric_=numeric_, cap=cap)
        if label == "request" and "inetd hizmeti" in source:
            # standart girdinin ağ bağlantısı olduğu proje düzeyi ipucundan (soket birimi/xinetd) çıkarıldı; programın
            # o birim tarafından başlatıldığı kanıtlı değil (ör. boruyla beslenen arka uç süreci): kanıtsız kaynak
            return core.weaken(t)
        return t

    def global_taint(self, name: str) -> frozenset:
        # küresel değişken/alan kirliliği akışa ve bağlama duyarsızdır: kanıtsız adım
        return core.weaken(super().global_taint(name))

    def is_global(self, name: str) -> bool:
        return bool(name) and name not in self.locals and name not in self.param_index and name not in self.env \
            and name != "this"

    def taint_target(self, lo: int, hi: int, taint: frozenset, *, strong: bool = False,
                     clean: bool = False) -> None:
        name = self.base_ident(lo, hi)
        if not name:
            return
        access = self.access_key(lo, hi)
        if not taint and self.final and (self._clean_rhs or clean):
            # 27. tur: alana kirli olmayan (sabit/temiz) değer yazımı — alan "karışık" (her okuma kirli değil)
            ak = access
            if ak is not None and self.field_kind(ak[0]):
                self.col.facts.setdefault("clean_field_writes", set()).add(ak[0][1:])
                receiver = self._expression_instance(lo, hi, receiver=True) or name
                self._write_receiver_field(receiver, ak[0], ak[1], EMPTY, self.toks[lo].line,
                                           strong=not self.branch_depth)
        if taint:
            ak = access
            if ak is not None:
                self.write_field(ak[0], ak[1], taint, self.toks[lo].line)
                receiver = self._expression_instance(lo, hi, receiver=True) or name
                self._write_receiver_field(receiver, ak[0], ak[1], taint, self.toks[lo].line, strong=strong)
            else:
                # sabit kaba yazılan içerik kabın boyutunu aşamaz (aşarsa o yazımın kendisi taşmadır)
                cap = self.container_cap((lo, hi))
                if cap:
                    taint = self.capped(taint, cap - 1)
                if not any(t.text in (".", "->", "[") for t in self.toks[lo:hi]):
                    self.expand_raw_struct(name, taint, self.toks[lo].line)
        if taint and any(o.label == "request" for o in taint) and \
                not any(t.text in (".", "->", "[") for t in self.toks[lo:hi]):
            # ağdan okunan ham bayt doğrudan bu değişkene yazıldı (recv(fd, &hdr, …)): tamsayı alanları saldırgan sayısı
            self.var_info.setdefault(name, {})["raw"] = True
        if self.is_global(name):
            # küresel yapı alanı: alan duyarlı anahtar (server.x) — bütün yapıyı kirletmez
            toks = self.toks
            for j in range(lo, hi - 2):
                if toks[j].kind == "id" and toks[j].text == name and toks[j + 1].text in (".", "->") and toks[j + 2].kind == "id":
                    name = f"{name}.{toks[j + 2].text}"
                    break
        # Bir yapı alanına yazım bütün yerel yapıyı kirletmez. Alanın proje/dosyalar arası özeti yukarıda ayrı
        # anahtara yazılır; kök değişkeni kirletmek kardeş alanlarda (r.safe) yanlış pozitif oluşturuyordu.
        if access is None:
            self.set_var(name, taint, strong=strong)

    _EXITS = frozenset({"return", "goto", "break", "continue", "exit", "abort", "_exit", "throw", "longjmp"})

    def _guard_region(self, j: int, lo: int, hi: int, ends: list[int]) -> tuple[int, int]:
        """Karşılaştırmanın koruduğu bölge: if/while koşulundaysa yalnız gövde; gövde çıkış (return/goto/break…)
        içeriyorsa erken çıkış kalıbıdır ve bloğun geri kalanını korur; diğer konumlarda bloğun geri kalanı."""
        toks = self.toks
        depth = 0
        q = j - 1
        while q >= lo:
            t = toks[q]
            if t.kind == "op" and t.text in (")", "]"):
                depth += 1
            elif t.kind == "op" and t.text in ("(", "["):
                if depth == 0:
                    if t.text == "(" and q > lo and toks[q - 1].kind == "id" and toks[q - 1].text in ("if", "while"):
                        close = match_close(toks, q, hi)
                        body = close + 1
                        if body < hi and toks[body].text == "{":
                            bend = match_close(toks, body, hi)
                        else:
                            bend = body
                            while bend < hi and toks[bend].text != ";":
                                bend += 1
                        if any(toks[x].kind == "id" and toks[x].text in self._EXITS for x in range(body, min(bend + 1, hi))):
                            return (j, ends[j - lo])
                        return (close, bend)
                    if t.text == "(" and q > lo and toks[q - 1].kind == "id" and toks[q - 1].text == "for":
                        close = match_close(toks, q, hi)
                        body = close + 1
                        bend = match_close(toks, body, hi) if body < hi and toks[body].text == "{" else body
                        return (close, bend)
                    depth = 0
                else:
                    depth -= 1
            elif t.kind == "op" and t.text in (";", "{", "}") and depth == 0:
                break
            q -= 1
        return (j, ends[j - lo])

    def guarded(self, name: str, pos: int, *, lower: bool = False) -> bool:
        for a, b in (self.lower if lower else self.upper).get(name, ()):
            if a < pos <= b:
                return True
        return False

    def _operand_name(self, j: int, *, back: bool) -> str:
        toks = self.toks
        if not (0 <= j < len(toks)):
            return ""
        t = toks[j]
        if back:
            if t.text == ")":
                # strlen(x) < n  /  (x) < n
                k = j - 1
                while k > 0 and toks[k].text != "(":
                    k -= 1
                if k > 0 and toks[k - 1].kind == "id" and toks[k - 1].text in ("strlen", "wcslen", "strnlen"):
                    return toks[k + 1].text if toks[k + 1].kind == "id" else ""
                return toks[j - 1].text if toks[j - 1].kind == "id" else ""
            return t.text if t.kind == "id" else ""
        if t.text in ("(",) and j + 1 < len(toks):
            if j > 0 and toks[j - 1].kind == "id":
                return ""
            return toks[j + 1].text if toks[j + 1].kind == "id" else ""
        if t.kind == "id" and t.text in ("strlen", "wcslen", "strnlen") and j + 2 < len(toks):
            return toks[j + 2].text if toks[j + 2].kind == "id" else ""
        if t.kind == "id" and j + 1 < len(toks) and toks[j + 1].text not in ("(",):
            return t.text
        return ""

    def _operand_literal(self, j: int, *, back: bool) -> str:
        toks = self.toks
        if not (0 <= j < len(toks)):
            return ""
        t = toks[j]
        if t.kind == "num":
            if not back and j + 1 < len(toks) and toks[j + 1].text in ("&&", "||", ")", ";", ","):
                return t.text
            if back:
                return "-1" if j > 0 and toks[j - 1].text == "-" and t.text == "1" else t.text
        if t.kind == "op" and t.text == "-" and not back and j + 1 < len(toks) and toks[j + 1].text == "1":
            return "-1"
        if t.kind == "id" and t.text in ("NULL", "nullptr"):
            return "NULL"
        return ""

    def evaluate(self, lo: int, hi: int) -> frozenset:
        """Üçlü işleç: ``koşul ? a : b`` → koşul yan etkileri için değerlendirilir, değer a ∪ b (koşuldaki
        karşılaştırma işleçleri değeri boşaltmasın)."""
        toks = self.toks
        qs = self.unit.info.get("qmarks")
        if qs is None:
            qs = self.unit.info["qmarks"] = [j for j, t in enumerate(toks) if t.kind == "op" and t.text == "?"]
        k = bisect.bisect_left(qs, lo)
        if k >= len(qs) or qs[k] >= hi:
            return super().evaluate(lo, hi)
        depth, q = 0, -1
        for j in range(lo, hi):
            t = toks[j]
            if t.kind != "op":
                continue
            if t.text in "([{":
                depth += 1
            elif t.text in ")]}":
                depth -= 1
            elif depth == 0 and t.text == "?":
                q = j
                break
        if q > lo:
            depth, nest = 0, 0
            for c in range(q + 1, hi):
                t = toks[c]
                if t.kind != "op":
                    continue
                if t.text in "([{":
                    depth += 1
                elif t.text in ")]}":
                    depth -= 1
                elif depth == 0 and t.text == "?":
                    nest += 1
                elif depth == 0 and t.text == ":":
                    if nest:
                        nest -= 1
                        continue
                    super().evaluate(lo, q)
                    return compact(self.evaluate(q + 1, c) | self.evaluate(c + 1, hi))
        return super().evaluate(lo, hi)

    def base_ident(self, lo: int, hi: int) -> str:
        """C: tür dönüşümü grupları ((char *), (const wchar_t *)) atlanarak ilk değişken adı."""
        toks = self.toks
        i = lo
        while i < hi:
            t = toks[i]
            if t.kind == "op" and t.text == "(":
                close = match_close(toks, i, hi)
                inner = toks[i + 1:close]
                if inner and all(x.kind == "id" or x.text in ("*", "&", "::", "<", ">", ",") for x in inner) and \
                        close + 1 < hi and (toks[close + 1].kind == "id" or toks[close + 1].text in ("(", "&", "*")):
                    i = close + 1
                    continue
                i += 1
                continue
            if t.kind == "id":
                if t.text in self.SKIP_KEYWORDS or t.text in _CPP_STD_NUM or t.text in ("void", "wchar_t"):
                    i += 1
                    continue
                if i + 1 < hi and toks[i + 1].text == "(":
                    return ""
                if t.text == "this" and i + 2 < hi and toks[i + 1].text in ("->", "."):
                    return toks[i + 2].text if toks[i + 2].kind == "id" else ""
                # std::string::x gibi yollar: son parça
                j = i
                while j + 2 < hi and toks[j + 1].text == "::" and toks[j + 2].kind == "id":
                    j += 2
                return toks[j].text
            i += 1
        return ""

    def var_taint(self, name: str) -> frozenset:
        # Takma ad zincirini dinamik çöz: ``q -> p -> buf`` kurulduktan sonra buf'a recv yazılması q'ya da
        # ulaşmalıdır. Döngülü/bozuk işaretçi grafiğinde sekiz adımda güvenli biçimde durur.
        out = super().var_taint(name)
        seen = {name}
        current = name
        for _ in range(8):
            pointee = self.var_info.get(current, {}).get("points_to")
            if not pointee or pointee in seen:
                break
            seen.add(pointee)
            out = out | super().var_taint(pointee)
            current = pointee
        return out

    def set_var(self, name: str, taint: frozenset, *, strong: bool) -> None:
        super().set_var(name, taint, strong=strong)
        pointee = self.var_info.get(name, {}).get("points_to")
        if pointee and pointee != name and (taint or strong):
            super().set_var(pointee, taint, strong=strong)

    def out_param(self, p: Param) -> bool:
        return "*" in p.type_text or "&" in p.type_text or "[" in p.type_text

    def finish(self) -> None:
        # 27. tur düzeltmesi: yardımcı çıkış parametresini kendi içinde doğruluyorsa (if (!is_sane(buf)) return false;)
        # çağıranda değerin doğrulanmış olup olmadığı dönüş değerinin denetimine bağlıdır — model bunu izlemez:
        # çıkış parametresi kirliliği kanıtsız sayılır (doğrulanmış akışa yükseltilmez).
        guarded = {var for _a, _b, var in getattr(self, "path_guards", ())}
        if guarded:
            for p in self.fn.params:
                if p.name in guarded and self.out_param(p) and self.env.get(p.name):
                    self.env[p.name] = core.weaken(self.env[p.name])
        super().finish()

    def is_struct_literal(self, parts: list[str], k: int) -> bool:
        return False

    # -- deyimler -----------------------------------------------------------

    def statement(self, lo: int, hi: int, *, header: bool, tail: bool) -> None:
        toks = self.toks
        first = toks[lo]
        if first.kind == "id" and first.text == "return":
            self.ret |= self.evaluate(lo + 1, hi)
            self.nested_blocks(lo, hi)
            return
        if first.kind == "id" and lo + 1 < hi and toks[lo + 1].text == ":" and toks[lo + 1].kind == "op" and \
                first.text not in ("public", "private", "protected"):
            # etiket: "kaynak:" (goto hedefi)
            if lo + 2 < hi:
                self.statement(lo + 2, hi, header=header, tail=tail)
            return
        if first.kind == "id" and first.text in ("case", "default"):
            k = lo
            while k < hi and toks[k].text != ":":
                k += 1
            if k + 1 < hi:
                self.statement(k + 1, hi, header=header, tail=tail)
            return
        if header:
            # if (...) / while (...) / for (init; cond; inc) / switch (...)
            self.evaluate(lo, hi)
            if first.text == "for":
                k = lo + 1
                if k < hi and toks[k].text == "(":
                    close = match_close(toks, k, hi)
                    for a, b in _split_semis(toks, k + 1, close):
                        self.simple(a, b)
            return
        # tek satırlık if/while/for gövdesi: if (c) foo(x);
        if first.kind == "id" and first.text in ("if", "while", "for", "switch") and lo + 1 < hi and toks[lo + 1].text == "(":
            close = match_close(toks, lo + 1, hi)
            if first.text == "for":
                for a, b in _split_semis(toks, lo + 2, close):
                    self.simple(a, b)
            else:
                self.evaluate(lo + 2, close)
            if close + 1 < hi:
                self.statement(close + 1, hi, header=False, tail=tail)
            return
        if first.kind == "id" and first.text in ("else", "do", "try"):
            if lo + 1 < hi:
                self.statement(lo + 1, hi, header=False, tail=tail)
            return
        self.simple(lo, hi)
        self.nested_blocks(lo, hi)

    def stmt_end(self, i: int, hi: int) -> tuple[int, bool]:
        toks = self.toks
        if toks[i].kind == "id" and i + 1 < hi and toks[i + 1].kind == "op" and toks[i + 1].text == ":" and \
                toks[i].text not in ("case",):
            return i + 2, False  # etiket ("kaynak:") kendi başına bir deyimdir
        return super().stmt_end(i, hi)

    def nested_blocks(self, lo: int, hi: int) -> None:
        # C'de yalnız lambda gövdeleri; küme ilk değer listeleri ({a, b}) atlanır.
        toks = self.toks
        j = lo
        while j < hi:
            if toks[j].text == "{" and toks[j].kind == "op":
                close = match_close(toks, j, hi)
                if j > lo and toks[j - 1].text == ")" and close - j > 1:
                    self.block(j + 1, close)
                j = close + 1
                continue
            j += 1

    def simple(self, lo: int, hi: int) -> None:
        toks = self.toks
        if lo >= hi:
            return
        # Kuruculu C++ akış bildirimi ``declared_names`` tarafından argümanla karıştırılmadan önce türü kaydet.
        for q in range(lo, min(hi - 1, lo + 8)):
            if toks[q].text not in {"ifstream", "wifstream", "fstream", "basic_ifstream", "basic_fstream"}:
                continue
            j = q + 1
            if j < hi and toks[j].text == "<":
                depth = 0
                while j < hi:
                    if toks[j].text == "<":
                        depth += 1
                    elif toks[j].text == ">":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
            if j < hi and toks[j].kind == "id":
                self.var_info.setdefault(toks[j].text, {})["type"] = " ".join(
                    token.text for token in toks[lo:j]
                )
            break
        # std::cin >> a >> b;
        if toks[lo].text in ("cin", "std", "wcin") and any(t.text == ">>" for t in toks[lo:hi]) and \
                any(t.text in ("cin", "wcin") for t in toks[lo:min(hi, lo + 4)]):
            for j in range(lo, hi):
                if toks[j].text == ">>" and j + 1 < hi and toks[j + 1].kind == "id":
                    name = toks[j + 1].text
                    self.set_var(name, self.src("local", "standart girdi (std::cin)", toks[j].line), strong=True)
            return
        # std::ifstream/fstream >> value: yalnız türü yerel dosya giriş akışı olarak bildirilen alıcı.
        if toks[lo].kind == "id" and self._local_file_stream(toks[lo].text) and \
                any(t.text == ">>" for t in toks[lo:hi]):
            for j in range(lo, hi):
                if toks[j].text == ">>" and j + 1 < hi and toks[j + 1].kind == "id" and \
                        toks[j + 1].text in self.locals:
                    self.set_var(toks[j + 1].text, self.src(
                        "local", "yerel dosyadan okunan veri (std::ifstream >>)", toks[j].line,
                    ), strong=True)
            return
        # stringstream: ss << x
        split = self.assignment_split(lo, hi)
        decl_names = self.declared_names(lo, split[0] if split else hi)
        for name in decl_names:
            self.declare(name)
        if split is None:
            if any(t.text == "<<" for t in toks[lo:hi]) and toks[lo].kind == "id" and not decl_names:
                # akış: out << x  (ostringstream birikimi)
                first = toks[lo].text
                rhs = self.evaluate(lo + 2, hi) if lo + 2 <= hi else EMPTY
                if rhs and first in self.locals:
                    self.set_var(first, rhs, strong=False)
                    return
            # bildirim: std::string s(x);  T v{x};
            if decl_names:
                last = decl_names[-1]
                for j in range(lo, hi):
                    if toks[j].kind == "id" and toks[j].text == last and j + 1 < hi and toks[j + 1].text in ("(", "{"):
                        close = match_close(toks, j + 1, hi)
                        typ = " ".join(t.text for t in toks[lo:j])
                        self.var_info.setdefault(last, {})["type"] = typ
                        cls_name = self._decl_class(lo, j)
                        if cls_name:
                            self.var_info.setdefault(last, {})["class"] = cls_name
                        val = self.evaluate(j + 2, close)
                        cands = self.prog.resolve(cls_name, self.file, None, method=True, cls=cls_name) if cls_name else []
                        if cands:
                            ranges = split_args(toks, j + 2, close)
                            self.apply(cands, self.arg_taints(ranges), toks[j].line, cls_name, ranges)
                        self.ctor_sink(typ, j, j + 2, close, val)
                        self.set_var(last, val, strong=True)
                        return
                cls_name = self._decl_class(lo, hi)
                for name in decl_names:
                    self.env[name] = EMPTY
                    if cls_name:
                        self.var_info.setdefault(name, {})["class"] = cls_name
                    for q in range(lo, hi):
                        if toks[q].kind == "id" and toks[q].text == name:
                            self.var_info.setdefault(name, {})["type"] = " ".join(t.text for t in toks[lo:q])
                            if q + 1 < hi and toks[q + 1].text == "[":
                                self.var_info[name]["array"] = True
                                self._note_array_cap(name, q, hi)
                            break
                return
            self.evaluate(lo, hi)
            return
        eq, op = split
        rhs = self.evaluate(eq + 1, hi)
        if decl_names:
            name0 = decl_names[-1]
            for q in range(lo, eq):
                if toks[q].kind == "id" and toks[q].text == name0:
                    self.var_info.setdefault(name0, {})["type"] = " ".join(t.text for t in toks[lo:q])
                    if q + 1 < eq and toks[q + 1].text == "[":
                        self.var_info[name0]["array"] = True
                        self._note_array_cap(name0, q, eq)
                    break
            self._note_value_kind(name0, eq + 1, hi)
            self._note_deps(name0, eq + 1, hi, replace=True)
            # tamsayı değişkene ham kirli bayt/alan: saldırganın seçtiği sayı (int n = *(int *)buf;)
            if rhs and self._int_scalar(name0) and (self._raw_value(eq + 1, hi) or self._byte_assembly(eq + 1, hi)):
                rhs = numeric(rhs)
            # nesnenin somut sınıfı (sanal çağrı çözümlemesi): T obj; T *p = new U; T &r = obj;
            cls_name = self._decl_class(lo, eq)
            for q in range(eq + 1, hi - 1):
                if toks[q].kind == "id" and toks[q].text == "new" and toks[q + 1].kind == "id":
                    cls_name = toks[q + 1].text
                    break
            if eq + 2 < hi and toks[eq + 1].kind == "id" and toks[eq + 2].text == "(" and self._class_known(toks[eq + 1].text):
                cls_name = toks[eq + 1].text  # geçici nesne: Base &b = Derived();
            if eq + 2 == hi and toks[eq + 1].kind == "id" and self.var_info.get(toks[eq + 1].text, {}).get("class"):
                cls_name = self.var_info[toks[eq + 1].text]["class"]
            if cls_name:
                self.var_info.setdefault(name0, {})["class"] = cls_name
            # işaretçi/başvuru takma adı: T **p = &x;  T &r = x;
            if eq + 3 == hi and toks[eq + 1].text == "&" and toks[eq + 2].kind == "id":
                self.var_info.setdefault(name0, {})["points_to"] = toks[eq + 2].text
            elif eq + 2 == hi and toks[eq + 1].kind == "id" and any(t.text in ("&",) for t in toks[lo:eq]):
                self.var_info.setdefault(name0, {})["points_to"] = toks[eq + 1].text
            elif self._ptrlike(name0) and not self.var_info.get(name0, {}).get("array"):
                # işaretçi takma adı: char *p = buf;  char *p = (char *)buf + n;  char *q = strchr(buf, c);
                target = self._alias_target(eq + 1, hi)
                if target and target != name0:
                    self.var_info[name0]["points_to"] = target
            # İşlev işaretçisi takma adı: doğrudan/paren hedef, önceki takma ad
            # ve koşullu hedef kümesini koru.
            self._assign_function_alias_expr(name0, eq + 1, hi)
            # dizi/küme ilk değeri: char *args[] = {PATH, "-c", data, NULL};
            if eq + 1 < hi and toks[eq + 1].text == "{":
                lits = {t.text for t in toks[eq + 1:hi] if t.kind == "str"}
                self.var_info.setdefault(decl_names[-1], {})["literals"] = lits
            self.note_alloc(decl_names[-1], eq + 1, hi)
            self.set_var(decl_names[-1], rhs, strong=True)
            if rhs and toks[eq + 1].text == "(" and "*" in self.var_info.get(name0, {}).get("type", ""):
                self.expand_raw_struct(name0, rhs, toks[eq].line)  # struct msg *m = (struct msg *)buf;
            return
        lhs_simple = (eq - lo == 1 and toks[lo].kind == "id")
        if lhs_simple and op == "+=":
            self.snprintf_accumulation(toks[lo].text, eq + 1, hi)
        if lhs_simple and op == "=":
            name = toks[lo].text
            pidx = self.param_index.get(name)
            if pidx is not None and not self.branch_depth and "&" in self.fn.params[pidx].type_text:
                # C++ T&/T*& çıkışı doğrudan atamada eski çağıran değerini korumaz.
                self.summary.out_overwrite.add(pidx)
            self._note_value_kind(name, eq + 1, hi)
            self._note_deps(name, eq + 1, hi, replace=op == "=")
            tracked_alias = name in self.aliases or name in self.function_alias_candidates or \
                name in self.overflow_function_aliases or name in self.unknown_function_aliases
            alias_known = self._assign_function_alias_expr(name, eq + 1, hi)
            if tracked_alias and not alias_known and not self.branch_depth:
                self._invalidate_function_alias(name)
            self.note_alloc(name, eq + 1, hi)
            info = self.var_info.get(name)
            if info is not None and self._ptrlike(name) and not info.get("array"):
                target = self._alias_target(eq + 1, hi)
                if target and target != name:
                    info["points_to"] = target
                else:
                    info.pop("points_to", None)
            if rhs and self._int_scalar(name) and (self._raw_value(eq + 1, hi) or self._byte_assembly(eq + 1, hi)):
                rhs = numeric(rhs)
            self.set_var(name, rhs, strong=True)
            return
        # *p = x, p->f = x, a[i] = x, this->m = x, x += y
        self.evaluate(lo, eq)  # sol taraftaki dizi indeksi hedefleri için
        self.index_write(lo, eq)
        # temiz (sabit) değer: dizgi/sayı değişmezi ya da kirli olmayan yerel değişken; NULL/""/0 sıfırlaması, ayırma,
        # çağrı sonucu (basename(x->f) gibi dönüşümler) ve alanın kendisinden türeyen değer sayılmaz
        rhs_toks = toks[eq + 1:hi]
        lit = len(rhs_toks) == 1 and ((rhs_toks[0].kind == "str" and rhs_toks[0].text != "") or (
            rhs_toks[0].kind == "num" and rhs_toks[0].text not in ("0", "0L", "0UL")))
        local_var = len(rhs_toks) == 1 and rhs_toks[0].kind == "id" and rhs_toks[0].text in self.locals and \
            rhs_toks[0].text not in self.param_index
        self._clean_rhs = op == "=" and (lit or local_var)
        lhs_deref = any(t.text == "*" for t in toks[lo:eq]) and not any(
            t.text in (".", "->", "[") for t in toks[lo:eq]
        )
        target_name = self.base_ident(lo, eq)
        target_type = self.var_info.get(target_name, {}).get("type", "")
        # ``*char_ptr = 0`` tamponun tek baytını değiştirir ve bütün tamponu temizlemez. Güçlü güncelleme yalnız
        # işaretçinin kendisini değiştiren pointer-to-pointer/reference çıkışlarında geçerlidir.
        strong_out = op == "=" and lhs_deref and (
            target_type.count("*") >= 2 or ("*" in target_type and "&" in target_type)
        )
        if strong_out and not self.branch_depth and target_name in self.param_index:
            self.summary.out_overwrite.add(self.param_index[target_name])
        try:
            self.taint_target(lo, eq, rhs, strong=strong_out)
        finally:
            self._clean_rhs = False

    _pending_sockstream = False
    _strtok_taint: frozenset = EMPTY
    _clean_rhs = False

    def _note_array_cap(self, name: str, q: int, hi: int) -> None:
        toks = self.toks
        dims: list[list[Tok]] = []
        r = q + 1
        while r < hi and toks[r].text == "[":
            close = match_close(toks, r, hi)
            dims.append(toks[r + 1:close])
            r = close + 1
        typ = self.var_info.get(name, {}).get("type", "")
        cap = _decl_cap(typ, dims, self.unit.info.get("num_macros"))
        if cap is not None:
            self.var_info[name]["cap"] = cap

    def _note_value_kind(self, name: str, lo: int, hi: int) -> None:
        """Atanan değerin türü: soket akışı (fdopen), işlev işaretçisi alanı, sabit boyutlu ayırma, kod dosyası."""
        toks = self.toks
        info = self.var_info.setdefault(name, {})
        if self._pending_sockstream:
            info["sockstream"] = True
            self._pending_sockstream = False
        if hi - lo >= 3 and toks[hi - 2].text in (".", "->") and toks[hi - 1].kind == "id" and \
                toks[hi - 1].text in self.cindex().fptr_fields:
            info["fptr_field"] = toks[hi - 1].text
        j = lo
        while j < hi and toks[j].kind == "op" and toks[j].text == "(":
            j = match_close(toks, j, hi) + 1 if all(x.kind == "id" or x.text == "*" for x in toks[j + 1:match_close(toks, j, hi)]) else j + 1
        if j + 1 < hi and toks[j].kind == "id" and toks[j + 1].text == "(":
            fn = toks[j].text
            close = match_close(toks, j + 1, hi)
            args = split_args(toks, j + 2, close)
            if fn in ("malloc", "alloca", "xmalloc", "g_malloc") and len(args) == 1:
                v = self.length_value(args[0])
                if v:
                    info["cap"] = v
            elif fn in ("calloc", "xcalloc") and len(args) == 2:
                a, b = self.length_value(args[0]), self.length_value(args[1])
                if a and b:
                    info["cap"] = a * b
            elif fn in ("fopen", "popen", "open", "fdopen") and args:
                lit = self._lit(args[0])
                mode = self._lit(args[1]) if len(args) > 1 else ""
                writes = any(c in mode for c in "wa+") or (fn == "open" and "O_" in " ".join(
                    t.text for t in toks[args[1][0]:args[1][1]]) and "RDONLY" not in " ".join(
                    t.text for t in toks[args[1][0]:args[1][1]])) if len(args) > 1 else False
                if fn == "popen" and lit and _COMPILER_RE.search(lit) and "w" in mode:
                    info["codefile"] = f"popen(\"{lit[:40]}\")"
                elif fn in ("fopen", "open") and lit and _SRC_EXT_RE.search(lit) and writes:
                    info["codefile"] = f"{fn}(\"{lit[:40]}\")"
                elif fn in ("fopen", "open") and writes and len(args) >= 1 and self.var_taint(
                        self.base_ident(*args[0])) is not None:
                    src_name = self.base_ident(*args[0])
                    if src_name and self.var_info.get(src_name, {}).get("srcpath"):
                        info["codefile"] = f"{fn}({src_name})"

    def snprintf_accumulation(self, var: str, lo: int, hi: int) -> None:
        """``n += snprintf(buf + n, sizeof buf - n, "%s", kirli)``: snprintf yazılacak uzunluğu döndürür; kesilmede
        ``n`` tampon boyutunu aşar, ``sizeof buf - n`` taşar ve sonraki yazım tamponun dışına çıkar. Biçimlenen değer
        kirliyse ve ``n`` üst sınırla hiç karşılaştırılmıyorsa ``memory_len``."""
        toks = self.toks
        i = lo
        while i < hi and toks[i].kind == "op" and toks[i].text == "(":
            close = match_close(toks, i, hi)
            if all(x.kind == "id" for x in toks[i + 1:close]):
                i = close + 1
                continue
            break
        if not (i + 1 < hi and toks[i].kind == "id" and toks[i].text in _SNPRINTF and toks[i + 1].text == "("):
            return
        close = match_close(toks, i + 1, hi)
        args = split_args(toks, i + 2, close)
        if len(args) < 3 or var in self.upper:
            return
        in_dst = any(t.kind == "id" and t.text == var for t in toks[args[0][0]:args[0][1]])
        in_len = any(t.kind == "id" and t.text == var for t in toks[args[1][0]:args[1][1]])
        if not (in_dst and in_len):
            return
        t = EMPTY
        for a, b in args[3:]:
            t = t | self.scan_idents(a, b)
        t = strings_only(t)
        if t:
            self.sink("memory_len", f"{toks[i].text}() dönüş değeri birikimi", toks[i].line, numeric(t))

    def _decl_class(self, lo: int, hi: int) -> str:
        toks = self.toks
        for q in range(lo, hi):
            t = toks[q]
            if t.kind == "id" and t.text not in _KEYWORDS and t.text not in _CPP_STD_NUM and t.text not in ("std", "void"):
                if q + 1 < hi and toks[q + 1].text == "::":
                    continue
                return t.text
            if t.kind == "op" and t.text in ("=", "("):
                break
        return ""

    def note_alloc(self, name: str, lo: int, hi: int) -> None:
        """Yığın ayırma: boyutu değişkene bağlıysa (``malloc(strlen(s)+1)``) sınırsız kopyalama muafiyeti; sabit
        boyutlu ayırma (``malloc(8)``, ``calloc(REQSZ, 1)``) sabit tampon gibi değerlendirilir."""
        toks = self.toks
        for j in range(lo, min(hi, lo + 6)):
            if toks[j].kind == "id" and toks[j].text in ("malloc", "calloc", "realloc", "strdup", "strndup", "alloca",
                                                         "xmalloc", "g_malloc", "new", "xcalloc", "xrealloc"):
                info = self.var_info.setdefault(name, {})
                fn = toks[j].text
                ids: set[str] = set()
                if fn == "new":
                    k = j + 1
                    while k < hi and toks[k].text != "[":
                        k += 1
                    if k < hi:
                        close = match_close(toks, k, hi)
                        ids = {t.text for t in toks[k + 1:close] if t.kind == "id"}
                    dynamic = bool(ids) or k >= hi
                elif fn in ("strdup", "strndup"):
                    dynamic = True
                elif j + 1 < hi and toks[j + 1].text == "(":
                    close = match_close(toks, j + 1, hi)
                    q = j + 2
                    while q < close:
                        t = toks[q]
                        if t.kind == "id" and t.text in ("sizeof", "alignof") and q + 1 < close and toks[q + 1].text == "(":
                            q = match_close(toks, q + 1, close) + 1
                            continue
                        if t.kind == "id" and t.text not in self.SKIP_KEYWORDS and t.text not in _CPP_STD_NUM:
                            ids.add(t.text)
                        q += 1
                    if fn == "realloc":
                        args = split_args(toks, j + 2, close)
                        ids = {t.text for a, b in args[1:] for t in toks[a:b] if t.kind == "id"} if len(args) > 1 else ids
                    dynamic = bool(ids)
                else:
                    dynamic = True
                info["heap"] = dynamic
                info["alloc_ids"] = ids
                return

    def declared_names(self, lo: int, hi: int) -> list[str]:
        """C/C++ bildirimi mi? ``T ad``, ``T *ad[N]``, ``T a, *b``, ``void (*fp)(…)`` → bildirilen adlar."""
        toks = self.toks
        if hi - lo < 2:
            return []
        first = toks[lo]
        if first.kind != "id" or first.text in ("return", "if", "while", "for", "switch", "case", "goto", "delete",
                                                 "throw", "else", "do", "sizeof"):
            return []
        # işlev işaretçisi
        for j in range(lo, hi - 3):
            if toks[j].text == "(" and toks[j + 1].text == "*" and toks[j + 2].kind == "id" and toks[j + 3].text == ")":
                if j > lo and toks[j - 1].kind == "id":
                    return [toks[j + 2].text]
        names: list[str] = []
        for a, b in split_args(toks, lo, hi, angle=True):
            # son tanımlayıcı ([N] grupları atlanarak)
            q = b - 1
            while q >= a and toks[q].text == "]":
                depth = 0
                while q >= a:
                    if toks[q].text == "]":
                        depth += 1
                    elif toks[q].text == "[":
                        depth -= 1
                        if depth == 0:
                            break
                    q -= 1
                q -= 1
            if q < a or toks[q].kind != "id" or toks[q].text in _KEYWORDS:
                if names:
                    continue
                return []
            name = toks[q].text
            prev = toks[q - 1] if q - 1 >= lo else None
            if not names:
                # ilk bildirici: önünde tür olmalı
                if prev is None or q - 1 < a:
                    return []
                if prev.kind == "op" and prev.text not in ("*", "&", "&&", ">", "::", ">>"):
                    return []
                if prev.kind == "op" and prev.text == "*" and q - 2 >= a and toks[q - 2].kind != "id" and toks[q - 2].text not in ("*", ">"):
                    return []
                # ``std::function<void(char *)> handler`` gibi C++ sarmalayici turlerinde
                # parantez, bildirici ifadesi degil template turunun parcasidir. Yalniz
                # dengeli ``<...>`` icindeki parantezi kabul et; ust duzey cagri/ifade
                # operatorleri halen bildirimi kapali bicimde reddeder.
                angle_depth = 0
                for token in toks[a:q]:
                    if token.kind != "op":
                        continue
                    if token.text == "<":
                        angle_depth += 1
                        continue
                    if token.text == ">":
                        angle_depth = max(0, angle_depth - 1)
                        continue
                    if token.text == ">>":
                        angle_depth = max(0, angle_depth - 2)
                        continue
                    if angle_depth == 0 and token.text in ("(", "->", ".", "=", "+", "-", "!"):
                        return []
            names.append(name)
        return names

    def index_write(self, lo: int, hi: int) -> None:
        """``buf[i] = …`` sol tarafı: kirli sayısal indeks → dizi indeksi hedefi."""
        toks = self.toks
        for j in range(lo, hi):
            if toks[j].text == "[" and toks[j].kind == "op" and j > lo and toks[j - 1].kind == "id":
                close = match_close(toks, j, hi)
                self.index_sink(toks[j - 1].text, j + 1, close)

    def index(self, cur: frozenset, base: str | None, lo: int, hi: int) -> frozenset:
        if base:
            self.index_sink(base, lo, hi)
            if base in self.env and any(o.source.startswith("komut satırı") for o in cur):
                return cur
        self.evaluate(lo, hi)
        return cur

    def index_sink(self, array: str, lo: int, hi: int) -> None:
        toks = self.toks
        if hi - lo != 1 or toks[lo].kind != "id":
            return
        if lo >= 3 and toks[lo - 3].kind == "id" and toks[lo - 3].text == "new":
            return  # new T[n]: dizi oluşturma (bellek ayırma), indeks değil
        idx = toks[lo].text
        typ = self.var_info.get(idx, {}).get("type", "")
        unsigned = bool(re.search(r"\bunsigned\b|\bsize_t\b|\buint\w*|\bUINT\b|\bDWORD\b|\bu8\b|\bu16\b|\bu32\b", typ))
        if self.guarded(idx, lo) and (unsigned or self.guarded(idx, lo, lower=True)):
            self.col.evaluated(self.file, "memory_index", toks[lo].line)
            return
        t = self.var_taint(idx)
        nums = frozenset(o for o in t if o.numeric or o.label == "param")
        if not nums:
            if array not in self.param_index and t == EMPTY:
                self.col.evaluated(self.file, "memory_index", toks[lo].line)
            return
        # parametre kökenleri sayısal kullanımda (özet) — sayısal işaretiyle aktarılır
        self.sink("memory_index", f"{array}[{idx}]", toks[lo].line, nums)

    def ctor_sink(self, typ: str, name_idx: int, lo: int, hi: int, val: frozenset) -> None:
        for kw in ("ifstream", "ofstream", "fstream", "wifstream", "wofstream"):
            if kw in typ.split():
                ranges = split_args(self.toks, lo, hi)
                if ranges:
                    self.sink("path", f"std::{kw}", self.toks[name_idx].line, strings_only(self.evaluate(*ranges[0])))

    # -- çağrılar ------------------------------------------------------------

    def call(self, parts: list[str], open_: int, close: int, name_idx: int, turbofish: str) -> frozenset:
        toks = self.toks
        name = parts[-1]
        line = toks[name_idx].line
        ranges = split_args(toks, open_ + 1, close)
        if name in ("sizeof", "alignof", "offsetof"):
            return EMPTY
        if name in _NUM_CONV:
            return numeric(self.args_union(open_ + 1, close))
        if name in _PTR_INTO_ARG0 and ranges and name not in self.prog.by_name:
            # 27. tur: dönüş ilk argümanın içini gösterir — ayrıştırıcıda strstr(req->hdr, …) sonucu kirli veridir
            ts = [self.evaluate(a, b) for a, b in ranges]
            return strings_only(ts[0])
        if name in _CLEAN_CALLS:
            for a, b in ranges:
                self.evaluate(a, b)
            return EMPTY
        if name == "getline" and len(ranges) >= 2:
            stream = self.base_ident(*ranges[0])
            stream_text = " ".join(t.text for t in toks[ranges[0][0]:ranges[0][1]])
            if stream_text in ("std :: cin", "std :: wcin") or \
                    (stream in ("cin", "wcin") and stream not in self.locals):
                self.taint_target(*ranges[1], self.src(
                    "local", "standart girdi (std::getline)", line, cap=-1,
                ))
                return EMPTY
            if stream and self._local_file_stream(stream):
                self.taint_target(*ranges[1], self.src(
                    "local", "yerel dosyadan okunan veri (std::getline)", line, cap=-1,
                ))
                return EMPTY
        source_aliases = set(self.function_alias_candidates.get(name, ()))
        if name in self.aliases:
            source_aliases.add(self.aliases[name])
        source_handled = False
        for source_name in sorted(source_aliases & set(_RECV_OUT)):
            source_handled = self.c_source(source_name, ranges, line) is not None or source_handled
        if source_handled:
            return EMPTY
        handled = self.c_source(name, ranges, line)
        if handled is not None:
            return handled
        taints = self.arg_taints(ranges)
        self.c_sinks(name, ranges, taints, line)
        prop = self.c_propagate(name, ranges, taints)
        if prop is not None:
            return prop
        fw = self.framework_call(name, ranges, taints, line)
        if fw is not None:
            return fw
        if len(parts) == 1 and name not in self.prog.by_name and name not in self.aliases:
            ff = self.var_info.get(name, {}).get("fptr_field")
            if ff:
                return self.indirect_apply(ff, "field", ranges, taints, line)
            if name in self.locals or name in self.param_index or name in self.cindex().fptr_vars:
                return self.indirect_apply(name, "var", ranges, taints, line)
        cls = parts[-2] if len(parts) >= 2 else ""
        return self.default_call(name, ranges, taints, line, cls=cls if cls and cls != "std" else "")

    def method(self, name: str, dot: int, open_: int, close: int, recv: frozenset, base: str | None,
               turbofish: str) -> frozenset:
        toks = self.toks
        ranges = split_args(toks, open_ + 1, close)
        taints = self.arg_taints(ranges)
        line = toks[dot].line
        if name in ("c_str", "data", "str", "substr", "toStdString", "constData", "toUtf8", "toLatin1",
                    "front", "back", "at", "begin", "end"):
            return recv
        if name in ("length", "size", "count", "capacity", "empty", "find", "compare", "rfind"):
            return EMPTY
        qualified_std_input = dot >= 3 and toks[dot - 1].text in ("cin", "wcin") and \
            toks[dot - 2].text == "::" and toks[dot - 3].text == "std"
        std_input = qualified_std_input or (base in ("cin", "wcin") and base not in self.locals)
        if name in ("read", "getline", "get", "readsome") and std_input and len(ranges) >= 2:
            self._len_sink(name, ranges[0], [ranges[1]], line)
            self.taint_target(*ranges[0], self.src(
                "local", f"standart girdi (std::cin.{name})", line,
                cap=self._read_cap(ranges[0], ranges[1]),
            ))
            return recv
        if name in ("read", "getline", "get", "readsome") and base and self._local_file_stream(base) \
                and len(ranges) >= 2:
            self._len_sink(name, ranges[0], [ranges[1]], line)
            self.taint_target(*ranges[0], self.src(
                "local", f"yerel dosyadan okunan veri (std::ifstream.{name})", line,
                cap=self._read_cap(ranges[0], ranges[1]),
            ))
            return recv
        if name == "get":
            # Container/string accessor semantics remain unchanged when this
            # is not the buffered istream overload handled above.
            return recv
        if name in ("append", "assign", "insert", "push_back", "emplace_back", "push", "add") and base:
            add = EMPTY
            for t in taints:
                add = add | t
            if add:
                self.set_var(base, add, strong=name == "assign")
            return recv | add
        if name == "open" and base:
            info = self.var_info.get(base, {})
            if ranges and (info.get("stream") or "stream" in base.lower() or base.endswith(("ifs", "ofs", "file", "File"))):
                self.sink("path", f"{base}.open", line, strings_only(taints[0]))
        if name in _SQL and ranges:
            idx = _SQL[name]
            if idx < len(taints):
                self.sink("sql", f"{base or ''}.{name}" if base else name, line, strings_only(taints[idx]))
        cls = self.var_info.get(base, {}).get("class", "") if base else ""
        if base == "this" or (base is None and False):
            cls = self.fn.cls
        cands = self.prog.resolve(name, self.file, len(taints), method=True, cls=cls)
        if cls and cands and all(f.cls != cls for f in cands) and self._class_known(cls):
            cands = []  # sınıf biliniyor, yöntem bu sınıfta değil (temel sınıf/kütüphane): ad eşleşmesi kullanılmaz
        if not cls and len({f.cls for f in cands}) > 1:
            cands = []  # alıcı sınıfı bilinmiyor ve ad birden çok sınıfta: ad tabanlı eşleme yanıltıcı
        if cands:
            return self.apply(cands, taints, line, name, ranges)
        receiver_key = (self.fn.key, base) if base else None
        if receiver_key is not None and receiver_key in self.cindex().fptr_receivers:
            # Sabit yapı/dizi alıcısı: ``ops[1].run`` yalnız o örneğe atanmış hedefleri kullanır.
            return self.indirect_apply(receiver_key, "receiver", ranges, taints, line)
        if name in self.cindex().fptr_fields:
            return self.indirect_apply(name, "field", ranges, taints, line)
        if base and base in self.cindex().fptr_vars:
            # Konumsal yerel tablo/yapı ilk değeri alıcı örneğine bağlanır: ``Ops bad = { dangerous }``.
            return self.indirect_apply(base, "var", ranges, taints, line)
        out = recv
        for t in taints:
            out = out | t
        return core.weaken(compact(out))

    def _class_known(self, cls: str) -> bool:
        return cls in self.prog.classes

    def field(self, cur: frozenset, base: str | None, name: str, op: str) -> frozenset:
        if base == "this":
            return self.member_taint(name)
        res = cur | self.global_taint(f"{base}.{name}") if base and self.is_global(base) else cur
        if base and res and self._raw(base):
            # ağdan ham okunan yapının tamsayı alanı saldırganın seçtiği bir sayıdır (uzunluk/indeks kaynağı). Yalnız
            # yapının kendisi okunduysa: bir alanına veri yazılmış yapının (conn->buf) sayaç alanları program durumudur.
            info = self._field_info(base, name)
            if info and not info[1] and not info[2] and _is_int_type(info[0]):
                res = frozenset(o.as_numeric() if o.label == "request" else o for o in res)
        return res

    def _raw(self, var: str) -> bool:
        info = self.var_info.get(var, {})
        if info.get("raw"):
            return True
        target = info.get("points_to")
        return bool(target and self.var_info.get(target, {}).get("raw"))

    # -- tür bilgisi yardımcıları ---------------------------------------------

    def _struct_of(self, var: str) -> dict[str, tuple[str, bool, bool]] | None:
        structs = self.unit.info.get("structs") or {}
        typ = self.var_info.get(var, {}).get("type", "")
        if not typ or not structs:
            return None
        for word in reversed(re.findall(r"[A-Za-z_]\w*", typ)):
            if word in structs and word != var:
                return structs[word]
        return None

    def _field_info(self, var: str, field: str) -> tuple[str, bool, bool] | None:
        st = self._struct_of(var)
        return st.get(field) if st else None

    def _ptrlike(self, name: str) -> bool:
        info = self.var_info.get(name, {})
        typ = info.get("type", "")
        return bool(info.get("array")) or "*" in typ or "[" in typ

    def _local_file_stream(self, name: str) -> bool:
        typ = self.var_info.get(name, {}).get("type", "")
        return bool(re.search(r"\b(?:w?ifstream|fstream|basic_ifstream|basic_fstream)\b", typ))

    def _int_scalar(self, name: str) -> bool:
        info = self.var_info.get(name, {})
        return not info.get("array") and _is_int_type(info.get("type", ""))

    def _raw_value(self, lo: int, hi: int) -> bool:
        """Çok baytlı ham yorum mu: ``*(int *)buf``, ``*(uint32_t *)(p + 4)``? Tek bayt okuma (``buf[i]``, ``*p``) ve
        hesaplama (karma, toplam) sayılmaz — değer aralığı küçüktür ya da saldırganın seçtiği bir uzunluk değildir."""
        toks = self.toks
        if hi - lo < 5 or toks[lo].text != "*" or toks[lo + 1].text != "(":
            return False
        close = match_close(toks, lo + 1, hi)
        inner = toks[lo + 2:close]
        if not inner or inner[-1].text != "*" or not all(x.kind == "id" or x.text in ("*", "::") for x in inner):
            return False
        typ = " ".join(x.text for x in inner[:-1])
        if not _is_int_type(typ) or re.fullmatch(r"(unsigned |signed )?char|u?int8_t|uint8|BYTE|u8|s8", typ):
            return False
        return all(not (toks[j].kind == "id" and toks[j + 1].text == "(") for j in range(close + 1, hi - 1))

    def _byte_assembly(self, lo: int, hi: int) -> bool:
        """Çok baytlı uzunluk birleştirme: ``(buf[0] << 8) | buf[1]``, ``p[2] << 24 | …`` (ağ bayt sırası)."""
        toks = self.toks
        texts = [t.text for t in toks[lo:hi]]
        return "<<" in texts and texts.count("[") >= 2 and not any(
            toks[j].kind == "id" and j + 1 < hi and toks[j + 1].text == "(" for j in range(lo, hi))

    def _alias_target(self, lo: int, hi: int) -> str:
        """``(T *)buf``, ``buf + n``, ``&x``, ``&buf[i]``, ``strchr(buf, c)`` → işaret edilen değişken adı."""
        toks = self.toks
        i = lo
        while i < hi and toks[i].kind == "op" and toks[i].text == "(":
            close = match_close(toks, i, hi)
            inner = toks[i + 1:close]
            if inner and all(x.kind == "id" or x.text in ("*", "&", "::", "<", ">", ",") for x in inner):
                i = close + 1  # tür dönüşümü
                continue
            i += 1  # gruplama parantezi
        amp = i < hi and toks[i].text == "&"
        if amp:
            i += 1
        if i >= hi or toks[i].kind != "id" or toks[i].text in self.SKIP_KEYWORDS:
            return ""
        name = toks[i].text
        if i + 1 < hi and toks[i + 1].text == "(":
            if name in _PTR_INTO_ARG0:
                close = match_close(toks, i + 1, hi)
                ranges = split_args(toks, i + 2, close)
                return self.base_ident(*ranges[0]) if ranges else ""
            return ""
        if amp or self._ptrlike(name):
            return name
        return ""

    def _set_function_alias(self, name: str, target: str) -> None:
        """Koşulsuz atama tek hedef, koşullu farklı atamalar aday kümesi olarak kalır."""
        if not name:
            return
        if not self.branch_depth:
            self.unknown_function_aliases.discard(name)
            self.overflow_function_aliases.discard(name)
            self.ambiguous_function_aliases.discard(name)
            self.function_alias_candidates[name] = {target}
            self.aliases[name] = target
            return
        if name in self.overflow_function_aliases:
            return
        candidates = self.function_alias_candidates.setdefault(name, set())
        if target not in candidates and len(candidates) >= MAX_FUNCTION_ALIAS_CANDIDATES:
            candidates.clear()
            self.aliases.pop(name, None)
            self.ambiguous_function_aliases.add(name)
            self.overflow_function_aliases.add(name)
            self.prog.limitations.add("callback-candidates")
            return
        candidates.add(target)
        if name in self.ambiguous_function_aliases:
            return
        previous = self.aliases.get(name)
        if previous is None or previous == target:
            self.aliases[name] = target
            return
        self.aliases.pop(name, None)
        self.ambiguous_function_aliases.add(name)

    def _function_alias_expr(self, lo: int, hi: int, depth: int = 0) -> tuple[set[str], bool, bool]:
        """Resolve a bounded direct/parenthesized/ternary function-pointer expression.

        Returns ``(targets, recognized, overflowed)``.  The condition of a
        ternary is deliberately ignored: either branch may execute.
        """
        if depth > 8:
            return set(), False, False
        toks = self.toks
        while lo < hi:
            if toks[lo].text != "(":
                break
            close = match_close(toks, lo, hi)
            if close == hi - 1:
                lo += 1
                hi -= 1
                continue
            cast_end = _function_pointer_cast_end(toks, lo, hi, self.cindex().fn_typedefs)
            if cast_end < 0:
                break
            lo = cast_end
        if lo < hi and toks[lo].text == "&":
            lo += 1
        if hi - lo == 1 and toks[lo].kind == "id":
            value = toks[lo].text
            if value in self.overflow_function_aliases:
                return set(), True, True
            targets: set[str] = set()
            # A local function pointer shadows a same-named project function.
            # Otherwise copying that local would incorrectly union both values.
            if value in self.prog.by_name and value not in self.locals and value not in self.param_index:
                targets.add(value)
            elif value in _RECV_OUT and value not in self.locals and value not in self.param_index:
                targets.add(value)
            alias = self.aliases.get(value)
            if alias:
                targets.add(alias)
            targets.update(self.function_alias_candidates.get(value, ()))
            return targets, bool(targets), False
        if lo + 2 < hi and toks[lo].kind == "id" and toks[lo + 1].text == "(" and \
                match_close(toks, lo + 1, hi) == hi - 1:
            ranges = split_args(toks, lo + 2, hi - 1)
            returned: set[str] = set()
            for factory in self.prog.by_name.get(toks[lo].text, ()):
                if len(factory.params) == len(ranges):
                    returned.update(self.cindex().fptr_returns.get(factory.key, ()))
            overflow = len(returned) > MAX_FUNCTION_ALIAS_CANDIDATES
            return (set() if overflow else returned), bool(returned), overflow

        nesting = 0
        question = -1
        for index in range(lo, hi):
            text = toks[index].text
            if text in ("(", "[", "{"):
                nesting += 1
            elif text in (")", "]", "}"):
                nesting = max(0, nesting - 1)
            elif text == "?" and nesting == 0:
                question = index
                break
        if question < 0:
            return set(), False, False
        nested_ternary = 0
        nesting = 0
        colon = -1
        for index in range(question + 1, hi):
            text = toks[index].text
            if text in ("(", "[", "{"):
                nesting += 1
            elif text in (")", "]", "}"):
                nesting = max(0, nesting - 1)
            elif nesting == 0 and text == "?":
                nested_ternary += 1
            elif nesting == 0 and text == ":":
                if nested_ternary:
                    nested_ternary -= 1
                else:
                    colon = index
                    break
        if colon < 0:
            return set(), False, False
        left, left_known, left_overflow = self._function_alias_expr(question + 1, colon, depth + 1)
        right, right_known, right_overflow = self._function_alias_expr(colon + 1, hi, depth + 1)
        return left | right, left_known or right_known, left_overflow or right_overflow

    def _assign_function_alias_expr(self, name: str, lo: int, hi: int) -> bool:
        targets, recognized, overflow = self._function_alias_expr(lo, hi)
        if not recognized:
            return False
        if overflow or len(targets) > MAX_FUNCTION_ALIAS_CANDIDATES:
            self.unknown_function_aliases.discard(name)
            self.function_alias_candidates.pop(name, None)
            self.aliases.pop(name, None)
            self.ambiguous_function_aliases.add(name)
            self.overflow_function_aliases.add(name)
            self.prog.limitations.add("callback-candidates")
            return True
        if self.branch_depth:
            for target in sorted(targets):
                self._set_function_alias(name, target)
            return True
        self.unknown_function_aliases.discard(name)
        self.overflow_function_aliases.discard(name)
        self.function_alias_candidates[name] = set(targets)
        if len(targets) == 1:
            self.ambiguous_function_aliases.discard(name)
            self.aliases[name] = next(iter(targets))
        else:
            self.aliases.pop(name, None)
            self.ambiguous_function_aliases.add(name)
        return True

    def _invalidate_function_alias(self, name: str) -> None:
        """Forget an exact target after an unconditional unresolved overwrite."""
        self.function_alias_candidates.pop(name, None)
        self.aliases.pop(name, None)
        self.ambiguous_function_aliases.add(name)
        self.overflow_function_aliases.discard(name)
        self.unknown_function_aliases.add(name)

    def _copy_function_alias(self, name: str, source: str) -> bool:
        """Copy the bounded target set of one local function pointer to another.

        An unconditional copy replaces the destination just like an ordinary
        assignment.  A copy inside a conditional branch merges with the
        destination's existing alternatives.  An already overflowed source
        remains explicitly unknown instead of being reduced to a partial set.
        """
        if not name or not source:
            return False
        if source in self.overflow_function_aliases:
            self.function_alias_candidates.pop(name, None)
            self.aliases.pop(name, None)
            self.ambiguous_function_aliases.add(name)
            self.overflow_function_aliases.add(name)
            self.prog.limitations.add("callback-candidates")
            return True
        candidates = set(self.function_alias_candidates.get(source, ()))
        exact = self.aliases.get(source)
        if exact:
            candidates.add(exact)
        if not candidates:
            return False
        if len(candidates) > MAX_FUNCTION_ALIAS_CANDIDATES:
            self.function_alias_candidates.pop(name, None)
            self.aliases.pop(name, None)
            self.ambiguous_function_aliases.add(name)
            self.overflow_function_aliases.add(name)
            self.prog.limitations.add("callback-candidates")
            return True
        if not self.branch_depth:
            self.overflow_function_aliases.discard(name)
            self.function_alias_candidates[name] = candidates
            if len(candidates) == 1 and source not in self.ambiguous_function_aliases:
                self.ambiguous_function_aliases.discard(name)
                self.aliases[name] = next(iter(candidates))
            else:
                self.aliases.pop(name, None)
                self.ambiguous_function_aliases.add(name)
            return True
        for candidate in sorted(candidates):
            self._set_function_alias(name, candidate)
        return True

    def _dst_fixed_field(self, r: tuple[int, int]) -> bool:
        """Hedef bir yapının sabit boyutlu dizi alanı mı (``d->name``, ``req.path``)? Yığın ayırma muafiyeti uygulanmaz."""
        toks = self.toks
        a, b = r
        for j in range(a, b - 2):
            if toks[j].kind == "id" and toks[j + 1].text in (".", "->") and toks[j + 2].kind == "id":
                info = self._field_info(toks[j].text, toks[j + 2].text)
                return bool(info and info[1])
        return False

    def _heap_dst(self, r: tuple[int, int]) -> bool:
        dst = self.base_ident(*r)
        return bool(self.var_info.get(dst, {}).get("heap")) and not self._dst_fixed_field(r)

    def _len_sink(self, name: str, dst_r: tuple[int, int], len_rs: list[tuple[int, int]], line: int,
                  taints: list[frozenset] | None = None) -> None:
        """Okuma/kopyalama uzunluğu kirli bir sayıysa ve sınır denetimi yoksa ``memory_len`` hedefi."""
        toks = self.toks
        ids = [t.text for a, b in len_rs for t in toks[a:b] if t.kind == "id"]
        if taints is None:
            taints = [self.evaluate(a, b) for a, b in len_rs]
        t = EMPTY
        for x in taints:
            t = t | x
        t = frozenset(o for o in t if o.numeric or o.label == "param")
        if not t:
            return
        if any(x in self.upper or x in self.lower for x in ids) or \
                any(x in ("sizeof", "strlen", "wcslen", "MIN", "min") for x in ids):
            self.col.evaluated(self.file, "memory_len", line)
            return
        info = self.var_info.get(self.base_ident(*dst_r), {})
        if info.get("heap") and set(ids) & set(info.get("alloc_ids", ())):
            self.col.evaluated(self.file, "memory_len", line)  # tampon aynı uzunlukla ayrılmış
            return
        self.sink("memory_len", f"{name}() uzunluğu", line, t)

    def member_taint(self, name: str) -> frozenset:
        if name in self.env:
            return self.env[name]
        return self.global_taint(name)

    def c_source(self, name: str, ranges: list[tuple[int, int]], line: int) -> frozenset | None:
        toks = self.toks
        if self.prog.resolve(name, self.file, len(ranges)):
            return None
        if name in ("getenv", "_wgetenv", "secure_getenv", "_tgetenv", "g_getenv"):
            key = ""
            if ranges and ranges[0][1] - ranges[0][0] == 1 and toks[ranges[0][0]].kind == "str":
                key = toks[ranges[0][0]].text
            if _CGI_REMOTE_ENV.match(key):
                return self.src("request", f"CGI ortam değişkeni {key}", line, cap=HTTP_FRAMEWORK_CAP)
            return self.src("local", f"ortam değişkeni {key or '(getenv)'}".strip(), line, cap=-1)
        if name in ("GetEnvironmentVariableA", "GetEnvironmentVariableW", "GetEnvironmentVariable") and len(ranges) >= 2:
            self.taint_target(*ranges[1], self.src("local", "ortam değişkeni (GetEnvironmentVariable)", line))
            return EMPTY
        if name in _RECV_OUT and len(ranges) > _RECV_OUT[name]:
            if name in _READ_LEN and len(ranges) > 2:
                self._len_sink(name, ranges[1], [ranges[2]], line)
            cap = self._read_cap(ranges[_RECV_OUT[name]], ranges[2] if len(ranges) > 2 else None)
            self.taint_target(*ranges[_RECV_OUT[name]], self.src("request", f"ağdan okunan veri ({name})", line, cap=cap))
            return EMPTY
        if name in ("read", "_read", "pread", "pread64") and len(ranges) >= 2:
            if len(ranges) >= 3:
                self._len_sink(name, ranges[1], [ranges[2]], line)
            fd = " ".join(t.text for t in toks[ranges[0][0]:ranges[0][1]])
            cap = self._read_cap(ranges[1], ranges[2] if len(ranges) > 2 else None)
            if fd in ("0", "STDIN_FILENO", "fileno ( stdin )"):
                if self.cgi or self.inetd:
                    self.taint_target(*ranges[1], self.src("request", "HTTP istek gövdesi (CGI standart girdi)"
                                                           if self.cgi else "standart girdi (inetd hizmeti, read)",
                                                           line, cap=cap))
                else:
                    self.taint_target(*ranges[1], self.src("local", "standart girdi (read)", line, cap=cap))
            elif self.var_info.get(fd, {}).get("socket"):
                self.taint_target(*ranges[1], self.src("request", f"ağdan okunan veri (read {fd})", line, cap=cap))
            elif _SOCKISH.search(fd) or self._sock_field(fd):
                # soket yalnız ad örüntüsünden tanındı (accept/socket kanıtı yok): kanıtsız kaynak
                self.taint_target(*ranges[1], core.weaken(
                    self.src("request", f"ağdan okunan veri (read {fd})", line, cap=cap)))
            else:
                self.taint_target(*ranges[1], self.src(
                    "local", f"yerel tanımlayıcıdan okunan veri (read {fd})", line, cap=cap,
                ))
            return EMPTY
        if name in _STDIN_OUT:
            out_i, stream_i = _STDIN_OUT[name]
            if len(ranges) > stream_i:
                stream = " ".join(t.text for t in toks[ranges[stream_i][0]:ranges[stream_i][1]])
                sock = self._sock_stream(stream)
                if stream in ("stdin", "std :: cin") or sock:
                    if name in _READ_LEN:
                        self._len_sink(name, ranges[out_i], [ranges[1]], line)
                    label = "request" if self.cgi or sock or self.inetd else "local"
                    desc = f"ağdan okunan veri ({name} {stream})" if sock else \
                        "HTTP istek gövdesi (CGI standart girdi)" if self.cgi else \
                        f"standart girdi (inetd hizmeti, {name})" if self.inetd else f"standart girdi ({name})"
                    cap = self._read_cap(ranges[out_i], ranges[1]) if name in ("fgets", "fgetws") else -1
                    src = self.src(label, desc, line, cap=cap)
                    self.taint_target(*ranges[out_i], src if not sock or self._sock_stream_proven(stream)
                                      else core.weaken(src))
                    return EMPTY
                if name in _READ_LEN:
                    self._len_sink(name, ranges[out_i], [ranges[1]], line)
                cap = self._read_cap(ranges[out_i], ranges[1]) if name in ("fgets", "fgetws") else -1
                self.taint_target(*ranges[out_i], self.src(
                    "local", f"yerel dosyadan okunan veri ({name})", line, cap=cap,
                ))
                return EMPTY
            return None
        if name in ("gets_s", "_getws_s") and len(ranges) >= 2:
            self._len_sink(name, ranges[0], [ranges[1]], line)
            src = self.src(
                "request" if self.cgi or self.inetd else "local",
                "HTTP istek gövdesi (CGI standart girdi)" if self.cgi else
                f"standart girdi (inetd hizmeti, {name})" if self.inetd else
                f"standart girdi ({name})",
                line,
                cap=self._read_cap(ranges[0], ranges[1]),
            )
            self.taint_target(*ranges[0], src)
            return EMPTY
        if name in ("gets", "_getws", "getws"):
            if ranges:
                src = self.src("request", "HTTP istek gövdesi (CGI standart girdi)", line, cap=-1) if self.cgi else \
                    self.src("request", f"standart girdi (inetd hizmeti, {name})", line, cap=-1) if self.inetd else \
                    self.src("local", f"standart girdi ({name})", line, cap=-1)
                self.sink("memory", f"{name}() sınırsız okuma", line, src)
                self.taint_target(*ranges[0], src)
            return EMPTY
        if name in ("vscanf", "vwscanf", "vfscanf", "vfwscanf", "vsscanf", "vswscanf"):
            # The final argument is a va_list cursor, not a destination buffer.
            # Resolving the pointed-to variadic outputs requires caller ABI
            # modeling; tainting the cursor itself creates false data flows.
            return EMPTY
        scanf_names = {
            "scanf", "wscanf", "fscanf", "fwscanf", "sscanf", "swscanf",
            "scanf_s", "wscanf_s", "fscanf_s", "fwscanf_s", "sscanf_s", "swscanf_s",
        }
        scanf_streams = {"fscanf", "fwscanf", "fscanf_s", "fwscanf_s"}
        scanf_strings = {"sscanf", "swscanf", "sscanf_s", "swscanf_s"}
        if name in scanf_names:
            fmt_i = 1 if name in scanf_streams | scanf_strings else 0
            if len(ranges) <= fmt_i:
                return EMPTY
            fa, fb = ranges[fmt_i]
            fmt = toks[fa].text if fb - fa == 1 and toks[fa].kind == "str" else ""
            if name in scanf_strings:
                src_t = self.evaluate(*ranges[0])
            else:
                stream = " ".join(t.text for t in toks[ranges[0][0]:ranges[0][1]]) if fmt_i == 1 else "stdin"
                if stream != "stdin" and self._sock_stream(stream):
                    src_t = self.src("request", f"ağdan okunan veri ({name})", line, cap=-1)
                    if not self._sock_stream_proven(stream):
                        src_t = core.weaken(src_t)
                elif stream != "stdin":
                    src_t = self.src("local", f"yerel dosyadan okunan veri ({name})", line, cap=-1)
                else:
                    src_t = self.src("request" if self.cgi or self.inetd else "local",
                                     f"standart girdi (inetd hizmeti, {name})" if self.inetd else f"standart girdi ({name})",
                                     line, cap=-1)
            if not src_t:
                return EMPTY
            conversion_re = re.compile(
                r"%(?!%)(?:(\d+)\$)?(\*)?[^%a-zA-Z\[]*(?:hh|h|ll|l|j|z|t|L)?(\[[^\]]*\]|[a-zA-Z])"
            )
            conversions = [
                (match.group(3), bool(match.group(2)), int(match.group(1)) if match.group(1) else None)
                for match in conversion_re.finditer(fmt)
            ]
            out_ranges = ranges[fmt_i + 1:]
            if fmt:
                out_index = 0
                for conv, suppressed, position in conversions:
                    if suppressed:
                        continue
                    target_index = position - 1 if position is not None else out_index
                    if position is None:
                        out_index += 1
                    if target_index < 0 or target_index >= len(out_ranges):
                        break
                    a, b = out_ranges[target_index]
                    if conv[:1] in "diouxXfeEgGaAc" and conv != "c":
                        self.taint_target(a, b, numeric(src_t))
                    else:
                        self.taint_target(a, b, strings_only(src_t) or src_t)
                    if position is None and name.endswith("_s") and conv[:1] in "cCsS[" \
                            and out_index < len(out_ranges):
                        out_index += 1
            else:
                # Dynamic formats do not expose which secure-CRT arguments are
                # buffer sizes. Preserve conservative source propagation.
                for a, b in out_ranges:
                    self.taint_target(a, b, strings_only(src_t) or src_t)
            if not name.endswith("_s") and fmt and _SCANF_STR_UNBOUNDED.search(fmt) and \
                    not re.search(r"%\d+[sS\[]", fmt):
                self.sink("memory", f"{name}(\"%s\") sınırsız okuma", line, strings_only(src_t))
            return EMPTY
        if name in ("fgetc", "getc", "_IO_getc") and len(ranges) == 1 and \
                self._sock_stream(" ".join(t.text for t in toks[ranges[0][0]:ranges[0][1]])):
            src = self.src("request", f"ağdan okunan veri ({name})", line, cap=-1)
            return src if self._sock_stream_proven(" ".join(t.text for t in toks[ranges[0][0]:ranges[0][1]])) \
                else core.weaken(src)
        if name in ("fread",) and len(ranges) >= 4 and \
                self._sock_stream(" ".join(t.text for t in toks[ranges[3][0]:ranges[3][1]])):
            self._len_sink(name, ranges[0], [ranges[1], ranges[2]], line)
            src = self.src("request", "ağdan okunan veri (fread)", line, cap=self._read_cap(ranges[0], None))
            if not self._sock_stream_proven(" ".join(t.text for t in toks[ranges[3][0]:ranges[3][1]])):
                src = core.weaken(src)
            self.taint_target(*ranges[0], src)
            return EMPTY
        if name in ("fread",) and len(ranges) >= 4 and self.cgi:
            stream = " ".join(t.text for t in toks[ranges[3][0]:ranges[3][1]])
            if stream == "stdin":
                self._len_sink(name, ranges[0], [ranges[1], ranges[2]], line)
                self.taint_target(*ranges[0], self.src("request", "HTTP istek gövdesi (CGI standart girdi)", line,
                                                       cap=self._read_cap(ranges[0], None)))
                return EMPTY
        if name in ("fread",) and len(ranges) >= 4:
            self._len_sink(name, ranges[0], [ranges[1], ranges[2]], line)
            self.taint_target(*ranges[0], self.src(
                "local", "yerel dosyadan okunan veri (fread)", line, cap=self._read_cap(ranges[0], None),
            ))
            return EMPTY
        if name in ("mysql_real_escape_string", "mysql_escape_string", "PQescapeStringConn", "PQescapeString") and ranges:
            dst = 1 if name.startswith("mysql_real") or name == "PQescapeStringConn" else 0
            if dst < len(ranges):
                self.taint_target(*ranges[dst], EMPTY, strong=True)
                name_ = self.base_ident(*ranges[dst])
                if name_:
                    self.env[name_] = EMPTY
            return EMPTY
        if name in ("sqlite3_mprintf", "sqlite3_snprintf", "sqlite3_vmprintf") and ranges:
            fmt_r = ranges[1] if name == "sqlite3_snprintf" and len(ranges) > 2 else ranges[0]
            if name == "sqlite3_snprintf" and len(ranges) > 2:
                fmt_r = ranges[2]
            fa, fb = fmt_r
            fmt = toks[fa].text if fb - fa == 1 and toks[fa].kind == "str" else ""
            if fmt and "%s" not in fmt and re.search(r"%[qQw]", fmt):
                return EMPTY
            return None
        return None

    def _read_cap(self, dst: tuple[int, int], ln: tuple[int, int] | None) -> int | None:
        """Okunan verinin saldırganca ulaşılabilir en büyük uzunluğu: uzunluk argümanı ve hedef kap boyutunun küçüğü."""
        v = self.length_value(ln) if ln is not None else None
        c = self.container_cap(dst)
        cands = [x for x in (v, c) if x]
        return max(0, min(cands) - 1) if cands else None

    def _sock_field(self, fd: str) -> bool:
        """``conn->fd`` / ``c . sock`` gibi bağlantı yapısının soket alanı."""
        parts = fd.replace(" ", "").replace("->", ".").split(".")
        return len(parts) >= 2 and bool(re.search(r"(?i)^(fd|sock|sockfd|socket|client_fd|cfd|conn_fd|connfd)$",
                                                  parts[-1])) and bool(_SOCKISH.search(parts[0]) or parts[0] in (
            "c", "cl", "con", "req", "request", "session", "sess", "ctx", "s", "st"))

    def _sock_stream_proven(self, stream: str) -> bool:
        """Akış soket olarak kanıtlı mı (fdopen(accept sonucu)); yalnız ad örüntüsü kanıt sayılmaz."""
        return bool(self.var_info.get(stream, {}).get("sockstream"))

    def _sock_stream(self, stream: str) -> bool:
        info = self.var_info.get(stream, {})
        return bool(info.get("sockstream")) or (bool(re.fullmatch(r"\w+", stream)) and bool(
            re.search(r"(?i)sock|client|conn|peer|remote", stream)) and "file" not in stream.lower() and
            stream not in ("stdin", "stdout", "stderr"))

    def framework_call(self, name: str, ranges: list[tuple[int, int]], taints: list[frozenset],
                       line: int) -> frozenset | None:
        """HTTP çatı API'leri (libmicrohttpd, mongoose, civetweb, libevent, FastCGI, onion, ulfius)."""
        if name in self.prog.by_name:
            return None
        if name in _FRAMEWORK_RET:
            return self.src("request", _FRAMEWORK_RET[name], line, cap=HTTP_FRAMEWORK_CAP)
        spec = _FRAMEWORK_OUT.get(name)
        if spec is not None:
            oi, li = spec
            if 0 <= oi < len(ranges):
                cap = self._read_cap(ranges[oi], ranges[li] if 0 <= li < len(ranges) else None)
                if li >= 0 and li < len(ranges) and name in ("mg_read", "evbuffer_remove", "evbuffer_copyout"):
                    self._len_sink(name, ranges[oi], [ranges[li]], line)
                self.taint_target(*ranges[oi], self.src("request", f"HTTP isteği ({name})", line,
                                                        cap=cap if cap is not None else HTTP_FRAMEWORK_CAP))
            return EMPTY
        if name == "fdopen" and ranges:
            fd = " ".join(t.text for t in self.toks[ranges[0][0]:ranges[0][1]])
            if _SOCKISH.search(fd) or self.var_info.get(fd, {}).get("socket") or self._sock_field(fd):
                self._pending_sockstream = True
            return EMPTY
        return None

    def c_sinks(self, name: str, ranges: list[tuple[int, int]], taints: list[frozenset], line: int) -> None:
        toks = self.toks
        if self.cmd_guards and (name in _CMD_DIRECT or name in _EXEC_L or name in _EXEC_V):
            # doğrulayıcı / izin listesi denetiminden geçmiş argümanlar komut hedefi için temiz
            taints = [EMPTY if t and self._cmd_guarded(line, t, ranges[k]) else t for k, t in enumerate(taints)]
        if name in _CMD_DIRECT and len(taints) > _CMD_DIRECT[name]:
            self.sink("command", f"{name}()", line, strings_only(taints[_CMD_DIRECT[name]]))
        elif name in _EXEC_L and len(taints) > _EXEC_L[name]:
            p = _EXEC_L[name]
            path_lit = self._lit(ranges[p])
            lits = {self._lit(r) for r in ranges[p + 1:]}
            shell = bool(_SHELL_RE.search(path_lit)) and bool(lits & _SHELL_FLAGS)
            self.sink("command", f"{name}()", line, strings_only(taints[p]))
            if shell:
                for t in taints[p + 1:]:
                    self.sink("command", f"{name}() kabuk -c", line, strings_only(t))
            else:
                self.col.evaluated(self.file, "command", line)
        elif name in _EXEC_V and len(taints) > _EXEC_V[name] + 1:
            p = _EXEC_V[name]
            path_lit = self._lit(ranges[p])
            self.sink("command", f"{name}()", line, strings_only(taints[p]))
            arr = self.base_ident(*ranges[p + 1])
            lits = self.var_info.get(arr, {}).get("literals", set())
            if _SHELL_RE.search(path_lit) and lits & _SHELL_FLAGS:
                self.sink("command", f"{name}() kabuk -c", line, strings_only(taints[p + 1]))
        if name in _FMT and len(taints) > _FMT[name]:
            fi = _FMT[name]
            fa, fb = ranges[fi]
            if not (fb - fa == 1 and toks[fa].kind == "str"):
                self.sink("format_string", f"{name}() biçim dizgesi", line, strings_only(taints[fi]))
                if self.cgi and name in ("printf", "wprintf"):
                    self.sink("html", f"{name}() CGI HTML çıktısı", line, strings_only(taints[fi]))
            else:
                self.col.evaluated(self.file, "format_string", line)
                fmt = toks[fa].text
                if name in ("sprintf", "vsprintf", "swprintf", "wsprintfA", "wsprintfW", "wsprintf") and \
                        _UNBOUNDED_S.search(fmt) and name not in ("swprintf",):
                    if not self._heap_dst(ranges[0]):
                        for t in taints[fi + 1:]:
                            self.sink("memory", f"{name}(\"%s\")", line, strings_only(t))
                    else:
                        self.col.evaluated(self.file, "memory", line)
            # CGI çıktısı: biçim dizgesi değişken olsa da (printf(sablon, x)) biçimlenen değerler HTML'e gider
            if self.cgi and name in ("printf", "fprintf", "wprintf") and (name != "fprintf" or
                                                                       self._lit_or_id(ranges[0]) == "stdout"):
                for t in taints[fi + 1:]:
                    self.sink("html", f"{name}() CGI HTML çıktısı", line, strings_only(t))
        if self.cgi and name in ("puts", "fputs") and taints:
            if name == "puts" or (len(ranges) > 1 and self._lit_or_id(ranges[1]) == "stdout"):
                self.sink("html", f"{name}() CGI HTML çıktısı", line, strings_only(taints[0]))
        if self.cgi and name in ("write", "_write") and len(taints) >= 2 and \
                self._lit_or_id(ranges[0]) in ("1", "STDOUT_FILENO", "fileno ( stdout )"):
            self.sink("html", f"{name}() CGI HTML çıktısı", line, strings_only(taints[1]))
        if self.cgi and name == "fwrite" and len(taints) >= 4 and self._lit_or_id(ranges[3]) == "stdout":
            self.sink("html", "fwrite() CGI HTML çıktısı", line, strings_only(taints[0]))
        if name in ("fgets", "fgetws", "fread") and len(ranges) > max(_READ_LEN[name][1]):
            d, lens = _READ_LEN[name]
            self._len_sink(name, ranges[d], [ranges[x] for x in lens], line, [taints[x] for x in lens])
        if name in _UNBOUNDED_COPY and len(taints) >= 2:
            d, s = _UNBOUNDED_COPY[name]
            src_name = self.base_ident(*ranges[s])
            if self._heap_dst(ranges[d]) or self.guarded(src_name, ranges[s][0]) or \
                    self._fits(ranges[d], taints[s]):
                self.col.evaluated(self.file, "memory", line)
            else:
                self.sink("memory", f"{name}()", line, strings_only(taints[s]))
        if name in _BOUNDED_COPY and len(taints) > _BOUNDED_COPY[name][2]:
            ln = _BOUNDED_COPY[name][2]
            la, lb = ranges[ln]
            ids = [t.text for t in toks[la:lb] if t.kind == "id"]
            dinfo = self.var_info.get(self.base_ident(*ranges[_BOUNDED_COPY[name][0]]), {})
            if any(self.guarded(x, la) for x in ids) or any(x in ("sizeof", "strlen", "wcslen", "MIN", "min") for x in ids) \
                    or (dinfo.get("heap") and set(ids) & set(dinfo.get("alloc_ids", ()))):
                self.col.evaluated(self.file, "memory_len", line)
            else:
                self.sink("memory_len", f"{name}() uzunluğu", line,
                          frozenset(o for o in taints[ln] if o.numeric or o.label == "param"))
        # 27. tur: HTTP yanıtına HTML olarak yazılan istek verisi (CGI dışı sunucular: dprintf/mg_printf/sprintf …)
        fi_h = _HTTP_OUT_FMT.get(name)
        if fi_h is not None and fi_h < len(ranges) and not self.cgi:
            fmt_lit = self._lit(ranges[fi_h])
            if fmt_lit and _HTML_TAG_RE.search(fmt_lit) and name != "printf" and (
                    name != "fprintf" or self._lit_or_id(ranges[0]) not in ("stderr", "stdout")):
                for t in self.fmt_arg_taints(fmt_lit, taints[fi_h + 1:]):
                    self.sink("html", f"{name}() HTML yanıtı", line, strings_only(t))
                if name in ("sprintf", "snprintf", "asprintf"):
                    self.var_info.setdefault(self.base_ident(*ranges[0]), {})["html"] = True
        if name in ("strcat", "strncat", "strcpy") and len(taints) >= 2 and not self.cgi:
            lit = self._lit(ranges[1]) if ranges[1][1] - ranges[1][0] == 1 else ""
            dst = self.base_ident(*ranges[0])
            if lit and _HTML_TAG_RE.search(lit):
                self.var_info.setdefault(dst, {})["html"] = True
            elif name in ("strcat", "strncat") and self.var_info.get(dst, {}).get("html"):
                self.sink("html", f"{name}() HTML yanıtı", line, strings_only(taints[1]))
        # 27. tur: kod enjeksiyonu — yorumlayıcıya verilen kod ya da derlenecek/yorumlanacak kaynak dosyasına yazım
        if name in _CODE_EVAL and _CODE_EVAL[name] < len(taints) and name not in self.prog.by_name:
            self.sink("code", f"{name}() kod", line, strings_only(taints[_CODE_EVAL[name]]))
        cf_i = {"fprintf": 0, "fputs": 1, "fwrite": 3, "write": 0, "fputc": 1, "dprintf": 0}.get(name)
        if cf_i is not None and cf_i < len(ranges):
            cfile = self.var_info.get(self.base_ident(*ranges[cf_i]), {}).get("codefile")
            if cfile:
                data = [x for k, x in enumerate(taints) if k != cf_i]
                for t in data:
                    self.sink("code", f"{name}() → {cfile} (derlenen/yorumlanan kaynak)", line, strings_only(t))
        if name in _SQL and len(taints) > _SQL[name] and _SQL[name] >= 1:
            self.sink("sql", f"{name}()", line, strings_only(taints[_SQL[name]]))
        if name in _PATH and len(taints) > _PATH[name]:
            if self._path_guarded(line, taints[_PATH[name]], ranges[_PATH[name]]):
                self.col.evaluated(self.file, "path", line)
            else:
                self.sink("path", f"{name}()", line, strings_only(taints[_PATH[name]]))
        if name in _LDAP and len(taints) > _LDAP[name]:
            self.sink("ldap", f"{name}() filtresi", line, strings_only(taints[_LDAP[name]]))
        if name in ("curl_easy_setopt",) and len(taints) >= 3:
            opt = " ".join(t.text for t in toks[ranges[1][0]:ranges[1][1]])
            if opt in ("CURLOPT_URL",):
                self.sink("ssrf", "curl_easy_setopt(CURLOPT_URL)", line, strings_only(taints[2]))

    def c_propagate(self, name: str, ranges: list[tuple[int, int]], taints: list[frozenset]) -> frozenset | None:
        """Kopyalama/birleştirme: hedef argüman kaynağın kirliliğini alır; dönüş değeri hedeftir."""
        toks = self.toks
        if name in _UNBOUNDED_COPY and len(taints) >= 2:
            d, s = _UNBOUNDED_COPY[name]
            strong = name.endswith("cpy") and "cat" not in name
            self._note_deps(self.base_ident(*ranges[d]), *ranges[s], replace=strong)
            cap = self.container_cap(ranges[d])
            val = self.capped(taints[s], None if cap is None else cap - 1)
            sa, sb = ranges[s]
            clean_literal = strong and not val and sb - sa == 1 and toks[sa].kind == "str"
            self.taint_target(*ranges[d], val, strong=strong, clean=clean_literal)
            return val | (EMPTY if strong else taints[d])
        if name in _BOUNDED_COPY and len(taints) >= 2:
            d, s, ln = _BOUNDED_COPY[name]
            if s < len(ranges):
                self._note_deps(self.base_ident(*ranges[d]), *ranges[s], replace=False)
            if s < len(taints):
                cap = self.container_cap(ranges[d])
                lv = self.length_value(ranges[ln]) if ln < len(ranges) else None
                caps = [x for x in (None if cap is None else cap - 1, lv) if x is not None]
                val = self.capped(taints[s], min(caps) if caps else None)
                self.taint_target(*ranges[d], val, strong=False)
                return val | taints[d]
        if name in ("sprintf", "snprintf", "swprintf", "vsprintf", "vsnprintf", "_snprintf", "_snwprintf",
                    "wsprintfA", "wsprintfW", "wsprintf", "asprintf", "vasprintf") and len(ranges) >= 2:
            fi = _FMT.get(name, 1)
            add = EMPTY
            fmt_lit = self._lit(ranges[fi]) if fi < len(ranges) and ranges[fi][1] - ranges[fi][0] == 1 else ""
            for t in (self.fmt_arg_taints(fmt_lit, taints[fi + 1:]) if fmt_lit else taints[fi + 1:]):
                add = add | t
            if fi < len(ranges):
                fa, fb = ranges[fi]
                if fb - fa == 1 and toks[fa].kind == "str" and self.fixed_host_literal(toks[fa].text):
                    add = core.with_host(add)
                if fb - fa == 1 and toks[fa].kind == "str" and _SRC_EXT_RE.search(toks[fa].text.strip()):
                    self.var_info.setdefault(self.base_ident(*ranges[0]), {})["srcpath"] = True
                add = add | (taints[fi] if not (fb - fa == 1 and toks[fa].kind == "str") else EMPTY)
            dst_name = self.base_ident(*ranges[0])
            self._note_deps(dst_name, ranges[min(fi, len(ranges) - 1)][0], ranges[-1][1], replace=True)
            cap = self.container_cap(ranges[0])
            if name in ("snprintf", "_snprintf", "vsnprintf", "_vsnprintf", "swprintf", "_snwprintf") and len(ranges) > 1:
                lv = self.length_value(ranges[1])
                cap = lv if cap is None or (lv is not None and lv < cap) else cap
            add = self.capped(add, None if cap is None else cap - 1)
            self.taint_target(*ranges[0], add, strong=True)
            return EMPTY
        if name in ("strtok", "strtok_r", "strsep") and ranges:
            # strtok(NULL, …): önceki çağrının tamponundan devam eder
            if self._lit_or_id(ranges[0]) in ("NULL", "0", "nullptr"):
                return self._strtok_taint
            self._strtok_taint = taints[0]
            if name == "strtok_r" and len(ranges) >= 3:
                self.taint_target(*ranges[2], taints[0])
            return taints[0]
        if name in ("strdup", "strndup", "_strdup", "wcsdup", "_wcsdup", "g_strdup", "xstrdup", "estrdup",
                    "realpath", "strtok", "strtok_r", "string", "wstring", "basic_string", "move", "to_string",
                    "QString", "fromStdString"):
            if name in ("realpath",) and len(taints) >= 2:
                self.taint_target(*ranges[1], taints[0], strong=False)
            return taints[0] if taints else EMPTY
        if name in ("strchr", "strrchr", "strstr", "strpbrk"):
            return taints[0] if taints else EMPTY
        return None

    _CONV_RE = re.compile(r"%[-+ #0']*(?:\*|\d+)?(?:\.(?:\*|\d+))?(?:hh|h|ll|l|j|z|t|L|q)?([a-zA-Z%])")

    def fmt_arg_taints(self, fmt: str, taints: list[frozenset]) -> list[frozenset]:
        """Biçim dizgesine göre argüman kirliliği: %s/%S dışındaki dönüşümler (sayı, karakter, işaretçi) dizge
        enjeksiyonu taşımaz → sayısal kökene indirgenir (``snprintf(q, n, "id=%d", r->id)``)."""
        convs = [c for c in self._CONV_RE.findall(fmt) if c != "%"]
        out = []
        k = 0
        for c in convs:
            if k >= len(taints):
                break
            if c in "*":
                k += 1
                continue
            out.append(taints[k] if c in "sS" else numeric(taints[k]))
            k += 1
        out.extend(taints[len(out):])
        return out

    def _note_deps(self, name: str, lo: int, hi: int, *, replace: bool) -> None:
        """Yerel türetme ilişkisi: ``x = f(a, b)``, ``strcpy(x, a)``, ``sprintf(x, "%s/%s", a, b)`` → x ← {a, b}."""
        if not name:
            return
        toks = self.toks
        names = {toks[j].text for j in range(lo, hi) if toks[j].kind == "id" and toks[j].text not in self.SKIP_KEYWORDS
                 and not (j + 1 < hi and toks[j + 1].text == "(") and not (j > lo and toks[j - 1].text in (".", "->"))
                 and toks[j].text != name}
        deps = self.__dict__.setdefault("var_deps", {})
        if replace or name not in deps:
            deps[name] = names
        else:
            deps[name] = deps[name] | names

    def _path_guarded(self, line: int, t: frozenset, r: tuple[int, int] | None = None) -> bool:
        """Yol argümanının türediği bütün kirli değişkenler dizin geçişi denetiminden/doğrulayıcıdan geçmiş mi?"""
        return self._guarded_by(self.path_guards, line, t, r)

    def _cmd_guarded(self, line: int, t: frozenset, r: tuple[int, int] | None = None) -> bool:
        """Komut argümanının türediği bütün kirli değişkenler doğrulayıcıdan/izin listesinden geçmiş mi?"""
        return self._guarded_by(self.cmd_guards, line, t, r)

    def sink_arg_guarded(self, kind: str, param: int, arg_ranges: list[tuple[int, int]] | None, line: int) -> bool:
        """Çağrı yerinde argüman, çağrılanın içindeki hedef için arındırılmış mı (çağıranda doğrulama/izin listesi)."""
        if arg_ranges is None or param >= len(arg_ranges):
            return False
        guards = self.cmd_guards if kind in ("command", "code") else self.path_guards if kind == "path" else None
        if not guards:
            return False
        return self._guarded_by(guards, line, frozenset({True}), arg_ranges[param])

    def _guarded_by(self, guards: list[tuple[int, int, str]], line: int, t: frozenset,
                    r: tuple[int, int] | None = None) -> bool:
        if not guards or not t or r is None:
            return False
        guarded = {var for a, b, var in guards if a <= line <= b}
        if not guarded:
            return False
        toks = self.toks
        deps = self.__dict__.get("var_deps", {})
        start = {toks[j].text for j in range(*r) if toks[j].kind == "id" and toks[j].text not in self.SKIP_KEYWORDS
                 and not (j + 1 < r[1] and toks[j + 1].text == "(") and not (j > r[0] and toks[j - 1].text in (".", "->"))}
        seen: set[str] = set()
        stack = list(start)
        reached_guard = False
        while stack:
            v = stack.pop()
            if v in seen:
                continue
            seen.add(v)
            if v in guarded:
                reached_guard = True
                continue
            sub = deps.get(v)
            if sub:
                stack.extend(sub)
            elif self.var_taint(v):
                return False  # denetlenmemiş kirli yaprak
        return reached_guard

    def _fits(self, dst: tuple[int, int], t: frozenset) -> bool:
        """Kirli dizginin bütün kökenlerinin ulaşılabilir uzunluğu biliniyor ve hedef kaba sığıyor mu?"""
        real = [o for o in strings_only(t) if o.label != "param"]
        if not real or any(o.cap is None or o.cap < 0 for o in real):
            return False
        cap = self.container_cap(dst)
        return cap is not None and max(o.cap for o in real) + 1 <= cap

    def _http_stream(self, r: tuple[int, int] | None) -> bool:
        if r is None:
            return False
        name = self.base_ident(*r)
        return bool(name) and (bool(self.var_info.get(name, {}).get("sockstream")) or self._sock_stream(name))

    def _lit(self, r: tuple[int, int]) -> str:
        a, b = r
        toks = self.toks
        for j in range(a, b):
            if toks[j].kind == "str":
                return toks[j].text
        return ""

    def _lit_or_id(self, r: tuple[int, int]) -> str:
        a, b = r
        return " ".join(t.text for t in self.toks[a:b])

    # -- 27. tur: dosyalar arası model (yapı alanları, işlev işaretçileri, kap boyutu, olgular) ---------------

    _ci: "CIndex | None" = None

    def cindex(self) -> "CIndex":
        idx = self._ci
        if idx is not None:
            return idx
        idx = getattr(self.prog, "cindex", None)
        if idx is None:
            idx = build_cindex(self.prog.units, self.prog.by_name)
            self.prog.cindex = idx
        self._ci = idx
        return idx

    def _struct_type(self, var: str) -> str:
        structs = self.unit.info.get("structs") or {}
        root = re.match(r"[A-Za-z_]\w*", var or "")
        root_name = root.group(0) if root else var
        typ = self.var_info.get(root_name, {}).get("type", "")
        if not typ:
            g = self.unit.info.get("global_types", {}).get(root_name)
            typ = g or ""
        for word in reversed(re.findall(r"[A-Za-z_]\w*", typ)):
            if word in structs and word != root_name:
                return word
        return ""

    def _expression_instance(self, lo: int, hi: int, *, receiver: bool = False) -> str:
        """Sabit yerel yapı yolu: ``items[0].inner.value`` için öğe/alıcı kimliği.

        ``receiver=True`` son alanı atar; böylece alan yazımı ``items[0].inner`` örneğine bağlanır.
        Değişken indekslerde güvenli tür düzeyi fallback için yalnız kök döner.
        """
        toks = self.toks
        i = lo
        while i < hi and toks[i].text in ("*", "&", "("):
            i += 1
        if i >= hi or toks[i].kind != "id":
            return ""
        identity = toks[i].text
        i += 1
        member_positions = [j for j in range(i, hi - 1)
                            if toks[j].text in (".", "->") and toks[j + 1].kind == "id"]
        stop = member_positions[-1] if receiver and member_positions else hi
        while i < stop:
            if toks[i].text == "[":
                close = match_close(toks, i, stop)
                inner = toks[i + 1:close]
                if len(inner) != 1 or inner[0].kind != "num" or not re.fullmatch(r"\d+", inner[0].text):
                    return identity.split("[", 1)[0].split(".", 1)[0]
                identity += f"[{int(inner[0].text)}]"
                i = close + 1
                continue
            if toks[i].text in (".", "->") and i + 1 < stop and toks[i + 1].kind == "id":
                identity += "." + toks[i + 1].text
                i += 2
                continue
            i += 1
        return identity

    def _field_type(self, stype: str, fname: str) -> str:
        info = ((self.unit.info.get("structs") or {}).get(stype) or {}).get(fname)
        if not info:
            return ""
        structs = self.unit.info.get("structs") or {}
        for word in reversed(re.findall(r"[A-Za-z_]\w*", info[0])):
            if word in structs:
                return word
        return ""

    def field_cap(self, stype: str, fname: str) -> int | None:
        raw = ((self.unit.info.get("struct_caps") or {}).get(stype) or {}).get(fname)
        if raw is None:
            return None
        if isinstance(raw, int):
            return raw
        return _decl_cap(raw[0], raw[1], self.unit.info.get("num_macros"))

    def access_key(self, lo: int, hi: int) -> tuple[tuple, int | None] | None:
        """``req->path``, ``c->req.query``, ``s[i].name`` (yazma hedefi) → (("#F", yapı, alan), alan dizi kapasitesi)."""
        toks = self.toks
        j = lo
        while j < hi and toks[j].kind == "op" and toks[j].text in ("*", "&", "("):
            j += 1
        if j >= hi or toks[j].kind != "id":
            return None
        stype = self._struct_type(toks[j].text)
        containers = self.cindex().containers
        key = None
        k = j + 1
        while k < hi:
            x = toks[k]
            if x.text == "[":
                k = match_close(toks, k, hi) + 1
                continue
            if x.text in (".", "->") and k + 1 < hi and toks[k + 1].kind == "id":
                f = toks[k + 1].text
                if not stype or stype in containers:
                    return key
                key = (("#F", stype, f), self.field_cap(stype, f))
                stype = self._field_type(stype, f)
                k += 2
                continue
            break
        return key

    def container_cap(self, r: tuple[int, int]) -> int | None:
        """Hedef kabın bayt boyutu: yerel/küresel sabit dizi, sabit boyutlu ayırma, yapının dizi alanı."""
        a, b = r
        toks = self.toks
        ak = self.access_key(a, b)
        if ak is not None:
            return ak[1]
        name = self.base_ident(a, b)
        if not name:
            return None
        info = self.var_info.get(name, {})
        if info.get("cap") and not any(t.text in ("+", "-") for t in toks[a:b]):
            return info["cap"]
        gcap = self.unit.info.get("global_caps", {}).get(name)
        if gcap and not any(t.text in ("+", "-") for t in toks[a:b]):
            return gcap
        return None

    def length_value(self, r: tuple[int, int]) -> int | None:
        """Uzunluk argümanı sabiti: ``64``, ``sizeof(buf)``, ``sizeof buf - 1``, ``BUFSZ``."""
        a, b = r
        toks = self.toks
        items: list[Tok] = []
        q = a
        while q < b:
            t = toks[q]
            if t.kind == "id" and t.text == "sizeof":
                inner_a, inner_b = q + 1, q + 2
                if q + 1 < b and toks[q + 1].text == "(":
                    close = match_close(toks, q + 1, b)
                    inner_a, inner_b = q + 2, close
                    q = close + 1
                else:
                    q += 2
                cap = self.container_cap((inner_a, inner_b))
                if cap is None:
                    return None
                items.append(Tok("num", str(cap), t.line))
                continue
            items.append(t)
            q += 1
        return _dim_value(items, self.unit.info.get("num_macros"))

    def capped(self, t: frozenset, cap: int | None) -> frozenset:
        if cap is None or not t:
            return t
        return frozenset(o.with_cap(cap) if o.label != "param" else o for o in t)

    def field_taint(self, key: tuple) -> frozenset:
        self.gdeps.add(key)
        t = self.prog.globals.get(key) or EMPTY
        if t:
            idx = self.cindex()
            if idx.file_programs:
                t = frozenset(o for o in t if idx.same_program(o.file, self.file))
        return t

    def _local_struct_instance(self, name: str | None) -> str:
        """Somut stack yapı alıcısını çöz; parametre/bilinmeyen işaretçi tür düzeyi modele düşer."""
        if not name:
            return ""
        match = re.match(r"([A-Za-z_]\w*)(.*)\Z", name)
        if not match:
            return ""
        current, suffix = match.group(1), match.group(2)
        seen: set[str] = set()
        for _ in range(8):
            if current in seen:
                return ""
            seen.add(current)
            target = self.var_info.get(current, {}).get("points_to")
            if not target:
                break
            current = target
        info = self.var_info.get(current, {})
        typ = info.get("type", "")
        if current not in self.locals or "*" in typ or not self._struct_type(current):
            return ""
        if info.get("array") and not re.match(r"^\[\d+\](?:\.|\Z)", suffix):
            return ""
        return current + suffix

    def _local_array_wildcard(self, name: str | None) -> str:
        """Çözülemeyen yerel yapı dizisi elemanı için bütün elemanlarla örtüşen kimlik."""
        match = re.match(r"([A-Za-z_]\w*)", name or "")
        if not match:
            return ""
        root = match.group(1)
        info = self.var_info.get(root, {})
        return f"{root}[*]" if root in self.locals and info.get("array") and self._struct_type(root) else ""

    def _record_receiver_field(self, receiver_param: int, key: tuple, cap: int | None,
                               taint: frozenset, line: int) -> None:
        if not taint:
            return
        skey = (receiver_param, key)
        writes = self.summary.receiver_field_writes
        if skey not in writes and len(writes) >= core.MAX_FIELD_WRITES:
            self.prog.limitations.add("field-writes")
            return
        writes.setdefault(skey, set()).update(compact(taint))
        self.summary.receiver_field_sites.setdefault(
            skey, (f"{self.file}:{line} {key[1]}.{key[2]} alıcı alanına yazım", cap),
        )

    def _write_receiver_field(self, receiver: str, key: tuple, cap: int | None, taint: frozenset,
                              line: int, *, strong: bool = False) -> bool:
        """Alan etkisini somut yerel örneğe veya alıcı parametre özetine uygula; çözülemezse False."""
        instance = self._local_struct_instance(receiver)
        if instance:
            ikey = (instance, key)
            if strong and not self.branch_depth:
                self.instance_fields[ikey] = compact(taint)
            elif taint:
                self.instance_fields[ikey] = compact(self.instance_fields.get(ikey, EMPTY) | taint)
            elif not self.branch_depth:
                self.instance_fields[ikey] = EMPTY
            return True
        wildcard = self._local_array_wildcard(receiver)
        if wildcard:
            # Bilinmeyen indeks tek bir elemanı yazar; kir bütün olası elemanlara ulaşır ancak temiz yazım
            # bütün diziyi güçlü biçimde temizleyemez.
            if taint:
                ikey = (wildcard, key)
                self.instance_fields[ikey] = compact(self.instance_fields.get(ikey, EMPTY) | taint)
            return True
        pidx = self.param_index.get(receiver)
        if pidx is not None:
            self._record_receiver_field(pidx, key, cap, taint, line)
            return True
        return False

    def _apply_receiver_field_effects(self, cands: list[Func], arg_taints: list[frozenset], line: int,
                                      name: str, arg_ranges: list[tuple[int, int]] | None) -> None:
        if arg_ranges is None:
            return
        hop = self.call_hop(line, name)
        cweak = self.call_weak(cands, name)
        for fn in cands:
            if fn.key == self.fn.key:
                continue
            summary = self.prog.summary(fn)
            for (receiver_param, key), origins in summary.receiver_field_writes.items():
                if receiver_param >= len(arg_ranges):
                    continue
                actual: set[Origin] = set()
                for origin in origins:
                    if origin.label == "param":
                        if origin.param < len(arg_taints):
                            actual.update(x.through(fn.name, hop, xfer=True, weak=cweak or origin.weak)
                                          for x in arg_taints[origin.param])
                    else:
                        actual.add(origin.through(fn.name, hop, xfer=True, weak=cweak))
                if not actual:
                    continue
                receiver = self._expression_instance(*arg_ranges[receiver_param]) or \
                    self.base_ident(*arg_ranges[receiver_param])
                site = summary.receiver_field_sites.get((receiver_param, key))
                cap = site[1] if site is not None else None
                applied = self._write_receiver_field(receiver, key, cap, compact(actual), line)
                if not applied:
                    # Bilinmeyen/kaçmış alıcı mevcut tür düzeyi özetini kullanır; çağrı etkisini de kaybetme.
                    for origin in actual:
                        self.apply_field_write(key, origin, fn, hop, summary)

    _CHARISH_WORDS = frozenset({"char", "uint8_t", "u8", "u_char", "uchar", "gchar", "guchar", "BYTE", "UCHAR",
                                "CHAR", "TCHAR", "wchar_t", "int8_t", "sds"})

    def expand_raw_struct(self, var: str, taint: frozenset, line: int) -> None:
        """Ağdan ham okunan yapı (``recv(fd, &hdr, sizeof hdr)``, ``struct msg *m = (struct msg *)buf``): bütün alanları
        saldırgan denetiminde — tamsayı alanları (uzunluk: keylen, payload_size, declared_len) sayısal kirli."""
        if not any(o.label == "request" and not o.numeric for o in taint):
            return
        stype = self._struct_type(var)
        if not stype or stype in self.cindex().containers:
            return
        fields = (self.unit.info.get("structs") or {}).get(stype) or {}
        req = frozenset(o for o in taint if o.label == "request" and not o.numeric)
        for fname in list(fields)[:64]:
            key = ("#F", stype, fname)
            kind = self.field_kind(key)
            if kind == "num":
                self.write_field(key, None, numeric(req), line)
            elif kind == "str":
                self.write_field(key, self.field_cap(stype, fname), req, line)

    def field_key_ok(self, key: tuple) -> bool:
        return bool(self.field_kind(key))

    def _field_ids(self, key: tuple) -> set:
        """Alana yazılmış kaynak kimlikleri (kaynak, satır, dosya, sayısal) — tekrar yazımı hızla elemek için."""
        store = self.cindex().field_ids
        ids = store.get(key)
        if ids is None:
            ids = store[key] = set()
        return ids

    def field_kind(self, key: tuple) -> str:
        """Alan duyarlı küresel kirlilik yalnız dizgi (char işaretçisi/dizisi) ve tamsayı alanlarında tutulur; kap
        türündeki (buffer *, mg_str) ya da çok biçimli alanlar (aynı alana farklı anlamlar) birleştirilmez."""
        cache = self.cindex().field_kinds
        k = cache.get(key)
        if k is None:
            k = cache[key] = self._field_kind(key)
        return k

    def _field_kind(self, key: tuple) -> str:
        info = ((self.unit.info.get("structs") or {}).get(key[1]) or {}).get(key[2])
        if not info or "{" in info[0] or "union" in info[0].split():
            return ""  # iç içe birlik/yapı üyesi (union { void *v; char *s; … } v): çok biçimli
        words = set(re.findall(r"[A-Za-z_]\w*", info[0])) - {"const", "volatile", "unsigned", "signed", "struct"}
        if words & self._CHARISH_WORDS and (info[1] or info[2] or "sds" in words):
            return "str"
        if not info[1] and not info[2] and _is_int_type(info[0]):
            return "num"
        return ""

    def _field_accepts(self, kind: str, o: Origin) -> bool:
        return (kind == "str" and not o.numeric) or (kind == "num" and o.numeric)

    def write_field(self, key: tuple, cap: int | None, taint: frozenset, line: int) -> None:
        if not taint:
            return
        fkind = self.field_kind(key)
        if not fkind:
            return
        idx = self.cindex()
        taint = frozenset(o for o in taint if o.label == "param" or (self._field_accepts(fkind, o) and
                                                                     idx.model_origin_ok(o)))
        hop = f"{self.file}:{line} {key[1]}.{key[2]} alanına yazım"
        real = set()
        for o in taint:
            if o.label == "param":
                if key not in self.summary.field_writes and len(self.summary.field_writes) >= core.MAX_FIELD_WRITES:
                    self.prog.limitations.add("field-writes")
                    continue
                self.summary.field_writes.setdefault(key, set()).add(-(o.param + 1) if o.numeric else o.param)
                sites = getattr(self.summary, "field_sites", None)
                if sites is None:
                    sites = self.summary.field_sites = {}
                sites.setdefault(key, (hop, cap))
            elif sum(1 for h in o.hops if h.endswith("alanına yazım")) < MAX_FIELD_HOPS:
                ids = self._field_ids(key)
                ident = (o.source, o.line, o.file, o.numeric)
                if ident in ids:
                    continue
                ids.add(ident)
                real.add(self._field_origin(o, cap, hop))
        if real:
            self.write_global_key(key, frozenset(real))

    @staticmethod
    def _field_origin(o: Origin, cap: int | None, hop: str) -> Origin:
        """Alan kirliliği yeni bir başlangıçtır: çağrı zinciri (via) sıfırlanır, kanıt adımları (hops) korunur."""
        o2 = Origin(o.label, o.source, o.line, o.file, (), o.numeric, -1, o.fixed_host, o.cap, o.hops, weak=True)
        return o2.with_cap(cap).with_hop(hop)

    def apply_field_write(self, key: tuple, o: Origin, fn: Func, hop: str, summary: Any) -> None:
        if not self._field_accepts(self.field_kind(key), o) or not self.cindex().model_origin_ok(o):
            return
        ids = self._field_ids(key)
        ident = (o.source, o.line, o.file, o.numeric)
        if ident in ids:
            return  # aynı kaynak bu alanda zaten var (yalnız kanıt zinciri farklı): sabit noktayı oynatmaz
        if sum(1 for h in o.hops if h.endswith("alanına yazım")) >= MAX_FIELD_HOPS:
            return
        ids.add(ident)
        site = (getattr(summary, "field_sites", None) or {}).get(key)
        o2 = o.with_hop(hop)
        if site is not None:
            o2 = self._field_origin(o2, site[1], site[0])
        else:
            o2 = self._field_origin(o2, None, "")
        self.write_global_key(key, frozenset({o2}))

    def call_hop(self, line: int, name: str) -> str:
        return f"{self.file}:{line} {name}()"

    _indirect = False
    cmd_guards: list = []

    def call_weak(self, cands: list[Func], name: str) -> bool:
        """Çağrı kanıtlı mı: doğrudan çağrı, tek aday ve aday ya çağıranla aynı dosyada ya da projede o adla tek
        tanım (bağlayıcı aynı adda iki dış tanıma izin vermez). İşlev işaretçisi/tablo/takma ad ve çok adaylı ad
        eşleşmesi kanıtsızdır."""
        if self._indirect or len(cands) != 1 or name in self.aliases:
            return True
        fn = cands[0]
        if fn.name != name:
            return True
        return fn.file != self.file and len(self.prog.by_name.get(fn.name, ())) != 1

    def note_call(self, fn: Func, arg_taints: list[frozenset], line: int,
                  arg_ranges: list[tuple[int, int]] | None) -> None:
        if not self.final:
            return
        facts = self.col.facts
        hop = f"{self.file}:{line} {fn.name}()"
        for i, t in enumerate(arg_taints):
            if i >= len(fn.params) or not t:
                continue
            key = (fn.file, fn.name, i)
            for o in t:
                if o.label == "param":
                    facts.setdefault("edges", {}).setdefault(key, set()).add((self.file, self.fn.name, o.param, hop))
                else:
                    cur = facts.setdefault("param_in", {}).setdefault(key, set())
                    if len(cur) < 8:
                        cur.add(o.with_hop(hop))

    def apply(self, cands: list[Func], arg_taints: list[frozenset], line: int, name: str,
              arg_ranges: list[tuple[int, int]] | None = None) -> frozenset:
        if not self._indirect and _is_escaper(name):
            # proje içindeki kaçışlama/tırnaklama yardımcısı (shell_escape, html_escape, quote_arg …): çıktısı
            # (dönüş ve çıkış parametreleri) arınmış; yardımcının kendi içindeki hedefler (bellek) yine uygulanır.
            # url_decode / unescape / unquote / decode arındırıcı DEĞİLDİR (bkz. _is_escaper).
            super().apply(cands, arg_taints, line, name, None)
            if arg_ranges is not None:
                for fn in cands:
                    for p in self.prog.summary(fn).out_params:
                        if p < len(arg_ranges):
                            base = self.base_ident(*arg_ranges[p])
                            if base and (base in self.locals or base in self.param_index):
                                self.env[base] = EMPTY
            return EMPTY
        res = super().apply(cands, arg_taints, line, name, arg_ranges)
        self._apply_receiver_field_effects(cands, arg_taints, line, name, arg_ranges)
        if arg_ranges is not None and not self._indirect:
            for wrapper in cands:
                for callback_param, mapped in self.cindex().callback_calls.get(wrapper.key, ()):
                    if callback_param >= len(arg_ranges):
                        continue
                    names = self._callback_targets(arg_ranges[callback_param])
                    targets = [fn for target in names for fn in self.prog.by_name.get(target, ())
                               if len(fn.params) == len(mapped)]
                    if not targets or len(targets) > 16:
                        continue
                    callback_taints = [arg_taints[p] if 0 <= p < len(arg_taints) else EMPTY for p in mapped]
                    callback_ranges = [arg_ranges[p] if 0 <= p < len(arg_ranges) else (0, 0) for p in mapped]
                    self._indirect = True
                    try:
                        self.apply(targets, callback_taints, line, sorted(names)[0], callback_ranges)
                    finally:
                        self._indirect = False
        if self.final:
            calls = self.col.facts.setdefault("calls", {}).setdefault(self.fn.name, set())
            for f in cands:
                calls.add(f.name)
            real = frozenset(o for o in res if o.label != "param")
            if real:
                self.col.facts.setdefault("call_ret", {})[(self.file, line, name)] = real
            if arg_ranges:
                for i, r in enumerate(arg_ranges):
                    base = self.base_ident(*r)
                    if not base:
                        continue
                    t = frozenset(o for o in self.var_taint(base) if o.label != "param")
                    if t and t != frozenset(o for o in arg_taints[i] if o.label != "param"):
                        self.col.facts.setdefault("call_out", {})[(self.file, line, name, i)] = t
        return res

    def _callback_targets(self, arg_range: tuple[int, int]) -> set[str]:
        a, b = arg_range
        ids = [t.text for t in self.toks[a:b] if t.kind == "id"]
        out: set[str] = set()
        for value in ids:
            if value in self.prog.by_name and value not in self.locals and value not in self.param_index:
                out.add(value)
            alias = self.aliases.get(value)
            if alias:
                out.add(alias)
            if value not in self.overflow_function_aliases:
                out.update(self.function_alias_candidates.get(value, ()))
            out.update(self.cindex().fptr_vars.get(value, ()))
        return out

    def indirect(self, key: Any, kind: str, open_: int, close: int, line: int) -> frozenset:
        """İşlev işaretçisiyle çağrı: ``routes[i].handler(req)``, ``fp(x)``, ``(*fp)(x)``, ``table[i](x)``."""
        toks = self.toks
        ranges = split_args(toks, open_ + 1, close)
        taints = self.arg_taints(ranges)
        return self.indirect_apply(key, kind, ranges, taints, line)

    def indirect_apply(self, key: Any, kind: str, ranges: list[tuple[int, int]], taints: list[frozenset],
                       line: int) -> frozenset:
        idx = self.cindex()
        table = idx.fptr_fields if kind == "field" else idx.fptr_receivers if kind == "receiver" else idx.fptr_vars
        locally_unknown = kind == "var" and key in self.unknown_function_aliases
        locally_overflowed = kind == "var" and key in self.overflow_function_aliases
        names = set() if locally_unknown or locally_overflowed else set(table.get(key, set()))
        if kind == "var" and not locally_overflowed:
            names.update(self.function_alias_candidates.get(key, ()))
        if kind == "var" and key in self.param_index:
            if any(cb_param == self.param_index[key] for cb_param, _args in
                   idx.callback_calls.get(self.fn.key, ())):
                # Bu sarmalayıcı çağrı yerinde somut callback ile uygulanır; bütün kayıtlı hedefleri burada
                # birleştirmek ``invoke(safe, tainted)`` için yanlış pozitif üretirdi.
                out: set[Origin] = set()
                for item in taints:
                    out.update(item)
                return core.weaken(compact(out))
            names.update(idx.fptr_params.get((self.fn.key, self.param_index[key]), ()))
        for source_name in sorted(names & set(_RECV_OUT)):
            self.c_source(source_name, ranges, line)
        cands = []
        for nm in sorted(names):
            for f in self.prog.by_name.get(nm, ()):
                if len(f.params) == len(taints) or (f.params and f.params[-1].type_text.strip() == "..."):
                    cands.append(f)
        if len(cands) > 16:
            cands = []
        if cands:
            self._indirect = True
            try:
                return self.apply(cands, taints, line, key, ranges)
            finally:
                self._indirect = False
        out: set[Origin] = set()
        for t in taints:
            out |= t
        return core.weaken(compact(out))

    def postfix(self, i: int, hi: int, cur: frozenset, base: str | None) -> tuple[int, frozenset]:
        toks = self.toks
        arr_base = None
        ftype = None  # yapı türü yalnız alan erişiminde (tembel) çözülür
        while i < hi:
            t = toks[i]
            if t.kind == "op" and t.text in (".", "->") and i + 1 < hi and toks[i + 1].kind in ("id", "num"):
                receiver_base = base
                if ftype is None:
                    ftype = self._struct_type(base) if base else ""
                instance = self._local_struct_instance(base)
                m = toks[i + 1].text
                k = i + 2
                if k < hi and toks[k].text == "(":
                    close = match_close(toks, k, hi)
                    cur = self.method(m, i, k, close, cur, base, "")
                    base = None
                    ftype = ""
                    i = close + 1
                    continue
                cur = self.field(cur, base, m, t.text)
                if ftype and ftype not in self.cindex().containers:
                    key = ("#F", ftype, m)
                    # Somut yerel örnekte yalnız alıcıya özelleştirilmiş örtüyü oku. Parametre/bilinmeyen işaretçi
                    # için proje tür özeti güvenli fallback olarak kalır.
                    if instance:
                        ft = self.instance_fields.get((instance, key), EMPTY)
                        if "[" in instance:
                            root = instance.split("[", 1)[0]
                            ft = compact(ft | self.instance_fields.get((f"{root}[*]", key), EMPTY))
                    else:
                        ft = self.field_taint(key)
                    if ft and m in self.cindex().guarded_fields:
                        ft = strings_only(ft)  # uzunluk alanı projede sınırla denetleniyor
                    cur = compact(cur | ft)
                    ftype = self._field_type(ftype, m)
                else:
                    ftype = ""
                # İç içe yapı alanında alıcı yolunu koru: request.left.value ile request.right.value
                # aynı Inner türünü paylaşsa da farklı somut örneklerdir.
                base = f"{receiver_base}.{m}" if receiver_base and ftype and k < hi \
                    and toks[k].text in (".", "->") else None
                arr_base = None
                i = k
                continue
            if t.kind == "op" and t.text == "[":
                close = match_close(toks, i, hi)
                arr_base = base
                cur = self.index(cur, base, i + 1, close)
                element = ""
                if arr_base and close == i + 2 and toks[i + 1].kind == "num" \
                        and re.fullmatch(r"\d+", toks[i + 1].text):
                    element = f"{arr_base}[{int(toks[i + 1].text)}]"
                # Yapı dizisinin sabit elemanı üzerindeki alan erişimi için eleman kimliğini koru.
                if close + 1 < hi and toks[close + 1].text in (".", "->"):
                    ftype = self._struct_type(arr_base) if arr_base else ""
                    base = element or arr_base
                else:
                    base = None
                i = close + 1
                if arr_base and i < hi and toks[i].text == "(" and arr_base not in self.prog.by_name:
                    close2 = match_close(toks, i, hi)
                    cur = self.indirect(arr_base, "var", i, close2, toks[i].line)
                    i = close2 + 1
                    arr_base = None
                continue
            if t.kind == "op" and t.text == "(" and base is not None:
                close = match_close(toks, i, hi)
                cur = self.call([base], i, close, i - 1, "")
                base = None
                ftype = ""
                i = close + 1
                continue
            break
        return i, cur

    def primary(self, i: int, hi: int) -> tuple[int, frozenset]:
        toks = self.toks
        # (*fp)(x) / (*s->fn)(x)
        if toks[i].kind == "op" and toks[i].text == "(" and i + 3 < hi and toks[i + 1].text == "*":
            close = match_close(toks, i, hi)
            last = close - 1
            while last > i + 1 and toks[last].text == "]":  # (*tablo[i])(x), (*s->fn[k])(x)
                depth = 0
                while last > i + 1:
                    if toks[last].text == "]":
                        depth += 1
                    elif toks[last].text == "[":
                        depth -= 1
                        if depth == 0:
                            break
                    last -= 1
                last -= 1
            if close + 1 < hi and toks[close + 1].text == "(" and close - i <= 12 and last > i + 1 and \
                    toks[last].kind == "id":
                inner = toks[i + 2:last + 1]
                name = toks[last].text
                kind = "field" if len(inner) >= 3 and inner[-2].text in (".", "->") else "var"
                if kind == "var" and name in self.prog.by_name:
                    return super().primary(i, hi)
                key: Any = name
                if kind == "field":
                    receiver = _fptr_receiver_before_field(toks, last)
                    receiver_key = (self.fn.key, receiver) if receiver else None
                    if receiver_key is not None and receiver_key in self.cindex().fptr_receivers:
                        key, kind = receiver_key, "receiver"
                c2 = match_close(toks, close + 1, hi)
                res = self.indirect(key, kind, close + 1, c2, toks[i].line)
                return self.postfix(c2 + 1, hi, res, None)
        return super().primary(i, hi)


_ESCAPER_VERBS = frozenset({"escape", "quote", "sanitize", "sanitise", "shellescape", "shellquote", "htmlescape",
                            "escapeshellarg", "escapeshellcmd", "htmlspecialchars"})
_NOT_ESCAPER = frozenset({"un", "de", "unescape", "unquote", "dequote", "decode", "is", "has", "needs", "need",
                          "parse", "skip", "find", "strip", "remove", "count", "len", "length", "size", "check"})


def _is_escaper(name: str) -> bool:
    """Kaçışlama/tırnaklama yardımcısı mı (ad tabanlı): escape/quote/sanitize fiili bir ad parçası olmalı;
    çözme yönündekiler (url_decode, unescape, unquote, dequote) ve sorgu/ayrıştırma adları (is_quoted,
    parse_quoted, skip_quote) değildir."""
    parts = [x.lower() for x in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", name.replace("_", " ")) if x]
    if not parts or any(x in _NOT_ESCAPER for x in parts):
        return False
    low = name.lower()
    if any(x in low for x in ("unescape", "unquote", "dequote", "decode", "unesc")):
        return False
    return any(x in _ESCAPER_VERBS for x in parts) or low.endswith(("_escape", "escape", "_quote"))


def _is_int_type(typ: str) -> bool:
    """Tamsayı (işaretçi/dizi olmayan) tür metni mi? ``char`` yalnız ``signed/unsigned`` ile tamsayı sayılır."""
    if not typ or "*" in typ or "[" in typ or _NOT_INT_RE.search(typ):
        return False
    if re.search(r"\bchar\b", typ) and not re.search(r"\b(unsigned|signed)\b", typ):
        return False
    return bool(_INT_TYPE_RE.search(typ))


def _collect_structs(unit: FileUnit, caps_out: dict[str, dict[str, int]] | None = None,
                     ) -> dict[str, dict[str, tuple[str, bool, bool]]]:
    """struct/union/class tanımları → {ad (ve typedef takma adları): {alan: (tür metni, dizi mi, işaretçi mi)}}.
    Yöntemler ve işlev işaretçisi alanları atlanır; iç içe tanımlar opak tutulur."""
    toks = unit.toks
    n = len(toks)
    out: dict[str, dict[str, tuple[str, bool, bool]]] = {}
    i = 0
    while i < n:
        t = toks[i]
        if not (t.kind == "id" and t.text in ("struct", "union", "class")):
            i += 1
            continue
        j = i + 1
        name = ""
        if j < n and toks[j].kind == "id" and toks[j].text not in _KEYWORDS:
            name = toks[j].text
            j += 1
        while j < n and j - i < 12 and toks[j].text not in ("{", ";", "(", "=", ")", ","):
            j += 1  # ": public Taban" vb.
        if j >= n or toks[j].text != "{":
            i += 1
            continue
        close = match_close(toks, j)
        fields: dict[str, tuple[str, bool, bool]] = {}
        caps: dict[str, int] = {}
        k, start, depth = j + 1, j + 1, 0
        while k < close:
            x = toks[k]
            if x.kind == "op" and x.text == "{":
                k = match_close(toks, k, close) + 1
                continue
            if x.kind == "op" and x.text == ":" and k == start + 1 and toks[start].text in ("public", "private", "protected"):
                start = k + 1
            elif x.kind == "op" and x.text == ";":
                _struct_member(toks, start, k, fields, caps)
                start = k + 1
            k += 1
        if fields:
            if name:
                out.setdefault(name, fields)
                if caps_out is not None:
                    caps_out.setdefault(name, caps)
            # typedef struct {…} Ad, *PAd;
            q = close + 1
            while q < n and q - close < 12 and toks[q].text != ";":
                if toks[q].kind == "id" and toks[q].text not in _KEYWORDS:
                    out.setdefault(toks[q].text, fields)
                    if caps_out is not None:
                        caps_out.setdefault(toks[q].text, caps)
                q += 1
        i = close + 1
    return out


_ELEM_BYTES = {"char": 1, "signed char": 1, "unsigned char": 1, "uint8_t": 1, "int8_t": 1, "u8": 1, "BYTE": 1,
               "wchar_t": 4, "short": 2, "int": 4, "unsigned": 4, "uint16_t": 2, "uint32_t": 4, "int32_t": 4}


def _dim_value(toks: list[Tok], consts: dict[str, int] | None = None, *, positive: bool = True) -> int | None:
    """Dizi boyutu ifadesi (sayısal değişmezler, bilinen sayısal makrolar ve + - * / << ( ))."""
    items: list[Any] = []
    for t in toks:
        if t.kind == "id" and consts and t.text in consts:
            items.append(consts[t.text])
        elif t.kind == "num":
            try:
                items.append(int(re.sub(r"[uUlL]+$", "", t.text), 0))
            except ValueError:
                return None
        elif t.kind == "op" and t.text in ("+", "-", "*", "/", "(", ")", "<<"):
            items.append(t.text)
        else:
            return None
    if not items or len(items) > 15:
        return None
    pos = [0]

    def atom() -> int | None:
        if pos[0] >= len(items):
            return None
        x = items[pos[0]]
        pos[0] += 1
        if x == "(":
            v = shift()
            if pos[0] >= len(items) or items[pos[0]] != ")":
                return None
            pos[0] += 1
            return v
        return x if isinstance(x, int) else None

    def mul() -> int | None:
        v = atom()
        while v is not None and pos[0] < len(items) and items[pos[0]] in ("*", "/"):
            op = items[pos[0]]
            pos[0] += 1
            w = atom()
            if w is None or (op == "/" and w == 0):
                return None
            v = v * w if op == "*" else v // w
        return v

    def add() -> int | None:
        v = mul()
        while v is not None and pos[0] < len(items) and items[pos[0]] in ("+", "-"):
            op = items[pos[0]]
            pos[0] += 1
            w = mul()
            if w is None:
                return None
            v = v + w if op == "+" else v - w
        return v

    def shift() -> int | None:
        v = add()
        while v is not None and pos[0] < len(items) and items[pos[0]] == "<<":
            pos[0] += 1
            w = add()
            if w is None or not 0 <= w < 31:
                return None
            v = v << w
        return v

    v = shift()
    if pos[0] != len(items):
        return None
    if v is None or not -(1 << 31) < v < 1 << 31:
        return None
    return v if not positive or v > 0 else None


def _decl_cap(type_words: str, dims: list[list[Tok]], consts: dict[str, int] | None = None) -> int | None:
    """``char buf[64]`` → 64 bayt (yalnız 1–4 bayt öğeli diziler; çok boyutlu: çarpım)."""
    base = " ".join(w for w in type_words.split() if w not in ("const", "static", "volatile", "struct", "register"))
    es = _ELEM_BYTES.get(base)
    if es is None or not dims:
        return None
    total = es
    for d in dims:
        v = _dim_value(d, consts)
        if v is None:
            return None
        total *= v
    return total


def _struct_member(toks: list[Tok], lo: int, hi: int, fields: dict[str, tuple[str, bool, bool]],
                   caps: dict[str, int] | None = None) -> None:
    seg = [t for t in toks[lo:hi]]
    if not seg or any(t.text == "(" for t in seg) or seg[0].text in ("typedef", "using", "friend", "static", "template",
                                                                       "public", "private", "protected", "enum"):
        return
    # varsayılan değer ve bit alanı kesilir
    for q, t in enumerate(seg):
        if t.text in ("=",) or (t.text == ":" and t.kind == "op"):
            seg = seg[:q]
            break
    parts: list[list[Tok]] = [[]]
    depth = 0
    for t in seg:
        if t.text in ("[", "<"):
            depth += 1
        elif t.text in ("]", ">"):
            depth -= 1
        if t.text == "," and depth == 0:
            parts.append([])
            continue
        parts[-1].append(t)
    base_type = ""
    for idx, decl in enumerate(parts):
        q = len(decl) - 1
        arr = False
        while q >= 0 and decl[q].text == "]":
            arr = True
            while q >= 0 and decl[q].text != "[":
                q -= 1
            q -= 1
        if q < 0 or decl[q].kind != "id" or decl[q].text in _KEYWORDS:
            continue
        fname = decl[q].text
        head = decl[:q]
        if idx == 0:
            base_type = " ".join(t.text for t in head if t.text not in ("*", "&"))
        ptr = any(t.text == "*" for t in head)
        fields[fname] = (base_type, arr, ptr)
        if arr and not ptr and caps is not None:
            dims: list[list[Tok]] = []
            r = q + 1
            while r < len(decl) and decl[r].text == "[":
                e = r + 1
                depth2 = 1
                while e < len(decl) and depth2:
                    if decl[e].text == "[":
                        depth2 += 1
                    elif decl[e].text == "]":
                        depth2 -= 1
                        if depth2 == 0:
                            break
                    e += 1
                dims.append(decl[r + 1:e])
                r = e + 1
            caps[fname] = (base_type, dims)  # type: ignore[assignment]  # proje sayısal makrolarıyla sonra hesaplanır


def _split_semis(toks: list[Tok], lo: int, hi: int) -> list[tuple[int, int]]:
    out, start, depth = [], lo, 0
    for j in range(lo, hi):
        x = toks[j].text
        if toks[j].kind != "op":
            continue
        if x in "([{":
            depth += 1
        elif x in ")]}":
            depth -= 1
        elif x == ";" and depth == 0:
            out.append((start, j))
            start = j + 1
    out.append((start, hi))
    return out


# ---------------------------------------------------------------------------
# 27. tur: proje dizini — işlev işaretçisi tabloları, yönlendirme kayıtları, çatı geri çağırmaları
# ---------------------------------------------------------------------------

# Çatı kayıt çağrıları: ad → (geri çağırma argümanı dizini, {geri çağırma parametresi: kaynak açıklaması})
_FRAMEWORK_REG: dict[str, tuple[int, dict[int, str]]] = {
    "MHD_start_daemon": (4, {2: "libmicrohttpd istek URL'si (url)", 3: "libmicrohttpd HTTP yöntemi",
                             4: "libmicrohttpd HTTP sürümü", 5: "libmicrohttpd istek gövdesi (upload_data)"}),
    "mg_http_listen": (2, {2: "mongoose HTTP iletisi (ev_data)"}),
    "mg_listen": (2, {2: "mongoose olay verisi (ev_data)"}),
    "mg_bind": (2, {2: "mongoose olay verisi (ev_data)"}),
    "mg_bind_opt": (2, {2: "mongoose olay verisi (ev_data)"}),
    "mg_set_request_handler": (2, {}),
    "mg_set_websocket_handler": (2, {}),
    "evhttp_set_cb": (2, {}),
    "evhttp_set_gencb": (1, {}),
    "ulfius_add_endpoint_by_val": (5, {0: "ulfius HTTP isteği"}),
    "onion_url_add": (2, {1: "onion HTTP isteği"}),
    "kore_server_bind": (-1, {}),
}
# Çatı istek API'leri: dönüşü istek verisi olanlar
_FRAMEWORK_RET = {
    "MHD_lookup_connection_value": "libmicrohttpd istek değeri", "MHD_lookup_connection_value_n": "libmicrohttpd istek değeri",
    "mg_get_header": "HTTP başlığı (mg_get_header)", "mg_get_request_info": "HTTP isteği (mg_get_request_info)",
    "mg_http_get_header": "HTTP başlığı (mg_http_get_header)", "mg_http_var": "HTTP parametresi (mg_http_var)",
    "mg_get_http_header": "HTTP başlığı", "evhttp_request_get_uri": "HTTP istek URI'si (libevent)",
    "evhttp_request_uri": "HTTP istek URI'si (libevent)", "evhttp_find_header": "HTTP başlığı (libevent)",
    "evhttp_uri_get_query": "HTTP sorgu dizgisi (libevent)", "evhttp_uri_get_path": "HTTP yolu (libevent)",
    "FCGX_GetParam": "FastCGI parametresi", "onion_request_get_query": "HTTP parametresi (onion)",
    "onion_request_get_post": "HTTP gövde parametresi (onion)", "onion_request_get_path": "HTTP yolu (onion)",
    "onion_request_get_header": "HTTP başlığı (onion)", "u_map_get": "HTTP parametresi (ulfius)",
    "u_map_get_case": "HTTP parametresi (ulfius)", "http_get_header": "HTTP başlığı",
}
# Çatı istek API'leri: çıkış argümanına istek verisi yazanlar (ad → (çıkış argümanı, uzunluk argümanı | -1))
_FRAMEWORK_OUT = {
    "mg_get_var": (3, 4), "mg_get_var2": (3, 4), "mg_get_cookie": (2, 3), "mg_read": (1, 2),
    "mg_http_get_var": (2, 3), "mg_url_decode": (2, 3), "evbuffer_remove": (1, 2), "evbuffer_copyout": (1, 2),
    "FCGX_GetStr": (0, 1), "FCGX_GetLine": (0, 1), "FCGI_fgets": (0, 1), "http_argument_get_string": (2, -1),
    "MHD_get_connection_values": (-1, -1),
}
# Çatı HTTP yanıt çıktıları: ad → biçim argümanı dizini (HTML bağlamı biçimde etiket varsa)
_HTTP_OUT_FMT = {"mg_printf": 1, "mg_http_reply": 3, "mg_printf_data": 1, "evbuffer_add_printf": 1, "dprintf": 1,
                 "fprintf": 1, "sprintf": 1, "snprintf": 2, "printf": 0, "asprintf": 1, "mg_send_http_ok": 2,
                 "kore_buf_appendf": 1}
_HTML_TAG_RE = re.compile(r"(?i)<\s*/?\s*(html|body|head|div|p|h[1-6]|a|li|ul|ol|td|tr|th|table|span|b|i|br|pre|"
                          r"title|form|input|script|img|em|strong|code|textarea|option|label|button|hr)\b[^>]*>")
# Kod yorumlayıcıları: ad → kod argümanı dizini
_CODE_EVAL = {"luaL_dostring": 1, "luaL_loadstring": 1, "luaL_loadbuffer": 1, "PyRun_SimpleString": 0,
              "PyRun_String": 0, "PyRun_SimpleStringFlags": 0, "Tcl_Eval": 1, "Tcl_EvalEx": 1, "Tcl_GlobalEval": 1,
              "duk_eval_string": 1, "duk_peval_string": 1, "duk_compile_string": 2, "JS_Eval": 1, "mrb_load_string": 1,
              "rb_eval_string": 0, "dlopen": 0, "LoadLibraryA": 0, "LoadLibrary": 0, "tcc_compile_string": 1}
_SRC_EXT_RE = re.compile(r"\.(c|cc|cpp|cxx|h|py|sh|bash|pl|php|rb|lua|js|tcl|s|asm)$", re.I)
_COMPILER_RE = re.compile(r"(?i)^\s*(\S*/)?(gcc|g\+\+|cc|clang|clang\+\+|tcc|python[0-9.]*|perl|php|ruby|lua|node|sh|bash)\b")
# Varsayılan ulaşılabilir uzunluk: HTTP çatılarının tipik istek satırı/başlık sınırı (8 KiB)
HTTP_FRAMEWORK_CAP = 8000


class CIndex:
    """Proje genelinde işlev değerleri: alan adı → işlevler, değişken → işlevler, çatı geri çağırmaları."""

    def __init__(self) -> None:
        self.limitations: set[str] = set()
        self.fptr_fields: dict[str, set[str]] = {}
        self.fptr_vars: dict[str, set[str]] = {}
        # Somut alıcı kimliği (``ops[0]``, ``handler``) → o örneğin alanına atanmış işlevler. Alan tabanlı
        # birleşim bilinmeyen indeksler için korunur; sabit indeksli çağrı bu daha kesin tabloyu kullanır.
        self.fptr_receivers: dict[tuple[tuple, str], set[str]] = {}
        # (çağrılan işlev anahtarı, parametre sırası) → çağrı yerinde geçirilen somut işlev değerleri.
        self.fptr_params: dict[tuple[tuple, int], set[str]] = {}
        # Function-pointer factory summaries: function key -> statically returned targets.
        self.fptr_returns: dict[tuple, set[str]] = {}
        # Sarmalayıcı içindeki callback çağrısı: işlev anahtarı → (callback parametresi, çağrı argümanlarının
        # sarmalayıcı parametre sıraları). Çağrı yerinde somut callback ile bağlama duyarlı uygulanır.
        self.callback_calls: dict[tuple, list[tuple[int, tuple[int, ...]]]] = {}
        self.callbacks: dict[str, dict[int, str]] = {}
        self.fn_typedefs: set[str] = set()
        self.taken: set[str] = set()
        self.table_hops: dict[str, str] = {}  # işlev → "dosya:satır alan/tablo" (kanıt zinciri)
        # soket tanımlayıcısı/akışı alan parametreler: işlev → {parametre: "fd" | "stream" | "fdptr"}
        self.sock_params: dict[str, dict[int, str]] = {}
        self.sock_locals: dict[tuple, dict[str, str]] = {}  # fonksiyon anahtarı → {yerel ad: tür}
        # genel kap türleri (dizgi/tampon yapıları: lighttpd buffer, mg_str, dynbuf, robj …): alan duyarlı küresel
        # kirlilik bunların içine inmez (her örneği aynı anahtarı paylaşırdı); kirlilik onu taşıyan kayıt alanında tutulur
        self.containers: set[str] = set()
        # dosya → onu (çağrı/işlev değeri üzerinden) içeren programlar (main dosyaları); boşsa kitaplık (her program)
        self.file_programs: dict[str, frozenset[str]] = {}
        self.field_kinds: dict[tuple, str] = {}
        # projede bir yerde üst/alt sınırla karşılaştırılan alan adları (len, payload_size …): doğrulanmış sayılır
        self.guarded_fields: set[str] = set()
        # inetd/xinetd/systemd-socket tarzı hizmet: standart girdi ağ bağlantısıdır (setvbuf(stdout…) ve kendi
        # dinleyen soketi yok) — yerel stdin kökenleri dosyalar arası modelde ağ girdisi gibi taşınır
        self.stdin_service = False
        self.field_ids: dict[tuple, set] = {}

    def model_origin_ok(self, o: Origin) -> bool:
        if o.label == "request":
            return True
        return self.stdin_service and o.label == "local" and o.source.startswith("standart girdi")

    def same_program(self, a: str, b: str) -> bool:
        pa = self.file_programs.get(a)
        pb = self.file_programs.get(b)
        return not pa or not pb or bool(pa & pb)


_ENTRY_NAMES = frozenset({"main", "wmain", "_tmain", "WinMain", "wWinMain", "LLVMFuzzerTestOneInput"})


def _file_programs(units: list[FileUnit], by_name: dict[str, list[Func]]) -> dict[str, frozenset[str]]:
    """Her main'den çağrı ve işlev değeri başvurularıyla ulaşılan dosyalar → dosya başına program kümesi."""
    refs: dict[tuple, list[Func]] = {}
    for u in units:
        toks = u.toks
        for fn in u.funcs:
            lo, hi = fn.body
            out: list[Func] = []
            seen: set[str] = set()
            for j in range(lo + 1, hi):
                t = toks[j]
                if t.kind != "id" or t.text not in by_name or t.text in seen or \
                        (j > 0 and toks[j - 1].text in (".", "->")):
                    continue
                seen.add(t.text)
                cands = by_name[t.text]
                same = [f for f in cands if f.file == fn.file]
                out.extend(same or [f for f in cands if not f.is_static][:3])
            refs[fn.key] = out
    progs: dict[str, set[str]] = {}
    entries = [f for fs in by_name.values() for f in fs if f.name in _ENTRY_NAMES]
    if len({f.file for f in entries}) < 2:
        return {}
    for entry in entries:
        seen_k = {entry.key}
        stack = [entry]
        files = {entry.file}
        while stack and len(seen_k) < 20_000:
            f = stack.pop()
            for g in refs.get(f.key, ()):
                if g.key not in seen_k:
                    seen_k.add(g.key)
                    files.add(g.file)
                    stack.append(g)
        for path in files:
            progs.setdefault(path, set()).add(entry.file)
    return {k: frozenset(v) for k, v in progs.items()}


def _container_types(structs: dict[str, dict[str, tuple[str, bool, bool]]]) -> set[str]:
    """Üç ya da daha çok farklı yapının alan türü olarak kullandığı yapılar (genel kap/dizgi türleri)."""
    embed: dict[str, set[str]] = {}
    ids = {}
    for sname, fields in structs.items():
        key = id(fields)
        for ftype, _arr, _ptr in fields.values():
            for w in re.findall(r"[A-Za-z_]\w*", ftype):
                if w in structs and id(structs[w]) != key:
                    embed.setdefault(w, set()).add(key)
        ids[sname] = key
    out = set()
    for w, users in embed.items():
        if len(users) >= 3:
            out.add(w)
            # aynı tanımın typedef takma adları
            for other, fid in ids.items():
                if fid == ids.get(w):
                    out.add(other)
    return out


_ACCEPT_RE_NAMES = frozenset({"accept", "accept4", "WSAAccept"})
# Doğrulayıcı işlev adları: if (!check_filename(x)) { return; } → x arınmış (yol hedefleri)
_VALIDATOR_RE = re.compile(r"^(is_?)?(check|valid|validate|sanitize|sanitise|safe|allowed|whitelist|verify)(_\w+)?$|"
                           r"^(is|check|valid|validate|sanitize|verify)[A-Z]\w*$|^\w+_(valid|safe|allowed|sanitized?|ok)$|"
                           # 27. tur düzeltmesi: mg_path_is_sane, path_is_safe, url_is_valid
                           r"^\w+_is_(sane|safe|valid|allowed|ok)$")


def _sock_prepass(units: list[FileUnit], by_name: dict[str, list[Func]], idx: CIndex) -> None:
    """Soket tanımlayıcısı/akışı yayılımı (belirteç düzeyi, proje geneli): ``fd = accept(…)`` → ``handle(fd)`` →
    ``handle(int c)`` içinde ``c`` soket; ``fdopen(c, "r")`` → akış; ``pthread_create(…, fn, &fd)`` → ``*(int *)arg``."""
    funcs = [(u, f) for u in units for f in u.funcs]
    for _ in range(6):
        changed = False
        for u, f in funcs:
            toks = u.toks
            lo, hi = f.body
            local: dict[str, str] = {}
            for pi, kind in idx.sock_params.get(f.name, {}).items():
                if pi < len(f.params) and f.params[pi].name:
                    local[f.params[pi].name] = kind
            j = lo + 1
            while j < hi - 2:
                t = toks[j]
                if t.kind == "op" and t.text == "=" and toks[j - 1].kind == "id":
                    lhs = toks[j - 1].text
                    k = j + 1
                    # tür dönüşümleri: (int)(intptr_t)x, *(int *)x
                    deref = False
                    if toks[k].text == "*":
                        deref = True
                        k += 1
                    while k < hi and toks[k].text == "(":
                        c = match_close(toks, k, hi)
                        inner = toks[k + 1:c]
                        if inner and all(x.kind == "id" or x.text == "*" for x in inner):
                            k = c + 1
                            continue
                        if c - k == 2 and toks[k + 1].kind == "id":
                            k += 1
                            break
                        break
                    if k < hi and toks[k].kind == "id":
                        w = toks[k].text
                        if w in _ACCEPT_RE_NAMES and k + 1 < hi and toks[k + 1].text == "(":
                            if local.get(lhs) != "fd":
                                local[lhs] = "fd"
                        elif w == "fdopen" and k + 2 < hi and toks[k + 1].text == "(" and toks[k + 2].kind == "id" and \
                                local.get(toks[k + 2].text) == "fd":
                            local[lhs] = "stream"
                        elif deref and local.get(w) == "fdptr":
                            local[lhs] = "fd"
                        elif not deref and w in local and k + 1 < hi and toks[k + 1].text in (";", ","):
                            local.setdefault(lhs, local[w] if local[w] != "fdptr" else "fdptr")
                if t.kind == "id" and toks[j + 1].text == "(" and (t.text in by_name or t.text == "pthread_create"):
                    close = match_close(toks, j + 1, hi)
                    args = split_args(toks, j + 2, close)
                    targets: list[tuple[str, int, str]] = []
                    if t.text == "pthread_create" and len(args) == 4:
                        fa, fb = args[2]
                        fnm = toks[fb - 1].text if fb > fa else ""
                        aa, ab = args[3]
                        names = [x.text for x in toks[aa:ab] if x.kind == "id"]
                        if fnm in by_name and names and local.get(names[-1]) in ("fd", "fdptr"):
                            targets.append((fnm, 0, "fdptr"))
                    elif t.text in by_name:
                        for ai, (aa, ab) in enumerate(args):
                            seg = toks[aa:ab]
                            if len(seg) == 1 and seg[0].kind == "id" and seg[0].text in local:
                                targets.append((t.text, ai, local[seg[0].text]))
                            elif len(seg) == 2 and seg[0].text == "&" and local.get(seg[1].text) == "fd":
                                targets.append((t.text, ai, "fdptr"))
                    for fnm, ai, kind in targets:
                        cur = idx.sock_params.setdefault(fnm, {})
                        if cur.get(ai) is None:
                            cur[ai] = kind
                            changed = True
                j += 1
            if local:
                idx.sock_locals[f.key] = dict(local)
        if not changed:
            break


def _stmt_start(toks: list[Tok], j: int) -> int:
    depth = 0
    k = j - 1
    while k >= 0:
        t = toks[k]
        if t.kind == "op":
            if t.text in (")", "]"):
                depth += 1
            elif t.text in ("(", "["):
                if depth == 0:
                    return k + 1
                depth -= 1
            elif t.text in (";", "{", "}") and depth == 0:
                return k + 1
        k -= 1
    return 0


def _param_stores(toks: list[Tok], fn: Func) -> dict[int, tuple[str, str]]:
    """Fonksiyon gövdesinde parametre bir alana/diziye saklanıyor mu: ``r->handler = h`` → {i: ("field", handler)}."""
    names = {p.name: p.index for p in fn.params if p.name}
    out: dict[int, tuple[str, str]] = {}
    lo, hi = fn.body
    for j in range(lo + 1, hi - 1):
        t = toks[j]
        if t.kind == "op" and t.text == "=" and toks[j + 1].kind == "id" and toks[j + 1].text in names and \
                toks[j + 2].text in (";", ","):
            idx = names[toks[j + 1].text]
            k = j - 1
            if toks[k].kind == "id" and k > 0 and toks[k - 1].text in (".", "->"):
                out.setdefault(idx, ("field", toks[k].text))
            elif toks[k].text == "]":
                depth = 0
                while k > lo:
                    if toks[k].text == "]":
                        depth += 1
                    elif toks[k].text == "[":
                        depth -= 1
                        if depth == 0:
                            break
                    k -= 1
                if k - 1 > lo and toks[k - 1].kind == "id":
                    if k - 2 > lo and toks[k - 2].text in (".", "->"):
                        out.setdefault(idx, ("field", toks[k - 1].text))
                    else:
                        out.setdefault(idx, ("var", toks[k - 1].text))
    return out


def _callback_prepass(units: list[FileUnit], idx: CIndex) -> None:
    for unit in units:
        toks = unit.toks
        for fn in unit.funcs:
            params = {p.name: p.index for p in fn.params if p.name}
            lo, hi = fn.body
            for j in range(lo + 1, hi - 2):
                if toks[j].kind != "id" or toks[j].text not in params:
                    continue
                open_ = j + 1 if toks[j + 1].text == "(" else (
                    j + 2 if j >= 2 and toks[j - 2].text == "(" and toks[j - 1].text == "*"
                    and toks[j + 1].text == ")" and toks[j + 2].text == "(" else -1)
                if open_ < 0:
                    continue
                close = match_close(toks, open_, hi)
                mapped: list[int] = []
                for a, b in split_args(toks, open_ + 1, close):
                    ids = [x.text for x in toks[a:b] if x.kind == "id" and x.text in params]
                    mapped.append(params[ids[-1]] if len(set(ids)) == 1 else -1)
                item = (params[toks[j].text], tuple(mapped))
                calls = idx.callback_calls.setdefault(fn.key, [])
                if item not in calls and len(calls) < 8:
                    calls.append(item)
                elif item not in calls:
                    idx.limitations.add("callback-candidates")


def _callback_wrapper_closure(units: list[FileUnit], by_name: dict[str, list[Func]], idx: CIndex) -> None:
    """Callback parametresini başka bir callback sarmalayıcısına aktaran ince sarmalayıcıları kapat."""
    for _round in range(8):
        changed = False
        for unit in units:
            toks = unit.toks
            for fn in unit.funcs:
                params = {p.name: p.index for p in fn.params if p.name}
                if not params:
                    continue
                lo, hi = fn.body
                for j in range(lo + 1, hi - 1):
                    if toks[j].kind != "id" or toks[j].text not in by_name or toks[j + 1].text != "(":
                        continue
                    close = match_close(toks, j + 1, hi)
                    ranges = split_args(toks, j + 2, close)
                    candidates = by_name[toks[j].text]
                    if len(candidates) > core.MAX_CANDIDATES:
                        idx.limitations.add("callback-candidates")
                    for callee in candidates[:core.MAX_CANDIDATES]:
                        for callback_param, mapped in idx.callback_calls.get(callee.key, ()):
                            if callback_param >= len(ranges):
                                continue
                            a, b = ranges[callback_param]
                            callback_ids = {x.text for x in toks[a:b] if x.kind == "id" and x.text in params}
                            if len(callback_ids) != 1:
                                continue
                            callback_name = next(iter(callback_ids))
                            translated: list[int] = []
                            for callee_param in mapped:
                                if callee_param < 0 or callee_param >= len(ranges):
                                    translated.append(-1)
                                    continue
                                ma, mb = ranges[callee_param]
                                ids = {x.text for x in toks[ma:mb] if x.kind == "id" and x.text in params}
                                translated.append(params[next(iter(ids))] if len(ids) == 1 else -1)
                            item = (params[callback_name], tuple(translated))
                            calls = idx.callback_calls.setdefault(fn.key, [])
                            if item not in calls and len(calls) < 8:
                                calls.append(item)
                                changed = True
                            elif item not in calls:
                                idx.limitations.add("callback-candidates")
        if not changed:
            break


def _fptr_receiver_before_field(toks: list[Tok], field: int) -> str:
    """``receiver.field`` ifadesinde güvenle kimliklendirilebilen alıcıyı döndür."""
    if field < 2 or toks[field - 1].text not in (".", "->"):
        return ""
    end = field - 2
    if toks[end].kind == "id":
        return toks[end].text
    if toks[end].text != "]":
        return ""
    depth = 0
    start = end
    while start >= 0:
        if toks[start].text == "]":
            depth += 1
        elif toks[start].text == "[":
            depth -= 1
            if depth == 0:
                break
        start -= 1
    if start < 1 or toks[start - 1].kind != "id" or end != start + 2 or toks[start + 1].kind != "num" \
            or not re.fullmatch(r"\d+", toks[start + 1].text):
        return ""
    return f"{toks[start - 1].text}[{int(toks[start + 1].text)}]"


def _function_pointer_cast_end(toks: list[Tok], lo: int, hi: int,
                               fn_typedefs: set[str] | frozenset[str] = frozenset()) -> int:
    """Return the token after a bounded C function-pointer cast, or ``-1``.

    This intentionally accepts only a known function typedef or the explicit
    ``return-type (*)(parameter-types)`` shape.  General parenthesized
    expressions and data-pointer casts therefore cannot invent call targets.
    """
    if lo >= hi or toks[lo].text != "(":
        return -1
    close = match_close(toks, lo, hi)
    if close >= hi - 1:
        return -1
    inner = toks[lo + 1:close]
    if len(inner) == 1 and inner[0].kind == "id" and inner[0].text in fn_typedefs:
        return close + 1
    if not inner or any(
            token.kind not in ("id", "op") or
            (token.kind == "op" and token.text not in ("(", ")", "*", "&", "::", ",", "...", "[", "]"))
            for token in inner):
        return -1
    for index in range(len(inner) - 3):
        if inner[index].text != "(":
            continue
        cursor = index + 1
        while cursor < len(inner) and inner[cursor].kind == "id" and inner[cursor].text in (
                "const", "volatile", "restrict", "__restrict", "__stdcall", "__cdecl"):
            cursor += 1
        if cursor >= len(inner) or inner[cursor].text != "*":
            continue
        cursor += 1
        while cursor < len(inner) and inner[cursor].kind == "id" and inner[cursor].text in (
                "const", "volatile", "restrict", "__restrict", "__stdcall", "__cdecl"):
            cursor += 1
        if cursor + 1 < len(inner) and inner[cursor].text == ")" and inner[cursor + 1].text == "(":
            return close + 1
    return -1


def _static_function_targets(toks: list[Tok], lo: int, hi: int,
                             by_name: dict[str, list[Func]], depth: int = 0) -> set[str]:
    """Direct/parenthesized/ternary function values for bounded factory summaries."""
    if depth > 8:
        return set()
    while lo < hi and toks[lo].text == "(":
        close = match_close(toks, lo, hi)
        if close == hi - 1:
            lo += 1
            hi -= 1
            continue
        cast_end = _function_pointer_cast_end(toks, lo, hi)
        if cast_end < 0:
            break
        lo = cast_end
    if lo < hi and toks[lo].text == "&":
        lo += 1
    if hi - lo == 1 and toks[lo].kind == "id":
        return {toks[lo].text} if toks[lo].text in by_name else set()
    nesting = 0
    question = -1
    for index in range(lo, hi):
        text = toks[index].text
        if text in ("(", "[", "{"):
            nesting += 1
        elif text in (")", "]", "}"):
            nesting = max(0, nesting - 1)
        elif text == "?" and nesting == 0:
            question = index
            break
    if question < 0:
        return set()
    nesting = nested = 0
    colon = -1
    for index in range(question + 1, hi):
        text = toks[index].text
        if text in ("(", "[", "{"):
            nesting += 1
        elif text in (")", "]", "}"):
            nesting = max(0, nesting - 1)
        elif nesting == 0 and text == "?":
            nested += 1
        elif nesting == 0 and text == ":":
            if nested:
                nested -= 1
            else:
                colon = index
                break
    if colon < 0:
        return set()
    return (_static_function_targets(toks, question + 1, colon, by_name, depth + 1) |
            _static_function_targets(toks, colon + 1, hi, by_name, depth + 1))


def build_cindex(units: list[FileUnit], by_name: dict[str, list[Func]]) -> CIndex:
    idx = CIndex()
    structs: dict[str, dict[str, tuple[str, bool, bool]]] = {}
    for u in units:
        structs = u.info.get("structs") or structs
        break
    stores_cache: dict[str, dict[int, tuple[str, str]]] = {}
    field_order_cache: dict[str, list[str]] = {}
    idx.containers = _container_types(structs)
    unbuffered = listens = False
    for u in units:
        toks = u.toks
        for j in range(len(toks) - 3):
            t = toks[j]
            if t.kind == "id" and t.text in ("setvbuf", "setbuf") and toks[j + 1].text == "(" and \
                    toks[j + 2].text == "stdout":
                unbuffered = True
            elif t.kind == "id" and t.text in ("listen", "accept", "accept4", "MHD_start_daemon", "mg_http_listen",
                                               "mg_start", "evhttp_bind_socket") and toks[j + 1].text == "(":
                listens = True
    idx.stdin_service = unbuffered and not listens
    for u in units:
        toks = u.toks
        n = len(toks)
        for j in range(2, n - 3):
            t = toks[j]
            if t.kind != "op" or t.text not in ("<", "<=", ">", ">="):
                continue
            if toks[j - 1].kind == "id" and toks[j - 2].text in (".", "->"):
                idx.guarded_fields.add(toks[j - 1].text)
            if toks[j + 1].kind == "id" and toks[j + 2].text in (".", "->") and toks[j + 3].kind == "id":
                q = j + 3
                while q + 2 < n and toks[q + 1].text in (".", "->") and toks[q + 2].kind == "id":
                    q += 2
                if q + 1 < n and toks[q + 1].text != "(":
                    idx.guarded_fields.add(toks[q].text)
    try:
        idx.file_programs = _file_programs(units, by_name)
    except RecursionError:
        idx.file_programs = {}
    try:
        _sock_prepass(units, by_name, idx)
    except (RecursionError, IndexError):
        pass
    try:
        _callback_prepass(units, idx)
        _callback_wrapper_closure(units, by_name, idx)
    except (RecursionError, IndexError):
        pass
    # Statically bounded function-pointer factories: ``return dangerous`` or
    # ``return flag ? dangerous : harmless``.  Argument-dependent returns stay
    # unknown so callers do not inherit a project-wide target union.
    for unit in units:
        toks = unit.toks
        for fn in unit.funcs:
            targets: set[str] = set()
            lo, hi = fn.body
            for start in range(lo + 1, hi):
                if toks[start].text != "return":
                    continue
                nesting = 0
                end = start + 1
                while end < hi:
                    text = toks[end].text
                    if text in ("(", "[", "{"):
                        nesting += 1
                    elif text in (")", "]", "}"):
                        nesting = max(0, nesting - 1)
                    elif text == ";" and nesting == 0:
                        break
                    end += 1
                targets.update(_static_function_targets(toks, start + 1, end, by_name))
                if len(targets) > MAX_FUNCTION_ALIAS_CANDIDATES:
                    idx.limitations.add("callback-candidates")
                    targets.clear()
                    break
            if targets:
                idx.fptr_returns[fn.key] = targets
    for u in units:
        toks = u.toks
        n = len(toks)
        # işlev işaretçisi typedef'leri: typedef T (*ad)(...)
        for j in range(n - 4):
            if toks[j].text == "typedef":
                k = j + 1
                while k < n and k - j < 12 and toks[k].text not in (";", "{"):
                    if toks[k].text == "(" and k + 2 < n and toks[k + 1].text == "*" and toks[k + 2].kind == "id":
                        idx.fn_typedefs.add(toks[k + 2].text)
                        break
                    k += 1
        brace_stack: list[tuple[int, int]] = []  # ('{' dizini, öğe sayacı)
        for j in range(n):
            t = toks[j]
            if t.kind != "id" or (t.text not in by_name and t.text not in _RECV_OUT):
                continue
            nxt = toks[j + 1].text if j + 1 < n else ""
            prev = toks[j - 1].text if j > 0 else ""
            if nxt == "(" or prev in (".", "->", "::") or (j > 0 and toks[j - 1].kind == "id" and prev not in ("return",)):
                continue
            if nxt not in (",", ";", "}", ")") and not (nxt == "=" and False):
                continue
            fname = t.text
            p = j - 1
            if prev == "&":
                p -= 1
            if p >= 0 and toks[p].text == "(" and p > 0 and toks[p - 1].text == ")":
                continue
            idx.taken.add(fname)
            hop = f"{u.path}:{t.line}"
            # (a) atama
            if p >= 0 and toks[p].text == "=":
                k = p - 1
                declared_pointer = next((toks[q + 2].text for q in range(max(0, p - 48), p - 3)
                                         if toks[q].text == "(" and toks[q + 1].text == "*"
                                         and toks[q + 2].kind == "id" and toks[q + 3].text == ")"), "")
                if declared_pointer:
                    idx.fptr_vars.setdefault(declared_pointer, set()).add(fname)
                    continue
                if toks[k].kind == "id" and k > 0 and toks[k - 1].text in (".", "->"):
                    receiver = _fptr_receiver_before_field(toks, k)
                    if receiver:
                        owner = next((fn.key for fn in u.funcs if fn.body[0] < j < fn.body[1]), None)
                        if owner is not None:
                            idx.fptr_receivers.setdefault((owner, receiver), set()).add(fname)
                    idx.fptr_fields.setdefault(toks[k].text, set()).add(fname)
                    idx.table_hops.setdefault(fname, f"{hop} .{toks[k].text} = {fname}")
                    continue
                if toks[k].kind == "id":
                    idx.fptr_vars.setdefault(toks[k].text, set()).add(fname)
                    continue
                if toks[k].text == "]":
                    q = k
                    depth = 0
                    while q > 0:
                        if toks[q].text == "]":
                            depth += 1
                        elif toks[q].text == "[":
                            depth -= 1
                            if depth == 0:
                                break
                        q -= 1
                    if q > 0 and toks[q - 1].kind == "id":
                        if q > 1 and toks[q - 2].text in (".", "->"):
                            idx.fptr_fields.setdefault(toks[q - 1].text, set()).add(fname)
                        else:
                            idx.fptr_vars.setdefault(toks[q - 1].text, set()).add(fname)
                    continue
            # (b) küme ilk değeri: { "/yol", isleyici } / { .handler = isleyici }
            if p >= 0 and toks[p].text in ("{", ",", "("):
                # içteki '{' ve öğe sırası
                depth = 0
                pos = 0
                k = p
                open_ = -1
                while k >= 0:
                    x = toks[k]
                    if x.kind == "op" and x.text in (")", "]", "}"):
                        depth += 1
                    elif x.kind == "op" and x.text in ("(", "["):
                        if depth == 0:
                            break
                        depth -= 1
                    elif x.kind == "op" and x.text == "{":
                        if depth == 0:
                            open_ = k
                            break
                        depth -= 1
                    elif x.kind == "op" and x.text == "," and depth == 0:
                        pos += 1
                    elif x.kind == "op" and x.text == ";" and depth == 0:
                        break
                    k -= 1
                if open_ < 0:
                    # işlev çağrısı argümanı: G(…, isleyici, …)
                    if k >= 1 and toks[k].text == "(" and toks[k - 1].kind == "id":
                        g = toks[k - 1].text
                        reg = _FRAMEWORK_REG.get(g)
                        if reg is not None and (reg[0] == pos or reg[0] < 0):
                            spec = idx.callbacks.setdefault(fname, {})
                            spec.update(reg[1])
                            idx.table_hops.setdefault(fname, f"{hop} {g}() kaydı")
                        elif g in by_name:
                            # Kullanıcı tanımlı callback sarmalayıcısı: ``invoke(handler, value)`` içinde ilk
                            # parametre ``cb(value)`` olarak çağrıldığında somut hedefi çağrı yerine bağla.
                            candidates = by_name[g]
                            if len(candidates) > core.MAX_CANDIDATES:
                                idx.limitations.add("callback-candidates")
                            for gf0 in candidates[:core.MAX_CANDIDATES]:
                                if pos < len(gf0.params):
                                    idx.fptr_params.setdefault((gf0.key, pos), set()).add(fname)
                                    idx.table_hops.setdefault(fname, f"{hop} {g}() callback parametresi")
                            st = stores_cache.get(g)
                            if st is None:
                                gf = by_name[g][0]
                                gu = next((x for x in units if x.path == gf.file), None)
                                st = stores_cache[g] = _param_stores(gu.toks, gf) if gu is not None else {}
                            where = st.get(pos)
                            if where is not None:
                                (idx.fptr_fields if where[0] == "field" else idx.fptr_vars).setdefault(
                                    where[1], set()).add(fname)
                                idx.table_hops.setdefault(fname, f"{hop} {g}(…, {fname}) yönlendirme kaydı")
                    continue
                # tasarımlanmış alan: .handler = fn
                if p >= 1 and toks[p].text == "=" and toks[p - 1].kind == "id" and p >= 2 and toks[p - 2].text == ".":
                    pass
                q = j - 1
                if toks[q].text == "&":
                    q -= 1
                if q >= 2 and toks[q].text == "=" and toks[q - 1].kind == "id" and toks[q - 2].text == ".":
                    idx.fptr_fields.setdefault(toks[q - 1].text, set()).add(fname)
                    idx.table_hops.setdefault(fname, f"{hop} .{toks[q - 1].text} = {fname}")
                    continue
                # konumsal: dış bildirimin yapı türü
                outer = open_
                level = 1
                while outer > 0 and toks[outer - 1].text in ("{", ","):
                    # dış '{' ara
                    d = 0
                    k2 = outer - 1
                    found = -1
                    while k2 >= 0:
                        x = toks[k2]
                        if x.kind == "op" and x.text in (")", "]", "}"):
                            d += 1
                        elif x.kind == "op" and x.text in ("(", "["):
                            d -= 1
                        elif x.kind == "op" and x.text == "{":
                            if d == 0:
                                found = k2
                                break
                            d -= 1
                        elif x.kind == "op" and x.text == ";" and d == 0:
                            break
                        k2 -= 1
                    if found < 0:
                        break
                    outer = found
                    level += 1
                if outer <= 0 or toks[outer - 1].text != "=":
                    continue
                s0 = _stmt_start(toks, outer - 1)
                head = [x for x in toks[s0:outer - 1]]
                var = ""
                q2 = len(head) - 1
                while q2 >= 0 and head[q2].text == "]":
                    while q2 >= 0 and head[q2].text != "[":
                        q2 -= 1
                    q2 -= 1
                if q2 >= 0 and head[q2].kind == "id":
                    var = head[q2].text
                stype = ""
                for hx, x in enumerate(head[:max(q2, 0)]):
                    if x.kind == "id" and x.text in structs:
                        stype = x.text
                    elif x.text in ("struct", "union") and hx + 1 < len(head) and head[hx + 1].kind == "id":
                        stype = head[hx + 1].text
                if stype and level >= 1:
                    order = list(structs.get(stype, {}))
                    # fonksiyon işaretçisi alanları yapı ayrıştırıcısında atlanır: sıra, kaynak metinden yeniden
                    order = _struct_field_order(units, stype, field_order_cache) or order
                    if pos < len(order):
                        idx.fptr_fields.setdefault(order[pos], set()).add(fname)
                        idx.table_hops.setdefault(fname, f"{hop} {var or stype} tablosu .{order[pos]}")
                        array_decl = q2 + 1 < len(head) and head[q2 + 1].text == "["
                        if var and array_decl and level >= 2:
                            element = 0
                            depth = 0
                            for z in range(outer + 1, j):
                                if toks[z].text in ("{", "(", "["):
                                    depth += 1
                                elif toks[z].text in ("}", ")", "]"):
                                    depth = max(0, depth - 1)
                                elif toks[z].text == "," and depth == 0:
                                    element += 1
                            owner = next((fn.key for fn in u.funcs if fn.body[0] < j < fn.body[1]), None)
                            if owner is not None:
                                idx.fptr_receivers.setdefault((owner, f"{var}[{element}]"), set()).add(fname)
                        continue
                if var:
                    idx.fptr_vars.setdefault(var, set()).add(fname)
                    idx.table_hops.setdefault(fname, f"{hop} {var} tablosu")
    return idx


def _struct_field_order(units: list[FileUnit], stype: str,
                        cache: dict[str, list[str]] | None = None) -> list[str]:
    """Yapı alanlarının bildirim sırası (işlev işaretçisi alanları dahil): ``void (*h)(int);`` → h."""
    cache = cache if cache is not None else {}
    if stype in cache:
        return cache[stype]
    order: list[str] = []
    for u in units:
        toks = u.toks
        n = len(toks)
        for i in range(n - 2):
            if toks[i].text not in ("struct", "union"):
                continue
            j = i + 1
            name = toks[j].text if toks[j].kind == "id" else ""
            if name:
                j += 1
            if j >= n or toks[j].text != "{":
                continue
            close = match_close(toks, j)
            alias = []
            q = close + 1
            while q < n and q - close < 8 and toks[q].text != ";":
                if toks[q].kind == "id":
                    alias.append(toks[q].text)
                q += 1
            if stype != name and stype not in alias:
                continue
            start = j + 1
            for k in range(j + 1, close):
                if toks[k].text == ";":
                    seg = toks[start:k]
                    start = k + 1
                    nm = ""
                    for a in range(len(seg) - 2):
                        if seg[a].text == "(" and seg[a + 1].text == "*" and seg[a + 2].kind == "id":
                            nm = seg[a + 2].text
                            break
                    if not nm:
                        b = len(seg) - 1
                        while b >= 0 and seg[b].text == "]":
                            while b >= 0 and seg[b].text != "[":
                                b -= 1
                            b -= 1
                        if b >= 0 and seg[b].kind == "id":
                            nm = seg[b].text
                    if nm:
                        order.append(nm)
            if order:
                break
        if order:
            break
    cache[stype] = order
    return order


# ---------------------------------------------------------------------------
# Giriş noktaları
# ---------------------------------------------------------------------------


def language_of(path: str) -> str:
    low = path.lower()
    for s in CPP_SUFFIXES:
        if low.endswith(s):
            return "cpp"
    return "c"


_INCLUDE_RE = re.compile(r'(?m)^\s*#\s*include\s*"([^"]+)"')
_INCLUDE_META_RE = re.compile(r'(?m)^\s*#\s*include\s*([<"])([^>"]+)[>"]')
_INCLUDE_LINE_RE = re.compile(r'(?m)^\s*#\s*include\s*([<"])([^>"]+)[>"][^\n]*(?:\n|$)')
MAX_TRANSITIVE_HEADER_DEPTH = 16
MAX_TRANSITIVE_HEADER_FILES = 256
MAX_TRANSITIVE_HEADER_BYTES = 2 * 1024 * 1024


def _build_profile(path: str, build_info: Any) -> tuple[
        dict[str, str], set[str], list[str], list[str],
        dict[str, tuple[tuple[str, ...], list[Tok]]], str]:
    """c_build.FileFlags'i statik motorun kapalı veri biçimine çevir.

    Yalnız c_build tarafından süzülmüş -D/-U/include/-include değerleri kabul edilir; burada dosya okunmaz ve
    süreç başlatılmaz.
    """
    if build_info is None or not hasattr(build_info, "flags_for") or not hasattr(build_info, "root"):
        return {}, set(), [], [], {}, "yok"
    try:
        flags = build_info.flags_for(Path(build_info.root) / path)
    except (OSError, ValueError, RuntimeError):
        return {}, set(), [], [], {}, "yok"
    defs: dict[str, str] = {}
    undefs: set[str] = set()
    includes: list[str] = []
    forced: list[str] = []
    function_defs: dict[str, tuple[tuple[str, ...], list[Tok]]] = {}
    args = list(getattr(flags, "args", ()) or ())
    i = 0
    while i < len(args):
        arg = str(args[i]); i += 1
        if arg.startswith("-D") and len(arg) > 2:
            raw = arg[2:]
            name, sep, value = raw.partition("=")
            fm = re.fullmatch(r"([A-Za-z_]\w*)\(([^()]*)\)", name)
            if fm and sep:
                params = tuple(x.strip() for x in fm.group(2).split(",") if x.strip())
                body = value.strip()
                if len(params) <= 8 and len(params) == len(set(params)) and all(
                        re.fullmatch(r"[A-Za-z_]\w*", x) for x in params) and body and len(body) <= 400 \
                        and "#" not in body and "__VA_ARGS__" not in body:
                    bt = core.tokenize(body, rust=False)
                    if 0 < len(bt) <= 96:
                        function_defs[fm.group(1)] = (params, bt)
                        undefs.discard(fm.group(1))
            elif re.fullmatch(r"[A-Za-z_]\w*", name):
                body = value if sep else "1"
                if re.fullmatch(r'[A-Za-z_]\w*|"(?:[^"\\]|\\.)*"|L"(?:[^"\\]|\\.)*"', body):
                    defs[name] = body
                else:
                    value_ = _dim_value(core.tokenize(body, rust=False), {}, positive=False)
                    # c_build zaten uzunluğu ve satır sonlarını sınırlar. Bu küçük sabit değerlendiricinin
                    # çözemediği gövdeyi etkin özellik gibi ``1`` sayma; kapalı profil fail-closed varsayımdır.
                    defs[name] = str(value_) if value_ is not None else "0"
                undefs.discard(name)
        elif arg.startswith("-U") and len(arg) > 2 and re.fullmatch(r"[A-Za-z_]\w*", arg[2:]):
            defs.pop(arg[2:], None); function_defs.pop(arg[2:], None); undefs.add(arg[2:])
        elif arg in ("-I", "-isystem", "-iquote") and i < len(args):
            includes.append(str(args[i])); i += 1
        elif arg == "-include" and i < len(args):
            forced.append(str(args[i])); i += 1
    return defs, undefs, includes[:48], forced[:8], function_defs, \
        str(getattr(flags, "source", "yok") or "yok")


def _relative_build_file(raw: str, build_info: Any, files: dict[str, str]) -> str:
    try:
        rel = Path(raw).resolve().relative_to(Path(build_info.root).resolve()).as_posix()
    except (OSError, ValueError, RuntimeError):
        return ""
    return rel if rel in files else ""


def _resolve_include(path: str, name: str, quoted: bool, include_dirs: list[str],
                     build_info: Any, files: dict[str, str]) -> str:
    candidates: list[str] = []
    if quoted:
        candidates.append((Path(path).parent / name).as_posix())
    if build_info is not None:
        for directory in include_dirs:
            rel = _relative_build_file(str(Path(directory) / name), build_info, files)
            if rel:
                candidates.append(rel)
    if quoted:
        candidates.append(name.replace("\\", "/"))
    for candidate in candidates:
        clean = Path(candidate).as_posix().lstrip("./")
        if clean in files:
            return clean
    return ""


def _expand_project_headers(path: str, include_dirs: list[str], build_info: Any,
                            files: dict[str, str], seen: set[str], budget: list[int],
                            depth: int = 0) -> tuple[str, bool]:
    """Inline bounded project headers before preprocessing so nested macros remain visible.

    System and unresolved includes stay as directives and are ignored by the bounded
    preprocessor as before. ``seen`` is the active recursion path, so an include cycle
    terminates deterministically while a deliberate later re-include is expanded in its
    new macro environment. ``budget`` tracks expanded bytes and visits across siblings.
    """
    if path in seen:
        return "", False
    visits = budget[1] if len(budget) > 1 else 0
    if depth > MAX_TRANSITIVE_HEADER_DEPTH or visits >= MAX_TRANSITIVE_HEADER_FILES:
        return "", True
    text = files.get(path, "")
    size = len(text.encode("utf-8", "replace"))
    if budget[0] + size > MAX_TRANSITIVE_HEADER_BYTES:
        return "", True
    seen.add(path)
    budget[0] += size
    if len(budget) == 1:
        budget.append(1)
    else:
        budget[1] += 1
    limited = False

    def replace(match: re.Match) -> str:
        nonlocal limited
        quoted = match.group(1) == '"'
        selected = _resolve_include(path, match.group(2), quoted, include_dirs, build_info, files)
        if not selected:
            return match.group(0)
        nested, nested_limited = _expand_project_headers(
            selected, include_dirs, build_info, files, seen, budget, depth + 1,
        )
        limited = limited or nested_limited
        return nested

    try:
        expanded = _INCLUDE_LINE_RE.sub(replace, text)
    finally:
        seen.discard(path)
    return expanded, limited


def build_unit(path: str, text: str, extra_macros: dict[str, str] | None = None,
               pre: tuple[list[tuple[int, int]], dict[str, str]] | None = None,
               function_macros: dict[str, tuple[tuple[str, ...], list[Tok]]] | None = None,
               extra_function_macros: dict[str, tuple[tuple[str, ...], list[Tok]]] | None = None) -> FileUnit:
    local_fm: dict[str, tuple[tuple[str, ...], list[Tok]]] = function_macros if function_macros is not None else {}
    skips, macros = pre or preprocess(text, function_macros=local_fm)
    if extra_macros:
        macros = {**extra_macros, **macros}
    fmacros = {**(extra_function_macros or {}), **local_fm}
    toks = core.tokenize(text, rust=False, skip_ranges=skips)
    limitations: set[str] = set()
    if len(toks) > core.MAX_TOKENS_PER_FILE:
        limitations.add("token")
    toks = _substitute(toks, macros)
    toks = _expand_function_macros(toks, fmacros, limitations)
    unit = FileUnit(path, toks, macros={})
    unit.info["limitations"] = limitations
    # CGI: HTML içerik türü basan ve istek verisini ortamdan (QUERY_STRING…) ya da standart girdiden (POST gövdesi)
    # okuyan program; cgi-bin/ altındaki ya da .cgi uzantılı dosyalar da CGI sayılır.
    stdin_reads = re.search(r"\bgets\s*\(|\bstdin\b|\bread\s*\(\s*(0|STDIN_FILENO)\s*,", text)
    cgiish = "getenv" in text or "QUERY_STRING" in text or "cgi" in path.lower()
    # 27. tur: kendi soketini dinleyen sunucu (socket/accept/listen) CGI programı değildir (stdout konsoldur)
    server = bool(re.search(r"\baccept4?\s*\(", text)) and bool(re.search(r"\blisten\s*\(", text))
    unit.info["cgi_html"] = bool(_CGI_HTML_RE.search(text)) and (cgiish or bool(stdin_reads)) and not server
    try:
        extract_functions(unit)
    except (RecursionError, IndexError):
        unit.funcs = []
    _collect_globals(unit)
    caps: dict[str, dict[str, int]] = {}
    try:
        unit.info["structs"] = _collect_structs(unit, caps)
    except (RecursionError, IndexError):
        unit.info["structs"] = {}
    unit.info["struct_caps"] = caps
    return unit


def _collect_globals(unit: FileUnit) -> None:
    """Dosya düzeyindeki değişken bildirimleri: static olanlar dosyaya özgü anahtarla tutulur."""
    toks = unit.toks
    bodies = sorted(f.body for f in unit.funcs)
    statics: set[str] = set()
    globs: set[str] = set()
    gtypes: dict[str, str] = {}
    gdims: dict[str, tuple] = {}
    i, n, b = 0, len(toks), 0
    start = 0
    while i < n:
        if b < len(bodies) and i >= bodies[b][0]:
            i = bodies[b][1] + 1
            start = i
            b += 1
            continue
        t = toks[i]
        if t.kind == "op" and t.text == "{":
            close = match_close(toks, i)
            # sınıf/yapı gövdesi değil, küme ilk değer listesi ise bildirim devam eder
            if i > 0 and toks[i - 1].text == "=":
                i = close + 1
                continue
            i += 1
            start = i
            continue
        if t.kind == "op" and t.text in (";", "}"):
            stmt = toks[start:i]
            if stmt and stmt[0].text not in ("typedef", "using", "extern", "struct", "enum", "union", "class", "namespace", "template") \
                    and not any(x.text == "(" for x in stmt[:3]):
                eq = next((k for k, x in enumerate(stmt) if x.text == "="), len(stmt))
                head = stmt[:eq]
                q = len(head) - 1
                while q >= 0 and head[q].text == "]":
                    while q >= 0 and head[q].text != "[":
                        q -= 1
                    q -= 1
                if q >= 1 and head[q].kind == "id" and head[q].text not in _KEYWORDS:
                    (statics if any(x.text == "static" for x in head) else globs).add(head[q].text)
                    gname = head[q].text
                    gtypes[gname] = " ".join(x.text for x in head[:q])
                    if q + 1 < len(head) and head[q + 1].text == "[":
                        dims: list[list[Tok]] = []
                        r = q + 1
                        while r < len(head) and head[r].text == "[":
                            e = r + 1
                            while e < len(head) and head[e].text != "]":
                                e += 1
                            dims.append(head[r + 1:e])
                            r = e + 1
                        gdims[gname] = (gtypes[gname], dims)
            start = i + 1
        i += 1
    unit.info["statics"] = statics
    unit.info["globals"] = globs
    unit.info["global_types"] = gtypes
    unit.info["global_dims"] = gdims


_NUM_DEFINE_RE = re.compile(r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+([^\n]{1,80})$")


def _numeric_macros(files: dict[str, str]) -> dict[str, int]:
    """Proje genelinde sayısal nesne makroları: ``#define BUFSZ (1024 * 4)`` → 4096 (ilk tanım geçerli)."""
    raw: dict[str, str] = {}
    for text in files.values():
        if len(raw) > 20_000:
            break
        for m in _NUM_DEFINE_RE.finditer(text):
            body = _strip_c_comments(m.group(2), line_comments_each_line=False).strip()
            if body and re.fullmatch(r"[\w\s()+\-*/<]+", body):
                raw.setdefault(m.group(1), body)
    out: dict[str, int] = {}
    for _ in range(3):
        for name, body in raw.items():
            if name in out:
                continue
            v = _dim_value(core.tokenize(body, rust=False), out)
            if v is not None:
                out[name] = v
    return out


def _finish_facts(prog: Any, collector: Collector, units: list[FileUnit]) -> dict[str, Any]:
    """Model olguları: parametre girdileri (çağrı kenarları üzerinden kapanış), yapı alanı kirliliği, küreseller."""
    facts = collector.facts
    param_in: dict[tuple, set[Origin]] = facts.setdefault("param_in", {})
    edges: dict[tuple, set[tuple]] = facts.get("edges", {})
    funcs_by_name: dict[str, list[tuple]] = {}
    for key in set(param_in) | set(edges):
        funcs_by_name.setdefault(key[1], []).append(key)
    changed = True
    rounds = 0
    while changed and rounds < 8:
        changed = False
        rounds += 1
        for key, srcs in edges.items():
            cur = param_in.setdefault(key, set())
            for (cfile, cfunc, cparam, hop) in srcs:
                for o in list(param_in.get((cfile, cfunc, cparam), ())):
                    if len(cur) >= 8:
                        break
                    o2 = o.with_hop(hop)
                    if o2 not in cur and not any(x.source == o.source and x.line == o.line and x.file == o.file
                                                 for x in cur):
                        cur.add(o2)
                        changed = True
    fields: dict[tuple, frozenset] = {}
    globs: dict[tuple, frozenset] = {}
    for key, t in prog.globals.items():
        if not t:
            continue
        if key and key[0] == "#F":
            fields[(key[1], key[2])] = t
        elif len(key) == 2:
            globs[key] = t
    facts["fields"] = fields
    facts["globals"] = globs
    try:
        import cflow_uaf

        facts["dangling"] = cflow_uaf.analyze(units, facts.get("calls", {}))
    except (RecursionError, IndexError, ValueError):
        facts["dangling"] = []
    idx = getattr(prog, "cindex", None)
    facts["callbacks"] = dict(idx.callbacks) if idx is not None else {}
    facts["file_programs"] = dict(idx.file_programs) if idx is not None else {}
    facts["guarded_fields"] = set(idx.guarded_fields) if idx is not None else set()
    facts["stdin_service"] = bool(idx.stdin_service) if idx is not None else False
    facts["table_hops"] = dict(idx.table_hops) if idx is not None else {}
    return facts


def analyze_files(files: dict[str, str], facts_out: dict[str, Any] | None = None,
                  build_info: Any = None) -> dict[str, Analysis]:
    """Proje dosyaları (göreli yol → metin) → dosya başına :class:`Analysis`. ``facts_out`` verilirse dosyalar arası
    model olguları (bellek motoru için dış girdi bilgisi) içine yazılır. ``build_info`` verilirse c_build'in önceden
    süzdüğü compile_commands/CMake/Make tanım ve include yolları yalnız statik önişlemci seçimine katılır."""
    function_macros: dict[str, dict[str, tuple[tuple[str, ...], list[Tok]]]] = {}
    profiles = {path: _build_profile(path, build_info) for path in files}
    pre: dict[str, tuple[list[tuple[int, int]], dict[str, str]]] = {}
    for path, text in files.items():
        defs, undefs, _incs, _forced, build_fm, _source = profiles[path]
        fm: dict[str, tuple[tuple[str, ...], list[Tok]]] = dict(build_fm)
        pre[path] = preprocess(text, defs, undefs, fm)
        function_macros[path] = fm
    # proje başlık dosyalarının makroları onları #include eden dosyalara da uygulanır (ad eşleşmesi)
    header_macros: dict[str, dict[str, str]] = {}
    header_function_macros: dict[str, dict[str, tuple[tuple[str, ...], list[Tok]]]] = {}
    for path, (_, macros) in pre.items():
        if path.lower().endswith((".h", ".hpp", ".hh", ".hxx")) and macros:
            header_macros.setdefault(path.rsplit("/", 1)[-1], macros)
        if path.lower().endswith((".h", ".hpp", ".hh", ".hxx")) and function_macros[path]:
            header_function_macros.setdefault(path.rsplit("/", 1)[-1], function_macros[path])
    units = []
    for path, text in sorted(files.items()):
        extra: dict[str, str] = {}
        extra_fm: dict[str, tuple[tuple[str, ...], list[Tok]]] = {}
        header_limited = False
        header_seen: set[str] = set()
        header_budget = [0, 0]
        defs, undefs, include_dirs, forced, _build_fm, build_source = profiles[path]
        direct_includes = _INCLUDE_META_RE.findall(text)
        if len(direct_includes) > 50:
            header_limited = True
        includes = [(mark == '"', name, False) for mark, name in direct_includes[:50]]
        includes += [(False, rel, True) for raw in forced
                     if (rel := _relative_build_file(raw, build_info, files))]
        for quoted, inc, forced_direct in includes:
            selected = inc if forced_direct and inc in files else \
                _resolve_include(path, inc, quoted, include_dirs, build_info, files)
            hm = None
            hfm = None
            if selected:
                hfm_local: dict[str, tuple[tuple[str, ...], list[Tok]]] = {}
                expanded, limited = _expand_project_headers(
                    selected, include_dirs, build_info, files, header_seen, header_budget,
                )
                header_limited = header_limited or limited
                _skips, hm = preprocess(expanded, defs, undefs, hfm_local)
                hfm = hfm_local
            if hm is None and quoted:
                hm = header_macros.get(inc.rsplit("/", 1)[-1])
                hfm = header_function_macros.get(inc.rsplit("/", 1)[-1])
            if hm:
                for k, v in hm.items():
                    extra.setdefault(k, v)
            if hfm:
                for k, v in hfm.items():
                    extra_fm.setdefault(k, v)
        # Replay the bounded translation unit in source order.  This preserves
        # the macro environment at each include site, including legitimate
        # unguarded headers that are included more than once after #define /
        # #undef changes.  Only the resulting macro tables are consumed; the
        # original source is still tokenized so finding line numbers stay exact.
        tu_seen: set[str] = set()
        tu_budget = [0, 0]
        tu_parts: list[str] = []
        for raw in forced:
            forced_rel = _relative_build_file(raw, build_info, files)
            if not forced_rel:
                continue
            forced_text, limited = _expand_project_headers(
                forced_rel, include_dirs, build_info, files, tu_seen, tu_budget,
            )
            header_limited = header_limited or limited
            tu_parts.append(forced_text)
        expanded_source, limited = _expand_project_headers(
            path, include_dirs, build_info, files, tu_seen, tu_budget,
        )
        header_limited = header_limited or limited
        tu_parts.append(expanded_source)
        tu_fm: dict[str, tuple[tuple[str, ...], list[Tok]]] = {}
        _tu_skips, tu_macros = preprocess("\n".join(tu_parts), defs, undefs, tu_fm)
        extra.update(tu_macros)
        extra_fm.update(tu_fm)
        unit = build_unit(path, text, extra, pre[path], function_macros[path], extra_fm)
        if header_limited:
            unit.info.setdefault("limitations", set()).add("header-expansion")
        unit.info["build_info_source"] = build_source
        units.append(unit)
    # struct tanımları proje genelinde paylaşılır (başlık dosyasındaki tanım .c dosyasında kullanılır)
    structs: dict[str, dict[str, tuple[str, bool, bool]]] = {}
    for u in units:
        for k, v in u.info.get("structs", {}).items():
            structs.setdefault(k, v)
    caps: dict[str, Any] = {}
    for u in units:
        for k, v in u.info.get("struct_caps", {}).items():
            caps.setdefault(k, v)
    num_macros = _numeric_macros(files)
    for defs, _undefs, _incs, _forced, _fdefs, _source in profiles.values():
        for name, body in defs.items():
            if name not in num_macros:
                value = _dim_value(core.tokenize(body, rust=False), num_macros)
                if value is not None:
                    num_macros[name] = value
    gcaps: dict[str, int] = {}
    gtypes: dict[str, str] = {}
    for u in units:
        for k, (typ, dims) in u.info.get("global_dims", {}).items():
            c = _decl_cap(typ, dims, num_macros)
            if c is not None:
                gcaps.setdefault(k, c)
        for k, v in u.info.get("global_types", {}).items():
            gtypes.setdefault(k, v)
    for u in units:
        u.info["structs"] = structs
        u.info["struct_caps"] = caps
        u.info["num_macros"] = num_macros
        u.info["global_caps"] = gcaps
        u.info["global_types"] = gtypes
    language_of_map = {u.path: language_of(u.path) for u in units}
    collector = Collector({}, language_of_map)
    for u in units:
        collector.analysis(u.path)
    hint = bool(facts_out.get("stdin_service_hint")) if facts_out is not None else False
    prog = core.Program(units)
    if hint:
        idx = build_cindex(units, prog.by_name)
        idx.stdin_service = True
        prog.cindex = idx
    prog = core.run_program(units, lambda unit: CBody, collector, rounds=C_ROUNDS, prog=prog)
    limitations = set(prog.limitations)
    limitations.update(getattr(getattr(prog, "cindex", None), "limitations", ()))
    for unit in units:
        limitations.update(unit.info.get("limitations") or ())
    if limitations:
        for analysis in collector.analyses.values():
            analysis.mark_incomplete(*sorted(limitations))
    if facts_out is not None:
        try:
            facts_out.update(_finish_facts(prog, collector, units))
            facts_out["structs"] = structs
            facts_out["struct_caps"] = {k: v for k, v in caps.items()}
            facts_out["num_macros"] = num_macros
        except (RecursionError, ValueError):
            pass
    return collector.analyses


def analyze_single(text: str, filename: str) -> Analysis:
    return analyze_files({filename: text}).get(filename, Analysis(language=language_of(filename)))
