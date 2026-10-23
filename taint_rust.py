"""Rust hızlı taint motoru (saf Python, belirteç tabanlı; derleyici/cargo gerektirmez).

Kaynaklar (``request``): actix-web/axum/rocket/warp/poem/iron/tide çıkarıcıları (Query/Path/Json/Form/
TypedHeader…), istek nesneleri (HttpRequest, &mut Request), işleyici olarak kayıtlı fonksiyonların String/
Bytes/HeaderMap parametreleri, rocket rota parametreleri (<ad>), warp süzgeç kapanışları. Yerel (``local``):
std::env::args/var, stdin — Rust'ta bellek güvenliği hedefi olmadığından yalnız ``unsafe`` uzunluk hedeflerinde.
Hedefler: SQL (sqlx::query/query_as, diesel sql_query/sql, rusqlite/postgres/mysql execute/query/prepare,
sea-orm), komut (Command::new(kirli) ya da sh -c ile kirli argüman), yol (fs::*, File::open/create, NamedFile),
SSRF (reqwest/ureq/surf/awc; sabit ana makine → kısmi SSRF), XSS (Html/RawHtml, text/html içerik türlü yanıt
gövdesi, HTML kalıplı format! ile içerik türsüz gövde), açık yönlendirme (Redirect::*, Location başlığı),
SSTI (Tera::one_off/render_str, handlebars render_template, minijinja render_str), sınırsız ikili seri çözme
(bincode), XPath (sxd_xpath Factory::build/evaluate_xpath), LDAP filtresi (ldap3 search), unsafe uzunluk/indeks.
"""
from __future__ import annotations

import re
from typing import Any

import taint_native_core as core
from taint_native_core import EMPTY, BodyAnalyzer, Collector, FileUnit, Func, Origin, Param, Tok, compact, \
    match_close, numeric, split_args, strings_only
from taint_flow import Analysis

SUFFIXES = frozenset({".rs"})

NUMERIC_TYPES = frozenset({"i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
                           "f32", "f64", "bool", "NonZeroU32", "NonZeroU64", "NonZeroUsize", "Uuid", "NaiveDate",
                           "NaiveDateTime", "DateTime", "IpAddr", "Ipv4Addr", "Ipv6Addr", "SocketAddr", "Duration"})
_EXTRACTORS = frozenset({"Query", "Path", "Json", "Form", "TypedHeader", "Multipart", "MultipartForm", "RawQuery",
                         "Cookies", "CookieJar", "PrivateCookieJar", "SignedCookieJar", "Payload", "RawForm",
                         "OriginalUri", "Host", "Data_"})
_REQUEST_OBJECTS = frozenset({"HttpRequest", "ServiceRequest", "Request"})
_HANDLER_PLAIN = frozenset({"String", "str", "Bytes", "HeaderMap", "Body", "Vec", "Option"})
_ROUTE_ATTRS = re.compile(r"#\s*\[\s*(?:[\w:]*::)?(get|post|put|delete|patch|head|options|route|handler|endpoint|"
                          r"connect|trace|catch)\b")
_STATE_METHODS = frozenset({"app_data", "state", "extensions", "extensions_mut", "peer_addr", "method", "version",
                            "connection_info", "app_config", "resource_map", "match_pattern", "match_name",
                            "remote_addr", "local_addr"})
_BOOL_METHODS = frozenset({"is_empty", "contains", "starts_with", "ends_with", "eq", "ne", "is_some", "is_none",
                           "is_ok", "is_err", "any", "all", "contains_key", "exists", "is_file", "is_dir",
                           "is_absolute", "is_relative", "eq_ignore_ascii_case", "is_ascii", "is_alphanumeric",
                           "cmp", "partial_cmp", "lt", "le", "gt", "ge", "is_match"})
_NUM_METHODS = frozenset({"len", "count", "capacity", "to_digit", "position", "rposition"})
_SANITIZER_METHODS = frozenset({"file_name", "escape_default", "html_escape", "escape_html"})
_SANITIZER_CALLS = frozenset({"encode_text", "encode_safe", "encode_minimal", "encode_double_quoted_attribute",
                              "encode_single_quoted_attribute", "encode_unquoted_attribute", "encode_quoted_attribute",
                              "escape_html", "html_escape", "clean", "sanitize", "sanitize_filename", "sanitize_with_options",
                              "quote", "utf8_percent_encode", "percent_encode", "encode_text_minimal", "escape"})
_SQL_CRATES = re.compile(r"\b(?:sqlx|diesel|rusqlite|postgres|tokio_postgres|mysql|mysql_async|sea_orm|tiberius|"
                         r"duckdb|libsql|sqlite|r2d2_sqlite|deadpool_postgres|bb8_postgres|scylla|clickhouse)\b")
_HTTP_CRATES = re.compile(r"\b(?:reqwest|ureq|surf|awc|hyper|isahc|attohttpc|curl)\b")
_SQL_METHODS = frozenset({"execute", "query", "query_row", "query_map", "prepare", "prepare_cached", "execute_batch",
                          "batch_execute", "simple_query", "query_one", "query_opt", "query_raw", "execute_raw",
                          "query_drop", "query_first", "query_iter", "execute_unprepared", "query_all", "exec_drop",
                          "exec_first", "exec", "prepare_typed"})
_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head"})
_SHELLS = re.compile(r"(?i)^(?:/(?:usr/)?bin/)?(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$")
_SHELL_FLAGS = frozenset({"-c", "/C", "/c", "-Command", "-command", "/K", "/k"})
_HTMLISH = re.compile(r"<\s*/?[a-zA-Z!]")
_NOT_HANDLERS = frozenset({"new", "from", "into", "default", "clone", "parse", "map", "unwrap", "to_string",
                           "to_owned", "len", "ok", "err", "some", "identity", "drop", "boxed", "into_response",
                           "handle_error", "handle_rejection"})
_KEYWORDS = frozenset("""as async await break const continue crate dyn else enum extern false fn for if impl in let loop
match mod move mut pub ref return Self static struct super trait true type unsafe use where while yield""".split())


# ---------------------------------------------------------------------------
# Ayrıştırma: fonksiyonlar, impl blokları, yapılar, işleyici kayıtları
# ---------------------------------------------------------------------------


def _skip_angle(toks: list[Tok], i: int, hi: int) -> int:
    depth = 0
    for j in range(i, hi):
        t = toks[j]
        if t.kind != "op":
            continue
        if t.text == "<":
            depth += 1
        elif t.text == ">":
            depth -= 1
        elif t.text == ">>":
            depth -= 2
        elif t.text == "->":
            continue
        elif t.text in ("{", ";"):
            return j - 1
        if depth <= 0:
            return j
    return hi - 1


def _impl_blocks(toks: list[Tok]) -> list[tuple[int, int, str, bool]]:
    """(açılış, kapanış, tür adı, trait mi) — impl/trait blokları."""
    out = []
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind != "id" or t.text not in ("impl", "trait"):
            continue
        if i > 0 and toks[i - 1].text in ("(", ",", ":", "->", "<", "&", "=", "dyn"):
            continue  # impl Trait tür konumu
        j = i + 1
        if j < n and toks[j].text == "<":
            j = _skip_angle(toks, j, n) + 1
        k = j
        while k < n and toks[k].text not in ("{", ";"):
            k += 1
        if k >= n or toks[k].text != "{":
            continue
        head = toks[j:k]
        words = [x.text for x in head]
        name = ""
        if t.text == "impl" and "for" in words:
            after = head[words.index("for") + 1:]
            name = next((x.text for x in after if x.kind == "id" and x.text not in ("dyn", "mut")), "")
        else:
            idents = [x for x in head if x.kind == "id" and x.text not in ("where", "dyn")]
            # yol: a::b::Tür → son parça (jenerik öncesi)
            last = ""
            for q, x in enumerate(head):
                if x.text == "<" or x.text == "where":
                    break
                if x.kind == "id":
                    last = x.text
            name = last or (idents[0].text if idents else "")
        out.append((k, match_close(toks, k), name, t.text == "trait"))
    return out


def _attrs_before(toks: list[Tok], i: int) -> str:
    """``fn`` belirtecinden geriye #[...] öznitelikleri (pub/async/unsafe/const/extern atlanarak)."""
    parts: list[str] = []
    j = i - 1
    while j >= 0:
        t = toks[j]
        if t.kind == "id" and t.text in ("pub", "async", "unsafe", "const", "extern", "default", "crate", "in", "self", "super"):
            j -= 1
            continue
        if t.kind == "str":  # extern "C"
            j -= 1
            continue
        if t.kind == "op" and t.text == ")" :
            # pub(crate)
            k = j
            while k >= 0 and toks[k].text != "(":
                k -= 1
            j = k - 1
            continue
        if t.kind == "op" and t.text == "]":
            depth = 0
            k = j
            while k >= 0:
                if toks[k].text == "]":
                    depth += 1
                elif toks[k].text == "[":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            if k > 0 and toks[k - 1].text == "#":
                parts.append(" ".join(x.text if x.kind != "str" else '"' + x.text + '"' for x in toks[k - 1:j + 1]))
                j = k - 2
                continue
            break
        break
    return " ".join(reversed(parts))


def _param_names(toks: list[Tok], a: int, b: int) -> list[str]:
    names = []
    for q in range(a, b):
        t = toks[q]
        if t.kind != "id" or t.text in _KEYWORDS or t.text == "_":
            continue
        nxt = toks[q + 1].text if q + 1 < b else ""
        prev = toks[q - 1].text if q - 1 >= a else ""
        if nxt in ("(", "{", "::", "!") or prev == "::":
            continue
        if t.text[:1].isupper():
            continue
        names.append(t.text)
    return names


def extract(unit: FileUnit) -> None:
    toks = unit.toks
    n = len(toks)
    impls = _impl_blocks(toks)
    for i, t in enumerate(toks):
        if t.kind != "id" or t.text != "fn" or i + 1 >= n or toks[i + 1].kind != "id":
            continue
        name_i = i + 1
        j = name_i + 1
        if j < n and toks[j].text == "<":
            j = _skip_angle(toks, j, n) + 1
        if j >= n or toks[j].text != "(":
            continue
        pclose = match_close(toks, j)
        k = pclose + 1
        ret_lo = k
        while k < n and toks[k].text not in ("{", ";"):
            if toks[k].text == "<":
                k = _skip_angle(toks, k, n) + 1
                continue
            if toks[k].text in ("(", "["):
                k = match_close(toks, k) + 1
                continue
            k += 1
        if k >= n or toks[k].text != "{":
            continue
        body_close = match_close(toks, k)
        cls, trait = "", False
        for lo, hi, name, is_trait in impls:
            if lo < i < hi:
                cls, trait = name, is_trait
        params: list[Param] = []
        has_self = False
        for a, b in split_args(toks, j + 1, pclose, angle=True):
            ptoks = toks[a:b]
            words = [x.text for x in ptoks]
            if "self" in words and (len(words) <= 3 or words.index("self") < 3):
                has_self = True
                params.append(Param("self", " ".join(words), len(params), ("self",)))
                continue
            colon = next((q for q in range(a, b) if toks[q].text == ":" and toks[q].kind == "op"), b)
            names = _param_names(toks, a, colon)
            typ = " ".join(x.text for x in toks[colon + 1:b])
            params.append(Param(names[0] if names else "", typ, len(params), tuple(names)))
        ret = " ".join(x.text for x in toks[ret_lo:k])
        fn = Func(toks[name_i].text, f"{cls}::{toks[name_i].text}" if cls else toks[name_i].text, unit.path, params,
                  (k, body_close), toks[name_i].line, cls=cls, has_self=has_self, attrs=_attrs_before(toks, i),
                  ret_type=ret)
        fn.is_handler = bool(_ROUTE_ATTRS.search(fn.attrs))
        unit.funcs.append(fn)
    # yapı alanı türleri
    structs: dict[str, dict[str, str]] = {}
    for i, t in enumerate(toks):
        if t.kind == "id" and t.text == "struct" and i + 2 < n and toks[i + 1].kind == "id":
            j = i + 2
            if toks[j].text == "<":
                j = _skip_angle(toks, j, n) + 1
            while j < n and toks[j].text == "where":
                while j < n and toks[j].text != "{":
                    j += 1
            if j < n and toks[j].text == "{":
                close = match_close(toks, j)
                fields = {}
                for a, b in split_args(toks, j + 1, close, angle=True):
                    colon = next((q for q in range(a, b) if toks[q].text == ":"), -1)
                    if colon > a and toks[colon - 1].kind == "id":
                        fields[toks[colon - 1].text] = " ".join(x.text for x in toks[colon + 1:b])
                structs[toks[i + 1].text] = fields
    unit.info["structs"] = structs
    # işleyici kayıtları: .to(f) / get(f) / post(f) … / routes![a, b] / Iron::new(f) / .and_then(f) / .map(f)
    handlers: set[str] = set()
    unit_words = {x.text for x in toks[:4000] if x.kind == "id"}

    def route_ctx(i: int) -> bool:
        # axum zincirleme: get(a).post(b) — geriye doğru ".route(" ya da serbest get( çağrısı
        for q in range(i - 1, max(0, i - 60), -1):
            if toks[q].kind == "op" and toks[q].text in (";", "{", "}"):
                return False
            if toks[q].kind == "id" and toks[q].text in ("route", "routing", "MethodRouter", "on"):
                return True
        return False

    for i, t in enumerate(toks):
        if t.kind != "id" or i + 3 >= n or toks[i + 1].text != "(":
            continue
        if t.text in ("to", "get", "post", "put", "delete", "patch", "head", "options", "any", "trace", "connect",
                      "and_then", "map", "then", "service", "new", "handler", "at", "on", "fallback", "to_async"):
            if t.text in ("map", "and_then", "then") and "warp" not in unit_words:
                continue
            if t.text in ("get", "post", "put", "delete", "patch", "head", "options", "any", "trace", "connect") and \
                    i > 0 and toks[i - 1].text == "." and not route_ctx(i):
                continue
            close = match_close(toks, i + 1)
            args = split_args(toks, i + 2, close)
            if not args:
                continue
            a, b = args[-1]
            ids = [x for x in toks[a:b] if x.kind == "id"]
            if ids and all(x.kind == "id" or x.text == "::" for x in toks[a:b]) and ids[-1].text[:1].islower() and \
                    ids[-1].text not in _NOT_HANDLERS and not (len(ids) >= 2 and ids[-2].text[:1].isupper()):
                if t.text == "new" and not (i >= 2 and toks[i - 2].text in ("Iron", "Server", "Router")):
                    continue
                handlers.add(ids[-1].text)
        if t.text == "routes" and toks[i + 1].text == "!" :
            pass
    for i, t in enumerate(toks):
        if t.kind == "id" and t.text in ("routes", "openapi_get_routes") and i + 2 < n and toks[i + 1].text == "!":
            close = match_close(toks, i + 2)
            for a, b in split_args(toks, i + 3, close):
                ids = [x.text for x in toks[a:b] if x.kind == "id"]
                if ids:
                    handlers.add(ids[-1])
    unit.info["handlers"] = handlers
    text_imports = " ".join(x.text for x in toks[:4000] if x.kind == "id")
    unit.info["sql"] = bool(_SQL_CRATES.search(text_imports))
    unit.info["http"] = bool(_HTTP_CRATES.search(text_imports))
    unit.info["xpath"] = "sxd_xpath" in text_imports or "sxd_document" in text_imports
    unit.info["ldap"] = "ldap3" in text_imports
    unit.info["warp"] = "warp" in text_imports
    unit.info["iron"] = "iron" in text_imports


# ---------------------------------------------------------------------------
# Gövde yürütücüsü
# ---------------------------------------------------------------------------


def _crate(path: str) -> str:
    """Dosyanın crate kökü (son "/src/" öncesi); çok crate'li depolarda ad çözümlemesi crate içinde kalır."""
    k = path.rfind("/src/")
    if k >= 0:
        return path[:k]
    return path.split("/", 1)[0] if path.startswith("src/") is False and "/" in path else ""


def _generic_args(typ: str) -> str:
    m = re.search(r"<(.*)>", typ)
    return m.group(1).strip() if m else ""


def _type_is_numeric(typ: str) -> bool:
    if re.search(r"\bVec\b|\[|\bBytes\b|\bString\b|\bstr\b|HashMap|BTreeMap", typ):
        return False  # bayt/öğe dizileri ve dizgeler sayı değil, veri taşır
    inner = typ.replace("&", " ").replace("Option <", " ").replace("Vec <", " ").replace(">", " ").replace("<", " ")
    words = [w for w in re.split(r"[\s,()\[\]]+", inner) if w and w not in ("mut", "'static", "Option", "Vec")]
    return bool(words) and all(w in NUMERIC_TYPES for w in words)


class RustBody(BodyAnalyzer):
    LANG = "rust"
    BLOCK_KEYWORDS = frozenset({"if", "else", "match", "while", "for", "loop", "unsafe"})
    SKIP_KEYWORDS = frozenset({"mut", "ref", "move", "async", "await", "dyn", "impl", "pub", "crate", "super", "where",
                               "in", "true", "false", "None", "let", "if", "else", "match", "while", "for", "loop",
                               "unsafe", "break", "continue", "Self", "const", "static", "return"})
    NUMERIC_TYPES = NUMERIC_TYPES

    def prepare(self) -> None:
        super().prepare()
        fn = self.fn
        info = self.unit.info
        handlers = self.prog_handlers()
        is_handler = fn.is_handler or fn.name in handlers
        rocket_params = set(re.findall(r"<(\w+)(?:\.\.)?>", fn.attrs)) if fn.attrs else set()
        for p in fn.params:
            if p.name == "self":
                continue
            typ = p.type_text.replace(" ", "")
            base = re.sub(r"^&(?:'\w+)?(?:mut)?", "", typ)
            head = re.split(r"[<(]", base, 1)[0].split("::")[-1]
            gen = _generic_args(p.type_text)
            label = ""
            if head in _EXTRACTORS and gen and not gen.startswith("'"):
                if not _type_is_numeric(gen):
                    label = f"istek parametresi ({head}<{gen.replace(' ', '')[:40]}>)"
                struct = re.split(r"[<\s,(]", gen.split("::")[-1].strip(), 1)[0]
                if struct in self.struct_fields_all():
                    for nm in p.names or (p.name,):
                        self.var_info.setdefault(nm, {})["struct"] = struct
                # Path<(String, u32)> deseni → konumsal türler
                if gen.startswith("(") and len(p.names) > 1:
                    gtypes = [g.strip() for g in gen.strip("() ").split(",")]
                    for nm, gt in zip(p.names, gtypes):
                        if _type_is_numeric(gt):
                            self.var_info.setdefault(nm, {})["numeric"] = True
            elif head in _REQUEST_OBJECTS and (head != "Request" or is_handler or info.get("iron") or "hyper" in typ or "axum" in typ
                                               or re.search(r"\bResponse\b", fn.ret_type or "")):
                # 18. tur: kendi HTTP katmanı: fn(…, req: &Request) -> Response (proje içi istek/yanıt türleri)
                label = f"HTTP isteği ({head})"
            elif is_handler and head in _HANDLER_PLAIN and not _type_is_numeric(base):
                label = f"istek gövdesi/parametresi ({head})"
            elif rocket_params and (set(p.names) & rocket_params) and re.fullmatch(
                    r"(?:Option<)?(?:&(?:'\w+)?)?(?:str|String|Cow<(?:'\w+,)?str>)>?", base):
                # rocket: yalnız dize türleri; PathBuf (FromSegments ".." reddeder) ve özel FromParam türleri doğrular
                label = "rota parametresi (rocket)"
            elif fn.attrs and "data" in fn.attrs and head in ("Form", "Json", "Data"):
                label = f"istek gövdesi ({head})"
            if label:
                self.handler_like = True
                for nm in p.names or (p.name,):
                    if self.var_info.get(nm, {}).get("numeric"):
                        continue
                    self.env[nm] = self.env.get(nm, EMPTY) | self.src("request", label, fn.line)
        # yol arındırma: canonicalize/starts_with denetimi ya da ".." kontrolü yapılan değişkenler
        toks = self.toks
        lo, hi = fn.body
        self.path_guards: set[str] = set()
        for j in range(lo, hi - 3):
            t = toks[j]
            if t.kind == "id" and toks[j + 1].text == "." and toks[j + 2].kind == "id" and toks[j + 2].text in (
                    "starts_with", "strip_prefix", "components") and toks[j + 3].text == "(":
                self.path_guards.add(t.text)
            if t.kind == "id" and toks[j + 1].text == "." and toks[j + 2].text == "contains" and toks[j + 3].text == "(" \
                    and j + 4 < hi and toks[j + 4].kind == "str" and ".." in toks[j + 4].text:
                self.path_guards.add(t.text)
        # doğrulama fonksiyonu: if !path_is_valid(p) / sanitize_path(&p) → p yol hedeflerinde arındırılmış sayılır
        for j in range(lo, hi - 2):
            t = toks[j]
            if t.kind == "id" and toks[j + 1].text == "(" and re.search(r"(?i)valid|saniti|safe_path|is_safe|allowed|check_path", t.text):
                close = match_close(toks, j + 1, hi)
                for q in range(j + 2, close):
                    if toks[q].kind == "id":
                        self.path_guards.add(toks[q].text)
        self.pending_match: frozenset | None = None

    handler_like = False

    def finish(self) -> None:
        super().finish()
        if self.handler_like:
            # işleyicinin kendi istek kaynakları dönüş özetine yazılmaz (uri!/doğrudan çağrılarda dönüş istek verisi değildir)
            self.summary.ret_sources.clear()

    def prog_handlers(self) -> set[str]:
        """Bu dosyanın crate'inde kayıtlı işleyici adları (çok crate'li depolarda adlar crate dışına taşmaz)."""
        by_crate = getattr(self.prog, "_rust_handlers", None)
        if by_crate is None:
            by_crate = {}
            for u in self.prog.units:
                by_crate.setdefault(_crate(u.path), set()).update(u.info.get("handlers", set()))
            self.prog._rust_handlers = by_crate  # type: ignore[attr-defined]
        return by_crate.get(_crate(self.file), set())

    def struct_fields_all(self) -> dict[str, dict[str, str]]:
        sf = getattr(self.prog, "_rust_structs", None)
        if sf is None:
            sf = {}
            for u in self.prog.units:
                sf.update(u.info.get("structs", {}))
            self.prog._rust_structs = sf  # type: ignore[attr-defined]
        return sf

    def out_param(self, p: Param) -> bool:
        return "&mut" in p.type_text.replace(" ", "") or "& mut" in p.type_text

    # -- deyimler ------------------------------------------------------------

    def enter_block(self, lo: int, hi: int) -> None:
        if self.pending_match is not None:
            subject = self.pending_match
            self.pending_match = None
            self.match_arms(lo + 1, hi, subject)
            return
        self.block(lo + 1, hi)

    def match_arms(self, lo: int, hi: int, subject: frozenset) -> None:
        toks = self.toks
        i = lo
        while i < hi:
            # desen: '=>' öncesi (üst düzey)
            j = i
            depth = 0
            while j < hi:
                x = toks[j]
                if x.kind == "op":
                    if x.text in "([{":
                        depth += 1
                    elif x.text in ")]}":
                        depth -= 1
                    elif x.text == "=>" and depth == 0:
                        break
                j += 1
            if j >= hi:
                return
            guard_at = next((q for q in range(i, j) if toks[q].kind == "id" and toks[q].text == "if"), j)
            for name in _param_names(toks, i, guard_at):
                self.declare(name)
                self.set_var(name, subject, strong=False)
            if guard_at < j:
                self.evaluate(guard_at + 1, j)
            k = j + 1
            if k < hi and toks[k].text == "{":
                close = match_close(toks, k, hi)
                self.branch_depth += 1
                try:
                    self.block(k + 1, close)
                finally:
                    self.branch_depth -= 1
                i = close + 1
                if i < hi and toks[i].text == ",":
                    i += 1
                continue
            # ifade gövdesi: ',' (üst düzey) ya da blok sonuna kadar
            e = k
            depth = 0
            while e < hi:
                x = toks[e]
                if x.kind == "op":
                    if x.text in "([{":
                        e = match_close(toks, e, hi) + 1
                        continue
                    if x.text == "," and depth == 0:
                        break
                e += 1
            self.branch_depth += 1
            try:
                val = self.evaluate(k, e)
                self.nested_blocks(k, e)
            finally:
                self.branch_depth -= 1
            self.ret |= val
            i = e + 1

    def statement(self, lo: int, hi: int, *, header: bool, tail: bool) -> None:
        toks = self.toks
        first = toks[lo]
        if first.kind == "op" and first.text == "#":
            # deyim özniteliği #[cfg(...)] — atla
            if lo + 1 < hi and toks[lo + 1].text == "[":
                close = match_close(toks, lo + 1, hi)
                if close + 1 < hi:
                    self.statement(close + 1, hi, header=header, tail=tail)
            return
        if first.kind == "id" and first.text == "let":
            self.let_statement(lo, hi)
            return
        if header:
            self.header(lo, hi)
            return
        if first.kind == "id" and first.text == "return":
            self.ret |= self.evaluate(lo + 1, hi)
            self.nested_blocks(lo, hi)
            return
        if first.kind == "id" and first.text in ("use", "mod", "struct", "enum", "type", "impl", "trait", "fn",
                                                 "const", "static", "extern", "macro_rules"):
            return
        split = self.assignment_split(lo, hi)
        if split is not None:
            eq, op = split
            rhs = self.evaluate(eq + 1, hi)
            chain = self.chain
            if eq - lo == 1 and toks[lo].kind == "id":
                name = toks[lo].text
                self.set_var(name, rhs, strong=(op == "="))
                if chain:
                    self.var_info.setdefault(name, {})["chain"] = chain
            else:
                self.evaluate(lo, eq)
                self.taint_target(lo, eq, rhs, strong=False)
            self.nested_blocks(lo, hi)
            return
        val = self.evaluate(lo, hi)
        if tail:
            self.ret |= val
        self.nested_blocks(lo, hi)

    def header(self, lo: int, hi: int) -> None:
        toks = self.toks
        i = lo
        while i < hi and toks[i].kind == "id" and toks[i].text in ("else", "unsafe", "loop"):
            i += 1
        if i >= hi:
            return
        kw = toks[i].text
        if kw in ("if", "while") and i + 1 < hi and toks[i + 1].text == "let":
            eq = next((q for q in range(i + 2, hi) if toks[q].text == "=" and toks[q].kind == "op"), -1)
            if eq > 0:
                val = self.evaluate(eq + 1, hi)
                for name in _param_names(toks, i + 2, eq):
                    self.declare(name)
                    self.set_var(name, val, strong=False)
                self.nested_blocks(eq + 1, hi)
            return
        if kw == "for":
            inn = next((q for q in range(i + 1, hi) if toks[q].kind == "id" and toks[q].text == "in"), -1)
            if inn > 0:
                val = self.evaluate(inn + 1, hi)
                for name in _param_names(toks, i + 1, inn):
                    self.declare(name)
                    self.set_var(name, val, strong=False)
            return
        if kw == "match":
            self.pending_match = self.evaluate(i + 1, hi)
            self.nested_blocks(i + 1, hi)
            return
        if kw in ("if", "while"):
            self.evaluate(i + 1, hi)
            return

    def let_statement(self, lo: int, hi: int) -> None:
        toks = self.toks
        eq = None
        depth = 0
        for q in range(lo + 1, hi):
            x = toks[q]
            if x.kind == "op":
                if x.text in "([{<":
                    depth += 1 if x.text != "<" else 0
                elif x.text in ")]}":
                    depth -= 1
                elif x.text == "=" and depth == 0:
                    eq = q
                    break
        pat_end = eq if eq is not None else hi
        colon = next((q for q in range(lo + 1, pat_end) if toks[q].text == ":" and toks[q].kind == "op"), pat_end)
        names = _param_names(toks, lo + 1, colon)
        typ = " ".join(x.text for x in toks[colon + 1:pat_end]) if colon < pat_end else ""
        for name in names:
            self.declare(name)
        if eq is None:
            for name in names:
                self.env[name] = EMPTY
            return
        # let-else: "let Some(x) = e else { … };"
        rhs_end = hi
        depth = 0
        seen_if = False
        for q in range(eq + 1, hi):
            x = toks[q]
            if x.kind == "op" and x.text in "([{":
                depth += 1
            elif x.kind == "op" and x.text in ")]}":
                depth -= 1
            elif x.kind == "id" and x.text in ("if", "match") and depth == 0:
                seen_if = True
            elif x.kind == "id" and x.text == "else" and depth == 0 and not seen_if:
                rhs_end = q
                break
        self.chain = None
        rhs = self.evaluate(eq + 1, rhs_end)
        chain = self.chain
        if typ and _type_is_numeric(typ):
            rhs = numeric(rhs)
        for name in names:
            self.set_var(name, rhs, strong=True)
            if chain:
                self.var_info.setdefault(name, {})["chain"] = chain
            if self._htmlish(eq + 1, rhs_end):
                self.var_info.setdefault(name, {})["htmlish"] = True
            m = re.search(r"(\w+)\s*(?:>|$)", typ.split("::")[-1]) if typ else None
            if m and m.group(1) in self.struct_fields_all():
                self.var_info.setdefault(name, {})["struct"] = m.group(1)
        self.nested_blocks(eq + 1, hi)

    def _htmlish(self, lo: int, hi: int) -> bool:
        toks = self.toks
        for q in range(lo, min(hi, lo + 400)):
            if toks[q].kind == "str" and _HTMLISH.search(toks[q].text):
                return True
            if toks[q].kind == "id" and self.var_info.get(toks[q].text, {}).get("htmlish"):
                return True
        return False

    def evaluate(self, lo: int, hi: int) -> frozenset:
        toks = self.toks
        if lo < hi and ((toks[lo].kind == "id" and toks[lo].text in ("if", "match", "loop", "unsafe", "async")) or
                        (toks[lo].kind == "op" and toks[lo].text == "{")):
            return self.block_expr(lo, hi)
        return super().evaluate(lo, hi)

    def block_expr(self, lo: int, hi: int) -> frozenset:
        """Blok ifadesinin değeri: if/else dallarının ve match kollarının son ifadeleri (koşul yalnız yan etki)."""
        toks = self.toks
        j = lo
        while j < hi and toks[j].kind == "id" and toks[j].text in ("unsafe", "async", "move", "loop"):
            j += 1
        if j < hi and toks[j].kind == "id" and toks[j].text == "match":
            head_end = next((q for q in range(j + 1, hi) if toks[q].text == "{" and toks[q].kind == "op"), hi)
            subject = super().evaluate(j + 1, head_end)
            if head_end >= hi:
                return EMPTY
            close = match_close(toks, head_end, hi)
            return self.match_value(head_end + 1, close, subject)
        out = EMPTY
        while j < hi:
            t = toks[j]
            if t.kind == "op" and t.text == "{":
                close = match_close(toks, j, hi)
                out = out | self.block_value(j + 1, close)
                j = close + 1
                continue
            if t.kind == "id" and t.text in ("if", "else"):
                # koşul: '{' öncesi
                k = j + 1
                if t.text == "if":
                    head_end = k
                    while head_end < hi and not (toks[head_end].kind == "op" and toks[head_end].text == "{"):
                        if toks[head_end].text in ("(", "["):
                            head_end = match_close(toks, head_end, hi)
                        head_end += 1
                    if k < hi and toks[k].text == "let":
                        eq = next((q for q in range(k + 1, head_end) if toks[q].text == "="), -1)
                        if eq > 0:
                            val = super().evaluate(eq + 1, head_end)
                            for name in _param_names(toks, k + 1, eq):
                                self.declare(name)
                                self.set_var(name, val, strong=False)
                    else:
                        super().evaluate(k, head_end)
                    j = head_end
                    continue
                j = k
                continue
            j += 1
        return compact(out)

    def block_value(self, lo: int, hi: int) -> frozenset:
        """Blok içeriğinin son (';' ile bitmeyen) ifadesinin değeri; önceki let bağlamaları ön değerlendirilir."""
        toks = self.toks
        i = lo
        last = None
        while i < hi:
            if toks[i].kind == "op" and toks[i].text in (";", ","):
                i += 1
                continue
            j, header = self.stmt_end(i, hi)
            if j <= i:
                j = i + 1
            if header:
                # if/match başlığı + bloğu: tek ifade olarak al
                k = j
                while k < hi and toks[k].kind == "op" and toks[k].text == "{":
                    k = match_close(toks, k, hi) + 1
                    while k < hi and toks[k].kind == "id" and toks[k].text == "else":
                        k += 1
                        while k < hi and not (toks[k].kind == "op" and toks[k].text == "{"):
                            k += 1
                last = (i, k, False)
                i = k
                continue
            terminated = j < hi and toks[j].text == ";"
            if toks[i].kind == "id" and toks[i].text == "let" and terminated:
                # blok içi let: değer zinciri için ön bağlama (deyim düzeyinde ayrıca işlenir)
                self.let_statement(i, j)
            last = (i, j, terminated)
            i = j + 1 if terminated else j
        if last is None or last[2]:
            return EMPTY
        a, b, _ = last
        if toks[a].kind == "id" and toks[a].text == "return":
            a += 1
        return self.evaluate(a, b)

    def match_value(self, lo: int, hi: int, subject: frozenset) -> frozenset:
        toks = self.toks
        out = EMPTY
        i = lo
        while i < hi:
            j = i
            depth = 0
            while j < hi:
                x = toks[j]
                if x.kind == "op":
                    if x.text in "([{":
                        depth += 1
                    elif x.text in ")]}":
                        depth -= 1
                    elif x.text == "=>" and depth == 0:
                        break
                j += 1
            if j >= hi:
                break
            guard_at = next((q for q in range(i, j) if toks[q].kind == "id" and toks[q].text == "if"), j)
            for name in _param_names(toks, i, guard_at):
                self.declare(name)
                self.set_var(name, subject, strong=False)
            k = j + 1
            if k < hi and toks[k].text == "{":
                close = match_close(toks, k, hi)
                out = out | self.block_value(k + 1, close)
                i = close + 1
                if i < hi and toks[i].text == ",":
                    i += 1
                continue
            e = k
            while e < hi:
                x = toks[e]
                if x.kind == "op" and x.text in "([{":
                    e = match_close(toks, e, hi) + 1
                    continue
                if x.kind == "op" and x.text == ",":
                    break
                e += 1
            out = out | self.evaluate(k, e)
            i = e + 1
        return compact(out)

    # -- kapanışlar -----------------------------------------------------------

    def closure_start(self, i: int, lo: int) -> bool:
        toks = self.toks
        if i == lo:
            return True
        prev = toks[i - 1]
        return prev.text in ("(", ",", "=", "move", "return", "=>", "{", ";", ":") or prev.kind == "id" and prev.text in ("move",)

    def closure(self, i: int, hi: int) -> int:
        toks = self.toks
        if toks[i].text == "||":
            body = i + 1
            params: list[tuple[list[str], str]] = []
        else:
            j = i + 1
            depth = 0
            while j < hi and not (toks[j].text == "|" and depth == 0):
                if toks[j].text in ("(", "[", "<"):
                    depth += 1
                elif toks[j].text in (")", "]", ">"):
                    depth -= 1
                j += 1
            params = []
            for a, b in split_args(toks, i + 1, j, angle=True):
                colon = next((q for q in range(a, b) if toks[q].text == ":"), b)
                params.append((_param_names(toks, a, colon), " ".join(x.text for x in toks[colon + 1:b])))
            body = j + 1
        ctx = self.closure_ctx
        for names, typ in params:
            base = typ.replace(" ", "")
            head = re.split(r"[<(]", re.sub(r"^&(?:mut)?", "", base), 1)[0].split("::")[-1]
            t = ctx
            if head in _REQUEST_OBJECTS or (self.unit.info.get("warp") and self.closure_warp and not _type_is_numeric(base)):
                t = t | self.src("request", f"HTTP isteği (kapanış parametresi {head or 'warp'})", toks[i].line)
            if _type_is_numeric(base):
                t = numeric(t)
            for name in names:
                self.declare(name)
                self.set_var(name, t, strong=False)
        # gövde
        if body < hi and toks[body].text == "{":
            return match_close(toks, body, hi) + 1  # blok gövdesi deyim düzeyinde (nested_blocks) işlenir
        if body < hi and toks[body].text == "->":
            k = body
            while k < hi and toks[k].text != "{":
                k += 1
            return match_close(toks, k, hi) + 1 if k < hi else hi
        e = body
        while e < hi:
            x = toks[e]
            if x.kind == "op" and x.text in "([{":
                e = match_close(toks, e, hi) + 1
                continue
            if x.kind == "op" and x.text in (",", ")", ";", "}"):
                break
            e += 1
        self.evaluate(body, e)
        return e

    closure_warp = False

    # -- çağrılar ---------------------------------------------------------------

    def macro(self, parts: list[str], lo: int, hi: int, name_idx: int) -> frozenset:
        name = parts[-1]
        toks = self.toks
        if name in ("query", "query_as", "query_scalar", "query_file", "query_as_unchecked", "sql", "include_str", "uri",
                    "include_bytes", "env", "concat", "stringify", "matches", "assert", "assert_eq", "debug_assert",
                    "assert_ne", "cfg"):
            # derleme zamanı denetimli sorgu makroları / sabitler
            for a, b in split_args(toks, lo, hi):
                self.evaluate(a, b)
            return EMPTY
        if name in ("write", "writeln") and lo < hi:
            args = split_args(toks, lo, hi)
            if args:
                val = EMPTY
                for a, b in args[1:]:
                    val = val | self.evaluate(a, b)
                self.taint_target(*args[0], val)
            return EMPTY
        if name in ("format", "format_args", "vec", "json", "concat_string", "html", "hashmap", "btreemap",
                    "context", "doc", "tera_context"):
            args = split_args(toks, lo, hi)
            out = EMPTY
            host = False
            for k, (a, b) in enumerate(args):
                if k == 0 and b - a == 1 and toks[a].kind == "str":
                    lit = toks[a].text
                    if self.fixed_host_literal(lit):
                        host = True
                    else:
                        # "http://ana-makine:port{path}": yer tutucu doğrudan ana makineden sonra ve değer bir yol
                        # (path/path_and_query her zaman "/" ile başlar) → ana makine sabit
                        m = re.match(r"https?://[^/{}@\s]+\{(\w*)", lit)
                        if m:
                            ph = m.group(1)
                            nxt = args[1] if len(args) > 1 else None
                            nxt_text = " ".join(x.text for x in toks[nxt[0]:nxt[1]]) if nxt else ""
                            if "path" in ph.lower() or (not ph and "path" in nxt_text.lower()):
                                host = True
                    # format!("{name}") yakalanan değişkenler
                    for nm in re.findall(r"\{([A-Za-z_]\w*)(?:[:}])", toks[a].text):
                        out = out | self.var_taint(nm)
                    continue
                eqpos = next((q for q in range(a, b) if toks[q].text == "=" and toks[q].kind == "op"), -1)
                out = out | (self.evaluate(eqpos + 1, b) if eqpos > 0 else self.evaluate(a, b))
            return core.with_host(out) if host else out
        if name in ("println", "print", "eprintln", "eprint", "info", "debug", "warn", "error", "trace", "log",
                    "panic", "unreachable", "todo", "unimplemented", "tracing"):
            for a, b in split_args(toks, lo, hi):
                self.evaluate(a, b)
            return EMPTY
        if name == "params" or name == "named_params":
            for a, b in split_args(toks, lo, hi):
                self.evaluate(a, b)
            return EMPTY
        return self.args_union(lo, hi)

    def call(self, parts: list[str], open_: int, close: int, name_idx: int, turbofish: str) -> frozenset:
        toks = self.toks
        name = parts[-1]
        line = toks[name_idx].line
        path = "::".join(parts)
        ranges = split_args(toks, open_ + 1, close)
        info = self.unit.info
        # kaynaklar
        if parts[-2:] in (["env", "args"], ["env", "args_os"]) or (name in ("args", "args_os") and len(parts) == 1 and False):
            return self.src("local", "komut satırı argümanı (env::args)", line)
        if parts[-2:] in (["env", "var"], ["env", "var_os"]):
            for a, b in ranges:
                self.evaluate(a, b)
            return self.src("local", "ortam değişkeni (env::var)", line)
        if parts[-2:] == ["io", "stdin"] or (name == "stdin" and len(parts) <= 2):
            self.next_chain = {"stdin": True}
            return EMPTY
        # arındırıcılar ve sayısal dönüşümler
        if name in _SANITIZER_CALLS and (name not in ("escape", "clean", "quote", "sanitize", "encode") or len(parts) >= 1):
            for a, b in ranges:
                self.evaluate(a, b)
            return EMPTY
        if len(parts) >= 2 and parts[-2] in NUMERIC_TYPES and name in ("from_str", "from_str_radix", "try_from", "from"):
            return numeric(self.args_union(open_ + 1, close))
        taints = self.arg_taints(ranges)
        # oluşturucu zincirleri
        if parts[-2:] == ["Command", "new"] and taints:
            lit = self._lit(ranges[0])
            self.sink("command", "Command::new()", line, strings_only(taints[0]))
            self.next_chain = {"cmd": True, "shell": bool(_SHELLS.match(lit)), "dash": False}
            return EMPTY
        if len(parts) >= 2 and parts[-2] in ("HttpResponse", "HttpResponseBuilder") or parts[-2:] in (["Response", "builder"], ["Builder", "new"]):
            self.next_chain = {"resp": True, "html": False}
            return EMPTY
        if parts[-2:] in (["Client", "new"], ["Client", "builder"], ["ClientBuilder", "new"], ["Client", "default"],
                          ["Agent", "new"], ["AgentBuilder", "new"]) and info.get("http"):
            self.next_chain = {"http": True}
            return EMPTY
        if parts[-2:] == ["Factory", "new"] and info.get("xpath"):
            self.next_chain = {"xpath": True}
            return EMPTY
        # hedefler
        if info.get("sql") and name in ("query", "query_as", "query_scalar", "query_with", "query_as_with", "raw_sql",
                                         "sql_query", "query_file") and taints and (
                parts[0] in ("sqlx", "diesel", "sea_orm") or (len(parts) == 1 and len(taints) <= 2 and not self.prog.by_name.get(name))):
            self.sink("sql", f"{path}()", line, strings_only(taints[0]))
            return taints[0]
        if info.get("sql") and name == "sql" and turbofish and taints:
            self.sink("sql", "diesel::dsl::sql()", line, strings_only(taints[0]))
            return taints[0]
        if parts[-2:] in (["Statement", "from_string"], ["Statement", "from_sql_and_values"]) and len(taints) >= 2:
            self.sink("sql", f"{path}()", line, strings_only(taints[1]))
            return EMPTY
        if (len(parts) >= 2 and parts[-2] in ("fs", "File", "NamedFile", "ServeFile", "ServeDir", "OpenOptions")
                and name in ("read", "read_to_string", "write", "remove_file", "remove_dir", "remove_dir_all", "read_dir",
                             "copy", "rename", "create_dir_all", "open", "create", "open_async", "new", "read_link",
                             "metadata", "set_permissions", "hard_link", "symlink_metadata", "append")) and taints:
            self.path_sink(f"{path}()", line, ranges[0], taints[0])
            if name in ("read", "read_to_string", "open", "open_async", "read_dir"):
                return EMPTY
            return EMPTY
        if name in ("get", "post", "put", "delete", "patch", "head", "request", "get_async") and len(parts) >= 2 and \
                parts[0] in ("reqwest", "ureq", "surf", "isahc", "attohttpc", "awc") and taints:
            idx = 1 if name == "request" and len(taints) > 1 else 0
            self.sink("ssrf", f"{path}()", line, strings_only(taints[idx]))
            return EMPTY
        if name in ("Html", "RawHtml") or (name == "html" and "reply" in parts):
            if taints:
                self.sink("html", f"{path}()", line, strings_only(taints[0]))
            return taints[0] if taints else EMPTY
        if len(parts) >= 2 and parts[-2] == "Redirect" and name in ("to", "temporary", "permanent", "found", "see_other",
                                                                  "moved", "new", "with_status_code") and taints:
            self.sink("redirect", f"{path}()", line, strings_only(taints[-1] if name == "with_status_code" else taints[0]))
            return EMPTY
        if parts[0] == "warp" and name in ("redirect", "temporary", "permanent", "see_other", "found") and taints:
            self.sink("redirect", f"{path}()", line, strings_only(taints[0]))
            return EMPTY
        if parts[-2:] == ["Response", "with"] and taints:
            tup = taints[0]
            for t in taints[1:]:
                tup = tup | t
            a, b = ranges[0]
            html_marker = any(x.kind == "id" and x.text in ("html", "Html", "TEXT_HTML", "TEXT_HTML_UTF_8") for x in toks[a:b]) \
                or any(x.kind == "str" and "text/html" in x.text for x in toks[a:b])
            if html_marker or self._htmlish(a, b):
                self.sink("html", "Response::with()", line, strings_only(tup))
            else:
                self.col.evaluated(self.file, "html", line)
            return EMPTY
        if parts[0] == "bincode" and name in ("deserialize", "deserialize_from", "decode_from_slice",
                                              "decode_from_std_read", "borrow_decode_from_slice") and taints:
            self.sink("deserialize_unbounded", f"{path}()", line, strings_only(taints[0]))
            return taints[0]
        if name == "evaluate_xpath" and len(taints) >= 2:
            self.sink("xpath", "evaluate_xpath()", line, strings_only(taints[1]))
            return EMPTY
        if parts[-2:] in (["Tera", "one_off"],) and taints:
            self.sink("ssti", "Tera::one_off()", line, strings_only(taints[0]))
            return EMPTY
        if name in ("from_raw_parts", "from_raw_parts_mut") and len(taints) >= 2:
            self.sink("memory_len", f"{path}()", line, numeric(taints[1]) if any(o.numeric for o in taints[1]) else frozenset(o for o in taints[1] if o.numeric or o.label == "param"))
            return EMPTY
        if name in ("copy", "copy_nonoverlapping") and "ptr" in parts and len(taints) >= 3:
            self.sink("memory_len", f"{path}()", line, frozenset(o for o in taints[2] if o.numeric or o.label == "param"))
            return EMPTY
        cls = parts[-2] if len(parts) >= 2 and parts[-2][:1].isupper() and parts[-2] != "Self" else (self.fn.cls if parts[0] == "Self" else "")
        if not cls and len(parts) >= 2 and parts[0] in ("std", "core", "alloc", "tokio", "serde", "serde_json"):
            out = EMPTY
            for t in taints:
                out = out | t
            return out
        return self.default_call(name, ranges, taints, line, cls=cls, strict=bool(cls))

    next_chain: dict[str, Any] | None = None

    def primary(self, i: int, hi: int) -> tuple[int, frozenset]:
        self.next_chain = None
        return super().primary(i, hi)

    def postfix(self, i: int, hi: int, cur: frozenset, base: str | None) -> tuple[int, frozenset]:
        if self.next_chain is not None:
            self.chain = self.next_chain
            self.next_chain = None
        return super().postfix(i, hi, cur, base)

    def default_call(self, name: str, ranges: list[tuple[int, int]], taints: list[frozenset], line: int,
                     *, method: bool = False, cls: str = "", strict: bool = False) -> frozenset:
        if name and name[:1].isupper() and not self.prog.by_name.get(name):
            # Some(x) / Ok(x) / Box::new(x) / tuple struct: argümanların birleşimi
            out = EMPTY
            for t in taints:
                out = out | t
            return out
        target = self.aliases.get(name, name)
        cands = [f for f in self.prog.resolve(target, self.file, len(taints), method=method, cls=cls, strict=strict)
                 if _crate(f.file) == _crate(self.file)]
        if cands:
            return self.apply(cands, taints, line, target, ranges)
        out = EMPTY
        for t in taints:
            out = out | t
        return compact(out)

    def method(self, name: str, dot: int, open_: int, close: int, recv: frozenset, base: str | None,
               turbofish: str) -> frozenset:
        toks = self.toks
        line = toks[dot].line
        chain = self.chain
        ranges = split_args(toks, open_ + 1, close)
        saved_ctx, saved_warp = self.closure_ctx, self.closure_warp
        self.closure_ctx = recv
        self.closure_warp = bool(self.unit.info.get("warp")) and name in ("map", "and_then", "then", "untuple_one") and \
            self._warp_chain(dot)
        try:
            taints = self.arg_taints(ranges)
        finally:
            self.closure_ctx, self.closure_warp = saved_ctx, saved_warp
        self.chain = chain
        info = self.unit.info
        # 18. tur: doğrulama çağrısı + "?" (policy.validate(&url)?; ensure_allowed(&u)?): başarısızlıkta erken dönülür,
        # sonrasında değişken doğrulanmış sayılır (izin listesi/kapsam denetimi).
        if re.fullmatch(r"(?i)(validate|verify|ensure|check)(_\w+)?", name) and ranges and close + 1 < len(toks) and \
                toks[close + 1].text == "?":
            a, b = ranges[0]
            ids = [x.text for x in toks[a:b] if x.kind == "id"]
            if len(ids) == 1 and all(x.kind == "id" or x.text in ("&", "*") for x in toks[a:b]):
                self.set_var(ids[0], EMPTY, strong=True)
        # oluşturucu zincirleri
        if chain and chain.get("cmd"):
            if name == "arg" and ranges:
                lit = self._lit(ranges[0])
                if lit in _SHELL_FLAGS:
                    chain["dash"] = True
                elif chain.get("shell") and chain.get("dash"):
                    self.sink("command", "Command::arg() kabuk -c", line, strings_only(taints[0]))
                else:
                    self.col.evaluated(self.file, "command", line)
                return EMPTY
            if name == "args" and ranges:
                a, b = ranges[0]
                lits = {x.text for x in toks[a:b] if x.kind == "str"}
                if lits & _SHELL_FLAGS:
                    chain["dash"] = True
                if chain.get("shell") and chain.get("dash"):
                    self.sink("command", "Command::args() kabuk -c", line, strings_only(taints[0]))
                return EMPTY
            if name in ("output", "spawn", "status", "exec"):
                self.chain = None
                return EMPTY
            return EMPTY
        if chain and chain.get("resp"):
            if name == "content_type" and ranges:
                a, b = ranges[0]
                if any((x.kind == "str" and "html" in x.text.lower()) or (x.kind == "id" and x.text in ("html", "TEXT_HTML", "TEXT_HTML_UTF_8")) for x in toks[a:b]):
                    chain["html"] = True
                return EMPTY
            if name in ("insert_header", "append_header", "header", "set_header", "with_header", "typed_header"):
                a, b = (ranges[0][0], ranges[-1][1]) if ranges else (open_ + 1, close)
                words = [x.text for x in toks[a:b]]
                lows = " ".join(words).lower()
                if "text/html" in lows or "html" in words or "TEXT_HTML" in words or "TEXT_HTML_UTF_8" in words:
                    chain["html"] = True
                if "location" in lows:
                    val = EMPTY
                    for t in taints:
                        val = val | t
                    self.sink("redirect", f"{name}(Location)", line, strings_only(val))
                return EMPTY
            if name in ("body", "streaming", "message_body", "set_body"):
                if ranges:
                    a, b = ranges[0]
                    if chain.get("html") or self._htmlish(a, b):
                        self.sink("html", f"HttpResponse::{name}()", line, strings_only(taints[0]))
                    else:
                        self.col.evaluated(self.file, "html", line)
                self.chain = None
                return EMPTY
            if name in ("json", "finish", "streaming_json"):
                self.chain = None
                return EMPTY
            return EMPTY
        if chain and chain.get("http") and (name in _HTTP_METHODS or (name == "request" and len(taints) > 1)) and taints:
            idx = 1 if name == "request" and len(taints) > 1 else 0
            self.sink("ssrf", f"Client::{name}()", line, strings_only(taints[idx]))
            self.chain = None
            return EMPTY
        if chain and chain.get("http"):
            return EMPTY
        if chain and chain.get("xpath") and name == "build" and taints:
            self.sink("xpath", "sxd_xpath Factory::build()", line, strings_only(taints[0]))
            self.chain = None
            return EMPTY
        if chain and chain.get("stdin") and name in ("read_line", "read_to_string", "lines", "lock"):
            self.chain = chain
            if name in ("read_line", "read_to_string") and ranges:
                self.taint_target(*ranges[0], self.src("local", f"standart girdi ({name})", line))
                return EMPTY
            return self.src("local", "standart girdi", line)
        self.chain = None
        # istemci adlı alıcılar (önceden kurulmuş istemci değişkeni)
        # 18. tur: alıcı bir alan zinciriyse (self.vulnerable_client.get(u)) son alan adı da istemci adı sayılır
        recv_name = toks[dot - 1].text if dot > 0 and toks[dot - 1].kind == "id" else ""
        if (base or recv_name) and info.get("http") and (name in _HTTP_METHODS or (name == "request" and len(taints) > 1)) \
                and taints and (re.search(r"(?i)client|http|agent", base or "") or re.search(r"(?i)client|agent", recv_name)
                                or self.var_info.get(base or "", {}).get("chain", {}).get("http")):
            idx = 1 if name == "request" and len(taints) > 1 else 0
            if not (ranges and toks[ranges[idx][0]].kind == "str" and ranges[idx][1] - ranges[idx][0] == 1):
                self.sink("ssrf", f"{base or recv_name}.{name}()", line, strings_only(taints[idx]))
            return EMPTY
        if info.get("sql") and name in _SQL_METHODS and taints:
            a, b = ranges[0]
            first = toks[a].text if a < b else ""
            if first not in ("[", "&", "(") or (first == "&" and a + 1 < b and toks[a + 1].text not in ("[", "(")):
                if not (b - a >= 2 and toks[a].text == "params" and toks[a + 1].text == "!"):
                    self.sink("sql", f".{name}()", line, strings_only(taints[0]))
        if info.get("xpath") and name == "build" and base and self.var_info.get(base, {}).get("chain", {}).get("xpath") and taints:
            self.sink("xpath", "sxd_xpath Factory::build()", line, strings_only(taints[0]))
        if info.get("ldap") and name in ("search", "streaming_search") and len(taints) >= 3:
            self.sink("ldap", "ldap3 search() filtresi", line, strings_only(taints[2]))
        if name in ("render", "render_to_string", "call") and ranges and toks[ranges[0][0]].kind == "str":
            # adlı şablon (tera/handlebars/tinytemplate/askama): otomatik HTML kaçışlı çıktı
            return EMPTY
        if name in ("render_str", "render_template", "one_off", "add_raw_template", "register_template_string",
                    "template_from_str") and taints:
            idx = 1 if name in ("add_raw_template", "register_template_string") and len(taints) > 1 else 0
            self.sink("ssti", f".{name}()", line, strings_only(taints[idx]))
        if name in ("set_len",) and taints:
            self.sink("memory_len", ".set_len()", line, frozenset(o for o in taints[0] if o.numeric or o.label == "param"))
        if name in ("get_unchecked", "get_unchecked_mut") and taints:
            self.sink("memory_index", f".{name}()", line, frozenset(o for o in taints[0] if o.numeric or o.label == "param"))
        if base and name in ("read_line", "read_to_string", "read", "read_exact", "read_to_end") and ranges and \
                re.search(r"(?i)sock|stream|conn|tcp|client", base):
            self.taint_target(*ranges[0], self.src("request", f"ağdan okunan veri ({base}.{name})", line))
            return EMPTY
        # değer anlamı
        if name in _BOOL_METHODS:
            return EMPTY
        if name in _NUM_METHODS:
            return EMPTY  # uzunluk/sayım saldırganın seçtiği bir sayı değildir
        if name == "parse":
            if turbofish and _type_is_numeric(turbofish):
                return numeric(recv)
            return recv
        if name in _SANITIZER_METHODS:
            return EMPTY
        if name in _STATE_METHODS and base and self.env.get(base) and any(o.source.startswith("HTTP isteği") for o in self.env[base]):
            return EMPTY
        if name in ("push_str", "push", "extend", "extend_from_slice", "insert", "append", "insert_str") and base:
            add = EMPTY
            for t in taints:
                add = add | t
            if add:
                self.set_var(base, add, strong=False)
            return EMPTY
        if name in ("join",) and base is None and recv and False:
            return recv
        cls = ""
        if base:
            st = self.var_info.get(base, {}).get("struct")
            cls = st or ""
        if base == "self":
            cls = self.fn.cls
        pool = [f for f in self.prog.resolve(name, self.file, len(taints) + 1, method=True, cls=cls)
                if f.has_self and len(f.params) == len(taints) + 1]
        cands = [f for f in pool if _crate(f.file) == _crate(self.file)]
        if not cands and len(pool) == 1 and len(name) > 6 and "_" in name:
            # 18. tur: çalışma alanının (workspace) başka crate'indeki yöntem — yalnız proje genelinde TEKİL ve ayırt
            # edici (alt çizgili, uzun) adla (state.command_runner.run_vulnerable(&istek.alan))
            cands = pool
        if cands and (cls or len(cands) == 1 or all(f.file == self.file for f in cands)):
            return self.apply(cands, [recv] + taints, line, name, [(dot, dot)] + ranges) | EMPTY
        out = recv
        for t in taints:
            out = out | t
        return compact(out)

    def _warp_chain(self, dot: int) -> bool:
        toks = self.toks
        lo = max(self.fn.body[0], dot - 400)
        for q in range(dot - 1, lo, -1):
            t = toks[q]
            if t.kind == "op" and t.text in (";", "{", "}"):
                break
            if t.kind == "id" and t.text in ("path", "query", "body", "header", "param", "cookie", "form", "json",
                                             "full", "headers_cloned") and q > 1 and toks[q - 1].text == "::":
                return True
        return False

    def field(self, cur: frozenset, base: str | None, name: str, op: str) -> frozenset:
        if base:
            st = self.var_info.get(base, {}).get("struct")
            if st:
                ftype = self.struct_fields_all().get(st, {}).get(name)
                if ftype and _type_is_numeric(ftype):
                    return EMPTY
        if base == "self" and self.fn.cls:
            return cur | self.global_taint(f"self.{name}")
        return cur

    def path_sink(self, desc: str, line: int, r: tuple[int, int], taint: frozenset) -> None:
        a, b = r
        idents = {x.text for x in self.toks[a:b] if x.kind == "id"}
        if idents & self.path_guards:
            self.col.evaluated(self.file, "path", line)
            return
        self.sink("path", desc, line, strings_only(taint))

    def _lit(self, r: tuple[int, int]) -> str:
        a, b = r
        for q in range(a, b):
            if self.toks[q].kind == "str":
                return self.toks[q].text
        return ""

    def base_ident(self, lo: int, hi: int) -> str:
        toks = self.toks
        for q in range(lo, hi):
            t = toks[q]
            if t.kind == "id" and t.text not in ("mut", "ref") and t.text not in _KEYWORDS:
                if q + 1 < hi and toks[q + 1].text in ("(", "::", "!"):
                    return ""
                return t.text
        return ""


# ---------------------------------------------------------------------------
# Giriş noktaları
# ---------------------------------------------------------------------------


def build_unit(path: str, text: str) -> FileUnit:
    toks = core.tokenize(text, rust=True)
    unit = FileUnit(path, toks)
    if len(toks) > core.MAX_TOKENS_PER_FILE:
        unit.info["limitations"] = {"token"}
    try:
        extract(unit)
    except (RecursionError, IndexError):
        unit.funcs = []
    return unit


def analyze_files(files: dict[str, str]) -> dict[str, Analysis]:
    units = [build_unit(path, text) for path, text in sorted(files.items())]
    collector = Collector({}, {u.path: "rust" for u in units})
    for u in units:
        collector.analysis(u.path)
    prog = core.run_program(units, lambda unit: RustBody, collector)
    limitations = set(prog.limitations)
    for unit in units:
        limitations.update(unit.info.get("limitations") or ())
    if limitations:
        for analysis in collector.analyses.values():
            analysis.mark_incomplete(*sorted(limitations))
    return collector.analyses


def analyze_single(text: str, filename: str) -> Analysis:
    return analyze_files({filename: text}).get(filename, Analysis(language="rust"))
