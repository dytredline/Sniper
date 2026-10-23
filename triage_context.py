"""Ajan triyajı için bulgu bağlamı (26. tur).

Triyaj paketi (``ai_triage``) her bulgu için yalnız bulgu satırının çevresinden kısa bir kod kesiti verir. Kör
değerlendirmede ajanlar kesitte görünmeyen üç şey yüzünden yanıldı: dosya başındaki içe aktarmalar (Go
``text/template`` ↔ ``html/template``), kodda adı geçen şablon dosyası (``{{ q|safe }}``) ve kayıtlı verinin yazıldığı
yer. Bu modül bulguya isteğe bağlı, boyut sınırlı bir ``context`` alanı üretir:

* ``imports``   — dosya başındaki import/use/require/package (şablonda extends/load/autoescape) satırları;
* ``framework`` — proje düzeyinde algılanan çatı ve şablon motorları (son proje analizinin tehdit modeli + manifestler);
* ``templates`` — bulgu satırında ya da kesitinde adı açıkça geçen şablon dosyasından, aktarılan değişken adlarının
  geçtiği satırlar (±2); değişken bulunamazsa kaçışsız çıktı satırları;
* ``related``   — kayıtlı akış kanıtındaki "yazıldığı yer: dosya:satır" (ve kesit dışındaki akış kaynağı) kesiti.

Güvenlik: tüm dosyalar ``ai_triage.project_file_lines`` ile okunur (proje kökü içinde, sembolik bağ hiçbir bileşende
izlenmez, '..'/mutlak yol reddedilir, boyut sınırlı); şablon dizini taraması sembolik bağları izlemez; hassas adlı
dosyalar (.env, anahtar/sertifika) okunmaz; tüm metinler ``ai_triage.redact_text`` ile maskelenir ve isteğe bağlı
olarak tam satır yorumlardan arındırılır. Toplam boyut bulgu başına ``max_bytes`` (varsayılan 4096) ile sınırlıdır.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import ai_triage

DEFAULT_CONTEXT_BYTES = 4096
MAX_CONTEXT_BYTES = 32_768
CONTEXT_ENV = "SNIPER_TRIAGE_CONTEXT_BYTES"
MAX_LINE_CHARS = 240                 # bağlamdaki tek satır (küçültülmüş JS vb.)
IMPORT_SCAN_LINES = 200              # içe aktarmalar yalnız dosya başında aranır
MAX_IMPORT_LINES = 30
IMPORTS_SHARE = 1536                 # bütçede içe aktarmaların payı (bayt)
TEMPLATE_WINDOW = 2                  # şablon satırı ±2
MAX_TEMPLATES = 2
MAX_TEMPLATE_WINDOWS = 8
RELATED_WINDOW = 3
MAX_RELATED = 3
MAX_FRAMEWORKS = 12
CALL_SCAN_CHARS = 800                # şablon çağrısının argümanları için bakılan metin
INDEX_MAX_ENTRIES = 60_000           # şablon dizini taramasında en çok dizin girdisi
MANIFEST_MAX_DEPTH = 3
MANIFEST_MAX_FILES = 40
MANIFEST_MAX_BYTES = 512_000

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "venv", ".venv", "env",
                       "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target", ".next",
                       ".nuxt", "coverage", ".idea", ".vscode", "site-packages", ".gradle", "bin", "obj"})
# Bağlam için hiçbir zaman okunmayan dosya adları (sır taşıyabilir).
_SENSITIVE_NAME = re.compile(r"(?i)(^\.env(\..*)?$|\.(pem|key|p12|pfx|jks|keystore|crt|cer|der|kdbx|asc|gpg)$|"
                             r"^id_(rsa|dsa|ecdsa|ed25519)|^\.?netrc$|^\.?npmrc$|^\.?pypirc$|credentials|secrets?\.)")

# Şablon dosya uzantıları (en uzun önce: ".html.erb" ".html"'den önce denenir).
TEMPLATE_EXTS = tuple(sorted((
    ".html", ".htm", ".xhtml", ".jinja", ".jinja2", ".j2", ".djhtml", ".tpl", ".tpl.php", ".twig", ".html.twig",
    ".ejs", ".pug", ".jade", ".hbs", ".handlebars", ".mustache", ".njk", ".nunjucks", ".erb", ".html.erb", ".haml",
    ".html.haml", ".slim", ".html.slim", ".jsp", ".jspx", ".jspf", ".ftl", ".ftlh", ".vm", ".cshtml", ".razor",
    ".gohtml", ".tmpl", ".blade.php", ".phtml", ".liquid", ".mako", ".eex", ".heex", ".marko", ".dust", ".jst",
), key=len, reverse=True))
# Uzantısız şablon adı (res.render('index'), view('shop.search'), render "users/show") için denenen uzantılar.
DEFAULT_TEMPLATE_EXTS = (".html", ".html.erb", ".erb", ".ejs", ".pug", ".jade", ".hbs", ".handlebars", ".njk",
                         ".mustache", ".twig", ".html.twig", ".blade.php", ".jinja2", ".j2", ".tmpl", ".gohtml",
                         ".cshtml", ".jsp", ".ftl", ".ftlh", ".haml", ".html.haml", ".slim", ".html.slim",
                         ".liquid", ".mako", ".vm", ".htm", ".tpl", ".marko")

_EXT_ALT = "|".join(re.escape(ext[1:]) for ext in TEMPLATE_EXTS)
_TEMPLATE_LITERAL = re.compile(r"""(["'`])([^"'`\s<>|]{1,200}?\.(?:%s))\1""" % _EXT_ALT, re.I)
_RENDER_CALL = re.compile(
    r"""\b(?:render_template|render_to_response|render_to_string|TemplateResponse|get_template|select_template|"""
    r"""render|view|View|PartialView|ExecuteTemplate|HTML|ModelAndView|make_response_template|template)\s*\(\s*"""
    r"""(?:[\w.\[\]]+\s*,\s*)?(["'])([\w./@-]{1,150})\1""")
_RAILS_RENDER = re.compile(r"""\brender\s*\(?\s*(?:(?:template|partial|action)\s*:\s*|:(?:template|partial)\s*=>\s*)?"""
                           r"""(["'])([\w./-]{1,150})\1""")

# --- içe aktarma satırları (dil başına) ---------------------------------------------------------------------------
_LANG_BY_EXT = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js", ".mts": "js", ".cts": "js",
    ".vue": "js", ".svelte": "js",
    ".go": "go", ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java", ".groovy": "java",
    ".cs": "csharp", ".php": "php", ".rb": "ruby", ".rake": "ruby", ".rs": "rust", ".swift": "swift",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".hh": "c", ".m": "c", ".mm": "c",
}
_IMPORT_RES = {
    "python": re.compile(r"^\s*(?:from\s+[\w.]+\s+import\b|import\s+[\w.]+)"),
    "js": re.compile(r"""^\s*(?:import\b|export\s+(?:\*|\{[^}]*\})\s*from\b|(?:const|let|var)\s+[^=]{1,120}=\s*"""
                     r"""(?:await\s+)?(?:require|import)\s*\(|require\s*\()"""),
    "go": re.compile(r"^\s*(?:package\s+\w+|import\b)"),
    "java": re.compile(r"^\s*(?:package\s+[\w.]+|import\s+(?:static\s+)?[\w.*]+)"),
    "csharp": re.compile(r"^\s*(?:global\s+)?(?:using\s+(?:static\s+)?[\w.]+(?:\s*=\s*[\w.<>]+)?\s*;|namespace\s+[\w.]+)"),
    "php": re.compile(r"^\s*(?:<\?php\s+)?(?:namespace\s+[\w\\]+|use\s+[\w\\{}, ]+|(?:require|include)(?:_once)?\b)"),
    "ruby": re.compile(r"^\s*(?:require(?:_relative)?\b|load\s|(?:include|extend|prepend)\s+[A-Z]|"
                       r"class\s+\w+(?:::\w+)*\s*<\s*[\w:]+|module\s+[A-Z])"),
    "rust": re.compile(r"^\s*(?:pub\s+)?(?:use\s|extern\s+crate\s|mod\s+\w+\s*;)"),
    "swift": re.compile(r"^\s*(?:@testable\s+)?import\s"),
    "c": re.compile(r"^\s*#\s*(?:include|import)\b"),
    # Şablon dosyası: kalıtım/yükleme/kaçış yönergeleri (bulgu şablondaysa kesitte görünmeyebilir)
    "template": re.compile(r"""(?:\{%-?\s*(?:extends|load|import|from|include|autoescape|set\s+autoescape)\b|"""
                           r"""<%@\s*(?:page|taglib|include)\b|^\s*@(?:model|using|inject|inherits|layout)\b|"""
                           r"""\{\{-?\s*(?:define|template)\b|<%!|<%inherit|<%namespace|#\s*(?:extends|include)\b)""",
                           re.I),
}

# --- şablon satırı seçimi --------------------------------------------------------------------------------------------
_EXPR_MARK = re.compile(r"""\{\{|\{%|<%|\$\{|#\{|\{!!|@[\w(]|th:|!\{|^\s*(?:!=|=|-)\s|\{\$|\$\w|\[\[""")
_UNESCAPED = re.compile(
    r"""\|\s*safe\b|\|\s*raw\b|\|\s*noescape\b|\bautoescape\b|\{\{\{|<%-|<%==|\braw\s*\(|\.html_safe\b|th:utext|"""
    r"""Html\.Raw|\{!!|!\{|^\s*!=|\bmark_safe\b|\bMarkup\s*\(|\btemplate\.HTML\b|escape(?:Xml)?\s*=\s*["']?false|"""
    r"""\|n\b|\bv-html\b|dangerouslySetInnerHTML|\binnerHTML\b|<%=\s*raw\b|\bsafeHTML\b|\bnoescape\b""", re.I)
_AUTOESCAPE = re.compile(r"""\bautoescape\b|<%@\s*page\b[^%]*isELIgnored|\bescape(?:Xml)?\s*=\s*["']?false""", re.I)
_KWARG = re.compile(r"\b([A-Za-z_]\w*)\s*=(?![=>~])")
_QUOTED_KEY = re.compile(r"""["']([A-Za-z_$][\w$]*)["']\s*(?::|=>)""")
_OBJ_KEY = re.compile(r"""[{,(]\s*([A-Za-z_$][\w$]*)\s*(?::(?!:)|(?=\s*[,}]))""")
_COMPACT = re.compile(r"""\bcompact\s*\(([^)]{1,300})\)""")
_WITH_ATTR = re.compile(r"""(?:->with|\.addAttribute|\.addObject|\.put|\.setAttribute|ViewData|ViewBag)\s*[(\[.]\s*["']?"""
                        r"""([A-Za-z_]\w*)""")
_RUBY_IVAR = re.compile(r"(?<![\w@])@([A-Za-z_]\w*)\s*=(?!=)")
_NOISE_NAMES = frozenset({
    "request", "req", "res", "response", "self", "this", "ctx", "context", "c", "w", "r", "true", "false", "none",
    "null", "nil", "undefined", "http", "status", "statusok", "status_code", "mimetype", "content_type", "headers",
    "template", "template_name", "layout", "locals", "return", "new", "await", "const", "let", "var", "def", "render",
    "view", "html", "json", "text", "data", "model", "map", "string", "interface", "any", "h", "gin", "fiber", "err",
    "using", "partial", "action", "formats", "handlers", "object", "collection", "as", "and", "or", "not", "in", "is",
})

# --- kayıtlı akış: yazıldığı yer --------------------------------------------------------------------------------------
_WRITE_SITE = re.compile(r"yazıldığı yer:\s*([^\s:;()\[\]\"'<>]{1,300}):(\d{1,7})")

# --- çatı / şablon motoru algılama (manifestler) ---------------------------------------------------------------------
_PY_DEPS = (("flask", "Flask"), ("django", "Django"), ("fastapi", "FastAPI"), ("starlette", "Starlette"),
            ("tornado", "Tornado"), ("pyramid", "Pyramid"), ("bottle", "Bottle"), ("sanic", "Sanic"),
            ("quart", "Quart"), ("falcon", "Falcon"), ("aiohttp", "aiohttp"), ("web.py", "web.py"),
            ("jinja2", "Jinja2"), ("mako", "Mako"), ("chameleon", "Chameleon"), ("genshi", "Genshi"))
_JS_DEPS = {"express": "Express", "koa": "Koa", "fastify": "Fastify", "@nestjs/core": "NestJS", "next": "Next.js",
            "@hapi/hapi": "hapi", "hapi": "hapi", "restify": "restify", "sails": "Sails", "loopback": "LoopBack",
            "@loopback/core": "LoopBack", "nuxt": "Nuxt", "@sveltejs/kit": "SvelteKit", "ejs": "EJS", "pug": "Pug",
            "jade": "Jade", "handlebars": "Handlebars", "hbs": "Handlebars (hbs)",
            "express-handlebars": "Handlebars (express-handlebars)", "nunjucks": "Nunjucks", "mustache": "Mustache",
            "dustjs-linkedin": "Dust", "marko": "Marko", "swig": "Swig", "react-dom": "React", "vue": "Vue",
            "@angular/core": "Angular", "svelte": "Svelte", "jquery": "jQuery", "dompurify": "DOMPurify",
            "sanitize-html": "sanitize-html", "xss": "xss (filtre)"}
_TEXT_DEPS = {
    "Gemfile": (("rails", "Rails"), ("sinatra", "Sinatra"), ("hanami", "Hanami"), ("roda", "Roda"),
                ("grape", "Grape"), ("padrino", "Padrino"), ("haml", "Haml"), ("slim", "Slim"),
                ("liquid", "Liquid"), ("erubi", "ERB (erubi)")),
    "java": (("spring-boot", "Spring Boot"), ("spring-webmvc", "Spring MVC"), ("spring-webflux", "Spring WebFlux"),
             ("thymeleaf", "Thymeleaf"), ("freemarker", "FreeMarker"), ("velocity", "Velocity"),
             ("struts", "Struts"), ("jstl", "JSP/JSTL"), ("javax.servlet", "Servlet"), ("jakarta.servlet", "Servlet"),
             ("micronaut", "Micronaut"), ("quarkus", "Quarkus"), ("dropwizard", "Dropwizard"),
             ("jersey", "JAX-RS (Jersey)"), ("ktor", "Ktor"), ("pebble", "Pebble"), ("mustache", "Mustache")),
    "composer.json": (("laravel/framework", "Laravel"), ("symfony/framework-bundle", "Symfony"),
                      ("symfony/symfony", "Symfony"), ("twig/twig", "Twig"), ("smarty", "Smarty"),
                      ("slim/slim", "Slim"), ("codeigniter", "CodeIgniter"), ("cakephp/cakephp", "CakePHP"),
                      ("yiisoft/yii", "Yii"), ("illuminate/view", "Blade"), ("laminas", "Laminas")),
    "go.mod": (("github.com/gin-gonic/gin", "Gin"), ("github.com/labstack/echo", "Echo"),
               ("github.com/gofiber/fiber", "Fiber"), ("github.com/go-chi/chi", "chi"),
               ("github.com/gorilla/mux", "gorilla/mux"), ("github.com/beego", "Beego"),
               ("github.com/revel/revel", "Revel"), ("github.com/gobuffalo/buffalo", "Buffalo"),
               ("github.com/a-h/templ", "templ")),
    "dotnet": (("Microsoft.NET.Sdk.Web", "ASP.NET Core"), ("Microsoft.AspNetCore", "ASP.NET Core"),
               ("Microsoft.AspNet.Mvc", "ASP.NET MVC"), ("System.Web.Mvc", "ASP.NET MVC"),
               ("Microsoft.AspNet.WebPages", "Razor (WebPages)"), ("Nancy", "Nancy")),
    "Cargo.toml": (("actix-web", "Actix Web"), ("axum", "axum"), ("rocket", "Rocket"), ("warp", "warp"),
                   ("tera", "Tera"), ("askama", "Askama"), ("handlebars", "Handlebars"), ("maud", "Maud")),
}
# Çatının varsayılan şablon motoru (manifestte ayrıca görünmeyebilir).
_IMPLIED = {"Flask": "Jinja2", "Rails": "ERB", "Laravel": "Blade", "Django": "Django şablonları",
            "Sinatra": "ERB", "ASP.NET Core": "Razor", "ASP.NET MVC": "Razor"}


def context_limit(value: Any = None) -> int:
    """Bulgu başına bağlam sınırı (bayt): parametre > SNIPER_TRIAGE_CONTEXT_BYTES > 4096; 0 bağlamı kapatır."""
    raw = value if value is not None else os.environ.get(CONTEXT_ENV)
    if raw is None or raw == "":
        return DEFAULT_CONTEXT_BYTES
    try:
        number = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_CONTEXT_BYTES
    return max(0, min(number, MAX_CONTEXT_BYTES))


def _ext_of(rel: str) -> str:
    name = rel.rsplit("/", 1)[-1].lower()
    for ext in TEMPLATE_EXTS:
        if name.endswith(ext):
            return ext
    return os.path.splitext(name)[1]


def is_template(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    return any(name.endswith(ext) for ext in TEMPLATE_EXTS)


def language_of(rel: str) -> str:
    if is_template(rel):
        return "template"
    return _LANG_BY_EXT.get(os.path.splitext(rel.lower())[1], "")


# ---------------------------------------------------------------------------
# Yorum çıkarma (isteğe bağlı): yalnız TAM SATIR yorumlar boş satır olur, satır numaraları korunur
# ---------------------------------------------------------------------------
_HASH_LANGS = {"python", "ruby"}
_SLASH_LANGS = {"js", "go", "java", "csharp", "rust", "swift", "c", "php"}
_TEMPLATE_COMMENT = re.compile(r"""^\s*(?:\{#.*#\}|<!--.*-->|\{\{!--.*--\}\}|\{\{!.*\}\}|<%#.*%>|<%--.*--%>|@\*.*\*@|"""
                               r"""\{\{/\*.*\*/\}\}|\{\*.*\*\}|//-.*|##.*)\s*$""")


def strip_comment_lines(lines: Iterable[str], rel: str) -> list[str]:
    """Dosya diline göre tam satır yorumları (ve çok satırlı /* */ bloklarını) boş satıra çevirir. Satır sonu
    yorumlara dokunulmaz (dizgi içi '#'/'//' ile karışmasın diye)."""
    lang = language_of(rel)
    out: list[str] = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if lang in _SLASH_LANGS:
            if in_block:
                out.append("")
                if "*/" in stripped:
                    in_block = False
                continue
            if stripped.startswith("/*"):
                out.append("")
                in_block = "*/" not in stripped[2:]
                continue
            if stripped.startswith("//") or (lang == "php" and stripped.startswith("#") and not stripped.startswith("#[")):
                out.append("")
                continue
        elif lang in _HASH_LANGS:
            if stripped.startswith("#") and not stripped.startswith("#!") and "coding" not in stripped[:30]:
                out.append("")
                continue
        elif lang == "template":
            if _TEMPLATE_COMMENT.match(line):
                out.append("")
                continue
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------
def _clip(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + "…"


def _size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _windows(lines_wanted: Iterable[int], radius: int, total: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for number in sorted(set(lines_wanted)):
        start, end = max(1, number - radius), min(total, number + radius)
        if spans and start <= spans[-1][1] + 1:
            spans[-1] = (spans[-1][0], max(spans[-1][1], end))
        else:
            spans.append((start, end))
    return spans


def _common_prefix(a: str, b: str) -> int:
    count = 0
    for x, y in zip(a.split("/")[:-1], b.split("/")[:-1]):
        if x != y:
            break
        count += 1
    return count


class ContextBuilder:
    """Bir proje için bağlam üreticisi. Proje düzeyi bilgiler (çatı, şablon dizini, dosya satırları) bir paket
    boyunca önbelleklenir. Hata durumunda ilgili bölüm atlanır; bağlam hiçbir zaman zorunlu değildir."""

    def __init__(self, project_path: str, *, store: Any = None, max_bytes: Any = None,
                 strip_comments: bool = False) -> None:
        self.project_path = str(project_path or "")
        self.store = store
        self.max_bytes = context_limit(max_bytes)
        self.strip_comments = bool(strip_comments)
        self._framework: dict[str, Any] | None | bool = False
        self._template_index: dict[str, list[str]] | None = None
        self._lines: dict[str, list[str] | None] = {}

    def limits(self) -> dict[str, Any]:
        return {"max_bytes": self.max_bytes, "template_window": TEMPLATE_WINDOW, "related_window": RELATED_WINDOW,
                "max_import_lines": MAX_IMPORT_LINES, "strip_comments": self.strip_comments}

    # -- güvenli okuma ------------------------------------------------------
    def _root_ok(self) -> bool:
        root = Path(self.project_path)
        return bool(self.project_path) and root.is_absolute() and root.is_dir()

    def lines_of(self, rel: str) -> list[str] | None:
        """Proje dosyasının satırları (ham). Hassas adlar, sembolik bağ ve kök dışı → None."""
        rel = str(rel or "").strip()
        if rel in self._lines:
            return self._lines[rel]
        lines = None
        if rel and not _SENSITIVE_NAME.search(rel.rsplit("/", 1)[-1]):
            try:
                _, lines = ai_triage.project_file_lines(self.project_path, rel)
            except (ai_triage.TriageError, OSError, ValueError):
                lines = None
        if len(self._lines) > 256:
            self._lines.clear()
        self._lines[rel] = lines
        return lines

    def _render(self, rel: str, lines: list[str], start: int, end: int) -> str:
        """[start, end] satırları: yorum çıkarma (isteğe bağlı) → maskeleme → satır kırpma (maske önce: kırpılan sır
        örüntüsü tanınmaz hâle gelmesin)."""
        selected = lines[start - 1:end]
        if self.strip_comments:
            selected = strip_comment_lines(selected, rel)
        masked = ai_triage.redact_text("\n".join(selected)).split("\n")
        return "\n".join(_clip(line) for line in masked)

    # -- framework ----------------------------------------------------------
    def framework(self) -> dict[str, Any] | None:
        if self._framework is not False:
            return self._framework  # type: ignore[return-value]
        detected: list[str] = []
        sources: list[str] = []

        def add(label: str, source: str) -> None:
            if label and label not in detected:
                detected.append(label)
            if source and source not in sources:
                sources.append(source)

        for label in self._frameworks_from_audit():
            add(label, "proje analizi")
        if self._root_ok():
            for rel, labels in self._frameworks_from_manifests():
                for label in labels:
                    add(label, rel)
        for label in list(detected):
            implied = _IMPLIED.get(label)
            if implied and not any(implied.split(" ")[0].lower() in d.lower() for d in detected):
                add(f"{implied} (varsayılan)", "")
        self._framework = ({"detected": detected[:MAX_FRAMEWORKS], "sources": sources[:6]} if detected else None)
        return self._framework

    def _frameworks_from_audit(self) -> list[str]:
        if self.store is None or not self.project_path:
            return []
        try:
            with self.store._connect() as db:
                row = db.execute("SELECT summary_json FROM project_audits WHERE project_path = ? "
                                 "ORDER BY created_at DESC, rowid DESC LIMIT 1", (self.project_path,)).fetchone()
        except (sqlite3.Error, AttributeError, OSError):
            return []
        if not row:
            return []
        try:
            summary = json.loads(row[0] or "{}")
        except ValueError:
            return []
        model = summary.get("threat_model") if isinstance(summary, dict) else None
        labels: list[str] = []
        for node in (model or {}).get("nodes", []) if isinstance(model, dict) else []:
            if isinstance(node, dict) and node.get("type") == "process":
                for label in node.get("frameworks") or []:
                    if isinstance(label, str) and label not in labels:
                        labels.append(label[:60])
        return labels

    def _frameworks_from_manifests(self) -> list[tuple[str, list[str]]]:
        root = Path(self.project_path)
        found: list[tuple[str, list[str]]] = []
        visited = 0
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack and len(found) < MANIFEST_MAX_FILES and visited < 4000:
            directory, depth = stack.pop()
            try:
                entries = sorted(os.scandir(directory), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                visited += 1
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if depth < MANIFEST_MAX_DEPTH and entry.name not in SKIP_DIRS and not entry.name.startswith("."):
                            stack.append((Path(entry.path), depth + 1))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                kind = self._manifest_kind(entry.name)
                if not kind:
                    continue
                rel = Path(entry.path).relative_to(root).as_posix()
                lines = self.lines_of(rel) if entry.stat(follow_symlinks=False).st_size <= MANIFEST_MAX_BYTES else None
                if lines is None:
                    continue
                labels = self._manifest_labels(kind, "\n".join(lines))
                if labels:
                    found.append((rel, labels))
        return found

    @staticmethod
    def _manifest_kind(name: str) -> str:
        lower = name.lower()
        if lower == "package.json":
            return "package.json"
        if (lower.startswith("requirements") and lower.endswith(".txt")) or lower in {"pyproject.toml", "pipfile",
                                                                                      "setup.py", "setup.cfg"}:
            return "python"
        if lower in {"gemfile", "gems.rb"}:
            return "Gemfile"
        if lower in {"pom.xml", "build.gradle", "build.gradle.kts", "build.sbt"}:
            return "java"
        if lower == "composer.json":
            return "composer.json"
        if lower == "go.mod":
            return "go.mod"
        if lower.endswith((".csproj", ".vbproj", ".fsproj")) or lower == "packages.config":
            return "dotnet"
        if lower == "cargo.toml":
            return "Cargo.toml"
        return ""

    @staticmethod
    def _manifest_labels(kind: str, text: str) -> list[str]:
        labels: list[str] = []
        if kind == "package.json":
            try:
                data = json.loads(text)
            except ValueError:
                return []
            deps: set[str] = set()
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                if isinstance(data.get(key) if isinstance(data, dict) else None, dict):
                    deps.update(data[key])
            return [label for name, label in _JS_DEPS.items() if name in deps]
        if kind == "python":
            lowered = text.lower()
            for name, label in _PY_DEPS:
                if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-])", lowered):
                    labels.append(label)
            return labels
        if kind == "Gemfile":
            for name, label in _TEXT_DEPS["Gemfile"]:
                if re.search(r"""^\s*gem\s+["']%s["']""" % re.escape(name), text, re.M):
                    labels.append(label)
            return labels
        for name, label in _TEXT_DEPS.get(kind, ()):
            if name.lower() in text.lower() and label not in labels:
                labels.append(label)
        return labels

    # -- imports ------------------------------------------------------------
    def imports(self, rel: str, lines: list[str]) -> list[str]:
        """Dosya başındaki içe aktarma satırları ("satır: metin"). Go/Python çok satırlı blokları dahil."""
        lang = language_of(rel)
        pattern = _IMPORT_RES.get(lang)
        if pattern is None:
            return []
        picked: list[int] = []
        depth = 0
        in_go_block = False
        for index, line in enumerate(lines[:IMPORT_SCAN_LINES]):
            number = index + 1
            if in_go_block:
                picked.append(number)
                if line.strip().startswith(")"):
                    in_go_block = False
                continue
            if depth > 0:  # Python "from x import (\n a,\n b)" / JS çok satırlı import { … }
                picked.append(number)
                depth += line.count("(") + line.count("{") - line.count(")") - line.count("}")
                continue
            if pattern.search(line):
                picked.append(number)
                if lang == "go" and re.match(r"^\s*import\s*\(\s*$", line):
                    in_go_block = True
                elif lang in {"python", "js"}:
                    depth = max(0, line.count("(") + line.count("{") - line.count(")") - line.count("}"))
            if len(picked) >= MAX_IMPORT_LINES * 2:
                break
        if not picked:
            return []
        text = self._render(rel, lines, 1, max(picked)).split("\n")
        out = []
        for number in picked:
            value = text[number - 1].rstrip()
            if value.strip():
                out.append(f"{number}: {value}")
        return out

    # -- şablonlar ----------------------------------------------------------
    def _index(self) -> dict[str, list[str]]:
        """Proje içindeki şablon dosyaları: taban ad → göreli yollar. Sembolik bağlar izlenmez/alınmaz."""
        if self._template_index is not None:
            return self._template_index
        index: dict[str, list[str]] = {}
        root = Path(self.project_path)
        visited = 0
        stack = [root]
        while stack and visited < INDEX_MAX_ENTRIES:
            directory = stack.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError:
                continue
            for entry in entries:
                visited += 1
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name not in SKIP_DIRS and not entry.name.startswith("."):
                            stack.append(Path(entry.path))
                        continue
                except OSError:
                    continue
                if is_template(entry.name):
                    rel = Path(entry.path).relative_to(root).as_posix()
                    index.setdefault(entry.name.lower(), []).append(rel)
        self._template_index = index
        return index

    def resolve_template(self, name: str, source_rel: str) -> list[str]:
        """Şablon adını proje kökü içindeki dosyaya çöz (tam yol ya da sonek eşleşmesi). En iyi aday önce."""
        name = name.strip().lstrip("/")
        while name.startswith("./"):
            name = name[2:]
        if not name or len(name) > 300 or "\\" in name or "\x00" in name:
            return []
        if any(part == ".." for part in PurePosixPath(name).parts):
            return []
        variants = [name] if is_template(name) else [name + ext for ext in DEFAULT_TEMPLATE_EXTS]
        if not is_template(name) and "/" not in name and "." in name:  # Laravel view('shop.search')
            dotted = name.replace(".", "/")
            variants += [dotted + ext for ext in DEFAULT_TEMPLATE_EXTS]
        if not is_template(name):  # Rails partial: render partial: "x/row" → _row
            head, _, tail = name.rpartition("/")
            partial = f"{head}/_{tail}" if head else f"_{tail}"
            variants += [partial + ext for ext in DEFAULT_TEMPLATE_EXTS]
        index = self._index()
        candidates: list[str] = []
        for variant in variants:
            base = variant.rsplit("/", 1)[-1].lower()
            for rel in index.get(base, ()):
                if (rel.lower() == variant.lower() or rel.lower().endswith("/" + variant.lower())) and rel not in candidates:
                    candidates.append(rel)
        candidates.sort(key=lambda rel: (0 if rel.lower() in {v.lower() for v in variants} else 1,
                                         -_common_prefix(rel, source_rel),
                                         0 if re.search(r"(^|/)(templates|views|view|layouts|pages)/", rel) else 1,
                                         rel.count("/"), rel))
        return candidates

    @staticmethod
    def template_names(text_lines: list[tuple[int, str]]) -> list[tuple[str, int, int]]:
        """(ad, satır, ad sonrası ofset) — bulgu satırı önce, sonra kesit."""
        found: list[tuple[str, int, int]] = []
        seen: set[str] = set()
        for number, line in text_lines:
            for match in _TEMPLATE_LITERAL.finditer(line):
                if match.group(2) not in seen:
                    seen.add(match.group(2))
                    found.append((match.group(2), number, match.end()))
            for regex in (_RENDER_CALL, _RAILS_RENDER):
                for match in regex.finditer(line):
                    name = match.group(2)
                    if name not in seen and not name.startswith(("http", "/api")) and len(name) >= 2:
                        seen.add(name)
                        found.append((name, number, match.end()))
        return found

    @staticmethod
    def passed_names(call_text: str, window_text: str) -> list[str]:
        """Şablona aktarılan değişken adları: çağrı argümanları (kwargs, sözlük/nesne anahtarları, compact, with) ve
        kesitteki model.addAttribute / @örnek_değişken atamaları."""
        names: list[str] = []

        def add(name: str) -> None:
            name = name.lstrip("$@")
            if name and name.lower() not in _NOISE_NAMES and name not in names and len(names) < 24:
                names.append(name)

        for regex in (_KWARG, _QUOTED_KEY, _OBJ_KEY):
            for match in regex.finditer(call_text):
                add(match.group(1))
        for match in _COMPACT.finditer(call_text):
            for inner in re.findall(r"""["'](\w+)["']""", match.group(1)):
                add(inner)
        for match in _WITH_ATTR.finditer(window_text):
            add(match.group(1))
        for match in _RUBY_IVAR.finditer(window_text):
            add(match.group(1))
        if not names:  # render(request, 'x.html', context): bağlam sözlüğü kesitte kurulmuş olabilir
            for match in _QUOTED_KEY.finditer(window_text):
                add(match.group(1))
        return names

    def _call_text(self, lines: list[str], number: int, offset: int) -> str:
        """Şablon adından sonra, parantezler kapanana kadar (en çok CALL_SCAN_CHARS) çağrı metni."""
        text = lines[number - 1][offset:] if 0 < number <= len(lines) else ""
        follow = number
        while follow < len(lines) and len(text) < CALL_SCAN_CHARS:
            depth = text.count("(") + text.count("{") + text.count("[") - text.count(")") - text.count("}") - text.count("]")
            if depth < 0 or (depth == 0 and text.strip()):
                break
            text += "\n" + lines[follow]
            follow += 1
        return text[:CALL_SCAN_CHARS]

    def template_context(self, rel: str, line: int, lines: list[str], code_range: tuple[int, int]) -> list[dict[str, Any]]:
        start, end = code_range
        ordered = [(line, lines[line - 1])] if 0 < line <= len(lines) else []
        ordered += [(n, lines[n - 1]) for n in range(start, min(end, len(lines)) + 1) if n != line]
        names = self.template_names(ordered)
        if not names:
            return []
        window_text = "\n".join(lines[start - 1:end])
        out: list[dict[str, Any]] = []
        used: set[str] = set()
        for name, number, offset in names:
            if len(out) >= MAX_TEMPLATES:
                break
            candidates = [c for c in self.resolve_template(name, rel) if c != rel and c not in used]
            if not candidates:
                continue
            target = candidates[0]
            template_lines = self.lines_of(target)
            if template_lines is None:
                continue
            used.add(target)
            variables = self.passed_names(self._call_text(lines, number, offset), window_text)
            wanted: list[int] = []
            for variable in variables:
                word = re.compile(r"(?<![\w$])" + re.escape(variable) + r"(?!\w)")
                wanted += [i + 1 for i, text in enumerate(template_lines) if word.search(text) and _EXPR_MARK.search(text)]
            basis = "variables"
            if not wanted:  # değişken yok/bulunamadı (**locals(), res.locals): kaçışsız çıktı satırları
                wanted = [i + 1 for i, text in enumerate(template_lines) if _UNESCAPED.search(text)]
                basis = "unescaped_output"
            directives = [i + 1 for i, text in enumerate(template_lines) if _AUTOESCAPE.search(text)]
            spans = _windows(wanted[:200], TEMPLATE_WINDOW, len(template_lines))
            spans += [(n, n) for n in directives if not any(a <= n <= b for a, b in spans)]
            spans.sort()
            entry: dict[str, Any] = {"file": target, "name": name[:200], "referenced_at": number,
                                     "variables": variables[:12], "basis": basis if wanted else "none",
                                     "total_lines": len(template_lines), "excerpts": []}
            if len(candidates) > 1:
                entry["other_candidates"] = candidates[1:4]
            for a, b in spans[:MAX_TEMPLATE_WINDOWS]:
                entry["excerpts"].append({"start_line": a, "end_line": b,
                                          "text": self._render(target, template_lines, a, b)})
            if len(spans) > MAX_TEMPLATE_WINDOWS:
                entry["truncated"] = True
            out.append(entry)
        return out

    # -- related (kayıtlı akış) ---------------------------------------------
    def related_sites(self, rel: str, finding: dict[str, Any], code_range: tuple[int, int]) -> list[dict[str, Any]]:
        flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else {}
        texts = [str(finding.get("evidence") or ""), str(flow.get("source") or "")]
        texts += [str(v) for v in flow.get("via") or [] if isinstance(v, str)] if isinstance(flow.get("via"), list) else []
        sites: list[tuple[str, str, int]] = []
        for text in texts:
            for match in _WRITE_SITE.finditer(text):
                site = ("yazıldığı yer", match.group(1).strip().lstrip("./"), int(match.group(2)))
                if site not in sites:
                    sites.append(site)
        try:
            source_line = int(flow.get("source_line") or 0)
        except (TypeError, ValueError):
            source_line = 0
        source_file = str(flow.get("source_file") or "") or ("" if is_template(rel) else rel)
        if source_line > 0 and source_file:
            sites.append(("kaynak", source_file, source_line))
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for role, path, number in sites:
            if len(out) >= MAX_RELATED or (path, number) in seen:
                continue
            seen.add((path, number))
            if path == rel and code_range[0] <= number <= code_range[1]:
                continue  # kesitte zaten görünüyor
            lines = self.lines_of(path)
            if not lines or number > len(lines):
                continue
            a, b = max(1, number - RELATED_WINDOW), min(len(lines), number + RELATED_WINDOW)
            out.append({"role": role, "file": path, "line": number, "start_line": a, "end_line": b,
                        "text": self._render(path, lines, a, b)})
        return out

    # -- birleştirme (bütçe) ------------------------------------------------
    def build(self, rel: str, line: int, *, finding: dict[str, Any] | None = None,
              code: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Bulgu bağlamı; bütçe sırası: framework → imports → related(yazıldığı yer) → templates → related(kaynak).
        Sığmayan parça atlanır ve 'truncated' işaretlenir. Bağlam yoksa None."""
        if self.max_bytes <= 0 or not self._root_ok():
            return None
        finding = finding if isinstance(finding, dict) else {}
        rel = str(rel or "").strip()
        lines = self.lines_of(rel) if rel else None
        try:
            line = int(line or 0)
        except (TypeError, ValueError):
            line = 0
        if code and code.get("start_line"):
            code_range = (int(code["start_line"]), int(code.get("end_line") or code["start_line"]))
        elif line:
            code_range = (max(1, line - ai_triage.SNIPPET_CONTEXT), line + ai_triage.SNIPPET_CONTEXT)
        else:
            code_range = (0, -1)
        context: dict[str, Any] = {}
        truncated = False

        def fits(candidate: dict[str, Any]) -> bool:
            return _size(candidate) <= self.max_bytes - 24  # 'truncated' alanına pay

        framework = self.framework()
        if framework and fits({"framework": framework}):
            context["framework"] = framework
        elif framework:
            truncated = True
        if lines is not None:
            imported = self.imports(rel, lines)
            if imported:
                share = min(IMPORTS_SHARE, self.max_bytes)
                kept: list[str] = []
                for item in imported[:MAX_IMPORT_LINES]:
                    trial = {**context, "imports": {"file": rel, "lines": kept + [item]}}
                    if _size(trial["imports"]) > share or not fits(trial):
                        truncated = True
                        break
                    kept.append(item)
                if len(imported) > MAX_IMPORT_LINES:
                    truncated = True
                if kept:
                    context["imports"] = {"file": rel, "lines": kept}
                    if len(kept) < len(imported):
                        context["imports"]["truncated"] = True
        related = self.related_sites(rel, finding, code_range) if finding else []
        related_kept: list[dict[str, Any]] = []
        for item in [r for r in related if r["role"] == "yazıldığı yer"]:
            if fits({**context, "related": related_kept + [item]}):
                related_kept.append(item)
            else:
                truncated = True
        if related_kept:
            context["related"] = related_kept
        if lines is not None and code_range[1] >= code_range[0]:
            templates_kept: list[dict[str, Any]] = []
            for entry in self.template_context(rel, line, lines, code_range):
                excerpts = entry.pop("excerpts")
                entry["excerpts"] = []
                if not fits({**context, "templates": templates_kept + [entry]}):
                    truncated = True
                    continue
                for excerpt in excerpts:
                    trial = {**context, "templates": templates_kept + [{**entry, "excerpts": entry["excerpts"] + [excerpt]}]}
                    if fits(trial):
                        entry["excerpts"].append(excerpt)
                        continue
                    shrunk = self._shrink(excerpt, lambda e: fits({**context, "templates": templates_kept + [
                        {**entry, "excerpts": entry["excerpts"] + [e]}]}))
                    if shrunk:
                        entry["excerpts"].append(shrunk)
                    entry["truncated"] = True
                    truncated = True
                    break
                templates_kept.append(entry)
            if templates_kept:
                context["templates"] = templates_kept
        for item in [r for r in related if r["role"] != "yazıldığı yer"]:
            trial_list = context.get("related", []) + [item]
            if fits({**context, "related": trial_list}):
                context["related"] = trial_list
            else:
                truncated = True
        if not context:
            return None
        if truncated:
            context["truncated"] = True
        return context

    @staticmethod
    def _shrink(excerpt: dict[str, Any], ok) -> dict[str, Any] | None:
        """Sığmayan kesiti sondan satır atarak küçült (en az bir satır)."""
        lines = excerpt["text"].split("\n")
        while len(lines) > 1:
            lines = lines[:-1]
            candidate = {**excerpt, "end_line": excerpt["start_line"] + len(lines) - 1, "text": "\n".join(lines)}
            if ok(candidate):
                return candidate
        return None


def finding_context(project_path: str, rel: str, line: int, *, finding: dict[str, Any] | None = None,
                    code: dict[str, Any] | None = None, store: Any = None, max_bytes: Any = None,
                    strip_comments: bool = False) -> dict[str, Any] | None:
    """Tek bulgu için kısayol (önbelleksiz)."""
    return ContextBuilder(project_path, store=store, max_bytes=max_bytes, strip_comments=strip_comments).build(
        rel, line, finding=finding, code=code)

