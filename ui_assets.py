"""Arayüz ilk yükleme iyileştirmesi (17. tur W3-UI).

Kaynak ``static/index.html`` olduğu gibi kalır (testler ve elle geliştirme için tek tek betik etiketleri). Sunucu ana
sayfayı verirken:

* index.html'deki yerel, ``defer``'li klasik betikleri belge sırasıyla TEK pakette birleştirir
  (``/static/__bundle/ui-<özet>.js``); ``type="module"`` betikler ayrı kalır.
* yerel stil dosyalarını aynı sırayla TEK stil paketinde birleştirir (``/static/__bundle/ui-<özet>.css``).

Paket anlamı korunur: klasik betikler zaten aynı global kapsamı paylaşır ve ``defer`` sırasıyla çalışır. Tek bir IIFE
olan her dosya ``try`` içine alınır; üst düzey hata yalnız o dosyayı durdurur (hata ``setTimeout`` ile yeniden
fırlatılır, konsolda görünür). Üst düzeyde global bildirim yapan dosyalar (``app.js``) olduğu gibi eklenir. Dosyanın
başında ``"use strict"`` varsa katı kip, dosyayı saran işlevde korunur.

``SNIPER_UI_BUNDLE=0`` paketlemeyi kapatır (özgün index.html aynen sunulur).

``BOOTSTRAP_PATHS``: ilk açılışta arayüzün istediği salt okunur GET'ler; ``/api/bootstrap`` bunları tek yanıtta
toplar (her alt yol için oturum/rol denetimi ayrıca yapılır; bkz. ``server.SniperHandler._bootstrap_get``).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path

# İlk açılışta (app.js loadAll, panel betikleri) istenen salt okunur GET'ler. Yavaş olan /api/tooling/readiness
# (araç ikilileri denetimi) bilerek dışarıda: tek başına istenir, yinelenen istekler istemcide birleştirilir.
BOOTSTRAP_PATHS: tuple[str, ...] = (
    "/api/scan-scope",
    "/api/dashboard",
    "/api/targets",
    "/api/scans?limit=200",
    "/api/engagements",
    "/api/lab-runs",
    "/api/project-audits",
    "/api/tooling",
    "/api/dependency-security",
    "/api/jobs",
    "/api/notifications?unread=1&limit=1",
    "/api/taint-rules",
    "/api/eval/latest",
    "/api/eval/history",
    "/api/eval/rule-false-positives",
    "/api/system/version",
)
BOOTSTRAP_MAX_BYTES = 8_000_000  # tek alt yanıt bundan büyükse pakete alınmaz (istemci ağdan ister)

BUNDLE_PREFIX = "/static/__bundle/"
# Üst düzeyde global bildirim yapan (IIFE olmayan) betikler: try ile sarılmaz.
GLOBAL_SCRIPTS = frozenset({"app.js"})

_SCRIPT_TAG = re.compile(r'[ \t]*<script src="(/(?:static/)?[A-Za-z0-9_.-]+\.js)(?:\?v=[0-9A-Za-z._-]+)?" defer></script>[ \t]*\n?')
_STYLE_TAG = re.compile(r'[ \t]*<link rel="stylesheet" href="(/(?:static/)?[A-Za-z0-9_.-]+\.css)(?:\?v=[0-9A-Za-z._-]+)?">[ \t]*\n?')
_LEADING = re.compile(r'\A(?:\s+|//[^\n]*\n|/\*.*?\*/)*', re.S)
_STRICT = re.compile(r'\A(["\'])use strict\1;?')


def enabled() -> bool:
    return os.environ.get("SNIPER_UI_BUNDLE", "1") != "0"


def _static_file(static_dir: Path, src: str) -> Path | None:
    name = src.lstrip("/")
    if name.startswith("static/"):
        name = name[len("static/"):]
    if "/" in name or name.startswith("."):
        return None
    path = static_dir / name
    return path if path.is_file() else None


def _wrap_script(name: str, text: str) -> str:
    """Tek IIFE olan dosyayı try ile sarar; global bildirimli ya da tanınmayan biçimde olduğu gibi bırakır."""
    if not text.endswith("\n"):
        text += "\n"
    if name in GLOBAL_SCRIPTS:
        return text + ";\n"
    rest = text[_LEADING.match(text).end():]
    strict = bool(_STRICT.match(rest))
    if strict:
        rest2 = rest[_STRICT.match(rest).end():]
        rest2 = rest2[_LEADING.match(rest2).end():]
    else:
        rest2 = rest
    if not rest2[:1] in ("(", "!", ";"):
        return text + ";\n"  # IIFE değil: anlam değişmesin diye sarılmaz
    body = '(function () {\n"use strict";\n' + text + '})();\n' if strict else text
    return ("try {\n" + body + "} catch (error) { setTimeout(() => { throw error; }); }\n")


class _Bundle:
    def __init__(self, signature: tuple, html: str, js: bytes | None, css: bytes | None):
        self.signature = signature
        self.html = html
        self.js = js
        self.css = css
        self.js_hash = hashlib.sha256(js).hexdigest()[:16] if js else ""
        self.css_hash = hashlib.sha256(css).hexdigest()[:16] if css else ""


_LOCK = threading.Lock()
_CACHE: dict[str, _Bundle] = {}


def _signature(static_dir: Path, index_text: str, sources: list[Path]) -> tuple:
    stats = []
    for path in sources:
        st = path.stat()
        stats.append((path.name, st.st_mtime_ns, st.st_size))
    return (hashlib.sha256(index_text.encode("utf-8")).hexdigest(), tuple(stats))


def build(static_dir: Path, index_text: str) -> _Bundle:
    """index.html metninden paketleri kurar (kaynak dosyalar değişmedikçe önbellekten)."""
    scripts = [(m, _static_file(static_dir, m.group(1))) for m in _SCRIPT_TAG.finditer(index_text)]
    styles = [(m, _static_file(static_dir, m.group(1))) for m in _STYLE_TAG.finditer(index_text)]
    scripts = [(m, p) for m, p in scripts if p is not None]
    styles = [(m, p) for m, p in styles if p is not None]
    sig = _signature(static_dir, index_text, [p for _, p in scripts] + [p for _, p in styles])
    key = str(static_dir)
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and cached.signature == sig:
            return cached
    js = None
    if len(scripts) > 1:
        parts = ["/* Sniper arayüz paketi (ui_assets.py): index.html sırasıyla birleştirilmiş klasik betikler. */\n"]
        for _, path in scripts:
            parts.append(f"/* --- {path.name} --- */\n")
            parts.append(_wrap_script(path.name, path.read_text(encoding="utf-8")))
        js = "".join(parts).encode("utf-8")
    css = None
    if len(styles) > 1:
        parts = ["/* Sniper stil paketi (ui_assets.py): index.html sırasıyla. */\n"]
        for _, path in styles:
            text = path.read_text(encoding="utf-8")
            parts.append(f"/* --- {path.name} --- */\n{text}\n")
        css = "".join(parts).encode("utf-8")
    bundle = _Bundle(sig, "", js, css)
    html = index_text
    if js:
        first = True
        def _replace_script(match: re.Match) -> str:
            nonlocal first
            if _static_file(static_dir, match.group(1)) is None:
                return match.group(0)
            if first:
                first = False
                return f'  <script src="{BUNDLE_PREFIX}ui-{bundle.js_hash}.js" defer></script>\n'
            return ""
        html = _SCRIPT_TAG.sub(_replace_script, html)
    if css:
        first_css = True
        def _replace_style(match: re.Match) -> str:
            nonlocal first_css
            if _static_file(static_dir, match.group(1)) is None:
                return match.group(0)
            if first_css:
                first_css = False
                return f'  <link rel="stylesheet" href="{BUNDLE_PREFIX}ui-{bundle.css_hash}.css">\n'
            return ""
        html = _STYLE_TAG.sub(_replace_style, html)
    bundle.html = html
    with _LOCK:
        _CACHE[key] = bundle
    return bundle


def rewrite_index(static_dir: Path, index_bytes: bytes) -> bytes:
    if not enabled():
        return index_bytes
    try:
        return build(static_dir, index_bytes.decode("utf-8")).html.encode("utf-8")
    except (OSError, UnicodeDecodeError):
        return index_bytes  # paketleme hatası ana sayfayı bozmasın


def bundle_asset(static_dir: Path, path: str) -> tuple[bytes, str, bool] | None:
    """``/static/__bundle/ui-<özet>.(js|css)`` → (gövde, içerik türü, özet eşleşti mi)."""
    if not path.startswith(BUNDLE_PREFIX):
        return None
    name = path[len(BUNDLE_PREFIX):]
    match = re.fullmatch(r"ui-([0-9a-f]{16})\.(js|css)", name)
    if not match:
        return None
    index = static_dir / "index.html"
    try:
        bundle = build(static_dir, index.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return None
    digest, kind = match.groups()
    if kind == "js" and bundle.js:
        return bundle.js, "application/javascript; charset=utf-8", digest == bundle.js_hash
    if kind == "css" and bundle.css:
        return bundle.css, "text/css; charset=utf-8", digest == bundle.css_hash
    return None


def parse_captured(raw: bytes) -> dict:
    """Yakalanan ham HTTP yanıtı → {"status": n[, "body": json]} (yalnız 200 + JSON gövdesi taşınır)."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return {"status": 500}
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        return {"status": 500}
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        headers[key.strip().lower()] = value.strip()
    ctype = headers.get(b"content-type", b"").decode("latin-1").lower()
    if status != 200 or not ctype.startswith("application/json") or len(body) > BOOTSTRAP_MAX_BYTES:
        return {"status": status}
    try:
        return {"status": 200, "body": json.loads(body.decode("utf-8"))}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": 500}


_STYLE_BLOCK = re.compile(r"<style\b[^>]*>(.*?)</style>", re.S | re.I)
_STYLE_ATTR = re.compile(r"<[a-zA-Z][^<>]*\sstyle\s*=", re.S)


def report_csp(document: str) -> str:
    """HTML raporlar için CSP: belgede satır içi style="" özniteliği yoksa 'unsafe-inline' yerine yalnız bu belgedeki
    <style> bloklarının SHA-256 özetleri (rapor içine sızabilecek başka stil uygulanmaz). Öznitelik varsa (eski/üçüncü
    taraf şablon) geriye uyumlu olarak 'unsafe-inline' kalır."""
    import base64
    if _STYLE_ATTR.search(document):
        return "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    hashes = sorted({"'sha256-" + base64.b64encode(hashlib.sha256(block.encode("utf-8")).digest()).decode("ascii") + "'"
                     for block in _STYLE_BLOCK.findall(document)})
    style = " ".join(hashes) if hashes else "'none'"
    return f"default-src 'none'; style-src {style}; frame-ancestors 'none'"
