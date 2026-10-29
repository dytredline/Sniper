from __future__ import annotations

import json
from pathlib import Path
from pathlib import PurePosixPath
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from project_tree import ProjectFile, ProjectTree
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500
MAX_COLLECTED_PATHS = 15_000
LISTENER_WINDOW_LINES = 25

EXTENSION_MANIFEST_CONTROLS: list[str] = [
    "SNIPER-EXT-01",
    "SNIPER-EXT-02",
    "SNIPER-EXT-03",
    "SNIPER-EXT-04",
    "SNIPER-EXT-05",
]
EXTENSION_SCRIPT_CONTROLS: list[str] = [
    "SNIPER-EXT-02",
    "SNIPER-EXT-03",
    "SNIPER-EXT-06",
]
SERVICE_WORKER_CONTROLS: list[str] = [
    "SNIPER-PWA-01",
    "SNIPER-PWA-02",
]
EXTENSION_PWA_CONTROLS_EVALUATED: list[str] = sorted(
    set(EXTENSION_MANIFEST_CONTROLS) | set(EXTENSION_SCRIPT_CONTROLS) | set(SERVICE_WORKER_CONTROLS)
)

SCRIPT_EXTENSIONS: set[str] = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
SERVICE_WORKER_FILENAMES: set[str] = {
    "sw.js",
    "sw.ts",
    "service-worker.js",
    "service-worker.ts",
    "serviceworker.js",
    "firebase-messaging-sw.js",
}

BROAD_HOST_LITERALS: frozenset[str] = frozenset(
    {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*", "file:///*"}
)
WILDCARD_RESOURCES: frozenset[str] = frozenset({"*", "**/*", "/*", "**", "*.*", "/**/*"})
EXTENSION_MANIFEST_HINT_KEYS: frozenset[str] = frozenset(
    {
        "action",
        "background",
        "browser_action",
        "chrome_settings_overrides",
        "chrome_url_overrides",
        "commands",
        "content_scripts",
        "content_security_policy",
        "declarative_net_request",
        "devtools_page",
        "externally_connectable",
        "host_permissions",
        "incognito",
        "minimum_chrome_version",
        "omnibox",
        "optional_host_permissions",
        "optional_permissions",
        "options_page",
        "options_ui",
        "page_action",
        "permissions",
        "side_panel",
        "update_url",
        "web_accessible_resources",
    }
)

# permission -> (severity, severity_with_broad_hosts, reason)
DANGEROUS_PERMISSIONS: dict[str, tuple[str, str, str]] = {
    "debugger": ("high", "high", "Chrome DevTools protokolüyle herhangi bir sekmeye bağlanıp sayfa içeriğini okuyabilir ve değiştirebilir."),
    "nativeMessaging": ("medium", "medium", "Tarayıcı dışındaki yerel uygulamalarla konuşur; ele geçirilmiş eklenti işletim sistemine köprü olur."),
    "proxy": ("high", "high", "Tüm tarayıcı trafiğini saldırgan kontrollü bir vekil sunucuya yönlendirebilir."),
    "webRequestBlocking": ("medium", "high", "Ağ isteklerini engelleyip değiştirebilir (güvenlik başlıklarını kaldırma dahil)."),
    "declarativeNetRequestWithHostAccess": ("medium", "high", "İzin verilen sitelerde istekleri yönlendirip başlıkları değiştirebilir."),
    "cookies": ("medium", "high", "Oturum çerezlerini (HttpOnly dahil) okuyup yazabilir; oturum ele geçirmeye yol açabilir."),
    "management": ("medium", "medium", "Diğer eklentileri listeleyebilir, devre dışı bırakabilir veya kaldırabilir."),
    "privacy": ("medium", "medium", "Tarayıcı gizlilik ayarlarını (WebRTC, Safe Browsing vb.) değiştirebilir."),
    "downloads.open": ("medium", "medium", "İndirilen dosyaları kullanıcı etkileşimi olmadan açabilir."),
    "clipboardRead": ("medium", "medium", "Pano içeriğini (parolalar, tek kullanımlık kodlar) okuyabilir."),
    "history": ("medium", "medium", "Tüm tarama geçmişine erişir; gizlilik ihlali riski yüksektir."),
    "tabCapture": ("medium", "medium", "Sekme ses/görüntüsünü yakalayabilir."),
    "desktopCapture": ("medium", "medium", "Ekran/pencere görüntüsünü yakalayabilir."),
    "scripting": ("medium", "high", "Sayfalara kod enjekte edebilir; geniş host erişimiyle her siteye betik çalıştırır."),
}

_EXT_CATEGORY = "browser_extension"
_PWA_CATEGORY = "pwa_service_worker"

# --- Script / service worker patterns ---------------------------------------

EXTERNAL_LISTENER_RE = re.compile(
    r"\b(?:chrome|browser)\.runtime\.(onMessageExternal|onConnectExternal)\.addListener\s*\("
)
SENDER_CHECK_RE = re.compile(
    r"""\bsender\s*(?:\?\.|\.)\s*(?:id|origin|url)\b|\bsender\s*\[\s*['"](?:id|origin|url)['"]"""
)
WINDOW_MESSAGE_RE = re.compile(
    r"""\bwindow\.addEventListener\s*\(\s*['"]message['"]|\bwindow\.onmessage\s*="""
)
ORIGIN_CHECK_RE = re.compile(r"\.origin\b")
EVAL_RE = re.compile(r"""(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['"`]""")
TABS_EXECUTE_RE = re.compile(r"\b(?:chrome|browser)\.tabs\.executeScript\s*\(")
SCRIPTING_EXECUTE_RE = re.compile(r"\b(?:chrome|browser)\.scripting\.executeScript\s*\(")
MESSAGE_DATA_RE = re.compile(r"\b(?:message|msg|request|data|response|resp|payload)\b|\b(?:event|e|evt)\.data\b")
HTML_SINK_RE = re.compile(
    r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(?P<rhs>[^;\n]*)"
    r"|\binsertAdjacentHTML\s*\((?P<rhs2>[^;\n]*)"
    r"|\bdocument\.write(?:ln)?\s*\((?P<rhs3>[^;\n]*)"
)
STORAGE_SYNC_SET_RE = re.compile(r"\b(?:chrome|browser)\.storage\.sync\.set\s*\(")
SECRET_TOKEN_RE = re.compile(r"token|password|passwd|secret|api_?key|credential", re.IGNORECASE)
COOKIES_READ_RE = re.compile(r"\b(?:chrome|browser)\.cookies\.(?:getAll|get)\s*\(")
NETWORK_EXFIL_RE = re.compile(
    r"\b(?:fetch\s*\(|new\s+XMLHttpRequest\b|navigator\.sendBeacon\s*\(|new\s+WebSocket\s*\()"
)
DEBUGGER_COMMAND_RE = re.compile(r"\b(?:chrome|browser)\.debugger\.sendCommand\s*\(")
DANGEROUS_CDP_METHOD_RE = re.compile(
    r"""['"`](?:Runtime\.evaluate|Page\.addScriptToEvaluateOnNewDocument|Network\.getAllCookies|Network\.getCookies|Fetch\.enable)['"`]"""
)

IMPORT_SCRIPTS_RE = re.compile(r"\bimportScripts\s*\(")
ABSOLUTE_URL_RE = re.compile(r"""['"`](?:https?:)?//[^'"`\s]+['"`]""", re.IGNORECASE)
SW_REGISTER_HTTP_RE = re.compile(r"""navigator\.serviceWorker\.register\s*\(\s*['"`]http://""", re.IGNORECASE)
CACHE_PUT_RE = re.compile(r"\b(?:\w*[Cc]ache|c)\.put\s*\(")
ADD_ALL_RE = re.compile(r"\.addAll\s*\(")
REGISTER_ROUTE_RE = re.compile(r"\bregisterRoute\s*\(")
CACHE_STRATEGY_RE = re.compile(r"\b(?:CacheFirst|StaleWhileRevalidate|CacheOnly)\b")
SENSITIVE_ROUTE_TEXT_RE = re.compile(r"/api|auth|account|token|session|profile|/me\b|/user", re.IGNORECASE)
AUTH_HEADER_RE = re.compile(
    r"""headers\.get\s*\(\s*['"]authorization['"]|credentials\s*:\s*['"]include['"]""",
    re.IGNORECASE,
)
RESPONSE_CHECK_RE = re.compile(r"\.ok\b|\.status\b|\.type\b|opaque", re.IGNORECASE)
SW_CONTENT_RE = re.compile(r"""\bself\.addEventListener\s*\(\s*['"]fetch['"]|\bself\.onfetch\s*=""")


# --- Helpers -----------------------------------------------------------------


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def _make_finding(
    *,
    domain: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
) -> dict[str, Any]:
    clean_ev = evidence.strip()[:320]
    if domain == "pwa":
        category = _PWA_CATEGORY
        reference = f"OWASP PWA / Service Worker Security · {cwe}"
    else:
        category = _EXT_CATEGORY
        reference = f"Chrome Extensions Security Best Practices · OWASP Browser Extension Vulnerabilities · {cwe}"
    item = _finding(
        severity,
        category,
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, cwe, title),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    return item


class _FindingSink:
    def __init__(self) -> None:
        self.findings: list[dict[str, Any]] = []
        self._seen: set[tuple[str, str, int, str]] = set()

    def add(self, finding: dict[str, Any]) -> None:
        key = (finding["control_id"], finding["cwe"], int(finding["line"]), finding.get("title", ""))
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(finding)


def _validate_inline(raw_content: Any, empty_message: str) -> str:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError(empty_message)
    if len(raw_content.encode("utf-8", errors="replace")) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    return raw_content


def _clean_filename(filename: Any, default: str) -> str:
    if not isinstance(filename, str) or not filename.strip():
        return default
    return filename.strip()


def _line_of(raw: str, needle: str | None = None, *, after_key: str | None = None) -> int:
    """Best-effort 1-based line of `needle` (optionally searched after a JSON key)."""
    start = 0
    key_pos = -1
    if after_key:
        key_match = re.search(r'"' + re.escape(after_key) + r'"\s*:', raw)
        if key_match:
            key_pos = key_match.start()
            start = key_pos
    pos = raw.find(needle, start) if needle else -1
    if pos < 0:
        pos = key_pos
    if pos < 0:
        return 1
    return raw.count("\n", 0, pos) + 1


def _json_needle(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _is_broad_host(pattern: Any) -> bool:
    if not isinstance(pattern, str):
        return False
    value = pattern.strip()
    if value in BROAD_HOST_LITERALS:
        return True
    if "://" not in value:
        return False
    rest = value.split("://", 1)[1]
    host = rest.split("/", 1)[0]
    if host == "*":
        return True
    # Wildcard over a whole TLD, e.g. *://*.com/*
    if host.startswith("*.") and "." not in host[2:]:
        return True
    return False


def _remote_script_sources(csp_text: str) -> list[str]:
    directives: dict[str, list[str]] = {}
    for part in csp_text.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        directives.setdefault(tokens[0].lower(), tokens[1:])
    sources = directives.get("script-src") or directives.get("default-src") or []
    remote: list[str] = []
    for token in sources:
        lowered = token.lower()
        if token.startswith("'"):
            continue
        if lowered.startswith(("blob:", "filesystem:", "chrome-extension:", "moz-extension:")):
            continue
        if (
            token == "*"
            or lowered.startswith(("http:", "https:", "ws:", "wss:", "//", "data:"))
            or "." in token
        ):
            remote.append(token)
    return remote


def _call_arguments(lines: list[str], idx: int, open_col: int, max_lines: int = 4) -> str:
    depth = 0
    out: list[str] = []
    for k in range(idx, min(len(lines), idx + max_lines)):
        segment = lines[k][open_col:] if k == idx else lines[k]
        for ch in segment:
            out.append(ch)
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return "".join(out)
        out.append("\n")
    return "".join(out)


def _is_comment(stripped: str) -> bool:
    return stripped.startswith(("//", "/*", "*"))


def _contains_sensitive_path(value: str) -> bool:
    folded = value.casefold()
    if any(term in folded for term in ("auth", "account", "token", "session", "profile", "/user")):
        return True
    for term in ("/api", "/me"):
        start = 0
        while (found := folded.find(term, start)) >= 0:
            end = found + len(term)
            if end == len(folded) or not (folded[end].isalnum() or folded[end] == "_"):
                return True
            start = found + 1
    return False


def _find_sensitive_path_literal(text: str) -> str | None:
    """İlk tamamlanmış hassas tırnaklı yolu tek geçişte döndür."""
    index = 0
    while index < len(text):
        quote = text[index]
        if quote not in "'\"`":
            index += 1
            continue
        end = index + 1
        while end < len(text) and text[end] not in "'\"`\n":
            end += 1
        if end >= len(text):
            return None
        if text[end] in "'\"`":
            literal = text[index:end + 1]
            if _contains_sensitive_path(literal[1:-1]):
                return literal
        index = end + 1
    return None


def _has_postmessage_star(line: str) -> bool:
    """postMessage çağrısında `'*'` hedef kökenini geri izleme olmadan bul."""
    cursor = 0
    marker = ".postMessage"
    while (start := line.find(marker, cursor)) >= 0:
        pos = start + len(marker)
        while pos < len(line) and line[pos].isspace():
            pos += 1
        if pos >= len(line) or line[pos] != "(":
            cursor = start + len(marker)
            continue
        end = line.find(")", pos + 1)
        if end < 0:
            end = len(line)
        comma = pos + 1
        while (comma := line.find(",", comma, end)) >= 0:
            value = comma + 1
            while value < end and line[value].isspace():
                value += 1
            if value + 2 < end and line[value] in "'\"" and line[value + 1] == "*" \
                    and line[value + 2] == line[value]:
                return True
            comma += 1
        if end == len(line):
            return False
        cursor = end + 1
    return False


def _is_service_worker_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in SERVICE_WORKER_FILENAMES or lowered.endswith(("-sw.js", "-sw.ts", ".sw.js"))


# --- Public API: extension manifest -----------------------------------------


def _parse_manifest_json_object(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        # Chrome tolerates whole-line // comments in manifest.json; retry once without them.
        stripped_comments = re.sub(r"(?m)^\s*//[^\n]*$", "", raw)
        try:
            data = json.loads(stripped_comments)
        except json.JSONDecodeError:
            raise ValueError(
                f"Manifest geçerli bir JSON değil (satır {exc.lineno}, sütun {exc.colno})."
            ) from exc
    if not isinstance(data, dict):
        raise ValueError("Manifest kökü bir JSON nesnesi olmalıdır.")
    return data


def audit_extension_manifest_inline(
    raw_content: str,
    *,
    filename: str = "manifest.json",
) -> dict[str, Any]:
    raw = _validate_inline(raw_content, "Denetlenecek eklenti manifest içeriği boş olamaz.")
    clean_filename = _clean_filename(filename, "manifest.json")
    data = _parse_manifest_json_object(raw)

    sink = _FindingSink()

    def _emit(severity: str, title: str, description: str, evidence: str, recommendation: str,
              cwe: str, control_id: str, line: int) -> None:
        sink.add(
            _make_finding(
                domain="extension",
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                cwe=cwe,
                control_id=control_id,
                filename=clean_filename,
                line=line,
            )
        )

    manifest_version = data.get("manifest_version")
    if type(manifest_version) is not int or manifest_version not in {2, 3}:
        raise ValueError("manifest_version yalnızca 2 veya 3 tamsayısı olmalıdır.")
    name_raw = data.get("name")
    extension_name = name_raw.strip()[:120] if isinstance(name_raw, str) else ""

    raw_permissions = _str_list(data.get("permissions"))
    host_like_permissions = [p for p in raw_permissions if "://" in p or p.strip() == "<all_urls>"]
    api_permissions = [p for p in raw_permissions if p not in host_like_permissions]
    mv3_hosts = _str_list(data.get("host_permissions"))
    host_permissions = sorted(set(mv3_hosts) | set(host_like_permissions))

    content_scripts = [item for item in data.get("content_scripts") or [] if isinstance(item, dict)] \
        if isinstance(data.get("content_scripts"), list) else []
    content_script_matches: list[str] = []
    for script in content_scripts:
        content_script_matches.extend(_str_list(script.get("matches")))

    broad_mv3 = [h for h in mv3_hosts if _is_broad_host(h)]
    broad_perm_hosts = [h for h in host_like_permissions if _is_broad_host(h)]
    broad_content = [m for m in content_script_matches if _is_broad_host(m)]
    has_broad_hosts = bool(broad_mv3 or broad_perm_hosts or broad_content)

    # SNIPER-EXT-05: deprecated Manifest V2.
    if manifest_version == 2:
        _emit(
            "medium",
            "Kullanımdan kalkmış Manifest V2",
            "Eklenti Manifest V2 kullanıyor. MV2 Chrome'da kullanımdan kaldırıldı; uzaktan kod, kalıcı arka plan "
            "sayfası ve engelleyici webRequest gibi daha geniş saldırı yüzeylerine izin verir.",
            '"manifest_version": 2',
            "Eklentiyi Manifest V3'e taşıyın (service_worker arka planı, host_permissions ayrımı, katı CSP).",
            "CWE-1104",
            "SNIPER-EXT-05",
            _line_of(raw, None, after_key="manifest_version"),
        )

    # SNIPER-EXT-01: broad host access.
    if broad_mv3 or broad_perm_hosts:
        pattern = (broad_mv3 or broad_perm_hosts)[0]
        key = "host_permissions" if broad_mv3 else "permissions"
        _emit(
            "high",
            "Tüm sitelere geniş host erişimi",
            f"Eklenti '{pattern}' host izniyle tüm web sitelerinin içeriğine ve isteklerine erişebiliyor. "
            "Eklenti ele geçirilirse veya kötü niyetli güncelleme yayınlanırsa tüm oturumlar risk altındadır.",
            f'"{key}": {", ".join(broad_mv3 or broad_perm_hosts)}',
            "Host izinlerini yalnızca gerekli alan adlarıyla sınırlayın; mümkünse activeTab veya "
            "optional_host_permissions ile çalışma zamanında izin isteyin.",
            "CWE-250",
            "SNIPER-EXT-01",
            _line_of(raw, _json_needle(pattern), after_key=key),
        )
    if broad_content:
        pattern = broad_content[0]
        _emit(
            "high",
            "İçerik betiği tüm sitelere enjekte ediliyor",
            f"content_scripts.matches '{pattern}' deseniyle her sayfaya betik enjekte ediyor; içerik betiği "
            "açıkları tüm sitelerde istismar edilebilir hale gelir.",
            f'"content_scripts.matches": {", ".join(broad_content)}',
            "İçerik betiği eşleşmelerini yalnızca gereken alan adlarına daraltın veya scripting API ile "
            "kullanıcı eylemi sonrası enjekte edin.",
            "CWE-250",
            "SNIPER-EXT-01",
            _line_of(raw, _json_needle(pattern), after_key="content_scripts"),
        )

    # SNIPER-EXT-01: dangerous API permissions (one finding per permission).
    risk_permissions: list[str] = []
    for permission in sorted(set(api_permissions)):
        spec = DANGEROUS_PERMISSIONS.get(permission)
        if spec is None:
            continue
        risk_permissions.append(permission)
        severity = spec[1] if has_broad_hosts else spec[0]
        description = spec[2]
        if has_broad_hosts and spec[1] != spec[0]:
            description += " Geniş host erişimiyle birleştiği için risk yükseltildi."
        _emit(
            severity,
            f"Riskli eklenti izni: {permission}",
            description,
            f'"permissions": "{permission}"',
            "İzni gerçekten gerekmiyorsa kaldırın; gerekiyorsa optional_permissions ile çalışma zamanında, "
            "kullanıcı onayıyla isteyin ve kullanımını en aza indirin.",
            "CWE-250",
            "SNIPER-EXT-01",
            _line_of(raw, _json_needle(permission), after_key="permissions"),
        )

    # SNIPER-EXT-02: content security policy.
    csp_raw = data.get("content_security_policy")
    csp_text = ""
    csp_key = "content_security_policy"
    if isinstance(csp_raw, str):
        csp_text = csp_raw
    elif isinstance(csp_raw, dict):
        pages = csp_raw.get("extension_pages")
        if isinstance(pages, str):
            csp_text = pages
            csp_key = "extension_pages"
    if csp_text:
        csp_line = _line_of(raw, None, after_key=csp_key)
        lowered = csp_text.lower()
        if "'unsafe-eval'" in lowered:
            _emit(
                "high",
                "Eklenti CSP'si 'unsafe-eval' içeriyor",
                "eval(), new Function() ve string tabanlı setTimeout çağrılarına izin verilerek eklenti "
                "bağlamında dinamik kod yürütme mümkün hale geliyor.",
                csp_text,
                "CSP'den 'unsafe-eval' ifadesini kaldırın ve dinamik kod üretimini statik koda dönüştürün.",
                "CWE-95",
                "SNIPER-EXT-02",
                csp_line,
            )
        elif "'wasm-unsafe-eval'" in lowered:
            _emit(
                "low",
                "Eklenti CSP'si 'wasm-unsafe-eval' içeriyor",
                "WebAssembly derlemesine izin veriliyor; yalnızca paketlenmiş ve doğrulanmış wasm modülleri "
                "kullanıldığından emin olun.",
                csp_text,
                "WebAssembly gerekmiyorsa 'wasm-unsafe-eval' ifadesini kaldırın.",
                "CWE-95",
                "SNIPER-EXT-02",
                csp_line,
            )
        if "'unsafe-inline'" in lowered:
            _emit(
                "medium",
                "Eklenti CSP'si 'unsafe-inline' içeriyor",
                "Satır içi betiklere izin verildiğinden eklenti sayfalarında XSS istismarı kolaylaşır.",
                csp_text,
                "'unsafe-inline' ifadesini kaldırın; betikleri ayrı dosyalara taşıyın.",
                "CWE-79",
                "SNIPER-EXT-02",
                csp_line,
            )
        remote = _remote_script_sources(csp_text)
        if remote:
            _emit(
                "high",
                "Eklenti CSP'si uzak betik kaynaklarına izin veriyor",
                f"script-src uzak kaynaklar içeriyor ({', '.join(remote[:5])}). Uzak sunucu veya CDN ele "
                "geçirilirse eklenti ayrıcalıklarıyla keyfi kod çalışır (MV3 bunu yasaklar).",
                csp_text,
                "Tüm betikleri eklenti paketine dahil edin; script-src 'self' dışında kaynak bırakmayın.",
                "CWE-829",
                "SNIPER-EXT-02",
                csp_line,
            )

    # SNIPER-EXT-03: externally_connectable.
    externally = data.get("externally_connectable")
    if isinstance(externally, dict):
        ec_matches = _str_list(externally.get("matches"))
        ec_ids = _str_list(externally.get("ids"))
        wildcard_matches = [m for m in ec_matches if _is_broad_host(m)]
        if wildcard_matches or "*" in ec_ids:
            parts = []
            if wildcard_matches:
                parts.append(f"matches: {', '.join(wildcard_matches)}")
            if "*" in ec_ids:
                parts.append("ids: *")
            _emit(
                "high",
                "externally_connectable joker karakterle herkese açık",
                "Herhangi bir web sitesi veya eklenti, eklentinin arka planına mesaj gönderebilir "
                f"({'; '.join(parts)}). Gönderen doğrulaması yoksa ayrıcalıklı işlemler tetiklenebilir.",
                "; ".join(parts),
                "externally_connectable.matches ve ids listelerini yalnızca güvenilen kökenler ve eklenti "
                "kimlikleriyle sınırlayın.",
                "CWE-346",
                "SNIPER-EXT-03",
                _line_of(raw, None, after_key="externally_connectable"),
            )

    # SNIPER-EXT-04: web_accessible_resources exposure.
    war = data.get("web_accessible_resources")
    war_reasons: list[str] = []
    if isinstance(war, list):
        for item in war:
            if isinstance(item, str):
                if item.strip() in WILDCARD_RESOURCES:
                    war_reasons.append(f"tüm kaynaklar ('{item.strip()}') açık")
            elif isinstance(item, dict):
                resources = _str_list(item.get("resources"))
                matches = _str_list(item.get("matches"))
                wildcard_res = [r for r in resources if r.strip() in WILDCARD_RESOURCES]
                if wildcard_res:
                    war_reasons.append(f"joker kaynak ('{wildcard_res[0].strip()}')")
                if resources and any(_is_broad_host(m) for m in matches):
                    war_reasons.append("kaynaklar tüm sitelere ('<all_urls>') açık")
    if war_reasons:
        _emit(
            "medium",
            "web_accessible_resources her siteye açık",
            "Eklenti kaynakları web sayfalarından erişilebilir: "
            f"{'; '.join(dict.fromkeys(war_reasons))}. Bu, eklenti parmak izi çıkarmaya ve eklenti "
            "sayfalarının tıklama korsanlığı (clickjacking) amacıyla çerçevelenmesine yol açar.",
            "; ".join(dict.fromkeys(war_reasons)),
            "Yalnızca gereken dosyaları listeleyin, matches alanını belirli kökenlerle sınırlayın ve "
            "use_dynamic_url: true kullanın.",
            "CWE-200",
            "SNIPER-EXT-04",
            _line_of(raw, None, after_key="web_accessible_resources"),
        )

    # Low-severity hygiene: all_frames with broad matches, persistent background page.
    for script in content_scripts:
        if script.get("all_frames") is True and any(_is_broad_host(m) for m in _str_list(script.get("matches"))):
            _emit(
                "low",
                "İçerik betiği tüm çerçevelerde ve tüm sitelerde çalışıyor",
                "all_frames: true ile geniş eşleşme birleşince içerik betiği üçüncü taraf iframe'lerde de çalışır; "
                "saldırgan sayfalar betikle etkileşime girebilir.",
                '"all_frames": true',
                "all_frames seçeneğini kapatın veya eşleşmeleri belirli alan adlarıyla sınırlayın.",
                "CWE-1021",
                "SNIPER-EXT-01",
                _line_of(raw, '"all_frames"', after_key="content_scripts"),
            )
            break
    background = data.get("background")
    if manifest_version == 2 and isinstance(background, dict) and background.get("persistent") is True:
        _emit(
            "low",
            "Kalıcı arka plan sayfası (persistent: true)",
            "Kalıcı arka plan sayfası sürekli bellekte kalır, saldırı penceresini ve kaynak tüketimini artırır.",
            '"persistent": true',
            "Olay tabanlı arka plan (persistent: false) veya MV3 service_worker kullanın.",
            "CWE-400",
            "SNIPER-EXT-05",
            _line_of(raw, '"persistent"', after_key="background"),
        )

    update_url = data.get("update_url")
    if isinstance(update_url, str) and update_url.strip().lower().startswith("http://"):
        _emit(
            "high",
            "Eklenti güncellemeleri şifresiz HTTP üzerinden alınıyor",
            "update_url HTTP kullanıyor; ağdaki bir saldırgan güncelleme bildirimini değiştirerek kötü amaçlı "
            "bir sürüm dağıtabilir.",
            update_url.strip()[:200],
            "update_url için yalnızca HTTPS kullanın ve paket imzasını doğrulayın.",
            "CWE-494",
            "SNIPER-EXT-05",
            _line_of(raw, None, after_key="update_url"),
        )

    findings = sink.findings
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    return {
        "format": "sniper-browser-extension-manifest-audit-v1",
        "filename": clean_filename,
        "manifest_version": manifest_version if isinstance(manifest_version, int) else None,
        "extension_name": extension_name,
        "permissions": sorted(set(raw_permissions)),
        "host_permissions": host_permissions,
        "risk_permissions": sorted(risk_permissions),
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(EXTENSION_MANIFEST_CONTROLS),
    }


# --- Public API: extension scripts ------------------------------------------


def audit_extension_script_inline(
    raw_content: str,
    *,
    filename: str = "background.js",
) -> dict[str, Any]:
    raw = _validate_inline(raw_content, "Denetlenecek eklenti betiği içeriği boş olamaz.")
    clean_filename = _clean_filename(filename, "background.js")
    lines = raw.splitlines()
    sink = _FindingSink()

    def _emit(severity: str, title: str, description: str, evidence: str, recommendation: str,
              cwe: str, control_id: str, line: int) -> None:
        sink.add(
            _make_finding(
                domain="extension",
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                cwe=cwe,
                control_id=control_id,
                filename=clean_filename,
                line=line,
            )
        )

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue
        window = "\n".join(lines[idx:idx + LISTENER_WINDOW_LINES])

        external = EXTERNAL_LISTENER_RE.search(line)
        if external and not SENDER_CHECK_RE.search(window):
            _emit(
                "high",
                f"Harici mesaj dinleyicisi gönderen doğrulaması yapmıyor ({external.group(1)})",
                "runtime.onMessageExternal/onConnectExternal işleyicisinde sender.id, sender.origin veya "
                "sender.url kontrolü bulunamadı. externally_connectable kapsamındaki herhangi bir site veya "
                "eklenti ayrıcalıklı işlemleri tetikleyebilir.",
                stripped,
                "İşleyicinin başında sender.id / sender.origin değerini izin listesine göre doğrulayın ve "
                "mesaj şemasını katı biçimde kontrol edin.",
                "CWE-346",
                "SNIPER-EXT-03",
                idx + 1,
            )

        if WINDOW_MESSAGE_RE.search(line) and not ORIGIN_CHECK_RE.search(window):
            _emit(
                "medium",
                "window 'message' dinleyicisi köken (origin) doğrulaması yapmıyor",
                "İçerik betiği sayfadan gelen postMessage olaylarını event.origin kontrolü olmadan işliyor; "
                "kötü niyetli sayfa betikleri eklentiye sahte komut gönderebilir.",
                stripped,
                "event.origin değerini beklenen kökenle karşılaştırın ve event.source === window kontrolüne "
                "ek olarak mesaj türünü doğrulayın.",
                "CWE-345",
                "SNIPER-EXT-03",
                idx + 1,
            )

        if EVAL_RE.search(line):
            _emit(
                "high",
                "Eklentide dinamik kod yürütme (eval / new Function)",
                "eval(), new Function() veya string argümanlı setTimeout/setInterval eklenti ayrıcalıklarıyla "
                "keyfi kod çalıştırabilir; MV3 CSP'si bunu engeller ancak MV2'de kritik risktir.",
                stripped,
                "Dinamik kod yerine JSON.parse ve önceden tanımlı fonksiyon eşlemeleri kullanın.",
                "CWE-95",
                "SNIPER-EXT-02",
                idx + 1,
            )

        tabs_exec = TABS_EXECUTE_RE.search(line)
        if tabs_exec:
            arguments = _call_arguments(lines, idx, tabs_exec.end() - 1, max_lines=6)
            if re.search(r"\bcode\s*:", arguments):
                _emit(
                    "medium",
                    "tabs.executeScript ile metin tabanlı kod enjeksiyonu",
                    "chrome.tabs.executeScript({code: ...}) çalışma zamanında oluşturulan kodu sayfaya enjekte "
                    "ediyor; kod mesaj veya sayfa verisinden üretiliyorsa kod enjeksiyonu oluşur.",
                    stripped,
                    "Paketlenmiş dosyaları (files: [...]) veya chrome.scripting.executeScript({func}) kullanın; "
                    "dış veriyi yalnızca args ile ve doğrulayarak geçirin.",
                    "CWE-94",
                    "SNIPER-EXT-02",
                    idx + 1,
                )

        scripting_exec = SCRIPTING_EXECUTE_RE.search(line)
        if scripting_exec:
            arguments = _call_arguments(lines, idx, scripting_exec.end() - 1, max_lines=6)
            if re.search(r"\b(?:func|function|args)\s*:", arguments) and MESSAGE_DATA_RE.search(arguments):
                _emit(
                    "medium",
                    "scripting.executeScript mesaj verisiyle besleniyor",
                    "chrome.scripting.executeScript çağrısının func/args değerleri mesaj veya yanıt verisinden "
                    "türetiliyor; doğrulanmamış veri sayfa bağlamında çalıştırılabilir.",
                    stripped,
                    "Enjekte edilen fonksiyonu sabit tutun, mesaj verisini şema doğrulamasından geçirin ve "
                    "hedef sekmeyi izin listesine göre kontrol edin.",
                    "CWE-94",
                    "SNIPER-EXT-02",
                    idx + 1,
                )

        html_sink = HTML_SINK_RE.search(line)
        if html_sink:
            rhs = html_sink.group("rhs") or html_sink.group("rhs2") or html_sink.group("rhs3") or ""
            if MESSAGE_DATA_RE.search(rhs):
                _emit(
                    "medium",
                    "Mesaj/yanıt verisi innerHTML ile DOM'a yazılıyor",
                    "Mesaj veya ağ yanıtından gelen veri innerHTML/insertAdjacentHTML/document.write ile "
                    "işleniyor; eklenti sayfasında veya içerik betiğinde XSS oluşabilir.",
                    stripped,
                    "textContent kullanın veya DOMPurify gibi bir temizleyiciyle HTML'i arındırın.",
                    "CWE-79",
                    "SNIPER-EXT-02",
                    idx + 1,
                )

        storage_set = STORAGE_SYNC_SET_RE.search(line)
        if storage_set:
            arguments = _call_arguments(lines, idx, storage_set.end() - 1, max_lines=4)
            if SECRET_TOKEN_RE.search(arguments):
                _emit(
                    "medium",
                    "Gizli bilgi chrome.storage.sync içinde saklanıyor",
                    "Token/parola/gizli anahtar chrome.storage.sync'e yazılıyor. Bu alan şifrelenmemiştir ve "
                    "kullanıcının tüm cihazlarına senkronize edilir.",
                    stripped,
                    "Uzun ömürlü gizli bilgileri saklamayın; gerekirse chrome.storage.session veya kısa ömürlü, "
                    "sunucu tarafında iptal edilebilir token kullanın.",
                    "CWE-312",
                    "SNIPER-EXT-06",
                    idx + 1,
                )

        if COOKIES_READ_RE.search(line) and NETWORK_EXFIL_RE.search(window):
            _emit(
                "critical",
                "Oturum çerezleri (chrome.cookies) harici ağ isteğine aktarılıyor",
                "chrome.cookies.getAll/get ile okunan oturum çerezleri yakın satırlarda fetch/XMLHttpRequest/"
                "sendBeacon/WebSocket çağrısıyla ağa gönderiliyor; HttpOnly oturum çerezlerinin sızdırılması "
                "tam hesap ele geçirmeye yol açar.",
                stripped,
                "Eklenti içinde çerez değerlerini harici sunuculara iletmeyin; oturum doğrulamasını tarayıcının "
                "kendi çerez mekanizmasına bırakın ve cookies iznini kaldırın.",
                "CWE-359",
                "SNIPER-EXT-06",
                idx + 1,
            )

        debugger_cmd = DEBUGGER_COMMAND_RE.search(line)
        if debugger_cmd:
            arguments = _call_arguments(lines, idx, debugger_cmd.end() - 1, max_lines=6)
            if DANGEROUS_CDP_METHOD_RE.search(arguments):
                _emit(
                    "high",
                    "chrome.debugger.sendCommand ile tehlikeli DevTools komutu yürütülüyor",
                    "chrome.debugger.sendCommand üzerinden Runtime.evaluate, Network.getAllCookies veya "
                    "Page.addScriptToEvaluateOnNewDocument çağrılıyor; bu yöntemler CSP ve HttpOnly sınırlarını "
                    "tamamen atlatır.",
                    stripped,
                    "debugger API'sini üretim eklentilerinde kullanmayın; standart scripting veya declarativeNetRequest "
                    "API'lerini tercih edin.",
                    "CWE-94",
                    "SNIPER-EXT-02",
                    idx + 1,
                )

    findings = sink.findings
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    return {
        "format": "sniper-browser-extension-script-audit-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(EXTENSION_SCRIPT_CONTROLS),
    }


# --- Public API: service worker ---------------------------------------------


def audit_service_worker_inline(
    raw_content: str,
    *,
    filename: str = "sw.js",
) -> dict[str, Any]:
    raw = _validate_inline(raw_content, "Denetlenecek service worker içeriği boş olamaz.")
    clean_filename = _clean_filename(filename, "sw.js")
    lines = raw.splitlines()
    sink = _FindingSink()

    def _emit(severity: str, title: str, description: str, evidence: str, recommendation: str,
              cwe: str, control_id: str, line: int) -> None:
        sink.add(
            _make_finding(
                domain="pwa",
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                cwe=cwe,
                control_id=control_id,
                filename=clean_filename,
                line=line,
            )
        )

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue

        imports = IMPORT_SCRIPTS_RE.search(line)
        if imports:
            arguments = _call_arguments(lines, idx, imports.end() - 1, max_lines=4)
            if re.search(r"""['"`]http://""", arguments, re.IGNORECASE):
                _emit(
                    "high",
                    "importScripts şifresiz HTTP üzerinden betik yüklüyor",
                    "Service worker HTTP üzerinden betik içe aktarıyor; ağdaki saldırgan kodu değiştirerek "
                    "tüm site trafiğini kalıcı olarak ele geçirebilir.",
                    stripped,
                    "Betikleri aynı kökenden (same-origin) ve HTTPS ile sunun; harici kodu pakete dahil edin.",
                    "CWE-829",
                    "SNIPER-PWA-01",
                    idx + 1,
                )
            elif ABSOLUTE_URL_RE.search(arguments):
                _emit(
                    "high",
                    "importScripts çapraz kökenli betik yüklüyor",
                    "Service worker başka bir kökenden (CDN/üçüncü taraf) betik içe aktarıyor. Üçüncü taraf ele "
                    "geçirilirse kod, tüm istekleri yakalayan service worker ayrıcalıklarıyla çalışır.",
                    stripped,
                    "Bağımlılığı yerel olarak paketleyin (ör. workbox-cli/injectManifest) ve aynı kökenden yükleyin.",
                    "CWE-829",
                    "SNIPER-PWA-01",
                    idx + 1,
                )

        if SW_REGISTER_HTTP_RE.search(line):
            _emit(
                "high",
                "Service worker HTTP adresinden kaydediliyor",
                "navigator.serviceWorker.register HTTP bir betik adresi kullanıyor; betik bütünlüğü korunmuyor.",
                stripped,
                "Service worker betiğini yalnızca HTTPS ve aynı kökenden kaydedin.",
                "CWE-829",
                "SNIPER-PWA-01",
                idx + 1,
            )

        add_all = ADD_ALL_RE.search(line)
        if add_all:
            arguments = _call_arguments(lines, idx, add_all.end() - 1, max_lines=12)
            sensitive = _find_sensitive_path_literal(arguments)
            if sensitive:
                _emit(
                    "high",
                    "Kimlik doğrulamalı/API yanıtları önbelleğe önceden alınıyor",
                    f"cache.addAll listesi hassas bir yol içeriyor ({sensitive[:80]}). Kişisel veya "
                    "oturuma bağlı yanıtlar Cache Storage'da kalır; ortak cihazda veya oturum kapandıktan sonra "
                    "okunabilir.",
                    stripped,
                    "Yalnızca statik varlıkları önbelleğe alın; API ve hesap uç noktaları için NetworkOnly "
                    "stratejisi kullanın ve oturum kapanışında önbelleği temizleyin.",
                    "CWE-524",
                    "SNIPER-PWA-02",
                    idx + 1,
                )

        route = REGISTER_ROUTE_RE.search(line)
        if route:
            arguments = _call_arguments(lines, idx, route.end() - 1, max_lines=8)
            if SENSITIVE_ROUTE_TEXT_RE.search(arguments) and CACHE_STRATEGY_RE.search(arguments):
                _emit(
                    "high",
                    "Workbox API/hesap rotası önbellek öncelikli stratejiyle sunuluyor",
                    "registerRoute ile API, kimlik doğrulama veya hesap yolları CacheFirst/StaleWhileRevalidate "
                    "stratejisiyle önbelleğe alınıyor; bayat veya başka kullanıcıya ait yanıtlar sunulabilir.",
                    stripped,
                    "Kimlik doğrulamalı rotalarda NetworkOnly (veya kısa ömürlü NetworkFirst + Vary) kullanın.",
                    "CWE-524",
                    "SNIPER-PWA-02",
                    idx + 1,
                )

        cache_put = CACHE_PUT_RE.search(line)
        if cache_put:
            before = "\n".join(lines[max(0, idx - 12):idx + 1])
            around = "\n".join(lines[max(0, idx - 8):idx + 9])
            auth_context = AUTH_HEADER_RE.search(around)
            api_context = _find_sensitive_path_literal(around)
            unchecked = not RESPONSE_CHECK_RE.search(before)
            if auth_context or api_context:
                title = (
                    "Authorization başlıklı istek yanıtı önbelleğe alınıyor"
                    if auth_context
                    else "Kimlik doğrulamalı/API yanıtı önbelleğe alınıyor"
                )
                description = (
                    "cache.put çağrısı kimlik bilgisi taşıyan veya API'ye giden isteklerin yanıtlarını Cache "
                    "Storage'a yazıyor; kullanıcıya özel veriler kalıcı olarak saklanır ve oturum sonrası okunabilir."
                )
                if unchecked:
                    description += " Ayrıca yanıt durumu (response.ok/status/type) doğrulanmıyor."
                _emit(
                    "high",
                    title,
                    description,
                    stripped,
                    "Authorization başlığı içeren veya API'ye giden istekleri önbelleğe almayın; gerekiyorsa "
                    "Cache-Control: no-store başlığına uyun ve oturum kapanışında caches.delete çağırın.",
                    "CWE-524",
                    "SNIPER-PWA-02",
                    idx + 1,
                )
            elif unchecked:
                _emit(
                    "medium",
                    "Yanıt durumu doğrulanmadan önbelleğe alınıyor",
                    "fetch işleyicisi yanıtları response.ok/status/type kontrolü olmadan önbelleğe yazıyor; hata "
                    "sayfaları, yönlendirmeler veya opak (opaque) üçüncü taraf yanıtları kalıcı olarak sunulabilir.",
                    stripped,
                    "Önbelleğe yazmadan önce response.ok && response.type === 'basic' kontrolü yapın.",
                    "CWE-524",
                    "SNIPER-PWA-02",
                    idx + 1,
                )

        if _has_postmessage_star(line):
            _emit(
                "low",
                "postMessage hedef kökeni '*' olarak ayarlanmış",
                "Mesaj herhangi bir kökene teslim edilebilir; hassas veri içeriyorsa sızabilir.",
                stripped,
                "postMessage çağrılarında hedef kökeni açıkça belirtin.",
                "CWE-345",
                "SNIPER-PWA-01",
                idx + 1,
            )

    findings = sink.findings
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    return {
        "format": "sniper-pwa-service-worker-audit-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(SERVICE_WORKER_CONTROLS),
    }


# --- Public API: project scan -----------------------------------------------


def _read_bounded(tree: ProjectTree, project_file: ProjectFile) -> str | None:
    if project_file.size == 0 or project_file.size > MAX_INLINE_BYTES:
        return None
    content = tree.read_text(project_file, MAX_INLINE_BYTES, errors="replace")
    if not content.strip():
        return None
    return content


@project_scan_scope
def audit_extension_pwa_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    manifest_paths: list[ProjectFile] = []
    script_paths: list[ProjectFile] = []

    with ProjectTree(root) as tree:
        for project_file in tree.iter_files(skip_dirs=SKIP_DIRS, reject_unsafe=False):
            if len(manifest_paths) + len(script_paths) >= MAX_COLLECTED_PATHS:
                continue
            if any(part.casefold() in SKIP_DIRS for part in project_file.path.parts[:-1]):
                continue
            if project_file.name.casefold() == "manifest.json":
                manifest_paths.append(project_file)
            elif project_file.path.suffix.lower() in SCRIPT_EXTENSIONS:
                script_paths.append(project_file)

        findings: list[dict[str, Any]] = []
        scanned_files = 0
        extension_manifest_count = 0
        extension_script_count = 0
        service_worker_count = 0
        extension_dirs: list[PurePosixPath] = []

        for project_file in manifest_paths:
            if scanned_files >= MAX_PROJECT_FILES:
                break
            content = _read_bounded(tree, project_file)
            if content is None:
                continue
            scanned_files += 1
            # PWA web app manifests share the file name but lack manifest_version.
            manifest_data = _parse_manifest_json_object(content)
            if "manifest_version" not in manifest_data:
                if EXTENSION_MANIFEST_HINT_KEYS.intersection(manifest_data):
                    raise ValueError("manifest_version yalnızca 2 veya 3 tamsayısı olmalıdır.")
                continue
            rel_name = project_file.path.as_posix()
            report = audit_extension_manifest_inline(content, filename=rel_name)
            extension_manifest_count += 1
            extension_dirs.append(project_file.path.parent)
            findings.extend(report["findings"])

        for project_file in script_paths:
            if scanned_files >= MAX_PROJECT_FILES:
                break
            in_extension = any(
                base == project_file.path.parent or base in project_file.path.parents
                for base in extension_dirs
            )
            named_worker = _is_service_worker_name(project_file.name)
            content = _read_bounded(tree, project_file)
            if content is None:
                continue
            scanned_files += 1
            is_worker = named_worker or bool(SW_CONTENT_RE.search(content))
            if not (in_extension or is_worker):
                continue
            rel_name = project_file.path.as_posix()
            if in_extension:
                try:
                    report = audit_extension_script_inline(content, filename=rel_name)
                except ValueError:
                    report = None
                if report is not None:
                    extension_script_count += 1
                    findings.extend(report["findings"])
            if is_worker:
                try:
                    report = audit_service_worker_inline(content, filename=rel_name)
                except ValueError:
                    report = None
                if report is not None:
                    service_worker_count += 1
                    findings.extend(report["findings"])

    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, PROJECT_FINDING_LIMIT)
    return {
        "format": "sniper-browser-extension-pwa-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "extension_manifest_count": extension_manifest_count,
        "extension_script_count": extension_script_count,
        "service_worker_count": service_worker_count,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(EXTENSION_PWA_CONTROLS_EVALUATED),
    }


_XSTACK_USE_SERVER_RE = re.compile(r"""["']use server["']""")
_XSTACK_DB_MUTATION_RE = re.compile(
    r"\b(?:prisma|db)\.[A-Za-z0-9_]+\.(?:delete|deleteMany|update|updateMany|create|upsert)\s*\("
    r"|\b(?:DELETE\s+FROM|UPDATE\s+\w+\s+SET|INSERT\s+INTO)\b",
    re.IGNORECASE,
)
_XSTACK_AUTH_CHECK_RE = re.compile(
    r"\b(?:auth\s*\(|getServerSession|currentUser|verifySession|requireAuth|checkPermission|getSession)\b"
)
_XSTACK_POSTMESSAGE_RE = re.compile(
    r"""(?:(?:\bwindow|\bglobalThis)\s*\.\s*|(?<![.\w$]))addEventListener\s*\(\s*["']message["']"""
)
_XSTACK_SSR_LOADER_RE = re.compile(r"\bgetServerSideProps\b|export\s+(?:async\s+)?function\s+loader\b")
_XSTACK_SSR_SECRET_ENV_RE = re.compile(
    r"process\.env(?:\.[A-Za-z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|DATABASE_URL)\b|\s*[,\}\)])"
)


def audit_cross_stack_web_security(
    raw_content: str,
    *,
    filename: str = "actions.ts",
) -> dict[str, Any]:
    """Next.js Server Actions, postMessage origin ve SSR veri yükleyici çapraz katman güvenlik denetimi."""
    if not isinstance(raw_content, str) or not raw_content.strip():
        return {"findings": [], "count": 0, "finding_count": 0, "filename": filename}

    findings: list[dict[str, Any]] = []

    if _XSTACK_USE_SERVER_RE.search(raw_content) and not _XSTACK_AUTH_CHECK_RE.search(raw_content):
        for match in _XSTACK_DB_MUTATION_RE.finditer(raw_content):
            line_no = raw_content.count("\n", 0, match.start()) + 1
            findings.append(
                {
                    "control_id": "SNIPER-XSTACK-SA-01",
                    "severity": "high",
                    "cwe": "CWE-862",
                    "reference": "CWE-862",
                    "category": "authorization",
                    "title": (
                        "Next.js Server Action ('use server') içinde kimlik/yetki doğrulaması "
                        "olmadan doğrudan veritabanı mutasyonu"
                    ),
                    "description": (
                        "Server Action doğrudan dış HTTP POST uç noktası olarak çağrılabilir; "
                        "oturum ve yetki doğrulaması olmadan veritabanı mutasyonu yetkisiz erişime yol açar."
                    ),
                    "file": filename,
                    "line": line_no,
                    "evidence": match.group(0)[:200],
                    "recommendation": (
                        "Server Action içinde veritabanı mutasyonundan önce getServerSession / auth() "
                        "ile oturum ve yetki doğrulaması uygulayın."
                    ),
                }
            )

    for match in _XSTACK_POSTMESSAGE_RE.finditer(raw_content):
        window_text = raw_content[match.start() : match.end() + 450]
        if ".origin" not in window_text:
            line_no = raw_content.count("\n", 0, match.start()) + 1
            findings.append(
                {
                    "control_id": "SNIPER-XSTACK-MSG-02",
                    "severity": "high",
                    "cwe": "CWE-346",
                    "reference": "CWE-346",
                    "category": "web_hardening",
                    "title": (
                        "window.addEventListener('message') işleyicisinde event.origin "
                        "doğrulaması eksik (Cross-Origin postMessage DOM XSS)"
                    ),
                    "description": (
                        "postMessage dinleyicisi gelen mesajın event.origin kaynağını doğrulamadan "
                        "veriyi işliyor; çapraz kaynaklı pencerelerden DOM XSS veya durum manipülasyonu tetiklenebilir."
                    ),
                    "file": filename,
                    "line": line_no,
                    "evidence": match.group(0)[:200],
                    "recommendation": (
                        "postMessage işleyicisinde mesaj verisini kullanmadan önce event.origin "
                        "değerini katı bir güvenilir kaynak listesiyle (allowlist) doğrulayın."
                    ),
                }
            )

    if _XSTACK_SSR_LOADER_RE.search(raw_content):
        for match in _XSTACK_SSR_SECRET_ENV_RE.finditer(raw_content):
            line_no = raw_content.count("\n", 0, match.start()) + 1
            findings.append(
                {
                    "control_id": "SNIPER-XSTACK-SSR-03",
                    "severity": "high",
                    "cwe": "CWE-200",
                    "reference": "CWE-200",
                    "category": "web_hardening",
                    "title": (
                        "SSR veri yükleyicisinde (getServerSideProps / loader) gizli ortam "
                        "değişkeninin istemciye sızdırılması"
                    ),
                    "description": (
                        "SSR veri yükleyicisi (getServerSideProps / loader) içinde gizli ortam "
                        "değişkeni veya tüm process.env nesnesi istemciye serileştirilen props içine aktarılıyor."
                    ),
                    "file": filename,
                    "line": line_no,
                    "evidence": match.group(0)[:200],
                    "recommendation": (
                        "SSR yükleyicilerinde gizli ortam değişkenlerini yalnızca sunucu tarafında "
                        "kullanın ve istemciye serileştirilen props nesnesine dahil etmeyin."
                    ),
                }
            )

    return {
        "findings": findings,
        "count": len(findings),
        "finding_count": len(findings),
        "filename": filename,
    }

