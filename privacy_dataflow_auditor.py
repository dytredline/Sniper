from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from safe_file_read import read_text_bounded
import taint_flow
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500
MAX_FINDINGS_PER_FILE = 300
MAX_LINE_CHARS = 4_000

PRIVACY_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-LOGG-02",
    "SNIPER-DATA-02",
    "SNIPER-DATA-05",
    "SNIPER-DATA-07",
    "SNIPER-DATA-08",
    "SNIPER-AI-06",
]

PRIVACY_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".go", ".java", ".kt", ".rb",
    ".php", ".cs", ".swift", ".dart", ".sql", ".prisma", ".html",
}

TRACKING_EXTENSIONS: set[str] = {".html", ".htm", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}

STORAGE_EXTENSIONS: set[str] = {".sql", ".prisma"}


# ---------------------------------------------------------------------------
# PII taksonomisi (KVKK / GDPR)
# ---------------------------------------------------------------------------

CAT_IDENTITY = "Kimlik"
CAT_FINANCIAL = "Finansal"
CAT_HEALTH = "Sağlık"
CAT_BIOMETRIC = "Biyometrik"
CAT_SPECIAL = "Özel nitelikli"
CAT_CONTACT = "İletişim/Kimlik"
CAT_LOCATION = "Konum"
CAT_ONLINE = "Çevrimiçi tanımlayıcı"

# kategori -> (KVKK/GDPR sınıfı, özel nitelikli mi)
CATEGORY_CLASSES: dict[str, tuple[str, bool]] = {
    CAT_IDENTITY: ("Kimlik verisi (özel nitelikli değil ama yüksek risk)", False),
    CAT_FINANCIAL: ("Finansal veri (özel nitelikli değil ama yüksek risk)", False),
    CAT_HEALTH: ("Sağlık (özel nitelikli, KVKK m.6 / GDPR Art.9)", True),
    CAT_BIOMETRIC: ("Biyometrik (özel nitelikli, KVKK m.6 / GDPR Art.9)", True),
    CAT_SPECIAL: ("Özel nitelikli (KVKK m.6 / GDPR Art.9)", True),
    CAT_CONTACT: ("Kimlik/İletişim verisi (KVKK m.4 genel ilkeler / GDPR Art.5)", False),
    CAT_LOCATION: ("Konum verisi (GDPR Art.4(1))", False),
    CAT_ONLINE: ("Çevrimiçi tanımlayıcı (GDPR Recital 30)", False),
}

# snake_case biçimine normalize edilmiş tanımlayıcı -> kategori
PII_TAXONOMY: dict[str, str] = {
    # Kimlik
    "tc_kimlik": CAT_IDENTITY, "tc_kimlik_no": CAT_IDENTITY, "tckn": CAT_IDENTITY,
    "tc_no": CAT_IDENTITY, "kimlik_no": CAT_IDENTITY, "national_id": CAT_IDENTITY,
    "ssn": CAT_IDENTITY, "social_security_number": CAT_IDENTITY,
    "passport_number": CAT_IDENTITY, "passport_no": CAT_IDENTITY,
    # Finansal
    "iban": CAT_FINANCIAL, "card_number": CAT_FINANCIAL, "card_no": CAT_FINANCIAL,
    "credit_card": CAT_FINANCIAL, "credit_card_number": CAT_FINANCIAL, "cvv": CAT_FINANCIAL,
    "cvc": CAT_FINANCIAL, "pan": CAT_FINANCIAL, "kart_no": CAT_FINANCIAL,
    "account_number": CAT_FINANCIAL,
    # Sağlık (özel nitelikli)
    "health": CAT_HEALTH, "health_data": CAT_HEALTH, "health_record": CAT_HEALTH,
    "diagnosis": CAT_HEALTH, "blood_type": CAT_HEALTH, "medical": CAT_HEALTH,
    "medical_record": CAT_HEALTH, "disease": CAT_HEALTH, "prescription": CAT_HEALTH,
    "teshis": CAT_HEALTH, "kan_grubu": CAT_HEALTH,
    # Biyometrik (özel nitelikli)
    "biometric": CAT_BIOMETRIC, "biometrics": CAT_BIOMETRIC, "fingerprint": CAT_BIOMETRIC,
    "face_id": CAT_BIOMETRIC, "face_template": CAT_BIOMETRIC, "voiceprint": CAT_BIOMETRIC,
    "iris_scan": CAT_BIOMETRIC,
    # Diğer özel nitelikli
    "religion": CAT_SPECIAL, "ethnicity": CAT_SPECIAL, "ethnic_origin": CAT_SPECIAL,
    "political": CAT_SPECIAL, "political_opinion": CAT_SPECIAL,
    "sexual_orientation": CAT_SPECIAL, "union_membership": CAT_SPECIAL,
    "trade_union": CAT_SPECIAL, "criminal_record": CAT_SPECIAL, "mezhep": CAT_SPECIAL,
    # İletişim / Kimlik
    "email": CAT_CONTACT, "e_mail": CAT_CONTACT, "email_address": CAT_CONTACT,
    "eposta": CAT_CONTACT, "phone": CAT_CONTACT, "phone_number": CAT_CONTACT,
    "mobile_number": CAT_CONTACT, "msisdn": CAT_CONTACT, "telefon": CAT_CONTACT,
    "address": CAT_CONTACT, "home_address": CAT_CONTACT, "adres": CAT_CONTACT,
    "birth_date": CAT_CONTACT, "birthdate": CAT_CONTACT, "date_of_birth": CAT_CONTACT,
    "dob": CAT_CONTACT, "dogum_tarihi": CAT_CONTACT, "full_name": CAT_CONTACT,
    "ad_soyad": CAT_CONTACT,
    # Konum
    "latitude": CAT_LOCATION, "longitude": CAT_LOCATION, "geolocation": CAT_LOCATION,
    "geo_location": CAT_LOCATION, "gps": CAT_LOCATION,
    # Çevrimiçi tanımlayıcı
    "ip_address": CAT_ONLINE, "ip_addr": CAT_ONLINE, "client_ip": CAT_ONLINE,
    "remote_addr": CAT_ONLINE, "device_id": CAT_ONLINE, "idfa": CAT_ONLINE,
    "gaid": CAT_ONLINE, "advertising_id": CAT_ONLINE, "mac_address": CAT_ONLINE,
    "imei": CAT_ONLINE,
}

# Belirli belirteçlerden sonra gelince PII anlamı taşımayan parçalar
# (ör. health_check, fingerprint_sha256).
_TOKEN_BLOCK_NEXT: dict[str, set[str]] = {
    "health": {"check", "checks", "checker", "z", "status", "probe", "endpoint", "monitor",
               "url", "port", "service", "ok", "route", "handler"},
    "fingerprint": {"sha256", "sha1", "sha", "md5", "hash", "hex"},
    "address": {"space", "family", "book"},
}

_IDENT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
_CAMEL_LOWER_UPPER_RE = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_ACRONYM_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_STRING_LITERAL_RE = re.compile(
    r"\"(?:\\.|[^\"\\\n]){0,2000}\"|'(?:\\.|[^'\\\n]){0,2000}'|`(?:\\.|[^`\\\n]){0,2000}`"
)
_INTERPOLATION_RE = re.compile(r"\{([^{}\n]{1,200})\}")

_MASK_RE = re.compile(
    r"(?i)(mask|redact|hash|anonymi[sz]e|pseudonymi[sz]e|tokeni[sz]e|encrypt|sha256|hmac|obfuscat|\*\*\*)"
)
_LLM_MASK_RE = re.compile(
    r"(?i)(redact|mask|anonymi[sz]|pseudonymi[sz]|presidio|scrub|deidentif|de_identif)"
)
_ENCRYPT_RE = re.compile(
    r"(?i)(encrypt|cipher|pgp_sym|EncryptedField|EncryptedType|fernet|aes_|_aes\b|kms)"
)

_LOG_SINK_RE = re.compile(
    r"(?:\blogger\.\w+\s*\(|\blogging\.\w+\s*\(|\blog\.(?:Printf|Println|Print|Fatal\w*|Panic\w*|"
    r"debug|info|warn|warning|error|trace|fatal)\s*\(|(?<![\w.])print\s*\(|"
    r"\bconsole\.(?:log|info|warn|error|debug|trace)\s*\(|\bSystem\.(?:out|err)\.print(?:ln|f)?\s*\(|"
    r"\bLog\.[dievw]\s*\(|\bfmt\.Print(?:ln|f)?\s*\(|\berror_log\s*\(|\bRails\.logger\.\w+|"
    r"\bslog\.\w+\s*\(|\bNSLog\s*\(|\bdebugPrint\s*\()"
)

_ANALYTICS_SINK_RE = re.compile(
    r"(?:\bSentry\.(?:setUser|setContext|setExtra|setTag)\s*\(|\bsentry_sdk\.set_(?:user|context|extra|tag)\s*\(|"
    r"\banalytics\.(?:track|identify|page)\s*\(|\bmixpanel\.(?:track|identify|register|people\.set)\s*\(|"
    r"\bgtag\s*\(|(?<![\w.])ga\s*\(|\bfbq\s*\(|\bamplitude\.(?:logEvent|track|identify|setUserId|setUserProperties)\s*\(|"
    r"\bposthog\.(?:capture|identify)\s*\(|\bdatadogRum\.(?:setUser|addAction)\s*\(|\blogEvent\s*\(|"
    r"\bsetUserProperty\s*\(|\bsetUserProperties\s*\(|\bhj\s*\(\s*['\"]identify)"
)

_LLM_SINK_RE = re.compile(
    r"(?:\bopenai\.(?:ChatCompletion|Completion|chat|completions|responses)\b|"
    r"\banthropic\.(?:messages|completions)\b|\bchat\.completions\.create\s*\(|"
    r"\bcompletions\.create\s*\(|\bresponses\.create\s*\(|\bgenai\.GenerativeModel\s*\(|"
    r"\bgenerate_content\s*\(|\bChatOpenAI\s*\(|\bChatAnthropic\s*\()"
)
_ANTHROPIC_MESSAGES_RE = re.compile(r"\bmessages\.create\s*\(")
_ANTHROPIC_CONTEXT_RE = re.compile(r"(?i)(anthropic|claude)")

_TRACKER_RE = re.compile(
    r"(?i)(googletagmanager\.com|google-analytics\.com|connect\.facebook\.net|static\.hotjar\.com|"
    r"analytics\.tiktok\.com|snap\.licdn\.com|clarity\.ms)"
)
_CONSENT_RE = re.compile(
    r"(?i)(consent|onetrust|cookiebot|klaro|usercentrics|gdprApplies|tcfapi|iubenda|didomi|cookieyes|complianz)"
)

_MODEL_MARKER_RE = re.compile(
    r"(?im)(^\s*CREATE\s+TABLE\b|"
    r"^\s*class\s+\w+\s*\([^)\n]{0,200}\b(?:Model|Base|BaseModel|DeclarativeBase|Document|SQLModel)\b[^)\n]{0,200}\)|"
    r"^\s*model\s+\w+\s*\{|@Entity\b|\bmongoose\.Schema\s*\(|\bnew\s+Schema\s*\(|"
    r"\bdefine\s*\(\s*['\"]\w+['\"]\s*,\s*\{)"
)
_DECLARATION_RE = re.compile(
    r"(?i)(\bColumn\s*\(|\bmodels\.\w+Field\s*\(|\bmapped_column\s*\(|\bField\s*\(|@Column\b|"
    r"^\s*[A-Za-z_]\w*\s+(?:VARCHAR|NVARCHAR|TEXT|CHAR|INT|INTEGER|BIGINT|DATE|TIMESTAMP|BLOB|BYTEA|"
    r"JSONB?|NUMERIC|DECIMAL|BOOLEAN|UUID|String|Int|DateTime|Json|Bytes|Float)\b|"
    r"^\s*[A-Za-z_]\w*\s*:\s*(?:str|int|date|datetime|Optional\[|Mapped\[|String|Number|Date)\b|"
    r"^\s*[A-Za-z_]\w*\s*:\s*\{\s*type\s*:)"
)

_ERASURE_RE = re.compile(
    r"(?i)(delete_user|deleteuser|delete_account|deleteaccount|\berase|anonymi[sz]e|right_to_erasure|"
    r"gdpr_delete|on\s+delete\s+cascade|forget_me|forgetme|purge_user)"
)

_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "<!--")


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def _split_identifier(identifier: str) -> list[str]:
    snake = _CAMEL_ACRONYM_RE.sub(r"\1_\2", _CAMEL_LOWER_UPPER_RE.sub(r"\1_\2", identifier))
    return [part for part in snake.lower().split("_") if part]


def _identifier_categories(identifier: str) -> list[str]:
    parts = _split_identifier(identifier)
    categories: list[str] = []
    index = 0
    total = len(parts)
    while index < total:
        matched = False
        for width in (4, 3, 2, 1):
            if index + width > total:
                continue
            key = "_".join(parts[index:index + width])
            category = PII_TAXONOMY.get(key)
            if category is None:
                continue
            blocked = _TOKEN_BLOCK_NEXT.get(key)
            if blocked and index + width < total and parts[index + width] in blocked:
                continue
            categories.append(category)
            index += width
            matched = True
            break
        if not matched:
            index += 1
    return categories


def _code_view(line: str) -> str:
    """Dize sabitlerinin içeriğini atar, yalnızca {ifade} enterpolasyonlarını korur."""

    def _replace(match: re.Match[str]) -> str:
        expressions = _INTERPOLATION_RE.findall(match.group(0))
        return " " + " ".join(expressions) + " " if expressions else " "

    return _STRING_LITERAL_RE.sub(_replace, line)


def _pii_hits(line: str) -> list[tuple[str, str]]:
    if len(line) > MAX_LINE_CHARS:
        return []
    hits: list[tuple[str, str]] = []
    for match in _IDENT_RE.finditer(_code_view(line)):
        identifier = match.group(0)
        for category in _identifier_categories(identifier):
            hits.append((category, identifier))
    return hits


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(_COMMENT_PREFIXES)


def _effective_ext(filename: str) -> str:
    return Path(filename).suffix.lower()


def _is_special(categories: set[str]) -> bool:
    return any(CATEGORY_CLASSES[category][1] for category in categories)


def _make_privacy_finding(
    *,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    reference: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
    categories: set[str],
) -> dict[str, Any]:
    clean_ev = evidence.strip()[:240]
    item = _finding(
        severity,
        "privacy",
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        f"{reference} · {cwe}",
        cookie_identity=(filename, str(line), control_id, cwe),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    item["data_categories"] = sorted(categories)
    item["special_category"] = _is_special(categories)
    return item


def _new_inventory() -> dict[str, dict[str, set[str]]]:
    return {}


def _inventory_add(
    inventory: dict[str, dict[str, set[str]]],
    hits: list[tuple[str, str]],
    filename: str,
    sink: str | None = None,
) -> None:
    for category, identifier in hits:
        entry = inventory.setdefault(category, {"fields": set(), "files": set(), "sinks": set()})
        entry["fields"].add(identifier)
        entry["files"].add(filename)
        if sink:
            entry["sinks"].add(sink)


def _merge_inventory(
    target: dict[str, dict[str, set[str]]],
    source: dict[str, dict[str, set[str]]],
) -> None:
    for category, entry in source.items():
        merged = target.setdefault(category, {"fields": set(), "files": set(), "sinks": set()})
        for key in ("fields", "files", "sinks"):
            merged[key].update(entry[key])


def _build_ropa(inventory: dict[str, dict[str, set[str]]]) -> list[dict[str, Any]]:
    ropa: list[dict[str, Any]] = []
    for category in sorted(inventory):
        entry = inventory[category]
        kvkk_class, special = CATEGORY_CLASSES[category]
        ropa.append({
            "data_category": category,
            "kvkk_class": kvkk_class,
            "fields": sorted(entry["fields"])[:50],
            "files": sorted(entry["files"])[:20],
            "sinks": sorted(entry["sinks"]),
            "special_category": special,
        })
    return ropa


def _analyze_privacy(
    content: str,
    filename: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, set[str]]], bool]:
    """Tek dosya analizi: (bulgular, ROPA envanteri, PII içeren model tanımı var mı)."""
    lines = content.splitlines()
    total = len(lines)
    ext = _effective_ext(filename)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    inventory = _new_inventory()
    has_pii_model = False

    def _add(finding: dict[str, Any]) -> None:
        key = (str(finding["control_id"]), int(finding["line"]))
        if key in seen or len(findings) >= MAX_FINDINGS_PER_FILE:
            return
        seen.add(key)
        findings.append(finding)

    comment_flags = [_is_comment(line) for line in lines]
    line_hits = [[] if comment_flags[i] else _pii_hits(line) for i, line in enumerate(lines)]
    for hits in line_hits:
        if hits:
            _inventory_add(inventory, hits, filename)

    # 1. Loglara PII yazımı (SNIPER-LOGG-02, CWE-532)
    for index, line in enumerate(lines):
        hits = line_hits[index]
        if not hits or not _LOG_SINK_RE.search(line):
            continue
        _inventory_add(inventory, hits, filename, "log")
        if _MASK_RE.search(line):
            continue
        categories = {category for category, _ident in hits}
        special = _is_special(categories)
        fields = ", ".join(sorted({ident for _cat, ident in hits})[:6])
        _add(_make_privacy_finding(
            severity="critical" if special else "high",
            title="Kişisel veri maskelenmeden log kaydına yazılıyor",
            description=(
                f"Log çağrısı kişisel veri ({', '.join(sorted(categories))}) içeriyor ve maskeleme/"
                f"hash'leme görülmüyor. Alanlar: {fields}. Loglar genellikle geniş erişimli ve uzun "
                "süre saklanır; veri minimizasyonu ilkesine aykırıdır."
            ),
            evidence=line,
            recommendation=(
                "Kişisel verileri loglamayın; gerekiyorsa maskeleyin (ör. e-posta → a***@d***.com), "
                "anahtarlı hash (HMAC) veya takma ad (pseudonym) kullanın ve log saklama süresini sınırlayın."
            ),
            reference="KVKK m.4/m.12 · GDPR Art.5(1)(c)/32 · OWASP Logging Cheat Sheet",
            cwe="CWE-532",
            control_id="SNIPER-LOGG-02",
            filename=filename,
            line=index + 1,
            categories=categories,
        ))

    # 1b. Veri akışı: kişisel veri alanı değişken(ler) üzerinden log çağrısına ulaşıyor
    # (ör. contact = user.email; logger.info(contact)). Satırda doğrudan PII görülen
    # çağrılar yukarıdaki satır tabanlı kontrolle değerlendirilir.
    analysis = taint_flow.analyze_source(content, filename, pii=lambda name: bool(_identifier_categories(name)))
    if analysis is not None:
        for flow in analysis.flows_of("log", "pii"):
            index = flow.line - 1
            if not 0 <= index < total or comment_flags[index] or line_hits[index]:
                continue
            sink_line = lines[index]
            if _MASK_RE.search(sink_line):
                continue
            source_name = flow.source.rsplit(".", 1)[-1]
            categories = set(_identifier_categories(source_name))
            if not categories:
                continue
            _inventory_add(inventory, [(category, source_name) for category in sorted(categories)], filename, "log")
            special = _is_special(categories)
            finding = _make_privacy_finding(
                severity="critical" if special else "high",
                title="Kişisel veri maskelenmeden log kaydına yazılıyor",
                description=(
                    f"Kişisel veri alanı ({', '.join(sorted(categories))}) değişken üzerinden maskelenmeden "
                    f"log çağrısına ulaşıyor. Veri akışı: {flow.describe()}. Loglar genellikle geniş erişimli "
                    "ve uzun süre saklanır; veri minimizasyonu ilkesine aykırıdır."
                ),
                evidence=sink_line,
                recommendation=(
                    "Kişisel verileri loglamayın; gerekiyorsa maskeleyin (ör. e-posta → a***@d***.com), "
                    "anahtarlı hash (HMAC) veya takma ad (pseudonym) kullanın ve log saklama süresini sınırlayın."
                ),
                reference="KVKK m.4/m.12 · GDPR Art.5(1)(c)/32 · OWASP Logging Cheat Sheet",
                cwe="CWE-532",
                control_id="SNIPER-LOGG-02",
                filename=filename,
                line=flow.line,
                categories=categories,
            )
            finding["taint_flow"] = flow.as_dict()
            _add(finding)

    # 2. Üçüncü taraf analitik/telemetriye PII (SNIPER-DATA-05, CWE-359)
    for index, line in enumerate(lines):
        if comment_flags[index] or not _ANALYTICS_SINK_RE.search(line):
            continue
        window = range(max(0, index - 3), min(total, index + 4))
        window_hits = [hit for j in window for hit in line_hits[j]]
        if not window_hits:
            continue
        _inventory_add(inventory, window_hits, filename, "analytics")
        if any(_MASK_RE.search(lines[j]) for j in window):
            continue
        categories = {category for category, _ident in window_hits}
        _add(_make_privacy_finding(
            severity="high",
            title="Kişisel veri üçüncü taraf analitik/telemetri servisine gönderiliyor",
            description=(
                f"Analitik/telemetri çağrısının yakınında kişisel veri ({', '.join(sorted(categories))}) "
                "kullanılıyor. Veri yurt dışındaki bir veri işleyene aktarılabilir; açık rıza ve "
                "veri işleme sözleşmesi (DPA) gerekir."
            ),
            evidence=line,
            recommendation=(
                "Analitik servislerine yalnızca rastgele/takma kimlik gönderin; e-posta, telefon, kimlik "
                "numarası gibi alanları göndermeyin. Gerekiyorsa anahtarlı hash kullanın ve "
                "Sentry 'send_default_pii=False' gibi ayarları etkinleştirin."
            ),
            reference="KVKK m.5/m.9 · GDPR Art.5/25/44",
            cwe="CWE-359",
            control_id="SNIPER-DATA-05",
            filename=filename,
            line=index + 1,
            categories=categories,
        ))

    # 3. Harici LLM API'sine PII (SNIPER-AI-06, CWE-359)
    anthropic_context = bool(_ANTHROPIC_CONTEXT_RE.search(content))
    for index, line in enumerate(lines):
        if comment_flags[index]:
            continue
        is_llm = bool(_LLM_SINK_RE.search(line)) or (
            anthropic_context and bool(_ANTHROPIC_MESSAGES_RE.search(line))
        )
        if not is_llm:
            continue
        window = range(max(0, index - 5), min(total, index + 6))
        window_hits = [hit for j in window for hit in line_hits[j]]
        if not window_hits:
            continue
        _inventory_add(inventory, window_hits, filename, "llm")
        if any(_LLM_MASK_RE.search(lines[j]) for j in window):
            continue
        categories = {category for category, _ident in window_hits}
        _add(_make_privacy_finding(
            severity="high",
            title="Kişisel veri harici LLM API'sine maskelenmeden gönderiliyor",
            description=(
                f"Harici dil modeli çağrısının ±5 satırında kişisel veri ({', '.join(sorted(categories))}) "
                "kullanılıyor ve redaksiyon/anonimleştirme görülmüyor. İstem içeriği sağlayıcıda "
                "saklanabilir veya yurt dışına aktarılabilir."
            ),
            evidence=line,
            recommendation=(
                "İstemi göndermeden önce PII'yi redakte edin veya takma adlandırın (ör. Microsoft Presidio), "
                "sıfır veri saklama (ZDR) sözleşmeli uç nokta kullanın ve yurt dışı aktarım için "
                "KVKK m.9 şartlarını sağlayın."
            ),
            reference="KVKK m.4/m.9 · GDPR Art.5/25/28/44 · OWASP LLM Top 10 LLM02",
            cwe="CWE-359",
            control_id="SNIPER-AI-06",
            filename=filename,
            line=index + 1,
            categories=categories,
        ))

    # 4. Rıza alınmadan izleme betiği (SNIPER-DATA-07, CWE-359)
    if ext in TRACKING_EXTENSIONS and not _CONSENT_RE.search(content):
        for index, line in enumerate(lines):
            if len(line) > MAX_LINE_CHARS * 4:
                continue
            match = _TRACKER_RE.search(line)
            if not match:
                continue
            host = match.group(1).lower()
            _add(_make_privacy_finding(
                severity="medium",
                title="Kullanıcı rızası alınmadan izleme betiği yükleniyor",
                description=(
                    f"Dosya '{host}' izleme/analitik kaynağını yüklüyor ancak dosyada çerez rızası "
                    "(consent) mekanizmasına dair bir işaret yok. Zorunlu olmayan çerezler ve "
                    "izleme için önceden açık rıza gerekir."
                ),
                evidence=line,
                recommendation=(
                    "İzleme betiklerini bir rıza yönetim platformu (CMP) ile kullanıcı onayı sonrasında "
                    "yükleyin; Google Consent Mode v2 'default denied' ayarını kullanın."
                ),
                reference="KVKK m.5 · ePrivacy Art.5(3) · GDPR Art.6/7",
                cwe="CWE-359",
                control_id="SNIPER-DATA-07",
                filename=filename,
                line=index + 1,
                categories={CAT_ONLINE},
            ))

    # 6. Şifrelenmemiş özel nitelikli veri saklama (SNIPER-DATA-02, CWE-311)
    if ext in STORAGE_EXTENSIONS or _MODEL_MARKER_RE.search(content):
        for index, line in enumerate(lines):
            hits = line_hits[index]
            if not hits or not _DECLARATION_RE.search(line):
                continue
            has_pii_model = True
            _inventory_add(inventory, hits, filename, "storage")
            special_categories = {
                category for category, _ident in hits if CATEGORY_CLASSES[category][1]
            }
            if not special_categories or _ENCRYPT_RE.search(line):
                continue
            _add(_make_privacy_finding(
                severity="medium",
                title="Özel nitelikli kişisel veri şifrelenmeden saklanıyor",
                description=(
                    f"Veri modeli/tablo alanı özel nitelikli veri ({', '.join(sorted(special_categories))}) "
                    "içeriyor ancak alan düzeyinde şifreleme işareti görülmüyor. KVKK özel nitelikli "
                    "veriler için ek teknik tedbir (şifreleme) bekler."
                ),
                evidence=line,
                recommendation=(
                    "Alanı uygulama düzeyinde şifreleyin (ör. EncryptedType, pgp_sym_encrypt, KMS ile "
                    "zarf şifreleme), erişimi rol bazlı sınırlayın ve anahtarları ayrı saklayın."
                ),
                reference="KVKK m.6/m.12 · Kurul Kararı 2018/10 · GDPR Art.9/32",
                cwe="CWE-311",
                control_id="SNIPER-DATA-02",
                filename=filename,
                line=index + 1,
                categories=special_categories,
            ))

    return findings, inventory, has_pii_model


def _inventory_summary(inventory: dict[str, dict[str, set[str]]]) -> dict[str, Any]:
    categories = sorted(inventory)
    return {
        "ropa": _build_ropa(inventory),
        "pii_categories_detected": categories,
        "special_category_detected": any(CATEGORY_CLASSES[category][1] for category in categories),
    }


def audit_privacy_inline(
    raw_content: str,
    *,
    filename: str = "app.py",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Gizlilik veri akışı denetimi için kaynak içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "app.py"
    clean_filename = filename.strip()

    findings, inventory, _has_pii_model = _analyze_privacy(raw_content, clean_filename)
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    result: dict[str, Any] = {
        "format": "sniper-privacy-dataflow-inline-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(PRIVACY_CONTROLS_EVALUATED),
    }
    result.update(_inventory_summary(inventory))
    return result


@project_scan_scope
@taint_flow.project_context
def audit_privacy_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    taint_flow.activate_project(root, SKIP_DIRS)
    findings: list[dict[str, Any]] = []
    inventory = _new_inventory()
    scanned_files = 0
    pii_model_files: list[str] = []
    erasure_flow_detected = False

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            if scanned_files >= MAX_PROJECT_FILES:
                break
            file_path = Path(current) / name
            if file_path.is_symlink():
                continue
            if file_path.suffix.lower() not in PRIVACY_EXTENSIONS:
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip():
                continue
            rel_name = str(file_path.relative_to(root))
            scanned_files += 1
            file_findings, file_inventory, has_pii_model = _analyze_privacy(content, rel_name)
            findings.extend(file_findings)
            _merge_inventory(inventory, file_inventory)
            if has_pii_model:
                pii_model_files.append(rel_name)
            if not erasure_flow_detected and _ERASURE_RE.search(content):
                erasure_flow_detected = True

    # 5. Unutulma hakkı (silme/anonimleştirme) akışı eksikliği (SNIPER-DATA-08)
    if pii_model_files and not erasure_flow_detected:
        model_categories = {
            category
            for category, entry in inventory.items()
            if "storage" in entry["sinks"]
        }
        sample = ", ".join(sorted(pii_model_files)[:5])
        findings.append(_make_privacy_finding(
            severity="medium",
            title="Unutulma hakkı (veri silme/anonimleştirme) akışı bulunamadı",
            description=(
                "Projede kişisel veri içeren veri modelleri/tablolar var ancak hiçbir dosyada kullanıcı "
                "verisini silme veya anonimleştirme akışı (delete_user, anonymize, ON DELETE CASCADE vb.) "
                "bulunamadı. İlgili kişinin silme talebi karşılanamayabilir."
            ),
            evidence=f"PII içeren model dosyaları: {sample}",
            recommendation=(
                "Kullanıcı hesabını ve ilişkili tüm kişisel verileri silen veya geri döndürülemez şekilde "
                "anonimleştiren bir akış ekleyin; yedekler ve üçüncü taraf işleyenler için silme "
                "prosedürü ve saklama-imha politikası tanımlayın."
            ),
            reference="KVKK m.7/m.11 · Silme, Yok Etme veya Anonim Hale Getirme Yönetmeliği · GDPR Art.17",
            cwe="CWE-359",
            control_id="SNIPER-DATA-08",
            filename="(proje geneli)",
            line=0,
            categories=model_categories,
        ))

    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, PROJECT_FINDING_LIMIT)
    result: dict[str, Any] = {
        "format": "sniper-privacy-dataflow-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(PRIVACY_CONTROLS_EVALUATED),
        "pii_model_files": sorted(pii_model_files)[:50],
        "erasure_flow_detected": erasure_flow_detected,
    }
    result.update(_inventory_summary(inventory))
    return result
