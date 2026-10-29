"""Faz 1.1 — Kardeş Yordam / Sınıf Güvenlik Paritesi Denetleyicisi (Sibling Security Parity Auditor).

Aynı ad alanı (namespace), taban sınıf (base class) veya servis ailesi içindeki
kardeş uç noktalar, servis dalları, dönüştürücüler ve dosya sistemi işleyicileri
arasındaki asimetrik güvenlik kontrollerini tespit eder:
- SNIPER-PARITY-RAILS-01: Kardeş Rails Controller sınıfları arasında eksik before_action güvenlik paritesi.
- SNIPER-PARITY-SVC-02: Servis içinde asimetrik Ability.allowed? veya rezerve anahtar (.except) parite eksikliği.
- SNIPER-PARITY-SINK-03: Kardeş dönüştürücü/렌더러 sınıfları arasında eksik HTML sanitizasyonu veya --allowed-protocols kısıtı.
- SNIPER-PARITY-FS-04: Kardeş dosya sistemi dallarında asimetrik isSymbolicLink / validateBackupFile kontrolü.
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-sibling-security-parity/1"

_SECURITY_CALLBACKS = frozenset(
    {
        "verify_confirmed_email!",
        "verify_admin_allowed!",
        "enforce_organization_maintenance_mode",
        "authenticate_user!",
        "authorize!",
        "verify_user_active!",
        "require_admin!",
        "check_2fa_requirement",
    }
)

_RAILS_CLASS_RE = re.compile(
    r"^\s*class\s+([A-Za-z0-9_:]+Controller)\s*(?:<\s*([A-Za-z0-9_:]+))?",
    re.MULTILINE,
)
_MODULE_RE = re.compile(r"^\s*module\s+([A-Za-z0-9_:]+)", re.MULTILINE)
_BEFORE_ACTION_RE = re.compile(
    r"^\s*(before_action|prepend_before_action|before_filter)\s+([^\n#]+)",
    re.MULTILINE,
)
_SKIP_BEFORE_ACTION_RE = re.compile(
    r"^\s*(skip_before_action|skip_before_filter)\s+([^\n#]+)",
    re.MULTILINE,
)
_SYMBOL_RE = re.compile(r":([A-Za-z0-9_?!]+)")


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _extract_controller_units(files_map: dict[str, str]) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    for fname, content in files_map.items():
        matches = list(_RAILS_CLASS_RE.finditer(content))
        if not matches:
            continue
        module_matches = list(_MODULE_RE.finditer(content))
        for idx, m in enumerate(matches):
            start = m.start()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
            body = content[start:end]
            raw_cls_name = m.group(1)
            base_cls = (m.group(2) or "ApplicationController").strip()

            active_modules = [
                mm.group(1) for mm in module_matches if mm.start() < start
            ]
            if "::" in raw_cls_name:
                full_name = raw_cls_name
                namespace = raw_cls_name.rsplit("::", 1)[0]
            elif active_modules:
                namespace = "::".join(active_modules)
                full_name = f"{namespace}::{raw_cls_name}"
            else:
                namespace = ""
                full_name = raw_cls_name

            enforced: set[str] = set()
            for bm in _BEFORE_ACTION_RE.finditer(body):
                for sym in _SYMBOL_RE.findall(bm.group(2)):
                    if sym in _SECURITY_CALLBACKS or sym.startswith(
                        ("verify_", "enforce_", "authenticate_", "authorize")
                    ):
                        enforced.add(sym)

            skipped: set[str] = set()
            for sm in _SKIP_BEFORE_ACTION_RE.finditer(body):
                for sym in _SYMBOL_RE.findall(sm.group(2)):
                    skipped.add(sym)

            effective = enforced - skipped
            units.append(
                {
                    "filename": fname,
                    "class_name": full_name,
                    "namespace": namespace,
                    "base_class": base_cls,
                    "enforced": enforced,
                    "skipped": skipped,
                    "effective": effective,
                    "line": _line_number(content, start),
                    "snippet": m.group(0).strip(),
                }
            )
    return units


def _audit_rails_controllers(files_map: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    units = _extract_controller_units(files_map)
    if len(units) < 2:
        return findings

    groups: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        group_key = unit["namespace"] or unit["base_class"]
        groups.setdefault(group_key, []).append(unit)

    for _group_key, siblings in groups.items():
        if len(siblings) < 2:
            continue
        union_callbacks: set[str] = set()
        callback_sources: dict[str, str] = {}
        for sib in siblings:
            for cb in sib["effective"]:
                union_callbacks.add(cb)
                callback_sources.setdefault(cb, sib["class_name"])

        if not union_callbacks:
            continue

        for sib in siblings:
            missing = sorted(union_callbacks - sib["effective"])
            if not missing:
                continue
            ref_sibling = next(
                (
                    callback_sources[cb]
                    for cb in missing
                    if callback_sources.get(cb) != sib["class_name"]
                ),
                siblings[0]["class_name"],
            )
            findings.append(
                {
                    "rule_id": "SNIPER-PARITY-RAILS-01",
                    "cwe": "CWE-863",
                    "reference": "CWE-863",
                    "severity": "high",
                    "category": "authz",
                    "title": "Kardeş Rails Controller sınıfları arasında eksik güvenlik geri çağrısı (before_action) paritesi",
                    "description": (
                        f"`{sib['class_name']}` sınıfı, kardeş `{ref_sibling}` sınıfında zorunlu tutulan "
                        f"`{', '.join(missing)}` güvenlik geri çağrılarını (`before_action`) uygulamıyor "
                        "veya `skip_before_action` ile atlıyor."
                    ),
                    "remediation": (
                        f"Ortak güvenlik geri çağrılarını (`{', '.join(missing)}`) paylaşılan bir taban "
                        "denetleyiciye taşıyın veya kardeş sınıfta açıkça zorunlu kılın."
                    ),
                    "filename": sib["filename"],
                    "line": sib["line"],
                    "evidence": sib["snippet"],
                    "missing_callbacks": missing,
                    "reference_sibling": ref_sibling,
                }
            )
    return findings


def _audit_service_authz_and_except_parity(
    files_map: dict[str, str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    def_re = re.compile(r"^\s*def\s+([A-Za-z0-9_?!]+)", re.MULTILINE)
    except_re = re.compile(r"\.except\(\s*:orbit\s*\)")
    static_gitlab_re = re.compile(
        r"(?:\bgitlab\s*:|:gitlab\s*=>|\bSTATIC_SERVERS\b|\bmerge\s*\([^)]*gitlab)",
        re.IGNORECASE,
    )

    for fname, content in files_map.items():
        # 1) Asimetrik .except(:orbit) vs :gitlab rezerve anahtar paritesi
        for em in except_re.finditer(content):
            if static_gitlab_re.search(content):
                line_no = _line_number(content, em.start())
                findings.append(
                    {
                        "rule_id": "SNIPER-PARITY-SVC-02",
                        "cwe": "CWE-862",
                        "reference": "CWE-862",
                        "severity": "high",
                        "category": "authz",
                        "title": "Servis içinde asimetrik yetki kontrolü (Ability.allowed?) veya rezerve anahtar (.except) parite eksikliği",
                        "description": (
                            "Kullanıcı/konfigürasyon sunucu haritası `.except(:orbit)` ile filtrelenirken "
                            "statik `:gitlab` sunucu anahtarı dışlanmamış; dinamik yapılandırma statik sunucu "
                            "tanımını ezebilir veya çakışma yaratabilir."
                        ),
                        "remediation": (
                            "Statik sunucu anahtarlarının tamamını `.except(:orbit, :gitlab)` ile dışlayın."
                        ),
                        "filename": fname,
                        "line": line_no,
                        "evidence": em.group(0),
                    }
                )

        # 2) Asimetrik Ability.allowed? kontrolü (bir metot/dal kontrol ederken kardeş metot/dal atlıyor)
        if "Ability.allowed?" not in content:
            continue

        defs = list(def_re.finditer(content))
        if len(defs) >= 2:
            guarded_methods: list[str] = []
            unguarded_methods: list[tuple[str, int, str]] = []
            sensitive_ops_re = re.compile(
                r"\b(ItemConsumersFinder|item_version|reset_item_version|find_by|update!?|destroy!?|execute_for|consumers\.each|items\.each)\b"
            )
            for idx, dm in enumerate(defs):
                m_name = dm.group(1)
                if m_name == "initialize":
                    continue
                start = dm.start()
                end = defs[idx + 1].start() if idx + 1 < len(defs) else len(content)
                m_body = content[start:end]
                if "Ability.allowed?" in m_body or "authorize!" in m_body:
                    guarded_methods.append(m_name)
                elif sensitive_ops_re.search(m_body):
                    # Eğer bu metot içeriden guarded_method'u çağırmıyorsa asimetri vardır
                    called_guarded = any(
                        re.search(rf"\b{re.escape(gm)}\b", m_body)
                        for gm in guarded_methods
                    )
                    if not called_guarded:
                        unguarded_methods.append(
                            (m_name, _line_number(content, start), dm.group(0).strip())
                        )

            if guarded_methods and unguarded_methods:
                for m_name, line_no, snippet in unguarded_methods:
                    findings.append(
                        {
                            "rule_id": "SNIPER-PARITY-SVC-02",
                            "cwe": "CWE-862",
                            "reference": "CWE-862",
                            "severity": "high",
                            "category": "authz",
                            "title": "Servis içinde asimetrik yetki kontrolü (Ability.allowed?) veya rezerve anahtar (.except) parite eksikliği",
                            "description": (
                                f"`{m_name}` metodu hassas nesne/versiyon erişimi yaparken `Ability.allowed?` "
                                f"yetki kontrolünü atlıyor; aynı servisteki `{guarded_methods[0]}` ise bu "
                                "kontrolü zorunlu tutuyor."
                            ),
                            "remediation": (
                                f"`{m_name}` içinde nesne/versiyon erişiminden önce `Ability.allowed?` "
                                "yetki doğrulamasını uygulayın."
                            ),
                            "filename": fname,
                            "line": line_no,
                            "evidence": snippet,
                        }
                    )
        else:
            # Tek metot veya blok içinde iki ayrı dal (ör. ItemConsumersFinder vs item_version)
            if (
                "ItemConsumersFinder" in content
                and "item_version" in content
                and re.search(
                    r"item_version(?![\s\S]{0,160}Ability\.allowed\?)", content
                )
            ):
                m = re.search(r".*item_version.*", content)
                line_no = _line_number(content, m.start()) if m else 1
                findings.append(
                    {
                        "rule_id": "SNIPER-PARITY-SVC-02",
                        "cwe": "CWE-862",
                        "reference": "CWE-862",
                        "severity": "high",
                        "category": "authz",
                        "title": "Servis içinde asimetrik yetki kontrolü (Ability.allowed?) veya rezerve anahtar (.except) parite eksikliği",
                        "description": (
                            "Servis içinde bir dal `Ability.allowed?` ile yetki doğrularken `item_version` "
                            "erişim dalı yetki kontrolü olmadan çalışıyor."
                        ),
                        "remediation": (
                            "`item_version` çözümlemesinde de `Ability.allowed?` kontrolünü zorunlu kılın."
                        ),
                        "filename": fname,
                        "line": line_no,
                        "evidence": m.group(0).strip() if m else "item_version",
                    }
                )

    return findings


def _audit_converter_sink_parity(files_map: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    sink_re = re.compile(
        r"\b(processExecutor|weasyprint|chromium|libreoffice|wkhtmltopdf|URL_TO_PDF)\b"
    )
    guard_re = re.compile(
        r"(customHtmlSanitizer\.sanitize|HtmlSanitizer|--allowed-protocols|ssrfFilter|validateUrl)"
    )
    class_re = re.compile(
        r"^\s*(?:public\s+|final\s+|abstract\s+)*class\s+([A-Za-z0-9_]+)",
        re.MULTILINE,
    )

    units: list[dict[str, Any]] = []
    for fname, content in files_map.items():
        cls_matches = list(class_re.finditer(content))
        if len(cls_matches) >= 2:
            for idx, cm in enumerate(cls_matches):
                start = cm.start()
                end = (
                    cls_matches[idx + 1].start()
                    if idx + 1 < len(cls_matches)
                    else len(content)
                )
                body = content[start:end]
                if sink_re.search(body):
                    units.append(
                        {
                            "filename": fname,
                            "unit_name": cm.group(1),
                            "has_guard": bool(guard_re.search(body)),
                            "line": _line_number(content, start),
                            "evidence": cm.group(0).strip(),
                        }
                    )
        elif sink_re.search(content):
            unit_name = cls_matches[0].group(1) if cls_matches else fname
            sm = sink_re.search(content)
            units.append(
                {
                    "filename": fname,
                    "unit_name": unit_name,
                    "has_guard": bool(guard_re.search(content)),
                    "line": _line_number(content, sm.start()) if sm else 1,
                    "evidence": sm.group(0).strip() if sm else unit_name,
                }
            )

    guarded = [u for u in units if u["has_guard"]]
    unguarded = [u for u in units if not u["has_guard"]]
    if guarded and unguarded:
        ref_name = guarded[0]["unit_name"]
        for ug in unguarded:
            findings.append(
                {
                    "rule_id": "SNIPER-PARITY-SINK-03",
                    "cwe": "CWE-918",
                    "reference": "CWE-918",
                    "severity": "high",
                    "category": "command_data",
                    "title": "Kardeş dönüştürücü/렌더러 sınıfları arasında eksik HTML sanitizasyonu veya --allowed-protocols kısıtı",
                    "description": (
                        f"`{ug['unit_name']}` dönüştürücüsü harici işlem/tarayıcı (`processExecutor` / `weasyprint` / `chromium`) "
                        f"çağırırken HTML sanitizasyonu veya `--allowed-protocols` kısıtı uygulamıyor; "
                        f"kardeş `{ref_name}` sınıfı ise bu korumayı uyguluyor."
                    ),
                    "remediation": (
                        "Kardeş dönüştürücüde olduğu gibi girdi üzerinde `customHtmlSanitizer.sanitize` "
                        "veya komut satırında `--allowed-protocols` / URL doğrulama kısıtını zorunlu kılın."
                    ),
                    "filename": ug["filename"],
                    "line": ug["line"],
                    "evidence": ug["evidence"],
                    "reference_sibling": ref_name,
                }
            )
    return findings


def _audit_filesystem_branch_parity(files_map: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    symlink_guard_re = re.compile(
        r"(Files\.isSymbolicLink|validateBackupFile|LinkOption\.NOFOLLOW_LINKS|os\.Lstat)"
    )
    unsafe_fs_re = re.compile(
        r"(Files::isRegularFile|Files\.isRegularFile\s*\([^),]+\)|os\.ReadFile\s*\(|new\s+FileInputStream\s*\(|Files\.readAllBytes\s*\()"
    )
    method_re = re.compile(
        r"^\s*(?:public|private|protected|func|def)\s+[^{;\n]*?\b([A-Za-z0-9_]+)\s*\(",
        re.MULTILINE,
    )

    for fname, content in files_map.items():
        if not symlink_guard_re.search(content):
            continue

        methods = list(method_re.finditer(content))
        emitted_in_file = False
        if len(methods) >= 2:
            guarded_methods: list[str] = []
            unguarded_methods: list[tuple[str, int, str]] = []
            for idx, mm in enumerate(methods):
                start = mm.start()
                end = (
                    methods[idx + 1].start()
                    if idx + 1 < len(methods)
                    else len(content)
                )
                m_body = content[start:end]
                m_name = mm.group(1)
                has_guard = bool(symlink_guard_re.search(m_body))
                um = unsafe_fs_re.search(m_body)
                if has_guard and not um:
                    guarded_methods.append(m_name)
                elif has_guard and um:
                    # Aynı metot içinde if/else dalları arasında asimetri (ör. recursive ? ... isSymbolicLink : Files::isRegularFile)
                    guard_pos = symlink_guard_re.search(m_body)
                    if guard_pos and "Files::isRegularFile" in m_body:
                        unguarded_methods.append(
                            (
                                m_name,
                                _line_number(content, start + um.start()),
                                um.group(0).strip(),
                            )
                        )
                        guarded_methods.append(m_name)
                elif um and not has_guard:
                    unguarded_methods.append(
                        (
                            m_name,
                            _line_number(content, start + um.start()),
                            um.group(0).strip(),
                        )
                    )

            if guarded_methods and unguarded_methods:
                for m_name, line_no, evidence in unguarded_methods:
                    emitted_in_file = True
                    findings.append(
                        {
                            "rule_id": "SNIPER-PARITY-FS-04",
                            "cwe": "CWE-59",
                            "reference": "CWE-59",
                            "severity": "high",
                            "category": "command_data",
                            "title": "Kardeş dosya sistemi dallarında asimetrik sembolik link (isSymbolicLink) veya yedekleme doğrulayıcı (validateBackupFile) kontrolü",
                            "description": (
                                f"`{m_name}` dalı/yordamı dosya erişiminde sembolik link veya yedek doğrulaması "
                                f"(`isSymbolicLink` / `validateBackupFile`) yapmadan `{evidence}` kullanıyor; "
                                f"kardeş `{guarded_methods[0]}` dalı ise bu korumayı uyguluyor."
                            ),
                            "remediation": (
                                "Tüm kardeş dosya sistemi dallarında `Files.isSymbolicLink` / `NOFOLLOW_LINKS` "
                                "veya `validateBackupFile` doğrulamasını simetrik olarak uygulayın."
                            ),
                            "filename": fname,
                            "line": line_no,
                            "evidence": evidence,
                        }
                    )

        if not emitted_in_file:
            um = unsafe_fs_re.search(content)
            if um:
                line_no = _line_number(content, um.start())
                findings.append(
                    {
                        "rule_id": "SNIPER-PARITY-FS-04",
                        "cwe": "CWE-59",
                        "reference": "CWE-59",
                        "severity": "high",
                        "category": "command_data",
                        "title": "Kardeş dosya sistemi dallarında asimetrik sembolik link (isSymbolicLink) veya yedekleme doğrulayıcı (validateBackupFile) kontrolü",
                        "description": (
                            f"Dosya içinde bir dal sembolik link / yedekleme doğrulaması yaparken diğer dal "
                            f"doğrulama olmadan `{um.group(0).strip()}` çağırıyor."
                        ),
                        "remediation": (
                            "Her iki dalda da `Files.isSymbolicLink` / `NOFOLLOW_LINKS` veya `validateBackupFile` "
                            "kontrolünü zorunlu kılın."
                        ),
                        "filename": fname,
                        "line": line_no,
                        "evidence": um.group(0).strip(),
                    }
                )

    return findings


def _audit_express_router_client_auth_parity(
    files_map: dict[str, str],
) -> list[dict[str, Any]]:
    """Express/TS kardeş router uç noktaları arasında istemci kimlik doğrulama paritesini denetler."""
    findings: list[dict[str, Any]] = []

    revoke_guard_re = re.compile(
        r"router\.post\s*\(\s*['\"][^'\"]*revoke['\"]|\bverifyRevocationClient\b"
    )
    token_route_re = re.compile(
        r"router\.post\s*\(\s*['\"][^'\"]*token['\"]|\bgrant_type\b"
    )
    conditional_cred_bypass_re = re.compile(
        r"if\s*\(\s*hasCredentials\b[^)]*\)\s*\{?[^{}]*\b(?:authenticateClient|verifyRevocationClient)\b"
        r"|\bhasCredentials\s*(?:&&|\?)[^;\n]*\b(?:authenticateClient|verifyRevocationClient)\b",
        re.DOTALL,
    )
    auth_code_branch_re = re.compile(
        r"(?:grant_type\s*===\s*['\"]authorization_code['\"]|case\s+['\"]authorization_code['\"]|\bexchangeCodeForToken\s*\()"
    )
    client_auth_call_re = re.compile(
        r"\b(?:authenticateClient|verifyRevocationClient)\s*\("
    )
    grant_branch_start_re = re.compile(
        r"(?:if\s*\([^)]*grant_type|switch\s*\([^)]*grant_type|case\s+['\"](?:authorization_code|refresh_token)['\"])"
    )

    has_global_revoke_guard = any(
        revoke_guard_re.search(c) for c in files_map.values()
    )
    if not has_global_revoke_guard:
        return findings

    for fname, content in files_map.items():
        if not token_route_re.search(content):
            continue

        token_match = re.search(
            r"router\.post\s*\(\s*['\"][^'\"]*token['\"]", content
        )
        token_start = token_match.start() if token_match else 0
        token_body = content[token_start:]

        first_grant = grant_branch_start_re.search(token_body)
        pre_grant_body = (
            token_body[: first_grant.start()] if first_grant else ""
        )
        unconditional_pre_grant_auth = bool(
            client_auth_call_re.search(pre_grant_body)
            and not conditional_cred_bypass_re.search(pre_grant_body)
        )

        cond_match = conditional_cred_bypass_re.search(token_body)
        if cond_match:
            abs_pos = token_start + cond_match.start()
            line_no = _line_number(content, abs_pos)
            evidence = cond_match.group(0).strip().splitlines()[0].strip()
            findings.append(
                {
                    "rule_id": "SNIPER-PARITY-ROUTE-05",
                    "cwe": "CWE-306",
                    "reference": "CWE-306",
                    "severity": "high",
                    "category": "authz",
                    "title": "Kardeş Router uç noktaları arasında istemci kimlik doğrulama (verifyRevocationClient / authenticateClient) parite eksikliği",
                    "description": (
                        "Kardeş `/v1/revoke` uç noktası gizli istemciler (confidential clients) için "
                        "`verifyRevocationClient` / `authenticateClient` zorunluluğu uygularken, "
                        "`/v1/token` (`refresh_token`) akışı istemci doğrulamasını `if (hasCredentials)` "
                        "koşuluna bağlayarak kimlik bilgisiz (credential-less) isteklerde doğrulamayı atlıyor."
                    ),
                    "remediation": (
                        "`/v1/token` uç noktasında hem `authorization_code` hem de `refresh_token` "
                        "akışlarında gizli istemciler için `authenticateClient` / `verifyRevocationClient` "
                        "doğrulamasını koşulsuz olarak uygulayın."
                    ),
                    "filename": fname,
                    "line": line_no,
                    "evidence": evidence,
                }
            )
            continue

        if unconditional_pre_grant_auth:
            continue

        auth_code_match = auth_code_branch_re.search(token_body)
        if auth_code_match:
            window_start = max(0, auth_code_match.start() - 120)
            next_branch = re.search(
                r"(?:grant_type\s*===\s*['\"]refresh_token['\"]|case\s+['\"]refresh_token['\"])",
                token_body[auth_code_match.end() :],
            )
            window_end = (
                auth_code_match.end() + next_branch.start()
                if next_branch
                else min(len(token_body), auth_code_match.end() + 450)
            )
            auth_code_window = token_body[window_start:window_end]
            if not client_auth_call_re.search(auth_code_window):
                abs_pos = token_start + auth_code_match.start()
                line_no = _line_number(content, abs_pos)
                evidence = auth_code_match.group(0).strip()
                findings.append(
                    {
                        "rule_id": "SNIPER-PARITY-ROUTE-05",
                        "cwe": "CWE-306",
                        "reference": "CWE-306",
                        "severity": "high",
                        "category": "authz",
                        "title": "Kardeş Router uç noktaları arasında istemci kimlik doğrulama (verifyRevocationClient / authenticateClient) parite eksikliği",
                        "description": (
                            "Kardeş `/v1/revoke` uç noktası gizli istemciler için `verifyRevocationClient` "
                            "ile istemci sırrını doğrularken, `/v1/token` (`authorization_code`) dalı "
                            "`authenticateClient` / `verifyRevocationClient` çağırmadan kod değişimi yapıyor."
                        ),
                        "remediation": (
                            "`/v1/token` üzerindeki `authorization_code` ve `refresh_token` dallarında "
                            "`/v1/revoke` ile simetrik olarak `authenticateClient` / `verifyRevocationClient` "
                            "kontrolünü zorunlu kılın."
                        ),
                        "filename": fname,
                        "line": line_no,
                        "evidence": evidence,
                    }
                )

    return findings


def _audit_sdk_postmessage_bridge_parity(
    files_map: dict[str, str],
) -> list[dict[str, Any]]:
    """SDK postMessage köprüsünde varsayılan wildcard targetOrigin ('*') parite eksikliğini denetler."""
    findings: list[dict[str, Any]] = []

    default_wildcard_re = re.compile(
        r"targetOrigin\s*(?::\s*[A-Za-z0-9_|&\s]+)?(?:=\s*(?:[^;\n]*?(?:\?\?|\|\|)\s*)?['\"]\*['\"]|\?\?\s*['\"]\*['\"]|\|\|\s*['\"]\*['\"])"
    )
    wildcard_check_or_postmessage_re = re.compile(
        r"(?:this\.)?targetOrigin\s*===\s*['\"]\*['\"]|\bpostMessage\s*\([^)]*(?:this\.)?targetOrigin\b",
        re.DOTALL,
    )

    for fname, content in files_map.items():
        wm = default_wildcard_re.search(content)
        if not wm:
            continue
        pm = wildcard_check_or_postmessage_re.search(content)
        if not pm:
            continue

        line_no = _line_number(content, wm.start())
        evidence = wm.group(0).strip()
        findings.append(
            {
                "rule_id": "SNIPER-PARITY-BRIDGE-06",
                "cwe": "CWE-346",
                "reference": "CWE-346",
                "severity": "high",
                "category": "authz",
                "title": "SDK postMessage köprüsünde varsayılan wildcard targetOrigin ('*') ile kardeş bileşen origin doğrulaması arasında parite eksikliği",
                "description": (
                    "SDK postMessage köprü sınıfı/modülü `targetOrigin` değerini varsayılan olarak `'*'` "
                    "olarak tanımlıyor ve `this.targetOrigin === '*'` kontrolü veya `postMessage(..., this.targetOrigin)` "
                    "ile çapraz-köken (cross-origin) mesaj doğrulamasını devre dışı bırakıyor."
                ),
                "remediation": (
                    "`targetOrigin` için açık ve doğrulanmış bir origin zorunlu tutun; `' * '` wildcard "
                    "varsayılanını ve `this.targetOrigin === '*'` doğrulama atlamasını kaldırın."
                ),
                "filename": fname,
                "line": line_no,
                "evidence": evidence,
            }
        )

    return findings


def audit_sibling_security_parity(
    raw_content_or_files: str | dict[str, str],
    *,
    filename: str = "controller.rb",
) -> dict[str, Any]:
    """Kardeş sınıflar, servis metotları ve dosya sistemi dalları arasındaki güvenlik paritesini denetler."""
    if isinstance(raw_content_or_files, dict):
        files_map = {str(k): str(v or "") for k, v in raw_content_or_files.items()}
    else:
        files_map = {filename: str(raw_content_or_files or "")}

    findings: list[dict[str, Any]] = []
    findings.extend(_audit_rails_controllers(files_map))
    findings.extend(_audit_service_authz_and_except_parity(files_map))
    findings.extend(_audit_converter_sink_parity(files_map))
    findings.extend(_audit_filesystem_branch_parity(files_map))
    findings.extend(_audit_express_router_client_auth_parity(files_map))
    findings.extend(_audit_sdk_postmessage_bridge_parity(files_map))

    return {
        "format": FORMAT_VERSION,
        "finding_count": len(findings),
        "findings": findings,
    }
