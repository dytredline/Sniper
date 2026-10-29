"""Automated Scan, Project Audit, Dependency & Tool Evidence -> OWASP WSTG 161 Controls Bridge."""

from __future__ import annotations

from typing import Any


def _is_false_positive(finding: dict[str, Any]) -> bool:
    triage = finding.get("triage")
    if isinstance(triage, dict) and str(triage.get("disposition") or "").strip().lower() == "false_positive":
        return True
    tracking = finding.get("tracking")
    if isinstance(tracking, dict) and str(tracking.get("status") or "").strip().lower() == "false_positive":
        return True
    if str(finding.get("disposition") or "").strip().lower() == "false_positive":
        return True
    if str(finding.get("status") or "").strip().lower() == "false_positive":
        return True
    return False


def _finding_cwe_ref(finding: dict[str, Any]) -> str:
    parts = [str(finding.get("reference", "")), str(finding.get("cwe", "")), str(finding.get("cwe_id", ""))]
    for raw_cwe in (finding.get("cwe"), finding.get("cwe_id")):
        text = str(raw_cwe or "").strip()
        if text.isdigit():
            parts.append(f"CWE-{int(text)}")
    return " ".join(parts)


def _scan_matches(
    scan_findings: list[dict[str, Any]],
    *,
    categories: set[str] | tuple[str, ...] = (),
    titles: set[str] | tuple[str, ...] = (),
    title_substrings: tuple[str, ...] = (),
    cwes: set[str] | tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    cat_set = set(categories)
    title_set = set(titles)
    cwe_set = set(cwes)
    matched: list[dict[str, Any]] = []
    for finding in scan_findings:
        cat = str(finding.get("category", "")).strip()
        title = str(finding.get("title", "")).strip()
        ref = _finding_cwe_ref(finding)
        if (
            (cat_set and cat in cat_set)
            or (title_set and title in title_set)
            or (title_substrings and any(sub in title for sub in title_substrings))
            or (cwe_set and any(cwe in ref for cwe in cwe_set))
        ):
            matched.append(finding)
    return matched


def _audit_matches(
    audit_findings: list[dict[str, Any]],
    *,
    categories: set[str] | tuple[str, ...] = (),
    titles: set[str] | tuple[str, ...] = (),
    title_substrings: tuple[str, ...] = (),
    cwes: set[str] | tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    cat_set = set(categories)
    title_set = set(titles)
    cwe_set = set(cwes)
    matched: list[dict[str, Any]] = []
    for finding in audit_findings:
        cat = str(finding.get("category", "")).strip()
        title = str(finding.get("title", "")).strip()
        ref = _finding_cwe_ref(finding)
        if (
            (cat_set and cat in cat_set)
            or (title_set and title in title_set)
            or (title_substrings and any(sub in title for sub in title_substrings))
            or (cwe_set and any(cwe in ref for cwe in cwe_set))
        ):
            matched.append(finding)
    return matched


def _format_scan_evidence(scan_id: str, matched: list[dict[str, Any]], clean_desc: str) -> tuple[str, str]:
    if matched:
        titles = ", ".join(sorted({str(f.get("title", "")) for f in matched if f.get("title")}))
        ev_parts = [
            f"{f.get('title', 'Bulgu')}: {str(f.get('evidence', '')).strip()[:160]}"
            for f in matched[:4]
        ]
        note = f"Otomatik web taraması ({scan_id}) bulgu tespit etti: {titles[:280]}"
        evidence = " | ".join(ev_parts)[:1000]
        return note, evidence
    return (
        f"Otomatik web taraması ({scan_id}) kapsamında {clean_desc} doğrulandı; olumsuz bulgu gözlenmedi.",
        f"Tarama kimliği: {scan_id} · durum: temiz",
    )


def _format_audit_evidence(audit_id: str, matched: list[dict[str, Any]], clean_desc: str) -> tuple[str, str]:
    if matched:
        titles = ", ".join(sorted({str(f.get("title", "")) for f in matched if f.get("title")}))
        ev_parts = [
            f"{f.get('file', 'Proje')}:{f.get('line', 0)} ({f.get('title', 'Bulgu')} · {f.get('reference', '')})"
            for f in matched[:4]
        ]
        note = f"Proje kaynak kodu denetimi ({audit_id}) bulgu tespit etti: {titles[:280]}"
        evidence = " | ".join(ev_parts)[:1000]
        return note, evidence
    return (
        f"Proje kaynak kodu denetimi ({audit_id}) kapsamında {clean_desc} incelendi; olumsuz sinyal bulunmadı.",
        f"Proje denetimi kimliği: {audit_id} · durum: temiz",
    )


def synchronize_engagement_auto_evidence(
    store: Any,
    engagement_id: str,
    *,
    project_audit_id: str | None = None,
    overwrite_manual: bool = False,
    openapi_audit: dict[str, Any] | None = None,
    dns_email_audit: dict[str, Any] | None = None,
    discovery_audit: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Synchronize automated scan, project audit, tool evidence, and dependency findings to WSTG controls."""
    engagement = store.get_engagement(engagement_id)
    if engagement is None:
        raise ValueError("Manuel denetim bulunamadı.")

    latest_scan = engagement.get("latest_scan")
    has_scan = isinstance(latest_scan, dict)
    scan_findings: list[dict[str, Any]] = [
        f
        for f in (latest_scan.get("findings", []) if has_scan else [])
        if isinstance(f, dict) and not _is_false_positive(f)
    ]
    scan_id = str(latest_scan.get("id") or "latest_scan") if has_scan else ""

    project_audit: dict[str, Any] | None = None
    if project_audit_id:
        if project_audit_id == "latest":
            audits = store.list_project_audits(limit=1) if hasattr(store, "list_project_audits") else []
            if audits:
                project_audit = store.get_project_audit(audits[0]["id"]) or audits[0]
        elif project_audit_id != "none":
            project_audit = store.get_project_audit(project_audit_id)
            if project_audit is None:
                raise ValueError("Proje denetimi bulunamadı.")
    elif hasattr(store, "list_project_audits"):
        audits = store.list_project_audits(limit=1)
        if audits:
            project_audit = store.get_project_audit(audits[0]["id"]) or audits[0]

    has_audit = isinstance(project_audit, dict)
    audit_findings: list[dict[str, Any]] = [
        f
        for f in (project_audit.get("findings", []) if has_audit else [])
        if isinstance(f, dict) and not _is_false_positive(f)
    ]
    audit_id = str(project_audit.get("id") or "project_audit") if has_audit else ""

    if openapi_audit is None and has_audit and project_audit.get("project_path"):
        try:
            from openapi_contract_auditor import audit_project_api_contracts

            cand_oa = audit_project_api_contracts(str(project_audit["project_path"]))
            if isinstance(cand_oa, dict) and int(
                cand_oa.get("contracts_audited", cand_oa.get("contract_count", 0)) or 0
            ) > 0:
                openapi_audit = cand_oa
        except Exception:
            pass

    tool_evidence: list[dict[str, Any]] = [
        item for item in (engagement.get("tool_evidence") or []) if isinstance(item, dict)
    ]
    gitleaks_evidence = [
        item
        for item in tool_evidence
        if any(k in str(item.get("tool_identity", "")).lower() for k in ("gitleaks", "trufflehog"))
    ]
    gitleaks_finding_count = sum(
        int(item.get("total_findings", item.get("finding_count", 0)) or 0)
        for item in gitleaks_evidence
    )
    nmap_evidence = [
        item for item in tool_evidence if "nmap" in str(item.get("tool_identity", "")).lower()
    ]
    testssl_evidence = [
        item
        for item in tool_evidence
        if any(k in str(item.get("tool_identity", "")).lower() for k in ("testssl", "ssllabs", "openssl"))
    ]
    trivy_evidence = [
        item for item in tool_evidence if "trivy" in str(item.get("tool_identity", "")).lower()
    ]

    dep_sec = store.dependency_security() if hasattr(store, "dependency_security") else {}
    if not isinstance(dep_sec, dict):
        dep_sec = {}
    active_statuses = {"open", "in_progress", "retest_required", "reopened"}
    dep_findings = [
        f for f in (dep_sec.get("findings") or [])
        if isinstance(f, dict) and f.get("status", "open") in active_statuses
    ]
    dep_summary = dep_sec.get("summary") if isinstance(dep_sec.get("summary"), dict) else {}
    dep_active_count = max(len(dep_findings), int(dep_summary.get("active", 0) or 0))
    has_dep_reports = bool(
        dep_sec.get("imports")
        or dep_sec.get("sboms")
        or int(dep_summary.get("total", 0) or 0) > 0
    )

    evaluated: dict[str, tuple[str, str, str]] = {}
    status_priority = {"failed": 3, "needs_review": 2, "passed": 1}

    def record(control_id: str, status: str, notes: str, evidence: str) -> None:
        existing = evaluated.get(control_id)
        if existing is not None:
            if status_priority.get(status, 0) < status_priority.get(existing[0], 0):
                return
        evaluated[control_id] = (status, notes, evidence)

    # 1. Information Gathering (SNIPER-INFO-*)
    if has_scan:
        m = _scan_matches(
            scan_findings,
            categories=("disclosure",),
            title_substrings=("robots.txt", "bilgi", "ifşa"),
        )
        note, ev = _format_scan_evidence(scan_id, m, "harici bilgi sızıntısı ve arama motoru indeksleme")
        record("SNIPER-INFO-01", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, titles=("Sunucu teknolojisi ayrıntısı açığa çıkıyor",))
        note, ev = _format_scan_evidence(scan_id, m, "sunucu parmak izi ve üstbilgi ifşası")
        record("SNIPER-INFO-02", "failed" if m else "passed", note, ev)

        m = _scan_matches(
            scan_findings,
            categories=("disclosure",),
            titles=(
                "security.txt bulunamadı",
                "security.txt iletişim alanı eksik",
                "security.txt süre sonu alanı eksik",
            ),
            title_substrings=("robots.txt", "security.txt"),
        )
        note, ev = _format_scan_evidence(scan_id, m, "web meta dosyaları (security.txt / robots.txt)")
        record("SNIPER-INFO-03", "failed" if m else "passed", note, ev)

        note, ev = _format_scan_evidence(scan_id, [], "uygulama ve hedef URL envanteri")
        record("SNIPER-INFO-04", "passed", note, ev)

        m = _scan_matches(
            scan_findings,
            titles=(
                "Üretim sayfasında kaynak haritası referansı var",
                "İstemci yanıtında olası sır deseni bulundu",
            ),
        )
        note, ev = _format_scan_evidence(scan_id, m, "sayfa içeriği ve kaynak haritası sızıntısı")
        record("SNIPER-INFO-05", "failed" if m else "passed", note, ev)

        note, ev = _format_scan_evidence(scan_id, [], "HTTP giriş noktaları ve form yüzeyi")
        record("SNIPER-INFO-06", "passed", note, ev)

    if has_scan or has_audit:
        if has_audit:
            note, ev = _format_audit_evidence(audit_id, [], "teknoloji, dil ve mimari bileşen haritalama")
        else:
            note, ev = _format_scan_evidence(scan_id, [], "teknoloji ve mimari haritalama")
        record("SNIPER-INFO-08", "passed", note, ev)

    # 2. Configuration (SNIPER-CONF-*)
    if has_audit:
        m = _audit_matches(
            audit_findings,
            categories=("iac", "container", "ports"),
            cwes=("CWE-250", "CWE-284"),
            title_substrings=("host_network", "privileged", "0.0.0.0"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "ağ ve altyapı yapılandırma sertleştirmesi")
        record("SNIPER-CONF-01", "failed" if m else "passed", note, ev)

        m = _audit_matches(
            audit_findings,
            categories=("configuration", "framework"),
            title_substrings=("debug", "DEBUG", "werkzeug", "trace"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "uygulama platformu yapılandırma incelemesi")
        record("SNIPER-CONF-02", "failed" if m else "passed", note, ev)

        m = _audit_matches(
            audit_findings,
            categories=("secret_file",),
            title_substrings=(".env", ".pem", ".key", "gizli dosya"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "dosya uzantıları ve hassas dosya işleme")
        record("SNIPER-CONF-03", "failed" if m else "passed", note, ev)

        m = _audit_matches(
            audit_findings,
            title_substrings=(".bak", ".old", "backup", "yedek"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "eski, yedek ve referanssız dosyaların kontrolü")
        record("SNIPER-CONF-04", "failed" if m else "passed", note, ev)

        m = _audit_matches(
            audit_findings,
            categories=("ports",),
            title_substrings=("0.0.0.0", "2375", "9200", "admin"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "yönetim arayüzlerinin ve özel uçların tespiti")
        record("SNIPER-CONF-05", "failed" if m else "passed", note, ev)

        m = _audit_matches(
            audit_findings,
            categories=("container", "iac", "kubernetes"),
            cwes=("CWE-250",),
        )
        note, ev = _format_audit_evidence(audit_id, m, "bulut depolama ve konteyner izinleri")
        record("SNIPER-CONF-09", "failed" if m else "passed", note, ev)

    if has_scan:
        m = _scan_matches(scan_findings, categories=("configuration",), title_substrings=("HTTP", "yöntem", "TRACE"))
        note, ev = _format_scan_evidence(scan_id, m, "HTTP yöntemleri ve durum kodları")
        record("SNIPER-CONF-06", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, categories=("headers", "privacy"))
        note, ev = _format_scan_evidence(scan_id, m, "HTTP güvenlik ve mahremiyet başlıkları")
        record("SNIPER-CONF-07", "failed" if m else "passed", note, ev)

    # 3. Identity (SNIPER-IDNT-*)
    if has_audit:
        m = _audit_matches(audit_findings, categories=("authorization", "identity"), cwes=("CWE-862", "CWE-285"))
        note, ev = _format_audit_evidence(audit_id, m, "rol tanımlarının ve yetki matrisinin incelenmesi")
        record("SNIPER-IDNT-01", "failed" if m else "passed", note, ev)

    if has_scan or has_audit:
        m_scan = _scan_matches(scan_findings, categories=("identity",), cwes=("CWE-204",))
        m_aud = _audit_matches(audit_findings, categories=("identity",), cwes=("CWE-204",))
        if m_scan or m_aud:
            note, ev = (
                _format_scan_evidence(scan_id, m_scan, "hesap numaralandırma")
                if m_scan
                else _format_audit_evidence(audit_id, m_aud, "hesap numaralandırma")
            )
            record("SNIPER-IDNT-04", "failed", note, ev)
        elif has_scan:
            pwd_forms = int(
                latest_scan.get("password_form_count", (latest_scan.get("metadata") or {}).get("password_form_count", 0))
                or 0
            )
            if pwd_forms > 0:
                record(
                    "SNIPER-IDNT-04",
                    "needs_review",
                    f"Otomatik taramada ({scan_id}) giriş formu tespit edildi; hesap numaralandırma tepkileri uzman incelemesi gerektiriyor.",
                    f"Tarama kimliği: {scan_id} · password_form_count={pwd_forms}",
                )
            else:
                note, ev = _format_scan_evidence(scan_id, [], "hesap numaralandırma yüzeyi")
                record("SNIPER-IDNT-04", "passed", note, ev)

    # 4. Authentication (SNIPER-AUTH-*)
    if has_scan:
        m = _scan_matches(
            scan_findings,
            titles=(
                "Parola formu güvenli olmayan adrese gönderiliyor",
                "Parola formu GET yöntemi kullanıyor",
            ),
        )
        note, ev = _format_scan_evidence(scan_id, m, "şifreli kimlik bilgisi taşıma")
        record("SNIPER-AUTH-01", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, titles=("Kimlik doğrulama sayfasında no-store yok",))
        note, ev = _format_scan_evidence(scan_id, m, "kimlik doğrulama önbellek politikası")
        record("SNIPER-AUTH-06", "failed" if m else "passed", note, ev)

    if has_audit:
        m = _audit_matches(
            audit_findings,
            categories=("secrets",),
            cwes=("CWE-798",),
            title_substrings=("parola", "password", "varsayılan", "kimlik"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "varsayılan veya sabit kodlu kimlik bilgileri")
        record("SNIPER-AUTH-02", "failed" if m else "passed", note, ev)

        m = _audit_matches(
            audit_findings,
            cwes=("CWE-916",),
            title_substrings=("KDF", "parola", "pbkdf2", "bcrypt", "argon2"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "parola karmaşıklığı ve saklama politikası")
        record("SNIPER-AUTH-07", "failed" if m else "passed", note, ev)

    # 5. Authorization (SNIPER-ATHZ-*)
    if has_scan or has_audit:
        m_scan = _scan_matches(scan_findings, categories=("authorization",))
        m_aud = _audit_matches(audit_findings, categories=("authorization",), cwes=("CWE-862", "CWE-863", "CWE-285"))
        if m_scan or m_aud:
            note, ev = (
                _format_scan_evidence(scan_id, m_scan, "dizin ve dosya yetkisi")
                if m_scan
                else _format_audit_evidence(audit_id, m_aud, "dizin ve dosya yetkisi")
            )
            record("SNIPER-ATHZ-01", "failed", note, ev)
        elif has_scan:
            note, ev = _format_scan_evidence(scan_id, [], "dizin ve dosya yetki sınırları")
            record("SNIPER-ATHZ-01", "passed", note, ev)
        elif has_audit:
            note, ev = _format_audit_evidence(audit_id, [], "dizin ve dosya yetki sınırları")
            record("SNIPER-ATHZ-01", "passed", note, ev)

    if has_audit:
        m = _audit_matches(
            audit_findings,
            cwes=("CWE-250", "CWE-269"),
            title_substrings=("privileged", "root", "yetki yükseltme", "CAP_SYS_ADMIN"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "yetki yükseltme ve rol atlama kontrolleri")
        record("SNIPER-ATHZ-02", "failed" if m else "passed", note, ev)

    # 6. Session Management (SNIPER-SESS-*)
    if has_audit:
        m = _audit_matches(audit_findings, cwes=("CWE-338", "CWE-330"), title_substrings=("PRNG", "random", "token"))
        note, ev = _format_audit_evidence(audit_id, m, "oturum belirteci üretim ve entropi şeması")
        record("SNIPER-SESS-01", "failed" if m else "passed", note, ev)

    if has_scan:
        m = _scan_matches(scan_findings, categories=("session",))
        note, ev = _format_scan_evidence(scan_id, m, "oturum çerez nitelikleri (Secure/HttpOnly/SameSite)")
        record("SNIPER-SESS-02", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, categories=("session",), title_substrings=("HttpOnly", "çerez", "cookie"))
        note, ev = _format_scan_evidence(scan_id, m, "istemci tarafı oturum verisi sızıntısı")
        record("SNIPER-SESS-04", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, categories=("session",), title_substrings=("SameSite", "CSRF"))
        note, ev = _format_scan_evidence(scan_id, m, "siteler arası istek sahteciliği (CSRF) çerez savunması")
        record("SNIPER-SESS-05", "failed" if m else "passed", note, ev)

    # 7. Input Validation (SNIPER-INPV-*)
    if has_scan or has_audit:
        m_scan = _scan_matches(scan_findings, title_substrings=("Content-Security-Policy", "CSP", "XSS"))
        m_aud = _audit_matches(audit_findings, cwes=("CWE-79",))
        if m_scan:
            note, ev = _format_scan_evidence(scan_id, m_scan, "yansıtılmış betik enjeksiyonu (XSS) ve CSP yüzeyi")
            record("SNIPER-INPV-01", "failed", note, ev)
        elif m_aud:
            note, ev = _format_audit_evidence(audit_id, m_aud, "betik enjeksiyonu (XSS) yüzeyi")
            record("SNIPER-INPV-01", "failed", note, ev)
        elif has_scan:
            note, ev = _format_scan_evidence(scan_id, [], "yansıtılmış betik enjeksiyonu (XSS) ve CSP yüzeyi")
            record("SNIPER-INPV-01", "passed", note, ev)
        elif has_audit:
            note, ev = _format_audit_evidence(audit_id, [], "betik enjeksiyonu (XSS) yüzeyi")
            record("SNIPER-INPV-01", "passed", note, ev)

    if has_audit:
        m = _audit_matches(
            audit_findings,
            cwes=("CWE-79",),
            title_substrings=("innerHTML", "dangerouslySetInnerHTML", "mark_safe", "v-html"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "kalıcı betik enjeksiyonu ve içerik temizleme")
        record("SNIPER-INPV-02", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, categories=("data_query",), cwes=("CWE-89", "CWE-943"))
        note, ev = _format_audit_evidence(audit_id, m, "veri tabanı sorgu parametreleştirme")
        record("SNIPER-INPV-05", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-611",))
        note, ev = _format_audit_evidence(audit_id, m, "XML ve XPath dış varlık (XXE) güvenliği")
        record("SNIPER-INPV-06", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, categories=("command_data",), cwes=("CWE-78", "CWE-95"))
        note, ev = _format_audit_evidence(audit_id, m, "sunucu tarafı kod ve işletim sistemi komut işleme")
        record("SNIPER-INPV-07", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, categories=("ssrf",), cwes=("CWE-918",))
        note, ev = _format_audit_evidence(audit_id, m, "sunucu tarafı istek tetikleme (SSRF) girdi doğrulaması")
        record("SNIPER-INPV-08", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-22", "CWE-434"), title_substrings=("extractall", "upload", "dosya"))
        note, ev = _format_audit_evidence(audit_id, m, "dosya yükleme ve arşiv doğrulama kontrolleri")
        record("SNIPER-INPV-10", "failed" if m else "passed", note, ev)

    # 8. Server-side Interactions (SNIPER-SRVR-*)
    if has_audit:
        m = _audit_matches(audit_findings, categories=("ssrf",), cwes=("CWE-918",))
        note, ev = _format_audit_evidence(audit_id, m, "sunucu tarafı istek sahteciliği (SSRF) kontrolleri")
        record("SNIPER-SRVR-01", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-22", "CWE-98"), title_substrings=("include", "path", "dizin"))
        note, ev = _format_audit_evidence(audit_id, m, "yerel ve uzak dosya dahil etme riskleri")
        record("SNIPER-SRVR-02", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-22",))
        note, ev = _format_audit_evidence(audit_id, m, "dizin geçişi ve arşiv çıkarma sınırları")
        record("SNIPER-SRVR-03", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-1336",))
        note, ev = _format_audit_evidence(audit_id, m, "sunucu tarafı şablon enjeksiyonu (SSTI)")
        record("SNIPER-SRVR-04", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, categories=("command_data",), cwes=("CWE-78",))
        note, ev = _format_audit_evidence(audit_id, m, "işletim sistemi komut çağrısı yüzeyleri")
        record("SNIPER-SRVR-05", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-502",))
        note, ev = _format_audit_evidence(audit_id, m, "güvensiz nesne serileştirme")
        record("SNIPER-SRVR-06", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-611",))
        note, ev = _format_audit_evidence(audit_id, m, "XML ve harici varlık işleme güvenliği")
        record("SNIPER-SRVR-07", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-22", "CWE-409"), title_substrings=("extractall", "arşiv", "Zip Slip"))
        note, ev = _format_audit_evidence(audit_id, m, "dosya işleme ve dönüştürme hattı güvenliği")
        record("SNIPER-SRVR-10", "failed" if m else "passed", note, ev)

    # 9. Error Handling (SNIPER-ERRH-*)
    if has_scan:
        m = _scan_matches(scan_findings, categories=("errors",))
        note, ev = _format_scan_evidence(scan_id, m, "uygulama hata mesajları ve yığın izi kontrolü")
        record("SNIPER-ERRH-01", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, categories=("errors",), title_substrings=("500", "istisna", "stack", "hata"))
        note, ev = _format_scan_evidence(scan_id, m, "beklenmeyen girdi ve sınır durum hata davranışı")
        record("SNIPER-ERRH-02", "failed" if m else "passed", note, ev)

    if has_audit:
        m = _audit_matches(audit_findings, categories=("logging",), cwes=("CWE-209", "CWE-532"))
        note, ev = _format_audit_evidence(audit_id, m, "hata kaydı ve izleme bütünlüğü")
        record("SNIPER-ERRH-03", "failed" if m else "passed", note, ev)

    # 10. Cryptography (SNIPER-CRYP-*)
    if has_scan or has_audit or testssl_evidence:
        m_scan = _scan_matches(scan_findings, categories=("transport",))
        m_aud = _audit_matches(audit_findings, categories=("transport",), cwes=("CWE-295",))
        testssl_bad = any(
            int((item.get("severity_counts") or {}).get("critical", 0) or 0)
            + int((item.get("severity_counts") or {}).get("high", 0) or 0)
            + int((item.get("severity_counts") or {}).get("medium", 0) or 0)
            > 0
            for item in testssl_evidence
        )
        if m_scan:
            note, ev = _format_scan_evidence(scan_id, m_scan, "TLS ve taşıma katmanı yapılandırması")
            record("SNIPER-CRYP-01", "failed", note, ev)
        elif m_aud:
            note, ev = _format_audit_evidence(audit_id, m_aud, "TLS sertifika doğrulaması")
            record("SNIPER-CRYP-01", "failed", note, ev)
        elif testssl_bad:
            digest = str(testssl_evidence[0].get("report_sha256", ""))[:16]
            record(
                "SNIPER-CRYP-01",
                "failed",
                "testssl.sh toplu kanıtında orta/yüksek/kritik TLS bulgusu tespit edildi.",
                f"testssl.sh SHA-256: {digest}",
            )
        elif has_scan:
            note, ev = _format_scan_evidence(scan_id, [], "TLS ve taşıma katmanı yapılandırması")
            record("SNIPER-CRYP-01", "passed", note, ev)
        elif has_audit:
            note, ev = _format_audit_evidence(audit_id, [], "TLS sertifika doğrulaması")
            record("SNIPER-CRYP-01", "passed", note, ev)

    if has_scan:
        m = _scan_matches(
            scan_findings,
            categories=("transport",),
            title_substrings=("HSTS", "Strict-Transport-Security", "HTTPS", "Karışık içerik"),
        )
        note, ev = _format_scan_evidence(scan_id, m, "hassas verilerin taşıma sırasında korunması")
        record("SNIPER-CRYP-02", "failed" if m else "passed", note, ev)

    if has_audit:
        m = _audit_matches(audit_findings, cwes=("CWE-327", "CWE-338"))
        note, ev = _format_audit_evidence(audit_id, m, "uygulama kriptografisi ve PRNG güvenliği")
        record("SNIPER-CRYP-03", "failed" if m else "passed", note, ev)

    if has_audit or gitleaks_evidence:
        m_aud = _audit_matches(audit_findings, categories=("secrets",), cwes=("CWE-798", "CWE-522"))
        if m_aud:
            note, ev = _format_audit_evidence(audit_id, m_aud, "sır yönetimi")
            record("SNIPER-CRYP-04", "failed", note, ev)
        elif gitleaks_finding_count > 0:
            digest = str(gitleaks_evidence[0].get("report_sha256", ""))[:16]
            record(
                "SNIPER-CRYP-04",
                "failed",
                f"Gitleaks toplu kanıtında {gitleaks_finding_count} sır bulgusu tespit edildi.",
                f"Gitleaks bulgu sayısı: {gitleaks_finding_count} · SHA-256: {digest}",
            )
        elif has_audit:
            note, ev = _format_audit_evidence(audit_id, [], "sır yönetimi")
            record("SNIPER-CRYP-04", "passed", note, ev)
        elif gitleaks_evidence:
            digest = str(gitleaks_evidence[0].get("report_sha256", ""))[:16]
            record(
                "SNIPER-CRYP-04",
                "passed",
                "Gitleaks toplu kanıtında sır sızıntısı gözlenmedi.",
                f"Gitleaks bulgu sayısı: 0 · SHA-256: {digest}",
            )

    if has_audit:
        m = _audit_matches(
            audit_findings,
            titles=("Parola işleme için yavaş KDF doğrulanamadı",),
            cwes=("CWE-916",),
        )
        note, ev = _format_audit_evidence(audit_id, m, "parola saklama ve yavaş KDF kullanımı")
        record("SNIPER-CRYP-05", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, categories=("qr",), cwes=("CWE-347",))
        note, ev = _format_audit_evidence(audit_id, m, "belirteç ve imza doğrulama")
        record("SNIPER-CRYP-06", "failed" if m else "passed", note, ev)

    # 11. Data Protection (SNIPER-DATA-*)
    if has_scan:
        m = _scan_matches(scan_findings, categories=("privacy",), title_substrings=("Referrer-Policy", "Permissions-Policy"))
        note, ev = _format_scan_evidence(scan_id, m, "veri minimizasyonu ve mahremiyet üstbilgileri")
        record("SNIPER-DATA-02", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, title_substrings=("no-store", "Cache-Control", "önbellek"))
        note, ev = _format_scan_evidence(scan_id, m, "arama, dışa aktarma ve önbellek veri sızıntısı")
        record("SNIPER-DATA-06", "failed" if m else "passed", note, ev)

        m = _scan_matches(scan_findings, titles=("İstemci yanıtında olası sır deseni bulundu",))
        note, ev = _format_scan_evidence(scan_id, m, "istemci paketi sırları")
        record("SNIPER-DATA-09", "failed" if m else "passed", note, ev)

    # 12. Business Logic (SNIPER-BUSL-*)
    if has_audit:
        m = _audit_matches(audit_findings, cwes=("CWE-400", "CWE-770"))
        note, ev = _format_audit_evidence(audit_id, m, "dosya ve kaynak limitleri")
        record("SNIPER-BUSL-06", "failed" if m else "passed", note, ev)

    # 13. Client-side (SNIPER-CLNT-*)
    if has_audit:
        m = _audit_matches(audit_findings, cwes=("CWE-79",))
        note, ev = _format_audit_evidence(audit_id, m, "DOM tabanlı betik enjeksiyonu (XSS)")
        record("SNIPER-CLNT-01", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-95",), title_substrings=("eval", "Function(", "dinamik kod"))
        note, ev = _format_audit_evidence(audit_id, m, "istemci tarafı JavaScript çalıştırma yüzeyleri")
        record("SNIPER-CLNT-02", "failed" if m else "passed", note, ev)

        m = _audit_matches(audit_findings, cwes=("CWE-79", "CWE-1336"), title_substrings=("innerHTML", "şablon", "template"))
        note, ev = _format_audit_evidence(audit_id, m, "istemci tarafı HTML ve şablon enjeksiyonu")
        record("SNIPER-CLNT-03", "failed" if m else "passed", note, ev)

    if has_scan:
        m = _scan_matches(scan_findings, title_substrings=("Karışık içerik", "Content-Security-Policy"))
        note, ev = _format_scan_evidence(scan_id, m, "CSS, stil ve harici kaynak yükleme riskleri")
        record("SNIPER-CLNT-05", "failed" if m else "passed", note, ev)

    if has_scan or has_audit:
        m_scan = _scan_matches(scan_findings, categories=("cors",))
        m_aud = _audit_matches(audit_findings, cwes=("CWE-942", "CWE-345"))
        if m_scan:
            note, ev = _format_scan_evidence(scan_id, m_scan, "CORS ve web mesajlaşması")
            record("SNIPER-CLNT-07", "failed", note, ev)
        elif m_aud:
            note, ev = _format_audit_evidence(audit_id, m_aud, "CORS ve postMessage köken doğrulaması")
            record("SNIPER-CLNT-07", "failed", note, ev)
        elif has_scan:
            note, ev = _format_scan_evidence(scan_id, [], "CORS ve web mesajlaşması")
            record("SNIPER-CLNT-07", "passed", note, ev)
        elif has_audit:
            note, ev = _format_audit_evidence(audit_id, [], "CORS ve postMessage köken doğrulaması")
            record("SNIPER-CLNT-07", "passed", note, ev)

    if has_scan:
        m = _scan_matches(scan_findings, titles=("Çerçeveleme koruması eksik",))
        note, ev = _format_scan_evidence(scan_id, m, "tıklama kaçırma (clickjacking) koruması")
        record("SNIPER-CLNT-08", "failed" if m else "passed", note, ev)

        m = _scan_matches(
            scan_findings,
            titles=(
                "Üçüncü taraf betiklerde bütünlük doğrulaması yok",
                "Karışık içerik bağlantıları bulundu",
            ),
        )
        note, ev = _format_scan_evidence(scan_id, m, "üçüncü taraf istemci bağımlılıkları")
        record("SNIPER-CLNT-09", "failed" if m else "passed", note, ev)

    # 14. API Security (SNIPER-APIT-*)
    if has_audit:
        m = _audit_matches(audit_findings, categories=("api", "openapi"), cwes=("CWE-347",))
        note, ev = _format_audit_evidence(audit_id, m, "JWT ve API erişim belirteçleri")
        record("SNIPER-APIT-12", "failed" if m else "passed", note, ev)

    if isinstance(openapi_audit, dict) and (
        int(openapi_audit.get("contracts_audited", openapi_audit.get("contract_count", 0)) or 0) > 0
        or "endpoint_count" in openapi_audit
        or "findings" in openapi_audit
    ):
        oa_findings = [f for f in (openapi_audit.get("findings") or []) if isinstance(f, dict)]
        oa_controls = (
            ("SNIPER-APIT-01", "API envanteri, sürümleme ve dokümantasyon sızıntısı"),
            ("SNIPER-APIT-02", "nesne ve alan düzeyinde yetkilendirme (BOLA/BOPLA)"),
            ("SNIPER-APIT-03", "toplu atama ve beklenmeyen alan kabulü"),
            ("SNIPER-APIT-04", "sorgu karmaşıklığı, sayfalama ve hız sınırı"),
            ("SNIPER-APIT-05", "webhook ve geri çağırma entegrasyon güvenliği"),
            ("SNIPER-APIT-06", "GraphQL ve şema tabanlı sorgu güvenliği"),
            ("SNIPER-APIT-09", "şema doğrulama ve içerik tipi zorlaması"),
        )
        for cid, desc in oa_controls:
            matched_oa = [
                f for f in oa_findings
                if str(f.get("control_id") or f.get("rule_id") or "").strip() == cid
            ]
            if matched_oa:
                titles = ", ".join(sorted({str(f.get("title", "")) for f in matched_oa if f.get("title")}))
                ev_str = " | ".join(
                    f"{f.get('location', 'spec')}: {str(f.get('evidence', ''))[:140]}"
                    for f in matched_oa[:4]
                )
                record(
                    cid,
                    "failed",
                    f"OpenAPI/GraphQL sözleşme denetimi bulgu tespit etti: {titles[:260]}",
                    ev_str[:1000] or f"OpenAPI denetimi ({cid})",
                )
            else:
                record(
                    cid,
                    "passed",
                    f"OpenAPI/GraphQL sözleşme denetimi kapsamında {desc} doğrulandı; bulgu yok.",
                    "OpenAPI/GraphQL sözleşme analizi · durum: temiz",
                )
        matched_cryp02 = [
            f for f in oa_findings
            if str(f.get("control_id") or f.get("rule_id") or "").strip() == "SNIPER-CRYP-02"
        ]
        if matched_cryp02:
            record(
                "SNIPER-CRYP-02",
                "failed",
                f"OpenAPI sözleşmesinde güvensiz taşıma şeması: {matched_cryp02[0].get('title', 'HTTP')}",
                str(matched_cryp02[0].get("evidence", "http://"))[:500],
            )
        oa_control_ids = {c[0] for c in oa_controls}
        extra_oa_controls: dict[str, list[dict[str, Any]]] = {}
        for f in oa_findings:
            extra_cid = str(f.get("control_id") or f.get("rule_id") or "").strip()
            if (
                extra_cid
                and extra_cid.startswith("SNIPER-")
                and extra_cid not in oa_control_ids
                and extra_cid != "SNIPER-CRYP-02"
            ):
                extra_oa_controls.setdefault(extra_cid, []).append(f)
        for extra_cid, extra_matches in sorted(extra_oa_controls.items()):
            titles = ", ".join(sorted({str(f.get("title", "")) for f in extra_matches if f.get("title")}))
            ev_str = " | ".join(
                f"{f.get('location', 'spec')}: {str(f.get('evidence', ''))[:140]}"
                for f in extra_matches[:4]
            )
            record(
                extra_cid,
                "failed",
                f"OpenAPI/GraphQL sözleşme denetimi bulgu tespit etti: {titles[:260]}",
                ev_str[:1000] or f"OpenAPI denetimi ({extra_cid})",
            )

    # 15. Infrastructure (SNIPER-INFR-*)
    if has_audit:
        m = _audit_matches(audit_findings, categories=("ports", "iac"), title_substrings=("0.0.0.0", "2375", "host_network"))
        note, ev = _format_audit_evidence(audit_id, m, "yönetim ve teşhis yüzeylerinin izolasyonu")
        record("SNIPER-INFR-04", "failed" if m else "passed", note, ev)

    if has_audit or nmap_evidence or has_scan:
        m_aud = _audit_matches(audit_findings, categories=("ports",), cwes=("CWE-284",))
        if m_aud:
            note, ev = _format_audit_evidence(audit_id, m_aud, "ağ ve servis maruziyeti")
            record("SNIPER-INFR-09", "failed", note, ev)
        elif nmap_evidence:
            open_ports = sum(int(item.get("open_port_count", 0) or 0) for item in nmap_evidence)
            digest = str(nmap_evidence[0].get("report_sha256", ""))[:16]
            record(
                "SNIPER-INFR-09",
                "needs_review" if open_ports > 0 else "passed",
                f"Nmap toplu kanıtında {open_ports} açık port gözlendi.",
                f"Nmap açık port sayısı: {open_ports} · SHA-256: {digest}",
            )
        elif has_audit:
            note, ev = _format_audit_evidence(audit_id, [], "ağ ve servis maruziyeti")
            record("SNIPER-INFR-09", "passed", note, ev)

    if isinstance(dns_email_audit, dict):
        dns_findings = [f for f in (dns_email_audit.get("findings") or []) if isinstance(f, dict)]
        dns_controls = (
            ("SNIPER-INFR-01", "DNS, CAA ve alan adı devralma kontrolleri"),
            ("SNIPER-INFR-02", "e-posta kimlik doğrulama (SPF, DKIM ve DMARC)"),
            ("SNIPER-INFR-07", "CDN, WAF ve ters vekil başlık güvenilirliği"),
            ("SNIPER-INFR-08", "TLS/mTLS ve servisler arası iletişim"),
        )
        for cid, desc in dns_controls:
            matched_dns = [
                f for f in dns_findings
                if str(f.get("control_id") or f.get("rule_id") or "").strip() == cid
            ]
            if matched_dns:
                titles = ", ".join(sorted({str(f.get("title", "")) for f in matched_dns if f.get("title")}))
                ev_str = " | ".join(str(f.get("evidence", ""))[:160] for f in matched_dns[:4])
                record(
                    cid,
                    "failed",
                    f"DNS/E-posta ve sınır güvenliği denetiminde bulgu: {titles[:260]}",
                    ev_str[:1000] or f"DNS/E-posta denetimi ({cid})",
                )
            else:
                record(
                    cid,
                    "passed",
                    f"DNS/E-posta ve sınır güvenliği denetimi kapsamında {desc} doğrulandı.",
                    f"DNS/E-posta denetimi ({dns_email_audit.get('domain', 'hedef')}) · durum: temiz",
                )

    if isinstance(discovery_audit, dict):
        disc_findings = [f for f in (discovery_audit.get("findings") or []) if isinstance(f, dict)]
        disc_controls = (
            ("SNIPER-AUTH-11", "SSO, OAuth ve OIDC yönlendirme/durum güvenliği"),
            ("SNIPER-APIT-06", "GraphQL ve şema tabanlı sorgu güvenliği"),
        )
        for cid, desc in disc_controls:
            matched_disc = [
                f for f in disc_findings
                if str(f.get("control_id") or f.get("rule_id") or "").strip() == cid
            ]
            if matched_disc:
                titles = ", ".join(sorted({str(f.get("title", "")) for f in matched_disc if f.get("title")}))
                ev_str = " | ".join(str(f.get("evidence", ""))[:160] for f in matched_disc[:4])
                record(
                    cid,
                    "failed",
                    f"Web keşif denetiminde bulgu: {titles[:260]}",
                    ev_str[:1000] or f"Keşif denetimi ({cid})",
                )
            else:
                record(
                    cid,
                    "passed",
                    f"Web keşif denetimi kapsamında {desc} doğrulandı.",
                    "OIDC/JWKS/GraphQL keşif denetimi · durum: temiz",
                )
        for extra_f in disc_findings:
            extra_cid = str(extra_f.get("control_id") or "").strip()
            if extra_cid and extra_cid not in {"SNIPER-AUTH-11", "SNIPER-APIT-06"}:
                record(
                    extra_cid,
                    "failed",
                    f"Web keşif denetiminde bulgu: {str(extra_f.get('title', ''))[:240]}",
                    str(extra_f.get("evidence", ""))[:500] or f"Keşif denetimi ({extra_cid})",
                )

    # 16. Supply Chain (SNIPER-SUPP-*)
    if has_audit:
        m = _audit_matches(audit_findings, categories=("components",), cwes=("CWE-1104",))
        note, ev = _format_audit_evidence(audit_id, m, "bağımlılık envanteri ve sürüm sabitleme")
        record("SNIPER-SUPP-01", "failed" if m else "passed", note, ev)
        record("SNIPER-SUPP-03", "failed" if m else "passed", note, ev)

        m_sec = _audit_matches(audit_findings, categories=("secrets", "secret_file"), cwes=("CWE-798",))
        note_s, ev_s = _format_audit_evidence(audit_id, m_sec, "kaynak kodu ve yapı artefaktlarında sır taraması")
        record("SNIPER-SUPP-08", "failed" if m_sec else "passed", note_s, ev_s)

    if dep_sec.get("sboms") or has_audit:
        sbom_count = len(dep_sec.get("sboms") or [])
        record(
            "SNIPER-SUPP-06",
            "passed",
            f"SBOM ve bileşen köken envanteri doğrulandı (kayıtlı SBOM: {sbom_count}).",
            f"SBOM sayısı: {sbom_count} · proje denetimi: {audit_id or 'yok'}",
        )

    trivy_vulns = sum(
        sum(int(v or 0) for v in (item.get("vuln_counts") or {}).values())
        for item in trivy_evidence
    )
    if dep_active_count > 0 or trivy_vulns > 0:
        record(
            "SNIPER-SUPP-02",
            "failed",
            f"Bağımlılık güvenliği taramasında {dep_active_count + trivy_vulns} açık zafiyet bulundu.",
            f"Açık bağımlılık bulgusu: {dep_active_count} · Trivy zafiyeti: {trivy_vulns}",
        )
    elif has_dep_reports or trivy_evidence:
        record(
            "SNIPER-SUPP-02",
            "passed",
            "Bağımlılık güvenliği raporlarında açık CVE/OSV bulgusu bulunmadı.",
            f"Toplam izlenen bağımlılık kaydı: {int(dep_summary.get('total', 0) or 0)} · açık: 0",
        )

    if has_scan:
        m = _scan_matches(scan_findings, categories=("supplychain",))
        note, ev = _format_scan_evidence(scan_id, m, "üçüncü taraf betik bütünlüğü (SRI)")
        record("SNIPER-SUPP-04", "failed" if m else "passed", note, ev)

    if has_audit:
        m = _audit_matches(
            audit_findings,
            categories=("supplychain", "container", "cicd", "kubernetes"),
            cwes=("CWE-250", "CWE-829"),
        )
        note, ev = _format_audit_evidence(audit_id, m, "derleme, konteyner ve CI/CD yayın hattı")
        record("SNIPER-SUPP-05", "failed" if m else "passed", note, ev)

    # 17. Availability (SNIPER-AVAL-*)
    if has_audit:
        m = _audit_matches(audit_findings, cwes=("CWE-409",), title_substrings=("arşiv", "Zip Slip"))
        note, ev = _format_audit_evidence(audit_id, m, "sıkıştırma ve arşiv çıkarma güvenliği")
        record("SNIPER-AVAL-03", "failed" if m else "passed", note, ev)

    # 18. Logging & Incident Response (SNIPER-LOGG-*)
    if has_audit:
        m = _audit_matches(
            audit_findings,
            titles=("Kimlik doğrulama güvenlik olayı kaydı doğrulanamadı",),
            cwes=("CWE-778",),
        )
        note, ev = _format_audit_evidence(audit_id, m, "güvenlik olay kapsamı ve denetim izi")
        record("SNIPER-LOGG-01", "failed" if m else "passed", note, ev)

        m = _audit_matches(
            audit_findings,
            titles=("Günlüğe hassas veri yazma olasılığı",),
            cwes=("CWE-532",),
        )
        note, ev = _format_audit_evidence(audit_id, m, "günlüklerde hassas veri maskeleme")
        record("SNIPER-LOGG-02", "failed" if m else "passed", note, ev)

    # 19. Controlled Lab Scenarios (SNIPER-SAFE-*)
    try:
        lab_runs = store.list_lab_runs() if hasattr(store, "list_lab_runs") else []
    except Exception:
        lab_runs = []
    for run in lab_runs:
        if not isinstance(run, dict):
            continue
        if run.get("engagement_id") != engagement_id or run.get("status") != "completed":
            continue
        run_id = str(run.get("id") or "lab")
        stype = str(run.get("scenario_type") or "")
        ev_sum = str(run.get("evidence_summary") or run.get("name") or run_id)[:300]
        if stype == "lockout_plan":
            record(
                "SNIPER-SAFE-AUTH-01",
                "passed",
                f"Kontrollü hesap kilitleme laboratuvar senaryosu ({run_id}) tamamlandı.",
                f"Lab çalışması: {run_id} · {ev_sum}",
            )
            record(
                "SNIPER-AUTH-03",
                "passed",
                f"Hesap kilitleme ve hız sınırı davranışı laboratuvar planıyla ({run_id}) doğrulandı.",
                f"Lab çalışması: {run_id} · {ev_sum}",
            )
        elif stype == "capacity_plan":
            record(
                "SNIPER-SAFE-CAP-01",
                "passed",
                f"Staging kapasite ve hız sınırı laboratuvar senaryosu ({run_id}) tamamlandı.",
                f"Lab çalışması: {run_id} · {ev_sum}",
            )
            record(
                "SNIPER-AVAL-08",
                "passed",
                f"Kapasite planı ve önbellek/CDN dayanıklılığı ({run_id}) doğrulandı.",
                f"Lab çalışması: {run_id} · {ev_sum}",
            )
        elif stype == "external_result":
            record(
                "SNIPER-SAFE-DATA-01",
                "passed",
                f"Maskeli veri kanıtı ve dış doğrulama sonucu ({run_id}) kaydedildi.",
                f"Lab çalışması: {run_id} · {ev_sum}",
            )

    # 20. Mobile Security & OWASP MASVS v2.1.0 (mobile_security / mobile_audit)
    pa_mobile_findings: list[dict[str, Any]] = [
        f
        for f in audit_findings
        if str(f.get("category") or "").strip().lower() in {"mobile_security", "mobile"}
    ]
    ma_findings: list[dict[str, Any]] = [
        f
        for f in (mobile_audit.get("findings") or [] if isinstance(mobile_audit, dict) else [])
        if isinstance(f, dict) and (f.get("triage") or {}).get("disposition") != "false_positive"
    ]
    all_mobile_findings = pa_mobile_findings + ma_findings
    has_mobile_surface = bool(
        isinstance(mobile_audit, dict)
        or all_mobile_findings
        or (
            has_audit
            and any(
                isinstance(chk, dict)
                and chk.get("id") == "mobile_masvs"
                and chk.get("status") in {"pass", "review"}
                for chk in (project_audit.get("checks") or [])
            )
        )
    )
    if has_mobile_surface:
        mobile_source_id = (
            str(mobile_audit.get("project_name") or mobile_audit.get("package_name") or "mobile_audit")
            if isinstance(mobile_audit, dict)
            else (audit_id or "mobile_audit")
        )
        mobile_control_specs: tuple[
            tuple[str, tuple[str, ...], tuple[str, ...], str, str],
            ...,
        ] = (
            (
                "SNIPER-DATA-02",
                ("CWE-312", "CWE-532"),
                ("SNIPER-MOB-STOR-01", "SNIPER-MOB-STOR-02", "SNIPER-MOB-STOR-03", "SNIPER-MOB-STOR-04", "SNIPER-MOB-PKG-01"),
                "MASVS-STORAGE",
                "mobil yerel veri saklama ve mahremiyet (MASVS-STORAGE)",
            ),
            (
                "SNIPER-CONF-02",
                ("CWE-489", "CWE-693"),
                ("SNIPER-MOB-MAN-01", "SNIPER-MOB-IOS-02", "SNIPER-MOB-GRD-01", "SNIPER-MOB-RES-01", "SNIPER-MOB-PKG-02"),
                "MASVS-RESILIENCE",
                "mobil uygulama yapılandırması, debuggable ve tersine mühendislik direnci (MASVS-RESILIENCE)",
            ),
            (
                "SNIPER-CLNT-01",
                ("CWE-749", "CWE-939"),
                (
                    "SNIPER-MOB-PLAT-01",
                    "SNIPER-MOB-PLAT-02",
                    "SNIPER-MOB-PLAT-03",
                    "SNIPER-MOB-PLAT-04",
                    "SNIPER-MOB-MAN-05",
                    "SNIPER-MOB-MAN-06",
                    "SNIPER-MOB-MAN-07",
                    "SNIPER-MOB-MAN-08",
                    "SNIPER-MOB-IOS-04",
                ),
                "MASVS-PLATFORM",
                "mobil WebView, IPC ve Deep Link istemci yüzeyleri (MASVS-PLATFORM)",
            ),
            (
                "SNIPER-AUTH-02",
                ("CWE-287", "CWE-347"),
                ("SNIPER-MOB-AUTH-01",),
                "MASVS-AUTH",
                "mobil kimlik doğrulama ve kriptografik biyometri bağlaması (MASVS-AUTH)",
            ),
            (
                "SNIPER-BUSL-01",
                ("CWE-530",),
                ("SNIPER-MOB-MAN-02", "SNIPER-MOB-DOM-FIN-01", "SNIPER-MOB-IOS-03"),
                "",
                "mobil yedekleme (allowBackup) ve ekran görüntüsü veri sızıntısı (MASVS-STORAGE)",
            ),
            (
                "SNIPER-BUSL-04",
                ("CWE-602",),
                ("SNIPER-MOB-AUTH-02", "SNIPER-MOB-DOM-GAM-01", "SNIPER-MOB-DOM-GAM-02"),
                "",
                "istemci tarafı rol/fiyat doğrulaması ve uygulama içi satın alma (IAP) bütünlüğü (MASVS-RESILIENCE)",
            ),
        )
        for cid, cwe_list, rule_ids, masvs_tag, desc in mobile_control_specs:
            matched_mob: list[dict[str, Any]] = []
            for mf in all_mobile_findings:
                mf_ref = f"{mf.get('cwe', '')} {mf.get('cwe_id', '')} {mf.get('reference', '')}".upper()
                mf_rule = str(mf.get("control_id") or mf.get("rule_id") or "").strip().upper()
                mf_masvs = str(mf.get("masvs") or mf.get("masvs_id") or "").strip().upper()
                if any(c in mf_ref for c in cwe_list):
                    matched_mob.append(mf)
                elif mf_rule and mf_rule in rule_ids:
                    matched_mob.append(mf)
                elif (
                    masvs_tag
                    and mf_masvs.startswith(masvs_tag)
                    and not any(
                        other_c in mf_ref
                        for other_c in ("CWE-530", "CWE-602")
                        if other_c not in cwe_list
                    )
                    and mf_rule
                    not in {
                        "SNIPER-MOB-MAN-02",
                        "SNIPER-MOB-DOM-FIN-01",
                        "SNIPER-MOB-IOS-03",
                        "SNIPER-MOB-AUTH-02",
                        "SNIPER-MOB-DOM-GAM-01",
                        "SNIPER-MOB-DOM-GAM-02",
                    }
                ):
                    matched_mob.append(mf)
            if matched_mob:
                note_m, ev_m = _format_audit_evidence(mobile_source_id, matched_mob, desc)
                record(cid, "failed", note_m, ev_m)
            elif cid not in evaluated or isinstance(mobile_audit, dict):
                note_m, ev_m = _format_audit_evidence(mobile_source_id, [], desc)
                record(cid, "passed", note_m, ev_m)

    # Also honor explicit tool_evidence links for any control not yet evaluated
    for tev in tool_evidence:
        cid = str(tev.get("control_id", "")).strip()
        if not cid or cid in evaluated:
            continue
        tool_id = str(tev.get("tool_identity", "tool")).strip()
        digest = str(tev.get("report_sha256", ""))[:16]
        sev_counts = tev.get("severity_counts") or tev.get("risk_counts") or {}
        high_or_crit = (
            int(sev_counts.get("critical", 0) or 0)
            + int(sev_counts.get("high", 0) or 0)
            + int(sev_counts.get("medium", 0) or 0)
            + int(tev.get("total_findings", 0) or 0)
        )
        status = "failed" if high_or_crit > 0 else "needs_review"
        record(
            cid,
            status,
            f"Bağlı araç kanıtı ({tool_id}) otomatik senkronize edildi.",
            f"Araç: {tool_id} · SHA-256: {digest}",
        )

    tests_by_id = {
        str(row.get("control_id")): row
        for row in (engagement.get("tests") or [])
        if isinstance(row, dict) and row.get("control_id")
    }

    updated: list[dict[str, Any]] = []
    passed_count = 0
    failed_count = 0
    review_count = 0

    for control_id, (target_status, note_text, evidence_text) in evaluated.items():
        current = tests_by_id.get(control_id)
        if current is None:
            continue
        prev_status = str(current.get("status", "not_tested"))
        if prev_status == "not_tested" or overwrite_manual:
            store.update_manual_test(
                engagement_id,
                control_id,
                status=target_status,
                notes=note_text,
                evidence=evidence_text,
            )
            if target_status == "passed":
                passed_count += 1
            elif target_status == "failed":
                failed_count += 1
            elif target_status == "needs_review":
                review_count += 1
            updated.append({
                "control_id": control_id,
                "category": str(current.get("category", "")),
                "title": str(current.get("title", "")),
                "previous_status": prev_status,
                "status": target_status,
                "notes": note_text,
                "evidence": evidence_text,
            })

    refreshed = store.get_engagement(engagement_id) or engagement
    return {
        "format": "sniper-wstg-auto-evidence-sync-v1",
        "engagement_id": engagement_id,
        "evaluated_control_count": len(evaluated),
        "updated_control_count": len(updated),
        "passed_count": passed_count,
        "failed_count": failed_count,
        "needs_review_count": review_count,
        "coverage": refreshed.get("coverage", {"total": 0, "completed": 0, "percent": 0}),
        "updated_controls": updated,
    }


def derive_auto_evidence_updates(
    *,
    openapi_audit: dict[str, Any] | None = None,
    dns_email_audit: dict[str, Any] | None = None,
    discovery_audit: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Stateless helper to derive control updates from specialized audit payloads."""
    from methodology import TEST_CATALOG

    class _MemStore:
        def __init__(self) -> None:
            self._eng = {
                "id": "eng_mem",
                "tests": [
                    {"control_id": c["control_id"], "category": c.get("category", ""), "title": c.get("title", ""), "status": "not_tested"}
                    for c in TEST_CATALOG
                ],
                "coverage": {"total": len(TEST_CATALOG), "completed": 0, "percent": 0},
            }

        def get_engagement(self, _eid: str) -> dict[str, Any]:
            return self._eng

        def update_manual_test(self, _eid: str, cid: str, *, status: str, notes: str, evidence: str) -> None:
            for t in self._eng["tests"]:
                if t["control_id"] == cid:
                    t.update(status=status, notes=notes, evidence=evidence)

    store = _MemStore()
    res = synchronize_engagement_auto_evidence(
        store,
        "eng_mem",
        project_audit_id="none",
        openapi_audit=openapi_audit,
        dns_email_audit=dns_email_audit,
        discovery_audit=discovery_audit,
        mobile_audit=mobile_audit,
    )
    res["updates"] = {u["control_id"]: u for u in res.get("updated_controls", [])}
    return res


def verify_engagement_retests(
    store: Any,
    engagement_id: str,
    *,
    project_audit_id: str | None = None,
    auto_resolve: bool = True,
) -> dict[str, Any]:
    """Automatically verify retest_required/reopened/in_progress/open findings against latest scan & project audit."""
    import re

    sync_res = synchronize_engagement_auto_evidence(
        store,
        engagement_id,
        project_audit_id=project_audit_id,
        overwrite_manual=True,
    )
    engagement = store.get_engagement(engagement_id)
    if engagement is None:
        raise ValueError("Manuel denetim bulunamadı.")

    latest_scan = engagement.get("latest_scan")
    has_scan = isinstance(latest_scan, dict)
    scan_findings: list[dict[str, Any]] = [
        f
        for f in (latest_scan.get("findings", []) if has_scan else [])
        if isinstance(f, dict) and not _is_false_positive(f)
    ]

    project_audit: dict[str, Any] | None = None
    if project_audit_id and project_audit_id not in ("latest", "none"):
        project_audit = store.get_project_audit(project_audit_id)
    elif project_audit_id != "none" and hasattr(store, "list_project_audits"):
        audits = store.list_project_audits(limit=1)
        if audits:
            project_audit = store.get_project_audit(audits[0]["id"]) or audits[0]

    has_audit = isinstance(project_audit, dict)
    audit_findings: list[dict[str, Any]] = [
        f
        for f in (project_audit.get("findings", []) if has_audit else [])
        if isinstance(f, dict) and not _is_false_positive(f)
    ]

    tests_by_id = {
        str(row.get("control_id")): row
        for row in (engagement.get("tests") or [])
        if isinstance(row, dict) and row.get("control_id")
    }

    control_re = re.compile(r"SNIPER-(?:SAFE-)?[A-Z]{4}-\d{2}")
    candidate_statuses = {"retest_required", "reopened", "in_progress", "open"}
    decisions: list[dict[str, Any]] = []
    resolved_ids: list[str] = []
    reopened_ids: list[str] = []
    still_open_ids: list[str] = []

    for finding in engagement.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        f_id = str(finding.get("id") or "")
        f_status = str(finding.get("status") or "open")
        if not f_id or f_status not in candidate_statuses:
            continue

        f_title = str(finding.get("title") or "").strip()
        f_cwe = str(finding.get("cwe_id") or "").strip().upper()
        text_blob = " ".join(
            str(finding.get(k) or "")
            for k in ("control_id", "owasp_category", "title", "description", "evidence", "reproduction")
        )
        matched_controls = sorted(set(control_re.findall(text_blob)))

        matched_active: list[dict[str, Any]] = []
        for sf in scan_findings + audit_findings:
            sf_title = str(sf.get("title") or "").strip()
            sf_ref = f"{sf.get('cwe', '')} {sf.get('cwe_id', '')} {sf.get('reference', '')}".upper()
            if f_cwe and f_cwe.startswith("CWE-") and f_cwe in sf_ref:
                matched_active.append(sf)
            elif f_title and sf_title and (
                f_title.lower() == sf_title.lower()
                or (len(f_title) >= 6 and f_title.lower() in sf_title.lower())
                or (len(sf_title) >= 6 and sf_title.lower() in f_title.lower())
            ):
                matched_active.append(sf)

        failed_controls = [
            cid for cid in matched_controls
            if str((tests_by_id.get(cid) or {}).get("status") or "") == "failed"
        ]
        passed_controls = [
            cid for cid in matched_controls
            if str((tests_by_id.get(cid) or {}).get("status") or "") == "passed"
        ]

        is_failing = bool(matched_active) or bool(failed_controls)
        is_clean = (not is_failing) and (
            (bool(matched_controls) and len(passed_controls) == len(matched_controls))
            or ((has_scan or has_audit) and not matched_active)
        )

        new_status = f_status
        decision_label = "still_open"
        if is_clean:
            new_status = "resolved"
            decision_label = "resolved"
            note = (
                str(finding.get("resolution_notes") or "").strip()
                or "Otomatik yeniden test doğrulaması: ilgili kontroller ve tarama sinyalleri temizlendi."
            )
            if auto_resolve and f_status != "resolved":
                store.update_manual_finding(f_id, {"status": "resolved", "resolution_notes": note})
            resolved_ids.append(f_id)
        elif is_failing:
            if f_status == "retest_required":
                new_status = "reopened"
                decision_label = "reopened"
                note = (
                    str(finding.get("resolution_notes") or "").strip()
                    or "Otomatik yeniden test doğrulaması: zafiyet sinyali halen devam ediyor."
                )
                if auto_resolve:
                    store.update_manual_finding(f_id, {"status": "reopened", "resolution_notes": note})
                reopened_ids.append(f_id)
            elif f_status == "reopened":
                decision_label = "reopened"
                reopened_ids.append(f_id)
            else:
                still_open_ids.append(f_id)
        else:
            still_open_ids.append(f_id)

        decisions.append({
            "finding_id": f_id,
            "title": f_title,
            "previous_status": f_status,
            "status": new_status if auto_resolve else f_status,
            "decision": decision_label,
            "matched_controls": matched_controls,
            "active_signal_count": len(matched_active),
        })

    refreshed = store.get_engagement(engagement_id) or engagement
    return {
        "format": "sniper-retest-verification-v1",
        "engagement_id": engagement_id,
        "auto_resolve": bool(auto_resolve),
        "checked_count": len(decisions),
        "resolved_count": len(resolved_ids),
        "reopened_count": len(reopened_ids),
        "still_open_count": len(still_open_ids),
        "resolved_finding_ids": resolved_ids,
        "reopened_finding_ids": reopened_ids,
        "still_open_finding_ids": still_open_ids,
        "decisions": decisions,
        "sync_summary": {
            "evaluated_control_count": sync_res["evaluated_control_count"],
            "updated_control_count": sync_res["updated_control_count"],
        },
        "coverage": refreshed.get("coverage", {"total": 0, "completed": 0, "percent": 0}),
        "remediation": refreshed.get("remediation", {}),
    }

