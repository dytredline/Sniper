"""Report Evidence Provenance & Redaction helpers (Wave 6-8 / M33-B).

Provides deterministic redaction for untrusted evidence strings and export
payloads, combined engagement finding provenance rows, engagement provenance
views, and redacted HTML/SARIF/CSV engagement report renderers.
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
from pathlib import Path
from typing import Any


_AUTHORIZATION_RE = re.compile(
    r"(?i)\b(authorization)\b[\"']?(\s*[:=]\s*)(?:(?:Bearer|Basic)\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(password|passwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|auth[_-]?token|x[_-]?api[_-]?key|webhook[_-]?secret|signing[_-]?secret|encryption[_-]?key|master[_-]?key|service[_-]?role[_-]?key|anon[_-]?key|secret|token|api[_-]?key|private[_-]?key)\b[\"']?(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_SPACED_CREDENTIAL_RE = re.compile(
    r"(?i)\b(password|passwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|auth[_-]?token|x[_-]?api[_-]?key|webhook[_-]?secret|signing[_-]?secret|encryption[_-]?key|master[_-]?key|service[_-]?role[_-]?key|anon[_-]?key|token|api[_-]?key|private[_-]?key)\b[\"']?(\s+)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_BEARER_RE = re.compile(
    r"(?i)\b(Bearer|Basic)(\s+)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_JWT_TOKEN_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_PROVIDER_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|AKIA[0-9A-Z]{16})\b"
)
_PRIVATE_NOTE_FIELDS = {"resolution_notes", "notes", "reproduction"}
_SECRET_VALUE_KEYS = {
    "password",
    "passwd",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "authtoken",
    "xapikey",
    "webhooksecret",
    "signingsecret",
    "encryptionkey",
    "masterkey",
    "servicerolekey",
    "anonkey",
    "secret",
    "token",
    "apikey",
    "privatekey",
}

_NESTED_CREDENTIAL_PREFIX_RE = re.compile(
    r"""(?i)\b(?:authorization|Bearer|Basic|password|passwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|auth[_-]?token|x[_-]?api[_-]?key|webhook[_-]?secret|signing[_-]?secret|encryption[_-]?key|master[_-]?key|service[_-]?role[_-]?key|anon[_-]?key|secret|token|api[_-]?key|private[_-]?key)\b["']?(?:\s*[:=]\s*|\s+)(?:(?:Bearer|Basic)\s+)?"""
)
_ENTITY_DOUBLE_QUOTE_RE = re.compile(r"(?i)&(?:quot|#0*34|#x0*22);")
_ENTITY_SINGLE_QUOTE_RE = re.compile(r"(?i)&(?:apos|#0*39|#x0*27);")


def _function_wrapper_end(text: str, start: int) -> int | None:
    """Return the end of ``identifier(`` using one forward-only pass."""
    if start >= len(text) or text[start] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_":
        return None
    cursor = start + 1
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_."
    while cursor < len(text) and text[cursor] in allowed:
        cursor += 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    return cursor + 1 if cursor < len(text) and text[cursor] == "(" else None


def _nested_credential_value_end(text: str, start: int) -> int:
    """Find the end of a structured or quoted untrusted credential value.

    If the value is malformed or too deeply nested, mask through the end
    rather than exposing a partial credential value.
    """
    entity_quote = _ENTITY_DOUBLE_QUOTE_RE.match(text, start)
    quote_re = _ENTITY_DOUBLE_QUOTE_RE
    if entity_quote is None:
        entity_quote = _ENTITY_SINGLE_QUOTE_RE.match(text, start)
        quote_re = _ENTITY_SINGLE_QUOTE_RE
    if entity_quote is not None:
        for closer in quote_re.finditer(text, entity_quote.end()):
            if closer.end() == len(text) or text[closer.end()].isspace():
                return closer.end()
        return len(text)

    function_end = _function_wrapper_end(text, start)
    if function_end is not None:
        return _nested_credential_value_end(text, function_end - 1)

    if text[start] == chr(96):
        fence_length = 1
        while start + fence_length < len(text) and text[start + fence_length] == chr(96):
            fence_length += 1
        fence = chr(96) * fence_length
        index = start + fence_length
        while index < len(text):
            if text.startswith(fence, index) and text[index - 1] != chr(92):
                return index + fence_length
            index += 1
        return len(text)

    if text[start] in (chr(34), chr(39)):
        quote = text[start]
        escaped = False
        for index in range(start + 1, len(text)):
            char = text[index]
            if escaped:
                escaped = False
            elif char == chr(92):
                escaped = True
            elif char == quote:
                return index + 1
        return len(text)

    stack: list[str] = []
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in (chr(34), chr(39), chr(96)):
            quote = char
        elif char in "{[(":
            stack.append(char)
            if len(stack) > 64:
                return len(text)
        elif char in "}])":
            expected = {"}": "{", "]": "[", ")": "("}[char]
            if not stack or stack[-1] != expected:
                return len(text)
            stack.pop()
            if not stack:
                return index + 1
    return len(text)


def _redact_nested_credential_text(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    while match := _NESTED_CREDENTIAL_PREFIX_RE.search(text, cursor):
        prefix = match.group(0)
        # Preserve benign prose such as "The secret recipe" when "secret" is followed by plain whitespace
        if re.match(r"(?i)^secret\s+$", prefix):
            pieces.append(text[cursor : match.end()])
            cursor = match.end()
            continue
        start = match.end()
        if not (
            start < len(text)
            and (
                text[start] in (chr(34), chr(39), chr(96), "{", "[", "(")
                or _ENTITY_DOUBLE_QUOTE_RE.match(text, start)
                or _ENTITY_SINGLE_QUOTE_RE.match(text, start)
                or _function_wrapper_end(text, start) is not None
            )
        ):
            pieces.append(text[cursor:start])
            cursor = start
            continue
        pieces.extend((text[cursor:start], "[REDACTED]"))
        cursor = _nested_credential_value_end(text, start)
    pieces.append(text[cursor:])
    return "".join(pieces)


def redact_evidence_text(value: object, *, max_len: int = 240) -> str:
    text = str(value if value is not None else "").strip()
    if not text:
        return ""
    text = _redact_nested_credential_text(text)
    text = _AUTHORIZATION_RE.sub(r"\1\2[REDACTED]", text)
    text = _CREDENTIAL_RE.sub(r"\1\2[REDACTED]", text)
    text = _SPACED_CREDENTIAL_RE.sub(r"\1\2[REDACTED]", text)
    text = _BEARER_RE.sub(r"\1\2[REDACTED]", text)
    text = _JWT_TOKEN_RE.sub("[REDACTED]", text)
    text = _PROVIDER_TOKEN_RE.sub("[REDACTED]", text)
    if max_len > 0 and len(text) > max_len:
        return text[:max_len] + "…"
    return text


def _redact_export_payload(value: Any, *, key: str = "") -> Any:
    """Protect credential or private-note subtrees and redact embedded secrets in strings."""
    normalized_key = re.sub(r"[^a-z0-9]", "", key.casefold()) if isinstance(key, str) else ""
    secret_context = normalized_key in _SECRET_VALUE_KEYS
    private_note_context = isinstance(key, str) and key in _PRIVATE_NOTE_FIELDS
    if isinstance(value, dict):
        return {
            field: _redact_export_payload(
                item, key=key if secret_context or private_note_context else field
            )
            for field, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_export_payload(item, key=key) for item in value]
    if isinstance(value, str):
        if secret_context and value.strip():
            return "[REDACTED]"
        if private_note_context and value.strip():
            return "[INTERNAL NOTE REDACTED]"
        return redact_evidence_text(value, max_len=0)
    if value is not None and secret_context:
        return "[REDACTED]"
    if value is not None and private_note_context:
        return "[INTERNAL NOTE REDACTED]"
    return value


def format_tool_evidence_redacted_summary(link: dict) -> str:
    if not isinstance(link, dict):
        return ""
    fmt = redact_evidence_text(link.get("tool_identity") or link.get("format") or "tool-evidence", max_len=0)
    parts = [fmt]
    if link.get("total_findings") is not None:
        parts.append(f"bulgu={int(link.get('total_findings') or 0)}")
    if link.get("rules_triggered") is not None:
        parts.append(f"kural/dedektör={int(link.get('rules_triggered') or 0)}")
    if link.get("files_affected") is not None:
        parts.append(f"dosya={int(link.get('files_affected') or 0)}")
    sha = str(link.get("report_sha256") or "")
    if sha:
        parts.append(f"sha256={sha[:12]}…")
    return " · ".join(parts)


def _combined_engagement_findings(engagement: dict) -> list[dict]:
    engagement = _redact_export_payload(engagement)
    latest_scan = engagement.get("latest_scan") or {}
    automated = latest_scan.get("findings", [])
    scan_id = str(latest_scan.get("id") or "")
    scan_recorded_at = str(
        latest_scan.get("finished_at")
        or latest_scan.get("started_at")
        or engagement.get("updated_at")
        or engagement.get("created_at")
        or ""
    )
    manual_rows = []
    for finding in engagement.get("findings", []):
        if not isinstance(finding, dict):
            continue
        redacted_ev = redact_evidence_text(finding.get("evidence", ""), max_len=12_000)
        summary_source = finding.get("evidence") or finding.get("description") or finding.get("title") or ""
        manual_rows.append(
            {
                **finding,
                "source": "manual",
                "source_record_id": str(finding.get("id") or ""),
                "recorded_at": str(
                    finding.get("updated_at")
                    or finding.get("created_at")
                    or engagement.get("updated_at")
                    or engagement.get("created_at")
                    or ""
                ),
                "evidence": redacted_ev,
                "redacted_summary": redact_evidence_text(summary_source, max_len=240),
                "affected_asset": finding.get("affected_asset") or engagement.get("target_url", ""),
                "owasp": finding.get("owasp_category", ""),
                "cwe": finding.get("cwe_id", ""),
            }
        )
    auto_rows = []
    for finding in automated:
        if not isinstance(finding, dict):
            continue
        redacted_ev = redact_evidence_text(finding.get("evidence", ""), max_len=12_000)
        summary_source = finding.get("evidence") or finding.get("description") or finding.get("title") or ""
        auto_rows.append(
            {
                **finding,
                "source": "automatic",
                "source_record_id": scan_id or str(finding.get("id") or ""),
                "recorded_at": scan_recorded_at,
                "evidence": redacted_ev,
                "redacted_summary": redact_evidence_text(summary_source, max_len=240),
                "affected_asset": engagement.get("target_url", ""),
            }
        )
    return manual_rows + auto_rows


def build_engagement_provenance(engagement: dict, *, finding_id: str | None = None) -> dict:
    engagement = _redact_export_payload(engagement)
    findings = _combined_engagement_findings(engagement)
    if finding_id is not None:
        target_id = str(finding_id).strip()
        findings = [
            item
            for item in findings
            if str(item.get("id") or "") == target_id or str(item.get("source_record_id") or "") == target_id
        ]
    tool_evidence_rows = []
    for link in engagement.get("tool_evidence", []) or []:
        if not isinstance(link, dict):
            continue
        tool_evidence_rows.append(
            {
                "source_record_id": str(link.get("id") or ""),
                "control_id": str(link.get("control_id") or ""),
                "tool_identity": str(link.get("tool_identity") or ""),
                "recorded_at": str(link.get("created_at") or ""),
                "report_sha256": str(link.get("report_sha256") or ""),
                "total_findings": int(link.get("total_findings") or 0),
                "rules_triggered": int(link.get("rules_triggered") or 0),
                "files_affected": int(link.get("files_affected") or 0),
                "redacted_summary": format_tool_evidence_redacted_summary(link),
            }
        )
    return {
        "engagement_id": engagement.get("id"),
        "engagement_name": engagement.get("name"),
        "target_url": engagement.get("target_url"),
        "finding_filter": redact_evidence_text(finding_id, max_len=0) if finding_id is not None else None,
        "tool_evidence_scope": "engagement_control",
        "findings": [
            {
                "id": item.get("id"),
                "source": item.get("source"),
                "source_record_id": item.get("source_record_id"),
                "recorded_at": item.get("recorded_at"),
                "severity": item.get("severity"),
                "status": item.get("status", "open"),
                "title": item.get("title"),
                "affected_asset": item.get("affected_asset"),
                "redacted_summary": item.get("redacted_summary"),
            }
            for item in findings
        ],
        "tool_evidence": tool_evidence_rows,
    }


def _csv_safe(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return value
    rendered = str(value)
    if rendered and rendered[0] in ("\t", "\r", "\n", "\x00"):
        return "'" + rendered
    if rendered.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠")):
        return "'" + rendered
    return rendered


def render_engagement_csv(engagement: dict) -> str:
    engagement = _redact_export_payload(engagement)
    output = io.StringIO(newline="")
    fields = [
        "source", "id", "severity", "status", "title", "affected_asset", "owasp", "cwe",
        "cvss_score", "cvss_vector", "remediation_owner", "due_date", "description", "impact",
        "evidence", "recommendation", "resolution_notes", "resolved_at", "last_retested_at",
        "record_type", "source_record_id", "recorded_at", "redacted_summary",
        "control_id", "tool_identity", "report_sha256", "total_findings", "rules_triggered", "files_affected",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for finding in _combined_engagement_findings(engagement):
        row = {**finding, "record_type": "finding"}
        writer.writerow({field: _csv_safe(row.get(field, "")) for field in fields})
    for link in build_engagement_provenance(engagement)["tool_evidence"]:
        row = {
            "record_type": "tool_evidence",
            "source": "tool_evidence",
            "id": link["source_record_id"],
            **link,
        }
        writer.writerow({field: _csv_safe(row.get(field, "")) for field in fields})
    return output.getvalue()


def render_engagement_sarif(engagement: dict) -> dict:
    engagement = _redact_export_payload(engagement)
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()
    for finding in _combined_engagement_findings(engagement):
        finding_id = str(finding.get("id") or "finding")
        rule_id = f"SNIPER-{finding.get('source', 'finding').upper()}-{finding_id}"
        if rule_id not in seen_rules:
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": str(finding.get("title") or "Sniper bulgusu")},
                    "fullDescription": {"text": redact_evidence_text(finding.get("description") or "", max_len=12_000)},
                    "help": {"text": str(finding.get("recommendation") or "")},
                    "properties": {
                        "source": finding.get("source"),
                        "severity": finding.get("severity"),
                        "owasp": finding.get("owasp"),
                        "cwe": finding.get("cwe"),
                    },
                }
            )
            seen_rules.add(rule_id)
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(finding.get("severity", "info"), "note"),
                "message": {
                    "text": redact_evidence_text(
                        finding.get("description") or finding.get("title") or "Sniper bulgusu",
                        max_len=12_000,
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.get("affected_asset") or engagement.get("target_url", ""))
                            }
                        }
                    }
                ],
                "fingerprints": {"sniper/engagement/v1": finding_id},
                "properties": {
                    "source": finding.get("source"),
                    "status": finding.get("status"),
                    "sourceRecordId": finding.get("source_record_id"),
                    "recordedAt": finding.get("recorded_at"),
                    "redactedEvidenceSummary": finding.get("redacted_summary"),
                    "severity": finding.get("severity"),
                    "owasp": finding.get("owasp"),
                    "cwe": finding.get("cwe"),
                    "cvssScore": finding.get("cvss_score"),
                    "cvssVector": finding.get("cvss_vector"),
                    "remediationOwner": finding.get("remediation_owner"),
                    "dueDate": finding.get("due_date"),
                    "resolutionNotes": finding.get("resolution_notes"),
                },
            }
        )
    provenance = build_engagement_provenance(engagement)
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sniper",
                        "version": "1.1",
                        "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"sniper/engagement/{engagement.get('id', 'assessment')}"},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "engagementId": engagement.get("id"),
                            "target": engagement.get("target_url"),
                            "coveragePercent": (engagement.get("coverage") or {}).get("percent"),
                            "toolEvidenceProvenance": provenance["tool_evidence"],
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def test_status_label(status: str) -> str:
    return {
        "not_tested": "Test edilmedi",
        "passed": "Geçti",
        "failed": "Bulgu var",
        "needs_review": "İnceleme gerekli",
        "not_applicable": "Uygulanamaz",
    }.get(status, status)


def finding_status_label(status: str) -> str:
    return {
        "open": "Açık",
        "in_progress": "Üzerinde çalışılıyor",
        "retest_required": "Yeniden test bekliyor",
        "resolved": "Çözüldü",
        "reopened": "Yeniden açıldı",
        "risk_accepted": "Risk kabulü",
    }.get(status, status)


def render_engagement_report(engagement: dict) -> str:
    engagement = _redact_export_payload(engagement)
    esc = lambda value: html.escape(str(value) if value is not None else "")
    coverage = engagement.get("coverage", {})
    remediation = engagement.get("remediation", {})
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    combined = [
        {
            **item,
            "source_label": "Manuel" if item.get("source") == "manual" else "Otomatik temel tarama",
        }
        for item in _combined_engagement_findings(engagement)
    ]
    combined.sort(key=lambda item: severity_order.get(item.get("severity", "info"), 5))
    counts = {severity: sum(1 for item in combined if item.get("severity") == severity) for severity in severity_order}
    finding_rows = "".join(
        f"""
        <article class="finding {esc(item.get('severity'))}">
          <div class="finding-head"><span>{esc(item.get('severity', '').upper())}</span><b>{esc(item.get('title'))}</b><small>{esc(item.get('source_label'))}</small></div>
          <p>{esc(item.get('description'))}</p>
          <dl><dt>Etkilenen varlık</dt><dd>{esc(item.get('affected_asset'))}</dd>
              <dt>Kaynak kaydı</dt><dd><code>{esc(item.get('source_record_id') or '—')}</code> · {esc(item.get('recorded_at') or '—')}</dd>
              <dt>İyileştirme durumu</dt><dd>{esc(finding_status_label(item.get('status', 'open')))}</dd>
              <dt>Sınıflandırma</dt><dd>{esc(' · '.join(value for value in (item.get('owasp_category') or item.get('owasp'), item.get('cwe_id') or item.get('cwe')) if value) or '—')}</dd>
              <dt>CVSS 3.1</dt><dd>{esc(f"{item.get('cvss_score'):.1f} · {item.get('cvss_vector')}" if item.get('cvss_score') is not None else '—')}</dd>
              <dt>Etki</dt><dd>{esc(item.get('impact', 'Otomatik bulgu; manuel etki değerlendirmesi önerilir.'))}</dd>
              <dt>Kanıt</dt><dd><code>{esc(item.get('evidence'))}</code></dd>
              <dt>Redakte kanıt özeti</dt><dd><code>{esc(item.get('redacted_summary') or '—')}</code></dd>
              <dt>Öneri</dt><dd>{esc(item.get('recommendation'))}</dd>
              <dt>Sorumlu / hedef</dt><dd>{esc(' · '.join(value for value in (item.get('remediation_owner'), item.get('due_date')) if value) or '—')}</dd>
              <dt>Çözüm / yeniden test</dt><dd>{esc(item.get('resolution_notes') or '—')}</dd>
              <dt>Zaman damgası</dt><dd>{esc(' · '.join(value for value in (item.get('resolved_at'), item.get('last_retested_at')) if value) or '—')}</dd></dl>
        </article>"""
        for item in combined
    ) or "<p>Kaydedilmiş açık bulgu bulunmuyor.</p>"
    category_rows = "".join(
        f"<tr><td>{esc(category['title'])}</td><td>{esc(category['completed'])} / {esc(category['total'])}</td><td>{esc(category['percent'])}%</td><td>{esc(category['reference'])}</td></tr>"
        for category in engagement.get("categories", [])
    )
    test_rows = "".join(
        f"<tr><td><code>{esc(test['control_id'])}</code></td><td>{esc(test['category_title'])}</td><td>{esc(test['title'])}</td><td>{esc(test_status_label(test['status']))}</td><td>{esc(test.get('notes'))}</td></tr>"
        for test in engagement.get("tests", [])
    )
    tool_evidence_rows = "".join(
        f"<tr><td><code>{esc(link.get('id'))}</code></td><td><code>{esc(link.get('control_id'))}</code></td><td><code>{esc(link.get('tool_identity'))}</code></td><td>{esc(link.get('created_at'))}</td><td><code>{esc(link.get('report_sha256'))}</code></td><td>{esc(format_tool_evidence_redacted_summary(link))}</td></tr>"
        for link in (engagement.get("tool_evidence") or [])
        if isinstance(link, dict)
    ) or '<tr><td colspan="6">Bağlı toplu araç kanıtı bulunmuyor.</td></tr>'
    approvals = engagement.get("special_approvals", {})
    approval_text = ", ".join(
        label
        for key, label in (
            ("controlled_lockout", "Kontrollü hesap kilitlenme doğrulaması"),
            ("staging_capacity", "Staging kapasite testi gözlemi"),
            ("redacted_data_proof", "Maskeli veri sızıntısı kanıtı"),
        )
        if approvals.get(key)
    ) or "Özel onaylı doğrulama yok"
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>Sniper manuel sızma testi raporu</title>
    <style>
    :root{{--ink:#13231e;--muted:#61716b;--line:#dce5df;--paper:#fff;--bg:#f3f6f4;--green:#0e7a54;--red:#bd3b45;--amber:#b8780e;--blue:#2f7088}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,Arial,sans-serif}}main{{max-width:980px;margin:35px auto;background:var(--paper);padding:50px;border:1px solid var(--line)}}
    header{{display:flex;justify-content:space-between;gap:24px;border-bottom:2px solid var(--ink);padding-bottom:25px}}h1{{font-size:29px;margin:0 0 7px}}h2{{margin:40px 0 14px;font-size:21px}}h3{{font-size:15px}}.brand{{letter-spacing:.15em;font-weight:800;color:var(--green)}}
    .coverage{{font-size:42px;font-weight:800;line-height:1;text-align:right}}.coverage small{{display:block;font-size:10px;color:var(--muted);margin-top:6px}}.meta,.counts{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:23px 0}}.card{{padding:13px;border:1px solid var(--line);background:#f9fbfa}}.card small,dt{{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.07em}}.card b{{display:block;font-size:15px;overflow-wrap:anywhere}}
    .scope{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}.scope>div{{border:1px solid var(--line);padding:16px}}.scope p{{white-space:pre-wrap}}table{{width:100%;border-collapse:collapse;font-size:11px}}th,td{{border:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}th{{background:#f4f7f5;color:var(--muted);text-transform:uppercase;font-size:9px;letter-spacing:.06em}}
    .finding{{border:1px solid var(--line);border-left:5px solid var(--blue);padding:18px;margin:12px 0;break-inside:avoid}}.finding.high,.finding.critical{{border-left-color:var(--red)}}.finding.medium{{border-left-color:var(--amber)}}.finding-head{{display:flex;gap:11px;align-items:center}}.finding-head span{{font-size:9px;font-weight:900}}.finding-head small{{margin-left:auto;color:var(--muted)}}dl{{display:grid;grid-template-columns:115px 1fr;gap:7px 13px}}dd{{margin:0}}code{{white-space:pre-wrap;overflow-wrap:anywhere}}
    .summary{{white-space:pre-wrap;border-left:4px solid var(--green);padding:4px 0 4px 16px}}footer{{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}}
    @media print{{body{{background:white}}main{{border:0;margin:0;max-width:none;padding:18px}}h2{{break-after:avoid}}table,.finding{{break-inside:avoid}}}}@media(max-width:700px){{main{{margin:0;padding:24px}}header{{display:block}}.coverage{{text-align:left;margin-top:15px}}.meta,.counts,.scope{{grid-template-columns:1fr 1fr}}}}
    </style></head><body><main>
    <header><div><div class="brand">SNIPER / MANUEL SIZMA TESTİ</div><h1>{esc(engagement.get('name'))}</h1><div>{esc(engagement.get('target_url'))}</div></div><div class="coverage">{esc(coverage.get('percent', 0))}%<small>METODOLOJİ KAPSAMI</small></div></header>
    <section class="meta"><div class="card"><small>Denetim kimliği</small><b>{esc(engagement.get('id'))}</b></div><div class="card"><small>Durum</small><b>{esc(engagement.get('status'))}</b></div><div class="card"><small>Yetki referansı</small><b>{esc(engagement.get('authorization_ref') or 'Belirtilmedi')}</b></div><div class="card"><small>Test penceresi</small><b>{esc(engagement.get('test_window') or 'Belirtilmedi')}</b></div></section>
    <section class="counts"><div class="card"><small>Kritik</small><b>{counts['critical']}</b></div><div class="card"><small>Yüksek</small><b>{counts['high']}</b></div><div class="card"><small>Orta</small><b>{counts['medium']}</b></div><div class="card"><small>Düşük</small><b>{counts['low']}</b></div></section>
    <section class="counts"><div class="card"><small>Etkin bulgu</small><b>{esc(remediation.get('active', 0))}</b></div><div class="card"><small>Geciken</small><b>{esc(remediation.get('overdue', 0))}</b></div><div class="card"><small>Yeniden test</small><b>{esc(remediation.get('retest', 0))}</b></div><div class="card"><small>Çözülen</small><b>{esc(remediation.get('resolved', 0))}</b></div></section>
    <h2>Yönetici özeti</h2><p class="summary">{esc(engagement.get('executive_summary') or 'Yönetici özeti henüz yazılmadı.')}</p>
    <h2>Kapsam ve çalışma kuralları</h2><section class="scope"><div><h3>Kapsam içi</h3><p>{esc(engagement.get('scope_notes') or 'Belirtilmedi')}</p></div><div><h3>Kapsam dışı</h3><p>{esc(engagement.get('out_of_scope') or 'Belirtilmedi')}</p></div></section><p><b>Özel onaylar:</b> {esc(approval_text)}</p>
    <h2>Bulgular</h2>{finding_rows}
    <h2>Metodoloji kapsamı</h2><table><thead><tr><th>Kategori</th><th>Tamamlanan</th><th>Kapsam</th><th>Referans</th></tr></thead><tbody>{category_rows}</tbody></table>
    <h2>Test günlüğü</h2><table><thead><tr><th>Kontrol</th><th>Kategori</th><th>Test</th><th>Durum</th><th>Not</th></tr></thead><tbody>{test_rows}</tbody></table>
    <h2>Bağlı toplu araç kanıtları</h2><table><thead><tr><th>Kanıt kaydı</th><th>Kontrol</th><th>Araç / Biçim</th><th>Kaydedilme zamanı</th><th>Rapor SHA-256</th><th>Redakte özet</th></tr></thead><tbody>{tool_evidence_rows}</tbody></table>
    <footer>Sniper yerel denetim kaydı · Otomatik temel tarama ve manuel test kanıtlarını birleştirir. Özel onaylı doğrulamalar trafik üretmez; yalnızca yetkili test uzmanının güvenli kanıtını kaydeder.</footer>
    </main></body></html>"""


def export_engagement_provenance(
    engagement_id: str,
    *,
    finding_id: str | None = None,
    view: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
    store: Any = None,
) -> dict | None:
    """Export engagement provenance as JSON, HTML, SARIF, or CSV."""
    if store is None:
        from storage import Store
        import server as srv

        store = Store(db_path or srv.DB_PATH)
    engagement = store.get_engagement(engagement_id)
    if not engagement:
        return None
    normalized_view = (view or "json").strip().lower()
    if normalized_view == "html":
        rendered = render_engagement_report(engagement)
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
        return {
            "engagement_id": engagement_id,
            "view": "html",
            "output": str(output) if output is not None else None,
            "bytes": len(rendered.encode("utf-8")),
        }
    if normalized_view == "sarif":
        sarif = render_engagement_sarif(engagement)
        if output is not None:
            output.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
            return {
                "engagement_id": engagement_id,
                "view": "sarif",
                "output": str(output),
                "results": len(sarif.get("runs", [{}])[0].get("results", [])),
            }
        return sarif
    if normalized_view == "csv":
        csv_text = render_engagement_csv(engagement)
        if output is not None:
            output.write_text(csv_text, encoding="utf-8")
        return {
            "engagement_id": engagement_id,
            "view": "csv",
            "output": str(output) if output is not None else None,
            "bytes": len(csv_text.encode("utf-8")),
        }
    provenance = build_engagement_provenance(engagement, finding_id=finding_id)
    if output is not None:
        output.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
    return provenance
