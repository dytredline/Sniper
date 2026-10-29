"""Wave 5 — Kriptografik Cüzdan Harcama Yetkisi ve Alan Ayrımı (Domain Separation) Denetleyicisi.

Kriptografik cüzdan, teklif (offer) çözümü ve imzalama akışlarındaki iki yüksek etkili
yetkilendirme / kriptografi zafiyetini tespit eder:
- SNIPER-WALLET-SPEND-01: Cüzdan/Teklif imzalama akışında örtük coin seçimi ve aşım
  kontrolsüz harcama yetkisi (Implicit Coin Spend — CWE-863).
- SNIPER-CRYPTO-DOMAIN-02: Kriptografik imzalama/doğrulama çağrısında alan ayrımı
  (Domain Separation / Genesis Challenge / ChainID) eksikliği (CWE-347).
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-wallet-signing-domain-audit/1"

_FUNC_HEADER_RE = re.compile(
    r"^[ \t]*(?:async[ \t]+def|def|async[ \t]+function|function|func|pub[ \t]+(?:async[ \t]+)?fn|fn)[ \t]+([A-Za-z0-9_]+)",
    re.MULTILINE,
)

_WALLET_ENTRY_FN_NAMES: frozenset[str] = frozenset(
    {
        "take_offer",
        "create_signed_transaction",
        "sign_coin_spends",
        "fulfill_offer",
        "build_spend_bundle",
        "accept_offer",
        "respond_to_offer",
    }
)

_COIN_SELECT_CALL_RE = re.compile(
    r"\b(select_coins|get_spendable_coins|select_spendable_coins)\s*\("
)

_SPEND_SIGN_CALL_RE = re.compile(
    r"\b(sign_coin_spends|generate_signed_transaction|generate_signed_transactions|build_spend_bundle)\s*\("
)

_SPEND_CAP_GUARD_RE = re.compile(
    r"(?:"
    r"\bassert_spend_within_user_cap\b"
    r"|\bverify_max_send_amount\b"
    r"|\bmax_authorized_amount\b"
    r"|\bmax_send_amount\b"
    r"|\buser_authorized_cap\b"
    r"|\bauthorized_asset_caps\b"
    r"|\bverify_spend_limits\b"
    r"|\bcheck_spend_cap\b"
    r"|\breject_unbounded_solver\b"
    r"|\bif\s+not\s+(?:requested_payments|authorized_amounts|max_amounts|user_caps|solver_caps)\b"
    r"|(?:selected_amount|total_selected|spend_amount|total_spend)\s*>\s*(?:max_|cap|authorized|limit)"
    r")"
)

_RAW_CRYPTO_SIGN_RE = re.compile(
    r"\b("
    r"AugSchemeMPL\.(?:sign|verify|aggregate_verify)"
    r"|BasicSchemeMPL\.(?:sign|verify)"
    r"|bls\.(?:sign|verify)"
    r"|ed25519_sign_raw"
    r"|secp256k1\.sign_recoverable"
    r")\s*\("
)

_DOMAIN_SEPARATION_GUARD_RE = re.compile(
    r"\b("
    r"GENESIS_CHALLENGE|genesis_challenge"
    r"|AGG_SIG_ME_ADDITIONAL_DATA|agg_sig_me_additional_data"
    r"|domain_string|DOMAIN_STRING"
    r"|EIP712Domain|eip712_domain"
    r"|chain_id|chainId|CHAIN_ID"
    r"|domain_separator|DOMAIN_SEPARATOR|domainSeparator"
    r")\b"
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _extract_scopes(content: str) -> tuple[str, list[dict[str, Any]]]:
    """Modül başlığını ve fonksiyon bloklarını ayrıştırır."""
    matches = list(_FUNC_HEADER_RE.finditer(content))
    if not matches:
        return content, [
            {
                "name": "<module>",
                "start": 0,
                "end": len(content),
                "text": content,
            }
        ]

    preamble = content[: matches[0].start()]
    scopes: list[dict[str, Any]] = []
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
        scopes.append(
            {
                "name": m.group(1),
                "start": start,
                "end": end,
                "text": content[start:end],
            }
        )
    return preamble, scopes


def audit_wallet_signing_and_domain_separation(
    raw_content: str,
    *,
    filename: str = "wallet_rpc_api.py",
) -> dict[str, Any]:
    """Cüzdan örtük coin harcama yetkisi (Implicit Coin Spend) ve kriptografik alan ayrımı (Domain Separation) eksikliklerini denetler."""
    content = str(raw_content or "")
    findings: list[dict[str, Any]] = []
    if not content:
        return {
            "format": FORMAT_VERSION,
            "filename": filename,
            "finding_count": 0,
            "findings": findings,
        }

    preamble, scopes = _extract_scopes(content)

    # (a) SNIPER-WALLET-SPEND-01
    seen_spend_lines: set[int] = set()
    for scope in scopes:
        scope_text = scope["text"]
        fn_name = scope["name"]
        select_match = _COIN_SELECT_CALL_RE.search(scope_text)
        sign_match = _SPEND_SIGN_CALL_RE.search(scope_text)

        is_wallet_fn = fn_name in _WALLET_ENTRY_FN_NAMES
        has_select_and_sign = bool(
            select_match
            and (sign_match or fn_name in {"sign_coin_spends", "create_signed_transaction", "build_spend_bundle"})
        )

        if not (has_select_and_sign or (is_wallet_fn and select_match and sign_match)):
            continue

        if _SPEND_CAP_GUARD_RE.search(scope_text) or (len(scopes) == 1 and _SPEND_CAP_GUARD_RE.search(preamble)):
            continue

        anchor_match = sign_match or select_match
        assert anchor_match is not None
        abs_offset = scope["start"] + anchor_match.start()
        line_no = _line_number(content, abs_offset)
        if line_no in seen_spend_lines:
            continue
        seen_spend_lines.add(line_no)

        line_start = content.rfind("\n", 0, abs_offset) + 1
        line_end = content.find("\n", abs_offset)
        if line_end < 0:
            line_end = len(content)
        evidence_line = content[line_start:line_end].strip()

        title = "Cüzdan/Teklif imzalama akışında örtük coin seçimi ve aşım kontrolsüz harcama yetkisi (Implicit Coin Spend)"
        remediation = (
            "Coin seçimi (`select_coins` / `get_spendable_coins`) ve imzalama (`sign_coin_spends` / "
            "`generate_signed_transaction`) öncesinde kullanıcının onayladığı varlık bazlı azami harcama "
            "tutarını (`verify_max_send_amount` / `assert_spend_within_user_cap` / `max_authorized_amount`) "
            "açıkça doğrulayın ve sınırsız/boş çözücü (solver) isteklerini reddedin."
        )
        findings.append(
            {
                "control_id": "SNIPER-WALLET-SPEND-01",
                "rule_id": "SNIPER-WALLET-SPEND-01",
                "cwe": "CWE-863",
                "reference": "CWE-863",
                "severity": "high",
                "category": "authz",
                "title": title,
                "description": (
                    f"`{filename}` içindeki `{fn_name}` akışında `{select_match.group(1)}` ile coin seçilip "
                    f"`{(sign_match.group(1) if sign_match else fn_name)}` ile imzalanırken kullanıcının "
                    "yetkilendirdiği varlık bazlı üst harcama sınırı (`verify_max_send_amount` / "
                    "`assert_spend_within_user_cap` / `max_authorized_amount`) doğrulanmıyor."
                ),
                "remediation": remediation,
                "recommendation": remediation,
                "filename": filename,
                "file": filename,
                "line": line_no,
                "evidence": evidence_line,
            }
        )

    # (b) SNIPER-CRYPTO-DOMAIN-02
    seen_crypto_lines: set[int] = set()
    for m in _RAW_CRYPTO_SIGN_RE.finditer(content):
        call_offset = m.start()
        enclosing_scope_text = content
        for scope in scopes:
            if scope["start"] <= call_offset < scope["end"]:
                enclosing_scope_text = preamble + "\n" + scope["text"]
                break

        if _DOMAIN_SEPARATION_GUARD_RE.search(enclosing_scope_text):
            continue

        line_no = _line_number(content, call_offset)
        if line_no in seen_crypto_lines:
            continue
        seen_crypto_lines.add(line_no)

        line_start = content.rfind("\n", 0, call_offset) + 1
        line_end = content.find("\n", call_offset)
        if line_end < 0:
            line_end = len(content)
        evidence_line = content[line_start:line_end].strip()

        title = "Kriptografik imzalama/doğrulama çağrısında alan ayrımı (Domain Separation / Genesis Challenge / ChainID) eksikliği"
        remediation = (
            "İmzalanan veya doğrulanan mesaja protokol/ağ bağlamını (`GENESIS_CHALLENGE`, "
            "`AGG_SIG_ME_ADDITIONAL_DATA`, `domain_string`, `EIP712Domain`, `chain_id` veya "
            "`domain_separator`) kriptografik olarak bağlayın."
        )
        findings.append(
            {
                "control_id": "SNIPER-CRYPTO-DOMAIN-02",
                "rule_id": "SNIPER-CRYPTO-DOMAIN-02",
                "cwe": "CWE-347",
                "reference": "CWE-347",
                "severity": "high",
                "category": "crypto",
                "title": title,
                "description": (
                    f"`{filename}` içinde `{m.group(1)}` çağrısı ham mesaj/özet üzerinde alan ayrımı "
                    "(`GENESIS_CHALLENGE`, `AGG_SIG_ME_ADDITIONAL_DATA`, `domain_string`, `EIP712Domain`, "
                    "`chain_id`, `domain_separator`) bağlaması olmadan yürütülüyor; imzalar ağlar veya "
                    "mesaj türleri arasında yeniden oynatılabilir (Cross-Network / Cross-Context Replay)."
                ),
                "remediation": remediation,
                "recommendation": remediation,
                "filename": filename,
                "file": filename,
                "line": line_no,
                "evidence": evidence_line,
            }
        )

    return {
        "format": FORMAT_VERSION,
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }
