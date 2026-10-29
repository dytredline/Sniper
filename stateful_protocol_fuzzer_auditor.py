"""Wave 6 — Durum Bilgili (Stateful) Çoklu Protokol Durum Makinesi Denetçisi ve Sıra Dışı (Out-of-Order) Dizi Bulandırıcısı.

WebSocket (`ws.on("message")`, `onmessage`), gRPC akışları (`stream.Recv()`), MQTT ve
çok adımlı iş akışı denetleyicilerinde:
1. `SNIPER-STATE-SKIP-01` (CWE-841, critical): Kimlik doğrulama / MFA / el sıkışma
   adımı (`AUTH`, `LOGIN`, `VERIFY_MFA`) tanımlı olduğu halde, ayrıcalıklı işlem
   dalının (`TRANSFER_FUNDS`, `EXECUTE`, `ADMIN_CMD`, `EXPORT_DATA`, `DELETE_ACCOUNT`,
   `COMPLETE_ORDER` vb.) oturum durumunu (`isAuthenticated`, `authenticated`,
   `mfa_verified`, `state == "AUTHENTICATED"`) doğrulamadan çalışması.
2. `SNIPER-STATE-REPLAY-02` (CWE-294, high): Durum değiştiren protokol mesajlarında
   monotonik sıra numarası / tek kullanımlık anahtar (`seq`, `lastSeq`, `nonce`,
   `message_id`, `timestamp`, `version`) kontrolünün bulunmaması veya oturum
   ayrıcalıklarını sıfırlamadan başlangıç durumuna (`INIT`, `RESET`) geri sarma
   (rollback) izni verilmesi.
"""

from __future__ import annotations

from itertools import permutations
import re
from typing import Any

AUDIT_FORMAT_VERSION = "sniper-stateful-protocol-audit/1"
FUZZ_FORMAT_VERSION = "sniper-stateful-sequence-fuzz-proof/1"

_INITIAL_STATES = frozenset(
    {
        "INIT",
        "CONNECT",
        "CONNECTED",
        "HANDSHAKE",
        "AUTH_CHALLENGE",
        "START",
        "HELLO",
    }
)

_AUTH_GATE_STATES = frozenset(
    {
        "AUTH",
        "AUTHENTICATE",
        "AUTHENTICATED",
        "LOGIN",
        "VERIFY_MFA",
        "MFA_VERIFY",
        "MFA_VERIFIED",
        "VERIFY_OTP",
        "VERIFY_TOKEN",
        "HANDSHAKE_AUTH",
    }
)

_PRIVILEGED_ACTION_STATES = frozenset(
    {
        "EXECUTE",
        "EXECUTE_CMD",
        "TRANSFER",
        "TRANSFER_FUNDS",
        "WITHDRAW",
        "WITHDRAW_FUNDS",
        "ADMIN_CMD",
        "ADMIN_ACTION",
        "EXPORT",
        "EXPORT_DATA",
        "DELETE_ACCOUNT",
        "COMPLETE_ORDER",
        "CHECKOUT_COMPLETE",
        "SETTLE_PAYMENT",
        "DEPLOY",
        "GRANT_ROLE",
    }
)

_RESET_ROLLBACK_STATES = frozenset(
    {
        "RESET",
        "ROLLBACK",
        "REINIT",
        "RESTART_TRIAL",
        "DOWNGRADE",
    }
)

_BRANCH_HEADER_RE = re.compile(
    r"""(?:^\s*+case\s++(?:[A-Za-z0-9_]++\.)?['"]?([A-Z][A-Z0-9_]{1,40})['"]?\s*+:|^\s*+(?:el)?if\b[^\n{;:]{0,2048}?(?:type|action|step|stage|cmd|command|event|state)\s*+['"\]]*+\s*+[=!]==?\s*+['"]([A-Z][A-Z0-9_]{1,40})['"])""",
    re.MULTILINE,
)

_AUTH_STATE_ASSIGN_RE = re.compile(
    r"""(?:\b(?:isAuthenticated|authenticated|authed|mfa_verified|mfaVerified|isVerified)\s*=\s*(?:true|True|1)\b|\b(?:state|step|stage)\s*=\s*['"](?:AUTHENTICATED|MFA_VERIFIED|VERIFIED|AUTHORIZED)['"])"""
)

_STATE_GUARD_CHECK_RE = re.compile(
    r"""(?:\b(?:isAuthenticated|authenticated|authed|mfa_verified|mfaVerified|isVerified|require_auth|ensure_authenticated|check_auth|assert_authenticated|verify_state)\b|\b(?:state|step|stage)\s*(?:!==?|===?|==|!=|\bin\b)\s*['"](?:AUTHENTICATED|MFA_VERIFIED|VERIFIED|AUTHORIZED)['"])"""
)

_PRIVILEGED_SINK_CALL_RE = re.compile(
    r"""\b(?:wallet\.transfer|transferFunds|transfer|withdraw|executeCommand|execCommand|deleteAccount|exportData|completeOrder|settlePayment|grantRole|adminExecute)\s*\("""
)

_SEQUENCE_NONCE_GUARD_RE = re.compile(
    r"""\b(?:seq|lastSeq|last_seq|sequence|seq_num|nonce|seen_nonces|message_id|msg_id|timestamp|replay_guard|anti_replay|version)\b"""
)

_PRIVILEGE_INVALIDATION_RE = re.compile(
    r"""(?:\b(?:isAuthenticated|authenticated|authed|mfa_verified|mfaVerified)\s*=\s*(?:false|False|0)\b|\b(?:destroy|clear|invalidate|revoke|resetSession)\s*\()"""
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _extract_protocol_branches(raw_content: str) -> list[dict[str, Any]]:
    matches = list(_BRANCH_HEADER_RE.finditer(raw_content))
    branches: list[dict[str, Any]] = []
    for idx, m in enumerate(matches):
        state_name = (m.group(1) or m.group(2) or "").strip()
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(raw_content)
        body = raw_content[start:end]
        branches.append(
            {
                "name": state_name,
                "start": start,
                "end": end,
                "line": _line_number(raw_content, start),
                "body": body,
                "evidence": m.group(0).strip(),
            }
        )
    return branches


def audit_stateful_protocol_state_machine(
    raw_content: str,
    *,
    filename: str = "ws_handler.ts",
) -> dict[str, Any]:
    """Durum bilgili protokol işleyicilerinde adım atlama (SNIPER-STATE-SKIP-01) ve tekrar/geri sarma (SNIPER-STATE-REPLAY-02) zafiyetlerini denetler."""
    content = str(raw_content or "")
    branches = _extract_protocol_branches(content)

    detected_states: list[str] = []
    for b in branches:
        if b["name"] and b["name"] not in detected_states:
            detected_states.append(b["name"])

    for assign_m in re.finditer(
        r"""\b(?:state|step|stage)\s*=\s*['"]([A-Z][A-Z0-9_]{1,40})['"]""",
        content,
    ):
        st = assign_m.group(1)
        if st not in detected_states:
            detected_states.append(st)

    findings: list[dict[str, Any]] = []
    unprotected_actions: list[str] = []

    preamble = content[: branches[0]["start"]] if branches else content
    has_global_auth_guard = bool(_STATE_GUARD_CHECK_RE.search(preamble))
    has_global_seq_guard = bool(_SEQUENCE_NONCE_GUARD_RE.search(content))

    has_auth_gate = any(
        b["name"] in _AUTH_GATE_STATES or _AUTH_STATE_ASSIGN_RE.search(b["body"])
        for b in branches
    ) or bool(_AUTH_STATE_ASSIGN_RE.search(content))

    for b in branches:
        b_name = b["name"]
        b_body = b["body"]
        is_privileged_branch = (
            b_name in _PRIVILEGED_ACTION_STATES
            or (
                b_name not in _INITIAL_STATES
                and b_name not in _AUTH_GATE_STATES
                and bool(_PRIVILEGED_SINK_CALL_RE.search(b_body))
            )
        )

        # 1) SNIPER-STATE-SKIP-01: Ayrıcalıklı dalda durum/kimlik doğrulama kontrolü eksikliği
        if has_auth_gate and is_privileged_branch:
            has_branch_guard = has_global_auth_guard or bool(
                _STATE_GUARD_CHECK_RE.search(b_body)
            )
            if not has_branch_guard:
                if b_name not in unprotected_actions:
                    unprotected_actions.append(b_name)
                findings.append(
                    {
                        "rule_id": "SNIPER-STATE-SKIP-01",
                        "cwe": "CWE-841",
                        "reference": "CWE-841",
                        "severity": "critical",
                        "category": "business_logic",
                        "title": "Durum Bilgili (Stateful) protokolde sıra dışı mesajla kimlik/adım atlama (Out-of-Order State Skipping)",
                        "description": (
                            f"`{filename}` içindeki `{b_name}` ayrıcalıklı durum dalı, oturumun kimlik doğrulama "
                            "veya önceki adım durumunu (`isAuthenticated`, `authenticated`, `mfa_verified`, "
                            "`state == 'AUTHENTICATED'`) doğrulamadan işlemi yürütüyor."
                        ),
                        "remediation": (
                            f"`{b_name}` dalının başında oturum durumunu açıkça doğrulayın "
                            "(ör. `if (!ws.isAuthenticated) return;`) ve geçersiz durum geçişlerini reddedin."
                        ),
                        "filename": filename,
                        "line": b["line"],
                        "state": b_name,
                        "evidence": b["evidence"],
                    }
                )

        # 2a) SNIPER-STATE-REPLAY-02: Geri sarma (Rollback / Reset) dalında ayrıcalıkların sıfırlanmaması
        if b_name in _RESET_ROLLBACK_STATES or (
            b_name in _INITIAL_STATES
            and re.search(r"\b(?:state|step|stage)\s*=", b_body)
            and has_auth_gate
            and len(branches) >= 2
        ):
            if b_name in _RESET_ROLLBACK_STATES and not _PRIVILEGE_INVALIDATION_RE.search(
                b_body
            ):
                findings.append(
                    {
                        "rule_id": "SNIPER-STATE-REPLAY-02",
                        "cwe": "CWE-294",
                        "reference": "CWE-294",
                        "severity": "high",
                        "category": "protocol",
                        "title": "Durum geçiş mesajlarında sıra numarası (sequence/nonce) veya geri sarma (rollback) koruması eksikliği",
                        "description": (
                            f"`{filename}` içindeki `{b_name}` dalı durum makinesini başlangıç/deneme adımına "
                            "geri sararken oturum ayrıcalıklarını (`isAuthenticated = false`) geçersiz kılmıyor."
                        ),
                        "remediation": (
                            "Durum sıfırlama/geri sarma mesajlarında tüm kimlik doğrulama bayraklarını ve "
                            "oturum anahtarlarını sıfırlayın."
                        ),
                        "filename": filename,
                        "line": b["line"],
                        "state": b_name,
                        "evidence": b["evidence"],
                    }
                )

    # 2b) SNIPER-STATE-REPLAY-02: Durum değiştiren protokolde sıra numarası (seq/nonce) kontrolü eksikliği
    if branches and has_auth_gate and not has_global_seq_guard:
        anchor_branch = next(
            (b for b in branches if b["name"] in _PRIVILEGED_ACTION_STATES),
            branches[0],
        )
        findings.append(
            {
                "rule_id": "SNIPER-STATE-REPLAY-02",
                "cwe": "CWE-294",
                "reference": "CWE-294",
                "severity": "high",
                "category": "protocol",
                "title": "Durum geçiş mesajlarında sıra numarası (sequence/nonce) veya geri sarma (rollback) koruması eksikliği",
                "description": (
                    f"`{filename}` durum bilgili mesaj işleyicisi durum değiştiren çerçeveleri işlerken "
                    "monotonik sıra numarası (`seq`, `lastSeq`) veya tek kullanımlık `nonce` doğrulaması yapmıyor."
                ),
                "remediation": (
                    "Her durum geçiş mesajında monotonik artan `msg.seq > ws.lastSeq` veya benzersiz `nonce` "
                    "doğrulaması uygulayın."
                ),
                "filename": filename,
                "line": anchor_branch["line"],
                "state": anchor_branch["name"],
                "evidence": anchor_branch["evidence"],
            }
        )

    return {
        "format": AUDIT_FORMAT_VERSION,
        "filename": filename,
        "detected_states": detected_states,
        "unprotected_terminal_actions": unprotected_actions,
        "finding_count": len(findings),
        "findings": findings,
    }


def _collect_transitive_predecessors(
    state: str,
    required_predecessors: dict[str, list[str]],
) -> set[str]:
    """Bir durumun doğrudan ve geçişli (transitive) tüm zorunlu öncül durumlarını döndürür."""
    visited: set[str] = set()
    stack = list(required_predecessors.get(state, []))
    while stack:
        curr = stack.pop()
        if curr == state or curr in visited:
            continue
        visited.add(curr)
        for parent in required_predecessors.get(curr, []):
            if parent not in visited:
                stack.append(parent)
    return visited


def _generate_default_candidate_sequences(
    initial_state: str,
    all_states: list[str],
) -> list[list[str]]:
    """Başlangıç durumundan hedef durumlara giden sıra dışı (out-of-order) ve tam aday dizileri üretir."""
    non_initial = [s for s in all_states if s != initial_state]
    sequences: list[list[str]] = []

    for r in range(1, min(len(non_initial), 4) + 1):
        for perm in permutations(non_initial, r):
            sequences.append([initial_state, *perm])

    return sequences


def simulate_out_of_order_state_sequence(
    state_machine_spec: dict[str, Any],
    *,
    candidate_sequences: list[list[str]] | None = None,
) -> dict[str, Any]:
    """Durum makinesi tanımındaki (`required_predecessors` vs `enforced_guards`) sıra dışı adım atlama dizilerini simüle eder."""
    spec = state_machine_spec or {}
    initial_state = str(spec.get("initial_state") or "INIT")
    raw_required = spec.get("required_predecessors") or {}
    raw_enforced = spec.get("enforced_guards") or {}

    required_predecessors: dict[str, list[str]] = {
        str(k): [str(x) for x in (v or [])] for k, v in raw_required.items()
    }
    enforced_guards: dict[str, list[str]] = {
        str(k): [str(x) for x in (v or [])] for k, v in raw_enforced.items()
    }

    all_states: list[str] = []
    for s in [initial_state, *required_predecessors.keys(), *enforced_guards.keys()]:
        if s not in all_states:
            all_states.append(s)

    sequences_to_test = (
        [list(seq) for seq in candidate_sequences]
        if candidate_sequences is not None
        else _generate_default_candidate_sequences(initial_state, all_states)
    )

    bypasses: list[list[str]] = []
    for seq in sequences_to_test:
        if not seq:
            continue
        visited: set[str] = set()
        allowed_by_enforced = True
        bypass_triggered_on_last = False

        for idx, step in enumerate(seq):
            if idx == 0 and step == initial_state:
                visited.add(step)
                continue

            guards = enforced_guards.get(step, [])
            if any(g not in visited for g in guards):
                allowed_by_enforced = False
                break

            all_req = _collect_transitive_predecessors(step, required_predecessors)
            missing_req = all_req - visited
            if idx == len(seq) - 1 and missing_req:
                bypass_triggered_on_last = True

            visited.add(step)

        if allowed_by_enforced and bypass_triggered_on_last:
            if seq not in bypasses:
                bypasses.append(seq)

    return {
        "format": FUZZ_FORMAT_VERSION,
        "bypass_found": bool(bypasses),
        "bypass_sequences": bypasses,
        "tested_sequence_count": len(sequences_to_test),
    }
