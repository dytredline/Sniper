from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from audit_integrity import KeyState, compute_hmac_entry_hash, is_hmac_hash


GENESIS_HASH = "0" * 64


def _canonical_json(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    text = str(value).strip()
    if text.startswith("{") or text.startswith("["):
        try:
            parsed = json.loads(text)
            return json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except Exception:
            pass
    return text


def _safe_event_id(event: dict[str, Any]) -> int:
    raw = event.get("id")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def verify_audit_log_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Verilen olay listesi üzerinde zincir HESAPLAR (dışa aktarılmış listeler için).

    Kalıcı denetim günlüğünün bütünlüğü için bunu değil `Store.verify_audit_chain()` kullanın:
    bu işlev kayıtlarda saklı hash yoksa değişikliği/silmeyi göremez.
    """
    if not isinstance(events, list):
        raise ValueError("Denetim günlüğü olayları bir liste olmalıdır.")

    ordered = sorted(
        (e for e in events if isinstance(e, dict)),
        key=_safe_event_id,
    )

    prev_hash = GENESIS_HASH
    verified = True
    tampered_ids: list[Any] = []
    chain_entries: list[dict[str, Any]] = []

    for event in ordered:
        eid = event.get("id", "")
        occurred_at = str(event.get("occurred_at") or "")
        action = str(event.get("action") or "")
        entity_id = str(event.get("entity_id") or "")
        canonical_details = _canonical_json(event.get("details"))

        material = f"{prev_hash}|{eid}|{occurred_at}|{action}|{entity_id}|{canonical_details}"
        entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()

        recorded_prev = event.get("prev_hash")
        recorded_entry = event.get("entry_hash")
        entry_valid = True
        if isinstance(recorded_prev, str) and recorded_prev and recorded_prev != prev_hash:
            entry_valid = False
        if isinstance(recorded_entry, str) and recorded_entry and recorded_entry != entry_hash:
            entry_valid = False
        if not entry_valid:
            verified = False
            tampered_ids.append(eid)

        chain_entries.append({
            "id": eid,
            "occurred_at": occurred_at,
            "action": action,
            "entity_id": entity_id,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "valid": entry_valid,
        })
        prev_hash = entry_hash

    return {
        "format": "sniper-audit-chain-verification-v1",
        "verified": verified,
        "event_count": len(ordered),
        "genesis_hash": GENESIS_HASH,
        "head_hash": prev_hash,
        "tampered_ids": tampered_ids,
        "chain_tail": chain_entries[-25:],
    }


# --- Kalıcı (veritabanında saklı) hash zinciri -------------------------------------------------
#
# `verify_audit_log_chain` yalnız verilen olay listesi üzerinde zincir HESAPLAR; kayıtlarda saklı
# hash yoksa hiçbir şeyi doğrulayamaz. Aşağıdaki işlevler `audit_log.prev_hash/entry_hash`
# sütunlarına yazılan kalıcı zinciri tüm tabloyu id ASC sırasıyla akış hâlinde doğrular.

STORED_CHAIN_FORMAT = "sniper-audit-chain-verification-v1"
STORED_CHAIN_SCHEME = "sniper-audit-entry-v1"
_TAIL_LIMIT = 25
_TAMPERED_ID_LIMIT = 100


def compute_audit_entry_hash(
    prev_hash: str,
    occurred_at: str,
    action: str,
    entity_id: str,
    details_json: str,
) -> str:
    """Kaydın kanonik JSON'u + prev_hash üzerinden SHA-256.

    Kapsanan alanlar: occurred_at, action, entity_id, details_json (veritabanında saklandığı
    biçimiyle, bayt bayt) ve prev_hash. `id` bilinçli olarak dışarıda: silme/sıra bozulması
    prev_hash bağlantısıyla yakalanır.
    """
    material = json.dumps(
        {
            "scheme": STORED_CHAIN_SCHEME,
            "prev_hash": str(prev_hash),
            "occurred_at": str(occurred_at),
            "action": str(action),
            "entity_id": str(entity_id),
            "details_json": str(details_json),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class StoredAuditChainVerifier:
    """id ASC sırasıyla gelen saklı kayıtları akış hâlinde (bellek dostu) doğrular.

    Kurallar:
    - İlk hash'li kayıttan önceki hash'siz kayıtlar "legacy" sayılır (legacy_unchained).
    - Zincir ilk hash'li kayıtta GENESIS_HASH ile başlar.
    - Zincir başladıktan sonra: hash'siz kayıt, prev_hash bağlantı kopukluğu (silme/sıra) veya
      yeniden hesaplanan entry_hash uyuşmazlığı (değişiklik) -> verified=False.
    - ``hmac1:`` önekli kayıtlar anahtarla (HMAC-SHA256) doğrulanır; anahtar yoksa doğrulanamaz
      sayılır (verified=False, integrity=unverifiable). İlk HMAC'li kayıttan sonra gelen anahtarsız
      SHA-256 kaydı şema düşürme (scheme_downgrade) olarak işaretlenir.
    - `apply_anchor` veritabanı dışı çapayla kuyruk silinmesini/geri sarmayı denetler.
    """

    def __init__(self, *, key: bytes | None = None, watch_id: int | None = None) -> None:
        self._key = key
        self._watch_id = watch_id
        self.watch_entry_hash: str | None = None
        self.watch_chained_count: int | None = None
        self.hmac_count = 0
        self.plain_count = 0
        self.unverifiable_hmac = 0
        self.max_id: Any = None
        self.chained_after_watch = 0
        self.event_count = 0
        self.legacy_unchained = 0
        self.chained_count = 0
        self.verified = True
        self.first_broken_id: Any = None
        self.first_broken_reason = ""
        self.tampered_ids: list[Any] = []
        self.head_hash = GENESIS_HASH
        self._chain_started = False
        self._expected_prev = GENESIS_HASH
        self._tail: list[dict[str, Any]] = []

    def _mark_broken(self, eid: Any, reason: str) -> None:
        if self.verified:
            self.first_broken_id = eid
            self.first_broken_reason = reason
        self.verified = False
        if len(self.tampered_ids) < _TAMPERED_ID_LIMIT:
            self.tampered_ids.append(eid)

    def feed(self, row: Any) -> None:
        eid = row["id"]
        prev_hash = row["prev_hash"]
        entry_hash = row["entry_hash"]
        self.event_count += 1
        self.max_id = eid
        has_hash = bool(prev_hash) or bool(entry_hash)
        if not self._chain_started and not has_hash:
            self.legacy_unchained += 1
            return
        self._chain_started = True
        if not has_hash:
            # Zincir başladıktan sonra hash'siz kayıt: zincir dışı ekleme ya da hash silme.
            self._mark_broken(eid, "unchained_after_chain_start")
            self._append_tail(eid, row, "", "", False)
            return
        self.chained_count += 1
        valid = True
        reason = ""
        if prev_hash != self._expected_prev:
            valid = False
            reason = "prev_hash_mismatch"
        fields = (
            str(prev_hash or ""),
            row["occurred_at"] or "",
            row["action"] or "",
            row["entity_id"] or "",
            row["details_json"] or "",
        )
        if is_hmac_hash(entry_hash):
            self.hmac_count += 1
            if self._key is None:
                # Anahtarsız HMAC doğrulanamaz; bağlantı yine denetlenir, kayıt kurcalanmış sayılmaz.
                self.unverifiable_hmac += 1
                recomputed = str(entry_hash)
            else:
                recomputed = compute_hmac_entry_hash(self._key, *fields)
                if not hmac.compare_digest(recomputed, str(entry_hash)):
                    valid = False
                    reason = reason or "entry_hash_mismatch"
        else:
            self.plain_count += 1
            recomputed = compute_audit_entry_hash(*fields)
            if recomputed != entry_hash:
                valid = False
                reason = reason or "entry_hash_mismatch"
            elif self.hmac_count:
                valid = False
                reason = reason or "scheme_downgrade"
        if self._watch_id is not None:
            if eid == self._watch_id:
                self.watch_entry_hash = str(entry_hash or "")
                self.watch_chained_count = self.chained_count
            elif self.watch_entry_hash is not None:
                self.chained_after_watch += 1
        if not valid:
            self._mark_broken(eid, reason)
        self._append_tail(eid, row, str(prev_hash or ""), str(entry_hash or ""), valid)
        # Tek bir değişikliğin sonraki tüm kayıtları bozuk göstermemesi için saklı hash'le devam.
        self._expected_prev = str(entry_hash or recomputed)
        self.head_hash = self._expected_prev

    def _append_tail(self, eid: Any, row: Any, prev_hash: str, entry_hash: str, valid: bool) -> None:
        self._tail.append({
            "id": eid,
            "occurred_at": str(row["occurred_at"] or ""),
            "action": str(row["action"] or ""),
            "entity_id": str(row["entity_id"] or ""),
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "valid": valid,
        })
        if len(self._tail) > _TAIL_LIMIT:
            del self._tail[0]

    def apply_anchor(self, result: dict[str, Any], anchor: dict[str, Any], key_state: KeyState) -> dict[str, Any]:
        """`result()` çıktısına anahtar ve çapa denetimini ekle (verified'ı yalnız daraltır)."""
        hmac_info = {
            "status": key_state.status,
            "message": key_state.message,
            "key_id": key_state.key_id,
            "hmac_entries": self.hmac_count,
            "plain_entries": self.plain_count,
            "unverifiable_entries": self.unverifiable_hmac,
        }
        anchor_info: dict[str, Any] = {
            "status": anchor.get("status", "missing"),
            "authenticated": bool(anchor.get("authenticated")),
            "last_id": anchor.get("last_id"),
            "head_matches": None,
            "entries_after_anchor": 0,
        }
        problems: list[str] = []
        if self.unverifiable_hmac:
            problems.append("hmac_key_unavailable")
        status = anchor_info["status"]
        if status in {"ok", "unauthenticated", "unverifiable"}:
            last_id = anchor.get("last_id")
            if self.watch_entry_hash is None:
                anchor_info["head_matches"] = False
                problems.append("anchor_tail_truncated" if self.max_id is None or last_id > self.max_id
                                else "anchor_head_missing")
            else:
                matches = (hmac.compare_digest(self.watch_entry_hash, str(anchor.get("head_hash") or ""))
                           and self.watch_chained_count == anchor.get("chained_count"))
                anchor_info["head_matches"] = matches
                anchor_info["entries_after_anchor"] = self.chained_after_watch
                if not matches:
                    problems.append("anchor_head_mismatch")
            if status == "unverifiable" and self.hmac_count:
                problems.append("anchor_unverifiable")
            if status == "unauthenticated" and key_state.usable and self.hmac_count:
                problems.append("anchor_unauthenticated")
        elif status == "missing":
            if self.hmac_count:
                problems.append("anchor_missing")
        else:  # mac_invalid, db_mismatch, invalid, insecure, unreadable
            problems.append(f"anchor_{status}")
        result = dict(result)
        result["hmac"] = hmac_info
        result["anchor"] = anchor_info
        result["integrity_problems"] = problems
        if problems:
            result["verified"] = False
            if not result.get("first_broken_reason"):
                result["first_broken_reason"] = problems[0]
        if not result["verified"]:
            result["integrity"] = "broken" if (self.tampered_ids or any(
                p not in {"hmac_key_unavailable", "anchor_unverifiable"} for p in problems)) else "unverifiable"
        elif self.hmac_count and anchor_info["authenticated"]:
            result["integrity"] = "hmac_anchored"
        elif self.hmac_count:
            result["integrity"] = "hmac"
        else:
            result["integrity"] = "unkeyed"
        return result

    def result(self) -> dict[str, Any]:
        return {
            "format": STORED_CHAIN_FORMAT,
            "scheme": STORED_CHAIN_SCHEME,
            "source": "stored_chain",
            "verified": self.verified,
            "event_count": self.event_count,
            "chained_count": self.chained_count,
            "legacy_unchained": self.legacy_unchained,
            "first_broken_id": self.first_broken_id,
            "first_broken_reason": self.first_broken_reason,
            "genesis_hash": GENESIS_HASH,
            "head_hash": self.head_hash,
            "tampered_ids": list(self.tampered_ids),
            "chain_tail": list(self._tail),
        }


def build_signed_provenance_envelope(
    payload: dict[str, Any],
    *,
    audit_head_hash: str = "",
    scope_label: str = "sniper-report",
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Provenans zarfı yükü bir sözlük olmalıdır.")
    canonical_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload_sha256 = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
    effective_head = (audit_head_hash or "").strip() or GENESIS_HASH
    clean_scope = (scope_label or "sniper-report").strip() or "sniper-report"
    envelope_material = f"sniper-provenance-v1|{clean_scope}|{payload_sha256}|{effective_head}"
    envelope_sha256 = hashlib.sha256(envelope_material.encode("utf-8")).hexdigest()
    return {
        "format": "sniper-provenance-envelope-v1",
        "scope_label": clean_scope,
        "payload_sha256": payload_sha256,
        "audit_head_hash": effective_head,
        "envelope_sha256": envelope_sha256,
    }
