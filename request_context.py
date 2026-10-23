"""İstek / iş bağlamı: denetim kaydına işlemi yapan kullanıcıyı eklemek için.

Giriş kapalıyken hiçbir zaman ayarlanmaz; denetim kayıtları eskisiyle bayt bayt aynı kalır.
"""
from __future__ import annotations

import contextlib
import contextvars
from typing import Any, Iterator

ACTOR: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("sniper_actor", default=None)


def current_actor() -> dict[str, Any] | None:
    return ACTOR.get()


def actor_summary(user: dict[str, Any] | None) -> dict[str, Any] | None:
    if not user:
        return None
    return {"id": user.get("id"), "username": user.get("username"), "role": user.get("role")}


@contextlib.contextmanager
def acting_as(actor: dict[str, Any] | None) -> Iterator[None]:
    token = ACTOR.set(actor_summary(actor))
    try:
        yield
    finally:
        ACTOR.reset(token)


def with_actor(details_json: str) -> str:
    """Etkin kullanıcı varsa denetim ayrıntısına ``actor`` alanı ekle (yoksa girdi aynen döner)."""
    actor = ACTOR.get()
    if not actor:
        return details_json
    import json
    try:
        details = json.loads(details_json)
    except ValueError:
        return details_json
    if not isinstance(details, dict) or "actor" in details:
        return details_json
    details["actor"] = actor
    return json.dumps(details, ensure_ascii=False)
