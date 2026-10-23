"""HTTP katmanı: giriş kapısı (her istekte), /api/auth/* uçları ve iş kuyruğu yetki bağlamı.

``server.py`` yalnız kancaları çağırır; giriş kapalıyken kapı tek bir ``stat`` ile geçer ve hiçbir davranış değişmez.
"""
from __future__ import annotations

from http import HTTPStatus
import os
from typing import Any
from urllib.parse import urlsplit

import auth
import request_context

LOGIN_ASSETS = frozenset({"login.html", "login.js", "app.css", "auth.css", "i18n.js", "i18n-en.tsv",
                          "ui-refresh.css", "ui-icons.svg"})  # Codex arayüzü: giriş sayfası stili ve simgeleri


def manager() -> auth.AuthManager:
    import server  # çalışma anında (döngüsel içe aktarma yok)
    return auth.manager_for(server.DATA_DIR)


def _secure_cookies() -> bool:
    return os.environ.get("SNIPER_COOKIE_SECURE") == "1"


def _static_relative(path: str) -> str:
    relative = "index.html" if path in {"", "/"} else path.lstrip("/")
    return relative[len("static/"):] if relative.startswith("static/") else relative


def _client(handler) -> str:
    address = getattr(handler, "client_address", None)
    return str(address[0]) if address else "local"


def _is_api(path: str) -> bool:
    return path == "/metrics" or path == "/api" or path.startswith("/api/")


def gate(handler) -> bool:
    """Her istekte (``_request_preflight`` sonunda): oturum, CSRF ve rol denetimi. ``False`` → yanıt verildi."""
    handler._auth_session = None
    m = manager()
    if not m.enabled():
        return True
    path = urlsplit(handler.path).path
    method = (handler.command or "GET").upper()
    level = auth.required_level(method, path)
    if method in {"GET", "HEAD"} and not _is_api(path) and _static_relative(path) in LOGIN_ASSETS:
        level = "public"
    session = m.lookup_session(auth.parse_cookies(handler.headers.get("Cookie")).get(auth.SESSION_COOKIE))
    handler._auth_session = session
    if session:
        request_context.ACTOR.set(request_context.actor_summary(session["user"]))
    if level == "public":
        return True
    if session is None:
        if method in {"GET", "HEAD"} and not _is_api(path):
            handler.send_response(HTTPStatus.FOUND)
            handler.send_header("Location", "/login.html")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return False
        handler._error(HTTPStatus.UNAUTHORIZED, "Oturum açmanız gerekiyor.")
        return False
    if method not in {"GET", "HEAD", "OPTIONS"} and not m.csrf_ok(session, handler.headers.get(auth.CSRF_HEADER)):
        handler._error(HTTPStatus.FORBIDDEN, "CSRF doğrulaması başarısız; sayfayı yenileyip yeniden deneyin.")
        return False
    if not auth.role_allows(session["user"]["role"], level):
        handler._error(HTTPStatus.FORBIDDEN, "Bu işlem için yetkiniz yok.")
        return False
    return True


# ---------------------------------------------------------------------------
# İş kuyruğu
# ---------------------------------------------------------------------------
_JOB_OWNERS: dict[str, str] = {}
_STRIPPED_JOB_HEADERS = frozenset({"cookie", auth.CSRF_HEADER.lower()})


def job_headers(headers) -> list[tuple[str, str]]:
    """İşe aktarılan başlıklar: oturum çerezi ve CSRF belirteci iş kaydına/alt sürece taşınmaz."""
    return [(k, v) for k, v in headers.items() if k.lower() not in _STRIPPED_JOB_HEADERS]


def job_submit_denied(handler, route: str) -> bool:
    """Kuyruğa alınan iç rota, kuyruğa alan kullanıcının rolüyle denetlenir (iç çağrı kapıyı atlatmaz)."""
    session = getattr(handler, "_auth_session", None)
    if not manager().enabled():
        return False
    role = session["user"]["role"] if session else None
    if not auth.role_allows(role, auth.required_level("POST", route)):
        handler._error(HTTPStatus.FORBIDDEN, "Bu işi kuyruğa almak için yetkiniz yok.")
        return True
    return False


def remember_job_owner(job_id: str) -> None:
    actor = request_context.current_actor()
    if actor:
        _JOB_OWNERS[job_id] = actor["id"]
        if len(_JOB_OWNERS) > 5000:
            _JOB_OWNERS.pop(next(iter(_JOB_OWNERS)))


def job_cancel_denied(handler, job_id: str) -> bool:
    if not manager().enabled():
        return False
    session = getattr(handler, "_auth_session", None)
    user = session["user"] if session else None
    if user and (user["role"] == "admin" or _JOB_OWNERS.get(job_id) == user["id"]):
        return False
    handler._error(HTTPStatus.FORBIDDEN, "Yalnız işi başlatan kullanıcı ya da yönetici iptal edebilir.")
    return True


# ---------------------------------------------------------------------------
# /api/auth/*
# ---------------------------------------------------------------------------
def _store():
    import server
    return server.STORE


def _log(action: str, entity_id: str, details: dict[str, Any] | None = None, *, actor: dict | None = None) -> None:
    if actor is not None:
        with request_context.acting_as(actor):
            _store().log(action, entity_id, details or {})
    else:
        _store().log(action, entity_id, details or {})


def _exact(payload: dict, required: set[str], optional: set[str] = frozenset()) -> bool:
    keys = set(payload)
    return required <= keys <= (required | set(optional))


def _issue_session(handler, user: dict[str, Any], payload_extra: dict | None = None, status=HTTPStatus.OK) -> None:
    token, csrf = manager().create_session(user["id"], _client(handler))
    body = {"user": user, **(payload_extra or {})}
    handler._json(body, status=status, cookies=auth.session_cookie_headers(token, csrf, secure=_secure_cookies()))


def handle_get(handler, path: str) -> None:
    m = manager()
    session = getattr(handler, "_auth_session", None)
    if path == "/api/auth/status":
        enabled = m.enabled()
        return handler._json({
            "enabled": enabled,
            "authenticated": bool(session),
            "user": session["user"] if session else None,
            "setup_pending": (not enabled) and m.setup_token_path().is_file(),
            "roles": auth.ROLE_LABELS,
            "password_min": auth.PASSWORD_MIN,
        })
    if not m.enabled():
        return handler._error(HTTPStatus.CONFLICT, "Giriş etkin değil.")
    if path == "/api/auth/me":
        user = session["user"]
        return handler._json({
            "user": user,
            "recovery_codes_left": m.recovery_codes_left(user["id"]) if user.get("totp_enabled") else 0,
            "session_idle_minutes": auth.session_idle_seconds() // 60,
            "session_max_hours": auth.session_max_seconds() // 3600,
        })
    if path == "/api/auth/users":
        return handler._json({"users": m.list_users(), "roles": auth.ROLE_LABELS})
    return handler._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")


def handle_post(handler, path: str, payload: dict) -> None:
    try:
        return _handle_post(handler, path, payload)
    except auth.AuthError as exc:
        return handler._error(exc.status, str(exc))


def _handle_post(handler, path: str, payload: dict) -> None:
    m = manager()
    enabled = m.enabled()
    session = getattr(handler, "_auth_session", None)
    client = _client(handler)

    if path == "/api/auth/setup/begin":
        if enabled:
            return handler._error(HTTPStatus.CONFLICT, "Giriş zaten etkin.")
        if not handler._is_loopback_client() or payload.get("confirm") is not True or set(payload) != {"confirm"}:
            return handler._error(HTTPStatus.FORBIDDEN, "Kurulum yalnız yerelden ve açık onayla (confirm: true) başlatılır.")
        token_path = m.setup_begin()
        _log("auth.setup_token_created", "auth", {"expires_in_seconds": auth.SETUP_TOKEN_SECONDS})
        return handler._json({"token_file": str(token_path), "expires_in_seconds": auth.SETUP_TOKEN_SECONDS})
    if path == "/api/auth/setup/complete":
        if enabled:
            return handler._error(HTTPStatus.CONFLICT, "Giriş zaten etkin.")
        if not handler._is_loopback_client() or not _exact(payload, {"token", "username", "password"}):
            return handler._error(HTTPStatus.FORBIDDEN, "Kurulum yalnız yerelden; token, username ve password gerekli.")
        user = m.setup_complete(payload["token"], payload["username"], payload["password"])
        _log("auth.enabled", user["id"], {"username": user["username"], "method": "setup_token"}, actor=user)
        return _issue_session(handler, user, status=HTTPStatus.CREATED)

    if not enabled:
        return handler._error(HTTPStatus.CONFLICT, "Giriş etkin değil.")

    if path == "/api/auth/login":
        if not _exact(payload, {"username", "password"}):
            return handler._error(HTTPStatus.BAD_REQUEST, "Yalnız username ve password alanları gönderin.")
        try:
            kind, data = m.authenticate(payload["username"], payload["password"], client)
        except auth.AuthError as exc:
            _log("auth.login_failed", "auth", {"client": client, "reason": "locked" if exc.status == 429 else "denied"})
            raise
        if kind == "totp":
            return handler._json({"totp_required": True, "challenge": data["challenge"]})
        _log("auth.login", data["id"], {"client": client, "second_factor": False}, actor=data)
        return _issue_session(handler, data)
    if path == "/api/auth/login/totp":
        if not (_exact(payload, {"challenge", "code"}) or _exact(payload, {"challenge", "recovery_code"})):
            return handler._error(HTTPStatus.BAD_REQUEST, "challenge ile code ya da recovery_code gönderin.")
        try:
            user = m.complete_totp(payload["challenge"], payload.get("code"), payload.get("recovery_code"), client)
        except auth.AuthError:
            _log("auth.login_failed", "auth", {"client": client, "reason": "second_factor"})
            raise
        _log("auth.login", user["id"], {"client": client, "second_factor": True,
                                        "recovery_code": "recovery_code" in payload}, actor=user)
        return _issue_session(handler, user)

    # Buradan sonrası oturum ister (kapı zaten denetledi).
    if session is None:
        return handler._error(HTTPStatus.UNAUTHORIZED, "Oturum açmanız gerekiyor.")
    user = session["user"]
    if path == "/api/auth/logout":
        m.revoke_session(session["token_hash"])
        _log("auth.logout", user["id"])
        return handler._json({"ok": True}, cookies=auth.clear_cookie_headers(secure=_secure_cookies()))
    if path == "/api/auth/sessions/revoke-all":
        count = m.revoke_user_sessions(user["id"], except_hash=session["token_hash"])
        _log("auth.sessions_revoked", user["id"], {"count": count})
        return handler._json({"revoked": count})
    if path == "/api/auth/password":
        if not _exact(payload, {"current_password", "new_password"}):
            return handler._error(HTTPStatus.BAD_REQUEST, "current_password ve new_password gerekli.")
        m.change_own_password(user["id"], payload["current_password"], payload["new_password"])
        _log("auth.password_changed", user["id"], {"by": "self"})
        return _issue_session(handler, user)  # tüm eski oturumlar düştü; bu tarayıcıya yeni oturum
    if path == "/api/auth/totp/begin":
        result = m.totp_begin(user["id"])
        return handler._json(result)
    if path == "/api/auth/totp/confirm":
        if not _exact(payload, {"code"}):
            return handler._error(HTTPStatus.BAD_REQUEST, "code gerekli.")
        codes = m.totp_confirm(user["id"], payload["code"])
        _log("auth.totp_enabled", user["id"])
        fresh = m.get_user(user["id"]) or user
        return _issue_session(handler, fresh, {"recovery_codes": codes})
    if path == "/api/auth/totp/disable":
        if not _exact(payload, {"password"}, {"code"}):
            return handler._error(HTTPStatus.BAD_REQUEST, "password (ve TOTP etkinse code) gerekli.")
        m.totp_disable(user["id"], payload["password"], payload.get("code"))
        _log("auth.totp_disabled", user["id"], {"by": "self"})
        return handler._json({"ok": True})

    # Yönetici: kullanıcı yönetimi (kapı rolü denetledi).
    if path == "/api/auth/users":
        if not _exact(payload, {"username", "password", "role"}):
            return handler._error(HTTPStatus.BAD_REQUEST, "username, password ve role gerekli.")
        created = m.create_user(payload["username"], payload["password"], payload["role"])
        _log("auth.user_created", created["id"], {"username": created["username"], "role": created["role"]})
        return handler._json({"user": created}, status=HTTPStatus.CREATED)
    parts = [part for part in path.split("/") if part]
    if len(parts) == 4 and parts[:3] == ["api", "auth", "users"]:
        allowed = {"role", "disabled", "password", "unlock", "reset_totp"}
        if not payload or not set(payload) <= allowed:
            return handler._error(HTTPStatus.BAD_REQUEST, "Alanlar: role, disabled, password, unlock, reset_totp.")
        if parts[3] == user["id"] and (payload.get("role") not in (None, "admin") or payload.get("disabled") is True):
            return handler._error(HTTPStatus.BAD_REQUEST, "Kendi yönetici rolünüzü düşüremez ya da hesabınızı kapatamazsınız.")
        updated = m.update_user(parts[3], role=payload.get("role"), disabled=payload.get("disabled"),
                                password=payload.get("password"), unlock=payload.get("unlock") is True,
                                reset_totp=payload.get("reset_totp") is True)
        changes = {k: v for k, v in payload.items() if k != "password"}
        if "password" in payload:
            changes["password_reset"] = True
        _log("auth.user_updated", updated["id"], {"username": updated["username"], **changes})
        return handler._json({"user": updated})
    return handler._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")
