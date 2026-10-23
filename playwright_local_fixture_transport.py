"""In-memory capability authentication and AF_UNIX transport for the fixed local browser fixture.

The 32-byte capability is delivered on supervisor-owned stdin pipes. It is
never serialized in an environment variable, command line, file or HTTP body.
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import re
import secrets
import select
import socket
import stat
import struct
import time
from pathlib import Path

PROTOCOL = "sniper-playwright-local-fixture-auth-v1"
MAX_FRAME = 2048
_KEY: bytes | None = None
_NONCE = re.compile(r"[0-9a-f]{32}\Z")

ROUTE_RESULT = {
    "format": "playwright-local-fixture-v1",
    "fixture": "about:blank-dom-v1",
    "status": "passed",
    "checks": {
        "browser_started": True,
        "fixed_dom_assertion": True,
        "renderer_userns_isolated": True,
    },
}


class AuthError(ValueError):
    pass


class PlaywrightFixtureUnavailable(RuntimeError):
    pass


class PlaywrightFixtureBusy(RuntimeError):
    pass


class PlaywrightFixtureFailed(RuntimeError):
    pass


def install_capability(value: bytes) -> None:
    global _KEY
    if type(value) is not bytes or len(value) != 32 or _KEY is not None:
        raise AuthError("geçersiz yetenek kurulumu")
    if os.name != "posix" or ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        raise AuthError("süreç belleği mühürlenemiyor")
    _KEY = value


def ready() -> bool:
    return _KEY is not None


def read_capability_stdin(timeout: float = 5.0) -> bytes:
    if timeout <= 0 or timeout > 10:
        raise AuthError("geçersiz önyükleme zaman aşımı")
    chunks = bytearray()
    deadline = time.monotonic() + timeout
    while len(chunks) < 32:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
            raise AuthError("yetenek önyüklemesi zaman aşımına uğradı")
        part = os.read(0, 32 - len(chunks))
        if not part:
            raise AuthError("yetenek önyüklemesi kesik")
        chunks.extend(part)
    # The supervising pipe remains open only for the exactly 32 bytes. A
    # trailing byte that arrives immediately is an invalid bootstrap.
    if select.select([0], [], [], 0)[0] and os.read(0, 1):
        raise AuthError("yetenek önyüklemesi çok büyük")
    return bytes(chunks)


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _mac(obj: dict) -> str:
    if _KEY is None:
        raise AuthError("yetenek kullanılamıyor")
    return hmac.new(_KEY, _canonical(obj), hashlib.sha256).hexdigest()


def seal(obj: dict) -> bytes:
    if "mac" in obj:
        raise AuthError("ayrılmış alan")
    frame = {**obj, "mac": _mac(obj)}
    raw = _canonical(frame) + b"\n"
    if len(raw) > MAX_FRAME:
        raise AuthError("çerçeve çok büyük")
    return raw


def open_frame(raw: bytes, *, allowed: set[str]) -> dict:
    if not raw or len(raw) > MAX_FRAME or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise AuthError("geçersiz çerçeve")
    try:
        obj = json.loads(raw[:-1])
    except (ValueError, UnicodeError) as exc:
        raise AuthError("geçersiz çerçeve") from exc
    if type(obj) is not dict or set(obj) != allowed | {"mac"}:
        raise AuthError("geçersiz çerçeve alanları")
    mac = obj.pop("mac")
    if type(mac) is not str or not re.fullmatch(r"[0-9a-f]{64}", mac):
        raise AuthError("geçersiz MAC")
    if not hmac.compare_digest(mac, _mac(obj)):
        raise AuthError("geçersiz MAC")
    if obj.get("protocol") != PROTOCOL or type(obj.get("nonce")) is not str or not _NONCE.fullmatch(obj["nonce"]):
        raise AuthError("geçersiz protokol veya nonce")
    return obj


def request(action: str, *, challenge: str | None = None) -> tuple[str, bytes]:
    if action == "hello":
        if challenge is not None:
            raise AuthError("hello iletisi sınama taşıyamaz")
        fields = {"protocol": PROTOCOL, "nonce": secrets.token_hex(16), "action": "hello"}
    elif action in ("probe", "run") and type(challenge) is str and _NONCE.fullmatch(challenge):
        fields = {"protocol": PROTOCOL, "nonce": secrets.token_hex(16),
                  "action": action, "challenge": challenge}
    else:
        raise AuthError("geçersiz bağlı istek")
    return fields["nonce"], seal(fields)


def _socket_path() -> Path:
    raw = os.environ.get("SNIPER_PLAYWRIGHT_FIXTURE_SOCKET", "")
    if not raw or len(raw.encode("utf-8")) > 100:
        raise PlaywrightFixtureUnavailable("aracı soketi yapılandırılmamış")
    path = Path(raw)
    if not path.is_absolute():
        raise PlaywrightFixtureUnavailable("aracı soketi mutlak yol olmalı")
    return path


def _verified_connect(timeout: float) -> socket.socket:
    if not ready():
        raise PlaywrightFixtureUnavailable("aracı yeteneği kullanılamıyor")
    path = _socket_path()
    try:
        parent_info = path.parent.lstat()
        info = path.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != os.getuid()
                or parent_info.st_mode & 0o077
                or not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise PlaywrightFixtureUnavailable("aracı soketi sahipliği geçersiz")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(timeout)
            conn.connect(str(path))
            pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            # A host broker may appear as PID 0 inside a private container PID namespace.
            # UID/GID and the in-memory HMAC capability are the trust checks.
            if uid != os.getuid() or gid != os.getgid():
                raise PlaywrightFixtureUnavailable("aracı eş kimliği uyuşmuyor")
            return conn
        except BaseException:
            conn.close()
            raise
    except (FileNotFoundError, ConnectionRefusedError, PermissionError, TimeoutError, OSError) as exc:
        raise PlaywrightFixtureUnavailable("aracı kullanılamıyor") from exc


def _recv_frame(conn: socket.socket) -> bytes:
    raw = bytearray()
    while len(raw) <= MAX_FRAME and b"\n" not in raw:
        part = conn.recv(min(512, MAX_FRAME + 1 - len(raw)))
        if not part:
            break
        raw.extend(part)
    if len(raw) > MAX_FRAME:
        raise PlaywrightFixtureFailed("aracı yanıtı çok büyük")
    return bytes(raw)


def _exchange(action: str, timeout: float) -> dict:
    try:
        hello_nonce, hello_frame = request("hello")
        with _verified_connect(timeout) as conn:
            conn.sendall(hello_frame)
            greeting = open_frame(_recv_frame(conn), allowed={"protocol", "nonce", "status", "result"})
            challenge = greeting["result"]
            if (greeting["nonce"] != hello_nonce or greeting["status"] != "challenge"
                    or type(challenge) is not str or not re.fullmatch(r"[0-9a-f]{32}", challenge)):
                raise AuthError("aracı sınaması geçersiz")
            nonce, frame = request(action, challenge=challenge)
            conn.sendall(frame)
            response = open_frame(_recv_frame(conn), allowed={"protocol", "nonce", "status", "result"})
        if response["nonce"] != nonce or type(response["status"]) is not str:
            raise AuthError("aracı yanıtı uyuşmuyor")
        return response
    except PlaywrightFixtureUnavailable:
        raise
    except (TimeoutError, OSError) as exc:
        raise PlaywrightFixtureUnavailable("aracı kullanılamıyor") from exc
    except AuthError as exc:
        raise PlaywrightFixtureUnavailable("aracı kimlik doğrulaması başarısız oldu") from exc


def broker_ready() -> bool:
    try:
        response = _exchange("probe", 0.5)
        return response["status"] == "ready" and response["result"] is None
    except (PlaywrightFixtureUnavailable, KeyError):
        return False


def run_local_playwright_fixture() -> dict:
    response = _exchange("run", 80)
    status = response["status"]
    result = response["result"]
    if status == "busy" and result is None:
        raise PlaywrightFixtureBusy("aracı meşgul")
    if status == "unavailable" and result is None:
        raise PlaywrightFixtureUnavailable("aracı kullanılamıyor")
    if status == "failed" and result is None:
        raise PlaywrightFixtureFailed("fikstür başarısız oldu")
    if status != "passed":
        raise PlaywrightFixtureFailed("aracı yanıtı geçersiz")
    if not isinstance(result, dict) or set(result) != {"format", "fixture", "status", "checks"}:
        raise PlaywrightFixtureFailed("aracı sonucu geçersiz")
    checks = result["checks"]
    if (result["format"] != ROUTE_RESULT["format"]
            or result["fixture"] != ROUTE_RESULT["fixture"]
            or result["status"] != "passed"
            or not isinstance(checks, dict)
            or set(checks) != set(ROUTE_RESULT["checks"])
            or any(checks[key] is not True for key in ROUTE_RESULT["checks"])):
        raise PlaywrightFixtureFailed("aracı sonucu geçersiz")
    return {"format": ROUTE_RESULT["format"], "fixture": ROUTE_RESULT["fixture"],
            "status": "passed", "checks": dict(ROUTE_RESULT["checks"])}
