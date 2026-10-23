"""Private, cross-process SSL Labs rate state. No network or account data.

Every transition takes a process-shared file lock and atomically replaces a small
JSON state file. An in-flight lease prevents a crashed worker from immediately
starting a second assessment for the same host.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import secrets
import stat
import time

STATE_ENV = "SNIPER_SSLLABS_RATE_STATE_DIR"
MAX_STATE_BYTES = 65536
MAX_HOSTS = 1024
COOLDOWN_SECONDS = 3600
INFLIGHT_SECONDS = 1800
HOST_BACKOFF_SECONDS = 900
GLOBAL_BACKOFF_SECONDS = 1800
LOCK_WAIT_SECONDS = 1.85
LOCK_RETRY_SECONDS = 0.02


class RateStateUnavailable(RuntimeError):
    """Rate state cannot safely authorize an upstream request."""


def _directory() -> int:
    configured = os.environ.get(STATE_ENV)
    if configured is not None:
        path = Path(configured)
        if not path.is_absolute() or configured != str(path) or not configured or ".." in path.parts:
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
    else:
        base = Path(os.environ.get("SNIPER_DATA_DIR") or Path.home() / ".local/state/sniper")
        if not base.is_absolute():
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        path = base / "ssllabs-rate"
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.") from exc
    # Walk each component without following symlinks. The final directory must
    # already be private and owned by the service user when explicitly set.
    parts = path.parts
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        return fd
    except (OSError, RateStateUnavailable) as exc:
        try:
            os.close(fd)
        except (OSError, UnboundLocalError):
            pass
        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.") from exc


def _regular(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("yinelenen durum anahtarı")
        result[key] = value
    return result


def _moment(value):
    return (type(value) in (int, float) and math.isfinite(value)
            and 0 <= value <= 1_000_000_000_000)


def _read(fd: int) -> dict:
    try:
        source = os.open("rate.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        return {"version": 1, "last_seen": 0.0, "global_until": 0.0,
                "host_until": {}, "last_start": {}, "inflight": {}}
    try:
        _regular(source)
        info = os.fstat(source)
        if not 0 < info.st_size <= MAX_STATE_BYTES:
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        with os.fdopen(source, "rb", closefd=False) as stream:
            raw = stream.read(MAX_STATE_BYTES + 1)
        if len(raw) != info.st_size:
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        state = json.loads(raw, object_pairs_hook=_unique_pairs)
        if (not isinstance(state, dict) or set(state) !=
                {"version", "last_seen", "global_until", "host_until", "last_start", "inflight"}
                or type(state["version"]) is not int or state["version"] != 1
                or not _moment(state["last_seen"]) or not _moment(state["global_until"])):
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        for field in ("host_until", "last_start", "inflight"):
            items = state[field]
            if not isinstance(items, dict) or len(items) > MAX_HOSTS:
                raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
            for host, item in items.items():
                if not isinstance(host, str) or not 0 < len(host) <= 253:
                    raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
                if field == "inflight":
                    if (not isinstance(item, dict) or set(item) != {"until", "token"}
                            or not _moment(item["until"]) or not isinstance(item["token"], str)
                            or len(item["token"]) != 32):
                        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
                elif not _moment(item):
                    raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        return state
    except (OSError, ValueError, UnicodeError, TypeError, RateStateUnavailable) as exc:
        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.") from exc
    finally:
        os.close(source)


def _write(fd: int, state: dict) -> None:
    raw = (json.dumps(state, separators=(",", ":"), sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_STATE_BYTES:
        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
    name = ".rate-" + secrets.token_hex(16)
    temp = None
    try:
        temp = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        _regular(temp)
        with os.fdopen(temp, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(temp)
        os.replace(name, "rate.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    except (OSError, ValueError) as exc:
        try:
            os.unlink(name, dir_fd=fd)
        except OSError:
            pass
        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.") from exc
    finally:
        if temp is not None:
            os.close(temp)


@contextmanager
def _locked():
    fd = _directory()
    lock = None
    try:
        lock = os.open("rate.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        _regular(lock)
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.") from exc
                time.sleep(min(LOCK_RETRY_SECONDS, remaining))
        yield fd
    except OSError as exc:
        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.") from exc
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def _update_clock(state: dict, now: float) -> None:
    if not _moment(now) or now < state["last_seen"]:
        raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
    state["last_seen"] = now


def _prune(state: dict, now: float) -> None:
    state["host_until"] = {k: v for k, v in state["host_until"].items() if v > now}
    state["last_start"] = {k: v for k, v in state["last_start"].items() if v + COOLDOWN_SECONDS > now}
    state["inflight"] = {k: v for k, v in state["inflight"].items() if v["until"] > now}


def check_global(now: float) -> None:
    with _locked() as fd:
        state = _read(fd)
        _update_clock(state, now)
        if now < state["global_until"]:
            raise RateStateUnavailable("SSL Labs hizmeti geçici olarak kullanılamıyor.")
        _prune(state, now)
        _write(fd, state)


def begin(hostname: str, now: float) -> tuple[bool, str]:
    with _locked() as fd:
        state = _read(fd)
        _update_clock(state, now)
        _prune(state, now)
        if (now < state["global_until"] or now < state["host_until"].get(hostname, 0.0)
                or hostname in state["inflight"]):
            raise RateStateUnavailable("SSL Labs hizmeti geçici olarak kullanılamıyor.")
        if len(state["last_start"]) >= MAX_HOSTS or len(state["inflight"]) >= MAX_HOSTS:
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        begin_new = hostname not in state["last_start"]
        if begin_new:
            state["last_start"][hostname] = now
        token = secrets.token_hex(16)
        state["inflight"][hostname] = {"until": now + INFLIGHT_SECONDS, "token": token}
        _write(fd, state)
        return begin_new, token


def finish(hostname: str, token: str, now: float, status: int | None = None) -> None:
    with _locked() as fd:
        state = _read(fd)
        _update_clock(state, now)
        lease = state["inflight"].get(hostname)
        if not lease or lease["token"] != token:
            raise RateStateUnavailable("SSL Labs hız sınırı durumu kullanılamıyor.")
        del state["inflight"][hostname]
        if status == 529:
            state["global_until"] = max(state["global_until"], now + GLOBAL_BACKOFF_SECONDS)
        elif status == 503:
            state["host_until"][hostname] = max(state["host_until"].get(hostname, 0.0), now + HOST_BACKOFF_SECONDS)
        _prune(state, now)
        _write(fd, state)


def info_failure(status: int, now: float) -> None:
    if status not in (503, 529):
        return
    with _locked() as fd:
        state = _read(fd)
        _update_clock(state, now)
        length = GLOBAL_BACKOFF_SECONDS if status == 529 else HOST_BACKOFF_SECONDS
        state["global_until"] = max(state["global_until"], now + length)
        _prune(state, now)
        _write(fd, state)
