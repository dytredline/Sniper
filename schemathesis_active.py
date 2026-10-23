"""Explicit-consent Schemathesis smoke for a server-pinned synthetic fixture.

The first slice does not implement arbitrary localhost or staging API scanning.
An independent synthetic fixture/proxy must hard-stop at 24 HTTP requests.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from tool_report_schemathesis_junit import parse_schemathesis_junit_summary


class SchemathesisUnavailable(RuntimeError):
    pass


class SchemathesisBusy(RuntimeError):
    pass


class SchemathesisExecutionError(RuntimeError):
    pass


_SCANNER_LOCK = threading.Lock()
_PORTABLE_RUNTIME_ROOT = Path(os.environ.get(
    "SNIPER_PORTABLE_RUNTIMES_DIR",
    str(Path.home() / ".local" / "state" / "sniper-tool-runtimes"),
)).expanduser()
ST_EXECUTABLE = Path(os.environ.get(
    "SNIPER_SCHEMATHESIS_BINARY",
    str(_PORTABLE_RUNTIME_ROOT / "schemathesis-4.31.0" / "venv" / "bin" / "st"),
)).expanduser()
ST_EXECUTABLE_SHA256 = "cd07ef9ca68ee5759f8c448c4667ee5a341b7f658fa681439860ef1891745245"
WORK_PARENT = Path.home() / ".local/state/sniper/schemathesis-local"
MAX_SCHEMA_BYTES = 65_536
MAX_REPORT_BYTES = 60_000
MAX_OUTPUT_BYTES = 4_096
MAX_RESPONSE_BYTES = 2_048
MAX_WALL_SECONDS = 15
_ORIGIN_RE = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
_OPENAPI_RE = re.compile(r"3\.(?:0|1)\.[0-9]+\Z")
_FORBIDDEN_SCHEMA_KEYS = {
    "$ref", "externalDocs", "callbacks", "webhooks", "links", "security",
    "securitySchemes", "servers", "parameters", "requestBody", "example",
    "examples", "discriminator",
}


def _pinned_origin() -> str:
    origin = os.environ.get("SNIPER_SCHEMATHESIS_LOCAL_ORIGIN", "")
    match = _ORIGIN_RE.fullmatch(origin)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise SchemathesisUnavailable("Sentetik loopback fikstürü kullanılamıyor.")
    parsed = urlsplit(origin)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise SchemathesisUnavailable("Sentetik loopback fikstürü kullanılamıyor.")
    return origin


def _walk_safe_schema(value: object, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 24 or budget[0] > 1500:
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or key in _FORBIDDEN_SCHEMA_KEYS or key.startswith("x-"):
                raise ValueError("Geçersiz sentetik OpenAPI şeması.")
            _walk_safe_schema(child, depth=depth + 1, budget=budget)
    elif isinstance(value, list):
        if len(value) > 500:
            raise ValueError("Geçersiz sentetik OpenAPI şeması.")
        for child in value:
            _walk_safe_schema(child, depth=depth + 1, budget=budget)
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")


def _validated_schema_bytes(schema: object, origin: str) -> bytes:
    if not isinstance(schema, dict) or set(schema) - {"openapi", "info", "servers", "paths"}:
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    if not isinstance(schema.get("openapi"), str) or not _OPENAPI_RE.fullmatch(schema["openapi"]):
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    info = schema.get("info")
    if (not isinstance(info, dict) or set(info) != {"title", "version"}
            or any(not isinstance(info[k], str) or not 1 <= len(info[k]) <= 100
                   for k in ("title", "version"))):
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    if "servers" in schema and schema["servers"] != [{"url": origin}]:
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    paths = schema.get("paths")
    if not isinstance(paths, dict) or set(paths) != {"/api/ping"}:
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    path_item = paths["/api/ping"]
    if not isinstance(path_item, dict) or set(path_item) != {"get"}:
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    operation = path_item["get"]
    if (not isinstance(operation, dict)
            or set(operation) - {"operationId", "summary", "description", "responses"}
            or not isinstance(operation.get("responses"), dict)
            or "200" not in operation["responses"]):
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    _walk_safe_schema(info)
    _walk_safe_schema(paths)
    try:
        raw = json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exc:
        raise ValueError("Geçersiz sentetik OpenAPI şeması.") from exc
    if not raw or len(raw) > MAX_SCHEMA_BYTES:
        raise ValueError("Geçersiz sentetik OpenAPI şeması.")
    return raw


def _checked_executable() -> Path:
    exe = ST_EXECUTABLE
    if not exe.is_absolute() or exe.is_symlink():
        raise SchemathesisUnavailable("Schemathesis çalışma zamanı kullanılamıyor.")
    try:
        mode = exe.stat().st_mode
        if not stat.S_ISREG(mode) or not os.access(exe, os.X_OK):
            raise OSError("çalıştırılabilir değil")
        digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    except OSError as exc:
        raise SchemathesisUnavailable("Schemathesis çalışma zamanı kullanılamıyor.") from exc
    if digest != ST_EXECUTABLE_SHA256:
        raise SchemathesisUnavailable("Schemathesis çalışma zamanı kullanılamıyor.")
    return exe


def _private_parent() -> Path:
    parent = WORK_PARENT
    if not parent.is_absolute() or parent.is_symlink():
        raise SchemathesisUnavailable("Schemathesis özel çalışma alanı kullanılamıyor.")
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o077:
            raise OSError("güvensiz çalışma alanı")
    except OSError as exc:
        raise SchemathesisUnavailable("Schemathesis özel çalışma alanı kullanılamıyor.") from exc
    return parent


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _argv(executable: Path, config: Path, schema: Path, origin: str, report: Path) -> list[str]:
    return [str(executable), "--config-file", str(config), "--no-color", "run", str(schema),
            "--url", origin, "--workers", "1", "--phases", "fuzzing",
            "--max-examples", "1", "--max-time", "8", "--max-failures", "1",
            "--request-timeout", "2", "--request-retries", "0", "--max-redirects", "0",
            "--rate-limit", "1/s", "--report-junit-path", str(report)]


def _child_environment(private_home: Path) -> dict[str, str]:
    return {"HOME": str(private_home), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
            "http_proxy": "", "https_proxy": "", "all_proxy": "", "NO_PROXY": "127.0.0.1",
            "no_proxy": "127.0.0.1", "PYTHONDONTWRITEBYTECODE": "1"}


def _stop_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _bounded_child(argv: list[str], cwd: Path) -> None:
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=_child_environment(cwd),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, close_fds=True,
                                   start_new_session=True)
    except OSError as exc:
        raise SchemathesisUnavailable("Schemathesis çalışma zamanı kullanılamıyor.") from exc
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    sizes = {stream.fileno(): 0 for stream in streams}
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + MAX_WALL_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.")
            for key, _ in selector.select(min(remaining, 0.2)):
                chunk = os.read(key.fd, 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                sizes[key.fd] += len(chunk)
                if sizes[key.fd] > MAX_OUTPUT_BYTES:
                    raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.")
        if process.wait(timeout=remaining) != 0:
            raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.") from exc
    finally:
        selector.close()
        _stop_child(process)
        for stream in streams:
            stream.close()


def _read_report(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REPORT_BYTES:
                raise ValueError("geçersiz rapor")
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if not raw or len(raw) > MAX_REPORT_BYTES:
            raise ValueError("geçersiz rapor")
        return raw.decode("utf-8", errors="strict")
    except (OSError, ValueError, UnicodeError) as exc:
        raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.") from exc


def run_schemathesis_synthetic_local(schema: object) -> dict[str, object]:
    """Run a synthetic-fixture-only local smoke after route-level consent."""
    origin = _pinned_origin()
    schema_bytes = _validated_schema_bytes(schema, origin)
    executable = _checked_executable()
    if not _SCANNER_LOCK.acquire(blocking=False):
        raise SchemathesisBusy("Schemathesis çalıştırması meşgul.")
    try:
        parent = _private_parent()
        with tempfile.TemporaryDirectory(prefix="run-", dir=parent) as directory:
            private = Path(directory)
            config = private / "schemathesis.toml"
            schema_path = private / "schema.json"
            report = private / "report.xml"
            _write_private(config, b"")
            if os.environ.get("SNIPER_SCHEMATHESIS_EPHEMERAL_FIXTURE") == "1":
                from schemathesis_synthetic_fixture import SyntheticPingFixture
                with SyntheticPingFixture(port=0) as fixture:
                    run_origin = fixture.origin
                    run_schema = dict(schema) if isinstance(schema, dict) else {}
                    if "servers" in run_schema:
                        run_schema["servers"] = [{"url": run_origin}]
                    _write_private(schema_path, _validated_schema_bytes(run_schema, run_origin))
                    _bounded_child(_argv(executable, config, schema_path, run_origin, report), private)
            else:
                _write_private(schema_path, schema_bytes)
                _bounded_child(_argv(executable, config, schema_path, origin, report), private)
            summary = parse_schemathesis_junit_summary(_read_report(report))
            result: dict[str, object] = {"status": "completed", "scope": "synthetic-fixture-only", **summary}
            if len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_RESPONSE_BYTES:
                raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.")
            return result
    except ValueError as exc:
        raise SchemathesisExecutionError("Schemathesis çalıştırılamadı.") from exc
    finally:
        _SCANNER_LOCK.release()
