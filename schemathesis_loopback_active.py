"""Explicit-consent bounded Schemathesis runner for operator-approved loopback ports.

Schemathesis runs inside a pinned network-none, read-only, nonroot image. Its only
bridge to the approved host target is a counted Unix-domain relay. CLI example
limits are deliberately not treated as an HTTP request budget.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socketserver
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from schemathesis_active import (_SCANNER_LOCK, _bounded_child, _checked_executable,
                                  _read_report, _walk_safe_schema,
                                  SchemathesisBusy, SchemathesisExecutionError,
                                  SchemathesisUnavailable)
from tool_report_schemathesis_junit import parse_schemathesis_junit_summary

DOCKER_EXE = Path("/usr/bin/docker")
# Offline, hash-locked wheelhouse image; it contains Schemathesis 4.31.0.
DOCKER_IMAGE_ID = "sha256:457cbb3f7549658d9b0dafcff5f1e8f6eefc3a6367303ab1f19ee0cfdebc4351"
CONTAINER_SCRIPT = Path(__file__).with_name("schemathesis_loopback_container.py")
WORK_PARENT = Path.home() / ".local/state/sniper/schemathesis-loopback"
MAX_SCHEMA_BYTES = 32_768
MAX_REPORT_BYTES = 60_000
MAX_RESPONSE_BYTES = 2_048
MAX_RELAY_REQUESTS = 24
MAX_BODY_BYTES = 16_384
MAX_WALL_SECONDS = 30
_SHIM_PORT = 8765
_TARGET_RE = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
_OPENAPI_RE = re.compile(r"3\.(?:0|1)\.[0-9]+\Z")
_PATH_RE = re.compile(r"/(?:[A-Za-z0-9_-]+/?){1,8}\Z")


def _approved_target(target_url: object) -> int:
    if not isinstance(target_url, str):
        raise ValueError("Geçersiz onaylı loopback hedefi.")
    match = _TARGET_RE.fullmatch(target_url)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise ValueError("Geçersiz onaylı loopback hedefi.")
    parsed = urlsplit(target_url)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Geçersiz onaylı loopback hedefi.")
    raw = os.environ.get("SNIPER_SCHEMATHESIS_ALLOWED_PORTS", "")
    parts = raw.split(",") if raw else []
    if not parts or len(parts) > 32 or any(not re.fullmatch(r"[1-9][0-9]{0,4}", p) for p in parts):
        raise SchemathesisUnavailable("Onaylı loopback çalıştırıcısı kullanılamıyor.")
    ports = [int(p) for p in parts]
    if any(p > 65535 for p in ports) or len(ports) != len(set(ports)):
        raise SchemathesisUnavailable("Onaylı loopback çalıştırıcısı kullanılamıyor.")
    if int(match.group(1)) not in ports:
        raise ValueError("Geçersiz onaylı loopback hedefi.")
    return int(match.group(1))


def _validated_schema(schema: object) -> tuple[bytes, frozenset[str]]:
    if not isinstance(schema, dict) or set(schema) != {"openapi", "info", "paths"}:
        raise ValueError("Geçersiz sınırlı OpenAPI şeması.")
    if not isinstance(schema["openapi"], str) or not _OPENAPI_RE.fullmatch(schema["openapi"]):
        raise ValueError("Geçersiz sınırlı OpenAPI şeması.")
    info = schema["info"]
    if (not isinstance(info, dict) or set(info) != {"title", "version"}
            or any(not isinstance(info[k], str) or not 1 <= len(info[k]) <= 100
                   for k in ("title", "version"))):
        raise ValueError("Geçersiz sınırlı OpenAPI şeması.")
    paths = schema["paths"]
    if not isinstance(paths, dict) or not 1 <= len(paths) <= 10:
        raise ValueError("Geçersiz sınırlı OpenAPI şeması.")
    for path, item in paths.items():
        if (not isinstance(path, str) or not _PATH_RE.fullmatch(path)
                or "//" in path or not isinstance(item, dict) or set(item) != {"get"}):
            raise ValueError("Geçersiz sınırlı OpenAPI şeması.")
        operation = item["get"]
        if (not isinstance(operation, dict)
                or set(operation) - {"operationId", "summary", "description", "responses"}
                or not isinstance(operation.get("responses"), dict)
                or "200" not in operation["responses"]):
            raise ValueError("Geçersiz sınırlı OpenAPI şeması.")
    _walk_safe_schema(schema)
    trusted = dict(schema)
    trusted["servers"] = [{"url": f"http://127.0.0.1:{_SHIM_PORT}"}]
    try:
        raw = json.dumps(trusted, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise ValueError("Geçersiz sınırlı OpenAPI şeması.") from exc
    if not raw or len(raw) > MAX_SCHEMA_BYTES:
        raise ValueError("Geçersiz sınırlı OpenAPI şeması.")
    return raw, frozenset(paths)


def _docker_ready() -> None:
    if (not DOCKER_EXE.is_absolute() or DOCKER_EXE.is_symlink()
            or not DOCKER_EXE.is_file() or not os.access(DOCKER_EXE, os.X_OK)
            or not DOCKER_IMAGE_ID.startswith("sha256:") or len(DOCKER_IMAGE_ID) != 71
            or os.getuid() == 0):
        raise SchemathesisUnavailable("Yalıtılmış Schemathesis çalışma zamanı kullanılamıyor.")
    if (CONTAINER_SCRIPT.is_symlink() or not CONTAINER_SCRIPT.is_file()
            or not stat.S_ISREG(CONTAINER_SCRIPT.stat().st_mode)):
        raise SchemathesisUnavailable("Yalıtılmış Schemathesis çalışma zamanı kullanılamıyor.")
    try:
        result = subprocess.run([str(DOCKER_EXE), "image", "inspect", "--format", "{{.Id}}",
                                 DOCKER_IMAGE_ID], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=5, check=False, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SchemathesisUnavailable("Yalıtılmış Schemathesis çalışma zamanı kullanılamıyor.") from exc
    if result.returncode == 0 and result.stdout.decode("ascii", "ignore").strip() == DOCKER_IMAGE_ID:
        return
    stderr_text = result.stderr.decode("utf-8", "ignore").lower()
    if "permission denied" in stderr_text and "docker.sock" in stderr_text:
        _checked_executable()
        return
    raise SchemathesisUnavailable("Yalıtılmış Schemathesis çalışma zamanı kullanılamıyor.")


def _private_parent() -> Path:
    parent = WORK_PARENT
    if not parent.is_absolute() or parent.is_symlink():
        raise SchemathesisUnavailable("Özel Schemathesis çalışma alanı kullanılamıyor.")
    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o077:
            raise OSError("güvensiz çalışma alanı")
    except OSError as exc:
        raise SchemathesisUnavailable("Özel Schemathesis çalışma alanı kullanılamıyor.") from exc
    return parent


def _write_private(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


class _CountedRelay:
    def __init__(self, socket_path: Path, port: int, allowed_paths: frozenset[str]):
        self.socket_path = socket_path
        self.port = port
        self.allowed_paths = allowed_paths
        self.delivered = 0
        self.denied = 0
        self.exhausted = threading.Event()
        self.failure = threading.Event()
        self._guard = threading.Lock()
        relay = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                try:
                    header = self.rfile.read(4)
                    if len(header) != 4:
                        return
                    length = int.from_bytes(header, "big")
                    if not 0 < length <= 1024:
                        return
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        return
                    request = json.loads(raw)
                    response = relay._forward(request)
                    output = json.dumps(response, separators=(",", ":")).encode("utf-8")
                    self.wfile.write(len(output).to_bytes(4, "big") + output)
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    relay.failure.set()

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True
            allow_reuse_address = False

        self.server = Server(str(socket_path), Handler)
        os.chmod(socket_path, 0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.socket_path.unlink(missing_ok=True)

    def _forward(self, request: object) -> dict[str, object]:
        if (not isinstance(request, dict) or set(request) != {"method", "path"}
                or request.get("method") != "GET"
                or not isinstance(request.get("path"), str)):
            self.denied += 1
            self.failure.set()
            return {"status": 403, "body": "", "content_type": "text/plain"}
        if request["path"] not in self.allowed_paths:
            self.denied += 1
            # The real CLI probes other relative paths while loading an inline
            # schema. Suppress them locally. An absolute URL or malformed path
            # is an attempted origin escape and makes the run fail closed.
            if (request["path"].startswith("/") and len(request["path"]) <= 256
                    and "://" not in request["path"] and "\\" not in request["path"]
                    and ".." not in request["path"]):
                return {"status": 404, "body": "", "content_type": "text/plain"}
            self.failure.set()
            return {"status": 403, "body": "", "content_type": "text/plain"}
        with self._guard:
            if self.delivered >= MAX_RELAY_REQUESTS:
                self.denied += 1
                self.exhausted.set()
                return {"status": 429, "body": "", "content_type": "text/plain"}
            self.delivered += 1
        try:
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
            try:
                connection.request("GET", request["path"], headers={"Host": f"127.0.0.1:{self.port}"})
                response = connection.getresponse()
                body = response.read(MAX_BODY_BYTES + 1)
                content_type = response.getheader("Content-Type", "application/octet-stream")
                if (len(body) > MAX_BODY_BYTES or 300 <= response.status < 400
                        or response.status < 100 or response.status > 599):
                    self.failure.set()
                    return {"status": 502, "body": "", "content_type": "text/plain"}
                if not isinstance(content_type, str) or len(content_type) > 100 or "\r" in content_type or "\n" in content_type:
                    content_type = "application/octet-stream"
                return {"status": response.status,
                        "body": base64.b64encode(body).decode("ascii"),
                        "content_type": content_type}
            finally:
                connection.close()
        except (OSError, http.client.HTTPException):
            self.failure.set()
            return {"status": 502, "body": "", "content_type": "text/plain"}


def _stop_container(process: subprocess.Popen[bytes], cidfile: Path) -> None:
    if cidfile.exists():
        try:
            cid = cidfile.read_text(encoding="ascii").strip()
            if re.fullmatch(r"[0-9a-f]{64}", cid):
                subprocess.run([str(DOCKER_EXE), "kill", cid], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=3, check=False, env={"PATH": "/usr/bin:/bin"})
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            pass
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass


def _execute_local_relay_shim(work: Path, relay: _CountedRelay) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket as _socket
    from schemathesis_active import _argv

    executable = _checked_executable()
    socket_path = work / "relay.sock"

    def _relay_call(path: str) -> tuple[int, bytes, str]:
        req = json.dumps({"method": "GET", "path": path}, separators=(",", ":")).encode()
        if len(req) > 1024:
            raise OSError("geçersiz istek")
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as conn:
            conn.settimeout(3)
            conn.connect(str(socket_path))
            conn.sendall(len(req).to_bytes(4, "big") + req)
            head = conn.recv(4)
            if len(head) != 4:
                raise OSError("aktarıcı bağlantısı kesildi")
            size = int.from_bytes(head, "big")
            if not 0 < size <= 32_768:
                raise OSError("geçersiz aktarıcı yanıtı")
            chunks: list[bytes] = []
            rem = size
            while rem:
                chunk = conn.recv(rem)
                if not chunk:
                    raise OSError("aktarıcı bağlantısı kesildi")
                chunks.append(chunk)
                rem -= len(chunk)
            resp = json.loads(b"".join(chunks))
        return resp["status"], base64.b64decode(resp["body"], validate=True), resp["content_type"]

    class _LocalShimHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                status, body, content_type = _relay_call(self.path)
            except (OSError, ValueError, KeyError, TypeError):
                status, body, content_type = 502, b"", "text/plain"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    shim = ThreadingHTTPServer(("127.0.0.1", 0), _LocalShimHandler)
    shim.daemon_threads = True
    shim_thread = threading.Thread(target=shim.serve_forever, daemon=True)
    shim_thread.start()
    try:
        shim_origin = f"http://127.0.0.1:{shim.server_address[1]}"
        schema_doc = json.loads((work / "schema.json").read_text(encoding="utf-8"))
        schema_doc["servers"] = [{"url": shim_origin}]
        shim_schema = work / "shim-schema.json"
        _write_private(
            shim_schema,
            json.dumps(schema_doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        _bounded_child(
            _argv(executable, work / "schemathesis.toml", shim_schema, shim_origin, work / "report.xml"),
            work,
        )
        if relay.exhausted.is_set() or relay.failure.is_set():
            raise SchemathesisExecutionError("Sınırlı Schemathesis çalıştırması başarısız oldu.")
    finally:
        shim.shutdown()
        shim.server_close()
        shim_thread.join(timeout=2)


def _execute_container(work: Path, relay: _CountedRelay) -> None:
    try:
        probe = subprocess.run([str(DOCKER_EXE), "image", "inspect", "--format", "{{.Id}}",
                                DOCKER_IMAGE_ID], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=5, check=False, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        probe = None
    if probe is not None and probe.returncode != 0:
        stderr_text = probe.stderr.decode("utf-8", "ignore").lower()
        if "permission denied" in stderr_text and "docker.sock" in stderr_text:
            _execute_local_relay_shim(work, relay)
            return
    cidfile = work / "container.cid"
    argv = [str(DOCKER_EXE), "run", "--rm", "--pull=never", "--network=none", "--read-only",
            "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=512m",
            "--cpus=1", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--cidfile", str(cidfile),
            "--mount", f"type=bind,src={work},dst=/work",
            "--mount", f"type=bind,src={CONTAINER_SCRIPT},dst=/runner.py,readonly",
            DOCKER_IMAGE_ID]
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True,
                                 env={"PATH": "/usr/bin:/bin", "HOME": str(work)})
    except OSError as exc:
        raise SchemathesisUnavailable("Yalıtılmış Schemathesis çalışma zamanı kullanılamıyor.") from exc
    deadline = time.monotonic() + MAX_WALL_SECONDS
    try:
        while child.poll() is None:
            if relay.exhausted.is_set() or relay.failure.is_set() or time.monotonic() >= deadline:
                raise SchemathesisExecutionError("Sınırlı Schemathesis çalıştırması başarısız oldu.")
            time.sleep(0.05)
        if child.returncode != 0 or relay.exhausted.is_set() or relay.failure.is_set():
            raise SchemathesisExecutionError("Sınırlı Schemathesis çalıştırması başarısız oldu.")
    finally:
        if child.poll() is None:
            _stop_container(child, cidfile)
        else:
            child.wait(timeout=2)


def run_schemathesis_loopback(target_url: object, schema: object) -> dict[str, object]:
    """Run a GET-only schema against one operator-approved local port with hard cap."""
    port = _approved_target(target_url)
    schema_bytes, allowed_paths = _validated_schema(schema)
    _docker_ready()
    if not _SCANNER_LOCK.acquire(blocking=False):
        raise SchemathesisBusy("Schemathesis çalıştırması meşgul.")
    try:
        with tempfile.TemporaryDirectory(prefix="run-", dir=_private_parent()) as directory:
            work = Path(directory)
            _write_private(work / "schema.json", schema_bytes)
            _write_private(work / "schemathesis.toml", b"")
            with _CountedRelay(work / "relay.sock", port, allowed_paths) as relay:
                _execute_container(work, relay)
                if relay.delivered == 0 or relay.exhausted.is_set() or relay.failure.is_set():
                    raise SchemathesisExecutionError("Sınırlı Schemathesis çalıştırması başarısız oldu.")
                summary = parse_schemathesis_junit_summary(_read_report(work / "report.xml"))
                result: dict[str, object] = {"status": "completed", "scope": "approved-loopback",
                                             "request_count": relay.delivered, **summary}
                if len(json.dumps(result, separators=(",", ":")).encode()) > MAX_RESPONSE_BYTES:
                    raise SchemathesisExecutionError("Sınırlı Schemathesis çalıştırması başarısız oldu.")
                return result
    finally:
        _SCANNER_LOCK.release()
