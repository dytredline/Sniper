"""Container-only fixed Schemathesis entrypoint; network-none, nonroot runtime.

Only a loopback HTTP shim is reachable in this container. The shim sends each
GET to the mandatory counted host Unix socket; no target URL enters st argv.
"""
from __future__ import annotations

import base64
import importlib.metadata
import json
import os
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHIM_PORT = 8765
SOCKET_PATH = "/work/relay.sock"
MAX_FRAME = 32_768


def _read_exact(stream: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    while length:
        chunk = stream.recv(length)
        if not chunk:
            raise OSError("aktarıcı bağlantısı kesildi")
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def _relay(path: str) -> tuple[int, bytes, str]:
    request = json.dumps({"method": "GET", "path": path}, separators=(",", ":")).encode()
    if len(request) > 1024:
        raise OSError("geçersiz istek")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(SOCKET_PATH)
        connection.sendall(len(request).to_bytes(4, "big") + request)
        length = int.from_bytes(_read_exact(connection, 4), "big")
        if not 0 < length <= MAX_FRAME:
            raise OSError("geçersiz aktarıcı yanıtı")
        response = json.loads(_read_exact(connection, length))
    if (not isinstance(response, dict) or set(response) != {"status", "body", "content_type"}
            or not isinstance(response["status"], int) or not 100 <= response["status"] <= 599
            or not isinstance(response["content_type"], str)):
        raise OSError("geçersiz aktarıcı yanıtı")
    return response["status"], base64.b64decode(response["body"], validate=True), response["content_type"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        try:
            status, body, content_type = _relay(self.path)
        except (OSError, ValueError, KeyError, TypeError):
            status, body, content_type = 502, b"", "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main() -> int:
    if os.getuid() == 0 or importlib.metadata.version("schemathesis") != "4.31.0":
        return 3
    server = ThreadingHTTPServer(("127.0.0.1", SHIM_PORT), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    argv = ["/usr/local/bin/st", "--config-file", "/work/schemathesis.toml", "--no-color",
            "run", "/work/schema.json", "--url", f"http://127.0.0.1:{SHIM_PORT}",
            "--workers", "1", "--phases", "fuzzing", "--max-examples", "1",
            "--max-time", "8", "--max-failures", "1", "--request-timeout", "2",
            "--request-retries", "0", "--max-redirects", "0", "--rate-limit", "1/s",
            "--report-junit-path", "/work/report.xml"]
    try:
        with open(os.devnull, "wb") as sink:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=sink,
                                    stderr=sink, timeout=15, check=False,
                                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp",
                                         "PYTHONDONTWRITEBYTECODE": "1", "HTTP_PROXY": "",
                                         "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "127.0.0.1"})
        return result.returncode
    except (OSError, subprocess.TimeoutExpired):
        return 4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
