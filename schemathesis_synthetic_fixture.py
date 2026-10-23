"""Synthetic-only loopback fixture with an independent 24-request HTTP budget.

This module never invokes Schemathesis or contacts an upstream server. The
budget is shared atomically by every handler thread for one fixture lifetime.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_REQUESTS = 24
MAX_IN_FLIGHT_CONNECTIONS = 8
_PING = b'{"ok":true}'
_NOT_FOUND = b'{"error":"not found"}'
_METHOD_NOT_ALLOWED = b'{"error":"method not allowed"}'
_BUDGET_EXHAUSTED = b'{"error":"request budget exhausted"}'


class _BudgetHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = False
    request_queue_size = 64

    def __init__(self, address: tuple[str, int]) -> None:
        self._budget_lock = threading.Lock()
        self._admitted = 0
        self._rejected = 0
        self._handler_invocations = 0
        self._connection_slots = threading.BoundedSemaphore(MAX_IN_FLIGHT_CONNECTIONS)
        super().__init__(address, _PingHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        return connection, address

    def process_request(self, request, client_address) -> None:
        # Acquire before ThreadingMixIn creates a handler thread. A partial HTTP
        # header never reaches parse_request(), so the HTTP budget alone cannot
        # prevent unbounded threads from half-open clients.
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            try:
                self.shutdown_request(request)
            finally:
                self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def admit(self) -> bool:
        with self._budget_lock:
            if self._admitted >= MAX_REQUESTS:
                self._rejected += 1
                return False
            self._admitted += 1
            return True

    def note_handler(self) -> None:
        with self._budget_lock:
            self._handler_invocations += 1

    def counts(self) -> tuple[int, int, int]:
        with self._budget_lock:
            return self._admitted, self._rejected, self._handler_invocations


class _PingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "SniperSyntheticFixture/1"
    sys_version = ""

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        # This runs after parsing but before BaseHTTPRequestHandler dispatches
        # any do_* method. Every client/thread shares the same server lock.
        if not self.server.admit():
            self.close_connection = True
            self._reply(429, _BUDGET_EXHAUSTED)
            return False
        return True

    def do_GET(self) -> None:
        self.server.note_handler()
        if self.path == "/api/ping":
            self._reply(200, _PING)
        else:
            self._reply(404, _NOT_FOUND)

    def do_POST(self) -> None:
        self.server.note_handler()
        self._reply(405, _METHOD_NOT_ALLOWED)

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST
    do_HEAD = do_POST

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args: object) -> None:
        pass


class SyntheticPingFixture:
    """One-shot loopback listener; stop it to release its port deterministically."""

    def __init__(self, port: int = 0) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not (
            port == 0 or 1024 <= port <= 65535
        ):
            raise ValueError("Port 0 veya 1024 ile 65535 arasında ayrıcalıksız bir port kullanın.")
        self._port = port
        self._state_lock = threading.Lock()
        self._used = False
        self._server: _BudgetHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._address: tuple[str, int] | None = None

    def start(self) -> "SyntheticPingFixture":
        with self._state_lock:
            if self._used:
                raise RuntimeError("Fikstür örnekleri tek kullanımlıktır.")
            self._used = True
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                raise PermissionError("Fikstürü ayrıcalıksız bir kullanıcıyla çalıştırın.")
            server = _BudgetHTTPServer(("127.0.0.1", self._port))
            thread = threading.Thread(target=server.serve_forever, name="synthetic-ping-fixture")
            try:
                thread.start()
            except BaseException:
                server.server_close()
                raise
            self._server = server
            self._thread = thread
            self._address = server.server_address
        return self

    def stop(self) -> None:
        with self._state_lock:
            server, thread = self._server, self._thread
            self._server = None
            self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
            assert thread is not None
            thread.join()
            if thread.is_alive():
                raise RuntimeError("Fikstür dinleyicisi durdurulamadı.")

    @property
    def address(self) -> tuple[str, int]:
        if self._address is None:
            raise RuntimeError("Fikstür başlatılmadı.")
        return self._address

    @property
    def origin(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    @property
    def admitted_requests(self) -> int:
        return self._counts()[0]

    @property
    def rejected_requests(self) -> int:
        return self._counts()[1]

    @property
    def handler_invocations(self) -> int:
        return self._counts()[2]

    def _counts(self) -> tuple[int, int, int]:
        if self._server is None:
            raise RuntimeError("Fikstür çalışmıyor.")
        return self._server.counts()

    def __enter__(self) -> "SyntheticPingFixture":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded synthetic 127.0.0.1 /api/ping fixture")
    parser.add_argument("--port", type=int, default=0,
                        help="0 for a free port, or an unprivileged port 1024-65535")
    args = parser.parse_args()
    stop = threading.Event()
    previous_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        with SyntheticPingFixture(port=args.port) as fixture:
            print(json.dumps({"origin": fixture.origin, "max_requests": MAX_REQUESTS},
                             separators=(",", ":"), sort_keys=True), flush=True)
            try:
                stop.wait()
            except KeyboardInterrupt:
                pass
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
