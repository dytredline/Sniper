"""Independent runtime checks for connection and HTTP budgets on fresh fixtures."""
from __future__ import annotations

import select
import socket
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from schemathesis_synthetic_fixture import MAX_REQUESTS, SyntheticPingFixture


def half_open(address: tuple[str, int]) -> socket.socket:
    sock = socket.create_connection(address, timeout=2)
    sock.settimeout(1)
    sock.sendall(b"GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1\r\n")
    return sock


def live_handlers(fixture: SyntheticPingFixture) -> int:
    threads = fixture._server._threads
    if threads is type(fixture._server)._threads:
        # ThreadingMixIn starts with a non-iterable sentinel before first accept.
        return 0
    return sum(thread.is_alive() for thread in threads)


class ConnectionBoundTests(unittest.TestCase):
    def fill_eight_slots(self, fixture: SyntheticPingFixture) -> list[socket.socket]:
        held = [half_open(fixture.address) for _ in range(8)]
        deadline = time.monotonic() + 1.5
        while live_handlers(fixture) < 8 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(live_handlers(fixture), 8)
        return held

    def test_32_half_open_clients_do_not_spawn_more_than_eight_handlers(self):
        fixture = SyntheticPingFixture()
        fixture.start()
        held: list[socket.socket] = []
        overflow: list[socket.socket] = []
        try:
            held = self.fill_eight_slots(fixture)
            overflow = [half_open(fixture.address) for _ in range(24)]
            ready, _, _ = select.select(overflow, [], [], 0.8)
            # Accepted overflow sockets close without a handler thread. Some
            # sockets may still be queued in the kernel accept backlog.
            self.assertGreater(len(ready), 0)
            self.assertLessEqual(live_handlers(fixture), 8)
            for sock in ready:
                try:
                    self.assertEqual(sock.recv(1), b"")
                except ConnectionResetError:
                    pass
            self.assertEqual(fixture.admitted_requests, 0)
            self.assertEqual(fixture.handler_invocations, 0)
        finally:
            for sock in held + overflow:
                sock.close()
            fixture.stop()

    def test_held_client_exit_releases_slots_for_new_ping(self):
        fixture = SyntheticPingFixture()
        fixture.start()
        held: list[socket.socket] = []
        try:
            held = self.fill_eight_slots(fixture)
            for sock in held:
                sock.close()
            held.clear()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    with urlopen(fixture.origin + "/api/ping", timeout=0.5) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(), b'{"ok":true}')
                    break
                except (URLError, ConnectionResetError):
                    time.sleep(0.05)
            else:
                self.fail("handler slot was not released after held clients closed")
        finally:
            for sock in held:
                sock.close()
            fixture.stop()

    def test_fresh_fixture_still_rejects_25th_http_request_before_handler(self):
        self.assertEqual(MAX_REQUESTS, 24)  # Public README contract: 24 accepted, 25th rejected.
        with SyntheticPingFixture() as fixture:
            for _ in range(MAX_REQUESTS):
                with urlopen(fixture.origin + "/api/ping", timeout=2) as response:
                    self.assertEqual(response.status, 200)
            with self.assertRaises(HTTPError) as error:
                urlopen(fixture.origin + "/api/ping", timeout=2)
            self.assertEqual(error.exception.code, 429)
            self.assertEqual(fixture.admitted_requests, MAX_REQUESTS)
            self.assertEqual(fixture.handler_invocations, MAX_REQUESTS)
            self.assertEqual(fixture.rejected_requests, 1)

    def test_bad_request_releases_handler_slot(self):
        with SyntheticPingFixture() as fixture:
            for _ in range(12):
                with socket.create_connection(fixture.address, timeout=2) as sock:
                    sock.sendall(b"BROKEN\r\n\r\n")
                    sock.settimeout(2)
                    try:
                        sock.recv(4096)
                    except ConnectionResetError:
                        pass
            with urlopen(fixture.origin + "/api/ping", timeout=2) as response:
                self.assertEqual(response.status, 200)
            self.assertEqual(fixture.admitted_requests, 1)

    def test_shutdown_drains_half_open_handlers(self):
        fixture = SyntheticPingFixture()
        fixture.start()
        held = self.fill_eight_slots(fixture)
        origin = fixture.origin
        try:
            started = time.monotonic()
            fixture.stop()
            self.assertLess(time.monotonic() - started, 6)
            with self.assertRaises(URLError):
                urlopen(origin + "/api/ping", timeout=0.5)
        finally:
            for sock in held:
                sock.close()
            fixture.stop()


if __name__ == "__main__":
    unittest.main()
