import io
import os
import unittest


os.environ.setdefault("SNIPER_SCHEDULER", "0")

import server


class ResponseHeaderSafetyTests(unittest.TestCase):
    @staticmethod
    def handler() -> server.SniperHandler:
        handler = server.SniperHandler.__new__(server.SniperHandler)
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.requestline = "GET /response-header-proof HTTP/1.1"
        handler.wfile = io.BytesIO()
        handler.log_request = lambda *_args: None
        return handler

    def test_json_rejects_crlf_disposition_without_writing_response(self) -> None:
        handler = self.handler()

        with self.assertRaises(ValueError):
            handler._json(
                {"ok": True},
                disposition='attachment; filename="safe.json"\r\nX-Injected: yes',
            )

        self.assertEqual(handler.wfile.getvalue(), b"")
        buffered = b"".join(getattr(handler, "_headers_buffer", ()))
        self.assertNotIn(b"X-Injected", buffered)

    def test_common_header_sink_rejects_bare_cr_and_lf(self) -> None:
        for unsafe in ("safe\rX-Injected: yes", "safe\nX-Injected: yes"):
            with self.subTest(unsafe=repr(unsafe)):
                handler = self.handler()
                handler.send_response(200)

                with self.assertRaises(ValueError):
                    handler.send_header("X-Sniper-Test", unsafe)

                self.assertEqual(handler.wfile.getvalue(), b"")
                buffered = b"".join(getattr(handler, "_headers_buffer", ()))
                self.assertNotIn(b"X-Injected", buffered)

    def test_safe_json_disposition_is_preserved(self) -> None:
        handler = self.handler()

        handler._json(
            {"ok": True},
            disposition='attachment; filename="safe.json"',
        )

        raw = handler.wfile.getvalue()
        self.assertIn(
            b'\r\nContent-Disposition: attachment; filename="safe.json"\r\n',
            raw,
        )
        self.assertTrue(raw.endswith(b'\r\n\r\n{"ok":true}'))


if __name__ == "__main__":
    unittest.main()
