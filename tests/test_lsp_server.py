"""Editör tanılama sunucusu (LSP): JSON-RPC çerçeveleme, didOpen → tanılama, hızlı düzeltme, kapsam,
süre sınırı, büyük dosya ve gerçek stdio oturumu."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import lsp_server
import scan_scope

APP_DIR = Path(__file__).resolve().parents[1]
SQL_VULN = (
    "import sqlite3\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
    "@app.route('/u')\ndef user():\n    db = sqlite3.connect('x.db')\n"
    "    return str(db.execute(\"SELECT * FROM u WHERE id=\" + request.args['id']).fetchall())\n"
)


def frame(payload: dict) -> bytes:
    return lsp_server.encode_message(payload)


def parse_all(data: bytes) -> list[dict]:
    stream = io.BytesIO(data)
    out = []
    while True:
        message = lsp_server.read_message(stream)
        if message is None:
            return out
        out.append(message)


class FramingTests(unittest.TestCase):
    def test_round_trip_utf8_length_is_bytes(self):
        payload = {"jsonrpc": "2.0", "method": "x", "params": {"metin": "çğıöşü İ €"}}
        data = frame(payload)
        header, _, body = data.partition(b"\r\n\r\n")
        self.assertEqual(int(header.split(b":")[1]), len(body))
        self.assertGreater(len(body), len(json.dumps(payload, ensure_ascii=False)))  # çok baytlı karakterler
        self.assertEqual(parse_all(data + frame({"id": 2})), [payload, {"id": 2}])

    def test_extra_headers_and_eof(self):
        body = b'{"jsonrpc":"2.0","id":1}'
        data = b"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
        self.assertEqual(parse_all(data), [{"jsonrpc": "2.0", "id": 1}])
        self.assertIsNone(lsp_server.read_message(io.BytesIO(b"")))

    def test_bad_frames(self):
        for bad in (b"X-Foo: 1\r\n\r\n{}", b"Content-Length: abc\r\n\r\n", b"Content-Length: 10\r\n\r\n{}",
                    b"Content-Length: %d\r\n\r\n" % (lsp_server.MAX_MESSAGE_BYTES + 1), b"A" * 9000 + b"\r\n"):
            with self.subTest(bad=bad[:40]), self.assertRaises(lsp_server.ProtocolError):
                lsp_server.read_message(io.BytesIO(bad))
        with self.assertRaises(ValueError):
            lsp_server.read_message(io.BytesIO(b"Content-Length: 3\r\n\r\n[1]"))

    def test_text_edit_and_positions(self):
        old = "a\nb\nc\n"
        edit = lsp_server.text_edit_for(old, "a\nB\nc\n")
        self.assertEqual(edit, {"range": {"start": {"line": 1, "character": 0}, "end": {"line": 2, "character": 0}},
                                "newText": "B\n"})
        tail = lsp_server.text_edit_for("a\nb", "a\nb2")
        self.assertEqual(tail["range"]["end"], {"line": 1, "character": 1})
        self.assertIsNone(lsp_server.text_edit_for(old, old))
        self.assertEqual(lsp_server.utf16_len("a😀"), 3)


class ServerHarness(unittest.TestCase):
    """Bellek içi akışlarla eşzamanlı (synchronous) sunucu."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "proj"
        self.root.mkdir()
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.cache_dir = base / "cache"
        (self.root / "app.py").write_text(SQL_VULN, encoding="utf-8")

    def run_session(self, messages: list[dict], **kwargs) -> tuple[list[dict], lsp_server.SniperLanguageServer]:
        data = b"".join(frame(m) for m in messages)
        out = io.BytesIO()
        server = lsp_server.SniperLanguageServer(
            io.BytesIO(data), out, data_dir=self.data_dir, cache_dir=self.cache_dir,
            allowed_roots=(self.root.parent,), synchronous=kwargs.pop("synchronous", True), **kwargs)
        server.serve()
        return parse_all(out.getvalue()), server

    def init(self, **options) -> dict:
        return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"rootUri": self.root.as_uri(), "capabilities": {}, "initializationOptions": options}}

    def open_msg(self, rel: str, text: str | None = None, version: int = 1) -> dict:
        path = self.root / rel
        return {"jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": path.as_uri(), "languageId": "python", "version": version,
                                            "text": path.read_text(encoding="utf-8") if text is None else text}}}

    @staticmethod
    def end() -> list[dict]:
        return [{"jsonrpc": "2.0", "id": 99, "method": "shutdown"}, {"jsonrpc": "2.0", "method": "exit"}]

    @staticmethod
    def diagnostics(out: list[dict], uri: str) -> list[list[dict]]:
        return [m["params"]["diagnostics"] for m in out
                if m.get("method") == "textDocument/publishDiagnostics" and m["params"]["uri"] == uri]


class SessionTests(ServerHarness):
    def test_initialize_capabilities_and_lifecycle(self):
        out, server = self.run_session([self.init()] + self.end())
        init = next(m for m in out if m.get("id") == 1)["result"]
        self.assertEqual(init["serverInfo"]["name"], "sniper-lsp")
        self.assertEqual(init["capabilities"]["textDocumentSync"]["change"], 1)
        self.assertIn("quickfix", init["capabilities"]["codeActionProvider"]["codeActionKinds"])
        self.assertEqual(next(m for m in out if m.get("id") == 99)["result"], None)
        self.assertEqual(server.exit_code, 0)

    def test_requests_before_initialize_and_unknown_methods(self):
        out, server = self.run_session([
            {"jsonrpc": "2.0", "id": 5, "method": "textDocument/hover", "params": {}},
            self.init(),
            {"jsonrpc": "2.0", "id": 6, "method": "textDocument/hover", "params": {}},
            {"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 6}},
            {"jsonrpc": "2.0", "method": "exit"},
        ])
        errors = {m["id"]: m["error"]["code"] for m in out if "error" in m}
        self.assertEqual(errors, {5: lsp_server.SERVER_NOT_INITIALIZED, 6: lsp_server.METHOD_NOT_FOUND})
        self.assertEqual(server.exit_code, 1)  # shutdown olmadan exit

    def test_did_open_publishes_diagnostics_with_fingerprint(self):
        uri = (self.root / "app.py").as_uri()
        out, server = self.run_session([self.init(), self.open_msg("app.py")] + self.end())
        published = self.diagnostics(out, uri)
        self.assertEqual(len(published), 1)
        flows = [d for d in published[0] if d["data"].get("kind") == "sql"]
        self.assertTrue(flows, published[0])
        diag = flows[0]
        self.assertEqual(diag["source"], "sniper")
        self.assertEqual(diag["severity"], 1)  # yüksek/kritik → hata
        self.assertEqual(diag["range"]["start"]["line"], 9)
        self.assertEqual(diag["range"]["start"]["character"], 4)  # girinti atlanır
        self.assertEqual(diag["code"], "CWE-89")
        self.assertIn("cwe.mitre.org", diag["codeDescription"]["href"])
        self.assertRegex(diag["data"]["fingerprint"], r"^[0-9a-f]{32}$")
        self.assertIn("flow", diag["data"])
        self.assertEqual(server.stats["analyses"], 1)
        # Önbellek dizini 0700 ve canlı veri dizinine hiçbir şey yazılmadı.
        self.assertEqual(os.stat(self.cache_dir).st_mode & 0o777, 0o700)
        self.assertEqual(list(self.data_dir.iterdir()), [])

    def test_code_action_quickfix_parameterizes_query(self):
        uri = (self.root / "app.py").as_uri()
        out, _ = self.run_session([self.init(), self.open_msg("app.py")])
        diag = next(d for d in self.diagnostics(out, uri)[0] if d["data"].get("kind") == "sql")
        request = {"jsonrpc": "2.0", "id": 7, "method": "textDocument/codeAction",
                   "params": {"textDocument": {"uri": uri}, "range": diag["range"], "context": {"diagnostics": [diag]}}}
        out, _ = self.run_session([self.init(), self.open_msg("app.py"), request] + self.end())
        actions = next(m for m in out if m.get("id") == 7)["result"]
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action["kind"], "quickfix")
        self.assertTrue(action["title"].startswith("Sniper: Parametreli sorgu"))
        edit = action["edit"]["changes"][uri][0]
        self.assertIn("?", edit["newText"])
        self.assertNotIn("+ request", edit["newText"])
        lines = SQL_VULN.splitlines(keepends=True)
        applied = "".join(lines[:edit["range"]["start"]["line"]]) + edit["newText"] + "".join(lines[edit["range"]["end"]["line"]:])
        self.assertIn("WHERE id=?", applied)
        compile(applied, "app.py", "exec")
        # Sniper dışı ya da türü olmayan tanılamalara eylem yok.
        other = dict(diag, source="pylint")
        request["params"]["context"]["diagnostics"] = [other]
        out, _ = self.run_session([self.init(), self.open_msg("app.py"), request] + self.end())
        self.assertEqual(next(m for m in out if m.get("id") == 7)["result"], [])

    def test_code_action_uses_unsaved_buffer(self):
        uri = (self.root / "app.py").as_uri()
        out, _ = self.run_session([self.init(), self.open_msg("app.py")])
        diag = next(d for d in self.diagnostics(out, uri)[0] if d["data"].get("kind") == "sql")
        shifted = "# yeni satır\n" + SQL_VULN
        diag["range"]["start"]["line"] += 1
        diag["range"]["end"]["line"] += 1
        out, _ = self.run_session([
            self.init(), self.open_msg("app.py"),
            {"jsonrpc": "2.0", "method": "textDocument/didChange",
             "params": {"textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": shifted}]}},
            {"jsonrpc": "2.0", "id": 8, "method": "textDocument/codeAction",
             "params": {"textDocument": {"uri": uri}, "range": diag["range"], "context": {"diagnostics": [diag]}}},
        ] + self.end())
        edit = next(m for m in out if m.get("id") == 8)["result"][0]["edit"]["changes"][uri][0]
        self.assertEqual(edit["range"]["start"]["line"], 10)  # tamponda kaymış satır

    def test_did_close_clears_and_cache_reused_until_save(self):
        uri = (self.root / "app.py").as_uri()
        close = {"jsonrpc": "2.0", "method": "textDocument/didClose", "params": {"textDocument": {"uri": uri}}}
        save = {"jsonrpc": "2.0", "method": "textDocument/didSave", "params": {"textDocument": {"uri": uri}}}
        out, server = self.run_session([self.init(), self.open_msg("app.py"), close, self.open_msg("app.py"), save] + self.end())
        published = self.diagnostics(out, uri)
        self.assertEqual(len(published), 4)
        self.assertEqual(published[1], [])  # kapatınca temizlenir
        self.assertEqual(server.stats, {"analyses": 2, "cache_hits": 1, "timeouts": 0})  # yeniden açma önbellekten

    def test_files_outside_workspace_and_unsupported_are_ignored(self):
        outside = Path(self.tmp.name) / "dis.py"
        outside.write_text(SQL_VULN, encoding="utf-8")
        (self.root / "notes.md").write_text("# not\n", encoding="utf-8")
        msgs = [self.init(),
                {"jsonrpc": "2.0", "method": "textDocument/didOpen",
                 "params": {"textDocument": {"uri": outside.as_uri(), "languageId": "python", "version": 1, "text": SQL_VULN}}},
                self.open_msg("notes.md")] + self.end()
        out, server = self.run_session(msgs)
        self.assertFalse([m for m in out if m.get("method") == "textDocument/publishDiagnostics"])
        self.assertEqual(server.stats["analyses"], 0)

    def test_persisted_scope_is_respected(self):
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_x.py").write_text(SQL_VULN, encoding="utf-8")
        uri = (self.root / "tests" / "test_x.py").as_uri()
        out, _ = self.run_session([self.init(), self.open_msg("tests/test_x.py")] + self.end())
        self.assertEqual(self.diagnostics(out, uri), [[]])  # varsayılan kapsamda test dizini atlanır
        self.assertTrue(any("analiz edilmedi" in m["params"]["message"] for m in out if m.get("method") == "window/logMessage"))
        scan_scope.save_default(scan_scope.parse_scope({"include_dirs": ["tests"]}), {"SNIPER_DATA_DIR": str(self.data_dir)})
        out, _ = self.run_session([self.init(), self.open_msg("tests/test_x.py")] + self.end())
        self.assertTrue(any(d["data"].get("kind") == "sql" for d in self.diagnostics(out, uri)[0]))

    def test_min_severity_option(self):
        uri = (self.root / "app.py").as_uri()
        out, _ = self.run_session([self.init(), self.open_msg("app.py")] + self.end())
        self.assertEqual({d["data"]["severity"] for d in self.diagnostics(out, uri)[0]}, {"critical", "medium"})
        out, _ = self.run_session([self.init(minSeverity="critical"), self.open_msg("app.py")] + self.end())
        self.assertEqual({d["data"]["severity"] for d in self.diagnostics(out, uri)[0]}, {"critical"})


class LimitsTests(ServerHarness):
    def test_timeout_kills_worker_and_server_keeps_running(self):
        slow = [sys.executable, "-c", "import time; time.sleep(60)"]
        uri = (self.root / "app.py").as_uri()
        started = time.monotonic()
        out, server = self.run_session([self.init(), self.open_msg("app.py")] + self.end(),
                                       timeout=2.0, worker_command=slow)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(server.stats["timeouts"], 1)
        self.assertEqual(self.diagnostics(out, uri), [])  # eski tanılama korunur, boş yayın yok
        self.assertTrue(any("süre sınırını aştı" in m["params"]["message"] for m in out if m.get("method") == "window/logMessage"))
        self.assertEqual(next(m for m in out if m.get("id") == 99)["result"], None)

    def test_large_file_within_budget_and_oversized_skipped(self):
        body = "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(12_000))
        (self.root / "big.py").write_text(SQL_VULN + body, encoding="utf-8")
        self.assertLess((self.root / "big.py").stat().st_size, 1_000_000)
        uri = (self.root / "big.py").as_uri()
        started = time.monotonic()
        out, _ = self.run_session([self.init(), self.open_msg("big.py")] + self.end())
        elapsed = time.monotonic() - started
        self.assertTrue(any(d["data"].get("kind") == "sql" for d in self.diagnostics(out, uri)[0]))
        self.assertLess(elapsed, 30, f"büyük dosya analizi {elapsed:.1f} sn")
        (self.root / "huge.py").write_text(SQL_VULN + body * 3, encoding="utf-8")  # > 1 MB: kapsam sınırı
        uri = (self.root / "huge.py").as_uri()
        out, _ = self.run_session([self.init(), self.open_msg("huge.py")] + self.end())
        self.assertEqual(self.diagnostics(out, uri), [[]])

    def test_async_worker_thread_coalesces(self):
        uri = (self.root / "app.py").as_uri()
        save = {"jsonrpc": "2.0", "method": "textDocument/didSave", "params": {"textDocument": {"uri": uri}}}
        data = b"".join(frame(m) for m in [self.init(), self.open_msg("app.py"), save, save])
        reader = io.BytesIO(data)
        out = io.BytesIO()
        server = lsp_server.SniperLanguageServer(reader, out, data_dir=self.data_dir, cache_dir=self.cache_dir,
                                                 allowed_roots=(self.root.parent,))
        server._thread = None
        import threading

        thread = threading.Thread(target=server._worker_loop, daemon=True)
        thread.start()
        while True:
            message = lsp_server.read_message(reader)
            if message is None:
                break
            server.handle(message)
        self.assertTrue(server.wait_idle(60))
        server._stop.set()
        published = self.diagnostics(parse_all(out.getvalue()), uri)
        self.assertGreaterEqual(len(published), 1)
        self.assertLessEqual(len(published), 3)
        self.assertTrue(any(d["data"].get("kind") == "sql" for d in published[-1]))


class StdioEndToEndTests(unittest.TestCase):
    """Gerçek süreç: scripts/sniper-lsp stdio üzerinden (proje kullanıcı dizini altında olmalı)."""

    def test_real_process_session(self):
        base = Path.home() / ".cache"
        if not os.access(base, os.W_OK):
            self.skipTest("kullanıcı önbellek dizini yazılamıyor")
        with tempfile.TemporaryDirectory(dir=base, prefix="sniper-lsp-test-") as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "app.py").write_text(SQL_VULN, encoding="utf-8")
            data_dir = Path(tmp) / "data"
            data_dir.mkdir()
            uri = (root / "app.py").as_uri()
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"rootUri": root.as_uri(), "capabilities": {}}},
                {"jsonrpc": "2.0", "method": "initialized", "params": {}},
                {"jsonrpc": "2.0", "method": "textDocument/didOpen",
                 "params": {"textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": SQL_VULN}}},
            ]
            proc = subprocess.Popen([sys.executable, str(APP_DIR / "scripts" / "sniper-lsp"), "--data-dir", str(data_dir),
                                     "--cache-dir", str(Path(tmp) / "cache")],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                for m in messages:
                    proc.stdin.write(frame(m))
                proc.stdin.flush()
                found = None
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    message = lsp_server.read_message(proc.stdout)
                    if message is None:
                        break
                    if message.get("method") == "textDocument/publishDiagnostics":
                        found = message["params"]["diagnostics"]
                        break
                proc.stdin.write(frame({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}))
                proc.stdin.write(frame({"jsonrpc": "2.0", "method": "exit"}))
                proc.stdin.flush()
                proc.stdin.close()
                self.assertEqual(proc.wait(timeout=20), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                proc.stdout.close()
            self.assertTrue(found and any(d["data"].get("kind") == "sql" for d in found), found)


if __name__ == "__main__":
    unittest.main()
