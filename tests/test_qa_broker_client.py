from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import qa_broker_client as qa  # noqa: E402


class FakeBroker:
    """Gerçek Unix soketi; tek bağlantıya verilen yanıtı yazar."""

    def __init__(self, directory: Path, reply: bytes | None) -> None:
        self.path = directory / "request.sock"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path))
        os.chmod(self.path, 0o660)
        self.server.listen(1)
        self.reply = reply
        self.received = b""
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        conn, _ = self.server.accept()
        with conn:
            self.received = conn.makefile("rb").readline(600)
            if self.reply is not None:
                conn.sendall(self.reply)

    def close(self) -> None:
        self.thread.join(timeout=5)
        self.server.close()
        self.path.unlink(missing_ok=True)


class QABrokerClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.data = self.root / "data"
        self.data.mkdir()
        self.env = mock.patch.dict(os.environ, {"SNIPER_QA_BROKER": "1", "SNIPER_DATA_DIR": str(self.data)})
        self.env.start()
        self.ids = mock.patch.object(qa, "_identities", return_value=(os.getuid(), os.getgid()))
        self.ids.start()
        # Sahte soket kendi geçici dizinimizde; gerçek aracı dizini bizim değildir.
        self.parent = mock.patch.object(qa, "_parent_is_foreign", return_value=True)
        self.parent.start()

    def tearDown(self) -> None:
        self.parent.stop()
        self.ids.stop()
        self.env.stop()
        self.tmp.cleanup()

    def _run(self, reply: bytes | None, operation: str = "k6") -> tuple[dict, bytes]:
        broker = FakeBroker(self.root, reply)
        try:
            return qa.run_qa_broker_probe(operation, path=broker.path), broker.received
        finally:
            broker.close()

    def test_passed_result_is_filtered(self) -> None:
        output = "\x1b[32m✓ status 200\x1b[0m\x07\n" + "x" * 5000
        reply = json.dumps({"operation": "k6", "exit_code": 0, "fixture_hits": 1, "passed": True, "output": output})
        result, received = self._run(reply.encode() + b"\n")
        self.assertEqual(json.loads(received), {"operation": "k6"})
        self.assertTrue(result["passed"])
        self.assertEqual(result["fixture_hits"], 1)
        self.assertLessEqual(len(result["output_tail"]), qa.OUTPUT_TAIL)
        self.assertNotIn("\x1b", result["output_tail"])
        self.assertEqual(len(result["output_sha256"]), 64)

    def test_passed_requires_exit_zero_and_fixture_hit(self) -> None:
        reply = json.dumps({"operation": "schemathesis", "exit_code": 0, "fixture_hits": 0, "passed": True, "output": ""})
        result, _ = self._run(reply.encode() + b"\n", "schemathesis")
        self.assertFalse(result["passed"])

    def test_broker_error_and_invalid_responses(self) -> None:
        result, _ = self._run(b'{"passed":false,"error":"BrokerError"}\n')
        self.assertEqual(result, {"format": "sniper-qa-broker-v1", "operation": "k6", "passed": False, "error": "BrokerError"})
        for bad in (b"[]", b"not json", b'{"operation":"schemathesis","exit_code":0,"fixture_hits":1,"passed":true,"output":""}',
                    b'{"operation":"k6","exit_code":0,"fixture_hits":1,"passed":true,"output":"","extra":1}'):
            with self.assertRaises(qa.QABrokerError):
                self._run(bad + b"\n")

    def test_silent_close_means_rejected(self) -> None:
        with self.assertRaises(qa.QABrokerUnavailable):
            self._run(None)

    def test_oversized_response_rejected(self) -> None:
        with self.assertRaises(qa.QABrokerError):
            self._run(b"{" + b" " * (qa.RESPONSE_MAX + 10) + b"}\n")

    def test_disabled_invalid_operation_and_socket_checks(self) -> None:
        with self.assertRaises(ValueError):
            qa.run_qa_broker_probe("bash")
        with mock.patch.dict(os.environ, {"SNIPER_QA_BROKER": "0"}):
            with self.assertRaises(qa.QABrokerUnavailable):
                qa.run_qa_broker_probe("k6", path=self.root / "missing.sock")
        with self.assertRaises(qa.QABrokerUnavailable):
            qa.run_qa_broker_probe("k6", path=self.root / "missing.sock")
        regular = self.root / "regular.sock"
        regular.write_text("x")
        with self.assertRaises(qa.QABrokerUnavailable):
            qa.run_qa_broker_probe("k6", path=regular)
        broker = FakeBroker(self.root, b"")
        try:
            os.chmod(broker.path, 0o666)
            with self.assertRaises(qa.QABrokerUnavailable):
                qa.run_qa_broker_probe("k6", path=broker.path)
        finally:
            socket.socket(socket.AF_UNIX).connect(str(broker.path))
            broker.close()

    def test_peer_uid_mismatch_rejected(self) -> None:
        with mock.patch.object(qa, "_identities", return_value=(os.getuid(), os.getgid())):
            broker = FakeBroker(self.root, b'{"passed":false,"error":"X"}\n')
            try:
                with mock.patch.object(qa, "_check_socket"), \
                        mock.patch.object(qa, "_identities", return_value=(os.getuid() + 1, os.getgid())):
                    with self.assertRaises(qa.QABrokerUnavailable):
                        qa.run_qa_broker_probe("k6", path=broker.path)
            finally:
                broker.close()

    def test_status_reports_reason_without_connecting(self) -> None:
        missing = qa.status(self.root / "missing.sock")
        self.assertEqual(missing["reason"], "broker_socket_missing")
        broker = FakeBroker(self.root, b"")
        try:
            state = qa.status(broker.path)
            self.assertTrue(state["socket_ok"])
            self.assertEqual(state["reason"], "ready")
            with mock.patch.dict(os.environ, {"SNIPER_QA_BROKER": "0"}):
                self.assertEqual(qa.status(broker.path)["reason"], "disabled")
        finally:
            socket.socket(socket.AF_UNIX).connect(str(broker.path))
            broker.close()


class UnitLaunchTests(unittest.TestCase):
    def test_unit_command_is_fixed_and_namespace_free(self) -> None:
        command = qa._unit_command("sniper-qa-probe-x", "k6")
        self.assertEqual(command[-4:], [str(Path(qa.__file__).resolve()), "--exchange", "k6", str(qa.SOCKET_PATH)])
        joined = " ".join(command)
        for prop in ("NoNewPrivileges=yes", "RestrictAddressFamilies=AF_UNIX", "MemoryMax=128M", "TasksMax=16"):
            self.assertIn(prop, joined)
        for namespacing in ("PrivateTmp", "ProtectSystem", "ProtectHome", "PrivateNetwork", "ReadWritePaths"):
            self.assertNotIn(namespacing, joined)

    def _completed(self, code: int, out: bytes = b"", err: bytes = b"") -> mock.Mock:
        return mock.Mock(returncode=code, stdout=out, stderr=err)

    def test_unit_exit_codes_map_to_errors(self) -> None:
        reply = b'{"passed":false,"error":"BrokerError"}\n'
        self.assertEqual(qa._exchange_via_unit("k6", runner=lambda *a, **k: self._completed(0, reply)), reply)
        with self.assertRaises(qa.QABrokerUnavailable) as caught:
            qa._exchange_via_unit("k6", runner=lambda *a, **k: self._completed(3, err=b"broker_connect_failed\n"))
        self.assertEqual(str(caught.exception), "broker_connect_failed")
        with self.assertRaises(qa.QABrokerError) as caught:
            qa._exchange_via_unit("k6", runner=lambda *a, **k: self._completed(4, err=b"Traceback: secret /path\n"))
        self.assertEqual(str(caught.exception), "probe_unit_failed")
        with self.assertRaises(qa.QABrokerError):
            qa._exchange_via_unit("k6", runner=lambda *a, **k: self._completed(0, b"x" * (qa.RESPONSE_MAX + 1)))

    def test_helper_rejects_anything_but_fixed_arguments(self) -> None:
        for argv in ([], ["--exchange", "bash", str(qa.SOCKET_PATH)], ["--exchange", "k6", "/tmp/evil.sock"],
                     ["--other", "k6", str(qa.SOCKET_PATH)], ["--exchange", "k6", str(qa.SOCKET_PATH), "x"]):
            with mock.patch.object(qa, "_exchange") as exchange, mock.patch("sys.stderr"):
                self.assertEqual(qa._helper_main(argv), 4, argv)
                exchange.assert_not_called()

    def test_launch_mode_override(self) -> None:
        with mock.patch.dict(os.environ, {"SNIPER_QA_BROKER_LAUNCH": "direct"}):
            self.assertEqual(qa._launch_mode(), "direct")
        with mock.patch.dict(os.environ, {"SNIPER_QA_BROKER_LAUNCH": ""}), \
                mock.patch.object(qa, "_in_user_namespace", return_value=True):
            self.assertEqual(qa._launch_mode(), "systemd-run" if qa.SYSTEMD_RUN.is_file() else "direct")


class NamespaceIdentityTests(unittest.TestCase):
    def test_visible_id_maps_through_namespace_or_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "overflow").write_text("65534\n")
            (root / "full").write_text("         0          0 4294967295\n")
            (root / "single").write_text("      1000       1000          1\n")
            (root / "shifted").write_text("0 100000 65536\n")
            self.assertEqual(qa._visible_id(996, str(root / "full"), str(root / "overflow")), 996)
            self.assertEqual(qa._visible_id(996, str(root / "single"), str(root / "overflow")), 65534)
            self.assertEqual(qa._visible_id(1000, str(root / "single"), str(root / "overflow")), 1000)
            self.assertEqual(qa._visible_id(100996, str(root / "shifted"), str(root / "overflow")), 996)
            (root / "bad").write_text("x y z\n")
            with self.assertRaises(qa.QABrokerUnavailable):
                qa._visible_id(1, str(root / "bad"), str(root / "overflow"))

    def test_own_or_writable_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(qa._parent_is_foreign(Path(tmp), os.lstat(tmp)))
        if os.getuid() != 0:
            self.assertTrue(qa._parent_is_foreign(Path("/proc/1"), os.lstat("/proc/1")))


if __name__ == "__main__":
    unittest.main()
