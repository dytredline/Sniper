"""In-memory API contract for the exact two-key Nuclei loopback request."""
from __future__ import annotations

import ast
import io
import json
import math
import os
import re
import unittest
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit


SOURCE_ROOT = Path(os.environ.get("SNIPER_TASK50_SOURCE_ROOT", Path(__file__).resolve().parents[1]))


def _source_handler():
    tree = ast.parse((SOURCE_ROOT / "server.py").read_text())
    handler = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "SniperHandler")
    required = {"do_POST", "_dispatch_post", "_read_json", "_json", "_error"}
    methods = [node for node in handler.body if isinstance(node, ast.FunctionDef) and node.name in required]
    if {node.name for node in methods} != required:
        raise AssertionError("Expected complete SniperHandler JSON POST path")
    handler.bases = []
    handler.keywords = []
    handler.decorator_list = []
    handler.body = methods
    namespace = {
        "HTTPStatus": HTTPStatus,
        "json": json,
        "math": math,
        "urlsplit": urlsplit,
        "_LARGE_BODY_PATHS": frozenset(),
        "LARGE_MAX_BODY_BYTES": 300_000,
        "DEFAULT_MAX_BODY_BYTES": 65_536,
        "NucleiUnavailable": type("NucleiUnavailable", (RuntimeError,), {}),
        "NucleiBusy": type("NucleiBusy", (RuntimeError,), {}),
        "NucleiExecutionError": type("NucleiExecutionError", (RuntimeError,), {}),
    }
    module = ast.fix_missing_locations(ast.Module(body=[handler], type_ignores=[]))
    exec(compile(module, str(SOURCE_ROOT / "server.py"), "exec"), namespace)
    return namespace["SniperHandler"], namespace


def _target_pattern():
    tree = ast.parse((SOURCE_ROOT / "nuclei_active.py").read_text())
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "TARGET_PATTERN" for target in node.targets)]
    if len(assignments) != 1:
        raise AssertionError("Expected one source-pinned Nuclei target pattern")
    namespace = {"re": re}
    exec(compile(ast.fix_missing_locations(ast.Module(body=assignments, type_ignores=[])),
                 str(SOURCE_ROOT / "nuclei_active.py"), "exec"), namespace)
    return namespace["TARGET_PATTERN"]


class NucleiExactKeysContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handler_class, cls.namespace = _source_handler()
        cls.target_pattern = _target_pattern()

    def invoke(self, body):
        raw = json.dumps(body, separators=(",", ":")).encode()
        namespace = self.namespace
        valid_calls = []
        delegate_invocations = []

        def fake_runner(target):
            delegate_invocations.append(target)
            match = self.target_pattern.fullmatch(target)
            if match is None or int(match.group(1)) > 65535:
                raise ValueError("target 1..65535 aralığında portla 127.0.0.1:<port> olmalı")
            valid_calls.append(target)
            return {"format": "nuclei-loopback-v1", "record_count": 0}

        namespace["run_nuclei_loopback"] = fake_runner

        class InMemoryHandler(self.handler_class):
            def __init__(self):
                self.command = "POST"
                self.path = "/api/tool-runs/nuclei-loopback"
                self.headers = Message()
                self.headers.add_header("Content-Type", "application/json")
                self.headers.add_header("Content-Length", str(len(raw)))
                self.rfile = io.BytesIO(raw)
                self.wfile = io.BytesIO()
                self.status = None

            def _request_preflight(self):
                return True

            def _rate_limit(self):
                return True

            def _origin_allowed(self):
                return True

            def send_response(self, status):
                self.status = int(status)

            def send_header(self, name, value):
                pass

            def end_headers(self):
                pass

        request = InMemoryHandler()
        request.do_POST()
        self.assertIsNotNone(request.status)
        return request.status, json.loads(request.wfile.getvalue()), valid_calls, delegate_invocations

    def test_exact_two_key_request_returns_200_with_one_delegate_call(self):
        status, response, calls, invocations = self.invoke(
            {"confirm_local": True, "target": "127.0.0.1:42424"})
        self.assertEqual(status, 200)
        self.assertEqual(response["format"], "nuclei-loopback-v1")
        self.assertEqual(calls, ["127.0.0.1:42424"])
        self.assertEqual(invocations, ["127.0.0.1:42424"])

    def test_unknown_key_is_400_before_runner_invocation(self):
        status, response, calls, invocations = self.invoke(
            {"confirm_local": True, "target": "127.0.0.1:42424", "unused": "no"})
        self.assertEqual(status, 400)
        self.assertIn("error", response)
        self.assertEqual(calls, [])
        self.assertEqual(invocations, [])

    def test_missing_consent_rejected_without_runner(self):
        status, response, calls, invocations = self.invoke({"target": "127.0.0.1:42424"})
        self.assertEqual(status, 400)
        self.assertIn("error", response)
        self.assertEqual(calls, [])
        self.assertEqual(invocations, [])

    def test_external_target_cannot_reach_would_execute_stub(self):
        status, response, calls, invocations = self.invoke(
            {"confirm_local": True, "target": "8.8.8.8:80"})
        self.assertEqual(status, 400)
        self.assertIn("error", response)
        self.assertEqual(calls, [])
        self.assertEqual(invocations, ["8.8.8.8:80"])


if __name__ == "__main__":
    unittest.main()
