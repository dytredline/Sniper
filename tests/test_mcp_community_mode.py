from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile
import unittest
from unittest import mock

import ai_triage
import mcp_triage_server
import tool_runtime_autodiscover
from scanner import normalize_target
from storage import Store
from tests.test_finding_tracking_collab import finding, make_audit, tracked_ids


PYTHON = "/usr/bin/python3"
APP_DIR = Path(__file__).resolve().parents[1]


def _tool_payload(reply: dict) -> dict:
    return json.loads(reply["content"][0]["text"])


class MCPCommunityModeTests(unittest.TestCase):
    def test_public_mcp_source_has_no_machine_specific_home(self) -> None:
        source = Path(mcp_triage_server.__file__).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"/home/(?!community-user(?:/|\b))[A-Za-z0-9_.-]+", source))

    def test_installed_live_root_uses_os_account_home_not_client_home_environment(self) -> None:
        spoofed = self.root / "spoofed-home" if hasattr(self, "root") else Path("/tmp/spoofed-mcp-home")
        code = "import mcp_triage_server as m; print(m.INSTALLED_SNIPER_ROOT)"
        proc = subprocess.run(
            [PYTHON, "-c", code],
            cwd=APP_DIR,
            env={**os.environ, "HOME": str(spoofed), "PYTHONPATH": str(APP_DIR)},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        self.assertEqual(Path(proc.stdout.strip()), account_home / ".local" / "share" / "sniper")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "app.py").write_text("from flask import request\nvalue = request.args['value']\n", encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        make_audit(self.store, self.project, [finding("app.py", 2)])
        self.finding_id = tracked_ids(self.store, self.project)[0]
        self.target = self.store.create_target(normalize_target("https://example.com"))
        self.engagement = self.store.create_engagement(
            target_id=self.target["id"],
            name="Yetkili Community testi",
            authorization_ref="AUTH-COMMUNITY",
            scope_notes="Yalnız kayıtlı hedef",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )

    def test_community_local_owner_can_use_existing_write_and_catalog_tools_without_token(self) -> None:
        server = mcp_triage_server.TriageMCPServer(self.store, mode="community")
        self.assertEqual(server.user["role"], "admin")
        self.assertEqual(server.user["id"], "community-local-owner")

        catalog = server.call_tool("list_scan_profiles", {})
        self.assertFalse(catalog["isError"])
        self.assertIn("nuclei_http_authorized", {item["id"] for item in _tool_payload(catalog)["profiles"]})

        submitted = server.call_tool("submit_triage", {
            "finding_id": self.finding_id,
            "verdict": "uncertain",
            "confidence": 0.5,
            "rationale": "Community yerel sahip önerisi; insan kararı bekleniyor.",
        })
        self.assertFalse(submitted["isError"])
        self.assertEqual(_tool_payload(submitted)["decision"], "pending")
        self.assertEqual(self.store.get_tracked_finding(self.finding_id)["status"], "open")

        requested = server.call_tool("request_scan", {
            "profile_id": "nuclei_http_authorized",
            "parameters": {"target_id": self.target["id"], "engagement_id": self.engagement["id"]},
            "confirm_request": True,
        })
        self.assertFalse(requested["isError"])
        self.assertEqual(_tool_payload(requested)["status"], "pending")
        self.assertEqual(len(_tool_payload(server.call_tool("list_scan_requests", {}))["requests"]), 1)

    def test_community_source_context_needs_no_separate_external_agent_consent(self) -> None:
        self.assertFalse(ai_triage.external_allowed(self.data_dir, str(self.project)))
        community = mcp_triage_server.TriageMCPServer(self.store, mode="community")

        listing = _tool_payload(community.call_tool("list_findings", {"project": str(self.project)}))
        self.assertTrue(listing["external_agents_allowed"])
        self.assertTrue(listing["community_local_access"])
        self.assertNotIn("note", listing)

        detail = community.call_tool("get_finding", {"finding_id": self.finding_id})
        self.assertFalse(detail["isError"])
        self.assertIn("request.args", json.dumps(_tool_payload(detail), ensure_ascii=False))
        source = community.call_tool("read_source", {
            "project": self.finding_id, "path": "app.py", "start_line": 1, "end_line": 2,
        })
        self.assertFalse(source["isError"])
        self.assertIn("request.args", _tool_payload(source)["text"])

        escaped = community.call_tool("read_source", {"project": self.finding_id, "path": "../outside"})
        self.assertTrue(escaped["isError"])
        authenticated = mcp_triage_server.TriageMCPServer(self.store)
        self.assertTrue(authenticated.call_tool("get_finding", {"finding_id": self.finding_id})["isError"])

    def test_cli_defaults_to_community_stdio_and_performs_no_scan(self) -> None:
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "clientInfo": {"name": "community-test"},
            }},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_finding", "arguments": {"finding_id": self.finding_id},
            }},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "submit_triage", "arguments": {
                    "finding_id": self.finding_id, "verdict": "likely_true", "confidence": 0.8,
                    "rationale": "Community stdio varsayılanı.",
                },
            }},
        ]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(APP_DIR)
        run = subprocess.run(
            [PYTHON, str(APP_DIR / "mcp_triage_server.py"), "--db", str(self.store.path)],
            input="".join(json.dumps(item) + "\n" for item in messages),
            text=True,
            capture_output=True,
            timeout=20,
            env=env,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        replies = {item["id"]: item for item in map(json.loads, run.stdout.splitlines())}
        self.assertIn("Community", replies[1]["result"]["instructions"])
        self.assertFalse(replies[2]["result"]["isError"])
        self.assertFalse(replies[3]["result"]["isError"])
        self.assertEqual(_tool_payload(replies[3]["result"])["decision"], "pending")

    def test_candidate_default_database_is_local_and_never_installed_live_database(self) -> None:
        with mock.patch.dict(os.environ, {"SNIPER_DB_PATH": "", "SNIPER_DATA_DIR": "", "XDG_DATA_HOME": ""}):
            default_path = mcp_triage_server._resolve_db(None)
        self.assertEqual(default_path, Path.home() / ".local" / "share" / "sniper-community" / "sniper.db")
        self.assertFalse(mcp_triage_server._is_installed_live_db(default_path))
        self.assertTrue(mcp_triage_server._is_installed_live_db(mcp_triage_server.INSTALLED_LIVE_DB))
        self.assertTrue(mcp_triage_server._is_installed_live_db(
            mcp_triage_server.INSTALLED_SNIPER_ROOT / "app" / "not-a-database",
        ))
        with mock.patch.dict(os.environ, {"SNIPER_MCP_MODE": "", "SNIPER_MCP_TOKEN_FILE": ""}), \
                mock.patch.object(mcp_triage_server, "_resolve_db",
                                  return_value=mcp_triage_server.INSTALLED_LIVE_DB):
            self.assertEqual(mcp_triage_server.main([]), 2)

        local_data = self.root / "chosen-data"
        with mock.patch.dict(os.environ, {"SNIPER_DB_PATH": "", "SNIPER_DATA_DIR": str(local_data)}):
            self.assertEqual(mcp_triage_server._resolve_db(None), local_data / "sniper.db")

        xdg_data = self.root / "xdg"
        with mock.patch.dict(os.environ, {"SNIPER_DB_PATH": "", "SNIPER_DATA_DIR": "",
                                          "XDG_DATA_HOME": str(xdg_data), "SNIPER_MCP_MODE": "",
                                          "SNIPER_MCP_TOKEN_FILE": ""}), \
                mock.patch.object(mcp_triage_server.TriageMCPServer, "serve") as serve:
            self.assertEqual(mcp_triage_server._resolve_db(None), xdg_data / "sniper-community" / "sniper.db")
            self.assertEqual(mcp_triage_server.main([]), 0)
        self.assertTrue((xdg_data / "sniper-community" / "sniper.db").is_file())
        self.assertEqual((xdg_data / "sniper-community").stat().st_mode & 0o777, 0o700)
        self.assertEqual((xdg_data / "sniper-community" / "sniper.db").stat().st_mode & 0o777, 0o600)
        serve.assert_called_once()

    def test_community_cli_binds_verified_runtimes_before_server_start(self) -> None:
        xdg_data = self.root / "runtime-xdg"
        observed: list[tuple[dict, str]] = []

        def discover(**kwargs):
            observed.append((kwargs, os.environ.get("SNIPER_DATA_DIR", "")))
            os.environ["SNIPER_NUCLEI_BINARY"] = "/verified/community/nuclei"
            return {"format": "sniper-runtime-autodiscover-v1", "bound_tool_count": 1}

        with mock.patch.dict(os.environ, {
            "SNIPER_DB_PATH": "",
            "SNIPER_DATA_DIR": "",
            "XDG_DATA_HOME": str(xdg_data),
            "SNIPER_MCP_MODE": "",
            "SNIPER_MCP_TOKEN_FILE": "",
        }), mock.patch.object(
            tool_runtime_autodiscover,
            "autodiscover_and_bind_runtimes",
            side_effect=discover,
        ) as bind, mock.patch.object(mcp_triage_server.TriageMCPServer, "serve") as serve:
            self.assertEqual(mcp_triage_server.main(["--mode", "community"]), 0)

        expected_data = xdg_data / "sniper-community"
        bind.assert_called_once_with(apply_env=True, persist=True, include_readiness=False)
        self.assertEqual(observed, [(
            {"apply_env": True, "persist": True, "include_readiness": False},
            str(expected_data),
        )])
        serve.assert_called_once()

    def test_community_cli_discards_partial_bindings_when_discovery_fails(self) -> None:
        xdg_data = self.root / "failed-runtime-xdg"

        def fail_discovery(**_kwargs):
            os.environ["SNIPER_NUCLEI_BINARY"] = "/unverified/partial/nuclei"
            raise ValueError("invalid manifest")

        with mock.patch.dict(os.environ, {
            "SNIPER_DB_PATH": "",
            "SNIPER_DATA_DIR": "",
            "XDG_DATA_HOME": str(xdg_data),
            "SNIPER_MCP_MODE": "",
            "SNIPER_MCP_TOKEN_FILE": "",
            "SNIPER_NUCLEI_BINARY": "",
        }), mock.patch.object(
            tool_runtime_autodiscover,
            "autodiscover_and_bind_runtimes",
            side_effect=fail_discovery,
        ), mock.patch.object(mcp_triage_server.TriageMCPServer, "serve") as serve:
            self.assertEqual(mcp_triage_server.main(["--mode", "community"]), 0)
            self.assertEqual(os.environ["SNIPER_NUCLEI_BINARY"], "")

        serve.assert_called_once()

    def test_authenticated_cli_does_not_autodiscover_community_runtimes(self) -> None:
        with mock.patch.object(
            tool_runtime_autodiscover,
            "autodiscover_and_bind_runtimes",
        ) as bind, mock.patch.object(mcp_triage_server.TriageMCPServer, "serve") as serve:
            self.assertEqual(mcp_triage_server.main([
                "--mode", "authenticated", "--db", str(self.store.path),
            ]), 0)

        bind.assert_not_called()
        serve.assert_called_once()


if __name__ == "__main__":
    unittest.main()
