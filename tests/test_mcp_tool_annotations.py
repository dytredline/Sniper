"""Public MCP tool metadata is an agent safety contract, independent of the database."""

import unittest

import mcp_triage_server


class MCPToolAnnotationTests(unittest.TestCase):
    def test_tools_list_declares_effects_for_both_modes(self) -> None:
        expected = {
            "list_findings": (True, False, True, False),
            "get_finding": (True, False, True, False),
            "read_source": (True, False, True, False),
            "submit_triage": (False, True, False, False),
            "list_scan_profiles": (True, False, True, False),
            "list_scan_requests": (True, False, True, False),
            "request_scan": (False, False, False, False),
            "list_scan_result_findings": (True, False, True, False),
            "submit_scan_result_triage": (False, False, False, False),
            "list_community_capabilities": (True, False, True, False),
            "community_job_status": (True, False, True, False),
            "prepare_action": (False, False, False, False),
            "execute_action": (False, True, False, True),
        }
        keys = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
        for mode in ("authenticated", "community"):
            with self.subTest(mode=mode):
                server = mcp_triage_server.TriageMCPServer(
                    None, mode=mode, community_actions=object(),
                )
                reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                self.assertIsNotNone(reply)
                tools = {tool["name"]: tool for tool in reply["result"]["tools"]}
                expected_names = set(expected) if mode == "community" else {
                    tool["name"] for tool in mcp_triage_server.TOOLS
                }
                self.assertEqual(set(tools), expected_names)
                for name, tool in tools.items():
                    annotations = tool["annotations"]
                    self.assertEqual(set(annotations), set(keys))
                    self.assertEqual(tuple(annotations[key] for key in keys), expected[name])


if __name__ == "__main__":
    unittest.main()
