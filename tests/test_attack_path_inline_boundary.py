from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from attack_path_correlator import correlate_attack_paths


class AttackPathInlineBoundaryTests(unittest.TestCase):
    def test_inline_project_audit_cannot_use_payload_paths_for_source_lookup(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            project = Path(temp)
            source = project / "chosen.py"
            source.write_text(
                "def payload_selected_handler():\n"
                "    user_value = request.args.get('value')\n"
                "    return db.execute('SELECT ' + user_value)\n",
                encoding="utf-8",
            )
            inline_audit = {
                "project_path": str(project),
                "route_inventory": {
                    "routes": [{
                        "file": "router.py",
                        "line": 1,
                        "path": "/selected",
                        "methods": ["GET"],
                        "handler": "payload_selected_handler",
                        "public": True,
                    }]
                },
                "findings": [{
                    "file": "chosen.py",
                    "line": 3,
                    "category": "data_query",
                    "severity": "critical",
                    "title": "inline payload must not authorize a file read",
                    "taint_flow": {
                        "source_label": "request",
                        "source_file": "chosen.py",
                        "source_line": 2,
                        "source": "request.args",
                        "sink": "db.execute",
                        "sink_kind": "sql",
                    },
                }],
            }

            result = correlate_attack_paths(project_audit=inline_audit)

        self.assertEqual(result["route_chain_count"], 0)
        self.assertEqual(result["route_chains"], [])


if __name__ == "__main__":
    unittest.main()
