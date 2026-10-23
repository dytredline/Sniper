from __future__ import annotations

import inspect
from pathlib import Path
import unittest

import server


APP = Path(__file__).resolve().parents[1]


class DocumentationContractsR28Tests(unittest.TestCase):
    def test_release_guide_and_auth_statements_match_product(self) -> None:
        readme = (APP / "README.md").read_text(encoding="utf-8")
        guide = (APP / "docs" / "KULLANIM-KILAVUZU.md").read_text(encoding="utf-8")
        doc = inspect.getdoc(server.remote_bind_refusal) or ""

        self.assertRegex(guide.splitlines()[0], r"sürüm 2\.0\.1-r\d+")
        self.assertNotIn("uygulamada kimlik doğrulama olmadığından", readme)
        self.assertNotIn("Çok kullanıcılı kimlik doğrulama bu paketin kapsamında değildir", readme)
        self.assertIn("SNIPER_REMOTE_AUTH_ACK=1", readme)
        self.assertIn("isteğe bağlı giriş", doc)

    def test_known_limits_describe_narrow_runtime_proof_and_agent_triage(self) -> None:
        readme = (APP / "README.md").read_text(encoding="utf-8")
        guide = (APP / "docs" / "KULLANIM-KILAVUZU.md").read_text(encoding="utf-8")
        self.assertNotIn("Yerel yapay zekâ (AI) triyajı yok", guide)
        self.assertIn("MCP ajan triyajı", guide)
        self.assertIn("açık yönlendirme", guide)
        self.assertIn("ASan öz sınaması", guide)
        self.assertIn("c-reference-set1", guide)
        for contract in (
            "/api/mcp-scan-requests", "/api/runtime-proofs/asan-selftest",
            "/runtime-proof/open-redirect", "/runtime-proof/reflected-html", "/runtime-proof/asan-binary",
            "/runtime-proof/asan-compile-database",
            "list_scan_result_findings", "scripts/prepare_ground_truth.py",
        ):
            self.assertIn(contract, readme)
        self.assertIn("triage_summary", guide)


if __name__ == "__main__":
    unittest.main()
