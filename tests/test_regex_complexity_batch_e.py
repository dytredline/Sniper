"""CodeQL polynomial-ReDoS batch E runtime and semantic regressions."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

import report_provenance
import runtime_proof
import sandbox_targets
import threat_model
import tool_report_k6_summary


ROOT = Path(__file__).resolve().parents[1]


def _k6_report(version: str) -> dict:
    return {
        "version": "1.0.0",
        "metadata": {"generatedAt": "2025-01-15T10:30:45Z", "k6Version": version},
        "config": {"execution": "local", "duration": 1},
        "results": {
            "metrics": [
                {"name": "http_reqs", "type": "counter", "contains": "default", "values": {"count": 1}},
            ],
        },
    }


class RegexComplexityBatchETests(unittest.TestCase):
    ADVERSARIAL = {
        "alert_427_nested_function": """
import report_provenance as m
m._nested_credential_value_end('A' * 300000, 0)
""",
        "alert_428_nested_gate": """
import report_provenance as m
m.redact_evidence_text('password=' + 'A' * 300000, max_len=0)
""",
        "alert_434_csp_source": """
import runtime_proof as m
m._valid_frame_ancestor_source('A' * 300000)
""",
        "alert_435_remote_host": """
import sandbox_targets as m
try:
    m.remote_host('0.' * 100000 + 'com')
except ValueError:
    pass
""",
        "alert_444_openapi_path": """
import threat_model as m
c = m.ThreatModelCollector('demo')
c.add('openapi.yaml', 'openapi: 3\\npaths:\\n  /' + ' ' * 60000 + 'X\\n', 'source')
""",
        "alert_445_nest_route": """
import threat_model as m
c = m.ThreatModelCollector('demo')
c.add('routes.ts', \"import {Controller,Get} from '@nestjs/common';\\n@Controller()\\n@Get()\\n\" + '\\n' * 10000, 'source')
""",
        "alert_446_k6_version": """
import tool_report_k6_summary as m
report = {'version': '1.0.0', 'metadata': {'generatedAt': '2025-01-15T10:30:45Z', 'k6Version': '1' * 300000}, 'config': {}, 'results': {}}
try:
    m.parse_k6_machine_summary_v1(report)
except ValueError:
    pass
""",
    }

    def test_codeql_adversarial_inputs_complete_with_linear_budget(self):
        for name, body in self.ADVERSARIAL.items():
            script = "import json,time\nt=time.monotonic()\n" + body + "\nprint(json.dumps({'elapsed': time.monotonic()-t}))\n"
            with self.subTest(alert=name):
                run = subprocess.run(
                    [sys.executable, "-c", script], cwd=ROOT, text=True, capture_output=True,
                    timeout=1.0, check=False,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertLess(json.loads(run.stdout)["elapsed"], 0.35, name)

    def test_redaction_and_validators_preserve_controls(self):
        redacted = report_provenance.redact_evidence_text(
            'password=String("top-secret") and secret recipe', max_len=0,
        )
        self.assertNotIn("top-secret", redacted)
        self.assertIn("password=[REDACTED]", redacted)
        self.assertIn("secret recipe", redacted)

        for source in ("'self'", "https:", "https://example.com", "*.example.com:443/path"):
            with self.subTest(source=source):
                self.assertTrue(runtime_proof._valid_frame_ancestor_source(source))
        for source in ("https://-bad.example", "example..com", "example.com:0", "https://"):
            with self.subTest(source=source):
                self.assertFalse(runtime_proof._valid_frame_ancestor_source(source))

        self.assertEqual(sandbox_targets.remote_host("Api.Ornek.COM."), "api.ornek.com")
        for host in ("a..example.com", "-bad.example.com", "example.c0m", "printer.local"):
            with self.subTest(host=host), self.assertRaises(sandbox_targets.TargetError):
                sandbox_targets.remote_host(host)

    def test_threat_routes_and_k6_versions_preserve_controls(self):
        collector = threat_model.ThreatModelCollector("demo")
        collector.add(
            "openapi.yaml",
            "openapi: 3.0.0\npaths:\n  '/pets/{id}':\n    get:\n      operationId: pets.get\n",
            "source",
        )
        collector.add(
            "pets.controller.ts",
            "import { Controller, Get } from '@nestjs/common';\n"
            "@Controller('pets')\nexport class PetsController {\n"
            "  @Get(':id')\n  public async findOne() {}\n}\n",
            "source",
        )
        routes = {(item["method"], item["path"], item["handler"], item["framework"]) for item in collector.routes}
        self.assertIn(("GET", "/pets/{id}", "pets.get", "openapi"), routes)
        self.assertIn(("GET", "/pets/:id", "findOne", "nestjs"), routes)

        for version in ("0.0.0", "1.7.1", "1.2.3-alpha.1+build-7"):
            with self.subTest(version=version):
                self.assertEqual(tool_report_k6_summary.parse_k6_machine_summary_v1(_k6_report(version))["http_requests"], 1)
        for version in ("01.2.3", "1.2", "1.2.3-", "1.2.3+"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                tool_report_k6_summary.parse_k6_machine_summary_v1(_k6_report(version))


if __name__ == "__main__":
    unittest.main()
