"""Work Package M28: Semgrep Trusted JS/TS & Python Rulepack Verification Suite."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import semgrep_active
from semgrep_active import _extract_rulepack_coverage_metadata, run_local_semgrep
from semgrep_rulepack_inventory import summarize_trusted_semgrep_rulepack
from semgrep_tls_verify_filter import _is_rule, filter_direct_requests_tls_findings


DEFAULT_SEMGREP_BINARY = Path(
    "/home/community-user/.local/state/sniper-tool-runtimes/semgrep-1.180.0/bin/semgrep"
)

TRUSTED_MULTILANG_RULEPACK_YAML = """rules:
  - id: sniper.python.eval-call
    languages: [python]
    severity: ERROR
    message: Dynamic evaluation can execute untrusted code.
    pattern: eval(...)
  - id: sniper.python.pickle.loads-call
    languages: [python]
    severity: ERROR
    message: Deserializing untrusted data with pickle.loads is dangerous.
    pattern: pickle.loads(...)
  - id: sniper.python.pickle.load-call
    languages: [python]
    severity: ERROR
    message: Deserializing untrusted data with pickle.load is dangerous.
    pattern: pickle.load(...)
  - id: sniper.python.os.system-call
    languages: [python]
    severity: ERROR
    message: Command execution via os.system can run arbitrary shell commands.
    pattern: os.system(...)
  - id: sniper.python.subprocess-run-shell-true
    languages: [python]
    severity: WARNING
    message: Subprocess with shell=True may execute untrusted command lines.
    pattern: subprocess.run(..., shell = True, ...)
  - id: sniper.python.subprocess-popen-shell-true
    languages: [python]
    severity: WARNING
    message: Subprocess with shell=True may execute untrusted command lines.
    pattern: subprocess.Popen(..., shell = True, ...)
  - id: sniper.python.subprocess-call-shell-true
    languages: [python]
    severity: WARNING
    message: Subprocess with shell=True may execute untrusted command lines.
    pattern: subprocess.call(..., shell = True, ...)
  - id: sniper.python.yaml-load-unsafe-loader
    languages: [python]
    severity: ERROR
    message: Deserializing YAML with unsafe Loader can execute arbitrary code.
    pattern: yaml.load(..., Loader = yaml.Loader, ...)
  - id: sniper.python.yaml-load-unsafe-universalloader
    languages: [python]
    severity: ERROR
    message: Deserializing YAML with unsafe Loader can execute arbitrary code.
    pattern: yaml.load(..., Loader = yaml.UnsafeLoader, ...)
  - id: sniper.python.requests-get-verify-false
    languages: [python]
    severity: WARNING
    message: requests.get with verify=False disables TLS certificate validation.
    options:
      constant_propagation: false
      symbolic_propagation: false
    patterns:
      - pattern: requests.get(..., verify=$TLS_VERIFY, ...)
      - metavariable-regex:
          metavariable: $TLS_VERIFY
          regex: ^False$
      - pattern-regex: \\brequests\\s*\\.\\s*get\\s*\\(
      - pattern-inside: |
          import requests
          ...
      - pattern-not-inside: |
          requests = $VALUE
          ...
      - pattern-not-inside: |
          def $FUNC(requests, ...):
            ...
  - id: sniper.javascript-typescript.eval-call
    languages: [javascript, typescript]
    severity: ERROR
    message: "Direct JavaScript eval can execute dynamic code; review its input and trust boundary."
    pattern: eval(...)
"""


def _resolve_semgrep_binary() -> Path | None:
    env_bin = os.environ.get("SNIPER_TEST_SEMGREP_BINARY") or os.environ.get("SNIPER_SEMGREP_BINARY")
    candidates = [Path(env_bin)] if env_bin else []
    candidates.append(DEFAULT_SEMGREP_BINARY)
    for candidate in candidates:
        if (
            candidate.is_absolute()
            and candidate.is_file()
            and not candidate.is_symlink()
            and os.access(candidate, os.X_OK)
        ):
            return candidate
    return None


class SemgrepJsTsRulepackM28Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_m28_semgrep_")
        self.base = Path(self._tmpdir.name).resolve()
        self.rulepack_path = Path(__file__).parent / "fixtures" / "trusted-multilang-rules.yaml"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_multilang_rulepack_inventory_and_extension_coverage_mapping(self) -> None:
        expected_sha = hashlib.sha256(TRUSTED_MULTILANG_RULEPACK_YAML.encode("utf-8")).hexdigest()
        summary = summarize_trusted_semgrep_rulepack(
            self.rulepack_path,
            target_extensions=[".py", ".js", ".ts", ".tsx", ".rs", ".go"],
        )
        self.assertEqual(summary["format"], "semgrep-rulepack-inventory-v1")
        self.assertEqual(summary["rule_count"], 11)
        self.assertEqual(summary["languages"], ["javascript", "python", "typescript"])
        self.assertEqual(summary["rulepack_sha256"], expected_sha)
        self.assertEqual(summary["scope_notice"], "bounded_trusted_rulepack_only")
        self.assertEqual(summary["covered_extensions"], [".js", ".py", ".ts", ".tsx"])
        self.assertEqual(summary["uncovered_extensions"], [".go", ".rs"])

        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn("/home/", serialized)
        self.assertNotIn(str(self.rulepack_path), serialized)

        active_meta = _extract_rulepack_coverage_metadata(self.rulepack_path)
        self.assertEqual(active_meta["profile_id"], "local-trusted-rules-v1")
        self.assertEqual(active_meta["rule_count"], 11)
        self.assertEqual(active_meta["languages"], ["javascript", "python", "typescript"])
        self.assertEqual(active_meta["rulepack_sha256"], expected_sha)
        self.assertFalse(active_meta["remote_rules_fetched"])
        self.assertEqual(
            active_meta["categories"],
            ["code-execution", "command-injection", "deserialization"],
        )

    def test_tls_verify_filter_and_rule_id_classification_across_python_and_js_ts(self) -> None:
        self.assertTrue(_is_rule("sniper.python.requests-get-verify-false"))
        self.assertTrue(_is_rule("rules.sniper.python.requests-get-verify-false"))
        self.assertFalse(_is_rule("sniper.javascript-typescript.eval-call"))
        self.assertFalse(_is_rule("sniper.python.eval-call"))
        self.assertFalse(_is_rule(None))

        src_dir = self.base / "mixed_src"
        src_dir.mkdir()
        (src_dir / "direct_tls.py").write_text(
            "import requests\n"
            "resp = requests.get('https://example.invalid', verify=False)\n",
            encoding="utf-8",
        )
        (src_dir / "shadowed_tls.py").write_text(
            "import requests\n"
            "def call(requests):\n"
            "    return requests.get('https://example.invalid', verify=False)\n",
            encoding="utf-8",
        )
        (src_dir / "rebound_tls.py").write_text(
            "import requests\n"
            "requests.get = lambda *a, **kw: None\n"
            "resp = requests.get('https://example.invalid', verify=False)\n",
            encoding="utf-8",
        )
        (src_dir / "widget.js").write_text("const out = eval(userControlled);\n", encoding="utf-8")
        (src_dir / "widget.ts").write_text("const out: unknown = eval(userControlled);\n", encoding="utf-8")

        raw_findings = [
            {
                "check_id": "rules.sniper.python.requests-get-verify-false",
                "path": "direct_tls.py",
                "start": {"line": 2, "col": 8},
                "extra": {"severity": "WARNING", "message": "TLS disabled"},
            },
            {
                "check_id": "sniper.python.requests-get-verify-false",
                "path": "shadowed_tls.py",
                "start": {"line": 3, "col": 12},
                "extra": {"severity": "WARNING", "message": "TLS disabled"},
            },
            {
                "check_id": "sniper.python.requests-get-verify-false",
                "path": "rebound_tls.py",
                "start": {"line": 3, "col": 8},
                "extra": {"severity": "WARNING", "message": "TLS disabled"},
            },
            {
                "check_id": "rules.sniper.javascript-typescript.eval-call",
                "path": "widget.js",
                "start": {"line": 1, "col": 13},
                "extra": {"severity": "ERROR", "message": "JS eval"},
            },
            {
                "check_id": "rules.sniper.javascript-typescript.eval-call",
                "path": "widget.ts",
                "start": {"line": 1, "col": 22},
                "extra": {"severity": "ERROR", "message": "TS eval"},
            },
            {
                "check_id": "rules.sniper.python.eval-call",
                "path": "direct_tls.py",
                "start": {"line": 1, "col": 1},
                "extra": {"severity": "ERROR", "message": "Python eval"},
            },
        ]

        with patch("semgrep_tls_verify_filter.ast.parse", wraps=ast.parse) as spy_parse:
            filtered = filter_direct_requests_tls_findings(raw_findings, src_dir)
            self.assertEqual(spy_parse.call_count, 3)

        kept_paths_and_rules = [(f["path"], f["check_id"]) for f in filtered]
        self.assertEqual(
            kept_paths_and_rules,
            [
                ("direct_tls.py", "rules.sniper.python.requests-get-verify-false"),
                ("widget.js", "rules.sniper.javascript-typescript.eval-call"),
                ("widget.ts", "rules.sniper.javascript-typescript.eval-call"),
                ("direct_tls.py", "rules.sniper.python.eval-call"),
            ],
        )

        # Verify a non-.py file claiming the Python TLS rule ID fails closed
        with self.assertRaises(ValueError):
            filter_direct_requests_tls_findings(
                [
                    {
                        "check_id": "sniper.python.requests-get-verify-false",
                        "path": "widget.js",
                        "start": {"line": 1, "col": 1},
                    }
                ],
                src_dir,
            )

    def test_real_local_semgrep_binary_and_multilang_rulepack_offline_execution(self) -> None:
        semgrep_bin = _resolve_semgrep_binary()
        if semgrep_bin is None:
            self.skipTest("Trusted local Semgrep binary is not available on this host")

        target_dir = self.base / "offline_project"
        target_dir.mkdir()
        (target_dir / "app.js").write_text(
            "const badJs = eval(untrustedInput);\n"
            "const safeJs = JSON.parse(untrustedInput);\n"
            "const helper = { eval(v) { return v; } };\n"
            "const safeMemberJs = helper.eval(untrustedInput);\n",
            encoding="utf-8",
        )
        (target_dir / "app.ts").write_text(
            "const badTs: unknown = eval(untrustedInput);\n"
            "const safeTs: unknown = JSON.parse(untrustedInput);\n"
            "const helperTs = { eval(v: string): string { return v; } };\n"
            "const safeMemberTs: string = helperTs.eval(untrustedInput);\n",
            encoding="utf-8",
        )
        (target_dir / "direct_tls.py").write_text(
            "import requests\n"
            "res = requests.get('https://example.invalid', timeout=1, verify=False)\n"
            "safe = requests.get('https://example.invalid', timeout=1, verify=True)\n",
            encoding="utf-8",
        )
        (target_dir / "shadow_tls.py").write_text(
            "import requests\n"
            "def f(x, requests):\n"
            "    return requests.get('https://example.invalid', verify=False)\n",
            encoding="utf-8",
        )

        report_1 = self.base / "report_1.json"
        report_2 = self.base / "report_2.json"
        semgrep_home = self.base / ".semgrep_home"
        semgrep_cache = self.base / ".semgrep_cache"
        semgrep_home.mkdir()
        semgrep_cache.mkdir()

        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"
        env["HOME"] = str(semgrep_home)
        env["XDG_CACHE_HOME"] = str(semgrep_cache)

        for report_out in (report_1, report_2):
            cmd = [
                str(semgrep_bin),
                str(target_dir),
                "--config",
                str(self.rulepack_path),
                "--json",
                "--quiet",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--output",
                str(report_out),
            ]
            proc = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(report_out.is_file())

        doc_1 = json.loads(report_1.read_text(encoding="utf-8"))
        doc_2 = json.loads(report_2.read_text(encoding="utf-8"))
        self.assertEqual(doc_1.get("errors"), [])
        self.assertEqual(doc_2.get("errors"), [])

        filtered_1 = filter_direct_requests_tls_findings(doc_1["results"], target_dir)
        filtered_2 = filter_direct_requests_tls_findings(doc_2["results"], target_dir)
        key_1 = sorted((Path(r["path"]).name, r["check_id"], r["start"]["line"]) for r in filtered_1)
        key_2 = sorted((Path(r["path"]).name, r["check_id"], r["start"]["line"]) for r in filtered_2)
        self.assertEqual(key_1, key_2)
        self.assertEqual(len(key_1), 3)
        self.assertTrue(any(f == "app.js" and cid.endswith("sniper.javascript-typescript.eval-call") for f, cid, _ in key_1))
        self.assertTrue(any(f == "app.ts" and cid.endswith("sniper.javascript-typescript.eval-call") for f, cid, _ in key_1))
        self.assertTrue(any(f == "direct_tls.py" and cid.endswith("sniper.python.requests-get-verify-false") for f, cid, _ in key_1))
        self.assertFalse(any(f == "shadow_tls.py" for f, _, _ in key_1))

        # Verify run_local_semgrep integration with the multi-language fixture.
        # Üretim yolu yalnız SHA-256 sabitli ikili çalıştırır: sabitli Opengrep
        # (Semgrep uyumlu motor) aynı kural paketiyle kullanılır.
        from tool_pins import PINS, pin_status
        opengrep_bin = str(PINS["opengrep"].default_binary)
        if pin_status("opengrep", opengrep_bin)["state"] != "pinned":
            self.skipTest("Sabitli Opengrep kurulu değil")
        data_dir = self.base / "sniper_data"
        with patch.dict(
            os.environ,
            {
                "SNIPER_OPENGREP_BINARY": opengrep_bin,
                "SNIPER_OPENGREP_RULES": str(self.rulepack_path),
                "SNIPER_DATA_DIR": str(data_dir),
            },
            clear=False,
        ):
            summary = run_local_semgrep(str(target_dir))
            self.assertEqual(summary["profile"], "local-trusted-rules-v1")
            self.assertGreaterEqual(summary["result_count"], 3)
            self.assertEqual(len(summary["report_sha256"]), 64)
            coverage = summary["rulepack_coverage"]
            self.assertEqual(coverage["languages"], ["javascript", "python", "typescript"])
            self.assertEqual(coverage["rule_count"], 11)
            self.assertFalse(coverage["remote_rules_fetched"])
            self.assertEqual(coverage["staged_file_count"], 4)
            self.assertNotIn("/home/", json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
