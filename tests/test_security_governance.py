from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-community-source.py"
VALIDATOR = ROOT / ".github" / "scripts" / "validate-community-release.py"
MAINTAINER_NAME = "Gökçe Baran Karakamış"
MAINTAINER_HANDLE = "@dytredline"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityGovernanceTests(unittest.TestCase):
    def test_public_collaboration_surface_is_release_gated(self) -> None:
        builder = _load(BUILDER, "collaboration_surface_builder_test")
        validator = _load(VALIDATOR, "collaboration_surface_validator_test")
        expected = {
            "CHANGELOG.md",
            "SUPPORT.md",
            "CITATION.cff",
            "COMMUNITY-TOOLS.lock.json",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/pull_request_template.md",
            ".github/dependabot.yml",
            "docs/COMMUNITY-TOOLS.md",
            "scripts/install-community-tools",
        }

        self.assertEqual(expected - set(validator.REQUIRED_FILES), set())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "community"
            builder.build(ROOT, output)
            self.assertEqual(validator.validate(output, scan_release_tree=True), [])

            for relative in sorted(expected):
                path = output / relative
                original = path.read_bytes()
                path.unlink()
                try:
                    failures = validator.validate(output, scan_release_tree=True)
                finally:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(original)
                with self.subTest(relative=relative):
                    self.assertTrue(
                        any(f"missing required file: {relative}" in failure for failure in failures),
                        failures,
                    )

    def test_named_security_maintainer_contract_is_complete(self) -> None:
        policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        maintainers = (ROOT / "SECURITY-MAINTAINERS.md").read_text(encoding="utf-8")

        for text in (policy, maintainers):
            self.assertIn(MAINTAINER_NAME, text)
            self.assertIn(MAINTAINER_HANDLE, text)
            self.assertIn("Security Maintainer", text)

        self.assertIn("2026-10-23", maintainers)
        self.assertIn("not a claim of an existing CVE or GHSA", maintainers)
        self.assertIn("3 business days", policy)
        self.assertIn("7 business days", policy)
        self.assertIn("90 days", policy)
        self.assertIn("Private Vulnerability Reporting", policy)

    def test_codeowners_assigns_security_surfaces(self) -> None:
        codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        for protected_path in (
            "/SECURITY.md",
            "/SECURITY-MAINTAINERS.md",
            "/.github/CODEOWNERS",
            "/.github/VULNERABILITY_REPORT.yml",
            "/.github/workflows/",
            "/auth.py",
            "/authz_routes.py",
            "/mcp_*.py",
            "/sandbox_*.py",
            "/tool_sandbox.py",
            "/verified_exec.py",
        ):
            self.assertRegex(codeowners, rf"(?m)^{protected_path.replace('*', r'.*')}\s+{MAINTAINER_HANDLE}$")

    def test_private_report_template_collects_actionable_safe_evidence(self) -> None:
        template = (ROOT / ".github" / "VULNERABILITY_REPORT.yml").read_text(encoding="utf-8")
        for schema_key in ("name:", "description:", "body:", "type:", "id:", "attributes:", "validations:"):
            self.assertIn(schema_key, template)
        for field in (
            "Affected version or commit",
            "Impact",
            "Weakness (CWE)",
            "Safe reproduction",
            "Suggested remediation",
            "I tested only systems I own or am explicitly authorized to assess",
            "I removed secrets, personal data, and third-party exploit traffic",
        ):
            self.assertIn(field, template)

    def test_release_validator_fails_closed_when_governance_is_removed(self) -> None:
        builder = _load(BUILDER, "security_governance_builder_test")
        validator = _load(VALIDATOR, "security_governance_validator_test")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "community"
            builder.build(ROOT, output)
            self.assertEqual(validator.validate(output, scan_release_tree=True), [])

            maintainers = output / "SECURITY-MAINTAINERS.md"
            original = maintainers.read_text(encoding="utf-8")
            maintainers.write_text(original.replace(MAINTAINER_HANDLE, "@unassigned"), encoding="utf-8")
            failures = validator.validate(output, scan_release_tree=True)
            self.assertTrue(any("SECURITY-MAINTAINERS.md" in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
