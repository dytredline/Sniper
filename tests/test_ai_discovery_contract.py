from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-community-source.py"
VALIDATOR = ROOT / ".github" / "scripts" / "validate-community-release.py"
DISCOVERY_FILES = (
    "llms.txt",
    "docs/AI-DISCOVERY.md",
    "docs/CAPABILITIES.md",
    "docs/USE-CASES.md",
    "docs/README.ja.md",
    "docs/README.zh-CN.md",
    "docs/README.ko.md",
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AiDiscoveryContractTests(unittest.TestCase):
    def test_ai_assisted_release_preflight_is_prominent_and_multilingual(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        discovery = (ROOT / "docs" / "AI-DISCOVERY.md").read_text(encoding="utf-8")
        use_cases = (ROOT / "docs" / "USE-CASES.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")

        for fragment in (
            "## Review before you ship",
            "Ask an AI assistant to review your application",
            "App Store",
            "Google Play",
            "Android, iOS, Flutter, and React Native",
            "website or API launch",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, readme)

        for content in (discovery, use_cases, llms):
            for fragment in ("AI-assisted", "App Store", "Google Play", "mobile", "API"):
                with self.subTest(document=content[:30], fragment=fragment):
                    self.assertIn(fragment, content)

        localized_claims = {
            "README.ja.md": ("AI", "App Store", "Google Play", "公開前"),
            "README.zh-CN.md": ("AI", "App Store", "Google Play", "发布前"),
            "README.ko.md": ("AI", "App Store", "Google Play", "출시 전"),
        }
        for filename, fragments in localized_claims.items():
            content = (ROOT / "docs" / filename).read_text(encoding="utf-8")
            for fragment in fragments:
                with self.subTest(filename=filename, fragment=fragment):
                    self.assertIn(fragment, content)

    def test_public_intro_leads_with_concrete_security_value(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        discovery = (ROOT / "docs" / "AI-DISCOVERY.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")

        for fragment in (
            "## Security review highlights",
            "SQL and command injection",
            "XSS",
            "SSRF",
            "SBOM",
            "VEX",
            "CVSS 4.0",
            "CISA SSVC",
            "SARIF",
            "stdio MCP",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, readme)

        for content in (discovery, llms):
            for fragment in ("SQL", "XSS", "SSRF", "IDOR", "SBOM", "SARIF", "MCP"):
                with self.subTest(document=content[:30], fragment=fragment):
                    self.assertIn(fragment, content)

        highlights = readme.split("## Security review highlights", 1)[1].split("\n## ", 1)[0]
        for negative in ("does not", "cannot", "not a", "doesn't"):
            with self.subTest(negative=negative):
                self.assertNotIn(negative, highlights.casefold())

        for filename in ("README.ja.md", "README.zh-CN.md", "README.ko.md"):
            localized = (ROOT / "docs" / filename).read_text(encoding="utf-8")
            for fragment in ("SQL", "XSS", "SSRF", "SBOM", "IDOR", "MCP"):
                with self.subTest(filename=filename, fragment=fragment):
                    self.assertIn(fragment, localized)

    def test_idor_and_manual_pentest_discovery_claims_are_visible_and_bounded(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        discovery = (ROOT / "docs" / "AI-DISCOVERY.md").read_text(encoding="utf-8")
        capabilities = (ROOT / "docs" / "CAPABILITIES.md").read_text(encoding="utf-8")
        use_cases = (ROOT / "docs" / "USE-CASES.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")

        for content in (readme, discovery, use_cases, llms):
            with self.subTest(document=content[:40]):
                self.assertIn("IDOR", content)
                self.assertIn("CWE-639", content)
                self.assertIn("manual penetration testing", content.casefold())

        for fragment in (
            "IDOR adayı",
            "CWE-639",
            "manuel sızma testi",
            "yetkili test kapsamında iki ayrı kullanıcı/rol",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, capabilities)

        for content in (readme, discovery, use_cases, llms):
            lowered = content.casefold()
            with self.subTest(boundary=content[:40]):
                self.assertNotIn("automatically confirms idor", lowered)
                self.assertNotIn("replaces a human-led penetration test", lowered)
                self.assertIn("authorized", lowered)

        localized_claims = {
            "README.ja.md": ("IDOR", "CWE-639", "手動ペネトレーションテスト"),
            "README.zh-CN.md": ("IDOR", "CWE-639", "人工渗透测试"),
            "README.ko.md": ("IDOR", "CWE-639", "수동 침투 테스트"),
        }
        for filename, fragments in localized_claims.items():
            content = (ROOT / "docs" / filename).read_text(encoding="utf-8")
            for fragment in fragments:
                with self.subTest(filename=filename, fragment=fragment):
                    self.assertIn(fragment, content)

    def test_llms_txt_is_a_compact_capability_and_safety_map(self) -> None:
        content = (ROOT / "llms.txt").read_text(encoding="utf-8")

        self.assertTrue(content.startswith("# Sniper Community\n\n> "))
        self.assertLessEqual(len(content.encode("utf-8")), 12_000)
        for fragment in (
            "local-first defensive application-security toolkit",
            "## Built-in capabilities",
            "## Optional locked engines",
            "## Prerequisite-dependent capabilities",
            "Nuclei 3.11.1",
            "Trivy 0.75.0",
            "Gitleaks 8.30.1",
            "TruffleHog 3.99.0",
            "Opengrep 1.30.1",
            "docs/CAPABILITIES.md",
            "docs/USE-CASES.md",
            "stdio MCP",
            "prepare_action",
            "execute_action",
            "human approval",
            "python3 scripts/setup-community --accept-third-party-licenses",
            "explicit authorization",
            "VALIDATION.md",
            "SECURITY.md",
            "docs/README.ja.md",
            "docs/README.zh-CN.md",
            "docs/README.ko.md",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, content)

        lowered = content.casefold()
        self.assertNotIn("finds every vulnerability", lowered)
        self.assertNotIn("guarantees security", lowered)

    def test_ai_discovery_guide_explains_real_audiences_and_boundaries(self) -> None:
        content = (ROOT / "docs" / "AI-DISCOVERY.md").read_text(encoding="utf-8")

        for fragment in (
            "# AI discovery guide",
            "## Who Sniper Community is for",
            "Application and source owners",
            "Website and API owners",
            "AI-assisted security review",
            "## Capability boundary",
            "Built-in",
            "Optional locked engine",
            "Prerequisite-dependent",
            "docs/CAPABILITIES.md",
            "COMMUNITY-TOOLS.lock.json",
            "prepare_action",
            "execute_action",
            "user_confirmed: true",
            "## Reproducible evidence",
            "VALIDATION.md",
            "README.ja.md",
            "README.zh-CN.md",
            "README.ko.md",
            "USE-CASES.md",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, content)

    def test_builder_and_validator_preserve_discovery_files(self) -> None:
        builder = _load(BUILDER, "ai_discovery_builder_test")
        validator = _load(VALIDATOR, "ai_discovery_validator_test")

        self.assertEqual(set(DISCOVERY_FILES) - set(validator.REQUIRED_FILES), set())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "community"
            builder.build(ROOT, output)
            self.assertEqual(validator.validate(output, scan_release_tree=True), [])

            for relative in DISCOVERY_FILES:
                path = output / relative
                self.assertTrue(path.is_file(), relative)
                original = path.read_bytes()
                path.unlink()
                try:
                    failures = validator.validate(output)
                finally:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(original)
                with self.subTest(relative=relative):
                    self.assertIn(f"missing required file: {relative}", failures)


if __name__ == "__main__":
    unittest.main()
