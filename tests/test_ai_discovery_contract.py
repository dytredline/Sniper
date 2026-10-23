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
