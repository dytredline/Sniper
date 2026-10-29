from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
READMES = {
    "en": (ROOT / "README.md", "## Capability tags"),
    "tr": (ROOT / "docs" / "README.tr.md", "## Yetenek etiketleri"),
    "ja": (ROOT / "docs" / "README.ja.md", "## 機能タグ"),
    "zh-CN": (ROOT / "docs" / "README.zh-CN.md", "## 功能标签"),
    "ko": (ROOT / "docs" / "README.ko.md", "## 기능 태그"),
}
SHARED_TECHNICAL_TAGS = (
    "SAST", "SCA", "SBOM", "IDOR", "GraphQL", "Kubernetes", "SLSA", "MCP",
    "SARIF", "OpenVEX", "GHSA", "CVSS", "SSVC", "DevSecOps",
)


def _section(document: str, heading: str) -> str:
    start = document.find(heading)
    if start < 0:
        return ""
    end = document.find("\n## ", start + len(heading))
    return document[start:] if end < 0 else document[start:end]


class LocalizedReadmeFeatureParityTests(unittest.TestCase):
    def test_every_advertised_language_has_complete_v11_feature_section(self) -> None:
        for locale, (path, heading) in READMES.items():
            with self.subTest(locale=locale):
                document = path.read_text(encoding="utf-8")
                section = _section(document, heading)
                self.assertTrue(section, f"{path}: feature-tag section is absent")
                self.assertIn("v1.1", section)
                self.assertEqual(section.count("\n- **"), 6)
                for tag in SHARED_TECHNICAL_TAGS:
                    self.assertIn(f"`{tag}`", section, f"{path}: missing shared tag {tag}")

    def test_navigation_advertises_all_five_language_documents(self) -> None:
        expected_links = ("README.md", "README.tr.md", "README.ja.md", "README.zh-CN.md", "README.ko.md")
        for locale, (path, _heading) in READMES.items():
            first_lines = "\n".join(path.read_text(encoding="utf-8").splitlines()[:6])
            with self.subTest(locale=locale):
                for filename in expected_links:
                    if filename == path.name:
                        continue
                    self.assertIn(filename, first_lines)


if __name__ == "__main__":
    unittest.main()
