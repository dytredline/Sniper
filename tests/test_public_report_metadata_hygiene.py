from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-community-source.py"
REPORT_RENDERERS = ROOT / "report_renderers.py"
GITLAB_FILE = "workhorse/internal/ai_assist/duoworkflow/mcp.go"
N8N_FILE = "packages/workflow/src/extensions/string-extensions.ts"
STIRLING_FILE = (
    "app/core/src/main/java/stirling/software/SPDF/controller/api/converters/"
    "ConvertWebsiteToPDF.java"
)
PRIVATE_MARKERS = (
    "/home/" + "converserai",
    "sniper-" + "research",
    "portfolio-" + "20261025",
    "pre-submission-" + "verification",
    "GITLAB-" + "CAND-",
    "N8N-" + "CAND-",
    "STIRLING-" + "CAND-",
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finding(file_name: str) -> dict:
    return {
        "severity": "high",
        "scope_tier": "production",
        "triage_verdict": "verified_true_positive",
        "file": file_name,
        "line": 17,
        "title": "Verified production finding",
        "description": "Bounded local test evidence",
        "reference": "CWE-20",
    }


class PublicReportMetadataHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.output = Path(cls.temporary.name) / "community"
        cls.builder = _load(BUILDER, "public_report_metadata_builder_test")
        cls.builder.build(ROOT, cls.output)
        cls.renderer = _load(
            cls.output / "report_renderers.py",
            "public_report_metadata_built_renderer_test",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_public_source_tree_excludes_private_report_research_metadata(self) -> None:
        violations: dict[str, list[str]] = {}
        for path in sorted(item for item in self.output.rglob("*") if item.is_file()):
            text = path.read_bytes().decode("utf-8", errors="ignore")
            for marker in PRIVATE_MARKERS:
                if marker in text:
                    violations.setdefault(marker, []).append(path.relative_to(self.output).as_posix())
        self.assertEqual(violations, {})

    def test_built_renderer_keeps_public_results_without_private_patch_paths(self) -> None:
        for file_name in (GITLAB_FILE, N8N_FILE):
            with self.subTest(file_name=file_name):
                rendered = self.renderer.render_ghsa_advisory_bundles(
                    {"findings": [_finding(file_name)]},
                    repository="example/project",
                )
                self.assertEqual(rendered["bundle_count"], 1)
                bundle = rendered["bundles"][0]
                self.assertNotIn("patch_file", bundle)
                self.assertNotIn("patch_sha256", bundle)
                self.assertNotIn("verification_log", bundle)

        eliminated = self.renderer.render_ghsa_advisory_bundles(
            {"findings": [_finding(STIRLING_FILE)]},
            repository="example/project",
        )
        self.assertEqual(eliminated["bundle_count"], 0)
        duplicate = eliminated["eliminated_upstream_advisories"][0]
        self.assertEqual(duplicate["upstream_cve"], "CVE-2026-71270")
        self.assertEqual(duplicate["upstream_ghsa"], "GHSA-j5rg-wh78-9f2q")
        self.assertNotIn("remediation_patch_file", duplicate)
        self.assertNotIn("remediation_patch_sha256", duplicate)
        self.assertNotIn("still_unpatched_in_head", duplicate)

    def test_report_metadata_transform_fails_closed_on_anchor_drift(self) -> None:
        source = REPORT_RENDERERS.read_text(encoding="utf-8")
        drifted = source.replace(
            "_KNOWN_UPSTREAM_ADVISORY_DUPLICATES:",
            "_DRIFTED_UPSTREAM_ADVISORY_DUPLICATES:",
            1,
        )
        self.assertNotEqual(drifted, source)
        with self.assertRaisesRegex(ValueError, r"report_renderers\.py.*anchor"):
            self.builder._apply_artifact_transform(Path("report_renderers.py"), drifted)


if __name__ == "__main__":
    unittest.main()
