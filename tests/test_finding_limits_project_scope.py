import tempfile
from pathlib import Path
import unittest

from dos_resilience_redos_auditor import audit_dos_resilience_inline, audit_dos_resilience_project
from finding_limits import (
    INLINE_FINDING_LIMIT,
    PROJECT_FINDING_LIMIT,
    cap_findings,
    project_scan_scope,
)


class ProjectScanScopeTests(unittest.TestCase):
    def test_inline_cap_deferred_only_inside_project_scope(self):
        findings = [{"severity": "low", "title": "x", "i": i} for i in range(INLINE_FINDING_LIMIT + 50)]

        @project_scan_scope
        def inside() -> tuple:
            return cap_findings(findings, INLINE_FINDING_LIMIT)

        kept, total, truncated = inside()
        self.assertEqual((len(kept), total, truncated), (INLINE_FINDING_LIMIT + 50, INLINE_FINDING_LIMIT + 50, False))
        # Kapsam çıkışta sıfırlanır: aynı çağrı dışarıda yine kırpılır.
        kept, total, truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
        self.assertEqual((len(kept), total, truncated), (INLINE_FINDING_LIMIT, INLINE_FINDING_LIMIT + 50, True))

    def test_project_limit_still_applies_inside_scope(self):
        findings = [{"severity": "low", "title": "x", "i": i} for i in range(PROJECT_FINDING_LIMIT + 10)]

        @project_scan_scope
        def inside() -> tuple:
            return cap_findings(findings, PROJECT_FINDING_LIMIT)

        kept, total, truncated = inside()
        self.assertEqual((len(kept), total, truncated), (PROJECT_FINDING_LIMIT, PROJECT_FINDING_LIMIT + 10, True))

    def test_scope_resets_after_exception(self):
        @project_scan_scope
        def boom() -> None:
            raise RuntimeError("x")

        with self.assertRaises(RuntimeError):
            boom()
        findings = [{"severity": "low", "title": "x"}] * (INLINE_FINDING_LIMIT + 1)
        self.assertTrue(cap_findings(findings, INLINE_FINDING_LIMIT)[2])

    def test_project_counts_are_exact_when_one_file_exceeds_inline_limit(self):
        source = "requests.get(u)\n" * (INLINE_FINDING_LIMIT + 100)
        inline = audit_dos_resilience_inline(source)
        self.assertTrue(inline["findings_truncated"])
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            project = base / "svc"
            project.mkdir()
            (project / "client.py").write_text(source, encoding="utf-8")
            result = audit_dos_resilience_project(str(project), allowed_roots=(base,))
        self.assertEqual(result["finding_count"], inline["finding_count"])
        self.assertGreater(result["finding_count"], INLINE_FINDING_LIMIT)
        self.assertEqual(sum(group["count"] for group in result["finding_groups"]), result["finding_count"])
        self.assertFalse(result["findings_truncated"])
        self.assertEqual(len(result["findings"]), result["finding_count"])


if __name__ == "__main__":
    unittest.main()
