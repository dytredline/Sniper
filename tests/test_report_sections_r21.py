"""21. tur rapor bütünlüğü: alan sınıflandırması (report_sections), yönetici özeti ve proje raporunda alanlar,
bağımlılık açıklarının tek kaynaktan sayılması (kötü amaçlı paket çift sayılmaz), portföy alan kırılımı, konteyner/SBOM
kayıtlarının rapor başlığı, İngilizce çeviri ve rapor CSP'si."""
from __future__ import annotations

import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import i18n_server  # noqa: E402
import portfolio  # noqa: E402
from project_audit_diff import render_project_audit_html  # noqa: E402
from project_executive_summary import build_project_executive_summary, render_page_html, render_section_html  # noqa: E402
import report_sections as rs  # noqa: E402
from storage import Store  # noqa: E402
import ui_assets  # noqa: E402

MAL_TITLE = "Kötü amaçlı paket: evil-pkg 1.0.0 (MAL-2025-1)"


def _findings() -> list[dict]:
    return [
        {"category": "data_query", "severity": "critical", "title": "Doğrulanmış veri akışı: istek girdisi SQL sorgusuna ulaşıyor",
         "file": "app.py", "line": 10, "taint_flow": {"kind": "sql"}, "reference": "CWE-89", "evidence": "x"},
        {"category": "crypto", "severity": "medium", "title": "Zayıf kriptografik özet", "file": "util.py", "line": 3,
         "evidence": "md5"},
        {"category": "container", "severity": "high", "title": "Terraform güvenlik grubunda dünyaya açık (0.0.0.0/0) ağ erişimi",
         "file": "main.tf", "line": 5, "iac": {"id": "TF-001"}, "evidence": "sg"},
        {"category": "supply_chain", "severity": "critical", "title": MAL_TITLE, "file": "package-lock.json", "line": 0,
         "cwe": "CWE-506", "reference": "MAL-2025-1", "evidence": "evil"},
        {"category": "supply_chain", "severity": "info", "title": "Kurulumda betik çalıştıran npm bağımlılıkları",
         "file": "package-lock.json", "line": 0, "evidence": "scripts"},
        {"category": "api", "severity": "low", "title": "Belgelenmemiş (gölge) API uç noktası", "file": "routes.py",
         "line": 7, "evidence": "/x"},
        {"category": "components", "severity": "medium", "title": "Python bağımlılıkları sabitlenmemiş",
         "file": "requirements.txt", "line": 1, "evidence": "flask"},
    ]


def _dependency(package: str, version: str, vuln: str, severity: str, title: str, project: str) -> dict:
    return {"project_path": project, "source": "osv", "vulnerability_id": vuln, "package_name": package,
            "installed_version": version, "severity": severity, "fixed_version": "", "title": title, "summary": "",
            "references": []}


class SectionClassificationTests(unittest.TestCase):
    def test_section_of(self):
        f = {f["title"]: rs.section_of(f) for f in _findings()}
        self.assertEqual(f[_findings()[0]["title"]], "code")
        self.assertEqual(f["Zayıf kriptografik özet"], "code")
        self.assertEqual(f[_findings()[2]["title"]], "iac")
        self.assertEqual(f[MAL_TITLE], "dependencies")
        self.assertEqual(f["Kurulumda betik çalıştıran npm bağımlılıkları"], "supply_chain")
        self.assertEqual(f["Belgelenmemiş (gölge) API uç noktası"], "api")
        self.assertEqual(f["Python bağımlılıkları sabitlenmemiş"], "dependencies")
        self.assertEqual(rs.section_of({"category": "container_os", "title": "x"}), "container")
        self.assertEqual(rs.section_of({"category": "sbom_component", "package": {"type": "deb"}}), "container")
        self.assertEqual(rs.section_of({"category": "sbom_component", "package": {"type": "PyPI"}}), "dependencies")
        self.assertEqual(rs.section_of({"category": "license", "title": "GPL"}), "license")
        self.assertEqual(rs.section_of({"category": "supplychain", "title": "Konteyner imajı sabitlenmemiş"}), "iac")
        # takip satırı: önceden hesaplanmış alan; tam bulgusu olmayan eski satırda IaC başlığı
        self.assertEqual(rs.section_of({"section": "license", "category": "crypto"}), "license")
        self.assertEqual(rs.section_of({"category": "container", "title": "Dockerfile içinde HEALTHCHECK tanımı yok"}), "iac")

    def test_build_sections_single_source_and_malicious_dedup(self):
        project = "/p"
        deps = [
            _dependency("evil-pkg", "1.0.0", "MAL-2025-1", "critical", MAL_TITLE, project),  # proje bulgusuyla aynı
            dict(_dependency("lodash", "4.17.4", "GHSA-1", "high", "Prototype pollution", project), priority_tier="fix_first",
                 priority_score=80, status="open"),
            dict(_dependency("x", "1", "GHSA-2", "unknown", "Belirsiz", project), status="open"),
            dict(_dependency("y", "1", "GHSA-3", "low", "Düzeldi", project), status="resolved"),
        ]
        built = rs.build_sections(_findings(), deps)
        by = {s["key"]: s for s in built["sections"]}
        self.assertEqual(by["dependencies"]["active"], 4)  # 2 proje (kötü amaçlı + bileşen) + lodash + bilinmeyen
        self.assertEqual(by["dependencies"]["malicious"], 1)
        self.assertEqual(by["dependencies"]["fix_first"], 1)
        self.assertEqual(by["dependencies"]["by_severity"]["unknown"], 1)
        self.assertTrue(by["dependencies"]["top"][0]["malicious"])  # kötü amaçlı en üstte
        self.assertEqual(by["code"]["active"], 2)
        self.assertEqual(by["code"]["verified_flows"], 1)
        self.assertEqual(by["iac"]["critical_high"], 1)
        self.assertEqual(built["totals"]["active"], sum(s["active"] for s in built["sections"]))
        self.assertEqual(built["totals"]["active"], len(_findings()) + 2)
        self.assertIn("Kötü amaçlı", by["dependencies"]["action"])


class ReportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_env = os.environ.get("SNIPER_DATA_DIR")
        os.environ["SNIPER_DATA_DIR"] = self.tmp.name
        self.addCleanup(lambda: os.environ.pop("SNIPER_DATA_DIR", None) if self.old_env is None
                        else os.environ.__setitem__("SNIPER_DATA_DIR", self.old_env))
        self.store = Store(Path(self.tmp.name) / "sniper.db")
        self.project = str(Path(self.tmp.name) / "proj")
        Path(self.project).mkdir()
        result = {"project_path": self.project, "project_name": "proj", "created_at": "2026-10-21T00:00:00Z",
                  "score": 40, "grade": "D", "file_count": 4, "bytes_scanned": 100, "findings": _findings(),
                  "checks": [{"id": "x", "label": "Etiketli kontrol", "status": "review"}],
                  "api_contract": {"summary": {"specs": 1, "spec_operations": 4, "matched_operations": 3, "code_routes": 4,
                                               "shadow_routes": 1, "missing_in_code": 0, "auth_mismatch": 0}},
                  "supply_chain": {"summary": {"malicious": 1, "suspicious_install_scripts": 0, "confusion_hints": 0}}}
        audit = self.store.create_project_audit(result)
        self.audit = self.store.get_project_audit(audit["id"])
        self.store.import_dependency_findings({
            "source": "osv", "source_path": "osv-offline:npm", "source_timestamp": "2026-10-21T00:00:00Z",
            "document_hash": "a" * 64, "project_path": self.project,
            "findings": [_dependency("evil-pkg", "1.0.0", "MAL-2025-1", "critical", MAL_TITLE, self.project),
                         _dependency("lodash", "4.17.4", "GHSA-1", "high", "Prototype pollution", self.project)]})

    def test_executive_summary_sections_and_counts(self):
        summary = build_project_executive_summary(self.store, self.audit)
        by = {s["key"]: s for s in summary["sections"]}
        self.assertEqual(summary["active_findings"], len(_findings()))  # bulgu takibi (proje bulguları)
        self.assertEqual(summary["dependency_vulnerabilities"], 3)  # 2 proje + lodash (kötü amaçlı tekrar sayılmaz)
        self.assertEqual(summary["overall_active"], len(_findings()) + 1)
        self.assertEqual(by["dependencies"]["malicious"], 1)
        self.assertEqual(summary["risk_level"], "critical")
        self.assertEqual(summary["verified_flow_findings"], 1)
        self.assertEqual(summary["section_context"]["api"]["shadow_routes"], 1)
        section = render_section_html(summary)
        self.assertIn("Alanlara göre durum", section)
        self.assertIn("KÖTÜ AMAÇLI", section)
        self.assertNotIn(" style=", section)
        page = render_page_html(summary)
        self.assertNotIn("unsafe-inline", ui_assets.report_csp(page))
        # İngilizce: yeni etiketler çevrilir
        en = i18n_server.localize_html(page, "en")
        for word in ("Status by area", "Dependencies", "Infrastructure (IaC)", "Recommended action", "MALICIOUS"):
            self.assertIn(word, en)
        for leftover in ("Alanlara göre durum", "Önerilen eylem", "Kötü amaçlı paketleri derhal"):
            self.assertNotIn(leftover, en)

    def test_project_report_groups_sections_and_lists_dependencies(self):
        summary = build_project_executive_summary(self.store, self.audit)
        deps = self.store.dependency_findings_for_project(self.project)
        page = render_project_audit_html(self.audit, render_section_html(summary), deps)
        for key in ("code", "dependencies", "iac", "api", "supply_chain"):
            self.assertIn(f"id='section-{key}'", page)
        dep_section = page[page.index("id='section-dependencies'"):]
        self.assertLess(dep_section.index(MAL_TITLE), dep_section.index("Python bağımlılıkları sabitlenmemiş"))
        self.assertIn("Bağımlılık açıkları — çevrimdışı tarama (2)", page)
        table = dep_section[dep_section.index("<table>"):]
        self.assertLess(table.index("evil-pkg"), table.index("lodash"))  # kötü amaçlı en üstte
        self.assertIn("Etiketli kontrol", page)  # 'label' alanlı kontroller (konteyner/SBOM) adıyla görünür
        self.assertIn("Bağımlılık açığı:", page)
        self.assertNotIn(" style=", page)
        self.assertNotIn("unsafe-inline", ui_assets.report_csp(page))
        en = i18n_server.localize_html(page, "en")
        self.assertIn("Dependency vulnerabilities — offline scan (2)", en)

    def test_portfolio_by_section_matches_summary(self):
        with sqlite3.connect(Path(self.tmp.name) / "sniper.db") as db:
            db.row_factory = sqlite3.Row
            overview = portfolio.overview(db, portfolio.load_policy()[0])
        entry = next(p for p in overview["projects"] if p["project_path"] == self.project)
        summary = build_project_executive_summary(self.store, self.audit)
        expected = {s["key"]: s["active"] for s in summary["sections"]}
        self.assertEqual(entry["by_section"], expected)
        self.assertEqual(overview["totals"]["by_section"]["dependencies"], expected["dependencies"])

    def test_container_audit_header(self):
        audit = {"id": "prj_c", "audit_kind": "container", "project_name": "img", "score": 70, "grade": "C",
                 "findings": [{"category": "container_os", "severity": "high", "title": "Açıklı işletim sistemi paketi: openssl",
                               "file": "/var/lib/dpkg/status", "line": 0}],
                 "checks": [{"id": "os_packages", "label": "İşletim sistemi paket açıkları", "status": "review"}],
                 "container": {"os": {"pretty_name": "Debian GNU/Linux 12"}, "package_count": 120}}
        page = render_project_audit_html(audit)
        self.assertIn("Debian GNU/Linux 12", page)
        self.assertIn("<strong>Paket:</strong> 120", page)
        self.assertIn("İşletim sistemi paket açıkları", page)
        self.assertIn("id='section-container'", page)
        self.assertNotIn("Taranan Dosya", page)
        self.assertTrue(re.search(r"Bu analizdeki bulgu:</strong> 1", page))


if __name__ == "__main__":
    unittest.main()
