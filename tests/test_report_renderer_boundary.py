from __future__ import annotations

import builtins
import hashlib
import importlib.util
import json
from pathlib import Path
from unittest import mock

import cli_reports
import report_renderers


class _Diff:
    def compare_scans(self, previous_scan_id: str, current_scan_id: str, *, include_details: bool) -> dict:
        assert (previous_scan_id, current_scan_id, include_details) == ("old", "new", True)
        return {
            "summary": {
                "scan_1_id": "old",
                "scan_2_id": "new",
                "scan_1_score": 70,
                "scan_2_score": 80,
                "score_delta": 10,
                "new_count": 1,
                "resolved_count": 0,
                "persistent_count": 0,
            },
            "new_findings": [{
                "id": "csv-formula",
                "severity": "high",
                "title": "=1+1",
                "description": "boundary",
            }],
            "resolved_findings": [],
            "persistent_findings": [],
        }


class _Store:
    def get_scan(self, scan_id: str) -> dict:
        return {
            "id": scan_id,
            "target_url": "https://boundary.invalid/",
            "target_hostname": "boundary.invalid",
            "grade": "B",
        }


def _block_server_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "server":
        raise AssertionError("CLI report rendering must not import the HTTP server")
    return _block_server_import.original(name, globals, locals, fromlist, level)


_block_server_import.original = builtins.__import__


def test_cli_html_and_csv_render_without_importing_server(tmp_path: Path) -> None:
    """Report-only CLI paths must remain usable when the HTTP/server stack is unavailable."""
    html_path = tmp_path / "diff.html"
    csv_path = tmp_path / "diff.csv"
    with (
        mock.patch("scan_diff.create_scan_diff", return_value=_Diff()),
        mock.patch.object(cli_reports, "_store", return_value=_Store()),
        mock.patch.object(builtins, "__import__", side_effect=_block_server_import),
    ):
        cli_reports.compare_scans("old", "new", output=html_path, view="html")
        cli_reports.compare_scans("old", "new", output=csv_path, view="csv")

    assert html_path.read_bytes().startswith(b"<!doctype html>")
    csv_bytes = csv_path.read_bytes()
    assert b"change,id,severity,title" in csv_bytes
    assert b"'=1+1" in csv_bytes


def test_report_renderer_module_runtime_boundary_and_server_reexports() -> None:
    direct_imports: list[str] = []
    original_import = builtins.__import__

    def record_import(name, globals=None, locals=None, fromlist=(), level=0):
        if globals and globals.get("__name__") == "isolated_report_renderers":
            direct_imports.append(name)
        return original_import(name, globals, locals, fromlist, level)

    module_path = Path(report_renderers.__file__)
    spec = importlib.util.spec_from_file_location("isolated_report_renderers", module_path)
    assert spec is not None and spec.loader is not None
    isolated = importlib.util.module_from_spec(spec)
    with mock.patch.object(builtins, "__import__", side_effect=record_import):
        spec.loader.exec_module(isolated)
    assert set(direct_imports) == {"__future__", "csv", "html", "io"}

    import server

    exported = (
        "render_sarif", "_combined_engagement_findings", "render_engagement_csv",
        "DIFF_CSV_FIELDS", "render_diff_csv", "_csv_safe", "render_engagement_sarif",
        "render_report", "REPORT_STYLE", "render_diff_report", "render_engagement_report",
        "test_status_label", "finding_status_label",
    )
    for name in exported:
        assert getattr(server, name) is getattr(report_renderers, name)
    assert server._localized_report.__module__ == "server"


def test_rendered_report_bytes_match_r58_contract() -> None:
    scan = {
        "id": "scn_boundary", "status": "completed",
        "target_url": "https://example.invalid/", "target_hostname": "example.invalid",
        "score": 73, "grade": "C", "finished_at": "2026-10-22T10:11:12Z",
        "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "findings": [{
            "id": "f_1", "severity": "high", "category": "headers", "title": "<başlık>",
            "description": "Açıklama & ayrıntı", "evidence": "=SUM(1,1)",
            "recommendation": "Düzelt", "reference": "OWASP", "owasp": "A05",
            "cwe": "CWE-693", "confidence": "high", "detection": "passive",
        }],
    }
    diff = {
        "summary": {
            "scan_1_id": "old", "scan_2_id": "new", "scan_1_score": 70,
            "scan_2_score": 73, "score_delta": 3, "new_count": 1,
            "resolved_count": 0, "persistent_count": 0,
            "new_by_severity": {"high": 1}, "resolved_by_severity": {},
            "persistent_by_severity": {},
        },
        "new_findings": [scan["findings"][0]], "resolved_findings": [],
        "persistent_findings": [],
    }
    engagement = {
        "id": "eng_boundary", "name": "Sınır", "target_url": "https://example.invalid/",
        "status": "active", "authorization_ref": "AUTH-1", "test_window": "2026-10-22",
        "scope_notes": "/api", "out_of_scope": "/admin", "coverage": {"percent": 50},
        "remediation": {"active": 1, "overdue": 0, "retest": 0, "resolved": 0},
        "findings": [{
            "id": "m_1", "severity": "high", "status": "open", "title": "=FORMULA",
            "description": "Manuel", "affected_asset": "/api", "owasp_category": "A01",
            "cwe_id": "CWE-639", "recommendation": "Kontrol ekle",
        }],
        "latest_scan": scan, "categories": [], "tests": [], "special_approvals": {},
    }
    scan_1 = {**scan, "id": "old", "score": 70}
    scan_2 = {**scan, "id": "new", "score": 73}
    outputs = {
        "scan_html": report_renderers.render_report(scan).encode(),
        "scan_sarif": json.dumps(
            report_renderers.render_sarif(scan), ensure_ascii=False, indent=2,
        ).encode(),
        "diff_html": report_renderers.render_diff_report(diff, scan_1, scan_2).encode(),
        "diff_csv": report_renderers.render_diff_csv(diff).encode(),
        "eng_html": report_renderers.render_engagement_report(engagement).encode(),
        "eng_csv": report_renderers.render_engagement_csv(engagement).encode(),
        "eng_sarif": json.dumps(
            report_renderers.render_engagement_sarif(engagement), ensure_ascii=False, indent=2,
        ).encode(),
    }
    expected = {
        "scan_html": "f86502fda870e78ed8bd65c18e967a0af404989827ec64715633416fdd08e314",
        "scan_sarif": "67ebd6c1d3378385bea1e5d59fd13120462b1d1aa3fecc71bb665a043f6a9843",
        "diff_html": "98bdb4be62ebc1659a2882d2c4d34e93f98cb5728bb8ecfe08150c2c355a386b",
        "diff_csv": "607658c1122cf0b45788ec957b4823e9d29bb5ac898594e8698e6fdf6408d902",
        "eng_html": "7aa73c2dcb48a70a7dccc3d2567784036e9bbb8cd3f58f1dcc84b63827c96840",
        "eng_csv": "f273755eec394d48b2426aaa74f61cd8a096ea9efe4651e93dc5c79694f40af4",
        "eng_sarif": "d0178bc2e7e9591df78ea7220992e0453719cce52c87d1f459d9d4cda46810c5",
    }
    assert {name: hashlib.sha256(value).hexdigest() for name, value in outputs.items()} == expected
