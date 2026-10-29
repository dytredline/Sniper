"""Paket lockfile inventory and CycloneDX coverage (P1.1b)."""

from __future__ import annotations

from pathlib import Path
import tempfile

from dependency_security import generate_cyclonedx_sbom
from project_analyzer import analyze_project


PAKET_LOCK = """
NUGET
  remote: https://api.nuget.org/v3/index.json
    Newtonsoft.Json (13.0.3)
      System.Runtime (>= 4.3)
    Serilog (3.1.2-dev-02000)
      System.Diagnostics.DiagnosticSource (>= 7.0)

GROUP Test
NUGET
  remote: https://api.nuget.org/v3/index.json
    NUnit (4.1.0)
    Invalid.Constraint (>= 2.0)

GITHUB
  remote: example/repository
    fixture.fs (abc123)
"""


def test_paket_lock_resolved_nuget_packages_are_exported_to_sbom() -> None:
    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        project = base / "project"
        project.mkdir()
        (project / "paket.lock").write_text(PAKET_LOCK, encoding="utf-8")

        sbom = generate_cyclonedx_sbom(str(project), allowed_roots=(base,))

    components = {item["name"]: item for item in sbom["components"]}
    assert set(components) == {"Newtonsoft.Json", "Serilog", "NUnit"}
    assert components["Newtonsoft.Json"]["purl"] == "pkg:nuget/Newtonsoft.Json@13.0.3"
    assert components["Serilog"]["version"] == "3.1.2-dev-02000"
    assert components["NUnit"]["properties"] == [
        {"name": "sniper:manifest", "value": "paket.lock"}
    ]
    assert "System.Runtime" not in components
    assert "Invalid.Constraint" not in components
    assert "fixture.fs" not in components


def test_nested_paket_lock_is_discovered_and_manifest_path_is_preserved() -> None:
    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        project = base / "project"
        nested = project / "services/api"
        nested.mkdir(parents=True)
        (nested / "paket.lock").write_text(
            "NUGET\n  remote: https://api.nuget.org/v3/index.json\n    Polly (8.4.2)\n",
            encoding="utf-8",
        )

        sbom = generate_cyclonedx_sbom(str(project), allowed_roots=(base,))

    assert len(sbom["components"]) == 1
    assert sbom["components"][0]["purl"] == "pkg:nuget/Polly@8.4.2"
    assert sbom["components"][0]["properties"] == [
        {"name": "sniper:manifest", "value": "services/api/paket.lock"}
    ]


def test_project_analyzer_accepts_paket_lock_as_manifest_only_project() -> None:
    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        project = base / "project"
        project.mkdir()
        (project / "paket.lock").write_text(
            "NUGET\n  remote: https://api.nuget.org/v3/index.json\n    Dapper (2.1.35)\n",
            encoding="utf-8",
        )

        report = analyze_project(str(project), allowed_roots=(base,))

    assert report["file_count"] == 1
    assert report["manifests"] == ["paket.lock"]

