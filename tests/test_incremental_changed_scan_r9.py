"""Product-connected, bounded incremental scan-cone contracts (Wave 2 / R9)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import incremental_scan_plan
import project_analyzer
import scan_scope


GIT = shutil.which("git")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _git(repo: Path, *args: str) -> None:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(repo),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "incremental-test",
        "GIT_AUTHOR_EMAIL": "incremental@example.test",
        "GIT_COMMITTER_NAME": "incremental-test",
        "GIT_COMMITTER_EMAIL": "incremental@example.test",
    }
    subprocess.run(
        [str(GIT), "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env=environment,
    )


def _repository(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    return repo


def _changed_scan(repo: Path, root: Path, *, max_files: int | None = None) -> dict:
    raw_scope: dict[str, object] = {"changed_only": True, "base_ref": "HEAD"}
    if max_files is not None:
        raw_scope["max_files"] = max_files
    return project_analyzer.analyze_project(
        str(repo),
        allowed_roots=(root,),
        scope=scan_scope.parse_scope(raw_scope),
    )


@pytest.mark.skipif(GIT is None, reason="git yok")
def test_changed_dependency_scans_caller_and_does_less_work_than_full_scan(tmp_path: Path) -> None:
    files = {
        "source.py": 'def user_value():\n    return "localhost"\n',
        "runner.py": (
            "import os\n"
            "from source import user_value\n"
            "def run():\n"
            "    return os.system('ping ' + user_value())\n"
        ),
        **{f"unrelated_{index:03d}.py": f"VALUE = {index}\n" for index in range(64)},
    }
    repo = _repository(tmp_path, files)
    (repo / "source.py").write_text(
        'from flask import request\ndef user_value():\n    return request.args["host"]\n',
        encoding="utf-8",
    )

    full = project_analyzer.analyze_project(str(repo), allowed_roots=(tmp_path,))
    incremental = _changed_scan(repo, tmp_path)

    caller_findings = [
        finding for finding in incremental["findings"]
        if finding.get("file") == "runner.py" and finding.get("taint_flow")
    ]
    assert caller_findings
    assert all(finding.get("is_new") is True for finding in caller_findings)
    assert all(finding.get("in_changed_lines") is False for finding in caller_findings)
    assert incremental["file_count"] < full["file_count"]
    assert not any(str(finding.get("file") or "").startswith("unrelated_") for finding in incremental["findings"])

    plan = incremental["changed_scan"]["incremental_plan"]
    assert plan["format"] == "sniper-incremental-scan-plan/1"
    assert plan["inventory_complete"] is True
    assert plan["fallback_full_scan"] is False
    assert plan["candidate_file_count"] == 66
    assert plan["changed_file_count"] == 1
    assert plan["cone_file_count"] == 2
    assert plan["dependent_file_count"] == 1
    assert plan["skipped_unchanged_file_count"] == 64
    assert plan["scanned_file_count"] == incremental["file_count"]
    assert plan["scanned_byte_count"] == incremental["bytes_scanned"]
    assert plan["cone_reduction_ratio"] > 0.9
    assert "2 dosyalık etki konisi incelendi" in incremental["warnings"][0]
    for key in ("content_sha256", "config_sha256", "tool_sha256", "invalidation_sha256"):
        assert SHA256_RE.fullmatch(plan[key])
    public_plan = json.dumps(plan, sort_keys=True)
    assert "runner.py" not in public_plan
    assert "request.args" not in public_plan


@pytest.mark.skipif(GIT is None, reason="git yok")
def test_changed_csharp_policy_keeps_dependent_r5_controller_in_cone(tmp_path: Path) -> None:
    repo = _repository(
        tmp_path,
        {
            "SecurityPolicy.cs": (
                "public class SecurityPolicy {\n"
                "  public static bool Check() { return true; }\n"
                "}\n"
            ),
            "DocumentsController.cs": (
                "using Microsoft.AspNetCore.Authorization;\n"
                "[ApiController]\n"
                "[Route(\"api/documents\")]\n"
                "[Authorize]\n"
                "public class DocumentsController : ControllerBase {\n"
                "  [HttpGet(\"{id}\")]\n"
                "  public Document Get(Guid id) {\n"
                "    if (!SecurityPolicy.Check()) throw new Exception();\n"
                "    return db.Documents.Find(id);\n"
                "  }\n"
                "}\n"
            ),
            "Unrelated.cs": "public class Unrelated { public int Value() { return 1; } }\n",
        },
    )
    (repo / "SecurityPolicy.cs").write_text(
        "public class SecurityPolicy {\n"
        "  public static bool Check() { return false; }\n"
        "}\n",
        encoding="utf-8",
    )

    full = project_analyzer.analyze_project(str(repo), allowed_roots=(tmp_path,))
    incremental = _changed_scan(repo, tmp_path)

    assert full["route_inventory"]["summary"]["frameworks"] == {"aspnet": 1}
    assert incremental["route_inventory"]["summary"]["frameworks"] == {"aspnet": 1}
    assert incremental["changed_scan"]["incremental_plan"]["cone_file_count"] == 2
    assert incremental["changed_scan"]["incremental_plan"]["dependent_file_count"] == 1
    assert incremental["file_count"] == 2
    controller_findings = [
        finding for finding in incremental["findings"]
        if finding.get("file") == "DocumentsController.cs" and finding.get("category") == "authz"
    ]
    assert controller_findings
    assert all(finding["is_new"] is False for finding in controller_findings)
    assert all(finding["in_changed_lines"] is False for finding in controller_findings)


@pytest.mark.skipif(GIT is None, reason="git yok")
def test_changed_java_policy_keeps_dependent_r5_controller_in_cone(tmp_path: Path) -> None:
    repo = _repository(
        tmp_path,
        {
            "SecurityPolicy.java": (
                "public final class SecurityPolicy {\n"
                "  public static boolean check() { return true; }\n"
                "}\n"
            ),
            "DocumentsController.java": (
                "@RestController\n"
                "@RequestMapping(\"/api/documents\")\n"
                "@PreAuthorize(\"isAuthenticated()\")\n"
                "public class DocumentsController {\n"
                "  @GetMapping(\"/{id}\")\n"
                "  public Document get(Long id) {\n"
                "    if (!SecurityPolicy.check()) throw new SecurityException();\n"
                "    return documents.findById(id).orElseThrow();\n"
                "  }\n"
                "}\n"
            ),
            "Unrelated.java": "public class Unrelated { public int value() { return 1; } }\n",
        },
    )
    (repo / "SecurityPolicy.java").write_text(
        "public final class SecurityPolicy {\n"
        "  public static boolean check() { return false; }\n"
        "}\n",
        encoding="utf-8",
    )

    incremental = _changed_scan(repo, tmp_path)

    assert incremental["route_inventory"]["summary"]["frameworks"] == {"spring": 1}
    assert incremental["changed_scan"]["incremental_plan"]["cone_file_count"] == 2
    assert incremental["changed_scan"]["incremental_plan"]["dependent_file_count"] == 1
    assert incremental["file_count"] == 2
    controller_findings = [
        finding for finding in incremental["findings"]
        if finding.get("file") == "DocumentsController.java" and finding.get("category") == "authz"
    ]
    assert controller_findings
    assert all(finding["is_new"] is False for finding in controller_findings)
    assert all(finding["in_changed_lines"] is False for finding in controller_findings)


@pytest.mark.skipif(GIT is None, reason="git yok")
def test_incremental_invalidation_is_deterministic_and_separates_content_config_and_tool(tmp_path: Path) -> None:
    repo = _repository(
        tmp_path,
        {
            "lib.py": "def value():\n    return 1\n",
            "caller.py": "from lib import value\nRESULT = value()\n",
            "other.py": "OTHER = 1\n",
        },
    )
    (repo / "lib.py").write_text("def value():\n    return 2\n", encoding="utf-8")

    first = _changed_scan(repo, tmp_path)["changed_scan"]["incremental_plan"]
    repeated = _changed_scan(repo, tmp_path)["changed_scan"]["incremental_plan"]
    configured = _changed_scan(repo, tmp_path, max_files=500)["changed_scan"]["incremental_plan"]

    assert first == repeated
    assert configured["content_sha256"] == first["content_sha256"]
    assert configured["tool_sha256"] == first["tool_sha256"]
    assert configured["config_sha256"] != first["config_sha256"]
    assert configured["invalidation_sha256"] != first["invalidation_sha256"]

    (repo / "other.py").write_text("OTHER = 2\n", encoding="utf-8")
    content_changed = _changed_scan(repo, tmp_path)["changed_scan"]["incremental_plan"]
    assert content_changed["content_sha256"] != first["content_sha256"]
    assert content_changed["config_sha256"] == first["config_sha256"]
    assert content_changed["tool_sha256"] == first["tool_sha256"]
    assert content_changed["invalidation_sha256"] != first["invalidation_sha256"]


@pytest.mark.skipif(GIT is None, reason="git yok")
def test_incremental_cone_is_cycle_safe_and_does_not_follow_symlinked_source(tmp_path: Path) -> None:
    repo = _repository(
        tmp_path,
        {
            "a.py": "import b\ndef a():\n    return b.b()\n",
            "b.py": "import a\ndef b():\n    return 1\n",
            "main.py": "import a\nRESULT = a.a()\n",
            **{f"idle_{index}.py": f"IDLE = {index}\n" for index in range(12)},
        },
    )
    outside = tmp_path / "outside.py"
    outside.write_text("import a\nLEAK = 'outside'\n", encoding="utf-8")
    (repo / "linked.py").symlink_to(outside)
    (repo / "b.py").write_text("import a\ndef b():\n    return 2\n", encoding="utf-8")

    result = _changed_scan(repo, tmp_path)
    plan = result["changed_scan"]["incremental_plan"]

    assert plan["inventory_complete"] is True
    assert plan["fallback_full_scan"] is False
    assert plan["candidate_file_count"] == 15
    assert plan["cone_file_count"] == 3
    assert plan["dependent_file_count"] == 2
    assert plan["scanned_file_count"] == 3
    assert result["file_count"] == 3


@pytest.mark.skipif(GIT is None, reason="git yok")
def test_inventory_cap_fails_safe_to_full_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repository(
        tmp_path,
        {
            "lib.py": "def value():\n    return 1\n",
            "caller.py": "from lib import value\nRESULT = value()\n",
            "independent.py": "INDEPENDENT = True\n",
        },
    )
    (repo / "lib.py").write_text("def value():\n    return 2\n", encoding="utf-8")
    monkeypatch.setattr(incremental_scan_plan, "MAX_CANDIDATE_FILES", 1)

    result = _changed_scan(repo, tmp_path)
    plan = result["changed_scan"]["incremental_plan"]

    assert plan["inventory_complete"] is False
    assert plan["fallback_full_scan"] is True
    assert plan["fallback_reason"] == "inventory-limit"
    assert plan["scanned_file_count"] == 3
    assert result["file_count"] == 3


def test_dependency_depth_cap_fails_safe_instead_of_returning_partial_cone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(incremental_scan_plan, "MAX_DEPENDENCY_DEPTH", 1)
    plan = incremental_scan_plan.build(
        {
            "leaf.py": "def leaf():\n    return 1\n",
            "middle.py": "from leaf import leaf\ndef middle():\n    return leaf()\n",
            "root.py": "from middle import middle\nRESULT = middle()\n",
        },
        {"leaf.py"},
        config={"scope": "test"},
        inventory_complete=True,
    )

    assert plan.selected_files is None
    assert plan.public["inventory_complete"] is False
    assert plan.public["fallback_full_scan"] is True
    assert plan.public["fallback_reason"] == "dependency-depth"
