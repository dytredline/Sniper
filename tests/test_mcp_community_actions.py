from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import mcp_community_actions
from storage import Store


class FakeStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.created: list[dict] = []
        self.audits: dict[str, dict] = {}
        self.comparisons: list[tuple[str, str, bool]] = []

    def create_project_audit(self, result: dict) -> dict:
        saved = {**result, "id": "prj_123456789abc"}
        self.created.append(result)
        self.audits[saved["id"]] = saved
        return saved

    def get_project_audit(self, audit_id: str) -> dict | None:
        return self.audits.get(audit_id)

    def compare_scans(self, before: str, after: str, *, include_details: bool = True) -> dict:
        self.comparisons.append((before, after, include_details))
        return {"scan_1_id": before, "scan_2_id": after, "new_count": 1}


class FakeQueue:
    def __init__(self) -> None:
        self.jobs = {"job_" + "1" * 24: {"id": "job_" + "1" * 24, "state": "queued"}}

    def get(self, job_id: str) -> dict | None:
        return self.jobs.get(job_id)

    def cancel(self, job_id: str) -> dict | None:
        item = self.jobs.get(job_id)
        if item is not None:
            item = {**item, "state": "cancelled", "cancel_requested": True}
            self.jobs[job_id] = item
        return item


def _adapter(tmp_path: Path, **kwargs) -> mcp_community_actions.CommunityActions:
    scan_launcher = kwargs.pop(
        "scan_launcher",
        lambda approved_plan: {"job_id": "job_" + "2" * 24, "state": "queued"},
    )
    return mcp_community_actions.CommunityActions(
        store=kwargs.pop("store", FakeStore(tmp_path / "sniper.db")),
        queue=kwargs.pop("queue", FakeQueue()),
        allowed_roots=(tmp_path,),
        requester={"id": "usr_test", "username": "tester", "role": "analyst"},
        scan_launcher=scan_launcher,
        **kwargs,
    )


def _execute(adapter: mcp_community_actions.CommunityActions, plan: dict) -> dict:
    return adapter.execute_plan(
        plan["plan_id"],
        plan_sha256=plan["plan_sha256"],
        user_confirmed=True,
    )


def test_export_rejects_destination_symlink_without_overwriting_its_target(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = Store(data_dir / "sniper.db")
    project = tmp_path / "project"
    project.mkdir()
    saved = store.create_project_audit({
        "created_at": "2026-10-23T00:00:00+00:00",
        "project_path": str(project),
        "project_name": "demo",
        "score": 100,
        "grade": "A",
        "file_count": 1,
        "bytes_scanned": 1,
        "summary": {},
        "findings": [],
    })
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    victim = tmp_path / "victim.json"
    victim.write_text("original\n", encoding="utf-8")
    destination = export_dir / f"demo_{saved['id']}_report.json"
    destination.symlink_to(victim)
    adapter = _adapter(tmp_path, store=store)
    plan = adapter.plan_action("export_saved_audit", {
        "audit_id": saved["id"],
        "format": "json",
        "target_dir": str(export_dir),
    })

    with pytest.raises(mcp_community_actions.ActionUnavailable, match="sembolik|güvenli"):
        _execute(adapter, plan)

    assert victim.read_text(encoding="utf-8") == "original\n"
    assert destination.is_symlink()


def test_capabilities_report_real_readiness_and_missing_adapters(tmp_path: Path) -> None:
    ready = _adapter(tmp_path).list_capabilities()
    by_name = {item["name"]: item for item in ready["capabilities"]}

    assert ready["format"] == "sniper-community-capabilities-v1"
    assert by_name["analyze_local_project"]["status"] == "ready"
    assert by_name["generate_sbom"]["status"] == "ready"
    assert by_name["verify_fix"]["status"] == "ready"
    assert by_name["apply_fix"]["status"] == "ready"
    assert by_name["job_status"]["status"] == "ready"
    assert by_name["cancel_job"]["requires_confirmation"] is True
    assert by_name["request_external_scan"]["execution"] == "approved_job_launch"

    unavailable = mcp_community_actions.CommunityActions(
        store=None,
        queue=None,
        allowed_roots=(tmp_path,),
    ).list_capabilities()
    missing = {item["name"]: item for item in unavailable["capabilities"]}
    assert missing["compare_saved_scans"]["status"] == "unavailable"
    assert missing["job_status"]["status"] == "unavailable"
    assert missing["request_external_scan"]["status"] == "unavailable"
    assert missing["request_external_scan"]["reason"]


def test_mcp_tool_schemas_and_call_surface_bind_full_arguments_and_reject_replay(monkeypatch, tmp_path: Path) -> None:
    names = [tool["name"] for tool in mcp_community_actions.COMMUNITY_TOOLS]
    assert names == ["list_community_capabilities", "community_job_status", "prepare_action", "execute_action"]
    assert len(names) == len(set(names))
    assert all(tool["inputSchema"]["additionalProperties"] is False for tool in mcp_community_actions.COMMUNITY_TOOLS)

    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text("answer = 42\n", encoding="utf-8")
    monkeypatch.setattr("mcp_community_actions.secrets.token_hex", lambda _size: "a" * 24)
    first = _adapter(tmp_path, clock=lambda: 1000.0)
    second = _adapter(tmp_path, clock=lambda: 1000.0)
    plan_10 = first.call("prepare_action", {
        "action": "analyze_local_project",
        "parameters": {"path": str(project), "max_files": 10, "persist": False},
    })
    plan_11 = second.call("prepare_action", {
        "action": "analyze_local_project",
        "parameters": {"path": str(project), "max_files": 11, "persist": False},
    })
    assert plan_10["plan_id"] == plan_11["plan_id"]
    assert plan_10["created_at"] == plan_11["created_at"]
    assert plan_10["plan_sha256"] != plan_11["plan_sha256"]
    assert isinstance(plan_10["consent_scope"], str) and str(project.resolve()) in plan_10["consent_scope"]
    assert plan_10["effects"] == ["read_local_source"]

    executed = first.call("execute_action", {
        "plan_id": plan_10["plan_id"],
        "plan_sha256": plan_10["plan_sha256"],
        "user_confirmed": True,
    })
    assert executed["status"] == "completed"
    assert str(project.resolve()) not in json.dumps(executed, ensure_ascii=False)
    with pytest.raises(mcp_community_actions.PlanRejected, match="kullanılmış"):
        first.call("execute_action", {
            "plan_id": plan_10["plan_id"],
            "plan_sha256": plan_10["plan_sha256"],
            "user_confirmed": True,
        })


def _fix_fixture(tmp_path: Path) -> tuple[FakeStore, Path, dict, str]:
    project = tmp_path / "fix-project"
    project.mkdir()
    source = project / "app.py"
    original = "import os\n\ndef run(name):\n    os.system(\"echo \" + name)\n"
    source.write_text(original, encoding="utf-8")
    audit = {
        "id": "prj_aaaaaaaaaaaa",
        "project_path": str(project),
        "findings": [{
            "title": "Komut enjeksiyonu",
            "category": "command_data",
            "severity": "high",
            "reference": "CWE-78",
            "file": "app.py",
            "line": 4,
            "taint_flow": {"sink_kind": "command", "sink": "os.system"},
        }],
    }
    store = FakeStore(tmp_path / "sniper.db")
    store.audits[audit["id"]] = audit
    return store, source, audit, original


def test_verify_fix_delegates_to_sandbox_verifier_and_never_writes(monkeypatch, tmp_path: Path) -> None:
    store, source, audit, original = _fix_fixture(tmp_path)
    calls: list[tuple[dict, int, tuple[Path, ...] | None]] = []

    def fake_verify(actual_audit, index, *, allowed_roots):
        calls.append((actual_audit, index, allowed_roots))
        return {
            "format": "sniper-fix-verification-v1",
            "verdict": "verified",
            "verdict_label": "doğrulandı",
            "reasons": ["Hedef bulgu kapandı."],
            "finding_index": index,
            "files": ["app.py"],
            "diff": f"--- a/app.py\n+++ b/app.py\n-{audit['project_path']}\n",
            "applied_to_project": False,
        }

    monkeypatch.setattr("fix_verification.verify_finding_fix", fake_verify)
    adapter = _adapter(tmp_path, store=store)
    plan = adapter.call("prepare_action", {
        "action": "verify_fix",
        "parameters": {"audit_id": audit["id"], "finding_index": 0},
    })
    result = adapter.call("execute_action", {
        "plan_id": plan["plan_id"],
        "plan_sha256": plan["plan_sha256"],
        "user_confirmed": True,
    })["result"]

    assert calls == [(audit, 0, (tmp_path.resolve(),))]
    assert result["verdict"] == "verified"
    assert result["files"] == ["app.py"]
    assert result["source_sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert "diff" not in result
    assert str(tmp_path.resolve()) not in json.dumps(result, ensure_ascii=False)
    assert source.read_text(encoding="utf-8") == original


def test_apply_fix_recomputes_verifies_preimage_and_atomically_replaces(monkeypatch, tmp_path: Path) -> None:
    import taint_autofix

    store, source, audit, original = _fix_fixture(tmp_path)
    expected_sha = hashlib.sha256(original.encode()).hexdigest()
    real_compute = taint_autofix.compute_fix
    compute_calls: list[tuple[str, str, int, str]] = []

    def tracked_compute(text, relpath, line, kind, *, flow=None):
        compute_calls.append((text, relpath, line, kind))
        return real_compute(text, relpath, line, kind, flow=flow)

    verify_calls: list[tuple[dict, int]] = []

    def verified(actual_audit, index, *, allowed_roots):
        verify_calls.append((actual_audit, index))
        return {
            "format": "sniper-fix-verification-v1",
            "verdict": "verified",
            "verdict_label": "doğrulandı",
            "reasons": ["Hedef bulgu kapandı."],
            "diff": real_compute(original, "app.py", 4, "command", flow=audit["findings"][0]["taint_flow"])[0]["diff"],
            "applied_to_project": False,
        }

    real_replace = os.replace
    replace_calls: list[tuple[object, object, dict]] = []

    def tracked_replace(before, after, **kwargs):
        replace_calls.append((before, after, dict(kwargs)))
        return real_replace(before, after, **kwargs)

    monkeypatch.setattr("taint_autofix.compute_fix", tracked_compute)
    monkeypatch.setattr("fix_verification.verify_finding_fix", verified)
    monkeypatch.setattr("mcp_community_actions.os.replace", tracked_replace)
    adapter = _adapter(tmp_path, store=store)
    plan = adapter.plan_action("apply_fix", {
        "audit_id": audit["id"],
        "finding_index": 0,
        "expected_source_sha256": expected_sha,
    })
    result = _execute(adapter, plan)["result"]

    changed = source.read_text(encoding="utf-8")
    assert changed != original
    assert compute_calls == [(original, "app.py", 4, "command")]
    assert verify_calls == [(audit, 0)]
    assert len(replace_calls) == 1
    assert str(replace_calls[0][0]).startswith(".sniper-fix-")
    assert replace_calls[0][1] == source.name
    assert replace_calls[0][2]["src_dir_fd"] == replace_calls[0][2]["dst_dir_fd"]
    assert result == {
        "file": "app.py",
        "before_sha256": expected_sha,
        "after_sha256": hashlib.sha256(changed.encode()).hexdigest(),
        "verification_verdict": "verified",
    }


def test_apply_fix_anchors_parent_directory_during_rename_symlink_race(monkeypatch, tmp_path: Path) -> None:
    import taint_autofix

    store, source, audit, original = _fix_fixture(tmp_path)
    project = source.parent
    moved = tmp_path / "moved-project"
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_source = outside / "app.py"
    outside_source.write_text(original, encoding="utf-8")
    expected_sha = hashlib.sha256(original.encode()).hexdigest()
    expected_diff = taint_autofix.compute_fix(
        original,
        "app.py",
        4,
        "command",
        flow=audit["findings"][0]["taint_flow"],
    )[0]["diff"]
    monkeypatch.setattr(
        "fix_verification.verify_finding_fix",
        lambda *args, **kwargs: {"verdict": "verified", "diff": expected_diff},
    )
    real_open = os.open
    raced = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal raced
        if not raced and flags & os.O_CREAT and ".sniper-fix-" in str(path):
            raced = True
            project.rename(moved)
            project.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("mcp_community_actions.os.open", racing_open)
    adapter = _adapter(tmp_path, store=store)
    plan = adapter.plan_action("apply_fix", {
        "audit_id": audit["id"],
        "finding_index": 0,
        "expected_source_sha256": expected_sha,
    })
    result = _execute(adapter, plan)["result"]

    assert raced is True
    assert result["verification_verdict"] == "verified"
    assert (moved / "app.py").read_text(encoding="utf-8") != original
    assert outside_source.read_text(encoding="utf-8") == original


def test_real_verify_and_apply_runtime_control(tmp_path: Path) -> None:
    import project_analyzer

    project = tmp_path / "real-fix-project"
    project.mkdir()
    source = project / "app.py"
    original = (
        "import os\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/ping')\n"
        "def ping():\n"
        "    host = request.args['host']\n"
        "    os.system('ping -c 1 ' + host)\n"
        "    return 'ok'\n"
    )
    source.write_text(original, encoding="utf-8")
    audit = project_analyzer.analyze_project(str(project), allowed_roots=(tmp_path,))
    audit["id"] = "prj_aaaaaaaaaaaa"
    index = next(
        index
        for index, finding in enumerate(audit["findings"])
        if (finding.get("taint_flow") or {}).get("sink_kind") == "command"
    )
    store = FakeStore(tmp_path / "sniper.db")
    store.audits[audit["id"]] = audit
    adapter = _adapter(tmp_path, store=store)

    verify_plan = adapter.plan_action("verify_fix", {"audit_id": audit["id"], "finding_index": index})
    verification = _execute(adapter, verify_plan)["result"]
    assert verification["verdict"] == "verified", verification["reasons"]
    assert source.read_text(encoding="utf-8") == original

    before_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    apply_plan = adapter.plan_action("apply_fix", {
        "audit_id": audit["id"],
        "finding_index": index,
        "expected_source_sha256": before_sha,
    })
    applied = _execute(adapter, apply_plan)["result"]
    assert applied["verification_verdict"] == "verified"
    assert applied["file"] == "app.py"
    assert applied["before_sha256"] == before_sha
    assert applied["after_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert source.read_text(encoding="utf-8") != original


def test_apply_fix_rejects_arbitrary_patch_stale_source_failed_verification_and_symlink(
    monkeypatch, tmp_path: Path,
) -> None:
    store, source, audit, original = _fix_fixture(tmp_path)
    expected_sha = hashlib.sha256(original.encode()).hexdigest()
    adapter = _adapter(tmp_path, store=store)

    with pytest.raises(mcp_community_actions.PlanRejected, match="Desteklenmeyen"):
        adapter.plan_action("apply_fix", {
            "audit_id": audit["id"], "finding_index": 0, "expected_source_sha256": expected_sha,
            "patch": "arbitrary",
        })

    stale = adapter.plan_action("apply_fix", {
        "audit_id": audit["id"], "finding_index": 0, "expected_source_sha256": expected_sha,
    })
    source.write_text(original + "# changed\n", encoding="utf-8")
    verify_calls: list[int] = []
    monkeypatch.setattr(
        "fix_verification.verify_finding_fix",
        lambda *args, **kwargs: verify_calls.append(1) or {"verdict": "verified"},
    )
    with pytest.raises(mcp_community_actions.ActionUnavailable, match="değişmiş"):
        _execute(adapter, stale)
    assert verify_calls == []
    assert source.read_text(encoding="utf-8").endswith("# changed\n")

    source.write_text(original, encoding="utf-8")
    rejected = adapter.plan_action("apply_fix", {
        "audit_id": audit["id"], "finding_index": 0, "expected_source_sha256": expected_sha,
    })
    monkeypatch.setattr(
        "fix_verification.verify_finding_fix",
        lambda *args, **kwargs: {"verdict": "partial", "diff": ""},
    )
    with pytest.raises(mcp_community_actions.ActionUnavailable, match="doğrulanmadı"):
        _execute(adapter, rejected)
    assert source.read_text(encoding="utf-8") == original

    outside = tmp_path / "outside.py"
    outside.write_text(original, encoding="utf-8")
    source.unlink()
    source.symlink_to(outside)
    symlink_plan = adapter.plan_action("apply_fix", {
        "audit_id": audit["id"], "finding_index": 0, "expected_source_sha256": expected_sha,
    })
    with pytest.raises(mcp_community_actions.ActionUnavailable, match="sembolik|okunamadı"):
        _execute(adapter, symlink_plan)
    assert outside.read_text(encoding="utf-8") == original


def test_fix_actions_reject_project_outside_allowed_root(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    outside_source = outside_root / "app.py"
    outside_source.write_text("import os\nos.system(input())\n", encoding="utf-8")
    store = FakeStore(tmp_path / "sniper.db")
    store.audits["prj_aaaaaaaaaaaa"] = {
        "id": "prj_aaaaaaaaaaaa",
        "project_path": str(outside_root),
        "findings": [{"file": "app.py", "line": 2, "reference": "CWE-78", "taint_flow": {"sink_kind": "command"}}],
    }
    adapter = mcp_community_actions.CommunityActions(
        store=store,
        queue=FakeQueue(),
        allowed_roots=(allowed_root,),
        requester={"id": "usr_test", "username": "tester", "role": "analyst"},
        scan_launcher=lambda _plan: {"job_id": "job_" + "2" * 24, "state": "queued"},
    )
    plan = adapter.plan_action("verify_fix", {"audit_id": "prj_aaaaaaaaaaaa", "finding_index": 0})
    with pytest.raises(mcp_community_actions.ActionUnavailable, match="kök|klasörü"):
        _execute(adapter, plan)


def test_local_analysis_reuses_analyzer_and_optional_store(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    observed: dict = {}

    def fake_analyze(path: str, *, allowed_roots, max_files: int) -> dict:
        observed.update(path=path, allowed_roots=allowed_roots, max_files=max_files)
        return {
            "project_path": path,
            "project_name": "project",
            "created_at": "2026-10-23T00:00:00Z",
            "score": 100,
            "grade": "A",
            "file_count": 1,
            "bytes_scanned": 12,
            "findings": [],
        }

    monkeypatch.setattr("project_analyzer.analyze_project", fake_analyze)
    store = FakeStore(tmp_path / "sniper.db")
    adapter = _adapter(tmp_path, store=store)
    plan = adapter.plan_action("analyze_local_project", {"path": str(project), "max_files": 17, "persist": True})
    result = _execute(adapter, plan)

    assert result["status"] == "completed"
    assert result["result"]["id"] == "prj_123456789abc"
    assert observed == {"path": str(project.resolve()), "allowed_roots": (tmp_path.resolve(),), "max_files": 17}
    assert len(store.created) == 1


def test_plan_is_confirmation_bound_hash_bound_expiring_and_single_use(tmp_path: Path) -> None:
    clock = [1000.0]
    adapter = _adapter(tmp_path, clock=lambda: clock[0], plan_ttl_seconds=10)
    job_id = "job_" + "1" * 24
    plan = adapter.plan_action("cancel_job", {"job_id": job_id})

    with pytest.raises(mcp_community_actions.ConfirmationRequired):
        adapter.execute_plan(plan["plan_id"], plan_sha256=plan["plan_sha256"], user_confirmed=1)
    with pytest.raises(mcp_community_actions.PlanRejected):
        adapter.execute_plan(plan["plan_id"], plan_sha256="0" * 64, user_confirmed=True)

    result = _execute(adapter, plan)
    assert result["result"]["state"] == "cancelled"
    with pytest.raises(mcp_community_actions.PlanRejected, match="kullanılmış"):
        _execute(adapter, plan)

    expiring = adapter.plan_action("cancel_job", {"job_id": job_id})
    clock[0] = 1011.0
    with pytest.raises(mcp_community_actions.PlanRejected, match="süresi"):
        _execute(adapter, expiring)


@pytest.mark.parametrize(
    ("fmt", "expected"),
    (("cyclonedx", "CycloneDX"), ("spdx", "SPDX-2.3")),
)
def test_sbom_generation_uses_existing_generators(monkeypatch, tmp_path: Path, fmt: str, expected: str) -> None:
    project = tmp_path / "project"
    project.mkdir()
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    monkeypatch.setattr("dependency_security.generate_cyclonedx_sbom", lambda path, *, allowed_roots: cdx)
    monkeypatch.setattr(
        "sbom_formats.cyclonedx_to_spdx",
        lambda document, **kwargs: {"spdxVersion": "SPDX-2.3", "packages": []},
    )

    adapter = _adapter(tmp_path)
    plan = adapter.plan_action("generate_sbom", {"path": str(project), "format": fmt})
    result = _execute(adapter, plan)

    document = result["result"]["document"]
    assert document.get("bomFormat") == expected or document.get("spdxVersion") == expected
    assert result["result"]["component_count"] == 0


def test_real_local_analyzer_and_sbom_runtime_control(tmp_path: Path) -> None:
    project = tmp_path / "runtime-project"
    project.mkdir()
    (project / "main.py").write_text("def answer():\n    return 42\n", encoding="utf-8")
    (project / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    adapter = _adapter(tmp_path)

    analysis_plan = adapter.plan_action(
        "analyze_local_project",
        {"path": str(project), "max_files": 10, "persist": False},
    )
    analysis = _execute(adapter, analysis_plan)["result"]
    assert analysis["file_count"] >= 1
    assert isinstance(analysis["finding_count"], int)
    assert analysis["persisted"] is False
    assert str(project.resolve()) not in json.dumps(analysis, ensure_ascii=False)

    cdx_plan = adapter.plan_action("generate_sbom", {"path": str(project), "format": "cyclonedx"})
    cdx = _execute(adapter, cdx_plan)["result"]
    assert cdx["document"]["bomFormat"] == "CycloneDX"
    assert cdx["component_count"] == 1
    assert len(cdx["document_sha256"]) == 64

    spdx_plan = adapter.plan_action("generate_sbom", {"path": str(project), "format": "spdx"})
    spdx = _execute(adapter, spdx_plan)["result"]
    assert spdx["document"]["spdxVersion"] == "SPDX-2.3"
    assert spdx["component_count"] == 1


def test_saved_comparison_and_job_status_use_injected_product_adapters(monkeypatch, tmp_path: Path) -> None:
    store = FakeStore(tmp_path / "sniper.db")
    adapter = _adapter(tmp_path, store=store)
    monkeypatch.setattr(
        "project_audit_diff.compare_project_audits",
        lambda actual_store, first, second: {"audit_1_id": first, "audit_2_id": second, "new_count": 2},
    )

    project_plan = adapter.plan_action(
        "compare_saved_scans",
        {"kind": "project_audit", "before_id": "prj_aaaaaaaaaaaa", "after_id": "prj_bbbbbbbbbbbb"},
    )
    assert _execute(adapter, project_plan)["result"]["new_count"] == 2

    network_plan = adapter.plan_action(
        "compare_saved_scans",
        {"kind": "network_scan", "before_id": "scan_old", "after_id": "scan_new"},
    )
    assert _execute(adapter, network_plan)["result"]["new_count"] == 1
    assert store.comparisons == [("scan_old", "scan_new", True)]
    assert adapter.job_status("job_" + "1" * 24)["state"] == "queued"
    assert adapter.job_status("job_" + "9" * 24)["status"] == "unavailable"


@pytest.mark.parametrize("fmt", ("json", "sarif", "html", "csv"))
def test_export_delegates_to_cli_report_and_returns_evidence(monkeypatch, tmp_path: Path, fmt: str) -> None:
    output_dir = tmp_path / "exports"
    output_dir.mkdir()
    store = FakeStore(tmp_path / "sniper.db")

    def fake_export(audit_id: str, output_format: str, target_dir: Path, *, db_path: Path) -> Path:
        assert audit_id == "prj_aaaaaaaaaaaa"
        assert output_format == fmt
        assert db_path == store.path
        path = target_dir / f"report.{fmt}"
        path.write_text(f"safe-{fmt}\n", encoding="utf-8")
        return path

    monkeypatch.setattr("cli_reports.export_project", fake_export)
    adapter = _adapter(tmp_path, store=store)
    plan = adapter.plan_action(
        "export_saved_audit",
        {"audit_id": "prj_aaaaaaaaaaaa", "format": fmt, "target_dir": str(output_dir)},
    )
    result = _execute(adapter, plan)["result"]

    expected = output_dir / f"report.{fmt}"
    assert result == {
        "filename": expected.name,
        "format": fmt,
        "bytes": expected.stat().st_size,
        "sha256": hashlib.sha256(expected.read_bytes()).hexdigest(),
    }


def test_fix_suggestion_is_unified_diff_and_never_writes(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "app.py"
    secret = "super-secret-canary"
    original = f'import os\napi_key = "{secret}"\n\ndef run(name):\n    os.system("echo " + name)\n'
    source.write_text(original, encoding="utf-8")
    audit = {
        "id": "prj_aaaaaaaaaaaa",
        "project_path": str(project),
        "findings": [{
            "title": "Komut enjeksiyonu",
            "file": "app.py",
            "line": 5,
            "taint_flow": {"sink_kind": "command"},
        }],
    }
    store = FakeStore(tmp_path / "sniper.db")
    store.audits[audit["id"]] = audit
    adapter = _adapter(tmp_path, store=store)
    plan = adapter.plan_action("suggest_fix", {"audit_id": audit["id"], "finding_index": 0})
    result = _execute(adapter, plan)["result"]

    assert result["applied"] is False
    assert result["source_sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert result["mode"] == "diff"
    assert result["diff"].startswith("--- a/app.py\n+++ b/app.py\n")
    assert secret not in result["diff"]
    assert "[maskelendi]" in result["diff"]
    assert source.read_text(encoding="utf-8") == original


def test_external_scan_only_delegates_to_pending_request(monkeypatch, tmp_path: Path) -> None:
    calls: list[dict] = []
    launches: list[dict] = []

    def fake_create(store, profile_id, parameters, *, requester, confirm_request):
        calls.append({
            "store": store,
            "profile_id": profile_id,
            "parameters": parameters,
            "requester": requester,
            "confirm_request": confirm_request,
        })
        return {"id": "msr_" + "a" * 16, "status": "pending"}

    monkeypatch.setattr("mcp_scan_requests.create_request", fake_create)
    def launch(approved_plan):
        launches.append(approved_plan)
        return {"job_id": "job_" + "3" * 24, "state": "queued"}

    adapter = _adapter(tmp_path, scan_launcher=launch)
    plan = adapter.plan_action(
        "request_external_scan",
        {
            "profile_id": "operator_authorized_http",
            "parameters": {"tool_id": "owasp-zap", "target": "https://example.com"},
        },
    )
    result = _execute(adapter, plan)

    assert result["result"]["state"] == "queued"
    assert result["result"]["execution"] == "launched"
    assert result["result"]["message"]
    assert calls[0]["confirm_request"] is True
    assert len(launches) == 1
    assert launches[0]["plan_id"] == plan["plan_id"]
    assert launches[0]["plan_sha256"] == plan["plan_sha256"]
    assert launches[0]["parameters"] == plan["parameters"]
    assert launches[0]["request"]["id"] == "msr_" + "a" * 16


def test_external_scan_is_unavailable_without_launcher_and_never_launches_on_failed_gate(monkeypatch, tmp_path: Path) -> None:
    without = _adapter(tmp_path, scan_launcher=None)
    by_name = {item["name"]: item for item in without.list_capabilities()["capabilities"]}
    assert by_name["request_external_scan"]["status"] == "unavailable"
    with pytest.raises(mcp_community_actions.ActionUnavailable):
        without.plan_action("request_external_scan", {
            "profile_id": "operator_authorized_http",
            "parameters": {"tool_id": "owasp-zap", "target": "https://example.com"},
        })

    launches: list[dict] = []
    requests: list[int] = []
    monkeypatch.setattr(
        "mcp_scan_requests.create_request",
        lambda *args, **kwargs: requests.append(1) or {"id": "msr_" + "b" * 16, "status": "pending"},
    )
    adapter = _adapter(tmp_path, scan_launcher=lambda value: launches.append(value) or {"job_id": "job_" + "4" * 24, "state": "queued"})
    plan = adapter.plan_action("request_external_scan", {
        "profile_id": "operator_authorized_http",
        "parameters": {"tool_id": "owasp-zap", "target": "https://example.com"},
    })
    with pytest.raises(mcp_community_actions.ConfirmationRequired):
        adapter.execute_plan(plan["plan_id"], plan_sha256=plan["plan_sha256"], user_confirmed=False)
    with pytest.raises(mcp_community_actions.PlanRejected):
        adapter.execute_plan(plan["plan_id"], plan_sha256="0" * 64, user_confirmed=True)
    assert requests == []
    assert launches == []

    monkeypatch.setattr(
        "mcp_scan_requests.create_request",
        lambda *args, **kwargs: {"id": "invalid", "status": "pending"},
    )
    invalid_request = _adapter(
        tmp_path,
        scan_launcher=lambda value: launches.append(value) or {"job_id": "job_" + "4" * 24, "state": "queued"},
    )
    invalid_plan = invalid_request.plan_action("request_external_scan", {
        "profile_id": "operator_authorized_http",
        "parameters": {"tool_id": "owasp-zap", "target": "https://example.com"},
    })
    with pytest.raises(mcp_community_actions.ActionUnavailable):
        _execute(invalid_request, invalid_plan)
    assert launches == []


def test_invalid_inputs_are_rejected_before_a_plan_exists(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)

    with pytest.raises(mcp_community_actions.ActionUnavailable):
        adapter.plan_action("analyze_local_project", {"path": str(outside)})
    with pytest.raises(mcp_community_actions.PlanRejected):
        adapter.plan_action("export_saved_audit", {"audit_id": "bad", "format": "xml", "target_dir": str(tmp_path)})
    with pytest.raises(mcp_community_actions.PlanRejected):
        adapter.plan_action("unknown", {})


def test_plan_hash_covers_normalized_parameters(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    plan = adapter.plan_action("cancel_job", {"job_id": "job_" + "1" * 24})
    exact = {
        "format": plan["format"],
        "plan_id": plan["plan_id"],
        "action": plan["action"],
        "parameters": plan["parameters"],
        "consent_scope": plan["consent_scope"],
        "effects": plan["effects"],
        "created_at": plan["created_at"],
        "expires_at": plan["expires_at"],
    }
    canonical = json.dumps(exact, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    assert plan["plan_sha256"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
