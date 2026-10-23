from __future__ import annotations

from pathlib import Path
import json
import tempfile
from types import SimpleNamespace

import pytest

import mcp_scan_requests
import mcp_community_actions
import mcp_triage_server
from mcp_community_runtime import CommunityRuntimeError, CommunityScanLauncher
from scanner import normalize_target
from storage import Store


ADMIN = {"id": "community-local-owner", "username": "community-local-owner", "role": "admin"}


class RecordingQueue:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def submit(self, route, runner, *, dedupe_key, label=None, timeout_seconds=None, before_enqueue=None):
        job = SimpleNamespace(id="job_" + "a" * 24, route=route, state="queued")
        if before_enqueue is not None:
            before_enqueue(job)
        self.calls.append({
            "route": route,
            "runner": runner,
            "dedupe_key": dedupe_key,
            "label": label,
            "timeout_seconds": timeout_seconds,
        })
        return job

    def get(self, job_id):
        return {"id": job_id, "route": self.calls[-1]["route"], "state": "queued"} if self.calls else None

    def cancel(self, job_id):
        return {"id": job_id, "route": self.calls[-1]["route"], "state": "cancelled"} if self.calls else None


@pytest.fixture()
def runtime_store():
    with tempfile.TemporaryDirectory(dir=Path.home()) as raw:
        data_dir = Path(raw) / "data"
        store = Store(data_dir / "sniper.db")
        target = store.create_target(normalize_target("https://example.com"))
        engagement = store.create_engagement(
            target_id=target["id"],
            name="Community runtime contract",
            authorization_ref="AUTH-RUNTIME",
            scope_notes="Registered target only",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )
        yield store, target, engagement


def test_confirmed_registered_scan_claims_and_enqueues_only_derived_route(runtime_store) -> None:
    store, target, engagement = runtime_store
    preview = mcp_scan_requests.preview_request(
        store,
        "nuclei_http_authorized",
        {"target_id": target["id"], "engagement_id": engagement["id"]},
    )
    request = mcp_scan_requests.create_request(
        store,
        "nuclei_http_authorized",
        {"target_id": target["id"], "engagement_id": engagement["id"]},
        requester=ADMIN,
        confirm_request=True,
    )
    queue = RecordingQueue()
    launcher = CommunityScanLauncher(store, queue=queue, actor=ADMIN)

    result = launcher({
        "plan_id": "plan_" + "1" * 24,
        "plan_sha256": "2" * 64,
        "action": "request_external_scan",
        "parameters": preview,
        "request": request,
    })

    assert result["execution"] == "launched"
    assert result["state"] == "queued"
    assert result["job_id"] == "job_" + "a" * 24
    assert result["request_id"] == request["id"]
    assert queue.calls[0]["route"] == "/api/nuclei/http-scans"
    saved = next(row for row in mcp_scan_requests.list_requests(store, requester=ADMIN) if row["id"] == request["id"])
    assert saved["status"] == "started"
    assert saved["job_id"] == result["job_id"]
    assert saved["authorization_receipt"]["confirm_authorized"] is True


def test_launcher_rejects_any_claim_route_outside_fixed_catalog(monkeypatch, runtime_store) -> None:
    store, _target, _engagement = runtime_store
    queue = RecordingQueue()
    launcher = CommunityScanLauncher(store, queue=queue, actor=ADMIN)
    monkeypatch.setattr(
        mcp_scan_requests,
        "claim_request",
        lambda *args, **kwargs: {
            "id": "msr_" + "b" * 16,
            "launch": {"route": "/api/arbitrary", "payload": {"command": "id"}},
        },
    )

    with pytest.raises(CommunityRuntimeError, match="route"):
        launcher({
            "plan_id": "plan_" + "3" * 24,
            "plan_sha256": "4" * 64,
            "action": "request_external_scan",
            "parameters": {
                "profile_id": "operator_authorized_http",
                "parameters": {},
                "scan_plan_sha256": "7" * 64,
                "normalized_target": "https://example.com/",
            },
            "request": {
                "id": "msr_" + "b" * 16,
                "profile_id": "operator_authorized_http",
                "parameters": {},
                "plan_sha256": "7" * 64,
                "normalized_target": "https://example.com/",
            },
        })
    assert queue.calls == []


def test_launcher_rejects_mismatched_request_and_plan_before_claim(monkeypatch, runtime_store) -> None:
    store, _target, _engagement = runtime_store
    launcher = CommunityScanLauncher(store, queue=RecordingQueue(), actor=ADMIN)
    claimed: list[bool] = []
    monkeypatch.setattr(
        mcp_scan_requests,
        "claim_request",
        lambda *args, **kwargs: claimed.append(True),
    )
    with pytest.raises(CommunityRuntimeError, match="eşleşmiyor"):
        launcher({
            "plan_id": "plan_" + "5" * 24,
            "plan_sha256": "6" * 64,
            "action": "request_external_scan",
            "parameters": {
                "profile_id": "sandbox_k6",
                "parameters": {"target": "http://127.0.0.1:8080"},
                "scan_plan_sha256": "8" * 64,
                "normalized_target": "http://127.0.0.1:8080/",
            },
            "request": {
                "id": "msr_" + "c" * 16,
                "profile_id": "nuclei_http_authorized",
                "parameters": {},
                "plan_sha256": "8" * 64,
                "normalized_target": "http://127.0.0.1:8080/",
            },
        })
    assert claimed == []


def test_worker_inherits_verified_runtime_bindings(monkeypatch, runtime_store) -> None:
    store, _target, _engagement = runtime_store
    launcher = CommunityScanLauncher(store, queue=RecordingQueue(), actor=ADMIN)
    captured: dict = {}

    class WorkerProcess:
        returncode = 0

        @staticmethod
        def communicate(_request):
            return json.dumps({"status": 200, "body": {"ok": True}}).encode("utf-8"), None

    def popen(_command, **kwargs):
        captured.update(kwargs["env"])
        return WorkerProcess()

    monkeypatch.setattr("mcp_community_runtime.subprocess.Popen", popen)
    with monkeypatch.context() as scoped:
        scoped.setenv("SNIPER_NUCLEI_BINARY", "/verified/community/nuclei")
        scoped.setenv("SNIPER_NUCLEI_SHA256", "a" * 64)
        status, body = launcher._run_worker("/api/nuclei/http-scans", {}, ADMIN, SimpleNamespace())

    assert (status, body) == (200, {"ok": True})
    assert captured["SNIPER_NUCLEI_BINARY"] == "/verified/community/nuclei"
    assert captured["SNIPER_NUCLEI_SHA256"] == "a" * 64
    assert captured["SNIPER_DATA_DIR"] == str(Path(store.path).parent)


def _mcp_payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


def test_community_server_exposes_and_dispatches_action_tools_but_authenticated_mode_does_not(runtime_store) -> None:
    store, _target, _engagement = runtime_store
    queue = RecordingQueue()
    actions = mcp_community_actions.CommunityActions(
        store=store,
        queue=queue,
        requester=ADMIN,
        scan_launcher=lambda _plan: {"job_id": "job_" + "d" * 24, "state": "queued"},
    )
    community = mcp_triage_server.TriageMCPServer(
        store,
        mode="community",
        community_actions=actions,
    )
    authenticated = mcp_triage_server.TriageMCPServer(store, mode="authenticated")

    community_names = {
        item["name"]
        for item in community.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    }
    authenticated_names = {
        item["name"]
        for item in authenticated.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    }
    assert {"list_community_capabilities", "prepare_action", "execute_action", "community_job_status"} <= community_names
    assert not ({"list_community_capabilities", "prepare_action", "execute_action", "community_job_status"} & authenticated_names)

    capabilities = community.call_tool("list_community_capabilities", {})
    assert capabilities["isError"] is False
    assert _mcp_payload(capabilities)["format"] == "sniper-community-capabilities-v1"

    rejected = community.call_tool("execute_action", {
        "plan_id": "plan_" + "e" * 24,
        "plan_sha256": "f" * 64,
        "user_confirmed": False,
    })
    assert rejected["isError"] is True
    assert "onay" in rejected["content"][0]["text"].lower()


def test_external_action_normalizes_target_before_plan_hash_and_enqueues_without_pending_orphan(runtime_store) -> None:
    store, _target, _engagement = runtime_store
    queue = RecordingQueue()
    launcher = CommunityScanLauncher(store, queue=queue, actor=ADMIN)
    actions = mcp_community_actions.CommunityActions(
        store=store,
        queue=queue,
        requester=ADMIN,
        scan_launcher=launcher,
    )
    plan = actions.plan_action("request_external_scan", {
        "profile_id": "operator_authorized_http",
        "parameters": {"tool_id": "owasp-zap", "target": "https://example.com"},
    })

    assert plan["parameters"]["parameters"]["target"] == "https://example.com/"
    assert plan["parameters"]["scan_plan_sha256"]
    result = actions.execute_plan(
        plan["plan_id"],
        plan_sha256=plan["plan_sha256"],
        user_confirmed=True,
    )["result"]

    assert result["execution"] == "launched"
    assert result["state"] == "queued"
    rows = mcp_scan_requests.list_requests(store, requester=ADMIN)
    assert len(rows) == 1
    assert rows[0]["status"] == "started"
    assert rows[0]["parameters"]["target"] == "https://example.com/"


def test_external_action_returns_manual_handoff_as_success_without_fake_job(runtime_store) -> None:
    store, _target, _engagement = runtime_store
    queue = RecordingQueue()
    launcher = CommunityScanLauncher(store, queue=queue, actor=ADMIN)
    actions = mcp_community_actions.CommunityActions(
        store=store,
        queue=queue,
        requester=ADMIN,
        scan_launcher=launcher,
    )
    plan = actions.plan_action("request_external_scan", {
        "profile_id": "operator_authorized_http",
        "parameters": {"tool_id": "burp-suite", "target": "https://example.com"},
    })
    result = actions.execute_plan(
        plan["plan_id"],
        plan_sha256=plan["plan_sha256"],
        user_confirmed=True,
    )["result"]

    assert result["execution"] == "manual_handoff"
    assert result["state"] == "approved"
    assert "job_id" not in result
    assert queue.calls == []


def test_external_action_marks_request_failed_when_launcher_result_is_invalid(runtime_store) -> None:
    store, _target, _engagement = runtime_store
    actions = mcp_community_actions.CommunityActions(
        store=store,
        queue=RecordingQueue(),
        requester=ADMIN,
        scan_launcher=lambda _plan: {"job_id": "invalid", "state": "queued"},
    )
    plan = actions.plan_action("request_external_scan", {
        "profile_id": "operator_authorized_http",
        "parameters": {"tool_id": "owasp-zap", "target": "https://example.com"},
    })

    with pytest.raises(mcp_community_actions.ActionUnavailable):
        actions.execute_plan(
            plan["plan_id"],
            plan_sha256=plan["plan_sha256"],
            user_confirmed=True,
        )

    rows = mcp_scan_requests.list_requests(store, requester=ADMIN)
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
