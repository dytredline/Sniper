from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

import community_tool_installer as installer


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-community-tools-image"
BASE_COMPOSE = ROOT / "docker-compose.yml"
TOOLS_COMPOSE = ROOT / "docker-compose.tools.yml"


def _run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_build_plan_fails_closed_without_explicit_license_acceptance() -> None:
    run = _run_script("--dry-run")
    assert run.returncode == 2
    assert run.stdout == ""
    assert "third-party license acceptance" in run.stderr.lower()


def test_dry_run_reports_exact_locked_profile_without_starting_docker() -> None:
    run = _run_script("--dry-run", "--accept-third-party-licenses")
    assert run.returncode == 0, run.stderr
    plan = json.loads(run.stdout)
    lock = json.loads((ROOT / "COMMUNITY-TOOLS.lock.json").read_text(encoding="utf-8"))

    assert plan == {
        "format": "sniper-community-tools-container-plan-v1",
        "status": "planned",
        "command": [
            "docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.tools.yml",
            "build", "sniper",
        ],
        "compose_files": ["docker-compose.yml", "docker-compose.tools.yml"],
        "service": "sniper",
        "build_target": "community-tools",
        "image": "sniper-community-tools:local",
        "platform_source": "linux-container-runtime",
        "tools": lock["profiles"]["local"],
        "tool_count": 7,
        "downloads_locked_artifacts": True,
        "executes_scanners": False,
        "publishes": ["127.0.0.1:8787:8787"],
    }


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
def test_compose_override_requires_acceptance_and_preserves_loopback_and_volumes() -> None:
    command = [
        "docker", "compose", "-f", str(BASE_COMPOSE), "-f", str(TOOLS_COMPOSE),
        "config", "--format", "json",
    ]
    rejected = subprocess.run(
        command,
        cwd=ROOT,
        env={
            **{key: value for key, value in os.environ.items() if key != "SNIPER_ACCEPT_THIRD_PARTY_LICENSES"},
            "GRAFANA_ADMIN_PASSWORD": "synthetic-compose-contract",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "SNIPER_ACCEPT_THIRD_PARTY_LICENSES" in rejected.stderr

    accepted = subprocess.run(
        command,
        cwd=ROOT,
        env={
            **os.environ,
            "GRAFANA_ADMIN_PASSWORD": "synthetic-compose-contract",
            "SNIPER_ACCEPT_THIRD_PARTY_LICENSES": "1",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert accepted.returncode == 0, accepted.stderr
    config = json.loads(accepted.stdout)
    sniper = config["services"]["sniper"]
    assert sniper["build"]["target"] == "community-tools"
    assert sniper["build"]["args"] == {"SNIPER_ACCEPT_THIRD_PARTY_LICENSES": "1"}
    assert sniper["image"] == "sniper-community-tools:local"
    assert sniper["ports"] == [{
        "mode": "ingress", "target": 8787, "published": "8787", "protocol": "tcp",
        "host_ip": "127.0.0.1",
    }]
    assert {item["target"] for item in sniper["volumes"]} == {
        "/var/lib/sniper", "/var/lib/sniper-integrity", "/var/lib/sniper-secrets",
    }


def test_default_dockerfile_target_stays_core_and_tools_target_is_license_gated() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "AS community-runtime" in text
    assert "AS community-tools" in text
    assert "AS community-core" in text
    assert text.rfind("AS community-core") > text.rfind("AS community-tools")
    tools_target = text.split("FROM community-runtime AS community-tools", 1)[1].split(
        "FROM community-runtime AS community-core", 1
    )[0]
    instructions = [
        line.strip() for line in tools_target.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert instructions[:2] == [
        "ARG SNIPER_ACCEPT_THIRD_PARTY_LICENSES=0",
        'RUN test "$SNIPER_ACCEPT_THIRD_PARTY_LICENSES" = "1" || \\',
    ]
    assert "scripts/install-community-tools" in text
    assert "--accept-third-party-licenses" in text


@pytest.mark.parametrize(
    ("machine", "expected"),
    (("amd64", "linux-x86_64"), ("x86_64", "linux-x86_64"), ("arm64", "linux-aarch64")),
)
def test_installer_selects_locked_artifact_for_linux_container_architecture(
    monkeypatch: pytest.MonkeyPatch, machine: str, expected: str
) -> None:
    monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(installer.platform, "machine", lambda: machine)
    assert installer.current_platform_key() == expected
