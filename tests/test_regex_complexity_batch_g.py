"""Batch G: bounded YAML/GitHub Actions parsing in project_analyzer."""
from __future__ import annotations

from pathlib import Path
import time

import project_analyzer


def _analyze_yaml(tmp_path: Path, relative: str, source: str) -> list[dict]:
    root = tmp_path / "project"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return project_analyzer.analyze_project(
        str(root), allowed_roots=(tmp_path,)
    )["findings"]


def test_rule_pack_yaml_classifier_preserves_supported_forms() -> None:
    for source in (
        "rules:\n  - id: x\n    pattern: dangerous(...)\n",
        "rules:\n  - patterns:\n      - pattern-regex: foo.*bar\n",
        "rules:\n  - mode: taint\n    pattern-sources: []\n",
    ):
        assert project_analyzer._is_detection_rule_pack(".yaml", source)

    assert not project_analyzer._is_detection_rule_pack(
        ".yaml", "ruleset:\n  - ordinary: value\n"
    )
    assert not project_analyzer._is_detection_rule_pack(
        ".yaml", "rules:\n  - ordinary: value\n"
    )


def test_rule_pack_yaml_adversarial_whitespace_is_bounded() -> None:
    source = "rules:\n" + (" " * 16_000) + "!\n"
    started = time.perf_counter()
    detected = project_analyzer._is_detection_rule_pack(".yaml", source)
    elapsed = time.perf_counter() - started

    assert not detected
    assert elapsed < 0.25, f"rule-pack YAML classification took {elapsed:.3f}s"


def test_yaml_security_fallback_preserves_findings(tmp_path: Path) -> None:
    findings = _analyze_yaml(
        tmp_path,
        "config/settings.yaml",
        "- privileged: true\n"
        "- network_mode: \"host\"\n"
        "- hostNetwork: TRUE\n"
        "- allowPrivilegeEscalation: true\n",
    )
    def lines(title: str) -> list[int]:
        return sorted(finding["line"] for finding in findings if finding["title"] == title)

    assert lines("Konteyner/Pod privileged (tam yetkili) modda çalışıyor") == [1]
    assert lines("Konteyner/Pod ana makine ağ uzayını (hostNetwork) paylaşıyor") == [2, 3]
    assert lines("Kubernetes iş yükünde yetki yükseltme (allowPrivilegeEscalation) açık") == [4]


def test_github_actions_untrusted_field_semantics_are_preserved(tmp_path: Path) -> None:
    findings = _analyze_yaml(
        tmp_path,
        ".github/workflows/ci.yml",
        "name: CI\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: echo '${{ github.event.issue.title }}'\n"
        "      - run: echo '${{ github.event.pages.0.page_name }}'\n"
        "      - run: echo '${{ github.event.commits.0.author.email }}'\n"
        "      - env:\n"
        "          TITLE: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"$TITLE\"\n"
        "      - run: echo '${{ github.event.pull_request.head.sha }}'\n"
        "      - run: echo '${{ github.workflow }}'\n",
    )
    injection_lines = sorted(
        finding["line"] for finding in findings
        if finding["title"] == "CI/CD iş akışında güvenilmeyen etkinlik verisiyle komut enjeksiyonu riski"
    )

    assert injection_lines == [5, 6, 7]


def test_project_yaml_adversarial_lines_are_bounded(tmp_path: Path) -> None:
    spaces = " " * 12_000
    malformed_expression = "${{{{" * 4_000
    source = (
        "name: CI\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        f"run:{spaces}\n"
        f"{spaces}!\n"
        f"      - run: {malformed_expression}\n"
    )

    started = time.perf_counter()
    findings = _analyze_yaml(tmp_path, ".github/workflows/adversarial.yml", source)
    elapsed = time.perf_counter() - started

    assert not any(finding["reference"] == "CWE-78" for finding in findings)
    assert elapsed < 1.0, f"project YAML analysis took {elapsed:.3f}s"
