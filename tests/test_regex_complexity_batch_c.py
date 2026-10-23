"""Batch-C regressions for polynomial regexes over project/report input."""
from __future__ import annotations

from pathlib import Path
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import i18n_server  # noqa: E402
import iac_engine  # noqa: E402
import iac_helm  # noqa: E402
import iac_yaml  # noqa: E402


def _translator() -> i18n_server.Translator:
    return i18n_server.Translator({
        "strings": {"Test": "Trial", "Bir.": "One.", "İki": "Two", "Öğe": "Item"},
        "patterns": [],
        "fragments": [],
    })


def test_i18n_suffix_sentence_bullet_and_markup_semantics() -> None:
    tr = _translator()
    assert tr.exact("Test...") == "Trial..."
    assert tr.sentences("Bir. İki") == "One. Two"
    assert tr.core("* Öğe") == "* Item"
    assert i18n_server._translate_markup('<p title="Öğe">Öğe</p>', tr) == \
        '<p title="Item">Item</p>'


def test_i18n_suffix_failure_is_bounded() -> None:
    started = time.perf_counter()
    assert _translator().exact("A" + (" " * 10_000) + "X") is None
    elapsed = time.perf_counter() - started
    assert elapsed < 0.15, f"i18n suffix parsing took {elapsed:.3f}s"


def test_i18n_bullet_failure_is_bounded() -> None:
    started = time.perf_counter()
    assert _translator().core("* " + ("  " * 10_000)) is None
    elapsed = time.perf_counter() - started
    assert elapsed < 0.3, f"i18n bullet parsing took {elapsed:.3f}s"


def test_i18n_unterminated_markup_is_bounded() -> None:
    payload = "<" * 40_000
    started = time.perf_counter()
    assert i18n_server._translate_markup(payload, _translator()) == payload
    elapsed = time.perf_counter() - started
    assert elapsed < 0.2, f"i18n markup splitting took {elapsed:.3f}s"


def test_helm_action_rendering_semantics() -> None:
    template = "{{$A := .Values.a}}\nvalue: {{$A}}\n{{- if .Values.on }}\nenabled: true\n{{- end }}"
    rendered, mapping = iac_helm.render(template, {"a": "x", "on": True})
    assert rendered == "value: x\nenabled: true"
    assert mapping == [2, 4]

    lite = iac_yaml.render_helm_lite("a: {{ .Values.a }}\n{{ if .Values.on }}\nb: true\n{{ end }}")
    assert lite == f"a: {iac_yaml.HELM_PLACEHOLDER}\n\nb: true\n"


def test_helm_unterminated_inline_actions_are_bounded() -> None:
    payload = "{{{{" + ("{{{{a" * 3_000)
    scope = {"root": {}, "dot": {}, "vars": {}, "uncertain": False}
    started = time.perf_counter()
    assert iac_helm._render_inline(payload, scope) == [payload.replace("{{", "")]
    elapsed = time.perf_counter() - started
    assert elapsed < 0.25, f"Helm inline action parsing took {elapsed:.3f}s"


def test_helm_unterminated_multiline_action_is_bounded() -> None:
    payload = "{{{{" + ("{{{{\n" * 300)
    started = time.perf_counter()
    rendered = iac_helm.render(payload, {})
    elapsed = time.perf_counter() - started
    assert rendered is not None
    assert elapsed < 0.25, f"Helm multiline parsing took {elapsed:.3f}s"


def test_helm_unterminated_assignment_is_bounded() -> None:
    payload = "{{$A:=" + (" " * 1_000)
    started = time.perf_counter()
    rendered = iac_helm.render(payload, {})
    elapsed = time.perf_counter() - started
    assert rendered is not None
    assert elapsed < 0.25, f"Helm assignment parsing took {elapsed:.3f}s"


def test_helm_lite_unterminated_actions_are_bounded() -> None:
    multiline = "{{{{" + ("{{{{\n" * 300)
    inline = "{{{{" + ("{{{{-" * 1_500)
    started = time.perf_counter()
    assert iac_yaml.render_helm_lite(multiline) == multiline.replace("{{", "")
    assert iac_yaml.render_helm_lite(inline) == inline.replace("{{", "")
    elapsed = time.perf_counter() - started
    assert elapsed < 0.25, f"Helm-lite action parsing took {elapsed:.3f}s"


def test_docker_and_ci_parsing_semantics() -> None:
    docker = iac_engine.analyze_dockerfile(
        "FROM --platform=linux/amd64 alpine AS build\n"
        "RUN git config --global http.sslverify false\n"
        "ARG NODE_TLS_REJECT_UNAUTHORIZED=0\n"
    )
    docker_ids = [finding["id"] for finding in docker.findings]
    assert docker_ids.count("SNP-IAC-DF-009") == 2

    github = iac_engine.analyze_ci(
        ".github/workflows/x.yml",
        'id: build\necho "result=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT\n'
        'run: echo "${{ steps.build.outputs.result }}"',
    )
    assert github is not None
    assert [(finding["id"], finding["line"]) for finding in github.findings] == [("SNP-IAC-CI-001", 3)]

    gitlab = iac_engine.analyze_ci(
        ".gitlab-ci.yml",
        'PAYLOAD=$CI_MERGE_REQUEST_TITLE > result.env\nscript:\n  echo "$PAYLOAD"',
    )
    assert gitlab is not None
    assert [(finding["id"], finding["line"]) for finding in gitlab.findings] == [("SNP-IAC-CI-002", 3)]


def test_docker_tls_spacing_is_bounded() -> None:
    started = time.perf_counter()
    result = iac_engine.analyze_dockerfile("RUN http.sslverify" + (" " * 20_000) + "X")
    elapsed = time.perf_counter() - started
    assert not any(finding["id"] == "SNP-IAC-DF-009" for finding in result.findings)
    assert elapsed < 0.25, f"Docker TLS parsing took {elapsed:.3f}s"


def test_gitlab_unterminated_dotenv_redirect_is_bounded() -> None:
    payload = "$CI_MERGE_REQUEST_TITLE " + (">!" * 10_000)
    started = time.perf_counter()
    result = iac_engine.analyze_ci(".gitlab-ci.yml", payload)
    elapsed = time.perf_counter() - started
    assert result is not None and result.findings == []
    assert elapsed < 0.12, f"GitLab dotenv parsing took {elapsed:.3f}s"


def test_github_output_name_failure_is_bounded() -> None:
    payload = "id: build\n" + ("A" * 10_000) + " GITHUB_OUTPUT"
    started = time.perf_counter()
    result = iac_engine.analyze_ci(".github/workflows/x.yml", payload)
    elapsed = time.perf_counter() - started
    assert result is not None and result.findings == []
    assert elapsed < 0.2, f"GitHub output parsing took {elapsed:.3f}s"
