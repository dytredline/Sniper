"""Regression tests for bounded-time parsing of attacker-controlled project text."""
from __future__ import annotations

from pathlib import Path
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import iac_engine  # noqa: E402
import project_analyzer  # noqa: E402
import taint_clike  # noqa: E402


def test_docker_env_parser_preserves_quoted_values() -> None:
    assert iac_engine._env_pairs(
        'A=one B="two words" C=\'three words\' D= E', "ARG"
    ) == [
        ("A", "one"),
        ("B", "two words"),
        ("C", "three words"),
        ("D", ""),
        ("E", ""),
    ]


def test_docker_env_unterminated_escape_sequence_is_bounded() -> None:
    value = "\\!" * 24
    started = time.perf_counter()
    pairs = iac_engine._env_pairs('A="' + value, "ARG")
    elapsed = time.perf_counter() - started

    assert pairs == [("A", value)]
    assert elapsed < 0.4, f"unterminated Docker ENV value took {elapsed:.3f}s"


def test_mybatis_annotation_parser_preserves_supported_forms() -> None:
    source = r'''
        @Select("SELECT * FROM users WHERE id = ${id}")
        User find(String id);

        @Update({"UPDATE users", "SET name = ${name}"})
        @Deprecated
        java.util.List<User> rename(String name);

        @Delete("DELETE FROM users WHERE id = #{id}")
        int safeDelete(String id);
    '''
    assert taint_clike.mybatis_unsafe_methods({"Mapper.java": source}) == {"find", "rename"}


def test_mybatis_unterminated_escaped_annotation_is_bounded() -> None:
    source = '@Select("${column}' + ("\\!" * 25)
    started = time.perf_counter()
    methods = taint_clike.mybatis_unsafe_methods({"Mapper.java": source})
    elapsed = time.perf_counter() - started

    assert methods == set()
    assert elapsed < 0.5, f"unterminated MyBatis annotation took {elapsed:.3f}s"


def test_inline_template_masking_preserves_dom_flow_and_line() -> None:
    page = '''<script>
const input = location.hash;
const ignored = "{{ value }} {% if ok %}yes{% endif %} {# note #} <% value %>";
document.body.innerHTML = input;
</script>'''
    analysis = project_analyzer._inline_script_analysis(page, "templates/page.html")

    assert analysis is not None
    assert {(flow.sink_kind, flow.line) for flow in analysis.flows} == {("html", 4)}


def test_inline_template_masking_preserves_length_and_every_newline() -> None:
    source = "{{\n value\n}}\n<%\n other\n%>"
    masked = project_analyzer._mask_inline_template_tags(source)

    assert len(masked) == len(source)
    assert [index for index, char in enumerate(masked) if char == "\n"] == [
        index for index, char in enumerate(source) if char == "\n"
    ]
    assert masked[0] == "0"


def test_inline_unterminated_template_sequence_is_bounded() -> None:
    page = (
        "<script>const input=location.hash;document.body.innerHTML=input;"
        + ("{{" * 12_000)
        + "</script>"
    )
    started = time.perf_counter()
    analysis = project_analyzer._inline_script_analysis(page, "templates/adversarial.html")
    elapsed = time.perf_counter() - started

    assert analysis is None
    assert elapsed < 0.75, f"unterminated inline template sequence took {elapsed:.3f}s"
