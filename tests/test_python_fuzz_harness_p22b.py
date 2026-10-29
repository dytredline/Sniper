"""Executable Python/Atheris fuzz harness synthesis (P2.2b)."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

import asan_project_proof


PARSER_SOURCE = '''
# def decode_comment_decoy(value: bytes): ...
STRING_DECOY = "def normalize_string_decoy(value: bytes): ..."

def parse_frame(payload: bytes):
    if not payload:
        raise ValueError("empty frame")
    if payload == b"crash":
        raise RuntimeError("unexpected parser fault")
    return payload[0]
'''


def _synthesize(source: str = PARSER_SOURCE) -> dict:
    return asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "src/frame_decoder.py", "reference": "CWE-20"},
        source_snippet=source,
    )


def test_python_parser_resolves_one_ast_target_and_generated_harness_executes_check() -> None:
    result = _synthesize()

    assert result["format"] == "sniper-sanitizer-fuzz-harness/1"
    assert result["language"] == "python"
    assert result["fuzz_engine"] == "atheris"
    assert result["target_symbol"] == "parse_frame"
    assert result["target_input"] == "bytes"
    assert result["runtime_available"] is (importlib.util.find_spec("atheris") is not None)
    assert result["harness_filename"] == "fuzz_parse_frame.py"
    ast.parse(result["harness_code"], filename=result["harness_filename"])

    with tempfile.TemporaryDirectory() as raw_project:
        project = Path(raw_project)
        (project / "src").mkdir()
        (project / "src/frame_decoder.py").write_text(PARSER_SOURCE, encoding="utf-8")
        harness = project / result["harness_filename"]
        harness.write_text(result["harness_code"], encoding="utf-8")

        compiled = subprocess.run(
            [sys.executable, "-m", "py_compile", str(harness), str(project / "src/frame_decoder.py")],
            cwd=project,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert compiled.returncode == 0, compiled.stderr

        checked = subprocess.run(
            [sys.executable, str(harness), "--check-target"],
            cwd=project,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert checked.returncode == 0, checked.stderr
        assert checked.stdout.strip() == "SNIPER_PY_FUZZ_TARGET_OK parse_frame bytes"


def test_missing_atheris_runtime_fails_closed_without_running_fuzzer() -> None:
    result = _synthesize()
    if result["runtime_available"]:
        pytest.skip("Atheris is installed; missing-runtime branch is not applicable")

    with tempfile.TemporaryDirectory() as raw_project:
        project = Path(raw_project)
        (project / "src").mkdir()
        (project / "src/frame_decoder.py").write_text(PARSER_SOURCE, encoding="utf-8")
        harness = project / result["harness_filename"]
        harness.write_text(result["harness_code"], encoding="utf-8")
        checked = subprocess.run(
            [sys.executable, str(harness), "--check-runtime"],
            cwd=project,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    assert checked.returncode == 2
    assert checked.stdout == ""
    assert checked.stderr.strip() == "Atheris runtime unavailable; install the declared requirement before fuzzing."
    assert "Traceback" not in checked.stderr


def test_ambiguous_or_untrusted_python_target_is_rejected() -> None:
    ambiguous = '''
def parse_alpha(data: bytes):
    return data

def decode_beta(data: bytes):
    return data
'''
    with pytest.raises(asan_project_proof.AsanProjectProofError, match="tam olarak bir"):
        _synthesize(ambiguous)

    untyped = "def normalize_value(value):\n    return value\n"
    with pytest.raises(asan_project_proof.AsanProjectProofError, match="tam olarak bir"):
        _synthesize(untyped)

    with pytest.raises(asan_project_proof.AsanProjectProofError, match="güvenli göreli"):
        asan_project_proof.synthesize_sanitizer_fuzz_harness(
            {"file": "../frame_decoder.py", "reference": "CWE-20"},
            source_snippet=PARSER_SOURCE,
        )
