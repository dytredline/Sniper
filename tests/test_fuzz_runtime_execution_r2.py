"""Bounded, operator-supplied optional fuzz runtime execution (R2)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys

import pytest

import asan_project_proof
import fuzz_runtime
from verified_exec import file_sha256, open_verified_executable


PYTHON_SOURCE = """\
def parse_frame(payload: bytes):
    if not payload:
        raise ValueError("empty")
    return payload[0]
"""

JS_SOURCE = """\
/** @param {Buffer} payload */
export function parseFrame(payload) {
  return payload.length;
}
"""

JAVA_SOURCE = """\
package example;
public final class Decoder {
    public static byte[] decode(byte[] input) { return input; }
}
"""


def _missing(language: str, tmp_path: Path) -> dict:
    if language == "python":
        finding = {"file": "src/parser.py", "reference": "CWE-20"}
        source = PYTHON_SOURCE
    elif language == "javascript":
        finding = {"file": "src/parser.mjs", "reference": "CWE-20"}
        source = JS_SOURCE
    else:
        finding = {
            "file": "src/example/Decoder.java",
            "reference": "CWE-20",
            "symbol": "Decoder#decode(byte[])",
        }
        source = JAVA_SOURCE
    target = tmp_path / finding["file"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return asan_project_proof.execute_sanitizer_fuzz_runtime(
        finding,
        source_snippet=source,
        project_root=tmp_path,
        confirm_local=True,
        max_runs=3,
        seed=17,
        max_input_bytes=256,
        timeout_seconds=2,
        max_output_bytes=4096,
    )


@pytest.mark.parametrize(
    ("language", "engine"),
    [("python", "atheris"), ("javascript", "fast-check"), ("java", "jazzer")],
)
def test_unconfigured_optional_engine_is_explicitly_not_run(
    language: str, engine: str, tmp_path: Path,
) -> None:
    result = _missing(language, tmp_path)

    assert result["format"] == "sniper-fuzz-runtime-execution/1"
    assert result["engine"] == engine
    assert result["readiness"] == "runtime_missing"
    assert result["execution"] == "not_run"
    assert result["reason"] == "runtime_configuration_incomplete"
    assert result["bounds"] == {
        "max_runs": 3,
        "seed": 17,
        "max_input_bytes": 256,
        "timeout_seconds": 2,
        "max_output_bytes": 4096,
    }
    assert result["runtime_sha256"] is None
    assert result["support_sha256"] is None
    assert "project_root" not in result
    assert str(tmp_path) not in repr(result)


def test_execution_requires_exact_local_consent_and_strict_bounds(tmp_path: Path) -> None:
    finding = {"file": "src/parser.py", "reference": "CWE-20"}
    target = tmp_path / "src/parser.py"
    target.parent.mkdir()
    target.write_text(PYTHON_SOURCE, encoding="utf-8")

    with pytest.raises(asan_project_proof.AsanProjectProofError, match="confirm_local"):
        asan_project_proof.execute_sanitizer_fuzz_runtime(
            finding, source_snippet=PYTHON_SOURCE, project_root=tmp_path, confirm_local=False,
        )
    with pytest.raises(asan_project_proof.AsanProjectProofError, match="max_runs"):
        asan_project_proof.execute_sanitizer_fuzz_runtime(
            finding,
            source_snippet=PYTHON_SOURCE,
            project_root=tmp_path,
            confirm_local=True,
            max_runs=0,
        )
    with pytest.raises(asan_project_proof.AsanProjectProofError, match="timeout_seconds"):
        asan_project_proof.execute_sanitizer_fuzz_runtime(
            finding,
            source_snippet=PYTHON_SOURCE,
            project_root=tmp_path,
            confirm_local=True,
            timeout_seconds=31,
        )


def test_runtime_digest_pin_mismatch_fails_before_any_engine_execution(tmp_path: Path) -> None:
    finding = {"file": "src/parser.py", "reference": "CWE-20"}
    target = tmp_path / "src/parser.py"
    target.parent.mkdir()
    target.write_text(PYTHON_SOURCE, encoding="utf-8")
    module = tmp_path / "atheris.py"
    module.write_text("raise AssertionError('must never import')\n", encoding="utf-8")
    module.chmod(0o600)
    support_sha = hashlib.sha256(module.read_bytes()).hexdigest()

    with pytest.raises(asan_project_proof.AsanProjectProofError, match="SHA-256"):
        asan_project_proof.execute_sanitizer_fuzz_runtime(
            finding,
            source_snippet=PYTHON_SOURCE,
            project_root=tmp_path,
            confirm_local=True,
            runtime_path=os.path.realpath(sys.executable),
            runtime_sha256="0" * 64,
            support_path=module,
            support_sha256=support_sha,
        )


def test_generated_harnesses_publish_source_and_harness_digests_and_js_bounds() -> None:
    py = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "src/parser.py", "reference": "CWE-20"}, source_snippet=PYTHON_SOURCE,
    )
    js = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "src/parser.mjs", "reference": "CWE-20"}, source_snippet=JS_SOURCE,
    )

    for result, source in ((py, PYTHON_SOURCE), (js, JS_SOURCE)):
        assert result["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
        assert result["harness_sha256"] == hashlib.sha256(result["harness_code"].encode()).hexdigest()
        assert result["runtime_execution_supported"] is True
    assert "SNIPER_FUZZ_RUNS" in js["harness_code"]
    assert "SNIPER_FUZZ_SEED" in js["harness_code"]
    assert "SNIPER_FUZZ_MAX_INPUT_BYTES" in js["harness_code"]
    assert "numRuns" in js["harness_code"]
    assert "maxLength" in js["harness_code"]


def test_real_sandbox_runner_enforces_wall_clock_and_output_edges(tmp_path: Path) -> None:
    runtime_path = os.path.realpath(sys.executable)
    try:
        timed = fuzz_runtime._run_stage(
            tmp_path,
            "deadline",
            [],
            [runtime_path, "-c", "import time; time.sleep(5)"],
            (),
            timeout=1,
            output_bytes=4096,
        )
    except fuzz_runtime._RuntimeUnavailable as exc:
        pytest.skip(f"networkless sandbox unavailable on this runner: {exc}")
    assert timed == (-9, "", False, True)

    try:
        capped = fuzz_runtime._run_stage(
            tmp_path,
            "output-cap",
            [],
            [runtime_path, "-c", "import sys; sys.stdout.write('x' * 100000); sys.stdout.flush()"],
            (),
            timeout=2,
            output_bytes=4096,
        )
    except fuzz_runtime._RuntimeUnavailable as exc:
        pytest.skip(f"networkless sandbox unavailable on this runner: {exc}")
    assert len(capped[1].encode()) <= 4096
    assert capped[2] is True
    assert capped[3] is False


def test_pinned_runtime_inode_is_the_one_executed_in_networkless_sandbox(tmp_path: Path) -> None:
    runtime_path = os.path.realpath(sys.executable)
    runtime_sha = file_sha256(runtime_path, "Python")
    with open_verified_executable(runtime_path, {runtime_sha: "test"}, label="Python") as runtime:
        binds, command = fuzz_runtime._safe_runtime_root(None, runtime, "/runtime")
        try:
            completed = fuzz_runtime._run_stage(
                tmp_path,
                "pinned-runtime",
                binds,
                [command, "-c", "print('SNIPER_PINNED_RUNTIME_OK')"],
                (runtime.fd,),
                timeout=2,
                output_bytes=4096,
            )
        except fuzz_runtime._RuntimeUnavailable as exc:
            pytest.skip(f"networkless sandbox unavailable on this runner: {exc}")
    assert completed == (0, "SNIPER_PINNED_RUNTIME_OK\n", False, False)
