"""Executable JavaScript/TypeScript fast-check harness synthesis (P2.2d)."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest

import asan_project_proof


NODE = shutil.which("node")

JS_SOURCE = r'''
// export function decodeCommentDecoy(input) {}
const stringDecoy = "export function normalizeStringDecoy(input) {}";
const templateDecoy = `export function parseTemplateDecoy(input) {}`;

/** @param {Buffer} input */
export function parseFrame(input) {
  if (input.length === 0) return null;
  return input[0];
}
'''

TS_SOURCE = r'''
const decoy = `export function parseTemplateDecoy(input: string) {}`;

export function decodePacket(input: Uint8Array): number {
  return input.length;
}
'''


def _synthesize(file_path: str, source: str) -> dict:
    return asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": file_path, "reference": "CWE-20"},
        source_snippet=source,
    )


def _materialize_and_check(result: dict, source: str) -> subprocess.CompletedProcess[str]:
    assert NODE is not None
    with tempfile.TemporaryDirectory() as raw_project:
        project = Path(raw_project)
        target = project / result["target_file"]
        target.parent.mkdir(parents=True)
        target.write_text(source, encoding="utf-8")
        harness = project / result["harness_filename"]
        harness.write_text(result["harness_code"], encoding="utf-8")

        parsed = subprocess.run(
            [NODE, "--check", str(harness)],
            cwd=project,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert parsed.returncode == 0, parsed.stderr
        if result["language"] == "javascript":
            parsed_target = subprocess.run(
                [NODE, "--check", str(target)],
                cwd=project,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            assert parsed_target.returncode == 0, parsed_target.stderr
        return subprocess.run(
            [NODE, str(harness), "--check-target"],
            cwd=project,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )


@pytest.mark.skipif(NODE is None, reason="Node runtime required for real generated-harness validation")
def test_exported_js_parser_ignores_decoys_and_generated_harness_imports_target() -> None:
    result = _synthesize("src/frame_parser.mjs", JS_SOURCE)

    assert result["format"] == "sniper-sanitizer-fuzz-harness/1"
    assert result["language"] == "javascript"
    assert result["fuzz_engine"] == "fast-check"
    assert result["target_symbol"] == "parseFrame"
    assert result["target_input"] == "buffer"
    assert result["runtime_available"] is False
    assert result["harness_filename"] == "fuzz_parseFrame.mjs"

    checked = _materialize_and_check(result, JS_SOURCE)
    assert checked.returncode == 0, checked.stderr
    assert checked.stdout.strip() == "SNIPER_JS_FUZZ_TARGET_OK parseFrame buffer"


@pytest.mark.skipif(NODE is None, reason="Node runtime required for real generated-harness validation")
def test_exported_typescript_uint8array_target_is_parsed_and_imported_by_node() -> None:
    result = _synthesize("src/packet_decoder.ts", TS_SOURCE)
    assert result["language"] == "typescript"
    assert result["target_symbol"] == "decodePacket"
    assert result["target_input"] == "uint8array"

    checked = _materialize_and_check(result, TS_SOURCE)
    assert checked.returncode == 0, checked.stderr
    assert checked.stdout.strip() == "SNIPER_JS_FUZZ_TARGET_OK decodePacket uint8array"


@pytest.mark.skipif(NODE is None, reason="Node runtime required for real generated-harness validation")
def test_missing_fast_check_runtime_fails_closed() -> None:
    result = _synthesize("src/frame_parser.mjs", JS_SOURCE)
    if result["runtime_available"]:
        pytest.skip("fast-check is installed; missing-runtime branch is not applicable")

    with tempfile.TemporaryDirectory() as raw_project:
        project = Path(raw_project)
        target = project / result["target_file"]
        target.parent.mkdir(parents=True)
        target.write_text(JS_SOURCE, encoding="utf-8")
        harness = project / result["harness_filename"]
        harness.write_text(result["harness_code"], encoding="utf-8")
        checked = subprocess.run(
            [NODE, str(harness), "--check-runtime"],
            cwd=project,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    assert checked.returncode == 2
    assert checked.stdout == ""
    assert checked.stderr.strip() == "fast-check runtime unavailable; install the declared requirement before fuzzing."
    assert "Error [ERR_MODULE_NOT_FOUND]" not in checked.stderr


def test_overload_multiple_parameters_and_dynamic_export_are_rejected() -> None:
    overload = '''
export function parseValue(input: string): object;
export function parseValue(input: Uint8Array): object;
export function parseValue(input: string | Uint8Array): object { return {}; }
'''
    with pytest.raises(asan_project_proof.AsanProjectProofError, match="tam olarak bir"):
        _synthesize("src/parser.ts", overload)

    multiple_parameters = '''
/** @param {Buffer} input */
export function parseFrame(input, options) { return input; }
'''
    with pytest.raises(asan_project_proof.AsanProjectProofError, match="tam olarak bir"):
        _synthesize("src/parser.mjs", multiple_parameters)

    dynamic_export = '''
/** @param {Buffer} input */
function parseFrame(input) { return input; }
const targetName = "parseFrame";
module.exports[targetName] = parseFrame;
'''
    with pytest.raises(asan_project_proof.AsanProjectProofError, match="tam olarak bir"):
        _synthesize("src/parser.js", dynamic_export)
