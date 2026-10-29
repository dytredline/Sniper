from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest

import asan_project_proof


GO_SOURCE = """package parser

import "errors"

func ParseFrame(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty")
	}
	return nil
}
"""


def test_go_native_fuzz_harness_compiles_with_real_go_toolchain() -> None:
    harness = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {
            "file": "internal/parser/frame.go",
            "function": "ParseFrame",
            "reference": "CWE-20",
            "title": "Frame decoder input validation",
        },
        source_snippet=GO_SOURCE,
    )

    assert harness == {
        "format": "sniper-sanitizer-fuzz-harness/1",
        "language": "go",
        "target_file": "internal/parser/frame.go",
        "target_function": "ParseFrame",
        "input_type": "[]byte",
        "cwe": "CWE-20",
        "compile_command": "go test -run=^$ ./...",
        "fuzz_command": "go test -run=^$ -fuzz=^FuzzParseFrame$ -fuzztime=60s ./...",
        "harness_filename": "frame_sniper_fuzz_test.go",
        "harness_code": harness["harness_code"],
        "network_required": False,
    }
    assert "package parser" in harness["harness_code"]
    assert "func FuzzParseFrame(f *testing.F)" in harness["harness_code"]
    assert "ParseFrame(data)" in harness["harness_code"]

    go = shutil.which("go")
    if go is None:
        pytest.skip("real Go toolchain is unavailable")
    with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
        root = Path(directory)
        (root / "go.mod").write_text("module example.invalid/sniperfixture\n\ngo 1.20\n", encoding="utf-8")
        (root / "frame.go").write_text(GO_SOURCE, encoding="utf-8")
        (root / harness["harness_filename"]).write_text(harness["harness_code"], encoding="utf-8")
        (root / ".gocache").mkdir()
        (root / ".gotmp").mkdir()
        env = {
            **os.environ, "GOPROXY": "off", "GOSUMDB": "off",
            "GOCACHE": str(root / ".gocache"), "GOTMPDIR": str(root / ".gotmp"),
        }
        completed = subprocess.run(
            [go, "test", "-run=^$", "./..."], cwd=root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30, check=False,
        )
        fuzzed = subprocess.run(
            [go, "test", "-run=^$", "-fuzz=^FuzzParseFrame$", "-fuzztime=1x", "./..."],
            cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=30, check=False,
        )
    assert completed.returncode == 0, completed.stdout
    assert fuzzed.returncode == 0, fuzzed.stdout
    assert "PASS" in fuzzed.stdout


def test_go_string_target_and_single_candidate_inference_are_deterministic() -> None:
    source = """package decode

func Normalize(value string) (string, error) { return value, nil }
"""
    harness = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "normalize.go", "reference": "CWE-180"}, source_snippet=source,
    )

    assert harness["target_function"] == "Normalize"
    assert harness["input_type"] == "string"
    assert 'f.Add("")' in harness["harness_code"]
    assert "Normalize(value)" in harness["harness_code"]


@pytest.mark.parametrize(
    ("finding", "source"),
    [
        ({"file": "parser.go", "function": "Parse; os.Exit(1)"}, GO_SOURCE),
        ({"file": "parser.go", "function": ""}, GO_SOURCE),
        ({"file": "parser.go", "function": None}, GO_SOURCE),
        ({"file": "parser.go", "function": "ParseFrame", "symbol": "Decode"}, GO_SOURCE),
        ({"file": "parser.go", "function": "Missing"}, GO_SOURCE),
        ({"file": "../parser.go", "function": "ParseFrame"}, GO_SOURCE),
        ({"file": "parser.go"}, "package parser\nfunc Parse(a []byte) {}\nfunc Decode(a []byte) {}\n"),
        ({"file": "parser.go", "function": "Parse"}, "package parser\nfunc Parse(a []byte, mode int) {}\n"),
        ({"file": "parser.go", "function": "Parse"}, "package parser\nfunc (p *P) Parse(a []byte) {}\n"),
        ({"file": "parser.go", "function": "Parse"}, "package parser\n/*\nfunc Parse(a []byte) {}\n*/\n"),
        ({"file": "parser.go", "function": "Parse"}, "package parser\nfunc Parse[T any](a []byte) {}\n"),
        ({"file": "parser.go", "function": "Parse"}, "package parser\n\x00func Parse(a []byte) {}\n"),
    ],
)
def test_go_harness_rejects_ambiguous_or_unsafe_targets(finding: dict, source: str) -> None:
    with pytest.raises(ValueError):
        asan_project_proof.synthesize_sanitizer_fuzz_harness(finding, source_snippet=source)


def test_existing_c_and_rust_harness_contracts_remain_stable() -> None:
    c_harness = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "parser.c", "reference": "CWE-787"}
    )
    rust_harness = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "codec.rs", "reference": "CWE-190"}
    )

    assert c_harness["language"] == "c_cpp"
    assert "LLVMFuzzerTestOneInput" in c_harness["harness_code"]
    assert rust_harness["language"] == "rust"
    assert "fuzz_target!" in rust_harness["harness_code"]


def test_go_harness_accepts_crlf_source_without_changing_generated_code() -> None:
    lf = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "frame.go", "function": "ParseFrame"}, source_snippet=GO_SOURCE,
    )
    crlf = asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {"file": "frame.go", "function": "ParseFrame"},
        source_snippet=GO_SOURCE.replace("\n", "\r\n"),
    )
    assert crlf == lf


def test_go_harness_scope_is_documented_without_execution_claims() -> None:
    root = Path(__file__).resolve().parents[1]
    capabilities = (root / "docs" / "CAPABILITIES.md").read_text(encoding="utf-8")
    guide = (root / "docs" / "KULLANIM-KILAVUZU.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert "Go için yerleşik `testing.F`" in capabilities
    assert "ürün bunları otomatik çalıştırmaz" in guide
    assert "execution remains an explicit operator step" in readme
