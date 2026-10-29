from __future__ import annotations

import json
from pathlib import Path

import ground_truth_review
from scripts import eval_pipeline


def _spec(tmp_path: Path, *, require_review: bool) -> dict:
    root = tmp_path / "corpus"
    project = root / "sample"
    project.mkdir(parents=True)
    (project / "app.py").write_text(
        "import os\n"
        "def run(user_input):\n"
        "    os.system(user_input)\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "review-manifest.json"
    ground_truth = tmp_path / "ground-truth.json"
    ground_truth_review.prepare_bundle(
        root,
        ["sample"],
        manifest,
        ground_truth,
        source_profiles=["python"],
    )
    raw = json.loads(ground_truth.read_text(encoding="utf-8"))
    raw["projects"]["sample"] = [{
        "file": "app.py",
        "lines": [3, 3],
        "class": "cmd",
        "kind": "direct",
    }]
    raw["meta"]["blinded_review"] = {
        "prepared_before_analysis": True,
        "independent_of_engine_output": True,
        "reviewer": "release-gate-test",
        "reviewed_at": "2026-10-27T00:00:00Z",
        "source_manifest_sha256": ground_truth_review.file_sha256(manifest),
    }
    ground_truth.write_text(json.dumps(raw), encoding="utf-8")
    return {
        "name": "release-gate",
        "kind": "vulnerable",
        "root": root,
        "projects": ["sample"],
        "ground_truth": ground_truth,
        "review_manifest": manifest,
        "require_blinded_ground_truth": require_review,
        "baseline": None,
        "codeql_sarif_dir": None,
    }


def test_run_set_serializes_verified_review_contract(tmp_path: Path) -> None:
    result = eval_pipeline.run_set(_spec(tmp_path, require_review=True), lambda _message: None)

    assert result["ground_truth_review"]["project_count"] == 1
    assert result["ground_truth_review"]["label_count"] == 1
    assert result["ground_truth_review"]["classes"] == {"cmd": 1}


def test_run_set_omits_review_contract_when_not_required(tmp_path: Path) -> None:
    result = eval_pipeline.run_set(_spec(tmp_path, require_review=False), lambda _message: None)

    assert "ground_truth_review" not in result
