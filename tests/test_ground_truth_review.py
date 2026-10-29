from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import eval_metrics
import ground_truth_review as review
from scripts import eval_pipeline


APP = Path(__file__).resolve().parents[1]
REFERENCE_DOCS = APP / "docs" / "olcum"


class GroundTruthReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "corpus"
        self.project = self.root / "c-one"
        self.project.mkdir(parents=True)
        self.source = self.project / "uaf.c"
        self.source.write_text("#include <stdlib.h>\nint main(void) {\n int *p = malloc(4);\n free(p);\n return *p;\n}\n")
        self.manifest = self.base / "review-manifest.json"
        self.gt = self.base / "ground-truth.json"

    def prepare(self) -> tuple[dict, dict]:
        return review.prepare_bundle(self.root, ["c-one"], self.manifest, self.gt)

    def attest(self, *, lines=(5, 5)) -> None:
        raw = json.loads(self.gt.read_text())
        raw["projects"]["c-one"] = [{"file": "uaf.c", "lines": list(lines), "class": "mem",
                                       "kind": "direct", "note": "free sonrası okuma"}]
        raw["meta"]["blinded_review"] = {
            "prepared_before_analysis": True,
            "independent_of_engine_output": True,
            "reviewer": "human-reviewer",
            "reviewed_at": "2026-10-21T16:30:00Z",
            "source_manifest_sha256": review.file_sha256(self.manifest),
        }
        self.gt.write_text(json.dumps(raw))

    def test_prepare_has_only_source_inventory_then_attested_labels_validate(self) -> None:
        manifest, template = self.prepare()
        self.assertEqual(manifest["format"], review.MANIFEST_FORMAT)
        self.assertEqual(template["projects"], {"c-one": []})
        self.assertNotIn("findings", json.dumps(manifest))
        self.assertNotIn("sniper_output", json.dumps(template))
        self.attest()
        result = review.validate_bundle(self.root, self.manifest, self.gt, require_attestation=True)
        self.assertEqual(result["project_count"], 1)
        self.assertEqual(result["label_count"], 1)
        self.assertEqual(result["classes"], {"mem": 1})

    def test_changed_source_bad_line_and_missing_attestation_fail_closed(self) -> None:
        self.prepare()
        self.attest()
        self.source.write_text(self.source.read_text() + "/* changed */\n")
        with self.assertRaises(review.GroundTruthReviewError):
            review.validate_bundle(self.root, self.manifest, self.gt, require_attestation=True)

    def test_manifest_requires_a_machine_readable_utc_preparation_time(self) -> None:
        self.prepare()
        raw = json.loads(self.manifest.read_text())
        raw["prepared_at"] = "sonra"
        self.manifest.write_text(json.dumps(raw))
        self.attest()
        with self.assertRaisesRegex(review.GroundTruthReviewError, "hazırlama zamanı"):
            review.validate_bundle(self.root, self.manifest, self.gt, require_attestation=True)

        self.source.write_text("#include <stdlib.h>\nint main(void) {\n int *p = malloc(4);\n free(p);\n return *p;\n}\n")
        self.attest(lines=(99, 99))
        with self.assertRaises(review.GroundTruthReviewError):
            review.validate_bundle(self.root, self.manifest, self.gt, require_attestation=True)

        raw = json.loads(self.gt.read_text())
        raw["projects"]["c-one"][0]["lines"] = [5, 5]
        raw["meta"].pop("blinded_review")
        self.gt.write_text(json.dumps(raw))
        with self.assertRaises(review.GroundTruthReviewError):
            review.validate_bundle(self.root, self.manifest, self.gt, require_attestation=True)

    def test_eval_config_can_require_review_manifest_before_analysis(self) -> None:
        self.prepare()
        self.attest()
        config = self.base / "eval.json"
        config.write_text(json.dumps({"sets": [{
            "name": "c-set", "kind": "vulnerable", "root": str(self.root), "projects": ["c-one"],
            "ground_truth": str(self.gt), "review_manifest": str(self.manifest),
            "require_blinded_ground_truth": True,
        }]}))
        loaded = eval_pipeline.load_config(config)
        check = eval_pipeline.validate_ground_truth_contract(loaded["sets"][0])
        self.assertEqual(check["label_count"], 1)

    def test_multilanguage_source_manifest_is_explicit_and_stable(self) -> None:
        py_project = self.root / "python-one"
        py_project.mkdir()
        (py_project / "app.py").write_text("print('ok')\n")
        (py_project / "ignored.c").write_text("int main(void) { return 0; }\n")
        manifest = review.source_manifest(self.root, ["python-one"], source_profiles=["python"])
        self.assertEqual(manifest["format"], review.MANIFEST_FORMAT)
        self.assertEqual(manifest["source_profiles"], ["python"])
        self.assertEqual([row["file"] for row in manifest["projects"]["python-one"]], ["app.py"])

        self.manifest.write_text(json.dumps(manifest))
        self.gt.write_text(json.dumps({
            "format": eval_metrics.GT_FORMAT,
            "meta": {"blinded_review": {
                "prepared_before_analysis": True,
                "independent_of_engine_output": True,
                "reviewer": "human-reviewer",
                "reviewed_at": "2026-10-21T16:30:00Z",
                "source_manifest_sha256": review.file_sha256(self.manifest),
            }},
            "projects": {"python-one": [{"file": "app.py", "lines": [1, 1], "class": "cmd"}]},
            "adjudicated": {},
        }))
        checked = review.validate_bundle(self.root, self.manifest, self.gt)
        self.assertEqual(checked["source_profiles"], ["python"])

    def test_unknown_or_empty_source_profile_fails_closed(self) -> None:
        with self.assertRaises(review.GroundTruthReviewError):
            review.source_manifest(self.root, ["c-one"], source_profiles=[])
        with self.assertRaises(review.GroundTruthReviewError):
            review.source_manifest(self.root, ["c-one"], source_profiles=["shell"])

    @unittest.skipUnless(REFERENCE_DOCS.is_dir(), "maintainer reference bundles are not distributed")
    def test_installed_reference_bundle_is_valid_and_scores_without_execution(self) -> None:
        root = APP / "tests" / "fixtures" / "c-reference-set1"
        manifest = APP / "docs" / "olcum" / "c-reference-set1.manifest.json"
        gt_path = APP / "docs" / "olcum" / "c-reference-set1.ground-truth.json"
        checked = review.validate_bundle(root, manifest, gt_path, require_attestation=True)
        self.assertEqual(checked["label_count"], 2)
        gt = eval_metrics.load_ground_truth(gt_path)
        self.assertEqual({item["class"] for item in gt["projects"]["sniper-c-memory-reference"]}, {"mem", "fmt"})


if __name__ == "__main__":
    unittest.main()

class SyntheticLanguageReferenceTests(unittest.TestCase):
    @unittest.skipUnless(REFERENCE_DOCS.is_dir(), "maintainer reference bundles are not distributed")
    def test_python_and_javascript_contract_sets_validate_without_human_claim(self):
        app = Path(__file__).resolve().parents[1]
        for name, profile in (("python-reference-set1", "python"),
                              ("javascript-reference-set1", "javascript_typescript")):
            result = review.validate_bundle(
                app / "tests" / "fixtures" / name,
                app / "docs" / "olcum" / f"{name}.manifest.json",
                app / "docs" / "olcum" / f"{name}.ground-truth.json",
                require_attestation=False,
            )
            self.assertEqual(result["source_profiles"], [profile])
            self.assertEqual(result["project_count"], 1)
            self.assertEqual(result["label_count"], 1)
            ground_truth = json.loads((app / "docs" / "olcum" / f"{name}.ground-truth.json").read_text())
            self.assertFalse(ground_truth["meta"]["independent_human_review"])
