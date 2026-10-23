import json
import unittest

from nuclei_verification_summary import build_nuclei_verification_coverage_summary


class NucleiVerificationSummaryTests(unittest.TestCase):
    def test_valid_jsonl_marks_findings_unverified_and_computes_template_coverage(self):
        lines = [
            json.dumps(
                {
                    "template-id": "http/misconfiguration/exposed-panel",
                    "type": "http",
                    "info": {"name": "Exposed Panel", "severity": "medium"},
                }
            ),
            json.dumps(
                {
                    "template-id": "ssl/deprecated-tls",
                    "type": "ssl",
                    "info": {"name": "Deprecated TLS", "severity": "low"},
                }
            ),
        ]
        raw_jsonl = "\n".join(lines) + "\n"
        executed = [
            "http/misconfiguration/exposed-panel",
            "ssl/deprecated-tls",
            "http/exposures/git-config",
        ]

        summary = build_nuclei_verification_coverage_summary(
            raw_jsonl,
            executed_template_ids=executed,
        )

        self.assertEqual(summary["finding_count"], 2)
        self.assertEqual(summary["unverified_finding_count"], 2)
        self.assertEqual(
            summary["matched_template_ids"],
            ["http/misconfiguration/exposed-panel", "ssl/deprecated-tls"],
        )
        self.assertEqual(summary["executed_template_count"], 3)
        self.assertEqual(summary["unmatched_executed_template_count"], 1)
        self.assertEqual(summary["coverage_scope"], "bounded_template_subset_only")
        self.assertEqual(len(summary["summary_sha256"]), 64)
        for finding in summary["findings"]:
            self.assertEqual(
                finding["verification_state"],
                "independent_confirmation_required",
            )

    def test_zero_findings_control_proves_bounded_template_subset_only(self):
        summary = build_nuclei_verification_coverage_summary(
            "",
            executed_template_ids=["http/misconfiguration/test-header"],
        )
        self.assertEqual(summary["finding_count"], 0)
        self.assertEqual(summary["unverified_finding_count"], 0)
        self.assertEqual(summary["matched_template_ids"], [])
        self.assertEqual(summary["executed_template_count"], 1)
        self.assertEqual(summary["unmatched_executed_template_count"], 1)
        self.assertEqual(summary["coverage_scope"], "bounded_template_subset_only")
        self.assertEqual(len(summary["summary_sha256"]), 64)

    def test_rejects_malformed_jsonl_invalid_template_ids_and_oversized_input(self):
        with self.assertRaises(ValueError):
            build_nuclei_verification_coverage_summary("{not-valid-json}\n")

        with self.assertRaises(ValueError):
            build_nuclei_verification_coverage_summary("[]\n")

        valid_line = json.dumps(
            {
                "template-id": "http/misconfiguration/test-header",
                "type": "http",
                "info": {"severity": "info"},
            }
        )

        for bad_tid in (
            "http/../secret-template",
            "template..traversal",
            "HTTP/Uppercase-Template",
            "http/with space/test",
            "-leading-dash",
            "trailing/slash/",
            "double//slash",
            "",
            "a" * 129,
        ):
            with self.subTest(bad_tid=bad_tid):
                with self.assertRaises(ValueError):
                    build_nuclei_verification_coverage_summary(
                        valid_line,
                        executed_template_ids=[bad_tid],
                    )
                bad_record = json.dumps(
                    {
                        "template-id": bad_tid,
                        "type": "http",
                        "info": {"severity": "info"},
                    }
                )
                with self.assertRaises(ValueError):
                    build_nuclei_verification_coverage_summary(bad_record)

        with self.assertRaises(ValueError):
            build_nuclei_verification_coverage_summary(
                valid_line,
                executed_template_ids="not-a-list",  # type: ignore[arg-type]
            )

        oversized = "a" * (256 * 1024 + 1)
        with self.assertRaises(ValueError):
            build_nuclei_verification_coverage_summary(oversized)


if __name__ == "__main__":
    unittest.main()
