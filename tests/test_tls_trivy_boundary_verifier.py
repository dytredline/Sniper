import json
import unittest

from tls_trivy_boundary_verifier import (
    verify_tls_workflow_boundary,
    verify_trivy_offline_db_freshness,
)


class TlsTrivyBoundaryVerifierTests(unittest.TestCase):
    def test_ssllabs_saved_report_passes_and_rejects_live_target(self):
        saved_report = json.dumps({
            "status": "READY",
            "endpoints": [
                {"grade": "A+"},
                {"grade": "A"},
            ],
        })
        result = verify_tls_workflow_boundary(
            "ssllabs-saved-report",
            report_json=saved_report,
        )
        self.assertEqual(result["execution_policy"], "offline_saved_report_only")
        self.assertEqual(result["format"], "ssllabs-v4-host")
        self.assertEqual(result["assessment_status"], "READY")
        self.assertEqual(result["endpoint_count"], 2)
        self.assertEqual(result["grade_counts"]["A+"], 1)
        self.assertEqual(result["grade_counts"]["A"], 1)
        self.assertFalse(result["live_query_allowed"])

        for live_target in ("https://example.com", "example.com", "127.0.0.1:443", ""):
            with self.subTest(live_target=live_target):
                with self.assertRaisesRegex(ValueError, "SSL Labs canlı sorguları devre dışı"):
                    verify_tls_workflow_boundary(
                        "ssllabs-saved-report",
                        target=live_target,
                        report_json=saved_report,
                    )

        for bad_report in (None, "", "   ", "{bad", json.dumps({"status": "UNKNOWN", "endpoints": []})):
            with self.subTest(bad_report=bad_report):
                with self.assertRaises(ValueError):
                    verify_tls_workflow_boundary("ssllabs-saved-report", report_json=bad_report)

    def test_testssl_loopback_allows_127_0_0_1_port_and_rejects_external_targets(self):
        result = verify_tls_workflow_boundary(
            "testssl-loopback",
            target="127.0.0.1:8443",
        )
        self.assertEqual(result["execution_policy"], "loopback_only")
        self.assertEqual(result["approved_port"], 8443)
        self.assertEqual(result["approved_host"], "127.0.0.1")
        self.assertFalse(result["external_https_allowed"])

        for external_target in (
            "https://example.com",
            "https://127.0.0.1:8443",
            "192.0.2.1:443",
            "localhost:8443",
            "[::1]:8443",
            "0.0.0.0:443",
            "",
            None,
        ):
            with self.subTest(external_target=external_target):
                with self.assertRaisesRegex(
                    ValueError,
                    "Harici HTTPS hedefleri testssl loopback kapsamı dışında",
                ):
                    verify_tls_workflow_boundary("testssl-loopback", target=external_target)

        for bad_loopback in (
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "127.0.0.1:0443",
            "127.0.0.1:-443",
            "127.0.0.1:8443/path",
        ):
            with self.subTest(bad_loopback=bad_loopback):
                with self.assertRaises(ValueError):
                    verify_tls_workflow_boundary("testssl-loopback", target=bad_loopback)

    def test_trivy_offline_db_freshness_evaluates_fresh_and_stale_and_fails_closed(self):
        metadata_json = json.dumps({
            "Version": 2,
            "UpdatedAt": "2026-10-15T12:00:00.123456789Z",
            "NextUpdate": "2026-10-16T00:00:00Z",
        })

        fresh = verify_trivy_offline_db_freshness(
            metadata_json,
            reference_utc="2026-10-17T18:00:00Z",
            max_age_hours=168,
        )
        self.assertEqual(fresh["format"], "trivy-db-freshness-v1")
        self.assertEqual(fresh["schema_version"], 2)
        self.assertEqual(fresh["age_hours"], 54.0)
        self.assertTrue(fresh["is_fresh"])
        self.assertEqual(fresh["max_age_hours"], 168)
        self.assertEqual(fresh["freshness_state"], "fresh")

        stale = verify_trivy_offline_db_freshness(
            metadata_json,
            reference_utc="2026-10-25T12:00:00Z",
            max_age_hours=168,
        )
        self.assertEqual(stale["format"], "trivy-db-freshness-v1")
        self.assertEqual(stale["schema_version"], 2)
        self.assertEqual(stale["age_hours"], 240.0)
        self.assertFalse(stale["is_fresh"])
        self.assertEqual(stale["freshness_state"], "stale_offline_db")

        for bad_max_age in (0, -1, -168, True, False, "168", None, 900000):
            with self.subTest(bad_max_age=bad_max_age):
                with self.assertRaises(ValueError):
                    verify_trivy_offline_db_freshness(
                        metadata_json,
                        reference_utc="2026-10-17T18:00:00Z",
                        max_age_hours=bad_max_age,
                    )

        for bad_ref in (
            "",
            "2026-10-17 18:00:00",
            "2026-10-17T18:00:00+03:00",
            "2026-10-14T00:00:00Z",
            "not-a-timestamp",
        ):
            with self.subTest(bad_ref=bad_ref):
                with self.assertRaises(ValueError):
                    verify_trivy_offline_db_freshness(metadata_json, reference_utc=bad_ref)

        for bad_meta in (
            "",
            "{invalid",
            json.dumps({"Version": 0, "UpdatedAt": "2026-10-15T12:00:00Z", "NextUpdate": "2026-10-16T00:00:00Z"}),
            json.dumps({"Version": True, "UpdatedAt": "2026-10-15T12:00:00Z", "NextUpdate": "2026-10-16T00:00:00Z"}),
            json.dumps({"Version": 2, "UpdatedAt": "2026-10-16T12:00:00Z", "NextUpdate": "2026-10-15T00:00:00Z"}),
            json.dumps({"Version": 2, "UpdatedAt": "bad", "NextUpdate": "2026-10-16T00:00:00Z"}),
        ):
            with self.subTest(bad_meta=bad_meta):
                with self.assertRaises(ValueError):
                    verify_trivy_offline_db_freshness(
                        bad_meta,
                        reference_utc="2026-10-17T18:00:00Z",
                    )


if __name__ == "__main__":
    unittest.main()
