from __future__ import annotations

import json
import unittest

from dependency_remediation_plan import (
    ACTION_NO_PATCH,
    ACTION_PATCH_AVAILABLE,
    NETWORK_SYNC_POLICY,
    PLAN_FORMAT,
    build_readonly_dependency_remediation_plan,
)


class DependencyRemediationPlanTests(unittest.TestCase):
    def test_combined_npm_audit_and_dependabot_deduplication_and_sorting(self) -> None:
        npm_report = {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "moderate",
                    "fixAvailable": False,
                    "title": "SECRET_ADVISORY_TEXT_MUST_NOT_LEAK",
                },
                "minimist": {
                    "name": "minimist",
                    "severity": "low",
                    "fixAvailable": {
                        "name": "minimist",
                        "version": "1.2.8",
                        "isSemVerMajor": False,
                    },
                },
                "semver": {
                    "name": "semver",
                    "severity": "high",
                    "fixAvailable": False,
                },
            },
        }
        dependabot_report = {
            "alerts": [
                {
                    "state": "open",
                    "security_advisory": {
                        "severity": "critical",
                        "summary": "DEPENDABOT_SECRET_SUMMARY_DO_NOT_ECHO",
                    },
                    "dependency": {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "manifest_path": "/home/community-user/project/package-lock.json",
                    },
                    "security_vulnerability": {
                        "first_patched_version": {"identifier": "4.17.21"}
                    },
                },
                {
                    "state": "open",
                    "security_advisory": {"severity": "high"},
                    "dependency": {
                        "package": {"ecosystem": "pip", "name": "urllib3"},
                    },
                    "security_vulnerability": {
                        "first_patched_version": {"identifier": "2.0.7"}
                    },
                },
                {
                    "state": "fixed",
                    "security_advisory": {"severity": "critical"},
                    "dependency": {
                        "package": {"ecosystem": "npm", "name": "already-fixed-pkg"},
                    },
                    "security_vulnerability": {
                        "first_patched_version": {"identifier": "1.0.1"}
                    },
                },
            ]
        }

        plan = build_readonly_dependency_remediation_plan(
            npm_audit_raw=json.dumps(npm_report),
            dependabot_raw=json.dumps(dependabot_report),
        )

        self.assertEqual(plan["format"], PLAN_FORMAT)
        self.assertIs(plan["mutates_lockfile"], False)
        self.assertEqual(plan["network_sync"], NETWORK_SYNC_POLICY)
        self.assertEqual(plan["total_advisories"], 5)
        self.assertEqual(
            plan["severity_totals"],
            {
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1,
                "info": 0,
            },
        )

        actions = plan["package_actions"]
        self.assertEqual(
            actions,
            [
                {
                    "ecosystem": "npm",
                    "package": "lodash",
                    "max_severity": "critical",
                    "fixed_version_available": True,
                    "recommended_action": ACTION_PATCH_AVAILABLE,
                },
                {
                    "ecosystem": "npm",
                    "package": "semver",
                    "max_severity": "high",
                    "fixed_version_available": False,
                    "recommended_action": ACTION_NO_PATCH,
                },
                {
                    "ecosystem": "pip",
                    "package": "urllib3",
                    "max_severity": "high",
                    "fixed_version_available": True,
                    "recommended_action": ACTION_PATCH_AVAILABLE,
                },
                {
                    "ecosystem": "npm",
                    "package": "minimist",
                    "max_severity": "low",
                    "fixed_version_available": True,
                    "recommended_action": ACTION_PATCH_AVAILABLE,
                },
            ],
        )

        plan_sha = plan["plan_sha256"]
        self.assertIsInstance(plan_sha, str)
        self.assertEqual(len(plan_sha), 64)

        serialized = json.dumps(plan)
        self.assertNotIn("SECRET_ADVISORY_TEXT_MUST_NOT_LEAK", serialized)
        self.assertNotIn("DEPENDABOT_SECRET_SUMMARY_DO_NOT_ECHO", serialized)
        self.assertNotIn("/home/", serialized)
        self.assertNotIn("already-fixed-pkg", serialized)

    def test_single_source_npm_audit_only(self) -> None:
        npm_report = {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "@babel/traverse": {
                    "severity": "critical",
                    "fixAvailable": True,
                },
                "postcss": {
                    "severity": "info",
                    "fixAvailable": False,
                },
            },
        }
        plan = build_readonly_dependency_remediation_plan(
            npm_audit_raw=json.dumps(npm_report)
        )
        self.assertEqual(plan["total_advisories"], 2)
        self.assertEqual(
            plan["severity_totals"],
            {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 1},
        )
        self.assertEqual(
            plan["package_actions"],
            [
                {
                    "ecosystem": "npm",
                    "package": "@babel/traverse",
                    "max_severity": "critical",
                    "fixed_version_available": True,
                    "recommended_action": ACTION_PATCH_AVAILABLE,
                },
                {
                    "ecosystem": "npm",
                    "package": "postcss",
                    "max_severity": "info",
                    "fixed_version_available": False,
                    "recommended_action": ACTION_NO_PATCH,
                },
            ],
        )

    def test_single_source_dependabot_only_and_deterministic_hash(self) -> None:
        dep_report_a = {
            "alerts": [
                {
                    "state": "open",
                    "security_advisory": {"severity": "medium"},
                    "dependency": {"package": {"name": "express"}},
                    "security_vulnerability": {"first_patched_version": {"identifier": "   "}},
                },
                {
                    "state": "open",
                    "security_advisory": {"severity": "high"},
                    "dependency": {"package": {"name": "express"}},
                    "security_vulnerability": {"first_patched_version": {"identifier": "4.19.2"}},
                },
                {
                    "state": "dismissed",
                    "security_advisory": {"severity": "critical"},
                    "dependency": {"package": {"name": "ignored-pkg"}},
                },
            ]
        }
        dep_report_b = {"alerts": list(reversed(dep_report_a["alerts"]))}

        plan_a = build_readonly_dependency_remediation_plan(
            dependabot_raw=json.dumps(dep_report_a)
        )
        plan_b = build_readonly_dependency_remediation_plan(
            dependabot_raw=json.dumps(dep_report_b)
        )

        self.assertEqual(plan_a, plan_b)
        self.assertEqual(plan_a["total_advisories"], 2)
        self.assertEqual(
            plan_a["package_actions"],
            [
                {
                    "ecosystem": "npm",
                    "package": "express",
                    "max_severity": "high",
                    "fixed_version_available": True,
                    "recommended_action": ACTION_PATCH_AVAILABLE,
                }
            ],
        )

    def test_invalid_inputs_raise_value_error(self) -> None:
        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan()

        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan(npm_audit_raw="   ")

        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan(npm_audit_raw="{not-json")

        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan(dependabot_raw="[1, 2, 3]")

        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan(
                npm_audit_raw=json.dumps({"auditReportVersion": 1, "vulnerabilities": {}})
            )

        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan(
                npm_audit_raw=json.dumps({"auditReportVersion": True, "vulnerabilities": {}})
            )

        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan(
                npm_audit_raw=json.dumps(
                    {
                        "auditReportVersion": 2,
                        "vulnerabilities": {
                            "../evil": {"severity": "high"}
                        },
                    }
                )
            )

        with self.assertRaises(ValueError):
            build_readonly_dependency_remediation_plan(
                dependabot_raw=json.dumps(
                    {
                        "alerts": [
                            {
                                "state": "open",
                                "security_advisory": {"severity": "high"},
                            }
                        ]
                    }
                )
            )


if __name__ == "__main__":
    unittest.main()
