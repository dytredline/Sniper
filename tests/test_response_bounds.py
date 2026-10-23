import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from business_logic_auditor import audit_business_logic_inline  # noqa: E402
from crypto_cbom_pqc_auditor import audit_crypto_pqc_inline  # noqa: E402
from database_rls_schema_auditor import audit_database_schema_inline  # noqa: E402
from finding_limits import INLINE_FINDING_LIMIT  # noqa: E402
from web3_iot_firmware_auditor import audit_iot_firmware_inline, audit_smart_contract_inline  # noqa: E402

MAX_RESPONSE_BYTES = 1_000_000


class ResponseBoundTests(unittest.TestCase):
    """Large hostile inputs must stay fast and produce bounded JSON responses."""

    def _assert_bounded(self, func, unit: str, filename: str) -> dict:
        content = unit * (250_000 // len(unit))
        started = time.monotonic()
        result = func(content, filename=filename)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertLessEqual(len(result["findings"]), INLINE_FINDING_LIMIT)
        self.assertGreater(result["finding_count"], INLINE_FINDING_LIMIT)
        self.assertTrue(result["findings_truncated"])
        self.assertLess(len(json.dumps(result, default=str)), MAX_RESPONSE_BYTES)
        return result

    def test_previous_wave_auditors_cap_findings(self):
        self._assert_bounded(audit_business_logic_inline, "def w(u, amount):\n    u.balance -= float(amount)\n", "wallet.py")
        self._assert_bounded(
            audit_database_schema_inline,
            "CREATE TABLE t (tenant_id UUID, ssn TEXT);\nGRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO PUBLIC;\n",
            "schema.sql",
        )
        self._assert_bounded(audit_iot_firmware_inline, "gets(buf);\nstrcpy(a, b);\n", "fw.c")
        self._assert_bounded(audit_smart_contract_inline, "require(tx.origin == owner);\n", "Vault.sol")
        crypto = self._assert_bounded(audit_crypto_pqc_inline, "import hashlib\nhashlib.md5(x)\n", "c.py")
        components = crypto["cyclonedx_cbom"]["components"]
        self.assertEqual(len(components), len({c["name"] for c in components}))
        self.assertLessEqual(max(len(c["evidence"]["occurrences"]) for c in components), 50)

    def test_flooded_rule_does_not_hide_other_issue_types(self):
        content = "strcpy(a, b);\n" * 2000 + "allow_anonymous true\n"
        result = audit_iot_firmware_inline(content, filename="fw.c")
        self.assertTrue(result["findings_truncated"])
        returned_titles = {f["title"] for f in result["findings"]}
        group_titles = {g["title"] for g in result["finding_groups"]}
        self.assertEqual(returned_titles, group_titles)
        self.assertEqual(sum(g["count"] for g in result["finding_groups"]), result["finding_count"])

    def test_small_inputs_are_not_truncated(self):
        result = audit_business_logic_inline("def w(u, amount):\n    u.balance -= float(amount)\n", filename="w.py")
        self.assertFalse(result["findings_truncated"])
        self.assertEqual(len(result["findings"]), result["finding_count"])


class RlsExactTableMatchTests(unittest.TestCase):
    def test_rls_on_other_table_with_similar_name_does_not_cover_table(self):
        schema = (
            "CREATE TABLE t (id INT, tenant_id UUID);\n"
            "CREATE TABLE tenants (id INT, tenant_id UUID);\n"
            "ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;\n"
        )
        result = audit_database_schema_inline(schema, filename="schema.sql")
        rls = [f for f in result["findings"] if f["control_id"] == "SNIPER-AUTHZ-04"]
        self.assertEqual(len(rls), 1)
        self.assertIn("'t'", rls[0]["title"])

    def test_schema_qualified_and_policy_coverage(self):
        schema = (
            "CREATE TABLE app.orders (id INT, tenant_id UUID);\n"
            "CREATE TABLE invoices (id INT, org_id UUID);\n"
            "ALTER TABLE ONLY app.orders ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY tenant_isolation ON invoices USING (org_id = current_setting('app.org')::uuid);\n"
        )
        result = audit_database_schema_inline(schema, filename="schema.sql")
        self.assertFalse([f for f in result["findings"] if f["control_id"] == "SNIPER-AUTHZ-04"])


if __name__ == "__main__":
    unittest.main()
