"""Public SARIF summary behavior; no scanner or live service is used."""

import json
import unittest

from tool_report_sarif import parse_sarif_summary


class EffectiveSarifSeverityTests(unittest.TestCase):
    def summary(self, results, *, rules=None, invocations=None, extensions=None):
        driver = {"name": "Semgrep"}
        if rules is not None:
            driver["rules"] = rules
        tool = {"driver": driver}
        if extensions is not None:
            tool["extensions"] = extensions
        run = {"tool": tool, "results": results}
        if invocations is not None:
            run["invocations"] = invocations
        return parse_sarif_summary({"version": "2.1.0", "runs": [run]})

    def assert_counts(self, summary, **counts):
        expected = {name: counts.get(name, 0) for name in ("error", "warning", "note", "none")}
        self.assertEqual(summary["tools"][0]["levels"], expected)
        self.assertEqual(summary["result_count"], sum(expected.values()))

    def test_missing_kind_and_level_are_a_warning_not_none(self):
        summary = self.summary([{"message": {"text": "private finding"}}])
        self.assert_counts(summary, warning=1)
        self.assertNotIn("private finding", json.dumps(summary))

    def test_explicit_fail_without_level_is_a_warning(self):
        self.assert_counts(self.summary([{"kind": "fail"}]), warning=1)

    def test_rule_default_error_applies_without_explicit_rule_reference(self):
        rules = [{"id": "SEC001", "defaultConfiguration": {"level": "error"}}]
        self.assert_counts(self.summary([{"ruleId": "SEC001", "ruleIndex": 0}], rules=rules), error=1)

    def test_rule_default_note_applies_with_rule_reference(self):
        rules = [{"id": "SEC002", "defaultConfiguration": {"level": "note"}}]
        result = {"ruleId": "SEC002", "rule": {"index": 0}, "kind": "fail"}
        self.assert_counts(self.summary([result], rules=rules), note=1)

    def test_invocation_override_precedes_rule_default(self):
        rules = [{"id": "SEC003", "defaultConfiguration": {"level": "error"}}]
        invocations = [{"executionSuccessful": True, "ruleConfigurationOverrides": [
            {"descriptor": {"index": 0}, "configuration": {"level": "warning"}},
        ]}]
        result = {"ruleId": "SEC003", "ruleIndex": 0,
                  "provenance": {"invocationIndex": 0}, "kind": "fail"}
        self.assert_counts(self.summary([result], rules=rules, invocations=invocations), warning=1)

    def test_extension_rule_default_is_resolved(self):
        extensions = [{"name": "PolicyRules", "rules": [
            {"id": "EXT001", "defaultConfiguration": {"level": "note"}},
        ]}]
        result = {"rule": {"id": "EXT001", "index": 0,
                           "toolComponent": {"index": 0, "name": "PolicyRules"}}}
        self.assert_counts(self.summary([result], extensions=extensions), note=1)

    def test_extension_guid_reference_resolves_without_index(self):
        guid = "11111111-1111-4111-8111-111111111111"
        extensions = [{"name": "PolicyRules", "guid": guid, "rules": [
            {"id": "EXT002", "defaultConfiguration": {"level": "error"}},
        ]}]
        result = {"rule": {"id": "EXT002", "toolComponent": {"guid": guid}}}
        self.assert_counts(self.summary([result], extensions=extensions), error=1)

    def test_extension_name_alone_does_not_select_component(self):
        extensions = [{"name": "PolicyRules", "rules": [
            {"id": "EXT003", "defaultConfiguration": {"level": "error"}},
        ]}]
        result = {"rule": {"id": "EXT003", "toolComponent": {"name": "PolicyRules"}}}
        with self.assertRaises(ValueError):
            self.summary([result], extensions=extensions)

    def test_nonfail_without_level_stays_none_despite_rule_default(self):
        rules = [{"id": "SEC004", "defaultConfiguration": {"level": "error"}}]
        result = {"kind": "notApplicable", "ruleId": "SEC004", "ruleIndex": 0}
        self.assert_counts(self.summary([result], rules=rules), none=1)

    def test_explicit_result_level_takes_precedence(self):
        rules = [{"id": "SEC005", "defaultConfiguration": {"level": "note"}}]
        result = {"kind": "fail", "level": "error", "ruleId": "SEC005", "ruleIndex": 0}
        self.assert_counts(self.summary([result], rules=rules), error=1)

    def test_unknown_rule_descriptor_falls_back_to_warning(self):
        self.assert_counts(self.summary([{"kind": "fail", "ruleId": "unknown"}]), warning=1)

    def test_invalid_explicit_level_is_rejected(self):
        with self.assertRaises(ValueError):
            self.summary([{"kind": "fail", "level": "critical"}])

    def test_nonfail_with_error_level_is_rejected(self):
        with self.assertRaises(ValueError):
            self.summary([{"kind": "pass", "level": "error"}])

    def test_result_reference_fields_must_agree_with_selected_rule(self):
        a = "11111111-1111-4111-8111-111111111111"
        b = "22222222-2222-4222-8222-222222222222"
        rules = [{"id": "RULE_A", "guid": a, "defaultConfiguration": {"level": "error"}},
                 {"id": "RULE_B", "guid": b, "defaultConfiguration": {"level": "note"}}]
        invalid = [
            {"rule": {"index": 0, "id": "RULE_B"}},
            {"rule": {"index": 0, "guid": b}},
            {"ruleId": "RULE_B", "rule": {"index": 0}},
            {"ruleId": "RULE_A", "rule": {"index": 0, "id": "RULE_B"}},
            {"ruleIndex": 0, "rule": {"index": 1}},
            {"rule": {"id": "RULE_A", "guid": b}},
            {"rule": {"id": "RULE_A", "guid": "33333333-3333-4333-8333-333333333333"}},
        ]
        for result in invalid:
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.summary([result], rules=rules)

    def test_matching_result_index_guid_and_id_resolve_one_rule(self):
        guid = "11111111-1111-4111-8111-111111111111"
        rules = [{"id": "RULE_A", "guid": guid, "defaultConfiguration": {"level": "error"}}]
        result = {"ruleId": "RULE_A", "ruleIndex": 0,
                  "rule": {"id": "RULE_A", "index": 0, "guid": guid}}
        self.assert_counts(self.summary([result], rules=rules), error=1)

    def test_one_extra_hierarchical_rule_id_component_is_allowed(self):
        rules = [{"id": "RULE_A", "defaultConfiguration": {"level": "note"}}]
        result = {"ruleId": "RULE_A/subcase", "rule": {"index": 0}}
        self.assert_counts(self.summary([result], rules=rules), note=1)
        for bad_id in ("RULE_A/subcase/extra", "RULE_AB/subcase"):
            with self.subTest(bad_id=bad_id), self.assertRaises(ValueError):
                self.summary([{"ruleId": bad_id, "rule": {"index": 0}}], rules=rules)

    def test_override_reference_fields_must_agree_with_selected_rule(self):
        a = "11111111-1111-4111-8111-111111111111"
        b = "22222222-2222-4222-8222-222222222222"
        rules = [{"id": "RULE_A", "guid": a, "defaultConfiguration": {"level": "error"}},
                 {"id": "RULE_B", "guid": b, "defaultConfiguration": {"level": "note"}}]
        result = {"ruleId": "RULE_A", "ruleIndex": 0, "provenance": {"invocationIndex": 0}}
        invalid = [
            {"index": 0, "id": "RULE_B"},
            {"index": 0, "guid": b},
            {"id": "RULE_A", "guid": b},
            {"id": "RULE_A", "guid": "33333333-3333-4333-8333-333333333333"},
        ]
        for descriptor in invalid:
            invocations = [{"ruleConfigurationOverrides": [
                {"descriptor": descriptor, "configuration": {"level": "warning"}},
            ]}]
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                self.summary([result], rules=rules, invocations=invocations)

    def test_single_invocation_override_applies_without_invocation_index(self):
        rules = [{"id": "RULE_A", "defaultConfiguration": {"level": "error"}}]
        invocations = [{"ruleConfigurationOverrides": [
            {"descriptor": {"index": 0, "id": "RULE_A"},
             "configuration": {"level": "note"}},
        ]}]
        for result in ({"ruleId": "RULE_A", "ruleIndex": 0},
                       {"ruleId": "RULE_A", "ruleIndex": 0, "provenance": {}}):
            with self.subTest(result=result):
                self.assert_counts(self.summary([result], rules=rules,
                                                invocations=invocations), note=1)

    def test_multiple_invocations_without_index_use_rule_default(self):
        rules = [{"id": "RULE_A", "defaultConfiguration": {"level": "error"}}]
        invocations = [
            {"ruleConfigurationOverrides": [
                {"descriptor": {"index": 0}, "configuration": {"level": "note"}}]},
            {"ruleConfigurationOverrides": [
                {"descriptor": {"index": 0}, "configuration": {"level": "warning"}}]},
        ]
        self.assert_counts(self.summary([{"ruleId": "RULE_A", "ruleIndex": 0}],
                                        rules=rules, invocations=invocations), error=1)

    def test_explicit_invalid_invocation_index_is_not_a_default(self):
        rules = [{"id": "RULE_A", "defaultConfiguration": {"level": "error"}}]
        invocations = [{}]
        for index in (-1, 1, True):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.summary([{"ruleId": "RULE_A", "ruleIndex": 0,
                               "provenance": {"invocationIndex": index}}],
                             rules=rules, invocations=invocations)

    def test_explicit_level_and_nonfail_still_reject_conflicting_rule_reference(self):
        rules = [{"id": "RULE_A", "defaultConfiguration": {"level": "error"}},
                 {"id": "RULE_B", "defaultConfiguration": {"level": "note"}}]
        for result in ({"kind": "fail", "level": "warning",
                        "rule": {"index": 0, "id": "RULE_B"}},
                       {"kind": "pass", "rule": {"index": 0, "id": "RULE_B"}}):
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.summary([result], rules=rules)



if __name__ == "__main__":
    unittest.main()
