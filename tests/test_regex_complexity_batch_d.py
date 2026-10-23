"""Batch-D regressions for polynomial parsing of mobile, GraphQL and C input."""
from __future__ import annotations

from pathlib import Path
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import memsafety_c  # noqa: E402
import mobile_security_auditor  # noqa: E402
import openapi_contract_auditor  # noqa: E402


def _mobile_rules(content: str, filename: str) -> set[str]:
    report = mobile_security_auditor.audit_mobile_manifest_inline(content, filename=filename)
    return {finding["control_id"] for finding in report["findings"]}


def test_mobile_manifest_attribute_semantics() -> None:
    manifest = '''<manifest>
      <data android:host="example.test" android:scheme="myapp" />
      <data android:scheme="https" />
    </manifest>'''
    assert "SNIPER-MOB-MAN-07" in _mobile_rules(manifest, "AndroidManifest.xml")

    network = '<network-security-config><certificates src="user" /></network-security-config>'
    assert "SNIPER-MOB-NSC-02" in _mobile_rules(network, "network_security_config.xml")

    gradle = "release { minifyEnabled = false }"
    assert "SNIPER-MOB-GRD-01" in _mobile_rules(gradle, "build.gradle")


def test_mobile_unterminated_deep_links_are_bounded() -> None:
    payload = "<manifest><data " + ('android:scheme="!"' * 8_000)
    started = time.perf_counter()
    report = mobile_security_auditor.audit_mobile_manifest_inline(payload, filename="AndroidManifest.xml")
    elapsed = time.perf_counter() - started
    assert report["finding_count"] == 0
    assert elapsed < 0.15, f"Android data-tag parsing took {elapsed:.3f}s"


def test_mobile_unterminated_certificates_are_bounded() -> None:
    payload = "<network-security-config><certificates " + (" " * 20_000) + "X"
    started = time.perf_counter()
    report = mobile_security_auditor.audit_mobile_manifest_inline(
        payload, filename="network_security_config.xml"
    )
    elapsed = time.perf_counter() - started
    assert not any(finding["control_id"] == "SNIPER-MOB-NSC-02" for finding in report["findings"])
    assert elapsed < 0.3, f"Android certificates parsing took {elapsed:.3f}s"


def test_mobile_minify_spacing_is_bounded() -> None:
    payload = "minifyEnabled" + (" " * 30_000) + "=X"
    started = time.perf_counter()
    report = mobile_security_auditor.audit_mobile_manifest_inline(payload, filename="build.gradle")
    elapsed = time.perf_counter() - started
    assert not any(finding["control_id"] == "SNIPER-MOB-GRD-01" for finding in report["findings"])
    assert elapsed < 0.2, f"Gradle minify setting parsing took {elapsed:.3f}s"


def test_c_define_collection_semantics() -> None:
    defines = memsafety_c._collect_defines(
        "#define N 10\n#define FN(x) x\n#define TOTAL (N + \\\n  2)\n"
    )
    assert set(defines) == {"N", "TOTAL"}
    assert [token.text for token in defines["TOTAL"]] == ["(", "N", "+", "2", ")"]


def test_c_define_trailing_escape_is_bounded() -> None:
    payload = "#define\tA" + ("\t" * 10_000) + "\\"
    started = time.perf_counter()
    assert memsafety_c._collect_defines(payload) == {}
    elapsed = time.perf_counter() - started
    assert elapsed < 0.3, f"C macro parsing took {elapsed:.3f}s"


def test_openapi_scalar_and_graphql_semantics() -> None:
    assert openapi_contract_auditor._parse_scalar("-42") == -42
    assert openapi_contract_auditor._parse_scalar("10.25") == 10.25
    assert openapi_contract_auditor._parse_scalar("10.2.5") == "10.2.5"

    schema = '''
      type Query { user(id: ID!): User }
      type Mutation {
        rename(id: ID!, name: String!): User @auth
        remove(id: ID!): Boolean
      }
      type User { id: ID! }
    '''
    report = openapi_contract_auditor.audit_api_contract(schema, contract_type="graphql")
    assert report["endpoint_count"] == 3
    assert any(finding["location"] == "Mutation.remove" for finding in report["findings"])
    assert not any(finding["location"] == "Mutation.rename" for finding in report["findings"])


def test_graphql_unterminated_type_header_is_bounded() -> None:
    payload = "type A" + (" " * 20_000) + "X"
    started = time.perf_counter()
    try:
        openapi_contract_auditor.audit_api_contract(payload, contract_type="graphql")
    except openapi_contract_auditor.ApiContractAuditError:
        pass
    else:
        raise AssertionError("unterminated GraphQL type unexpectedly parsed")
    elapsed = time.perf_counter() - started
    assert elapsed < 0.3, f"GraphQL type parsing took {elapsed:.3f}s"


def test_graphql_field_spacing_is_bounded() -> None:
    payload = "type Query {\nA" + (" " * 30_000) + "X\n}"
    started = time.perf_counter()
    report = openapi_contract_auditor.audit_api_contract(payload, contract_type="graphql")
    elapsed = time.perf_counter() - started
    assert report["endpoint_count"] == 0
    assert elapsed < 0.2, f"GraphQL field parsing took {elapsed:.3f}s"
