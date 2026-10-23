from __future__ import annotations

import json
import pytest

from burp_handoff_profile import (
    build_burp_manual_handoff_manifest,
    parse_burp_sitemap_xml_summary,
)


VALID_IN_SCOPE_XML = (
    "<items>"
    "<item>"
    "<url>https://app.example.test/login</url>"
    "<host ip=\"198.51.100.10\">app.example.test</host>"
    "<method>GET</method>"
    "<request>SECRET_REQ_MARKER_1</request>"
    "<response>SECRET_RESP_MARKER_1</response>"
    "<status>200</status>"
    "<mimetype>HTML</mimetype>"
    "</item>"
    "<item>"
    "<url>https://app.example.test/api/v1/orders?order_id=99&amp;token=SECRET_QUERY</url>"
    "<host>app.example.test</host>"
    "<method>POST</method>"
    "<status>201</status>"
    "<mimetype>JSON</mimetype>"
    "</item>"
    "<item>"
    "<url>https://app.example.test/api/v1/items/{id}</url>"
    "<method>DELETE</method>"
    "<status>204</status>"
    "<mimetype>OTHER</mimetype>"
    "</item>"
    "</items>"
)


def test_valid_in_scope_burp_xml_produces_deterministic_non_sensitive_manifest() -> None:
    manifest_1 = build_burp_manual_handoff_manifest(
        VALID_IN_SCOPE_XML,
        allowed_host="APP.EXAMPLE.TEST",
    )
    manifest_2 = build_burp_manual_handoff_manifest(
        VALID_IN_SCOPE_XML,
        allowed_host="app.example.test",
    )

    assert manifest_1 == manifest_2
    assert manifest_1["format"] == "burp-manual-handoff-v1"
    assert manifest_1["automation_mode"] == "manual_operator_guided_only"
    assert manifest_1["allowed_host"] == "app.example.test"
    assert manifest_1["in_scope_endpoint_count"] == 3
    assert manifest_1["methods_observed"] == ["DELETE", "GET", "POST"]
    assert manifest_1["parameterized_endpoint_count"] == 2
    assert isinstance(manifest_1["manifest_sha256"], str)
    assert len(manifest_1["manifest_sha256"]) == 64

    summary = parse_burp_sitemap_xml_summary(VALID_IN_SCOPE_XML)
    assert manifest_1["sitemap_report_sha256"] == summary["report_sha256"]
    assert manifest_1["status_counts"] == {"200": 1, "201": 1, "204": 1}

    serialized = json.dumps(manifest_1)
    for sensitive_marker in (
        "SECRET_REQ_MARKER_1",
        "SECRET_RESP_MARKER_1",
        "SECRET_QUERY",
        "198.51.100.10",
        "/api/v1/orders",
    ):
        assert sensitive_marker not in serialized


def test_out_of_scope_host_fails_closed() -> None:
    out_of_scope_url_xml = (
        "<items>"
        "<item><url>https://other.example/admin?debug=1</url><status>200</status></item>"
        "</items>"
    )
    with pytest.raises(ValueError, match="Burp site haritasında kapsam dışı ana makine"):
        build_burp_manual_handoff_manifest(
            out_of_scope_url_xml,
            allowed_host="app.example.test",
        )

    out_of_scope_minimal_xml = (
        "<items><item><url>https://other.example/path</url></item></items>"
    )
    with pytest.raises(ValueError, match="Burp site haritasında kapsam dışı ana makine"):
        build_burp_manual_handoff_manifest(
            out_of_scope_minimal_xml,
            allowed_host="app.example.test",
        )

    mismatched_host_tag_xml = (
        "<items>"
        "<item>"
        "<url>https://app.example.test/home</url>"
        "<host>other.example</host>"
        "<status>200</status>"
        "</item>"
        "</items>"
    )
    with pytest.raises(ValueError, match="Burp site haritasında kapsam dışı ana makine"):
        build_burp_manual_handoff_manifest(
            mismatched_host_tag_xml,
            allowed_host="app.example.test",
        )


@pytest.mark.parametrize(
    "unsafe_xml",
    [
        '<?xml version="1.0"?><!DOCTYPE items [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><items><item><url>https://app.example.test/</url><status>200</status></item></items>',
        "<!DOCTYPE items><items><item><url>https://app.example.test/</url><status>200</status></item></items>",
        "<items><item><url>https://app.example.test/</url><status>999</status></item></items>",
        "<items></items>",
    ],
)
def test_xxe_doctype_and_malformed_xml_fail_closed(unsafe_xml: str) -> None:
    with pytest.raises(ValueError):
        build_burp_manual_handoff_manifest(
            unsafe_xml,
            allowed_host="app.example.test",
        )


@pytest.mark.parametrize(
    "bad_host",
    [
        "",
        "   ",
        "https://app.example.test",
        "app.example.test:8443",
        "app.example.test/login",
        "user@app.example.test",
        "app.example.test?foo=1",
        "-bad.example.test",
        "bad..example.test",
        "127.0.0.1",
    ],
)
def test_invalid_allowed_host_fails_closed(bad_host: str) -> None:
    with pytest.raises(ValueError):
        build_burp_manual_handoff_manifest(
            VALID_IN_SCOPE_XML,
            allowed_host=bad_host,
        )
