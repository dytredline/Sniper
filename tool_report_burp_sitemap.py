from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from xml.parsers import expat
from xml.etree import ElementTree as ET

MAX_ITEMS = 500
MAX_REPORT_BYTES = 60_000
ALLOWED_STATUSES = set(range(100, 600))
MIME_TYPES = {"HTML", "JSON", "XML", "OTHER", "UNKNOWN"}


def _parse_xml_safely(xml_str: str) -> ET.Element:
    # Enforce 60,000-byte UTF-8 cap before parsing
    data = xml_str.encode("utf-8", errors="strict")
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Geçersiz XML.")

    try:
        # Preflight Expat parse to reject unsafe constructs
        p = expat.ParserCreate()
        p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

        def start_doctype(name, sysid, pubid, has_internal_subset):
            if sysid is not None or pubid is not None:
                raise expat.ExpatError("Harici DTD alt kümesine izin verilmiyor")

        def entity_decl(name, is_parameter_entity, value, base, system_id, public_id, notation_name):
            raise expat.ExpatError("ENTITY bildirimlerine izin verilmiyor")

        def external_entity_ref(context, base, system_id, public_id):
            raise expat.ExpatError("Harici varlık başvurularına izin verilmiyor")

        def pi_decl(target, data):
            if target.lower() != "xml":
                raise expat.ExpatError("XML dışı işleme talimatlarına izin verilmiyor")

        p.StartDoctypeDeclHandler = start_doctype
        p.EntityDeclHandler = entity_decl
        p.ExternalEntityRefHandler = external_entity_ref
        p.ProcessingInstructionHandler = pi_decl

        # Safe preflight parse
        try:
            p.Parse(data, True)
        except expat.ExpatError:
            raise ValueError("Geçersiz XML.")

        # Now parse with ElementTree (safe because Expat already vetted DTD)
        root = ET.fromstring(xml_str)
        return root
    except (expat.ExpatError, ET.ParseError) as e:
        raise ValueError("Geçersiz XML.") from e


def parse_burp_sitemap_summary(report: str) -> dict[str, Any]:
    if not isinstance(report, str):
        raise ValueError("Geçersiz XML.")

    try:
        root = _parse_xml_safely(report)
    except ValueError as e:
        raise ValueError("Geçersiz XML.") from e

    # Validate root element
    if root.tag != "items":
        raise ValueError("Geçersiz XML.")

    # Count items and collect status/mimetype
    status_counts: dict[str, int] = {}
    mimetype_counts: dict[str, int] = {"HTML": 0, "JSON": 0, "XML": 0, "OTHER": 0, "UNKNOWN": 0}
    item_count = 0

    for item in root:
        if item.tag != "item":
            raise ValueError("Geçersiz XML.")

        item_count += 1
        if item_count > MAX_ITEMS:
            raise ValueError("Geçersiz XML.")

        # Extract status: exactly one direct child
        status_elems = item.findall("status")
        if len(status_elems) != 1:
            raise ValueError("Geçersiz XML.")
        status_elem = status_elems[0]
        if len(status_elem):
            raise ValueError("Geçersiz XML.")
        if status_elem.text is None:
            raise ValueError("Geçersiz XML.")
        # Only exactly three ASCII digits 100..599 (RFC 9110/9112 status-code).
        # int() would also accept " 200", "+200", "2_00" or non-ASCII digits.
        # XML biçimlendirmesinden gelen çevresel ASCII boşluk kırpılır; içerik yalnız ASCII ondalık olmalı.
        status_text = status_elem.text.strip(" \t\r\n")
        if not re.fullmatch(r"[1-5][0-9]{2}", status_text):
            raise ValueError("Geçersiz XML.")
        status_val = int(status_text)
        if not (100 <= status_val <= 599):
            raise ValueError("Geçersiz XML.")
        status_str = str(status_val)
        status_counts[status_str] = status_counts.get(status_str, 0) + 1

        # Extract mimetype: zero or one direct child
        mimetype_elems = item.findall("mimetype")
        if len(mimetype_elems) > 1:
            raise ValueError("Geçersiz XML.")
        if mimetype_elems:
            if len(mimetype_elems[0]):
                raise ValueError("Geçersiz XML.")
            mime = mimetype_elems[0].text.strip().upper() if mimetype_elems[0].text else ""
            if mime in {"HTML", "JSON", "XML"}:
                mimetype_counts[mime] += 1
            elif mime == "":
                mimetype_counts["UNKNOWN"] += 1
            else:
                mimetype_counts["OTHER"] += 1
        else:
            mimetype_counts["UNKNOWN"] += 1

    # Build canonical summary dict (no format field in digest)
    summary = {
        "item_count": item_count,
        "status_counts": status_counts,
        "mimetype_counts": mimetype_counts
    }

    # Compute SHA-256 of canonical JSON (only aggregate fields)
    canonical = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    report_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # Final output includes format and digest
    return {
        "format": "burp-sitemap-xml",
        "item_count": item_count,
        "status_counts": status_counts,
        "mimetype_counts": mimetype_counts,
        "report_sha256": report_sha256
    }
