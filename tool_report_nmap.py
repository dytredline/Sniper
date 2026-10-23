from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from xml.parsers import expat
from xml.etree import ElementTree as ET

MAX_HOSTS = 500
MAX_PORTS = 5000
MAX_REPORT_BYTES = 60_000
_PORTID_RE = re.compile(r"[1-9][0-9]{0,4}")


def _validated_tcp_udp_portid(port: ET.Element, *, allow_zero: bool = False) -> int:
    """Return portid as 1..65535; only plain ASCII decimal without sign/space/leading zero.

    ``allow_zero``: gerçek ``nmap -p0`` çıktısında açık olmayan port 0 görülebilir.
    """
    portid_str = port.get("portid")
    if allow_zero and portid_str == "0":
        return 0
    if portid_str is None or not _PORTID_RE.fullmatch(portid_str):
        raise ValueError("Geçersiz XML.")
    portid = int(portid_str)
    if not (1 <= portid <= 65535):
        raise ValueError("Geçersiz XML.")
    return portid


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
            # Allow harmless xml-stylesheet PI; reject others
            if target.lower() == "xml" or target.lower() == "xml-stylesheet":
                return
            # Reject non-xml PI (e.g., custom processing instructions)
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


def parse_nmap_inline_summary(report: str) -> dict[str, Any]:
    if not isinstance(report, str):
        raise ValueError("Geçersiz XML.")

    try:
        root = _parse_xml_safely(report)
    except ValueError as e:
        raise ValueError("Geçersiz XML.") from e

    # Validate root element
    if root.tag != "nmaprun":
        raise ValueError("Geçersiz XML.")

    # Count hosts and open ports
    host_count = 0
    up_host_count = 0
    open_port_count = 0
    open_protocol_counts = {"tcp": 0, "udp": 0}
    open_port_bands = {"well_known": 0, "registered": 0, "dynamic": 0}
    port_element_count = 0

    for host in root:
        if host.tag != "host":
            continue

        host_count += 1
        if host_count > MAX_HOSTS:
            raise ValueError("Geçersiz XML.")

        # Count <port> elements globally before host status check
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem:
                if port.tag == "port":
                    port_element_count += 1
                    if port_element_count > MAX_PORTS:
                        raise ValueError("Geçersiz XML.")
                    # Every TCP/UDP port identity is validated, including
                    # ports of down hosts and closed/filtered ports.
                    if port.get("protocol") in ("tcp", "udp"):
                        port_state = port.find("state")
                        is_open = port_state is not None and port_state.get("state") == "open"
                        _validated_tcp_udp_portid(port, allow_zero=not is_open)

        # Only process up hosts for open ports
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        up_host_count += 1

        if ports_elem is None:
            continue

        for port in ports_elem:
            if port.tag != "port":
                continue

            # Validate protocol
            protocol = port.get("protocol")
            if protocol not in ("tcp", "udp"):
                continue

            # Validate state
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            # Already validated above for every TCP/UDP port element.
            portid = _validated_tcp_udp_portid(port)

            open_port_count += 1
            if open_port_count > MAX_PORTS:
                raise ValueError("Geçersiz XML.")

            open_protocol_counts[protocol] = open_protocol_counts.get(protocol, 0) + 1

            # Band classification
            if 1 <= portid <= 1024:
                open_port_bands["well_known"] += 1
            elif 1025 <= portid <= 49151:
                open_port_bands["registered"] += 1
            else:
                open_port_bands["dynamic"] += 1

    # Build canonical summary dict (no format field in digest)
    summary = {
        "host_count": host_count,
        "up_host_count": up_host_count,
        "open_port_count": open_port_count,
        "open_protocol_counts": open_protocol_counts,
        "open_port_bands": open_port_bands
    }

    # Compute SHA-256 of exact UTF-8 input XML string (per contract)
    report_sha256 = hashlib.sha256(report.encode("utf-8")).hexdigest()

    # Final output includes format and digest
    return {
        "format": "nmap-xml",
        "host_count": host_count,
        "up_host_count": up_host_count,
        "open_port_count": open_port_count,
        "open_protocol_counts": open_protocol_counts,
        "open_port_bands": open_port_bands,
        "report_sha256": report_sha256
    }
