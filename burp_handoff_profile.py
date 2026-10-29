from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET
from xml.parsers import expat

from tool_report_burp_sitemap import (
    MAX_ITEMS,
    MAX_REPORT_BYTES,
    parse_burp_sitemap_summary,
)

ALLOWED_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)
_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PARAM_PATH_RE = re.compile(
    r"\{[^{}/]+\}|/:[A-Za-z_][A-Za-z0-9_]*|<[^<>/]+>|\[[^\[\]/]+\]|;[A-Za-z_][A-Za-z0-9_]*="
)


def _validate_allowed_host(allowed_host: str) -> str:
    if not isinstance(allowed_host, str):
        raise ValueError("Geçersiz allowed_host: bir metin olmalı")
    if not allowed_host or allowed_host != allowed_host.strip():
        raise ValueError("Geçersiz allowed_host: boş veya çevresinde boşluk var")
    if "://" in allowed_host:
        raise ValueError("Geçersiz allowed_host: şemaya izin verilmiyor")
    if any(ch in allowed_host for ch in "/:?#@\\") or any(
        ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in allowed_host
    ):
        raise ValueError("Geçersiz allowed_host: yol, port, kullanıcı bilgisi veya denetim karakterlerine izin verilmiyor")

    normalized = allowed_host.lower()
    if len(normalized) > 253 or normalized.startswith(".") or normalized.endswith("."):
        raise ValueError("Geçersiz allowed_host: ana makine adı uzunluğu veya noktaları geçersiz")

    labels = normalized.split(".")
    if any(not _HOSTNAME_LABEL_RE.match(label) for label in labels):
        raise ValueError("Geçersiz allowed_host: geçersiz DNS etiketi")

    if normalized != "localhost" and (len(labels) < 2 or labels[-1].isdigit()):
        raise ValueError("Geçersiz allowed_host: nitelikli bir ana makine adı olmalı")

    return normalized


def _parse_sitemap_xml_safely(sitemap_xml: str) -> ET.Element:
    if not isinstance(sitemap_xml, str) or not sitemap_xml.strip():
        raise ValueError("Geçersiz Burp site haritası XML'i")

    data = sitemap_xml.encode("utf-8", errors="strict")
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Burp site haritası XML'i izin verilen azami boyutu aşıyor")

    lowered = sitemap_xml.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("Burp site haritası XML'inde DTD ve ENTITY bildirimlerine izin verilmiyor")

    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def _reject_doctype(name, sysid, pubid, has_internal_subset):
        raise expat.ExpatError("DOCTYPE bildirimlerine izin verilmiyor")

    def _reject_entity(name, is_parameter_entity, value, base, system_id, public_id, notation_name):
        raise expat.ExpatError("ENTITY bildirimlerine izin verilmiyor")

    def _reject_external_entity(context, base, system_id, public_id):
        raise expat.ExpatError("Harici varlık başvurularına izin verilmiyor")

    def _reject_pi(target, pi_data):
        if target.lower() != "xml":
            raise expat.ExpatError("XML dışı işleme talimatlarına izin verilmiyor")

    parser.StartDoctypeDeclHandler = _reject_doctype
    parser.EntityDeclHandler = _reject_entity
    parser.ExternalEntityRefHandler = _reject_external_entity
    parser.ProcessingInstructionHandler = _reject_pi

    try:
        parser.Parse(data, True)
        root = ET.fromstring(sitemap_xml)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError("Geçersiz veya güvensiz Burp site haritası XML'i") from exc

    if root.tag != "items":
        raise ValueError("Geçersiz Burp site haritası XML kök öğesi")

    return root


def parse_burp_sitemap_xml_summary(sitemap_xml: str) -> dict[str, object]:
    """Validate and summarize Burp Suite Site-map XML using the canonical summary parser."""
    root = _parse_sitemap_xml_safely(sitemap_xml)
    needs_default_status = False
    for item in root:
        if item.tag != "item":
            raise ValueError("Geçersiz Burp site haritası XML öğesi")
        if len(item.findall("status")) == 0:
            needs_default_status = True

    if needs_default_status:
        normalized_root = ET.fromstring(sitemap_xml)
        for item in normalized_root:
            if len(item.findall("status")) == 0:
                status_elem = ET.SubElement(item, "status")
                status_elem.text = "200"
        xml_for_summary = ET.tostring(normalized_root, encoding="unicode")
        return parse_burp_sitemap_summary(xml_for_summary)

    return parse_burp_sitemap_summary(sitemap_xml)


def _extract_item_host_and_url(item: ET.Element, allowed_host: str) -> tuple[str, str]:
    url_elems = item.findall("url")
    host_elems = item.findall("host")

    if len(url_elems) > 1 or len(host_elems) > 1:
        raise ValueError("Geçersiz Burp site haritası öğesi: yinelenen url veya host öğeleri")

    if not url_elems and not host_elems:
        raise ValueError("Geçersiz Burp site haritası öğesi: url ve host eksik")

    if host_elems:
        host_elem = host_elems[0]
        if len(host_elem):
            raise ValueError("Geçersiz Burp site haritası öğesi: host içinde iç içe öğeler")
        raw_host = (host_elem.text or "").strip().lower()
        if not raw_host:
            raise ValueError("Geçersiz Burp site haritası öğesi: boş host öğesi")
        if raw_host != allowed_host:
            raise ValueError("Burp site haritasında kapsam dışı ana makine")

    if url_elems:
        url_elem = url_elems[0]
        if len(url_elem):
            raise ValueError("Geçersiz Burp site haritası öğesi: url içinde iç içe öğeler")
        raw_url = (url_elem.text or "").strip()
        if not raw_url:
            raise ValueError("Geçersiz Burp site haritası öğesi: boş url öğesi")
        try:
            parsed = urlsplit(raw_url)
        except ValueError as exc:
            raise ValueError("Burp site haritası öğesinde geçersiz URL") from exc

        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Burp site haritası öğesinde geçersiz URL şeması veya eksik ana makine adı")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Burp site haritası URL'sinde kimlik bilgilerine izin verilmiyor")

        url_host = parsed.hostname.rstrip(".").lower()
        if url_host != allowed_host:
            raise ValueError("Burp site haritasında kapsam dışı ana makine")

        path = parsed.path or "/"
        query = parsed.query or ""
        return path, query

    path_elems = item.findall("path")
    if len(path_elems) > 1:
        raise ValueError("Geçersiz Burp site haritası öğesi: yinelenen path öğeleri")
    raw_path = (path_elems[0].text or "/").strip() if path_elems else "/"
    parsed_path = urlsplit(raw_path)
    return parsed_path.path or "/", parsed_path.query or ""


def _extract_item_method(item: ET.Element) -> str:
    method_elems = item.findall("method")
    if len(method_elems) > 1:
        raise ValueError("Geçersiz Burp site haritası öğesi: yinelenen method öğeleri")
    if method_elems:
        method_elem = method_elems[0]
        if len(method_elem):
            raise ValueError("Geçersiz Burp site haritası öğesi: method içinde iç içe öğeler")
        method = (method_elem.text or "").strip().upper()
        if method not in ALLOWED_HTTP_METHODS:
            raise ValueError("Burp site haritası öğesinde geçersiz HTTP yöntemi")
        return method
    return "GET"


def build_burp_manual_handoff_manifest(
    sitemap_xml: str,
    *,
    allowed_host: str,
) -> dict[str, object]:
    """Build a bounded, non-sensitive Burp manual testing handoff manifest for an in-scope host."""
    normalized_host = _validate_allowed_host(allowed_host)
    root = _parse_sitemap_xml_safely(sitemap_xml)

    items = list(root)
    if not items:
        raise ValueError("Burp site haritası hiç öğe içermiyor")
    if len(items) > MAX_ITEMS:
        raise ValueError("Burp site haritası azami öğe sınırını aşıyor")

    methods_seen: set[str] = set()
    in_scope_endpoint_count = 0
    parameterized_endpoint_count = 0

    for item in items:
        if item.tag != "item":
            raise ValueError("Geçersiz Burp site haritası XML öğesi")
        path, query = _extract_item_host_and_url(item, normalized_host)
        method = _extract_item_method(item)
        methods_seen.add(method)
        in_scope_endpoint_count += 1
        if bool(query.strip()) or ("{" in path and "}" in path) or bool(_PARAM_PATH_RE.search(path)):
            parameterized_endpoint_count += 1

    sitemap_summary = parse_burp_sitemap_xml_summary(sitemap_xml)
    methods_observed = sorted(methods_seen)

    manifest_core: dict[str, object] = {
        "format": "burp-manual-handoff-v1",
        "automation_mode": "manual_operator_guided_only",
        "allowed_host": normalized_host,
        "in_scope_endpoint_count": in_scope_endpoint_count,
        "methods_observed": methods_observed,
        "parameterized_endpoint_count": parameterized_endpoint_count,
        "status_counts": sitemap_summary["status_counts"],
        "mimetype_counts": sitemap_summary["mimetype_counts"],
        "sitemap_report_sha256": sitemap_summary["report_sha256"],
    }
    canonical = json.dumps(manifest_core, sort_keys=True, separators=(",", ":"))
    manifest_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        **manifest_core,
        "manifest_sha256": manifest_sha256,
    }
