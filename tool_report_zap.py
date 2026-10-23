from __future__ import annotations

import hashlib
import json
import re
from typing import Any

MAX_SITES = 20
MAX_ALERT_TYPES = 500
MAX_INSTANCES_TOTAL = 5000


def _count_risk_codes(alerts: list[dict[str, Any]]) -> tuple[dict[str, int], int]:
    counts = {"informational": 0, "low": 0, "medium": 0, "high": 0}
    total_instances = 0
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("Her uyarı bir nesne olmalı")
        riskcode_raw = alert.get("riskcode")
        if not isinstance(riskcode_raw, str):
            raise ValueError("riskcode bir metin olmalı")
        if riskcode_raw not in {"0", "1", "2", "3"}:
            raise ValueError("Geçersiz riskcode")
        count_raw = alert.get("count")
        if not isinstance(count_raw, str):
            raise ValueError("count bir metin olmalı")
        # Strictly validate count: must be ASCII digits only and positive
        if not re.fullmatch(r"[0-9]+", count_raw):
            raise ValueError("count pozitif bir ondalık metin olmalı")
        try:
            count = int(count_raw)
        except ValueError:
            raise ValueError("count pozitif bir ondalık metin olmalı")
        if count <= 0:
            raise ValueError("count pozitif olmalı")
        # Count alert types by riskcode
        if riskcode_raw == "0":
            counts["informational"] += 1
        elif riskcode_raw == "1":
            counts["low"] += 1
        elif riskcode_raw == "2":
            counts["medium"] += 1
        elif riskcode_raw == "3":
            counts["high"] += 1
        # Accumulate total instances
        total_instances += count
    return counts, total_instances


def parse_zap_traditional_json_summary(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("report bir JSON nesnesi olmalı")

    sites = report.get("site")
    if not isinstance(sites, list):
        raise ValueError("site bir liste olmalı")

    if len(sites) > MAX_SITES:
        raise ValueError("Çok fazla site")

    total_alert_types = 0
    total_instances = 0
    global_risk_counts = {"informational": 0, "low": 0, "medium": 0, "high": 0}

    for site in sites:
        if not isinstance(site, dict):
            raise ValueError("Her site bir nesne olmalı")
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            raise ValueError("site.alerts bir liste olmalı")
        site_alert_types = len(alerts)
        total_alert_types += site_alert_types
        if total_alert_types > MAX_ALERT_TYPES:
            raise ValueError("Çok fazla uyarı türü")
        site_risk_counts, site_instances = _count_risk_codes(alerts)
        for risk in global_risk_counts:
            global_risk_counts[risk] += site_risk_counts[risk]
        total_instances += site_instances
        if total_instances > MAX_INSTANCES_TOTAL:
            raise ValueError("Toplam örnek sayısı sınırı aşıyor")

    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "format": "zap-traditional-json",
        "site_count": len(sites),
        "alert_type_count": total_alert_types,
        "instance_count": total_instances,
        "risk_counts": global_risk_counts,
        "report_sha256": report_sha256
    }
