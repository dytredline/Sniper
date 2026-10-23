#!/usr/bin/env python3
"""Sniper 2.0 için yalnız yerel, veri değiştirmeyen sağlık tanısı."""

from __future__ import annotations

import http.client
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = Path.home() / ".local/share/sniper/data"
DATA_DIR = Path(os.environ.get("SNIPER_DATA_DIR", str(DEFAULT_DATA_DIR))).expanduser().resolve()
DB_PATH = DATA_DIR / "sniper.db"
HOST = os.environ.get("SNIPER_HOST", "127.0.0.1")
PORT = int(os.environ.get("SNIPER_PORT", "8787"))


class Outcome:
    def __init__(self, status: str):
        self.status = status

    def __bool__(self) -> bool:
        return self.status != "FAIL"


def report(name: str, status: str, message: str) -> Outcome:
    print(f"[{status}] {name}: {message}")
    return Outcome(status)


def http_get(path: str) -> tuple[int, Any]:
    connection = http.client.HTTPConnection(HOST, PORT, timeout=4)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            return response.status, "HTTP body too large"
        content_type = response.getheader("Content-Type", "")
        if "json" in content_type or path != "/metrics":
            try:
                return response.status, json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                return response.status, raw.decode("utf-8", errors="replace")
        return response.status, raw.decode("utf-8", errors="replace")
    finally:
        connection.close()


def check_service() -> Outcome:
    result = subprocess.run(
        ["systemctl", "--user", "is-active", "--quiet", "sniper.service"],
        check=False,
        capture_output=True,
        text=True,
    )
    return report("sniper.service", "PASS" if result.returncode == 0 else "FAIL", "active" if result.returncode == 0 else "active değil")


def check_http_health() -> Outcome:
    try:
        status, payload = http_get("/api/health")
    except OSError as exc:
        return report("HTTP sağlık", "FAIL", f"servise ulaşılamadı: {type(exc).__name__}")
    passed = status == 200 and isinstance(payload, dict) and payload.get("status") == "ok"
    return report("HTTP sağlık", "PASS" if passed else "FAIL", f"HTTP {status}; status={payload.get('status') if isinstance(payload, dict) else 'geçersiz'}")


def check_plugins() -> Outcome:
    try:
        status, payload = http_get("/api/plugins")
    except OSError as exc:
        return report("Eklenti uç noktası", "FAIL", f"servise ulaşılamadı: {type(exc).__name__}")
    passed = status == 200 and isinstance(payload, (dict, list))
    return report("Eklenti uç noktası", "PASS" if passed else "FAIL", f"HTTP {status}; JSON={passed}")


def check_metrics() -> Outcome:
    try:
        status, payload = http_get("/metrics")
    except OSError as exc:
        return report("Metrikler", "FAIL", f"servise ulaşılamadı: {type(exc).__name__}")
    text = payload if isinstance(payload, str) else ""
    passed = status == 200 and any(line.startswith("sniper_") for line in text.splitlines())
    return report("Metrikler", "PASS" if passed else "FAIL", f"HTTP {status}; içerik={len(text.encode('utf-8'))} bayt")


def check_scan_diff() -> Outcome:
    """Aynı hedefe ait son iki tamamlanmış taramayı salt-okunur karşılaştırır; yeterli veri yoksa atlanır."""
    try:
        status, payload = http_get("/api/scans?limit=200")
    except OSError as exc:
        return report("Scan Diff", "FAIL", f"servise ulaşılamadı: {type(exc).__name__}")
    scans = payload.get("scans") if isinstance(payload, dict) else None
    if status != 200 or not isinstance(scans, list):
        return report("Scan Diff", "FAIL", f"tarama listesi alınamadı: HTTP {status}")
    by_target: dict[str, list[dict]] = {}
    for scan in scans:
        if isinstance(scan, dict) and scan.get("status") == "completed" and scan.get("target_id"):
            by_target.setdefault(str(scan["target_id"]), []).append(scan)
    pair = None
    for rows in by_target.values():
        if len(rows) >= 2:
            rows.sort(key=lambda row: str(row.get("created_at") or ""))
            newest_time = str(rows[-1].get("created_at") or "")
            # Karşılaştırma eşit zamanları reddeder; aynı saniyede biten iki tarama çift sayılmaz.
            older = [row for row in rows[:-1] if str(row.get("created_at") or "") < newest_time]
            if older:
                try:
                    pair = (older[-1]["id"], rows[-1]["id"])
                except KeyError:
                    return report("Scan Diff", "FAIL", "tarama verisi eksik: id alanı bulunamadı")
                break
    if pair is None:
        return report("Scan Diff", "SKIP", "atlandı: aynı hedefte iki tamamlanmış tarama yok")
    try:
        status, payload = http_get(f"/api/scans/diff/{pair[0]}/{pair[1]}?details=0")
    except OSError as exc:
        return report("Scan Diff", "FAIL", f"servise ulaşılamadı: {type(exc).__name__}")
    summary = payload.get("summary") if isinstance(payload, dict) else None
    passed = status == 200 and isinstance(summary, dict) and all(
        isinstance(summary.get(key), int) and not isinstance(summary.get(key), bool) and summary.get(key) >= 0 for key in ("new_count", "resolved_count", "persistent_count")
    )
    detail = (
        f"HTTP {status}; yeni={summary.get('new_count')} giderilen={summary.get('resolved_count')} devam={summary.get('persistent_count')}"
        if isinstance(summary, dict) else f"HTTP {status}; özet yok"
    )
    return report("Scan Diff", "PASS" if passed else "FAIL", detail)


def check_database() -> Outcome:
    if not DB_PATH.is_file():
        return report("SQLite integrity_check", "FAIL", f"veritabanı yok: {DB_PATH}")
    uri = f"file:{DB_PATH}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=4) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as exc:
        return report("SQLite integrity_check", "FAIL", type(exc).__name__)
    passed = bool(result and result[0] == "ok")
    return report("SQLite integrity_check", "PASS" if passed else "FAIL", str(result[0] if result else "sonuç yok"))


def main() -> int:
    checks = [check_service(), check_http_health(), check_plugins(), check_metrics(), check_scan_diff(), check_database()]
    passed = sum(1 for c in checks if c.status == "PASS")
    skipped = sum(1 for c in checks if c.status == "SKIP")
    failed = sum(1 for c in checks if c.status == "FAIL")

    if skipped:
        print(f"ÖZET: {passed}/{len(checks)} PASS, {skipped} SKIP")
    else:
        print(f"ÖZET: {passed}/{len(checks)} PASS")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
