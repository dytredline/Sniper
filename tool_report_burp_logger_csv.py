"""Bounded, offline aggregate preview of caller-mapped Burp Logger CSV.

No Burp process, network request, evidence write or arbitrary input field is
used in the returned summary. Column labels are supplied by the caller because
PortSwigger's export header schema is not assumed here.
"""
from __future__ import annotations

import re
from typing import Any

_MAX_REPORT_BYTES = 65_536
_MAX_CELL_BYTES = 4_096
_MAX_COLUMNS = 64
_MAX_DATA_RECORDS = 500
_STATUS_KEYS = ("1xx", "2xx", "3xx", "4xx", "5xx", "unknown")
_MIME_KEYS = ("application", "audio", "image", "text", "video", "other", "unknown")
_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_QUOTED = r'"(?:[\x20-\x21\x23-\x5B\x5D-\x7E]|\\[\x20-\x7E])*"'
_MIME = re.compile(
    rf"(?P<top>{_TOKEN})/{_TOKEN}(?:[ \t]*;[ \t]*{_TOKEN}[ \t]*=[ \t]*(?:{_TOKEN}|{_QUOTED}))*[ \t]*"
)
_STATUS = re.compile(r"[1-5][0-9]{2}")


def _records(report: str) -> list[tuple[str, ...]]:
    """Parse a strict, small RFC-4180-style CSV without losing logical rows."""
    rows: list[tuple[str, ...]] = []
    row: list[str] = []
    cell: list[str] = []
    # start, bare, quoted, after_quote
    state = "start"
    after_break = False

    def finish_cell() -> None:
        value = "".join(cell)
        if len(value.encode("utf-8", "strict")) > _MAX_CELL_BYTES:
            raise ValueError("Geçersiz CSV hücresi.")
        row.append(value)
        cell.clear()
        if len(row) > _MAX_COLUMNS:
            raise ValueError("Çok fazla CSV sütunu.")

    def finish_row() -> None:
        finish_cell()
        if not any(value for value in row):
            raise ValueError("Boş CSV kaydı.")
        rows.append(tuple(row))
        row.clear()
        if len(rows) > _MAX_DATA_RECORDS + 1:
            raise ValueError("Çok fazla CSV kaydı.")

    i = 0
    while i < len(report):
        ch = report[i]
        if ch == "\x00":
            raise ValueError("CSV içinde NUL karakteri.")
        if state != "quoted" and ch in "\r\n":
            if ch == "\r":
                if i + 1 >= len(report) or report[i + 1] != "\n":
                    raise ValueError("Geçersiz CSV satır sonu.")
                i += 1
            finish_row()
            state = "start"
            after_break = True
            i += 1
            continue
        if state == "start":
            if ch == '"':
                state = "quoted"
            elif ch == ",":
                finish_cell()
            else:
                cell.append(ch)
                state = "bare"
        elif state == "bare":
            if ch == '"':
                raise ValueError("Geçersiz CSV tırnağı.")
            if ch == ",":
                finish_cell()
                state = "start"
            else:
                cell.append(ch)
        elif state == "quoted":
            if ch == '"':
                state = "after_quote"
            else:
                cell.append(ch)
        else:
            if ch == '"':
                cell.append('"')
                state = "quoted"
            elif ch == ",":
                finish_cell()
                state = "start"
            else:
                raise ValueError("Geçersiz CSV tırnak bitişi.")
        after_break = False
        i += 1
    if state == "quoted":
        raise ValueError("Kapatılmamış CSV tırnağı.")
    if not after_break:
        finish_row()
    if not rows:
        raise ValueError("CSV başlığı eksik.")
    return rows


def _mime_bucket(raw: str) -> str:
    if raw == "":
        return "unknown"
    match = _MIME.fullmatch(raw)
    if not match:
        raise ValueError("Geçersiz MIME değeri.")
    top = match.group("top").lower()
    return top if top in _MIME_KEYS[:-2] else "other"


def parse_burp_logger_csv_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """Return only fixed-key aggregate counts for explicitly mapped columns."""
    if not isinstance(payload, dict) or set(payload) != {"report", "columns"}:
        raise ValueError("Geçersiz Logger CSV isteği.")
    report = payload["report"]
    columns = payload["columns"]
    if not isinstance(report, str) or not isinstance(columns, dict) or set(columns) != {"status", "mime"}:
        raise ValueError("Geçersiz Logger CSV isteği.")
    try:
        encoded = report.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ValueError("Geçersiz Logger CSV kodlaması.") from exc
    if not encoded or len(encoded) > _MAX_REPORT_BYTES:
        raise ValueError("Geçersiz Logger CSV uzunluğu.")
    status_label = columns["status"]
    mime_label = columns["mime"]
    if not isinstance(status_label, str) or not status_label.strip():
        raise ValueError("Geçersiz durum sütunu.")
    if mime_label is not None and (not isinstance(mime_label, str) or not mime_label.strip() or mime_label == status_label):
        raise ValueError("Geçersiz MIME sütunu.")

    rows = _records(report)
    headers = rows[0]
    if any(not label.strip() for label in headers) or len(set(headers)) != len(headers):
        raise ValueError("Geçersiz CSV başlığı.")
    if status_label not in headers or (mime_label is not None and mime_label not in headers):
        raise ValueError("Eşlenen CSV başlığı eksik.")
    status_index = headers.index(status_label)
    mime_index = headers.index(mime_label) if mime_label is not None else None
    statuses = {key: 0 for key in _STATUS_KEYS}
    mimes = {key: 0 for key in _MIME_KEYS} if mime_index is not None else None
    for row in rows[1:]:
        if len(row) != len(headers):
            raise ValueError("Düzensiz CSV kaydı.")
        status = row[status_index]
        if status == "":
            bucket = "unknown"
        elif _STATUS.fullmatch(status):
            bucket = status[0] + "xx"
        else:
            raise ValueError("Geçersiz durum değeri.")
        statuses[bucket] += 1
        if mimes is not None and mime_index is not None:
            mimes[_mime_bucket(row[mime_index])] += 1
    response: dict[str, Any] = {
        "format": "burp-logger-csv",
        "entry_count": len(rows) - 1,
        "status_class_counts": statuses,
    }
    if mimes is not None:
        response["mime_bucket_counts"] = mimes
    return response
