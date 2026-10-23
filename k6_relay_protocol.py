#!/usr/bin/env python3
"""Fixed k6 host-relay protocol for the isolated active-local candidate.

The caller supplies a transport bound to one approved host-loopback port.
"""
from __future__ import annotations

import json
import math
import re
import threading
from dataclasses import dataclass
from typing import Callable

MAX_FRAME_BYTES = 2048
MAX_REQUESTS = 3
MAX_TARGET_BODY_BYTES = 2048
SHIM_HOST = "127.0.0.1:8765"
SHIM_PATH = "/probe"
SUCCESS_BODY = b'{"ok":true}'
_ALLOWED_HEADERS = frozenset({"host", "user-agent", "accept", "accept-encoding", "connection"})
_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,40}\Z")


class ProtocolError(ValueError):
    pass


def encode_frame(raw: bytes) -> bytes:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_FRAME_BYTES:
        raise ProtocolError("geçersiz çerçeve gövdesi")
    return len(raw).to_bytes(4, "big") + raw


def decode_frame(frame: bytes) -> bytes:
    if type(frame) is not bytes or len(frame) < 5:
        raise ProtocolError("geçersiz çerçeve")
    length = int.from_bytes(frame[:4], "big")
    if not 1 <= length <= MAX_FRAME_BYTES or len(frame) != length + 4:
        raise ProtocolError("geçersiz çerçeve uzunluğu")
    return frame[4:]


def parse_request(raw: bytes) -> None:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_FRAME_BYTES:
        raise ProtocolError("istek çok büyük")
    if b"\x00" in raw or not raw.endswith(b"\r\n\r\n"):
        raise ProtocolError("geçersiz istek sonlandırıcısı veya gövdesi")
    try:
        lines = raw[:-4].decode("ascii", "strict").split("\r\n")
    except UnicodeError as exc:
        raise ProtocolError("ASCII olmayan istek") from exc
    if not lines or lines[0] != f"GET {SHIM_PATH} HTTP/1.1":
        raise ProtocolError("yöntem, köken yolu veya HTTP sürümü reddedildi")
    if not 1 <= len(lines[1:]) <= 8:
        raise ProtocolError("geçersiz başlık sayısı")
    seen: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line or line[0].isspace():
            raise ProtocolError("geçersiz başlık")
        name, value = line.split(":", 1)
        if not _HEADER_NAME.fullmatch(name) or not value.startswith(" "):
            raise ProtocolError("geçersiz başlık sözdizimi")
        key = name.lower()
        value = value[1:]
        if (key not in _ALLOWED_HEADERS or key in seen or not value
                or len(value) > 128 or any(ord(ch) < 32 or ord(ch) > 126 for ch in value)):
            raise ProtocolError("başlık reddedildi")
        seen[key] = value
    if seen.get("host") != SHIM_HOST:
        raise ProtocolError("ana makine reddedildi")


@dataclass(frozen=True)
class RelayReply:
    status: int
    body: bytes = b""

    def wire_frame(self) -> bytes:
        # Fixed response body prevents target bytes, headers, or Location leak.
        if self.status not in (200, 403, 429, 502):
            raise ProtocolError("desteklenmeyen yanıt")
        if self.status != 200 and self.body:
            raise ProtocolError("hata gövdesi yasak")
        if self.status == 200 and self.body != SUCCESS_BODY:
            raise ProtocolError("başarı gövdesi sabit olmalı")
        value = {"status": self.status, "body": self.body.decode("ascii")}
        return encode_frame(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"))


SUMMARY_MAX_BYTES = 65536


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("yinelenen JSON anahtarı")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ProtocolError("sonlu olmayan JSON sabiti")


def _exact_counter(metric, field, expected):
    values = metric.get("values")
    if type(values) is not dict or type(values.get(field)) is not int:
        raise ProtocolError("sayaç eksik veya tamsayı değil")
    if values[field] != expected:
        raise ProtocolError("sayaç uyuşmuyor")


def _exact_rate(metric, expected):
    values = metric.get("values")
    value = values.get("rate") if type(values) is dict else None
    if type(value) not in (int, float) or not math.isfinite(value) or value != expected:
        raise ProtocolError("oran uyuşmuyor")


def _metric(metrics, name, metric_type):
    item = metrics.get(name)
    if type(item) is not dict or item.get("type") != metric_type:
        raise ProtocolError("metrik eksik veya tür uyuşmuyor")
    return item


def _threshold(metric, expression):
    entries = metric.get("thresholds")
    if type(entries) is not dict or set(entries) != {expression}:
        raise ProtocolError("eşik eksik veya belirsiz")
    result = entries[expression]
    if type(result) is not dict or set(result) != {"ok"} or result["ok"] is not True:
        raise ProtocolError("başarısız veya bozuk eşik")


def parse_fixed_summary(raw):
    """Fail-closed contract for the *pinned* fixed k6 handleSummary JSON bytes.

    The runner must separately attest that raw came from the fixed script's
    private /work/summary.json output; this parser cannot prove provenance.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= SUMMARY_MAX_BYTES:
        raise ProtocolError("özet boyutu/türü reddedildi")
    try:
        data = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise ProtocolError("geçersiz özet JSON'u") from exc
    metrics = data.get("metrics") if type(data) is dict else None
    if type(metrics) is not dict:
        raise ProtocolError("k6 metrik nesnesi eksik")

    checks = _metric(metrics, "checks", "rate")
    _exact_rate(checks, 1)
    _exact_counter(checks, "passes", 3)
    _exact_counter(checks, "fails", 0)
    _threshold(checks, "rate==1")

    failed = _metric(metrics, "http_req_failed", "rate")
    _exact_rate(failed, 0)
    _threshold(failed, "rate==0")

    reqs = _metric(metrics, "http_reqs", "counter")
    _exact_counter(reqs, "count", 3)
    _threshold(reqs, "count==3")

    dropped = _metric(metrics, "dropped_iterations", "counter")
    _exact_counter(dropped, "count", 0)
    _threshold(dropped, "count==0")

    iterations = _metric(metrics, "iterations", "counter")
    _exact_counter(iterations, "count", 3)


class RelayGate:
    """Count parsed HTTP requests before invoking a caller-supplied transport."""

    def __init__(self, transport: Callable[[], tuple[int, bytes]]):
        if not callable(transport):
            raise TypeError("aktarım katmanı enjekte edilmeli")
        self._transport = transport
        self._lock = threading.Lock()
        self.delivered = 0
        self.denied = 0
        self.exhausted = False
        self.failure = False

    def _deny(self, status: int) -> RelayReply:
        with self._lock:
            self.denied += 1
            self.failure = True
        return RelayReply(status)

    def handle_frame(self, frame: bytes) -> RelayReply:
        try:
            parse_request(decode_frame(frame))
        except ProtocolError:
            return self._deny(403)
        with self._lock:
            if self.delivered >= MAX_REQUESTS:
                self.denied += 1
                self.exhausted = True
                self.failure = True
                return RelayReply(429)
            if self.failure:
                self.denied += 1
                return RelayReply(502)
            # Reservation occurs before opening any target connection.
            self.delivered += 1
        try:
            status, body = self._transport()
            if (type(status) is not int or status != 200
                    or type(body) is not bytes or len(body) > MAX_TARGET_BODY_BYTES):
                raise ProtocolError("hedef yanıtı reddedildi")
        except Exception:
            with self._lock:
                self.failure = True
            return RelayReply(502)
        return RelayReply(200, SUCCESS_BODY)

    def success_gate(self, *, fixture_requests: int, raw_summary: bytes) -> bool:
        try:
            parse_fixed_summary(raw_summary)
        except ProtocolError:
            return False
        with self._lock:
            return (
                self.delivered == MAX_REQUESTS
                and self.denied == 0
                and not self.failure
                and not self.exhausted
                and type(fixture_requests) is int
                and fixture_requests == MAX_REQUESTS
            )
