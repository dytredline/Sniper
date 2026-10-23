#!/usr/bin/env python3
"""Loopback Sniper uçlarını mevcut oturum çereziyle salt okunur doğrula."""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ENDPOINTS = ("/api/health", "/api/self-analysis", "/api/tooling/readiness")


def run(base_url: str, cookie: str, *, timeout: float = 30.0, opener=urlopen) -> dict:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"} \
            or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Smoke hedefi yalnız açık metin kimlik bilgisi içermeyen loopback HTTP adresi olabilir.")
    if not cookie.strip() or "\r" in cookie or "\n" in cookie or len(cookie) > 4096:
        raise ValueError("Geçerli oturum Cookie başlığı stdin üzerinden gerekli.")
    results = []
    for path in ENDPOINTS:
        request = Request(base_url.rstrip("/") + path, headers={"Cookie": cookie.strip(), "Accept": "application/json"})
        with opener(request, timeout=timeout) as response:
            body = response.read(2_000_001)
            if response.status != 200 or len(body) > 2_000_000:
                raise RuntimeError(f"Smoke başarısız: {path} HTTP {response.status}")
            payload = json.loads(body)
            if not isinstance(payload, dict) or payload.get("error"):
                raise RuntimeError(f"Smoke geçersiz yanıt döndürdü: {path}")
            results.append({"path": path, "status": response.status})
    return {"format": "sniper-authenticated-smoke/1", "ok": True, "results": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8787")
    parser.add_argument("--cookie-stdin", action="store_true", required=True)
    args = parser.parse_args(argv)
    cookie = sys.stdin.readline().rstrip("\n")
    print(json.dumps(run(args.base_url, cookie), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
