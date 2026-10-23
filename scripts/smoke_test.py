#!/usr/bin/env python3
"""Sniper uçtan uca duman testi: geçici veri diziniyle ayrı portta sunucu başlatır.

Canlı veritabanına ve servise dokunmaz. Sağlık kontrolü, arayüz, tarama listesi, denetim
kaydı doğrulaması ve yerel (ağsız) denetçi uç noktalarını çağırır; sunucuyu kapatır.

Kullanım: python3 scripts/smoke_test.py [--keep-data]
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

APP_ROOT = Path(__file__).resolve().parents[1]

PY_SAMPLE = (
    "from flask import request\n"
    "@app.route('/s')\n"
    "def s():\n"
    "    term = request.args.get('q')\n"
    "    logger.info('t %s', term)\n"
)
MESH_SAMPLE = (
    "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\n"
    "metadata: {name: gw, namespace: web}\n"
    "spec:\n  listeners:\n  - name: web\n    protocol: HTTP\n    port: 80\n"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(base: str, method: str, path: str, payload: dict | None = None) -> tuple[int, bytes]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base + path, data=data, method=method)
    request.add_header("Origin", base)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sniper duman testi (geçici veri dizini)")
    parser.add_argument("--keep-data", action="store_true", help="Geçici veri dizinini silme")
    args = parser.parse_args(argv)

    data_dir = Path(tempfile.mkdtemp(prefix="sniper-smoke-"))
    os.chmod(data_dir, 0o700)
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ, SNIPER_DATA_DIR=str(data_dir), SNIPER_PORT=str(port), SNIPER_HOST="127.0.0.1",
               SNIPER_DISABLE_STARTUP_AUTODISCOVER="1", SNIPER_QUIET="1",
               SNIPER_AUDIT_KEY_FILE=str(data_dir / "integrity" / "audit.key"),
               SNIPER_AUDIT_ANCHOR_DIR=str(data_dir / "integrity" / "audit-anchors"))
    env.pop("SNIPER_ENABLE_PLUGINS", None)
    log_path = data_dir / "server.log"
    with open(log_path, "wb") as log:
        server = subprocess.Popen([sys.executable, str(APP_ROOT / "server.py")], cwd=APP_ROOT, env=env,
                                  stdout=log, stderr=subprocess.STDOUT)
    failures: list[str] = []
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if _request(base, "GET", "/api/health")[0] == 200:
                    break
            except OSError:
                pass
            if server.poll() is not None:
                break
            time.sleep(0.25)
        checks: list[tuple[str, str, dict | None, int, str]] = [
            ("GET", "/api/health", None, 200, '"status":"ok"'),
            ("GET", "/", None, 200, "<html"),
            ("GET", "/api/scans", None, 200, ""),
            ("GET", "/api/audit-log/verify", None, 200, "verified"),
            ("POST", "/api/cvss-ssvc/prioritize",
             {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, 200, '"score": 9.3'),
            ("POST", "/api/cvss-ssvc/prioritize", {"vector": "CVSS:4.0/AV:N"}, 400, ""),
            ("POST", "/api/audit-logging/audit", {"raw_content": PY_SAMPLE, "filename": "app.py"}, 200, "taint_flow"),
            ("POST", "/api/zero-trust-mesh/audit", {"raw_content": MESH_SAMPLE, "filename": "gw.yaml"}, 200, "Gateway API"),
        ]
        for method, path, payload, expected, needle in checks:
            try:
                status, body = _request(base, method, path, payload)
            except OSError as exc:
                failures.append(f"{method} {path}: bağlantı hatası {exc}")
                continue
            text = body.decode("utf-8", errors="replace")
            if needle == '"score": 9.3':
                ok = status == expected and json.loads(text).get("score") == 9.3
            else:
                ok = status == expected and needle in text
            print(f"{'GEÇTİ' if ok else 'BAŞARISIZ'}  {method} {path} → {status}")
            if not ok:
                failures.append(f"{method} {path}: {status} {text[:200]}")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        server_log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        if "Traceback" in server_log:
            failures.append("sunucu günlüğünde Traceback var:\n" + server_log[-2000:])
        if args.keep_data:
            print(f"Veri dizini korundu: {data_dir}")
        else:
            shutil.rmtree(data_dir, ignore_errors=True)
    if failures:
        print("SONUÇ: BAŞARISIZ")
        for failure in failures:
            print(" -", failure)
        return 1
    print("SONUÇ: TÜMÜ GEÇTİ")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
