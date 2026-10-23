"""Run one ZAP passive request against Sniper's own loopback health endpoint.

This is intentionally not a spider or an active scan. The HTTP API cannot
choose a target, method, rule, image, or command line.
"""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from tool_report_zap import parse_zap_traditional_json_summary


SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMD_RUN_SHA256 = "0253595d482ea0aa9c4bf2e58080e9615bc59a51e29dbe1cebd14145b92bd8fc"
SYSTEMCTL = Path("/usr/bin/systemctl")
SYSTEMCTL_SHA256 = "1bf2f1e98c533b0313a78143ffcda2690116d90d76816dc7b74df79c4767aa95"
_PORTABLE_RUNTIME_ROOT = Path(os.environ.get(
    "SNIPER_PORTABLE_RUNTIMES_DIR",
    str(Path.home() / ".local" / "state" / "sniper-tool-runtimes"),
)).expanduser()
RUNTIME = Path(os.environ.get(
    "SNIPER_ZAP_RUNTIME_DIR",
    str(_PORTABLE_RUNTIME_ROOT / "zap-2.17.0-arm64"),
)).expanduser()
PINNED_FILES = {
    "zap/zap.sh": "14cbae7c389e1b9fdbfe43dab82163f44e486a391792f1fc74e77e7092f38999",
    "zap/zap-2.17.0.jar": "015dda4709b5ef79736086bb41e8e2a4e95b04cf6625f14d6bcc02b197c99c0c",
    "java17/bin/java": "ea5be6b2f621724689de59a9af1801b4fc5ce4eaf71898f9ce38b0f05abadb7c",
    "java17/conf/security/java.security": "e96a92c44eca826ffd37077799a3188a6074aaef51aad49599a000116b83fde1",
    "java17/lib/security/cacerts": "2635257dbf909d73e2bdfa697e06109cf524771c2fe7ea149b3c12dfee4120cc",
}
MAX_REPORT_BYTES = 2_000_000
RUN_TIMEOUT_SECONDS = 240


class ZapUnavailable(RuntimeError):
    pass


class ZapBusy(RuntimeError):
    pass


class ZapExecutionError(RuntimeError):
    pass


def _trusted_runtime() -> tuple[str, Path]:
    for path, expected in (
        (SYSTEMD_RUN, SYSTEMD_RUN_SHA256),
        (SYSTEMCTL, SYSTEMCTL_SHA256),
        *((RUNTIME / name, digest) for name, digest in PINNED_FILES.items()),
    ):
        try:
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ZapUnavailable("Sabitlenmiş ZAP çalışma zamanı kullanılamıyor.")
        except OSError as exc:
            raise ZapUnavailable("Sabitlenmiş ZAP çalışma zamanı kullanılamıyor.") from exc
    if not os.access(SYSTEMD_RUN, os.X_OK) or not os.access(RUNTIME / "zap/zap.sh", os.X_OK):
        raise ZapUnavailable("Sabitlenmiş ZAP çalışma zamanı kullanılamıyor.")
    return str(SYSTEMD_RUN), RUNTIME


def _lock_scan() -> int:
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise ZapUnavailable("Sniper veri dizini kullanılamıyor.")
    path = Path(data_dir) / "zap-self-passive.lock"
    fd = None
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise OSError("geçersiz kilit")
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        raise ZapUnavailable("ZAP kilidi kullanılamıyor.") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise ZapBusy("Bir ZAP taraması zaten sürüyor.") from exc
    return fd


def _plan(port: int, report_dir: str) -> str:
    target = f"http://127.0.0.1:{port}/api/health"
    return f'''env:
  contexts:
    - name: sniper-self-health
      urls:
        - "{target}"
      includePaths:
        - '^http://127[.]0[.]0[.]1:{port}/api/health$'
  parameters:
    failOnError: true
    failOnWarning: false
    continueOnFailure: false
    progressToStdout: true
    maxDuration: 180
jobs:
  - type: passiveScan-config
    parameters:
      scanOnlyInScope: true
      maxAlertsPerRule: 20
      maxBodySizeInBytesToScan: 65536
  - type: requestor
    requests:
      - url: "{target}"
        method: GET
        responseCode: 200
  - type: passiveScan-wait
    parameters:
      maxDuration: 2
  - type: report
    parameters:
      template: traditional-json
      reportDir: {report_dir}
      reportFile: report.json
      displayReport: false
'''


def _stop_unit(name: str) -> None:
    try:
        subprocess.run(
            [str(SYSTEMCTL), "--user", "stop", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def run_zap_self_passive(host: str, port: int) -> dict:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Sniper ana makinesi loopback olmalı") from exc
    if address.version != 4 or address != ipaddress.ip_address("127.0.0.1"):
        raise ValueError("Sniper ana makinesi 127.0.0.1 olmalı")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Sniper portu 1..65535 olmalı")

    binary, runtime = _trusted_runtime()
    lock_fd = _lock_scan()
    try:
        # sniper.service has PrivateTmp=true. A Docker daemon cannot bind a path
        # from that private /tmp namespace, so keep the short-lived work area in
        # the service's explicitly writable data directory instead.
        data_dir = Path(os.environ["SNIPER_DATA_DIR"])
        if data_dir.is_symlink() or not data_dir.is_dir() or data_dir.stat().st_uid != os.getuid():
            raise ZapUnavailable("Sniper veri dizini kullanılamıyor.")
        with tempfile.TemporaryDirectory(prefix="sniper_zap_", dir=data_dir) as temp:
            work = Path(temp)
            (work / "plan.yaml").write_text(_plan(port, str(work)), encoding="utf-8")
            name = "sniper-zap-" + uuid.uuid4().hex[:20]
            command = [
                binary, "--user", "--wait", "--collect", "--pipe", "--unit=" + name,
                "-p", "PrivateTmp=yes", "-p", "ProtectSystem=strict",
                "-p", "ProtectHome=read-only", "-p", "ReadWritePaths=" + str(work),
                "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes",
                "-p", "LockPersonality=yes", "-p", "RestrictRealtime=yes",
                "-p", "MemoryMax=2G", "-p", "TasksMax=256",
                "-p", "CPUQuota=200%", "-p", "RuntimeMaxSec=240",
                "-E", "HOME=" + str(work),
                "-E", "JAVA_HOME=" + str(runtime / "java17"),
                str(runtime / "zap/zap.sh"), "-Xmx1024m", "-cmd", "-autorun", str(work / "plan.yaml"),
            ]
            started = time.monotonic()
            try:
                with (work / "zap.log").open("wb") as log:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        env={"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8",
                             "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")},
                    )
                    try:
                        exit_code = process.wait(timeout=RUN_TIMEOUT_SECONDS + 10)
                    except subprocess.TimeoutExpired as exc:
                        _stop_unit(name)
                        process.kill()
                        process.wait(timeout=5)
                        raise ZapExecutionError("ZAP çalıştırması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise ZapExecutionError("ZAP çalıştırması başarısız oldu.") from exc
            if exit_code:
                raise ZapExecutionError("ZAP çalıştırması başarısız oldu.")
            report = work / "report.json"
            try:
                info = report.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                    raise ValueError("geçersiz rapor")
                data = json.loads(report.read_text(encoding="utf-8"))
                summary = parse_zap_traditional_json_summary(data)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                raise ZapExecutionError("ZAP raporu doğrulamadan geçemedi.") from exc
            summary["format"] = "zap-self-passive-v1"
            summary["profile"] = "single-health-get-passive-v1"
            summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
            return summary
    finally:
        os.close(lock_fd)
