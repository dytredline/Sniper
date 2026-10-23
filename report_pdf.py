"""HTML raporları PDF'e çevirme (17. tur): pinli Chromium + playwright-core, bwrap yalıtımında, ağsız.

Akış (tool_sandbox.py ile aynı katmanlar, aktarıcı yok):
1. Arayan: HTML'i (Sniper'ın kendi rapor üreticisinden; boyut sınırlı) veri dizinindeki özel iş dizinine yazar,
   yardımcıyı başlatır (servis kullanıcı ad alanındaysa kısıtlı geçici systemd kullanıcı birimi).
2. Yardımcı (``--helper``): pinli bwrap, Node, Chromium ve playwright-core'u doğrular; seccomp filtresini kurar.
3. Sandbox (bwrap): ayrı user/pid/net/ipc/uts/cgroup ad alanları, yeteneksiz; ağ ad alanında yalnız ``lo`` ve
   dinleyen hiçbir şey yok. Sürücü (sandbox_pdf_driver.cjs) JavaScript'i kapalı sayfada yalnız /job/report.html'i
   açar, her ağ/dosya isteğini reddeder ve /out/report.pdf yazar.

Sonuç PDF'i boyut sınırıyla okunur ve %PDF imzası denetlenir; iş dizini her durumda silinir.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DRIVER = APP_DIR / "sandbox_pdf_driver.cjs"
MAX_HTML_BYTES = 8 * 1024 * 1024
MAX_PDF_BYTES = 25 * 1024 * 1024
PAGE_FORMATS = ("A4", "Letter")
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 120
LOCK_NAME = "pdf"


class ReportPdfUnavailable(RuntimeError):
    """PDF bileşenleri (bwrap/Node/Chromium/playwright-core/seccomp) kullanılamıyor; ``reason`` kısa koddur."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ReportPdfBusy(RuntimeError):
    """Aynı anda yalnız bir PDF üretilir."""


class ReportPdfError(RuntimeError):
    """Üretim başarısız (süre aşımı, sürücü hatası, geçersiz çıktı); ``reason`` kısa koddur."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def driver_sha256() -> str:
    return hashlib.sha256(DRIVER.read_bytes()).hexdigest()


def _timeout() -> int:
    try:
        value = int(os.environ.get("SNIPER_PDF_TIMEOUT_SECONDS", DEFAULT_TIMEOUT))
    except ValueError:
        value = DEFAULT_TIMEOUT
    return max(15, min(MAX_TIMEOUT, value))


def readiness() -> dict:
    """Arayüz/hata iletisi için: bileşenler hazır mı (çalıştırmadan)."""
    import sandbox_seccomp
    import tool_sandbox as ts
    try:
        ts.open_bwrap().close()
        ts.open_node().close()
        ts.chromium_dir()
        ts.playwright_core_dir()
        sandbox_seccomp.build_filter()
    except ts.SandboxUnavailable as exc:
        return {"available": False, "reason": str(exc)}
    except sandbox_seccomp.SeccompUnsupported:
        return {"available": False, "reason": "seccomp_desteklenmiyor"}
    return {"available": True, "reason": None}


def filename_for(html_name: str) -> str:
    """``sniper-x.html`` → ``sniper-x.pdf`` (yalnız güvenli karakterler)."""
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", html_name)[:120]
    if stem.endswith(".html"):
        stem = stem[:-5]
    return (stem or "sniper-rapor") + ".pdf"


# ---------------------------------------------------------------------------
# Arayan taraf
# ---------------------------------------------------------------------------
def _helper_command(work: Path, unit: str, timeout: int, mode: str) -> list[str]:
    import tool_sandbox as ts
    helper = ["/usr/bin/python3", "-I", str(APP_DIR / "report_pdf.py"), "--helper", str(work)]
    if mode == "direct":
        return helper
    return [
        str(ts.SYSTEMD_RUN), "--user", "--wait", "--collect", "--pipe", "--quiet", "--unit=" + unit,
        "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes", "-p", "LockPersonality=yes",
        "-p", "RestrictRealtime=yes", "-p", "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "-p", "MemoryMax=1536M", "-p", "TasksMax=512", "-p", "CPUQuota=200%",
        "-p", f"RuntimeMaxSec={timeout + 45}", "-E", "PYTHONDONTWRITEBYTECODE=1",
    ] + helper


def render_pdf(document: str, *, page_format: str = "A4") -> bytes:
    """HTML belgeyi PDF baytlarına çevirir. Bileşen yoksa ``ReportPdfUnavailable``, meşgulse ``ReportPdfBusy``."""
    import tool_sandbox as ts
    if page_format not in PAGE_FORMATS:
        raise ValueError("Geçersiz sayfa biçimi.")
    data = document.encode("utf-8")
    if len(data) > MAX_HTML_BYTES:
        raise ReportPdfError("rapor_cok_buyuk")
    state = readiness()
    if not state["available"]:
        raise ReportPdfUnavailable(state["reason"] or "pdf_bilesenleri")
    try:
        parent = ts._private_dir(ts._data_dir() / "sandbox-runs")
    except ts.SandboxUnavailable as exc:
        raise ReportPdfUnavailable(str(exc)) from exc
    try:
        lock_fd = ts._lock(LOCK_NAME, parent)
    except ts.SandboxBusy as exc:
        raise ReportPdfBusy("mesgul") from exc
    timeout = _timeout()
    unit = "sniper-pdf-" + uuid.uuid4().hex[:20]
    work: Path | None = None
    try:
        work = Path(tempfile.mkdtemp(prefix="pdf-", dir=parent))
        for sub in ("job", "out"):
            (work / sub).mkdir(mode=0o700)
        ts._write(work / "job" / "report.html", data, 0o644)
        plan = {"timeout_ms": (timeout - 10) * 1000, "page_format": page_format}
        ts._write(work / "job" / "plan.json", json.dumps(plan).encode(), 0o644)
        ts._write(work / "spec.json", json.dumps({"timeout": timeout}).encode())
        mode = ts.launch_mode()
        finished = False
        try:
            try:
                completed = subprocess.run(
                    _helper_command(work, unit, timeout, mode), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 60, close_fds=True,
                    check=False,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                         "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"),
                         **{k: os.environ[k] for k in ts.PASS_ENV if k in os.environ}},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ReportPdfError("yardimci_basarisiz") from exc
            finished = True
        finally:
            if not finished and mode == "systemd-run":
                subprocess.run([str(ts.SYSTEMCTL), "--user", "stop", unit], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
        if completed.returncode == 3:
            lines = completed.stderr.decode("ascii", "replace").strip().splitlines()
            reason = lines[-1] if lines and re.fullmatch(r"[a-z0-9_]{1,64}", lines[-1]) else "sandbox"
            raise ReportPdfUnavailable(reason)
        raw = _read_helper_result(work)
        if completed.returncode != 0 or raw is None:
            if os.environ.get("SNIPER_SANDBOX_DEBUG") == "1":
                sys.stderr.write(completed.stderr.decode("utf-8", "replace")[-3000:])
            raise ReportPdfError("yardimci_basarisiz")
        outer = json.loads(raw)
        if outer.get("timed_out"):
            raise ReportPdfError("sure_asildi")
        if outer.get("exit_code") != 0:
            if os.environ.get("SNIPER_SANDBOX_DEBUG") == "1":
                sys.stderr.write(str(outer.get("stderr", ""))[-3000:])
            raise ReportPdfError("pdf_surucu_basarisiz")
        try:
            pdf = ts.read_output(work, "report.pdf", MAX_PDF_BYTES)
        except ts.SandboxExecutionError as exc:
            raise ReportPdfError("pdf_cok_buyuk") from exc
        if not pdf or not pdf.startswith(b"%PDF-"):
            raise ReportPdfError("pdf_gecersiz")
        return pdf
    finally:
        try:
            if work is not None:
                shutil.rmtree(work, ignore_errors=True)
        finally:
            os.close(lock_fd)


def _read_helper_result(work: Path) -> bytes | None:
    try:
        fd = os.open(work / "helper.json", os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        return handle.read(65537)[:65536]


# ---------------------------------------------------------------------------
# Yardımcı (geçici birimde ya da doğrudan alt süreç olarak)
# ---------------------------------------------------------------------------
def _helper(work_text: str) -> int:
    import stat

    import sandbox_seccomp
    import tool_sandbox as ts
    work = Path(work_text)
    try:
        meta = os.lstat(work)
    except OSError:
        return ts._fail("is_dizini")
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        return ts._fail("is_dizini")
    spec = json.loads((work / "spec.json").read_bytes()[:4096])
    timeout = int(spec.get("timeout", DEFAULT_TIMEOUT))
    if not 15 <= timeout <= MAX_TIMEOUT:
        return ts._fail("is_tanimi")
    try:
        bwrap = ts.open_bwrap()
    except ts.SandboxUnavailable as exc:
        return ts._fail(str(exc))
    opened: list[int] = []
    try:
        try:
            node = ts.open_node()
            browser_dir = ts.chromium_dir()
            core_dir = ts.playwright_core_dir()
            program = sandbox_seccomp.build_filter()
        except ts.SandboxUnavailable as exc:
            return ts._fail(str(exc))
        except sandbox_seccomp.SeccompUnsupported:
            return ts._fail("seccomp_desteklenmiyor")
        opened.append(node.fd)
        driver_fd = os.open(DRIVER, os.O_RDONLY | os.O_NOFOLLOW)
        opened.append(driver_fd)
        seccomp_fd = ts._data_fd(program, opened)
        hosts_fd = ts._data_fd(ts.hosts_file(None), opened)
        fds = [bwrap.fd, node.fd, driver_fd, seccomp_fd, hosts_fd]
        binds = ["--dir", "/sbx", "--perms", "0444", "--ro-bind-data", str(driver_fd), "/sbx/pdf_driver.cjs",
                 "--perms", "0444", "--ro-bind-data", str(hosts_fd), "/etc/hosts",
                 "--dir", "/opt/node", "--perms", "0555", "--ro-bind-data", str(node.fd), "/opt/node/node",
                 "--ro-bind", str(browser_dir), "/opt/chromium", "--ro-bind", str(core_dir), "/opt/playwright-core",
                 "--ro-bind-try", "/etc/fonts", "/etc/fonts", "--tmpfs", "/dev/shm",
                 "--ro-bind", str(work / "job"), "/job", "--bind", str(work / "out"), "/out",
                 "--setenv", "PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS", "1",
                 "--setenv", "NODE_OPTIONS", "--max-old-space-size=384", "--setenv", "TMPDIR", "/tmp"]
        argv = ts.bwrap_argv(bwrap.fd, binds, seccomp_fd=seccomp_fd) + \
            ["/opt/node/node", "/sbx/pdf_driver.cjs", "/job/plan.json"]
        started = time.monotonic()
        timed_out = False
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, pass_fds=tuple(fds), close_fds=True,
                                   start_new_session=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        try:
            _, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
            _, err = process.communicate(timeout=10)
        outer = {"exit_code": process.returncode, "timed_out": timed_out,
                 "elapsed_s": round(time.monotonic() - started, 2),
                 "stderr": (err or b"")[-600:].decode("utf-8", "replace") if process.returncode else ""}
        # Sonuç sandbox'ın yazabildiği /out dışında tutulur (sürücü önceden dosya oluşturup bozamaz).
        ts._write(work / "helper.json", json.dumps(outer).encode())
        return 0
    finally:
        bwrap.close()
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    # python3 -I betik dizinini sys.path'e eklemez; yalnız uygulama dizini eklenir.
    sys.path.insert(0, str(APP_DIR))
    if len(sys.argv) == 3 and sys.argv[1] == "--helper":
        sys.exit(_helper(sys.argv[2]))
    sys.stderr.write("kullanim\n")
    sys.exit(4)
