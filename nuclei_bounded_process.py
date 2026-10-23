import os
import signal
import sys
import threading
import time
import hashlib
from pathlib import Path
from subprocess import Popen, DEVNULL
from typing import Dict, Any, Optional

class BoundedNucleiProcess:
    def __init__(self, timeout_seconds: float = 3600.0, max_report_bytes: int = 1_000_000):
        self._timeout_seconds = timeout_seconds
        self._max_report_bytes = max_report_bytes
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._state: str = "pending"
        self._proc: Optional[Popen] = None
        self._exit_code: Optional[int] = None
        self._report_sha256: Optional[str] = None
        self._start_time: Optional[float] = None
        self._supervisor_thread: Optional[threading.Thread] = None
        self._launched = False
        self._report_path: Optional[Path] = None

    def _check_report(self) -> None:
        try:
            if self._report_path is None:
                return
            size = os.path.getsize(self._report_path)
            if size > self._max_report_bytes:
                self._terminate("report_exceeded")
        except (OSError, ValueError):
            pass

    def _supervisor(self, argv: list, env: dict) -> None:
        try:
            self._start_time = time.monotonic()
            with self._lock:
                if self._state != "pending":
                    return
                self._state = "running"
            try:
                with self._lock:
                    is_cancelled = self._state in ("cancelling", "cancelled")
                if is_cancelled:
                    return
                self._proc = Popen(
                    argv,
                    stdin=DEVNULL,
                    stdout=DEVNULL,
                    stderr=DEVNULL,
                    start_new_session=True,
                    env=env
                )
            except Exception:
                with self._lock:
                    if self._state in ("pending", "running"):
                        self._state = "failed"
                        self._exit_code = "spawn_failed"
                self._event.set()
                return

            try:
                while True:
                    with self._lock:
                        if self._state in ("cancelling", "cancelled", "failed", "completed"):
                            break
                    if self._proc.poll() is not None:
                        break
                    if self._event.wait(0.25):
                        break
                    if self._start_time and time.monotonic() - self._start_time > self._timeout_seconds:
                        self._terminate("timeout")
                        break
                    self._check_report()
            finally:
                if self._proc and self._proc.poll() is None:
                    try:
                        os.killpg(self._proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                exit_code = self._proc.wait() if self._proc else -1
                with self._lock:
                    if self._state == "running":
                        if exit_code == 0:
                            try:
                                if self._report_path is None:
                                    raise OSError("report_path ayarlanmamış")
                                stat = os.stat(self._report_path)
                                if stat.st_size > self._max_report_bytes:
                                    self._state = "report_exceeded"
                                    raise OSError("report_exceeded")
                                with open(self._report_path, "rb") as f:
                                    data = f.read(self._max_report_bytes + 1)
                                if len(data) > self._max_report_bytes:
                                    self._state = "report_exceeded"
                                    raise OSError("report_exceeded")
                                self._state = "completed"
                                self._report_sha256 = hashlib.sha256(data[:self._max_report_bytes]).hexdigest()
                            except OSError:
                                self._state = "failed"
                                self._exit_code = -2
                        else:
                            self._state = "failed"
                            self._exit_code = exit_code
                    self._event.set()

        except Exception:
            with self._lock:
                if self._state in ("pending", "running"):
                    self._state = "failed"
                self._exit_code = -1
            self._event.set()

    def _terminate(self, reason: str) -> None:
        with self._lock:
            if self._state in ("cancelling", "cancelled", "failed", "completed"):
                return
            if self._state == "pending":
                self._state = "cancelled"
                self._event.set()
                return
            self._state = "cancelling"
        if self._proc:
            try:
                os.killpg(self._proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        exit_code = -1
        if self._proc:
            try:
                exit_code = self._proc.wait()
            except (ProcessLookupError, PermissionError, OSError):
                exit_code = -1
        with self._lock:
            if reason == "timeout":
                self._state = "failed"
                self._exit_code = "timeout"
            elif reason == "report_exceeded":
                self._state = "failed"
                self._exit_code = "report_exceeded"
            else:
                self._state = "failed"
                self._exit_code = "nonzero_exit"
        self._event.set()

    def start(self, argv: list, report_path: Path) -> dict:
        with self._lock:
            if self._launched:
                raise RuntimeError("Süreç zaten başlatıldı")
            self._launched = True
            if not argv or not isinstance(argv, list) or not all(isinstance(x, str) for x in argv):
                raise ValueError("argv boş olmayan bir metin listesi olmalı")
            exe = argv[0]
            if not os.path.isabs(exe):
                raise ValueError("Çalıştırılabilir yolu mutlak olmalı")
            if not os.path.isfile(exe):
                raise ValueError("Çalıştırılabilir dosya yok")
            if not os.access(exe, os.X_OK):
                raise ValueError("Çalıştırılabilir dosya çalıştırılabilir değil")
            if not report_path.is_absolute():
                raise ValueError("report_path mutlak olmalı")
            if not report_path.exists():
                raise ValueError("report_path yok")
            if report_path.is_symlink():
                raise ValueError("report_path sembolik bağ olmamalı")
            try:
                stat = os.stat(report_path)
            except OSError:
                raise ValueError("report_path bilgisi alınamadı")
            if stat.st_uid != os.getuid():
                raise ValueError("report_path geçerli kullanıcıya ait değil")
            mode = stat.st_mode & 0o777
            if mode != 0o600:
                raise ValueError("report_path izni 0600 olmalı")
            self._report_path = report_path

        env = {
            "HOME": str(report_path.parent),
            "TMPDIR": str(report_path.parent),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8"
        }

        with self._lock:
            if self._state == "cancelled":
                return {"state": "cancelled", "elapsed_seconds": 0}
            self._state = "pending"
            self._event.clear()

        self._supervisor_thread = threading.Thread(
            target=self._supervisor,
            args=(argv, env),
            daemon=True
        )
        self._supervisor_thread.start()

        with self._lock:
            elapsed = time.monotonic() - self._start_time if self._start_time else 0.0
            return {"state": self._state, "elapsed_seconds": elapsed}

    def status(self) -> dict:
        with self._lock:
            if self._state in ("failed", "completed"):
                result = {"state": self._state, "elapsed_seconds": time.monotonic() - self._start_time if self._start_time else 0}
                if self._state == "failed" and self._exit_code is not None:
                    result["error_code"] = self._exit_code
                if self._state == "completed" and self._report_sha256:
                    result["report_sha256"] = self._report_sha256
                return result
            elif self._state == "cancelling":
                return {"state": "cancelling", "elapsed_seconds": time.monotonic() - self._start_time if self._start_time else 0}
            elif self._state == "cancelled":
                return {"state": "cancelled", "elapsed_seconds": time.monotonic() - self._start_time if self._start_time else 0}
            elif self._state == "running":
                return {"state": "running", "elapsed_seconds": time.monotonic() - self._start_time if self._start_time else 0}
            else:
                return {"state": "pending", "elapsed_seconds": 0}

    def cancel(self) -> dict:
        with self._lock:
            if self._state == "cancelled":
                return {"state": "cancelled", "elapsed_seconds": 0.0}
            if self._state == "pending":
                self._state = "cancelled"
                self._event.set()
                return {"state": "cancelled", "elapsed_seconds": 0.0}
            if self._state in ("failed", "completed"):
                return self._build_final()
            self._state = "cancelled"
            self._event.set()

        if self._supervisor_thread:
            self._supervisor_thread.join(timeout=30)

        return self._build_final()

    def _build_final(self) -> dict:
        elapsed = time.monotonic() - self._start_time if self._start_time else 0.0
        if self._state == "cancelled":
            return {"state": "cancelled", "elapsed_seconds": elapsed}
        elif self._state == "failed" and self._exit_code is not None:
            return {"state": "failed", "elapsed_seconds": elapsed, "error_code": self._exit_code}
        elif self._state == "completed" and self._report_sha256:
            return {"state": "completed", "elapsed_seconds": elapsed, "report_sha256": self._report_sha256}
        else:
            return {"state": self._state, "elapsed_seconds": elapsed}
