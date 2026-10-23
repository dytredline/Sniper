"""Uzun süren araç çalıştırmaları için sınırlı, bellek içi iş kuyruğu.

HTTP isteği iş kimliğini (202) hemen alır; araç arka plandaki sınırlı sayıdaki iş
parçacığında çalışır. Özellikler:

* Eşzamanlılık (``workers``) ve bekleyen iş (``max_queued``) sınırları; dolu kuyruk reddedilir.
* Durumlar: ``queued``, ``running``, ``succeeded``, ``failed``, ``cancelled``, ``expired``.
* Aynı ``dedupe_key`` (rota + hedef) için etkin bir iş varken ikinci iş reddedilir.
* İptal ve süre aşımı: işin iş parçacığında başlatılan alt süreçler (``subprocess.Popen``)
  izlenir; iptalde/süre aşımında kendi süreç grubu liderleri ``killpg(SIGKILL)`` ile, aksi
  halde doğrudan süreç ``kill`` ile durdurulur. Saf Python adımları zorla kesilemez: sonuç
  atılır, iş "cancelled"/"expired" olur ve yuva iş parçacığı bitince boşalır.
* Hata ayrıntısı (traceback, yol) istemciye gitmez; yalnız sunucu günlüğüne yazılır.
* Biten işler ``retention_seconds`` sonra veya ``max_retained`` aşılınca bellekten silinir.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import signal
import subprocess
import threading
import time
import traceback
from typing import Any, Callable

ACTIVE_STATES = frozenset({"queued", "running"})
FINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "expired", "interrupted"})
INTERRUPTED_MESSAGE = "Servis yeniden başladığı için iş yarıda kaldı; gerekirse yeniden başlatın."
_JOB_ID_RE = re.compile(r"job_[0-9a-f]{24}\Z")
_MAX_PERSISTED_FILES = 500
GENERIC_FAILURE = "İş beklenmeyen bir hatayla sonlandı; ayrıntılar sunucu günlüğünde."
# Sonuç boyut sınırını aşınca bile saklanan küçük kimlik alanları (ör. kayıtlı proje analizinin kimliği).
_RESULT_ID_KEYS = ("id", "project_name", "project_path", "file_count", "finding_count", "finding_counts", "score", "grade")


class JobQueueError(Exception):
    status = 400


class QueueFull(JobQueueError):
    status = 503


class DuplicateJob(JobQueueError):
    status = 409


class JobPersistenceError(JobQueueError):
    status = 503


# İşin yürütüldüğü iş parçacığında etkin iş (Popen izleme için).
_CURRENT = threading.local()
_HOOK_LOCK = threading.Lock()
_ORIGINAL_POPEN_INIT: Any = None


def _install_popen_hook() -> None:
    """``subprocess.Popen`` örneklerini başlatan iş parçacığının işine kaydet (bir kez)."""
    global _ORIGINAL_POPEN_INIT
    with _HOOK_LOCK:
        if _ORIGINAL_POPEN_INIT is not None:
            return
        original = subprocess.Popen.__init__

        def __init__(self: subprocess.Popen, *args: Any, **kwargs: Any) -> None:
            original(self, *args, **kwargs)
            job = getattr(_CURRENT, "job", None)
            if job is not None:
                job._track(self)

        subprocess.Popen.__init__ = __init__  # type: ignore[method-assign]
        _ORIGINAL_POPEN_INIT = original


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        pgid = os.getpgid(process.pid)
        if pgid == process.pid and pgid != os.getpgrp():
            os.killpg(pgid, signal.SIGKILL)
        else:
            # Sunucunun kendi grubunu asla öldürme: yalnız doğrudan alt süreç.
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Job:
    id: str
    route: str
    dedupe_key: str
    runner: Callable[["Job"], tuple[int, Any]] | None
    created_at: str = field(default_factory=_now)
    created_monotonic: float = field(default_factory=time.monotonic)
    state: str = "queued"
    started_at: str | None = None
    finished_at: str | None = None
    finished_monotonic: float | None = None
    http_status: int | None = None
    result: Any = None
    error: str | None = None
    result_truncated: bool = False
    cancel_requested: bool = False
    expired: bool = False
    # İlerleme (aşama, yüzde, done/total) ve kullanıcıya gösterilecek kısa etiket (ör. proje adı).
    progress: dict[str, Any] | None = None
    label: str | None = None
    # 25. tur: işe özgü süre sınırı (ör. toplu depo taraması saatler sürebilir); None → kuyruğun genel sınırı.
    timeout_seconds: float | None = None
    processes: list[subprocess.Popen] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def _track(self, process: subprocess.Popen) -> None:
        with self.lock:
            self.processes = [p for p in self.processes if p.poll() is None]
            self.processes.append(process)
            stop = self.cancel_requested or self.expired
        if stop:
            _terminate(process)

    def set_progress(self, progress: dict[str, Any]) -> None:
        """İş çalışırken ilerlemeyi güncelle (iş parçacığı güvenli; bitmiş işte yok sayılır)."""
        if not isinstance(progress, dict):
            return
        with self.lock:
            if self.state == "running":
                self.progress = dict(progress)

    def stop_processes(self) -> int:
        with self.lock:
            processes = list(self.processes)
        alive = [p for p in processes if p.poll() is None]
        for process in alive:
            _terminate(process)
        return len(alive)

    def public(self, *, include_result: bool = True, position: int | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "route": self.route,
            "state": self.state,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "http_status": self.http_status,
            "cancel_requested": self.cancel_requested,
        }
        if self.label:
            data["label"] = self.label
        progress = self.progress
        if self.state == "succeeded":
            progress = {"stage": "done", "label": "Tamamlandı", "percent": 100.0}
        if progress:
            data["progress"] = dict(progress)
        if position is not None:
            data["queue_position"] = position
        if self.error:
            data["error"] = self.error
        if include_result and self.state == "succeeded":
            data["result"] = self.result
            data["result_truncated"] = self.result_truncated
        return data


class JobQueue:
    def __init__(
        self,
        *,
        workers: int = 2,
        max_queued: int = 20,
        timeout_seconds: float = 1800.0,
        retention_seconds: float = 3600.0,
        max_retained: int = 200,
        max_result_bytes: int = 2_000_000,
        on_finish: Callable[[Job], None] | None = None,
        store_dir: Path | None = None,
    ) -> None:
        self.workers = max(1, int(workers))
        self.max_queued = max(1, int(max_queued))
        self.timeout_seconds = float(timeout_seconds)
        self.retention_seconds = float(retention_seconds)
        self.max_retained = max(1, int(max_retained))
        self.max_result_bytes = int(max_result_bytes)
        self.on_finish = on_finish
        self._lock = threading.Lock()
        self._wakeup = threading.Condition(self._lock)
        self._jobs: dict[str, Job] = {}
        self._pending: deque[str] = deque()
        self._threads: list[threading.Thread] = []
        self._running = 0
        # Kalıcılık: iş kayıtları (ve başarılı sonuç) store_dir/<id>.json (0600) dosyalarında;
        # yeniden başlatmada yarıda kalan işler "interrupted" olarak görünür.
        self._store_required = store_dir is not None
        self.store_dir = self._prepare_store(store_dir)
        if self.store_dir is not None:
            self._load()

    # -- kalıcılık -------------------------------------------------------------------
    @staticmethod
    def _prepare_store(store_dir: Path | None) -> Path | None:
        if store_dir is None:
            return None
        try:
            store_dir.mkdir(mode=0o700, exist_ok=True)
            info = os.lstat(store_dir)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                return None
        except OSError:
            return None
        return store_dir

    def _persist(self, job: Job, *, strict: bool = False) -> None:
        if self.store_dir is None:
            if strict and self._store_required:
                raise JobPersistenceError("İş kalıcı depo dizini güvenli değil.")
            return
        record = job.public(include_result=True)
        record["finished_epoch"] = time.time() if job.state in FINAL_STATES else None
        try:
            fd, tmp = tempfile.mkstemp(prefix=".job-", dir=self.store_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle, ensure_ascii=False, default=str)
            os.replace(tmp, self.store_dir / f"{job.id}.json")
        except (OSError, TypeError, ValueError) as exc:
            try:
                os.unlink(tmp)
            except (OSError, UnboundLocalError):
                pass
            if strict:
                raise JobPersistenceError("İş kaydı kalıcı depoya yazılamadı.") from exc

    def _unpersist(self, job_id: str) -> None:
        if self.store_dir is not None and _JOB_ID_RE.fullmatch(job_id):
            try:
                (self.store_dir / f"{job_id}.json").unlink()
            except OSError:
                pass

    def _load(self) -> None:
        assert self.store_dir is not None
        now_wall, now_mono = time.time(), time.monotonic()
        entries = sorted(self.store_dir.glob("job_*.json"))[-_MAX_PERSISTED_FILES:]
        for path in entries:
            if not _JOB_ID_RE.fullmatch(path.stem):
                continue
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_result_bytes + 65_536:
                        continue
                    data = json.loads(os.read(fd, info.st_size + 1))
                finally:
                    os.close(fd)
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict) or data.get("id") != path.stem:
                continue
            job = Job(id=path.stem, route=str(data.get("route", "")), dedupe_key="", runner=None,
                      label=str(data["label"])[:120] if isinstance(data.get("label"), str) else None)
            job.created_at = str(data.get("created_at") or job.created_at)
            job.started_at = data.get("started_at")
            job.http_status = data.get("http_status") if isinstance(data.get("http_status"), int) else None
            job.error = data.get("error") if isinstance(data.get("error"), str) else None
            job.cancel_requested = bool(data.get("cancel_requested"))
            state = data.get("state")
            if state in FINAL_STATES:
                job.state = state
                job.finished_at = data.get("finished_at")
                epoch = data.get("finished_epoch")
                age = max(0.0, now_wall - float(epoch)) if isinstance(epoch, (int, float)) else 0.0
                job.finished_monotonic = now_mono - age
                if state == "succeeded":
                    job.result = data.get("result")
                    job.result_truncated = bool(data.get("result_truncated"))
            else:
                job.state = "interrupted"
                job.error = INTERRUPTED_MESSAGE
                job.finished_at = _now()
                job.finished_monotonic = now_mono
                self._persist(job)
            job.created_monotonic = job.finished_monotonic or now_mono
            self._jobs[job.id] = job
        self._purge()

    # -- yönetim -------------------------------------------------------------------
    def _ensure_workers(self) -> None:
        if self._threads:
            return
        _install_popen_hook()
        for index in range(self.workers):
            thread = threading.Thread(target=self._worker, name=f"sniper-job-{index + 1}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def _purge(self) -> None:
        now = time.monotonic()
        finished = [job for job in self._jobs.values() if job.state in FINAL_STATES]
        for job in finished:
            if job.finished_monotonic is not None and now - job.finished_monotonic > self.retention_seconds:
                del self._jobs[job.id]
                self._unpersist(job.id)
        finished = [job for job in self._jobs.values() if job.state in FINAL_STATES]
        excess = len(self._jobs) - self.max_retained
        for job in sorted(finished, key=lambda j: j.finished_monotonic or 0.0)[: max(0, excess)]:
            del self._jobs[job.id]
            self._unpersist(job.id)

    def submit(self, route: str, runner: Callable[[Job], tuple[int, Any]], *, dedupe_key: str,
               label: str | None = None, timeout_seconds: float | None = None,
               before_enqueue: Callable[[Job], None] | None = None) -> Job:
        with self._lock:
            self._purge()
            for job in self._jobs.values():
                if job.dedupe_key == dedupe_key and job.state in ACTIVE_STATES:
                    raise DuplicateJob(f"Aynı araç ve hedef için etkin bir iş zaten var ({job.id}).")
            if len(self._pending) >= self.max_queued:
                raise QueueFull("İş kuyruğu dolu; çalışan işlerin bitmesini bekleyin.")
            job = Job(id="job_" + secrets.token_hex(12), route=route, dedupe_key=dedupe_key, runner=runner,
                      label=(str(label)[:120] if label else None),
                      timeout_seconds=(float(timeout_seconds) if timeout_seconds else None))
            # Worker creation can fail (thread limits/monkeypatched runtime).  Do it while no
            # durable caller binding or published queue entry exists; idle workers cannot run.
            self._ensure_workers()
            # First make the reserved id durable, then bind any caller-owned record to it.
            # Only after both writes succeed does the job become visible or runnable.
            persisted = False
            try:
                self._persist(job, strict=True)
                persisted = self.store_dir is not None
                if before_enqueue is not None:
                    before_enqueue(job)
            except Exception:
                if persisted:
                    self._unpersist(job.id)
                raise
            try:
                self._jobs[job.id] = job
                self._pending.append(job.id)
                self._wakeup.notify()
            except Exception:
                self._jobs.pop(job.id, None)
                try:
                    self._pending.remove(job.id)
                except ValueError:
                    pass
                if persisted:
                    self._unpersist(job.id)
                raise
            return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._purge()
            job = self._jobs.get(job_id)
            return job.public(position=self._position(job)) if job else None

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            self._purge()
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_monotonic, reverse=True)
            return [job.public(include_result=False, position=self._position(job)) for job in jobs]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "workers": self.workers,
                "running": self._running,
                "queued": len(self._pending),
                "max_queued": self.max_queued,
                "timeout_seconds": self.timeout_seconds,
            }

    def _position(self, job: Job) -> int | None:
        if job.state != "queued":
            return None
        try:
            return list(self._pending).index(job.id) + 1
        except ValueError:
            return None

    def cancel(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if job.state in FINAL_STATES:
                return job.public()
            job.cancel_requested = True
            if job.state == "queued":
                try:
                    self._pending.remove(job.id)
                except ValueError:
                    pass
                self._finish_locked(job, "cancelled")
                finished = job
            else:
                finished = None
        if finished is not None:
            self._notify_finish(finished)
        else:
            job.stop_processes()
        return job.public()

    # -- yürütme -------------------------------------------------------------------
    def _finish_locked(self, job: Job, state: str) -> None:
        job.state = state
        job.finished_at = _now()
        job.finished_monotonic = time.monotonic()
        if state != "succeeded":
            job.result = None
        if state == "cancelled" and not job.error:
            job.error = "İş kullanıcı isteğiyle iptal edildi."
        elif state == "expired":
            job.error = f"İş süre sınırını ({int(self.timeout_seconds)} sn) aştı ve durduruldu."
        self._persist(job)

    def _notify_finish(self, job: Job) -> None:
        if self.on_finish is None:
            return
        try:
            self.on_finish(job)
        except Exception:
            traceback.print_exc()

    def _expire(self, job: Job) -> None:
        with job.lock:
            if job.state != "running":
                return
            job.expired = True
        job.stop_processes()

    def _worker(self) -> None:
        while True:
            with self._lock:
                while not self._pending:
                    self._wakeup.wait()
                job = self._jobs.get(self._pending.popleft())
                if job is None or job.state != "queued":
                    continue
                job.state = "running"
                job.started_at = _now()
                self._running += 1
                self._persist(job)
            timer = threading.Timer(job.timeout_seconds or self.timeout_seconds, self._expire, args=(job,))
            timer.daemon = True
            timer.start()
            _CURRENT.job = job
            status: int | None = None
            result: Any = None
            failed = False
            try:
                assert job.runner is not None
                status, result = job.runner(job)
            except Exception:
                # 22. tur QA: kullanıcının iptal ettiği ya da süresi dolan işin durdurulan alt süreci beklenen bir
                # sonuçtur; sunucu günlüğüne korkutucu yığın izi yazılmaz (gerçek hatalarda yazılmaya devam eder).
                if not (job.cancel_requested or job.expired):
                    traceback.print_exc()
                failed = True
            finally:
                _CURRENT.job = None
                timer.cancel()
                job.stop_processes()
            self._record(job, status, result, failed)

    def _record(self, job: Job, status: int | None, result: Any, failed: bool) -> None:
        with self._lock:
            self._running -= 1
            job.http_status = status
            if job.cancel_requested:
                self._finish_locked(job, "cancelled")
            elif job.expired:
                self._finish_locked(job, "expired")
            elif failed or status is None:
                job.error = GENERIC_FAILURE
                self._finish_locked(job, "failed")
            elif 200 <= status < 300:
                encoded = json.dumps(result, ensure_ascii=False, default=str)
                if len(encoded.encode("utf-8")) > self.max_result_bytes:
                    job.result = {"note": "Sonuç bellek sınırını aştığı için saklanmadı; araç sonuçları kayıtlı raporlarda."}
                    if isinstance(result, dict):  # kayıtlı sonucu bulmaya yeten kimlik alanları korunur
                        job.result.update({key: result[key] for key in _RESULT_ID_KEYS if key in result})
                    job.result_truncated = True
                else:
                    job.result = result
                self._finish_locked(job, "succeeded")
            else:
                message = result.get("error") if isinstance(result, dict) else None
                job.error = str(message)[:500] if isinstance(message, str) and message else f"Rota {status} durum koduyla döndü."
                self._finish_locked(job, "failed")
        self._notify_finish(job)
