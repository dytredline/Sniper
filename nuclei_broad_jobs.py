import hashlib
import json
import os
import re
import signal
import sys
import threading
import time
import fcntl
import tempfile
import shutil
import stat
from ipaddress import ip_address
from pathlib import Path
from subprocess import DEVNULL, Popen
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit
from nuclei_aggregate_history import AggregateHistoryError, AggregateHistoryJournal
from nuclei_finding_journal import NucleiFindingJournal, NucleiFindingJournalError


class NucleiBroadUnavailable(RuntimeError):
    pass


class NucleiBroadBusy(RuntimeError):
    pass


class TargetRejected(ValueError):
    pass


AUTHORIZED_ORIGIN_TEMPLATE_IDS = [
    "http-missing-security-headers",
    "robots-txt",
    "tech-detect",
]
AUTHORIZED_ORIGIN_TIMEOUT_SECONDS = 90.0
AUTHORIZED_ORIGIN_MAX_REPORT_BYTES = 1_000_000
_ORIGIN_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_authorized_http_origin(value: Any) -> str:
    """Return one canonical HTTP(S) origin; paths, credentials, query and fragments are not accepted."""
    if not isinstance(value, str):
        raise ValueError("target_origin bir metin olmalı")
    raw = value.strip()
    if not raw or len(raw) > 2048 or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in raw):
        raise ValueError("target_origin geçersiz")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target_origin geçersiz") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("target_origin http veya https origin olmalı")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target_origin kullanıcı bilgisi içermemeli")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("target_origin yalnız origin içermeli")
    raw_hostname = parsed.hostname.rstrip(".")
    try:
        hostname = ip_address(raw_hostname).compressed
    except ValueError:
        try:
            hostname = raw_hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("target_origin hostu geçersiz") from exc
        if (
            not hostname
            or len(hostname) > 253
            or any(not _ORIGIN_HOST_LABEL.fullmatch(label) for label in hostname.split("."))
        ):
            raise ValueError("target_origin hostu geçersiz")
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= effective_port <= 65535:
        raise ValueError("target_origin portu geçersiz")
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = (scheme == "https" and effective_port == 443) or (scheme == "http" and effective_port == 80)
    authority = rendered_host if default_port else f"{rendered_host}:{effective_port}"
    return urlunsplit((scheme, authority, "", "", ""))


def _is_global_ip(addr: str) -> bool:
    """Check if address is globally routable (IPv4 or IPv6)."""
    try:
        ip = ip_address(addr)
        return ip.is_global
    except ValueError:
        return False


class BroadNucleiJobs:
    def __init__(
        self,
        data_dir: Path,
        binary: Path,
        binary_sha256: str,
        catalog_root: Path,
        pin_path: Path,
        expected_pin_sha256: str,
        expected_index_sha256: str,
        expected_template_count: int,
        mapping_sha256: str,
        resolve_ips: Optional[callable] = None,
    ):
        # Validate inputs
        if not isinstance(data_dir, Path):
            data_dir = Path(data_dir)
        if not isinstance(binary, Path):
            binary = Path(binary)
        if not isinstance(catalog_root, Path):
            catalog_root = Path(catalog_root)
        if not isinstance(pin_path, Path):
            pin_path = Path(pin_path)

        if not data_dir.is_absolute():
            raise ValueError("data_dir mutlak olmalı")
        if not data_dir.is_dir():
            raise ValueError("data_dir bir dizin olmalı")

        if not binary.is_absolute():
            raise ValueError("binary mutlak olmalı")
        if binary.is_symlink():
            raise ValueError("binary sembolik bağ olmamalı")
        if not binary.is_file():
            raise ValueError("binary normal bir dosya olmalı")
        if not os.access(binary, os.X_OK):
            raise ValueError("binary çalıştırılabilir olmalı")

        binary_bytes = binary.read_bytes()
        computed = hashlib.sha256(binary_bytes).hexdigest()
        expected = binary_sha256.lower() if binary_sha256 else ""
        if computed != expected:
            raise ValueError(f"ikili SHA256 değeri uyuşmuyor: {expected} bekleniyordu, {computed} hesaplandı")

        if not catalog_root.is_absolute():
            raise ValueError("catalog_root mutlak olmalı")
        if catalog_root.is_symlink():
            raise ValueError("catalog_root sembolik bağ olmamalı")
        if not catalog_root.is_dir():
            raise ValueError("catalog_root bir dizin olmalı")

        if not pin_path.is_absolute():
            raise ValueError("pin_path mutlak olmalı")
        if pin_path.is_symlink():
            raise ValueError("pin_path sembolik bağ olmamalı")
        if not pin_path.is_file():
            raise ValueError("pin_path bir dosya olmalı")

        self._data_dir = data_dir
        self._binary = binary
        self._binary_sha256 = binary_sha256
        self._catalog_root = catalog_root
        self._pin_path = pin_path
        self._expected_pin_sha256 = expected_pin_sha256
        self._expected_index_sha256 = expected_index_sha256
        self._expected_template_count = expected_template_count
        self._mapping_sha256 = mapping_sha256
        # Use default resolver unless injected
        self._resolve_ips = resolve_ips if resolve_ips is not None else self._resolve_public_ips_default

        # In-process lock for start/cancel/status operations
        self._jobs_lock = threading.Lock()
        self._jobs: Dict[str, dict] = {}
        self._max_recent_completed = 20
        try:
            self._history = AggregateHistoryJournal(data_dir)
            self._finding_journal = NucleiFindingJournal(data_dir)
            self._recent_completed: List[Tuple[str, dict]] = self._history.load()
            self._finding_journal.load()
        except (AggregateHistoryError, NucleiFindingJournalError) as exc:
            raise NucleiBroadUnavailable("Nuclei toplu geçmişi güvensiz") from exc

        # flock-based concurrency guard
        self._loopback_lock_path = data_dir / "nuclei-loopback.lock"
        self._loopback_lock_fd = None
        self._loopback_lock_guard = threading.Lock()

    @staticmethod
    def _resolve_public_ips_default(hostname: str, port: int) -> List[str]:
        import socket
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TargetRejected(f"Alan adı çözümlenemedi: {exc}") from exc
        except OSError as exc:
            raise TargetRejected("Hedef çözümlenemedi.") from exc
        addresses = list(dict.fromkeys(record[4][0] for record in records))
        if not addresses:
            raise TargetRejected("Hedef için IP adresi bulunamadı.")
        for addr in addresses:
            if not _is_global_ip(addr):
                raise TargetRejected("Özel, yerel veya ayrılmış ağ adresleri güvenlik nedeniyle engellendi.")
        return addresses

    def _acquire_loopback_lock(self):
        with self._loopback_lock_guard:
            if self._loopback_lock_fd is not None:
                raise NucleiBroadBusy("Başka bir tarama çalışıyor")
            if not hasattr(os, "O_NOFOLLOW"):
                raise NucleiBroadUnavailable("Güvenli kilit açma kullanılamıyor")
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(self._loopback_lock_path, flags, 0o600)
            except OSError as exc:
                raise NucleiBroadUnavailable("Nuclei kilidi kullanılamıyor") from exc
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
                    raise NucleiBroadUnavailable("Nuclei kilidi güvensiz")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise NucleiBroadBusy("Başka bir tarama çalışıyor") from exc
                self._loopback_lock_fd = fd
            except BaseException:
                os.close(fd)
                raise

    def _release_loopback_lock(self):
        with self._loopback_lock_guard:
            fd = self._loopback_lock_fd
            self._loopback_lock_fd = None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                os.close(fd)
            except Exception:
                pass

    def start(
        self,
        target_record: dict,
        engagement_record: dict,
        confirm_authorized: bool,
        template_ids: List[str] | None = None,
        include_excluded: bool = False,
        *,
        _authorized_direct: bool = False,
        _timeout_seconds: float = 28800.0,
        _max_report_bytes: int = 20_000_000,
    ) -> dict:
        # Basic argument validation
        if not isinstance(target_record, dict):
            raise ValueError("target_record bir sözlük olmalı")
        if not isinstance(engagement_record, dict):
            raise ValueError("engagement_record bir sözlük olmalı")
        if confirm_authorized is not True:
            raise ValueError("confirm_authorized tam olarak True olmalı")

        # Engagement must be active
        if engagement_record.get("status") != "active":
            raise ValueError("görev etkin değil")

        # Engagement must match target
        if engagement_record.get("target_id") != target_record.get("id"):
            raise ValueError("görev target_id değeri target_record kimliğiyle eşleşmiyor")

        # Required engagement fields
        auth_ref = engagement_record.get("authorization_ref")
        scope_notes = engagement_record.get("scope_notes")
        if not isinstance(auth_ref, str) or not auth_ref.strip():
            raise ValueError("görev authorization_ref eksik veya boş")
        if not isinstance(scope_notes, str) or not scope_notes.strip():
            raise ValueError("görev scope_notes eksik veya boş")

        # Validate target URL
        url = target_record.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError("target_record url eksik veya boş")

        # Normalize and validate URL
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("hedef URL şeması http veya https olmalı")
        if parsed.username or parsed.password:
            raise ValueError("hedef URL kullanıcı bilgisi içermemeli")
        if parsed.query or parsed.fragment:
            raise ValueError("hedef URL sorgu veya parça içermemeli")
        if not parsed.hostname:
            raise ValueError("hedef URL boş olmayan bir ana makine adı içermeli")

        hostname = target_record.get("hostname")
        port = target_record.get("port")
        if not isinstance(hostname, str) or not hostname:
            raise ValueError("target_record ana makine adı eksik veya boş")
        if type(port) is not int or port < 1 or port > 65535:
            raise ValueError("target_record portu geçersiz")

        # Validate URL hostname matches target_record hostname (case-insensitive)
        if parsed.hostname.lower() != hostname.lower():
            raise ValueError("target_record ana makine adı URL ana makinesiyle eşleşmiyor")

        # Effective port: parsed.port or default for scheme
        try:
            effective_port = parsed.port
        except ValueError as exc:
            raise ValueError("hedef URL portu geçersiz") from exc
        if effective_port is None:
            if parsed.scheme == "https":
                effective_port = 443
            elif parsed.scheme == "http":
                effective_port = 80
            else:
                effective_port = port  # fallback
        if effective_port != port:
            raise ValueError(f"etkin URL portu {effective_port}, kayıtlı port {port} ile eşleşmiyor")

        if not _authorized_direct:
            # The legacy registered-target route preserves its public-address contract byte-for-byte.
            resolved = self._resolve_ips(hostname, port)
            if not isinstance(resolved, list) or not resolved:
                raise ValueError("resolve_ips geçersiz tür veya boş liste döndürdü")
            for ip in resolved:
                if not _is_global_ip(ip):
                    raise TargetRejected("Özel, yerel veya ayrılmış ağ adresleri güvenlik nedeniyle engellendi.")

        # Validate target status (only allow 'ready')
        if target_record.get("status") != "ready":
            raise ValueError("hedef 'ready' durumunda olmalı")

        if type(include_excluded) is not bool:
            raise ValueError("include_excluded bir mantıksal değer olmalı")

        # Verify and resolve the pinned catalog before creating job artifacts.
        try:
            from nuclei_catalog_integrity import verify_http_catalog
            from nuclei_catalog_resolver import resolve_http_template_paths
            verify_http_catalog(
                self._catalog_root,
                self._pin_path,
                self._expected_pin_sha256,
                self._expected_template_count,
                self._mapping_sha256,
            )
            selected_template_paths = None
            if template_ids:
                resolved_paths = resolve_http_template_paths(
                    self._catalog_root,
                    template_ids,
                    self._expected_index_sha256,
                )
                if include_excluded:
                    selected_template_paths = resolved_paths
        except ValueError:
            raise
        except Exception as exc:
            raise NucleiBroadUnavailable("Katalog bütünlüğü veya şablon seçimi başarısız oldu") from exc

        from nuclei_bounded_process import BoundedNucleiProcess
        from nuclei_broad_args import build_nuclei_http_args

        job_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        job_dir = self._data_dir / f"job_{job_id}"
        report_path = job_dir / "report.jsonl"
        args = build_nuclei_http_args(
            binary=self._binary,
            catalog_root=self._catalog_root,
            target_url=url,
            output_path=report_path,
            template_ids=template_ids,
            include_excluded=include_excluded,
            selected_template_paths=selected_template_paths,
        )

        # Parent-death wrapper
        parent_death = Path(__file__).resolve().parent / "nuclei_parent_death.py"
        if not parent_death.is_absolute() or not parent_death.is_file() or parent_death.is_symlink():
            raise RuntimeError("nuclei_parent_death.py mutlak, sembolik bağ olmayan bir dosya olmalı")
        argv = [str(sys.executable), str(parent_death), str(os.getpid()), *args]

        self._acquire_loopback_lock()
        created_job_dir = False
        try:
            job_dir.mkdir(mode=0o700)
            created_job_dir = True
            if not hasattr(os, "O_NOFOLLOW"):
                raise NucleiBroadUnavailable("Güvenli rapor oluşturma kullanılamıyor")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            fd = os.open(report_path, flags, 0o600)
            os.close(fd)
        except BaseException:
            if created_job_dir and job_dir.is_dir() and not job_dir.is_symlink():
                shutil.rmtree(job_dir)
            self._release_loopback_lock()
            raise

        # Start bounded process
        bounded = BoundedNucleiProcess(timeout_seconds=_timeout_seconds, max_report_bytes=_max_report_bytes)

        job_entry = {
            "job_id": job_id,
            "state": "pending",
            "start_time": time.monotonic(),
            "report_path": str(report_path),
            "bounded": bounded,
            "argv": argv,
            "env": {},
        }

        with self._jobs_lock:
            self._jobs[job_id] = job_entry

        def monitor():
            try:
                bounded.start(argv=argv, report_path=report_path)
                bounded._event.wait()
                # Cancellation signals the event before the process group has
                # necessarily exited. Never free the lock or report until the
                # supervisor has reaped the child.
                if bounded._supervisor_thread is not None:
                    bounded._supervisor_thread.join()
                final = bounded._build_final()
                job_entry["state"] = final["state"]
                job_entry["elapsed_seconds"] = final.get("elapsed_seconds", 0)
                if final.get("error_code") is not None:
                    job_entry["error_code"] = final["error_code"]

                if final["state"] == "completed":
                    try:
                        with open(report_path, "rb") as report:
                            data = report.read(_max_report_bytes + 1)
                        if len(data) > _max_report_bytes:
                            raise OverflowError("rapor sınırı aşıldı")
                        records = []
                        for line in data.decode("utf-8").splitlines():
                            if line.strip():
                                record = json.loads(line)
                                if not isinstance(record, dict):
                                    raise ValueError("nesne olmayan JSONL kaydı")
                                records.append(record)
                        severity_counts = {}
                        template_ids_found = set()
                        for record in records:
                            info = record.get("info")
                            severity = info.get("severity") if isinstance(info, dict) else None
                            if severity not in ("info", "low", "medium", "high", "critical", "unknown"):
                                severity = "unknown"
                            severity_counts[severity] = severity_counts.get(severity, 0) + 1
                            template_id = record.get("template-id")
                            if isinstance(template_id, str):
                                template_ids_found.add(template_id)
                        self._finding_journal.save_job(job_id, records)
                        job_entry.update(
                            record_count=len(records),
                            severity_counts=severity_counts,
                            unique_template_count=len(template_ids_found),
                            report_sha256=hashlib.sha256(data).hexdigest(),
                        )
                    except OverflowError:
                        job_entry.update(state="failed", error_code="report_exceeded")
                    except NucleiFindingJournalError:
                        job_entry.update(state="failed", error_code="finding_journal_unavailable")
                    except (OSError, UnicodeError, ValueError, TypeError):
                        job_entry.update(state="failed", error_code="report_malformed")
            except Exception:
                bounded.cancel()
                job_entry.update(state="failed", error_code="monitor_failed")
            finally:
                try:
                    if job_dir.is_dir() and not job_dir.is_symlink():
                        shutil.rmtree(job_dir)
                finally:
                    try:
                        with self._jobs_lock:
                            self._jobs.pop(job_id, None)
                            public_keys = (
                                "job_id", "state", "elapsed_seconds", "error_code",
                                "report_sha256", "record_count", "severity_counts",
                                "unique_template_count",
                            )
                            completed = {key: job_entry[key] for key in public_keys if key in job_entry}
                            self._recent_completed.insert(0, (job_id, completed))
                            del self._recent_completed[self._max_recent_completed:]
                            try:
                                self._history.save(self._recent_completed)
                            except AggregateHistoryError:
                                self._recent_completed[0] = (job_id, {
                                    "job_id": job_id, "state": "failed",
                                    "elapsed_seconds": completed.get("elapsed_seconds", 0),
                                    "error_code": "history_unavailable",
                                })
                    finally:
                        self._release_loopback_lock()

        try:
            threading.Thread(target=monitor, daemon=True).start()
        except BaseException:
            with self._jobs_lock:
                self._jobs.pop(job_id, None)
            if job_dir.is_dir() and not job_dir.is_symlink():
                shutil.rmtree(job_dir)
            self._release_loopback_lock()
            raise

        return {"job_id": job_id, "state": "starting"}

    def start_authorized_origin(self, origin: Any, confirm_authorized: Any) -> dict:
        """Start the fixed direct-origin profile after explicit per-run human authorization."""
        if confirm_authorized is not True:
            raise ValueError("confirm_authorized tam olarak True olmalı")
        canonical = normalize_authorized_http_origin(origin)
        parsed = urlsplit(canonical)
        effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        target = {
            "id": f"direct-{target_digest[:16]}",
            "url": canonical,
            "hostname": parsed.hostname,
            "port": effective_port,
            "status": "ready",
        }
        engagement = {
            "status": "active",
            "target_id": target["id"],
            "authorization_ref": "per-run-human-consent-v1",
            "scope_notes": "fixed authorized-origin HTTP profile",
        }
        result = self.start(
            target,
            engagement,
            True,
            template_ids=list(AUTHORIZED_ORIGIN_TEMPLATE_IDS),
            include_excluded=False,
            _authorized_direct=True,
            _timeout_seconds=AUTHORIZED_ORIGIN_TIMEOUT_SECONDS,
            _max_report_bytes=AUTHORIZED_ORIGIN_MAX_REPORT_BYTES,
        )
        return {
            **result,
            "profile": "authorized-origin-fixed-http-v1",
            "target_sha256": target_digest,
        }

    def status(self, job_id: str) -> dict:
        with self._jobs_lock:
            entry = self._jobs.get(job_id)
            if entry:
                bounded = entry.get("bounded")
                if bounded:
                    status = bounded.status()
                    return {
                        "job_id": job_id,
                        "state": "finalizing" if status.get("state") in ("completed", "failed", "cancelled") else status.get("state", "pending"),
                        "elapsed_seconds": status.get("elapsed_seconds", 0),
                    }
                else:
                    return {
                        "job_id": job_id,
                        "state": entry.get("state", "pending"),
                        "elapsed_seconds": entry.get("elapsed_seconds", 0),
                    }
            else:
                # Check recent completed
                for jid, jentry in self._recent_completed:
                    if jid == job_id:
                        res = {
                            "job_id": job_id,
                            "state": jentry.get("state", "unknown"),
                            "elapsed_seconds": jentry.get("elapsed_seconds", 0),
                        }
                        if "error_code" in jentry:
                            res["error_code"] = jentry["error_code"]
                        if "report_sha256" in jentry:
                            res["report_sha256"] = jentry["report_sha256"]
                        if "record_count" in jentry:
                            res["record_count"] = jentry["record_count"]
                        if "severity_counts" in jentry:
                            res["severity_counts"] = jentry["severity_counts"]
                        if "unique_template_count" in jentry:
                            res["unique_template_count"] = jentry["unique_template_count"]
                        return res
                raise FileNotFoundError(f"Bilinmeyen job_id: {job_id}")

    def cancel(self, job_id: str) -> dict:
        with self._jobs_lock:
            entry = self._jobs.get(job_id)
            if not entry:
                # Check recent completed
                for jid, jentry in self._recent_completed:
                    if jid == job_id:
                        return {
                            "job_id": job_id,
                            "state": jentry.get("state"),
                            "elapsed_seconds": jentry.get("elapsed_seconds", 0),
                        }
                raise FileNotFoundError(f"Bilinmeyen job_id: {job_id}")
            bounded = entry.get("bounded")
        if bounded:
            # BoundedNucleiProcess.cancel() takes its own state lock and returns
            # the authoritative post-cancel terminal state.  Propagate that
            # result instead of converting a completed/failed terminal race
            # into a false "cancelling" acknowledgement.
            final = bounded.cancel()
            if not isinstance(final, dict):
                return {"job_id": job_id, "state": "unknown"}
            result = {"job_id": job_id, "state": final.get("state", "unknown")}
            for key in ("elapsed_seconds", "error_code", "report_sha256"):
                if key in final:
                    result[key] = final[key]
            return result
        return {"job_id": job_id, "state": entry.get("state", "pending")}
