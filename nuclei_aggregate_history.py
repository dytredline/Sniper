"""Owner-private, bounded persistence for redacted Nuclei job aggregates.

This journal holds only fields already exposed by the job-status API. It never
stores a scan target, command, authorization reference, JSONL record or report.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
from pathlib import Path


class AggregateHistoryError(RuntimeError):
    pass


class AggregateHistoryJournal:
    NAME = "nuclei-http-aggregate-history-v1.json"
    MAX_ENTRIES = 20
    MAX_BYTES = 65536
    FIELDS = frozenset({
        "job_id", "state", "elapsed_seconds", "error_code", "report_sha256",
        "record_count", "severity_counts", "unique_template_count",
    })
    SEVERITIES = frozenset({"info", "low", "medium", "high", "critical", "unknown"})
    STATES = frozenset({"completed", "failed", "cancelled"})
    HEX16 = re.compile(r"[0-9a-f]{16}\Z")
    HEX64 = re.compile(r"[0-9a-f]{64}\Z")
    ERROR_CODE = re.compile(r"[a-z_]{1,64}\Z")

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        if not self.data_dir.is_absolute() or not self.data_dir.is_dir() or self.data_dir.is_symlink():
            raise AggregateHistoryError("güvensiz geçmiş dizini")
        self.path = self.data_dir / self.NAME
        if not hasattr(os, "O_NOFOLLOW"):
            raise AggregateHistoryError("güvenli geçmiş açma kullanılamıyor")

    @staticmethod
    def _no_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AggregateHistoryError("yinelenen geçmiş anahtarı")
            result[key] = value
        return result

    @staticmethod
    def _no_constant(value):
        raise AggregateHistoryError("geçersiz geçmiş numarası")

    @classmethod
    def _entry(cls, job_id: str, aggregate: dict) -> dict:
        if not isinstance(aggregate, dict) or not isinstance(job_id, str) or not cls.HEX16.fullmatch(job_id):
            raise AggregateHistoryError("geçersiz geçmiş girdisi")
        if not set(aggregate).issubset(cls.FIELDS - {"job_id"}):
            raise AggregateHistoryError("beklenmeyen geçmiş alanı")
        state = aggregate.get("state")
        elapsed = aggregate.get("elapsed_seconds")
        if type(state) is not str or state not in cls.STATES or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed <= 100000:
            raise AggregateHistoryError("geçersiz geçmiş durumu veya süresi")
        entry = {"job_id": job_id, "state": state, "elapsed_seconds": elapsed}
        if "error_code" in aggregate:
            code = aggregate["error_code"]
            if not ((type(code) is int and -128 <= code <= 255)
                    or (isinstance(code, str) and cls.ERROR_CODE.fullmatch(code))):
                raise AggregateHistoryError("geçersiz geçmiş hata kodu")
            entry["error_code"] = code
        if "report_sha256" in aggregate:
            digest = aggregate["report_sha256"]
            if not isinstance(digest, str) or not cls.HEX64.fullmatch(digest):
                raise AggregateHistoryError("geçersiz geçmiş özeti")
            entry["report_sha256"] = digest
        for key, limit in (("record_count", 20_000_000), ("unique_template_count", 11655)):
            if key in aggregate:
                value = aggregate[key]
                if type(value) is not int or not 0 <= value <= limit:
                    raise AggregateHistoryError("geçersiz geçmiş sayısı")
                entry[key] = value
        if "severity_counts" in aggregate:
            counts = aggregate["severity_counts"]
            if (not isinstance(counts, dict) or not set(counts).issubset(cls.SEVERITIES)
                    or any(type(value) is not int or not 0 <= value <= 20_000_000 for value in counts.values())):
                raise AggregateHistoryError("geçersiz geçmiş önem sayıları")
            if "record_count" in entry and sum(counts.values()) != entry["record_count"]:
                raise AggregateHistoryError("tutarsız geçmiş sayıları")
            entry["severity_counts"] = dict(counts)
        if entry.get("state") == "completed" and not {"report_sha256", "record_count", "unique_template_count", "severity_counts"}.issubset(entry):
            raise AggregateHistoryError("tamamlanmış geçmiş eksik")
        return entry

    @staticmethod
    def _check_file_descriptor(fd: int) -> None:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > AggregateHistoryJournal.MAX_BYTES:
            raise AggregateHistoryError("güvensiz geçmiş dosyası")

    def _check_existing(self) -> bool:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > self.MAX_BYTES:
            raise AggregateHistoryError("güvensiz geçmiş yolu")
        return True

    def load(self) -> list[tuple[str, dict]]:
        if not self._check_existing():
            return []
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.path, flags)
            try:
                self._check_file_descriptor(fd)
                with os.fdopen(fd, "rb", closefd=False) as source:
                    raw = source.read(self.MAX_BYTES + 1)
            finally:
                os.close(fd)
        except OSError as error:
            raise AggregateHistoryError("geçmiş okunamadı") from error
        if len(raw) > self.MAX_BYTES:
            raise AggregateHistoryError("geçmiş çok büyük")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=self._no_duplicate_keys,
                              parse_constant=self._no_constant)
        except (UnicodeError, ValueError, TypeError) as error:
            raise AggregateHistoryError("bozuk geçmiş") from error
        if (not isinstance(data, dict) or set(data) != {"version", "entries"}
                or type(data["version"]) is not int or data["version"] != 1
                or not isinstance(data["entries"], list) or len(data["entries"]) > self.MAX_ENTRIES):
            raise AggregateHistoryError("geçersiz geçmiş zarfı")
        result = []
        seen = set()
        for value in data["entries"]:
            if not isinstance(value, dict) or not set(value).issubset(self.FIELDS) or "job_id" not in value:
                raise AggregateHistoryError("geçersiz geçmiş alanları")
            job_id = value["job_id"]
            entry = self._entry(job_id, {key: item for key, item in value.items() if key != "job_id"})
            if job_id in seen:
                raise AggregateHistoryError("yinelenen geçmiş işi")
            seen.add(job_id)
            result.append((job_id, {key: item for key, item in entry.items() if key != "job_id"}))
        return result

    def save(self, recent: list[tuple[str, dict]]) -> None:
        if not isinstance(recent, list) or len(recent) > self.MAX_ENTRIES:
            raise AggregateHistoryError("geçmiş sınırı aşıldı")
        entries = []
        seen = set()
        for job_id, aggregate in recent:
            if not isinstance(aggregate, dict) or aggregate.get("job_id", job_id) != job_id:
                raise AggregateHistoryError("geçmiş iş kimliği uyuşmuyor")
            entry = self._entry(job_id, {key: value for key, value in aggregate.items() if key != "job_id"})
            if job_id in seen:
                raise AggregateHistoryError("yinelenen geçmiş işi")
            seen.add(job_id)
            entries.append(entry)
        raw = (json.dumps({"version": 1, "entries": entries}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True) + "\n").encode()
        if len(raw) > self.MAX_BYTES:
            raise AggregateHistoryError("geçmiş çok büyük")
        self._check_existing()
        temporary = None
        try:
            fd, name = tempfile.mkstemp(prefix=".nuclei-aggregate-history-", dir=self.data_dir)
            temporary = Path(name)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            self._check_existing()
            os.replace(temporary, self.path)
            temporary = None
            directory_fd = os.open(self.data_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as error:
            raise AggregateHistoryError("geçmiş yazılamadı") from error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
