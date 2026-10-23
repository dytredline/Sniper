"""Nuclei JSONL sonuçlarının hedef ve gövde içermeyen, sınırlı bulgu günlüğü."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


class NucleiFindingJournalError(RuntimeError):
    pass


class NucleiFindingJournal:
    NAME = "nuclei-http-findings-v1.json"
    MAX_JOBS = 20
    MAX_FINDINGS_PER_JOB = 200
    MAX_BYTES = 1_048_576
    SEVERITIES = frozenset({"info", "low", "medium", "high", "critical", "unknown"})
    HEX16 = re.compile(r"[0-9a-f]{16}\Z")
    HEX64 = re.compile(r"[0-9a-f]{64}\Z")
    TEMPLATE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,299}\Z")

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        if not self.data_dir.is_absolute() or not self.data_dir.is_dir() or self.data_dir.is_symlink():
            raise NucleiFindingJournalError("güvensiz bulgu günlüğü dizini")
        if not hasattr(os, "O_NOFOLLOW"):
            raise NucleiFindingJournalError("güvenli bulgu günlüğü açma kullanılamıyor")
        self.path = self.data_dir / self.NAME

    @staticmethod
    def _no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise NucleiFindingJournalError("yinelenen bulgu günlüğü anahtarı")
            value[key] = item
        return value

    @staticmethod
    def _clean_title(value: object) -> str:
        if not isinstance(value, str):
            return "Nuclei bulgusu"
        clean = " ".join(value.split())[:200]
        return clean or "Nuclei bulgusu"

    @classmethod
    def _finding(cls, record: object) -> dict[str, str]:
        if not isinstance(record, dict):
            raise NucleiFindingJournalError("Nuclei kaydı nesne olmalı")
        template_id = record.get("template-id")
        if not isinstance(template_id, str) or not cls.TEMPLATE_ID.fullmatch(template_id):
            template_id = "unknown-" + hashlib.sha256(
                json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()
            ).hexdigest()[:12]
        info = record.get("info")
        info = info if isinstance(info, dict) else {}
        severity = info.get("severity")
        if severity not in cls.SEVERITIES:
            severity = "unknown"
        title = cls._clean_title(info.get("name"))
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                               default=str).encode()
        evidence = hashlib.sha256(canonical).hexdigest()
        fingerprint = hashlib.sha256(
            json.dumps([template_id, title, severity, evidence], ensure_ascii=True,
                       separators=(",", ":")).encode()
        ).hexdigest()
        return {"template_id": template_id, "title": title, "severity": severity,
                "fingerprint_sha256": fingerprint, "evidence_sha256": evidence}

    @classmethod
    def _validate_job(cls, value: object) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"job_id", "truncated", "findings"}:
            raise NucleiFindingJournalError("geçersiz bulgu günlüğü işi")
        job_id, truncated, findings = value["job_id"], value["truncated"], value["findings"]
        if not isinstance(job_id, str) or not cls.HEX16.fullmatch(job_id) or type(truncated) is not bool \
                or not isinstance(findings, list) or len(findings) > cls.MAX_FINDINGS_PER_JOB:
            raise NucleiFindingJournalError("geçersiz bulgu günlüğü zarfı")
        expected = {"template_id", "title", "severity", "fingerprint_sha256", "evidence_sha256"}
        checked = []
        seen = set()
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != expected \
                    or not isinstance(finding["template_id"], str) or not cls.TEMPLATE_ID.fullmatch(finding["template_id"]) \
                    or not isinstance(finding["title"], str) or not finding["title"] or len(finding["title"]) > 200 \
                    or finding["severity"] not in cls.SEVERITIES \
                    or not cls.HEX64.fullmatch(str(finding["fingerprint_sha256"])) \
                    or not cls.HEX64.fullmatch(str(finding["evidence_sha256"])):
                raise NucleiFindingJournalError("geçersiz bulgu günlüğü kaydı")
            if finding["fingerprint_sha256"] in seen:
                continue
            seen.add(finding["fingerprint_sha256"])
            checked.append(dict(finding))
        return {"job_id": job_id, "truncated": truncated, "findings": checked}

    def _existing(self) -> bool:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > self.MAX_BYTES:
            raise NucleiFindingJournalError("güvensiz bulgu günlüğü yolu")
        return True

    def load(self) -> list[dict[str, Any]]:
        if not self._existing():
            return []
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > self.MAX_BYTES:
                    raise NucleiFindingJournalError("güvensiz bulgu günlüğü dosyası")
                raw = os.read(fd, self.MAX_BYTES + 1)
            finally:
                os.close(fd)
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=self._no_duplicates)
        except NucleiFindingJournalError:
            raise
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            raise NucleiFindingJournalError("bulgu günlüğü okunamadı") from exc
        if len(raw) > self.MAX_BYTES or not isinstance(data, dict) or set(data) != {"version", "jobs"} \
                or data.get("version") != 1 or not isinstance(data.get("jobs"), list) \
                or len(data["jobs"]) > self.MAX_JOBS:
            raise NucleiFindingJournalError("geçersiz bulgu günlüğü")
        jobs = [self._validate_job(item) for item in data["jobs"]]
        if len({item["job_id"] for item in jobs}) != len(jobs):
            raise NucleiFindingJournalError("yinelenen bulgu günlüğü işi")
        return jobs

    def load_job(self, job_id: str) -> dict[str, Any] | None:
        if not isinstance(job_id, str) or not self.HEX16.fullmatch(job_id):
            return None
        return next((item for item in self.load() if item["job_id"] == job_id), None)

    def save_job(self, job_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(job_id, str) or not self.HEX16.fullmatch(job_id) or not isinstance(records, list):
            raise NucleiFindingJournalError("geçersiz bulgu günlüğü girdisi")
        findings = []
        seen = set()
        for record in records:
            finding = self._finding(record)
            if finding["fingerprint_sha256"] in seen:
                continue
            seen.add(finding["fingerprint_sha256"])
            if len(findings) < self.MAX_FINDINGS_PER_JOB:
                findings.append(finding)
        job = {"job_id": job_id, "truncated": len(seen) > len(findings), "findings": findings}
        jobs = [item for item in self.load() if item["job_id"] != job_id]
        jobs.insert(0, job)
        jobs = jobs[:self.MAX_JOBS]
        raw = (json.dumps({"version": 1, "jobs": jobs}, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True) + "\n").encode()
        if len(raw) > self.MAX_BYTES:
            raise NucleiFindingJournalError("bulgu günlüğü çok büyük")
        self._existing()
        temporary: Path | None = None
        try:
            fd, name = tempfile.mkstemp(prefix=".nuclei-findings-", dir=self.data_dir)
            temporary = Path(name)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            self._existing()
            os.replace(temporary, self.path)
            temporary = None
            directory_fd = os.open(self.data_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            raise NucleiFindingJournalError("bulgu günlüğü yazılamadı") from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return job
