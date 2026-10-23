"""safe_file_read.read_text_bounded ve denetçilerin proje taramalarında kullanımı.

Yarış (stat() sonrası dosyanın FIFO'ya çevrilmesi) ``pathlib.Path.stat`` sahte
"normal dosya" döndürecek şekilde yamalanarak benzetilir: eski
``stat()`` + ``read_text()`` deseni FIFO'yu okumaya çalışıp süresiz beklerdi.
"""

from __future__ import annotations

import os
import pathlib
import stat
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import ai_llm_security_auditor
import audit_logging_integrity_auditor
import browser_extension_pwa_auditor
import business_logic_auditor
import cloud_iam_rbac_auditor
import database_rls_schema_auditor
import dos_resilience_redos_auditor
import host_cis_hardening_auditor
import mobile_security_auditor
import privacy_dataflow_auditor
import secret_intelligence_auditor
import supply_chain_slsa_auditor
import zero_trust_mesh_auditor
from project_analyzer import ProjectRejected
from safe_file_read import read_bytes_bounded, read_text_bounded

_REAL_PATH_STAT = pathlib.Path.stat
_CALL_TIMEOUT = 15.0


def _fake_path_stat(fifo_paths: set[str], size: int = 64):
    def wrapper(self, *args, **kwargs):
        result = _REAL_PATH_STAT(self, *args, **kwargs)
        if str(self) in fifo_paths:
            values = list(result)
            values[stat.ST_MODE] = stat.S_IFREG | 0o644
            values[stat.ST_SIZE] = size
            return os.stat_result(values)
        return result

    return wrapper


def _run_with_deadline(testcase: unittest.TestCase, fifos: list[Path], func, *args, **kwargs):
    box: dict[str, object] = {}

    def target() -> None:
        try:
            box["result"] = func(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(_CALL_TIMEOUT)
    if thread.is_alive():
        for fifo in fifos:
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        thread.join(5)
        testcase.fail(f"{getattr(func, '__name__', func)} FIFO üzerinde süresiz bekledi")
    return box


class ReadTextBoundedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_safe_read_")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_regular_file_within_limit(self) -> None:
        path = self.root / "a.txt"
        path.write_bytes("merhaba ğüş".encode("utf-8"))
        self.assertEqual(read_text_bounded(path, 1000), "merhaba ğüş")
        self.assertEqual(read_text_bounded(str(path), 1000), "merhaba ğüş")

    def test_exact_limit_allowed_and_over_limit_rejected(self) -> None:
        path = self.root / "b.txt"
        path.write_bytes(b"x" * 10)
        self.assertEqual(read_text_bounded(path, 10), "x" * 10)
        self.assertIsNone(read_text_bounded(path, 9))

    def test_empty_file_skipped_unless_allowed(self) -> None:
        path = self.root / "empty.txt"
        path.write_bytes(b"")
        self.assertIsNone(read_text_bounded(path, 10))
        self.assertEqual(read_text_bounded(path, 10, allow_empty=True), "")

    def test_invalid_utf8_replaced_or_ignored(self) -> None:
        path = self.root / "bad.txt"
        path.write_bytes(b"ok\xffok")
        self.assertEqual(read_text_bounded(path, 100), "ok�ok")
        self.assertEqual(read_text_bounded(path, 100, errors="ignore"), "okok")

    def test_symlink_directory_missing_rejected(self) -> None:
        target = self.root / "t.txt"
        target.write_text("data", encoding="utf-8")
        link = self.root / "link.txt"
        link.symlink_to(target)
        self.assertIsNone(read_text_bounded(link, 100))
        self.assertIsNone(read_text_bounded(self.root, 100))
        self.assertIsNone(read_text_bounded(self.root / "missing.txt", 100))

    def test_fifo_returns_none_without_blocking(self) -> None:
        fifo = self.root / "pipe.txt"
        os.mkfifo(fifo)
        box = _run_with_deadline(self, [fifo], read_text_bounded, fifo, 100)
        self.assertIsNone(box.get("result"))
        self.assertNotIn("error", box)

    def test_growth_after_fstat_is_bounded(self) -> None:
        # fstat küçük boyut bildirse bile en fazla max+1 bayt okunur ve sınır aşımı reddedilir.
        path = self.root / "grow.txt"
        path.write_bytes(b"y" * 50)
        real_fstat = os.fstat

        def small_fstat(fd):
            values = list(real_fstat(fd))
            values[stat.ST_SIZE] = 5
            return os.stat_result(values)

        with mock.patch("safe_file_read.os.fstat", side_effect=small_fstat):
            self.assertIsNone(read_bytes_bounded(path, 10))
            self.assertEqual(read_bytes_bounded(path, 50), b"y" * 50)

    def test_negative_limit(self) -> None:
        path = self.root / "n.txt"
        path.write_text("a", encoding="utf-8")
        self.assertIsNone(read_text_bounded(path, -1))


class AuditorProjectScanFifoTests(unittest.TestCase):
    """Denetçiler stat() sonrası FIFO'ya çevrilen dosyada takılmaz; normal dosyaları okumaya devam eder."""

    FIFO_NAMES = (
        ".env", ".env.local", "app.py", "index.js", "main.ts", "config.yaml", "deploy.yml", "data.json",
        "main.tf", "schema.sql", "nginx.conf", "Dockerfile", "sshd_config", "manifest.json", "sw.js",
        "AndroidManifest.xml", "Info.plist", "service.go", "policy.rego", "audit.log", "settings.toml",
    )

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_auditor_fifo_")
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        (self.project / "sub").mkdir(parents=True)
        (self.project / ".github" / "workflows").mkdir(parents=True)
        self.fifos: list[Path] = []
        for name in self.FIFO_NAMES:
            fifo = self.project / "sub" / name
            os.mkfifo(fifo)
            self.fifos.append(fifo)
        for name in ("package.json", "pyproject.toml", "Cargo.toml"):
            fifo = self.project / name
            os.mkfifo(fifo)
            self.fifos.append(fifo)
        wf_fifo = self.project / ".github" / "workflows" / "ci.yml"
        os.mkfifo(wf_fifo)
        self.fifos.append(wf_fifo)
        self.allowed = (self.base,)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _scan(self, func, **kwargs):
        # Kapsam dışı (başka ekiplerin düzenlediği) taint_flow.project_js_handler_names ve
        # dependency_security.discover_components aynı stat()+read_text desenini hâlâ
        # kullanıyor; bu test yalnız denetçi dosyalarındaki düzeltmeyi ölçmek için onları yalıtır.
        with mock.patch.object(pathlib.Path, "stat", _fake_path_stat({str(p) for p in self.fifos})), \
                mock.patch("taint_flow.project_js_handler_names", return_value=frozenset()), \
                mock.patch.object(supply_chain_slsa_auditor, "discover_components", return_value=(None, [])):
            box = _run_with_deadline(self, self.fifos, func, str(self.project), allowed_roots=self.allowed, **kwargs)
        self.assertNotIn("error", box, repr(box.get("error")))
        return box["result"]

    def test_all_refactored_project_scans_skip_fifo_without_blocking(self) -> None:
        funcs = (
            secret_intelligence_auditor.audit_secrets_project,
            ai_llm_security_auditor.audit_ai_llm_project,
            audit_logging_integrity_auditor.audit_logging_project,
            business_logic_auditor.audit_business_logic_project,
            cloud_iam_rbac_auditor.audit_cloud_iam_project,
            host_cis_hardening_auditor.audit_host_config_project,
            privacy_dataflow_auditor.audit_privacy_project,
            zero_trust_mesh_auditor.audit_zero_trust_project,
            dos_resilience_redos_auditor.audit_dos_resilience_project,
            database_rls_schema_auditor.audit_database_schema_project,
            browser_extension_pwa_auditor.audit_extension_pwa_project,
            mobile_security_auditor.audit_mobile_project,
            supply_chain_slsa_auditor.audit_supply_chain_slsa,
        )
        for func in funcs:
            with self.subTest(func=func.__name__):
                result = self._scan(func)
                self.assertIsInstance(result, dict)
                if "scanned_files" in result:
                    self.assertEqual(result["scanned_files"], 0)

    def test_secret_scan_skip_semantics_unchanged(self) -> None:
        # Normal dosya okunur; boş, sınırı aşan ve FIFO dosyalar atlanır (önceki davranışla aynı).
        (self.project / "real.env").write_text("API_KEY=abc\n", encoding="utf-8")
        (self.project / "empty.env").write_text("", encoding="utf-8")
        (self.project / "huge.env").write_bytes(b"A=" + b"x" * (secret_intelligence_auditor.MAX_INLINE_BYTES + 1))
        result = self._scan(secret_intelligence_auditor.audit_secrets_project)
        self.assertEqual(result["scanned_files"], 1)

    def test_mobile_project_still_counts_empty_and_small_files(self) -> None:
        (self.project / "pubspec.yaml").write_text("name: demo\n", encoding="utf-8")
        (self.project / "main.dart").write_text("", encoding="utf-8")
        result = self._scan(mobile_security_auditor.audit_mobile_project)
        self.assertEqual(result["scanned_files"], 2)


class MobilePackageFifoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_mobile_pkg_")
        self.base = Path(self.temp.name).resolve()
        self.allowed = (self.base,)
        (self.base / "pkgs").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_fifo_package_rejected_without_blocking(self) -> None:
        fifo = self.base / "pkgs" / "app.apk"
        os.mkfifo(fifo)
        with mock.patch.object(pathlib.Path, "stat", _fake_path_stat({str(fifo)})):
            box = _run_with_deadline(
                self, [fifo], mobile_security_auditor.audit_mobile_package_archive, str(fifo),
                allowed_roots=self.allowed,
            )
        self.assertIsInstance(box.get("error"), ProjectRejected)

    def test_regular_package_still_analyzed(self) -> None:
        apk = self.base / "pkgs" / "app.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"dex")
            zf.writestr("META-INF/CERT.RSA", b"sig")
        result = mobile_security_auditor.audit_mobile_package_archive(str(apk), allowed_roots=self.allowed)
        self.assertEqual(result["package_type"], "apk")

    def test_wrong_extension_rejected_and_fd_closed(self) -> None:
        bad = self.base / "pkgs" / "app.zip"
        bad.write_bytes(b"PK")
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(ProjectRejected):
            mobile_security_auditor.audit_mobile_package_archive(str(bad), allowed_roots=self.allowed)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__":
    unittest.main()
