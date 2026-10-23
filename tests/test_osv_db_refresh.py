"""OSV çevrimdışı veritabanı güncellemesi testleri (ağsız; sahte HTTP yanıtıyla)."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import email.message
import fcntl
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import osv_active  # noqa: E402
import osv_db_refresh  # noqa: E402
from osv_db_refresh import OSVRefreshError  # noqa: E402


def _record(osv_id: str, ecosystem: str = "npm") -> dict:
    return {"id": osv_id, "modified": "2026-10-01T00:00:00Z", "aliases": ["CVE-2026-0001"],
            "affected": [{"package": {"name": "left-pad", "ecosystem": ecosystem}, "ranges": [], "versions": ["1.0.0"]}]}


def _zip(members: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _good_zip(count: int = 3) -> bytes:
    return _zip({f"GHSA-{i:04d}.json": json.dumps(_record(f"GHSA-{i:04d}")).encode() for i in range(count)})


class _FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200, length: int | None = -1, md5: str | None = "auto"):
        self._stream = io.BytesIO(body)
        self.status = status
        headers = email.message.Message()
        if length == -1:
            headers["Content-Length"] = str(len(body))
        elif length is not None:
            headers["Content-Length"] = str(length)
        if md5 == "auto":
            headers["x-goog-hash"] = "crc32c=AAAAAA=="
            headers["x-goog-hash"] = "md5=" + base64.b64encode(hashlib.md5(body).digest()).decode()
        elif md5 is not None:
            headers["x-goog-hash"] = "md5=" + md5
        headers["Last-Modified"] = "Mon, 19 Oct 2026 13:48:03 GMT"
        self.headers = headers

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        pass


def _opener(body: bytes, **kwargs):
    calls = []

    def open_url(request, timeout=None):
        calls.append((request.full_url, timeout))
        return _FakeResponse(body, **kwargs)

    open_url.calls = calls
    return open_url


class OSVRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "osv-db"
        self._env = mock.patch.dict(os.environ, {
            "SNIPER_AUDIT_KEY_FILE": str(self.tmp / "cfg" / "audit.key"),
            "SNIPER_AUDIT_ANCHOR_DIR": str(self.tmp / "cfg" / "anchors"),
        })
        self._env.start()
        os.environ.pop("SNIPER_AUDIT_HMAC", None)

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def _key(self) -> None:
        import audit_integrity
        self.assertTrue(audit_integrity.load_key(create=True).usable)

    def _refresh(self, body: bytes, *, when: datetime | None = None, **kwargs) -> dict:
        return osv_db_refresh.refresh("npm", root=self.root, opener=_opener(body, **kwargs), now=when)

    # --- başarılı yol ---------------------------------------------------------------------------

    def test_refresh_writes_signed_manifest_and_private_generation(self) -> None:
        self._key()
        body = _good_zip(5)
        result = self._refresh(body)
        self.assertEqual(result["status"], "updated")
        self.assertTrue(result["manifest_signed"])
        self.assertTrue(result["md5_verified"])
        manifest_file = self.root / "NPM-OFFLINE-DB-MANIFEST-v2.json"
        manifest = json.loads(manifest_file.read_text())
        self.assertEqual(manifest["schema"], "SNIPER_OSV_NPM_OFFLINE_DB_V2")
        self.assertEqual(manifest["source_url"], "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip")
        self.assertEqual(manifest["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(manifest["bytes"], len(body))
        self.assertEqual(manifest["zip_members"], 5)
        self.assertEqual(manifest["zip_test"], "PASS")
        self.assertEqual(manifest["network"], "none")
        db = Path(manifest["scanner_cache_path"])
        self.assertEqual(db.parts[-3:], ("osv-scalibr", "npm", "all.zip"))
        self.assertEqual(db.read_bytes(), body)
        self.assertEqual(os.stat(db).st_mode & 0o777, 0o400)
        self.assertEqual(os.stat(manifest_file).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.root).st_mode & 0o777, 0o700)
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(manifest_file.read_bytes()).hexdigest())
        self.assertEqual(list(db.parent.parent.parent.parent.parent.glob(".incoming-*")), [])

    def test_keeps_exactly_one_previous_generation(self) -> None:
        base = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)
        first = self._refresh(_good_zip(1), when=base)
        second = self._refresh(_good_zip(2), when=base + timedelta(hours=1))
        self.assertEqual(second["previous_generation"], first["generation"])
        third = self._refresh(_good_zip(3), when=base + timedelta(hours=2))
        self.assertEqual(third["previous_generation"], second["generation"])
        self.assertEqual(third["removed_generations"], [first["generation"]])
        remaining = sorted(p.name for p in (self.root / "generations" / "npm").iterdir())
        self.assertEqual(remaining, sorted([second["generation"], third["generation"]]))

    def test_unsigned_without_key(self) -> None:
        result = self._refresh(_good_zip(1))
        self.assertFalse(result["manifest_signed"])
        self.assertEqual(result["key_status"], "missing")

    # --- indirme reddi --------------------------------------------------------------------------

    def test_md5_mismatch_rejected_and_nothing_written(self) -> None:
        with self.assertRaisesRegex(OSVRefreshError, "md5"):
            self._refresh(_good_zip(1), md5=base64.b64encode(b"x" * 16).decode())
        self.assertFalse((self.root / "NPM-OFFLINE-DB-MANIFEST-v2.json").exists())
        self.assertEqual(list((self.root / "generations" / "npm").iterdir()), [])

    def test_truncated_download_rejected(self) -> None:
        body = _good_zip(1)
        with self.assertRaisesRegex(OSVRefreshError, "eksik"):
            self._refresh(body, length=len(body) + 10, md5=None)

    def test_size_limit_enforced_with_and_without_length(self) -> None:
        body = _good_zip(2)
        for length in (-1, None):
            with self.subTest(length=length):
                with self.assertRaisesRegex(OSVRefreshError, "boyut"):
                    osv_db_refresh.refresh("npm", root=self.root, max_bytes=len(body) - 1,
                                           opener=_opener(body, length=length, md5=None))

    def test_http_error_status_rejected(self) -> None:
        with self.assertRaisesRegex(OSVRefreshError, "HTTP 500"):
            self._refresh(b"", status=500)

    def test_only_official_https_source(self) -> None:
        for url in ("http://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
                    "https://evil.example/npm/all.zip",
                    "https://osv-vulnerabilities.storage.googleapis.com:8443/npm/all.zip"):
            with self.subTest(url=url):
                with self.assertRaises(OSVRefreshError):
                    osv_db_refresh.download(url, self.tmp / "x.zip", opener=_opener(b""))

    def test_redirects_are_refused(self) -> None:
        handler = osv_db_refresh._NoRedirect()
        with self.assertRaisesRegex(OSVRefreshError, "yönlendirme"):
            handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/")
        self.assertTrue(any(isinstance(h, osv_db_refresh._NoRedirect) for h in osv_db_refresh._opener().handlers))

    def test_deadline_enforced(self) -> None:
        with self.assertRaisesRegex(OSVRefreshError, "süre"):
            osv_db_refresh.refresh("npm", root=self.root, deadline_seconds=-1, opener=_opener(_good_zip(1)))

    def test_invalid_ecosystem_names(self) -> None:
        for name in ("../npm", "npm/../../x", "", "a" * 80, "npm\n"):
            with self.subTest(name=name):
                with self.assertRaises(OSVRefreshError):
                    osv_db_refresh.validate_ecosystem(name)
        self.assertTrue(osv_db_refresh.source_url("Debian:12").endswith("/Debian%3A12/all.zip"))

    def test_concurrent_refresh_is_busy(self) -> None:
        self.root.mkdir(mode=0o700)
        (self.root / "generations" / "npm").mkdir(parents=True, mode=0o700)
        lock_fd = os.open(self.root / ".refresh-npm.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            with self.assertRaises(osv_db_refresh.OSVRefreshBusy):
                self._refresh(_good_zip(1))
        finally:
            os.close(lock_fd)

    # --- zip / şema ------------------------------------------------------------------------------

    def _validate(self, body: bytes, **kwargs) -> dict:
        path = self.tmp / "a.zip"
        path.write_bytes(body)
        return osv_db_refresh.validate_archive(path, "npm", **kwargs)

    def test_zip_slip_and_unexpected_names_rejected(self) -> None:
        for name in ("../evil.json", "/abs.json", "dir/GHSA-1.json", "..json", ".hidden.json", "GHSA-1.txt",
                     "a\\b.json"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(OSVRefreshError, "girdi adı"):
                    self._validate(_zip({name: b"{}"}))

    def test_directory_entry_rejected(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(zipfile.ZipInfo("GHSA-dir/"), b"")
        with self.assertRaises(OSVRefreshError):
            self._validate(buffer.getvalue())

    def test_duplicate_member_rejected(self) -> None:
        buffer = io.BytesIO()
        data = json.dumps(_record("GHSA-1")).encode()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("GHSA-1.json", data)
            with self.assertWarns(UserWarning):
                archive.writestr("GHSA-1.json", data)
        with self.assertRaisesRegex(OSVRefreshError, "yinelenen"):
            self._validate(buffer.getvalue())

    def test_zip_bomb_ratio_and_limits(self) -> None:
        bomb = _zip({"GHSA-1.json": b"{" + b" " * (5 * 1024 * 1024) + b"}"})
        with self.assertRaisesRegex(OSVRefreshError, "zip bombası"):
            self._validate(bomb)
        with self.assertRaisesRegex(OSVRefreshError, "fazla girdi"):
            self._validate(_good_zip(3), max_members=2)
        with self.assertRaisesRegex(OSVRefreshError, "çok büyük"):
            self._validate(_good_zip(1), max_member_bytes=10)
        with self.assertRaisesRegex(OSVRefreshError, "toplam"):
            self._validate(_good_zip(3), max_total_uncompressed=200)

    def test_encrypted_flag_rejected(self) -> None:
        body = bytearray(_good_zip(1))
        # Yerel ve merkezi başlıktaki genel amaçlı bayrakların 0. bitini (şifreli) işaretle.
        local = body.find(b"PK\x03\x04")
        central = body.find(b"PK\x01\x02")
        body[local + 6] |= 0x1
        body[central + 8] |= 0x1
        with self.assertRaisesRegex(OSVRefreshError, "şifreli"):
            self._validate(bytes(body))

    def test_corrupt_member_crc_rejected(self) -> None:
        data = json.dumps(_record("GHSA-1")).encode()
        body = bytearray(_zip({"GHSA-1.json": data}, compression=zipfile.ZIP_STORED))
        index = body.find(b'"modified"')
        body[index + 2] ^= 0x01
        with self.assertRaisesRegex(OSVRefreshError, "bozuk"):
            self._validate(bytes(body))

    def test_not_a_zip_and_empty_zip(self) -> None:
        with self.assertRaisesRegex(OSVRefreshError, "geçerli bir zip"):
            self._validate(b"<html>hata</html>")
        with self.assertRaisesRegex(OSVRefreshError, "boş"):
            self._validate(_zip({}))

    def test_schema_violations_rejected(self) -> None:
        cases = {
            "json": b"{bozuk",
            "nesne": b"[]",
            "id alanı": json.dumps({**_record("BASKA"), "id": "BASKA"}).encode(),
            "modified": json.dumps({"id": "GHSA-1"}).encode(),
            "affected": json.dumps({**_record("GHSA-1"), "affected": "x"}).encode(),
            "aliases": json.dumps({**_record("GHSA-1"), "aliases": [1]}).encode(),
        }
        for needle, data in cases.items():
            with self.subTest(case=needle):
                with self.assertRaisesRegex(OSVRefreshError, needle if needle != "nesne" else "nesne değil"):
                    self._validate(_zip({"GHSA-1.json": data}))


class OSVActiveManifestTrustTests(unittest.TestCase):
    """osv_active: manifeste ortam pini YA DA yerel anahtar imzasıyla güvenilir."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "osv-db"
        self._env = mock.patch.dict(os.environ, {
            "SNIPER_AUDIT_KEY_FILE": str(self.tmp / "cfg" / "audit.key"),
            "SNIPER_AUDIT_ANCHOR_DIR": str(self.tmp / "cfg" / "anchors"),
            "SNIPER_OSV_DB_MANIFEST": str(self.root / "NPM-OFFLINE-DB-MANIFEST-v2.json"),
        })
        self._env.start()
        os.environ.pop("SNIPER_OSV_DB_MANIFEST_SHA256", None)
        os.environ.pop("SNIPER_AUDIT_HMAC", None)

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def _refresh(self, *, signed: bool = True, when: datetime | None = None) -> dict:
        import audit_integrity
        if signed:
            audit_integrity.load_key(create=True)
        return osv_db_refresh.refresh("npm", root=self.root, opener=_opener(_good_zip(2)), now=when)

    def test_signed_manifest_trusted_without_or_with_stale_pin(self) -> None:
        result = self._refresh()
        _cache, db_path, sha, _retrieved = osv_active._trusted_db()
        self.assertEqual(sha, result["sha256"])
        os.environ["SNIPER_OSV_DB_MANIFEST_SHA256"] = "0" * 64  # eski pin
        self.assertEqual(osv_active._trusted_db()[1], db_path)

    def test_unsigned_manifest_needs_matching_pin(self) -> None:
        result = self._refresh(signed=False)
        with self.assertRaisesRegex(osv_active.OSVUnavailable, "yapılandırılmamış"):
            osv_active._trusted_db()
        os.environ["SNIPER_OSV_DB_MANIFEST_SHA256"] = "0" * 64
        with self.assertRaisesRegex(osv_active.OSVUnavailable, "sabitlemesi uyuşmuyor"):
            osv_active._trusted_db()
        os.environ["SNIPER_OSV_DB_MANIFEST_SHA256"] = result["manifest_sha256"]
        self.assertEqual(osv_active._trusted_db()[2], result["sha256"])

    def test_tampered_signed_manifest_rejected(self) -> None:
        self._refresh()
        path = Path(os.environ["SNIPER_OSV_DB_MANIFEST"])
        manifest = json.loads(path.read_text())
        manifest["retrieved_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["sha256"] = "f" * 64
        path.write_text(json.dumps(manifest))
        with self.assertRaises(osv_active.OSVUnavailable):
            osv_active._trusted_db()

    def test_other_key_signature_rejected(self) -> None:
        self._refresh()
        key_file = Path(os.environ["SNIPER_AUDIT_KEY_FILE"])
        os.chmod(key_file, 0o600)
        key_file.write_bytes(os.urandom(32))
        with self.assertRaises(osv_active.OSVUnavailable):
            osv_active._trusted_db()

    def test_stale_signed_db_rejected(self) -> None:
        self._refresh(when=datetime.now(timezone.utc) - timedelta(days=8))
        with self.assertRaisesRegex(osv_active.OSVUnavailable, "bayat"):
            osv_active._trusted_db()

    def test_tampered_database_bytes_rejected(self) -> None:
        result = self._refresh()
        db = Path(json.loads(Path(os.environ["SNIPER_OSV_DB_MANIFEST"]).read_text())["scanner_cache_path"])
        os.chmod(db, 0o600)
        data = bytearray(db.read_bytes())
        data[-1] ^= 0x01
        db.write_bytes(bytes(data))
        self.assertNotEqual(hashlib.sha256(bytes(data)).hexdigest(), result["sha256"])
        with self.assertRaisesRegex(osv_active.OSVUnavailable, "sabitlemesi uyuşmuyor"):
            osv_active._trusted_db()

    def test_symlinked_manifest_rejected(self) -> None:
        self._refresh()
        real = Path(os.environ["SNIPER_OSV_DB_MANIFEST"])
        link = self.root / "link.json"
        os.symlink(real, link)
        os.environ["SNIPER_OSV_DB_MANIFEST"] = str(link)
        with self.assertRaises(osv_active.OSVUnavailable):
            osv_active._trusted_db()

    def test_cli_status_and_dropin(self) -> None:
        import subprocess
        self._refresh()
        script = Path(__file__).resolve().parents[1] / "scripts" / "osv_refresh.py"
        proc = subprocess.run([sys.executable, str(script), "--root", str(self.root), "--status"],
                              capture_output=True, text=True, timeout=60, env=dict(os.environ))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        status = json.loads(proc.stdout)[0]
        self.assertEqual(status["status"], "present")
        self.assertIs(status["signature_valid"], True)
        key_bytes = Path(os.environ["SNIPER_AUDIT_KEY_FILE"]).read_bytes()
        self.assertNotIn(key_bytes.hex(), proc.stdout + proc.stderr)
        proc = subprocess.run([sys.executable, str(script), "--root", str(self.root), "--print-dropin"],
                              capture_output=True, text=True, timeout=60)
        self.assertIn("Environment=SNIPER_OSV_DB_MANIFEST=", proc.stdout)


if __name__ == "__main__":
    unittest.main()
