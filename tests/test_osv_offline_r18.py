"""18. tur: çok ekosistemli çevrimdışı OSV eşlemesi (sürüm karşılaştırma, aralıklar, güven, dizin, envanter, API)."""
from __future__ import annotations

import base64
import email.message
import gzip
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit_integrity  # noqa: E402
import dependency_security as ds  # noqa: E402
import osv_db_refresh  # noqa: E402
import osv_offline as oo  # noqa: E402
import project_analyzer  # noqa: E402
import system_health  # noqa: E402


# --- yardımcılar -----------------------------------------------------------------------------------

def _zip(records: list[dict]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
    return buffer.getvalue()


class _Response:
    def __init__(self, body: bytes):
        self._stream = io.BytesIO(body)
        self.status = 200
        headers = email.message.Message()
        headers["Content-Length"] = str(len(body))
        headers["x-goog-hash"] = "md5=" + base64.b64encode(hashlib.md5(body).digest()).decode()
        headers["Last-Modified"] = "Mon, 19 Oct 2026 13:48:03 GMT"
        self.headers = headers

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        pass


def _install(root: Path, ecosystem: str, records: list[dict], now: datetime | None = None) -> dict:
    body = _zip(records)
    return osv_db_refresh.refresh(ecosystem, root=root, opener=lambda request, timeout=None: _Response(body),
                                  now=now)


def _rec(rid: str, ecosystem: str, name: str, events: list[dict] | None = None, *, rtype: str = "ECOSYSTEM",
         versions: list[str] | None = None, aliases: list[str] | None = None, severity: str | None = None,
         symbols: list[str] | None = None) -> dict:
    affected: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if events is not None:
        affected["ranges"] = [{"type": rtype, "events": events}]
    if versions is not None:
        affected["versions"] = versions
    if symbols:
        affected["ecosystem_specific"] = {"imports": [{"path": name, "symbols": symbols}]}
    record = {"id": rid, "modified": "2026-10-01T00:00:00Z", "summary": f"{rid} özeti", "affected": [affected],
              "aliases": aliases or []}
    if severity:
        record["database_specific"] = {"severity": severity}
    return record


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- sürüm karşılaştırma ---------------------------------------------------------------------------

class VersionCompareTests(unittest.TestCase):
    def test_semver_and_go_pseudo(self):
        self.assertLess(oo.compare_semver("1.0.0-alpha", "1.0.0"), 0)
        self.assertLess(oo.compare_semver("1.0.0-alpha.1", "1.0.0-alpha.beta"), 0)
        self.assertLess(oo.compare_semver("1.2.9", "1.10.0"), 0)
        self.assertEqual(oo.compare_semver("v1.2.3", "1.2.3"), 0)
        self.assertLess(oo.compare_semver("0.0.0-20201021035429-f5854403a974", "0.0.1"), 0)
        self.assertEqual(oo.normalize_version("Go", "v2.0.3+incompatible"), "2.0.3")

    def test_pep440(self):
        self.assertLess(oo.compare_pypi("1.0rc1", "1.0"), 0)
        self.assertGreater(oo.compare_pypi("1.0.post1", "1.0"), 0)
        self.assertEqual(oo.compare_pypi("1.0", "1.0.0"), 0)

    def test_maven(self):
        order = ["1.0-alpha", "1.0-beta", "1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp", "1.0.1"]
        for a, b in zip(order, order[1:]):
            self.assertLess(oo.compare_maven(a, b), 0, (a, b))
        self.assertEqual(oo.compare_maven("2.0.0.RELEASE", "2.0"), 0)
        self.assertEqual(oo.compare_maven("1.0.0-alpha", "1.0-alpha"), 0)
        self.assertLess(oo.compare_maven("5.3.17", "5.3.18"), 0)

    def test_rubygems_and_platform(self):
        self.assertLess(oo.compare_rubygems("1.0.a", "1.0"), 0)
        self.assertGreater(oo.compare_rubygems("1.10", "1.9"), 0)
        self.assertEqual(oo.compare_rubygems("1.0.0", "1.0"), 0)
        self.assertEqual(oo.normalize_version("RubyGems", "1.19.0-x86_64-linux-gnu"), "1.19.0")
        self.assertEqual(oo.normalize_version("RubyGems", "2.0.0.rc1"), "2.0.0.rc1")

    def test_nuget_and_packagist(self):
        self.assertLess(oo.compare_nuget("1.0.0-beta", "1.0.0"), 0)
        self.assertLess(oo.compare_nuget("4.5.0", "4.5.0.1"), 0)
        self.assertLess(oo.compare_packagist("v3.4.29", "3.4.30"), 0)
        self.assertLess(oo.compare_packagist("1.0.0-RC1", "1.0.0"), 0)
        self.assertGreater(oo.compare_packagist("1.0.0-p1", "1.0.0"), 0)

    def test_concrete_version(self):
        for value in ("1.2.3", "v1.2", "2.0.0.RELEASE"):
            self.assertTrue(oo.concrete_version("Maven", value), value)
        for value in ("", "^1.2", "${spring.version}", ">=1.0", "latest", "dev-main", "[1.0,2.0)"):
            self.assertFalse(oo.concrete_version("Maven", value), value)


class RangeTests(unittest.TestCase):
    def test_intervals_last_affected_and_unsorted(self):
        cmp = oo.compare_semver
        events = [{"fixed": "2.3.0"}, {"introduced": "2.0.0"}, {"introduced": "0"}, {"fixed": "1.2.0"}]
        self.assertTrue(oo.range_affects("1.1.9", events, cmp))
        self.assertFalse(oo.range_affects("1.2.0", events, cmp))
        self.assertFalse(oo.range_affects("1.5.0", events, cmp))
        self.assertTrue(oo.range_affects("2.1.0", events, cmp))
        self.assertFalse(oo.range_affects("2.3.0", events, cmp))
        last = [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]
        self.assertTrue(oo.range_affects("1.4.0", last, cmp))
        self.assertFalse(oo.range_affects("1.4.1", last, cmp))
        self.assertFalse(oo.range_affects("0.9.0", last, cmp))

    def test_versions_list_and_git_ranges_ignored(self):
        entry = {"versions": ["1.0"], "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}
        self.assertTrue(oo.affected_entry_matches("PyPI", "1.0.0", entry))  # PEP 440 eşitliği
        self.assertFalse(oo.affected_entry_matches("PyPI", "1.1", entry))


class SeverityTests(unittest.TestCase):
    def test_words_and_cvss(self):
        self.assertEqual(oo.record_severity({"database_specific": {"severity": "MODERATE"}}), "medium")
        self.assertEqual(oo.record_severity({"severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}), "critical")
        self.assertEqual(oo.record_severity({}), "unknown")


# --- uçtan uca: güvenilir veritabanı + eşleme ------------------------------------------------------

class OfflineMatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "osv"
        audit_integrity.load_key(create=True)
        pypi = [
            _rec("PYSEC-2026-1", "PyPI", "Django_Rest", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["GHSA-aaaa"]),
            _rec("GHSA-aaaa", "PyPI", "django-rest", [{"introduced": "0"}, {"fixed": "2.0"}], severity="HIGH",
                 aliases=["PYSEC-2026-1", "CVE-2026-1"]),
            _rec("GHSA-bbbb", "PyPI", "flask", versions=["0.12.2"], severity="LOW"),
            _rec("GHSA-withdrawn", "PyPI", "flask", [{"introduced": "0"}]) | {"withdrawn": "2026-01-01T00:00:00Z"},
        ]
        go = [
            _rec("GO-2026-0001", "Go", "golang.org/x/net", [{"introduced": "0"}, {"fixed": "0.7.0"}], rtype="SEMVER",
                 aliases=["GHSA-cccc"], symbols=["Parse"]),
            _rec("GHSA-cccc", "Go", "golang.org/x/net", [{"introduced": "0"}, {"fixed": "0.7.0"}], rtype="SEMVER",
                 aliases=["GO-2026-0001"], severity="CRITICAL"),
        ]
        ruby = [_rec("GHSA-dddd", "RubyGems", "nokogiri", [{"introduced": "0"}, {"fixed": "1.19.1"}], severity="HIGH")]
        self.results = {eco: _install(self.root, eco, records) for eco, records in
                        (("PyPI", pypi), ("Go", go), ("RubyGems", ruby))}
        self.project = self.base / "proj"
        _write(self.project, "requirements.txt", "django_rest==1.5\nflask==0.12.2\nrequests\n")
        _write(self.project, "go.mod", "module demo\n\ngo 1.13\n\nrequire (\n\tgithub.com/gorilla/mux v1.7.4\n)\n")
        _write(self.project, "go.sum", "golang.org/x/net v0.0.0-20200101000000-aaaaaaaaaaaa h1:x=\n"
                                       "golang.org/x/net v0.6.0 h1:y=\ngolang.org/x/net v0.9.0/go.mod h1:z=\n")
        _write(self.project, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n"
                                             "    nokogiri (1.19.0-x86_64-linux-gnu)\n    nokogiri (1.19.0-arm64-darwin)\n"
                                             "\nPLATFORMS\n  ruby\n")
        _write(self.project, "Cargo.lock", '[[package]]\nname = "regex"\nversion = "1.5.4"\n')
        patcher = mock.patch.object(project_analyzer, "_allowed_roots", return_value=(self.base,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_manifest_records_signed_index(self):
        manifest = osv_db_refresh.read_manifest(osv_db_refresh.manifest_path(self.root, "PyPI"))
        index_path = Path(manifest["scanner_cache_path"]).parent / osv_db_refresh.INDEX_FILENAME
        raw = index_path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest["package_index_sha256"])
        packages = json.loads(gzip.decompress(raw))["packages"]
        self.assertEqual(sorted(packages["django-rest"]), ["GHSA-aaaa.json", "PYSEC-2026-1.json"])  # PEP 503
        self.assertNotIn("GHSA-withdrawn.json", packages["flask"])

    def test_scan_project_end_to_end(self):
        report = oo.scan_project(str(self.project), root=self.root)
        by = {(f["package_name"], f["vulnerability_id"]): f for f in report["findings"]}
        # PYSEC + GHSA takma adları tek bulgu; önem takma addan; sürümsüz 'requests' atlanır
        self.assertIn(("django_rest", "GHSA-aaaa"), by)
        self.assertNotIn(("django_rest", "PYSEC-2026-1"), by)
        self.assertEqual(by[("django_rest", "GHSA-aaaa")]["severity"], "high")
        self.assertEqual(by[("django_rest", "GHSA-aaaa")]["fixed_version"], "2.0")
        self.assertIn(("flask", "GHSA-bbbb"), by)
        # Go: go.sum'dan en yüksek sürüm (0.6.0 < 0.7.0) ve sembollü GO- kaydı temsilci; önem GHSA'dan
        self.assertIn(("golang.org/x/net", "GO-2026-0001"), by)
        self.assertEqual(by[("golang.org/x/net", "GO-2026-0001")]["severity"], "critical")
        self.assertEqual(by[("golang.org/x/net", "GO-2026-0001")]["installed_version"], "0.6.0")
        # Ruby platform kopyaları tek bulgu, platform eki atılmış sürümle
        ruby = [f for f in report["findings"] if f["package_name"] == "nokogiri"]
        self.assertEqual([(f["installed_version"], f["vulnerability_id"]) for f in ruby], [("1.19.0", "GHSA-dddd")])
        self.assertEqual(report["skipped"]["no_concrete_version"], 1)
        coverage = {c["ecosystem"]: c for c in report["coverage"]}
        self.assertEqual(coverage["crates.io"]["status"], "unavailable")  # veritabanı yok → kapsam dışı, uyarı
        self.assertIn("crates.io: çevrimdışı veritabanı yok. 1 bileşen denetlenmedi.", report["warnings"])
        self.assertEqual(report["source"], "osv")
        self.assertTrue(report["source_path"].startswith("osv-offline:"))

    def test_fixed_version_does_not_match(self):
        result = oo.match_components([
            {"name": "django-rest", "version": "2.0", "ecosystem": "PyPI", "manifest": "x"},
            {"name": "golang.org/x/net", "version": "0.7.0", "ecosystem": "Golang", "manifest": "x"},
            {"name": "nokogiri", "version": "1.19.1", "ecosystem": "RubyGems", "manifest": "x"}], root=self.root)
        self.assertEqual(result["document"]["results"][0]["packages"], [])

    def test_tampered_manifest_and_archive_are_rejected(self):
        path = osv_db_refresh.manifest_path(self.root, "PyPI")
        manifest = json.loads(path.read_text())
        manifest["bytes"] += 0  # aynı içerik
        manifest["generation"] = "değiştirildi"
        os.chmod(path, 0o600)
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(oo.OfflineDBError, "imzası doğrulanamadı"):
            oo.load_db("PyPI", root=self.root)
        archive = Path(json.loads(osv_db_refresh.manifest_path(self.root, "Go").read_text())["scanner_cache_path"])
        os.chmod(archive, 0o600)
        with archive.open("ab") as stream:
            stream.write(b"x")
        with self.assertRaisesRegex(oo.OfflineDBError, "uyuşmuyor"):
            oo.load_db("Go", root=self.root)
        statuses = {s["ecosystem"]: s["status"] for s in oo.database_status(root=self.root)}
        self.assertEqual((statuses["PyPI"], statuses["Go"], statuses["RubyGems"], statuses["npm"]),
                         ("untrusted", "untrusted", "ok", "missing"))

    def test_tampered_index_is_rejected(self):
        manifest = osv_db_refresh.read_manifest(osv_db_refresh.manifest_path(self.root, "RubyGems"))
        index_path = Path(manifest["scanner_cache_path"]).parent / osv_db_refresh.INDEX_FILENAME
        os.chmod(index_path, 0o600)
        index_path.write_bytes(gzip.compress(b'{"format":"sniper-osv-index/1","packages":{}}'))
        oo._INDEXES.clear()
        with self.assertRaisesRegex(oo.OfflineDBError, "paket dizini"):
            oo.load_db("RubyGems", root=self.root).index()

    def test_stale_database_warns(self):
        later = datetime.now(timezone.utc) + timedelta(days=9)
        result = oo.match_components([{"name": "flask", "version": "0.12.2", "ecosystem": "PyPI", "manifest": "x"}],
                                     root=self.root, now=later)
        self.assertEqual(result["coverage"][0]["status"], "stale")
        self.assertTrue(result["warnings"])
        self.assertEqual(len(result["document"]["results"][0]["packages"]), 1)  # bayat veri yine kullanılır

    def test_index_fallback_for_old_generation(self):
        manifest_path = osv_db_refresh.manifest_path(self.root, "RubyGems")
        manifest = json.loads(manifest_path.read_text())
        for key in [k for k in manifest if k.startswith("package_index")]:
            manifest.pop(key)
        key_state = audit_integrity.load_key(create=False)
        manifest["mac"] = audit_integrity.document_mac(key_state.key, osv_db_refresh.MANIFEST_MAC_LABEL, manifest)
        os.chmod(manifest_path, 0o600)
        manifest_path.write_text(json.dumps(manifest))
        oo._INDEXES.clear()
        self.assertEqual(oo.load_db("RubyGems", root=self.root).index(), {"nokogiri": ["GHSA-dddd.json"]})


class EcosystemConfigTests(unittest.TestCase):
    def test_env_config_file_and_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(osv_db_refresh.configured_ecosystems(root, {}), list(osv_db_refresh.DEFAULT_ECOSYSTEMS))
            (root / "ecosystems.json").write_text(json.dumps({"ecosystems": ["PyPI", "../x", "Go", "PyPI"]}))
            self.assertEqual(osv_db_refresh.configured_ecosystems(root, {}), ["PyPI", "Go"])
            self.assertEqual(osv_db_refresh.configured_ecosystems(root, {"SNIPER_OSV_ECOSYSTEMS": "npm, Maven"}),
                             ["npm", "Maven"])

    def test_per_ecosystem_download_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = b"x" * 2048
            with mock.patch.dict(osv_db_refresh.ECOSYSTEM_MAX_BYTES, {"Pub": 1024}):
                with self.assertRaisesRegex(osv_db_refresh.OSVRefreshError, "boyut"):
                    osv_db_refresh.refresh("Pub", root=Path(tmp) / "osv",
                                           opener=lambda request, timeout=None: _Response(body))

    def test_cli_continues_after_one_failure(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("osv_refresh_cli", Path(__file__).resolve().parents[1] / "scripts" / "osv_refresh.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        calls = []

        def fake_refresh(ecosystem, **kwargs):
            calls.append(ecosystem)
            if ecosystem == "PyPI":
                raise RuntimeError("beklenmeyen")
            return {"status": "updated", "ecosystem": ecosystem, "manifest_signed": True}

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(cli.osv_db_refresh, "refresh", fake_refresh), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            code = cli.main(["--root", tmp, "--ecosystem", "PyPI", "--ecosystem", "Go"])
        self.assertEqual((code, calls), (1, ["PyPI", "Go"]))


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_nuget_sources(self):
        _write(self.root, "App.csproj", '<Project><ItemGroup>'
                                        '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
                                        '<PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference>'
                                        '<PackageReference Include="Central.Pkg" />'
                                        '<PackageReference Include="Floating" Version="1.*" />'
                                        '</ItemGroup></Project>')
        _write(self.root, "Directory.Packages.props", '<Project><ItemGroup><PackageVersion Include="Central.Pkg" Version="[3.1.0]" />'
                                                      '</ItemGroup></Project>')
        _write(self.root, "packages.config", '<packages><package id="jQuery" version="1.7.1" /></packages>')
        _write(self.root, "packages.lock.json", json.dumps({"dependencies": {"net8.0": {
            "Polly": {"type": "Transitive", "resolved": "7.2.3"}, "MyLib": {"type": "Project"}}}}))
        got = {(c["name"], c["version"], c["manifest"]) for c in ds._nuget_components(self.root)}
        self.assertEqual(got, {("Newtonsoft.Json", "12.0.1", "App.csproj"), ("Serilog", "2.10.0", "App.csproj"),
                               ("Central.Pkg", "3.1.0", "App.csproj"), ("jQuery", "1.7.1", "packages.config"),
                               ("Polly", "7.2.3", "packages.lock.json")})

    def test_nuget_xml_entities_rejected(self):
        _write(self.root, "packages.config", '<!DOCTYPE x [<!ENTITY a "b">]><packages/>')
        with self.assertRaises(ds.DependencySecurityError):
            ds._nuget_components(self.root)

    def test_uv_lock_registry_only(self):
        _write(self.root, "uv.lock", 'version = 1\n[[package]]\nname = "jinja2"\nversion = "3.1.2"\n'
                                     'source = { registry = "https://pypi.org/simple" }\n'
                                     '[[package]]\nname = "local-app"\nversion = "0.1.0"\nsource = { editable = "." }\n')
        self.assertEqual([(c["name"], c["version"]) for c in ds._uv_lock_components(self.root)], [("jinja2", "3.1.2")])

    def test_go_sum_highest_version_not_in_go_mod(self):
        _write(self.root, "go.mod", "module x\n\nrequire github.com/a/b v1.0.0\n")
        _write(self.root, "go.sum", "github.com/a/b v0.9.0 h1:a=\ngolang.org/x/text v0.3.0 h1:b=\n"
                                    "golang.org/x/text v0.3.3 h1:c=\ngolang.org/x/text v0.9.0/go.mod h1:d=\n")
        got = [(c["name"], c["version"], c["manifest"]) for c in ds._go_components(self.root)]
        self.assertEqual(got, [("github.com/a/b", "1.0.0", "go.mod"), ("golang.org/x/text", "0.3.3", "go.sum")])

    def test_purl_types(self):
        self.assertEqual(ds._package_url("NuGet", "Newtonsoft.Json", "12.0.1"), "pkg:nuget/Newtonsoft.Json@12.0.1")


class HealthTests(unittest.TestCase):
    def test_other_ecosystems_info_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": tmp}):
            check = system_health.check_osv_ecosystems(datetime.now(timezone.utc))[0]
        self.assertEqual((check["id"], check["status"]), ("osv_db_ecosystems", "info"))


class OfflineScanApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.osv_root = base / "osv"
        audit_integrity.load_key(create=True)
        _install(self.osv_root, "PyPI", [_rec("GHSA-eeee", "PyPI", "jinja2", [{"introduced": "0"}, {"fixed": "3.1.3"}],
                                              severity="MODERATE")])
        self.project = base / "proj"
        _write(self.project, "requirements.txt", "Jinja2==3.1.2\n")
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        for patch in (mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir),
                                                   "SNIPER_OSV_DB_ROOT": str(self.osv_root)}),
                      mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,)),
                      mock.patch.object(server, "LIMITER", server.RateLimiter(limit=100000))):
            patch.start()
            self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def call(self, path, body=None):
        request = urllib.request.Request(
            self.base_url + path, method="POST" if body is not None else "GET",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_scan_imports_findings_and_status(self):
        path = str(self.project)
        self.assertEqual(self.call("/api/dependency-security/offline-scan", {"project_path": path})[0], 400)
        self.assertEqual(self.call("/api/dependency-security/offline-scan",
                                   {"project_path": path, "confirm_local": False})[0], 400)
        status, data = self.call("/api/dependency-security/offline-scan", {"project_path": path, "confirm_local": True})
        self.assertEqual(status, 201, data)
        self.assertEqual((data["finding_count"], data["deduplicated"]), (1, False))
        self.assertEqual(data["coverage"][0]["ecosystem"], "PyPI")
        status, again = self.call("/api/dependency-security/offline-scan", {"project_path": path, "confirm_local": True})
        self.assertTrue(again["deduplicated"])
        findings = self.call("/api/dependency-security")[1]["findings"]
        self.assertEqual([(f["package_name"], f["vulnerability_id"], f["severity"], f["source"]) for f in findings],
                         [("Jinja2", "GHSA-eeee", "medium", "osv")])
        status, db = self.call("/api/dependency-security/offline-db")
        self.assertEqual(status, 200)
        pypi = next(item for item in db["databases"] if item["ecosystem"] == "PyPI")
        self.assertEqual((pypi["status"], pypi["records"], pypi["indexed"]), ("ok", 1, True))


if __name__ == "__main__":
    unittest.main()
