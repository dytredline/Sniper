"""18. tur: konteyner imajı / rootfs işletim sistemi paket taraması (Docker daemon yok, ağ yok).

Sürüm karşılaştırmaları (dpkg/apk/rpm), imaj biçimleri (docker save, OCI gzip, rootfs tar/dizin), güvenli katman
açma (whiteout, ``..``/mutlak ad, aygıt dosyası, kök dışına sembolik bağ, zstd), paket veritabanları, OSV eşleştirme
(aralık, ``versions`` listesi, düzeltmesiz, duyuru tekilleştirme), bulgu takibi ("düzeldi"), API ve rol kuralları.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
import zipfile

import auth
import container_scan as cs
import os_versions as ov

DEB_OS = b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\nID=debian\n'
ALP_OS = b'ID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME="Alpine Linux v3.19"\n'
DEB_STATUS = b"""Package: libssl3
Status: install ok installed
Architecture: arm64
Source: openssl
Version: 3.0.11-1~deb12u1

Package: openssl
Status: install ok installed
Architecture: arm64
Version: 3.0.11-1~deb12u1

Package: zlib1g
Status: install ok installed
Source: zlib (1:1.2.13.dfsg-1)
Version: 1:1.2.13.dfsg-1+b1

Package: gone
Status: deinstall ok config-files
Version: 1.0-1
"""
ALP_DB = b"P:libcrypto3\nV:3.1.4-r0\nA:aarch64\no:openssl\n\nP:busybox\nV:1.36.1-r15\no:busybox\n\n"


def _tar(entries, gz=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name, kind, data in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = data
                archive.addfile(info)
            elif kind == "chr":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gz else raw


def _osv_root(base: Path, ecosystem: str, records: list[dict]) -> Path:
    """osv_db_refresh düzeninde sahte çevrimdışı OSV veritabanı (manifest + zip)."""
    import osv_db_refresh

    root = base / "osv"
    slug = osv_db_refresh._slug(ecosystem)
    target = root / "generations" / slug / "g1" / "db-cache" / "osv-scalibr" / ecosystem / "all.zip"
    target.parent.mkdir(parents=True)
    for path in [root, *target.parents]:
        if root in path.parents or path == root:
            os.chmod(path, 0o700)
    with zipfile.ZipFile(target, "w") as bundle:
        for record in records:
            bundle.writestr(f"{record['id']}.json", json.dumps(record))
    sha = hashlib.sha256(target.read_bytes()).hexdigest()
    osv_db_refresh.manifest_path(root, ecosystem).write_text(json.dumps({
        "ecosystem": ecosystem, "scanner_cache_path": str(target), "sha256": sha, "generation": "g1",
        "retrieved_utc": "2026-10-21T00:00:00+00:00"}))
    return root


def _rec(vid, ecosystem, name, events, *, versions=None, aliases=(), specific=None, severity=None):
    affected = {"package": {"name": name, "ecosystem": ecosystem}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
    if versions is not None:
        affected["versions"] = versions
    if specific:
        affected["ecosystem_specific"] = specific
    record = {"id": vid, "modified": "2026-01-01T00:00:00Z", "aliases": list(aliases), "affected": [affected]}
    if severity:
        record["severity"] = [{"type": "CVSS_V3", "score": severity}]
    return record


DEBIAN_RECORDS = [
    _rec("CVE-2023-5363", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}],
         specific={"urgency": "high"}),
    _rec("CVE-2099-0001", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.10-1"}]),  # zaten düzeltilmiş
    _rec("CVE-2023-45853", "Debian:12", "zlib", [{"introduced": "0"}],
         severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # düzeltme yok, CVSS → kritik
    _rec("DSA-5532-1", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}],
         aliases=["CVE-2023-5363"]),  # duyuru: CVE kaydıyla yinelenir → tekilleşir
    _rec("CVE-2023-0001", "Debian:11", "openssl", [{"introduced": "0"}, {"fixed": "9.9"}]),  # başka sürüm: yok sayılır
    _rec("CVE-2023-0002", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.12-1"}],
         specific={"urgency": "unimportant"}),
]


class VersionCompareTests(unittest.TestCase):
    def check(self, compare, cases):
        for a, b, expected in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(compare(a, b), expected)
                self.assertEqual(compare(b, a), -expected)

    def test_dpkg(self):
        self.check(ov.dpkg_compare, [
            ("1.0", "1.0", 0), ("1.0", "1.0-0", 0), ("1:0.9", "1.0", 1), ("1.0~rc1", "1.0", -1),
            ("1.0~rc1", "1.0~rc1~b", 1), ("1.0a", "1.0", 1), ("1.0+b1", "1.0", 1),
            ("2.36-9+deb12u3", "2.36-9+deb12u10", -1), ("1.2.13.dfsg-1", "1.2.13-1", 1),
            ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.10", -1), ("1.0-1", "1.0-1build1", -1),
        ])
        with self.assertRaises(ValueError):
            ov.dpkg_compare("a:1", "1")

    def test_apk(self):
        self.check(ov.apk_compare, [
            ("1.0", "1.0-r1", -1), ("1.0_alpha1", "1.0", -1), ("1.0_rc1", "1.0_rc2", -1), ("1.0_p1", "1.0", 1),
            ("1.0a", "1.0", 1), ("1.0a", "1.0b", -1), ("3.1.4-r0", "3.1.4-r1", -1), ("3.1.10-r0", "3.1.9-r5", 1),
            ("1.2.4_git20230717-r4", "1.2.4-r4", 1), ("1.0_beta2", "1.0_alpha9", 1), ("2.0", "1.99", 1),
            ("1.36.1-r15", "1.36.1-r15", 0),
        ])

    def test_rpm(self):
        self.check(ov.rpm_compare, [
            ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0.1a", "2.0.1", 1), ("5.5p1", "5.5p2", -1),
            ("10.0001", "10.1", 0), ("1.0~rc1", "1.0", -1), ("1.0^git1", "1.0", 1), ("1.0^git1", "1.0.1", -1),
            ("1:1.0-1", "2.0-1", 1), ("1.0-1.el9", "1.0-2.el9", -1),
        ])


class OsAndPackageDbTests(unittest.TestCase):
    def test_os_ecosystem_mapping(self):
        cases = {
            ("debian", "12", ""): "Debian:12", ("ubuntu", "24.04", "24.04.5 LTS (Noble Numbat)"): "Ubuntu:24.04:LTS",
            ("ubuntu", "23.10", "23.10 (Mantic)"): "Ubuntu:23.10", ("alpine", "3.19.1", ""): "Alpine:v3.19",
            ("almalinux", "9.3", ""): "AlmaLinux:9", ("rocky", "8.9", ""): "Rocky Linux:8",
        }
        for (os_id, version, label), expected in cases.items():
            with self.subTest(os_id=os_id):
                self.assertEqual(cs.os_ecosystem({"ID": os_id, "VERSION_ID": version, "VERSION": label})[0], expected)
        self.assertIsNone(cs.os_ecosystem({"ID": "debian"})[0])
        self.assertIsNone(cs.os_ecosystem({"ID": "gentoo", "VERSION_ID": "2"})[0])
        self.assertEqual(cs.parse_os_release(b'ID="alpine"\n# yorum\nVERSION_ID=3.19\n'), {"ID": "alpine", "VERSION_ID": "3.19"})

    def test_dpkg_status_parsing(self):
        packages = cs.parse_dpkg(DEB_STATUS, "var/lib/dpkg/status")
        self.assertEqual([p["name"] for p in packages], ["libssl3", "openssl", "zlib1g"])  # kaldırılan yok
        zlib = packages[2]
        self.assertEqual((zlib["source"], zlib["source_version"], zlib["version"]), ("zlib", "1:1.2.13.dfsg-1", "1:1.2.13.dfsg-1+b1"))
        self.assertEqual(packages[0]["line"], 1)

    def test_apk_installed_parsing(self):
        packages = cs.parse_apk(ALP_DB, "lib/apk/db/installed")
        self.assertEqual([(p["name"], p["source"], p["version"]) for p in packages],
                         [("libcrypto3", "openssl", "3.1.4-r0"), ("busybox", "busybox", "1.36.1-r15")])

    def test_rpm_sqlite_parsing(self):
        def header(tags):
            index, data = b"", b""
            for tag, kind, value in tags:
                offset = len(data)
                if kind == 6:
                    data += value.encode() + b"\x00"
                else:
                    while len(data) % 4:
                        data += b"\x00"
                    offset = len(data)
                    data += struct.pack(">I", value)
                index += struct.pack(">IIII", tag, kind, offset, 1)
            return struct.pack(">II", len(tags), len(data)) + index + data

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "rpmdb.sqlite"
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
            con.execute("INSERT INTO Packages VALUES (1, ?)", (header([(1000, 6, "openssl-libs"), (1001, 6, "3.0.7"),
                        (1002, 6, "24.el9"), (1003, 4, 1), (1022, 6, "aarch64"), (1044, 6, "openssl-3.0.7-24.el9.src.rpm")]),))
            con.execute("INSERT INTO Packages VALUES (2, ?)", (b"\x00\x00\x00\x05bozuk",))
            con.commit()
            con.close()
            packages = cs.parse_rpm_sqlite(db.read_bytes(), "var/lib/rpm/rpmdb.sqlite")
        self.assertEqual(len(packages), 1)
        self.assertEqual((packages[0]["name"], packages[0]["version"], packages[0]["source"]), ("openssl-libs", "1:3.0.7-24.el9", "openssl"))


class ImageFormatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.lower = [("usr/lib/os-release", "file", ALP_OS), ("etc/os-release", "sym", "../usr/lib/os-release"),
                      ("lib/apk/db/installed", "file", ALP_DB), ("dev/null", "chr", None), ("../kacis", "file", b"x"),
                      ("/mutlak/kacis", "file", b"x"), ("opt/eski/lib/python3/site-packages/eski-1.0.dist-info/METADATA", "file", b"Name: eski\nVersion: 1.0\n"),
                      ("srv/catalog", "dir", None), ("srv/catalog/lib/node_modules/sil/package.json", "file", b'{"name":"sil","version":"1.0.0"}')]
        self.upper = [("lib/apk/db/installed", "file", ALP_DB.split(b"\n\n")[0] + b"\n"), ("opt/.wh.eski", "file", b""),
                      ("srv/catalog/.wh..wh..opq", "file", b""),
                      ("usr/lib/python3/site-packages/Jinja2-2.10.dist-info/METADATA", "file", b"Name: Jinja2\nVersion: 2.10\n"),
                      ("app/node_modules/@scope/pkg/package.json", "file", b'{"name":"@scope/pkg","version":"2.0.0"}')]

    def _docker_save(self, layers):
        path = self.base / "imaj.tar"
        with tarfile.open(path, "w") as archive:
            names = []
            for index, data in enumerate(layers):
                info = tarfile.TarInfo(f"l{index}/layer.tar")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
                names.append(info.name)
            manifest = json.dumps([{"RepoTags": ["test/alpine:1"], "Layers": names}]).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            archive.addfile(info, io.BytesIO(manifest))
        return path

    def _oci(self, layers, media="application/vnd.oci.image.layer.v1.tar+gzip"):
        path = self.base / "oci.tar"
        blobs = {}

        def blob(data):
            digest = hashlib.sha256(data).hexdigest()
            blobs[digest] = data
            return digest
        descriptors = [{"mediaType": media, "digest": "sha256:" + blob(layer), "size": len(layer)} for layer in layers]
        manifest = json.dumps({"schemaVersion": 2, "layers": descriptors}).encode()
        index = json.dumps({"manifests": [{"digest": "sha256:" + blob(manifest),
                                            "annotations": {"org.opencontainers.image.ref.name": "test/oci:1"}}]}).encode()
        with tarfile.open(path, "w") as archive:
            for name, data in [("oci-layout", b"{}"), ("index.json", index)] + [(f"blobs/sha256/{d}", b) for d, b in blobs.items()]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def _check_merged(self, vfs):
        self.assertEqual(cs.parse_os_release(vfs.read("etc/os-release"))["ID"], "alpine")  # sembolik bağ çözüldü
        self.assertEqual([p["name"] for p in cs.parse_apk(vfs.read("lib/apk/db/installed"), "x")], ["libcrypto3"])  # üst katman
        components = {(c["ecosystem"], c["name"]) for c in cs.language_components(vfs)}
        self.assertEqual(components, {("PyPI", "Jinja2"), ("npm", "@scope/pkg")})  # whiteout + opak dizin uygulandı
        self.assertEqual(vfs.skipped["special"], 1)
        self.assertEqual(vfs.skipped["unsafe_name"], 1)  # "../kacis"; "/mutlak/kacis" köke göreli kabul edilir
        self.assertNotIn("kacis", vfs.files)

    def test_docker_save(self):
        vfs, meta = cs.load_image(self._docker_save([_tar(self.lower), _tar(self.upper)]))
        self.assertEqual((meta["format"], meta["layers"], meta["tags"]), ("docker-save", 2, ["test/alpine:1"]))
        self._check_merged(vfs)

    def test_oci_gzip_layers(self):
        vfs, meta = cs.load_image(self._oci([_tar(self.lower, gz=True), _tar(self.upper, gz=True)]))
        self.assertEqual((meta["format"], meta["tags"]), ("oci", ["test/oci:1"]))
        self._check_merged(vfs)

    def test_zstd_layer_rejected(self):
        with self.assertRaises(cs.ContainerScanError):
            cs.load_image(self._oci([b"\x28\xb5\x2f\xfd" + b"0" * 32], media="application/vnd.oci.image.layer.v1.tar+zstd"))

    def test_plain_rootfs_tar_and_dir(self):
        path = self.base / "rootfs.tar"
        path.write_bytes(_tar(self.lower))
        vfs, meta = cs.load_image(path)
        self.assertEqual(meta["format"], "rootfs-tar")
        self.assertEqual(len(cs.parse_apk(vfs.read("lib/apk/db/installed"), "x")), 2)
        root = self.base / "rootfs"
        (root / "etc").mkdir(parents=True)
        (root / "etc/os-release").write_bytes(DEB_OS)
        (root / "var/lib/dpkg").mkdir(parents=True)
        (root / "var/lib/dpkg/status").write_bytes(DEB_STATUS)
        vfs, meta = cs.load_image(root)
        self.assertEqual(meta["format"], "rootfs-dir")
        self.assertEqual(len(cs.parse_dpkg(vfs.read("var/lib/dpkg/status"), "x")), 3)

    def test_symlink_cannot_escape_root(self):
        vfs = cs.VirtualFS()
        vfs.links["etc/os-release"] = "../../../../etc/passwd"
        vfs.links["a"] = "/b"
        vfs.links["b"] = "a"  # döngü
        self.assertEqual(vfs.resolve("etc/os-release"), "etc/passwd")
        self.assertIsNone(vfs.resolve("a/x"))


class MatchingAndScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.osv = _osv_root(self.base, "Debian:12", DEBIAN_RECORDS)
        self.root = self.base / "rootfs"
        (self.root / "etc").mkdir(parents=True)
        (self.root / "etc/os-release").write_bytes(DEB_OS)
        (self.root / "var/lib/dpkg").mkdir(parents=True)
        (self.root / "var/lib/dpkg/status").write_bytes(DEB_STATUS)

    def scan(self, **kwargs):
        return cs.scan_image(str(self.root), osv_root=self.osv, allowed_roots=(self.base,), **kwargs)

    def test_findings_severity_fix_and_dedupe(self):
        result = self.scan()
        by_id = {f["reference"]: f for f in result["findings"]}
        self.assertEqual(set(by_id), {"CVE-2023-5363", "CVE-2023-45853", "CVE-2023-0002"})  # DSA yinelemesi ve Debian:11 yok
        ssl = by_id["CVE-2023-5363"]
        self.assertEqual((ssl["severity"], ssl["fixed_version"], ssl["fix_state"]), ("high", "3.0.11-1~deb12u2", "fixed"))
        self.assertEqual(ssl["package"]["binaries"], ["libssl3", "openssl"])  # kaynak paket başına tek bulgu
        self.assertEqual(ssl["title"], "Açıklı işletim sistemi paketi: openssl (CVE-2023-5363)")
        self.assertNotIn("3.0.11", ssl["evidence"])  # sürüm parmak izine girmez
        zlib = by_id["CVE-2023-45853"]
        self.assertEqual((zlib["severity"], zlib["fix_state"], zlib["package"]["installed_version"]),
                         ("critical", "not_fixed", "1:1.2.13.dfsg-1"))  # kaynak sürümle eşleşir (+b1 değil)
        self.assertEqual(by_id["CVE-2023-0002"]["severity"], "info")  # unimportant
        self.assertEqual(result["audit_kind"], "container")
        self.assertEqual(result["container"]["os"]["ecosystem"], "Debian:12")
        self.assertEqual(result["container"]["fixable_findings"], 2)
        self.assertFalse(result["container"]["osv"]["cached"])
        self.assertTrue(self.scan()["container"]["osv"]["cached"])  # ikinci tarama dizini önbellekten okur

    def test_ignore_unfixed_and_versions_list(self):
        result = self.scan(ignore_unfixed=True)
        self.assertNotIn("CVE-2023-45853", {f["reference"] for f in result["findings"]})
        vuln = {"ranges": [], "versions": ["1.0-1", "1.0-2"]}
        self.assertEqual(cs._affected("1.0-2", vuln, ov.dpkg_compare), (True, None))
        self.assertEqual(cs._affected("1.0-3", vuln, ov.dpkg_compare), (False, None))
        last = {"ranges": [[{"introduced": "1.0"}, {"last_affected": "1.5"}]]}
        self.assertTrue(cs._affected("1.5", last, ov.dpkg_compare)[0])
        self.assertFalse(cs._affected("1.6", last, ov.dpkg_compare)[0])
        self.assertFalse(cs._affected("0.9", last, ov.dpkg_compare)[0])

    def test_missing_db_and_tampered_archive(self):
        (self.root / "etc/os-release").write_bytes(ALP_OS)
        (self.root / "lib/apk/db").mkdir(parents=True)
        (self.root / "lib/apk/db/installed").write_bytes(ALP_DB)
        result = self.scan()
        self.assertEqual(result["findings"], [])
        self.assertTrue(any("Alpine:v3.19" in w and "osv_refresh.py" in w for w in result["warnings"]))
        (self.root / "etc/os-release").write_bytes(DEB_OS)
        archive = next(self.osv.rglob("all.zip"))
        os.chmod(archive, 0o600)
        with zipfile.ZipFile(archive, "a") as bundle:
            bundle.writestr("EXTRA.json", "{}")
        with self.assertRaisesRegex(cs.ContainerScanError, "SHA-256"):
            cs.load_index("Debian:12", root=self.osv)

    def test_legacy_rpmdb_is_fail_closed_with_backend_evidence(self):
        """Gerçek Berkeley DB girdisi paket envanteri başarılıymış gibi gösterilmemeli."""
        root = self.base / "rhel-legacy"
        (root / "etc").mkdir(parents=True)
        (root / "etc/os-release").write_bytes(b'ID="rhel"\nVERSION_ID="9.4"\n')
        packages = root / "var/lib/rpm/Packages"
        packages.parent.mkdir(parents=True)
        encoded = (Path(__file__).parent / "fixtures/rpm_legacy_berkeleydb_hash_v9.b64").read_bytes()
        fixture = base64.b64decode(b"".join(encoded.split()), validate=True)
        self.assertEqual(hashlib.sha256(fixture).hexdigest(),
                         "71feca9d6704c596a734bdf42bf865122a8e5e6876f6c448e764b7d666fd5418")
        packages.write_bytes(fixture)
        osv = _osv_root(self.base / "rheldb", "Red Hat Enterprise Linux", [])

        result = cs.scan_image(str(root), osv_root=osv, allowed_roots=(self.base,))

        self.assertEqual(next(c for c in result["checks"] if c["id"] == "os_packages")["status"], "na")
        self.assertEqual(result["container"]["package_inventory"], {
            "status": "unsupported",
            "package_type": "rpm",
            "covered_files": [],
            "unsupported_files": [{"path": "var/lib/rpm/Packages", "backend": "berkeleydb"}],
            "reason": "legacy_rpmdb_unsupported",
        })
        self.assertTrue(any("BerkeleyDB" in warning and "var/lib/rpm/Packages" in warning
                            for warning in result["warnings"]))

    def test_unknown_legacy_rpmdb_is_not_mislabeled_or_passed(self):
        root = self.base / "rhel-unknown"
        (root / "etc").mkdir(parents=True)
        (root / "etc/os-release").write_bytes(b'ID="rhel"\nVERSION_ID="9.4"\n')
        packages = root / "var/lib/rpm/Packages"
        packages.parent.mkdir(parents=True)
        packages.write_bytes(b"not-a-database")
        osv = _osv_root(self.base / "rheldb-unknown", "Red Hat Enterprise Linux", [])

        result = cs.scan_image(str(root), osv_root=osv, allowed_roots=(self.base,))

        self.assertEqual(next(c for c in result["checks"] if c["id"] == "os_packages")["status"], "na")
        unsupported = result["container"]["package_inventory"]["unsupported_files"]
        self.assertEqual(unsupported, [{"path": "var/lib/rpm/Packages", "backend": "unknown"}])
        self.assertTrue(any("tanınmayan eski RPM" in warning for warning in result["warnings"]))
        self.assertEqual(cs.detect_legacy_rpmdb(b"short", "var/lib/rpm/Packages.db"), "ndb_candidate")
        self.assertEqual(cs._interesting("usr/lib/sysimage/rpm/Packages"), "rpm-legacy")

    def test_supported_inventory_control_is_available_and_can_pass(self):
        clean_osv = _osv_root(self.base / "clean-debian", "Debian:12", [])
        result = cs.scan_image(str(self.root), osv_root=clean_osv, allowed_roots=(self.base,))
        check = next(c for c in result["checks"] if c["id"] == "os_packages")
        self.assertEqual(check["status"], "pass")
        self.assertEqual(result["container"]["package_inventory"], {
            "status": "available",
            "package_type": "deb",
            "covered_files": ["var/lib/dpkg/status"],
            "unsupported_files": [],
            "reason": None,
        })

    def test_base_archive_fallback_and_non_security_filter(self):
        root = self.base / "alma"
        (root / "etc").mkdir(parents=True)
        (root / "etc/os-release").write_bytes(b'ID="almalinux"\nVERSION_ID="9.4"\n')
        osv = _osv_root(self.base / "almadb", "AlmaLinux", [
            _rec("ALSA-2024:0310", "AlmaLinux:9", "openssl-libs", [{"introduced": "0"}, {"fixed": "1:3.0.7-25.el9_3"}]),
            _rec("ALBA-2024:0001", "AlmaLinux:9", "openssl-libs", [{"introduced": "0"}, {"fixed": "1:3.0.7-99.el9"}]),
            _rec("ALSA-2024:0002", "AlmaLinux:8", "openssl-libs", [{"introduced": "0"}, {"fixed": "1:9.9-1"}]),
        ])
        self.assertEqual(cs.archive_ecosystem("AlmaLinux:9"), "AlmaLinux")
        self.assertEqual(cs.archive_ecosystem("Ubuntu:24.10"), "Ubuntu")
        self.assertEqual(cs.archive_ecosystem("Ubuntu:24.04:LTS"), "Ubuntu:24.04:LTS")
        index, info = cs.load_index("AlmaLinux:9", root=osv)
        self.assertEqual(info["archive"], "AlmaLinux")
        self.assertEqual([v["id"] for v in index["openssl-libs"]], ["ALSA-2024:0310"])  # ALBA ve AlmaLinux:8 yok
        packages = [{"type": "rpm", "name": "openssl-libs", "version": "1:3.0.7-24.el9", "source": "openssl",
                     "source_version": "1:3.0.7-24.el9", "arch": "aarch64", "db": "var/lib/rpm/rpmdb.sqlite", "line": 1}]
        findings = cs.match_packages(packages, index, "rpm")
        self.assertEqual([(f["reference"], f["fixed_version"]) for f in findings], [("ALSA-2024:0310", "1:3.0.7-25.el9_3")])

    def test_path_validation(self):
        with self.assertRaises(cs.ContainerScanError):
            cs.scan_image("/etc", osv_root=self.osv, allowed_roots=(self.base,))
        with self.assertRaises(cs.ContainerScanError):
            cs.scan_image(str(self.base / "yok"), osv_root=self.osv, allowed_roots=(self.base,))

    def test_sbom(self):
        sbom = cs.cyclonedx_sbom(self.scan())
        purls = [c["purl"] for c in sbom["components"]]
        self.assertIn("pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=arm64&distro=debian-12&upstream=openssl", purls)
        self.assertEqual((sbom["bomFormat"], sbom["specVersion"]), ("CycloneDX", "1.5"))

    def test_tracking_marks_upgraded_package_fixed(self):
        from storage import Store

        store = Store(self.base / "t.db")
        store.create_project_audit(self.scan())
        status = self.root / "var/lib/dpkg/status"
        status.write_bytes(DEB_STATUS.replace(b"3.0.11-1~deb12u1", b"3.0.12-1"))
        store.create_project_audit(self.scan())
        con = sqlite3.connect(self.base / "t.db")
        rows = con.execute("SELECT new_count, seen_count, fixed_count FROM project_audit_tracking ORDER BY rowid").fetchall()
        con.close()
        self.assertEqual(rows, [(3, 0, 0), (0, 1, 2)])  # openssl'in iki açığı düzeldi, zlib sürüyor
        listed = store.list_project_audits()[0]
        self.assertNotIn("components", listed)  # liste görünümünde bileşen listeleri yok


class ApiTests(unittest.TestCase):
    def test_roles(self):
        self.assertEqual(auth.required_level("POST", "/api/container-images"), "analyst")
        self.assertEqual(auth.required_level("GET", "/api/container-images/prj_0123456789ab/sbom"), "read")

    def test_api_scan_and_sbom(self):
        import project_analyzer
        import server
        from storage import Store
        from http.server import ThreadingHTTPServer

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            osv = _osv_root(base, "Debian:12", DEBIAN_RECORDS)
            root = base / "img"
            (root / "etc").mkdir(parents=True)
            (root / "etc/os-release").write_bytes(DEB_OS)
            (root / "var/lib/dpkg").mkdir(parents=True)
            (root / "var/lib/dpkg/status").write_bytes(DEB_STATUS)
            previous = server.STORE
            server.STORE = Store(base / "s.db")
            patches = [mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(base), "SNIPER_OSV_DB_ROOT": str(osv)}),
                       mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,))]
            for patch in patches:
                patch.start()
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            url = f"http://127.0.0.1:{httpd.server_address[1]}"

            def call(path, body=None):
                request = urllib.request.Request(url + path, method="POST" if body is not None else "GET",
                                                 data=json.dumps(body).encode() if body is not None else None,
                                                 headers={"Content-Type": "application/json"} if body is not None else {})
                try:
                    with urllib.request.urlopen(request, timeout=60) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as exc:
                    return exc.code, json.loads(exc.read() or b"{}")
            try:
                status, saved = call("/api/container-images", {"image_path": str(root)})
                self.assertEqual(status, 201, saved)
                self.assertEqual(saved["audit_kind"], "container")
                self.assertEqual(len(saved["findings"]), 3)
                status, sbom = call(f"/api/container-images/{saved['id']}/sbom")
                self.assertEqual((status, sbom["bomFormat"]), (200, "CycloneDX"))
                self.assertEqual(call("/api/container-images", {"image_path": str(root), "x": 1})[0], 400)
                self.assertEqual(call("/api/container-images", {"image_path": str(root), "ignore_unfixed": "evet"})[0], 400)
                self.assertEqual(call("/api/container-images", {"image_path": "/etc"})[0], 400)
                self.assertEqual(call("/api/container-images", {})[0], 400)  # 22. tur QA: eksik image_path 500 değil 400
                self.assertEqual(call("/api/container-images/prj_000000000000/sbom")[0], 404)
            finally:
                httpd.shutdown()
                httpd.server_close()
                for patch in patches:
                    patch.stop()
                server.STORE = previous


if __name__ == "__main__":
    unittest.main()


class LanguageMatcherWiringTests(unittest.TestCase):
    """18. tur birleştirme: konteynerdeki dil paketleri varsayılan olarak çevrimdışı OSV eşleyicisine gider."""

    def test_default_matcher_maps_offline_osv_results(self):
        import container_scan as cs
        import osv_offline

        self.assertIs(cs._LANGUAGE_MATCHER, cs.offline_osv_language_matcher)
        doc = {"document": {"results": [{"source": {"path": "x", "type": "inventory"}, "packages": [{
            "package": {"name": "django", "version": "2.0.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{"id": "GHSA-test", "summary": "örnek",
                                 "affected": [{"ranges": [{"type": "ECOSYSTEM",
                                                           "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}]}]}],
        }]}]}, "coverage": [], "skipped": {}, "warnings": [], "oldest_db_retrieved_utc": ""}
        with mock.patch.object(osv_offline, "match_components", return_value=doc) as matcher:
            out = cs.offline_osv_language_matcher([{"ecosystem": "PyPI", "name": "django", "version": "2.0.0",
                                                    "path": "/site-packages/Django-2.0.0.dist-info/METADATA"}])
        matcher.assert_called_once()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["category"], "container_lang")
        self.assertEqual(out[0]["file"], "/site-packages/Django-2.0.0.dist-info/METADATA")
        self.assertEqual(out[0]["reference"], "GHSA-test")
