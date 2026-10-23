import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

APP_ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_joern", APP_ROOT / "scripts" / "install_joern.py")
install_joern = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install_joern)


def _sha(path: Path, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, path.read_bytes()).hexdigest()


def _tar(path: Path, *, escape_link: bool = False) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, data, mode in (("jdk-21/bin/java", b"#!/bin/sh\n", 0o755), ("jdk-21/lib/x.so", b"so", 0o644)):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
        if escape_link:
            link = tarfile.TarInfo("jdk-21/lib/kacis")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(link)


def _zip(path: Path, *, escape_link: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("joern-cli/lib/a.jar", b"jar-a")
        info = zipfile.ZipInfo("joern-cli/joern")
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        bundle.writestr(info, b"#!/bin/sh\n")
        if escape_link:
            link = zipfile.ZipInfo("joern-cli/lib/kacis")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(link, "../../../../etc")


class InstallJoernTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for child in list(self.root.iterdir()):
            if child.is_dir() and not child.is_symlink():
                install_joern.remove_tree(child)
        self._tmp.cleanup()

    def _archives(self, **kwargs):
        jdk = self.root / "jdk.tar.gz"
        joern = self.root / "joern.zip"
        _tar(jdk, escape_link=kwargs.get("jdk_escape", False))
        _zip(joern, escape_link=kwargs.get("zip_escape", False))
        sha512 = self.root / "joern.zip.sha512"
        sha512.write_text(_sha(joern, "sha512") + "  joern.zip\n", encoding="ascii")
        patches = [
            mock.patch.object(install_joern, "JDK_ARCHIVES", {install_joern.machine(): ("jdk.tar.gz", _sha(jdk))}),
            mock.patch.object(install_joern, "JOERN_ARCHIVES", {install_joern.machine(): ("joern.zip", _sha(joern))}),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        return jdk, joern, sha512

    def test_install_verifies_digests_makes_read_only_and_writes_manifest(self):
        jdk, joern, sha512 = self._archives()
        tools = self.root / "tools"
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(install_joern.main(["--jdk-archive", str(jdk), "--joern-archive", str(joern),
                                                 "--joern-sha512", str(sha512), "--tools-dir", str(tools)]), 0)
        report = json.loads(out.getvalue())
        java = tools / "jdk" / install_joern.JDK_VERSION / "bin" / "java"
        self.assertEqual(report["java_sha256"], _sha(java))
        home = Path(report["joern_home"])
        manifest_raw = (home / install_joern.MANIFEST_NAME).read_bytes()
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(manifest_raw).hexdigest())
        manifest = json.loads(manifest_raw)
        self.assertEqual(manifest["files"]["lib/a.jar"], hashlib.sha256(b"jar-a").hexdigest())
        self.assertEqual(stat.S_IMODE((home / "lib" / "a.jar").stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(java.stat().st_mode), 0o555)
        # Yeniden kurulum salt okunur eski kurulumu değiştirebilmeli.
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            install_joern.main(["--jdk-archive", str(jdk), "--joern-archive", str(joern),
                                "--joern-sha512", str(sha512), "--tools-dir", str(tools)])

    def test_digest_mismatches_are_rejected(self):
        jdk, joern, sha512 = self._archives()
        sha512.write_text("0" * 128 + "\n", encoding="ascii")
        with self.assertRaisesRegex(SystemExit, "sha512"):
            install_joern.install_joern(joern, sha512, self.root / "j")
        with open(jdk, "ab") as handle:
            handle.write(b"x")
        with self.assertRaisesRegex(SystemExit, "SHA-256"):
            install_joern.install_jdk(jdk, self.root / "k")

    def test_escaping_links_are_rejected(self):
        jdk, joern, sha512 = self._archives(jdk_escape=True, zip_escape=True)
        with self.assertRaises((tarfile.FilterError, tarfile.TarError)):
            install_joern.install_jdk(jdk, self.root / "k")
        with self.assertRaisesRegex(SystemExit, "kurulum dışını"):
            install_joern.install_joern(joern, sha512, self.root / "j")


if __name__ == "__main__":
    unittest.main()
