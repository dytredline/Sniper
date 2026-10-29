import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import joern_active


FIXED_PHP_VERSION = "8.3.36"
FIXED_PHP_SOURCE_SHA256 = "dd54693aa334c5c4d72e9aee96b082c2473750a18a6c1d105789c93a3b1692fd"
VULNERABLE_PHP_SOURCE_SHA256 = "ff4630fbbbd94359134b7d3c223db59329905bdc4f5a9ef93d257b48e358619a"
VULNERABLE_PHP_BINARY = Path("/home/community-user/.local/share/sniper/tools/php/8.3.35/bin/php")
VULNERABLE_PHP_BINARY_SHA256 = "1530653183ec7c70b361ea09540f77ca6b0f086ce02f4ea1ec44f890ee26e070"
FIXED_PHP_EXECUTABLE = b"#!/bin/sh\nprintf '8.3.36'\n"


def _php_home(root: Path, *, version: str, source_sha256: str,
              binary: bytes = FIXED_PHP_EXECUTABLE) -> Path:
    (root / "bin").mkdir(parents=True)
    os.chmod(root, 0o755)
    os.chmod(root / "bin", 0o755)
    (root / "bin" / "php").write_bytes(binary)
    os.chmod(root / "bin" / "php", 0o555)
    provenance = {
        "tool": "php",
        "version": version,
        "source_sha256": source_sha256,
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
    }
    (root / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
    os.chmod(root / "provenance.json", 0o444)
    return root


def _installer_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "joern_install_php.py"
    spec = importlib.util.spec_from_file_location("joern_install_php_security_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PhpRuntimeSecurityContractTests(unittest.TestCase):
    def test_fixed_security_release_is_the_only_accepted_provenance(self):
        self.assertEqual(joern_active.PHP_VERSION, FIXED_PHP_VERSION)
        self.assertEqual(joern_active.PHP_MINIMUM_SAFE_VERSION, FIXED_PHP_VERSION)
        self.assertEqual(joern_active.PHP_SOURCE_SHA256, FIXED_PHP_SOURCE_SHA256)
        approved = hashlib.sha256(FIXED_PHP_EXECUTABLE).hexdigest()

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(joern_active, "PHP_APPROVED_BINARY_SHA256", {approved: "test approval"}):
            root = Path(tmp)
            old = _php_home(
                root / "8.3.35",
                version="8.3.35",
                source_sha256=VULNERABLE_PHP_SOURCE_SHA256,
            )
            fixed = _php_home(
                root / FIXED_PHP_VERSION,
                version=FIXED_PHP_VERSION,
                source_sha256=FIXED_PHP_SOURCE_SHA256,
            )
            with mock.patch.object(joern_active, "php_home", return_value=old):
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "resmî kaynak"):
                    joern_active.verified_php()
            with mock.patch.object(joern_active, "php_home", return_value=fixed):
                self.assertEqual(joern_active.verified_php(), FIXED_PHP_EXECUTABLE)

    @unittest.skipUnless(VULNERABLE_PHP_BINARY.is_file(), "kurulu PHP 8.3.35 runtime yok")
    def test_actual_php_8_3_35_binary_cannot_be_relabelled_as_fixed(self):
        binary = VULNERABLE_PHP_BINARY.read_bytes()
        self.assertEqual(hashlib.sha256(binary).hexdigest(), VULNERABLE_PHP_BINARY_SHA256)
        with tempfile.TemporaryDirectory() as tmp:
            home = _php_home(
                Path(tmp) / FIXED_PHP_VERSION,
                version=FIXED_PHP_VERSION,
                source_sha256=FIXED_PHP_SOURCE_SHA256,
                binary=binary,
            )
            with mock.patch.object(joern_active, "php_home", return_value=home):
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "mimari onayı"):
                    joern_active.verified_php()

    def test_self_reported_fixed_version_wrapper_is_not_an_approval(self):
        liar = b"#!/bin/sh\nprintf '8.3.36'\n"
        with tempfile.TemporaryDirectory() as tmp:
            home = _php_home(
                Path(tmp) / FIXED_PHP_VERSION,
                version=FIXED_PHP_VERSION,
                source_sha256=FIXED_PHP_SOURCE_SHA256,
                binary=liar,
            )
            with mock.patch.object(joern_active, "php_home", return_value=home):
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "mimari onayı"):
                    joern_active.verified_php()

    def test_arbitrary_correct_version_binary_digest_is_rejected(self):
        alternate = b"#!/bin/sh\n# alternate build\nprintf '8.3.36'\n"
        with tempfile.TemporaryDirectory() as tmp:
            home = _php_home(
                Path(tmp) / FIXED_PHP_VERSION,
                version=FIXED_PHP_VERSION,
                source_sha256=FIXED_PHP_SOURCE_SHA256,
                binary=alternate,
            )
            with mock.patch.object(joern_active, "php_home", return_value=home):
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "mimari onayı"):
                    joern_active.verified_php()

    def test_php_home_ignores_spoofed_home_environment(self):
        expected = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/share/sniper/tools/php" / FIXED_PHP_VERSION
        app = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as spoof:
            env = dict(os.environ, HOME=spoof, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(app))
            completed = subprocess.run(
                [sys.executable, "-c", "import joern_active; print(joern_active.php_home())"],
                cwd=app,
                env=env,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
        self.assertEqual(Path(completed.stdout.strip()), expected)

    def test_php_trust_chain_rejects_writable_directories_and_files(self):
        cases = (("parent", 0o775), ("home", 0o775), ("bin", 0o777),
                 ("provenance", 0o664), ("binary", 0o775))
        approved = hashlib.sha256(FIXED_PHP_EXECUTABLE).hexdigest()
        for part, mode in cases:
            with self.subTest(part=part), tempfile.TemporaryDirectory() as tmp:
                home = _php_home(
                    Path(tmp) / FIXED_PHP_VERSION,
                    version=FIXED_PHP_VERSION,
                    source_sha256=FIXED_PHP_SOURCE_SHA256,
                )
                path = {"parent": home.parent, "home": home, "bin": home / "bin",
                        "provenance": home / "provenance.json",
                        "binary": home / "bin" / "php"}[part]
                os.chmod(path, mode)
                with mock.patch.object(joern_active, "php_home", return_value=home), \
                        mock.patch.object(joern_active, "PHP_APPROVED_BINARY_SHA256",
                                          {approved: "test approval"}):
                    with self.assertRaises(joern_active.JoernUnavailable):
                        joern_active.verified_php()

    def test_installer_requires_an_explicit_offline_archive(self):
        installer = _installer_module()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "php-home"
            with mock.patch.object(joern_active, "php_home", return_value=target), \
                    mock.patch("urllib.request.urlopen", side_effect=AssertionError("network attempted")):
                with self.assertRaises(SystemExit) as caught:
                    installer.main([])
                self.assertFalse(target.exists())
        self.assertEqual(caught.exception.code, 2)

    def test_installer_rejects_an_existing_old_runtime(self):
        installer = _installer_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = _php_home(
                root / "8.3.35",
                version="8.3.35",
                source_sha256=VULNERABLE_PHP_SOURCE_SHA256,
            )
            archive = root / "unused.tar.xz"
            archive.write_bytes(b"unused")
            with mock.patch.object(joern_active, "php_home", return_value=target):
                with self.assertRaisesRegex(SystemExit, "Mevcut PHP kurulumu doğrulanamadı"):
                    installer.main(["--archive", str(archive)])

    def test_installer_rejects_an_unapproved_archive_before_creating_target(self):
        installer = _installer_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / FIXED_PHP_VERSION
            archive = root / "php-8.3.36.tar.xz"
            archive.write_bytes(b"not the approved archive")
            with mock.patch.object(joern_active, "php_home", return_value=target):
                with self.assertRaisesRegex(SystemExit, "SHA-256"):
                    installer.main(["--archive", str(archive)])
            self.assertFalse(target.exists())

    def test_installer_rejects_archive_symlinks(self):
        installer = _installer_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.tar.xz"
            target.write_bytes(b"archive")
            source = root / "source.tar.xz"
            source.symlink_to(target)
            with self.assertRaisesRegex(SystemExit, "düzenli bir yerel dosya"):
                installer._copy_verified_archive(source, root / "private.tar.xz")

    def test_installer_archive_path_swap_cannot_change_opened_bytes(self):
        installer = _installer_module()
        approved = b"approved archive bytes"
        replacement = b"replacement bytes"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.tar.xz"
            source.write_bytes(approved)
            swap = root / "swap.tar.xz"
            swap.write_bytes(replacement)
            private = root / "private.tar.xz"
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                kwargs = {} if dir_fd is None else {"dir_fd": dir_fd}
                fd = real_open(path, flags, mode, **kwargs)
                if Path(path) == source and not swapped:
                    swapped = True
                    os.replace(swap, source)
                return fd

            with mock.patch.object(joern_active, "PHP_SOURCE_SHA256", hashlib.sha256(approved).hexdigest()), \
                    mock.patch.object(installer.os, "open", side_effect=swapping_open):
                installer._copy_verified_archive(source, private)
            self.assertEqual(private.read_bytes(), approved)
            self.assertEqual(source.read_bytes(), replacement)

    def test_installer_normalizes_owned_install_directory_modes(self):
        installer = _installer_module()
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "php"
            parent.mkdir(mode=0o777)
            os.chmod(parent, 0o777)
            target = parent / FIXED_PHP_VERSION
            binary_dir = installer._prepare_install_directories(target)
            for path in (parent, target, binary_dir):
                self.assertEqual(path.stat().st_uid, os.getuid())
                self.assertEqual(path.stat().st_mode & 0o022, 0)

    def test_installer_records_digest_as_pending_not_approved(self):
        installer = _installer_module()
        binary = b"candidate binary"
        provenance = installer._pending_provenance(binary)
        self.assertEqual(provenance["binary_sha256"], hashlib.sha256(binary).hexdigest())
        self.assertEqual(provenance["activation"], "pending_architecture_binary_approval")
        self.assertNotIn(provenance["binary_sha256"], joern_active.PHP_APPROVED_BINARY_SHA256)

    def test_wrong_fixed_release_hash_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = _php_home(
                Path(tmp) / FIXED_PHP_VERSION,
                version=FIXED_PHP_VERSION,
                source_sha256="0" * 64,
            )
            with mock.patch.object(joern_active, "php_home", return_value=home):
                with self.assertRaises(joern_active.JoernUnavailable):
                    joern_active.verified_php()


if __name__ == "__main__":
    unittest.main()
