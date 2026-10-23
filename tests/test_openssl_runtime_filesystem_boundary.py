from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import openssl_loopback_active as active


class OpenSSLRuntimeFilesystemBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="openssl-runtime-boundary-")
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.data_dir.mkdir(mode=0o700)
        self.ca_path = self.data_dir / "openssl-trust-ca.pem"
        self.ca_path.write_bytes(b"synthetic-local-ca\n")
        self.ca_path.chmod(0o600)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "SNIPER_DATA_DIR": str(self.data_dir),
                "SNIPER_OPENSSL_CA_SHA256": hashlib.sha256(self.ca_path.read_bytes()).hexdigest(),
                "SNIPER_OPENSSL_BINARY_SHA256": hashlib.sha256(Path("/usr/bin/openssl").read_bytes()).hexdigest(),
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_private_runtime_directory_and_lock_are_accepted(self) -> None:
        data_dir, ca_bytes, binary = active._pinned_runtime()
        self.assertEqual(data_dir, self.data_dir)
        self.assertEqual(ca_bytes, b"synthetic-local-ca\n")
        self.assertEqual(binary, Path("/usr/bin/openssl"))

        fd = active._lock(data_dir)
        try:
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_group_or_world_writable_trust_directory_is_rejected(self) -> None:
        for mode in (0o720, 0o707):
            with self.subTest(mode=oct(mode)):
                self.data_dir.chmod(mode)
                with self.assertRaises(active.OpenSSLUnavailable):
                    active._pinned_runtime()
        self.data_dir.chmod(0o700)

    def test_preexisting_permissive_lock_file_is_rejected(self) -> None:
        lock_path = self.data_dir / "openssl-x509-loopback.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o666)

        with self.assertRaises(active.OpenSSLUnavailable):
            active._lock(self.data_dir)


if __name__ == "__main__":
    unittest.main()
