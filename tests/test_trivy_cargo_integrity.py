from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import trivy_cargo_active


class TrivyCargoIntegrityTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, dict[str, str]]:
        project = root / "project"
        project.mkdir()
        (project / "Cargo.lock").write_text(
            'version = 3\n\n[[package]]\nname = "demo"\nversion = "1.0.0"\n'
        )
        data = root / "data"
        data.mkdir()
        binary = root / "trivy"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        db_dir = root / "cache" / "db"
        db_dir.mkdir(parents=True)
        (db_dir / "metadata.json").write_text("{}")
        database = db_dir / "trivy.db"
        database.write_bytes(b"cargo test database")
        return project, {
            "SNIPER_DATA_DIR": str(data),
            "SNIPER_TRIVY_BINARY": str(binary),
            "SNIPER_TRIVY_VULN_CACHE_DIR": str(root / "cache"),
            "SNIPER_TRIVY_VULN_DB_SHA256": hashlib.sha256(database.read_bytes()).hexdigest(),
        }

    def test_route_requires_binary_digest_before_subprocess(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            project, environment = self._fixture(Path(temp))
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(
                        trivy_cargo_active.subprocess,
                        "run",
                        side_effect=AssertionError("scanner started"),
                    ) as scanner:
                with self.assertRaisesRegex(RuntimeError, "özeti"):
                    trivy_cargo_active.run_local_trivy_cargo_lock_vulnerability(str(project))
            scanner.assert_not_called()

    def test_binary_digest_control_and_mismatch_edge(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            binary = root / "trivy"
            binary.write_bytes(b"trusted-cargo-trivy")
            binary.chmod(0o755)
            environment = {
                "SNIPER_TRIVY_BINARY": str(binary),
                "SNIPER_TRIVY_BINARY_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                descriptor = trivy_cargo_active._open_trivy_binary()
                os.close(descriptor)
                os.environ["SNIPER_TRIVY_BINARY_SHA256"] = "0" * 64
                with self.assertRaisesRegex(RuntimeError, "eşleşmiyor"):
                    trivy_cargo_active._open_trivy_binary()


if __name__ == "__main__":
    unittest.main()
