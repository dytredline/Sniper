from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import trivy_active
import trivy_config_active
import trivy_go_mod_active
import trivy_image_archive_active
import trivy_npm_active
import trivy_vuln_active


class TrivyRuntimeIntegrityTests(unittest.TestCase):
    def test_verified_descriptor_survives_binary_path_replacement(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            binary = root / "trivy"
            trusted = b"#!/bin/sh\n# trusted-trivy\n"
            binary.write_bytes(trusted)
            binary.chmod(0o755)
            replacement = root / "replacement"
            replacement.write_bytes(b"#!/bin/sh\n# replacement\n")
            replacement.chmod(0o755)
            environment = {
                "SNIPER_TRIVY_BINARY": str(binary),
                "SNIPER_TRIVY_BINARY_SHA256": hashlib.sha256(trusted).hexdigest(),
            }

            with mock.patch.dict(os.environ, environment, clear=True):
                _path, descriptor = trivy_config_active._open_trusted_binary()
                try:
                    replacement.replace(binary)
                    self.assertEqual(os.pread(descriptor, len(trusted), 0), trusted)
                finally:
                    os.close(descriptor)

    def test_every_active_route_rejects_mismatched_binary_before_execution(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            data = root / "data"
            data.mkdir()
            project = root / "project"
            project.mkdir()
            (project / "requirements.txt").write_text("demo==1\n")
            (project / "package-lock.json").write_text("{}\n")
            (project / "go.mod").write_text("module example.invalid/demo\n")
            (project / "image.tar").write_bytes(b"not-a-real-image")

            binary = root / "trivy"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            db_dir = root / "cache" / "db"
            db_dir.mkdir(parents=True)
            (db_dir / "metadata.json").write_text("{}")
            database = db_dir / "trivy.db"
            database.write_bytes(b"pinned test database")
            environment = {
                "SNIPER_DATA_DIR": str(data),
                "SNIPER_TRIVY_BINARY": str(binary),
                "SNIPER_TRIVY_BINARY_SHA256": "0" * 64,
                "SNIPER_TRIVY_VULN_CACHE_DIR": str(root / "cache"),
                "SNIPER_TRIVY_VULN_DB_SHA256": hashlib.sha256(database.read_bytes()).hexdigest(),
            }
            calls = (
                (trivy_active.run_local_trivy_secret, (str(project),)),
                (trivy_vuln_active.run_local_trivy_vulnerability, (str(project),)),
                (trivy_npm_active.run_local_trivy_npm_vulnerability, (str(project),)),
                (trivy_go_mod_active.run_local_trivy_go_mod_vulnerability, (str(project),)),
                (
                    trivy_image_archive_active.run_local_trivy_image_archive_vulnerability,
                    (str(project), "image.tar"),
                ),
            )
            with mock.patch.dict(os.environ, environment), \
                    mock.patch.object(
                        trivy_active,
                        "run_in_process_group",
                        side_effect=AssertionError("scanner started"),
                    ), \
                    mock.patch("subprocess.run", side_effect=AssertionError("scanner started")):
                for runner, arguments in calls:
                    with self.subTest(runner=runner.__name__):
                        with self.assertRaisesRegex(RuntimeError, "hash"):
                            runner(*arguments)


if __name__ == "__main__":
    unittest.main()
