"""Loopback dışı dinleme için iki aşamalı açık onay testleri."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

import server  # noqa: E402

BOTH = {"SNIPER_ALLOW_REMOTE": "1", "SNIPER_ALLOW_UNAUTHENTICATED_REMOTE": "1"}


class RemoteBindGuardTests(unittest.TestCase):
    def test_loopback_needs_no_consent(self) -> None:
        for host in ("127.0.0.1", "::1", "localhost", "LOCALHOST", "127.0.0.2"):
            with self.subTest(host=host):
                self.assertIsNone(server.remote_bind_refusal(host, {}))

    def test_remote_bind_requires_both_flags(self) -> None:
        for host in ("0.0.0.0", "::", "192.168.1.10", "sniper.example"):
            with self.subTest(host=host):
                self.assertIn("SNIPER_ALLOW_REMOTE=1", server.remote_bind_refusal(host, {}))
                refusal = server.remote_bind_refusal(host, {"SNIPER_ALLOW_REMOTE": "1"})
                self.assertIn("kimlik doğrulama yok", refusal)
                self.assertIn("SNIPER_ALLOW_UNAUTHENTICATED_REMOTE=1", refusal)
                self.assertIn("SSH", refusal)
                self.assertIsNone(server.remote_bind_refusal(host, BOTH))

    def test_only_exact_one_counts_as_consent(self) -> None:
        for value in ("true", "yes", "0", "", " 1"):
            with self.subTest(value=value):
                env = {"SNIPER_ALLOW_REMOTE": "1", "SNIPER_ALLOW_UNAUTHENTICATED_REMOTE": value}
                self.assertIsNotNone(server.remote_bind_refusal("0.0.0.0", env))

    def test_server_process_refuses_to_start_without_second_consent(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            env = dict(os.environ, SNIPER_HOST="0.0.0.0", SNIPER_PORT="1", SNIPER_ALLOW_REMOTE="1",
                       SNIPER_DATA_DIR=data_dir, SNIPER_DISABLE_STARTUP_AUTODISCOVER="1")
            env.pop("SNIPER_ALLOW_UNAUTHENTICATED_REMOTE", None)
            proc = subprocess.run([sys.executable, str(APP_ROOT / "server.py")], cwd=APP_ROOT, env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("SNIPER_ALLOW_UNAUTHENTICATED_REMOTE=1", proc.stderr)
            self.assertNotIn("Sniper hazır", proc.stdout)
            # Veritabanı bile oluşturulmadan düşer.
            self.assertFalse((Path(data_dir) / "sniper.db").exists())

    def test_compose_publishes_loopback_only_and_gives_consent(self) -> None:
        compose = (APP_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        sniper_block = compose.split("\n  prometheus:", 1)[0]
        self.assertIn('"127.0.0.1:8787:8787"', sniper_block)
        self.assertIn('SNIPER_ALLOW_UNAUTHENTICATED_REMOTE: "1"', sniper_block)
        dockerfile = (APP_ROOT / "Dockerfile").read_text(encoding="utf-8")
        # İmajın kendisi onayı vermez: `docker run -p 8787:8787` tüm arayüzlere açıp sessizce çalışmasın.
        self.assertNotIn("SNIPER_ALLOW_UNAUTHENTICATED_REMOTE", dockerfile)


if __name__ == "__main__":
    unittest.main()
