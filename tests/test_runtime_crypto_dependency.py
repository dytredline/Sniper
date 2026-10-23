"""Pinned runtime crypto and no-PYTHONPATH TOTP integration contract."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


APP = Path(__file__).resolve().parents[1]
RUNTIME_PINS = {
    "cryptography==41.0.7",
    "packaging==26.3",
    "PyYAML==6.0.3",
}


class RuntimeCryptoDependencyTests(unittest.TestCase):
    def test_runtime_lock_and_container_install_exact_runtime_dependencies(self) -> None:
        lock = (APP / "requirements-runtime.lock").read_text(encoding="utf-8").splitlines()
        observed = {line.strip() for line in lock if line.strip() and not line.startswith("#")}
        self.assertTrue(RUNTIME_PINS.issubset(observed), RUNTIME_PINS - observed)
        dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY requirements-runtime.lock", dockerfile)
        self.assertIn("pip install", dockerfile)
        self.assertIn("requirements-runtime.lock", dockerfile)
        self.assertIn("SNIPER_AUTH_FIELD_KEY_FILE=/var/lib/sniper-secrets/auth-field-keys.json", dockerfile)
        self.assertIn('"/var/lib/sniper-secrets"', dockerfile)

    def test_isolated_python_without_pythonpath_can_enroll_and_login_with_totp(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            script = """
import json, pathlib, sys, time
sys.path.insert(0, sys.argv[1])
import auth, cryptography
root=pathlib.Path(sys.argv[2])
m=auth.AuthManager(root/'data', key_file=root/'secrets'/'keyring.json')
u=m.create_admin_and_enable('container-admin', 'doğru-at-pil-zımba-42')
started=m.totp_begin(u['id']); step=int(time.time()//30)
m.totp_confirm(u['id'], auth.totp_code(started['secret'], step))
state, challenge=m.authenticate('container-admin', 'doğru-at-pil-zımba-42', 'container')
done=m.complete_totp(challenge['challenge'], auth.totp_code(started['secret'], step+1), None, 'container')
print(json.dumps({'state':state,'user':done['id'],'crypto':cryptography.__version__}, sort_keys=True))
"""
            env = {"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
            completed = subprocess.run(
                ["/usr/bin/python3", "-I", "-c", script, str(APP), str(root)],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["state"], "totp")
        self.assertEqual(result["crypto"], "41.0.7")
        self.assertTrue(result["user"].startswith("usr_"))
        self.assertNotIn("PYTHONPATH", env)

    def test_secret_patterns_are_excluded_from_source_contexts(self) -> None:
        dockerignore = (APP / ".dockerignore").read_text(encoding="utf-8")
        gitignore = (APP / ".gitignore").read_text(encoding="utf-8")
        for pattern in (".auth-field-keys", "release-signing.key", "*auth-field-keys*.json"):
            self.assertIn(pattern, dockerignore)
            self.assertIn(pattern, gitignore)


if __name__ == "__main__":
    unittest.main()
