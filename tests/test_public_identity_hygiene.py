from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import k6_loopback_active


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-community-source.py"
VALIDATOR = ROOT / ".github" / "scripts" / "validate-community-release.py"
PORTABLE_CONTAINER_LABEL = "org.sniper.community.k6.local"
PORTABLE_TEMPLATE_AUTHOR = "sniper-community"
ACTIVE_TARGET_TESTS = (
    "tests/test_wave20_sqlite_wal_concurrency_stress.py",
    "tests/test_zap_actor_job_lease.py",
    "tests/test_zap_actor_job_lifecycle_audit.py",
    "tests/test_zap_storage_and_redirect_guard.py",
    "tests/test_zap_target_active_api.py",
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _http_hosts(text: str) -> set[str]:
    hosts: set[str] = set()
    for value in re.findall(r"https?://[^\s\"'<>]+", text):
        authority = value.rstrip("),];").split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
        if authority.startswith("["):
            end = authority.find("]")
            hostname = authority[1:end] if end > 1 else ""
        else:
            hostname = authority.split(":", 1)[0]
        if hostname:
            hosts.add(hostname.casefold())
    return hosts


class PublicIdentityHygieneTests(unittest.TestCase):
    def test_runtime_ownership_label_is_vendor_neutral(self) -> None:
        argv = k6_loopback_active._docker_argv(Path("/tmp/sniper-community-test"), "run-name", "proof")
        self.assertEqual(k6_loopback_active.CONTAINER_OWNERSHIP_LABEL, PORTABLE_CONTAINER_LABEL)
        self.assertEqual(argv[argv.index("--label") + 1], PORTABLE_CONTAINER_LABEL + "=proof")

    def test_public_metadata_and_synthetic_targets_are_portable(self) -> None:
        builder = BUILDER.read_text(encoding="utf-8")
        self.assertNotIn("MAINTAINER_HOME", builder)

        template = (ROOT / "templates/nuclei/local-powered-by.yaml").read_text(encoding="utf-8")
        self.assertRegex(template, rf"(?m)^\s*author:\s*{re.escape(PORTABLE_TEMPLATE_AUTHOR)}\s*$")

        for relative in ACTIVE_TARGET_TESTS:
            with self.subTest(relative=relative):
                hosts = _http_hosts((ROOT / relative).read_text(encoding="utf-8"))
                self.assertTrue(hosts, relative)
                self.assertTrue(all(
                    host in {"example.test", "example.local", "localhost", "127.0.0.1", "::1"}
                    or host.endswith(".example.test")
                    or host.endswith(".example.local")
                    or host.endswith(".example")
                    or host.endswith(".invalid")
                    for host in hosts
                ), hosts)

        for relative in ("static/trufflehog_filesystem.js", "static/trufflehog_git_history.js"):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotRegex(source, r"segments\s*\[\s*2\s*\]\s*===\s*['\"]")

    def test_release_validator_rejects_nonportable_identity_surfaces(self) -> None:
        builder = _load(BUILDER, "public_identity_builder_test")
        validator = _load(VALIDATOR, "public_identity_validator_test")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "community"
            builder.build(ROOT, output)
            self.assertEqual(validator.validate(output, scan_release_tree=True), [])

            cases = (
                (
                    "k6_loopback_active.py",
                    lambda text: text.replace(PORTABLE_CONTAINER_LABEL, "org.private-vendor.sniper.k6.local", 1),
                    "nonportable container ownership namespace",
                ),
                (
                    "templates/nuclei/local-powered-by.yaml",
                    lambda text: re.sub(r"(?m)^\s*author:.*$", "  author: Personal Maintainer", text, count=1),
                    "nonportable template author",
                ),
                (
                    "static/trufflehog_filesystem.js",
                    lambda text: text + "\nconst leakedHomeRule = segments[2] === 'operator';\n",
                    "hard-coded home account",
                ),
                (
                    "tests/test_zap_target_active_api.py",
                    lambda text: text + '\nLEAKED_TARGET = "https://company.internal/"\n',
                    "non-reserved active target fixture",
                ),
            )
            for relative, mutate, expected in cases:
                path = output / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(mutate(original), encoding="utf-8")
                try:
                    failures = validator.validate(output, scan_release_tree=True)
                finally:
                    path.write_text(original, encoding="utf-8")
                with self.subTest(relative=relative):
                    self.assertTrue(any(expected in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
