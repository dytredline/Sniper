from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-community-source.py"
VALIDATOR = ROOT / ".github" / "scripts" / "validate-community-release.py"

CLOSED_PATHS = (
    "distribution_" + "entitlement.py",
    "distribution_profile.py",
    "native_" + "distribution_build.py",
    "native_" + "distribution_readiness.py",
    "native_launcher.py",
    "native_platform_verification.py",
    "release_info.py",
    "release_ops.py",
    "scripts/distribution_" + "entitlement.py",
    "scripts/" + "install.py",
    "scripts/package_" + "release.py",
    "scripts/" + "rollback.py",
    "scripts/" + "update.py",
    "docs/kurulum.md",
    "tests/test_distribution_" + "entitlement.py",
    "tests/test_distribution_package_boundaries.py",
    "tests/test_entitlement_install_enforcement.py",
    "tests/test_native_" + "distribution_build.py",
    "tests/test_native_" + "distribution_readiness.py",
    "tests/test_native_platform_verification.py",
    "tests/test_protected_distribution_profile.py",
    "tests/test_release_lifecycle.py",
    "tests/test_runtime_entitlement_enforcement.py",
    "tests/test_runtime_entitlement_ui.mjs",
)

CLOSED_CONTRACT = re.compile(
    "protected-" + r"v1|distribution_" + r"entitlement|SNIPER_" + r"ENTITLEMENT|customer-" + r"entitlement|"
    r"\.sniper-" + r"entitlement|sniper-" + r"protected|native_" + r"distribution_(?:build|readiness)|"
    r"(?:from|import)\s+(?:release_" + r"info|release_" + r"ops)\b|"
    r"scripts/(?:package_" + r"release|install|update|rollback)\.py",
    re.IGNORECASE,
)

PRIVATE_PUBLICATION_WORDING = re.compile(
    r"\b(?:" + "Sp" + "ark|TRUE" + r"\s+" + "LIVE" + r")\b",
    re.IGNORECASE,
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCommunitySourceSeparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.output = cls.root / "community-source"
        cls.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        built = subprocess.run(
            [sys.executable, str(BUILDER), "--source", str(ROOT), "--output", str(cls.output)],
            cwd=ROOT,
            env=cls.env,
            text=True,
            capture_output=True,
            check=False,
        )
        if built.returncode != 0:
            raise AssertionError(built.stdout + built.stderr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_closed_distribution_implementation_and_contracts_are_absent(self) -> None:
        for relative in CLOSED_PATHS:
            self.assertFalse((self.output / relative).exists(), relative)

        violations: list[str] = []
        for path in sorted(item for item in self.output.rglob("*") if item.is_file()):
            text = path.read_bytes().decode("utf-8", errors="ignore")
            if CLOSED_CONTRACT.search(text):
                violations.append(path.relative_to(self.output).as_posix())
        self.assertEqual(violations, [])
        self.assertTrue((self.output / "tests/test_mcp_community_mode.py").is_file())
        self.assertTrue((self.output / "tests/test_runtime_source_portability.py").is_file())

    def test_private_product_wording_is_absent_but_community_installers_remain(self) -> None:
        violations: list[str] = []
        for path in sorted(item for item in self.output.rglob("*") if item.is_file()):
            text = path.read_bytes().decode("utf-8", errors="ignore")
            if PRIVATE_PUBLICATION_WORDING.search(text):
                violations.append(path.relative_to(self.output).as_posix())
        self.assertEqual(violations, [])
        self.assertTrue((self.output / "scripts/install_joern.py").is_file())
        self.assertTrue((self.output / "tests/test_install_joern.py").is_file())

    def test_executable_plugin_roots_are_not_group_or_world_writable(self) -> None:
        for relative in ("plugins", "plugins/base", "plugins/user"):
            mode = (self.output / relative).stat().st_mode
            self.assertEqual(mode & 0o077, 0, relative)
        for path in (self.output / "plugins").glob("*/*.py"):
            self.assertEqual(path.stat().st_mode & 0o077, 0, path.name)

    def test_community_server_and_mcp_import_without_closed_modules(self) -> None:
        smoke = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                (
                    "import importlib.util, mcp_triage_server, server; "
                    "assert callable(server.main); "
                    "assert importlib.util.find_spec('community_release_info') is not None; "
                    "assert importlib.util.find_spec('distribution_' + 'entitlement') is None; "
                    "assert importlib.util.find_spec('release_info') is None"
                ),
            ],
            cwd=self.output,
            env={
                **self.env,
                "SNIPER_DATA_DIR": str(self.root / "data"),
                "SNIPER_DISABLE_STARTUP_AUTODISCOVER": "1",
            },
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(smoke.returncode, 0, smoke.stdout + smoke.stderr)

        mcp_help = subprocess.run(
            [sys.executable, "-B", "scripts/sniper-mcp", "--help"],
            cwd=self.output,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(mcp_help.returncode, 0, mcp_help.stdout + mcp_help.stderr)
        self.assertIn("--mode", mcp_help.stdout)

    def test_community_version_and_database_backup_compatibility(self) -> None:
        database_root = self.root / "backup-control"
        code = """
import pathlib, sqlite3, stat
import community_release_info as info

root = pathlib.Path(__import__('sys').argv[1])
root.mkdir()
source = root / 'source.db'
connection = sqlite3.connect(source)
connection.execute('CREATE TABLE proof (value TEXT NOT NULL)')
connection.execute('INSERT INTO proof VALUES (?)', ('community',))
connection.commit()
connection.close()

target = root / 'backup.db'
result = info.backup_database(source, target)
assert result['integrity'] == 'ok'
assert len(result['sha256']) == 64
assert stat.S_IMODE(target.stat().st_mode) == 0o600
check = sqlite3.connect(f'file:{target}?mode=ro', uri=True)
try:
    assert check.execute('SELECT value FROM proof').fetchone() == ('community',)
finally:
    check.close()

try:
    info.backup_database(source, target)
except info.CommunityReleaseError:
    pass
else:
    raise AssertionError('existing backup destination must fail closed')

payload = info.system_version_payload(pathlib.Path.cwd(), root)
assert payload['format'] == 'sniper-community-version/1'
assert payload['product_version'] == '1.0.0'
assert payload['distribution'] == 'community-source'
assert payload['packaged'] is False
assert 'entitlement' not in payload
"""
        run = subprocess.run(
            [sys.executable, "-B", "-c", code, str(database_root)],
            cwd=self.output,
            env={**self.env, "PYTHONPATH": str(self.output)},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_transform_fails_closed_when_a_server_anchor_drifts(self) -> None:
        builder = _load(BUILDER, "community_source_builder_test")
        with self.assertRaisesRegex(ValueError, "server.py.*anchor"):
            builder._apply_artifact_transform(Path("server.py"), "anchorless source\n")

    def test_private_wording_transforms_fail_closed_when_anchors_drift(self) -> None:
        builder = _load(BUILDER, "community_wording_builder_test")
        for relative in (
            "mcp_triage_server.py",
            "static/index.html",
            "static/i18n-en.tsv",
        ):
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(ValueError, re.escape(relative) + ".*anchor"):
                    builder._apply_artifact_transform(Path(relative), "anchorless source\n")

    def test_builder_rejects_broken_output_symlink_and_symlinked_parent(self) -> None:
        builder = _load(BUILDER, "community_output_path_builder_test")
        source = self.root / "minimal-output-source"
        source.mkdir()
        (source / "COMMUNITY_VERSION").write_text("1.0.0\n", encoding="utf-8")

        redirected = self.root / "redirected-output"
        requested = self.root / "requested-output"
        requested.symlink_to(redirected, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "output.*symbolic link"):
            builder.build(source, requested)
        self.assertFalse(redirected.exists())

        real_parent = self.root / "real-output-parent"
        real_parent.mkdir()
        parent_alias = self.root / "output-parent-alias"
        parent_alias.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "output parent.*symbolic link"):
            builder.build(source, parent_alias / "community")
        self.assertFalse((real_parent / "community").exists())

    def test_builder_rejects_source_file_swapped_to_symlink_before_open(self) -> None:
        builder = _load(BUILDER, "community_source_race_builder_test")
        source = self.root / "minimal-race-source"
        source.mkdir()
        (source / "COMMUNITY_VERSION").write_text("1.0.0\n", encoding="utf-8")
        raced = source / "zz-race.txt"
        raced.write_text("inside\n", encoding="utf-8")
        outside = self.root / "outside-race.txt"
        outside.write_text("OUTSIDE_RACE_PAYLOAD\n", encoding="utf-8")
        output = self.root / "race-output"

        real_open = builder.os.open
        swapped = False

        def swapping_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "zz-race.txt" and kwargs.get("dir_fd") is not None and not swapped:
                raced.unlink()
                raced.symlink_to(outside)
                swapped = True
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(builder.os, "open", side_effect=swapping_open):
            with self.assertRaises((OSError, ValueError)):
                builder.build(source, output)
        self.assertTrue(swapped)
        self.assertFalse(output.exists())

    def test_builder_does_not_read_excluded_runtime_payloads(self) -> None:
        builder = _load(BUILDER, "community_excluded_payload_builder_test")
        source = self.root / "minimal-excluded-source"
        (source / "data").mkdir(parents=True)
        (source / "COMMUNITY_VERSION").write_text("1.0.0\n", encoding="utf-8")
        excluded = source / "data" / "sniper.db"
        excluded.write_bytes(b"runtime-state-must-not-be-read")
        output = self.root / "excluded-output"

        real_open = builder.os.open
        opened_excluded = False

        def observing_open(path, flags, *args, **kwargs):
            nonlocal opened_excluded
            if path == "sniper.db" and kwargs.get("dir_fd") is not None:
                opened_excluded = True
                raise AssertionError("excluded runtime payload was opened")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(builder.os, "open", side_effect=observing_open):
            builder.build(source, output)
        self.assertFalse(opened_excluded)
        self.assertFalse((output / "data/sniper.db").exists())

    def test_builder_and_validator_fail_closed_on_oversized_regular_file(self) -> None:
        builder = _load(BUILDER, "community_size_bound_builder_test")
        validator = _load(VALIDATOR, "community_size_bound_validator_test")
        source = self.root / "minimal-size-source"
        source.mkdir()
        (source / "COMMUNITY_VERSION").write_text("1.0.0\n", encoding="utf-8")
        oversized_source = source / "oversized.bin"
        with oversized_source.open("wb") as stream:
            stream.truncate(builder.MAX_REGULAR_FILE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "exceeds.*publication limit"):
            builder.build(source, self.root / "oversized-output")

        oversized_artifact = self.output / "oversized.bin"
        with oversized_artifact.open("wb") as stream:
            stream.truncate(validator.MAX_REGULAR_FILE_BYTES + 1)
        try:
            failures = validator.validate(self.output, scan_release_tree=True)
        finally:
            oversized_artifact.unlink()
        self.assertTrue(
            any("regular file exceeds" in failure and "oversized.bin" in failure for failure in failures),
            failures,
        )

    def test_validator_rejects_reintroduced_closed_filename(self) -> None:
        validator = _load(VALIDATOR, "community_release_validator_test")
        forbidden = self.output / ("distribution_" + "entitlement.py")
        forbidden.write_text("# accidentally restored\n", encoding="utf-8")
        try:
            failures = validator.validate(self.output, scan_release_tree=True)
        finally:
            forbidden.unlink()
        self.assertTrue(
            any("excluded closed implementation path" in failure for failure in failures),
            failures,
        )

    def test_validator_rejects_private_product_wording(self) -> None:
        validator = _load(VALIDATOR, "community_release_validator_wording_test")
        path = self.output / "README.md"
        original = path.read_text(encoding="utf-8")
        private_label = "Sp" + "ark"
        path.write_text(original + f"\nPrivate product: {private_label}\n", encoding="utf-8")
        try:
            failures = validator.validate(self.output, scan_release_tree=True)
        finally:
            path.write_text(original, encoding="utf-8")
        self.assertTrue(
            any("private publication wording" in failure for failure in failures),
            failures,
        )

    def test_validator_rejects_special_files_and_manifest_sees_them(self) -> None:
        validator = _load(VALIDATOR, "community_release_validator_special_file_test")
        special = self.output / "unlisted-special.pipe"
        os.mkfifo(special)
        try:
            failures = validator.validate(self.output, scan_release_tree=True)
        finally:
            special.unlink()
        self.assertTrue(
            any("non-regular filesystem entry" in failure for failure in failures),
            failures,
        )
        self.assertTrue(
            any("manifest: unlisted filesystem entry: unlisted-special.pipe" in failure for failure in failures),
            failures,
        )

    def test_validator_rejects_same_inode_change_after_read(self) -> None:
        validator = _load(VALIDATOR, "community_release_validator_read_race_test")
        target = self.output / "README.md"
        original = target.read_bytes()
        real_stat = validator.os.stat
        target_stat_calls = 0
        race_fired = False

        def racing_stat(path, *args, **kwargs):
            nonlocal target_stat_calls, race_fired
            if path == "README.md" and kwargs.get("dir_fd") is not None:
                target_stat_calls += 1
                if target_stat_calls == 2:
                    with target.open("r+b") as stream:
                        stream.seek(-1, os.SEEK_END)
                        stream.write(b"X")
                        stream.flush()
                        os.fsync(stream.fileno())
                    race_fired = True
            return real_stat(path, *args, **kwargs)

        try:
            with mock.patch.object(validator.os, "stat", side_effect=racing_stat):
                failures = validator.validate(self.output, scan_release_tree=True)
        finally:
            target.write_bytes(original)
        self.assertTrue(race_fired)
        self.assertTrue(
            any("file changed during safe read: README.md" in failure for failure in failures),
            failures,
        )


if __name__ == "__main__":
    unittest.main()
