#!/usr/bin/env python3
"""Assemble a deterministic, offline Sniper Community source tree."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
from typing import NamedTuple


DEFAULT_SOURCE = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "COMMUNITY-SOURCE-MANIFEST.sha256"
LIMITATIONS_NAME = "COMMUNITY-RELEASE-LIMITATIONS.md"
VERSION_FILE = "COMMUNITY_VERSION"
MAX_REGULAR_FILE_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024

EXCLUDED_DIRS = frozenset({
    ".git", ".codebase-memory", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".venv",
    "__pycache__", "node_modules", "runtimes", "data", "backup", "backups", "evidence",
    "dev-" + "evidence", "frozen-" + "evidence",
})
EXCLUDED_SUFFIXES = (
    ".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", "-wal", "-shm", "-journal",
)
EXCLUDED_NAMES = frozenset({"RELEASE.json", ".DS_Store", ".coverage"})
EXCLUDED_NAMES_CASEFOLD = frozenset(name.casefold() for name in EXCLUDED_NAMES)

# These files are maintainer evaluation fixtures, not the runtime measurement
# modules used by the product. Keep this list narrow and review additions.
INTERNAL_EVALUATION_PATHS = frozenset({
    "docs/sniper-2-evaluation.md",
    "docs/olcum",
    "scripts/ai_triage_eval.py",
    "scripts/clike_benchmark_java.py",
    "scripts/clike_taint_eval.py",
    "scripts/fp_corpus_eval.py",
    "scripts/joern_benchmark.py",
    "scripts/joern_javaseccode_eval.py",
    "scripts/joern_multilang_eval.py",
    "scripts/owasp_benchmark_python.py",
    "scripts/taint_benchmark.py",
})

# Public source is assembled from a broader internal product tree.  Keep this
# deny-list exact: a newly coupled private file must be reviewed explicitly,
# never swept out by a broad name pattern.
_DELIVERY_MODULE = "distribution_" + "entitlement.py"
_DELIVERY_PROFILE = "distribution_" + "profile.py"
_NATIVE_BUILD = "native_" + "distribution_build.py"
_NATIVE_READINESS = "native_" + "distribution_readiness.py"
_RELEASE_INFO = "release_" + "info.py"
_RELEASE_OPS = "release_" + "ops.py"
_DELIVERY_SCRIPT = "scripts/distribution_" + "entitlement.py"
_PACKAGE_SCRIPT = "scripts/package_" + "release.py"
_INSTALL_SCRIPT = "scripts/" + "install.py"
_UPDATE_SCRIPT = "scripts/" + "update.py"
_ROLLBACK_SCRIPT = "scripts/" + "rollback.py"

CLOSED_DELIVERY_PATHS = frozenset({
    _DELIVERY_MODULE,
    _DELIVERY_PROFILE,
    _NATIVE_BUILD,
    _NATIVE_READINESS,
    "native_launcher.py",
    "native_platform_verification.py",
    _RELEASE_INFO,
    _RELEASE_OPS,
    _DELIVERY_SCRIPT,
    _PACKAGE_SCRIPT,
    _INSTALL_SCRIPT,
    _UPDATE_SCRIPT,
    _ROLLBACK_SCRIPT,
    "docs/kurulum.md",
    "tests/test_distribution_" + "entitlement.py",
    "tests/test_distribution_package_boundaries.py",
    "tests/test_" + "entitlement_install_enforcement.py",
    "tests/test_native_" + "distribution_build.py",
    "tests/test_native_" + "distribution_readiness.py",
    "tests/test_native_platform_verification.py",
    "tests/test_protected_distribution_profile.py",
    "tests/test_release_lifecycle.py",
    "tests/test_runtime_" + "entitlement_enforcement.py",
    "tests/test_runtime_" + "entitlement_ui.mjs",
})

PRIVATE_HOME = re.compile(r"/home/(?!community-user(?=/|[^A-Za-z0-9_.-]|$))[A-Za-z0-9_.-]+")
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.S,
)
TOKEN_PATTERNS = (
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
)
INTERNAL_PATTERNS = (
    re.compile("sniper-" + "gptoss-" + r"migration|development-loop-v\d+", re.I),
    re.compile("frozen-" + "evidence|dev-" + "evidence", re.I),
    re.compile(
        r"\b(?:" + "|".join(("Ar" + "gon", "Vivu" + "sunda", "Guar" + "dian", "Q" + "wen")) + r")\b",
        re.I,
    ),
)

LIMITATIONS = """# Community source distribution boundaries

This assembled tree is the Sniper Community source distribution.

Commercial delivery, customer-bound licensing, private installer, and native
binary-delivery implementation are intentionally absent. The web runtime uses
the small Community-only version and backup module included in this tree.

Maintainer-only evaluation fixtures, generated caches, database state,
evidence bundles, frozen artifacts, and machine/session-specific documentation
or tests are not copied into this source distribution.

Required runtime files are retained when they contain a machine-specific
literal, but the literal is normalized to a neutral Community placeholder in
the assembled tree. This prevents publishing a maintainer path; it does not
install optional engines or prove that every legacy default is portable.
Operators must provide their own configured data and tool locations. Optional
engine availability remains host-specific and is not implied by this archive.
"""


def _is_under(relative: str, parent: str) -> bool:
    return relative == parent or relative.startswith(parent + "/")


def _excluded(relative: Path) -> bool:
    relative_text = relative.as_posix()
    if relative_text in CLOSED_DELIVERY_PATHS:
        return True
    if any(part in EXCLUDED_DIRS for part in relative.parts[:-1]):
        return True
    if relative.name.endswith(EXCLUDED_SUFFIXES):
        return True
    if relative.name.casefold() in EXCLUDED_NAMES_CASEFOLD or relative.name.startswith(".coverage."):
        return True
    return any(_is_under(relative_text, item) for item in INTERNAL_EVALUATION_PATHS)


def _has_secret(text: str) -> bool:
    return bool(PRIVATE_KEY_BLOCK.search(text) or any(pattern.search(text) for pattern in TOKEN_PATTERNS))


def _has_machine_metadata(text: str) -> bool:
    return bool(PRIVATE_HOME.search(text) or any(pattern.search(text) for pattern in INTERNAL_PATTERNS))


def _must_exclude_doc_or_test(text: str) -> bool:
    return any(pattern.search(text) for pattern in INTERNAL_PATTERNS)


def _sanitize(text: str) -> str:
    text = PRIVATE_HOME.sub("/home/community-user", text)
    for pattern in INTERNAL_PATTERNS:
        text = pattern.sub("community-build", text)
    return text


class SourceFile(NamedTuple):
    relative: Path
    payload: bytes
    mode: int


def _stat_identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _stat_content_state(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _read_bounded_fd(file_fd: int, relative: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(file_fd, READ_CHUNK_BYTES)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_REGULAR_FILE_BYTES:
            raise ValueError(
                f"source file exceeds {MAX_REGULAR_FILE_BYTES}-byte publication limit: {relative}"
            )
        chunks.append(chunk)


def _source_files(source: Path) -> tuple[list[SourceFile], int]:
    """Snapshot regular source files through anchored descriptors without following links."""
    try:
        source_lstat = source.lstat()
    except OSError as exc:
        raise ValueError(f"source cannot be inspected safely: {source}: {exc}") from exc
    if not stat.S_ISDIR(source_lstat.st_mode):
        raise ValueError(f"source is not a directory: {source}")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    file_flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        source_fd = os.open(source, directory_flags)
    except OSError as exc:
        raise ValueError(f"source cannot be opened without following links: {source}: {exc}") from exc
    try:
        if _stat_identity(os.fstat(source_fd)) != _stat_identity(source_lstat):
            raise ValueError("source root changed while the build started")
        files: list[SourceFile] = []
        skipped = 0
        snapshot_bytes = 0

        def walk(directory_fd: int, parent: Path) -> None:
            nonlocal skipped, snapshot_bytes
            try:
                with os.scandir(directory_fd) as iterator:
                    names = sorted(item.name for item in iterator)
            except OSError as exc:
                location = parent.as_posix() if parent.parts else "."
                raise ValueError(f"source directory cannot be enumerated safely: {location}: {exc}") from exc
            for name in names:
                relative = parent / name
                relative_text = relative.as_posix()
                if "\n" in name or "\r" in name:
                    raise ValueError(f"source path contains a line break: {relative_text!r}")
                try:
                    observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    raise ValueError(f"source entry changed before stat: {relative_text}: {exc}") from exc
                if stat.S_ISLNK(observed.st_mode):
                    raise ValueError(f"symbolic links are not accepted: {relative_text}")
                if stat.S_ISDIR(observed.st_mode):
                    if any(part in EXCLUDED_DIRS for part in relative.parts):
                        skipped += 1
                        continue
                    try:
                        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                    except OSError as exc:
                        raise ValueError(
                            f"source directory cannot be opened safely: {relative_text}: {exc}"
                        ) from exc
                    try:
                        if _stat_identity(os.fstat(child_fd)) != _stat_identity(observed):
                            raise ValueError(f"source directory changed during traversal: {relative_text}")
                        walk(child_fd, relative)
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(observed.st_mode):
                    raise ValueError(f"source entry is not a regular file or directory: {relative_text}")
                if _excluded(relative):
                    skipped += 1
                    continue
                if observed.st_size > MAX_REGULAR_FILE_BYTES:
                    raise ValueError(
                        f"source file exceeds {MAX_REGULAR_FILE_BYTES}-byte publication limit: {relative_text}"
                    )
                if snapshot_bytes + observed.st_size > MAX_SNAPSHOT_BYTES:
                    raise ValueError(
                        f"included source exceeds {MAX_SNAPSHOT_BYTES}-byte publication snapshot limit"
                    )

                try:
                    file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise ValueError(f"source file cannot be opened safely: {relative_text}: {exc}") from exc
                try:
                    opened = os.fstat(file_fd)
                    if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(observed):
                        raise ValueError(f"source file changed before safe read: {relative_text}")
                    payload = _read_bounded_fd(file_fd, relative_text)
                    finished = os.fstat(file_fd)
                    try:
                        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        raise ValueError(f"source file changed after safe read: {relative_text}: {exc}") from exc
                    if _stat_identity(current) != _stat_identity(opened) \
                            or _stat_content_state(finished) != _stat_content_state(opened) \
                            or _stat_content_state(current) != _stat_content_state(finished):
                        raise ValueError(f"source file changed during safe read: {relative_text}")
                    snapshot_bytes += len(payload)
                    if snapshot_bytes > MAX_SNAPSHOT_BYTES:
                        raise ValueError(
                            f"included source exceeds {MAX_SNAPSHOT_BYTES}-byte publication snapshot limit"
                        )
                    files.append(SourceFile(relative, payload, opened.st_mode))
                finally:
                    os.close(file_fd)

        walk(source_fd, Path())
        return sorted(files, key=lambda item: item.relative.as_posix()), skipped
    finally:
        os.close(source_fd)


def _community_version(files: list[SourceFile]) -> str:
    match = next((item for item in files if item.relative.as_posix() == VERSION_FILE), None)
    if match is None:
        raise ValueError(f"{VERSION_FILE} is absent")
    try:
        value = match.payload.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{VERSION_FILE} must be UTF-8 text") from exc
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None:
        raise ValueError(f"{VERSION_FILE} must contain a semantic X.Y.Z version")
    return value


def _community_version_module(text: str, version: str) -> str:
    updated, count = re.subn(
        r'(?m)^__version__\s*=\s*"[^"]+"\s*$',
        f'__version__ = "{version}"',
        text,
        count=1,
    )
    if count != 1:
        raise ValueError("version.py does not contain one replaceable __version__ assignment")
    return updated.replace("Sniper Enterprise", "Sniper Community")


def _write_text(destination: Path, text: str, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    destination.chmod(stat.S_IMODE(mode))


def _write_bytes(destination: Path, payload: bytes, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    destination.chmod(stat.S_IMODE(mode))


def _replace_exact(text: str, old: str, new: str, *, expected: int, relative: str) -> str:
    count = text.count(old)
    if count != expected:
        raise ValueError(f"{relative}: expected {expected} exact transform anchor(s), found {count}")
    return text.replace(old, new)


def _replace_pattern(
    text: str,
    pattern: str,
    replacement: str,
    *,
    expected: int,
    relative: str,
) -> str:
    updated, count = re.subn(pattern, replacement, text, flags=re.MULTILINE | re.DOTALL)
    if count != expected:
        raise ValueError(f"{relative}: expected {expected} structural transform anchor(s), found {count}")
    return updated


def _transform_server(text: str) -> str:
    relative = "server.py"
    private_delivery_module = _DELIVERY_MODULE.removesuffix(".py")
    private_release_module = _RELEASE_INFO.removesuffix(".py")
    if "import community_release_info\n" in text:
        markers = (
            "RUNNING_RELEASE = None\n",
            '"profile": "community-v1"',
            '"restore_commands": {},',
        )
        if any(marker not in text for marker in markers):
            raise ValueError(f"{relative}: Community transform marker is incomplete")
        for contract in (private_delivery_module, "runtime_" + "entitlement", "scripts/" + "update.py"):
            if contract in text:
                raise ValueError(f"{relative}: excluded delivery contract remained after transform")
        return text
    text = _replace_exact(
        text,
        private_release_module,
        "community_release_info",
        expected=6,
        relative=relative,
    )
    text = _replace_exact(
        text,
        f"import {private_delivery_module}\n",
        "",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        "RUNNING_RELEASE = community_release_info.read_json(BASE_DIR / community_release_info.RELEASE_FILE, None)\n",
        "RUNNING_RELEASE = None\n",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        f"RUNTIME_ENTITLEMENT = {private_delivery_module}.runtime_entitlement_status(BASE_DIR, RUNNING_RELEASE)\n",
        "",
        expected=1,
        relative=relative,
    )
    text = _replace_pattern(
        text,
        r"^def _runtime_entitlement_state\(\) -> dict:\n.*?(?=^def get_broad_nuclei_jobs)",
        "",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        "        running_release=RUNNING_RELEASE, runtime_entitlement=_runtime_entitlement_state(), refresh=refresh,\n",
        "        running_release=RUNNING_RELEASE, refresh=refresh,\n",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        "                BASE_DIR, DATA_DIR, running_release=RUNNING_RELEASE, runtime_entitlement=_runtime_entitlement_state()\n",
        "                BASE_DIR, DATA_DIR, running_release=RUNNING_RELEASE\n",
        expected=1,
        relative=relative,
    )
    text = _replace_pattern(
        text,
        r'^        if path == "/api/health":\n.*?(?=^        if path == "/api/plugins":)',
        '        if path == "/api/health":\n'
        '            return self._json({\n'
        '                "status": "ok",\n'
        '                "service": "sniper-audit",\n'
        '                "profile": "community-v1",\n'
        '                "plugins": PLUGIN_MANAGER.public_status(),\n'
        '            })\n',
        expected=1,
        relative=relative,
    )
    text = _replace_pattern(
        text,
        r"^def _backups_payload\(\) -> dict:\n.*?(?=^def _tracking_auth_enabled)",
        'def _backups_payload() -> dict:\n'
        '    """Read-only Community database-backup status."""\n'
        '    return {\n'
        '        "db_backups": data_retention.list_db_backups(DATA_DIR),\n'
        '        "summary": data_retention.backup_summary(DATA_DIR),\n'
        '        "update_backups": [],\n'
        '        "restore_commands": {},\n'
        '        "ui_restore": False,\n'
        '    }\n'
        '\n',
        expected=1,
        relative=relative,
    )
    text = _replace_pattern(
        text,
        r"^def main\(\) -> None:\n    try:\n.*?^    refusal = remote_bind_refusal\(HOST\)\n",
        "def main() -> None:\n    refusal = remote_bind_refusal(HOST)\n",
        expected=1,
        relative=relative,
    )
    for contract in (private_delivery_module, "runtime_" + "entitlement", "scripts/" + "update.py"):
        if contract in text:
            raise ValueError(f"{relative}: excluded delivery contract remained after transform")
    return text


def _transform_system_health(text: str) -> str:
    relative = "system_health.py"
    private_release_module = _RELEASE_INFO.removesuffix(".py")
    if "import community_release_info" in text:
        if text.count("community_release_info") != 4 \
                or "runtime_" + "entitlement" in text \
                or "protected-" + "v1" in text.casefold():
            raise ValueError(f"{relative}: Community transform marker is incomplete")
        return text
    text = _replace_exact(
        text,
        private_release_module,
        "community_release_info",
        expected=4,
        relative=relative,
    )
    text = _replace_pattern(
        text,
        r"^def check_runtime_entitlement\(runtime_entitlement: Any\) -> list\[dict\[str, Any\]\]:\n.*?(?=^def check_auth)",
        "",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        "                 pin_states: Callable[[], list[dict[str, Any]]] | None = None,\n                 runtime_entitlement: Any = None) -> dict[str, Any]:",
        "                 pin_states: Callable[[], list[dict[str, Any]]] | None = None) -> dict[str, Any]:",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        "        lambda: check_runtime_entitlement(runtime_entitlement),\n",
        "",
        expected=1,
        relative=relative,
    )
    recovery_tool = _UPDATE_SCRIPT.rsplit("/", 1)[-1]
    text = _replace_exact(
        text,
        recovery_tool,
        "documented Community recovery procedure",
        expected=1,
        relative=relative,
    )
    if "runtime_" + "entitlement" in text or "protected-" + "v1" in text.casefold():
        raise ValueError(f"{relative}: excluded delivery contract remained after transform")
    return text


def _transform_data_retention(text: str) -> str:
    relative = "data_retention.py"
    private_release_module = _RELEASE_INFO.removesuffix(".py")
    if "import community_release_info" in text:
        if text.count("community_release_info") != 5 or _UPDATE_SCRIPT.rsplit("/", 1)[-1] in text:
            raise ValueError(f"{relative}: Community transform marker is incomplete")
        return text
    text = _replace_exact(
        text,
        private_release_module,
        "community_release_info",
        expected=5,
        relative=relative,
    )
    recovery_tool = _UPDATE_SCRIPT.rsplit("/", 1)[-1]
    text = _replace_exact(
        text,
        recovery_tool,
        "documented Community recovery procedure",
        expected=6,
        relative=relative,
    )
    return text


def _transform_system_version_ui(text: str) -> str:
    relative = "static/system_version.js"
    if 'command.textContent = data.maintenance_note || ""' in text:
        if "protected-" + "v1" in text.casefold() or "entitlement" in text.casefold():
            raise ValueError(f"{relative}: Community transform marker is incomplete")
        return text
    text = _replace_pattern(
        text,
        r"^    const entitlement = data\.entitlement \|\| \{};\n.*?(?=^    if \(data\.restart_pending)",
        "",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        '    if (command) command.textContent = `${data.update_command}\\n${data.rollback_command}`;',
        '    if (command) command.textContent = data.maintenance_note || "";',
        expected=1,
        relative=relative,
    )
    if "protected-" + "v1" in text.casefold() or "entitlement" in text.casefold():
        raise ValueError(f"{relative}: excluded delivery contract remained after transform")
    return text


def _transform_system_version_test(text: str) -> str:
    relative = "tests/test_system_version_ui.mjs"
    if "maintenance_note: 'Review the next Community source archive before replacement.'" in text:
        if _UPDATE_SCRIPT in text:
            raise ValueError(f"{relative}: Community transform marker is incomplete")
        return text
    private_update_path = _UPDATE_SCRIPT
    text = _replace_exact(
        text,
        f"  update_command: 'python3 /x/app/{private_update_path} <paket>.tar.gz', rollback_command: 'python3 /x/app/{private_update_path} --rollback <yedek-kimliği>',",
        "  maintenance_note: 'Review the next Community source archive before replacement.',",
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        "  assert.match(ids['system-version-command'].textContent, /update\\.py <paket>\\.tar\\.gz\\n.*--rollback/);",
        "  assert.match(ids['system-version-command'].textContent, /Review the next Community source archive/);",
        expected=1,
        relative=relative,
    )
    return text


def _transform_data_retention_test(text: str) -> str:
    relative = "tests/test_data_retention_r17.py"
    if "restored = dr.restore_db_backup(self.dir, sniper_backup)" in text:
        if _UPDATE_SCRIPT in text:
            raise ValueError(f"{relative}: Community transform marker is incomplete")
        return text
    private_update_tool = _UPDATE_SCRIPT.rsplit("/", 1)[-1]
    text = _replace_exact(
        text,
        f'''        proc = subprocess.run([sys.executable, str(APP / "scripts" / "{private_update_tool}"), "--prefix", self.tmp.name,
                               "--data-dir", self.tmp.name, "--restore-db", sniper_backup, "--no-restart"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
''',
        '''        restored = dr.restore_db_backup(self.dir, sniper_backup)
        self.assertEqual(restored["restored"], sniper_backup)
''',
        expected=1,
        relative=relative,
    )
    text = _replace_exact(
        text,
        f'''        listed = subprocess.run([sys.executable, str(APP / "scripts" / "{private_update_tool}"), "--prefix", self.tmp.name,
                                 "--data-dir", self.tmp.name, "--list-db-backups"], capture_output=True, text=True, timeout=60)
        self.assertIn(sniper_backup, listed.stdout)
        bad = subprocess.run([sys.executable, str(APP / "scripts" / "{private_update_tool}"), "--prefix", self.tmp.name,
                              "--data-dir", self.tmp.name, "--restore-db", "../sniper.db", "--no-restart"],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(bad.returncode, 2)
''',
        '''        listed = {item["name"] for item in dr.list_db_backups(self.dir)}
        self.assertIn(sniper_backup, listed)
        with self.assertRaises(dr.RetentionError):
            dr.restore_db_backup(self.dir, "../sniper.db")
''',
        expected=1,
        relative=relative,
    )
    return text


def _transform_user_guide(text: str) -> str:
    relative = "docs/KULLANIM-KILAVUZU.md"
    private_fragments = (
        _PACKAGE_SCRIPT,
        _INSTALL_SCRIPT,
        _UPDATE_SCRIPT,
        _ROLLBACK_SCRIPT,
        _UPDATE_SCRIPT.rsplit("/", 1)[-1],
    )
    if "| Community source update |" in text:
        if any(fragment in text for fragment in private_fragments):
            raise ValueError(f"{relative}: Community transform marker is incomplete")
        return text
    lines = text.splitlines(keepends=True)
    removed = [line for line in lines if any(fragment in line for fragment in private_fragments)]
    if len(removed) != 8:
        raise ValueError(f"{relative}: expected 8 private delivery instruction anchors, found {len(removed)}")
    output: list[str] = []
    inserted = False
    for line in lines:
        if any(fragment in line for fragment in private_fragments):
            if not inserted:
                output.append("| Community source update | Yeni arşivi ve SHA-256 manifestini inceleyip kaynak ağacını değiştirin |\n")
                inserted = True
            continue
        output.append(line)
    return "".join(output)


def _transform_dockerfile(text: str) -> str:
    relative = "Dockerfile"
    if "# Authentication field encryption is a mandatory runtime capability." in text:
        return text
    return _replace_exact(
        text,
        "# Authentication field encryption and release signatures are mandatory runtime\n# capabilities, not optional extras. The exact version is shared by source and\n# container profiles.",
        "# Authentication field encryption is a mandatory runtime capability.\n# The exact dependency version is shared by source and container profiles.",
        expected=1,
        relative=relative,
    )


def _transform_mcp_community_wording(text: str) -> str:
    relative = "mcp_triage_server.py"
    private_label = "TRUE" + " LIVE"
    old = (
        f"    # Community verisi kurulu Sniper'ın {private_label} veri kökünden ayrıdır. "
        "Bu varsayılan APP_DIR'ye de bağlı değildir;\n"
        "    # aynı yayın paketi nereden çalıştırılırsa çalıştırılsın kurulu uygulamanın "
        "veritabanına sessizce düşemez."
    )
    new = (
        "    # Community verisi açıkça belirtilen uygulama veritabanlarından ayrıdır. "
        "Varsayılan APP_DIR'ye bağlı değildir;\n"
        "    # kaynak ağacı nereden çalıştırılırsa çalıştırılsın başka bir uygulama "
        "veritabanına sessizce düşemez."
    )
    if new in text:
        if text.count(new) != 1 or private_label in text:
            raise ValueError(f"{relative}: Community wording transform marker is incomplete")
        return text
    return _replace_exact(text, old, new, expected=1, relative=relative)


def _transform_project_audit_ui_wording(text: str) -> str:
    relative = "static/index.html"
    private_label = "Sp" + "ark"
    old = (
        f"Kaynak kod {private_label} dışına çıkmaz. Sır değerleri ve kaynak satırları rapora "
        "kopyalanmaz; yalnız kural, dosya ve satır numarası saklanır."
    )
    new = (
        "Kaynak kod yerel makinenin dışına çıkmaz. Sır değerleri ve kaynak satırları rapora "
        "kopyalanmaz; yalnız kural, dosya ve satır numarası saklanır."
    )
    if new in text:
        if text.count(new) != 1 or private_label in text:
            raise ValueError(f"{relative}: Community wording transform marker is incomplete")
        return text
    return _replace_exact(text, old, new, expected=1, relative=relative)


def _transform_project_audit_i18n_wording(text: str) -> str:
    relative = "static/i18n-en.tsv"
    private_label = "Sp" + "ark"
    old = (
        f"S\tKaynak kod {private_label} dışına çıkmaz. Sır değerleri ve kaynak satırları rapora "
        "kopyalanmaz; yalnız kural, dosya ve satır numarası saklanır.\t"
        f"Source code does not leave {private_label}. Secret values and source lines are not "
        "copied into the report; only the rule, file and line number are stored."
    )
    new = (
        "S\tKaynak kod yerel makinenin dışına çıkmaz. Sır değerleri ve kaynak satırları rapora "
        "kopyalanmaz; yalnız kural, dosya ve satır numarası saklanır.\t"
        "Source code does not leave the local machine. Secret values and source lines are not "
        "copied into the report; only the rule, file and line number are stored."
    )
    if new in text:
        if text.count(new) != 1 or private_label in text:
            raise ValueError(f"{relative}: Community wording transform marker is incomplete")
        return text
    return _replace_exact(text, old, new, expected=1, relative=relative)


def _apply_artifact_transform(relative: Path, text: str) -> str:
    transforms = {
        "Dockerfile": _transform_dockerfile,
        "data_retention.py": _transform_data_retention,
        "docs/KULLANIM-KILAVUZU.md": _transform_user_guide,
        "mcp_triage_server.py": _transform_mcp_community_wording,
        "server.py": _transform_server,
        "static/i18n-en.tsv": _transform_project_audit_i18n_wording,
        "static/index.html": _transform_project_audit_ui_wording,
        "static/system_version.js": _transform_system_version_ui,
        "system_health.py": _transform_system_health,
        "tests/test_data_retention_r17.py": _transform_data_retention_test,
        "tests/test_system_version_ui.mjs": _transform_system_version_test,
    }
    transform = transforms.get(relative.as_posix())
    if transform is not None:
        return transform(text)
    return text


def _manifest(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative == MANIFEST_NAME:
            continue
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
    return "\n".join(lines) + "\n"


def _secure_runtime_directories(root: Path) -> None:
    """Give executable plugin roots deterministic fail-closed permissions."""
    for relative in ("plugins", "plugins/base", "plugins/user"):
        path = root / relative
        if path.is_dir():
            path.chmod(0o700)
            for child in path.iterdir():
                if child.is_file():
                    child.chmod(0o600)


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_output_parent(output: Path) -> int:
    """Open/create an absolute output parent one component at a time without links."""
    if not output.is_absolute() or not output.name:
        raise ValueError(f"output must name a non-root path: {output}")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    current_fd = os.open(output.anchor, directory_flags)
    current_path = Path(output.anchor)
    try:
        for component in output.parent.parts[1:]:
            current_path /= component
            try:
                observed = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
                observed = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(observed.st_mode):
                raise ValueError(f"output parent path component is a symbolic link: {current_path}")
            if not stat.S_ISDIR(observed.st_mode):
                raise ValueError(f"output parent path component is not a directory: {current_path}")
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            except OSError as exc:
                raise ValueError(f"output parent cannot be opened safely: {current_path}: {exc}") from exc
            if _stat_identity(os.fstat(next_fd)) != _stat_identity(observed):
                os.close(next_fd)
                raise ValueError(f"output parent changed during traversal: {current_path}")
            os.close(current_fd)
            current_fd = next_fd

        try:
            output_entry = os.stat(output.name, dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            return current_fd
        if stat.S_ISLNK(output_entry.st_mode):
            raise ValueError(f"output path is a symbolic link: {output}")
        raise ValueError(f"output already exists: {output}")
    except Exception:
        os.close(current_fd)
        raise


def _anchored_staging_path(parent_fd: int, parent: Path, staging_name: str) -> Path:
    proc_parent = Path("/proc/self/fd") / str(parent_fd)
    if proc_parent.is_dir():
        return proc_parent / staging_name
    return parent / staging_name


def build(source: Path, output: Path) -> tuple[int, int, int]:
    source = source.resolve()
    output = _lexical_absolute(output)
    if output == source or output.is_relative_to(source):
        raise ValueError("output must be outside the source tree")
    source_files, skipped = _source_files(source)
    version = _community_version(source_files)

    parent_fd = _open_output_parent(output)
    staging_name = f".{output.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
    staging_stat = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
    staging = _anchored_staging_path(parent_fd, output.parent, staging_name)

    copied = sanitized = 0
    try:
        for source_file in source_files:
            relative = source_file.relative
            payload = source_file.payload
            destination = staging / relative
            scan_text = payload.decode("utf-8", errors="ignore")
            doc_or_test = bool(relative.parts and relative.parts[0] in {"docs", "tests", "browser-tests"})
            if _has_secret(scan_text):
                if doc_or_test:
                    skipped += 1
                    continue
                raise ValueError(f"credential-shaped content in runtime source: {relative.as_posix()}")
            machine_metadata = _has_machine_metadata(scan_text)
            if doc_or_test and _must_exclude_doc_or_test(scan_text):
                skipped += 1
                continue
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                if machine_metadata:
                    raise ValueError(f"machine-specific metadata in binary runtime source: {relative.as_posix()}")
                _write_bytes(destination, payload, source_file.mode)
                copied += 1
                continue

            if machine_metadata:
                text = _sanitize(text)
                sanitized += 1
            if relative.as_posix() == "version.py":
                text = _community_version_module(text, version)
                sanitized += 1
            transformed = _apply_artifact_transform(relative, text)
            if transformed != text:
                text = transformed
                sanitized += 1
            _write_text(destination, text, source_file.mode)
            copied += 1

        _secure_runtime_directories(staging)
        _write_text(staging / LIMITATIONS_NAME, LIMITATIONS, 0o644)
        _write_text(staging / MANIFEST_NAME, _manifest(staging), 0o644)
        try:
            current_parent = output.parent.lstat()
        except OSError as exc:
            raise ValueError(f"output parent changed before publication: {output.parent}: {exc}") from exc
        if _stat_identity(current_parent) != _stat_identity(os.fstat(parent_fd)):
            raise ValueError(f"output parent changed before publication: {output.parent}")
        current_staging = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(current_staging.st_mode) \
                or _stat_identity(current_staging) != _stat_identity(staging_stat):
            raise ValueError("staging directory changed before publication")
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError(f"output appeared during build: {output}")
        os.rename(staging_name, output.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    except Exception:
        try:
            current_staging = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISDIR(current_staging.st_mode) \
                    and _stat_identity(current_staging) == _stat_identity(staging_stat):
                shutil.rmtree(staging)
        except OSError:
            pass
        raise
    finally:
        os.close(parent_fd)
    return copied, sanitized, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        copied, sanitized, skipped = build(args.source, args.output)
    except (OSError, ValueError) as exc:
        print(f"community source build: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"community source build: PASS "
        f"(copied={copied}, sanitized={sanitized}, skipped={skipped}, output={args.output.resolve()})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
