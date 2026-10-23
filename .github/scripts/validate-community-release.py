#!/usr/bin/env python3
"""Validate the documentation and metadata of the Community release surface.

This validator is deliberately offline and read-only.  It does not inspect or
modify a Sniper database and it never starts a scanner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tomllib
from typing import NamedTuple


DEFAULT_ROOT = Path(__file__).resolve().parents[2]
MAX_REGULAR_FILE_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
REQUIRED_FILES = (
    "README.md",
    "VALIDATION.md",
    "DEPLOYMENT.md",
    "LICENSE",
    "SECURITY.md",
    "SECURITY-MAINTAINERS.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "SUPPORT.md",
    "CITATION.cff",
    "COMMUNITY-TOOLS.lock.json",
    "COMMUNITY_VERSION",
    ".github/CODEOWNERS",
    ".github/VULNERABILITY_REPORT.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/pull_request_template.md",
    ".github/dependabot.yml",
    "docs/COMMUNITY-TOOLS.md",
    "scripts/install-community-tools",
    "docs/COMMUNITY-MCP.md",
    "docs/examples/mcp/stdio-community.json",
    "docs/examples/mcp/stdio-read-only.json",
    "docs/examples/mcp/stdio-with-token.json",
    "docs/examples/mcp/codex-config.toml",
)

REQUIRED_TEXT = {
    "README.md": (
        "Sniper Community",
        "Apache License 2.0",
        "licensed under the Apache License 2.0",
        "publication status does not make that license grant provisional",
        "AI-first",
        "stdio MCP",
        "human approval",
        "Manual CLI",
        "Local web",
        "Enterprise code is not included",
        "python3 scripts/sniper-mcp --help",
        "prepare_action",
        "execute_action",
        "MCP host",
        "Gökçe Baran Karakamış",
        "@dytredline",
    ),
    "VALIDATION.md": (
        "Sniper Community validation evidence",
        "2,787 tests, 0 failures, 0 errors",
        "163 passed",
        "426 passed, 0 failed",
        "not a security certification",
        "No step in this validation snapshot scans an external website",
    ),
    "DEPLOYMENT.md": (
        "Sniper Community local deployment",
        "127.0.0.1:8787",
        "COMMUNITY-SOURCE-MANIFEST.sha256",
        "--scan-release-tree",
        "explicitly authorized",
    ),
    "SECURITY.md": (
        "Private Vulnerability Reporting",
        "authorized systems",
        "Do not include secrets",
        "Gökçe Baran Karakamış",
        "@dytredline",
        "3 business days",
        "7 business days",
        "90 days",
    ),
    "SECURITY-MAINTAINERS.md": (
        "Security Maintainer",
        "Gökçe Baran Karakamış",
        "@dytredline",
        "2026-10-23",
        "not a claim of an existing CVE or GHSA",
    ),
    ".github/CODEOWNERS": (
        "/SECURITY.md @dytredline",
        "/SECURITY-MAINTAINERS.md @dytredline",
        "/.github/VULNERABILITY_REPORT.yml @dytredline",
        "/auth.py @dytredline",
        "/mcp_*.py @dytredline",
        "/verified_exec.py @dytredline",
    ),
    ".github/VULNERABILITY_REPORT.yml": (
        "name: Report a Sniper vulnerability",
        "description: Privately report a suspected vulnerability to Gökçe Baran Karakamış (@dytredline).",
        "body:",
        "type:",
        "validations:",
        "Affected version or commit",
        "Safe reproduction",
        "explicitly authorized to assess",
        "I removed secrets, personal data, and third-party exploit traffic",
    ),
    "CONTRIBUTING.md": (
        "python3 .github/scripts/validate-community-release.py",
        "python3 scripts/run_all_tests.py",
        "external target",
        "Apache-2.0 inbound=outbound",
        "right to submit the contribution",
    ),
    "CODE_OF_CONDUCT.md": ("Contributor Covenant", "Enforcement"),
    "CHANGELOG.md": (
        "# Changelog",
        "Sniper Community 1.0.0",
        "Apache-2.0",
        "human-confirmed MCP action plans",
    ),
    "SUPPORT.md": (
        "# Community support",
        "no support SLA",
        "Private Vulnerability Reporting",
        "explicitly authorized",
    ),
    "CITATION.cff": (
        "cff-version: 1.2.0",
        "title: Sniper Community",
        "Gökçe Baran",
        "Karakamış",
        "version: 1.0.0",
        "license: Apache-2.0",
        "https://github.com/dytredline/Sniper",
    ),
    "COMMUNITY-TOOLS.lock.json": (
        '"schema": "sniper-community-tools-lock-v1"',
        '"local"',
        '"linux-aarch64"',
        '"linux-x86_64"',
        '"sha256"',
        '"license"',
    ),
    "docs/COMMUNITY-TOOLS.md": (
        "# Community tool installation",
        "python3 scripts/install-community-tools --profile local --accept-third-party-licenses",
        "COMMUNITY-TOOLS.lock.json",
        "Burp Suite Professional",
        "must remain unavailable",
    ),
    "scripts/install-community-tools": (
        "community_tool_installer",
        "--accept-third-party-licenses",
        "COMMUNITY-TOOLS.lock.json",
    ),
    ".github/ISSUE_TEMPLATE/bug_report.yml": (
        "name: Bug report",
        "Do not report security vulnerabilities in a public issue",
        "Sniper Community version or commit",
        "Safe local reproduction",
        "I removed secrets, personal data, and production evidence",
    ),
    ".github/ISSUE_TEMPLATE/feature_request.yml": (
        "name: Feature request",
        "Defensive use case",
        "Observable outcome",
        "Authorization and safety boundary",
    ),
    ".github/ISSUE_TEMPLATE/config.yml": (
        "blank_issues_enabled: false",
        "Private vulnerability report",
        "https://github.com/dytredline/Sniper/security/advisories/new",
    ),
    ".github/pull_request_template.md": (
        "## Observable behavior",
        "## Tests actually run",
        "No external target was scanned",
        "No live Sniper database was used",
    ),
    ".github/dependabot.yml": (
        "version: 2",
        'package-ecosystem: "pip"',
        'package-ecosystem: "npm"',
        'package-ecosystem: "github-actions"',
        'package-ecosystem: "docker"',
        'interval: "monthly"',
    ),
    "docs/COMMUNITY-MCP.md": (
        "stdin/stdout",
        "confirm_request",
        "prepare_action",
        "execute_action",
        "user_confirmed",
        "consent_scope",
        "MCP host",
        "model provider",
        "python3 scripts/sniper-mcp --help",
    ),
}

FORBIDDEN_RELEASE_SURFACE = {
    "private home path": re.compile(r"/home/[A-Za-z0-9_.-]+/"),
    "migration workspace": re.compile("sniper-" + "gptoss-" + r"migration|development-loop-v\d+", re.I),
    "frozen or evidence workspace": re.compile("frozen-" + "evidence|dev-" + "evidence", re.I),
    "session/project codename": re.compile(
        r"\b(?:" + "|".join(("Ar" + "gon", "Vivu" + "sunda", "Guar" + "dian", "Q" + "wen")) + r")\b",
        re.I,
    ),
    "private key material": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "enterprise-only contract": re.compile(
        "protected-" + "v1|distribution_" + "entitlement|SNIPER_" + "ENTITLEMENT|customer-" + "entitlement",
        re.I,
    ),
    "installed private product path": re.compile(r"~/\.local/share/" + "sniper/app" + r"(?:/|\b)"),
}

FORBIDDEN_ARTIFACT_DIRS = frozenset({
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "node_modules",
    "data", "backups", "backup", "evidence", "dev-" + "evidence", "frozen-" + "evidence",
})
FORBIDDEN_ARTIFACT_NAMES = frozenset({"release.json", ".coverage"})
FORBIDDEN_ARTIFACT_SUFFIXES = (
    ".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", "-wal", "-shm", "-journal",
)
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
PRIVATE_PUBLICATION_WORDING = re.compile(
    r"\b(?:" + "Sp" + "ark|TRUE" + r"\s+" + "LIVE" + r")\b",
    re.IGNORECASE,
)
PORTABLE_CONTAINER_LABEL = "org.sniper.community.k6.local"
PORTABLE_TEMPLATE_AUTHOR = "sniper-community"
ACTIVE_TARGET_TESTS = frozenset({
    "tests/test_wave20_sqlite_wal_concurrency_stress.py",
    "tests/test_zap_actor_job_lease.py",
    "tests/test_zap_actor_job_lifecycle_audit.py",
    "tests/test_zap_storage_and_redirect_guard.py",
    "tests/test_zap_target_active_api.py",
})
HTTP_URL = re.compile(r"https?://[^\s\"'<>]+")
LEGACY_CONTAINER_NAMESPACE = re.compile(r"\borg\.[A-Za-z0-9.-]+\.sniper\.k6\.local\b")
HARD_CODED_HOME_ACCOUNT = re.compile(r"segments\s*\[\s*2\s*\]\s*===\s*['\"]")

_DELIVERY_MODULE = "distribution_" + "entitlement.py"
_DELIVERY_PROFILE = "distribution_" + "profile.py"
_NATIVE_BUILD = "native_" + "distribution_build.py"
_NATIVE_READINESS = "native_" + "distribution_readiness.py"
_RELEASE_INFO = "release_" + "info.py"
_RELEASE_OPS = "release_" + "ops.py"
_UPDATE_TOOL = "update" + ".py"

FORBIDDEN_CLOSED_BASENAMES = frozenset({
    _DELIVERY_MODULE,
    _DELIVERY_PROFILE,
    _NATIVE_BUILD,
    _NATIVE_READINESS,
    "native_launcher.py",
    "native_platform_verification.py",
    _RELEASE_INFO,
    _RELEASE_OPS,
})
FORBIDDEN_CLOSED_PATHS = frozenset({
    "scripts/distribution_" + "entitlement.py",
    "scripts/package_" + "release.py",
    "scripts/" + "install.py",
    "scripts/" + _UPDATE_TOOL,
    "scripts/" + "rollback.py",
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
FORBIDDEN_CLOSED_BASENAMES_CASEFOLD = frozenset(name.casefold() for name in FORBIDDEN_CLOSED_BASENAMES)
FORBIDDEN_CLOSED_PATHS_CASEFOLD = frozenset(name.casefold() for name in FORBIDDEN_CLOSED_PATHS)
FORBIDDEN_CLOSED_CONTRACTS = (
    re.compile("protected-" + "v1", re.I),
    re.compile("distribution_" + "entitlement", re.I),
    re.compile("SNIPER_" + "ENTITLEMENT", re.I),
    re.compile("customer-" + "entitlement", re.I),
    re.compile(r"\.sniper-" + "entitlement", re.I),
    re.compile("sniper-" + "protected", re.I),
    re.compile("native_" + r"distribution_(?:build|readiness)", re.I),
    re.compile(r"(?:from|import)\s+" + "release_" + r"(?:info|ops)\b", re.I),
    re.compile(r"scripts/(?:package_" + "release|install|update|rollback)" + r"\.py", re.I),
)


def fail(message: str, failures: list[str]) -> None:
    failures.append(message)


def _literal_http_hostname(value: str) -> str | None:
    authority = value.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    if authority.startswith("["):
        end = authority.find("]")
        return authority[1:end].casefold() if end > 1 else None
    hostname = authority.split(":", 1)[0].casefold()
    return hostname or None


def _validate_portable_public_identity(relative: str, text: str, failures: list[str]) -> None:
    if relative == "k6_loopback_active.py":
        expected = f"CONTAINER_OWNERSHIP_LABEL = '{PORTABLE_CONTAINER_LABEL}'"
        if expected not in text or LEGACY_CONTAINER_NAMESPACE.search(text):
            fail(f"release tree: nonportable container ownership namespace: {relative}", failures)

    if relative == "templates/nuclei/local-powered-by.yaml":
        authors = [value.strip() for value in re.findall(r"(?m)^\s*author:\s*([^#\r\n]+)", text)]
        if authors != [PORTABLE_TEMPLATE_AUTHOR]:
            fail(f"release tree: nonportable template author: {relative}", failures)

    if relative in {"static/trufflehog_filesystem.js", "static/trufflehog_git_history.js"} \
            and HARD_CODED_HOME_ACCOUNT.search(text):
        fail(f"release tree: hard-coded home account: {relative}", failures)

    if relative == "scripts/build-community-source.py" \
            and ("MAINTAINER" + "_HOME") in text:
        fail(f"release tree: maintainer-specific home rule: {relative}", failures)

    if relative in ACTIVE_TARGET_TESTS:
        for value in HTTP_URL.findall(text):
            hostname = _literal_http_hostname(value.rstrip("),];"))
            if hostname is None:
                continue
            reserved = (
                hostname in {"example.test", "example.local", "localhost", "127.0.0.1", "::1"}
                or hostname.endswith(".example.test")
                or hostname.endswith(".example.local")
                or hostname.endswith(".example")
                or hostname.endswith(".invalid")
            )
            if not reserved:
                fail(f"release tree: non-reserved active target fixture: {relative}", failures)
                break


class ReleaseEntry(NamedTuple):
    relative: str
    mode: int
    payload: bytes | None


def _identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _content_state(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _entry_kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symbolic link"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block device"
    if stat.S_ISCHR(mode):
        return "character device"
    return "unknown special entry"


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
                f"release tree: regular file exceeds {MAX_REGULAR_FILE_BYTES}-byte validation limit: {relative}"
            )
        chunks.append(chunk)


def _snapshot_release_tree(root: Path, failures: list[str]) -> list[ReleaseEntry]:
    """Read a release tree without following links or reopening files by path."""
    try:
        lexical_root = root.absolute()
        root_lstat = lexical_root.lstat()
    except OSError as exc:
        fail(f"release tree: cannot stat root: {exc}", failures)
        return []
    if not stat.S_ISDIR(root_lstat.st_mode):
        fail("release tree: root must be a regular directory, not a link or special entry", failures)
        return []

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    file_flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(lexical_root, directory_flags)
    except OSError as exc:
        fail(f"release tree: cannot open root without following links: {exc}", failures)
        return []
    try:
        if _identity(os.fstat(root_fd)) != _identity(root_lstat):
            fail("release tree: root changed while validation started", failures)
            return []

        entries: list[ReleaseEntry] = []
        snapshot_bytes = 0

        def walk(directory_fd: int, parent: PurePosixPath) -> None:
            nonlocal snapshot_bytes
            try:
                with os.scandir(directory_fd) as iterator:
                    names = sorted(item.name for item in iterator)
            except OSError as exc:
                location = parent.as_posix() if parent.parts else "."
                fail(f"release tree: cannot enumerate directory {location}: {exc}", failures)
                return

            for name in names:
                relative_path = parent / name
                relative = relative_path.as_posix()
                if "\n" in name or "\r" in name:
                    fail(f"release tree: unsafe filesystem entry name: {relative!r}", failures)
                try:
                    observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    fail(f"release tree: entry changed before stat: {relative}: {exc}", failures)
                    continue

                if stat.S_ISDIR(observed.st_mode):
                    entries.append(ReleaseEntry(relative, observed.st_mode, None))
                    try:
                        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                    except OSError as exc:
                        fail(f"release tree: cannot open directory safely: {relative}: {exc}", failures)
                        continue
                    try:
                        if _identity(os.fstat(child_fd)) != _identity(observed):
                            fail(f"release tree: directory changed during traversal: {relative}", failures)
                            continue
                        walk(child_fd, relative_path)
                    finally:
                        os.close(child_fd)
                    continue

                if not stat.S_ISREG(observed.st_mode):
                    entries.append(ReleaseEntry(relative, observed.st_mode, None))
                    continue
                if observed.st_size > MAX_REGULAR_FILE_BYTES:
                    entries.append(ReleaseEntry(relative, observed.st_mode, None))
                    fail(
                        f"release tree: regular file exceeds {MAX_REGULAR_FILE_BYTES}-byte validation limit: "
                        f"{relative}",
                        failures,
                    )
                    continue
                if snapshot_bytes + observed.st_size > MAX_SNAPSHOT_BYTES:
                    entries.append(ReleaseEntry(relative, observed.st_mode, None))
                    fail(
                        f"release tree: regular files exceed {MAX_SNAPSHOT_BYTES}-byte snapshot limit",
                        failures,
                    )
                    continue

                try:
                    file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                except OSError as exc:
                    entries.append(ReleaseEntry(relative, observed.st_mode, None))
                    fail(f"release tree: cannot open regular file safely: {relative}: {exc}", failures)
                    continue
                try:
                    opened = os.fstat(file_fd)
                    if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(observed):
                        entries.append(ReleaseEntry(relative, opened.st_mode, None))
                        fail(f"release tree: file changed before safe read: {relative}", failures)
                        continue
                    try:
                        payload = _read_bounded_fd(file_fd, relative)
                    except ValueError as exc:
                        entries.append(ReleaseEntry(relative, opened.st_mode, None))
                        fail(str(exc), failures)
                        continue
                    finished = os.fstat(file_fd)
                    try:
                        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        entries.append(ReleaseEntry(relative, opened.st_mode, payload))
                        fail(f"release tree: file changed after safe read: {relative}: {exc}", failures)
                        continue
                    if _identity(current) != _identity(opened) \
                            or _content_state(finished) != _content_state(opened) \
                            or _content_state(current) != _content_state(finished):
                        fail(f"release tree: file changed during safe read: {relative}", failures)
                    snapshot_bytes += len(payload)
                    if snapshot_bytes > MAX_SNAPSHOT_BYTES:
                        fail(
                            f"release tree: regular files exceed {MAX_SNAPSHOT_BYTES}-byte snapshot limit",
                            failures,
                        )
                    entries.append(ReleaseEntry(relative, opened.st_mode, payload))
                finally:
                    os.close(file_fd)

        walk(root_fd, PurePosixPath())
        return sorted(entries, key=lambda item: item.relative)
    finally:
        os.close(root_fd)


def _validate_manifest(entries: list[ReleaseEntry], failures: list[str]) -> None:
    by_relative = {entry.relative: entry for entry in entries}
    manifest = by_relative.get("COMMUNITY-SOURCE-MANIFEST.sha256")
    if manifest is None or not stat.S_ISREG(manifest.mode) or manifest.payload is None:
        fail("release tree: COMMUNITY-SOURCE-MANIFEST.sha256 is absent", failures)
        return

    expected: dict[str, str] = {}
    try:
        manifest_text = manifest.payload.decode("utf-8")
    except UnicodeDecodeError:
        fail("manifest: content is not valid UTF-8", failures)
        return
    for line_number, line in enumerate(manifest_text.splitlines(), 1):
        try:
            digest, relative = line.split("  ", 1)
        except ValueError:
            fail(f"manifest line {line_number}: expected '<sha256>  <path>'", failures)
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"manifest line {line_number}: invalid SHA-256", failures)
            continue
        if relative in expected:
            fail(f"manifest line {line_number}: duplicate path: {relative}", failures)
            continue
        parsed = PurePosixPath(relative)
        if parsed.is_absolute() or relative != parsed.as_posix() or ".." in parsed.parts:
            fail(f"manifest line {line_number}: unsafe or non-canonical path", failures)
            continue
        expected[relative] = digest

    actual_paths = {
        entry.relative for entry in entries
        if not stat.S_ISDIR(entry.mode) and entry.relative != "COMMUNITY-SOURCE-MANIFEST.sha256"
    }
    for relative in sorted(actual_paths - expected.keys()):
        fail(f"manifest: unlisted filesystem entry: {relative}", failures)
    for relative in sorted(expected.keys() - actual_paths):
        fail(f"manifest: listed file is absent: {relative}", failures)
    for relative in sorted(actual_paths & expected.keys()):
        entry = by_relative[relative]
        if not stat.S_ISREG(entry.mode) or entry.payload is None:
            fail(f"manifest: listed entry is not a readable regular file: {relative}", failures)
            continue
        actual = hashlib.sha256(entry.payload).hexdigest()
        if actual != expected[relative]:
            fail(f"manifest: SHA-256 mismatch: {relative}", failures)


def _validate_release_tree(entries: list[ReleaseEntry], failures: list[str]) -> None:
    by_relative = {entry.relative: entry for entry in entries}
    limitations = by_relative.get("COMMUNITY-RELEASE-LIMITATIONS.md")
    if limitations is None or not stat.S_ISREG(limitations.mode) or limitations.payload is None:
        fail("release tree: COMMUNITY-RELEASE-LIMITATIONS.md is absent", failures)
    for entry in entries:
        relative = PurePosixPath(entry.relative)
        relative_text = entry.relative
        if stat.S_ISDIR(entry.mode):
            if relative.name in FORBIDDEN_ARTIFACT_DIRS:
                fail(f"release tree: forbidden artifact directory: {relative_text}", failures)
            continue
        if not stat.S_ISREG(entry.mode):
            fail(
                f"release tree: non-regular filesystem entry ({_entry_kind(entry.mode)}): {relative_text}",
                failures,
            )
            continue
        if entry.payload is None:
            fail(f"release tree: regular file could not be read safely: {relative_text}", failures)
            continue
        if any(part in FORBIDDEN_ARTIFACT_DIRS for part in relative.parts[:-1]):
            fail(f"release tree: forbidden artifact directory: {relative_text}", failures)
        if relative.name.casefold() in FORBIDDEN_ARTIFACT_NAMES or relative.name.startswith(".coverage."):
            fail(f"release tree: forbidden installed/runtime record: {relative_text}", failures)
        if relative.name.endswith(FORBIDDEN_ARTIFACT_SUFFIXES):
            fail(f"release tree: forbidden runtime artifact: {relative_text}", failures)
        if relative.name.casefold() in FORBIDDEN_CLOSED_BASENAMES_CASEFOLD \
                or relative_text.casefold() in FORBIDDEN_CLOSED_PATHS_CASEFOLD:
            fail(f"release tree: excluded closed implementation path: {relative_text}", failures)

        scan_text = entry.payload.decode("utf-8", errors="ignore")
        _validate_portable_public_identity(relative_text, scan_text, failures)
        if PRIVATE_HOME.search(scan_text):
            fail(f"release tree: private home path: {relative_text}", failures)
        for label in (
            "migration workspace",
            "frozen or evidence workspace",
            "session/project codename",
            "installed private product path",
        ):
            if FORBIDDEN_RELEASE_SURFACE[label].search(scan_text):
                fail(f"release tree: {label}: {relative_text}", failures)
        if PRIVATE_PUBLICATION_WORDING.search(scan_text):
            fail(f"release tree: private publication wording: {relative_text}", failures)
        if PRIVATE_KEY_BLOCK.search(scan_text):
            fail(f"release tree: private key block: {relative_text}", failures)
        if any(pattern.search(scan_text) for pattern in TOKEN_PATTERNS):
            fail(f"release tree: credential-shaped token: {relative_text}", failures)
        if any(pattern.search(scan_text) for pattern in FORBIDDEN_CLOSED_CONTRACTS):
            fail(f"release tree: excluded closed implementation contract: {relative_text}", failures)

    _validate_manifest(entries, failures)
    community_version_entry = by_relative.get("COMMUNITY_VERSION")
    version_module_entry = by_relative.get("version.py")
    if community_version_entry is not None and community_version_entry.payload is not None:
        community_version = community_version_entry.payload.decode("utf-8", errors="replace").strip()
        if community_version != "1.0.0":
            fail("release tree: COMMUNITY_VERSION must be 1.0.0 for Community v1", failures)
        if version_module_entry is not None and version_module_entry.payload is not None:
            version_text = version_module_entry.payload.decode("utf-8", errors="replace")
            if f'__version__ = "{community_version}"' not in version_text:
                fail("release tree: version.py does not match COMMUNITY_VERSION", failures)
            if "Sniper Community" not in version_text or "Sniper Enterprise" in version_text:
                fail("release tree: version.py does not identify the Community product", failures)


def validate(root: Path, *, scan_release_tree: bool = False) -> list[str]:
    failures: list[str] = []
    entries = _snapshot_release_tree(root, failures) if scan_release_tree else None
    entry_map = {entry.relative: entry for entry in entries} if entries is not None else None
    texts: dict[str, str] = {}

    def read_text(relative: str) -> str | None:
        if entry_map is not None:
            entry = entry_map.get(relative)
            if entry is None or not stat.S_ISREG(entry.mode) or entry.payload is None:
                return None
            try:
                return entry.payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                fail(f"{relative}: not valid UTF-8: {exc}", failures)
                return None
        path = root / relative
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            fail(f"{relative}: cannot read text: {exc}", failures)
            return None

    for relative in REQUIRED_FILES:
        text = read_text(relative)
        if text is None:
            fail(f"missing required file: {relative}", failures)
        else:
            texts[relative] = text

    for relative, fragments in REQUIRED_TEXT.items():
        text = texts.get(relative)
        if text is None:
            continue
        for fragment in fragments:
            if fragment not in text:
                fail(f"{relative}: missing contract text: {fragment!r}", failures)

    license_text = texts.get("LICENSE")
    if license_text is not None:
        for fragment in (
            "Apache License",
            "Version 2.0, January 2004",
            "http://www.apache.org/licenses/",
            "END OF TERMS AND CONDITIONS",
        ):
            if fragment not in license_text:
                fail(f"LICENSE: not a complete Apache-2.0 text ({fragment!r} absent)", failures)

    tool_lock_text = texts.get("COMMUNITY-TOOLS.lock.json")
    if tool_lock_text is not None:
        try:
            tool_lock = json.loads(tool_lock_text)
            if not isinstance(tool_lock, dict) or tool_lock.get("schema") != "sniper-community-tools-lock-v1":
                raise ValueError("unexpected schema")
            profiles = tool_lock.get("profiles")
            tools = tool_lock.get("tools")
            expected_local = {"nuclei", "trivy", "gitleaks", "trufflehog", "opengrep"}
            if not isinstance(profiles, dict) or set(profiles.get("local", ())) != expected_local:
                raise ValueError("local profile does not contain the supported locked engines")
            if not isinstance(tools, dict) or not expected_local.issubset(tools):
                raise ValueError("local tool definitions are incomplete")
            for tool_id in sorted(expected_local):
                tool = tools[tool_id]
                if not isinstance(tool, dict) or not all(
                    isinstance(tool.get(key), str) and tool[key]
                    for key in ("version", "license", "destination", "binary", "env_binary", "env_sha256")
                ):
                    raise ValueError(f"{tool_id}: incomplete metadata")
                for key in ("destination", "binary"):
                    relative = PurePosixPath(tool[key])
                    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                        raise ValueError(f"{tool_id}: unsafe {key}")
                platforms = tool.get("platforms")
                if not isinstance(platforms, dict) or set(platforms) != {"linux-aarch64", "linux-x86_64"}:
                    raise ValueError(f"{tool_id}: expected Linux ARM64 and x86-64 artifacts")
                for platform_name, artifact in platforms.items():
                    if not isinstance(artifact, dict):
                        raise ValueError(f"{tool_id}/{platform_name}: invalid artifact")
                    url = artifact.get("url")
                    asset_name = artifact.get("asset_name")
                    digest = artifact.get("sha256")
                    kind = artifact.get("kind")
                    maximum = artifact.get("max_bytes")
                    if not isinstance(url, str) or not url.startswith("https://github.com/"):
                        raise ValueError(f"{tool_id}/{platform_name}: non-GitHub HTTPS artifact")
                    if not isinstance(asset_name, str) or PurePosixPath(asset_name).name != asset_name:
                        raise ValueError(f"{tool_id}/{platform_name}: invalid asset name")
                    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                        raise ValueError(f"{tool_id}/{platform_name}: invalid SHA-256")
                    if kind not in {"raw", "zip", "tar.gz"}:
                        raise ValueError(f"{tool_id}/{platform_name}: invalid archive kind")
                    if type(maximum) is not int or not 1 <= maximum <= 4_000_000_000:
                        raise ValueError(f"{tool_id}/{platform_name}: invalid size bound")
                    if kind != "raw":
                        member = PurePosixPath(artifact.get("member", ""))
                        if member.is_absolute() or not member.parts or ".." in member.parts:
                            raise ValueError(f"{tool_id}/{platform_name}: unsafe archive member")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            fail(f"COMMUNITY-TOOLS.lock.json: invalid tool lock: {exc}", failures)

    installer_relative = "scripts/install-community-tools"
    if entry_map is not None:
        installer_entry = entry_map.get(installer_relative)
        installer_mode = installer_entry.mode if installer_entry is not None else 0
    else:
        try:
            installer_mode = (root / installer_relative).lstat().st_mode
        except OSError:
            installer_mode = 0
    if installer_mode and not installer_mode & 0o111:
        fail("scripts/install-community-tools: entrypoint is not executable", failures)

    for relative in (
        "docs/examples/mcp/stdio-community.json",
        "docs/examples/mcp/stdio-read-only.json",
        "docs/examples/mcp/stdio-with-token.json",
    ):
        text = texts.get(relative)
        if text is None:
            continue
        try:
            payload = json.loads(text)
            server = payload["mcpServers"]["sniper-triage"]
            if server.get("command") != "python3" or not isinstance(server.get("args"), list):
                raise ValueError("expected python3 command and args array")
            args = server["args"]
            if not all(isinstance(value, str) for value in args):
                raise ValueError("all args must be strings")
            if not any(value.endswith("/scripts/sniper-mcp") for value in args):
                raise ValueError("scripts/sniper-mcp entrypoint is absent")
            expected_mode = "community" if relative.endswith("stdio-community.json") else "authenticated"
            if "--mode" not in args or args.index("--mode") + 1 >= len(args) \
                    or args[args.index("--mode") + 1] != expected_mode:
                raise ValueError(f"expected --mode {expected_mode}")
            has_token = "--token-file" in args
            if has_token != relative.endswith("stdio-with-token.json"):
                raise ValueError("token-file presence does not match the example name")
            if expected_mode == "community" and "--db" in args:
                raise ValueError("Community quick start must use the isolated default database")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            fail(f"{relative}: invalid MCP example: {exc}", failures)

    toml_text = texts.get("docs/examples/mcp/codex-config.toml")
    if toml_text is not None:
        try:
            payload = tomllib.loads(toml_text)
            server = payload["mcp_servers"]["sniper-triage"]
            if server.get("command") != "python3" or not isinstance(server.get("args"), list):
                raise ValueError("expected python3 command and args array")
            args = server["args"]
            if "--mode" not in args or args.index("--mode") + 1 >= len(args) \
                    or args[args.index("--mode") + 1] != "community" or "--db" in args:
                raise ValueError("expected Community mode with isolated default database")
        except (KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
            fail(f"docs/examples/mcp/codex-config.toml: invalid example: {exc}", failures)

    for relative, text in texts.items():
        for label, pattern in FORBIDDEN_RELEASE_SURFACE.items():
            if pattern.search(text):
                fail(f"{relative}: forbidden {label}", failures)

    if entries is not None:
        _validate_release_tree(entries, failures)

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_ROOT,
        help="source or assembled release tree to validate (default: repository root)",
    )
    parser.add_argument(
        "--scan-release-tree",
        action="store_true",
        help="also reject runtime artifacts, private paths, secrets, and manifest drift",
    )
    args = parser.parse_args()
    root = Path(os.path.abspath(os.fspath(args.root)))
    try:
        root_mode = root.lstat().st_mode
    except OSError:
        root_mode = 0
    if not stat.S_ISDIR(root_mode):
        print(f"community release validation: FAIL (root is not a directory: {root})")
        return 2

    failures = validate(root, scan_release_tree=args.scan_release_tree)
    if failures:
        print(f"community release validation: FAIL ({len(failures)} issue(s))")
        for item in failures:
            print(f"- {item}")
        return 1
    print(f"community release validation: PASS ({len(REQUIRED_FILES)} files checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
