from __future__ import annotations

import hashlib
import json
import pytest

from secret_bundle_validator import validate_bounded_secret_scan_bundle


def test_valid_multi_file_bundle_manifest_and_canonical_sha256() -> None:
    files_a = [
        {"relative_path": "src/config.py", "content": "API_TIMEOUT = 10\n"},
        {"relative_path": "deploy/env.example", "content": "SERVICE_MODE=local\n"},
    ]
    manifest = validate_bounded_secret_scan_bundle(files_a)

    assert manifest["format"] == "secret-scan-bundle-manifest-v1"
    assert manifest["scope"] == "explicit_in_memory_bundle_only"
    assert manifest["file_count"] == 2

    c1 = b"API_TIMEOUT = 10\n"
    c2 = b"SERVICE_MODE=local\n"
    assert manifest["total_bytes"] == len(c1) + len(c2)

    expected_files = [
        {
            "relative_path": "src/config.py",
            "size_bytes": len(c1),
            "sha256": hashlib.sha256(c1).hexdigest(),
        },
        {
            "relative_path": "deploy/env.example",
            "size_bytes": len(c2),
            "sha256": hashlib.sha256(c2).hexdigest(),
        },
    ]
    assert manifest["files"] == expected_files

    expected_canonical = json.dumps(
        {
            "format": "secret-scan-bundle-manifest-v1",
            "scope": "explicit_in_memory_bundle_only",
            "file_count": 2,
            "total_bytes": len(c1) + len(c2),
            "files": sorted(expected_files, key=lambda item: item["relative_path"]),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    expected_bundle_sha = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest()
    assert manifest["bundle_sha256"] == expected_bundle_sha

    # Canonical bundle_sha256 is deterministic regardless of input file ordering
    manifest_reordered = validate_bounded_secret_scan_bundle(list(reversed(files_a)))
    assert manifest_reordered["bundle_sha256"] == expected_bundle_sha


@pytest.mark.parametrize(
    "bad_path",
    [
        "../secret",
        "a/../../secret.txt",
        "./local.env",
        "/etc/passwd",
        "/home/community-user/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "C:/Users/admin/.env",
        "subdir\\secret.key",
        "secret\x00.txt",
        ".git/config",
        ".git/hooks/pre-commit",
        "nested/.git/HEAD",
        ".gitleaks.toml",
        "sub/.gitleaksignore",
        "trailing/slash/",
        "double//slash.txt",
        "",
        "   ",
    ],
)
def test_rejects_unsafe_or_out_of_scope_paths(bad_path: str) -> None:
    with pytest.raises(ValueError):
        validate_bounded_secret_scan_bundle(
            [{"relative_path": bad_path, "content": "data"}]
        )


def test_rejects_duplicate_relative_paths() -> None:
    with pytest.raises(ValueError, match="Yinelenen"):
        validate_bounded_secret_scan_bundle(
            [
                {"relative_path": "app/settings.py", "content": "A = 1\n"},
                {"relative_path": "app/settings.py", "content": "B = 2\n"},
            ]
        )


def test_rejects_empty_list_and_more_than_16_files() -> None:
    with pytest.raises(ValueError):
        validate_bounded_secret_scan_bundle([])

    too_many = [
        {"relative_path": f"dir/file_{i}.txt", "content": "ok"}
        for i in range(17)
    ]
    with pytest.raises(ValueError):
        validate_bounded_secret_scan_bundle(too_many)


def test_rejects_oversized_file_and_total_bundle_bytes_and_nul_content() -> None:
    with pytest.raises(ValueError):
        validate_bounded_secret_scan_bundle(
            [{"relative_path": "big.txt", "content": "a" * 65_537}]
        )

    # 5 files * 60_000 bytes = 300_000 bytes (> 262_144 total limit, each <= 65_536)
    with pytest.raises(ValueError):
        validate_bounded_secret_scan_bundle(
            [
                {"relative_path": f"chunk_{i}.txt", "content": "b" * 60_000}
                for i in range(5)
            ]
        )

    with pytest.raises(ValueError):
        validate_bounded_secret_scan_bundle(
            [{"relative_path": "binary.txt", "content": "abc\x00def"}]
        )
