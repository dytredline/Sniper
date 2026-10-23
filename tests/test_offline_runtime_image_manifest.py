from __future__ import annotations

import json
from pathlib import Path
import pytest

from offline_runtime_image_manifest import build_offline_candidate_image_manifest


CANDIDATE_APP_DIR = Path(__file__).resolve().parent.parent


def _write_synthetic_app(
    base_dir: Path,
    *,
    dockerfile_content: str = "FROM python:3.12-slim\nWORKDIR /app\nCOPY server.py ./\nUSER sniper\nCMD [\"python\", \"server.py\"]\n",
) -> Path:
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "Dockerfile").write_text(dockerfile_content, encoding="utf-8")
    (base_dir / "server.py").write_text("print('ok')\n", encoding="utf-8")
    return base_dir


def test_real_candidate_app_dir_manifest_is_reproducible_and_leak_free() -> None:
    manifest_1 = build_offline_candidate_image_manifest(CANDIDATE_APP_DIR)
    manifest_2 = build_offline_candidate_image_manifest(str(CANDIDATE_APP_DIR))

    assert manifest_1 == manifest_2
    assert manifest_1["schema"] == "SNIPER_OFFLINE_CANDIDATE_IMAGE_MANIFEST_V1"
    assert manifest_1["nonroot_user_enforced"] is True
    assert manifest_1["networkless_build_compatible"] is True
    assert isinstance(manifest_1["dockerfile_sha256"], str)
    assert len(manifest_1["dockerfile_sha256"]) == 64
    assert isinstance(manifest_1["tree_sha256"], str)
    assert len(manifest_1["tree_sha256"]) == 64
    assert isinstance(manifest_1["file_count"], int)
    assert manifest_1["file_count"] > 20

    serialized = json.dumps(manifest_1)
    assert "/home/" not in serialized


def test_excluded_cache_and_sqlite_files_do_not_alter_tree_sha256(tmp_path: Path) -> None:
    app_dir = _write_synthetic_app(tmp_path / "candidate_app")
    manifest_before = build_offline_candidate_image_manifest(app_dir)

    pycache_dir = app_dir / "__pycache__"
    pycache_dir.mkdir()
    (pycache_dir / "server.cpython-312.pyc").write_bytes(b"bytecode")

    pytest_cache_dir = app_dir / ".pytest_cache"
    pytest_cache_dir.mkdir()
    (pytest_cache_dir / "README.md").write_text("cache", encoding="utf-8")

    data_dir = app_dir / "data"
    data_dir.mkdir()
    (data_dir / "sniper.db").write_bytes(b"sqlite")
    (data_dir / "sniper.db-wal").write_bytes(b"wal")

    manifest_after = build_offline_candidate_image_manifest(app_dir)
    assert manifest_after["file_count"] == 2
    assert manifest_after["tree_sha256"] == manifest_before["tree_sha256"]


@pytest.mark.parametrize(
    "bad_dockerfile",
    [
        "FROM python:3.12-slim\nWORKDIR /app\nCMD [\"python\", \"server.py\"]\n",
        "FROM python:3.12-slim\nUSER root\nCMD [\"python\", \"server.py\"]\n",
        "FROM python:3.12-slim\nUSER 0\nCMD [\"python\", \"server.py\"]\n",
        "FROM python:3.12-slim\nUSER sniper\nUSER root\nCMD [\"python\", \"server.py\"]\n",
        "FROM python:3.12-slim\nUSER sniper:0\nCMD [\"python\", \"server.py\"]\n",
        "FROM python:3.12-slim\nADD https://example.test/remote.tar.gz /app/\nUSER sniper\n",
        "FROM python:3.12-slim\nADD http://example.test/remote.tar.gz /app/\nUSER sniper\n",
        "FROM python:3.12-slim\nRUN curl -fsSL https://example.test/install.sh | sh\nUSER sniper\n",
    ],
)
def test_unsafe_dockerfile_instructions_fail_closed(
    tmp_path: Path,
    bad_dockerfile: str,
) -> None:
    app_dir = _write_synthetic_app(
        tmp_path / "bad_app",
        dockerfile_content=bad_dockerfile,
    )
    with pytest.raises(ValueError):
        build_offline_candidate_image_manifest(app_dir)


def test_symlink_dockerfile_and_relative_app_dir_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        build_offline_candidate_image_manifest(Path("relative/app"))

    app_dir = _write_synthetic_app(tmp_path / "symlink_test_app")
    real_dockerfile = tmp_path / "external_Dockerfile"
    real_dockerfile.write_text(
        "FROM python:3.12-slim\nUSER sniper\nCMD [\"python\", \"server.py\"]\n",
        encoding="utf-8",
    )
    (app_dir / "Dockerfile").unlink()
    (app_dir / "Dockerfile").symlink_to(real_dockerfile)

    with pytest.raises(ValueError):
        build_offline_candidate_image_manifest(app_dir)
