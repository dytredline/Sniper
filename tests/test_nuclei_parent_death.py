import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


def test_success_with_valid_args(tmp_path: Path) -> None:
    # Construct absolute wrapper path
    wrapper_path = Path(__file__).resolve().parents[1] / 'nuclei_parent_death.py'
    assert wrapper_path.exists(), 'wrapper must exist at expected path'

    # Create a fake executable Python script in tmp_path
    marker = tmp_path / 'marker_ok'
    fake_script = tmp_path / 'fake_executable.py'
    fake_script.write_text(f'#!/usr/bin/python3\nfrom pathlib import Path\nPath("{marker}").write_bytes(b"OK")\n')
    # Make executable
    st = fake_script.stat()
    fake_script.chmod(st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Run wrapper with valid args: [wrapper, str(os.getpid()), str(fake_script)]
    result = subprocess.run(
        [sys.executable, str(wrapper_path), str(os.getpid()), str(fake_script)],
        timeout=3,
        capture_output=True,
        text=True
    )

    # Expect success (returncode 0)
    assert result.returncode == 0, f'expected 0, got {result.returncode} (stderr: {result.stderr})'
    # Expect marker file written with exact bytes
    assert marker.exists(), 'marker file must exist'
    assert marker.read_bytes() == b'OK', 'marker content must be exactly b"OK"'


def test_malformed_pid_returns_nonzero(tmp_path: Path) -> None:
    wrapper_path = Path(__file__).resolve().parents[1] / 'nuclei_parent_death.py'
    fake_script = tmp_path / 'dummy.py'
    fake_script.touch()
    fake_script.chmod(0o700)

    for bad_pid in ['abc', '12.3', '00', '+123', '', ' 123']:
        result = subprocess.run(
            [sys.executable, str(wrapper_path), bad_pid, str(fake_script)],
            timeout=3,
            capture_output=True,
            text=True
        )
        assert result.returncode != 0, f'expected nonzero for bad_pid={bad_pid!r}, got {result.returncode}'


def test_zero_pid_returns_nonzero(tmp_path: Path) -> None:
    wrapper_path = Path(__file__).resolve().parents[1] / 'nuclei_parent_death.py'
    fake_script = tmp_path / 'dummy.py'
    fake_script.touch()
    fake_script.chmod(0o700)

    result = subprocess.run(
        [sys.executable, str(wrapper_path), '0', str(fake_script)],
        timeout=3,
        capture_output=True,
        text=True
    )
    assert result.returncode != 0, 'zero PID must return nonzero'


def test_negative_pid_returns_nonzero(tmp_path: Path) -> None:
    wrapper_path = Path(__file__).resolve().parents[1] / 'nuclei_parent_death.py'
    fake_script = tmp_path / 'dummy.py'
    fake_script.touch()
    fake_script.chmod(0o700)

    for bad_pid in ['-1', '-123']:
        result = subprocess.run(
            [sys.executable, str(wrapper_path), bad_pid, str(fake_script)],
            timeout=3,
            capture_output=True,
            text=True
        )
        assert result.returncode != 0, f'negative PID {bad_pid} must return nonzero'


def test_nonexistent_binary_returns_nonzero(tmp_path: Path) -> None:
    wrapper_path = Path(__file__).resolve().parents[1] / 'nuclei_parent_death.py'
    nonexistent = tmp_path / 'nonexistent_binary_12345'

    result = subprocess.run(
        [sys.executable, str(wrapper_path), str(os.getpid()), str(nonexistent)],
        timeout=3,
        capture_output=True,
        text=True
    )
    assert result.returncode != 0, 'nonexistent binary must return nonzero'


def test_relative_binary_path_returns_nonzero(tmp_path: Path) -> None:
    wrapper_path = Path(__file__).resolve().parents[1] / 'nuclei_parent_death.py'
    fake_script = tmp_path / 'relative.py'
    fake_script.touch()
    fake_script.chmod(0o700)

    rel_path = fake_script.name  # relative to cwd, not absolute

    result = subprocess.run(
        [sys.executable, str(wrapper_path), str(os.getpid()), rel_path],
        timeout=3,
        capture_output=True,
        text=True
    )
    assert result.returncode != 0, 'relative binary path must return nonzero'


def test_symlink_binary_returns_nonzero(tmp_path: Path) -> None:
    wrapper_path = Path(__file__).resolve().parents[1] / 'nuclei_parent_death.py'
    real_script = tmp_path / 'real_script.py'
    real_script.write_text('#!/usr/bin/env python3\nprint(1)')
    real_script.chmod(0o700)

    symlink_path = tmp_path / 'link_script.py'
    try:
        symlink_path.unlink()
    except FileNotFoundError:
        pass
    symlink_path.symlink_to(real_script)

    # Verify it's a symlink
    assert symlink_path.is_symlink(), 'test setup error: symlink not created'

    result = subprocess.run(
        [sys.executable, str(wrapper_path), str(os.getpid()), str(symlink_path)],
        timeout=3,
        capture_output=True,
        text=True
    )
    assert result.returncode != 0, 'symlink binary must return nonzero'
