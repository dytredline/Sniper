import os
import sys
import tempfile
import hashlib
import time
from pathlib import Path

from nuclei_bounded_process import BoundedNucleiProcess


def test_bounded_process_completed_with_report_sha256():
    """Test successful execution of a fake local script that writes 'ok\n', verify report hash and state."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        report_path = tmp_path / "report.json"

        # Create report file with mode 0600
        report_path.touch(mode=0o600, exist_ok=True)

        # Create fake local Python script that writes b'ok\n' and exits 0
        # Use explicit bytes without embedded newline in string literal
        script_path = tmp_path / "fake_script.py"
        script_content = '''import sys
Path = __import__("pathlib").Path
Path(sys.argv[1]).write_bytes(bytes([111, 107, 10]))
exit(0)
'''
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        # Prepare argv
        argv = [str(sys.executable), str(script_path), str(report_path)]

        # Run the bounded process
        proc = BoundedNucleiProcess(timeout_seconds=5.0, max_report_bytes=1_000_000)
        result = proc.start(argv, report_path)
        assert result["state"] in ("pending", "running")

        # Wait until completed (deadline ≤5s)
        deadline = time.monotonic() + 5.0
        while True:
            status = proc.status()
            if status["state"] in ("completed", "failed", "cancelled"):
                break
            if time.monotonic() > deadline:
                proc.cancel()
                assert False, "Timeout waiting for completion"
            time.sleep(0.1)

        final = proc.status()
        assert final["state"] == "completed"
        # Compute SHA256 of exact expected bytes 'ok\n'
        expected_sha256 = hashlib.sha256(b"ok\n").hexdigest()
        assert final["report_sha256"] == expected_sha256
        assert final["elapsed_seconds"] >= 0

        # Second start should be rejected
        try:
            proc.start(argv, report_path)
            assert False, "Second start should raise RuntimeError"
        except RuntimeError as e:
            assert "zaten başlatıldı" in str(e).lower()


def test_bounded_process_cancelled_before_termination():
    """Test cancellation of a sleeper process with marker file to ensure it started."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        report_path = tmp_path / "report.json"
        marker_path = tmp_path / "started.flag"
        report_path.touch(mode=0o600, exist_ok=True)

        # Create sleeper script with marker: writes marker, sleeps 5 seconds
        script_path = tmp_path / "sleeper_with_marker.py"
        script_content = """import sys, time
with open(sys.argv[1], 'w') as f:
    f.write('started')
time.sleep(5)
"""
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        argv = [str(sys.executable), str(script_path), str(marker_path)]

        proc = BoundedNucleiProcess(timeout_seconds=30.0, max_report_bytes=1_000_000)
        result = proc.start(argv, report_path)
        assert result["state"] in ("pending", "running")

        # Wait up to 2 seconds for the marker file to be written
        deadline = time.monotonic() + 2.0
        while not marker_path.exists():
            if time.monotonic() > deadline:
                assert False, "Timeout waiting for sleeper to start"
            time.sleep(0.05)

        # Cancel after ensuring the child started
        cancel_result = proc.cancel()
        assert cancel_result["state"] == "cancelled"

        # Wait a bit to let cancel complete
        time.sleep(0.5)

        final_status = proc.status()
        assert final_status["state"] == "cancelled"
        assert "elapsed_seconds" in final_status
        assert final_status["elapsed_seconds"] >= 0
