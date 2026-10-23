import json
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest


def test_spawn_failure_leads_to_terminal_failed_state():
    """Test that Popen-raised OSError during process spawn leads to terminal failed state with stable error code."""
    sys.path.insert(0, str(Path.cwd()))
    import importlib
    nuclei_module = importlib.import_module("nuclei_bounded_process")

    # Save original Popen
    original_popen = nuclei_module.Popen

    # Mock Popen to raise OSError (simulating spawn failure)
    def failing_popen(*args, **kwargs):
        raise OSError("spawn_failed_synthetic")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        report_path = tmp_path / "report.json"
        report_path.touch(mode=0o600, exist_ok=True)

        process = nuclei_module.BoundedNucleiProcess(timeout_seconds=5.0)

        # Monkeypatch Popen
        with patch.object(nuclei_module, "Popen", failing_popen):
            result = process.start([str(sys.executable), "--version"], report_path)
            # start() may return pending, running, or already failed — do NOT use its result for final assertions
            assert result["state"] in ("pending", "running", "failed")

            # Poll status() to wait for terminal state; only status() includes error_code
            deadline = time.monotonic() + 2.0
            final_status = None
            while time.monotonic() < deadline:
                status = process.status()
                if status["state"] in ("failed", "completed", "cancelled"):
                    final_status = status
                    break
                time.sleep(0.05)
            else:
                pytest.fail("Timeout waiting for terminal state on spawn failure")

            assert final_status["state"] == "failed"
            assert "error_code" in final_status
            # Only assert stable non-sensitive code — do NOT leak raw error text
            assert final_status["error_code"] in ("spawn_failed", "spawn_error")

            # Restore Popen to avoid side effects
            nuclei_module.Popen = original_popen
