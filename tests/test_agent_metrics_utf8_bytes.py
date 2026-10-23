import importlib
import re
from unittest.mock import patch


def test_check_metrics_utf8_byte_length(capsys):
    # Dynamically import the healthcheck module to ensure isolation
    healthcheck = importlib.import_module("healthcheck")

    # Payload contains Unicode characters that occupy more bytes in UTF-8 than code points
    payload = "sniper_metric 1\nunicode_line ñøß\n"
    expected_byte_len = len(payload.encode("utf-8"))

    # Patch http_get to return the payload with a 200 status
    with patch.object(healthcheck, "http_get", return_value=(200, payload)):
        outcome = healthcheck.check_metrics()
        # The check should PASS because the payload contains a line starting with "sniper_"
        assert outcome.status == "PASS"

    # Capture printed output from report
    captured = capsys.readouterr()
    # The report line looks like "[PASS] Metrikler: HTTP 200; içerik={bytes} bayt"
    printed = captured.out.strip()
    match = re.search(r"içerik=(\d+) bayt", printed)
    assert match is not None, f"Could not find byte count in output: {printed}"
    reported_bytes = int(match.group(1))
    assert reported_bytes == expected_byte_len, f"Reported byte count {reported_bytes} != expected {expected_byte_len}"
