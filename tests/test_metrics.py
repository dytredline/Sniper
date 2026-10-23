from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from exporter.metrics import Metrics  # noqa: E402


class MetricsTests(unittest.TestCase):
    def test_renders_prometheus_counters_histogram_and_gauges(self):
        metrics = Metrics()
        metrics.observe_request("GET", "/api/scans/scn_123456789/report.json", 200, 0.02)
        metrics.record_scan("completed")
        rendered = metrics.render(active_scans=2, loaded_plugins=1)
        self.assertIn("sniper_scans_active 2", rendered)
        self.assertIn("sniper_plugins_loaded 1", rendered)
        self.assertIn('status="200"', rendered)
        self.assertIn('route="/api/scans/:id/report.json"', rendered)
        self.assertIn('sniper_scans_total{status="completed"} 1', rendered)
        self.assertIn("sniper_http_request_duration_seconds_bucket", rendered)


if __name__ == "__main__":
    unittest.main()
