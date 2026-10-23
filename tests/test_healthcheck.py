import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class HealthcheckConfigurationTests(unittest.TestCase):
    def test_uses_service_data_directory_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(__file__).resolve().parents[1] / "healthcheck.py"
            spec = importlib.util.spec_from_file_location("healthcheck_under_test", module_path)
            module = importlib.util.module_from_spec(spec)
            with patch.dict(os.environ, {"SNIPER_DATA_DIR": directory}):
                spec.loader.exec_module(module)
            self.assertEqual(module.DB_PATH, Path(directory).resolve() / "sniper.db")


    def test_candidate_checkout_defaults_to_live_database(self):
        module_path = Path(__file__).resolve().parents[1] / "healthcheck.py"
        spec = importlib.util.spec_from_file_location("healthcheck_default_under_test", module_path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {}, clear=True):
            spec.loader.exec_module(module)
            expected = Path.home() / ".local/share/sniper/data/sniper.db"
        self.assertEqual(module.DB_PATH, expected.resolve())


if __name__ == "__main__":
    unittest.main()
