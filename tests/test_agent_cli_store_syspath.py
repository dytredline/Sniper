import sys
import unittest
import tempfile
from pathlib import Path

import cli_reports


class TestAgentCliStoreSyspath(unittest.TestCase):
    def setUp(self):
        # Preserve the original sys.path for later restoration.
        self._original_path = list(sys.path)
        # Create a temporary directory for the database files.
        self._temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._temp_dir.name)

    def tearDown(self):
        # Restore sys.path to its original state to avoid side effects.
        sys.path[:] = self._original_path
        # Clean up the temporary directory.
        self._temp_dir.cleanup()

    def test_store_does_not_duplicate_syspath(self):
        """Calling ``cli_reports._store`` repeatedly should not insert
        ``APP_DIR`` into ``sys.path`` more than once.

        The function inserts ``APP_DIR`` only if it is not already present.
        This test ensures that behaviour works as expected and that the
        ``sys.path`` list is restored after the test.
        """
        app_dir = str(cli_reports.APP_DIR)
        # Ensure the path is not present before the first call.
        while app_dir in sys.path:
            sys.path.remove(app_dir)
        self.assertNotIn(app_dir, sys.path)
        # First invocation of _store.
        _ = cli_reports._store(self.tmp_path / "first.db")
        # Second invocation of _store should not duplicate the entry.
        _ = cli_reports._store(self.tmp_path / "second.db")
        # Verify that APP_DIR appears exactly once.
        self.assertEqual(sys.path.count(app_dir), 1)

if __name__ == "__main__":
    unittest.main()
