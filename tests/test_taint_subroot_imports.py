"""Python taint: alt kaynak kökünden (app/, backend/) çalışan projelerde mutlak içe aktarma çözümü.

``app/apis/admin/utils.py`` dosyası ``from apis.admin.utils import f`` ile içe aktarılabilir; tam ad önceliklidir
ve birden çok modüle uyan takma ad kullanılmaz."""
from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_flow as tf  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _flows(files):
    results = tf._analyze_python_files_uncached({k: _src(v) for k, v in files.items()}, None, frozenset())
    return {k: sorted((f.sink_kind, f.line) for f in v.flows if f.source_label == "request") for k, v in results.items()}


ROUTE = """
    from fastapi import APIRouter
    from apis.admin.utils import run_df
    router = APIRouter()

    @router.get("/admin/disk")
    def disk(parameters: str = ""):
        return run_df(parameters)
"""

SINK = """
    import subprocess

    def run_df(parameters):
        return subprocess.run("df -h " + parameters, shell=True)
"""


class SubrootImportTests(unittest.TestCase):
    def test_absolute_import_from_subroot_resolves(self):
        flows = _flows({"app/apis/admin/routes.py": ROUTE, "app/apis/admin/utils.py": SINK})
        self.assertEqual(flows["app/apis/admin/utils.py"], [("command", 4)])

    def test_full_name_wins_over_alias(self):
        safe = """
            def run_df(parameters):
                return parameters
        """
        flows = _flows({
            "app/apis/admin/routes.py": ROUTE,
            "app/apis/admin/utils.py": SINK,
            # Tam adı "apis.admin.utils" olan modül takma addan önce gelir.
            "apis/admin/utils.py": safe,
        })
        self.assertEqual(flows["app/apis/admin/utils.py"], [])

    def test_ambiguous_alias_is_not_used(self):
        flows = _flows({
            "app/apis/admin/routes.py": ROUTE,
            "app/apis/admin/utils.py": SINK,
            "other/apis/admin/utils.py": SINK,
        })
        self.assertEqual(flows["app/apis/admin/utils.py"], [])
        self.assertEqual(flows["other/apis/admin/utils.py"], [])


if __name__ == "__main__":
    unittest.main()
