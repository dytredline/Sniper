from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest import mock


APP = Path(__file__).resolve().parents[1]
ASSIGNED_RUNTIME_SOURCES = (
    "cli_reports.py",
    "storage.py",
    "schemathesis_active.py",
    "zap_passive_active.py",
    "tool_runtime_readiness.py",
    "server.py",
    "static/gitleaks_filesystem.js",
    "static/npm_audit_active.js",
    "static/osv_local_active.js",
    "static/semgrep_evidence_link.js",
    "static/semgrep_local.js",
)


class RuntimeSourcePortabilityTests(unittest.TestCase):
    def test_assigned_runtime_sources_do_not_embed_build_host_or_workspace(self):
        for relative in ASSIGNED_RUNTIME_SOURCES:
            source = (APP / relative).read_text(encoding="utf-8")
            with self.subTest(relative=relative):
                self.assertIsNone(re.search(r"/home/(?!community-user(?:/|\b))[A-Za-z0-9_.-]+", source))
                self.assertNotIn("community-build", source)

    def test_live_roots_follow_the_effective_user_home(self):
        portable_home = Path("/var/lib/sniper-portable-test")
        script = (
            "import json, cli_reports, storage; "
            "print(json.dumps({"
            "'live_dir': str(cli_reports.LIVE_DIR), "
            "'data_dir': str(cli_reports.DATA_DIR), "
            "'live_root': str(storage.LIVE_SNIPER_ROOT)}))"
        )
        env = dict(os.environ, HOME=str(portable_home), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=APP, env=env,
            text=True, capture_output=True, timeout=20, check=True,
        )
        payload = json.loads(result.stdout)
        root = portable_home / ".local" / "share" / "sniper"
        self.assertEqual(payload, {
            "live_dir": str(root / "app"),
            "data_dir": str(root / "data"),
            "live_root": str(root),
        })

    def test_pinned_runtimes_accept_explicit_portable_locations(self):
        script = (
            "import json, schemathesis_active, zap_passive_active; "
            "print(json.dumps({"
            "'schemathesis': str(schemathesis_active.ST_EXECUTABLE), "
            "'zap': str(zap_passive_active.RUNTIME)}))"
        )
        env = dict(
            os.environ,
            HOME="/var/lib/sniper-portable-test",
            SNIPER_SCHEMATHESIS_BINARY="/opt/sniper/runtimes/schemathesis/bin/st",
            SNIPER_ZAP_RUNTIME_DIR="/opt/sniper/runtimes/zap",
            PYTHONDONTWRITEBYTECODE="1",
        )
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=APP, env=env,
            text=True, capture_output=True, timeout=20, check=True,
        )
        self.assertEqual(json.loads(result.stdout), {
            "schemathesis": "/opt/sniper/runtimes/schemathesis/bin/st",
            "zap": "/opt/sniper/runtimes/zap",
        })

    def test_broad_nuclei_uses_configured_binary_and_catalog(self):
        import server

        binary = "/opt/sniper/runtimes/nuclei/nuclei"
        catalog = "/opt/sniper/runtimes/nuclei-templates"
        sentinel = object()
        previous = server.BROAD_NUCLEI_JOBS
        server.BROAD_NUCLEI_JOBS = None
        try:
            with mock.patch.dict(os.environ, {
                "SNIPER_NUCLEI_BINARY": binary,
                "SNIPER_NUCLEI_CATALOG_DIR": catalog,
            }), mock.patch.object(server, "BroadNucleiJobs", return_value=sentinel) as factory:
                self.assertIs(server.get_broad_nuclei_jobs(), sentinel)
            kwargs = factory.call_args.kwargs
            self.assertEqual(kwargs["binary"], Path(binary))
            self.assertEqual(kwargs["catalog_root"], Path(catalog))
            self.assertEqual(kwargs["pin_path"], Path(catalog) / "SNIPER-HTTP-CATALOG-PIN-v2.json")
        finally:
            server.BROAD_NUCLEI_JOBS = previous

    def test_readiness_checks_the_same_configured_nuclei_paths(self):
        import nuclei_active
        import tool_runtime_readiness as readiness

        binary = "/opt/sniper/runtimes/nuclei/nuclei"
        catalog = "/opt/sniper/runtimes/nuclei-templates"
        digests: list[str] = []
        directories: list[str] = []

        def digest(path, _expected):
            digests.append(str(path))
            return True

        def directory(path):
            directories.append(str(path))
            return True

        with mock.patch.dict(os.environ, {
            "SNIPER_NUCLEI_BINARY": binary,
            "SNIPER_NUCLEI_CATALOG_DIR": catalog,
        }), mock.patch.object(nuclei_active, "_trusted_binary"), \
             mock.patch.object(readiness, "_digest_matches", side_effect=digest), \
             mock.patch.object(readiness, "_directory", side_effect=directory):
            self.assertEqual(
                readiness._runtime_check("nuclei", readiness._NUCLEI_BROAD_ROUTE),
                (True, "binary_and_catalog_pin_found"),
            )
        self.assertIn(binary, digests)
        self.assertIn(str(Path(catalog) / "SNIPER-HTTP-CATALOG-PIN-v2.json"), digests)
        self.assertEqual(directories, [catalog])

    def test_index_runtime_home_metadata_is_attribute_escaped(self):
        import server

        with mock.patch.object(server.Path, "home", return_value=Path('/Users/a"b&c')):
            rendered = server._inject_local_home_config(b"<!doctype html><html><head><title>x</title></head></html>")
        self.assertIn(b'<meta name="sniper-local-home" content="/Users/a&quot;b&amp;c">', rendered)
        self.assertNotIn(b'/Users/a"b&c', rendered)


if __name__ == "__main__":
    unittest.main()
