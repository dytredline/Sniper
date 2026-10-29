import hashlib
import json
import socketserver
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nmap_active import normalize_authorized_nmap_target, run_authorized_nmap_scan
from nuclei_broad_jobs import BroadNucleiJobs, normalize_authorized_http_origin


NMAP = Path.home() / ".local/share/sniper/tools/nmap-7.94/bin/nmap"
NUCLEI = Path("/home/community-user/.local/state/sniper-tool-runtimes/nuclei-3.11.1/nuclei")
CATALOG = Path("/home/community-user/.local/state/sniper-tool-runtimes/nuclei-templates-v10.5.0")


def _prepare_nuclei_catalog(temp_root: Path) -> dict[str, object]:
    pin_file = CATALOG / "SNIPER-HTTP-CATALOG-PIN-v2.json"
    idx_file = CATALOG / "SNIPER-HTTP-ID-INDEX.json"
    if pin_file.is_file() and idx_file.is_file():
        return {
            "catalog_root": CATALOG,
            "pin_path": pin_file,
            "expected_pin_sha256": "0458128285de1a22a9b5bbdf247323451663644607bdddf3252ff2b6e31f099e",
            "expected_index_sha256": "c6e3589ad085a9b15529b49fe8b6397b36e9c2b77461f603e1f7f3787a31856a",
            "expected_template_count": 11655,
            "mapping_sha256": "201335d35f4ebf4dee6b15fc879bacb6b24d41870168191bce3e613e523e05b6",
        }
    catalog_root = temp_root / "catalog"
    mapping_path = catalog_root / "http/technologies/wappalyzer-mapping.yml"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    (catalog_root / ".nuclei-ignore").write_text("", encoding="utf-8")
    mapping_bytes = b"fixture: fixture\n"
    mapping_path.write_bytes(mapping_bytes)
    mapping_sha = hashlib.sha256(mapping_bytes).hexdigest()

    templates = [
        (
            "http-missing-security-headers",
            "http/misconfiguration/http-missing-security-headers.yaml",
            (
                "id: http-missing-security-headers\n"
                "info:\n"
                "  name: HTTP Missing Security Headers\n"
                "  author: sniper-fixture\n"
                "  severity: info\n"
                "http:\n"
                "  - method: GET\n"
                "    path:\n"
                "      - \"{{BaseURL}}\"\n"
                "    matchers:\n"
                "      - type: status\n"
                "        status:\n"
                "          - 200\n"
            ).encode("utf-8"),
        ),
        (
            "robots-txt",
            "http/misconfiguration/robots-txt.yaml",
            (
                "id: robots-txt\n"
                "info:\n"
                "  name: Robots.txt Fixture\n"
                "  author: sniper-fixture\n"
                "  severity: info\n"
                "http:\n"
                "  - method: GET\n"
                "    path:\n"
                "      - \"{{BaseURL}}\"\n"
                "    matchers:\n"
                "      - type: word\n"
                "        words:\n"
                "          - fixture\n"
            ).encode("utf-8"),
        ),
        (
            "tech-detect",
            "http/technologies/tech-detect.yaml",
            (
                "id: tech-detect\n"
                "info:\n"
                "  name: Tech Detect Fixture\n"
                "  author: sniper-fixture\n"
                "  severity: info\n"
                "http:\n"
                "  - method: GET\n"
                "    path:\n"
                "      - \"{{BaseURL}}\"\n"
                "    matchers:\n"
                "      - type: word\n"
                "        part: header\n"
                "        words:\n"
                "          - r48-loopback-fixture\n"
            ).encode("utf-8"),
        ),
    ]
    paths_and_hashes: list[list[str]] = []
    ids_paths_hashes: list[list[str]] = []
    for tid, rel, raw in templates:
        target = catalog_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        paths_and_hashes.append([rel, digest])
        ids_paths_hashes.append([tid, rel, digest])
    paths_and_hashes.sort(key=lambda item: item[0])
    ids_paths_hashes.sort(key=lambda item: item[0])

    pin_doc = {
        "version": "v10.5.0",
        "scope": "http",
        "count": len(paths_and_hashes),
        "sha256": "0" * 64,
        "paths_and_hashes": paths_and_hashes,
    }
    pin_bytes = json.dumps(pin_doc, sort_keys=True).encode("utf-8")
    pin_out = catalog_root / "SNIPER-HTTP-CATALOG-PIN-v2.json"
    pin_out.write_bytes(pin_bytes)

    idx_doc = {
        "version": "v10.5.0",
        "count": len(ids_paths_hashes),
        "sha256": "0" * 64,
        "ids_paths_hashes": ids_paths_hashes,
    }
    idx_bytes = json.dumps(idx_doc, sort_keys=True).encode("utf-8")
    idx_out = catalog_root / "SNIPER-HTTP-ID-INDEX.json"
    idx_out.write_bytes(idx_bytes)

    return {
        "catalog_root": catalog_root,
        "pin_path": pin_out,
        "expected_pin_sha256": hashlib.sha256(pin_bytes).hexdigest(),
        "expected_index_sha256": hashlib.sha256(idx_bytes).hexdigest(),
        "expected_template_count": len(paths_and_hashes),
        "mapping_sha256": mapping_sha,
    }


class TargetNormalizationTests(unittest.TestCase):
    def test_nmap_host_and_ip_are_canonical_and_urls_or_ports_are_rejected(self):
        self.assertEqual(normalize_authorized_nmap_target(" Example.COM. "), "example.com")
        self.assertEqual(normalize_authorized_nmap_target("2001:0db8::1"), "2001:db8::1")
        for invalid in ("https://example.com", "example.com:443", "a/b", "[::1]"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_authorized_nmap_target(invalid)

    def test_nuclei_accepts_only_a_canonical_http_origin(self):
        self.assertEqual(normalize_authorized_http_origin(" HTTP://Example.COM.:80/ "), "http://example.com")
        self.assertEqual(normalize_authorized_http_origin("https://[::1]:8443"), "https://[::1]:8443")
        for invalid in (
            "example.com", "ftp://example.com", "https://user@example.com", "https://example.com/a",
            "https://example.com/?x=1", "https://example.com/#fragment", "https://bad_host.example",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_authorized_http_origin(invalid)


@unittest.skipUnless(NMAP.is_file(), "pinned Nmap runtime is not installed")
class RealNmapDirectTargetRuntimeTests(unittest.TestCase):
    def test_fixed_default_profile_observes_a_loopback_tcp_fixture(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.recv(16)
                except ConnectionError:
                    pass

        fixture = None
        selected_port = None
        for port in (8080, 8443, 9200, 27017, 6379, 3306):
            try:
                fixture = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
                selected_port = port
                break
            except OSError:
                continue
        if fixture is None:
            self.skipTest("no fixed-profile loopback port is available")
        fixture.daemon_threads = True
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        try:
            result = run_authorized_nmap_scan("127.0.0.1", profile="default")
        finally:
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=3)
        self.assertEqual(result["profile"], "authorized-default-v1")
        self.assertIn(selected_port, result["open_ports"])
        self.assertEqual(result["open_port_count"], len(result["open_ports"]))
        self.assertRegex(result["report_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["target_sha256"], r"^[0-9a-f]{64}$")


@unittest.skipUnless(NUCLEI.is_file() and CATALOG.is_dir(), "pinned Nuclei runtime/catalog is not installed")
class RealNucleiDirectOriginRuntimeTests(unittest.TestCase):
    def test_fixed_catalog_profile_completes_against_loopback_http_fixture(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Server", "r48-loopback-fixture")
                self.end_headers()
                self.wfile.write(b"fixture")

            def log_message(self, *_args):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        httpd.daemon_threads = True
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
                root_dir = Path(directory)
                data_dir = root_dir / "data"
                data_dir.mkdir(mode=0o700)
                data_dir.chmod(0o700)
                cat_cfg = _prepare_nuclei_catalog(root_dir)
                jobs = BroadNucleiJobs(
                    data_dir=data_dir,
                    binary=NUCLEI,
                    binary_sha256="f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477",
                    **cat_cfg,
                )
                start = jobs.start_authorized_origin(f"http://127.0.0.1:{httpd.server_port}/", True)
                self.assertEqual(start["profile"], "authorized-origin-fixed-http-v1")
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    result = jobs.status(start["job_id"])
                    if result["state"] in {"completed", "failed", "cancelled"}:
                        break
                    time.sleep(0.1)
                else:
                    self.fail("Nuclei loopback job did not reach a terminal state")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=3)
        self.assertEqual(result["state"], "completed", result)
        self.assertGreaterEqual(result["record_count"], 0)
        self.assertRegex(result["report_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
