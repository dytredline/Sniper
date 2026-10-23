from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import server


class _CapturingStore:
    def __init__(self) -> None:
        self.project_path: str | None = None

    def save_dependency_sbom(self, project_path: str, document: dict) -> dict:
        self.project_path = project_path
        return {"project_path": project_path, "component_count": len(document.get("components", []))}


class CodeQLServerUiOpenAlertTests(unittest.TestCase):
    @staticmethod
    def handler(path: str, *, command: str = "GET") -> server.SniperHandler:
        handler = server.SniperHandler.__new__(server.SniperHandler)
        handler.command = command
        handler.path = path
        handler.request_version = "HTTP/1.1"
        handler.requestline = f"{command} {path} HTTP/1.1"
        handler.wfile = io.BytesIO()
        handler.log_request = lambda *_args: None
        return handler

    def test_alert_303_sbom_route_pins_validated_project_before_generation(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as allowed_temp, tempfile.TemporaryDirectory() as outside_temp:
            allowed = Path(allowed_temp)
            project = allowed / "project"
            project.mkdir()
            (project / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
            outside = Path(outside_temp)
            link = allowed / "selected"
            link.symlink_to(project, target_is_directory=True)
            store = _CapturingStore()
            real_generate = server.generate_cyclonedx_sbom
            swapped = False

            def generate_then_swap(project_path: str) -> dict:
                nonlocal swapped
                document = real_generate(project_path, allowed_roots=(allowed.resolve(),))
                link.unlink()
                link.symlink_to(outside, target_is_directory=True)
                swapped = True
                return document

            handler = self.handler("/api/dependency-security/sbom", command="POST")
            handler._scan_scope_active = True
            with mock.patch.object(server, "STORE", store), mock.patch.object(
                server, "generate_cyclonedx_sbom", side_effect=generate_then_swap
            ):
                handler._dispatch_post({"project_path": str(link)})

            self.assertTrue(swapped, "test must replace the submitted symlink after validation")
            self.assertEqual(store.project_path, str(project.resolve()))
            self.assertNotEqual(store.project_path, str(outside.resolve()))
            self.assertEqual(json.loads(handler.wfile.getvalue().split(b"\r\n\r\n", 1)[1])["project_path"], str(project.resolve()))

    def test_alerts_304_305_static_read_rejects_intermediate_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as static_temp, tempfile.TemporaryDirectory() as outside_temp:
            static_root = Path(static_temp)
            selected = static_root / "selected"
            selected.mkdir()
            candidate = selected / "asset.txt"
            candidate.write_text("trusted", encoding="utf-8")
            moved = static_root / "selected-original"
            outside = Path(outside_temp)
            (outside / "asset.txt").write_text("outside-sentinel", encoding="utf-8")
            real_is_file = Path.is_file
            swapped = False

            def is_file_then_swap(path: Path) -> bool:
                nonlocal swapped
                result = real_is_file(path)
                if not swapped and path == candidate and result:
                    selected.rename(moved)
                    selected.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return result

            handler = self.handler("/selected/asset.txt")
            with mock.patch.object(server, "STATIC_DIR", static_root), mock.patch.object(
                server.ui_assets, "bundle_asset", return_value=None
            ), mock.patch.object(Path, "is_file", is_file_then_swap):
                handler._static("/selected/asset.txt")

            raw = handler.wfile.getvalue()
            self.assertTrue(swapped, "test must replace the checked parent before descriptor-based open")
            self.assertIn(b" 404 ", raw.split(b"\r\n", 1)[0])
            self.assertNotIn(b"outside-sentinel", raw)


if __name__ == "__main__":
    unittest.main()
