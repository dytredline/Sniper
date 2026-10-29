from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import asan_project_proof
import server
from storage import Store


class AsanProjectProofTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("gcc") is None or shutil.which("bwrap") is None:
            self.skipTest("gcc veya bwrap yok")
        probe = subprocess.run(
            ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "/bin/true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if probe.returncode != 0:
            self.skipTest("bwrap userns bu çekirdekte kısıtlı")
        try:
            with asan_project_proof.tool_sandbox.open_bwrap():
                pass
        except asan_project_proof.tool_sandbox.SandboxUnavailable:
            self.skipTest("sabitlenmiş bwrap ikilisi yapılandırılmamış")
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        source = self.root / "uaf.c"
        source.write_text("""#include <stdlib.h>
volatile int sink;
int main(void) { int *p = malloc(sizeof(int)); if (!p) return 2; *p = 7; free(p); sink = *p; return 0; }
""")
        self.binary = self.root / "uaf-proof"
        subprocess.run(
            ["/usr/bin/gcc", "-O0", "-g0", "-fsanitize=address", "-fno-omit-frame-pointer",
             str(source), "-o", str(self.binary)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
        )
        self.binary.chmod(0o700)
        self.store = Store(Path(self.temp.name) / "data" / "sniper.db")
        self.audit = self.store.create_project_audit({
            "created_at": "2026-10-21T16:00:00Z", "project_path": str(self.root),
            "project_name": "project", "score": 50, "grade": "C", "file_count": 1,
            "bytes_scanned": source.stat().st_size,
            "findings": [{"title": "Use after free", "category": "memory_safety", "severity": "critical",
                          "reference": "CWE-416", "file": "uaf.c", "line": 3,
                          "memory_safety": {"kind": "uaf", "engine": "sniper-memsafety"}}],
        })

    def test_prebuilt_instrumented_elf_runs_without_arguments_in_networkless_sandbox(self) -> None:
        proof = asan_project_proof.run(
            self.store, self.audit["id"], 0, binary_relpath="uaf-proof", confirm_local=True,
        )
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual(proof["expected_error_class"], "heap-use-after-free")
        self.assertEqual(proof["observed_error_class"], "heap-use-after-free")
        self.assertTrue(proof["asan_error"])
        self.assertFalse(proof["network_available"])
        self.assertEqual(proof["argument_count"], 0)
        encoded = json.dumps(proof)
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn("stderr", encoded)
        stored = self.store.get_project_audit(self.audit["id"])["findings"][0]["runtime_proofs"][0]
        self.assertEqual(stored["proof_type"], "asan_prebuilt_binary")

    def test_scripts_symlinks_uninstrumented_and_wrong_findings_are_rejected_before_execution(self) -> None:
        script = self.root / "script"
        script.write_text("#!/bin/sh\necho should-not-run > marker\n")
        script.chmod(0o700)
        (self.root / "link").symlink_to(self.binary)
        plain = self.root / "plain"
        subprocess.run(["/usr/bin/gcc", str(self.root / "uaf.c"), "-o", str(plain)], check=True, timeout=20)
        plain.chmod(0o700)
        wrong = self.store.create_project_audit({
            "created_at": "2026-10-21T16:00:00Z", "project_path": str(self.root), "project_name": "project",
            "score": 50, "grade": "C", "file_count": 1, "bytes_scanned": 1,
            "findings": [{"title": "SQLi", "category": "data_flow", "severity": "high",
                          "reference": "CWE-89", "file": "x.c", "line": 1}],
        })
        for audit_id, relative in ((self.audit["id"], "script"), (self.audit["id"], "link"),
                                   (self.audit["id"], "plain"), (wrong["id"], "uaf-proof")):
            with self.subTest(relative=relative), self.assertRaises(asan_project_proof.AsanProjectProofError):
                asan_project_proof.run(
                    self.store, audit_id, 0, binary_relpath=relative, confirm_local=True,
                )
        self.assertFalse((self.root / "marker").exists())

    def test_exact_finding_source_is_compiled_with_fixed_profile_then_run_in_sandbox(self) -> None:
        with self.store._connect() as db:
            self.assertIsNone(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'project_asan_source_proofs'"
            ).fetchone())
        self.store.get_project_audit(self.audit["id"])
        with self.store._connect() as db:
            self.assertIsNone(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'project_asan_source_proofs'"
            ).fetchone())
        proof = asan_project_proof.run_source(
            self.store, self.audit["id"], 0, source_relpath="uaf.c", confirm_local=True,
        )
        self.assertEqual(proof["proof_type"], "asan_source_fixed_profile")
        self.assertEqual(proof["build_profile"], "c11-asan-fixed-v1")
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual(proof["observed_error_class"], "heap-use-after-free")
        self.assertEqual(len(proof["source_sha256"]), 64)
        self.assertEqual(len(proof["compiler_sha256"]), 64)
        self.assertFalse(proof["network_available"])
        self.assertEqual(proof["argument_count"], 0)
        stored = self.store.get_project_audit(self.audit["id"])["findings"][0]["runtime_proofs"]
        self.assertTrue(any(item["proof_type"] == "asan_source_fixed_profile" for item in stored))
        with self.store._connect() as db:
            self.assertIsNotNone(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'project_asan_source_proofs'"
            ).fetchone())

    def test_source_profile_compiles_explicit_companion_without_build_scripts(self) -> None:
        (self.root / "helper.c").write_text("int helper(void) { return 1; }\n")
        proof = asan_project_proof.run_source(
            self.store, self.audit["id"], 0, source_relpath="uaf.c",
            companion_relpaths=["helper.c"], confirm_local=True,
        )
        self.assertEqual(proof["build_profile"], "c11-asan-fixed-multifile-v1")
        self.assertFalse(proof["project_build_scripts_executed"])

    def test_source_profile_rejects_nonfinding_source_and_symlink(self) -> None:
        (self.root / "other.c").write_text("int main(void) { return 0; }\n")
        (self.root / "source-link.c").symlink_to(self.root / "uaf.c")
        for relative in ("other.c", "source-link.c", "../uaf.c"):
            with self.subTest(relative=relative), self.assertRaises(asan_project_proof.AsanProjectProofError):
                asan_project_proof.run_source(
                    self.store, self.audit["id"], 0, source_relpath=relative, confirm_local=True,
                )

    def test_compile_database_entry_rebuilds_finding_in_private_snapshot_then_runs(self) -> None:
        (self.root / "uaf.c").write_text("""#include <stdlib.h>
#ifndef SNIPER_ENABLE_UAF
#error compile database define missing
#endif
volatile int sink;
int main(void) { int *p = malloc(sizeof(int)); if (!p) return 2; *p = 7; free(p); sink = *p; return 0; }
""")
        database = [{
            "directory": str(self.root),
            "file": "uaf.c",
            "arguments": ["gcc", "-std=c11", "-DSNIPER_ENABLE_UAF=1", "-c", "uaf.c",
                          "-o", "build/uaf.o"],
        }]
        (self.root / "compile_commands.json").write_text(json.dumps(database))

        proof = asan_project_proof.run_compile_database(
            self.store, self.audit["id"], 0, compile_commands_relpath="compile_commands.json",
            entry_index=0, confirm_local=True,
        )

        self.assertEqual(proof["proof_type"], "asan_compile_database_single_tu")
        self.assertEqual(proof["build_profile"], "compile-database-single-tu-v1")
        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual(proof["observed_error_class"], "heap-use-after-free")
        self.assertEqual(proof["snapshot_scope"], "bounded_c_cpp_sources_headers_only")
        self.assertFalse(proof["project_build_scripts_executed"])
        self.assertFalse(proof["network_available"])
        self.assertEqual(proof["argument_count"], 0)
        self.assertEqual(len(proof["compile_database_sha256"]), 64)
        self.assertEqual(len(proof["compile_entry_sha256"]), 64)
        self.assertEqual(len(proof["snapshot_sha256"]), 64)
        encoded = json.dumps(proof)
        self.assertNotIn(str(self.root), encoded)
        stored = self.store.get_project_audit(self.audit["id"])["findings"][0]["runtime_proofs"]
        self.assertTrue(any(item["proof_type"] == "asan_compile_database_single_tu" for item in stored))

    def test_compile_database_snapshot_skips_unrelated_empty_header(self) -> None:
        (self.root / "unused.h").write_bytes(b"")
        database = [{
            "directory": str(self.root),
            "file": "uaf.c",
            "arguments": ["gcc", "-std=c11", "-c", "uaf.c", "-o", "build/uaf.o"],
        }]
        (self.root / "compile_commands.json").write_text(json.dumps(database))

        proof = asan_project_proof.run_compile_database(
            self.store, self.audit["id"], 0, compile_commands_relpath="compile_commands.json",
            entry_index=0, confirm_local=True,
        )

        self.assertEqual(proof["verdict"], "confirmed")
        self.assertEqual(proof["snapshot_file_count"], 1)

    def test_compile_database_snapshot_still_rejects_empty_selected_translation_unit(self) -> None:
        (self.root / "uaf.c").write_bytes(b"")
        database = [{
            "directory": str(self.root),
            "file": "uaf.c",
            "arguments": ["gcc", "-std=c11", "-c", "uaf.c", "-o", "build/uaf.o"],
        }]
        (self.root / "compile_commands.json").write_text(json.dumps(database))

        with self.assertRaises(asan_project_proof.AsanProjectProofError):
            asan_project_proof.run_compile_database(
                self.store, self.audit["id"], 0, compile_commands_relpath="compile_commands.json",
                entry_index=0, confirm_local=True,
            )

    def test_compile_database_rejects_script_driver_and_does_not_execute_it(self) -> None:
        marker = self.root / "must-not-exist"
        cases = (
            ["/bin/sh", "-c", f"touch {marker}"],
            ["/usr/bin/gcc", "-fplugin=/tmp/untrusted.so", "-c", "uaf.c", "-o", "uaf.o"],
            ["/usr/bin/gcc", "-I/etc", "-c", "uaf.c", "-o", "uaf.o"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                database = [{"directory": str(self.root), "file": "uaf.c", "arguments": arguments}]
                (self.root / "compile_commands.json").write_text(json.dumps(database))
                with self.assertRaises(asan_project_proof.AsanProjectProofError):
                    asan_project_proof.run_compile_database(
                        self.store, self.audit["id"], 0, compile_commands_relpath="compile_commands.json",
                        entry_index=0, confirm_local=True,
                    )
        self.assertFalse(marker.exists())


class AsanProjectProofApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = server.SniperHandler.__new__(server.SniperHandler)
        self.responses: list[tuple[int, dict]] = []
        self.client._json = lambda body, status=200, **_kw: self.responses.append((int(status), body))
        self.client._error = lambda status, message: self.responses.append((int(status), {"error": message}))

    def test_handler_accepts_only_exact_fields(self) -> None:
        expected = {"format": "sniper-asan-project-proof/1", "verdict": "confirmed"}
        payload = {"binary_relpath": "build/app", "confirm_local": True}
        with mock.patch.object(asan_project_proof, "run", return_value=expected) as run:
            self.client._asan_project_proof_post("prj_abc", "0", payload)
        self.assertEqual(self.responses.pop(), (200, expected))
        run.assert_called_once_with(server.STORE, "prj_abc", 0, binary_relpath="build/app", confirm_local=True)
        self.client._asan_project_proof_post("prj_abc", "0", {**payload, "args": ["--unsafe"]})
        self.assertEqual(self.responses.pop()[0], 400)

    def test_source_handler_accepts_only_exact_fields(self) -> None:
        expected = {"format": "sniper-asan-source-proof/1", "verdict": "confirmed"}
        payload = {"source_relpath": "src/main.c", "confirm_local": True}
        with mock.patch.object(asan_project_proof, "run_source", return_value=expected) as run:
            self.client._asan_project_source_proof_post("prj_abc", "0", payload)
        self.assertEqual(self.responses.pop(), (200, expected))
        run.assert_called_once_with(server.STORE, "prj_abc", 0, source_relpath="src/main.c",
                                    companion_relpaths=None, confirm_local=True)
        self.client._asan_project_source_proof_post("prj_abc", "0", {**payload, "compiler_flags": ["-DSECRET"]})
        self.assertEqual(self.responses.pop()[0], 400)

    def test_compile_database_handler_accepts_only_declarative_selection(self) -> None:
        expected = {"format": "sniper-asan-compile-database-proof/1", "verdict": "confirmed"}
        payload = {"compile_commands_relpath": "compile_commands.json", "entry_index": 0,
                   "confirm_local": True}
        with mock.patch.object(asan_project_proof, "run_compile_database", return_value=expected) as run:
            self.client._asan_project_compile_database_proof_post("prj_abc", "0", payload)
        self.assertEqual(self.responses.pop(), (200, expected))
        run.assert_called_once_with(
            server.STORE, "prj_abc", 0, compile_commands_relpath="compile_commands.json",
            entry_index=0, confirm_local=True,
        )
        self.client._asan_project_compile_database_proof_post(
            "prj_abc", "0", {**payload, "command": "make"},
        )
        self.assertEqual(self.responses.pop()[0], 400)


if __name__ == "__main__":
    unittest.main()
