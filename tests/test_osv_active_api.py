"""Behavior tests for the explicit, offline OSV npm-lockfile API profile."""
import hashlib
import json
import os
import socket
import subprocess
import time
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store


class OSVOfflineApiTests(unittest.TestCase):
    def test_route_returns_runtime_summary_and_rejects_implicit_network_or_missing_consent(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            data = Path(tmp)
            saved_store = server.STORE
            server.STORE = Store(data / "sniper.db")
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            root = f"http://127.0.0.1:{httpd.server_address[1]}"
            private_path = str(data / "private-project")
            expected = {
                "format": "osv-scanner-json", "profile": "local-npm-lock-osv-offline-v1",
                "coverage": "public-registry-lockfile", "package_count": 1,
                "affected_package_count": 1, "vulnerability_group_count": 2,
                "offline_db_sha256": "a" * 64, "offline_db_retrieved_utc": "2026-10-13T10:00:00+00:00",
                "report_sha256": "b" * 64,
            }

            def post(payload):
                req = Request(root + "/api/tool-runs/osv-scanner-local",
                              data=json.dumps(payload).encode(), method="POST",
                              headers={"Content-Type": "application/json"})
                try:
                    with urlopen(req, timeout=5) as response:
                        return response.status, response.read().decode()
                except HTTPError as exc:
                    return exc.code, exc.read().decode()
            try:
                with mock.patch.object(server, "run_local_osv_scanner", create=True, return_value=expected) as run:
                    status, body = post({"confirm_local": True, "project_path": private_path})
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body), expected)
                    self.assertNotIn(private_path, body)
                    self.assertNotIn("private-project", body)
                    run.assert_called_once_with(private_path)
                    self.assertEqual(post({"confirm_local": False, "project_path": private_path})[0], 400)
                    self.assertEqual(post({"confirm_local": True, "confirm_osv_network": True,
                                           "project_path": private_path})[0], 400)
                    self.assertEqual(run.call_count, 1)
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)
                server.STORE = saved_store

    def test_report_requires_positive_exact_package_coverage_before_clean(self):
        from osv_active import _summarize_report, OSVExecutionError
        package = {"package": {"name": "is-number", "version": "7.0.0", "ecosystem": "npm",
                               "purl": "pkg:npm/is-number@7.0.0?source=PUBLIC_REGISTRY"}, "groups": []}
        snapshot = Path("/private/scratch/package-lock.json")
        result = {"results": [{"source": {"path": str(snapshot), "type": "lockfile"},
                               "packages": [package]}]}
        raw = json.dumps(result).encode()
        summary = _summarize_report(raw, {("is-number", "7.0.0")}, 0, "a" * 64,
                                    "2026-10-13T10:00:00+00:00", snapshot)
        self.assertEqual(summary["package_count"], 1)
        self.assertEqual(summary["vulnerability_group_count"], 0)
        with self.assertRaises(OSVExecutionError):
            _summarize_report(raw, {("other", "7.0.0")}, 0, "a" * 64, "x", snapshot)
        with self.assertRaises(OSVExecutionError):
            _summarize_report(json.dumps({"results": [{"source": result["results"][0]["source"],
                                                        "packages": []}]}).encode(),
                              {("is-number", "7.0.0")}, 0, "a" * 64, "x", snapshot)
        with self.assertRaises(OSVExecutionError):
            _summarize_report(raw, {("is-number", "7.0.0")}, 1, "a" * 64, "x", snapshot)
        with self.assertRaises(OSVExecutionError):
            _summarize_report(raw, {("is-number", "7.0.0")}, 0, "a" * 64, "x",
                              Path("/private/other/package-lock.json"))

    def test_stdout_cap_and_timeout_terminate_child_process(self):
        from osv_active import _run_bounded, OSVExecutionError
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            with self.assertRaises(OSVExecutionError):
                _run_bounded([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*2000001)"], root, root)
            with self.assertRaises(OSVExecutionError):
                _run_bounded([sys.executable, "-c", "import time;time.sleep(5)"], root, root,
                             timeout_seconds=0.2)

    def test_unverified_scanner_cleanup_quarantines_future_runs(self):
        import osv_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            project = root / "project"
            project.mkdir()
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data)}), \
                 mock.patch.object(osv_active, "validate_project_path", return_value=project), \
                 mock.patch.object(osv_active, "_trusted_binary", return_value=Path("/bin/true")), \
                 mock.patch.object(osv_active, "_trusted_launcher", return_value=Path("/bin/true")), \
                 mock.patch.object(osv_active, "_trusted_db", return_value=(root, root / "db.zip", "b" * 64, "2026-10-13T10:00:00+00:00")), \
                 mock.patch.object(osv_active, "_snapshot_lockfile", return_value=(project / "package-lock.json", {("is-number", "7.0.0")})), \
                 mock.patch.object(osv_active, "_stage_db", return_value=root), \
                 mock.patch.object(osv_active, "_run_bounded", side_effect=osv_active.OSVExecutionError("timeout")) as run, \
                 mock.patch.object(osv_active, "_sha256_file", return_value="b" * 64):
                with self.assertRaises(osv_active.OSVExecutionError):
                    osv_active.run_local_osv_scanner(str(project))
                self.assertTrue((data / "osv-scanner-quarantine").is_file())
                with self.assertRaises(osv_active.OSVUnavailable):
                    osv_active.run_local_osv_scanner(str(project))
                self.assertEqual(run.call_count, 1)

    def test_abnormal_scanner_exit_quarantines_future_runs(self):
        import osv_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            project = root / "project"
            project.mkdir()
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data)}), \
                 mock.patch.object(osv_active, "validate_project_path", return_value=project), \
                 mock.patch.object(osv_active, "_trusted_binary", return_value=Path("/bin/true")), \
                 mock.patch.object(osv_active, "_trusted_launcher", return_value=Path("/bin/true")), \
                 mock.patch.object(osv_active, "_trusted_db", return_value=(root, root / "db.zip", "b" * 64, "2026-10-13T10:00:00+00:00")), \
                 mock.patch.object(osv_active, "_snapshot_lockfile", return_value=(project / "package-lock.json", {("is-number", "7.0.0")})), \
                 mock.patch.object(osv_active, "_stage_db", return_value=root), \
                 mock.patch.object(osv_active, "_run_bounded", return_value=(2, b"")) as run:
                with self.assertRaises(osv_active.OSVExecutionError):
                    osv_active.run_local_osv_scanner(str(project))
                self.assertTrue((data / "osv-scanner-quarantine").is_file())
                with self.assertRaises(osv_active.OSVUnavailable):
                    osv_active.run_local_osv_scanner(str(project))
                self.assertEqual(run.call_count, 1)

    def test_timeout_kills_descendants_in_scanner_process_group(self):
        from osv_active import _run_bounded, OSVExecutionError
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            pid_file = root / "child.pid"
            script = ("import subprocess,time,pathlib;"
                      "p=subprocess.Popen(['/bin/sleep','30']);"
                      f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid));"
                      "time.sleep(30)")
            with self.assertRaises(OSVExecutionError):
                _run_bounded([sys.executable, "-c", script], root, root, timeout_seconds=0.4)
            self.assertTrue(pid_file.is_file())
            child = int(pid_file.read_text())
            for _ in range(20):
                stat_path = Path(f"/proc/{child}/stat")
                if not stat_path.exists():
                    break
                try:
                    state = stat_path.read_text().split()[2]
                except (FileNotFoundError, ProcessLookupError):
                    # The descendant can exit between the existence check and
                    # the procfs read; that is the successful outcome here.
                    break
                if state == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail("scanner descendant remained runnable after timeout")

    def test_direct_guarded_scanner_uses_exact_snapshot_and_runtime_result(self):
        import osv_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            project = root / "project"
            project.mkdir()
            db = root / "db.zip"
            db.write_bytes(b"synthetic database")
            db_hash = osv_active._sha256_file(db)

            def snapshot_lockfile(_root, work):
                snapshot = work / "package-lock.json"
                snapshot.write_text("{}")
                return snapshot, {("lodash", "4.17.20")}

            def stage_db(_db, _sha, work):
                cache = work / "db-cache"
                staged = cache / "osv-scalibr" / "npm" / "all.zip"
                staged.parent.mkdir(parents=True)
                staged.write_bytes(db.read_bytes())
                return cache

            def scanner_result(cmd, work, cache):
                self.assertEqual(cmd[:3], [sys.executable, "-I", "-S"])
                self.assertEqual(cmd[5:10], ["scan", "source", "--offline", "--no-resolve", "--format"])
                self.assertEqual(cmd[-2], "--lockfile")
                self.assertEqual(Path(cmd[-1]).parent, work)
                self.assertEqual(cache, work / "db-cache")
                report = {"results": [{"source": {"path": cmd[-1], "type": "lockfile"},
                                       "packages": [{"package": {"name": "lodash", "version": "4.17.20",
                                                                "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.20?source=PUBLIC_REGISTRY"},
                                                     "groups": [{"ids": ["GHSA-test"]}]}]}]}
                return 1, json.dumps(report).encode()
            guard = Path(__file__).resolve().parents[1] / "osv_seccomp_launcher.py"
            env = {"SNIPER_DATA_DIR": str(data), "SNIPER_OSV_SECCOMP_LAUNCHER": str(guard),
                   "SNIPER_OSV_SECCOMP_LAUNCHER_SHA256": hashlib.sha256(guard.read_bytes()).hexdigest(),
                   "SNIPER_OSV_DOCKER_BINARY": "", "SNIPER_OSV_DOCKER_SHA256": "",
                   "SNIPER_OSV_DOCKER_IMAGE_ID": ""}
            with mock.patch.dict(os.environ, env), \
                 mock.patch.object(osv_active, "validate_project_path", return_value=project), \
                 mock.patch.object(osv_active, "_trusted_binary", return_value=Path("/bin/true")), \
                 mock.patch.object(osv_active, "_trusted_db", return_value=(root, db, db_hash, "2026-10-13T10:00:00+00:00")), \
                 mock.patch.object(osv_active, "_snapshot_lockfile", side_effect=snapshot_lockfile), \
                 mock.patch.object(osv_active, "_stage_db", side_effect=stage_db), \
                 mock.patch.object(osv_active, "_run_bounded", side_effect=scanner_result) as run:
                summary = osv_active.run_local_osv_scanner(str(project))
                self.assertEqual(summary["package_count"], 1)
                self.assertEqual(summary["affected_package_count"], 1)
                self.assertEqual(summary["vulnerability_group_count"], 1)
                self.assertFalse((data / "osv-scanner-quarantine").exists())
                self.assertEqual(run.call_count, 1)

    def test_readiness_checks_scanner_guard_and_offline_db_without_docker(self):
        import osv_active
        from tool_runtime_readiness import _runtime_check
        route = "/api/tool-runs/osv-scanner-local"
        with mock.patch.object(osv_active, "_trusted_binary", return_value=Path("/bin/true")), \
             mock.patch.object(osv_active, "_trusted_launcher", return_value=Path("/bin/true")) as guard, \
             mock.patch.object(osv_active, "_trusted_db", return_value=(Path("/tmp"), Path("/tmp/db"), "a" * 64, "now")):
            self.assertEqual(_runtime_check("osv-scanner", route),
                             (True, "pinned_offline_runtime_and_db_found"))
            guard.assert_called_once()
        with mock.patch.object(osv_active, "_trusted_binary", return_value=Path("/bin/true")), \
             mock.patch.object(osv_active, "_trusted_launcher", side_effect=osv_active.OSVUnavailable("missing")):
            self.assertEqual(_runtime_check("osv-scanner", route),
                             (False, "pinned_offline_runtime_or_db_unavailable"))

    def test_seccomp_launcher_closes_even_explicitly_inherited_socket_and_denies_new_socket(self):
        import osv_seccomp_launcher
        left, right = socket.socketpair()
        try:
            script = ("import errno,os,socket,sys; "
                      "fd=int(sys.argv[1]); "
                      "exec('try:\\n os.fstat(fd)\\n raise AssertionError(\\\"fd inherited\\\")\\n"
                      "except OSError as exc:\\n assert exc.errno == errno.EBADF'); "
                      "exec('try:\\n socket.socket()\\n raise AssertionError(\\\"network open\\\")\\n"
                      "except OSError as exc:\\n assert exc.errno == errno.EPERM')")
            command = [sys.executable, "-I", "-S", str(Path(osv_seccomp_launcher.__file__)),
                       str(Path(sys.executable).resolve()), "-c", script, str(left.fileno())]
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, pass_fds=(left.fileno(),), timeout=5,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        finally:
            left.close()
            right.close()

    def test_seccomp_launcher_forbids_process_fork_before_detach(self):
        import osv_seccomp_launcher
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            marker = Path(tmp) / "detached-child"
            script = (
                "import errno,os,pathlib,sys\n"
                "try:\n"
                " pid=os.fork()\n"
                "except OSError as exc:\n"
                " assert exc.errno == errno.EPERM, exc\n"
                " print('fork-denied')\n"
                " sys.exit(0)\n"
                "if pid == 0:\n"
                " os.setsid()\n"
                f" pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\n"
                " os._exit(0)\n"
                "os.waitpid(pid, 0)\n"
                "raise AssertionError('independent child was created')\n"
            )
            command = [sys.executable, "-I", "-S", str(Path(osv_seccomp_launcher.__file__)),
                       str(Path(sys.executable).resolve()), "-c", script]
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, close_fds=True, timeout=5,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b"fork-denied\n")
            self.assertFalse(marker.exists())

    def test_bounded_guarded_run_cannot_leave_detached_child(self):
        from osv_active import _run_bounded
        import osv_seccomp_launcher
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            marker = root / "escaped-child.pid"
            script = (
                "import errno,os,pathlib,sys,time\n"
                "try:\n"
                " pid=os.fork()\n"
                "except OSError as exc:\n"
                " assert exc.errno == errno.EPERM, exc\n"
                " print('fork-denied')\n"
                " sys.exit(0)\n"
                "if pid == 0:\n"
                " os.setsid()\n"
                " os.dup2(os.open('/dev/null', os.O_WRONLY), 1)\n"
                f" pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\n"
                " time.sleep(5)\n"
                " os._exit(0)\n"
                f"deadline=time.monotonic()+0.5\n"
                f"while not pathlib.Path({str(marker)!r}).exists() and time.monotonic()<deadline: time.sleep(0.005)\n"
                "os._exit(0)\n"
            )
            command = [sys.executable, "-I", "-S", str(Path(osv_seccomp_launcher.__file__)),
                       str(Path(sys.executable).resolve()), "-c", script]
            try:
                status, raw = _run_bounded(command, root, root, timeout_seconds=2)
                self.assertEqual(status, 0)
                self.assertEqual(raw, b"fork-denied\n")
                self.assertFalse(marker.exists())
            finally:
                if marker.exists():
                    escaped = int(marker.read_text())
                    try:
                        os.kill(escaped, 9)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
