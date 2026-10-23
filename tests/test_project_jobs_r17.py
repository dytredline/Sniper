"""17. tur W1-JOBS: proje analizi ilerlemesi (aşama + yüzde), iş kuyruğunda iptal, süre bütçesiyle kısmi sonuç,
monorepo alt proje tespiti/özeti ve arka plan analizi bitiş bildirimi."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

import job_queue
from job_queue import JobQueue
import monorepo
import project_analyzer
import project_progress

VULN = 'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n'


def _wait(queue, job_id, states, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = queue.get(job_id)
        if job and job["state"] in states:
            return job
        time.sleep(0.02)
    raise AssertionError(f"iş {states} durumuna geçmedi: {queue.get(job_id)}")


def _write(root: Path, rel: str, text: str = "x = 1\n") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ProgressUnitTests(unittest.TestCase):
    def test_percent_weights_and_snapshot(self):
        self.assertEqual(project_progress.percent("walk"), 1.0)
        self.assertEqual(project_progress.percent("files", 0, 10), 5.0)
        self.assertEqual(project_progress.percent("files", 5, 10), 45.0)
        self.assertEqual(project_progress.percent("files", 99, 10), 85.0)  # taşma kırpılır
        snap = project_progress.snapshot("files", 3, 4, "x" * 500)
        self.assertEqual((snap["stage"], snap["done"], snap["total"], snap["label"]), ("files", 3, 4, "Dosyalar analiz ediliyor"))
        self.assertEqual(len(snap["detail"]), 200)

    def test_report_without_listener_is_noop_and_throttle(self):
        project_progress.report("files", 1, 2)  # dinleyici yok: hata yok
        seen = []
        with project_progress.reporting(seen.append):
            for index in range(50):
                project_progress.report("files", index, 100)
            project_progress.report("files", 100, 100)  # son adım kısıtlanmaz
            project_progress.report("threat")  # aşama değişimi her zaman iletilir
        self.assertLess(len(seen), 10)
        self.assertEqual(seen[-2]["done"], 100)
        self.assertEqual(seen[-1]["stage"], "threat")
        self.assertFalse(project_progress.active())

    def test_reporter_errors_never_break_analysis(self):
        def boom(_data):
            raise OSError("boru kapandı")
        with project_progress.reporting(boom):
            project_progress.report("walk", force=True)

    def test_parse_line_validates_fields(self):
        good = project_progress.parse_line(b'{"stage":"files","percent":42.5,"done":3,"total":7,"detail":"a","extra":1}\n')
        self.assertEqual(good, {"stage": "files", "label": "Dosyalar analiz ediliyor", "percent": 42.5, "done": 3, "total": 7, "detail": "a"})
        for raw in (b"not json", b'{"stage":"rm -rf"}', b"[]", b"\xff\xfe"):
            self.assertIsNone(project_progress.parse_line(raw))
        bad = project_progress.parse_line(b'{"stage":"walk","percent":900,"done":true,"total":-1}')
        self.assertEqual(bad, {"stage": "walk", "label": "Dosyalar listeleniyor", "percent": 1.0})

    def test_fd_writer_round_trip(self):
        read_fd, write_fd = os.pipe()
        try:
            project_progress.fd_writer(write_fd)(project_progress.snapshot("files", 1, 2))
            os.close(write_fd)
            with os.fdopen(read_fd, "rb") as handle:
                self.assertEqual(project_progress.parse_line(handle.readline())["percent"], 45.0)
        finally:
            for fd in (write_fd,):
                try:
                    os.close(fd)
                except OSError:
                    pass


class AnalyzerProgressAndBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "proj"
        for index in range(12):
            _write(self.root, f"pkg/mod{index}.py", VULN if index == 0 else f"value_{index} = {index}\n")

    def analyze(self):
        return project_analyzer.analyze_project(str(self.root), allowed_roots=(self.root.parent,))

    def test_stages_in_order_and_files_reach_total(self):
        seen = []
        with project_progress.reporting(seen.append):
            result = self.analyze()
        stages = [item["stage"] for item in seen]
        order = ["walk", "files", "routes", "licenses", "threat", "subprojects"]
        self.assertEqual([s for s in dict.fromkeys(stages) if s in order], order)
        files = [item for item in seen if item["stage"] == "files"]
        self.assertEqual(files[-1]["done"], files[-1]["total"])
        self.assertEqual(files[-1]["total"], result["file_count"])
        self.assertIsNone(result["partial"])
        self.assertTrue(all(0 <= item["percent"] <= 100 for item in seen))

    def test_time_budget_returns_partial_result(self):
        clock = iter([0.0] + [0.0] * 3 + [10_000.0] * 1000)  # bütçe kurulur, 3 dosyadan sonra aşılır
        with mock.patch.dict(os.environ, {"SNIPER_PROJECT_TIME_BUDGET_SECONDS": "5"}), \
                mock.patch.object(project_analyzer.time, "monotonic", side_effect=lambda: next(clock)):
            result = self.analyze()
        self.assertEqual(result["partial"]["reason"], "time_budget")
        self.assertEqual(result["partial"]["analyzed_files"], 3)
        self.assertEqual(result["file_count"], 3)
        self.assertEqual(result["skipped_files"]["time_budget"], result["partial"]["total_files"] - 3)
        self.assertTrue(result["warnings"][0].startswith("Süre bütçesi aşıldı"))
        # kısmi sonuçta proje geneli yokluk denetimleri yapılmaz
        self.assertFalse([f for f in result["findings"] if f["file"] == "Proje geneli"])

    def test_time_budget_before_any_file_rejects(self):
        with mock.patch.dict(os.environ, {"SNIPER_PROJECT_TIME_BUDGET_SECONDS": "5"}), \
                mock.patch.object(project_analyzer.time, "monotonic", side_effect=[0.0] + [1e9] * 100):
            with self.assertRaises(project_analyzer.ProjectRejected) as caught:
                self.analyze()
        self.assertIn("Süre bütçesi", str(caught.exception))

    def test_budget_env_parsing(self):
        for raw, expected in (("", None), ("0", None), ("-5", None), ("abc", None), ("90", 90.0), ("1e9", 86400.0)):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"SNIPER_PROJECT_TIME_BUDGET_SECONDS": raw}):
                self.assertEqual(project_analyzer._time_budget_seconds(), expected)

    def test_tracking_does_not_mark_fixed_after_time_budget(self):
        import finding_tracking
        import scan_scope

        (self.root / "pkg" / "mod5.py").write_text("y = 2\n", encoding="utf-8")
        self.assertFalse(finding_tracking.file_covered(self.root, "pkg/mod5.py", scan_scope.DEFAULT_SCOPE, {"time_budget": 4}))
        self.assertTrue(finding_tracking.file_covered(self.root, "pkg/mod5.py", scan_scope.DEFAULT_SCOPE, {}))


class MonorepoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "mono"
        self.root.mkdir()

    def kinds(self):
        detected = monorepo.detect(self.root)
        return None if detected is None else {s["path"]: s["kind"] for s in detected["subprojects"]}

    def test_npm_pnpm_and_lerna_workspaces_with_negation(self):
        _write(self.root, "package.json", json.dumps({"workspaces": {"packages": ["packages/*", "!packages/old"]}}))
        for name in ("web", "api", "old"):
            _write(self.root, f"packages/{name}/package.json", "{}")
        _write(self.root, "packages/no-manifest/index.js", "1")
        _write(self.root, "packages/node_modules/package.json", "{}")  # atlanan dizin
        self.assertEqual(self.kinds(), {"packages/api": "npm", "packages/web": "npm"})
        (self.root / "package.json").unlink()
        _write(self.root, "pnpm-workspace.yaml", "packages:\n  - 'apps/**'\n  - \"!apps/legacy\"\nother: 1\n")
        _write(self.root, "apps/a/package.json", "{}")
        _write(self.root, "apps/group/b/package.json", "{}")
        _write(self.root, "apps/legacy/package.json", "{}")
        self.assertEqual(set(self.kinds()), {"apps/a", "apps/group", "apps/group/b"} - {"apps/group"})

    def test_go_cargo_maven_gradle_dotnet(self):
        _write(self.root, "go.work", "go 1.22\nuse (\n  ./svc/a // yorum\n  ./svc/b\n)\nuse ./tools\n")
        for rel in ("svc/a", "svc/b", "tools"):
            (self.root / rel).mkdir(parents=True)
        _write(self.root, "Cargo.toml", '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/skip"]\n')
        for rel in ("crates/core", "crates/cli", "crates/skip"):
            _write(self.root, f"{rel}/Cargo.toml", "[package]\nname='x'\n")
        _write(self.root, "pom.xml", "<project><modules><module>java-api</module><!-- <module>gone</module> --></modules></project>")
        (self.root / "java-api").mkdir()
        _write(self.root, "settings.gradle.kts", 'include(":android:app", "lib")\nincludeBuild("build-logic")\n')
        for rel in ("android/app", "lib", "build-logic"):
            (self.root / rel).mkdir(parents=True)
        _write(self.root, "App.sln", 'Project("{FAE04EC0}") = "Web", "src\\Web\\Web.csproj", "{1}"\nEndProject\n')
        (self.root / "src" / "Web").mkdir(parents=True)
        kinds = self.kinds()
        self.assertEqual(kinds, {
            "svc/a": "go", "svc/b": "go", "tools": "go", "crates/cli": "cargo", "crates/core": "cargo",
            "java-api": "maven", "android/app": "gradle", "lib": "gradle", "src/Web": "dotnet",
        })

    def test_escape_symlink_and_traversal_rejected(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside, target_is_directory=True)
        _write(self.root, "go.work", "use (\n ../outside\n ./link\n /etc\n)\n")
        self.assertIsNone(self.kinds())

    def test_implicit_multi_manifest_and_single_project(self):
        self.assertIsNone(monorepo.detect(self.root, ["package.json", "deploy/docker-compose.yml"]))
        detected = monorepo.detect(self.root, ["frontend/package.json", "backend/requirements.txt", "backend/api/pyproject.toml",
                                               "deploy/docker-compose.yml"])
        self.assertIsNone(detected)  # dizinler yoksa eklenmez
        for rel in ("frontend", "backend/api", "deploy"):
            (self.root / rel).mkdir(parents=True)
        detected = monorepo.detect(self.root, ["frontend/package.json", "backend/requirements.txt", "backend/api/pyproject.toml",
                                               "deploy/docker-compose.yml"])
        self.assertFalse(detected["declared"])
        self.assertEqual([s["path"] for s in detected["subprojects"]], ["backend", "frontend"])

    def test_summary_assigns_files_by_longest_prefix(self):
        _write(self.root, "package.json", json.dumps({"workspaces": ["packages/*", "packages/web/plugins/*"]}))
        _write(self.root, "packages/web/package.json", "{}")
        _write(self.root, "packages/web/plugins/p1/package.json", "{}")
        files = [("packages/web/a.js", "JavaScript"), ("packages/web/plugins/p1/b.js", "JavaScript"), ("tools/x.py", "Python")]
        findings = [
            {"file": "packages/web/plugins/p1/b.js", "severity": "high"},
            {"file": "packages/web/a.js", "severity": "low"},
            {"file": "Proje geneli", "severity": "medium"},
        ]
        summary = monorepo.summarize(self.root, ["package.json", "packages/web/package.json"], files, findings)
        rows = {row["path"]: row for row in summary["subprojects"]}
        self.assertEqual(rows["packages/web/plugins/p1"]["finding_counts"]["high"], 1)
        self.assertEqual(rows["packages/web"]["finding_counts"]["low"], 1)
        self.assertEqual(rows["packages/web"]["file_count"], 1)
        self.assertEqual(summary["root"]["finding_counts"]["medium"], 1)
        self.assertEqual(summary["root"]["languages"], {"Python": 1})
        self.assertEqual(rows["packages/web"]["manifests"], ["packages/web/package.json"])
        self.assertEqual(rows["packages/web"]["dependencies"]["component_count"], 0)

    def test_analyze_project_includes_subprojects(self):
        _write(self.root, "package.json", json.dumps({"workspaces": ["packages/*"]}))
        _write(self.root, "packages/a/package.json", "{}")
        _write(self.root, "packages/a/index.py", VULN)
        _write(self.root, "packages/b/package.json", "{}")
        _write(self.root, "packages/b/util.py", "x = 1\n")
        result = project_analyzer.analyze_project(str(self.root), allowed_roots=(self.root.parent,))
        self.assertEqual(result["subprojects"]["count"], 2)
        single = Path(self.tmp.name) / "single"
        _write(single, "app.py", VULN)
        self.assertIsNone(project_analyzer.analyze_project(str(single), allowed_roots=(single.parent,))["subprojects"])


class JobQueueProgressTests(unittest.TestCase):
    def test_progress_label_and_done(self):
        release = threading.Event()

        def runner(job):
            job.set_progress({"stage": "files", "label": "Dosyalar analiz ediliyor", "percent": 40.0, "done": 4, "total": 10})
            release.wait(5)
            return 200, {"id": "prj_1"}

        queue = JobQueue(workers=1)
        job = queue.submit("/api/project-audits", runner, dedupe_key="a", label="proje-a" * 40)
        deadline = time.monotonic() + 5
        while (queue.get(job.id) or {}).get("progress") is None and time.monotonic() < deadline:
            time.sleep(0.02)
        running = queue.get(job.id)
        self.assertEqual(running["progress"]["percent"], 40.0)
        self.assertEqual(len(running["label"]), 120)
        release.set()
        done = _wait(queue, job.id, {"succeeded"})
        self.assertEqual(done["progress"]["percent"], 100.0)
        job_obj = queue._jobs[job.id]
        job_obj.set_progress({"percent": 1})  # bitmiş iş güncellenmez
        self.assertEqual(queue.get(job.id)["progress"]["percent"], 100.0)

    def test_truncated_result_keeps_identity(self):
        queue = JobQueue(workers=1, max_result_bytes=200)
        big = {"id": "prj_x", "project_name": "p", "finding_counts": {"high": 1}, "findings": ["a" * 500]}
        job = queue.submit("/api/project-audits", lambda _job: (201, big), dedupe_key="b")
        done = _wait(queue, job.id, {"succeeded"})
        self.assertTrue(done["result_truncated"])
        self.assertEqual(done["result"]["id"], "prj_x")
        self.assertNotIn("findings", done["result"])

    def test_label_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "jobs"
            queue = JobQueue(store_dir=store)
            job = queue.submit("/api/x", lambda _job: (200, {}), dedupe_key="c", label="kayitli")
            _wait(queue, job.id, {"succeeded"})
            self.assertEqual(JobQueue(store_dir=store).get(job.id)["label"], "kayitli")


class SubprocessProjectJobTests(unittest.TestCase):
    """Gerçek iş süreci (job_worker.py): ilerleme borusu, kayıt aşaması ve iptal (2 sn içinde)."""

    def setUp(self):
        import server

        self.server = server
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data = base / "data"
        self.data.mkdir()
        self.project = base / "proj"
        _write(self.project, "package.json", json.dumps({"workspaces": ["svc/*"]}))
        _write(self.project, "svc/a/package.json", "{}")
        _write(self.project, "svc/a/app.py", VULN)
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data), "SNIPER_JOB_PERSIST": "0"})
        env.start()
        self.addCleanup(env.stop)

    def fake_server(self):
        return type("S", (), {"server_port": 1})()

    def test_progress_pipe_and_saved_result(self):
        seen = []
        status, body = self.server._run_post_subprocess(
            self.fake_server(), ("127.0.0.1", 1), [("Host", "127.0.0.1:1")], "/api/project-audits",
            {"project_path": str(self.project)}, progress=seen.append)
        self.assertEqual(status, 201, body)
        self.assertTrue(body["id"].startswith("prj_"))
        self.assertEqual(body["subprojects"]["count"], 1)
        stages = [item["stage"] for item in seen]
        for stage in ("start", "walk", "files", "subprojects", "saving"):
            self.assertIn(stage, stages)
        self.assertTrue(all(set(item) <= {"stage", "label", "percent", "done", "total", "detail"} for item in seen))

    def test_no_progress_pipe_when_not_requested(self):
        status, body = self.server._run_post_subprocess(
            self.fake_server(), ("127.0.0.1", 1), [("Host", "127.0.0.1:1")], "/api/project-audits",
            {"project_path": str(self.project)})
        self.assertEqual(status, 201, body)

    def test_cancel_running_analysis_within_two_seconds(self):
        for index in range(4000):
            _write(self.project, f"bulk/m{index // 100}/f{index}.py", f"def f{index}(x):\n    return x + {index}\n")
        queue = JobQueue(workers=1)
        job = queue.submit("/api/project-audits", lambda j: self.server._run_post_subprocess(
            self.fake_server(), ("127.0.0.1", 1), [("Host", "127.0.0.1:1")], "/api/project-audits",
            {"project_path": str(self.project)}, progress=j.set_progress), dedupe_key="cancel")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = queue.get(job.id)
            if (current.get("progress") or {}).get("stage") == "files":
                break
            if current["state"] in job_queue.FINAL_STATES:
                self.fail(f"iş iptalden önce bitti: {current}")
            time.sleep(0.02)
        started = time.monotonic()
        queue.cancel(job.id)
        done = _wait(queue, job.id, {"cancelled", "succeeded", "failed"}, timeout=10)
        self.assertEqual(done["state"], "cancelled", done)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_time_budget_env_for_worker(self):
        with mock.patch.dict(os.environ, {"SNIPER_PROJECT_TIME_BUDGET_SECONDS": ""}):
            env = self.server._job_time_budget_env()
            self.assertEqual(env["SNIPER_PROJECT_TIME_BUDGET_SECONDS"],
                             str(int(max(60.0, self.server.JOBS.timeout_seconds * 0.85 - 30.0))))
        with mock.patch.dict(os.environ, {"SNIPER_PROJECT_TIME_BUDGET_SECONDS": "77"}):
            self.assertEqual(self.server._job_time_budget_env(), {})


class ProjectJobHttpTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server_module = server
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data = base / "data"
        self.data.mkdir()
        self.project = base / "webshop"
        _write(self.project, "app.py", VULN)
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data), "SNIPER_JOB_PERSIST": "0"})
        env.start()
        self.addCleanup(env.stop)
        self.old = (server.STORE, server.LIMITER, server.JOBS, server.SCHEDULER)
        server.STORE = Store(self.data / "sniper.db")
        server.LIMITER = server.RateLimiter()
        server.JOBS = JobQueue(workers=1, on_finish=server._job_finished)
        server.SCHEDULER = None
        self.httpd = server.SniperHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server = self.server_module
        server.STORE, server.LIMITER, server.JOBS, server.SCHEDULER = self.old

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": f"127.0.0.1:{self.port}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(data))})
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        payload = response.read()
        conn.close()
        return response.status, json.loads(payload or b"{}")

    def test_background_project_analysis_reports_progress_and_notifies(self):
        status, job = self.request("POST", "/api/jobs", {"route": "/api/project-audits", "payload": {"project_path": str(self.project)}})
        self.assertEqual(status, 202, job)
        self.assertEqual(job["label"], "webshop")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            status, current = self.request("GET", f"/api/jobs/{job['id']}")
            if current["state"] in job_queue.FINAL_STATES:
                break
            time.sleep(0.1)
        self.assertEqual(current["state"], "succeeded", current)
        self.assertEqual(current["progress"]["percent"], 100.0)
        audit_id = current["result"]["id"]
        status, audit = self.request("GET", f"/api/project-audits/{audit_id}")
        self.assertEqual(status, 200)
        # eşzamanlı API geriye uyumlu: aynı rota doğrudan da çalışır
        status, direct = self.request("POST", "/api/project-audits", {"project_path": str(self.project)})
        self.assertEqual(status, 201, direct)
        center = json.loads((self.data / "notifications.json").read_text(encoding="utf-8"))
        finished = [item for item in center["items"] if item["event"] == "analysis_finished"]
        self.assertEqual(len(finished), 1)
        self.assertEqual(finished[0]["data"]["audit_id"], audit_id)
        self.assertIn("webshop", finished[0]["title"])


class NotificationTextTests(unittest.TestCase):
    def test_analysis_finished_message(self):
        import notifications

        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": tmp}):
            item = notifications.on_project_analysis_finished("job_1", "etiket", {"id": "prj_1", "project_name": "dukkan",
                                                                                 "finding_counts": {"high": 2, "low": 1}})
            self.assertEqual(item["message"], "dukkan analizi tamamlandı (2 yüksek, 1 düşük).")
            empty = notifications.on_project_analysis_finished("job_2", "etiket", None)
            self.assertEqual(empty["message"], "etiket analizi tamamlandı (bulgu yok).")
            self.assertIn("analysis_finished", notifications.EVENT_TYPES)


if __name__ == "__main__":
    unittest.main()
