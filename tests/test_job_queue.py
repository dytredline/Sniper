import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import job_queue
from job_queue import DuplicateJob, JobPersistenceError, JobQueue, QueueFull


def _wait_state(queue, job_id, states, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = queue.get(job_id)
        if job and job["state"] in states:
            return job
        time.sleep(0.02)
    raise AssertionError(f"{job_id} durumu {states} olmadı: {queue.get(job_id)}")


class JobQueueUnitTests(unittest.TestCase):
    def test_before_enqueue_failure_never_publishes_or_runs_reserved_job(self):
        queue = JobQueue(workers=1, max_queued=2, timeout_seconds=1)
        ran = threading.Event()

        def reject(_job):
            raise RuntimeError("persist failed")

        with self.assertRaisesRegex(RuntimeError, "persist failed"):
            queue.submit("/api/x", lambda _job: (ran.set(), (200, {}))[1], dedupe_key="reserved",
                         before_enqueue=reject)
        self.assertFalse(ran.wait(0.05))
        self.assertEqual(queue.list(), [])
        self.assertEqual(queue.stats()["queued"], 0)

    def test_initial_persistence_precedes_callback_and_callback_failure_removes_record(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "jobs"
            queue = JobQueue(workers=1, max_queued=2, timeout_seconds=1, store_dir=store)
            ran = threading.Event()
            callback_saw_file = []

            def reject(job):
                callback_saw_file.append((store / f"{job.id}.json").is_file())
                raise RuntimeError("binding failed")

            with self.assertRaisesRegex(RuntimeError, "binding failed"):
                queue.submit("/api/x", lambda _job: (ran.set(), (200, {}))[1], dedupe_key="durable",
                             before_enqueue=reject)
            self.assertEqual(callback_saw_file, [True])
            self.assertFalse(ran.wait(0.05))
            self.assertEqual(queue.list(), [])
            self.assertEqual(list(store.glob("job_*.json")), [])

    def test_initial_persistence_failure_never_calls_callback_or_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = JobQueue(workers=1, max_queued=2, timeout_seconds=1,
                             store_dir=Path(directory) / "jobs")
            ran = threading.Event()
            bound = threading.Event()
            with mock.patch.object(job_queue.tempfile, "mkstemp", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(JobPersistenceError, "kalıcı depoya"):
                    queue.submit(
                        "/api/x", lambda _job: (ran.set(), (200, {}))[1], dedupe_key="persist-fail",
                        before_enqueue=lambda _job: bound.set(),
                    )
            self.assertFalse(bound.is_set())
            self.assertFalse(ran.wait(0.05))
            self.assertEqual(queue.list(), [])

    def test_explicit_unsafe_store_fails_closed_instead_of_becoming_memory_only(self):
        with tempfile.TemporaryDirectory() as directory:
            unsafe = Path(directory) / "unsafe-jobs"
            unsafe.mkdir(mode=0o755)
            os.chmod(unsafe, 0o755)
            queue = JobQueue(workers=1, store_dir=unsafe)
            ran = threading.Event()
            bound = threading.Event()
            self.assertIsNone(queue.store_dir)
            with self.assertRaisesRegex(JobPersistenceError, "güvenli değil"):
                queue.submit(
                    "/api/x", lambda _job: (ran.set(), (200, {}))[1], dedupe_key="unsafe-store",
                    before_enqueue=lambda _job: bound.set(),
                )
            self.assertFalse(bound.is_set())
            self.assertFalse(ran.wait(0.05))
            self.assertEqual(queue.list(), [])

    def test_worker_or_publish_failure_rolls_back_without_delayed_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "jobs"
            queue = JobQueue(workers=1, store_dir=store)
            ran = threading.Event()
            bound = threading.Event()
            with mock.patch.object(queue, "_ensure_workers", side_effect=RuntimeError("thread failed")):
                with self.assertRaisesRegex(RuntimeError, "thread failed"):
                    queue.submit(
                        "/api/x", lambda _job: (ran.set(), (200, {}))[1], dedupe_key="thread-fail",
                        before_enqueue=lambda _job: bound.set(),
                    )
            self.assertFalse(bound.is_set())
            self.assertEqual(list(store.glob("job_*.json")), [])

            # Start the idle worker successfully, then inject a failure at final publication.
            queue._ensure_workers()
            with mock.patch.object(queue._wakeup, "notify", side_effect=RuntimeError("notify failed")):
                with self.assertRaisesRegex(RuntimeError, "notify failed"):
                    queue.submit(
                        "/api/x", lambda _job: (ran.set(), (200, {}))[1], dedupe_key="publish-fail",
                        before_enqueue=lambda _job: bound.set(),
                    )
            self.assertTrue(bound.is_set())
            self.assertFalse(ran.wait(0.05))
            self.assertEqual(queue.list(), [])
            self.assertEqual(list(store.glob("job_*.json")), [])

            # A later valid submit must not resurrect the rolled-back runner.
            followup = queue.submit("/api/y", lambda _job: (200, {}), dedupe_key="followup")
            _wait_state(queue, followup.id, {"succeeded"})
            self.assertFalse(ran.is_set())

    def test_success_result_and_finish_callback(self):
        finished = []
        queue = JobQueue(workers=1, on_finish=finished.append)
        job = queue.submit("/api/x", lambda _job: (200, {"ok": True}), dedupe_key="a")
        result = _wait_state(queue, job.id, {"succeeded"})
        self.assertEqual(result["result"], {"ok": True})
        self.assertEqual(result["http_status"], 200)
        self.assertEqual([j.id for j in finished], [job.id])
        self.assertNotIn("result", queue.list()[0])

    def test_concurrency_limit_and_queue_full(self):
        release = threading.Event()
        running = []
        lock = threading.Lock()

        def runner(job):
            with lock:
                running.append(job.id)
            release.wait(5)
            return 200, {}

        queue = JobQueue(workers=2, max_queued=2)
        jobs = [queue.submit("/api/x", runner, dedupe_key=str(i)) for i in range(2)]
        _wait_state(queue, jobs[0].id, {"running"})
        _wait_state(queue, jobs[1].id, {"running"})
        waiting = [queue.submit("/api/x", runner, dedupe_key=str(i)) for i in range(2, 4)]
        self.assertEqual(queue.get(waiting[0].id)["state"], "queued")
        self.assertEqual(queue.get(waiting[1].id)["queue_position"], 2)
        with self.assertRaises(QueueFull):
            queue.submit("/api/x", runner, dedupe_key="5")
        time.sleep(0.1)
        self.assertEqual(len(running), 2)
        self.assertEqual(queue.stats()["running"], 2)
        release.set()
        for job in jobs + waiting:
            _wait_state(queue, job.id, {"succeeded"})

    def test_cancelled_job_failure_does_not_print_traceback(self):
        # 22. tur QA: iptal edilen işin durdurulan sürecinden gelen hata beklenen sonuçtur, yığın izi basılmaz;
        # iptal edilmemiş işin gerçek hatası basılmaya devam eder.
        release = threading.Event()

        def stopped(_job):
            release.wait(5)
            raise RuntimeError("iş süreci başarısız oldu veya durduruldu")

        queue = JobQueue(workers=1)
        with mock.patch.object(job_queue.traceback, "print_exc") as printed:
            job = queue.submit("/api/x", stopped, dedupe_key="c")
            _wait_state(queue, job.id, {"running"})
            queue.cancel(job.id)
            release.set()
            _wait_state(queue, job.id, {"cancelled"})
            time.sleep(0.1)
            printed.assert_not_called()
            failing = queue.submit("/api/x", lambda _j: (_ for _ in ()).throw(RuntimeError("gerçek hata")), dedupe_key="d")
            _wait_state(queue, failing.id, {"failed"})
            printed.assert_called()

    def test_duplicate_active_job_rejected_until_finished(self):
        release = threading.Event()
        queue = JobQueue(workers=1)
        job = queue.submit("/api/x", lambda _j: (release.wait(5), (200, {}))[1], dedupe_key="same")
        with self.assertRaises(DuplicateJob):
            queue.submit("/api/x", lambda _j: (200, {}), dedupe_key="same")
        release.set()
        _wait_state(queue, job.id, {"succeeded"})
        second = queue.submit("/api/x", lambda _j: (200, {}), dedupe_key="same")
        _wait_state(queue, second.id, {"succeeded"})

    def test_cancel_kills_process_group_and_plain_child(self):
        procs = {}

        def runner(job):
            procs["group"] = subprocess.Popen(["sleep", "30"], start_new_session=True)
            procs["plain"] = subprocess.Popen(["sleep", "30"])
            procs["group"].wait()
            procs["plain"].wait()
            return 200, {"should": "be discarded"}

        queue = JobQueue(workers=1)
        job = queue.submit("/api/x", runner, dedupe_key="c")
        _wait_state(queue, job.id, {"running"})
        deadline = time.monotonic() + 5
        while len(procs) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        started = time.monotonic()
        self.assertTrue(queue.cancel(job.id)["cancel_requested"])
        result = _wait_state(queue, job.id, {"cancelled"})
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNotNone(procs["group"].poll())
        self.assertIsNotNone(procs["plain"].poll())
        self.assertNotIn("result", result)
        self.assertIn("iptal", result["error"])

    def test_cancel_queued_job(self):
        release = threading.Event()
        queue = JobQueue(workers=1)
        first = queue.submit("/api/x", lambda _j: (release.wait(5), (200, {}))[1], dedupe_key="1")
        _wait_state(queue, first.id, {"running"})
        second = queue.submit("/api/x", lambda _j: (200, {}), dedupe_key="2")
        self.assertEqual(queue.cancel(second.id)["state"], "cancelled")
        release.set()
        _wait_state(queue, first.id, {"succeeded"})
        self.assertEqual(queue.get(second.id)["state"], "cancelled")
        self.assertIsNone(queue.cancel("job_yok"))

    def test_timeout_expires_and_kills_process(self):
        holder = {}

        def runner(job):
            holder["p"] = subprocess.Popen(["sleep", "30"], start_new_session=True)
            holder["p"].wait()
            return 200, {}

        queue = JobQueue(workers=1, timeout_seconds=0.3)
        job = queue.submit("/api/x", runner, dedupe_key="t")
        result = _wait_state(queue, job.id, {"expired"})
        self.assertIsNotNone(holder["p"].poll())
        self.assertIn("süre sınırını", result["error"])

    def test_errors_do_not_leak_internal_details(self):
        def boom(_job):
            raise RuntimeError("/home/community-user/yol parola=xyz")

        queue = JobQueue(workers=1)
        with mock.patch("traceback.print_exc"):
            job = queue.submit("/api/x", boom, dedupe_key="e")
            result = _wait_state(queue, job.id, {"failed"})
        self.assertEqual(result["error"], job_queue.GENERIC_FAILURE)
        self.assertNotIn("gizli", json.dumps(result))
        failed = queue.submit("/api/x", lambda _j: (400, {"error": "Geçersiz proje yolu."}), dedupe_key="f")
        self.assertEqual(_wait_state(queue, failed.id, {"failed"})["error"], "Geçersiz proje yolu.")

    def test_large_results_and_retention_purge(self):
        queue = JobQueue(workers=1, max_result_bytes=100, retention_seconds=0.5)
        big = queue.submit("/api/x", lambda _j: (200, {"data": "x" * 1000}), dedupe_key="b")
        result = _wait_state(queue, big.id, {"succeeded"})
        self.assertTrue(result["result_truncated"])
        self.assertNotIn("x" * 200, json.dumps(result))
        time.sleep(0.6)
        self.assertEqual(queue.list(), [])
        # Adet sınırı: en eski biten işler silinir.
        capped = JobQueue(workers=1, max_retained=2)
        jobs = []
        for i in range(4):
            jobs.append(capped.submit("/api/x", lambda _j: (200, {}), dedupe_key=str(i)))
            deadline = time.monotonic() + 5
            while capped._jobs.get(jobs[-1].id) and capped._jobs[jobs[-1].id].state != "succeeded" and time.monotonic() < deadline:
                time.sleep(0.01)
        ids = [job["id"] for job in capped.list()]
        self.assertEqual(len(ids), 2)
        self.assertEqual(set(ids), {jobs[2].id, jobs[3].id})


class JobsHttpTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server_module = server
        self.temp = tempfile.TemporaryDirectory()
        self.old = (server.STORE, server.LIMITER, server.JOBS)
        server.STORE = Store(Path(self.temp.name) / "fixture.db")
        server.LIMITER = server.RateLimiter()
        server.JOBS = JobQueue(workers=1, on_finish=server._job_finished)
        self.httpd = server.SniperHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server = self.server_module
        server.STORE, server.LIMITER, server.JOBS = self.old
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host or f"127.0.0.1:{self.port}")
        for key, value in (headers or {}).items():
            conn.putheader(key, value)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)
        response = conn.getresponse()
        payload = response.read()
        conn.close()
        return response.status, json.loads(payload or b"{}")

    def wait_job(self, job_id, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, job = self.request("GET", f"/api/jobs/{job_id}")
            self.assertEqual(status, 200)
            if job["state"] in job_queue.FINAL_STATES:
                return job
            time.sleep(0.05)
        raise AssertionError(job)

    def test_job_runs_same_route_logic_and_logs(self):
        project = Path(self.temp.name) / "proj"
        project.mkdir()
        document = {"bomFormat": "CycloneDX", "components": []}
        # Süreç içi yol (sahte fonksiyon alt süreçte geçerli olmaz); alt süreç yolu
        # test_job_persistence_and_worker içinde ayrıca sınanır.
        with mock.patch.object(self.server_module, "generate_cyclonedx_sbom", return_value=document) as generate, \
                mock.patch.object(self.server_module, "SUBPROCESS_JOB_ROUTES", frozenset()):
            status, job = self.request("POST", "/api/jobs", {"route": "/api/dependency-security/sbom", "payload": {"project_path": str(project)}})
            self.assertEqual(status, 202, job)
            done = self.wait_job(job["id"])
        self.assertEqual(done["state"], "succeeded", done)
        self.assertEqual(done["http_status"], 201)
        generate.assert_called_once_with(str(project))
        # Aynı rotanın doğrulaması: eksik alan → başarısız iş, Türkçe hata
        status, job = self.request("POST", "/api/jobs", {"route": "/api/dependency-security/sbom", "payload": {}})
        failed = self.wait_job(job["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["http_status"], 400)
        status, listing = self.request("GET", "/api/jobs")
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["jobs"]), 2)
        self.assertIn("/api/tool-runs/semgrep", listing["routes"])
        actions = [row["action"] for row in self.server_module.STORE.recent_audit_log(limit=50)]
        self.assertIn("job.created", actions)
        self.assertIn("job.finished", actions)

    def test_route_allowlist_and_payload_validation(self):
        for body in (
            {"route": "/api/targets", "payload": {"url": "https://example.com"}},
            {"route": "/api/jobs", "payload": {}},
            {"route": "/api/tool-runs/semgrep", "payload": []},
            {"route": "/api/tool-runs/semgrep", "payload": {}, "extra": 1},
        ):
            with self.subTest(body=body):
                status, data = self.request("POST", "/api/jobs", body)
                self.assertEqual(status, 400)
                self.assertIn("error", data)
        self.assertEqual(self.request("GET", "/api/jobs/job_yok")[0], 404)
        self.assertEqual(self.request("POST", "/api/jobs/job_yok/cancel", {})[0], 404)

    def test_preflight_applies_to_jobs(self):
        body = {"route": "/api/tool-runs/semgrep", "payload": {}}
        self.assertEqual(self.request("POST", "/api/jobs", body, host="evil.example")[0], 421)
        self.assertEqual(self.request("GET", "/api/jobs", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.request("POST", "/api/jobs", body, headers={"Origin": "http://evil.example"})[0], 403)

    def test_duplicate_and_cancel_over_http(self):
        release = threading.Event()

        def slow(project_path):
            release.wait(5)
            return {"bomFormat": "CycloneDX", "components": []}

        project = Path(self.temp.name) / "p2"
        project.mkdir()
        with mock.patch.object(self.server_module, "generate_cyclonedx_sbom", side_effect=slow):
            body = {"route": "/api/dependency-security/sbom", "payload": {"project_path": str(project)}}
            status, job = self.request("POST", "/api/jobs", body)
            self.assertEqual(status, 202)
            self.assertEqual(self.request("POST", "/api/jobs", body)[0], 409)
            status, cancelled = self.request("POST", f"/api/jobs/{job['id']}/cancel", {})
            self.assertEqual(status, 200)
            self.assertTrue(cancelled["cancel_requested"])
            release.set()
            self.assertEqual(self.wait_job(job["id"])["state"], "cancelled")


if __name__ == "__main__":
    unittest.main()
