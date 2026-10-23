import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

import job_queue
from job_queue import JobQueue


def _wait(queue, job_id, states, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = queue.get(job_id)
        if job and job["state"] in states:
            return job
        time.sleep(0.05)
    raise AssertionError(f"iş {states} durumuna geçmedi: {queue.get(job_id)}")


class JobPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Path(self._tmp.name) / "jobs"

    def test_finished_job_and_result_survive_restart(self):
        queue = JobQueue(store_dir=self.store)
        job = queue.submit("/api/x", lambda _job: (200, {"ok": True}), dedupe_key="a")
        _wait(queue, job.id, {"succeeded"})
        path = self.store / f"{job.id}.json"
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.store.stat().st_mode & 0o777), "0o700")
        restored = JobQueue(store_dir=self.store).get(job.id)
        self.assertEqual(restored["state"], "succeeded")
        self.assertEqual(restored["result"], {"ok": True})

    def test_running_job_becomes_interrupted_after_restart(self):
        release = threading.Event()
        queue = JobQueue(store_dir=self.store)
        job = queue.submit("/api/x", lambda _job: (release.wait(5), (200, {}))[1], dedupe_key="b")
        _wait(queue, job.id, {"running"})
        restored = JobQueue(store_dir=self.store).get(job.id)
        release.set()
        _wait(queue, job.id, {"succeeded"})
        self.assertEqual(restored["state"], "interrupted")
        self.assertIn("yeniden başladığı", restored["error"])

    def test_purge_removes_files_and_insecure_store_is_ignored(self):
        queue = JobQueue(store_dir=self.store, retention_seconds=0.5)
        job = queue.submit("/api/x", lambda _job: (200, {}), dedupe_key="c")
        _wait(queue, job.id, {"succeeded"})
        self.assertTrue((self.store / f"{job.id}.json").exists())
        time.sleep(0.7)
        queue.list()
        self.assertFalse((self.store / f"{job.id}.json").exists())
        loose = Path(self._tmp.name) / "loose"
        loose.mkdir(mode=0o755)
        os.chmod(loose, 0o755)
        self.assertIsNone(JobQueue(store_dir=loose).store_dir)


class SubprocessWorkerTests(unittest.TestCase):
    def test_worker_runs_route_through_same_dispatch(self):
        import server

        status, body = server._run_post_subprocess(
            type("S", (), {"server_port": server.PORT})(), ("127.0.0.1", 1), [],
            "/api/cvss-ssvc/prioritize", {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["score"], 9.3)

    def test_cancel_kills_python_worker_process(self):
        import server

        with tempfile.TemporaryDirectory() as tmp:
            slow = Path(tmp) / "slow_worker.py"
            slow.write_text("import time, sys\nsys.stdin.read()\ntime.sleep(60)\n", encoding="utf-8")
            queue = JobQueue()
            with mock.patch.object(server, "JOB_WORKER_SCRIPT", slow):
                job = queue.submit("/api/project-audits", lambda _job: server._run_post_subprocess(
                    type("S", (), {"server_port": 1})(), None, [], "/api/project-audits", {}), dedupe_key="d")
                _wait(queue, job.id, {"running"})
                time.sleep(0.5)
                started = time.monotonic()
                queue.cancel(job.id)
                done = _wait(queue, job.id, {"cancelled"}, timeout=10)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(done["state"], "cancelled")


if __name__ == "__main__":
    unittest.main()
