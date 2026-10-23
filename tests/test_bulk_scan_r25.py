"""25. tur: toplu depo taraması — keşif (sınırlar, sembolik bağ, uzak ad, commit), yürütücü (atla/değişenler/hata/
iptal/eşzamanlılık), bulgu takibi (yalnız değişenler "düzeldi" yapmaz), portföy süzgeci, zamanlayıcı türü, işe özgü
süre sınırı, API (rol/CSRF/onay, uçtan uca gerçek iş süreci) ve CLI (kuru çalıştırma, depo başına SARIF + tek özet).

Testler geçici dizinde ``git init`` + commit ile küçük depolar kurar; ağ kullanılmaz.
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from http.server import ThreadingHTTPServer

import auth
import bulk_scan
from job_queue import JobQueue
from project_analyzer import ProjectRejected
import scheduler as sniper_scheduler
from storage import Store

APP = Path(__file__).resolve().parents[1]
GIT = shutil.which("git")
STRONG = "doğru-at-pil-zımba-42"
VULN = "import sqlite3\nfrom flask import request\n\ndef view():\n    q = request.args['q']\n" \
       "    sqlite3.connect('x').execute('SELECT * FROM t WHERE a = ' + q)\n"


def git(cwd: Path, *args: str) -> str:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(cwd), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    done = subprocess.run([GIT, "-c", "user.name=Test", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
                           "-c", "commit.gpgsign=false", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_repo(path: Path, files: dict[str, str], *, remote: str | None = None, commit: bool = True) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        write(path, rel, text)
    git(path, "init", "-q")
    if remote:
        git(path, "remote", "add", "origin", remote)
    if commit:
        git(path, "add", "-A")
        git(path, "commit", "-q", "-m", "ilk")
    return path


def commit_change(path: Path, rel: str, text: str) -> str:
    write(path, rel, text)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "değişiklik")
    return git(path, "rev-parse", "HEAD")


@unittest.skipUnless(GIT, "git yok")
class RemoteNameTests(unittest.TestCase):
    def test_credentials_ports_and_forms(self):
        cases = {
            "https://user:s3cret@github.com/acme/alpha.git": {"name": "acme/alpha", "host": "github.com"},
            "https://ghp_TOKEN@github.com:443/acme/beta": {"name": "acme/beta", "host": "github.com"},
            "git@gitlab.example.com:grp/sub/gamma.git": {"name": "sub/gamma", "host": "gitlab.example.com"},
            "ssh://git@host.local:2222/team/delta.git?x=1": {"name": "team/delta", "host": "host.local"},
            "file:///srv/git/epsilon.git": {"name": "epsilon", "host": ""},
            "../zeta": {"name": "zeta", "host": ""},
            "/srv/repos/eta.git/": {"name": "eta", "host": ""},
        }
        for url, expected in cases.items():
            self.assertEqual(bulk_scan.derive_remote_name(url), expected, url)
            self.assertNotIn("s3cret", json.dumps(bulk_scan.derive_remote_name(url)))
            self.assertNotIn("TOKEN", json.dumps(bulk_scan.derive_remote_name(url)))
        for bad in ("", "   ", "https://host/", None, "x" * 3000):
            self.assertIsNone(bulk_scan.derive_remote_name(bad))

    def test_config_parsing_prefers_origin(self):
        text = '[core]\n\tbare = false\n[remote "upstream"]\n\turl = https://h/a/up.git\n' \
               '[remote "origin"]\n\turl = git@h:me/fork.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n'
        self.assertEqual(bulk_scan.remote_urls(text), {"upstream": "https://h/a/up.git", "origin": "git@h:me/fork.git"})


@unittest.skipUnless(GIT, "git yok")
class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "kok"
        self.alpha = make_repo(self.root / "alpha", {"app.py": VULN}, remote="https://user:s3cret@github.com/acme/alpha.git")
        make_repo(self.root / "alpha" / "nested", {"x.py": "x = 1\n"})  # iç depo ayrıca listelenmez
        make_repo(self.root / "beta", {"package.json": "{}", "index.js": "module.exports = 1\n",
                                       "node_modules/dep/package.json": "{}"})
        write(self.root, "gamma/requirements.txt", "flask==2.0.0\n")
        write(self.root, "gamma/main.py", "print(1)\n")
        make_repo(self.root / "grup" / "derin" / "delta", {"main.go": "package main\n"})
        make_repo(self.root / "a" / "b" / "c" / "d" / "epsilon", {"x.rb": "puts 1\n"})  # derinlik 5
        make_repo(self.root / ".gizli" / "zeta", {"z.py": "z = 1\n"})
        make_repo(self.root / "bos", {}, commit=False)
        (self.root / "bag").symlink_to(self.alpha, target_is_directory=True)
        (self.root / "notlar").mkdir()
        write(self.root, "notlar/oku.txt", "proje değil\n")
        self.data = self.base / "data"
        self.data.mkdir()
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data)})
        env.start()
        self.addCleanup(env.stop)

    def discover(self, **kwargs):
        return bulk_scan.discover(str(self.root), allowed_roots=(self.base,), **kwargs)

    def test_candidates_limits_symlinks_and_metadata(self):
        found = self.discover()
        by_rel = {item["rel"]: item for item in found["candidates"]}
        self.assertEqual(set(by_rel), {"alpha", "beta", "gamma", "grup/derin/delta", "bos"})
        self.assertGreaterEqual(found["skipped"]["depth"], 1)  # epsilon derinlik sınırının ötesinde
        self.assertGreaterEqual(found["skipped"]["symlink"], 1)
        self.assertGreaterEqual(found["skipped"]["skip_dir"], 1)  # .gizli
        alpha = by_rel["alpha"]
        self.assertEqual(alpha["kind"], "git")
        self.assertEqual(alpha["remote"], {"name": "acme/alpha", "host": "github.com", "remote": "origin"})
        self.assertEqual(alpha["commit"], git(self.alpha, "rev-parse", "HEAD"))
        self.assertEqual(alpha["branch"], "main")
        self.assertLess(abs((dt.datetime.fromisoformat(alpha["committed_at"]) - dt.datetime.now(dt.timezone.utc)).total_seconds()), 600)
        self.assertIn("Python", [lang["name"] for lang in alpha["languages"]])
        self.assertTrue(alpha["selected"])
        self.assertNotIn("s3cret", json.dumps(found))  # ham uzak adres / kimlik bilgisi hiçbir yerde yok
        self.assertNotIn("t@example.invalid", json.dumps(found))  # committer e-postası okunmaz
        self.assertEqual(by_rel["beta"]["file_count"], 2)  # node_modules sayılmaz
        self.assertEqual((by_rel["gamma"]["kind"], by_rel["gamma"]["commit"]), ("manifest", None))
        self.assertEqual((by_rel["bos"]["commit"], by_rel["bos"]["git_error"]), (None, "henüz commit yok"))
        deeper = self.discover(max_depth=6)
        self.assertIn("a/b/c/d/epsilon", {item["rel"] for item in deeper["candidates"]})

    def test_count_and_size_limits_and_validation(self):
        found = self.discover(max_repos=2)
        self.assertEqual((found["count"], found["truncated"]), (2, ["count"]))
        small = self.discover(max_repo_bytes=10)
        sized = [item for item in small["candidates"] if item["size_bytes"] > 10]
        self.assertTrue(sized and all(item["too_large"] == ["size"] and not item["selected"] for item in sized))
        with self.assertRaises(ProjectRejected):
            bulk_scan.discover("/etc", allowed_roots=(self.base,))
        with self.assertRaises(bulk_scan.BulkScanError):
            self.discover(max_depth=99)
        with self.assertRaises(bulk_scan.BulkScanError):
            self.discover(max_repos=0)
        single = bulk_scan.discover(str(self.alpha), allowed_roots=(self.base,))
        self.assertEqual([(c["rel"], c["name"]) for c in single["candidates"]], [(".", "alpha")])

    def test_repo_config_cannot_run_commands(self):
        marker = self.base / "PWNED"
        config = self.alpha / ".git" / "config"
        config.write_text(config.read_text() + f"[core]\n\tfsmonitor = touch {marker}\n[log]\n\tshowSignature = true\n"
                          f"[gpg]\n\tprogram = /bin/sh -c 'touch {marker}'\n[core]\n\tpager = touch {marker}\n")
        found = self.discover()
        self.assertTrue(next(c for c in found["candidates"] if c["rel"] == "alpha")["commit"])
        self.assertFalse(marker.exists())

    def test_selection_validation(self):
        root, repos = bulk_scan.validate_selection(str(self.root), [str(self.alpha), str(self.alpha), str(self.root / "beta")],
                                                   allowed_roots=(self.base,))
        self.assertEqual(repos, [self.alpha, self.root / "beta"])
        other = self.base / "baska"
        other.mkdir()
        for bad in ([str(other)], [], "x", [1]):
            with self.assertRaises((bulk_scan.BulkScanError, ProjectRejected)):
                bulk_scan.validate_selection(str(self.root), bad, allowed_roots=(self.base,))
        with self.assertRaises(bulk_scan.BulkScanError):
            bulk_scan.BulkOptions.parse({"parallel": 9})
        with self.assertRaises(bulk_scan.BulkScanError):
            bulk_scan.BulkOptions.parse({"sca": "evet"})
        with self.assertRaises(bulk_scan.BulkScanError):
            bulk_scan.BulkOptions.parse({"bilinmeyen": True})
        self.assertEqual(bulk_scan.validate_group(None, self.root), "kok")
        with self.assertRaises(bulk_scan.BulkScanError):
            bulk_scan.validate_group("<script>", self.root)


class FakeJob:
    def __init__(self):
        self.cancel_requested = False
        self.expired = False
        self.progress = []

    def set_progress(self, data):
        self.progress.append(data)


@unittest.skipUnless(GIT, "git yok")
class ExecuteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data = base / "data"
        self.data.mkdir()
        self.root = base / "kok"
        self.alpha = make_repo(self.root / "alpha", {"app.py": "x = 1\n"})
        self.beta = make_repo(self.root / "beta", {"index.js": "1\n"})
        self.gamma = self.root / "gamma"
        write(self.root, "gamma/requirements.txt", "flask\n")
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data)})
        env.start()
        self.addCleanup(env.stop)
        self.calls = []
        self.lock = threading.Lock()

    def route(self, fail=(), sca_status=201, changed_status=201, delay=0.0, on_call=None):
        def run(route, payload):
            with self.lock:
                self.calls.append((route, json.loads(json.dumps(payload))))
            if on_call:
                on_call(route, payload)
            if delay:
                time.sleep(delay)
            name = Path(payload.get("project_path") or payload.get("image_path")).name
            if name in fail:
                raise RuntimeError("iş süreci başarısız oldu veya durduruldu")
            if route == "/api/dependency-security/offline-scan":
                return (sca_status, {"finding_count": 2, "component_count": 5, "priority": {"fix_first": 1}}
                        if sca_status == 201 else {"error": "Çevrimdışı OSV veritabanı yok."})
            if "scope" in payload and changed_status != 201:
                return changed_status, {"error": "Taban başvurusu çözülemedi"}
            return 201, {"id": f"prj_{name}", "project_name": name, "score": 80, "grade": "B",
                         "findings": [{"severity": "high"}, {"severity": "low"}]}
        return run

    def start(self, repos, **options):
        run = bulk_scan.create_run(self.root, repos, group="takım", options=bulk_scan.BulkOptions(**options))
        return run["id"]

    def test_errors_continue_state_and_skip_unchanged(self):
        run_id = self.start([self.alpha, self.beta, self.gamma])
        job = FakeJob()
        result = bulk_scan.execute(run_id, self.route(fail={"beta"}), job=job)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual((result["totals"]["succeeded"], result["totals"]["failed"]), (2, 1))
        run = bulk_scan.public_run(bulk_scan.get_run(run_id), "succeeded")
        items = {item["name"]: item for item in run["items"]}
        self.assertEqual(items["alpha"]["severity_counts"], {"high": 1, "low": 1})
        self.assertEqual(items["alpha"]["sca"]["finding_count"], 2)
        self.assertEqual(items["beta"]["status"], "failed")
        self.assertIn("iş süreci", items["beta"]["error"])
        self.assertEqual(run["totals"]["severity_counts"]["high"], 2)
        self.assertEqual(job.progress[-1]["done"], 3)
        state = bulk_scan.load_state()
        self.assertEqual(state["repos"][str(self.alpha)]["last_commit"], git(self.alpha, "rev-parse", "HEAD"))
        self.assertNotIn("last_commit", state["repos"][str(self.beta)])
        # ikinci tur: alpha'nın commit'i aynı → atlanır; gamma git değil → yeniden taranır; beta önceki hatadan sonra taranır
        self.calls.clear()
        run2 = self.start([self.alpha, self.beta, self.gamma])
        bulk_scan.execute(run2, self.route(), job=FakeJob())
        items = {item["name"]: item for item in bulk_scan.get_run(run2)["items"]}
        self.assertEqual((items["alpha"]["status"], items["alpha"]["reason"]), ("skipped", "unchanged"))
        self.assertEqual((items["beta"]["status"], items["gamma"]["status"]), ("succeeded", "succeeded"))
        self.assertNotIn(str(self.alpha), [p.get("project_path") for _r, p in self.calls])
        # zorla: skip_unchanged kapalıysa taranır
        run3 = self.start([self.alpha], skip_unchanged=False, sca=False)
        bulk_scan.execute(run3, self.route(), job=FakeJob())
        self.assertEqual(bulk_scan.get_run(run3)["items"][0]["status"], "succeeded")

    def test_changed_files_mode_and_fallback(self):
        first = git(self.alpha, "rev-parse", "HEAD")
        bulk_scan.execute(self.start([self.alpha], sca=False), self.route(), job=FakeJob())
        second = commit_change(self.alpha, "app.py", "x = 2\n")
        self.calls.clear()
        run_id = self.start([self.alpha], sca=False, changed_files=True)
        bulk_scan.execute(run_id, self.route(), job=FakeJob())
        self.assertEqual(self.calls, [("/api/project-audits", {"project_path": str(self.alpha),
                                                                "scope": {"changed_only": True, "base_ref": first}})])
        item = bulk_scan.get_run(run_id)["items"][0]
        self.assertEqual((item["mode"], item["commit"]), ("changed", second))
        # taban commit çözülemezse (400) tam analize düşülür
        commit_change(self.alpha, "app.py", "x = 3\n")
        self.calls.clear()
        run_id = self.start([self.alpha], sca=False, changed_files=True)
        bulk_scan.execute(run_id, self.route(changed_status=400), job=FakeJob())
        self.assertEqual([("scope" in p) for _r, p in self.calls], [True, False])
        self.assertEqual(bulk_scan.get_run(run_id)["items"][0]["mode"], "full")

    def test_cancel_stops_remaining_and_sca_unavailable(self):
        job = FakeJob()

        def cancel_on_first(route, payload):
            if route == "/api/project-audits":
                job.cancel_requested = True

        run_id = self.start([self.alpha, self.beta, self.gamma])
        result = bulk_scan.execute(run_id, self.route(on_call=cancel_on_first, fail={"alpha"}), job=job)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual([item["status"] for item in bulk_scan.get_run(run_id)["items"]], ["cancelled"] * 3)
        self.assertEqual(len(self.calls), 1)  # iptalden sonra yeni depo başlamadı
        run_id = self.start([self.gamma])
        bulk_scan.execute(run_id, self.route(sca_status=503), job=FakeJob())
        item = bulk_scan.get_run(run_id)["items"][0]
        self.assertEqual((item["status"], item["sca"]["status"]), ("succeeded", "unavailable"))

    def test_parallel_runs_concurrently(self):
        active = [0, 0]

        def track(route, payload):
            with self.lock:
                active[0] += 1
                active[1] = max(active[1], active[0])
            time.sleep(0.15)
            with self.lock:
                active[0] -= 1

        run_id = self.start([self.alpha, self.beta, self.gamma], parallel=3, sca=False)
        result = bulk_scan.execute(run_id, self.route(on_call=track), job=FakeJob())
        self.assertEqual(result["totals"]["succeeded"], 3)
        self.assertGreaterEqual(active[1], 2)

    def test_groups_and_portfolio_filter(self):
        self.start([self.alpha, self.beta])
        self.start([self.gamma])  # aynı grup: üyeler birleşir
        self.assertEqual(bulk_scan.group_paths("takım"), {str(self.alpha), str(self.beta), str(self.gamma)})
        self.assertEqual(bulk_scan.groups()[0]["project_count"], 3)
        keep = bulk_scan.project_filter(group="takım")
        self.assertTrue(keep(str(self.alpha)) and not keep("/baska/proje"))
        self.assertFalse(bulk_scan.project_filter(group="yok")(str(self.alpha)))
        keep = bulk_scan.project_filter(root=str(self.root))
        self.assertTrue(keep(str(self.alpha)) and not keep(str(self.root) + "-x/a"))
        self.assertIsNone(bulk_scan.project_filter())
        self.assertEqual(len(bulk_scan.list_runs()), 2)
        stale = bulk_scan.public_run(bulk_scan.get_run(bulk_scan.list_runs()[0]["id"]), None)
        self.assertEqual(stale["status"], "interrupted")  # iş yok (yeniden başlatma)


class TrackingTests(unittest.TestCase):
    def test_git_changed_scan_does_not_fix_unchanged_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "proj"
            for name in ("a.py", "b.py"):
                write(root, name, "x = 1\n")
            store = Store(base / "s.db")

            def finding(file):
                return {"category": "data_query", "severity": "high", "reference": "CWE-89", "file": file, "line": 3,
                        "title": "SQL enjeksiyonu", "evidence": "-", "recommendation": "-"}

            def audit(findings, **extra):
                return store.create_project_audit({"created_at": "2026-10-01T10:00:00Z", "project_path": str(root),
                                                   "project_name": "proj", "score": 60, "grade": "D", "file_count": 2,
                                                   "bytes_scanned": 10, "findings": findings, "skipped_files": {}, **extra})

            audit([finding("a.py"), finding("b.py")], scope={})
            audit([], scope={"changed_only": True, "base_ref": "HEAD~1"},
                  changed_scan={"mode": "git", "changed_files": ["a.py"]})
            statuses = {row["file"]: row["status"] for row in store.list_tracked_findings(str(root))}
            self.assertEqual(statuses, {"a.py": "fixed", "b.py": "open"})
            audit([], scope={})  # tam analiz: b.py'deki bulgu da artık yok → düzeldi
            statuses = {row["file"]: row["status"] for row in store.list_tracked_findings(str(root))}
            self.assertEqual(statuses, {"a.py": "fixed", "b.py": "fixed"})


class SchedulerAndQueueTests(unittest.TestCase):
    def test_bulk_schedule_type(self):
        types = {item["key"]: item for item in sniper_scheduler.available_scan_types()}
        self.assertEqual(types["bulk_repos"]["target_kind"], "directory")
        self.assertEqual(sniper_scheduler.job_request({"scan_type": "bulk_repos", "project_path": "/home/community-user/projeler"}),
                         ("/api/bulk-scans", {"root": "/home/community-user/projeler"}))
        self.assertIn("/api/bulk-scans", sniper_scheduler.SCAN_ROUTES)  # başarısız gece taraması bildirim üretir

    def test_per_job_timeout(self):
        queue = JobQueue(workers=1, timeout_seconds=60)

        def runner(job):
            deadline = time.monotonic() + 5
            while not job.expired and time.monotonic() < deadline:
                time.sleep(0.02)
            raise RuntimeError("durduruldu")

        job = queue.submit("/x", runner, dedupe_key="a", timeout_seconds=0.2)
        deadline = time.monotonic() + 5
        while queue.get(job.id)["state"] not in {"expired", "failed", "succeeded"} and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(queue.get(job.id)["state"], "expired")


# ---------------------------------------------------------------------------
# API ve CLI
# ---------------------------------------------------------------------------
class Client:
    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}
        self.send_csrf = True

    def request(self, method: str, path: str, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        headers = {"Host": f"127.0.0.1:{self.port}"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            if self.send_csrf and auth.CSRF_COOKIE in self.cookies:
                headers[auth.CSRF_HEADER] = self.cookies[auth.CSRF_COOKIE]
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                cookie, _, flags = value.partition(";")
                key, _, val = cookie.partition("=")
                if "Max-Age=0" in flags:
                    self.cookies.pop(key, None)
                else:
                    self.cookies[key] = val
        conn.close()
        return response.status, (json.loads(raw) if raw else {})

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body):
        return self.request("POST", path, body)


@unittest.skipUnless(GIT, "git yok")
class ApiTests(unittest.TestCase):
    def setUp(self):
        import server

        self.server = server
        # İş süreci (job_worker) gerçek izinli kökleri kullanır: geçici dizin kullanıcı dizininde.
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home(), prefix=".sniper-bulk-test-")
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data = base / "data"
        self.data.mkdir()
        (base / "osv").mkdir()
        self.root = base / "kok"
        self.alpha = make_repo(self.root / "alpha", {"app.py": VULN})
        self.beta = make_repo(self.root / "beta", {"requirements.txt": "flask==0.12\n", "web.py": "x = 1\n"})
        self.previous = server.STORE
        server.STORE = Store(self.data / "sniper.db")
        for patch in (
            mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data), "SNIPER_OSV_DB_ROOT": str(base / "osv"),
                                         "SNIPER_JOB_PERSIST": "0"}),
            mock.patch.object(server, "DATA_DIR", self.data),
            mock.patch.object(server, "LIMITER", server.RateLimiter(limit=100000)),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        auth._MANAGERS.clear()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous
        auth._MANAGERS.clear()

    def wait(self, client, bulk_id, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, run = client.get(f"/api/bulk-scans/{bulk_id}")
            self.assertEqual(status, 200, run)
            if run["status"] not in {"queued", "running"}:
                return run
            time.sleep(0.2)
        self.fail("toplu tarama bitmedi")

    def test_roles(self):
        self.assertEqual(auth.required_level("POST", "/api/bulk-scans"), "analyst")
        self.assertEqual(auth.required_level("POST", "/api/bulk-scans/discover"), "analyst")
        self.assertEqual(auth.required_level("POST", "/api/bulk-scans/blk_0123456789ab/cancel"), "analyst")
        self.assertEqual(auth.required_level("GET", "/api/bulk-scans"), "read")

    def test_end_to_end_discover_scan_portfolio_and_rerun(self):
        c = Client(self.port)
        self.assertEqual(c.post("/api/bulk-scans/discover", {"root": str(self.root)})[0], 400)  # onay yok
        self.assertEqual(c.post("/api/bulk-scans/discover", {"confirm": True, "root": "/etc"})[0], 400)
        self.assertEqual(c.post("/api/bulk-scans/discover", {"confirm": True, "root": str(self.root), "x": 1})[0], 400)
        status, found = c.post("/api/bulk-scans/discover", {"confirm": True, "root": str(self.root)})
        self.assertEqual((status, found["count"]), (200, 2), found)
        paths = [item["path"] for item in found["candidates"]]
        self.assertEqual(c.post("/api/bulk-scans", {"confirm": True, "root": str(self.root), "paths": ["/etc"]})[0], 400)
        self.assertEqual(c.post("/api/bulk-scans", {"confirm": True, "root": str(self.root), "paths": paths,
                                                    "options": {"parallel": 7}})[0], 400)
        status, body = c.post("/api/bulk-scans", {"confirm": True, "root": str(self.root), "paths": paths, "group": "ekip-a",
                                                  "options": {"parallel": 2}})
        self.assertEqual(status, 202, body)
        self.assertEqual(c.post("/api/bulk-scans", {"confirm": True, "root": str(self.root), "paths": paths})[0], 409)
        run = self.wait(c, body["bulk"]["id"])
        self.assertEqual(run["status"], "succeeded", run)
        items = {item["name"]: item for item in run["items"]}
        self.assertEqual({items[n]["status"] for n in items}, {"succeeded"}, items)
        self.assertTrue(items["alpha"]["audit_id"].startswith("prj_"))
        self.assertGreaterEqual(items["alpha"]["finding_count"], 1)
        self.assertIn(items["beta"]["sca"]["status"], {"succeeded", "unavailable"})  # boş OSV kökü: analiz yine sürdü
        status, job = c.get(f"/api/jobs/{body['job']['id']}")
        self.assertEqual((job["state"], job["route"]), ("succeeded", "/api/bulk-scans"))
        status, port = c.get("/api/portfolio?group=ekip-a")
        self.assertEqual(status, 200, port)
        projects = {p["project_path"] for p in port["projects"]}
        self.assertIn(str(self.alpha), projects)
        self.assertLessEqual(projects, {str(self.alpha), str(self.beta)})
        self.assertEqual(port["filter"]["group"], "ekip-a")
        self.assertEqual(port["bulk_groups"][0]["project_count"], 2)
        self.assertEqual(c.get("/api/portfolio?root=/olmayan/kok")[1]["totals"]["projects"], 0)
        self.assertEqual(c.get(f"/api/portfolio?root={self.root}")[1]["totals"]["projects"], len(projects))
        self.assertEqual(c.get("/api/portfolio?root=goreli")[0], 400)
        # yeniden çalıştırma: commit değişmedi → atlanır
        status, body = c.post("/api/bulk-scans", {"confirm": True, "root": str(self.root), "paths": paths})
        run = self.wait(c, body["bulk"]["id"])
        self.assertEqual([item["status"] for item in run["items"]], ["skipped", "skipped"])
        status, listing = c.get("/api/bulk-scans")
        self.assertEqual((status, len(listing["runs"])), (200, 2))
        self.assertEqual(c.get("/api/bulk-scans/blk_000000000000")[0], 404)
        self.assertEqual(c.post("/api/bulk-scans/blk_000000000000/cancel", {"confirm": True})[0], 404)

    def test_login_roles_csrf_and_cancel(self):
        manager = auth.manager_for(self.data)
        manager.create_admin_and_enable("yonetici", STRONG)
        admin = Client(self.port)
        self.assertEqual(admin.post("/api/auth/login", {"username": "yonetici", "password": STRONG})[0], 200)
        for name, role in (("okuyucu1", "reader"), ("analist1", "analyst")):
            self.assertEqual(admin.post("/api/auth/users", {"username": name, "password": STRONG + role, "role": role})[0], 201)
        reader, analyst = Client(self.port), Client(self.port)
        reader.post("/api/auth/login", {"username": "okuyucu1", "password": STRONG + "reader"})
        analyst.post("/api/auth/login", {"username": "analist1", "password": STRONG + "analyst"})
        body = {"confirm": True, "root": str(self.root)}
        self.assertEqual(Client(self.port).post("/api/bulk-scans/discover", body)[0], 401)
        self.assertEqual(reader.post("/api/bulk-scans/discover", body)[0], 403)
        analyst.send_csrf = False
        self.assertEqual(analyst.post("/api/bulk-scans/discover", body)[0], 403)
        analyst.send_csrf = True
        status, found = analyst.post("/api/bulk-scans/discover", body)
        self.assertEqual(status, 200, found)
        self.assertEqual(reader.get("/api/bulk-scans")[0], 200)
        paths = [item["path"] for item in found["candidates"]]
        with mock.patch.object(self.server, "_run_post_subprocess",
                               side_effect=lambda *a, **k: (time.sleep(1.0), (201, {"id": "prj_x", "findings": []}))[1]):
            status, started = analyst.post("/api/bulk-scans", {**body, "paths": paths, "options": {"sca": False}})
            self.assertEqual(status, 202, started)
            bulk_id = started["bulk"]["id"]
            self.assertEqual(reader.post(f"/api/bulk-scans/{bulk_id}/cancel", {"confirm": True})[0], 403)
            self.assertEqual(analyst.post(f"/api/bulk-scans/{bulk_id}/cancel", {})[0], 400)  # onay yok
            status, cancelled = analyst.post(f"/api/bulk-scans/{bulk_id}/cancel", {"confirm": True})
            self.assertEqual(status, 200, cancelled)
            run = self.wait(analyst, bulk_id, timeout=30)
        self.assertEqual(run["status"], "cancelled")
        self.assertIn("cancelled", {item["status"] for item in run["items"]})


@unittest.skipUnless(GIT, "git yok")
class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "kok"
        make_repo(self.root / "alpha", {"app.py": VULN})
        make_repo(self.root / "beta", {"web.py": "x = 1\n"})

    def cli(self, *args):
        env = {**os.environ, "SNIPER_OSV_DB_ROOT": str(self.base / "osv-yok")}
        env.pop("GITHUB_STEP_SUMMARY", None)
        return subprocess.run([sys.executable, str(APP / "cli_reports.py"), "bulk", str(self.root), *args],
                              capture_output=True, text=True, env=env, timeout=600)

    def test_dry_run_lists_without_scanning(self):
        out = self.base / "kesif.json"
        done = self.cli("--dry-run", "--json", str(out))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("2 depo bulundu", done.stdout)
        self.assertIn("Kuru çalıştırma", done.stdout)
        self.assertEqual(json.loads(out.read_text())["count"], 2)

    def test_bulk_ci_sarif_per_repo_and_single_summary(self):
        sarif_dir, summary, state = self.base / "sarif", self.base / "ozet.md", self.base / "durum.json"
        done = self.cli("--parallel", "2", "--sarif-dir", str(sarif_dir), "--summary", str(summary), "--no-sca",
                        "--state", str(state))
        self.assertIn(done.returncode, (0, 1), done.stdout + done.stderr)
        sarifs = sorted(p.name for p in sarif_dir.glob("*.sarif"))
        self.assertEqual(len(sarifs), 2, done.stdout)
        self.assertTrue(all(json.loads((sarif_dir / name).read_text())["version"] == "2.1.0" for name in sarifs))
        text = summary.read_text()
        self.assertIn("Sniper toplu CI", text)
        self.assertEqual(text.count("| alpha |") + text.count("| beta |"), 2)
        self.assertEqual(len(json.loads(state.read_text())), 2)
        again = self.cli("--no-sca", "--state", str(state))
        self.assertEqual(again.returncode, 0, again.stdout)
        self.assertEqual(again.stdout.count("atlandı (commit değişmedi)"), 2)


if __name__ == "__main__":
    unittest.main()
