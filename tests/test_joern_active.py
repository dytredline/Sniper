import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import joern_active
from project_analyzer import ProjectRejected
from verified_exec import open_verified_executable

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "joern"
JOERN_BENCHMARK = Path(__file__).resolve().parents[1] / "scripts" / "joern_benchmark.py"


def _line(**overrides):
    record = {
        "kind": "command", "label": "external", "language": "c", "source": "getenv", "sink": "system",
        "steps": [["/w/src/main.c", 5, "main"], ["/w/src/util.c", 9, "run"], ["/w/src/util.c", 12, "run"]],
    }
    record.update(overrides)
    return json.dumps(record)


class ParseAndConvertTests(unittest.TestCase):
    def test_parse_relativizes_dedupes_and_rejects_unsafe_records(self):
        text = "\n".join([
            _line(),
            _line(),  # yinelenen
            _line(kind="bilinmeyen"),
            _line(label="kimbilir"),
            _line(steps=[["/etc/passwd", 1, "x"]]),  # çalışma dizini dışı
            _line(steps=[["../../a.c", 1, "x"]]),
            _line(kind="xss", label="external"),  # XSS yalnız HTTP istek girdisiyle
            "{bozuk json",
            json.dumps([1, 2]),
            _line(kind="sql", label="request", language="java", source="request.getParameter", sink="executeQuery",
                  steps=[["/w/src/App.java", 10, "doGet"], ["/w/src/App.java", 14, "doGet"]]),
        ])
        flows = joern_active.parse_joern_flows(text, workspace=Path("/w/src"), language="c")
        self.assertEqual([(f["kind"], f["label"]) for f in flows], [("command", "external"), ("sql", "request")])
        self.assertEqual(flows[0]["steps"][0], {"file": "main.c", "line": 5, "method": "main"})
        self.assertEqual(flows[0]["steps"][-1]["file"], "util.c")

    def test_findings_and_sarif_code_flows(self):
        flows = joern_active.parse_joern_flows(
            _line() + "\n" + _line(kind="sql", label="request", source="request.getParameter", sink="executeQuery",
                                   steps=[["/w/src/App.java", 10, "doGet"], ["/w/src/App.java", 14, "doGet"]]),
            workspace=Path("/w/src"),
        )
        findings = joern_active.flows_to_findings(flows)
        command, sql = findings
        self.assertEqual(command["file"], "util.c")
        self.assertEqual(command["line"], 12)
        self.assertEqual(command["severity"], "high")  # dış (argv/ortam) girdi: kritik yerine yüksek
        self.assertEqual(command["reference"], "CWE-78")
        self.assertEqual(command["taint_flow"]["source_file"], "main.c")
        self.assertIn("main.c satır 5", command["evidence"])
        self.assertNotIn("source_file", sql["taint_flow"])
        self.assertEqual(sql["severity"], "critical")
        sarif = joern_active.render_sarif(findings)
        run = sarif["runs"][0]
        locations = run["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual([loc["location"]["physicalLocation"]["region"]["startLine"] for loc in locations], [5, 9, 12])
        self.assertEqual(locations[0]["location"]["message"]["text"], "Kaynak: getenv")
        rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "SNIPER-JOERN-COMMAND")
        self.assertIn("external/cwe/cwe-78", rule["properties"]["tags"])
        self.assertEqual(len(run["results"][0]["partialFingerprints"]["sniperJoern/v1"]), 32)

    def test_long_paths_are_trimmed(self):
        steps = [[f"/w/src/a.c", i, "f"] for i in range(1, 200)]
        flows = joern_active.parse_joern_flows(_line(steps=steps), workspace=Path("/w/src"))
        self.assertEqual(len(flows[0]["steps"]), joern_active.MAX_STEPS)
        self.assertEqual(flows[0]["steps"][0]["line"], 1)
        self.assertEqual(flows[0]["steps"][-1]["line"], 199)


class CollectSourcesTests(unittest.TestCase):
    def test_collects_c_and_java_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "a.c").write_text("int main(){}", encoding="utf-8")
            (root / "src" / "B.java").write_text("class B {}", encoding="utf-8")
            (root / "src" / "notes.py").write_text("x = 1", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "x.c").write_text("", encoding="utf-8")
            (root / "link.c").symlink_to("/etc/hostname")
            found = joern_active.collect_sources(root)
            self.assertEqual({k: [p.name for p in v] for k, v in found.items()}, {"c": ["a.c"], "java": ["B.java"]})
            dest = Path(tmp) / "copy"
            dest.mkdir()
            self.assertEqual(joern_active._copy_sources(root, found["c"], dest), 1)
            self.assertTrue((dest / "src" / "a.c").is_file())

    def test_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(4):
                (root / f"{i}.c").write_text("x", encoding="utf-8")
            with mock.patch.object(joern_active, "MAX_FILES", 3):
                with self.assertRaises(ProjectRejected):
                    joern_active.collect_sources(root)


class InstallVerificationTests(unittest.TestCase):
    def _install(self, root: Path) -> tuple[Path, str]:
        home = root / "joern-cli"
        for lib in joern_active.CLASSPATH_DIRS:
            (home / lib).mkdir(parents=True)
        files = {}
        for name, data in (("lib/a.jar", b"jar-a"), ("lib/b.jar", b"jar-b"),
                           ("frontends/c2cpg/lib/c.jar", b"jar-c"), ("frontends/javasrc2cpg/lib/j.jar", b"jar-j")):
            (home / name).write_bytes(data)
            files[name] = hashlib.sha256(data).hexdigest()
        manifest = json.dumps({"format": "sniper-joern-install-v1", "files": files}).encode()
        (home / joern_active.MANIFEST_NAME).write_bytes(manifest)
        for path in home.rglob("*"):
            os.chmod(path, 0o555 if path.is_dir() else 0o444)
        for path in [home, *(home / lib for lib in joern_active.CLASSPATH_DIRS)]:
            os.chmod(path, 0o755)
        return home, hashlib.sha256(manifest).hexdigest()

    def test_manifest_pin_file_digests_and_extra_jars(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, digest = self._install(Path(tmp))
            with mock.patch.dict(os.environ, {"SNIPER_JOERN_MANIFEST_SHA256": ""}), \
                    mock.patch.object(joern_active, "JOERN_MANIFEST_SHA256", {}):
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "sabitlenmiş"):
                    joern_active.verify_joern_install(home)
            with mock.patch.dict(os.environ, {"SNIPER_JOERN_MANIFEST_SHA256": digest}):
                manifest = joern_active.verify_joern_install(home)
                self.assertIn("frontends/c2cpg/lib/c.jar", manifest["files"])
                self.assertIn("lib/a.jar", joern_active._classpath(home, manifest))
                (home / "lib" / "evil.jar").write_bytes(b"x")
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "manifestte olmayan"):
                    joern_active.verify_joern_install(home)
                (home / "lib" / "evil.jar").unlink()
                os.chmod(home / "lib" / "a.jar", 0o644)
                (home / "lib" / "a.jar").write_bytes(b"degisti")
                os.chmod(home / "lib" / "a.jar", 0o444)
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "uyuşmuyor"):
                    joern_active.verify_joern_install(home)
            with mock.patch.dict(os.environ, {"SNIPER_JOERN_MANIFEST_SHA256": "0" * 64}):
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "uyuşmuyor"):
                    joern_active.verify_joern_install(home)

    def test_heap_is_capped(self):
        with mock.patch.dict(os.environ, {"SNIPER_JOERN_HEAP_GB": "64"}):
            self.assertEqual(joern_active.heap_gb(), joern_active.MAX_HEAP_GB)
        with mock.patch.dict(os.environ, {"SNIPER_JOERN_HEAP_GB": "x"}):
            self.assertEqual(joern_active.heap_gb(), joern_active.DEFAULT_HEAP_GB)


class RunOrchestrationTests(unittest.TestCase):
    """Joern çalıştırılmadan: sahte çalıştırıcı ve doğrulanmış sahte JDK ile uçtan uca akış."""

    def _manifest(self, home):
        return {"files": {
            "lib/a.jar": "x", "lib/b.jar": "y",
            f"frontends/c2cpg/lib/io.joern.c2cpg-{joern_active.JOERN_VERSION}-launcher.jar": "z",
            f"frontends/javasrc2cpg/lib/io.joern.javasrc2cpg-{joern_active.JOERN_VERSION}-launcher.jar": "w",
        }}

    def test_run_with_fake_runner(self):
        home = Path("/opt/joern-cli")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with tempfile.TemporaryDirectory(dir=Path.home() / ".cache") as proj:
                proj_root = Path(proj)
                (proj_root / "main.c").write_text("int main(){}", encoding="utf-8")
                fake_jdk = mock.MagicMock()
                fake_jdk.argv0, fake_jdk.fd, fake_jdk.sha256, fake_jdk.provenance = "/proc/self/fd/9", 9, "a" * 64, "test"
                fake_jdk.__enter__.return_value = fake_jdk
                commands = []

                def runner(cmd, timeout, env, cwd, pass_fds):
                    commands.append((cmd, env))
                    self.assertEqual(pass_fds, (9,))
                    self.assertFalse({"JAVA_TOOL_OPTIONS", "http_proxy", "HTTPS_PROXY"} & set(env))
                    if joern_active.SCRIPT_MAIN in cmd:
                        shim_dir = env["PATH"].split(":")[0]
                        self.assertTrue(os.access(Path(shim_dir) / "java", os.X_OK))
                        cpg = Path(cwd) / "c.cpg.bin"
                        out = Path(cwd) / "c.flows.jsonl"
                        fork = ["-classpath", f"{home}/lib/a.jar:{home}/lib/b.jar", "replpp.scripting.NonForkingScriptRunner",
                                "--runBefore", "import x.*", "--script", str(joern_active.QUERY_SCRIPT)]
                        for param in joern_active._script_params(cpg, out):
                            fork += ["--param", param]
                        (Path(cwd) / "fork-args.bin").write_bytes(("\0".join(fork) + "\0").encode())
                    elif "replpp.scripting.NonForkingScriptRunner" in cmd:
                        out = next(arg.split("=", 1)[1] for arg in cmd if str(arg).startswith("outFile="))
                        Path(out).write_text(_line(steps=[["main.c", 1, "main"], ["main.c", 3, "main"]]), encoding="utf-8")
                    return subprocess.CompletedProcess(cmd, 0, b"", b"")

                with mock.patch.object(joern_active, "verify_joern_install", return_value=self._manifest(home)), \
                        mock.patch.object(joern_active, "joern_home", return_value=home), \
                        mock.patch.object(joern_active, "open_pinned", return_value=fake_jdk), \
                        mock.patch.object(joern_active, "available_memory_gb", return_value=64.0), \
                        mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(base)}):
                    result = joern_active.run_joern_deep(str(proj_root), runner=runner)
        self.assertEqual(result["format"], "sniper-joern-deep-v1")
        self.assertEqual(result["languages"], {"c": 1})
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["file"], "main.c")
        self.assertEqual(len(commands), 3)
        frontend, capture, query = (cmd for cmd, _env in commands)
        self.assertIn("-jar", frontend)
        self.assertTrue(frontend[frontend.index("-jar") + 1].endswith("c2cpg-4.0.647-launcher.jar"))
        self.assertTrue(all(cmd[0] == "/proc/self/fd/9" for cmd, _env in commands))
        self.assertTrue(any(str(a).startswith("-Xmx") for a in query))
        self.assertIn("replpp.scripting.NonForkingScriptRunner", query)
        self.assertIn("codeFlows", result["sarif"]["runs"][0]["results"][0])

    def test_fork_args_validation_rejects_tampering(self):
        home = Path("/opt/joern-cli")
        manifest = self._manifest(home)
        cpg, out = Path("/w/c.cpg.bin"), Path("/w/c.jsonl")

        def build(classpath=f"{home}/lib/a.jar", main="replpp.scripting.NonForkingScriptRunner",
                  script=str(joern_active.QUERY_SCRIPT), params=None, extra=()):
            args = ["-classpath", classpath, main, *extra, "--script", script]
            for param in params if params is not None else joern_active._script_params(cpg, out):
                args += ["--param", param]
            return ("\0".join(args) + "\0").encode()

        self.assertIn("--script", joern_active._validated_fork_args(build(), home, manifest, cpg, out))
        for bad in (build(classpath=f"{home}/lib/a.jar:/tmp/evil.jar"),
                    build(classpath=f"{home}/lib/unlisted.jar"),
                    build(main="evil.Main"),
                    build(script="/tmp/evil.sc"),
                    build(params=["cpgFile=/etc/passwd"]),
                    build(extra=("-javaagent:/tmp/a.jar",))):
            with self.assertRaises(joern_active.JoernExecutionError):
                joern_active._validated_fork_args(bad, home, manifest, cpg, out)

    def test_low_memory_and_busy_lock(self):
        with tempfile.TemporaryDirectory(dir=Path.home() / ".cache") as proj, tempfile.TemporaryDirectory() as data:
            (Path(proj) / "a.c").write_text("x", encoding="utf-8")
            with mock.patch.object(joern_active, "verify_joern_install", return_value={"files": {}}), \
                    mock.patch.object(joern_active, "available_memory_gb", return_value=1.0), \
                    mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": data}):
                with self.assertRaisesRegex(joern_active.JoernUnavailable, "bellek"):
                    joern_active.run_joern_deep(proj)
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": data}):
                first = joern_active._lock()
                try:
                    with self.assertRaises(joern_active.JoernBusy):
                        joern_active._lock()
                finally:
                    os.close(first)

    def test_rejects_projects_without_c_or_java(self):
        with tempfile.TemporaryDirectory(dir=Path.home() / ".cache") as proj:
            (Path(proj) / "a.py").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ProjectRejected, "C/C\\+\\+, Java, Kotlin, PHP, Go, Ruby veya C#"):
                joern_active.run_joern_deep(proj)


class JoernRouteTests(unittest.TestCase):
    def setUp(self):
        import http.client
        import threading
        import server
        from storage import Store

        self.server_module = server
        self.http = http.client
        self.temp = tempfile.TemporaryDirectory()
        self.old_store, self.old_limiter = server.STORE, server.LIMITER
        server.STORE = Store(Path(self.temp.name) / "fixture.db")
        server.LIMITER = server.RateLimiter()
        self.httpd = server.SniperHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        self.server_module.STORE, self.server_module.LIMITER = self.old_store, self.old_limiter
        self.temp.cleanup()

    def post(self, body):
        conn = self.http.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = json.dumps(body).encode()
        conn.request("POST", "/api/tool-runs/joern-deep", body=data,
                     headers={"Content-Type": "application/json", "Host": f"127.0.0.1:{self.port}"})
        response = conn.getresponse()
        payload = json.loads(response.read() or b"{}")
        conn.close()
        return response.status, payload

    def test_validation_and_unavailable(self):
        self.assertEqual(self.post({"project_path": "/x"})[0], 400)
        status, body = self.post({"confirm_local": "true", "project_path": "/x"})
        self.assertEqual(status, 400)
        self.assertIn("confirm_local", body["error"])
        self.assertEqual(self.post({"confirm_local": True, "project_path": "/x", "extra": 1})[0], 400)
        with tempfile.TemporaryDirectory(dir=Path.home() / ".cache") as proj:
            (Path(proj) / "a.c").write_text("int main(){}", encoding="utf-8")
            with mock.patch.dict(os.environ, {"SNIPER_JOERN_MANIFEST_SHA256": "", "SNIPER_JOERN_HOME": proj}):
                status, body = self.post({"confirm_local": True, "project_path": proj})
            self.assertEqual(status, 503)
            self.assertIn("Joern kurulu değil", body["error"])
            self.assertNotIn(proj, body["error"])
        self.assertIn("/api/tool-runs/joern-deep", self.server_module.JOB_ROUTES)


class SpringModelTests(unittest.TestCase):
    """Spring/MyBatis desteği: XML eşleyici taraması, yalnız-istek türleri, delombok kapalı ön uç."""

    def test_mybatis_scan_finds_dollar_statements_and_included_fragments(self):
        mapper = """<?xml version="1.0"?>
<!DOCTYPE mapper [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<mapper namespace="app.mapper.UserMapper">
  <sql id="orderPart">order by ${sort}</sql>
  <select id="vuln" resultType="User">select * from u where name = '${name}'</select>
  <select id="safe" resultType="User">select * from u where name = #{name}</select>
  <select id="ordered" resultType="User">select * from u <include refid="orderPart"/></select>
  <update id="touch">update u set seen = 1 where id = #{id}</update>
</mapper>"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "res").mkdir()
            (root / "res" / "UserMapper.xml").write_text(mapper)
            (root / "res" / "pom.xml").write_text("<project>${version}</project>")   # eşleyici değil
            (root / "node_modules").mkdir()
            (root / "node_modules" / "M.xml").write_text(mapper.replace("UserMapper", "Other"))
            (root / "link.xml").symlink_to(root / "res" / "UserMapper.xml")
            self.assertEqual(joern_active.mybatis_unsafe_statements(root),
                             ["app.mapper.UserMapper.ordered", "app.mapper.UserMapper.vuln"])

    def test_request_only_kinds_drop_external_sources(self):
        lines = "\n".join(json.dumps({"kind": kind, "label": label, "language": "java", "source": "s", "sink": "k",
                                      "steps": [["A.java", line, "m"]]})
                          for line, (kind, label) in enumerate([("redirect", "external"), ("log", "external"),
                                                                ("crlf", "external"), ("xxe", "external"),
                                                                ("redirect", "request")], start=1))
        flows = joern_active.parse_joern_flows(lines)
        self.assertEqual(sorted((f["kind"], f["label"]) for f in flows), [("redirect", "request"), ("xxe", "external")])
        findings = joern_active.flows_to_findings(flows)
        self.assertEqual(sorted(f["reference"] for f in findings), ["CWE-601", "CWE-611"])

    def test_java_frontend_disables_delombok(self):
        manifest = {"files": {"frontends/javasrc2cpg/lib/io.joern.javasrc2cpg-4.0.647-launcher.jar": "x",
                              "frontends/c2cpg/lib/io.joern.c2cpg-4.0.647-launcher.jar": "x"}}
        java = joern_active._frontend_command("/proc/self/fd/3", Path("/h"), manifest, "java", Path("/s"), Path("/c"), Path("/w"))
        self.assertEqual(java[-2:], ["--delombok-mode", "no-delombok"])
        c = joern_active._frontend_command("/proc/self/fd/3", Path("/h"), manifest, "c", Path("/s"), Path("/c"), Path("/w"))
        self.assertNotIn("--delombok-mode", c)


class MultiLanguageTests(unittest.TestCase):
    """PHP/Go/Ruby/C#/Kotlin: kaynak toplama, ön uç hazırlığı, PHP doğrulaması, C# satır düzeltmesi."""

    def test_collect_sources_groups_new_languages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("a.php", "b.go", "c.rb", "d.cs", "e.kt", "f.java", "g.py"):
                (root / name).write_text("x")
            (root / "vendor").mkdir()
            (root / "vendor" / "h.php").write_text("x")
            found = joern_active.collect_sources(root)
            self.assertEqual({k: [p.name for p in v] for k, v in found.items()},
                             {"php": ["a.php"], "go": ["b.go"], "ruby": ["c.rb"], "csharp": ["d.cs"],
                              "kotlin": ["e.kt"], "java": ["f.java"]})

    def test_csharp_lines_are_shifted_to_one_based(self):
        line = json.dumps({"kind": "sql", "label": "request", "language": "csharp", "source": "s", "sink": "k",
                           "steps": [["A.cs", 11, "Show"], ["A.cs", 12, "Show"]]})
        flows = joern_active.parse_joern_flows(line, language="csharp")
        self.assertEqual([s["line"] for s in flows[0]["steps"]], [12, 13])
        self.assertEqual([s["line"] for s in joern_active.parse_joern_flows(line, language="java")[0]["steps"]], [11, 12])

    def _php_home(self, root: Path, binary: bytes, provenance: dict) -> Path:
        (root / "bin").mkdir(parents=True)
        os.chmod(root, 0o755)
        os.chmod(root / "bin", 0o755)
        (root / "bin" / "php").write_bytes(binary)
        os.chmod(root / "bin" / "php", 0o555)
        (root / "provenance.json").write_text(json.dumps(provenance))
        os.chmod(root / "provenance.json", 0o444)
        return root

    def test_verified_php_checks_source_pin_and_binary_hash(self):
        binary = b"\x7fELF php"
        good = {"version": joern_active.PHP_VERSION, "source_sha256": joern_active.PHP_SOURCE_SHA256,
                "binary_sha256": hashlib.sha256(binary).hexdigest()}
        cases = [
            (good, binary, True),
            (dict(good, binary_sha256="0" * 64), binary, False),            # ikili değişmiş
            (dict(good, source_sha256="f" * 64), binary, False),            # resmî kaynak değil
            (dict(good, version="8.2.0"), binary, False),
        ]
        for provenance, data, ok in cases:
            with self.subTest(provenance=provenance), tempfile.TemporaryDirectory() as tmp:
                home = self._php_home(Path(tmp) / "php", data, provenance)
                with mock.patch.object(joern_active, "php_home", return_value=home), \
                        mock.patch.object(joern_active, "PHP_APPROVED_BINARY_SHA256",
                                          {hashlib.sha256(data).hexdigest(): "test approval"}):
                    if ok:
                        self.assertEqual(joern_active.verified_php(), data)
                    else:
                        with self.assertRaises(joern_active.JoernUnavailable):
                            joern_active.verified_php()

    def test_language_status_requires_frontend_and_helpers(self):
        launcher = lambda name: f"frontends/{name}/lib/io.joern.{name}-{joern_active.JOERN_VERSION}-launcher.jar"
        manifest = {"files": {launcher("gosrc2cpg"): "x", launcher("csharpsrc2cpg"): "x",
                              joern_active.FRONTEND_HELPERS["csharp"]: "x", launcher("rubysrc2cpg"): "x"}}
        self.assertEqual(joern_active.language_status("go", manifest)[0], False)       # goastgen yok
        self.assertEqual(joern_active.language_status("csharp", manifest), (True, "hazır"))
        self.assertEqual(joern_active.language_status("ruby", manifest), (True, "hazır"))
        self.assertEqual(joern_active.language_status("kotlin", manifest)[0], False)   # ön uç yok
        with mock.patch.object(joern_active, "verified_php", side_effect=joern_active.JoernUnavailable("PHP yok")):
            manifest["files"][launcher("php2cpg")] = "x"
            manifest["files"][joern_active.FRONTEND_HELPERS["php"]] = "x"
            self.assertEqual(joern_active.language_status("php", manifest), (False, "PHP yok"))


class PatternAndModelTests(unittest.TestCase):
    """Kalıp bulguları (zayıf kripto/rastgelelik/çerez), yapılandırma çözümlemesi, yeni türler."""

    def _record(self, kind, label, detail=None, line=5):
        record = {"kind": kind, "label": label, "language": "java", "source": "", "sink": "x",
                  "steps": [["A.java", line, "doPost"]]}
        if detail is not None:
            record["detail"] = detail
        return json.dumps(record)

    def test_pattern_records_need_pattern_label_and_vice_versa(self):
        lines = "\n".join([
            self._record("weakrand", "pattern"),
            self._record("weakrand", "request"),          # kalıp türü akış etiketiyle gelemez
            self._record("command", "pattern"),            # akış türü kalıp etiketiyle gelemez
            self._record("trustbound", "external"),        # güven sınırı yalnız HTTP girdisi
            self._record("trustbound", "request", line=9),
        ])
        flows = joern_active.parse_joern_flows(lines)
        self.assertEqual(sorted((f["kind"], f["label"]) for f in flows),
                         [("trustbound", "request"), ("weakrand", "pattern")])

    def test_weak_algorithm_resolution_from_literal_property_and_default(self):
        props = {"hashAlg1": "MD5", "hashAlg2": "SHA-256", "cryptoAlg1": "DES/ECB/PKCS5Padding", "cryptoAlg2": "AES/CCM/NoPadding"}
        cases = [
            ("weakhash", {"literal": "SHA1"}, True),
            ("weakhash", {"literal": "sha-384"}, False),
            ("weakhash", {"property": "hashAlg1", "default": "SHA-512"}, True),
            ("weakhash", {"property": "hashAlg2", "default": "MD5"}, False),
            ("weakhash", {"property": "missing", "default": "MD5"}, True),
            ("weakhash", {}, False),
            ("weakcipher", {"literal": "DES/CBC/PKCS5Padding"}, True),
            ("weakcipher", {"literal": "DESede/ECB/PKCS5Padding"}, True),
            ("weakcipher", {"literal": "AES/ECB/PKCS5Padding"}, True),
            ("weakcipher", {"literal": "AES"}, True),
            ("weakcipher", {"literal": "AES/GCM/NoPadding"}, False),
            ("weakcipher", {"property": "cryptoAlg1", "default": "AES/GCM/NoPadding"}, True),
            ("weakcipher", {"property": "cryptoAlg2", "default": "AES/ECB/PKCS5Padding"}, False),
        ]
        for kind, detail, weak in cases:
            with self.subTest(kind=kind, detail=detail):
                flows = joern_active.parse_joern_flows(self._record(kind, "pattern", detail))
                findings = joern_active.flows_to_findings(flows, properties=props)
                self.assertEqual(bool(findings), weak)
                if findings:
                    self.assertEqual(findings[0]["reference"], "CWE-328" if kind == "weakhash" else "CWE-327")
                    self.assertNotIn("taint_flow", findings[0])

    def test_detail_values_are_sanitized_and_bounded(self):
        flows = joern_active.parse_joern_flows(self._record(
            "weakhash", "pattern", {"literal": "MD5<script>" + "x" * 300, "other": "yok"}))
        self.assertEqual(set(flows[0]["detail"]), {"literal"})
        self.assertNotIn("<", flows[0]["detail"]["literal"])
        self.assertLessEqual(len(flows[0]["detail"]["literal"]), 120)

    def test_load_properties_is_bounded_and_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "conf").mkdir()
            (root / "conf" / "app.properties").write_text("# yorum\nhashAlg = MD5\ncipher: DES\n", encoding="utf-8")
            (root / "link.properties").symlink_to(root / "conf" / "app.properties")
            values = joern_active.load_properties(root)
        self.assertEqual(values, {"hashAlg": "MD5", "cipher": "DES"})

    def test_sarif_for_pattern_findings_has_no_code_flow(self):
        flows = joern_active.parse_joern_flows(self._record("insecurecookie", "pattern"))
        findings = joern_active.flows_to_findings(flows)
        sarif = joern_active.render_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        self.assertNotIn("codeFlows", result)
        self.assertEqual(result["ruleId"], "SNIPER-JOERN-INSECURECOOKIE")


class BenchmarkScoringTests(unittest.TestCase):
    @unittest.skipUnless(JOERN_BENCHMARK.is_file(), "maintainer benchmark script is not distributed")
    def test_youden_score_per_category(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("joern_benchmark", Path(__file__).resolve().parents[1] / "scripts" / "joern_benchmark.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expected = {"T1": ("sqli", True), "T2": ("sqli", True), "T3": ("sqli", False), "T4": ("sqli", False),
                    "T5": ("xss", True)}
        table = module.score(expected, {"T1": {"sqli"}, "T3": {"sqli"}, "T5": {"sqli"}})
        self.assertEqual(table["sqli"]["score"], 0.0)   # TPR 0.5 − FPR 0.5
        self.assertEqual(table["xss"]["score"], 0.0)    # yanlış kategori sayılmaz
        self.assertEqual(table["ORTALAMA"]["score"], 0.0)


class SecondOrderAndTailTests(unittest.TestCase):
    def test_stored_label_is_accepted_for_request_only_kinds(self):
        flows = joern_active.parse_joern_flows(_line(kind="xss", label="stored", language="php", source="oturum ← $_POST",
                                                     sink="echo"), workspace=Path("/w/src"), language="php")
        self.assertEqual(len(flows), 1)
        finding = joern_active.flows_to_findings(flows)[0]
        self.assertEqual(finding["taint_flow"]["source_label"], "stored")
        self.assertIn("ikinci derece", finding["evidence"])
        self.assertEqual(finding["severity"], joern_active.KIND_RULES["xss"][1])

    def test_virtual_sink_tail_is_appended_after_call_site(self):
        record = json.loads(_line(kind="xss", label="request", language="csharp", source="Request[]", sink="Show → Text",
                                  steps=[["/w/src/P.cs", 11, "Page_Load"], ["/w/src/P.cs", 12, "Page_Load"]]))
        record["tail"] = [["/w/src/P.cs", 20, "Show"], ["/w/src/P.cs", 22, "Show"], ["/etc/passwd", 1, "x"], "bozuk"]
        flows = joern_active.parse_joern_flows(json.dumps(record), workspace=Path("/w/src"), language="csharp")
        finding = joern_active.flows_to_findings(flows)[0]
        self.assertEqual((finding["file"], finding["line"]), ("P.cs", 13))   # konum çağrı noktası (C# +1)
        self.assertEqual([(s["line"], s.get("method")) for s in finding["steps"]],
                         [(12, "Page_Load"), (13, "Page_Load"), (21, "Show"), (23, "Show")])

    def test_query_script_models_second_order_and_frontend_workarounds(self):
        script = joern_active.QUERY_SCRIPT.read_text(encoding="utf-8")
        for marker in ("bridgeGlobals", "sessionWrites", "dbWriters", "rubyScopes", "helperSeeds", "crossArgument",
                       "onlyThroughCondition", "\"stored\" -> storedSeeds", "tailJson", "preparedWrites",
                       "mysqli_stmt_bind_param"):
            self.assertIn(marker, script)


class CpgCacheTests(unittest.TestCase):
    """Ön uç çıktısının (CPG) aynı kaynak için yeniden kullanımı: sahte çalıştırıcı CPG'ye üretildiği kaynak
    kökünü yazar; sorgu adımı bulgu yolunu CPG'den okur (gerçek Joern'deki mutlak dosya adları gibi)."""

    home = Path("/opt/joern-cli")

    def _manifest(self):
        return RunOrchestrationTests._manifest(self, self.home)

    def _run(self, project: Path, data: Path, commands: list, env: dict | None = None):
        fake_jdk = mock.MagicMock()
        fake_jdk.argv0, fake_jdk.fd, fake_jdk.sha256, fake_jdk.provenance = "/proc/self/fd/9", 9, "a" * 64, "test"
        fake_jdk.__enter__.return_value = fake_jdk
        home = self.home

        def runner(cmd, timeout, env, cwd, pass_fds):
            commands.append(cmd)
            if "--output" in cmd:   # ön uç
                src = Path(cmd[cmd.index("--output") - 1])
                Path(cmd[cmd.index("--output") + 1]).write_text(str(src), encoding="utf-8")
            elif joern_active.SCRIPT_MAIN in cmd:
                cpg, out = Path(cwd) / "c.cpg.bin", Path(cwd) / "c.flows.jsonl"
                fork = ["-classpath", f"{home}/lib/a.jar:{home}/lib/b.jar", "replpp.scripting.NonForkingScriptRunner",
                        "--runBefore", "import x.*", "--script", str(joern_active.QUERY_SCRIPT)]
                for param in joern_active._script_params(cpg, out):
                    fork += ["--param", param]
                (Path(cwd) / "fork-args.bin").write_bytes(("\0".join(fork) + "\0").encode())
            elif "replpp.scripting.NonForkingScriptRunner" in cmd:
                cpg = Path(next(a.split("=", 1)[1] for a in cmd if str(a).startswith("cpgFile=")))
                out = next(a.split("=", 1)[1] for a in cmd if str(a).startswith("outFile="))
                src = cpg.read_text(encoding="utf-8")
                Path(out).write_text(_line(steps=[[f"{src}/main.c", 1, "main"], [f"{src}/main.c", 3, "main"]]),
                                     encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        environ = {"SNIPER_DATA_DIR": str(data), **(env or {})}
        with mock.patch.object(joern_active, "verify_joern_install", return_value=self._manifest()), \
                mock.patch.object(joern_active, "joern_home", return_value=home), \
                mock.patch.object(joern_active, "open_pinned", return_value=fake_jdk), \
                mock.patch.object(joern_active, "available_memory_gb", return_value=64.0), \
                mock.patch.object(joern_active, "launch_mode", return_value="direct"), \
                mock.patch.dict(os.environ, environ):
            return joern_active.run_joern_deep(str(project), runner=runner)

    def _frontends(self, commands):
        return sum(1 for cmd in commands if "--output" in cmd)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name) / "data"
        self.data.mkdir(mode=0o700)
        self.proj_dir = tempfile.TemporaryDirectory(dir=Path.home() / ".cache")
        self.project = Path(self.proj_dir.name)
        (self.project / "main.c").write_text("int main(){ system(getenv(\"X\")); }", encoding="utf-8")

    def tearDown(self):
        self.proj_dir.cleanup()
        self.tmp.cleanup()

    def _summary(self, result):
        return [(f["file"], f["line"], f["control_id"]) for f in result["findings"]]

    def test_second_run_skips_frontend_and_results_match(self):
        first_cmds, second_cmds = [], []
        first = self._run(self.project, self.data, first_cmds)
        second = self._run(self.project, self.data, second_cmds)
        self.assertEqual((self._frontends(first_cmds), self._frontends(second_cmds)), (1, 0))
        self.assertEqual(first["cpg_cache_hits"], [])
        self.assertEqual(second["cpg_cache_hits"], ["c"])
        self.assertEqual(self._summary(first), self._summary(second))
        self.assertEqual(self._summary(second)[0][0], "main.c")   # eski kökten göreli yola çevrildi
        cache = self.data / joern_active.CPG_CACHE_DIRNAME
        self.assertEqual(cache.stat().st_mode & 0o777, 0o700)
        entry = next(p for p in cache.iterdir() if not p.name.startswith("."))
        self.assertEqual((entry / "cpg.bin").stat().st_mode & 0o777, 0o600)

    def test_changed_source_tampered_entry_and_disabled_cache_miss(self):
        self._run(self.project, self.data, [])
        (self.project / "main.c").write_text("int main(){ return 0; }", encoding="utf-8")
        cmds = []
        self._run(self.project, self.data, cmds)
        self.assertEqual(self._frontends(cmds), 1)
        cache = self.data / joern_active.CPG_CACHE_DIRNAME
        for entry in cache.iterdir():
            if not entry.name.startswith("."):
                (entry / "cpg.bin").write_text("bozuk", encoding="utf-8")
        cmds = []
        self._run(self.project, self.data, cmds)
        self.assertEqual(self._frontends(cmds), 1)
        cmds = []
        self._run(self.project, self.data, cmds, env={"SNIPER_JOERN_CPG_CACHE": "0"})
        self.assertEqual(self._frontends(cmds), 1)

    def test_unsafe_cache_directory_and_symlinked_entry_are_ignored(self):
        cache = self.data / joern_active.CPG_CACHE_DIRNAME
        cache.mkdir(mode=0o700)
        os.chmod(cache, 0o770)
        with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data)}):
            self.assertIsNone(joern_active.cpg_cache_dir())
        os.chmod(cache, 0o700)
        self._run(self.project, self.data, [])
        entry = next(p for p in cache.iterdir() if not p.name.startswith("."))
        moved = Path(self.tmp.name) / "elsewhere"
        entry.rename(moved)
        entry.symlink_to(moved, target_is_directory=True)
        cmds = []
        self._run(self.project, self.data, cmds)
        self.assertEqual(self._frontends(cmds), 1)
        self.assertFalse(entry.is_symlink())   # temizlikte bağ kaldırıldı, hedefine dokunulmadı
        self.assertTrue((moved / "cpg.bin").is_file())

    def test_prune_keeps_most_recently_used_within_limits(self):
        cache = self.data / joern_active.CPG_CACHE_DIRNAME
        cache.mkdir(mode=0o700)
        for index in range(4):
            key = hashlib.sha256(str(index).encode()).hexdigest()
            entry = cache / key
            entry.mkdir(mode=0o700)
            (entry / "cpg.bin").write_bytes(b"x" * 100)
            (entry / "meta.json").write_text("{}", encoding="utf-8")
            os.utime(entry / "meta.json", (1000 + index, 1000 + index))
        stale = cache / ".tmp-eski"
        stale.mkdir()
        os.utime(stale, (1, 1))
        joern_active.cpg_cache_prune(cache, max_bytes=250, max_entries=10)
        left = sorted(p.name for p in cache.iterdir())
        self.assertEqual(left, sorted(hashlib.sha256(str(i).encode()).hexdigest() for i in (2, 3)))
        joern_active.cpg_cache_prune(cache, max_bytes=10_000, max_entries=1)
        self.assertEqual([p.name for p in cache.iterdir()], [hashlib.sha256(b"3").hexdigest()])

    def test_cache_key_covers_language_options_and_ignores_heap(self):
        src = Path(self.tmp.name) / "src"
        src.mkdir()
        (src / "a.c").write_text("x", encoding="utf-8")
        manifest = self._manifest()
        key = joern_active.cpg_cache_key("c", src, manifest)
        with mock.patch.object(joern_active, "heap_gb", return_value=6):
            self.assertEqual(joern_active.cpg_cache_key("c", src, manifest), key)
        self.assertNotEqual(joern_active.cpg_cache_key("java", src, manifest), key)
        (src / "a.c").write_text("y", encoding="utf-8")
        self.assertNotEqual(joern_active.cpg_cache_key("c", src, manifest), key)


@unittest.skipUnless(os.environ.get("SNIPER_JOERN_INTEGRATION") == "1", "Joern entegrasyon testi (SNIPER_JOERN_INTEGRATION=1)")
class JoernIntegrationTests(unittest.TestCase):
    def test_fixtures(self):
        with tempfile.TemporaryDirectory() as data, mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": data}):
            result = joern_active.run_joern_deep(str(FIXTURES))
        got = {(f["file"], f["line"], f["control_id"].split("SNIPER-JOERN-")[1].lower()) for f in result["findings"]}
        expected = set()
        for path in FIXTURES.rglob("*"):
            if path.is_file():
                for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                    if "EXPECT:" in text:
                        expected.add((str(path.relative_to(FIXTURES)), number, text.split("EXPECT:")[1].split()[0].lower()))
        self.assertEqual(got, expected)


if __name__ == "__main__":
    unittest.main()


class JoernSystemdLaunchTests(unittest.TestCase):
    def test_launch_mode_detects_service(self):
        import joern_active
        with mock.patch.dict(os.environ, {"INVOCATION_ID": "x", "SNIPER_JOERN_LAUNCH": "auto"}):
            self.assertEqual(joern_active.launch_mode(), "systemd-run")
        with mock.patch.dict(os.environ, {"SNIPER_JOERN_LAUNCH": "direct", "INVOCATION_ID": "x"}):
            self.assertEqual(joern_active.launch_mode(), "direct")

    def test_systemd_runner_hardens_unit_and_stops_it_on_failure(self):
        import subprocess as sp
        import joern_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            java = Path(temp) / "java"
            java.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            java.chmod(0o700)
            digest = hashlib.sha256(java.read_bytes()).hexdigest()
            jdk = open_verified_executable(java, {digest: "test"}, label="Java")
            calls = []
            failed = sp.CompletedProcess([], 3, b"", b"")
            with jdk, mock.patch.object(
                    joern_active, "run_in_process_group", side_effect=lambda cmd, **kw: (calls.append(cmd), failed)[1]
            ), mock.patch.object(joern_active.subprocess, "run") as stop:
                runner = joern_active._systemd_runner(jdk)
                result = runner(
                    [jdk.argv0, "-Xmx4g", "-jar", "x.jar"], 60,
                    joern_active._environment(Path("/w")), Path("/w"), (jdk.fd,),
                )
        self.assertEqual(result.returncode, 3)
        command = calls[0]
        self.assertIn("--user", command)
        for prop in ("MemoryDenyWriteExecute", ):
            self.assertFalse(any(prop in part for part in command))
        for prop in ("NoNewPrivileges=yes", "RestrictAddressFamilies=AF_UNIX", "ProtectHome=read-only", "ReadWritePaths=/w"):
            self.assertIn(prop, command)
        launcher = command.index(str(joern_active.SYSTEM_PYTHON))
        self.assertEqual(command[launcher + 1:launcher + 3], ["-I", "-c"])
        self.assertEqual(command[-3:], ["-Xmx4g", "-jar", "x.jar"])
        self.assertNotEqual(command[launcher], str(java))
        self.assertIn("HOME=/w", command)
        stop.assert_called_once()
        self.assertEqual(stop.call_args[0][0][:3], ["/usr/bin/systemctl", "--user", "stop"])

    def test_systemd_payload_rejects_path_swap_instead_of_executing_replacement(self):
        import joern_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            java = root / "java"
            marker = root / "PWNED-PATH-WAS-EXECUTED"
            java.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            java.chmod(0o700)
            digest = hashlib.sha256(java.read_bytes()).hexdigest()
            jdk = open_verified_executable(java, {digest: "test"}, label="Java")
            runner = joern_active._systemd_runner(jdk)
            java.rename(root / "verified-java")
            java.write_text(f"#!/bin/sh\nprintf PWNED > '{marker}'\n", encoding="utf-8")
            java.chmod(0o700)

            def execute_payload(command, **kwargs):
                start = command.index(str(joern_active.SYSTEM_PYTHON))
                return subprocess.run(
                    command[start:], cwd=kwargs["cwd"], env=kwargs["env"],
                    stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], check=False,
                )

            with jdk, mock.patch.object(joern_active, "run_in_process_group", side_effect=execute_payload), \
                    mock.patch.object(joern_active.subprocess, "run"):
                result = runner(
                    [jdk.argv0, "ignored"], 10, joern_active._environment(root), root, (jdk.fd,),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_systemd_payload_rejects_non_ga_java_before_workload(self):
        import joern_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            java = root / "java"
            marker = root / "NON-GA-WORKLOAD-WAS-EXECUTED"
            java.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = -version ]; then\n"
                "  printf '%s\\n' 'openjdk version \"25.0.4.1-ea\" 2026-08-18 LTS' >&2\n"
                "  printf '%s\\n' 'OpenJDK Runtime Environment Temurin-25.0.4.1-ea+1 "
                "(build 25.0.4.1-ea+1-LTS)' >&2\n"
                "  printf '%s\\n' 'OpenJDK 64-Bit Server VM Temurin-25.0.4.1-ea+1 "
                "(build 25.0.4.1-ea+1-LTS, mixed mode, sharing)' >&2\n"
                "  exit 0\n"
                "fi\n"
                f"printf PWNED > '{marker}'\n",
                encoding="utf-8",
            )
            java.chmod(0o700)
            digest = hashlib.sha256(java.read_bytes()).hexdigest()
            jdk = open_verified_executable(java, {digest: "test"}, label="Java")
            runner = joern_active._systemd_runner(jdk)

            def execute_payload(command, **kwargs):
                start = command.index(str(joern_active.SYSTEM_PYTHON))
                return subprocess.run(
                    command[start:], cwd=kwargs["cwd"], env=kwargs["env"],
                    stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], check=False,
                )

            with jdk, mock.patch.object(joern_active, "run_in_process_group", side_effect=execute_payload), \
                    mock.patch.object(joern_active.subprocess, "run"):
                result = runner(
                    [jdk.argv0, "ignored"], 10, joern_active._environment(root), root, (jdk.fd,),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_systemd_payload_exec_environment_is_exact_allowlist(self):
        import joern_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            java = root / "java"
            captured = root / "workload.env"
            java.write_text(
                "#!/usr/bin/python3\n"
                "import os, sys\n"
                "if sys.argv[1:] == ['-version']:\n"
                "    sys.stderr.write('openjdk version \\\"25.0.4.1\\\" 2026-08-18 LTS\\n')\n"
                "    sys.stderr.write('OpenJDK Runtime Environment Temurin-25.0.4.1+1 "
                "(build 25.0.4.1+1-LTS)\\n')\n"
                "    sys.stderr.write('OpenJDK 64-Bit Server VM Temurin-25.0.4.1+1 "
                "(build 25.0.4.1+1-LTS, mixed mode, sharing)\\n')\n"
                "    raise SystemExit(0)\n"
                "with open(sys.argv[1], 'wb') as stream:\n"
                "    stream.write(b'\\n'.join(key + b'=' + value for key, value in "
                "sorted(os.environb.items())))\n",
                encoding="utf-8",
            )
            java.chmod(0o700)
            digest = hashlib.sha256(java.read_bytes()).hexdigest()
            jdk = open_verified_executable(java, {digest: "test"}, label="Java")
            runner = joern_active._systemd_runner(jdk)
            expected_env = joern_active._environment(root)

            def execute_payload(command, **kwargs):
                start = command.index(str(joern_active.SYSTEM_PYTHON))
                unit_env = dict(kwargs["env"])
                for index, item in enumerate(command[:-1]):
                    if item == "-E":
                        key, value = command[index + 1].split("=", 1)
                        unit_env[key] = value
                unit_env.update({
                    "JDK_JAVA_OPTIONS": "-Dsniper.review.injected=true",
                    "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/review-agent.jar",
                    "_JAVA_OPTIONS": "-Dsniper.review.underscore=true",
                    "HTTPS_PROXY": "http://127.0.0.1:9",
                    "SNIPER_REVIEW_MANAGER_SECRET": "must-not-leak",
                })
                return subprocess.run(
                    command[start:], cwd=kwargs["cwd"], env=unit_env,
                    stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], check=False,
                )

            with jdk, mock.patch.object(joern_active, "run_in_process_group", side_effect=execute_payload):
                result = runner([jdk.argv0, str(captured)], 10, expected_env, root, (jdk.fd,))
            self.assertEqual(result.returncode, 0)
            got = dict(line.split("=", 1) for line in captured.read_text(encoding="utf-8").splitlines())
            self.assertEqual(got, expected_env)

    def test_systemd_runner_rejects_unexpected_environment_contract(self):
        import joern_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            java = root / "java"
            java.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            java.chmod(0o700)
            digest = hashlib.sha256(java.read_bytes()).hexdigest()
            jdk = open_verified_executable(java, {digest: "test"}, label="Java")
            runner = joern_active._systemd_runner(jdk)
            bad_env = {**joern_active._environment(root), "JDK_JAVA_OPTIONS": "-Dsniper.review.injected=true"}
            with jdk, mock.patch.object(joern_active, "run_in_process_group") as run:
                with self.assertRaises(joern_active.JoernExecutionError):
                    runner([jdk.argv0, "-version"], 10, bad_env, root, (jdk.fd,))
            run.assert_not_called()

    def test_systemd_payload_rejects_duplicate_environment_key(self):
        import joern_active
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            java = root / "java"
            marker = root / "DUPLICATE-ENV-WORKLOAD-WAS-EXECUTED"
            java.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = -version ]; then\n"
                "  printf '%s\\n' 'openjdk version \"25.0.4.1\" 2026-08-18 LTS' >&2\n"
                "  printf '%s\\n' 'OpenJDK Runtime Environment Temurin-25.0.4.1+1 "
                "(build 25.0.4.1+1-LTS)' >&2\n"
                "  printf '%s\\n' 'OpenJDK 64-Bit Server VM Temurin-25.0.4.1+1 "
                "(build 25.0.4.1+1-LTS, mixed mode, sharing)' >&2\n"
                "  exit 0\n"
                "fi\n"
                f"printf PWNED > '{marker}'\n",
                encoding="utf-8",
            )
            java.chmod(0o700)
            digest = hashlib.sha256(java.read_bytes()).hexdigest()
            jdk = open_verified_executable(java, {digest: "test"}, label="Java")
            runner = joern_active._systemd_runner(jdk)

            def execute_payload(command, **kwargs):
                command = list(command)
                start = command.index(str(joern_active.SYSTEM_PYTHON))
                first_entry = start + 11
                last_entry = first_entry + len(joern_active.SYSTEMD_JAVA_ENV_KEYS) - 1
                command[last_entry] = command[first_entry]
                return subprocess.run(
                    command[start:], cwd=kwargs["cwd"], env=kwargs["env"],
                    stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], check=False,
                )

            with jdk, mock.patch.object(joern_active, "run_in_process_group", side_effect=execute_payload), \
                    mock.patch.object(joern_active.subprocess, "run"):
                result = runner(
                    [jdk.argv0, "ignored"], 10, joern_active._environment(root), root, (jdk.fd,),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
