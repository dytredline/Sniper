"""25. tur: Joern JS/TS (jssrc2cpg) ve Python (pysrc2cpg) ön uçları, hızlı motorla karma kullanım, kısmi sonuç."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import joern_active
from project_analyzer import ProjectRejected

HOME = Path("/opt/joern-cli")
SCRIPT = joern_active.QUERY_SCRIPT.read_text(encoding="utf-8")


def _launcher(name):
    return f"frontends/{name}/lib/io.joern.{name}-{joern_active.JOERN_VERSION}-launcher.jar"


def _manifest():
    files = {"lib/a.jar": "x"}
    for name in ("c2cpg", "pysrc2cpg", "jssrc2cpg"):
        files[_launcher(name)] = "y"
    files[joern_active.FRONTEND_HELPERS["javascript"]] = "z"
    return {"files": files}


def _record(kind, label, language, source, sink, steps):
    return json.dumps({"kind": kind, "label": label, "language": language, "source": source, "sink": sink,
                       "steps": steps})


class LanguageTableTests(unittest.TestCase):
    def test_frontends_and_extensions(self):
        self.assertEqual(joern_active.FRONTENDS["javascript"], "jssrc2cpg")
        self.assertEqual(joern_active.FRONTENDS["python"], "pysrc2cpg")
        self.assertIn(".tsx", joern_active.LANGUAGE_EXTENSIONS["javascript"])
        self.assertIn(".py", joern_active.LANGUAGE_EXTENSIONS["python"])
        self.assertEqual(joern_active.SCRIPTING_LANGUAGES, frozenset({"javascript", "python"}))
        # jssrc2cpg'nin astgen ikilisi kurulum manifestiyle doğrulanır; pysrc2cpg saf JVM.
        self.assertTrue(joern_active.FRONTEND_HELPERS["javascript"].startswith("frontends/jssrc2cpg/bin/astgen/"))
        self.assertNotIn("python", joern_active.FRONTEND_HELPERS)
        self.assertIn("frontends/pysrc2cpg/lib", joern_active.CLASSPATH_DIRS)
        self.assertEqual(joern_active.LANGUAGE_NAMES["javascript"], "JavaScript/TypeScript")
        self.assertEqual(joern_active.KIND_RULES["ssti"][0], "CWE-1336")

    def test_language_status_requires_astgen_in_manifest(self):
        manifest = _manifest()
        self.assertEqual(joern_active.language_status("python", manifest), (True, "hazır"))
        self.assertEqual(joern_active.language_status("javascript", manifest), (True, "hazır"))
        del manifest["files"][joern_active.FRONTEND_HELPERS["javascript"]]
        self.assertFalse(joern_active.language_status("javascript", manifest)[0])

    def test_default_is_off(self):
        with mock.patch.dict(os.environ, {"SNIPER_JOERN_SCRIPTING": ""}):
            self.assertFalse(joern_active.scripting_default())
        with mock.patch.dict(os.environ, {"SNIPER_JOERN_SCRIPTING": "1"}):
            self.assertTrue(joern_active.scripting_default())


class CollectTests(unittest.TestCase):
    def _tree(self, root: Path):
        for rel, text in {"main.c": "int main(){}", "app.py": "x = 1", "web/a.js": "1", "web/b.ts": "1",
                          "web/c.min.js": "1", "web/types.d.ts": "1", "node_modules/x/i.js": "1"}.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def test_scripting_files_only_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._tree(root)
            self.assertEqual(set(joern_active.collect_sources(root)), {"c"})
            found = joern_active.collect_sources(root, scripting=True)
            self.assertEqual(set(found), {"c", "python", "javascript"})
            self.assertEqual(sorted(p.name for p in found["javascript"]), ["a.js", "b.ts"])

    def test_script_budget_drops_with_warning_instead_of_rejecting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._tree(root)
            warnings = []
            with mock.patch.object(joern_active, "MAX_SCRIPT_FILES", 1):
                found = joern_active.collect_sources(root, scripting=True, warnings=warnings)
            self.assertEqual(sum(len(found.get(k, [])) for k in ("python", "javascript")), 1)
            self.assertEqual(found["c"][0].name, "main.c")
            self.assertEqual(len(warnings), 1)
            self.assertIn("2 dosya", warnings[0])

    def test_python_only_project_explains_option(self):
        with tempfile.TemporaryDirectory(dir=Path.home() / ".cache") as proj:
            (Path(proj) / "app.py").write_text("x = 1", encoding="utf-8")
            with mock.patch.dict(os.environ, {"SNIPER_JOERN_SCRIPTING": "0"}):
                with self.assertRaisesRegex(ProjectRejected, "JS/TS ve Python dahil"):
                    joern_active.run_joern_deep(proj)


class QueryScriptTests(unittest.TestCase):
    def test_language_detection_and_models(self):
        self.assertIn('language.contains("JSSRC")', SCRIPT)
        self.assertIn('else if (language.contains("PYTHON")) "python"', SCRIPT)
        # JAVASCRIPT adı Java sanılmamalı.
        self.assertIn('!language.contains("JAVASCRIPT")', SCRIPT)
        self.assertIn('case "javascript" =>', SCRIPT)
        self.assertIn('case "python" =>', SCRIPT)
        self.assertIn('Set("php", "go", "ruby", "csharp", "javascript", "python").contains(lang)', SCRIPT)
        for needle in ("child_process:(exec|", "__builtin\\\\.(eval|exec|compile)", "render_template_string",
                       "SCRIPT_SANITIZERS", "secure_filename", "scriptAstSanitized", "SCRIPT_BARRIERS",
                       "def fixedPathPrefix", "fastapiFiles", ".filter(htmlText)", "def fixedHost",
                       "scriptRedirectChecked", 'annotation.name("Query|Param|Body|Headers',
                       'id.name == "self" || id.name == "this"', "read_text|read_bytes|readFileSync"):
            self.assertIn(needle, SCRIPT)
        # Ortam değişkenleri JS/Python'da dış girdi sayılmaz (yapılandırma gürültüsü).
        self.assertNotIn('"process\\\\.(argv|env)"', SCRIPT)

    def test_partial_output_is_flushed_per_line(self):
        self.assertIn("new java.io.FileOutputStream(outFile), \"UTF-8\"), true)", SCRIPT)
        self.assertIn("val sinkGroups", SCRIPT)

    def test_parse_accepts_new_languages_and_ssti(self):
        text = "\n".join([
            _record("ssti", "request", "python", "request.args", "render_template_string",
                    [["/w/app.py", 5, "tpl"], ["/w/app.py", 6, "tpl"]]),
            _record("xss", "request", "javascript", "req.query", "send", [["/w/a.js", 2, "x"], ["/w/a.js", 3, "x"]]),
        ])
        flows = joern_active.parse_joern_flows(text, workspace=Path("/w"))
        self.assertEqual([(f["kind"], f["language"]) for f in flows], [("ssti", "python"), ("xss", "javascript")])
        findings = joern_active.flows_to_findings(flows)
        self.assertEqual(findings[0]["reference"], "CWE-1336")
        self.assertEqual(findings[0]["severity"], "critical")


class RedirectSourceTests(unittest.TestCase):
    def test_path_only_sources_are_not_open_redirects(self):
        def rec(source, language="python", line=4):
            return _record("redirect", "request", language, source, "HttpResponseRedirect",
                           [["/w/v.py", 3, "m"], ["/w/v.py", line, "m"]])
        text = "\n".join([rec("request.path"), rec("req.originalUrl", "javascript"), rec("request.GET"),
                          rec("request.path", "java", 9)])
        flows = joern_active.parse_joern_flows(text, workspace=Path("/w"))
        self.assertEqual([(f["source"], f["language"]) for f in flows], [("request.GET", "python"), ("request.path", "java")])


class HybridAnnotationTests(unittest.TestCase):
    APP = ('from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n\n'
           '@app.route("/p")\ndef p():\n    h = request.args.get("h")\n'
           '    return subprocess.check_output("ping " + h, shell=True)\n')

    def test_marks_match_and_joern_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(self.APP, encoding="utf-8")
            sources = {"python": [root / "app.py"]}
            findings = [
                {"file": "app.py", "line": 8, "evidence": "e", "taint_flow": {"sink_kind": "command"}},
                {"file": "app.py", "line": 3, "evidence": "e", "taint_flow": {"sink_kind": "sql"}},
                {"file": "Main.java", "line": 3, "evidence": "e", "taint_flow": {"sink_kind": "sql"}},
            ]
            summary = joern_active.annotate_scripting_fast_engine(root, sources, findings)
        self.assertTrue(summary["available"])
        self.assertGreaterEqual(summary["python"]["fast_flows"], 1)
        self.assertTrue(findings[0].get("fast_engine_match"))
        self.assertTrue(findings[1].get("joern_only"))
        self.assertNotIn("joern_only", findings[2])  # JS/Python dışı bulgular etiketlenmez
        self.assertEqual((summary["matched"], summary["joern_only"]), (1, 1))

    def test_ssti_matches_fast_eval_flow(self):
        app = ('from flask import Flask, request\nfrom jinja2 import Template\napp = Flask(__name__)\n\n'
               '@app.route("/t")\ndef t():\n    return Template(request.args.get("x")).render()\n')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(app, encoding="utf-8")
            findings = [{"file": "app.py", "line": 7, "evidence": "e", "taint_flow": {"sink_kind": "ssti"}}]
            summary = joern_active.annotate_scripting_fast_engine(root, {"python": [root / "app.py"]}, findings)
        self.assertTrue(summary["available"])
        self.assertTrue(findings[0].get("fast_engine_match") or findings[0].get("fast_engine_uncertain")
                        or findings[0].get("joern_only"))

    def test_no_scripting_sources(self):
        self.assertIsNone(joern_active.annotate_scripting_fast_engine(Path("/"), {"c": []}, []))


class PartialRunTests(unittest.TestCase):
    """Sahte çalıştırıcı: C tamamlanır; JS sorgusu bütçede kesilir (kısmi çıktı) ya da JS ön ucu başarısız olur.
    Diller LANGUAGE_EXTENSIONS sırasıyla işlenir (C → JS → Python)."""

    def _run(self, runner, budget=900.0):
        fake_jdk = mock.MagicMock()
        fake_jdk.argv0, fake_jdk.fd, fake_jdk.sha256, fake_jdk.provenance = "/proc/self/fd/9", 9, "a" * 64, "test"
        fake_jdk.__enter__.return_value = fake_jdk
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory(dir=Path.home() / ".cache") as proj:
            root = Path(proj)
            (root / "main.c").write_text("int main(){}", encoding="utf-8")
            (root / "app.py").write_text("x = 1\n", encoding="utf-8")
            (root / "web.js").write_text("x = 1\n", encoding="utf-8")
            with mock.patch.object(joern_active, "verify_joern_install", return_value=_manifest()), \
                    mock.patch.object(joern_active, "joern_home", return_value=HOME), \
                    mock.patch.object(joern_active, "open_pinned", return_value=fake_jdk), \
                    mock.patch.object(joern_active, "available_memory_gb", return_value=64.0), \
                    mock.patch.object(joern_active, "annotate_scripting_fast_engine", return_value={"available": True}), \
                    mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": data, "SNIPER_JOERN_CPG_CACHE": "0"}):
                return joern_active.run_joern_deep(proj, runner=runner, scripting=True, timeout=budget)

    def _runner(self, behaviour):
        def runner(cmd, timeout, env, cwd, pass_fds):
            cwd = Path(cwd)
            if "-jar" in cmd:
                language = next(lang for lang, name in joern_active.FRONTENDS.items()
                                if f"/{name}/lib/" in cmd[cmd.index("-jar") + 1])
                (cwd / f"{language}.cpg.bin").write_bytes(b"cpg")
                if behaviour.get(language) == "frontend-fail":
                    return subprocess.CompletedProcess(cmd, 1, b"", b"")
                runner.current = language
                return subprocess.CompletedProcess(cmd, 0, b"", b"")
            language = runner.current
            cpg, out = cwd / f"{language}.cpg.bin", cwd / f"{language}.flows.jsonl"
            if joern_active.SCRIPT_MAIN in cmd:
                fork = ["-classpath", f"{HOME}/lib/a.jar", "replpp.scripting.NonForkingScriptRunner",
                        "--script", str(joern_active.QUERY_SCRIPT)]
                for param in joern_active._script_params(cpg, out):
                    fork += ["--param", param]
                (cwd / "fork-args.bin").write_bytes(("\0".join(fork) + "\0").encode())
                return subprocess.CompletedProcess(cmd, 0, b"", b"")
            src = str(cwd / f"src-{language}")
            name = {"c": "main.c", "python": "app.py", "javascript": "web.js"}[language]
            line = _record("command", "request" if language != "c" else "external", language, "girdi", "system",
                           [[f"{src}/{name}", 1, "m"], [f"{src}/{name}", 1, "m"]])
            if behaviour.get(language) == "query-timeout":
                out.write_text(line + "\n{\"yarım", encoding="utf-8")
                raise subprocess.TimeoutExpired(cmd, timeout)
            out.write_text(line + "\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        runner.current = None
        return runner

    def test_query_timeout_returns_partial_with_warning(self):
        result = self._run(self._runner({"javascript": "query-timeout"}))
        self.assertTrue(result["partial"])
        # Yarım kalan son satır atlanır; kesilmeden önce yazılan akış korunur, sonraki dil (Python) çalışmaz.
        self.assertEqual(sorted(f["file"] for f in result["findings"]), ["main.c", "web.js"])
        self.assertIn("Python", result["skipped_languages"])
        self.assertTrue(any("kısmi sonuç" in w for w in result["warnings"]))
        self.assertTrue(result["scripting"])

    def test_scripting_frontend_failure_keeps_other_languages(self):
        result = self._run(self._runner({"javascript": "frontend-fail"}))
        self.assertFalse(result["partial"])
        self.assertEqual(sorted(f["file"] for f in result["findings"]), ["app.py", "main.c"])
        self.assertIn("JavaScript/TypeScript", result["skipped_languages"])
        self.assertTrue(any("tamamlanamadı" in w for w in result["warnings"]))

    def test_core_language_failure_still_raises(self):
        with self.assertRaises(joern_active.JoernExecutionError):
            self._run(self._runner({"c": "frontend-fail"}))

    def test_timeout_before_any_output_raises(self):
        def runner(cmd, timeout, env, cwd, pass_fds):
            raise subprocess.TimeoutExpired(cmd, timeout)
        with self.assertRaisesRegex(joern_active.JoernExecutionError, "zaman aşımı"):
            self._run(runner)


class ServerRouteTests(unittest.TestCase):
    def test_route_validates_optional_fields(self):
        source = (Path(joern_active.__file__).parent / "server.py").read_text(encoding="utf-8")
        self.assertIn('"include_scripting", "time_budget_seconds"', source)
        self.assertIn("run_joern_deep(project_path, scripting=include_scripting", source)


@unittest.skipUnless(os.environ.get("SNIPER_JOERN_REAL") == "1", "gerçek Joern koşusu için SNIPER_JOERN_REAL=1")
class RealJoernTests(unittest.TestCase):
    """Kurulu Joern ile küçük Flask/Express örneği (en çok 6 GB yığın, tek süreç)."""

    def test_real_flask_and_express(self):
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory(dir=Path.home() / ".cache") as proj:
            root = Path(proj)
            (root / "app.py").write_text(HybridAnnotationTests.APP, encoding="utf-8")
            (root / "server.js").write_text(
                "const cp = require('child_process');\nconst express = require('express');\nconst app = express();\n"
                "app.get('/a', (req, res) => { cp.execSync('ls ' + req.query.dir); res.send('ok'); });\n"
                "app.get('/b', (req, res) => { const m = /x/.exec(req.query.q); res.json({ m }); });\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": data, "SNIPER_JOERN_LAUNCH": "direct"}):
                result = joern_active.run_joern_deep(proj, scripting=True, timeout=600)
        located = {(f["file"], f["line"], f["reference"]) for f in result["findings"]}
        self.assertIn(("app.py", 8, "CWE-78"), located)
        self.assertIn(("server.js", 4, "CWE-78"), located)
        self.assertFalse(any(f["file"] == "server.js" and f["line"] == 5 for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
