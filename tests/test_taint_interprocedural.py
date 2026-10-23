import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import taint_flow
import taint_models
from taint_flow import analyze_python, analyze_python_files


def _sinks(analysis):
    return sorted((flow.sink_kind, flow.line) for flow in analysis.flows)


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


class SameFileInterproceduralTests(unittest.TestCase):
    def test_parameter_reaches_sink_through_helper_chain(self):
        source = _src("""
            import os
            from flask import request

            def run(cmd):
                os.system(cmd)

            def wrap(value):
                run("ls " + value)

            @app.route("/x")
            def view():
                wrap(request.args["q"])
        """)
        analysis = analyze_python(source)
        self.assertEqual(_sinks(analysis), [("command", 5)])
        flow = analysis.flows[0]
        self.assertEqual(flow.source, "request.args")
        self.assertEqual(flow.source_line, 12)
        self.assertIn("wrap()", flow.via)
        self.assertIn("run()", flow.via)

    def test_unreached_helper_sink_is_evaluated_clean(self):
        source = _src("""
            import os

            def run(cmd):
                os.system(cmd)

            run("ls -l")
        """)
        analysis = analyze_python(source)
        self.assertEqual(analysis.flows, [])
        self.assertTrue(analysis.is_clean_sink("command", 4))

    def test_return_value_propagation_and_sanitizing_helpers(self):
        source = _src("""
            import os
            from flask import request

            def passthrough(value):
                return value.strip()

            def as_number(value):
                return int(value)

            def quoted(value):
                import shlex
                return shlex.quote(value)

            @app.route("/x")
            def view():
                os.system("a " + passthrough(request.args["a"]))
                os.system("b " + as_number(request.args["b"]))
                os.system("c " + quoted(request.args["c"]))
        """)
        self.assertEqual(_sinks(analyze_python(source)), [("command", 16)])

    def test_function_returning_a_source(self):
        source = _src("""
            from flask import request

            def term():
                return request.args.get("q")

            def view():
                cursor.execute("SELECT * FROM t WHERE a = '" + term() + "'")
        """)
        analysis = analyze_python(source)
        self.assertEqual(_sinks(analysis), [("sql", 7)])
        self.assertEqual(analysis.flows[0].source_line, 4)

    def test_methods_self_calls_typed_instances_and_inheritance(self):
        source = _src("""
            import subprocess
            from flask import request

            class Base:
                def execute(self, command):
                    subprocess.run(command, shell=True)

            class Runner(Base):
                def start(self, name):
                    self.execute("start " + name)

            def helper(runner: Runner, value):
                runner.start(value)

            @app.route("/a")
            def a():
                r = Runner()
                r.start(request.args["x"])

            @app.route("/b")
            def b():
                helper(Runner(), request.args["y"])
        """)
        analysis = analyze_python(source)
        self.assertEqual(_sinks(analysis), [("command", 6), ("command", 6)])
        self.assertEqual(sorted(flow.source_line for flow in analysis.flows), [18, 22])

    def test_recursion_terminates(self):
        source = _src("""
            import os
            from flask import request

            def walk(value, depth):
                if depth > 3:
                    os.system(value)
                    return value
                return walk(value, depth + 1)

            @app.route("/x")
            def view():
                walk(request.args["q"], 0)
        """)
        analysis = analyze_python(source)
        self.assertIsNotNone(analysis)
        self.assertEqual(_sinks(analysis), [("command", 6)])

    def test_nested_function_resolved_locally(self):
        source = _src("""
            import os
            from flask import request

            @app.route("/x")
            def view():
                def inner(cmd):
                    os.system(cmd)
                inner(request.args["q"])
        """)
        self.assertEqual(_sinks(analyze_python(source)), [("command", 7)])


class GuardTests(unittest.TestCase):
    def _flows(self, body):
        source = "import os, re\nfrom flask import request, abort\nALLOWED = {'a', 'b'}\n" + _src(body)
        return _sinks(analyze_python(source))

    def test_allowlist_guard_with_abort(self):
        self.assertEqual(self._flows("""
            @app.route("/x")
            def view():
                name = request.args["n"]
                if name not in ALLOWED:
                    abort(400)
                os.system("run " + name)
        """), [])

    def test_guard_only_cleans_inside_positive_branch(self):
        self.assertEqual(self._flows("""
            @app.route("/x")
            def view():
                name = request.args["n"]
                if name in ALLOWED:
                    os.system("ok " + name)
                os.system("run " + name)
        """), [("command", 9)])

    def test_predicates_regex_and_isinstance(self):
        self.assertEqual(self._flows("""
            @app.route("/x")
            def view():
                a = request.args["a"]
                b = request.args["b"]
                c = request.json["c"]
                if not a.isdigit():
                    return "no"
                if not re.fullmatch(r"[a-z]+", b):
                    raise ValueError(b)
                if not isinstance(c, int):
                    return "no"
                os.system(a + b + str(c))
        """), [])

    def test_unanchored_regex_match_is_not_a_guard(self):
        self.assertEqual(self._flows("""
            @app.route("/x")
            def view():
                a = request.args["a"]
                if not re.match(r"[a-z]+", a):
                    return "no"
                os.system(a)
        """), [("command", 9)])

    def test_dotdot_check_cleans_only_path_kind(self):
        self.assertEqual(self._flows("""
            @app.route("/x")
            def view():
                name = request.args["f"]
                if ".." in name:
                    abort(400)
                open("/srv/" + name)
                os.system("cat " + name)
        """), [("command", 10)])

    def test_validator_function_name(self):
        self.assertEqual(self._flows("""
            @app.route("/x")
            def view():
                url = request.args["next"]
                if not is_safe_url(url):
                    return redirect("/")
                return redirect(url)
        """), [])


class ModelSinkTests(unittest.TestCase):
    def _flows(self, body):
        return _sinks(analyze_python("from flask import request\n" + _src(body)))

    def test_deserialization_models_respect_safe_loader(self):
        self.assertEqual(self._flows("""
            import pickle, yaml, numpy
            @app.post("/x")
            def view():
                data = request.get_data()
                pickle.loads(data)
                yaml.load(data, Loader=yaml.SafeLoader)
                yaml.load(data)
                numpy.load(data)
                numpy.load(data, allow_pickle=True)
        """), [("deserialize", 6), ("deserialize", 8), ("deserialize", 10)])

    def test_ssrf_full_url_vs_fixed_host(self):
        self.assertEqual(self._flows("""
            import requests, httpx
            @app.get("/x")
            def view():
                url = request.args["u"]
                requests.get(url)
                httpx.post(url=url)
                requests.get(f"https://api.example.com/items/{url}")
                requests.request("GET", url)
        """), [("ssrf", 6), ("ssrf", 7), ("ssrf", 9), ("ssrf_partial", 8)])  # sabit ana makine: kısmi SSRF sınıfı

    def test_path_models_receiver_and_sanitizer(self):
        self.assertEqual(self._flows("""
            import os
            from pathlib import Path
            from werkzeug.utils import secure_filename
            @app.get("/x")
            def view():
                name = request.args["f"]
                Path("/srv", name).read_text()
                p = Path(name)
                p.unlink()
                open(os.path.join("/srv", secure_filename(name)))
                send_file(name)
        """), [("path", 8), ("path", 10), ("path", 12)])

    def test_reflected_xss_on_html_return(self):
        self.assertEqual(self._flows("""
            from markupsafe import escape
            @app.get("/x")
            def view():
                name = request.args["n"]
                if request.args.get("json"):
                    return {"name": name}
                if request.args.get("safe"):
                    return f"<p>{escape(name)}</p>"
                return "<p>" + name + "</p>"
        """), [("html", 10)])

    def test_operator_model_file_extends_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "extra.json"
            path.write_text(json.dumps({
                "format": "sniper-taint-models-v1",
                "language": "python",
                "sinks": [{"kind": "command", "names": ["fabric.run"], "args": [0]}],
            }), encoding="utf-8")
            bad = Path(tmp) / "bad.json"
            bad.write_text('{"format": "x"}', encoding="utf-8")
            taint_models._load.cache_clear()
            try:
                with mock.patch.dict(os.environ, {"SNIPER_TAINT_MODELS": f"{path}{os.pathsep}{bad}"}):
                    flows = self._flows("""
                        import fabric
                        @app.get("/x")
                        def view():
                            fabric.run(request.args["c"])
                    """)
                    status = taint_models.model_status()["python"]
            finally:
                taint_models._load.cache_clear()
        self.assertEqual(flows, [("command", 5)])
        self.assertTrue(any("bad.json" in error for error in status["errors"]))
        self.assertGreater(status["sinks"], 10)


class CrossFileTests(unittest.TestCase):
    FILES = {
        "app/__init__.py": "",
        "app/views.py": _src("""
            from flask import request
            from . import services
            from .util import shell as sh
            from app.db import *

            @app.route("/a")
            def a():
                services.Service().deploy(request.args["v"])

            @app.route("/b")
            def b():
                sh(request.form["cmd"])

            @app.route("/c")
            def c():
                lookup(request.args["id"])
        """),
        "app/services.py": _src("""
            from .util import shell

            class Service:
                def deploy(self, version):
                    shell("deploy " + version)
        """),
        "app/util.py": _src("""
            import subprocess

            def shell(command):
                subprocess.run(command, shell=True)
        """),
        "app/db.py": _src("""
            def lookup(item):
                cursor.execute(f"SELECT * FROM t WHERE id = {item}")
        """),
    }

    def test_flows_are_reported_at_sink_file_with_source_file(self):
        results = analyze_python_files(self.FILES)
        util = results["app/util.py"]
        self.assertEqual(_sinks(util), [("command", 4), ("command", 4)])
        sources = sorted((flow.source_file, flow.source_line) for flow in util.flows)
        self.assertEqual(sources, [("app/views.py", 8), ("app/views.py", 12)])
        flow = next(f for f in util.flows if f.source_line == 8)
        self.assertTrue(flow.cross_file)
        self.assertIn("app/views.py satır 8", flow.describe())
        self.assertEqual(flow.as_dict()["source_file"], "app/views.py")
        self.assertEqual(_sinks(results["app/db.py"]), [("sql", 2)])
        self.assertEqual(results["app/views.py"].flows, [])

    def test_project_context_uses_cross_file_results_and_falls_back_for_stale_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relpath, text in self.FILES.items():
                target = root / relpath
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")

            @taint_flow.project_context
            def scan():
                taint_flow.activate_project(root, frozenset())
                fresh = taint_flow.analyze_source(self.FILES["app/util.py"], "app/util.py")
                stale = taint_flow.analyze_source(self.FILES["app/util.py"] + "\n# değişti\n", "app/util.py")
                return fresh, stale

            fresh, stale = scan()
        self.assertEqual(len(fresh.flows), 2)
        self.assertEqual(stale.flows, [])
        self.assertTrue(stale.is_clean_sink("command", 4))
        self.assertIsNone(taint_flow._PROJECT.get())

    def test_unparseable_module_does_not_break_project(self):
        files = dict(self.FILES)
        files["app/broken.py"] = "def x(:\n"
        results = analyze_python_files(files)
        self.assertNotIn("app/broken.py", results)
        self.assertEqual(len(results["app/util.py"].flows), 2)

    def test_step_budget_returns_none(self):
        body = "\n".join(f"x{i} = y{i} + z{i}" for i in range(3000))
        with mock.patch.object(taint_flow, "_PY_FILE_STEPS", 100), \
                mock.patch.object(taint_flow, "_PY_STEPS_PER_PROJECT_FILE", 0):
            self.assertIsNone(analyze_python_files({"a.py": body}))


class HotspotDowngradeTests(unittest.TestCase):
    def test_constant_shell_command_is_downgraded_but_tainted_one_stays(self):
        from project_analyzer import analyze_project

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "proj"
            root.mkdir()
            (root / "app.py").write_text(_src("""
                import os
                from flask import request

                def run(cmd):
                    os.system(cmd)

                os.system("ls -l")

                @app.route("/x")
                def view():
                    run(request.args["q"])
            """), encoding="utf-8")
            findings = analyze_project(str(root), allowed_roots=(root.parent,))["findings"]
        shell = {f["line"]: f for f in findings if f["title"] == "Kabuk üzerinden komut çalıştırma"}
        self.assertEqual(shell[7]["severity"], "low")
        self.assertEqual(shell[7]["taint_verdict"], "no_request_flow")
        self.assertEqual(shell[5]["severity"], "high")
        self.assertNotIn("taint_verdict", shell[5])
        verified = [f for f in findings if f["title"].startswith("Doğrulanmış veri akışı") and f["line"] == 5]
        self.assertEqual(len(verified), 1)


if __name__ == "__main__":
    unittest.main()


class SarifCodeFlowTests(unittest.TestCase):
    def test_project_sarif_has_code_flows_tags_and_fingerprints(self):
        from project_analyzer import analyze_project
        from project_audit_diff import render_project_audit_sarif

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "proj"
            (root / "pkg").mkdir(parents=True)
            (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            (root / "pkg" / "util.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
            (root / "pkg" / "views.py").write_text(_src("""
                from flask import request
                from .util import run

                @app.route("/x")
                def view():
                    run(request.args["c"])
            """), encoding="utf-8")
            result = analyze_project(str(root), allowed_roots=(root.parent,))
        verified = [f for f in result["findings"] if f.get("taint_flow")]
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0]["file"], "pkg/util.py")
        self.assertEqual(verified[0]["taint_flow"]["source_file"], "pkg/views.py")
        sarif = render_project_audit_sarif({"project_name": "proj", "findings": result["findings"]})
        run = sarif["runs"][0]
        flow_results = [r for r in run["results"] if "codeFlows" in r]
        self.assertEqual(len(flow_results), 1)
        steps = flow_results[0]["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(steps[0]["location"]["physicalLocation"]["artifactLocation"]["uri"], "pkg/views.py")
        self.assertEqual(steps[0]["location"]["physicalLocation"]["region"]["startLine"], 6)
        self.assertEqual(steps[-1]["location"]["physicalLocation"]["artifactLocation"]["uri"], "pkg/util.py")
        self.assertEqual(steps[-1]["location"]["physicalLocation"]["region"]["startLine"], 4)
        rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == flow_results[0]["ruleId"])
        self.assertEqual(rule["properties"]["security-severity"], "9.5")
        self.assertIn("external/cwe/cwe-78", rule["properties"]["tags"])
        self.assertEqual(len(flow_results[0]["partialFingerprints"]["sniperFinding/v1"]), 32)


class StoredDataTests(unittest.TestCase):
    """İkinci derece (veritabanından okunan) veri: 'stored' etiketli kaynak."""

    def test_python_orm_and_cursor_reads_are_stored_sources(self):
        analysis = analyze_python(_src("""
            import pickle

            def show(user_id):
                user = User.objects.get(id=user_id)
                eval(user.nickname)
                row = cursor.fetchone()
                pickle.loads(row[0])
                cursor.execute("SELECT * FROM t WHERE a = '%s'" % user.name)
                plain = settings.get("x")
                eval(plain)
        """))
        stored = sorted((f.sink_kind, f.line) for f in analysis.flows if f.source_label == "stored")
        self.assertEqual(stored, [("deserialize", 7), ("eval", 5), ("sql", 8)])
        self.assertFalse(any(f.line == 10 for f in analysis.flows))

    def test_project_reports_stored_flows_one_level_lower_and_skips_sql(self):
        from project_analyzer import analyze_project

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "proj"
            root.mkdir()
            (root / "app.py").write_text(_src("""
                def render(user_id):
                    user = User.objects.get(id=user_id)
                    eval(user.template)
                    cursor.execute("SELECT * FROM t WHERE a = '%s'" % user.name)
            """), encoding="utf-8")
            findings = analyze_project(str(root), allowed_roots=(root.parent,))["findings"]
        stored = [f for f in findings if "kayıtlı veri" in f["title"]]
        self.assertEqual([(f["line"], f["severity"], f["reference"]) for f in stored], [(3, "high", "CWE-95")])
        self.assertEqual(stored[0]["taint_flow"]["source_label"], "stored")
