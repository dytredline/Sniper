"""6. tur: sabit değerlendirme, alan/öğe duyarlı kaplar, yeni hedefler ve doğrulama kalıpları."""
import textwrap
import unittest

from taint_flow import analyze_python


def _flows(body):
    source = "from flask import request\n" + textwrap.dedent(body).lstrip("\n")
    return sorted((f.sink_kind, f.line, f.source_label) for f in analyze_python(source).flows)


class ConstantFoldingTests(unittest.TestCase):
    def test_dead_branches_from_constant_if_match_and_ternary(self):
        self.assertEqual(_flows("""
            @app.post("/x")
            def view():
                param = request.form["p"]
                bar = "safe"
                if (7 * 42) - 86 > 200:
                    bar = "still safe"
                else:
                    bar = param
                possible = "ABC"
                match possible[1]:
                    case "A":
                        other = param
                    case "B":
                        other = "bob"
                    case _:
                        other = param
                third = param if len("abc") > 5 else "x"
                eval(bar)
                eval(other)
                eval(third)
                fourth = "should"
                if "should" in fourth:
                    fourth = param
                eval(fourth)
        """), [("eval", 25, "request")])

    def test_unknown_conditions_keep_both_branches(self):
        self.assertEqual(_flows("""
            @app.post("/x")
            def view():
                param = request.form["p"]
                bar = "safe"
                if request.args.get("flag"):
                    bar = param
                eval(bar)
        """), [("eval", 8, "request")])


class ContainerTests(unittest.TestCase):
    def test_constant_key_dicts_list_items_and_mutators(self):
        self.assertEqual(_flows("""
            import configparser
            @app.post("/x")
            def view():
                param = request.form["p"]
                m = {}
                m["a"] = "safe"
                m["b"] = param
                eval(m["a"])
                eval(m["b"])
                lst = []
                lst.append("safe")
                lst.append(param)
                lst.append("moresafe")
                lst.pop(0)
                eval(lst[1])
                eval(lst[0])
                acc = []
                acc.extend([param])
                eval(acc)
                conf = configparser.ConfigParser()
                conf.set("s", "k", param)
                eval(conf.get("s", "k"))
        """), [("eval", 10, "request"), ("eval", 17, "request"), ("eval", 20, "request"), ("eval", 23, "request")])


class NewSinkTests(unittest.TestCase):
    def test_ldap_xpath_xxe_session_cookie_and_shell_argv(self):
        flows = _flows("""
            import subprocess, flask, random, secrets
            import lxml.etree
            import xml.sax, xml.sax.handler, xml.dom.minidom
            @app.post("/x")
            def view():
                p = request.form["p"]
                conn.search("ou=users", f"(uid={p})")
                root.xpath(f"//u[@id='{p}']")
                lxml.etree.XPath(f"//u[@id='{p.replace(chr(39), '')}']")
                root.xpath(f"//u[@id='{p.replace("'", "&apos;")}']")
                parser = xml.sax.make_parser()
                parser.setFeature(xml.sax.handler.feature_external_ges, True)
                xml.dom.minidom.parseString(p, parser)
                safe_parser = xml.sax.make_parser()
                xml.dom.minidom.parseString(p, safe_parser)
                flask.session["user"] = p
                flask.session[p] = "1"
                mysession = {}
                mysession["remember"] = str(random.random())
                mysession["token"] = secrets.token_hex(8)
                resp.set_cookie("c", str(random.getrandbits(32)))
                subprocess.run(["sh", "-c", f"echo {p}"])
                subprocess.run(["echo", p])
        """)
        kinds = [(k, line) for k, line, label in flows if label == "request"]
        self.assertIn(("ldap", 8), kinds)
        self.assertIn(("xpath", 9), kinds)
        self.assertNotIn(("xpath", 11), kinds)
        self.assertIn(("xxe", 14), kinds)
        self.assertNotIn(("xxe", 16), kinds)
        self.assertIn(("session", 17), kinds)
        self.assertIn(("session", 18), kinds)
        self.assertIn(("command", 23), kinds)
        self.assertNotIn(("command", 24), kinds)
        weak = [(k, line) for k, line, label in flows if label == "weakrand"]
        self.assertEqual(sorted(weak), [("cookie", 22), ("session", 20)])


class GuardPatternTests(unittest.TestCase):
    def test_quote_checks_and_quoted_literal_validation(self):
        self.assertEqual(_flows("""
            @app.post("/x")
            def view():
                bar = request.form["p"]
                if "'" in bar:
                    return "no"
                root.xpath(f"//u[@id='{bar}']")
                eval(bar)
                lit = request.form["q"]
                if not lit.startswith("'") or not lit.endswith("'") or "'" in lit[1:-1]:
                    return "no"
                eval(lit)
        """), [("eval", 8, "request")])

    def test_derived_url_validation_cleans_source_for_redirect_only(self):
        self.assertEqual(_flows("""
            import urllib.parse
            from flask import redirect
            @app.post("/x")
            def view():
                target = request.form["next"]
                url = urllib.parse.urlparse(target)
                if url.netloc not in ["example.com"] or url.scheme != "https":
                    return "no"
                cursor.execute("SELECT '" + target + "'")
                return redirect(target)
        """), [("sql", 10, "request")])

    def test_reflected_string_response_and_json_container(self):
        self.assertEqual(_flows("""
            @app.post("/x")
            def view():
                name = request.form["n"]
                if request.args.get("json"):
                    data = {"name": name}
                    return data
                body = ""
                body += f"Merhaba {name}"
                return body
        """), [("html", 10, "request")])


class DispatchByNameTests(unittest.TestCase):
    def test_unknown_receiver_uses_few_matching_methods(self):
        self.assertEqual(_flows("""
            import os
            class A:
                def transform_value(self, x):
                    return x
            class B:
                def transform_value(self, x):
                    return "" + x
            @app.post("/x")
            def view():
                thing = factory()
                os.system(thing.transform_value(request.form["p"]))
        """), [("command", 12, "request")])


if __name__ == "__main__":
    unittest.main()


class FieldSensitiveFlowTests(unittest.TestCase):
    def test_constructor_field_reaches_sink_in_other_method(self):
        self.assertEqual(_flows("""
            import os
            class Runner:
                def __init__(self, cmd, label):
                    self.cmd = cmd
                    self.label = label
                def run(self):
                    os.system(self.cmd)
                def show(self):
                    os.system("echo " + self.label)
            @app.post("/x")
            def view():
                r = Runner(request.form["c"], "sabit")
                r.run()
                r.show()
                Runner(request.form["d"], "x").run()
        """), [("command", 8, "request"), ("command", 8, "request")])

    def test_setter_and_self_method_chain(self):
        self.assertEqual(_flows("""
            import subprocess
            class Job:
                def __init__(self):
                    self.target = "localhost"
                def set_target(self, value):
                    self.target = value
                def _build(self):
                    return "ping " + self.target
                def start(self):
                    subprocess.run(self._build(), shell=True)
            @app.post("/x")
            def view():
                job = Job()
                job.start()
                job.set_target(request.form["t"])
                job.start()
        """), [("command", 11, "request")])

    def test_factory_return_type_and_field_typed_dependency(self):
        self.assertEqual(_flows("""
            class Repo:
                def find(self, name):
                    return cursor.execute("SELECT * FROM t WHERE n = '" + name + "'")
            class Service:
                def __init__(self):
                    self.repo = Repo()
                def lookup(self, name):
                    return self.repo.find(name)
            def make_service():
                return Service()
            @app.post("/x")
            def view():
                svc = make_service()
                svc.lookup(request.form["n"])
        """), [("sql", 4, "request")])
