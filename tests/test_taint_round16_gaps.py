"""16. tur: 7. setteki kaçırmalardan çıkarılan genel kalıplar ve JSONP bulgu türü. Olumlu ve olumsuz örnekler.

* Java: Struts2 eylem alanları (ayarlayıcılı alan = istek parametresi) ve struts.xml ``redirect`` sonucu ``${alan}``;
  ``list()`` gibi PHP'ye özgü adlı yöntemler; çözme (Base64/URL) önceki doğrulamayı geçersiz kılar; anonim sınıf
  yöntemi ve ``defineClass``; çapasız ``Matcher.find()`` doğrulayıcısı arındırıcı değildir; istek verisiyle kurulmuş
  nesnenin ``toString()`` değeri.
* C#: ``ContentResult { ContentType = "text/html" }``, ``XmlSerializer(Type.GetType(…))``, DTD kapatılmamış
  ``XmlTextReader``, istek XML'iyle yüklenen ``XmlDocument``.
* JSONP: geri çağırma adı JS/JSON yanıtına yansıyor → ayrı "jsonp" türü (HTML XSS değil).
* Python: WTForms/Flask-WTF form alanları, ``request.path`` (yansıtma; yönlendirme/SSRF değil),
  ``render_template_string`` → SSTI, kullanıcının yazdığı alanın ``|safe`` / ``mark_safe(self.alan)`` ile basılması,
  SQLAlchemy 2.0 okumaları.
* JS: Nunjucks ``| safe``, NestJS ``@Redirect()``, kabuksuz ``spawn`` (program girdiden / curl adresi), şema öneki
  ``startsWith('http')`` SSRF koruması değildir, ``doT.compile``; HTML şablonundaki satır içi betikte DOM akışı.
"""
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_analyzer  # noqa: E402
import taint_clike  # noqa: E402
import taint_flow as tf  # noqa: E402
import taint_js_ast  # noqa: E402
import taint_js_views  # noqa: E402
from tests.test_taint_js_ast import NODE_ENV  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _clike(files, extra=None):
    results = taint_clike.analyze_files({k: _src(v) for k, v in files.items()}, extra or {})
    return {path: sorted({(f.sink_kind, f.line) for f in a.flows}) for path, a in results.items()}


def _py(files):
    return tf._analyze_python_files_uncached({k: _src(v) for k, v in files.items()}, None, frozenset())


STRUTS_ACTION = """
import com.opensymphony.xwork2.ActionSupport;
public class GoAction extends ActionSupport {
    private String url;
    private String host;
    private int count;
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public void setHost(String host) { this.host = host; }
    public void setCount(int count) { this.count = count; }
    public String list() {
        if (url == null) return INPUT;
        else Runtime.getRuntime().exec("ping " + host);
        return "redirect";
    }
    public String other() {
        Runtime.getRuntime().exec("ping " + count);
        return SUCCESS;
    }
}
"""
STRUTS_XML = """<struts><package name="p"><action name="go" class="a.GoAction">
<result name="redirect" type="redirect">${url}</result><result name="success">/ok.jsp</result>
</action></package></struts>"""


class JavaGapTests(unittest.TestCase):
    def test_struts2_action_fields_and_redirect_result(self):
        flows = _clike({"a/GoAction.java": STRUTS_ACTION}, {"struts.xml": STRUTS_XML})["a/GoAction.java"]
        self.assertIn(("command", 12), flows)  # list() yöntemi de çıkarılır; host ayarlayıcılı alan
        self.assertIn(("redirect", 13), flows)  # return "redirect" → ${url}
        self.assertNotIn(("command", 16), flows)  # int alan: sayı, kaynak değil
        plain = _clike({"a/GoAction.java": STRUTS_ACTION.replace("extends ActionSupport", "")})["a/GoAction.java"]
        self.assertEqual(plain, [])  # Struts2 eylemi değilse alanlar kaynak değil

    def test_decode_after_validation_and_unanchored_find(self):
        src = """
        import java.util.regex.*;
        public class V extends HttpServlet {
          static final Pattern P = Pattern.compile("^[a-z0-9.-]+");
          static final Pattern Q = Pattern.compile("^[a-z0-9.-]+$");
          protected void doGet(HttpServletRequest request, HttpServletResponse response) {
            String x = Base64.getEncoder().encodeToString(request.getParameter("x").getBytes());
            String ok = validate(x);
            String y = new String(Base64.getDecoder().decode(ok));
            conn.createStatement().executeQuery(y);
            String d = request.getParameter("d");
            if (!isValidDomain(d)) { return; }
            Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping " + d});
            String e = request.getParameter("e");
            if (!isValidStrict(e)) { return; }
            Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping " + e});
          }
          public String validate(String v) { if (v.contains("X")) { return v; } return ""; }
          private static boolean isValidDomain(String s) { Matcher m = P.matcher(s); return m.find(); }
          private static boolean isValidStrict(String s) { return Q.matcher(s).matches(); }
        }
        """
        flows = _clike({"V.java": src})["V.java"]
        self.assertIn(("sql", 9), flows)  # çözülen değer: önceki doğrulama geçersiz
        self.assertIn(("command", 12), flows)  # ^ ile başlayıp $ olmadan find(): kısmi eşleşme
        self.assertNotIn(("command", 15), flows)  # matches(): tam eşleşme doğrulayıcısı

    def test_anonymous_class_define_class_and_tostring(self):
        src = """
        public class I extends HttpServlet {
          protected void doPost(HttpServletRequest request, HttpServletResponse response) {
            byte[] b = new sun.misc.BASE64Decoder().decodeBuffer(request.getParameter("x"));
            new ClassLoader() {
              Class x(byte[] b) { return defineClass(null, b, 0, b.length); }
            }.x(b).newInstance();
          }
        }
        """
        self.assertIn(("eval", 5), _clike({"I.java": src})["I.java"])
        ctrl = """
        @RestController
        public class C {
          @RequestMapping("/debug")
          public String debug(@RequestParam String name) {
            Customer c = new Customer(name);
            return c.toString().toLowerCase();
          }
          @RequestMapping("/plain")
          public String plain(@RequestParam String name) {
            Customer c = new Customer("sabit");
            return c.toString();
          }
        }
        """
        cust = "public class Customer { private String n; public Customer(String n) { this.n = n; }\n" \
               " public String toString() { return \"Customer \" + n; } }\n"
        flows = _clike({"C.java": ctrl, "Customer.java": cust})["C.java"]
        self.assertIn(("html", 6), flows)
        self.assertNotIn(("html", 11), flows)


class CSharpGapTests(unittest.TestCase):
    SRC = """
    public class ApiController : Controller {
        [HttpGet("xss")]
        public ContentResult Xss(string data) {
            return new ContentResult() { Content = data, ContentType = "text/html" };
        }
        [HttpGet("txt")]
        public ContentResult Txt(string data) {
            return new ContentResult() { Content = data, ContentType = "text/plain" };
        }
        [HttpPost]
        public IActionResult Post() {
            XmlDocument doc = new XmlDocument();
            doc.Load(HttpContext.Request.Body);
            foreach (XmlElement item in doc.SelectNodes("E")) {
                var ser = new XmlSerializer(Type.GetType(item.GetAttribute("Type")));
                var ok = new XmlSerializer(typeof(Product));
            }
            return Ok();
        }
        [HttpPost("xxe")]
        public JsonResult Xxe([FromBody] string xml) {
            XmlTextReader r = new XmlTextReader(new StringReader(xml));
            return Json("ok");
        }
        [HttpPost("safe")]
        public JsonResult Safe([FromBody] string xml) {
            XmlTextReader r = new XmlTextReader(new StringReader(xml));
            r.DtdProcessing = DtdProcessing.Prohibit;
            return Json("ok");
        }
    }
    """

    def test_csharp_sinks(self):
        flows = _clike({"Api.cs": self.SRC})["Api.cs"]
        self.assertIn(("html", 4), flows)
        self.assertNotIn(("html", 8), flows)  # text/plain
        self.assertIn(("deserialize", 15), flows)
        self.assertNotIn(("deserialize", 16), flows)  # typeof(...)
        self.assertIn(("xxe", 22), flows)
        self.assertNotIn(("xxe", 27), flows)  # DtdProcessing.Prohibit


class JsonpTests(unittest.TestCase):
    def test_php_jsonp_is_separate_kind(self):
        php = '<?php\nheader("Content-Type: application/json");\n$cb = $_GET["callback"];\n' \
              'echo $cb . "(" . json_encode($o) . ")";\n$x = $_GET["x"];\necho json_encode($x);\n'
        self.assertEqual(_clike({"jsonp.php": php})["jsonp.php"], [("jsonp", 4)])

    def test_spring_produces_javascript_jsonp(self):
        src = """
        @RestController
        public class J {
          @GetMapping(value = "/t", produces = "application/javascript")
          public String t(HttpServletRequest request) {
            String callback = request.getParameter("cb");
            JSONPObject jsonpObj = new JSONPObject(callback);
            return jsonpObj.toString();
          }
        }
        """
        self.assertEqual(_clike({"J.java": src})["J.java"], [("jsonp", 7)])

    def test_jsonp_rule_is_low_and_not_verified_flow(self):
        category, severity, title, _rec, cwe = project_analyzer.TAINT_FLOW_RULES["jsonp"]
        self.assertEqual((severity, cwe), ("low", "CWE-79"))
        self.assertFalse(title.startswith("Doğrulanmış veri akışı"))


class PythonGapTests(unittest.TestCase):
    def test_wtforms_and_request_path(self):
        results = _py({
            "forms.py": "from wtforms import Form, StringField\nclass ImageForm(Form):\n    url = StringField('u')\n"
                        "from flask_wtf import FlaskForm\nclass Login(FlaskForm):\n    name = StringField('n')\n",
            "app.py": """
            from flask import request, render_template_string, redirect
            from urllib.request import urlopen
            from forms import ImageForm, Login
            @app.route('/i', methods=['POST'])
            def image():
                form = ImageForm(request.form)
                if form.validate():
                    urlopen(form.url.data)
                return 'ok'
            @app.route('/l', methods=['POST'])
            def login():
                form = Login()
                db.execute("SELECT 1 WHERE n='" + form.name.data + "'")
                return 'ok'
            @app.errorhandler(404)
            def nf(error):
                render_template_string(f"{error} {request.path}")
                return redirect(request.path)
            @app.route('/sabit')
            def fixed():
                return render_template_string("<p>" + request.path + "</p>")
            """})
        flows = sorted({(f.sink_kind, f.line) for f in results["app.py"].flows})
        self.assertIn(("ssrf", 8), flows)
        self.assertIn(("sql", 13), flows)
        self.assertIn(("ssti", 17), flows)
        self.assertNotIn(("redirect", 18), flows)  # istemcinin kendi yolu: açık yönlendirme değil
        self.assertNotIn(("ssti", 21), flows)  # değişkensiz rotada request.path rota kalıbının kendisi

    def test_user_written_field_marks_stored_template_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "templates").mkdir(parents=True)
            (root / "templates" / "home.html").write_text("<p>{{ note.text | safe }}</p>\n<p>{{ note.title | safe }}</p>\n")
            (root / "app.py").write_text(_src("""
            from flask import Flask, request, render_template
            app = Flask(__name__)
            @app.route('/add', methods=['POST'])
            def add():
                db.session.add(Note(text=request.form['t']))
                db.session.commit()
                return 'ok'
            @app.route('/')
            def home():
                notes = db.session.scalars(select(Note)).all()
                for note in notes:
                    pass
                return render_template('home.html', note=notes[0])
            class User(db.Model):
                def safe_name(self):
                    return mark_safe(self.text)
            """))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))
        verified = {(f["file"], f["line"]) for f in result["findings"]
                    if f["title"].startswith("Doğrulanmış veri akışı (kayıtlı veri)")}
        self.assertIn(("templates/home.html", 1), verified)  # kullanıcının yazdığı alan (text)
        self.assertNotIn(("templates/home.html", 2), verified)  # title istekten yazılmıyor
        self.assertIn(("app.py", 16), verified)  # mark_safe(self.text)


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsGapTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def flows(self, files, filename, templates=None):
        results = taint_js_ast.analyze_files({k: _src(v) for k, v in files.items()},
                                             templates={k: _src(v) for k, v in (templates or {}).items()})
        self.assertIsNotNone(results)
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows if f.source_label in ("request", "stored")})

    def test_nunjucks_safe_filter(self):
        server = """
        const express = require('express');
        const expressNunjucks = require('express-nunjucks');
        const app = express();
        app.set('views', __dirname + '/templates');
        app.get('/', (req, res) => {
          res.render('user.html', { message: req.query.message, other: req.query.other });
        });
        """
        templates = {"templates/user.html": "<p>{{ message | safe }}</p>\n<p>{{ other }}</p>\n"}
        self.assertEqual(self.flows({"server.js": server}, "server.js", templates), [("html", 6)])
        found = taint_js_views.unescaped_outputs("t.njk", "{% autoescape false %}{{ a }}{% endautoescape %}{{ b }}")
        self.assertEqual([p for _l, _s, p in found], [[("a",)]])

    def test_spawn_curl_redirect_startswith_and_dot(self):
        src = """
        const { spawn, spawnSync } = require('child_process');
        const axios = require('axios');
        const dot = require('dot');
        app.post('/run', (req, res) => {
          const [exe, ...args] = req.body.cmd.split(' ');
          spawn(exe, args);
          spawn('ls', [req.body.dir]);
          spawnSync('curl', [req.body.url]);
          const u = req.query.u;
          if (u.startsWith('http')) { axios(u); }
          const v = req.query.v;
          if (v.startsWith('https://api.example.com/')) { axios(v); }
          dot.compile(req.body.t)();
        });
        """
        flows = self.flows({"a.js": src}, "a.js")
        self.assertIn(("command", 6), flows)
        self.assertNotIn(("command", 7), flows)  # program sabit, kabuksuz: argüman komut değil
        self.assertIn(("ssrf", 8), flows)
        self.assertIn(("ssrf", 10), flows)  # 'http' öneki konağı sabitlemez
        self.assertNotIn(("ssrf", 12), flows)
        self.assertIn(("eval", 13), flows)

    def test_nest_redirect_decorator(self):
        src = """
        import { Controller, Get, Query, Redirect } from '@nestjs/common';
        @Controller()
        export class AppController {
          @Get('goto')
          @Redirect()
          async redirect(@Query('url') url: string) {
            return { url };
          }
          @Get('plain')
          async plain(@Query('url') url: string) {
            return { url };
          }
        }
        """
        self.assertEqual(self.flows({"app.controller.ts": src}, "app.controller.ts"), [("redirect", 7)])

    def test_inline_script_dom_flow_in_html_template(self):
        page = ("<html><body>{% if x %}<p>{{ y }}</p>{% endif %}\n<script>\n  var h = location.hash.split('#')[1];\n"
                "  var v = decodeURIComponent(h);\n  document.write('<b>' + v + '</b>');\n  var k = '{{ token }}';\n"
                "</script>\n<script src='a.js'></script>\n</body></html>\n")
        analysis = project_analyzer._inline_script_analysis(page, "templates/p.html")
        self.assertIsNotNone(analysis)
        self.assertEqual(sorted({(f.sink_kind, f.line) for f in analysis.flows}), [("html", 5)])
        self.assertIsNone(project_analyzer._inline_script_analysis("<script>var a = 1;</script>", "t.html"))


if __name__ == "__main__":
    unittest.main()
