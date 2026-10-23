"""Java hızlı taint motoru (taint_clike): Spring/Servlet kaynakları, hedefler, arındırıcılar, sabit katlama,
liste/eşlem modelleri, dosyalar arası özetler ve proje analizinde raporlama."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402


def flows(files: dict[str, str], label: str = "request") -> list[tuple[str, str, int]]:
    results = taint_clike.analyze_files({k: textwrap.dedent(v) for k, v in files.items()})
    return sorted((f.file, f.sink_kind, f.line) for a in results.values() for f in a.flows if f.source_label == label)


SERVLET = """
import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    %s
  }
}
"""


def servlet(body: str) -> dict[str, str]:
    return {"T.java": SERVLET % textwrap.dedent(body).strip().replace("\n", "\n    ")}


class JavaSourcesAndSinks(unittest.TestCase):
    def kinds(self, body: str) -> list[str]:
        return [k for _f, k, _l in flows(servlet(body))]

    def test_sql_command_path_xss(self):
        self.assertEqual(self.kinds('statement.executeQuery("select * from u where n=\'" + param + "\'");'), ["sql"])
        self.assertEqual(self.kinds('Runtime.getRuntime().exec("ping " + param);'), ["command"])
        self.assertEqual(self.kinds('new java.io.File(dir, param);'), ["path"])
        self.assertEqual(self.kinds('response.getWriter().println(param);'), ["html"])
        self.assertEqual(self.kinds('response.sendRedirect(param);'), ["redirect"])
        self.assertEqual(self.kinds('request.getSession().setAttribute("u", param);'), ["session"])

    def test_sanitizers_are_kind_specific(self):
        self.assertEqual(self.kinds('String s = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);\n'
                                    'response.getWriter().println(s);\nstatement.executeQuery("x" + s);'), ["sql"])
        self.assertEqual(self.kinds('int n = Integer.parseInt(param);\nstatement.executeQuery("x" + n);'), [])
        self.assertEqual(self.kinds('PreparedStatement ps = conn.prepareStatement("select ?");\nps.setString(1, param);\n'
                                    'ps.executeQuery();'), [])

    def test_constant_folding_and_collections(self):
        # (7*42) - 106 = 188 > 200 yanlış → param
        self.assertEqual(self.kinds('int num = 106;\nString bar = (7 * 42) - num > 200 ? "safe" : param;\n'
                                    'new java.io.File(bar);'), ["path"])
        self.assertEqual(self.kinds('int num = 86;\nString bar;\nif ((7 * 42) - num > 200) bar = "safe"; else bar = param;\n'
                                    'new java.io.File(bar);'), [])
        self.assertEqual(self.kinds('java.util.List<String> l = new java.util.ArrayList<String>();\n'
                                    'l.add("safe"); l.add(param); l.add("moresafe"); l.remove(0);\n'
                                    'new java.io.File(l.get(1));'), [])
        self.assertEqual(self.kinds('java.util.HashMap<String,Object> m = new java.util.HashMap<String,Object>();\n'
                                    'm.put("keyA", "a"); m.put("keyB", param);\nString bar = (String) m.get("keyB");\n'
                                    'new java.io.File(bar);'), ["path"])
        self.assertEqual(self.kinds('String guess = "ABC";\nchar t = guess.charAt(1);\nString bar;\n'
                                    "switch (t) { case 'A': bar = param; break; case 'B': bar = \"bob\"; break; "
                                    "default: bar = param; }\nnew java.io.File(bar);"), [])

    def test_builder_cookie_and_header_sources(self):
        self.assertEqual(self.kinds('StringBuilder sb = new StringBuilder(param);\n'
                                    'response.getWriter().format(sb.append("_x").toString(), new Object[]{"a"});'), ["html"])
        body = ('javax.servlet.http.Cookie[] cs = request.getCookies();\nString v = "none";\n'
                'for (javax.servlet.http.Cookie c : cs) { if (c.getName().equals("x")) { v = c.getValue(); break; } }\n'
                'new java.io.File(v);')
        self.assertEqual(self.kinds(body), ["path"])


class JavaSpringAndCrossFile(unittest.TestCase):
    def test_spring_params_return_and_mybatis_style(self):
        src = """
        @RestController
        public class C {
          @GetMapping("/a")
          public String a(@RequestParam String q, Model model) { return q; }
          @GetMapping("/b")
          public String b(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); return "ok"; }
          @GetMapping("/c")
          public String c(String url) { return "redirect:" + url; }
          @GetMapping("/d")
          public String d(@RequestParam String n) { return Encode.forHtml(n); }
        }
        """
        self.assertEqual(flows({"C.java": src}), [("C.java", "command", 7), ("C.java", "html", 5), ("C.java", "redirect", 9)])

    def test_cross_file_helper_and_interface(self):
        files = {
            "web/Ctl.java": """
            public class Ctl {
              private Db db;
              @PostMapping("/x")
              public String x(HttpServletRequest request) throws Exception {
                String body = WebUtils.getRequestBody(request);
                Thing t = Factory.make();
                db.run(t.doIt(body));
                return "";
              }
            }
            """,
            "util/WebUtils.java": """
            public class WebUtils {
              public static String getRequestBody(HttpServletRequest request) throws Exception {
                java.io.InputStream in = request.getInputStream();
                return read(in);
              }
              static String read(java.io.InputStream is) { java.util.Scanner s = new java.util.Scanner(is); return s.next(); }
            }
            """,
            "util/Db.java": """
            public class Db { public void run(String sql) throws Exception { stmt.executeQuery("select " + sql); } }
            """,
            "util/Thing.java": "public interface Thing { String doIt(String v); }",
            "util/ThingA.java": "public class ThingA implements Thing { public String doIt(String v) { return v; } }",
        }
        self.assertEqual(flows(files), [("util/Db.java", "sql", 2)])

    def test_xxe_requires_unhardened_parser_in_method(self):
        src = """
        public class X {
          @PostMapping("/v")
          public String v(@RequestBody String body) throws Exception {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            db.parse(new InputSource(new StringReader(body)));
            return "";
          }
          @PostMapping("/s")
          public String s(@RequestBody String body) throws Exception {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder db = f.newDocumentBuilder();
            db.parse(new InputSource(new StringReader(body)));
            return "";
          }
        }
        """
        self.assertEqual(flows({"X.java": src}), [("X.java", "xxe", 6)])

    def test_null_check_validator_guard_and_ssrf_hook(self):
        src = """
        public class G {
          public void r(HttpServletRequest request, HttpServletResponse response) throws Exception {
            String url = request.getParameter("url");
            if (SecurityUtil.checkURL(url) == null) { return; }
            response.sendRedirect(url);
          }
          @GetMapping("/s")
          public String s(String url) throws Exception {
            SecurityUtil.startSSRFHook();
            return new URL(url).openConnection().toString();
          }
        }
        """
        self.assertEqual(flows({"G.java": src}), [])

    def test_project_analyzer_reports_java_flows(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "src").mkdir(parents=True)
            (root / "src" / "T.java").write_text(SERVLET % 'Runtime.getRuntime().exec("ping " + param);')
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        flows_found = [f for f in result["findings"] if f.get("taint_flow")]
        self.assertEqual([(f["reference"], f["file"], f["line"]) for f in flows_found], [("CWE-78", "src/T.java", 6)])


if __name__ == "__main__":
    unittest.main()
