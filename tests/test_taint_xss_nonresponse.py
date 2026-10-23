"""15. tur XSS kesinliği: HTTP yanıtı olmayan çıkışlar XSS hedefi değildir.

* dosya/bellek akışları (Java FileWriter, StringWriter, ByteArrayOutputStream, Files.newBufferedWriter; C# StreamWriter,
  StringWriter, File.CreateText) — yanıt yazıcısını saran örnekler (``new PrintWriter(response.getWriter())``,
  ``new StreamWriter(Response.OutputStream)``) yanıta yazar ve XSS olarak kalır;
* yanıtın içerik türü HTML dışı (JSON, düz metin) ya da ek (Content-Disposition: attachment) yapıldıysa sonraki yanıt
  yazımları (Java setContentType/setHeader, C# Response.ContentType/AddHeader, PHP header(), Spring ``produces``,
  Express res.attachment()/Content-Disposition, Django yanıt başlığı, Go Header().Set);
* HTML içerik türü açıkça atanmışsa ya da içerik türü bilinmiyorsa eski davranış (XSS) sürer.
"""
import os
from pathlib import Path
import sys
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402
import taint_flow as tf  # noqa: E402
import taint_goruby  # noqa: E402
import taint_js_ast  # noqa: E402
from tests.test_taint_js_ast import NODE_ENV  # noqa: E402


def _src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def clike_xss(files: dict[str, str]) -> list[tuple[str, int]]:
    res = taint_clike.analyze_files({k: _src(v) for k, v in files.items()})
    return sorted((f.file, f.line) for a in res.values() for f in a.flows if f.sink_kind == "html")


class JavaStreams(unittest.TestCase):
    def test_file_and_buffer_writers_are_not_response(self):
        src = """
        import java.io.*;
        import java.nio.file.*;
        import javax.servlet.http.*;
        public class A extends HttpServlet {
          protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String n = request.getParameter("n");
            FileWriter fileWriter = new FileWriter("/tmp/a");
            fileWriter.write(n);
            PrintWriter pw = new PrintWriter(new FileWriter("/tmp/b"));
            pw.println(n);
            StringWriter sw = new StringWriter();
            sw.write(n);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(n.getBytes());
            BufferedWriter bw = Files.newBufferedWriter(Paths.get("/tmp/c"));
            bw.write(n);
            PrintStream ps = new PrintStream(new FileOutputStream("/tmp/d"));
            ps.println(n);
            PrintWriter out = response.getWriter();
            out.println(n);
            PrintWriter rw = new PrintWriter(response.getWriter());
            rw.print(n);
            response.getOutputStream().print(n);
          }
        }
        """
        self.assertEqual(clike_xss({"A.java": src}), [("A.java", 20), ("A.java", 22), ("A.java", 23)])

    def test_non_html_content_type_and_attachment(self):
        src = """
        import java.io.*;
        import javax.servlet.http.*;
        class B extends HttpServlet {
          protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("application/json");
            response.getWriter().print("{\\"a\\":\\"" + request.getParameter("n") + "\\"}");
          }
        }
        class C extends HttpServlet {
          protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setHeader("Content-Disposition", "attachment; filename=r.csv");
            response.getWriter().print(request.getParameter("n"));
          }
        }
        class D extends HttpServlet {
          protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().print(request.getParameter("n"));
          }
        }
        class E extends HttpServlet {
          protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("application/json");
            response.setContentType("text/html");
            response.getWriter().print(request.getParameter("n"));
          }
        }
        """
        self.assertEqual(clike_xss({"B.java": src}), [("B.java", 18), ("B.java", 25)])

    def test_spring_produces(self):
        src = """
        import org.springframework.web.bind.annotation.*;
        import org.springframework.http.MediaType;
        @RestController
        public class C {
            @GetMapping(value = "/a", produces = MediaType.APPLICATION_JSON_VALUE)
            public String a(@RequestParam String q) { return "{\\"q\\":\\"" + q + "\\"}"; }
            @GetMapping(value = "/b", produces = {"text/plain", "application/json"})
            public String b(@RequestParam String q) { return q; }
            @GetMapping("/c")
            public String c(@RequestParam String q) { return q; }
            @GetMapping(value = "/d", produces = {"application/json", "text/html"})
            public String d(@RequestParam String q) { return q; }
        }
        @RestController
        @RequestMapping(value = "/x", produces = "application/json")
        class D {
            @GetMapping("/e")
            public String e(@RequestParam String q) { return q; }
        }
        """
        self.assertEqual(clike_xss({"C.java": src}), [("C.java", 10), ("C.java", 12)])

    def test_jsp_scriptlet_content_type(self):
        files = {"web/a.jsp": '<%@ page language="java" %>\n<% response.setContentType("application/json"); %>\n'
                              '{"q": "<%= request.getParameter("q") %>"}\n',
                 "web/b.jsp": '<%@ page language="java" %>\n<p><%= request.getParameter("q") %></p>\n'}
        res = taint_clike.analyze_files(files)
        self.assertEqual(sorted((f.file, f.line) for a in res.values() for f in a.flows if f.sink_kind == "html"),
                         [("web/b.jsp", 2)])


class CSharpStreams(unittest.TestCase):
    def test_stream_writers_and_response_content_type(self):
        src = """
        using System.IO;
        using System.Web;
        public class H : IHttpHandler {
            public void ProcessRequest(HttpContext context) {
                string q = context.Request["q"];
                context.Response.ContentType = "text/plain";
                context.Response.Write(q);
            }
        }
        public class H2 : IHttpHandler {
            public void ProcessRequest(HttpContext context) {
                string q = context.Request["q"];
                var w = new StreamWriter(context.Response.OutputStream);
                w.Write(q);
                context.Response.Write(q);
                var f = new StreamWriter("/tmp/a.txt");
                f.Write(q);
                StringWriter s2 = new StringWriter();
                s2.Write(q);
                TextWriter tw = File.CreateText("/tmp/b.txt");
                tw.Write(q);
            }
        }
        public class H3 : IHttpHandler {
            public void ProcessRequest(HttpContext context) {
                string q = context.Request["q"];
                context.Response.AddHeader("Content-Disposition", "attachment; filename=a.txt");
                context.Response.Write(q);
            }
        }
        """
        self.assertEqual(clike_xss({"H.ashx.cs": src}), [("H.ashx.cs", 14), ("H.ashx.cs", 15)])


class PhpHeaders(unittest.TestCase):
    def test_header_content_type_and_attachment(self):
        files = {
            "a.php": "<?php\n$n = $_GET['n'];\necho 'Merhaba ' . $n;\nfile_put_contents('/tmp/a', $n);\n",
            "json.php": "<?php\nheader('Content-Type: application/json');\necho '{\"a\":\"' . $_GET['n'] . '\"}';\n",
            "dl.php": "<?php\nheader(\"Content-Disposition: attachment; filename=\\\"x.csv\\\"\");\necho $_GET['n'];\n",
            "html.php": "<?php\nheader('Content-Type: text/html; charset=utf-8');\necho $_GET['n'];\n",
            "plain.php": "<?php\nfunction f() {\n  header('Content-type: text/plain');\n  echo $_GET['n'];\n}\n"
                         "function g() {\n  echo $_GET['m'];\n}\n",
        }
        self.assertEqual(clike_xss(files), [("a.php", 3), ("html.php", 3), ("plain.php", 7)])

    def test_header_after_output_does_not_hide_earlier_echo(self):
        src = "<?php\necho $_GET['a'];\nheader('Content-Type: application/json');\necho $_GET['b'];\n"
        self.assertEqual(clike_xss({"x.php": src}), [("x.php", 2)])


class PythonResponses(unittest.TestCase):
    def test_django_attachment_and_content_type_header(self):
        res = tf._analyze_python_files_uncached({"app/views.py": _src("""
            from django.http import HttpResponse

            def x(request):
                response = HttpResponse("a," + request.GET.get("n"))
                response["Content-Disposition"] = "attachment; filename=r.csv"
                return response

            def y(request):
                response = HttpResponse("a," + request.GET.get("n"))
                response["X-Frame-Options"] = "DENY"
                return response

            def z(request):
                response = HttpResponse("a," + request.GET.get("n"))
                response["Content-Type"] = "application/json"
                return response
        """), "app/urls.py": _src("""
            from django.urls import path
            from . import views
            urlpatterns = [path("x", views.x), path("y", views.y), path("z", views.z)]
        """)}, None, frozenset())
        self.assertEqual(sorted((f.sink_kind, f.line) for f in res["app/views.py"].flows), [("html", 9)])


class GoAttachment(unittest.TestCase):
    def test_content_disposition_attachment(self):
        files = {"go.mod": "module ex\n", "web/a.go": _src("""
            package web
            import ("fmt"; "net/http")
            func dl(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Disposition", "attachment; filename=r.csv")
                fmt.Fprintf(w, "%s", r.URL.Query().Get("n"))
            }
            func page(w http.ResponseWriter, r *http.Request) {
                fmt.Fprintf(w, "<p>%s</p>", r.URL.Query().Get("n"))
            }
            func main() { http.HandleFunc("/dl", dl); http.HandleFunc("/p", page) }
        """)}
        res = taint_goruby.analyze_files(files, "go")
        self.assertEqual(sorted({(f.sink_kind, f.line) for a in res.values() for f in a.flows}), [("html", 8)])


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class ExpressAttachment(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_attachment_responses_are_not_xss(self):
        files = {"app.js": _src("""
            const express = require('express');
            const app = express();
            app.get('/a', (req, res) => { res.send('Merhaba ' + req.query.n); });
            app.get('/b', (req, res) => { res.attachment('r.csv'); res.send('x' + req.query.n); });
            app.get('/c', (req, res) => {
              res.setHeader('Content-Disposition', 'attachment; filename="r.txt"');
              res.send('x' + req.query.n);
            });
            app.get('/d', (req, res) => { res.attachment('a.txt').send('x' + req.query.n); });
            app.get('/e', (req, res) => { res.status(200).send('x' + req.query.n); });
            app.listen(3000);
        """)}
        results = taint_js_ast.analyze_files(files)
        self.assertIsNotNone(results)
        self.assertEqual(sorted({(f.sink_kind, f.line) for f in results["app.js"].flows if f.sink_kind == "html"}),
                         [("html", 3), ("html", 10)])


if __name__ == "__main__":
    unittest.main()
