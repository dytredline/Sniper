"""17. tur W2-XSS: XSS kesinliği (sınıf düzeyi).

* jQuery öğe nesneleri: ``$('<a/>', {href: x})`` ve ``.attr()/.text(x)`` ayarlayıcı zincirleri DOM öğesidir; eklenmeleri
  HTML ayrıştırması yapmaz. ``$('#' + x)`` gibi '<' ile başlamayan sabit önekli dizge seçicidir. Yalnız alan yazımıyla
  kirlenen nesnenin kendisi ya da başka alanı (``$(form)``, ``$(options.target)``) HTML dizgesi değildir.
* Dosya içeriği: yol istekten gelse de okunan içerik HTML bağlamında saldırgan verisi değildir (PHP, C#, Go, Java
  okuyucuları); yol aşımı hedefi ayrıca raporlanır.
* Yardımcılar arası içerik türü: ``asJson(res)`` / ``json_headers()`` / ``json(resp)`` çağıranın yanıtına da uygulanır;
  sonlanan daldaki (``exit`` / ``return``) içerik türü sonraki çıktıya taşınmaz.
* Twig varsayılan otomatik kaçışı: ``|raw`` içermeyen dosya şablonunun ``render()`` sonucu kaçışlı HTML'dir.
* ``request.getRemoteUser()`` kimliği doğrulanmış kullanıcı adıdır (HTML bağlamında kaynak değil).
"""
import os
from pathlib import Path
import sys
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402
import taint_goruby  # noqa: E402
import taint_js_ast  # noqa: E402
from tests.test_taint_js_ast import NODE_ENV  # noqa: E402


def _src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def clike(files: dict[str, str], extra: dict[str, str] | None = None) -> list[tuple[str, str, int]]:
    res = taint_clike.analyze_files({k: _src(v) for k, v in files.items()}, extra)
    return sorted({(f.sink_kind, f.file, f.line) for a in res.values() for f in a.flows})


def html_lines(flows: list[tuple[str, str, int]]) -> list[int]:
    return sorted(line for kind, _, line in flows if kind == "html")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsDomAndHelpers(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def html(self, text: str, name: str = "a.js") -> list[int]:
        results = taint_js_ast.analyze_files({name: _src(text)})
        self.assertIsNotNone(results)
        return sorted({f.line for f in results[name].flows if f.sink_kind == "html"})

    def test_jquery_elements_selectors_and_field_only_objects(self):
        self.assertEqual(self.html("""
            function prep(form) {
              if (!form.action) { form.action = location.href; }
              $(form).addClass('x');
            }
            function sub(options) {
              options.url = window.location.href;
              $(options.target).html('ok');
              $('<iframe src="' + options.url + '"/>');
            }
            var u = location.href.split('?')[0];
            var $tab = $('<li class="x"/>').append($('<a/>', { href: u, text: 'Sonuç' }));
            $('.links').prepend($tab);
            $('ul').append($('<li></li>').append($('<a></a>').attr('href', u + '#1').text('t')));
            $('#' + location.hash.slice(1)).addClass('on');
            $(location.hash);
            $('div').html(location.hash);
            var el = $('<div/>').text(location.hash);
            $('#out').html(el.text());
            $(`#${location.hash.slice(1)}`).show();
        """), [8, 15, 16, 18])

    def test_content_type_helper_and_terminating_branch(self):
        self.assertEqual(self.html("""
            const express = require('express'); const app = express();
            function asJson(res) { res.set('Content-Type', 'application/json'); }
            function asText(r) { r.type('text/plain'); }
            app.get('/a', (req, res) => { asJson(res); res.send(req.query.q); });
            app.get('/b', (req, res) => { asText(res); res.send(req.query.q); });
            app.get('/c', (req, res) => { res.send('<b>' + req.query.q + '</b>'); });
            app.get('/d', (req, res) => {
              if (!req.query.q) { asJson(res); return res.send('{}'); }
              res.send('<p>' + req.query.q + '</p>');
            });
            app.get('/e', (req, res) => {
              if (req.query.f === 'j') { res.type('json'); } else { res.type('json'); }
              res.send(req.query.q);
            });
        """), [6, 9])


class FileContent(unittest.TestCase):
    def test_php_file_reads(self):
        flows = clike({"a.php": """
            <?php
            echo file_get_contents($_GET['f']);
            echo "<p>" . $_GET['f'] . "</p>";
            $c = file($_GET['f']); echo $c[0];
            echo file_get_contents("pages/" . $_GET['p']);
            echo file_get_contents($_GET['url']);
        """})
        self.assertEqual(html_lines(flows), [3, 6])
        self.assertIn(("path", "a.php", 2), flows)
        self.assertIn(("path", "a.php", 4), flows)

    def test_csharp_java_go_file_reads(self):
        cs = clike({"C.cs": """
            using Microsoft.AspNetCore.Mvc;
            public class FController : Controller {
                public IActionResult A(string f) { return Content(System.IO.File.ReadAllText(f), "text/html"); }
                public IActionResult B(string f) { return Content("<p>" + f + "</p>", "text/html"); }
            }
        """})
        self.assertEqual(html_lines(cs), [4])
        self.assertIn(("path", "C.cs", 3), cs)
        java = clike({"G.java": """
            import javax.servlet.http.*; import java.io.*;
            public class G extends HttpServlet {
              protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                String x = req.getParameter("x");
                BufferedReader r = new BufferedReader(new FileReader(x));
                while ((x = r.readLine()) != null) { resp.getWriter().println(x); }
                resp.getWriter().println(req.getRemoteUser());
                resp.getWriter().println(req.getParameter("y"));
              }
            }
        """})
        self.assertEqual(html_lines(java), [8])
        self.assertIn(("path", "G.java", 5), java)
        files = {"go.mod": "module ex\n", "main.go": _src("""
            package main
            import ("net/http"; "os")
            func h(w http.ResponseWriter, r *http.Request) {
                b, _ := os.ReadFile(r.URL.Query().Get("f"))
                w.Write(b)
            }
            func main() { http.HandleFunc("/", h) }
        """)}
        res = taint_goruby.analyze_files(files, "go")
        self.assertEqual(sorted({(f.sink_kind, f.line) for a in res.values() for f in a.flows}), [("path", 4)])


class ContentTypeHelpers(unittest.TestCase):
    def test_php_helper_and_exiting_helper(self):
        flows = clike({"a.php": """
            <?php
            function json_headers() { header('Content-Type: application/json; charset=utf-8'); }
            function json_err() { header('Content-Type: application/json'); echo '{"ok":false}'; exit; }
            json_headers();
            echo $_GET['q'];
        """, "b.php": """
            <?php
            function json_err() { header('Content-Type: application/json'); echo '{"ok":false}'; exit; }
            if (!isset($_GET['q'])) { json_err(); }
            echo "<p>" . $_GET['q'] . "</p>";
            if (empty($_GET['z'])) { header('Content-Type: application/json'); echo '{}'; exit; }
            echo "<p>" . $_GET['z'] . "</p>";
        """})
        self.assertEqual([(f, line) for kind, f, line in flows if kind == "html"], [("b.php", 4), ("b.php", 6)])

    def test_java_helper(self):
        flows = clike({"S.java": """
            import javax.servlet.http.*;
            public class S extends HttpServlet {
              private void json(HttpServletResponse r) { r.setContentType("application/json"); }
              protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
                json(resp);
                resp.getWriter().print(req.getParameter("q"));
              }
              protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
                resp.getWriter().print(req.getParameter("q"));
              }
            }
        """})
        self.assertEqual(html_lines(flows), [9])


class TwigAutoescape(unittest.TestCase):
    PAGE = """
        <?php
        $loader = new \\Twig\\Loader\\FilesystemLoader('templates');
        $twig = new \\Twig\\Environment($loader);
        echo $twig->render('t.twig', ['q' => $_GET['q']]);
    """

    def test_escaped_template_is_not_xss(self):
        self.assertEqual(html_lines(clike({"index.php": self.PAGE})), [])

    def test_raw_filter_template_stays_xss(self):
        extra = {"templates/t.twig": "<p>{{ q|raw }}</p>\n"}
        self.assertEqual(html_lines(clike({"index.php": self.PAGE}, extra)), [4])


if __name__ == "__main__":
    unittest.main()
