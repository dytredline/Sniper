"""14. tur Java/PHP hızlı taint: XPath sonucu, yetkili bağlam notları, JSP sayfaları, PDO bağlı yazma ile kayıtlı
veri, Twig/Smarty SSTI, URL sarmalayıcısı SSRF."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import eval_metrics  # noqa: E402
import taint_clike  # noqa: E402
import taint_clike_lex  # noqa: E402


def analyze(files: dict[str, str]):
    return taint_clike.analyze_files({k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()})


def flows(files: dict[str, str], labels=("request",)) -> list[tuple[str, str, int]]:
    return sorted((f.file, f.sink_kind, f.line) for a in analyze(files).values() for f in a.flows
                  if f.source_label in labels)


class XPathResult(unittest.TestCase):
    def test_xpath_result_is_document_data(self):
        src = """
        <?php
        $xpath = new DOMXPath($doc);
        $query = "/Coffees/Coffee[@ID='" . $_POST['search'] . "']";
        $result = $xpath->query($query);
        foreach ($result as $row) { echo "<td>" . $row->getElementsByTagName('ID')->item(0)->nodeValue . "</td>"; }
        $sx = simplexml_load_file('a.xml');
        $r2 = $sx->xpath("//u[@n='" . $_GET['n'] . "']");
        echo $r2[0]->name;
        """
        self.assertEqual(flows({"x.php": src}), [("x.php", "xpath", 4), ("x.php", "xpath", 7)])

    def test_java_xpath_evaluate_result(self):
        src = """
        import javax.servlet.http.HttpServletRequest;
        class X {
          void run(HttpServletRequest request, java.io.PrintWriter out, javax.xml.xpath.XPath xpath, Object doc) throws Exception {
            String v = xpath.evaluate("/u[@n='" + request.getParameter("n") + "']", doc);
            out.print(v);
          }
        }
        """
        self.assertEqual(flows({"X.java": src}), [("X.java", "xpath", 4)])


class PrivilegedContext(unittest.TestCase):
    SRC = """
    <?php
    function admin_page() {
      if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'no' ); }
      echo $_GET['x'];
    }
    function old_api() {
      _deprecated_function( __FUNCTION__, '1.0' );
      echo $_GET['y'];
    }
    echo $_GET['z'];
    """

    def test_privileged_flows_are_separate(self):
        result = analyze({"p.php": self.SRC})["p.php"]
        self.assertEqual([(f.sink_kind, f.line) for f in result.flows], [("html", 10)])  # üst düzey: korunmuyor
        self.assertEqual([(f.sink_kind, f.line) for f in result.privileged_flows], [("html", 4)])  # kalkmış: yok

    def test_project_analyzer_reports_low_note_outside_eval(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "p.php").write_text(textwrap.dedent(self.SRC).lstrip("\n"))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        flow_findings = [f for f in result["findings"] if f.get("taint_flow")]
        notes = [f for f in flow_findings if f.get("privileged")]
        self.assertEqual([(f["line"], f["severity"]) for f in notes], [(4, "low")])
        self.assertTrue(notes[0]["title"].startswith(project_analyzer.PRIVILEGED_FLOW_PREFIX))
        self.assertTrue(notes[0]["taint_flow"]["privileged"])
        self.assertFalse(eval_metrics.is_verified_flow(notes[0]))
        self.assertEqual(eval_metrics.sniper_items("p", notes, verified_only=False), [])
        verified = [f for f in flow_findings if eval_metrics.is_verified_flow(f)]
        self.assertEqual([f["line"] for f in verified], [10])


class Jsp(unittest.TestCase):
    PAGE = """
    <%@ page language="java" contentType="text/html; charset=UTF-8"%>
    <%-- yorum --%>
    <% String q = request.getParameter("q"); // arama
    %>
    <p>Sonuç: <%= q %></p>
    <input value="<%=(request.getParameter("d")==null)?"":request.getParameter("d")%>"/>
    <p>${param.name}</p>
    <c:out value="${param.safe}"/>
    <p><%= org.owasp.encoder.Encode.forHtml(q) %></p>
    <% String content = request.getParameter("content"); %>
    <jsp:include page="<%= content %>"/>
    <% if (q != null) response.sendRedirect(q); %>
    <%! int count = 0; %>
    <% Runtime.getRuntime().exec(new String[] {"bash", "-c", "cat " + request.getParameter("f")}); %>
    """

    def test_converter_keeps_lines(self):
        page = textwrap.dedent(self.PAGE).lstrip("\n")
        self.assertEqual(taint_clike_lex.jsp_to_java(page).count("\n"), page.count("\n"))

    def test_jsp_sinks(self):
        self.assertEqual(flows({"web/a.jsp": self.PAGE}), [
            ("web/a.jsp", "command", 14), ("web/a.jsp", "html", 5), ("web/a.jsp", "html", 6),
            ("web/a.jsp", "html", 7), ("web/a.jsp", "path", 11), ("web/a.jsp", "redirect", 12)])

    def test_non_html_content_type(self):
        page = """
        <%@ page contentType="application/json"%>
        {"q": "<%= request.getParameter("q") %>"}
        """
        self.assertEqual(flows({"api.jsp": page}), [])


class PhpStoredAndTemplates(unittest.TestCase):
    def test_pdo_bound_write_then_read(self):
        src = """
        <?php
        $stmt = $db->prepare("insert into comments (user, comment) values (:user, :comment)");
        $stmt->bindParam(":user", $_POST['name']);
        $stmt->bindParam(":comment", $_POST['msg']);
        $stmt->execute();
        $u = $db->prepare('UPDATE users SET seen = now() WHERE user = (:user)');
        $u->bindParam(':user', $_POST['who']);
        $u->execute();
        $r = $db->prepare("select user, comment from comments");
        $r->execute();
        while ($row = $r->fetch()) { echo "<p>" . $row[1] . "</p>"; }
        $s = $db->prepare("select * from users");
        $s->execute();
        while ($row = $s->fetch()) { echo "<p>" . $row[0] . "</p>"; }
        """
        self.assertEqual(flows({"c.php": src}, labels=("stored",)), [("c.php", "html", 11)] * 2)  # name + msg; users yazılmadı

    def test_twig_and_smarty_ssti(self):
        src = """
        <?php
        $loader = new Twig_Loader_String();
        $twig = new Twig_Environment($loader);
        $out = $twig->render($_GET['name']);
        $t = $twig->createTemplate($_GET['tpl']);
        $smarty->display('string:' . $_GET['s']);
        $smarty->display('page.tpl');
        """
        self.assertEqual([k for k in flows({"t.php": src}) if k[1] == "ssti"],
                         [("t.php", "ssti", 4), ("t.php", "ssti", 5), ("t.php", "ssti", 6)])

    def test_twig_file_loader_render_is_not_ssti(self):
        src = """
        <?php
        $twig = new \\Twig\\Environment(new \\Twig\\Loader\\FilesystemLoader('templates'));
        echo $twig->render('page.html', ['name' => $_GET['name']]);
        """
        self.assertNotIn("ssti", [k[1] for k in flows({"t.php": src})])

    def test_url_wrapper_ssrf(self):
        src = """
        <?php
        $img = file_get_contents($_POST['img_url']);
        $page = file_get_contents($_GET['page']);
        $x = file_get_contents('http://api.local/' . $_GET['feed_url']);
        """
        got = flows({"s.php": src})
        self.assertIn(("s.php", "ssrf", 2), got)
        self.assertNotIn(("s.php", "ssrf", 3), got)  # dosya adı alanı: yalnız yol hedefi
        self.assertNotIn(("s.php", "ssrf", 4), got)  # sabit önekli adres


if __name__ == "__main__":
    unittest.main()
