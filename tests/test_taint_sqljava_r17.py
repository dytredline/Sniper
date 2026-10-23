"""17. tur W2-SQLJAVA: PHP SQL arındırıcıları (sprintf, settype, tırnak ikileme, süper küresel toplu arındırma,
kapanışlı array_map, yüklem karşılaştırmaları), yönlendirme/yol korumaları (ana makine denetimi, "/" + "//" öneki,
kanonik yol + kök öneki, File.getName), Java duyarlılığı (@ModelAttribute alıcıları, Thymeleaf th:utext, Spring Data
kayıtlı veri, zincirli StringBuilder) ve Ruby ActiveRecord kayıtlı verisi; Go dosya içeriği ve işlev düzeyi korumalar."""
from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402
import taint_goruby  # noqa: E402


def _dedent(files: dict[str, str]) -> dict[str, str]:
    return {k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}


def flows(files: dict[str, str], extra: dict[str, str] | None = None, labels=("request", "stored")) -> list[tuple]:
    res = taint_clike.analyze_files(_dedent(files), _dedent(extra or {}))
    return sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label in labels)


def rb_flows(files: dict[str, str]) -> list[tuple]:
    res = taint_goruby.analyze_files(_dedent(files), "ruby")
    return sorted((f.file, f.sink_kind, f.line, f.source_label) for a in res.values() for f in a.flows)


def go_flows(src: str) -> list[tuple]:
    res = taint_goruby.analyze_files({"main.go": textwrap.dedent(src).lstrip("\n")}, "go")
    return sorted((f.sink_kind, f.line) for a in res.values() for f in a.flows)


PHP_HEAD = "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\n"


def php(body: str) -> dict[str, str]:
    return {"a.php": PHP_HEAD + textwrap.dedent(body).lstrip("\n")}


class PhpSqlSanitizers(unittest.TestCase):
    def test_sprintf_numeric_specifiers_are_clean(self):
        self.assertEqual(flows(php("""
            $sql = sprintf("SELECT * FROM o WHERE id = %d AND n = %u", $_GET['a'], $_GET['b']);
            mysqli_query($conn, $sql);
            """)), [])

    def test_sprintf_escaped_string_inside_quotes_is_clean_but_unquoted_is_not(self):
        quoted = php("""
            mysqli_query($conn, sprintf("SELECT * FROM t WHERE b = '%s'", mysqli_real_escape_string($conn, $_GET['b'])));
            """)
        unquoted = php("""
            mysqli_query($conn, sprintf("SELECT * FROM t WHERE b = %s", mysqli_real_escape_string($conn, $_GET['b'])));
            """)
        self.assertEqual(flows(quoted), [])
        self.assertEqual(flows(unquoted), [("a.php", "sql", 3)])

    def test_settype_and_quote_doubling(self):
        self.assertEqual(flows(php("""
            $s = $_GET['s']; settype($s, "integer");
            mysqli_query($conn, "SELECT * FROM t WHERE s = $s");
            """)), [])
        # Tırnak ikileme MySQL'de ters eğik çizgiyle atlatılır: tırnak içinde de açık sayılır.
        self.assertEqual(flows(php("""
            $q = str_replace("'", "''", $_GET['q']);
            mysqli_query($conn, "SELECT * FROM t WHERE q = '$q'");
            """)), [("a.php", "sql", 4)])
        self.assertEqual(flows(php("""
            $q = str_replace("'", "''", $_GET['q']);
            mysqli_query($conn, "SELECT * FROM t WHERE q = $q");
            """)), [("a.php", "sql", 4)])

    def test_superglobal_bulk_escape_in_foreach(self):
        self.assertEqual(flows(php("""
            foreach ($_POST as $k => $v) { $_POST[$k] = mysqli_real_escape_string($conn, $v); }
            mysqli_query($conn, "SELECT * FROM t WHERE a = '" . $_POST['a'] . "'");
            """)), [])
        # yalnız trim: arındırma değil; kaçış + tırnaksız sayısal bağlam: hâlâ açık
        self.assertEqual(flows(php("""
            foreach ($_POST as $k => $v) { $_POST[$k] = trim($v); }
            mysqli_query($conn, "SELECT * FROM t WHERE a = '" . $_POST['a'] . "'");
            """)), [("a.php", "sql", 4)])
        self.assertEqual(flows(php("""
            foreach ($_POST as $k => $v) { $_POST[$k] = mysqli_real_escape_string($conn, $v); }
            mysqli_query($conn, "SELECT * FROM t WHERE a = " . $_POST['a']);
            """)), [("a.php", "sql", 4)])

    def test_array_map_closure_and_superglobal_reassignment(self):
        self.assertEqual(flows(php("""
            $_POST = array_map(function($v) use ($conn) { return mysqli_real_escape_string($conn, $v); }, $_POST);
            mysqli_query($conn, "SELECT * FROM t WHERE b = '" . $_POST['b'] . "'");
            $_GET = array_map("intval", $_GET);
            mysqli_query($conn, "SELECT * FROM t WHERE a = " . $_GET['a']);
            """)), [])
        self.assertEqual(flows(php("""
            $_POST = array_map(fn($v) => trim($v), $_POST);
            mysqli_query($conn, "SELECT * FROM t WHERE a = '" . $_POST['a'] . "'");
            """)), [("a.php", "sql", 4)])

    def test_predicate_compared_to_literal(self):
        self.assertEqual(flows(php("""
            $p = $_GET['p'];
            if (preg_match("/^[a-z0-9_]+$/i", $p) !== 1) { die(); }
            mysqli_query($conn, "SELECT * FROM t WHERE p = '$p'");
            """)), [])
        self.assertEqual(flows(php("""
            $p = $_GET['p'];
            if (preg_match("/^[a-z0-9_]+$/i", $p) == 0) { mysqli_query($conn, "SELECT * FROM t WHERE p = '$p'"); }
            """)), [("a.php", "sql", 4)])


class RedirectAndPathGuards(unittest.TestCase):
    def test_php_host_check_and_prefix_guard(self):
        src = {"r1.php": """
            <?php
            $u = $_GET['next'];
            $h = parse_url($u, PHP_URL_HOST);
            if ($h !== null && $h !== 'example.com') { exit; }
            header("Location: " . $u);
            """, "r2.php": """
            <?php
            $u = $_GET['next'];
            if (strpos($u, '/') !== 0 || strpos($u, '//') === 0) { $u = '/'; }
            header("Location: " . $u);
            """, "neg.php": """
            <?php
            $u = $_GET['next'];
            if (strpos($u, '/') !== 0) { $u = '/'; }
            header("Location: " . $u);
            $h = parse_url($_GET['x'], PHP_URL_HOST);
            error_log($h);
            header("Location: " . $_GET['x']);
            """}
        self.assertEqual(flows(src), [("neg.php", "redirect", 4), ("neg.php", "redirect", 7)])

    def test_php_realpath_prefix_and_java_normalize_startswith(self):
        src = {"p.php": """
            <?php
            $p = realpath("/var/www/files/" . $_GET['g']);
            if ($p === false || strpos($p, "/var/www/files/") !== 0) { die("x"); }
            readfile($p);
            """, "q.php": """
            <?php
            $p = realpath("/var/www/files/" . $_GET['g']);
            readfile($p);
            """, "C.java": """
            import javax.servlet.http.*;
            import java.nio.file.*;
            public class C extends HttpServlet {
              protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
                Path base = Paths.get("/srv/files");
                Path p = base.resolve(req.getParameter("f")).normalize();
                if (!p.startsWith(base)) { resp.sendError(403); return; }
                Files.copy(p, resp.getOutputStream());
                String fn = new java.io.File(req.getParameter("g")).getName();
                new java.io.FileInputStream("/srv/files/" + fn);
              }
            }
            """}
        self.assertEqual(flows(src), [("q.php", "path", 3)])

    def test_java_uri_host_check_and_slash_prefix(self):
        src = {"D.java": """
            import javax.servlet.http.*;
            import java.net.URI;
            public class D extends HttpServlet {
              protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
                String n = req.getParameter("next");
                URI uri = URI.create(n);
                if (uri.getHost() != null && !"example.com".equals(uri.getHost())) { resp.sendError(400); return; }
                resp.sendRedirect(n);
                String m = req.getParameter("m");
                if (!m.startsWith("/") || m.startsWith("//")) { m = "/"; }
                resp.sendRedirect(m);
                String o = req.getParameter("o");
                if (!o.startsWith("/")) { o = "/"; }
                resp.sendRedirect(o);
              }
            }
            """}
        self.assertEqual(flows(src), [("D.java", "redirect", 14)])


class JavaRecall(unittest.TestCase):
    CTRL = """
        package demo;
        import org.springframework.web.bind.annotation.*;
        import org.springframework.stereotype.Controller;
        import org.springframework.ui.Model;
        import org.springframework.jdbc.core.JdbcTemplate;
        @Controller
        public class UserController {
          JdbcTemplate jdbc;
          UserRepository repo;
          @PostMapping("/a")
          @ResponseBody
          public Object a(@ModelAttribute UserForm form) {
            return jdbc.queryForList("SELECT * FROM users WHERE email = '" + form.getEmail() + "'");
          }
          @GetMapping("/b")
          public String b(@RequestParam String msg, Model model) {
            model.addAttribute("msg", msg);
            return "show";
          }
          @PostMapping("/c")
          @ResponseBody
          public String c(@RequestParam String comment) {
            Comment cm = new Comment();
            cm.setText(comment);
            repo.save(cm);
            return "ok";
          }
          @GetMapping("/d")
          @ResponseBody
          public String d() {
            StringBuilder sb = new StringBuilder();
            for (Comment x : repo.findAll()) { sb.append("<p>").append(x.getText()).append("</p>"); }
            return sb.toString();
          }
          @GetMapping("/e")
          @ResponseBody
          public Object e(@RequestParam String n) {
            return repo.findByName(n);
          }
        }
        """
    OTHERS = {
        "demo/UserForm.java": "package demo;\npublic class UserForm { private String email; "
                              "public String getEmail(){return email;} public void setEmail(String e){email=e;} }\n",
        "demo/Comment.java": "package demo;\npublic class Comment { private String text; "
                             "public String getText(){return text;} public void setText(String t){text=t;} }\n",
        "demo/UserRepository.java": "package demo;\nimport org.springframework.data.jpa.repository.JpaRepository;\n"
                                    "public interface UserRepository extends JpaRepository<Comment, Long> {}\n",
    }

    def test_spring_model_attribute_thymeleaf_and_jpa_stored(self):
        files = {"demo/UserController.java": self.CTRL, **self.OTHERS}
        extra = {"src/main/resources/templates/show.html":
                 '<html xmlns:th="http://www.thymeleaf.org"><body><div th:utext="${msg}"></div></body></html>\n'}
        got = flows(files, extra)
        self.assertIn(("demo/UserController.java", "sql", 13), got)    # @ModelAttribute alıcısı
        self.assertIn(("demo/UserController.java", "html", 17), got)   # th:utext model özniteliği
        self.assertIn(("demo/UserController.java", "html", 33), got)   # JPA kayıtlı veri → @ResponseBody
        self.assertNotIn(("demo/UserController.java", "html", 38), got)  # Object (varlık listesi) JSON'a çevrilir

    def test_thymeleaf_escaped_text_is_not_a_sink(self):
        files = {"demo/UserController.java": self.CTRL, **self.OTHERS}
        extra = {"src/main/resources/templates/show.html": '<div th:text="${msg}"></div>\n'}
        self.assertNotIn(("demo/UserController.java", "html", 17), flows(files, extra))


class RubyStored(unittest.TestCase):
    def test_active_record_written_attribute_is_stored_source(self):
        files = {
            "app/controllers/posts_controller.rb": """
                class PostsController < ApplicationController
                  def show
                    @note = Post.find(params[:id]).body
                    @title = Post.find(params[:id]).title
                  end
                  def create
                    Post.create(body: params[:body])
                  end
                end
                """,
            "app/views/posts/show.html.erb": "<p><%= @note.html_safe %></p>\n<p><%= @title.html_safe %></p>\n",
            "app/models/post.rb": "class Post < ApplicationRecord\nend\n",
        }
        got = rb_flows(files)
        self.assertIn(("app/views/posts/show.html.erb", "html", 1, "stored"), got)
        self.assertNotIn(("app/views/posts/show.html.erb", "html", 2, "stored"), got)  # title yazılmadı


class GoFileAndGuards(unittest.TestCase):
    def test_file_content_is_not_request_data_and_function_guards(self):
        src = """
            package main
            import ("net/http"; "net/url"; "os"; "path/filepath"; "strings")
            func a(w http.ResponseWriter, r *http.Request) {
                n := r.URL.Query().Get("next")
                u, err := url.Parse(n)
                if err != nil || (u.Host != "" && u.Host != "example.com") { http.Error(w, "x", 400); return }
                http.Redirect(w, r, n, 302)
            }
            func c(w http.ResponseWriter, r *http.Request) {
                p := filepath.Join("/srv/files", filepath.Clean("/"+r.URL.Query().Get("f")))
                if !strings.HasPrefix(p, "/srv/files/") { return }
                d, _ := os.ReadFile(p); w.Write(d)
            }
            func pos(w http.ResponseWriter, r *http.Request) {
                http.Redirect(w, r, r.URL.Query().Get("to"), 302)
                d, _ := os.ReadFile("/srv/files/" + r.URL.Query().Get("f")); w.Write(d)
            }
            func main() { http.HandleFunc("/a", a); http.HandleFunc("/c", c); http.HandleFunc("/p", pos) }
            """
        self.assertEqual(go_flows(src), [("path", 16), ("redirect", 15)])


if __name__ == "__main__":
    unittest.main()
