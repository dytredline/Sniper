"""17. tur derin model boşlukları: Go kayıtlı (ikinci derece) XSS, Python MongoDB sözlük anahtarı/operatör
enjeksiyonu, Struts2 ``<s:property escape="false">`` (istek alanı, #parameters, iterator ile kayıtlı veri)."""
from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402
import taint_flow  # noqa: E402
import taint_goruby as g  # noqa: E402


def _go(files: dict[str, str]) -> list[tuple[str, int, str, str]]:
    files = {"go.mod": "module ex\n", **{k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}}
    res = g.analyze_files(files, "go")
    return sorted({(f.file, f.line, f.sink_kind, f.source_label) for a in res.values() for f in a.flows})


class GoStoredXssTests(unittest.TestCase):
    def test_database_sql_write_then_read_to_writer_and_template(self):
        found = _go({"web/a.go": """
            package web
            import ("database/sql"; "fmt"; "html/template"; "net/http")
            var db *sql.DB
            func add(w http.ResponseWriter, r *http.Request) {
                db.Exec("INSERT INTO comments(body) VALUES(?)", r.FormValue("body"))
            }
            func list(w http.ResponseWriter, r *http.Request) {
                rows, _ := db.Query("SELECT body FROM comments")
                for rows.Next() {
                    var b string
                    rows.Scan(&b)
                    fmt.Fprintf(w, "<li>%s</li>", b)
                }
            }
            func one(w http.ResponseWriter, r *http.Request) {
                var b string
                db.QueryRow("SELECT body FROM comments WHERE id = ?", 1).Scan(&b)
                w.Write([]byte(template.HTML(b)))
            }
        """})
        self.assertIn(("web/a.go", 12, "html", "stored"), found)
        self.assertTrue(any(f[1] == 18 and f[3] == "stored" for f in found), found)

    def test_unwritten_table_numeric_target_and_other_columns_are_clean(self):
        found = _go({"web/a.go": """
            package web
            import ("database/sql"; "fmt"; "net/http")
            var db *sql.DB
            func add(w http.ResponseWriter, r *http.Request) {
                db.Exec("UPDATE users SET bio = ? WHERE id = 1", r.FormValue("bio"))
            }
            func settings(w http.ResponseWriter, r *http.Request) {
                var n string
                db.QueryRow("SELECT name FROM settings").Scan(&n)
                fmt.Fprintf(w, "<p>%s</p>", n)
            }
            func count(w http.ResponseWriter, r *http.Request) {
                var c int
                db.QueryRow("SELECT bio FROM users").Scan(&c)
                fmt.Fprintf(w, "<p>%d</p>", c)
            }
            func names(w http.ResponseWriter, r *http.Request) {
                var e string
                db.QueryRow("SELECT email FROM users").Scan(&e)
                fmt.Fprintf(w, "<p>%s</p>", e)
            }
        """})
        self.assertEqual([f for f in found if f[3] == "stored"], [])

    def test_helper_function_write_and_text_template(self):
        found = _go({
            "web/store.go": """
                package web
                import "database/sql"
                var db *sql.DB
                func saveNote(t string) { db.Exec("INSERT INTO notes(text) VALUES(?)", t) }
            """,
            "web/h.go": """
                package web
                import ("net/http"; "text/template")
                type Note struct{ Text string }
                func add(w http.ResponseWriter, r *http.Request) { saveNote(r.FormValue("t")) }
                func show(w http.ResponseWriter, r *http.Request) {
                    var n Note
                    db.QueryRow("SELECT text FROM notes").Scan(&n.Text)
                    t := template.Must(template.New("x").Parse("{{.Text}}"))
                    t.Execute(w, n)
                }
            """,
        })
        self.assertIn(("web/h.go", 9, "html", "stored"), found)

    def test_gorm_create_then_find_and_bluemonday_sanitizer(self):
        found = _go({"web/a.go": """
            package web
            import ("html/template"; "net/http"; "github.com/gin-gonic/gin"; "github.com/microcosm-cc/bluemonday"; "gorm.io/gorm")
            var db *gorm.DB
            type Post struct{ Body string }
            func create(c *gin.Context) { var p Post; c.ShouldBind(&p); db.Create(&p) }
            func show(c *gin.Context) {
                var posts []Post
                db.Where("id > ?", 0).Find(&posts)
                c.HTML(http.StatusOK, "x", gin.H{"b": template.HTML(posts[0].Body)})
            }
            func safe(c *gin.Context) {
                var posts []Post
                db.Find(&posts)
                p := bluemonday.UGCPolicy()
                c.HTML(http.StatusOK, "x", gin.H{"b": template.HTML(p.Sanitize(posts[0].Body))})
            }
        """})
        self.assertIn(("web/a.go", 9, "html", "stored"), found)
        self.assertFalse(any(f[1] == 14 for f in found), found)


def _py(src: str) -> list[tuple[int, str, str]]:
    res = taint_flow.analyze_python_files({"app.py": textwrap.dedent(src).lstrip("\n")})
    return sorted({(f.line, f.sink_kind, f.source) for a in res.values() for f in a.flows})


class PythonMongoOperatorTests(unittest.TestCase):
    HEAD = """
        from flask import Flask, request
        from pymongo import MongoClient
        app = Flask(__name__)
        db = MongoClient()["shop"]
    """

    def test_key_and_where_operator_from_string_sources(self):
        found = _py(self.HEAD + """
        @app.route("/a")
        def a():
            return str(db.users.find_one({request.args.get("f"): request.args.get("v")}))
        @app.route("/b")
        def b():
            q = {}
            q[request.args["k"]] = request.args["v"]
            return str(db.users.find_one(q))
        @app.route("/c")
        def c():
            name = request.form["name"]
            return str(db.users.find_one({"$where": "this.name == '" + name + "'"}))
        """)
        lines = {line for line, kind, _ in found if kind == "nosql"}
        self.assertEqual(lines, {8, 13, 17}, found)
        self.assertTrue(all("sorgu anahtarı/operatörü" in src for _, kind, src in found if kind == "nosql"))

    def test_constant_keys_with_string_values_are_clean(self):
        found = _py(self.HEAD + """
        @app.route("/d")
        def d():
            return str(db.users.find_one({"name": request.args.get("name")}))
        @app.route("/e")
        def e():
            q = {"status": "active"}
            q["name"] = request.args.get("n")
            return str(db.users.find_one(q))
        """)
        self.assertEqual([f for f in found if f[1] == "nosql"], [])


STRUTS_XML = """<struts><package name="d" extends="struts-default">
  <action name="search" class="com.x.SearchAction"><result name="success">/search.jsp</result></action>
  <action name="list" class="com.x.ProductAction" method="list"><result>/products.jsp</result></action>
  <action name="add" class="com.x.ProductAction" method="add"><result type="redirectAction">list</result></action>
</package></struts>"""

STRUTS_FILES = {
    "src/com/x/SearchAction.java": """
        package com.x;
        import com.opensymphony.xwork2.ActionSupport;
        public class SearchAction extends ActionSupport {
            private String query;
            private String note;
            public void setQuery(String query) { this.query = query; }
            public String getQuery() { return query; }
            public void setNote(String note) { this.note = note; }
            public String execute() { return SUCCESS; }
        }
    """,
    "src/com/x/ProductAction.java": """
        package com.x;
        import com.opensymphony.xwork2.ActionSupport;
        import java.util.List;
        public class ProductAction extends ActionSupport {
            private String name;
            private List<Product> products;
            private ProductDao dao = new ProductDao();
            public void setName(String name) { this.name = name; }
            public String add() throws Exception { dao.insert(name); return SUCCESS; }
            public String list() throws Exception { products = dao.findAll(); return SUCCESS; }
        }
    """,
    "src/com/x/Product.java": """
        package com.x;
        public class Product { private String name; public Product(String n) { name = n; } public String getName() { return name; } }
    """,
    "src/com/x/ProductDao.java": """
        package com.x;
        import java.sql.*;
        import java.util.*;
        public class ProductDao {
            private Connection conn;
            public void insert(String name) throws SQLException {
                PreparedStatement ps = conn.prepareStatement("INSERT INTO products(name) VALUES(?)");
                ps.setString(1, name);
                ps.executeUpdate();
            }
            public List<Product> findAll() throws SQLException {
                List<Product> out = new ArrayList<>();
                ResultSet rs = conn.createStatement().executeQuery("SELECT name FROM products");
                while (rs.next()) { out.add(new Product(rs.getString("name"))); }
                return out;
            }
        }
    """,
    "WebContent/search.jsp": """
        <%@ taglib prefix="s" uri="/struts-tags" %>
        <p><s:property value="query" escape="false"/></p>
        <p><s:property value="note"/></p>
        <p><s:property value="%{#parameters.q}" escapeHtml="false"/></p>
    """,
    "WebContent/products.jsp": """
        <%@ taglib prefix="s" uri="/struts-tags" %>
        <s:iterator value="products">
          <li><s:property value="name" escape="false"/></li>
        </s:iterator>
    """,
    "WebContent/orphan.jsp": """
        <%@ taglib prefix="s" uri="/struts-tags" %>
        <p><s:property value="query" escape="false"/></p>
    """,
}


class StrutsPropertyTests(unittest.TestCase):
    def _flows(self, files: dict[str, str], extra: dict[str, str]) -> list[tuple[str, int, str]]:
        files = {k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}
        res = taint_clike.analyze_files(files, extra)
        return sorted({(f.file, f.line, f.source_label) for a in res.values() for f in a.flows if f.sink_kind == "html"})

    def test_unescaped_property_request_parameters_and_stored_iterator(self):
        found = self._flows(STRUTS_FILES, {"src/main/resources/struts.xml": STRUTS_XML})
        self.assertIn(("WebContent/search.jsp", 2, "request"), found)
        self.assertIn(("WebContent/search.jsp", 4, "request"), found)
        self.assertIn(("WebContent/products.jsp", 3, "stored"), found)
        self.assertFalse(any(f[1] == 3 and f[0].endswith("search.jsp") for f in found), "kaçışlı özellik")
        self.assertFalse(any(f[0].endswith("orphan.jsp") for f in found), "eylemle eşlenmeyen sayfa")

    def test_without_struts_xml_no_property_flows(self):
        found = self._flows(STRUTS_FILES, {})
        self.assertFalse(any(f[0].endswith(".jsp") for f in found), found)


if __name__ == "__main__":
    unittest.main()
