"""Go taint motoru (taint_goruby): kaynaklar, hedefler, arındırıcılar ve dosyalar arası özetler."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_goruby as g  # noqa: E402


def _flows(files: dict[str, str]) -> dict[str, list[tuple[str, int]]]:
    res = g.analyze_files({k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}, "go")
    return {k: sorted((f.sink_kind, f.line) for f in v.flows) for k, v in res.items()}


HANDLER = """
    package web

    import (
        "database/sql"
        "fmt"
        "net/http"
        "os/exec"
        "html/template"
    )

    var DB *sql.DB

    func Search(w http.ResponseWriter, r *http.Request) {
        q := r.FormValue("q")
        rows, _ := DB.Query("SELECT * FROM t WHERE name = '" + q + "'")
        _ = rows
        out := fmt.Sprintf("<b>%s</b>", q)
        _ = template.HTML(out)
        exec.Command("sh", "-c", "ping "+q).Run()
    }
"""


class GoTaintTests(unittest.TestCase):
    def test_sql_xss_command_from_request(self):
        flows = _flows({"web/h.go": HANDLER})["web/h.go"]
        self.assertIn(("sql", 15), flows)
        self.assertIn(("html", 18), flows)
        self.assertIn(("command", 19), flows)

    def test_prepared_statement_and_sanitizers_are_clean(self):
        src = """
            package web

            import (
                "database/sql"
                "html"
                "html/template"
                "net/http"
                "os/exec"
                "strconv"
            )

            func Safe(w http.ResponseWriter, r *http.Request, db *sql.DB) {
                id := r.FormValue("id")
                stmt, _ := db.Prepare("SELECT * FROM t WHERE id = ?")
                stmt.QueryRow(id)
                db.Query("SELECT * FROM t WHERE id = ?", id)
                n, _ := strconv.Atoi(id)
                db.Query(fmt.Sprintf("SELECT * FROM t LIMIT %d", n))
                _ = template.HTML(html.EscapeString(id))
                exec.Command("ping", id).Run()
            }
        """
        self.assertEqual(_flows({"web/s.go": src})["web/s.go"], [])

    def test_cross_file_summary_and_branch_weak_update(self):
        files = {
            "go.mod": "module example.com/app\n",
            "store/q.go": """
                package store

                import "database/sql"

                func Find(db *sql.DB, name string) {
                    db.Query("SELECT * FROM u WHERE n = '" + name + "'")
                }
            """,
            "web/h.go": """
                package web

                import (
                    "net/http"
                    "example.com/app/store"
                )

                func H(w http.ResponseWriter, r *http.Request) {
                    name := r.URL.Query().Get("n")
                    if len(name) > 3 {
                        name = escape(name)
                    }
                    store.Find(nil, name)
                }
            """,
        }
        flows = _flows(files)
        self.assertEqual(flows["store/q.go"], [("sql", 6)])

    def test_gin_and_redirect_prefix(self):
        src = """
            package web

            import (
                "net/http"
                "github.com/gin-gonic/gin"
            )

            func G(c *gin.Context) {
                u := c.Query("next")
                c.Redirect(http.StatusFound, u)
                c.Redirect(http.StatusFound, "/home/"+u)
                http.Get("https://api.example.com/v1/" + u)
                http.Get(u)
                c.File(c.Param("f"))
            }
        """
        flows = _flows({"web/g.go": src})["web/g.go"]
        self.assertIn(("redirect", 10), flows)
        self.assertNotIn(("redirect", 11), flows)
        self.assertIn(("ssrf_partial", 12), flows)
        self.assertIn(("ssrf", 13), flows)
        self.assertIn(("path", 14), flows)

    def test_response_writer_respects_content_type_and_funclit(self):
        src = """
            package web

            import (
                "fmt"
                "net/http"
            )

            func Routes() {
                http.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
                    fmt.Fprintf(w, "hi %s", r.FormValue("n"))
                })
                http.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
                    w.Header().Set("Content-Type", "application/json")
                    fmt.Fprintf(w, "{\\"n\\": %q}", r.FormValue("n"))
                })
            }
        """
        flows = _flows({"web/r.go": src})["web/r.go"]
        self.assertEqual(flows, [("html", 10)])

    def test_project_analyzer_reports_go_flow(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "goapp"
            (root / "web").mkdir(parents=True)
            (root / "web" / "h.go").write_text(textwrap.dedent(HANDLER).lstrip("\n"))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        titles = [(f["title"], f["line"]) for f in result["findings"] if f.get("taint_flow")]
        self.assertTrue(any("SQL" in t and line == 15 for t, line in titles), titles)
        self.assertTrue(any("komut" in t and line == 19 for t, line in titles), titles)


if __name__ == "__main__":
    unittest.main()


class JoernFastEngineMatchTests(unittest.TestCase):
    def test_go_mod_prefix_rejects_parent_directory_symlink_replacement(self):
        import joern_active

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            outside = base / "outside"
            project.mkdir()
            outside.mkdir()
            candidate = project / "go.mod"
            candidate.write_text("module verified.example/project\n", encoding="utf-8")
            (outside / "go.mod").write_text("module attacker.example/outside\n", encoding="utf-8")

            project.rename(base / "validated-project")
            project.symlink_to(outside, target_is_directory=True)

            with self.assertRaises((OSError, joern_active.JoernUnavailable)):
                joern_active._read_regular_prefix(candidate, 80_003)

    def test_large_go_mod_keeps_bounded_prefix_for_fast_engine(self):
        import joern_active

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "goapp"
            root.mkdir()
            source = root / "main.go"
            source.write_text("package main\n", encoding="utf-8")
            module_line = "module example.com/large\n"
            (root / "go.mod").write_text(module_line + ("x" * 25_000), encoding="utf-8")
            with mock.patch.object(g, "analyze_files", return_value={}) as analyze:
                joern_active.annotate_fast_engine_matches(root, {"go": [source]}, [])

        files, language = analyze.call_args.args
        self.assertEqual(language, "go")
        self.assertTrue(files["go.mod"].startswith(module_line))
        self.assertEqual(len(files["go.mod"]), 20_000)

    def test_joern_findings_are_annotated_when_fast_engine_agrees(self):
        import joern_active

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "goapp"
            (root / "web").mkdir(parents=True)
            (root / "web" / "h.go").write_text(textwrap.dedent(HANDLER).lstrip("\n"))
            sources = {"go": [root / "web" / "h.go"]}
            findings = [
                {"file": "web/h.go", "line": 15, "taint_flow": {"sink_kind": "sql"}},
                {"file": "web/h.go", "line": 18, "taint_flow": {"sink_kind": "xss"}},
                {"file": "web/h.go", "line": 3, "taint_flow": {"sink_kind": "path"}},
            ]
            summary = joern_active.annotate_fast_engine_matches(root, sources, findings)
        self.assertEqual([f.get("fast_engine_match") for f in findings], [True, True, None])
        self.assertEqual(summary["matched_findings"], 2)
        self.assertEqual(summary["joern_only_findings"], 1)
