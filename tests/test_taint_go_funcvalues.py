"""Go taint motoru (14. tur): işlev değeriyle yapılan çağrılar ve işleyici kayıtları — yapı alanları, eşlem/dilim
işleyicileri, kapanış fabrikaları, parametre olarak geçen işlevler, tür dönüşümleri, tür iddiası, blok kapsamı."""
from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_goruby as g  # noqa: E402


def _flows(src: str) -> list[tuple[str, int]]:
    files = {"go.mod": "module ex\n", "web/a.go": textwrap.dedent(src).lstrip("\n")}
    res = g.analyze_files(files, "go")
    return sorted({(f.sink_kind, f.line) for a in res.values() for f in a.flows})


class GoFunctionValueTests(unittest.TestCase):
    def test_named_and_method_value_handlers(self):
        src = """
            package web
            import ("net/http"; "os"; "os/exec")
            func run(w http.ResponseWriter, r *http.Request) { exec.Command("sh", "-c", r.FormValue("c")).Run() }
            type Files struct{}
            func (Files) ServeHTTP(w http.ResponseWriter, r *http.Request) { os.Open(r.URL.Path) }
            type Svc struct{}
            func (s *Svc) del(w http.ResponseWriter, r *http.Request) { os.Remove(r.FormValue("f")) }
            func main() { s := &Svc{}; http.HandleFunc("/run", run); http.Handle("/f", Files{}); http.HandleFunc("/d", s.del) }
        """
        self.assertEqual(_flows(src), [("command", 3), ("path", 5), ("path", 7)])

    def test_handlerfunc_conversion_and_function_parameter(self):
        src = """
            package web
            import ("net/http"; "os/exec")
            func doRun(cmd string) { exec.Command("sh", "-c", cmd).Run() }
            func wrap(fn func(string)) http.HandlerFunc {
                return func(w http.ResponseWriter, r *http.Request) {
                    fn(r.URL.Query().Get("c"))
                }
            }
            func main() { http.Handle("/run", http.HandlerFunc(wrap(doRun))) }
        """
        self.assertEqual(_flows(src), [("command", 3)])

    def test_map_and_package_slice_of_handlers(self):
        src = """
            package web
            import ("net/http"; "os/exec"; "os")
            func runCmd(s string) { exec.Command("bash", "-c", s).Run() }
            func readF(s string) { os.ReadFile(s) }
            var steps = []func(string) error{
                func(p string) error { return os.Remove(p) },
            }
            func H(w http.ResponseWriter, r *http.Request) {
                actions := map[string]func(string){
                    "run": runCmd,
                    "read": readF,
                }
                actions[r.FormValue("a")](r.FormValue("v"))
                for _, s := range steps { s(r.FormValue("p")) }
            }
        """
        self.assertEqual(_flows(src), [("command", 3), ("path", 4), ("path", 6)])

    def test_struct_field_function_and_arity_filter(self):
        src = """
            package web
            import ("net/http"; "os/exec"; "database/sql")
            var db *sql.DB
            type Job struct { Name string; Fn func(arg string) }
            type Other struct { Fn func(a, b string) }
            func runIt(arg string) { exec.Command("sh", "-c", arg).Run() }
            func two(a, b string) { db.Query("SELECT " + b) }
            var jobs = []Job{{Name: "x", Fn: runIt}}
            var others = []Other{{Fn: two}}
            func H(w http.ResponseWriter, r *http.Request) {
                for _, j := range jobs { j.Fn(r.FormValue("arg")) }
            }
        """
        # two() iki parametreli: tek argümanlı j.Fn(...) çağrısına bağlanmaz
        self.assertEqual(_flows(src), [("command", 6)])

    def test_closure_factory_and_type_assertion(self):
        src = """
            package web
            import ("net/http"; "database/sql"; "github.com/gin-gonic/gin")
            var db *sql.DB
            func finder(table string) func(string) {
                return func(name string) { db.Query("SELECT * FROM " + table + " WHERE n = '" + name + "'") }
            }
            type W func(opaque interface{}, p string)
            var red = struct{ F W }{F: func(opaque interface{}, p string) {
                c, ok := opaque.(*gin.Context)
                if !ok { return }
                c.Redirect(302, p)
            }}
            func H(w http.ResponseWriter, r *http.Request) {
                f := finder("users")
                f(r.FormValue("n"))
            }
            func G(c *gin.Context) { red.F(c, c.Query("next")) }
        """
        self.assertEqual(_flows(src), [("redirect", 11), ("sql", 5)])

    def test_gin_group_registrations(self):
        src = """
            package web
            import ("github.com/gin-gonic/gin"; "os/exec")
            type Ctl struct{}
            func (c *Ctl) Ping(ctx *gin.Context) { exec.Command("sh", "-c", "ping " + ctx.Query("h")).Run() }
            func Routes(r *gin.Engine) {
                ctl := &Ctl{}
                api := r.Group("/api")
                {
                    api.GET("/ping", ctl.Ping)
                    api.POST("/x", func(c *gin.Context) { exec.Command("sh", "-c", c.PostForm("x")).Run() })
                }
            }
        """
        self.assertEqual(_flows(src), [("command", 4), ("command", 10)])

    def test_case_clause_scope_and_same_host_redirect_are_clean(self):
        src = """
            package web
            import ("net/http"; "database/sql"; "fmt")
            var db *sql.DB
            func H(w http.ResponseWriter, r *http.Request) {
                in := r.FormValue("q")
                switch r.FormValue("m") {
                case "a":
                    q := "SELECT '" + in + "'"
                    db.Exec(q)
                case "b":
                    q := "SELECT ?"
                    db.Exec(q, in)
                }
                http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), 301)
                u := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)
                http.Redirect(w, r, u, 301)
            }
        """
        self.assertEqual(_flows(src), [("sql", 9)])

    def test_multiline_package_var_does_not_hide_functions(self):
        # Çok satırlı paket düzeyi bileşik değişmez sonrasındaki işlevler eskiden hiç ayrıştırılmıyordu.
        src = """
            package web
            import ("net/http"; "os/exec")
            var cfg = Config{
                Name: "x",
            }
            func H(w http.ResponseWriter, r *http.Request) {
                q := builder.New().
                    Set(r.FormValue("a")).
                    Build()
                _ = q
                exec.Command("sh", "-c", r.FormValue("c")).Run()
            }
        """
        self.assertEqual(_flows(src), [("command", 11)])


if __name__ == "__main__":
    unittest.main()
