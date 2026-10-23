"""C# hızlı taint motoru (taint_clike): ASP.NET Core/MVC eylemleri, WebForms denetimleri, ADO.NET/EF/Dapper,
Process, yol, SSRF, yönlendirme, XPath, LDAP; arındırıcılar ve özellik hedefleri."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402


def flows(files: dict[str, str]) -> list[tuple[str, int]]:
    results = taint_clike.analyze_files({k: textwrap.dedent(v) for k, v in files.items()})
    return sorted((f.sink_kind, f.line) for a in results.values() for f in a.flows if f.source_label == "request")


class CSharpTaint(unittest.TestCase):
    def test_controller_action_sinks(self):
        src = """
        public class HomeController : Controller {
          public IActionResult Index(string name, int id, CancellationToken ct) {
            var cmd = new SqlCommand("select * from t where n='" + name + "'", conn);
            cmd.CommandText = $"select * from t where n = '{name}'";
            Process.Start("cmd", "/c " + name);
            var path = System.IO.File.ReadAllText(Path.Combine(root, name));
            var html = new HtmlString(name);
            db.Users.FromSqlRaw("select * from u where n = " + name);
            var q = db.Users.FromSqlInterpolated($"select * from u where n = {name}");
            var safe = Path.GetFileName(name);
            System.IO.File.ReadAllText(Path.Combine(root, safe));
            var n = int.Parse(name);
            conn.Query("select " + n);
            return Content(HttpUtility.HtmlEncode(name), "text/html");
          }
          public IActionResult Go(string returnUrl) {
            if (Url.IsLocalUrl(returnUrl)) return Redirect(returnUrl);
            return LocalRedirect("/");
          }
          public IActionResult Bad(string u) => Redirect(u);
          [NonAction] public void Helper(string s) { Process.Start(s); }
        }
        """
        self.assertEqual(flows({"HomeController.cs": src}),
                         [("command", 6), ("html", 8), ("path", 7), ("redirect", 21), ("sql", 4), ("sql", 5), ("sql", 9)])

    def test_request_members_and_webforms_controls(self):
        files = {
            "Page1.aspx.cs": """
            public partial class Page1 : System.Web.UI.Page {
              protected void Btn_Click(object sender, EventArgs e) {
                string n = txtName.Text;
                lblOut.Text = "Merhaba " + n;
                lblSafe.Text = Server.HtmlEncode(n);
                string q = Request.QueryString["q"];
                Response.Write(q);
                var doc = new XmlDocument();
                doc.SelectNodes("//u[name='" + Request["n"] + "']");
                FileUpload1.SaveAs(Server.MapPath("~/up/") + Path.GetFileName(FileUpload1.FileName));
                lblStatus.Text = "Yüklendi: " + FileUpload1.FileName;
              }
            }
            """,
            "Page1.aspx.designer.cs": """
            public partial class Page1 {
              protected global::System.Web.UI.WebControls.TextBox txtName;
              protected global::System.Web.UI.WebControls.Label lblOut;
              protected global::System.Web.UI.WebControls.Label lblSafe;
              protected global::System.Web.UI.WebControls.Label lblStatus;
              protected global::System.Web.UI.WebControls.FileUpload FileUpload1;
            }
            """,
        }
        self.assertEqual(flows(files), [("html", 5), ("html", 8), ("html", 12), ("xpath", 10)])

    def test_cross_file_provider_interface(self):
        files = {
            "Page.cs": """
            public class Lookup : Page {
              IDbProvider du = Settings.CurrentDbProvider;
              protected void Find(object s, EventArgs e) { du.GetEmailByName(Request.Form["name"]); }
            }
            """,
            "IDbProvider.cs": "public interface IDbProvider { string GetEmailByName(string name); }",
            "MySqlProvider.cs": """
            public class MySqlDbProvider : IDbProvider {
              public string GetEmailByName(string name) {
                string sql = "select email from CustomerLogin where email like '" + name + "%'";
                var da = new MySqlDataAdapter(sql, connection);
                return "";
              }
            }
            """,
        }
        self.assertEqual(flows(files), [("sql", 5)])

    def test_project_analyzer_reports_csharp(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "C.cs").write_text("public class AController : Controller {\n"
                                       "  public IActionResult A(string f) { return PhysicalFile(f, \"text/plain\"); }\n}\n")
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        refs = [(f["reference"], f["line"]) for f in result["findings"] if f.get("taint_flow")]
        self.assertEqual(refs, [("CWE-22", 2)])


if __name__ == "__main__":
    unittest.main()
