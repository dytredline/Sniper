"""16. tur C# kolu: modern ASP.NET Core kalıpları (taint_clike, C# lehçesi).

* Minimal API (``app.MapGet("/x", (string q) => …)``): lambda parametreleri kaynak; DI servis türleri değil.
* Razor görünümleri (.cshtml) ve Blazor bileşenleri (.razor): satır korunarak C#'a çevrilir; yalnız kaçışsız çıktı
  (``Html.Raw``, ``(MarkupString)``) hedef. Model/ViewData/ViewBag denetleyicideki yazmalardan, model bağlamalı DTO
  özelliklerinden ve EF varlık yazmalarından (kayıtlı veri) taint alır.
* Razor Pages ``[BindProperty]`` ve Blazor ``[SupplyParameterFromQuery]`` özellikleri kaynak.
* EF Core ``FromSql($"…")``/``FromSqlInterpolated`` parametreli (güvenli); ``FromSqlRaw`` birleştirmesi değil.
* Location başlığı yönlendirmesi, ``new StreamReader(Request.Body)`` yol değil, ``GetFullPath`` + ``StartsWith`` yol arındırıcı,
  ``[Authorize(Roles = "Admin")]`` yetkili bağlam, DataTable filtre ifadesi, XmlReader DtdProcessing.Parse,
  Roslyn betiği, ADO.NET kayıtlı veri okuması, satır içi Newtonsoft TypeNameHandling, C# 11 ham dizeler.
"""
from pathlib import Path
import sys
import textwrap
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402
import taint_clike_lex as lex  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _analyze(files):
    return taint_clike.analyze_files({k: _src(v) for k, v in files.items()})


def _flows(files):
    return {path: sorted({(f.sink_kind, f.line) for f in a.flows}) for path, a in _analyze(files).items()}


MINIMAL_API = """
var app = WebApplication.CreateBuilder(args).Build();
app.MapGet("/run", (string cmd) => Process.Start("sh", "-c " + cmd));
app.MapGet("/read", async ([FromQuery] string name) => Results.Text(await File.ReadAllTextAsync("/srv/" + name)));
app.MapGet("/svc", (IUserService users, AppDbContext db) => db.Database.ExecuteSqlRaw("DELETE FROM t WHERE x = " + users.Name));
app.MapPost("/login", [ProducesResponseType(200)] async (HttpRequest request, [FromBody] Creds login) =>
    db.Users.FromSqlRaw("SELECT * FROM U WHERE n = '" + login.User + "'"));
app.MapGet("/hello", (HttpContext ctx) => Results.Content("<h1>" + ctx.Request.Query["n"] + "</h1>", "text/html"));
app.MapGet("/plain", (string n) => "<h1>" + n + "</h1>");
app.MapGet("/go", (string next) => Results.Redirect(next));
app.Run();
public record Creds(string User, string Passwd);
"""

CONTROLLER = """
public class HomeController : Controller
{
    public IActionResult Index(string name)
    {
        ViewData["Name"] = name;
        ViewBag.Msg = name;
        ViewData["Safe"] = "sabit";
        return View();
    }
    public IActionResult Show(ShowModel m) => View(m);
    public IActionResult Reply(int id, string contents)
    {
        var r = new BlogResponse() { Contents = contents, Author = "anonim" };
        _db.Add(r);
        return RedirectToAction("Index");
    }
}
public class ShowModel { public string Q { get; set; } }
public class BlogResponse { public string Contents { get; set; } public string Author { get; set; } }
public class Db : DbContext { public DbSet<BlogResponse> Responses { get; set; } }
"""

INDEX_VIEW = """
@{
    ViewData["Title"] = "Ana sayfa";
}
<div>@Html.Raw(ViewData["Name"])</div>
<div>@Html.Raw(ViewBag.Msg)</div>
<div>@ViewData["Name"]</div>
<div>@Html.Raw(ViewData["Safe"])</div>
@foreach (var r in Model.Responses)
{
    <p>@Html.Raw(r.Contents)</p>
    <p>@Html.Raw(r.Author)</p>
}
"""

SHOW_VIEW = """
@model ShowModel
<div>@Html.Raw(Model.Q)</div>
<div>@Model.Q</div>
"""

PAGE_MODEL = """
public class SearchModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string Term { get; set; }
    public string Plain { get; set; }
    public void OnGet()
    {
        Results = _db.Users.FromSqlRaw("SELECT * FROM U WHERE n LIKE '%" + Term + "%'").ToList();
        _db.Users.FromSqlRaw("SELECT * FROM U WHERE n = '" + Plain + "'");
        _db.Users.FromSqlInterpolated($"SELECT * FROM U WHERE n = {Term}");
        _db.Users.FromSql($"SELECT * FROM U WHERE n = {Term}");
        _db.Database.ExecuteSqlRaw($"DELETE FROM U WHERE n = '{Term}'");
    }
}
"""

PAGE_VIEW = """
@page
@model SearchModel
<p>@Html.Raw(Model.Term)</p>
<p>@Model.Term</p>
"""

BLAZOR = """
@page "/search"
@inject NavigationManager Nav
<p>@((MarkupString)Q)</p>
<p>@((MarkupString)Title)</p>
@code {
    [SupplyParameterFromQuery]
    public string Q { get; set; }
    [Parameter]
    public string Title { get; set; }
    protected override void OnInitialized()
    {
        Nav.NavigateTo(Q);
    }
}
"""


class MinimalApiTests(unittest.TestCase):
    def test_lambda_parameters_are_sources(self):
        flows = _flows({"Program.cs": MINIMAL_API})["Program.cs"]
        self.assertIn(("command", 2), flows)
        self.assertIn(("path", 3), flows)
        self.assertIn(("sql", 6), flows)  # öznitelikli lambda; [FromBody] record özelliği
        self.assertIn(("html", 7), flows)  # Results.Content(…, "text/html")
        self.assertIn(("redirect", 9), flows)
        self.assertNotIn(("sql", 4), flows)  # DI servisleri (IUserService, AppDbContext) istek verisi değil
        self.assertNotIn(("html", 8), flows)  # dize dönüşü text/plain

    def test_method_group_handler(self):
        flows = _flows({"Program.cs": """
            app.MapGet("/x", Handlers.Run);
            public static class Handlers {
                public static IResult Run(string cmd) { Process.Start("sh", "-c " + cmd); return Results.Ok(); }
                public static IResult Other(string cmd) { Process.Start("sh", "-c " + cmd); return Results.Ok(); }
            }
            """})["Program.cs"]
        self.assertIn(("command", 3), flows)
        self.assertNotIn(("command", 4), flows)  # haritalanmamış statik yöntem uç nokta değil


class RazorTests(unittest.TestCase):
    def test_translation_keeps_lines(self):
        text = _src(INDEX_VIEW)
        out, model = lex.razor_to_cs("﻿" + text, "Views/Home/Index.cshtml")
        self.assertEqual(out.count("\n"), text.count("\n"))
        self.assertIn('Html.Raw(ViewData["Name"])', out)
        self.assertNotIn("<div>", out)
        self.assertEqual(lex.razor_to_cs("@model IEnumerable<Blog.Models.BlogEntry>\n", "a.cshtml")[1], "BlogEntry")

    def test_viewdata_viewbag_model_and_stored_entity(self):
        flows = _flows({"Controllers/HomeController.cs": CONTROLLER, "Views/Home/Index.cshtml": INDEX_VIEW,
                        "Views/Home/Show.cshtml": SHOW_VIEW})
        index = flows["Views/Home/Index.cshtml"]
        self.assertIn(("html", 4), index)  # ViewData["Name"]
        self.assertIn(("html", 5), index)  # ViewBag.Msg
        self.assertNotIn(("html", 6), index)  # @ViewData[…] Razor tarafından kodlanır
        self.assertNotIn(("html", 7), index)  # sabit değer
        self.assertIn(("html", 10), index)  # EF varlığına yazılan istek verisi (kayıtlı XSS)
        self.assertNotIn(("html", 11), index)  # Author sabit
        self.assertIn(("html", 2), flows["Views/Home/Show.cshtml"])  # model bağlamalı DTO özelliği
        self.assertNotIn(("html", 3), flows["Views/Home/Show.cshtml"])
        stored = [f for f in _analyze({"Controllers/HomeController.cs": CONTROLLER,
                                       "Views/Home/Index.cshtml": INDEX_VIEW})["Views/Home/Index.cshtml"].flows
                  if f.line == 10]
        self.assertEqual(stored[0].source_label, "stored")

    def test_razor_pages_bind_property(self):
        flows = _flows({"Pages/Search.cshtml.cs": PAGE_MODEL, "Pages/Search.cshtml": PAGE_VIEW})
        model = flows["Pages/Search.cshtml.cs"]
        self.assertIn(("sql", 8), model)
        self.assertNotIn(("sql", 9), model)  # bağlanmamış özellik
        self.assertNotIn(("sql", 10), model)  # FromSqlInterpolated
        self.assertNotIn(("sql", 11), model)  # FromSql($"…") EF Core: FormattableString parametreli
        self.assertIn(("sql", 12), model)  # ExecuteSqlRaw($"…") ham
        self.assertEqual(flows["Pages/Search.cshtml"], [("html", 3)])

    def test_blazor_component(self):
        flows = _flows({"Components/Search.razor": BLAZOR})["Components/Search.razor"]
        self.assertIn(("html", 3), flows)
        self.assertNotIn(("html", 4), flows)  # [Parameter]: üst bileşenden, istekten değil
        self.assertIn(("redirect", 12), flows)


class CSharpSinkTests(unittest.TestCase):
    def test_location_header_and_exists_and_stream(self):
        flows = _flows({"C.cs": """
            public class SomeController : ControllerBase {
                public void Post([FromBody] string value, string p) {
                    Response.Headers["location"] = value;
                    Response.Headers.Add("location", value);
                    Response.Headers["X-Other"] = value;
                    var bad = "/home/community-user/" + p;
                    if (File.Exists(bad)) { System.IO.File.ReadAllText(bad); }
                    using var r = new StreamReader(Request.Body);
                    var g = File.ReadAllText(new Guid(p).ToString());
                    if (Url.IsLocalUrl(value)) Redirect(value);
                    Redirect(HttpUtility.UrlEncode(value));
                }
            }
            """})["C.cs"]
        self.assertIn(("redirect", 3), flows)
        self.assertIn(("redirect", 4), flows)
        self.assertNotIn(("redirect", 5), flows)
        # File.Exists dalı: olgun projelerde (bitwarden, jellyfin) kesinlik için beyaz liste yüklemi sayılmaya devam
        # ediyor (bilinen boşluk: if (!File.Exists(p)) return NotFound(); return PhysicalFile(p) kaçar)
        self.assertNotIn(("path", 7), flows)
        self.assertNotIn(("path", 8), flows)  # akış, dosya yolu değil
        self.assertNotIn(("path", 9), flows)  # Guid ayrıştırması
        self.assertNotIn(("redirect", 10), flows)
        self.assertNotIn(("redirect", 11), flows)

    def test_full_path_prefix_check_and_handler_authorization(self):
        res = _analyze({"P.cs": """
            public class FilesController : ControllerBase {
                public IActionResult Get(string name) {
                    var full = Path.GetFullPath(Path.Combine(_root, name));
                    if (!full.StartsWith(_root)) return BadRequest();
                    return PhysicalFile(full, "application/octet-stream");
                }
            }
            app.MapGet("/media", async (string path, IAuthorizationService auth, HttpContext ctx) => {
                if (!await auth.AuthorizeAsync(ctx.User, MediaPermissions.ManageMedia)) return Results.Forbid();
                return Results.Text(File.ReadAllText(path));
            });
            """})["P.cs"]
        self.assertEqual([f.line for f in res.flows], [])
        self.assertEqual([f.line for f in res.privileged_flows], [10])

    def test_admin_authorize_is_privileged(self):
        res = _analyze({"A.cs": """
            [Authorize(Roles = "Admin")]
            public class AdminController : Controller {
                public IActionResult Run(string cmd) { Process.Start("sh", "-c " + cmd); return Ok(); }
            }
            public class UserController : Controller {
                [Authorize(Policy = "AdminOnly")]
                public IActionResult Run(string cmd) { Process.Start("sh", "-c " + cmd); return Ok(); }
                [Authorize]
                public IActionResult Run2(string cmd) { Process.Start("sh", "-c " + cmd); return Ok(); }
            }
            """})["A.cs"]
        self.assertEqual(sorted(f.line for f in res.flows), [9])
        self.assertEqual(sorted(f.line for f in res.privileged_flows), [3, 7])

    def test_misc_sinks(self):
        flows = _flows({"H.cs": """
            public class XController : Controller {
                public object Act(string u, string x, string code) {
                    var rows = DataSet.Tables[0].Select("User = '" + u + "'");
                    var s = new XmlReaderSettings(); s.DtdProcessing = DtdProcessing.Parse;
                    var rd = XmlReader.Create(new StringReader(x), s);
                    CSharpScript.EvaluateAsync(code);
                    JsonConvert.DeserializeObject<object>(x, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
                    JsonConvert.DeserializeObject<object>(x, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None });
                    var c = new SqlConnection("x");
                    c.QueryAsync<User>($"SELECT * FROM U WHERE Id = {u}");
                    return null;
                }
            }
            """})["H.cs"]
        for item in (("sql", 3), ("xxe", 5), ("eval", 6), ("deserialize", 7), ("sql", 10)):
            self.assertIn(item, flows)
        self.assertNotIn(("deserialize", 8), flows)

    def test_ssti_ssrf_and_relative_redirects(self):
        flows = _flows({"T.cs": """
            public class TController : Controller {
                public IActionResult T(string tpl, string url, string returnUrl) {
                    var r = Engine.Razor.RunCompile(tpl, "k", null, new { });
                    var s = Template.Parse(tpl).Render(new { });
                    var ok = Template.Parse("Hello {{name}}").Render(new { });
                    var req = WebRequest.Create(url);
                    var u = new Uri(returnUrl, UriKind.RelativeOrAbsolute);
                    Redirect(u.IsAbsoluteUri ? "/" : returnUrl);
                    Redirect(new Uri(returnUrl, UriKind.Relative).ToString());
                    return Redirect(returnUrl);
                }
            }
            """})["T.cs"]
        for item in (("ssti", 3), ("ssti", 4), ("ssrf", 6), ("redirect", 10)):
            self.assertIn(item, flows)
        for item in (("ssti", 5), ("redirect", 8), ("redirect", 9)):
            self.assertNotIn(item, flows)

    def test_ado_stored_read_after_write(self):
        flows = _flows({"S.cs": """
            public class CommentsController : Controller {
                public void Add(string text) {
                    var cmd = new SqlCommand("INSERT INTO comments (body) VALUES (@b)", conn);
                    cmd.Parameters.AddWithValue("@b", text);
                    cmd.ExecuteNonQuery();
                }
                public void List() {
                    var cmd = new SqlCommand("SELECT body FROM comments", conn);
                    var r = cmd.ExecuteReader();
                    while (r.Read()) { Response.Write("<p>" + r.GetString(0) + "</p>"); }
                    var other = new SqlCommand("SELECT name FROM products", conn).ExecuteReader();
                    Response.Write(other.GetString(0));
                }
            }
            """})["S.cs"]
        self.assertIn(("html", 10), flows)
        self.assertNotIn(("html", 12), flows)  # istek verisi yazılmayan tablo

    def test_raw_string_literals_do_not_hang(self):
        text = 'public class C { string A(string n) { return $"""\n<a href="{n}">{{x}}</a>\n"""; } }\n' * 40
        start = time.monotonic()
        unit = lex.build_unit("C.cs", text)
        self.assertLess(time.monotonic() - start, 5)
        self.assertTrue(any(t.kind == "istr" for t in unit.toks))


if __name__ == "__main__":
    unittest.main()
