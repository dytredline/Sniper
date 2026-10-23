"""17. tur: klasik ASP.NET (WebForms .aspx/.ascx, ASMX/ASHX, WCF, SqlDataSource) ve Kotlin/Java gRPC, Spring WebFlux,
R2DBC kaynak/hedefleri. Olumlu ve olumsuz örnekler."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import project_analyzer
import taint_clike
import taint_clike_lex as lex
import taint_kotlin


def flows(files: dict[str, str], extra: dict[str, str] | None = None) -> set[tuple[str, int, str]]:
    res = taint_clike.analyze_files(files, extra)
    return {(path, f.line, f.sink_kind) for path, a in res.items() for f in a.flows}


ASPX = """<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Search.aspx.cs" Inherits="Demo.Web.Search" %>
<html><body>
  <h1>Results for <%= Request.QueryString["q"] %></h1>
  <p><%: Request.QueryString["q"] %></p>
  <p><%= Message %></p>
  <p><%= SafeMessage %></p>
  <asp:Label ID="lbl" runat="server" Text='<%# Eval("Name") %>' />
  <%-- <%= Request["yorum"] %> --%>
  <script runat="server">
    protected string Echo(string v) { return v; }
  </script>
  <p><%= Echo(Request.Form["comment"]) %></p>
  <p><%= Echo("sabit") %></p>
</body></html>
"""

CODE_BEHIND = """using System;
using System.Web.UI;
namespace Demo.Web {
    public partial class Search : Page {
        protected string Message;
        protected string SafeMessage = "merhaba";
        protected void Page_Load(object sender, EventArgs e) {
            Message = Request.QueryString["msg"];
            string id = Request.QueryString["id"];
            SqlDataSource1.SelectCommand = "SELECT * FROM Products WHERE Id = " + id;
            SqlDataSource1.SelectCommand = "SELECT * FROM Products";
        }
    }
}
"""


class WebFormsTests(unittest.TestCase):
    def test_translation_keeps_lines(self):
        out = lex.aspx_to_cs(ASPX, "Search.aspx")
        self.assertEqual(out.count("\n"), ASPX.count("\n"))
        self.assertIn("public partial class Search : Page", out)
        self.assertIn("protected string Echo", out)
        self.assertEqual(lex.aspx_to_cs("<%@ Control Language=\"C#\" %><b>x</b>", "x.ascx").split(":")[1].split("{")[0].strip(),
                         "UserControl")

    def test_markup_output_and_page_fields(self):
        got = flows({"Search.aspx": ASPX, "Search.aspx.cs": CODE_BEHIND})
        aspx = {line for path, line, kind in got if path == "Search.aspx" and kind == "html"}
        self.assertEqual(aspx, {3, 5, 12})  # <%= Request… %>, arka kodda istekle yazılan alan, sunucu betiği üzerinden
        self.assertIn(("Search.aspx.cs", 10, "sql"), got)  # SqlDataSource komut metni
        self.assertNotIn(("Search.aspx.cs", 11, "sql"), got)

    def test_vb_pages_are_skipped(self):
        vb = '<%@ Page Language="VB" %>\n<script runat="server">\nSub Page_Load()\n Response.Write(Request("x"))\nEnd Sub\n' \
             '</script>\n<%= Request("q") %>\n'
        self.assertEqual(flows({"Vb.aspx": vb}), set())

    def test_single_file_page_without_code_behind(self):
        page = '<%@ Page Language="C#" %>\n<script runat="server">\nvoid Page_Load() { lit.Text = "x"; }\n</script>\n' \
               '<p><%= Request["name"] %></p>\n'
        self.assertEqual(flows({"Tek.aspx": page}), {("Tek.aspx", 5, "html")})


class ClassicServiceTests(unittest.TestCase):
    ASMX = """<%@ WebService Language="C#" Class="Demo.Lookup" %>
using System.Web.Services;
using System.Data.SqlClient;
namespace Demo {
    public class Lookup : WebService {
        [WebMethod]
        public string FindUser(string name) { var c = new SqlCommand("SELECT * FROM U WHERE N = '" + name + "'"); return ""; }
        [WebMethod]
        public int Count(int id) { var c = new SqlCommand("SELECT * FROM U WHERE Id = " + id); return 1; }
        public string Hidden(string name) { var c = new SqlCommand("SELECT * FROM U WHERE N = '" + name + "'"); return ""; }
    }
}
"""

    def test_asmx_web_methods(self):
        self.assertEqual(flows({"Lookup.asmx": self.ASMX}), {("Lookup.asmx", 7, "sql")})

    def test_ashx_handler(self):
        ashx = """<%@ WebHandler Language="C#" Class="Demo.Ping" %>
using System.Web;
using System.Diagnostics;
namespace Demo {
    public class Ping : IHttpHandler {
        public void ProcessRequest(HttpContext context) {
            string host = context.Request.QueryString["host"];
            Process.Start("ping", "-c 1 " + host);
            context.Response.Write("<pre>" + context.Request["msg"] + "</pre>");
            context.Response.Write(System.Web.HttpUtility.HtmlEncode(context.Request["msg"]));
        }
        public bool IsReusable { get { return false; } }
    }
}
"""
        self.assertEqual(flows({"Ping.ashx": ashx}), {("Ping.ashx", 8, "command"), ("Ping.ashx", 9, "html")})

    def test_wcf_contract_implementation(self):
        src = """using System.ServiceModel;
using System.IO;
namespace Demo {
    [ServiceContract]
    public interface IOrderService {
        [OperationContract]
        string GetOrder(string orderId);
        [OperationContract(IsOneWay = true)]
        void Archive(string fileName);
    }
    public class OrderService : IOrderService {
        public string GetOrder(string orderId) {
            var c = new System.Data.SqlClient.SqlCommand("SELECT * FROM O WHERE Id = '" + orderId + "'");
            return "";
        }
        public void Archive(string fileName) { File.Delete(Path.Combine("C:/arsiv", fileName)); }
        public string Helper(string x) {
            var c = new System.Data.SqlClient.SqlCommand("SELECT * FROM O WHERE Id = '" + x + "'");
            return x;
        }
    }
}
"""
        self.assertEqual(flows({"OrderService.cs": src}), {("OrderService.cs", 13, "sql"), ("OrderService.cs", 16, "path")})


class AdoNetDataSetTests(unittest.TestCase):
    PROVIDER = """using System.Data;
using System.Data.SqlClient;
namespace Demo {
    public class Db {
        public string AddComment(string email, string comment) {
            var c = new SqlCommand("insert into Comments (email, comment) values ('" + email + "', '" + comment + "')");
            c.ExecuteNonQuery();
            return "";
        }
        public void SetPassword(string pwd) {
            var c = new SqlCommand("update Users set password = '" + pwd + "' where id = 1");
            c.ExecuteNonQuery();
        }
        public DataSet GetComments() {
            var da = new SqlDataAdapter("select * from Comments", "cs");
            DataSet ds = new DataSet();
            da.Fill(ds);
            return ds;
        }
        public DataSet GetQuestion() {
            var da = new SqlDataAdapter("select question_text, hint from Users", "cs");
            DataSet ds = new DataSet();
            da.Fill(ds);
            return ds;
        }
    }
}
"""
    PAGE = """using System;
using System.Data;
using System.Web.UI;
using System.Web.UI.WebControls;
namespace Demo {
    public partial class Guestbook : Page {
        protected TextBox txtEmail; protected TextBox txtComment; protected Label lblComments; protected Label lblQ;
        Db du = new Db();
        protected void btnSave_Click(object sender, EventArgs e) {
            du.AddComment(txtEmail.Text, txtComment.Text);
            du.SetPassword(Request.Form["pwd"]);
        }
        void Load() {
            DataSet ds = du.GetComments();
            string html = "";
            foreach (DataRow row in ds.Tables[0].Rows) {
                html += "<b>" + row["email"] + "</b>" + row["comment"];
            }
            lblComments.Text = html;
            lblQ.Text = du.GetQuestion().Tables[0].Rows[0]["question_text"].ToString();
        }
    }
}
"""

    def test_stored_xss_through_provider_and_dataset(self):
        got = flows({"Db.cs": self.PROVIDER, "Guestbook.aspx.cs": self.PAGE})
        html = {line for path, line, kind in got if path == "Guestbook.aspx.cs" and kind == "html"}
        self.assertEqual(html, {19})  # Comments tablosu; Users.question_text yazılmadı (yalnız password)
        self.assertIn(("Db.cs", 6, "sql"), got)

    def test_column_helpers(self):
        project = taint_clike.Project({})
        self.assertEqual(project.write_columns("update Users set password = 'x', name='y' where id=1"),
                         frozenset({"password", "name"}))
        self.assertEqual(project.write_columns("insert into T (a, b) values ("), frozenset({"a", "b"}))
        self.assertIsNone(project.write_columns("insert into T values ("))
        self.assertEqual(project.read_columns("select t.a, b as c from T"), frozenset({"a", "b"}))
        self.assertIsNone(project.read_columns("select * from T"))
        self.assertIsNone(project.read_columns("select count(*) from T"))


PROTO = """syntax = "proto3";
message GetUserRequest {
  string name = 1;
  int64 user_id = 2;  // sayısal
  Role role = 3;
  Address address = 4;
}
message Address { string city = 1; int32 zip = 2; }
enum Role { USER = 0; ADMIN = 1; }
"""


class GrpcTests(unittest.TestCase):
    def test_kotlin_unary_and_coroutine_services(self):
        src = """package demo
import io.grpc.stub.StreamObserver
import java.sql.DriverManager
class UserServiceImpl : UserServiceGrpc.UserServiceImplBase() {
    override fun getUser(request: GetUserRequest, responseObserver: StreamObserver<UserReply>) {
        val conn = DriverManager.getConnection("jdbc:h2:mem:x")
        conn.createStatement().executeQuery("SELECT * FROM u WHERE name = '" + request.name + "'")
        conn.createStatement().executeQuery("SELECT * FROM u WHERE id = " + request.userId)
        conn.createStatement().executeQuery("SELECT * FROM u WHERE r = " + request.role)
        conn.createStatement().executeQuery("SELECT * FROM u WHERE c = '" + request.address.city + "'")
        responseObserver.onCompleted()
    }
}
class FileService : FileServiceGrpcKt.FileServiceCoroutineImplBase() {
    override suspend fun readFile(request: GetUserRequest): UserReply {
        val text = java.io.File("/data/" + request.name).readText()
        return UserReply.getDefaultInstance()
    }
    fun notExposed(request: GetUserRequest) {
        java.io.File("/data/" + request.name).readText()
    }
}
"""
        got = flows({"Svc.kt": src}, {"proto/user.proto": PROTO})
        self.assertEqual(got, {("Svc.kt", 7, "sql"), ("Svc.kt", 10, "sql"), ("Svc.kt", 16, "path")})

    def test_kotlin_streaming_requests(self):
        src = """package d
import java.sql.DriverManager
class Chat : ChatGrpcKt.ChatCoroutineImplBase() {
    override fun chat(requests: Flow<Msg>): Flow<Reply> = flow {
        requests.collect { m ->
            DriverManager.getConnection("x").createStatement().executeQuery("SELECT * FROM t WHERE a = '" + m.text + "'")
        }
    }
    override suspend fun upload(requests: Flow<Chunk>): Reply {
        requests.collect { c -> java.io.File("/up/" + c.name).writeText("x") }
        return Reply.getDefaultInstance()
    }
}
"""
        self.assertEqual(flows({"Chat.kt": src}), {("Chat.kt", 6, "sql"), ("Chat.kt", 10, "path")})

    def test_java_service_getters(self):
        src = """package demo;
import io.grpc.stub.StreamObserver;
import java.sql.*;
public class UserServiceImpl extends UserServiceGrpc.UserServiceImplBase {
    private Connection conn;
    @Override
    public void getUser(GetUserRequest request, StreamObserver<UserReply> responseObserver) {
        try {
            Statement st = conn.createStatement();
            st.executeQuery("SELECT * FROM u WHERE name = '" + request.getName() + "'");
            st.executeQuery("SELECT * FROM u WHERE id = " + request.getUserId());
            st.executeQuery("SELECT * FROM u WHERE c = '" + request.getAddress().getCity() + "'");
            st.executeQuery("SELECT * FROM u WHERE z = " + request.getAddress().getZip());
        } catch (SQLException e) {}
    }
}
"""
        got = flows({"UserServiceImpl.java": src}, {"user.proto": PROTO})
        self.assertEqual(got, {("UserServiceImpl.java", 10, "sql"), ("UserServiceImpl.java", 12, "sql")})

    def test_proto_parser(self):
        messages, enums = taint_clike.proto_messages({"a.proto": PROTO, "b.txt": "message X { int32 a = 1; }"})
        self.assertEqual(messages["GetUserRequest"]["userId"], "int64")
        self.assertEqual(messages["GetUserRequest"]["user_id"], "int64")
        self.assertEqual(messages["Address"]["city"], "string")
        self.assertEqual(messages["Address"]["zip"], "int32")  # tek satırlık ileti gövdesi
        self.assertNotIn("X", messages)
        self.assertEqual(enums, frozenset({"Role"}))


class WebFluxTests(unittest.TestCase):
    def test_kotlin_functional_handlers(self):
        src = """package demo
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.r2dbc.core.DatabaseClient
import java.net.URI
class Handler(private val db: DatabaseClient) {
    fun hello(request: ServerRequest) =
        ServerResponse.ok().contentType(MediaType.TEXT_HTML).bodyValue("<h1>" + request.queryParam("n").orElse("") + "</h1>")
    fun json(request: ServerRequest) =
        ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(request.queryParam("n").orElse(""))
    fun find(request: ServerRequest) = db.sql("SELECT * FROM t WHERE id = '" + request.pathVariable("id") + "'").fetch().all()
    fun safe(request: ServerRequest) = db.sql("SELECT * FROM t WHERE id = :id").bind("id", request.pathVariable("id")).fetch().all()
    fun go(request: ServerRequest) = ServerResponse.temporaryRedirect(URI.create(request.queryParam("next").get())).build()
    fun self(request: ServerRequest) = ServerResponse.temporaryRedirect(request.uri()).build()
}
"""
        got = flows({"Handler.kt": src})
        self.assertEqual(got, {("Handler.kt", 9, "html"), ("Handler.kt", 12, "sql"), ("Handler.kt", 14, "redirect")})

    def test_java_functional_handler_and_qualified_annotation(self):
        java = """package demo;
import org.springframework.web.reactive.function.server.*;
import reactor.core.publisher.Mono;
public class H {
  public Mono<ServerResponse> hello(ServerRequest request) {
    String name = request.queryParam("name").orElse("x");
    return ServerResponse.ok().contentType(MediaType.TEXT_HTML).bodyValue("<b>" + name + "</b>");
  }
}
"""
        kt = """package demo
import org.springframework.r2dbc.core.DatabaseClient
@org.springframework.web.bind.annotation.RestController
class C(private val db: DatabaseClient) {
    @org.springframework.web.bind.annotation.GetMapping("/s")
    fun s(@org.springframework.web.bind.annotation.RequestParam q: String) = db.sql("SELECT * FROM t WHERE n = '$q'").fetch().all()
}
"""
        self.assertEqual(flows({"H.java": java, "C.kt": kt}), {("H.java", 7, "html"), ("C.kt", 6, "sql")})

    def test_kotlin_qualified_constructor(self):
        out = taint_kotlin.kotlin_to_java("class A { fun f(x: String) { java.io.File(x).readText(); obj.Method(x) } }")
        self.assertIn("new java . io . File", out)
        self.assertNotIn("new obj", out)


class ProjectAnalyzerTests(unittest.TestCase):
    def test_aspx_flow_and_request_validation_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "site"
            root.mkdir()
            (root / "Search.aspx").write_text('<%@ Page Language="C#" validateRequest="false" Inherits="X.Search" %>\n'
                                              '<p><%= Request["q"] %></p>\n')
            (root / "HomeController.cs").write_text("public class HomeController : Controller {\n [ValidateInput(false)]\n"
                                                    " public ActionResult A(string q) { return View(); }\n}\n")
            (root / "Safe.cs").write_text("public class S { bool validateRequestFlag = true; }\n")
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        got = {(f["file"], f["line"], f["title"][:32]) for f in result["findings"]}
        self.assertIn(("Search.aspx", 2, "Doğrulanmış veri akışı: istek/UR"), got)
        rule = {(f, line) for f, line, title in got if title.startswith("ASP.NET istek doğrulaması")}
        self.assertEqual(rule, {("Search.aspx", 1), ("HomeController.cs", 2)})
        self.assertEqual(result["languages"].get("C#"), 3)


if __name__ == "__main__":
    unittest.main()
