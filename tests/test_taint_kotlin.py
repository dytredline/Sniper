"""16. tur Kotlin hızlı taint: Kotlin → Java çevirisi (taint_kotlin) üzerinde Java motoru; Spring, Ktor, Javalin,
Android kaynak/hedefleri, kapsam işlevleri (let/also/apply/run), when/if/try ifadeleri, dize şablonları ve kesinlik."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402
import taint_clike_lex  # noqa: E402
import taint_flow  # noqa: E402
import taint_kotlin  # noqa: E402


def analyze(files: dict[str, str]):
    return taint_clike.analyze_files({k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()})


def flows(files: dict[str, str]) -> list[tuple[str, str, int]]:
    return sorted((f.file, f.sink_kind, f.line) for a in analyze(files).values() for f in a.flows
                  if f.source_label == "request")


def kinds(src: str, name: str = "A.kt") -> list[tuple[str, int]]:
    return sorted(((k, line) for _f, k, line in flows({name: src})), key=lambda x: (x[1], x[0]))


class Translation(unittest.TestCase):
    def test_lines_are_preserved_and_language_is_kotlin(self):
        src = textwrap.dedent("""
            package a

            class A {
                fun f(x: String): String {
                    val y = "v=$x"
                    return y
                }
            }
            """).lstrip("\n")
        out = taint_kotlin.kotlin_to_java(src)
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertIn("String f ( String x )", out.splitlines()[3])
        self.assertIn('( "v=" + ( x ) )', out.splitlines()[4])
        unit = taint_clike_lex.build_unit("a/A.kt", src)
        self.assertEqual((unit.lang, unit.dialect), ("java", "kotlin"))
        self.assertEqual([m.name for m in unit.methods], ["f"])
        self.assertEqual(taint_clike.analyze_single(src, "A.kt").language, "kotlin")

    def test_broken_source_does_not_raise(self):
        for src in ("fun (", "class { val", '"""abc', "when { -> }", "x.let { it ->", "@file:"):
            self.assertIsInstance(taint_kotlin.kotlin_to_java(src), str)
        self.assertEqual(taint_clike.analyze_single("fun f( { ]", "B.kt").flows, [])

    def test_templates_raw_strings_and_nested_braces(self):
        toks = taint_kotlin.tokenize('val s = """a ${m["k"]} $b\nc"""')
        parts = toks[3].value
        self.assertEqual(parts[0], "a ")
        self.assertIsInstance(parts[1], list)
        self.assertEqual([t.value for t in parts[3]], ["b"])

    def test_project_analyzer_routes_kt_files(self):
        import project_analyzer

        src = """
        import org.springframework.web.bind.annotation.*
        @RestController
        class C(private val jdbcTemplate: JdbcTemplate) {
            @GetMapping("/u")
            fun u(@RequestParam name: String): List<Map<String, Any>> =
                jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '$name'")
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "src").mkdir(parents=True)
            (root / "src" / "C.kt").write_text(textwrap.dedent(src).lstrip("\n"))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        hits = [f for f in result["findings"] if f.get("taint_flow")]
        self.assertEqual([(f["file"], f["line"], f["reference"]) for f in hits], [("src/C.kt", 6, "CWE-89")])
        self.assertIn(".kt", taint_flow.CLIKE_SUFFIXES)


class Spring(unittest.TestCase):
    def test_controller_sinks(self):
        src = """
        @RestController
        class UserController(private val jdbcTemplate: JdbcTemplate, private val restTemplate: RestTemplate) {
            @GetMapping("/users")
            fun users(@RequestParam name: String): List<Map<String, Any>> {
                val sql = "SELECT * FROM users WHERE name = '$name'"
                return jdbcTemplate.queryForList(sql)
            }
            @GetMapping("/hi")
            fun hi(@RequestParam name: String) = "<b>Hello ${name.trim()}</b>"
            @GetMapping("/fetch")
            fun fetch(@RequestParam url: String) = restTemplate.getForObject(url, String::class.java)
            @PostMapping("/run")
            fun run(@RequestBody body: CmdRequest): String {
                val p = ProcessBuilder(listOf("sh", "-c", body.cmd)).start()
                return "ok"
            }
            @GetMapping("/view")
            fun view(@RequestParam template: String) = ModelAndView(template)
        }
        """
        self.assertEqual(kinds(src), [("sql", 6), ("html", 9), ("ssrf", 11), ("command", 14), ("ssti", 18)])

    def test_redirect_and_object_returns(self):
        src = """
        @Controller
        class Nav {
            @GetMapping("/go")
            fun go(@RequestParam next: String): String = "redirect:$next"
        }
        @RestController
        class Api(private val repo: Repo) {
            @GetMapping("/u/{id}")
            fun get(@PathVariable id: String): Any = repo.findById(id)
            @GetMapping("/n")
            fun n(@RequestParam id: String) = repo.findById(id)
        }
        """
        self.assertEqual(kinds(src), [("redirect", 4)])

    def test_response_entity_html_body(self):
        src = """
        @RestController
        class P {
            @GetMapping("/card")
            fun card(@RequestParam q: String): ResponseEntity<String> {
                val body = "<h1>" + q + "</h1>"
                val headers = HttpHeaders().apply { contentType = MediaType.TEXT_HTML }
                return ResponseEntity.ok().headers(headers).body(body)
            }
            @GetMapping("/json")
            fun json(@RequestParam q: String): ResponseEntity<String> = ResponseEntity.ok().body(q)
        }
        """
        self.assertEqual(kinds(src), [("html", 7)])

    def test_xxe_with_inferred_types(self):
        src = """
        @RestController
        class X {
            @PostMapping("/xml")
            fun parse(@RequestBody xml: String): String {
                val dbf = DocumentBuilderFactory.newInstance()
                val db = dbf.newDocumentBuilder()
                val doc = db.parse(InputSource(StringReader(xml)))
                return "ok"
            }
            @PostMapping("/safe")
            fun safe(@RequestBody xml: String): String {
                val dbf = DocumentBuilderFactory.newInstance()
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                val doc = dbf.newDocumentBuilder().parse(InputSource(StringReader(xml)))
                return "ok"
            }
        }
        """
        self.assertEqual(kinds(src), [("xxe", 7)])

    def test_cross_file_service_call(self):
        files = {
            "web/C.kt": """
            @RestController
            class C(private val svc: QueryService) {
                @GetMapping("/t")
                fun t(@RequestParam table: String) = svc.listAll(table)
            }
            """,
            "svc/QueryService.kt": """
            @Service
            class QueryService(private val jdbc: JdbcTemplate) {
                fun listAll(tableName: String): List<Map<String, Any>> {
                    val sql = "SELECT * FROM ${tableName}"
                    return jdbc.queryForList(sql)
                }
            }
            """,
        }
        self.assertEqual(flows(files), [("svc/QueryService.kt", "sql", 5)])


class Ktor(unittest.TestCase):
    def test_routing_lambdas(self):
        src = """
        fun Application.module() {
            routing {
                get("/hello") {
                    val n = call.parameters["name"] ?: "x"
                    call.respondText("<h1>Hello $n</h1>", ContentType.Text.Html)
                }
                get("/plain") {
                    call.respondText("Hello ${call.parameters["name"]}")
                }
                get("/go") {
                    val u = call.request.queryParameters["u"]
                    if (u != null) {
                        call.respondRedirect(u)
                    }
                }
                get("/self") {
                    call.respondRedirect(call.request.uri)
                }
                post("/q") {
                    val body = call.receiveText()
                    val r = body.let { it.trim() }
                    transaction {
                        exec("SELECT * FROM t WHERE x = '$r'")
                    }
                }
                get("/file/{name}") {
                    call.respondFile(File("files/" + call.parameters["name"]))
                }
            }
        }
        """
        self.assertEqual(kinds(src), [("html", 5), ("redirect", 13), ("sql", 23), ("path", 27)])

    def test_numeric_conversion_and_kotlinx_html(self):
        src = """
        fun Route.pages() {
            get("/links/{n}") {
                val number = (call.parameters["n"]?.toIntOrNull() ?: 0).coerceAtLeast(1)
                val links = buildString {
                    for (i in 0..<number) {
                        append("<a href='/links/$i'>$i</a> ")
                    }
                }
                call.respondText("<html>$links</html>", ContentType.Text.Html)
            }
            get("/echo") {
                val q = call.request.queryParameters["q"]
                val page = buildString { append("<p>"); append(q); append("</p>") }
                call.respondText(page, ContentType.Text.Html)
            }
            get("/raw") {
                val q = call.parameters["q"]
                call.respondHtml {
                    body {
                        +"safe text ${q}"
                        unsafe { +"<b>$q</b>" }
                    }
                }
            }
        }
        """
        self.assertEqual(kinds(src), [("html", 14), ("html", 21)])

    def test_http_client_ssrf_and_path_only_uri(self):
        src = """
        fun Application.proxy(client: HttpClient) {
            intercept(ApplicationCallPipeline.Call) {
                val r = client.request("https://en.wikipedia.org${call.request.uri}")
                val target = call.request.queryParameters["target"]!!
                val r2 = client.get(target)
            }
        }
        """
        self.assertEqual(kinds(src), [("ssrf", 5)])


class Javalin(unittest.TestCase):
    def test_context_sources(self):
        src = """
        fun main() {
            val app = Javalin.create().start(7070)
            app.get("/hello") { ctx ->
                ctx.html("<p>" + ctx.queryParam("q") + "</p>")
            }
            app.get("/plain") { ctx -> ctx.result("Hi " + ctx.queryParam("q")) }
            app.post("/cmd") { ctx ->
                val c = ctx.formParam("c")
                Runtime.getRuntime().exec(c)
            }
            app.get("/hdr") { ctx ->
                ctx.header("X-Seen", "1")
                ctx.redirect(ctx.header("Referer") ?: "/")
            }
        }
        """
        self.assertEqual(kinds(src), [("html", 4), ("command", 9), ("redirect", 13)])


class ScopeFunctionsAndExpressions(unittest.TestCase):
    def test_let_also_apply_when_if_try(self):
        src = """
        class S {
            fun f(request: HttpServletRequest, conn: Connection) {
                val q = request.getParameter("q")?.let { it.trim() }
                conn.createStatement().executeQuery("SELECT 1 WHERE a='" + q + "'")
                val m = request.getParameter("m")
                val sql = when (m) {
                    "a" -> "SELECT * FROM a WHERE x=$q"
                    else -> "SELECT 1"
                }
                conn.createStatement().execute(sql)
                val z = if (q.isNullOrEmpty()) "x" else q
                val t = try { File(z) } catch (e: Exception) { null }
                request.getParameter("w").also { w -> Runtime.getRuntime().exec(w) }
                val ids = request.getParameterValues("id").map { "'$it'" }.joinToString(",")
                conn.createStatement().executeQuery("SELECT * FROM t WHERE id IN ($ids)")
                val safe = request.getParameter("n").toInt()
                conn.createStatement().executeQuery("SELECT * FROM t WHERE n=$safe")
            }
        }
        """
        self.assertEqual(kinds(src), [("sql", 4), ("sql", 10), ("path", 12), ("command", 13), ("sql", 15)])

    def test_servlet_property_syntax(self):
        src = """
        class Sv : HttpServlet() {
            override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
                val q = request.queryString
                response.writer.write("<p>$q</p>")
                val f = FileWriter("log.txt")
                f.write(q)
                response.sendRedirect(request.getParameter("next"))
            }
        }
        """
        self.assertEqual(kinds(src), [("html", 4), ("redirect", 7)])

    def test_url_read_text_ssrf_and_deserialize(self):
        src = """
        @RestController
        class D {
            @GetMapping("/f")
            fun f(@RequestParam u: String) = URL(u).readText().length
            @PostMapping("/o")
            fun o(@RequestBody b: ByteArray): String {
                val ois = ObjectInputStream(ByteArrayInputStream(b))
                return ois.readObject().toString()
            }
        }
        """
        # readObject sonucu (saldırganın nesnesi) dize olarak döndürülüyor: Java kuralıyla aynı HTML akışı
        self.assertEqual(kinds(src), [("ssrf", 4), ("deserialize", 8), ("html", 8)])


class Android(unittest.TestCase):
    def test_intent_to_sql_and_file(self):
        src = """
        class StorageActivity : AppCompatActivity() {
            override fun onCreate(savedInstanceState: Bundle?) {
                super.onCreate(savedInstanceState)
                val user = intent.getStringExtra("user")
                val db = openOrCreateDatabase("app.db", MODE_PRIVATE, null)
                db.rawQuery("SELECT * FROM users WHERE name = '$user'", null)
                db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(user))
                val f = File(filesDir, intent.data?.getQueryParameter("file"))
                val out = contentResolver.openOutputStream(Uri.fromFile(f))
                out?.write(user!!.toByteArray())
                webView.evaluateJavascript("show('" + user + "')", null)
            }
        }
        """
        self.assertEqual(kinds(src), [("sql", 6), ("path", 8), ("eval", 11)])


class AndroidProvider(unittest.TestCase):
    def test_exported_content_provider_selection(self):
        src = """
        import android.content.ContentProvider
        import android.database.sqlite.SQLiteQueryBuilder

        class NotesProvider : ContentProvider() {
            override fun query(uri: Uri, projection: Array<String>?, selection: String?,
                               selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
                val qb = SQLiteQueryBuilder()
                qb.tables = "notes"
                return qb.query(database.readableDatabase, projection, selection, selectionArgs, null, null, sortOrder)
            }
            override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int =
                database.writableDatabase.delete("notes", selection, selectionArgs)
            fun helper(name: String) = database.readableDatabase.query("t", null, "name = '$name'", null, null, null, null)
        }
        """
        self.assertEqual(kinds(src), [("sql", 9), ("sql", 9), ("sql", 12)])


class FrameworkPrecision(unittest.TestCase):
    def test_client_response_encoders_and_config_base(self):
        src = """
        class Svc(private val client: HttpClient, private val http: HttpHandler) {
            suspend fun image(baseUrl: String, id: String) = client.get("$baseUrl/$id")
            fun verify(url: String): String {
                val body = http(Request(GET, url)).bodyString()
                return File(body).readText()
            }
        }
        fun Route.r(svc: Svc) {
            get("/img/{id}") {
                call.respond(svc.image(config.base, call.parameters["id"]!!))
            }
            get("/p") {
                val path = call.request.queryParameters["p"]!!.encodeURLPath()
                call.respondHtml { body { script { unsafe { +"var p = '$path';" } } } }
            }
        }
        """
        found = flows({"S.kt": src})
        self.assertEqual([(k, line) for _f, k, line in found], [("ssrf_partial", 2)])


class Precision(unittest.TestCase):
    def test_benign_patterns(self):
        src = """
        @RestController
        class B(private val jdbc: JdbcTemplate) {
            @GetMapping("/a")
            fun a(@RequestParam name: String) = jdbc.queryForList("SELECT * FROM t WHERE a = ?", name)
            @GetMapping("/b")
            fun b(@RequestParam n: String): String {
                val k = n.toLong()
                return jdbc.queryForObject("SELECT name FROM t WHERE id = $k", String::class.java)
            }
            @GetMapping("/c")
            fun c(@RequestParam id: String): Map<String, Any> = mapOf("id" to id)
            @GetMapping(value = ["/d"], produces = [MediaType.APPLICATION_JSON_VALUE])
            fun d(@RequestParam q: String): String = "{\\"q\\": \\"$q\\"}"
        }
        fun Application.m() {
            routing {
                get("/x") {
                    val q = call.parameters["q"]
                    call.respondText("you said $q")
                    File("data.txt").writeText(q ?: "")
                }
            }
        }
        """
        self.assertEqual(kinds(src), [])


if __name__ == "__main__":
    unittest.main()
