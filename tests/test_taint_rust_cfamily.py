"""Rust ve C/C++ hızlı taint motorları (taint_rust, taint_cfamily): kaynaklar, hedefler, arındırıcılar, dosyalar arası
özetler ve proje analizi entegrasyonu."""
from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

import i18n_server
import project_analyzer
import taint_cfamily
import taint_flow
import taint_rust


def c_flows(files: dict[str, str]) -> list[tuple[str, str, int, str]]:
    res = taint_cfamily.analyze_files({k: textwrap.dedent(v) for k, v in files.items()})
    return sorted((f.sink_kind, f.file, f.line, f.source_label) for a in res.values() for f in a.flows)


def rs_flows(files: dict[str, str]) -> list[tuple[str, str, int]]:
    res = taint_rust.analyze_files({k: textwrap.dedent(v) for k, v in files.items()})
    return sorted((f.sink_kind, f.file, f.line) for a in res.values() for f in a.flows)


def kinds(flows) -> list[str]:
    return sorted(f[0] for f in flows)


class CFamilyTests(unittest.TestCase):
    def test_socket_to_shell_and_local_console_not_reported_for_command(self):
        flows = c_flows({"a.c": """
            #include <stdlib.h>
            #ifdef _WIN32
            #define SHELL "cmd.exe"
            #define ARG "/c"
            #else
            #define SHELL "/bin/sh"
            #define ARG "-c"
            #endif
            #define EXEC execl
            void bad(int sock) {
                char data[100] = "ls ";
                recv(sock, (char *)(data + 3), 90, 0);
                EXEC(SHELL, SHELL, ARG, data, NULL);
            }
            void local(void) {
                char buf[100];
                fgets(buf, sizeof buf, stdin);
                system(buf);
            }
            void good(void) {
                char d[100] = "ls";
                strcat(d, " *.*");
                system(d);
            }
        """})
        self.assertEqual(flows, [("command", "a.c", 14, "request")])

    def test_format_string_local_and_safe_variant(self):
        flows = c_flows({"m.c": """
            #include <stdio.h>
            int main(int argc, char **argv) {
                printf(argv[1]);
                printf("%s\\n", argv[1]);
                return 0;
            }
        """})
        self.assertEqual(flows, [("format_string", "m.c", 4, "local")])

    def test_index_requires_both_bounds_unless_unsigned(self):
        flows = c_flows({"i.c": """
            void f(void) {
                char input[16]; int data; int buffer[10] = {0};
                fgets(input, 16, stdin);
                data = atoi(input);
                if (data >= 0) { buffer[data] = 1; }
                if (data >= 0 && data < 10) { buffer[data] = 2; }
                if (data < 10) { buffer[data] = 3; }
            }
            void g(void) {
                char input[16]; size_t n; int buffer[10];
                fgets(input, 16, stdin);
                n = strtoul(input, 0, 10);
                if (n < 10) { buffer[n] = 1; }
            }
        """})
        self.assertEqual([f[2] for f in flows if f[0] == "memory_index"], [6, 8])

    def test_unbounded_copy_heap_destination_and_sprintf(self):
        flows = c_flows({"s.c": """
            void f(int s) {
                char net[256]; char fixed[16]; char *heap; char out[64];
                recv(s, net, 255, 0);
                strcpy(fixed, net);
                heap = malloc(strlen(net) + 1);
                strcpy(heap, net);
                sprintf(out, "user=%s", net);
                snprintf(out, sizeof out, "user=%s", net);
            }
        """})
        self.assertEqual([(f[0], f[2]) for f in flows], [("memory", 5), ("memory", 8)])

    def test_sql_path_ssrf_and_escape_sanitizer(self):
        flows = c_flows({"q.c": """
            void f(int s, sqlite3 *db, MYSQL *conn, CURL *h) {
                char name[64]; char q[256]; char esc[130];
                recv(s, name, 63, 0);
                sprintf(q, "SELECT * FROM t WHERE n='%s'", name);
                sqlite3_exec(db, q, 0, 0, 0);
                fopen(name, "r");
                curl_easy_setopt(h, CURLOPT_URL, name);
                mysql_real_escape_string(conn, esc, name, strlen(name));
                sprintf(q, "SELECT * FROM t WHERE n='%s'", esc);
                mysql_query(conn, q);
            }
            int main(int argc, char **argv) { fopen(argv[1], "r"); return 0; }
        """})
        # sabit boyutlu q arabelleğine %s ile ağ verisi: sprintf taşma riski (bellek) de raporlanır
        self.assertEqual(sorted((f[0], f[2]) for f in flows), [("memory", 5), ("path", 7), ("sql", 6), ("ssrf", 8)])

    def test_cross_file_sink_and_header_macros(self):
        flows = c_flows({
            "x.h": '#define COMMAND_ARG3 data\n#define SH "/bin/sh"\n',
            "a.c": """
                #include "x.h"
                void sink_b(char *data);
                void bad(int s) { char data[100]; recv(s, data, 99, 0); sink_b(data); }
            """,
            "b.c": """
                #include "x.h"
                void sink_b(char *data) { execl(SH, SH, "-c", COMMAND_ARG3, NULL); }
            """,
        })
        self.assertEqual(flows, [("command", "b.c", 3, "request")])

    def test_function_pointer_goto_and_cpp_virtual_dispatch(self):
        flows = c_flows({"v.cpp": """
            class Base { public: virtual void action(char *data) const = 0; };
            class Bad : public Base { public: void action(char *data) const; };
            class Good : public Base { public: void action(char *data) const; };
            void Bad::action(char *data) const { system(data); }
            void Good::action(char *data) const { printf("%s", data); }
            static void sinkf(char *data) { popen(data, "r"); }
            void run(int s) {
                char data[100];
                goto source;
            source:
                recv(s, data, 99, 0);
                const Base &obj = Bad();
                obj.action(data);
                void (*fp)(char *) = sinkf;
                fp(data);
            }
            void safe(int s) {
                char data[100] = "ls";
                const Base &obj = Good();
                obj.action(data);
            }
        """})
        self.assertEqual(sorted((f[0], f[2]) for f in flows), [("command", 5), ("command", 7)])

    def test_cgi_query_string_reflected_html(self):
        flows = c_flows({"cgi.c": """
            int main(void) {
                char *q = getenv("QUERY_STRING");
                printf("Content-type: text/html\\n\\n");
                printf("<p>%s</p>", q);
                return 0;
            }
        """})
        self.assertIn(("html", "cgi.c", 5, "request"), flows)

    def test_mature_style_code_without_sources_has_no_flows(self):
        flows = c_flows({"lib.c": """
            static int parse(const char *p, size_t len, char *out) {
                if (len > 63) return -1;
                memcpy(out, p, len);
                out[len] = 0;
                return 0;
            }
            int api(const char *name) { char b[64]; return parse(name, strlen(name), b); }
        """})
        self.assertEqual(flows, [])

    def test_local_chain_length_limit(self):
        # yerel girdi 3 fonksiyon sınırından sonra raporlanmaz (bağlama duyarsız uzun zincir)
        flows = c_flows({"z.c": """
            void d(char *x) { printf(x); }
            void c2(char *x) { d(x); }
            void b(char *x) { c2(x); }
            int main(int argc, char **argv) { b(argv[1]); return 0; }
        """})
        self.assertEqual(flows, [])
        flows = c_flows({"y.c": """
            void d(char *x) { printf(x); }
            int main(int argc, char **argv) { d(argv[1]); return 0; }
        """})
        self.assertEqual(flows, [("format_string", "y.c", 2, "local")])


class RustTests(unittest.TestCase):
    def test_actix_query_sql_command_path_redirect_ssrf(self):
        flows = rs_flows({"src/main.rs": """
            use actix_web::{get, web, HttpRequest, HttpResponse, Responder, http};
            use rusqlite::Connection;
            use std::process::Command;
            use std::fs;
            #[derive(serde::Deserialize)]
            struct Q { name: String, id: i64, url: String }
            #[get("/a")]
            async fn a(q: web::Query<Q>, conn: web::Data<Connection>) -> impl Responder {
                let sql = format!("SELECT * FROM u WHERE n = '{}'", q.name);
                conn.prepare(&sql).unwrap();
                let by_id = format!("SELECT * FROM u WHERE id = {}", q.id);
                conn.prepare(&by_id).unwrap();
                conn.execute("DELETE FROM u WHERE n = ?1", [&q.name]).unwrap();
                let body = fs::read_to_string(&q.name).unwrap_or_default();
                HttpResponse::Found().insert_header((http::header::LOCATION, q.url.clone())).finish()
            }
            #[get("/b")]
            async fn b(req: HttpRequest) -> impl Responder {
                if let Some(qs) = req.uri().query() {
                    for pair in qs.split('&') {
                        if let Some(rest) = pair.strip_prefix("cmd=") {
                            let out = Command::new("sh").arg("-c").arg(rest).output();
                            let ok = Command::new("ping").arg(rest).output();
                        }
                    }
                }
                HttpResponse::Ok().finish()
            }
            #[get("/c")]
            async fn c(q: web::Query<Q>) -> impl Responder {
                let r = reqwest::blocking::get(&q.url);
                let p = reqwest::blocking::get(format!("https://api.example.com/v1/{}", q.name));
                HttpResponse::Ok().finish()
            }
        """})
        self.assertEqual(flows, [
            ("command", "src/main.rs", 23),
            ("path", "src/main.rs", 15),
            ("redirect", "src/main.rs", 16),
            ("sql", "src/main.rs", 11),
            ("ssrf", "src/main.rs", 32),
            ("ssrf_partial", "src/main.rs", 33),
        ])

    def test_xss_content_type_rules_and_sanitizer(self):
        flows = rs_flows({"src/main.rs": """
            use actix_web::{post, web, HttpResponse, Responder};
            use axum::response::Html;
            #[post("/e")]
            async fn e(body: String) -> impl Responder {
                let html = format!("<div>{}</div>", body);
                HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
            }
            #[post("/p")]
            async fn p(body: String) -> impl Responder {
                HttpResponse::Ok().body(format!("Hello {}", body))
            }
            #[post("/j")]
            async fn j(body: String) -> impl Responder {
                let clean = ammonia::clean(&body);
                HttpResponse::Ok().content_type("text/html").body(format!("<p>{}</p>", clean))
            }
            async fn ax(axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>) -> Html<String> {
                Html(format!("<h1>{}</h1>", q.get("n").cloned().unwrap_or_default()))
            }
        """})
        self.assertEqual(flows, [("html", "src/main.rs", 7), ("html", "src/main.rs", 19)])

    def test_handler_registration_and_non_handler_strings(self):
        flows = rs_flows({
            "src/main.rs": """
                use actix_web::{web, App, HttpResponse};
                mod db;
                async fn search(term: String) -> HttpResponse {
                    db::run(&term).await;
                    HttpResponse::Ok().finish()
                }
                fn helper(term: String) { let _ = sqlx::query(&format!("SELECT {}", term)); }
                fn main() { App::new().route("/s", web::post().to(search)); }
            """,
            "src/db.rs": """
                use sqlx::SqlitePool;
                pub async fn run(term: &str) {
                    let q = if term == "all" { "SELECT * FROM t".to_string() } else {
                        let s = format!("SELECT * FROM t WHERE n LIKE '%{}%'", term);
                        s
                    };
                    let rows = match sqlx::query(&q).fetch_all(&pool()).await { Ok(r) => r, Err(_) => return };
                    let safe = sqlx::query("SELECT * FROM t WHERE n = ?").bind(term);
                    let m = sqlx::query!("SELECT * FROM t WHERE n = ?", term);
                }
            """,
        })
        self.assertEqual(flows, [("sql", "src/db.rs", 8)])

    def test_path_guard_bincode_and_named_template(self):
        flows = rs_flows({"src/main.rs": """
            use axum::extract::{Path, Json};
            use std::path::PathBuf;
            async fn dl(Path(name): Path<String>) -> Vec<u8> {
                let base = PathBuf::from("/srv/files");
                let full = base.join(&name).canonicalize().unwrap();
                if !full.starts_with(&base) { return vec![]; }
                std::fs::read(&full).unwrap()
            }
            async fn raw(Path(name): Path<String>) -> Vec<u8> { std::fs::read(&name).unwrap() }
            async fn de(Json(b): Json<Vec<u8>>) -> String {
                let v: Vec<String> = bincode::deserialize(&b).unwrap();
                let t = tera.render("page.html", &ctx).unwrap();
                t
            }
            async fn num(Path(id): Path<u32>) -> Vec<u8> { std::fs::read(format!("/d/{}", id)).unwrap() }
        """})
        self.assertEqual(flows, [("deserialize_unbounded", "src/main.rs", 12), ("path", "src/main.rs", 10)])

    def test_mature_style_library_has_no_flows(self):
        flows = rs_flows({"src/lib.rs": """
            pub struct Reader { buf: Vec<u8> }
            impl Reader {
                pub fn new(s: &str) -> Self { Reader { buf: s.as_bytes().to_vec() } }
                pub fn get(&self, i: usize) -> u8 { unsafe { *self.buf.get_unchecked(i) } }
                pub fn run(cmd: &str) { std::process::Command::new("sh").arg("-c").arg(cmd).output().unwrap(); }
            }
        """})
        self.assertEqual(flows, [])


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "proj"
        (self.root / "src").mkdir(parents=True)

    def analyze(self):
        return project_analyzer.analyze_project(str(self.root), allowed_roots=(self.root.parent,))

    def test_language_routing(self):
        self.assertEqual(taint_flow.language_for("a/b.rs"), "rust")
        self.assertEqual(taint_flow.language_for("x.c"), "c")
        self.assertEqual(taint_flow.language_for("x.hpp"), "cpp")

    def test_project_findings_local_title_hotspot_dedupe_and_unsafe_note(self):
        (self.root / "src" / "tool.c").write_text(textwrap.dedent("""
            #include <stdio.h>
            #include <string.h>
            int main(int argc, char **argv) {
                char buf[16];
                strcpy(buf, argv[1]);
                strcpy(buf, "sabit");
                printf(argv[2]);
                return 0;
            }
        """).lstrip("\n"))
        (self.root / "src" / "ffi.rs").write_text("extern \"C\" { fn abs(x: i32) -> i32; }\n"
                                                  "pub fn f(x: i32) -> i32 { unsafe { abs(x) } }\n")
        res = self.analyze()
        by_line = {}
        for f in res["findings"]:
            if f["file"].endswith("tool.c"):
                by_line.setdefault(f["line"], []).append(f)
        titles5 = [f["title"] for f in by_line[5]]
        self.assertEqual(titles5, ["Doğrulanmış veri akışı: yerel girdi (komut satırı/ortam/standart girdi) sınır "
                                   "denetimsiz bellek kopyalamasına ulaşıyor (arabellek taşması)"])
        self.assertEqual(by_line[5][0]["severity"], "high")
        # sabit kaynaklı strcpy: desen bulgusu düşük öncelikli gözden geçirme notuna iner
        self.assertEqual([(f["severity"], f.get("taint_verdict")) for f in by_line[6]], [("low", "no_request_flow")])
        self.assertTrue(any("biçim dizgesine" in f["title"] for f in by_line[7]))
        notes = [f for f in res["findings"] if f["title"].startswith("Rust unsafe/FFI")]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["severity"], "info")

    def test_rust_project_flow_and_english_title(self):
        (self.root / "src" / "main.rs").write_text(textwrap.dedent("""
            use actix_web::{get, web, HttpResponse};
            #[get("/f")]
            async fn f(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
                let p = q.get("p").cloned().unwrap_or_default();
                let body = std::fs::read_to_string(&p).unwrap_or_default();
                HttpResponse::Ok().finish()
            }
        """).lstrip("\n"))
        res = self.analyze()
        flows = [f for f in res["findings"] if f.get("taint_flow")]
        self.assertEqual([(f["line"], f["reference"]) for f in flows], [(5, "CWE-22")])
        tr = i18n_server.translator()
        self.assertEqual(tr.text("Rust unsafe/FFI kullanımı (bellek güvenliği denetimi devre dışı)"),
                         "Rust unsafe/FFI usage (memory safety checks disabled)")
        self.assertNotRegex(tr.text(project_analyzer.TAINT_FLOW_RULES["memory_index"][2]), "[çğıöşüÇĞİÖŞÜ]")


if __name__ == "__main__":
    unittest.main()
