"""18. tur gaps kolu: 9. setteki kaçırma sınıflarını kapatan genel kurallar (olumlu ve olumsuz örnekler).

* Java: Spring meta-ek açıklamalı eşlemeler / bağlama ek açıklamalı parametreler, lambda gövdeleri, URL parametreli
  yardımcı (openConnection), Location başlığı (HttpHeaders/MultiValueMap/ResponseEntity), sabit dize alanları,
  JSP görünümünde kaçışsız ``${…}`` EL (model öznitelikleri), aynı site "redirect:/…", ``(new File(x)).getName()``.
* PHP: include edilen ortak kitaplık işlevinin çağrı yeri (aynı site yönlendirme öneki hariç).
* Python: çağrı yerinde kurulan sorgu (run_sql(f"…{x}")), ``user``/``req`` adlı pydantic gövdesi, lxml XMLParser,
  ``is_public…`` doğrulayıcısı, montydb, find(parametre).
* Rust: çalışma alanı crate'leri arası tekil yöntem, alan zinciri istemcisi, ``validate(&x)?``, kendi Request→Response.
* Go: gRPC hizmet yöntemi istek iletisi. Ruby: boşluklu parantezli komut çağrısı, Model.new(params) yansıması.
* JS: başka modülde tanımlı GraphQL rootValue çözücüleri, ``import * as m`` → ``m.default.f``.
"""
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_clike  # noqa: E402
import taint_flow  # noqa: E402
import taint_goruby  # noqa: E402
import taint_rust  # noqa: E402


def _d(files: dict[str, str]) -> dict[str, str]:
    return {k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}


def clike(files: dict[str, str]) -> list[tuple]:
    res = taint_clike.analyze_files(_d(files), {})
    return sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")


def py(src: str) -> list[tuple]:
    a = taint_flow.analyze_source(textwrap.dedent(src).lstrip("\n"), "main.py")
    return sorted((f.sink_kind, f.line) for f in a.flows if f.source_label == "request")


class JavaGapTests(unittest.TestCase):
    def test_custom_mapping_and_bound_params_are_endpoints(self):
        self.assertEqual(clike({"A.java": """
            class A {
              @VulnerableAppRequestMapping(value = "L1")
              public ResponseEntity<String> a(@RequestParam final Map<String, String> q) {
                return jdbc.queryForList("select * from c where id=" + q.get("id"));
              }
              public String b(@RequestParam String id) {
                return jdbc.queryForList("select * from c where id=" + id);
              }
              public String helper(String id) {
                return jdbc.queryForList("select * from c where id=" + id);
              }
            }
        """}), [("A.java", "sql", 4), ("A.java", "sql", 7)])

    def test_lambda_body_url_helper_and_location_headers(self):
        self.assertEqual(clike({"A.java": """
            class A {
              private static final String LOC = "Location";
              @GetMapping("/x")
              public Object a(@RequestParam String id) {
                return jdbc.query((conn) -> conn.prepareStatement("select * from c where id='" + id + "'"), (ps) -> {}, (rs) -> { return 1; });
              }
              @GetMapping("/y")
              public String b(@RequestParam String u) throws Exception { return get(new URL(u)); }
              String get(URL u) throws Exception { URLConnection c = u.openConnection(); return ""; }
              @GetMapping("/z")
              public ResponseEntity<?> c(@RequestParam String u) {
                MultiValueMap<String, String> h = new HttpHeaders();
                h.put(LOC, new ArrayList<>());
                h.get(LOC).add(u);
                return ResponseEntity.status(302).header("Location", u).build();
              }
              @GetMapping("/w")
              public ResponseEntity<?> d(@RequestParam String u) {
                return ResponseEntity.ok().header("X-Name", u).build();
              }
            }
        """}), [("A.java", "redirect", 14), ("A.java", "redirect", 15), ("A.java", "sql", 5), ("A.java", "ssrf", 9)])

    def test_same_site_redirect_prefix_and_parenthesized_getname(self):
        self.assertEqual(clike({"A.java": """
            class A {
              @GetMapping("/r") public String r(@RequestParam String t) { return "redirect:/transfer/" + t; }
              @GetMapping("/f") public String f(@RequestParam String t) { return "forward:" + t; }
              @GetMapping("/o") public String o(@RequestParam String t) { return "redirect:" + t; }
              @GetMapping("/n") public String n(@RequestParam String t) { return ext((new File(t)).getName()); }
            }
        """}), [("A.java", "redirect", 4)])

    def test_jsp_el_view_outputs(self):
        files = {
            "src/main/java/C.java": """
                class C {
                  @GetMapping("/s") String s(@RequestParam("k") String k, Model model) {
                    model.addAttribute("keyword", k);
                    model.addAttribute("transfer", k);
                    return "home";
                  }
                  @PostMapping("/t") String t(@ModelAttribute Transfer tr, Model model) { return helper(tr, model); }
                  private String helper(final Transfer tr, final Model model) {
                    model.addAttribute("bean", tr);
                    return "check";
                  }
                }
            """,
            "src/main/webapp/WEB-INF/jsp/home.jsp": """
                <c:url var="transfer" value="/transfer"/>
                <c:out value="${keyword}"/> <input value="${fn:escapeXml(keyword)}">
                <a href="${transfer}">x</a>
                <h5>No ads for <strong>"${keyword}"</strong></h5>
                <input value="${keyword}">
            """,
            "src/main/webapp/WEB-INF/jsp/check.jsp": """
                <td><c:out value="${bean.toAccount}"/></td>
                <td>${bean.description}</td>
            """,
        }
        self.assertEqual(clike(files), [("src/main/webapp/WEB-INF/jsp/check.jsp", "html", 2),
                                        ("src/main/webapp/WEB-INF/jsp/home.jsp", "html", 4),
                                        ("src/main/webapp/WEB-INF/jsp/home.jsp", "html", 5)])


class PhpGapTests(unittest.TestCase):
    def test_library_function_call_site(self):
        files = {
            "libs/db.inc.php": "<?php\nfunction dbQuery($q) {\n  $r = mysql_query($q);\n}\n"
                               "function http_redirect($url) {\n  header(\"Location: {$url}\");\n  exit(0);\n}\n",
            "get.php": "<?php\nrequire_once('libs/db.inc.php');\n$query = \"SELECT * FROM u WHERE id=\" . $_GET['id'];\n"
                       "dbQuery($query);\nhttp_redirect($_POST['next']);\nhttp_redirect('..' . '/view.php?id=' . $_POST['id']);\n",
        }
        flows = clike(files)
        self.assertIn(("get.php", "sql", 4), flows)
        self.assertIn(("get.php", "redirect", 5), flows)
        self.assertNotIn(("get.php", "redirect", 6), flows)  # sabit göreli önek: aynı site
        self.assertIn(("libs/db.inc.php", "sql", 3), flows)  # hedef satırındaki bulgu da kalır


class PythonGapTests(unittest.TestCase):
    def test_call_site_constructed_query_and_model_params(self):
        flows = py("""
            from typing import Optional
            import sqlite3
            from pydantic import BaseModel
            from fastapi import FastAPI, Depends
            app = FastAPI()
            class User(BaseModel):
                address: str
            def get_current_user(): pass
            def run_sql(query):
                conn = sqlite3.connect("x")
                return conn.execute(query)
            @app.get('/s')
            async def s(username: str):
                return run_sql(f'SELECT * FROM u WHERE n = "{username}"')
            @app.delete('/u')
            async def u(user: Optional[User] = None):
                return run_sql(f'DELETE FROM u WHERE a = {user.address};')
            @app.get('/me')
            async def me(user: User = Depends(get_current_user)):
                return run_sql(f'SELECT * FROM u WHERE a = {user.address};')
        """)
        self.assertIn(("sql", 14), flows)  # çağrı yeri
        self.assertIn(("sql", 17), flows)  # Optional[User] gövdesi
        self.assertIn(("sql", 11), flows)  # sarmalayıcıdaki hedef
        self.assertNotIn(("sql", 20), flows)  # Depends ile gelen kullanıcı

    def test_lxml_parser_validator_and_mongo_helper(self):
        flows = py("""
            import httpx
            from lxml import etree
            from flask import Flask, request
            from pymongo import MongoClient
            app = Flask(__name__)
            coll = MongoClient().db.users
            def _is_public_http_url(u): return u.startswith("https://")
            def find_users(query):
                return list(coll.find(query))
            @app.route('/xml', methods=['POST'])
            def xml():
                parser = etree.XMLParser(no_network=False, dtd_validation=True)
                return etree.tostring(etree.fromstring(request.form['xml'], parser))
            @app.route('/safe-xml', methods=['POST'])
            def safe_xml():
                parser = etree.XMLParser(resolve_entities=False)
                return etree.tostring(etree.fromstring(request.form['xml'], parser))
            @app.route('/fetch', methods=['POST'])
            def fetch():
                u = request.form['u']
                if not _is_public_http_url(u):
                    return "no", 400
                return httpx.get(u).text
            @app.route('/find', methods=['POST'])
            def find():
                return str(find_users(request.get_json()))
        """)
        self.assertIn(("xxe", 13), flows)
        self.assertNotIn(("xxe", 17), flows)
        self.assertFalse(any(k == "ssrf" for k, _ in flows))
        self.assertIn(("nosql", 9), flows)


class RustGapTests(unittest.TestCase):
    def test_workspace_method_field_client_and_validate(self):
        files = {
            "crates/runner/src/lib.rs": """
                use std::process::Command;
                pub struct CommandRunner { t: String }
                impl CommandRunner {
                    pub fn run_vulnerable(&self, artifact_name: &str) -> std::io::Result<std::process::Output> {
                        let command = format!("echo {artifact_name}");
                        Command::new("sh").arg("-c").arg(command).output()
                    }
                }
            """,
            "crates/fetch/src/lib.rs": """
                use reqwest::Client;
                pub struct Fetcher { vulnerable_client: Client, fixed_client: Client, policy: Policy }
                impl Fetcher {
                    pub async fn fetch_vulnerable(&self, raw_url: &str) -> Result<u16, E> {
                        let r = self.vulnerable_client.get(raw_url).send().await?;
                        Ok(1)
                    }
                    pub async fn fetch_checked(&self, raw_url: &str) -> Result<u16, E> {
                        let url = Url::parse(raw_url)?;
                        self.policy.validate(&url)?;
                        let r = self.fixed_client.get(url).send().await?;
                        Ok(1)
                    }
                }
            """,
            "apps/api/src/main.rs": """
                use axum::{extract::State, Json};
                async fn post_process(State(state): State<S>, Json(request): Json<Req>) -> Json<u8> {
                    state.command_runner.run_vulnerable(&request.artifact_name);
                    state.fetcher.fetch_vulnerable(&request.url).await;
                    state.fetcher.fetch_checked(&request.url).await;
                    Json(0)
                }
            """,
        }
        res = taint_rust.analyze_files(_d(files))
        got = sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows)
        self.assertIn(("crates/runner/src/lib.rs", "command", 6), got)
        self.assertIn(("crates/fetch/src/lib.rs", "ssrf", 5), got)
        self.assertNotIn(("crates/fetch/src/lib.rs", "ssrf", 11), got)

    def test_custom_request_response_handler(self):
        files = {"src/lib.rs": """
            pub struct Request { q: String }
            pub struct Response { b: String }
            pub fn handle(app: &App, req: &Request) -> Response {
                let name = req.query_get("name").unwrap_or("");
                let out = std::process::Command::new("sh").arg("-c").arg(format!("ls {}", name)).output();
                Response { b: String::new() }
            }
            pub fn helper(req: &Request) -> String {
                let name = req.query_get("name").unwrap_or("");
                std::process::Command::new("sh").arg("-c").arg(format!("ls {}", name)).output();
                String::new()
            }
        """}
        res = taint_rust.analyze_files(_d(files))
        got = sorted((f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")
        self.assertEqual(got, [("command", 5)])


class GoRubyGapTests(unittest.TestCase):
    def test_go_grpc_service_method(self):
        src = """
            package main
            import ("context"; "database/sql"; "fmt"; pb "x/proto")
            type server struct {
                pb.UnimplementedFriendsServer
                db *sql.DB
            }
            type other struct { db *sql.DB }
            func (s *server) GetPosts(ctx context.Context, in *pb.Person) (*pb.Posts, error) {
                s.db.Query(fmt.Sprintf("SELECT * FROM posts WHERE u = '%s'", in.GetUname()))
                return nil, nil
            }
            func (o *other) GetPosts(ctx context.Context, in *pb.Person) (*pb.Posts, error) {
                o.db.Query(fmt.Sprintf("SELECT * FROM posts WHERE u = '%s'", in.GetUname()))
                return nil, nil
            }
        """
        res = taint_goruby.analyze_files({"main.go": textwrap.dedent(src).lstrip("\n")}, "go")
        got = sorted((f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")
        self.assertEqual(got, [("sql", 9)])

    def test_ruby_spaced_paren_and_model_new_reflection(self):
        files = {
            "app/models/rider.rb": "class Rider < ApplicationRecord\nend\n",
            "app/controllers/riders_controller.rb": """
                class RidersController < ApplicationController
                  def create
                    @rider = Rider.new(params[:rider])
                    @rider.save
                  end
                  def download
                    send_file ('./' + params[:filename])
                  end
                  def x
                    puts (1 + 2)
                  end
                end
            """,
            "app/views/riders/create.html.erb": "<h1>Hi <%= raw @rider.name %></h1>\n<p><%= @rider.name %></p>\n",
        }
        res = taint_goruby.analyze_files(_d(files), "ruby")
        got = sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")
        self.assertEqual(got, [("app/controllers/riders_controller.rb", "path", 7),
                               ("app/views/riders/create.html.erb", "html", 1)])


try:
    from tests.test_taint_js_ast import NODE_ENV  # noqa: E402
    import taint_js_ast  # noqa: E402
except Exception:  # pragma: no cover
    NODE_ENV = None


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsGapTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def flows(self, files):
        res = taint_js_ast.analyze_files(_d(files))
        self.assertIsNotNone(res)
        return sorted((k, f.sink_kind, f.line) for k, a in res.items() for f in a.flows)

    def test_root_value_resolvers_in_other_module(self):
        files = {
            "controllers/c.js": """
                const mysql = require('mysql2');
                const con = mysql.createConnection({});
                async function getUser(arg) {
                  await con.promise().query("SELECT * FROM u WHERE n='" + arg.username + "'");
                }
                async function listAll() { await con.promise().query('SELECT * FROM u'); }
                const graphqlroot = { user: getUser, list: listAll };
                module.exports = { graphqlroot };
            """,
            "routes/app.js": """
                const express = require('express');
                const { graphqlHTTP } = require('express-graphql');
                const ctrl = require('../controllers/c');
                const router = express.Router();
                router.use('/graphql', graphqlHTTP({ schema: 1, rootValue: ctrl.graphqlroot }));
            """,
        }
        self.assertIn(("controllers/c.js", "sql", 4), self.flows(files))

    def test_namespace_default_interop(self):
        files = {"svc.ts": """
            import * as axios from 'axios';
            import express from 'express';
            const app = express();
            app.post('/d', async (req, res) => {
              await axios.default.get(req.body.url);
              res.json({});
            });
        """}
        self.assertIn(("svc.ts", "ssrf", 5), self.flows(files))


if __name__ == "__main__":
    unittest.main()



class RailsRecordRedirectTests(unittest.TestCase):
    """18. tur birleştirme: redirect_to @kayıt Rails'in polimorfik rotasıdır (açık yönlendirme değil);
    params ile verilen adres ise hâlâ açık yönlendirmedir."""

    def test_redirect_to_record_is_not_open_redirect(self):
        files = {
            "app/models/user.rb": "class User < ApplicationRecord\nend\n",
            "app/controllers/users_controller.rb": """
                class UsersController < ApplicationController
                  def create
                    @user = User.new(params[:user])
                    if @user.save
                      redirect_to @user, notice: 'ok'
                    end
                  end
                  def go
                    redirect_to params[:next]
                  end
                end
            """,
        }
        res = taint_goruby.analyze_files(_d(files), "ruby")
        got = sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")
        self.assertNotIn(("app/controllers/users_controller.rb", "redirect", 5), got)
        self.assertIn(("app/controllers/users_controller.rb", "redirect", 9), got)
