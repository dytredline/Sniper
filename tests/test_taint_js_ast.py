import hashlib
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import taint_flow
import taint_js_ast
import tool_pins


def _node_env() -> dict[str, str] | None:
    default = tool_pins.PINS["node"].default_binary
    if default is None or not default.is_file():
        return None
    real = os.path.realpath(default)
    with open(real, "rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return {"SNIPER_NODE_BINARY": real, "SNIPER_NODE_SHA256": digest, "SNIPER_TAINT_JS_ENGINE": "ast"}


NODE_ENV = _node_env()


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _sinks(analysis):
    return sorted((flow.sink_kind, flow.line) for flow in analysis.flows)


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsAstEngineTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def analyze(self, source, filename="a.js"):
        analysis = taint_flow.analyze_javascript(_src(source), filename=filename)
        self.assertIsNotNone(analysis)
        return analysis

    def test_same_file_helper_and_destructuring(self):
        analysis = self.analyze("""
            const { exec } = require('child_process');
            function run(cmd) { exec('ls ' + cmd); }
            app.post('/x', (req, res) => {
              const { name, age } = req.body;
              run(name);
              run(String(Number(age)));
            });
        """)
        self.assertEqual(_sinks(analysis), [("command", 2)])
        self.assertIn("run()", analysis.flows[0].via)

    def test_typescript_class_methods_and_instances(self):
        analysis = self.analyze("""
            import { Request, Response } from 'express';
            class Repo {
              constructor(private db: any) {}
              find(name: string): Promise<any> {
                return this.db.query(`SELECT * FROM t WHERE n = '${name}'`);
              }
              safe(name: string) {
                return this.db.query('SELECT * FROM t WHERE n = $1', [name]);
              }
            }
            const repo = new Repo(pool);
            export const handler = async (req: Request, res: Response) => {
              const name = req.query.name as string;
              await repo.find(name);
              await repo.safe(name);
            };
        """, "a.ts")
        self.assertEqual(_sinks(analysis), [("sql", 5)])

    def test_guards_ternary_and_terminating_branches(self):
        analysis = self.analyze("""
            const ALLOWED = ['a', 'b'];
            app.get('/x', (req, res) => {
              const v = req.query.v;
              if (!ALLOWED.includes(v)) {
                return res.status(400).end();
              }
              exec('run ' + v);
              const w = /^[a-z]+$/.test(req.query.w) ? req.query.w : 'x';
              exec('run ' + w);
              const n = req.query.n;
              if (typeof n === 'number') { exec('n ' + n); }
              exec('raw ' + req.query.raw);
            });
        """)
        self.assertEqual(_sinks(analysis), [("command", 12)])

    def test_callbacks_and_promise_chains(self):
        analysis = self.analyze("""
            app.get('/x', (req, res) => {
              req.query.ids.split(',').forEach((id) => {
                db.query('DELETE FROM t WHERE id = ' + id);
              });
              Promise.resolve(req.query.p).then((p) => eval(p));
              [1, 2].map((i) => db.query('SELECT ' + i));
            });
        """)
        self.assertEqual(_sinks(analysis), [("eval", 5), ("sql", 3)])

    def test_dom_sources_sinks_and_sanitizers(self):
        analysis = self.analyze("""
            const h = location.hash.slice(1);
            document.getElementById('o').innerHTML = h;
            el.innerHTML = DOMPurify.sanitize(h);
            window.location.href = h;
            location.href = '/fixed';
            window.addEventListener('message', (e) => { el.innerHTML = e.data; });
            el.textContent = h;
        """)
        self.assertEqual(_sinks(analysis), [("html", 2), ("html", 6), ("redirect", 4)])

    def test_model_sinks_ssrf_path_redirect_deserialize(self):
        analysis = self.analyze("""
            const fs = require('fs');
            const path = require('path');
            const serialize = require('node-serialize');
            app.get('/x', async (req, res) => {
              await fetch(req.query.u);
              await fetch(`https://api.example.com/v1/${req.query.u}`);
              await axios({ url: req.query.u, method: 'get' });
              fs.readFile(path.join('/srv', req.query.f), () => {});
              fs.readFile(path.join('/srv', path.basename(req.query.f)), () => {});
              res.sendFile(req.query.f, { root: '/srv' });
              res.redirect(301, req.query.next);
              serialize.unserialize(req.cookies.profile);
              spawn(req.query.c, { shell: true });
              spawn('ls', [req.query.c]);
            });
        """)
        self.assertEqual(_sinks(analysis), [
            ("command", 13), ("deserialize", 12), ("path", 8), ("redirect", 11), ("ssrf", 5), ("ssrf", 7),
            ("ssrf_partial", 6),  # sabit ana makine: kısmi SSRF sınıfı
        ])

    def test_nosql_where_and_safe_sql_tag(self):
        analysis = self.analyze("""
            app.get('/x', async (req, res) => {
              await db.find({ $where: `this.qty > ${req.query.q}` });
              await prisma.$queryRaw`SELECT * FROM t WHERE id = ${req.query.id}`;
              await prisma.$queryRawUnsafe('SELECT * FROM t WHERE id = ' + req.query.id);
            });
        """)
        self.assertEqual(_sinks(analysis), [("eval", 2), ("sql", 4)])

    def test_nestjs_param_decorators(self):
        analysis = self.analyze("""
            @Controller('u')
            export class UsersController {
              @Get()
              find(@Query('name') name: string, @Body() body: Dto) {
                return this.repo.query(`SELECT * FROM u WHERE n = '${name}'`);
              }
            }
        """, "c.ts")
        self.assertEqual(_sinks(analysis), [("sql", 5)])

    def test_cross_file_require_import_and_constructor_functions(self):
        files = {
            "routes/index.js": _src("""
                const { UsersDAO } = require('../data/users-dao');
                const helpers = require('../lib/helpers');
                import { render } from '../lib/view.mjs';
                module.exports = (app, db) => {
                  const dao = new UsersDAO(db);
                  app.get('/u', (req, res) => {
                    dao.find(req.query.id);
                    helpers.shell(req.body.cmd);
                    render(res, req.query.title);
                  });
                };
            """),
            "data/users-dao.js": _src("""
                function UsersDAO(db) {
                  this.find = function (id) {
                    return db.collection('u').find({ $where: 'this.id == ' + id });
                  };
                }
                module.exports.UsersDAO = UsersDAO;
            """),
            "lib/helpers.js": _src("""
                const cp = require('child_process');
                exports.shell = (cmd) => cp.exec(cmd);
            """),
            "lib/view.mjs": _src("""
                export function render(res, title) {
                  res.send('<h1>' + title + '</h1>');
                }
            """),
        }
        results = taint_js_ast.analyze_files(files)
        self.assertEqual(_sinks(results["data/users-dao.js"]), [("eval", 3)])
        self.assertEqual(_sinks(results["lib/helpers.js"]), [("command", 2)])
        self.assertEqual(_sinks(results["lib/view.mjs"]), [("html", 2)])
        flow = results["lib/helpers.js"].flows[0]
        self.assertEqual(flow.source_file, "routes/index.js")
        self.assertTrue(flow.cross_file)

    def test_project_context_uses_ast_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "routes.js").write_text(
                "const c = require('./ctrl');\nrouter.get('/x', c.show);\n", encoding="utf-8")
            controller = "exports.show = (rq, rs) => {\n  logger.info('q ' + rq.query.q);\n};\n"
            (root / "ctrl.js").write_text(controller, encoding="utf-8")

            @taint_flow.project_context
            def scan():
                taint_flow.activate_project(root, frozenset())
                return taint_flow.analyze_source(controller, "ctrl.js")

            analysis = scan()
        self.assertEqual(_sinks(analysis), [("log", 2)])

    def test_minified_and_unparseable_files(self):
        minified = "var a=1;" * 400 + "eval(location.hash);"
        self.assertIsNone(taint_flow.analyze_javascript(minified))
        results = taint_js_ast.analyze_files({"bad.js": "function ((", "ok.js": "eval(location.hash);"})
        self.assertNotIn("bad.js", {k for k, v in results.items() if v.flows})
        self.assertEqual(_sinks(results["ok.js"]), [("eval", 1)])

    def test_pinning_failures_fall_back_to_tokens(self):
        bad = {"SNIPER_NODE_BINARY": "/nonexistent/sniper-node", "SNIPER_NODE_SHA256": "0" * 64}
        with mock.patch.dict(os.environ, {**bad, "SNIPER_TAINT_JS_ENGINE": "auto"}):
            self.assertFalse(taint_js_ast.available())
            analysis = taint_flow.analyze_javascript("app.get('/x', (req, res) => { exec(req.query.c); });")
            self.assertEqual(_sinks(analysis), [("command", 1)])
        with mock.patch.dict(os.environ, {**bad, "SNIPER_TAINT_JS_ENGINE": "ast"}):
            self.assertIsNone(taint_flow.analyze_javascript("exec(req.query.c);"))
        with mock.patch.object(taint_js_ast, "PARSER_SHA256", "0" * 64):
            with self.assertRaises(taint_js_ast.JsParserUnavailable):
                taint_js_ast.parse_files({"a.js": "x"})

    def test_parser_timeout_kills_process(self):
        with taint_js_ast.NodeParser() as parser:
            self.assertIsNotNone(parser.parse("a.js", "let x = 1;"))
            pid = parser.proc.pid
            stdin = parser.proc.stdin
            parser.proc.stdin = mock.MagicMock()  # istek ulaşmaz → yanıt gelmez → zaman aşımı
            try:
                with self.assertRaises(taint_js_ast.JsParserUnavailable):
                    parser.parse("a.js", "", timeout=0.5)
            finally:
                parser.proc.stdin = stdin
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsStoredDataTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_orm_reads_are_stored_sources(self):
        analysis = taint_flow.analyze_javascript(_src("""
            async function profile(id) {
              const user = await UserModel.findByPk(id);
              eval(user.username);
              const rows = await pool.query('SELECT bio FROM u');
              el.innerHTML = rows[0].bio;
              const list = [1, 2].find((x) => x > 1);
              eval(String(list));
            }
        """), filename="p.js")
        stored = sorted((f.sink_kind, f.line) for f in analysis.flows if f.source_label == "stored")
        self.assertEqual(stored, [("eval", 3), ("html", 5)])
