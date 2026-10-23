"""JS/TS AST taint motoru: sabit değerlendirme, kap/alan duyarlılığı, türetilmiş doğrulama,
yönlendirme/SSRF sabit önekleri ve JS'e özgü hedefler (NoSQL, prototip, LDAP, XPath, XXE, oturum,
çerez, şablon). Her model için olumlu (akış var) ve olumsuz (akış yok) örnek bulunur."""
import os
from pathlib import Path
import textwrap
import unittest
from unittest import mock

import taint_flow
import taint_js_ast
from tests.test_taint_js_ast import NODE_ENV


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsSemanticsTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def flows(self, source, filename="a.js"):
        results = taint_js_ast.analyze_files({filename: _src(source)})
        self.assertIsNotNone(results)
        self.assertIn(filename, results, "ayrıştırılamadı")
        return results[filename].flows

    def sinks(self, source, filename="a.js"):
        return sorted((f.sink_kind, f.line) for f in self.flows(source, filename))

    # -- 1a: sabitler ve ölü dal budama ---------------------------------------------------
    def test_constant_folding_prunes_dead_branches(self):
        self.assertEqual(self.sinks("""
            app.get('/a', (req, res) => {
              const param = req.query.p;
              const num = 106;
              let a = (7 * 18) + num > 200 ? 'safe' : param;
              exec(a);
              let b = 'x';
              if ((500 / 42) + num > 100) { b = param; }
              exec(b);
              let c = 'x';
              if ((500 / 42) + num > 200) { c = param; }
              exec(c);
              const guess = 'ABC';
              let d;
              switch (guess.charAt(2)) { case 'A': d = param; break; case 'C': d = 'safe'; break; default: d = param; }
              exec(d);
              let e;
              switch (guess.charAt(0)) { case 'A': e = param; break; default: e = 'safe'; }
              exec(e);
              const flag = 'abc'.length === 3 && !'';
              exec(flag ? 'ls' : param);
              exec(['safe', param][0]);
              exec(['safe', param][1]);
            });
        """), [("command", 8), ("command", 18), ("command", 22)])

    def test_loop_and_closure_assignments_are_not_constants(self):
        self.assertEqual(self.sinks("""
            app.get('/a', (req, res) => {
              let mode = 0;
              for (const x of req.query.list) { mode = mode + 1; }
              exec(mode === 0 ? 'ls' : req.query.c);
              let flag = false;
              items.forEach(() => { flag = true; });
              if (flag) { exec(req.query.d); }
            });
        """), [("command", 4), ("command", 7)])

    # -- 1c: kaplar ---------------------------------------------------------------------
    def test_object_map_and_array_items_are_tracked(self):
        self.assertEqual(self.sinks("""
            app.get('/a', (req, res) => {
              const param = req.query.p;
              const map = { a: 'safe', b: param };
              exec(map['a']);
              exec(map.b);
              const m = new Map();
              m.set('k1', 'safe');
              m.set('k2', param);
              exec(m.get('k1'));
              exec(m.get('k2'));
              const list = ['safe'];
              list.push(param);
              list.push('moresafe');
              list.shift();
              exec(list[1]);
              exec(list[0]);
              const arr = [];
              arr.push(param);
              exec(arr.join(' '));
              const key = 'k';
              const o = {};
              o[key] = param;
              exec(o.k);
              exec(o.other);
              const merged = Object.assign({}, { z: 'safe' });
              exec(merged.z);
            });
        """), [("command", 5), ("command", 10), ("command", 16), ("command", 19), ("command", 23)])

    # -- 1b: alan duyarlı akış --------------------------------------------------------------
    def test_field_sensitive_classes_setters_and_factories(self):
        self.assertEqual(set(self.sinks("""
            class Runner {
              constructor(cmd) { this.cmd = cmd; this.safe = 'ls'; }
              runCmd() { exec(this.cmd); }
              runSafe() { exec(this.safe); }
              setCmd(c) { this.cmd = c; return this; }
              set target(v) { this.t = v; }
              runTarget() { exec(this.t); }
            }
            function makeRunner(c) { return new Runner(c); }
            app.get('/a', (req, res) => {
              const r = new Runner(req.query.c);
              r.runCmd();
              r.runSafe();
              const r2 = new Runner('ls');
              r2.runCmd();
              r2.target = req.query.t;
              r2.runTarget();
              const r3 = new Runner('ls');
              r3.setCmd(req.query.z);
              r3.runCmd();
              const r4 = makeRunner(req.query.f);
              r4.runCmd();
              makeRunner('ls').runCmd();
            });
        """)), {("command", 3), ("command", 7)})
        flows = self.flows("""
            class Runner {
              constructor(cmd) { this.cmd = cmd; }
              runCmd() { exec(this.cmd); }
              setCmd(c) { this.cmd = c; return this; }
            }
            function makeRunner(c) { return new Runner(c); }
            app.get('/a', (req, res) => {
              new Runner(req.query.a).runCmd();
              const r3 = new Runner('ls');
              r3.setCmd(req.query.z);
              r3.runCmd();
              const r4 = makeRunner(req.query.f);
              r4.runCmd();
              const r5 = makeRunner('ls');
              r5.runCmd();
            });
        """)
        self.assertEqual(sorted(f.source_line for f in flows), [8, 10, 12])

    def test_typescript_field_types_and_parameter_annotations(self):
        self.assertEqual(self.sinks("""
            class Db { query(sql: string) { return pool.query(sql); } safe(id: number) { return 1; } }
            class Service {
              constructor(private db: Db) {}
              find(name: string) { return this.db.query("SELECT * FROM t WHERE n = '" + name + "'"); }
              ok(name: string) { return this.db.safe(1); }
            }
            export function handler(svc: Service, req: any) {
              svc.find(req.query.n);
              svc.ok(req.query.n);
            }
        """, "s.ts"), [("sql", 1)])

    # -- 1d: türetilmiş doğrulama ve tırnak denetimi --------------------------------------
    def test_derived_url_validation_and_quote_checks(self):
        self.assertEqual(self.sinks("""
            app.get('/a', async (req, res) => {
              const u = new URL(req.query.url);
              if (!['a.example', 'b.example'].includes(u.hostname)) return;
              await fetch(req.query.url);
              const u2 = new URL(req.query.url2);
              await fetch(req.query.url2);
              const n = req.query.n;
              if (n.includes("'")) return;
              xpath.select("//user[name='" + n + "']", doc);
              xpath.select("//user[name='" + req.query.m + "']", doc);
              const q = req.query.q.replace(/'/g, '');
              xpath.select("//u[n='" + q + "']", doc);
            });
        """), [("ssrf", 6), ("xpath", 10)])

    # -- yönlendirme / SSRF sabit önekleri ---------------------------------------------
    def test_redirect_fixed_prefix_and_page_address(self):
        self.assertEqual(self.sinks("""
            app.get('/a', (req, res) => {
              res.redirect('/pet/' + req.query.id);
              res.redirect(`/u/${req.query.id}`);
              res.redirect('//' + req.query.h);
              res.redirect(req.query.next);
              res.redirect('https://example.com/' + req.query.p);
              res.redirect('https://' + req.query.h);
              res.redirect('?q=' + req.query.q);
              res.redirect(req.get('Referrer') || '/');
              fetch('/api/' + req.query.id).then(r => r.text()).then(t => res.send(t));
            });
            var url = new URL(window.location.href);
            url.searchParams.append('a', document.getElementById('x').value);
            window.location.href = url.toString();
            location.href = location.hash.slice(1);
            fetch(src + '?' + new URLSearchParams(location.search).toString());
            fetch(location.search.substring(1)).then(r => r.text()).then(h => { el.innerHTML = h; });
            const cur = new URL(document.URL);
            location.assign;
            window.location = cur.searchParams.get('next');
        """), [("redirect", 4), ("redirect", 5), ("redirect", 7), ("redirect", 15), ("redirect", 20), ("ssrf", 17)])

    def test_single_slash_guard_does_not_hide_backslash_open_redirect(self):
        self.assertEqual(self.sinks(r"""
            app.get('/go', (req, res) => {
              const next = req.query.next;
              if (next.startsWith('/') && !next.startsWith('//')) {
                return res.redirect(next);
              }
            });
            app.get('/safe', (req, res) => {
              const next = req.query.next;
              if (/^\/(?![\\/])[^\\]*$/.test(next)) {
                return res.redirect(next);
              }
            });
        """), [("redirect", 4)])

    # -- 1e: yeni hedefler -------------------------------------------------------------
    def test_nosql_operator_injection(self):
        self.assertEqual(self.sinks("""
            app.post('/a', async (req, res) => {
              await User.findOne({ name: req.body.name });
              await User.findOne({ name: String(req.body.name) });
              await User.findOne({ name: req.params.name });
              await db.collection('users').find({ name: req.query.n }).toArray();
              await User.findOne({ where: { name: req.body.name } });
              await Math.find(req.body.x);
              if (typeof req.body.id !== 'string') { return res.status(400).end(); }
              await db.reviewsCollection.update({ _id: req.body.id }, { $set: { m: 1 } });
            });
        """), [("nosql", 2), ("nosql", 5)])

    def test_prototype_pollution(self):
        self.assertEqual(self.sinks("""
            const _ = require('lodash');
            function store(key, phase, v) { solves[key][phase] = v; }
            function store2(a, b) { tree[a][b] = 1; }
            app.post('/a', (req, res) => {
              _.merge({}, req.body);
              _.merge({}, { a: req.params.x });
              _.set(cfg, req.body.path, 1);
              const cfg = {};
              cfg[req.body.a][req.body.b] = req.body.c;
              const k1 = req.body.k;
              if (k1 === '__proto__' || k1 === 'constructor') return;
              cfg[k1][req.body.b] = 1;
              store(req.body.key, 'fix it', true);
              store2(req.body.a, req.body.b);
            });
        """), [("prototype", 3), ("prototype", 5), ("prototype", 7), ("prototype", 9)])

    def test_ldap_xpath_xxe_template_session_cookie(self):
        flows = self.flows("""
            const ldap = require('ldapjs');
            const client = ldap.createClient({ url: 'ldap://localhost' });
            app.post('/a', (req, res) => {
              client.search('ou=people', { filter: `(uid=${req.query.u})` }, () => {});
              client.search('ou=people', { filter: '(uid=admin)' }, () => {});
              es.search({ index: 'x', q: req.query.u });
              req.session.user = req.body.user;
              req.session.token = Math.random().toString(36);
              req.session.n = 'x';
              res.cookie('sid', Math.random().toString(36), { secure: false });
              res.cookie('sid', crypto.randomBytes(16).toString('hex'));
              ejs.render(req.body.tpl, {});
              ejs.render('<p><%= x %></p>', { x: req.body.tpl });
              libxmljs.parseXml(req.body.xml, { noent: true });
              libxmljs.parseXml(req.body.xml, { noent: false });
              xpath.select('//user', doc);
            });
        """)
        got = sorted((f.sink_kind, f.line, f.source_label) for f in flows)
        self.assertEqual(got, [
            ("cookie", 10, "weakrand"), ("eval", 12, "request"), ("ldap", 4, "request"),
            ("session", 7, "request"), ("session", 8, "weakrand"), ("xxe", 14, "request"),
        ])

    def test_angular_route_sources_and_bypass_sinks(self):
        self.assertEqual(self.sinks("""
            class SearchComponent {
              filterTable() {
                let q: string = this.route.snapshot.queryParams.q;
                q = q.trim();
                this.searchValue = this.sanitizer.bypassSecurityTrustHtml(q);
                this.plain = q;
                this.route.queryParams.subscribe((params) => {
                  this.x = this.sanitizer.bypassSecurityTrustResourceUrl(params.u);
                });
                this.y = this.sanitizer.bypassSecurityTrustHtml('<b>sabit</b>');
              }
            }
        """, "c.ts"), [("html", 5), ("html", 8)])

    # -- 2: üretilmiş Node modelleri ---------------------------------------------------------
    def test_generated_node_models_scalar_returns_are_clean(self):
        self.assertEqual(self.sinks("""
            const fs = require('fs');
            const { join } = require('node:path');
            app.get('/a', (req, res) => {
              res.send('<b>' + fs.existsSync(req.query.f) + '</b>');
              res.send('<b>' + join('a', req.query.f) + '</b>');
            });
        """), [("html", 5)])

    def test_truncated_snippet_is_parsed_with_closing_braces(self):
        self.assertEqual(self.sinks("""
            export function login () {
              return (req, res) => {
                models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
        """, "snippet.ts"), [("sql", 3)])

    def test_user_model_sources_create_js_flows(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kurum.json"
            path.write_text(json.dumps({
                "format": "sniper-taint-models-v1", "language": "javascript",
                "sources": [{"label": "request", "names": ["sirket.istek.oku"], "attributes": ["sirket.istek.govde"]}],
            }), encoding="utf-8")
            with mock.patch.dict(os.environ, {"SNIPER_TAINT_MODELS": str(path)}):
                got = self.sinks("""
                    exec(sirket.istek.oku('x'));
                    exec(sirket.istek.baska('x'));
                    eval(sirket.istek.govde);
                    eval(sirket.istek.baslik);
                """)
        self.assertEqual(got, [("command", 1), ("eval", 3)])

    def test_model_sources_hook_is_optional(self):
        project = taint_js_ast.JsProject(None, max_steps=100_000)
        project.models = mock.MagicMock(wraps=project.models)
        project.models.source_for = lambda name: "request" if name == "getUntrusted" else None
        project.models.attribute_source_for = lambda dotted: "request" if dotted == "config.untrusted" else None
        programs = taint_js_ast.parse_files({"a.js": "exec(getUntrusted());\nexec(getTrusted());\neval(config.untrusted);\neval(config.safe);\n"})
        project.add_module("a.js", programs["a.js"])
        project.run()
        self.assertEqual(sorted((f.sink_kind, f.line) for f in project.flows["a.js"]), [("command", 1), ("eval", 3)])


if __name__ == "__main__":
    unittest.main()
