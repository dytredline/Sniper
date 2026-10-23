"""JS/TS taint (12. tur): sunucu tarafı şablonlarda kaçışsız çıktı (EJS/Pug/Handlebars) ve res.render'a bütün
istek nesnesi, fonksiyon içi require ile node-serialize, üçüncü taraf HTTP yanıtı ikinci derece kaynağı.
Olumlu ve olumsuz örnekler."""
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import taint_js_ast
import taint_js_views
from tests.test_taint_js_ast import NODE_ENV


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


class TemplateParserTests(unittest.TestCase):
    def test_ejs_raw_and_escaped(self):
        text = _src("""
            <h1><%= title %></h1>
            <p><%- q %></p>
            <%- include('footer') %>
            <%- typeof msg === 'string' && msg.length ? msg : '' %>
            <%- escapeHtml(note) %>
        """)
        outputs = taint_js_views.unescaped_outputs("views/a.ejs", text)
        self.assertEqual([(line, paths) for line, _, paths in outputs], [(2, [("q",)]), (4, [("msg",)])])

    def test_pug_raw_and_escaped(self):
        text = _src("""
            h1= title
            h2!= 'Sonuç: ' + text
            p #{safe} ve !{raw}
            if a != b
              p ok
        """)
        outputs = taint_js_views.unescaped_outputs("views/a.pug", text)
        self.assertEqual(sorted((line, paths) for line, _, paths in outputs), [(2, [("text",)]), (3, [("raw",)])])

    def test_handlebars_triple_stash_only(self):
        text = "{{name}}\n{{{bio}}}\n{{{markdown post.body}}}\n{{#each x}}{{/each}}\n"
        outputs = taint_js_views.unescaped_outputs("views/a.hbs", text)
        self.assertEqual([(line, paths) for line, _, paths in outputs],
                         [(2, [("bio",)]), (3, [("markdown",), ("post", "body")])])

    def test_resolve_view(self):
        inventory = frozenset({"views/a.ejs", "web/views/a.ejs", "templates/b.pug", "app/views/c.hbs"})
        self.assertEqual(taint_js_views.resolve_view("a", "web/routes/x.js", inventory, [], ["ejs"]), "web/views/a.ejs")
        self.assertEqual(taint_js_views.resolve_view("a", "routes/x.js", inventory, [], ["ejs"]), "views/a.ejs")
        self.assertEqual(taint_js_views.resolve_view("b", "x.js", inventory, ["templates"], []), "templates/b.pug")
        self.assertEqual(taint_js_views.resolve_view("c.hbs", "app/x.js", inventory, [], []), "app/views/c.hbs")
        self.assertIsNone(taint_js_views.resolve_view("../etc/passwd", "x.js", inventory, [], []))
        self.assertIsNone(taint_js_views.resolve_view("missing", "x.js", inventory, [], []))


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsRound12Tests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def flows(self, files, filename, templates=None, label="request"):
        results = taint_js_ast.analyze_files({k: _src(v) for k, v in files.items()},
                                             templates={k: _src(v) for k, v in (templates or {}).items()})
        self.assertIsNotNone(results)
        self.assertIn(filename, results, "ayrıştırılamadı")
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows if label is None or f.source_label == label})

    # -- şablonlarda kaçışsız çıktı ----------------------------------------------------------
    def test_ejs_unescaped_request_value_is_xss(self):
        files = {"routes/shop.js": """
            const express = require('express');
            const router = express.Router();
            router.get('/search', (req, res) => {
              const q = req.query.q;
              res.render('products', { q, title: req.query.t, count: parseInt(req.query.n) });
            });
            module.exports = router;
        """}
        templates = {"views/products.ejs": """
            <h1><%= title %></h1>
            <p>Sonuç: <%- q %> (<%- count %>)</p>
        """}
        self.assertEqual(self.flows(files, "routes/shop.js", templates), [("html", 5)])

    def test_ejs_escaped_or_sanitized_is_clean(self):
        files = {"routes/shop.js": """
            const escapeHtml = require('escape-html');
            module.exports = (app) => app.get('/s', (req, res) => {
              res.render('products', { q: req.query.q, safe: escapeHtml(req.query.s) });
            });
        """}
        templates = {"views/products.ejs": "<p><%= q %></p><p><%- safe %></p><%- include('footer') %>\n"}
        self.assertEqual(self.flows(files, "routes/shop.js", templates), [])

    def test_nested_locals_object_and_views_setting(self):
        files = {
            "app.js": """
                const path = require('path');
                const express = require('express');
                const app = express();
                app.set('views', path.join(__dirname, 'ui'));
                app.set('view engine', 'pug');
                app.post('/p', (req, res) => {
                  const output = { term: req.body.name, list: [] };
                  res.render('results', { output: output, page: { heading: 'Ara' } });
                });
            """,
        }
        templates = {
            "ui/results.pug": "h1!= page.heading\np!= output.term\n",
            "views/results.pug": "p!= page.heading\n",
        }
        self.assertEqual(self.flows(files, "app.js", templates), [("html", 8)])

    def test_handlebars_triple_stash(self):
        files = {"server.js": """
            const app = require('express')();
            app.get('/u', (req, res) => res.render('user.hbs', { bio: req.query.bio, name: req.query.name }));
        """}
        templates = {"views/user.hbs": "<h1>{{name}}</h1>\n<div>{{{bio}}}</div>\n"}
        self.assertEqual(self.flows(files, "server.js", templates), [("html", 2)])
        templates = {"views/user.hbs": "<h1>{{name}}</h1>\n<div>{{bio}}</div>\n"}
        self.assertEqual(self.flows(files, "server.js", templates), [])

    def test_ambiguous_view_is_not_guessed(self):
        files = {"server.js": """
            const app = require('express')();
            app.get('/u', (req, res) => res.render('page', { x: req.query.x }));
        """}
        templates = {"a/views/page.ejs": "<%- x %>\n", "b/views/page.ejs": "<%= x %>\n"}
        self.assertEqual(self.flows(files, "server.js", templates), [])

    # -- res.render'a bütün istek nesnesi -------------------------------------------------------
    def test_whole_request_object_as_locals(self):
        files = {"routes/index.js": """
            exports.save = function (req, res) {
              const profile = req.body;
              profile.first = String(profile.first).trim();
              return res.render('account.hbs', profile);
            };
            exports.query = (req, res) => res.render('list', req.query);
            exports.spread = (req, res) => res.render('list', { ...req.body, page: 1 });
            exports.fields = (req, res) => res.render('list', { name: req.body.name });
        """}
        flows = self.flows(files, "routes/index.js")
        self.assertIn(("template_object", 4), flows)
        self.assertIn(("template_object", 6), flows)
        self.assertIn(("template_object", 7), flows)
        self.assertNotIn(("template_object", 8), flows)

    def test_reassigned_name_is_not_request_object(self):
        files = {"r.js": """
            exports.a = (req, res) => {
              let data = req.body;
              data = { name: 'sabit' };
              res.render('list', data);
            };
        """}
        self.assertEqual(self.flows(files, "r.js"), [])

    # -- node-serialize -----------------------------------------------------------------
    def test_node_serialize_with_local_require_and_text_body(self):
        files = {"seed.js": """
            const express = require('express');
            const app = express();
            app.use(express.text({ type: 'application/x-www-form-urlencoded' }));
            function loadState(payload) {
              const unserialize = require('node-serialize');
              return unserialize.unserialize(payload);
            }
            app.post('/session', (req, res) => res.json(loadState(req.body)));
            app.post('/other', (req, res) => {
              const s = require('node-serialize');
              res.json(s.unserialize(req.body.state));
            });
            app.post('/safe', (req, res) => {
              const s = require('serialize-javascript');
              res.json(s(req.body));
            });
        """}
        self.assertEqual(self.flows(files, "seed.js"), [("deserialize", 6), ("deserialize", 11)])

    # -- ikinci derece kaynak: üçüncü taraf HTTP yanıtı ----------------------------------------
    def test_http_response_is_second_order_source(self):
        files = {"svc.js": """
            const axios = require('axios');
            const { exec } = require('child_process');
            module.exports = (app) => app.get('/sync', async (req, res) => {
              const r = await axios.get('https://api.example.com/job');
              exec(r.data.command);
              const html = await fetch('https://api.example.com/x').then(x => x.text());
              res.send('<div>' + html + '</div>');
              res.json(await (await fetch('https://api.example.com/y')).json());
            });
        """}
        self.assertEqual(self.flows(files, "svc.js", label="second_order"), [("command", 5)])
        self.assertEqual(self.flows(files, "svc.js"), [])

    def test_request_url_taint_still_not_in_response(self):
        files = {"svc.js": """
            const axios = require('axios');
            module.exports = (app) => app.get('/p', async (req, res) => {
              const r = await axios.get('https://api.example.com/u/' + encodeURIComponent(req.query.id));
              eval(r.data);
            });
        """}
        self.assertEqual(self.flows(files, "svc.js"), [])
        self.assertEqual(self.flows(files, "svc.js", label="second_order"), [("eval", 4)])

    # -- kısmi SSRF: sabit ana makine, kullanıcı yalnız yol/sorguyu belirler ---------------------
    def test_partial_ssrf_with_fixed_host(self):
        files = {"svc.js": """
            const axios = require('axios');
            const BASE = 'https://api.example.com';
            const client = axios.create({ baseURL: 'https://api.example.com' });
            module.exports = (app) => app.get('/p', async (req, res) => {
              await fetch('https://api.example.com/' + req.query.p);
              await fetch(`https://api.example.com/u/${req.query.id}`);
              await fetch(`https://api.example.com/search?q=${req.query.q}`);
              await fetch(new URL('/v1/' + req.query.p, BASE));
              await axios.get('/users/' + req.query.id, { baseURL: 'https://api.example.com' });
              await client.post('/items/' + req.body.id, {});
              let u = 'https://api.example.com/items/';
              u += req.query.id;
              await axios.get(u);
            });
        """}
        self.assertEqual(self.flows(files, "svc.js"), [
            ("ssrf_partial", 5), ("ssrf_partial", 6), ("ssrf_partial", 7), ("ssrf_partial", 8),
            ("ssrf_partial", 9), ("ssrf_partial", 10), ("ssrf_partial", 13),
        ])

    def test_user_controlled_host_stays_full_ssrf(self):
        files = {"svc.js": """
            const axios = require('axios');
            const BASE = 'https://api.example.com';
            module.exports = (app) => app.get('/p', async (req, res) => {
              await fetch(req.query.url);
              await fetch('https://' + req.query.h + '/x');
              await fetch(new URL(req.query.u, BASE));
              await axios.get(req.query.u, { baseURL: 'https://api.example.com' });
              await fetch(`${req.query.scheme}://api.example.com/x`);
            });
        """}
        self.assertEqual(self.flows(files, "svc.js"), [("ssrf", 4), ("ssrf", 5), ("ssrf", 6), ("ssrf", 7), ("ssrf", 8)])

    def test_partial_ssrf_clean_cases(self):
        files = {"svc.js": """
            module.exports = (app) => app.get('/p', async (req, res) => {
              await fetch('https://api.example.com/' + encodeURIComponent(req.query.p));
              await fetch('/api/' + req.query.id);
              await fetch(`https://api.example.com/n/${parseInt(req.query.n, 10)}`);
              res.redirect('https://example.com/' + req.query.p);
            });
        """}
        self.assertEqual(self.flows(files, "svc.js"), [])


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class ProjectReportingTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "proj"
        (self.root / "views").mkdir(parents=True)

    def analyze(self):
        import project_analyzer
        return project_analyzer.analyze_project(str(self.root), allowed_roots=(self.root.parent,))

    def test_template_xss_object_and_second_order_findings(self):
        (self.root / "package.json").write_text('{"name": "p", "dependencies": {"express": "4.21.2", "ejs": "3.1.10"}}\n')
        (self.root / "views" / "list.ejs").write_text("<p><%- q %></p>\n")
        (self.root / "app.js").write_text(_src("""
            const express = require('express');
            const axios = require('axios');
            const { exec } = require('child_process');
            const app = express();
            app.set('view engine', 'ejs');
            app.get('/list', (req, res) => res.render('list', { q: req.query.q }));
            app.post('/all', (req, res) => res.render('list', req.body));
            app.get('/job', async (req, res) => {
              const r = await axios.get('https://api.example.com/job');
              exec(r.data.cmd);
              res.end();
            });
            app.listen(3000);
        """))
        findings = [f for f in self.analyze()["findings"] if f.get("taint_flow")]
        by_line = {(f["line"], f["reference"]): f for f in findings}
        self.assertIn((6, "CWE-79"), by_line)
        self.assertIn("views/list.ejs:1", by_line[(6, "CWE-79")]["evidence"])
        self.assertEqual(by_line[(7, "CWE-94")]["severity"], "high")
        second = by_line[(10, "CWE-78")]
        self.assertEqual(second["severity"], "low")
        self.assertTrue(second["title"].startswith("İkinci derece veri akışı:"))
        verified = [f for f in findings if f["title"].startswith("Doğrulanmış veri akışı")]
        self.assertNotIn(second, verified)


if __name__ == "__main__":
    unittest.main()
