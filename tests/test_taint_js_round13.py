"""JS/TS taint (13. tur): Express res.send(dize) yansıtılmış XSS ve içerik türü, Mongo sorgu nesnesi,
dosya yükleme yolu (express-fileupload mv), kod çözme sonrası yol denetimi, ek HTTP istemci yöntemleri (SSRF),
konum argümanlı yöntemler ve doğrulanmış akışların dosya başı sınırı. Olumlu ve olumsuz örnekler."""
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import project_analyzer
import taint_js_ast
from tests.test_taint_js_ast import NODE_ENV


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsRound13Tests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def flows(self, source, filename="app.js", label="request"):
        results = taint_js_ast.analyze_files({filename: _src(source)})
        self.assertIsNotNone(results)
        self.assertIn(filename, results, "ayrıştırılamadı")
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows if label is None or f.source_label == label})

    # -- Express res.send(dize) ----------------------------------------------------------
    def test_express_string_send_is_reflected_xss(self):
        source = """
            const express = require('express');
            const app = express();
            app.get('/a', (req, res) => { res.send('Bulunamadı: ' + req.query.q); });
            app.get('/b', function (req, res) { res.status(404).send(`Yok: ${req.query.q}`); });
            app.get('/c', (req, res) => { const msg = 'Aranan ' + req.query.q; res.send(msg); });
            app.get('/d/:id', (req, res) => { res.send(req.params.id); });
            app.get('/e', (req, res) => { res.setHeader('Content-Type', 'text/html'); res.send('x ' + req.query.q); });
        """
        self.assertEqual(self.flows(source), [("html", 3), ("html", 4), ("html", 5), ("html", 6), ("html", 7)])

    def test_express_send_non_html_or_escaped_is_clean(self):
        source = """
            const express = require('express');
            const escapeHtml = require('escape-html');
            const app = express();
            app.get('/a', (req, res) => { res.type('text/plain'); res.send('x ' + req.query.q); });
            app.get('/b', (req, res) => { res.set('Content-Type', 'application/json'); res.send('x ' + req.query.q); });
            app.get('/c', (req, res) => { res.send('x ' + escapeHtml(req.query.q)); });
            app.get('/d', (req, res) => { res.send({ q: req.query.q }); });
            app.get('/e', (req, res) => { res.json('x ' + req.query.q); });
            app.get('/f', (req, res) => { res.type('json').send('x ' + req.query.q); });
            app.get('/g', (req, res) => { res.send(req.body.data); });
            app.get('/h', (req, res) => { res.send('Sayı: ' + parseInt(req.query.n, 10)); });
            app.get('/i', (req, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.send('x ' + req.query.q); });
        """
        self.assertEqual(self.flows(source), [])

    def test_nested_callback_send(self):
        source = """
            var express = require('express');
            var mongo = require('mongodb').MongoClient;
            var api = express();
            api.get('/api/search', function (req, res) {
              mongo.connect(url, function (err, db) {
                db.collection('p').find({ $text: { $search: String(req.query.query) } }).toArray(function (e, found) {
                  if (found.length) { res.json(found); }
                  else { res.status(500).send('No photos found containing ' + req.query.query); }
                });
              });
            });
        """
        self.assertEqual(self.flows(source), [("html", 8)])

    def test_content_type_suppresses_html_literal_and_xpath_result_is_clean(self):
        source = """
            const express = require('express');
            const xpath = require('xpath');
            const app = express();
            app.get('/x/:r', (req, res) => {
              var v = decodeURI(req.params.r.toString());
              var xr = xpath.evaluate("//c[text()='" + v + "']", doc, null, 0, null);
              var out = [];
              out.push(xr.iterateNext().toString());
              res.send(out.toString());
            });
            app.get('/p', (req, res) => { res.type('text/plain'); res.send('<b>' + req.query.q + '</b>'); });
            app.get('/q', (req, res) => { res.set('Content-Type', 'application/xml'); res.send(`<u>${req.query.q}</u>`); });
        """
        self.assertEqual(self.flows(source), [("html", 12), ("xpath", 6)])

    # -- Mongo sorgu nesnesi ---------------------------------------------------------------
    def test_mongo_filter_from_request(self):
        source = """
            const express = require('express');
            const app = express();
            app.get('/s', (req, res) => {
              db.collection('users').find({ $or: [{ name: req.query.search }, { email: req.query.search }] });
              db.collection('users').findOne({ email: String(req.body.user), password: { $eq: req.body.pass } });
              db.collection('pictures').find({ $text: { $search: req.query.query } });
              db.collection('pictures').remove({ _id: req.query.picture_id });
            });
        """
        self.assertEqual(self.flows(source), [("nosql", 4), ("nosql", 7)])

    # -- dosya yükleme ve yol --------------------------------------------------------------
    def test_fileupload_mv_with_client_name(self):
        source = """
            const express = require('express');
            const path = require('path');
            const app = express();
            app.post('/up', (req, res) => {
              const file = req.files.file;
              file.mv('upload/' + file.name, () => {});
              file.mv(path.join('upload', path.basename(file.name)), () => {});
              file.mv('upload/fixed.bin', () => {});
            });
        """
        self.assertEqual(self.flows(source), [("path", 6)])

    def test_decode_after_traversal_check_reopens_path(self):
        source = """
            const express = require('express');
            const fs = require('fs');
            const app = express();
            app.post('/home', (req, res) => {
              let filename = req.body.filename;
              if (!filename.includes('../')) {
                fs.readFile(filename, () => {});
                filename = decodeURIComponent(filename);
                fs.readFile(filename, () => {});
              }
            });
        """
        self.assertEqual(self.flows(source), [("path", 9)])

    # -- SSRF: ek istemci yöntemleri --------------------------------------------------------
    def test_request_head_and_needle_methods(self):
        source = """
            const express = require('express');
            const request = require('request');
            const needle = require('needle');
            const app = express();
            app.post('/c', (req, res) => {
              request.head(req.body.url, { timeout: 2000 }, () => {});
              needle.head(req.body.url, () => {});
              request.head('https://status.example.com/ping', () => {});
            });
        """
        self.assertEqual(self.flows(source), [("ssrf", 6), ("ssrf", 7)])

    def test_request_field_named_size_is_tainted(self):
        source = """
            const express = require('express');
            const { exec } = require('child_process');
            const app = express();
            app.post('/r', (req, res) => {
              exec(`convert a.png -resize ${req.body.size}% a.png`);
              const seen = new Set([req.body.x]);
              exec('echo ' + seen.size);
              exec('echo ' + req.body.q.length);
            });
        """
        self.assertEqual(self.flows(source), [("command", 5)])

    # -- konum argümanlı yöntemler -----------------------------------------------------------
    def test_index_arguments_do_not_taint_result(self):
        source = """
            const express = require('express');
            const app = express();
            const users = [{ name: 'a' }, { name: 'b' }];
            app.get('/u/:from-:to', (req, res) => {
              const names = users.map((u) => u.name);
              res.send('users ' + names.slice(req.params.from, req.params.to + 1).join(', '));
              res.send('ilk ' + req.query.q.slice(0, 20));
            });
        """
        self.assertEqual(self.flows(source), [("html", 7)])


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class FlowCapTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_more_than_four_verified_flows_in_one_file_are_reported(self):
        routes = "\n".join(
            f"app.get('/r{i}', (req, res) => {{ res.send('x ' + req.query.q{i}); }});" for i in range(7)
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "server.js").write_text("const express = require('express');\nconst app = express();\n" + routes + "\n")
            result = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))
        lines = sorted(f["line"] for f in result["findings"] if f.get("taint_flow") and f["reference"] == "CWE-79")
        self.assertEqual(lines, list(range(3, 10)))


if __name__ == "__main__":
    unittest.main()
