"""JS taint (8. tur, bağımsız ölçüm bulguları): sorgu sonucu argüman taint'ini taşımaz, XML'den
ayrıştırılan değer NoSQL işleci taşımaz, korumasız özyinelemeli merge prototip kirletmedir."""
import os
import textwrap
import unittest
from unittest import mock

import taint_js_ast
from tests.test_taint_js_ast import NODE_ENV


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsDbXmlMergeTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def sinks(self, files, filename="a.js", label=None):
        results = taint_js_ast.analyze_files({k: _src(v) for k, v in files.items()})
        self.assertIsNotNone(results)
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows
                       if label is None or f.source_label == label})

    def test_query_result_does_not_carry_request_taint(self):
        self.assertEqual(self.sinks({"a.js": """
            const db = require('./db');
            app.post('/login', async (req, res) => {
              const { rows } = await db.pool.query('SELECT * FROM u WHERE n = $1', [req.body.user]);
              req.session.userId = rows[0].id;
              const u = await User.findOne({ where: { name: req.body.user } });
              req.session.name = u.name;
              req.session.role = req.body.role;
            });
        """}, label="request"), [("session", 7)])

    def test_xml_parsed_values_cannot_inject_operators(self):
        self.assertEqual(self.sinks({"a.js": """
            const mongoose = require('mongoose');
            const xml2js = require('xml2js');
            const libxml = require('libxmljs');
            const User = mongoose.model('User', new mongoose.Schema({}));
            app.post('/x', async (req, res) => {
              const parsed = await new xml2js.Parser().parseStringPromise(req.body.xml);
              await User.findOne({ username: parsed.profile.username });
              const doc = libxml.parseXml(req.body);
              await User.findOne({ username: doc.get('//username').text() });
              await User.findOne({ username: req.body.username });
            });
        """}), [("nosql", 10)])

    def test_unguarded_recursive_merge_is_prototype_pollution(self):
        self.assertEqual(self.sinks({"a.js": """
            function deepMerge(target, source) {
              for (const key of Object.keys(source)) {
                if (typeof source[key] === 'object') {
                  if (!target[key]) target[key] = {};
                  deepMerge(target[key], source[key]);
                } else {
                  target[key] = source[key];
                }
              }
              return target;
            }
            function safeMerge(target, source) {
              for (const key in source) {
                if (key === '__proto__' || key === 'constructor') continue;
                if (typeof source[key] === 'object') safeMerge(target[key], source[key]);
                else target[key] = source[key];
              }
            }
            function copy(target, source) {
              for (const key in source) target[key] = source[key];
            }
            app.post('/p', (req, res) => {
              deepMerge({}, req.body.prefs);
              safeMerge({}, req.body.prefs);
              copy({}, req.body.prefs);
              deepMerge({}, { a: 1 });
            });
        """}), [("prototype", 4), ("prototype", 7)])

    def test_url_part_of_parameter_does_not_crash_summary(self):
        # Parametre kökenine ".searchParams" eklenmesi özet eşlemesinde int() hatasıyla tüm analizi düşürüyordu.
        results = taint_js_ast.analyze_files({
            "lib.js": _src("""
                const { exec } = require('child_process');
                function f(u) { exec(u.searchParams.get('c')); }
                module.exports = f;
            """),
            "a.js": _src("""
                const f = require('./lib');
                app.get('/x', (req, res) => { f(new URL(req.query.u)); });
            """),
        })
        self.assertIsNotNone(results)
        self.assertIn("lib.js", results)


if __name__ == "__main__":
    unittest.main()
