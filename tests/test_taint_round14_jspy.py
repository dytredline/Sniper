"""14. tur JS/Python taint: 6. setteki kaçırmalardan çıkarılan genel kalıplar. Olumlu ve olumsuz örnekler.

* Express: ``const { x } = req.query`` → ``res.send(x)`` (yıkım ile alınan dize alanı); urlencoded gövde
  ayrıştırıcısı varsa ``req.body`` alanları da dize sayılır;
* şablonlarda ``<script>`` içindeki tırnak dışı KAÇIŞLI çıktı (Pug ``script #{x}``, EJS ``<%= %>``, Handlebars ``{{ }}``);
* DynamoDB ifade/tablo enjeksiyonu (``nosql_expr``; JS parametre nesnesi, Python boto3 anahtar sözcükleri);
* AWS Chalice: ``app.current_request`` ve SNS/SQS olay işleyicileri; Chalice dize dönüşü HTML değildir.
"""
import os
from pathlib import Path
import sys
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_flow as tf  # noqa: E402
import taint_js_ast  # noqa: E402
import taint_js_views  # noqa: E402
from tests.test_taint_js_ast import NODE_ENV  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _py(files):
    return tf._analyze_python_files_uncached({k: _src(v) for k, v in files.items()}, None, frozenset())


class ScriptContextTemplateTests(unittest.TestCase):
    def test_pug_script_escaped_interpolation(self):
        text = "script #{payload}\np #{safe}\nscript.\n  var a = '#{quoted}';\n  var b = #{raw};\nscript(src='x.js')\n"
        found = taint_js_views.unescaped_outputs("views/a.pug", text)
        self.assertEqual([(line, paths) for line, _shown, paths in found], [(1, [("payload",)]), (5, [("raw",)])])

    def test_ejs_and_handlebars_script_blocks(self):
        ejs = ('<script>var a = "<%= q %>"; var b = <%= n %>;</script><p><%= z %></p>\n'
               '<script type="application/json"><%= data %></script><script src="a.js"></script>\n')
        self.assertEqual([p for _l, _s, p in taint_js_views.unescaped_outputs("views/a.ejs", ejs)], [[("n",)]])
        hbs = '<script>var a = "{{q}}"; init({{cfg}});</script><div>{{name}}</div>\n'
        self.assertEqual([p for _l, _s, p in taint_js_views.unescaped_outputs("views/a.hbs", hbs)], [[("cfg",)]])


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsRound14Tests(unittest.TestCase):
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

    def test_destructured_query_send_is_xss(self):
        files = {"app.js": """
            const express = require('express');
            const path = require('path');
            const api = express.Router();
            api.get('/a', (req, res) => {
              const { input } = req.query;
              path.extname(input);
              res.send(input);
            });
            api.get('/b', (req, res) => { const { input } = req.query; res.json(input); });
            api.get('/c', (req, res) => { const { input } = req.body; res.send(input); });
            api.get('/d', (req, res) => { const { input } = req.query; res.type('text/plain').send(input); });
            module.exports = api;
        """}
        self.assertEqual(self.flows(files, "app.js"), [("html", 7)])

    def test_body_fields_are_strings_with_urlencoded_parser(self):
        files = {
            "index.js": """
                const express = require('express');
                const bodyParser = require('body-parser');
                const app = express();
                app.use(bodyParser.urlencoded({ extended: true }));
                app.use('/x', require('./routes'));
            """,
            "routes.js": """
                const api = require('express').Router();
                api.post('/a', (req, res) => { const { input } = req.body; res.send(input); });
                api.post('/b', (req, res) => { res.send(req.body.name); });
                module.exports = api;
            """,
        }
        self.assertEqual(self.flows(files, "routes.js"), [("html", 2), ("html", 3)])

    def test_pug_script_context_render(self):
        files = {"app.js": """
            const app = require('express')();
            app.set('view engine', 'pug');
            app.get('/u', (req, res) => res.render('page', { code: req.query.c, text: req.query.t }));
        """}
        templates = {"views/page.pug": "script #{code}\np #{text}\n"}
        self.assertEqual(self.flows(files, "app.js", templates), [("html", 3)])

    def test_dynamodb_expression_injection(self):
        files = {"db.js": """
            const AWS = require('aws-sdk');
            const client = new AWS.DynamoDB.DocumentClient();
            module.exports = (app) => {
              app.post('/scan', (req, res) => {
                const { field, value } = req.body;
                const params = {
                  FilterExpression: `#${field} = :v`,
                  ExpressionAttributeNames: { '#f': 'name' },
                  ExpressionAttributeValues: { ':v': value },
                };
                client.scan(params, () => res.end());
              });
              app.post('/safe', (req, res) => {
                client.query({ TableName: 'users', KeyConditionExpression: 'id = :id',
                               ExpressionAttributeValues: { ':id': req.body.id } }, () => res.end());
              });
              app.post('/table', (req, res) => client.getItem({ TableName: req.query.t, Key: {} }, () => res.end()));
            };
        """}
        self.assertEqual(self.flows(files, "db.js"), [("nosql_expr", 7), ("nosql_expr", 17)])

    def test_dynamo_keys_without_aws_sdk_are_ignored(self):
        files = {"x.js": """
            module.exports = (app) => app.post('/p', (req, res) => {
              const policy = { Statement: [req.body.s], TableName: req.body.t };
              res.json(policy);
            });
        """}
        self.assertEqual([f for f in self.flows(files, "x.js") if f[0] == "nosql_expr"], [])


class PythonRound14Tests(unittest.TestCase):
    def test_chalice_request_and_event_sources(self):
        results = _py({"app.py": """
            from chalice import Chalice
            from json import loads
            import yaml
            import pymysql

            app = Chalice(app_name="x")
            db = pymysql.connect()

            @app.route("/up", methods=["POST"])
            def up():
                return str(yaml.load(app.current_request.raw_body))

            @app.on_sns_message(topic="t")
            def react(event):
                data = loads(event.message)
                db.cursor().execute("INSERT INTO t VALUES ('%s', %s)" % (event.subject, data["r"]))

            @app.route("/echo/{name}")
            def echo(name):
                return "<b>" + name + "</b>"

            @app.schedule("rate(1 hour)")
            def tick(event):
                db.cursor().execute("DELETE FROM t WHERE x = '%s'" % event.time)
        """})
        self.assertEqual(sorted((f.sink_kind, f.line) for f in results["app.py"].flows),
                         [("deserialize", 11), ("sql", 16)])

    def test_boto3_dynamo_expression_and_table(self):
        results = _py({"app.py": """
            import boto3
            from boto3.dynamodb.conditions import Key
            from flask import request

            client = boto3.client("dynamodb")
            table = boto3.resource("dynamodb").Table("t")

            def a():
                body = request.get_json()
                client.scan(TableName=body["db"], ScanFilter={
                    body["field"]: {"AttributeValueList": [{"S": body["term"]}], "ComparisonOperator": body["op"]}})

            def b():
                table.scan(FilterExpression="name = " + request.args["n"])

            def c():
                table.query(KeyConditionExpression=Key("id").eq(request.args["id"]))
                client.execute_statement(Statement="SELECT * FROM t WHERE id = ?",
                                         Parameters=[{"S": request.args["id"]}])

            def d():
                client.execute_statement(Statement=f"SELECT * FROM t WHERE id = '{request.args['id']}'")
        """})
        self.assertEqual(sorted((f.sink_kind, f.line) for f in results["app.py"].flows),
                         [("nosql_expr", 10), ("nosql_expr", 14), ("nosql_expr", 22)])


if __name__ == "__main__":
    unittest.main()
