"""JS/TS taint (11. tur): GraphQL resolver birleştirme (mergeResolvers, resolvers dizisi), serverless.ts ve
AWS CDK handler eşlemesi, Angular @Input alanlarının ebeveyn şablonundan beslenmesi. Olumlu ve olumsuz örnekler."""
import os
import textwrap
import unittest
from unittest import mock

import taint_js_ast
from tests.test_taint_js_ast import NODE_ENV


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsRound11Tests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def project(self, files, templates=None):
        results = taint_js_ast.analyze_files({k: _src(v) for k, v in files.items()},
                                             templates={k: _src(v) for k, v in (templates or {}).items()})
        self.assertIsNotNone(results)
        return results

    def sinks(self, files, filename, templates=None, label="request"):
        results = self.project(files, templates)
        self.assertIn(filename, results, "ayrıştırılamadı")
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows if label is None or f.source_label == label})

    # -- GraphQL: mergeResolvers / resolvers dizisi -------------------------------------
    def test_merge_resolvers_marks_type_maps_without_root_keys(self):
        files = {
            "src/user.resolvers.js": """
                const { exec } = require('child_process');
                module.exports = {
                  User: {
                    avatar: (parent, args) => exec('convert ' + args.name),
                  },
                };
            """,
            "src/post.resolvers.js": """
                const { exec } = require('child_process');
                const postResolvers = { Post: { render: (parent, args) => exec(args.cmd) } };
                module.exports = postResolvers;
            """,
            "src/index.js": """
                const { mergeResolvers } = require('@graphql-tools/merge');
                const userResolvers = require('./user.resolvers');
                const postResolvers = require('./post.resolvers');
                const resolvers = mergeResolvers([userResolvers, postResolvers]);
                module.exports = resolvers;
            """,
        }
        self.assertEqual(self.sinks(files, "src/user.resolvers.js"), [("command", 4)])
        self.assertEqual(self.sinks(files, "src/post.resolvers.js"), [("command", 2)])

    def test_resolvers_array_in_server_config(self):
        files = {
            "a.js": """
                const { exec } = require('child_process');
                const extra = { Item: { run: (parent, args) => exec(args.c) } };
                const server = new ApolloServer({ typeDefs, resolvers: [extra] });
            """,
        }
        self.assertEqual(self.sinks(files, "a.js"), [("command", 2)])

    def test_merge_negatives(self):
        files = {
            "a.js": """
                const { exec } = require('child_process');
                const helpers = { Util: { run: (parent, args) => exec(args.c) } };
                const merged = Object.assign({}, helpers);
                const config = { resolvers: [helpers] };
                lodashMerge([helpers]);
            """,
        }
        # typeDefs/schema olmayan { resolvers } ya da birleştirme dışı çağrılar çözücü haritası değildir.
        self.assertEqual(self.sinks(files, "a.js"), [])

    # -- serverless.ts / AWS CDK -----------------------------------------------------------
    def test_serverless_ts_and_function_config(self):
        files = {
            "serverless.ts": """
                import type { AWS } from '@serverless/typescript';
                const config: AWS = { service: 'x', functions: { admin: { handler: 'src/admin.run' } } };
                export default config;
            """,
            "src/admin.ts": """
                export const run = async (payload: any) => { eval(payload.body); };
                export const other = async (payload: any) => { eval(payload.body); };
            """,
            "src/functions/hello/index.ts": """
                import { handlerPath } from '@libs/handler-resolver';
                export default { handler: `${handlerPath(__dirname)}/handler.main`, events: [{ http: { method: 'post' } }] };
            """,
            "src/functions/hello/handler.ts": """
                export const main = async (input: any) => { eval(input.body); };
            """,
        }
        self.assertEqual(self.sinks(files, "src/admin.ts"), [("eval", 1)])
        self.assertEqual(self.sinks(files, "src/functions/hello/handler.ts"), [("eval", 1)])

    def test_cdk_function_and_nodejs_function(self):
        files = {
            "lib/stack.ts": """
                import * as lambda from 'aws-cdk-lib/aws-lambda';
                import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
                import * as path from 'path';
                new lambda.Function(this, 'A', { runtime: lambda.Runtime.NODEJS_20_X, handler: 'index.process',
                  code: lambda.Code.fromAsset(path.join(__dirname, '../functions/a')) });
                new NodejsFunction(this, 'B', { entry: path.join(__dirname, '../functions/b/main.ts'), handler: 'go' });
                new NodejsFunction(this, 'C', { entry: 'functions/c/app.ts' });
            """,
            "functions/a/index.js": "exports.process = async (input) => { eval(input.body); };\n",
            "functions/b/main.ts": "export const go = async (input: any) => { eval(input.body); };\n",
            "functions/c/app.ts": "export const handler = async (msg: any) => { eval(msg.body); };\n",
        }
        self.assertEqual(self.sinks(files, "functions/a/index.js"), [("eval", 1)])
        self.assertEqual(self.sinks(files, "functions/b/main.ts"), [("eval", 1)])
        self.assertEqual(self.sinks(files, "functions/c/app.ts"), [("eval", 1)])

    def test_handler_mapping_negatives(self):
        files = {
            # CDK paketi olmadan `new Function(...)` ve serverless dosyası olmayan nesnedeki handler eşleme değildir.
            "lib/other.ts": """
                new Function(this, 'A', { handler: 'index.process', code: Code.fromAsset('functions/a') });
                const settings = { handler: 'functions/b/main.go' };
            """,
            "functions/a/index.js": "exports.process = async (input) => { eval(input.body); };\n",
            "functions/b/main.ts": "export const go = async (input: any) => { eval(input.body); };\n",
            # Kök dışına çıkan yol yok sayılır.
            "serverless.ts": "export default { functions: { x: { handler: '../../outside.run' } } };\n",
        }
        self.assertEqual(self.sinks(files, "functions/a/index.js"), [])
        self.assertEqual(self.sinks(files, "functions/b/main.ts"), [])

    # -- Angular @Input ------------------------------------------------------------------
    def test_angular_input_fed_by_parent_binding(self):
        files = {
            "src/app/page.component.ts": """
                import { Component } from '@angular/core';
                @Component({ selector: 'app-page', templateUrl: './page.component.html' })
                export class PageComponent {
                  q: any;
                  safe = 'merhaba';
                  constructor(private route: ActivatedRoute) {}
                  ngOnInit() { this.q = this.route.snapshot.queryParams.q; }
                }
            """,
            "src/app/card.component.ts": """
                import { Component, Input } from '@angular/core';
                @Component({ selector: 'app-card', template: '<div [innerHTML]="body"></div><p [innerHTML]="title"></p>' })
                export class CardComponent {
                  @Input() body: string;
                  @Input('heading') title: string;
                }
            """,
            "src/app/note.component.ts": """
                import { Component, Input, input } from '@angular/core';
                @Component({ selector: 'app-note', template: '<p [innerHTML]="text()"></p><i [innerHTML]="shown"></i>' })
                export class NoteComponent {
                  text = input<string>();
                  shown: string;
                  @Input() set raw(v: string) { this.shown = v; }
                }
            """,
        }
        templates = {
            "src/app/page.component.html": """
                <app-card [body]="q" [heading]="safe"></app-card>
                <app-note [text]="q" [raw]="q"></app-note>
            """,
        }
        results = self.project(files, templates)
        card = sorted((f.sink_kind, f.line, f.source_label) for f in results["src/app/card.component.ts"].flows)
        self.assertEqual(card, [("angular_html", 4, "request")])
        note = sorted((f.sink_kind, f.line, f.source_label) for f in results["src/app/note.component.ts"].flows)
        self.assertEqual(note, [("angular_html", 4, "request"), ("angular_html", 5, "request")])

    def test_angular_unbound_input_is_not_source(self):
        files = {
            "src/app/card.component.ts": """
                import { Component, Input } from '@angular/core';
                @Component({ selector: 'app-card', template: '<div [innerHTML]="body"></div>' })
                export class CardComponent { @Input() body: string; }
            """,
            "src/app/page.component.ts": """
                import { Component } from '@angular/core';
                @Component({ selector: 'app-page', template: '<app-card [body]="greeting"></app-card><app-cardx [body]="q"></app-cardx>' })
                export class PageComponent {
                  greeting = 'merhaba';
                  q = location.hash;
                }
            """,
        }
        results = self.project(files)
        self.assertEqual(results["src/app/card.component.ts"].flows, [])

    # -- Koşul döndüren dizi yöntemleri ve geri çağrı dönüşleri -----------------------------
    def test_predicate_callbacks_do_not_taint_result(self):
        files = {
            "a.js": """
                const { exec } = require('child_process');
                app.get('/x', (req, res) => {
                  const items = ['ls', 'pwd'];
                  const picked = items.filter((i) => req.query.flag);
                  exec(picked[0]);
                  const first = items.find((i) => req.query.flag);
                  exec(first);
                  const sorted = items.sort((a, b) => req.query.order);
                  exec(sorted[0]);
                  const mapped = items.map((i) => req.query.q + i);
                  exec(mapped[0]);
                  const own = req.query.list.filter((i) => i);
                  exec(own[0]);
                });
            """,
        }
        # map değer üretir; süzülen liste kendisi kirliyse (req.query.list) sonuç da kirlidir.
        self.assertEqual(self.sinks(files, "a.js"), [("command", 11), ("command", 13)])

    def test_callback_return_is_not_enclosing_function_return(self):
        files = {
            "a.js": """
                const { exec } = require('child_process');
                function pick(list, opts) {
                  list.forEach((x) => { return opts.cmd; });
                  return list.filter((x) => { return opts.show; });
                }
                function wrap(list, opts) { return list.map((x) => opts.cmd); }
                app.get('/x', (req, res) => {
                  exec(pick(['ls'], req.query)[0]);
                  exec(wrap(['ls'], req.query)[0]);
                });
            """,
        }
        # Geri çağrıdaki return dış fonksiyondan dönmez; map ise değeri sonuca taşır.
        self.assertEqual(self.sinks(files, "a.js"), [("command", 9)])

if __name__ == "__main__":
    unittest.main()
