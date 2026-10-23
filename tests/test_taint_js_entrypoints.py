"""JS/TS taint (9. tur): Express dışı giriş noktaları kaynak olarak — AWS Lambda/Netlify (event),
serverless.yml / SAM eşlemesi, Firebase/GCP/Azure/Vercel HTTP işlevleri ve GraphQL çözücüleri.
Her biri için olumlu ve olumsuz örnek."""
import os
import textwrap
import unittest
from unittest import mock

import taint_js_ast
from tests.test_taint_js_ast import NODE_ENV


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsEntrypointTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def project(self, files, configs=None):
        results = taint_js_ast.analyze_files({k: _src(v) for k, v in files.items()},
                                             templates={k: _src(v) for k, v in (configs or {}).items()})
        self.assertIsNotNone(results)
        return results

    def sinks(self, files, filename, configs=None):
        results = self.project(files, configs)
        self.assertIn(filename, results, "ayrıştırılamadı")
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows if f.source_label == "request"})

    # -- AWS Lambda / Netlify -----------------------------------------------------------
    def test_lambda_handler_event_is_source(self):
        self.assertEqual(self.sinks({"order.js": """
            const serialize = require('node-serialize');
            const { exec } = require('child_process');
            exports.handler = async (event, context) => {
              const req = serialize.unserialize(event.body);
              exec('ls ' + event.queryStringParameters.dir);
              eval(context.functionName);
              return { statusCode: 200 };
            };
        """}, "order.js"), [("command", 5), ("deserialize", 4)])

    def test_lambda_variants_esm_ts_and_records(self):
        self.assertEqual(self.sinks({"h.ts": """
            import { exec } from 'child_process';
            import type { APIGatewayProxyEvent, APIGatewayProxyHandler } from 'aws-lambda';
            export async function handler(evt) { exec(evt.pathParameters.id); }
            export const typed: APIGatewayProxyHandler = async (input) => { exec(input.headers.h); return null; };
            export const byType = async (input: APIGatewayProxyEvent) => { exec(input.body); };
            module.exports.queue = async (event) => { for (const r of event.Records) exec(r.body); };
        """}, "h.ts"), [("command", 3), ("command", 4), ("command", 5)])

    def test_serverless_yml_and_sam_mapping(self):
        files = {
            "src/fns/admin.js": """
                module.exports.run = async (payload) => { eval(payload.body); };
                module.exports.other = async (payload) => { eval(payload.body); };
            """,
            "hello-world/app.mjs": """
                export const lambdaHandler = async (input, ctx) => { eval(input.body); };
            """,
        }
        configs = {
            "serverless.yml": "functions:\n  admin:\n    handler: src/fns/admin.run\n",
            "template.yaml": "Resources:\n  Fn:\n    Properties:\n      CodeUri: hello-world/\n      Handler: app.lambdaHandler\n",
        }
        self.assertEqual(self.sinks(files, "src/fns/admin.js", configs), [("eval", 1)])
        self.assertEqual(self.sinks(files, "hello-world/app.mjs", configs), [("eval", 1)])

    def test_lambda_negatives(self):
        self.assertEqual(self.sinks({"lib.js": """
            const { exec } = require('child_process');
            exports.handler = (req, res) => { exec(req.cmd); };
            exports.process = async (event) => { exec(event.body); };
            function handler(event) { exec(event.body); }
            exports.cleanHandler = async (event) => { exec('ls ' + parseInt(event.body, 10)); };
        """}, "lib.js"), [])

    # -- Firebase / GCP / Azure / Vercel -----------------------------------------------
    def test_firebase_gcp_azure_vercel(self):
        files = {
            "fb.js": """
                const functions = require('firebase-functions');
                const { exec } = require('child_process');
                exports.api = functions.https.onRequest((req, res) => { exec(req.query.c); });
                exports.call = functions.https.onCall((data, context) => { exec(data.c); exec(context.auth.uid); });
            """,
            "gcp.js": """
                const ff = require('@google-cloud/functions-framework');
                const { exec } = require('child_process');
                ff.http('run', (req, res) => { exec(req.body.c); });
            """,
            "az3/index.js": """
                const { exec } = require('child_process');
                module.exports = async function (context, req) { exec(req.query.c); exec(context.invocationId); };
            """,
            "az4.js": """
                const { app } = require('@azure/functions');
                const { exec } = require('child_process');
                app.http('run', { methods: ['POST'], handler: async (request, context) => { exec(request.query.get('c')); } });
            """,
            "pages/api/run.js": """
                const { exec } = require('child_process');
                export default function handler(req, res) { exec(req.query.c); }
            """,
        }
        results = self.project(files)
        got = {name: sorted({(f.sink_kind, f.line) for f in a.flows if f.source_label == "request"})
               for name, a in results.items()}
        self.assertEqual(got["fb.js"], [("command", 3), ("command", 4)])
        self.assertEqual(got["gcp.js"], [("command", 3)])
        self.assertEqual(got["az3/index.js"], [("command", 2)])
        self.assertEqual(got["az4.js"], [("command", 3)])
        self.assertEqual(got["pages/api/run.js"], [("command", 2)])

    def test_serverless_negatives_without_packages(self):
        self.assertEqual(self.sinks({"x.js": """
            const { exec } = require('child_process');
            const bus = require('./bus');
            bus.onRequest((msg) => { exec(msg.c); });
            bus.onCall((data) => { exec(data.c); });
            module.exports = async function (opts, cfg) { exec(cfg.c); };
        """}, "x.js"), [])

    # -- GraphQL ------------------------------------------------------------------------
    def test_apollo_resolver_map_args(self):
        files = {
            "resolvers/user.js": """
                const { exec } = require('child_process');
                const userQueries = {
                  user: async (_, { id }) => { exec('id ' + id); },
                };
                module.exports = { userQueries };
            """,
            "resolvers/index.js": """
                const { userQueries } = require('./user');
                const db = require('../db');
                const { exec } = require('child_process');
                module.exports = {
                  Query: {
                    ...userQueries,
                    search(parent, args, ctx) { return db.sequelize.query('SELECT * FROM p WHERE t = ' + args.term); },
                    stats: (parent) => { exec(parent.cmd); },
                  },
                  Mutation: {
                    run: { resolve: (_, args) => exec(args.cmd) },
                  },
                  Post: { comments: (post, args) => exec(args.filter) },
                };
            """,
        }
        results = self.project(files)
        got = {name: sorted({(f.sink_kind, f.line) for f in a.flows if f.source_label == "request"})
               for name, a in results.items()}
        self.assertEqual(got["resolvers/index.js"], [("command", 11), ("command", 13), ("sql", 7)])
        self.assertEqual(got["resolvers/user.js"], [("command", 3)])

    def test_graphql_js_resolve_root_value_and_decorators(self):
        self.assertEqual(self.sinks({"schema.ts": """
            import { GraphQLObjectType, GraphQLString } from 'graphql';
            import { graphqlHTTP } from 'express-graphql';
            import { Resolver, Query, Arg } from 'type-graphql';
            import { exec } from 'child_process';
            const QueryType = new GraphQLObjectType({ name: 'Q', fields: {
              ping: { type: GraphQLString, args: { host: { type: GraphQLString } }, resolve: (src, args) => exec('ping ' + args.host) },
              safe: { type: GraphQLString, resolve: (src) => exec(src.cmd) },
            } });
            const root = { hello: ({ name }) => exec(name) };
            app.use('/g', graphqlHTTP({ schema, rootValue: root }));
            @Resolver()
            class R {
              @Query(() => String)
              run(@Arg('cmd') cmd: string, other: string) { exec(cmd); exec(other); return ''; }
            }
        """}, "schema.ts"), [("command", 6), ("command", 9), ("command", 14)])

    def test_graphql_negative_plain_objects(self):
        self.assertEqual(self.sinks({"cfg.js": """
            const { exec } = require('child_process');
            const handlers = { list: (_, args) => exec(args.cmd) };
            const cache = { Queries: { get: (_, args) => exec(args.k) } };
            module.exports = { handlers, cache };
        """}, "cfg.js"), [])


    # -- çağıranı olmayan dışa aktarmalar: hotspot "ulaşılamıyor" sayılmaz ---------------
    def test_uncalled_exported_param_sinks_are_uncertain(self):
        results = self.project({"lib.js": """
            const { exec } = require('child_process');
            module.exports.run = (input) => { exec(input.cmd); };
            function inner(x) { exec(x); }
            inner('ls');
            module.exports.fixed = () => { exec('uptime'); };
        """})
        analysis = results["lib.js"]
        self.assertFalse(analysis.is_unreached_sink("command", 2))
        self.assertTrue(analysis.is_unreached_sink("command", 3))
        self.assertTrue(analysis.is_unreached_sink("command", 5))


    def test_url_part_of_parameter_does_not_crash_summary(self):
        # u.searchParams / u.search parametre kökeninde: eskiden int('0.searchParams') ile tüm analiz çöküyordu.
        self.assertEqual(self.sinks({"a.js": """
            const { exec } = require('child_process');
            function run(u) { exec(u.searchParams.get('c')); exec(u.search); }
            class S { constructor(u) { this.u = u; } go() { exec(this.u.hash); } }
            app.get('/x', (req, res) => { run(new URL(req.url, 'http://h')); new S(new URL(req.query.u)).go(); });
        """}, "a.js"), [("command", 2), ("command", 3)])


if __name__ == "__main__":
    unittest.main()
