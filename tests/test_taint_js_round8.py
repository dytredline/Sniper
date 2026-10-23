"""JS/TS taint motoru (8. tur): döngü/geri çağrı kapları, NoSQL alıcı türü çıkarımı, değerle taşınan
güvenli URL öneki, TS tür açıklamaları ve Angular şablonları. Her yetenek için olumlu ve olumsuz örnek."""
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import taint_angular
import taint_js_ast
from tests.test_taint_js_ast import NODE_ENV


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsRound8Tests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def project(self, files, templates=None):
        results = taint_js_ast.analyze_files({k: _src(v) for k, v in files.items()},
                                             templates={k: _src(v) for k, v in (templates or {}).items()})
        self.assertIsNotNone(results)
        return results

    def sinks(self, source, filename="a.js"):
        results = self.project({filename: source})
        self.assertIn(filename, results, "ayrıştırılamadı")
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows})

    # -- 1: döngü ve geri çağrı kapları --------------------------------------------------
    def test_callback_writes_reach_outer_containers(self):
        self.assertEqual(self.sinks("""
            app.post('/a', (req, res) => {
              const out = [];
              req.body.items.forEach((it) => { out.push(it); });
              exec(out[0]);
              const o = {};
              Object.entries(req.body).forEach(([k, v]) => { o[k] = v; });
              exec(o.x);
              const safe = [];
              ['a', 'b'].forEach((x) => safe.push(x));
              exec(safe[0]);
              const local = [];
              req.body.items.forEach((it) => { const tmp = []; tmp.push(it); });
              exec(local.join(''));
              const nums = [];
              req.body.items.forEach((it) => nums.push(parseInt(it, 10)));
              exec(nums.join(''));
            });
        """), [("command", 4), ("command", 7)])

    def test_loop_carried_values_reach_fixed_point(self):
        self.assertEqual(self.sinks("""
            app.get('/a', (req, res) => {
              let a = 'x', b = 'x', c = 'x', d = 'x';
              for (let i = 0; i < 9; i++) { d = c; c = b; b = a; a = req.query.z; }
              exec(c);
              exec(d);
              const m = {};
              for (const k in req.query) { m[k] = req.query[k]; }
              exec(m.a);
              const keep = [];
              for (const k of ['a', 'b']) { keep.push(k); }
              exec(keep.join(' '));
            });
        """), [("command", 4), ("command", 5), ("command", 8)])

    # -- 2: NoSQL alıcı türü çıkarımı -------------------------------------------------------
    def test_nosql_receiver_inferred_across_files(self):
        results = self.project({
            "models/user.js": """
                const mongoose = require('mongoose');
                module.exports = mongoose.model('User', new mongoose.Schema({ name: String }));
            """,
            "models/account.ts": """
                import { Schema, model } from 'mongoose';
                export default model('Account', new Schema({ a: String }));
            """,
            "data/mongodb.ts": """
                import * as MarsDB from 'marsdb';
                export const reviewsCollection = new MarsDB.Collection('posts');
                export const cache = new Map();
            """,
            "services/Cache.js": """
                class Cache { static find(key) { return key; } }
                module.exports = Cache;
            """,
            "routes.js": """
                const User = require('./models/user');
                const Cache = require('./services/Cache');
                import Account from './models/account';
                const Lodash = require('lodash');
                import * as db from './data/mongodb';
                app.post('/login', async (req, res) => {
                  await User.findOne({ username: req.body.username });
                  await Account.find(req.body);
                  Cache.find(req.body.k);
                  Lodash.find(req.body.list, req.body.pred);
                  await Account.find({ name: req.params.id });
                  await Account.find({ name: String(req.body.name) });
                  db.reviewsCollection.update({ _id: req.body.id }, { $set: { m: 1 } });
                  db.cache.delete(req.body.k);
                });
            """,
        })
        self.assertEqual(sorted((f.sink_kind, f.line) for f in results["routes.js"].flows), [("nosql", 7), ("nosql", 8), ("nosql", 13)])

    def test_nosql_typed_receivers_and_sql_orm_projects(self):
        results = self.project({
            "svc.ts": """
                import { Repository } from 'typeorm';
                import { Collection } from 'mongodb';
                import { InjectModel } from '@nestjs/mongoose';
                export class Svc {
                  constructor(private readonly repo: Repository<User>, private users: Collection<User>,
                              @InjectModel('U') private um: any) {}
                  @Post() a(@Body() body: any) { return this.repo.find(body); }
                  @Post() b(@Body() body: any) { return this.users.find(body); }
                  @Post() c(@Body() body: any) { return this.um.findOne(body); }
                }
            """,
        })
        self.assertEqual(sorted((f.sink_kind, f.line) for f in results["svc.ts"].flows), [("nosql", 8), ("nosql", 9)])
        # Yalnız SQL ORM'li projede (MongoDB kitaplığı yok) ada dayalı model sezgisi kapalı.
        results = self.project({
            "db.js": "const { Sequelize } = require('sequelize');\nmodule.exports = new Sequelize('sqlite::memory:');\n",
            "r.js": "app.post('/a', async (req, res) => { await Product.findOne(req.body); });\n",
        })
        self.assertEqual(results["r.js"].flows, [])

    # -- 3: güvenli URL öneki değerle ve parametreyle taşınır ------------------------------
    def test_safe_url_prefix_travels_through_values_and_parameters(self):
        self.assertEqual(self.sinks("""
            function go(res, url) { res.redirect(url); }
            function build(p) { return '/app/' + p; }
            function buildBad(p) { return p + '/x'; }
            function fetchIt(u) { return axios.get(u); }
            function wrap(res, p) { go(res, '/home/' + p); }
            app.get('/a', (req, res) => {
              go(res, '/app/' + req.query.p);
              go(res, req.query.p);
              res.redirect(build(req.query.p));
              res.redirect(buildBad(req.query.p));
              const u = `/x/${req.query.p}`;
              res.redirect(u);
              let v = '/x/';
              v += req.query.p;
              res.redirect(v);
              fetchIt('https://api.example.com/' + req.query.p);
              fetchIt(req.query.p);
              wrap(res, req.query.q);
              go(res, '//' + req.query.p);
            });
        """), [("redirect", 1), ("redirect", 10), ("ssrf", 4)])
        results = self.project({"a.js": """
            function go(res, url) { res.redirect(url); }
            app.get('/a', (req, res) => {
              go(res, '/app/' + req.query.p);
              go(res, req.query.p);
              go(res, '//' + req.query.p);
            });
        """})
        self.assertEqual(sorted(f.source_line for f in results["a.js"].flows), [4, 5])

    def test_safe_prefix_requires_all_branches(self):
        self.assertEqual(self.sinks("""
            app.get('/a', (req, res) => {
              let u = CONFIG.base;
              if (req.query.c) { u = '/x/'; }
              u += req.query.p;
              res.redirect(u);
              let v = '/ok/';
              if (req.query.c) { v += req.query.a; } else { v += 'z'; }
              res.redirect(v);
              let w = '/';
              w += req.query.p;
              res.redirect(w);
            });
        """), [("redirect", 5), ("redirect", 11)])

    # -- 4: TS tür açıklamaları ---------------------------------------------------------
    def test_typescript_request_response_and_casts(self):
        results = self.project({
            "svc.ts": """
                import { Request } from 'express';
                import { Repository } from 'typeorm';
                export class Runner { run(cmd: string) { exec(cmd); } }
                export class UserService {
                  constructor(private readonly repo: Repository<User>) {}
                  byName(r: Request) {
                    const name = r.query.name as string;
                    return this.repo.createQueryBuilder('u').where("u.name = '" + name + "'").getMany();
                  }
                  safe(r: Request) {
                    return this.repo.createQueryBuilder('u').where('u.name = :n', { n: r.query.name }).getMany();
                  }
                }
            """,
            "next.ts": """
                import type { NextApiRequest, NextApiResponse } from 'next';
                export default function handler(rq: NextApiRequest, rs: NextApiResponse) { rs.redirect(rq.query.to as string); }
            """,
            "app/api/x/route.ts": """
                export async function POST(request: Request) { const b = await request.json(); exec(b.cmd); }
            """,
            "browser.ts": """
                function send(r: Request) { return fetch(r.url); }
            """,
            "routes.ts": """
                import { Runner } from './svc';
                app.get('/a', (req, res) => {
                  (container.get('runner') as Runner).run(req.query.c);
                  const r2: Runner = container.get('runner');
                  r2.run(req.query.b);
                });
            """,
        })
        flows = {name: sorted({(f.sink_kind, f.line) for f in analysis.flows}) for name, analysis in results.items()}
        self.assertEqual(flows["svc.ts"], [("command", 3), ("sql", 8)])
        self.assertEqual(flows["next.ts"], [("redirect", 2)])
        self.assertEqual(flows["app/api/x/route.ts"], [("command", 1)])
        self.assertEqual(flows["browser.ts"], [])
        sources = sorted(f.source_line for f in results["svc.ts"].flows if f.source_file == "routes.ts")
        self.assertEqual(sources, [3, 5])

    # -- 5: Angular şablonları ------------------------------------------------------------
    def test_angular_template_bindings(self):
        results = self.project({
            "src/app/search.component.ts": """
                import { Component } from '@angular/core';
                @Component({ selector: 'app-s', templateUrl: './search.component.html' })
                export class SearchComponent {
                  q: any;
                  trusted: any;
                  fromApi: any;
                  plain = 'hello';
                  items: any[] = [];
                  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer, private http: HttpClient) {}
                  ngOnInit() {
                    this.q = this.route.snapshot.queryParams.q;
                    this.route.queryParams.subscribe((p) => { this.trusted = this.sanitizer.bypassSecurityTrustHtml(p.x); });
                    this.http.get('/api/x').subscribe((data: any) => { this.fromApi = data.html; this.items = data.items; });
                  }
                  getHtml() { return this.q + '<b>'; }
                }
            """,
            "src/app/inline.component.ts": """
                @Component({
                  selector: 'app-i',
                  template: `<div>
                    <p [innerHTML]="msg"></p>
                  </div>`,
                })
                export class InlineComponent { msg = location.hash.substring(1); }
            """,
        }, templates={
            "src/app/search.component.html": """
                <p [innerHTML]="q"></p>
                <p [innerHTML]="trusted"></p>
                <p [innerHTML]="plain"></p>
                <p [innerHTML]="q | safeHtml"></p>
                <p [innerHtml]="getHtml()"></p>
                <span>{{ q }}</span>
                <li *ngFor="let it of items"><span [innerHTML]="it.body | safeHtml"></span></li>
                <div [innerHTML]="fromApi"></div>
            """,
        })
        flows = sorted((f.sink_kind, f.line, f.source_label, f.sink) for f in results["src/app/search.component.ts"].flows)
        self.assertEqual(flows, [
            ("angular_html", 4, "request", "[innerHTML] (src/app/search.component.html:1)"),
            ("angular_html", 6, "stored", "[innerHTML] (src/app/search.component.html:8)"),
            ("angular_html", 15, "request", "[innerHtml] (src/app/search.component.html:5)"),
            ("html", 4, "request", "[innerHTML] (src/app/search.component.html:4)"),
            ("html", 8, "stored", "[innerHTML] (src/app/search.component.html:7)"),
            ("html", 12, "request", "this.sanitizer.bypassSecurityTrustHtml"),
        ])
        inline = [(f.sink_kind, f.line, f.sink) for f in results["src/app/inline.component.ts"].flows]
        self.assertEqual(inline, [("angular_html", 7, "[innerHTML] (satır içi şablon:4)")])


class AngularTemplateParsingTests(unittest.TestCase):
    def test_bindings_pipes_aliases_and_interpolation(self):
        text = _src("""
            <a [href]="url"></a>
            <p [innerHTML]="a.b | safeHtml: 'x' | other"></p>
            <p bind-innerHTML="c || d"></p>
            <p innerHTML="{{ e }}"></p>
            <iframe [srcdoc]="this.f"></iframe>
            <li *ngFor="let x of xs; let i = index"><b [innerHTML]="x.body"></b></li>
        """)
        bindings = [(b.prop, b.root, b.call, b.pipes, b.line) for b in taint_angular.html_bindings(text)]
        self.assertEqual(bindings, [
            ("innerHTML", "a", False, ("safeHtml", "other"), 2),
            ("innerHTML", "c", False, (), 3),
            ("innerHTML", "e", False, (), 4),
            ("srcdoc", "f", False, (), 5),
            ("innerHTML", "xs", False, (), 6),
        ])

    def test_template_path_stays_inside_project(self):
        self.assertEqual(taint_angular.resolve_template_path("src/app/a.component.ts", "./a.component.html"),
                         "src/app/a.component.html")
        self.assertEqual(taint_angular.resolve_template_path("src/app/a.ts", "../shared/x.html"), "src/shared/x.html")
        self.assertIsNone(taint_angular.resolve_template_path("a.ts", "../../etc/passwd.html"))
        self.assertIsNone(taint_angular.resolve_template_path("a.ts", "/etc/x.html"))
        self.assertIsNone(taint_angular.resolve_template_path("a.ts", "./x.js"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "p"
            root.mkdir()
            (root / "ok.html").write_text("<p [innerHTML]='x'></p>", encoding="utf-8")
            outside = Path(tmp) / "secret.html"
            outside.write_text("gizli", encoding="utf-8")
            (root / "link.html").symlink_to(outside)
            self.assertEqual(taint_angular.read_template(root, "ok.html"), "<p [innerHTML]='x'></p>")
            self.assertIsNone(taint_angular.read_template(root, "link.html"))
            self.assertIsNone(taint_angular.read_template(root, "missing.html"))


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class AngularProjectScanTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_project_scan_reads_template_url_and_reports_low_severity(self):
        from project_analyzer import analyze_project

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "p"
            (root / "src").mkdir(parents=True)
            (root / "src" / "x.component.ts").write_text(
                "@Component({ selector: 'x', templateUrl: './x.component.html' })\n"
                "export class X {\n"
                "  html: any;\n"
                "  constructor(private route: ActivatedRoute) {}\n"
                "  ngOnInit() { this.html = this.route.snapshot.queryParams.h; }\n"
                "}\n", encoding="utf-8")
            (root / "src" / "x.component.html").write_text('<div [innerHTML]="html"></div>\n', encoding="utf-8")
            findings = analyze_project(str(root), allowed_roots=(root.parent,))["findings"]
        flows = [(f["file"], f["line"], f["severity"], f["reference"]) for f in findings if f.get("taint_flow")]
        self.assertEqual(flows, [("src/x.component.ts", 3, "low", "CWE-79")])


if __name__ == "__main__":
    unittest.main()
