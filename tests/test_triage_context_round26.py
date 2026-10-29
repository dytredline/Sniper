"""Triyaj paketi bağlamı (26. tur): bulgu başına isteğe bağlı ``context`` alanı.

Kör değerlendirmede ajanların yanıldığı üç boşluk: (1) kesitte import satırları yok (Go text/template ↔ html/template),
(2) ``render_template("shop/search.html", q=q)`` ile adı geçen şablon pakette yok (``{{ q|safe }}``), (3) kayıtlı
verinin yazıldığı yer görünmüyor. Testler olumlu/olumsuz örnekleri, proje kökü dışına çıkmayı (.., mutlak yol, sembolik
bağ), boyut sınırını, sır maskelemeyi, yorum çıkarmayı, paket/MCP/CLI/ölçüm betiği yollarını sınar.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import ai_triage as at
import mcp_triage_server
from storage import Store
import triage_context as tc
from tests.test_finding_tracking_collab import make_audit

APP = Path(__file__).resolve().parents[1]
AI_TRIAGE_EVAL = APP / "scripts" / "ai_triage_eval.py"
SECRET = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA"

FLASK_VIEW = (
    "from flask import Flask, request, render_template\n"
    "from markupsafe import Markup\n"
    "app = Flask(__name__)\n"
    "\n"
    "@app.route('/search')\n"
    "def search():\n"
    "    q = request.args.get('q', '')\n"
    "    return render_template('shop/search.html', q=q, items=[])\n"
    "\n"
    "def plain():\n"
    "    return 'merhaba'\n"
)
SEARCH_TEMPLATE = (
    "{% extends 'base.html' %}\n"
    "<h1>Arama</h1>\n"
    "<p class='x'>\n"
    "{{ q|safe }}\n"
    "</p>\n"
    "<footer>sabit</footer>\n"
    "<div>a</div>\n<div>b</div>\n<div>c</div>\n"
    "{% for i in items %}{{ i }}{% endfor %}\n"
)
GO_TEXT = (
    "package main\n\n"
    "import (\n"
    "\t\"net/http\"\n"
    "\t\"text/template\"\n"
    ")\n\n"
    "func h(w http.ResponseWriter, r *http.Request) {\n"
    "\tt := template.Must(template.New(\"x\").Parse(\"<p>{{.}}</p>\"))\n"
    "\tt.Execute(w, r.URL.Query().Get(\"q\"))\n"
    "}\n"
)


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        self.root.mkdir()
        env = mock.patch.dict(os.environ, {tc.CONTEXT_ENV: ""})
        env.start()
        self.addCleanup(env.stop)

    def ctx(self, rel, line, **kw):
        return tc.finding_context(str(self.root), rel, line, **kw)


class ImportsTests(_Tmp):
    def test_go_template_package_is_visible(self):
        write(self.root, "main.go", GO_TEXT)
        context = self.ctx("main.go", 10)
        lines = context["imports"]["lines"]
        self.assertIn('5: \t"text/template"', lines)
        self.assertEqual(lines[0], "1: package main")
        self.assertIn("6: )", lines)
        write(self.root, "safe.go", GO_TEXT.replace("text/template", "html/template"))
        self.assertIn('5: \t"html/template"', self.ctx("safe.go", 10)["imports"]["lines"])

    def test_languages(self):
        cases = {
            "a.py": ("import os\nfrom markupsafe import (\n    Markup,\n    escape)\nx = 1\n", ["2: from markupsafe import (", "3:     Markup,"]),
            "A.java": ("package x.y;\nimport org.owasp.encoder.Encode;\nclass A {}\n", ["2: import org.owasp.encoder.Encode;"]),
            "a.php": ("<?php\nnamespace App;\nuse Illuminate\\Support\\HtmlString;\necho 1;\n", ["3: use Illuminate\\Support\\HtmlString;"]),
            "app.rb": ("require 'sinatra'\nclass App < Sinatra::Base\nend\n", ["1: require 'sinatra'", "2: class App < Sinatra::Base"]),
            "a.cs": ("using System.Web;\nusing Microsoft.AspNetCore.Html;\nnamespace N {}\n", ["2: using Microsoft.AspNetCore.Html;"]),
            "a.js": ("const express = require('express');\nimport { x } from './y';\nfoo();\n", ["1: const express = require('express');"]),
            "t.html": ("{% extends 'b.html' %}\n{% autoescape false %}\n{{ x }}\n{% endautoescape %}\n", ["2: {% autoescape false %}"]),
        }
        for rel, (text, expected) in cases.items():
            write(self.root, rel, text)
            lines = self.ctx(rel, 3)["imports"]["lines"]
            for item in expected:
                self.assertIn(item, lines, rel)

    def test_no_imports_no_context(self):
        write(self.root, "plain.py", "x = 1\ny = 2\n")
        self.assertIsNone(self.ctx("plain.py", 2))
        self.assertIsNone(self.ctx("yok.py", 2))
        self.assertIsNone(tc.finding_context("goreli/yol", "plain.py", 1))


class TemplateTests(_Tmp):
    def setUp(self):
        super().setUp()
        write(self.root, "shop/views.py", FLASK_VIEW)
        write(self.root, "shop/templates/shop/search.html", SEARCH_TEMPLATE)

    def test_named_template_variable_lines(self):
        context = self.ctx("shop/views.py", 8)
        [entry] = context["templates"]
        self.assertEqual(entry["file"], "shop/templates/shop/search.html")
        self.assertEqual((entry["name"], entry["referenced_at"], entry["basis"]), ("shop/search.html", 8, "variables"))
        self.assertEqual(entry["variables"][:2], ["q", "items"])
        texts = "\n".join(e["text"] for e in entry["excerpts"])
        self.assertIn("{{ q|safe }}", texts)
        self.assertIn("{% for i in items %}", texts)
        first = entry["excerpts"][0]
        self.assertEqual((first["start_line"], first["end_line"]), (2, 6))  # satır 4 ±2
        self.assertNotIn("<div>a</div>", texts)  # değişken satırlarından uzak satır (7) yok
        self.assertEqual([(e["start_line"], e["end_line"]) for e in entry["excerpts"]], [(2, 6), (8, 10)])

    def test_template_named_only_in_snippet_and_negative(self):
        # Bulgu satırı şablonu anmasa da kesitte (±12) adı geçiyorsa bağlam üretilir.
        self.assertIn("templates", self.ctx("shop/views.py", 11))
        write(self.root, "other.py", "x = 1\n" * 40 + "y = render_template('shop/search.html', q=q)\n")
        self.assertNotIn("templates", self.ctx("other.py", 3) or {})  # şablon kesit dışında

    def test_fallback_unescaped_lines_and_frameworks(self):
        write(self.root, "views/index.ejs", "<h1>x</h1>\n<p><%- body %></p>\n<p><%= safe %></p>\n")
        write(self.root, "routes.js", "const express = require('express');\nrouter.get('/', (req, res) => res.render('index', locals));\n")
        entry = self.ctx("routes.js", 2)["templates"][0]
        self.assertEqual((entry["file"], entry["basis"]), ("views/index.ejs", "unescaped_output"))
        self.assertIn("<%- body %>", entry["excerpts"][0]["text"])
        write(self.root, "resources/views/shop/search.blade.php", "<div>{!! $q !!}</div>\n")
        write(self.root, "app/Http/C.php", "<?php\nreturn view('shop.search', compact('q'));\n")
        entry = self.ctx("app/Http/C.php", 2)["templates"][0]
        self.assertEqual((entry["file"], entry["variables"]), ("resources/views/shop/search.blade.php", ["q"]))
        write(self.root, "app/views/notes/show.html.erb", "<p><%= raw @note %></p>\n<p><%= @other %></p>\n")
        write(self.root, "app/controllers/notes_controller.rb",
              "class NotesController < ApplicationController\n  def show\n    @note = Note.find(params[:id]).body\n"
              "    render 'notes/show'\n  end\nend\n")
        entry = self.ctx("app/controllers/notes_controller.rb", 3)["templates"][0]
        self.assertEqual(entry["file"], "app/views/notes/show.html.erb")
        self.assertIn("note", entry["variables"])
        self.assertIn("raw @note", entry["excerpts"][0]["text"])

    def test_context_dict_built_in_snippet(self):
        write(self.root, "shop/templates/shop/d.html", "<p>{{ msg|safe }}</p>\n<p>{{ other }}</p>\n")
        write(self.root, "shop/d.py", "def v(request):\n    context = {'msg': request.GET['m']}\n"
                                      "    return render(request, 'shop/d.html', context)\n")
        entry = self.ctx("shop/d.py", 3)["templates"][0]
        self.assertEqual((entry["variables"], entry["basis"]), (["msg"], "variables"))
        self.assertIn("{{ msg|safe }}", entry["excerpts"][0]["text"])

    def test_autoescape_directive_included(self):
        write(self.root, "shop/templates/shop/list.html",
              "{% autoescape off %}\n" + "<p>x</p>\n" * 20 + "{{ title }}\n{% endautoescape %}\n")
        write(self.root, "shop/list.py", "def v(r):\n    return render(r, 'shop/list.html', {'title': t})\n")
        entry = self.ctx("shop/list.py", 2)["templates"][0]
        starts = [e["start_line"] for e in entry["excerpts"]]
        self.assertIn(1, starts)  # autoescape yönergesi uzak olsa da eklenir
        self.assertTrue(any("{{ title }}" in e["text"] for e in entry["excerpts"]))

    def test_path_escape_absolute_and_symlinks_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        write(outside, "evil.html", "{{ q|safe }} DIŞARIDA\n")
        write(self.root, "esc.py", "render_template('../outside/evil.html', q=q)\n"
                                   "render_template('/outside/evil.html', q=q)\n"
                                   f"render_template('{outside}/evil.html', q=q)\n")
        self.assertNotIn("templates", self.ctx("esc.py", 1) or {})
        (self.root / "templates").mkdir()
        os.symlink(outside / "evil.html", self.root / "templates" / "link.html")
        os.symlink(outside, self.root / "linkdir")
        write(self.root, "sym.py", "render_template('link.html', q=q)\nrender_template('linkdir/evil.html', q=q)\n")
        context = self.ctx("sym.py", 1) or {}
        self.assertNotIn("DIŞARIDA", json.dumps(context, ensure_ascii=False))
        self.assertNotIn("templates", context)
        self.assertEqual(tc.ContextBuilder(str(self.root)).resolve_template("link.html", "sym.py"), [])
        # Sembolik bağlı proje dosyası da bağlam kaynağı olmaz
        os.symlink(outside / "evil.html", self.root / "alias.py")
        self.assertIsNone(self.ctx("alias.py", 1))
        self.assertIsNone(self.ctx("../outside/evil.html", 1))


class RelatedTests(_Tmp):
    def test_write_site_excerpt(self):
        write(self.root, "notes/models.py", "class Note:\n    pass\n\n\ndef create(request):\n    Note(body=request.POST['b'])\n")
        write(self.root, "notes/views.py", "from notes.models import Note\n\n" + "x = 1\n" * 30 + "html = mark_safe(note.body)\n")
        finding = {"evidence": "Veri akışı: Note.objects.get().body (kullanıcının yazdığı alan: body; yazıldığı yer: "
                               "notes/models.py:6) (satır 20) → mark_safe (satır 33)",
                   "taint_flow": {"source": "x (kullanıcının yazdığı alan: body; yazıldığı yer: notes/models.py:6)",
                                  "source_line": 20, "sink_line": 33}}
        context = self.ctx("notes/views.py", 33, finding=finding)
        write_site = [r for r in context["related"] if r["role"] == "yazıldığı yer"]
        self.assertEqual(len(write_site), 1)
        self.assertEqual((write_site[0]["file"], write_site[0]["line"], write_site[0]["start_line"]), ("notes/models.py", 6, 3))
        self.assertIn("Note(body=request.POST['b'])", write_site[0]["text"])
        source = [r for r in context["related"] if r["role"] == "kaynak"]
        self.assertEqual([(r["file"], r["line"]) for r in source], [("notes/views.py", 20)])  # kesit 21–45 dışında
        inside = self.ctx("notes/views.py", 30, finding=finding)
        self.assertEqual([r for r in inside["related"] if r["role"] == "kaynak"], [])  # 20 ∈ 18–42: tekrar yok

    def test_write_site_rejections(self):
        write(self.base / "outside", "x.py", "GIZLI_DIS = 1\n")
        write(self.root, ".env", "TOKEN=abc\n")
        write(self.root, "v.py", "import os\nprint(1)\n")
        finding = {"evidence": "yazıldığı yer: ../outside/x.py:1; yazıldığı yer: .env:1; yazıldığı yer: /etc/passwd:1; "
                               "yazıldığı yer: v.py:999"}
        context = self.ctx("v.py", 2, finding=finding)
        self.assertNotIn("related", context)
        self.assertNotIn("GIZLI_DIS", json.dumps(context))
        self.assertNotIn("TOKEN", json.dumps(context))


class LimitAndMaskTests(_Tmp):
    def test_size_limit_and_truncation(self):
        imports = "".join(f"import modul_{i:03d}_uzun_bir_ad_burada_{'x' * 40}\n" for i in range(80))
        write(self.root, "big.py", imports + "def v():\n    return render_template('t.html', q=q)\n")
        write(self.root, "templates/t.html", "".join(f"<p>{{{{ q|safe }}}} {'y' * 200}</p>\n" for _ in range(60)))
        full = self.ctx("big.py", 82)
        self.assertLessEqual(tc._size(full), tc.DEFAULT_CONTEXT_BYTES)
        self.assertTrue(full["truncated"])
        self.assertTrue(full["imports"]["truncated"])
        self.assertIn("templates", full)
        for limit in (300, 1000, 2500, 8000):
            context = self.ctx("big.py", 82, max_bytes=limit)
            self.assertLessEqual(tc._size(context or {}), limit, limit)
        self.assertIsNone(self.ctx("big.py", 82, max_bytes=0))
        with mock.patch.dict(os.environ, {tc.CONTEXT_ENV: "700"}):
            self.assertLessEqual(tc._size(self.ctx("big.py", 82)), 700)
            self.assertEqual(tc.context_limit(), 700)
        self.assertEqual((tc.context_limit("abc"), tc.context_limit(-5), tc.context_limit(10 ** 9)),
                         (tc.DEFAULT_CONTEXT_BYTES, 0, tc.MAX_CONTEXT_BYTES))
        long_line = "import " + "a" * 5000 + "\nx = 1\n"
        write(self.root, "long.py", long_line)
        self.assertLessEqual(len(self.ctx("long.py", 2)["imports"]["lines"][0]), tc.MAX_LINE_CHARS + 10)

    def test_secrets_masked_in_all_fields(self):
        write(self.root, "s.py", f"import os  # {SECRET}\nAPI_KEY = '{SECRET}'\n\n" + "x = 1\n" * 30
              + "return render_template('s.html', q=q)\n")
        write(self.root, "templates/s.html", f"<p>{{{{ q|safe }}}}</p>\n<!-- password = \"hunter2-gizli\" -->\n")
        write(self.root, "w.py", f"token = '{SECRET}'\nstore(q)\n")
        finding = {"evidence": "yazıldığı yer: w.py:2"}
        text = json.dumps(self.ctx("s.py", 34, finding=finding), ensure_ascii=False)
        self.assertNotIn("sk-proj-AAAA", text)
        self.assertNotIn("hunter2", text)
        self.assertIn(at.MASK, text)
        self.assertIn("store(q)", text)

    def test_strip_comments_option(self):
        write(self.root, "c.py", "import os\n# GIZLI_YORUM: bu açık değil\nx = 1\nreturn render_template('c.html', q=q)\n")
        write(self.root, "templates/c.html", "{# YORUM_SABLON #}\n<p>{{ q|safe }}</p>\n")
        plain = json.dumps(self.ctx("c.py", 4))
        self.assertIn("YORUM_SABLON", plain)
        stripped = json.dumps(self.ctx("c.py", 4, strip_comments=True))
        self.assertNotIn("YORUM_SABLON", stripped)
        self.assertIn("q|safe", stripped)
        code = at.code_snippet(str(self.root), "c.py", 4, strip_comments=True)
        self.assertNotIn("GIZLI_YORUM", code["text"])
        self.assertEqual(code["text"].split("\n")[1], "")  # satır numarası korunur
        self.assertIn("GIZLI_YORUM", at.code_snippet(str(self.root), "c.py", 4)["text"])
        self.assertEqual(tc.strip_comment_lines(["/* a", " * b", " */", "int x; // y", "#include <a.h>"], "a.c"),
                         ["", "", "", "int x; // y", "#include <a.h>"])


class FrameworkTests(_Tmp):
    def test_manifests(self):
        cases = {
            "Gemfile": ("source 'https://rubygems.org'\ngem 'sinatra'\n", "Sinatra"),
            "go.mod": ("module x\nrequire github.com/gin-gonic/gin v1.9.0\n", "Gin"),
            "composer.json": ('{"require": {"laravel/framework": "^10"}}', "Laravel"),
            "web/App.csproj": ('<Project Sdk="Microsoft.NET.Sdk.Web"></Project>', "ASP.NET Core"),
            "pom.xml": ("<artifactId>spring-boot-starter-thymeleaf</artifactId>", "Thymeleaf"),
            "package.json": ('{"dependencies": {"express": "4", "ejs": "3"}}', "EJS"),
        }
        for rel, (text, _) in cases.items():
            write(self.root, rel, text)
        write(self.root, "a.txt", "x\n")
        detected = tc.ContextBuilder(str(self.root)).framework()["detected"]
        for _, label in cases.values():
            self.assertIn(label, detected)
        self.assertIn("Spring Boot", detected)

    def test_negative_and_symlinked_manifest(self):
        write(self.root, "a.py", "import os\n")
        self.assertIsNone(tc.ContextBuilder(str(self.root)).framework())
        outside = self.base / "out"
        write(outside, "requirements.txt", "django\n")
        os.symlink(outside / "requirements.txt", self.root / "requirements.txt")
        os.symlink(outside, self.root / "sub")
        self.assertIsNone(tc.ContextBuilder(str(self.root)).framework())
        write(self.root, "node_modules/x/package.json", '{"dependencies": {"express": "4"}}')
        self.assertIsNone(tc.ContextBuilder(str(self.root)).framework())


class PacketAndMcpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        write(self.root, "shop/views.py", FLASK_VIEW)
        write(self.root, "shop/templates/shop/search.html", SEARCH_TEMPLATE)
        write(self.root, "main.go", GO_TEXT)
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir), tc.CONTEXT_ENV: ""})
        env.start()
        self.addCleanup(env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        findings = [
            {"category": "web_hardening", "severity": "high", "reference": "CWE-79", "file": "shop/views.py", "line": 8,
             "title": "Şablon XSS adayı", "evidence": "q → render_template", "recommendation": "Kaçış."},
            {"category": "web_hardening", "severity": "high", "reference": "CWE-79", "file": "main.go", "line": 10,
             "title": "Go şablon XSS adayı", "evidence": "q → Execute", "recommendation": "html/template."},
            {"category": "secrets", "severity": "high", "reference": "CWE-798", "file": "shop/views.py", "line": 1,
             "title": "Kaynakta anahtar", "evidence": "x", "recommendation": "Kasaya."},
        ]
        audit = make_audit(self.store, self.root, findings)
        with self.store._connect() as db:  # proje analizinin tehdit modeli (çatı ipucu kaynağı)
            summary = json.loads(db.execute("SELECT summary_json FROM project_audits WHERE id = ?", (audit["id"],)).fetchone()[0])
            summary["threat_model"] = {"nodes": [{"type": "process", "frameworks": ["Flask"]}]}
            db.execute("UPDATE project_audits SET summary_json = ? WHERE id = ?", (json.dumps(summary), audit["id"]))
        items = self.store.list_tracked_findings(str(self.root))
        self.ids = {i["file"] + ("#s" if i["category"] == "secrets" else ""): i["id"] for i in items}

    def test_packet_has_context_and_version(self):
        at.set_project_consent(self.data_dir, str(self.root), True, "test")
        packet = at.build_packet(self.store, str(self.root))
        self.assertEqual((packet["prompt_version"], packet["format"]), ("sniper-ai-triage/2", "sniper-triage-packet/1"))
        self.assertIn("'context'", packet["instructions"])
        self.assertEqual(packet["context_limits"]["max_bytes"], tc.DEFAULT_CONTEXT_BYTES)
        by_file = {f["file"] + ("#s" if f["secret_finding"] else ""): f for f in packet["findings"]}
        flask = by_file["shop/views.py"]["context"]
        self.assertIn("Flask", flask["framework"]["detected"])
        self.assertIn("proje analizi", flask["framework"]["sources"])
        self.assertIn("{{ q|safe }}", flask["templates"][0]["excerpts"][0]["text"])
        self.assertIn('5: \t"text/template"', by_file["main.go"]["context"]["imports"]["lines"])
        self.assertNotIn("context", by_file["shop/views.py#s"])  # sır bulgusu: bağlam yok
        for item in packet["findings"]:
            self.assertLessEqual(tc._size(item.get("context") or {}), tc.DEFAULT_CONTEXT_BYTES)
        small = at.build_packet(self.store, str(self.root), context_bytes=0)
        self.assertFalse(any("context" in f for f in small["findings"]))
        messages = at.build_messages(by_file["main.go"])
        self.assertIn("BAGLAM", messages[1]["content"])

    def test_consent_and_mcp_same_context(self):
        with self.assertRaises(at.ConsentError):
            at.get_finding(self.store, self.ids["main.go"])
        view = at.finding_view(self.store.get_tracked_finding(self.ids["main.go"]) | {"finding": {}}, include_code=False)
        self.assertNotIn("context", view)
        at.set_project_consent(self.data_dir, str(self.root), True, "test")
        server = mcp_triage_server.TriageMCPServer(self.store)
        reply = server.call_tool("get_finding", {"finding_id": self.ids["shop/views.py"]})
        self.assertFalse(reply["isError"])
        data = json.loads(reply["content"][0]["text"])
        direct = at.get_finding(self.store, self.ids["shop/views.py"])
        self.assertEqual(data["context"], direct["context"])
        self.assertIn("'context'", data["instructions"])
        tool = next(t for t in mcp_triage_server.TOOLS if t["name"] == "get_finding")
        self.assertIn("context", tool["description"])

    def test_cli_export_options(self):
        at.set_project_consent(self.data_dir, str(self.root), True, "test")
        out = Path(self.tmp.name) / "p.json"
        done = subprocess.run([sys.executable, str(APP / "cli_reports.py"), "triage", "export", str(self.root), "-o", str(out),
                               "--context-bytes", "600", "--strip-comments", "--db", str(self.store.path)],
                              capture_output=True, text=True, timeout=60, env={**os.environ, "SNIPER_DATA_DIR": str(self.data_dir)})
        self.assertEqual(done.returncode, 0, done.stderr)
        packet = json.loads(out.read_text())
        self.assertEqual(packet["context_limits"], {**packet["context_limits"], "max_bytes": 600, "strip_comments": True})
        self.assertTrue(all(tc._size(f.get("context") or {}) <= 600 for f in packet["findings"]))


class EvalPacketContextTests(unittest.TestCase):
    @unittest.skipUnless(AI_TRIAGE_EVAL.is_file(), "maintainer evaluation script is not distributed")
    def test_eval_packet_has_context(self):
        sys.path.insert(0, str(APP / "scripts"))
        import ai_triage_eval as ev

        with tempfile.TemporaryDirectory() as tmp:
            set_dir = Path(tmp) / "heldoutX"
            write(set_dir / "p", "main.go", GO_TEXT)
            (set_dir / "ground_truth.json").write_text(json.dumps({"adjudicated": {"p": [
                {"file": "main.go", "line": 10, "class": "xss", "verdict": "true_positive", "note": "GIZLI-NOT"}]}}))
            packet, _ = ev.build_eval_packet([set_dir])
            [item] = packet["findings"]
            self.assertIn('5: \t"text/template"', item["context"]["imports"]["lines"])
            self.assertNotIn("GIZLI-NOT", json.dumps(packet))
            bare, _ = ev.build_eval_packet([set_dir], context_bytes=0)
            self.assertNotIn("context", bare["findings"][0])


if __name__ == "__main__":
    unittest.main()


class DynamicValueMaskingTests(unittest.TestCase):
    """Değişken ekleme içeren 'parola = ...' kod satırları maskelenmez (asıl açığı gizler); gerçek sırlar maskelenir."""

    def test_interpolations_kept(self):
        from ai_triage import redact_text
        for text in ("q = `UPDATE users SET password = '${newPassword}' WHERE id = 1`",
                     "password = '$pass'", 'password = "#{params[:pw]}"', "cur.execute(\"... password = '%s'\" % pw)",
                     'password: "{user_pw}"'):
            self.assertEqual(redact_text(text), text)

    def test_literal_secrets_masked(self):
        from ai_triage import MASK, redact_text
        for text in ("PASSWORD = 'hunter22'", "password = 'pa$Sword1'", "password = 'abc?def'",
                     'app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"'):
            self.assertIn(MASK, redact_text(text), text)
