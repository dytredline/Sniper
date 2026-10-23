"""14. tur hızlandırmaları: çıktıyı değiştirmeyen kısayolların eşdeğerlik testleri.

* ``taint_flow.fast_walk`` ``ast.walk`` ile aynı düğümleri aynı sırada verir;
* rota yetki envanteri proje analizinin ağaç/düğüm listesiyle kendi ayrıştırmasıyla aynı sonucu üretir;
* satır kuralı ön süzgecinin her kural için sabit parçası vardır ve eşleşen satırlar süzgeçten geçer;
* analiz sırasında yükseltilen çöp toplayıcı eşikleri sonra geri yüklenir.
"""
from __future__ import annotations

import ast
import gc
from pathlib import Path
import re
import tempfile
import threading
import unittest

import authz_routes
import project_analyzer
import taint_flow

APP = Path(__file__).resolve().parents[1]

SAMPLE = '''
import os, pickle, hashlib
from flask import Blueprint, request
from django.urls import path
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

bp = Blueprint("x", __name__)

@bp.before_request
def guard():
    if not request.user.is_authenticated:
        abort(401)

@bp.route("/items/<int:item_id>", methods=["POST"])
def update(item_id):
    global COUNTER
    item = Item.objects.get(id=item_id)
    data = pickle.loads(request.data)
    os.system("ping " + request.args["h"])
    return hashlib.md5(b"x").hexdigest()

class ItemView(LoginRequiredMixin, View):
    permission_required = "app.change_item"
    def post(self, request, pk):
        return Item.objects.get(pk=pk)

class OpenView(View):
    def get(self, request, pk):
        match pk:
            case 1: return lambda: [x async for x in y]
        return f"{pk!r:>10}"

urlpatterns = [path("items/<pk>/", ItemView.as_view()), path("open/<pk>/", OpenView.as_view())]
'''


class FastWalkTests(unittest.TestCase):
    def test_same_nodes_same_order(self):
        sources = [SAMPLE] + [p.read_text(encoding="utf-8") for p in sorted(APP.glob("*.py"))[:40]]
        for text in sources:
            tree = ast.parse(text)
            self.assertEqual([id(n) for n in ast.walk(tree)], [id(n) for n in taint_flow.fast_walk(tree)])

    def test_slim_tree_nodes(self):
        tree = taint_flow._slim_tree(ast.parse(SAMPLE), {})
        self.assertEqual([id(n) for n in ast.walk(tree)], [id(n) for n in taint_flow.fast_walk(tree)])


class AuthzSharedTreeTests(unittest.TestCase):
    def test_shared_tree_matches_own_parse(self):
        own = authz_routes.analyze_sources([("app/views.py", SAMPLE), ("app/urls.py", SAMPLE)])
        shared = []
        for rel in ("app/views.py", "app/urls.py"):
            tree = ast.parse(SAMPLE)
            shared.append((rel, SAMPLE, tree, list(taint_flow.fast_walk(tree))))
        again = authz_routes.analyze_sources(shared)
        self.assertEqual(authz_routes.inventory(own["routes"]), authz_routes.inventory(again["routes"]))
        self.assertEqual(own["findings"], again["findings"])
        self.assertTrue(own["routes"])


def _line_rules() -> tuple:
    """_analyze_project içindeki satır kurallarını kaynak koddan derle (testte kural listesine erişim)."""
    source = (APP / "project_analyzer.py").read_text(encoding="utf-8")
    namespace = {"re": re, **{k: getattr(project_analyzer, k) for k in dir(project_analyzer) if k.isupper()}}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {"extra_line_rules", "line_rules"}
                                                for t in node.targets):
            exec(compile(ast.Module([node], []), "rules", "exec"), namespace)
    return namespace["line_rules"]


class LineRulePrefilterTests(unittest.TestCase):
    def test_every_rule_has_literals(self):
        rules = _line_rules()
        self.assertGreater(len(rules), 20)
        for rule in rules:
            literals = project_analyzer._LINE_RULE_LITERALS.get(rule[2])
            self.assertTrue(literals, rule[2])
            for literal in literals:
                self.assertEqual(literal, literal.casefold())
                self.assertFalse(any(ch.isspace() for ch in literal))

    def test_matching_lines_pass_prefilter(self):
        lines = [
            'data = pickle.loads(body)', 'x = yaml.load(f)', 'el.innerHTML = value', 'document.write(x)',
            'jwt.decode(t, verify=False)', 'tar.extractall(dest)', 'render_template_string(s)', 'Template(f"{x}")',
            'parser = etree.XMLParser(resolve_entities=True)', 'token = random.choice(chars)', 'nodeIntegration: true',
            'contextIsolation: false', 'torch.load(path)', 'grpc.insecure_channel(addr)', 'addr.call{value: 1}("")',
            'require(tx.origin == owner)', 'strcpy(dst, src)', 'PASSWORD = "supersecretvalue"', 'eval(code)',
            'subprocess.run(cmd, shell=True)', 'cursor.execute("SELECT " + q)', 'hashlib.md5(b"x")',
            'requests.get(u, verify=False)', 'app.run(host="0.0.0.0")', "allow_origins=['*']",
            'logger.info("token %s", token)', 'API_KEY = "ıııııııı"', 'prİnt(password)',
        ]
        rules = _line_rules()
        matched = 0
        for line in lines:
            folded = project_analyzer._fold_for_literals(line.casefold())
            for rule in rules:
                if rule[3].search(line):
                    matched += 1
                    self.assertIn(rule, project_analyzer._rules_present((rule,), folded), (rule[2], line))
        self.assertGreater(matched, 25)

    def test_absent_literal_skips_rule(self):
        rules = _line_rules()
        present = project_analyzer._rules_present(rules, "x = 1")
        self.assertEqual(present, ())


class RelaxedGcTests(unittest.TestCase):
    def test_threshold_restored_and_nested(self):
        before = gc.get_threshold()
        with project_analyzer._relaxed_gc():
            self.assertGreaterEqual(gc.get_threshold()[0], 50_000)
            with project_analyzer._relaxed_gc():
                self.assertGreaterEqual(gc.get_threshold()[0], 50_000)
            self.assertGreaterEqual(gc.get_threshold()[0], 50_000)
        self.assertEqual(gc.get_threshold(), before)

    def test_concurrent_analyses_restore(self):
        before = gc.get_threshold()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "p"
            root.mkdir()
            (root / "app.py").write_text('import os\nos.system("x" + input())\n')
            errors = []

            def run():
                try:
                    project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=run) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
        self.assertEqual(gc.get_threshold(), before)

    def test_disabled_threshold_untouched(self):
        before = gc.get_threshold()
        try:
            gc.set_threshold(0)
            with project_analyzer._relaxed_gc():
                self.assertEqual(gc.get_threshold()[0], 0)
            self.assertEqual(gc.get_threshold()[0], 0)
        finally:
            gc.set_threshold(*before)


if __name__ == "__main__":
    unittest.main()
