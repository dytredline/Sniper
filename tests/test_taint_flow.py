import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import taint_flow
from taint_flow import analyze_javascript, analyze_python, collect_js_route_handlers


APP_ROOT = Path(__file__).resolve().parents[1]
TAINT_BENCHMARK = APP_ROOT / "scripts" / "taint_benchmark.py"


def _sinks(analysis, kind=None, label=None):
    return sorted((f.sink_kind, f.line) for f in analysis.flows if (kind is None or f.sink_kind == kind) and (label is None or f.source_label == label))


class PythonTaintTests(unittest.TestCase):
    def test_variable_and_multiline_flows(self):
        source = (
            "@app.route('/s')\n"
            "def s():\n"
            "    term = request.args.get('q')\n"
            "    logger.info('t %s', term)\n"
            "    logger.warning(\n"
            "        'x %s',\n"
            "        request.form['a'],\n"
            "    )\n"
            "    sql = 'SELECT ' + term\n"
            "    cur.execute(sql)\n"
            "    cur.execute('SELECT ?', (term,))\n"
        )
        analysis = analyze_python(source)
        self.assertEqual(_sinks(analysis), [("log", 4), ("log", 5), ("sql", 10)])
        flow = analysis.flows_of("sql")[0]
        self.assertEqual(flow.source, "request.args")
        self.assertEqual(flow.via, ("term", "sql"))
        self.assertTrue(analysis.is_clean_sink("sql", 11))

    def test_sanitizers_and_strong_update(self):
        source = (
            "def v():\n"
            "    uid = request.args['id']\n"
            "    uid = int(uid)\n"
            "    logger.info('u %s', uid)\n"
            "    logger.info('n %d', len(request.args))\n"
            "    logger.info('r %r', request.args['q'])\n"
            "    logger.info('c ' + request.args['q'].replace('\\n', ''))\n"
            "    logger.info('e', extra={'q': request.args['q']})\n"
            "    re.compile(re.escape(request.args['p']))\n"
            "    subprocess.run(['ls', request.args['f']])\n"
        )
        analysis = analyze_python(source)
        self.assertEqual(analysis.flows, [])
        for line in (4, 5, 6, 7, 8):
            self.assertTrue(analysis.is_clean_sink("log", line), line)

    def test_branch_merge_keeps_taint(self):
        source = (
            "def v():\n"
            "    if cond:\n"
            "        x = request.json['a']\n"
            "    else:\n"
            "        x = 'safe'\n"
            "    os.system('echo ' + x)\n"
        )
        self.assertEqual(_sinks(analyze_python(source)), [("command", 6)])

    def test_route_parameters_respect_types_and_depends(self):
        source = (
            "@router.get('/u/{uid}')\n"
            "async def u(uid: int, q: str = '', db=Depends(get_db)):\n"
            "    log.info(uid)\n"
            "    log.info(q)\n"
            "    log.info(db)\n"
            "@app.route('/d/<int:item_id>/<name>')\n"
            "def d(item_id, name):\n"
            "    log.info(item_id)\n"
            "    log.info(name)\n"
        )
        self.assertEqual(_sinks(analyze_python(source)), [("log", 4), ("log", 9)])

    def test_pii_classifier_flows(self):
        source = "def f(user):\n    contact = user.email\n    print(contact)\n    logger.info(mask(contact))\n"
        analysis = analyze_python(source, pii=lambda name: name == "email")
        self.assertEqual(_sinks(analysis, label="pii"), [("log", 3)])

    def test_syntax_error_returns_none(self):
        self.assertIsNone(analyze_python("def broken(:\n"))


class JavaScriptTaintTests(unittest.TestCase):
    def test_express_handler_flows(self):
        source = (
            "router.post('/u', async (req, res) => {\n"
            "  const { name } = req.body;\n"
            "  console.log('n=' + req.body.items.length);\n"
            "  console.log(`name ${name}`);\n"
            "  await db.query(\n"
            "    'SELECT * FROM u WHERE n = ' + name\n"
            "  );\n"
            "  await db.query('SELECT $1', [name]);\n"
            "  await db.query({ text: 'SELECT $1', values: [name] });\n"
            "  logger.info('p', JSON.stringify(req.body));\n"
            "  const n = parseInt(req.query.n, 10);\n"
            "  logger.info('n', n);\n"
            "  const re = new RegExp(req.query.p);\n"
            "  exec('convert ' + req.query.f);\n"
            "  /x/.exec(req.query.f);\n"
            "});\n"
        )
        analysis = analyze_javascript(source)
        self.assertEqual(
            _sinks(analysis),
            [("command", 14), ("log", 4), ("regex", 13), ("sql", 5)],
        )
        for kind, line in (("log", 3), ("sql", 8), ("sql", 9), ("log", 10), ("log", 12)):
            self.assertTrue(analysis.is_clean_sink(kind, line), (kind, line))

    def test_dom_sources_and_sinks(self):
        source = (
            "function r() {\n"
            "  const h = location.hash.slice(1);\n"
            "  document.getElementById('o').innerHTML = h;\n"
            "  el.innerHTML = escapeHtml(h);\n"
            "  $('#a').html(h);\n"
            "  el.insertAdjacentHTML('beforeend', `<b>${h}</b>`);\n"
            "  el.textContent = h;\n"
            "  eval(location.hash.substring(1));\n"
            "}\n"
        )
        self.assertEqual(
            _sinks(analyze_javascript(source)),
            [("eval", 8), ("html", 3), ("html", 5), ("html", 6)],
        )

    def test_block_scoped_declarations_do_not_leak(self):
        source = (
            "app.get('/a', (req, res) => { const q = req.query.q; });\n"
            "function other() { const q = 'safe'; console.log(q); }\n"
        )
        self.assertEqual(analyze_javascript(source).flows, [])

    def test_cross_file_handler_names(self):
        routes = "router.get('/s', userController.search);\nrouter.post('/c', auth, create);\n"
        names = collect_js_route_handlers(routes)
        self.assertEqual(names, frozenset({"search", "auth", "create"}))
        controller = "exports.search = async (rq, rs) => {\n  logger.info(`q ${rq.query.q}`);\n};\n"
        self.assertEqual(analyze_javascript(controller).flows, [])
        self.assertEqual(_sinks(analyze_javascript(controller, handler_names=names)), [("log", 2)])
        # router olmayan nesnelerin .get( çağrıları işleyici sayılmaz
        self.assertEqual(collect_js_route_handlers("cache.get(key, loader);\n"), frozenset())

    def test_koa_context_source_and_typescript_annotation(self):
        source = (
            "router.post('/c', async (ctx) => {\n"
            "  const file: string = ctx.request.body.file;\n"
            "  exec(`convert ${file}`);\n"
            "});\n"
        )
        self.assertEqual(_sinks(analyze_javascript(source)), [("command", 3)])


class SwitchTests(unittest.TestCase):
    def test_disabled_context_and_env(self):
        source = "def f():\n    logger.info(request.args['q'])\n"
        self.assertIsNotNone(taint_flow.analyze_source(source, "a.py"))
        with taint_flow.disabled():
            self.assertIsNone(taint_flow.analyze_source(source, "a.py"))
        with mock.patch.dict(os.environ, {"SNIPER_TAINT_ANALYSIS": "0"}):
            self.assertIsNone(taint_flow.analyze_source(source, "a.py"))
        # Desteklenmeyen dil: None. Go/Ruby 13. turdan beri taint_goruby, Rust/C/C++ 16. turdan beri
        # taint_rust/taint_cfamily ile analiz edilir.
        self.assertIsNone(taint_flow.analyze_source(source, "a.swift"))
        self.assertEqual(taint_flow.analyze_source("fn main() {}\n", "a.rs").language, "rust")
        self.assertEqual(taint_flow.analyze_source("package a\n", "a.go").language, "go")
        with taint_flow.disabled():
            self.assertIsNone(taint_flow.analyze_source("package a\n", "a.go"))

    def test_project_context_does_not_leak_handler_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "routes.js").write_text("router.get('/x', ctl.show);\n", encoding="utf-8")

            @taint_flow.project_context
            def scan() -> frozenset:
                taint_flow.activate_project_js_handlers(root, frozenset())
                return taint_flow._PROJECT_JS_HANDLERS.get()

            self.assertEqual(scan(), frozenset({"show"}))
        self.assertEqual(taint_flow._PROJECT_JS_HANDLERS.get(), frozenset())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo yok")
    def test_handler_prepass_skips_fifo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.mkfifo(root / "blocking.js")
            (root / "routes.js").write_text("router.get('/x', ctl.show);\n", encoding="utf-8")
            self.assertEqual(taint_flow.project_js_handler_names(root, frozenset()), frozenset({"show"}))


class BenchmarkTests(unittest.TestCase):
    """followup-02 ölçüm seti: taint analizi satır tabanlı moddan kötü olmamalı."""

    def _run(self, env):
        spec = importlib.util.spec_from_file_location("taint_benchmark", APP_ROOT / "scripts" / "taint_benchmark.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.dict(os.environ, env):
            return module, module.run_benchmark()

    @unittest.skipUnless(TAINT_BENCHMARK.is_file(), "maintainer benchmark script is not distributed")
    def test_token_fallback_engine_keeps_precision(self):
        # Node olmadan (belirteç motoru) dosyalar arası JS örnekleri kaçar, yanlış pozitif olmamalı.
        _module, result = self._run({"SNIPER_TAINT_JS_ENGINE": "tokens"})
        new = result["taint"]["TOPLAM"]
        self.assertEqual(new["false_positives"], [])
        self.assertTrue(all(item.startswith("js_ip_") for item in new["false_negatives"]), new["false_negatives"])

    @unittest.skipUnless(TAINT_BENCHMARK.is_file(), "maintainer benchmark script is not distributed")
    def test_benchmark_precision_and_recall(self):
        from tests.test_taint_js_ast import NODE_ENV

        if NODE_ENV is None:
            self.skipTest("node bulunamadı (AST motoru)")
        module, result = self._run(NODE_ENV)
        old, new = result["line_based"]["TOPLAM"], result["taint"]["TOPLAM"]
        self.assertGreaterEqual(result["expected"], 39)
        self.assertEqual(new["recall"], 1.0, new["false_negatives"])
        self.assertGreaterEqual(new["precision"], 0.9, new["false_positives"])
        self.assertGreater(new["recall"], old["recall"])
        self.assertGreaterEqual(new["precision"], old["precision"])
        for key in module.KEYS:
            self.assertGreaterEqual(result["taint"][key]["tp"], result["line_based"][key]["tp"], key)


if __name__ == "__main__":
    unittest.main()
