"""19. tur determinizm: motor çıktısı PYTHONHASHSEED'e bağlı olmamalı (frozenset yinelemesi karma sırasına
bağlıdır). Aynı girdi farklı tohumlarla ayrı süreçlerde çalıştırılır, akış dökümleri birebir aynı olmalı.
Ayrıca bulgu takibinin ikincil (kaynaktan bağımsız) eşlemesi: aynı hedefe farklı kaynak gösterilirse kayıt ve
triyaj korunur."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

import finding_tracking as ft
from storage import Store

APP = Path(__file__).resolve().parents[1]
SEEDS = ("0", "1", "2", "3", "4242")

_DUMP = textwrap.dedent("""
    import json, sys
    sys.path.insert(0, sys.argv[1])
    engine, lang = sys.argv[2], sys.argv[3]
    files = json.loads(sys.stdin.read())
    if engine == "clike":
        import taint_clike
        res = taint_clike.analyze_files(files, {})
    elif engine == "goruby":
        import taint_goruby
        res = taint_goruby.analyze_files(files, lang)
    else:
        import taint_flow
        res = {p: taint_flow.analyze_source(t, p) for p, t in files.items()}
    out = []
    for path in sorted(res):
        a = res[path]
        for kind, flows in (("F", a.flows), ("P", getattr(a, "privileged_flows", []))):
            out.extend([kind, f.file, f.line, f.sink_kind, f.source, f.source_line, list(f.via)] for f in flows)
    print(json.dumps(out, ensure_ascii=False))
""")


def run_seeds(engine: str, files: dict[str, str], lang: str = "") -> list[str]:
    outs = []
    for seed in SEEDS:
        env = {**os.environ, "PYTHONHASHSEED": seed}
        proc = subprocess.run([sys.executable, "-c", _DUMP, str(APP), engine, lang], input=json.dumps(files),
                              capture_output=True, text=True, env=env, timeout=120, check=True)
        outs.append(proc.stdout)
    return outs


class EngineDeterminismTests(unittest.TestCase):
    def assert_stable(self, outs: list[str]) -> None:
        self.assertTrue(json.loads(outs[0]), "örnek akış üretmeli")
        self.assertEqual(len(set(outs)), 1, "çıktı karma tohumuna bağlı")

    def test_php_include_callsite_picks_stable_source(self):
        # Ortak kitaplığa verilen dizi öğesi üç kaynağı birleştirir; çağrı yeri bulgusu tek kaynak gösterir.
        files = {
            "lib.php": "<?php\nfunction runq($q) {\n  mysqli_query($GLOBALS['c'], \"SELECT * FROM t WHERE a=\" . $q);\n}\n",
            "page.php": textwrap.dedent("""\
                <?php
                include 'lib.php';
                $s = array('slug' => $_POST['slug'], 'name' => $_POST['name'], 'plugin' => $_POST['plugin']);
                if (x()) { $s['err'] = 'e'; }
                runq($s['plugin']);
            """),
        }
        self.assert_stable(run_seeds("clike", files))

    def test_csharp_params_same_line_stable_order(self):
        # Aynı satırdaki üç parametre aynı hedefe: eşit (satır, tür, kaynak satırı) akışların sırası kararlı olmalı.
        files = {"C.cs": textwrap.dedent("""\
            public class AController : Controller {
              public IActionResult Create(string activityName, string returnUrl, string third) {
                var u = Helper(activityName + returnUrl + third);
                return Redirect(u);
              }
              private string Helper(string x) { return x; }
            }
        """)}
        self.assert_stable(run_seeds("clike", files))

    def test_go_many_sources_one_sink(self):
        files = {"main.go": textwrap.dedent("""\
            package main
            import ("net/http"; "os/exec")
            func h(w http.ResponseWriter, r *http.Request) {
              a := r.URL.Query().Get("a"); b := r.FormValue("b"); c := r.Header.Get("c"); d := r.URL.Path
              exec.Command("sh", "-c", a+b+c+d).Run()
              exec.Command("sh", "-c", d+c+b+a).Run()
              exec.Command("sh", "-c", b+d).Run()
            }
            func main() { http.HandleFunc("/", h) }
        """)}
        self.assert_stable(run_seeds("goruby", files, "go"))


class TrackingSourceChangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "proj"
        self.root.mkdir()
        (self.root / "app.php").write_text("<?php\n")
        self.store = Store(base / "data" / "sniper.db")
        self.n = 0

    def finding(self, source: str, line: int = 10, sink: str = "mysqli_query") -> dict:
        return {
            "category": "data_query", "severity": "critical", "reference": "CWE-89", "file": "app.php", "line": line,
            "title": "Doğrulanmış veri akışı: istek girdisi SQL sorgusuna ulaşıyor (SQL enjeksiyonu)",
            "evidence": f"Veri akışı: {source} → {sink}", "recommendation": "Bağlayın.",
            "taint_flow": {"sink_kind": "sql", "sink": sink, "sink_line": line, "source": source, "source_label": "request",
                           "source_line": line - 1, "via": [], "source_file": "app.php"},
        }

    def audit(self, findings):
        self.n += 1
        return self.store.create_project_audit({
            "created_at": f"2026-10-{self.n:02d}T10:00:00Z", "project_path": str(self.root), "project_name": "proj",
            "score": 50, "grade": "D", "file_count": 1, "bytes_scanned": 5, "findings": findings, "scope": {},
            "skipped_files": {},
        })

    def test_same_sink_other_source_keeps_record_and_triage(self):
        first = self.audit([self.finding("$_POST['name']")])
        tracked_id = first["findings"][0]["tracking"]["id"]
        self.store.set_tracked_finding_status(tracked_id, "false_positive", "test")
        second = self.audit([self.finding("$_POST['slug']", line=12)])
        self.assertEqual(second["tracking"]["new_count"], 0)
        self.assertEqual(second["findings"][0]["tracking"]["id"], tracked_id)
        items = self.store.list_tracked_findings(str(self.root))
        self.assertEqual([(i["id"], i["status"]) for i in items], [(tracked_id, "false_positive")])
        self.assertEqual(items[0]["fingerprint"] if "fingerprint" in items[0] else ft.fingerprint(self.finding("$_POST['slug']")),
                         ft.fingerprint(self.finding("$_POST['slug']")))

    def test_other_sink_is_still_new_and_fixed_rows_not_revived(self):
        self.audit([self.finding("$_POST['a']")])
        second = self.audit([])  # düzeldi
        self.assertEqual(second["tracking"]["fixed_count"], 1)
        third = self.audit([self.finding("$_POST['b']")])  # aynı yer, farklı kaynak: düzelmiş kayıt diriltilmez
        self.assertEqual(third["tracking"]["new_count"], 1)
        fourth = self.audit([self.finding("$_POST['b']"), self.finding("$_POST['c']", sink="pg_query")])
        self.assertEqual(fourth["tracking"]["new_count"], 1)  # farklı hedef adı: yeni bulgu


if __name__ == "__main__":
    unittest.main()
