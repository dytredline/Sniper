"""19. tur hız değişiklikleri: eşdeğerlik testleri (çıktı önceki uygulamayla birebir aynı olmalı)."""
from __future__ import annotations

import ast
import random
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import taint_cfamily  # noqa: E402
import taint_flow  # noqa: E402
import taint_js_ast  # noqa: E402
import taint_native_core  # noqa: E402
import project_analyzer  # noqa: E402


def _old_brace_ends(toks, lo, hi):
    stack, ends = [], [hi] * (hi - lo + 1)
    for j in range(lo, hi + 1):
        t = toks[j]
        if t.kind == "op" and t.text == "{":
            stack.append(j)
        elif t.kind == "op" and t.text == "}" and stack:
            o = stack.pop()
            for q in range(o, j + 1):
                if ends[q - lo] == hi or ends[q - lo] > j:
                    ends[q - lo] = j
    return ends


class BraceEndsTests(unittest.TestCase):
    def test_matches_quadratic_reference_on_random_sequences(self):
        rng = random.Random(19)
        for _ in range(3000):
            n = rng.randint(1, 40)
            toks = [SimpleNamespace(kind="op" if rng.random() < 0.6 else "id",
                                    text=rng.choice("{}{}x;")) for _ in range(n)]
            lo = rng.randint(0, n - 1)
            hi = rng.randint(lo, n - 1)
            self.assertEqual(taint_cfamily._brace_ends(toks, lo, hi), _old_brace_ends(toks, lo, hi))


class CompactTests(unittest.TestCase):
    def test_empty_and_single(self):
        o = taint_native_core.Origin("request", "x", 1, "a.c") if hasattr(taint_native_core, "Origin") else None
        self.assertEqual(taint_native_core.compact(set()), frozenset())
        if o is not None:
            self.assertEqual(taint_native_core.compact([o]), frozenset({o}))


class JsTokenizerTests(unittest.TestCase):
    def test_tokens_unchanged_on_tricky_input(self):
        src = ("a = `x${b + `y${c}`}` + 'q\\'w' + \"e\\\nr\" // yorum\n/* çok\nsatır */ x >>>= 1; y?.z ?? w;"
               " r = /a[/]b/gi; s = 'açık\n t = \"\\\\\"; café = 1;\ufeff\f\v u")
        toks = taint_flow._js_tokenize(src)
        self.assertIsNotNone(toks)
        values = [(t.kind, t.value, t.line) for t in toks]
        # Beklenen: 18. tur (karakter döngülü) belirteç ayrıştırıcısının çıktısı (ayrıca 2432 dosyada fark testi).
        self.assertEqual(values, [
            ("id", "a", 1), ("punct", "=", 1), ("tpl", "x${}", 1), ("punct", "+", 1), ("str", "q\\'w", 1),
            ("punct", "+", 1), ("str", "e\\\nr", 1), ("id", "x", 4), ("punct", ">>>=", 4), ("num", "1", 4),
            ("punct", ";", 4), ("id", "y", 4), ("punct", "?.", 4), ("id", "z", 4), ("punct", "??", 4), ("id", "w", 4),
            ("punct", ";", 4), ("id", "r", 4), ("punct", "=", 4), ("regex", "/a[/]b/gi", 4), ("punct", ";", 4),
            ("id", "s", 4), ("punct", "=", 4), ("str", "açık", 4), ("id", "t", 5), ("punct", "=", 5),
            ("str", "\\\\", 5), ("punct", ";", 5), ("id", "café", 5), ("punct", "=", 5), ("num", "1", 5),
            ("punct", ";", 5), ("id", "u", 5)])
        self.assertEqual(toks[2].parts[0][2].value, "y${}")  # iç içe şablon


class JsWalkTests(unittest.TestCase):
    def test_walk_order_matches_children_reference(self):
        node = {"type": "A", "x": {"type": "B", "k": [{"type": "C"}, {"no": 1}, {"type": "D"}]},
                "l": {"type": "IGNORED"}, "y": [{"type": "E", "z": {"type": "F"}}]}

        def ref(n):
            out, stack = [], [n]
            while stack:
                cur = stack.pop()
                if not isinstance(cur, dict):
                    continue
                out.append(cur["type"])
                stack.extend(reversed(list(taint_js_ast._children(cur))))
            return out

        self.assertEqual([c["type"] for c in taint_js_ast._walk(node)], ref(node))


class PyFunctionScanTests(unittest.TestCase):
    def test_scan_matches_separate_walks(self):
        src = ("def f(a, b):\n    global G\n    x = 1\n    if a and b > 2:\n        r = Response(1)\n"
               "        r['Content-Disposition'] = 'attachment; x'\n    while c: pass\n    assert d\n"
               "    y = e if g else h\n    match k:\n        case 1: pass\n")
        tree = ast.parse(src)
        func = tree.body[0]
        project = taint_flow._PyProject(None) if hasattr(taint_flow, "_PyProject") else None
        if project is None:
            self.skipTest("proje sınıfı yok")
        decls, stored = project.function_names(func)
        self.assertEqual(decls, frozenset({"G"}))
        self.assertEqual(stored, frozenset({"x", "r", "y"}))
        self.assertEqual(project.test_params(func), frozenset({"a", "b", "c", "d", "g", "k"}))
        self.assertEqual(project.non_html_response_calls(func), frozenset(taint_flow._non_html_response_calls(func)))


class MobileRulePrefilterTests(unittest.TestCase):
    def test_no_anchor_patterns(self):
        # Ön süzgeç yalnız ^/$ çapası olmayan desenlerde geçerli (tüm metin araması satır aramasının üst kümesi).
        for rx in project_analyzer._MOBILE_LINE_RX:
            self.assertNotIn("^", rx.pattern.replace("[^", ""))
            self.assertNotIn("$", rx.pattern)


if __name__ == "__main__":
    unittest.main()
