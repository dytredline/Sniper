import tempfile
import unittest
from pathlib import Path

import joern_active
from joern_source_prep import brace_csharp_bodies, prepare_source


class CSharpBraceTests(unittest.TestCase):
    def assertBraced(self, source, expected):
        result = brace_csharp_bodies(source)
        self.assertEqual(result, expected)
        self.assertEqual(result.count("\n"), source.count("\n"))   # satır numaraları korunur

    def test_wraps_braceless_bodies_of_all_control_statements(self):
        self.assertBraced("if (a) Sink(a);", "if (a) { Sink(a); }")
        self.assertBraced("if (a == null) return;\nelse Sink(a);", "if (a == null) { return; }\nelse { Sink(a); }")
        self.assertBraced("for (int i = 0; i < 3; i++) Sink(i);", "for (int i = 0; i < 3; i++) { Sink(i); }")
        self.assertBraced("foreach (var x in xs) Sink(x);", "foreach (var x in xs) { Sink(x); }")
        self.assertBraced("while (a) Sink(a);", "while (a) { Sink(a); }")
        self.assertBraced("do Sink(a); while (a);", "do { Sink(a); } while (a);")
        self.assertBraced("using (var s = Open()) Sink(s);", "using (var s = Open()) { Sink(s); }")
        self.assertBraced("if (!ok)\n    throw new Exception(\"x\");", "if (!ok)\n    { throw new Exception(\"x\"); }")

    def test_nested_and_else_if_chains(self):
        self.assertBraced("if (a) if (b) x(); else y(); else z();",
                          "if (a) { if (b) { x(); } else { y(); } } else { z(); }")
        self.assertBraced("if (a) x(); else if (b) y();", "if (a) { x(); } else if (b) { y(); }")
        self.assertBraced("if (a) switch (b) { case 1: break; }", "if (a) { switch (b) { case 1: break; } }")
        self.assertBraced("if (a) try { x(); } catch (E e) when (f(e)) { } finally { }",
                          "if (a) { try { x(); } catch (E e) when (f(e)) { } finally { } }")

    def test_leaves_braced_empty_and_do_while_tails_alone(self):
        for source in ("if (a) { x(); }", "while (a) ;", "do { x(); } while (a);", "class C { void M() { } }"):
            self.assertEqual(brace_csharp_bodies(source), source)

    def test_lambdas_initializers_strings_and_comments(self):
        self.assertBraced("if (a) x(() => { y(); });", "if (a) { x(() => { y(); }); }")
        self.assertBraced("if (a) v = new T { A = 1, B = { 2 } };", "if (a) { v = new T { A = 1, B = { 2 } }; }")
        self.assertBraced('if (a) s = $"{(b ? "}" : "{")} {{x}}";', 'if (a) { s = $"{(b ? "}" : "{")} {{x}}"; }')
        self.assertBraced('s = @"a "" if (x) y();";', 's = @"a "" if (x) y();";')
        self.assertBraced('// if (x) y();\n/* if (z) w(); */', '// if (x) y();\n/* if (z) w(); */')
        self.assertBraced("if (a)\n#if DEBUG\n  x();\n#endif\nelse y();", "if (a)\n#if DEBUG\n  { x(); }\n#endif\nelse { y(); }")

    def test_unparsable_input_is_returned_unchanged(self):
        for source in ('if (a) s = "kapanmayan', "if (a) x(", "if (a) x() ) y();", "/* yarım"):
            self.assertEqual(brace_csharp_bodies(source), source)

    def test_prepare_source_only_changes_csharp(self):
        self.assertEqual(prepare_source("csharp", b"if (a) x();"), b"if (a) { x(); }")
        self.assertEqual(prepare_source("java", b"if (a) x();"), b"if (a) x();")
        self.assertEqual(prepare_source("csharp", b"\xff\xfe if (a) x();"), b"\xff\xfe if (a) x();")

    def test_lock_becomes_monitor_enter_and_block(self):
        enter = "System.Threading.Monitor.Enter"
        self.assertEqual(brace_csharp_bodies("lock (o) { Sink(x); }"), f"{enter}     (o); {{ Sink(x); }}")
        self.assertEqual(brace_csharp_bodies("lock(o)Sink(x);"), f"{enter}    (o);{{ Sink(x); }}")
        # Gövdesi lock olan if: önce if gövdesi sarılır, sonra çağrı adı gelir.
        self.assertEqual(brace_csharp_bodies("if (a) lock (o) Run(q);"),
                         f"if (a) {{ {enter}     (o); {{ Run(q); }} }}")
        self.assertEqual(brace_csharp_bodies("lock (a) lock (b) Sink(q);"),
                         f"{enter}     (a); {{ {enter}     (b); {{ Sink(q); }} }}")

    def test_lock_keeps_line_numbers_and_ignores_strings_comments_and_identifiers(self):
        src = "lock (o)\n{\n  Sink(q);\n}\n"
        out = brace_csharp_bodies(src)
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertEqual(out.splitlines()[2], "  Sink(q);")
        for text in ('var s = "lock (x)"; // lock (y) {\n', "var @lock = Get(); @lock.Run();\n", "/* lock (z) { } */\n"):
            self.assertEqual(brace_csharp_bodies(text), text)

    def test_copy_sources_applies_language_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, dest = Path(tmp) / "p", Path(tmp) / "d"
            root.mkdir()
            dest.mkdir()
            (root / "A.cs").write_text("if (a) x();\n", encoding="utf-8")
            (root / "B.java").write_text("if (a) x();\n", encoding="utf-8")
            joern_active._copy_sources(root, [root / "A.cs"], dest, "csharp")
            joern_active._copy_sources(root, [root / "B.java"], dest, "java")
            self.assertEqual((dest / "A.cs").read_text(encoding="utf-8"), "if (a) { x(); }\n")
            self.assertEqual((dest / "B.java").read_text(encoding="utf-8"), "if (a) x();\n")


if __name__ == "__main__":
    unittest.main()
