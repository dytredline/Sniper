"""26. tur: C/C++ bellek güvenliği motoru (memsafety_c), clang ek analizörü (memsafety_clang) ve proje analizi
entegrasyonu — olumlu (açık bulunur) ve olumsuz (güvenli kalıp bulgu vermez) örnekler."""
from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import eval_metrics
import i18n_server
import memsafety_c
import memsafety_clang
import project_analyzer


def mem(src: str, name: str = "t.c", headers=()) -> list[memsafety_c.MemFinding]:
    return memsafety_c.analyze_text(textwrap.dedent(src), name, headers=headers) if headers else \
        memsafety_c.analyze_text(textwrap.dedent(src), name)


def kinds(findings, certain_only: bool = False) -> list[tuple[str, int]]:
    return sorted((f.kind, f.line) for f in findings if f.certain or not certain_only)


class OverflowTests(unittest.TestCase):
    def test_literal_longer_than_stack_buffer(self):
        fs = mem("""
            #include <string.h>
            void f(void) {
                char buf[16];
                strcpy(buf, "this string is longer than sixteen");
            }
        """)
        self.assertEqual(kinds(fs, True), [("overflow", 5)])
        self.assertEqual(fs[0].cwe, "CWE-121")
        self.assertEqual(fs[0].buffer, "buf")
        self.assertEqual(fs[0].buffer_line, 4)
        self.assertTrue(fs[0].title.startswith("Doğrulanmış bellek hatası"))

    def test_argv_unbounded_copy_and_length_guard(self):
        bad = mem("""
            #include <string.h>
            int main(int argc, char **argv) {
                char buf[32];
                strcpy(buf, argv[1]);
                return 0;
            }
        """)
        self.assertEqual(kinds(bad, True), [("overflow_taint", 5)])
        self.assertEqual(bad[0].source_line, 3)
        self.assertEqual(bad[0].cwe, "CWE-120")
        good = mem("""
            #include <string.h>
            int main(int argc, char **argv) {
                char buf[32];
                if (strlen(argv[1]) < sizeof(buf)) strcpy(buf, argv[1]);
                snprintf(buf, sizeof(buf), "%s", argv[1]);
                strncpy(buf, argv[1], sizeof(buf) - 1);
                return 0;
            }
        """)
        self.assertEqual(kinds(good), [])

    def test_known_lengths_from_memset_and_terminator(self):
        fs = mem("""
            #include <string.h>
            void f(void) {
                char src[100];
                char small[50];
                char big[100];
                memset(src, 'A', 99);
                src[99] = '\\0';
                strcpy(small, src);
                strcpy(big, src);
            }
        """)
        self.assertEqual(kinds(fs, True), [("overflow", 9)])

    def test_loop_off_by_one_and_safe_loop(self):
        fs = mem("""
            #define N 10
            void f(void) {
                char a[N];
                int i;
                for (i = 0; i <= N; i++) a[i] = 'x';
                for (i = 0; i < N; i++) a[i] = 'y';
                a[N - 1] = 0;
            }
        """)
        self.assertEqual(kinds(fs, True), [("off_by_one", 6)])
        self.assertEqual(fs[0].cwe, "CWE-193")

    def test_bounded_functions_with_wrong_and_right_size(self):
        fs = mem("""
            #include <string.h>
            #include <stdio.h>
            void f(const char *s) {
                char d[32];
                strncpy(d, s, 64);
                strncpy(d, s, sizeof(d));
                snprintf(d, sizeof d, "%s", s);
                memcpy(d, s, sizeof(d));
                memcpy(d, s, 40);
            }
        """)
        self.assertEqual(kinds(fs, True), [("overflow", 6), ("overflow", 10)])

    def test_symbolic_heap_size_read_length(self):
        fs = mem("""
            #include <stdio.h>
            #include <stdlib.h>
            void up(int len) {
                char *buffer = malloc(len + 1);
                if (!buffer) return;
                fread(buffer, 1, len + 100, stdin);
                buffer[len] = 0;
                free(buffer);
            }
            void ok(int len) {
                char *b = malloc(len + 1);
                if (!b) return;
                fread(b, 1, len, stdin);
                free(b);
            }
        """)
        self.assertEqual(kinds(fs, True), [("overflow", 7)])

    def test_strlen_allocation_off_by_one(self):
        fs = mem("""
            #include <string.h>
            #include <stdlib.h>
            char *dup1(const char *s) { char *p = malloc(strlen(s)); strcpy(p, s); return p; }
            char *dup2(const char *s) { char *p = malloc(strlen(s) + 1); strcpy(p, s); return p; }
        """)
        self.assertEqual(kinds(fs, True), [("off_by_one", 4)])

    def test_scanf_widths(self):
        fs = mem("""
            #include <stdio.h>
            void f(void) {
                char s[20];
                scanf("%s", s);
                scanf("%19s", s);
                scanf("%20s", s);
            }
        """)
        self.assertEqual(kinds(fs, True), [("off_by_one", 7), ("overflow_taint", 5)])

    def test_underwrite_through_negative_offset(self):
        fs = mem("""
            #include <string.h>
            void f(void) {
                char buf[100];
                char *data = buf - 8;
                strcpy(data, "abc");
            }
        """)
        self.assertEqual(kinds(fs, True), [("underwrite", 6)])


class LifetimeTests(unittest.TestCase):
    def test_use_after_free_and_double_free(self):
        fs = mem("""
            #include <stdlib.h>
            void f(void) {
                char *p = malloc(10);
                free(p);
                p[0] = 'a';
                free(p);
            }
        """)
        self.assertEqual(kinds(fs, True), [("double_free", 7), ("uaf", 6)])
        self.assertEqual(fs[0].source_line, 5)

    def test_null_after_free_and_reallocation_are_safe(self):
        fs = mem("""
            #include <stdlib.h>
            void f(int n) {
                char *p = malloc(10);
                free(p);
                p = NULL;
                free(p);
                char *q = malloc(4);
                free(q);
                q = malloc(8);
                q[0] = 1;
                free(q);
                for (int i = 0; i < n; i++) { char *r = malloc(5); r[0] = 0; free(r); }
            }
        """)
        self.assertEqual(kinds(fs), [])

    def test_alias_use_after_free(self):
        fs = mem("""
            #include <stdlib.h>
            #include <stdio.h>
            char *global_buffer;
            void f(int len) {
                char *buffer = malloc(len + 1);
                global_buffer = buffer;
                free(buffer);
                printf("%s", global_buffer);
            }
        """)
        self.assertEqual(kinds(fs, True), [("uaf", 9)])

    def test_conditional_free_is_possible_not_certain(self):
        fs = mem("""
            #include <stdlib.h>
            void use(char *);
            void f(int c) {
                char *p = malloc(10);
                if (c) free(p);
                p[0] = 1;
            }
        """)
        self.assertEqual(kinds(fs), [("uaf", 7)])
        self.assertFalse(fs[0].certain)
        self.assertTrue(fs[0].title.startswith("Olası bellek hatası"))

    def test_free_wrappers_inlined(self):
        fs = mem("""
            #include <stdlib.h>
            static void release(char *p) { free(p); }
            void f(void) {
                char *p = malloc(10);
                release(p);
                release(p);
            }
        """)
        self.assertIn(("double_free", 3), kinds(fs, True))

    def test_free_of_stack_and_alias_refinement(self):
        fs = mem("""
            #include <stdlib.h>
            void f(int big) {
                char stackbuf[64];
                char *p = big ? malloc(1024) : stackbuf;
                if (p != stackbuf) free(p);
                char arr[8];
                free(arr);
            }
        """)
        self.assertEqual(kinds(fs, True), [("free_nonheap", 8)])
        self.assertEqual(fs[0].cwe, "CWE-590")

    def test_mismatched_new_free_cpp(self):
        fs = mem("""
            #include <cstdlib>
            void f() {
                char *a = new char[10];
                free(a);
                char *b = (char *)malloc(10);
                delete b;
                char *c = new char[4];
                delete[] c;
            }
        """, "t.cpp")
        self.assertEqual(kinds(fs, True), [("mismatch_free", 5), ("mismatch_free", 7)])

    def test_flag_correlated_literal_free_not_certain(self):
        fs = mem("""
            #include <stdlib.h>
            int check(char **err);
            void f(void) {
                char *err = NULL;
                int need_free = 0;
                check(&err);
                if (err == NULL) err = "";
                else need_free = 1;
                if (need_free) free(err);
            }
        """)
        self.assertEqual(kinds(fs, True), [])

    def test_constant_condition_folding(self):
        fs = mem("""
            #include <stdlib.h>
            static int staticFalse = 0;
            void f(void) {
                char *data = malloc(100);
                if (staticFalse) { free(data); }
                free(data);
                switch (6) { case 6: break; default: free(data); break; }
            }
        """)
        self.assertEqual(kinds(fs), [])


class FormatAndAllocTests(unittest.TestCase):
    def test_file_content_as_format_string(self):
        fs = mem("""
            #include <stdio.h>
            void f(void) {
                char buf[128];
                FILE *fp = fopen("x.txt", "r");
                fgets(buf, sizeof(buf), fp);
                printf(buf);
                printf("%s", buf);
            }
        """)
        self.assertEqual(kinds(fs, True), [("format", 7)])
        self.assertEqual(fs[0].cwe, "CWE-134")
        self.assertEqual(fs[0].source_line, 6)

    def test_tainted_allocation_size_and_checked_variant(self):
        fs = mem("""
            #include <stdio.h>
            #include <stdlib.h>
            void bad(void) { int n; scanf("%d", &n); int *q = malloc(n * sizeof(int)); free(q); }
            void good(void) { int n; scanf("%d", &n); if (n > 0 && n < 1000) { int *q = malloc(n * sizeof(int)); free(q); } }
            void cal(void) { int n; scanf("%d", &n); int *q = calloc(n, sizeof(int)); free(q); }
        """)
        self.assertEqual(kinds(fs, True), [("alloc_overflow", 4)])
        self.assertEqual(fs[0].cwe, "CWE-680")


class InterproceduralTests(unittest.TestCase):
    def test_file_data_through_parameter_into_fixed_buffer(self):
        fs = mem("""
            #include <stdio.h>
            #include <string.h>
            int bof(char *str) {
                char buffer[24];
                strcpy(buffer, str);
                return 1;
            }
            int main(void) {
                char str[517];
                FILE *badfile = fopen("badfile", "r");
                fread(str, sizeof(char), 517, badfile);
                bof(str);
                return 0;
            }
        """)
        self.assertEqual(kinds(fs, True), [("overflow_taint", 6)])
        self.assertEqual(fs[0].function, "bof")
        self.assertIn("main() satır 13", fs[0].evidence)

    def test_size_bounded_writer_called_with_too_large_size(self):
        fs = mem("""
            #define MAXLINE 1024
            typedef struct { char filename[512]; long offset; } http_request;
            void url_decode(char *src, char *dest, int max) {
                char *p = src;
                while (*p && --max) {
                    *dest++ = *p++;
                }
                *dest = '\\0';
            }
            void parse(http_request *req, char *uri) {
                url_decode(uri, req->filename, MAXLINE);
            }
            void parse_ok(http_request *req, char *uri) {
                url_decode(uri, req->filename, sizeof(req->filename));
            }
        """)
        self.assertEqual(kinds(fs, True), [("overflow", 7)])
        self.assertIn("req->filename", fs[0].evidence)

    def test_struct_and_macro_from_project_header(self):
        header = "#define NAME_MAX_LEN 8\ntypedef struct { char name[NAME_MAX_LEN]; int id; } user_t;\n"
        src = """
            #include <string.h>
            #include "user.h"
            void set(user_t *u) { strcpy(u->name, "much too long a name"); }
        """
        self.assertEqual(kinds(mem(src)), [])
        fs = mem(src, headers=[("user.h", header)])
        self.assertEqual(kinds(fs, True), [("overflow", 4)])


class ProjectIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.project = self.root / "proj"
        self.project.mkdir()
        self.env = mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "0"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def analyze(self):
        return project_analyzer.analyze_project(str(self.project), allowed_roots=(self.root,))

    def test_regex_rule_only_in_c_family_files(self):
        (self.project / "page.php").write_text("<?php\n$x = sprintf('%s', $y);\nstrcpy($a, $b);\n", encoding="utf-8")
        (self.project / "tool.js").write_text("const s = sprintf('%s', x); strcat(a, b);\n", encoding="utf-8")
        (self.project / "a.c").write_text("#include <string.h>\nvoid f(char *u){ char b[8]; strcpy(b, u); }\n",
                                          encoding="utf-8")
        result = self.analyze()
        hits = [(f["file"], f["line"]) for f in result["findings"] if f["title"] == project_analyzer.C_OVERFLOW_RULE_TITLE]
        self.assertEqual(hits, [("a.c", 2)])

    def test_memsafety_finding_shape_evidence_and_scoring(self):
        (self.project / "vuln.c").write_text(textwrap.dedent("""
            #include <stdlib.h>
            #include <string.h>
            void f(void) {
                char *p = malloc(10);
                free(p);
                strcpy(p, "x");
            }
        """), encoding="utf-8")
        result = self.analyze()
        mems = [f for f in result["findings"] if f.get("memory_safety")]
        self.assertEqual(len(mems), 1)
        f = mems[0]
        self.assertEqual((f["file"], f["line"], f["reference"]), ("vuln.c", 7, "CWE-416"))
        self.assertTrue(f["title"].startswith("Doğrulanmış bellek hatası"))
        self.assertIn("Kanıt:", f["evidence"])
        self.assertIn("kaynak satır 6", f["evidence"])
        self.assertIn("hedef satır 7", f["evidence"])
        self.assertIn("tanımı satır 5", f["evidence"])
        self.assertEqual(f["memory_safety"]["sink_line"], 7)
        self.assertEqual(f["memory_safety"]["engine"], "sniper-memsafety")
        self.assertTrue(eval_metrics.is_verified_flow(f))
        self.assertEqual(eval_metrics.sniper_classes(f["reference"]), frozenset({"mem"}))
        # aynı satırdaki strcpy desen bulgusu bellek bulgusuyla birleşir (iki kez raporlanmaz)
        self.assertFalse(any(x["title"] == project_analyzer.C_OVERFLOW_RULE_TITLE and x["line"] == 7
                             for x in result["findings"]))

    def test_taint_flow_line_not_duplicated(self):
        (self.project / "cli.c").write_text(textwrap.dedent("""
            #include <string.h>
            int main(int argc, char **argv) {
                char buf[16];
                strcpy(buf, argv[1]);
                return 0;
            }
        """), encoding="utf-8")
        result = self.analyze()
        on_line = [f for f in result["findings"] if f["line"] == 5 and eval_metrics.sniper_classes(f["reference"])]
        self.assertEqual(len(on_line), 1, on_line)

    def test_bounded_sprintf_regex_hit_downgraded(self):
        (self.project / "fmt.c").write_text(textwrap.dedent("""
            #include <stdio.h>
            void f(int line, int col) {
                char error[128];
                sprintf(error, "Unexpected EOF (at %d:%d)", line, col);
            }
        """), encoding="utf-8")
        result = self.analyze()
        hit = [f for f in result["findings"] if f["title"] == project_analyzer.C_OVERFLOW_RULE_TITLE]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "low")
        self.assertEqual(hit[0]["taint_verdict"], "memsafety_bounded")

    def test_ino_is_c_family(self):
        (self.project / "sketch.ino").write_text("void loop() { char b[4]; strcpy(b, \"12345678\"); }\n", encoding="utf-8")
        result = self.analyze()
        self.assertEqual(result["languages"].get("C/C++"), 1)
        self.assertTrue(any(f.get("memory_safety") for f in result["findings"]))

    def test_new_titles_translated(self):
        tr = i18n_server.translator()
        for title in memsafety_c.ALL_TITLES:
            html = i18n_server.localize_html(f"<p>{title}</p>", "en")
            self.assertNotIn(title, html, title)


class RustUnsafeTests(unittest.TestCase):
    def test_from_raw_parts_length_and_get_unchecked(self):
        import memsafety_rust

        src = textwrap.dedent("""
            pub unsafe fn read_all(data: &[u8], n: usize) -> u64 {
                let view = std::slice::from_raw_parts(data.as_ptr(), n);
                view.iter().map(|&b| b as u64).sum()
            }
            pub fn ok(data: &[u8], n: usize) -> u64 {
                let m = n.min(data.len());
                let view = unsafe { std::slice::from_raw_parts(data.as_ptr(), m) };
                let all = unsafe { std::slice::from_raw_parts(data.as_ptr(), data.len()) };
                view.len() as u64 + all.len() as u64
            }
            pub fn idx(v: &[u32], i: usize) -> u32 { unsafe { *v.get_unchecked(i) } }
            pub fn idx_ok(v: &[u32], i: usize) -> u32 { assert!(i < v.len()); unsafe { *v.get_unchecked(i) } }
            extern "C" fn cb(data: *const u8, len: usize) -> i32 {
                let b = unsafe { std::slice::from_raw_parts(data, len) };
                b.len() as i32
            }
            pub fn twice(p: *mut u8) { unsafe { let a = Box::from_raw(p); let b = Box::from_raw(p); } }
        """)
        fs = memsafety_rust.analyze_text(src, "lib.rs")
        self.assertEqual(sorted((f.kind, f.line) for f in fs), [("double_free", 18), ("overread", 3), ("overread", 12)])
        self.assertTrue(all(not f.certain for f in fs))


class ClangTests(unittest.TestCase):
    def test_parse_output_classifies_and_drops_outside_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.c").write_text("int main(){return 0;}\n", encoding="utf-8")
            text = "\n".join([
                f"{root}/a.c:12:5: warning: Attempt to free released memory [unix.Malloc]",
                f"{root}/a.c:20:3: warning: Use of memory after it is freed [unix.Malloc]",
                f"{root}/a.c:30:3: warning: String copy function overflows the destination buffer [alpha.unix.cstring.OutOfBounds]",
                f"{root}/a.c:31:3: warning: Potential leak of memory pointed to by 'q' [unix.Malloc]",
                "/usr/include/string.h:5:1: warning: Use of memory after it is freed [unix.Malloc]",
            ])
            out = memsafety_clang.parse_output(text, root)
        self.assertEqual([(x["file"], x["line"], x["kind"]) for x in out],
                         [("a.c", 12, "double_free"), ("a.c", 20, "uaf"), ("a.c", 30, "overflow")])

    def test_unavailable_binary_is_skipped_gracefully(self):
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_BINARY": "/nonexistent/clang"}):
            res = memsafety_clang.analyze_files(Path("."), [Path("x.c")])
        self.assertEqual(res["status"], "unavailable")
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "0"}):
            self.assertIsNone(memsafety_clang.binary())

    @unittest.skipUnless(memsafety_clang.binary(), "clang yok")
    def test_clang_confirms_native_finding_without_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proj = root / "p"
            proj.mkdir()
            (proj / "uaf.c").write_text(textwrap.dedent("""
                #include <stdlib.h>
                #include <string.h>
                void f(void) {
                    char *p = malloc(10);
                    free(p);
                    strcpy(p, "x");
                }
            """), encoding="utf-8")
            with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
                result = project_analyzer.analyze_project(str(proj), allowed_roots=(root,))
        mems = [f for f in result["findings"] if f.get("memory_safety")]
        lines = [f["line"] for f in mems]
        self.assertEqual(len(lines), len(set(lines)), mems)
        self.assertTrue(all(f["memory_safety"].get("engine") != "clang-analyzer" or f["line"] != 7 for f in mems))


if __name__ == "__main__":
    unittest.main()
