"""27. tur: C/C++ derleme bilgisi (c_build) — yalnız metin okuma; clang --analyze dosya başına güvenli bayraklarla.

Kapsam: güvensiz bayrakların atılması, kök dışı include reddi, $(shell …) ifadesinin ÇALIŞTIRILMADIĞI (sahte yan
etkiyle), CMake / Make ayrıştırma örnekleri, compile_commands önceliği, bayrak etkisi (-DFOO olmadan görünmeyen kod).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock

import c_build
import memsafety_clang
import project_analyzer

DOUBLE_FREE_UNDER_FOO = textwrap.dedent("""
    #include <stdlib.h>
    void f(void) {
    #ifdef FOO
        char *p = malloc(8);
        free(p);
        free(p);
    #endif
    }
""")


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


class TempProject(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name).resolve()
        self.root = self.base / "proje"
        self.root.mkdir()
        self.outside = self.base / "disarida"
        self.outside.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def policy(self) -> c_build._PathPolicy:
        return c_build._PathPolicy(self.root)


class UnsafeFlagTests(TempProject):
    def test_unsafe_flags_are_dropped_and_safe_ones_kept(self):
        (self.root / "inc").mkdir()
        write(self.root / "cfg.h", "#define X 1\n")
        argv = ["/usr/bin/cc", "-o", "out.o", "-c", "src/a.c", "-Xclang", "-load", "-Xclang", "/tmp/evil.so",
                "-fplugin=/tmp/evil.so", "-fpass-plugin=/tmp/p.so", "-B/tmp/evil", "-B", "/tmp/evil2",
                "--sysroot=/tmp/sr", "--sysroot", "/tmp/sr2", "-isysroot", "/tmp/sr3", "@/tmp/resp.rsp",
                "-fcaret-diagnostics", "-fcolor-diagnostics", "-fdiagnostics-format=sarif", "-mllvm", "-print-x",
                "-fsanitize-ignorelist=/etc/passwd", "-fprofile-instr-use=/tmp/x.prof", "-fmodules-cache-path=/tmp/m",
                "-MF", "dep.d", "-MD", "-Wall", "-Werror", "-O2", "-g", "-x", "c++", "-imacros", "/etc/passwd",
                "-DFOO=1", "-D", "BAR", "-UBAZ", "-Iinc", "-I", "inc", "-std=gnu99", "-fno-strict-aliasing",
                "-fsigned-char", "-m64", "-march=x86-64", "-include", "cfg.h", "-D$(shell id)", "-D BAD NAME"]
        flags = c_build.filter_args(argv, self.root, self.policy())
        args = flags.to_args(".c")
        joined = " ".join(args)
        for bad in ("evil", "/tmp/sr", "resp.rsp", "caret", "color", "sarif", "mllvm", "print-x", "/etc/passwd",
                    "x.prof", "/tmp/m", "dep.d", "-Wall", "-Werror", "-O2", "-g", "c++", "-o", "-load", "shell"):
            self.assertNotIn(bad, joined, bad)
        self.assertEqual(flags.defines, ["-DFOO=1", "-DBAR", "-UBAZ"])
        self.assertEqual(flags.std, ["-std=gnu99"])
        self.assertEqual(flags.lang, ["-fno-strict-aliasing", "-fsigned-char", "-m64", "-march=x86-64"])
        self.assertEqual(flags.includes, [("-I", str(self.root / "inc")), ("-I", str(self.root / "inc"))])
        self.assertEqual(flags.forced, [str(self.root / "cfg.h")])
        # tekrarlanan include bir kez; C dosyasına C++ standardı verilmez
        self.assertEqual(args.count(str(self.root / "inc")), 1)
        cxx = c_build.filter_args(["-std=c++17", "-std=gnu11"], self.root, self.policy())
        self.assertEqual(cxx.to_args(".cpp"), ["-std=c++17"])
        self.assertEqual(cxx.to_args(".c"), ["-std=gnu11"])

    def test_clang_command_keeps_fixed_diagnostic_and_output_flags(self):
        cmd = memsafety_clang._command("/usr/bin/clang", self.root / "a.c", [self.root], ["-DFOO", "-I", str(self.root)])
        self.assertEqual(cmd[1:6], ["--analyze", "-o", "/dev/null", "-fno-caret-diagnostics", "-fno-color-diagnostics"])
        self.assertIn("-DFOO", cmd)
        self.assertIn("-idirafter", cmd)  # sezgisel dizinler sistem başlıklarını gölgelemez
        self.assertEqual(cmd[-1], str(self.root / "a.c"))
        legacy = memsafety_clang._command("/usr/bin/clang", self.root / "a.c", [self.root])
        self.assertNotIn("-I", legacy)  # bilgi yokken de sezgisel dizinler -idirafter ile (gölgeleme yok)
        self.assertIn("-idirafter", legacy)


class OutsideRootTests(TempProject):
    def test_include_outside_root_rejected_system_allowed(self):
        (self.root / "inc").mkdir()
        os.symlink(self.outside, self.root / "kacak")  # kök içinde, dışarıyı gösteren bağ
        write(self.outside / "secret.h", "#define S 1\n")
        argv = ["-I" + str(self.outside), "-I../disarida", "-Ikacak", "-isystem", str(self.outside), "-iquote",
                "../disarida", "-Iinc", "-include", str(self.outside / "secret.h"), "-include", "kacak/secret.h",
                "-I/etc", "-I/usr/include"]
        flags = c_build.filter_args(argv, self.root, self.policy())
        paths = [p for _, p in flags.includes]
        self.assertNotIn(str(self.outside), paths)
        self.assertFalse(any(p.startswith(str(self.outside)) or p == "/etc" for p in paths), paths)
        self.assertIn(str(self.root / "inc"), paths)
        self.assertEqual(flags.forced, [])
        if Path("/usr/include").is_dir():
            self.assertIn("/usr/include", paths)

    def test_cmake_and_make_outside_paths_rejected(self):
        write(self.root / "CMakeLists.txt", f"""
            include_directories({self.outside} ../disarida ${{CMAKE_CURRENT_SOURCE_DIR}}/../disarida)
            add_definitions(-DOK)
        """)
        write(self.root / "a.c", "int x;\n")
        info = c_build.load(self.root)
        ff = info.flags_for(self.root / "a.c")
        self.assertEqual(ff.source, c_build.SOURCE_CMAKE)
        self.assertEqual(ff.args, ["-DOK"])
        write(self.root / "m" / "Makefile", f"CFLAGS = -I{self.outside} -I../../disarida -DM\n")
        write(self.root / "m" / "b.c", "int y;\n")
        info = c_build.load(self.root)
        self.assertNotIn(str(self.outside), " ".join(info.flags_for(self.root / "m" / "b.c").args))


class NoExecutionTests(TempProject):
    def test_make_shell_and_cmake_execute_process_are_never_run(self):
        marker_dir = self.outside
        markers = [marker_dir / f"MARKER{i}" for i in range(1, 7)]
        write(self.root / "Makefile", f"""
            CFLAGS = -DA $(shell touch {markers[0]}) -Iinc
            CPPFLAGS += $(shell sh -c 'touch {markers[1]}') -DB
            X != touch {markers[2]}
            DEFS = -DV=$(shell touch {markers[3]})
            INCLUDES = `touch {markers[4]}`
            all:
            \ttouch {markers[5]}
        """)
        (self.root / "inc").mkdir()
        write(self.root / "a.c", "int main(void) { return 0; }\n")
        write(self.root / "sub" / "CMakeLists.txt", f"""
            execute_process(COMMAND touch {markers[0]})
            add_custom_command(OUTPUT x COMMAND touch {markers[1]})
            add_definitions(-DSUB)
        """)
        write(self.root / "sub" / "b.c", "int b;\n")
        real_popen = subprocess.Popen
        spawned: list[list[str]] = []

        def guard(*args, **kwargs):  # c_build hiçbir süreç başlatmamalı
            spawned.append(list(args[0]) if args else [])
            raise AssertionError("c_build süreç başlattı")

        with mock.patch.object(subprocess, "Popen", side_effect=guard), \
                mock.patch.object(os, "system", side_effect=guard), mock.patch.object(os, "popen", side_effect=guard):
            info = c_build.load(self.root)
            ff = info.flags_for(self.root / "a.c")
            fb = info.flags_for(self.root / "sub" / "b.c")
        self.assertEqual(spawned, [])
        self.assertIs(subprocess.Popen, real_popen)
        self.assertEqual(ff.source, c_build.SOURCE_MAKE)
        self.assertIn("-DA", ff.args)
        self.assertIn("-DB", ff.args)
        self.assertIn(str(self.root / "inc"), ff.args)
        self.assertFalse(any("touch" in a or "shell" in a or "MARKER" in a for a in ff.args), ff.args)
        self.assertFalse(any(a.startswith("-DV") for a in ff.args), ff.args)  # $(shell) değeri uydurulmaz
        self.assertEqual(fb.source, c_build.SOURCE_CMAKE)
        self.assertEqual(fb.args, ["-DSUB"])
        if memsafety_clang.binary():  # tam hat (clang dahil) de hiçbir proje komutunu çalıştırmaz
            with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
                memsafety_clang.analyze_files(self.root, [self.root / "a.c", self.root / "sub" / "b.c"], budget=30)
        for m in markers:
            self.assertFalse(m.exists(), f"yan etki oluştu: {m.name}")

    def test_module_does_not_import_process_apis(self):
        import ast

        tree = ast.parse(Path(c_build.__file__).read_text(encoding="utf-8"))
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                    for a in n.names} | {(n.module or "").split(".")[0] for n in ast.walk(tree)
                                         if isinstance(n, ast.ImportFrom)}
        self.assertFalse(imported & {"subprocess", "pty", "multiprocessing", "ctypes", "importlib", "runpy"}, imported)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
                self.assertFalse(node.attr in ("system", "popen", "fork", "forkpty") or
                                 node.attr.startswith(("exec", "spawn", "posix_spawn")), node.attr)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ("eval", "exec", "compile", "__import__"))


class CMakeParseTests(TempProject):
    def test_cmake_text_parsing_examples(self):
        for d in ("include", "api", "src", "win", "sub/private"):
            (self.root / d).mkdir(parents=True)
        write(self.root / "CMakeLists.txt", """
            cmake_minimum_required(VERSION 3.10)
            project(demo C)
            set(CMAKE_C_STANDARD 99)
            set(CMAKE_C_EXTENSIONS OFF)
            # add_definitions(-DCOMMENTED)
            include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include "${PROJECT_SOURCE_DIR}/src")
            add_definitions(-DFOO -DBAR=2 -Wall)
            add_compile_definitions(BAZ "QUUX=3")
            include_directories(${MY_UNKNOWN_VAR}/x $ENV{HOME}/y)
            if(WIN32)
              add_definitions(-DWINONLY)
              include_directories(win)
            endif()
            function(helper)
              add_definitions(-DINFUNC)
            endfunction()
            add_library(lib a.c)
            target_include_directories(lib PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/api>
                                           $<INSTALL_INTERFACE:include>)
            target_compile_definitions(lib PRIVATE LIBDEF=1)
            add_subdirectory(sub)
        """)
        write(self.root / "sub" / "CMakeLists.txt", """
            target_include_directories(subt PRIVATE private)
            set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS "SUBDEF")
            set(CMAKE_C_STANDARD 11)
        """)
        write(self.root / "a.c", "int a;\n")
        write(self.root / "sub" / "b.c", "int b;\n")
        write(self.root / "other.cpp", "int o;\n")
        info = c_build.load(self.root)
        a = info.flags_for(self.root / "a.c")
        self.assertEqual(a.source, c_build.SOURCE_CMAKE)
        self.assertIn("-std=c99", a.args)
        for d in ("-DFOO", "-DBAR=2", "-DBAZ", "-DQUUX=3", "-DLIBDEF=1"):
            self.assertIn(d, a.args)
        for d in ("-DCOMMENTED", "-DWINONLY", "-DINFUNC", "-DSUBDEF", "-Wall"):
            self.assertNotIn(d, a.args)
        joined = " ".join(a.args)
        for d in ("include", "src", "api", "win"):  # koşullu bloktaki include yolu alınır, -D alınmaz
            self.assertIn(str(self.root / d), joined)
        self.assertNotIn("/x", [p for p in a.args if p.endswith("/x")])
        b = info.flags_for(self.root / "sub" / "b.c")
        self.assertIn("-DSUBDEF", b.args)
        self.assertIn("-DFOO", b.args)  # üst dizin kapsamı alt dizine geçer
        self.assertIn(str(self.root / "sub" / "private"), b.args)
        self.assertIn("-std=c11", b.args)
        self.assertNotIn("-std=c99", b.args)
        self.assertNotIn("-std=c99", info.flags_for(self.root / "other.cpp").args)

    def test_cmake_tokenizer_handles_quotes_brackets_and_comments(self):
        cmds = c_build.cmake_commands(textwrap.dedent('''
            #[[ add_definitions(-DBLOCK) ]]
            add_definitions("-DQ=\\"x\\"" [[-DBRACKET]]) # add_definitions(-DTAIL)
            message(STATUS "a (b) c")
        '''))
        self.assertEqual(cmds[0], ("add_definitions", ['-DQ="x"', "-DBRACKET"]))
        self.assertEqual([c[0] for c in cmds], ["add_definitions", "message"])


class MakeParseTests(TempProject):
    def test_make_text_parsing_examples(self):
        for d in ("include", "lib", "win"):
            (self.root / d).mkdir()
        write(self.root / "Makefile", """
            VERSION := 1.2
            TOP ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
            WARN = -Wall -Wextra
            STD = -std=c99
            CFLAGS = -O2 $(WARN) $(STD) -Iinclude -DFOO \\
                     -DCONT=1
            CPPFLAGS += -DBAR=1
            INCLUDES = -I$(CURDIR)/lib -I$(TOP)/hidden
            DEFS = -DVER=$(VERSION) -DUNDEF=$(NOT_DEFINED)
            CXXFLAGS = -std=c++17 -DCXXONLY
            LDFLAGS = -L/opt/lib -DLDFLAG
            ifeq ($(OS),Windows_NT)
              CFLAGS += -DWIN -Iwin
            else
              CFLAGS += -DNOTWIN
            endif
            define RECIPE
            CFLAGS += -DINDEFINE
            endef
            prog: CFLAGS += -DTARGETSPECIFIC
            prog: main.o
            \t$(CC) $(CFLAGS) -DINRECIPE -o $@ $^
        """)
        write(self.root / "a.c", "int a;\n")
        write(self.root / "b.cpp", "int b;\n")
        info = c_build.load(self.root)
        a = info.flags_for(self.root / "a.c")
        self.assertEqual(a.source, c_build.SOURCE_MAKE)
        self.assertEqual(a.origin, "Makefile")
        for d in ("-DFOO", "-DCONT=1", "-DBAR=1", "-DVER=1.2", "-std=c99", str(self.root / "include"),
                  str(self.root / "lib"), str(self.root / "win")):
            self.assertIn(d, a.args)
        for d in ("-DWIN", "-DNOTWIN", "-DINDEFINE", "-DTARGETSPECIFIC", "-DINRECIPE", "-DLDFLAG", "-DCXXONLY",
                  "-Wall", "-O2", "-std=c++17"):
            self.assertNotIn(d, a.args)
        self.assertFalse(any("hidden" in x or "UNDEF" in x for x in a.args), a.args)
        b = info.flags_for(self.root / "b.cpp")
        self.assertIn("-std=c++17", b.args)
        self.assertIn("-DCXXONLY", b.args)
        self.assertNotIn("-std=c99", b.args)

    def test_mk_file_in_subdirectory_and_nearest_makefile_scope(self):
        write(self.root / "Makefile", "CFLAGS = -DTOPLEVEL\n")
        write(self.root / "mod" / "rules.mk", "CPPFLAGS += -DMODULE\n")
        write(self.root / "mod" / "m.c", "int m;\n")
        write(self.root / "x" / "deep" / "d.c", "int d;\n")
        info = c_build.load(self.root)
        m = info.flags_for(self.root / "mod" / "m.c")
        self.assertEqual((m.source, m.args, m.origin), (c_build.SOURCE_MAKE, ["-DMODULE"], "mod/rules.mk"))
        d = info.flags_for(self.root / "x" / "deep" / "d.c")
        self.assertEqual((d.source, d.args), (c_build.SOURCE_MAKE, ["-DTOPLEVEL"]))

    def test_no_build_info_means_yok(self):
        write(self.root / "a.c", "int a;\n")
        ff = c_build.load(self.root).flags_for(self.root / "a.c")
        self.assertEqual((ff.source, ff.args), (c_build.SOURCE_NONE, []))


class CompileCommandsTests(TempProject):
    def _db(self, path: Path, entries: list[dict]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entries), encoding="utf-8")

    def test_compile_commands_has_priority_over_cmake_and_make(self):
        (self.root / "include").mkdir()
        write(self.root / "CMakeLists.txt", "add_definitions(-DFROM_CMAKE)\n")
        write(self.root / "Makefile", "CFLAGS = -DFROM_MAKE\n")
        write(self.root / "a.c", "int a;\n")
        write(self.root / "b.c", "int b;\n")
        self._db(self.root / "build" / "compile_commands.json", [
            {"directory": str(self.root / "build"), "file": "../a.c",
             "command": "cc -DFROM_CC -I../include -o a.o -c ../a.c"},
        ])
        info = c_build.load(self.root)
        a = info.flags_for(self.root / "a.c")
        self.assertEqual(a.source, c_build.SOURCE_COMPILE_COMMANDS)
        self.assertEqual(a.args, ["-DFROM_CC", "-I", str(self.root / "include")])
        b = info.flags_for(self.root / "b.c")  # derleme veritabanında yok: sıradaki kaynak
        self.assertEqual((b.source, b.args), (c_build.SOURCE_CMAKE, ["-DFROM_CMAKE"]))
        self.assertEqual(info.summary()["compile_commands"], ["build/compile_commands.json"])

    def test_symlinked_compile_commands_is_not_followed(self):
        write(self.root / "a.c", "int a;\n")
        self._db(self.outside / "compile_commands.json", [
            {"directory": str(self.root), "file": "a.c", "arguments": ["cc", "-DEVIL", "-c", "a.c"]}])
        (self.root / "build").mkdir()
        os.symlink(self.outside / "compile_commands.json", self.root / "build" / "compile_commands.json")
        os.symlink(self.outside, self.root / "linkdir")
        ff = c_build.load(self.root).flags_for(self.root / "a.c")
        self.assertEqual(ff.source, c_build.SOURCE_NONE)

    def test_compile_commands_generated_elsewhere_is_remapped(self):
        (self.root / "src").mkdir()
        (self.root / "include").mkdir()
        write(self.root / "src" / "x.c", "int x;\n")
        self._db(self.root / "compile_commands.json", [
            {"directory": "/home/community-user/work/proj/build", "file": "/home/community-user/work/proj/src/x.c",
             "arguments": ["cc", "-I/home/community-user/work/proj/include", "-I/home/community-user/secret", "-DREMAP",
                           "-c", "/home/community-user/work/proj/src/x.c"]}])
        ff = c_build.load(self.root).flags_for(self.root / "src" / "x.c")
        self.assertEqual(ff.source, c_build.SOURCE_COMPILE_COMMANDS)
        self.assertEqual(ff.args, ["-DREMAP", "-I", str(self.root / "include")])


@unittest.skipUnless(memsafety_clang.binary(), "clang yok")
class FlagEffectTests(TempProject):
    def _kinds(self, result: dict) -> list[tuple[str, int, str]]:
        return sorted((f["kind"], f["line"], f.get("build_info")) for f in result["findings"])

    def test_code_under_ifdef_is_analyzed_only_with_define(self):
        write(self.root / "a.c", DOUBLE_FREE_UNDER_FOO)
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            plain = memsafety_clang.analyze_files(self.root, [self.root / "a.c"], budget=30, build_info=False)
            self.assertEqual(plain["findings"], [])
            write(self.root / "Makefile", "CFLAGS = -O2 -DFOO\n")
            res = memsafety_clang.analyze_files(self.root, [self.root / "a.c"], budget=30)
        self.assertIn(("double_free", 7, "make-metin"), self._kinds(res))
        self.assertEqual(res["build"]["files_by_source"], {"make-metin": 1})
        self.assertEqual(res["build"]["analyzed_with_flags"], 1)

    def test_compile_commands_define_reaches_clang(self):
        write(self.root / "a.c", DOUBLE_FREE_UNDER_FOO)
        (self.root / "build").mkdir()
        (self.root / "build" / "compile_commands.json").write_text(json.dumps([
            {"directory": str(self.root), "file": "a.c", "arguments": ["cc", "-DFOO", "-c", "a.c", "-o", "a.o"]}]),
            encoding="utf-8")
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            res = memsafety_clang.analyze_files(self.root, [self.root / "a.c"], budget=30)
        self.assertIn(("double_free", 7, "compile_commands"), self._kinds(res))

    def test_missing_generated_header_falls_back_to_plain_analysis(self):
        write(self.root / "a.c", """
            #ifdef HAVE_CONFIG_H
            #include "config_generated.h"
            #endif
            #include <stdlib.h>
            void f(void) { char *p = malloc(4); free(p); free(p); }
        """)
        write(self.root / "CMakeLists.txt", "add_definitions(-DHAVE_CONFIG_H)\n")
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            res = memsafety_clang.analyze_files(self.root, [self.root / "a.c"], budget=30)
        self.assertIn(("double_free", 6, "yok"), self._kinds(res))
        self.assertEqual(res["build"]["fallback_without_flags"], 1)
        self.assertEqual(res["build"]["files_by_source"], {"cmake-metin": 1})

    def test_project_report_records_build_source(self):
        proj = self.root / "p"
        write(proj / "a.c", DOUBLE_FREE_UNDER_FOO)
        write(proj / "Makefile", "CPPFLAGS = -DFOO\n")
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            report = project_analyzer.analyze_project(str(proj), allowed_roots=(self.root,))
        summary = report["clang_analysis"]
        self.assertIsNotNone(summary)
        self.assertEqual(summary["build"]["files_by_source"], {"make-metin": 1})
        self.assertEqual(summary["build"]["analyzed_with_flags"], 1)
        mems = [f for f in report["findings"] if f.get("memory_safety")]
        tagged = [f for f in mems if f["memory_safety"].get("build_info") == "make-metin"
                  or f["memory_safety"].get("clang_build_info") == "make-metin"]
        self.assertTrue(tagged, mems)
        for f in mems:
            if f["memory_safety"].get("engine") == "clang-analyzer":
                self.assertIn("Derleme bilgisi: make-metin", f["evidence"])


STUB_PROJECT_SOURCE = textwrap.dedent("""
    #include "gen_config.h"
    #include <stdlib.h>
    #ifndef GEN_CONFIG_INCLUDED
    void f(void) { char *p = malloc(4); free(p); free(p); }
    #endif
""")


@unittest.skipUnless(memsafety_clang.binary(), "clang yok")
class StubHeaderAndPriorityTests(TempProject):
    def _snapshot(self) -> dict[str, bytes]:
        return {str(p.relative_to(self.root)): p.read_bytes() for p in sorted(self.root.rglob("*")) if p.is_file()}

    def _run(self, **kw) -> dict:
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            return memsafety_clang.analyze_files(self.root, sorted(self.root.rglob("*.c")), budget=30, **kw)

    def test_missing_generated_header_gets_placeholder_and_is_marked(self):
        write(self.root / "a.c", STUB_PROJECT_SOURCE)
        write(self.root / "gen_config.h.in", "#cmakedefine X\n")  # üretilen başlığın şablonu (metin kanıtı)
        write(self.root / "CMakeLists.txt", "configure_file(gen_config.h.in gen_config.h)\nadd_definitions(-DA)\n")
        before = self._snapshot()
        res = self._run()
        self.assertEqual(self._snapshot(), before)  # proje dosyalarına hiçbir şey yazılmadı
        self.assertEqual([(f["kind"], f["line"], f["build_info"], f["stub_headers"]) for f in res["findings"]],
                         [("double_free", 5, "cmake-metin", ["gen_config.h"])])
        self.assertEqual(res["build"]["analyzed_with_stub_headers"], 1)
        self.assertEqual(res["build"]["stub_headers"], ["gen_config.h"])
        created: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def track(*a, **k):
            path = real_mkdtemp(*a, **k)
            created.append(path)
            return path

        with mock.patch.object(tempfile, "mkdtemp", side_effect=track):
            self._run()
        self.assertTrue(created)
        self.assertFalse(any(os.path.exists(p) for p in created))  # yer tutucu dizini taramadan sonra silinir
        self.assertFalse(any(p.startswith(str(self.root)) for p in created))

    def test_placeholder_needs_generated_evidence_and_quoted_include(self):
        write(self.root / "a.c", STUB_PROJECT_SOURCE)
        write(self.root / "Makefile", "CFLAGS = -DA\n")  # başlık hiçbir yapı dosyasında geçmiyor
        res = self._run()
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["build"]["analyzed_with_stub_headers"], 0)
        write(self.root / "Makefile", "CFLAGS = -DA\ngen_config.h:\n\techo > gen_config.h\n")
        write(self.root / "a.c", STUB_PROJECT_SOURCE.replace('"gen_config.h"', "<gen_config.h>"))
        res = self._run()  # <...> (sistem/dış bağımlılık) başlığa yer tutucu verilmez
        self.assertEqual(res["build"]["analyzed_with_stub_headers"], 0)
        write(self.root / "a.c", STUB_PROJECT_SOURCE)
        res = self._run()  # Make tarifinde üretiliyor + tırnaklı include: yer tutucu
        self.assertEqual(res["build"]["analyzed_with_stub_headers"], 1)
        res = self._run(stubs=False)
        self.assertEqual(res["build"]["analyzed_with_stub_headers"], 0)

    def test_project_header_shadowing_system_header_no_longer_breaks_analysis(self):
        write(self.root / "compat" / "stdint.h", '#error "Use this header only with MSVC"\n')
        write(self.root / "a.c", "#include <stdint.h>\n#include <stdlib.h>\n"
                                 "void f(void) { uint8_t *p = malloc(4); free(p); free(p); }\n")
        res = self._run(build_info=False)
        self.assertEqual([(f["kind"], f["line"]) for f in res["findings"]], [("double_free", 3)])

    def test_priority_and_input_reading_files_first(self):
        for name in ("aa.c", "bb.c", "cc.c"):
            write(self.root / name, "int x_%s;\n" % name[0])
        write(self.root / "zz_net.c", "#include <unistd.h>\nint g(int fd, char *b) { return (int)read(fd, b, 4); }\n")
        files = sorted(self.root.glob("*.c"))
        order: list[str] = []
        real = memsafety_clang._run_with_build

        def spy(clang, path, *a, **k):
            order.append(path.name)
            return real(clang, path, *a, **k)

        with mock.patch.object(memsafety_clang, "_run_with_build", side_effect=spy), \
                mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            res = memsafety_clang.analyze_files(self.root, files, budget=30, workers=1, priority=[self.root / "cc.c"])
        self.assertEqual(order[:2], ["cc.c", "zz_net.c"])
        self.assertEqual(res["build"]["priority_files"], 1)
        order.clear()
        with mock.patch.object(memsafety_clang, "_run_with_build", side_effect=spy), \
                mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            memsafety_clang.analyze_files(self.root, files, budget=30, workers=1, max_files=1,
                                          priority=[self.root / "bb.c"])
        self.assertEqual(order, ["bb.c"])  # dosya sınırı dolsa da öncelikli dosya çözümlenir

    def test_project_report_marks_placeholder_findings_low_and_possible(self):
        proj = self.root / "p"
        write(proj / "a.c", STUB_PROJECT_SOURCE)
        write(proj / "CMakeLists.txt", "configure_file(gen_config.h.in ${CMAKE_BINARY_DIR}/gen_config.h)\n")
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_ANALYZER": "1"}):
            report = project_analyzer.analyze_project(str(proj), allowed_roots=(self.root,))
        stubbed = [f for f in report["findings"] if (f.get("memory_safety") or {}).get("stub_headers")
                   or (f.get("memory_safety") or {}).get("clang_stub_headers")]
        self.assertTrue(stubbed, report["findings"])
        for f in stubbed:
            ms = f["memory_safety"]
            if ms.get("engine") == "clang-analyzer":
                self.assertIn("Yer tutucu başlıkla analiz edildi (eksik üretilen başlık: gen_config.h)", f["evidence"])
                self.assertEqual(f["severity"], "low")
                self.assertFalse(ms["certain"])
                self.assertTrue(f["title"].startswith("Olası"))
        self.assertEqual(report["clang_analysis"]["build"]["analyzed_with_stub_headers"], 1)


class AuthorSuppressionTests(TempProject):
    def test_gcc_use_after_free_pragma_suppresses_standalone_uaf(self):
        write(self.root / "x.c", """
            void *f(void *ptr, int n) {
              void *q = realloc(ptr, n);
              if (q != ptr) {
            #pragma GCC diagnostic ignored "-Wuse-after-free"
                table_del(ptr);
              }
              return q;
            }
        """)
        self.assertTrue(memsafety_clang.author_suppressed(self.root, "x.c", 6, "uaf"))
        self.assertFalse(memsafety_clang.author_suppressed(self.root, "x.c", 6, "overflow"))
        self.assertFalse(memsafety_clang.author_suppressed(self.root, "x.c", 3, "uaf"))


if __name__ == "__main__":
    unittest.main()
