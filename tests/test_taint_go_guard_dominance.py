"""Go path feasibility: filepath.IsLocal must dominate a sink through an early return."""
from __future__ import annotations

from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_goruby  # noqa: E402


def flows(source: str) -> list[tuple[str, int]]:
    result = taint_goruby.analyze_files(
        {"web/files.go": textwrap.dedent(source).lstrip("\n")},
        "go",
    )["web/files.go"]
    return sorted((flow.sink_kind, flow.line) for flow in result.flows)


class GoFilepathGuardDominanceTests(unittest.TestCase):
    def test_negative_islocal_guard_with_return_cleans_only_path(self) -> None:
        got = flows(
            """
            package web
            import (
                "net/http"
                "os"
                "os/exec"
                "path/filepath"
            )
            func Download(w http.ResponseWriter, r *http.Request) {
                name := r.URL.Query().Get("file")
                if !filepath.IsLocal(name) {
                    return
                }
                _, _ = os.ReadFile(filepath.Join("/srv/data", name))
                exec.Command("sh", "-c", "cat " + name).Run()
            }
            """
        )

        self.assertEqual(got, [("command", 14)])

    def test_aliased_filepath_import_has_the_same_guard_contract(self) -> None:
        got = flows(
            """
            package web
            import (
                "net/http"
                "os"
                fp "path/filepath"
            )
            func Download(w http.ResponseWriter, r *http.Request) {
                name := r.FormValue("file")
                if !fp.IsLocal(name) { return }
                _, _ = os.ReadFile(fp.Join("/srv/data", name))
            }
            """
        )

        self.assertEqual(got, [])

    def test_nondominating_or_wrong_polarity_checks_remain_findings(self) -> None:
        got = flows(
            """
            package web
            import (
                "log"
                "net/http"
                "os"
                "path/filepath"
            )
            func NonTerminating(w http.ResponseWriter, r *http.Request) {
                name := r.FormValue("a")
                if !filepath.IsLocal(name) { log.Print("bad") }
                _, _ = os.ReadFile(name)
            }
            func WrongPolarity(w http.ResponseWriter, r *http.Request) {
                name := r.FormValue("b")
                if filepath.IsLocal(name) { return }
                _, _ = os.ReadFile(name)
            }
            func NestedReturn(w http.ResponseWriter, r *http.Request) {
                name := r.FormValue("c")
                if !filepath.IsLocal(name) {
                    if r.Method == "GET" { return }
                }
                _, _ = os.ReadFile(name)
            }
            """
        )

        self.assertEqual(got, [("path", 11), ("path", 16), ("path", 23)])

    def test_reassignment_after_guard_does_not_inherit_clean_state(self) -> None:
        got = flows(
            """
            package web
            import (
                "net/http"
                "os"
                "path/filepath"
            )
            func Download(w http.ResponseWriter, r *http.Request) {
                name := r.FormValue("checked")
                if !filepath.IsLocal(name) { return }
                name = r.FormValue("replacement")
                _, _ = os.ReadFile(name)
            }
            """
        )

        self.assertEqual(got, [("path", 11)])

    def test_shadowed_filepath_import_is_not_trusted_as_the_stdlib_guard(self) -> None:
        got = flows(
            """
            package web
            import (
                "net/http"
                "os"
                "path/filepath"
            )
            type localValidator struct{}
            func (localValidator) IsLocal(string) bool { return true }
            func Download(w http.ResponseWriter, r *http.Request) {
                _ = filepath.Separator
                filepath := localValidator{}
                name := r.FormValue("file")
                if !filepath.IsLocal(name) { return }
                _, _ = os.ReadFile(name)
            }
            """
        )

        self.assertEqual(got, [("path", 14)])


if __name__ == "__main__":
    unittest.main()

