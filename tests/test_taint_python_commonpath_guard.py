"""Python path feasibility for a realpath + commonpath containment guard."""
from __future__ import annotations

from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from taint_flow import analyze_python  # noqa: E402


def flows(body: str) -> list[tuple[str, int]]:
    source = "from flask import request\n" + textwrap.dedent(body).lstrip("\n")
    return sorted((flow.sink_kind, flow.line) for flow in analyze_python(source).flows)


class PythonCommonpathGuardTests(unittest.TestCase):
    def test_realpath_commonpath_early_abort_cleans_only_canonical_path(self) -> None:
        got = flows(
            """
            import os
            from flask import abort
            ROOT = "/srv/files"
            @app.get("/download")
            def download():
                name = request.args["name"]
                joined = os.path.join(ROOT, name)
                candidate = os.path.realpath(joined)
                if os.path.commonpath([ROOT, candidate]) != ROOT:
                    abort(400)
                open(candidate).read()
                os.system(candidate)
            """
        )

        self.assertEqual(got, [("command", 13)])

    def test_from_import_aliases_have_the_same_containment_contract(self) -> None:
        got = flows(
            """
            from os.path import commonpath as within, join, realpath
            from flask import abort
            ROOT = "/srv/files"
            @app.get("/download")
            def download():
                name = request.args["name"]
                joined = join(ROOT, name)
                candidate = realpath(joined)
                if within((ROOT, candidate)) != ROOT:
                    abort(400)
                open(candidate).read()
            """
        )

        self.assertEqual(got, [])

    def test_unguarded_commonprefix_and_wrong_polarity_remain_findings(self) -> None:
        got = flows(
            """
            import os
            from flask import abort
            ROOT = "/srv/files"
            def unguarded():
                raw = request.args["a"]
                candidate = os.path.realpath(os.path.join(ROOT, raw))
                open(candidate).read()
            def lexical_prefix_only():
                raw = request.args["b"]
                candidate = os.path.realpath(os.path.join(ROOT, raw))
                if os.path.commonprefix([ROOT, candidate]) != ROOT:
                    abort(400)
                open(candidate).read()
            def wrong_polarity():
                raw = request.args["c"]
                candidate = os.path.realpath(os.path.join(ROOT, raw))
                if os.path.commonpath([ROOT, candidate]) == ROOT:
                    abort(400)
                open(candidate).read()
            def nonterminating():
                raw = request.args["d"]
                candidate = os.path.realpath(os.path.join(ROOT, raw))
                if os.path.commonpath([ROOT, candidate]) != ROOT:
                    print("outside")
                open(candidate).read()
            """
        )

        self.assertEqual(got, [("path", 8), ("path", 14), ("path", 20), ("path", 26)])

    def test_guard_does_not_clean_raw_input_or_non_realpath_candidate(self) -> None:
        got = flows(
            """
            import os
            from flask import abort
            ROOT = "/srv/files"
            def raw_reuse():
                raw = request.args["a"]
                joined = os.path.join(ROOT, raw)
                candidate = os.path.realpath(joined)
                if os.path.commonpath([ROOT, candidate]) != ROOT:
                    abort(400)
                open(candidate).read()
                open(raw).read()
            def no_realpath():
                raw = request.args["b"]
                candidate = os.path.abspath(os.path.join(ROOT, raw))
                if os.path.commonpath([ROOT, candidate]) != ROOT:
                    abort(400)
                open(candidate).read()
            """
        )

        self.assertEqual(got, [("path", 12), ("path", 18)])

    def test_conditional_realpath_or_tainted_root_cannot_supply_the_proof(self) -> None:
        got = flows(
            """
            import os
            from flask import abort
            ROOT = "/srv/files"
            def conditional(flag):
                raw = request.args["a"]
                candidate = os.path.join(ROOT, raw)
                if flag:
                    candidate = os.path.realpath(candidate)
                if os.path.commonpath([ROOT, candidate]) != ROOT:
                    abort(400)
                open(candidate).read()
            def tainted_root():
                root = request.args["root"]
                raw = request.args["b"]
                candidate = os.path.realpath(os.path.join(root, raw))
                if os.path.commonpath([root, candidate]) != root:
                    abort(400)
                open(candidate).read()
            """
        )

        self.assertEqual(got, [("path", 12), ("path", 19), ("path", 19)])


if __name__ == "__main__":
    unittest.main()

