from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import taint_flow
import taint_js_ast
from project_tree import ProjectTree


class TaintProjectTreeTests(unittest.TestCase):
    def test_js_handler_collection_does_not_follow_a_replaced_project_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-taint-tree-") as temp:
            base = Path(temp)
            parent = base / "selected"
            project = parent / "project"
            project.mkdir(parents=True)
            (project / "routes.js").write_text(
                "router.get('/safe', safeHandler);\n",
                encoding="utf-8",
            )
            validated = project.resolve(strict=True)

            outside_parent = base / "outside"
            outside_project = outside_parent / "project"
            outside_project.mkdir(parents=True)
            (outside_project / "routes.js").write_text(
                "router.get('/outside', outsideSentinelHandler);\n",
                encoding="utf-8",
            )

            parent.rename(base / "selected-original")
            parent.symlink_to(outside_parent, target_is_directory=True)
            names = taint_flow.project_js_handler_names(validated, frozenset())

        self.assertNotIn("outsideSentinelHandler", names)
        self.assertEqual(names, frozenset())

    def test_path_iterator_contract_and_js_template_inventory_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-taint-view-tree-") as temp:
            base = Path(temp).resolve()
            parent = base / "selected"
            project = parent / "project"
            (project / "views").mkdir(parents=True)
            (project / "views" / "safe.ejs").write_text("<%= safe %>\n", encoding="utf-8")
            paths = list(taint_flow._walk_project_files(project, frozenset(), frozenset({".ejs"})))
            self.assertEqual([path.relative_to(project).as_posix() for path in paths], ["views/safe.ejs"])
            self.assertTrue(all(isinstance(path, Path) for path in paths))

            outside_parent = base / "outside"
            outside_project = outside_parent / "project"
            (outside_project / "views").mkdir(parents=True)
            (outside_project / "views" / "outside.ejs").write_text("<%= outside %>\n", encoding="utf-8")
            held_parent = base / "selected-held"

            with ProjectTree(project) as tree:
                token = taint_flow._PROJECT.set(SimpleNamespace(
                    root=project,
                    skip_dirs=frozenset(),
                    project_tree=tree,
                ))
                parent.rename(held_parent)
                parent.symlink_to(outside_parent, target_is_directory=True)
                try:
                    state = taint_js_ast.JsProject(None, max_steps=1_000)
                    state.template_root = project
                    self.assertEqual(state.view_inventory(), frozenset({"views/safe.ejs"}))
                finally:
                    taint_flow._PROJECT.reset(token)
                    parent.unlink()
                    held_parent.rename(parent)

    def test_serverless_config_is_read_from_the_pinned_project_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-taint-serverless-tree-") as temp:
            base = Path(temp).resolve()
            parent = base / "selected"
            project = parent / "project"
            project.mkdir(parents=True)
            safe = "functions:\n  safe:\n    handler: src/safe.run\n"
            (project / "serverless.yml").write_text(safe, encoding="utf-8")

            outside_parent = base / "outside"
            outside_project = outside_parent / "project"
            outside_project.mkdir(parents=True)
            (outside_project / "serverless.yml").write_text(
                "functions:\n  outside:\n    handler: src/outside.run\n",
                encoding="utf-8",
            )
            held_parent = base / "selected-held"

            with ProjectTree(project) as tree:
                token = taint_flow._PROJECT.set(SimpleNamespace(
                    root=project,
                    skip_dirs=frozenset(),
                    project_tree=tree,
                ))
                parent.rename(held_parent)
                parent.symlink_to(outside_parent, target_is_directory=True)
                try:
                    state = taint_js_ast.JsProject(None, max_steps=1_000)
                    state.template_root = project
                    self.assertEqual(state._serverless_configs(), [("serverless.yml", safe)])
                finally:
                    taint_flow._PROJECT.reset(token)
                    parent.unlink()
                    held_parent.rename(parent)


if __name__ == "__main__":
    unittest.main()
