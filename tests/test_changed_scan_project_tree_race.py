"""Changed-scan keeps using the project directory validated at scan start."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import changed_scan
import project_analyzer
import scan_scope


GIT = shutil.which("git")


def _git(root: Path, *args: str) -> None:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    subprocess.run(
        [GIT, "-C", str(root), *args],
        check=True,
        capture_output=True,
        env=env,
    )


@unittest.skipUnless(GIT, "git yok")
class ChangedScanProjectTreeRaceTests(unittest.TestCase):
    def test_parent_swap_after_base_resolution_cannot_change_worktree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-changed-pinned-") as temporary:
            base = Path(temporary)
            original_parent = base / "original"
            root = original_parent / "repo"
            outside_parent = base / "outside"
            replacement = outside_parent / "repo"
            root.mkdir(parents=True)
            replacement.mkdir(parents=True)

            for repository in (root, replacement):
                _git(repository, "init", "-q")
                (repository / "safe.py").write_text("SAFE = True\n", encoding="utf-8")
                _git(repository, "add", ".")
                _git(repository, "commit", "-qm", "base")
            (replacement / "outside_only.py").write_text("OUTSIDE = True\n", encoding="utf-8")

            real_resolve = changed_scan.resolve_base
            swapped = False

            def resolve_then_swap(*args, **kwargs):
                nonlocal swapped
                resolved = real_resolve(*args, **kwargs)
                if not swapped:
                    swapped = True
                    original_parent.rename(base / "pinned-original")
                    original_parent.symlink_to(outside_parent, target_is_directory=True)
                return resolved

            scope = scan_scope.parse_scope({"changed_only": True, "base_ref": "HEAD"})
            with mock.patch.object(changed_scan, "resolve_base", side_effect=resolve_then_swap):
                result = changed_scan.analyze_changed(
                    str(root),
                    allowed_roots=(base,),
                    max_files=None,
                    scope=scope,
                )

            self.assertTrue(swapped)
            self.assertEqual(result["changed_scan"]["changed_files"], [])
            self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
