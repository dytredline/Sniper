from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from project_analyzer import ProjectRejected
import threat_model_generator
import trufflehog_git_active


class ThreatModelProjectTreeTests(unittest.TestCase):
    def test_parent_swap_after_validation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-threat-tree-") as temp:
            base = Path(temp).resolve()
            checked_parent = base / "checked"
            project = checked_parent / "project"
            project.mkdir(parents=True)
            (project / "safe.txt").write_text("safe\n", encoding="utf-8")

            attacker_parent = base / "attacker"
            attacker_project = attacker_parent / "project"
            attacker_project.mkdir(parents=True)
            (attacker_project / "Dockerfile").write_text("FROM outside\n", encoding="utf-8")
            held_parent = base / "checked-held"
            real_validate = threat_model_generator.validate_project_path
            swapped = False

            def validate_then_swap(value, allowed_roots=None):
                nonlocal swapped
                validated = real_validate(value, allowed_roots)
                checked_parent.rename(held_parent)
                checked_parent.symlink_to(attacker_parent, target_is_directory=True)
                swapped = True
                return validated

            try:
                with mock.patch.object(
                    threat_model_generator,
                    "validate_project_path",
                    side_effect=validate_then_swap,
                ):
                    with self.assertRaises(ProjectRejected):
                        threat_model_generator.generate_threat_model(
                            project_path=str(project),
                            findings=[],
                            allowed_roots=(base,),
                        )
            finally:
                if checked_parent.is_symlink():
                    checked_parent.unlink()
                if held_parent.exists():
                    held_parent.rename(checked_parent)
            self.assertTrue(swapped)

    def test_normal_signals_are_preserved_and_symlinks_are_not_signals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-threat-signals-") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            (project / ".github" / "workflows").mkdir(parents=True)
            (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (project / "openapi.yaml").write_text("openapi: 3.0.0\n", encoding="utf-8")
            (project / "AndroidManifest.xml").write_text("<manifest/>\n", encoding="utf-8")
            (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            report = threat_model_generator.generate_threat_model(
                project_path=str(project), findings=[], allowed_roots=(base,)
            )
            self.assertEqual(
                report["project_signals"],
                ["github_actions", "container_runtime", "api_contract", "mobile_surface", "package_manifest"],
            )

            (project / "Dockerfile").unlink()
            outside = base / "outside-Dockerfile"
            outside.write_text("FROM outside\n", encoding="utf-8")
            (project / "Dockerfile").symlink_to(outside)
            report = threat_model_generator.generate_threat_model(
                project_path=str(project), findings=[], allowed_roots=(base,)
            )
            self.assertNotIn("container_runtime", report["project_signals"])


class GitHistoryProjectTreeTests(unittest.TestCase):
    @staticmethod
    def _repository(path: Path, filename: str) -> None:
        path.mkdir(parents=True)
        commands = (
            ["/usr/bin/git", "init", "-q", str(path)],
            ["/usr/bin/git", "-C", str(path), "config", "user.email", "test@example.invalid"],
            ["/usr/bin/git", "-C", str(path), "config", "user.name", "Test"],
        )
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (path / filename).write_text(filename + "\n", encoding="utf-8")
        subprocess.run(
            ["/usr/bin/git", "-C", str(path), "add", filename],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["/usr/bin/git", "-C", str(path), "commit", "-q", "-m", filename],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_validated_parent_swap_is_rejected_before_binary_lookup(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper-git-tree-") as temp:
            base = Path(temp).resolve()
            checked_parent = base / "checked"
            project = checked_parent / "project"
            attacker_parent = base / "attacker"
            attacker_project = attacker_parent / "project"
            self._repository(project, "safe.txt")
            self._repository(attacker_project, "outside.txt")
            held_parent = base / "checked-held"
            real_validate = trufflehog_git_active.validate_project_path
            swapped = False

            def validate_then_swap(value, *, allowed_roots=None):
                nonlocal swapped
                validated = real_validate(value, allowed_roots=allowed_roots)
                checked_parent.rename(held_parent)
                checked_parent.symlink_to(attacker_parent, target_is_directory=True)
                swapped = True
                return validated

            try:
                with mock.patch.object(
                    trufflehog_git_active,
                    "validate_project_path",
                    side_effect=validate_then_swap,
                ):
                    with self.assertRaises(trufflehog_git_active.GitHistoryInvalid):
                        trufflehog_git_active.run_local_trufflehog_git_history(str(project))
            finally:
                if checked_parent.is_symlink():
                    checked_parent.unlink()
                if held_parent.exists():
                    held_parent.rename(checked_parent)
            self.assertTrue(swapped)

    def test_open_git_tree_stages_original_bytes_after_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-git-stage-") as temp:
            base = Path(temp).resolve()
            checked_parent = base / "checked"
            project = checked_parent / "project"
            attacker_parent = base / "attacker"
            attacker_project = attacker_parent / "project"
            self._repository(project, "safe.txt")
            self._repository(attacker_project, "outside.txt")
            safe_index = (project / ".git" / "index").read_bytes()
            outside_index = (attacker_project / ".git" / "index").read_bytes()
            self.assertNotEqual(safe_index, outside_index)

            git_tree = trufflehog_git_active._required_git_dir(project)
            held_parent = base / "checked-held"
            checked_parent.rename(held_parent)
            checked_parent.symlink_to(attacker_parent, target_is_directory=True)
            temporary = None
            try:
                staged, temporary, _env = trufflehog_git_active._stage(
                    git_tree, Path("/usr/bin/git")
                )
                staged_index = (staged / ".git" / "index").read_bytes()
                self.assertEqual(staged_index, safe_index)
                self.assertNotEqual(staged_index, outside_index)
            finally:
                git_tree.close()
                if temporary is not None:
                    temporary.cleanup()
                if checked_parent.is_symlink():
                    checked_parent.unlink()
                if held_parent.exists():
                    held_parent.rename(checked_parent)

    def test_symlink_inside_selected_git_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-git-link-") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            self._repository(project, "safe.txt")
            outside = base / "outside-ref"
            outside.write_text("ref: refs/heads/main\n", encoding="utf-8")
            (project / ".git" / "refs" / "linked").symlink_to(outside)
            git_tree = trufflehog_git_active._required_git_dir(project)
            try:
                with self.assertRaises(trufflehog_git_active.GitHistoryInvalid):
                    trufflehog_git_active._stage(git_tree, Path("/usr/bin/git"))
            finally:
                git_tree.close()


if __name__ == "__main__":
    unittest.main()
