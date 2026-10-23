from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "release.yml",
)
EXPECTED_PINS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1", 2),
    "actions/setup-python": ("6d4fd22b20465ccc0f7354476588e8df7c9ca0e0", "v7.1.0", 2),
    "actions/setup-node": ("949feb2413d6458794dcd2491c4babbbce0c15c1", "v7.1.0", 1),
    "actions/upload-artifact": ("cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2", 1),
}
USES_PATTERN = re.compile(r"(?m)^\s*-\s+uses:\s+([^\s#]+)(?:\s+#\s*(\S+))?\s*$")


class GithubActionPinTests(unittest.TestCase):
    def test_every_action_is_pinned_to_the_reviewed_commit(self) -> None:
        observed: dict[str, list[tuple[str, str | None, str]]] = {}
        for workflow in WORKFLOWS:
            for reference, comment in USES_PATTERN.findall(workflow.read_text(encoding="utf-8")):
                action, separator, revision = reference.partition("@")
                self.assertTrue(separator, f"{workflow.name}: missing action revision: {reference}")
                observed.setdefault(action, []).append((revision, comment or None, workflow.name))

        self.assertEqual(set(observed), set(EXPECTED_PINS), observed)
        for action, (expected_sha, expected_version, expected_count) in EXPECTED_PINS.items():
            with self.subTest(action=action):
                references = observed[action]
                self.assertEqual(len(references), expected_count, references)
                for revision, comment, workflow_name in references:
                    self.assertRegex(revision, r"^[0-9a-f]{40}$", workflow_name)
                    self.assertEqual(revision, expected_sha, workflow_name)
                    self.assertEqual(comment, expected_version, workflow_name)


if __name__ == "__main__":
    unittest.main()
