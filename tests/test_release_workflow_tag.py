from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
VERSION_PATH = ROOT / "COMMUNITY_VERSION"


class TestCommunityRelease(unittest.TestCase):
    def test_workflow_publishes_validated_tag_assets_without_overwrite(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        version = VERSION_PATH.read_text(encoding="utf-8").strip()

        self.assertEqual(version, "1.1.0")
        self.assertRegex(version, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertIn('tags: ["v*"]', workflow)
        self.assertIn("VERSION=$(tr -d '\\n\\r' < COMMUNITY_VERSION)", workflow)
        self.assertIn('"${GITHUB_REF_NAME}" != "v${VERSION}"', workflow)
        self.assertIn('RELEASE_TREE="${RUNNER_TEMP}/sniper-community-${VERSION}"', workflow)
        self.assertIn('RELEASE_ARCHIVE="${GITHUB_WORKSPACE}/sniper-community-${VERSION}.tar.gz"', workflow)
        self.assertIn('python scripts/build-community-source.py --output "${RELEASE_TREE}"', workflow)
        self.assertNotIn(
            'python scripts/build-community-source.py --output "sniper-community-${VERSION}"',
            workflow,
        )
        self.assertIn('--root "${RELEASE_TREE}" --scan-release-tree', workflow)
        self.assertIn('-C "${RUNNER_TEMP}"', workflow)
        self.assertIn("--scan-release-tree", workflow)
        self.assertIn("tar --sort=name --mtime='UTC 1970-01-01'", workflow)
        self.assertIn('-czf "${RELEASE_ARCHIVE}"', workflow)
        self.assertIn('sha256sum "sniper-community-${VERSION}.tar.gz"', workflow)
        self.assertIn(
            "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2",
            workflow,
        )
        self.assertIn("permissions:\n  contents: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("artifact-metadata: write", workflow)
        self.assertIn(
            "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
            workflow,
        )
        self.assertIn("subject-path: sniper-community-*.tar.gz", workflow)
        self.assertIn("if: github.ref_type == 'tag'", workflow)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
        self.assertIn('gh release create "v${VERSION}"', workflow)
        self.assertIn('"sniper-community-${VERSION}.tar.gz"', workflow)
        self.assertIn('"SHA256SUMS"', workflow)
        self.assertIn("--verify-tag", workflow)
        self.assertNotIn("--clobber", workflow)
        self.assertNotIn("Sniper Enterprise", workflow)
        self.assertNotIn("from version import", workflow)

    def test_public_release_documents_do_not_claim_candidate_status(self) -> None:
        texts = [
            (ROOT / "README.md").read_text(encoding="utf-8"),
            (ROOT / "SECURITY.md").read_text(encoding="utf-8"),
            (ROOT / "COMMUNITY-RELEASE-LIMITATIONS.md").read_text(encoding="utf-8"),
            (ROOT / "scripts" / "build-community-source.py").read_text(encoding="utf-8"),
        ]
        combined = "\n".join(texts).casefold()
        for stale in (
            "community release candidate",
            "not yet a promoted production release",
            "review artifact, not a promoted release",
        ):
            self.assertNotIn(stale, combined)
        self.assertIn("sniper community v1.1.0 source release", texts[0].casefold())

    def test_builder_excludes_installed_release_record_and_rebrands_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "community-source"
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            built = subprocess.run(
                [sys.executable, "scripts/build-community-source.py", "--output", str(output)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertFalse((output / "RELEASE.json").exists())
            self.assertEqual((output / "COMMUNITY_VERSION").read_text(encoding="utf-8").strip(), "1.1.0")
            self.assertEqual(
                (output / "COMMUNITY-RELEASE-LIMITATIONS.md").read_text(encoding="utf-8"),
                (ROOT / "COMMUNITY-RELEASE-LIMITATIONS.md").read_text(encoding="utf-8"),
            )

            version_text = (output / "version.py").read_text(encoding="utf-8")
            self.assertIn('__version__ = "1.1.0"', version_text)
            self.assertIn("Sniper Community", version_text)
            self.assertNotIn("Sniper Enterprise", version_text)

            manifest = (output / "COMMUNITY-SOURCE-MANIFEST.sha256").read_text(encoding="utf-8")
            self.assertNotRegex(manifest, r"(?m)  (?:.*/)?RELEASE\.json$")
            validated = subprocess.run(
                [
                    sys.executable,
                    ".github/scripts/validate-community-release.py",
                    "--root",
                    str(output),
                    "--scan-release-tree",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(validated.returncode, 0, validated.stdout + validated.stderr)


if __name__ == "__main__":
    unittest.main()
