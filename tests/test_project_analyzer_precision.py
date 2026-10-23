"""project_analyzer hassasiyet: GitHub Actions ifade enjeksiyonu ve kod olmayan dosyalarda exec(."""
from pathlib import Path
import tempfile
import textwrap
import unittest

from project_analyzer import analyze_project

WORKFLOW = textwrap.dedent('''
    concurrency:
      group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
    jobs:
      a:
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - env:
              TITLE: ${{ github.event.pull_request.title }}
            run: echo "$TITLE"
          - run: echo "${{ github.event.pull_request.title }}"
          - run: |
              echo hello
              echo "${{ github.event.issue.body }}"
          - uses: actions/github-script@v7
            with:
              script: |
                const parsed = SEMVER.exec(version)
                console.log("${{ github.head_ref }}")
          - run: echo "${{ github.event.pull_request.head.sha }}"
''')


class GithubActionsInjectionTests(unittest.TestCase):
    def test_only_untrusted_fields_inside_run_or_script_are_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "p"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github/workflows/ci.yml").write_text(WORKFLOW, encoding="utf-8")
            findings = analyze_project(str(root), allowed_roots=(root.parent,))["findings"]
        flagged = sorted((f["line"], f["reference"]) for f in findings if f["reference"] in {"CWE-78", "CWE-95"})
        self.assertEqual(flagged, [(13, "CWE-78"), (16, "CWE-78"), (21, "CWE-78")])


class JsCookieAndNewKindsTests(unittest.TestCase):
    def test_express_cookie_flags_and_new_taint_rules(self):
        import project_analyzer
        self.assertEqual(project_analyzer.TAINT_FLOW_RULES["nosql"][4], "CWE-943")
        self.assertEqual(project_analyzer.TAINT_FLOW_RULES["prototype"][4], "CWE-1321")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "p"
            root.mkdir()
            (root / "app.js").write_text(
                "app.get('/a', (req, res) => {\n"
                "  res.cookie('sid', 'x', { secure: false, httpOnly: false });\n"
                "  res.cookie('ok', 'y', { secure: true, httpOnly: true });\n"
                "});\n", encoding="utf-8")
            findings = analyze_project(str(root), allowed_roots=(root.parent,))["findings"]
        cookie = sorted((f["line"], f["reference"]) for f in findings if f["reference"] in {"CWE-614", "CWE-1004"})
        self.assertEqual(cookie, [(2, "CWE-1004"), (2, "CWE-614")])


if __name__ == "__main__":
    unittest.main()
