# Sniper Community validation evidence

This page records reproducible evidence for the public Community source tree. It is intentionally limited to code,
tests, packaging, and synthetic fixtures included in this repository. It does not describe or compare a private
edition, and it contains no customer data, live Sniper database content, external-target scan results, workstation
paths, or maintainer-only evidence.

## What the Community release provides

| Area | Public capability | Evidence boundary |
| --- | --- | --- |
| Source and configuration review | Local project analysis across the languages and configuration formats documented in the user guide | Static analysis is advisory; a clean result is not a security certification. |
| Dependency and artifact review | Dependency inventory, reachability context, SBOM generation/import, container archive review, and bounded report summaries | Optional local tools must pass their own runtime readiness checks. |
| Infrastructure review | Terraform, Kubernetes, Helm, Dockerfile, CI workflow, cloud IAM, and related configuration checks | Unsupported or incomplete syntax is reported as a limitation instead of being treated as clean. |
| Evidence handling | SARIF and bounded summaries for supported saved reports, with hashes and aggregate-only output where documented | Importing a report does not run the external tool or prove target authorization. |
| AI-assisted operation | Local stdio MCP server, manual CLI workflows, and a two-step prepare/confirm/execute contract for effectful Community actions | The MCP host must present the exact plan and must not invent human approval. |
| Local interface | Loopback web interface whose tool cards and forms are driven by runtime readiness | Unavailable, external-only, and unsupported controls are omitted instead of being displayed as usable. |

The public catalog maps 161 methodology controls to built-in checks, optional local profiles, saved-report imports,
and human review. That mapping is a coverage guide, not a claim that 161 controls were automatically executed or
passed.

## Reproducible validation snapshot

Snapshot date: **2026-10-23**. Scope: the Community v1.0.0 publication candidate and its assembled public source
tree.

| Gate | Observed result |
| --- | --- |
| Community metadata/release-surface validation | PASS — 28 required release files checked |
| Assembled source validation | PASS — deterministic source builder completed; assembled tree passed the release-tree scan |
| Python unittest launcher | 2,787 tests, 0 failures, 0 errors |
| Python pytest modules | 167 passed |
| JavaScript/Node tests | 426 passed, 0 failed |
| Changed-file Python compilation and JavaScript syntax | PASS |
| Docker Compose configuration | PASS in GitHub Actions |
| Community container image build | PASS in GitHub Actions |
| CodeQL languages | GitHub Actions, JavaScript/TypeScript, and Python analysis jobs passed |

Public workflow history is available in [Community CI](https://github.com/dytredline/Sniper/actions/workflows/ci.yml)
and the [CodeQL runs](https://github.com/dytredline/Sniper/actions?query=workflow%3ACodeQL+branch%3Amain).

The publication security gate was allowed to fail during review. Its first blocking pass reported 12 high-severity
alerts in changed code. Five were reproduced as real path-race or polynomial-complexity defects and fixed with
regression tests. Seven were reviewed as false positives only after root, intermediate-component, leaf, and
containment controls were exercised; each dismissal has a recorded reason in GitHub. The first release pull request
was not merged until required CI and CodeQL checks passed and its head had no open code-scanning alerts.

A subsequent analysis of the merged source reconstructed deeper call paths and reported 11 additional high-severity
alerts. Eight were reproduced as real root/parent-directory races or polynomial-complexity defects and fixed. Three
were redundant metadata checks or a defended fixed-glob read; they were removed or documented only after focused
adversarial controls passed. Publication policy requires a fresh CI and CodeQL pass after these changes.

These numbers describe this exact snapshot. Future commits can legitimately change test totals, and optional-engine
availability varies by host.

## Run the same public checks

Use Python 3.12 and the pinned dependency locks:

```bash
python3 -m pip install -r requirements-runtime.lock -r requirements-test.lock
python3 .github/scripts/validate-community-release.py
python3 scripts/run_all_tests.py --verbose
```

Build and inspect a fresh public source tree outside the checkout:

```bash
python3 scripts/build-community-source.py --output /ABSOLUTE/PATH/TO/sniper-community-source
python3 .github/scripts/validate-community-release.py \
  --root /ABSOLUTE/PATH/TO/sniper-community-source --scan-release-tree
```

The GitHub workflow additionally validates the Compose configuration, builds the local Community image, and runs
CodeQL. No step in this validation snapshot scans an external website or uses a live Sniper database.

## How to interpret the result

- PASS means the stated contract held for the tested source and fixtures.
- A parser or analyzer test demonstrates the documented behavior, not complete vulnerability coverage.
- A saved-report summary validates structure, bounds, and aggregate output; it does not independently validate the
  originating scanner's findings.
- Optional integrations that are unavailable or skipped on a host are not counted as working on that host.
- Security findings should be reproduced and reviewed by an authorized human before remediation decisions.

Security issues in Sniper Community should be reported privately through the process in [SECURITY.md](SECURITY.md).
