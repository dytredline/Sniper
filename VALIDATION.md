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

Snapshot date: **2026-10-29**. Scope: the Community v1.1.0 release and its assembled public source
tree.

| Gate | Observed result |
| --- | --- |
| Community metadata/release-surface validation | PASS — 43 required release files checked |
| Assembled source validation | PASS — deterministic source builder completed; assembled tree passed the release-tree scan |
| Python unittest launcher | 3,077 tests, 0 failures, 0 errors |
| Python pytest modules | 337 passed |
| JavaScript/Node tests | 517 passed, 0 failed |
| CJK real-browser layout | PASS — Turkish, English, Japanese, Simplified Chinese, and Korean at desktop and mobile viewports (10/10) |
| Platform setup policy | PASS — Linux full/core paths, real-host macOS Apple Silicon core-only, portable Windows core-only contract, and fail-closed unknown-native routes covered |
| Optional-tools container profile | PASS — exact seven-tool target, explicit license gate, Linux architecture selection, loopback port, and three volumes contract-tested; the five-engine macOS Docker path has real-host evidence |
| Publication secret-name boundary | PASS — deployment `.env`, field-key records, key files, and image archives are excluded before read and rejected by release-tree validation |
| Locked tool installer smoke | PASS — seven Linux ARM64 lock entries and their fail-closed installer contracts validated; pinned Syft and Grype runtimes were installed and reverified locally |
| One-command offline setup smoke | PASS — parseable JSON result, seven provenance-bound tools, and both real help entrypoints |
| Synthetic runtime proofs | PASS — Schemathesis completed a one-operation loopback OpenAPI check; Syft/Grype completed an offline local-fixture run against the pinned Grype database; no external target was scanned |
| Changed-file Python compilation and JavaScript syntax | PASS |
| Docker Compose configuration | PASS locally for default and explicit tools override; missing license acknowledgement rejected |
| Community container image build | PASS — the final assembled source replaced `/app` in the already verified locked R66 runtime without network access; the isolated image reached `healthy` and `/api/health` returned `status: ok` |
| CodeQL languages | PASS on the published main baseline — Actions, JavaScript/TypeScript, and Python jobs passed; the v1.1.0 release pull request must pass fresh CI and CodeQL checks before tagging |

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

The final full-tree review surfaced 100 additional alerts that were audited individually. Fifty-two were deliberate
positive static-analysis fixtures and five were bounded loopback or temporary-project test patterns; all 57 were
closed as **used in tests** with their test boundary recorded. Thirty-nine were closed as false positives only after
the relevant allowlist, containment, no-follow, XML-entity, header, redirect, and redaction controls passed focused
runtime checks. The remaining four caused code changes: one real SBOM saved-path identity race was fixed in the
product, and three unnecessary test-harness patterns were replaced with safer equivalents. Release policy requires
the current release pull request and its merged main commit to pass fresh CI and CodeQL checks before a tag is created.

These numbers describe this exact snapshot. Future commits can legitimately change test totals, and optional-engine
availability varies by host.

## macOS native & Docker Desktop verification — 2026-10-24

Both the **native macOS source setup (`--core-only`)** and the **five-engine Docker Desktop profile** were executed
and verified on a real Apple Silicon Mac:

1. **Native macOS source setup (`python3 scripts/setup-community --core-only`):**
   - Created a native macOS `.venv` (CPython 3.12), installed `requirements-runtime.lock` (`pip check` clean), and
     verified the `scripts/sniper-mcp --help`, `scripts/sniper-project-audit --help`, and `cli_reports.py --help`
     entrypoints natively on macOS.
   - Initialized an isolated local SQLite data directory on macOS, started the loopback web interface, and executed a
     real local project audit (`audit_id: prj_162d09c47587`, `baseline_id: prj_497a1c478d97`) against a local Python
     smoke project, confirming end-to-end native macOS detection (`[critical] Doğrulanmış veri akışı: istek girdisi SQL
     sorgusuna ulaşıyor (SQL enjeksiyonu)` at `app.py:4`) and notification persistence.

2. **macOS Apple Silicon + Docker Desktop five-engine profile (`./scripts/deploy-community-tools --accept-third-party-licenses`):**
   - The five-engine Community image was built on the same Apple Silicon Mac with Docker Desktop after explicit
     acceptance of the engines' separate open-source licenses. Sniper started on loopback and reported healthy. Runtime
     prechecks passed for the pinned Nuclei loopback, Trivy local-secret, Gitleaks, TruffleHog filesystem, and Opengrep
     local-code profiles. The Turkish web dashboard and tool matrix opened in a browser on the same Mac.
   - A synthetic test project was copied from a macOS Documents checkout into the persistent Docker project volume and
     remained accessible after the service was recreated. Local API smoke checks completed for all five engines.
     Opengrep reported the two deliberately planted SQL-injection fixture findings; the other profiles completed against
     their bounded local fixtures or loopback target. A real Nuclei binary regression test exercised positive and
     negative loopback header cases. No external website was scanned.

The full source test runner executed in a Linux test container on that Mac: **2,826 unittest tests passed with zero
failures/errors; 203 pytest tests passed, one skipped; 432 Node tests passed**. Both the native macOS `--core-only`
source route and the Docker-backed five-engine route are verified and supported on macOS; this result does not claim
that every one of the 161 methodology controls is automated. See also
[docs/SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](docs/SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) for the
Turkish macOS verification summary and open-source repository audit report.

## Run the same public checks

Use Python 3.12 and the pinned dependency locks:

```bash
python3 -m pip install --no-deps -r requirements-runtime.lock -r requirements-test.lock
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
