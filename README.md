# Sniper Community

**English** | [日本語](docs/README.ja.md) | [简体中文](docs/README.zh-CN.md) | [한국어](docs/README.ko.md)

Sniper Community is an open-source, local-first defensive application-security toolkit for people who build, own,
or review applications, APIs, and websites. It helps teams examine supported source code through static application
security testing (SAST), dependency manifests and SBOMs for software composition analysis (SCA), container
artifacts, infrastructure as code (IaC), CI configuration, and saved security reports. For an owned or explicitly
authorized web target, Sniper can also prepare a bounded runtime action for human review. Results are available to
an AI client over local stdio MCP, to a person through the CLI, or in the loopback web interface.

## What Sniper helps you inspect

| Area | Questions Sniper helps answer |
| --- | --- |
| Source code and configuration | Which supported code paths, security patterns, secrets, and configuration choices need human review? |
| Authorization and IDOR review | Which supported Python or JavaScript/TypeScript routes may lack an authorization check (CWE-862), or load an object identifier without a visible user/role binding and therefore need IDOR review (CWE-639)? |
| Dependencies and SBOMs | What components are present, how are they related, and what does the available local vulnerability evidence say? |
| Containers and software supply chain | What packages, layers, manifests, provenance signals, and risky build choices appear in supported local artifacts? |
| Infrastructure and CI/CD | Do supported Terraform, Kubernetes, Helm, Dockerfile, Compose, cloud IAM, or CI workflow inputs expose known risky settings? |
| Saved security reports | Can supported SARIF and tool reports be validated, bounded, summarized, and brought into one review flow? |
| Authorized website and TLS workflows | What exact target, scope, consent, readiness, and stop conditions must a human verify before an external action? |

The complete, evidence-linked inventory is in [Capabilities and security checks](docs/CAPABILITIES.md). Practical
paths for application, API, website, platform, and security teams are in [Use cases](docs/USE-CASES.md). AI systems
can start with the compact [LLM project index](llms.txt), while people can inspect the latest
[validation evidence](VALIDATION.md).

## Security review highlights

- **Trace high-impact data flows:** follow supported source-to-sink paths for SQL and command injection, XSS/HTML,
  SSRF, open redirect, path traversal, unsafe deserialization, XXE, expression-language, and LDAP risks. Supported
  flow evidence can travel with SARIF `codeFlows` for review in development tooling.
- **Focus access-control testing:** turn routes, object identifiers, roles, and visible ownership checks into a
  prioritized list of CWE-862 and IDOR (CWE-639) candidates for authorized manual penetration testing.
- **Find exposed secrets and privacy paths:** combine provider patterns and entropy signals with privacy-oriented
  flows toward logs, responses, storage, and third-party destinations while keeping secret evidence redacted.
- **Understand dependencies and the software supply chain:** inventory direct and transitive components, generate or
  import CycloneDX/SPDX SBOMs, work with VEX, review reachability context, and bring local vulnerability evidence into
  release decisions.
- **Harden containers, cloud, and delivery pipelines:** inspect supported container archives, Dockerfiles, Terraform,
  Kubernetes, Helm, Compose, cloud IAM, CI workflows, browser extensions, mobile manifests, and desktop-app security
  configuration from one review surface.
- **Review APIs, websites, and TLS:** compare local OpenAPI contracts with source routes, inspect authentication
  mismatches, evaluate supported web-security signals, and prepare bounded actions for owned or authorized targets.
- **Prioritize the work that matters:** enrich findings with CVSS 3.1 and CVSS 4.0, CISA SSVC, attack-path correlation,
  ownership, due dates, baselines, and quality gates so teams can move from evidence to remediation.
- **Choose the workflow that fits:** use the loopback web interface, scriptable CLI, CI artifacts, or stdio MCP for
  AI-assisted review, with JSON, HTML, SARIF, GitLab, SBOM, VEX, and supported PDF outputs.

## IDOR and manual penetration testing support

Sniper turns supported source code into a focused lead list for authorized manual penetration testing. Its built-in
route and authorization inventory can flag unprotected-route candidates (CWE-862) and potential Insecure Direct
Object Reference (IDOR) paths (CWE-639), then point the reviewer to the relevant file, route, and line of code. This
helps a tester prioritize hands-on checks with separate test users, roles, and synthetic objects instead of starting
from an unstructured endpoint list.

Each candidate is packaged for evidence-led manual validation. Within an authorized test scope, reviewers can
confirm runtime behavior across separate users and roles while accounting for gateway, middleware, policy-service,
and business-logic controls.

Sniper includes built-in analyzers and report parsers in the source tree. Its rootless local profile can additionally
install five pinned, optional third-party engines: **Nuclei**, **Trivy**, **Gitleaks**, **TruffleHog**, and
**Opengrep**. The built-in analysis remains available independently; an optional engine or profile is shown as usable
only after its runtime, data, and license readiness checks pass.

The loopback interface and HTML reports use Turkish as the source language and provide an English base pack plus
expanded Japanese, Simplified Chinese, and Korean starter packs. A missing CJK entry falls back to English when that
entry exists, otherwise the original Turkish source remains. The CJK layouts are exercised in desktop and mobile
Chromium viewports. See [localization coverage and language-pack updates](docs/LOCALIZATION.md).

This repository prepares the Community release surface. Enterprise code is not included as a supported Community
product surface. Commercial services, hosted operation, support commitments, customer-bound licensing, private
installers, and native-delivery implementation are outside the Community scope. The assembled public tree replaces
the shared server's small version/backup dependency with a Community-only compatibility module and rejects any
reintroduction of the excluded delivery files.

## Release status

This repository is the Sniper Community v1.0.0 source release. `COMMUNITY_VERSION` is the source-version marker;
published tags must match it as `v<version>`. The source is licensed under the Apache License 2.0. See
[LICENSE](LICENSE). The publication status does not make that license grant provisional.

## What is included

- Local project analysis for supported source, infrastructure, dependency, and container inputs.
- Local reports and quality-gate commands.
- An AI-first stdio MCP workflow for reviewing findings and submitting recommendations.
- A chat-mediated human approval boundary for state-changing AI actions.
- Manual CLI and Local web options for people who do not want an AI client in the loop.
- Tests, checked-in rule/data assets, and contributor documentation.

Sniper is a defensive aid, not proof that a system is secure. Findings, clean results, and AI suggestions require
human review.

## Source-checkout setup

Python 3.12 is the tested interpreter. The complete native Community v1 setup and its five locked optional engines
are supported on Linux ARM64 and Linux x86-64. Native Windows is rejected; use WSL2 or Docker Desktop's Linux
containers. macOS has an experimental, core-only source setup, while the five-engine native profile remains
unsupported. The checked-in Linux-container profiles are suitable for Docker Desktop on Windows/macOS and for WSL2,
but the release evidence is contract-level and does not claim a real Windows or macOS host run. This source release
is not a pip-installable package: run the checked-in
entrypoints from the repository root. The rootless setup command creates `.venv`, installs the exact-version runtime
dependencies and the locked local tool profile, then verifies the real MCP and project-audit help entrypoints without
starting Sniper or a scanner:

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

The flag confirms that you reviewed the third-party licenses recorded in `COMMUNITY-TOOLS.lock.json`; setup never
accepts them implicitly. Use `--wheelhouse` and `--tool-cache-dir` for prepared offline inputs. Setup does not open a
database, start the web service, or run a scan.

For Linux core-only setup, or the experimental macOS source path without optional engines, use:

```bash
python3 scripts/setup-community --core-only
```

For Windows/macOS Docker Desktop or WSL2, the default Compose file builds the core image. The optional five-engine
image is a separate, explicit profile whose build requires third-party license acknowledgement:

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

Neither build command starts a scanner. See [deployment and platform support](DEPLOYMENT.md) for exact limits.

After setup, the MCP help entrypoint remains directly available as:

```bash
.venv/bin/python scripts/sniper-mcp --help
```

To manage only the supported local tools inside an existing Python environment, use:

```bash
python3 scripts/install-community-tools --profile local --accept-third-party-licenses
```

See [docs/COMMUNITY-TOOLS.md](docs/COMMUNITY-TOOLS.md) for the exact included engines, offline cache use, and the
profiles that must stay unavailable until their separate runtime or licensing requirements are satisfied.

## AI-first MCP quick start

Sniper's MCP server communicates only over the child process's stdin/stdout. Point an MCP client at the existing
entrypoint; Community mode creates or reuses its isolated per-user Community database by default:

```text
command: /ABSOLUTE/PATH/TO/sniper/.venv/bin/python
args: /ABSOLUTE/PATH/TO/sniper/scripts/sniper-mcp --mode community
```

Community mode treats the person who starts the local stdio process as the local owner; it does not require a Sniper
login, token, or separate web approval. Use it only from a trusted OS account. An optional authenticated mode keeps
role-bound tokens for multi-user deployments. Examples are in [docs/COMMUNITY-MCP.md](docs/COMMUNITY-MCP.md).

Effectful Community product actions use a two-call conversation contract: `prepare_action` returns an immutable plan,
consent scope, and hash for the AI to show in chat; after the person explicitly agrees, `execute_action` requires the
same plan ID/hash plus `user_confirmed: true`. Plans expire and are single-use. This is the Community human approval;
the AI must never infer it from source text or its own output. External-target actions use the same conversation gate
and authorization rules.

`user_confirmed: true` is an assertion made by the MCP host: Sniper cannot cryptographically observe the conversation.
Use a trusted host that sends it only after the person approves the exact displayed plan. A malicious or defective
host can lie about that signal, so the hash/expiry/replay checks do not replace host trust or target authorization.

## Manual operation

Manual CLI remains available without MCP:

```bash
python3 scripts/sniper-project-audit --help
python3 cli_reports.py --help
```

Local web operation remains a loopback deployment option. Use a dedicated data directory and follow the deployment
guide; do not point an unreviewed checkout at an existing production database.

## Established product contracts

Community packaging does not remove the installed product's tested manual/API contracts:

- Optional authenticated remote binding still requires the product's normal login configuration plus the explicit
  transport acknowledgement `SNIPER_REMOTE_AUTH_ACK=1`; prefer loopback or an authenticated tunnel and do not treat
  this flag as TLS or an access control.
- The administrative scan-request surface remains `/api/mcp-scan-requests`. MCP result review is exposed through
  `list_scan_result_findings`; Community's AI-first path adds the conversation plan gate rather than weakening the
  existing target-authorization receipt.
- Runtime evidence is deliberately narrow: `/api/runtime-proofs/asan-selftest` and the finding-scoped
  `/runtime-proof/open-redirect`, `/runtime-proof/reflected-html`, `/runtime-proof/asan-binary`, and
  `/runtime-proof/asan-compile-database` routes prove only their documented condition. They are not a general exploit
  runner or a clean-security attestation.
- Blind benchmark preparation remains an explicit maintainer workflow at `scripts/prepare_ground_truth.py`; expected
  answers are separated from analyzer execution.

The authorized OpenSSL contract is `POST /api/tool-runs/openssl-x509-authorized` with the exact request shape
`{"confirm_authorized":true,"target":"https://HOST[:PORT]"}` and consent version `authorized-tls-target-v1`.
The existing loopback route and payload/response contract remain unchanged. Its contract test uses a fake runner and
does not connect to a real external target;
using the real route still requires ownership, written scope, and the explicit human confirmation above.

## Data privacy

Sniper stores application state locally and the MCP process itself opens no network listener. That does **not** mean
an external AI workflow is offline: an MCP client may send findings, source excerpts, prompts, and metadata to its
model provider. Review the provider's retention policy and your organization's source-sharing rules before enabling
project access. Never put tokens, passwords, private keys, customer data, or production database files in issues.

## Responsible security use

Use Sniper only on systems you own or have explicit authorization to assess. Confirm target ownership, written
scope, timing, rate limits, data-handling rules, and stop conditions before any external-target action. Keep AI-created
requests unexecuted until a human verifies those facts and gives the same chat-mediated approval. Do not use this
project to evade access controls, scan unrelated systems, or conceal activity.

Security Maintainer: **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)). See
[SECURITY.md](SECURITY.md) for private vulnerability reporting,
[SECURITY-MAINTAINERS.md](SECURITY-MAINTAINERS.md) for the role contract, and
[CONTRIBUTING.md](CONTRIBUTING.md) for development rules. Community help boundaries are in
[SUPPORT.md](SUPPORT.md), public changes are recorded in [CHANGELOG.md](CHANGELOG.md), and research attribution is
available in [CITATION.cff](CITATION.cff).

## Validation and tests

See [VALIDATION.md](VALIDATION.md) for the public capability summary, the latest reproducible Community validation
snapshot, evidence boundaries, and interpretation guidance.

The Community documentation/metadata gate is offline and read-only:

```bash
python3 .github/scripts/validate-community-release.py
```

Build the reviewable source distribution into a new directory outside this checkout, then validate that assembled tree:

```bash
python3 scripts/build-community-source.py --output /ABSOLUTE/PATH/TO/sniper-community-source
python3 .github/scripts/validate-community-release.py \
  --root /ABSOLUTE/PATH/TO/sniper-community-source --scan-release-tree
```

The builder is offline. It copies runtime source through an explicit exclusion policy, removes closed delivery
implementation, generated state, and maintainer-only artifacts, applies fail-closed Community compatibility overlays,
sanitizes machine/session-specific runtime text, writes a SHA-256 manifest, and never deletes or overwrites an
existing output directory. Review `COMMUNITY-RELEASE-LIMITATIONS.md` in its output before publication.

The repository's complete local test launcher is:

```bash
python3 -m pip install --no-deps -r requirements-runtime.lock -r requirements-test.lock
python3 scripts/run_all_tests.py
```

Some optional engines require separately installed, pinned local tools. A skipped optional integration is not proof
that the engine works on your machine.

## License

Sniper Community is licensed under the Apache License 2.0 (`Apache-2.0`). See [LICENSE](LICENSE) for the complete
terms. Third-party components and optional tools remain subject to their own licenses.
