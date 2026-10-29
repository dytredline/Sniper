# Sniper Community

[![M8ven Verified](https://m8ven.ai/badge/mcp/dytredline-sniper-9er1v0?v=d16a3a51d05233973aecdea96d29b90c&variant=verified)](https://m8ven.ai/mcp/dytredline-sniper-9er1v0?s=readme)

**English** | [Türkçe](docs/README.tr.md) | [日本語](docs/README.ja.md) | [简体中文](docs/README.zh-CN.md) | [한국어](docs/README.ko.md)

[Project overview at ConverserAI](https://converserai.com/#sniper) · [Capabilities](docs/CAPABILITIES.md) · [Setup](#source-checkout-setup) · [Frequently asked questions](#frequently-asked-questions)

Sniper Community is an open-source, local-first defensive application-security toolkit for people who build, own,
or review applications, APIs, and websites. It helps teams examine supported source code through static application
security testing (SAST), dependency manifests and SBOMs for software composition analysis (SCA), container
artifacts, infrastructure as code (IaC), CI configuration, and saved security reports. For an owned or explicitly
authorized web target, Sniper can also prepare a bounded runtime action for human review. Results are available to
an AI client over local stdio MCP, to a person through the CLI, or in the loopback web interface.

## Capability tags

`Application Security` · `SAST` · `SCA` · `SBOM` · `IaC Security` · `API Security` · `Website Security` ·
`Mobile Security` · `Android` · `iOS` · `IDOR` · `Authorization` · `GraphQL` · `Rails` · `Spring` · `ASP.NET` ·
`Kubernetes` · `Helm` · `Terraform` · `Container Security` · `CI/CD Security` · `Software Supply Chain` ·
`SLSA` · `OCI Provenance` · `Syft` · `Grype` · `Fuzzing` · `Memory Safety` · `MCP` · `AI Security` ·
`SARIF` · `OpenVEX` · `GHSA` · `CVSS` · `SSVC` · `Secrets Detection` · `Privacy` · `Static Analysis` ·
`Runtime Evidence` · `Multi-Repository Analysis` · `Trust Graphs` · `Artifact Provenance` · `Protocol Security` ·
`Archive and Symlink Security` · `Binary Hardening` · `DevSecOps` · `Local First`

Sniper Community v1.1 adds deeper, reviewable coverage in these areas:

- **Cross-framework access control:** correlate supported Rails inheritance, Spring and ASP.NET routes, GraphQL
  resolvers, object identifiers, authorization annotations, policies, roles, owners, and tenant-bound lookups.
- **Multi-repository trust graphs:** map supported HTTP/OpenAPI, webhook, Kafka, authentication-contract, GraphQL,
  exact PyPI dependency, CI artifact, and reusable-workflow relationships without returning private endpoints or
  credentials.
- **Bounded fuzz and runtime evidence:** prepare reviewable C/C++, Rust, Go, Python, Java, and JavaScript/TypeScript
  fuzz targets, with explicit runtime pins, network isolation, resource limits, and fail-closed readiness states for
  supported optional execution paths.
- **Supply-chain and platform review:** inspect supported OCI/SLSA provenance, SBOM/VEX evidence, Kubernetes, Helm,
  Terraform, containers, schema migrations, CI/CD trust, archives, symlinks, protocols, and binary-hardening signals.
- **AI-assisted defensive workflows:** use local stdio MCP tools for response comparison, authorization matrices,
  token sequencing, traffic decoding, GHSA/OpenVEX preparation, and bounty-readiness review while keeping
  state-changing actions behind the displayed plan and explicit human-confirmation contract.
- **Evidence-led prioritization:** connect supported findings to SARIF code flows, CVSS 3.1/4.0, CISA SSVC,
  reachability, attack paths, ownership, baselines, and remediation-oriented quality gates.

## Review before you ship

**Find website security weaknesses with a powerful, open-source toolkit.** Combine authorized website and API
scanning with local code and dependency review, then turn findings into a prioritized remediation plan. External
scans require the relevant engines, data, readiness checks, and explicit scope approval; they are not an unrestricted
scan service. See the [website and API review path](docs/USE-CASES.md#plan-an-authorized-website-or-api-action).

Ask an AI assistant to review your application before release. Through Sniper's local stdio MCP workflow, the AI can
guide a supported security review, explain findings with code evidence, and help prioritize remediation while the
same results remain available in the web interface, CLI, and CI artifacts.

For Android, iOS, Flutter, and React Native projects, bring supported source code, mobile manifests, API paths,
secrets, dependencies, SBOM data, and CI configuration into one release-preflight view. Whether you are preparing an
**App Store or Google Play submission**, a **website or API launch**, or a **pull request**, Sniper helps surface the
security work worth completing before users receive the release.

## What Sniper helps you inspect

| Area | Questions Sniper helps answer |
| --- | --- |
| Source code and configuration | Which supported code paths, security patterns, secrets, and configuration choices need human review? |
| Authorization and IDOR review | Which supported Python, JavaScript/TypeScript, Ruby/Rails, Spring, or ASP.NET routes may lack an authorization check (CWE-862), or load an object identifier without a visible user/role binding and therefore need IDOR review (CWE-639)? Rails analysis correlates cross-file controller inheritance; Spring and ASP.NET analysis correlates literal controller/minimal routes with authorization annotations or policies and subject-bound lookups. |
| GraphQL resolver authorization | Which supported GraphQL-Ruby SDL root fields map to method-style or explicit `BaseResolver` classes that perform an unscoped ActiveRecord object lookup without a visible owner, tenant, or policy guard? |
| Multi-repository trust | Which selected local repositories are linked by supported OpenAPI calls, webhooks, Kafka topics, explicit auth contracts, GraphQL operations, or exact PyPI pins—and where do static trust/version signals disagree? |
| Dependencies and SBOMs | What components are present across supported manifests—including NuGet/Paket and Terraform provider lock selections—how are they related, and what does the available local vulnerability evidence say? |
| Containers and software supply chain | What packages, layers, manifests, provenance signals, and risky build choices appear in supported local artifacts? |
| Infrastructure and CI/CD | Do supported Terraform, Kubernetes, Helm, Dockerfile, Compose, cloud IAM, or CI workflow inputs expose known risky settings, including unsafe reusable-workflow permission/secret inheritance or pull-request artifact trust edges? |
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
  release decisions. Bulk local review can also correlate unambiguous exact PyPI pins across repositories and report
  version drift without returning private package-index addresses or credentials.
- **Map service trust across repositories:** correlate supported OpenAPI operations, webhook boundaries, literal Kafka
  topics, explicit authentication contracts, and exact GraphQL query/mutation/subscription root-field pairs across
  separate repositories, including safe named fragments and SHA-256 verified Apollo persisted operations
  in one bounded offline bulk result. Optionally correlate an integrity-checked, exact-schema local runtime trace
  manifest with those static HTTP/webhook/Kafka/GraphQL edges without returning URLs, bodies, tokens, or secrets;
  missing or invalid trace evidence never removes the static edge.
- **Harden containers, cloud, and delivery pipelines:** inspect supported container archives, Dockerfiles, Terraform,
  Kubernetes, Helm, Compose, cloud IAM, CI workflows, browser extensions, mobile manifests, and desktop-app security
  configuration from one review surface.
- **Review APIs, websites, and TLS:** compare local OpenAPI contracts with source routes, inspect authentication
  mismatches, evaluate supported web-security signals, and prepare bounded actions for owned or authorized targets.
- **Prioritize the work that matters:** enrich findings with CVSS 3.1 and CVSS 4.0, CISA SSVC, attack-path correlation,
  ownership, due dates, baselines, and quality gates so teams can move from evidence to remediation.
- **Prepare reviewable fuzz targets:** synthesize C/C++ LibFuzzer, Rust cargo-fuzz, native Go `testing.F`, Python
  Atheris, Java Jazzer, and JavaScript/TypeScript fast-check harness text for a specific local parser or decoder
  finding. Target resolution binds one supported function or method to its reviewed source and fails closed on
  ambiguous signatures. Atheris, Jazzer, and fast-check can also run through the explicit local-runtime API when an
  operator supplies exact runtime/module-or-JAR paths and SHA-256 pins; runs are network-isolated and bounded by
  seed, run count, input bytes, wall time, output bytes, and process-group cleanup. Optional engines are not bundled
  or downloaded, and an absent engine remains `runtime_missing/not_run` rather than simulated evidence; execution remains an explicit operator step.
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
install seven pinned, optional third-party engines: **Nuclei**, **Trivy**, **Gitleaks**, **TruffleHog**, **Opengrep**,
**Syft**, and **Grype**. The built-in analysis remains available independently; an optional engine or profile is shown as usable
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

This repository is the Sniper Community v1.1.0 source release. `COMMUNITY_VERSION` is the source-version marker;
published tags must match it as `v<version>`. The source is licensed under the Apache License 2.0. See
[LICENSE](LICENSE). The publication status does not make that license grant provisional.

GitHub publishes an OIDC-backed provenance attestation for the source archive. After downloading the release asset,
verify its identity and digest with:

```bash
gh attestation verify sniper-community-1.1.0.tar.gz --repo dytredline/Sniper
```

## What is included

- Local project analysis for supported source, infrastructure, dependency, and container inputs.
- Six bounded cross-repository graph views for supported HTTP/OpenAPI, webhook, Kafka, auth-contract, GraphQL, and
  exact PyPI dependency evidence. Each graph fails closed independently so one unavailable correlation does not erase
  the others.
- Cross-file GitHub Actions trust review for local reusable workflows and for literal artifacts that cross from an
  untrusted pull-request producer into a `workflow_run` consumer, including bounded permission, secret, and
  declared-verifier signals. Commit-SHA-pinned remote reusable workflows are resolved only from a bounded,
  exact-schema, digest-locked offline mirror; a command name alone is never reported as successful verification.
- Local reports and quality-gate commands.
- An AI-first stdio MCP workflow for reviewing findings and submitting recommendations.
- A chat-mediated human approval boundary for state-changing AI actions.
- Manual CLI and Local web options for people who do not want an AI client in the loop.
- Tests, checked-in rule/data assets, and contributor documentation.

Sniper is a defensive aid, not proof that a system is secure. Findings, clean results, and AI suggestions require
human review.

## Source-checkout setup

On macOS Apple Silicon, **both** the native source setup (`python3 scripts/setup-community --core-only`) and the
five-engine Docker Desktop profile (`./scripts/deploy-community-tools --accept-third-party-licenses`) are supported
and verified on real macOS hardware. Python 3.12 is the tested interpreter for source-checkout use. The complete
native Community v1 setup and its seven locked optional engines are supported on Linux ARM64 and Linux x86-64.
Windows core-only is supported by the portable setup contract; WSL2 and Docker Desktop provide the Linux container
paths, but this release does not claim a real Windows-host run. The seven-engine native profile remains Linux-only.
This source release
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

For Linux, macOS, or Windows native core-only source setup without the optional Linux engine binaries, use:

```bash
python3 scripts/setup-community --core-only
```

For Windows/macOS Docker Desktop or WSL2, the default Compose file builds the core image. The optional seven-engine
image is a separate, explicit profile whose build requires third-party license acknowledgement:

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

Neither build command starts a scanner. See [deployment and platform support](DEPLOYMENT.md) for exact limits.
For a checked macOS start that builds, launches, and verifies all five local engine prechecks, run
`./scripts/deploy-community-tools --accept-third-party-licenses`; to copy one Mac source project into its persistent
Docker volume, run `./scripts/import-community-project /absolute/path/to/project --name project-name`.

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
  `/runtime-proof/open-redirect`, `/runtime-proof/reflected-html`, `/runtime-proof/dast`,
  `/runtime-proof/asan-binary`, and `/runtime-proof/asan-compile-database` routes prove only their documented
  condition. The fixed DAST catalog includes bounded CWE-918 GET, POST, delayed-callback, one-hop same-origin
  redirect, and local DNS/OOB-correlation profiles. They inject only a Sniper-owned, one-request loopback canary into
  a registered noncritical loopback fixture and never accept an external canary or target. Redirects require exact
  `http`, `127.0.0.1`, original port, path and callback query equality. Response bodies, callback addresses, tokens
  and secrets are not returned or stored. These routes are not a general exploit runner or a clean-security
  attestation.
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

### Gökçe Baran Karakamış — macOS Hardware Validation & Repositories Scanned with Sniper Report

The **real-hardware macOS (Apple Silicon) installation and runtime verification** performed by **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)) — covering both the native source setup (`python3 scripts/setup-community --core-only`) and the five-engine Docker Desktop profile (`./scripts/deploy-community-tools --accept-third-party-licenses`) — together with the detailed evidence audit, false-positive separation, how code patterns turn into exploitable risks, and real-world attack chaining across **8 open-source repositories** scanned with **Sniper**, are summarized below and published in full in [docs/SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md](docs/SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md) and [VALIDATION.md](VALIDATION.md).

> **Important Methodology & Responsible Disclosure Note:** In static analysis, the mere presence of a dangerous sink (`exec`, `pickle.loads`, `subprocess.Popen`) or a CI/CD expression pattern does not by itself constitute a confirmed product CVE. For a finding to qualify as an exploitable vulnerability in a default or supported deployment, **reachability**, **trust-boundary crossing**, and **realistic attacker preconditions** must be proven together. Findings in projects currently undergoing Coordinated Vulnerability Disclosure (CVD / CVE-GHSA) are withheld until upstream patches are released.

| Repository | Sniper SAST / IaC / SCA Summary | Verified Source Evidence & How Code Patterns Turn into Risk | Real-World Scenarios (`Scenario A / B / C`) & Attack Chaining | Combined Severity & Verification Command |
| :--- | :--- | :--- | :--- | :--- |
| **1. `autogpt`** | `93` above threshold (`2C / 39H`); `142` triaged | **2 Critical SQLi (`obj.execute`), JWT & FastAPI `Security()` are false positives**; `jobstore_backfill.py:99` `pickle.loads(row.job_state)` + Compose default password (`RABBITMQ_DEFAULT_PASS`) + root Dockerfile are real | **Scenario A:** An attacker on the internal network using default Compose credentials writes a malicious pickle payload into `apscheduler_jobs.job_state`, achieving RCE inside the root container.<br/>**Scenario B:** Tampering with a backup or migration database triggers arbitrary code execution during restore via `jobstore_backfill.py`.<br/>**Scenario C:** Unpinned `:latest` container tags combined with root execution amplify post-exploitation impact. | **MEDIUM / HIGH (Conditional — Requires DB Write)**<br/>`python3 scripts/sniper-project-audit ./autogpt` |
| **2. `zitadel`** | `67` above threshold (`8C / 42H`); `286` triaged | **8 Critical SQLi/`exec` findings are false positives** (parameterized `pgx` wrapper); 3 `docker.sock` mounts under `deploy/compose/`, `NODE_TLS_REJECT_UNAUTHORIZED=0` in reverse-proxy docs, and `WithInsecure()` are real | **Scenario A:** If an operator copies the `deploy/compose/` sample to production with `/var/run/docker.sock` mounted, container compromise escalates to host root.<br/>**Scenario B:** Copying `NODE_TLS_REJECT_UNAUTHORIZED=0` from the reverse-proxy sample into production enables active MITM interception of OIDC/OAuth session traffic.<br/>**Scenario C:** Leaving `cfg.Insecure = true` enabled on the OTLP telemetry pipeline transmits internal trace spans in cleartext. | **LOW / MEDIUM (Sample Deployment Hardening)**<br/>`python3 scripts/sniper-project-audit ./zitadel` |
| **3. `nextcloud-mcp`** | `59` above threshold (`SAST 1C/6H`, `IaC 7H`, `SCA 5C/40H`) | **`token_utils.py` JWT and `login_flow.py:192` `poll_endpoint` SSRF are 100% false positives** (`initiate()` line 130 pins the origin via `_rewrite_to_nextcloud_host`); `pact.yml:93` `--branch "${{ github.head_ref }}"` is guarded by a `same-repo` condition | **Scenario A:** A compromised maintainer or insider account with branch-creation rights can inject shell metacharacters via a crafted branch name in `pact.yml:93` (external forks are blocked).<br/>**Scenario B:** Exposing the local development Compose stack with hardcoded Keycloak/Greenmail secrets to an untrusted network compromises test accounts.<br/>**Scenario C:** Outdated `pillow`/`cryptography`/`pyjwt` packages in `uv.lock` expose known transitive CVEs. | **LOW / MEDIUM (Internal CI & SCA)**<br/>`python3 scripts/sniper-project-audit ./nextcloud-mcp` |
| **4. `mcpjam-inspector`** | `122` above threshold (`SAST 12C/8H`, `SCA 6C/96H`) | **18 of 20 C/H SAST findings (90%) are false positives** (14 JSDoc comments, 2 `.d.ts` files, 2 UI labels); `pr-preview.yml:116` `echo "branch=${{ github.event.pull_request.head.ref }}"` is guarded by a `same-repo` check | **Scenario A:** An account with in-repo branch creation permissions can manipulate `$GITHUB_OUTPUT` and the runner shell via `pr-preview.yml:116` (external fork PRs are blocked).<br/>**Scenario B:** Running dynamic evaluation helpers without sandbox isolation allows code execution in the evaluation worker environment.<br/>**Scenario C:** Vulnerable transitive dependencies (`handlebars`, `shell-quote`) in `package-lock.json` create supply-chain exposure. | **LOW / MEDIUM (Internal CI & SCA)**<br/>`python3 scripts/sniper-project-audit ./mcpjam-inspector` |
| **5. `codebase-memory-mcp`** | `32` above threshold (`SAST 17C/7H`, `SCA 8H`) | **`store.c:2864` SQLi, `c_lsp.h:54` comment, and `kotlin_lsp.c`/`py_lsp.c` bounded buffers are false positives**; `http_server.c:668` `GET /api/browse?path=...` is protected by `localhost`-only CORS and `Host` header validation (`403`) | **Scenario A:** When `--ui` mode is enabled, another local process on the same machine can enumerate directory names via `http://127.0.0.1:<port>/api/browse?path=/` (cross-origin browser requests are blocked by CORS/Host checks).<br/>**Scenario B:** Accidentally exposing the `--ui` port through a reverse proxy or SSH port forward reveals the host directory tree.<br/>**Scenario C:** Unpatched frontend packages in `graph-ui/package-lock.json` introduce development-time dependency risk. | **LOW (Local Service Boundary)**<br/>`python3 scripts/sniper-project-audit ./codebase-memory-mcp` |
| **6. `gitlab-mcp-server`** | `5` above threshold (`0C / 4H`) | `recorder.go:84` and `make.go:35` are false positives (shell-free `exec.Command("git", args...)`); `internal/gitlab/client.go:1416` `GITLAB_MCP_SKIP_TLS_VERIFY=true` is opt-in only | **Scenario A:** A developer enabling `GITLAB_MCP_SKIP_TLS_VERIFY=true` for a self-signed internal GitLab instance on shared Wi-Fi or VPN exposes their GitLab Personal Access Token (PAT) to active MITM interception.<br/>**Scenario B:** Leaving the flag enabled in CI/CD allows a network attacker to feed forged GitLab API responses into the MCP agent.<br/>**Scenario C:** The `pull_request_target` label workflow would become dangerous if an untrusted PR checkout step were added in the future. | **LOW (Opt-In Configuration)**<br/>`python3 scripts/sniper-project-audit ./gitlab-mcp-server` |
| **7. `apktool-mcp`** | `16` above threshold (`SAST 1M`, `SCA 4C / 12H`) | SAST privacy warnings are false positives; **`uv.lock` contains 4 Critical and 12 High SCA dependency advisories** (`starlette 0.46.2`, `h11 0.14.0`, `fastmcp 2.2.0`, `mcp 1.6.0`) | **Scenario A:** Analyzing untrusted or malformed APKs over HTTP exposes the MCP server to denial-of-service or request-smuggling flaws in outdated `starlette`/`h11` parsers.<br/>**Scenario B:** Session and validation weaknesses in older `mcp`/`fastmcp` releases affect the local agent bridge.<br/>**Scenario C:** Outdated `certifi`/`anyio` packages weaken transport-layer reliability. | **LOW / MEDIUM (SCA Dependency Risk)**<br/>`python3 scripts/sniper-project-audit ./apktool-mcp` |
| **8. `jadx-mcp`** | `32` above threshold (`SAST 3M`, `SCA 6C / 26H`) | Zero confirmed Critical/High SAST bugs; **`uv.lock` contains 6 Critical and 26 High SCA dependency advisories** (`authlib 1.6.8`, `cryptography 46.0.5`, `pyjwt 2.11.0`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`) | **Scenario A:** Multipart file/APK upload endpoints using outdated `python-multipart` and `starlette` versions are vulnerable to memory/CPU exhaustion (DoS).<br/>**Scenario B:** Validation flaws in older `authlib` and `pyjwt` versions weaken token verification in authenticated MCP deployments.<br/>**Scenario C:** `urllib3` redirect header leakage and `cryptography` CVEs expose outbound requests. | **LOW / MEDIUM (SCA Dependency Risk)**<br/>`python3 scripts/sniper-project-audit ./jadx-mcp` |

For the complete file-and-line evidence audit of all 8 repositories, full `Scenario A / B / C` walkthroughs, example execution commands, and macOS verification details, see [docs/SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md](docs/SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md).

#### Verified Vulnerabilities Discovered by Our Sniper Scanner

Below are the **11 verified security vulnerabilities** discovered during our security audits with the **Sniper** static/dynamic analysis engine — complete with **How the Code Bug Turns into a Vulnerability**, **3 Diversified Real-World Critical Scenarios (`Scenario A / B / C`)**, **Example Execution Commands**, and **End-to-End Runtime Proofs (`RED -> GREEN + BENIGN`)** (see [docs/advisories/README.md](docs/advisories/README.md) and [docs/SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md](docs/SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md)):

| # | Advisory Document & Upstream GHSA | Target Project & Component | CWE & CVSS v3.1 | How the Bug Turns into a Vulnerability & 3 Critical Real-World Scenarios (`Scenario A / B / C`) | Runtime Proof (`RED -> GREEN`) & Example Command |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](docs/advisories/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **How It Happens in Code:** In default `recursive=false` mode, `Files.isRegularFile(entry)` (without `LinkOption.NOFOLLOW_LINKS`) follows symlinks while `FolderAccessGuard.isProtected` only validates the symlink's lexical path before `Files.copy` / `Files.move`.<br/>**Scenario A:** A low-privileged office user drops `invoice.pdf -> ../configs/settings.yml` into a shared SMB/NFS scanner hot-folder, exfiltrating admin credentials and OAuth secrets into the shared output directory.<br/>**Scenario B:** An external partner SFTP/Nextcloud drop-folder symlink reads host `.env` or SSH keys.<br/>**Scenario C:** `FolderOutputSink.archiveOriginal()` moves (`Files.move`) the live configuration file into the archive folder, breaking the service. | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false`<br/>`pytest -k test_stirling_cand02` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](docs/advisories/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **How It Happens in Code:** The `CVE-2026-71270` fix restricted WeasyPrint in `FileToPdf.java` to `--allowed-protocols data`, but sibling endpoint `/api/v1/convert/url/pdf` (`ConvertWebsiteToPDF.java`) still passes `--allowed-protocols data,http,https` and skips `customHtmlSanitizer`.<br/>**Scenario A:** A public webpage submitted to an invoice/receipt URL-to-PDF feature embeds `<link rel="stylesheet" href="http://169.254.169.254/...">`, rendering cloud IAM credentials directly into the returned PDF.<br/>**Scenario B:** Internal intranet microservices (`http://127.0.0.1:8080/actuator/env`) are exfiltrated into the downloadable PDF.<br/>**Scenario C:** Malicious `@import` and `<img>` subrequests perform internal port scanning and render unauthenticated internal dashboards into PDF pages. | `RED`: `internal_data_embedded_in_pdf: true`<br/>`GREEN`: `internal_loopback_hit_count: 0`<br/>`pytest -k test_stirling_cand01` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](docs/advisories/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **How It Happens in Code:** `cuabotd.ts` binds `0.0.0.0:7842` without authentication, sets `Access-Control-Allow-Origin: *` on every response, and bind-mounts host `~/.cuabot/user/.claude` read-write.<br/>**Scenario A:** When a developer visits any webpage while `cuabot` is running, page JavaScript calls `fetch("http://localhost:7842/bash")` to execute shell commands and steal Claude OAuth credentials.<br/>**Scenario B:** A malicious site opens `ws://localhost:7842/?command=...` (CSWSH) and writes a persistent `PreToolUse` hook into `.claude/settings.json`.<br/>**Scenario C:** Any device on the same café, coworking, or office Wi-Fi (`0.0.0.0:7842`) directly calls `http://<lan-ip>:7842/bash` and `/screenshot` to take over the workstation. | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`pytest -k test_cua_cand01` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](docs/advisories/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **How It Happens in Code:** `worker_server.py` configures `allow_origins=["*"]`, `ip_filter_middleware` trusts cross-origin browser requests arriving from `127.0.0.1` and fails open when `OSGYM_ALLOWED_IPS=""` is empty, and `POST /reset` executes arbitrary `env_path/main.py` via `spec.loader.exec_module`.<br/>**Scenario A:** Opening a webpage in a browser triggers `fetch("http://127.0.0.1:8001/reset")` pointing to a downloaded folder, executing `main.py` in the host Python process.<br/>**Scenario B:** In Kubernetes/Docker Compose where `OSGYM_ALLOWED_IPS=""` is set empty, any pod or LAN host achieves unauthenticated RCE over `0.0.0.0:8001/reset`.<br/>**Scenario C:** Attackers monitor desktop screenshots via `/screenshot` and inject mouse/keyboard actions via `/step`. | `RED`: `arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`pytest -k test_cua_cand02` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](docs/advisories/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **How It Happens in Code:** While `object_path(&key)` blocks `..` on the object key, `?uploadId=` is never sanitized and `Method::DELETE` unconditionally executes `tokio::fs::remove_dir_all(root.join("uploads").join(&id))` even when `uploads.remove(&id)` returns `None`.<br/>**Scenario A:** In a multi-tenant environment, a single sandbox tenant sends `DELETE /daytona/x?uploadId=../objects`, wiping the entire organization's sandbox images in one request.<br/>**Scenario B:** Deeper traversal (`?uploadId=../../...`) escapes `d.objects.root` and deletes host directories and databases writable by `cua-spacesd`.<br/>**Scenario C:** Automated multipart abort requests (`AbortMultipartUpload`) destroy active `uploads/` and `stage/` directories belonging to other tenants. | `RED`: `objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `objects_store_preserved: true`<br/>`pytest -k test_cua_cand03` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](docs/advisories/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **How It Happens in Code:** Safe Rust `VtEncoder::encode` -> `pixel_buffer_for` calls `unsafe { std::ptr::copy_nonoverlapping }` on `FrameData::Nv12` (`y` and `uv` slices) and `FrameData::Bgra` without verifying slice lengths against `stride * height`.<br/>**Scenario A:** During a macOS remote desktop stream resize, a truncated `NV12` buffer causes `960` bytes of adjacent heap memory (tokens/keys) to be copied into the H.264 video frame and streamed to the viewer.<br/>**Scenario B:** A malformed or zero-length `VideoFrame` crashes the `cua-spacesd` media daemon with `SIGSEGV`, dropping all active desktop sessions.<br/>**Scenario C:** On a multi-session macOS agent host, an out-of-bounds read leaks another session's heap allocations into the video stream. | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0`<br/>`pytest -k test_cua_vt01` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](docs/advisories/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **How It Happens in Code:** `cli.py` launches the Windows VM container with `-p 8006:8006` (unauthenticated noVNC) and `-p 3390:3389` (passwordless RDP) bound to `0.0.0.0` and mounts host `setup_path` read-write as `-v {setup_path}:/shared`.<br/>**Scenario A:** Anyone on the university or office LAN opens `http://<ip>:8006` in a browser to take over the live Windows VM desktop and steal configured API keys.<br/>**Scenario B:** An attacker inside the VM modifies host setup scripts via the writable `/shared` (`setup_path`) mount to escalate onto the host OS.<br/>**Scenario C:** Because `server/main.py:180` (`POST /execute_windows` -> `exec()`) inside the VM runs without authentication, any webpage visited by the browser agent executes arbitrary Python/OS commands inside the VM. | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"]`<br/>`GREEN`: `lan_exposed_ports: []`<br/>`pytest -k test_cua_cand06` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](docs/advisories/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **How It Happens in Code:** `AreCertsTrusted()` in `ziti edge login` calls `InsecureClient(&client, certs)`, which unconditionally sets `InsecureSkipVerify: true` even when `RootCAs` is populated, causing Go's `crypto/tls` to skip all chain verification and rendering the `x509.UnknownAuthorityError` check dead code.<br/>**Scenario A:** When an administrator runs `ziti edge login`, a rogue MITM certificate is accepted with *"Verified that server supplied certificates are trusted"* and admin credentials are sent to the attacker.<br/>**Scenario B:** Automated CI/CD Zero-Trust enrollment jobs connect to a spoofed Edge Controller and leak production service tokens.<br/>**Scenario C:** During multi-region DNS/BGP routing shifts, clients silently authenticate to an untrusted controller without any certificate warning. | `RED`: `rogue_mitm_cert_accepted_as_trusted: true`<br/>`GREEN`: `x509.UnknownAuthorityError`<br/>`pytest -k test_ziti_cand01` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](docs/advisories/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-io/n8n` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:94, 326, 375` | `CWE-1333`<br/>**5.3 Medium** | **How It Happens in Code:** `isEmail()`, `extractDomain()`, and `extractEmail()` in `string-extensions.ts` evaluate unanchored regexes with nested quantifiers (`(\.[^...]+)*`) without input length bounds on the single-threaded Node.js event loop.<br/>**Scenario A:** A single 20 KB JSON request sent to a public customer-intake Webhook stalls the Node.js event loop for ~832 ms, freezing all concurrent Stripe payment and Slack webhooks on the server.<br/>**Scenario B:** An automation workflow parsing inbound support emails or chat messages via `{{ $json.text.extractEmail() }}` hangs and triggers Kubernetes liveness-probe restarts.<br/>**Scenario C:** On a multi-workflow n8n instance, a low-privileged workflow saturates the V8 CPU core and starves critical production automations. | `RED`: `regex_stall_ms: 165.035, concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017`<br/>`pytest -k test_n8n_cand01` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](docs/advisories/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`<= v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **How It Happens in Code:** When `SSL.Enabled=true` and `SSL.RedirectToHTTPS=true`, the HTTP-to-HTTPS middleware in `router.go` builds the `308 Permanent Redirect` `Location` header directly from the unvalidated `ctx.Request.Host` header instead of `LetsEncrypt.Hosts`.<br/>**Scenario A:** An attacker sends `Host: phish-gotify.example` to poison a shared cache or captive portal with a `308 Permanent Redirect`, persistently redirecting users to a credential-harvesting page.<br/>**Scenario B:** Notification scripts or CLI clients calling `http://gotify-host/message?token=<app-token>` with redirect-following enabled (`curl -L`) leak the application token to the attacker's host.<br/>**Scenario C:** Behind a reverse proxy that forwards `Host` headers, client and notification links are redirected to an attacker-controlled domain. | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false`<br/>`pytest -k test_gotify_cand01` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](docs/advisories/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **How It Happens in Code:** Called by `build.yaml` (`secrets: inherit`, `packages: write`) and executing on the persistent self-hosted `xrd-runner-8c` pool, `_build-and-package.yml` interpolates `${{ github.head_ref }}` directly inside a double-quoted bash `run:` script.<br/>**Scenario A:** Opening a PR with a crafted branch name (`feat";...;#`) executes arbitrary shell commands on the persistent `xrd-runner-8c` host before code review begins.<br/>**Scenario B:** Because `build.yaml` passes `secrets: inherit` and `packages: write`, the injected command accesses the GHCR package-publishing token and repository secrets.<br/>**Scenario C:** Poisoning the local Gradle/Docker build cache on the persistent `xrd-runner-8c` runner backdoors subsequent official X-Road release packages. | `RED`: `arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true`<br/>`pytest -k test_xroad_cand01` |
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](docs/advisories/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) and `Oauth::TokensController` (`tokens_controller.rb:42-75`) omit `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization`, and `enforce_organization_maintenance_mode` (all enforced in sibling `Oauth::AuthorizationsController`).<br/>**Scenario A (Full Instance Admin Takeover):** A regular user creates an untrusted OAuth app (`trusted: false`); when an admin enters its `user_code` on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes=true` and mints a full `api admin_mode` token allowing complete server takeover, private repo theft, and CI secret extraction.<br/>**Scenario B (Unverified Account API Backdoor):** An unconfirmed account (`confirmed_at: nil`) blocked on `/oauth/authorize` (`403`) mints persistent API & refresh tokens via `/oauth/device`.<br/>**Scenario C (Backdoor Commit During Legal/Migration Freeze):** Attackers mint tokens and push commits (`201 Created`) into frozen repositories while an organization is locked in `migration` (`503`) or `legal` (`403`) maintenance mode. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](docs/advisories/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` accept unvalidated RFC 8414 `token_endpoint`/`revocation_endpoint` URLs and use `OAuth2::Client` (`max_redirects: 5`, no `UrlBlocker`), reflecting raw `OAuth2::Error` bodies into `flash[:alert]`.<br/>**Scenario A (Stealing Cloud IAM Keys via `flash[:alert]`):** A `307 Temporary Redirect` on `token_endpoint` hits `169.254.169.254` or `127.0.0.1` and prints cloud IAM credentials / internal API responses directly into the user's `flash[:alert]` banner.<br/>**Scenario B (Internal `POST` SSRF & Secret Replay):** `OAuth2::Client` replays `POST` requests with `client_secret` and `refresh_token` to firewalled internal `127.0.0.1` services.<br/>**Scenario C (`RevokeTokenService` SSRF):** Disconnecting an MCP server posts Basic Auth credentials to unvalidated internal/external `revocation_endpoint` targets. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](docs/advisories/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::McpConnectorsAuthController` calls global `Ai::Catalog::McpServer.find(params[:id])` without `.in_organization(Current.organization)`, `ConnectService` overwrites DCR credentials without checking `update_ai_catalog_mcp_server`, and `ClientState.from_state` discards `data` binding.<br/>**Scenario A (Cross-Organization AI Connector Hijack):** A user in Organization A overwrites `oauth_client_id` / `oauth_client_secret` on an `McpServer` belonging to Organization B.<br/>**Scenario B (Read-Only User Overwrites Production Connector):** A non-maintainer with read-only access overwrites company MCP OAuth credentials via DCR.<br/>**Scenario C (Cross-Session Account Binding / Login CSRF):** Replaying an unbound `ClientState` token binds a victim developer's GitLab session to the attacker's external MCP account. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](docs/advisories/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `externalMcpTransport` in `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` omits `transport.WithSSRFFilter()`, and `roundTripper.RoundTrip` (`mcp.go:101-104`) re-injects `Authorization: Bearer` headers on every redirect hop.<br/>**Scenario A (Bearer Token Theft & Account Takeover):** A `302` redirect from an external MCP server sends the victim's live `Authorization: Bearer` token to a cross-origin attacker server.<br/>**Scenario B (Workhorse Internal & Cloud Metadata SSRF):** Redirects reach `127.0.0.1` internal services or `169.254.169.254` from the Workhorse process.<br/>**Scenario C (DNS Rebinding into Corporate Intranet):** DNS rebinding bypasses initial URL validation because Workhorse's dialer lacks `WithSSRFFilter`. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](docs/advisories/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` (enforced at line 334), and `workflows.rb:1065` (`GET /ws`) allows overriding `workflow_definition` and `ai_catalog_item_version_id`.<br/>**Scenario A (Escalating Read-Only `chat` to Write-Capable Agent):** Overriding `workflow_definition` and `ai_catalog_item_version_id` on `/ws` injects withheld write tools (`create_issue`) into a restricted `chat` session.<br/>**Scenario B (Stealing Private `public: false` Agent Toolsets):** Enumerating `ai_catalog_item_version_id` discloses the confidential toolset of foreign private AI Catalog agents.<br/>**Scenario C (Unauthorized Private Agent Binding):** `POST /workflows` binds private cross-organization `ItemVersion` records without `:read_ai_catalog_item` checks. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](docs/advisories/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **How It Happens in Code:** `McpConfigService#execute` (`mcp_config_service.rb:61`) calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, and `ListService`/`Agent::Create` omit `.in_organization`.<br/>**Scenario A (Unlocking All Prohibited Built-in GitLab MCP Tools):** An `Ai::Catalog::McpServer` named `"GitLab"` (`:gitlab`, `Tools: nil`) overwrites the built-in `:gitlab` entry so Workhorse (`mcp.go:254`) sets `allToolsAvailable = true`, disabling all `withheld_server_tools` restrictions.<br/>**Scenario B (Cross-Org MCP Server Binding):** GraphQL `aiCatalogAgentCreate`/`Update` binds foreign-organization `McpServer` Global IDs.<br/>**Scenario C (Duo Workflow `401` DoS):** Overwriting `Headers` on `:gitlab` strips `X-Gitlab-Oauth-Token` and breaks `/api/v4/mcp`. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](docs/advisories/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) redirects to unvalidated `request_params[:redirect_url]`, passes `request_params[:response_url]` to `VerifyRequest`, and keys Redis `CACHE_KEY` only by `command_id` without `project_id`/`integration_id`.<br/>**Scenario A (Corporate SSO Phishing After Slash Command Confirm):** Confirming a slash command on the trusted GitLab domain redirects (`302 Found`) the developer to an external credential-harvesting page.<br/>**Scenario B (Cross-Project ChatOps Account Binding):** A `command_id` minted in Project B is accepted on Project A's `/slash_commands/confirm` endpoint.<br/>**Scenario C (ChatOps Callback Hijack):** `request_params[:response_url]` overrides the cached `response_url` during `VerifyRequest#approve!`. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](docs/advisories/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Upstream Duplicate: `CVE-2026-40295`<br/>*(GitHub Only — Not Submitted to MITRE)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[UPSTREAM DUPLICATE: `CVE-2026-40295` — Published on GitHub Only, Not Submitted to MITRE]**<br/>**How It Happens in Code:** `Gitlab::DeviseFailure` inherits `Devise 5.0.3` `redirect_url` (`CVE-2026-40295`), which redirects to an unsanitized external `Referer` on non-GET `:timeout` failures; `AuthorizationsController#validate_pkce_for_dynamic_applications` (`CAND-03`) has an early return on `nil` `code_challenge_method` (mitigated at runtime by `Doorkeeper 5.9.3`).<br/>**Scenario A/B/C:** Product-level `extract_path_from_location(request.referrer)` override in `lib/gitlab/devise_failure.rb` and controller-level PKCE defense-in-depth patch. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |

#### Kendi Sniper Taramamızda Bulduğumuz Doğrulanmış Açıklar (Vulnerabilities Discovered by Our Sniper Scanner)

**Sniper** statik/dinamik analiz motoru ile yürüttüğümüz güvenlik taramalarında tespit edilen, **Adım Adım Günlük Hayat Kritik Senaryoları (`Scenario A / B / C`)**, **Uçtan Uca Çalışma Zamanı Kanıtları (`RED -> GREEN + BENIGN`)** ve **Doğrulanmış Savunma Yamaları (`git diff`)** ile kanıtlanan **11 güvenlik açığı** ([docs/advisories/README.md](docs/advisories/README.md)) aşağıda yayımlanmıştır:

| # | Açık / Advisory Bağlantısı | Hedef Proje & Bileşen | CWE & CVSS v3.1 | Günlük Hayatta Yol Açtığı Kritik Senaryolar (`Scenario A / B / C`) | Çalışma Zamanı Kanıtı (`RED -> GREEN`) |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](docs/advisories/01-STIRLING-CAND-02-SYMLINK.md) | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **A)** Ortak belge/tarayıcı klasörüne bırakılan `invoice.pdf -> ../configs/settings.yml` sembolik bağı, varsayılan `recursive=false` modunda `FolderAccessGuard` kontrolünü aşarak admin/OAuth ayarlarını sızdırır.<br/>**B)** `FolderOutputSink.archiveOriginal()` hedef dosyayı taşır. | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](docs/advisories/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md) | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **A)** `CVE-2026-71270` eksik yaması: `/api/v1/convert/url/pdf` içinde WeasyPrint `--allowed-protocols data,http,https` ile çalıştığından, dış HTML sayfasındaki `<link rel="stylesheet" href="http://127.0.0.1:.../secrets.css">` veya `169.254.169.254` alt kaynağı doğrudan üretilen PDF içine basılır. | `RED`: `internal_data_embedded_in_pdf: true`<br/>`GREEN`: `internal_loopback_hit_count: 0` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](docs/advisories/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **A)** `cuabot` açıkken ziyaret edilen herhangi bir web sayfası `fetch("http://localhost:7842/bash")` (`Access-Control-Allow-Origin: *`) ile komut çalıştırıp bağlanmış `~/.cuabot/user/.claude` kimlik bilgilerini çalar.<br/>**B)** `0.0.0.0:7842` yüzünden aynı LAN'daki herkes erişebilir. | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](docs/advisories/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | **trycua/cua** (`pip: cua-bench-rl <= 0.3.1`)<br/>`worker_server.py:79-108, 338-360` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **A)** Tarayıcıdan `http://127.0.0.1:8001/reset` (`allow_origins=["*"]`) çağrıldığında `ip_filter_middleware` geçilir ve `spec.loader.exec_module` ile konakta keyfi `<env_path>/main.py` çalıştırılır.<br/>**B)** `OSGYM_ALLOWED_IPS=""` boş verildiğinde filtre fail-open olup tüm ağa açılır. | `RED`: `arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](docs/advisories/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | **trycua/cua** (`cargo: cua-compat <= 0.9.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **A)** `DELETE /daytona/x?uploadId=../objects` isteği (önceden multipart yükleme başlatmadan), `uploads.remove(&id)` dönüş değeri kontrol edilmediği için `tokio::fs::remove_dir_all` ile tüm `objects/` deposunu siler. | `RED`: `objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `objects_store_preserved: true` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](docs/advisories/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | **trycua/cua** (`cargo: cua-media-codec <= 0.9.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **A)** Safe Rust `VtEncoder::encode` -> `pixel_buffer_for` içinde `FrameData::Nv12` dilim boyutu kontrol edilmeden `unsafe { std::ptr::copy_nonoverlapping }` çağrılır; kısa dilimde bitişik heap belleğindeki `960` bayt video karesine kopyalanır veya `SIGSEGV` üretir. | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](docs/advisories/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265` | `CWE-306` / `CWE-668`<br/>**8.6 High** | **A)** WinArena `0.0.0.0:8006` (şifresiz noVNC) ve `0.0.0.0:3390` (parolasız RDP) portlarını tüm yerel ağa açar ve konak `setup` dizinini `-v {setup_path}:/shared` olarak yazılabilir bağlar. | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"]`<br/>`GREEN`: `lan_exposed_ports: []` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](docs/advisories/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **A)** `ziti edge login` içindeki `AreCertsTrusted`, `InsecureClient` içinde koşulsuz `InsecureSkipVerify: true` bıraktığı için `RootCAs` havuzunu yok sayar ve sahte MITM sertifikasını *"Verified that server supplied certificates are trusted"* diyerek kabul eder. | `RED`: `rogue_mitm_cert_accepted_as_trusted: true`<br/>`GREEN`: `x509.UnknownAuthorityError` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](docs/advisories/09-N8N-CAND-01-WEBHOOK-REDOS.md) | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:94, 326, 375` | `CWE-1333`<br/>**5.3 Medium** | **A)** Dışa açık n8n Webhook ifadelerinde kullanılan `isEmail()`, `extractDomain()` ve `extractEmail()` fonksiyonlarındaki uzunluk kontrolsüz iç içe nicelleyiciler, 10–20 KB'lık tek bir istekle Node.js ana olay döngüsünü yüzlerce milisaniye kilitler. | `RED`: `regex_stall_ms: 165.035, concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](docs/advisories/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | **gotify/server** (`v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **A)** `SSL.RedirectToHTTPS=true` açıkken `SslMiddleware` içinde `AllowedHosts` boş bırakıldığı için sahte `Host` başlığı `308 Permanent Redirect` ile saldırganın alan adına yönlendirilir. | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](docs/advisories/11-XROAD-CAND-01-RUNNER-INJECTION.md) | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **A)** `build.yaml` (`secrets: inherit`, `packages: write`) tarafından çağrılan ve kalıcı `xrd-runner-8c` self-hosted runner üzerinde çalışan iş akışında `${{ github.head_ref }}` doğrudan bash `run:` bloğuna gömülerek komut çalıştırmaya yol açar. | `RED`: `arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true` |
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](docs/advisories/tr/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **Kodda Oluşumu:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) ve `Oauth::TokensController` (`tokens_controller.rb:42-75`), kardeş `Oauth::AuthorizationsController` içinde zorunlu olan `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization` ve `enforce_organization_maintenance_mode` kontrollerini içermez.<br/>**Senaryo A (Tam Sunucu / Admin Ele Geçirme):** Normal kullanıcının oluşturduğu güvenilmeyen (`trusted: false`) uygulama, `disable_admin_oauth_scopes=true` açıkken bile `/oauth/device` üzerinden tam yetkili `api admin_mode` jetonu üreterek tüm özel depoların, CI/CD sırlarının ve GitLab sunucusunun ele geçirilmesini sağlar.<br/>**Senaryo B (E-Posta Onaysız Kalıcı API Arka Kapısı):** E-postası doğrulanmamış (`confirmed_at: nil`) hesap `/oauth/device` üzerinden kalıcı `access_token` ve `refresh_token` alır.<br/>**Senaryo C (Adli İnceleme / Göç Kilidinde Dondurulmuş Depoya Kod Enjeksiyonu):** Organizasyon `migration` (`503`) veya `legal` (`403`) bakım kilidindeyken cihaz token basılır ve dondurulmuş depoya commit (`201 Created`) atılır. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](docs/advisories/tr/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService` ve `DynamicRegistrationClient`, RFC 8414 `token_endpoint`/`revocation_endpoint` adreslerini doğrulamaz ve `UrlBlocker` olmayan `OAuth2::Client` (`max_redirects: 5`) kullanarak `OAuth2::Error` gövdelerini `flash[:alert]` içine yansıtır.<br/>**Senaryo A (Bulut IAM Anahtarlarının `flash[:alert]` İle Çalınması):** `token_endpoint` üzerindeki `307` yönlendirmesiyle `169.254.169.254` / `127.0.0.1` hedeflerine ulaşılır ve bulut IAM yetki anahtarları doğrudan `flash[:alert]` içinde ekrandan okunur.<br/>**Senaryo B (İç Ağa `POST` SSRF ve Sır Sızıntısı):** `POST` gövdesindeki `client_secret` ve `refresh_token` güvenlik duvarı arkasındaki iç servise iletilir.<br/>**Senaryo C (`RevokeTokenService` SSRF):** Bağlantı kesilirken Basic Auth bilgileri doğrulanmamış `revocation_endpoint` adresine gönderilir. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](docs/advisories/tr/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **Kodda Oluşumu:** `Oauth::McpConnectorsAuthController` `.in_organization(Current.organization)` olmadan global `McpServer.find` çağırır, `ConnectService` `update_ai_catalog_mcp_server` kontrolü yapmadan DCR kimlik bilgilerini yazar ve `ClientState.from_state` `data` bağlamasını düşürür.<br/>**Senaryo A (Rakip Organizasyonun AI Konnektörünü Ele Geçirme):** Organizasyon A'daki saldırgan Organizasyon B'ye ait `McpServer` kaydının `oauth_client_id` ve `oauth_client_secret` bilgilerini kendi OAuth istemcisiyle ezer.<br/>**Senaryo B (Salt-Okunur Kullanıcının Üretim Ayarlarını Ezmesi):** Yalnızca okuma yetkili kullanıcı şirketin MCP OAuth kimlik bilgilerini değiştirir.<br/>**Senaryo C (Kurban Oturumunu Saldırganın MCP Hesabına Bağlama):** Bağlanmamış `state` jetonuyla kurban geliştiricinin GitLab hesabı saldırganın MCP hesabına bağlanır. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](docs/advisories/tr/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` içindeki `externalMcpTransport` `transport.WithSSRFFilter()` kullanmaz ve `roundTripper.RoundTrip` (`mcp.go:101-104`) her yönlendirme adımında `Authorization: Bearer` başlığını yeniden ekler.<br/>**Senaryo A (Canlı Bearer Token Hırsızlığı ve Özel Depo Ele Geçirme):** Harici MCP sunucusundan dönen `302` yönlendirmesinde kurbanın canlı `Authorization: Bearer` jetonu saldırgan sunucusuna sızdırılır.<br/>**Senaryo B (Workhorse İç Ağ ve Bulut Metadata SSRF):** Yönlendirme üzerinden Workhorse sürecinden `127.0.0.1` ve `169.254.169.254` adreslerine doğrudan bağlanılır.<br/>**Senaryo C (DNS Rebinding ile İç Ağa Sızma):** Soket seviyesinde `WithSSRFFilter` olmadığı için DNS Rebinding ile şirket iç ağına erişilir. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](docs/advisories/tr/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **Kodda Oluşumu:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) aynı dosyanın 334. satırında bulunan `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` kontrolünü atlar ve `workflows.rb:1065` (`GET /ws`) `workflow_definition` ile `ai_catalog_item_version_id` ezilmesine izin verir.<br/>**Senaryo A (Salt-Okunur `chat` Oturumundan Yazma Aracı Çalıştırma):** `/ws` üzerinde `workflow_definition` ve `ai_catalog_item_version_id` değiştirilerek yasaklı yazma araçları (`create_issue`) etkinleştirilir.<br/>**Senaryo B (Gizli `public: false` Ajan Yapılandırmasını Çalma):** Başka organizasyonlara ait özel AI ajanlarının araç listesi sızdırılır.<br/>**Senaryo C (Yetkisiz Özel Ajan Sürümü Bağlama):** `POST /workflows` ile özel ajan sürümleri yetki kontrolsüz bağlanır. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](docs/advisories/tr/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **Kodda Oluşumu:** `McpConfigService#execute` (`mcp_config_service.rb:61`) `.except(:orbit)` kullanırken `:gitlab` anahtarını dışlamaz ve `ListService`/`Agent::Create` `.in_organization` kontrolü yapmaz.<br/>**Senaryo A (Tüm Yerleşik GitLab AI Araç Kısıtlamalarını Sıfırlama):** Adı `"GitLab"` (`:gitlab`, `Tools: nil`) olan katalog sunucusu yerleşik `:gitlab` kaydını ezerek Workhorse'ta (`mcp.go:254`) `allToolsAvailable = true` yapar ve tüm `withheld_server_tools` yasaklarını kaldırır.<br/>**Senaryo B (Başka Organizasyonun MCP Sunucusunu Bağlama):** GraphQL mutasyonlarıyla başka organizasyondaki `McpServer` GID'si ajana bağlanır.<br/>**Senaryo C (Duo Workflow `401` DoS):** `:gitlab` üzerindeki `Headers` ezilerek `/api/v4/mcp` çağrıları çökertilir. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](docs/advisories/tr/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **Kodda Oluşumu:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) doğrulanmamış `request_params[:redirect_url]` adresine yönlendirme yapar, `request_params[:response_url]` kullanır ve Redis `CACHE_KEY` içinde `project_id`/`integration_id` bağlamaz.<br/>**Senaryo A (Güvenilir GitLab Onay Ekranı Üzerinden Şifre/2FA Avı):** Slash komutu onaylandığı anda kullanıcı `302 Found` ile harici sahte SSO giriş sayfasına yönlendirilir.<br/>**Senaryo B (Projeler Arası ChatOps Hesap Bağlama):** Proje B'de üretilen `command_id` Proje A'nın onay uç noktasında geçerli kabul edilir.<br/>**Senaryo C (ChatOps Geri Çağrı Yönlendirmesi):** `request_params[:response_url]` önbellekteki URL'nin yerine kullanılarak onay yanıtı saldırgana yönlendirilir. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](docs/advisories/tr/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Üst Akış Duplicate: `CVE-2026-40295`<br/>*(Yalnızca GitHub — MITRE'ye Gönderilmedi)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[ÜST AKIŞ DUPLICATE: `CVE-2026-40295` — Yalnızca GitHub'da Yayımlandı, MITRE'ye Gönderilmedi]**<br/>**Kodda Oluşumu:** `Gitlab::DeviseFailure`, `Devise 5.0.3` (`CVE-2026-40295`) içindeki `redirect_url` metodunu miras alarak `GET` dışı `:timeout` hatalarında harici `Referer` başlığına yönlendirme yapar; `CAND-03` ise çalışma zamanında `Doorkeeper 5.9.3` tarafından engellenir.<br/>**Senaryo A/B/C:** `lib/gitlab/devise_failure.rb` içinde `extract_path_from_location(request.referrer)` ürün yaması ve PKCE savunma derinliği yaması. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |

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

## Frequently asked questions

### What is Sniper Community?

Sniper Community is an Apache-2.0 open-source application-security toolkit for authorized source-code, dependency,
SBOM, container, infrastructure, website, and API review. It combines local analyzers and saved-report workflows
with a CLI, loopback web interface, and optional AI-assisted review through Model Context Protocol (MCP).
The [capability map](docs/CAPABILITIES.md) distinguishes built-in checks from optional engines and manual review.

### Can I use Sniper without an AI subscription?

Yes. The CLI and local web interface do not require an AI client. An optional MCP client can connect to its own
model provider; that provider's availability, privacy rules, and fees are separate from Sniper's source license.
Local hardware and optional third-party tools also have their own requirements.

### Can Sniper be used on Windows, macOS, and Linux?

Yes. Python 3.12 is the tested interpreter. The full native five-engine setup is supported on Linux ARM64 and x86-64.
On **macOS (Apple Silicon)**, both the native source setup (`python3 scripts/setup-community --core-only`) and the
five-engine Docker Desktop profile (`./scripts/deploy-community-tools --accept-third-party-licenses`) are verified on
real macOS hardware and supported (not experimental). On **Windows**, Sniper supports the native `--core-only` source
setup (`python3 scripts/setup-community --core-only`), WSL2, and Linux containers via Docker Desktop; see the
[deployment guide](DEPLOYMENT.md) and [validation evidence](VALIDATION.md) for platform details.

### Can Sniper scan a website for vulnerabilities?

Yes, for websites and APIs you own or are explicitly authorized to assess. Supported workflows prepare bounded
external-target actions, combine web and TLS evidence with local source analysis, and produce reviewable findings.
The relevant engines, pinned catalogs or vulnerability data, runtime readiness, and human approval must be in place.
See the [website/API workflow](docs/USE-CASES.md#plan-an-authorized-website-or-api-action) and
[capability boundaries](docs/CAPABILITIES.md); no tool can guarantee discovery of every vulnerability.

### Can Sniper help find and fix mobile application vulnerabilities?

Sniper helps teams review supported Android, iOS, Flutter, and React Native code, manifests, dependencies, API
paths, and release configuration. It turns evidence into prioritized remediation work before an App Store or Google
Play release. Developers can use the findings and AI-assisted explanations to prepare changes and review them.
Coverage depends on supported inputs: this is not universal mobile-binary scanning, automatic repair of every
vulnerability, or an app-store approval guarantee. See [mobile release preflight](#review-before-you-ship) and the
[capability map](docs/CAPABILITIES.md).

### Does Sniper replace a penetration test or guarantee a secure release?

No. It produces evidence and review candidates, including potential authorization and IDOR issues. A qualified
reviewer must validate material findings, test runtime controls within an authorized scope, and decide what to fix.
A clean scan is not a security certification. See the [validation evidence](VALIDATION.md).

### Where are the official source and installation instructions?

The source repository is [dytredline/Sniper](https://github.com/dytredline/Sniper). Start with the
[source-checkout setup](#source-checkout-setup) and [deployment guide](DEPLOYMENT.md) for your platform.
The project is introduced on [ConverserAI](https://converserai.com/#sniper); the repository remains the source of
truth for capabilities, platform support, license terms, and release evidence. Use [CITATION.cff](CITATION.cff)
when citing the software in research or published work.

## License

Sniper Community is licensed under the Apache License 2.0 (`Apache-2.0`). See [LICENSE](LICENSE) for the complete
terms. Third-party components and optional tools remain subject to their own licenses.
