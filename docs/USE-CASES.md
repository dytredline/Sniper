# Sniper Community use cases

Sniper Community is a local-first defensive application-security toolkit for developers, maintainers, platform
teams, and security reviewers. It combines built-in analysis with optional, readiness-gated local engines and makes
results available through stdio MCP, the command line, or a loopback web interface.

It can help an application, API, or website owner find evidence worth investigating. It does not promise to find
every vulnerability, prove that a system is secure, or replace authorization, reproduction, and human judgment.

## Choose a review path

| Path | Best fit | Important boundary |
| --- | --- | --- |
| AI client over MCP | Ask an AI to inspect available context, explain findings, and prepare supported actions | The local MCP server uses stdio, but the client may send selected data to its model provider. Effectful actions require the exact plan to be shown to, and explicitly approved by, a human. |
| Manual CLI | Scriptable local reviews, CI gates, exports, and evidence handling | Read each command's help and select only inputs and output paths you control. |
| Loopback web interface | Human-led local review, triage, and readiness-aware tool selection | Keep the service on loopback unless the documented authentication and transport requirements are deliberately configured. |

All three paths expose the same defensive product boundaries. Choosing an AI client does not grant extra target
authorization, and choosing a manual path does not bypass readiness or confirmation checks.

## Review a mobile application before store submission

| Stage | What to expect |
| --- | --- |
| Input | Supported Android, iOS, Flutter, or React Native source; mobile manifests; API definitions; dependency files; SBOMs; and CI configuration. |
| AI-assisted review | Ask an MCP-capable AI client to organize the available security evidence, explain findings, and prepare supported remediation recommendations. |
| Release value | Bring secrets, privacy flows, mobile configuration, API paths, dependencies, supply-chain evidence, and release-pipeline findings into one preflight review. |
| Best timing | Before an App Store or Google Play submission, before a website or API launch, and before merging a release pull request. |

This path gives product and security teams a shared, evidence-linked checklist for finding and prioritizing security
work while the release is still easy to improve.

## Local source repository review

| Stage | What to expect |
| --- | --- |
| Input | A local application, service, API, library, monorepo, or infrastructure repository under an allowed project root. |
| Checks | Supported language and taint analysis, security patterns, hard-coded secret indicators, application and framework configuration, dependency manifests, IaC, container build files, and CI definitions. Exact support and limits are listed in [Capabilities and security checks](CAPABILITIES.md). |
| Output | Reviewable findings with severity and evidence, project summaries, supported SARIF/GitLab artifacts, and optional quality-gate decisions. |
| Safety and approval boundary | Source files are treated as untrusted input and are not executed as part of static review. Confirm the path and sharing policy before exposing project context to an AI client. A clean result is not a security certificate. |

This workflow is useful before a pull request, during a secure-code review, or when taking ownership of an unfamiliar
application. Start by inspecting the checked-in command contract:

```bash
python3 scripts/sniper-project-audit --help
```

## Prioritize IDOR checks in an authorized manual penetration test

| Stage | What to expect |
| --- | --- |
| Input | Supported Python or JavaScript/TypeScript application source from a project you are authorized to assess. |
| Checks | Route and authorization inventory for unprotected-route candidates (CWE-862) and object lookups that may expose an Insecure Direct Object Reference (IDOR) path (CWE-639). |
| Output | A focused review list with file, route, line, framework, method, and available protection context. |
| Manual verification | In a controlled test environment, an authorized tester can compare separate test users, roles, and synthetic object identifiers while respecting written scope and stop conditions. |

This workflow reduces endpoint triage before manual penetration testing. Reviewers validate each IDOR candidate with
separate test identities and account for runtime enforcement outside the analyzed handler. All validation stays
inside the written authorization scope and uses synthetic or explicitly approved test objects.

## Dependency inventory and SBOM review

| Stage | What to expect |
| --- | --- |
| Input | Supported package manifests and lockfiles, a local project, or a supported CycloneDX/SPDX document. |
| Checks | Dependency inventory, direct/transitive and reachability context where available, SBOM generation/import, license context, VEX workflows, and matching against configured local vulnerability evidence. |
| Output | CycloneDX or SPDX inventory, bounded dependency findings, VEX-related output where requested, and CI/report artifacts supported by the chosen command. |
| Safety and approval boundary | Vulnerability conclusions depend on database freshness, package identity, and analyzer limits. Offline vulnerability profiles stay unavailable until the required pinned database is present. Importing an SBOM does not establish that its contents are complete or authentic. |

This is appropriate for release inventory, dependency review, and software-supply-chain evidence. See
[SBOM.md](SBOM.md) and [OSV-CEVRIMDISI.md](OSV-CEVRIMDISI.md) for exact formats, commands, and offline database
requirements.

## Container and infrastructure-as-code review

| Stage | What to expect |
| --- | --- |
| Input | Supported local container archives or root filesystems, Dockerfiles/Containerfiles, Terraform, Kubernetes, Helm, Compose, cloud IAM, and CI workflow files. |
| Checks | Package and layer inventory for supported container inputs; risky build choices; and built-in configuration checks for exposed services, excessive privilege, weak hardening, public access, secrets, and other documented IaC/CI conditions. |
| Output | Local findings, container SBOM data where supported, configuration evidence, and bounded reports suitable for review or a quality gate. |
| Safety and approval boundary | Analysis is limited to supported local inputs and syntax. Unknown or incomplete syntax must remain a limitation, not be interpreted as safe. Registry access or a missing external database is not implied by local artifact support. |

The built-in IaC engine does not require Trivy. If the optional Trivy profile is installed, configuration profiles can
become available after readiness checks; vulnerability profiles additionally require their pinned offline database.
See [IAC-MOTORU.md](IAC-MOTORU.md) and [KONTEYNER-TARAMA.md](KONTEYNER-TARAMA.md).

## Saved security report analysis

| Stage | What to expect |
| --- | --- |
| Input | A supported, already-generated SARIF or scanner report stored as a local file. |
| Checks | File/type and size bounds, supported schema structure, finding normalization, hashes, counts, severity aggregates, and masked or aggregate-only summaries where documented. |
| Output | A bounded summary or imported evidence that can join Sniper's local review and triage flow. |
| Safety and approval boundary | Importing a report does not execute its originating tool, reproduce a finding, prove the scanned target was authorized, or prove the report is truthful. Report content remains untrusted input. |

This workflow helps teams review results from an existing pipeline without presenting every upstream integration as
installed. An importer's presence is not an engine-readiness signal.

## Plan an authorized website or API action

| Stage | What to expect |
| --- | --- |
| Input | An HTTP(S) target you own or are explicitly authorized to assess, plus written scope, timing, rate limits, data-handling requirements, and stop conditions. |
| Checks | Target normalization, runtime/profile readiness, immutable plan contents, consent scope, expiry, plan hash, and replay protection. The exact runtime check depends on the available, documented profile. |
| Output | A non-executing plan for review; only after approval, a separately submitted action request and its bounded result or execution state. |
| Safety and approval boundary | The AI must show the exact plan and cannot approve it itself. A human must explicitly agree in the same conversation before the MCP host sends `user_confirmed: true`. That signal does not create legal authorization, and unavailable profiles remain unavailable. |

The Community MCP flow is deliberately two-step: `prepare_action` first, then `execute_action` with the unchanged
plan ID and SHA-256 after explicit human approval. Plans expire and are single-use. The fixed target, scope, and
profile must be reviewed before execution; Sniper is not permission to scan an arbitrary internet host. See
[COMMUNITY-MCP.md](COMMUNITY-MCP.md).

## Optional local engines

Sniper's built-in analyzers and report parsers are included in the source tree. The rootless local profile can also
install exactly five pinned third-party engines:

| Optional engine | Community role | Readiness boundary |
| --- | --- | --- |
| Nuclei 3.11.1 | Checked-in pinned loopback-template support and authorized HTTP profiles | Broad authorized HTTP work requires a separately pinned template catalog. |
| Trivy 0.75.0 | Configuration-oriented profiles, with additional dependency/container vulnerability profiles when their data is ready | Vulnerability profiles require a separately pinned offline database. |
| Gitleaks 8.30.1 | Local secret-scanning profiles | The binary, hash, input scope, and license must pass readiness checks. |
| TruffleHog 3.99.0 | Local secret-scanning profiles | The binary, hash, input scope, and license must pass readiness checks. |
| Opengrep 1.30.1 | Local source-pattern and taint-rule execution | The pinned binary and selected rules must pass readiness checks. |

Installation is explicit and license-aware. A missing, unverified, or unready engine is not shown as usable merely
because Sniper can import one of its saved reports. See [COMMUNITY-TOOLS.md](COMMUNITY-TOOLS.md) for the exact lock,
platforms, offline cache flow, and third-party license boundary.

## Interpret results responsibly

- A finding is evidence for investigation, not an automatic conclusion that a vulnerability is exploitable.
- A clean result covers only the selected inputs, enabled checks, available data, and documented limits.
- Optional integrations can be unavailable on a host; skipped integrations are not counted as working.
- Reproduce security findings safely and have an authorized human review remediation decisions.
- Never place tokens, passwords, private keys, customer data, or production database files in issues or AI prompts.

For the complete public coverage map, start with [Capabilities and security checks](CAPABILITIES.md). For reproducible
test totals and the limits of that evidence, read [VALIDATION.md](../VALIDATION.md). For AI-oriented discovery, use
the repository's [LLM project index](../llms.txt).
