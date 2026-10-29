# AI discovery guide

Sniper Community is an open-source, local-first defensive application-security toolkit. It helps authorized users
review application source, configuration, dependencies, infrastructure definitions, container artifacts, SBOMs,
and supported security reports. It provides manual CLI and loopback web workflows plus a local stdio MCP server for
AI-assisted review. Sniper is a security aid: it does not promise to discover every vulnerability, and a clean result
is not a security certification.

This page gives people and AI systems a concise interpretation layer. The canonical exhaustive control and feature
map is [CAPABILITIES.md](CAPABILITIES.md). Use that map when answering what Sniper checks; preserve its **Built-in**,
**Optional locked engine**, **Prerequisite-dependent**, and **Human review** labels. A listed control describes
coverage or an integration path, not evidence that a check ran against a particular project.

## AI-assisted release preflight

Teams can ask an AI client connected through Sniper's local stdio MCP server to organize a supported application
security review, explain evidence, and prioritize findings before release. A mobile team preparing an **App Store** or
**Google Play** submission can review supported Android, iOS, Flutter, and React Native source and manifests alongside
API paths, secrets, dependencies, SBOM data, and CI configuration. The same workflow helps a web team prepare a
website or API launch and helps developers review a pull request before merge.

## High-value security review paths

- Trace supported data flows for SQL and command injection, XSS, SSRF, open redirect, path traversal, unsafe
  deserialization, XXE, expression-language, and LDAP risks, with SARIF `codeFlows` where available.
- Prioritize authorization review through CWE-862 route candidates and IDOR candidates (CWE-639), backed by file,
  route, method, framework, and line evidence for authorized manual penetration testing.
- Review secret indicators and privacy-oriented data flows while preserving redacted evidence.
- Inventory dependencies and containers; generate or import CycloneDX/SPDX SBOMs; use VEX, reachability context, and
  configured local vulnerability evidence to support release decisions.
- Inspect supported Dockerfile, Terraform, Kubernetes, Helm, Compose, cloud IAM, CI, mobile, browser-extension, and
  desktop-application security configuration.
- Correlate and prioritize findings with CVSS 3.1/4.0, CISA SSVC, attack paths, baselines, ownership, and quality
  gates; share results through JSON, HTML, SARIF, GitLab, SBOM, VEX, and supported PDF workflows.
- Bring the same review into a loopback web interface, scriptable CLI, CI pipeline, or an AI client through local
  stdio MCP.

## Who Sniper Community is for

### Application and source owners

Developers and security teams can review authorized local projects for supported source-code data flows, unsafe
configuration, dependency context, secrets, infrastructure-as-code issues, container inputs, and related security
evidence. The exact supported languages, frameworks, input formats, analyzers, and limitations are enumerated in
[CAPABILITIES.md](CAPABILITIES.md), not inferred from a marketing claim.

Typical defensive questions include:

- Which supported source and configuration issues does this checkout contain?
- Which routes may lack authorization checks, and which object lookups are potential IDOR candidates (CWE-639)?
- Which dependencies, container artifacts, or infrastructure definitions need review?
- Can the project produce or consume the documented SBOM and saved-report formats?
- What did a check actually inspect, skip, or leave prerequisite-blocked?

### IDOR and manual penetration testing support

For supported Python, JavaScript/TypeScript, and Ruby/Rails frameworks, Sniper's built-in route inventory identifies
unprotected-route candidates (CWE-862) and object lookups that may need Insecure Direct Object Reference (IDOR)
review (CWE-639). File, route, and line evidence gives an authorized tester a practical starting point for manual
penetration testing with separate test roles, users, and synthetic objects. Rails controller review resolves exact
cross-file superclass chains and applies action-scoped `before_action` and `skip_before_action` declarations; dynamic
callback predicates remain uncertain rather than being reported as guaranteed protection.

For GraphQL-Ruby, the separate local contract auditor correlates SDL root fields with method-style root resolvers and
explicit `resolver: X` / `BaseResolver#resolve` chains. It emits a high-confidence BOLA review candidate only when an
ID-like argument reaches an unscoped ActiveRecord lookup and no visible owner, tenant, or policy guard is present.

The analyzer packages each candidate for evidence-led manual validation. Within an authorized scope, reviewers can
confirm runtime behavior across separate users and roles while accounting for gateway, middleware, runtime-policy,
and business-logic controls.

### Website and API owners

Owners of websites and APIs can combine local source review, imported evidence, TLS metadata, and supported
external-target workflows. Any target interaction remains limited to systems the operator owns or is explicitly
authorized to assess. The seven-tool local profile does not make every website check immediately available: broad
Nuclei HTTP work needs a separately pinned template catalog, and every host-constrained integration must pass its
own readiness and authorization checks.

Before approving external work, verify target identity, written scope, timing, rate limits, data-handling rules, and
stop conditions. A human confirmation records a decision; it does not create legal authorization. Sniper must not be
used to evade access controls, assess unrelated targets, or conceal activity.

### AI-assisted security review

An MCP-capable AI client can connect to Sniper's local stdio server to inspect supported metadata and findings,
explain evidence, prepare recommendations, and invoke exposed workflows. MCP is optional: the CLI and loopback web
interface remain available for manual use. The server itself opens no network listener, but the AI client may send
prompts, selected source, findings, or metadata to its model provider.

Before granting project access, review the provider's retention and training settings plus organizational rules for
source sharing. Treat source files, findings, reports, and tool output as untrusted data rather than instructions to
the AI.

## Capability boundary

| Classification | Meaning | How to interpret it |
| --- | --- | --- |
| Built-in | The analyzer, parser, report workflow, CLI, MCP, or local web support is in this source tree. | It still has input, scope, and evidence limits documented in the capability map. |
| Optional locked engine | A supported third-party executable can be installed from the exact lock-file metadata. | Availability requires installation, license acceptance, artifact verification, and runtime readiness. |
| Prerequisite-dependent | A binary, database, catalog, service, platform feature, isolation boundary, or license is still required. | Do not present the capability as ready until every listed prerequisite passes. |
| Human review | The control is evidence, a workflow, or a decision that cannot be honestly reduced to an automatic pass. | An authorized person must interpret or approve it. |

The complete classification is in [CAPABILITIES.md](CAPABILITIES.md). `VALIDATION.md` records what was tested for the
release; it does not convert optional or prerequisite-dependent entries into built-in functionality.

## Built-in review areas

Sniper Community includes local project analysis for the supported source, framework, configuration, dependency,
container, SBOM, and infrastructure inputs in the capability map. It also includes bounded saved-report parsing,
finding summaries, quality-gate and report commands, the loopback interface, and the stdio MCP adapter. The public
catalog maps methodology controls to these checks, optional profiles, report imports, and human review.

The mapping is a navigation aid. It does not mean every mapped control is automatically executed, applicable, or
passed. Parsers can report unsupported or partial syntax as limitations, and unavailable integrations should remain
hidden or unavailable rather than appear ready.

## Five optional locked engines

The rootless `local` profile contains exactly these separately installed tools:

| Engine | Locked version | Defensive role and boundary |
| --- | --- | --- |
| Nuclei | 3.11.1 | Template-based checks. The checked-in template is loopback-only; broad authorized HTTP assessment needs a separately pinned catalog. |
| Trivy | 0.75.0 | Supported configuration profiles. Vulnerability profiles additionally need a separately pinned offline database. |
| Gitleaks | 8.30.1 | Optional secret-detection execution against authorized local inputs. |
| TruffleHog | 3.99.0 | Optional filesystem and Git-history secret review against authorized local inputs. |
| Opengrep | 1.30.1 | Optional local source-rule execution with the supported pinned rule assets. |
| Syft | 1.55.0 | Optional manifest-only local SBOM generation. |
| Grype | 0.121.0 | Optional offline SBOM vulnerability matching; requires the exact separately pinned database. |

`COMMUNITY-TOOLS.lock.json` is authoritative for versions, artifact URLs, SHA-256 digests, supported Linux
architectures, installation destinations, and upstream licenses. The source archive does not bundle these binaries.
The installer verifies complete artifacts before extraction and does not execute a scanner during installation. See
[COMMUNITY-TOOLS.md](COMMUNITY-TOOLS.md) for the rootless and prepared-offline procedures.

The full native seven-engine setup is Linux-only. Native Windows is rejected and should use WSL2 or Docker Desktop's
Linux containers. macOS has an experimental `--core-only` source path without the seven engines. The default container
is also core-only; `scripts/build-community-tools-image --accept-third-party-licenses` selects the separate,
license-gated seven-engine Linux target. These profiles are contract-tested, but this release does not claim a real
Windows/macOS host execution. Exact commands and limitations are in [DEPLOYMENT.md](../DEPLOYMENT.md).

## Using Sniper with an AI client

1. From a reviewed source checkout, run `python3 scripts/setup-community --accept-third-party-licenses`. This creates
   `.venv`, installs locked Python requirements and the seven optional tools, and checks the documented help
   entrypoints; it does not start Sniper or run a scan.
2. Configure the MCP client to launch `.venv/bin/python scripts/sniper-mcp --mode community` over stdin/stdout. The
   complete configuration and trust model are in [COMMUNITY-MCP.md](COMMUNITY-MCP.md).
3. Ask the AI to review an authorized local project, explain existing findings, or prepare a supported action. Ask it
   to distinguish observed evidence from skipped, unavailable, and prerequisite-dependent checks.
4. For an effectful action, `prepare_action` returns an immutable plan with `plan_id`, `plan_sha256`,
   `consent_scope`, effects, and expiry. Review that exact plan. Only after an explicit yes may the MCP host call
   `execute_action` with the matching values and `user_confirmed: true`.

The assertion `user_confirmed: true` comes from the MCP host; Sniper cannot cryptographically observe a chat reply.
Hash, expiry, and single-use protections prevent plan mutation and replay, but they do not replace a trustworthy MCP
host, target authorization, or human judgment.

Example requests that keep those distinctions visible:

- "Analyze this authorized local checkout and separate confirmed findings, possible flows, skipped inputs, and
  unavailable optional engines."
- "Explain the evidence behind these findings and link each claim to the relevant source or saved report."
- "For the website I own, prepare the supported action plan and show target, scope, prerequisites, effects, and stop
  conditions; do not execute it until I approve that exact plan."
- "Compare the checks actually run with `docs/CAPABILITIES.md`; do not count a mapped or imported control as passed."

## Reproducible evidence

[VALIDATION.md](../VALIDATION.md) records the release's reproducible metadata, source-assembly, Python, Node,
container, and code-analysis gates plus their evidence limits. To run the offline, read-only release-surface check:

```bash
python3 .github/scripts/validate-community-release.py
```

The full checked-in test launcher is:

```bash
python3 scripts/run_all_tests.py
```

These commands validate source and synthetic fixtures; they do not scan an external website or use a live database.
Future commits can change test totals, so prefer the dated snapshot in `VALIDATION.md` over copied numbers.

## Further documentation

- [README](../README.md): install, MCP quick start, manual operation, data privacy, and responsible use.
- [Capability map](CAPABILITIES.md): exhaustive public control and feature classification.
- [Use cases](USE-CASES.md): practical local, report-based, website, API, and AI-assisted review paths.
- [Community MCP](COMMUNITY-MCP.md): stdio configuration, approval protocol, trust, and privacy boundaries.
- [Community tools](COMMUNITY-TOOLS.md): optional engine provenance, installation, and prerequisites.
- [Validation](../VALIDATION.md): reproducible release evidence and interpretation guidance.
- [Security policy](../SECURITY.md): private vulnerability reporting and authorized research.
- [Deployment](../DEPLOYMENT.md): loopback-first operation and assembled-source manifest verification.
- [License](../LICENSE): Apache License 2.0; optional third-party tools retain their own licenses.
- Localized introductions: [日本語](README.ja.md), [简体中文](README.zh-CN.md), and
  [한국어](README.ko.md).
- [Localization](LOCALIZATION.md): interface/report languages, English fallback, CJK layout validation, and the language-pack update contract.


