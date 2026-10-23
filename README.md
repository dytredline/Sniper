# Sniper Community

Sniper Community is a local-first defensive application-security toolkit. It combines source and configuration
analysis, dependency and container inventory, reports, a loopback web interface, command-line workflows, and an
AI-first review path through a stdio MCP server.

This repository prepares the Community release surface. Enterprise code is not included as a supported Community
product surface. Commercial services, hosted operation, support commitments, customer-bound licensing, private
installers, and native-delivery implementation are outside the Community scope. The assembled public tree replaces
the shared server's small version/backup dependency with a Community-only compatibility module and rejects any
reintroduction of the excluded delivery files.

## Release status

This tree prepares Sniper Community v1.0.0. `COMMUNITY_VERSION` is the candidate source-version marker. This tree is
not yet a promoted production release. The source in this repository is licensed under the Apache License 2.0;
publication status does not make that license grant provisional. See [LICENSE](LICENSE).

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

Python 3.12 is the tested interpreter. This candidate does not claim a pip-installable package: run the checked-in
entrypoints from the repository root. Install the pinned runtime dependency in an isolated environment, then verify
the real MCP entrypoint:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-runtime.lock
python3 scripts/sniper-mcp --help
```

The final command is intentionally side-effect free: it prints the actual stdio MCP options and does not open a
database or start a scan.

## AI-first MCP quick start

Sniper's MCP server communicates only over the child process's stdin/stdout. Point an MCP client at the existing
entrypoint; Community mode creates or reuses its isolated per-user Community database by default:

```text
command: python3
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
Mevcut loopback rota ve payload/yanıt sözleşmesi değişmez. Its contract test uses a fake runner and gerçek dış hedefe bağlanmaz;
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
[CONTRIBUTING.md](CONTRIBUTING.md) for development rules.

## Validation and tests

The Community documentation/metadata gate is offline and read-only:

```bash
python3 .github/scripts/validate-community-release.py
```

Build the reviewable source candidate into a new directory outside this checkout, then validate that assembled tree:

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
python3 -m pip install -r requirements-runtime.lock -r requirements-test.lock
python3 scripts/run_all_tests.py
```

Some optional engines require separately installed, pinned local tools. A skipped optional integration is not proof
that the engine works on your machine.

## License

Sniper Community is licensed under the Apache License 2.0 (`Apache-2.0`). See [LICENSE](LICENSE) for the complete
terms. Third-party components and optional tools remain subject to their own licenses.
