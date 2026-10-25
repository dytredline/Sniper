# Sniper Community

**English** | [Türkçe](docs/README.tr.md) | [日本語](docs/README.ja.md) | [简体中文](docs/README.zh-CN.md) | [한국어](docs/README.ko.md)

[Project overview at ConverserAI](https://converserai.com/#sniper) · [Capabilities](docs/CAPABILITIES.md) · [Setup](#source-checkout-setup) · [Frequently asked questions](#frequently-asked-questions)

Sniper Community is an open-source, local-first defensive application-security toolkit for people who build, own,
or review applications, APIs, and websites. It helps teams examine supported source code through static application
security testing (SAST), dependency manifests and SBOMs for software composition analysis (SCA), container
artifacts, infrastructure as code (IaC), CI configuration, and saved security reports. For an owned or explicitly
authorized web target, Sniper can also prepare a bounded runtime action for human review. Results are available to
an AI client over local stdio MCP, to a person through the CLI, or in the loopback web interface.

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

On macOS Apple Silicon, **both** the native source setup (`python3 scripts/setup-community --core-only`) and the
five-engine Docker Desktop profile (`./scripts/deploy-community-tools --accept-third-party-licenses`) are supported
and verified on real macOS hardware. Python 3.12 is the tested interpreter for source-checkout use. The complete native
Community v1 setup and its five locked optional engines are supported on Linux ARM64 and Linux x86-64. On Windows,
Sniper supports the native `--core-only` source setup (`python3 scripts/setup-community --core-only`), WSL2, and
Docker Desktop's Linux containers. This source release
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

For Windows/macOS Docker Desktop or WSL2, the default Compose file builds the core image. The optional five-engine
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

### Gökçe Baran Karakamış — macOS Kurulum Doğrulaması ve Sniper ile Taranan Depolar Raporu

**Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)) tarafından gerçekleştirilen **macOS (Apple Silicon) gerçek donanım kurulum ve çalışma doğrulaması** (hem yerel kaynak kurulumu `python3 scripts/setup-community --core-only` hem de 5 motorlu Docker Desktop kurulumu `./scripts/deploy-community-tools --accept-third-party-licenses`) ile **Sniper** tarafından taranan **8 açık kaynak deponun** ayrıntılı kanıt denetimi, yanlış pozitif ayrımı ve saldırı zinciri (*chaining*) analizi aşağıda özetlenmiş ve tam rapor olarak [docs/SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](docs/SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) ve [VALIDATION.md](VALIDATION.md) belgelerinde yayınlanmıştır.

> **Önemli Metodoloji ve Sorumlu Bildirim Notu:** Statik analizde tehlikeli bir fonksiyonun (`exec`, `pickle.loads`, `subprocess.Popen`) veya CI/CD deseninin varlığı tek başına doğrulanmış bir ürün CVE'si anlamına gelmez. Bir bulgunun istismar edilebilir açık sayılması için varsayılan/desteklenen dağıtımda **erişilebilirlik**, **güven sınırı (trust boundary) aşımı** ve **saldırgan önkoşulları** birlikte kanıtlanmalıdır. Koordine güvenlik bildirimi (Coordinated Vulnerability Disclosure / CVE-GHSA) süreci devam eden projelere ait bulgular, sorumlu bildirim ilkeleri gereği yamalar yayınlanana kadar bu halka açık listede paylaşılmamaktadır.

| Repo | Sniper SAST / IaC / SCA Özeti | Doğrulanmış Kaynak Kanıtı (Gerçek vs. Yanlış Pozitif) | Tek Başına Kritiklik | Bulgular Birleşiyor mu? (Saldırı Zinciri / Chaining) | Birlikte (Zincir) Kritiklik ve Yayın Durumu |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. `autogpt`** | `93` eşik aşan (`2K / 39Y`); `142` triyaj | **2 kritik SQLi (`obj.execute`), JWT ve FastAPI `Security()` tamamen yanlış pozitif**; `jobstore_backfill.py` `pickle.loads` + Compose sabit parola + Root Dockerfile gerçek | **Düşük / Orta** | **KOŞULLU HİPOTEZ:** Yalnızca saldırgan DB `apscheduler_jobs` tablosuna yazma erişimi kazanırsa `pickle.loads` + Root konteyner birleşir | **ORTA / YÜKSEK (Koşullu)** *(Doğrulanmış doğrudan açık yok; derinlemesine savunma sertleştirmesi)* |
| **2. `zitadel`** | `67` eşik aşan (`8K / 42Y`); `286` triyaj | **8 kritik SQLi/`exec` tamamen yanlış pozitif**; `deploy/compose/` altında 3 `docker.sock` bağlaması ve dokümantasyon örneğinde `TLS_REJECT=0` gerçek | **Düşük / Orta** | **HAYIR (Farklı Örnekler):** `docker.sock` (`deploy/compose/`) ile `TLS_REJECT=0` (`apps/docs/...`) farklı compose dosyalarındadır | **DÜŞÜK / ORTA** *(Geliştirme/örnek dağıtım sertleştirmesi; ürün CVE'si değil)* |
| **3. `nextcloud-mcp`** | `59` eşik aşan (`SAST 1K/6Y`, `IaC 7Y`, `SCA 5K/40Y`) | **`token_utils.py` JWT ve `login_flow.py:192` `poll_endpoint` SSRF %100 yanlış pozitif** (`initiate()` satır 130 `_rewrite_to_nextcloud_host` ile origin'i sabitler); `pact.yml` `pull_request` + `same-repo` korumalı | **Düşük / Orta (SCA)** | **HAYIR:** Tüm birinci-parti SAST/CI bulguları ya yanlış pozitif ya da `same-repo` korumalıdır; yalnız `uv.lock` SCA kayıtları mevcuttur | **DÜŞÜK / ORTA (SCA)** *(Doğrulanmış birinci-parti kod açığı yok)* |
| **4. `mcpjam-inspector`** | `122` eşik aşan (`SAST 12K/8Y`, `SCA 6K/96Y`) | **20 K/Y SAST bulgusunun 18'i (%90) yanlış pozitif** (14 JSDoc yorumu, 2 `.d.ts`, 2 UI etiketi); 2'si kasıtlı `new Function` / E2B; `pr-preview.yml` `same-repo` korumalı | **Düşük / Orta** | **HAYIR:** Dış fork PR'lar engellendiği için dış saldırgan CI/CD zinciri oluşmaz; aynı-repo dal adı interpolasyonu sertleştirilmelidir | **DÜŞÜK / ORTA** *(İç CI sertleştirmesi ve SCA güncellemesi)* |
| **5. `codebase-memory-mcp`** | `32` eşik aşan (`SAST 17K/7Y`, `SCA 8Y`) | **24 K/Y SAST bulgusunun tamamı (%100) yanlış pozitif veya kontrollü iç çağrı** (`store.c` statik DDL, `c_lsp.h` yorum, `mcp.c` `git` argv); `http_server.c` `localhost` CORS/Host korumalı | **Düşük** | **HAYIR:** `http_server.c` yabancı origin'lere CORS başlığı dönmez ve DNS rebinding'i reddeder | **DÜŞÜK** *(Doğrulanmış birinci-parti kod açığı yok)* |
| **6. `gitlab-mcp-server`** | `5` eşik aşan (`0K / 4Y`) | `recorder.go` ve `make.go` yanlış pozitif; `GITLAB_MCP_SKIP_TLS_VERIFY=true` yalnızca kullanıcı seçerse aktif | **Düşük** | **HAYIR:** Birleşen bulgu yoktur | **DÜŞÜK** *(Opsiyonel ayar)* |
| **7. `apktool-mcp`** | `16` eşik aşan (`SAST 1 Orta`, `SCA 4K / 12Y`) | SAST gizlilik uyarıları yanlış pozitif; **`uv.lock` içinde 4 kritik, 12 yüksek SCA bağımlılık kaydı var** | **Düşük / Orta (SCA)** | **HAYIR:** Doğrulanmış birinci-parti kod zinciri yoktur; bağımlılık güncellemeleri incelenmelidir | **DÜŞÜK / ORTA (SCA)** *(SAST temiz, SCA kayıtları mevcut)* |
| **8. `jadx-mcp`** | `32` eşik aşan (`SAST 3 Orta`, `SCA 6K / 26Y`) | Doğrulanmış kritik/yüksek SAST açığı yok; **`uv.lock` içinde 6 kritik, 26 yüksek SCA bağımlılık kaydı var** | **Düşük / Orta (SCA)** | **HAYIR:** Doğrulanmış birinci-parti kod zinciri yoktur; bağımlılık güncellemeleri incelenmelidir | **DÜŞÜK / ORTA (SCA)** *(SAST kritik/yüksek yok, SCA kayıtları mevcut)* |

Her deponun dosya/satır düzeyindeki tam kanıt incelemesi ve macOS doğrulama detayları için: [docs/SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](docs/SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md).

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
