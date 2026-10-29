# Sniper Community

[![M8ven Verified](https://m8ven.ai/badge/mcp/dytredline-sniper-9er1v0?v=d16a3a51d05233973aecdea96d29b90c&variant=verified)](https://m8ven.ai/mcp/dytredline-sniper-9er1v0?s=readme)

[English](../README.md) | [Türkçe](README.tr.md) | [日本語](README.ja.md) | **简体中文** | [한국어](README.ko.md)

[ConverserAI 项目概览](https://converserai.com/#sniper) · [功能清单](CAPABILITIES.md) · [源码检出安装与配置](#源码检出安装与配置) · [常见问题](#常见问题)

Sniper Community 是一套开源、本地优先的防御性应用安全工具包，适合应用、API 和网站的开发者、所有者与
安全审查人员使用。它把受支持的源代码静态应用安全测试（SAST）、依赖项清单与 SBOM 软件成分分析（SCA）、容器制品、
基础设施即代码（IaC）、CI 配置以及已保存的安全报告纳入同一条审查流程。
对于您拥有或已获得明确授权的 Web/API 目标，Sniper 还可以准备一个范围受限、需人工复核的运行时执行计划。
结果可通过本地 stdio MCP 提供给 AI 客户端，也可通过 CLI 或本地回环 Web 界面查看。

## 功能标签

`应用安全` · `SAST` · `SCA` · `SBOM` · `IaC 安全` · `API 安全` · `网站安全` · `移动安全` ·
`Android` · `iOS` · `IDOR` · `授权` · `GraphQL` · `Rails` · `Spring` · `ASP.NET` · `Kubernetes` ·
`Helm` · `Terraform` · `容器安全` · `CI/CD 安全` · `软件供应链` · `SLSA` · `OCI 来源证明` ·
`Syft` · `Grype` · `模糊测试` · `内存安全` · `MCP` · `AI 安全` · `SARIF` · `OpenVEX` · `GHSA` ·
`CVSS` · `SSVC` · `密钥检测` · `隐私` · `静态分析` · `运行时证据` · `多仓库分析` · `信任图` ·
`制品来源证明` · `协议安全` · `归档与符号链接安全` · `二进制加固` · `DevSecOps` · `本地优先`

Sniper Community v1.1 在以下领域增加了更深入、可审查的能力：

- **跨框架访问控制：** 关联受支持的 Rails 继承关系、Spring 和 ASP.NET 路由、GraphQL 解析器、
  对象标识符、授权注解、策略、角色、所有者以及租户约束查询。
- **多仓库信任图：** 映射受支持的 HTTP/OpenAPI、Webhook、Kafka、身份验证契约、GraphQL、精确 PyPI
  依赖项、CI 制品和可复用工作流关系，且不返回私有端点或凭据。
- **有边界的模糊测试与运行时证据：** 为 C/C++、Rust、Go、Python、Java 和 JavaScript/TypeScript
  准备可审查的模糊测试目标；对受支持的可选执行路径实施精确运行时固定、网络隔离、资源上限和
  失败时关闭的就绪状态。
- **供应链与平台审查：** 检查受支持的 OCI/SLSA 来源证明、SBOM/VEX 证据、Kubernetes、Helm、
  Terraform、容器、模式迁移、CI/CD 信任、归档、符号链接、协议和二进制加固信号。
- **AI 辅助防御工作流：** 在以已显示计划和明确人工确认契约保护状态变更操作的同时，通过本地
  stdio MCP 提供响应比较、授权矩阵、令牌序列、流量解码、GHSA/OpenVEX 准备和漏洞赏金就绪审查。
- **基于证据的优先级排序：** 将受支持的发现与 SARIF 代码流、CVSS 3.1/4.0、CISA SSVC、可达性、
  攻击路径、负责人、基线以及面向修复的质量门关联起来。

## 发布前使用 AI 进行安全审查

**使用强大的开源工具包查找网站安全弱点。** 将经授权的网站和 API 扫描与本地代码及依赖项审查相结合，将发现转化为按优先级排列的修复计划。外部扫描需要相应的引擎、数据、就绪检查和明确的范围批准；它不是无限制的扫描服务。参见[网站与 API 审查路径](USE-CASES.md#plan-an-authorized-website-or-api-action)。

在发布前让 AI 助手审查您的应用。通过 Sniper 的本地 stdio MCP 工作流，AI 可以引导受支持的安全审查、结合代码证据解释发现，并协助确定修复优先级，同时相同的结果在 Web 界面、CLI 和 CI 产物中保持可用。

对于 Android、iOS、Flutter 和 React Native 项目，可将受支持的源代码、移动端清单、API 路径、密钥线索、依赖项、SBOM 数据和 CI 配置整合到同一个发布前预检视图中。无论您是在准备 **App Store 或 Google Play 提交**、**网站或 API 上线**，还是 **Pull Request 审查**，Sniper 都能帮助团队在用户收到新版本之前发现并完成关键的安全工作。

## Sniper 可协助检查的内容

| 领域 | Sniper 帮助回答的问题 |
| --- | --- |
| 源代码与配置 | 哪些受支持的代码路径、安全模式、密钥线索和配置选择需要人工审查？ |
| 授权与 IDOR 审查 | 哪些受支持的 Python 或 JavaScript/TypeScript 路由可能缺少授权检查（CWE-862），或在不绑定用户/角色的情况下加载对象标识符而需要 IDOR 审查（CWE-639）？ |
| 依赖项与 SBOM | 存在哪些组件、它们如何关联，以及现有的本地漏洞证据说明了什么？ |
| 容器与软件供应链 | 受支持的本地制品中出现了哪些软件包、镜像层、清单、溯源信号和高风险构建选择？ |
| 基础设施与 CI/CD | 受支持的 Terraform、Kubernetes、Helm、Dockerfile、Compose、云 IAM 或 CI 工作流输入是否暴露了已知风险设置？ |
| 已保存的安全报告 | 受支持的 SARIF 和工具报告能否经过验证、边界控制和汇总后纳入同一审查流？ |
| 授权网站与 TLS 工作流 | 在执行任何外部操作之前，人工必须核实的确切目标、范围、同意、就绪状态和停止条件是什么？ |

完整且带证据链接的功能清单见 [功能与安全检查](CAPABILITIES.md)。面向应用、API、网站、平台与安全团队的实用路径见 [使用场景](USE-CASES.md)。AI 系统可从紧凑的 [LLM 项目索引](../llms.txt) 开始，人工审查者可查看最新的 [验证证据](../VALIDATION.md)。

## 安全审查亮点

- **跟踪高影响数据流：** 跟踪受支持的源到汇（source-to-sink）路径，覆盖 SQL/命令注入、XSS/HTML、SSRF、开放重定向、路径遍历、不安全反序列化、XXE、表达式语言（EL）和 LDAP 风险，并支持携带 SARIF `codeFlows` 在开发工具中复核。
- **聚焦访问控制测试：** 将路由、对象标识符、角色与可见的所有权检查转化为按优先级排列的 CWE-862 与 IDOR（CWE-639）候选项，用于经授权的人工渗透测试。
- **发现暴露的密钥与隐私路径：** 在保持密钥证据脱敏的同时，结合提供商特征与熵信号追踪流向日志、响应、存储和第三方目标的隐私数据流。
- **理解依赖项与软件供应链：** 清点直接与传递组件，生成或导入 CycloneDX/SPDX SBOM，配合 VEX 与可达性上下文将本地漏洞证据纳入发布决策。
- **加固容器、云与交付流水线：** 在同一审查界面检查受支持的容器归档、Dockerfile、Terraform、Kubernetes、Helm、Compose、云 IAM、CI 工作流、浏览器扩展、移动端清单和桌面应用安全配置。
- **审查 API、网站与 TLS：** 对比本地 OpenAPI 契约与源码路由，检查认证不匹配，评估受支持的 Web/TLS 安全信号，并为自有或已授权目标准备受限操作。
- **确定关键工作的优先级：** 使用 CVSS 3.1 与 CVSS 4.0、CISA SSVC、攻击路径关联、负责人、截止日期、基线和质量门禁丰富发现，推动团队从证据走向修复。
- **选择合适的工作流：** 通过本地回环 Web 界面、可脚本化 CLI、CI 产物或用于 AI 辅助审查的 stdio MCP，输出 JSON、HTML、SARIF、GitLab、SBOM、VEX 和受支持的 PDF 报告。

## IDOR 与人工渗透测试支持

Sniper 将受支持的源代码转化为经授权人工渗透测试的重点线索清单。其内置路由与授权清单可标记未受保护的路由候选项（CWE-862）以及潜在的不安全直接对象引用（IDOR）路径（CWE-639），并将审查人员直接定位到相关文件、路由和代码行。这样测试人员无需从杂乱的端点列表起步，即可使用不同的测试用户、角色和合成对象优先开展实测。

每个候选项都针对基于证据的人工验证进行了封装。在授权测试范围内，审查人员可以结合网关、中间件、策略服务和业务逻辑控制，确认跨不同用户与角色的运行时行为。

Sniper 在源码树中内置了分析器与报告解析器。其无需 root 权限的本地配置还可额外安装五个锁定版本的可选第三方引擎：**Nuclei**、**Trivy**、**Gitleaks**、**TruffleHog** 和 **Opengrep**。内置分析可独立运行；可选引擎或配置仅在其运行时、数据和许可证就绪检查全部通过后才显示为可用。

本地回环界面和 HTML 报告以土耳其语作为源语言，并提供英语基础语言包以及扩展的日语、简体中文和韩语语言包。若 CJK 条目缺失，优先回退到英语（若存在），否则保留原始土耳其语文本。CJK 布局已在桌面端和移动端 Chromium 视口中完成验证。详见 [本地化覆盖率与语言包更新](LOCALIZATION.md)。

本仓库提供 Community 发布面。Enterprise 专属商业交付代码不包含在受支持的 Community 产品面中。商业服务、托管运营、支持承诺、客户绑定许可、私有安装器与原生二进制交付实现均不在 Community 范围内。

## 版本状态

本仓库为 Sniper Community v1.0.0 源码版本。`COMMUNITY_VERSION` 是源码版本标记；发布的标签必须以 `v<版本>` 格式与之匹配。源代码采用 Apache License 2.0 授权（参见 [LICENSE](../LICENSE)）。

## 包含内容

- 针对受支持的源码、基础设施、依赖项和容器输入的本地项目分析。
- 本地报告与质量门禁（quality-gate）命令。
- 用于审查发现并提交建议的 AI 优先 stdio MCP 工作流。
- 针对状态变更 AI 操作的对话式人工审批边界。
- 面向不希望引入 AI 客户端的用户的手动 CLI 与本地 Web 选项。
- 测试、随仓检入的规则/数据资产以及贡献者文档。

Sniper 是防御性辅助工具，并非系统绝对安全的证明。所有发现、零告警结果和 AI 建议均需人工复核。

## 源码检出安装与配置

在 **macOS Apple Silicon** 上，原生源码安装（`python3 scripts/setup-community --core-only`）与五引擎 Docker Desktop 配置（`./scripts/deploy-community-tools --accept-third-party-licenses`）**均已在真实 macOS 硬件上完成验证并正式支持**（并非实验性功能）。源码检出使用经测试的解释器为 Python 3.12。完整的原生 Community v1 安装及其五个锁定的可选引擎支持 Linux ARM64 与 Linux x86-64。在 **Windows** 上，Sniper 支持原生 `--core-only` 源码安装（`python3 scripts/setup-community --core-only`）、WSL2 以及 Docker Desktop 的 Linux 容器。本源码版本不是通过 pip 安装的软件包，请从仓库根目录运行检入的入口脚本。无 root 安装命令会创建 `.venv`，安装精确版本的运行时依赖项与锁定的本地工具配置，并在不启动 Sniper 或扫描器的情况下验证真实的 MCP 与项目审计帮助入口：

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

该参数确认您已审阅 `COMMUNITY-TOOLS.lock.json` 中记录的第三方许可证；安装脚本绝不会隐式默认接受。对于预先准备好的离线输入，可使用 `--wheelhouse` 和 `--tool-cache-dir`。安装过程不会打开数据库、不会启动 Web 服务，也不会运行扫描。

在 Linux、macOS 或 Windows 上进行不含可选 Linux 引擎二进制文件的原生核心（`--core-only`）源码安装：

```bash
python3 scripts/setup-community --core-only
```

在 Windows/macOS Docker Desktop 或 WSL2 中，默认 Compose 文件构建核心镜像。可选的五引擎镜像是独立且需显式指定的配置，构建时必须确认第三方许可证：

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

上述两条构建命令均不会启动扫描器。具体平台限制见 [部署与平台支持](../DEPLOYMENT.md)。在 macOS 上一键构建、启动并验证全部五个本地引擎预检，请运行 `./scripts/deploy-community-tools --accept-third-party-licenses`；将 Mac 本地源码项目复制到持久化 Docker 卷，请运行 `./scripts/import-community-project /absolute/path/to/project --name project-name`。

安装完成后，MCP 帮助入口可直接通过以下命令调用：

```bash
.venv/bin/python scripts/sniper-mcp --help
```

若要在现有 Python 环境中仅管理受支持的本地工具，请使用：

```bash
python3 scripts/install-community-tools --profile local --accept-third-party-licenses
```

有关包含的引擎、离线缓存用法以及在满足独立运行时或许可要求前必须保持不可用的配置，请参阅 [COMMUNITY-TOOLS.md](COMMUNITY-TOOLS.md)。

## AI 优先的 MCP 快速开始

Sniper 的 MCP 服务器仅通过子进程的 `stdin/stdout` 通信。将 MCP 客户端指向现有入口即可；Community 模式默认创建或复用按用户隔离的 Community 数据库：

```text
command: /ABSOLUTE/PATH/TO/sniper/.venv/bin/python
args: /ABSOLUTE/PATH/TO/sniper/scripts/sniper-mcp --mode community
```

Community 模式将启动本地 stdio 进程的人员视为本地所有者，无需单独的 Sniper 登录、令牌或额外 Web 审批。请仅在受信任的操作系统账户下使用。面向多用户部署的可选认证模式则保留绑定角色的令牌。配置示例见 [COMMUNITY-MCP.md](COMMUNITY-MCP.md)。

会产生状态变更的 Community 产品操作采用两步调用对话契约：`prepare_action` 返回不可变的执行计划、同意范围与哈希供 AI 在对话中展示；待用户明确同意后，`execute_action` 要求传入相同的计划 ID/哈希以及 `user_confirmed: true`。计划具有有效期且仅限单次使用。这就是 Community 的人工审批边界；AI 绝不能从源码文本或自身输出中自行推断批准。针对外部目标的操作同样遵循这一对话门禁与授权规则。

`user_confirmed: true` 是由 MCP 宿主（host）发出的声明：Sniper 无法从密码学层面直接观测聊天界面。请使用仅在人工批准所展示的确切计划后才发送该信号的受信任宿主。

## 手动运行模式

在不接入 MCP 的情况下，仍可直接使用手动 CLI：

```bash
python3 scripts/sniper-project-audit --help
python3 cli_reports.py --help
```

本地 Web 运行模式作为回环（loopback）部署选项提供。请使用专用数据目录并遵循部署指南；不要将未经审查的代码检出指向现有的生产数据库。

## 既定产品契约

Community 打包不会移除已安装产品中经过测试的手动/API 契约：

- 可选的认证远程绑定除需配置常规登录外，还必须显式设置传输确认标志 `SNIPER_REMOTE_AUTH_ACK=1`；请优先使用本地回环或认证隧道，切勿将该标志视作 TLS 或访问控制机制。
- 管理端扫描请求接口仍为 `/api/mcp-scan-requests`。MCP 结果审查通过 `list_scan_result_findings` 暴露；Community 的 AI 优先路径是在现有目标授权凭证之上增加对话计划门禁，而非削弱授权检查。
- 运行时证据路由范围严格受限：`/api/runtime-proofs/asan-selftest` 以及绑定具体发现的 `/runtime-proof/open-redirect`、`/runtime-proof/reflected-html`、`/runtime-proof/asan-binary` 和 `/runtime-proof/asan-compile-database` 仅用于验证其文档所述的特定条件，并非通用漏洞利用运行器或安全认证。
- 盲测基准（blind benchmark）准备仍是由维护者显式执行的 `scripts/prepare_ground_truth.py` 流程，预期标准答案与分析器执行严格分离。

经授权的 OpenSSL 契约路由为 `POST /api/tool-runs/openssl-x509-authorized`，请求格式严格为 `{"confirm_authorized":true,"target":"https://HOST[:PORT]"}`，同意版本为 `authorized-tls-target-v1`。调用真实路由仍需具备目标所有权、书面授权范围以及上述明确的人工确认。

## 数据隐私

Sniper 在本地存储应用状态，且 MCP 进程自身不开启任何网络监听端口。但这 **并不** 意味着外部 AI 工作流是完全离线的：MCP 客户端可能会将发现、源码片段、提示词和元数据发送给其模型提供商。在启用项目访问前，请审阅模型提供商的数据保留政策以及贵组织的源码共享规范。切勿在 issue 中填入令牌、密码、私钥、客户数据或生产数据库文件。

## 负责任的安全使用

请仅在您拥有或已获得明确评估授权的系统上使用 Sniper。在执行任何针对外部目标的操作之前，必须确认目标所有权、书面范围、时间窗口、速率限制、数据处理规则与停止条件。在人工核实上述事实并通过同一对话给出明确批准之前，保持 AI 创建的请求处于未执行状态。

安全维护者（Security Maintainer）：**Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))。私有漏洞报告流程见 [SECURITY.md](../SECURITY.md)，角色职责契约见 [SECURITY-MAINTAINERS.md](../SECURITY-MAINTAINERS.md)，开发规范见 [CONTRIBUTING.md](../CONTRIBUTING.md)。社区支持边界见 [SUPPORT.md](../SUPPORT.md)，公开变更记录见 [CHANGELOG.md](../CHANGELOG.md)，学术与研究引用信息见 [CITATION.cff](../CITATION.cff)。

### Gökçe Baran Karakamış — macOS 真机安装验证与 Sniper 扫描仓库审计报告

由 **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)) 完成的 **macOS（Apple Silicon）真实硬件安装与运行验证**（涵盖原生源码安装 `python3 scripts/setup-community --core-only` 与五引擎 Docker Desktop 配置 `./scripts/deploy-community-tools --accept-third-party-licenses`），以及使用 **Sniper** 扫描的 **8 个开源仓库** 的详细证据审计、误报（False Positive）甄别、代码模式如何转化为可利用风险的机制分析与攻击链（*chaining*）评估汇总如下。完整报告已发布于 [SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md) 与 [VALIDATION.md](../VALIDATION.md)。

> **重要方法论与负责任披露说明：** 在静态分析中，仅存在危险函数（`exec`、`pickle.loads`、`subprocess.Popen`）或 CI/CD 表达式模式本身并不等同于已确认的产品 CVE。一项发现若要构成默认或受支持部署下的可利用漏洞，必须同时证明 **可达性（reachability）**、**跨越信任边界（trust boundary）** 以及 **符合现实的攻击者前置条件**。正处于协调漏洞披露（Coordinated Vulnerability Disclosure / CVE-GHSA）流程中的项目发现，遵循负责任披露原则，在上游发布补丁前不在本公开列表中披露。

| 仓库 | Sniper SAST / IaC / SCA 汇总 | 已验证源码证据及代码转化为风险的机制分析 | 日常生产环境中的 3 个关键场景（`场景 A / B / C`）与组合利用 | 综合严重度与验证命令 |
| :--- | :--- | :--- | :--- | :--- |
| **1. `autogpt`** | `93` 项超阈值（`2 严重 / 39 高危`）；`142` 项已分诊 | **2 项严重 SQLi（`obj.execute`）、JWT 与 FastAPI `Security()` 为误报**；`jobstore_backfill.py:99` `pickle.loads(row.job_state)` + Compose 硬编码默认密码（`RABBITMQ_DEFAULT_PASS`）+ root Dockerfile 为真实风险 | **场景 A：** 内网攻击者利用默认 Compose 凭据访问数据库，向 `apscheduler_jobs.job_state` 写入恶意 pickle 载荷，在 root 容器内实现远程代码执行（RCE）。<br/>**场景 B：** 篡改备份或迁移数据库文件后，在恢复阶段通过 `jobstore_backfill.py` 触发任意代码执行。<br/>**场景 C：** `:latest` 镜像标签与 root 容器运行相叠加，放大后渗透阶段的横向影响。 | **中危 / 高危（有条件 — 需具备数据库写权限）**<br/>`python3 scripts/sniper-project-audit ./autogpt` |
| **2. `zitadel`** | `67` 项超阈值（`8 严重 / 42 高危`）；`286` 项已分诊 | **8 项严重 SQLi/`exec` 为误报**（参数化 `pgx` 封装）；`deploy/compose/` 下的 3 处 `docker.sock` 挂载、反向代理文档示例中的 `NODE_TLS_REJECT_UNAUTHORIZED=0` 及 `WithInsecure()` 为真实配置风险 | **场景 A：** 若运维人员将 `deploy/compose/` 示例原样用于生产并保留 `/var/run/docker.sock` 挂载，一旦容器失陷即可直接提权至宿主机 root。<br/>**场景 B：** 将反向代理示例中的 `NODE_TLS_REJECT_UNAUTHORIZED=0` 复制到生产环境，导致 OIDC/OAuth 会话流量遭受中间人（MITM）劫持。<br/>**场景 C：** 保持 `cfg.Insecure = true` 开启的 OTLP 遥测通道会以明文传输内部调用链数据。 | **低危 / 中危（示例部署加固）**<br/>`python3 scripts/sniper-project-audit ./zitadel` |
| **3. `nextcloud-mcp`** | `59` 项超阈值（`SAST 1严重/6高危`，`IaC 7高危`，`SCA 5严重/40高危`） | **`token_utils.py` JWT 与 `login_flow.py:192` `poll_endpoint` SSRF 为 100% 误报**（`initiate()` 第 130 行通过 `_rewrite_to_nextcloud_host` 固定源站）；`pact.yml:93` `--branch "${{ github.head_ref }}"` 受 `same-repo` 条件保护 | **场景 A：** 拥有仓库内建分支权限的失陷维护者账号可通过构造特殊分支名在 `pact.yml:93` 中执行 shell 命令（外部 fork PR 已被阻断）。<br/>**场景 B：** 若本地开发环境的硬编码 Keycloak/Greenmail 初始密钥暴露至不受信任网络，测试账号将被接管。<br/>**场景 C：** `uv.lock` 中老旧的 `pillow`/`cryptography`/`pyjwt` 依赖项可触发已知传递性 CVE。 | **低危 / 中危（内部 CI 与 SCA）**<br/>`python3 scripts/sniper-project-audit ./nextcloud-mcp` |
| **4. `mcpjam-inspector`** | `122` 项超阈值（`SAST 12严重/8高危`，`SCA 6严重/96高危`） | **20 项严重/高危 SAST 发现中有 18 项（90%）为误报**（14 处 JSDoc 注释、2 处 `.d.ts`、2 处 UI 标签）；`pr-preview.yml:116` `echo "branch=${{ github.event.pull_request.head.ref }}"` 受 `same-repo` 保护 | **场景 A：** 具备仓库内建分支权限的账号可通过 `pr-preview.yml:116` 污染 `$GITHUB_OUTPUT` 与 runner shell 环境（外部 fork PR 被拦截）。<br/>**场景 B：** 若评测（eval）执行器中的动态辅助函数未做沙箱隔离，可在评测工作节点环境中执行代码。<br/>**场景 C：** `package-lock.json` 中的 `handlebars` 与 `shell-quote` 依赖漏洞形成供应链风险。 | **低危 / 中危（内部 CI 与 SCA）**<br/>`python3 scripts/sniper-project-audit ./mcpjam-inspector` |
| **5. `codebase-memory-mcp`** | `32` 项超阈值（`SAST 17严重/7高危`，`SCA 8高危`） | **`store.c:2864` SQLi、`c_lsp.h:54` 注释及 `kotlin_lsp.c`/`py_lsp.c` 定长缓冲区均为误报**；`http_server.c:668` `GET /api/browse?path=...` 受仅限 `localhost` 的 CORS 与 `Host` 头校验（403）保护 | **场景 A：** 开启 `--ui` 模式时，同一机器上的其他本地进程可通过 `http://127.0.0.1:<port>/api/browse?path=/` 枚举目录结构（浏览器跨源请求被 CORS/Host 拦截）。<br/>**场景 B：** 若通过 SSH 隧道或反向代理误将 `--ui` 端口暴露至公网，将泄露服务器目录树。<br/>**场景 C：** `graph-ui/package-lock.json` 中未更新的前端依赖包带来开发环境风险。 | **低危（本地服务边界）**<br/>`python3 scripts/sniper-project-audit ./codebase-memory-mcp` |
| **6. `gitlab-mcp-server`** | `5` 项超阈值（`0 严重 / 4 高危`） | `recorder.go:84` 与 `make.go:35` 为误报（无 shell 的 `exec.Command("git", args...)`）；`internal/gitlab/client.go:1416` `GITLAB_MCP_SKIP_TLS_VERIFY=true` 仅在用户主动开启时生效 | **场景 A：** 开发者针对自签名内网 GitLab 实例开启 `GITLAB_MCP_SKIP_TLS_VERIFY=true` 后，在公共 Wi-Fi/VPN 网络中遭遇 MITM 窃取 GitLab PAT 令牌。<br/>**场景 B：** 在 CI/CD 环境中长期保留该标志，攻击者可伪造 GitLab API 响应向 MCP 代理注入恶意数据。<br/>**场景 C：** PR 标签工作流中的 `pull_request_target` 若未来加入不可信代码检出（checkout）步骤将引发风险。 | **低危（可选配置项）**<br/>`python3 scripts/sniper-project-audit ./gitlab-mcp-server` |
| **7. `apktool-mcp`** | `16` 项超阈值（`SAST 1中危`，`SCA 4严重 / 12高危`） | SAST 隐私告警为误报；**`uv.lock` 中存在 4 项严重、12 项高危 SCA 依赖通告**（`starlette 0.46.2`、`h11 0.14.0`、`fastmcp 2.2.0`、`mcp 1.6.0`） | **场景 A：** 解析恶意或畸形 APK 时，老旧 `starlette`/`h11` 的 HTTP 解析器漏洞可导致 MCP 服务拒绝服务（DoS）或请求走私。<br/>**场景 B：** 旧版 `mcp`/`fastmcp` 的会话与校验缺陷影响本地代理桥接安全。<br/>**场景 C：** 未更新的 `certifi`/`anyio` 软件包降低传输层可靠性。 | **低危 / 中危（SCA 依赖风险）**<br/>`python3 scripts/sniper-project-audit ./apktool-mcp` |
| **8. `jadx-mcp`** | `32` 项超阈值（`SAST 3中危`，`SCA 6严重 / 26高危`） | 无已确认的严重/高危 SAST 漏洞；**`uv.lock` 中存在 6 项严重、26 项高危 SCA 依赖通告**（`authlib 1.6.8`、`cryptography 46.0.5`、`pyjwt 2.11.0`、`python-multipart 0.0.20`、`starlette 0.47.3`、`urllib3 2.5.0`） | **场景 A：** 在多部分（multipart）文件/APK 上传端点上，旧版 `python-multipart` 与 `starlette` 可被触发内存/CPU 耗尽（DoS）。<br/>**场景 B：** 旧版 `authlib` 与 `pyjwt` 的验证缺陷削弱认证 MCP 部署中的令牌校验。<br/>**场景 C：** `urllib3` 重定向头泄露与 `cryptography` CVE 威胁出站连接安全。 | **低危 / 中危（SCA 依赖风险）**<br/>`python3 scripts/sniper-project-audit ./jadx-mcp` |

有关全部 8 个仓库精确到文件与行号的完整证据审查、`场景 A / B / C` 详情、示例运行命令以及 macOS 真机验证细节，请参阅 [SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md)。

#### 我们通过 Sniper 扫描发现并验证的安全漏洞（11 项已验证安全通告）

以下发布我们在使用 **Sniper** 静态/动态分析引擎开展安全审计时发现并验证的 **11 项安全漏洞**，每项均包含 **代码缺陷如何转化为安全漏洞的机制**、**3 个贴近日常生产环境的关键利用场景（`场景 A / B / C`）**、**示例运行与验证命令** 以及 **端到端运行时证明（`RED -> GREEN + BENIGN`）**（详见 [advisories/README.zh-CN.md](advisories/README.zh-CN.md) 与 [SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md)）：

| # | 安全通告文档 & 上游 GHSA | 目标项目与组件 | CWE & CVSS v3.1 | 代码缺陷如何转化为漏洞 & 日常生产环境中的 3 个关键场景（`场景 A / B / C`） | 运行时证明（`RED -> GREEN`） & 示例命令 |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/zh-CN/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **代码成因：** 在默认 `recursive=false` 模式下，`Files.isRegularFile(entry)`（未传 `LinkOption.NOFOLLOW_LINKS`）会跟随符号链接，而 `FolderAccessGuard.isProtected` 仅检查符号链接本身的字面路径。<br/>**场景 A：** 企业 SMB/NFS 共享扫描仪热目录中被放入 `invoice.pdf -> ../configs/settings.yml` 符号链接，导致管理员密码与 OAuth 密钥被复制到共享输出目录。<br/>**场景 B：** 外部合作伙伴通过 SFTP/Nextcloud 投递目录中的符号链接读取服务器 `.env` 或 SSH 私钥。<br/>**场景 C：** `FolderOutputSink.archiveOriginal()` 将目标配置文件移动（`Files.move`）至归档目录，导致服务崩溃。 | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false`<br/>`pytest -k test_stirling_cand02` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6` | **Stirling-Tools/Stirling-PDF** (`<= 3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **代码成因：** `CVE-2026-71270` 补丁在 `FileToPdf.java` 中将 WeasyPrint 限制为 `--allowed-protocols data`，但兄弟端点 `/api/v1/convert/url/pdf`（`ConvertWebsiteToPDF.java`）仍传入 `--allowed-protocols data,http,https` 且未调用 `customHtmlSanitizer`。<br/>**场景 A：** 提交给发票/回单 URL 转 PDF 功能的外部网页内嵌 `<link rel="stylesheet" href="http://169.254.169.254/...">`，将云 IAM 凭据直接渲染进生成的 PDF。<br/>**场景 B：** 企业内网微服务（`http://127.0.0.1:8080/actuator/env`）响应通过生成的 PDF 外泄。<br/>**场景 C：** 恶意 `@import` / `<img>` 子请求探测内网端口并将未授权内部管理面板截图渲染为 PDF。 | `RED`: `internal_data_embedded_in_pdf: true`<br/>`GREEN`: `internal_loopback_hit_count: 0`<br/>`pytest -k test_stirling_cand01` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **代码成因：** `cuabotd.ts` 在后台无认证监听 `0.0.0.0:7842`，对所有响应附加 `Access-Control-Allow-Origin: *`，并将宿主机 `~/.cuabot/user/.claude` 目录以可读写方式挂载。<br/>**场景 A：** 开发者在运行 `cuabot` 时访问任意网页，页面 JS 调用 `fetch("http://localhost:7842/bash")` 执行命令并窃取 Claude OAuth 凭据。<br/>**场景 B：** 恶意网页通过 `ws://localhost:7842/?command=...`（CSWSH）向 `.claude/settings.json` 写入持久化 `PreToolUse` 钩子。<br/>**场景 C：** 咖啡馆、共享办公空间或办公室 Wi-Fi（`0.0.0.0:7842`）下的任意设备直接调用 `http://<lan-ip>:7842/bash` 与 `/screenshot` 接管工作站。 | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`pytest -k test_cua_cand01` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/zh-CN/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **代码成因：** `worker_server.py` 配置 `allow_origins=["*"]`，`ip_filter_middleware` 不拦截来自浏览器的 `127.0.0.1` 跨源请求且在 `OSGYM_ALLOWED_IPS=""` 为空时失效放行（fail-open），而 `POST /reset` 通过 `spec.loader.exec_module` 直接执行任意 `env_path/main.py`。<br/>**场景 A：** 研究人员在浏览器打开网页时，页面调用 `fetch("http://127.0.0.1:8001/reset")` 加载下载目录中的 `main.py` 并在宿主机 Python 进程中执行。<br/>**场景 B：** 在 Kubernetes/Docker Compose 中若 `OSGYM_ALLOWED_IPS=""` 留空，集群或局域网内任意节点可通过 `0.0.0.0:8001/reset` 远程执行代码。<br/>**场景 C：** 攻击者通过 `/screenshot` 和 `/step` 监控桌面截图并注入键鼠操作。 | `RED`: `arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`pytest -k test_cua_cand02` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **代码成因：** `object_path(&key)` 虽对键名做了 `..` 检查，但从未校验 `?uploadId=` 参数，且 `Method::DELETE` 分支无论 `uploads.remove(&id)` 是否命中都会无条件执行 `tokio::fs::remove_dir_all(root.join("uploads").join(&id))`。<br/>**场景 A：** 在多租户环境中，单个沙箱租户发送 `DELETE /daytona/x?uploadId=../objects`，仅用一次请求即可清空整个组织的沙箱镜像存储。<br/>**场景 B：** 利用 `?uploadId=../../...` 跳出 `d.objects.root`，删除 `cua-spacesd` 进程可写的宿主机目录与数据库文件。<br/>**场景 C：** 在自动取消多部分上传（`AbortMultipartUpload`）时破坏其他租户正在使用的 `uploads/` 与 `stage/` 目录。 | `RED`: `objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `objects_store_preserved: true`<br/>`pytest -k test_cua_cand03` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **代码成因：** Safe Rust `VtEncoder::encode` -> `pixel_buffer_for` 在未校验 `FrameData::Nv12`（`y` 与 `uv` 切片）及 `FrameData::Bgra` 切片长度的情况下调用 `unsafe { std::ptr::copy_nonoverlapping }`。<br/>**场景 A：** 在 macOS 远程桌面推流调整窗口/分辨率时，截断的 `NV12` 缓冲区导致相邻堆内存中的 `960` 字节敏感信息被复制进 H.264 视频帧并推流给观看端。<br/>**场景 B：** 收到畸形或空 `VideoFrame` 时，`cua-spacesd` 媒体服务因 `SIGSEGV` 崩溃，导致所有远程桌面会话中断。<br/>**场景 C：** 在承载多会话的 macOS 代理服务器上，越界读取将其他会话的堆内存数据泄露至视频流。 | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0`<br/>`pytest -k test_cua_vt01` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **代码成因：** `cli.py` 启动 Docker 容器时将 `-p 8006:8006`（无认证 noVNC）与 `-p 3390:3389`（免密 RDP）绑定在 `0.0.0.0` 上，并将宿主机 `setup_path` 以 `-v {setup_path}:/shared` 可读写方式挂载。<br/>**场景 A：** 校园网或办公局域网内的任何人可在浏览器打开 `http://<ip>:8006`，直接接管 Windows 虚拟机桌面并窃取其中的 API 密钥。<br/>**场景 B：** 进入虚拟机的攻击者通过可写的 `/shared`（`setup_path`）挂载篡改宿主机安装脚本，横向渗透至宿主机操作系统。<br/>**场景 C：** 由于虚拟机内 `server/main.py:180`（`POST /execute_windows` -> `exec()`）无认证运行，当代理浏览恶意页面时即可在虚拟机内执行任意系统命令。 | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"]`<br/>`GREEN`: `lan_exposed_ports: []`<br/>`pytest -k test_cua_cand06` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **代码成因：** `ziti edge login` 中的 `AreCertsTrusted()` 调用了无条件设置 `InsecureSkipVerify: true` 的 `InsecureClient(&client, certs)`，导致 Go `crypto/tls` 完全忽略 `RootCAs` 证书池，使 `x509.UnknownAuthorityError` 检查沦为死代码。<br/>**场景 A：** 管理员执行 `ziti edge login` 时，中间人（MITM）攻击者的伪造证书被提示为 *"Verified that server supplied certificates are trusted"* 并直接接收管理员密码。<br/>**场景 B：** CI/CD 流水线中自动执行零信任身份注册的工作负载连接到伪造的 Edge Controller，泄露生产服务令牌。<br/>**场景 C：** 在多数据中心 DNS/BGP 路由漂移时，客户端在无任何证书告警的情况下登录至失陷控制器。 | `RED`: `rogue_mitm_cert_accepted_as_trusted: true`<br/>`GREEN`: `x509.UnknownAuthorityError`<br/>`pytest -k test_ziti_cand01` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/zh-CN/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-io/n8n` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:94, 326, 375` | `CWE-1333`<br/>**5.3 Medium** | **代码成因：** `string-extensions.ts` 中的 `isEmail()`、`extractDomain()` 与 `extractEmail()` 在无长度限制的情况下，在单线程 Node.js 事件循环中运行无起始锚点且含嵌套量词的正则表达式。<br/>**场景 A：** 向公网客户登记/联系 Webhook 发送单个 20 KB 的 JSON 请求即可阻塞 Node.js 事件循环约 832 ms，冻结同一服务器上所有并发的 Stripe 支付与 Slack Webhook。<br/>**场景 B：** 使用 `{{ $json.text.extractEmail() }}` 解析入站客服邮件或聊天消息的工作流卡死，触发 Kubernetes 存活探针超时并反复重启容器。<br/>**场景 C：** 在多租户 n8n 服务器上，低权限工作流耗尽整个 V8 CPU 核心，使关键生产工作流饥饿停摆。 | `RED`: `regex_stall_ms: 165.035, concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017`<br/>`pytest -k test_n8n_cand01` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`<= v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **代码成因：** 当开启 `SSL.Enabled=true` 与 `SSL.RedirectToHTTPS=true` 时，`router.go` 中的重定向中间件直接使用未经校验的客户端 `ctx.Request.Host` 头（而非已配置的 `LetsEncrypt.Hosts`）构造 `308 Permanent Redirect` 的 `Location` 响应头。<br/>**场景 A：** 攻击者使用 `Host: phish-gotify.example` 头投毒缓存或门户的 `308 Permanent Redirect` 响应，将用户浏览器永久重定向至钓鱼登录页。<br/>**场景 B：** 请求 `http://gotify-host/message?token=<app-token>` 且开启自动跟随重定向（`curl -L` / 通知脚本）的客户端在收到 `308` 后将应用令牌泄露给攻击者服务器。<br/>**场景 C：** 在透传 `Host` 头的反向代理部署下，通知与客户端连接被劫持至攻击者控制的域名。 | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false`<br/>`pytest -k test_gotify_cand01` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **代码成因：** 由 `build.yaml`（`secrets: inherit`、`packages: write`）调用并在持久化自托管 `xrd-runner-8c` 节点上运行的 `_build-and-package.yml`，将 `${{ github.head_ref }}` 直接拼接进双引号包裹的 bash `run:` 脚本块。<br/>**场景 A：** 使用精心构造的分支名（`feat";...;#`）发起 PR，即可在代码审查开始前在持久化 `xrd-runner-8c` 服务器上执行任意 shell 命令。<br/>**场景 B：** 由于 `build.yaml` 传递了 `secrets: inherit` 与 `packages: write` 权限，注入的命令可直接获取 GHCR 软件包发布令牌与仓库密钥。<br/>**场景 C：** 投毒持久化 `xrd-runner-8c` 构建服务器上的本地 Gradle/Docker 缓存，从而在后续官方 X-Road 发行包中植入后门。 | `RED`: `arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true`<br/>`pytest -k test_xroad_cand01` |
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/zh-CN/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) and `Oauth::TokensController` (`tokens_controller.rb:42-75`) omit `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization`, and `enforce_organization_maintenance_mode` (all enforced in sibling `Oauth::AuthorizationsController`).<br/>**Scenario A:** An untrusted user-created OAuth app (`trusted: false`) mints a full-privilege admin `api admin_mode` token even when `disable_admin_oauth_scopes=true` is enabled.<br/>**Scenario B:** An unconfirmed account (`confirmed_at: nil`) blocked on `/oauth/authorize` (`403`) mints persistent OAuth tokens via `/oauth/device`.<br/>**Scenario C:** Device token exchange and repository commits succeed during `migration` (`503`) or `legal` (`403`) organization maintenance locks. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/zh-CN/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` accept unvalidated RFC 8414 `token_endpoint`/`revocation_endpoint` URLs and use `OAuth2::Client` (`max_redirects: 5`, no `UrlBlocker`), reflecting raw `OAuth2::Error` bodies into `flash[:alert]`.<br/>**Scenario A:** A `307 Temporary Redirect` on `token_endpoint` hits internal loopback/cloud metadata endpoints and reflects error bodies into `flash[:alert]`.<br/>**Scenario B:** `OAuth2::Client` replays `POST` bodies containing `client_secret` and `refresh_token` to internal `127.0.0.1` services.<br/>**Scenario C:** `RevokeTokenService` sends Basic Auth credentials to unvalidated `revocation_endpoint` targets. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/zh-CN/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::McpConnectorsAuthController` calls global `Ai::Catalog::McpServer.find(params[:id])` without `.in_organization(Current.organization)`, `ConnectService` overwrites DCR credentials without checking `update_ai_catalog_mcp_server`, and `ClientState.from_state` discards `data` binding.<br/>**Scenario A:** A user in Organization A mutates or triggers OAuth connection flows on an `McpServer` belonging to Organization B.<br/>**Scenario B:** A non-maintainer user with read-only access overwrites `oauth_client_id` and `oauth_client_secret` via DCR.<br/>**Scenario C:** Unbound `ClientState` tokens allow cross-session OAuth callback state replay. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/zh-CN/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `externalMcpTransport` in `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` omits `transport.WithSSRFFilter()`, and `roundTripper.RoundTrip` (`mcp.go:101-104`) re-injects `Authorization: Bearer` headers on every redirect hop.<br/>**Scenario A:** A `302` redirect from an external MCP server leaks the user's `Authorization: Bearer` token to a cross-origin host.<br/>**Scenario B:** Redirects from an allowed external host reach `127.0.0.1` or `169.254.169.254` from the Workhorse process.<br/>**Scenario C:** DNS rebinding bypasses initial URL validation because Workhorse's dialer lacks `WithSSRFFilter`. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/zh-CN/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` (enforced at line 334), and `workflows.rb:1065` (`GET /ws`) allows overriding `workflow_definition` and `ai_catalog_item_version_id`.<br/>**Scenario A:** A restricted `chat` workflow overrides `workflow_definition` and `ai_catalog_item_version_id` on `/ws` to inject withheld write tools (`create_issue`).<br/>**Scenario B:** Attackers enumerate `ai_catalog_item_version_id` to disclose the configured toolset of foreign private (`public: false`) AI Catalog agents.<br/>**Scenario C:** Injected write tools execute during the Duo Workflow session without the intended workflow definition restrictions. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/zh-CN/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **How It Happens in Code:** `McpConfigService#execute` (`mcp_config_service.rb:61`) calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, and `ListService`/`Agent::Create` omit `.in_organization`.<br/>**Scenario A:** An `Ai::Catalog::McpServer` named `"GitLab"` (`:gitlab`, `Tools: nil`) overwrites the built-in `:gitlab` entry so Workhorse (`mcp.go:254`) sets `allToolsAvailable = true`, bypassing `withheld_server_tools`.<br/>**Scenario B:** GraphQL `aiCatalogAgentCreate`/`Update` binds foreign-organization `McpServer` Global IDs.<br/>**Scenario C:** Overwriting `Headers` on `:gitlab` strips `X-Gitlab-Oauth-Token` and causes `401` DoS on `/api/v4/mcp`. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/zh-CN/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) redirects to unvalidated `request_params[:redirect_url]`, passes `request_params[:response_url]` to `VerifyRequest`, and keys Redis `CACHE_KEY` only by `command_id` without `project_id`/`integration_id`.<br/>**Scenario A:** Confirming a slash command redirects (`302 Found`) the authenticated user to an external phishing origin.<br/>**Scenario B:** A `command_id` generated in Project B is replayed on Project A's `/slash_commands/confirm` endpoint.<br/>**Scenario C:** `request_params[:response_url]` overrides the cached `response_url` during `VerifyRequest#approve!`. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/zh-CN/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Upstream Duplicate: `CVE-2026-40295`<br/>*(GitHub Only — Not Submitted to MITRE)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[UPSTREAM DUPLICATE: `CVE-2026-40295` — Published on GitHub Only, Not Submitted to MITRE]**<br/>**How It Happens in Code:** `Gitlab::DeviseFailure` inherits `Devise 5.0.3` `redirect_url` (`CVE-2026-40295`), which redirects to an unsanitized external `Referer` on non-GET `:timeout` failures; `AuthorizationsController#validate_pkce_for_dynamic_applications` (`CAND-03`) has an early return on `nil` `code_challenge_method` (mitigated at runtime by `Doorkeeper 5.9.3`).<br/>**Scenario A/B/C:** Product-level `extract_path_from_location(request.referrer)` override in `lib/gitlab/devise_failure.rb` and controller-level PKCE defense-in-depth patch. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |

## 验证与测试

有关公开能力摘要、最新可复现的 Community 验证快照、证据边界与结果解读指南，请参阅 [VALIDATION.md](../VALIDATION.md)。

Community 文档与元数据门禁可离线且只读运行：

```bash
python3 .github/scripts/validate-community-release.py
```

将可审查的源码发行包构建到当前检出目录之外的新目录中，并对组装生成的目录树进行验证：

```bash
python3 scripts/build-community-source.py --output /ABSOLUTE/PATH/TO/sniper-community-source
python3 .github/scripts/validate-community-release.py \
  --root /ABSOLUTE/PATH/TO/sniper-community-source --scan-release-tree
```

仓库的完整本地测试启动器为：

```bash
python3 -m pip install --no-deps -r requirements-runtime.lock -r requirements-test.lock
python3 scripts/run_all_tests.py
```

部分可选引擎需要单独安装并锁定版本的本地工具。跳过某项可选集成测试并不代表该引擎在您的机器上可用。

## 常见问题

### 什么是 Sniper Community？

Sniper Community 是采用 Apache-2.0 许可的开源应用安全工具包，用于经授权的源代码、依赖项、SBOM、容器、基础设施、网站与 API 审查。它将本地分析器、已保存报告工作流与 CLI、本地回环 Web 界面以及基于 Model Context Protocol（MCP）的可选 AI 辅助审查融为一体。[功能地图](CAPABILITIES.md) 明确区分了内置检查、可选引擎和人工审查。

### 没有 AI 订阅可以使用 Sniper 吗？

可以。CLI 和本地 Web 界面不需要 AI 客户端。可选的 MCP 客户端可以连接其自身的模型提供商；该提供商的可用性、隐私规则和费用独立于 Sniper 的开源许可证。本地硬件和可选第三方工具也有各自的要求。

### 可以在 Windows、macOS 和 Linux 上使用吗？

可以。经过测试的解释器为 Python 3.12。Linux ARM64 和 x86-64 支持完整的原生五引擎安装。在 **macOS（Apple Silicon）** 上，原生源码安装（`python3 scripts/setup-community --core-only`）与五引擎 Docker Desktop 配置（`./scripts/deploy-community-tools --accept-third-party-licenses`）**均已在真实 macOS 硬件上通过验证并正式受支持（并非实验性）**。在 **Windows** 上，Sniper 支持原生 `--core-only` 源码安装（`python3 scripts/setup-community --core-only`）、WSL2 以及通过 Docker Desktop 运行 Linux 容器。平台详情见 [部署指南](../DEPLOYMENT.md) 和 [验证证据](../VALIDATION.md)。

### Sniper 可以扫描网站漏洞吗？

可以，针对您拥有或已获明确评估授权的网站和 API。受支持的工作流可准备有边界的外部目标操作，将 Web 与 TLS 证据同本地源码分析结合，并生成可供复核的发现。执行前需具备相应的引擎、固定模板目录或漏洞数据、运行时就绪状态以及人工批准。参见 [网站/API 工作流](USE-CASES.md#plan-an-authorized-website-or-api-action) 与 [功能边界](CAPABILITIES.md)；没有任何工具能够保证发现所有漏洞。

### Sniper 能帮助发现并修复移动应用漏洞吗？

Sniper 帮助团队在提交 App Store 或 Google Play 之前审查受支持的 Android、iOS、Flutter 和 React Native 代码、清单、依赖项、API 路径和发布配置，将证据转化为按优先级排列的修复工作。覆盖范围取决于受支持的输入：它不是通用的移动二进制扫描器，不能自动修复所有漏洞，也不构成应用商店过审保证。参见 [发布前安全审查](#发布前使用-ai-进行安全审查) 与 [功能地图](CAPABILITIES.md)。

### Sniper 能替代渗透测试或保证安全发布吗？

不能。它生成包括潜在授权与 IDOR 问题在内的证据和审查候选项。具备资质的审查人员必须在授权范围内核实重要发现、测试运行时控制措施并决定修复方案。零告警的扫描结果不是安全认证。参见 [验证证据](../VALIDATION.md)。

### 官方源码和安装说明在哪里？

官方源码仓库位于 [dytredline/Sniper](https://github.com/dytredline/Sniper)。请从适合您平台的 [源码检出安装与配置](#源码检出安装与配置) 和 [部署指南](../DEPLOYMENT.md) 开始。项目概览发布于 [ConverserAI](https://converserai.com/#sniper)；本代码仓库始终是能力范围、平台支持、许可条款和发布证据的唯一权威来源。在学术研究或出版物中引用本软件时，请使用 [CITATION.cff](../CITATION.cff)。

## 许可证

Sniper Community 采用 Apache License 2.0（`Apache-2.0`）授权。完整条款请参阅 [LICENSE](../LICENSE)。第三方组件与可选工具仍遵循其各自的许可证。
