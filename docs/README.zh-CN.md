# Sniper Community

[English](../README.md) | [Türkçe](README.tr.md) | [日本語](README.ja.md) | **简体中文** | [한국어](README.ko.md)

[ConverserAI 项目概览](https://converserai.com/#sniper) · [功能清单](CAPABILITIES.md) · [安装与配置](#安装) · [常见问题](#常见问题)

Sniper Community 是一套开源、本地优先的防御性应用安全工具，适合应用、API 和网站的开发者、所有者与
安全审查人员使用。它把受支持的源代码静态分析（SAST）、依赖项与 SBOM 分析（SCA）、容器制品、
基础设施即代码（IaC）、CI 配置以及已保存的安全报告纳入同一条审查流程。
对于您拥有或已获得明确授权的 Web/API 目标，Sniper 还可以先生成一个范围明确、需要人工审查的执行计划。
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

**使用强大的开源工具包查找网站安全弱点。** 将经授权的网站和 API 扫描与本地代码及依赖项审查相结合，将发现转化为按优先级排列的修复计划。外部扫描需要相应的引擎、数据、就绪检查和明确的范围批准。参见[网站与 API 审查路径](USE-CASES.md#plan-an-authorized-website-or-api-action)。

在提交 App Store 或 Google Play 之前，可让 AI 助手通过 Sniper 的本地 stdio MCP 审查受支持的 Android、
iOS、Flutter、React Native 源码与移动端清单。API 路径、密钥线索、依赖项、SBOM 和 CI 配置集中在同一
发布前视图中，便于解释发现并确定修复优先级。同一流程也适用于网站/API 上线和发布 pull request。

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

完整且带证据链接的功能清单见 [Capabilities and security checks](CAPABILITIES.md)，实用场景见 [USE-CASES.md](USE-CASES.md)，AI 项目索引见 [llms.txt](../llms.txt)，最新可复现验证证据见 [VALIDATION.md](../VALIDATION.md)。

## 安全审查亮点

- **跟踪高影响数据流：** 跟踪受支持的源到汇（source-to-sink）路径，覆盖 SQL/命令注入、XSS/HTML、SSRF、开放重定向、路径遍历、不安全反序列化、XXE、表达式语言（EL）和 LDAP 风险，并支持 SARIF `codeFlows`。
- **聚焦访问控制测试：** 整理路由、角色与对象标识符，优先检查 IDOR（CWE-639）和授权缺失候选项（CWE-862）。
- **发现暴露的密钥与隐私路径：** 在保持密钥脱敏的同时，结合提供商特征与熵信号追踪流向日志、响应、存储和第三方的隐私数据流。
- **理解依赖项与软件供应链：** 清点直接与传递组件，生成或导入 CycloneDX/SPDX SBOM，配合 VEX 与可达性上下文开展审查。
- **加固容器、云与交付流水线：** 在同一审查界面检查 Dockerfile、Terraform、Kubernetes、Helm、Compose、云 IAM、CI、移动端、浏览器扩展和桌面应用配置。
- **审查 API、网站与 TLS：** 对比本地 OpenAPI 契约与源码路由，检查认证不匹配并评估 Web/TLS 安全信号。
- **确定修复优先级：** 使用 CVSS 3.1/4.0、CISA SSVC、攻击路径关联、负责人、截止日期、基线和质量门禁确定修复顺序。
- **选择合适的工作流：** 通过本地回环 Web、CLI、CI 或 stdio MCP，输出 JSON、HTML、SARIF、GitLab、SBOM、VEX 和受支持的 PDF 报告。

## IDOR 与人工渗透测试支持

对于受支持的 Python 和 JavaScript/TypeScript 源码，内置路由与授权清单会标出可能缺少授权检查的路由
（CWE-862），以及潜在的不安全直接对象引用（IDOR）路径（CWE-639），并给出文件、路由和行号证据。
这些线索可帮助已获授权的测试人员使用不同的测试用户、角色和合成对象，确定人工渗透测试的优先顺序。

每个候选项都为授权范围内的人工验证提供有证据的起点；测试人员可使用不同的测试用户、角色和合成对象进行核验。

## 安全审查亮点

- 跟踪受支持的数据流，聚焦 SQL/命令注入、XSS、SSRF、开放重定向、路径遍历、不安全反序列化和 XXE。
- 整理路由、角色与对象标识符，优先检查 IDOR（CWE-639）和授权缺失候选项（CWE-862）。
- 汇总密钥线索与隐私数据流，并把依赖项、容器、CycloneDX/SPDX SBOM、VEX 和可达性上下文纳入同一审查。
- 检查 Dockerfile、Terraform、Kubernetes、Helm、Compose、云 IAM、CI、移动端、浏览器扩展和桌面应用配置。
- 使用 CVSS 3.1/4.0、CISA SSVC、攻击路径、基线和质量门禁确定修复优先级，并输出 JSON、HTML、SARIF、
  GitLab、SBOM、VEX 和受支持的 PDF 工作流。
- 通过本地 Web、CLI、CI 或 stdio MCP，让人员和 AI 使用同一套证据开展审查。

## IDOR 与人工渗透测试支持

对于受支持的 Python 和 JavaScript/TypeScript 源码，内置路由与授权清单会标出可能缺少授权检查的路由
（CWE-862），以及潜在的不安全直接对象引用（IDOR）路径（CWE-639），并给出文件、路由和行号证据。
这些线索可帮助已获授权的测试人员使用不同的测试用户、角色和合成对象，确定人工渗透测试的优先顺序。

每个候选项都为授权范围内的人工验证提供有证据的起点；测试人员可使用不同的测试用户、角色和合成对象进行核验。

## 内置功能与七个可选引擎

内置分析器、报告解析器、MCP 服务器、CLI 和仅回环访问的 Web UI 都包含在源代码树中。除此之外，
无 root 的本地配置还可以选择安装七个锁定版本的第三方引擎：

- Nuclei 3.11.1
- Trivy 0.75.0
- Gitleaks 8.30.1
- TruffleHog 3.99.0
- Syft 1.55.0
- Grype 0.121.0
- Opengrep 1.30.1

只有在相应的可执行文件、SHA-256、所需数据、输入范围和许可证就绪检查通过后，可选引擎才会显示为可用。
Nuclei 的广泛授权 HTTP 流程还需要单独固定的模板目录；Trivy 的漏洞配置还需要单独固定的离线数据库。
Sniper 的内置分析独立于这七个可选引擎。多语言界面与语言包说明见 [LOCALIZATION.md](LOCALIZATION.md)。

## 版本状态与包含内容

本仓库为 Sniper Community v1.1.0 源码版本，采用 Apache License 2.0（[LICENSE](../LICENSE)）授权。包含本地项目分析、本地报告与质量门禁命令、AI 优先的 stdio MCP 工作流、针对状态变更操作的对话式人工审批边界、手动 CLI、本地回环 Web 界面以及测试与文档。

## 安装

经过测试的解释器为 Python 3.12。Community v1 的完整原生七引擎安装支持 Linux ARM64/x86-64。
在 **macOS（Apple Silicon）**上，原生 `--core-only` 源码安装（`python3 scripts/setup-community --core-only`）与
Docker Desktop 五引擎配置（`./scripts/deploy-community-tools --accept-third-party-licenses`）**均已在真实
macOS 主机上完成验证并受支持（并非实验性功能）**。在 **Windows** 上，Sniper 支持原生 `--core-only` 源码安装
（`python3 scripts/setup-community --core-only`）、WSL2 以及 Docker Desktop 的 Linux 容器（详见 [VALIDATION.md](../VALIDATION.md) 与 [DEPLOYMENT.md](../DEPLOYMENT.md)）。

在 Linux 上安装并验证锁定的依赖项和七个本地工具：

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

在 Linux、macOS 或 Windows 上进行不含可选 Linux 引擎二进制文件的原生核心（`--core-only`）源码安装：

```bash
python3 scripts/setup-community --core-only
```

在 Windows/macOS Docker Desktop 或 WSL2 中构建核心镜像或五引擎镜像：

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

在 macOS Apple Silicon + Docker Desktop 上一键构建、启动并验证全部五个本地引擎预检，请运行 `./scripts/deploy-community-tools --accept-third-party-licenses`；将 Mac 本地项目复制到持久化 Docker 卷，请运行 `./scripts/import-community-project /absolute/path/to/project --name project-name`。安装后可通过 `.venv/bin/python scripts/sniper-mcp --help`、`python3 scripts/sniper-project-audit --help` 和 `python3 cli_reports.py --help` 验证入口。具体要求见 [Community 工具安装说明](COMMUNITY-TOOLS.md)。

## MCP、命令行和本地 Web

- **MCP：** AI 客户端通过本地 stdio 服务器（`.venv/bin/python scripts/sniper-mcp --mode community`）读取受支持的上下文、解释发现并准备操作。
- **CLI：** 人员或脚本可以运行本地审查、CI 门禁和报告导出。
- **本地 Web：** 人员可通过仅回环访问的界面（`127.0.0.1:8787`）选择并审查已经通过就绪检查的能力。

会改变状态的 Community MCP 操作采用两步协议。`prepare_action` 返回不可变计划、同意范围、有效期和
SHA-256；AI 必须把原样计划展示给用户。只有用户在同一对话中明确批准后，MCP 主机才能使用同一计划调用
`execute_action` 并发送 `user_confirmed: true`。AI 不能自行批准。详情参见
[Community MCP 指南](COMMUNITY-MCP.md)。

## 安全与授权边界及验证报告

- 只能用于您拥有的系统，或您已经获得明确评估授权的系统。
- 执行任何外部操作前，应由人员核对目标、书面范围、时间、速率限制、数据处理规则和停止条件。
- MCP 进程使用本地 stdio，但 AI 客户端可能把所选源代码或发现发送给其模型提供商。
- “没有发现”只适用于已选择的输入、已启用的检查和现有数据，并不是安全认证。
- 不要把私钥、令牌、密码、客户数据或生产数据库放进 issue 或 AI 提示词。
- 安全维护者（Security Maintainer）：**Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))。私有漏洞报告见 [SECURITY.md](../SECURITY.md)，macOS 真机验证与 8 个开源仓库审计报告见 [VALIDATION.md](../VALIDATION.md) 和 [SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md)。

## 常见问题

### 什么是 Sniper Community？

Sniper Community 是采用 Apache-2.0 许可的开源应用安全工具包，用于经授权的源代码、依赖项、SBOM、容器、基础设施、网站与 API 审查。[功能地图](CAPABILITIES.md)区分了内置检查、可选引擎和人工审查。

### 没有 AI 订阅可以使用 Sniper 吗？

可以。CLI 和本地 Web 界面不需要 AI 客户端。可选的 MCP 客户端可连接其模型提供商，提供商的费用与隐私规则独立于 Sniper 的开源许可证。

### 可以在 Windows、macOS 和 Linux 上使用吗？

可以。经过测试的解释器为 Python 3.12。Linux ARM64 和 x86-64 支持完整的原生五引擎安装。在 **macOS（Apple Silicon）**上，原生 `--core-only` 源码安装与 Docker Desktop 五引擎配置**均已在真实 macOS 硬件上通过验证并正式受支持（并非实验性）**。在 **Windows** 上，Sniper 支持原生 `--core-only` 源码安装、WSL2 以及通过 Docker Desktop 运行 Linux 容器。详见 [DEPLOYMENT.md](../DEPLOYMENT.md) 和 [VALIDATION.md](../VALIDATION.md)。

### Sniper 可以扫描网站漏洞吗？

可以，针对您拥有或已获明确评估授权的网站和 API。受支持的工作流可准备有边界的外部目标操作，并将 Web/TLS 证据与本地源码分析结合。

### Sniper 能帮助发现并修复移动应用漏洞吗？

可以。它帮助团队在提交 App Store 或 Google Play 之前审查受支持的 Android、iOS、Flutter 和 React Native 代码、清单、依赖项、API 路径和发布配置，并生成按优先级排序的修复工作。

### Sniper 能替代渗透测试或保证发布绝对安全吗？

不能。它提供证据与审查候选项（包括潜在授权和 IDOR 问题），重要发现仍需具备资质的审查人员在授权范围内复核。

### 官方源码和安装说明在哪里？

官方仓库为 [dytredline/Sniper](https://github.com/dytredline/Sniper)，项目介绍见 [ConverserAI](https://converserai.com/#sniper)，学术与研究引用见 [CITATION.cff](../CITATION.cff)，许可证为 Apache License 2.0（[LICENSE](../LICENSE)）。
