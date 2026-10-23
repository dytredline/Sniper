# Sniper Community

[English](../README.md) | [日本語](README.ja.md) | **简体中文** | [한국어](README.ko.md)

Sniper Community 是一套开源、本地优先的防御性应用安全工具，适合应用、API 和网站的开发者、所有者与
安全审查人员使用。它把受支持的源代码静态分析（SAST）、依赖项与 SBOM 分析（SCA）、容器制品、
基础设施即代码（IaC）、CI 配置以及已保存的安全报告纳入同一条审查流程。

对于您拥有或已获得明确授权的 Web/API 目标，Sniper 还可以先生成一个范围明确、需要人工审查的执行计划。
Sniper 不承诺发现所有漏洞，也不能证明某个系统绝对安全。

## 发布前使用 AI 进行安全审查

在提交 App Store 或 Google Play 之前，可让 AI 助手通过 Sniper 的本地 stdio MCP 审查受支持的 Android、
iOS、Flutter、React Native 源码与移动端清单。API 路径、密钥线索、依赖项、SBOM 和 CI 配置集中在同一
发布前视图中，便于解释发现并确定修复优先级。同一流程也适用于网站/API 上线和发布 pull request。

## 适用对象和价值

| 用户 | 可解决的问题 |
| --- | --- |
| 应用和 API 开发者 | 在本地审查受支持的代码路径、安全模式、配置和依赖关系 |
| 网站所有者 | 审查本地项目，并核对授权目标的范围、时间、速率限制和停止条件 |
| 平台团队 | 检查 Terraform、Kubernetes、Helm、Dockerfile、Compose、云 IAM 和 CI 工作流 |
| 安全审查人员 | 对 SARIF 和受支持的已保存报告进行有边界的汇总、证据整理与人工复核 |

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

## 内置功能与五个可选引擎

内置分析器、报告解析器、MCP 服务器、CLI 和仅回环访问的 Web UI 都包含在源代码树中。除此之外，
无 root 的本地配置还可以选择安装五个锁定版本的第三方引擎：

- Nuclei 3.11.1
- Trivy 0.75.0
- Gitleaks 8.30.1
- TruffleHog 3.99.0
- Opengrep 1.30.1

只有在相应的可执行文件、SHA-256、所需数据、输入范围和许可证就绪检查通过后，可选引擎才会显示为可用。
Nuclei 的广泛授权 HTTP 流程还需要单独固定的模板目录；Trivy 的漏洞配置还需要单独固定的离线数据库。
Sniper 的内置分析独立于这五个可选引擎。

## MCP、命令行和本地 Web

- **MCP：** AI 客户端通过本地 stdio 服务器读取受支持的上下文、解释发现并准备操作。
- **CLI：** 人员或脚本可以运行本地审查、CI 门禁和报告导出。
- **本地 Web：** 人员可通过仅回环访问的界面选择并审查已经通过就绪检查的能力。

会改变状态的 Community MCP 操作采用两步协议。`prepare_action` 返回不可变计划、同意范围、有效期和
SHA-256；AI 必须把原样计划展示给用户。只有用户在同一对话中明确批准后，MCP 主机才能使用同一计划调用
`execute_action` 并发送 `user_confirmed: true`。AI 不能自行批准。详情参见
[Community MCP 指南](COMMUNITY-MCP.md)。

## 安装

经过测试的解释器为 Python 3.12。Community v1 的完整原生安装和五个可选引擎仅支持 Linux ARM64/x86-64。
不支持 Windows 原生安装；macOS 仅提供实验性的 `--core-only` 源码安装。面向 Windows/macOS Docker Desktop
和 WSL2 的 Linux 容器配置已经提供并通过契约测试，但本版本尚无真实 Windows/macOS 主机运行证据。在受支持的仓库根目录运行：

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

该参数表示您已经查看 `COMMUNITY-TOOLS.lock.json` 中记录的第三方许可证。安装程序会创建 `.venv`，安装并
验证锁定的依赖项和本地工具，但不会启动服务器、打开数据库或运行扫描器。具体要求见
[Community 工具安装说明](COMMUNITY-TOOLS.md)。

## 安全与授权边界

- 只能用于您拥有的系统，或您已经获得明确评估授权的系统。
- 执行任何外部操作前，应由人员核对目标、书面范围、时间、速率限制、数据处理规则和停止条件。
- MCP 进程使用本地 stdio，但 AI 客户端可能把所选源代码或发现发送给其模型提供商。
- “没有发现”只适用于已选择的输入、已启用的检查和现有数据，并不是安全认证。
- 不要把私钥、令牌、密码、客户数据或生产数据库放进 issue 或 AI 提示词。

## 权威功能资料

完整且权威的功能地图以 [Capabilities and security checks](CAPABILITIES.md) 这一规范源文件为准。本简体中文页面仅提供
概览，不会扩大受支持范围或修改限制。实际使用场景见 [USE-CASES.md](USE-CASES.md)，面向 AI 的项目索引见
[llms.txt](../llms.txt)，可复现测试结果及其证据边界见 [VALIDATION.md](../VALIDATION.md)。
