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
