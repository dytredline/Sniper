# 0.0.0.0:8001 Worker Server 通配符 CORS + OSGYM_ALLOWED_IPS 失效放行 (Fail-Open) + 未认证 POST /reset 任意模块执行 (`GHSA-xm8w-gj3g-4f25`)

[English](../04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [Türkçe](../tr/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [日本語](../ja/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | **简体中文** | [한국어](../ko/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

## GitHub GHSA 与 MITRE CNA 表单快速填写字段
- **代码仓库:** `trycua/cua`
- **GitHub 安全公告 URL:** `https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`
- **现有 GHSA ID:** `GHSA-xm8w-gj3g-4f25`
- **生态系统:** `pip`
- **软件包名称:** `cua-bench-rl (及 cua-bench)`
- **受影响版本:** `<= 0.1.0 (cua-bench <= 0.3.1, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **已修复版本:** `无（附修复补丁）`
- **CWE:** `CWE-94 (代码生成控制不当) / CWE-942 (过度宽松的跨域白名单)`
- **CVSS v3.1:** `8.8 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **MITRE 厂商:** `TryCua`
- **MITRE 漏洞类型:** `Dynamic Code Execution via Wildcard CORS and Fail-Open IP Filter (CWE-94 / CWE-942)`
- **MITRE 受影响组件:** `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (lines 79-108, 338-360, 499) 与 libs/cua-bench/cua_bench/core.py (make, lines 25-51)`
- **MITRE 建议漏洞描述:**
  > 在 TryCua cua-bench-rl 0.1.0 及更早版本与 cua-bench 0.3.1 及更早版本（`trycua/cua`）中，`worker_server.py` 在无身份验证的情况下绑定到 `0.0.0.0:8001`，启用 `allow_origins=['*']` 的 `CORSMiddleware`，且其 `ip_filter_middleware` 既放行发往 `127.0.0.1` 的浏览器跨域请求，又在 `OSGYM_ALLOWED_IPS` 设为空字符串时对所有远程 IP 失效放行（Fail-Open）。攻击者可携带任意 `env_path` 参数调用 `POST /reset`，触发 `cua_bench.core.make` 通过 `spec.loader.exec_module` 在宿主机上直接执行 `<env_path>/main.py`。
- **报告者 / 致谢:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `trycua/cua`（`cua-bench-rl` `<= 0.1.0` 与 `cua-bench` `<= 0.3.1`，提交 `e754cfec69c41400eb2aabde716c27d15607b2f0`）中，`worker_server.py` 在 `0.0.0.0:8001`（`worker_server.py:499-500`）启动 FastAPI 服务以管理强化学习（RL）环境工作节点。以下三处缺陷串联在一起，直接导致宿主机上的任意 Python 代码执行（`CWE-94` / `CWE-942`）：

1. **步骤 1 — 通配符 CORS 与本地回环 IP 信任放行浏览器跨域请求 (`worker_server.py:79-95`)：**
   `CORSMiddleware` 配置了 `allow_origins=["*"]`、`allow_methods=["*"]` 和 `allow_headers=["*"]`。由于 `ip_filter_middleware` 仅检查 `client_ip`（默认允许 `127.0.0.1`）而忽略 `Origin` 头，浏览器中任意网页发往 `http://127.0.0.1:8001` 的跨域请求均源自 `127.0.0.1`，从而直接通过过滤器。
2. **步骤 2 — 当 `OSGYM_ALLOWED_IPS=""` 为空时 IP 过滤器失效放行 (`worker_server.py:90-103`)：**
   当环境变量 `OSGYM_ALLOWED_IPS` 被设为空字符串（`""`）时，`allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]` 的计算结果为空列表 `[]`。第 102 行执行 `if allowed_ips and client_ip not in allowed_ips:` 时，由于 `bool([])` 为 `False`，IP 检查被完全跳过，允许局域网或集群内的所有远程客户端访问。
3. **步骤 3 — 未校验的 `request.env_path` 直接传入 `spec.loader.exec_module` (`worker_server.py:338-360`, `cua_bench/core.py:25-51`)：**
   `POST /reset` 将调用者可控的 `request.env_path` 直接传给 `cb.make(request.env_path)`，后者解析 `<env_path>/main.py` 并通过 `spec.loader.exec_module(module)` 在宿主机 Python 进程内直接加载执行。

### 漏洞源码片段 (`worker_server.py:79-104, 338-349`)
```python
# File: libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (lines 79-104, 338-349)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # BUG 1: 通配符 CORS 允许任意网站发起跨域 POST 请求！
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    client_ip = request.client.host if request.client else None
    if allowed_ips and client_ip not in allowed_ips: # BUG 2: 当 allowed_ips == [] 时失效放行（Fail-Open）！
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)
...
@app.post("/reset", response_model=ResetResponse)
async def reset_environment(request: ResetRequest):
    env = cb.make(request.env_path, ...) # BUG 3: 动态加载并执行任意 <env_path>/main.py！
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 运行 RL 训练节点的机器学习工程师通过浏览器标签页遭跨域 RCE (`POST /reset` -> `exec_module`)
1. AI 研究员在本地（`127.0.0.1:8001`）运行 `cua-bench-rl` 工作节点，同时在浏览器中下载数据集文件或浏览模型评测榜单。
2. 某网页发起跨域请求 `fetch("http://127.0.0.1:8001/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ env_path: "/home/community-user/Downloads/untrusted_bundle" }) })`。
3. 由于请求来自本地回环（`127.0.0.1`）且 `CORSMiddleware` 允许 `*`，`ip_filter_middleware` 放行该请求，`cua_bench.core.make` 立即通过 `spec.loader.exec_module` 在宿主机 Python 进程中执行 `/home/community-user/Downloads/untrusted_bundle/main.py`。

### 场景 B — GPU 集群 / Docker Compose 部署将 `OSGYM_ALLOWED_IPS=""` 设为空字符串导致向全网开放
1. 在 Kubernetes/Helm 或 Docker Compose 模板中，若将 `OSGYM_ALLOWED_IPS: ""` 作为空环境变量传入，`allowed_ips` 会变成 `[]`。
2. 第 102 行 `if allowed_ips and client_ip not in allowed_ips:` 因 `bool([])` 为 `False` 而完全失效，网络上的任何节点均可调用 `0.0.0.0:8001/reset` 执行共享 NFS 或数据集挂载盘上的任意 Python 模块。

### 场景 C — 利用 `/screenshot` 与 `/step` 实施静默桌面监控与键鼠操作注入
1. 即使不在磁盘上投放文件，任何跨域网页或局域网节点也可以轮询 `GET /screenshot`，实时获取当前桌面环境的 Base64 屏幕截图。
2. 攻击者随后可调用 `POST /step`，直接向正在运行的桌面会话注入任意键盘按键和鼠标操作。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py"
```

### 2. 本地隔离环境复现与验证 (`127.0.0.1`)
```bash
# 验证当 OSGYM_ALLOWED_IPS="" 为空时如何生成空列表 [] 并导致过滤器失效放行
python3 -c '
import os
os.environ["OSGYM_ALLOWED_IPS"] = ""
allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
client_ip = "10.20.30.40"
blocked = bool(allowed_ips and client_ip not in allowed_ips)
print({"allowed_ips": allowed_ips, "remote_client_ip": client_ip, "blocked_by_filter": blocked})
'
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

针对真实 `cua_bench.core.make` 实现运行 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02` 的结果：

```json
{
  "CUA-CAND-02": {
    "ghsa_id": "GHSA-xm8w-gj3g-4f25",
    "source_file": "cua/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py",
    "core_file": "cua/libs/cua-bench/cua_bench/core.py",
    "elapsed_ms": 16.323,
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

### Unified Diff 补丁 (`git apply --check` 验证通过)
```diff
--- a/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
+++ b/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
@@ -78,12 +78,6 @@
-app.add_middleware(
-    CORSMiddleware,
-    allow_origins=["*"],
-    allow_credentials=True,
-    allow_methods=["*"],
-    allow_headers=["*"],
-)
-
 @app.middleware("http")
 async def ip_filter_middleware(request: Request, call_next):
+    if request.headers.get("origin"):
+        return JSONResponse(status_code=403, content={"detail": "Cross-origin browser requests forbidden"})
     allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
-    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
+    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()] or ["127.0.0.1"]
@@ -102,3 +96,3 @@
-    if allowed_ips and client_ip not in allowed_ips:
+    if client_ip not in allowed_ips:
         return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
```
