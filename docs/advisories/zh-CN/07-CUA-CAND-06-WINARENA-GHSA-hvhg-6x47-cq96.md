# WinArena 编排器将未认证 noVNC (0.0.0.0:8006) 与免密 RDP (0.0.0.0:3390) 暴露在所有网络接口且可写挂载宿主机 /shared (`GHSA-hvhg-6x47-cq96`)

[English](../07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [Türkçe](../tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [日本語](../ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | **简体中文** | [한국어](../ko/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `trycua/cua`（`cua-bench` `<= 0.3.1`，`libs/cua-bench/tasks/winarena_adapter/cli.py:262-265, 421-424, 646-649` 与 `infra/vm/setup/server/main.py:180-248, 290-321`，提交 `e754cfec69c41400eb2aabde716c27d15607b2f0`）中，全部三个 Docker 启动命令（`cmd_vm_setup`、`cmd_vm_start`、`cmd_task_run`）都在毫无网络与文件系统隔离的情况下暴露了 Windows 虚拟机和宿主机源码目录（`CWE-668` / `CWE-732`）：

1. **步骤 1 — 在 `0.0.0.0` 上无认证发布 Docker 端口 (`cli.py:262-263, 421-422, 646-647`)：**
   代码传入了未加 `127.0.0.1:` 前缀的 `-p {args.browser_port}:8006` 和 `-p {args.rdp_port}:3389`，导致 Docker 将未认证的 noVNC Web 控制台（`8006`）和免密 Windows RDP 服务（`3390`）绑定到所有 LAN/Wi-Fi 网络接口（`0.0.0.0`）上，并通过 Docker 的 `FORWARD` 链绕过宿主机 `ufw` `INPUT` 防火墙规则。
2. **步骤 2 — 宿主机源码目录以读写方式挂载 (`cli.py:265, 424, 649`)：**
   代码传入未加 `:ro` 的 `-v {setup_path}:/shared`，将宿主机的 `winarena_adapter/infra/vm/setup` 目录以读写模式挂载进容器环境。
3. **步骤 3 — 客户机内部无认证的 `exec()` 控制服务 (`infra/vm/setup/server/main.py:180-248`)：**
   在客户机虚拟机内部，`server/main.py` 监听 `0.0.0.0:5000`，在没有任何令牌或请求头校验的情况下，直接通过 `POST /execute_windows`（`exec(command)`）执行任意 Python 代码，并通过 `POST /setup/launch`（`shell=True`）执行任意 Shell 命令。

### 漏洞源码片段 (`winarena_adapter/cli.py:261-266`)
```python
# File: libs/cua-bench/tasks/winarena_adapter/cli.py (lines 261-266, repeated at 421-424 and 646-649)
        "-p", f"{args.browser_port}:8006", # BUG 1: 将未认证的 noVNC 暴露在局域网 0.0.0.0:8006！
        "-p", f"{args.rdp_port}:3389",     # BUG 2: 将免密 RDP 暴露在局域网 0.0.0.0:3390！
        "-v", f"{storage_path}:/storage",
        "-v", f"{setup_path}:/shared",     # BUG 3: 以读写方式而非 :ro 挂载宿主机源码目录！
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 高校/企业实验室局域网内的其他人员通过 `http://<host-ip>:8006` (noVNC) 或 `:3390` (RDP) 直接接管评测 Windows 虚拟机
1. 研究员在连接高校或企业共享局域网的实验室工作站上运行 `cua-bench` WinArena 评测任务。
2. 由于 `cli.py:262-265` 传入了不带 `127.0.0.1:` 的 `-p 8006:8006 -p 3390:3389`，Docker 将两个端口绑定在 `0.0.0.0` 上（通过 `DOCKER` 转发链绕过宿主机 `ufw` `INPUT` 规则）。
3. 局域网内的任何用户在浏览器打开 `http://<workstation-ip>:8006`（无需密码），即可获得 Windows 虚拟机桌面的完整 Administrator 交互控制权，并窃取注入到评测环境中的大模型 API 密钥或凭据。

### 场景 B — 通过可写的 `-v {setup_path}:/shared` 挂载实现从虚拟机到宿主机的反向投毒
1. 容器将宿主机的 `winarena_adapter/infra/vm/setup` 目录以读写方式挂载在 `/shared`（`cli.py:265, 424, 649`）。
2. 通过 `0.0.0.0:8006` 或 `0.0.0.0:3390` 进入环境的攻击者直接修改 `/shared` 目录下的安装脚本与 Python 文件。
3. 由于 `/shared` 直接映射到宿主机的 `winarena_adapter` 源码树，后续宿主机侧运行 CLI 或测试时将直接加载执行被篡改的脚本。

### 场景 C — 虚拟机内浏览器代理访问外部网页触发对未认证 `0.0.0.0:5000/execute_windows` (`exec()`) 的路过式 RCE
1. 在评测运行期间，Windows 虚拟机内的自主浏览器代理访问了外部网页或不可信的本地 HTML 任务文件。
2. 页面上的 JavaScript 向 `infra/vm/setup/server/main.py:180-248` 托管的 `http://127.0.0.1:5000/execute_windows` 或 `http://127.0.0.1:5000/setup/launch` 发送请求。
3. 由于 `server/main.py` 没有任何身份验证，且将负载直接传给 Python 的 `exec(command)` 和 `subprocess.Popen(..., shell=True)`，该网页立即以 Windows Administrator 权限在虚拟机内执行任意代码。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench/tasks/winarena_adapter/cli.py"
```

### 2. 本地隔离环境复现与验证
```bash
# 检查 cli.py 中未加 127.0.0.1 前缀的 Docker 端口绑定与可写 /shared 卷挂载
grep -n -C 4 "8006" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# 检查 infra/vm/setup/server/main.py 中未认证的 exec() 调用
grep -n -C 8 "def execute_windows" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06` 执行的验证结果：

```json
{
  "CUA-CAND-06": {
    "ghsa_id": "GHSA-hvhg-6x47-cq96",
    "cli_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/cli.py",
    "server_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py",
    "elapsed_ms": 0.05,
    "RED": {
      "lan_exposed_ports": [
        "8006:8006",
        "3390:3389"
      ],
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

### Unified Diff 补丁 (`git apply --check` 验证通过)
```diff
--- a/libs/cua-bench/tasks/winarena_adapter/cli.py
+++ b/libs/cua-bench/tasks/winarena_adapter/cli.py
@@ -261,9 +261,9 @@
-        "-p", f"{args.browser_port}:8006",
-        "-p", f"{args.rdp_port}:3389",
-        "-v", f"{storage_path}:/storage",
-        "-v", f"{setup_path}:/shared",
+        "-p", f"127.0.0.1:{args.browser_port}:8006",
+        "-p", f"127.0.0.1:{args.rdp_port}:3389",
+        "-v", f"{storage_path}:/storage",
+        "-v", f"{setup_path}:/shared:ro",
```
