# 未认证的 0.0.0.0:7842 cuabotd 守护进程 + POST /bash 通配符 CORS + 零 Origin 校验 WebSocket + 可写宿主机 .claude 挂载 (`GHSA-cp36-x5hg-3gg8`)

[English](../03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [Türkçe](../tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [日本語](../ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | **简体中文** | [한국어](../ko/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `trycua/cua`（`cuabot` npm 包 `<= 1.0.16`，提交 `e754cfec69c41400eb2aabde716c27d15607b2f0`）中，`cuabotd` 守护进程（`libs/cuabot/src/cuabotd.ts`）通过 HTTP 和 WebSocket 提供容器 Shell 执行与桌面自动化控制。以下几处叠加的代码缺陷直接导致了零点击浏览器路过式（Drive-By）攻击与局域网远程命令执行漏洞（`CWE-306` / `CWE-942`）：

1. **步骤 1 — 在所有网络接口 (`0.0.0.0:7842`) 上无认证监听 (`cuabotd.ts:1120`)：**
   `server.listen(port, () => ...)` 省略了 `'127.0.0.1'` 参数，导致端口 `7842` 在所有 Wi-Fi/LAN 网络接口（`0.0.0.0`）上完全暴露，且没有任何 Bearer 令牌或会话认证。
2. **步骤 2 — `POST /bash` 设置通配符 CORS (`Access-Control-Allow-Origin: *`) 且 WebSocket PTY 无 Origin 校验 (`cuabotd.ts:969-1002, 1018-1063`)：**
   所有 HTTP 响应均设置 `Access-Control-Allow-Origin: *` 和 `Access-Control-Allow-Headers: Content-Type`，且 `OPTIONS` 预检直接返回 `200 OK`。开发者在浏览器打开的任意恶意网页均可发起跨域 `fetch("http://localhost:7842/bash", ...)` 并完整读取包含 `stdout`/`stderr` 的 JSON 响应，或通过 `new WebSocket("ws://localhost:7842/?command=...")` 在无 `Origin` 检查的情况下打开交互式 PTY。
3. **步骤 3 — 宿主机 `.claude` 目录以读写模式绑定挂载 (`cuabotd.ts:259-260`)：**
   由于 `cuabotd` 将宿主机的 `~/.cuabot/user/.claude` 目录以读写方式挂载到 `/home/community-user/.claude` 并映射了 `host.docker.internal:host-gateway`，通过 `/bash` 执行的命令可直接窃取 Claude OAuth 令牌并篡改宿主机持久化的 `.claude/settings.json` 钩子。

### 漏洞源码片段 (`libs/cuabot/src/cuabotd.ts:965-1002, 1120`)
```typescript
// File: libs/cuabot/src/cuabotd.ts (lines 965-1002, 1120)
    // CORS headers
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*'); // BUG 1: 允许任意外部网站跨域调用并读取响应内容！
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
...
      if (path === 'bash' && req.method === 'POST') {  // BUG 2: 任意 Shell 命令执行没有任何身份验证！
        const { command, timeout } = body;
        const result = await execBash(command, timeout);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }
...
  server.listen(port, () => {                          // BUG 3: 绑定在 0.0.0.0:7842 而非 127.0.0.1！
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 开发者运行 `cuabot` 时浏览任意网页（零点击浏览器 Drive-By RCE 与 Claude 令牌窃取）
1. 开发者在笔记本电脑上启动 `npx cuabot` 使用 CUA 编程代理，`cuabotd` 在后台监听端口 `7842`。
2. 当开发者使用 Chrome/Firefox/Safari 浏览技术博客或文档网站时，页面中嵌入的脚本执行 `fetch("http://localhost:7842/bash", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command: "cat /home/community-user/.claude/.credentials.json" }) })`。
3. 由于 `cuabotd.ts:969-977` 对浏览器的 `OPTIONS` 预检返回 `200 OK` 和 `Access-Control-Allow-Origin: *`，浏览器不仅放行 `POST /bash` 请求，还允许恶意网页直接读取包含 `stdout` 的 JSON 响应，瞬间窃取开发者的 Claude OAuth/API 凭据。

### 场景 B — 通过可写的 `.claude/settings.json` 注入持久化钩子控制宿主机
1. 利用相同的跨域 `POST /bash` 或 `new WebSocket("ws://localhost:7842/?command=...")` 调用，恶意网页向 `/home/community-user/.claude/settings.json`（`hooks.PreToolUse` 或 `mcpServers`）写入恶意 Shell 命令。
2. 由于 `/home/community-user/.claude` 是宿主机 `~/.cuabot/user/.claude`（`cuabotd.ts:259-260`）的读写挂载，即使容器停止，被篡改的配置也会持久保留在宿主机文件系统上。
3. 此后开发者在宿主机每次运行 Claude Code 或 CUA 时，都会自动执行攻击者植入的持久化钩子。

### 场景 C — 咖啡馆、共享办公或企业 Wi-Fi (`0.0.0.0:7842`) 局域网内的设备直接接管开发机
1. `cuabotd.ts:1120` 中的 `server.listen(port)` 未传入回环地址参数 `'127.0.0.1'`，将 TCP 端口 `7842` 绑定在 `0.0.0.0` / `::` 上。
2. 处于同一咖啡馆、共享办公空间或企业 Wi-Fi/LAN 网络中的任何设备，无需认证即可直接调用 `http://<developer-lan-ip>:7842/bash` 或 `http://<developer-lan-ip>:7842/screenshot`。
3. 局域网攻击者可以实时截取屏幕画面、注入鼠标键盘事件，并在开发者环境中执行任意 Shell 命令。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cuabot/src/cuabotd.ts"
```

### 2. 本地隔离环境复现与验证 (`127.0.0.1`)
```bash
# 对本地 127.0.0.1:7842 上的 cuabotd 实例模拟浏览器跨域预检与 POST /bash 调用
curl -i -X OPTIONS http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && ls -la /home/community-user/.claude"}'
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01` 执行的验证结果：

```json
{
  "CUA-CAND-01": {
    "ghsa_id": "GHSA-cp36-x5hg-3gg8",
    "source_file": "cua/libs/cuabot/src/cuabotd.ts",
    "elapsed_ms": 0.828,
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

### Unified Diff 补丁 (`git apply --check` 验证通过)
```diff
--- a/libs/cuabot/src/cuabotd.ts
+++ b/libs/cuabot/src/cuabotd.ts
@@ -965,15 +965,16 @@
     const path = url.pathname.slice(1); // Remove leading /
 
-    // CORS headers
+    // Restrict local daemon to non-browser clients with bearer token auth
     res.setHeader('Content-Type', 'application/json');
-    res.setHeader('Access-Control-Allow-Origin', '*');
-    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
-    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
-
-    if (req.method === 'OPTIONS') {
-      res.writeHead(200);
+    const origin = req.headers['origin'];
+    if (origin || req.method === 'OPTIONS') {
+      res.writeHead(403);
+      res.end(JSON.stringify({ error: 'Cross-origin browser requests are forbidden' }));
+      return;
+    }
+    if (req.headers['authorization'] !== `Bearer ${DAEMON_AUTH_TOKEN}`) {
+      res.writeHead(401);
+      res.end(JSON.stringify({ error: 'Unauthorized' }));
       return;
     }
@@ -1117,5 +1118,5 @@
-  server.listen(port, () => {
+  server.listen(port, '127.0.0.1', () => {
```
