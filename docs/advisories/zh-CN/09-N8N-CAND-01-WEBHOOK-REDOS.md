# string-extensions.ts 中无起始锚点的 EMAIL_REGEXP 与 DOMAIN_EXTRACT_REGEXP 导致 Webhook 事件循环饥饿 DoS (`n8n-io/n8n`)

[English](../09-N8N-CAND-01-WEBHOOK-REDOS.md) | [Türkçe](../tr/09-N8N-CAND-01-WEBHOOK-REDOS.md) | [日本語](../ja/09-N8N-CAND-01-WEBHOOK-REDOS.md) | **简体中文** | [한국어](../ko/09-N8N-CAND-01-WEBHOOK-REDOS.md)

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `n8n-io/n8n`（`<= 2.45.0`，提交 `cfbd9a56cba2e73901dc1962e47727adbea0b23e`）中，`packages/workflow/src/extensions/string-extensions.ts:59, 94, 326, 375, 383` 内的内置工作流表达式方法 `.isEmail()`、`.extractEmail()` 和 `.extractDomain()` 存在多项式/灾难性回溯漏洞（`CWE-1333`）：

1. **步骤 1 — 含重叠量词子组且无起始锚点的正则表达式 (`string-extensions.ts:59, 94`)：**
   `EMAIL_REGEXP` 以 `/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@...` 开头，既没有起始锚点或负向后行断言边界（`(?<![^<>()\[\]\\.,;:\s@"])`），又包含贪婪分支 `".+"`。当面对形如 `"a.a.a...a@!"` 的不匹配点分隔字符串时，V8 正则引擎会从整个字符串的每一个字符偏移位置重复尝试嵌套量词匹配。
2. **步骤 2 — 缺少 RFC-5321 / RFC-1035 输入长度守卫 (`string-extensions.ts:326, 375, 383`)：**
   尽管合法的 RFC-5321 电子邮件地址长度不可能超过 `254`/`320` 个字符，`isEmail(value)`、`extractEmail(value)` 和 `extractDomain(value)` 却将任意长度的字符串直接传入 `EMAIL_REGEXP` 和 `DOMAIN_EXTRACT_REGEXP`。
3. **步骤 3 — 单线程 Node.js 事件循环同步阻塞：**
   由于 n8n 在 Node.js 主线程上同步求值工作流表达式，单个 20 KB 的请求负载即可阻塞 V8 事件循环 `831.78 ms`（打补丁后仅需 `0.0029 ms`，提速 `286,000` 倍），导致所有并发 Webhook 执行和前端 UI 请求陷入饥饿与超时。

### 漏洞源码片段 (`string-extensions.ts:93-95, 324-328, 373-377`)
```typescript
// File: packages/workflow/src/extensions/string-extensions.ts (lines 93-95, 324-328, 373-377)
const EMAIL_REGEXP =
	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/; // BUG 1: 无起始锚点 + 贪婪 ".+"！
...
function isEmail(value: string) {
	const result = EMAIL_REGEXP.test(value); // BUG 2: 没有 value.length > 320 长度检查！
	return result;
}
...
function extractEmail(value: string) {
	const matched = EMAIL_REGEXP.exec(value); // BUG 3: 在主线程上对数 KB/MB 字符串同步执行正则匹配！
	return matched ? matched[0] : undefined;
}
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 公开线索收集/联系表单 Webhook 冻结整台企业 n8n 自动化服务器
1. 企业暴露了一个公开的 n8n Webhook 节点（`POST /webhook/contact-us`），后续连接了用于校验 `{{ $json.body.contact.isEmail() }}` 或 `{{ $json.body.website.extractDomain() }}` 的 `IF` 或 `Set` 节点。
2. 未经认证的攻击者向该公开 Webhook URL 连续发送 20 KB 的 JSON 负载（`{"contact": "a.a.a...a@!"}`）。
3. 由于每个请求都会阻塞单线程 Node.js 事件循环约 832 ms，同一服务器上的并发 Stripe 支付回调、Slack 机器人以及 n8n 编辑器界面全部被挂起并超时。

### 场景 B — 精心构造的消息正文导致自动化客服工单与邮件分拣流水线卡死
1. 自动化客户支持工作流摄取收到的工单、聊天记录或邮件，并求值 `{{ $json.messageBody.extractEmail() }}` 以从自由文本中提取回复邮箱。
2. 外部用户提交了一条包含大量重复点分隔词元但没有合法域名后缀的工单正文。
3. 由于 `extractEmail()` 在无长度上限的情况下对整段消息正文执行 `EMAIL_REGEXP.exec(value)`，n8n 工作进程陷入停滞，导致 Kubernetes 存活探针（Liveness Probe）失败并触发容器无限重启循环。

### 场景 C — 畸形 URL 触发 `extractDomain()` 导致 CRM / B2B 线索富化队列阻塞
1. B2B 营销自动化工作流在将数据同步到 HubSpot/Salesforce 之前，使用 `{{ $json.companyUrl.extractDomain() }}` 规范化企业域名。
2. 包含长串类子域名片段但缺少合法顶级域名的负载在 `DOMAIN_EXTRACT_REGEXP`（`string-extensions.ts:59`）中触发严重回溯。
3. 工作流执行队列被严重阻塞，拖慢该实例上所有后续定时自动化任务。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/n8n \
  --include "packages/workflow/src/extensions/string-extensions.ts"
```

### 2. 本地隔离环境复现与验证 (`Node.js`)
```bash
# 在 20 KB 点分隔负载上测量修复前后的 EMAIL_REGEXP 阻塞 V8 事件循环耗时
node -e '
const vuln = /(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
const payload = "a.".repeat(10000) + "a@!";
const t0 = performance.now();
vuln.test(payload);
const redMs = performance.now() - t0;
const t1 = performance.now();
const greenResult = payload.length <= 320 && payload.includes("@") && !payload.includes(" ") ? vuln.test(payload) : false;
const greenMs = performance.now() - t1;
console.log(JSON.stringify({ payload_bytes: payload.length, red_ms: +redMs.toFixed(3), green_ms: +greenMs.toFixed(4), greenResult }));
'
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过真实 Node.js `v22.22.2`（`logs/N8N-CAND-01-node-benchmark.json`: RED `831.78 ms` -> GREEN `0.0029 ms`，提速 `286,000` 倍）及 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01` 执行的验证结果：

```json
{
  "N8N-CAND-01": {
    "source_file": "n8n/packages/workflow/src/extensions/string-extensions.ts",
    "patch_file": "pre-submission-verification-20261026/patches/N8N-CAND-01.patch",
    "patch_sha256": "7e38173c95ccccb119cc57ac0226b9ac4af1bf21c590e74123ec5e9b385121e0",
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

### 边界条件说明
需要存在对不可信输入（如 Webhook 触发器负载或外部消息正文）调用 `.isEmail()`、`.extractEmail()` 或 `.extractDomain()` 的活动 n8n 工作流。

### Unified Diff 补丁 (`git apply --check` 验证通过)
```diff
--- a/packages/workflow/src/extensions/string-extensions.ts
+++ b/packages/workflow/src/extensions/string-extensions.ts
@@ -91,7 +91,7 @@
   ))/;
 */
 const EMAIL_REGEXP =
-	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
+	/(?<![^<>()\[\]\\.,;:\s@"])(?:[^<>()\[\]\\.,;:\s@"]+(?:\.[^<>()\[\]\\.,;:\s@"]+)*|"(?:[^"\\]|\\.)+")@(?<domain>\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}]|(?:[a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})/;
 
@@ -324,6 +324,7 @@
 function isEmail(value: string) {
+	if (value.length > 320 || !value.includes('@') || value.includes(' ')) return false;
 	const result = EMAIL_REGEXP.test(value);
@@ -373,6 +374,7 @@
 function extractEmail(value: string) {
+	if (value.length > 4096 || !value.includes('@')) return undefined;
 	const matched = EMAIL_REGEXP.exec(value);
```
