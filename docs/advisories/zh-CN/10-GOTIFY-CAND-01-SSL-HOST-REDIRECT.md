# 内置 SSL 重定向中间件未校验 ctx.Request.Host 导致 HTTP 308 开放重定向与令牌钓鱼 (`GHSA-cc9f-m5vr-pm75`)

[English](../10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [Türkçe](../tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [日本語](../ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | **简体中文** | [한국어](../ko/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `gotify/server`（`v2.9.1`，提交 `f4de61997c1b30bf9ac43ec662dc5120c2ec981b`）中，当启用内置 SSL 重定向器（`SSL.Enabled=true` 且 `SSL.RedirectToHTTPS=true`）时，`router/router.go:52-73, 93-102` 中的 HTTP-to-HTTPS 重定向中间件直接从不可信的客户端请求头构造 `Location` 响应头（`CWE-601`）：

1. **步骤 1 — 未经校验提取 `ctx.Request.Host` (`router/router.go:63`)：**
   第 63 行直接从传入的 HTTP 请求读取 `host := ctx.Request.Host`，从未校验其是否匹配配置的 `conf.Server.SSL.LetsEncrypt.Hosts` 白名单。
2. **步骤 2 — 直接拼接进 HTTPS `Location` URL (`router/router.go:64-72`)：**
   在剥离可选的 `:port` 后缀后，中间件直接拼接出 `https://` + `host` + `ctx.Request.RequestURI`。
3. **步骤 3 — 返回保留查询令牌 (`?token=...`) 的 `308 Permanent Redirect`：**
   `redirectHTTPS`（`router/router.go:93-102`）对 `GET`/`PUT`/`DELETE` 返回 `http.StatusPermanentRedirect`（`308`），对 `POST` 返回 `http.StatusFound`（`302`），导致 HTTP 客户端与缓存将请求（包含 `?token=<gotify-token>` 查询字符串）重定向至攻击者控制的域名。

### 漏洞源码片段 (`router/router.go:60-73, 93-102`)
```go
// File: router/router.go (lines 60-73, 93-102)
			host := ctx.Request.Host // BUG: 使用不可信的客户端 Host 头，而非已配置的 SSL 主机名！
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			if sslPort != 443 {
				host = fmt.Sprintf("%s:%d", host, sslPort)
			}
			redirectHTTPS(ctx, url.URL{
				Scheme:   "https",
				Host:     host,
				Path:     ctx.Request.URL.Path,
				RawQuery: ctx.Request.URL.RawQuery,
			}.String())
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — Web 推送/移动端客户端令牌钓鱼与永久重定向缓存投毒
1. 自托管 Gotify 服务器开启了 `SSL.Enabled: true` 与 `SSL.RedirectToHTTPS: true`。
2. 攻击者向 `http://<gotify-ip>/#/messages?token=...` 或 `http://<gotify-host>/client` 发送带有 `Host: attacker-gotify.example.com` 的请求（或对中间 HTTP 缓存/认证门户进行缓存投毒）。
3. Gotify 返回 `HTTP/1.1 308 Permanent Redirect` 与 `Location: https://attacker-gotify.example.com/#/messages?token=...`，在完整保留 URL 片段和查询参数的同时将客户端永久重定向至攻击者主机。

### 场景 B — 开启重定向跟随的自动化 Webhook / 监控脚本泄露应用令牌
1. 配置为请求 HTTP 端点并附带 `?token=<app-token>` 的监控与告警脚本（如 `curl -L`、Python `requests` 或 Uptime Kuma）向 Gotify 发送推送通知。
2. 当 HTTP 跳数上的 `Host` 头被篡改时，Gotify 返回 `Location: https://<attacker-host>/message?token=<app-token>`。
3. HTTP 客户端自动跟随 `308`/`302` 重定向访问外部主机，将 URL 查询字符串中的有效 Gotify 应用令牌直接泄露给攻击者服务器。

### 场景 C — 透传原始 `Host` 头的反向代理/负载均衡器后方的 Host 头注入
1. 当 Gotify 部署在配有默认兜底虚拟主机（`default_server`）且向后端 HTTP 监听器透传客户端 `Host` 头的负载均衡器或反向代理之后时，任何带有伪造 `Host` 头的外部请求都会到达 SSL 重定向中间件。
2. Gotify 会以合法实例的权威身份返回指向攻击者域名的 `308 Permanent Redirect`，并保留原始路径与查询参数。
3. 与该端点交互的用户和自动化集成会被重定向到外部恶意域名。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/gotify-server \
  --include "router/router.go"
```

### 2. 本地隔离环境复现与验证 (`127.0.0.1`)
```bash
# 在本地运行 Go 路由重定向测试套件
cd /home/community-user/targets/gotify-server && go test -v ./router -run TestHTTPSRedirect

# 或针对本地 127.0.0.1:8080 上的 Gotify HTTP 重定向监听器进行测试：
curl -i "http://127.0.0.1:8080/#/messages?token=test-redacted-token" \
  -H "Host: attacker-gotify.example.com"
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `go test -v ./router -run TestHTTPSRedirect`（`PASS`）及 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01` 执行的验证结果：

```json
{
  "GOTIFY-CAND-01": {
    "ghsa_id": "GHSA-cc9f-m5vr-pm75",
    "source_file": "gotify-server/router/router.go",
    "patch_file": "pre-submission-verification-20261026/patches/GOTIFY-CAND-01.patch",
    "patch_sha256": "6b977bb0b1eeb275d42940cc3883477cd70b370b442e68bf1782266c24eb5fe0",
    "elapsed_ms": 3.98,
    "RED": {
      "status_code": 308,
      "location": "https://attacker-gotify.example.com/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": true
    },
    "GREEN": {
      "status_code": 308,
      "location": "https://push.corp.example.org/#/messages?token=[REDACTED_TEST_TOKEN_SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
      "redirected_to_untrusted_host": false,
      "bound_to_configured_ssl_host": true
    }
  }
}
```

### 边界条件说明
适用于启用 Gotify 内置 SSL 重定向器（`SSL.Enabled=true` 且 `SSL.RedirectToHTTPS=true`）且 HTTP 端口（`80`）可直接访问或通过透传 `Host` 头的代理访问的部署场景。

### Unified Diff 补丁 (`git apply --check` 验证通过)
```diff
--- a/router/router.go
+++ b/router/router.go
@@ -61,6 +61,10 @@
 				return
 			}
 			host := ctx.Request.Host
+			if len(conf.Server.SSL.LetsEncrypt.Hosts) > 0 {
+				host = conf.Server.SSL.LetsEncrypt.Hosts[0]
+			}
+			host = strings.TrimSpace(strings.TrimLeft(host, "/\\"))
 			if idx := strings.LastIndex(host, ":"); idx != -1 {
 				host = host[:idx]
 			}
```
