# AreCertsTrusted() 无条件设置 InsecureSkipVerify: true 导致 ziti edge login 期间 TLS 证书校验完全失效 (`GHSA-qwv8-hh9r-cqrf`)

[English](../08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [Türkçe](../tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [日本語](../ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | **简体中文** | [한국어](../ko/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

## GitHub GHSA 与 MITRE CNA 表单快速填写字段
- **代码仓库:** `openziti/ziti`
- **GitHub 安全公告 URL:** `https://github.com/openziti/security/security/advisories/GHSA-qwv8-hh9r-cqrf`
- **现有 GHSA ID:** `GHSA-qwv8-hh9r-cqrf`
- **生态系统:** `Go`
- **软件包名称:** `github.com/openziti/ziti/v2`
- **受影响版本:** `<= v2 (commit 236f351a5149fe68328fc8083bebe514f0307d0c)`
- **已修复版本:** `无（附修复补丁）`
- **CWE:** `CWE-295 (证书校验不当 — Improper Certificate Validation)`
- **CVSS v3.1:** `7.4 High — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **MITRE 厂商:** `NetFoundry / OpenZiti`
- **MITRE 漏洞类型:** `Improper Certificate Validation (CWE-295)`
- **MITRE 受影响组件:** `ziti/util/certs.go (AreCertsTrusted & InsecureClient, lines 91-103, 199-208) 与 ziti/cmd/edge/login.go (fetchTrustedServerCerts, lines 511, 535-549)`
- **MITRE 建议漏洞描述:**
  > 在 OpenZiti ziti 提交 `236f351a5149fe68328fc8083bebe514f0307d0c` 及更早版本（`github.com/openziti/ziti/v2`）中，`ziti/util/certs.go` 中的 `util.AreCertsTrusted` 调用了 `InsecureClient(&client, certs)`，而该函数即使在 `len(certs) > 0` 时也无条件设置 `tls.Config{InsecureSkipVerify: true}`。由于 Go 的 `crypto/tls` 在 `InsecureSkipVerify` 为 `true` 时会忽略 `RootCAs`，`AreCertsTrusted` 中的 `x509.UnknownAuthorityError` 检查成为永不可达的死代码，`AreCertsTrusted` 在 `ziti edge login` 期间始终返回 `true`，从而使持有不可信 TLS 证书的中间人（MITM）攻击者能够截获管理员凭据。
- **报告者 / 致谢:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `openziti/ziti`（`github.com/openziti/ziti/v2`，提交 `236f351a5149fe68328fc8083bebe514f0307d0c`）中，`ziti edge login`（`ziti/cmd/edge/login.go:511, 535-549`）会从控制器的 `/.well-known/est/cacerts` 获取 CA 证书包，并在发送管理员凭据前调用 `util.AreCertsTrusted(host, wellKnownCerts, httpClient)`（`ziti/util/certs.go:91-103`），以验证服务器的 TLS 叶子证书是否确实由该 CA 证书包签发。然而，`InsecureClient` 中的一处致命缺陷彻底关闭了这一验证（`CWE-295`）：

1. **步骤 1 — `AreCertsTrusted` 中原本预期的 `x509.UnknownAuthorityError` 检查 (`ziti/util/certs.go:91-103`)：**
   `AreCertsTrusted` 对 `host` 发起 HTTPS `GET` 请求，并在第 95-98 行检查 `if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) { return false, nil }`。
2. **步骤 2 — `InsecureClient` 无条件硬编码 `InsecureSkipVerify: true` (`ziti/util/certs.go:199-208`)：**
   `AreCertsTrusted` 通过 `InsecureClient(&client, certs)` 构建 HTTP 客户端。即使 `len(certs) > 0` 且证书已被追加到 `tlsConfig.RootCAs` 中，第 202 行仍然硬编码了 `InsecureSkipVerify: true`。
3. **步骤 3 — `ziti edge login` 期间完全跳过 `RootCAs` 证书链校验：**
   在 Go 标准库 `crypto/tls` 中，设置 `InsecureSkipVerify: true` 会完全跳过针对 `RootCAs` 的证书链验证。因此，`x509.UnknownAuthorityError` 永远不会抛出，第 96 行成为永不可达的死代码，`AreCertsTrusted` 对任何伪造的中间人证书始终返回 `true, nil`，且 `login.go:511` 会打印 `"Verified that server supplied certificates are trusted by server"` 并将管理员密码直接发送给攻击者。

### 漏洞源码片段 (`ziti/util/certs.go:91-103, 199-208`)
```go
// File: ziti/util/certs.go (lines 91-103, 199-208)
func AreCertsTrusted(host string, certs []byte, httpClient *http.Client) (bool, error) {
	client := *httpClient
	resp, err := InsecureClient(&client, certs).Get(host)
	if err != nil {
		if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) {
			return false, nil // DEAD CODE: 因为 InsecureSkipVerify 无条件为 true，永远不会执行到这里！
		}
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}
...
func InsecureClient(client *http.Client, certs []byte) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true, // BUG: 应为 len(certs) == 0，否则 RootCAs 永远不会生效！
	}
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 运维工程师通过 Wi-Fi / VPN 运行 `ziti edge login` 时将管理员账号密码发送给伪造的中间人控制器
1. 管理员在工作站上执行 `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminPassword>`。
2. 处于网络路径上的主动攻击者（通过 ARP 欺骗、伪造 Wi-Fi 热点或 DNS 劫持）使用不可信的自签名 TLS 证书拦截连接，同时在 `/.well-known/est/cacerts` 上返回看似合法的 CA 证书包。
3. 由于 `AreCertsTrusted` 保留了 `InsecureSkipVerify: true`，Go 的 `crypto/tls` 从未校验服务器 TLS 证书是否由 `/.well-known/est/cacerts` 签发；`login.go:511` 错误地输出 `"Verified that server supplied certificates are trusted by server"`，并直接将管理员密码或令牌发送给中间人攻击者。

### 场景 B — 自动化 CI/CD 与 Kubernetes 零信任注册流水线被伪造 TLS 叶子证书劫持
1. 自动化 CI/CD 流水线或 Kubernetes 初始化任务运行 `ziti edge login --yes` 来初始化零信任服务身份与路由器策略。
2. 网络路径上的攻击者出示任意未经控制器 EST CA 证书包签发的伪造叶子 TLS 证书。
3. 由于 `AreCertsTrusted()` 无条件返回 `true, nil`，流水线会将不可信证书链持久化保存，并在被劫持的连接上发送高权限注册凭据。

### 场景 C — 多集群运维中静默接受过期、自签名或跨环境的错误控制器证书
1. 在运行独立 `dev`、`staging` 和 `prod` OpenZiti 环境的多集群企业中，入口代理配置错误导致前端返回了过期、自签名或并非由控制器 EST CA 签发的叶子证书。
2. `AreCertsTrusted()` 不会触发 `login.go:545` 预期的告警（`"Server supplied certs are not trusted by server"`），反而谎报证书链已通过验证，导致运维人员向不可信端点发送生产环境凭据。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/ziti \
  --include "ziti/util/certs.go"
```

### 2. 本地隔离环境复现与验证 (`127.0.0.1`)
```bash
# 运行针对本地 127.0.0.1 TLS 服务器验证 AreCertsTrusted 行为的 Go 单元测试
cd /home/community-user/targets/ziti && go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util`（`0.014s` 内 `PASS`）及 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01` 执行的验证结果：

```json
{
  "ZITI-CAND-01": {
    "ghsa_id": "GHSA-qwv8-hh9r-cqrf",
    "source_file": "ziti/ziti/util/certs.go",
    "login_caller_file": "ziti/ziti/cmd/edge/login.go",
    "elapsed_ms": 0.719,
    "RED": {
      "insecure_skip_verify": true,
      "rogue_mitm_cert_accepted_as_trusted": true,
      "admin_credentials_sent_to_mitm": true
    },
    "GREEN": {
      "insecure_skip_verify": false,
      "rogue_mitm_cert_accepted_as_trusted": false,
      "tls_error": "x509.UnknownAuthorityError: certificate signed by unknown authority"
    },
    "BENIGN": {
      "valid_ca_signed_controller_trusted": true
    }
  }
}
```

### Unified Diff 补丁 (`git apply --check` 验证通过)
```diff
--- a/ziti/util/certs.go
+++ b/ziti/util/certs.go
@@ -199,7 +199,7 @@
 func InsecureClient(client *http.Client, certs []byte) *http.Client {
 	tlsConfig := &tls.Config{
 		RootCAs:            x509.NewCertPool(),
-		InsecureSkipVerify: true,
+		InsecureSkipVerify: len(certs) == 0,
 	}
 
 	if len(certs) > 0 {
```
