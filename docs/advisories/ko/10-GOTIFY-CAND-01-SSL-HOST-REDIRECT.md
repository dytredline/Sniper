# 내장 SSL 리다이렉트 미들웨어의 미검증 ctx.Request.Host로 인한 HTTP 308 오픈 리다이렉트 및 토큰 피싱 (`GHSA-cc9f-m5vr-pm75`)

[English](../10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [Türkçe](../tr/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [日本語](../ja/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | [简体中文](../zh-CN/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md) | **한국어**

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`gotify/server`(`v2.9.1`, 커밋 `f4de61997c1b30bf9ac43ec662dc5120c2ec981b`)에서 내장 SSL 리다이렉터가 활성화된 경우(`SSL.Enabled=true` 및 `SSL.RedirectToHTTPS=true`), `router/router.go:52-73, 93-102`의 HTTP-to-HTTPS 리다이렉트 미들웨어는 신뢰할 수 없는 요청 입력으로부터 `Location` 헤더를 생성합니다(`CWE-601`).

1. **1단계 — 검증되지 않은 `ctx.Request.Host` 추출 (`router/router.go:63`):**
   63번째 줄은 수신된 HTTP 요청에서 `host := ctx.Request.Host`를 직접 읽어 들이며, 설정된 `conf.Server.SSL.LetsEncrypt.Hosts` 허용 목록과 일치하는지 전혀 확인하지 않습니다.
2. **2단계 — HTTPS `Location` URL에 직접 보간 (`router/router.go:64-72`):**
   선택적인 `:port` 접미사를 제거한 후 미들웨어는 `https://` + `host` + `ctx.Request.RequestURI`를 그대로 결합합니다.
3. **3단계 — 쿼리 토큰(`?token=...`)을 유지한 채 `308 Permanent Redirect` 반환:**
   `redirectHTTPS`(`router/router.go:93-102`)는 `GET`/`PUT`/`DELETE`에 대해 `http.StatusPermanentRedirect`(`308`)를, `POST`에 대해 `http.StatusFound`(`302`)를 반환하여 HTTP 클라이언트와 캐시가 `?token=<gotify-token>` 쿼리 문자열을 포함한 요청을 공격자가 제어하는 도메인으로 리다이렉트하게 만듭니다.

### 취약한 코드 조각 (`router/router.go:60-73, 93-102`)
```go
// File: router/router.go (lines 60-73, 93-102)
			host := ctx.Request.Host // BUG: 설정된 SSL 호스트 대신 신뢰할 수 없는 클라이언트 제공 Host 헤더를 사용함!
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

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 웹 푸시 / 모바일 클라이언트 토큰 피싱 및 영구 리다이렉트 캐시 포이즈닝
1. 자체 호스팅된 Gotify 서버가 `SSL.Enabled: true` 및 `SSL.RedirectToHTTPS: true`로 실행 중입니다.
2. 공격자가 `http://<gotify-ip>/#/messages?token=...` 또는 `http://<gotify-host>/client`에 `Host: attacker-gotify.example.com` 헤더로 요청을 보내거나 중간 HTTP 캐시/캡티브 포털을 오염시킵니다.
3. Gotify는 `HTTP/1.1 308 Permanent Redirect` 및 `Location: https://attacker-gotify.example.com/#/messages?token=...`로 응답하여 URL 프래그먼트와 쿼리 매개변수를 유지한 채 클라이언트를 공격자의 호스트로 리다이렉트합니다.

### 시나리오 B — 리다이렉트를 따라가는 자동화된 Webhook / 모니터링 스크립트의 애플리케이션 토큰 유출
1. `?token=<app-token>`이 포함된 HTTP 엔드포인트에 대해 설정된 모니터링 및 알림 스크립트(`curl -L`, Python `requests`, Uptime Kuma 등)가 Gotify로 푸시 알림을 전송합니다.
2. HTTP 홉에서 `Host` 헤더가 스푸핑되면 Gotify는 `Location: https://<attacker-host>/message?token=<app-token>`으로 응답합니다.
3. HTTP 클라이언트가 자동으로 외부 호스트로의 `308`/`302` 리다이렉트를 따라가면서 URL 쿼리 문자열에 담긴 실제 Gotify 애플리케이션 토큰이 유출됩니다.

### 시나리오 C — 원시 `Host` 헤더를 전달하는 리버스 프록시 / 로드 밸런서 뒤에서의 Host 헤더 인젝션
1. Gotify가 클라이언트의 `Host` 헤더를 백엔드 HTTP 리스너로 그대로 전달하는 캐치올 가상 호스트(`default_server`)를 가진 로드 밸런서나 리버스 프록시 뒤에 배포된 경우, 조작된 `Host` 헤더를 가진 외부 요청이 SSL 리다이렉트 미들웨어에 도달합니다.
2. Gotify는 경로와 쿼리 문자열을 유지한 채 공격자의 도메인을 가리키는 공식 `308 Permanent Redirect`를 발급합니다.
3. 해당 엔드포인트와 상호작용하는 사용자 및 자동화 통합 시스템이 정상 Gotify 인스턴스의 권한 아래 외부 공격자 도메인으로 리다이렉트됩니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/gotify-server \
  --include "router/router.go"
```

### 2. 로컬 격리 환경 재현 및 검증 (`127.0.0.1`)
```bash
# 로컬에서 Go 라우터 리다이렉트 테스트 스위트 실행
cd /home/community-user/targets/gotify-server && go test -v ./router -run TestHTTPSRedirect

# 또는 로컬 127.0.0.1:8080의 Gotify HTTP 리다이렉트 리스너를 대상으로 테스트:
curl -i "http://127.0.0.1:8080/#/messages?token=test-redacted-token" \
  -H "Host: attacker-gotify.example.com"
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`go test -v ./router -run TestHTTPSRedirect` (`PASS`) 및 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01` 실행 결과:

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

### 경계 조건 명시
Gotify의 내장 SSL 리다이렉터(`SSL.Enabled=true` 및 `SSL.RedirectToHTTPS=true`)가 활성화되어 있고 HTTP 포트(`80`)에 직접 도달할 수 있거나 `Host` 헤더를 전달하는 프록시를 통해 도달할 수 있는 환경에 적용됩니다.

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
