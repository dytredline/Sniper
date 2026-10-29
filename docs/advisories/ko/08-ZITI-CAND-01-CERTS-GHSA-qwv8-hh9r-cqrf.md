# AreCertsTrusted()가 무조건 InsecureSkipVerify: true를 설정하여 ziti edge login 시 TLS 인증서 검증이 비활성화되는 취약점 (`GHSA-qwv8-hh9r-cqrf`)

[English](../08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [Türkçe](../tr/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [日本語](../ja/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | [简体中文](../zh-CN/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md) | **한국어**

## GitHub GHSA 및 MITRE CNA 양식 필드 요약
- **저장소:** `openziti/ziti`
- **GitHub 보안 권고 URL:** `https://github.com/openziti/security/security/advisories/GHSA-qwv8-hh9r-cqrf`
- **기존 GHSA ID:** `GHSA-qwv8-hh9r-cqrf`
- **에코시스템:** `Go`
- **패키지 이름:** `github.com/openziti/ziti/v2`
- **영향받는 버전:** `<= v2 (commit 236f351a5149fe68328fc8083bebe514f0307d0c)`
- **패치된 버전:** `없음 (패치 첨부)`
- **CWE:** `CWE-295 (부적절한 인증서 검증 — Improper Certificate Validation)`
- **CVSS v3.1:** `7.4 High — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **MITRE 벤더:** `NetFoundry / OpenZiti`
- **MITRE 취약점 유형:** `Improper Certificate Validation (CWE-295)`
- **MITRE 영향받는 컴포넌트:** `ziti/util/certs.go (AreCertsTrusted & InsecureClient, lines 91-103, 199-208) 및 ziti/cmd/edge/login.go (fetchTrustedServerCerts, lines 511, 535-549)`
- **MITRE 권장 CVE 설명:**
  > OpenZiti ziti 커밋 `236f351a5149fe68328fc8083bebe514f0307d0c` 이하(`github.com/openziti/ziti/v2`)에서 `ziti/util/certs.go`의 `util.AreCertsTrusted`는 `InsecureClient(&client, certs)`를 호출하는데, 이 함수는 `len(certs) > 0`인 경우에도 무조건 `tls.Config{InsecureSkipVerify: true}`를 설정합니다. Go의 `crypto/tls`는 `InsecureSkipVerify`가 `true`일 때 `RootCAs`를 무시하므로 `AreCertsTrusted` 내부의 `x509.UnknownAuthorityError` 검사는 도달할 수 없는 사문화된 코드(dead code)가 되며, `ziti edge login` 실행 중 `AreCertsTrusted`가 항상 `true`를 반환하여 신뢰할 수 없는 TLS 인증서를 가진 중간자(MITM) 공격자가 관리자 자격 증명을 가로챌 수 있습니다.
- **제보자 / 크레딧:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`openziti/ziti`(`github.com/openziti/ziti/v2`, 커밋 `236f351a5149fe68328fc8083bebe514f0307d0c`)에서 `ziti edge login`(`ziti/cmd/edge/login.go:511, 535-549`)은 컨트롤러의 `/.well-known/est/cacerts`에서 CA 번들을 가져온 뒤, 자격 증명을 전송하기 전에 서버의 리프 TLS 인증서가 해당 CA 번들로 서명되었는지 검증하기 위해 `util.AreCertsTrusted(host, wellKnownCerts, httpClient)`(`ziti/util/certs.go:91-103`)를 호출합니다. 그러나 `InsecureClient`의 치명적인 결함으로 인해 이 검증이 완전히 무력화됩니다(`CWE-295`).

1. **1단계 — `AreCertsTrusted`에서 의도한 `x509.UnknownAuthorityError` 검사 (`ziti/util/certs.go:91-103`):**
   `AreCertsTrusted`는 `host`에 HTTPS `GET` 요청을 보내고 95-98번째 줄에서 `if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) { return false, nil }`를 검사합니다.
2. **2단계 — `InsecureClient`에서 무조건적인 `InsecureSkipVerify: true` 설정 (`ziti/util/certs.go:199-208`):**
   `AreCertsTrusted`는 `InsecureClient(&client, certs)`를 통해 HTTP 클라이언트를 생성합니다. `len(certs) > 0`이고 인증서가 `tlsConfig.RootCAs`에 추가되었음에도 202번째 줄에서 `InsecureSkipVerify: true`를 하드코딩합니다.
3. **3단계 — `ziti edge login` 중 `RootCAs` 검증 완전 우회:**
   Go의 `crypto/tls`에서 `InsecureSkipVerify: true`를 설정하면 `RootCAs`에 대한 인증서 체인 검증을 완전히 건너뜁니다. 결과적으로 `x509.UnknownAuthorityError`는 절대 발생하지 않고 96번째 줄은 도달 불가능한 데드 코드가 되며, 모든 위조된 MITM 인증서에 대해 `AreCertsTrusted`가 항상 `true, nil`을 반환하고 `login.go:511`은 `"Verified that server supplied certificates are trusted by server"`를 출력한 뒤 관리자 자격 증명을 공격자에게 전송합니다.

### 취약한 코드 조각 (`ziti/util/certs.go:91-103, 199-208`)
```go
// File: ziti/util/certs.go (lines 91-103, 199-208)
func AreCertsTrusted(host string, certs []byte, httpClient *http.Client) (bool, error) {
	client := *httpClient
	resp, err := InsecureClient(&client, certs).Get(host)
	if err != nil {
		if ue, ok := err.(*url.Error); ok && errors.As(ue.Err, &x509.UnknownAuthorityError{}) {
			return false, nil // DEAD CODE: InsecureSkipVerify가 무조건 true이므로 절대 도달하지 않음!
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
		InsecureSkipVerify: true, // BUG: RootCAs가 실제로 적용되려면 len(certs) == 0 이어야 함!
	}
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — DevOps 엔지니어가 Wi-Fi / VPN에서 `ziti edge login` 실행 시 위조된 MITM 컨트롤러로 관리자 비밀번호 전송
1. 관리자가 워크스테이션에서 `ziti edge login https://ziti-controller.internal:1280 -u admin -p <AdminPassword>`를 실행합니다.
2. 네트워크상의 능동적 공격자(ARP 스푸핑, 불량 Wi-Fi 또는 DNS 하이재킹)가 신뢰할 수 없는 자체 서명 TLS 인증서로 연결을 가로채면서 `/.well-known/est/cacerts`에는 정상처럼 보이는 CA 번들을 제공합니다.
3. `AreCertsTrusted`가 `InsecureSkipVerify: true`를 그대로 두기 때문에 Go의 `crypto/tls`는 서버의 TLS 인증서가 `/.well-known/est/cacerts` 풀에 의해 서명되었는지 전혀 검증하지 않으며, `login.go:511`은 `"Verified that server supplied certificates are trusted by server"`를 잘못 출력하고 관리자의 비밀번호나 토큰을 MITM 공격자에게 직접 전송합니다.

### 시나리오 B — 신뢰할 수 없는 TLS 리프 인증서를 통한 자동화된 CI/CD 및 Kubernetes 제로트러스트 등록 파이프라인 침해
1. 자동화된 CI/CD 파이프라인이나 Kubernetes 초기화 작업이 제로트러스트 서비스 ID와 라우터 정책을 부트스트랩하기 위해 `ziti edge login --yes`를 실행합니다.
2. 네트워크 경로상의 공격자가 컨트롤러의 EST CA 번들로 서명되지 않은 임의의 비신뢰 리프 TLS 인증서를 제시합니다.
3. `AreCertsTrusted()`가 무조건 `true, nil`을 반환하므로 파이프라인은 신뢰할 수 없는 인증서 체인을 저장하고 침해된 연결을 통해 높은 권한의 등록 자격 증명을 전송합니다.

### 시나리오 C — 다중 클러스터 운영 환경에서 만료되거나 잘못된 CA로 서명된 컨트롤러 인증서를 경고 없이 수락
1. 인그레스 프록시 뒤에서 별도의 `dev`, `staging`, `prod` OpenZiti 환경을 운영하는 다중 클러스터 기업에서 프록시가 컨트롤러의 EST CA로 서명되지 않은 만료된 인증서나 자체 서명 리프 인증서를 제시합니다.
2. `login.go:545`에 의도된 경고(`"Server supplied certs are not trusted by server"`)가 발생하는 대신 `AreCertsTrusted()`가 인증서 체인이 검증되었다고 잘못 보고하여 운영자가 신뢰할 수 없는 엔드포인트에 운영 자격 증명을 인증하게 됩니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/ziti \
  --include "ziti/util/certs.go"
```

### 2. 로컬 격리 환경 재현 및 검증 (`127.0.0.1`)
```bash
# 로컬 127.0.0.1 TLS 서버를 대상으로 AreCertsTrusted 동작을 증명하는 Go 단위 테스트 실행
cd /home/community-user/targets/ziti && go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`go test -v -run TestRealOpenZitiAreCertsTrusted ./ziti/util` (`0.014s` 만에 `PASS`) 및 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01` 실행 결과:

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

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
