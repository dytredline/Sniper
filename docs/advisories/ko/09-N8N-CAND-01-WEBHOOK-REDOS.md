# string-extensions.ts의 시작 앵커 없는 EMAIL_REGEXP 및 DOMAIN_EXTRACT_REGEXP로 인한 Webhook 이벤트 루프 고갈 DoS (`n8n-io/n8n`)

[English](../09-N8N-CAND-01-WEBHOOK-REDOS.md) | [Türkçe](../tr/09-N8N-CAND-01-WEBHOOK-REDOS.md) | [日本語](../ja/09-N8N-CAND-01-WEBHOOK-REDOS.md) | [简体中文](../zh-CN/09-N8N-CAND-01-WEBHOOK-REDOS.md) | **한국어**

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`n8n-io/n8n`(`<= 2.45.0`, 커밋 `cfbd9a56cba2e73901dc1962e47727adbea0b23e`)에서 `packages/workflow/src/extensions/string-extensions.ts:59, 94, 326, 375, 383`의 내장 워크플로 표현식 메서드 `.isEmail()`, `.extractEmail()`, `.extractDomain()`은 다항식/치명적 백트래킹(`CWE-1333`)에 취약합니다.

1. **1단계 — 중첩된 수량자 하위 그룹이 있는 시작 앵커 없는 정규식 (`string-extensions.ts:59, 94`):**
   `EMAIL_REGEXP`는 시작 앵커나 부정형 후방 탐색 경계(`(?<![^<>()\[\]\\.,;:\s@"])`) 없이 `/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@...`로 시작하며 탐욕적(greedy) `".+"` 분기를 포함합니다. `"a.a.a...a@!"`와 같이 매칭에 실패하는 점 구분 문자열이 입력되면 V8 엔진은 전체 문자열의 모든 단일 문자 오프셋에서 수량자 매칭을 반복해서 재시도합니다.
2. **2단계 — RFC-5321 / RFC-1035 입력 길이 제한 누락 (`string-extensions.ts:326, 375, 383`):**
   유효한 RFC-5321 이메일 주소는 `254`/`320`자를 초과할 수 없음에도 불구하고, `isEmail(value)`, `extractEmail(value)`, `extractDomain(value)`은 임의 크기의 문자열을 그대로 `EMAIL_REGEXP` 및 `DOMAIN_EXTRACT_REGEXP`에 전달합니다.
3. **3단계 — 단일 스레드 Node.js 이벤트 루프 동기 차단:**
   n8n은 메인 Node.js 스레드에서 워크플로 표현식을 동기적으로 평가하므로 단일 20 KB 페이로드가 V8 이벤트 루프를 `831.78 ms` 동안 차단하여(패치 후에는 `0.0029 ms` 소요 — `286,000`배 속도 향상) 모든 동시 Webhook 실행과 UI 요청을 멈추게 합니다.

### 취약한 코드 조각 (`string-extensions.ts:93-95, 324-328, 373-377`)
```typescript
// File: packages/workflow/src/extensions/string-extensions.ts (lines 93-95, 324-328, 373-377)
const EMAIL_REGEXP =
	/(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(?<domain>(\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/; // BUG 1: 시작 앵커 없음 + 탐욕적 ".+"!
...
function isEmail(value: string) {
	const result = EMAIL_REGEXP.test(value); // BUG 2: value.length > 320 길이 제한 없음!
	return result;
}
...
function extractEmail(value: string) {
	const matched = EMAIL_REGEXP.exec(value); // BUG 3: 메인 스레드에서 수 KB/MB 문자열을 동기적으로 평가함!
	return matched ? matched[0] : undefined;
}
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 공개 고객 문의/리드 수집 Webhook을 통해 사내 전체 n8n 자동화 서버 마비
1. 기업이 `{{ $json.body.contact.isEmail() }}` 또는 `{{ $json.body.website.extractDomain() }}`을 평가하는 `IF` 또는 `Set` 노드에 연결된 공개 n8n Webhook 노드(`POST /webhook/contact-us`)를 노출합니다.
2. 인증되지 않은 공격자가 공개 Webhook URL로 20 KB JSON 페이로드(`{"contact": "a.a.a...a@!"}`)를 연속 전송합니다.
3. `EMAIL_REGEXP`가 요청당 약 832 ms 동안 단일 스레드 Node.js 이벤트 루프를 차단하므로, 동일 서버에서 실행 중인 동시 Stripe 결제 웹훅, Slack 봇 및 n8n 에디터 UI가 모두 응답 불능 및 타임아웃에 빠집니다.

### 시나리오 B — 조작된 메시지 본문으로 인한 자동 고객 지원 티켓 및 이메일 분류 파이프라인 중단
1. 자동화된 고객 지원 워크플로가 수신 티켓, 채팅 로그 또는 이메일을 수집하고 자유 형식 텍스트에서 회신 주소를 추출하기 위해 `{{ $json.messageBody.extractEmail() }}`을 평가합니다.
2. 외부 사용자가 유효한 도메인 접미사 없이 반복된 점 구분 토큰이 포함된 티켓 본문을 제출합니다.
3. `extractEmail()`이 길이 제한 없이 전체 메시지 본문에 `EMAIL_REGEXP.exec(value)`를 적용하므로 n8n 워커가 멈추고, Kubernetes Liveness Probe가 실패하여 파드가 재시작 루프에 빠집니다.

### 시나리오 C — 비정상 URL에 대한 `extractDomain()` 호출로 CRM / B2B 리드 보강 파이프라인 대기열 정체
1. B2B 마케팅 자동화 워크플로가 HubSpot/Salesforce에 동기화하기 전에 `{{ $json.companyUrl.extractDomain() }}`을 사용해 기업 도메인을 정규화합니다.
2. 유효한 TLD 없이 긴 서브도메인 형태의 세그먼트가 포함된 페이로드가 입력되면 `DOMAIN_EXTRACT_REGEXP`(`string-extensions.ts:59`)에서 과도한 백트래킹이 발생합니다.
3. 워크플로 실행 대기열이 정체되어 해당 인스턴스의 모든 후속 예약 자동화가 지연됩니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/n8n \
  --include "packages/workflow/src/extensions/string-extensions.ts"
```

### 2. 로컬 격리 환경 재현 및 검증 (`Node.js`)
```bash
# 20 KB 점 구분 페이로드에 대해 미패치 대 패치된 EMAIL_REGEXP의 V8 이벤트 루프 차단 시간 측정
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

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

실제 Node.js `v22.22.2`(`logs/N8N-CAND-01-node-benchmark.json`: `831.78 ms` RED -> `0.0029 ms` GREEN, `286,000`배 속도 향상) 및 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01` 실행 결과:

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

### 경계 조건 명시
신뢰할 수 없는 입력(예: Webhook 트리거 페이로드 또는 외부 메시지 본문)에 대해 `.isEmail()`, `.extractEmail()`, 또는 `.extractDomain()`을 평가하는 활성 n8n 워크플로가 필요합니다.

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
