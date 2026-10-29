# 비인증 0.0.0.0:7842 cuabotd 데몬 + POST /bash 와일드카드 CORS + 무검증 Origin WebSocket + 쓰기 가능한 호스트 .claude 마운트 (`GHSA-cp36-x5hg-3gg8`)

[English](../03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [Türkçe](../tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [日本語](../ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [简体中文](../zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | **한국어**

## GitHub GHSA 및 MITRE CNA 양식 필드 요약
- **저장소:** `trycua/cua`
- **GitHub 보안 권고 URL:** `https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`
- **기존 GHSA ID:** `GHSA-cp36-x5hg-3gg8`
- **에코시스템:** `npm`
- **패키지 이름:** `cuabot`
- **영향받는 버전:** `>= 1.0.1, <= 1.0.16 (commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **패치된 버전:** `없음 (패치 첨부)`
- **CWE:** `CWE-306 (중요 기능에 대한 인증 누락) / CWE-942 (과도하게 허용된 교차 도메인 화이트리스트)`
- **CVSS v3.1:** `9.6 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
- **MITRE 벤더:** `TryCua`
- **MITRE 취약점 유형:** `Missing Authentication / Permissive CORS Leading to Remote Command Execution (CWE-306 / CWE-942)`
- **MITRE 영향받는 컴포넌트:** `libs/cuabot/src/cuabotd.ts (lines 34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120)`
- **MITRE 권장 CVE 설명:**
  > TryCua cuabot 1.0.1부터 1.0.16(`trycua/cua`)까지에서 `cuabotd` 데몬(`libs/cuabot/src/cuabotd.ts`)은 인증 없이 `0.0.0.0:7842`에 바인딩하며, `POST /bash` 및 `OPTIONS` 프리플라이트를 포함한 모든 HTTP 엔드포인트에 `Access-Control-Allow-Origin: *`을 설정하고, `Origin` 검사가 없는 WebSocket PTY 터미널을 노출하는 동시에 호스트의 `~/.cuabot/user/.claude` 디렉터리를 읽기/쓰기 가능하게 마운트합니다. 사용자가 브라우저로 방문한 임의의 웹사이트나 로컬 네트워크의 다른 기기에서 `POST /bash`를 통해 임의의 명령을 실행하고 마운트된 Claude OAuth 자격 증명을 탈취하거나 호스트 훅을 변조할 수 있습니다.
- **제보자 / 크레딧:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`trycua/cua`(`cuabot` npm 패키지 `<= 1.0.16`, 커밋 `e754cfec69c41400eb2aabde716c27d15607b2f0`)에서 `cuabotd` 데몬(`libs/cuabot/src/cuabotd.ts`)은 HTTP 및 WebSocket을 통해 컨테이너 셸 실행 및 데스크톱 자동화 기능을 노출합니다. 다음의 복합적인 코드 결함이 결합되어 제로클릭 브라우저 드라이브바이(Drive-By) 공격 및 LAN 원격 명령 실행 취약점(`CWE-306` / `CWE-942`)으로 이어집니다.

1. **1단계 — 모든 네트워크 인터페이스 (`0.0.0.0:7842`)에 비인증 바인딩 (`cuabotd.ts:1120`):**
   `server.listen(port, () => ...)` 호출 시 `'127.0.0.1'` 인자가 생략되어 포트 `7842`가 모든 Wi-Fi/LAN 인터페이스(`0.0.0.0`)에 토큰이나 세션 인증 없이 노출됩니다.
2. **2단계 — `POST /bash`의 와일드카드 CORS (`Access-Control-Allow-Origin: *`) 및 무검증 Origin WebSocket PTY (`cuabotd.ts:969-1002, 1018-1063`):**
   모든 HTTP 응답에 `Access-Control-Allow-Origin: *` 및 `Access-Control-Allow-Headers: Content-Type`이 설정되고 `OPTIONS` 프리플라이트가 `200 OK`를 반환합니다. 개발자가 브라우저에서 연 임의의 악성 웹페이지는 교차 출처 `fetch("http://localhost:7842/bash", ...)`를 전송하여 `stdout`/`stderr` JSON 응답 전체를 읽거나, `Origin` 검사 없이 `new WebSocket("ws://localhost:7842/?command=...")`를 열어 대화형 PTY를 실행할 수 있습니다.
3. **3단계 — 읽기/쓰기 가능한 호스트 `.claude` 바인드 마운트 (`cuabotd.ts:259-260`):**
   `cuabotd`는 호스트의 `~/.cuabot/user/.claude` 디렉터리를 `/home/community-user/.claude`에 읽기/쓰기 가능하게 마운트하고 `host.docker.internal:host-gateway`를 매핑하므로, `/bash`를 통해 실행된 명령이 Claude OAuth 토큰을 탈취하고 호스트에 영구 보존되는 `.claude/settings.json` 훅을 오염시킬 수 있습니다.

### 취약한 코드 조각 (`libs/cuabot/src/cuabotd.ts:965-1002, 1120`)
```typescript
// File: libs/cuabot/src/cuabotd.ts (lines 965-1002, 1120)
    // CORS headers
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*'); // BUG 1: 모든 외부 웹사이트가 호출하고 응답을 읽을 수 있도록 허용함!
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
...
      if (path === 'bash' && req.method === 'POST') {  // BUG 2: 임의 셸 명령 실행에 인증이 전혀 없음!
        const { command, timeout } = body;
        const result = await execBash(command, timeout);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }
...
  server.listen(port, () => {                          // BUG 3: 127.0.0.1 대신 0.0.0.0:7842에 바인딩함!
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 개발자가 `cuabot` 실행 중 임의의 웹페이지 방문 (제로클릭 브라우저 Drive-By RCE 및 Claude 토큰 탈취)
1. 개발자가 노트북에서 CUA 코딩 에이전트를 사용하기 위해 `npx cuabot`을 실행하면 백그라운드에서 `cuabotd`가 포트 `7842`를 엽니다.
2. 개발자가 Chrome/Firefox/Safari에서 기술 블로그나 문서 사이트를 읽는 동안, 페이지에 삽입된 스크립트가 `fetch("http://localhost:7842/bash", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command: "cat /home/community-user/.claude/.credentials.json" }) })`를 실행합니다.
3. `cuabotd.ts:969-977`이 브라우저의 `OPTIONS` 프리플라이트에 `200 OK`와 `Access-Control-Allow-Origin: *`으로 응답하므로, 브라우저는 `POST /bash` 요청을 전송할 뿐만 아니라 악성 웹페이지가 `stdout`이 담긴 JSON 응답을 그대로 읽도록 허용하여 개발자의 Claude OAuth/API 자격 증명이 즉시 유출됩니다.

### 시나리오 B — 쓰기 가능한 `.claude/settings.json` 훅 주입을 통한 영구적 호스트 장악
1. 동일한 교차 출처 `POST /bash` 또는 `new WebSocket("ws://localhost:7842/?command=...")` 호출을 이용해 악성 웹페이지가 `/home/community-user/.claude/settings.json`(`hooks.PreToolUse` 또는 `mcpServers`)에 악성 셸 명령을 기록합니다.
2. `/home/community-user/.claude`는 호스트 `~/.cuabot/user/.claude`(`cuabotd.ts:259-260`)의 읽기/쓰기 바인드 마운트이므로, 컨테이너가 종료된 후에도 변조된 설정이 호스트 파일시스템에 그대로 유지됩니다.
3. 이후 호스트에서 Claude Code나 CUA를 실행할 때마다 공격자의 영구 훅이 실행됩니다.

### 시나리오 C — 카페, 공유 오피스 또는 사내 Wi-Fi (`0.0.0.0:7842`) LAN에서의 워크스테이션 장악
1. `cuabotd.ts:1120`의 `server.listen(port)`는 루프백 호스트 인자(`'127.0.0.1'`)를 생략하여 TCP 포트 `7842`를 `0.0.0.0` / `::`에 바인딩합니다.
2. 동일한 카페, 공유 오피스 또는 사내 Wi-Fi/LAN 네트워크에 있는 어떤 기기든 인증 없이 `http://<developer-lan-ip>:7842/bash` 또는 `http://<developer-lan-ip>:7842/screenshot`을 직접 호출할 수 있습니다.
3. LAN 공격자는 실시간 화면 스크린샷을 캡처하고 마우스/키보드 이벤트를 주입하며 개발자 환경 내부에서 임의의 셸 명령을 실행할 수 있습니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cuabot/src/cuabotd.ts"
```

### 2. 로컬 격리 환경 재현 및 검증 (`127.0.0.1`)
```bash
# 로컬 127.0.0.1:7842의 cuabotd 인스턴스에 대해 교차 출처 브라우저 프리플라이트 및 POST /bash 시뮬레이션
curl -i -X OPTIONS http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && ls -la /home/community-user/.claude"}'
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01` 실행 결과:

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

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
