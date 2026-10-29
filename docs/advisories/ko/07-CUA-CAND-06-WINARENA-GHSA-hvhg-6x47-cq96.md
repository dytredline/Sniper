# WinArena 오케스트레이터의 비인증 noVNC (0.0.0.0:8006) 및 무암호 RDP (0.0.0.0:3390) 전체 인터페이스 노출과 쓰기 가능한 호스트 /shared 마운트 (`GHSA-hvhg-6x47-cq96`)

[English](../07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [Türkçe](../tr/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [日本語](../ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [简体中文](../zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | **한국어**

## GitHub GHSA 및 MITRE CNA 양식 필드 요약
- **저장소:** `trycua/cua`
- **GitHub 보안 권고 URL:** `https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`
- **기존 GHSA ID:** `GHSA-hvhg-6x47-cq96`
- **에코시스템:** `pip`
- **패키지 이름:** `cua-bench`
- **영향받는 버전:** `<= 0.3.1 (commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **패치된 버전:** `없음 (패치 첨부)`
- **CWE:** `CWE-668 (잘못된 영역으로의 리소스 노출) / CWE-732 (중요 리소스에 대한 부적절한 권한 할당)`
- **CVSS v3.1:** `8.6 High — CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **MITRE 벤더:** `TryCua`
- **MITRE 취약점 유형:** `Unauthenticated Network Exposure and Writable Host Volume Mount (CWE-668 / CWE-732)`
- **MITRE 영향받는 컴포넌트:** `libs/cua-bench/tasks/winarena_adapter/cli.py (lines 262-265, 421-424, 646-649) 및 infra/vm/setup/server/main.py (lines 180-248, 290-321)`
- **MITRE 권장 CVE 설명:**
  > TryCua cua-bench 0.3.1 이하(`trycua/cua`)에서 WinArena 컨테이너 오케스트레이터(`libs/cua-bench/tasks/winarena_adapter/cli.py`)는 Windows 게스트 VM의 비인증 noVNC 웹 데스크톱(`-p 8006:8006`)과 무암호 RDP 서비스(`-p 3390:3389`)를 `127.0.0.1` 대신 `0.0.0.0`(모든 네트워크 인터페이스)에 바인딩하며, 호스트의 `setup_path` 디렉터리를 읽기/쓰기 가능하게(`-v {setup_path}:/shared`) 마운트합니다. 인접 네트워크의 공격자는 게스트 데스크톱을 장악하고 호스트와 공유된 설정 스크립트 파일을 변조할 수 있습니다.
- **제보자 / 크레딧:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`trycua/cua`(`cua-bench` `<= 0.3.1`, `libs/cua-bench/tasks/winarena_adapter/cli.py:262-265, 421-424, 646-649` 및 `infra/vm/setup/server/main.py:180-248, 290-321`, 커밋 `e754cfec69c41400eb2aabde716c27d15607b2f0`)에서 세 가지 Docker 런처 명령(`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`) 모두 격리 없이 Windows VM과 호스트 소스 디렉터리를 노출합니다(`CWE-668` / `CWE-732`).

1. **1단계 — `0.0.0.0`에 대한 비인증 Docker 포트 노출 (`cli.py:262-263, 421-422, 646-647`):**
   `127.0.0.1:` 접두사 없이 `-p {args.browser_port}:8006` 및 `-p {args.rdp_port}:3389`를 전달하여 Docker가 비인증 noVNC 웹 콘솔(`8006`)과 무암호 Windows RDP 서비스(`3390`)를 모든 LAN/Wi-Fi 인터페이스(`0.0.0.0`)에 바인딩합니다(Docker의 `FORWARD` 체인을 통해 호스트 `ufw` `INPUT` 규칙도 우회함).
2. **2단계 — 쓰기 가능한 호스트 소스 디렉터리 마운트 (`cli.py:265, 424, 649`):**
   `:ro` 옵션 없이 `-v {setup_path}:/shared`를 전달하여 호스트의 `winarena_adapter/infra/vm/setup` 디렉터리를 컨테이너 내부에 읽기/쓰기 가능하게 마운트합니다.
3. **3단계 — 게스트 내부의 비인증 `exec()` 제어 서버 (`infra/vm/setup/server/main.py:180-248`):**
   게스트 VM 내부에서 `server/main.py`는 `0.0.0.0:5000`에서 수신 대기하며, 어떠한 토큰이나 헤더 검증도 없이 `POST /execute_windows`(`exec(command)`)를 통해 임의 Python 코드를 실행하고 `POST /setup/launch`(`shell=True`)를 통해 셸 명령을 실행합니다.

### 취약한 코드 조각 (`winarena_adapter/cli.py:261-266`)
```python
# File: libs/cua-bench/tasks/winarena_adapter/cli.py (lines 261-266, repeated at 421-424 and 646-649)
        "-p", f"{args.browser_port}:8006", # BUG 1: 비인증 noVNC를 LAN의 0.0.0.0:8006에 노출!
        "-p", f"{args.rdp_port}:3389",     # BUG 2: 무암호 RDP를 LAN의 0.0.0.0:3390에 노출!
        "-v", f"{storage_path}:/storage",
        "-v", f"{setup_path}:/shared",     # BUG 3: 호스트 소스 디렉터리를 :ro 대신 읽기/쓰기 가능하게 마운트!
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 대학/기업 연구실 LAN의 다른 사용자가 `http://<host-ip>:8006` (noVNC) 또는 `:3390` (RDP)을 통해 Windows 평가 VM을 장악
1. 연구원이 대학이나 기업 공유 네트워크에 연결된 연구실 워크스테이션에서 `cua-bench` WinArena 작업을 실행합니다.
2. `cli.py:262-265`가 `127.0.0.1:` 없이 `-p 8006:8006 -p 3390:3389`를 전달하므로 Docker가 두 포트를 `0.0.0.0`에 바인딩합니다.
3. 동일 LAN의 모든 사용자가 브라우저에서 `http://<workstation-ip>:8006`을 열기만 하면(비밀번호 불필요) Windows VM 데스크톱에 대한 전체 Administrator 제어권과 벤치마크 환경에 주입된 LLM API 키를 획득할 수 있습니다.

### 시나리오 B — 읽기/쓰기 가능한 `-v {setup_path}:/shared` 마운트를 통한 게스트-호스트 역오염
1. 컨테이너는 호스트의 `winarena_adapter/infra/vm/setup` 디렉터리를 `/shared`(`cli.py:265, 424, 649`)에 읽기/쓰기 가능하게 마운트합니다.
2. `0.0.0.0:8006` 또는 `0.0.0.0:3390`을 통해 환경에 접근한 공격자가 `/shared` 내부의 설정 스크립트와 Python 파일을 수정합니다.
3. `/shared`는 호스트의 `winarena_adapter` 소스 트리에 직접 매핑되어 있으므로, 이후 호스트 측 CLI 실행이나 테스트 실행 시 변조된 파일이 로드됩니다.

### 시나리오 C — 게스트 내부 브라우저에서 비인증 `0.0.0.0:5000/execute_windows` (`exec()`)를 대상으로 한 드라이브바이 RCE
1. 벤치마크 평가 실행 중 Windows VM 내부의 자율 브라우저 에이전트가 외부 웹페이지나 신뢰할 수 없는 로컬 HTML 작업 아티팩트를 방문합니다.
2. 해당 페이지의 JavaScript가 `infra/vm/setup/server/main.py:180-248`에서 호스팅하는 `http://127.0.0.1:5000/execute_windows` 또는 `http://127.0.0.1:5000/setup/launch`로 요청을 전송합니다.
3. `server/main.py`는 인증을 전혀 수행하지 않고 페이로드를 Python의 `exec(command)` 및 `subprocess.Popen(..., shell=True)`에 직접 전달하므로, 웹페이지가 VM 내부에서 Windows Administrator 권한으로 즉시 임의 코드를 실행합니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench/tasks/winarena_adapter/cli.py"
```

### 2. 로컬 격리 환경 재현 및 검증
```bash
# cli.py 전반의 127.0.0.1 접두사 없는 Docker 포트 바인딩과 쓰기 가능한 /shared 볼륨 마운트 확인
grep -n -C 4 "8006" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# infra/vm/setup/server/main.py의 비인증 exec() 확인
grep -n -C 8 "def execute_windows" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06` 실행 결과:

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

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
