# 0.0.0.0:8001 Worker Server 와일드카드 CORS + OSGYM_ALLOWED_IPS Fail-Open 우회 + 비인증 POST /reset 임의 모듈 실행 (`GHSA-xm8w-gj3g-4f25`)

[English](../04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [Türkçe](../tr/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [日本語](../ja/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [简体中文](../zh-CN/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | **한국어**

## GitHub GHSA 및 MITRE CNA 양식 필드 요약
- **저장소:** `trycua/cua`
- **GitHub 보안 권고 URL:** `https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`
- **기존 GHSA ID:** `GHSA-xm8w-gj3g-4f25`
- **에코시스템:** `pip`
- **패키지 이름:** `cua-bench-rl (및 cua-bench)`
- **영향받는 버전:** `<= 0.1.0 (cua-bench <= 0.3.1, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **패치된 버전:** `없음 (패치 첨부)`
- **CWE:** `CWE-94 (코드 생성 제어 부적절) / CWE-942 (과도하게 허용된 교차 도메인 화이트리스트)`
- **CVSS v3.1:** `8.8 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **MITRE 벤더:** `TryCua`
- **MITRE 취약점 유형:** `Dynamic Code Execution via Wildcard CORS and Fail-Open IP Filter (CWE-94 / CWE-942)`
- **MITRE 영향받는 컴포넌트:** `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (lines 79-108, 338-360, 499) 및 libs/cua-bench/cua_bench/core.py (make, lines 25-51)`
- **MITRE 권장 CVE 설명:**
  > TryCua cua-bench-rl 0.1.0 이하 및 cua-bench 0.3.1 이하(`trycua/cua`)에서 `worker_server.py`는 인증 없이 `0.0.0.0:8001`에 바인딩하며, `allow_origins=['*']`로 `CORSMiddleware`를 활성화하고, `127.0.0.1`로 들어오는 교차 출처 브라우저 요청을 허용할 뿐만 아니라 `OSGYM_ALLOWED_IPS`가 빈 문자열로 설정될 때 모든 원격 IP에 대해 필터가 우회(Fail-Open)되는 `ip_filter_middleware`를 사용합니다. 공격자는 임의의 `env_path` 매개변수로 `POST /reset`을 호출하여 `cua_bench.core.make`가 `spec.loader.exec_module`을 통해 호스트에서 `<env_path>/main.py`를 직접 실행하도록 만들 수 있습니다.
- **제보자 / 크레딧:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`trycua/cua`(`cua-bench-rl` `<= 0.1.0` 및 `cua-bench` `<= 0.3.1`, 커밋 `e754cfec69c41400eb2aabde716c27d15607b2f0`)에서 `worker_server.py`는 강화학습(RL) 환경 워커를 관리하기 위해 `0.0.0.0:8001`(`worker_server.py:499-500`)에서 FastAPI 서버를 실행합니다. 다음 세 가지 결함이 연쇄적으로 작용하여 호스트에서의 임의 Python 코드 실행(`CWE-94` / `CWE-942`)으로 이어집니다.

1. **1단계 — 와일드카드 CORS와 루프백 IP 신뢰로 인한 브라우저 드라이브바이 요청 허용 (`worker_server.py:79-95`):**
   `CORSMiddleware`가 `allow_origins=["*"]`, `allow_methods=["*"]`, `allow_headers=["*"]`로 설정되어 있습니다. `ip_filter_middleware`는 `Origin` 헤더를 확인하지 않고 `client_ip`(기본값 `127.0.0.1`)만 검사하므로, 브라우저의 임의 웹페이지에서 `http://127.0.0.1:8001`로 보낸 교차 출처 요청은 `127.0.0.1`에서 도착하여 필터를 통과합니다.
2. **2단계 — `OSGYM_ALLOWED_IPS=""` 설정 시 IP 필터가 무력화되는 Fail-Open 결함 (`worker_server.py:90-103`):**
   `OSGYM_ALLOWED_IPS`가 빈 문자열(`""`)로 설정되면 `allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]`는 빈 리스트 `[]`가 됩니다. 102번째 줄의 `if allowed_ips and client_ip not in allowed_ips:` 검사에서 `bool([])`이 `False`가 되어 IP 검사가 완전히 생략되고 모든 원격 LAN/클러스터 클라이언트가 허용됩니다.
3. **3단계 — 검증되지 않은 `request.env_path`를 `spec.loader.exec_module`로 직접 실행 (`worker_server.py:338-360`, `cua_bench/core.py:25-51`):**
   `POST /reset`은 호출자가 전달한 `request.env_path`를 그대로 `cb.make(request.env_path)`에 전달하며, 이는 `<env_path>/main.py`를 찾아 `spec.loader.exec_module(module)`로 호스트 프로세스 내에서 즉시 실행합니다.

### 취약한 코드 조각 (`worker_server.py:79-104, 338-349`)
```python
# File: libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (lines 79-104, 338-349)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # BUG 1: 와일드카드 CORS로 인해 모든 웹사이트에서 교차 출처 POST 가능!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    client_ip = request.client.host if request.client else None
    if allowed_ips and client_ip not in allowed_ips: # BUG 2: allowed_ips == []일 때 Fail-Open 발생!
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)
...
@app.post("/reset", response_model=ResetResponse)
async def reset_environment(request: ResetRequest):
    env = cb.make(request.env_path, ...) # BUG 3: <env_path>/main.py를 동적으로 로드 및 실행함!
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — RL 학습 워커를 실행 중인 ML 엔지니어가 브라우저 탭을 통해 침해됨 (`POST /reset` -> `exec_module`)
1. AI 연구원이 로컬(`127.0.0.1:8001`)에서 `cua-bench-rl` 워커를 실행한 상태로 데이터셋을 다운로드하거나 모델 리더보드 웹페이지를 탐색합니다.
2. 방문한 웹페이지가 `fetch("http://127.0.0.1:8001/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ env_path: "/home/community-user/Downloads/untrusted_bundle" }) })`를 호출합니다.
3. 요청이 루프백(`127.0.0.1`)으로 들어오고 `CORSMiddleware`가 `*`를 허용하므로 `ip_filter_middleware`가 이를 통과시키고, `cua_bench.core.make`가 호스트 Python 프로세스에서 `/home/community-user/Downloads/untrusted_bundle/main.py`를 `spec.loader.exec_module`로 즉시 실행합니다.

### 시나리오 B — 빈 `OSGYM_ALLOWED_IPS=""` 환경 변수를 사용한 GPU 클러스터 / Docker Compose 배포가 전체 네트워크에 노출됨
1. Kubernetes/Helm 또는 Docker Compose 템플릿에서 `OSGYM_ALLOWED_IPS: ""`가 빈 문자열로 전달되면 `allowed_ips`가 `[]`로 평가됩니다.
2. 102번째 줄 `if allowed_ips and client_ip not in allowed_ips:`에서 `bool([])`이 `False`가 되어 IP 필터가 완전히 우회되며, 네트워크의 모든 노드가 `0.0.0.0:8001`의 `/reset`을 호출해 공유 NFS나 데이터셋 마운트에 있는 임의의 Python 모듈을 실행할 수 있습니다.

### 시나리오 C — `/screenshot` 및 `/step`을 통한 데스크톱 화면 감시 및 입력 주입
1. 디스크에 파일을 배치하지 않더라도, 임의의 교차 출처 웹페이지나 LAN 노드가 `GET /screenshot`을 폴링하여 활성 데스크톱 환경의 실시간 Base64 스크린샷을 수집할 수 있습니다.
2. 이어서 공격자는 `POST /step`을 호출해 실행 중인 데스크톱 세션에 임의의 키보드 입력과 마우스 동작을 직접 주입할 수 있습니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py"
```

### 2. 로컬 격리 환경 재현 및 검증 (`127.0.0.1`)
```bash
# 빈 OSGYM_ALLOWED_IPS=""가 어떻게 []로 평가되어 필터가 우회(Fail-Open)되는지 확인
python3 -c '
import os
os.environ["OSGYM_ALLOWED_IPS"] = ""
allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
client_ip = "10.20.30.40"
blocked = bool(allowed_ips and client_ip not in allowed_ips)
print({"allowed_ips": allowed_ips, "remote_client_ip": client_ip, "blocked_by_filter": blocked})
'
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

실제 `cua_bench.core.make` 구현을 대상으로 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02`를 실행한 결과:

```json
{
  "CUA-CAND-02": {
    "ghsa_id": "GHSA-xm8w-gj3g-4f25",
    "source_file": "cua/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py",
    "core_file": "cua/libs/cua-bench/cua_bench/core.py",
    "elapsed_ms": 16.323,
    "RED": {
      "cross_origin_reset_status": 200,
      "empty_allowed_ips_remote_lan_status": 200,
      "arbitrary_env_path_exec_module_rce": true
    },
    "GREEN": {
      "cross_origin_reset_status": 403,
      "empty_allowed_ips_remote_lan_status": 403,
      "outside_env_path_status": 400,
      "arbitrary_env_path_exec_module_rce": false
    },
    "BENIGN": {
      "loopback_valid_task_reset_status": 200
    }
  }
}
```

### Unified Diff 패치 (`git apply --check` 검증 완료)
```diff
--- a/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
+++ b/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
@@ -78,12 +78,6 @@
-app.add_middleware(
-    CORSMiddleware,
-    allow_origins=["*"],
-    allow_credentials=True,
-    allow_methods=["*"],
-    allow_headers=["*"],
-)
-
 @app.middleware("http")
 async def ip_filter_middleware(request: Request, call_next):
+    if request.headers.get("origin"):
+        return JSONResponse(status_code=403, content={"detail": "Cross-origin browser requests forbidden"})
     allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
-    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
+    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()] or ["127.0.0.1"]
@@ -102,3 +96,3 @@
-    if allowed_ips and client_ip not in allowed_ips:
+    if client_ip not in allowed_ips:
         return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
```
