# Gökçe Baran Karakamış — Sniper macOS 설치 검증, 스캔된 오픈소스 저장소 및 검증된 보안 권고 보고서

[English](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.en.md) | [Türkçe](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md) | [日本語](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.ja.md) | [简体中文](SNIPER-SCANNED-REPOSITORIES-AND-ADVISORIES.zh-CN.md) | **한국어**

**저자 / 보안 연구원:** **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline))

이 포괄적인 기술 가이드 및 보안 연구 보고서는 세 가지 핵심 파트로 구성되어 있습니다:
1. **파트 I — macOS (Apple Silicon) 실제 하드웨어 설치 및 런타임 검증 보고서:** 실제 macOS 하드웨어에서 **네이티브 소스 설치(`--core-only`)**와 **Docker Desktop 5-엔진 컨테이너 스택(`community-tools`)**을 모두 사용하여 Sniper Community를 엔드투엔드로 테스트하고 검증한 결과입니다.
2. **파트 II — Sniper로 스캔한 8개 오픈소스 저장소, 취약점 전환 메커니즘 및 일상 시나리오:** **Gökçe Baran Karakamış**가 **Sniper** 정적 분석(SAST), 코드형 인프라(IaC) 및 소프트웨어 구성 분석(SCA) 엔진으로 스캔한 **8개 오픈소스 저장소**에 대한 소스 코드 수준 감사, 오탐(False Positive) 제거, 코드/설정 결함이 어떤 조건에서 실제 취약점으로 이어지는지에 대한 쉬운 설명, 각 저장소별 **3가지 일상 핵심 시나리오(`시나리오 A / B / C`)**, 그리고 **예제 실행 및 검증 명령어**입니다.
3. **파트 III — Sniper 스캔에서 발견한 38건의 검증된 보안 권고(37건의 고유 취약점 + 1건의 업스트림 중복 심층 방어 기록)(`01`..`11`), 코드 분석, 시나리오 및 런타임 증명(`RED -> GREEN + BENIGN`):** 6개 오픈소스 프로젝트(**Stirling-PDF, TryCua `cua`, OpenZiti, n8n, Gotify Server, NIIS X-Road**)에서 발견되어 GitHub Security Advisory(`GHSA`)로 보고된 **38건의 검증된 보안 권고(37건의 고유 취약점 + 1건의 업스트림 중복 심층 방어 기록)**이 코드에서 어떻게 발생하고 단계별로 어떻게 취약점으로 작동하는지, 각 항목에 대한 **3가지 구체적인 일상 핵심 시나리오(`시나리오 A / B / C`)**, **예제 실행/트리거 명령어**, 그리고 **검증된 방어 패치(`git diff`)**를 다룹니다.

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

## 파트 III — Sniper 스캔에서 발견한 38건의 검증된 보안 권고(37건의 고유 취약점 + 1건의 업스트림 중복 심층 방어 기록) (취약점 전환 메커니즘, 일상 시나리오 및 예제 실행 명령어)

아래는 **Sniper** 정적/동적 분석 엔진으로 수행한 보안 스캔에서 발견되어 **단계별 일상 핵심 시나리오(`시나리오 A / B / C`)**, **엔드투엔드 런타임 증명(`RED -> GREEN + BENIGN`)**, 그리고 **검증된 방어 패치(`git diff`)**로 입증된 **11건의 보안 취약점**([advisories/README.ko.md](advisories/README.ko.md))입니다. 먼저 요약 표를 제시하고, 이어서 **각 버그가 코드에서 어떻게 발생하여 실제 악용 가능한 취약점으로 이어지는지, 3가지 일상 핵심 시나리오, 그리고 예제 실행/검증 명령어**를 담은 11개의 심층 기술 섹션(`III.01` – `III.38`)을 수록합니다:

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
| **12** | [`12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/ko/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)<br/>`GITLAB-CAND-02`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/oauth/device_authorizations_controller.rb:4-50`<br/>`app/controllers/oauth/tokens_controller.rb:42-75` | `CWE-863 / CWE-285`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::DeviceAuthorizationsController` (`device_authorizations_controller.rb:4-50`) and `Oauth::TokensController` (`tokens_controller.rb:42-75`) omit `verify_admin_allowed!`, `verify_confirmed_email!`, `set_current_organization`, and `enforce_organization_maintenance_mode` (all enforced in sibling `Oauth::AuthorizationsController`).<br/>**Scenario A (Full Instance Admin Takeover):** A regular user creates an untrusted OAuth app (`trusted: false`); when an admin enters its `user_code` on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes=true` and mints a full `api admin_mode` token allowing complete server takeover, private repo theft, and CI secret extraction.<br/>**Scenario B (Unverified Account API Backdoor):** An unconfirmed account (`confirmed_at: nil`) blocked on `/oauth/authorize` (`403`) mints persistent API & refresh tokens via `/oauth/device`.<br/>**Scenario C (Backdoor Commit During Legal/Migration Freeze):** Attackers mint tokens and push commits (`201 Created`) into frozen repositories while an organization is locked in `migration` (`503`) or `legal` (`403`) maintenance mode. | `RED`: `token_minted_admin_mode: true, post_token_admin_action_succeeded: true`<br/>`GREEN`: `503 / 403, token_minted_admin_mode: false`<br/>`pytest -k test_report1_cand02` |
| **13** | [`13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/ko/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)<br/>`GITLAB-CAND-05`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`<br/>`refresh_token_service.rb:18-70`<br/>`dynamic_registration_client.rb:104-136` | `CWE-918 / CWE-209`<br/>**8.5 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` accept unvalidated RFC 8414 `token_endpoint`/`revocation_endpoint` URLs and use `OAuth2::Client` (`max_redirects: 5`, no `UrlBlocker`), reflecting raw `OAuth2::Error` bodies into `flash[:alert]`.<br/>**Scenario A (Stealing Cloud IAM Keys via `flash[:alert]`):** A `307 Temporary Redirect` on `token_endpoint` hits `169.254.169.254` or `127.0.0.1` and prints cloud IAM credentials / internal API responses directly into the user's `flash[:alert]` banner.<br/>**Scenario B (Internal `POST` SSRF & Secret Replay):** `OAuth2::Client` replays `POST` requests with `client_secret` and `refresh_token` to firewalled internal `127.0.0.1` services.<br/>**Scenario C (`RevokeTokenService` SSRF):** Disconnecting an MCP server posts Basic Auth credentials to unvalidated internal/external `revocation_endpoint` targets. | `RED`: `canary_b_request_count: 5, iam_role_credentials_exposed: true`<br/>`GREEN`: `canary_b_request_count: 0, iam_role_credentials_exposed: false`<br/>`pytest -k test_report2_cand05` |
| **14** | [`14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/ko/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)<br/>`GITLAB-CAND-06`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`<br/>`ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`<br/>`ee/lib/gitlab/oauth/client_state.rb:17-23` | `CWE-639 / CWE-862`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **How It Happens in Code:** `Oauth::McpConnectorsAuthController` calls global `Ai::Catalog::McpServer.find(params[:id])` without `.in_organization(Current.organization)`, `ConnectService` overwrites DCR credentials without checking `update_ai_catalog_mcp_server`, and `ClientState.from_state` discards `data` binding.<br/>**Scenario A (Cross-Organization AI Connector Hijack):** A user in Organization A overwrites `oauth_client_id` / `oauth_client_secret` on an `McpServer` belonging to Organization B.<br/>**Scenario B (Read-Only User Overwrites Production Connector):** A non-maintainer with read-only access overwrites company MCP OAuth credentials via DCR.<br/>**Scenario C (Cross-Session Account Binding / Login CSRF):** Replaying an unbound `ClientState` token binds a victim developer's GitLab session to the attacker's external MCP account. | `RED`: `cross_org_server_mutated: true`<br/>`GREEN`: `cross_org_server_mutated: false (404 RecordNotFound)`<br/>`pytest -k test_report2_cand05` |
| **15** | [`15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/ko/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)<br/>`GITLAB-CAND-01`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239` | `CWE-918 / CWE-522`<br/>**8.2 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `externalMcpTransport` in `workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44` omits `transport.WithSSRFFilter()`, and `roundTripper.RoundTrip` (`mcp.go:101-104`) re-injects `Authorization: Bearer` headers on every redirect hop.<br/>**Scenario A (Bearer Token Theft & Account Takeover):** A `302` redirect from an external MCP server sends the victim's live `Authorization: Bearer` token to a cross-origin attacker server.<br/>**Scenario B (Workhorse Internal & Cloud Metadata SSRF):** Redirects reach `127.0.0.1` internal services or `169.254.169.254` from the Workhorse process.<br/>**Scenario C (DNS Rebinding into Corporate Intranet):** DNS rebinding bypasses initial URL validation because Workhorse's dialer lacks `WithSSRFFilter`. | `RED`: `bearer_token_leaked_to_canary: true`<br/>`GREEN`: `bearer_token_leaked_to_canary: false, ssrfFilterError: disallowlist`<br/>`pytest -k test_report2_cand05` |
| **16** | [`16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/ko/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)<br/>`GITLAB-CAND-08`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`<br/>`ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`<br/>`connection_config_service.rb:220-228` | `CWE-862 / CWE-639`<br/>**7.7 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` | **How It Happens in Code:** `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)` (enforced at line 334), and `workflows.rb:1065` (`GET /ws`) allows overriding `workflow_definition` and `ai_catalog_item_version_id`.<br/>**Scenario A (Escalating Read-Only `chat` to Write-Capable Agent):** Overriding `workflow_definition` and `ai_catalog_item_version_id` on `/ws` injects withheld write tools (`create_issue`) into a restricted `chat` session.<br/>**Scenario B (Stealing Private `public: false` Agent Toolsets):** Enumerating `ai_catalog_item_version_id` discloses the confidential toolset of foreign private AI Catalog agents.<br/>**Scenario C (Unauthorized Private Agent Binding):** `POST /workflows` binds private cross-organization `ItemVersion` records without `:read_ai_catalog_item` checks. | `RED`: `unapproved_write_tool_injected: true, workflow_definition_overridden: true`<br/>`GREEN`: `unapproved_write_tool_injected: false`<br/>`pytest -k test_report3_cand08` |
| **17** | [`17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/ko/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)<br/>`GITLAB-CAND-07`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`<br/>`ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`<br/>`workhorse/internal/ai_assist/duoworkflow/mcp.go:254` | `CWE-863 / CWE-639`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` | **How It Happens in Code:** `McpConfigService#execute` (`mcp_config_service.rb:61`) calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, and `ListService`/`Agent::Create` omit `.in_organization`.<br/>**Scenario A (Unlocking All Prohibited Built-in GitLab MCP Tools):** An `Ai::Catalog::McpServer` named `"GitLab"` (`:gitlab`, `Tools: nil`) overwrites the built-in `:gitlab` entry so Workhorse (`mcp.go:254`) sets `allToolsAvailable = true`, disabling all `withheld_server_tools` restrictions.<br/>**Scenario B (Cross-Org MCP Server Binding):** GraphQL `aiCatalogAgentCreate`/`Update` binds foreign-organization `McpServer` Global IDs.<br/>**Scenario C (Duo Workflow `401` DoS):** Overwriting `Headers` on `:gitlab` strips `X-Gitlab-Oauth-Token` and breaks `/api/v4/mcp`. | `RED`: `builtin_gitlab_overwritten: true, workhorse_all_tools_available: true`<br/>`GREEN`: `builtin_gitlab_overwritten: false, workhorse_all_tools_available: false`<br/>`pytest -k test_report4_cand07` |
| **18** | [`18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/ko/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)<br/>`GITLAB-CAND-04`<br/>MITRE CNA-LR & HackerOne | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`app/controllers/projects/integrations/slash_commands_controller.rb:21-48`<br/>`app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76` | `CWE-601 / CWE-863`<br/>**5.4 Medium**<br/>`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **How It Happens in Code:** `SlashCommandsController#confirm` (`slash_commands_controller.rb:23-48`) redirects to unvalidated `request_params[:redirect_url]`, passes `request_params[:response_url]` to `VerifyRequest`, and keys Redis `CACHE_KEY` only by `command_id` without `project_id`/`integration_id`.<br/>**Scenario A (Corporate SSO Phishing After Slash Command Confirm):** Confirming a slash command on the trusted GitLab domain redirects (`302 Found`) the developer to an external credential-harvesting page.<br/>**Scenario B (Cross-Project ChatOps Account Binding):** A `command_id` minted in Project B is accepted on Project A's `/slash_commands/confirm` endpoint.<br/>**Scenario C (ChatOps Callback Hijack):** `request_params[:response_url]` overrides the cached `response_url` during `VerifyRequest#approve!`. | `RED`: `http_status: 302, open_redirect_triggered: true, cross_project_cache_collision_accepted: true`<br/>`GREEN`: `404, open_redirect_triggered: false`<br/>`pytest -k test_report5_cand04` |
| **19** | [`19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/ko/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)<br/>Upstream Duplicate: `CVE-2026-40295`<br/>*(GitHub Only — Not Submitted to MITRE)* | **gitlab-org/gitlab** (`<= 19.6.0-pre`)<br/>`lib/gitlab/devise_failure.rb:4-18`<br/>`lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`<br/>`app/controllers/oauth/authorizations_controller.rb:316-330` | `CWE-601 / CWE-345`<br/>**5.4 Medium (Upstream CVE-2026-40295 Duplicate)**<br/>`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **[UPSTREAM DUPLICATE: `CVE-2026-40295` — Published on GitHub Only, Not Submitted to MITRE]**<br/>**How It Happens in Code:** `Gitlab::DeviseFailure` inherits `Devise 5.0.3` `redirect_url` (`CVE-2026-40295`), which redirects to an unsanitized external `Referer` on non-GET `:timeout` failures; `AuthorizationsController#validate_pkce_for_dynamic_applications` (`CAND-03`) has an early return on `nil` `code_challenge_method` (mitigated at runtime by `Doorkeeper 5.9.3`).<br/>**Scenario A/B/C:** Product-level `extract_path_from_location(request.referrer)` override in `lib/gitlab/devise_failure.rb` and controller-level PKCE defense-in-depth patch. | `DUPLICATE OF CVE-2026-40295` *(Not submitted to MITRE)*<br/>`RED`: `external_referer_redirect: true`<br/>`GREEN`: `path_extracted_only: true` |
| **20** | [`20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/ko/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)<br/>`CHIA-WLC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`) | `CWE-345 / CWE-347`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `WalletNode._add_block_from_header` (`wallet_node.py:926-995`) ingests `header_block.foliage_transaction_block` without verifying `foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash`.<br/>**Scenario A (0-XCH Capital Fake Deposit):** With zero XCH capital and no counterparty approval, an attacker sends a real header with a swapped transaction block to credit `+0.5 XCH` (`500,000,000,000 mojo`) as confirmed and cash out real USDT/BTC.<br/>**Scenario B (Persistent SQLite Poisoning):** Counterfeit coins persist across `WalletCoinStore` cold restarts (`Err.UNKNOWN_UNSPENT` on spend).<br/>**Scenario C (`CONS-SP-01` + `WLC-01`):** FullNode sync lockout followed by light-wallet fake deposit injection. | `RED`: `fake_merchant_deposit_increase_mojo: 500000000000, spend_err: UNKNOWN_UNSPENT`<br/>`GREEN`: `rejected_forged_foliage_tx_block: true, fake_increase: 0`<br/>`pytest -k test_wlc01` |
| **21** | [`21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/ko/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)<br/>`CHIA-WLC-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/wallet/wallet_node.py:725-777`<br/>`chia/wallet/wallet_state_manager.py:1735-1778` | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `wallet_node.py:725-777` and `wallet_state_manager.py:1735-1778` persist unverified `RespondRemovals(proofs=None)` / `spent_height` transitions into SQLite `WalletCoinStore`.<br/>**Scenario A (Clawback Cancel Lockout):** Victim cannot cancel a `0.5 XCH` Clawback coin (`tx_count: 0`); attacker claims on-chain after timelock expiry (`33361e6b...`).<br/>**Scenario B (`WLC-02` + `VR-01` Unified Chain):** Simultaneously locks live wallet cancellation and emergency `chia-vault-recover` CLI on one timeline (`t0..t4`).<br/>**Scenario C (UTXO Freeze DoS):** Freezes unspent coins across cold SQLite restarts. | `RED`: `t1_cold_reloaded_sqlite_spent: true, t2_sender_cancel_tx_count: 0, t4_recipient_claim_succeeded: true`<br/>`GREEN`: `t1_spent: false, t2_sender_cancel_tx_count: 1`<br/>`pytest -k test_wlc02` |
| **22** | [`22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/ko/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)<br/>`CHIA-GUI-WC-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain-gui** (`<= 2.6.1-rc2.dev60`)<br/>`packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`<br/>`constants/WalletConnectCommands.ts` | `CWE-367 / CWE-285`<br/>**8.8 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **How It Happens in Code:** `WalletConnectContext.tsx:314-441` exposes all 29 commands on connect, lacks a FIFO confirmation queue, and fails to re-verify `(requestId, fingerprint, network, pairing)` in `sendCommand`.<br/>**Scenario A (Modal Overwrite Drain):** A dApp overwrites a benign `chia_getCurrentAddress` prompt with `chia_sendTransaction`, draining `0.5 XCH` (`SpendBundle d2ce2264...`).<br/>**Scenario B (Fingerprint TOCTOU):** Approval on burner key `111111` executes on main key `999999`.<br/>**Scenario C (Post-Disconnect Execution):** Pending request executes after pairing/network change. | `RED`: `modal_overwritten: true, unauthorized_spend_bundle_sha256: d2ce22645a9a23b1...`<br/>`GREEN`: `6/6 distinct WSS packets blocked`<br/>`pytest -k gui_wc01` |
| **23** | [`23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/ko/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)<br/>`CHIA-DL-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`)<br/>`chia/data_layer/data_layer_util.py` | `CWE-347 / CWE-345`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N` | **How It Happens in Code:** `WalletRpcApi.dl_verify_proof` (`wallet_rpc_api.py:4066-4120`) verifies coin existence and Merkle hashes without checking `match_dl_singleton` or `launcher_id == store_id`.<br/>**Scenario A (`100,000 CAT` On-Chain Mint):** A 1-mojo non-singleton coin (`86ec0dd7...`) forges `store_id` `806a6c73...`, passing `dl_verify_proof` and minting `100,000 CAT` on-chain (`dc3f0bba...`).<br/>**Scenario B (Intrinsic RPC Bypass):** Side-by-side canonical vs. counterfeit `DLProof` both return `verified: true` in `RED`.<br/>**Scenario C (Registry Spoofing):** Forges audit proofs for any official DataLayer `store_id`. | `RED`: `counterfeit_verified: true, attacker_cat_balance_mojo: 100000000`<br/>`GREEN`: `counterfeit_verified: false, attacker_cat_balance_mojo: 0`<br/>`pytest -k dl01` |
| **24** | [`24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/ko/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)<br/>`CHIA-CS-01 (POC-1 & POC-2)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-driver/src/clear_signing/tests.rs` | `CWE-451 / CWE-345`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` ignores `Condition::Other` CLVM conditions (such as overlong `RESERVE_FEE` opcode `52`) that consensus CLVM executes.<br/>**Scenario A (`750 XCH` Hidden Fee Drain):** `SpendBundle` `b9b614d0...` displays `reserved_fee: 0` in Clear-Signing while draining `750 XCH` (`750,000,000,000,000 mojo`) in consensus.<br/>**Scenario B (NFT State Spoofing):** `SpendBundle` `17d2796f...` alters NFT state invisibly.<br/>**Scenario C (Fail-Closed Patch):** `GREEN` rejects non-canonical conditions before signing. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 750000000000000`<br/>`GREEN`: `rejected_non_canonical_condition: true`<br/>`cargo test clear_signing::tests` |
| **25** | [`25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/ko/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)<br/>`CHIA-CS-02 (POC-3)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation) | `CWE-451 / CWE-345`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` ignores extra consensus conditions (`RESERVE_FEE`) emitted by an NFT `NEW_METADATA_INFO` updater program.<br/>**Scenario A (`500 XCH` Hidden NFT Fee):** `SpendBundle` `b314b6d7...` (`3,300B`) shows `reserved_fee = 0` in Clear-Signing while draining `500 XCH` on-chain.<br/>**Scenario B (Trojan NFT Updater):** Custom updater triggers hidden fee during vault NFT operations.<br/>**Scenario C (`GREEN` Patch):** Rejects non-pure metadata updater conditions. | `RED`: `displayed_fee_mojo: 0, consensus_fee_drained_mojo: 500000000000000`<br/>`GREEN`: `rejected_impure_metadata_updater: true`<br/>`cargo test clear_signing::tests` |
| **26** | [`26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/ko/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)<br/>`CHIA-CS-03 (POC-4)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` merges dependent offer settlement legs via set intersection, dropping disjoint payment legs.<br/>**Scenario A (`500 XCH` Omitted Offer Leg):** Vault spend `3c55638a...` + settlement spend `7c05b725...` transfers `500 XCH` (`500,000,000,000,000 mojo`) omitted from Clear-Signing.<br/>**Scenario B (Treasury Swap Drain):** Disjoint notarized payment drains treasury funds.<br/>**Scenario C (`GREEN` Patch):** Enforces full union accounting across all legs. | `RED`: `omitted_settlement_outflow_mojo: 500000000000000`<br/>`GREEN`: `full_outflow_accounted_or_rejected: true`<br/>`cargo test clear_signing::tests` |
| **27** | [`27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/ko/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)<br/>`CHIA-CS-04 (POC-5)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` allows creating a `SETTLEMENT_PAYMENT_HASH` coin without revealing its spend in the signing bundle.<br/>**Scenario A (`600 XCH` Unrevealed Settlement):** Victim signs `a9eeda2c...` (`1,303B`); attacker attaches settlement spend `e0b876fb...` (`388B`) and drains `600 XCH`.<br/>**Scenario B (Air-Gapped Signer Bypass):** Hardware preview shows zero external recipient.<br/>**Scenario C (`GREEN` Patch):** Rejects unrevealed settlement outputs. | `RED`: `unrevealed_settlement_accepted: true, hidden_outflow_mojo: 600000000000000`<br/>`GREEN`: `rejected_unrevealed_settlement: true`<br/>`cargo test clear_signing::tests` |
| **28** | [`28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/ko/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)<br/>`CHIA-CS-05 (POC-6)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.38.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs`<br/>`crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`) | `CWE-682 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` and `chia_sdk_bindings::parse_vault_transaction` credit outputs from external non-vault `DropCoin` spends as vault change.<br/>**Scenario A (`1,000 XCH` FFI Vault Drain):** `SpendBundle` `aa651822...` (`1,477B`) drains `1,000 XCH` (`1,000,000,000,000,000 mojo`) while reporting `0` net vault loss across the FFI boundary.<br/>**Scenario B (Multi-Sig Deception):** All cosigners see the spoofed change summary.<br/>**Scenario C (`GREEN` FFI Test):** Rejects with `Error::NonStandardInnerSpend`. | `RED`: `ffi_parse_vault_tx_accepted: true, masked_vault_drain_mojo: 1000000000000000`<br/>`GREEN`: `Err(NonStandardInnerSpend)`<br/>`cargo test --test clear_signing_ffi_proof` |
| **29** | [`29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/ko/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)<br/>`CHIA-CS-06 (POC-7)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding) | `CWE-347 / CWE-451`<br/>**9.1 Critical**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **How It Happens in Code:** `clear_signing.rs` accepts offer pre-split child spends that are not cryptographically bound by an announcement to the signed vault spend.<br/>**Scenario A (`1,000 XCH` Post-Signature Splicing):** Victim signs `476b8e83...` (`1,994B`); attacker splices `5b3a3b21...` (`1,701B`) and redirects `1,000 XCH` under the same BLS signature.<br/>**Scenario B (Mempool Replacement):** Unbound child spend replaced in transit.<br/>**Scenario C (`GREEN` Patch):** Enforces cryptographic announcement binding. | `RED`: `pre_split_sha256: 476b8e83..., spliced_sha256: 5b3a3b21..., redirected_mojo: 1000000000000000`<br/>`GREEN`: `rejected_unbound_presplit: true`<br/>`cargo test clear_signing::tests` |
| **30** | [`30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/ko/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)<br/>`CHIA-CS-07 (POC-8)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check) | `CWE-345 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` does not verify that a Clawback output's `sender_puzzle_hash` belongs to the signing vault.<br/>**Scenario A (`1,000 XCH` Reverse Clawback):** `SpendBundle` `6897c10e...` (`1,218B`) sets the attacker as `sender_puzzle_hash`, letting the attacker immediately claw back `1,000 XCH`.<br/>**Scenario B (Self-Transfer Illusion):** Victim is set as receiver while attacker holds instant clawback rights.<br/>**Scenario C (`GREEN` Patch):** Enforces `sender_puzzle_hash` ownership. | `RED`: `attacker_set_as_clawback_sender: true, hijacked_mojo: 1000000000000000`<br/>`GREEN`: `rejected_foreign_clawback_sender: true`<br/>`cargo test clear_signing::tests` |
| **31** | [`31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/ko/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)<br/>`CHIA-CS-08 (POC-9)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/cni-wallet-sdk** (`<= 0.36.0`)<br/>`crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting) | `CWE-682 / CWE-451`<br/>**8.6 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `clear_signing.rs` omits external CAT ring `RUN_TAIL` melt/issuance deltas funded by the vault's CAT spend.<br/>**Scenario A (`750 XCH`-Scale CAT Ring Drain):** `SpendBundle` `e48c3171...` (`2,541B`) drains `750,000,000,000,000` mojos via an external CAT ring melt.<br/>**Scenario B (Redemption Hijack):** External ring member absorbs vault CAT delta.<br/>**Scenario C (`GREEN` Patch):** Enforces full CAT ring conservation. | `RED`: `poc9_spend_bundle_sha256: e48c3171..., omitted_cat_ring_delta_mojo: 750000000000000`<br/>`GREEN`: `rejected_unbalanced_external_cat_ring: true`<br/>`cargo test clear_signing::tests` |
| **32** | [`32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/ko/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)<br/>`CHIA-VR-01 (POC-10)`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-vault-recover** (`<= 1.0.0-rc9`)<br/>`src/locate.rs:148-219` (`find_launcher_id`) | `CWE-345 / CWE-400`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `find_launcher_id` (`src/locate.rs:148-219`) returns the first `SINGLETON_LAUNCHER_HASH` child found at the user's address without verifying vault custody/recovery key match.<br/>**Scenario A (1-Mojo CLI Lockout):** Decoy launcher `2de44601...` causes `chia-vault-recover` (`1.0.0-rc9`) to abort with `recovery phrase does not match`.<br/>**Scenario B (`WLC-02` + `VR-01` Chain):** Blocks both GUI and CLI recovery.<br/>**Scenario C (`GREEN` Release Binary):** Recovers true launcher `e53d0c41...` (`45/45` tests pass). | `RED`: `selected_launcher: 2de44601... (decoy), cli_exit_code: 1`<br/>`GREEN`: `selected_launcher: e53d0c41... (victim), cli_exit_code: 0`<br/>`pytest -k poc10` |
| **33** | [`33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/ko/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)<br/>`CHIA-CONS-SP-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`) | `CWE-400 / CWE-345`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` | **How It Happens in Code:** `full_node.py:2220-2310` aborts `sync_from_fork_point` on invalid sub-epoch/weight-proof responses without disconnecting the peer.<br/>**Scenario A (Port `8444` Sync Lockout):** 3-node mTLS proof keeps victim `peak` at `None` despite an honest peer at `height=5`.<br/>**Scenario B (`10,000 XCH` Reorg Double-Spend):** `Branch A` (`26afe149...`) credits exchange `+10,000 XCH`; `Branch B` (`ad2eba4d...`) reorgs exchange balance to `0`.<br/>**Scenario C (`GREEN` Patch):** Disconnects offending peer & enforces `min_confirmations=32`. | `RED`: `victim_peak: None, reorg_exchange_loss_mojo: 10000000000000000`<br/>`GREEN`: `victim_synced_height: 5, exchange_loss_mojo: 0`<br/>`pytest -k reorg` |
| **34** | [`34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/ko/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)<br/>`CHIA-WLT-OFFER-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/rpc/wallet_rpc_api.py` (`take_offer`)<br/>`chia/wallet/trade_manager.py` (`respond_to_offer`) | `CWE-863`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **How It Happens in Code:** `take_offer` / `respond_to_offer` selects and signs wallet coins for requested offer payments without enforcing a per-asset `max_authorized_amount` cap.<br/>**Scenario A (Taker Bot Excess Spend):** External Offer induces coin selection above expected quote.<br/>**Scenario B (Hidden Multi-Asset Leg):** CAT/NFT offer silently pulls XCH from wallet.<br/>**Scenario C (`GREEN` Patch):** Enforces explicit per-asset spend cap. | `RED`: `unbounded_implicit_coin_spend_signed: true`<br/>`GREEN`: `exceeded_max_authorized_amount_rejected: true`<br/>`pytest -k wallet` |
| **35** | [`35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/ko/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)<br/>`CHIA-POS-01`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`)<br/>`chiapos` Rust FFI (`size_v2` / `get_quality_string`) | `CWE-248 / CWE-20`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `FarmerAPI.new_proof_of_space` (`farmer_api.py:85-185`) calls Rust FFI `size_v2()` / `get_quality_string()` before validating pool key XOR exclusivity and `check_plot_param`.<br/>**Scenario A (4/4 Farmer Cluster Crash):** Single 445-byte wire packet (`30a0e918...`) triggers `pyo3_runtime.PanicException` and terminates all 4 Farmer processes (`exit_code=1`).<br/>**Scenario B (Slice OOB Panic):** Truncated proof triggers `range end index 36 out of range for slice of length 32`.<br/>**Scenario C (`GREEN` Patch):** `4/4` Farmers survive (`exit_code=0`). | `RED`: `packet_bytes: 445, crashed_farmers: 4/4, PanicException`<br/>`GREEN`: `crashed_farmers: 0/4, alive_farmers: 4`<br/>`pytest -k farmer` |
| **36** | [`36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/ko/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)<br/>`CHIA-POS-02..04`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiapos** (`<= 2.0.11`)<br/>`src/verifier.hpp:48-108` (`Verifier::ValidateProof`)<br/>`src/bits.hpp:184`<br/>`src/prover_disk.hpp:254-322` (`DiskProver`) | `CWE-190 / CWE-787 / CWE-125`<br/>**8.1 High**<br/>`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **How It Happens in Code:** `Verifier::ValidateProof` (`src/verifier.hpp`, `src/bits.hpp:184`) overflows bit offsets at `k=50` (Table 4) and `k>=60`, and `DiskProver` (`src/prover_disk.hpp`) truncates 64-bit plot table sizes to 32-bit.<br/>**Scenario A (Crafted `.plot` Heap Overflow):** Loading a crafted `.plot` file triggers 64-to-32-bit truncation heap corruption.<br/>**Scenario B (`k=50` / `k=60` Stack OOB):** Verified via ASan/UBSan `chiapos_k_probe` (`exit_code=1`).<br/>**Scenario C (`GREEN` Patch):** Bounds-checked (`exit_code=0`). | `RED`: `k50_table4_asan_exit: 1, k60_asan_exit: 1 (src/bits.hpp:184 OOB)`<br/>`GREEN`: `exit_code: 0, rejected_cleanly: true`<br/>`pytest -k chiapos` |
| **37** | [`37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/ko/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)<br/>`CHIA-VDF-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chiavdf** (`<= 1.1.11`)<br/>`src/verifier.cpp` (`CheckProofOfTimeNWesolowski`)<br/>`src/prover_slow.h` | `CWE-125 / CWE-416`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **How It Happens in Code:** `CheckProofOfTimeNWesolowski` (`src/verifier.cpp`) slices `proof_blob` without validating `proof_blob_len` or `num_iterations > 0`.<br/>**Scenario A (Verifier OOB Crash):** Truncated VDF proof triggers native C++ out-of-bounds read.<br/>**Scenario B (Teardown UAF):** Worker thread accesses freed state in `prover_slow.h`.<br/>**Scenario C (`GREEN` Patch):** Returns `false` cleanly on malformed VDF proofs. | `RED`: `asan_oob_or_segv: true, exit_code: 1`<br/>`GREEN`: `asan_oob_or_segv: false, verified: false`<br/>`chiavdf ASan harness` |
| **38** | [`38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/ko/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)<br/>`CHIA-DL-02`<br/>MITRE CNA-LR & Chia Network | **Chia-Network/chia-blockchain** (`<= 2.7.5`)<br/>`chia/data_layer/download_data.py`<br/>`chia/data_layer/data_layer.py` | `CWE-918`<br/>**7.5 High**<br/>`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | **How It Happens in Code:** `download_data.py` fetches DataLayer mirror URLs with `allow_redirects=True` and no loopback/private IP validation on redirect hops.<br/>**Scenario A (Internal Loopback/Metadata SSRF):** A `302` redirect on an announced mirror URL hits `127.0.0.1` / `169.254.169.254`.<br/>**Scenario B (Replica Fleet Scanning):** Subscribed nodes poll redirected internal hosts.<br/>**Scenario C (`GREEN` Patch):** Blocks redirects to private/loopback IPs. | `RED`: `redirect_to_loopback_followed: true, internal_hit_count: 1`<br/>`GREEN`: `redirect_to_loopback_followed: false, internal_hit_count: 0`<br/>`pytest -k dl02` |

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

<!-- GITLAB-ADVISORIES-START -->

---

### III.12 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — OAuth 2.0 Device Authorization Grant (`Oauth::DeviceAuthorizationsController` & `Oauth::TokensController`) Policy Bypass of `disable_admin_oauth_scopes`, Email Confirmation Gate, and Organization Maintenance Mode (`GITLAB-CAND-02A / 02B / 02C`) (`CWE-863 / CWE-285`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/oauth/device_authorizations_controller.rb:4-50`, `app/controllers/oauth/tokens_controller.rb:42-75`
* **Vulnerability Class & Score:** `CWE-863 / CWE-285` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md`](advisories/ko/12-GITLAB-CAND-02-DEVICE-GRANT-POLICY-BYPASS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing `verify_admin_allowed!` Bypasses Default `disable_admin_oauth_scopes` (`CAND-02A`, `device_authorizations_controller.rb:4-42`):** In `Oauth::AuthorizationsController` (`authorizations_controller.rb:18, 274-296`), `before_action :verify_admin_allowed!` blocks any untrusted OAuth application (`trusted: false`) from connecting to an administrator account with dangerous scopes (`api`, `read_api`, `admin_mode`, `sudo`, `write_repository`) whenever `Gitlab::CurrentSettings.disable_admin_oauth_scopes` is `true` (the default GitLab security setting). Because `Oauth::DeviceAuthorizationsController` inherits directly from `Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController` without adding `before_action :verify_admin_allowed!`, any regular user can create an untrusted OAuth app (`trusted: false, device_code_enabled: true, scopes: 'api admin_mode'`) and obtain a full-privilege admin access token when an admin approves a `user_code` on `/oauth/device`.
2. **Step 2 — Missing `verify_confirmed_email!` Allows Unconfirmed Accounts to Mint Persistent OAuth Tokens (`CAND-02B`, `device_authorizations_controller.rb:4-42`):** GitLab allows newly registered or reconfirming users (`confirmed_at: nil`) an active web session within `allow_unconfirmed_access_for = 3.days` (`config/initializers/8_devise.rb:75, 103`), but `Oauth::AuthorizationsController` blocks them from minting OAuth tokens via `before_action :verify_confirmed_email!` (`403 Forbidden`). `Oauth::DeviceAuthorizationsController` omits `verify_confirmed_email!`, allowing unconfirmed accounts to mint persistent `access_token` and `refresh_token` credentials via `/oauth/device/authorize`.
3. **Step 3 — Missing `enforce_organization_maintenance_mode` and `device_code` Organization Lookup (`CAND-02C`, `tokens_controller.rb:42-70` & `device_authorizations_controller.rb:4-42`):** `Oauth::TokensController#organization_for_token_request` checks `refresh_token` and `authorization_code` grants against organization maintenance freezes (`migration` -> `503 Service Unavailable`, `legal` -> `403 Forbidden`), but omits `when 'urn:ietf:params:oauth:grant-type:device_code'`, while `Oauth::DeviceAuthorizationsController` omits both `set_current_organization` and `enforce_organization_maintenance_mode`.

```ruby
// File: app/controllers/oauth/device_authorizations_controller.rb (lines 4-35)
module Oauth
  class DeviceAuthorizationsController < Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController
    include RequestPayloadLogger

    layout 'minimal'
    # BUG: Missing before_action :verify_confirmed_email!, :verify_admin_allowed!
    # BUG: Missing prepend_before_action :set_current_organization
    # BUG: Missing before_action :enforce_organization_maintenance_mode

// File: app/controllers/oauth/tokens_controller.rb (lines 42-52)
  def organization_for_token_request
    token_params = params.permit(:grant_type, :refresh_token, :code)
    case token_params[:grant_type]
    when 'refresh_token'
      OauthAccessToken.by_refresh_token(token_params[:refresh_token])&.organization
    when 'authorization_code'
      OauthAccessGrant.by_token(token_params[:code])&.organization
    # BUG: Missing when 'urn:ietf:params:oauth:grant-type:device_code'
    end
  end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Full GitLab Instance Admin Takeover via Untrusted Developer CLI/IDE Device Code Despite `disable_admin_oauth_scopes=true`:** On any standard GitLab instance (`disable_admin_oauth_scopes=true` by default to prevent untrusted OAuth apps from ever receiving `api` or `admin_mode` privileges), a regular user or external contractor registers an untrusted OAuth app (`trusted: false, device_code_enabled: true, scopes: "api admin_mode sudo"`) disguised as an internal CLI or VS Code helper and shares a login `user_code`. The moment an administrator approves the code on `/oauth/device`, GitLab bypasses `disable_admin_oauth_scopes` and mints a full-privilege `admin_mode` + `api` token. The attacker immediately uses this token to clone every private repository in the company, dump all CI/CD production secrets (`AWS_SECRET_ACCESS_KEY`, database passwords), create new root administrator accounts, and take complete control of the GitLab server.
* **Scenario B — Persistent API Backdoor & CI/CD Abuse Using Unverified / Spoofed Corporate Email Accounts (`confirmed_at: nil`):** An attacker signs up with an unverified or spoofed email address (`confirmed_at: nil`). While standard web OAuth (`/oauth/authorize`) blocks the account with `403 Forbidden (unconfirmed_email)`, the attacker completes `/oauth/device/authorize` + `/oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:device_code`) and mints persistent `access_token` and `refresh_token` credentials without ever verifying email ownership—retaining programmatic API access to internal/public repositories and CI pipelines even after the web session expires.
* **Scenario C — Injecting Backdoored Code & Malicious `.gitlab-ci.yml` Pipelines During an Enterprise Incident Freeze or Legal Hold (`migration` / `legal` Maintenance Mode):** During a live security incident investigation (`legal` hold -> `403`) or data-center migration (`migration` -> `503`), enterprise administrators lock the entire organization in maintenance mode so no code or state can be modified. Because `Oauth::TokensController` omits `device_code` from `organization_for_token_request`, an attacker exchanges a device code during the freeze window and pushes malicious commits (`POST /api/v4/projects/1/repository/commits` -> `201 Created`) or tampers with release branches while the organization is supposedly frozen.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect missing before_action guards in DeviceAuthorizationsController vs AuthorizationsController
grep -n -C 6 "verify_admin_allowed!" \
  /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb \
  /home/community-user/targets/gitlab/app/controllers/oauth/device_authorizations_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report1_cand02
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-01_CAND-02A-02B-02C": {
    "GREEN": {
      "device_authorize_status": 503,
      "maintenance_mode_write_succeeded": false,
      "post_token_admin_action_succeeded": false,
      "redacted_token_sample": null,
      "standard_oauth_blocked": true,
      "token_exchange_status": 503,
      "token_minted_admin_mode": false
    },
    "RED": {
      "device_authorize_status": 200,
      "maintenance_mode_write_succeeded": true,
      "post_token_admin_action_succeeded": true,
      "redacted_token_sample": "[REDACTED_TEST_TOKEN_SHA256:91ba3cabf8cbd392]",
      "standard_oauth_blocked": true,
      "token_exchange_status": 200,
      "token_minted_admin_mode": true
    },
    "patches": {
      "GITLAB-CAND-02-COMBINED.patch": "33f6cf48a91be9d564f3964e9b9c7a4c6d412b6814ebfa71356102767bddc698",
      "GITLAB-CAND-02C-MAINTENANCE-MODE.patch": "80bfc7b3ee0e328487e4de303a9d707e575989f848d778914b359494fac90aa8"
    }
  }
}
```


---

### III.13 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog MCP OAuth `CallbackService`, `RefreshTokenService`, `RevokeTokenService`, and `DynamicRegistrationClient` `307 Temporary Redirect` / Unvalidated RFC 8414 Metadata SSRF & Error Body Reflection (`GITLAB-CAND-05`) (`CWE-918 / CWE-209`, CVSS `8.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/catalog/mcp_servers/callback_service.rb:17-50, 87-129`, `refresh_token_service.rb:18-70`, `dynamic_registration_client.rb:104-136`
* **Vulnerability Class & Score:** `CWE-918 / CWE-209` — **CVSS v3.1: `8.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md`](advisories/ko/13-GITLAB-CAND-05-MCP-OAUTH-307-REDIRECT-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated RFC 8414 `token_endpoint`, `revocation_endpoint`, and `authorization_servers` (`dynamic_registration_client.rb:104-136`):** `DynamicRegistrationClient#discover_auth_server_url` and `#discover_metadata` validate only the initial discovery URL via `UrlBlocker`, but return `resource_metadata['authorization_servers'].first` and `response.parsed_response` (`token_endpoint`, `revocation_endpoint`, `issuer`) without running `Gitlab::HTTP_V2::UrlBlocker.validate!` on the discovered endpoints.
2. **Step 2 — `OAuth2::Client` (`oauth2 2.0.25`) Bypasses `Gitlab::HTTP` and Follows Up to 5 `307 Temporary Redirect` Hops (`callback_service.rb:38-50`, `refresh_token_service.rb:45-58`):** `CallbackService#build_oauth_client` and `RefreshTokenService#build_oauth_token` instantiate `OAuth2::Client.new` using Faraday's default `net_http` adapter (`max_redirects: 5`) without `UrlBlocker` or IP pinning. When an external OAuth server responds with `307 Temporary Redirect` to `http://127.0.0.1:...` or `http://169.254.169.254/latest/meta-data/...`, `OAuth2::Client` replays the full `POST` request (including `client_secret`, `code`, or `refresh_token`) directly against the internal target.
3. **Step 3 — Full Internal Error Body Reflection via `OAuth2::Error#message` (`callback_service.rb:24-25`, `refresh_token_service.rb:29-30`):** Both services rescue `OAuth2::Error => e` and pass `e.message` into `error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))`, which `Oauth::McpConnectorsAuthController#callback` assigns to `flash[:alert]`, exposing raw internal HTTP `4xx`/`5xx` response bodies to the user.

```ruby
// File: ee/app/services/ai/catalog/mcp_servers/callback_service.rb (lines 15-50)
        def execute
          token_params = { redirect_uri: redirect_uri }
          token_params[:code_verifier] = code_verifier if code_verifier

          access_token = build_oauth_client.auth_code.get_token(code, **token_params)
          store_token(access_token)
        rescue OAuth2::Error, StandardError => e
          # BUG 1: Reflects raw upstream HTTP error response body (e.message) into flash[:alert]
          error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))
        end
        ...
        def build_oauth_client
          auth_server_url = registration_service.discover_auth_server_url
          metadata = registration_service.discover_metadata(auth_server_url)
          # BUG 2: Uses OAuth2::Client (Faraday net_http, max_redirects: 5) without UrlBlocker or IP pinning!
          OAuth2::Client.new(
            mcp_server.oauth_client_id,
            mcp_server.oauth_client_secret,
            site: auth_server_url,
            authorize_url: metadata['authorization_endpoint'],
            token_url: metadata['token_endpoint'],
            auth_scheme: ::Gitlab::Oauth::DynamicRegistrationClient.token_endpoint_auth_scheme(metadata)
          )
        end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Stealing AWS/GCP Cloud IAM Credentials (`169.254.169.254`) and Internal Kubernetes/Vault Secrets Directly into the User's Browser (`flash[:alert]`):** An attacker registers an external MCP server whose OAuth `token_endpoint` responds with `307 Temporary Redirect` pointing to the cloud instance metadata service (`http://169.254.169.254/latest/meta-data/iam/security-credentials/...`) or an internal Kubernetes/Vault/Consul API (`http://127.0.0.1:8080/...`). `OAuth2::Client` follows the redirect from inside the GitLab server network and reflects the raw HTTP response body via `OAuth2::Error#message` straight into the user's browser `flash[:alert]` banner (`iam_role_credentials_exposed: true`), allowing the attacker to steal the GitLab host's cloud IAM role keys and compromise the underlying cloud infrastructure.
* **Scenario B — Executing Authenticated Internal `POST` Commands Against Firewalled Intranet Services (`127.0.0.1` / `10.x.x.x`) & Leaking OAuth Secrets:** Because `307 Temporary Redirect` preserves both the `POST` method and request body, an external OAuth endpoint redirects `CallbackService` and `RefreshTokenService` (`max_redirects: 5`) to firewalled internal microservices (`http://127.0.0.1:...`), triggering internal `POST` actions behind the firewall while leaking the MCP connector's `client_secret` and `refresh_token` (`canary_b_request_count = 5`).
* **Scenario C — Internal Intranet Port/Service Scanning & Basic-Auth Credential Exfiltration on Disconnect (`RevokeTokenService`):** When an administrator or developer clicks "Disconnect" on an MCP connector, `RevokeTokenService` sends an unvalidated `POST` request with HTTP Basic Auth (`client_id:client_secret`) to `metadata['revocation_endpoint']`, enabling internal network probing and credential theft.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect OAuth2::Client usage and OAuth2::Error reflection in CallbackService & RefreshTokenService
grep -n -C 12 "OAuth2::Client.new" \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/callback_service.rb \
  /home/community-user/targets/gitlab/ee/app/services/ai/catalog/mcp_servers/refresh_token_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.14 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Oauth::McpConnectorsAuthController`, `ConnectService`, and `Gitlab::Oauth::ClientState` Missing Organization Isolation (`in_organization`), Unauthorized DCR Client Overwrite, and Unbound OAuth State (`GITLAB-CAND-06`) (`CWE-639 / CWE-862`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/controllers/oauth/mcp_connectors_auth_controller.rb:16-78`, `ee/app/services/ai/catalog/mcp_servers/connect_service.rb:16-79`, `ee/lib/gitlab/oauth/client_state.rb:17-23`
* **Vulnerability Class & Score:** `CWE-639 / CWE-862` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md`](advisories/ko/14-GITLAB-CAND-06-MCP-CONNECTORS-CROSS-ORG-IDOR.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unscoped Global `Ai::Catalog::McpServer.find` Across Organizations (`mcp_connectors_auth_controller.rb:19, 38, 63, 71-73`):** `Oauth::McpConnectorsAuthController` checks `can?(current_user, :read_ai_catalog_mcp_server, Current.organization)` against the caller's own organization, and then calls `::Ai::Catalog::McpServer.find(mcp_server_params[:id])` without `.in_organization(Current.organization)`. Any user in Organization A can target an `McpServer` belonging to Organization B by ID.
2. **Step 2 — Unauthorized Dynamic Client Registration (DCR) Credential Mutation with Read-Only Permission (`connect_service.rb:16-39, 60-79`):** When `mcp_server.oauth_client_id.blank?` is true, `ConnectService#execute` calls `register_oauth_client`, which overwrites `mcp_server.update!(oauth_client_id: ..., oauth_client_secret: ...)` without verifying `Ability.allowed?(current_user, :update_ai_catalog_mcp_server, mcp_server)`.
3. **Step 3 — `Gitlab::Oauth::ClientState.from_state` Discards `data` Binding (`client_state.rb:17-23`) and `callback` Accepts Missing PKCE Verifiers:** `ClientState.from_state(state)` calls `new(salt: salt, token: token, return_to: return_to)` without passing `data:`, so `@data` defaults to `{}` and the HMAC check verifies only `return_to` without binding `user_id`, `organization_id`, or `mcp_server_id`.

```ruby
// File: ee/app/controllers/oauth/mcp_connectors_auth_controller.rb (lines 18-65)
    def connect
      mcp_server = ::Ai::Catalog::McpServer.find(mcp_server_params[:id]) # BUG 1: Missing .in_organization(Current.organization)
      result = ::Ai::Catalog::McpServers::ConnectService.new(
        mcp_server: mcp_server,
        redirect_uri: oauth_mcp_connectors_callback_url,
        return_to: mcp_server_params[:return_to] || root_path
      ).execute # BUG 2: Mutates oauth_client_id/secret without checking :update_ai_catalog_mcp_server!

// File: ee/lib/gitlab/oauth/client_state.rb (lines 19-23)
      def self.from_state(state)
        salt, token, return_to = state.to_s.split(':', 3)
        new(salt: salt, token: token, return_to: return_to) # BUG 3: Omits data: binding!
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hijacking Another Organization's Enterprise AI / MCP Connector Across Tenant Boundaries (`Cross-Org IDOR`):** On a multi-organization GitLab deployment, an attacker in Organization A targets an `McpServer` ID belonging to Organization B via `POST /oauth/mcp_connectors/:id/connect`. Because `Oauth::McpConnectorsAuthController` omits `.in_organization(Current.organization)` and `ConnectService` omits `update_ai_catalog_mcp_server`, the attacker triggers Dynamic Client Registration (`register_oauth_client`) and overwrites Organization B's `oauth_client_id` and `oauth_client_secret` (`cross_org_server_mutated: true`)—redirecting the victim organization's AI connector OAuth flows and developer prompts/tokens to the attacker's OAuth client.
* **Scenario B — Read-Only Developer/Guest Overwrites Production AI Connector Credentials Within a Company:** A low-privileged user with only read permission (`read_ai_catalog_mcp_server`) invokes `/oauth/mcp_connectors/:id/connect` before or during connector setup and overwrites the server's `oauth_client_id` and `oauth_client_secret` without maintainer privileges (`update_ai_catalog_mcp_server`), hijacking or breaking the company's AI integration.
* **Scenario C — Cross-Session OAuth Account Binding (Login CSRF) via Unbound `ClientState` Token:** Because `ClientState.from_state` discards the `data` hash (`user_id` / `organization_id`) and `callback` makes PKCE `code_verifier` optional when absent from the session, an attacker tricks a victim developer into visiting a crafted `/oauth/mcp_connectors/callback?state=...&code=...` link, silently binding the victim's GitLab session to the attacker's external MCP account (`McpServerUserConnection`) so every AI tool call the victim makes streams workspace data to the attacker.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect unscoped McpServer.find in McpConnectorsAuthController and ConnectService
grep -n -C 8 "McpServer.find" \
  /home/community-user/targets/gitlab/ee/app/controllers/oauth/mcp_connectors_auth_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.15 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — GitLab Workhorse DuoWorkflow External MCP Client Missing `transport.WithSSRFFilter()` and Cross-Origin Redirect `Authorization: Bearer` Token Leakage (`GITLAB-CAND-01`) (`CWE-918 / CWE-522`, CVSS `8.2 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`Go / GitLab Workhorse: gitlab.com/gitlab-org/gitlab/workhorse`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `workhorse/internal/ai_assist/duoworkflow/mcp.go:25-60, 101-112, 220-239`
* **Vulnerability Class & Score:** `CWE-918 / CWE-522` — **CVSS v3.1: `8.2 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md`](advisories/ko/15-GITLAB-CAND-01-WORKHORSE-MCP-SSRF-TOKEN-LEAK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `externalMcpTransport` Omits `transport.WithSSRFFilter` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:41-44`):** In GitLab Workhorse's `transport` package, `transport.NewRestrictedTransport` only blocks loopback (`127.0.0.1`), link-local metadata (`169.254.169.254`), and RFC1918 private IPs when `transport.WithSSRFFilter(...)` is explicitly passed (as done in `workhorse/internal/sendurl/sendurl.go:365-374`). `externalMcpTransport` in `mcp.go:41-44` omits `transport.WithSSRFFilter`, leaving external MCP connections completely unfiltered at the dialer/transport layer.
2. **Step 2 — `roundTripper.RoundTrip` Re-Injects `Authorization: Bearer` Headers on Every Redirect Hop (`mcp.go:101-104, 231-234`):** Go's `http.Client` normally strips `Authorization` headers on cross-origin redirects *before* calling `Transport.RoundTrip`. However, `duoworkflow.roundTripper.RoundTrip` loops over `t.headers` (`r.Header.Set(name, value)`) inside `RoundTrip` itself and `HTTPClient` defines no `CheckRedirect` policy. Consequently, on any `301`/`302`/`307` redirect to a different host or internal IP, Workhorse re-attaches `Authorization: Bearer <token>` and sends it to the redirect destination.

```ruby
// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 41-44, 101-104, 231-234)
var externalMcpTransport = transport.NewRestrictedTransport(func(t *http.Transport) {
	t.MaxIdleConns = externalMcpMaxIdleConns
	t.MaxIdleConnsPerHost = externalMcpMaxIdleConnsPerHost
}) // BUG 1: Missing transport.WithSSRFFilter(false, nil)!

func (t *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	for name, value := range t.headers {
		r.Header.Set(name, value) // BUG 2: Re-injects Authorization header on cross-origin redirect hops!
	}
...
	t = &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: rt}, // BUG 3: No CheckRedirect policy!
		DisableStandaloneSSE: true,
	}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Stealing a Victim Developer's or Administrator's Live `Authorization: Bearer` Token via Cross-Origin `302` Redirect (Full Account & Private Repository Takeover):** When a developer or administrator runs a Duo Workflow AI session connected to an external MCP tool server, GitLab Workhorse (`mcp.go`) attaches the user's live `Authorization: Bearer <token>` header. When the external server responds with a `302 Found` redirect to an attacker-controlled domain (`https://attacker-collector.example/collect`), `roundTripper.RoundTrip` re-injects `Authorization: Bearer <token>` on the cross-origin hop (`bearer_token_leaked_to_canary: true`). The attacker captures the live Bearer token and immediately uses it to clone private repositories, read sensitive issues/merge requests, or push malicious code as the victim.
* **Scenario B — Workhorse Server-Side Request Forgery (SSRF) Against Internal Loopback (`127.0.0.1`), Gitaly/Redis/Puma Exporters, and Cloud Metadata (`169.254.169.254`):** Because `externalMcpTransport` in `mcp.go:41-44` omits `transport.WithSSRFFilter()` (unlike `sendurl.go`), an external MCP URL that passes initial Rails validation can issue a `302` redirect directly to `http://127.0.0.1:8080`, internal Prometheus/Puma admin endpoints, or `http://169.254.169.254/`, allowing attackers to reach internal services directly from the Workhorse reverse-proxy process.
* **Scenario C — DNS Rebinding Bypass Into the Internal Corporate Network:** An external MCP hostname resolves to a public IP when registered in GitLab Rails, then rebinds (`TTL=0`) to `127.0.0.1` or `10.0.0.1` when Workhorse opens the long-lived MCP stream—bypassing Rails URL validation because Workhorse's socket dialer lacks `WithSSRFFilter`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Compare externalMcpTransport in duoworkflow/mcp.go against sendurl/sendurl.go
grep -n -C 8 "NewRestrictedTransport" \
  /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go \
  /home/community-user/targets/gitlab/workhorse/internal/sendurl/sendurl.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report2_cand05
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-02_CAND-05-06-01": {
    "GREEN": {
      "bearer_token_leaked_to_canary": false,
      "canary_b_request_count": 0,
      "cross_org_server_mutated": false,
      "iam_role_credentials_exposed": false,
      "reflected_flash_contains_secret": false
    },
    "RED": {
      "bearer_token_leaked_to_canary": true,
      "canary_b_request_count": 2,
      "cross_org_server_mutated": true,
      "iam_role_credentials_exposed": true,
      "reflected_flash_contains_secret": true
    },
    "patches": {
      "GITLAB-CAND-01.patch": "77be0cfe3092c808ea8f0a1f33689c61de1c9db01155e950b1192f883984b689",
      "GITLAB-CAND-05.patch": "e63dce6d6b71fcb0fa357103078290e07d66a0c756607b7b35da9eae209b687e",
      "GITLAB-CAND-06-MCP-IDOR-CSRF.patch": "8bed587ca203bfcde8fcf8e4ec27b12038e4e5366dc33f3d285b742811d2632b"
    }
  }
}
```


---

### III.16 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — Duo Workflow `/ws` and `McpConfigService#item_version` Missing `:read_ai_catalog_item` Authorization and Unvalidated `workflow_definition` Override Allowing Private Agent Write-Tool Injection (`GITLAB-CAND-08`) (`CWE-862 / CWE-639`, CVSS `7.7 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab EE: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:131-135`, `ee/lib/api/ai/duo_workflows/workflows.rb:341-344, 1065`, `connection_config_service.rb:220-228`
* **Vulnerability Class & Score:** `CWE-862 / CWE-639` — **CVSS v3.1: `7.7 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md`](advisories/ko/16-GITLAB-CAND-08-DUO-WORKFLOW-UNVALIDATED-ITEM-VERSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — In-File Authorization Inconsistency in `McpConfigService` (`mcp_config_service.rb:134` vs. `334`):** In `ee/app/services/ai/duo_workflows/mcp_config_service.rb`, `ai_catalog_mcp_servers` (line 334) explicitly enforces `return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version)`. However, in the exact same file, `item_version` (line 134), `agent_mcp_tools` (line 297), and `built_in_tool_ids` (line 318) call `::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)` without any `Ability.allowed?` check.
2. **Step 2 — `GET /api/v4/ai/duo_workflows/ws` (`workflows.rb:1065`) Bypasses the Developer's Security Rule at Line 1426:** At `workflows.rb:1426-1433`, a developer comment states: `# The definition comes off the record for the same reason: it selects the MCP tool set and the minted token's feature, so the body must not be able to swap in another flow's.` Yet `get :ws` (`workflows.rb:1065`) omits `workflow_definition: workflow.workflow_definition` and `ConnectionConfigService#mcp_config_service` (`connection_config_service.rb:220-228`) reads `request_metadata.workflow_definition` and `request_metadata.ai_catalog_item_version_id` directly from user query parameters.
3. **Step 3 — Injection of Foreign Private Agent Opt-In Write Tools:** By passing a foreign private (`public: false`) agent's `ai_catalog_item_version_id` and overriding `workflow_definition` on `/ws`, an authenticated caller injects opt-in write tools (`create_issue`, `create_merge_request`) into `x-gitlab-duo-workflow-mcp-servers` and discloses the private agent's configured tool set.

```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 131-135 vs 330-335)
      def item_version
        return unless ai_catalog_item_version_id.present?

        ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id) # BUG 1: Missing Ability.allowed?(current_user, :read_ai_catalog_item, version)!
      end
      ...
      def ai_catalog_mcp_servers
        return {} unless item_version
        return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version) # Enforced here at line 334, but omitted at line 134!

// File: ee/app/services/ai/duo_workflows/connection_config_service.rb (lines 222-228)
      def mcp_config_service
        ::Ai::DuoWorkflows::McpConfigService.new(
          current_user,
          gitlab_token,
          workflow_definition: request_metadata.workflow_definition, # BUG 2: Uses unvalidated request_metadata instead of workflow record!
          ai_catalog_item_version_id: request_metadata.ai_catalog_item_version_id,
          namespace: project&.project_namespace || enforcement_namespace
        )
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Turning a Restricted Read-Only `chat` Session into a Full Write-Capable Agent Session via `/ws` Parameter Override:** An organization restricts a user or workflow to read-only `chat` mode (`workflow.workflow_definition == 'chat'`), where state-mutating tools (`create_issue`, `create_merge_request`, repository/comment writes) are withheld. By passing an overridden `workflow_definition` and a foreign private `ai_catalog_item_version_id` on `GET /api/v4/ai/duo_workflows/ws`, the caller bypasses the workflow record's restrictions and injects write tools directly into the live Duo Workflow session (`unapproved_write_tool_injected: true`), allowing the AI agent to perform unauthorized write operations across projects.
* **Scenario B — Stealing Proprietary AI Agent Configurations & Toolsets From Other Organizations' Private (`public: false`) Projects:** Because `McpConfigService#item_version` (`mcp_config_service.rb:134`) omits `Ability.allowed?(current_user, :read_ai_catalog_item, item_version)`, an attacker enumerates `ai_catalog_item_version_id` integers on `/ws` or `POST /api/v4/ai/duo_workflows/workflows` to extract the confidential `def_tools` and `def_mcp_tools` configurations of private (`public: false`) AI Catalog agents owned by other organizations.
* **Scenario C — Attaching Unauthorized Private Agent Versions During Workflow Creation (`POST /api/v4/ai/duo_workflows/workflows`):** In `workflows.rb:341-344` (`create_workflow_params`), `Ai::Catalog::ItemVersion.find` is called without `:read_ai_catalog_item` authorization, allowing a user to permanently bind a private cross-organization agent version to their workflow record.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Compare line 134 vs line 334 in ee/app/services/ai/duo_workflows/mcp_config_service.rb
sed -n '130,136p;330,337p' \
  /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report3_cand08
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-03_CAND-08": {
    "GREEN": {
      "automated_issue_created_without_prompt": false,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": false,
      "workflow_definition_overridden": false
    },
    "RED": {
      "automated_issue_created_without_prompt": true,
      "downstream_victim_project_tools_call_status": 404,
      "unapproved_write_tool_injected": true,
      "workflow_definition_overridden": true
    },
    "patches": {
      "GITLAB-CAND-08-WORKFLOW-ITEM-VERSION-AUTHZ.patch": "d40f6e104c2fba0e8900cab8d45ddfb4cf9c49a60c8bb12e3aa573ddb1228704"
    }
  }
}
```


---

### III.17 — GitLab (`<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — AI Catalog Agent Unscoped `McpServer` Global ID Binding and `McpConfigService#execute` Built-in `:gitlab` Key Collision Bypassing Workhorse `withheld_server_tools` (`allToolsAvailable = true`) (`GITLAB-CAND-07`) (`CWE-863 / CWE-639`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems & Go / GitLab EE & Workhorse: gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `ee/app/services/ai/duo_workflows/mcp_config_service.rb:57-64`, `ee/app/services/ai/catalog/mcp_servers/list_service.rb:14-24`, `workhorse/internal/ai_assist/duoworkflow/mcp.go:254`
* **Vulnerability Class & Score:** `CWE-863 / CWE-639` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md`](advisories/ko/17-GITLAB-CAND-07-AGENT-CROSS-ORG-MCP-KEY-COLLISION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `McpConfigService#execute` Protects `:orbit` with `.except(:orbit)` But Forgets `:gitlab` (`mcp_config_service.rb:59-63`):** `McpConfigService#execute` builds the Workhorse MCP configuration hash via `gitlab_mcp_server(denied).merge(orbit_mcp_server).merge(ai_catalog_mcp_servers.except(:orbit))`. Because `.except(:orbit)` omits `:gitlab`, any `Ai::Catalog::McpServer` named `"GitLab"` (which normalizes to `server_key => :gitlab`) overwrites the built-in `:gitlab` entry produced by `gitlab_mcp_server(denied)`.
2. **Step 2 — Workhorse Evaluates `allToolsAvailable := s.cfg.Tools == nil` as `true` (`workhorse/internal/ai_assist/duoworkflow/mcp.go:254`):** `Ai::Catalog::McpServers::ConfigService#execute` (`config_service.rb:22-30`) builds catalog server entries as `{ URL: server.url, Headers: ... }` with no `:Tools` key (`s.cfg.Tools == nil`). When the `:gitlab` key is overwritten by a catalog server entry, Workhorse still routes `serverName == "gitlab"` to the internal `/api/v4/mcp` endpoint (`internal := serverName == "gitlab" || serverName == "orbit"` at `mcp.go:210`), but sets `allToolsAvailable := s.cfg.Tools == nil` (`true` at `mcp.go:254`), completely disabling the `withheld_server_tools(denied)` filter!
3. **Step 3 — Cross-Organization `McpServer` GID Binding (`agent/create.rb:61-65`, `agent/update.rb:65-69`, `list_service.rb:14-24`):** GraphQL agent mutations and `ListService#execute` resolve `mcp_servers` IDs via `::Ai::Catalog::McpServer.id_in(server_ids)` without `.in_organization(...)`.

```ruby
// File: ee/app/services/ai/duo_workflows/mcp_config_service.rb (lines 59-63)
        gitlab_mcp_server(denied)
          .merge(orbit_mcp_server)
          .merge(ai_catalog_mcp_servers.except(:orbit)) # BUG 1: Forgot :gitlab! Overwrites gitlab_mcp_server(denied)[:gitlab]
          .merge(slack_mcp_server)

// File: workhorse/internal/ai_assist/duoworkflow/mcp.go (lines 210, 254)
	internal := serverName == "gitlab" || serverName == "orbit"
...
	allToolsAvailable := s.cfg.Tools == nil // BUG 2: Catalog entry has Tools == nil -> allToolsAvailable becomes true!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Disabling All Built-in GitLab AI Tool Restrictions (`withheld_server_tools`) by Attaching a Catalog MCP Server Named `"GitLab"` (`allToolsAvailable = true`):** GitLab Duo Workflow enforces `withheld_server_tools(denied)` on its built-in `:gitlab` MCP server to block dangerous internal operations. Because `McpConfigService#execute` calls `.merge(ai_catalog_mcp_servers.except(:orbit))` without excluding `:gitlab`, an attacker creates an `Ai::Catalog::McpServer` named `"GitLab"` (`server_key => :gitlab`, `Tools: nil`). During any Duo Workflow run, this catalog entry overwrites the built-in `:gitlab` key so Workhorse (`mcp.go:254`) evaluates `allToolsAvailable := s.cfg.Tools == nil` as `true` (`workhorse_all_tools_available: true`), unlocking every prohibited built-in GitLab MCP tool across the instance.
* **Scenario B — Cross-Organization Tenant Boundary Breach via GraphQL `aiCatalogAgentCreate` / `aiCatalogAgentUpdate`:** Because `ListService` and GraphQL agent mutations resolve `mcp_servers` Global IDs (`gid://gitlab/Ai::Catalog::McpServer/<id>`) without `.in_organization`, an attacker in Organization A binds Organization B's private MCP servers to their agent.
* **Scenario C — Breaking All Built-in GitLab Duo Workflow `/api/v4/mcp` Calls (`401 Unauthorized` DoS) via `:gitlab` Header Collision:** When a colliding `"GitLab"` catalog MCP server is attached without an active user connection, `Headers` on `:gitlab` is overwritten with `{}` (stripping `X-Gitlab-Oauth-Token`), causing every built-in GitLab MCP tool call in Duo Workflow to fail with `401 Unauthorized`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect .except(:orbit) in McpConfigService and allToolsAvailable in Workhorse mcp.go
grep -n -C 5 "except(:orbit)" /home/community-user/targets/gitlab/ee/app/services/ai/duo_workflows/mcp_config_service.rb
grep -n -C 5 "allToolsAvailable :=" /home/community-user/targets/gitlab/workhorse/internal/ai_assist/duoworkflow/mcp.go

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report4_cand07
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-04_CAND-07": {
    "GREEN": {
      "builtin_gitlab_overwritten": false,
      "effective_gitlab_url": "http://127.0.0.1/api/v4/mcp",
      "effective_tools_filter": [
        "get_issue",
        "list_commits"
      ],
      "workhorse_all_tools_available": false
    },
    "RED": {
      "builtin_gitlab_overwritten": true,
      "effective_gitlab_url": "https://attacker-controlled-mcp.example/sse",
      "effective_tools_filter": null,
      "workhorse_all_tools_available": true
    },
    "patches": {
      "GITLAB-CAND-07-AGENT-MCP-CROSS-ORG-AND-KEY-COLLISION.patch": "8fc8646b4681d8d558cf25d2adc1c9ccd89363809243f17e9a79134956567f60"
    }
  }
}
```


---

### III.18 — GitLab (`<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)`) — `Projects::Integrations::SlashCommandsController#confirm` Unvalidated `redirect_url` Open Redirect, Unbound `response_url`, and Cross-Project Redis `CACHE_KEY` Collision (`GITLAB-CAND-04`) (`CWE-601 / CWE-863`, CVSS `5.4 Medium`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE: gitlab-ce / gitlab-ee`)
* **Affected Versions & Components:** `<= 19.6.0-pre (verified on live 19.5.1-ce.0 & 19.6.0-pre commit 06cc52e0bc0c1bd96affa9c3bec857ccf754938f)` — `app/controllers/projects/integrations/slash_commands_controller.rb:21-48`, `app/models/concerns/integrations/base/slash_commands.rb:6-10, 68-76`
* **Vulnerability Class & Score:** `CWE-601 / CWE-863` — **CVSS v3.1: `5.4 Medium`** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md`](advisories/ko/18-GITLAB-CAND-04-SLASH-COMMANDS-CONFIRM-OPEN-REDIRECT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unvalidated `redirect_to request_params[:redirect_url]` with `raise_on_open_redirects = false` (`slash_commands_controller.rb:26`, `config/application.rb:63`):** While `SlashCommandsController#show` (line 11) safely computes `@redirect_url = integration_redirect_url`, `#confirm` (line 26) calls `redirect_to request_params[:redirect_url]` directly on the user-controlled parameter. Because `config.action_controller.raise_on_open_redirects = false` is set globally in `config/application.rb:63`, Rails issues a `302 Found` redirect to any arbitrary external `https://` URL.
2. **Step 2 — Unbound `request_params[:response_url]` Passed to `VerifyRequest` (`slash_commands_controller.rb:25`):** Instead of reading `cached_params[:response_url]` from Redis, `#confirm` passes the request parameter `request_params[:response_url]` to `Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!`.
3. **Step 3 — Cross-Project Redis `CACHE_KEY` Lacks `project_id` and `integration_id` (`slash_commands.rb:9, 68-76`):** `CACHE_KEY = "slash-command-requests:%{secret}"` is keyed only by the UUID `command_id`. Any `command_id` minted in Project B is accepted as `valid_request?` on Project A's `/slash_commands/confirm` endpoint.

```ruby
// File: app/controllers/projects/integrations/slash_commands_controller.rb (lines 21-28, 41-48)
      def confirm
        if valid_request? && valid_user?
          # BUG 1: Uses request_params[:response_url] instead of cached_params[:response_url]
          Gitlab::SlashCommands::VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!
          # BUG 2: Redirects to unvalidated request_params[:redirect_url] (raise_on_open_redirects = false)
          redirect_to request_params[:redirect_url]
        else
...
      def cache_key
        @cache_key ||= Kernel.format(
          ::Integrations::Base::SlashCommands::CACHE_KEY, # BUG 3: "slash-command-requests:%{secret}" has no project_id/integration_id!
          secret: request_params[:command_id]
        )
      end
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Credential & 2FA Theft via Trusted GitLab Slash Command Confirmation Redirect (`302 Found` Open Redirect):** A developer clicks a legitimate corporate GitLab slash-command confirmation link (`https://gitlab.company.com/.../slash_commands/confirm?command_id=...&redirect_url=https://evil-gitlab-sso.example/login`) shared in Slack/Mattermost and presses **Confirm**. Because `SlashCommandsController#confirm` calls `redirect_to request_params[:redirect_url]` with `raise_on_open_redirects = false`, GitLab immediately redirects (`302 Found`) the authenticated user from the trusted corporate GitLab domain to the attacker's SSO credential-harvesting page (`open_redirect_triggered: true`).
* **Scenario B — Cross-Project ChatOps Account Binding (`Project B -> Project A`) via Unscoped Redis `CACHE_KEY` Collision:** Because Redis `CACHE_KEY = "slash-command-requests:%{secret}"` omits `project_id` and `integration_id`, an attacker generates a valid `command_id` on an attacker-controlled project (`Project B`) and crafts a `/slash_commands/confirm` link on a target production project (`Project A`). When the victim confirms on `Project A`, GitLab accepts the foreign `command_id` (`cross_project_cache_collision_accepted: true`) and binds the victim's `ChatName` identity to the target project's slash command integration.
* **Scenario C — Hijacking ChatOps Approval Callbacks via Unbound `request_params[:response_url]`:** Instead of using `cached_params[:response_url]` stored in Redis, `#confirm` passes `request_params[:response_url]` directly into `VerifyRequest.new(integration, chat_user, request_params[:response_url]).approve!`, allowing an attacker to redirect the ChatOps confirmation webhook payload to their own server.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect confirm and cache_key in Projects::Integrations::SlashCommandsController
sed -n '10,48p' \
  /home/community-user/targets/gitlab/app/controllers/projects/integrations/slash_commands_controller.rb

# 2. Run the 3-Layer Real-World Impact (RED -> GREEN) E2E Verification Harness
python3 -m unittest pre-submission-verification-20261026/tests/test_gitlab_real_world_impact_e2e.py -k test_report5_cand04
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "REPORT-05_CAND-04": {
    "GREEN": {
      "cross_project_cache_collision_accepted": false,
      "http_status": 404,
      "location_header": "",
      "open_redirect_triggered": false
    },
    "RED": {
      "cross_project_cache_collision_accepted": true,
      "http_status": 302,
      "location_header": "https://evil-phishing.example/oauth/callback?steal=1",
      "open_redirect_triggered": true
    }
  }
}
```


---

### III.19 — GitLab (`<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)`) — `[UPSTREAM DUPLICATE: CVE-2026-40295 — NOT SUBMITTED TO MITRE]` `Gitlab::DeviseFailure#redirect_url` External `Referer` Open Redirect Product Impact (`CVE-2026-40295`) & Dynamic OAuth PKCE Defense-in-Depth (`GITLAB-CAND-03`) (`CWE-601 / CWE-345`, CVSS `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`)

> **Upstream CVE Duplicate Disclosure:** This entry documents the product-level manifestation of upstream `Devise 5.0.3` (`CVE-2026-40295`) and the `CAND-03` PKCE defense-in-depth patch. It is published on GitHub for transparency and was **not submitted to MITRE CNA-LR**.

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `gitlab-org/gitlab` (`RubyGems / GitLab CE & EE (Devise 5.0.3): gitlab-ce / gitlab-ee (devise 5.0.3)`)
* **Affected Versions & Components:** `<= 19.6.0-pre (Devise 5.0.3 CVE-2026-40295 upstream dependency & Oauth::AuthorizationsController defense-in-depth)` — `lib/gitlab/devise_failure.rb:4-18`, `lib/gitlab/auth/session_expire_from_init_enforcer.rb:44-62`, `app/controllers/oauth/authorizations_controller.rb:316-330`
* **Vulnerability Class & Score:** `CWE-601 / CWE-345` — **CVSS v3.1: `5.4 Medium (Upstream CVE-2026-40295 Duplicate)`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md`](advisories/ko/19-GITLAB-DEVISE-CVE-2026-40295-DUPLICATE-AND-PKCE-DEFENSE.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Important Duplicate & Non-Submission Disclosure:** During our pre-submission duplicate and runtime verification gate, we identified that the `Gitlab::DeviseFailure#redirect_url` open redirect is the product-level manifestation of upstream **Devise `5.0.3` `CVE-2026-40295`**, and that `GITLAB-CAND-03` (`validate_pkce_for_dynamic_applications`) is mitigated at runtime by `Doorkeeper 5.9.3` (`pkce_code_challenge_methods ['S256']` at `config/initializers/doorkeeper.rb:158`). Therefore, **this advisory is published on GitHub for full engineering transparency and remediation, and was deliberately NOT submitted to MITRE for a duplicate CVE ID**.
2. **Step 1 — How Upstream `CVE-2026-40295` (`Devise 5.0.3`) Manifests in `Gitlab::DeviseFailure` (`lib/gitlab/devise_failure.rb:4-18`):** When `warden_message == :timeout` occurs on a non-`GET` request (such as a cross-site `POST` when `session_expire_from_init` is active in `SessionExpireFromInitEnforcer#enforce!`), `Devise::FailureApp#redirect_url` returns `request.referrer` directly without stripping the external host (`extract_path_from_location(request.referrer)`).
3. **Step 2 — Controller-Layer PKCE Guard Logic Flaw in `Oauth::AuthorizationsController#validate_pkce_for_dynamic_applications` (`authorizations_controller.rb:326`, `GITLAB-CAND-03`):** Line 326 writes `return unless code_challenge_method.present? && code_challenge_method != 'S256'`, which returns early when `code_challenge_method` is omitted (`nil`). While `Doorkeeper 5.9.3` blocks `nil` during `PreAuthorization`, replacing the guard with `return if code_challenge_method == 'S256'` provides defense-in-depth at the controller layer.

```ruby
// File: lib/gitlab/devise_failure.rb (lines 4-18) — Upstream Devise 5.0.3 CVE-2026-40295 Remediation
module Gitlab
  class DeviseFailure < Devise::FailureApp
    # Inherits Devise::FailureApp#redirect_url which returns raw request.referrer on non-GET :timeout
    # Remediated by overriding redirect_url to apply extract_path_from_location(request.referrer)
  end
end

// File: app/controllers/oauth/authorizations_controller.rb (lines 323-329) — GITLAB-CAND-03 Defense-in-Depth
    code_challenge_method = permitted_params[:code_challenge_method]
    return unless code_challenge_method.present? && code_challenge_method != 'S256' # Early return when nil!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Non-GET Session Timeout Redirects to External `Referer` (`CVE-2026-40295` Duplicate):** When a user's session times out (`warden_message == :timeout`) on a non-`GET` request with an external `Referer: https://attacker.example/login`, unpatched `Devise 5.0.3` redirects (`302`) to the external `Referer` instead of extracting only the relative path.
* **Scenario B — Product-Level Remediation in `Gitlab::DeviseFailure#redirect_url` Without Waiting for Gem Upgrade:** Overriding `redirect_url` in `lib/gitlab/devise_failure.rb` to call `extract_path_from_location(request.referrer)` neutralizes `CVE-2026-40295` immediately at the application layer.
* **Scenario C — Controller-Layer PKCE Enforcement (`GITLAB-CAND-03` Defense-in-Depth):** Changing `return unless code_challenge_method.present? && code_challenge_method != 'S256'` to `return if code_challenge_method == 'S256'` ensures dynamic OAuth apps cannot bypass the controller's `before_action` even if Doorkeeper configuration changes in the future.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect Gitlab::DeviseFailure and AuthorizationsController#validate_pkce_for_dynamic_applications
sed -n '1,20p' /home/community-user/targets/gitlab/lib/gitlab/devise_failure.rb
sed -n '316,330p' /home/community-user/targets/gitlab/app/controllers/oauth/authorizations_controller.rb
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "GITLAB-DEVISE-CVE-2026-40295-REM_AND_CAND-03": {
    "upstream_cve_duplicate_status": "Duplicate of upstream Devise 5.0.3 CVE-2026-40295 (Not submitted to MITRE CNA-LR)",
    "RED": {
      "external_referer_redirect_on_non_get_timeout": true
    },
    "GREEN": {
      "external_referer_redirect_on_non_get_timeout": false,
      "path_extracted_only": true
    }
  }
}
```

<!-- GITLAB-ADVISORIES-END -->

<!-- CHIA-ADVISORIES-START -->

---

### III.20 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Light Wallet Sync Unverified `FoliageTransactionBlock` Swap Allowing Zero-Capital Counterfeit Confirmed XCH Deposits (`WLC-01`) (`CWE-345 / CWE-347`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:926-995` (`_add_block_from_header`)
* **Vulnerability Class & Score:** `CWE-345 / CWE-347` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md`](advisories/ko/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Header-Body Cryptographic Binding Omission (`chia/wallet/wallet_node.py:926-995`):** In Chia's block structure, the signed `HeaderBlock.foliage` commits to the transaction payload via the 32-byte SHA-256 digest `header_block.foliage.foliage_transaction_block_hash`. However, when `WalletNode._add_block_from_header` ingests a `RespondBlockHeader` message from a P2P peer, it reads `header_block.foliage_transaction_block` and extracts coin additions without verifying `header_block.foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash`.
2. **Step 2 — Zero-Capital (`0 XCH`) Counterfeit Coin Injection Into SQLite `WalletCoinStore`:** Because the header itself is a real canonical header from the blockchain, header-level checks pass. An attacker with `0 XCH` capital swaps `foliage_transaction_block` with a fabricated payload crediting the merchant's puzzle hash (`+0.5 XCH` = `500,000,000,000 mojo` or `+1,000 XCH`). The victim wallet inserts the counterfeit coin into `WalletCoinStore` as a confirmed on-chain balance that persists across wallet restarts.
3. **Step 3 — Post-Settlement Spend Failure (`Err.UNKNOWN_UNSPENT`):** Once the merchant releases goods, USDT, or BTC in exchange for the displayed confirmed XCH deposit and later attempts to sweep or spend the credited coin, `FullNode` mempool validation rejects the transaction with `Err.UNKNOWN_UNSPENT` because the coin never existed on the canonical blockchain.

```python
# File: chia/wallet/wallet_node.py (lines 926-995)
async def _add_block_from_header(self, header_block: HeaderBlock, ...):
    # BUG: Missing cryptographic binding check between signed header and transaction block body:
    # if header_block.foliage_transaction_block is not None:
    #     if header_block.foliage_transaction_block.get_hash() != header_block.foliage.foliage_transaction_block_hash:
    #         raise ValueError("Invalid foliage_transaction_block_hash")
    additions, removals = await self.get_additions_and_removals(header_block, ...)
    await self.wallet_state_manager.add_block(...)
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Zero-Capital (`0 XCH`) Fake Deposit to an OTC Desk, Payment Gateway, or Merchant to Cash Out Real USDT/BTC:** Unlike a traditional 51%/reorg double-spend (which requires purchasing real XCH and mining a competing fork), an attacker with `0 XCH` capital connects to a merchant or OTC desk running a Chia Light Wallet and sends a `RespondBlockHeader` containing a genuine block header paired with a swapped `foliage_transaction_block`. The merchant's wallet immediately displays a confirmed `+0.5 XCH` (`500,000,000,000 mojo`) or `+1,000 XCH` deposit without requiring any counterparty approval. The attacker collects the real USDT/BTC payout and leaves before the merchant discovers the coin fails on-chain with `Err.UNKNOWN_UNSPENT`.
* **Scenario B — Automated E-Commerce & Cross-Chain Relayer Poisoning Across SQLite Restarts:** Because `_add_block_from_header` commits the counterfeit `CoinState` directly into SQLite `WalletCoinStore`, cold-reloading the wallet database (`reopened_sqlite_coin_present: true`) continues to report the phantom balance as confirmed, tricking automated order-fulfillment bots into shipping digital goods or gift cards.
* **Scenario C — Combined Chain (`CONS-SP-01` Full-Node Sync Lockout + `WLC-01` Light-Wallet Fake Deposit):** An attacker first stalls a merchant's primary FullNode on port `8444` via `CONS-SP-01` so the operator switches or falls back to light-wallet P2P header sync, and immediately injects the swapped `foliage_transaction_block` payload to credit counterfeit XCH.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect _add_block_from_header in chia/wallet/wallet_node.py
sed -n '926,995p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the RED -> GREEN End-to-End Verification Harness for WLC-01
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-01": {
    "RED": {
      "attacker_initial_xch_capital_mojo": 0,
      "accepted_swapped_foliage_transaction_block": true,
      "fake_merchant_deposit_increase_mojo": 500000000000,
      "reopened_sqlite_coin_present": true,
      "subsequent_spend_mempool_error": "Err.UNKNOWN_UNSPENT"
    },
    "GREEN": {
      "accepted_swapped_foliage_transaction_block": false,
      "fake_merchant_deposit_increase_mojo": 0,
      "reopened_sqlite_coin_present": false,
      "rejection_error": "ValueError: Invalid foliage_transaction_block_hash"
    }
  }
}
```


---

### III.21 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Wallet Unauthenticated `RespondRemovals` / `RespondCoinState` Phantom Spent-Height Poisoning & Timelock Clawback Cancellation Lockout (`WLC-02`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/wallet/wallet_node.py:725-777`, `chia/wallet/wallet_state_manager.py:1735-1778`
* **Vulnerability Class & Score:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md`](advisories/ko/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unverified `RespondRemovals(..., proofs=None)` & `spent_height` Acceptance (`wallet_node.py:725-777` & `wallet_state_manager.py:1735-1778`):** When a wallet synchronizes coin removals or receives a `RespondRemovals` message with `proofs=None` (or an unverified `CoinState` with `spent_height` set), `_add_coin_states` updates the coin's `spent_height` in SQLite `WalletCoinStore` without verifying a Merkle removal proof against a validated peak header.
2. **Step 2 — Persistent SQLite Lockout of Clawback Cancellation (`t1_cold_reloaded_sqlite_spent: true`):** Even after a cold SQLite reload (`WalletCoinStore`), the unspent Clawback coin (`0.5 XCH` = `500,000,000,000 mojo`, coin ID `e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649`) remains marked as `spent_height=8`. When the sender tries to cancel/claw back the transfer during the timelock window, `spend_clawback_coins` generates `0` transactions (`t2_sender_cancel_tx_count: 0`).
3. **Step 3 — Attacker Claims Real On-Chain Funds After Timelock Expiry (`SpendBundle SHA-256: 33361e6b2d8ee0d9...`):** Because the coin was never actually spent on-chain, the moment the Clawback timelock expires (`t4`), the attacker broadcasts a valid `SpendBundle` (`930 bytes`) and sweeps the real `0.5 XCH` on-chain.

```python
# File: chia/wallet/wallet_node.py (lines 725-777) & wallet_state_manager.py (lines 1735-1778)
# BUG: Accepts RespondRemovals with proofs=None or unverified spent_height without Merkle proof verification
if not validate_removals(coin_Main, proofs, peak_header):
    # Missing fail-closed rejection before updating WalletCoinStore spent_height!
await self.coin_store.set_spent(coin_name, spent_height)
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Blocking 24-Hour Clawback Cancellation Until Timelock Expiry to Steal `0.5 XCH` (`500,000,000,000 mojo`):** A sender transfers `0.5 XCH` protected by a Clawback timelock (`coin_id: e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649`). The attacker poisons the sender's wallet with `RespondRemovals(height=8, coins=[(coin_name, None)], proofs=None)`. Throughout the timelock window, the sender's Clawback cancellation button fails (`tx_count: 0`), and once the timelock expires, the attacker claims the real on-chain `0.5 XCH` (`SpendBundle SHA-256: 33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1`).
* **Scenario B — Unified Timeline Chain (`WLC-02` + `VR-01 / POC-10` — Blocking Both Wallet GUI Recovery and Emergency `chia-vault-recover` CLI):** On a single continuous timeline (`t0..t4`), the attacker simultaneously poisons the victim's live wallet state via `WLC-02` (`t1_cold_reloaded_sqlite_spent: true`) and sends a 1-mojo decoy launcher coin (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`) to break the victim's fallback `chia-vault-recover` CLI (`t3_poc10_matches_victim: false`), neutralizing both recovery paths until the timelock expires.
* **Scenario C — Custodial Hot-Wallet & DeFi Liquidation Bot UTXO Freeze:** Poisoning unspent UTXOs as `spent_height != None` in SQLite prevents automated market makers and custodial payout nodes from selecting those coins until a full resync is performed.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect removal validation in chia/wallet/wallet_node.py and wallet_state_manager.py
sed -n '725,777p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the Unified Timeline (t0..t4) & SQLite Cold-Reload Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLC-02": {
    "RED": {
      "clawback_coin_id": "e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649",
      "clawback_amount_mojo": 500000000000,
      "t1_cold_reloaded_sqlite_spent": true,
      "t2_sender_cancel_tx_count": 0,
      "t3_poc10_matches_victim": false,
      "t4_recipient_claim_spend_bundle_sha256": "33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1",
      "t4_recipient_claim_bytes": 930
    },
    "GREEN": {
      "t1_cold_reloaded_sqlite_spent": false,
      "t2_sender_cancel_tx_count": 1,
      "t3_poc10_matches_victim": true,
      "sender_clawback_cancel_succeeded": true
    }
  }
}
```


---

### III.22 — Chia-Network/chia-blockchain-gui (`<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)`) — Chia Desktop GUI WalletConnect Unscoped 29-Command Grant & Concurrent Confirmation Modal Overwrite TOCTOU (`GUI-WC-01`) (`CWE-367 / CWE-285`, CVSS `8.8 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain-gui` (`npm / TypeScript (Electron Desktop GUI): chia-blockchain-gui`)
* **Affected Versions & Components:** `<= 2.6.1-rc2.dev60 (verified on commit 2f6ee83a23ac8b0370b96111e02f8edfb81fa1f3)` — `packages/gui/src/components/walletConnect/WalletConnectContext.tsx:314-441`, `constants/WalletConnectCommands.ts`
* **Vulnerability Class & Score:** `CWE-367 / CWE-285` — **CVSS v3.1: `8.8 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md`](advisories/ko/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — All 29 WalletConnect Commands Exposed Upon Pairing (`constants/WalletConnectCommands.ts`):** When a user connects their Chia desktop wallet to any website/dApp (even one claiming to only check an address or NFT eligibility), the WalletConnect session namespace grants access to all 29 RPC commands, including `chia_sendTransaction`, `chia_spendCAT`, and `chia_takeOffer`.
2. **Step 2 — Concurrent Request Modal Overwrite (`WalletConnectContext.tsx:314-441`):** `handleSessionRequest` does not serialize incoming JSON-RPC requests with a FIFO lock. When a malicious dApp sends a benign `chia_getCurrentAddress` request followed milliseconds later by `chia_sendTransaction`, the confirmation state/promise overlaps so that clicking Approve on the benign prompt dispatches `chia_sendTransaction` (`0.5 XCH` signed `SpendBundle SHA-256: d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`).
3. **Step 3 — Post-Approval Context Switch (`TOCTOU` on Fingerprint, Network, and Pairing):** Between the moment the user clicks Approve (`check`) and `sendCommand` execution (`use`), `WalletConnectContext.tsx` does not verify that the active key fingerprint, network (`mainnet`/`testnet`), and pairing session still match the approved snapshot.

```typescript
// File: packages/gui/src/components/walletConnect/WalletConnectContext.tsx (lines 314-441)
async function handleSessionRequest(event: SignClientTypes.EventArguments['session_request']) {
  // BUG 1: No FIFO mutex/queue serializing concurrent session_request events
  // BUG 2: No immutable binding of (requestId, method, paramsHash, fingerprint, network) in sendCommand
  const confirmed = await showConfirmationDialog(event);
  if (confirmed) {
    return await sendCommand(command, params);
  }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 'Free Chia Airdrop / Address Checker' Website Drains Wallet Behind a `getCurrentAddress` Prompt:** A victim connects their desktop wallet to a dApp and sees a harmless `chia_getCurrentAddress` modal. In the same millisecond, the dApp sends `chia_sendTransaction` (`500,000,000,000 mojo` = `0.5 XCH`). When the victim clicks Confirm, `WalletRpcClient.send_transaction` executes and broadcasts signed `SpendBundle` `d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`.
* **Scenario B — Burner-Wallet to Cold/Main-Wallet Fingerprint Switch (`TOCTOU`):** A user pairs a 0-XCH burner key (`fingerprint: 111111`), but a concurrent fingerprint/context switch causes `sendCommand` to execute the spend against the user's `999999` main wallet.
* **Scenario C — Post-Disconnect Replay During Pending Confirmation:** Even if the user disconnects the pairing or switches networks while a confirmation promise is in flight, unpatched `sendCommand` still dispatches the RPC call (`GREEN` blocks all 3 vectors: `concurrent_rejected`, `context_switch_rejected`, `unknown_method_rejected`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect handleSessionRequest and sendCommand in WalletConnectContext.tsx
sed -n '314,441p' /home/community-user/targets/chia-blockchain-gui/packages/gui/src/components/walletConnect/WalletConnectContext.tsx

# 2. Run the Live WSS Relay -> GUI Handler -> WalletRpcClient E2E Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-GUI-WC-01": {
    "RED": {
      "displayed_prompt_method": "chia_getCurrentAddress",
      "concurrent_injected_method": "chia_sendTransaction",
      "modal_overwritten_by_second_request": true,
      "unauthorized_send_transaction_dispatched": true,
      "drained_amount_mojo": 500000000000,
      "signed_spend_bundle_sha256": "d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980"
    },
    "GREEN": {
      "distinct_wss_packets_tested": 6,
      "benign_get_current_address_succeeded": true,
      "benign_send_transaction_succeeded": true,
      "concurrent_modal_overwrite_rejected": true,
      "fingerprint_network_pairing_switch_rejected": true,
      "unknown_method_rejected": true
    }
  }
}
```


---

### III.23 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer `WalletRpcApi.dl_verify_proof` Missing Singleton Lineage Verification Allowing 1-Mojo Counterfeit Proofs & Unbacked `100,000 CAT` On-Chain Minting (`DL-01`) (`CWE-347 / CWE-345`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py:4066-4120` (`dl_verify_proof`), `chia/data_layer/data_layer_util.py`
* **Vulnerability Class & Score:** `CWE-347 / CWE-345` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md`](advisories/ko/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Singleton Top-Layer & Launcher Lineage Check in `WalletRpcApi.dl_verify_proof` (`chia/rpc/wallet_rpc_api.py:4066-4120`):** When verifying a `DLProof` (`ProofOfInclusion`), `dl_verify_proof` confirms that the referenced coin (`coin_id`) was spent on-chain and that its inner puzzle announcement matches the Merkle root of the key/value pairs, plus checks `dl_wallet.get_latest_singleton(store_id)` for existence. However, it **never calls `match_dl_singleton`** on the proof's parent coin spend to verify that the coin is actually the canonical DataLayer singleton for `store_id`!
2. **Step 2 — 1-Mojo Non-Singleton Coin Forges Any Official `store_id` Root:** An attacker spends a 1-mojo standard non-singleton coin (`coin_id: 86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17`) whose puzzle emits the announcement format expected by `dl_verify_proof` while referencing the victim institution's `store_id` (`806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6`). `WalletRpcApi.dl_verify_proof` returns `{"verified": true, "verified_clvm_hashes": true, "current_root": true}`.
3. **Step 3 — End-to-End On-Chain Minting of `100,000 CAT` (`100,000,000 CAT mojo`):** When a bridge, RWA issuer, or carbon-credit minter gates token issuance on `WalletRpcApi.dl_verify_proof`, the forged 1-mojo proof triggers a real `CATWallet` issuance (`cat_asset_id: 73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5`, `issuance SpendBundle SHA-256: 6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e`, `delivery SpendBundle SHA-256: dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`), crediting the attacker with `100,000 CAT` on-chain.

```python
# File: chia/rpc/wallet_rpc_api.py (lines 4066-4120)
async def dl_verify_proof(self, request: dict[str, Any]) -> EndpointResult:
    proof = DLProof.from_json_dict(request)
    verified_clvm_hashes = dl_verify_proof(proof)
    # BUG: Verifies coin existence and Merkle hash, but NEVER verifies that the parent coin spend
    # matches SINGLETON_TOP_LAYER_MOD with launcher_id == proof.store_proofs.store_id!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 1-Mojo Counterfeit DataLayer Reserve Proof Mints `100,000 CAT` (`100,000,000 CAT mojo`) On-Chain:** An institutional RWA/stablecoin bridge tracks collateralized minting approvals in DataLayer store `806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6` (backed by `1,000 XCH` collateral). The attacker spends a 1-mojo non-singleton coin (`86ec0dd71fbc7e41...`) announcing `mint_allowance=100000000` and submits the `DLProof` to `WalletRpcApi.dl_verify_proof`. Because `dl_verify_proof` returns `verified: true, current_root: true`, the bridge mints and delivers `100,000 CAT` on-chain (`SpendBundle` `dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`).
* **Scenario B — Side-by-Side Intrinsic RPC Forgery Against Any Third-Party Verifier (`test_dl01_side_by_side_canonical_vs_counterfeit_dl_verify_proof`):** Even without a bridge consumer, calling `WalletRpcApi.dl_verify_proof` directly with a canonical singleton proof vs. a 1-mojo non-singleton counterfeit proof returns identical `verified: true` responses in `RED`, proving the defect is intrinsic to Chia's RPC verifier.
* **Scenario C — Counterfeit Carbon-Credit / Registry Audit Attestations:** An attacker forges retirement or issuance records against an official climate registry's `store_id` using a 1-mojo coin spend.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect WalletRpcApi.dl_verify_proof in chia/rpc/wallet_rpc_api.py
sed -n '4066,4120p' /home/community-user/targets/chia-blockchain/chia/rpc/wallet_rpc_api.py

# 2. Run both the Intrinsic Side-by-Side RPC Test and the 100,000 CAT On-Chain Mint Test (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-DL-01": {
    "RED": {
      "victim_store_id": "806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6",
      "forged_non_singleton_coin_id": "86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17",
      "dl_verify_proof_verified": true,
      "dl_verify_proof_current_root": true,
      "cat_asset_id": "73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5",
      "cat_issuance_spend_bundle_sha256": "6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e",
      "cat_delivery_spend_bundle_sha256": "dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196",
      "attacker_minted_cat_mojo": 100000000,
      "attacker_minted_cat_tokens": 100000
    },
    "GREEN": {
      "canonical_singleton_proof_verified": true,
      "counterfeit_non_singleton_proof_verified": false,
      "attacker_minted_cat_mojo": 0
    }
  }
}
```


---

### III.24 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Permissive `Condition::Other` Bypass Allowing Hidden `750 XCH` Fee Drain & NFT Transfer-Program Spoofing (`CS-01` / `POC-1 & POC-2`) (`CWE-451 / CWE-345`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-driver/src/clear_signing/tests.rs`
* **Vulnerability Class & Score:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md`](advisories/ko/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Parser Divergence Between Consensus CLVM (`chia_rs`) and `cni-wallet-sdk` (`clear_signing.rs`):** Chia's consensus CLVM engine ignores extra trailing arguments on condition opcodes such as `RESERVE_FEE` (`(52 amount extra_atom)`), executing the full fee reservation on-chain. However, `cni-wallet-sdk` parses conditions using strict fixed-arity structs and silently wraps any condition with trailing atoms into `Condition::Other(NodePtr)` instead of rejecting it.
2. **Step 2 — Hidden `750 XCH` (`750,000,000,000,000 mojo`) Fee Drain (`POC-1`):** In `SpendBundle` `b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c` (`1,105 bytes`), a vault spend emits an overlong `RESERVE_FEE` condition for `750 XCH`. Unpatched Clear-Signing ignores `Condition::Other` and displays `reserved_fee: 0` to the hardware/mobile signer while consensus consumes `750 XCH`.
3. **Step 3 — Unvalidated NFT `-24` Transfer-Program / Metadata State Mutation (`POC-2`):** Similarly, non-canonical or uninspected NFT state conditions in `SpendBundle` `17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128` (`3,274 bytes`) alter NFT control on-chain while being omitted from the Clear-Signing summary.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Condition::Other(_) variants (such as overlong RESERVE_FEE opcode 52 or unparsed NFT opcodes)
// are silently ignored instead of returning Error::UnsupportedCondition / failing closed:
match condition {
    Condition::ReserveFee(fee) => reserved_fee += fee.amount,
    Condition::Other(_) => { /* silently ignored in unpatched RED! */ }
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Draining `750 XCH` (`750,000,000,000,000 mojo`) from an Enterprise Vault via Hidden `RESERVE_FEE` (`POC-1`):** An attacker proposes a routine Vault transaction (`SpendBundle SHA-256: b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c`). The Clear-Signing screen on the signer's device reports `reserved_fee = 0`, inducing the custodian to sign; when broadcast, `750 XCH` is drained as block fee (`consensus_reserved_fee_mojo: 750000000000000`).
* **Scenario B — Silent NFT Ownership / Transfer-Program Hijack (`POC-2`):** A collector signs an NFT transaction (`SpendBundle SHA-256: 17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128`) whose Clear-Signing preview shows a benign update while the unparsed condition mutates the NFT state on-chain.
* **Scenario C — Colluding Pool / Farmer Fee Extraction:** An attacker partners with a farmer or mempool relayer to capture the hidden `750 XCH` fee output immediately upon block inclusion.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Clear-Signing Rust Proof Suite in cni-wallet-sdk (POC-1 & POC-2)
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc1_and_poc2 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-01": {
    "RED": {
      "poc1_spend_bundle_sha256": "b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c",
      "poc1_spend_bundle_bytes": 1105,
      "poc1_clear_signing_displayed_fee_mojo": 0,
      "poc1_consensus_drained_fee_mojo": 750000000000000,
      "poc2_spend_bundle_sha256": "17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128",
      "poc2_spend_bundle_bytes": 3274
    },
    "GREEN": {
      "poc1_rejected_fail_closed": true,
      "poc2_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.25 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Uninspected NFT `NEW_METADATA_INFO` Updater Conditions Allowing Hidden `500 XCH` Drain (`CS-02` / `POC-3`) (`CWE-451 / CWE-345`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (`NEW_METADATA_INFO` evaluation)
* **Vulnerability Class & Score:** `CWE-451 / CWE-345` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md`](advisories/ko/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — NFT State Layer Executes Conditions Returned by the Metadata Updater Program:** Under Chia's CHIP-0007 NFT standard, when an inner spend emits a `NEW_METADATA_INFO` (`-24`) condition, the NFT state layer executes the metadata updater puzzle and merges any returned conditions into the spend's output conditions.
2. **Step 2 — Clear-Signing Discards Additional Conditions Emitted by the Metadata Updater (`clear_signing.rs`):** While `cni-wallet-sdk` evaluates the metadata updater to inspect updated metadata, it discards additional consensus conditions (such as `RESERVE_FEE` for `500 XCH` = `500,000,000,000,000 mojo`) returned by the updater program.
3. **Step 3 — `500 XCH` Drained Behind a '0 Fee' NFT Update Preview (`SpendBundle SHA-256: b314b6d7411bfb8a...`):** In `SpendBundle` `b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6` (`3,300 bytes`), the user sees `reserved_fee = 0` on the Clear-Signing screen while consensus drains `500 XCH`.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Evaluates NEW_METADATA_INFO metadata updater program for metadata diff,
// but ignores extra consensus conditions (e.g. RESERVE_FEE 500 XCH) returned by the updater!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 'Free NFT Metadata Reveal' Transaction Drains `500 XCH` (`500,000,000,000,000 mojo`):** A user signs an NFT reveal/update bundle (`b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6`) displaying `reserved_fee = 0` in Clear-Signing, losing `500 XCH` to consensus fees upon broadcast.
* **Scenario B — Malicious Custom Metadata Updater in Traded NFTs:** An attacker mints an NFT with a custom metadata updater puzzle and sells/transfers it to a vault; when the vault later updates or transfers the NFT, the hidden updater condition triggers.
* **Scenario C — Patched Verification (`GREEN`):** The patched driver rejects any metadata updater output emitting unexpected consensus conditions.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-3 (500 XCH NFT Metadata Updater Hidden Fee) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc3 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-02": {
    "RED": {
      "poc3_spend_bundle_sha256": "b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6",
      "poc3_spend_bundle_bytes": 3300,
      "clear_signing_displayed_fee_mojo": 0,
      "consensus_drained_fee_mojo": 500000000000000
    },
    "GREEN": {
      "poc3_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.26 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Dependent Offer Leg Set-Intersection Outflow Omission Hiding `500 XCH` Payment (`CS-03` / `POC-4`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (dependent offer leg aggregation)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md`](advisories/ko/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Set-Intersection Filtering Across Dependent Settlement Legs (`clear_signing.rs`):** When a Vault transaction participates in a multi-leg Offer settlement (`POC-4`), `cni-wallet-sdk` correlates notarized payments across legs using set intersection rather than union/full conservation.
2. **Step 2 — Non-Overlapping `500 XCH` (`500,000,000,000,000 mojo`) Outflow Dropped from Signing Preview:** In `POC-4` (vault spend `3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`, settlement spend `7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`), the secondary `500 XCH` payment leg to the attacker is excluded by the set intersection check and never shown in the Clear-Signing summary.
3. **Step 3 — Full `500 XCH` Outflow Executes On-Chain:** Once signed, both settlement legs execute on-chain and transfer `500 XCH` to the attacker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Uses set intersection across dependent settlement legs instead of accounting for every
// notarized payment outflow funded by the vault's settlement coins!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hidden `500 XCH` (`500,000,000,000,000 mojo`) Leg in a P2P Offer (`POC-4`):** A trader accepts a multi-leg Offer (`vault SpendBundle: 3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`) whose Clear-Signing preview omits the `500 XCH` settlement leg (`7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`).
* **Scenario B — OTC Treasury Swap Drain:** An institutional treasury signs what appears to be a small fee/test swap while a disjoint `500 XCH` settlement leg drains treasury funds.
* **Scenario C — Patched Verification (`GREEN`):** All settlement payment legs funded by the vault are unioned and strictly validated.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-4 (500 XCH Dependent Offer Leg Set-Intersection Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc4 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-03": {
    "RED": {
      "poc4_vault_spend_bundle_sha256": "3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8",
      "poc4_settlement_spend_bundle_sha256": "7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525",
      "omitted_outflow_mojo": 500000000000000
    },
    "GREEN": {
      "poc4_rejected_or_fully_accounted": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.27 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Unrevealed Settlement Spend Blind Spot Allowing Post-Signature `600 XCH` Drain (`CS-04` / `POC-5`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (unrevealed settlement output handling)
* **Vulnerability Class & Score:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md`](advisories/ko/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Settlement Coins Require No Signature to Spend Once Created:** Any coin created at `SETTLEMENT_PAYMENT_HASH` can be spent by anyone who supplies a matching notarized payment solution (unless constrained by a signed announcement in the parent vault spend).
2. **Step 2 — Clear-Signing Accepts Bundles Where the Created Settlement Coin Is Left Unspent (`clear_signing.rs`):** In `POC-5`, the signing bundle (`a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`, `1,303 bytes`) creates a `600 XCH` (`600,000,000,000,000 mojo`) settlement coin without including its spend in the preview bundle. Unpatched Clear-Signing does not report an external outflow.
3. **Step 3 — Attacker Attaches the Settlement Spend (`e0b876fbb8e0f264...`) Post-Signing:** After the victim signs the vault spend, the attacker appends the `600 XCH` settlement spend (`388 bytes`) and broadcasts the combined bundle on-chain.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Allows a vault spend to create a SETTLEMENT_PAYMENT_HASH coin without requiring
// the corresponding settlement CoinSpend to be revealed and verified in the signing bundle!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Post-Signing Attachment of an Unrevealed `600 XCH` (`600,000,000,000,000 mojo`) Settlement Spend (`POC-5`):** The victim reviews and signs vault bundle `a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`; the attacker attaches `e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe` and sweeps `600 XCH`.
* **Scenario B — Hardware Wallet Blind Signing via Deferred Settlement Reveal:** Air-gapped hardware signers see zero external recipients during review while signing away `600 XCH` into an unrevealed settlement coin.
* **Scenario C — Patched Verification (`GREEN`):** Any unspent/unrevealed settlement output in a Clear-Signing bundle is rejected fail-closed.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-5 (600 XCH Unrevealed Settlement Spend Blind Spot) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc5 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-04": {
    "RED": {
      "poc5_vault_spend_bundle_sha256": "a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb",
      "poc5_vault_spend_bundle_bytes": 1303,
      "poc5_attached_settlement_spend_bundle_sha256": "e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe",
      "poc5_attached_settlement_bytes": 388,
      "hidden_outflow_mojo": 600000000000000
    },
    "GREEN": {
      "poc5_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.28 — Chia-Network/cni-wallet-sdk (`chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing External `DropCoin` Vault Change Spoofing Hiding `1,000 XCH` Vault Drain Across the `chia-sdk-bindings` FFI Boundary (`CS-05` / `POC-6`) (`CWE-682 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (`chia-sdk-driver` & `chia-sdk-bindings` FFI): chia-sdk-bindings`)
* **Affected Versions & Components:** `chia-sdk-bindings <= 0.38.0 / chia-sdk-driver <= 0.36.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs`, `crates/chia-sdk-bindings/src/clear_signing.rs:62` (`parse_vault_transaction`)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md`](advisories/ko/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — External `DropCoin` Output Credited as Vault Change (`clear_signing.rs` & `chia-sdk-bindings/src/clear_signing.rs:62`):** When `parse_vault_transaction` computes the net outflow of a Vault transaction, it credits outputs sent to the vault's puzzle hash as vault change without verifying that the parent coin creating that output actually belonged to the vault (`DropCoin` parent lineage).
2. **Step 2 — Masking a `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Drain (`SpendBundle SHA-256: aa65182292515596...`):** In `POC-6` (`1,477 bytes`), the victim's vault sends `1,000 XCH` to the attacker while an external `DropCoin` spend included in the bundle creates a `1,000 XCH` output to the vault's puzzle hash. Unpatched Clear-Signing nets the two against each other and reports `0 XCH` net vault loss!
3. **Step 3 — Verified Directly Across the Production `chia-sdk-bindings` FFI Entrypoint (`clear_signing_ffi_proof.rs`):** Calling `chia_sdk_bindings::parse_vault_transaction` directly confirms the FFI boundary misreports the `1,000 XCH` drain in `RED` and returns `Error::NonStandardInnerSpend` in `GREEN`.

```rust
// File: crates/chia-sdk-bindings/src/clear_signing.rs (line 62) & chia-sdk-driver/src/clear_signing.rs
pub fn parse_vault_transaction(vault: ClvmVault, spend_bundle: SpendBundle, ...) -> Result<TransactionSummary> {
    // BUG: Credits outputs from external non-vault DropCoin spends as vault change,
    // masking a 1,000 XCH outflow from the victim's vault!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Enterprise Vault Drain Displayed as Zero Net Outflow at the FFI Boundary (`POC-6`):** An institutional custodian reviews `SpendBundle` `aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e` (`1,477 bytes`) via a mobile/hardware signer powered by `chia-sdk-bindings` and sees `0 XCH` net vault outflow while signing away `1,000 XCH`.
* **Scenario B — Multi-Sig Quorum Deception:** Multiple hardware cosigners independently verify the same FFI `TransactionSummary` and approve the `1,000 XCH` theft.
* **Scenario C — FFI Boundary Patch Verification (`GREEN`):** `clear_signing_ffi_proof.rs` verifies `parse_vault_transaction` rejects the spoofed `DropCoin` bundle with `Error::NonStandardInnerSpend`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-6 in chia-sdk-driver and the FFI Boundary Proof in chia-sdk-bindings
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc6 -- --nocapture
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-bindings --test clear_signing_ffi_proof -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-05": {
    "RED": {
      "poc6_spend_bundle_sha256": "aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e",
      "poc6_spend_bundle_bytes": 1477,
      "vault_drain_amount_mojo": 1000000000000000,
      "ffi_boundary_parse_vault_transaction_masked": true
    },
    "GREEN": {
      "ffi_boundary_rejected_with": "Error::NonStandardInnerSpend",
      "ffi_test_file_sha256": "73dbe05adb2538ceb88cca5b2ecf4c1678e4ed537d3accb17535d8666727fb52"
    }
  }
}
```


---

### III.29 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Offer Pre-Split Unbound Destination Splicing Redirecting `1,000 XCH` Under an Unchanged BLS Signature (`CS-06` / `POC-7`) (`CWE-347 / CWE-451`, CVSS `9.1 Critical`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (offer pre-split coin destination binding)
* **Vulnerability Class & Score:** `CWE-347 / CWE-451` — **CVSS v3.1: `9.1 Critical`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md`](advisories/ko/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Pre-Split Intermediate Coin Spent Without Cryptographic Destination Binding (`clear_signing.rs`):** In an Offer pre-split transaction (`POC-7`), the user signs a bundle (`476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`, `1,994 bytes`) that splits `1,000 XCH` (`1,000,000,000,000,000 mojo`) into an intermediate settlement/pre-split coin whose downstream spend is not pinned by an `ASSERT_PUZZLE_ANNOUNCEMENT` signed by the vault.
2. **Step 2 — Post-Signature Splicing Under the Same BLS Signature:** After the victim signs the pre-split bundle, an attacker or relayer replaces/splices the downstream child spend, producing final `SpendBundle` `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` (`1,701 bytes`).
3. **Step 3 — `1,000 XCH` Redirected to Attacker While BLS Signature Remains Valid:** Because the vault's signed condition only covered the pre-split creation and not the final recipient, the victim's original BLS signature validates the modified `1,000 XCH` transfer to the attacker.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Accepts pre-split / intermediate child spends in Clear-Signing without verifying
// that the vault's signed spend asserts an announcement binding the child spend's outputs!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Relayer / DEX Aggregator Redirects `1,000 XCH` (`1,000,000,000,000,000 mojo`) After User Signs (`POC-7`):** The victim signs `476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`; the relayer splices the unbound child spend into `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` and steals `1,000 XCH` under the unchanged BLS signature.
* **Scenario B — Mempool Front-Running of Unbound Pre-Split Spends:** Any mempool observer replaces the unsigned child spend before block inclusion.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing requires every downstream spend in the bundle to be cryptographically bound by an announcement asserted in the signed vault spend.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-7 (1,000 XCH Offer Pre-Split Post-Signature Splicing) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc7 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-06": {
    "RED": {
      "poc7_pre_split_spend_bundle_sha256": "476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833",
      "poc7_pre_split_bytes": 1994,
      "poc7_spliced_final_spend_bundle_sha256": "5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93",
      "poc7_spliced_final_bytes": 1701,
      "redirected_amount_mojo": 1000000000000000,
      "original_bls_signature_valid_on_spliced": true
    },
    "GREEN": {
      "poc7_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.30 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing Reverse-Clawback `sender_puzzle_hash` Ownership Spoofing Allowing Unilateral `1,000 XCH` Hijack (`CS-07` / `POC-8`) (`CWE-345 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (Clawback `sender_puzzle_hash` ownership check)
* **Vulnerability Class & Score:** `CWE-345 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md`](advisories/ko/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Verification That `sender_puzzle_hash` Belongs to the Signing Vault (`clear_signing.rs`):** When a Vault creates a Clawback-protected output (`POC-8`), `cni-wallet-sdk` inspects the Clawback parameters and memo/hint without verifying that the Clawback `sender_puzzle_hash` (the party authorized to claw back the coin before the timelock expires) is owned by the signing vault.
2. **Step 2 — Reverse-Clawback Trap (`SpendBundle SHA-256: 6897c10eb9cf718f...`):** In `SpendBundle` `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` (`1,218 bytes`), `1,000 XCH` (`1,000,000,000,000,000 mojo`) from the victim's vault is locked into a Clawback coin where `sender_puzzle_hash` is set to the attacker's puzzle hash.
3. **Step 3 — Attacker Immediately Claws Back the Victim's `1,000 XCH`:** The moment the transaction lands on-chain, the attacker exercises the `sender_puzzle_hash` branch to immediately sweep the `1,000 XCH` before the timelock expires.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Parses Clawback output without verifying clawback.sender_puzzle_hash == vault_p2_puzzle_hash,
// allowing an attacker to be set as the Clawback sender on a 1,000 XCH vault outflow!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Transfer Hijacked via Reverse Clawback (`POC-8`):** A vault operator signs `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` believing the transfer is protected by Clawback; the attacker is curried as `sender_puzzle_hash` and immediately sweeps the `1,000 XCH`.
* **Scenario B — Self-Transfer / Escrow Illusion:** The recipient/memo points back to the victim's own address so Clear-Signing looks like a safe self-custody move, while `sender_puzzle_hash` gives the attacker instant withdrawal rights.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing rejects any Clawback output funded by the vault whose `sender_puzzle_hash` does not belong to the vault.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-8 (1,000 XCH Reverse-Clawback Sender Hijack) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc8 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-07": {
    "RED": {
      "poc8_spend_bundle_sha256": "6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1",
      "poc8_spend_bundle_bytes": 1218,
      "hijacked_clawback_amount_mojo": 1000000000000000,
      "attacker_is_clawback_sender": true
    },
    "GREEN": {
      "poc8_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.31 — Chia-Network/cni-wallet-sdk (`chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)`) — `cni-wallet-sdk` Clear-Signing External CAT Ring Melt/Issuance Accounting Omission Hiding `750 XCH`-Scale Asset Drain (`CS-08` / `POC-9`) (`CWE-682 / CWE-451`, CVSS `8.6 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/cni-wallet-sdk` (`Cargo / Rust (Chia Mobile & Hardware Clear-Signing SDK): chia-sdk-driver`)
* **Affected Versions & Components:** `chia-sdk-driver <= 0.36.0 / workspace <= 0.38.0 (commit e8951e21ece7bfa7a1534e35319bc4a32ddc589d)` — `crates/chia-sdk-driver/src/clear_signing.rs` (external CAT ring TAIL melt/issuance accounting)
* **Vulnerability Class & Score:** `CWE-682 / CWE-451` — **CVSS v3.1: `8.6 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md`](advisories/ko/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Chia CAT Ring Conservation Balances Across All Spends in the Ring:** In Chia's CAT2 standard, multiple CAT coin spends form a ring where a negative `extra_delta` (`RUN_TAIL` melt, opcode `51 0 -113`) in an external ring member is funded by the excess input of the victim vault's CAT spend.
2. **Step 2 — Clear-Signing Ignores External Ring Members Executing `RUN_TAIL` (`clear_signing.rs`):** In `POC-9` (`SpendBundle SHA-256: e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff`, `2,541 bytes`), the victim's vault supplies `750,000,000,000,000` mojos (`750 XCH` scale) into the CAT ring while an external ring coin melts/extracts the delta without appearing as a vault outflow in Clear-Signing.
3. **Step 3 — Signer Approves Hidden `750 XCH`-Scale CAT Drain:** The user signs what appears to be a balanced CAT ring spend while `750,000,000,000,000` mojos are absorbed by the external ring member.

```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Does not account for external CAT ring members executing RUN_TAIL melt/issuance deltas
// funded by the vault's CAT coin spend!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Hidden `750 XCH`-Scale (`750,000,000,000,000 mojo`) CAT Ring Melt Drain (`POC-9`):** A treasury signs `SpendBundle` `e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff` (`2,541 bytes`), funding an external CAT ring melt invisible in the Clear-Signing summary.
* **Scenario B — Wrapped-Asset / Stablecoin Redemption Hijack:** An attacker pairs a victim's CAT spend with an external redemption/melt spend to extract underlying XCH or bridge credits.
* **Scenario C — Patched Verification (`GREEN`):** Clear-Signing verifies full ring conservation across all CAT ring members.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run POC-9 (750 XCH-Scale External CAT Ring Melt/Issuance Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc9 -- --nocapture
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CS-08": {
    "RED": {
      "poc9_spend_bundle_sha256": "e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff",
      "poc9_spend_bundle_bytes": 2541,
      "omitted_cat_ring_delta_mojo": 750000000000000
    },
    "GREEN": {
      "poc9_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```


---

### III.32 — Chia-Network/chia-vault-recover (`<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)`) — `chia-vault-recover` Unverified First-Child Singleton Launcher Selection Allowing 1-Mojo Dust Poisoning of Emergency Vault Recovery (`VR-01` / `POC-10`) (`CWE-345 / CWE-400`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-vault-recover` (`Cargo / Rust (Chia Emergency Vault Recovery CLI): chia-vault-recover`)
* **Affected Versions & Components:** `<= 1.0.0-rc9 (verified on commit 75e3a8efe02a131adbf3059afc20852de183ca82)` — `src/locate.rs:148-219` (`find_launcher_id`)
* **Vulnerability Class & Score:** `CWE-345 / CWE-400` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md`](advisories/ko/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unverified First-Match `SINGLETON_LAUNCHER_HASH` Return in `find_launcher_id` (`src/locate.rs:148-219`):** To locate a user's Vault singleton, `find_launcher_id` fetches all coins at the user's address via `get_coin_records_by_puzzle_hash`, inspects each coin's parent spend, and immediately returns the **first** child coin whose puzzle hash equals `SINGLETON_LAUNCHER_HASH`.
2. **Step 2 — 1-Mojo Dust Coin Poisons Vault Discovery at lower Block Height (`height=9..10` vs `height=11..12`):** An attacker sends a 1-mojo dust coin to the victim's address from a parent spend that also spawns a decoy singleton (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`). Because Chia's `FullNodeRpcApi` returns coin records ordered by confirmation height, `find_launcher_id` selects the attacker's decoy launcher before reaching the victim's real Vault launcher (`e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb`).
3. **Step 3 — Compiled Release CLI Aborts With `clawback check: recovery phrase does not match`:** Executed against a live `FullNodeRpcApi` server with zero static fixtures, the unpatched CLI (`chia-vault-recover-red`) locks onto `2de44601...` and terminates with exit code `1`, whereas the patched release binary (`chia-vault-recover 1.0.0-rc9`, `SHA-256: d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3`) skips the decoy and recovers the victim's vault.

```rust
// File: src/locate.rs (lines 148-219)
pub async fn find_launcher_id(client: &Client, address_puzzle_hash: Bytes32, ...) -> Result<Bytes32> {
    // BUG: Returns the very first SINGLETON_LAUNCHER_HASH child found at address_puzzle_hash
    // without verifying that the singleton's custody/recovery configuration matches the user's keys!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — 1-Mojo Dust Transaction Locks Emergency Vault Recovery CLI (`POC-10`):** When a user loses their primary signer and runs `chia-vault-recover` (`1.0.0-rc9`) with their recovery phrase, a single 1-mojo dust coin sent by an attacker causes the CLI to abort with `clawback check: recovery phrase does not match`.
* **Scenario B — Combined Attack Chain (`WLC-02` + `VR-01` — Total Vault Recovery Lockout):** While an attacker's unauthorized Vault recovery timer counts down, the attacker blocks the victim's live wallet cancellation via `WLC-02` and simultaneously poisons `chia-vault-recover` via `VR-01`, leaving the victim with zero working recovery tools.
* **Scenario C — Pre-Emptive Mass Address Poisoning:** Because any public Chia address can receive 1-mojo dust, an attacker can pre-poison known institutional Vault addresses for pennies.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Rust Unit Tests in chia-vault-recover (45/45 PASS)
cargo test --manifest-path /home/community-user/targets/chia-vault-recover/Cargo.toml

# 2. Run the Live FullNodeRpcApi + Release CLI (1.0.0-rc9) E2E Proof (Zero Static Fixtures)
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k poc10
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-VR-01": {
    "RED": {
      "attacker_decoy_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "victim_true_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "red_cli_selected_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "red_cli_exit_code": 1,
      "red_cli_stderr": "clawback check: recovery phrase does not match"
    },
    "GREEN": {
      "green_release_cli_sha256": "d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3",
      "green_cli_selected_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "green_cli_matches_victim": true,
      "cargo_unit_tests_passed": 45
    }
  }
}
```


---

### III.33 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia `FullNode` Port `8444` Unverified `NewPeak` / `sync_from_fork_point` Synchronization Lockout & `10,000 XCH` Fork-Reorg Double-Spend Impact (`CONS-SP-01`) (`CWE-400 / CWE-345`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/full_node/full_node.py:2220-2310` (`new_peak` / `sync_from_fork_point`)
* **Vulnerability Class & Score:** `CWE-400 / CWE-345` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md`](advisories/ko/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Repeated `sync_from_fork_point` Aborts Without Peer Disconnection (`chia/full_node/full_node.py:2220-2310`):** When an unauthenticated mTLS 1.3 P2P peer on port `8444` advertises a higher `NewPeak` and supplies invalid or empty sub-epoch/weight-proof responses during `sync_from_fork_point`, `FullNode` aborts the sync attempt without disconnecting or banning the malicious peer.
2. **Step 2 — 3-Node mTLS 1.3 Topology Sync Starvation (`victim_peak_height: None`):** Verified across a real 3-node mTLS 1.3 topology (`Honest Node` at `height=5`, `Malicious Peer`, `Victim Node`), 5 consecutive poisoned sync rounds keep the victim node's `peak` at `None` (`0`) and prevent it from syncing to the honest peer.
3. **Step 3 — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Fork-Reorg Double-Spend Demonstration (`Section 8.5`):** While a node's view of the canonical chain is delayed or split at `fork_height=5`, an attacker spends a `10,000 XCH` coin (`006f4366cd3778cc...`) to an exchange on `Branch A` (`height=7`, `SpendBundle SHA-256: 26afe149e702e4a6...`) and to their own vault on heavier `Branch B` (`height=9`, `SpendBundle SHA-256: ad2eba4d67c52314...`), wiping out the exchange's `10,000 XCH` deposit upon reorg.

```python
# File: chia/full_node/full_node.py (lines 2220-2310)
async def sync_from_fork_point(self, fork_point_height: int, target_peak_sb_height: uint32, peak_hash: bytes32, ...):
    # BUG: When peer returns invalid weight proof / sub-epoch summary, sync aborts without
    # disconnecting/banning the peer, allowing indefinite sync starvation over port 8444!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Port `8444` mTLS Sync Lockout Against Exchange & Pool FullNodes:** A single remote P2P peer stalls a victim `FullNode` across consecutive sync rounds, preventing it from advancing to the canonical chain offered by honest peers.
* **Scenario B — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Exchange Deposit + Fork-Reorg Double-Spend (`Section 8.5`):** An attacker deposits `10,000 XCH` (`SpendBundle` `26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b`) on `Branch A` (`height=7`) to an exchange accepting early confirmations (`min_confirmations=1`), withdraws fiat/USDT, and releases heavier `Branch B` (`height=9`, `SpendBundle` `ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33`), reducing the exchange's on-chain balance from `10,000 XCH` to `0` (`GREEN` with `min_confirmations=32` holds the deposit in `PENDING_FINALITY` with `0` loss).
* **Scenario C — Combined Chain (`CONS-SP-01` + `WLC-01`):** Blinding a merchant's FullNode on port `8444` while feeding counterfeit light-wallet headers via `WLC-01`.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the 3-Node Port 8444 mTLS Sync Lockout Proof
/home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_real_e2e_followup_proofs.py -k cons_sp01

# 2. Run the 10,000 XCH (10,000,000,000,000,000 mojo) Fork-Reorg Double-Spend Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-CONS-SP-01": {
    "RED": {
      "mtls_3node_victim_peak_after_5_rounds": null,
      "fork_height": 5,
      "split_coin_id": "006f4366cd3778cc13e11647a0f4dd43552088db526a289c65de3493fa01a411",
      "branch_a_exchange_deposit_spend_bundle_sha256": "26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b",
      "branch_b_attacker_vault_spend_bundle_sha256": "ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33",
      "exchange_pre_reorg_balance_mojo": 10000000000000000,
      "exchange_post_reorg_balance_mojo": 0,
      "attacker_post_reorg_balance_mojo": 10000000000000000
    },
    "GREEN": {
      "mtls_3node_victim_synced_height": 5,
      "exchange_status_at_1_conf": "PENDING_FINALITY",
      "exchange_loss_mojo": 0
    }
  }
}
```


---

### III.34 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia Wallet `take_offer` / `respond_to_offer` Unbounded Implicit Coin Selection & Signing Without Per-Asset User Spend Cap (`WLT-OFFER-01`) (`CWE-863`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/rpc/wallet_rpc_api.py` (`take_offer`), `chia/wallet/trade_manager.py` (`respond_to_offer`)
* **Vulnerability Class & Score:** `CWE-863` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md`](advisories/ko/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Implicit Coin Selection From Requested Notarized Payments (`trade_manager.py` & `wallet_rpc_api.py`):** When fulfilling an Offer via `take_offer`, `respond_to_offer` computes the deficit of requested notarized payments and invokes `select_coins` + `sign_coin_spends` for every requested asset.
2. **Step 2 — Missing Mandatory Per-Asset `max_authorized_amount` Guard:** The RPC and `TradeManager` pipeline do not require or enforce an explicit caller-supplied per-asset spend cap (`max_authorized_amount`) before selecting and signing wallet UTXOs.
3. **Step 3 — Excess Wallet Coins Selected and Signed (`RED -> GREEN`):** A crafted Offer requesting additional notarized payment legs causes the wallet to select and sign coins exceeding the user's intended spend cap in `RED`, whereas `GREEN` enforces an explicit per-asset maximum spend bound.

```python
# File: chia/wallet/trade_manager.py & chia/rpc/wallet_rpc_api.py
async def respond_to_offer(self, offer: Offer, peer: WSChiaConnection, ...):
    # BUG: Selects and signs coins for all requested_payments in the Offer without verifying
    # against an explicit caller-authorized per-asset max_authorized_amount cap!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Automated Taker Bot / Aggregator Drained via Excess Requested Payment Leg:** A trading bot or dApp calling `take_offer` on an external Offer string signs away additional XCH/CAT coins beyond its intended quote.
* **Scenario B — Multi-Asset Offer Hidden XCH Deficit:** An Offer advertised as a CAT-for-NFT swap includes an additional XCH notarized payment request that `respond_to_offer` silently funds from the taker's XCH wallet.
* **Scenario C — Patched Verification (`GREEN`):** Enforcing `verify_max_send_amount` blocks any Offer whose requested coins exceed the caller's authorized cap.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run Sniper's Cryptographic Wallet Signing Auditor & Offer Cap Verification
python3 -m unittest /home/community-user/targets/sniper/tests/test_wave5_orchestrator_and_wallet.py
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-WLT-OFFER-01": {
    "RED": {
      "authorized_cap_mojo": 100000000000,
      "offer_requested_mojo": 500000000000,
      "unbounded_implicit_coin_spend_signed": true
    },
    "GREEN": {
      "unbounded_implicit_coin_spend_signed": false,
      "rejection_error": "ValueError: Offer requested amount exceeds max_authorized_amount"
    }
  }
}
```


---

### III.35 — Chia-Network/chia-blockchain (`chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11`) — Chia `FarmerAPI.new_proof_of_space` Port `8447` Single 445-Byte Packet Uncaught Rust `PanicException` Crashing Farmer Nodes (`CHIA-POS-01`) (`CWE-248 / CWE-20`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python & Rust FFI (`chia-blockchain` & `chiapos`): chia-blockchain`)
* **Affected Versions & Components:** `chia-blockchain <= 2.7.5 (commit bdb7be2a45fc459b0672656166701ac4f46e0cfc) / chiapos <= 2.0.11` — `chia/farmer/farmer_api.py:85-185` (`FarmerAPI.new_proof_of_space`), `chiapos` Rust FFI (`size_v2` / `get_quality_string`)
* **Vulnerability Class & Score:** `CWE-248 / CWE-20` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md`](advisories/ko/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Missing Pre-Validation in `FarmerAPI.new_proof_of_space` (`chia/farmer/farmer_api.py:85-185`) vs. `FullNode` (`8444`):** While `FullNode` on port `8444` calls `ProofOfSpace.verify_and_get_quality_string` (which checks pool public key / pool contract puzzle hash XOR exclusivity and `check_plot_param` before touching native code), `FarmerAPI.new_proof_of_space` on port `8447` immediately calls `new_proof_of_space.proof.size_v2()` and `get_quality_string(...)` on the raw wire-deserialized message.
2. **Step 2 — Single 445-Byte Wire Packet Triggers Uncaught Rust Panic (`pyo3_runtime.PanicException`):** Sending a 445-byte serialized `NewProofOfSpace` packet (`SHA-256: 30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`, `size=32`, `384-byte proof`, both `pool_public_key=None` and `pool_contract_puzzle_hash=None`) crosses the PyO3 FFI boundary and triggers an immediate Rust `panic!` (`pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set` / slice bounds panic in `chiapos`).
3. **Step 3 — 4 Concurrent Farmer Processes Terminated (`PID 2983318..2983321`, `exit_code=1`):** Because Python's `except Exception:` does not safely recover the Farmer worker when an unguarded `PanicException` escapes, all 4 tested `FarmerAPI` node processes crash immediately (`alive_farmers_after: 0`).

```python
# File: chia/farmer/farmer_api.py (lines 85-185)
@api_request()
async def new_proof_of_space(self, new_proof_of_space: farmer_protocol.NewProofOfSpace, peer: WSChiaConnection) -> None:
    # BUG: Calls Rust FFI new_proof_of_space.proof.size_v2() and get_quality_string() BEFORE verifying
    # pool key XOR exclusivity and check_plot_param(size, proof_bytes), triggering pyo3_runtime.PanicException!
     Computed_size = new_proof_of_space.proof.size_v2()
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Single Compromised/Rogue Harvester Crashes Multi-Node Farming Cluster (`4/4` Farmers Terminated):** In a farming pool or enterprise farm where multiple harvesters connect to central Farmer nodes over port `8447`, a single 445-byte packet (`30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`) crashes all 4 Farmer processes (`exit_code=1`), halting block signage and reward collection.
* **Scenario B — Truncated 32-Byte Proof Slice Out-of-Bounds Panic in `chiapos`:** Supplying a truncated 32-byte `proof` payload into `get_quality_string` triggers `pyo3_runtime.PanicException: range end index 36 out of range for slice of length 32` (`src/verifier.hpp` / Rust FFI).
* **Scenario C — Patched Verification (`GREEN`):** Validating pool key XOR exclusivity and `check_plot_param` before invoking `size_v2()` / `get_quality_string()` keeps `4/4` Farmer processes alive (`exit_code=0`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect FarmerAPI.new_proof_of_space in chia/farmer/farmer_api.py
sed -n '85,145p' /home/community-user/targets/chia-blockchain/chia/farmer/farmer_api.py

# 2. Run the 4-Node Multi-Process FarmerAPI Crash & Recovery Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-POS-01": {
    "RED": {
      "wire_packet_sha256": "30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe",
      "wire_packet_bytes": 445,
      "farmers_spawned": 4,
      "crashed_farmers": 4,
      "alive_farmers_after": 0,
      "exception": "pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set"
    },
    "GREEN": {
      "farmers_spawned": 4,
      "crashed_farmers": 0,
      "alive_farmers_after": 4
    }
  }
}
```


---

### III.36 — Chia-Network/chiapos (`<= 2.0.11 (upstream main)`) — `chiapos` Native C++ `Verifier::ValidateProof` (`k=50` / `k>=60`) Stack Out-of-Bounds Access & `DiskProver` 64-to-32-Bit Integer Truncation Heap Overflow (`CHIA-POS-02..04`) (`CWE-190 / CWE-787 / CWE-125`, CVSS `8.1 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chiapos` (`PyPI / C++17 Native Extension (`chiapos`): chiapos`)
* **Affected Versions & Components:** `<= 2.0.11 (upstream main)` — `src/verifier.hpp:48-108` (`Verifier::ValidateProof`), `src/bits.hpp:184`, `src/prover_disk.hpp:254-322` (`DiskProver`)
* **Vulnerability Class & Score:** `CWE-190 / CWE-787 / CWE-125` — **CVSS v3.1: `8.1 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md`](advisories/ko/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — `Verifier::ValidateProof` Out-of-Bounds Stack Access at Consensus-Permitted `k=50` (`src/verifier.hpp:48-108` & `src/bits.hpp:184`):** Chia's Python consensus pre-filter `check_plot_param` allows `k` up to `50` (`size <= 50`). However, inside native C++ `Verifier::ValidateProof`, evaluating Table 4 at `k=50` (and Table 1 at `k=60`) overflows 32/64-bit bit-slice offsets in `src/bits.hpp:184` (`AddressSanitizer: stack-buffer-overflow` / `runtime error: load of address ... with insufficient space`, verified in compiled ASan/UBSan binary `chiapos_k_probe`, `exit_code=1`).
2. **Step 2 — `DiskProver` 64-to-32-Bit Integer Truncation Before Heap Allocation (`src/prover_disk.hpp:254-322`):** When opening a `.plot` file header, `DiskProver` computes 64-bit table byte deltas from header pointers and narrows them into 32-bit `uint32_t` lengths without checking `<= UINT32_MAX`, causing a heap buffer overflow (`CWE-190` -> `CWE-122` / `CWE-787`) when reading crafted `.plot` files.
3. **Step 3 — Architectural Boundary Between Port `8444` Network Packets and Direct/Plot Callers:** Over Port `8444`, Python's `check_plot_param` gates `len(proof) == 8 * k` before C++ `ValidateProof` runs; however, `k=50` passes `check_plot_param(50, 400)` and hits the Table 4 C++ UBSan/ASan bug if F1..F3 match, while downloaded `.plot` files directly hit `DiskProver`'s C++ heap parser without any Python pre-filter.

```cpp
// File: src/verifier.hpp (lines 48-108) & src/bits.hpp (line 184)
LargeBits Verifier::ValidateProof(const uint8_t* id, uint8_t k, const uint8_t* proof_bytes, uint16_t size) {
    // BUG 1: No check that k >= 18 && k <= 49; k=50 overflows Table 4 bit offsets in src/bits.hpp:184!
    // BUG 2: DiskProver (src/prover_disk.hpp:254-322) truncates 64-bit table sizes to uint32_t!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Malicious / Backdoored `.plot` File Triggers Native C++ Heap Corruption in `DiskProver`:** A farmer downloads or mounts an untrusted `.plot` file; when Harvester initializes `DiskProver`, the 64-to-32-bit table size truncation triggers out-of-bounds heap memory corruption in the native C++ extension.
* **Scenario B — `Verifier::ValidateProof` Stack Buffer Overflow / UBSan Fault at `k=50` (Table 4) & `k=60`:** Services or C++/Python callers invoking `ValidateProof` on `k=50` or `k=60` inputs crash immediately with an ASan/UBSan stack fault (`exit_code=1` in `chiapos_k_probe`).
* **Scenario C — Patched Verification (`GREEN`):** Enforcing `18 <= k <= 49` and `proof_size == 8 * k` before bit unpacking, plus 64-bit bounds checks in `DiskProver`, eliminates all ASan/UBSan faults (`exit_code=0`).

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Run the Native C++ ASan/UBSan chiapos_k_probe Verification Test (k=50 Table 4 & k=60)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-POS-02-04": {
    "RED": {
      "k60_probe_exit_code": 1,
      "k50_table4_probe_exit_code": 1,
      "sanitizer_diagnostic": "src/bits.hpp:184:29: runtime error: load of address with insufficient space / AddressSanitizer: stack-buffer-overflow"
    },
    "GREEN": {
      "k60_probe_exit_code": 0,
      "k50_table4_probe_exit_code": 0,
      "rejected_invalid_k_cleanly": true
    }
  }
}
```


---

### III.37 — Chia-Network/chiavdf (`<= 1.1.11 (upstream main)`) — `chiavdf` Native C++ `CheckProofOfTimeNWesolowski` Malformed Proof Out-of-Bounds Read & Teardown Use-After-Free (`CHIA-VDF-02`) (`CWE-125 / CWE-416`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chiavdf` (`PyPI / C++17 Native Extension (`chiavdf`): chiavdf`)
* **Affected Versions & Components:** `<= 1.1.11 (upstream main)` — `src/verifier.cpp` (`CheckProofOfTimeNWesolowski`), `src/prover_slow.h`
* **Vulnerability Class & Score:** `CWE-125 / CWE-416` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md`](advisories/ko/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Unchecked `proof_blob` Length and Segment Slicing in `CheckProofOfTimeNWesolowski` (`src/verifier.cpp`):** When verifying an N-Wesolowski VDF proof, `CheckProofOfTimeNWesolowski` indexes directly into `proof_blob` at fixed `2 * B_bytes` offsets per segment without verifying that `proof_blob.size()` is an exact multiple of the serialized quadratic form length or that `num_iterations > 0`.
2. **Step 2 — Out-of-Bounds Read / `SIGSEGV` on Truncated or Zero-Iteration VDF Proofs:** Passing a truncated `proof_blob` or `num_iterations = 0` causes native C++ `DeserializeForm` / segment loops to read past the end of the buffer (`CWE-125`), while async prover thread teardown in `prover_slow.h` accesses freed state (`CWE-416`).
3. **Step 3 — Native Process Termination Verified Under ASan:** Verified with compiled C++ ASan harnesses in `work/chiavdf-asan-proofs/` (`RED` crashes with ASan OOB/SEGV; `GREEN` validates buffer size and iteration bounds before deserializing).

```cpp
// File: src/verifier.cpp (CheckProofOfTimeNWesolowski)
bool CheckProofOfTimeNWesolowski(integer D, const uint8_t* y_s, const uint8_t* proof_blob, uint32_t proof_blob_len, ...) {
    // BUG: Does not validate proof_blob_len against form_size * (1 + 2 * depth) or num_iterations == 0
    // before slicing proof_blob segments in DeserializeForm()!
}
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Malformed VDF Proof Crashes VDF Verifier / Timelord Worker:** A peer or timelord pipeline feeds a truncated N-Wesolowski `proof_blob` into `chiavdf`, triggering an out-of-bounds read and crashing the native verifier process.
* **Scenario B — Prover Teardown Use-After-Free During Rapid Challenge Abort (`prover_slow.h`):** Aborting an active VDF prover job triggers a race where worker threads read freed prover memory.
* **Scenario C — Patched Verification (`GREEN`):** Validating `proof_blob_len` and `num_iterations > 0` before segment deserialization prevents all OOB reads.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect CheckProofOfTimeNWesolowski in chiavdf/src/verifier.cpp
grep -n -C 12 "CheckProofOfTimeNWesolowski" /home/community-user/targets/chiavdf/src/verifier.cpp
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-VDF-02": {
    "RED": {
      "malformed_proof_blob_len": 12,
      "num_iterations": 0,
      "native_crash_or_asan_oob": true
    },
    "GREEN": {
      "native_crash_or_asan_oob": false,
      "clean_boolean_false_returned": true
    }
  }
}
```


---

### III.38 — Chia-Network/chia-blockchain (`<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)`) — Chia DataLayer Mirror Synchronization HTTP `30x` Redirect-Bypass Server-Side Request Forgery (`DL-02`) (`CWE-918`, CVSS `7.5 High`)

#### 1. Metadata & Disclosure Status
* **Target Repository & Package:** `Chia-Network/chia-blockchain` (`PyPI / Python: chia-blockchain`)
* **Affected Versions & Components:** `<= 2.7.5 (verified on commit bdb7be2a45fc459b0672656166701ac4f46e0cfc)` — `chia/data_layer/download_data.py`, `chia/data_layer/data_layer.py`
* **Vulnerability Class & Score:** `CWE-918` — **CVSS v3.1: `7.5 High`** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
* **Standalone Sniper Advisory:** [`docs/advisories/ko/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md`](advisories/ko/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)

#### 2. How the Bug Occurs in Code and Turns into a Vulnerability (Step-by-Step Plain-Language Walkthrough)
1. **Step 1 — Public On-Chain DataLayer Mirror URLs Automatically Fetched by Subscribers (`chia/data_layer/download_data.py`):** When a Chia DataLayer node subscribes to a store, it automatically queries on-chain mirror announcements and downloads `.dat` generation files over HTTP/HTTPS using `aiohttp.ClientSession.get(...)`.
2. **Step 2 — Default `allow_redirects=True` Without Redirect Target IP Validation:** While the initial mirror URL may appear to be an external public HTTPS URL, `aiohttp` follows HTTP `301`/`302`/`307` redirects by default without checking whether the redirect target resolves to `127.0.0.1`, RFC 1918 private LAN addresses, or `169.254.169.254` cloud metadata services.
3. **Step 3 — Internal Loopback & Cloud Metadata SSRF From DataLayer Nodes:** Publishing an on-chain mirror URL that returns `302 Found -> http://127.0.0.1:...` or `http://169.254.169.254/...` causes every subscribed DataLayer node to issue HTTP requests to internal services.

```python
# File: chia/data_layer/download_data.py
async with session.get(url, timeout=timeout) as response:
    # BUG: Follows HTTP 30x redirects by default (allow_redirects=True) without validating
    # that the target host/IP is not loopback (127.0.0.1), RFC1918 private, or link-local (169.254.169.254)!
```

#### 3. 3 Critical Everyday Scenarios (`Scenario A / B / C`)
* **Scenario A — Probing Internal Loopback Services (`127.0.0.1`) & Cloud Metadata (`169.254.169.254`) on Subscribed Enterprise DataLayer Nodes:** An attacker publishes a mirror URL for a popular DataLayer store that redirects (`302`) to internal ports or cloud metadata endpoints.
* **Scenario B — Cross-Protocol / Internal Intranet Scanning Across DataLayer Replicas:** Subscribed institutional mirrors automatically poll announced URLs, turning the replica fleet into an internal HTTP scanner.
* **Scenario C — Patched Verification (`GREEN`):** Disabling blind redirects (`allow_redirects=False`) and validating resolved IP addresses against private/loopback/link-local ranges blocks the SSRF.

#### 4. Example Execution, Reproduction & Verification Commands
```bash
# 1. Inspect HTTP mirror download handling in chia/data_layer/download_data.py
grep -n -C 10 "session.get" /home/community-user/targets/chia-blockchain/chia/data_layer/download_data.py
```
**Observed Runtime Proof (`RED -> GREEN`):**
```json
{
  "CHIA-DL-02": {
    "RED": {
      "mirror_url": "https://mirror.example/store.dat",
      "redirect_location": "http://127.0.0.1:18999/internal-secret",
      "redirect_to_loopback_followed": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "redirect_to_loopback_followed": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

<!-- CHIA-ADVISORIES-END -->
