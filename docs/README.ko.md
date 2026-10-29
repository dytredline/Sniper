# Sniper Community

[English](../README.md) | [Türkçe](README.tr.md) | [日本語](README.ja.md) | [简体中文](README.zh-CN.md) | **한국어**

[ConverserAI 프로젝트 개요](https://converserai.com/#sniper) · [기능 목록](CAPABILITIES.md) · [설치 및 구성](#설치) · [자주 묻는 질문](#자주-묻는-질문)

Sniper Community는 애플리케이션, API, 웹사이트를 개발하거나 소유하고 검토하는 사람을 위한 오픈 소스,
로컬 우선 방어형 애플리케이션 보안 도구 모음입니다. 지원되는 소스 코드 정적 분석(SAST), 의존성 및
SBOM 분석(SCA), 컨테이너 아티팩트, 코드형 인프라(IaC), CI 설정, 저장된 보안 보고서를 하나의 검토 흐름으로
연결합니다. 본인이 소유했거나 명시적인 승인을 받은 Web/API 대상에는 실행 전에 사람이 검토하는 범위가 제한된 작업 계획을
준비할 수 있습니다. 결과는 로컬 stdio MCP를 통해 AI 클라이언트에서, CLI에서, 또는 루프백 웹 인터페이스에서 확인할 수 있습니다.

## 기능 태그

`애플리케이션 보안` · `SAST` · `SCA` · `SBOM` · `IaC 보안` · `API 보안` · `웹사이트 보안` ·
`모바일 보안` · `Android` · `iOS` · `IDOR` · `권한 부여` · `GraphQL` · `Rails` · `Spring` · `ASP.NET` ·
`Kubernetes` · `Helm` · `Terraform` · `컨테이너 보안` · `CI/CD 보안` · `소프트웨어 공급망` ·
`SLSA` · `OCI 출처` · `Syft` · `Grype` · `퍼징` · `메모리 안전성` · `MCP` · `AI 보안` ·
`SARIF` · `OpenVEX` · `GHSA` · `CVSS` · `SSVC` · `시크릿 탐지` · `개인정보 보호` · `정적 분석` ·
`런타임 증거` · `다중 저장소 분석` · `신뢰 그래프` · `아티팩트 출처` · `프로토콜 보안` ·
`아카이브 및 심볼릭 링크 보안` · `바이너리 강화` · `DevSecOps` · `로컬 우선`

Sniper Community v1.1은 다음 영역에 더 깊고 검토 가능한 기능을 추가합니다.

- **프레임워크 간 접근 제어:** 지원되는 Rails 상속, Spring 및 ASP.NET 경로, GraphQL 리졸버,
  객체 식별자, 권한 부여 어노테이션, 정책, 역할, 소유자 및 테넌트 제한 조회를 연계합니다.
- **다중 저장소 신뢰 그래프:** 지원되는 HTTP/OpenAPI, Webhook, Kafka, 인증 계약, GraphQL, 정확한 PyPI
  의존성, CI 아티팩트 및 재사용 가능 워크플로 관계를 비공개 엔드포인트나 자격 증명을 반환하지 않고 매핑합니다.
- **제한된 퍼징 및 런타임 증거:** C/C++, Rust, Go, Python, Java 및 JavaScript/TypeScript용 검토 가능한
  퍼즈 대상을 준비하고, 지원되는 선택적 실행 경로에 정확한 런타임 고정, 네트워크 격리, 리소스 제한 및
  실패 시 닫히는 준비 상태를 적용합니다.
- **공급망 및 플랫폼 검토:** 지원되는 OCI/SLSA 출처, SBOM/VEX 증거, Kubernetes, Helm, Terraform,
  컨테이너, 스키마 마이그레이션, CI/CD 신뢰, 아카이브, 심볼릭 링크, 프로토콜 및 바이너리 강화 신호를 검사합니다.
- **AI 지원 방어 워크플로:** 상태 변경 작업을 표시된 계획과 명시적 사용자 확인 계약 뒤에 유지하면서
  로컬 stdio MCP로 응답 비교, 권한 매트릭스, 토큰 순서, 트래픽 디코딩, GHSA/OpenVEX 준비 및
  버그 바운티 준비 상태 검토를 제공합니다.
- **증거 기반 우선순위 지정:** 지원되는 발견 사항을 SARIF 코드 흐름, CVSS 3.1/4.0, CISA SSVC,
  도달 가능성, 공격 경로, 소유권, 기준선 및 수정 중심 품질 게이트와 연결합니다.

## 출시 전 AI 보안 검토

**강력한 오픈 소스 툴킷으로 웹사이트 보안 약점을 찾으세요.** 승인된 웹사이트 및 API 스캔을 로컬 코드 및 의존성 검토와 결합하여 발견 사항을 우선순위가 지정된 수정 계획으로 전환합니다. 외부 스캔에는 관련 엔진, 데이터, 준비 상태 확인 및 명시적인 범위 승인이 필요합니다. 자세한 내용은 [웹사이트 및 API 검토 경로](USE-CASES.md#plan-an-authorized-website-or-api-action)를 참조하세요.

App Store 또는 Google Play 제출 전에 AI 어시스턴트를 Sniper의 로컬 stdio MCP에 연결해 지원되는 Android,
iOS, Flutter, React Native 소스와 모바일 매니페스트를 검토할 수 있습니다. API 경로, 시크릿 단서, 의존성,
SBOM, CI 구성을 하나의 출시 전 화면에서 보고 발견 사항 설명과 수정 우선순위 결정에 활용할 수 있습니다.
같은 흐름은 웹사이트/API 출시 전과 릴리스 pull request에도 사용할 수 있습니다.

## Sniper로 점검할 수 있는 항목

| 영역 | Sniper가 답하는 데 도움을 주는 질문 |
| --- | --- |
| 소스 코드 및 구성 | 어떤 지원 코드 경로, 보안 패턴, 시크릿, 구성 선택에 사람의 검토가 필요한가? |
| 권한 부여 및 IDOR 검토 | 지원되는 어떤 Python 또는 JavaScript/TypeScript 경로에 권한 검사가 누락되었을 수 있는가(CWE-862), 또는 사용자/역할 바인딩 없이 객체 식별자를 로드하여 IDOR 검토가 필요한가(CWE-639)? |
| 의존성 및 SBOM | 어떤 컴포넌트가 존재하고 어떻게 연결되어 있으며, 로컬 취약점 증거는 무엇을 보여주는가? |
| 컨테이너 및 소프트웨어 공급망 | 지원되는 로컬 아티팩트에 어떤 패키지, 레이어, 매니페스트, 출처 신호 및 위험한 빌드 선택이 나타나는가? |
| 인프라 및 CI/CD | 지원되는 Terraform, Kubernetes, Helm, Dockerfile, Compose, 클라우드 IAM 또는 CI 워크플로 입력이 알려진 위험 설정을 노출하는가? |
| 저장된 보안 보고서 | 지원되는 SARIF 및 도구 보고서를 검증하고 범위를 제한하여 하나의 검토 흐름으로 요약할 수 있는가? |
| 승인된 웹사이트 및 TLS 워크플로 | 외부 작업 전에 사람이 확인해야 하는 정확한 대상, 범위, 동의, 준비 상태 및 중단 조건은 무엇인가? |

전체 기능 목록은 [Capabilities and security checks](CAPABILITIES.md), 실제 활용 사례는 [USE-CASES.md](USE-CASES.md), AI용 프로젝트 색인은 [llms.txt](../llms.txt), 재현 가능한 최신 검증 증거는 [VALIDATION.md](../VALIDATION.md)를 참조하세요.

## 보안 검토 주요 기능

- **영향도가 높은 데이터 흐름 추적:** 지원되는 소스-싱크(source-to-sink) 경로에서 SQL/명령 주입, XSS/HTML, SSRF, 오픈 리다이렉트, 경로 탐색, 안전하지 않은 역직렬화, XXE, 표현식 언어(EL), LDAP 위험을 추적합니다(SARIF `codeFlows` 지원).
- **접근 제어 테스트 집중:** 경로, 역할, 객체 식별자를 정리해 IDOR(CWE-639)와 권한 검사 누락 후보(CWE-862)의 수동 검증 순서를 정합니다.
- **노출된 시크릿 및 개인정보 흐름 탐지:** 시크릿 값을 마스킹한 상태로 로그, 응답, 스토리지, 외부 대상으로 향하는 개인정보 흐름을 추적합니다.
- **의존성 및 소프트웨어 공급망 파악:** 직접 및 전이 컴포넌트를 목록화하고 CycloneDX/SPDX SBOM, VEX, 도달 가능성 컨텍스트를 하나의 검토 흐름으로 연결합니다.
- **컨테이너, 클라우드 및 배포 파이프라인 강화:** Dockerfile, Terraform, Kubernetes, Helm, Compose, 클라우드 IAM, CI, 모바일, 브라우저 확장, 데스크톱 앱의 보안 설정을 검토합니다.
- **API, 웹사이트 및 TLS 검토:** 로컬 OpenAPI 계약과 소스 경로를 비교하고 인증 불일치 및 웹/TLS 보안 신호를 평가합니다.
- **중요 작업 우선순위 지정:** CVSS 3.1/4.0, CISA SSVC, 공격 경로 상관관계, 담당자, 기한, 기준선, 품질 게이트로 대응 우선순위를 정합니다.
- **적합한 워크플로 선택:** 루프백 Web, CLI, CI 또는 stdio MCP를 통해 JSON, HTML, SARIF, GitLab, SBOM, VEX, 지원되는 PDF 워크플로로 공유합니다.

## IDOR 및 수동 침투 테스트 지원

지원되는 Python 및 JavaScript/TypeScript 소스에서 내장 경로·권한 인벤토리는 권한 검사 누락 후보
(CWE-862)와 잠재적인 Insecure Direct Object Reference(IDOR) 경로(CWE-639)를 파일, 경로, 줄 번호 근거와
함께 제시합니다. 이를 통해 승인을 받은 테스터는 서로 다른 테스트 사용자, 역할, 합성 객체를 사용하는
수동 침투 테스트의 우선순위를 정할 수 있습니다.

각 후보는 승인된 범위에서 서로 다른 테스트 사용자·역할과 합성 객체로 수동 검증할 수 있는 근거 중심의
출발점을 제공합니다.

## 보안 검토 주요 기능

- 지원되는 데이터 흐름에서 SQL/명령 주입, XSS, SSRF, 오픈 리다이렉트, 경로 탐색, 안전하지 않은
  역직렬화, XXE 검토 지점을 추적합니다.
- 경로, 역할, 객체 식별자를 정리해 IDOR(CWE-639)와 권한 검사 누락 후보(CWE-862)의 수동 검증 순서를 정합니다.
- 시크릿 단서와 개인정보 흐름을 검토하고 의존성, 컨테이너, CycloneDX/SPDX SBOM, VEX, 도달 가능성
  컨텍스트를 하나의 검토 흐름으로 연결합니다.
- Dockerfile, Terraform, Kubernetes, Helm, Compose, 클라우드 IAM, CI, 모바일, 브라우저 확장, 데스크톱 앱의
  보안 설정을 검토합니다.
- CVSS 3.1/4.0, CISA SSVC, 공격 경로, 기준선, 품질 게이트로 대응 우선순위를 정하고 JSON, HTML, SARIF,
  GitLab, SBOM, VEX, 지원되는 PDF 워크플로로 공유합니다.
- 로컬 Web, CLI, CI 또는 stdio MCP를 통해 사람과 AI가 같은 증거를 활용할 수 있습니다.

## IDOR 및 수동 침투 테스트 지원

지원되는 Python 및 JavaScript/TypeScript 소스에서 내장 경로·권한 인벤토리는 권한 검사 누락 후보
(CWE-862)와 잠재적인 Insecure Direct Object Reference(IDOR) 경로(CWE-639)를 파일, 경로, 줄 번호 근거와
함께 제시합니다. 이를 통해 승인을 받은 테스터는 서로 다른 테스트 사용자, 역할, 합성 객체를 사용하는
수동 침투 테스트의 우선순위를 정할 수 있습니다.

각 후보는 승인된 범위에서 서로 다른 테스트 사용자·역할과 합성 객체로 수동 검증할 수 있는 근거 중심의
출발점을 제공합니다.

## 내장 기능과 선택형 엔진

내장 분석기, 보고서 파서, MCP 서버, CLI, 루프백 Web UI는 소스 트리에 포함됩니다. 여기에 더해 root 권한이
필요 없는 로컬 프로필로 다음 일곱 개의 버전 고정 서드파티 엔진을 선택적으로 설치할 수 있습니다.

- Nuclei 3.11.1
- Trivy 0.75.0
- Gitleaks 8.30.1
- TruffleHog 3.99.0
- Syft 1.55.0
- Grype 0.121.0
- Opengrep 1.30.1

선택형 엔진은 실행 파일, SHA-256, 필수 데이터, 입력 범위, 라이선스 준비 상태 검사를 통과한 경우에만 사용 가능한
것으로 표시됩니다. Nuclei의 광범위한 승인 HTTP 흐름에는 별도로 고정된 템플릿 카탈로그가 필요하고, Trivy의
취약점 프로필에는 별도로 고정된 오프라인 데이터베이스가 필요합니다. 내장 분석은 이 일곱 엔진과 별도로 제공됩니다. 다국어 인터페이스 및 언어 팩 안내는 [LOCALIZATION.md](LOCALIZATION.md)를 참조하세요.

## 릴리스 상태 및 포함 항목

이 저장소는 Sniper Community v1.1.0 소스 릴리스이며 Apache License 2.0([LICENSE](../LICENSE))으로 제공됩니다. 로컬 프로젝트 분석, 로컬 보고서 및 품질 게이트 명령, AI 우선 stdio MCP 워크플로, 상태 변경 작업에 대한 대화형 사람 승인 경계, 수동 CLI, 루프백 웹 인터페이스, 테스트 및 문서가 포함되어 있습니다.

## 설치

테스트된 인터프리터는 Python 3.12입니다. Community v1의 전체 네이티브 7개 선택형 엔진 설치는
Linux ARM64/x86-64에서 지원됩니다. **macOS(Apple Silicon)**에서는 네이티브 `--core-only` 소스 설치
(`python3 scripts/setup-community --core-only`)와 Docker Desktop 5개 엔진 프로필
(`./scripts/deploy-community-tools --accept-third-party-licenses`)이 **모두 실제 macOS 장비에서 검증되었으며
정식 지원됩니다(실험적 기능이 아님)**. **Windows**에서는 네이티브 `--core-only` 소스 설치
(`python3 scripts/setup-community --core-only`), WSL2, 그리고 Docker Desktop의 Linux 컨테이너를
지원합니다(자세한 검증 증거는 [VALIDATION.md](../VALIDATION.md) 및 [DEPLOYMENT.md](../DEPLOYMENT.md) 참조).

Linux에서 고정된 의존성과 로컬 도구 7개를 설치 및 검증하려면 다음을 실행합니다:

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

Linux, macOS 또는 Windows에서 선택형 Linux 엔진 바이너리 없이 네이티브 코어(`--core-only`) 소스 설치를 수행하려면 다음을 실행합니다:

```bash
python3 scripts/setup-community --core-only
```

Windows/macOS Docker Desktop 또는 WSL2에서 코어 이미지 또는 5개 엔진 이미지를 빌드하려면 다음을 실행합니다:

```bash
docker compose build sniper
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

macOS Apple Silicon + Docker Desktop에서 5개 로컬 엔진 사전 검사를 모두 빌드, 시작 및 검증하려면 `./scripts/deploy-community-tools --accept-third-party-licenses`를 실행하고, Mac 프로젝트를 영구 Docker 볼륨으로 복사하려면 `./scripts/import-community-project /absolute/path/to/project --name project-name`을 실행하세요. 설치 후 `.venv/bin/python scripts/sniper-mcp --help`, `python3 scripts/sniper-project-audit --help`, `python3 cli_reports.py --help`로 진입점을 확인할 수 있습니다. 자세한 요구 사항은 [Community 도구 설치 안내](COMMUNITY-TOOLS.md)를 참조하세요.

## MCP, CLI, 로컬 Web

- **MCP:** AI 클라이언트가 로컬 stdio 서버(`.venv/bin/python scripts/sniper-mcp --mode community`)를 통해 지원되는 컨텍스트를 검토하고 발견 사항을 설명하며 작업을 준비합니다.
- **CLI:** 사람이나 스크립트가 로컬 검토, CI 게이트, 보고서 내보내기를 실행할 수 있습니다.
- **로컬 Web:** 루프백 인터페이스(`127.0.0.1:8787`)에서 준비 상태 검사를 통과한 기능만 사람이 선택하고 검토합니다.

상태를 변경하는 Community MCP 작업은 두 단계 계약을 따릅니다. `prepare_action`이 변경할 수 없는 계획, 동의 범위,
만료 시각, SHA-256을 반환하면 AI는 그 계획을 그대로 사람에게 보여 줍니다. 같은 대화에서 사람이 명시적으로 승인한
후에만 MCP 호스트가 동일한 계획으로 `execute_action`과 `user_confirmed: true`를 보낼 수 있습니다. AI가 스스로
승인해서는 안 됩니다. 자세한 내용은 [Community MCP 안내서](COMMUNITY-MCP.md)를 참조하세요.

## 안전 및 승인 경계·검증 보고서

- 본인이 소유했거나 평가에 대한 명시적인 승인을 받은 시스템에만 사용하세요.
- 외부 작업 전에 사람이 대상, 서면 범위, 시간, 속도 제한, 데이터 처리 규칙, 중단 조건을 확인해야 합니다.
- MCP 프로세스는 로컬 stdio를 사용하지만 AI 클라이언트는 선택된 소스나 발견 사항을 모델 제공자에게 보낼 수 있습니다.
- “발견 사항 없음”은 선택한 입력, 활성화된 검사, 사용 가능한 데이터 범위만 의미하며 보안 인증이 아닙니다.
- 개인 키, 토큰, 비밀번호, 고객 데이터, 운영 데이터베이스를 이슈나 AI 프롬프트에 넣지 마세요.
- 보안 메인테이너(Security Maintainer): **Gökçe Baran Karakamış** ([@dytredline](https://github.com/dytredline)). 비공개 취약점 제보는 [SECURITY.md](../SECURITY.md), macOS 실장비 검증 및 오픈 소스 8개 저장소 감사 보고서는 [VALIDATION.md](../VALIDATION.md) 및 [SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md](SNIPER-TARANAN-DEPOLAR-VE-BAGLANTILI-ACIKLAR.md)를 참조하세요.

## 자주 묻는 질문

### Sniper Community란 무엇인가요?

Sniper Community는 승인된 소스 코드, 의존성, SBOM, 컨테이너, 인프라, 웹사이트 및 API 검토를 위한 Apache-2.0 오픈 소스 애플리케이션 보안 툴킷입니다. [기능 지도](CAPABILITIES.md)에서 내장 검사, 선택형 엔진, 수동 검토를 구분합니다.

### AI 구독 없이 Sniper를 사용할 수 있나요?

예. CLI와 로컬 웹 인터페이스에는 AI 클라이언트가 필요하지 않습니다. 선택형 MCP 클라이언트를 사용하는 경우 해당 모델 제공자의 요금 및 개인정보 정책은 Sniper 라이선스와 별개입니다.

### Windows, macOS, Linux에서 사용할 수 있나요?

예. 테스트된 인터프리터는 Python 3.12입니다. Linux ARM64 및 x86-64에서는 전체 네이티브 5개 엔진 설치를 지원합니다. **macOS(Apple Silicon)**에서는 네이티브 `--core-only` 소스 설치와 Docker Desktop 5개 엔진 프로필이 **모두 실제 macOS 장비에서 검증되었으며 정식 지원됩니다(실험적 기능이 아님)**. **Windows**에서는 네이티브 `--core-only` 소스 설치, WSL2 및 Docker Desktop을 통한 Linux 컨테이너를 지원합니다. 자세한 내용은 [DEPLOYMENT.md](../DEPLOYMENT.md) 및 [VALIDATION.md](../VALIDATION.md)를 참조하세요.

### 웹사이트의 취약점을 스캔할 수 있나요?

예. 본인이 소유하거나 명시적으로 평가 승인을 받은 웹사이트 및 API에 대해 범위가 제한된 외부 대상 작업을 준비하고 웹/TLS 증거를 로컬 소스 분석과 결합할 수 있습니다.

### 모바일 애플리케이션 취약점을 찾고 수정하는 데 도움이 되나요?

예. Android, iOS, Flutter, React Native 코드, 매니페스트, 의존성, API 경로 및 릴리스 구성을 검토하여 App Store 또는 Google Play 출시 전에 우선순위가 지정된 수정 작업으로 전환합니다.

### Sniper가 침투 테스트를 대체하거나 안전한 출시를 보장하나요?

아니요. 잠재적인 권한 및 IDOR 문제를 포함한 증거와 검토 후보를 생성하며, 자격을 갖춘 검토자가 승인된 범위 내에서 중요한 발견 사항을 검증해야 합니다.

### 공식 소스 코드와 설치 지침은 어디에 있나요?

공식 저장소는 [dytredline/Sniper](https://github.com/dytredline/Sniper)이며, 프로젝트 소개는 [ConverserAI](https://converserai.com/#sniper), 연구 인용 정보는 [CITATION.cff](../CITATION.cff), 라이선스는 Apache License 2.0([LICENSE](../LICENSE))입니다.
