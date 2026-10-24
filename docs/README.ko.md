# Sniper Community

[English](../README.md) | [日本語](README.ja.md) | [简体中文](README.zh-CN.md) | **한국어**

Sniper Community는 애플리케이션, API, 웹사이트를 개발하거나 소유하고 검토하는 사람을 위한 오픈 소스,
로컬 우선 방어형 애플리케이션 보안 도구 모음입니다. 지원되는 소스 코드 정적 분석(SAST), 의존성 및
SBOM 분석(SCA), 컨테이너 아티팩트, 코드형 인프라(IaC), CI 설정, 저장된 보안 보고서를 하나의 검토 흐름으로
연결합니다.

본인이 소유했거나 명시적인 승인을 받은 Web/API 대상에는 실행 전에 사람이 검토하는 범위가 제한된 작업 계획을
준비할 수 있습니다. Sniper는 모든 취약점의 발견이나 시스템의 안전성을 보장하지 않습니다.

## 출시 전 AI 보안 검토

App Store 또는 Google Play 제출 전에 AI 어시스턴트를 Sniper의 로컬 stdio MCP에 연결해 지원되는 Android,
iOS, Flutter, React Native 소스와 모바일 매니페스트를 검토할 수 있습니다. API 경로, 시크릿 단서, 의존성,
SBOM, CI 구성을 하나의 출시 전 화면에서 보고 발견 사항 설명과 수정 우선순위 결정에 활용할 수 있습니다.
같은 흐름은 웹사이트/API 출시 전과 릴리스 pull request에도 사용할 수 있습니다.

## 누구에게 어떤 도움이 되는가

| 사용자 | 주요 활용 방법 |
| --- | --- |
| 애플리케이션/API 개발자 | 지원되는 코드 경로, 보안 패턴, 설정, 의존성을 로컬에서 검토 |
| 웹사이트 소유자 | 로컬 프로젝트를 검토하고 승인된 대상의 범위, 시간, 속도 제한, 중단 조건을 확인 |
| 플랫폼 팀 | Terraform, Kubernetes, Helm, Dockerfile, Compose, 클라우드 IAM, CI 워크플로를 검토 |
| 보안 검토자 | SARIF 및 지원되는 저장 보고서를 제한된 요약과 증거로 정리하고 사람이 재검토 |

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
필요 없는 로컬 프로필로 다음 다섯 개의 버전 고정 서드파티 엔진을 선택적으로 설치할 수 있습니다.

- Nuclei 3.11.1
- Trivy 0.75.0
- Gitleaks 8.30.1
- TruffleHog 3.99.0
- Opengrep 1.30.1

선택형 엔진은 실행 파일, SHA-256, 필수 데이터, 입력 범위, 라이선스 준비 상태 검사를 통과한 경우에만 사용 가능한
것으로 표시됩니다. Nuclei의 광범위한 승인 HTTP 흐름에는 별도로 고정된 템플릿 카탈로그가 필요하고, Trivy의
취약점 프로필에는 별도로 고정된 오프라인 데이터베이스가 필요합니다. 내장 분석은 이 다섯 엔진과 별도로 제공됩니다.

## MCP, CLI, 로컬 Web

- **MCP:** AI 클라이언트가 로컬 stdio 서버를 통해 지원되는 컨텍스트를 검토하고 발견 사항을 설명하며 작업을 준비합니다.
- **CLI:** 사람이나 스크립트가 로컬 검토, CI 게이트, 보고서 내보내기를 실행할 수 있습니다.
- **로컬 Web:** 루프백 인터페이스에서 준비 상태 검사를 통과한 기능만 사람이 선택하고 검토합니다.

상태를 변경하는 Community MCP 작업은 두 단계 계약을 따릅니다. `prepare_action`이 변경할 수 없는 계획, 동의 범위,
만료 시각, SHA-256을 반환하면 AI는 그 계획을 그대로 사람에게 보여 줍니다. 같은 대화에서 사람이 명시적으로 승인한
후에만 MCP 호스트가 동일한 계획으로 `execute_action`과 `user_confirmed: true`를 보낼 수 있습니다. AI가 스스로
승인해서는 안 됩니다. 자세한 내용은 [Community MCP 안내서](COMMUNITY-MCP.md)를 참조하세요.

## 설치

테스트된 인터프리터는 Python 3.12입니다. Community v1의 전체 네이티브 5개 선택형 엔진 설치는
Linux ARM64/x86-64에서 지원됩니다. macOS(Apple Silicon)에서는 네이티브 `--core-only` 소스 설치
(`python3 scripts/setup-community --core-only`)와 Docker Desktop 5개 엔진 프로필
(`./scripts/deploy-community-tools --accept-third-party-licenses`)이 모두 실제 macOS 장비에서 검증되었으며
정식 지원됩니다. Windows 네이티브 설치는 지원하지 않으며 WSL2 또는 Docker Desktop의 Linux 컨테이너를
사용합니다(자세한 검증 증거는 [VALIDATION.md](../VALIDATION.md) 및 [DEPLOYMENT.md](../DEPLOYMENT.md) 참조). 지원되는 저장소 루트에서 다음을 실행합니다.

```bash
python3 scripts/setup-community --accept-third-party-licenses
```

이 플래그는 `COMMUNITY-TOOLS.lock.json`에 기록된 서드파티 라이선스를 검토했음을 확인합니다. 설치 프로그램은
`.venv`를 만들고 고정된 의존성과 로컬 도구를 설치·검증하지만 서버, 데이터베이스, 스캐너는 시작하지 않습니다.
자세한 요구 사항은 [Community 도구 설치 안내](COMMUNITY-TOOLS.md)를 참조하세요.

## 안전 및 승인 경계

- 본인이 소유했거나 평가에 대한 명시적인 승인을 받은 시스템에만 사용하세요.
- 외부 작업 전에 사람이 대상, 서면 범위, 시간, 속도 제한, 데이터 처리 규칙, 중단 조건을 확인해야 합니다.
- MCP 프로세스는 로컬 stdio를 사용하지만 AI 클라이언트는 선택된 소스나 발견 사항을 모델 제공자에게 보낼 수 있습니다.
- “발견 사항 없음”은 선택한 입력, 활성화된 검사, 사용 가능한 데이터 범위만 의미하며 보안 인증이 아닙니다.
- 개인 키, 토큰, 비밀번호, 고객 데이터, 운영 데이터베이스를 이슈나 AI 프롬프트에 넣지 마세요.

## 공식 기능 정보

완전한 공식 기능 지도의 기준 문서는 [Capabilities and security checks](CAPABILITIES.md)입니다. 이 한국어 문서는 요약이며
지원 범위나 제한을 확장하지 않습니다. 실제 사용 사례는 [USE-CASES.md](USE-CASES.md), AI용 프로젝트 색인은
[llms.txt](../llms.txt), 재현 가능한 테스트 결과와 증거 한계는 [VALIDATION.md](../VALIDATION.md)를 참조하세요.
