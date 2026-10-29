# 자체 호스팅 러너 (xrd-runner-8c)의 _build-and-package.yml 내 github.head_ref Bash 스크립트 인젝션 (`GHSA-4fcw-7xqx-fjv5`)

[English](../11-XROAD-CAND-01-RUNNER-INJECTION.md) | [Türkçe](../tr/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [日本語](../ja/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [简体中文](../zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md) | **한국어**

## GitHub GHSA 및 MITRE CNA 양식 필드 요약
- **저장소:** `nordic-institute/X-Road`
- **GitHub 보안 권고 URL:** `https://github.com/nordic-institute/X-Road/security/advisories/GHSA-4fcw-7xqx-fjv5`
- **기존 GHSA ID:** `GHSA-4fcw-7xqx-fjv5`
- **에코시스템:** `GitHub Actions`
- **패키지 이름:** `nordic-institute/X-Road (.github/workflows/_build-and-package.yml)`
- **영향받는 버전:** `develop 브랜치 커밋 38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b 이하`
- **패치된 버전:** `없음 (패치 첨부)`
- **CWE:** `CWE-78 (OS 명령에 사용되는 특수 요소의 부적절한 무력화 — OS 명령 인젝션)`
- **CVSS v3.1:** `7.8 High — CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
- **MITRE 벤더:** `Nordic Institute for Interoperability Solutions (NIIS)`
- **MITRE 취약점 유형:** `OS Command Injection in CI Workflow on Self-Hosted Runner (CWE-78)`
- **MITRE 영향받는 컴포넌트:** `.github/workflows/build.yaml (lines 14-58) 및 .github/workflows/_build-and-package.yml (lines 27, 84-91)`
- **MITRE 권장 CVE 설명:**
  > Nordic Institute for Interoperability Solutions (NIIS) X-Road 커밋 `38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b` 이하에서, 영구 자체 호스팅 러너 `xrd-runner-8c`에서 `build.yaml`에 의해 `secrets: inherit` 및 `packages: write` 권한으로 호출되는 `.github/workflows/_build-and-package.yml`은 `${{ github.head_ref }}` 및 `${{ github.ref_name }}`을 bash `run:` 스크립트 블록에 직접 보간하여, 조작된 풀 리퀘스트 브랜치 이름을 통한 셸 명령 인젝션을 허용합니다.
- **제보자 / 크레딧:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`nordic-institute/X-Road`(커밋 `38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`)에서 `.github/workflows/build.yaml:14-58`은 `pull_request` 이벤트에서 `permissions: contents: write, packages: write`로 트리거되며 `secrets: inherit`를 사용해 `.github/workflows/_build-and-package.yml`을 호출합니다. `_build-and-package.yml:27, 84-91` 내부에서 해당 잡은 영구 자체 호스팅 러너 풀(`runs-on: labels: xrd-runner-8c`)에서 실행되며 `${{ github.head_ref }}`와 `${{ github.ref_name }}`을 bash `run:` 스크립트에 직접 보간합니다(`CWE-78`).

1. **1단계 — 실행 전 YAML 템플릿 리터럴 확장 (`_build-and-package.yml:86-90`):**
   `/bin/bash`를 호출하기 전에 GitHub Actions는 `if [[ -n "${{ github.head_ref }}" ]]; then branch_name="${{ github.head_ref }}"` 내부의 `${{ github.head_ref }}`를 문자 그대로 치환합니다.
2. **2단계 — Git 브랜치 이름을 통한 큰따옴표 탈출:**
   Git은 브랜치 이름에 `"`, `;`, `$()`, `` ` `` 등의 문자를 허용합니다. `feat";<command>;#`라는 이름의 브랜치는 87번째 줄을 `branch_name="feat";<command>;#"`으로 재작성하여 큰따옴표 할당문을 벗어나 `<command>`를 셸 명령문으로 실행합니다.
3. **3단계 — `secrets: inherit` 및 `packages: write`가 부여된 영구 `xrd-runner-8c` 러너에서의 실행 (`build.yaml:50-58`):**
   이 단계는 `secrets: inherit` 및 `packages: write`가 전달된 워크플로 내부의 `xrd-runner-8c`에서 실행되므로, 주입된 명령이 러너 파일시스템과 워크플로 자격 증명에 대한 접근 권한을 가지고 자체 호스팅 빌드 머신에서 직접 실행됩니다.

### 취약한 코드 조각 (`.github/workflows/_build-and-package.yml:26-27, 84-91`)
```yaml
# File: .github/workflows/_build-and-package.yml (lines 26-27, 84-91)
    runs-on:
      labels: xrd-runner-8c # 영구 자체 호스팅 러너 풀
...
          get_branch_name() {
            local branch_name=""
            if [[ -n "${{ github.head_ref }}" ]]; then # BUG 1: bash 내부로 직접 템플릿 확장!
              branch_name="${{ github.head_ref }}"     # BUG 2: 브랜치 이름이 "..."를 벗어나 임의 셸 명령 실행!
              echo "🔍 Using PR source branch: ${branch_name}" >&2
            elif [[ -n "${{ github.ref_name }}" ]]; then
              branch_name="${{ github.ref_name }}"
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 조작된 PR 브랜치 이름으로 코드 리뷰 전에 `xrd-runner-8c`에서 임의 셸 명령 실행
1. 기여자 또는 탈취된 개발자 계정이 무해한 한 줄짜리 문서 수정만 포함된 `feat";<command>;#` 브랜치를 푸시하고 Pull Request를 엽니다.
2. PR의 `Files changed` 탭을 검토하는 리뷰어에게는 빌드 스크립트나 소스 파일의 수정 사항이 전혀 보이지 않습니다.
3. `xrd-runner-8c`에서 `Setup build configuration` 단계가 실행되면 GitHub Actions가 `${{ github.head_ref }}`를 bash 스크립트로 확장하여 자체 호스팅 러너에서 `<command>`를 즉시 실행합니다.

### 시나리오 B — 상속된 시크릿 및 `packages: write` GHCR 토큰 유출
1. `build.yaml:50-58`이 `permissions: contents: write, packages: write`를 선언하고 `_build-and-package.yml`에 `secrets: inherit`를 전달하므로, 워크플로 단계는 쓰기 권한이 있는 토큰과 상속된 저장소 시크릿을 전달받습니다.
2. 주입된 셸 명령은 실행 중인 러너 환경을 읽어 `GITHUB_TOKEN`(`contents: write`, `packages: write`)과 상속된 시크릿을 추출합니다.
3. 공격자는 이러한 자격 증명을 사용해 변조된 컨테이너 이미지를 GHCR에 푸시하거나 저장소 콘텐츠를 수정할 수 있습니다.

### 시나리오 C — 영구 자체 호스팅 러너 캐시 및 후속 공식 빌드 아티팩트 오염
1. `xrd-runner-8c`는 일회성 임시 VM이 아닌 영구 자체 호스팅 러너이므로 러너 호스트에 기록된 상태가 여러 잡에 걸쳐 유지됩니다.
2. `${{ github.head_ref }}`를 통해 주입된 명령은 러너 호스트에 백그라운드 프로세스를 심거나 러너가 사용하는 로컬 Gradle/Docker/APT 캐시를 오염시킬 수 있습니다.
3. 이후 동일한 `xrd-runner-8c` 노드에서 실행되는 정상적인 `develop` 또는 릴리스 빌드가 오염된 의존성을 공식 X-Road 빌드 아티팩트에 포함하게 됩니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/X-Road \
  --include ".github/workflows/_build-and-package.yml"
```

### 2. 로컬 격리 환경 재현 및 검증 (`Bash`)
```bash
# github.head_ref 직접 템플릿 확장이 큰따옴표를 탈출하는 방식과 안전한 환경 변수 매개변수화 비교
bash -c '
HEAD_REF="feat\";echo INJECTED_ON_RUNNER >&2;#"
echo "--- [RED] Vulnerable inline expansion ---"
eval "if [[ -n \"${HEAD_REF}\" ]]; then branch_name=\"${HEAD_REF}\"; fi"

echo "--- [GREEN] Patched env var parameterization ---"
PR_HEAD_REF="$HEAD_REF" bash -c '\''if [[ -n "${PR_HEAD_REF}" ]]; then branch_name="${PR_HEAD_REF}"; echo "Safe literal branch_name=${branch_name}"; fi'\''
'
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01` 실행 결과:

```json
{
  "XROAD-CAND-01": {
    "ghsa_id": "GHSA-4fcw-7xqx-fjv5",
    "build_workflow": "x-road/.github/workflows/build.yaml",
    "package_workflow": "x-road/.github/workflows/_build-and-package.yml",
    "elapsed_ms": 5.513,
    "RED": {
      "direct_yaml_interpolation": true,
      "arbitrary_command_executed_on_self_hosted_runner": true
    },
    "GREEN": {
      "env_var_parameterized": true,
      "arbitrary_command_executed_on_self_hosted_runner": false
    }
  }
}
```

### Unified Diff 패치 (`git apply --check` 검증 완료)
```diff
--- a/.github/workflows/_build-and-package.yml
+++ b/.github/workflows/_build-and-package.yml
@@ -72,6 +72,9 @@
       - name: Setup build configuration
         id: build-config
         working-directory: ./src
+        env:
+          PR_HEAD_REF: ${{ github.head_ref }}
+          GIT_REF_NAME: ${{ github.ref_name }}
         run: |
@@ -84,11 +87,11 @@
           get_branch_name() {
             local branch_name=""
-            if [[ -n "${{ github.head_ref }}" ]]; then
-              branch_name="${{ github.head_ref }}"
+            if [[ -n "${PR_HEAD_REF}" ]]; then
+              branch_name="${PR_HEAD_REF}"
               echo "🔍 Using PR source branch: ${branch_name}" >&2
-            elif [[ -n "${{ github.ref_name }}" ]]; then
-              branch_name="${{ github.ref_name }}"
+            elif [[ -n "${GIT_REF_NAME}" ]]; then
+              branch_name="${GIT_REF_NAME}"
```
