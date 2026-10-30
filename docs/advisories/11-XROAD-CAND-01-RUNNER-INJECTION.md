# Self-Hosted Runner (xrd-runner-8c) github.head_ref Bash Script Injection in _build-and-package.yml (`GHSA-4fcw-7xqx-fjv5`)

**English** | [Türkçe](tr/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [日本語](ja/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [简体中文](zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [한국어](ko/11-XROAD-CAND-01-RUNNER-INJECTION.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `nordic-institute/X-Road` (commit `38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`), `.github/workflows/build.yaml:14-58` triggers on `pull_request` with `permissions: contents: write, packages: write` and invokes `.github/workflows/_build-and-package.yml` with `secrets: inherit`. Inside `_build-and-package.yml:27, 84-91`, the job executes on the persistent self-hosted runner fleet (`runs-on: labels: xrd-runner-8c`) and interpolates `${{ github.head_ref }}` and `${{ github.ref_name }}` directly into a bash `run:` script (`CWE-78`):

1. **Step 1 — Pre-Execution YAML Template Expansion (`_build-and-package.yml:86-90`):**
   Before invoking `/bin/bash`, GitHub Actions expands `${{ github.head_ref }}` literally inside `if [[ -n "${{ github.head_ref }}" ]]; then branch_name="${{ github.head_ref }}"`.
2. **Step 2 — Double-Quote Breakout via Git Branch Name:**
   Git allows characters such as `"`, `;`, `$()`, and `` ` `` in branch names. A branch named `feat";<command>;#` rewrites line 87 into `branch_name="feat";<command>;#"`, breaking out of the double-quoted assignment and executing `<command>` as a shell statement.
3. **Step 3 — Execution on Persistent `xrd-runner-8c` With `secrets: inherit` & `packages: write` (`build.yaml:50-58`):**
   Because the step runs on `xrd-runner-8c` inside a workflow invoked with `secrets: inherit` and `packages: write`, the injected command executes directly on the self-hosted build machine with access to the runner filesystem and workflow credentials.

### Vulnerable Code Snippet (`.github/workflows/_build-and-package.yml:26-27, 84-91`)
```yaml
# File: .github/workflows/_build-and-package.yml (lines 26-27, 84-91)
    runs-on:
      labels: xrd-runner-8c # Persistent self-hosted runner fleet
...
          get_branch_name() {
            local branch_name=""
            if [[ -n "${{ github.head_ref }}" ]]; then # BUG 1: Direct template expansion into bash!
              branch_name="${{ github.head_ref }}"     # BUG 2: Branch name breaks out of "..." and executes shell commands!
              echo "🔍 Using PR source branch: ${branch_name}" >&2
            elif [[ -n "${{ github.ref_name }}" ]]; then
              branch_name="${{ github.ref_name }}"
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Crafted PR Branch Name Executes Arbitrary Shell Commands on `xrd-runner-8c` Before Code Review
1. A contributor or compromised developer account pushes a branch named `feat";<command>;#` containing a benign one-line documentation edit and opens a Pull Request.
2. Reviewers inspecting the PR's `Files changed` tab see no code modifications in any build script or source file.
3. When the `Setup build configuration` step runs on `xrd-runner-8c`, GitHub Actions expands `${{ github.head_ref }}` into the bash script and executes `<command>` on the self-hosted runner.

### Scenario B — Exfiltration of Inherited Secrets & `packages: write` GHCR Token
1. Because `build.yaml:50-58` declares `permissions: contents: write, packages: write` and passes `secrets: inherit` into `_build-and-package.yml`, the workflow step receives write-scoped tokens and inherited repository secrets.
2. The injected shell command reads the live runner environment and extracts the `GITHUB_TOKEN` (`contents: write`, `packages: write`) along with any inherited secrets.
3. An attacker can use those credentials to push tampered container images to GHCR or modify repository contents.

### Scenario C — Persistent Self-Hosted Runner Cache & Build Artifact Poisoning Across Subsequent Official Builds
1. Because `xrd-runner-8c` is a persistent self-hosted runner rather than an ephemeral VM, state written to the runner host persists across jobs.
2. A command injected via `${{ github.head_ref }}` can plant a background process on the runner host or poison local Gradle/Docker/APT caches used by the runner.
3. Subsequent legitimate `develop` or release builds executing on the same `xrd-runner-8c` node ingest the poisoned dependencies into official X-Road build artifacts.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/X-Road \
  --include ".github/workflows/_build-and-package.yml"
```

### 2. Local Isolated Reproduction & Verification (`Bash`)
```bash
# Demonstrate how direct template expansion of github.head_ref breaks out of double quotes vs safe env var parameterization
bash -c '
HEAD_REF="feat\";echo INJECTED_ON_RUNNER >&2;#"
echo "--- [RED] Vulnerable inline expansion ---"
eval "if [[ -n \"${HEAD_REF}\" ]]; then branch_name=\"${HEAD_REF}\"; fi"

echo "--- [GREEN] Patched env var parameterization ---"
PR_HEAD_REF="$HEAD_REF" bash -c '\''if [[ -n "${PR_HEAD_REF}" ]]; then branch_name="${PR_HEAD_REF}"; echo "Safe literal branch_name=${branch_name}"; fi'\''
'
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01`:

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

### Unified Diff Patch (`git apply --check` clean)
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
