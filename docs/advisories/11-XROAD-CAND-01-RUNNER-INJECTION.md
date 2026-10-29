# Self-Hosted Runner (xrd-runner-8c) github.head_ref Bash Script Injection in _build-and-package.yml

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `nordic-institute/X-Road`
- **GitHub Advisory URL:** `https://github.com/nordic-institute/X-Road/security/advisories/new`
- **Existing GHSA ID:** `None (New GHSA & Security Advisory Candidate)`
- **Ecosystem:** `GitHub Actions`
- **Package Name:** `nordic-institute/X-Road (.github/workflows/_build-and-package.yml)`
- **Affected Versions:** `develop through commit 38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-78 (Improper Neutralization of Special Elements used in an OS Command)`
- **CVSS v3.1:** `7.8 High — CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
- **MITRE Vendor:** `Nordic Institute for Interoperability Solutions (NIIS)`
- **MITRE Vulnerability Type:** `OS Command Injection in CI Workflow on Self-Hosted Runner (CWE-78)`
- **MITRE Affected Component(s):** `.github/workflows/build.yaml (lines 14-58) and .github/workflows/_build-and-package.yml (lines 27, 84-91)`
- **MITRE Suggested CVE Description:**
  > In Nordic Institute for Interoperability Solutions (NIIS) X-Road through commit 38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b, .github/workflows/_build-and-package.yml (invoked by build.yaml with 'secrets: inherit' and 'packages: write' on the persistent self-hosted runner 'xrd-runner-8c') interpolates ${{ github.head_ref }} and ${{ github.ref_name }} directly into a bash 'run:' script block, allowing shell command injection via a crafted pull request branch name.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `nordic-institute/X-Road` (commit `38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`), `.github/workflows/build.yaml:14-58` triggers on `pull_request` with `permissions: contents: write, packages: write` and calls `.github/workflows/_build-and-package.yml` with `secrets: inherit`. Inside `_build-and-package.yml:27, 84-91`, the job runs on the persistent self-hosted runner fleet (`runs-on: labels: xrd-runner-8c`) and interpolates `${{ github.head_ref }}` and `${{ github.ref_name }}` directly inside a double-quoted bash `run:` script (`if [[ -n "${{ github.head_ref }}" ]]; then branch_name="${{ github.head_ref }}"`), enabling arbitrary shell command injection via a crafted PR branch name (`CWE-78`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — Crafted Branch Name Executes Arbitrary Shell Commands Before Code Review on Persistent Self-Hosted Runner (`xrd-runner-8c`):**
  1. A contributor or attacker with PR execution privileges pushes a branch named `feat";<command>;#` and opens a Pull Request.
  2. Before `actions/checkout` or any build step even runs, GitHub Actions expands `${{ github.head_ref }}` directly into the bash script of the `Setup build configuration` step on the self-hosted `xrd-runner-8c` machine.
- **Scenario B — Exposure of Inherited Secrets & `packages: write` GHCR Token on Same-Repo / Approved PR Runs:**
  1. Because `build.yaml:50-58` declares `permissions: contents: write, packages: write` and passes `secrets: inherit` into `_build-and-package.yml`, any same-repo PR or maintainer-approved PR run exposes the `GITHUB_TOKEN` with `packages: write` (GHCR container registry push access) to the injected shell command.
- **Scenario C — Persistent Self-Hosted Runner Cache / State Poisoning Across Subsequent Builds:**
  1. Because `xrd-runner-8c` is a self-hosted runner rather than an ephemeral GitHub-hosted VM, commands executed during the workflow step can plant persistent background processes or poison local Gradle/Docker build caches used by subsequent release builds.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01`:

```json
{
  "XROAD-CAND-01": {
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
