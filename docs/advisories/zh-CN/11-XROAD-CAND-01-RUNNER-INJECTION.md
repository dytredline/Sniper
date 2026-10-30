# 自托管构建节点 (xrd-runner-8c) 上 _build-and-package.yml 的 github.head_ref Bash 脚本注入 (`GHSA-4fcw-7xqx-fjv5`)

[English](../11-XROAD-CAND-01-RUNNER-INJECTION.md) | [Türkçe](../tr/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [日本語](../ja/11-XROAD-CAND-01-RUNNER-INJECTION.md) | **简体中文** | [한국어](../ko/11-XROAD-CAND-01-RUNNER-INJECTION.md)

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `nordic-institute/X-Road`（提交 `38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`）中，`.github/workflows/build.yaml:14-58` 在 `pull_request` 事件上触发，声明 `permissions: contents: write, packages: write`，并以 `secrets: inherit` 调用 `.github/workflows/_build-and-package.yml`。在 `_build-and-package.yml:27, 84-91` 内部，构建任务运行在持久化自托管节点池（`runs-on: labels: xrd-runner-8c`）上，并将 `${{ github.head_ref }}` 与 `${{ github.ref_name }}` 直接插值进 bash `run:` 脚本中（`CWE-78`）：

1. **步骤 1 — 执行前的 YAML 模板字面展开 (`_build-and-package.yml:86-90`)：**
   在启动 `/bin/bash` 之前，GitHub Actions 会将 `if [[ -n "${{ github.head_ref }}" ]]; then branch_name="${{ github.head_ref }}"` 中的 `${{ github.head_ref }}` 原样替换为分支名字符串。
2. **步骤 2 — 利用 Git 分支名逃逸双引号：**
   Git 允许分支名称中包含 `"`、`;`、`$()` 和 `` ` `` 等字符。若分支名为 `feat";<command>;#`，第 87 行会被改写为 `branch_name="feat";<command>;#"`，直接跳出双引号赋值语句并将 `<command>` 作为独立的 Shell 命令执行。
3. **步骤 3 — 在携带 `secrets: inherit` 与 `packages: write` 的持久化节点 `xrd-runner-8c` 上执行 (`build.yaml:50-58`)：**
   由于该步骤运行在 `xrd-runner-8c` 上且所属工作流具备 `secrets: inherit` 和 `packages: write` 权限，注入的命令直接在自托管构建机上执行，并可访问构建机文件系统与工作流凭据。

### 漏洞源码片段 (`.github/workflows/_build-and-package.yml:26-27, 84-91`)
```yaml
# File: .github/workflows/_build-and-package.yml (lines 26-27, 84-91)
    runs-on:
      labels: xrd-runner-8c # 持久化自托管构建节点池
...
          get_branch_name() {
            local branch_name=""
            if [[ -n "${{ github.head_ref }}" ]]; then # BUG 1: 直接将模板变量展开进 bash 脚本！
              branch_name="${{ github.head_ref }}"     # BUG 2: 分支名跳出 "..." 并执行任意 Shell 命令！
              echo "🔍 Using PR source branch: ${branch_name}" >&2
            elif [[ -n "${{ github.ref_name }}" ]]; then
              branch_name="${{ github.ref_name }}"
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 精心构造的 PR 分支名在代码审查开始前即在 `xrd-runner-8c` 上执行任意 Shell 命令
1. 贡献者或被盗用的开发者账号推送一个名为 `feat";<command>;#` 的分支（其中仅包含一行无害的文档修改）并发起 Pull Request。
2. 审查人员查看 PR 的 `Files changed` 标签页时，看不到任何构建脚本或源代码被修改。
3. 当 `Setup build configuration` 步骤在 `xrd-runner-8c` 上启动时，GitHub Actions 将 `${{ github.head_ref }}` 展开进 bash 脚本，直接在自托管构建节点上执行 `<command>`。

### 场景 B — 窃取继承的仓库机密与 `packages: write` GHCR 令牌
1. 由于 `build.yaml:50-58` 声明了 `permissions: contents: write, packages: write` 并向 `_build-and-package.yml` 传递了 `secrets: inherit`，该工作流步骤拥有具备写入权限的令牌及继承的仓库机密。
2. 注入的 Shell 命令直接读取构建机运行环境，提取具有 `contents: write`、`packages: write` 权限的 `GITHUB_TOKEN` 以及继承的机密信息。
3. 攻击者可利用这些凭据向 GHCR 推送篡改后的容器镜像或修改仓库内容。

### 场景 C — 污染持久化自托管构建节点缓存与后续官方发布包
1. 由于 `xrd-runner-8c` 是持久化自托管节点而非一次性临时虚拟机，写入宿主机的数据会在后续构建任务之间持久保留。
2. 通过 `${{ github.head_ref }}` 注入的命令可在宿主机植入后台常驻进程，或污染本地 Gradle/Docker/APT 缓存。
3. 随后在同一 `xrd-runner-8c` 节点上运行的合法 `develop` 或正式发版构建会将被污染的依赖打包进官方 X-Road 构建产物中。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/X-Road \
  --include ".github/workflows/_build-and-package.yml"
```

### 2. 本地隔离环境复现与验证 (`Bash`)
```bash
# 演示 github.head_ref 直接模板展开如何跳出双引号执行命令，以及环境变量参数化的安全防护效果
bash -c '
HEAD_REF="feat\";echo INJECTED_ON_RUNNER >&2;#"
echo "--- [RED] Vulnerable inline expansion ---"
eval "if [[ -n \"${HEAD_REF}\" ]]; then branch_name=\"${HEAD_REF}\"; fi"

echo "--- [GREEN] Patched env var parameterization ---"
PR_HEAD_REF="$HEAD_REF" bash -c '\''if [[ -n "${PR_HEAD_REF}" ]]; then branch_name="${PR_HEAD_REF}"; echo "Safe literal branch_name=${branch_name}"; fi'\''
'
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01` 执行的验证结果：

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

### Unified Diff 补丁 (`git apply --check` 验证通过)
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
