# Daytona S3 分片上传 uploadId 路径遍历与无条件 tokio::fs::remove_dir_all 任意目录删除 (`GHSA-3x8g-6h2v-8qx9`)

[English](../05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [Türkçe](../tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [日本語](../ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | **简体中文** | [한국어](../ko/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

## GitHub GHSA 与 MITRE CNA 表单快速填写字段
- **代码仓库:** `trycua/cua`
- **GitHub 安全公告 URL:** `https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`
- **现有 GHSA ID:** `GHSA-3x8g-6h2v-8qx9`
- **生态系统:** `Cargo`
- **软件包名称:** `cua-compat`
- **受影响版本:** `<= 0.8.0 (cua-spacesd <= 0.8.0, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **已修复版本:** `无（附修复补丁）`
- **CWE:** `CWE-22 (受限目录路径名限制不当 — 路径遍历)`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`
- **MITRE 厂商:** `TryCua`
- **MITRE 漏洞类型:** `Directory Traversal Leading to Arbitrary Directory Deletion (CWE-22)`
- **MITRE 受影响组件:** `libs/cua/crates/cua-compat/src/daytona/objectstore.rs (handle, lines 320-325, 360-422)`
- **MITRE 建议漏洞描述:**
  > 在 TryCua cua-compat 0.8.0 及更早版本（`trycua/cua`）中，Daytona 兼容 S3 对象存储（`libs/cua/crates/cua-compat/src/daytona/objectstore.rs`）虽然通过 `object_path(&key)` 校验了对象键以防止路径遍历，却未对 `uploadId` 查询参数进行任何校验。在 HTTP `DELETE`（`AbortMultipartUpload`）处理分支中，代码忽略了 `uploads.remove(&id)` 的返回值（不检查该 `uploadId` 是否存在），并无条件调用 `tokio::fs::remove_dir_all(root.join("uploads").join(&id))`，使拥有推送凭据的客户端能够递归删除整个对象存储或父级目录。
- **报告者 / 致谢:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `trycua/cua`（`cua-compat` crate `<= 0.8.0`，`libs/cua/crates/cua-compat/src/daytona/objectstore.rs:320-422`，提交 `e754cfec69c41400eb2aabde716c27d15607b2f0`）中，Daytona 兼容 S3 对象存储将分片上传临时目录存放在 `d.objects.root.join("uploads").join(&id)` 下。以下三处代码缺陷将 `uploadId` 查询参数变成了任意目录删除与文件写入漏洞（`CWE-22`）：

1. **步骤 1 — 未校验的 `?uploadId=` 查询参数 (`objectstore.rs:54-63, 323`)：**
   虽然 URL 路径中的 `key` 通过 `object_path(&key)` 拦截了 `Component::ParentDir`（`..`）（见第 490-496 行的测试 `keys_cannot_escape_the_store`），但第 323 行的 `let upload_id = q.get("uploadId").cloned();` 从未做任何校验，并在第 365、391、401 和 417 行直接传给 `PathBuf::join(&id)`。
2. **步骤 2 — `Method::DELETE` 分支忽略 `uploads.remove(&id)` 的返回值 (`objectstore.rs:415-417`)：**
   在 `AbortMultipartUpload`（`Method::DELETE`）分支中，`d.objects.uploads.lock().await.remove(&id);` 丢弃了返回值（`Option<Upload>`），没有检查 `.is_some()`。这意味着攻击者甚至无需事先发起任何分片上传会话。
3. **步骤 3 — 无条件执行 `tokio::fs::remove_dir_all` (`objectstore.rs:417`)：**
   第 417 行无条件执行 `tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await`，可通过 `?uploadId=../objects` 递归清空 `root/objects`，或通过 `?uploadId=../../...` 删除宿主机父级目录。

### 漏洞源码片段 (`objectstore.rs:323, 415-422`)
```rust
// File: libs/cua/crates/cua-compat/src/daytona/objectstore.rs (lines 323, 415-422)
    let upload_id = q.get("uploadId").cloned(); // BUG 1: 原始查询参数，从未检查 '..' 或路径分隔符！
...
        (Method::DELETE, Some(id), _, _) => {
            d.objects.uploads.lock().await.remove(&id); // BUG 2: 忽略返回值，id 无需真实存在！
            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await; // BUG 3: 无条件递归删除目录！
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::from(Bytes::new()))
                .unwrap()
        }
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — 单个受控沙箱租户通过 `?uploadId=../objects` 一键清空全组织所有沙箱镜像与快照
1. 在多沙箱 CUA Spaces / Daytona 部署环境中，某个沙箱运行器或租户通过 `GET /api/object-storage/push-access` 获取标准的对象存储推送凭据。
2. 该租户仅需发送一条 HTTP 请求：`DELETE /daytona/dummy?uploadId=../objects` 并附上 `Authorization: AWS4-HMAC-SHA256 Credential=<access_key>/...`（注：第 103-122 行的 `authorized()` 仅检查 `access_key` 子串，不验证 HMAC 签名）。
3. `objectstore.rs:417` 将 `root.join("uploads").join("../objects")` 解析为 `root/objects` 并调用 `tokio::fs::remove_dir_all`，瞬间清空整台服务器上存储的所有沙箱镜像与快照。

### 场景 B — 通过 `?uploadId=../../...` 逃逸出 `d.objects.root` 删除宿主机应用状态与数据库
1. 由于 Rust 的 `PathBuf::join` 会保留 `..` 路径段并交由操作系统内核在 `remove_dir_all` 时解析，传入 `?uploadId=../../state` 或 `?uploadId=../../db` 即可向上跳出 `d.objects.root`。
2. 单次 `DELETE` 请求即可销毁 `cua-spacesd` 守护进程用户可写的相邻应用状态目录、配置目录或本地数据库文件。

### 场景 C — 利用 `Method::PUT` (`UploadPart`) 任意写入文件并污染其他租户快照
1. 同一个未校验的 `uploadId` 参数也在 `Method::PUT`（`UploadPart`）分支（`objectstore.rs:364-376`）中被使用，该分支执行 `let dir = d.objects.root.join("uploads").join(&id); tokio::fs::create_dir_all(&dir)` 并将攻击者可控的字节流写入 `dir.join(format!("{part:05}"))`。
2. 攻击者可通过 `PUT` 请求跳出 `uploads/`，在宿主机文件系统的相邻存储路径中创建任意目录并写入分片文件。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-compat/src/daytona/objectstore.rs"
```

### 2. 本地隔离环境复现与验证 (`127.0.0.1`)
```bash
# 向本地 Daytona 对象存储实例发送携带路径遍历 uploadId 的 DELETE 请求
curl -i -X DELETE "http://127.0.0.1:8080/daytona/test-object?uploadId=../objects" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=daytona-access-key/20261026/us-east-1/s3/aws4_request"
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

通过 `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03` 执行的验证结果：

```json
{
  "CUA-CAND-03": {
    "ghsa_id": "GHSA-3x8g-6h2v-8qx9",
    "source_file": "cua/libs/cua/crates/cua-compat/src/daytona/objectstore.rs",
    "elapsed_ms": 0.583,
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
}
```

### Unified Diff 补丁 (`git apply --check` 验证通过)
```diff
--- a/libs/cua/crates/cua-compat/src/daytona/objectstore.rs
+++ b/libs/cua/crates/cua-compat/src/daytona/objectstore.rs
@@ -62,6 +62,13 @@
         Some(self.root.join("objects").join(BUCKET).join(key))
     }
 
+    fn upload_dir(&self, id: &str) -> Option<PathBuf> {
+        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
+            return None;
+        }
+        Some(self.root.join("uploads").join(id))
+    }
+
     pub fn stage_dir(&self) -> PathBuf {
         self.root.join("stage")
     }
@@ -413,8 +420,10 @@
             }
         }
         (Method::DELETE, Some(id), _, _) => {
-            d.objects.uploads.lock().await.remove(&id);
-            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
+            if d.objects.uploads.lock().await.remove(&id).is_some() {
+                if let Some(dir) = d.objects.upload_dir(&id) {
+                    let _ = tokio::fs::remove_dir_all(dir).await;
+                }
+            }
             Response::builder()
                 .status(StatusCode::NO_CONTENT)
```
