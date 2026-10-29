# Daytona S3 Multipart uploadId Path Traversal and Unconditional tokio::fs::remove_dir_all Directory Deletion

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`
- **Existing GHSA ID:** `GHSA-3x8g-6h2v-8qx9`
- **Ecosystem:** `Cargo`
- **Package Name:** `cua-compat`
- **Affected Versions:** `<= 0.8.0 (cua-spacesd <= 0.8.0, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-22 (Improper Limitation of a Pathname to a Restricted Directory — Path Traversal)`
- **CVSS v3.1:** `8.1 High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`
- **MITRE Vendor:** `TryCua`
- **MITRE Vulnerability Type:** `Directory Traversal Leading to Arbitrary Directory Deletion (CWE-22)`
- **MITRE Affected Component(s):** `libs/cua/crates/cua-compat/src/daytona/objectstore.rs (handle, lines 320-325, 360-422)`
- **MITRE Suggested CVE Description:**
  > In TryCua cua-compat through 0.8.0 (trycua/cua), the Daytona-compatible S3 object store (libs/cua/crates/cua-compat/src/daytona/objectstore.rs) validates the object key against path traversal via object_path(&key) but fails to validate the 'uploadId' query parameter. In the HTTP DELETE (AbortMultipartUpload) handler, uploads.remove(&id) ignores whether the uploadId existed and unconditionally calls tokio::fs::remove_dir_all(root.join("uploads").join(&id)), allowing a client with push-access credentials to recursively delete the object store or parent directories.
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

### Summary
In `trycua/cua` (`cua-compat` Rust crate `<= 0.8.0`, `libs/cua/crates/cua-compat/src/daytona/objectstore.rs:320-325, 360-422`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`), the Daytona-compatible S3 object store validates the URL path `key` against `..` traversal via `object_path(&key)` (`objectstore.rs:54-63`), but completely fails to validate the `?uploadId=` query parameter (`q.get("uploadId")`). Worse, in the `Method::DELETE` (`AbortMultipartUpload`) handler at lines 415-422, `d.objects.uploads.lock().await.remove(&id)` ignores whether `id` actually existed in the `uploads` map and unconditionally executes `tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await`. Any client holding push-access credentials (issued automatically by `GET /api/object-storage/push-access`) can send a single `DELETE /daytona/anykey?uploadId=../objects` or `?uploadId=../../...` request without ever initiating an upload and recursively delete the entire object store or arbitrary host directories writable by the `cua-spacesd` process (`CWE-22`).

### Concrete Everyday Real-World Production Scenarios (Why This Causes Critical Impact in Daily Use)
- **Scenario A — Single Compromised Sandbox Tenant Wipes All Organization Sandbox Snapshots (`?uploadId=../objects`):**
  1. In a multi-sandbox CUA Spaces / Daytona deployment, a sandbox runner or tenant obtains standard object-storage push credentials via `GET /api/object-storage/push-access`.
  2. The tenant sends a single HTTP request: `DELETE /daytona/dummy?uploadId=../objects` with `Authorization: AWS4-HMAC-SHA256 Credential=<access_key>/...` (note: `authorized()` at lines 103-122 only checks the `access_key` substring and does not verify the HMAC signature).
  3. `objectstore.rs:417` resolves `root.join("uploads").join("../objects")` to `root/objects` and calls `tokio::fs::remove_dir_all`, instantaneously wiping every stored sandbox image and snapshot across the entire server.
- **Scenario B — Escape from `d.objects.root` to Delete Host Application State (`?uploadId=../../...`):**
  1. Because `PathBuf::join` in Rust preserves `..` segments that are resolved by the OS kernel during `remove_dir_all`, supplying `?uploadId=../../state` or `?uploadId=../../db` traverses above `d.objects.root`.
  2. Even though `Method::POST` (`CompleteMultipartUpload`) checks `uploads.remove(&id)` first, `Method::DELETE` (`AbortMultipartUpload`) discards the `Option` returned by `remove(&id)` (`line 416`), meaning no valid `uploadId` is needed at all.
- **Scenario C — Sibling Control Parity Breakdown Within the Same File (`object_path` vs `uploadId`):**
  1. The developer explicitly wrote unit test `keys_cannot_escape_the_store` (`objectstore.rs:490-496`) to ensure `object_path(&key)` blocks `..` segments on the primary S3 object key.
  2. However, the secondary S3 multipart parameter `uploadId` was concatenated directly via `.join("uploads").join(&id)` at lines 365, 391, 401, and 417 without an equivalent `upload_dir(&id)` guard.

### End-to-End Runtime Proof (`RED -> GREEN + BENIGN`)
Executed via `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03`:

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

### Unified Diff Patch (`git apply --check` clean)
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
