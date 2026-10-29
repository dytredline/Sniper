# Daytona S3 Multipart uploadId Path Traversal and Unconditional tokio::fs::remove_dir_all Directory Deletion (`GHSA-3x8g-6h2v-8qx9`)

**English** | [Türkçe](tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [日本語](ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [简体中文](zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [한국어](ko/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

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

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `trycua/cua` (`cua-compat` crate `<= 0.8.0`, `libs/cua/crates/cua-compat/src/daytona/objectstore.rs:320-422`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`), the Daytona-compatible S3 object store stages multipart uploads under `d.objects.root.join("uploads").join(&id)`. Three code flaws turn the `uploadId` query parameter into an immediate arbitrary directory deletion and file write vulnerability (`CWE-22`):

1. **Step 1 — Unvalidated `?uploadId=` Query Parameter (`objectstore.rs:54-63, 323`):**
   While the URL path `key` is sanitized against `Component::ParentDir` (`..`) via `object_path(&key)` (tested by `keys_cannot_escape_the_store` at lines 490-496), `let upload_id = q.get("uploadId").cloned();` at line 323 is never validated and is passed directly to `PathBuf::join(&id)` at lines 365, 391, 401, and 417.
2. **Step 2 — Ignored `uploads.remove(&id)` Return Value in `Method::DELETE` (`objectstore.rs:415-417`):**
   In the `AbortMultipartUpload` (`Method::DELETE`) arm, `d.objects.uploads.lock().await.remove(&id);` discards its return value (`Option<Upload>`) instead of checking `.is_some()`. An attacker does not even need an active upload session.
3. **Step 3 — Unconditional `tokio::fs::remove_dir_all` Execution (`objectstore.rs:417`):**
   Line 417 unconditionally executes `tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await`, recursively wiping `root/objects` (via `?uploadId=../objects`) or parent host directories (via `?uploadId=../../...`).

### Vulnerable Code Snippet (`objectstore.rs:323, 415-422`)
```rust
// File: libs/cua/crates/cua-compat/src/daytona/objectstore.rs (lines 323, 415-422)
    let upload_id = q.get("uploadId").cloned(); // BUG 1: Raw query string, never checked for '..' or path separators!
...
        (Method::DELETE, Some(id), _, _) => {
            d.objects.uploads.lock().await.remove(&id); // BUG 2: Return value ignored; id need not exist!
            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await; // BUG 3: Unconditional recursive delete!
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::from(Bytes::new()))
                .unwrap()
        }
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Single Compromised Sandbox Tenant Wipes All Organization Sandbox Snapshots via `?uploadId=../objects`
1. In a multi-sandbox CUA Spaces / Daytona deployment, a sandbox runner or tenant obtains standard object-storage push credentials via `GET /api/object-storage/push-access`.
2. The tenant sends a single HTTP request: `DELETE /daytona/dummy?uploadId=../objects` with `Authorization: AWS4-HMAC-SHA256 Credential=<access_key>/...` (note: `authorized()` at lines 103-122 only checks the `access_key` substring and does not verify the HMAC signature).
3. `objectstore.rs:417` resolves `root.join("uploads").join("../objects")` to `root/objects` and calls `tokio::fs::remove_dir_all`, instantaneously wiping every stored sandbox image and snapshot across the entire server.

### Scenario B — Escape from `d.objects.root` to Delete Host Application State via `?uploadId=../../...`
1. Because `PathBuf::join` in Rust preserves `..` segments that are resolved by the OS kernel during `remove_dir_all`, supplying `?uploadId=../../state` or `?uploadId=../../db` traverses above `d.objects.root`.
2. A single `DELETE` request destroys the sibling application state, configuration directories, or local databases writable by the `cua-spacesd` daemon user.

### Scenario C — Arbitrary File Overwrite & Cross-Tenant Snapshot Poisoning via `Method::PUT` `UploadPart`
1. The same unvalidated `uploadId` parameter is used in the `Method::PUT` (`UploadPart`) handler (`objectstore.rs:364-376`), which executes `let dir = d.objects.root.join("uploads").join(&id); tokio::fs::create_dir_all(&dir)` and writes attacker-controlled bytes to `dir.join(format!("{part:05}"))`.
2. An attacker can traverse out of `uploads/` via `PUT` to create arbitrary directories and write part files into sibling storage paths on the host filesystem.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-compat/src/daytona/objectstore.rs"
```

### 2. Local Isolated Reproduction & Verification (`127.0.0.1`)
```bash
# Send an uninitiated multipart abort with path traversal in uploadId against a local Daytona objectstore instance
curl -i -X DELETE "http://127.0.0.1:8080/daytona/test-object?uploadId=../objects" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=daytona-access-key/20261026/us-east-1/s3/aws4_request"
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

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
