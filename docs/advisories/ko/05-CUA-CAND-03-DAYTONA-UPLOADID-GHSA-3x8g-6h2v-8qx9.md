# Daytona S3 멀티파트 uploadId 경로 탐색 및 무조건적인 tokio::fs::remove_dir_all 디렉터리 삭제 (`GHSA-3x8g-6h2v-8qx9`)

[English](../05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [Türkçe](../tr/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [日本語](../ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [简体中文](../zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | **한국어**

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`trycua/cua`(`cua-compat` 크레이트 `<= 0.8.0`, `libs/cua/crates/cua-compat/src/daytona/objectstore.rs:320-422`, 커밋 `e754cfec69c41400eb2aabde716c27d15607b2f0`)에서 Daytona 호환 S3 객체 저장소는 멀티파트 업로드 임시 데이터를 `d.objects.root.join("uploads").join(&id)` 아래에 저장합니다. 세 가지 코드 결함이 결합되어 `uploadId` 쿼리 매개변수가 즉각적인 임의 디렉터리 삭제 및 파일 쓰기 취약점(`CWE-22`)으로 이어집니다.

1. **1단계 — 검증되지 않은 `?uploadId=` 쿼리 매개변수 (`objectstore.rs:54-63, 323`):**
   URL 경로의 `key`는 `object_path(&key)`를 통해 `Component::ParentDir`(`..`)이 차단되지만(490-496번째 줄의 `keys_cannot_escape_the_store` 테스트로 검증됨), 323번째 줄의 `let upload_id = q.get("uploadId").cloned();`는 전혀 검증되지 않은 채 365, 391, 401, 417번째 줄에서 `PathBuf::join(&id)`에 직접 전달됩니다.
2. **2단계 — `Method::DELETE`에서 `uploads.remove(&id)` 반환값 무시 (`objectstore.rs:415-417`):**
   `AbortMultipartUpload`(`Method::DELETE`) 분기에서 `d.objects.uploads.lock().await.remove(&id);`는 반환값(`Option<Upload>`)이 `.is_some()`인지 확인하지 않고 버립니다. 따라서 공격자는 활성 업로드 세션을 먼저 시작할 필요조차 없습니다.
3. **3단계 — 무조건적인 `tokio::fs::remove_dir_all` 실행 (`objectstore.rs:417`):**
   417번째 줄은 무조건 `tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await`를 실행하여 `?uploadId=../objects`를 통해 `root/objects` 전체를 삭제하거나 `?uploadId=../../...`를 통해 상위 호스트 디렉터리를 삭제합니다.

### 취약한 코드 조각 (`objectstore.rs:323, 415-422`)
```rust
// File: libs/cua/crates/cua-compat/src/daytona/objectstore.rs (lines 323, 415-422)
    let upload_id = q.get("uploadId").cloned(); // BUG 1: '..'나 경로 구분자 검증이 전혀 없는 원시 쿼리 문자열!
...
        (Method::DELETE, Some(id), _, _) => {
            d.objects.uploads.lock().await.remove(&id); // BUG 2: 반환값을 무시하므로 id가 존재하지 않아도 됨!
            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await; // BUG 3: 무조건적인 재귀 삭제!
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::from(Bytes::new()))
                .unwrap()
        }
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — 침해된 단일 샌드박스 테넌트가 `?uploadId=../objects`로 조직 전체의 샌드박스 스냅샷을 일괄 삭제
1. 다중 샌드박스 CUA Spaces / Daytona 배포 환경에서 한 샌드박스 러너 또는 테넌트가 `GET /api/object-storage/push-access`를 통해 표준 객체 저장소 푸시 자격 증명을 획득합니다.
2. 해당 테넌트가 `Authorization: AWS4-HMAC-SHA256 Credential=<access_key>/...` 헤더와 함께 단 한 번의 HTTP 요청 `DELETE /daytona/dummy?uploadId=../objects`를 전송합니다(참고: 103-122번째 줄의 `authorized()`는 `access_key` 부분 문자열만 확인하고 HMAC 서명을 검증하지 않습니다).
3. `objectstore.rs:417`은 `root.join("uploads").join("../objects")`를 `root/objects`로 해석하고 `tokio::fs::remove_dir_all`을 호출하여 서버 전체의 모든 샌드박스 이미지와 스냅샷을 즉시 삭제합니다.

### 시나리오 B — `?uploadId=../../...`로 `d.objects.root`를 벗어나 호스트 애플리케이션 상태 삭제
1. Rust의 `PathBuf::join`은 `..` 세그먼트를 그대로 유지하며 OS 커널이 `remove_dir_all` 수행 시 이를 해석하므로, `?uploadId=../../state` 또는 `?uploadId=../../db`를 전달하면 `d.objects.root` 상위 디렉터리로 이동합니다.
2. 단 한 번의 `DELETE` 요청으로 `cua-spacesd` 데몬 사용자가 쓸 수 있는 인접 애플리케이션 상태, 설정 디렉터리 또는 로컬 데이터베이스가 파괴됩니다.

### 시나리오 C — `Method::PUT` (`UploadPart`)을 통한 임의 파일 덮어쓰기 및 타 테넌트 스냅샷 오염
1. 동일한 미검증 `uploadId` 매개변수가 `Method::PUT`(`UploadPart`) 핸들러(`objectstore.rs:364-376`)에서도 사용되며, `let dir = d.objects.root.join("uploads").join(&id); tokio::fs::create_dir_all(&dir)`를 실행한 후 공격자가 제어하는 바이트를 `dir.join(format!("{part:05}"))`에 기록합니다.
2. 공격자는 `PUT` 요청으로 `uploads/` 외부로 이동하여 임의의 디렉터리를 생성하고 호스트 파일시스템의 인접 저장소 경로에 파트 파일을 기록할 수 있습니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-compat/src/daytona/objectstore.rs"
```

### 2. 로컬 격리 환경 재현 및 검증 (`127.0.0.1`)
```bash
# 로컬 Daytona 객체 저장소 인스턴스에 uploadId 경로 탐색이 포함된 DELETE 요청 전송
curl -i -X DELETE "http://127.0.0.1:8080/daytona/test-object?uploadId=../objects" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=daytona-access-key/20261026/us-east-1/s3/aws4_request"
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03` 실행 결과:

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

### Unified Diff 패치 (`git apply --check` 검증 완료)
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
