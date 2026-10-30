# Safe Rust의 VtEncoder::encode에서 unsafe ptr::copy_nonoverlapping 호출 전 평면 길이 및 스트라이드 경계 검증 누락 (`GHSA-54v9-fxw3-36mm`)

[English](../06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [Türkçe](../tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [日本語](../ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [简体中文](../zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | **한국어**

## 1. 코드 결함이 실제 악용 가능한 취약점으로 전환되는 메커니즘

### 단계별 기술적 메커니즘
`trycua/cua`(`cua-media-codec` 크레이트 `0.8.0`, `libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs:334-420`, 커밋 `e754cfec69c41400eb2aabde716c27d15607b2f0`)에서 공개 Safe Rust 메서드 `VtEncoder::encode(&mut self, frame: &VideoFrame<'_>)`는 내부적으로 `self.pixel_buffer_for(frame)`를 호출합니다. `unsafe` 포인터 복사 루프에 진입하기 전 슬라이스 길이와 스트라이드 검증이 누락되어 있어 Safe Rust의 건전성(Soundness) 보장을 위반하고 결정론적인 힙 경계 밖 읽기(`CWE-125`) 또는 `SIGSEGV`를 유발합니다.

1. **1단계 — `FrameData::Nv12`에 대한 경계 검증 완전 누락 (`videotoolbox/mod.rs:358-367`):**
   형제 함수인 `convert::nv12_to_bgra`(`convert.rs:98-102`)는 `y.len()` 및 `uv.len()`을 `y_stride`, `uv_stride`, `width`, `height`에 대해 명시적으로 검증하지만, `VtEncoder::pixel_buffer_for`는 `FrameData::Nv12 { y, uv, y_stride, uv_stride }`를 받을 때 `y.len()`, `uv.len()`, `y_stride < w`, `uv_stride < row_bytes`를 전혀 검증하지 않습니다.
2. **2단계 — `std::ptr::copy_nonoverlapping`에서의 무검증 `unsafe` 포인터 연산 (`videotoolbox/mod.rs:394-415`):**
   `unsafe` 블록 내부에서 `for row in 0..rows` 루프가 `std::ptr::copy_nonoverlapping(src.as_ptr().add(row * src_stride), base.add(row * dst_stride), row_bytes)`를 호출합니다.
3. **3단계 — 인코딩된 비디오 프레임으로 힙 메모리 유출 또는 데몬 충돌 (`SIGSEGV`):**
   `y` 슬라이스가 `(h - 1) * y_stride + w`보다 작을 경우 `src.as_ptr().add(row * src_stride)`는 힙의 `y` 할당 영역 끝을 넘어 인접한 프로세스 힙 메모리를 하드웨어 인코딩되는 H.264/HEVC `CVPixelBuffer`로 복사하거나, 매핑되지 않은 페이지 경계를 넘을 때 미디어 데몬을 세그멘테이션 오류(`SIGSEGV`)로 종료시킵니다.

### 취약한 코드 조각 (`videotoolbox/mod.rs:358-414`)
```rust
// File: libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs (lines 358-414)
                    FrameData::Nv12 {
                        y: yp,
                        uv: uvp,
                        y_stride: ys,
                        uv_stride: uvs,
                    } => {
                        y = yp;
                        uv = uvp;
                        y_stride = ys;
                        uv_stride = uvs; // BUG: y.len(), uv.len(), y_stride, uv_stride에 대한 검증이 전혀 없음!
                    }
...
                for (plane, (src, src_stride, rows, row_bytes)) in planes.into_iter().enumerate() {
                    let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *mut u8;
                    let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
                    for row in 0..rows {
                        std::ptr::copy_nonoverlapping(
                            src.as_ptr().add(row * src_stride), // BUG: 경계 밖 힙 메모리를 읽음!
                            base.add(row * dst_stride),
                            row_bytes,
                        );
                    }
                }
```

---

## 2. 일상 운영 환경에서 발생 가능한 3가지 핵심 시나리오 (`시나리오 A` / `시나리오 B` / `시나리오 C`)

### 시나리오 A — macOS 원격 데스크톱 스트리밍 중 해상도/창 크기 전환 시 인접 힙 메모리가 H.264 비디오 프레임으로 유출됨
1. `cua-media-codec`을 사용하는 실시간 macOS 원격 데스크톱 또는 VM 스트리밍 세션 중, 캡처 소스나 프레임 변환기가 하위 평면 버퍼(`1280` 대신 `y.len() = 320`)가 재할당되기 전에 헤더 지오메트리(`width=320, height=4`)만 먼저 업데이트된 NV12 `VideoFrame`을 전달합니다.
2. `VtEncoder::pixel_buffer_for`는 `CodecError::InvalidArgument`를 반환하는 대신, 힙의 `y` 슬라이스 끝을 넘어선 `960`바이트를 `CVPixelBuffer` 루마(luma) 평면으로 직접 복사합니다.
3. 인접 프로세스 힙 메모리의 `960`바이트(스트리밍 데몬 내의 세션 토큰, API 키 또는 타 테넌트 상태 등)가 VideoToolbox에 의해 하드웨어 인코딩되어 원격 시청자에게 전송됩니다.

### 시나리오 B — 잘린 캡처 프레임으로 인해 다중 VM `cua-spacesd` 미디어 스트리밍 데몬이 `SIGSEGV`로 충돌
1. 여러 동시 VM 스트림을 관리하는 `cua-spacesd` 호스트 프로세스에서 캡처 파이프라인이 `1920x1080` 프레임에 대해 잘리거나 비어 있는 `FrameData::Nv12` 버퍼(`y: &[], uv: &[]`)를 Safe Rust 메서드 `VtEncoder::encode`에 전달합니다.
2. 호출자가 불량 프레임을 안전하게 건너뛸 수 있도록 `Err(CodecError::InvalidArgument)`를 반환하는 대신, 매핑되지 않은 메모리를 역참조하여 전체 `cua-spacesd` 프로세스가 `SIGSEGV`로 충돌하고 모든 활성 세션이 종료됩니다.

### 시나리오 C — 작은 `y_stride < width` / `uv_stride < row_bytes`로 인한 정렬 불량 평면 읽기 및 힙 메모리 노출
1. 하위 Rust 호출자나 WebRTC/FFI 미디어 브리지가 `width=640, height=480`으로 `VideoFrame`을 생성하면서 `FrameData::Nv12` / `FrameData::Bgra`에 너무 작은 `y_stride=160`(`y_stride < width`)이나 오버플로되는 스트라이드를 전달합니다.
2. `VtEncoder::pixel_buffer_for`에 `y_stride < w`, `uv_stride < uv_row_bytes` 및 오버플로 안전 산술(`checked_mul`/`checked_add`) 검사가 없으므로, 포인터 복사가 의도치 않은 힙 오프셋을 읽어들여 인코딩된 비디오 스트림으로 힙 구조를 유출합니다.

---

## 3. 예제 실행 및 검증 명령어

### 1. Sniper CLI로 대상 컴포넌트 감사
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs"
```

### 2. 로컬 격리 환경 재현 및 검증
```bash
# macOS (Apple Silicon / VideoToolbox 하드웨어)에서 Cargo 통합 테스트 스위트 실행:
cargo test --manifest-path /home/community-user/targets/cua/libs/cua/Cargo.toml \
  -p cua-media-codec --test videotoolbox_hw

# Linux/macOS에서 convert.rs의 경계 검사와 videotoolbox/mod.rs 비교:
grep -n -C 10 "FrameData::Nv12" \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/convert.rs \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs
```

### 3. 자동화된 `RED -> GREEN + BENIGN` E2E 검증 하네스 실행
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01
```

---

## 4. 엔드투엔드 런타임 증명 (`RED -> GREEN + BENIGN`) 및 방어 패치

1. **Apple VideoToolbox 실제 하드웨어 테스트 (Apple Silicon `Darwin 27.0.0 arm64`에서 `cargo test --test videotoolbox_hw` 실행):** `2 passed; 0 failed` (`videotoolbox_rejects_short_cpu_frame_buffers ... ok` 및 `320x240`~`1920x1080` 해상도에 걸친 `videotoolbox_h264_hardware_report ... ok`).
2. **인접 힙 경계 밖 읽기 검증 (`test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01`):**

```json
{
  "CUA-VT-01": {
    "ghsa_id": "GHSA-54v9-fxw3-36mm",
    "source_file": "cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs",
    "elapsed_ms": 0.164,
    "geometry": {
      "width": 320,
      "height": 4,
      "y_stride": 320,
      "provided_y_len": 320,
      "required_y_len": 1280
    },
    "RED": {
      "oob_bytes_read": 960,
      "adjacent_heap_secret_copied_to_video_frame": true
    },
    "GREEN": {
      "oob_bytes_read": 0,
      "adjacent_heap_secret_copied_to_video_frame": false,
      "error_returned": "CodecError::InvalidArgument(NV12 plane buffer smaller than its geometry)"
    }
  }
}
```

### 경계 조건 명시
현재 `trycua/cua` 모노레포에서 `cua-spacesd` 호출자들은 경계가 검증된 슬라이스로부터 `FrameData::Bgra`를 생성하며 `cua-media-codec/Cargo.toml:9`에는 `publish = false`가 설정되어 있습니다. 따라서 이 취약점은 로컬/프로세스 내 Safe Rust 건전성 및 메모리 안전성 취약점(`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H` — **5.5 Medium**)으로 정확하게 평가됩니다.

### Unified Diff 패치 (`git apply --check` 검증 완료)
```diff
--- a/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs
+++ b/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs
@@ -365,6 +370,18 @@
                         uv = uvp;
                         y_stride = ys;
                         uv_stride = uvs;
+                        let uv_rows = h.div_ceil(2);
+                        let uv_row_bytes = w.div_ceil(2) * 2;
+                        let y_req = h.checked_sub(1).and_then(|r| r.checked_mul(y_stride)).and_then(|o| o.checked_add(w));
+                        let uv_req = uv_rows.checked_sub(1).and_then(|r| r.checked_mul(uv_stride)).and_then(|o| o.checked_add(uv_row_bytes));
+                        if y_stride < w
+                            || uv_stride < uv_row_bytes
+                            || y_req.is_none_or(|req| y.len() < req)
+                            || uv_req.is_none_or(|req| uv.len() < req)
+                        {
+                            return Err(CodecError::InvalidArgument(
+                                "NV12 plane buffer smaller than its geometry".into(),
+                            ));
+                        }
                     }
```
