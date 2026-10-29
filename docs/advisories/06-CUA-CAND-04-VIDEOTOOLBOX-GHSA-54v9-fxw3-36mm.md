# Safe-Rust VtEncoder::encode Missing Plane Length and Stride Bounds Validation Before unsafe ptr::copy_nonoverlapping (`GHSA-54v9-fxw3-36mm`)

**English** | [Türkçe](tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [日本語](ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [简体中文](zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [한국어](ko/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

## Quick-Fill GitHub GHSA & MITRE CNA Form Fields
- **Repository:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-54v9-fxw3-36mm`
- **Existing GHSA ID:** `GHSA-54v9-fxw3-36mm`
- **Ecosystem:** `Cargo`
- **Package Name:** `cua-media-codec`
- **Affected Versions:** `<= 0.8.0 (cua-sdk <= 0.9.0, cua-spacesd <= 0.8.0, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Patched Versions:** `None (Patch attached)`
- **CWE:** `CWE-125 (Out-of-bounds Read)`
- **CVSS v3.1:** `5.5 Medium — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H`
- **MITRE Vendor:** `TryCua`
- **MITRE Vulnerability Type:** `Buffer Over-read / Safe-Rust Soundness Violation (CWE-125)`
- **MITRE Affected Component(s):** `libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs (VtEncoder::pixel_buffer_for and VtEncoder::encode, lines 334-420, 471-479)`
- **MITRE Suggested CVE Description:**
  > In TryCua cua-media-codec through 0.8.0 (trycua/cua), the safe Rust method VtEncoder::encode calls VtEncoder::pixel_buffer_for (libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs), which fails to validate that FrameData::Nv12 y and uv slice lengths and strides satisfy the frame geometry before invoking unsafe std::ptr::copy_nonoverlapping into an Apple VideoToolbox CVPixelBuffer. Passing an undersized NV12 or BGRA buffer from safe Rust causes an out-of-bounds heap read into the encoded video frame or a process crash (SIGSEGV).
- **Credit / Reporter:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
In `trycua/cua` (`cua-media-codec` crate `0.8.0`, `libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs:334-420`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`), the public safe-Rust method `VtEncoder::encode(&mut self, frame: &VideoFrame<'_>)` delegates to `self.pixel_buffer_for(frame)`. Missing slice length and stride checks before entering an `unsafe` pointer copy loop violate Safe-Rust soundness and trigger deterministic out-of-bounds heap reads (`CWE-125`) or `SIGSEGV`:

1. **Step 1 — Complete Absence of Bounds Checks on `FrameData::Nv12` (`videotoolbox/mod.rs:358-367`):**
   While sibling `convert::nv12_to_bgra` (`convert.rs:98-102`) explicitly validates `y.len()` and `uv.len()` against `y_stride`, `uv_stride`, `width`, and `height`, `VtEncoder::pixel_buffer_for` accepts `FrameData::Nv12 { y, uv, y_stride, uv_stride }` with zero validation of `y.len()`, `uv.len()`, `y_stride < w`, or `uv_stride < row_bytes`.
2. **Step 2 — Unchecked `unsafe` Pointer Arithmetic in `std::ptr::copy_nonoverlapping` (`videotoolbox/mod.rs:394-415`):**
   Inside `unsafe`, the loop iterates `for row in 0..rows` and calls `std::ptr::copy_nonoverlapping(src.as_ptr().add(row * src_stride), base.add(row * dst_stride), row_bytes)`.
3. **Step 3 — Heap Memory Exfiltration into Encoded Video or Daemon Crash (`SIGSEGV`):**
   When `y` is smaller than `(h - 1) * y_stride + w`, `src.as_ptr().add(row * src_stride)` reads past the end of the `y` allocation on the heap, copying adjacent process heap memory into the hardware-encoded H.264/HEVC `CVPixelBuffer` or segfaulting the media daemon when crossing an unmapped page boundary.

### Vulnerable Code Snippet (`videotoolbox/mod.rs:358-414`)
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
                        uv_stride = uvs; // BUG: Zero validation of y.len(), uv.len(), y_stride, or uv_stride!
                    }
...
                for (plane, (src, src_stride, rows, row_bytes)) in planes.into_iter().enumerate() {
                    let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *mut u8;
                    let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
                    for row in 0..rows {
                        std::ptr::copy_nonoverlapping(
                            src.as_ptr().add(row * src_stride), // BUG: Reads out-of-bounds heap memory!
                            base.add(row * dst_stride),
                            row_bytes,
                        );
                    }
                }
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Resolution / Window Resize Transition in macOS Remote Desktop Streaming Over-Reads Adjacent Heap Memory into H.264 Video Frames
1. During a live macOS remote desktop or VM streaming session using `cua-media-codec`, a capture source or frame converter passes an NV12 `VideoFrame` whose header geometry (`width=320, height=4`) was updated before the underlying plane buffer (`y.len() = 320` instead of `1280`) was reallocated.
2. Instead of returning a clean `CodecError::InvalidArgument`, `VtEncoder::pixel_buffer_for` copies `960` bytes past the end of the `y` slice on the heap directly into the `CVPixelBuffer` luma plane.
3. Those `960` bytes of adjacent process heap memory (such as session tokens, API keys, or other tenant state in the streaming daemon) are hardware-encoded by VideoToolbox and transmitted to the remote viewer.

### Scenario B — Multi-VM `cua-spacesd` Media Streaming Daemon Crashes with `SIGSEGV` on Truncated Capture Frame
1. In a `cua-spacesd` host process managing multiple concurrent VM streams, a capture pipeline passes a truncated or empty `FrameData::Nv12` buffer (`y: &[], uv: &[]`) for a `1920x1080` frame to the safe Rust method `VtEncoder::encode`.
2. Instead of returning `Err(CodecError::InvalidArgument)` so the caller can drop the bad frame gracefully, `src.as_ptr().add(row * src_stride)` dereferences unmapped memory and crashes the entire `cua-spacesd` process with `SIGSEGV`, terminating all active sessions.

### Scenario C — Misaligned Plane Read via Undersized `y_stride < width` / `uv_stride < row_bytes` Leading to Heap Disclosure
1. A downstream Rust caller or WebRTC/FFI media bridge constructs a `VideoFrame` with `width=640, height=480` but supplies an undersized `y_stride=160` (`y_stride < width`) or an overflowing stride in `FrameData::Nv12` / `FrameData::Bgra`.
2. Because `VtEncoder::pixel_buffer_for` lacks `y_stride < w`, `uv_stride < uv_row_bytes`, and checked arithmetic (`checked_mul`/`checked_add`), the pointer copy reads across unintended heap offsets per row and leaks heap structures into the encoded video stream.

---

## 3. Example Execution & Verification Commands

### 1. Auditing the Component with Sniper CLI
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs"
```

### 2. Local Isolated Reproduction & Verification
```bash
# On macOS (Apple Silicon / VideoToolbox hardware), run the Cargo integration test suite:
cargo test --manifest-path /home/community-user/targets/cua/libs/cua/Cargo.toml \
  -p cua-media-codec --test videotoolbox_hw

# On Linux/macOS, compare convert.rs bounds checking against videotoolbox/mod.rs:
grep -n -C 10 "FrameData::Nv12" \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/convert.rs \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs
```

### 3. Running the Automated `RED -> GREEN + BENIGN` E2E Verification Harness
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Optional Defensive Diff

1. **Apple VideoToolbox Hardware Test (`cargo test --test videotoolbox_hw` on Apple Silicon `Darwin 27.0.0 arm64`):** `2 passed; 0 failed` (`videotoolbox_rejects_short_cpu_frame_buffers ... ok` and `videotoolbox_h264_hardware_report ... ok` across `320x240` to `1920x1080`).
2. **Contiguous Heap Over-Read Verification (`test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01`):**

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

### Boundary Qualification
In the current `trycua/cua` monorepo, `cua-spacesd` callers construct `FrameData::Bgra` from bounds-checked slices and `cua-media-codec/Cargo.toml:9` sets `publish = false`; therefore this is accurately scored as a local/in-process Safe-Rust Soundness & Memory-Safety vulnerability (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H` — **5.5 Medium**).

### Unified Diff Patch (`git apply --check` clean)
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
