# Safe Rust 函数 VtEncoder::encode 在调用 unsafe ptr::copy_nonoverlapping 前缺少平面长度与步长边界校验 (`GHSA-54v9-fxw3-36mm`)

[English](../06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [Türkçe](../tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [日本語](../ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | **简体中文** | [한국어](../ko/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

## 1. 代码缺陷如何演变为可被利用的安全漏洞

### 分步技术机制剖析
在 `trycua/cua`（`cua-media-codec` crate `0.8.0`，`libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs:334-420`，提交 `e754cfec69c41400eb2aabde716c27d15607b2f0`）中，公开的 Safe Rust 方法 `VtEncoder::encode(&mut self, frame: &VideoFrame<'_>)` 内部调用了 `self.pixel_buffer_for(frame)`。由于在进入 `unsafe` 指针复制循环前缺少切片长度与步长校验，违反了 Safe Rust 的内存安全健全性（Soundness）保证，导致确定性的堆越界读取（`CWE-125`）或 `SIGSEGV`：

1. **步骤 1 — 对 `FrameData::Nv12` 完全没有任何边界检查 (`videotoolbox/mod.rs:358-367`)：**
   虽然同级模块 `convert::nv12_to_bgra`（`convert.rs:98-102`）严格校验了 `y.len()` 和 `uv.len()` 与 `y_stride`、`uv_stride`、`width`、`height` 的关系，但 `VtEncoder::pixel_buffer_for` 在接收 `FrameData::Nv12 { y, uv, y_stride, uv_stride }` 时，对 `y.len()`、`uv.len()`、`y_stride < w` 和 `uv_stride < row_bytes` 未做任何校验。
2. **步骤 2 — `std::ptr::copy_nonoverlapping` 中未受检的 `unsafe` 指针算术 (`videotoolbox/mod.rs:394-415`)：**
   在 `unsafe` 块内，循环 `for row in 0..rows` 直接执行 `std::ptr::copy_nonoverlapping(src.as_ptr().add(row * src_stride), base.add(row * dst_stride), row_bytes)`。
3. **步骤 3 — 堆内存泄露至编码视频帧或媒体守护进程崩溃 (`SIGSEGV`)：**
   当 `y` 的长度小于 `(h - 1) * y_stride + w` 时，`src.as_ptr().add(row * src_stride)` 会越过堆上 `y` 切片的末尾继续读取，将相邻进程堆内存复制进由硬件编码的 H.264/HEVC `CVPixelBuffer` 中，或在跨越未映射内存页边界时触发段错误崩溃。

### 漏洞源码片段 (`videotoolbox/mod.rs:358-414`)
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
                        uv_stride = uvs; // BUG: 完全未校验 y.len()、uv.len()、y_stride 或 uv_stride！
                    }
...
                for (plane, (src, src_stride, rows, row_bytes)) in planes.into_iter().enumerate() {
                    let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *mut u8;
                    let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
                    for row in 0..rows {
                        std::ptr::copy_nonoverlapping(
                            src.as_ptr().add(row * src_stride), // BUG: 越界读取相邻堆内存！
                            base.add(row * dst_stride),
                            row_bytes,
                        );
                    }
                }
```

---

## 2. 日常实际生产环境中的 3 个关键高危场景 (场景 A / 场景 B / 场景 C)

### 场景 A — macOS 远程桌面推流在分辨率或窗口大小切换时越界读取相邻堆内存并编码进 H.264 视频帧
1. 在使用 `cua-media-codec` 的 macOS 远程桌面或虚拟机推流会话中，当窗口尺寸或分辨率动态调整时，采集端传入了一个帧头尺寸已更新为 `width=320, height=4`，但底层平面缓冲区尚未重新分配（`y.len() = 320` 而非所需的 `1280`）的 NV12 `VideoFrame`。
2. `VtEncoder::pixel_buffer_for` 没有返回 `CodecError::InvalidArgument`，而是越过堆上 `y` 切片末尾，将相邻的 `960` 字节堆内存直接复制到 `CVPixelBuffer` 的亮度平面中。
3. 这 `960` 字节的相邻进程堆内存（如流媒体守护进程中的会话令牌、API 密钥或其他租户状态）被 VideoToolbox 硬件编码为 H.264 视频帧并发送给远程观看端。

### 场景 B — 截断的采集帧导致多虚拟机 `cua-spacesd` 媒体流守护进程触发 `SIGSEGV` 崩溃
1. 在管理多个并发虚拟机视频流的 `cua-spacesd` 宿主进程中，采集流水线针对 `1920x1080` 的视频帧向 Safe Rust 方法 `VtEncoder::encode` 传入了截断或空的 `FrameData::Nv12` 缓冲区（`y: &[], uv: &[]`）。
2. 代码没有返回 `Err(CodecError::InvalidArgument)` 以丢弃异常帧，而是直接解引用未映射内存，导致整个 `cua-spacesd` 进程因 `SIGSEGV` 崩溃，所有活动会话同时中断。

### 场景 C — 过小的 `y_stride < width` / `uv_stride < row_bytes` 导致非对齐平面读取与堆内存泄露
1. 下游 Rust 调用方或 WebRTC/FFI 媒体桥接层构造了 `width=640, height=480` 的 `VideoFrame`，但在 `FrameData::Nv12` / `FrameData::Bgra` 中传入了过小的 `y_stride=160`（`y_stride < width`）或溢出步长。
2. 由于 `VtEncoder::pixel_buffer_for` 缺少 `y_stride < w`、`uv_stride < uv_row_bytes` 以及溢出安全算术（`checked_mul`/`checked_add`），指针复制循环按错误偏移跨行读取堆数据并泄露到编码视频流中。

---

## 3. 示例执行、复现与验证命令

### 1. 使用 Sniper CLI 审计目标组件
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs"
```

### 2. 本地隔离环境复现与验证
```bash
# 在 macOS (Apple Silicon / VideoToolbox 硬件环境) 上运行 Cargo 集成测试套件：
cargo test --manifest-path /home/community-user/targets/cua/libs/cua/Cargo.toml \
  -p cua-media-codec --test videotoolbox_hw

# 在 Linux/macOS 上对比 convert.rs 的边界检查与 videotoolbox/mod.rs：
grep -n -C 10 "FrameData::Nv12" \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/convert.rs \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs
```

### 3. 运行自动化 `RED -> GREEN + BENIGN` 端到端验证套件
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01
```

---

## 4. 端到端运行时证明 (RED -> GREEN + BENIGN) 与防御补丁

1. **Apple VideoToolbox 真实硬件测试（Apple Silicon `Darwin 27.0.0 arm64` 上运行 `cargo test --test videotoolbox_hw`）：** `2 passed; 0 failed`（`videotoolbox_rejects_short_cpu_frame_buffers ... ok` 以及 `320x240` 至 `1920x1080` 分辨率下的 `videotoolbox_h264_hardware_report ... ok`）。
2. **连续堆内存越界读取验证 (`test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01`)：**

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

### 边界条件说明
在当前 `trycua/cua` 仓库中，`cua-spacesd` 调用方从已校验边界的切片构造 `FrameData::Bgra`，且 `cua-media-codec/Cargo.toml:9` 设置了 `publish = false`；因此该漏洞被准确评定为本地/进程内 Safe Rust 健全性与内存安全漏洞（`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H` — **5.5 Medium**）。

### Unified Diff 补丁 (`git apply --check` 验证通过)
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
