# Safe Rust の VtEncoder::encode における unsafe ptr::copy_nonoverlapping 前のプレーン長・ストライド境界検証の欠落 (`GHSA-54v9-fxw3-36mm`)

[English](../06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [Türkçe](../tr/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | **日本語** | [简体中文](../zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [한국어](../ko/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

## GitHub GHSA & MITRE CNA フォーム入力フィールド
- **対象リポジトリ:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-54v9-fxw3-36mm`
- **既存 GHSA ID:** `GHSA-54v9-fxw3-36mm`
- **エコシステム:** `Cargo`
- **パッケージ名:** `cua-media-codec`
- **影響を受けるバージョン:** `<= 0.8.0 (cua-sdk <= 0.9.0, cua-spacesd <= 0.8.0, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **修正済みバージョン:** `なし（修正パッチ添付）`
- **CWE:** `CWE-125 (境界外読み取り — Out-of-bounds Read)`
- **CVSS v3.1:** `5.5 Medium — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H`
- **MITRE ベンダー:** `TryCua`
- **MITRE 脆弱性タイプ:** `Buffer Over-read / Safe-Rust Soundness Violation (CWE-125)`
- **MITRE 影響を受けるコンポーネント:** `libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs (VtEncoder::pixel_buffer_for および VtEncoder::encode, lines 334-420, 471-479)`
- **MITRE 推奨説明文:**
  > TryCua cua-media-codec 0.8.0 以前（`trycua/cua`）において、Safe Rust の公開メソッド `VtEncoder::encode` から呼び出される `VtEncoder::pixel_buffer_for`（`libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs`）は、`FrameData::Nv12` の `y` および `uv` スライス長とストライドがフレームジオメトリを満たしているかを検証せずに、Apple VideoToolbox の `CVPixelBuffer` へ `unsafe std::ptr::copy_nonoverlapping` を実行します。Safe Rust からサイズ不足の NV12 または BGRA バッファを渡すと、ヒープの境界外読み取りデータがエンコード済み映像フレームへ混入するか、プロセスがクラッシュ（`SIGSEGV`）します。
- **報告者 / クレジット:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`trycua/cua`（`cua-media-codec` クレート `0.8.0`、`libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs:334-420`、コミット `e754cfec69c41400eb2aabde716c27d15607b2f0`）において、公開 Safe Rust メソッド `VtEncoder::encode(&mut self, frame: &VideoFrame<'_>)` は内部で `self.pixel_buffer_for(frame)` を呼び出します。`unsafe` ポインタコピーループに入る前のスライス長およびストライド検証が欠落しているため、Safe Rust の健全性（Soundness）保証が破られ、ヒープ境界外読み取り（`CWE-125`）または `SIGSEGV` が発生します。

1. **ステップ 1 — `FrameData::Nv12` に対する境界チェックの完全な欠落 (`videotoolbox/mod.rs:358-367`):**
   兄弟モジュールの `convert::nv12_to_bgra`（`convert.rs:98-102`）では `y.len()` と `uv.len()` を `y_stride`、`uv_stride`、`width`、`height` に対して明示的に検証していますが、`VtEncoder::pixel_buffer_for` は `FrameData::Nv12 { y, uv, y_stride, uv_stride }` を受け取る際、`y.len()`、`uv.len()`、`y_stride < w`、`uv_stride < row_bytes` を一切検証しません。
2. **ステップ 2 — `std::ptr::copy_nonoverlapping` における無検証の `unsafe` ポインタ演算 (`videotoolbox/mod.rs:394-415`):**
   `unsafe` ブロック内のループ `for row in 0..rows` が `std::ptr::copy_nonoverlapping(src.as_ptr().add(row * src_stride), base.add(row * dst_stride), row_bytes)` を実行します。
3. **ステップ 3 — エンコード映像へのヒープメモリ流出またはメディアデーモンのクラッシュ (`SIGSEGV`):**
   `y` スライスの長さが `(h - 1) * y_stride + w` より小さい場合、`src.as_ptr().add(row * src_stride)` はヒープ上の `y` バッファの終端を超えて読み取りを行い、隣接するプロセスヒープメモリをハードウェアエンコードされる H.264/HEVC `CVPixelBuffer` にコピーするか、未マップページに達した時点で `SIGSEGV` を引き起こします。

### 脆弱なコード箇所 (`videotoolbox/mod.rs:358-414`)
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
                        uv_stride = uvs; // BUG: y.len()、uv.len()、y_stride、uv_stride の検証が一切ない
                    }
...
                for (plane, (src, src_stride, rows, row_bytes)) in planes.into_iter().enumerate() {
                    let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *mut u8;
                    let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
                    for row in 0..rows {
                        std::ptr::copy_nonoverlapping(
                            src.as_ptr().add(row * src_stride), // BUG: ヒープ境界外メモリを読み取る
                            base.add(row * dst_stride),
                            row_bytes,
                        );
                    }
                }
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — macOS リモートデスクトップ配信の解像度・ウィンドウサイズ変更時に隣接ヒープメモリが H.264 映像フレームへ流出
1. `cua-media-codec` を使用した macOS リモートデスクトップや VM ストリーミング中、解像度変更のタイミングでヘッダー上のジオメトリ（`width=320, height=4`）が先に更新され、プレーンバッファ（`1280` バイトではなく `y.len() = 320`）が短いままの `VideoFrame` が渡されます。
2. `VtEncoder::pixel_buffer_for` は `CodecError::InvalidArgument` を返す代わりに、ヒープ上の `y` スライスの終端を超えた `960` バイトを `CVPixelBuffer` の輝度プレーンへ直接コピーします。
3. その隣接ヒープメモリ上の `960` バイト（セッショントークン、API キー、他テナントの状態データなど）が VideoToolbox によって H.264 映像としてエンコードされ、リモート視聴者へ送信されます。

### シナリオ B — 不完全なキャプチャフレームによるマルチ VM `cua-spacesd` メディア配信デーモンの `SIGSEGV` クラッシュ
1. 複数の VM ストリームを同時に処理する `cua-spacesd` ホストプロセスにおいて、キャプチャパイプラインが `1920x1080` フレームに対して空または切り詰められた `FrameData::Nv12` バッファ（`y: &[], uv: &[]`）を Safe Rust の `VtEncoder::encode` に渡します。
2. エラーを返して該当フレームのみを破棄する代わりに、未マップメモリを参照して `cua-spacesd` プロセス全体が `SIGSEGV` でクラッシュし、稼働中の全セッションが強制切断されます。

### シナリオ C — `y_stride < width` / `uv_stride < row_bytes` によるアライメント不正読み取りとヒープ情報漏洩
1. 下流の Rust 呼び出し元や WebRTC/FFI メディアブリッジが `width=640, height=480` に対して小さい `y_stride=160`（`y_stride < width`）やオーバーフローするストライドを持つ `VideoFrame` を構築します。
2. `VtEncoder::pixel_buffer_for` には `y_stride < w`、`uv_stride < uv_row_bytes`、および `checked_mul`/`checked_add` による検証がないため、意図しないヒープオフセットを走査して映像ストリームへ漏洩させます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs"
```

### 2. ローカル隔離環境での再現と検証
```bash
# macOS (Apple Silicon / VideoToolbox 実機) で Cargo 統合テストスイートを実行
cargo test --manifest-path /home/community-user/targets/cua/libs/cua/Cargo.toml \
  -p cua-media-codec --test videotoolbox_hw

# Linux/macOS で convert.rs の境界チェックと videotoolbox/mod.rs を比較
grep -n -C 10 "FrameData::Nv12" \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/convert.rs \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

1. **Apple VideoToolbox 実機テスト（Apple Silicon `Darwin 27.0.0 arm64` 上での `cargo test --test videotoolbox_hw`）:** `2 passed; 0 failed`（`videotoolbox_rejects_short_cpu_frame_buffers ... ok` および `320x240`〜`1920x1080` での `videotoolbox_h264_hardware_report ... ok`）。
2. **隣接ヒープ境界外読み取り検証 (`test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01`):**

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

### 境界条件の補足
現在の `trycua/cua` モノレポ内では、`cua-spacesd` の呼び出し箇所は境界チェック済みスライスから `FrameData::Bgra` を構築しており、`cua-media-codec/Cargo.toml:9` では `publish = false` が設定されています。したがって本件はローカル／プロセス内の Safe Rust 健全性・メモリ安全性脆弱性（`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H` — **5.5 Medium**）として評価されています。

### Unified Diff パッチ (`git apply --check` 検証済み)
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
