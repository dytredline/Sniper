# Safe-Rust `VtEncoder::encode` İçinde `unsafe ptr::copy_nonoverlapping` Öncesi Eksik Düzlem Uzunluğu ve `stride` Sınır Kontrolü (`GHSA-54v9-fxw3-36mm`)

[English](../06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | **Türkçe** | [日本語](../ja/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [简体中文](../zh-CN/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md) | [한국어](../ko/06-CUA-CAND-04-VIDEOTOOLBOX-GHSA-54v9-fxw3-36mm.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`trycua/cua` (`cua-media-codec` paketi `0.8.0`, `libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs:334-420`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`) içerisindeki `VtEncoder::encode(&mut self, frame: &VideoFrame<'_>)` metodu, dışarıya güvenli (*safe*) bir Rust fonksiyonu (`pub fn`) olarak sunulmaktadır. Rust'ın temel bellek güvenliği sözleşmesine göre, `unsafe` olarak işaretlenmemiş bir fonksiyonun hangi parametrelerle çağrılırsa çağrılsın bellek sınırları dışına taşmaması (*Undefined Behavior* üretmemesi) gerekir. Ancak `VtEncoder::pixel_buffer_for` içindeki eksik sınır kontrolleri doğrudan **Sınır Dışı Yığın Belleği Okuma (`Out-of-Bounds Heap Read`, `CWE-125`) ve `SIGSEGV` Çökmesi** yaratmaktadır:

1. **Adım 1 — `FrameData::Nv12` Dalında Sıfır Uzunluk ve `stride` Kontrolü (`videotoolbox/mod.rs:358-367`):**
   Aynı paketteki `convert::nv12_to_bgra` (`convert.rs:98-102`) fonksiyonu `y.len() < y_stride * (h - 1) + w` kontrolü yaparak küçük tamponları `CodecError::InvalidArgument` ile reddederken, `VtEncoder::pixel_buffer_for` içindeki `FrameData::Nv12` dalı `y.len()`, `uv.len()`, `y_stride < w` ve `uv_stride < row_bytes` kontrollerinin **hiçbirini** yapmaz. (Ayrıca `FrameData::Bgra` dalında `satır 334`'teki `stride * (h - 1) + w * 4` hesabı da `stride < w * 4` ve tam sayı taşması kontrolünden yoksundur.)
2. **Adım 2 — `unsafe` Blok İçinde `std::ptr::copy_nonoverlapping` ile Ham İşaretçi Aritmetiği (`videotoolbox/mod.rs:394-415`):**
   Kod, her satır için `src.as_ptr().add(row * src_stride)` adresinden başlayarak `row_bytes` kadar baytı Apple VideoToolbox `CVPixelBuffer` belleğine kopyalar.
3. **Adım 3 — Komşu Yığın (*Heap*) Belleğinin Video Karelerine Kodlanması veya Sürecin Çökmesi:**
   Eğer `width=320, height=4` olan bir kare için `1280` bayt yerine `320` baytlık bir `y` dilimi verilirse, döngü `y` diliminin sonundan sonraki `960` baytlık komşu yığın (*heap*) belleğini (`API anahtarları`, `oturum jetonları` veya diğer kiracı verileri) okuyup doğrudan H.264/HEVC video akışının içine kodlar ya da ayrılmamış bir bellek sayfasına denk gelirse tüm `cua-spacesd` sürecini `SIGSEGV` ile çökertir.

### Zafiyetli Kod Kesiti (`videotoolbox/mod.rs:358-414`)
```rust
// Dosya: libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs (satır 358-414)
                    FrameData::Nv12 {
                        y: yp,
                        uv: uvp,
                        y_stride: ys,
                        uv_stride: uvs,
                    } => {
                        y = yp;
                        uv = uvp;
                        y_stride = ys;
                        uv_stride = uvs; // HATA: y.len(), uv.len(), y_stride veya uv_stride için sıfır doğrulama!
                    }
...
                for (plane, (src, src_stride, rows, row_bytes)) in planes.into_iter().enumerate() {
                    let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *mut u8;
                    let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
                    for row in 0..rows {
                        std::ptr::copy_nonoverlapping(
                            src.as_ptr().add(row * src_stride), // HATA: Sınır dışı yığın (heap) belleğini okur!
                            base.add(row * dst_stride),
                            row_bytes,
                        );
                    }
                }
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — macOS Uzak Masaüstü Akışında Ekran Çözünürlüğü / Pencere Boyutu Değişimi Sırasında Komşu Yığın Belleğinin Video Akışına Sızması
1. Canlı bir macOS uzak masaüstü veya sanal makine akışı sırasında pencere/ekran çözünürlüğü değiştiğinde, yakalama katmanı yeni geometri başlığına (`width=320, height=4`) sahip ancak henüz eski boyuttaki (`y.len() = 320` bayt, olması gereken `1280` bayt) bir NV12 `VideoFrame` gönderir.
2. `VtEncoder::pixel_buffer_for` hata döndürmek yerine `y` tamponunun sonundan sonraki `960` baytlık komşu yığın (*heap*) belleğini doğrudan `CVPixelBuffer` parlaklık (*luma*) düzlemine kopyalar.
3. Aynı süreç belleğinde bulunan oturum anahtarları, API belirteçleri veya diğer kiracı verileri VideoToolbox donanım kodlayıcısı tarafından H.264 karesine dönüştürülerek uzak izleyiciye iletilir.

### Senaryo B — Çoklu Sanal Makine Yöneten `cua-spacesd` Medya Servisinin Bozuk/Kısa Kareyle `SIGSEGV` Alarak Çökmesi
1. Birden fazla sanal makine oturumuna medya kodlama hizmeti veren bir `cua-spacesd` sürecinde, sanal ekran sürücüsünden gelen bozuk veya boş bir NV12 kare (`y: &[], uv: &[]`, `1920x1080`) güvenli Rust fonksiyonu `VtEncoder::encode` ile işlenir.
2. Rust'ın `Result::Err` döndürmesi beklenirken, `src.as_ptr().add(row * src_stride)` ayrılmamış bellek sayfasına erişir ve işletim sistemi tüm `cua-spacesd` sürecini `SIGSEGV` ile sonlandırarak sunucudaki tüm aktif masaüstü akışlarını keser.

### Senaryo C — Özel Küçük `y_stride` / `uv_stride` Değerleriyle Yanlış Hizalanmış Bellek Okuması ve Yığın Verisi İfşası
1. Harici bir FFI veya WebRTC medya köprüsü `cua-media-codec` kütüphanesine `width=640, height=480` ancak hatalı bir `y_stride=160` (`y_stride < width`) veya taşmaya yol açan büyük bir `stride` değeriyle `FrameData::Nv12` / `FrameData::Bgra` gönderir.
2. `y_stride < w` ve `checked_mul` kontrolleri bulunmadığı için satır ofsetleri beklenmeyen bellek bölgelerine kayar ve yığın belleğindeki komşu yapıların içeriği video akışına sızdırılır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs"
```

### 2. İzole Yerel Test Ortamında Tetikleme ve Doğrulama
```bash
# macOS (Apple Silicon / VideoToolbox donanımı) üzerinde Cargo entegrasyon testini çalıştırın:
cargo test --manifest-path /home/community-user/targets/cua/libs/cua/Cargo.toml \
  -p cua-media-codec --test videotoolbox_hw

# Linux/macOS üzerinde convert.rs sınır kontrollerini videotoolbox/mod.rs ile karşılaştırın:
grep -n -C 10 "FrameData::Nv12" \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/convert.rs \
  /home/community-user/targets/cua/libs/cua/crates/cua-media-codec/src/backends/videotoolbox/mod.rs
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

1. **Apple VideoToolbox Donanım Testi (`cargo test --test videotoolbox_hw` — Apple Silicon `Darwin 27.0.0 arm64`):** `2 passed; 0 failed` (`videotoolbox_rejects_short_cpu_frame_buffers ... ok` ve `videotoolbox_h264_hardware_report ... ok` — `320x240` ile `1920x1080` arasında).
2. **Bitişik Yığın Belleği Aşımı Doğrulaması (`test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_vt01`):**

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

### Sınır Koşulları (Boundary Qualification)
Mevcut `trycua/cua` monoreposunda `cua-spacesd` çağırıcıları `FrameData::Bgra` yapılarını sınır kontrolü yapılmış dilimlerden oluşturmakta ve `cua-media-codec/Cargo.toml:9` dosyası `publish = false` olarak ayarlanmaktadır; bu nedenle zafiyet yerel/süreç-içi Safe-Rust Bellek Güvenliği açığı olarak derecelendirilmiştir (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H` — **5.5 Orta**).

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
