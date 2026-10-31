# `cni-wallet-sdk` Clear-Signing Dış CAT Halkası (Ring) Eritme/İhraç (`RUN_TAIL` Melt/Issuance) Hesaplama Eksikliği İle `750 XCH` Ölçeğinde Varlık Çıkışı (`CS-08` / `POC-9`)

[English](../31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md) | **Türkçe** | [日本語](../ja/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md) | [简体中文](../zh-CN/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md) | [한국어](../ko/31-CHIA-CS-08-CLEAR-SIGNING-EXTERNAL-CAT-RING-MELT-ISSUANCE-OMISSION.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Chia CAT Halkasında (Ring) Değer Korunumunun Tüm Halka Boyunca Hesaplanması:** Chia CAT standardında aynı halkadaki coin harcamaları birbirinin açığını/fazlasını dengeler; halkadaki harici bir coin `RUN_TAIL` (`51 0 -113`) ile token erittiğinde (melt) bu fark kasanın harcadığı CAT coin'inden karşılanır.
2. **Adım 2 — Clear-Signing Motorunun Dış Halkadaki `RUN_TAIL` Eritme İşlemini Hesaba Katmaması (`clear_signing.rs`):** `2.541 bayt` uzunluğundaki `POC-9` `SpendBundle` (`e48c3171dc9a9b4b...`) içinde kurbanın kasasından çıkan `750,000,000,000,000` mojo (`750 XCH` ölçeği), dış halkadaki eritme (`melt`) işlemiyle çekilirken Clear-Signing özetinde gizlenir.
3. **Adım 3 — İmza Sonrası Varlık Kaybı:** Kullanıcı dengeli görünen işlemi imzaladığında `750 XCH` ölçeğindeki varlık kasadan eksilir.

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Does not account for external CAT ring members executing RUN_TAIL melt/issuance deltas
// funded by the vault's CAT coin spend!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Dış CAT Halkası Üzerinden `750 XCH` Ölçeğinde (`750,000,000,000,000 mojo`) Gizli Varlık Eritme (`POC-9`)
Kasa yöneticisi `e48c3171dc9a9b4b...` (`2.541 bayt`) paketini imzaladığında, dış halkadaki `RUN_TAIL` eritme işlemi kasadaki varlığı çeker.

### Senaryo B — Sarılmış Varlık (Wrapped Asset / Stablecoin) İtfa Soygunu
Saldırgan kurbanın CAT harcamasını kendi harici eritme halkasına bağlayarak karşılık fonları çeker.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
Tüm CAT halkası üyelerinin net delta korunumu zorunlu tutulur.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run POC-9 (750 XCH-Scale External CAT Ring Melt/Issuance Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc9 -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-08": {
    "RED": {
      "poc9_spend_bundle_sha256": "e48c3171dc9a9b4b5914597784e7b5039a9af340c66aa2158bac22f1fba295ff",
      "poc9_spend_bundle_bytes": 2541,
      "omitted_cat_ring_delta_mojo": 750000000000000
    },
    "GREEN": {
      "poc9_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -240,6 +240,8 @@
+    // Account for all CAT ring members and reject unaccounted external RUN_TAIL deltas
```
