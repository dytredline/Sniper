# `cni-wallet-sdk` Clear-Signing NFT `NEW_METADATA_INFO` Güncelleyici Koşullarının Denetlenmemesi Nedeniyle Gizli `500 XCH` Çıkışı (`CS-02` / `POC-3`)

[English](../25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md) | **Türkçe** | [日本語](../ja/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md) | [简体中文](../zh-CN/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md) | [한국어](../ko/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — NFT Katmanının Metadata Güncelleyici Programdan Dönen Koşulları Çalıştırması:** Chia NFT standardında `NEW_METADATA_INFO` (`-24`) koşulu çalıştırıldığında, metadata güncelleyici programın döndürdüğü ek CLVM koşulları da konsensüs tarafından doğrudan yürütülür.
2. **Adım 2 — Clear-Signing Motorunun Metadata Güncelleyiciden Dönen `RESERVE_FEE` Koşulunu Yok Sayması (`clear_signing.rs`):** `cni-wallet-sdk` yalnızca yeni metadata bilgisini okur, ancak güncelleyici programın döndürdüğü `500 XCH` (`500,000,000,000,000 mojo`) tutarındaki `RESERVE_FEE` koşulunu toplam çıkış/ücret hesabına katmaz.
3. **Adım 3 — Ekranda `Ücret: 0 XCH` Görünen NFT Güncellemesiyle `500 XCH` Boşaltılması (`SpendBundle SHA-256: b314b6d7411bfb8a...`):** Kullanıcı `3.300 bayt` boyutundaki `SpendBundle` işlemini ücretsiz bir NFT metadata güncellemesi sanarak imzalar; işlem ağa girdiğinde `500 XCH` kasadan çekilir.

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Evaluates NEW_METADATA_INFO metadata updater program for metadata diff,
// but ignores extra consensus conditions (e.g. RESERVE_FEE 500 XCH) returned by the updater!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — 'Ücretsiz NFT Özelliği Güncelleme' İşlemiyle Kasadan `500 XCH` (`500,000,000,000,000 mojo`) Çekilmesi
Kullanıcı imza ekranında `reserved_fee = 0` gördüğü NFT işlemini (`SpendBundle SHA-256: b314b6d7411bfb8a...`) onaylar; ancak metadata güncelleyici içindeki gizli `RESERVE_FEE` koşulu yüzünden `500 XCH` kaybeder.

### Senaryo B — Özel Metadata Güncelleyicili Tuzak NFT Transferi
Saldırgan içine tuzaklı metadata güncelleyici yerleştirdiği bir NFT'yi hedef kasaya gönderir; kasa NFT üzerinde işlem yaptığında gizli ücret koşulu tetiklenir.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
Yama sonrasında metadata güncelleyicinin ekstra konsensüs koşulu üretmesi deterministik olarak reddedilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run POC-3 (500 XCH NFT Metadata Updater Hidden Fee) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc3 -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-02": {
    "RED": {
      "poc3_spend_bundle_sha256": "b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6",
      "poc3_spend_bundle_bytes": 3300,
      "clear_signing_displayed_fee_mojo": 0,
      "consensus_drained_fee_mojo": 500000000000000
    },
    "GREEN": {
      "poc3_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -165,6 +165,9 @@
+    // Reject any non-metadata consensus condition emitted by NEW_METADATA_INFO updater
```
