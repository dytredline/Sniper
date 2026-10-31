# `cni-wallet-sdk` Clear-Signing Teklif Ön-Bölme (Pre-Split) Bağlamsız Hedef Ekleme (`Post-Signature Splicing`) İle BLS İmzası Bozulmadan `1.000 XCH` Yönlendirme (`CS-06` / `POC-7`)

[English](../29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md) | **Türkçe** | [日本語](../ja/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md) | [简体中文](../zh-CN/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md) | [한국어](../ko/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Ön-Bölme (`Pre-Split`) Ara Coin Çıktısının Son Alıcıya Kriptografik Olarak Bağlanmaması (`clear_signing.rs`):** Kullanıcı `1.000 XCH` (`1,000,000,000,000,000 mojo`) tutarındaki bir Offer ön-bölme paketini (`476b8e836e435eec...`, `1.994 bayt`) imzalarken, Clear-Signing ara coin harcamasının kasanın imzaladığı bir anonsla (`ASSERT_PUZZLE_ANNOUNCEMENT`) kilitlenip kilitlenmediğini doğrulamaz.
2. **Adım 2 — Kullanıcı İmzaladıktan Sonra Alt Harcamanın Değiştirilmesi (`Post-Signature Splicing`):** Kurban imzayı attıktan sonra saldırgan alt harcamayı değiştirerek `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` (`1.701 bayt`) özetli yeni `SpendBundle` paketini oluşturur.
3. **Adım 3 — BLS İmzası Hiç Bozulmadan `1.000 XCH`'nin Saldırgana Akarılması:** Kurbanın ilk attığı BLS imzası yeni pakette de tamamen geçerli kalır ve `1.000 XCH` kurbanın onayladığı alıcı yerine doğrudan saldırganın adresine gider!

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Accepts pre-split / intermediate child spends in Clear-Signing without verifying
// that the vault's signed spend asserts an announcement binding the child spend's outputs!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Kullanıcı İmzaladıktan Sonra İmza Bozulmadan `1.000 XCH`'nin (`1,000,000,000,000,000 mojo`) Saldırgana Yönlendirilmesi (`POC-7`)
Kurban ekranda doğru alıcıyı görerek `476b8e836e435eec...` paketini imzalar; saldırgan imza sonrası alt harcamayı değiştirip `5b3a3b21376bfdfe...` paketini ağa sürer ve aynı BLS imzasıyla `1.000 XCH`'yi çalar.

### Senaryo B — Mempool Üzerinde İmzasız Alt Harcamanın Değiştirilmesi
Ağdaki bir gözlemci imzasız alt harcamayı blok kazılmadan önce kendi adresiyle değiştirir.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
Kasa tarafından kriptografik anonsla bağlanmamış tüm ön-bölme/alt harcamalar reddedilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run POC-7 (1,000 XCH Offer Pre-Split Post-Signature Splicing) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc7 -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-06": {
    "RED": {
      "poc7_pre_split_spend_bundle_sha256": "476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833",
      "poc7_pre_split_bytes": 1994,
      "poc7_spliced_final_spend_bundle_sha256": "5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93",
      "poc7_spliced_final_bytes": 1701,
      "redirected_amount_mojo": 1000000000000000,
      "original_bls_signature_valid_on_spliced": true
    },
    "GREEN": {
      "poc7_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -285,6 +285,8 @@
+    // Require pre-split and child spends to be bound via signed announcement
```
