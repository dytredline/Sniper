# `cni-wallet-sdk` Clear-Signing Bağımlı Teklif (Offer) Bacaklarında Kesişim (`Intersection`) Hatası İle `500 XCH` Ödeme Çıkışının Gizlenmesi (`CS-03` / `POC-4`)

[English](../26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md) | **Türkçe** | [日本語](../ja/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md) | [简体中文](../zh-CN/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md) | [한국어](../ko/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Çok Bacaklı Teklif (Offer) Hesaplamasında Kesişim (`Intersection`) Kullanılması (`clear_signing.rs`):** Bir kasa işlemi birden fazla bağımlı settlement (takas) bacağı içerdiğinde (`POC-4`), `cni-wallet-sdk` tüm ödemelerin birleşimini (`union`) almak yerine kümelerin kesişimini alır.
2. **Adım 2 — İkinci Bacaktaki `500 XCH` (`500,000,000,000,000 mojo`) Ödemenin İmza Ekranından Düşmesi:** Kasa harcaması (`3c55638a605214af...`) ve settlement harcaması (`7c05b725fb43d8fa...`) birleştiğinde, saldırgana giden `500 XCH` tutarındaki bacak kesişim kümesinde yer almadığı için Clear-Signing özetinden tamamen silinir.
3. **Adım 3 — İmzalanan İşlemin Zincir Üstünde `500 XCH` Transfer Etmesi:** Kullanıcı ekranda bu çıkışı görmeden imzayı atar; ancak konsensüs katmanında her iki bacak da geçerli olduğu için `500 XCH` saldırgana aktarılır.

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Uses set intersection across dependent settlement legs instead of accounting for every
// notarized payment outflow funded by the vault's settlement coins!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — P2P Takas Teklifinde (`Offer`) Gizlenen `500 XCH` (`500,000,000,000,000 mojo`) Ödeme Bacağı (`POC-4`)
Kullanıcı çok bacaklı bir takas teklifini imzalarken Clear-Signing ekranında ikinci bacaktaki `500 XCH` çıkışı (`7c05b725fb43d8fa...`) hiç görünmez; imza atıldığında `500 XCH` saldırgana geçer.

### Senaryo B — Kurumsal Hazine Takasında Gizli Çıkış
Hazine yöneticisi küçük bir takas onayladığını sanırken kesişim dışında bırakılan ikinci settlement bacağıyla `500 XCH` kaybeder.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
Yama sonrasında tüm settlement bacaklarının birleşimi zorunlu tutulur.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run POC-4 (500 XCH Dependent Offer Leg Set-Intersection Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc4 -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-03": {
    "RED": {
      "poc4_vault_spend_bundle_sha256": "3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8",
      "poc4_settlement_spend_bundle_sha256": "7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525",
      "omitted_outflow_mojo": 500000000000000
    },
    "GREEN": {
      "poc4_rejected_or_fully_accounted": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -210,6 +210,8 @@
+    // Union all dependent notarized payment legs rather than intersecting
```
