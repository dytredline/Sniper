# `cni-wallet-sdk` Clear-Signing Açılmamış (Unrevealed) Settlement Harcaması Kör Noktası İle İmza Sonrası `600 XCH` Çekilmesi (`CS-04` / `POC-5`)

[English](../27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md) | **Türkçe** | [日本語](../ja/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md) | [简体中文](../zh-CN/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md) | [한국어](../ko/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `SETTLEMENT_PAYMENT_HASH` Coin'lerinin Ek İmza Gerektirmeden Harcanabilmesi:** Kasa harcaması içinden `SETTLEMENT_PAYMENT_HASH` adresine bir coin oluşturulduğunda, bu settlement coin'in harcanması için kasanın ek bir BLS imzasına ihtiyaç yoktur.
2. **Adım 2 — Settlement Harcaması Paketten Gizlendiğinde Clear-Signing'in Çıkışı Görmemesi (`clear_signing.rs`):** `POC-5` içinde kasa harcaması (`a9eeda2c8526d95c...`, `1.303 bayt`) `600 XCH` (`600,000,000,000,000 mojo`) değerinde bir settlement coin üretir ancak bu coin'in nereye gideceğini gösteren harcamayı imza öncesi pakete koymaz; yamasız Clear-Signing bunu zararsız kabul eder.
3. **Adım 3 — Kullanıcı İmzaladıktan Sonra Saldırganın `600 XCH` Settlement Harcamasını (`e0b876fbb8e0f264...`) Pakete Eklemesi:** İmza alındıktan sonra saldırgan `388 bayt` uzunluğundaki settlement harcamasını pakete ekleyerek `600 XCH`'yi kendi adresine çeker.

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Allows a vault spend to create a SETTLEMENT_PAYMENT_HASH coin without requiring
// the corresponding settlement CoinSpend to be revealed and verified in the signing bundle!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — İmza Sırasında Gizlenen Settlement Harcamasının İmza Sonrasında Eklenerek `600 XCH` (`600,000,000,000,000 mojo`) Çalınması (`POC-5`)
Kurban `a9eeda2c8526d95c...` paketini imzalarken ekranda dışarıya giden bir alıcı görmez; saldırgan imzalı paketin yanına `e0b876fbb8e0f264...` settlement harcamasını ekleyip `600 XCH`'yi çeker.

### Senaryo B — Donanım Cüzdanlarında (Air-Gapped Signer) Kör İmzalama
Çevrimdışı imzalayıcı cihazda alıcı adresi görünmeden `600 XCH` çıkışına imza attırılır.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
Karşılığı pakette açılmamış (`unrevealed`) settlement çıktısı içeren işlemler imzalanmadan reddedilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run POC-5 (600 XCH Unrevealed Settlement Spend Blind Spot) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc5 -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-04": {
    "RED": {
      "poc5_vault_spend_bundle_sha256": "a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb",
      "poc5_vault_spend_bundle_bytes": 1303,
      "poc5_attached_settlement_spend_bundle_sha256": "e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe",
      "poc5_attached_settlement_bytes": 388,
      "hidden_outflow_mojo": 600000000000000
    },
    "GREEN": {
      "poc5_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -315,6 +315,8 @@
+    // Require every created settlement coin to have its corresponding spend revealed in the bundle
```
