# `cni-wallet-sdk` Clear-Signing (Şeffaf İmzalama) Motorunda `Condition::Other` Atlama Hatası İle Ekranda `0 Ücret` Gösterip `750 XCH` Çalma ve NFT Durumunu Değiştirme (`CS-01` / `POC-1 & POC-2`)

[English](../24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md) | **Türkçe** | [日本語](../ja/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md) | [简体中文](../zh-CN/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md) | [한국어](../ko/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Konsensüs Motoru (`chia_rs`) İle Clear-Signing Ayrıştırıcısı Arasındaki Uyumsuzluk (`clear_signing.rs`):** Chia konsensüs motoru CLVM koşullarının sonuna fazladan bir atom eklendiğinde (örneğin `(52 750_XCH extra_atom)`) bunu geçerli bir `RESERVE_FEE` komutu olarak çalıştırır. Buna karşılık `cni-wallet-sdk` sabit uzunluklu ayrıştırıcı kullandığı için bu koşulu `Condition::Other` olarak sınıflandırır ve hata vermeden yok sayar!
2. **Adım 2 — İmza Ekranında `Ücret: 0 XCH` Gösterip Arka Planda `750 XCH` (`750,000,000,000,000 mojo`) Çekilmesi (`POC-1`):** `b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c` (`1.105 bayt`) özetli gerçek `SpendBundle` içinde `750 XCH` tutarındaki çıkış `Condition::Other` içine saklanır; donanım/mobil cüzdan ekranında kullanıcıya `reserved_fee: 0` gösterilirken işlem imzalandığında `750 XCH` kasadan çıkar.
3. **Adım 3 — NFT `-24` Transfer Programı ve Durum Değişikliğinin Gizlenmesi (`POC-2`):** `17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128` (`3.274 bayt`) özetli `SpendBundle` içinde NFT durumunu değiştiren koşul Clear-Signing özetinde gizlenirken zincir üstünde yürütülür.

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Condition::Other(_) variants (such as overlong RESERVE_FEE opcode 52 or unparsed NFT opcodes)
// are silently ignored instead of returning Error::UnsupportedCondition / failing closed:
match condition {
    Condition::ReserveFee(fee) => reserved_fee += fee.amount,
    Condition::Other(_) => { /* silently ignored in unpatched RED! */ }
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Kurumsal Kasadan (Chia Vault) Ekranda `0 Ücret` Göstererek `750 XCH` (`750,000,000,000,000 mojo`) Boşaltma (`POC-1`)
Kasa yöneticisi rutin bir işlem imzalarken Clear-Signing ekranında `reserved_fee = 0` görür ve imzalar (`SpendBundle SHA-256: b9b614d01ee2b104...`); ancak işlem zincire girdiğinde `750 XCH` gizli ücret olarak kasadan çekilir.

### Senaryo B — NFT Transfer Programı ve Durumunun Gizlice Ele Geçirilmesi (`POC-2`)
Kullanıcı zararsız görünen bir NFT işlemini (`SpendBundle SHA-256: 17d2796f8bd6b9bf...`) imzalarken, `Condition::Other` olarak atlanan koşul zincir üstünde NFT'nin kontrolünü değiştirir.

### Senaryo C — Yamalı (`GREEN`) Davranış
`CHIA-CNI-WALLET-SDK-CLEAR-SIGNING-FIXES-20261030.patch` uygulandığında `Condition::Other` içeren her iki `SpendBundle` da imzalanmadan önce deterministik olarak reddedilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run the Clear-Signing Rust Proof Suite in cni-wallet-sdk (POC-1 & POC-2)
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc1_and_poc2 -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-01": {
    "RED": {
      "poc1_spend_bundle_sha256": "b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c",
      "poc1_spend_bundle_bytes": 1105,
      "poc1_clear_signing_displayed_fee_mojo": 0,
      "poc1_consensus_drained_fee_mojo": 750000000000000,
      "poc2_spend_bundle_sha256": "17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128",
      "poc2_spend_bundle_bytes": 3274
    },
    "GREEN": {
      "poc1_rejected_fail_closed": true,
      "poc2_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -120,6 +120,9 @@
+    if matches!(condition, Condition::Other(_)) {
+        return Err(DriverError::NonStandardInnerSpend);
+    }
```
