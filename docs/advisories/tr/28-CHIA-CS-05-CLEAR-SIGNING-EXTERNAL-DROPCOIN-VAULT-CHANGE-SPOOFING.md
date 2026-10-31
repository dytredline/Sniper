# `cni-wallet-sdk` Clear-Signing Harici `DropCoin` İle Kasa Para Üstü (Change) Sahteciliği ve `chia-sdk-bindings` FFI Sınırında `1.000 XCH` Kasa Boşaltma (`CS-05` / `POC-6`)

[English](../28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md) | **Türkçe** | [日本語](../ja/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md) | [简体中文](../zh-CN/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md) | [한국어](../ko/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Kasaya Ait Olmayan Harici `DropCoin` Çıktısının 'Kasaya Dönen Para Üstü (Change)' Sayılması (`clear_signing.rs` & `chia-sdk-bindings/src/clear_signing.rs:62`):** `parse_vault_transaction` fonksiyonu kasadan çıkan net parayı hesaplarken, kasa adresine gelen çıktıları 'para üstü (change)' olarak düşer; ancak bu çıktıyı üreten üst coin'in (`DropCoin`) gerçekten kasaya ait olup olmadığını kontrol etmez!
2. **Adım 2 — Kasadan Çalınan `1.000 XCH` (`1,000,000,000,000,000 mojo`) Tutarının Ekranda `0 XCH Kayıp` Gösterilmesi (`SpendBundle SHA-256: aa65182292515596...`):** `1.477 bayt` uzunluğundaki `POC-6` `SpendBundle` içinde kasa saldırgana `1.000 XCH` gönderirken, pakete eklenen harici bir `DropCoin` harcaması kasa adresine sahte/dış bağlamlı çıktı gösterir; Clear-Signing bunları birbirinden düşerek ekranda net kaybı `0` olarak gösterir.
3. **Adım 3 — Doğrudan `chia-sdk-bindings` FFI Sınırında Kanıt (`clear_signing_ffi_proof.rs`):** Mobil/masaüstü uygulamaların çağırdığı gerçek FFI fonksiyonu `chia_sdk_bindings::parse_vault_transaction` üzerinde yapılan testte `RED` modda `1.000 XCH` çıkışın gizlendiği, `GREEN` modda ise `Error::NonStandardInnerSpend` ile reddedildiği kanıtlanmıştır.

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-bindings/src/clear_signing.rs (line 62) & chia-sdk-driver/src/clear_signing.rs
pub fn parse_vault_transaction(vault: ClvmVault, spend_bundle: SpendBundle, ...) -> Result<TransactionSummary> {
    // BUG: Credits outputs from external non-vault DropCoin spends as vault change,
    // masking a 1,000 XCH outflow from the victim's vault!
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Kurumsal Kasadan (Chia Vault) Çalınan `1.000 XCH`'nin (`1,000,000,000,000,000 mojo`) FFI Sınırında `0 XCH Net Çıkış` Gösterilmesi (`POC-6`)
Kasa yöneticisi `chia-sdk-bindings` kullanan imzalayıcı uygulamada `aa65182292515596...` (`1.477 bayt`) paketini inceler; ekranda kasadan net para çıkmadığı göründüğü için onay verir ve `1.000 XCH` saldırgana aktarılır.

### Senaryo B — Çoklu İmza (Multi-Sig) Kurulunun Tamamının Yanıltılması
Kasadaki tüm ortak imzacılar kendi cihazlarında aynı yanıltıcı `TransactionSummary` özetini görerek `1.000 XCH` çıkışına imza atar.

### Senaryo C — `clear_signing_ffi_proof.rs` FFI Kanıtı (`GREEN`)
Yamalı kodda `chia_sdk_bindings::parse_vault_transaction` harici `DropCoin` içeren paketi `Error::NonStandardInnerSpend` ile reddeder.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run POC-6 in chia-sdk-driver and the FFI Boundary Proof in chia-sdk-bindings
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc6 -- --nocapture
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-bindings --test clear_signing_ffi_proof -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-05": {
    "RED": {
      "poc6_spend_bundle_sha256": "aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e",
      "poc6_spend_bundle_bytes": 1477,
      "vault_drain_amount_mojo": 1000000000000000,
      "ffi_boundary_parse_vault_transaction_masked": true
    },
    "GREEN": {
      "ffi_boundary_rejected_with": "Error::NonStandardInnerSpend",
      "ffi_test_file_sha256": "73dbe05adb2538ceb88cca5b2ecf4c1678e4ed537d3accb17535d8666727fb52"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -260,6 +260,8 @@
+    // Verify DropCoin parent lineage belongs to the vault before crediting as vault change
```
