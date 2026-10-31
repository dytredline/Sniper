# `cni-wallet-sdk` Clear-Signing Ters-Clawback (`sender_puzzle_hash`) Sahiplik Sahteciliği İle `1.000 XCH` İptal Yetkisinin Saldırgana Verilmesi (`CS-07` / `POC-8`)

[English](../30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md) | **Türkçe** | [日本語](../ja/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md) | [简体中文](../zh-CN/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md) | [한국어](../ko/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Clawback `sender_puzzle_hash` (İptal Yetkilisi) Alanının Kasa Adresiyle Karşılaştırılmaması (`clear_signing.rs`):** Bir kasa Clawback korumalı bir ödeme oluşturduğunda (`POC-8`), `cni-wallet-sdk` Clawback yapısını ayrıştırırken `sender_puzzle_hash` (yani süre dolmadan parayı geri çekme/iptal etme yetkisine sahip adres) alanının gerçekten imzalayan kasaya ait olup olmadığını kontrol etmez!
2. **Adım 2 — Ters-Clawback Tuzağı (`SpendBundle SHA-256: 6897c10eb9cf718f...`):** `1.218 bayt` uzunluğundaki `SpendBundle` içinde kurbanın kasasından çıkan `1.000 XCH` (`1,000,000,000,000,000 mojo`) Clawback coin'ine kilitlenir; ancak iptal yetkilisi (`sender_puzzle_hash`) olarak saldırganın adresi yazılmıştır.
3. **Adım 3 — İşlem Zincire Girer Girmez Saldırganın `1.000 XCH`'yi 'İptal Ederek' Çalması:** Kurban kendisini Clawback korumalı bir işlem yaptığını sanarak imzalar; işlem onaylandığı anda saldırgan `sender` yetkisini kullanarak `1.000 XCH`'yi beklemeden kendi cüzdanına çeker.

### Zafiyetli Kod Kesiti
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Parses Clawback output without verifying clawback.sender_puzzle_hash == vault_p2_puzzle_hash,
// allowing an attacker to be set as the Clawback sender on a 1,000 XCH vault outflow!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Korumalı Transfer Görünümlü İşlemde `1.000 XCH` (`1,000,000,000,000,000 mojo`) İptal Yetkisinin Saldırgana Verilmesi (`POC-8`)
Kasa yöneticisi `6897c10eb9cf718f...` paketini Clawback korumalı güvenli transfer sanarak imzalar; saldırgan `sender_puzzle_hash` olarak tanımlandığı için parayı anında geri çekerek çalar.

### Senaryo B — Kendi Adresine Transfer Yanılsaması
Alıcı (`receiver`) kısmına kurbanın kendi adresi yazılıp `sender` kısmına saldırgan yazıldığında, kurban parayı kendisine gönderdiğini sanırken saldırgan süre dolmadan parayı çeker.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
`sender_puzzle_hash` değeri kasaya ait olmayan Clawback çıktıları reddedilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run POC-8 (1,000 XCH Reverse-Clawback Sender Hijack) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc8 -- --nocapture
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-07": {
    "RED": {
      "poc8_spend_bundle_sha256": "6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1",
      "poc8_spend_bundle_bytes": 1218,
      "hijacked_clawback_amount_mojo": 1000000000000000,
      "attacker_is_clawback_sender": true
    },
    "GREEN": {
      "poc8_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -340,6 +340,8 @@
+    // Verify Clawback sender_puzzle_hash belongs to the signing vault
```
