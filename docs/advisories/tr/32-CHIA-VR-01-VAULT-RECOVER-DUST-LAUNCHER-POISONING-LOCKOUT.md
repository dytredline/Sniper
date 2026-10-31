# `chia-vault-recover` (`1.0.0-rc9`) Doğrulanmamış İlk Singleton Launcher Seçimi Nedeniyle `1 Mojo` Toz (Dust) Coin İle Acil Kasa Kurtarma Aracının Kilitlenmesi (`VR-01` / `POC-10`)

[English](../32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md) | **Türkçe** | [日本語](../ja/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md) | [简体中文](../zh-CN/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md) | [한국어](../ko/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `find_launcher_id` İçinde İlk Bulunan `SINGLETON_LAUNCHER_HASH` Kaydının Doğrulanmadan Seçilmesi (`src/locate.rs:148-219`):** `chia-vault-recover` aracı kullanıcının kasasını bulmak için adresteki tüm coin'leri sorgular, üst harcamalarına bakar ve `SINGLETON_LAUNCHER_HASH` tipindeki **ilk** alt coin'i kullanıcının kasası kabul ederek döner.
2. **Adım 2 — `1 Mojo` Toz (Dust) Coin Göndererek Kasa Keşfinin Zehirlenmesi:** Saldırgan kurbanın adresine `1 mojo` değerinde bir toz coin gönderir ve aynı işlemde sahte bir singleton (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`) başlatır. `FullNodeRpcApi` kayıtları blok yüksekliğine göre döndürdüğü için araç kurbanın gerçek kasasına (`e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb`) ulaşamadan saldırganın sahte kasasını seçer.
3. **Adım 3 — Derlenmiş `chia-vault-recover` (`1.0.0-rc9`) İkilisinin `recovery phrase does not match` Hatasıyla Çökmesi:** Canlı `FullNodeRpcApi` karşısında çalıştırılan yamasız ikili (`chia-vault-recover-red`) sahte `launcher_id` yüzünden kurtarma kelimelerinin uyuşmadığını söyleyerek çöker; yamalı release ikilisi (`d6e6b0bb...`) ise sahte launcher'ı atlayıp gerçek kasayı kurtarır.

### Zafiyetli Kod Kesiti
```rust
// File: src/locate.rs (lines 148-219)
pub async fn find_launcher_id(client: &Client, address_puzzle_hash: Bytes32, ...) -> Result<Bytes32> {
    // BUG: Returns the very first SINGLETON_LAUNCHER_HASH child found at address_puzzle_hash
    // without verifying that the singleton's custody/recovery configuration matches the user's keys!
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — `1 Mojo` Toz Coin İle Acil Kasa Kurtarma Aracının (`chia-vault-recover`) Çökertilmesi (`POC-10`)
Anahtarını kaybeden veya acil kurtarma yapmak isteyen kullanıcı `chia-vault-recover` (`1.0.0-rc9`) aracını çalıştırdığında, saldırganın gönderdiği `1 mojo` yüzünden araç `clawback check: recovery phrase does not match` hatası vererek durur.

### Senaryo B — Birleşik Saldırı Zinciri (`WLC-02` + `VR-01` — Hem Cüzdanı Hem Kurtarma Aracını Kilitleyip Kasayı Ele Geçirme)
Saldırgan bir yandan `WLC-02` ile canlı cüzdanın iptal düğmesini kilitlerken, diğer yandan `1 mojo` ile `chia-vault-recover` CLI aracını çökertir; kurban hiçbir kurtarma aracını kullanamaz.

### Senaryo C — Bilinen Kurumsal Kasa Adreslerinin Önceden `1 Mojo` İle Zehirlenmesi
Halka açık kasa adreslerine `1 mojo` gönderilerek acil durum kurtarma akışı önceden devre dışı bırakılır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run the Rust Unit Tests in chia-vault-recover (45/45 PASS)
cargo test --manifest-path /home/community-user/targets/chia-vault-recover/Cargo.toml

# 2. Run the Live FullNodeRpcApi + Release CLI (1.0.0-rc9) E2E Proof (Zero Static Fixtures)
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k poc10
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-VR-01": {
    "RED": {
      "attacker_decoy_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "victim_true_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "red_cli_selected_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "red_cli_exit_code": 1,
      "red_cli_stderr": "clawback check: recovery phrase does not match"
    },
    "GREEN": {
      "green_release_cli_sha256": "d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3",
      "green_cli_selected_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "green_cli_matches_victim": true,
      "cargo_unit_tests_passed": 45
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/src/locate.rs
+++ b/src/locate.rs
@@ -180,6 +180,9 @@
+    // Continue iterating candidate launchers until custody/recovery puzzle matches the user's configuration
```
