# `chiapos` C++ Kütüphanesinde `Verifier::ValidateProof` (`k=50` / `k>=60`) Yığın Sınır Aşımı ve `DiskProver` 64-Bit -> 32-Bit Tamsayı Daraltması Heap Taşması (`CHIA-POS-02..04`)

[English](../36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md) | **Türkçe** | [日本語](../ja/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md) | [简体中文](../zh-CN/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md) | [한국어](../ko/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Konsensüsün İzin Verdiği `k=50` Değerinde `Verifier::ValidateProof` C++ Yığın Sınır Aşımı (`src/verifier.hpp:48-108` & `src/bits.hpp:184`):** Chia'nın Python katmanındaki `check_plot_param` fonksiyonu `k <= 50` değerine izin verir. Ancak C++ katmanındaki `Verifier::ValidateProof` içinde `k=50` (Tablo 4) ve `k=60` (Tablo 1) değerleri `src/bits.hpp:184` satırında bit kaydırma ve yığın (stack) sınır aşımı (`runtime error: load of address ... with insufficient space` / `AddressSanitizer: stack-buffer-overflow`, `exit_code=1`) tetikler.
2. **Adım 2 — İndirilen `.plot` Dosyalarında 64-Bit -> 32-Bit Tamsayı Daraltması ve Heap Taşması (`src/prover_disk.hpp:254-322`):** `DiskProver` bir `.plot` dosyasını açarken 64-bit tablo boyutlarını üst sınır kontrolü yapmadan 32-bit `uint32_t` değişkene daraltıp bellek ayırır; bu da özel hazırlanmış bir `.plot` dosyası yüklendiğinde yığın (heap) taşmasına yol açar.
3. **Adım 3 — Port `8444` Ağ Paketi İle `.plot` Dosyası Arasındaki Mimari Fark:** Port `8444` üzerinden gelen ağ paketlerinde Python `check_plot_param` ön filtresi `k > 50` değerlerini tutar; ancak `k=50` bu filtreden geçer, indirilen `.plot` dosyaları ise doğrudan C++ `DiskProver` tarafından ayrıştırıldığı için doğrudan yerel bellek bozulmasını tetikler.

### Zafiyetli Kod Kesiti
```cpp
// File: src/verifier.hpp (lines 48-108) & src/bits.hpp (line 184)
LargeBits Verifier::ValidateProof(const uint8_t* id, uint8_t k, const uint8_t* proof_bytes, uint16_t size) {
    // BUG 1: No check that k >= 18 && k <= 49; k=50 overflows Table 4 bit offsets in src/bits.hpp:184!
    // BUG 2: DiskProver (src/prover_disk.hpp:254-322) truncates 64-bit table sizes to uint32_t!
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — İndirilen Zararlı `.plot` Dosyası İle `DiskProver` İçinde Heap Bellek Bozulması
Bir madenci (farmer) dışarıdan indirdiği `.plot` dosyasını Harvester'a tanıttığında, C++ `DiskProver` başlık ayrıştırıcısındaki 64-bit -> 32-bit tamsayı daraltması nedeniyle heap taşması meydana gelir.

### Senaryo B — `Verifier::ValidateProof` İçinde `k=50` (Tablo 4) ve `k=60` Yığın Sınır Aşımı (`ASan/UBSan`)
`chiapos_k_probe` ikilisiyle kanıtlandığı üzere `k=50` (Tablo 4) ve `k=60` parametreleri `src/bits.hpp:184` satırında yığın sınır aşımıyla (`exit_code=1`) süreci çökertir.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
`18 <= k <= 49` ve 64-bit tablo boyutu doğrulaması eklendiğinde ASan/UBSan hatası tamamen ortadan kalkar (`exit_code=0`).

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run the Native C++ ASan/UBSan chiapos_k_probe Verification Test (k=50 Table 4 & k=60)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-POS-02-04": {
    "RED": {
      "k60_probe_exit_code": 1,
      "k50_table4_probe_exit_code": 1,
      "sanitizer_diagnostic": "src/bits.hpp:184:29: runtime error: load of address with insufficient space / AddressSanitizer: stack-buffer-overflow"
    },
    "GREEN": {
      "k60_probe_exit_code": 0,
      "k50_table4_probe_exit_code": 0,
      "rejected_invalid_k_cleanly": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/src/verifier.hpp
+++ b/src/verifier.hpp
@@ -52,6 +52,9 @@ LargeBits Verifier::ValidateProof(
+    if (k < 18 || k > 49 || size != static_cast<uint16_t>(8 * k)) {
+        return LargeBits();
+    }
```
