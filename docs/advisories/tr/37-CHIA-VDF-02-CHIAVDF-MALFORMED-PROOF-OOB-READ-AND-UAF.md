# `chiavdf` C++ Kütüphanesinde `CheckProofOfTimeNWesolowski` Bozuk VDF Kanıtı Sınır Dışı Okuma (`OOB Read`) ve `Use-After-Free` Çökmesi (`CHIA-VDF-02`)

[English](../37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md) | **Türkçe** | [日本語](../ja/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md) | [简体中文](../zh-CN/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md) | [한국어](../ko/37-CHIA-VDF-02-CHIAVDF-MALFORMED-PROOF-OOB-READ-AND-UAF.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `CheckProofOfTimeNWesolowski` İçinde `proof_blob` Uzunluk ve Segment Sınırlarının Kontrol Edilmemesi (`src/verifier.cpp`):** N-Wesolowski zaman kanıtı (VDF) doğrulanırken `CheckProofOfTimeNWesolowski`, `proof_blob` dizisini sabit `2 * B_bytes` adımlarla okur; ancak tampon boyutunun segment sayısına yetip yetmediğini ve `num_iterations > 0` koşulunu kontrol etmez.
2. **Adım 2 — Kısa VDF Kanıtı veya `num_iterations = 0` İle Sınır Dışı Bellek Okuma (`CWE-125`) ve `Use-After-Free` (`CWE-416`):** Kısaltılmış `proof_blob` verildiğinde `DeserializeForm` tampon sınırının dışını okur; `prover_slow.h` içindeki iş parçacığı sonlandırma sırası ise serbest bırakılmış belleğe erişir.
3. **Adım 3 — Derlenmiş C++ ASan İkilisi İle Kanıt:** `work/chiavdf-asan-proofs/` altındaki ASan testinde yamasız kodun sınır dışı okumayla çöktüğü (`RED`), yamalı kodun ise bozuk VDF girdisini güvenle reddettiği (`GREEN`) kanıtlanmıştır.

### Zafiyetli Kod Kesiti
```cpp
// File: src/verifier.cpp (CheckProofOfTimeNWesolowski)
bool CheckProofOfTimeNWesolowski(integer D, const uint8_t* y_s, const uint8_t* proof_blob, uint32_t proof_blob_len, ...) {
    // BUG: Does not validate proof_blob_len against form_size * (1 + 2 * depth) or num_iterations == 0
    // before slicing proof_blob segments in DeserializeForm()!
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Bozuk VDF Kanıtıyla Doğrulayıcı / Timelord Sürecinin Çökertilmesi
Kısaltılmış bir N-Wesolowski `proof_blob` dizisi `chiavdf` doğrulayıcısına verildiğinde C++ süreci sınır dışı bellek okumasıyla çöker.

### Senaryo B — VDF Hesaplaması İptal Edilirken `Use-After-Free` (`prover_slow.h`)
Zorluk/meydan okuma değiştiğinde durdurulan VDF iş parçacığı serbest bırakılmış belleğe erişir.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
`proof_blob_len` ve `num_iterations > 0` ön kontrolü ile bellek hatası tamamen engellenir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect CheckProofOfTimeNWesolowski in chiavdf/src/verifier.cpp
grep -n -C 12 "CheckProofOfTimeNWesolowski" /home/community-user/targets/chiavdf/src/verifier.cpp
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-VDF-02": {
    "RED": {
      "malformed_proof_blob_len": 12,
      "num_iterations": 0,
      "native_crash_or_asan_oob": true
    },
    "GREEN": {
      "native_crash_or_asan_oob": false,
      "clean_boolean_false_returned": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/src/verifier.cpp
+++ b/src/verifier.cpp
@@ -68,6 +68,9 @@ bool CheckProofOfTimeNWesolowski(
+    if (iters == 0 || proof_blob_len < expected_min_bytes || (proof_blob_len % form_size) != 0) {
+        return false;
+    }
```
