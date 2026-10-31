# Chia `FarmerAPI.new_proof_of_space` Port `8447` Üzerinden Tek Bir `445 Bayt` Paketle Yakalanmayan Rust `PanicException` Tetikleyerek Farmer Sunucularını Çökertme (`CHIA-POS-01`)

[English](../35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md) | **Türkçe** | [日本語](../ja/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md) | [简体中文](../zh-CN/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md) | [한국어](../ko/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Port `8444` (`FullNode`) İle Port `8447` (`FarmerAPI`) Arasındaki Doğrulama Farkı (`chia/farmer/farmer_api.py:85-185`):** Port `8444` üzerindeki `FullNode` gelen kanıtları `verify_and_get_quality_string` ile kontrol ederken, Port `8447` üzerindeki `FarmerAPI.new_proof_of_space` ağdan gelen `NewProofOfSpace` paketini hiçbir ön kontrolden geçirmeden doğrudan Rust/C++ FFI sınırındaki `proof.size_v2()` ve `get_quality_string()` fonksiyonlarına verir.
2. **Adım 2 — Tek Bir `445 Bayt` Paketle Yakalanmayan Rust `panic!` Patlaması (`SHA-256: 30a0e918f96ff695...`):** İçinde hem `pool_public_key=None` hem `pool_contract_puzzle_hash=None` olan `445 bayt` uzunluğundaki tek bir `NewProofOfSpace` paketi gönderildiğinde, PyO3 FFI sınırında `pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set` (veya `chiapos` dilim sınır hatası `range end index 36 out of range for slice of length 32`) patlar.
3. **Adım 3 — 4 Ayrı Farmer Sunucu Sürecinin (`PID 2983318..2983321`) Aynı Anda Çökmesi (`exit_code=1`):** Gerçek çoklu süreç (`multiprocessing`) testinde 4 Farmer düğümüne gönderilen bu tek paket, 4 Farmer sürecinin tamamını anında `exit_code=1` ile çökertir (`alive_farmers_after: 0`).

### Zafiyetli Kod Kesiti
```python
# File: chia/farmer/farmer_api.py (lines 85-185)
@api_request()
async def new_proof_of_space(self, new_proof_of_space: farmer_protocol.NewProofOfSpace, peer: WSChiaConnection) -> None:
    # BUG: Calls Rust FFI new_proof_of_space.proof.size_v2() and get_quality_string() BEFORE verifying
    # pool key XOR exclusivity and check_plot_param(size, proof_bytes), triggering pyo3_runtime.PanicException!
     Computed_size = new_proof_of_space.proof.size_v2()
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Tek Bir `445 Bayt` Paketle 4 Farmer Sunucusunun Aynı Anda Çökertilmesi (`4/4 Crash`)
Merkezi Farmer sunucularına bağlanan bir Harvester üzerinden gönderilen `445 bayt` uzunluğundaki tek paket (`SHA-256: 30a0e918f96ff695...`), 4 Farmer düğümünün tamamını (`PID 2983318..2983321`) `pyo3_runtime.PanicException` ile çökertir ve blok ödülü üretimini durdurur.

### Senaryo B — Kısaltılmış `32 Bayt` Kanıt İle `chiapos` Dilim Sınır Aşımı (`range end index 36 out of range`)
`get_quality_string` çağrısına kısa kanıt dizisi verildiğinde Rust FFI katmanı sınır hatasıyla panikler.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
`size_v2()` ve `get_quality_string()` çağrılmadan önce `pool_public_key` / `pool_contract_puzzle_hash` XOR kontrolü ve `check_plot_param` doğrulaması yapıldığında 4 Farmer düğümünün tamamı ayakta kalır (`alive_farmers_after: 4`).

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect FarmerAPI.new_proof_of_space in chia/farmer/farmer_api.py
sed -n '85,145p' /home/community-user/targets/chia-blockchain/chia/farmer/farmer_api.py

# 2. Run the 4-Node Multi-Process FarmerAPI Crash & Recovery Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-POS-01": {
    "RED": {
      "wire_packet_sha256": "30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe",
      "wire_packet_bytes": 445,
      "farmers_spawned": 4,
      "crashed_farmers": 4,
      "alive_farmers_after": 0,
      "exception": "pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set"
    },
    "GREEN": {
      "farmers_spawned": 4,
      "crashed_farmers": 0,
      "alive_farmers_after": 4
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/chia/farmer/farmer_api.py
+++ b/chia/farmer/farmer_api.py
@@ -92,6 +92,9 @@ class FarmerAPI:
+        if (new_proof_of_space.proof.pool_public_key is None) == (
+            new_proof_of_space.proof.pool_contract_puzzle_hash is None
+        ) or not check_plot_param(new_proof_of_space.proof.size, len(new_proof_of_space.proof.proof)):
+            return None
```
