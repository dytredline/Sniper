# Chia Cüzdanında Doğrulanmamış `RespondRemovals` / `RespondCoinState` İle Hayalet Harcanmış (`Spent`) Zehirlemesi ve Zaman Kilitli Clawback İptal Kilidi (`WLC-02`)

[English](../21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md) | **Türkçe** | [日本語](../ja/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md) | [简体中文](../zh-CN/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md) | [한국어](../ko/21-CHIA-WLC-02-CLAWBACK-PHANTOM-SPENT-POISONING-LOCKOUT.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Kanıtsız (`proofs=None`) `RespondRemovals` / `spent_height` Bildiriminin Doğrulanmadan Kabul Edilmesi (`wallet_node.py:725-777` & `wallet_state_manager.py:1735-1778`):** Cüzdan P2P ağından gelen `RespondRemovals(height=8, coins=[(coin_name, None)], proofs=None)` mesajını işlerken, blok başlığına bağlı Merkle silinme kanıtını (`validate_removals`) doğrulamadan SQLite `WalletCoinStore` içinde coin'i `spent_height=8` (harcanmış) olarak işaretler.
2. **Adım 2 — 24 Saatlik Clawback İptal Düğmesinin Kalıcı Olarak Kilitlenmesi (`t1_cold_reloaded_sqlite_spent: true`):** Kurban yanlış adrese veya dolandırıcıya gönderdiği `0.5 XCH` (`500,000,000,000 mojo`) tutarındaki Clawback korumasını iptal etmek istediğinde, cüzdan veritabanı soğuk yeniden başlatılsa bile coin'i 'zaten harcanmış' sandığı için iptal işlemi üretemez (`t2_sender_cancel_tx_count: 0`).
3. **Adım 3 — Süre Dolunca Saldırganın Gerçek Zincirdeki Parayı Çekmesi (`SpendBundle SHA-256: 33361e6b2d8ee0d9...`):** Coin gerçek blokzincirinde hiç harcanmadığı için, zaman kilidi dolduğu saniyede (`t4`) saldırgan geçerli `SpendBundle` (`930 bayt`) ile `0.5 XCH`'yi kendi cüzdanına çeker.

### Zafiyetli Kod Kesiti
```python
# File: chia/wallet/wallet_node.py (lines 725-777) & wallet_state_manager.py (lines 1735-1778)
# BUG: Accepts RespondRemovals with proofs=None or unverified spent_height without Merkle proof verification
if not validate_removals(coin_Main, proofs, peak_header):
    # Missing fail-closed rejection before updating WalletCoinStore spent_height!
await self.coin_store.set_spent(coin_name, spent_height)
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — 24 Saatlik Clawback (İptal) Korumasını Kilitleyip Süre Dolunca `0.5 XCH` (`500,000,000,000 mojo`) Çalmak
Gönderici zaman kilitli Clawback ile `0.5 XCH` (`e088f25d...`) gönderir ve hatayı fark edip iptal etmek ister. Ancak saldırgan P2P üzerinden `RespondRemovals(height=8, proofs=None)` yollayarak göndericinin cüzdanında bu coin'i 'harcanmış' işaretler (`t1_cold_reloaded_sqlite_spent: true`). Gönderici süre boyunca iptal işlemi üretemez (`tx_count: 0`); süre dolunca saldırgan gerçek `SpendBundle` (`33361e6b2d8ee0d9...`) ile parayı çeker.

### Senaryo B — Birleşik Zaman Çizelgesi Zinciri (`WLC-02` + `VR-01 / POC-10` — Hem Canlı Cüzdan İptalini Hem Acil Durum `chia-vault-recover` Aracını Aynı Anda Kilitleme)
Tek bir kesintisiz zaman çizelgesinde (`t0..t4`), saldırgan hem `WLC-02` ile canlı cüzdanı kilitler hem de `1 mojo` dust coin göndererek kurbanın son çare olarak çalıştırdığı `chia-vault-recover` CLI aracını sahte `launcher_id` (`2de44601...`) ile çökertir (`t3_poc10_matches_victim: false`).

### Senaryo C — Borsa Sıcak Cüzdanları ve Likidasyon Botlarında UTXO Dondurma (DoS)
Harcanmamış coin'lerin yerel SQLite veritabanında `spent` işaretlenmesi, otomatik ödeme ve likidasyon botlarının bakiye kullanmasını engeller.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect removal validation in chia/wallet/wallet_node.py and wallet_state_manager.py
sed -n '725,777p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the Unified Timeline (t0..t4) & SQLite Cold-Reload Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k wlc02
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-WLC-02": {
    "RED": {
      "clawback_coin_id": "e088f25d50be49d29eb144248071f377d5f7bbdb5d7dd34078c9c72276a0b649",
      "clawback_amount_mojo": 500000000000,
      "t1_cold_reloaded_sqlite_spent": true,
      "t2_sender_cancel_tx_count": 0,
      "t3_poc10_matches_victim": false,
      "t4_recipient_claim_spend_bundle_sha256": "33361e6b2d8ee0d9bdd37738c4b2e54ece03c1eb507de8e59b370a1bd100e1e1",
      "t4_recipient_claim_bytes": 930
    },
    "GREEN": {
      "t1_cold_reloaded_sqlite_spent": false,
      "t2_sender_cancel_tx_count": 1,
      "t3_poc10_matches_victim": true,
      "sender_clawback_cancel_succeeded": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/chia/wallet/wallet_node.py
+++ b/chia/wallet/wallet_node.py
@@ -742,6 +742,8 @@ class WalletNode(Node):
+        if response.proofs is None or not validate_removals(coins, response.proofs, peak_header):
+            raise ValueError("Rejected unverified RespondRemovals without valid Merkle proofs")
```
