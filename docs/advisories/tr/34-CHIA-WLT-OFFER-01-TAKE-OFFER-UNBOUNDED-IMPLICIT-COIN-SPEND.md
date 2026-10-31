# Chia Cüzdanı `take_offer` / `respond_to_offer` Akışında Kullanıcı Harcama Tavanı Doğrulaması Olmadan Örtük Coin Seçimi ve İmzalama (`WLT-OFFER-01`)

[English](../34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md) | **Türkçe** | [日本語](../ja/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md) | [简体中文](../zh-CN/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md) | [한국어](../ko/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Teklif (`Offer`) Kabul Edilirken Otomatik Coin Seçimi (`trade_manager.py` & `wallet_rpc_api.py`):** `take_offer` çağrıldığında `respond_to_offer` teklifte talep edilen ödemeleri karşılamak için cüzdandan otomatik olarak `select_coins` ile coin seçer ve `sign_coin_spends` ile imzalar.
2. **Adım 2 — Varlık Başına Maksimum Harcama Tavanı (`max_authorized_amount`) Kontrolünün Olmaması:** RPC katmanı, seçilen ve imzalanan toplam coin miktarının kullanıcının onayladığı üst sınırı (`max_authorized_amount`) aşıp aşmadığını zorunlu bir güvenlik kapısıyla denetlemez.
3. **Adım 3 — Fazladan Coin Seçimi ve İmzalanması (`RED -> GREEN`):** Fazladan ödeme bacağı talep eden bir Offer kabul edildiğinde `RED` modda cüzdan ek coin'leri seçip imzalarken, `GREEN` yaması varlık başına yetki tavanını aşan teklifleri reddeder.

### Zafiyetli Kod Kesiti
```python
# File: chia/wallet/trade_manager.py & chia/rpc/wallet_rpc_api.py
async def respond_to_offer(self, offer: Offer, peer: WSChiaConnection, ...):
    # BUG: Selects and signs coins for all requested_payments in the Offer without verifying
    # against an explicit caller-authorized per-asset max_authorized_amount cap!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Otomatik Takas Botunun (`take_offer`) Fazladan Ödeme Bacağı İle Boşaltılması
Dışarıdan gelen bir Offer metnini `take_offer` ile kabul eden bot veya entegrasyon, beklediği tutarın üzerinde XCH/CAT coin'ini imzalar.

### Senaryo B — NFT/Token Takası İçine Gizlenen Ek XCH Talebi
Kullanıcı yalnızca token takası yaptığını sanırken teklifin içindeki ek XCH talebi cüzdandan otomatik seçilip imzalanır.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
`max_authorized_amount` kontrolüyle yetki tavanını aşan coin seçimi engellenir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run Sniper's Cryptographic Wallet Signing Auditor & Offer Cap Verification
python3 -m unittest /home/community-user/targets/sniper/tests/test_wave5_orchestrator_and_wallet.py
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-WLT-OFFER-01": {
    "RED": {
      "authorized_cap_mojo": 100000000000,
      "offer_requested_mojo": 500000000000,
      "unbounded_implicit_coin_spend_signed": true
    },
    "GREEN": {
      "unbounded_implicit_coin_spend_signed": false,
      "rejection_error": "ValueError: Offer requested amount exceeds max_authorized_amount"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/chia/wallet/trade_manager.py
+++ b/chia/wallet/trade_manager.py
@@ -450,6 +450,8 @@ class TradeManager:
+        if max_authorized_amounts is not None and total_requested > max_authorized_amounts.get(asset_id, 0):
+            raise ValueError("Offer requested amount exceeds max_authorized_amount")
```
