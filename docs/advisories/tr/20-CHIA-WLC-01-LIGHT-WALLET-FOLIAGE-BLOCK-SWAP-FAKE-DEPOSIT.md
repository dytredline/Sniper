# Chia Hafif Cüzdan (Light Wallet) Senkronizasyonunda Doğrulanmamış `FoliageTransactionBlock` Takası İle Sıfır Sermayeli (`0 XCH`) Sahte Onaylı Yatırım (`WLC-01`)

[English](../20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md) | **Türkçe** | [日本語](../ja/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md) | [简体中文](../zh-CN/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md) | [한국어](../ko/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Başlık ve İşlem Gövdesi Arasındaki SHA-256 Bağlamasının Kontrol Edilmemesi (`chia/wallet/wallet_node.py:926-995`):** Chia blok yapısında imzalı blok başlığı (`HeaderBlock.foliage`), içindeki işlem blokunun özetini `header_block.foliage.foliage_transaction_block_hash` alanında tutar. Ancak `WalletNode._add_block_from_header` metodu P2P ağından gelen `RespondBlockHeader` paketini işlerken `header_block.foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash` eşitliğini kontrol etmeyi unutur.
2. **Adım 2 — Cebinde `0 XCH` Olan Saldırganın Kurban Cüzdanına Sahte Onaylı Bakiye Yazması (`Karşı Onayı Gerekmez, Borsadan XCH Almak Gerekmez`):** Klasik çifte harcama (reorg) saldırılarının aksine saldırganın borsadan tek bir XCH bile satın almasına gerek yoktur (`0 XCH sermaye`). Saldırgan gerçek bir blok başlığının altına kendi ürettiği sahte `foliage_transaction_block` verisini takar; kurbanın cüzdanı zincirde hiç var olmayan `+0.5 XCH` (`500,000,000,000 mojo`) veya `+1.000 XCH` ödemeyi SQLite `WalletCoinStore` veritabanına **Onaylandı (Confirmed)** olarak kaydeder.
3. **Adım 3 — Satıcı Ödemeyi Teslim Ettikten Sonra Harcama Anında `Err.UNKNOWN_UNSPENT` Hatası:** Satıcı/OTC masası ekranda onaylı XCH yatırımını görüp karşılığında gerçek USDT, BTC veya ürünü teslim eder; daha sonra bu XCH'yi harcamak istediğinde `FullNode` mempool katmanı böyle bir coin zincirde hiç var olmadığı için işlemi `Err.UNKNOWN_UNSPENT` ile reddeder.

### Zafiyetli Kod Kesiti
```python
# File: chia/wallet/wallet_node.py (lines 926-995)
async def _add_block_from_header(self, header_block: HeaderBlock, ...):
    # BUG: Missing cryptographic binding check between signed header and transaction block body:
    # if header_block.foliage_transaction_block is not None:
    #     if header_block.foliage_transaction_block.get_hash() != header_block.foliage.foliage_transaction_block_hash:
    #         raise ValueError("Invalid foliage_transaction_block_hash")
    additions, removals = await self.get_additions_and_removals(header_block, ...)
    await self.wallet_state_manager.add_block(...)
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Borsadan Hiç XCH Almadan (`0 XCH` Sermaye, Karşı Onayı Yok) Satıcıya/OTC Masasına Sahte Yatırım Gösterip Gerçek USDT/BTC Çekmek
Klasik çifte harcama senaryosunda saldırganın gerçekten XCH satın alıp iki çatallı zincir üretmesi gerekirken, `WLC-01` açığında saldırganın cebinde `1 XCH` bile olmasına gerek yoktur! Karşı taraf (kripto ödeme noktası, OTC masası veya satıcı) Chia Light Wallet kullanıyorsa, saldırgan P2P ağından başlığı gerçek ama içindeki `foliage_transaction_block` listesi değiştirilmiş bir paket yollar. Satıcının cüzdanı blokzincirinde hiç var olmayan `+0.5 XCH` (`500,000,000,000 mojo`) veya `+1.000 XCH` ödemeyi **Onaylandı** gösterir; saldırgan karşılığında gerçek USDT, Bitcoin veya ürünü alıp çıkar.

### Senaryo B — SQLite Veritabanında Kalıcı Sahte Bakiye İle Otomatik Teslimat Botlarını Kandırma
Sahte coin SQLite `WalletCoinStore` tablosuna yazıldığı için cüzdan yeniden başlatılsa bile (`reopened_sqlite_coin_present: true`) onaylı görünmeye devam eder; ancak satıcı bu bakiyeyi başka adrese göndermeye çalıştığında `FullNode` işlemi `Err.UNKNOWN_UNSPENT` ile reddeder.

### Senaryo C — Birleşik Zincir (`CONS-SP-01` FullNode Senkron Kilidi + `WLC-01` Sahte Yatırım)
Saldırgan önce `8444` portundan `CONS-SP-01` ile hedef kurumun FullNode senkronizasyonunu kilitler, ardından hafif cüzdan P2P senkronizasyonu üzerinden `foliage_transaction_block` takasıyla sahte XCH bakiyesi enjekte eder.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect _add_block_from_header in chia/wallet/wallet_node.py
sed -n '926,995p' /home/community-user/targets/chia-blockchain/chia/wallet/wallet_node.py

# 2. Run the RED -> GREEN End-to-End Verification Harness for WLC-01
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_ek_kanit_gereksinimleri_20261030.py -k wlc01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-WLC-01": {
    "RED": {
      "attacker_initial_xch_capital_mojo": 0,
      "accepted_swapped_foliage_transaction_block": true,
      "fake_merchant_deposit_increase_mojo": 500000000000,
      "reopened_sqlite_coin_present": true,
      "subsequent_spend_mempool_error": "Err.UNKNOWN_UNSPENT"
    },
    "GREEN": {
      "accepted_swapped_foliage_transaction_block": false,
      "fake_merchant_deposit_increase_mojo": 0,
      "reopened_sqlite_coin_present": false,
      "rejection_error": "ValueError: Invalid foliage_transaction_block_hash"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/chia/wallet/wallet_node.py
+++ b/chia/wallet/wallet_node.py
@@ -932,6 +932,12 @@ class WalletNode(Node):
         if header_block.foliage_transaction_block is not None:
+            if (
+                header_block.foliage_transaction_block.get_hash()
+                != header_block.foliage.foliage_transaction_block_hash
+            ):
+                raise ValueError("Invalid foliage_transaction_block_hash in HeaderBlock")
```
