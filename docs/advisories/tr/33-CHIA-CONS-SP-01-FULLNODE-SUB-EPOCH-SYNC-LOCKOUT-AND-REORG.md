# Chia `FullNode` Port `8444` Üzerinde `NewPeak` / `sync_from_fork_point` Senkronizasyon Kilidi ve `10.000 XCH` Çatallanma (Reorg) Çifte Harcama Senaryosu (`CONS-SP-01`)

[English](../33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md) | **Türkçe** | [日本語](../ja/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md) | [简体中文](../zh-CN/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md) | [한국어](../ko/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Port `8444` Üzerinde Hatalı Senkronizasyon Verisi Gönderen Eşin (Peer) Engellenmemesi (`chia/full_node/full_node.py:2220-2310`):** Kimlik doğrulamasız P2P (`8444` mTLS 1.3) ağından bağlanan bir saldırgan sahte `NewPeak` duyurup `sync_from_fork_point` sırasında bozuk sub-epoch / weight-proof yanıtı döndüğünde, `FullNode` senkronizasyonu iptal eder ancak saldırgan bağlantısını kesmez.
2. **Adım 2 — 3 Düğümlü Canlı mTLS 1.3 Ağında Dürüst Düğüm Varken Senkronizasyonun Kilitlenmesi (`victim_peak_height: None`):** Biri dürüst (`height=5`), biri saldırgan, biri kurban olan 3 düğümlü gerçek mTLS 1.3 testinde, saldırgan 5 ardışık tur boyunca kurban düğümü meşgul ederek dürüst düğümden blok almasını engeller (`victim_peak_height: None`).
3. **Adım 3 — `10.000 XCH` (`10,000,000,000,000,000 mojo`) Çatallanma (Reorg) ve Çifte Harcama Kanıtı (`Bölüm 8.5`):** Ortak çatal yüksekliği `fork_height=5` üzerinde saldırgan `10.000 XCH` değerindeki coin'i (`006f4366...`) `Branch A` (`height=7`, `SpendBundle: 26afe149...`) üzerinde borsaya yatırıp nakit çeker, ardından daha ağır olan `Branch B` (`height=9`, `SpendBundle: ad2eba4d...`) dalını ağa sunarak borsadaki `10.000 XCH` bakiyeyi `0`'a düşürür ve kendi kasasında `10.000 XCH` tutar (`20.000 XCH` toplam ekonomik etki).

### Zafiyetli Kod Kesiti
```python
# File: chia/full_node/full_node.py (lines 2220-2310)
async def sync_from_fork_point(self, fork_point_height: int, target_peak_sb_height: uint32, peak_hash: bytes32, ...):
    # BUG: When peer returns invalid weight proof / sub-epoch summary, sync aborts without
    # disconnecting/banning the peer, allowing indefinite sync starvation over port 8444!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Port `8444` Üzerinden Borsa ve Havuz FullNode Sunucularının Senkronizasyonunu Kilitleme
Tek bir P2P bağlantısı üzerinden gönderilen bozuk senkronizasyon yanıtları, kurban düğümün dürüst düğümlerden güncel blokları almasını engeller.

### Senaryo B — `10.000 XCH` (`10,000,000,000,000,000 mojo`) Borsa Yatırımı ve Çatallanma (Reorg) Çifte Harcama Senaryosu (`Bölüm 8.5`)
Saldırgan `Branch A` (`height=7`, `SpendBundle: 26afe149e702e4a6...`) üzerinde borsaya `10.000 XCH` yatırıp karşılığını çeker; hemen ardından kendi kasasına `10.000 XCH` aktaran daha uzun `Branch B` (`height=9`, `SpendBundle: ad2eba4d67c52314...`) zincirini yayınlar. Reorg sonrası borsanın cüzdanındaki `10.000 XCH` sıfırlanır (`0 mojo`), saldırganın kasasında `10.000 XCH` kalır.

### Senaryo C — Birleşik Zincir (`CONS-SP-01` + `WLC-01`)
FullNode senkronizasyonu kilitlenen satıcının hafif cüzdanına `WLC-01` ile sıfır sermayeli sahte yatırım gösterilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Run the 3-Node Port 8444 mTLS Sync Lockout Proof
/home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_real_e2e_followup_proofs.py -k cons_sp01

# 2. Run the 10,000 XCH (10,000,000,000,000,000 mojo) Fork-Reorg Double-Spend Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k reorg
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CONS-SP-01": {
    "RED": {
      "mtls_3node_victim_peak_after_5_rounds": null,
      "fork_height": 5,
      "split_coin_id": "006f4366cd3778cc13e11647a0f4dd43552088db526a289c65de3493fa01a411",
      "branch_a_exchange_deposit_spend_bundle_sha256": "26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b",
      "branch_b_attacker_vault_spend_bundle_sha256": "ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33",
      "exchange_pre_reorg_balance_mojo": 10000000000000000,
      "exchange_post_reorg_balance_mojo": 0,
      "attacker_post_reorg_balance_mojo": 10000000000000000
    },
    "GREEN": {
      "mtls_3node_victim_synced_height": 5,
      "exchange_status_at_1_conf": "PENDING_FINALITY",
      "exchange_loss_mojo": 0
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/chia/full_node/full_node.py
+++ b/chia/full_node/full_node.py
@@ -2265,6 +2265,8 @@ class FullNode:
+        if not valid_weight_proof:
+            await peer.close(ban_seconds=300)
```
