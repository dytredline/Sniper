# Chia DataLayer `WalletRpcApi.dl_verify_proof` İçinde Singleton Soy Kütüğü Doğrulama Eksikliği İle `1 Mojo`'luk Sahte Kanıt Üretimi ve Zincir Üstünde `100.000 CAT` Token Basımı (`DL-01`)

[English](../23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md) | **Türkçe** | [日本語](../ja/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md) | [简体中文](../zh-CN/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md) | [한국어](../ko/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `WalletRpcApi.dl_verify_proof` İçinde Coin'in Gerçek Singleton Olup Olmadığının Kontrol Edilmemesi (`chia/rpc/wallet_rpc_api.py:4066-4120`):** Chia DataLayer, kurumların zincir üstünde resmi veri kayıtları (karbon kredisi sicili, RWA teminat tablosu, köprü rezerv kaydı) tuttuğu sistemdir. `dl_verify_proof` RPC'si kendisine verilen kanıttaki coin'in zincirde var olduğunu ve Merkle kökünü kontrol eder; ancak **bu coin'in gerçekten o kurumun resmi DataLayer Singleton'ı (`match_dl_singleton` ve `store_id` soy kütüğü) olup olmadığını hiç kontrol etmez!**
2. **Adım 2 — `1 Mojo` Maliyetle Herhangi Bir Kurumun `store_id` Kaydı Adına Sahte Kanıt Üretilmesi:** Saldırgan cebinden sadece `1 mojo` (trilyonda bir XCH) harcayarak sıradan (singleton olmayan) bir coin (`86ec0dd71fbc7e41...`) oluşturur ve içine hedef kurumun `store_id` (`806a6c73c7344b24...`) kimliğini yazar. `WalletRpcApi.dl_verify_proof` bu sahte kanıta `{"verified": true, "current_root": true}` (Tamamen Geçerli ve Güncel!) yanıtı döner.
3. **Adım 3 — Zincir Üstünde (On-Chain) `100.000 Adet Gerçek CAT Token` Basılması (`SpendBundle SHA-256: 6a635760183480c0...`):** `dl_verify_proof` onayına güvenen RWA/köprü servisi, gerçek Chia zinciri üzerinde `CATWallet` (`cat_asset_id: 73dc2527f5a75964...`) çalıştırarak saldırganın cüzdanına **`100.000 CAT` (`100,000,000 CAT mojo`)** basar ve transfer eder (`dc3f0bbaac81e982...`).

### Zafiyetli Kod Kesiti
```python
# File: chia/rpc/wallet_rpc_api.py (lines 4066-4120)
async def dl_verify_proof(self, request: dict[str, Any]) -> EndpointResult:
    proof = DLProof.from_json_dict(request)
    verified_clvm_hashes = dl_verify_proof(proof)
    # BUG: Verifies coin existence and Merkle hash, but NEVER verifies that the parent coin spend
    # matches SINGLETON_TOP_LAYER_MOD with launcher_id == proof.store_proofs.store_id!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — `1 Mojo`'luk Sahte DataLayer Kanıtıyla Zincir Üstünde `100.000 CAT` (`100,000,000 CAT mojo`) Basıp Çekmek
Kurumsal bir RWA/Stablecoin ihraççısı, `1.000 XCH` teminatlı kasasının ihraç onaylarını DataLayer `store_id = 806a6c73c7344b24...` üzerinde tutmaktadır. Saldırgan yalnızca `1 mojo` harcayarak sıradan bir coin (`86ec0dd71fbc7e41...`) içinde sahte Merkle kökü yayınlar ve kanıtı `WalletRpcApi.dl_verify_proof` uç noktasına verir. Cüzdan RPC'si `verified: true, current_root: true` döndürdüğü için sistem saldırganın cüzdanına zincir üstünde gerçek **`100.000 CAT` token** (`cat_asset_id: 73dc2527...`, `SpendBundle: dc3f0bbaac81e982...`) basar.

### Senaryo B — Doğrudan `WalletRpcApi.dl_verify_proof` Üzerinde Yan Yana Kanıt (`Gerçek Singleton` vs `1-Mojo Sahte Coin`)
Hiçbir harici köprü olmadan doğrudan Chia'nın kendi `WalletRpcApi.dl_verify_proof` metoduna gerçek Singleton kanıtı ile `1 mojo` sahte coin kanıtı yan yana verildiğinde, yamasız (`RED`) kod her ikisine de `verified: true` döner; yamalı (`GREEN`) kod ise sahte kanıtı `ProofIntegrityError` ile reddeder.

### Senaryo C — Sahte Karbon Kredisi ve Tedarik Zinciri Sertifikası Doğrulama
Resmi karbon sicilinin `store_id` kimliği kullanılarak `1 mojo` ile sahte sertifika kanıtı doğrulatılır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect WalletRpcApi.dl_verify_proof in chia/rpc/wallet_rpc_api.py
sed -n '4066,4120p' /home/community-user/targets/chia-blockchain/chia/rpc/wallet_rpc_api.py

# 2. Run both the Intrinsic Side-by-Side RPC Test and the 100,000 CAT On-Chain Mint Test (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k dl01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-DL-01": {
    "RED": {
      "victim_store_id": "806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6",
      "forged_non_singleton_coin_id": "86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17",
      "dl_verify_proof_verified": true,
      "dl_verify_proof_current_root": true,
      "cat_asset_id": "73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5",
      "cat_issuance_spend_bundle_sha256": "6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e",
      "cat_delivery_spend_bundle_sha256": "dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196",
      "attacker_minted_cat_mojo": 100000000,
      "attacker_minted_cat_tokens": 100000
    },
    "GREEN": {
      "canonical_singleton_proof_verified": true,
      "counterfeit_non_singleton_proof_verified": false,
      "attacker_minted_cat_mojo": 0
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/chia/rpc/wallet_rpc_api.py
+++ b/chia/rpc/wallet_rpc_api.py
@@ -4092,6 +4092,11 @@ class WalletRpcApi:
+        parent_spend = await fetch_coin_spend_for_coin_state(coin_state, peer)
+        matched, launcher_id, _ = match_dl_singleton(parent_spend)
+        if not matched or launcher_id != proof.store_proofs.store_id:
+            raise ProofIntegrityError("Coin is not a valid DataLayer singleton for store_id")
```
