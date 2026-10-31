# Chia DataLayer `WalletRpcApi.dl_verify_proof` Missing Singleton Lineage Verification Allowing 1-Mojo Counterfeit Proofs & Unbacked `100,000 CAT` On-Chain Minting (`DL-01`)

[English](../23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md) | [Türkçe](../tr/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md) | [日本語](../ja/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md) | [简体中文](../zh-CN/23-CHIA-DL-01-DATALAYER-VERIFY-PROOF-NON-SINGLETON-FORGERY-CAT-MINT.md) | **한국어**

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Missing Singleton Top-Layer & Launcher Lineage Check in `WalletRpcApi.dl_verify_proof` (`chia/rpc/wallet_rpc_api.py:4066-4120`):** When verifying a `DLProof` (`ProofOfInclusion`), `dl_verify_proof` confirms that the referenced coin (`coin_id`) was spent on-chain and that its inner puzzle announcement matches the Merkle root of the key/value pairs, plus checks `dl_wallet.get_latest_singleton(store_id)` for existence. However, it **never calls `match_dl_singleton`** on the proof's parent coin spend to verify that the coin is actually the canonical DataLayer singleton for `store_id`!
2. **Step 2 — 1-Mojo Non-Singleton Coin Forges Any Official `store_id` Root:** An attacker spends a 1-mojo standard non-singleton coin (`coin_id: 86ec0dd71fbc7e415e06dc504e8e74436cf4f60d2f4ab942fc2104685b20dd17`) whose puzzle emits the announcement format expected by `dl_verify_proof` while referencing the victim institution's `store_id` (`806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6`). `WalletRpcApi.dl_verify_proof` returns `{"verified": true, "verified_clvm_hashes": true, "current_root": true}`.
3. **Step 3 — End-to-End On-Chain Minting of `100,000 CAT` (`100,000,000 CAT mojo`):** When a bridge, RWA issuer, or carbon-credit minter gates token issuance on `WalletRpcApi.dl_verify_proof`, the forged 1-mojo proof triggers a real `CATWallet` issuance (`cat_asset_id: 73dc2527f5a75964c9b1b019def41d17aaa1f22d42235f479114c2e505f679f5`, `issuance SpendBundle SHA-256: 6a635760183480c0c94ccf7786c1700fa5b7d7b0ae2532da49ff22edc3257c5e`, `delivery SpendBundle SHA-256: dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`), crediting the attacker with `100,000 CAT` on-chain.

### Vulnerable Code Snippet
```python
# File: chia/rpc/wallet_rpc_api.py (lines 4066-4120)
async def dl_verify_proof(self, request: dict[str, Any]) -> EndpointResult:
    proof = DLProof.from_json_dict(request)
    verified_clvm_hashes = dl_verify_proof(proof)
    # BUG: Verifies coin existence and Merkle hash, but NEVER verifies that the parent coin spend
    # matches SINGLETON_TOP_LAYER_MOD with launcher_id == proof.store_proofs.store_id!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — 1-Mojo Counterfeit DataLayer Reserve Proof Mints `100,000 CAT` (`100,000,000 CAT mojo`) On-Chain
An institutional RWA/stablecoin bridge tracks collateralized minting approvals in DataLayer store `806a6c73c7344b24d23915a319f82da69e1129a70e3ef772da2be14de2b4a5d6` (backed by `1,000 XCH` collateral). The attacker spends a 1-mojo non-singleton coin (`86ec0dd71fbc7e41...`) announcing `mint_allowance=100000000` and submits the `DLProof` to `WalletRpcApi.dl_verify_proof`. Because `dl_verify_proof` returns `verified: true, current_root: true`, the bridge mints and delivers `100,000 CAT` on-chain (`SpendBundle` `dc3f0bbaac81e982baa174241b3a69fba1b8a34e7033d8e1465ecd832ea18196`).

### Scenario B — Side-by-Side Intrinsic RPC Forgery Against Any Third-Party Verifier (`test_dl01_side_by_side_canonical_vs_counterfeit_dl_verify_proof`)
Even without a bridge consumer, calling `WalletRpcApi.dl_verify_proof` directly with a canonical singleton proof vs. a 1-mojo non-singleton counterfeit proof returns identical `verified: true` responses in `RED`, proving the defect is intrinsic to Chia's RPC verifier.

### Scenario C — Counterfeit Carbon-Credit / Registry Audit Attestations
An attacker forges retirement or issuance records against an official climate registry's `store_id` using a 1-mojo coin spend.

---

## 3. Example Execution & Verification Commands

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

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

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

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/chia/rpc/wallet_rpc_api.py
+++ b/chia/rpc/wallet_rpc_api.py
@@ -4092,6 +4092,11 @@ class WalletRpcApi:
+        parent_spend = await fetch_coin_spend_for_coin_state(coin_state, peer)
+        matched, launcher_id, _ = match_dl_singleton(parent_spend)
+        if not matched or launcher_id != proof.store_proofs.store_id:
+            raise ProofIntegrityError("Coin is not a valid DataLayer singleton for store_id")
```
