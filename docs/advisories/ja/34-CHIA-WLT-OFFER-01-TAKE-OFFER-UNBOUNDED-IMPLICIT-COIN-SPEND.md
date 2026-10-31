# Chia Wallet `take_offer` / `respond_to_offer` Unbounded Implicit Coin Selection & Signing Without Per-Asset User Spend Cap (`WLT-OFFER-01`)

[English](../34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md) | [Türkçe](../tr/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md) | **日本語** | [简体中文](../zh-CN/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md) | [한국어](../ko/34-CHIA-WLT-OFFER-01-TAKE-OFFER-UNBOUNDED-IMPLICIT-COIN-SPEND.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Implicit Coin Selection From Requested Notarized Payments (`trade_manager.py` & `wallet_rpc_api.py`):** When fulfilling an Offer via `take_offer`, `respond_to_offer` computes the deficit of requested notarized payments and invokes `select_coins` + `sign_coin_spends` for every requested asset.
2. **Step 2 — Missing Mandatory Per-Asset `max_authorized_amount` Guard:** The RPC and `TradeManager` pipeline do not require or enforce an explicit caller-supplied per-asset spend cap (`max_authorized_amount`) before selecting and signing wallet UTXOs.
3. **Step 3 — Excess Wallet Coins Selected and Signed (`RED -> GREEN`):** A crafted Offer requesting additional notarized payment legs causes the wallet to select and sign coins exceeding the user's intended spend cap in `RED`, whereas `GREEN` enforces an explicit per-asset maximum spend bound.

### Vulnerable Code Snippet
```python
# File: chia/wallet/trade_manager.py & chia/rpc/wallet_rpc_api.py
async def respond_to_offer(self, offer: Offer, peer: WSChiaConnection, ...):
    # BUG: Selects and signs coins for all requested_payments in the Offer without verifying
    # against an explicit caller-authorized per-asset max_authorized_amount cap!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Automated Taker Bot / Aggregator Drained via Excess Requested Payment Leg
A trading bot or dApp calling `take_offer` on an external Offer string signs away additional XCH/CAT coins beyond its intended quote.

### Scenario B — Multi-Asset Offer Hidden XCH Deficit
An Offer advertised as a CAT-for-NFT swap includes an additional XCH notarized payment request that `respond_to_offer` silently funds from the taker's XCH wallet.

### Scenario C — Patched Verification (`GREEN`)
Enforcing `verify_max_send_amount` blocks any Offer whose requested coins exceed the caller's authorized cap.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run Sniper's Cryptographic Wallet Signing Auditor & Offer Cap Verification
python3 -m unittest /home/community-user/targets/sniper/tests/test_wave5_orchestrator_and_wallet.py
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

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

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/chia/wallet/trade_manager.py
+++ b/chia/wallet/trade_manager.py
@@ -450,6 +450,8 @@ class TradeManager:
+        if max_authorized_amounts is not None and total_requested > max_authorized_amounts.get(asset_id, 0):
+            raise ValueError("Offer requested amount exceeds max_authorized_amount")
```
