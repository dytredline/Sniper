# Chia Light Wallet Sync Unverified `FoliageTransactionBlock` Swap Allowing Zero-Capital Counterfeit Confirmed XCH Deposits (`WLC-01`)

**English** | [Türkçe](tr/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md) | [日本語](ja/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md) | [简体中文](zh-CN/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md) | [한국어](ko/20-CHIA-WLC-01-LIGHT-WALLET-FOLIAGE-BLOCK-SWAP-FAKE-DEPOSIT.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Header-Body Cryptographic Binding Omission (`chia/wallet/wallet_node.py:926-995`):** In Chia's block structure, the signed `HeaderBlock.foliage` commits to the transaction payload via the 32-byte SHA-256 digest `header_block.foliage.foliage_transaction_block_hash`. However, when `WalletNode._add_block_from_header` ingests a `RespondBlockHeader` message from a P2P peer, it reads `header_block.foliage_transaction_block` and extracts coin additions without verifying `header_block.foliage_transaction_block.get_hash() == header_block.foliage.foliage_transaction_block_hash`.
2. **Step 2 — Zero-Capital (`0 XCH`) Counterfeit Coin Injection Into SQLite `WalletCoinStore`:** Because the header itself is a real canonical header from the blockchain, header-level checks pass. An attacker with `0 XCH` capital swaps `foliage_transaction_block` with a fabricated payload crediting the merchant's puzzle hash (`+0.5 XCH` = `500,000,000,000 mojo` or `+1,000 XCH`). The victim wallet inserts the counterfeit coin into `WalletCoinStore` as a confirmed on-chain balance that persists across wallet restarts.
3. **Step 3 — Post-Settlement Spend Failure (`Err.UNKNOWN_UNSPENT`):** Once the merchant releases goods, USDT, or BTC in exchange for the displayed confirmed XCH deposit and later attempts to sweep or spend the credited coin, `FullNode` mempool validation rejects the transaction with `Err.UNKNOWN_UNSPENT` because the coin never existed on the canonical blockchain.

### Vulnerable Code Snippet
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

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Zero-Capital (`0 XCH`) Fake Deposit to an OTC Desk, Payment Gateway, or Merchant to Cash Out Real USDT/BTC
Unlike a traditional 51%/reorg double-spend (which requires purchasing real XCH and mining a competing fork), an attacker with `0 XCH` capital connects to a merchant or OTC desk running a Chia Light Wallet and sends a `RespondBlockHeader` containing a genuine block header paired with a swapped `foliage_transaction_block`. The merchant's wallet immediately displays a confirmed `+0.5 XCH` (`500,000,000,000 mojo`) or `+1,000 XCH` deposit without requiring any counterparty approval. The attacker collects the real USDT/BTC payout and leaves before the merchant discovers the coin fails on-chain with `Err.UNKNOWN_UNSPENT`.

### Scenario B — Automated E-Commerce & Cross-Chain Relayer Poisoning Across SQLite Restarts
Because `_add_block_from_header` commits the counterfeit `CoinState` directly into SQLite `WalletCoinStore`, cold-reloading the wallet database (`reopened_sqlite_coin_present: true`) continues to report the phantom balance as confirmed, tricking automated order-fulfillment bots into shipping digital goods or gift cards.

### Scenario C — Combined Chain (`CONS-SP-01` Full-Node Sync Lockout + `WLC-01` Light-Wallet Fake Deposit)
An attacker first stalls a merchant's primary FullNode on port `8444` via `CONS-SP-01` so the operator switches or falls back to light-wallet P2P header sync, and immediately injects the swapped `foliage_transaction_block` payload to credit counterfeit XCH.

---

## 3. Example Execution & Verification Commands

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

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](chia-real-world-impact-e2e-20261031.json)):

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

### Unified Diff Patch (`git apply --check` clean)
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
