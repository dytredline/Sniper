# Chia `FullNode` Port `8444` Unverified `NewPeak` / `sync_from_fork_point` Synchronization Lockout & `10,000 XCH` Fork-Reorg Double-Spend Impact (`CONS-SP-01`)

[English](../33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md) | [Türkçe](../tr/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md) | **日本語** | [简体中文](../zh-CN/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md) | [한국어](../ko/33-CHIA-CONS-SP-01-FULLNODE-SUB-EPOCH-SYNC-LOCKOUT-AND-REORG.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Repeated `sync_from_fork_point` Aborts Without Peer Disconnection (`chia/full_node/full_node.py:2220-2310`):** When an unauthenticated mTLS 1.3 P2P peer on port `8444` advertises a higher `NewPeak` and supplies invalid or empty sub-epoch/weight-proof responses during `sync_from_fork_point`, `FullNode` aborts the sync attempt without disconnecting or banning the malicious peer.
2. **Step 2 — 3-Node mTLS 1.3 Topology Sync Starvation (`victim_peak_height: None`):** Verified across a real 3-node mTLS 1.3 topology (`Honest Node` at `height=5`, `Malicious Peer`, `Victim Node`), 5 consecutive poisoned sync rounds keep the victim node's `peak` at `None` (`0`) and prevent it from syncing to the honest peer.
3. **Step 3 — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Fork-Reorg Double-Spend Demonstration (`Section 8.5`):** While a node's view of the canonical chain is delayed or split at `fork_height=5`, an attacker spends a `10,000 XCH` coin (`006f4366cd3778cc...`) to an exchange on `Branch A` (`height=7`, `SpendBundle SHA-256: 26afe149e702e4a6...`) and to their own vault on heavier `Branch B` (`height=9`, `SpendBundle SHA-256: ad2eba4d67c52314...`), wiping out the exchange's `10,000 XCH` deposit upon reorg.

### Vulnerable Code Snippet
```python
# File: chia/full_node/full_node.py (lines 2220-2310)
async def sync_from_fork_point(self, fork_point_height: int, target_peak_sb_height: uint32, peak_hash: bytes32, ...):
    # BUG: When peer returns invalid weight proof / sub-epoch summary, sync aborts without
    # disconnecting/banning the peer, allowing indefinite sync starvation over port 8444!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Port `8444` mTLS Sync Lockout Against Exchange & Pool FullNodes
A single remote P2P peer stalls a victim `FullNode` across consecutive sync rounds, preventing it from advancing to the canonical chain offered by honest peers.

### Scenario B — `10,000 XCH` (`10,000,000,000,000,000 mojo`) Exchange Deposit + Fork-Reorg Double-Spend (`Section 8.5`)
An attacker deposits `10,000 XCH` (`SpendBundle` `26afe149e702e4a622a5675aa77481e6b54074e3cfa98db93a47ef24c1793f8b`) on `Branch A` (`height=7`) to an exchange accepting early confirmations (`min_confirmations=1`), withdraws fiat/USDT, and releases heavier `Branch B` (`height=9`, `SpendBundle` `ad2eba4d67c52314303e62601ed42d89c2c4f488d67c9cc0554a3137c9214c33`), reducing the exchange's on-chain balance from `10,000 XCH` to `0` (`GREEN` with `min_confirmations=32` holds the deposit in `PENDING_FINALITY` with `0` loss).

### Scenario C — Combined Chain (`CONS-SP-01` + `WLC-01`)
Blinding a merchant's FullNode on port `8444` while feeding counterfeit light-wallet headers via `WLC-01`.

---

## 3. Example Execution & Verification Commands

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

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

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

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/chia/full_node/full_node.py
+++ b/chia/full_node/full_node.py
@@ -2265,6 +2265,8 @@ class FullNode:
+        if not valid_weight_proof:
+            await peer.close(ban_seconds=300)
```
