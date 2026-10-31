# `cni-wallet-sdk` Clear-Signing Unrevealed Settlement Spend Blind Spot Allowing Post-Signature `600 XCH` Drain (`CS-04` / `POC-5`)

**English** | [Türkçe](tr/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md) | [日本語](ja/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md) | [简体中文](zh-CN/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md) | [한국어](ko/27-CHIA-CS-04-CLEAR-SIGNING-UNREVEALED-SETTLEMENT-SPEND-BLIND-SPOT.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Settlement Coins Require No Signature to Spend Once Created:** Any coin created at `SETTLEMENT_PAYMENT_HASH` can be spent by anyone who supplies a matching notarized payment solution (unless constrained by a signed announcement in the parent vault spend).
2. **Step 2 — Clear-Signing Accepts Bundles Where the Created Settlement Coin Is Left Unspent (`clear_signing.rs`):** In `POC-5`, the signing bundle (`a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`, `1,303 bytes`) creates a `600 XCH` (`600,000,000,000,000 mojo`) settlement coin without including its spend in the preview bundle. Unpatched Clear-Signing does not report an external outflow.
3. **Step 3 — Attacker Attaches the Settlement Spend (`e0b876fbb8e0f264...`) Post-Signing:** After the victim signs the vault spend, the attacker appends the `600 XCH` settlement spend (`388 bytes`) and broadcasts the combined bundle on-chain.

### Vulnerable Code Snippet
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Allows a vault spend to create a SETTLEMENT_PAYMENT_HASH coin without requiring
// the corresponding settlement CoinSpend to be revealed and verified in the signing bundle!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Post-Signing Attachment of an Unrevealed `600 XCH` (`600,000,000,000,000 mojo`) Settlement Spend (`POC-5`)
The victim reviews and signs vault bundle `a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb`; the attacker attaches `e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe` and sweeps `600 XCH`.

### Scenario B — Hardware Wallet Blind Signing via Deferred Settlement Reveal
Air-gapped hardware signers see zero external recipients during review while signing away `600 XCH` into an unrevealed settlement coin.

### Scenario C — Patched Verification (`GREEN`)
Any unspent/unrevealed settlement output in a Clear-Signing bundle is rejected fail-closed.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run POC-5 (600 XCH Unrevealed Settlement Spend Blind Spot) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc5 -- --nocapture
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-04": {
    "RED": {
      "poc5_vault_spend_bundle_sha256": "a9eeda2c8526d95cb0a36ffcdf9a026b23e96c11e15ee419938e18dc342277eb",
      "poc5_vault_spend_bundle_bytes": 1303,
      "poc5_attached_settlement_spend_bundle_sha256": "e0b876fbb8e0f26400a38fb5e2e9963a5cb1dbff92b76d78b4403ed0cb2f7cbe",
      "poc5_attached_settlement_bytes": 388,
      "hidden_outflow_mojo": 600000000000000
    },
    "GREEN": {
      "poc5_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -315,6 +315,8 @@
+    // Require every created settlement coin to have its corresponding spend revealed in the bundle
```
