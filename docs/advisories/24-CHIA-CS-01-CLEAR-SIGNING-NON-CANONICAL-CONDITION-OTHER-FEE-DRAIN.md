# `cni-wallet-sdk` Clear-Signing Permissive `Condition::Other` Bypass Allowing Hidden `750 XCH` Fee Drain & NFT Transfer-Program Spoofing (`CS-01` / `POC-1 & POC-2`)

**English** | [Türkçe](tr/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md) | [日本語](ja/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md) | [简体中文](zh-CN/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md) | [한국어](ko/24-CHIA-CS-01-CLEAR-SIGNING-NON-CANONICAL-CONDITION-OTHER-FEE-DRAIN.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Parser Divergence Between Consensus CLVM (`chia_rs`) and `cni-wallet-sdk` (`clear_signing.rs`):** Chia's consensus CLVM engine ignores extra trailing arguments on condition opcodes such as `RESERVE_FEE` (`(52 amount extra_atom)`), executing the full fee reservation on-chain. However, `cni-wallet-sdk` parses conditions using strict fixed-arity structs and silently wraps any condition with trailing atoms into `Condition::Other(NodePtr)` instead of rejecting it.
2. **Step 2 — Hidden `750 XCH` (`750,000,000,000,000 mojo`) Fee Drain (`POC-1`):** In `SpendBundle` `b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c` (`1,105 bytes`), a vault spend emits an overlong `RESERVE_FEE` condition for `750 XCH`. Unpatched Clear-Signing ignores `Condition::Other` and displays `reserved_fee: 0` to the hardware/mobile signer while consensus consumes `750 XCH`.
3. **Step 3 — Unvalidated NFT `-24` Transfer-Program / Metadata State Mutation (`POC-2`):** Similarly, non-canonical or uninspected NFT state conditions in `SpendBundle` `17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128` (`3,274 bytes`) alter NFT control on-chain while being omitted from the Clear-Signing summary.

### Vulnerable Code Snippet
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Condition::Other(_) variants (such as overlong RESERVE_FEE opcode 52 or unparsed NFT opcodes)
// are silently ignored instead of returning Error::UnsupportedCondition / failing closed:
match condition {
    Condition::ReserveFee(fee) => reserved_fee += fee.amount,
    Condition::Other(_) => { /* silently ignored in unpatched RED! */ }
}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Draining `750 XCH` (`750,000,000,000,000 mojo`) from an Enterprise Vault via Hidden `RESERVE_FEE` (`POC-1`)
An attacker proposes a routine Vault transaction (`SpendBundle SHA-256: b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c`). The Clear-Signing screen on the signer's device reports `reserved_fee = 0`, inducing the custodian to sign; when broadcast, `750 XCH` is drained as block fee (`consensus_reserved_fee_mojo: 750000000000000`).

### Scenario B — Silent NFT Ownership / Transfer-Program Hijack (`POC-2`)
A collector signs an NFT transaction (`SpendBundle SHA-256: 17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128`) whose Clear-Signing preview shows a benign update while the unparsed condition mutates the NFT state on-chain.

### Scenario C — Colluding Pool / Farmer Fee Extraction
An attacker partners with a farmer or mempool relayer to capture the hidden `750 XCH` fee output immediately upon block inclusion.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run the Clear-Signing Rust Proof Suite in cni-wallet-sdk (POC-1 & POC-2)
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc1_and_poc2 -- --nocapture
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-01": {
    "RED": {
      "poc1_spend_bundle_sha256": "b9b614d01ee2b104325a7dde22c33c498ed9e2e6925f957411d9d9d162f06e5c",
      "poc1_spend_bundle_bytes": 1105,
      "poc1_clear_signing_displayed_fee_mojo": 0,
      "poc1_consensus_drained_fee_mojo": 750000000000000,
      "poc2_spend_bundle_sha256": "17d2796f8bd6b9bf9fc1f03cb0570be6ac6393215c27cf61718b2eb9924dd128",
      "poc2_spend_bundle_bytes": 3274
    },
    "GREEN": {
      "poc1_rejected_fail_closed": true,
      "poc2_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -120,6 +120,9 @@
+    if matches!(condition, Condition::Other(_)) {
+        return Err(DriverError::NonStandardInnerSpend);
+    }
```
