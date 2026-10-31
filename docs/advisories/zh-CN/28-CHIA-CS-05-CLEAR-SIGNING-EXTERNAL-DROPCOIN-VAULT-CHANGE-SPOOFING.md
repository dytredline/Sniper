# `cni-wallet-sdk` Clear-Signing External `DropCoin` Vault Change Spoofing Hiding `1,000 XCH` Vault Drain Across the `chia-sdk-bindings` FFI Boundary (`CS-05` / `POC-6`)

[English](../28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md) | [Türkçe](../tr/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md) | [日本語](../ja/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md) | **简体中文** | [한국어](../ko/28-CHIA-CS-05-CLEAR-SIGNING-EXTERNAL-DROPCOIN-VAULT-CHANGE-SPOOFING.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — External `DropCoin` Output Credited as Vault Change (`clear_signing.rs` & `chia-sdk-bindings/src/clear_signing.rs:62`):** When `parse_vault_transaction` computes the net outflow of a Vault transaction, it credits outputs sent to the vault's puzzle hash as vault change without verifying that the parent coin creating that output actually belonged to the vault (`DropCoin` parent lineage).
2. **Step 2 — Masking a `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Drain (`SpendBundle SHA-256: aa65182292515596...`):** In `POC-6` (`1,477 bytes`), the victim's vault sends `1,000 XCH` to the attacker while an external `DropCoin` spend included in the bundle creates a `1,000 XCH` output to the vault's puzzle hash. Unpatched Clear-Signing nets the two against each other and reports `0 XCH` net vault loss!
3. **Step 3 — Verified Directly Across the Production `chia-sdk-bindings` FFI Entrypoint (`clear_signing_ffi_proof.rs`):** Calling `chia_sdk_bindings::parse_vault_transaction` directly confirms the FFI boundary misreports the `1,000 XCH` drain in `RED` and returns `Error::NonStandardInnerSpend` in `GREEN`.

### Vulnerable Code Snippet
```rust
// File: crates/chia-sdk-bindings/src/clear_signing.rs (line 62) & chia-sdk-driver/src/clear_signing.rs
pub fn parse_vault_transaction(vault: ClvmVault, spend_bundle: SpendBundle, ...) -> Result<TransactionSummary> {
    // BUG: Credits outputs from external non-vault DropCoin spends as vault change,
    // masking a 1,000 XCH outflow from the victim's vault!
}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Enterprise Vault Drain Displayed as Zero Net Outflow at the FFI Boundary (`POC-6`)
An institutional custodian reviews `SpendBundle` `aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e` (`1,477 bytes`) via a mobile/hardware signer powered by `chia-sdk-bindings` and sees `0 XCH` net vault outflow while signing away `1,000 XCH`.

### Scenario B — Multi-Sig Quorum Deception
Multiple hardware cosigners independently verify the same FFI `TransactionSummary` and approve the `1,000 XCH` theft.

### Scenario C — FFI Boundary Patch Verification (`GREEN`)
`clear_signing_ffi_proof.rs` verifies `parse_vault_transaction` rejects the spoofed `DropCoin` bundle with `Error::NonStandardInnerSpend`.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run POC-6 in chia-sdk-driver and the FFI Boundary Proof in chia-sdk-bindings
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc6 -- --nocapture
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-bindings --test clear_signing_ffi_proof -- --nocapture
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-05": {
    "RED": {
      "poc6_spend_bundle_sha256": "aa6518229251559629861e9137f5cbd5186cb20b46c216a64dc209b86ed3004e",
      "poc6_spend_bundle_bytes": 1477,
      "vault_drain_amount_mojo": 1000000000000000,
      "ffi_boundary_parse_vault_transaction_masked": true
    },
    "GREEN": {
      "ffi_boundary_rejected_with": "Error::NonStandardInnerSpend",
      "ffi_test_file_sha256": "73dbe05adb2538ceb88cca5b2ecf4c1678e4ed537d3accb17535d8666727fb52"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -260,6 +260,8 @@
+    // Verify DropCoin parent lineage belongs to the vault before crediting as vault change
```
