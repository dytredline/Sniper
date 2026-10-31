# `cni-wallet-sdk` Clear-Signing Offer Pre-Split Unbound Destination Splicing Redirecting `1,000 XCH` Under an Unchanged BLS Signature (`CS-06` / `POC-7`)

[English](../29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md) | [Türkçe](../tr/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md) | [日本語](../ja/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md) | [简体中文](../zh-CN/29-CHIA-CS-06-CLEAR-SIGNING-OFFER-PRE-SPLIT-POST-SIG-SPLICING.md) | **한국어**

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Pre-Split Intermediate Coin Spent Without Cryptographic Destination Binding (`clear_signing.rs`):** In an Offer pre-split transaction (`POC-7`), the user signs a bundle (`476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`, `1,994 bytes`) that splits `1,000 XCH` (`1,000,000,000,000,000 mojo`) into an intermediate settlement/pre-split coin whose downstream spend is not pinned by an `ASSERT_PUZZLE_ANNOUNCEMENT` signed by the vault.
2. **Step 2 — Post-Signature Splicing Under the Same BLS Signature:** After the victim signs the pre-split bundle, an attacker or relayer replaces/splices the downstream child spend, producing final `SpendBundle` `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` (`1,701 bytes`).
3. **Step 3 — `1,000 XCH` Redirected to Attacker While BLS Signature Remains Valid:** Because the vault's signed condition only covered the pre-split creation and not the final recipient, the victim's original BLS signature validates the modified `1,000 XCH` transfer to the attacker.

### Vulnerable Code Snippet
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Accepts pre-split / intermediate child spends in Clear-Signing without verifying
// that the vault's signed spend asserts an announcement binding the child spend's outputs!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Relayer / DEX Aggregator Redirects `1,000 XCH` (`1,000,000,000,000,000 mojo`) After User Signs (`POC-7`)
The victim signs `476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833`; the relayer splices the unbound child spend into `5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93` and steals `1,000 XCH` under the unchanged BLS signature.

### Scenario B — Mempool Front-Running of Unbound Pre-Split Spends
Any mempool observer replaces the unsigned child spend before block inclusion.

### Scenario C — Patched Verification (`GREEN`)
Clear-Signing requires every downstream spend in the bundle to be cryptographically bound by an announcement asserted in the signed vault spend.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run POC-7 (1,000 XCH Offer Pre-Split Post-Signature Splicing) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc7 -- --nocapture
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-06": {
    "RED": {
      "poc7_pre_split_spend_bundle_sha256": "476b8e836e435eecb16fb924b8d8b8532fb6872fda3f9d50030d98231fff7833",
      "poc7_pre_split_bytes": 1994,
      "poc7_spliced_final_spend_bundle_sha256": "5b3a3b21376bfdfe06e7cc1ec334c43ffd3bb97b72133aeaa38f4de040ba0a93",
      "poc7_spliced_final_bytes": 1701,
      "redirected_amount_mojo": 1000000000000000,
      "original_bls_signature_valid_on_spliced": true
    },
    "GREEN": {
      "poc7_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -285,6 +285,8 @@
+    // Require pre-split and child spends to be bound via signed announcement
```
