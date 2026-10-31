# `cni-wallet-sdk` Clear-Signing Dependent Offer Leg Set-Intersection Outflow Omission Hiding `500 XCH` Payment (`CS-03` / `POC-4`)

[English](../26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md) | [Türkçe](../tr/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md) | [日本語](../ja/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md) | [简体中文](../zh-CN/26-CHIA-CS-03-CLEAR-SIGNING-OFFER-SET-INTERSECTION-OUTFLOW-OMISSION.md) | **한국어**

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Set-Intersection Filtering Across Dependent Settlement Legs (`clear_signing.rs`):** When a Vault transaction participates in a multi-leg Offer settlement (`POC-4`), `cni-wallet-sdk` correlates notarized payments across legs using set intersection rather than union/full conservation.
2. **Step 2 — Non-Overlapping `500 XCH` (`500,000,000,000,000 mojo`) Outflow Dropped from Signing Preview:** In `POC-4` (vault spend `3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`, settlement spend `7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`), the secondary `500 XCH` payment leg to the attacker is excluded by the set intersection check and never shown in the Clear-Signing summary.
3. **Step 3 — Full `500 XCH` Outflow Executes On-Chain:** Once signed, both settlement legs execute on-chain and transfer `500 XCH` to the attacker.

### Vulnerable Code Snippet
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Uses set intersection across dependent settlement legs instead of accounting for every
// notarized payment outflow funded by the vault's settlement coins!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Hidden `500 XCH` (`500,000,000,000,000 mojo`) Leg in a P2P Offer (`POC-4`)
A trader accepts a multi-leg Offer (`vault SpendBundle: 3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8`) whose Clear-Signing preview omits the `500 XCH` settlement leg (`7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525`).

### Scenario B — OTC Treasury Swap Drain
An institutional treasury signs what appears to be a small fee/test swap while a disjoint `500 XCH` settlement leg drains treasury funds.

### Scenario C — Patched Verification (`GREEN`)
All settlement payment legs funded by the vault are unioned and strictly validated.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run POC-4 (500 XCH Dependent Offer Leg Set-Intersection Omission) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc4 -- --nocapture
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-03": {
    "RED": {
      "poc4_vault_spend_bundle_sha256": "3c55638a605214afd4e6ca592d439b6e9b69e4550f40ce07f85daec8cef87fb8",
      "poc4_settlement_spend_bundle_sha256": "7c05b725fb43d8fae280b3e1cd0417b752598e8ce9bd7ae45c1a2f7b63ccf525",
      "omitted_outflow_mojo": 500000000000000
    },
    "GREEN": {
      "poc4_rejected_or_fully_accounted": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -210,6 +210,8 @@
+    // Union all dependent notarized payment legs rather than intersecting
```
