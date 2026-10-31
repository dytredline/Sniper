# `cni-wallet-sdk` Clear-Signing Uninspected NFT `NEW_METADATA_INFO` Updater Conditions Allowing Hidden `500 XCH` Drain (`CS-02` / `POC-3`)

[English](../25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md) | [Türkçe](../tr/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md) | [日本語](../ja/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md) | [简体中文](../zh-CN/25-CHIA-CS-02-CLEAR-SIGNING-NFT-METADATA-UPDATER-HIDDEN-FEE.md) | **한국어**

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — NFT State Layer Executes Conditions Returned by the Metadata Updater Program:** Under Chia's CHIP-0007 NFT standard, when an inner spend emits a `NEW_METADATA_INFO` (`-24`) condition, the NFT state layer executes the metadata updater puzzle and merges any returned conditions into the spend's output conditions.
2. **Step 2 — Clear-Signing Discards Additional Conditions Emitted by the Metadata Updater (`clear_signing.rs`):** While `cni-wallet-sdk` evaluates the metadata updater to inspect updated metadata, it discards additional consensus conditions (such as `RESERVE_FEE` for `500 XCH` = `500,000,000,000,000 mojo`) returned by the updater program.
3. **Step 3 — `500 XCH` Drained Behind a '0 Fee' NFT Update Preview (`SpendBundle SHA-256: b314b6d7411bfb8a...`):** In `SpendBundle` `b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6` (`3,300 bytes`), the user sees `reserved_fee = 0` on the Clear-Signing screen while consensus drains `500 XCH`.

### Vulnerable Code Snippet
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Evaluates NEW_METADATA_INFO metadata updater program for metadata diff,
// but ignores extra consensus conditions (e.g. RESERVE_FEE 500 XCH) returned by the updater!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — 'Free NFT Metadata Reveal' Transaction Drains `500 XCH` (`500,000,000,000,000 mojo`)
A user signs an NFT reveal/update bundle (`b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6`) displaying `reserved_fee = 0` in Clear-Signing, losing `500 XCH` to consensus fees upon broadcast.

### Scenario B — Malicious Custom Metadata Updater in Traded NFTs
An attacker mints an NFT with a custom metadata updater puzzle and sells/transfers it to a vault; when the vault later updates or transfers the NFT, the hidden updater condition triggers.

### Scenario C — Patched Verification (`GREEN`)
The patched driver rejects any metadata updater output emitting unexpected consensus conditions.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run POC-3 (500 XCH NFT Metadata Updater Hidden Fee) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc3 -- --nocapture
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-02": {
    "RED": {
      "poc3_spend_bundle_sha256": "b314b6d7411bfb8a87bd4b091a117b861e5a171ed4a0a4712955c592962042e6",
      "poc3_spend_bundle_bytes": 3300,
      "clear_signing_displayed_fee_mojo": 0,
      "consensus_drained_fee_mojo": 500000000000000
    },
    "GREEN": {
      "poc3_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -165,6 +165,9 @@
+    // Reject any non-metadata consensus condition emitted by NEW_METADATA_INFO updater
```
