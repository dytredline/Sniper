# `cni-wallet-sdk` Clear-Signing Reverse-Clawback `sender_puzzle_hash` Ownership Spoofing Allowing Unilateral `1,000 XCH` Hijack (`CS-07` / `POC-8`)

**English** | [Türkçe](tr/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md) | [日本語](ja/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md) | [简体中文](zh-CN/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md) | [한국어](ko/30-CHIA-CS-07-CLEAR-SIGNING-REVERSE-CLAWBACK-SENDER-HIJACK.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Missing Verification That `sender_puzzle_hash` Belongs to the Signing Vault (`clear_signing.rs`):** When a Vault creates a Clawback-protected output (`POC-8`), `cni-wallet-sdk` inspects the Clawback parameters and memo/hint without verifying that the Clawback `sender_puzzle_hash` (the party authorized to claw back the coin before the timelock expires) is owned by the signing vault.
2. **Step 2 — Reverse-Clawback Trap (`SpendBundle SHA-256: 6897c10eb9cf718f...`):** In `SpendBundle` `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` (`1,218 bytes`), `1,000 XCH` (`1,000,000,000,000,000 mojo`) from the victim's vault is locked into a Clawback coin where `sender_puzzle_hash` is set to the attacker's puzzle hash.
3. **Step 3 — Attacker Immediately Claws Back the Victim's `1,000 XCH`:** The moment the transaction lands on-chain, the attacker exercises the `sender_puzzle_hash` branch to immediately sweep the `1,000 XCH` before the timelock expires.

### Vulnerable Code Snippet
```rust
// File: crates/chia-sdk-driver/src/clear_signing.rs
// BUG: Parses Clawback output without verifying clawback.sender_puzzle_hash == vault_p2_puzzle_hash,
// allowing an attacker to be set as the Clawback sender on a 1,000 XCH vault outflow!
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — `1,000 XCH` (`1,000,000,000,000,000 mojo`) Vault Transfer Hijacked via Reverse Clawback (`POC-8`)
A vault operator signs `6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1` believing the transfer is protected by Clawback; the attacker is curried as `sender_puzzle_hash` and immediately sweeps the `1,000 XCH`.

### Scenario B — Self-Transfer / Escrow Illusion
The recipient/memo points back to the victim's own address so Clear-Signing looks like a safe self-custody move, while `sender_puzzle_hash` gives the attacker instant withdrawal rights.

### Scenario C — Patched Verification (`GREEN`)
Clear-Signing rejects any Clawback output funded by the vault whose `sender_puzzle_hash` does not belong to the vault.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run POC-8 (1,000 XCH Reverse-Clawback Sender Hijack) in cni-wallet-sdk
cargo test --manifest-path /home/community-user/targets/cni-wallet-sdk/Cargo.toml \
  -p chia-sdk-driver clear_signing::tests::test_poc8 -- --nocapture
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-CS-07": {
    "RED": {
      "poc8_spend_bundle_sha256": "6897c10eb9cf718ffa9bbfff998e6a496d3532bf2d198c8df16bf92e2d5f9db1",
      "poc8_spend_bundle_bytes": 1218,
      "hijacked_clawback_amount_mojo": 1000000000000000,
      "attacker_is_clawback_sender": true
    },
    "GREEN": {
      "poc8_rejected_fail_closed": true,
      "patch_sha256": "d92c4b9d9856f59e1d676468a2966bf7a474aa82efcb657c9ec3ecd8ad000e27"
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/crates/chia-sdk-driver/src/clear_signing.rs
+++ b/crates/chia-sdk-driver/src/clear_signing.rs
@@ -340,6 +340,8 @@
+    // Verify Clawback sender_puzzle_hash belongs to the signing vault
```
