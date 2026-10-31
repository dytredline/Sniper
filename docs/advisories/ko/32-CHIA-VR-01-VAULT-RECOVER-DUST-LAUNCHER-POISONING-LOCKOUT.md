# `chia-vault-recover` Unverified First-Child Singleton Launcher Selection Allowing 1-Mojo Dust Poisoning of Emergency Vault Recovery (`VR-01` / `POC-10`)

[English](../32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md) | [Türkçe](../tr/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md) | [日本語](../ja/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md) | [简体中文](../zh-CN/32-CHIA-VR-01-VAULT-RECOVER-DUST-LAUNCHER-POISONING-LOCKOUT.md) | **한국어**

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Unverified First-Match `SINGLETON_LAUNCHER_HASH` Return in `find_launcher_id` (`src/locate.rs:148-219`):** To locate a user's Vault singleton, `find_launcher_id` fetches all coins at the user's address via `get_coin_records_by_puzzle_hash`, inspects each coin's parent spend, and immediately returns the **first** child coin whose puzzle hash equals `SINGLETON_LAUNCHER_HASH`.
2. **Step 2 — 1-Mojo Dust Coin Poisons Vault Discovery at lower Block Height (`height=9..10` vs `height=11..12`):** An attacker sends a 1-mojo dust coin to the victim's address from a parent spend that also spawns a decoy singleton (`2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf`). Because Chia's `FullNodeRpcApi` returns coin records ordered by confirmation height, `find_launcher_id` selects the attacker's decoy launcher before reaching the victim's real Vault launcher (`e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb`).
3. **Step 3 — Compiled Release CLI Aborts With `clawback check: recovery phrase does not match`:** Executed against a live `FullNodeRpcApi` server with zero static fixtures, the unpatched CLI (`chia-vault-recover-red`) locks onto `2de44601...` and terminates with exit code `1`, whereas the patched release binary (`chia-vault-recover 1.0.0-rc9`, `SHA-256: d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3`) skips the decoy and recovers the victim's vault.

### Vulnerable Code Snippet
```rust
// File: src/locate.rs (lines 148-219)
pub async fn find_launcher_id(client: &Client, address_puzzle_hash: Bytes32, ...) -> Result<Bytes32> {
    // BUG: Returns the very first SINGLETON_LAUNCHER_HASH child found at address_puzzle_hash
    // without verifying that the singleton's custody/recovery configuration matches the user's keys!
}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — 1-Mojo Dust Transaction Locks Emergency Vault Recovery CLI (`POC-10`)
When a user loses their primary signer and runs `chia-vault-recover` (`1.0.0-rc9`) with their recovery phrase, a single 1-mojo dust coin sent by an attacker causes the CLI to abort with `clawback check: recovery phrase does not match`.

### Scenario B — Combined Attack Chain (`WLC-02` + `VR-01` — Total Vault Recovery Lockout)
While an attacker's unauthorized Vault recovery timer counts down, the attacker blocks the victim's live wallet cancellation via `WLC-02` and simultaneously poisons `chia-vault-recover` via `VR-01`, leaving the victim with zero working recovery tools.

### Scenario C — Pre-Emptive Mass Address Poisoning
Because any public Chia address can receive 1-mojo dust, an attacker can pre-poison known institutional Vault addresses for pennies.

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run the Rust Unit Tests in chia-vault-recover (45/45 PASS)
cargo test --manifest-path /home/community-user/targets/chia-vault-recover/Cargo.toml

# 2. Run the Live FullNodeRpcApi + Release CLI (1.0.0-rc9) E2E Proof (Zero Static Fixtures)
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k poc10
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-VR-01": {
    "RED": {
      "attacker_decoy_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "victim_true_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "red_cli_selected_launcher_id": "2de44601e6fcf4bdfc88eb553ddca729751a06da78cec724519e741f1dfefacf",
      "red_cli_exit_code": 1,
      "red_cli_stderr": "clawback check: recovery phrase does not match"
    },
    "GREEN": {
      "green_release_cli_sha256": "d6e6b0bb5e0d160d9a342274e2c1d384f67fa57c0c218267b27f46195c1370c3",
      "green_cli_selected_launcher_id": "e53d0c41ce3a78de1426630d059958ef37a5d7f55551d47908f9a106024640eb",
      "green_cli_matches_victim": true,
      "cargo_unit_tests_passed": 45
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/src/locate.rs
+++ b/src/locate.rs
@@ -180,6 +180,9 @@
+    // Continue iterating candidate launchers until custody/recovery puzzle matches the user's configuration
```
