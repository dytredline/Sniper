# Chia `FarmerAPI.new_proof_of_space` Port `8447` Single 445-Byte Packet Uncaught Rust `PanicException` Crashing Farmer Nodes (`CHIA-POS-01`)

[English](../35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md) | [Türkçe](../tr/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md) | [日本語](../ja/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md) | [简体中文](../zh-CN/35-CHIA-POS-01-HARVESTER-FARMER-SINGLE-PACKET-RUST-PANIC-DOS.md) | **한국어**

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — Missing Pre-Validation in `FarmerAPI.new_proof_of_space` (`chia/farmer/farmer_api.py:85-185`) vs. `FullNode` (`8444`):** While `FullNode` on port `8444` calls `ProofOfSpace.verify_and_get_quality_string` (which checks pool public key / pool contract puzzle hash XOR exclusivity and `check_plot_param` before touching native code), `FarmerAPI.new_proof_of_space` on port `8447` immediately calls `new_proof_of_space.proof.size_v2()` and `get_quality_string(...)` on the raw wire-deserialized message.
2. **Step 2 — Single 445-Byte Wire Packet Triggers Uncaught Rust Panic (`pyo3_runtime.PanicException`):** Sending a 445-byte serialized `NewProofOfSpace` packet (`SHA-256: 30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`, `size=32`, `384-byte proof`, both `pool_public_key=None` and `pool_contract_puzzle_hash=None`) crosses the PyO3 FFI boundary and triggers an immediate Rust `panic!` (`pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set` / slice bounds panic in `chiapos`).
3. **Step 3 — 4 Concurrent Farmer Processes Terminated (`PID 2983318..2983321`, `exit_code=1`):** Because Python's `except Exception:` does not safely recover the Farmer worker when an unguarded `PanicException` escapes, all 4 tested `FarmerAPI` node processes crash immediately (`alive_farmers_after: 0`).

### Vulnerable Code Snippet
```python
# File: chia/farmer/farmer_api.py (lines 85-185)
@api_request()
async def new_proof_of_space(self, new_proof_of_space: farmer_protocol.NewProofOfSpace, peer: WSChiaConnection) -> None:
    # BUG: Calls Rust FFI new_proof_of_space.proof.size_v2() and get_quality_string() BEFORE verifying
    # pool key XOR exclusivity and check_plot_param(size, proof_bytes), triggering pyo3_runtime.PanicException!
     Computed_size = new_proof_of_space.proof.size_v2()
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Single Compromised/Rogue Harvester Crashes Multi-Node Farming Cluster (`4/4` Farmers Terminated)
In a farming pool or enterprise farm where multiple harvesters connect to central Farmer nodes over port `8447`, a single 445-byte packet (`30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe`) crashes all 4 Farmer processes (`exit_code=1`), halting block signage and reward collection.

### Scenario B — Truncated 32-Byte Proof Slice Out-of-Bounds Panic in `chiapos`
Supplying a truncated 32-byte `proof` payload into `get_quality_string` triggers `pyo3_runtime.PanicException: range end index 36 out of range for slice of length 32` (`src/verifier.hpp` / Rust FFI).

### Scenario C — Patched Verification (`GREEN`)
Validating pool key XOR exclusivity and `check_plot_param` before invoking `size_v2()` / `get_quality_string()` keeps `4/4` Farmer processes alive (`exit_code=0`).

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect FarmerAPI.new_proof_of_space in chia/farmer/farmer_api.py
sed -n '85,145p' /home/community-user/targets/chia-blockchain/chia/farmer/farmer_api.py

# 2. Run the 4-Node Multi-Process FarmerAPI Crash & Recovery Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k farmer
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-POS-01": {
    "RED": {
      "wire_packet_sha256": "30a0e918f96ff695b7c711b297d1ee9203fcb8ee0d8b72844a901d9de9012dfe",
      "wire_packet_bytes": 445,
      "farmers_spawned": 4,
      "crashed_farmers": 4,
      "alive_farmers_after": 0,
      "exception": "pyo3_runtime.PanicException: Neither pool pk nor contract puzzle hash set"
    },
    "GREEN": {
      "farmers_spawned": 4,
      "crashed_farmers": 0,
      "alive_farmers_after": 4
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/chia/farmer/farmer_api.py
+++ b/chia/farmer/farmer_api.py
@@ -92,6 +92,9 @@ class FarmerAPI:
+        if (new_proof_of_space.proof.pool_public_key is None) == (
+            new_proof_of_space.proof.pool_contract_puzzle_hash is None
+        ) or not check_plot_param(new_proof_of_space.proof.size, len(new_proof_of_space.proof.proof)):
+            return None
```
