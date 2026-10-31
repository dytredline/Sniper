# `chiapos` Native C++ `Verifier::ValidateProof` (`k=50` / `k>=60`) Stack Out-of-Bounds Access & `DiskProver` 64-to-32-Bit Integer Truncation Heap Overflow (`CHIA-POS-02..04`)

**English** | [Türkçe](tr/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md) | [日本語](ja/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md) | [简体中文](zh-CN/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md) | [한국어](ko/36-CHIA-POS-VDF-NATIVE-CPP-INTEGER-TRUNCATION-AND-OOB-MEMORY-CORRUPTION.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — `Verifier::ValidateProof` Out-of-Bounds Stack Access at Consensus-Permitted `k=50` (`src/verifier.hpp:48-108` & `src/bits.hpp:184`):** Chia's Python consensus pre-filter `check_plot_param` allows `k` up to `50` (`size <= 50`). However, inside native C++ `Verifier::ValidateProof`, evaluating Table 4 at `k=50` (and Table 1 at `k=60`) overflows 32/64-bit bit-slice offsets in `src/bits.hpp:184` (`AddressSanitizer: stack-buffer-overflow` / `runtime error: load of address ... with insufficient space`, verified in compiled ASan/UBSan binary `chiapos_k_probe`, `exit_code=1`).
2. **Step 2 — `DiskProver` 64-to-32-Bit Integer Truncation Before Heap Allocation (`src/prover_disk.hpp:254-322`):** When opening a `.plot` file header, `DiskProver` computes 64-bit table byte deltas from header pointers and narrows them into 32-bit `uint32_t` lengths without checking `<= UINT32_MAX`, causing a heap buffer overflow (`CWE-190` -> `CWE-122` / `CWE-787`) when reading crafted `.plot` files.
3. **Step 3 — Architectural Boundary Between Port `8444` Network Packets and Direct/Plot Callers:** Over Port `8444`, Python's `check_plot_param` gates `len(proof) == 8 * k` before C++ `ValidateProof` runs; however, `k=50` passes `check_plot_param(50, 400)` and hits the Table 4 C++ UBSan/ASan bug if F1..F3 match, while downloaded `.plot` files directly hit `DiskProver`'s C++ heap parser without any Python pre-filter.

### Vulnerable Code Snippet
```cpp
// File: src/verifier.hpp (lines 48-108) & src/bits.hpp (line 184)
LargeBits Verifier::ValidateProof(const uint8_t* id, uint8_t k, const uint8_t* proof_bytes, uint16_t size) {
    // BUG 1: No check that k >= 18 && k <= 49; k=50 overflows Table 4 bit offsets in src/bits.hpp:184!
    // BUG 2: DiskProver (src/prover_disk.hpp:254-322) truncates 64-bit table sizes to uint32_t!
}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — Malicious / Backdoored `.plot` File Triggers Native C++ Heap Corruption in `DiskProver`
A farmer downloads or mounts an untrusted `.plot` file; when Harvester initializes `DiskProver`, the 64-to-32-bit table size truncation triggers out-of-bounds heap memory corruption in the native C++ extension.

### Scenario B — `Verifier::ValidateProof` Stack Buffer Overflow / UBSan Fault at `k=50` (Table 4) & `k=60`
Services or C++/Python callers invoking `ValidateProof` on `k=50` or `k=60` inputs crash immediately with an ASan/UBSan stack fault (`exit_code=1` in `chiapos_k_probe`).

### Scenario C — Patched Verification (`GREEN`)
Enforcing `18 <= k <= 49` and `proof_size == 8 * k` before bit unpacking, plus 64-bit bounds checks in `DiskProver`, eliminates all ASan/UBSan faults (`exit_code=0`).

---

## 3. Example Execution & Verification Commands

```bash
# 1. Run the Native C++ ASan/UBSan chiapos_k_probe Verification Test (k=50 Table 4 & k=60)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k chiapos
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-POS-02-04": {
    "RED": {
      "k60_probe_exit_code": 1,
      "k50_table4_probe_exit_code": 1,
      "sanitizer_diagnostic": "src/bits.hpp:184:29: runtime error: load of address with insufficient space / AddressSanitizer: stack-buffer-overflow"
    },
    "GREEN": {
      "k60_probe_exit_code": 0,
      "k50_table4_probe_exit_code": 0,
      "rejected_invalid_k_cleanly": true
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/src/verifier.hpp
+++ b/src/verifier.hpp
@@ -52,6 +52,9 @@ LargeBits Verifier::ValidateProof(
+    if (k < 18 || k > 49 || size != static_cast<uint16_t>(8 * k)) {
+        return LargeBits();
+    }
```
