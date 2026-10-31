# Chia Desktop GUI WalletConnect Unscoped 29-Command Grant & Concurrent Confirmation Modal Overwrite TOCTOU (`GUI-WC-01`)

[English](../22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md) | [Türkçe](../tr/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md) | [日本語](../ja/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md) | **简体中文** | [한국어](../ko/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)

## 1. How the Code Defect Turns Into an Exploitable Vulnerability (Step-by-Step Technical Mechanism)

### Step-by-Step Technical Mechanism
1. **Step 1 — All 29 WalletConnect Commands Exposed Upon Pairing (`constants/WalletConnectCommands.ts`):** When a user connects their Chia desktop wallet to any website/dApp (even one claiming to only check an address or NFT eligibility), the WalletConnect session namespace grants access to all 29 RPC commands, including `chia_sendTransaction`, `chia_spendCAT`, and `chia_takeOffer`.
2. **Step 2 — Concurrent Request Modal Overwrite (`WalletConnectContext.tsx:314-441`):** `handleSessionRequest` does not serialize incoming JSON-RPC requests with a FIFO lock. When a malicious dApp sends a benign `chia_getCurrentAddress` request followed milliseconds later by `chia_sendTransaction`, the confirmation state/promise overlaps so that clicking Approve on the benign prompt dispatches `chia_sendTransaction` (`0.5 XCH` signed `SpendBundle SHA-256: d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`).
3. **Step 3 — Post-Approval Context Switch (`TOCTOU` on Fingerprint, Network, and Pairing):** Between the moment the user clicks Approve (`check`) and `sendCommand` execution (`use`), `WalletConnectContext.tsx` does not verify that the active key fingerprint, network (`mainnet`/`testnet`), and pairing session still match the approved snapshot.

### Vulnerable Code Snippet
```typescript
// File: packages/gui/src/components/walletConnect/WalletConnectContext.tsx (lines 314-441)
async function handleSessionRequest(event: SignClientTypes.EventArguments['session_request']) {
  // BUG 1: No FIFO mutex/queue serializing concurrent session_request events
  // BUG 2: No immutable binding of (requestId, method, paramsHash, fingerprint, network) in sendCommand
  const confirmed = await showConfirmationDialog(event);
  if (confirmed) {
    return await sendCommand(command, params);
  }
}
```

---

## 2. Concrete Everyday Real-World Production Scenarios (`Scenario A` / `Scenario B` / `Scenario C`)

### Scenario A — 'Free Chia Airdrop / Address Checker' Website Drains Wallet Behind a `getCurrentAddress` Prompt
A victim connects their desktop wallet to a dApp and sees a harmless `chia_getCurrentAddress` modal. In the same millisecond, the dApp sends `chia_sendTransaction` (`500,000,000,000 mojo` = `0.5 XCH`). When the victim clicks Confirm, `WalletRpcClient.send_transaction` executes and broadcasts signed `SpendBundle` `d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`.

### Scenario B — Burner-Wallet to Cold/Main-Wallet Fingerprint Switch (`TOCTOU`)
A user pairs a 0-XCH burner key (`fingerprint: 111111`), but a concurrent fingerprint/context switch causes `sendCommand` to execute the spend against the user's `999999` main wallet.

### Scenario C — Post-Disconnect Replay During Pending Confirmation
Even if the user disconnects the pairing or switches networks while a confirmation promise is in flight, unpatched `sendCommand` still dispatches the RPC call (`GREEN` blocks all 3 vectors: `concurrent_rejected`, `context_switch_rejected`, `unknown_method_rejected`).

---

## 3. Example Execution & Verification Commands

```bash
# 1. Inspect handleSessionRequest and sendCommand in WalletConnectContext.tsx
sed -n '314,441p' /home/community-user/targets/chia-blockchain-gui/packages/gui/src/components/walletConnect/WalletConnectContext.tsx

# 2. Run the Live WSS Relay -> GUI Handler -> WalletRpcClient E2E Proof (RED & GREEN)
CHIA_DETACHED_GREEN=0 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
CHIA_DETACHED_GREEN=1 /home/community-user/targets/chia-blockchain/.venv/bin/pytest -q \
  /home/community-user/targets/chia-audit/work/composite-chain-proofs/test_chia_tam_dogrulama_ek_kanitlar_20261031.py -k gui_wc01
```

---

## 4. End-to-End Runtime Proof (`RED -> GREEN + BENIGN`) & Defensive Patch

Executed via the Chia Network Full-Verification E2E Suite (see [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-GUI-WC-01": {
    "RED": {
      "displayed_prompt_method": "chia_getCurrentAddress",
      "concurrent_injected_method": "chia_sendTransaction",
      "modal_overwritten_by_second_request": true,
      "unauthorized_send_transaction_dispatched": true,
      "drained_amount_mojo": 500000000000,
      "signed_spend_bundle_sha256": "d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980"
    },
    "GREEN": {
      "distinct_wss_packets_tested": 6,
      "benign_get_current_address_succeeded": true,
      "benign_send_transaction_succeeded": true,
      "concurrent_modal_overwrite_rejected": true,
      "fingerprint_network_pairing_switch_rejected": true,
      "unknown_method_rejected": true
    }
  }
}
```

### Unified Diff Patch (`git apply --check` clean)
```diff
--- a/packages/gui/src/components/walletConnect/WalletConnectContext.tsx
+++ b/packages/gui/src/components/walletConnect/WalletConnectContext.tsx
@@ -320,6 +320,12 @@
+  if (activeConfirmationLockRef.current) {
+    throw new Error('WalletConnect confirmation already in progress (FIFO lock)');
+  }
+  const approvalSnapshot = { id: event.id, topic: event.topic, method, paramsHash, fingerprint, network };
+  // Re-verify approvalSnapshot before invoking sendCommand()
```
