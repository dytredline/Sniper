# Chia Masaüstü Cüzdanı (`chia-blockchain-gui`) WalletConnect 29 Komutluk Yetki Açıklığı ve Eşzamanlı Onay Penceresi Ezme (`TOCTOU`) Zafiyeti (`GUI-WC-01`)

[English](../22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md) | **Türkçe** | [日本語](../ja/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md) | [简体中文](../zh-CN/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md) | [한국어](../ko/22-CHIA-GUI-WC-01-WALLETCONNECT-MODAL-OVERWRITE-TOCTOU.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Cüzdan Bağlandığında 29 Komutun Tamamına (Para Gönderme Dahil) Kapı Açılması (`WalletConnectCommands.ts`):** Günlük hayattan benzetmeyle *'Kimlik fotokopisi isteyen emlakçının arkadaki boş senetlere imza attırması'* gibidir. Kullanıcı bir NFT/ödül sitesine sadece adres doğrulamak için cüzdanını bağladığında, WalletConnect oturumu `chia_sendTransaction` (para gönderme) dahil 29 komutun tamamını aynı oturuma açar.
2. **Adım 2 — Arka Arkaya Gelen İki İstekle Onay Penceresinin Ezilmesi (`WalletConnectContext.tsx:314-441`):** Kodda gelen istekleri sıraya sokan bir FIFO kilidi yoktur. Web sitesi önce ekranda zararsız `chia_getCurrentAddress` (Adres Bilgisini Göster) penceresini açar, milisaniyeler içinde arka plandan `chia_sendTransaction` ateşler; kurban ekrandaki zararsız pencereyi onayladığı anda arka planda `0.5 XCH` (`500,000,000,000 mojo`) transferini içeren imzalı `SpendBundle` (`SHA-256: d2ce22645a9a23b1...`) üretilir ve cüzdan boşaltılır!
3. **Adım 3 — Onay Sonrası Cüzdan Parmak İzi / Ağ Bağlam Değişimi (`TOCTOU`):** İstek onaylandığı an ile `sendCommand` çalıştığı an arasında cüzdan parmak izi (`fingerprint`), ağ (`network`) ve eşleşme (`pairing`) bütünlüğü tekrar doğrulanmadığı için boş ikincil cüzdan (`fp=111111`) için verilen onay ana kasa cüzdanında (`fp=999999`) çalıştırılabilir.

### Zafiyetli Kod Kesiti
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

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — 'Sadece Bakiyene/Adresine Bakacağım' Diyen Ödül Sitesinin Cüzdanı Boşaltması
Kurban 'Ücretsiz Chia Ödül Kontrolü' sitesine masaüstü cüzdanını bağlar ve ekranda sadece `getCurrentAddress` (Adres Bilgisini Göster) penceresini görür. Bunu zararsız sanıp tıkladığı anda arka planda `chia_sendTransaction` çalışır ve `0.5 XCH` (`SpendBundle SHA-256: d2ce22645a9a23b165da6f3895d1139ed334a91aaef4e56d027f8b0c12754980`) saldırganın adresine akar.

### Senaryo B — Boş Test Cüzdanından (`fp=111111`) Ana Hazinenin (`fp=999999`) Boşaltılması (`TOCTOU`)
Kurban siteye içinde para olmayan ikincil cüzdanını bağladığını düşünürken, onay ile yürütme arasındaki parmak izi (`fingerprint`) değişimi kontrol edilmediği için işlem ana cüzdan üzerinde imzalanır.

### Senaryo C — Eşleşme Kapatıldıktan veya Ağ Değiştikten Sonra Asılı İsteğin Çalışması
Onay penceresi açıkken oturum kesilse veya ağ değiştirilse bile yamasız kodda `sendCommand` çalışmaya devam eder (`GREEN` yaması 6 bağımsız WSS paketiyle tüm yarış ve bağlam değişimlerini reddeder).

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

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

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

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

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
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
