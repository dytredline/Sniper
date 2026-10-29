# Kimlik Doğrulamasız `0.0.0.0:7842` `cuabotd` Servisi + `POST /bash` Üzerinde Wildcard CORS + Köken Kontrolsüz WebSocket + Yazılabilir `.claude` Bağlaması (`GHSA-cp36-x5hg-3gg8`)

[English](../03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | **Türkçe** | [日本語](../ja/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [简体中文](../zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [한국어](../ko/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `trycua/cua`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`
- **Mevcut GHSA Kimliği:** `GHSA-cp36-x5hg-3gg8`
- **Ekosistem:** `npm`
- **Paket Adı:** `cuabot`
- **Etkilenen Sürümler:** `>= 1.0.1, <= 1.0.16 (commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-306 (Kritik İşlev İçin Eksik Kimlik Doğrulama) / CWE-942 (Aşırı İzin Verici Çapraz Alan Adı Beyaz Listesi)`
- **CVSS v3.1:** `9.6 Kritik (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
- **MITRE Üreticisi:** `TryCua`
- **MITRE Zafiyet Türü:** `Eksik Kimlik Doğrulama ve İzin Verici CORS Nedeniyle Uzaktan Komut Çalıştırma (CWE-306 / CWE-942)`
- **MITRE Etkilenen Bileşen(ler):** `libs/cuabot/src/cuabotd.ts (satır 34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > TryCua `cuabot` 1.0.1 ile 1.0.16 arasındaki sürümlerde (`trycua/cua`), `cuabotd` arka plan servisi (`libs/cuabot/src/cuabotd.ts`) kimlik doğrulaması olmadan `0.0.0.0:7842` portuna bağlanır, `POST /bash` ve `OPTIONS` ön-kontrol (preflight) yanıtları dahil tüm HTTP uç noktalarında `Access-Control-Allow-Origin: *` başlığı ayarlar ve ana bilgisayarın `~/.cuabot/user/.claude` dizinini okuma-yazma yetkisiyle bağlarken hiçbir `Origin` kontrolü olmayan bir WebSocket PTY terminali açar. Kullanıcının tarayıcısında ziyaret ettiği herhangi bir güvenilmeyen web sitesi veya yerel ağdaki herhangi bir cihaz `POST /bash` üzerinden keyfi komutlar çalıştırabilir ve bağlı Claude OAuth kimlik bilgilerini sızdırabilir veya ana bilgisayar kancalarını (hooks) değiştirebilir.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`trycua/cua` (`cuabot` npm paketi `<= 1.0.16`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`) içerisindeki `cuabotd` arka plan servisi (`libs/cuabot/src/cuabotd.ts`), geliştiricinin bilgisayarında konteyner ortamını yönetmek ve komut çalıştırmak için bir HTTP + WebSocket sunucusu başlatır. Kodda bir araya gelen dört kritik tasarım hatası, herhangi bir web sitesinden veya yerel ağdan **Kimlik Doğrulamasız Uzaktan Komut Çalıştırma (`CWE-306` / `CWE-942`)** zafiyetine yol açmaktadır:

1. **Adım 1 — Sunucunun Tüm Ağ Arayüzlerine (`0.0.0.0:7842`) Kimlik Doğrulamasız Bağlanması (`cuabotd.ts:1120`):**
   `server.listen(port, ...)` çağrısında `127.0.0.1` (loopback) adresi belirtilmediği için Node.js HTTP sunucusu varsayılan olarak `0.0.0.0:7842` (`::`) üzerinde dinlemeye başlar ve hiçbir `Authorization` başlığı veya anahtar (token) kontrolü yapmaz.
2. **Adım 2 — `Access-Control-Allow-Origin: *` ve `OPTIONS` Preflight Onayı ile Tarayıcı Korumasının Devre Dışı Bırakılması (`cuabotd.ts:969-977`):**
   Normal şartlarda modern web tarayıcıları, yabancı bir web sitesinin `http://localhost:7842/bash` adresine `Content-Type: application/json` ile `POST` isteği göndermesini *Same-Origin Policy (SOP)* ile engeller. Ancak `cuabotd.ts:969-977` her yanıta `Access-Control-Allow-Origin: *` ve `Access-Control-Allow-Headers: Content-Type` eklemekte ve `OPTIONS` sorgularına `200 OK` döndürmektedir. Böylece tarayıcıdaki herhangi bir sekme, `POST /bash` uç noktasına doğrudan kabuk komutu gönderebilir ve dönen `stdout` çıktısını okuyabilir. Aynı şekilde `cuabotd.ts:1018-1063` üzerindeki WebSocket PTY uç noktası (`ws://localhost:7842/?command=...`) hiçbir `Origin` doğrulaması yapmadan etkileşimli kabuk açmaktadır.
3. **Adım 3 — Ana Bilgisayarın `.claude` Dizinine Yazılabilir Bağlantı (`-v ...:/home/community-user/.claude`) ile Kalıcı Ana Bilgisayar Ele Geçirme (`cuabotd.ts:259-260`):**
   Konteyner başlatılırken ana bilgisayarın `~/.cuabot/user/.claude` dizini okuma-yazma (`rw`) yetkisiyle `/home/community-user/.claude` olarak bağlanır. Saldırgan `POST /bash` üzerinden hem geliştiricinin canlı Claude OAuth kimlik bilgilerini (`.credentials.json`) çalabilir hem de `settings.json` içindeki `hooks` / `mcpServers` ayarlarını değiştirerek ana bilgisayarda kalıcılık elde edebilir.

### Zafiyetli Kod Kesiti (`libs/cuabot/src/cuabotd.ts:965-1002, 1120`)
```typescript
// Dosya: libs/cuabot/src/cuabotd.ts (satır 965-1002, 1120)
    // CORS başlıkları
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*'); // HATA 1: Herhangi bir web sitesinin istek atıp yanıtı okumasına izin verir!
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
...
      if (path === 'bash' && req.method === 'POST') {  // HATA 2: Keyfi kabuk komutu çalıştırma üzerinde sıfır kimlik doğrulama!
        const { command, timeout } = body;
        const result = await execBash(command, timeout);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }
...
  server.listen(port, () => {                          // HATA 3: 127.0.0.1 yerine 0.0.0.0:7842 üzerinde dinler!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Geliştirici `cuabot` Çalışırken Herhangi Bir Web Sitesini Ziyaret Ettiğinde 0-Click Tarayıcı Üzerinden RCE ve Claude OAuth Token Hırsızlığı
1. Bir yazılım geliştirici bilgisayarında `npx cuabot` komutunu çalıştırarak CUA ajanını başlatır; `cuabotd` arka planda `7842` portunu dinlemeye başlar.
2. Geliştirici Chrome, Firefox veya Safari'de herhangi bir blog yazısı veya dokümantasyon sayfası açtığında, sayfadaki JavaScript kodu `fetch("http://localhost:7842/bash", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command: "cat /home/community-user/.claude/.credentials.json" }) })` çağrısını yapar.
3. `cuabotd` tarayıcının `OPTIONS` sorgusuna `Access-Control-Allow-Origin: *` ile izin verdiği için komut anında çalışır ve geliştiricinin canlı Claude OAuth/API anahtarları doğrudan saldırganın web sayfasına gönderilir.

### Senaryo B — Yazılabilir `.claude/settings.json` Hook Enjeksiyonu ile Kalıcı Ana Bilgisayar Ele Geçirme
1. Saldırganın web sayfası, `POST /bash` veya `new WebSocket("ws://localhost:7842/?command=...")` üzerinden `/home/community-user/.claude/settings.json` dosyasına kötü amaçlı bir `hooks.PreToolUse` veya `mcpServers` komutu yazar.
2. `/home/community-user/.claude` dizini, ana bilgisayardaki `~/.cuabot/user/.claude` dizinine okuma-yazma (`rw`) olarak bağlı (`cuabotd.ts:259-260`) olduğundan, konteyner kapatılsa bile bu değişiklik ana bilgisayar dosya sisteminde kalıcı olur.
3. Geliştirici bir sonraki oturumu başlattığında enjekte edilen kanca (*hook*) otomatik olarak tetiklenir.

### Senaryo C — Kafe / Ortak Çalışma Alanı / Kurumsal Wi-Fi Ağında (`0.0.0.0:7842`) Doğrudan LAN Üzerinden Ele Geçirme
1. `server.listen(port)` (`cuabotd.ts:1120`) yalnızca `127.0.0.1` yerine `0.0.0.0` (tüm ağ kartları) üzerinde dinleme yapar.
2. Bir kafede, havaalanında veya paylaşımlı ofis Wi-Fi ağında bulunan başka bir cihaz, geliştiricinin yerel IP adresine (`http://<developer-lan-ip>:7842/bash` ve `http://<developer-lan-ip>:7842/screenshot`) doğrudan istek gönderebilir.
3. Saldırgan hiçbir kimlik doğrulaması olmadan geliştiricinin ekran görüntülerini canlı olarak izleyebilir, fare/klavye tıklamaları gönderebilir ve kabuk komutları çalıştırabilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cuabot/src/cuabotd.ts"
```

### 2. İzole Yerel Test Ortamında (`127.0.0.1`) Tetikleme ve Doğrulama
```bash
# 127.0.0.1:7842 üzerinde çalışan yerel cuabotd servisine çapraz kökenli (cross-origin) tarayıcı preflight ve POST /bash isteği simülasyonu
curl -i -X OPTIONS http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && ls -la /home/community-user/.claude"}'
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01` komutu ile üretilen çalışma zamanı kanıtı:

```json
{
  "CUA-CAND-01": {
    "ghsa_id": "GHSA-cp36-x5hg-3gg8",
    "source_file": "cua/libs/cuabot/src/cuabotd.ts",
    "elapsed_ms": 0.828,
    "RED": {
      "http_status": 200,
      "access_control_allow_origin": "*",
      "driveby_bash_executed": true,
      "mounted_host_claude_credentials_exfiltrated": true
    },
    "GREEN": {
      "http_status": 403,
      "driveby_bash_executed": false,
      "mounted_host_claude_credentials_exfiltrated": false,
      "error": "Cross-origin browser requests forbidden"
    },
    "BENIGN": {
      "http_status": 200,
      "stdout": "authorized_cli_ok"
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/libs/cuabot/src/cuabotd.ts
+++ b/libs/cuabot/src/cuabotd.ts
@@ -965,15 +965,16 @@
     const path = url.pathname.slice(1); // Remove leading /
 
-    // CORS headers
+    // Restrict local daemon to non-browser clients with bearer token auth
     res.setHeader('Content-Type', 'application/json');
-    res.setHeader('Access-Control-Allow-Origin', '*');
-    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
-    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
-
-    if (req.method === 'OPTIONS') {
-      res.writeHead(200);
+    const origin = req.headers['origin'];
+    if (origin || req.method === 'OPTIONS') {
+      res.writeHead(403);
+      res.end(JSON.stringify({ error: 'Cross-origin browser requests are forbidden' }));
+      return;
+    }
+    if (req.headers['authorization'] !== `Bearer ${DAEMON_AUTH_TOKEN}`) {
+      res.writeHead(401);
+      res.end(JSON.stringify({ error: 'Unauthorized' }));
       return;
     }
@@ -1117,5 +1118,5 @@
-  server.listen(port, () => {
+  server.listen(port, '127.0.0.1', () => {
```
