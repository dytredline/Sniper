# Next.js `/_next/image` (`fetchExternalImage`) `3xx` Yönlendirme `remotePatterns` İzin Listesi Atlaması ve `isPrivateIp()` Fail-Open Loopback/İç Ağ SSRF (`VERCEL-NEXT-09` / HackerOne `#4152265`)

[English](../40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md) | **Türkçe** | [日本語](../ja/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md) | [简体中文](../zh-CN/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md) | [한국어](../ko/40-VERCEL-NEXT-09-IMAGE-OPTIMIZER-REDIRECT-ALLOWLIST-AND-PRIVATE-IP-FAIL-OPEN-SSRF.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `remotePatterns` Kontrolünün Yalnızca İlk İstek Hopunda Yapılması (`image-optimizer.js:586-615`):** `validateParams()` fonksiyonu `hasMatch(domains, remotePatterns, href)` kontrolünü yalnızca ilk `/_next/image?url=...` parametresinde çalıştırır. İzin verilen sunucu `301`/`302`/`307`/`308` döndürdüğünde `fetchExternalImage()` yeni `Location` adresini yalnızca `validateUrl()` fonksiyonuna sokar; `hasMatch()` kontrolünü tekrar çağırmaz. Böylece hem **aynı sunucu içindeki dizin kısıtlamaları** (`/public-avatars/**` -> `/private-kyc-docs/passport-scan.png`) hem de **farklı alan adı kısıtlamaları** tamamen aşılır.
2. **Adım 2 — Monte Edilen HackerOne Yorumu #1 (`RE-EVALUATION-COMMENT-4152265`): İlk Hop İçin Ele Geçirilmiş Sunucuya Neden Gerek Yoktur:** Gravatar (`?d=https://...`), Cloudinary ve çok kiracılı S3 / R2 / Supabase Storage / Vercel Blob kovaları tasarım gereği `301`/`302` yönlendirmesi üretir.
3. **Adım 3 — Monte Edilen HackerOne Yorumu #1 (`RE-EVALUATION-COMMENT-4152265`): NAT64 Olmadan Standart Linux/Docker Çekirdeğinde Doğrudan `127.0.0.1` Soketine Bağlanma (`if (!ipaddr.isValid(ip)) return false`):** `next/dist/compiled/ipaddr.js` içindeki IPv6 `zoneIndex` düzenli ifadesi (`const o = "%[0-9a-z]{1,}"`) tire (`-`), alt çizgi (`_`) ve nokta (`.`) karakterlerini reddeder. Standart Linux/Docker/K8s sunucularındaki `br-1a49f5828144`, `docker_gwbridge`, `cni-podman0` gibi arayüzlerde `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` çekirdekte başarılı olur, `ipaddr.isValid()` `false` döner, `isPrivateIp()` **fail-open (`return false`)** yapar ve Node.js `http.get` doğrudan `127.0.0.1` loopback soketine bağlanarak iç yanıtı sızdırır!
4. **Adım 4 — Monte Edilen HackerOne Yorumu #1 & #2 (`ADDENDUM-SCENARIOS-4152265`): WHATWG `URL` vs. `ipaddr.js` RFC 4291 `::7f00:1` Ayrıştırıcı Farkı ve RFC 8215 `64:ff9b:1::/48` NAT64 Atlaması:** `Location: http://[::127.0.0.1]:8080/internal.png` adresi WHATWG `new URL()` tarafından `::7f00:1` olarak normalize edilir; `ipaddr.parse('::7f00:1').range()` ve `ipaddr.parse('64:ff9b:1::a9fe:a9fe').range()` `'unicast'` döndürdüğü için `isPrivateIp()` `false` verir!

### Zafiyetli Kod Kesiti
```javascript
// 1. Missing matchRemotePattern / hasMatch check on 3xx redirects in fetchExternalImage()
// File: node_modules/next/dist/esm/server/image-optimizer.js (lines 586-615)
if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
    if (redirectCount >= maxRedirects) {
        throw new ImageError(400, '"url" parameter reached maxRedirects');
    }
    const redirectUrl = new URL(res.headers.get('location'), href).href;
    const parsedRedirectUrl = new URL(redirectUrl);
    // BUG 1 (09A): Only calls validateUrl(parsedRedirectUrl); NEVER re-checks hasMatch(domains, remotePatterns, parsedRedirectUrl)!
    await validateUrl(parsedRedirectUrl);
    return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, redirectCount + 1);
}

// 2. isPrivateIp() fails open on hyphenated Linux IPv6 zone indices & RFC 4291 / RFC 8215 ranges
// File: node_modules/next/dist/esm/server/lib/find-root.js
function isPrivateIp(ip) {
    if (!ipaddr.isValid(ip)) {
        return false; // BUG 2 (09B): Fail-open! "::ffff:127.0.0.1%br-1a49f5828144" -> isValid=false -> returns false!
    }
    const addr = ipaddr.parse(ip);
    const range = addr.range(); // BUG 3 (09B): "::7f00:1" and "64:ff9b:1::a9fe:a9fe" -> range="unicast" -> returns false!
    return PRIVATE_IP_RANGES.includes(range);
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Aynı Sunucu Üzerinde `pathname` Kısıtlamasını Atlama (`/public-avatars/` -> `/private-kyc-docs/passport-scan.png`) (Monte Edilen HackerOne `#4152265` Senaryo A)
Uygulama `remotePatterns` ile yalnızca `/public-avatars/**` dizinine izin verirken, bu dizindeki bir `302` yönlendirmesi `fetchExternalImage()` fonksiyonunu `/private-kyc-docs/passport-scan.png` adresine taşır ve özel belgeyi `200 OK` olarak sızdırır.

### Senaryo B — İzinli Avatar/Depolama Servisi Üzerinden İzin Listesi Dışındaki Sunuculara SSRF Sıçraması (Monte Edilen HackerOne `#4152265` Yorum #1 & Senaryo B)
Gravatar (`?d=https://...`) veya çok kiracılı S3/Supabase/R2 kovası üzerinden verilen `301`/`302` yanıtı ile `remotePatterns` izin listesi tamamen atlanarak izin verilmeyen dış/iç sunuculardan görüntü çekilir.

### Senaryo C — Zincirleme `09A -> 09B` İle Standart Linux/Docker Çekirdeğinde Doğrudan `127.0.0.1` Loopback Soketine Bağlanma ve SSRF (Monte Edilen HackerOne `#4152265` Yorum #1 & Senaryo C)
İzinli ilk hop `Location: http://[::ffff:127.0.0.1%25br-1a49f5828144]:45829/admin-badge.png` (veya `::7f00:1` / `64:ff9b:1::a9fe:a9fe`) döndürdüğünde `isPrivateIp()` fail-open (`return false`) yapar ve Node.js `http.get` doğrudan `127.0.0.1` loopback soketine bağlanarak iç servis yanıtını sızdırır!

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect fetchExternalImage and isPrivateIp in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/image-optimizer.js | sed -n '586,615p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/lib/find-root.js | sed -n '100,145p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (09A + 09B + Linux Loopback Socket Proof)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-09-nextjs-image-optimizer-redirect-and-nat64-ssrf.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-NEXT-09": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152265 (with 2 follow-up comments mounted)",
      "same_host_pathname_bypass_status": 200,
      "cross_host_allowlist_bypass_status": 200,
      "scoped_loopback_input": "::ffff:127.0.0.1%br-1a49f5828144",
      "ipaddr_isValid": false,
      "nextjs_isPrivateIp_returned": false,
      "loopback_server_hit": true,
      "remote_address_seen_by_server": "::ffff:127.0.0.1",
      "rfc4291_ipv4_compatible_isPrivateIp": false,
      "rfc8215_local_nat64_isPrivateIp": false
    },
    "GREEN": {
      "redirect_hop_rechecks_hasMatch_remotePatterns": true,
      "invalid_or_hyphenated_zone_ip_fails_closed": true,
      "rfc4291_and_rfc8215_blocked": true,
      "loopback_server_hit": false
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/next/src/server/image-optimizer.ts
+++ b/packages/next/src/server/image-optimizer.ts
@@ -714,6 +714,9 @@ export async function fetchExternalImage(
       const redirectUrl = new URL(location, href).href
       const parsedRedirectUrl = new URL(redirectUrl)
+      if (!hasMatch(domains, remotePatterns, parsedRedirectUrl)) {
+        throw new ImageError(400, '"url" parameter redirect is not allowed')
+      }
       await validateUrl(parsedRedirectUrl)
--- a/packages/next/src/server/lib/validate-url.ts
+++ b/packages/next/src/server/lib/validate-url.ts
@@ -18,7 +18,10 @@ export function isPrivateIp(ip: string): boolean {
+  const cleanIp = ip.split('%')[0]
+  if (!ipaddr.isValid(cleanIp)) {
+    return true
+  }
+  if (cleanIp.toLowerCase().startsWith('64:ff9b:1:')) {
+    return true
+  }
```

---

## 5. Monte Edilen HackerOne Takip Yorumları (2 Yorum Doğrudan Entegre Edildi)

### Monte Edilen HackerOne `#4152265` Takip Yorumu #1 (`RE-EVALUATION-COMMENT-4152265.md`)

1. **`remotePatterns` Atlaması İçin Ele Geçirilmiş Sunucuya Gerek Yoktur (`FINDING-09A`):**
   - **Vektör A (Aynı Sunucu Üzerinde `pathname` Kısıtlamasını Atlama):** Aynı alan adında `/public-avatars/**` kısıtlamasını aşarak `/private-kyc-docs/passport-scan.png` dosyasını okur.
   - **Vektör B (Popüler İzinli Görsel Servislerindeki Yerleşik Yönlendiriciler):** Gravatar (`?d=https%3A%2F%2F...`), Cloudinary ve çok kiracılı S3 / R2 / Supabase Storage / Vercel Blob kovaları herhangi bir sunucu ele geçirilmesine gerek olmadan doğal olarak `301`/`302` yönlendirmesi üretir.
2. **NAT64 Gerekmeden `isPrivateIp()` Fail-Open (`if (!ipaddr.isValid(ip)) return false`) İle Doğrudan Linux `127.0.0.1` Soketine Bağlanma:**
   - `next/dist/compiled/ipaddr.js` içindeki IPv6 `zoneIndex` regex'i (`const o = "%[0-9a-z]{1,}"`) tire (`-`), alt çizgi (`_`) ve nokta (`.`) karakterlerini reddeder.
   - Standart Linux / Docker / Kubernetes ortamlarındaki `br-1a49f5828144`, `docker_gwbridge`, `cni-podman0`, `flannel.1` arayüzlerinde `dns.promises.lookup("::ffff:127.0.0.1%br-1a49f5828144", { all: true })` çekirdek seviyesinde başarılı olur, `ipaddr.isValid()` `false` döner, `isPrivateIp()` **fail-open (`return false`)** yapar ve Node.js `http.get` doğrudan `127.0.0.1` TCP soketine bağlanır!
3. **WHATWG `URL` vs. `ipaddr.js` RFC 4291 (`::7f00:1` & `0:0:0:0:0:0:127.0.0.1`) Ayrıştırıcı Farkı:**
   - `new URL('http://[::127.0.0.1]')` adresi `::7f00:1` olarak normalize edilir ve `ipaddr.parse('::7f00:1').range()` `'unicast'` döndürdüğü için `isPrivateIp()` `false` verir!

### Monte Edilen HackerOne `#4152265` Takip Yorumu #2 (`ADDENDUM-SCENARIOS-4152265.md`)

- **Senaryo A (Aynı Sunucu `pathname` Atlaması):** `/public-avatars/redirect-to-private` -> `/private-kyc-docs/passport-scan.png` (`200 OK`, `68 byte`) doğrulandı.
- **Senaryo B (Farklı Sunucu İzin Listesi Atlaması):** `allowed-cdn.example` -> `unapproved-internal.example` (`200 OK`) doğrulandı.
- **Senaryo C (`09A -> 09B` Zinciri İle Doğrudan `127.0.0.1` Loopback Soketine Bağlanma):** Canlı `next@16.4.3` üzerinde `loopback_server_hit: true`, `remote_address_seen_by_server: "::ffff:127.0.0.1"`, `status: 200`, `bytes_exfiltrated: 68` kanıtlandı.
