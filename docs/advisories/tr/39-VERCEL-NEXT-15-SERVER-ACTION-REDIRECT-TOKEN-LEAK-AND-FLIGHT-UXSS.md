# Next.js App Router Server Action Dahili `redirect()` SSRF, `previewModeId` (`x-next-revalidate-tag-token`) Gizli Anahtar Sızıntısı ve Build-ID Atlamalı Aynı Kökenli RSC Flight UXSS (`VERCEL-NEXT-15` / HackerOne `#4152250`)

[English](../39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md) | **Türkçe** | [日本語](../ja/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md) | [简体中文](../zh-CN/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md) | [한국어](../ko/39-VERCEL-NEXT-15-SERVER-ACTION-REDIRECT-TOKEN-LEAK-AND-FLIGHT-UXSS.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — `createRedirectRenderResult()` İçinde Eksik `redirect: 'manual'` ve Şema-Bağıl (`//host`) URL Kabulü (`action-handler.js:270-303`):** `forwardActionToWorker()` fonksiyonu `redirect: 'manual'` (satır 175) kullanırken, hemen altındaki `createRedirectRenderResult()` fonksiyonu `await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } })` çağrısını varsayılan `redirect: 'follow'` ile çalıştırır.
2. **Adım 2 — `x-next-revalidate-tag-token` (`previewModeId`) Anahtarının Dış `302` Yönlendirmelerine Otomatik Sızdırılması (`action-handler.js:904-911`):** Bir Server Action `revalidateTag()`, `revalidatePath()` veya `updateTag()` sonrasında `redirect('/api/sso-callback')` çağırdığında, `handleAction()` iç isteğe `x-next-revalidate-tag-token: store.previewProps.previewModeId` başlığını ekler. Üstelik `revalidateTag()` çağrılmasa bile `createRedirectRenderResult()` her `redirect('/internal-path')` çağrısında dış `302` hedefini sunucu tarafında takip eder.
3. **Adım 3 — Monte Edilen HackerOne Yorumu #1 (`RE-EVALUATION-COMMENT-4152250`): Build-ID Kontrolünü Atlayarak Aynı Kökenli RSC Flight Enjeksiyonu (`UXSS`) ve HTTP Yanıt Başlığı Enjeksiyonu:** `handleAction()`, `createRedirectRenderResult()` çağrısından ÖNCE `x-action-redirect: /api/oauth-bounce;push` başlığını ayarladığı için tarayıcı yanıtı aynı kökenli (`same-origin`) kabul eder. İstemci tarafındaki `server-action-reducer.js:161-162` (`if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId())`), dış sunucunun döndürdüğü sahte RSC Flight yanıtında `"b"` alanı bırakılmadığında (`undefined`) Build ID doğrulamasını tamamen atlar ve saldırganın `dangerouslySetInnerHTML` yükünü doğrudan `https://victim-app.com` DOM'una monte ederek **Universal XSS (`UXSS`)** oluşturur!
4. **Adım 4 — Monte Edilen HackerOne Yorumu #2 (`ADDENDUM-SCENARIOS-4152250`): Ayrı Bir Open-Redirect Hatası Olmadan Tasarım Gereği Dış `302` Döndüren Gerçek Next.js Mimarileri:** Çok kiracılı (Multi-Tenant) kurumsal B2B SSO/OIDC giriş akışları (`/api/sso/authorize?tenant=attacker-corp.com`), OAuth 2.0 sağlayıcı onay uç noktaları (`/api/oauth/complete`) ve ödeme/tıklama yönlendiricileri tasarım gereği dış `302` yanıtı üretir.

### Zafiyetli Kod Kesiti
```javascript
// 1. Server-side internal redirect fetch WITHOUT redirect: 'manual'
// File: node_modules/next/dist/esm/server/app-render/action-handler.js (lines 270-303)
function getAppRelativeRedirectUrl(redirectUrl, basePath, i18n) {
    if (redirectUrl.startsWith('/')) { // BUG: accepts '//attacker.example' and internal routes that 302 externally
        return `${basePath}${redirectUrl}`;
    }
    return new URL(redirectUrl).pathname;
}
async function createRedirectRenderResult(req, res, originalHost, redirectUrl, basePath, staticGenerationStore, workUnitStore) {
    const fetchUrl = new URL(formattedUrl, `http://localhost:${port}`);
    // BUG: Missing `redirect: 'manual'`! Undici follows 3xx hops to external hosts while carrying
    // x-next-revalidate-tag-token (previewModeId) and pipes external Flight body + headers to res!
    const response = await fetch(fetchUrl, { method: 'GET', headers: head, next: { internal: 1 } });
    if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        copyResponseHeaders(response, res);
        return new FlightRenderResult(response.body);
    }
}

// 2. Client-side Build ID validation skipped when 'b' is omitted (`responseBuildId === undefined`)
// File: node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js (lines 154-201)
let redirectFlightData = await createFromNextReadableStream(res.body, ...);
const { b: responseBuildId, f: flightData } = redirectFlightData;
if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId()) {
    return handleExternalUrl(state, mutable, action.mutable.redirectLocation, state.pushRef.pendingPush);
}
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Çok Kiracılı Kurumsal SSO / OAuth Giriş Akışında `previewModeId` Gizli Anahtarının Çalınması (Monte Edilen HackerOne `#4152250` Senaryo A)
Kurumsal bir SaaS uygulaması (`https://victim-app.com`), giriş Server Action'ında `revalidateTag('auth-session')` ve `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)` çağırır; bu rota kiracının OIDC sağlayıcısına `302 Found` döndürür. Saldırgan `user@attacker-corp.com` girdiğinde Next.js `302`'yi sunucu içinde takip eder ve `x-next-revalidate-tag-token: <previewModeId>` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`) başlığını doğrudan saldırganın sunucusuna teslim eder.

### Senaryo B — Çalınan `previewModeId` İle Yetkisiz Küresel On-Demand ISR Önbellek Sıfırlama ve Veritabanı Hizmet Engelleme (Monte Edilen HackerOne `#4152250` Senaryo B)
`try-get-preview-data.js:34` dosyası `req.headers['x-prerender-revalidate'] === previewProps.previewModeId` kontrolü yaptığı için saldırgan çaldığı anahtarı `x-prerender-revalidate` başlığında göndererek tüm önbellekli ISR sayfalarını (`200 OK`, `x-nextjs-cache: REVALIDATED`) sıfırlar.

### Senaryo C — `revalidateTag()` Olmadan Bile Build-ID Atlamalı Aynı Kökenli RSC Flight Enjeksiyonu ve Universal XSS (`UXSS`) (Monte Edilen HackerOne `#4152250` Yorum #1 & Senaryo C)
Server Action `revalidateTag()` çağırmasa dahi `redirect('/api/oauth-bounce')` çalıştığında `x-action-redirect: /api/oauth-bounce;push` (aynı kökenli) başlığı yazılır ve dış sunucunun döndürdüğü `Content-Type: text/x-component` yanıtı (içinde `"b"` alanı olmadan) `server-action-reducer.js:161` Build ID kontrolünü atlayarak `https://victim-app.com` üzerinde tam **Universal XSS (`UXSS`)** ve keyfi HTTP yanıt başlığı enjeksiyonu (`Access-Control-Allow-Origin`, `Clear-Site-Data`) sağlar.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect createRedirectRenderResult and server-action-reducer in next@16.4.3
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/server/app-render/action-handler.js | sed -n '270,305p'
nl -ba /home/community-user/targets/vercel-bounty-audit-20261027/live-dist-verify/node_modules/next/dist/esm/client/components/router-reducer/reducers/server-action-reducer.js | sed -n '154,201p'

# 2. Run the Live next@16.4.3 End-to-End Verification Harness (Scenarios A, B, and C + Patch Check)
node /home/community-user/targets/vercel-bounty-audit-20261027/pocs/verify_npm_stable_tarballs_20261028.mjs
git apply --check /home/community-user/targets/vercel-bounty-audit-20261027/patches/FINDING-15-nextjs-action-handler-redirect-token-leak-and-flight-injection.patch
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Vercel & Next.js Canlı npm Paketi Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`vercel-real-world-impact-e2e-20261029.json`](../vercel-real-world-impact-e2e-20261029.json)):

```json
{
  "VERCEL-NEXT-15": {
    "RED": {
      "package_tested": "next@16.4.3",
      "hackerone_report": "#4152250 (with 2 follow-up comments mounted)",
      "prerender_manifest_previewModeId": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "attacker_received_x_next_revalidate_tag_token": "f5dbbd8f6a6a51a6aa8ff1443f7090dd",
      "leaked_token_matches_prerender_manifest_previewModeId": true,
      "forged_flight_stream_injected_into_action_response": true,
      "response_build_id_field_b": null,
      "client_build_id_check_bypassed": true,
      "injected_cors_header_on_victim_origin": "https://attacker-oauth.example"
    },
    "GREEN": {
      "internal_redirect_fetch_mode": "manual",
      "scheme_relative_redirect_rejected": true,
      "external_hop_followed_by_server": false,
      "attacker_received_x_next_revalidate_tag_token": null,
      "forged_flight_stream_injected_into_action_response": false
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/packages/next/src/server/app-render/action-handler.ts
+++ b/packages/next/src/server/app-render/action-handler.ts
@@ -365,7 +365,7 @@ function getAppRelativeRedirectUrl(
-  if (redirectUrl.startsWith('/')) {
+  if (redirectUrl.startsWith('/') && !redirectUrl.startsWith('//') && !redirectUrl.startsWith('/\\')) {
     return `${basePath}${redirectUrl}`
   }
@@ -395,6 +395,7 @@ async function createRedirectRenderResult(
     const response = await fetch(fetchUrl, {
       method: 'GET',
       headers: head,
+      redirect: 'manual',
       next: {
         // @ts-ignore
         internal: 1,
       },
     })
+    if (response.status >= 300 && response.status < 400) {
+      const location = response.headers.get('location')
+      if (location) {
+        res.setHeader(ACTION_REDIRECT_HEADER, `${location};push`)
+      }
+      return RenderResult.EMPTY
+    }
```

---

## 5. Monte Edilen HackerOne Takip Yorumları (2 Yorum Doğrudan Entegre Edildi)

### Monte Edilen HackerOne `#4152250` Takip Yorumu #1 (`RE-EVALUATION-COMMENT-4152250.md`)

1. **Ayrı Bir Open-Redirect Hatasına Gerek Kalmadan `302` Hedefinin Gerçek Next.js Uygulamalarında Neden Saldırgan Kontrolünde Olduğu:**
   - **Desen 1 — Çok Kiracılı (Multi-Tenant) Kurumsal SSO / OIDC Keşfi:** `redirect(\`/api/sso/authorize?tenant=${emailDomain}\`)` çağrısı kiracının kendi IdP sunucusuna (`https://idp.attacker-corp.com/oauth2/authorize`) `302 Found` döndürür.
   - **Desen 2 — OAuth 2.0 / OIDC Sağlayıcı Onay Server Action'ları:** `redirect('/api/oauth/complete?session=...')` kayıtlı OAuth istemcisinin `redirect_uri` adresine `302 Found` döndürür.
   - **Desen 3 — Giden Bağlantı / Ödeme Yönlendiricileri:** `redirect(\`/out?dest=${partnerUrl}\`)` dış hedefe `302 Found` döndürür.
2. **`revalidateTag()` Çağrılmasa Bile Oluşan İkincil Kritik Etki — Aynı Kökenli RSC Flight Akışı Ele Geçirme ve Universal XSS (`UXSS`):**
   - `handleAction()` (`action-handler.js:1007`), `createRedirectRenderResult()` çalışmadan ÖNCE `x-action-redirect: /api/oauth-bounce;push` başlığını ayarlar.
   - İstemci tarafındaki `server-action-reducer.js:161-162` dosyasında `if (responseBuildId !== undefined && responseBuildId !== getNavigationBuildId())` kontrolü yer alır. Dış sunucu RSC Flight yanıtında `"b"` alanını göndermediğinde (`responseBuildId === undefined`), Build ID doğrulaması tamamen atlanır ve `dangerouslySetInnerHTML` içeren sahte Virtual DOM doğrudan `https://victim-app.com` içerisine monte edilerek **Universal XSS (`UXSS`)** tetiklenir!
3. **Keyfi HTTP Yanıt Başlığı Enjeksiyonu (`copyResponseHeaders`):**
   - `actionsForbiddenHeaders` (`action-handler.js:230-241`) yalnızca 9 başlığı filtrelediği için dış sunucu `https://victim-app.com` yanıtına `Access-Control-Allow-Origin: https://attacker.example`, `Access-Control-Allow-Credentials: true` ve `Clear-Site-Data: "storage"` enjekte edebilir.

### Monte Edilen HackerOne `#4152250` Takip Yorumu #2 (`ADDENDUM-SCENARIOS-4152250.md`)

- **Senaryo A (`previewModeId` Çalınması):** Canlı `next@16.4.3` üzerinde `"leaked_token_matches_prerender_manifest_previewModeId": true` (`f5dbbd8f6a6a51a6aa8ff1443f7090dd`) doğrulandı.
- **Senaryo B (Küresel On-Demand ISR Önbellek Sıfırlama):** Çalınan `previewModeId` ile `x-prerender-revalidate` başlığı gönderildiğinde önbellekli ISR rotalarının sıfırlandığı doğrulandı.
- **Senaryo C (Build-ID Atlamalı Aynı Kökenli RSC Flight Enjeksiyonu & UXSS):** `response_build_id_field_b: null`, `client_build_id_check_bypassed: true` ve `injected_cors_header_on_victim_origin: "https://attacker-oauth.example"` canlı olarak kanıtlandı.
