// Gelişmiş araç akışları paneli: araç kartlarının ve yalnız API'den erişilebilen uç noktaların
// arayüzü. Her akış, sunucunun beklediği anahtar kümesini birebir üreten bir şemadır; tüm
// dinamik değerler textContent / DOM API ile yazılır. Tarama başlatan akışlar açık onay
// kutuları olmadan gönderilmez (sunucu da aynı onayları ayrıca doğrular).
(() => {
  "use strict";

  const EVIDENCE_SLUGS = Object.freeze({
    "sarif": { label: "SARIF 2.1.0", kind: "object" },
    "semgrep-native-json": { label: "Semgrep JSON", kind: "object" },
    "trufflehog-json": { label: "TruffleHog JSONL", kind: "jsonl" },
    "npm-audit-v2": { label: "npm audit v2 JSON", kind: "object" },
    "dependabot-alerts": { label: "Dependabot uyarıları JSON", kind: "objectOrArray" },
    "ssllabs-host": { label: "SSL Labs host JSON", kind: "object" },
    "openssl-x509": { label: "OpenSSL x509 metni", kind: "text" },
    "playwright-json": { label: "Playwright JSON", kind: "object" },
    "k6-summary-json": { label: "k6 summary JSON", kind: "object" },
    "k6-machine-summary-v1": { label: "k6 makine özeti v1", kind: "object" },
    "schemathesis-junit": { label: "Schemathesis JUnit XML", kind: "text" },
    "siem-ecs-ndjson": { label: "SIEM ECS NDJSON", kind: "text" },
  });

  const consent = (name, label) => ({ name, label, type: "checkbox", required: true });
  const SANDBOX_TOOL_OPTIONS = [["all", "k6, Schemathesis, Playwright ve çalışma zamanı kanıtı"], ["both", "k6 ve Schemathesis"], ["k6", "Yalnız k6"],
    ["schemathesis", "Yalnız Schemathesis"], ["playwright", "Yalnız Playwright (tarayıcı)"],
    ["runtime_proof", "Yalnız çalışma zamanı kanıtı (loopback)"]];
  const sandboxTools = choice => ({ k6: ["k6"], schemathesis: ["schemathesis"], playwright: ["playwright"],
    runtime_proof: ["runtime_proof"], both: ["k6", "schemathesis"] })[choice] || ["k6", "schemathesis", "playwright", "runtime_proof"];
  const target = { name: "target_id", label: "Hedef", type: "target", required: true };
  const engagement = { name: "engagement_id", label: "Etkin denetim (yetki ve kapsam kayıtlı)", type: "engagement", required: true };
  const proofEngagement = { name: "engagement_id", label: "Denetim (etkin, yetkili, maskeli kanıt onaylı)", type: "engagement", eligible: "proof", required: true };

  const FLOWS = Object.freeze([
    { id: "zap-spider-scope", group: "OWASP ZAP", label: "ZAP seçili yol spider kapsamı", method: "POST", route: "/api/tool-runs/zap-target-spider-scope",
      fields: [target, engagement, { name: "selected_paths", label: "Seçili yollar (her satıra bir yol, / ile başlar)", type: "lines", required: true },
        consent("confirm_authorized", "Bu hedef için yazılı yetkim var"), consent("confirm_selected_scope", "Spider yalnız seçili yollarla sınırlı kalsın")] },
    { id: "zap-site-active", group: "OWASP ZAP", label: "ZAP site geneli aktif tarama", method: "POST", route: "/api/tool-runs/zap-site-active",
      fields: [target, engagement, consent("confirm_authorized", "Bu hedef için yazılı yetkim var"), consent("confirm_crawl", "Spider (tarama) onayı"), consent("confirm_active", "Aktif saldırı kuralları onayı")] },
    { id: "zap-af-preview", group: "OWASP ZAP", label: "ZAP Automation Framework plan önizlemesi", method: "POST", route: "/api/tool-plans/zap-af/preview",
      fields: [target, engagement, { name: "selected_path", label: "Seçili yol", type: "text", value: "/", required: true },
        { name: "mode", label: "Kip", type: "select", options: [["ACTIVE_ROOT", "Aktif (kök)"], ["PASSIVE_ONLY", "Yalnız pasif"]] },
        consent("confirm_authorized", "Bu hedef için yazılı yetkim var"), consent("confirm_crawl", "Spider onayı"),
        { name: "confirm_active", label: "Aktif kurallar onayı (aktif kipte zorunlu)", type: "checkbox" }],
      build(v) {
        const base = { target_id: v.target_id, engagement_id: v.engagement_id, selected_path: v.selected_path,
          confirm_authorized: v.confirm_authorized, confirm_crawl: v.confirm_crawl, mode: v.mode };
        if (v.mode === "PASSIVE_ONLY") return base;
        if (v.confirm_active !== true) throw new Error("Aktif kip için aktif kurallar onayı gerekli.");
        return { ...base, confirm_active: true };
      } },
    { id: "burp-handoff", group: "Burp Suite", label: "Burp sitemap → manuel devir manifestosu", method: "POST", route: "/api/tool-reports/burp-sitemap/handoff-manifest",
      renderer: "renderBurpHandoffManifestHtml",
      fields: [{ name: "sitemap_xml", label: "Burp sitemap XML", type: "textarea", file: ".xml", required: true },
        { name: "allowed_host", label: "İzin verilen ana makine adı", type: "text", required: true }] },
    { id: "burp-logger-csv", group: "Burp Suite", label: "Burp Logger++ CSV özeti", method: "POST", route: "/api/tool-reports/burp-logger-csv/summary",
      fields: [{ name: "report", label: "Logger++ CSV", type: "textarea", file: ".csv", required: true },
        { name: "status_column", label: "Durum kodu sütunu", type: "text", value: "Status", required: true },
        { name: "mime_column", label: "MIME sütunu (isteğe bağlı)", type: "text", value: "MimeType" }],
      build: v => ({ report: v.report, columns: { status: v.status_column, mime: v.mime_column || null } }) },
    { id: "semgrep-rulepack", group: "Semgrep / Opengrep", label: "Güvenilir Semgrep kural paketi envanteri", method: "POST", route: "/api/tool-reports/semgrep/rulepack-inventory",
      fields: [{ name: "target_extensions", label: "Hedef uzantılar (isteğe bağlı, her satıra bir uzantı: .py)", type: "lines" }],
      build: v => (v.target_extensions.length ? { target_extensions: v.target_extensions } : {}) },
    { id: "semgrep-tls-filter", group: "Semgrep / Opengrep", label: "Semgrep TLS doğrulama bulgu süzgeci", method: "POST", route: "/api/tool-reports/semgrep/tls-verify-filter",
      fields: [{ name: "project_path", label: "Proje klasörü (ev dizini altında)", type: "text", required: true },
        { name: "report", label: "Semgrep JSON raporu", type: "json", file: ".json", required: true }] },
    { id: "playwright-fixture", group: "Playwright", label: "Sabit yerel tarayıcı fikstürü", method: "POST", route: "/api/tool-runs/playwright-local-fixture",
      fields: [consent("confirm_local", "Yalnız sabit yerel fikstürün tarayıcıda çalıştırılmasını onaylıyorum")] },
    { id: "k6-loopback", group: "k6", label: "Onaylı loopback k6 duman testi", method: "POST", route: "/api/tool-runs/k6-loopback-smoke",
      fields: [{ name: "target_url", label: "Loopback hedef URL (http://127.0.0.1:PORT)", type: "text", required: true },
        { name: "path", label: "Yol", type: "text", value: "/", required: true },
        consent("confirm_local", "Yalnız onaylı loopback hedefe sınırlı yük testi")] },
    { id: "sandbox-targets-list", group: "Yalıtılmış test", label: "Test hedefleri, kapsam seçenekleri ve yük profilleri", method: "GET", route: "/api/sandbox-targets", fields: [] },
    { id: "sandbox-scope", group: "Yalıtılmış test", label: "Kapsam seçeneğini aç/kapat", method: "POST", route: "/api/sandbox-targets",
      fields: [{ name: "scope", label: "Kapsam", type: "select", options: [["local", "Yerel portlar (127.0.0.1)"], ["critical", "Kritik yerel servisler (Sniper, LLM, SSH tüneli, ssh, VNC)"], ["remote_verified", "Sahipliği doğrulanmış uzak hedefler"]] },
        { name: "enabled", label: "Durum", type: "select", options: [["on", "Açık"], ["off", "Kapalı"]] },
        consent("confirm", "Onaylıyorum")],
      build: v => ({ confirm: true, action: "scope", scope: v.scope, enabled: v.enabled === "on" }) },
    { id: "sandbox-target-add", group: "Yalıtılmış test", label: "Yerel test hedefi ekle (127.0.0.1:port)", method: "POST", route: "/api/sandbox-targets",
      fields: [{ name: "port", label: "Port", type: "text", required: true },
        { name: "tools", label: "Araçlar", type: "select", options: SANDBOX_TOOL_OPTIONS },
        { name: "label", label: "Etiket (isteğe bağlı)", type: "text" },
        consent("confirm", "Onaylıyorum")],
      build(v) {
        const port = Number(v.port);
        if (!Number.isInteger(port)) throw new Error("Port bir tam sayı olmalı.");
        const tools = sandboxTools(v.tools);
        return { confirm: true, action: "add-local", port, tools, label: v.label || "" };
      } },
    { id: "sandbox-target-remove", group: "Yalıtılmış test", label: "Test hedefini kaldır", method: "POST", route: "/api/sandbox-targets",
      fields: [{ name: "id", label: "Hedef kimliği (ör. local:3000 veya remote:alan.com:443)", type: "text", required: true },
        consent("confirm", "Onaylıyorum")],
      build: v => ({ confirm: true, action: "remove", id: v.id }) },
    { id: "sandbox-verify-start", group: "Yalıtılmış test", label: "Uzak hedef: sahiplik doğrulaması başlat", method: "POST", route: "/api/sandbox-targets",
      fields: [{ name: "host", label: "Alan adı (IP kabul edilmez)", type: "text", required: true },
        { name: "port", label: "Port", type: "text", value: "443", required: true },
        { name: "scheme", label: "Şema", type: "select", options: [["https", "https"], ["http", "http"]] },
        { name: "tools", label: "Araçlar", type: "select", options: SANDBOX_TOOL_OPTIONS },
        consent("confirm", "Onaylıyorum")],
      build(v) {
        const port = Number(v.port);
        if (!Number.isInteger(port)) throw new Error("Port bir tam sayı olmalı.");
        const tools = sandboxTools(v.tools);
        return { confirm: true, action: "verify-start", host: v.host, port, scheme: v.scheme, tools };
      } },
    { id: "sandbox-verify", group: "Yalıtılmış test", label: "Uzak hedef: Doğrula (.well-known dosyası ya da TXT kaydı)", method: "POST", route: "/api/sandbox-targets",
      fields: [{ name: "id", label: "Doğrulama kimliği", type: "text", required: true }, consent("confirm", "Doğrula")],
      build: v => ({ confirm: true, action: "verify", id: v.id }) },
    { id: "sandbox-preset-set", group: "Yalıtılmış test", label: "Özel yük profili tanımla", method: "POST", route: "/api/sandbox-targets",
      fields: [{ name: "name", label: "Profil adı (küçük harf, ör. ozel)", type: "text", value: "ozel", required: true },
        { name: "vus", label: "VU (1–200)", type: "text", value: "5", required: true },
        { name: "duration_s", label: "Süre saniye (1–600)", type: "text", value: "30", required: true },
        consent("confirm", "Onaylıyorum")],
      build(v) {
        const vus = Number(v.vus), duration_s = Number(v.duration_s);
        if (!Number.isInteger(vus) || !Number.isInteger(duration_s)) throw new Error("VU ve süre tam sayı olmalı.");
        return { confirm: true, action: "preset-set", name: v.name, vus, duration_s };
      } },
    { id: "k6-sandbox", group: "Yalıtılmış test", label: "k6 yük testi (bwrap yalıtımı, tek hedef)", method: "POST", route: "/api/tool-runs/k6-sandbox",
      fields: [{ name: "target", label: "Hedef (listedeki: http://127.0.0.1:PORT ya da https://alan:PORT)", type: "text", required: true },
        { name: "path", label: "Yol", type: "text", value: "/", required: true },
        { name: "method", label: "Yöntem", type: "select", options: [["GET", "GET"], ["HEAD", "HEAD"]] },
        { name: "preset", label: "Yük profili", type: "select", options: [["", "Varsayılan (kritik serviste Hafif)"], ["hafif", "Hafif (1 VU, 10 sn)"], ["orta", "Orta (10 VU, 1 dk)"], ["yogun", "Yoğun (50 VU, 5 dk)"], ["ozel", "Özel"]] },
        consent("confirm", "Onaylıyorum")],
      build(v) {
        const out = { confirm: true, target: v.target, path: v.path, method: v.method };
        if (v.preset) out.preset = v.preset;
        return out;
      } },
    { id: "schemathesis-sandbox", group: "Yalıtılmış test", label: "Schemathesis API testi (bwrap yalıtımı, tek hedef)", method: "POST", route: "/api/tool-runs/schemathesis-sandbox",
      fields: [{ name: "target", label: "Hedef (listedeki: http://127.0.0.1:PORT ya da https://alan:PORT)", type: "text", required: true },
        { name: "schema", label: "OpenAPI 3.x / Swagger 2.0 şeması (JSON; yalnız şema içi $ref)", type: "json", file: ".json", required: true },
        { name: "max_examples", label: "Örnek sayısı", type: "text", value: "10" },
        { name: "max_time_s", label: "Süre sınırı saniye", type: "text", value: "60" },
        consent("confirm", "Onaylıyorum")],
      build(v) {
        const out = { confirm: true, target: v.target, schema: v.schema,
          max_examples: Number(v.max_examples), max_time_s: Number(v.max_time_s) };
        if (!Number.isInteger(out.max_examples) || !Number.isInteger(out.max_time_s)) throw new Error("Örnek sayısı ve süre tam sayı olmalı.");
        return out;
      } },
    { id: "k6-authorized", group: "Yetkili hedef", label: "k6 — bu çalıştırma için yetkili hedef", method: "POST", route: "/api/tool-runs/k6-authorized",
      fields: [{ name: "target", label: "Tam hedef kökeni (http(s)://ana-makine[:port])", type: "text", required: true },
        { name: "path", label: "Yol", type: "text", value: "/", required: true },
        { name: "method", label: "Yöntem", type: "select", options: [["GET", "GET"], ["HEAD", "HEAD"]] },
        { name: "preset", label: "Sınırlı yük profili", type: "select", options: [["hafif", "Hafif (1 VU, 10 sn)"], ["orta", "Orta (10 VU, 1 dk)"], ["yogun", "Yoğun (50 VU, 5 dk)"], ["ozel", "Özel"]] },
        consent("confirm_authorized", "Bu hedefi test etmeye yetkili olduğumu bu çalıştırma için onaylıyorum")],
      build: v => ({ confirm_authorized: true, target: v.target, path: v.path, method: v.method, preset: v.preset }) },
    { id: "schemathesis-authorized", group: "Yetkili hedef", label: "Schemathesis — bu çalıştırma için yetkili hedef", method: "POST", route: "/api/tool-runs/schemathesis-authorized",
      fields: [{ name: "target", label: "Tam hedef kökeni (http(s)://ana-makine[:port])", type: "text", required: true },
        { name: "schema", label: "OpenAPI 3.x / Swagger 2.0 şeması (JSON; yalnız şema içi $ref)", type: "json", file: ".json", required: true },
        { name: "max_examples", label: "Örnek sayısı", type: "text", value: "10" },
        { name: "max_time_s", label: "Süre sınırı saniye", type: "text", value: "60" },
        consent("confirm_authorized", "Bu hedefi test etmeye yetkili olduğumu bu çalıştırma için onaylıyorum")],
      build(v) {
        const max_examples = Number(v.max_examples), max_time_s = Number(v.max_time_s);
        if (!Number.isInteger(max_examples) || !Number.isInteger(max_time_s)) throw new Error("Örnek sayısı ve süre tam sayı olmalı.");
        return { confirm_authorized: true, target: v.target, schema: v.schema, max_examples, max_time_s };
      } },
    { id: "sandbox-target-tools", group: "Yalıtılmış test", label: "Hedefin izinli araçlarını değiştir", method: "POST", route: "/api/sandbox-targets",
      fields: [{ name: "id", label: "Hedef kimliği (ör. local:3000)", type: "text", required: true },
        { name: "tools", label: "Araçlar", type: "select", options: SANDBOX_TOOL_OPTIONS },
        consent("confirm", "Onaylıyorum")],
      build: v => ({ confirm: true, action: "set-tools", id: v.id, tools: sandboxTools(v.tools) }) },
    { id: "playwright-sandbox", group: "Yalıtılmış test", label: "Playwright tarayıcı testi (bwrap yalıtımı, tek hedef)", method: "POST", route: "/api/tool-runs/playwright-sandbox",
      fields: [{ name: "target", label: "Hedef (listedeki: http://127.0.0.1:PORT ya da https://alan:PORT)", type: "text", required: true },
        { name: "paths", label: "Yollar (her satıra bir, / ile başlar; en çok 10)", type: "lines", value: "/", required: true },
        { name: "timeout_s", label: "Sayfa süre sınırı saniye (5–60)", type: "text", value: "20" },
        { name: "reflection_probe", label: "Yansıma sondası (zararsız işaretleyiciyle yansıyan XSS denetimi)", type: "select", options: [["on", "Açık"], ["off", "Kapalı"]] },
        { name: "screenshot", label: "İlk sayfanın ekran görüntüsü", type: "select", options: [["off", "Hayır"], ["on", "Evet"]] },
        { name: "ignore_https_errors", label: "TLS sertifika hataları", type: "select", options: [["off", "Doğrula"], ["on", "Yok say (kendinden imzalı yerel sertifika)"]] },
        consent("confirm", "Onaylıyorum")],
      build(v) {
        const timeout_s = Number(v.timeout_s || 20);
        if (!Number.isInteger(timeout_s)) throw new Error("Süre tam sayı olmalı.");
        return { confirm: true, target: v.target, paths: v.paths, timeout_s, reflection_probe: v.reflection_probe !== "off",
          screenshot: v.screenshot === "on", ignore_https_errors: v.ignore_https_errors === "on" };
      } },
    { id: "playwright-authorized", group: "Playwright", label: "Yetkili HTTP(S) hedefte tarayıcı güvenlik testi", method: "POST",
      route: "/api/tool-runs/playwright-authorized",
      fields: [{ name: "target", label: "HTTP(S) hedef kökeni (ör. https://uygulama.example)", type: "text", required: true },
        { name: "paths", label: "Yollar (her satıra bir, / ile başlar; en çok 10)", type: "lines", value: "/", required: true },
        { name: "timeout_s", label: "Sayfa süre sınırı saniye (5–60)", type: "text", value: "20" },
        { name: "reflection_probe", label: "Yansıma sondası", type: "select", options: [["off", "Kapalı"], ["on", "Açık"]] },
        { name: "screenshot", label: "İlk sayfanın ekran görüntüsü", type: "select", options: [["off", "Hayır"], ["on", "Evet"]] },
        { name: "ignore_https_errors", label: "TLS sertifika hataları", type: "select", options: [["off", "Doğrula"], ["on", "Yok say"]] },
        consent("confirm_authorized", "Bu hedefi bu koşuda test etmeye yetkili olduğumu onaylıyorum")],
      build(v) {
        const timeout_s = Number(v.timeout_s || 20);
        if (!Number.isInteger(timeout_s)) throw new Error("Süre tam sayı olmalı.");
        return { confirm_authorized: true, target: v.target, paths: v.paths, timeout_s,
          reflection_probe: v.reflection_probe === "on", screenshot: v.screenshot === "on",
          ignore_https_errors: v.ignore_https_errors === "on" };
      } },
    { id: "open-redirect-runtime-proof", group: "Yalıtılmış test", label: "Statik açık yönlendirme bulgusunu loopback üzerinde doğrula", method: "POST",
      route: "/api/project-audits/{audit_id}/findings/{finding_index}/runtime-proof/open-redirect",
      fields: [{ name: "audit_id", label: "Proje analizi kimliği", type: "text", required: true },
        { name: "finding_index", label: "Bulgu sırası (0 tabanlı)", type: "text", required: true },
        { name: "target", label: "Kayıtlı loopback hedef (http://127.0.0.1:PORT)", type: "text", required: true },
        { name: "path", label: "Yönlendirme yolu", type: "text", value: "/", required: true },
        { name: "parameter", label: "Yönlendirme parametresi", type: "text", value: "next", required: true },
        consent("confirm_local", "Tek loopback isteğini ve yönlendirmeyi izlemeden kanıt toplamayı onaylıyorum")],
      build(v) {
        const findingIndex = Number(v.finding_index);
        if (!Number.isInteger(findingIndex) || findingIndex < 0) throw new Error("Bulgu sırası negatif olmayan tam sayı olmalı.");
        return { target: v.target, path: v.path, parameter: v.parameter, confirm_local: true };
      } },
    { id: "reflected-html-runtime-proof", group: "Yalıtılmış test", label: "Statik HTML/XSS bulgusunun zararsız loopback yansıma kanıtı", method: "POST",
      route: "/api/project-audits/{audit_id}/findings/{finding_index}/runtime-proof/reflected-html",
      fields: [{ name: "audit_id", label: "Proje analizi kimliği", type: "text", required: true },
        { name: "finding_index", label: "Bulgu sırası (0 tabanlı)", type: "text", required: true },
        { name: "target", label: "Kayıtlı loopback hedef (http://127.0.0.1:PORT)", type: "text", required: true },
        { name: "path", label: "Yansıma yolu", type: "text", value: "/", required: true },
        { name: "parameter", label: "Yansıma parametresi", type: "text", value: "q", required: true },
        consent("confirm_local", "Betik çalıştırmadan tek zararsız HTML işaretleyicisiyle loopback kanıtını onaylıyorum")],
      build(v) {
        const findingIndex = Number(v.finding_index);
        if (!Number.isInteger(findingIndex) || findingIndex < 0) throw new Error("Bulgu sırası negatif olmayan tam sayı olmalı.");
        return { target: v.target, path: v.path, parameter: v.parameter, confirm_local: true };
      } },
    { id: "bounded-dast-runtime-proof", group: "Yalıtılmış test", label: "Sabit profilli sınırlı loopback DAST kanıtı", method: "POST",
      route: "/api/project-audits/{audit_id}/findings/{finding_index}/runtime-proof/dast",
      fields: [{ name: "audit_id", label: "Proje analizi kimliği", type: "text", required: true },
        { name: "finding_index", label: "Bulgu sırası (0 tabanlı)", type: "text", required: true },
        { name: "profile_id", label: "Sabit profil", type: "select", options: [
          ["open_redirect", "Açık yönlendirme (CWE-601)"],
          ["reflected_html", "Yansıyan HTML (CWE-79)"],
          ["cors_credentials", "Kimlik bilgili CORS yansıması (CWE-942)"],
          ["clickjacking_headers", "Clickjacking başlıkları (CWE-1021)"],
          ["ssrf_callback", "SSRF loopback callback (CWE-918)"],
          ["ssrf_callback_post", "SSRF loopback POST callback (CWE-918)"],
          ["ssrf_callback_redirect", "SSRF tek aynı-origin redirect callback (CWE-918)"],
          ["ssrf_callback_delayed", "SSRF gecikmeli loopback callback (CWE-918)"],
          ["ssrf_callback_dns", "SSRF yerel DNS/OOB korelasyonu (CWE-918)"]] },
        { name: "target", label: "Kayıtlı loopback hedef (http://127.0.0.1:PORT)", type: "text", required: true },
        { name: "path", label: "Tek istek yolu", type: "text", value: "/", required: true },
        { name: "parameter", label: "Parametre (CORS/clickjacking boş; yönlendirme: next; HTML: q; SSRF: url)", type: "text" },
        consent("confirm_local", "Seçilen sabit profille bir tetikleme ve gerekirse tek loopback callback isteğini onaylıyorum")],
      build(v) {
        const findingIndex = Number(v.finding_index);
        if (!Number.isInteger(findingIndex) || findingIndex < 0) throw new Error("Bulgu sırası negatif olmayan tam sayı olmalı.");
        const defaults = { open_redirect: "next", reflected_html: "q", cors_credentials: "", clickjacking_headers: "",
          ssrf_callback: "url", ssrf_callback_post: "url", ssrf_callback_redirect: "url",
          ssrf_callback_delayed: "url", ssrf_callback_dns: "url" };
        const parameter = v.parameter || defaults[v.profile_id] || "";
        return { profile_id: v.profile_id, target: v.target, path: v.path, parameter,
          confirm_local: true };
      } },
    { id: "asan-selftest", group: "Yalıtılmış test", label: "ASan araç zinciri öz sınaması (sabit fikstürler)", method: "POST",
      route: "/api/runtime-proofs/asan-selftest",
      fields: [consent("confirm_local", "Yalnız Sniper'ın sabit temiz ve use-after-free fikstürlerini yerelde derleyip çalıştırmayı onaylıyorum")],
      build: () => ({ confirm_local: true }) },
    { id: "asan-project-proof", group: "Yalıtılmış test", label: "Bellek güvenliği bulgusunu önceden derlenmiş ASan ikilisiyle doğrula", method: "POST",
      route: "/api/project-audits/{audit_id}/findings/{finding_index}/runtime-proof/asan-binary",
      fields: [{ name: "audit_id", label: "Proje analizi kimliği", type: "text", required: true },
        { name: "finding_index", label: "Bellek güvenliği bulgu sırası (0 tabanlı)", type: "text", required: true },
        { name: "binary_relpath", label: "Proje köküne göreli, önceden ASan ile derlenmiş ELF yolu", type: "text", required: true },
        consent("confirm_local", "İkiliyi argümansız, girdisiz ve ağsız bwrap yalıtımında çalıştırmayı onaylıyorum")],
      build(v) {
        const findingIndex = Number(v.finding_index);
        if (!Number.isInteger(findingIndex) || findingIndex < 0) throw new Error("Bulgu sırası negatif olmayan tam sayı olmalı.");
        return { binary_relpath: v.binary_relpath, confirm_local: true };
      } },
    { id: "asan-source-proof", group: "Yalıtılmış test", label: "Bellek güvenliği bulgusunu sabit çok dosyalı ASan profiliyle doğrula", method: "POST",
      route: "/api/project-audits/{audit_id}/findings/{finding_index}/runtime-proof/asan-source",
      fields: [{ name: "audit_id", label: "Proje analizi kimliği", type: "text", required: true },
        { name: "finding_index", label: "Bellek güvenliği bulgu sırası (0 tabanlı)", type: "text", required: true },
        { name: "source_relpath", label: "Bulgudaki C/C++ dosyasının proje köküne göreli yolu", type: "text", required: true },
        { name: "companion_relpaths", label: "Eşlikçi C/C++ kaynakları (isteğe bağlı, her satıra bir; en çok 3)", type: "lines" },
        consent("confirm_local", "Seçili kaynakları sabit bayraklarla derleyip ikiliyi argümansız, girdisiz ve ağsız yalıtımda çalıştırmayı onaylıyorum")],
      build(v) {
        const findingIndex = Number(v.finding_index);
        if (!Number.isInteger(findingIndex) || findingIndex < 0) throw new Error("Bulgu sırası negatif olmayan tam sayı olmalı.");
        const out = { source_relpath: v.source_relpath, confirm_local: true };
        if ((v.companion_relpaths || []).length) out.companion_relpaths = v.companion_relpaths;
        return out;
      } },
    { id: "asan-compile-database-proof", group: "Yalıtılmış test", label: "Bellek güvenliği bulgusunu compile_commands girdisiyle doğrula", method: "POST",
      route: "/api/project-audits/{audit_id}/findings/{finding_index}/runtime-proof/asan-compile-database",
      fields: [{ name: "audit_id", label: "Proje analizi kimliği", type: "text", required: true },
        { name: "finding_index", label: "Bellek güvenliği bulgu sırası (0 tabanlı)", type: "text", required: true },
        { name: "compile_commands_relpath", label: "Proje köküne göreli compile_commands.json yolu", type: "text", value: "compile_commands.json", required: true },
        { name: "entry_index", label: "Derleme girdisi sırası (0 tabanlı)", type: "text", value: "0", required: true },
        consent("confirm_local", "Seçili shell içermeyen girdiyi özel kaynak/header snapshot'ında ASan ile derleyip ikiliyi ağsız çalıştırmayı onaylıyorum")],
      build(v) {
        const findingIndex = Number(v.finding_index);
        const entryIndex = Number(v.entry_index);
        if (!Number.isInteger(findingIndex) || findingIndex < 0) throw new Error("Bulgu sırası negatif olmayan tam sayı olmalı.");
        if (!Number.isInteger(entryIndex) || entryIndex < 0) throw new Error("Derleme girdisi sırası negatif olmayan tam sayı olmalı.");
        return { compile_commands_relpath: v.compile_commands_relpath, entry_index: entryIndex, confirm_local: true };
      } },
    { id: "trivy-db-freshness", group: "Trivy", label: "Trivy çevrimdışı veritabanı tazeliği", method: "GET", route: "/api/tool-reports/trivy/db-freshness", fields: [] },
    { id: "testssl-boundary", group: "testssl.sh", label: "Kayıtlı testssl raporu sınır sözleşmesi", method: "POST", route: "/api/tool-reports/testssl/boundary-contract",
      fields: [{ name: "target", label: "Hedef (ana makine:port)", type: "text", required: true },
        { name: "report_json", label: "testssl JSON raporu", type: "textarea", file: ".json", required: true }] },
    { id: "nmap-service-fingerprint", group: "Nmap", label: "Nmap servis parmak izi (seçili portlar)", method: "POST", route: "/api/nmap/service-fingerprint",
      fields: [target, engagement, { name: "ports", label: "TCP portları (virgülle, en çok 8)", type: "ports", required: true },
        consent("confirm_authorized", "Bu hedef için yazılı yetkim var"), consent("confirm_service_probes", "Servis yoklama paketlerinin gönderilmesini onaylıyorum")] },
    { id: "nuclei-verification", group: "Nuclei", label: "Nuclei doğrulama kapsamı", method: "POST", route: "/api/tool-reports/nuclei/verification-coverage",
      renderer: "renderNucleiVerificationCoverageHtml",
      fields: [{ name: "raw_jsonl", label: "Nuclei JSONL çıktısı", type: "textarea", file: ".jsonl,.json", required: true },
        { name: "executed_template_ids", label: "Çalıştırılan şablon kimlikleri (isteğe bağlı, her satıra bir)", type: "lines" }],
      build: v => (v.executed_template_ids.length ? v : { raw_jsonl: v.raw_jsonl }) },
    { id: "secret-bundle", group: "Sır taraması", label: "Sınırlı sır tarama paketi doğrulaması", method: "POST", route: "/api/tool-runs/secret-bundle/validate",
      renderer: "renderSecretBundleManifestHtml",
      fields: [{ name: "files", label: "Dosyalar (1–16, her biri ≤ 64 KiB)", type: "files", required: true }] },
    { id: "dependency-plan", group: "Bağımlılıklar", label: "Salt-okunur bağımlılık düzeltme planı", method: "POST", route: "/api/tool-reports/dependency-remediation-plan",
      renderer: "renderDependencyRemediationPlanHtml",
      fields: [{ name: "npm_audit_raw", label: "npm audit v2 JSON (isteğe bağlı)", type: "textarea", file: ".json" },
        { name: "dependabot_raw", label: "Dependabot uyarıları JSON (isteğe bağlı)", type: "textarea", file: ".json" }],
      build(v) {
        const out = {};
        if (v.npm_audit_raw) out.npm_audit_raw = v.npm_audit_raw;
        if (v.dependabot_raw) out.dependabot_raw = v.dependabot_raw;
        if (!Object.keys(out).length) throw new Error("En az bir rapor gerekli.");
        return out;
      } },
    { id: "dependabot-sync", group: "Bağımlılıklar", label: "Dependabot çevrimdışı özet senkronu", method: "POST", route: "/api/tool-reports/dependabot/offline-sync",
      fields: [{ name: "owner", label: "Depo sahibi", type: "text", required: true }, { name: "repo", label: "Depo", type: "text", required: true },
        { name: "alerts", label: "Kayıtlı uyarılar JSON dizisi (isteğe bağlı)", type: "json", file: ".json" },
        consent("confirm_sync", "Yalnız bu depo için özet senkronunu onaylıyorum")],
      build(v) {
        const out = { owner: v.owner, repo: v.repo, confirm_sync: true };
        if (v.alerts !== undefined) {
          if (!Array.isArray(v.alerts)) throw new Error("Uyarılar bir JSON dizisi olmalı.");
          out.alerts = v.alerts;
        }
        return out;
      } },
    { id: "dns-email", group: "Web altyapısı", label: "DNS ve e-posta güvenliği (SPF/DMARC/CAA, devralma)", method: "POST", route: "/api/web-infra/dns-email-audit",
      fields: [{ name: "hostname", label: "Alan adı", type: "text", required: true },
        { name: "txt_records", label: "TXT kayıtları (isteğe bağlı, her satıra bir)", type: "lines" },
        { name: "caa_records", label: "CAA kayıtları (isteğe bağlı, her satıra bir)", type: "lines" },
        { name: "cname_target", label: "CNAME hedefi (isteğe bağlı)", type: "text" }],
      build(v) {
        const out = { hostname: v.hostname };
        if (v.txt_records.length) out.txt_records = v.txt_records;
        if (v.caa_records.length) out.caa_records = v.caa_records;
        if (v.cname_target) out.cname_target = v.cname_target;
        return out;
      } },
    { id: "discovery", group: "Web altyapısı", label: "Keşif ve kimlik uç noktaları (robots, OIDC, JWKS, GraphQL)", method: "POST", route: "/api/web-infra/discovery-audit",
      fields: [{ name: "target_url", label: "Hedef URL", type: "text", required: true },
        { name: "robots_txt", label: "robots.txt içeriği (isteğe bağlı)", type: "textarea" },
        { name: "openid_config", label: "OpenID yapılandırması JSON (isteğe bağlı)", type: "json" },
        { name: "jwks_doc", label: "JWKS JSON (isteğe bağlı)", type: "json" },
        { name: "graphql_response", label: "GraphQL yanıtı JSON (isteğe bağlı)", type: "json" },
        { name: "response_headers", label: "Yanıt başlıkları JSON nesnesi (isteğe bağlı)", type: "json" }],
      build(v) {
        const out = { target_url: v.target_url };
        if (v.robots_txt) out.robots_txt = v.robots_txt;
        for (const key of ["openid_config", "jwks_doc", "graphql_response", "response_headers"]) {
          if (v[key] === undefined) continue;
          if (!v[key] || typeof v[key] !== "object" || Array.isArray(v[key])) throw new Error(`${key} bir JSON nesnesi olmalı.`);
          out[key] = v[key];
        }
        return out;
      } },
    { id: "mobile-package", group: "Mobil", label: "Mobil paket arşivi (.apk/.aab/.ipa) analizi", method: "POST", route: "/api/mobile-security/audit-package",
      fields: [{ name: "package_path", label: "Paket dosyası yolu (ev dizini altında)", type: "text", required: true },
        consent("confirm_local", "Bu yerel paketin çevrimdışı ve salt-okunur incelenmesini onaylıyorum")] },
    { id: "ssllabs-rate-state", group: "SSL Labs", label: "SSL Labs hız sınırı / önbellek durumu", method: "GET", route: "/api/tools/ssllabs/rate-state",
      fields: [{ name: "hostname", label: "Ana makine adı (isteğe bağlı)", type: "text" }],
      query: v => (v.hostname ? `?hostname=${encodeURIComponent(v.hostname)}` : "") },
    { id: "ssllabs-cached-query", group: "SSL Labs", label: "SSL Labs önbellekten sorgu (Qualys)", method: "POST", route: "/api/tools/ssllabs/cached-query",
      fields: [{ name: "hostname", label: "Genel ana makine adı", type: "text", required: true },
        consent("confirm_qualys", "Bu ana makine adının Qualys SSL Labs önbelleğinden sorgulanmasını onaylıyorum (dış istek)")] },
    { id: "ssllabs-target-preview", group: "SSL Labs", label: "Kayıtlı SSL Labs raporu hedef adı önizlemesi", method: "POST",
      route: "/api/engagements/{engagement_id}/tool-reports/ssllabs-host/target-preview",
      fields: [proofEngagement, { name: "report", label: "Kayıtlı SSL Labs host JSON", type: "json", file: ".json", required: true },
        consent("confirm_host_preview", "Rapordaki ana makine adının denetim hedefiyle karşılaştırılmasını onaylıyorum")],
      build: v => ({ report: v.report, confirm_host_preview: true }) },
    { id: "tool-evidence", group: "Kanıt bağlama", label: "Kayıtlı araç raporunu denetime kanıt olarak bağla", method: "POST",
      route: "/api/engagements/{engagement_id}/tool-evidence/{slug}",
      fields: [proofEngagement, { name: "slug", label: "Rapor türü", type: "select", options: Object.entries(EVIDENCE_SLUGS).map(([key, item]) => [key, item.label]) },
        { name: "control_id", label: "Test adımı (ör. WSTG-INFO-02)", type: "text", required: true },
        { name: "report", label: "Rapor içeriği", type: "textarea", file: ".json,.jsonl,.xml,.txt,.pem,.ndjson", required: true },
        consent("confirm_link", "Bu raporun denetime kanıt olarak bağlanmasını onaylıyorum")],
      build(v) {
        const kind = EVIDENCE_SLUGS[v.slug]?.kind;
        if (!kind) throw new Error("Geçersiz rapor türü.");
        return { control_id: v.control_id, report: coerceEvidence(v.report, kind), confirm_link: true };
      } },
    { id: "project-audit-diff", group: "Proje analizi", label: "İki proje analizini karşılaştır", method: "POST", route: "/api/project-audits/diff",
      fields: [{ name: "before_id", label: "Önceki analiz", type: "project-audit", required: true },
        { name: "after_id", label: "Sonraki analiz", type: "project-audit", required: true }],
      build(v) {
        if (v.before_id === v.after_id) throw new Error("İki farklı analiz seçin.");
        return { before_id: v.before_id, after_id: v.after_id };
      } },
  ]);

  function coerceEvidence(raw, kind) {
    const text = String(raw || "").trim();
    if (kind === "text") return text;
    if (kind === "jsonl") {
      if (text.startsWith("[")) return JSON.parse(text);
      return text.split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line));
    }
    const parsed = JSON.parse(text);
    if (kind === "object" && (!parsed || typeof parsed !== "object" || Array.isArray(parsed))) throw new Error("Rapor bir JSON nesnesi olmalı.");
    if (kind === "objectOrArray" && (!parsed || typeof parsed !== "object")) throw new Error("Rapor JSON nesnesi veya dizisi olmalı.");
    return parsed;
  }

  const byId = id => document.getElementById(id);
  const flowById = id => FLOWS.find(flow => flow.id === id) || null;
  let generation = 0;
  const lists = { targets: [], engagements: [], audits: [] };

  function option(select, value, label) {
    const item = document.createElement("option");
    item.value = value;
    item.textContent = label;
    select.append(item);
  }

  function eligibleEngagements(kind) {
    return lists.engagements.filter(item => item && item.status === "active" &&
      typeof item.authorization_ref === "string" && item.authorization_ref.trim() &&
      (kind !== "proof" || item.special_approvals?.redacted_data_proof === true));
  }

  async function loadLists(apiClient) {
    const [targets, engagements, audits] = await Promise.all([
      apiClient("/api/targets").catch(() => ({})),
      apiClient("/api/engagements").catch(() => ({})),
      apiClient("/api/project-audits").catch(() => ({})),
    ]);
    lists.targets = Array.isArray(targets?.targets) ? targets.targets : [];
    lists.engagements = Array.isArray(engagements?.engagements) ? engagements.engagements : [];
    lists.audits = Array.isArray(audits?.project_audits) ? audits.project_audits : [];
  }

  function renderFields(flow) {
    const container = byId("advanced-tool-fields");
    if (!container) return;
    container.replaceChildren();
    for (const field of flow.fields) {
      const label = document.createElement("label");
      label.className = field.type === "checkbox" ? "full checkbox-row" : (["textarea", "json", "lines", "files"].includes(field.type) ? "full" : "");
      let input;
      if (field.type === "checkbox") {
        input = document.createElement("input");
        input.type = "checkbox";
        label.append(input, document.createTextNode(` ${field.label}`));
      } else {
        label.append(document.createTextNode(field.label));
        if (["target", "engagement", "select", "project-audit"].includes(field.type)) {
          input = document.createElement("select");
          if (field.type === "target") {
            option(input, "", "Hedef seçin");
            for (const item of lists.targets) option(input, item.id, `${item.hostname || item.url || item.id}`);
          } else if (field.type === "engagement") {
            const eligible = eligibleEngagements(field.eligible);
            option(input, "", eligible.length ? "Denetim seçin" : "Uygun etkin denetim yok");
            for (const item of eligible) option(input, item.id, `${item.name || item.id} · ${item.authorization_ref}`);
          } else if (field.type === "project-audit") {
            option(input, "", lists.audits.length ? "Analiz seçin" : "Kayıtlı proje analizi yok");
            for (const item of lists.audits) option(input, item.id, `${item.project_name || item.id} · ${item.score ?? "?"}/100 · ${item.created_at || ""}`);
          } else {
            for (const [value, text] of field.options) option(input, value, text);
          }
        } else if (["textarea", "json", "lines"].includes(field.type)) {
          input = document.createElement("textarea");
          input.rows = field.type === "lines" ? 3 : 6;
          input.spellcheck = false;
        } else if (field.type === "files") {
          input = document.createElement("input");
          input.type = "file";
          input.multiple = true;
        } else {
          input = document.createElement("input");
          input.type = "text";
          input.autocomplete = "off";
          input.spellcheck = false;
          if (field.value) input.value = field.value;
        }
        label.append(input);
      }
      input.dataset.advancedField = field.name;
      container.append(label);
      if (field.file) {
        const fileLabel = document.createElement("label");
        fileLabel.className = "full";
        fileLabel.append(document.createTextNode(`Veya dosyadan yükle (${field.label})`));
        const fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.accept = field.file;
        fileInput.addEventListener("change", async () => {
          const file = fileInput.files?.[0];
          if (!file) return;
          if (file.size > 300_000) { showError("Dosya çok büyük (en çok 300 KB)."); return; }
          input.value = await file.text();
        });
        fileLabel.append(fileInput);
        container.append(fileLabel);
      }
    }
  }

  async function readValues(flow) {
    const values = {};
    for (const field of flow.fields) {
      const input = document.querySelector(`#advanced-tool-fields [data-advanced-field="${field.name}"]`);
      if (!input) continue;
      if (field.type === "checkbox") {
        values[field.name] = input.checked === true;
        if (field.required && !values[field.name]) throw new Error(`Onay gerekli: ${field.label}`);
        continue;
      }
      if (field.type === "files") {
        const files = [...(input.files || [])];
        if (field.required && !files.length) throw new Error(`${field.label} seçilmedi.`);
        if (files.length > 16) throw new Error("En çok 16 dosya seçilebilir.");
        values[field.name] = await Promise.all(files.map(async file => {
          if (file.size > 65_536) throw new Error(`${file.name} 64 KiB sınırını aşıyor.`);
          return { relative_path: file.name, content: await file.text() };
        }));
        continue;
      }
      const raw = typeof input.value === "string" ? input.value : "";
      const text = field.type === "textarea" ? raw : raw.trim();
      if (field.required && !text.trim()) throw new Error(`${field.label} gerekli.`);
      if (field.type === "lines") {
        values[field.name] = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      } else if (field.type === "json") {
        if (!text.trim()) { values[field.name] = undefined; continue; }
        try { values[field.name] = JSON.parse(text); } catch { throw new Error(`${field.label}: geçerli JSON değil.`); }
      } else if (field.type === "ports") {
        const ports = text.split(/[,\s]+/).filter(Boolean).map(Number);
        if (!ports.length || ports.length > 8 || ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) {
          throw new Error("1–8 adet 1–65535 arası TCP portu girin.");
        }
        values[field.name] = ports;
      } else {
        values[field.name] = text;
      }
    }
    return values;
  }

  function defaultBuild(flow, values) {
    const out = {};
    for (const field of flow.fields) {
      if (values[field.name] === undefined || values[field.name] === "") continue;
      out[field.name] = values[field.name];
    }
    return out;
  }

  function resolveRoute(flow, values) {
    return flow.route.replace(/\{(\w+)\}/g, (_, key) => {
      const value = values[key];
      if (typeof value !== "string" || !value) throw new Error("Denetim seçilmedi.");
      return encodeURIComponent(value);
    });
  }

  function buildRequest(flow, values) {
    const path = resolveRoute(flow, values) + (flow.query ? flow.query(values) : "");
    if (flow.method === "GET") return { path, options: {} };
    const body = flow.build ? flow.build(values) : defaultBuild(flow, values);
    return { path, options: { method: "POST", body: JSON.stringify(body) } };
  }

  function showError(message) {
    const error = byId("advanced-tool-error");
    if (!error) return;
    error.textContent = message;
    error.classList.toggle("hidden", !message);
  }

  function summaryFacts(data) {
    const facts = [];
    if (!data || typeof data !== "object") return facts;
    for (const key of ["format", "status", "verdict", "score", "grade", "finding_count", "total", "file_count", "summary_status", "fresh", "age_hours"]) {
      const value = data[key];
      if (value === undefined || value === null || typeof value === "object") continue;
      facts.push([key, String(value)]);
    }
    return facts.slice(0, 8);
  }

  function renderResult(flow, data) {
    const summary = byId("advanced-tool-summary");
    const output = byId("advanced-tool-output");
    const renderer = flow.renderer && globalThis.SniperToolBoundary?.[flow.renderer];
    if (summary) {
      summary.replaceChildren();
      let rendered = false;
      if (typeof renderer === "function") {
        try {
          summary.innerHTML = renderer(data, globalThis.esc); // sniper-reviewed: html-safe (tool_boundary_summaries tüm alanları kaçışlar)
          rendered = true;
        } catch { rendered = false; }
      }
      if (!rendered) {
        for (const [key, value] of summaryFacts(data)) {
          const pill = document.createElement("span");
          pill.className = "status-pill";
          const strong = document.createElement("b");
          strong.textContent = `${key}: `;
          pill.append(strong, document.createTextNode(value));
          summary.append(pill);
        }
      }
      summary.classList.toggle("hidden", !summary.childNodes.length);
    }
    if (output) {
      output.textContent = JSON.stringify(data, null, 2);
      output.classList.remove("hidden");
    }
  }

  function selectFlow(flowId) {
    const select = byId("advanced-tool-route");
    const flow = flowById(flowId) || FLOWS[0];
    if (select) select.value = flow.id;
    generation += 1;
    showError("");
    byId("advanced-tool-summary")?.classList.add("hidden");
    byId("advanced-tool-output")?.classList.add("hidden");
    renderFields(flow);
    const description = byId("advanced-tool-route-info");
    if (description) description.textContent = `${flow.method} ${flow.route}`;
    return flow;
  }

  async function openFlow(flowId, apiClient = globalThis.api) {
    if (typeof apiClient === "function") await loadLists(apiClient);
    const flow = selectFlow(flowId);
    const panel = byId("advanced-tool-panel");
    panel?.scrollIntoView?.({ block: "start" });
    return flow;
  }

  async function submit(apiClient = globalThis.api) {
    const select = byId("advanced-tool-route");
    const flow = flowById(select?.value);
    if (!flow || typeof apiClient !== "function") return null;
    const current = ++generation;
    showError("");
    const button = byId("advanced-tool-submit");
    if (button) button.disabled = true;
    try {
      const values = await readValues(flow);
      const { path, options } = buildRequest(flow, values);
      const background = byId("advanced-tool-background")?.checked && options.method === "POST" && globalThis.SniperJobs;
      if (background) {
        // Uzun akış: /api/jobs üzerinden arka planda (sunucu izinli rotaları ayrıca denetler).
        const job = await globalThis.SniperJobs.run(path, JSON.parse(options.body || "{}"), byId("advanced-tool-job-status"));
        globalThis.SniperJobsPanel?.refresh?.();
        if (current !== generation) return null;
        if (job.state !== "succeeded") throw new Error(job.error || globalThis.SniperJobs.stateLabel(job.state));
        renderResult(flow, job.result);
        return job.result;
      }
      const data = await apiClient(path, options);
      if (current !== generation) return null;
      renderResult(flow, data);
      return data;
    } catch (error) {
      if (current === generation) showError(error?.message || "İstek tamamlanamadı.");
      return null;
    } finally {
      if (button) button.disabled = false;
    }
  }

  function init() {
    const select = byId("advanced-tool-route");
    const form = byId("advanced-tool-form");
    if (!select || !form || select.dataset.ready === "1") return;
    select.dataset.ready = "1";
    let group = null;
    let optgroup = null;
    for (const flow of FLOWS) {
      if (flow.group !== group) {
        group = flow.group;
        optgroup = document.createElement("optgroup");
        optgroup.label = group;
        select.append(optgroup);
      }
      option(optgroup, flow.id, flow.label);
    }
    select.addEventListener("change", () => { selectFlow(select.value); });
    form.addEventListener("submit", event => { event.preventDefault(); submit(); });
    byId("advanced-tool-refresh")?.addEventListener("click", async () => {
      if (typeof globalThis.api === "function") await loadLists(globalThis.api);
      selectFlow(select.value);
    });
    selectFlow(FLOWS[0].id);
    const initial = generation;
    // Listeler gelince alanları yalnız kullanıcı bu arada başka bir akış seçmediyse yeniden çiz.
    if (typeof globalThis.api === "function") {
      loadLists(globalThis.api).then(() => { if (initial === generation) selectFlow(select.value); }).catch(() => {});
    }
  }

  globalThis.SniperAdvancedTools = Object.freeze({ FLOWS, EVIDENCE_SLUGS, coerceEvidence, buildRequest, readValues, openFlow, selectFlow, submit, init, lists });
  globalThis.openAdvancedToolFlow = openFlow;
  if (typeof document !== "undefined" && document.readyState !== "loading") init();
  else if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", init);
})();
