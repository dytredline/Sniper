// MCP tarama isteklerinde insan hedef yetkisi kapısı. Sayfa açılışı yalnız kuyruğu okur; POST ancak yönetici
// hedefi/aracı inceleyip satırdaki kutuyu işaretleyerek Onayla düğmesine bastığında gönderilir.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function targetText(item) {
    const parameters = item && typeof item.parameters === "object" ? item.parameters : {};
    return String(item.normalized_target || parameters.target || parameters.target_id || "—");
  }

  function consentText(item) {
    const tool = item?.parameters?.tool_id;
    if (tool === "ssllabs") {
      return " Bu public DNS hedefinin HTTPS:443 değerlendirmesi için Qualys SSL Labs üçüncü taraf hizmetine gönderilmesine ve bu değerlendirmeye yetkim var";
    }
    if (tool === "schemathesis") {
      return " Bu kök originde inline şemadaki GET/POST/PUT/PATCH/DELETE operasyonlarına (POST/DELETE dahil) sınırlı istek gönderilmesine yetkim var";
    }
    return " Bu hedefte gösterilen sabit kapsamlı taramaya yetkim var";
  }

  function planText(item) {
    const tool = String(item?.parameters?.tool_id || item?.profile_id || "—").slice(0, 80);
    const profile = String(item?.effective_profile || item?.profile_id || "—").slice(0, 120);
    const scopes = Array.isArray(item?.scope_summary)
      ? item.scope_summary.slice(0, 4).filter(value => typeof value === "string").map(value => value.slice(0, 200))
      : [];
    return `${tool} · ${profile}${scopes.length ? ` · ${scopes.join("; ")}` : ""}`;
  }

  async function call(path, body) {
    const options = body === undefined ? { headers: { Accept: "application/json" } } : {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
    };
    const response = await scope.fetch(path, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }

  function render(data) {
    const body = byId("mcp-scan-approval-body");
    const status = byId("mcp-scan-approval-status");
    if (!body) return;
    body.replaceChildren();
    const actionable = (Array.isArray(data.requests) ? data.requests : []).filter(
      item => item && ["pending", "approved", "started", "running"].includes(item.status)
    );
    for (const item of actionable) {
      const row = el("tr");
      const tool = item.parameters && item.parameters.tool_id ? item.parameters.tool_id : item.profile_id;
      const requester = item.requested_by || {};
      const actions = el("td");
      if (item.status === "pending") {
        const label = el("label");
        const consent = el("input");
        consent.type = "checkbox";
        consent.setAttribute("aria-label", `${targetText(item)} hedefi için yetkim var`);
        label.append(consent, el("span", consentText(item)));
        const approve = el("button", "Onayla", "mini-button accent");
        approve.type = "button";
        approve.disabled = true;
        consent.addEventListener("change", () => { approve.disabled = consent.checked !== true; });
        approve.addEventListener("click", async () => {
          if (consent.checked !== true) return;
          approve.disabled = true;
          try {
            const result = await call(`/api/mcp-scan-requests/${item.id}/approve`, {
              confirm: true,
              confirm_authorized: true,
            });
            await load();
            if (status) {
              status.textContent = result?.request?.status === "started" && result?.job?.id
                ? `İnsan yetki beyanı SHA-256 makbuzuyla kaydedildi; ${result.job.id} iş kuyruğuna alındı.`
                : "İnsan yetki beyanı SHA-256 makbuzuyla kaydedildi; araç için onay kaydı hazırlandı.";
            }
          } catch (error) {
            if (status) status.textContent = error.message || "İstek onaylanamadı.";
            approve.disabled = consent.checked !== true;
          }
        });
        actions.append(label, approve);
      }
      const cancelLabel = item.status === "pending" ? "Reddet" : (item.status === "approved" ? "Kapat" : "İptal");
      const cancel = el("button", cancelLabel, "mini-button");
      cancel.type = "button";
      cancel.addEventListener("click", async () => {
        cancel.disabled = true;
        try {
          await call(`/api/mcp-scan-requests/${item.id}/cancel`, { confirm: true });
          await load();
          if (status) {
            status.textContent = item.status === "pending" ? "Tarama isteği reddedildi."
              : (item.status === "approved" ? "Elle devir kaydı kapatıldı." : "Tarama işi iptal edildi.");
          }
        } catch (error) {
          if (status) status.textContent = error.message || "İstek iptal edilemedi.";
          cancel.disabled = false;
        }
      });
      actions.append(cancel);
      row.append(
        el("td", planText(item)),
        el("td", targetText(item)),
        el("td", requester.username || requester.id || "—"),
        el("td", item.created_at || "—"),
        actions,
      );
      body.append(row);
    }
    if (status) {
      const pendingCount = actionable.filter(item => item.status === "pending").length;
      const approvedCount = actionable.filter(item => item.status === "approved").length;
      const activeCount = actionable.length - pendingCount - approvedCount;
      status.textContent = actionable.length
        ? `${pendingCount} iş insan hedef yetkisi bekliyor; ${approvedCount} elle devir; ${activeCount} iş çalışıyor.`
        : "Bekleyen veya çalışan iş yok.";
    }
  }

  async function load() {
    if (!byId("mcp-scan-approval-body")) return;
    const status = byId("mcp-scan-approval-status");
    try {
      render(await call("/api/mcp-scan-requests"));
    } catch (error) {
      if (status) status.textContent = error.message || "MCP kuyruğu alınamadı.";
    }
  }

  function start() {
    if (!byId("mcp-scan-approval-panel")) return;
    byId("mcp-scan-approval-refresh")?.addEventListener("click", load);
    load();
  }

  scope.SniperMCPScanApproval = { render, load, targetText, consentText, planText };
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
    else start();
  }
})();
