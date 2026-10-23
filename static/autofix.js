// Proje analizi bulguları için "Düzeltme öner": sunucudan salt-okunur önizleme (birleşik fark)
// ister ve yalnız DOM API / textContent ile gösterir (HTML enjeksiyonu yok). Dosyaya yazılmaz.
// "Doğrulanmış düzeltme": yama sunucuda geçici kopyaya uygulanıp yeniden analiz edilir; sonuç rozeti
// (doğrulandı / kısmen / başarısız), gerekçeler ve .patch indirme. "Benzer bulguları toplu düzelt":
// aynı kalıptaki bulgular için tek yama + tek doğrulama.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;

  async function request(path, body = {}) {
    if (typeof scope.api === "function") return scope.api(path, { method: "POST", body: JSON.stringify(body) });
    const response = await scope.fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), credentials: "same-origin" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : `İstek ${response.status} durum koduyla başarısız oldu.`);
    return data;
  }

  async function getJson(path) {
    if (typeof scope.api === "function") return scope.api(path);
    const response = await scope.fetch(path, { credentials: "same-origin" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : `İstek ${response.status} durum koduyla başarısız oldu.`);
    return data;
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function diffBlock(diff) {
    const pre = el("pre", null, "code-box autofix-diff");
    for (const line of String(diff).split("\n")) {
      const cls = line.startsWith("+") && !line.startsWith("+++") ? "diff-add"
        : line.startsWith("-") && !line.startsWith("---") ? "diff-del" : line.startsWith("@@") ? "diff-hunk" : "";
      pre.append(el("span", `${line}\n`, cls));
    }
    return pre;
  }

  function render(container, data) {
    container.replaceChildren();
    const strategy = data.strategy || {};
    container.append(el("p", `${strategy.title || "Öneri"} (${strategy.cwe || ""}) · güven: ${data.confidence || "?"} · yalnız önizleme, dosya değiştirilmedi`, "autofix-head"));
    if (strategy.explanation) container.append(el("p", strategy.explanation, "muted"));
    if (Array.isArray(data.notes) && data.notes.length) {
      const list = el("ul", null, "autofix-notes");
      for (const note of data.notes) list.append(el("li", note));
      container.append(list);
    }
    if (data.mode === "diff" && data.diff) {
      container.append(diffBlock(data.diff));
    } else if (data.snippet) {
      container.append(el("p", "Otomatik fark üretilemedi; örnek güvenli kullanım:", "muted"));
      container.append(el("pre", data.snippet, "code-box"));
    }
    container.classList.remove("hidden");
  }

  const VERDICT_TEXT = { verified: "Doğrulandı", partial: "Kısmen", failed: "Başarısız" };

  function setBadge(badge, verdict) {
    if (!badge) return;
    badge.className = `autofix-badge ${["verified", "partial", "failed"].includes(verdict) ? verdict : "failed"}`;
    badge.textContent = VERDICT_TEXT[verdict] || "Başarısız";
  }

  function downloadPatch(filename, text) {
    const blob = new Blob([String(text)], { type: "text/x-diff" });
    const url = URL.createObjectURL(blob);
    const link = el("a");
    link.href = url;
    link.download = /^[\w.-]{1,120}$/.test(filename || "") ? filename : "sniper-fix.patch";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function findingLabel(item) {
    return `${item.title || "Bulgu"} — ${item.file || ""}${item.line ? `:${Number(item.line)}` : ""}`;
  }

  function renderVerification(container, data) {
    container.replaceChildren();
    const head = el("p", null, "autofix-head");
    const badge = el("span");
    setBadge(badge, data.verdict);
    head.append(el("span", "Düzeltme doğrulaması: "), badge,
      el("span", ` · ${Number(data.duration_ms || 0)} ms · proje dosyalarına yazılmadı`));
    container.append(head);
    const reasons = el("ul", null, "autofix-reasons");
    for (const reason of data.reasons || []) reasons.append(el("li", reason));
    container.append(reasons);
    if (data.scope_note) container.append(el("p", data.scope_note, "muted"));
    const targets = Array.isArray(data.targets) ? data.targets : [];
    if (targets.length > 1 || targets.some(row => !row.closed)) {
      const table = el("table");
      const header = el("tr");
      for (const label of ["Bulgu", "Yama", "Sonuç"]) header.append(el("th", label));
      table.append(header);
      for (const row of targets) {
        const tr = el("tr");
        tr.append(el("td", findingLabel(row)), el("td", row.applied ? "uygulandı" : "üretilemedi"),
          el("td", row.closed ? "kapandı" : row.guarded ? `koruma eklendi — ${row.reason || ""}` : `açık — ${row.reason || ""}`));
        table.append(tr);
      }
      container.append(table);
    }
    for (const [label, items] of [["Yamanın doğurduğu yeni bulgular", data.new_findings], ["Yeni düşük önemli notlar", data.new_notes], ["Ayrıca kapanan bulgular", data.also_closed]]) {
      if (!Array.isArray(items) || !items.length) continue;
      container.append(el("p", label, "muted"));
      const list = el("ul", null, "autofix-notes");
      for (const item of items) list.append(el("li", `${findingLabel(item)} (${item.severity || "?"})`));
      container.append(list);
    }
    if (data.diff) {
      container.append(diffBlock(data.diff));
      const actions = el("div", null, "row-actions");
      const download = el("button", ".patch indir", "mini-button");
      download.type = "button";
      download.addEventListener("click", () => downloadPatch(data.patch_filename, data.diff));
      actions.append(download);
      container.append(actions);
    } else if (data.snippet) {
      container.append(el("p", "Otomatik yama üretilemedi; örnek güvenli kullanım:", "muted"));
      container.append(el("pre", data.snippet, "code-box"));
    }
    container.classList.remove("hidden");
  }

  async function suggest(button) {
    const auditId = button.dataset.autofixAudit || "";
    const index = button.dataset.autofixIndex || "";
    if (!/^\d+$/.test(index) || !auditId) return null;
    const article = button.closest("article") || document;
    const container = article.querySelector(`[data-autofix-result="${index}"]`);
    if (!container) return null;
    button.disabled = true;
    container.classList.remove("hidden");
    container.replaceChildren(el("p", "Öneri hazırlanıyor…", "muted"));
    try {
      const data = await request(`/api/project-audits/${encodeURIComponent(auditId)}/findings/${index}/autofix`);
      render(container, data);
      return data;
    } catch (error) {
      container.replaceChildren(el("p", `Öneri üretilemedi: ${error.message}`, "error-message"));
      return null;
    } finally {
      button.disabled = false;
    }
  }

  async function verify(button) {
    const auditId = button.dataset.autofixVerifyAudit || "";
    const index = button.dataset.autofixVerify || "";
    if (!/^\d+$/.test(index) || !auditId) return null;
    const article = button.closest("article") || document;
    const container = article.querySelector(`[data-autofix-result="${index}"]`);
    const badge = article.querySelector(`[data-autofix-badge="${index}"]`);
    if (!container) return null;
    button.disabled = true;
    container.classList.remove("hidden");
    container.replaceChildren(el("p", "Yama geçici kopyada uygulanıp yeniden analiz ediliyor…", "muted"));
    try {
      const data = await request(`/api/project-audits/${encodeURIComponent(auditId)}/findings/${index}/autofix/verify`);
      renderVerification(container, data);
      setBadge(badge, data.verdict);
      return data;
    } catch (error) {
      container.replaceChildren(el("p", `Doğrulama yapılamadı: ${error.message}`, "error-message"));
      return null;
    } finally {
      button.disabled = false;
    }
  }

  async function bulk(auditId, group, container) {
    const result = el("div", null, "autofix-result");
    container.append(result);
    result.replaceChildren(el("p", "Toplu yama geçici kopyada doğrulanıyor…", "muted"));
    try {
      const data = await request(`/api/project-audits/${encodeURIComponent(auditId)}/autofix/bulk`, { group });
      renderVerification(result, data);
      return data;
    } catch (error) {
      result.replaceChildren(el("p", `Toplu düzeltme yapılamadı: ${error.message}`, "error-message"));
      return null;
    }
  }

  async function groups(button) {
    const auditId = button.dataset.autofixGroups || "";
    if (!auditId) return null;
    const holder = button.parentElement || document;
    const container = holder.querySelector("[data-autofix-groups-result]");
    if (!container) return null;
    button.disabled = true;
    container.classList.remove("hidden");
    container.replaceChildren(el("p", "Benzer bulgu grupları hazırlanıyor…", "muted"));
    try {
      const data = await getJson(`/api/project-audits/${encodeURIComponent(auditId)}/autofix-groups`);
      container.replaceChildren();
      const list = Array.isArray(data.groups) ? data.groups : [];
      if (!list.length) {
        container.append(el("p", "Aynı kalıpta birden çok otomatik düzeltilebilir bulgu yok.", "muted"));
        return data;
      }
      const table = el("table");
      const header = el("tr");
      for (const label of ["Kalıp", "Bulgu", "Dosya", ""]) header.append(el("th", label));
      table.append(header);
      for (const group of list) {
        const tr = el("tr");
        const action = el("button", "Toplu düzelt ve doğrula", "mini-button accent");
        action.type = "button";
        action.addEventListener("click", async () => {
          action.disabled = true;
          try { await bulk(auditId, group.key, container); } finally { action.disabled = false; }
        });
        const cell = el("td");
        cell.append(action);
        tr.append(el("td", `${group.strategy || group.kind} · ${group.reference || ""}${group.api ? ` · ${group.api}` : ""}`),
          el("td", String(Number(group.count || 0))), el("td", (group.files || []).join(", ")), cell);
        table.append(tr);
      }
      container.append(table);
      return data;
    } catch (error) {
      container.replaceChildren(el("p", `Gruplar alınamadı: ${error.message}`, "error-message"));
      return null;
    } finally {
      button.disabled = false;
    }
  }

  function onClick(event) {
    const target = event.target && event.target.closest ? event.target : null;
    if (!target) return;
    const verifyButton = target.closest("[data-autofix-verify]");
    if (verifyButton && verifyButton.dataset && verifyButton.dataset.autofixVerify !== undefined) {
      event.preventDefault();
      verify(verifyButton);
      return;
    }
    const groupsButton = target.closest("[data-autofix-groups]");
    if (groupsButton && groupsButton.dataset && groupsButton.dataset.autofixGroups !== undefined) {
      event.preventDefault();
      groups(groupsButton);
      return;
    }
    const button = target.closest("[data-autofix-index]");
    if (button) {
      event.preventDefault();
      suggest(button);
    }
  }

  scope.SniperAutofix = Object.freeze({ suggest, render, verify, renderVerification, groups, bulk });
  if (typeof document !== "undefined") document.addEventListener("click", onClick);
})();
