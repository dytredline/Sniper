// Sürüm ve güncelleme kartı (salt okunur). Güncelleme/geri dönüş yalnız komut satırından yapılır; bu kart
// yalnız /api/system/version bilgisini gösterir. Yalnız DOM API ve textContent kullanır.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);
  const ACTIONS = { install: "Kurulum", update: "Güncelleme", rollback: "Geri dönüş", auto_rollback: "Otomatik geri dönüş" };
  const STATUSES = { ok: "Tamam", rolled_back: "Geri dönüldü", pending_restart: "Yeniden başlatma bekliyor", unhealthy: "Sağlıksız", failed: "Başarısız" };
  const SIGNATURES = { verified: "Ed25519 imzası doğrulandı", unsigned: "İmzasız (yalnız SHA-256 bütünlüğü)", signed_unverified: "İmzalı, genel anahtar yok" };

  function shortDigest(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/.test(value) ? `${value.slice(0, 12)}…` : "—";
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function when(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("tr-TR", { dateStyle: "short", timeStyle: "short" }).format(date);
  }

  function size(bytes) {
    if (!Number.isFinite(bytes)) return "—";
    return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
  }

  function facts(data) {
    const release = data.release || {};
    const last = data.last_update;
    const rows = [
      ["Sürüm", release.version || (data.product_version ? `${data.product_version} (paketsiz kurulum)` : "—")],
      ["Motor kimliği", data.engine_id || "—"],
      ["Paket imzası", release.version ? (SIGNATURES[release.signature] || release.signature || "—") : "—"],
      ["Kurulum tarihi", when(data.installed_at || release.installed_at)],
      ["Son güncelleme", last ? `${when(last.at)} · ${ACTIONS[last.action] || last.action} · ${STATUSES[last.status] || last.status || "—"}` : "Henüz yok"],
    ];
    if (data.restart_pending && data.installed_version) {
      rows.splice(1, 0, ["Bekleyen sürüm", `${data.installed_version} (servis yeniden başlatılınca)`]);
    }
    return rows;
  }

  function render(data) {
    const list = byId("system-version-facts");
    if (!list) return;
    list.replaceChildren();
    for (const [label, value] of facts(data)) {
      list.append(el("dt", label), el("dd", value));
    }
    const command = byId("system-version-command");
    if (command) command.textContent = data.maintenance_note || "";
    const body = byId("system-version-backups");
    const empty = byId("system-version-backups-empty");
    if (body) {
      body.replaceChildren();
      for (const item of data.backups || []) {
        const row = el("tr");
        row.append(el("td", item.id), el("td", when(item.created_at)), el("td", item.version || "—"),
          el("td", item.reason || "—"), el("td", item.has_db ? "Var" : "Yok"), el("td", size(item.bytes)));
        body.append(row);
      }
      empty?.classList.toggle("hidden", (data.backups || []).length > 0);
    }
  }

  async function load() {
    if (!byId("system-version-facts")) return;
    try {
      const response = await fetch("/api/system/version", { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`Sürüm bilgisi alınamadı (${response.status})`);
      render(await response.json());
    } catch (error) {
      const list = byId("system-version-facts");
      if (list) list.replaceChildren(el("dt", "Durum"), el("dd", error.message || "Sürüm bilgisi alınamadı"));
    }
  }

  scope.SniperSystemVersion = { render, facts, load };
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", load);
    else load();
  }
})();
