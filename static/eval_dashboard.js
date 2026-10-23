// Doğruluk panosu (salt okunur): son ölçüm (set başına TP/FN, kesinlik, CodeQL), sınıf kesinlikleri, ölçüm geçmişi
// ve triyaja göre kural bazlı yanlış alarm oranları. Ölçümler scripts/eval_pipeline.py ile üretilir; içerik textContent ile basılır.
(() => {
  const scope = typeof window !== "undefined" ? window : globalThis;
  const byId = id => (typeof document !== "undefined" ? document.getElementById(id) : null);
  const pct = value => (typeof value === "number" ? `%${Math.round(value * 100)}` : "—");

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function table(headers, rows) {
    const wrap = el("div", null, "responsive-table");
    const tableNode = el("table");
    const head = el("thead");
    const headRow = el("tr");
    headers.forEach(h => headRow.append(el("th", h)));
    head.append(headRow);
    const body = el("tbody");
    rows.forEach(cells => {
      const tr = el("tr");
      cells.forEach(value => tr.append(el("td", value)));
      body.append(tr);
    });
    tableNode.append(head, body);
    wrap.append(tableNode);
    return wrap;
  }

  function codeqlText(cq) {
    if (!cq) return "—";
    if (typeof cq.tp === "number") return `${cq.tp}/${cq.total}`;
    if (typeof cq.both === "number") return `ikisi ${cq.both} · yalnız CodeQL ${cq.only_codeql}`;
    return "—";
  }

  function renderLatest(container, data) {
    const latest = data && data.latest;
    if (!latest) {
      container.append(el("p", "Henüz ölçüm yok. scripts/eval_pipeline.py --config <yapılandırma> ile ilk ölçümü çalıştırın.", "muted"));
      return;
    }
    const regressions = (data.regressions || []).length;
    container.append(el("p", `Son ölçüm: ${latest.label || "—"} · ${latest.created_at || ""} · motor ${latest.engine || ""} · `
      + (regressions ? `${regressions} regresyon` : "regresyon yok"), regressions ? "eval-status bad" : "eval-status ok"));
    const rows = Object.entries(latest.sets || {}).map(([name, row]) => [
      name,
      row.kind === "benign" ? "olgun" : "açıklı",
      typeof row.tp === "number" ? `${row.tp}/${row.total}` : (row.verified_flows ?? "—"),
      pct(row.recall),
      pct(row.precision),
      typeof row.false_positives === "number" ? `${row.false_positives} / ${row.unclassified ?? 0}` : (row.new_flows_vs_baseline ?? "—"),
      codeqlText(row.codeql),
      row.seconds != null ? `${row.seconds} sn` : "—",
    ]);
    container.append(table(["Set", "Tür", "Bulunan (TP/toplam) veya akış", "Duyarlılık", "Kesinlik", "Yanlış / sınıflandırılmamış (olgun: yeni akış)", "CodeQL", "Süre"], rows));
    const classes = Object.entries(latest.class_precision || {}).filter(([, row]) => row.precision != null);
    if (classes.length) {
      container.append(el("h3", "Sınıf başına ölçülmüş kesinlik ve duyarlılık"));
      container.append(table(["Sınıf", "Kesinlik", "Değerlendirilen", "Duyarlılık", "Zemin gerçeği"],
        classes.map(([cls, row]) => [cls, pct(row.precision), row.judged, pct(row.recall), row.gt_total])));
    }
    const benches = Object.entries(latest.benchmarks || {});
    if (benches.length) {
      container.append(el("p", "Kıyaslar: " + benches.map(([name, value]) => `${name} ${value.score ?? (value.correct != null ? `${value.correct} doğru` : value.error || "")}`).join(" · "), "muted"));
    }
    const issues = [...(data.regressions || []).map(r => ["REGRESYON", r]), ...(data.warnings || []).map(w => ["uyarı", w])];
    if (issues.length) {
      container.append(el("h3", "Regresyon ve uyarılar"));
      container.append(table(["Tür", "Set/kıyas", "Ayrıntı"], issues.slice(0, 100).map(([kind, row]) => [
        `${kind}: ${row.type}`, row.set || row.benchmark || "", `${row.project ? row.project + " " : ""}${Array.isArray(row.detail) ? row.detail.join(", ") : row.detail}`,
      ])));
    }
  }

  function renderHistory(container, data) {
    const history = (data && data.history) || [];
    if (!history.length) return;
    const setNames = [...new Set(history.flatMap(item => Object.keys(item.sets || {})))];
    container.append(el("h3", "Ölçüm geçmişi (son 10)"));
    const rows = history.slice(-10).reverse().map(item => [
      `${item.label || ""} · ${item.created_at || ""}`,
      ...setNames.map(name => {
        const row = (item.sets || {})[name];
        if (!row) return "—";
        return typeof row.tp === "number" ? `${row.tp}/${row.total} (${pct(row.precision)})` : String(row.verified_flows ?? "—");
      }),
      item.regressions ? `${item.regressions} regresyon` : "—",
    ]);
    container.append(table(["Ölçüm", ...setNames, "Durum"], rows));
  }

  function renderRules(container, data) {
    const rules = ((data && data.rules) || []).filter(rule => rule.reviewed > 0);
    container.append(el("h3", "Triyaja göre kural yanlış alarm oranı"));
    if (!rules.length) {
      container.append(el("p", "Henüz triyaj kararı yok (bulgularda 'yanlış alarm / doğrulandı' işaretleyin).", "muted"));
      return;
    }
    container.append(el("p", `${data.reviewed} karar, ${data.audits} analiz. Kural ayarı otomatik değiştirilmez.`, "muted"));
    container.append(table(["Referans", "Kural", "Değerlendirilen", "Yanlış alarm", "Oran"],
      rules.slice(0, 20).map(rule => [rule.reference, rule.rule, rule.reviewed, rule.false_positive, pct(rule.false_positive_rate)])));
  }

  async function load(apiClient = scope.api) {
    const container = byId("eval-dashboard-body");
    if (!container || typeof apiClient !== "function") return null;
    const [latest, history, rules] = await Promise.all([
      apiClient("/api/eval/latest").catch(() => null),
      apiClient("/api/eval/history").catch(() => null),
      apiClient("/api/eval/rule-false-positives").catch(() => null),
    ]);
    container.replaceChildren();
    renderLatest(container, latest);
    renderHistory(container, history);
    renderRules(container, rules);
    return { latest, history, rules };
  }

  scope.sniperEvalDashboard = { load };
  if (typeof document !== "undefined") {
    const start = () => {
      byId("eval-dashboard-refresh")?.addEventListener("click", () => load());
      load();
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
    else start();
  }
})();
