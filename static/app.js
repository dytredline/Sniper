const state = {
  targets: [], scans: [], engagements: [], labRuns: [], projectAudits: [], projectAuditTotal: 0, dependencySecurity: null, tooling: null, toolingReadiness: null, dashboard: null, selectedTarget: null,
  selectedEngagement: null, selectedTest: null, selectedFinding: null, selectedLabRun: null, workspaceTab: "overview",
  methodologyCategory: "all", methodologyQuery: "", findingFilter: "all", scanTimer: null, scanDiffResult: null, selectedScan: null,
  dependencyPageOffset: 0, dependencyPageLimit: 100, dependencyRequestSeq: 0,
  reportHistory: { scans: [], offset: 0, anchor: null, hasMore: false, nextOffset: null, previousOffsets: [], initialized: false, loading: false, pendingDirection: null, error: "", generation: 0 },
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = (value = "") => String(value).replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
const uiSymbol = name => `<svg class="ui-symbol" aria-hidden="true"><use href="/static/ui-icons.svg#${name}"></use></svg>`;

// CSP (style-src 'self') satır içi style="" özniteliklerini reddeder; şablonlar bu yüzden data-style taşır ve değerler
// CSSOM ile (CSP'ye takılmadan) uygulanır. Yalnız CSS değişkenleri ve birkaç yerleşim özelliği; url()/expression yok.
const DATA_STYLE_PROPS = /^(--[a-z0-9-]+|margin-bottom|padding|border)$/;
function applyDataStyles(root) {
  if (!root || typeof root.querySelectorAll !== "function") return;
  const nodes = root.matches?.("[data-style]") ? [root, ...root.querySelectorAll("[data-style]")] : root.querySelectorAll("[data-style]");
  for (const node of nodes) {
    for (const declaration of String(node.getAttribute("data-style") || "").split(";")) {
      const index = declaration.indexOf(":");
      if (index < 1) continue;
      const property = declaration.slice(0, index).trim().toLowerCase();
      const value = declaration.slice(index + 1).trim();
      if (!DATA_STYLE_PROPS.test(property) || /url\(|expression|\\|[<>{}]/i.test(value) || value.length > 80) continue;
      node.style.setProperty(property, value);
    }
    node.removeAttribute("data-style");
  }
}
if (typeof MutationObserver === "function" && typeof document !== "undefined" && document.documentElement) {
  new MutationObserver(records => {
    for (const record of records) for (const node of record.addedNodes) if (node.nodeType === 1) applyDataStyles(node);
  }).observe(document.documentElement, { childList: true, subtree: true });
}

async function api(path, options = {}) {
  const config = { ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) } };
  const response = await fetch(path, config);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function toast(message, type = "success") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.innerHTML = `<span>${type === "error" ? "!" : "✓"}</span><span>${esc(message)}</span>`;
  $("#toast-region").append(item);
  setTimeout(() => item.remove(), 4200);
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  return new Intl.DateTimeFormat("tr-TR", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function statusLabel(status) {
  return ({ ready: "Hazır", queued: "Sırada", running: "Taranıyor", planned: "Planlandı", cancelled: "İptal edildi", completed: "Tamamlandı", failed: "Başarısız", active: "Etkin", paused: "Duraklatıldı", open: "Açık", in_progress: "Üzerinde çalışılıyor", retest_required: "Yeniden test bekliyor", resolved: "Çözüldü", reopened: "Yeniden açıldı", risk_accepted: "Risk kabulü" })[status] || status;
}

const activeFindingStatuses = new Set(["open", "in_progress", "retest_required", "reopened"]);

function findingIsOverdue(finding) {
  if (!finding.due_date || !activeFindingStatuses.has(finding.status)) return false;
  const today = new Date();
  const localDate = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;
  return finding.due_date < localDate;
}

function testStatusLabel(status) {
  return ({ not_tested: "Test edilmedi", passed: "Geçti", failed: "Bulgu var", needs_review: "İnceleme gerekli", not_applicable: "Uygulanamaz" })[status] || status;
}

function severityLabel(severity) {
  return ({ critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük", info: "Bilgi" })[severity] || severity;
}

function actionLabel(action) {
  return ({
    "target.created": "Hedef doğrudan eklendi",
    "scan.queued": "Tarama sıraya alındı",
    "scan.started": "Tarama başladı",
    "scan.completed": "Tarama tamamlandı",
    "scan.failed": "Tarama başarısız oldu",
    "engagement.created": "Manuel denetim oluşturuldu",
    "engagement.updated": "Manuel denetim güncellendi",
    "manual_test.updated": "Test adımı güncellendi",
    "manual_finding.created": "Manuel bulgu oluşturuldu",
    "manual_finding.updated": "Manuel bulgu güncellendi",
    "lab_run.created": "Güvenli laboratuvar kaydı oluşturuldu",
    "lab_run.updated": "Laboratuvar kaydı güncellendi",
    "project_audit.completed": "Uygulama kaynak analizi tamamlandı",
    "dependency_sbom.created": "CycloneDX SBOM oluşturuldu",
    "dependency_report.imported": "Bağımlılık raporu içe aktarıldı",
    "dependency_finding.updated": "Bağımlılık bulgusu güncellendi",
  })[action] || action;
}

function scoreClass(score) {
  return score >= 75 ? "good" : score >= 50 ? "warn" : "bad";
}

const modalStack = [];
const originalInert = new Map();
let originalBodyOverflow = "";
let lastModalTrigger = null;
let sarifPreviewGeneration = 0;
let schemathesisJunitModalOpen = false;
let siemEcsModalOpen = false;
const modalFocusSelector = 'a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"]),[contenteditable="true"]';

function visibleModalControl(element) {
  return !!(element && element.isConnected && !element.disabled &&
    !element.closest('.hidden,[hidden],[aria-hidden="true"]') &&
    element.getClientRects().length &&
    (typeof getComputedStyle === "undefined" || getComputedStyle(element).visibility !== "hidden"));
}

function modalControls(modal) {
  return $$(modalFocusSelector, modal).filter(visibleModalControl);
}

function isModalOpen(modal) {
  return Boolean(modal && !modal.classList?.contains?.("hidden"));
}

function activeModal() {
  return modalStack[modalStack.length - 1]?.modal || null;
}

function modalContains(modal, node) {
  // Native elements provide contains(); sparse test DOMs may omit it.
  return typeof modal.contains === "function" ? modal.contains(node) : true;
}

function focusModalBoundary(modal) {
  const entry = modalStack.find(item => item.modal === modal);
  if (entry && !modal.hasAttribute?.("tabindex")) {
    modal.setAttribute("tabindex", "-1");
    entry.addedTabIndex = true;
  }
  modal.focus();
}

function focusModal(modal, last = false) {
  const controls = modalControls(modal);
  const target = last ? controls[controls.length - 1] : controls[0];
  if (target) target.focus();
  else focusModalBoundary(modal);
}

function syncModalInert() {
  const top = activeModal();
  if (!top) {
    for (const [element, wasInert] of originalInert) element.inert = wasInert;
    originalInert.clear();
    return;
  }
  for (const child of Array.from(document.body.children ?? [])) {
    if (child.id === "toast-region" || child.tagName === "SCRIPT") continue;
    if (!originalInert.has(child)) originalInert.set(child, child.inert);
    child.inert = child !== top;
  }
}

function restoreModalFocus(entry) {
  const top = activeModal();
  if (visibleModalControl(entry.opener) && (!top || modalContains(top, entry.opener))) {
    entry.opener.focus();
    return;
  }
  if (top) {
    focusModal(top);
    return;
  }
  const fallback = $$('[data-action="add-target"],.nav-item.active,#mobile-menu')
    .find(visibleModalControl);
  if (fallback) {
    fallback.focus();
  } else {
    const main = $(".main");
    if (main) {
      if (!main.hasAttribute?.("tabindex")) main.setAttribute("tabindex", "-1");
      main.focus();
    }
  }
}

function showModal(id, visible = true) {
  if (id === "nuclei-jsonl-preview-modal") {
    nucleiJsonlModalOpen = Boolean(visible);
    if (!visible) clearNucleiJsonlModal();
  }
  if (id === "trufflehog-preview-modal") {
    const wasOpen = trufflehogPreviewModalOpen;
    trufflehogPreviewModalOpen = Boolean(visible);
    if (!visible || wasOpen) clearTrufflehogModal();
    else resetTrufflehogPreviewOutputs();
  }
  if (id === "k6-summary-preview-modal") {
    const wasOpen = k6SummaryModalOpen;
    k6SummaryModalOpen = Boolean(visible);
    if (!visible || wasOpen) clearK6SummaryPreview();
    else resetK6SummaryPreviewOutputs();
  }
  if (id === "k6-machine-summary-preview-modal") {
    const wasOpen = k6MachineSummaryModalOpen;
    k6MachineSummaryModalOpen = Boolean(visible);
    if (!visible || wasOpen) clearK6MachineSummaryPreview();
    else resetK6MachineSummaryPreviewOutputs();
  }
  if (id === "schemathesis-junit-preview-modal") {
    const wasOpen = schemathesisJunitModalOpen;
    schemathesisJunitModalOpen = Boolean(visible);
    if ((!visible || wasOpen) && typeof globalThis.clearSchemathesisJunitPreview === "function") {
      globalThis.clearSchemathesisJunitPreview();
    }
  }
  if (id === "siem-ecs-preview-modal") {
    const wasOpen = siemEcsModalOpen;
    siemEcsModalOpen = Boolean(visible);
    if ((!visible || wasOpen) && typeof globalThis.clearSiemEcsPreview === "function") {
      globalThis.clearSiemEcsPreview();
    }
  }
  const modal = document.getElementById(id);
  if (!modal) return;
  if (!visible && id === "playwright-json-preview-modal" &&
      typeof modal.dispatchEvent === "function" && typeof Event === "function") {
    modal.dispatchEvent(new Event("sniper:playwright-json-preview-close"));
  }
  if (!visible && id === "sarif-preview-modal") sarifPreviewGeneration++;
  if (!visible && id === "npm-audit-preview-modal") clearNpmAuditPreview();
  if (!visible && id === "testssl-preview-modal") clearTestsslPreviewModal();
  // A dismissed lab detail must not accept a pending response that arrives later.
  if (!visible && id === "lab-detail-modal") activeLabDetailTicket = null;
  const existingIndex = modalStack.findIndex(entry => entry.modal === modal);
  if (visible) {
    if (existingIndex !== -1) return;
    const top = activeModal();
    const active = document.activeElement;
    // Ignore a stale launcher when focus has moved into a different direct dialog.
    const activeOverlay = active?.closest?.('.modal-backdrop,.drawer-backdrop,.workspace-backdrop');
    const trigger = visibleModalControl(lastModalTrigger) &&
      (!activeOverlay || modalContains(activeOverlay, lastModalTrigger)) &&
      (!top || modalContains(top, lastModalTrigger)) ? lastModalTrigger : null;
    const opener = trigger || (visibleModalControl(active) && (!top || modalContains(top, active)) ? active : null);
    lastModalTrigger = null;
    // A background workflow may not place an overlay behind the active one.
    if (top && !opener) return;
    if (!top) originalBodyOverflow = document.body.style.overflow || "";
    const entry = { modal, opener, previousZIndex: modal.style.zIndex, addedTabIndex: false };
    modalStack.push(entry);
    modal.classList.remove("hidden");
    modal.style.zIndex = String(50 + modalStack.length);
    syncModalInert();
    document.body.style.overflow = "hidden";
    focusModal(modal);
    return;
  }

  if (id === "semgrep-trivy-compare-modal") clearSemgrepTrivyCompare();
  if (id === "gitleaks-preview-modal" && (existingIndex !== -1 || !modal.classList.contains("hidden") || isGitleaksPreviewDirty())) {
    clearGitleaksPreview();
  }
  if (id === "openssl-x509-preview-modal" && (existingIndex !== -1 || !modal.classList.contains("hidden") || isOpensslX509PreviewDirty())) {
    clearOpensslX509Preview();
  }
  if (existingIndex !== -1) {
    // Closing an underlying workflow also closes overlays opened from it.
    while (modalStack.length - 1 > existingIndex) showModal(activeModal().id, false);
    const entry = modalStack.pop();
    modal.classList.add("hidden");
    modal.style.zIndex = entry.previousZIndex;
    if (entry.addedTabIndex) modal.removeAttribute("tabindex");
    syncModalInert();
    if (!modalStack.length) document.body.style.overflow = originalBodyOverflow;
    restoreModalFocus(entry);
  } else {
    modal.classList.add("hidden");
  }
  if (id === "sarif-preview-modal") {
    $("#sarif-paste").value = "";
    $("#sarif-file").value = "";
    $("#sarif-preview-result").classList.add("hidden");
    $("#sarif-preview-error").textContent = "";
    $("#sarif-preview-error").classList.add("hidden");
    $("#sarif-run-count").textContent = "";
    $("#sarif-result-count").textContent = "";
    $("#sarif-tool-names").textContent = "";
    $("#sarif-levels").textContent = "";
    $("#sarif-report-sha256").textContent = "";
  }
}

const NAVIGATION_DESTINATIONS = Object.freeze({
  dashboard: Object.freeze({ view: "dashboard", hash: "#dashboard", label: "Genel bakış" }),
  targets: Object.freeze({ view: "targets", hash: "#targets", label: "Hedefler" }),
  projects: Object.freeze({ view: "projects", hash: "#projects", label: "Uygulama analizi" }),
  tracking: Object.freeze({ view: "tracking", hash: "#tracking", label: "Bulgu takibi" }),
  portfolio: Object.freeze({ view: "portfolio", hash: "#portfolio", label: "Portföy ve SLA" }),
  pentest: Object.freeze({ view: "pentest", hash: "#pentest", label: "Manuel test" }),
  tooling: Object.freeze({ view: "tooling", hash: "#tooling", label: "Araç matrisi" }),
  lab: Object.freeze({ view: "lab", hash: "#lab", label: "Güvenlik laboratuvarı" }),
  reports: Object.freeze({ view: "reports", hash: "#reports", label: "Raporlar" }),
  audit: Object.freeze({ view: "audit", hash: "#audit", label: "İşlem geçmişi" }),
  schedules: Object.freeze({ view: "schedules", hash: "#schedules", label: "Zamanlanmış taramalar" }),
  notifications: Object.freeze({ view: "notifications", hash: "#notifications", label: "Bildirimler" }),
});

function navigationDestination(view) {
  switch (view) {
    case "targets": return NAVIGATION_DESTINATIONS.targets;
    case "projects": return NAVIGATION_DESTINATIONS.projects;
    case "tracking": return NAVIGATION_DESTINATIONS.tracking;
    case "portfolio": return NAVIGATION_DESTINATIONS.portfolio;
    case "pentest": return NAVIGATION_DESTINATIONS.pentest;
    case "tooling": return NAVIGATION_DESTINATIONS.tooling;
    case "lab": return NAVIGATION_DESTINATIONS.lab;
    case "reports": return NAVIGATION_DESTINATIONS.reports;
    case "audit": return NAVIGATION_DESTINATIONS.audit;
    case "schedules": return NAVIGATION_DESTINATIONS.schedules;
    case "notifications": return NAVIGATION_DESTINATIONS.notifications;
    default: return NAVIGATION_DESTINATIONS.dashboard;
  }
}

function navigate(view) {
  const destination = navigationDestination(view);
  view = destination.view;
  $$("[data-view]").forEach(node => node.classList.toggle("active", node.dataset.view === view));
  $$(".nav-item").forEach(node => node.classList.toggle("active", node.dataset.nav === view));
  $("#page-label").textContent = destination.label;
  if (location.hash !== destination.hash) history.replaceState(null, "", destination.hash);
  $(".sidebar").classList.remove("open");
  if (view === "audit") loadAudit();
  if (view === "tracking" && typeof globalThis.sniperLoadTracking === "function") globalThis.sniperLoadTracking();
  if (view === "portfolio" && typeof globalThis.sniperLoadPortfolio === "function") globalThis.sniperLoadPortfolio();
  if ((view === "schedules" || view === "notifications") && globalThis.SniperOps) globalThis.SniperOps.show(view);
}

async function loadAll() {
  try {
    const [dashboard, targets, scans, engagements, labRuns, projectAudits, tooling, toolingReadiness, dependencySecurity] = await Promise.all([api("/api/dashboard"), api("/api/targets"), api("/api/scans?limit=200"), api("/api/engagements"), api("/api/lab-runs"), api("/api/project-audits"), api("/api/tooling"), api("/api/tooling/readiness").catch(() => null), api("/api/dependency-security")]);
    state.dashboard = dashboard;
    state.targets = targets.targets;
    state.scans = scans.scans;
    syncFirstScanHistoryPage(scans);
    state.engagements = engagements.engagements;
    state.labRuns = labRuns.lab_runs;
    state.projectAudits = projectAudits.project_audits;
    state.projectAuditTotal = projectAudits.total;
    state.tooling = tooling;
    state.toolingReadiness = toolingReadiness;
    state.dependencySecurity = dependencySecurity;
    renderDashboard();
    renderTargets();
    renderScans();
    renderEngagements();
    renderTooling();
    renderLabRuns();
    renderProjectAudits();
    renderDependencySecurity();
  } catch (error) {
    toast(error.message, "error");
  }
}

function renderDashboard() {
  const data = state.dashboard || {};
  const average = Number(data.average_score || 0);
  $("#hero-score").innerHTML = `
    <div class="score-ring" data-style="--score:${esc(average)}"><span>${esc(average || "—")}</span><small>/100</small></div>
    <div><small>ORTALAMA GÜVENLİK PUANI</small><b>${average ? (average >= 75 ? "Sağlam bir temel" : average >= 50 ? "İyileştirme gerekiyor" : "Öncelikli riskler var") : "Henüz ölçüm yok"}</b></div>`;

  const metrics = [
    ["KAYITLI HEDEF", data.ready_count || 0, `${data.target_count || 0} toplam varlık`, "◎", "#087b54", "#e5f5ee"],
    ["MANUEL DENETİM", data.engagement_count || 0, `${state.engagements.length} toplam dosya`, "⌘", "#2f7088", "#e8f3f6"],
    ["YÜKSEK RİSK", (data.finding_counts?.critical || 0) + (data.finding_counts?.high || 0), `${data.manual_finding_count || 0} etkin · ${data.overdue_finding_count || 0} gecikmiş`, "!", "#c2414c", "#fbeaec"],
    ["TAMAMLANAN TARAMA", state.scans.filter(scan => scan.status === "completed").length, `${data.active_count || 0} etkin işlem`, "↻", "#b8750b", "#fff4dd"],
  ];
  $("#metric-grid").innerHTML = metrics.map(([label, value, note, icon, color, soft]) => `
    <article class="metric" data-style="--metric-color:${esc(color)};--metric-soft:${esc(soft)}"><div class="metric-top"><span>${esc(label)}</span><span class="metric-icon">${esc(icon)}</span></div><strong>${esc(value)}</strong><small>${esc(note)}</small></article>`).join("");

  const recent = state.targets.slice(0, 4);
  $("#recent-targets").classList.remove("loading-lines");
  $("#recent-targets").innerHTML = recent.length ? recent.map(target => `
    <div class="target-row"><div class="target-identity"><span class="favicon">${esc(target.hostname[0] || "W")}</span><span><b>${esc(target.hostname)}</b><small>${esc(target.url)}</small></span></div><span class="status-pill ${esc(target.status)}">${statusLabel(target.status)}</span><span class="score-chip ${target.latest_score == null ? "" : scoreClass(target.latest_score)}">${target.latest_score == null ? "—" : `${target.latest_score}/100`}</span></div>`).join("") : `<div class="empty-state"><div class="empty-icon">◎</div><h3>Henüz hedef yok</h3><p>İlk web varlığınızı ekleyerek başlayın.</p><button class="button primary" data-action="add-target">Yeni hedef</button></div>`;

  const counts = data.finding_counts || {};
  const rows = [["Kritik", counts.critical || 0, "#a82937"], ["Yüksek", counts.high || 0, "#c2414c"], ["Orta", counts.medium || 0, "#b8750b"], ["Düşük", counts.low || 0, "#2f7088"]];
  const max = Math.max(...rows.map(row => row[1]), 1);
  $("#risk-breakdown").innerHTML = rows.map(([label, value, color]) => `<div class="risk-item"><span>${esc(label)}</span><div class="risk-bar"><i data-style="--width:${esc((value / max) * 100)}%;--risk:${esc(color)}"></i></div><b>${esc(value)}</b></div>`).join("");
}

function renderTargets(filter = "") {
  const query = filter.toLowerCase().trim();
  const targets = state.targets.filter(target => `${target.hostname} ${target.url}`.toLowerCase().includes(query));
  $("#target-count-label").textContent = `${state.targets.length} hedef`;
  $("#target-empty").classList.toggle("hidden", state.targets.length > 0 || query.length > 0);
  $("#target-table").innerHTML = targets.map(target => {
    const trend = Number(target.scan_count || 0) > 0 ? `<button class="mini-button" data-action="trend" data-id="${target.id}">Trend</button>` : "";
    const action = `${trend}<button class="mini-button accent" data-action="scan" data-id="${target.id}">Tarama başlat</button><button class="mini-button accent" data-action="nmap-scan" data-id="${target.id}">Nmap TCP</button><button class="mini-button accent" data-action="open-nuclei-http-scan" data-id="${esc(target.id)}">Nuclei HTTP</button>`;
    return `<tr><td><div class="table-target"><span class="favicon">${esc(target.hostname[0] || "W")}</span><span><b>${esc(target.hostname)}</b><small>${esc(target.url)}</small></span></div></td><td><span class="status-pill ${esc(target.status)}">${statusLabel(target.status)}</span></td><td><span class="score-chip ${target.latest_score == null ? "" : scoreClass(target.latest_score)}">${target.latest_score == null ? "—" : `${target.latest_score}/100 · ${esc(target.latest_grade || "")}`}</span></td><td>${target.scan_count || 0}</td><td><div class="row-actions">${action}</div></td></tr>`;
  }).join("");
}

function projectCheckLabel(status) {
  return ({ pass: "Doğrulandı", review: "İnceleme gerekli", na: "Uygulanamaz" })[status] || status;
}

function renderProjectAudits() {
  const audits = state.projectAudits || [];
  const total = (state.projectAuditTotal !== undefined) ? state.projectAuditTotal : audits.length;
  $("#project-audit-count").textContent = `${total} yerel analiz`;
  $("#project-audit-empty").classList.toggle("hidden", audits.length > 0);
  $("#project-audit-list").innerHTML = audits.map(audit => `
    <button class="project-audit-row" data-action="open-project-audit" data-id="${esc(audit.id)}">
      <span class="project-grade ${scoreClass(Number(audit.score || 0))}">${esc(audit.grade)}</span>
      <span><b>${esc(audit.project_name)}</b><small>${esc(audit.project_path)} · ${Number(audit.file_count || 0)} dosya</small></span>
      <span><b>${Number(audit.score || 0)}/100</b><small>${Number(audit.finding_count || 0)} bulgu</small></span>
      <span>${formatDate(audit.created_at)}</span><i>›</i>
    </button>`).join("");

  const latest = audits[0];
  if (!latest) {
    $("#project-audit-summary").innerHTML = "";
    return;
  }
  const counts = latest.finding_counts || {};
  const metrics = [
    ["SON PUAN", `${Number(latest.score || 0)}/100`, `Seviye ${esc(latest.grade)}`],
    ["İNCELENEN DOSYA", Number(latest.file_count || 0), Object.keys(latest.languages || {}).join(", ") || "Kaynak kod"],
    ["YÜKSEK RİSK", Number(counts.critical || 0) + Number(counts.high || 0), "Kritik + yüksek"],
    ["TOPLAM BULGU", Number(latest.finding_count || 0), "Statik ön inceleme"],
  ];
  $("#project-audit-summary").innerHTML = metrics.map(([label, value, note]) => `<article><small>${esc(label)}</small><b>${esc(value)}</b><span>${esc(note)}</span></article>`).join("");
}

// 20. tur: kötü amaçlı paket (OpenSSF MAL- / GitHub malware) bağımlılık bulgusu; veritabanında ayrı sütun yok
function isMaliciousDependency(item) {
  return String(item.vulnerability_id || "").startsWith("MAL-") || String(item.title || "").startsWith("Kötü amaçlı paket:");
}

function filterDependencyFindings(findings) {
  const query = String($("#dependency-filter-query")?.value ?? state.dependencyQuery ?? "").trim().toLowerCase();
  const source = String($("#dependency-filter-source")?.value ?? state.dependencySourceFilter ?? "all").toLowerCase();
  const severity = String($("#dependency-filter-severity")?.value ?? state.dependencySeverityFilter ?? "all").toLowerCase();
  const status = String($("#dependency-filter-status")?.value ?? state.dependencyStatusFilter ?? "all").toLowerCase();
  return findings.filter(item => {
    if (source !== "all" && String(item.source || "").toLowerCase() !== source) return false;
    if (severity !== "all" && String(item.severity || "").toLowerCase() !== severity) return false;
    if (status !== "all" && String(item.status || "").toLowerCase() !== status) return false;
    if (query) {
      const haystack = `${item.vulnerability_id || ""} ${item.package_name || ""} ${item.installed_version || ""} ${item.title || ""} ${item.project_path || ""}`.toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
}

async function refreshDependencyFindings({ resetOffset = false } = {}) {
  if (resetOffset) state.dependencyPageOffset = 0;
  const requestSeq = ++state.dependencyRequestSeq;
  const params = new URLSearchParams({
    limit: String(state.dependencyPageLimit),
    offset: String(state.dependencyPageOffset),
    query: String($("#dependency-filter-query")?.value || "").trim(),
    source: String($("#dependency-filter-source")?.value || "all"),
    severity: String($("#dependency-filter-severity")?.value || "all"),
    status: String($("#dependency-filter-status")?.value || "all"),
  });
  const data = await api(`/api/dependency-security?${params}`);
  if (requestSeq !== state.dependencyRequestSeq) return null;
  state.dependencySecurity = data;
  renderDependencySecurity();
  return data;
}

function renderDependencyFindingDetail(finding, feedbackMessage = "") {
  const panel = $("#dependency-finding-detail");
  if (!panel) return;
  if (!finding) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }
  const refs = (Array.isArray(finding.references) ? finding.references : [])
    .filter(ref => typeof ref === "string" && /^https?:\/\//i.test(ref))
    .slice(0, 5);
  panel.classList.remove("hidden");
  panel.innerHTML = `
    <div class="panel-head">
      <div>
        <p class="eyebrow">${esc(String(finding.source || "").toUpperCase())} · ${esc(finding.id)}</p>
        <h3>${esc(finding.vulnerability_id)} · ${esc(finding.package_name)} ${esc(finding.installed_version || "")}</h3>
        <small>${esc(finding.project_path || "")}${finding.target ? ` · ${esc(finding.target)}` : ""}</small>
      </div>
      <span class="status-pill ${esc(finding.status)}">${esc(statusLabel(finding.status))}</span>
    </div>
    <p><b>${esc(finding.title || "Başlık yok")}</b></p>
    <p>${esc(finding.summary || "Ayrıntılı açıklama bulunmuyor.")}</p>
    <small>Düzeltme sürümü: <b>${esc(finding.fixed_version || "Bilinmiyor")}</b> · İlk görülme: ${formatDate(finding.first_seen_at)} · Son görülme: ${formatDate(finding.last_seen_at)}</small>
    ${refs.length ? `<div class="dependency-refs">${refs.map(url => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>`).join(" · ")}</div>` : ""}
    <form id="dependency-finding-detail-form" class="form-grid" data-id="${esc(finding.id)}">
      <label>Durum
        <select name="status">
          <option value="open" ${finding.status === "open" ? "selected" : ""}>Açık</option>
          <option value="in_progress" ${finding.status === "in_progress" ? "selected" : ""}>Üzerinde çalışılıyor</option>
          <option value="retest_required" ${finding.status === "retest_required" ? "selected" : ""}>Yeniden test</option>
          <option value="resolved" ${finding.status === "resolved" ? "selected" : ""}>Çözüldü</option>
          <option value="reopened" ${finding.status === "reopened" ? "selected" : ""}>Yeniden açıldı</option>
          <option value="risk_accepted" ${finding.status === "risk_accepted" ? "selected" : ""}>Risk kabulü</option>
        </select>
      </label>
      <label class="full">Çözüm / değerlendirme notu
        <textarea name="resolution_notes" rows="3" maxlength="4000" placeholder="Yama sürümü, telafi edici kontrol veya doğrulama notu…">${esc(finding.resolution_notes || "")}</textarea>
      </label>
      <button class="button primary" type="submit">Durumu ve notu kaydet</button>
      <p id="dependency-finding-feedback" class="muted ${feedbackMessage ? "" : "hidden"}" role="status">${esc(feedbackMessage)}</p>
    </form>`;
}

function openDependencyFindingDetail(findingId, feedbackMessage = "") {
  const findings = state.dependencySecurity?.findings || [];
  const finding = findings.find(item => item.id === findingId) || null;
  state.selectedDependencyFindingId = finding ? finding.id : null;
  renderDependencyFindingDetail(finding, feedbackMessage);
}

function renderDependencySecurity() {
  const data = state.dependencySecurity || { summary: {}, findings: [], imports: [], sboms: [] };
  const summary = data.summary || {};
  const findings = data.findings || [];
  const filtered = filterDependencyFindings(findings);
  const reportSample = Array.isArray(data.report_findings) ? data.report_findings : findings;
  const active = reportSample.filter(item => item && activeFindingStatuses.has(item.status));
  const summaryHtml = [
    ["ETKİN BULGU", summary.active || 0], ["KRİTİK", summary.critical || 0],
    ["YÜKSEK", summary.high || 0], ["ESKİ VERİ KAYNAĞI", summary.stale_sources || 0],
  ].map(([label, value]) => `<article><small>${label}</small><b>${Number(value)}</b></article>`).join("");
  $("#dependency-summary").innerHTML = summaryHtml; // sniper-reviewed: html-safe
  $("#dependency-report-summary").innerHTML = summaryHtml; // sniper-reviewed: html-safe
  const countEl = $("#dependency-filter-count");
  const total = Number(summary.total ?? findings.length);
  const page = data.page || { offset: 0, limit: findings.length, filtered_total: findings.length, has_more: false };
  const matchingTotal = Number(page.filtered_total ?? findings.length);
  if (countEl) countEl.textContent = matchingTotal < total
    ? `${matchingTotal} eşleşme / ${total} bulgu`
    : `${filtered.length} / ${total} bulgu`;
  $("#dependency-empty").classList.toggle("hidden", total > 0);
  const noResults = $("#dependency-no-results");
  if (noResults) noResults.classList.toggle("hidden", total === 0 || filtered.length > 0);
  const prev = $("#dependency-page-prev");
  const next = $("#dependency-page-next");
  const pageLabel = $("#dependency-page-label");
  if (prev) prev.disabled = Number(page.offset || 0) === 0;
  if (next) next.disabled = !page.has_more;
  if (pageLabel) pageLabel.textContent = matchingTotal
    ? `${Math.min(Number(page.offset || 0) + 1, matchingTotal)}–${Math.min(Number(page.offset || 0) + findings.length, matchingTotal)} / ${matchingTotal} eşleşme`
    : "0 eşleşme";
  $("#dependency-sources").innerHTML = (data.imports || []).slice(0, 4).map(item => `<span class="${item.stale ? "stale" : "fresh"}"><b>${esc(item.source.toUpperCase())}</b> ${item.stale ? `Veri ${item.age_days ?? "?"} günlük` : "Güncel"} · ${formatDate(item.source_timestamp)} · ${Number(item.finding_count)} bulgu</span>`).join("") + (data.sboms || []).slice(0, 3).map(item => `<a href="/api/dependency-sboms/${encodeURIComponent(item.id)}" download><b>SBOM</b> ${esc(item.project_name)} · ${Number(item.component_count)} bileşen</a>`).join("");
  renderDependencySbomDeltaChoices(data.sboms || []);
  $("#dependency-findings").innerHTML = filtered.map(item => `<tr><td><b>${esc(item.vulnerability_id)}</b>${isMaliciousDependency(item) ? ` <span class="severity-label critical">KÖTÜ AMAÇLI</span>` : ""}<small>${esc(item.title || "")}</small></td><td><b>${esc(item.package_name)}</b><small>${esc(item.installed_version || "sürüm yok")}</small></td><td><span class="severity-label ${esc(item.severity)}">${esc(severityLabel(item.severity).toUpperCase())}</span></td><td>${esc(item.fixed_version || "Bilinmiyor")}</td><td>${esc(item.source.toUpperCase())}<small>${formatDate(item.source_timestamp)}</small></td><td><div class="row-actions"><select data-dependency-status data-id="${esc(item.id)}"><option value="open" ${item.status === "open" ? "selected" : ""}>Açık</option><option value="in_progress" ${item.status === "in_progress" ? "selected" : ""}>Üzerinde çalışılıyor</option><option value="retest_required" ${item.status === "retest_required" ? "selected" : ""}>Yeniden test</option><option value="resolved" ${item.status === "resolved" ? "selected" : ""}>Çözüldü</option><option value="reopened" ${item.status === "reopened" ? "selected" : ""}>Yeniden açıldı</option><option value="risk_accepted" ${item.status === "risk_accepted" ? "selected" : ""}>Risk kabulü</option></select><button class="mini-button" type="button" data-action="inspect-dependency-finding" data-id="${esc(item.id)}">Ayrıntı</button></div></td></tr>`).join("");
  const activeCount = Math.max(0, Number(summary.active) || 0);
  $("#dependency-report-findings").innerHTML = active.slice(0, 10).map(item => `<article><span class="severity-label ${esc(item.severity)}">${esc(severityLabel(item.severity).toUpperCase())}</span><p><b>${esc(item.vulnerability_id)} · ${esc(item.package_name)} ${esc(item.installed_version)}</b><small>${esc(item.title)} · Düzeltme: ${esc(item.fixed_version || "bilinmiyor")}</small></p><span class="status-pill ${esc(item.status)}">${esc(statusLabel(item.status))}</span></article>`).join("") || (activeCount > 0
    ? `<div class="empty-state"><h3>Etkin bulgu önizlemesi gösterilemiyor</h3><p>Toplam ${activeCount} etkin bağımlılık bulgusu var. Listeyi filtreleyerek inceleyin.</p></div>`
    : `<div class="empty-state"><div class="empty-icon">${uiSymbol("check")}</div><h3>Etkin bağımlılık bulgusu yok</h3></div>`);
  if (state.selectedDependencyFindingId) {
    openDependencyFindingDetail(state.selectedDependencyFindingId);
  }
}

document.addEventListener("input", event => {
  if (event.target?.id === "dependency-filter-query") {
    state.dependencyQuery = event.target.value;
    refreshDependencyFindings({ resetOffset: true }).catch(error => toast(error.message, "error"));
  }
});

document.addEventListener("change", event => {
  if (["dependency-filter-source", "dependency-filter-severity", "dependency-filter-status"].includes(event.target?.id)) {
    state.dependencySourceFilter = $("#dependency-filter-source")?.value || "all";
    state.dependencySeverityFilter = $("#dependency-filter-severity")?.value || "all";
    state.dependencyStatusFilter = $("#dependency-filter-status")?.value || "all";
    refreshDependencyFindings({ resetOffset: true }).catch(error => toast(error.message, "error"));
  }
});

document.addEventListener("click", event => {
  const direction = event.target?.id === "dependency-page-next" ? 1
    : event.target?.id === "dependency-page-prev" ? -1 : 0;
  if (!direction) return;
  const page = state.dependencySecurity?.page || {};
  if ((direction > 0 && !page.has_more) || (direction < 0 && !page.offset)) return;
  state.dependencyPageOffset = Math.max(0, Number(page.offset || 0) + direction * Number(page.limit || state.dependencyPageLimit));
  refreshDependencyFindings().catch(error => toast(error.message, "error"));
});

document.addEventListener("click", event => {
  const btn = event.target.closest?.('[data-action="inspect-dependency-finding"]');
  if (btn) {
    event.preventDefault();
    openDependencyFindingDetail(btn.dataset.id || "");
  }
});

document.addEventListener("submit", async event => {
  if (event.target?.id !== "dependency-finding-detail-form") return;
  event.preventDefault();
  const form = event.target;
  const findingId = form.dataset.id || "";
  const status = form.querySelector('[name="status"]')?.value || "";
  const resolutionNotes = String(form.querySelector('[name="resolution_notes"]')?.value || "");
  const submitBtn = form.querySelector('button[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;
  try {
    const updated = await api(`/api/dependency-findings/${encodeURIComponent(findingId)}/update`, {
      method: "POST",
      body: JSON.stringify({ status, resolution_notes: resolutionNotes }),
    });
    state.selectedDependencyFindingId = findingId;
    if (state.dependencySecurity) {
      state.dependencySecurity.findings = (state.dependencySecurity.findings || []).map(item => item.id === findingId ? updated : item);
      renderDependencySecurity();
    }
    renderDependencyFindingDetail(updated, "Durum ve çözüm notu güncellendi.");
    try {
      await refreshDependencyFindings();
      renderDependencyFindingDetail(updated, "Durum ve çözüm notu güncellendi.");
      toast("Bağımlılık bulgusu güncellendi.");
    } catch (refreshError) {
      renderDependencyFindingDetail(updated, "Değişiklik kaydedildi; liste yenilenemedi.");
      toast("Bulgu kaydedildi; liste yenilenemedi.", "error");
    }
  } catch (error) {
    toast(error.message, "error");
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
});

function renderDependencySbomDeltaChoices(sboms) {
  const projectCounts = new Map();
  for (const item of sboms) {
    if (typeof item?.id !== "string" || typeof item.project_path !== "string") continue;
    projectCounts.set(item.project_path, (projectCounts.get(item.project_path) || 0) + 1);
  }
  const comparable = sboms.filter(item => item && projectCounts.get(item.project_path) >= 2);
  const options = comparable.map(item => `<option value="${esc(item.id)}">${esc(item.project_name || item.project_path)} · ${formatDate(item.created_at)}</option>`).join("");
  $("#sbom-delta-before").innerHTML = `<option value="">Önceki kaydı seçin</option>${options}`; // sniper-reviewed: html-safe
  $("#sbom-delta-after").innerHTML = `<option value="">Sonraki kaydı seçin</option>${options}`; // sniper-reviewed: html-safe
  $("#sbom-delta-before").value = "";
  $("#sbom-delta-after").value = "";
  $("#sbom-delta-submit").disabled = comparable.length < 2;
  $("#sbom-delta-availability").textContent = comparable.length < 2
    ? "Karşılaştırma için aynı projeye ait en az iki kayıtlı SBOM gerekli."
    : "İki farklı kayıt seçip karşılaştırmayı başlatın.";
  $("#sbom-delta-result").classList.add("hidden");
  $("#sbom-delta-error").classList.add("hidden");
}

function changedScanSummary(audit) {
  const cs = audit.changed_scan;
  if (!cs || typeof cs !== "object") return "";
  const base = cs.mode === "audit" ? `kayıtlı analiz ${esc(cs.base_ref)}` : `${esc(cs.base_ref)} (${esc(String(cs.base_commit || "").slice(0, 7))})`;
  const files = cs.mode === "git" ? ` · ${Number(cs.added_count || 0)} yeni, ${Number(cs.modified_count || 0)} değişen, ${Number(cs.deleted_count || 0)} silinen dosya` : "";
  const fixed = (cs.fixed || []).map(item => `<p>• Düzeldi: ${esc(item.title)} <code>${esc(item.file || "")}${item.line ? `:${Number(item.line)}` : ""}</code></p>`).join("");
  return `<div class="project-limitations changed-scan-summary"><p><strong>Yalnız değişenler:</strong> taban ${base}${files} · <b>${Number(cs.new_findings || 0)} yeni bulgu</b> · ${Number(cs.fixed_count || 0)} düzelen</p>${fixed}</div>`;
}

$("#project-scan-mode")?.addEventListener("change", event => {
  $("#changed-base-label")?.classList.toggle("hidden", event.target.value !== "changed");
});

function hasSkippedFiles(audit) {
  if (audit.scope?.skipped_only) return false;
  const skipped = audit.skipped_files || {};
  return Object.keys(skipped).some(key => !key.endsWith("_bytes") && !["already_scanned", "decoded_lossy"].includes(key) && !key.startsWith("included_dir_") && Number(skipped[key]) > 0);
}

function rescanProject(mode, projectPath, baseAuditId = "") {
  const form = $("#project-audit-form");
  if (!form) return;
  $("#project-path").value = projectPath;
  form.elements.scan_mode.value = mode;
  if (baseAuditId) form.dataset.baseAuditId = baseAuditId; else delete form.dataset.baseAuditId;
  form.requestSubmit();
}

const SCAN_SCOPE_DEFAULTS = { include_dirs: [], include_generated: false, include_non_utf8: false, max_file_mb: 1, max_total_mb: 150, max_files: 10000 };

function scanScopeFromForm(form) {
  const data = new FormData(form);
  return {
    include_dirs: data.getAll("include_dirs"),
    include_generated: data.get("include_generated") === "on",
    include_non_utf8: data.get("include_non_utf8") === "on",
    max_file_mb: Number(data.get("max_file_mb")),
    max_total_mb: Number(data.get("max_total_mb")),
    max_files: Number(data.get("max_files")),
  };
}

function fillScanScopeForm(scope) {
  const form = $("#scan-scope-form");
  if (!form) return;
  const value = { ...SCAN_SCOPE_DEFAULTS, ...(scope || {}) };
  for (const box of form.querySelectorAll('input[name="include_dirs"]')) box.checked = value.include_dirs.includes(box.value);
  form.elements.include_generated.checked = Boolean(value.include_generated);
  form.elements.include_non_utf8.checked = Boolean(value.include_non_utf8);
  for (const name of ["max_file_mb", "max_total_mb", "max_files"]) {
    const select = form.elements[name];
    if (![...select.options].some(option => Number(option.value) === Number(value[name]))) select.add(new Option(String(value[name]), String(value[name])));
    select.value = String(value[name]);
  }
}

function renderScanScopeBadge(scope, isDefault) {
  const badge = $("#scan-scope-badge");
  if (!badge) return;
  const extras = (scope?.include_dirs || []).length + (scope?.include_generated ? 1 : 0) + (scope?.include_non_utf8 ? 1 : 0);
  badge.textContent = isDefault ? "varsayılan" : `genişletilmiş · ${extras} grup · ${scope.max_file_mb} MB / ${scope.max_total_mb} MB`;
  badge.classList.toggle("active", !isDefault);
}

async function loadScanScope() {
  try {
    const data = await api("/api/scan-scope");
    SCAN_SCOPE_DEFAULTS.max_total_mb = data.defaults?.max_total_mb ?? SCAN_SCOPE_DEFAULTS.max_total_mb;
    SCAN_SCOPE_DEFAULTS.max_files = data.defaults?.max_files ?? SCAN_SCOPE_DEFAULTS.max_files;
    fillScanScopeForm(data.scope);
    renderScanScopeBadge(data.scope, data.is_default);
  } catch (error) { /* eski sunucu: panel varsayılanla kalır */ }
}

$("#scan-scope-form")?.addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true;
  try {
    const data = await api("/api/scan-scope", { method: "POST", body: JSON.stringify({ confirm: true, scope: scanScopeFromForm(event.currentTarget) }) });
    fillScanScopeForm(data.scope);
    renderScanScopeBadge(data.scope, data.is_default);
    toast(data.is_default ? "Tarama kapsamı varsayılana döndü." : "Tarama kapsamı kaydedildi; proje yolu alan tüm yerel taramalara uygulanacak.");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; }
});

$("#scan-scope-form")?.addEventListener("click", event => {
  const preset = event.target.closest("[data-scope-preset]")?.dataset.scopePreset;
  if (!preset) return;
  fillScanScopeForm(preset === "all"
    ? { include_dirs: ["tests", "vendor", "packages", "build"], include_generated: true, include_non_utf8: true, max_file_mb: 20, max_total_mb: 1000, max_files: 50000 }
    : SCAN_SCOPE_DEFAULTS);
});

$("#project-audit-detail")?.addEventListener("click", event => {
  const button = event.target.closest("[data-rescan-mode]");
  if (!button) return;
  rescanProject(button.dataset.rescanMode, button.dataset.rescanPath, button.dataset.rescanBase || "");
});

loadScanScope();

async function openProjectAudit(auditId) {
  try {
    const audit = await api(`/api/project-audits/${encodeURIComponent(auditId)}`);
    const counts = audit.finding_counts || {};
    const checks = (audit.checks || []).map(check => `<div class="project-check ${esc(check.status)}"><span>${check.status === "pass" ? "✓" : check.status === "review" ? "!" : "—"}</span><p><b>${esc(check.label)}</b><small>${esc(projectCheckLabel(check.status))}</small></p></div>`).join("");
    const autofixable = finding => Boolean(finding.taint_flow) || /CWE-(89|78|95|94|79|22|918|502|601|90|643|611|501|117|1333|614|330|338)\b/.test(String(finding.reference || ""));
    const findings = (audit.findings || []).map((finding, index) => `<article class="project-finding ${esc(finding.severity)}"><span></span><div><div class="project-finding-head"><b>${finding.is_new === true ? `<span class="finding-new-badge">YENİ</span> ` : ""}${finding.privileged === true ? `<span class="finding-privileged-badge" title="Akış yetki/nonce denetimli yöntemde; doğrulanmış akış sayılmaz">YÖNETİCİ YETKİSİ</span> ` : ""}${esc(finding.title)}</b><em>${esc(severityLabel(finding.severity))}</em></div>${typeof globalThis.sniperTrackingBadge === "function" ? globalThis.sniperTrackingBadge(finding) : ""}<p>${esc(finding.evidence)}</p><small><code>${esc(finding.file)}${finding.line ? `:${Number(finding.line)}` : ""}</code> · ${esc(finding.reference)}</small><p class="project-recommendation"><strong>Öneri:</strong> ${esc(finding.recommendation)}</p>${finding.confidence?.note ? `<small class="finding-confidence">Güven: ${esc(finding.confidence.note)}</small>` : ""}${autofixable(finding) ? `<div class="row-actions"><button type="button" class="mini-button" data-autofix-audit="${esc(audit.id)}" data-autofix-index="${Number(index)}">Düzeltme öner</button><button type="button" class="mini-button accent" data-autofix-verify-audit="${esc(audit.id)}" data-autofix-verify="${Number(index)}">Doğrulanmış düzeltme</button><span class="autofix-badge hidden" data-autofix-badge="${Number(index)}"></span></div><div class="autofix-result hidden" data-autofix-result="${Number(index)}"></div>` : ""}</div></article>`).join("");
    $("#project-audit-detail").classList.remove("hidden");
    $("#project-audit-detail").innerHTML = `
      <div class="project-detail-head"><div><p class="eyebrow">${esc(audit.id)}</p><h2>${esc(audit.project_name)}</h2><small>${esc(audit.project_path)} · ${formatDate(audit.created_at)}</small></div><div class="project-score"><b>${Number(audit.score || 0)}</b><span>/100 · ${esc(audit.grade)}</span></div></div>
      <div class="report-actions" data-style="margin-bottom:14px"><a class="button secondary" href="/api/project-audits/${encodeURIComponent(audit.id)}/report.html" target="_blank" rel="noopener">HTML Rapor</a><a class="button secondary" href="/api/project-audits/${encodeURIComponent(audit.id)}/report.sarif?download=1" download>SARIF 2.1.0 İndir</a><a class="button secondary" href="/api/project-audits/${encodeURIComponent(audit.id)}/compliance-matrix" target="_blank" rel="noopener">Uyumluluk Matrisi (PCI/ISO/ASVS/KVKK)</a><a class="button secondary" href="/api/project-audits/${encodeURIComponent(audit.id)}/executive-summary.html" target="_blank" rel="noopener">Yönetici özeti</a><a class="button secondary" href="/api/project-audits/${encodeURIComponent(audit.id)}/report.html?format=pdf" download>PDF rapor</a><a class="button secondary" href="/api/project-audits/${encodeURIComponent(audit.id)}/executive-summary.html?format=pdf" download>Yönetici özeti PDF</a></div>
      <div class="autofix-bulk-launch"><button type="button" class="mini-button" data-autofix-groups="${esc(audit.id)}">Benzer bulguları toplu düzelt</button><div class="autofix-bulk hidden" data-autofix-groups-result="${esc(audit.id)}"></div></div>
      ${audit.tracking ? `<div class="project-limitations"><p><strong>Bulgu takibi:</strong> ${Number(audit.tracking.new_count)} yeni · ${Number(audit.tracking.seen_count)} önceden görülen · ${Number(audit.tracking.fixed_count)} düzelen · ${Number(audit.tracking.reopened_count)} yeniden açılan${audit.tracking.not_rescanned_count ? ` · ${Number(audit.tracking.not_rescanned_count)} kapsam dışı kaldığı için doğrulanamayan` : ""}${audit.tracking.mode === "supplement" ? " (ek tarama: hiçbir bulguyu düzeldi saymaz)" : ""}.</p></div>` : ""}
      <div class="project-check-grid">${checks}</div>
      ${changedScanSummary(audit)}
      ${audit.base_audit_id ? `<div class="project-limitations"><p><strong>Ek tarama:</strong> normal taramanın atladığı dosyalar incelendi. <button type="button" class="mini-button" data-action="open-project-audit" data-id="${esc(audit.base_audit_id)}">Temel analizi aç</button></p></div>` : ""}
      ${(audit.warnings || []).length ? `<div class="project-limitations"><p><strong>Uyarı:</strong> ${audit.scope?.skipped_only ? "Kapsam bilgisi" : "Proje sınırları nedeniyle bazı dosyalar atlandı (proje reddedilmedi)."}</p>${audit.warnings.map(item => `<p>• ${esc(item)}</p>`).join("")}${hasSkippedFiles(audit) ? `<div class="button-row"><button type="button" class="mini-button accent" data-rescan-mode="skipped" data-rescan-path="${esc(audit.project_path)}" data-rescan-base="${esc(audit.id)}">Yalnız atlananları tara</button><button type="button" class="mini-button" data-rescan-mode="all" data-rescan-path="${esc(audit.project_path)}">Tümünü dahil ederek baştan tara</button></div>` : ""}</div>` : ""}
      <div class="project-finding-summary"><b>${(audit.findings || []).length} doğrulanabilir sinyal</b><span>${Number(counts.critical || 0)} kritik · ${Number(counts.high || 0)} yüksek · ${Number(counts.medium || 0)} orta · ${Number(counts.low || 0)} düşük</span></div>
      <div class="project-findings">${findings || `<div class="empty-state"><div class="empty-icon">${uiSymbol("check")}</div><h3>Statik kural bulgusu yok</h3><p>Bu sonuç dinamik ve manuel test gereksinimini ortadan kaldırmaz.</p></div>`}</div>
      <div class="project-limitations">${(audit.limitations || []).map(item => `<p>• ${esc(item)}</p>`).join("")}</div>`;
    if (typeof window.renderRouteInventory === "function") window.renderRouteInventory(audit, $("#project-audit-detail"));
    globalThis.renderThreatModel?.(audit);
    globalThis.renderLicenseSummary?.(audit, $("#project-audit-detail"));
    $("#project-audit-detail").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    toast(error.message, "error");
  }
}

function syncFirstScanHistoryPage(response) {
  const page = state.reportHistory;
  state.scans = Array.isArray(response?.scans) ? response.scans : [];
  if (page.offset !== 0 || page.previousOffsets.length > 0 || page.loading) return;
  page.generation += 1;
  page.scans = state.scans;
  page.anchor = Number.isSafeInteger(response?.anchor) ? response.anchor : null;
  page.hasMore = response?.has_more === true;
  page.nextOffset = Number.isSafeInteger(response?.next_offset) ? response.next_offset : null;
  page.initialized = true;
  page.error = "";
}

async function loadScanHistoryPage(direction) {
  const page = state.reportHistory;
  if (page.loading) return;
  let targetOffset = null;
  let nextHistory = page.previousOffsets;
  if (direction === "next") {
    if (!page.hasMore || !Number.isSafeInteger(page.nextOffset)) return;
    targetOffset = page.nextOffset;
    nextHistory = [...page.previousOffsets, page.offset];
  } else if (direction === "prev") {
    if (!page.previousOffsets.length) return;
    targetOffset = page.previousOffsets[page.previousOffsets.length - 1];
    nextHistory = page.previousOffsets.slice(0, -1);
  } else {
    return;
  }
  const requestGeneration = page.generation + 1;
  page.generation = requestGeneration;
  page.loading = true;
  page.pendingDirection = direction;
  page.error = "";
  renderScans();
  try {
    const params = new URLSearchParams({ limit: "200", offset: String(targetOffset) });
    if (targetOffset > 0 && Number.isSafeInteger(page.anchor)) params.set("anchor", String(page.anchor));
    const response = await api(`/api/scans?${params.toString()}`);
    if (page.generation !== requestGeneration) return;
    const scans = Array.isArray(response.scans) ? response.scans : [];
    page.offset = targetOffset;
    page.previousOffsets = nextHistory;
    page.scans = scans;
    if (targetOffset === 0 || !Number.isSafeInteger(page.anchor)) {
      page.anchor = Number.isSafeInteger(response.anchor) ? response.anchor : null;
    }
    page.hasMore = response.has_more === true;
    page.nextOffset = Number.isSafeInteger(response.next_offset) ? response.next_offset : null;
    page.initialized = true;
    if (targetOffset === 0) state.scans = scans;
  } catch (error) {
    if (page.generation !== requestGeneration) return;
    page.error = error.message || "Rapor geçmişi sayfası yüklenemedi.";
    toast(page.error, "error");
  } finally {
    if (page.generation === requestGeneration) {
      page.loading = false;
      page.pendingDirection = null;
      renderScans();
    }
  }
}

function renderScans() {
  const page = state.reportHistory;
  const scans = page.initialized ? page.scans : state.scans;
  const comparableIds = new Set(state.scans.map(scan => scan.id));
  const pageNumber = page.previousOffsets.length + 1;
  const prevBtn = $("#scan-page-prev");
  const nextBtn = $("#scan-page-next");
  const pageLabel = $("#scan-page-label");
  const pageStatus = $("#scan-page-status");
  const pageError = $("#scan-page-error");
  const compareNote = $("#scan-page-compare-note");
  if (pageLabel) pageLabel.textContent = `Sayfa ${pageNumber}`;
  if (prevBtn) prevBtn.disabled = page.loading || page.previousOffsets.length === 0;
  if (nextBtn) nextBtn.disabled = page.loading || !page.hasMore || !Number.isSafeInteger(page.nextOffset);
  if (prevBtn) prevBtn.textContent = page.loading && page.pendingDirection === "prev" ? "Önceki yükleniyor…" : "Önceki";
  if (nextBtn) nextBtn.textContent = page.loading && page.pendingDirection === "next" ? "Sonraki yükleniyor…" : "Sonraki";
  if (pageStatus) pageStatus.textContent = page.loading ? "Sayfa yükleniyor…" : "";
  if (pageError) {
    pageError.textContent = page.error;
    pageError.classList.toggle("hidden", !page.error);
  }
  if (compareNote) compareNote.classList.toggle("hidden", page.offset === 0);
  $("#scan-empty").classList.toggle("hidden", scans.length > 0);
  $("#scan-table").innerHTML = scans.map(scan => {
    const comparison = scan.comparison;
    const change = !comparison ? "—" : comparison.baseline ? `<span class="change-chip baseline">İlk ölçüm</span>` : `<span class="change-chip new">+${comparison.new_count}</span><span class="change-chip resolved">−${comparison.resolved_count}</span>`;
    const canCompare = scan.status === "completed" && (page.offset === 0 || comparableIds.has(scan.id));
    return `<tr>
    <td><div class="table-target"><span class="favicon">${esc(scan.target_hostname?.[0] || "W")}</span><span><b>${esc(scan.target_hostname)}</b><small>${esc(scan.id)}</small></span></div></td>
    <td>${formatDate(scan.created_at)}</td><td><span class="status-pill ${esc(scan.status)}">${statusLabel(scan.status)}</span></td>
    <td><span class="score-chip ${scan.score == null ? "" : scoreClass(scan.score)}">${scan.score == null ? "—" : `${scan.score}/100 · ${esc(scan.grade)}`}</span></td><td>${scan.finding_count ?? "—"}</td>
    <td><div class="change-chips">${change}</div></td><td><div class="row-actions"><button class="mini-button" data-action="report" data-id="${esc(scan.id)}">İncele</button>${canCompare ? `<button class="mini-button accent" data-action="compare-scan" data-id="${esc(scan.id)}">Karşılaştır</button>` : ""}${scan.status === "completed" ? `<a class="mini-button accent" href="/api/scans/${encodeURIComponent(scan.id)}/report.html?download=1" download>HTML indir</a>` : ""}</div></td></tr>`;
  }).join("");
}

function renderEngagements() {
  $("#engagement-empty").classList.toggle("hidden", state.engagements.length > 0);
  $("#engagement-grid").innerHTML = state.engagements.map(engagement => `
    <article class="engagement-card" data-action="open-engagement" data-id="${esc(engagement.id)}">
      <div class="engagement-card-head"><div><p class="eyebrow">${esc(engagement.authorization_ref || "YEREL DENETİM")}</p><h3>${esc(engagement.name)}</h3><div class="target-url">${esc(engagement.target_url)}</div></div><span class="status-pill ${esc(engagement.status)}">${statusLabel(engagement.status)}</span></div>
      <div class="coverage-line"><div class="risk-bar"><i data-style="--width:${Number(engagement.coverage_percent || 0)}%;--risk:#087b54"></i></div><b>${Number(engagement.coverage_percent || 0)}% manuel</b></div>
      <div class="engagement-meta"><span>MANUEL KAPSAM<b>${Number(engagement.completed_test_count || 0)} / ${Number(engagement.test_count || 0)}</b></span><span>MANUEL BULGU<b>${Number(engagement.finding_count || 0)}</b></span><span>GECİKEN<b>${Number(engagement.overdue_finding_count || 0)}</b></span><span>YENİDEN TEST<b>${Number(engagement.retest_finding_count || 0)}</b></span></div>
    </article>`).join("");
}

document.addEventListener("submit", async event => {
  if (event.target.id !== "sarif-preview-form") return;
  event.preventDefault();
  const generation = ++sarifPreviewGeneration;
  const isCurrentSarifPreview = () => generation === sarifPreviewGeneration;

  const pasteInput = document.getElementById("sarif-paste");
  const fileInput = document.getElementById("sarif-file");
  const errorEl = document.getElementById("sarif-preview-error");
  const resultEl = document.getElementById("sarif-preview-result");

  // Clear previous state
  errorEl.textContent = "";
  errorEl.classList.add("hidden");
  resultEl.classList.add("hidden");

  let rawContent = pasteInput.value.trim();

  // If paste is empty, try file
  if (!rawContent) {
    const file = fileInput.files[0];
    if (file) {
      if (file.size > 65536) {
        errorEl.textContent = "Girdi çok büyük (maksimum 64 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      try {
        rawContent = await file.text();
        if (!isCurrentSarifPreview()) return;
      } catch {
        if (!isCurrentSarifPreview()) return;
        errorEl.textContent = "Dosya okunamadı.";
        errorEl.classList.remove("hidden");
        return;
      }
    } else {
      errorEl.textContent = "Boş içerik gönderilemez.";
      errorEl.classList.remove("hidden");
      return;
    }
  }

  // Validate JSON
  let sarifObj;
  try {
    sarifObj = JSON.parse(rawContent);
  } catch {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  if (typeof sarifObj !== "object" || sarifObj === null || Array.isArray(sarifObj)) {
    errorEl.textContent = "Geçersiz SARIF yapısı.";
    errorEl.classList.remove("hidden");
    return;
  }

  // Measure payload size
  const payload = JSON.stringify({ sarif: sarifObj });
  const encoder = new TextEncoder();
  if (encoder.encode(payload).length > 65536) {
    errorEl.textContent = "Girdi çok büyük (maksimum 64 KB).";
    errorEl.classList.remove("hidden");
    return;
  }

  // Call existing api helper
  try {
    const data = await api("/api/tool-reports/sarif/summary", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload
    });
    if (!isCurrentSarifPreview()) return;

    // Render allowlisted fields only
    const runCount = Number.isInteger(data.run_count) ? data.run_count : 0;
    const resultCount = Number.isInteger(data.result_count) ? data.result_count : 0;

    const toolNames = Array.isArray(data.tools)
      ? data.tools
          .filter(t => t && typeof t.name === "string")
          .map(t => escapeHtml(t.name))
          .join(", ")
      : "Yok";

    const levelsMap = {};
    if (Array.isArray(data.tools)) {
      data.tools.forEach(t => {
        if (t && typeof t.levels === "object" && t.levels !== null) {
          Object.entries(t.levels).forEach(([k, v]) => {
            if (typeof k === "string" && typeof v === "number") {
              levelsMap[k] = (levelsMap[k] || 0) + v;
            }
          });
        }
      });
    }
    const levels = Object.entries(levelsMap)
      .map(([k, v]) => `${escapeHtml(k)}: ${v}`)
      .join(", ") || "Yok";

    const reportSha256 = typeof data.report_sha256 === "string" ? data.report_sha256 : "";

    document.getElementById("sarif-run-count").textContent = runCount;
    document.getElementById("sarif-result-count").textContent = resultCount;
    document.getElementById("sarif-tool-names").textContent = toolNames;
    document.getElementById("sarif-levels").textContent = levels;
    document.getElementById("sarif-report-sha256").textContent = reportSha256;

    resultEl.classList.remove("hidden");

    // Clear inputs
    pasteInput.value = "";
    fileInput.value = "";
  } catch {
    if (!isCurrentSarifPreview()) return;
    // Clear all summary fields before showing error
    document.getElementById("sarif-run-count").textContent = "";
    document.getElementById("sarif-result-count").textContent = "";
    document.getElementById("sarif-tool-names").textContent = "";
    document.getElementById("sarif-levels").textContent = "";
    document.getElementById("sarif-report-sha256").textContent = "";

    errorEl.textContent = "Sunucu hatası.";
    errorEl.classList.remove("hidden");
  }
});

// Direct operator targets: no preregistration; each execution requires a fresh checkbox consent.
let directNmapBusy = false;
function directNmapUpdateReady() {
  $("#direct-nmap-start").disabled = directNmapBusy
    || !$("#direct-nmap-target").value.trim()
    || !$("#direct-nmap-confirm-authorized").checked;
}
function openDirectNmapScan() {
  $("#direct-nmap-confirm-authorized").checked = false;
  $("#direct-nmap-status").textContent = "Her çalıştırma sabit port ve süre bütçesiyle yürütülür.";
  $("#direct-nmap-result").classList.add("hidden");
  directNmapUpdateReady();
  showModal("direct-nmap-scan-modal", true);
}
document.addEventListener("click", event => {
  if (event.target.closest?.('[data-action="open-direct-nmap-scan"]')) {
    event.preventDefault();
    openDirectNmapScan();
  }
});
$("#direct-nmap-target").addEventListener("input", () => {
  $("#direct-nmap-confirm-authorized").checked = false;
  directNmapUpdateReady();
});
$("#direct-nmap-profile").addEventListener("change", () => {
  $("#direct-nmap-confirm-authorized").checked = false;
  directNmapUpdateReady();
});
$("#direct-nmap-confirm-authorized").addEventListener("change", directNmapUpdateReady);
$("#direct-nmap-scan-form").addEventListener("submit", async event => {
  event.preventDefault();
  const target = $("#direct-nmap-target").value.trim();
  const profile = $("#direct-nmap-profile").value;
  if (directNmapBusy || !target || !["default", "service-light"].includes(profile)
      || !$("#direct-nmap-confirm-authorized").checked) return;
  directNmapBusy = true;
  directNmapUpdateReady();
  $("#direct-nmap-result").classList.add("hidden");
  $("#direct-nmap-status").textContent = "Nmap taraması çalışıyor…";
  try {
    const result = await api("/api/nmap/authorized-target-scan", {
      method: "POST",
      body: JSON.stringify({ target, profile, confirm_authorized: true }),
    });
    const receipt = result.authorization_receipt;
    if (!Number.isSafeInteger(result.open_port_count) || result.open_port_count < 0
        || !Array.isArray(result.open_ports) || result.open_ports.length !== result.open_port_count
        || !result.open_ports.every(port => Number.isSafeInteger(port) && port >= 1 && port <= 65535)
        || !/^[0-9a-f]{64}$/.test(result.report_sha256 || "")
        || receipt?.consent_version !== "direct-target-authorization-v1"
        || receipt?.confirm_authorized !== true || typeof receipt?.confirmed_at !== "string") {
      throw new Error("Geçersiz Nmap yanıtı.");
    }
    $("#direct-nmap-open-count").textContent = String(result.open_port_count);
    $("#direct-nmap-open-ports").textContent = result.open_ports.join(", ") || "Yok";
    $("#direct-nmap-report-sha256").textContent = result.report_sha256;
    $("#direct-nmap-confirmed-at").textContent = receipt.confirmed_at;
    $("#direct-nmap-result").classList.remove("hidden");
    $("#direct-nmap-status").textContent = "Tarama tamamlandı; sonuç hedef ayrıntısı içermeyen toplu özettir.";
  } catch (error) {
    $("#direct-nmap-status").textContent = error.message;
  } finally {
    directNmapBusy = false;
    $("#direct-nmap-confirm-authorized").checked = false;
    directNmapUpdateReady();
  }
});

let directNucleiBusy = false;
let directNucleiJobId = null;
let directNucleiTimer = null;
function directNucleiUpdateReady() {
  $("#direct-nuclei-start").disabled = directNucleiBusy
    || !$("#direct-nuclei-origin").value.trim()
    || !$("#direct-nuclei-confirm-authorized").checked;
}
function openDirectNucleiScan() {
  $("#direct-nuclei-confirm-authorized").checked = false;
  $("#direct-nuclei-result").classList.add("hidden");
  $("#direct-nuclei-status").textContent = "Sabitlenmiş üç HTTP şablonu kullanılacaktır.";
  $("#direct-nuclei-cancel").disabled = !directNucleiBusy || !directNucleiJobId;
  directNucleiUpdateReady();
  showModal("direct-nuclei-scan-modal", true);
}
function directNucleiRender(result) {
  if (!result || result.job_id !== directNucleiJobId) throw new Error("Geçersiz Nuclei iş yanıtı.");
  if (["starting", "pending", "running", "cancelling", "finalizing"].includes(result.state)) {
    $("#direct-nuclei-status").textContent = result.state === "cancelling" ? "Tarama durduruluyor…" : "Nuclei taraması çalışıyor…";
    return false;
  }
  directNucleiBusy = false;
  $("#direct-nuclei-cancel").disabled = true;
  directNucleiUpdateReady();
  if (result.state !== "completed") {
    $("#direct-nuclei-status").textContent = result.state === "cancelled" ? "Tarama durduruldu." : "Tarama tamamlanamadı.";
    return true;
  }
  if (!Number.isSafeInteger(result.record_count) || result.record_count < 0
      || !Number.isSafeInteger(result.unique_template_count) || result.unique_template_count < 0
      || !/^[0-9a-f]{64}$/.test(result.report_sha256 || "")) throw new Error("Geçersiz Nuclei özeti.");
  $("#direct-nuclei-record-count").textContent = String(result.record_count);
  $("#direct-nuclei-template-count").textContent = String(result.unique_template_count);
  $("#direct-nuclei-report-sha256").textContent = result.report_sha256;
  $("#direct-nuclei-result").classList.remove("hidden");
  $("#direct-nuclei-status").textContent = "Tarama tamamlandı; ham bulgular arayüzde gösterilmez.";
  return true;
}
async function directNucleiPoll() {
  clearTimeout(directNucleiTimer);
  if (!directNucleiJobId || !directNucleiBusy) return;
  try {
    const result = await api(`/api/nuclei/http-scans/${encodeURIComponent(directNucleiJobId)}`);
    if (directNucleiRender(result)) return;
  } catch (error) {
    $("#direct-nuclei-status").textContent = error.message;
  }
  directNucleiTimer = setTimeout(directNucleiPoll, 3000);
}
document.addEventListener("click", event => {
  if (event.target.closest?.('[data-action="open-direct-nuclei-scan"]')) {
    event.preventDefault();
    openDirectNucleiScan();
  }
});
$("#direct-nuclei-origin").addEventListener("input", () => {
  $("#direct-nuclei-confirm-authorized").checked = false;
  directNucleiUpdateReady();
});
$("#direct-nuclei-confirm-authorized").addEventListener("change", directNucleiUpdateReady);
$("#direct-nuclei-scan-form").addEventListener("submit", async event => {
  event.preventDefault();
  const target_origin = $("#direct-nuclei-origin").value.trim();
  if (directNucleiBusy || !target_origin || !$("#direct-nuclei-confirm-authorized").checked) return;
  directNucleiBusy = true;
  directNucleiUpdateReady();
  $("#direct-nuclei-result").classList.add("hidden");
  $("#direct-nuclei-status").textContent = "Nuclei taraması başlatılıyor…";
  try {
    const result = await api("/api/nuclei/authorized-origin-scans", {
      method: "POST", body: JSON.stringify({ target_origin, confirm_authorized: true }),
    });
    if (!/^[0-9a-f]{16}$/.test(result.job_id || "")
        || result.profile !== "authorized-origin-fixed-http-v1"
        || result.authorization_receipt?.consent_version !== "direct-target-authorization-v1") {
      throw new Error("Geçersiz Nuclei başlatma yanıtı.");
    }
    directNucleiJobId = result.job_id;
    $("#direct-nuclei-confirmed-at").textContent = result.authorization_receipt.confirmed_at;
    $("#direct-nuclei-cancel").disabled = false;
    directNucleiPoll();
  } catch (error) {
    directNucleiBusy = false;
    $("#direct-nuclei-status").textContent = error.message;
    directNucleiUpdateReady();
  } finally {
    $("#direct-nuclei-confirm-authorized").checked = false;
  }
});
$("#direct-nuclei-cancel").addEventListener("click", async () => {
  if (!directNucleiJobId || !directNucleiBusy) return;
  $("#direct-nuclei-cancel").disabled = true;
  try {
    await api(`/api/nuclei/http-scans/${encodeURIComponent(directNucleiJobId)}/cancel`, {
      method: "POST", body: JSON.stringify({ confirm_cancel: true }),
    });
    $("#direct-nuclei-status").textContent = "Tarama durduruluyor…";
    directNucleiPoll();
  } catch (error) {
    $("#direct-nuclei-status").textContent = error.message;
    $("#direct-nuclei-cancel").disabled = false;
  }
});

// Nuclei HTTP: explicit, authorized broad catalog by default; exact IDs are optional.
let nucleiHttpJobId = null;
let nucleiHttpBusy = false;
let nucleiHttpTimer = null;

function nucleiHttpSetOptions(select, records, label) {
  select.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = records.length ? label : "Uygun kayıt yok";
  select.appendChild(placeholder);
  for (const record of records) {
    const option = document.createElement("option");
    option.value = record.id;
    option.textContent = record.hostname || record.name || record.id;
    select.appendChild(option);
  }
}

function nucleiHttpUpdateEngagements() {
  const targetId = $("#nuclei-http-target").value;
  const eligible = state.engagements.filter(item => item.target_id === targetId && item.status === "active"
    && item.authorization_ref?.trim() && item.scope_notes?.trim());
  nucleiHttpSetOptions($("#nuclei-http-engagement"), eligible, "Yetkili denetim seçin");
  nucleiHttpUpdateReady();
}

function nucleiHttpUpdateReady() {
  const targetId = $("#nuclei-http-target").value;
  const engagementId = $("#nuclei-http-engagement").value;
  const eligible = state.engagements.some(item => item.id === engagementId && item.target_id === targetId
    && item.status === "active" && item.authorization_ref?.trim() && item.scope_notes?.trim());
  $("#nuclei-http-start").disabled = nucleiHttpBusy || !eligible || !$("#nuclei-http-confirm-authorized").checked;
}

function openNucleiHttpScan(targetId = "") {
  const readyTargets = state.targets.filter(item => item.status === "ready");
  const target = $("#nuclei-http-target");
  nucleiHttpSetOptions(target, readyTargets, "Hedef seçin");
  if (readyTargets.some(item => item.id === targetId)) target.value = targetId;
  nucleiHttpUpdateEngagements();
  $("#nuclei-http-confirm-authorized").checked = false;
  nucleiHttpUpdateReady();
  if (!nucleiHttpJobId) {
    $("#nuclei-http-status").textContent = readyTargets.length ? "Şablon ID alanı boşsa tüm normal HTTP kataloğu kullanılır." : "Önce bir hedef ekleyin.";
    $("#nuclei-http-result").classList.add("hidden");
  }
  $("#nuclei-http-cancel").disabled = !nucleiHttpBusy || !nucleiHttpJobId;
  showModal("nuclei-http-scan-modal", true);
  if (nucleiHttpJobId && nucleiHttpBusy) nucleiHttpPoll();
}

function nucleiHttpRenderStatus(result) {
  if (!result || result.job_id !== nucleiHttpJobId) throw new Error("Geçersiz iş yanıtı.");
  const status = result.state;
  if (!["starting", "pending", "running", "cancelling", "finalizing", "cancelled", "completed", "failed"].includes(status)) {
    throw new Error("Geçersiz iş durumu.");
  }
  if (["starting", "pending", "running", "cancelling", "finalizing"].includes(status)) {
    $("#nuclei-http-status").textContent = status === "cancelling" ? "Tarama durduruluyor…" : "Nuclei taraması çalışıyor…";
    const elapsed = result.elapsed_seconds ?? 0;
    const elapsedText = Number.isFinite(elapsed) && elapsed >= 0 ? `Geçen süre: ${Math.floor(elapsed)}s` : "Geçen süre: 0s";
    $("#nuclei-http-elapsed").textContent = elapsedText;
    $("#nuclei-http-elapsed").classList.remove("hidden");
    $("#nuclei-http-cancel").disabled = status === "cancelling" || status === "finalizing";
    return false;
  }
  nucleiHttpBusy = false;
  $("#nuclei-http-cancel").disabled = true;
  $("#nuclei-http-elapsed").classList.add("hidden");
  nucleiHttpUpdateReady();
  if (status === "completed") {
    const count = result.record_count;
    const unique = result.unique_template_count;
    const hash = result.report_sha256;
    const counts = result.severity_counts;
    if (!Number.isSafeInteger(count) || count < 0 || !Number.isSafeInteger(unique) || unique < 0
      || typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)
      || !counts || typeof counts !== "object" || Array.isArray(counts)) throw new Error("Geçersiz tarama özeti.");
    $("#nuclei-http-record-count").textContent = String(count);
    $("#nuclei-http-unique-template-count").textContent = String(unique);
    $("#nuclei-http-report-sha256").textContent = hash;
    $("#nuclei-http-severity-counts").textContent = ["info", "low", "medium", "high", "critical", "unknown"]
      .map(key => `${key}:${Number.isSafeInteger(counts[key]) && counts[key] >= 0 ? counts[key] : 0}`).join(" ");
    $("#nuclei-http-result").classList.remove("hidden");
    $("#nuclei-http-status").textContent = "Tarama tamamlandı. Ham rapor saklanmadı; özet uzman incelemesi gerektirir.";
  } else {
    $("#nuclei-http-result").classList.add("hidden");
    $("#nuclei-http-status").textContent = status === "cancelled" ? "Tarama durduruldu." : "Tarama tamamlanamadı; sistem yöneticisi günlükleri denetlemeli.";
  }
  return true;
}

async function nucleiHttpPoll() {
  clearTimeout(nucleiHttpTimer);
  if (!nucleiHttpJobId || $("#nuclei-http-scan-modal").classList.contains("hidden")) return;
  try {
    const result = await api(`/api/nuclei/http-scans/${encodeURIComponent(nucleiHttpJobId)}`);
    if (nucleiHttpRenderStatus(result)) return;
  } catch {
    $("#nuclei-http-status").textContent = "Tarama durumu alınamadı; yeniden denenecek.";
  }
  nucleiHttpTimer = setTimeout(nucleiHttpPoll, 3000);
}

document.addEventListener("click", event => {
  const action = event.target.closest?.('[data-action="open-nuclei-http-scan"]');
  if (action) {
    event.preventDefault();
    openNucleiHttpScan(action.dataset.id || "");
  }
});
$("#nuclei-http-target").addEventListener("change", nucleiHttpUpdateEngagements);
$("#nuclei-http-engagement").addEventListener("change", nucleiHttpUpdateReady);
$("#nuclei-http-confirm-authorized").addEventListener("change", nucleiHttpUpdateReady);
$("#nuclei-http-scan-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (nucleiHttpBusy) return;
  const targetId = $("#nuclei-http-target").value;
  const engagementId = $("#nuclei-http-engagement").value;
  const authorized = $("#nuclei-http-confirm-authorized").checked;
  if (!targetId || !engagementId || !authorized) return;
  const rawIds = $("#nuclei-http-template-ids").value.trim();
  const ids = rawIds ? rawIds.split(/[\s,]+/).filter(Boolean) : [];
  if (ids.length > 1000 || new Set(ids).size !== ids.length || ids.some(id => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id))) {
    $("#nuclei-http-status").textContent = "Geçersiz veya yinelenen şablon kimliği.";
    return;
  }
  nucleiHttpBusy = true;
  nucleiHttpUpdateReady();
  $("#nuclei-http-result").classList.add("hidden");
  $("#nuclei-http-status").textContent = "Tarama başlatılıyor…";
  try {
    const body = { target_id: targetId, engagement_id: engagementId, confirm_authorized: true,
      include_excluded: $("#nuclei-http-include-excluded").checked };
    if (ids.length) body.template_ids = ids;
    const started = await api("/api/nuclei/http-scans", { method: "POST", body: JSON.stringify(body) });
    if (!/^[0-9a-f]{16}$/.test(started.job_id || "")) throw new Error("Geçersiz iş yanıtı.");
    nucleiHttpJobId = started.job_id;
    $("#nuclei-http-cancel").disabled = false;
    nucleiHttpPoll();
  } catch (error) {
    nucleiHttpBusy = false;
    nucleiHttpUpdateReady();
    $("#nuclei-http-status").textContent = error.message;
  }
});
$("#nuclei-http-cancel").addEventListener("click", async () => {
  if (!nucleiHttpJobId || !nucleiHttpBusy) return;
  $("#nuclei-http-cancel").disabled = true;
  try {
    const result = await api(`/api/nuclei/http-scans/${encodeURIComponent(nucleiHttpJobId)}/cancel`, {
      method: "POST", body: JSON.stringify({ confirm_cancel: true }),
    });
    if (result.job_id !== nucleiHttpJobId) throw new Error("Geçersiz iptal yanıtı.");
    $("#nuclei-http-status").textContent = "Tarama durduruluyor…";
    nucleiHttpPoll();
  } catch (error) {
    $("#nuclei-http-status").textContent = error.message;
    $("#nuclei-http-cancel").disabled = false;
  }
});

let opensslX509PreviewGeneration = 0;
let opensslX509PendingGeneration = 0;

function clearOpensslX509PreviewResult() {
  const result = document.getElementById("openssl-x509-preview-result");
  if (result) result.classList.add("hidden");
  for (const id of [
    "openssl-x509-validity",
    "openssl-x509-before",
    "openssl-x509-after",
    "openssl-x509-days",
    "openssl-x509-sha",
  ]) {
    const el = document.getElementById(id);
    if (el) el.textContent = "";
  }
}

function isOpensslX509PreviewDirty() {
  if (opensslX509PendingGeneration !== 0) return true;
  const input = document.getElementById("openssl-x509-paste");
  const error = document.getElementById("openssl-x509-preview-error");
  const result = document.getElementById("openssl-x509-preview-result");
  if (input && input.value !== "") return true;
  if (error && (error.textContent !== "" || !error.classList.contains("hidden"))) return true;
  if (result && !result.classList.contains("hidden")) return true;
  for (const id of [
    "openssl-x509-validity",
    "openssl-x509-before",
    "openssl-x509-after",
    "openssl-x509-days",
    "openssl-x509-sha",
  ]) {
    const el = document.getElementById(id);
    if (el && el.textContent !== "") return true;
  }
  return false;
}

function clearOpensslX509Preview() {
  opensslX509PreviewGeneration += 1;
  opensslX509PendingGeneration = 0;
  const input = document.getElementById("openssl-x509-paste");
  const error = document.getElementById("openssl-x509-preview-error");
  if (input) input.value = "";
  if (error) {
    error.textContent = "";
    error.classList.add("hidden");
  }
  clearOpensslX509PreviewResult();
}

// A saved OpenSSL x509 report is interpreted locally; this flow never starts a scan.
document.addEventListener("click", event => {
  const open = event.target.closest('[data-action="open-openssl-x509-preview"]');
  if (open) {
    event.preventDefault();
    clearOpensslX509Preview();
    showModal("openssl-x509-preview-modal", true);
    return;
  }
  const close = event.target.closest('[data-close="openssl-x509-preview-modal"]');
  if (close || event.target.id === "openssl-x509-preview-modal") {
    event.preventDefault();
    if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
    showModal("openssl-x509-preview-modal", false);
  }
});

document.addEventListener("input", event => {
  if (event.target?.id !== "openssl-x509-paste") return;
  opensslX509PreviewGeneration += 1;
  opensslX509PendingGeneration = 0;
  const error = document.getElementById("openssl-x509-preview-error");
  if (error) {
    error.textContent = "";
    error.classList.add("hidden");
  }
  clearOpensslX509PreviewResult();
});

document.addEventListener("submit", async event => {
  if (event.target.id !== "openssl-x509-preview-form") return;
  event.preventDefault();
  const requestGeneration = ++opensslX509PreviewGeneration;
  opensslX509PendingGeneration = requestGeneration;
  const modal = document.getElementById("openssl-x509-preview-modal");
  const input = document.getElementById("openssl-x509-paste");
  const error = document.getElementById("openssl-x509-preview-error");
  const result = document.getElementById("openssl-x509-preview-result");
  error.textContent = "";
  error.classList.add("hidden");
  clearOpensslX509PreviewResult();
  const report = input.value;
  const isCurrentOpensslX509Request = () =>
    requestGeneration === opensslX509PreviewGeneration &&
    (!modal || !modal.classList.contains("hidden")) &&
    Boolean(input) &&
    input.value === report;
  if (!report || new TextEncoder().encode(report).length > 4096) {
    opensslX509PendingGeneration = 0;
    error.textContent = "Geçersiz OpenSSL x509 raporu.";
    error.classList.remove("hidden");
    return;
  }
  try {
    const data = await api("/api/tool-reports/openssl-x509/summary", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report })
    });
    if (!isCurrentOpensslX509Request()) return;
    const allowed = ["valid", "expiring_soon", "expired", "not_yet_valid"];
    if (!data || typeof data !== "object" ||
        data.format !== "openssl-x509-dates-fingerprint-v1" ||
        !allowed.includes(data.validity) ||
        !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(data.not_before_utc) ||
        !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(data.not_after_utc) ||
        !Number.isSafeInteger(data.days_until_expiry) || data.days_until_expiry < 0 ||
        !/^[0-9a-f]{64}$/.test(data.report_sha256)) {
      throw new Error("invalid OpenSSL summary");
    }
    const labels = { valid: "Geçerli", expiring_soon: "Yakında sona erecek", expired: "Süresi dolmuş", not_yet_valid: "Henüz geçerli değil" };
    document.getElementById("openssl-x509-validity").textContent = labels[data.validity];
    document.getElementById("openssl-x509-before").textContent = data.not_before_utc;
    document.getElementById("openssl-x509-after").textContent = data.not_after_utc;
    document.getElementById("openssl-x509-days").textContent = String(data.days_until_expiry);
    document.getElementById("openssl-x509-sha").textContent = data.report_sha256;
    input.value = "";
    opensslX509PendingGeneration = 0;
    result.classList.remove("hidden");
  } catch {
    if (!isCurrentOpensslX509Request()) return;
    opensslX509PendingGeneration = 0;
    clearOpensslX509PreviewResult();
    error.textContent = "Geçersiz OpenSSL x509 raporu.";
    error.classList.remove("hidden");
  }
});

function escapeHtml(str) {  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}let trufflehogPreviewGeneration = 0;
let trufflehogPreviewModalOpen = false;

function resetTrufflehogPreviewOutputs() {
  const errorEl = document.getElementById("trufflehog-preview-error");
  const resultEl = document.getElementById("trufflehog-preview-result");
  if (errorEl) {
    errorEl.textContent = "";
    errorEl.classList.add("hidden");
  }
  if (resultEl) resultEl.classList.add("hidden");
  for (const id of [
    "trufflehog-format",
    "trufflehog-total",
    "trufflehog-verified",
    "trufflehog-unverified",
    "trufflehog-detectors"
  ]) {
    const el = document.getElementById(id);
    if (el) el.textContent = "";
  }
}

function clearTrufflehogModal() {
  trufflehogPreviewGeneration += 1;
  const pasteInput = document.getElementById("trufflehog-paste");
  const fileInput = document.getElementById("trufflehog-file");

  if (pasteInput) pasteInput.value = "";
  if (fileInput) {
    fileInput.value = "";
    if (Array.isArray(fileInput.files)) fileInput.files = [];
  }
  resetTrufflehogPreviewOutputs();
}

document.addEventListener("click", async event => {
  const action = event.target.closest?.("[data-action]");
  if (action && action.dataset.action === "open-trufflehog-preview") {
    event.preventDefault();
    clearTrufflehogModal();
    showModal("trufflehog-preview-modal", true);
    return;
  }

  const close = event.target.closest?.("[data-close]");
  if (close && close.dataset.close === "trufflehog-preview-modal") {
    event.preventDefault();
    clearTrufflehogModal();
    showModal("trufflehog-preview-modal", false);
    return;
  }

  if (event.target.id === "trufflehog-preview-modal") {
    event.preventDefault();
    clearTrufflehogModal();
    showModal("trufflehog-preview-modal", false);
    return;
  }
});

document.addEventListener("input", event => {
  if (event.target?.id === "trufflehog-paste" || event.target?.id === "trufflehog-file") {
    trufflehogPreviewGeneration += 1;
    resetTrufflehogPreviewOutputs();
  }
});

document.addEventListener("change", event => {
  if (event.target?.id === "trufflehog-paste" || event.target?.id === "trufflehog-file") {
    trufflehogPreviewGeneration += 1;
    resetTrufflehogPreviewOutputs();
  }
});

document.addEventListener("submit", async event => {
  if (event.target.id !== "trufflehog-preview-form") return;
  event.preventDefault();

  const modal = document.getElementById("trufflehog-preview-modal");
  if (modal && !modal.classList.contains("hidden")) trufflehogPreviewModalOpen = true;
  const requestGeneration = ++trufflehogPreviewGeneration;

  const pasteInput = document.getElementById("trufflehog-paste");
  const fileInput = document.getElementById("trufflehog-file");
  const errorEl = document.getElementById("trufflehog-preview-error");
  const resultEl = document.getElementById("trufflehog-preview-result");
  const initialPasteValue = pasteInput.value;
  const initialFile = (fileInput.files && fileInput.files[0]) || null;
  const initialFilesLength = fileInput.files ? fileInput.files.length : 0;
  const initialFileName = initialFile ? initialFile.name : "";
  const initialFileSize = initialFile ? initialFile.size : -1;
  const initialFileValue = fileInput.value;
  const isCurrentTrufflehogPreview = () => {
    const currentFile = (fileInput.files && fileInput.files[0]) || null;
    return (
      requestGeneration === trufflehogPreviewGeneration &&
      (!modal || !modal.classList.contains("hidden")) &&
      pasteInput.value === initialPasteValue &&
      currentFile === initialFile &&
      (fileInput.files ? fileInput.files.length : 0) === initialFilesLength &&
      (currentFile ? currentFile.name : "") === initialFileName &&
      (currentFile ? currentFile.size : -1) === initialFileSize &&
      fileInput.value === initialFileValue
    );
  };

  resetTrufflehogPreviewOutputs();

  let rawContent = pasteInput.value.trim();

  if (!rawContent) {
    const file = fileInput.files[0];
    if (file) {
      if (file.size > 65536) {
        errorEl.textContent = "Girdi çok büyük (maksimum 64 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      try {
        rawContent = await file.text();
        if (!isCurrentTrufflehogPreview()) return;
      } catch {
        if (!isCurrentTrufflehogPreview()) return;
        errorEl.textContent = "Dosya okunamadı.";
        errorEl.classList.remove("hidden");
        return;
      }
    } else {
      errorEl.textContent = "Boş içerik gönderilemez.";
      errorEl.classList.remove("hidden");
      return;
    }
  }

  const lines = rawContent.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  if (lines.length === 0) {
    errorEl.textContent = "Geçersiz JSONL: Boş içerik.";
    errorEl.classList.remove("hidden");
    return;
  }

  if (lines.length > 500) {
    errorEl.textContent = "Çok fazla kayıt (maksimum 500).";
    errorEl.classList.remove("hidden");
    return;
  }

  const records = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      errorEl.textContent = `Geçersiz JSON satır ${i + 1}.`;
      errorEl.classList.remove("hidden");
      return;
    }

    if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
      errorEl.textContent = `Geçersiz yapı satır ${i + 1}.`;
      errorEl.classList.remove("hidden");
      return;
    }

    if (typeof obj.DetectorName !== "string") {
      errorEl.textContent = `\'DetectorName\' eksik veya geçersiz satır ${i + 1}.`;
      errorEl.classList.remove("hidden");
      return;
    }
    if (typeof obj.Verified !== "boolean") {
      errorEl.textContent = `\'Verified\' eksik veya geçersiz satır ${i + 1}.`;
      errorEl.classList.remove("hidden");
      return;
    }

    records.push(obj);
  }

  const payload = JSON.stringify({ report: records });
  const encoder = new TextEncoder();
  if (encoder.encode(rawContent).length > 65536 || encoder.encode(payload).length > 65536) {
    errorEl.textContent = "Girdi çok büyük (maksimum 64 KB).";
    errorEl.classList.remove("hidden");
    return;
  }

  try {
    const data = await api("/api/tool-reports/trufflehog/summary", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload
    });
    if (!isCurrentTrufflehogPreview()) return;

    // Validate summary fields strictly
    const format = data.format === "trufflehog-native-json-records" ? "trufflehog-native-json-records" : "";
    const total = Number.isSafeInteger(data.total_findings) && data.total_findings >= 0 ? data.total_findings : null;
    const verified = Number.isSafeInteger(data.verified_findings) && data.verified_findings >= 0 ? data.verified_findings : null;
    const unverified = Number.isSafeInteger(data.unverified_findings) && data.unverified_findings >= 0 ? data.unverified_findings : null;
    const detectors = Number.isSafeInteger(data.detectors_triggered) && data.detectors_triggered >= 0 ? data.detectors_triggered : null;

    // Enforce consistency constraints
    const isValid = format !== "" &&
      total !== null && verified !== null && unverified !== null && detectors !== null &&
      verified + unverified === total && detectors <= total;

    if (!isValid) {
      resetTrufflehogPreviewOutputs();
      errorEl.textContent = "Sunucu hatası.";
      errorEl.classList.remove("hidden");
      return;
    }

    document.getElementById("trufflehog-format").textContent = format;
    document.getElementById("trufflehog-total").textContent = total;
    document.getElementById("trufflehog-verified").textContent = verified;
    document.getElementById("trufflehog-unverified").textContent = unverified;
    document.getElementById("trufflehog-detectors").textContent = detectors;

    resultEl.classList.remove("hidden");

    pasteInput.value = "";
    fileInput.value = "";
    if (Array.isArray(fileInput.files)) fileInput.files = [];
  } catch {
    if (!isCurrentTrufflehogPreview()) return;
    resetTrufflehogPreviewOutputs();
    errorEl.textContent = "Sunucu hatası.";
    errorEl.classList.remove("hidden");
  }
});
const SEVERITY_VALUES = ["info", "low", "medium", "high", "critical", "unknown"];

let nucleiJsonlPreviewGeneration = 0;
let nucleiJsonlModalOpen = false;

function resetNucleiJsonlPreviewOutputs() {
  const errorEl = document.getElementById("nuclei-jsonl-preview-error");
  const resultEl = document.getElementById("nuclei-jsonl-preview-result");
  const linkResult = document.getElementById("nuclei-jsonl-link-result");
  if (errorEl) {
    errorEl.textContent = "";
    errorEl.classList.add("hidden");
  }
  if (resultEl) resultEl.classList.add("hidden");
  if (linkResult) {
    linkResult.classList.add("hidden");
    linkResult.textContent = "";
  }
  for (const id of [
    "nuclei-jsonl-format",
    "nuclei-jsonl-record-count",
    "nuclei-jsonl-severity-counts",
    "nuclei-jsonl-unique-template-count",
    "nuclei-jsonl-report-sha256"
  ]) {
    const item = document.getElementById(id);
    if (item) item.textContent = "";
  }
}

function resetNucleiJsonlLinkState() {
  if (typeof globalThis.resetNucleiJsonlLinkPreview === "function") {
    globalThis.resetNucleiJsonlLinkPreview();
  } else if (typeof window !== "undefined" && typeof window.resetNucleiJsonlLinkPreview === "function") {
    window.resetNucleiJsonlLinkPreview();
  }
  const linkOptIn = document.getElementById("nuclei-jsonl-link-opt-in");
  const linkFields = document.getElementById("nuclei-jsonl-link-fields");
  const linkEngagement = document.getElementById("nuclei-jsonl-link-engagement");
  const linkControl = document.getElementById("nuclei-jsonl-link-control");
  const linkResult = document.getElementById("nuclei-jsonl-link-result");
  if (linkOptIn) linkOptIn.checked = false;
  if (linkFields) linkFields.classList.add("hidden");
  if (linkEngagement) {
    if (typeof linkEngagement.replaceChildren === "function") linkEngagement.replaceChildren();
    linkEngagement.innerHTML = "";
    linkEngagement.value = "";
    if (Array.isArray(linkEngagement.options)) linkEngagement.options.length = 0;
    if (Array.isArray(linkEngagement.children)) linkEngagement.children.length = 0;
  }
  if (linkControl) {
    if (typeof linkControl.replaceChildren === "function") linkControl.replaceChildren();
    linkControl.innerHTML = "";
    linkControl.value = "";
    if (Array.isArray(linkControl.options)) linkControl.options.length = 0;
    if (Array.isArray(linkControl.children)) linkControl.children.length = 0;
  }
  if (linkResult) {
    linkResult.classList.add("hidden");
    linkResult.textContent = "";
  }
}

function clearNucleiJsonlModal() {
  nucleiJsonlPreviewGeneration += 1;
  const pasteInput = document.getElementById("nuclei-jsonl-paste");
  const fileInput = document.getElementById("nuclei-jsonl-file");

  if (pasteInput) pasteInput.value = "";
  if (fileInput) {
    fileInput.value = "";
    if (Array.isArray(fileInput.files)) fileInput.files = [];
  }
  resetNucleiJsonlPreviewOutputs();
  resetNucleiJsonlLinkState();
  if (typeof renderNucleiEngagementOptions === "function") {
    renderNucleiEngagementOptions();
  }
}

document.addEventListener("click", async event => {
  const action = event.target.closest("[data-action]");
  if (action && action.dataset.action === "open-nuclei-jsonl-preview") {
    event.preventDefault();
    clearNucleiJsonlModal();
    if (typeof renderNucleiEngagementOptions === "function") await renderNucleiEngagementOptions();
    showModal("nuclei-jsonl-preview-modal", true);
    return;
  }

  const close = event.target.closest("[data-close]");
  if (close && close.dataset.close === "nuclei-jsonl-preview-modal") {
    event.preventDefault();
    showModal("nuclei-jsonl-preview-modal", false);
    return;
  }

  if (event.target.id === "nuclei-jsonl-preview-modal") {
    event.preventDefault();
    showModal("nuclei-jsonl-preview-modal", false);
    return;
  }
});

document.addEventListener("change", event => {
  if (
    [
      "nuclei-jsonl-link-opt-in",
      "nuclei-jsonl-link-engagement",
      "nuclei-jsonl-link-control",
      "nuclei-jsonl-file"
    ].includes(event.target.id)
  ) {
    nucleiJsonlPreviewGeneration += 1;
  }
});

document.addEventListener("input", event => {
  if (event.target.id === "nuclei-jsonl-paste" || event.target.id === "nuclei-jsonl-file") {
    nucleiJsonlPreviewGeneration += 1;
  }
});

document.addEventListener("submit", async event => {
  if (event.target.id !== "nuclei-jsonl-preview-form") return;
  event.preventDefault();
  const requestGeneration = ++nucleiJsonlPreviewGeneration;

  const pasteInput = document.getElementById("nuclei-jsonl-paste");
  const fileInput = document.getElementById("nuclei-jsonl-file");
  const errorEl = document.getElementById("nuclei-jsonl-preview-error");
  const resultEl = document.getElementById("nuclei-jsonl-preview-result");
  const linkOptIn = document.getElementById("nuclei-jsonl-link-opt-in");
  const linkEngagement = document.getElementById("nuclei-jsonl-link-engagement");
  const linkControl = document.getElementById("nuclei-jsonl-link-control");
  const linkResult = document.getElementById("nuclei-jsonl-link-result");
  const initialPasteValue = pasteInput.value;
  const initialFile = (fileInput.files && fileInput.files[0]) || null;
  const initialFileValue = fileInput.value;
  const linkRequested = Boolean(linkOptIn && linkOptIn.checked);
  const engagementId = linkEngagement ? linkEngagement.value : "";
  const controlId = linkControl ? linkControl.value : "";
  const isCurrentPreview = () =>
    requestGeneration === nucleiJsonlPreviewGeneration &&
    pasteInput.value === initialPasteValue &&
    ((fileInput.files && fileInput.files[0]) || null) === initialFile &&
    fileInput.value === initialFileValue &&
    Boolean(linkOptIn && linkOptIn.checked) === linkRequested &&
    (linkEngagement ? linkEngagement.value : "") === engagementId &&
    (linkControl ? linkControl.value : "") === controlId;

  resetNucleiJsonlPreviewOutputs();

  let rawContent = pasteInput.value.trim();

  if (!rawContent) {
    const file = fileInput.files[0];
    if (file) {
      if (file.size > 65536) {
        errorEl.textContent = "Girdi çok büyük (maksimum 64 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      try {
        rawContent = await file.text();
        if (!isCurrentPreview()) return;
      } catch {
        if (!isCurrentPreview()) return;
        errorEl.textContent = "Dosya okunamadı.";
        errorEl.classList.remove("hidden");
        return;
      }
    } else {
      errorEl.textContent = "Boş içerik gönderilemez.";
      errorEl.classList.remove("hidden");
      return;
    }
  }

  const lines = rawContent.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) {
    errorEl.textContent = "Boş içerik gönderilemez.";
    errorEl.classList.remove("hidden");
    return;
  }

  const records = [];
  for (const line of lines) {
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    const templateId = obj["template-id"];
    const type = obj["type"];
    const info = obj["info"];
    if (typeof templateId !== "string" || !templateId) {
      errorEl.textContent = "Geçersiz kayıt: 'template-id' eksik veya boş.";
      errorEl.classList.remove("hidden");
      return;
    }
    if (typeof type !== "string" || !type) {
      errorEl.textContent = "Geçersiz kayıt: 'type' eksik veya boş.";
      errorEl.classList.remove("hidden");
      return;
    }
    if (!info || typeof info !== "object" || Array.isArray(info)) {
      errorEl.textContent = "Geçersiz kayıt: 'info' eksik veya nesne değil.";
      errorEl.classList.remove("hidden");
      return;
    }
    if (info.severity !== undefined) {
      if (typeof info.severity !== "string" || !/[a-z]+$/.test(info.severity)) {
        errorEl.textContent = "Geçersiz kayıt: 'info.severity' geçerli bir küçük harf dizesi değil.";
        errorEl.classList.remove("hidden");
        return;
      }
      const allowed = ["info", "low", "medium", "high", "critical", "unknown"];
      if (!allowed.includes(info.severity)) {
        errorEl.textContent = "Geçersiz kayıt: 'info.severity' izin verilen değerlerden biri değil.";
        errorEl.classList.remove("hidden");
        return;
      }
    }
    records.push(obj);
  }

  if (records.length > 500) {
    errorEl.textContent = "Maksimum 500 kayıt izin verilir.";
    errorEl.classList.remove("hidden");
    return;
  }

  const payload = JSON.stringify({ report: records });
  const encoder = new TextEncoder();
  if (encoder.encode(rawContent).length > 65536 || encoder.encode(payload).length > 65536) {
    errorEl.textContent = "Girdi çok büyük (maksimum 64 KB).";
    errorEl.classList.remove("hidden");
    return;
  }

  try {
    let data;
    if (linkRequested) {
      if (!engagementId || !controlId) {
        errorEl.textContent = "Lütfen hem denetimi hem de test adımını seçin.";
        errorEl.classList.remove("hidden");
        return;
      }
      const linkBody = JSON.stringify({ control_id: controlId, report: records, confirm_link: true });
      const encoder = new TextEncoder();
      if (encoder.encode(linkBody).length > 65536) {
        errorEl.textContent = "Girdi çok büyük (maksimum 64 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      data = await api(`/api/engagements/${encodeURIComponent(engagementId)}/tool-evidence/nuclei-jsonl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: linkBody
      });
      if (!isCurrentPreview()) return;
      const toolIdentity = data.tool_identity;
      const isValidToolIdentity = toolIdentity === "nuclei-jsonl";
      const reportSha256 = typeof data.report_sha256 === "string" && /^[a-f0-9]{64}$/.test(data.report_sha256) ? data.report_sha256 : "";
      const recordCount = Number.isSafeInteger(data.record_count) && data.record_count >= 0 ? data.record_count : null;
      const uniqueTemplateCount = Number.isSafeInteger(data.unique_template_count) && data.unique_template_count >= 0 ? data.unique_template_count : null;
      const severityCounts = data.severity_counts;

      const isValidRecordCount = recordCount !== null && recordCount === records.length;
      const isValidUniqueTemplateCount = uniqueTemplateCount !== null && uniqueTemplateCount >= 0 && uniqueTemplateCount <= recordCount;
      const isValidSeverityCounts = severityCounts && typeof severityCounts === "object" && !Array.isArray(severityCounts);
      const severityKeys = isValidSeverityCounts ? Object.keys(severityCounts) : [];
      const isValidSeverityKeys = isValidSeverityCounts && severityKeys.length === 6 && SEVERITY_VALUES.every(k => severityKeys.includes(k)) && SEVERITY_VALUES.every(k => typeof severityCounts[k] === "number" && Number.isSafeInteger(severityCounts[k]) && severityCounts[k] >= 0);
      const isValidSeveritySum = isValidSeverityKeys && SEVERITY_VALUES.reduce((sum, k) => sum + severityCounts[k], 0) === recordCount;
      const isValidReportSha256 = reportSha256 !== "";

      if (!isValidToolIdentity || !isValidRecordCount || !isValidUniqueTemplateCount || !isValidSeveritySum || !isValidReportSha256) {
        errorEl.textContent = "Sunucu hatası.";
        errorEl.classList.remove("hidden");
        return;
      }

      document.getElementById("nuclei-jsonl-format").textContent = "nuclei-jsonl";
      document.getElementById("nuclei-jsonl-record-count").textContent = recordCount;
      document.getElementById("nuclei-jsonl-severity-counts").textContent = `info:${severityCounts.info} low:${severityCounts.low} medium:${severityCounts.medium} high:${severityCounts.high} critical:${severityCounts.critical} unknown:${severityCounts.unknown}`;
      document.getElementById("nuclei-jsonl-unique-template-count").textContent = uniqueTemplateCount;
      document.getElementById("nuclei-jsonl-report-sha256").textContent = reportSha256;

      resultEl.classList.remove("hidden");
      linkResult.textContent = "Bağlantı oluşturuldu.";
      linkResult.classList.remove("hidden");
    } else {
      data = await api("/api/tool-reports/nuclei-jsonl/summary", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload
      });
      if (!isCurrentPreview()) return;

      const format = data.format === "nuclei-jsonl" ? "nuclei-jsonl" : "";
      const recordCount = Number.isSafeInteger(data.record_count) && data.record_count >= 0 ? data.record_count : null;
      const uniqueTemplateCount = Number.isSafeInteger(data.unique_template_count) && data.unique_template_count >= 0 ? data.unique_template_count : null;
      const severityCounts = data.severity_counts;
      const reportSha256 = typeof data.report_sha256 === "string" && /^[a-f0-9]{64}$/.test(data.report_sha256) ? data.report_sha256 : "";

      const isValidFormat = format === "nuclei-jsonl";
      const isValidRecordCount = recordCount !== null && recordCount === records.length;
      const isValidUniqueTemplateCount = uniqueTemplateCount !== null && uniqueTemplateCount >= 0 && uniqueTemplateCount <= recordCount;
      const isValidSeverityCounts = severityCounts && typeof severityCounts === "object" && !Array.isArray(severityCounts);
      const severityKeys = isValidSeverityCounts ? Object.keys(severityCounts) : [];
      const isValidSeverityKeys = isValidSeverityCounts && severityKeys.length === 6 && SEVERITY_VALUES.every(k => severityKeys.includes(k)) && SEVERITY_VALUES.every(k => typeof severityCounts[k] === "number" && Number.isSafeInteger(severityCounts[k]) && severityCounts[k] >= 0);
      const isValidSeveritySum = isValidSeverityKeys && SEVERITY_VALUES.reduce((sum, k) => sum + severityCounts[k], 0) === recordCount;
      const isValidReportSha256 = reportSha256 !== "";

      if (!isValidFormat || !isValidRecordCount || !isValidUniqueTemplateCount || !isValidSeveritySum || !isValidReportSha256) {
        errorEl.textContent = "Sunucu hatası.";
        errorEl.classList.remove("hidden");
        return;
      }

      document.getElementById("nuclei-jsonl-format").textContent = format;
      document.getElementById("nuclei-jsonl-record-count").textContent = recordCount;
      document.getElementById("nuclei-jsonl-severity-counts").textContent = `info:${severityCounts.info} low:${severityCounts.low} medium:${severityCounts.medium} high:${severityCounts.high} critical:${severityCounts.critical} unknown:${severityCounts.unknown}`;
      document.getElementById("nuclei-jsonl-unique-template-count").textContent = uniqueTemplateCount;
      document.getElementById("nuclei-jsonl-report-sha256").textContent = reportSha256;

      resultEl.classList.remove("hidden");
    }

    pasteInput.value = "";
    fileInput.value = "";
    if (Array.isArray(fileInput.files)) fileInput.files = [];
  } catch {
    if (!isCurrentPreview()) return;
    errorEl.textContent = "Sunucu hatası.";
    errorEl.classList.remove("hidden");
  }
});
function burpXmlEligibleEngagements() {
  return state.engagements.filter(item => item.status === 'active'
    && typeof item.authorization_ref === 'string' && item.authorization_ref.trim()
    && typeof item.scope_notes === 'string' && item.scope_notes.trim()
    && item.special_approvals?.redacted_data_proof === true);
}

function renderBurpXmlEngagementOptions() {
  const optIn = document.getElementById('burp-xml-link-opt-in');
  const fields = document.getElementById('burp-xml-link-fields');
  const engagementSelect = document.getElementById('burp-xml-link-engagement');
  const controlSelect = document.getElementById('burp-xml-link-control');
  const availability = document.getElementById('burp-xml-link-availability');
  const linkResult = document.getElementById('burp-xml-link-result');
  const eligible = burpXmlEligibleEngagements();

  optIn.checked = false;
  optIn.disabled = eligible.length === 0;
  fields.classList.add('hidden');
  engagementSelect.innerHTML = '<option value="">' + (eligible.length ? 'Denetim seçin' : 'Uygun denetim yok') + '</option>'
    + eligible.map(item => '<option value="' + esc(item.id) + '">' + esc(item.name) + ' · ' + esc(item.authorization_ref) + '</option>').join('');
  controlSelect.innerHTML = '<option value="">Önce denetim seçin</option>';
  controlSelect.disabled = true;
  linkResult.textContent = '';
  linkResult.classList.add('hidden');
  availability.textContent = eligible.length
    ? 'Kanıt bağlantısı isteğe bağlıdır; yalnız etkin, yetki referansı, kapsam notu ve maskeli kanıt onayı bulunan denetimler listelenir.'
    : 'Kanıt bağlamak için etkin, yetki referansı, kapsam notu ve maskeli kanıt onayı bulunan bir denetim gerekir. Önizleme yine bağlantısız kullanılabilir.';
  availability.classList.remove('hidden');
}

async function loadBurpXmlControls(engagementId) {
  const controlSelect = document.getElementById('burp-xml-link-control');
  const selected = burpXmlEligibleEngagements().find(item => item.id === engagementId);
  controlSelect.disabled = true;
  controlSelect.innerHTML = '<option value="">Kontroller yükleniyor…</option>';
  controlSelect.value = "";
  if (!selected) {
    controlSelect.innerHTML = '<option value="">Etkin ve yetkili denetim seçin</option>';
    return;
  }
  try {
    const engagement = await api('/api/engagements/' + encodeURIComponent(engagementId));
    if (!engagement || engagement.id !== engagementId || !Array.isArray(engagement.tests)) {
      throw new Error('Kontrol listesi alınamadı.');
    }
    controlSelect.innerHTML = '<option value="">Test adımı seçin</option>'
      + engagement.tests.map(test => '<option value="' + esc(test.control_id) + '">' + esc(test.control_id) + ' · ' + esc(test.title) + '</option>').join('');
    if (!engagement.tests.length) {
      controlSelect.innerHTML = '<option value="">Denetimde test adımı yok</option>';
    }
  } catch {
    controlSelect.innerHTML = '<option value="">Test adımları yüklenemedi</option>';
    return;
  } finally {
    controlSelect.disabled = false;
  }
}

function clearBurpXmlModal() {
  const pasteInput = document.getElementById("burp-xml-paste");
  const fileInput = document.getElementById("burp-xml-file");
  const errorEl = document.getElementById("burp-xml-preview-error");
  const resultEl = document.getElementById("burp-xml-preview-result");

  pasteInput.value = "";
  fileInput.value = "";
  errorEl.textContent = "";
  errorEl.classList.add("hidden");
  resultEl.classList.add("hidden");

  document.getElementById("burp-xml-format").textContent = "";
  document.getElementById("burp-xml-item-count").textContent = "";
  document.getElementById("burp-xml-status-counts").textContent = "";
  document.getElementById("burp-xml-mimetype-counts").textContent = "";
  document.getElementById("burp-xml-report-sha256").textContent = "";
  renderBurpXmlEngagementOptions();
}

document.addEventListener("click", async event => {
  const action = event.target.closest("[data-action]");
  if (action && action.dataset.action === "open-burp-xml-preview") {
    event.preventDefault();
    renderBurpXmlEngagementOptions();
    showModal("burp-xml-preview-modal", true);
    return;
  }

  const close = event.target.closest("[data-close]");
  if (close && close.dataset.close === "burp-xml-preview-modal") {
    event.preventDefault();
    clearBurpXmlModal();
    showModal("burp-xml-preview-modal", false);
    return;
  }

  if (event.target.id === "burp-xml-preview-modal") {
    event.preventDefault();
    clearBurpXmlModal();
    showModal("burp-xml-preview-modal", false);
    return;
  }
});

document.addEventListener("change", async event => {
  if (event.target.id === "burp-xml-link-opt-in") {
    const fields = document.getElementById("burp-xml-link-fields");
    const availability = document.getElementById("burp-xml-link-availability");
    fields.classList.toggle("hidden", !event.target.checked);
    availability.classList.toggle("hidden", Boolean(event.target.checked));
    if (event.target.checked && !burpXmlEligibleEngagements().length) {
      event.target.checked = false;
      fields.classList.add("hidden");
      availability.classList.remove("hidden");
    }
    return;
  }
  if (event.target.id === "burp-xml-link-engagement") {
    await loadBurpXmlControls(event.target.value);
  }
});

document.addEventListener("submit", async event => {
  if (event.target.id !== "burp-xml-preview-form") return;
  event.preventDefault();

  const pasteInput = document.getElementById("burp-xml-paste");
  const fileInput = document.getElementById("burp-xml-file");
  const errorEl = document.getElementById("burp-xml-preview-error");
  const resultEl = document.getElementById("burp-xml-preview-result");
  const linkOptIn = document.getElementById("burp-xml-link-opt-in");
  const linkEngagement = document.getElementById("burp-xml-link-engagement");
  const linkControl = document.getElementById("burp-xml-link-control");
  const linkResult = document.getElementById("burp-xml-link-result");

  errorEl.textContent = "";
  errorEl.classList.add("hidden");
  resultEl.classList.add("hidden");
  linkResult.textContent = "";
  linkResult.classList.add("hidden");

  let rawContent = pasteInput.value.trim();

  if (!rawContent) {
    const file = fileInput.files[0];
    if (file) {
      // Check file.size BEFORE reading
      if (file.size > 60000) {
        errorEl.textContent = "Girdi çok büyük (maksimum 60 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      try {
        rawContent = await file.text();
      } catch {
        errorEl.textContent = "Dosya okuma hatası.";
        errorEl.classList.remove("hidden");
        return;
      }
    }
  }

  if (!rawContent) {
    errorEl.textContent = "Lütfen XML yapıştırın veya bir dosya seçin.";
    errorEl.classList.remove("hidden");
    return;
  }

  const encoder = new TextEncoder();
  if (encoder.encode(rawContent).length > 60000) {
    errorEl.textContent = "Girdi çok büyük (maksimum 60 KB).";
    errorEl.classList.remove("hidden");
    return;
  }

  const eligible = burpXmlEligibleEngagements();
  if (linkOptIn.checked && (!eligible.some(item => item.id === linkEngagement.value) || !linkControl.value)) {
    errorEl.textContent = "Kanıt bağlamak için etkin denetimi ve test adımını seçin.";
    errorEl.classList.remove("hidden");
    return;
  }

  try {
    let data;
    if (linkOptIn.checked) {
      const linkBody = JSON.stringify({ control_id: linkControl.value, report: rawContent, confirm_link: true });
      if (encoder.encode(linkBody).length > 65536) {
        errorEl.textContent = "Girdi çok büyük (maksimum 60 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      data = await api("/api/engagements/" + encodeURIComponent(linkEngagement.value) + "/tool-evidence/burp-sitemap-xml", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: linkBody
      });
    } else {
      data = await api("/api/tool-reports/burp-sitemap/summary", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: rawContent })
      });
    }

    const format = linkOptIn.checked
      ? (data.tool_identity === "burp-sitemap-xml" ? "burp-sitemap-xml" : "")
      : (data.format === "burp-sitemap-xml" ? "burp-sitemap-xml" : "");
    const itemCount = Number.isSafeInteger(data.item_count) && data.item_count >= 0 && data.item_count <= 500 ? data.item_count : null;
    const statusCounts = data.status_counts;
    const mimetypeCounts = data.mimetype_counts;
    const reportSha256 = typeof data.report_sha256 === "string" && /^[a-f0-9]{64}$/.test(data.report_sha256) ? data.report_sha256 : "";

    const isValidFormat = format === "burp-sitemap-xml";
    const isValidItemCount = itemCount !== null;

    // Validate status_counts: keys must be 100..599, values safe integers >=0, sum equals itemCount
    const isValidStatusCounts = statusCounts && typeof statusCounts === "object" && !Array.isArray(statusCounts);
    const statusKeys = isValidStatusCounts ? Object.keys(statusCounts) : [];
    const isValidStatusKeys = isValidStatusCounts && statusKeys.every(k => /^[1-5]\d{2}$/.test(k) && typeof statusCounts[k] === "number" && Number.isSafeInteger(statusCounts[k]) && statusCounts[k] >= 0);
    const statusSum = isValidStatusKeys ? statusKeys.reduce((sum, k) => sum + statusCounts[k], 0) : null;
    const isValidStatusSum = statusSum === itemCount;

    // Validate mimetype_counts: EXACTLY five keys, no extras, safe integer counts >=0
    const isValidMimetypeCounts = mimetypeCounts && typeof mimetypeCounts === "object" && !Array.isArray(mimetypeCounts);
    const mimeKeys = isValidMimetypeCounts ? Object.keys(mimetypeCounts) : [];
    const requiredMimeKeys = ["HTML", "JSON", "XML", "OTHER", "UNKNOWN"];
    const isValidMimeKeys = isValidMimetypeCounts &&
      requiredMimeKeys.every(k => typeof mimetypeCounts[k] === "number" && Number.isSafeInteger(mimetypeCounts[k]) && mimetypeCounts[k] >= 0) &&
      mimeKeys.length === requiredMimeKeys.length &&
      requiredMimeKeys.every(k => mimeKeys.includes(k));
    const mimeSum = isValidMimeKeys ? (mimetypeCounts["HTML"] || 0) + (mimetypeCounts["JSON"] || 0) + (mimetypeCounts["XML"] || 0) + (mimetypeCounts["OTHER"] || 0) + (mimetypeCounts["UNKNOWN"] || 0) : null;
    const isValidMimeSum = mimeSum === itemCount;

    const isValidReportSha256 = reportSha256 !== "";

    if (!isValidFormat || !isValidItemCount || !isValidStatusSum || !isValidMimeSum || !isValidReportSha256) {
      errorEl.textContent = "Sunucu hatası.";
      errorEl.classList.remove("hidden");
      return;
    }

    document.getElementById("burp-xml-format").textContent = format;
    document.getElementById("burp-xml-item-count").textContent = itemCount;
    document.getElementById("burp-xml-status-counts").textContent = Object.keys(statusCounts).sort().map(k => `${k}:${statusCounts[k]}`).join(" ");
    document.getElementById("burp-xml-mimetype-counts").textContent = `HTML:${mimetypeCounts.HTML} JSON:${mimetypeCounts.JSON} XML:${mimetypeCounts.XML} OTHER:${mimetypeCounts.OTHER} UNKNOWN:${mimetypeCounts.UNKNOWN}`;
    document.getElementById("burp-xml-report-sha256").textContent = reportSha256;

    resultEl.classList.remove("hidden");

    if (linkOptIn.checked) {
      linkResult.textContent = "Toplu özet " + linkControl.value + " test adımına kaydedildi. İnceleme sonucu ayrı olarak doğrulanmalıdır; kaynak XML saklanmaz ve SHA-256 hedef/provenans kanıtı değildir.";
      linkResult.classList.remove("hidden");
    }
    pasteInput.value = "";
    fileInput.value = "";
  } catch {
    // Generic catch: do not expose server error text
    errorEl.textContent = "Sunucu hatası.";
    errorEl.classList.remove("hidden");
  }
});
// Testssl flat JSON preview and explicit aggregate-evidence linking UI.
let testsslControlsGeneration = 0;
let testsslPreviewGeneration = 0;
function testsslEligibleEngagements() {
  return (Array.isArray(state.engagements) ? state.engagements : []).filter(item => item.status === 'active'
    && typeof item.authorization_ref === 'string' && item.authorization_ref.trim()
    && typeof item.scope_notes === 'string' && item.scope_notes.trim()
    && item.special_approvals?.redacted_data_proof === true);
}

function renderTestsslEngagementOptions() {
  testsslControlsGeneration += 1;
  testsslPreviewGeneration += 1;
  const optIn = document.getElementById('testssl-link-opt-in');
  const fields = document.getElementById('testssl-link-fields');
  const engagementSelect = document.getElementById('testssl-link-engagement');
  const controlSelect = document.getElementById('testssl-link-control');
  const availability = document.getElementById('testssl-link-availability');
  const linkResult = document.getElementById('testssl-link-result');
  const eligible = testsslEligibleEngagements();

  optIn.checked = false;
  optIn.disabled = eligible.length === 0;
  fields.classList.add('hidden');
  engagementSelect.innerHTML = '<option value="">' + (eligible.length ? 'Denetim seçin' : 'Uygun denetim yok') + '</option>'
    + eligible.map(item => '<option value="' + esc(item.id) + '">' + esc(item.name) + ' · ' + esc(item.authorization_ref) + '</option>').join('');
  controlSelect.innerHTML = '<option value="">Önce denetim seçin</option>';
  controlSelect.disabled = true;
  linkResult.textContent = '';
  linkResult.classList.add('hidden');
  availability.textContent = eligible.length
    ? 'Bağlama isteğe bağlıdır. Etkin, yetki referansı, kapsam notu ve maskeli kanıt onayı bulunan denetimler listelenir.'
    : 'Bağlama için etkin, yetki referansı, kapsam notu ve maskeli kanıt onayı gerekir. Bağlantısız özet yine kullanılabilir.';
  availability.classList.remove('hidden');
}

async function loadTestsslControls(engagementId) {
  const requestGeneration = ++testsslControlsGeneration;
  const engagementSelect = document.getElementById('testssl-link-engagement');
  const controlSelect = document.getElementById('testssl-link-control');
  const isCurrent = () => requestGeneration === testsslControlsGeneration &&
    engagementSelect.value === engagementId;
  const selected = testsslEligibleEngagements().find(item => item.id === engagementId);
  controlSelect.disabled = true;
  controlSelect.innerHTML = '<option value="">Kontroller yükleniyor…</option>';
  if (!selected) {
    controlSelect.innerHTML = '<option value="">Etkin ve yetkili denetim seçin</option>';
    return;
  }
  try {
    const engagement = await api('/api/engagements/' + encodeURIComponent(engagementId));
    if (!isCurrent()) return;
    if (!engagement || engagement.id !== engagementId || !Array.isArray(engagement.tests)) {
      throw new Error('Kontrol listesi alınamadı.');
    }
    controlSelect.innerHTML = '<option value="">Test adımı seçin</option>'
      + engagement.tests.map(item => '<option value="' + esc(item.control_id) + '">' + esc(item.control_id) + ' · ' + esc(item.title) + '</option>').join('');
    if (!engagement.tests.length) controlSelect.innerHTML = '<option value="">Denetimde test adımı yok</option>';
  } catch {
    if (isCurrent()) controlSelect.innerHTML = '<option value="">Test adımları yüklenemedi</option>';
  } finally {
    if (isCurrent()) controlSelect.disabled = false;
  }
}

function clearTestsslPreviewModal() {
  testsslPreviewGeneration += 1;
  const pasteInput = document.getElementById("testssl-paste");
  const fileInput = document.getElementById("testssl-file");
  const errorEl = document.getElementById("testssl-preview-error");
  const resultEl = document.getElementById("testssl-preview-result");

  if (pasteInput) pasteInput.value = "";
  if (fileInput) fileInput.value = "";
  if (errorEl) {
    errorEl.textContent = "";
    errorEl.classList.add("hidden");
  }
  if (resultEl) resultEl.classList.add("hidden");
  for (const id of ["testssl-format", "testssl-record-count", "testssl-severity-counts", "testssl-report-sha256"]) {
    const item = document.getElementById(id);
    if (item) item.textContent = "";
  }
  const controlSelect = document.getElementById("testssl-link-control");
  if (controlSelect) {
    controlSelect.innerHTML = '<option value="">Önce denetim seçin</option>';
    controlSelect.disabled = true;
  }
  renderTestsslEngagementOptions();
}

document.addEventListener("click", async event => {
  const action = event.target.closest("[data-action]");
  if (action && action.dataset.action === "open-testssl-flat-preview") {
    event.preventDefault();
    renderTestsslEngagementOptions();
    showModal("testssl-preview-modal", true);
    return;
  }
  const close = event.target.closest("[data-close]");
  if (close && close.dataset.close === "testssl-preview-modal") {
    event.preventDefault();
    showModal("testssl-preview-modal", false);
    return;
  }
  if (event.target.id === "testssl-preview-modal") {
    event.preventDefault();
    showModal("testssl-preview-modal", false);
  }
});

document.addEventListener("change", async event => {
  if (["testssl-link-opt-in", "testssl-link-engagement", "testssl-link-control", "testssl-file"].includes(event.target.id)) testsslPreviewGeneration += 1;
  if (event.target.id === "testssl-link-opt-in") {
    const fields = document.getElementById("testssl-link-fields");
    const availability = document.getElementById("testssl-link-availability");
    fields.classList.toggle("hidden", !event.target.checked);
    availability.classList.toggle("hidden", Boolean(event.target.checked));
    if (event.target.checked && !testsslEligibleEngagements().length) {
      event.target.checked = false;
      fields.classList.add("hidden");
      availability.classList.remove("hidden");
    }
    if (!event.target.checked) {
      testsslControlsGeneration += 1;
      const controlSelect = document.getElementById("testssl-link-control");
      controlSelect.innerHTML = '<option value="">Önce denetim seçin</option>';
      controlSelect.disabled = true;
    } else {
      const engagementId = document.getElementById("testssl-link-engagement").value;
      if (engagementId) await loadTestsslControls(engagementId);
    }
    return;
  }
  if (event.target.id === "testssl-link-engagement") await loadTestsslControls(event.target.value);
});

document.addEventListener("input", event => {
  if (event.target.id === "testssl-paste") testsslPreviewGeneration += 1;
});

document.addEventListener("submit", async event => {
  if (event.target.id !== "testssl-preview-form") return;
  event.preventDefault();
  const requestGeneration = ++testsslPreviewGeneration;
  const isCurrentPreview = () => requestGeneration === testsslPreviewGeneration;
  const pasteInput = document.getElementById("testssl-paste");
  const fileInput = document.getElementById("testssl-file");
  const errorEl = document.getElementById("testssl-preview-error");
  const resultEl = document.getElementById("testssl-preview-result");
  const linkOptIn = document.getElementById("testssl-link-opt-in");
  const linkEngagement = document.getElementById("testssl-link-engagement");
  const linkControl = document.getElementById("testssl-link-control");
  const linkResult = document.getElementById("testssl-link-result");
  errorEl.textContent = "";
  errorEl.classList.add("hidden");
  resultEl.classList.add("hidden");
  linkResult.textContent = "";
  linkResult.classList.add("hidden");

  let rawContent = pasteInput.value.trim();
  if (!rawContent) {
    const file = fileInput.files[0];
    if (file) {
      if (file.size > 60000) {
        errorEl.textContent = "Girdi çok büyük (maksimum 60 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      try {
        rawContent = await file.text();
        if (!isCurrentPreview()) return;
      } catch {
        if (!isCurrentPreview()) return;
        errorEl.textContent = "Dosya okuma hatası.";
        errorEl.classList.remove("hidden");
        return;
      }
    }
  }
  if (!rawContent) {
    errorEl.textContent = "Lütfen JSON yapıştırın veya bir dosya seçin.";
    errorEl.classList.remove("hidden");
    return;
  }
  const encoder = new TextEncoder();
  if (encoder.encode(rawContent).length > 60000) {
    errorEl.textContent = "Girdi çok büyük (maksimum 60 KB).";
    errorEl.classList.remove("hidden");
    return;
  }

  let report;
  try {
    report = JSON.parse(rawContent);
  } catch {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }
  if (!Array.isArray(report)) {
    errorEl.textContent = "Geçersiz JSON yapısı (dizi bekleniyor).";
    errorEl.classList.remove("hidden");
    return;
  }
  if (report.length > 500) {
    errorEl.textContent = "Kayıt sayısı çok fazla (maksimum 500).";
    errorEl.classList.remove("hidden");
    return;
  }
  const eligible = testsslEligibleEngagements();
  const linkRequested = linkOptIn.checked;
  const selectedEngagement = linkEngagement.value;
  const selectedControl = linkControl.value;
  if (linkRequested && (!eligible.some(item => item.id === selectedEngagement) || !selectedControl)) {
    errorEl.textContent = "Kanıt bağlamak için etkin denetimi ve test adımını seçin.";
    errorEl.classList.remove("hidden");
    return;
  }

  try {
    let data;
    if (linkRequested) {
      const body = JSON.stringify({ control_id: selectedControl, report, confirm_link: true });
      if (encoder.encode(body).length > 65536) {
        errorEl.textContent = "Girdi çok büyük (maksimum 60 KB).";
        errorEl.classList.remove("hidden");
        return;
      }
      data = await api("/api/engagements/" + encodeURIComponent(selectedEngagement) + "/tool-evidence/testssl-flat-json", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
      });
    } else {
      data = await api("/api/tool-reports/testssl/summary", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report })
      });
    }

    if (!isCurrentPreview()) return;
    const format = linkRequested
      ? (data.tool_identity === "testssl-flat-json" ? "testssl-flat-json" : "")
      : (data.format === "testssl-flat-json" ? "testssl-flat-json" : "");
    const recordCount = Number.isSafeInteger(data.record_count) && data.record_count >= 0 && data.record_count <= 500 ? data.record_count : null;
    const severityCounts = data.severity_counts;
    const reportSha256 = typeof data.report_sha256 === "string" && /^[a-f0-9]{64}$/.test(data.report_sha256) ? data.report_sha256 : "";
    const severityKeys = ["INFO", "OK", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN", "DEBUG", "FATAL"];
    const actualKeys = severityCounts ? Object.keys(severityCounts) : [];
    const validCounts = severityCounts && typeof severityCounts === "object" && !Array.isArray(severityCounts)
      && severityKeys.every(key => typeof severityCounts[key] === "number" && Number.isSafeInteger(severityCounts[key]) && severityCounts[key] >= 0)
      && actualKeys.length === severityKeys.length && severityKeys.every(key => actualKeys.includes(key))
      && severityKeys.reduce((sum, key) => sum + severityCounts[key], 0) === recordCount;
    if (!format || recordCount === null || !validCounts || !reportSha256) {
      errorEl.textContent = "Sunucu hatası.";
      errorEl.classList.remove("hidden");
      return;
    }
    document.getElementById("testssl-format").textContent = format;
    document.getElementById("testssl-record-count").textContent = recordCount;
    document.getElementById("testssl-severity-counts").textContent = severityKeys.map(key => key + ":" + severityCounts[key]).join(" ");
    document.getElementById("testssl-report-sha256").textContent = reportSha256;
    resultEl.classList.remove("hidden");
    if (linkRequested) {
      linkResult.textContent = "Toplu özet " + selectedControl + " test adımına bağlandı; uzman incelemesi gerekir. Ham rapor saklanmaz ve SHA-256 hedef/provenans kanıtı değildir.";
      linkResult.classList.remove("hidden");
    }
    pasteInput.value = "";
    fileInput.value = "";
  } catch {
    if (!isCurrentPreview()) return;
    errorEl.textContent = "Sunucu hatası.";
    errorEl.classList.remove("hidden");
  }
});

function gitleaksTrivyEligibleEngagements() {
  return (Array.isArray(state.engagements) ? state.engagements : []).filter(item =>
    item &&
    item.status === "active" &&
    typeof item.authorization_ref === "string" &&
    Boolean(item.authorization_ref.trim()) &&
    item.special_approvals?.redacted_data_proof === true
  );
}

let gitleaksPreviewGeneration = 0;
let gitleaksControlsGeneration = 0;

function renderGitleaksEngagementOptions() {
  gitleaksControlsGeneration += 1;
  const optIn = document.getElementById("gitleaks-link-opt-in");
  const fields = document.getElementById("gitleaks-link-fields");
  const engagementSelect = document.getElementById("gitleaks-link-engagement");
  const controlSelect = document.getElementById("gitleaks-link-control");
  const availability = document.getElementById("gitleaks-link-availability");
  const linkResult = document.getElementById("gitleaks-link-result");
  const eligible = gitleaksTrivyEligibleEngagements();

  optIn.checked = false;
  optIn.disabled = eligible.length === 0;
  fields.classList.add("hidden");
  engagementSelect.innerHTML = '<option value="">' + (eligible.length ? "Denetim seçin" : "Uygun denetim yok") + "</option>"
    + eligible.map(item => '<option value="' + esc(item.id) + '">' + esc(item.name) + " · " + esc(item.authorization_ref) + "</option>").join("");
  engagementSelect.value = "";
  controlSelect.innerHTML = '<option value="">Önce denetim seçin</option>';
  controlSelect.value = "";
  controlSelect.disabled = true;
  linkResult.textContent = "";
  linkResult.classList.add("hidden");
  availability.textContent = eligible.length
    ? "Bağlama isteğe bağlıdır. Etkin, yetki referansı ve maskeli kanıt onayı bulunan denetimler listelenir."
    : "Bağlama için etkin, yetki referansı ve maskeli kanıt onayı gerekir. Bağlantısız özet yine kullanılabilir.";
  availability.classList.remove("hidden");
}

async function loadGitleaksControls(engagementId) {
  const requestGeneration = ++gitleaksControlsGeneration;
  const controlSelect = document.getElementById("gitleaks-link-control");
  const selected = gitleaksTrivyEligibleEngagements().find(item => item.id === engagementId);
  controlSelect.disabled = true;
  controlSelect.innerHTML = '<option value="">Kontroller yükleniyor…</option>';
  if (!selected) {
    controlSelect.innerHTML = '<option value="">Etkin ve yetkili denetim seçin</option>';
    return;
  }
  try {
    const engagement = await api("/api/engagements/" + encodeURIComponent(engagementId));
    if (requestGeneration !== gitleaksControlsGeneration) return;
    if (!engagement || engagement.id !== engagementId || !Array.isArray(engagement.tests)) {
      throw new Error("Kontrol listesi alınamadı.");
    }
    controlSelect.innerHTML = '<option value="">Test adımı seçin</option>'
      + engagement.tests.map(item => '<option value="' + esc(item.control_id) + '">' + esc(item.control_id) + " · " + esc(item.title) + "</option>").join("");
    if (!engagement.tests.length) controlSelect.innerHTML = '<option value="">Denetimde test adımı yok</option>';
  } catch {
    if (requestGeneration !== gitleaksControlsGeneration) return;
    controlSelect.innerHTML = '<option value="">Test adımları yüklenemedi</option>';
    return;
  } finally {
    if (requestGeneration === gitleaksControlsGeneration) {
      controlSelect.disabled = false;
    }
  }
}

document.addEventListener("click", (e) => {
  const action = e.target.closest("[data-action]");
  if (action && action.dataset.action === "open-gitleaks-json-preview") {
    e.preventDefault();
    clearGitleaksPreview();
    showModal("gitleaks-preview-modal", true);
    return;
  }
  const close = e.target.closest("[data-close]");
  if (close && close.dataset.close === "gitleaks-preview-modal") {
    e.preventDefault();
    if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
    showModal("gitleaks-preview-modal", false);
    return;
  }
  if (e.target.id === "gitleaks-preview-modal") {
    e.preventDefault();
    if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
    showModal("gitleaks-preview-modal", false);
  }
});

document.addEventListener("change", async (event) => {
  if (event.target.id === "gitleaks-link-opt-in") {
    const fields = document.getElementById("gitleaks-link-fields");
    const availability = document.getElementById("gitleaks-link-availability");
    fields.classList.toggle("hidden", !event.target.checked);
    availability.classList.toggle("hidden", Boolean(event.target.checked));
    if (event.target.checked && !gitleaksTrivyEligibleEngagements().length) {
      event.target.checked = false;
      fields.classList.add("hidden");
      availability.classList.remove("hidden");
    }
    return;
  }
  if (event.target.id === "gitleaks-link-engagement") {
    await loadGitleaksControls(event.target.value);
  }
});

document.addEventListener("submit", async (e) => {
  if (e.target.id !== "gitleaks-preview-form") return;
  e.preventDefault();

  const requestGeneration = ++gitleaksPreviewGeneration;
  const modalEl = document.getElementById("gitleaks-preview-modal");
  const wasModalHiddenAtStart = Boolean(modalEl && modalEl.classList.contains("hidden"));
  const isStaleRequest = () =>
    requestGeneration !== gitleaksPreviewGeneration ||
    Boolean(modalEl && !wasModalHiddenAtStart && modalEl.classList.contains("hidden"));

  const pasteInput = document.getElementById("gitleaks-paste");
  const fileInput = document.getElementById("gitleaks-file");
  const errorEl = document.getElementById("gitleaks-preview-error");
  const resultEl = document.getElementById("gitleaks-preview-result");
  const linkOptIn = document.getElementById("gitleaks-link-opt-in");
  const linkEngagement = document.getElementById("gitleaks-link-engagement");
  const linkControl = document.getElementById("gitleaks-link-control");
  const linkResult = document.getElementById("gitleaks-link-result");

  errorEl.textContent = "";
  errorEl.classList.add("hidden");
  resultEl.classList.add("hidden");
  linkResult.textContent = "";
  linkResult.classList.add("hidden");

  let raw = pasteInput.value.trim();
  if (!raw && fileInput.files && fileInput.files[0]) {
    const file = fileInput.files[0];
    if (file.size > 60000) {
      errorEl.textContent = "Dosya çok büyük (en fazla 60000 bayt)";
      errorEl.classList.remove("hidden");
      return;
    }
    try {
      raw = await file.text();
    } catch {
      if (isStaleRequest()) return;
      errorEl.textContent = "Dosya okunamadı";
      errorEl.classList.remove("hidden");
      return;
    }
    if (isStaleRequest()) return;
  }

  if (!raw) {
    errorEl.textContent = "Geçerli bir JSON yapıştırın veya dosya seçin";
    errorEl.classList.remove("hidden");
    return;
  }

  const encoder = new TextEncoder();
  if (encoder.encode(raw).length > 60000) {
    errorEl.textContent = "Girdi en büyük boyutu aşıyor (60000 UTF-8 bayt)";
    errorEl.classList.remove("hidden");
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    errorEl.textContent = "Invalid JSON";
    errorEl.classList.remove("hidden");
    return;
  }

  if (!Array.isArray(parsed)) {
    errorEl.textContent = "Rapor bir JSON dizisi olmalıdır";
    errorEl.classList.remove("hidden");
    return;
  }

  if (parsed.length > 500) {
    errorEl.textContent = "Çok fazla bulgu (en fazla 500)";
    errorEl.classList.remove("hidden");
    return;
  }

  const linking = Boolean(linkOptIn.checked);
  const selectedEngagementId = linkEngagement.value;
  const selectedControlId = linkControl.value;
  const eligible = gitleaksTrivyEligibleEngagements();
  if (linking && (!eligible.some(item => item.id === selectedEngagementId) || !selectedControlId)) {
    errorEl.textContent = "Kanıt bağlamak için etkin denetimi ve test adımını seçin.";
    errorEl.classList.remove("hidden");
    return;
  }

  try {
    let response;
    if (linking) {
      const linkBody = JSON.stringify({ control_id: selectedControlId, report: parsed, confirm_link: true });
      if (encoder.encode(linkBody).length > 65536) {
        errorEl.textContent = "Girdi en büyük boyutu aşıyor (60000 UTF-8 bayt)";
        errorEl.classList.remove("hidden");
        return;
      }
      response = await api("/api/engagements/" + encodeURIComponent(selectedEngagementId) + "/tool-evidence/gitleaks-native-json", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: linkBody
      });
    } else {
      response = await api("/api/tool-reports/gitleaks/summary", {
        method: "POST",
        body: JSON.stringify({ report: parsed })
      });
    }

    if (isStaleRequest()) return;

    const format = linking
      ? (response && response.tool_identity === "gitleaks-native-json" ? "gitleaks-native-json" : "")
      : (response && response.format === "gitleaks-native-json" ? "gitleaks-native-json" : "");
    const reportSha256 = response && typeof response.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(response.report_sha256)
      ? response.report_sha256
      : "";
    const validSha = linking ? reportSha256 !== "" : true;

    if (response &&
        format === "gitleaks-native-json" &&
        validSha &&
        Number.isSafeInteger(response.total_findings) &&
        Number.isSafeInteger(response.rules_triggered) &&
        Number.isSafeInteger(response.files_affected) &&
        response.total_findings >= 0 &&
        response.rules_triggered >= 0 &&
        response.files_affected >= 0 &&
        response.total_findings <= 500 &&
        response.total_findings === parsed.length &&
        response.rules_triggered <= response.total_findings &&
        response.files_affected <= response.total_findings) {
      document.getElementById("gitleaks-format").textContent = format;
      document.getElementById("gitleaks-total-findings").textContent = String(response.total_findings);
      document.getElementById("gitleaks-rules-triggered").textContent = String(response.rules_triggered);
      document.getElementById("gitleaks-files-affected").textContent = String(response.files_affected);
      document.getElementById("gitleaks-report-sha256").textContent = reportSha256;
      resultEl.classList.remove("hidden");
      if (linking) {
        linkResult.textContent = "Toplu özet " + selectedControlId + " test adımına bağlandı; uzman incelemesi gerekir. Ham rapor saklanmaz ve SHA-256 hedef/provenans kanıtı değildir.";
        linkResult.classList.remove("hidden");
      }
      pasteInput.value = "";
      fileInput.value = "";
      if (Array.isArray(fileInput.files)) fileInput.files = [];
    } else {
      errorEl.textContent = "Sunucudan geçersiz yanıt alındı";
      errorEl.classList.remove("hidden");
    }
  } catch {
    if (isStaleRequest()) return;
    errorEl.textContent = "İşlem başarısız oldu";
    errorEl.classList.remove("hidden");
  }
});

function isGitleaksPreviewDirty() {
  const fileInput = document.getElementById("gitleaks-file");
  return Boolean(
    document.getElementById("gitleaks-paste")?.value ||
    fileInput?.value ||
    fileInput?.files?.length ||
    document.getElementById("gitleaks-link-opt-in")?.checked ||
    document.getElementById("gitleaks-link-fields")?.classList?.contains("hidden") === false ||
    document.getElementById("gitleaks-link-engagement")?.value ||
    document.getElementById("gitleaks-link-control")?.value ||
    document.getElementById("gitleaks-link-control")?.disabled === false ||
    document.getElementById("gitleaks-link-result")?.textContent ||
    document.getElementById("gitleaks-link-result")?.classList?.contains("hidden") === false ||
    document.getElementById("gitleaks-preview-error")?.textContent ||
    document.getElementById("gitleaks-preview-error")?.classList?.contains("hidden") === false ||
    document.getElementById("gitleaks-preview-result")?.classList?.contains("hidden") === false ||
    document.getElementById("gitleaks-total-findings")?.textContent ||
    document.getElementById("gitleaks-rules-triggered")?.textContent ||
    document.getElementById("gitleaks-files-affected")?.textContent ||
    document.getElementById("gitleaks-format")?.textContent ||
    document.getElementById("gitleaks-report-sha256")?.textContent
  );
}

function clearGitleaksPreview() {
  gitleaksPreviewGeneration += 1;
  const pasteInput = document.getElementById("gitleaks-paste");
  const fileInput = document.getElementById("gitleaks-file");
  pasteInput.value = "";
  fileInput.value = "";
  if (Array.isArray(fileInput.files)) fileInput.files = [];
  document.getElementById("gitleaks-preview-error").textContent = "";
  document.getElementById("gitleaks-preview-error").classList.add("hidden");
  document.getElementById("gitleaks-preview-result").classList.add("hidden");
  document.getElementById("gitleaks-total-findings").textContent = "";
  document.getElementById("gitleaks-rules-triggered").textContent = "";
  document.getElementById("gitleaks-files-affected").textContent = "";
  document.getElementById("gitleaks-format").textContent = "";
  document.getElementById("gitleaks-report-sha256").textContent = "";
  renderGitleaksEngagementOptions();
}

document.addEventListener("click", (e) => {
  const action = e.target.closest("[data-action]");
  if (action && action.dataset.action === "open-dependabot-alerts-preview") {
    e.preventDefault();
    clearDependabotPreviewResult();
    showModal("dependabot-preview-modal", true);
    return;
  }
  const close = e.target.closest("[data-close]");
  if (close && close.dataset.close === "dependabot-preview-modal") {
    e.preventDefault();
    clearDependabotPreview();
    showModal("dependabot-preview-modal", false);
    return;
  }
  if (e.target.id === "dependabot-preview-modal") {
    e.preventDefault();
    clearDependabotPreview();
    showModal("dependabot-preview-modal", false);
  }
});

document.addEventListener("submit", async (e) => {
  if (e.target.id !== "dependabot-preview-form") return;
  e.preventDefault();

  const pasteInput = document.getElementById("dependabot-paste");
  const fileInput = document.getElementById("dependabot-file");
  const errorEl = document.getElementById("dependabot-preview-error");
  const resultEl = document.getElementById("dependabot-preview-result");

  clearDependabotPreviewResult();

  let raw = pasteInput.value.trim();
  if (!raw && fileInput.files && fileInput.files[0]) {
    const file = fileInput.files[0];
    if (file.size > 60000) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    try {
      raw = await file.text();
    } catch {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
  }

  if (!raw) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  const encoder = new TextEncoder();
  if (encoder.encode(raw).length > 60000) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  const alerts = parsed.alerts;
  if (!Array.isArray(alerts)) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  if (alerts.length > 500) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  const payload = JSON.stringify({ alerts: alerts });

  try {
    const data = await api("/api/tool-reports/dependabot/summary", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload
    });

    const format = data.format === "dependabot-alerts" ? "dependabot-alerts" : "";
    const alertCount = Number.isSafeInteger(data.alert_count) && data.alert_count >= 0 && data.alert_count <= 500 ? data.alert_count : null;
    const stateCounts = data.state_counts;
    const severityCounts = data.severity_counts;
    const reportSha256 = typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256) ? data.report_sha256 : "";

    const isValidFormat = format === "dependabot-alerts";
    const isValidAlertCount = alertCount !== null;

    const stateKeys = ["open", "dismissed", "fixed", "auto_dismissed"];
    const isValidStateCounts = stateCounts && typeof stateCounts === "object" && !Array.isArray(stateCounts);
    const actualStateKeys = stateCounts ? Object.keys(stateCounts) : [];
    const isValidStateKeys = isValidStateCounts &&
      stateKeys.every(k => typeof stateCounts[k] === "number" && Number.isSafeInteger(stateCounts[k]) && stateCounts[k] >= 0) &&
      actualStateKeys.length === stateKeys.length &&
      stateKeys.every(k => actualStateKeys.includes(k));
    const stateSum = isValidStateKeys ? stateKeys.reduce((sum, k) => sum + stateCounts[k], 0) : null;
    const isValidStateSum = stateSum === alertCount;

    const severityKeys = ["low", "medium", "high", "critical"];
    const isValidSeverityCounts = severityCounts && typeof severityCounts === "object" && !Array.isArray(severityCounts);
    const actualSeverityKeys = severityCounts ? Object.keys(severityCounts) : [];
    const isValidSeverityKeys = isValidSeverityCounts &&
      severityKeys.every(k => typeof severityCounts[k] === "number" && Number.isSafeInteger(severityCounts[k]) && severityCounts[k] >= 0) &&
      actualSeverityKeys.length === severityKeys.length &&
      severityKeys.every(k => actualSeverityKeys.includes(k));
    const severitySum = isValidSeverityKeys ? severityKeys.reduce((sum, k) => sum + severityCounts[k], 0) : null;
    const isValidSeveritySum = severitySum === alertCount;

    const openPatchableRaw = data.open_alerts_with_available_patched_version;
    const openPatchableCount =
      typeof openPatchableRaw === "number" &&
      Number.isSafeInteger(openPatchableRaw) &&
      openPatchableRaw >= 0 &&
      isValidStateKeys &&
      isValidAlertCount &&
      openPatchableRaw <= stateCounts.open &&
      openPatchableRaw <= alertCount
        ? openPatchableRaw
        : null;
    const isValidOpenPatchableCount = openPatchableCount !== null;

    const isValidReportSha256 = reportSha256 !== "";

    if (!isValidFormat || !isValidAlertCount || !isValidStateSum || !isValidSeveritySum || !isValidOpenPatchableCount || !isValidReportSha256) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }

    if (document.getElementById("dependabot-format")) document.getElementById("dependabot-format").textContent = format;
    if (document.getElementById("dependabot-alert-count")) document.getElementById("dependabot-alert-count").textContent = alertCount;
    if (document.getElementById("dependabot-state-counts")) document.getElementById("dependabot-state-counts").textContent = stateKeys.map(k => `${k}:${stateCounts[k]}`).join(" ");
    if (document.getElementById("dependabot-severity-counts")) document.getElementById("dependabot-severity-counts").textContent = severityKeys.map(k => `${k}:${severityCounts[k]}`).join(" ");
    if (document.getElementById("dependabot-open-patchable-count")) document.getElementById("dependabot-open-patchable-count").textContent = String(openPatchableCount);
    if (document.getElementById("dependabot-report-sha256")) document.getElementById("dependabot-report-sha256").textContent = reportSha256;

    if (resultEl) resultEl.classList.remove("hidden");

    pasteInput.value = "";
    fileInput.value = "";
  } catch {
    clearDependabotPreviewResult();
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
  }
});

function clearDependabotPreviewResult() {
  const errorEl = document.getElementById("dependabot-preview-error");
  if (errorEl) {
    errorEl.textContent = "";
    errorEl.classList.add("hidden");
  }
  const resultEl = document.getElementById("dependabot-preview-result");
  if (resultEl) {
    resultEl.classList.add("hidden");
  }
  for (const id of [
    "dependabot-format",
    "dependabot-alert-count",
    "dependabot-state-counts",
    "dependabot-severity-counts",
    "dependabot-open-patchable-count",
    "dependabot-report-sha256"
  ]) {
    const el = document.getElementById(id);
    if (el) el.textContent = "";
  }
}

function clearDependabotPreview() {
  document.getElementById("dependabot-paste").value = "";
  document.getElementById("dependabot-file").value = "";
  clearDependabotPreviewResult();
}

let npmAuditPreviewGeneration=0;document.addEventListener("click",(e)=>{const action=e.target.closest("[data-action]");if(action&&action.dataset.action==="open-npm-audit-preview"){e.preventDefault();npmAuditPreviewGeneration++;showModal("npm-audit-preview-modal",true);return;}const close=e.target.closest("[data-close]");if(close&&close.dataset.close==="npm-audit-preview-modal"){e.preventDefault();showModal("npm-audit-preview-modal",false);return;}if(e.target.id==="npm-audit-preview-modal"){e.preventDefault();showModal("npm-audit-preview-modal",false);}});document.addEventListener("submit",async(e)=>{if(e.target.id!=="npm-audit-preview-form")return;e.preventDefault();const requestGeneration=++npmAuditPreviewGeneration;const isCurrentNpmAuditPreview=()=>requestGeneration===npmAuditPreviewGeneration;const pasteInput=document.getElementById("npm-audit-paste");const fileInput=document.getElementById("npm-audit-file");const errorEl=document.getElementById("npm-audit-preview-error");const resultEl=document.getElementById("npm-audit-preview-result");errorEl.textContent="";errorEl.classList.add("hidden");resultEl.classList.add("hidden");let raw=pasteInput.value.trim();if(!raw&&fileInput.files&&fileInput.files[0]){const file=fileInput.files[0];if(file.size>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{raw=await file.text();if(!isCurrentNpmAuditPreview())return;}catch{if(!isCurrentNpmAuditPreview())return;errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}if(!raw){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const encoder=new TextEncoder();if(encoder.encode(raw).length>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}let parsed;try{parsed=JSON.parse(raw);}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(parsed===null||typeof parsed!=="object"||Array.isArray(parsed)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const version=parsed.auditReportVersion;if(!Number.isInteger(version)||version!==2){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const vulnerabilities=parsed.vulnerabilities;if(!vulnerabilities||typeof vulnerabilities!=="object"||Array.isArray(vulnerabilities)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(Object.keys(vulnerabilities).length>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const payload=JSON.stringify({audit:parsed});try{const data=await api("/api/tool-reports/npm-audit/summary",{method:"POST",headers:{"Content-Type":"application/json"},body:payload});if(!isCurrentNpmAuditPreview())return;const format=data.format;if(format!=="npm-audit-v2"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const affectedPackageCount=data.affected_package_count;if(!Number.isSafeInteger(affectedPackageCount)||affectedPackageCount<0||affectedPackageCount>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const packageSeverityCounts=data.package_severity_counts;if(!packageSeverityCounts||typeof packageSeverityCounts!=="object"||Array.isArray(packageSeverityCounts)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const severityKeys=["info","low","moderate","high","critical"];const actualKeys=Object.keys(packageSeverityCounts);if(actualKeys.length!==severityKeys.length||!severityKeys.every(k=>actualKeys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const sum=severityKeys.reduce((acc,k)=>{const v=packageSeverityCounts[k];if(!Number.isSafeInteger(v)||v<0)throw new Error();return acc+v;},0);if(sum!==affectedPackageCount){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const reportSha256=data.report_sha256;if(typeof reportSha256!=="string"||!/^[0-9a-f]{64}$/.test(reportSha256)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(document.getElementById("npm-audit-format"))document.getElementById("npm-audit-format").textContent="npm-audit-v2";if(document.getElementById("npm-audit-package-count"))document.getElementById("npm-audit-package-count").textContent=affectedPackageCount.toString();if(document.getElementById("npm-audit-severity-counts"))document.getElementById("npm-audit-severity-counts").textContent=severityKeys.map(k=>`${k}:${packageSeverityCounts[k]}`).join(" ");if(document.getElementById("npm-audit-report-sha256"))document.getElementById("npm-audit-report-sha256").textContent=reportSha256;if(resultEl)resultEl.classList.remove("hidden");pasteInput.value="";fileInput.value="";}catch{if(!isCurrentNpmAuditPreview())return;errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");}});function clearNpmAuditPreview(){npmAuditPreviewGeneration++;document.getElementById("npm-audit-paste").value="";document.getElementById("npm-audit-file").value="";document.getElementById("npm-audit-preview-error").textContent="";document.getElementById("npm-audit-preview-error").classList.add("hidden");document.getElementById("npm-audit-preview-result").classList.add("hidden");document.getElementById("npm-audit-package-count").textContent="";document.getElementById("npm-audit-severity-counts").textContent="";document.getElementById("npm-audit-report-sha256").textContent="";document.getElementById("npm-audit-format").textContent="";}

function renderTrivyEngagementOptions() {
  const optIn = document.getElementById("trivy-link-opt-in");
  const fields = document.getElementById("trivy-link-fields");
  const engagementSelect = document.getElementById("trivy-link-engagement");
  const controlSelect = document.getElementById("trivy-link-control");
  const availability = document.getElementById("trivy-link-availability");
  const linkResult = document.getElementById("trivy-link-result");
  const eligible = gitleaksTrivyEligibleEngagements();

  optIn.checked = false;
  optIn.disabled = eligible.length === 0;
  fields.classList.add("hidden");
  engagementSelect.innerHTML = '<option value="">' + (eligible.length ? "Denetim seçin" : "Uygun denetim yok") + "</option>"
    + eligible.map(item => '<option value="' + esc(item.id) + '">' + esc(item.name) + " · " + esc(item.authorization_ref) + "</option>").join("");
  controlSelect.innerHTML = '<option value="">Önce denetim seçin</option>';
  controlSelect.disabled = true;
  linkResult.textContent = "";
  linkResult.classList.add("hidden");
  availability.textContent = eligible.length
    ? "Bağlama isteğe bağlıdır. Etkin, yetki referansı ve maskeli kanıt onayı bulunan denetimler listelenir."
    : "Bağlama için etkin, yetki referansı ve maskeli kanıt onayı gerekir. Bağlantısız özet yine kullanılabilir.";
  availability.classList.remove("hidden");
}

async function loadTrivyControls(engagementId) {
  const controlSelect = document.getElementById("trivy-link-control");
  const selected = gitleaksTrivyEligibleEngagements().find(item => item.id === engagementId);
  controlSelect.disabled = true;
  controlSelect.innerHTML = '<option value="">Kontroller yükleniyor…</option>';
  if (!selected) {
    controlSelect.innerHTML = '<option value="">Etkin ve yetkili denetim seçin</option>';
    return;
  }
  try {
    const engagement = await api("/api/engagements/" + encodeURIComponent(engagementId));
    if (!engagement || engagement.id !== engagementId || !Array.isArray(engagement.tests)) {
      throw new Error("Kontrol listesi alınamadı.");
    }
    controlSelect.innerHTML = '<option value="">Test adımı seçin</option>'
      + engagement.tests.map(item => '<option value="' + esc(item.control_id) + '">' + esc(item.control_id) + " · " + esc(item.title) + "</option>").join("");
    if (!engagement.tests.length) controlSelect.innerHTML = '<option value="">Denetimde test adımı yok</option>';
  } catch {
    controlSelect.innerHTML = '<option value="">Test adımları yüklenemedi</option>';
    return;
  } finally {
    controlSelect.disabled = false;
  }
}

document.addEventListener("click", (e) => {
  const action = e.target.closest("[data-action]");
  if (action && action.dataset.action === "open-trivy-preview") {
    e.preventDefault();
    renderTrivyEngagementOptions();
    showModal("trivy-preview-modal", true);
    return;
  }
  const close = e.target.closest("[data-close]");
  if (close && close.dataset.close === "trivy-preview-modal") {
    e.preventDefault();
    clearTrivyPreview();
    showModal("trivy-preview-modal", false);
    return;
  }
  if (e.target.id === "trivy-preview-modal") {
    e.preventDefault();
    clearTrivyPreview();
    showModal("trivy-preview-modal", false);
  }
});

document.addEventListener("change", async (event) => {
  if (event.target.id === "trivy-link-opt-in") {
    const fields = document.getElementById("trivy-link-fields");
    const availability = document.getElementById("trivy-link-availability");
    fields.classList.toggle("hidden", !event.target.checked);
    availability.classList.toggle("hidden", Boolean(event.target.checked));
    if (event.target.checked && !gitleaksTrivyEligibleEngagements().length) {
      event.target.checked = false;
      fields.classList.add("hidden");
      availability.classList.remove("hidden");
    }
    return;
  }
  if (event.target.id === "trivy-link-engagement") {
    await loadTrivyControls(event.target.value);
  }
});

document.addEventListener("submit", async (e) => {
  if (e.target.id !== "trivy-preview-form") return;
  e.preventDefault();
  const pasteInput = document.getElementById("trivy-paste");
  const fileInput = document.getElementById("trivy-file");
  const errorEl = document.getElementById("trivy-preview-error");
  const resultEl = document.getElementById("trivy-preview-result");
  const linkOptIn = document.getElementById("trivy-link-opt-in");
  const linkEngagement = document.getElementById("trivy-link-engagement");
  const linkControl = document.getElementById("trivy-link-control");
  const linkResult = document.getElementById("trivy-link-result");

  errorEl.textContent = "";
  errorEl.classList.add("hidden");
  resultEl.classList.add("hidden");
  linkResult.textContent = "";
  linkResult.classList.add("hidden");

  let raw = pasteInput.value.trim();
  if (!raw && fileInput.files && fileInput.files[0]) {
    const file = fileInput.files[0];
    if (file.size > 60000) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    try {
      raw = await file.text();
    } catch {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
  }
  if (!raw) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }
  const encoder = new TextEncoder();
  if (encoder.encode(raw).length > 60000) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }
  const schemaVersion = parsed.SchemaVersion;
  if (!Number.isInteger(schemaVersion) || schemaVersion !== 2) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }
  const results = parsed.Results !== undefined ? parsed.Results : [];
  if (!Array.isArray(results)) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }
  if (results.length > 500) {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
    return;
  }

  const eligible = gitleaksTrivyEligibleEngagements();
  if (linkOptIn.checked && (!eligible.some(item => item.id === linkEngagement.value) || !linkControl.value)) {
    errorEl.textContent = "Kanıt bağlamak için etkin denetimi ve test adımını seçin.";
    errorEl.classList.remove("hidden");
    return;
  }

  try {
    let data;
    if (linkOptIn.checked) {
      const linkBody = JSON.stringify({ control_id: linkControl.value, report: parsed, confirm_link: true });
      if (encoder.encode(linkBody).length > 65536) {
        errorEl.textContent = "Geçersiz JSON.";
        errorEl.classList.remove("hidden");
        return;
      }
      data = await api("/api/engagements/" + encodeURIComponent(linkEngagement.value) + "/tool-evidence/trivy-native-json", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: linkBody
      });
    } else {
      const payload = JSON.stringify({ report: parsed });
      data = await api("/api/tool-reports/trivy-native-json/summary", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload
      });
    }

    const format = linkOptIn.checked
      ? (data && data.tool_identity === "trivy-native-json" ? "trivy-native-json" : "")
      : (data && data.format === "trivy-native-json" ? "trivy-native-json" : "");
    if (format !== "trivy-native-json") {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    if (!linkOptIn.checked) {
      const schemaVersionResp = data.schema_version;
      if (!Number.isInteger(schemaVersionResp) || schemaVersionResp !== 2) {
        errorEl.textContent = "Geçersiz JSON.";
        errorEl.classList.remove("hidden");
        return;
      }
    }
    const resultCount = data.result_count;
    if (!Number.isSafeInteger(resultCount) || resultCount < 0 || resultCount > 500 || resultCount !== results.length) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    const classCountsResp = data.class_counts;
    if (!classCountsResp || typeof classCountsResp !== "object" || Array.isArray(classCountsResp)) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    const classKeys = ["os-pkgs", "lang-pkgs", "config", "secret", "license", "license-file", "crypto", "custom", "unknown"];
    const actualClassKeys = Object.keys(classCountsResp);
    if (actualClassKeys.length !== classKeys.length || !classKeys.every(k => actualClassKeys.includes(k))) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    const classSum = classKeys.reduce((acc, k) => {
      const v = classCountsResp[k];
      if (!Number.isSafeInteger(v) || v < 0) throw new Error();
      return acc + v;
    }, 0);
    if (classSum !== resultCount) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    const vulnCountsResp = data.vuln_counts;
    if (!vulnCountsResp || typeof vulnCountsResp !== "object" || Array.isArray(vulnCountsResp)) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    const vulnKeys = ["critical", "high", "medium", "low", "unknown"];
    const actualVulnKeys = Object.keys(vulnCountsResp);
    if (actualVulnKeys.length !== vulnKeys.length || !vulnKeys.every(k => actualVulnKeys.includes(k))) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    for (const key of vulnKeys) {
      if (typeof vulnCountsResp[key] !== "number" || !Number.isSafeInteger(vulnCountsResp[key]) || vulnCountsResp[key] < 0) {
        errorEl.textContent = "Geçersiz JSON.";
        errorEl.classList.remove("hidden");
        return;
      }
    }
    const findingCountsResp = data.finding_counts;
    if (!findingCountsResp || typeof findingCountsResp !== "object" || Array.isArray(findingCountsResp)) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    const findingKeys = ["vulnerabilities", "misconfigurations", "secrets", "licenses"];
    const actualFindingKeys = Object.keys(findingCountsResp);
    if (actualFindingKeys.length !== findingKeys.length || !findingKeys.every(k => actualFindingKeys.includes(k))) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    for (const key of findingKeys) {
      if (typeof findingCountsResp[key] !== "number" || !Number.isSafeInteger(findingCountsResp[key]) || findingCountsResp[key] < 0) {
        errorEl.textContent = "Geçersiz JSON.";
        errorEl.classList.remove("hidden");
        return;
      }
    }
    const reportSha256 = data.report_sha256;
    if (typeof reportSha256 !== "string" || !/^[0-9a-f]{64}$/.test(reportSha256)) {
      errorEl.textContent = "Geçersiz JSON.";
      errorEl.classList.remove("hidden");
      return;
    }
    if (document.getElementById("trivy-format")) document.getElementById("trivy-format").textContent = "trivy-native-json";
    if (document.getElementById("trivy-schema-version")) document.getElementById("trivy-schema-version").textContent = "2";
    if (document.getElementById("trivy-result-count")) document.getElementById("trivy-result-count").textContent = resultCount.toString();
    if (document.getElementById("trivy-class-counts")) document.getElementById("trivy-class-counts").textContent = classKeys.map(k => `${k}:${classCountsResp[k]}`).join(" ");
    if (document.getElementById("trivy-vuln-counts")) document.getElementById("trivy-vuln-counts").textContent = vulnKeys.map(k => `${k}:${vulnCountsResp[k]}`).join(" ");
    if (document.getElementById("trivy-misconfig-sev-counts")) {
      if (linkOptIn.checked && data.misconfig_sev_counts === undefined) {
        document.getElementById("trivy-misconfig-sev-counts").textContent = "—";
      } else {
        const misconfigSevCountsResp = data.misconfig_sev_counts;
        if (!misconfigSevCountsResp || typeof misconfigSevCountsResp !== "object" || Array.isArray(misconfigSevCountsResp)) {
          errorEl.textContent = "Geçersiz JSON.";
          errorEl.classList.remove("hidden");
          return;
        }
        const sevKeys = ["critical", "high", "medium", "low", "unknown"];
        const actualSevKeys = Object.keys(misconfigSevCountsResp);
        if (actualSevKeys.length !== sevKeys.length || !sevKeys.every(k => actualSevKeys.includes(k))) {
          errorEl.textContent = "Geçersiz JSON.";
          errorEl.classList.remove("hidden");
          return;
        }
        for (const key of sevKeys) {
          if (typeof misconfigSevCountsResp[key] !== "number" || !Number.isSafeInteger(misconfigSevCountsResp[key]) || misconfigSevCountsResp[key] < 0) {
            errorEl.textContent = "Geçersiz JSON.";
            errorEl.classList.remove("hidden");
            return;
          }
        }
        const sumSevCounts = sevKeys.reduce((acc, k) => acc + misconfigSevCountsResp[k], 0);
        if (sumSevCounts !== findingCountsResp.misconfigurations) {
          errorEl.textContent = "Geçersiz JSON.";
          errorEl.classList.remove("hidden");
          return;
        }
        document.getElementById("trivy-misconfig-sev-counts").textContent = sevKeys.map(k => `${k}:${misconfigSevCountsResp[k]}`).join(" ");
      }
    }
    if (document.getElementById("trivy-finding-counts")) document.getElementById("trivy-finding-counts").textContent = findingKeys.map(k => `${k}:${findingCountsResp[k]}`).join(" ");
    if (document.getElementById("trivy-report-sha256")) document.getElementById("trivy-report-sha256").textContent = reportSha256;
    if (resultEl) resultEl.classList.remove("hidden");
    if (linkOptIn.checked) {
      linkResult.textContent = "Toplu özet " + linkControl.value + " test adımına bağlandı; uzman incelemesi gerekir. Ham rapor saklanmaz ve SHA-256 hedef/provenans kanıtı değildir.";
      linkResult.classList.remove("hidden");
    }
    pasteInput.value = "";
    fileInput.value = "";
  } catch {
    errorEl.textContent = "Geçersiz JSON.";
    errorEl.classList.remove("hidden");
  }
});

function clearTrivyPreview() {
  document.getElementById("trivy-paste").value = "";
  document.getElementById("trivy-file").value = "";
  document.getElementById("trivy-preview-error").textContent = "";
  document.getElementById("trivy-preview-error").classList.add("hidden");
  document.getElementById("trivy-preview-result").classList.add("hidden");
  document.getElementById("trivy-format").textContent = "";
  document.getElementById("trivy-schema-version").textContent = "";
  document.getElementById("trivy-result-count").textContent = "";
  document.getElementById("trivy-class-counts").textContent = "";
  document.getElementById("trivy-vuln-counts").textContent = "";
  document.getElementById("trivy-misconfig-sev-counts").textContent = "";
  document.getElementById("trivy-finding-counts").textContent = "";
  document.getElementById("trivy-report-sha256").textContent = "";
  renderTrivyEngagementOptions();
}
document.addEventListener("click",(e)=>{const action=e.target.closest("[data-action]");if(action&&action.dataset.action==="open-zap-preview"){e.preventDefault();showModal("zap-preview-modal",true);return;}const close=e.target.closest("[data-close]");if(close&&close.dataset.close==="zap-preview-modal"){e.preventDefault();clearZapPreview();showModal("zap-preview-modal",false);return;}if(e.target.id==="zap-preview-modal"){e.preventDefault();clearZapPreview();showModal("zap-preview-modal",false);}});document.addEventListener("submit",async(e)=>{if(e.target.id!=="zap-preview-form")return;e.preventDefault();const pasteInput=document.getElementById("zap-paste");const fileInput=document.getElementById("zap-file");const errorEl=document.getElementById("zap-preview-error");const resultEl=document.getElementById("zap-preview-result");errorEl.textContent="";errorEl.classList.add("hidden");resultEl.classList.add("hidden");let raw=pasteInput.value.trim();if(!raw&&fileInput.files&&fileInput.files[0]){const file=fileInput.files[0];if(file.size>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{raw=await file.text();}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}if(!raw){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const encoder=new TextEncoder();if(encoder.encode(raw).length>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}let parsed;try{parsed=JSON.parse(raw);}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const sites=parsed.site;if(!Array.isArray(sites)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(sites.length>20){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}let totalAlertTypes=0;let totalInstances=0;const globalRiskCounts={informational:0,low:0,medium:0,high:0};for(const site of sites){if(!site||typeof site!=="object"||Array.isArray(site)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const alerts=site.alerts;if(!Array.isArray(alerts)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const siteAlertTypes=alerts.length;totalAlertTypes+=siteAlertTypes;if(totalAlertTypes>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const alert of alerts){if(!alert||typeof alert!=="object"||Array.isArray(alert)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const riskcodeRaw=alert.riskcode;if(typeof riskcodeRaw!=="string"||!/[0-3]/.test(riskcodeRaw)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const countRaw=alert.count;if(typeof countRaw!=="string"||!/^[0-9]+$/.test(countRaw)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}let count;try{count=Number(countRaw);}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isSafeInteger(count)||count<=0){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(riskcodeRaw==="0")globalRiskCounts.informational++;else if(riskcodeRaw==="1")globalRiskCounts.low++;else if(riskcodeRaw==="2")globalRiskCounts.medium++;else if(riskcodeRaw==="3")globalRiskCounts.high++;totalInstances+=count;if(totalInstances>5000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}}const payload=JSON.stringify({report:parsed});try{const data=await api("/api/tool-reports/zap/summary",{method:"POST",headers:{"Content-Type":"application/json"},body:payload});if(data.format!=="zap-traditional-json"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isSafeInteger(data.site_count)||data.site_count<0||data.site_count>20){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isSafeInteger(data.alert_type_count)||data.alert_type_count<0||data.alert_type_count>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isSafeInteger(data.instance_count)||data.instance_count<0||data.instance_count>5000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const riskCounts=data.risk_counts;if(!riskCounts||typeof riskCounts!=="object"||Array.isArray(riskCounts)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const riskKeys=["informational","low","medium","high"];const actualRiskKeys=Object.keys(riskCounts);if(actualRiskKeys.length!==riskKeys.length||!riskKeys.every(k=>actualRiskKeys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const key of riskKeys){if(!Number.isSafeInteger(riskCounts[key])||riskCounts[key]<0){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}const riskSum=riskKeys.reduce((acc,k)=>acc+riskCounts[k],0);if(riskSum!==data.alert_type_count){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof data.report_sha256!=="string"||!/^[0-9a-f]{64}$/.test(data.report_sha256)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(document.getElementById("zap-format"))document.getElementById("zap-format").textContent="zap-traditional-json";if(document.getElementById("zap-site-count"))document.getElementById("zap-site-count").textContent=data.site_count.toString();if(document.getElementById("zap-alert-type-count"))document.getElementById("zap-alert-type-count").textContent=data.alert_type_count.toString();if(document.getElementById("zap-instance-count"))document.getElementById("zap-instance-count").textContent=data.instance_count.toString();if(document.getElementById("zap-risk-counts"))document.getElementById("zap-risk-counts").textContent=riskKeys.map(k=>`${k}:${riskCounts[k]}`).join(" ");if(document.getElementById("zap-report-sha256"))document.getElementById("zap-report-sha256").textContent=data.report_sha256;if(resultEl)resultEl.classList.remove("hidden");pasteInput.value="";fileInput.value="";}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");}});function clearZapPreview(){document.getElementById("zap-paste").value="";document.getElementById("zap-file").value="";document.getElementById("zap-preview-error").textContent="";document.getElementById("zap-preview-error").classList.add("hidden");document.getElementById("zap-preview-result").classList.add("hidden");document.getElementById("zap-format").textContent="";document.getElementById("zap-site-count").textContent="";document.getElementById("zap-alert-type-count").textContent="";document.getElementById("zap-instance-count").textContent="";document.getElementById("zap-risk-counts").textContent="";document.getElementById("zap-report-sha256").textContent="";}
document.addEventListener("click",(e)=>{const action=e.target.closest("[data-action]");if(action&&action.dataset.action==="open-ssllabs-preview"){e.preventDefault();showModal("ssllabs-preview-modal",true);return;}const close=e.target.closest("[data-close]");if(close&&close.dataset.close==="ssllabs-preview-modal"){e.preventDefault();clearSsllabsPreview();showModal("ssllabs-preview-modal",false);return;}if(e.target.id==="ssllabs-preview-modal"){e.preventDefault();clearSsllabsPreview();showModal("ssllabs-preview-modal",false);}});document.addEventListener("submit",async(e)=>{if(e.target.id!=="ssllabs-preview-form")return;e.preventDefault();const pasteInput=document.getElementById("ssllabs-paste");const fileInput=document.getElementById("ssllabs-file");const errorEl=document.getElementById("ssllabs-preview-error");const resultEl=document.getElementById("ssllabs-preview-result");errorEl.textContent="";errorEl.classList.add("hidden");resultEl.classList.add("hidden");let raw=pasteInput.value.trim();if(!raw&&fileInput.files&&fileInput.files[0]){const file=fileInput.files[0];if(file.size>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{raw=await file.text();}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}if(!raw){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const encoder=new TextEncoder();if(encoder.encode(raw).length>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}let parsed;try{parsed=JSON.parse(raw);}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!("status" in parsed)||typeof parsed.status!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const HOST_STATUS_ENUM=["DNS","ERROR","IN_PROGRESS","READY"];if(!HOST_STATUS_ENUM.includes(parsed.status)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!("endpoints" in parsed)||!Array.isArray(parsed.endpoints)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(parsed.endpoints.length>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const ep of parsed.endpoints){if(!ep||typeof ep!=="object"||Array.isArray(ep)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}const GRADE_ENUM=["A+","A","A-","B","C","D","E","F","T","M"];const grade_counts={};for(const g of GRADE_ENUM)grade_counts[g]=0;for(const ep of parsed.endpoints){const grade=ep.grade;if(grade!==null&&grade!==undefined){if(typeof grade!=="string"||!GRADE_ENUM.includes(grade)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}grade_counts[grade]++;}}const payload=JSON.stringify({report:parsed});try{const data=await api("/api/tool-reports/ssllabs-host/summary",{method:"POST",headers:{"Content-Type":"application/json"},body:payload});if(data.format!=="ssllabs-v4-host"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isSafeInteger(data.endpoint_count)||data.endpoint_count<0||data.endpoint_count>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!data.grade_counts||typeof data.grade_counts!=="object"||Array.isArray(data.grade_counts)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const gradeKeys=Object.keys(data.grade_counts);if(gradeKeys.length!==GRADE_ENUM.length||!GRADE_ENUM.every(k=>gradeKeys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const key of GRADE_ENUM){if(!Number.isSafeInteger(data.grade_counts[key])||data.grade_counts[key]<0){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}const gradeSum=GRADE_ENUM.reduce((acc,k)=>acc+data.grade_counts[k],0);if(gradeSum>data.endpoint_count){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof data.report_sha256!=="string"||!/^[0-9a-f]{64}$/.test(data.report_sha256)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(document.getElementById("ssllabs-format"))document.getElementById("ssllabs-format").textContent="ssllabs-v4-host";if(document.getElementById("ssllabs-status"))document.getElementById("ssllabs-status").textContent=data.assessment_status;if(document.getElementById("ssllabs-endpoint-count"))document.getElementById("ssllabs-endpoint-count").textContent=data.endpoint_count.toString();if(document.getElementById("ssllabs-grade-counts"))document.getElementById("ssllabs-grade-counts").textContent=GRADE_ENUM.map(k=>`${k}:${data.grade_counts[k]}`).join(" ");if(document.getElementById("ssllabs-report-sha256"))document.getElementById("ssllabs-report-sha256").textContent=data.report_sha256;if(resultEl)resultEl.classList.remove("hidden");pasteInput.value="";fileInput.value="";}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");}});function clearSsllabsPreview(){document.getElementById("ssllabs-paste").value="";document.getElementById("ssllabs-file").value="";document.getElementById("ssllabs-preview-error").textContent="";document.getElementById("ssllabs-preview-error").classList.add("hidden");document.getElementById("ssllabs-preview-result").classList.add("hidden");document.getElementById("ssllabs-format").textContent="";document.getElementById("ssllabs-status").textContent="";document.getElementById("ssllabs-endpoint-count").textContent="";document.getElementById("ssllabs-grade-counts").textContent="";document.getElementById("ssllabs-report-sha256").textContent="";}
document.addEventListener("click",(e)=>{const action=e.target.closest("[data-action]");if(action&&action.dataset.action==="open-semgrep-preview"){e.preventDefault();showModal("semgrep-preview-modal",true);return;}const close=e.target.closest("[data-close]");if(close&&close.dataset.close==="semgrep-preview-modal"){e.preventDefault();clearSemgrepPreview();showModal("semgrep-preview-modal",false);return;}if(e.target.id==="semgrep-preview-modal"){e.preventDefault();clearSemgrepPreview();showModal("semgrep-preview-modal",false);}});document.addEventListener("submit",async(e)=>{if(e.target.id!=="semgrep-preview-form")return;e.preventDefault();const pasteInput=document.getElementById("semgrep-paste");const fileInput=document.getElementById("semgrep-file");const errorEl=document.getElementById("semgrep-preview-error");const resultEl=document.getElementById("semgrep-preview-result");errorEl.textContent="";errorEl.classList.add("hidden");resultEl.classList.add("hidden");let raw=pasteInput.value.trim();if(!raw&&fileInput.files&&fileInput.files[0]){const file=fileInput.files[0];if(file.size>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{raw=await file.text();}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}if(!raw){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const encoder=new TextEncoder();if(encoder.encode(raw).length>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}let parsed;try{parsed=JSON.parse(raw);}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!parsed.results||!Array.isArray(parsed.results)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(parsed.results.length>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!parsed.errors||!Array.isArray(parsed.errors)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!parsed.paths||typeof parsed.paths!=="object"||Array.isArray(parsed.paths)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!parsed.paths.scanned||!Array.isArray(parsed.paths.scanned)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const item of parsed.paths.scanned){if(typeof item!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}for(const result of parsed.results){if(!result||typeof result!=="object"||Array.isArray(result)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.check_id!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.path!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!result.start||typeof result.start!=="object"||Array.isArray(result.start)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.start.line)||result.start.line===true||result.start.line===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.start.col)||result.start.col===true||result.start.col===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!result.end||typeof result.end!=="object"||Array.isArray(result.end)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.end.line)||result.end.line===true||result.end.line===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.end.col)||result.end.col===true||result.end.col===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!result.extra||typeof result.extra!=="object"||Array.isArray(result.extra)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.extra.message!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!("metadata"in result.extra)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.extra.fingerprint!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.extra.lines!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const severityRaw=result.extra.severity;if(typeof severityRaw!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const allowedSeverities=["ERROR","WARNING","EXPERIMENT","INVENTORY","CRITICAL","HIGH","MEDIUM","LOW","INFO"];if(!allowedSeverities.includes(severityRaw)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}const payload=JSON.stringify({report:parsed});try{const data=await api("/api/tool-reports/semgrep-native-json/summary",{method:"POST",headers:{"Content-Type":"application/json"},body:payload});if(data.format!=="semgrep-native-json"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isSafeInteger(data.result_count)||data.result_count<0||data.result_count>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!data.severity_counts||typeof data.severity_counts!=="object"||Array.isArray(data.severity_counts)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const severityKeys=["ERROR","WARNING","EXPERIMENT","INVENTORY","CRITICAL","HIGH","MEDIUM","LOW","INFO"];const keys=Object.keys(data.severity_counts);if(keys.length!==severityKeys.length||!severityKeys.every(k=>keys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const key of severityKeys){if(!Number.isSafeInteger(data.severity_counts[key])||data.severity_counts[key]<0){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}const sum=severityKeys.reduce((acc,k)=>acc+data.severity_counts[k],0);if(sum!==data.result_count){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof data.report_sha256!=="string"||!/^[0-9a-f]{64}$/.test(data.report_sha256)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(document.getElementById("semgrep-format"))document.getElementById("semgrep-format").textContent="semgrep-native-json";if(document.getElementById("semgrep-result-count"))document.getElementById("semgrep-result-count").textContent=data.result_count.toString();if(document.getElementById("semgrep-severity-counts"))document.getElementById("semgrep-severity-counts").textContent=severityKeys.map(k=>`${k}:${data.severity_counts[k]}`).join(" ");if(document.getElementById("semgrep-report-sha256"))document.getElementById("semgrep-report-sha256").textContent=data.report_sha256;if(resultEl)resultEl.classList.remove("hidden");pasteInput.value="";fileInput.value="";}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");}});function clearSemgrepPreview(){document.getElementById("semgrep-paste").value="";document.getElementById("semgrep-file").value="";document.getElementById("semgrep-preview-error").textContent="";document.getElementById("semgrep-preview-error").classList.add("hidden");document.getElementById("semgrep-preview-result").classList.add("hidden");document.getElementById("semgrep-format").textContent="";document.getElementById("semgrep-result-count").textContent="";document.getElementById("semgrep-severity-counts").textContent="";document.getElementById("semgrep-report-sha256").textContent="";}
let semgrepTrivyCompareGeneration=0;
document.addEventListener("click",(e)=>{const action=e.target.closest("[data-action]");if(action&&action.dataset.action==="open-semgrep-trivy-compare"){e.preventDefault();clearSemgrepTrivyCompare();showModal("semgrep-trivy-compare-modal",true);return;}const close=e.target.closest("[data-close]");if(close&&close.dataset.close==="semgrep-trivy-compare-modal"){e.preventDefault();showModal("semgrep-trivy-compare-modal",false);return;}if(e.target.id==="semgrep-trivy-compare-modal"){e.preventDefault();showModal("semgrep-trivy-compare-modal",false);}});document.addEventListener("submit",async(e)=>{if(e.target.id!=="semgrep-trivy-compare-form")return;e.preventDefault();const compareGeneration=++semgrepTrivyCompareGeneration;const isCurrentCompare=()=>compareGeneration===semgrepTrivyCompareGeneration;const semgrepPasteInput=document.getElementById("compare-semgrep-paste");const semgrepFileInput=document.getElementById("compare-semgrep-file");const trivyPasteInput=document.getElementById("compare-trivy-paste");const trivyFileInput=document.getElementById("compare-trivy-file");const errorEl=document.getElementById("semgrep-trivy-compare-error");const resultEl=document.getElementById("semgrep-trivy-compare-result");const semgrepCard=document.getElementById("compare-semgrep-card");const trivyCard=document.getElementById("compare-trivy-card");errorEl.textContent="";errorEl.classList.add("hidden");resultEl.classList.add("hidden");semgrepCard.classList.add("hidden");trivyCard.classList.add("hidden");for(const id of ["compare-semgrep-format","compare-semgrep-result-count","compare-semgrep-severity-counts","compare-trivy-format","compare-trivy-schema-version","compare-trivy-result-count","compare-trivy-class-counts","compare-trivy-vuln-counts","compare-trivy-misconfig-sev-counts","compare-trivy-finding-counts","compare-trivy-report-sha256"]){const el=document.getElementById(id);if(el)el.textContent="";}let semgrepRaw="";let trivyRaw="";let hasSemgrep=false;let hasTrivy=false;let semgrepParsed;let trivyParsed;const encoder=new TextEncoder();if(semgrepPasteInput.value.trim()||semgrepFileInput.files&&semgrepFileInput.files[0]){if(!semgrepPasteInput.value.trim()&&semgrepFileInput.files&&semgrepFileInput.files[0]){const file=semgrepFileInput.files[0];if(file.size>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{semgrepRaw=await file.text();if(!isCurrentCompare())return;}catch{if(!isCurrentCompare())return;errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}else{semgrepRaw=semgrepPasteInput.value.trim();}if(encoder.encode(semgrepRaw).length>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{semgrepParsed=JSON.parse(semgrepRaw);}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!semgrepParsed||typeof semgrepParsed!=="object"||Array.isArray(semgrepParsed)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!semgrepParsed.results||!Array.isArray(semgrepParsed.results)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(semgrepParsed.results.length>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!semgrepParsed.errors||!Array.isArray(semgrepParsed.errors)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!semgrepParsed.paths||typeof semgrepParsed.paths!=="object"||Array.isArray(semgrepParsed.paths)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!semgrepParsed.paths.scanned||!Array.isArray(semgrepParsed.paths.scanned)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const item of semgrepParsed.paths.scanned){if(typeof item!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}for(const result of semgrepParsed.results){if(!result||typeof result!=="object"||Array.isArray(result)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.check_id!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.path!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!result.start||typeof result.start!=="object"||Array.isArray(result.start)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.start.line)||result.start.line===true||result.start.line===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.start.col)||result.start.col===true||result.start.col===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!result.end||typeof result.end!=="object"||Array.isArray(result.end)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.end.line)||result.end.line===true||result.end.line===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isInteger(result.end.col)||result.end.col===true||result.end.col===false){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!result.extra||typeof result.extra!=="object"||Array.isArray(result.extra)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.extra.message!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!("metadata"in result.extra)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.extra.fingerprint!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof result.extra.lines!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const severityRaw=result.extra.severity;if(typeof severityRaw!=="string"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const allowedSeverities=["ERROR","WARNING","EXPERIMENT","INVENTORY","CRITICAL","HIGH","MEDIUM","LOW","INFO"];if(!allowedSeverities.includes(severityRaw)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}hasSemgrep=true;}if(trivyPasteInput.value.trim()||trivyFileInput.files&&trivyFileInput.files[0]){if(!trivyPasteInput.value.trim()&&trivyFileInput.files&&trivyFileInput.files[0]){const file=trivyFileInput.files[0];if(file.size>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{trivyRaw=await file.text();if(!isCurrentCompare())return;}catch{if(!isCurrentCompare())return;errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}else{trivyRaw=trivyPasteInput.value.trim();}if(encoder.encode(trivyRaw).length>60000){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}try{trivyParsed=JSON.parse(trivyRaw);}catch{errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(trivyParsed===null||typeof trivyParsed!=="object"||Array.isArray(trivyParsed)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const schemaVersion=trivyParsed.SchemaVersion;if(!Number.isInteger(schemaVersion)||schemaVersion!==2){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const results=trivyParsed.Results!==undefined?trivyParsed.Results:[];if(!Array.isArray(results)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(results.length>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}hasTrivy=true;}if(!hasSemgrep&&!hasTrivy){errorEl.textContent="En az bir rapor gerekli.";errorEl.classList.remove("hidden");return;}const semgrepPayload=hasSemgrep?JSON.stringify({report:semgrepParsed}):null;const trivyPayload=hasTrivy?JSON.stringify({report:trivyParsed}):null;let semgrepData=null;let trivyData=null;try{if(hasSemgrep){semgrepData=await api("/api/tool-reports/semgrep-native-json/summary",{method:"POST",headers:{"Content-Type":"application/json"},body:semgrepPayload});if(!isCurrentCompare())return;if(semgrepData.format!=="semgrep-native-json"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!Number.isSafeInteger(semgrepData.result_count)||semgrepData.result_count<0||semgrepData.result_count>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(!semgrepData.severity_counts||typeof semgrepData.severity_counts!=="object"||Array.isArray(semgrepData.severity_counts)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const severityKeys=["ERROR","WARNING","EXPERIMENT","INVENTORY","CRITICAL","HIGH","MEDIUM","LOW","INFO"];const keys=Object.keys(semgrepData.severity_counts);if(keys.length!==severityKeys.length||!severityKeys.every(k=>keys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const key of severityKeys){if(!Number.isSafeInteger(semgrepData.severity_counts[key])||semgrepData.severity_counts[key]<0){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}const sum=severityKeys.reduce((acc,k)=>acc+semgrepData.severity_counts[k],0);if(sum!==semgrepData.result_count){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}if(typeof semgrepData.report_sha256!=="string"||!/^[0-9a-f]{64}$/.test(semgrepData.report_sha256)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}if(hasTrivy){trivyData=await api("/api/tool-reports/trivy-native-json/summary",{method:"POST",headers:{"Content-Type":"application/json"},body:trivyPayload});if(!isCurrentCompare())return;const format=trivyData.format;if(format!=="trivy-native-json"){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const schemaVersionResp=trivyData.schema_version;if(!Number.isInteger(schemaVersionResp)||schemaVersionResp!==2){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const resultCount=trivyData.result_count;if(!Number.isSafeInteger(resultCount)||resultCount<0||resultCount>500){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const classCountsResp=trivyData.class_counts;if(!classCountsResp||typeof classCountsResp!=="object"||Array.isArray(classCountsResp)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const classKeys=["os-pkgs","lang-pkgs","config","secret","license","license-file","crypto","custom","unknown"];const actualClassKeys=Object.keys(classCountsResp);if(actualClassKeys.length!==classKeys.length||!classKeys.every(k=>actualClassKeys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const classSum=classKeys.reduce((acc,k)=>{const v=classCountsResp[k];if(!Number.isSafeInteger(v)||v<0)throw new Error();return acc+v;},0);if(classSum!==resultCount){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const vulnCountsResp=trivyData.vuln_counts;if(!vulnCountsResp||typeof vulnCountsResp!=="object"||Array.isArray(vulnCountsResp)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const vulnKeys=["critical","high","medium","low","unknown"];const actualVulnKeys=Object.keys(vulnCountsResp);if(actualVulnKeys.length!==vulnKeys.length||!vulnKeys.every(k=>actualVulnKeys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for (const key of vulnKeys) { if (typeof vulnCountsResp[key] !== 'number' || !Number.isSafeInteger(vulnCountsResp[key]) || vulnCountsResp[key] < 0) { errorEl.textContent = 'Geçersiz JSON.'; errorEl.classList.remove('hidden'); return; } }const findingCountsResp=trivyData.finding_counts;if(!findingCountsResp||typeof findingCountsResp!=="object"||Array.isArray(findingCountsResp)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const findingKeys=["vulnerabilities","misconfigurations","secrets","licenses"];const actualFindingKeys=Object.keys(findingCountsResp);if(actualFindingKeys.length!==findingKeys.length||!findingKeys.every(k=>actualFindingKeys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for (const key of findingKeys) { if (typeof findingCountsResp[key] !== 'number' || !Number.isSafeInteger(findingCountsResp[key]) || findingCountsResp[key] < 0) { errorEl.textContent = 'Geçersiz JSON.'; errorEl.classList.remove('hidden'); return; } }const misconfigSevCountsResp=trivyData.misconfig_sev_counts;if(!misconfigSevCountsResp||typeof misconfigSevCountsResp!=="object"||Array.isArray(misconfigSevCountsResp)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const misconfigSevKeys=["critical","high","medium","low","unknown"];const actualMisconfigSevKeys=Object.keys(misconfigSevCountsResp);if(actualMisconfigSevKeys.length!==misconfigSevKeys.length||!misconfigSevKeys.every(k=>actualMisconfigSevKeys.includes(k))){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}for(const key of misconfigSevKeys){if(typeof misconfigSevCountsResp[key]!=="number"||!Number.isSafeInteger(misconfigSevCountsResp[key])||misconfigSevCountsResp[key]<0){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}const sumMisconfigSevCounts=misconfigSevKeys.reduce((acc,k)=>acc+misconfigSevCountsResp[k],0);if(sumMisconfigSevCounts!==findingCountsResp.misconfigurations){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}const reportSha256=trivyData.report_sha256;if(typeof reportSha256!=="string"||!/^[0-9a-f]{64}$/.test(reportSha256)){errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");return;}}resultEl.classList.remove("hidden");if(semgrepData){if(document.getElementById("compare-semgrep-format"))document.getElementById("compare-semgrep-format").textContent="semgrep-native-json";if(document.getElementById("compare-semgrep-result-count"))document.getElementById("compare-semgrep-result-count").textContent=semgrepData.result_count.toString();if(document.getElementById("compare-semgrep-severity-counts"))document.getElementById("compare-semgrep-severity-counts").textContent=Object.keys(semgrepData.severity_counts).map(k=>`${k}:${semgrepData.severity_counts[k]}`).join(" ");semgrepCard.classList.remove("hidden");}if(trivyData){if(document.getElementById("compare-trivy-format"))document.getElementById("compare-trivy-format").textContent="trivy-native-json";if(document.getElementById("compare-trivy-schema-version"))document.getElementById("compare-trivy-schema-version").textContent="2";if(document.getElementById("compare-trivy-result-count"))document.getElementById("compare-trivy-result-count").textContent=trivyData.result_count.toString();if(document.getElementById("compare-trivy-class-counts"))document.getElementById("compare-trivy-class-counts").textContent=Object.keys(trivyData.class_counts).map(k=>`${k}:${trivyData.class_counts[k]}`).join(" ");if(document.getElementById("compare-trivy-vuln-counts"))document.getElementById("compare-trivy-vuln-counts").textContent=Object.keys(trivyData.vuln_counts).map(k=>`${k}:${trivyData.vuln_counts[k]}`).join(" ");if(document.getElementById("compare-trivy-misconfig-sev-counts"))document.getElementById("compare-trivy-misconfig-sev-counts").textContent=["critical","high","medium","low","unknown"].map(k=>`${k}:${trivyData.misconfig_sev_counts[k]}`).join(" ");if(document.getElementById("compare-trivy-finding-counts"))document.getElementById("compare-trivy-finding-counts").textContent=Object.keys(trivyData.finding_counts).map(k=>`${k}:${trivyData.finding_counts[k]}`).join(" ");if(document.getElementById("compare-trivy-report-sha256"))document.getElementById("compare-trivy-report-sha256").textContent=trivyData.report_sha256;trivyCard.classList.remove("hidden");}semgrepPasteInput.value="";semgrepFileInput.value="";trivyPasteInput.value="";trivyFileInput.value="";}catch{if(!isCurrentCompare())return;errorEl.textContent="Geçersiz JSON.";errorEl.classList.remove("hidden");}});function clearSemgrepTrivyCompare(){semgrepTrivyCompareGeneration++;document.getElementById("compare-semgrep-paste").value="";document.getElementById("compare-semgrep-file").value="";document.getElementById("compare-trivy-paste").value="";document.getElementById("compare-trivy-file").value="";document.getElementById("semgrep-trivy-compare-error").textContent="";document.getElementById("semgrep-trivy-compare-error").classList.add("hidden");document.getElementById("semgrep-trivy-compare-result").classList.add("hidden");document.getElementById("compare-semgrep-card").classList.add("hidden");document.getElementById("compare-trivy-card").classList.add("hidden");document.getElementById("compare-semgrep-format").textContent="";document.getElementById("compare-semgrep-result-count").textContent="";document.getElementById("compare-semgrep-severity-counts").textContent="";document.getElementById("compare-trivy-format").textContent="";document.getElementById("compare-trivy-schema-version").textContent="";document.getElementById("compare-trivy-result-count").textContent="";document.getElementById("compare-trivy-class-counts").textContent="";document.getElementById("compare-trivy-vuln-counts").textContent="";if(document.getElementById("compare-trivy-misconfig-sev-counts"))document.getElementById("compare-trivy-misconfig-sev-counts").textContent="";document.getElementById("compare-trivy-finding-counts").textContent="";if(document.getElementById("compare-trivy-report-sha256"))document.getElementById("compare-trivy-report-sha256").textContent="";}
// Each card opens an existing UI entry point. A route is never used as a fetch URL here.
// Routes without a verified form are intentionally omitted from the card actions.
const TOOL_CARD_DESTINATIONS = Object.freeze({
  "/api/scans": { view: "targets" },
  "/api/tool-runs/zap-self-passive": { action: "open-zap-preview" },
  "/api/tool-runs/zap-authorized": { action: "open-zap-authorized" },
  "/api/tool-runs/zap-target-active": { action: "open-zap-target-active" },
  "/api/tool-runs/zap-target-spider": { action: "open-zap-target-spider" },
  "/api/tool-runs/zap-target-spider-scope": { panel: "advanced-tool-panel", flow: "zap-spider-scope" },
  "/api/tool-runs/zap-site-active": { panel: "advanced-tool-panel", flow: "zap-site-active" },
  "/api/tool-plans/zap-af/preview": { panel: "advanced-tool-panel", flow: "zap-af-preview" },
  "/api/tool-reports/zap/summary": { action: "open-zap-preview" },
  "/api/tool-reports/burp-sitemap/summary": { action: "open-burp-xml-preview" },
  "/api/tool-reports/burp-sitemap/handoff-manifest": { panel: "advanced-tool-panel", flow: "burp-handoff" },
  "/api/tool-reports/burp-logger-csv/summary": { panel: "advanced-tool-panel", flow: "burp-logger-csv" },
  "/api/tool-runs/semgrep": { action: "open-semgrep-local" },
  "/api/tool-reports/semgrep-native-json/summary": { action: "open-semgrep-preview" },
  "/api/tool-reports/semgrep/rulepack-inventory": { panel: "advanced-tool-panel", flow: "semgrep-rulepack" },
  "/api/tool-reports/semgrep/tls-verify-filter": { panel: "advanced-tool-panel", flow: "semgrep-tls-filter" },
  "/api/tool-reports/sarif/summary": { action: "open-sarif-preview" },
  "/api/tool-reports/schemathesis-junit/summary": { action: "open-schemathesis-junit-preview" },
  "/api/tool-runs/schemathesis-local": { action: "open-schemathesis-local" },
  "/api/tool-runs/schemathesis-loopback": { action: "open-schemathesis-loopback" },
  "/api/tool-runs/playwright-local-fixture": { panel: "advanced-tool-panel", flow: "playwright-fixture" },
  "/api/tool-reports/playwright-json/summary": { action: "open-playwright-json-preview" },
  "/api/tool-runs/k6-loopback-smoke": { panel: "advanced-tool-panel", flow: "k6-loopback" },
  "/api/tool-reports/k6-summary-json/summary": { action: "open-k6-summary-preview" },
  "/api/tool-reports/k6-machine-summary-v1/summary": { action: "open-k6-machine-summary-preview" },
  "/api/tool-reports/siem-ecs-ndjson/summary": { action: "open-siem-ecs-preview" },
  "/api/tool-runs/trivy-vulnerability": { panel: "trivy-vuln-local-panel" },
  "/api/tool-runs/trivy-npm-vulnerability": { panel: "trivy-npm-local-panel" },
  "/api/tool-runs/trivy-go-mod-vulnerability": { panel: "completed-backlog-panel", route: "/api/tool-runs/trivy-go-mod-vulnerability" },
  "/api/tool-runs/trivy-cargo-lock-vulnerability": { panel: "completed-backlog-panel", route: "/api/tool-runs/trivy-cargo-lock-vulnerability" },
  "/api/tool-runs/trivy-pnpm-vulnerability": { panel: "completed-backlog-panel", route: "/api/tool-runs/trivy-pnpm-vulnerability" },
  "/api/tool-runs/trivy-yarn-vulnerability": { panel: "completed-backlog-panel", route: "/api/tool-runs/trivy-yarn-vulnerability" },
  "/api/tool-runs/trivy-maven-vulnerability": { panel: "completed-backlog-panel", route: "/api/tool-runs/trivy-maven-vulnerability" },
  "/api/tool-runs/trivy-ruby-vulnerability": { panel: "completed-backlog-panel", route: "/api/tool-runs/trivy-ruby-vulnerability" },
  "/api/tool-runs/trivy-image-archive-vulnerability": { panel: "trivy-image-archive-panel" },
  "/api/tool-runs/trivy-secret": { panel: "trivy-secret-panel" },
  "/api/tool-runs/trivy-dockerfile-config": { panel: "trivy-dockerfile-config-panel" },
  "/api/tool-runs/trivy-terraform-config": { panel: "trivy-terraform-config-panel" },
  "/api/tool-runs/trivy-terraform-config-batch": { panel: "completed-backlog-panel", route: "/api/tool-runs/trivy-terraform-config-batch" },
  "/api/tool-runs/trivy-kubernetes-config": { panel: "trivy-kubernetes-single-panel" },
  "/api/tool-runs/trivy-kubernetes-config-batch": { panel: "trivy-kubernetes-batch-panel" },
  "/api/tool-runs/syft-grype": { panel: "completed-backlog-panel", route: "/api/tool-runs/syft-grype" },
  "/api/tool-reports/trivy-native-json/summary": { action: "open-trivy-preview" },
  "/api/tool-reports/trivy/db-freshness": { panel: "advanced-tool-panel", flow: "trivy-db-freshness" },
  "/api/tool-runs/testssl-protocols": { action: "open-testssl-loopback-full" },
  "/api/tool-runs/testssl-full": { action: "open-testssl-loopback-full" },
  "/api/tool-runs/testssl-authorized": { action: "open-testssl-authorized" },
  "/api/tool-reports/testssl/summary": { action: "open-testssl-flat-preview" },
  "/api/tool-reports/testssl/boundary-contract": { panel: "advanced-tool-panel", flow: "testssl-boundary" },
  "/api/nmap/tcp-scan": { view: "targets" },
  "/api/nmap/service-fingerprint": { panel: "advanced-tool-panel", flow: "nmap-service-fingerprint" },
  "/api/tool-reports/nmap/summary": { action: "open-nmap-xml-preview" },
  "/api/nuclei/http-scans": { action: "open-nuclei-http-scan" },
  "/api/tool-reports/nuclei-jsonl/summary": { action: "open-nuclei-jsonl-preview" },
  "/api/tool-reports/nuclei/verification-coverage": { panel: "advanced-tool-panel", flow: "nuclei-verification" },
  "/api/tool-runs/gitleaks": { action: "open-gitleaks-filesystem" },
  "/api/tool-runs/gitleaks-git-history": { panel: "completed-backlog-panel", route: "/api/tool-runs/gitleaks-git-history" },
  "/api/tool-reports/gitleaks/summary": { action: "open-gitleaks-json-preview" },
  "/api/tool-runs/trufflehog-filesystem": { action: "open-trufflehog-filesystem" },
  "/api/tool-runs/trufflehog-git-history": { action: "open-trufflehog-git-history" },
  "/api/tool-runs/secret-bundle/validate": { panel: "advanced-tool-panel", flow: "secret-bundle" },
  "/api/tool-reports/trufflehog/summary": { action: "open-trufflehog-preview" },
  "/api/tool-runs/npm-audit-local": { panel: "npm-audit-active-panel" },
  "/api/tool-runs/osv-scanner-local": { panel: "osv-active-panel" },
  "/api/tool-reports/npm-audit/summary": { action: "open-npm-audit-preview" },
  "/api/tool-reports/dependency-remediation-plan": { panel: "advanced-tool-panel", flow: "dependency-plan" },
  "/api/tool-reports/dependabot/summary": { action: "open-dependabot-alerts-preview" },
  "/api/tool-reports/dependabot/offline-sync": { panel: "advanced-tool-panel", flow: "dependabot-sync" },
  "/api/tool-runs/joern-deep": { panel: "joern-deep-panel" },
  "/api/tool-reports/ssllabs-host/summary": { action: "open-ssllabs-preview" },
  "/api/tool-reports/ssllabs/cache-contract": { panel: "completed-backlog-panel", route: "/api/tool-reports/ssllabs/cache-contract" },
  "/api/tool-runs/openssl-x509-loopback": { action: "open-openssl-loopback" },
  "/api/tool-runs/openssl-x509-authorized": { action: "open-openssl-authorized" },
  "/api/tool-reports/openssl-x509/summary": { action: "open-openssl-x509-preview" },
  "/api/tool-reports/openssl-x509/batch-summary": { action: "open-openssl-x509-preview" },  "/api/project-audits": { view: "projects" },
  "/api/project-audits/diff": { panel: "advanced-tool-panel", flow: "project-audit-diff" },
  "/api/web-infra/dns-email-audit": { panel: "advanced-tool-panel", flow: "dns-email" },
  "/api/ai-llm-security/audit": { panel: "completed-backlog-panel", route: "/api/ai-llm-security/audit" },
  "/api/attack-paths/correlate": { panel: "completed-backlog-panel", route: "/api/attack-paths/correlate" },
  "/api/audit-logging/audit": { panel: "completed-backlog-panel", route: "/api/audit-logging/audit" },
  "/api/auth-protocol/audit": { panel: "completed-backlog-panel", route: "/api/auth-protocol/audit" },
  "/api/blue-team/synthesize-rules": { panel: "completed-backlog-panel", route: "/api/blue-team/synthesize-rules" },
  "/api/browser-extension-pwa/audit": { panel: "completed-backlog-panel", route: "/api/browser-extension-pwa/audit" },
  "/api/business-logic/audit": { panel: "completed-backlog-panel", route: "/api/business-logic/audit" },
  "/api/cloud-iam-security/audit": { panel: "completed-backlog-panel", route: "/api/cloud-iam-security/audit" },
  "/api/crypto-cbom-pqc/audit": { panel: "completed-backlog-panel", route: "/api/crypto-cbom-pqc/audit" },
  "/api/cvss-ssvc/prioritize": { panel: "completed-backlog-panel", route: "/api/cvss-ssvc/prioritize" },
  "/api/database-security/audit": { panel: "completed-backlog-panel", route: "/api/database-security/audit" },
  "/api/desktop-security/audit": { panel: "completed-backlog-panel", route: "/api/desktop-security/audit" },
  "/api/dos-resilience/audit": { panel: "completed-backlog-panel", route: "/api/dos-resilience/audit" },
  "/api/host-hardening/audit": { panel: "completed-backlog-panel", route: "/api/host-hardening/audit" },
  "/api/mobile-security/audit-manifest": { panel: "completed-backlog-panel", route: "/api/mobile-security/audit-manifest" },
  "/api/openapi-security/audit": { panel: "completed-backlog-panel", route: "/api/openapi-security/audit" },
  "/api/privacy-dataflow/audit": { panel: "completed-backlog-panel", route: "/api/privacy-dataflow/audit" },
  "/api/protocol-security/audit": { panel: "completed-backlog-panel", route: "/api/protocol-security/audit" },
  "/api/secret-intelligence/audit": { panel: "completed-backlog-panel", route: "/api/secret-intelligence/audit" },
  "/api/supply-chain-slsa/audit": { panel: "completed-backlog-panel", route: "/api/supply-chain-slsa/audit" },
  "/api/threat-model/generate": { panel: "completed-backlog-panel", route: "/api/threat-model/generate" },
  "/api/web3-iot-security/audit": { panel: "completed-backlog-panel", route: "/api/web3-iot-security/audit" },
  "/api/zero-trust-mesh/audit": { panel: "completed-backlog-panel", route: "/api/zero-trust-mesh/audit" },
});

const TOOL_CARD_ROUTE_LABELS = Object.freeze({
  "/api/tool-runs/syft-grype": "SBOM ve zafiyet analizi",
  "/api/web-infra/dns-email-audit": "DNS ve e-posta yapılandırma denetimi",
  "/api/tool-reports/npm-audit/summary": "Rapor özeti",
  "/api/tool-reports/dependency-remediation-plan": "Düzeltme planı",
  "/api/tool-reports/dependabot/summary": "Uyarı özeti",
  "/api/tool-reports/dependabot/offline-sync": "Çevrimdışı eşitleme",
  "/api/tool-reports/semgrep-native-json/summary": "Rapor özeti",
  "/api/tool-reports/semgrep/rulepack-inventory": "Kural envanteri",
  "/api/tool-reports/semgrep/tls-verify-filter": "TLS doğrulama filtresi",
  "/api/tool-reports/trivy-native-json/summary": "Rapor özeti",
  "/api/tool-reports/trivy/db-freshness": "Veritabanı tazeliği",
  "/api/tool-reports/nuclei-jsonl/summary": "JSONL özeti",
  "/api/tool-reports/nuclei/verification-coverage": "Doğrulama kapsamı",
  "/api/tool-reports/burp-sitemap/summary": "Site haritası özeti",
  "/api/tool-reports/burp-sitemap/handoff-manifest": "Handoff manifesti",
  "/api/tool-reports/burp-logger-csv/summary": "Logger CSV özeti",
  "/api/tool-reports/testssl/summary": "Rapor özeti",
  "/api/tool-reports/testssl/boundary-contract": "Sınır sözleşmesi",
  "/api/tool-reports/trufflehog/summary": "Rapor özeti",
  "/api/tool-runs/secret-bundle/validate": "Sır doğrulama paketi",
  "/api/tool-reports/ssllabs-host/summary": "Ana makine özeti",
  "/api/tool-reports/ssllabs/cache-contract": "Önbellek sözleşmesi",
});

const TOOL_SPECIFIC_PANELS = Object.freeze([
  "trivy-vuln-local-panel",
  "trivy-secret-panel",
  "trivy-image-archive-panel",
  "trivy-kubernetes-single-panel",
  "trivy-kubernetes-batch-panel",
  "trivy-dockerfile-config-panel",
  "trivy-terraform-config-panel",
  "trivy-npm-local-panel",
  "npm-audit-active-panel",
  "osv-active-panel",
  "joern-deep-panel",
]);

function toolCardProfileAvailable(profile) {
  if (!profile) return false;
  if (profile.action === "report_only") return true;
  return profile.runtime === "precheck_passed" &&
    ["native", "authorization_required", "local_input_required"].includes(profile.action);
}

function toolCardProfileVisible(profile) {
  return toolCardProfileAvailable(profile) &&
    Object.hasOwn(TOOL_CARD_DESTINATIONS, profile.route || "");
}

function toolingReadinessMissing() {
  return !state.toolingReadiness || !Array.isArray(state.toolingReadiness.tools);
}

function safeFallbackToolProfiles(tool) {
  const modes = {
    built_in: { runtime: "precheck_passed", action: "native", reason_code: "catalog_built_in_fallback", execution_service: "sniper_serving" },
    report_import: { runtime: "not_applicable", action: "report_only", reason_code: "catalog_report_fallback", execution_service: "not_managed" },
  };
  return (tool?.workflows || []).flatMap(workflow => {
    const fallback = modes[workflow.mode];
    if (!fallback) return [];
    return (workflow.routes || []).filter(route => typeof route === "string" && route.startsWith("/api/"))
      .map(route => ({ mode: workflow.mode, label: workflow.label, route, ...fallback }));
  });
}

function effectiveToolReadinessTools() {
  if (!toolingReadinessMissing()) return state.toolingReadiness.tools;
  return (state.tooling?.tools || []).map(tool => ({ id: tool.id, profiles: safeFallbackToolProfiles(tool) }));
}

function renderToolSpecificPanels(profiles) {
  if (typeof document === "undefined") return;
  const visiblePanels = new Set(profiles.filter(toolCardProfileVisible).map(profile =>
    TOOL_CARD_DESTINATIONS[profile.route || ""]?.panel).filter(Boolean));
  TOOL_SPECIFIC_PANELS.forEach(panelId => {
    document.getElementById?.(panelId)?.classList?.toggle("hidden", !visiblePanels.has(panelId));
  });
}

function openToolCardRoute(route) {
  const destination = TOOL_CARD_DESTINATIONS[route];
  // Sunucu readiness sağladığında onu doğrudan kullan; katalog fallback'ini
  // yalnız readiness bütünüyle alınamadığında üret.
  const readinessTools = state.toolingReadiness && Array.isArray(state.toolingReadiness.tools)
    ? state.toolingReadiness.tools
    : (state.tooling?.tools || []).map(tool => ({ id: tool.id, profiles: safeFallbackToolProfiles(tool) }));
  const profile = readinessTools.flatMap(tool => tool.profiles || [])
    .find(item => item.route === route);
  if (!destination || !toolCardProfileAvailable(profile)) return false;
  if (destination.view) {
    navigate(destination.view);
    return true;
  }
  if (destination.action) {
    const opener = document.querySelector(`[data-view="tooling"] [data-action="${destination.action}"]`);
    if (!opener) return false;
    opener.click();
    return true;
  }
  const panel = document.getElementById(destination.panel);
  if (!panel) return false;
  if (destination.route) {
    // Genel denetçi formunda kartın rotasını seç (form boş/yanlış profille açılmasın).
    const select = document.getElementById("completed-trivy-route");
    if (select) {
      select.value = destination.route;
      if (typeof Event === "function") select.dispatchEvent?.(new Event("change", { bubbles: true }));
    }
  }
  if (destination.flow && typeof globalThis.openAdvancedToolFlow === "function") {
    globalThis.openAdvancedToolFlow(destination.flow);
  }
  panel.scrollIntoView?.({ block: "start" });
  panel.querySelector("input, button")?.focus?.();
  return true;
}

document.addEventListener("click", event => {
  const opener = event.target.closest?.('[data-action="open-project-audit-diff"]');
  if (!opener) return;
  event.preventDefault();
  navigate("tooling");
  if (typeof globalThis.openAdvancedToolFlow === "function") globalThis.openAdvancedToolFlow("project-audit-diff");
});

document.addEventListener("click", event => {
  const button = event.target.closest?.("[data-tool-route]");
  if (!button) return;
  event.preventDefault();
  if (!button.disabled) openToolCardRoute(button.dataset.toolRoute);
});

function taintEngineStatusText(engine) {
  if (!engine || typeof engine !== "object") return "";
  if (engine.enabled === false) return "Veri akışı (taint) analizi kapalı (SNIPER_TAINT_ANALYSIS=0).";
  const label = value => ({ interprocedural_ast: "fonksiyonlar ve dosyalar arası (AST)", token_fallback: "belirteç tabanlı yedek motor (Node sabitlenmemiş)" })[value] || "bilinmiyor";
  const errors = Object.entries(engine.models || {}).flatMap(([language, item]) =>
    (Array.isArray(item?.errors) ? item.errors : []).map(error => `${language}: ${error}`));
  const parser = engine.javascript_parser ? ` · ${engine.javascript_parser}` : "";
  return `Veri akışı motoru — Python: ${label(engine.python)} · JavaScript/TypeScript: ${label(engine.javascript)}${parser}` +
    (errors.length ? ` · Model hataları: ${errors.slice(0, 3).join("; ")}` : " · Modeller yüklendi");
}

function renderTaintEngineStatus(engine) {
  const el = typeof document !== "undefined" ? document.getElementById?.("taint-engine-status") : null;
  if (!el) return;
  const text = taintEngineStatusText(engine);
  el.textContent = text;
  el.classList?.toggle("hidden", !text);
}

function renderTooling() {
  const tooling = state.tooling;
  if (!tooling) return;
  const toolIndex = new Map(tooling.tools.map(tool => [tool.id, tool]));
  const readinessMissing = toolingReadinessMissing();
  const effectiveReadinessTools = effectiveToolReadinessTools();
  const readinessIndex = new Map(effectiveReadinessTools.map(tool => [tool.id, tool.profiles || []]));
  const visibleProfilesByTool = new Map([...readinessIndex].map(([toolId, profiles]) =>
    [toolId, profiles.filter(toolCardProfileVisible)]));
  const visibleTools = tooling.tools.filter(tool => (visibleProfilesByTool.get(tool.id) || []).length > 0);
  const visibleToolIds = new Set(visibleTools.map(tool => tool.id));
  const pinIndex = new Map((state.toolingReadiness?.binary_pins || []).map(pin => [pin.tool === "opengrep" ? "semgrep" : pin.tool, pin]));
  const pinText = pin => {
    const name = `${pin.tool || ""} ${pin.version || ""}`.trim();
    return ({
      pinned: `İkili SHA-256 sabitli (${name})`,
      mismatch: `İkili SHA-256 uyuşmuyor — çalıştırılmaz (${name})`,
      unpinned: `İkili sabitlenmemiş — çalıştırılmaz (${name})`,
      unavailable: `İkili bulunamadı veya güvenli değil (${name})`,
    })[pin.state] || "İkili durumu bilinmiyor";
  };
  const readinessText = profile => {
    if (profile.runtime === "unavailable" && profile.reason_code === "binary_digest_mismatch") return "İkili SHA-256 uyuşmuyor";
    if (profile.runtime === "unavailable" && profile.reason_code === "binary_unpinned") return "İkili sabitlenmemiş";
    if (profile.runtime === "unavailable") return "Ön koşul eksik";
    if (profile.action === "authorization_required") return "Ön koşul bulundu · hedef izni gerekli";
    if (profile.action === "local_input_required") return "Ön koşul bulundu · yerel girdi/onay gerekli";
    return ({ native: "Yerleşik akış", report_only: "Yalnız rapor özeti", external_only: "Yalnız harici yöntem", manual: "Manuel inceleme" })[profile.action] || "Durum bilinmiyor";
  };
  const summary = tooling.summary || {};
  const visibleFlowCount = [...visibleProfilesByTool.values()].reduce((total, profiles) => total + new Set(
    profiles.map(profile => `${profile.label || ""}\u001f${readinessText(profile)}`)
  ).size, 0);
  const metrics = [
    ["KONTROL EŞLEMESİ", summary.control_count || 0, "Tüm metodoloji maddeleri"],
    ["KATEGORİ", summary.category_count || 0, "Web, API, kod ve altyapı"],
    ["COMMUNITY'DE GÖRÜNEN", visibleTools.length, "Hazır araçlar ve rapor içe aktarma yöntemleri"],
    ["KULLANILABİLİR AKIŞ", visibleFlowCount, "Tekrarsız, çalışma zamanı doğrulanmış akışlar"],
  ];
  $("#tooling-summary").innerHTML = metrics.map(([label, value, note]) => `<article><small>${esc(label)}</small><b>${esc(value)}</b><span>${esc(note)}</span></article>`).join("");
  const readinessWarning = readinessMissing
    ? `<div class="error-message" role="alert">Araç uygunluk durumu alınamadı. Yalnız yerleşik ve rapor içe aktarma akışları gösteriliyor.</div>`
    : "";
  $("#tooling-policy").innerHTML = `<div><span>✓</span><p><b>Doğrulanabilir sonuç ilkesi</b><small>${esc(tooling.policy.native)} ${esc(tooling.policy.external)} ${esc(tooling.policy.completion)}</small></p></div><button class="button secondary" data-action="new-lab" data-type="external_result">Harici sonuç kaydet</button>${readinessWarning}`;
  $("#tool-count-label").textContent = `${visibleTools.length} kullanılabilir araç/yöntem`;
  renderTaintEngineStatus(state.toolingReadiness?.taint_engine);
  renderToolSpecificPanels(effectiveReadinessTools.flatMap(tool => tool.profiles || []));
  $("#tool-card-grid").innerHTML = visibleTools.map(tool => {
    const profiles = visibleProfilesByTool.get(tool.id) || [];
    const capabilityGroups = new Map();
    profiles.forEach(profile => {
      const status = readinessText(profile);
      const key = `${profile.label || ""}\u001f${status}`;
      if (!capabilityGroups.has(key)) capabilityGroups.set(key, { label: profile.label, status, profiles: [] });
      capabilityGroups.get(key).profiles.push(profile);
    });
    const pin = pinIndex.get(tool.id);
    const hasRunnableProfile = profiles.some(profile => profile.action !== "report_only");
    const pinHtml = pin && hasRunnableProfile
      ? `<div class="tool-formats" aria-label="İkili bütünlüğü"><span title="${esc(pin.provenance || pin.reason_code || "")}">${esc(pinText(pin))}</span></div>`
      : "";
    const capabilitiesHtml = [...capabilityGroups.values()].map(group => {
      const actionGroups = new Map();
      group.profiles.forEach(profile => {
        const destination = TOOL_CARD_DESTINATIONS[profile.route];
        const key = [destination.view, destination.action, destination.panel, destination.flow].join("\u001f");
        if (!actionGroups.has(key)) actionGroups.set(key, profile);
      });
      const actions = [...actionGroups.values()].map(profile => {
        const destination = TOOL_CARD_DESTINATIONS[profile.route];
        const label = TOOL_CARD_ROUTE_LABELS[profile.route] ||
          (destination.view ? "Hedefleri aç" : profile.action === "report_only" ? "Raporu aç" : "Formu aç");
        return `<button type="button" class="button secondary" data-tool-route="${esc(profile.route)}">${esc(label)}</button>`;
      }).join("");
      return `<section class="tool-capability"><div><b>${esc(group.label)}</b><small>${esc(group.status)}</small></div><div class="tool-card-actions">${actions}</div></section>`;
    }).join("");
    return `<article class="tool-card"><div class="tool-card-head"><span>${esc(tool.kind)}</span><b>${esc(tool.license)}</b></div><h3>${esc(tool.name)}</h3><p>${esc(tool.summary)}</p><div class="tool-formats">${tool.formats.map(format => `<span>${esc(format)}</span>`).join("")}</div>${pinHtml}<div class="tool-capabilities" aria-label="Kullanılabilir yetenekler">${capabilitiesHtml}</div><small>${esc(hasRunnableProfile ? "Çalıştırma için gerekli izin, kapsam ve girdiler çalışma anında ayrıca doğrulanır." : "Rapor özeti içe aktarma işlemi tarama başlatmaz.")}</small><a href="${esc(tool.url)}" target="_blank" rel="noopener noreferrer">Resmî sayfa →</a></article>`;
  }).join("");
  $("#tool-matrix-body").innerHTML = tooling.categories.map(category => `<tr><td><b>${esc(category.title)}</b><small>${esc(category.reference)}</small></td><td>${Number(category.control_count)}</td><td><span class="coverage-chip">${esc(category.coverage)}</span></td><td><div class="tool-tags">${category.tool_ids.filter(toolId => visibleToolIds.has(toolId)).map(toolId => `<span>${esc(toolIndex.get(toolId)?.name || toolId)}</span>`).join("")}</div></td><td>${esc(category.required_input)}</td></tr>`).join("");
}

function labScenarioLabel(type) {
  return ({ capacity_plan: "Kapasite planı", lockout_plan: "Sentetik kilitlenme planı", external_result: "Harici sonuç kaydı" })[type] || type;
}

function labScenarioIcon(type) {
  return ({ capacity_plan: "↗", lockout_plan: "⌁", external_result: "#" })[type] || "◫";
}

function labMetric(run) {
  if (run.scenario_type === "capacity_plan") return `<strong>${Number(run.results?.projected_requests || 0).toLocaleString("tr-TR")}</strong>tahmini istek`;
  if (run.scenario_type === "lockout_plan") return `<strong>${Number(run.results?.requests_generated || 0)}</strong>Sniper isteği`;
  return `<strong>MASKELİ</strong>sonuç kaydı`;
}

function renderLabRuns() {
  $("#lab-count-label").textContent = `${state.labRuns.length} yerel kayıt`;
  $("#lab-empty").classList.toggle("hidden", state.labRuns.length > 0);
  $("#lab-run-list").innerHTML = state.labRuns.map(run => `<article class="lab-run-row" data-action="open-lab" data-id="${esc(run.id)}">
    <span>${labScenarioIcon(run.scenario_type)}</span><div><b>${esc(run.name)}</b><small>${esc(labScenarioLabel(run.scenario_type))} · ${esc(run.environment.toUpperCase())} · ${formatDate(run.created_at)}</small></div>
    <div class="lab-run-metric">${labMetric(run)}</div><span class="status-pill ${esc(run.status)}">${statusLabel(run.status)}</span><span>›</span>
  </article>`).join("");
}

function openLabCreator(type) {
  const form = $("#lab-form");
  form.reset();
  $("#lab-scenario-type").value = type;
  $("#lab-engagement").innerHTML = `<option value="">Bağımsız kayıt</option>${state.engagements.map(item => `<option value="${esc(item.id)}">${esc(item.name)} · ${esc(item.authorization_ref)}</option>`).join("")}`;
  const environment = $("#lab-environment");
  environment.innerHTML = type === "external_result" ? `<option value="staging">Staging</option><option value="lab">Laboratuvar</option><option value="production">Üretim — yalnız sonuç kaydı</option>` : `<option value="staging">Staging</option><option value="lab">Laboratuvar</option>`; // sniper-reviewed: html-safe
  const details = {
    capacity_plan: ["KAPASİTE PLANLAMASI", "Staging kapasite planı", "Hedef yük ve durdurma eşikleri yalnızca projeksiyon üretir; hiçbir hedef adresi alınmaz."],
    lockout_plan: ["SENTETİK HESAP PLANI", "Kilitlenme doğrulama planı", "Gerçek kullanıcı veya parola almadan kontrollü gözlem adımlarını hesaplar."],
    external_result: ["MASKELİ HARİCİ SONUÇ", "Yetkili test sonucunu kaydedin", "Başka bir araçla yürütülen yetkili testin ham veri içermeyen özetini saklar."],
  }[type];
  $("#lab-modal-eyebrow").textContent = details[0];
  $("#lab-modal-title").textContent = details[1];
  $("#lab-modal-copy").textContent = details[2];
  const fields = {
    capacity_plan: `<p class="field-help">Planlanan değerler gerçek performans sonucu değildir. Hata veya gecikme eşiği aşılırsa harici testin acil durdurulması için kullanılır.</p><label>Hedef hız (istek/sn)<input name="target_rps" type="number" min="1" max="100000" value="50" required></label><label>Süre (saniye)<input name="duration_seconds" type="number" min="1" max="86400" value="60" required></label><label>Temel gecikme (ms)<input name="baseline_latency_ms" type="number" min="1" max="600000" value="200" required></label><label>Azami hata oranı (%)<input name="max_error_percent" type="number" min="0" max="100" step="0.1" value="2" required></label><label>Durdurma gecikmesi (ms)<input name="abort_latency_ms" type="number" min="1" max="600000" value="1000" required></label><label>Toparlanma gözlemi (sn)<input name="recovery_seconds" type="number" min="1" max="3600" value="120" required></label><label class="full">Acil durum sorumlusu / ekip takma adı<input name="emergency_contact" maxlength="160" placeholder="Nöbetçi SRE ekibi" required></label>`,
    lockout_plan: `<p class="field-help">Bu formda kullanıcı adı, e-posta veya parola alanı yoktur. Takma ad yalnızca önceden oluşturulmuş sentetik test hesabını işaret eder.</p><label class="full">Sentetik hesap takma adı<input name="synthetic_account_alias" maxlength="100" placeholder="sentetik-test-01" required></label><label>Azami kontrollü adım<input name="max_attempts" type="number" min="1" max="10" value="5" required></label><label>Adımlar arası süre (sn)<input name="interval_seconds" type="number" min="5" max="3600" value="10" required></label><label>Beklenen kilit süresi (sn)<input name="expected_lockout_seconds" type="number" min="1" max="86400" value="300" required></label><label>İzleme sinyali<input name="monitoring_signal" maxlength="240" placeholder="auth_lockout_total veya SIEM alarm adı" required></label>`,
    external_result: `<p class="field-help">Ham HTTP günlüğü, parola, erişim anahtarı veya çıkarılmış veri yapıştırmayın. Yalnız kimliksizleştirilmiş özet ve bütünlük hash’i kaydedilir.</p><label>Yetkili harici araç<input name="tool_name" maxlength="120" placeholder="Örn. OWASP ZAP" required></label><label>Test zaman penceresi<input name="test_window" maxlength="240" placeholder="01 Eylül 22:00–22:15" required></label><label class="full">161 kontrolden biri (isteğe bağlı)<select name="control_id" id="lab-control"><option value="">Önce manuel denetim seçin</option></select></label><label class="full">Maskeli kanıt hash’i<input name="evidence_hash" maxlength="128" placeholder="sha256:…" required></label><label class="full">Sonuç özeti<textarea name="outcome_summary" rows="4" maxlength="4000" placeholder="Eşikler, gözlenen sonuç ve toparlanma; ham günlük olmadan." required></textarea></label>`,
  }[type];
  $("#lab-specific-fields").innerHTML = fields; // sniper-reviewed: html-safe
  if (type === "external_result") renderLabControlOptions("");
  showModal("lab-modal");
}

async function renderLabControlOptions(engagementId) {
  const select = $("#lab-control");
  if (!select) return;
  if (!engagementId) {
    select.innerHTML = `<option value="">Denetim seçilmedi — bağımsız kayıt</option>`;
    return;
  }
  select.disabled = true;
  select.innerHTML = `<option value="">Kontroller yükleniyor…</option>`;
  try {
    const engagement = await api(`/api/engagements/${encodeURIComponent(engagementId)}`);
    select.innerHTML = `<option value="">Kontrole bağlama</option>${engagement.tests.map(test => `<option value="${esc(test.control_id)}">${esc(test.control_id)} · ${esc(test.title)}</option>`).join("")}`;
  } catch (error) {
    select.innerHTML = `<option value="">Kontroller yüklenemedi</option>`;
    toast(error.message, "error");
  } finally {
    select.disabled = false;
  }
}

function labScenarioDetails(run) {
  const assumptions = run && typeof run.assumptions === "object" && !Array.isArray(run.assumptions) && run.assumptions ? run.assumptions : {};
  const results = run && typeof run.results === "object" && !Array.isArray(run.results) && run.results ? run.results : {};
  if (run?.scenario_type === "capacity_plan") {
    return `<div class="lab-detail-summary" data-lab-scenario-details="capacity_plan">`
      + `<div><small>HEDEF HIZ / SÜRE</small><b>${esc(String(Number(assumptions.target_rps || 0)))} istek/sn · ${esc(String(Number(assumptions.duration_seconds || 0)))} sn</b></div>`
      + `<div><small>TEMEL GECİKME</small><b>${esc(String(Number(assumptions.baseline_latency_ms || 0)))} ms</b></div>`
      + `<div><small>DURDURMA EŞİKLERİ</small><b>%${esc(String(assumptions.max_error_percent ?? 0))} hata · ${esc(String(Number(assumptions.abort_latency_ms || 0)))} ms</b></div>`
      + `<div><small>TOPARLANMA GÖZLEMİ</small><b>${esc(String(Number(assumptions.recovery_seconds || 0)))} sn</b></div>`
      + `<div><small>ACİL DURUM SORUMLUSU</small><b>${esc(assumptions.emergency_contact || "—")}</b></div>`
      + `</div>`;
  }
  if (run?.scenario_type === "lockout_plan") {
    return `<div class="lab-detail-summary" data-lab-scenario-details="lockout_plan">`
      + `<div><small>SENTETİK HESAP TAKMA ADI</small><b>${esc(assumptions.synthetic_account_alias || "—")}</b></div>`
      + `<div><small>İZLEME SİNYALİ</small><b>${esc(assumptions.monitoring_signal || "—")}</b></div>`
      + `<div><small>KONTROLLÜ ADIM / ARALIK</small><b>${esc(String(Number(assumptions.max_attempts || 0)))} adım · ${esc(String(Number(assumptions.interval_seconds || 0)))} sn</b></div>`
      + `<div><small>BEKLENEN KİLİT SÜRESİ</small><b>${esc(String(Number(assumptions.expected_lockout_seconds || 0)))} sn</b></div>`
      + `</div>`;
  }
  const controlId = typeof assumptions.control_id === "string" ? assumptions.control_id.trim() : "";
  return `<div class="lab-detail-summary" data-lab-scenario-details="external_result">`
    + `<div><small>YETKİLİ HARİCİ ARAÇ</small><b>${esc(assumptions.tool_name || "—")}</b></div>`
    + `<div><small>TEST ZAMAN PENCERESİ</small><b>${esc(assumptions.test_window || "—")}</b></div>`
    + `<div><small>KANIT HASH’İ</small><b>${esc(assumptions.evidence_hash || "—")}</b></div>`
    + (controlId ? `<div><small>BAĞLI KONTROL</small><b>${esc(controlId)}</b></div>` : "")
    + `<div><small>MASKELİ SONUÇ ÖZETİ</small><b>${esc(results.outcome_summary || "—")}</b></div>`
    + `</div>`;
}

let activeLabDetailTicket = null;

async function openLabDetail(runId) {
  const requestTicket = Symbol("lab-detail");
  activeLabDetailTicket = requestTicket;
  const isCurrent = () => activeLabDetailTicket === requestTicket;
  state.selectedLabRun = null;
  $("#lab-detail-title").textContent = "";
  $("#lab-detail-content").innerHTML = "";
  const form = $("#lab-update-form");
  form?.reset?.();
  try {
    const run = await api(`/api/lab-runs/${encodeURIComponent(runId)}`);
    if (!isCurrent()) return;
    if (!run || typeof run !== "object" || String(run.id ?? "") !== String(runId ?? "")) {
      throw new Error("Laboratuvar kaydı yanıtı farklı bir kayda ait.");
    }
    state.selectedLabRun = run;
    $("#lab-detail-title").textContent = run.name;
    const results = run && typeof run.results === "object" && !Array.isArray(run.results) && run.results ? run.results : {};
    const engagementParts = [run.engagement_name, run.engagement_id]
      .map(value => (typeof value === "string" ? value.trim() : ""))
      .filter(Boolean);
    const engagementHtml = engagementParts.length
      ? `<div><small>BAĞLI DENETİM</small><b>${esc(engagementParts.join(" · "))}</b></div>`
      : "";
    const calculation = run.scenario_type === "capacity_plan"
      ? `<div><small>TAHMİNİ İSTEK</small><strong>${Number(results.projected_requests || 0).toLocaleString("tr-TR")}</strong></div><div><small>TAHMİNİ EŞZAMANLILIK</small><strong>${Number(results.estimated_concurrency || 0)}</strong></div>`
      : run.scenario_type === "lockout_plan"
        ? `<div><small>MİNİMUM GÖZLEM</small><strong>${Number(results.minimum_observation_seconds || 0)} sn</strong></div><div><small>SNIPER İSTEĞİ</small><strong>0</strong></div>`
        : `<div><small>KANIT TÜRÜ</small><strong>Maskeli</strong></div><div><small>SNIPER İSTEĞİ</small><strong>0</strong></div>`;
    $("#lab-detail-content").innerHTML = `<div class="lab-detail-summary"><div><small>SENARYO</small><b>${esc(labScenarioLabel(run.scenario_type))}</b></div><div><small>ORTAM</small><b>${esc(String(run.environment || "").toUpperCase())}</b></div><div><small>YETKİ REFERANSI</small><b>${esc(run.authorization_ref)}</b></div>${engagementHtml}</div><div class="lab-calculation">${calculation}</div>${labScenarioDetails(run)}<div class="lab-safety-result"><b>Güvenlik doğrulaması:</b> Sniper tarafından üretilen trafik/istek sayısı 0. Bu kayıt yalnızca planlama veya maskeli harici sonuç içerir.</div>`;
    form.elements.status.value = run.status;
    form.elements.evidence_summary.value = run.evidence_summary || "";
    showModal("lab-detail-modal");
  } catch (error) {
    if (isCurrent()) toast(error.message, "error");
  }
}

function openEngagementCreator() {
  if (!state.targets.length) {
    toast("Önce bir hedef ekleyin.", "error");
    navigate("targets");
    return;
  }
  $("#engagement-form").reset();
  $("#engagement-target").innerHTML = state.targets.map(target => `<option value="${esc(target.id)}">${esc(target.hostname)} · ${esc(target.url)}</option>`).join("");
  showModal("engagement-modal");
}

async function openEngagement(engagementId) {
  showModal("pentest-workspace");
  $("#workspace-content").innerHTML = `<div class="scan-progress"><div class="spinner"></div><b>Manuel denetim yükleniyor</b></div>`;
  try {
    state.selectedEngagement = await api(`/api/engagements/${encodeURIComponent(engagementId)}`);
    state.workspaceTab = "overview";
    state.methodologyCategory = "all";
    state.methodologyQuery = "";
    state.findingFilter = "all";
    $("#workspace-title").textContent = state.selectedEngagement.name;
    $("#workspace-subtitle").textContent = `${state.selectedEngagement.target_url}${state.selectedEngagement.authorization_ref ? ` · ${state.selectedEngagement.authorization_ref}` : ""}`;
    $("#workspace-report").href = `/api/engagements/${encodeURIComponent(engagementId)}/report.html`;
    $("#workspace-download").href = `/api/engagements/${encodeURIComponent(engagementId)}/report.html?download=1`;
    $("#workspace-json").href = `/api/engagements/${encodeURIComponent(engagementId)}/report.json?download=1`;
    $("#workspace-csv").href = `/api/engagements/${encodeURIComponent(engagementId)}/report.csv?download=1`;
    $("#workspace-sarif").href = `/api/engagements/${encodeURIComponent(engagementId)}/report.sarif?download=1`;
    renderWorkspace();
  } catch (error) {
    $("#workspace-content").innerHTML = `<div class="empty-state"><h3>Denetim açılamadı</h3><p>${esc(error.message)}</p></div>`;
  }
}

function renderWorkspace() {
  const engagement = state.selectedEngagement;
  if (!engagement) return;
  $$("[data-workspace-tab]").forEach(button => button.classList.toggle("active", button.dataset.workspaceTab === state.workspaceTab));
  if (state.workspaceTab === "overview") renderWorkspaceOverview(engagement);
  if (state.workspaceTab === "methodology") renderMethodology(engagement);
  if (state.workspaceTab === "findings") renderManualFindings(engagement);
  if (state.workspaceTab === "scope") renderScopeEditor(engagement);
}

function toolEvidenceSummary(link) {
  const count = value => Number(value || 0);
  const severity = link.severity_counts || {};
  switch (link.tool_identity) {
    case "nmap-xml":
      return "Host: " + count(link.host_count) + " · Açık port: " + count(link.open_port_count);
    case "testssl-flat-json":
      return "Kayıt: " + count(link.record_count) + " · HIGH: " + count(severity.HIGH)
        + " · CRITICAL: " + count(severity.CRITICAL);
    case "trivy-native-json": {
      const findings = link.finding_counts || {};
      return "Sonuç: " + count(link.result_count) + " · Zafiyet: " + count(findings.vulnerabilities)
        + " · Yanlış yapılandırma: " + count(findings.misconfigurations);
    }
    case "gitleaks-native-json":
      return "Bulgu: " + count(link.total_findings) + " · Kural: " + count(link.rules_triggered)
        + " · Dosya: " + count(link.files_affected);
    case "nuclei-jsonl":
      return "Kayıt: " + count(link.record_count) + " · Şablon: " + count(link.unique_template_count)
        + " · HIGH: " + count(severity.high) + " · CRITICAL: " + count(severity.critical);
    case "burp-sitemap-xml":
      return "Site haritası kaydı: " + count(link.item_count);
    case "zap-traditional-json":
      return "Site: " + count(link.site_count) + " · Uyarı türü: " + count(link.alert_type_count)
        + " · Örnek: " + count(link.instance_count);
    case "semgrep-local":
    case "semgrep-native-json":
      return "Bulgu: " + count(link.result_count) + " · ERROR: " + count(severity.ERROR)
        + " · WARNING: " + count(severity.WARNING);
    case "sarif":
      return "Çalışma: " + count(link.run_count) + " · Sonuç: " + count(link.result_count);
    case "trufflehog-native-json-records":
      return "Bulgu: " + count(link.total_findings) + " · Doğrulanmış: " + count(link.verified_findings)
        + " · Doğrulanmamış: " + count(link.unverified_findings)
        + " · Dedektör: " + count(link.detectors_triggered);
    case "npm-audit-v2": {
      const packages = link.package_severity_counts || {};
      return "Etkilenen paket: " + count(link.affected_package_count) + " · info: " + count(packages.info)
        + " · low: " + count(packages.low) + " · moderate: " + count(packages.moderate)
        + " · high: " + count(packages.high) + " · critical: " + count(packages.critical);
    }
    case "dependabot-alerts":
      return "Uyarı: " + count(link.alert_count) + " · Yaması hazır açık: "
        + count(link.open_alerts_with_available_patched_version);
    case "ssllabs-v4-host":
      return "Durum: " + String(link.assessment_status || "—") + " · Endpoint: " + count(link.endpoint_count);
    case "openssl-x509-dates-fingerprint-v1":
      return "Durum: " + String(link.validity || "—") + " · Kalan gün: " + count(link.days_until_expiry);
    case "playwright-json":
      return "Dosya: " + count(link.file_count) + " · Test: " + count(link.test_count);
    case "k6-handle-summary-json":
    case "k6-machine-summary-v1":
      return "HTTP isteği: " + count(link.http_requests);
    case "schemathesis-junit-xml":
      return "Paket: " + count(link.suite_count) + " · Testcase: " + count(link.testcase_count);
    case "ecs-ndjson":
      return "Olay kaydı: " + count(link.record_count);
    default:
      return "Toplu kanıt bağlantısı · uzman incelemesi gerekli";
  }
}

function renderWorkspaceOverview(engagement) {
  const coverage = engagement.coverage || { percent: 0, completed: 0, total: 0 };
  const remediation = engagement.remediation || {};
  const scan = engagement.latest_scan;
  const toolEvidence = Array.isArray(engagement.tool_evidence) ? engagement.tool_evidence : [];
  $("#workspace-content").innerHTML = `<div class="workspace-layout">
    <div class="workspace-kpis"><article class="workspace-kpi"><small>MANUEL KAPSAM İLERLEMESİ</small><b>${coverage.percent}%</b></article><article class="workspace-kpi"><small>UZMANCA DEĞERLENDİRİLEN</small><b>${coverage.completed}/${coverage.total}</b></article><article class="workspace-kpi"><small>ETKİN BULGU</small><b>${Number(remediation.active || 0)}</b></article><article class="workspace-kpi ${Number(remediation.overdue || 0) ? "attention" : ""}"><small>GECİKEN / YENİDEN TEST</small><b>${Number(remediation.overdue || 0)} / ${Number(remediation.retest || 0)}</b></article></div>
    <div class="coverage-explainer"><span>i</span><div><b>Bu yüzdeler manuel test ilerlemesini gösterir.</b><p>${scan ? `Otomatik temel tarama ${formatDate(scan.finished_at)} tarihinde tamamlandı ve aşağıdaki ayrı kartta gösteriliyor.` : "Henüz otomatik temel tarama tamamlanmadı."} Otomatik tarama; oturum, yetkilendirme, iş mantığı gibi uzman doğrulaması gerektiren maddeleri tamamlandı olarak işaretlemez.</p></div></div>
    <div class="workspace-two-col"><section class="workspace-section"><div class="workspace-section-head"><h3>Manuel kategori ilerlemesi</h3><button class="text-button" data-workspace-tab="methodology">Tüm manuel testler →</button></div><div class="category-progress-list">${engagement.categories.map(category => `<div class="category-progress"><span>${esc(category.title)}</span><div class="risk-bar"><i data-style="--width:${category.percent}%;--risk:#087b54"></i></div><b>${category.percent}%<small>${category.completed}/${category.total} manuel</small></b></div>`).join("")}</div></section>
    <aside><section class="workspace-section"><div class="workspace-section-head"><h3>Otomatik temel tarama</h3></div>${scan ? `<div class="report-summary" data-style="padding:18px;border:0"><div class="report-grade"><b>${scan.score}</b><small>/100 · ${esc(scan.grade)}</small></div><div class="report-meta"><b>Tamamlandı · ${scan.findings.length} otomatik bulgu</b><small>${formatDate(scan.finished_at)} · TLS, başlıklar ve dönen sayfa üzerinde pasif kontroller</small><button class="mini-button" data-action="report" data-id="${esc(scan.id)}">Otomatik raporu incele</button></div></div>` : `<div class="empty-state" data-style="padding:30px 15px"><p>Bu hedefte tamamlanmış temel tarama yok.</p><button class="mini-button accent" data-action="scan-from-engagement">Tarama başlat</button></div>`}</section>
    ${specialApprovalSummary(engagement)}</aside></div>
    <section class="workspace-section"><div class="workspace-section-head"><h3>Bağlı toplu araç kanıtları · ${toolEvidence.length}</h3><div class="button-row"><button class="mini-button accent" data-action="sync-auto-evidence">Otomatik Kanıtları 161 WSTG Kontrolüne Eşitle</button><button class="mini-button" data-action="verify-retests">Yeniden Test ve SLA Doğrula</button><a class="mini-button" href="/api/engagements/${encodeURIComponent(engagement.id)}/compliance-matrix" target="_blank" rel="noopener">Uyumluluk Matrisi</a></div></div><p>Bu bağlantılar uzman incelemesi içindir; raporun denetim hedefinden üretildiğini tek başına doğrulamaz.</p>
      ${toolEvidence.slice(0, 5).map(link => `<article class="audit-item"><div><b>${esc(link.tool_identity)} · ${esc(link.control_id)}</b><small>SHA-256: ${esc(link.report_sha256)} · ${esc(toolEvidenceSummary(link))}</small></div></article>`).join("") || "<p>Henüz bağlı toplu araç kanıtı yok.</p>"}
      ${toolEvidence.length > 5 ? `<small>Son 5 bağlantı gösteriliyor. Tam liste denetim JSON raporunda bulunur.</small>` : ""}
    </section></div>`;
}

function specialApprovalSummary(engagement) {
  const approvals = engagement.special_approvals || {};
  const enabled = [
    ["controlled_lockout", "Kontrollü hesap kilitlenmesi"], ["staging_capacity", "Staging kapasite gözlemi"], ["redacted_data_proof", "Maskeli veri kanıtı"],
  ].filter(([key]) => approvals[key]).map(([, label]) => label);
  return `<div class="special-approval-note"><b>Özel onaylı protokoller</b><br>${enabled.length ? enabled.map(esc).join(" · ") : "Bu denetimde özel onaylı doğrulama yok."}<br><br>Sniper bu kontroller için saldırı trafiği veya ham veri üretmez; yalnız uzman kanıtını kaydeder.</div>`;
}

function renderMethodology(engagement) {
  const categories = engagement.categories;
  const query = state.methodologyQuery.toLowerCase();
  const turkishQuery = state.methodologyQuery.toLocaleLowerCase("tr");
  const tests = engagement.tests.filter(test => {
    if (state.methodologyCategory !== "all" && test.category !== state.methodologyCategory) return false;
    const searchable = `${test.control_id} ${test.title} ${test.objective}`;
    return searchable.toLowerCase().includes(query) || searchable.toLocaleLowerCase("tr").includes(turkishQuery);
  });
  $("#workspace-content").innerHTML = `<div class="workspace-layout"><div class="methodology-toolbar"><label class="search"><span>⌕</span><input id="methodology-search" type="search" placeholder="Kontrol ara…" value="${esc(state.methodologyQuery)}"></label><span class="muted">${tests.length} test adımı</span></div><div class="category-filter"><button class="${state.methodologyCategory === "all" ? "active" : ""}" data-category="all">Tümü</button>${categories.map(category => `<button class="${state.methodologyCategory === category.slug ? "active" : ""}" data-category="${esc(category.slug)}">${esc(category.title)} · ${category.completed}/${category.total}</button>`).join("")}</div><div class="test-list">${tests.map(test => `<article class="test-row" data-action="edit-test" data-control="${esc(test.control_id)}"><code>${esc(test.control_id)}</code><div><b>${esc(test.title)}</b><small>${esc(test.objective)}</small></div><span class="test-status ${esc(test.status)}">${testStatusLabel(test.status)}</span><span>›</span></article>`).join("") || `<div class="empty-state"><h3>Eşleşen test yok</h3></div>`}</div></div>`;
}

function renderManualFindings(engagement) {
  const filters = [
    ["all", "Tümü"], ["active", "Etkin"], ["in_progress", "Çalışılıyor"],
    ["retest", "Yeniden test"], ["overdue", "Geciken"], ["risk_accepted", "Risk kabulü"], ["closed", "Kapalı"],
  ];
  const findings = engagement.findings.filter(finding => {
    if (state.findingFilter === "all") return true;
    if (state.findingFilter === "active") return activeFindingStatuses.has(finding.status);
    if (state.findingFilter === "retest") return ["retest_required", "reopened"].includes(finding.status);
    if (state.findingFilter === "overdue") return findingIsOverdue(finding);
    if (state.findingFilter === "closed") return ["resolved", "risk_accepted"].includes(finding.status);
    return finding.status === state.findingFilter;
  });
  const filterBar = `<div class="finding-filters">${filters.map(([key, label]) => `<button class="${state.findingFilter === key ? "active" : ""}" data-finding-filter="${key}" aria-pressed="${state.findingFilter === key ? "true" : "false"}">${label}</button>`).join("")}</div>`;
  $("#workspace-content").innerHTML = `<div class="workspace-layout"><div class="finding-toolbar"><div><p class="eyebrow">UZMAN BULGULARI</p><b>${findings.length} / ${engagement.findings.length} kayıt</b></div><button class="button primary" data-action="add-finding">＋ Yeni bulgu</button></div>${filterBar}${findings.map(finding => { const overdue = findingIsOverdue(finding); const tags = [finding.owasp_category, finding.cwe_id, finding.cvss_score != null ? `CVSS ${Number(finding.cvss_score).toFixed(1)}` : "", finding.remediation_owner ? `Sorumlu: ${finding.remediation_owner}` : "", finding.due_date ? `Hedef: ${finding.due_date}` : "", overdue ? "GECİKMİŞ" : ""].filter(Boolean); return `<article class="manual-finding-card ${esc(finding.severity)} ${overdue ? "overdue" : ""}" data-action="edit-finding" data-id="${esc(finding.id)}"><span class="finding-stripe"></span><div><div class="finding-card-head"><span class="severity-label">${esc(severityLabel(finding.severity).toUpperCase())}</span><h3>${esc(finding.title)}</h3></div>${tags.length ? `<div class="risk-tags">${tags.map(tag => `<span>${esc(tag)}</span>`).join("")}</div>` : ""}<p>${esc(finding.description)}</p><p><b>Etkilenen:</b> ${esc(finding.affected_asset)}</p>${finding.resolution_notes ? `<p class="resolution-preview"><b>Çözüm notu:</b> ${esc(finding.resolution_notes)}</p>` : ""}</div><div class="finding-side"><span class="status-pill ${esc(finding.status)}">${statusLabel(finding.status)}</span><small>${formatDate(finding.updated_at)}</small>${finding.last_retested_at ? `<small>Test: ${formatDate(finding.last_retested_at)}</small>` : ""}</div></article>`; }).join("") || `<div class="panel empty-state"><div class="empty-icon">✓</div><h3>Bu filtrede bulgu yok</h3><p>Başka bir durum filtresi seçebilir veya yeni bulgu ekleyebilirsiniz.</p></div>`}</div>`;
}

function renderScopeEditor(engagement) {
  $("#workspace-content").innerHTML = `<form id="scope-form" class="workspace-layout scope-editor"><section class="workspace-section"><h3>Kapsam içi</h3><label>İsteğe bağlı kapsam notu<textarea name="scope_notes" rows="9" maxlength="8000">${esc(engagement.scope_notes)}</textarea></label><label>İsteğe bağlı test penceresi<input name="test_window" maxlength="240" value="${esc(engagement.test_window)}"></label></section><section class="workspace-section"><h3>Kapsam dışı ve yönetişim</h3><label>İsteğe bağlı kapsam dışı notu<textarea name="out_of_scope" rows="6" maxlength="5000">${esc(engagement.out_of_scope)}</textarea></label><label>İsteğe bağlı yetki referansı<input name="authorization_ref" maxlength="240" value="${esc(engagement.authorization_ref)}"></label><label>Durum<select name="status"><option value="active" ${engagement.status === "active" ? "selected" : ""}>Etkin</option><option value="paused" ${engagement.status === "paused" ? "selected" : ""}>Duraklatıldı</option><option value="completed" ${engagement.status === "completed" ? "selected" : ""}>Tamamlandı</option></select></label></section><section class="workspace-section full"><h3>Yönetici özeti</h3><label>Teknik olmayan karar vericiler için özet<textarea name="executive_summary" rows="8" maxlength="12000" placeholder="Kapsam, genel risk durumu, öne çıkan etkiler ve öncelikli öneriler…">${esc(engagement.executive_summary || "")}</textarea></label><button class="button primary" type="submit">Kapsamı ve özeti kaydet</button></section></form>`;
}

function openTestEditor(controlId) {
  const test = state.selectedEngagement?.tests.find(item => item.control_id === controlId);
  if (!test) return;
  state.selectedTest = test;
  $("#test-control-id").textContent = `${test.control_id} · ${test.reference}`;
  $("#test-modal-title").textContent = test.title;
  $("#test-objective").textContent = test.objective;
  const categoryPlan = state.tooling?.categories?.find(category => category.slug === test.category);
  const toolIndex = new Map((state.tooling?.tools || []).map(tool => [tool.id, tool]));
  $("#test-tool-hint").innerHTML = categoryPlan ? `<b>Önerilen doğrulama zinciri</b><div>${categoryPlan.tool_ids.map(toolId => `<span>${esc(toolIndex.get(toolId)?.name || toolId)}</span>`).join("")}</div><small>${esc(categoryPlan.coverage)} · Gerekli: ${esc(categoryPlan.required_input)}. Araç sonucu tek başına “geçti” sayılmaz; uzman doğrulaması gerekir.</small>` : "";
  const form = $("#test-form");
  form.elements.status.value = test.status;
  form.elements.notes.value = test.notes || "";
  form.elements.evidence.value = test.evidence || "";
  showModal("test-modal");
}

function openFindingEditor(findingId) {
  const finding = state.selectedEngagement?.findings.find(item => item.id === findingId);
  if (!finding) return;
  state.selectedFinding = finding;
  $("#finding-modal-title").textContent = "Bulguyu güncelleyin";
  const form = $("#finding-form");
  ["severity", "status", "affected_asset", "title", "owasp_category", "cwe_id", "cvss_vector", "remediation_owner", "due_date", "description", "impact", "evidence", "reproduction", "recommendation", "resolution_notes"].forEach(key => { form.elements[key].value = finding[key] || ""; });
  $("button[type=submit]", form).textContent = "Bulguyu güncelle";
  showModal("finding-modal");
}

async function refreshSelectedEngagement() {
  if (!state.selectedEngagement) return;
  state.selectedEngagement = await api(`/api/engagements/${encodeURIComponent(state.selectedEngagement.id)}`);
  renderWorkspace();
  await loadAll();
}

async function loadAudit() {
  try {
    const result = await api("/api/audit-log");
    $("#audit-list").innerHTML = result.events.length ? result.events.map(event => `<div class="audit-item"><time>${formatDate(event.occurred_at)}</time><div><b>${esc(actionLabel(event.action))}</b><small>${esc(event.entity_id)}${event.details?.url ? ` · ${esc(event.details.url)}` : ""}</small></div></div>`).join("") : `<div class="empty-state"><div class="empty-icon">↻</div><h3>Henüz işlem yok</h3></div>`;
  } catch (error) { toast(error.message, "error"); }
}

function openScan(target) {
  state.selectedTarget = target;
  $("#scan-target-label").textContent = `${target.hostname} için temel güvenlik kontrolü çalıştırılacak.`;
  showModal("scan-modal");
}

function openNmapScan(target) {
  state.selectedTarget = target;
  document.getElementById("nmap-target-name").textContent = target.hostname;

  const eligible = state.engagements.filter(e =>
    e.target_id === target.id &&
    e.status === 'active' &&
    e.authorization_ref?.trim() &&
    e.scope_notes?.trim()
  );

  const select = document.getElementById("nmap-engagement-select");
  select.replaceChildren();

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.disabled = true;
  placeholder.selected = true;
  placeholder.textContent = eligible.length === 0 ? "Uygun proje bulunamadı" : "Bir proje seçin";
  select.appendChild(placeholder);

  eligible.forEach(e => {
    const option = document.createElement("option");
    option.value = e.id;
    option.textContent = e.name || e.id;
    select.appendChild(option);
  });

  document.getElementById("nmap-result").textContent = "";
  document.getElementById("nmap-ports").value = "";
  document.getElementById("nmap-ports-error").textContent = "";
  document.getElementById("nmap-ports-error").classList.add("hidden");
  const nmapServiceVersionEl = document.getElementById("nmap-service-version");
  if (nmapServiceVersionEl) nmapServiceVersionEl.checked = false;
  document.getElementById("nmap-confirm-authorized").checked = false;
  nmapConfirmedScope = null;
  document.getElementById("nmap-start-button").disabled = true;

  showModal("nmap-modal");
}

async function openTrend(targetId) {
  showModal("report-drawer");
  $("#drawer-title").textContent = "Güvenlik trendi";
  $("#drawer-content").innerHTML = `<div class="scan-progress"><div class="spinner"></div><b>Trend hazırlanıyor</b></div>`;
  try {
    const trend = await api(`/api/targets/${encodeURIComponent(targetId)}/trend`);
    const points = trend.points || [];
    $("#drawer-title").textContent = `${trend.target.hostname} · Güvenlik trendi`;
    if (!points.length) {
      $("#drawer-content").innerHTML = `<div class="empty-state"><div class="empty-icon">↗</div><h3>Henüz trend yok</h3><p>İlk tarama tamamlandığında güvenlik puanı burada görünür.</p></div>`;
      return;
    }
    const latest = points[points.length - 1];
    const first = points[0];
    const totalDelta = Number(latest.score || 0) - Number(first.score || 0);
    $("#drawer-content").innerHTML = `<div class="trend-summary"><div><small>SON PUAN</small><strong>${latest.score}/100</strong></div><div><small>DÖNEM DEĞİŞİMİ</small><strong class="${totalDelta >= 0 ? "positive" : "negative"}">${totalDelta > 0 ? "+" : ""}${totalDelta}</strong></div><div><small>ÖLÇÜM</small><strong>${points.length}</strong></div></div>
      <div class="trend-chart" aria-label="Güvenlik puanı trendi">${points.map(point => `<article class="trend-column"><div class="trend-value">${point.score}</div><div class="trend-track"><i data-style="--height:${Math.max(4, Number(point.score || 0))}%"></i></div><small>${new Intl.DateTimeFormat("tr-TR", { day: "2-digit", month: "short" }).format(new Date(point.finished_at))}</small></article>`).join("")}</div>
      <div class="trend-history">${[...points].reverse().map(point => { const comparison = point.comparison || {}; return `<button data-action="report" data-id="${esc(point.scan_id)}"><span><b>${formatDate(point.finished_at)}</b><small>${point.finding_count} bulgu · ${esc(point.grade)}</small></span><strong>${point.score}/100</strong><span class="change-chips">${comparison.baseline ? `<i class="change-chip baseline">İlk</i>` : `<i class="change-chip new">+${comparison.new_count || 0}</i><i class="change-chip resolved">−${comparison.resolved_count || 0}</i>`}</span></button>${point.diff_links ? `<a class="mini-button trend-diff-link" href="${esc(point.diff_links.html)}" target="_blank" rel="noopener">Fark raporu</a>${point.diff_links.csv ? ` <a class="mini-button trend-diff-link trend-diff-csv-link" href="${esc(point.diff_links.csv)}" download>Fark CSV</a>` : ""}` : ""}`; }).join("")}</div>`;
  } catch (error) { $("#drawer-content").innerHTML = `<div class="empty-state"><h3>Trend açılamadı</h3><p>${esc(error.message)}</p></div>`; }
}

async function openReport(scanId) {
  showModal("report-drawer");
  $("#drawer-content").innerHTML = `<div class="scan-progress"><div class="spinner"></div><b>Rapor yükleniyor</b><p>Sonuçlar hazırlanıyor…</p></div>`;
  try {
    const scan = await api(`/api/scans/${encodeURIComponent(scanId)}`);
    renderReport(scan);
    if (["queued", "running"].includes(scan.status)) pollReport(scan.id);
  } catch (error) { $("#drawer-content").innerHTML = `<div class="empty-state"><h3>Rapor açılamadı</h3><p>${esc(error.message)}</p></div>`; }
}

function renderReport(scan) {
  $("#drawer-title").textContent = scan.target_hostname || "Tarama sonucu";
  if (["queued", "running"].includes(scan.status)) {
    $("#drawer-content").innerHTML = `<div class="scan-progress"><div class="spinner"></div><b>${esc(scan.status === "queued" ? "Tarama sırada" : "Güvenli kontroller çalışıyor")}</b><p>En fazla üç düşük etkili istek gönderiliyor. Bu pencere otomatik yenilenecek.</p></div>`;
    return;
  }
  if (scan.status === "failed") {
    $("#drawer-content").innerHTML = `<div class="empty-state"><div class="empty-icon">!</div><h3>Tarama tamamlanamadı</h3><p>${esc(scan.error || "Bağlantı hatası oluştu.")}</p></div>`;
    return;
  }
  const findings = scan.findings || [];
  const comparison = scan.comparison || {};
  const newIds = new Set((comparison.new_findings || []).map(finding => finding.id));
  const comparisonHtml = comparison.baseline
    ? `<div class="comparison-banner baseline"><b>İlk ölçüm</b><span>Sonraki taramalarda yeni, devam eden ve giderilen bulgular otomatik karşılaştırılacak.</span></div>`
    : `<div class="comparison-grid"><div><small>ÖNCEKİ PUAN</small><b>${comparison.previous_score ?? "—"}</b></div><div><small>PUAN DEĞİŞİMİ</small><b class="${Number(comparison.score_delta || 0) >= 0 ? "positive" : "negative"}">${Number(comparison.score_delta || 0) > 0 ? "+" : ""}${comparison.score_delta ?? "—"}</b></div><div><small>YENİ BULGU</small><b>${comparison.new_count || 0}</b></div><div><small>GİDERİLEN</small><b class="positive">${comparison.resolved_count || 0}</b></div><div><small>DEVAM EDEN</small><b>${comparison.persistent_count || 0}</b></div></div>`;
  const resolvedHtml = (comparison.resolved_findings || []).length ? `<section class="resolved-section"><p class="eyebrow">GİDERİLEN BULGULAR · ${comparison.resolved_findings.length}</p>${comparison.resolved_findings.map(finding => `<div><span>✓</span><b>${esc(finding.title)}</b><small>${esc(finding.reference || "")}</small></div>`).join("")}</section>` : "";
  $("#drawer-content").innerHTML = `
    <div class="report-summary"><div class="report-grade"><b>${scan.score}</b><small>/100 · ${esc(scan.grade)}</small></div><div class="report-meta"><b>${esc(scan.target_url)}</b><small>${formatDate(scan.finished_at)} · ${findings.length} bulgu · ${esc(scan.metadata?.response_ms || "—")} ms</small><small>Profil: ${esc(scan.scope?.profile || "safe-baseline-v2")}</small></div></div>
    ${comparisonHtml}
    <div class="report-actions"><a class="button secondary" href="/api/scans/${encodeURIComponent(scan.id)}/report.html" target="_blank" rel="noopener">Raporu aç</a><a class="button secondary" href="/api/scans/${encodeURIComponent(scan.id)}/report.html?download=1" download>HTML indir</a><a class="button secondary" href="/api/scans/${encodeURIComponent(scan.id)}/report.html?format=pdf" download>PDF indir</a><a class="button secondary" href="/api/scans/${encodeURIComponent(scan.id)}/report.json?download=1" download>JSON indir</a><a class="button secondary" href="/api/scans/${encodeURIComponent(scan.id)}/report.sarif?download=1" download>SARIF indir</a></div>
    <p class="eyebrow">BULGULAR · ${findings.length}</p>
    ${findings.length ? findings.map(finding => `<article class="finding-card ${esc(finding.severity)}"><div class="finding-card-head"><span class="severity-label">${esc(finding.severity.toUpperCase())}</span><h3>${esc(finding.title)}</h3>${!comparison.baseline ? `<span class="finding-change ${newIds.has(finding.id) ? "new" : "persistent"}">${newIds.has(finding.id) ? "Yeni" : "Devam ediyor"}</span>` : ""}</div><div class="risk-tags"><span>${esc(finding.owasp || "OWASP WSTG")}</span>${finding.cwe ? `<span>${esc(finding.cwe)}</span>` : ""}<span>Pasif · ${esc(finding.confidence || "yüksek")} güven</span></div><p>${esc(finding.description)}</p><div class="evidence">${esc(finding.evidence)}</div><p class="recommendation"><b>Öneri: </b>${esc(finding.recommendation)}</p></article>`).join("") : `<div class="empty-state"><div class="empty-icon">✓</div><h3>Bulgu tespit edilmedi</h3><p>Bu temel profilde risk işareti görülmedi.</p></div>`}
    ${resolvedHtml}`;
}

function pollReport(scanId) {
  clearTimeout(state.scanTimer);
  state.scanTimer = setTimeout(async () => {
    if ($("#report-drawer").classList.contains("hidden")) return;
    try {
      const scan = await api(`/api/scans/${encodeURIComponent(scanId)}`);
      renderReport(scan);
      if (["queued", "running"].includes(scan.status)) pollReport(scanId);
      else { await loadAll(); toast(scan.status === "completed" ? "Tarama tamamlandı." : "Tarama tamamlanamadı.", scan.status === "completed" ? "success" : "error"); }
    } catch (error) { toast(error.message, "error"); }
  }, 5000);
}

document.addEventListener("click", async event => {
  const nav = event.target.closest("[data-nav]");
  if (nav) { event.preventDefault(); navigate(nav.dataset.nav); return; }

  const close = event.target.closest("[data-close]");
  if (close) { showModal(close.dataset.close, false); clearTimeout(state.scanTimer); return; }

  if (event.target.classList.contains("modal-backdrop") || event.target.classList.contains("drawer-backdrop")) {
    showModal(event.target.id, false); clearTimeout(state.scanTimer); return;
  }

  const workspaceTab = event.target.closest("[data-workspace-tab]");
  if (workspaceTab) {
    state.workspaceTab = workspaceTab.dataset.workspaceTab;
    renderWorkspace();
    return;
  }

  const category = event.target.closest("[data-category]");
  if (category) {
    state.methodologyCategory = category.dataset.category;
    renderMethodology(state.selectedEngagement);
    return;
  }

  const findingFilter = event.target.closest("[data-finding-filter]");
  if (findingFilter) {
    state.findingFilter = findingFilter.dataset.findingFilter;
    renderManualFindings(state.selectedEngagement);
    return;
  }

  const action = event.target.closest("[data-action]");
  if (action) {
    if (action.dataset.action === "add-target") { $("#target-form").reset(); showModal("target-modal"); }
    if (action.dataset.action === "add-engagement") openEngagementCreator();
    if (action.dataset.action === "new-lab") openLabCreator(action.dataset.type);
    if (action.dataset.action === "open-lab") openLabDetail(action.dataset.id);
    if (action.dataset.action === "open-project-audit") openProjectAudit(action.dataset.id);
    if (action.dataset.action === "open-engagement") openEngagement(action.dataset.id);
    if (action.dataset.action === "scan") { const target = state.targets.find(item => item.id === action.dataset.id); if (target) openScan(target); }
    if (action.dataset.action === "nmap-scan") { const target = state.targets.find(item => item.id === action.dataset.id); if (target) openNmapScan(target); }
    if (action.dataset.action === "trend") openTrend(action.dataset.id);
    if (action.dataset.action === "scan-from-engagement") { const target = state.targets.find(item => item.id === state.selectedEngagement?.target_id); if (target) openScan(target); }
    if (action.dataset.action === "report") openReport(action.dataset.id);
    if (action.dataset.action === "scan-page-next") await loadScanHistoryPage("next");
    if (action.dataset.action === "scan-page-prev") await loadScanHistoryPage("prev");
    if (action.dataset.action === "edit-test") openTestEditor(action.dataset.control);
    if (action.dataset.action === "add-finding") { state.selectedFinding = null; $("#finding-form").reset(); $("#finding-modal-title").textContent = "Yeni bulgu kaydedin"; $("button[type=submit]", $("#finding-form")).textContent = "Bulguyu kaydet"; showModal("finding-modal"); }
    if (action.dataset.action === "edit-finding") openFindingEditor(action.dataset.id);    if (action.dataset.action === "open-sarif-preview") { showModal("sarif-preview-modal", true); }
    if (action.dataset.action === "open-k6-summary-preview") showModal("k6-summary-preview-modal", true);
    if (action.dataset.action === "open-k6-machine-summary-preview") showModal("k6-machine-summary-preview-modal", true);
    if (action.dataset.action === "sync-auto-evidence" && state.selectedEngagement) {
      action.disabled = true;
      try {
        const res = await api(`/api/engagements/${encodeURIComponent(state.selectedEngagement.id)}/auto-evidence-sync`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ project_audit_id: "latest" }),
        });
        await refreshSelectedEngagement();
        toast(`${res.updated_control_count} WSTG kontrol adımı otomatik kanıtlarla eşitlendi.`);
      } catch (error) {
        toast(error.message, "error");
      } finally {
        action.disabled = false;
      }
    }
    if (action.dataset.action === "verify-retests" && state.selectedEngagement) {
      action.disabled = true;
      try {
        const res = await api(`/api/engagements/${encodeURIComponent(state.selectedEngagement.id)}/verify-retests`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ project_audit_id: "latest" }),
        });
        await refreshSelectedEngagement();
        toast(`Yeniden test doğrulandı: ${res.resolved_count || 0} çözüldü, ${res.reopened_count || 0} yeniden açıldı, ${res.overdue_count || 0} SLA gecikmeli.`);
      } catch (error) {
        toast(error.message, "error");
      } finally {
        action.disabled = false;
      }
    }
    return;
  }
});

document.addEventListener("input", event => {
  if (event.target.id === "methodology-search") {
    state.methodologyQuery = event.target.value;
    renderMethodology(state.selectedEngagement);
    const input = $("#methodology-search");
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  }
});

document.addEventListener("change", async event => {
  if (event.target.id === "lab-engagement" && $("#lab-scenario-type").value === "external_result") {
    renderLabControlOptions(event.target.value);
  }
  if (event.target.matches("[data-dependency-status]")) {
    event.target.disabled = true;
    try {
      const updated = await api(`/api/dependency-findings/${encodeURIComponent(event.target.dataset.id)}/update`, {
        method: "POST", body: JSON.stringify({ status: event.target.value }),
      });
      if (state.dependencySecurity) {
        state.dependencySecurity.findings = (state.dependencySecurity.findings || []).map(item => item.id === updated.id ? updated : item);
        renderDependencySecurity();
      }
      if (state.selectedDependencyFindingId === updated.id) renderDependencyFindingDetail(updated);
      try {
        await refreshDependencyFindings();
        toast("Bağımlılık bulgusu durumu güncellendi.");
      } catch (refreshError) {
        toast("Durum kaydedildi; liste yenilenemedi.", "error");
      }
    } catch (error) { toast(error.message, "error"); }
    finally { event.target.disabled = false; }
  }
});

document.addEventListener("submit", async event => {
  if (event.target.id !== "scope-form") return;
  event.preventDefault();
  const button = $("button[type=submit]", event.target);
  button.disabled = true;
  try {
    const form = new FormData(event.target);
    await api(`/api/engagements/${state.selectedEngagement.id}/update`, { method: "POST", body: JSON.stringify(Object.fromEntries(form.entries())) });
    await refreshSelectedEngagement();
    toast("Kapsam ve yönetici özeti güncellendi.");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; }
});

$("#target-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true; button.textContent = "Hedef kontrol ediliyor…";
  try {
    const form = new FormData(event.currentTarget);
    const target = await api("/api/targets", { method: "POST", body: JSON.stringify({ url: form.get("url") }) });
    showModal("target-modal", false); await loadAll(); navigate("targets"); toast(`${target.hostname} doğrudan eklendi.`);
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.innerHTML = `Hedefi ekle <span>→</span>`; }
});

$("#project-audit-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true;
  button.textContent = "Kaynaklar inceleniyor…";
  try {
    const form = new FormData(event.currentTarget);
    const body = { project_path: form.get("project_path") };
    const mode = form.get("scan_mode") || "saved";
    if (mode === "changed") body.scope = { changed_only: true, base_ref: String(form.get("base_ref") || "HEAD").trim() || "HEAD" };
    else if (mode !== "saved") body.scope = { preset: mode };
    const baseId = event.currentTarget.dataset.baseAuditId;
    if (mode === "skipped" && baseId) body.base_audit_id = baseId;
    delete event.currentTarget.dataset.baseAuditId;
    // Arka plan iş kuyruğu (ilerleme, iptal, sayfa kapansa da sürer; static/project_jobs.js); yoksa eşzamanlı API.
    const audit = globalThis.SniperProjectJobs
      ? await globalThis.SniperProjectJobs.start(body, event.currentTarget)
      : await api("/api/project-audits", { method: "POST", body: JSON.stringify(body) });
    await loadAll();
    navigate("projects");
    await openProjectAudit(audit.id);
    toast(`${audit.project_name} analizi gerçek dosyalardan tamamlandı.`);
  } catch (error) {
    toast(error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = "Analizi başlat";
  }
});

$("#dependency-sbom-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true; button.textContent = "SBOM üretiliyor…";
  try {
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    const sbom = await api("/api/dependency-security/sbom", { method: "POST", body: JSON.stringify(payload) });
    await loadAll();
    toast(`${sbom.component_count} bileşenli CycloneDX SBOM kaydedildi.`);
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.textContent = "CycloneDX SBOM üret"; }
});

$("#sbom-delta-form").addEventListener("submit", async event => {
  event.preventDefault();
  const error = $("#sbom-delta-error");
  const result = $("#sbom-delta-result");
  error.classList.add("hidden");
  result.classList.add("hidden");
  const snapshots = state.dependencySecurity?.sboms || [];
  const beforeId = $("#sbom-delta-before").value;
  const afterId = $("#sbom-delta-after").value;
  const before = snapshots.find(item => item.id === beforeId);
  const after = snapshots.find(item => item.id === afterId);
  if (!before || !after || beforeId === afterId || before.project_path !== after.project_path) {
    error.textContent = "İki farklı ve aynı projeye ait kayıtlı SBOM seçin.";
    error.classList.remove("hidden");
    return;
  }
  const button = $("#sbom-delta-submit");
  button.disabled = true;
  try {
    const delta = await api(`/api/dependency-sboms/${encodeURIComponent(beforeId)}/delta/${encodeURIComponent(afterId)}`);
    const summary = delta.summary || {};
    if (delta.before_id !== beforeId || delta.after_id !== afterId || delta.project_path !== before.project_path ||
        ![summary.added, summary.removed, summary.changed].every(value => Number.isSafeInteger(value) && value >= 0)) {
      throw new Error("invalid_delta_response");
    }
    $("#sbom-delta-added").textContent = String(summary.added);
    $("#sbom-delta-removed").textContent = String(summary.removed);
    $("#sbom-delta-changed").textContent = String(summary.changed);
    result.classList.remove("hidden");
  } catch (_error) {
    error.textContent = "Kayıtlı SBOM farkı gösterilemedi.";
    error.classList.remove("hidden");
  } finally {
    button.disabled = false;
  }
});

$("#dependency-import-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true; button.textContent = "Rapor doğrulanıyor…";
  try {
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    const result = await api("/api/dependency-security/import", { method: "POST", body: JSON.stringify(payload) });
    await loadAll();
    toast(result.deduplicated ? "Bu rapor daha önce içe aktarılmış." : `${result.finding_count} bağımlılık bulgusu kaydedildi.`);
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.textContent = "Yerel raporu içe aktar"; }
});

$("#engagement-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true; button.textContent = "Denetim dosyası hazırlanıyor…";
  try {
    const form = new FormData(event.currentTarget);
    const payload = {
      target_id: form.get("target_id"), name: form.get("name"), authorization_ref: form.get("authorization_ref"),
      scope_notes: form.get("scope_notes"), out_of_scope: form.get("out_of_scope"), test_window: form.get("test_window"),
      special_approvals: {
        controlled_lockout: form.get("controlled_lockout") === "on",
        staging_capacity: form.get("staging_capacity") === "on",
        redacted_data_proof: form.get("redacted_data_proof") === "on",
      },
    };
    const engagement = await api("/api/engagements", { method: "POST", body: JSON.stringify(payload) });
    showModal("engagement-modal", false); await loadAll(); navigate("pentest"); await openEngagement(engagement.id);
    toast("Kapsamlı manuel denetim oluşturuldu.");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.innerHTML = `Manuel denetimi oluştur <span>→</span>`; }
});

$("#lab-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true; button.textContent = "Güvenli kayıt hazırlanıyor…";
  try {
    const form = new FormData(event.currentTarget);
    const payload = Object.fromEntries(form.entries());
    delete payload.plan_ack;
    await api("/api/lab-runs", { method: "POST", body: JSON.stringify(payload) });
    showModal("lab-modal", false); await loadAll(); navigate("lab"); toast("Laboratuvar kaydı oluşturuldu; Sniper ağ isteği üretmedi.");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.innerHTML = `Kaydı oluştur <span>→</span>`; }
});

$("#lab-update-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!state.selectedLabRun) return;
  const button = $("button[type=submit]", event.currentTarget); button.disabled = true;
  try {
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    await api(`/api/lab-runs/${encodeURIComponent(state.selectedLabRun.id)}/update`, { method: "POST", body: JSON.stringify(payload) });
    showModal("lab-detail-modal", false); await loadAll(); toast("Maskeli laboratuvar kaydı güncellendi.");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; }
});

$("#test-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!state.selectedEngagement || !state.selectedTest) return;
  const button = $("button[type=submit]", event.currentTarget); button.disabled = true;
  try {
    const form = new FormData(event.currentTarget);
    await api(`/api/engagements/${state.selectedEngagement.id}/tests/${encodeURIComponent(state.selectedTest.control_id)}`, {
      method: "POST", body: JSON.stringify(Object.fromEntries(form.entries())),
    });
    showModal("test-modal", false); await refreshSelectedEngagement(); toast("Test adımı güncellendi.");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; }
});

$("#finding-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!state.selectedEngagement) return;
  const button = $("button[type=submit]", event.currentTarget); button.disabled = true; button.textContent = "Bulgu kaydediliyor…";
  try {
    const form = new FormData(event.currentTarget);
    const payload = JSON.stringify(Object.fromEntries(form.entries()));
    const endpoint = state.selectedFinding ? `/api/findings/${state.selectedFinding.id}/update` : `/api/engagements/${state.selectedEngagement.id}/findings`;
    await api(endpoint, { method: "POST", body: payload });
    showModal("finding-modal", false); state.workspaceTab = "findings"; await refreshSelectedEngagement(); toast(state.selectedFinding ? "Manuel bulgu güncellendi." : "Manuel bulgu kaydedildi.");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.textContent = "Bulguyu kaydet"; }
});

$("#start-scan-button").addEventListener("click", async event => {
  if (!state.selectedTarget) return;
  const button = event.currentTarget; button.disabled = true; button.textContent = "Tarama başlatılıyor…";
  try {
    const scan = await api("/api/scans", { method: "POST", body: JSON.stringify({ target_id: state.selectedTarget.id }) });
    showModal("scan-modal", false); await loadAll(); navigate("reports"); openReport(scan.id); toast("Tarama güvenli profille başlatıldı.");
  } catch (error) { toast(error.message, "error"); button.disabled = false; }
  finally { button.innerHTML = `Taramayı başlat <span>→</span>`; }
});

let nmapScanBusy = false;
let nmapConfirmedScope = null;
const nmapDefaultPorts = Object.freeze([21,22,25,53,80,110,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,6379,8080,8443,9200,27017]);
function parseNmapPortSelection(raw) {
  if (!raw.trim()) return { ports: null, error: "" };
  const values = raw.split(",").map(value => value.trim());
  if (values.length > 64 || values.some(value => !/^\d{1,5}$/.test(value))) {
    return { ports: null, error: "1–64 farklı TCP portunu virgülle ayırarak girin." };
  }
  const ports = values.map(Number);
  if (ports.some(port => port < 1 || port > 65535) || new Set(ports).size !== ports.length) {
    return { ports: null, error: "Portlar 1–65535 arasında ve birbirinden farklı olmalı." };
  }
  return { ports: ports.sort((a, b) => a - b), error: "" };
}
const nmapScopeFingerprint = () => {
  const target = state.selectedTarget;
  const engagement = state.engagements.find(item => item.id === $("#nmap-engagement-select").value);
  const selection = parseNmapPortSelection($("#nmap-ports").value);
  if (selection.error || !target || !engagement
    || engagement.target_id !== target.id
    || engagement.status !== 'active'
    || !engagement.authorization_ref?.trim()
    || !engagement.scope_notes?.trim()) return null;
  const currentTarget = Array.isArray(state.targets)
    ? state.targets.find(item => item.id === target.id)
    : target;
  if (!currentTarget) return null;
  const address = item => [item.url, item.scheme, item.hostname, item.port, item.path];
  return JSON.stringify([
    target.id, address(target), address(currentTarget),
    engagement.id, engagement.authorization_ref, engagement.scope_notes,
    selection.ports ?? nmapDefaultPorts,
  ]);
};
const nmapRevokeChangedScope = () => {
  const checkbox = $("#nmap-confirm-authorized");
  const fingerprint = nmapScopeFingerprint();
  if (!checkbox.checked || fingerprint === null || nmapConfirmedScope !== fingerprint) {
    checkbox.checked = false;
    nmapConfirmedScope = null;
  }
  return fingerprint;
};
const nmapReady = () => {
  const btn = $("#nmap-start-button");
  const checkbox = $("#nmap-confirm-authorized");
  const engagementSelect = $("#nmap-engagement-select");
  const { selectedTarget, engagements } = state;
  const engagementId = engagementSelect ? engagementSelect.value : null;
  const engagement = engagements.find(e => e.id === engagementId);
  const selection = parseNmapPortSelection($("#nmap-ports").value);
  const portError = $("#nmap-ports-error");
  portError.textContent = selection.error;
  portError.classList.toggle("hidden", !selection.error);
  const fingerprint = nmapRevokeChangedScope();
  const ready = !nmapScanBusy
    && !selection.error
    && checkbox?.checked
    && fingerprint !== null
    && nmapConfirmedScope === fingerprint
    && selectedTarget
    && engagement
    && engagement.target_id === selectedTarget.id
    && engagement.status === 'active'
    && engagement.authorization_ref?.trim()
    && engagement.scope_notes?.trim();
  btn.disabled = !ready;
};
$("#nmap-engagement-select").addEventListener("change", nmapReady);
$("#nmap-confirm-authorized").addEventListener("change", () => {
  const checkbox = $("#nmap-confirm-authorized");
  nmapConfirmedScope = checkbox.checked ? nmapScopeFingerprint() : null;
  if (nmapConfirmedScope === null) checkbox.checked = false;
  nmapReady();
});
$("#nmap-ports").addEventListener("input", nmapReady);
$("#nmap-start-button").addEventListener("click", async () => {
  const btn = $("#nmap-start-button");
  const checkbox = $("#nmap-confirm-authorized");
  const engagementSelect = $("#nmap-engagement-select");
  const { selectedTarget, engagements } = state;
  const engagementId = engagementSelect ? engagementSelect.value : null;
  const engagement = engagements.find(e => e.id === engagementId);
  const selection = parseNmapPortSelection($("#nmap-ports").value);
  const fingerprint = nmapRevokeChangedScope();
  if (nmapScanBusy
    || selection.error
    || !checkbox?.checked
    || fingerprint === null
    || nmapConfirmedScope !== fingerprint
    || !selectedTarget
    || !engagement
    || engagement.target_id !== selectedTarget.id
    || engagement.status !== 'active'
    || !engagement.authorization_ref?.trim()
    || !engagement.scope_notes?.trim()) {
    btn.disabled = true;
    toast("Lütfen tüm gerekli alanları doldurun ve onay kutusunu işaretleyin.", "error");
    return;
  }
  nmapScanBusy = true;
  btn.disabled = true;
  try {
    const request = { target_id: selectedTarget.id, engagement_id: engagement.id, confirm_authorized: true };
    if (selection.ports !== null) request.ports = selection.ports;
    if ($("#nmap-service-version")?.checked === true) request.service_version = true;
    const res = await api("/api/nmap/tcp-scan", { method: "POST", body: JSON.stringify(request) });
    const { open_port_count, open_ports } = res;
    if (!Number.isSafeInteger(open_port_count) || open_port_count < 0 || !Array.isArray(open_ports) ||
        open_ports.length !== open_port_count ||
        !open_ports.every(port => Number.isSafeInteger(port) && port >= 1 && port <= 65535) ||
        (selection.ports !== null && !open_ports.every(port => selection.ports.includes(port)))) {
      throw new Error("Invalid response");
    }
    const servicesSuffix = res.service_version === true && Array.isArray(res.open_services) && res.open_services.length > 0
      ? ` — Servisler: ${res.open_services.map(item => {
          const svc = item?.service || "unknown";
          const ver = [item?.product, item?.version].filter(Boolean).join(" ");
          return ver ? `${item?.port}/${svc} (${ver})` : `${item?.port}/${svc}`;
        }).join(", ")}`
      : "";
    $("#nmap-result").textContent = `Açık port sayısı: ${open_port_count} — Portlar: [${open_ports.join(", ")}]${servicesSuffix}`;
  } catch (e) {
    $("#nmap-result").textContent = "Tarama başarısız oldu. Lütfen tekrar deneyin.";
    toast("Tarama başlatılamadı. Lütfen sistem yöneticisine başvurun.", "error");
  } finally {
    nmapScanBusy = false;
    nmapReady();
  }
});
$("#target-search").addEventListener("input", event => renderTargets(event.target.value));
$("#mobile-menu").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
window.addEventListener("hashchange", () => navigate(location.hash.slice(1)));
document.addEventListener("click", event => {
  const top = activeModal();
  if (top && !modalContains(top, event.target)) {
    event.preventDefault();
    event.stopImmediatePropagation();
    lastModalTrigger = null;
    focusModalBoundary(top);
    return;
  }
  lastModalTrigger = event.target.closest("button,a,[data-action]");
}, true);

document.addEventListener("focusin", event => {
  const top = activeModal();
  if (top && !modalContains(top, event.target)) focusModalBoundary(top);
}, true);

document.addEventListener("keydown", event => {
  if (event.key === "Escape") {
    if (event.defaultPrevented) return;
    const trufflehogDialog = document.getElementById("trufflehog-filesystem-modal");
    if (trufflehogDialog?.classList?.contains?.("hidden") === false && !activeModal()) return;
  }
  const top = activeModal() || (
    event.key === "Escape"
      ? (typeof nucleiJsonlModalOpen !== "undefined" &&
         nucleiJsonlModalOpen &&
         isModalOpen(document.getElementById("nuclei-jsonl-preview-modal"))
          ? document.getElementById("nuclei-jsonl-preview-modal")
          : typeof trufflehogPreviewModalOpen !== "undefined" &&
            trufflehogPreviewModalOpen &&
            isModalOpen(document.getElementById("trufflehog-preview-modal"))
            ? document.getElementById("trufflehog-preview-modal")
            : typeof k6SummaryModalOpen !== "undefined" &&
            k6SummaryModalOpen &&
            isModalOpen(document.getElementById("k6-summary-preview-modal"))
            ? document.getElementById("k6-summary-preview-modal")
            : typeof k6MachineSummaryModalOpen !== "undefined" &&
              k6MachineSummaryModalOpen &&
              isModalOpen(document.getElementById("k6-machine-summary-preview-modal"))
              ? document.getElementById("k6-machine-summary-preview-modal")
              : typeof schemathesisJunitModalOpen !== "undefined" &&
                schemathesisJunitModalOpen &&
                isModalOpen(document.getElementById("schemathesis-junit-preview-modal"))
                ? document.getElementById("schemathesis-junit-preview-modal")
                : typeof siemEcsModalOpen !== "undefined" &&
                  siemEcsModalOpen &&
                  isModalOpen(document.getElementById("siem-ecs-preview-modal"))
                  ? document.getElementById("siem-ecs-preview-modal")
                  : null)
      : null
  );
  if (!top) return;
  if (event.key === "Escape") {
    event.preventDefault();
    // Direct dialogs also listen on document: one Escape closes one visible layer.
    if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
    else event.stopPropagation();
    if (top.id === "dependabot-preview-modal") clearDependabotPreview();
    showModal(top.id, false);
    return;
  }
  if (!modalContains(top, document.activeElement)) {
    if (event.key === "Tab" || event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      event.stopPropagation();
      if (event.key === "Tab") focusModal(top, event.shiftKey);
      else focusModalBoundary(top);
    }
    return;
  }
  if (event.key !== "Tab") return;
  const controls = modalControls(top);
  if (!controls.length) {
    event.preventDefault();
    focusModalBoundary(top);
  } else if (!controls.includes(document.activeElement)) {
    event.preventDefault();
    focusModal(top, event.shiftKey);
  } else if (event.shiftKey && document.activeElement === controls[0]) {
    event.preventDefault();
    controls[controls.length - 1].focus();
  } else if (!event.shiftKey && document.activeElement === controls[controls.length - 1]) {
    event.preventDefault();
    controls[0].focus();
  }
}, true);

navigate(location.hash.slice(1) || "dashboard");
loadAll();
let activeScanPollIsRefreshing = false;

async function refreshActiveScans() {
  if (activeScanPollIsRefreshing) {
    return;
  }
  activeScanPollIsRefreshing = true;

  var hasActive = state.scans.some(function(scan) { return scan.status === "queued" || scan.status === "running"; });

  if (!hasActive) {
    activeScanPollIsRefreshing = false;
    return;
  }

  try {
    const response = await api("/api/scans?limit=200");
    syncFirstScanHistoryPage(response);
    renderScans();

    if (!state.scans.some(function(scan) { return scan.status === "queued" || scan.status === "running"; })) {
      await loadAll();
    }
  } catch (err) {
    toast(err.message, "error");
  } finally {
    activeScanPollIsRefreshing = false;
  }
}

setInterval(() => {
  if (state.scans.some(scan => ["queued", "running"].includes(scan.status))) {
    refreshActiveScans();
  }
}, 15000);



// Scan Diff - Tarama Karşılaştırma Fonksiyonları
async function openScanDiffModal(scanId) {
  const modal = $("#scan-diff-modal");
  const select1 = $("#scan-diff-scan-1");
  const select2 = $("#scan-diff-scan-2");

  // Tıklanan taramayı bul
  const selectedScan = state.scans.find(s => s.id === scanId);
  if (!selectedScan) {
    toast("Tarama bulunamadı.", "error");
    return;
  }

  // state'e kaydet
  state.selectedScan = selectedScan;

  // Aynı hedefin daha eski taramalarını filtrele (deterministik)
  const earlierScans = state.scans
    .filter(s => s.status === 'completed' && s.target_id === selectedScan.target_id && s.id !== selectedScan.id)
    .filter(s => s.created_at < selectedScan.created_at)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));

  // Select1: daha eski taramalar
  select1.innerHTML = '<option value="">Önceki tarama seçin…</option>' +
    earlierScans.map(s =>
      `<option value="${s.id}">${esc(s.target_hostname)} · ${formatDate(s.created_at)} · ${s.score}/100</option>`
    ).join('');

  // Select2: tıklanan tarama (daha yeni)
  select2.innerHTML = '<option value="' + selectedScan.id + '" selected>' +
    esc(selectedScan.target_hostname) + ' · ' + formatDate(selectedScan.created_at) + ' · ' + selectedScan.score + '/100 (Seçili)</option>';

  // Select1 değişince, seçilen eski taramadan sonraki tüm uygun taramaları
  // göster. `onchange` ataması aynı modalı tekrar açarken dinleyici
  // birikmesini engeller ve tıklanan sonraki taramayı seçeneklerde tutar.
  select1.onchange = () => {
    const previousScan = state.scans.find(s => s.id === select1.value);
    const laterScans = state.scans
      .filter(s => s.status === 'completed' && s.target_id === selectedScan.target_id)
      .filter(s => previousScan && s.created_at > previousScan.created_at)
      .sort((a, b) => a.created_at.localeCompare(b.created_at));
    select2.innerHTML = '<option value="">Sonraki tarama seçin…</option>' +
      laterScans.map(s =>
        `<option value="${s.id}">${esc(s.target_hostname)} · ${formatDate(s.created_at)} · ${s.score}/100</option>`
      ).join('');
    if (laterScans.some(s => s.id === selectedScan.id)) select2.value = selectedScan.id;
  };

  // Modal'ı aç, önceki state'i temizle. `$` yerel bir DOM elemanı döndürür;
  // jQuery tarzı addClass burada TypeError üretip modalın açılmasını engelliyordu.
  state.scanDiffResult = null;
  $("#scan-diff-result").classList.add("hidden");
  $("#diff-findings-container").innerHTML = "";
  const button = $("#scan-diff-button");
  button.textContent = "Karşılaştırmayı Yükle";
  button.disabled = earlierScans.length === 0;
  const notice = $("#scan-diff-notice");
  notice.textContent = earlierScans.length === 0
    ? "Bu hedef için karşılaştırılabilecek daha eski tamamlanmış tarama yok."
    : "";
  notice.classList.toggle("hidden", earlierScans.length > 0);

  showModal('scan-diff-modal');
}

async function loadScanDiff() {
  const select1 = $("#scan-diff-scan-1");
  const select2 = $("#scan-diff-scan-2");
  const scan1 = select1.value;
  const scan2 = select2.value;

  if (!scan1 || !scan2) {
    toast("Her iki taramayı da seçin.", "error");
    return;
  }

  // Modal kapanmasın, temizleme yapılmadan önce state'i sıfırla
  state.scanDiffResult = null;

  const button = $("#scan-diff-button");
  button.disabled = true;
  button.textContent = "Yükleniyor…";

  try {
    const result = await api(`/api/scans/diff/${encodeURIComponent(scan1)}/${encodeURIComponent(scan2)}`);
    renderScanDiffResult(result);
    button.disabled = false;
    button.textContent = "Yeniden Karşılaştır";
  } catch (error) {
    toast(error.message || "Karşılaştırma yüklenemedi.", "error");
    button.disabled = false;
    button.textContent = "Karşılaştırmayı Yükle";
    state.scanDiffResult = null;
  }
}

function renderScanDiffResult(result) {
  const summary = result.summary;
  const container = $("#scan-diff-result");
  const findingsContainer = $("#diff-findings-container");

  // State'i güncelle
  state.scanDiffResult = result;

  // Özet bilgilerini güncelle
  $("#diff-score-delta").textContent = summary.score_delta !== null
    ? (summary.score_delta > 0 ? `+${summary.score_delta}` : summary.score_delta) + " puan"
    : "—";
  $("#diff-new-count").textContent = summary.new_count;
  $("#diff-resolved-count").textContent = summary.resolved_count;
  $("#diff-persistent-count").textContent = summary.persistent_count;

  findingsContainer.innerHTML = "";
  container.classList.remove("hidden");
  const download = $("#scan-diff-download");
  download.href = `/api/scans/diff/${encodeURIComponent(summary.scan_1_id)}/${encodeURIComponent(summary.scan_2_id)}/report.json?download=1`;
  download.setAttribute("download", `sniper-diff-${summary.scan_1_id}-${summary.scan_2_id}.json`);
  const downloadHtml = $("#scan-diff-download-html");
  downloadHtml.href = `/api/scans/diff/${encodeURIComponent(summary.scan_1_id)}/${encodeURIComponent(summary.scan_2_id)}/report.html?download=1`;
  downloadHtml.setAttribute("download", `sniper-diff-${summary.scan_1_id}-${summary.scan_2_id}.html`);
  const downloadCsv = $("#scan-diff-download-csv");
  if (downloadCsv) {
    downloadCsv.href = `/api/scans/diff/${encodeURIComponent(summary.scan_1_id)}/${encodeURIComponent(summary.scan_2_id)}/report.csv?download=1`;
    downloadCsv.setAttribute("download", `sniper-diff-${summary.scan_1_id}-${summary.scan_2_id}.csv`);
  }

  // İlk tab: NEW. Sekmeleri sırayla çizmek son sekmenin (devam eden) görünmesine
  // neden oluyordu; yalnızca seçili sekmenin içeriğini çiz.
  const severitySelect = $("#scan-diff-severity");
  if (severitySelect) severitySelect.value = "all";
  updateDiffTabState("new");
  renderFindingsTab("new", diffFindingsFor("new"));
}

function activeDiffTab() {
  const active = document.querySelector("#scan-diff-modal .diff-tab.active");
  return active ? active.dataset.tab : "new";
}

function diffFindingsFor(tabName) {
  const result = state.scanDiffResult;
  if (!result) return [];
  const findingsMap = {
    new: result.new_findings || [],
    resolved: result.resolved_findings || [],
    persistent: result.persistent_findings || []
  };
  const wanted = String($("#scan-diff-severity")?.value || "all").toLowerCase();
  const findings = findingsMap[tabName] || [];
  if (wanted === "all") return findings;
  return findings.filter(f => String(f.severity ?? "info").trim().toLowerCase() === wanted);
}

function updateDiffTabState(tabName) {
  document.querySelectorAll("#scan-diff-modal .diff-tab").forEach(btn => {
    const active = btn.dataset.tab === tabName;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
}

function renderFindingsTab(tabName, findings) {
  const container = $("#diff-findings-container");

  if (findings.length === 0) {
    const wanted = String($("#scan-diff-severity")?.value || "all");
    container.innerHTML = `<div class="empty-state"><p>${esc(wanted === "all" ? "Bu kategoride bulgu yok." : "Seçili önem derecesinde bulgu yok.")}</p></div>`;
    return;
  }

  const severityColors = {
    critical: "bg-red",
    high: "bg-orange",
    medium: "bg-yellow",
    low: "bg-blue",
    info: "bg-gray"
  };

  const ALLOWLISTED_SEVERITIES = new Set(Object.keys(severityColors));

  function getSeverityClass(severity) {
    const normalized = (severity || "info").toLowerCase();
    return ALLOWLISTED_SEVERITIES.has(normalized) ? severityColors[normalized] : "bg-gray";
  }

  container.innerHTML = findings.map(f => {
    const severity = (f.severity || "info").toLowerCase();
    const safeSeverity = ALLOWLISTED_SEVERITIES.has(severity) ? severity : "info";
    const colorClass = severityColors[safeSeverity];

    return `<article class="finding-card ${colorClass}" aria-live="polite">
      <div class="finding-header">
        <span class="severity-badge ${safeSeverity}" role="status">${esc(f.severity || "info").toUpperCase()}</span>
        <b class="finding-title" title="${esc(f.title || "Bulgu başlığı yok")}">${esc(f.title || "Bulgu başlığı yok")}</b>
      </div>
      ${f.description ? `<p class="finding-desc" title="${esc(f.description)}">${esc(f.description)}</p>` : ""}
      ${f.recommendation ? `<p class="finding-rec"><small>Öneri:</small> ${esc(f.recommendation)}</p>` : ""}
      ${f.affected_asset ? `<p class="finding-asset"><small>Varlık:</small> ${esc(f.affected_asset)}</p>` : ""}
    </article>`;
  }).join("");
}

// Tab değişimi - aria-selected ve state control
document.addEventListener("click", (e) => {
  const tab = e.target.closest?.("#scan-diff-modal .diff-tab");
  if (tab) {
    const tabName = tab.dataset.tab;
    const container = $("#diff-findings-container");
    updateDiffTabState(tabName);

    if (!state.scanDiffResult) {
      container.innerHTML = '<div class="empty-state"><p>Karşılaştırma verisi yok.</p></div>';
      return;
    }
    renderFindingsTab(tabName, diffFindingsFor(tabName));
  }
});

// Event listener ekle
document.addEventListener("change", (e) => {
  if (e.target && e.target.id === "scan-diff-severity") {
    if (!state.scanDiffResult) return;
    const tab = activeDiffTab();
    renderFindingsTab(tab, diffFindingsFor(tab));
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const compareButton = $("#scan-diff-button");
  if (compareButton) {
    compareButton.addEventListener("click", loadScanDiff);
  }
});

// compare-scan butonları için event delegation - tek listener
function handleCompareScanClick(e) {
  const button = e.target.closest('[data-action="compare-scan"]');
  if (button && button.tagName === "BUTTON") {
    e.preventDefault();
    const scanId = button.dataset.id;
    if (scanId) {
      openScanDiffModal(scanId);
    } else {
      toast("Tarama ID bulunamadı.", "error");
    }
  }
}

document.addEventListener("click", handleCompareScanClick);

function clearZapSelfPassive() {
  const confirm = document.getElementById("zap-self-confirm");
  const error = document.getElementById("zap-self-error");
  const result = document.getElementById("zap-self-result");
  if (confirm) confirm.checked = false;
  if (error) { error.textContent = ""; error.classList.add("hidden"); }
  if (result) result.classList.add("hidden");
  for (const id of ["zap-self-alert-types", "zap-self-instances", "zap-self-risks", "zap-self-sha256"]) {
    const field = document.getElementById(id);
    if (field) field.textContent = "";
  }
}

document.addEventListener("click", e => {
  const close = e.target.closest?.("[data-close]");
  if (close?.dataset.close === "zap-preview-modal") clearZapSelfPassive();
});

document.addEventListener("submit", async e => {
  if (e.target.id !== "zap-self-passive-form") return;
  e.preventDefault();
  const confirm = document.getElementById("zap-self-confirm");
  const button = document.getElementById("zap-self-run-button");
  const error = document.getElementById("zap-self-error");
  const result = document.getElementById("zap-self-result");
  error.textContent = "";
  error.classList.add("hidden");
  result.classList.add("hidden");
  if (confirm.checked !== true) {
    error.textContent = "Yerel kontrolü açıkça onaylayın.";
    error.classList.remove("hidden");
    return;
  }
  button.disabled = true;
  try {
    const data = await api("/api/tool-runs/zap-self-passive", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm_local: true }),
    });
    const keys = ["informational", "low", "medium", "high"];
    const counts = data?.risk_counts;
    if (data?.format !== "zap-self-passive-v1" ||
        !Number.isSafeInteger(data.alert_type_count) || data.alert_type_count < 0 || data.alert_type_count > 500 ||
        !Number.isSafeInteger(data.instance_count) || data.instance_count < 0 || data.instance_count > 5000 ||
        !counts || typeof counts !== "object" || Array.isArray(counts) ||
        Object.keys(counts).length !== keys.length ||
        !keys.every(key => Number.isSafeInteger(counts[key]) && counts[key] >= 0) ||
        keys.reduce((sum, key) => sum + counts[key], 0) !== data.alert_type_count ||
        typeof data.report_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(data.report_sha256)) {
      throw new Error("invalid ZAP summary");
    }
    document.getElementById("zap-self-alert-types").textContent = String(data.alert_type_count);
    document.getElementById("zap-self-instances").textContent = String(data.instance_count);
    document.getElementById("zap-self-risks").textContent = keys.map(key => `${key}:${counts[key]}`).join(" ");
    document.getElementById("zap-self-sha256").textContent = data.report_sha256;
    result.classList.remove("hidden");
    confirm.checked = false;
  } catch {
    error.textContent = "ZAP pasif kontrolü çalıştırılamadı.";
    error.classList.remove("hidden");
  } finally {
    button.disabled = false;
  }
});

(() => {
  const form = document.getElementById("trivy-vuln-local-form");
  if (!form) return;
  const path = document.getElementById("trivy-vuln-local-path");
  const consent = document.getElementById("trivy-vuln-local-consent");
  const submit = document.getElementById("trivy-vuln-local-submit");
  const error = document.getElementById("trivy-vuln-local-error");
  const result = document.getElementById("trivy-vuln-local-result");
  const classKeys = ["os-pkgs", "lang-pkgs", "config", "secret", "license", "license-file", "crypto", "custom", "unknown"];
  const severityKeys = ["critical", "high", "medium", "low", "unknown"];
  const findingKeys = ["vulnerabilities", "misconfigurations", "secrets", "licenses"];
  const responseKeys = ["format", "schema_version", "profile", "result_count", "class_counts", "vuln_counts", "misconfig_sev_counts", "finding_counts", "report_sha256"];
  let busy = false;

  const validCountMap = (value, keys) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const actual = Object.keys(value);
    return actual.length === keys.length && keys.every(key => actual.includes(key) && Number.isSafeInteger(value[key]) && value[key] >= 0);
  };
  const validSummary = data => {
    if (!data || typeof data !== "object" || Array.isArray(data)) return false;
    const actual = Object.keys(data);
    return actual.length === responseKeys.length && responseKeys.every(key => actual.includes(key))
      && data.format === "trivy-native-json" && data.schema_version === 2
      && data.profile === "local-python-requirements-v1"
      && Number.isSafeInteger(data.result_count) && data.result_count >= 0 && data.result_count <= 500
      && validCountMap(data.class_counts, classKeys)
      && validCountMap(data.vuln_counts, severityKeys)
      && validCountMap(data.misconfig_sev_counts, severityKeys)
      && validCountMap(data.finding_counts, findingKeys)
      && classKeys.reduce((sum, key) => sum + data.class_counts[key], 0) === data.result_count
      && severityKeys.reduce((sum, key) => sum + data.misconfig_sev_counts[key], 0) === data.finding_counts.misconfigurations
      && typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256);
  };
  const clearDisplay = () => {
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    for (const id of ["trivy-vuln-local-groups", "trivy-vuln-local-total", "trivy-vuln-local-severity", "trivy-vuln-local-hash"])
      document.getElementById(id).textContent = "";
  };
  consent.addEventListener("change", () => { submit.disabled = busy || !consent.checked; });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = path.value.trim();
    if (!consent.checked || !projectPath) {
      error.textContent = "Yerel proje yolu ve açık tarama onayı gerekli.";
      error.classList.remove("hidden");
      submit.disabled = !consent.checked;
      return;
    }
    busy = true;
    submit.disabled = true;
    try {
      const data = await api("/api/tool-runs/trivy-vulnerability", {
        method: "POST", body: JSON.stringify({ confirm_local: true, project_path: projectPath }),
      });
      if (!validSummary(data)) throw new Error("invalid_summary");
      document.getElementById("trivy-vuln-local-groups").textContent = String(data.result_count);
      document.getElementById("trivy-vuln-local-total").textContent = String(data.finding_counts.vulnerabilities);
      document.getElementById("trivy-vuln-local-severity").textContent = severityKeys.map(key => `${key}:${data.vuln_counts[key]}`).join(" ");
      document.getElementById("trivy-vuln-local-hash").textContent = data.report_sha256;
      result.classList.remove("hidden");
      consent.checked = false;
    } catch {
      error.textContent = "Tarama tamamlanamadı. Proje yolunu, yerel Trivy aracını ve veritabanını denetleyin.";
      error.classList.remove("hidden");
    } finally {
      busy = false;
      submit.disabled = !consent.checked;
    }
  });
})();

// Saved k6 classic handleSummary JSON preview. This never executes a test.
let k6SummaryPreviewGeneration = 0;
let k6SummaryModalOpen = false;
const k6SummaryFieldIds = [
  "k6-summary-http-requests",
  "k6-summary-p95",
  "k6-summary-threshold-passed",
  "k6-summary-threshold-failed",
  "k6-summary-report-sha256"
];
function resetK6SummaryPreviewOutputs() {
  k6SummaryPreviewGeneration += 1;
  const error = document.getElementById("k6-summary-preview-error");
  if (error) {
    error.textContent = "";
    error.classList.add("hidden");
  }
  const result = document.getElementById("k6-summary-preview-result");
  if (result) result.classList.add("hidden");
  k6SummaryFieldIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = "";
  });
}
function clearK6SummaryPreview() {
  resetK6SummaryPreviewOutputs();
  const paste = document.getElementById("k6-summary-paste");
  const fileInput = document.getElementById("k6-summary-file");
  if (paste) paste.value = "";
  if (fileInput) {
    fileInput.value = "";
    if (Array.isArray(fileInput.files)) fileInput.files = [];
  }
}
(() => {
  const modalId = "k6-summary-preview-modal";
  function fail() {
    const error = document.getElementById("k6-summary-preview-error");
    error.textContent = "Geçersiz veya desteklenmeyen klasik k6 JSON raporu.";
    error.classList.remove("hidden");
  }
  document.addEventListener("click", event => {
    const close = event.target.closest("[data-close]");
    if ((close && close.dataset.close === modalId) || event.target.id === modalId) {
      showModal(modalId, false);
      clearK6SummaryPreview();
    }
  });
  document.addEventListener("input", event => {
    if (event.target.id === "k6-summary-paste" || event.target.id === "k6-summary-file") {
      k6SummaryPreviewGeneration += 1;
    }
  });
  document.addEventListener("change", event => {
    if (event.target.id === "k6-summary-paste" || event.target.id === "k6-summary-file") {
      k6SummaryPreviewGeneration += 1;
    }
  });
  document.addEventListener("submit", async event => {
    if (event.target.id !== "k6-summary-preview-form") return;
    event.preventDefault();
    const modal = document.getElementById(modalId);
    if (!modal.classList.contains("hidden")) k6SummaryModalOpen = true;
    const requestGeneration = ++k6SummaryPreviewGeneration;
    const paste = document.getElementById("k6-summary-paste");
    const fileInput = document.getElementById("k6-summary-file");
    const error = document.getElementById("k6-summary-preview-error");
    const result = document.getElementById("k6-summary-preview-result");
    const initialPasteValue = paste.value;
    const initialFile = (fileInput.files && fileInput.files[0]) || null;
    const initialFileValue = fileInput.value;
    const isCurrent = () =>
      requestGeneration === k6SummaryPreviewGeneration &&
      !modal.classList.contains("hidden") &&
      paste.value === initialPasteValue &&
      ((fileInput.files && fileInput.files[0]) || null) === initialFile &&
      fileInput.value === initialFileValue;
    const failIfCurrent = () => {
      if (isCurrent()) fail();
    };
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    k6SummaryFieldIds.forEach(id => { document.getElementById(id).textContent = ""; });
    let raw = paste.value.trim();
    if (!raw && fileInput.files && fileInput.files[0]) {
      const file = fileInput.files[0];
      if (file.size > 60_000) { failIfCurrent(); return; }
      try { raw = await file.text(); } catch { failIfCurrent(); return; }
      if (!isCurrent()) return;
    }
    if (!raw || new TextEncoder().encode(raw).length > 60_000) { failIfCurrent(); return; }
    let report;
    try { report = JSON.parse(raw); } catch { failIfCurrent(); return; }
    if (!report || typeof report !== "object" || Array.isArray(report) ||
        !report.root_group || typeof report.root_group !== "object" || Array.isArray(report.root_group) ||
        !report.state || typeof report.state !== "object" || Array.isArray(report.state) ||
        !report.metrics || typeof report.metrics !== "object" || Array.isArray(report.metrics) ||
        !report.metrics.http_reqs || report.metrics.http_reqs.type !== "counter" ||
        report.version !== undefined || report.schema_version !== undefined || report.$schema !== undefined) {
      failIfCurrent(); return;
    }
    const body = JSON.stringify({report});
    if (new TextEncoder().encode(body).length > 65_536) { failIfCurrent(); return; }
    try {
      const data = await api("/api/tool-reports/k6-summary-json/summary", {
        method: "POST", headers: {"Content-Type": "application/json"}, body,
      });
      if (!isCurrent()) return;
      const counts = data.threshold_counts;
      if (data.format !== "k6-handle-summary-json" ||
          !Number.isSafeInteger(data.http_requests) || data.http_requests < 0 ||
          (data.duration_p95_ms !== null &&
            (typeof data.duration_p95_ms !== "number" || !Number.isFinite(data.duration_p95_ms) || data.duration_p95_ms < 0)) ||
          !counts || typeof counts !== "object" || Array.isArray(counts) ||
          !Number.isSafeInteger(counts.passed) || counts.passed < 0 ||
          !Number.isSafeInteger(counts.failed) || counts.failed < 0 ||
          typeof data.report_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(data.report_sha256)) {
        fail(); return;
      }
      document.getElementById("k6-summary-http-requests").textContent = String(data.http_requests);
      document.getElementById("k6-summary-p95").textContent = data.duration_p95_ms === null ? "—" : String(data.duration_p95_ms);
      document.getElementById("k6-summary-threshold-passed").textContent = String(counts.passed);
      document.getElementById("k6-summary-threshold-failed").textContent = String(counts.failed);
      document.getElementById("k6-summary-report-sha256").textContent = data.report_sha256;
      result.classList.remove("hidden");
      paste.value = "";
      fileInput.value = "";
      if (Array.isArray(fileInput.files)) fileInput.files = [];
    } catch { failIfCurrent(); }
  });
})();

(() => {
  const form = document.getElementById("trivy-npm-local-form");
  if (!form) return;
  const path = document.getElementById("trivy-npm-local-path");
  const consent = document.getElementById("trivy-npm-local-consent");
  const submit = document.getElementById("trivy-npm-local-submit");
  const error = document.getElementById("trivy-npm-local-error");
  const result = document.getElementById("trivy-npm-local-result");
  const classKeys = ["os-pkgs", "lang-pkgs", "config", "secret", "license", "license-file", "crypto", "custom", "unknown"];
  const severityKeys = ["critical", "high", "medium", "low", "unknown"];
  const findingKeys = ["vulnerabilities", "misconfigurations", "secrets", "licenses"];
  const responseKeys = ["format", "schema_version", "profile", "result_count", "class_counts", "vuln_counts", "misconfig_sev_counts", "finding_counts", "report_sha256"];
  let busy = false;

  const validCountMap = (value, keys) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const actual = Object.keys(value);
    return actual.length === keys.length && keys.every(key => actual.includes(key) && Number.isSafeInteger(value[key]) && value[key] >= 0);
  };
  const validSummary = data => {
    if (!data || typeof data !== "object" || Array.isArray(data)) return false;
    const actual = Object.keys(data);
    return actual.length === responseKeys.length && responseKeys.every(key => actual.includes(key))
      && data.format === "trivy-native-json" && data.schema_version === 2
      && data.profile === "local-npm-package-lock-v1"
      && Number.isSafeInteger(data.result_count) && data.result_count >= 0 && data.result_count <= 500
      && validCountMap(data.class_counts, classKeys)
      && validCountMap(data.vuln_counts, severityKeys)
      && validCountMap(data.misconfig_sev_counts, severityKeys)
      && validCountMap(data.finding_counts, findingKeys)
      && classKeys.reduce((sum, key) => sum + data.class_counts[key], 0) === data.result_count
      && severityKeys.reduce((sum, key) => sum + data.misconfig_sev_counts[key], 0) === data.finding_counts.misconfigurations
      && typeof data.report_sha256 === "string" && /^[0-9a-f]{64}$/.test(data.report_sha256);
  };
  const clearDisplay = () => {
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    for (const id of ["trivy-npm-local-groups", "trivy-npm-local-total", "trivy-npm-local-severity", "trivy-npm-local-hash"])
      document.getElementById(id).textContent = "";
  };
  consent.addEventListener("change", () => { submit.disabled = busy || !consent.checked; });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy) return;
    clearDisplay();
    const projectPath = path.value.trim();
    if (!consent.checked || !projectPath) {
      error.textContent = "Yerel proje yolu ve açık tarama onayı gerekli.";
      error.classList.remove("hidden");
      submit.disabled = !consent.checked;
      return;
    }
    busy = true;
    submit.disabled = true;
    try {
      const data = await api("/api/tool-runs/trivy-npm-vulnerability", {
        method: "POST", body: JSON.stringify({ confirm_local: true, project_path: projectPath }),
      });
      if (!validSummary(data)) throw new Error("invalid_summary");
      document.getElementById("trivy-npm-local-groups").textContent = String(data.result_count);
      document.getElementById("trivy-npm-local-total").textContent = String(data.finding_counts.vulnerabilities);
      document.getElementById("trivy-npm-local-severity").textContent = severityKeys.map(key => `${key}:${data.vuln_counts[key]}`).join(" ");
      document.getElementById("trivy-npm-local-hash").textContent = data.report_sha256;
      result.classList.remove("hidden");
      consent.checked = false;
    } catch {
      error.textContent = "Tarama tamamlanamadı. Proje yolunu, yerel yerel Trivy aracını ve veritabanını denetleyin.";
      error.classList.remove("hidden");
    } finally {
      busy = false;
      submit.disabled = !consent.checked;
    }
  });
})();

// Saved k6 machine-readable v1 JSON preview. This never executes a test.
let k6MachineSummaryPreviewGeneration = 0;
let k6MachineSummaryModalOpen = false;
const k6MachineSummaryFieldIds = [
  "k6-machine-summary-http-requests",
  "k6-machine-summary-p95",
  "k6-machine-summary-threshold-passed",
  "k6-machine-summary-threshold-failed",
  "k6-machine-summary-report-sha256"
];
function resetK6MachineSummaryPreviewOutputs() {
  k6MachineSummaryPreviewGeneration += 1;
  const error = document.getElementById("k6-machine-summary-preview-error");
  if (error) {
    error.textContent = "";
    error.classList.add("hidden");
  }
  const result = document.getElementById("k6-machine-summary-preview-result");
  if (result) result.classList.add("hidden");
  k6MachineSummaryFieldIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = "";
  });
}
function clearK6MachineSummaryPreview() {
  resetK6MachineSummaryPreviewOutputs();
  const paste = document.getElementById("k6-machine-summary-paste");
  const fileInput = document.getElementById("k6-machine-summary-file");
  if (paste) paste.value = "";
  if (fileInput) {
    fileInput.value = "";
    if (Array.isArray(fileInput.files)) fileInput.files = [];
  }
}
(() => {
  const modalId = "k6-machine-summary-preview-modal";
  function fail() {
    const error = document.getElementById("k6-machine-summary-preview-error");
    error.textContent = "Geçersiz veya desteklenmeyen k6 machine-readable v1 JSON raporu.";
    error.classList.remove("hidden");
  }
  document.addEventListener("click", event => {
    const close = event.target.closest("[data-close]");
    if ((close && close.dataset.close === modalId) || event.target.id === modalId) {
      showModal(modalId, false);
      clearK6MachineSummaryPreview();
    }
  });
  document.addEventListener("input", event => {
    if (event.target.id === "k6-machine-summary-paste" || event.target.id === "k6-machine-summary-file") {
      k6MachineSummaryPreviewGeneration += 1;
    }
  });
  document.addEventListener("change", event => {
    if (event.target.id === "k6-machine-summary-paste" || event.target.id === "k6-machine-summary-file") {
      k6MachineSummaryPreviewGeneration += 1;
    }
  });
  document.addEventListener("submit", async event => {
    if (event.target.id !== "k6-machine-summary-preview-form") return;
    event.preventDefault();
    const modal = document.getElementById(modalId);
    if (!modal.classList.contains("hidden")) k6MachineSummaryModalOpen = true;
    const requestGeneration = ++k6MachineSummaryPreviewGeneration;
    const paste = document.getElementById("k6-machine-summary-paste");
    const fileInput = document.getElementById("k6-machine-summary-file");
    const error = document.getElementById("k6-machine-summary-preview-error");
    const result = document.getElementById("k6-machine-summary-preview-result");
    const initialPasteValue = paste.value;
    const initialFile = (fileInput.files && fileInput.files[0]) || null;
    const initialFileValue = fileInput.value;
    const isCurrent = () =>
      requestGeneration === k6MachineSummaryPreviewGeneration &&
      !modal.classList.contains("hidden") &&
      paste.value === initialPasteValue &&
      ((fileInput.files && fileInput.files[0]) || null) === initialFile &&
      fileInput.value === initialFileValue;
    const failIfCurrent = () => {
      if (isCurrent()) fail();
    };
    error.textContent = "";
    error.classList.add("hidden");
    result.classList.add("hidden");
    k6MachineSummaryFieldIds.forEach(id => { document.getElementById(id).textContent = ""; });
    let raw = paste.value.trim();
    if (!raw && fileInput.files && fileInput.files[0]) {
      const file = fileInput.files[0];
      if (file.size > 60_000) { failIfCurrent(); return; }
      try { raw = await file.text(); } catch { failIfCurrent(); return; }
      if (!isCurrent()) return;
    }
    if (!raw || new TextEncoder().encode(raw).length > 60_000) { failIfCurrent(); return; }
    let report;
    try { report = JSON.parse(raw); } catch { failIfCurrent(); return; }
    if (!report || typeof report !== "object" || Array.isArray(report) ||
        report.version !== "1.0.0" || !report.results ||
        !Array.isArray(report.results.metrics)) { failIfCurrent(); return; }
    const body = JSON.stringify({report});
    if (new TextEncoder().encode(body).length > 65_536) { failIfCurrent(); return; }
    try {
      const data = await api("/api/tool-reports/k6-machine-summary-v1/summary", {
        method: "POST", headers: {"Content-Type": "application/json"}, body,
      });
      if (!isCurrent()) return;
      const counts = data.threshold_counts;
      if (Object.keys(data).length !== 5 || data.format !== "k6-machine-summary-v1" ||
          !Number.isSafeInteger(data.http_requests) || data.http_requests < 0 ||
          (data.duration_p95_ms !== null &&
            (typeof data.duration_p95_ms !== "number" || !Number.isFinite(data.duration_p95_ms) ||
              data.duration_p95_ms < 0)) ||
          !counts || typeof counts !== "object" || Array.isArray(counts) ||
          Object.keys(counts).length !== 2 || counts.passed !== 0 || counts.failed !== 0 ||
          typeof data.report_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(data.report_sha256)) {
        fail(); return;
      }
      document.getElementById("k6-machine-summary-http-requests").textContent = String(data.http_requests);
      document.getElementById("k6-machine-summary-p95").textContent = data.duration_p95_ms === null ? "—" : String(data.duration_p95_ms);
      document.getElementById("k6-machine-summary-threshold-passed").textContent = "0 (veri yok)";
      document.getElementById("k6-machine-summary-threshold-failed").textContent = "0 (veri yok)";
      document.getElementById("k6-machine-summary-report-sha256").textContent = data.report_sha256;
      result.classList.remove("hidden");
      paste.value = "";
      fileInput.value = "";
      if (Array.isArray(fileInput.files)) fileInput.files = [];
    } catch { failIfCurrent(); }
  });
})();

// Wave 1 Phase 1 UI Helpers (OpenSSL Batch, Burp Handoff, Semgrep Inventory, Dependency Remediation, Secret Bundle)
async function requestOpenSslBatchSummary(rawReports, apiClient = api) {
  if (typeof globalThis.requestOpenSslBatchPreview === "function") {
    return await globalThis.requestOpenSslBatchPreview(apiClient, rawReports);
  }
  const reports = Array.isArray(rawReports)
    ? rawReports.map(item => String(item ?? "").trim()).filter(Boolean)
    : String(rawReports ?? "").trim().split(/\r?\n?[ \t]*---CERT---[ \t]*\r?\n?|\r?\n[ \t]*\r?\n+/).map(s => s.trim()).filter(Boolean);
  if (reports.length < 1 || reports.length > 8) {
    throw new Error("OpenSSL x509 toplu önizleme 1 ile 8 arasında sertifika bloğu gerektirir.");
  }
  const body = JSON.stringify({ reports });
  if (new TextEncoder().encode(body).length > 65536) {
    throw new Error("OpenSSL x509 toplu isteği 65536 bayt sınırını aşıyor.");
  }
  return await apiClient("/api/tool-reports/openssl-x509/batch-summary", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
}

async function requestBurpHandoffProfile(reportXml, apiClient = api) {
  if (typeof reportXml !== "string" || !reportXml.trim() || reportXml.includes("\0")) {
    throw new Error("Geçerli bir Burp XML raporu gereklidir.");
  }
  const body = JSON.stringify({ report_xml: reportXml });
  if (new TextEncoder().encode(body).length > 65536) {
    throw new Error("Burp XML raporu 65536 bayt sınırını aşıyor.");
  }
  const data = await apiClient("/api/tool-reports/burp/handoff-profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!data || typeof data !== "object" || data.format !== "burp-handoff-profile-v1") {
    throw new Error("Geçersiz Burp handoff profil yanıtı.");
  }
  return data;
}

async function loadSemgrepRulepackInventory(apiClient = api) {
  const data = await apiClient("/api/tools/semgrep/rulepack-inventory");
  if (!data || typeof data !== "object" || data.format !== "semgrep-rulepack-inventory-v1") {
    throw new Error("Geçersiz Semgrep kural paketi envanter yanıtı.");
  }
  return data;
}

async function requestDependencyRemediationPlan(findings, apiClient = api) {
  if (!Array.isArray(findings) || findings.length < 1 || findings.length > 500) {
    throw new Error("Bağımlılık iyileştirme planı için 1–500 arasında bulgu gereklidir.");
  }
  const body = JSON.stringify({ findings });
  if (new TextEncoder().encode(body).length > 65536) {
    throw new Error("Bağımlılık iyileştirme isteği 65536 bayt sınırını aşıyor.");
  }
  const data = await apiClient("/api/tool-reports/dependency-remediation-plan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!data || typeof data !== "object" || data.format !== "dependency-remediation-plan-v1") {
    throw new Error("Geçersiz bağımlılık iyileştirme planı yanıtı.");
  }
  return data;
}

async function requestSecretBundleValidation(payload, apiClient = api) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Geçerli bir sır doğrulama paketi nesnesi gereklidir.");
  }
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).length > 65536) {
    throw new Error("Sır doğrulama paketi 65536 bayt sınırını aşıyor.");
  }
  const data = await apiClient("/api/tools/secret-bundle/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!data || typeof data !== "object" || data.format !== "secret-verification-bundle-v1") {
    throw new Error("Geçersiz sır doğrulama paketi yanıtı.");
  }
  return data;
}

async function loadSsllabsRateState(hostname = "", apiClient = api) {
  const suffix = typeof hostname === "string" && hostname.trim()
    ? "?hostname=" + encodeURIComponent(hostname.trim())
    : "";
  const data = await apiClient("/api/tools/ssllabs/rate-state" + suffix);
  if (!data || typeof data !== "object" || data.format !== "ssllabs-rate-state-v1") {
    throw new Error("Geçersiz SSL Labs hız durumu yanıtı.");
  }
  return data;
}

async function requestSsllabsCachedQuery(payload, apiClient = api) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || payload.confirm_qualys !== true) {
    throw new Error("Açık Qualys önbellek sorgu onayı gereklidir.");
  }
  return await apiClient("/api/tools/ssllabs/cached-query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestBurpLoggerCsvSummary(payload, apiClient = api) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || typeof payload.report !== "string") {
    throw new Error("Geçerli bir Burp Logger CSV raporu gereklidir.");
  }
  return await apiClient("/api/tool-reports/burp-logger-csv/summary", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestDependabotOfflineSync(payload, apiClient = api) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || payload.confirm_sync !== true) {
    throw new Error("Açık Dependabot eşitleme onayı gereklidir.");
  }
  return await apiClient("/api/tool-reports/dependabot/offline-sync", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestSemgrepTlsVerifyFilter(payload, apiClient = api) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Geçerli bir Semgrep TLS doğrulama filtresi isteği gereklidir.");
  }
  return await apiClient("/api/tool-reports/semgrep/tls-verify-filter", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function loadTrivyDbFreshness(profile = "", apiClient = api) {
  const suffix = typeof profile === "string" && profile.trim()
    ? "?profile=" + encodeURIComponent(profile.trim())
    : "";
  return await apiClient("/api/tools/trivy/db-freshness" + suffix);
}

async function requestTrivyTerraformBatch(projectPath, terraformFiles, apiClient = api) {
  return await apiClient("/api/tools/trivy/terraform-batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirm_local: true,
      project_path: projectPath,
      terraform_files: terraformFiles,
    }),
  });
}

async function requestPlaywrightLocalFixture(apiClient = api) {
  return await apiClient("/api/tools/playwright/local-fixture", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm_local: true }),
  });
}

async function requestK6LoopbackSmoke(targetUrl, path, apiClient = api) {
  return await apiClient("/api/tools/k6/loopback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirm_local: true,
      target_url: targetUrl,
      path,
    }),
  });
}

async function requestToolingAutodiscover(apiClient = api) {
  return await apiClient("/api/tooling/autodiscover", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm_bind: true }),
  });
}

async function loadPortableBundleManifest(apiClient = api) {
  return await apiClient("/api/tooling/bundle-manifest");
}

async function requestOpenApiSecurityAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/openapi-security/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestDnsEmailSecurityAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/web-infra/dns-email-audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestWebDiscoveryAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/web-infra/discovery-audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestEngagementAutoEvidenceSync(engagementId, payload = {}, apiClient = api) {
  return await apiClient(`/api/engagements/${encodeURIComponent(engagementId)}/auto-evidence-sync`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestEnableBuiltinPlugins(apiClient = api) {
  return await apiClient("/api/plugins/enable-builtins", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm_enable: true }),
  });
}

async function verifyAuditLogChain(apiClient = api) {
  return await apiClient("/api/audit-log/verify");
}

async function loadEngagementComplianceMatrix(engagementId, apiClient = api) {
  return await apiClient(`/api/engagements/${encodeURIComponent(engagementId)}/compliance-matrix`);
}

async function loadProjectAuditComplianceMatrix(auditId, apiClient = api) {
  return await apiClient(`/api/project-audits/${encodeURIComponent(auditId)}/compliance-matrix`);
}

async function requestProjectAuditDiff(beforeId, afterId, apiClient = api) {
  return await apiClient("/api/project-audits/diff", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ before_id: beforeId, after_id: afterId }),
  });
}

async function requestDependencyReachability(projectPath, vulnerablePackages = undefined, apiClient = api) {
  return await apiClient("/api/dependency-security/reachability", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      project_path: projectPath,
      confirm_local_scan: true,
      vulnerable_packages: vulnerablePackages,
    }),
  });
}

async function requestVerifyEngagementRetests(engagementId, payload = {}, apiClient = api) {
  return await apiClient(`/api/engagements/${encodeURIComponent(engagementId)}/verify-retests`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestQualityGateEvaluation(payload = {}, apiClient = api) {
  return await apiClient("/api/quality-gate/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestMobileProjectAudit(projectPath, appProfile = "all", apiClient = api) {
  return await apiClient("/api/mobile-security/audit-project", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      project_path: projectPath,
      app_profile: appProfile,
      confirm_local: true,
    }),
  });
}

async function requestMobilePackageAudit(packagePath, apiClient = api) {
  return await apiClient("/api/mobile-security/audit-package", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      package_path: packagePath,
      confirm_local: true,
    }),
  });
}

async function requestMobileManifestAudit(rawContent, filename = "AndroidManifest.xml", appProfile = "all", apiClient = api) {
  return await apiClient("/api/mobile-security/audit-manifest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      raw_content: rawContent,
      filename,
      app_profile: appProfile,
    }),
  });
}

async function requestAiLlmSecurityAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/ai-llm-security/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestCloudIamSecurityAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/cloud-iam-security/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestDesktopSecurityAudit(projectPath, apiClient = api) {
  return await apiClient("/api/desktop-security/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ project_path: projectPath, confirm_local: true }),
  });
}

async function requestProtocolSecurityAudit(rawContent, protocolType = "auto", filename = "service.proto", apiClient = api) {
  return await apiClient("/api/protocol-security/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_content: rawContent, protocol_type: protocolType, filename }),
  });
}

async function requestAuthProtocolAudit(rawContent, artifactType = "auto", apiClient = api) {
  return await apiClient("/api/auth-protocol/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_content: rawContent, artifact_type: artifactType }),
  });
}

async function requestAttackPathCorrelation(payload = {}, apiClient = api) {
  return await apiClient("/api/attack-paths/correlate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestAutoRemediationPatches(payload = {}, apiClient = api) {
  return await apiClient("/api/remediation/auto-patch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestExecutivePentestReport(payload = {}, apiClient = api) {
  return await apiClient("/api/reports/executive-pentest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestBusinessLogicAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/business-logic/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestDatabaseSecurityAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/database-security/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestCryptoCbomPqcAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/crypto-cbom-pqc/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestWeb3IotSecurityAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/web3-iot-security/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestThreatModelGenerate(payload = {}, apiClient = api) {
  return await apiClient("/api/threat-model/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestSupplyChainSlsaAudit(payload = {}, apiClient = api) {
  return await apiClient("/api/supply-chain-slsa/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestBlueTeamSynthesizeRules(payload = {}, apiClient = api) {
  return await apiClient("/api/blue-team/synthesize-rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function postAdvancedSuiteV3(route, payload = {}, apiClient = api) {
  return apiClient(route, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function requestSecretIntelligenceAudit(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/secret-intelligence/audit", payload, apiClient);
}

async function requestPrivacyDataflowAudit(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/privacy-dataflow/audit", payload, apiClient);
}

async function requestHostHardeningAudit(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/host-hardening/audit", payload, apiClient);
}

async function requestDosResilienceAudit(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/dos-resilience/audit", payload, apiClient);
}

async function requestAuditLoggingAudit(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/audit-logging/audit", payload, apiClient);
}

async function requestBrowserExtensionPwaAudit(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/browser-extension-pwa/audit", payload, apiClient);
}

async function requestZeroTrustMeshAudit(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/zero-trust-mesh/audit", payload, apiClient);
}

async function requestCvssSsvcPrioritize(payload = {}, apiClient = api) {
  return await postAdvancedSuiteV3("/api/cvss-ssvc/prioritize", payload, apiClient);
}

if (typeof globalThis !== "undefined") {
  globalThis.requestOpenSslBatchSummary = requestOpenSslBatchSummary;
  globalThis.requestBurpHandoffProfile = requestBurpHandoffProfile;
  globalThis.loadSemgrepRulepackInventory = loadSemgrepRulepackInventory;
  globalThis.requestDependencyRemediationPlan = requestDependencyRemediationPlan;
  globalThis.requestSecretBundleValidation = requestSecretBundleValidation;
  globalThis.loadSsllabsRateState = loadSsllabsRateState;
  globalThis.requestSsllabsCachedQuery = requestSsllabsCachedQuery;
  globalThis.requestBurpLoggerCsvSummary = requestBurpLoggerCsvSummary;
  globalThis.requestDependabotOfflineSync = requestDependabotOfflineSync;
  globalThis.requestSemgrepTlsVerifyFilter = requestSemgrepTlsVerifyFilter;
  globalThis.loadTrivyDbFreshness = loadTrivyDbFreshness;
  globalThis.requestTrivyTerraformBatch = requestTrivyTerraformBatch;
  globalThis.requestPlaywrightLocalFixture = requestPlaywrightLocalFixture;
  globalThis.requestK6LoopbackSmoke = requestK6LoopbackSmoke;
  globalThis.requestToolingAutodiscover = requestToolingAutodiscover;
  globalThis.loadPortableBundleManifest = loadPortableBundleManifest;
  globalThis.requestOpenApiSecurityAudit = requestOpenApiSecurityAudit;
  globalThis.requestDnsEmailSecurityAudit = requestDnsEmailSecurityAudit;
  globalThis.requestWebDiscoveryAudit = requestWebDiscoveryAudit;
  globalThis.requestEngagementAutoEvidenceSync = requestEngagementAutoEvidenceSync;
  globalThis.requestEnableBuiltinPlugins = requestEnableBuiltinPlugins;
  globalThis.verifyAuditLogChain = verifyAuditLogChain;
  globalThis.loadEngagementComplianceMatrix = loadEngagementComplianceMatrix;
  globalThis.loadProjectAuditComplianceMatrix = loadProjectAuditComplianceMatrix;
  globalThis.requestProjectAuditDiff = requestProjectAuditDiff;
  globalThis.requestDependencyReachability = requestDependencyReachability;
  globalThis.requestVerifyEngagementRetests = requestVerifyEngagementRetests;
  globalThis.requestQualityGateEvaluation = requestQualityGateEvaluation;
  globalThis.requestMobileProjectAudit = requestMobileProjectAudit;
  globalThis.requestMobilePackageAudit = requestMobilePackageAudit;
  globalThis.requestMobileManifestAudit = requestMobileManifestAudit;
  globalThis.requestAiLlmSecurityAudit = requestAiLlmSecurityAudit;
  globalThis.requestCloudIamSecurityAudit = requestCloudIamSecurityAudit;
  globalThis.requestDesktopSecurityAudit = requestDesktopSecurityAudit;
  globalThis.requestProtocolSecurityAudit = requestProtocolSecurityAudit;
  globalThis.requestAuthProtocolAudit = requestAuthProtocolAudit;
  globalThis.requestAttackPathCorrelation = requestAttackPathCorrelation;
  globalThis.requestAutoRemediationPatches = requestAutoRemediationPatches;
  globalThis.requestExecutivePentestReport = requestExecutivePentestReport;
  globalThis.requestBusinessLogicAudit = requestBusinessLogicAudit;
  globalThis.requestDatabaseSecurityAudit = requestDatabaseSecurityAudit;
  globalThis.requestCryptoCbomPqcAudit = requestCryptoCbomPqcAudit;
  globalThis.requestWeb3IotSecurityAudit = requestWeb3IotSecurityAudit;
  globalThis.requestThreatModelGenerate = requestThreatModelGenerate;
  globalThis.requestSupplyChainSlsaAudit = requestSupplyChainSlsaAudit;
  globalThis.requestBlueTeamSynthesizeRules = requestBlueTeamSynthesizeRules;
  globalThis.requestSecretIntelligenceAudit = requestSecretIntelligenceAudit;
  globalThis.requestPrivacyDataflowAudit = requestPrivacyDataflowAudit;
  globalThis.requestHostHardeningAudit = requestHostHardeningAudit;
  globalThis.requestDosResilienceAudit = requestDosResilienceAudit;
  globalThis.requestAuditLoggingAudit = requestAuditLoggingAudit;
  globalThis.requestBrowserExtensionPwaAudit = requestBrowserExtensionPwaAudit;
  globalThis.requestZeroTrustMeshAudit = requestZeroTrustMeshAudit;
  globalThis.requestCvssSsvcPrioritize = requestCvssSsvcPrioritize;
}

document.addEventListener("click", async (event) => {
  const autoBtn = event.target.closest("[data-completed-autodiscover]");
  if (autoBtn) {
    event.preventDefault();
    const outEl = document.getElementById("completed-backlog-output");
    const errEl = document.getElementById("completed-backlog-error");
    if (errEl) { errEl.textContent = ""; errEl.classList.add("hidden"); }
    if (outEl) { outEl.textContent = "Yerel ve taşınabilir araçlar algılanıp bağlanıyor..."; outEl.classList.remove("hidden"); }
    try {
      const res = await requestToolingAutodiscover();
      if (res && res.readiness) {
        state.toolingReadiness = res.readiness;
        renderTooling();
      }
      if (outEl) outEl.textContent = JSON.stringify(res, null, 2);
    } catch (err) {
      if (outEl) outEl.classList.add("hidden");
      if (errEl) { errEl.textContent = err?.message || "Araç bağlama başarısız oldu."; errEl.classList.remove("hidden"); }
    }
    return;
  }
  const pluginBtn = event.target.closest("[data-completed-enable-plugins]");
  if (pluginBtn) {
    event.preventDefault();
    const outEl = document.getElementById("completed-backlog-output");
    const errEl = document.getElementById("completed-backlog-error");
    if (errEl) { errEl.textContent = ""; errEl.classList.add("hidden"); }
    if (outEl) { outEl.textContent = "Yerleşik savunma eklentileri etkinleştiriliyor..."; outEl.classList.remove("hidden"); }
    try {
      const res = await requestEnableBuiltinPlugins();
      if (outEl) outEl.textContent = JSON.stringify(res, null, 2);
    } catch (err) {
      if (outEl) outEl.classList.add("hidden");
      if (errEl) { errEl.textContent = err?.message || "Eklenti etkinleştirme başarısız oldu."; errEl.classList.remove("hidden"); }
    }
    return;
  }
  const btn = event.target.closest("[data-completed-get]");
  if (!btn) return;
  event.preventDefault();
  const route = btn.getAttribute("data-completed-get");
  const outEl = document.getElementById("completed-backlog-output");
  const errEl = document.getElementById("completed-backlog-error");
  if (errEl) { errEl.textContent = ""; errEl.classList.add("hidden"); }
  if (outEl) { outEl.textContent = "Yükleniyor..."; outEl.classList.remove("hidden"); }
  try {
    const res = await api(route);
    if (outEl) outEl.textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    if (outEl) outEl.classList.add("hidden");
    if (errEl) { errEl.textContent = err?.message || "İstek başarısız oldu."; errEl.classList.remove("hidden"); }
  }
});

const COMPLETED_INLINE_ROUTES = new Set([
  "/api/secret-intelligence/audit", "/api/privacy-dataflow/audit", "/api/host-hardening/audit",
  "/api/dos-resilience/audit", "/api/audit-logging/audit", "/api/browser-extension-pwa/audit",
  "/api/zero-trust-mesh/audit", "/api/business-logic/audit", "/api/database-security/audit",
  "/api/crypto-cbom-pqc/audit", "/api/web3-iot-security/audit", "/api/ai-llm-security/audit",
  "/api/cloud-iam-security/audit", "/api/openapi-security/audit", "/api/protocol-security/audit",
  "/api/auth-protocol/audit", "/api/mobile-security/audit-manifest", "/api/tool-reports/ssllabs/cache-contract",
]);
const COMPLETED_INLINE_ONLY_ROUTES = new Set([
  "/api/protocol-security/audit", "/api/auth-protocol/audit", "/api/mobile-security/audit-manifest",
  "/api/tool-reports/ssllabs/cache-contract",
]);
const COMPLETED_STORE_ROUTES = new Set([
  "/api/quality-gate/evaluate", "/api/attack-paths/correlate", "/api/remediation/auto-patch",
  "/api/reports/executive-pentest", "/api/blue-team/synthesize-rules",
]);

function buildCompletedRequestBody(route, { projectPath, rawContent, filename, extra, consent }) {
  if (route === "/api/cvss-ssvc/prioritize" && extra) return { vector: extra };
  if (route === "/api/dos-resilience/audit" && extra && !rawContent && !projectPath) return { regex: extra };
  if (COMPLETED_STORE_ROUTES.has(route)) {
    const body = {};
    if (state.projectAudits?.[0]?.id) body.project_audit_id = state.projectAudits[0].id;
    if (state.selectedEngagement?.id) body.engagement_id = state.selectedEngagement.id;
    if (state.scans?.[0]?.id) body.scan_id = state.scans[0].id;
    if (!Object.keys(body).length) throw new Error("Bu profil için önce bir proje denetimi, tarama veya çalışma kaydı oluşturun.");
    return body;
  }
  if (rawContent && COMPLETED_INLINE_ROUTES.has(route)) {
    if (route === "/api/tool-reports/ssllabs/cache-contract") return { report_json: rawContent };
    const body = { raw_content: rawContent };
    if (filename) {
      body.filename = filename;
      if (route === "/api/openapi-security/audit") body.source_name = filename;
    }
    return body;
  }
  if (COMPLETED_INLINE_ONLY_ROUTES.has(route)) throw new Error("Bu profil yalnız satır içi içerikle çalışır; içerik alanını doldurun.");
  if (!projectPath) throw new Error("Proje klasörü veya satır içi içerik gereklidir.");
  if (!consent) throw new Error("Proje klasörü kipi için açık yerel inceleme onayı gereklidir.");
  if (route === "/api/tool-runs/trivy-terraform-config-batch") return { confirm_local: true, project_path: projectPath, terraform_files: ["main.tf"] };
  if (route === "/api/dependency-security/reachability") return { confirm_local_scan: true, project_path: projectPath };
  return { confirm_local: true, project_path: projectPath };
}

function describeTaintFlow(flow) {
  if (!flow || typeof flow !== "object") return "";
  const via = Array.isArray(flow.via) && flow.via.length ? ` → ${flow.via.join(" → ")}` : "";
  const where = flow.source_file ? `${flow.source_file} satır` : "satır";
  return `Veri akışı: ${flow.source} (${where} ${flow.source_line})${via} → ${flow.sink} (satır ${flow.sink_line})`;
}

function renderCompletedSummary(res) {
  const el = document.getElementById("completed-backlog-summary");
  if (!el) return;
  const facts = [];
  if (res?.format) facts.push(["Biçim", res.format]);
  if (typeof res?.vector === "string" && res.vector.startsWith("CVSS:")) {
    const score = res.score ?? res.base_score;
    facts.push([res.vector.startsWith("CVSS:4.0") ? "CVSS 4.0" : "CVSS 3.1", `${score} (${res.severity || "?"})`]);
    if (res.cvss40_score !== undefined && res.cvss40_score !== null) facts.push(["CVSS 4.0 (türetilmiş)", `${res.cvss40_score} (${res.cvss40_severity || "?"})`]);
  } else if (res?.score !== undefined && res?.score !== null) {
    facts.push(["Puan", `${res.score}${res.grade ? ` (${res.grade})` : ""}`]);
  }
  if (res?.finding_count !== undefined) facts.push(["Bulgu", `${res.finding_count}${res.findings_truncated ? " (listede kırpıldı)" : ""}`]);
  if (res?.vulnerable !== undefined) facts.push(["ReDoS riski", res.vulnerable ? `Var (${res.risk || "?"})` : "Görülmedi"]);
  if (res?.verified !== undefined) facts.push(["Zincir doğrulaması", res.verified ? "Doğrulandı" : "Doğrulanamadı"]);
  // 23. tur: eski üretici uçların veri dayanağı (gerçek / şablon / karışık) ve gerçek kaynaklı özetler.
  if (res?.data_basis?.label) facts.push(["Veri dayanağı", res.data_basis.label]);
  if (res?.route_chain_count !== undefined) facts.push(["Rota → akış zinciri", String(res.route_chain_count)]);
  if (res?.ci_policy && typeof res.ci_policy === "object") facts.push(["CI politikası", res.ci_policy.passed ? "Geçti" : `Kaldı (${res.ci_policy.failing_count ?? 0})`]);
  if (res?.matched_patch_count !== undefined) facts.push(["Bulguyla eşleşen yama", String(res.matched_patch_count)]);
  if (res?.project_threat_model?.route_count !== undefined) facts.push(["Proje tehdit modeli rotası", String(res.project_threat_model.route_count)]);
  if (res?.has_provenance !== undefined) facts.push(["Kaynak kanıtı (imza/in-toto)", res.has_provenance ? "Var" : "Yok"]);
  const items = Array.isArray(res?.findings) ? res.findings : (Array.isArray(res?.prioritized_findings) ? res.prioritized_findings : []);
  const rows = items.slice(0, 200).map(item => {
    const severity = String(item.severity || item.cvss31_severity || "info").toLowerCase();
    const location = item.file ? `${item.file}${item.line ? `:${item.line}` : ""}` : "";
    const details = [];
    if (item.taint_flow) details.push(describeTaintFlow(item.taint_flow));
    if (item.cvss31_score !== undefined) details.push(`CVSS 3.1 ${item.cvss31_score}`);
    if (item.cvss40_score !== undefined && item.cvss40_score !== null) details.push(`CVSS 4.0 ${item.cvss40_score} (${item.cvss40_severity || "?"})`);
    if (item.ssvc_decision) details.push(`SSVC ${item.ssvc_decision}${item.due_date ? ` · son tarih ${item.due_date}` : ""}`);
    if (item.control_id) details.push(item.control_id);
    return `<tr><td><span class="severity-label ${esc(severity)}">${esc(severityLabel(severity).toUpperCase())}</span></td><td><b>${esc(item.title || "Bulgu")}</b>${details.length ? `<small>${esc(details.join(" · "))}</small>` : ""}</td><td>${esc(location)}</td></tr>`;
  }).join("");
  const factHtml = facts.map(([key, value]) => `<span class="status-pill"><b>${esc(key)}:</b> ${esc(value)}</span>`).join(" ");
  const tableHtml = rows
    ? `<table><thead><tr><th>Önem</th><th>Bulgu</th><th>Konum</th></tr></thead><tbody>${rows}</tbody></table>${items.length > 200 ? `<p><small>İlk 200 bulgu gösteriliyor; tamamı aşağıdaki JSON'da.</small></p>` : ""}`
    : "";
  const basisKind = res?.data_basis?.kind;
  const basisHtml = basisKind && basisKind !== "real"
    ? `<p class="notice"><small>${esc(basisKind === "template" ? "Bu çıktı örnek/simülasyondur: hiçbir bulguya bağlı değildir." : "Bu çıktıda bulguya bağlı olmayan şablon öğeler de var (basis: template).")}</small>${res.data_basis.note ? ` <small>${esc(res.data_basis.note)}</small>` : ""}</p>`
    : "";
  el.innerHTML = `<div class="button-row">${factHtml}</div>${basisHtml}${tableHtml}`; // sniper-reviewed: html-safe (tüm değerler esc() ile)
  globalThis.renderReachabilitySummary?.(res, el);
  el.classList.toggle("hidden", !factHtml && !tableHtml);
}

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!form || form.id !== "completed-trivy-lang-form") return;
  event.preventDefault();
  const routeEl = document.getElementById("completed-trivy-route");
  const outEl = document.getElementById("completed-backlog-output");
  const errEl = document.getElementById("completed-backlog-error");
  const summaryEl = document.getElementById("completed-backlog-summary");
  if (errEl) { errEl.textContent = ""; errEl.classList.add("hidden"); }
  if (summaryEl) { summaryEl.innerHTML = ""; summaryEl.classList.add("hidden"); }
  const route = routeEl ? routeEl.value : "/api/tool-runs/trivy-go-mod-vulnerability";
  let body;
  try {
    body = buildCompletedRequestBody(route, {
      projectPath: (document.getElementById("completed-trivy-path")?.value || "").trim(),
      rawContent: document.getElementById("completed-inline-content")?.value || "",
      filename: (document.getElementById("completed-inline-filename")?.value || "").trim(),
      extra: (document.getElementById("completed-extra-param")?.value || "").trim(),
      consent: Boolean(document.getElementById("completed-trivy-consent")?.checked),
    });
  } catch (err) {
    if (errEl) { errEl.textContent = err.message; errEl.classList.remove("hidden"); }
    return;
  }
  if (outEl) { outEl.textContent = "Çevrimdışı analiz çalıştırılıyor..."; outEl.classList.remove("hidden"); }
  try {
    const res = await api(route, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    renderCompletedSummary(res);
    if (outEl) outEl.textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    if (outEl) outEl.classList.add("hidden");
    if (errEl) { errEl.textContent = err?.message || "Analiz başarısız oldu."; errEl.classList.remove("hidden"); }
  }
});

// Direct SSL Labs authorization: one human checkbox, no automatic request.
(() => {
  const modalId = "ssllabs-authorized-modal";
  const target = () => document.getElementById("ssllabs-authorized-target");
  const consent = () => document.getElementById("ssllabs-authorized-confirm");
  const submit = () => document.getElementById("ssllabs-authorized-submit");
  const error = () => document.getElementById("ssllabs-authorized-error");
  const result = () => document.getElementById("ssllabs-authorized-result");
  let busy = false;

  function clearOutput() {
    error().textContent = "";
    error().classList.add("hidden");
    result().classList.add("hidden");
    for (const id of [
      "ssllabs-authorized-status", "ssllabs-authorized-endpoint-count",
      "ssllabs-authorized-confirmed-at", "ssllabs-authorized-report-sha256",
    ]) document.getElementById(id).textContent = "";
  }

  function updateReady() {
    submit().disabled = busy || !target().value.trim() || !consent().checked;
  }

  document.addEventListener("click", event => {
    const action = event.target.closest ? event.target.closest("[data-action]") : null;
    if (action && action.dataset.action === "open-ssllabs-authorized") {
      event.preventDefault();
      clearOutput();
      consent().checked = false;
      updateReady();
      showModal(modalId, true);
      return;
    }
    const close = event.target.closest ? event.target.closest("[data-close]") : null;
    if ((close && close.dataset.close === modalId) || event.target.id === modalId) {
      event.preventDefault();
      consent().checked = false;
      clearOutput();
      updateReady();
      showModal(modalId, false);
    }
  });

  document.addEventListener("input", event => {
    if (event.target.id !== "ssllabs-authorized-target") return;
    consent().checked = false;
    clearOutput();
    updateReady();
  });

  document.addEventListener("change", event => {
    if (event.target.id === "ssllabs-authorized-confirm") updateReady();
  });

  document.addEventListener("submit", async event => {
    if (event.target.id !== "ssllabs-authorized-form") return;
    event.preventDefault();
    const requestedTarget = target().value.trim();
    if (busy || !requestedTarget || !consent().checked) return;
    busy = true;
    updateReady();
    clearOutput();
    try {
      const data = await api("/api/tool-runs/ssllabs-authorized", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({target: requestedTarget, confirm_authorized: true}),
      });
      const receipt = data && data.authorization_receipt;
      if (!data || data.format !== "ssllabs-v4-host" ||
          !["DNS", "ERROR", "IN_PROGRESS", "READY"].includes(data.assessment_status) ||
          !Number.isSafeInteger(data.endpoint_count) || data.endpoint_count < 0 ||
          typeof data.report_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(data.report_sha256) ||
          !receipt || receipt.consent_version !== "ssllabs-third-party-authorization-v1" ||
          receipt.confirm_authorized !== true || receipt.third_party !== "Qualys SSL Labs" ||
          typeof receipt.normalized_target !== "string" || typeof receipt.confirmed_at !== "string") {
        throw new Error("Geçersiz SSL Labs yanıtı.");
      }
      document.getElementById("ssllabs-authorized-status").textContent = data.assessment_status;
      document.getElementById("ssllabs-authorized-endpoint-count").textContent = String(data.endpoint_count);
      document.getElementById("ssllabs-authorized-confirmed-at").textContent = receipt.confirmed_at;
      document.getElementById("ssllabs-authorized-report-sha256").textContent = data.report_sha256;
      result().classList.remove("hidden");
      consent().checked = false;
    } catch (err) {
      error().textContent = err?.message || "SSL Labs değerlendirmesi tamamlanamadı.";
      error().classList.remove("hidden");
    } finally {
      busy = false;
      updateReady();
    }
  });
})();

(function initBurpAndWave6WorkbenchModal() {
  const modal = () => document.getElementById("burp-workbench-modal");
  const form = () => document.getElementById("burp-workbench-form");
  const toolSelect = () => document.getElementById("burp-workbench-tool");
  const payloadInput = () => document.getElementById("burp-workbench-payload");
  const submitBtn = () => document.getElementById("burp-workbench-submit");
  const errorEl = () => document.getElementById("burp-workbench-error");
  const resultEl = () => document.getElementById("burp-workbench-result");
  const formatEl = () => document.getElementById("burp-workbench-format");
  const verdictEl = () => document.getElementById("burp-workbench-verdict");
  const outputEl = () => document.getElementById("burp-workbench-output");

  document.addEventListener("click", (ev) => {
    const trigger = ev.target && ev.target.closest ? ev.target.closest('[data-action="open-burp-workbench"]') : null;
    if (trigger && modal()) {
      modal().classList.remove("hidden");
    }
    const closer = ev.target && ev.target.closest ? ev.target.closest('[data-close="burp-workbench-modal"]') : null;
    if (closer && modal()) {
      modal().classList.add("hidden");
    }
  });

  const workbenchForm = form();
  if (!workbenchForm || typeof workbenchForm.addEventListener !== "function") return;
  workbenchForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (errorEl()) {
      errorEl().textContent = "";
      errorEl().classList.add("hidden");
    }
    if (resultEl()) {
      resultEl().classList.add("hidden");
    }
    const endpoint = toolSelect() ? String(toolSelect().value || "").trim() : "";
    const rawJson = payloadInput() ? String(payloadInput().value || "").trim() : "";
    if (!endpoint.startsWith("/api/")) {
      if (errorEl()) {
        errorEl().textContent = "Geçersiz analiz uç noktası.";
        errorEl().classList.remove("hidden");
      }
      return;
    }
    let parsedPayload = {};
    try {
      parsedPayload = rawJson ? JSON.parse(rawJson) : {};
    } catch (_err) {
      if (errorEl()) {
        errorEl().textContent = "Geçerli bir JSON nesnesi girin.";
        errorEl().classList.remove("hidden");
      }
      return;
    }
    if (submitBtn()) submitBtn().disabled = true;
    try {
      const data = await api(endpoint, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(parsedPayload),
      });
      if (formatEl()) formatEl().textContent = String((data && data.format) || "sniper-workbench/1");
      if (verdictEl()) {
        const verdict = (data && (data.submission_verdict || data.satisfiability || data.entropy_verdict || data.finding_count)) ?? "OK";
        verdictEl().textContent = String(verdict);
      }
      if (outputEl()) outputEl().textContent = JSON.stringify(data, null, 2);
      if (resultEl()) resultEl().classList.remove("hidden");
    } catch (err) {
      if (errorEl()) {
        errorEl().textContent = err?.message || "Analiz isteği tamamlanamadı.";
        errorEl().classList.remove("hidden");
      }
    } finally {
      if (submitBtn()) submitBtn().disabled = false;
    }
  });
})();


