import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const appSource = fs.readFileSync(path.join(rootDir, "static", "app.js"), "utf8");
const junitSource = fs.readFileSync(path.join(rootDir, "static", "schemathesis_junit_preview.js"), "utf8");
const siemSource = fs.readFileSync(path.join(rootDir, "static", "siem_ecs_preview.js"), "utf8");

function classList(initial = []) {
  const set = new Set(initial);
  return {
    add: (...names) => names.forEach(name => set.add(name)),
    remove: (...names) => names.forEach(name => set.delete(name)),
    toggle(name, force) {
      if (force === undefined) {
        if (set.has(name)) set.delete(name);
        else set.add(name);
      } else if (force) {
        set.add(name);
      } else {
        set.delete(name);
      }
    },
    contains: name => set.has(name),
  };
}

function createHarness() {
  const elements = new Map();
  const docListeners = new Map();
  const fetchCalls = [];
  let documentRef = null;

  function node(tag = "div", id = "", initialClasses = []) {
    const listeners = new Map();
    const attrs = new Map();
    const el = {
      tagName: tag.toUpperCase(),
      id,
      value: "",
      files: [],
      textContent: "",
      innerHTML: "",
      disabled: false,
      checked: false,
      hidden: false,
      inert: false,
      isConnected: true,
      style: { zIndex: "" },
      dataset: {},
      classList: classList(initialClasses),
      children: [],
      parentElement: null,
      addEventListener(type, fn, options) {
        const list = listeners.get(type) || [];
        list.push({ fn, capture: Boolean(options === true || options?.capture) });
        listeners.set(type, list);
      },
      dispatchEvent(event) {
        for (const entry of listeners.get(event.type) || []) {
          entry.fn.call(el, event);
        }
      },
      setAttribute(name, val) {
        attrs.set(name, String(val));
      },
      getAttribute(name) {
        return attrs.get(name) ?? null;
      },
      hasAttribute(name) {
        return attrs.has(name);
      },
      removeAttribute(name) {
        attrs.delete(name);
      },
      getClientRects() {
        if (el.hidden || el.classList.contains("hidden")) return [];
        return [{ width: 100, height: 24 }];
      },
      focus() {
        if (documentRef) documentRef.activeElement = el;
      },
      append(child) {
        if (child && typeof child === "object") {
          child.parentElement = el;
          el.children.push(child);
        }
      },
      remove() {},
      reset() {},
      contains(target) {
        if (!target) return false;
        if (target === el) return true;
        let cur = target.parentElement;
        while (cur) {
          if (cur === el) return true;
          cur = cur.parentElement;
        }
        return false;
      },
      querySelector(selector) {
        if (selector === 'button[type="submit"]') return el.submitButton || (el.submitButton = node("button"));
        return elements.get(selector) || node();
      },
      querySelectorAll(selector) {
        if (selector.includes("button")) {
          return el.focusableControls || [];
        }
        return [];
      },
      closest(selector) {
        if (selector === ".hidden,[hidden],[aria-hidden=\"true\"]") {
          let cur = el;
          while (cur) {
            if (cur.hidden || cur.classList?.contains?.("hidden")) return cur;
            cur = cur.parentElement;
          }
          return null;
        }
        if (selector === ".modal-backdrop,.drawer-backdrop,.workspace-backdrop") {
          let cur = el;
          while (cur) {
            if (cur.classList?.contains?.("modal-backdrop")) return cur;
            cur = cur.parentElement;
          }
          return null;
        }
        if (el.closestMap && selector in el.closestMap) {
          return el.closestMap[selector];
        }
        return null;
      },
    };
    return el;
  }

  function register(id, el) {
    el.id = id;
    elements.set(`#${id}`, el);
    return el;
  }

  // Build Schemathesis JUnit modal DOM
  const junitModal = register("schemathesis-junit-preview-modal", node("div", "schemathesis-junit-preview-modal", ["modal-backdrop", "hidden"]));
  const junitForm = register("schemathesis-junit-preview-form", node("form", "schemathesis-junit-preview-form"));
  const junitSubmit = node("button", "schemathesis-junit-submit");
  junitForm.submitButton = junitSubmit;
  const junitPaste = register("schemathesis-junit-paste", node("textarea", "schemathesis-junit-paste"));
  const junitFile = register("schemathesis-junit-file", node("input", "schemathesis-junit-file"));
  const junitError = register("schemathesis-junit-preview-error", node("div", "schemathesis-junit-preview-error", ["hidden"]));
  const junitResult = register("schemathesis-junit-preview-result", node("div", "schemathesis-junit-preview-result", ["hidden"]));
  const junitCopyBtn = register("schemathesis-junit-copy-sha256", node("button", "schemathesis-junit-copy-sha256", ["hidden"]));
  junitCopyBtn.textContent = "SHA-256 kopyala";
  junitCopyBtn.disabled = true;
  junitCopyBtn.hidden = true;
  const junitCopyStatus = register("schemathesis-junit-copy-status", node("span", "schemathesis-junit-copy-status", ["hidden"]));
  junitCopyStatus.hidden = true;
  const junitSuiteCount = register("schemathesis-junit-suite-count", node("strong", "schemathesis-junit-suite-count"));
  const junitTestcaseCount = register("schemathesis-junit-testcase-count", node("strong", "schemathesis-junit-testcase-count"));
  const junitOutcomes = register("schemathesis-junit-outcomes", node("strong", "schemathesis-junit-outcomes"));
  const junitSha = register("schemathesis-junit-report-sha256", node("code", "schemathesis-junit-report-sha256"));
  [junitForm, junitSubmit, junitPaste, junitFile, junitError, junitResult, junitCopyBtn, junitCopyStatus].forEach(ch => junitModal.append(ch));
  junitModal.focusableControls = [junitPaste, junitSubmit];

  // Build SIEM ECS modal DOM
  const siemModal = register("siem-ecs-preview-modal", node("div", "siem-ecs-preview-modal", ["modal-backdrop", "hidden"]));
  const siemForm = register("siem-ecs-preview-form", node("form", "siem-ecs-preview-form"));
  const siemSubmit = node("button", "siem-ecs-submit");
  siemForm.submitButton = siemSubmit;
  const siemPaste = register("siem-ecs-paste", node("textarea", "siem-ecs-paste"));
  const siemFile = register("siem-ecs-file", node("input", "siem-ecs-file"));
  const siemError = register("siem-ecs-preview-error", node("div", "siem-ecs-preview-error", ["hidden"]));
  const siemResult = register("siem-ecs-preview-result", node("div", "siem-ecs-preview-result", ["hidden"]));
  const siemRecordCount = register("siem-ecs-record-count", node("strong", "siem-ecs-record-count"));
  const siemKindCounts = register("siem-ecs-kind-counts", node("strong", "siem-ecs-kind-counts"));
  const siemSha = register("siem-ecs-report-sha256", node("code", "siem-ecs-report-sha256"));
  [siemForm, siemSubmit, siemPaste, siemFile, siemError, siemResult].forEach(ch => siemModal.append(ch));
  siemModal.focusableControls = [siemPaste, siemSubmit];

  // Stacked top modal for top-layer Escape test
  const stackedTopModal = register("target-modal", node("div", "target-modal", ["modal-backdrop", "hidden"]));
  const stackedTopInput = node("input", "target-name");
  stackedTopModal.append(stackedTopInput);
  stackedTopModal.focusableControls = [stackedTopInput];

  const mainEl = node("main", "main");
  elements.set(".main", mainEl);
  const sidebarEl = node("aside", "sidebar");
  elements.set(".sidebar", sidebarEl);
  const toastRegion = register("toast-region", node("div", "toast-region"));

  let routeHandler = async path => {
    if (path === "/api/dashboard") return {};
    if (path === "/api/targets") return { targets: [] };
    if (path === "/api/scans?limit=200") return { scans: [] };
    if (path === "/api/engagements") return { engagements: [] };
    if (path === "/api/lab-runs") return { lab_runs: [] };
    if (path === "/api/project-audits") return { project_audits: [], total: 0 };
    if (path === "/api/tooling") return { tools: [] };
    if (path === "/api/tooling/readiness") return { tools: [] };
    if (path === "/api/dependency-security") return {};
    return {};
  };

  const document = {
    body: {
      style: { overflow: "" },
      children: [mainEl, toastRegion, junitModal, siemModal, stackedTopModal],
    },
    activeElement: mainEl,
    querySelector(selector) {
      if (!elements.has(selector)) {
        const created = node("div", selector.startsWith("#") ? selector.slice(1) : "");
        elements.set(selector, created);
      }
      return elements.get(selector);
    },
    querySelectorAll(selector) {
      if (selector.includes("a[href],button:not([disabled])")) {
        return [];
      }
      return [];
    },
    getElementById(id) {
      return this.querySelector(`#${id}`);
    },
    createElement(tag) {
      return node(tag);
    },
    addEventListener(type, fn, options) {
      const list = docListeners.get(type) || [];
      list.push({ fn, capture: Boolean(options === true || options?.capture) });
      docListeners.set(type, list);
    },
  };
  documentRef = document;

  function dispatchDocEvent(type, init = {}) {
    const list = docListeners.get(type) || [];
    const ordered = [
      ...list.filter(item => item.capture),
      ...list.filter(item => !item.capture),
    ];
    let immediateStopped = false;
    let propagationStopped = false;
    const event = {
      type,
      key: init.key || "",
      shiftKey: Boolean(init.shiftKey),
      target: init.target || document.activeElement || document.body,
      defaultPrevented: false,
      preventDefault() {
        this.defaultPrevented = true;
      },
      stopPropagation() {
        propagationStopped = true;
      },
      stopImmediatePropagation() {
        immediateStopped = true;
        propagationStopped = true;
      },
    };
    const promises = [];
    for (const entry of ordered) {
      if (immediateStopped) break;
      promises.push(Promise.resolve(entry.fn(event)));
    }
    return Promise.all(promises).then(() => ({ event, immediateStopped, propagationStopped }));
  }

  const context = {
    window: {
      addEventListener() {},
    },
    document,
    location: { hash: "#reports" },
    history: { replaceState() {} },
    navigator: {
      clipboard: {
        async writeText() {},
      },
    },
    Intl,
    TextEncoder,
    URLSearchParams,
    console,
    setTimeout: () => 1,
    clearTimeout() {},
    setInterval: () => 1,
    clearInterval() {},
    fetch: async (url, options = {}) => {
      fetchCalls.push({ url, options });
      const result = await routeHandler(url, options);
      if (result && result.__httpError) {
        return {
          ok: false,
          status: result.status || 400,
          async json() {
            return result.body || { error: "bad_request" };
          },
        };
      }
      return {
        ok: true,
        status: 200,
        async json() {
          return result;
        },
      };
    },
  };
  context.window.document = document;
  context.window.navigator = context.navigator;
  context.globalThis = context;
  document.defaultView = context.window;

  vm.runInNewContext(appSource, context, { filename: "static/app.js" });
  vm.runInNewContext(junitSource, context, { filename: "static/schemathesis_junit_preview.js" });
  vm.runInNewContext(siemSource, context, { filename: "static/siem_ecs_preview.js" });

  function makeOpener(action, parent = mainEl) {
    const btn = node("button");
    btn.parentElement = parent;
    btn.closestMap = {
      [`[data-action="${action}"]`]: btn,
      "button,a,[data-action]": btn,
    };
    return btn;
  }

  function makeCloseBtn(modalId, parent) {
    const btn = node("button");
    btn.parentElement = parent;
    btn.closestMap = {
      [`[data-close="${modalId}"]`]: btn,
      "button,a,[data-action]": btn,
    };
    return btn;
  }

  return {
    context,
    document,
    elements,
    fetchCalls,
    setRouteHandler(fn) {
      routeHandler = fn;
    },
    dispatchDocEvent,
    openJunitBtn: makeOpener("open-schemathesis-junit-preview"),
    closeJunitBtn: makeCloseBtn("schemathesis-junit-preview-modal", junitModal),
    openSiemBtn: makeOpener("open-siem-ecs-preview"),
    closeSiemBtn: makeCloseBtn("siem-ecs-preview-modal", siemModal),
    junitModal,
    junitForm,
    junitSubmit,
    junitPaste,
    junitFile,
    junitError,
    junitResult,
    junitCopyBtn,
    junitCopyStatus,
    junitSuiteCount,
    junitTestcaseCount,
    junitOutcomes,
    junitSha,
    siemModal,
    siemForm,
    siemSubmit,
    siemPaste,
    siemFile,
    siemError,
    siemResult,
    siemRecordCount,
    siemKindCounts,
    siemSha,
    stackedTopModal,
    stackedTopInput,
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function flushMicrotasks(turns = 6) {
  for (let i = 0; i < turns; i += 1) {
    await Promise.resolve();
  }
}

const VALID_JUNIT_SUMMARY_A = {
  format: "schemathesis-junit-xml",
  suite_count: 1,
  testcase_count: 3,
  outcome_counts: { passed: 2, failed: 1, errors: 0, skipped: 0 },
  report_sha256: "a".repeat(64),
};

const VALID_JUNIT_SUMMARY_B = {
  format: "schemathesis-junit-xml",
  suite_count: 2,
  testcase_count: 4,
  outcome_counts: { passed: 4, failed: 0, errors: 0, skipped: 0 },
  report_sha256: "b".repeat(64),
};

const VALID_SIEM_SUMMARY_A = {
  format: "ecs-ndjson",
  record_count: 2,
  kind_counts: {
    alert: 1,
    asset: 0,
    enrichment: 0,
    event: 1,
    metric: 0,
    state: 0,
    pipeline_error: 0,
    signal: 0,
  },
  report_sha256: "c".repeat(64),
};

const VALID_SIEM_SUMMARY_B = {
  format: "ecs-ndjson",
  record_count: 3,
  kind_counts: {
    alert: 0,
    asset: 1,
    enrichment: 0,
    event: 1,
    metric: 0,
    state: 0,
    pipeline_error: 0,
    signal: 1,
  },
  report_sha256: "d".repeat(64),
};

const mode = process.argv[2] || "all";

async function testNormalAndClickCloseControls() {
  const h = createHarness();
  await flushMicrotasks();
  h.fetchCalls.length = 0;

  h.setRouteHandler(async (url, options) => {
    if (url === "/api/tool-reports/schemathesis-junit/summary") {
      return VALID_JUNIT_SUMMARY_A;
    }
    if (url === "/api/tool-reports/siem-ecs-ndjson/summary") {
      return VALID_SIEM_SUMMARY_A;
    }
    return {};
  });

  // 1. Schemathesis normal submit -> single POST -> summary rendered -> click close clears
  await h.dispatchDocEvent("click", { target: h.openJunitBtn });
  assert.equal(h.junitModal.classList.contains("hidden"), false);

  h.junitPaste.value = "<testsuite tests=\"3\"></testsuite>";
  await h.dispatchDocEvent("submit", { target: h.junitForm });
  await flushMicrotasks();

  const junitPosts = h.fetchCalls.filter(c => c.url === "/api/tool-reports/schemathesis-junit/summary");
  assert.equal(junitPosts.length, 1);
  assert.equal(h.junitResult.classList.contains("hidden"), false);
  assert.equal(h.junitSuiteCount.textContent, "1");
  assert.equal(h.junitTestcaseCount.textContent, "3");
  assert.equal(h.junitSha.textContent, "a".repeat(64));
  assert.equal(h.junitCopyBtn.disabled, false);
  assert.equal(h.junitCopyBtn.classList.contains("hidden"), false);

  await h.dispatchDocEvent("click", { target: h.closeJunitBtn });
  assert.equal(h.junitModal.classList.contains("hidden"), true);
  assert.equal(h.junitResult.classList.contains("hidden"), true);
  assert.equal(h.junitSha.textContent, "");
  assert.equal(h.junitCopyBtn.disabled, true);

  // 2. SIEM normal submit -> single POST -> summary rendered -> click close clears
  await h.dispatchDocEvent("click", { target: h.openSiemBtn });
  assert.equal(h.siemModal.classList.contains("hidden"), false);

  h.siemPaste.value = '{"@timestamp":"2026-03-31T10:00:00Z","event":{"kind":"event"}}\n';
  await h.dispatchDocEvent("submit", { target: h.siemForm });
  await flushMicrotasks();

  const siemPosts = h.fetchCalls.filter(c => c.url === "/api/tool-reports/siem-ecs-ndjson/summary");
  assert.equal(siemPosts.length, 1);
  assert.equal(h.siemResult.classList.contains("hidden"), false);
  assert.equal(h.siemRecordCount.textContent, "2");
  assert.equal(h.siemSha.textContent, "c".repeat(64));

  await h.dispatchDocEvent("click", { target: h.closeSiemBtn });
  assert.equal(h.siemModal.classList.contains("hidden"), true);
  assert.equal(h.siemResult.classList.contains("hidden"), true);
  assert.equal(h.siemSha.textContent, "");
}

async function testSchemathesisEscapeLifecycle() {
  const h = createHarness();
  await flushMicrotasks();
  h.fetchCalls.length = 0;

  // Case A: Escape clears populated result, copy state, paste/file inputs, and error
  h.setRouteHandler(async url => {
    if (url === "/api/tool-reports/schemathesis-junit/summary") return VALID_JUNIT_SUMMARY_A;
    return {};
  });
  await h.dispatchDocEvent("click", { target: h.openJunitBtn });
  h.junitPaste.value = "<testsuite tests=\"3\"></testsuite>";
  await h.dispatchDocEvent("submit", { target: h.junitForm });
  await flushMicrotasks();

  assert.equal(h.junitResult.classList.contains("hidden"), false);
  assert.equal(h.junitCopyBtn.disabled, false);

  // User also drafts new paste/file before hitting Escape
  h.junitPaste.value = "<testsuite name=\"draft\"></testsuite>";
  h.junitFile.value = "C:\\fakepath\\draft.xml";
  h.junitFile.files = [{ size: 120, async text() { return "<testsuite/>"; } }];

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.junitPaste });
  assert.equal(h.junitModal.classList.contains("hidden"), true);
  assert.equal(h.junitPaste.value, "");
  assert.equal(h.junitFile.value, "");
  assert.equal(h.junitFile.files.length, 0);
  assert.equal(h.junitResult.classList.contains("hidden"), true);
  assert.equal(h.junitError.classList.contains("hidden"), true);
  assert.equal(h.junitSuiteCount.textContent, "");
  assert.equal(h.junitTestcaseCount.textContent, "");
  assert.equal(h.junitOutcomes.textContent, "");
  assert.equal(h.junitSha.textContent, "");
  assert.equal(h.junitCopyBtn.disabled, true);
  assert.equal(h.junitCopyBtn.hidden, true);
  assert.equal(h.junitCopyBtn.classList.contains("hidden"), true);
  assert.equal(h.junitCopyStatus.textContent, "");
  assert.equal(h.junitCopyStatus.hidden, true);

  // Case B: Escape during pending file.text() prevents POST and suppresses late file resolution
  const pendingFileRead = deferred();
  await h.dispatchDocEvent("click", { target: h.openJunitBtn });
  h.fetchCalls.length = 0;
  h.junitFile.value = "C:\\fakepath\\slow.xml";
  h.junitFile.files = [{ size: 256, text: () => pendingFileRead.promise }];

  const fileSubmitPromise = h.dispatchDocEvent("submit", { target: h.junitForm });
  await flushMicrotasks(2);
  assert.equal(h.junitSubmit.disabled, true);

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.junitFile });
  assert.equal(h.junitModal.classList.contains("hidden"), true);
  assert.equal(h.junitSubmit.disabled, false);
  assert.equal(h.junitFile.value, "");

  pendingFileRead.resolve("<testsuite tests=\"1\"><testcase name=\"a\"/></testsuite>");
  await fileSubmitPromise;
  await flushMicrotasks();

  assert.equal(h.fetchCalls.filter(c => c.url === "/api/tool-reports/schemathesis-junit/summary").length, 0);
  assert.equal(h.junitResult.classList.contains("hidden"), true);
  assert.equal(h.junitError.classList.contains("hidden"), true);

  // Case C: Escape during pending summary POST ignores late success and late error on closed or reopened modal,
  // and allows a fresh submission B to succeed cleanly
  const pendingPostA = deferred();
  const pendingPostB = deferred();
  let callIndex = 0;
  h.setRouteHandler(async url => {
    if (url === "/api/tool-reports/schemathesis-junit/summary") {
      callIndex += 1;
      return callIndex === 1 ? pendingPostA.promise : pendingPostB.promise;
    }
    return {};
  });

  await h.dispatchDocEvent("click", { target: h.openJunitBtn });
  h.junitPaste.value = "<testsuite name=\"A\"></testsuite>";
  const submitAPromise = h.dispatchDocEvent("submit", { target: h.junitForm });
  await flushMicrotasks(2);
  assert.equal(h.junitSubmit.disabled, true);

  // Press Escape while POST A is in flight
  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.junitForm });
  assert.equal(h.junitModal.classList.contains("hidden"), true);
  assert.equal(h.junitSubmit.disabled, false);

  // Reopen modal and start submission B before POST A resolves
  await h.dispatchDocEvent("click", { target: h.openJunitBtn });
  assert.equal(h.junitModal.classList.contains("hidden"), false);
  h.junitPaste.value = "<testsuite name=\"B\"></testsuite>";
  const submitBPromise = h.dispatchDocEvent("submit", { target: h.junitForm });
  await flushMicrotasks(2);

  // Stale POST A resolves first: must NOT overwrite B or populate A's digest
  pendingPostA.resolve(VALID_JUNIT_SUMMARY_A);
  await submitAPromise;
  await flushMicrotasks();
  assert.equal(h.junitResult.classList.contains("hidden"), true);
  assert.equal(h.junitSha.textContent, "");

  // Fresh POST B resolves: must populate B's summary
  pendingPostB.resolve(VALID_JUNIT_SUMMARY_B);
  await submitBPromise;
  await flushMicrotasks();
  assert.equal(h.junitResult.classList.contains("hidden"), false);
  assert.equal(h.junitSuiteCount.textContent, "2");
  assert.equal(h.junitTestcaseCount.textContent, "4");
  assert.equal(h.junitSha.textContent, "b".repeat(64));

  // Case D: Stacked modal on top of Schemathesis modal — Escape closes ONLY the top modal
  h.context.showModal("target-modal", true);
  assert.equal(h.stackedTopModal.classList.contains("hidden"), false);
  assert.equal(h.junitModal.classList.contains("hidden"), false);

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.stackedTopInput });
  assert.equal(h.stackedTopModal.classList.contains("hidden"), true);
  assert.equal(h.junitModal.classList.contains("hidden"), false);
  assert.equal(h.junitResult.classList.contains("hidden"), false);
  assert.equal(h.junitSha.textContent, "b".repeat(64));

  // Second Escape closes Schemathesis modal and clears its state
  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.junitPaste });
  assert.equal(h.junitModal.classList.contains("hidden"), true);
  assert.equal(h.junitResult.classList.contains("hidden"), true);
  assert.equal(h.junitSha.textContent, "");
}

async function testSiemEcsEscapeLifecycle() {
  const h = createHarness();
  await flushMicrotasks();
  h.fetchCalls.length = 0;

  // Case A: Escape clears populated result, paste/file inputs, and error
  h.setRouteHandler(async url => {
    if (url === "/api/tool-reports/siem-ecs-ndjson/summary") return VALID_SIEM_SUMMARY_A;
    return {};
  });
  await h.dispatchDocEvent("click", { target: h.openSiemBtn });
  h.siemPaste.value = '{"@timestamp":"2026-03-31T10:00:00Z","event":{"kind":"event"}}\n';
  await h.dispatchDocEvent("submit", { target: h.siemForm });
  await flushMicrotasks();

  assert.equal(h.siemResult.classList.contains("hidden"), false);
  assert.equal(h.siemRecordCount.textContent, "2");
  assert.equal(h.siemSha.textContent, "c".repeat(64));

  h.siemPaste.value = '{"@timestamp":"2026-03-31T10:01:00Z","event":{"kind":"alert"}}\n';
  h.siemFile.value = "C:\\fakepath\\draft.ndjson";
  h.siemFile.files = [{ size: 100, async text() { return "{}"; } }];

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.siemPaste });
  assert.equal(h.siemModal.classList.contains("hidden"), true);
  assert.equal(h.siemPaste.value, "");
  assert.equal(h.siemFile.value, "");
  assert.equal(h.siemFile.files.length, 0);
  assert.equal(h.siemResult.classList.contains("hidden"), true);
  assert.equal(h.siemError.classList.contains("hidden"), true);
  assert.equal(h.siemRecordCount.textContent, "");
  assert.equal(h.siemKindCounts.textContent, "");
  assert.equal(h.siemSha.textContent, "");

  // Case B: Escape during pending file.text() prevents POST and suppresses late file resolution
  const pendingFileRead = deferred();
  await h.dispatchDocEvent("click", { target: h.openSiemBtn });
  h.fetchCalls.length = 0;
  h.siemFile.value = "C:\\fakepath\\slow.ndjson";
  h.siemFile.files = [{ size: 256, text: () => pendingFileRead.promise }];

  const fileSubmitPromise = h.dispatchDocEvent("submit", { target: h.siemForm });
  await flushMicrotasks(2);
  assert.equal(h.siemSubmit.disabled, true);

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.siemFile });
  assert.equal(h.siemModal.classList.contains("hidden"), true);
  assert.equal(h.siemSubmit.disabled, false);
  assert.equal(h.siemFile.value, "");

  pendingFileRead.resolve('{"@timestamp":"2026-03-31T10:00:00Z","event":{"kind":"event"}}\n');
  await fileSubmitPromise;
  await flushMicrotasks();

  assert.equal(h.fetchCalls.filter(c => c.url === "/api/tool-reports/siem-ecs-ndjson/summary").length, 0);
  assert.equal(h.siemResult.classList.contains("hidden"), true);
  assert.equal(h.siemError.classList.contains("hidden"), true);

  // Case C: Escape during pending summary POST ignores late response and allows fresh submission B
  const pendingPostA = deferred();
  const pendingPostB = deferred();
  let callIndex = 0;
  h.setRouteHandler(async url => {
    if (url === "/api/tool-reports/siem-ecs-ndjson/summary") {
      callIndex += 1;
      return callIndex === 1 ? pendingPostA.promise : pendingPostB.promise;
    }
    return {};
  });

  await h.dispatchDocEvent("click", { target: h.openSiemBtn });
  h.siemPaste.value = '{"@timestamp":"2026-03-31T10:00:00Z","event":{"kind":"event"}}\n';
  const submitAPromise = h.dispatchDocEvent("submit", { target: h.siemForm });
  await flushMicrotasks(2);
  assert.equal(h.siemSubmit.disabled, true);

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.siemForm });
  assert.equal(h.siemModal.classList.contains("hidden"), true);
  assert.equal(h.siemSubmit.disabled, false);

  await h.dispatchDocEvent("click", { target: h.openSiemBtn });
  assert.equal(h.siemModal.classList.contains("hidden"), false);
  h.siemPaste.value = '{"@timestamp":"2026-03-31T10:02:00Z","event":{"kind":"signal"}}\n';
  const submitBPromise = h.dispatchDocEvent("submit", { target: h.siemForm });
  await flushMicrotasks(2);

  pendingPostA.resolve(VALID_SIEM_SUMMARY_A);
  await submitAPromise;
  await flushMicrotasks();
  assert.equal(h.siemResult.classList.contains("hidden"), true);
  assert.equal(h.siemSha.textContent, "");

  pendingPostB.resolve(VALID_SIEM_SUMMARY_B);
  await submitBPromise;
  await flushMicrotasks();
  assert.equal(h.siemResult.classList.contains("hidden"), false);
  assert.equal(h.siemRecordCount.textContent, "3");
  assert.equal(h.siemSha.textContent, "d".repeat(64));

  // Case D: Stacked modal on top of SIEM modal — Escape closes ONLY the top modal
  h.context.showModal("target-modal", true);
  assert.equal(h.stackedTopModal.classList.contains("hidden"), false);
  assert.equal(h.siemModal.classList.contains("hidden"), false);

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.stackedTopInput });
  assert.equal(h.stackedTopModal.classList.contains("hidden"), true);
  assert.equal(h.siemModal.classList.contains("hidden"), false);
  assert.equal(h.siemResult.classList.contains("hidden"), false);
  assert.equal(h.siemSha.textContent, "d".repeat(64));

  await h.dispatchDocEvent("keydown", { key: "Escape", target: h.siemPaste });
  assert.equal(h.siemModal.classList.contains("hidden"), true);
  assert.equal(h.siemResult.classList.contains("hidden"), true);
  assert.equal(h.siemSha.textContent, "");
}

if (mode === "control") {
  await testNormalAndClickCloseControls();
  console.log("control: PASS");
} else if (mode === "escape") {
  await testSchemathesisEscapeLifecycle();
  await testSiemEcsEscapeLifecycle();
  console.log("escape: PASS");
} else {
  await testNormalAndClickCloseControls();
  await testSchemathesisEscapeLifecycle();
  await testSiemEcsEscapeLifecycle();
  console.log("test_saved_preview_escape_junit_siem: ok");
}
