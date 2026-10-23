/* Sniper arayüz dil katmanı (Türkçe kaynak → seçilen dil).
 *
 * Yaklaşım: arayüz metinleri Türkçe yazılmaya devam eder; bu katman Türkçe kaynak metni anahtar alan
 * TSV dil paketleriyle (proje analizörü .json içeriğini kural metni olarak taradığından düz metin) görünür metin düğümlerini ve placeholder/title/aria-label/alt/value
 * özniteliklerini çevirir. Panelleri üreten betiklere dokunmadan yeni kartları da yakalamak için
 * MutationObserver kullanılır. Çeviri yalnız nodeValue/setAttribute ile yapılır (innerHTML asla).
 * Değer içeren iletiler için sözlükteki "{0}" yer tutuculu kalıplar düzenli ifadeye çevrilir.
 * İngilizce temel/fallback pakettir; ja/ko/zh-CN paketlerindeki yerelleştirilmiş girdiler onun üzerine yazılır.
 * Eksik bir yerel çeviri İngilizce girdisi varsa ona düşer; o da yoksa özgün Türkçe kaynak korunur.
 * Özgün metin her düğüm için saklanır; Türkçeye dönüşte sayfa yenilenmeden geri yazılır.
 * Kod, kaynak, kanıt alanları (code, pre, textarea, kbd, samp, translate="no", data-i18n-skip) çevrilmez.
 */
(function (global) {
  "use strict";

  const STORE_KEY = "sniper.lang";
  const LANGS = ["tr", "en", "ja", "zh-CN", "ko"];
  const DICTIONARY_URLS = {
    en: "/i18n-en.tsv?v=1",
    ja: "/i18n-ja.tsv?v=1",
    "zh-CN": "/i18n-zh-CN.tsv?v=1",
    ko: "/i18n-ko.tsv?v=1",
  };
  const ATTRS = ["placeholder", "title", "aria-label", "alt"];
  const VALUE_INPUT_TYPES = new Set(["button", "submit", "reset"]);
  const SKIP_SELECTOR = "script,style,code,pre,textarea,kbd,samp,[translate='no'],[data-i18n-skip]";
  // Birleşik metinlerde sırayla denenen ayırıcılar (her biri tek başına; parçalar yine kendi içinde bölünebilir).
  const SEPARATORS = [": ", " · ", " — ", " → ", " | ", "; "];
  const BULLET = /^([•·—–\-*]\s+|\[[A-Za-z_]+\]\s+)(.+)$/;  // 22. tur: bildirimlerdeki küçük harfli [critical] önekleri de
  const CACHE_LIMIT = 5000;

  let lang = "tr";
  let dict = null;          // {strings: {tr: en}, patterns: [[tr, en]]}
  let compiled = [];        // [{prefix, suffix, re, out}]
  let fragments = [];       // [[tr, en]] uzunluğa göre azalan
  let observer = null;
  let selectionRevision = 0;
  const dictionaries = new Map();
  const loading = new Map();
  const cache = new Map();
  const textOrig = new WeakMap();   // Text → {src, out}
  const attrOrig = new WeakMap();   // Element → Map(attr → {src, out})
  const listeners = new Set();

  function normalizeLang(value) {
    const raw = String(value || "tr").trim().replace(/_/g, "-").toLowerCase();
    const aliases = {
      tr: "tr", "tr-tr": "tr", en: "en", "en-us": "en", "en-gb": "en",
      ja: "ja", "ja-jp": "ja", ko: "ko", "ko-kr": "ko",
      zh: "zh-CN", "zh-cn": "zh-CN", "zh-hans": "zh-CN", "zh-hans-cn": "zh-CN",
    };
    return aliases[raw] || "tr";
  }

  function readStoredLang() {
    try {
      const value = global.localStorage && global.localStorage.getItem(STORE_KEY);
      return LANGS.includes(normalizeLang(value)) ? normalizeLang(value) : "tr";
    } catch (_err) {
      return "tr";
    }
  }

  function storeLang(value) {
    try {
      if (global.localStorage) global.localStorage.setItem(STORE_KEY, value);
    } catch (_err) {
      /* özel pencere / engellenmiş depolama: seçim yalnız bu sayfada geçerli */
    }
  }

  function escapeRe(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // "Toplam {0} dosya" → /^Toplam (.+?) dosya$/ ; çıktıda {n} yakalanan değerle (gerekirse o da çevrilerek) doldurulur.
  function compilePattern(source, target) {
    source = normalize(source);
    const names = [];
    let literal = "";
    let body = "";
    const parts = source.split(/(\{\d+\})/);
    for (const part of parts) {
      const m = /^\{(\d+)\}$/.exec(part);
      if (m) {
        names.push(m[1]);
        body += "(@@)";
      } else {
        literal += part;
        body += escapeRe(part);
      }
    }
    // Kısa sabit metinli kalıplarda (ör. "{0} sn") yer tutucu yalnız sayısal değer alır; aşırı eşleşmeyi önler.
    const short = literal.replace(/[\s·:.,()/%-]/g, "").length < 4;
    const group = short ? "[-+\\d.,:%/ ]*?" : "[\\s\\S]*?";
    const re = new RegExp("^" + body.split("(@@)").join("(" + group + ")") + "$");
    const first = parts[0] || "";
    const last = parts[parts.length - 1] || "";
    return { prefix: /^\{\d+\}$/.test(first) ? "" : first, suffix: /^\{\d+\}$/.test(last) ? "" : last, re, names, out: target, weight: literal.length };
  }

  /** Sekmeyle ayrılmış sözlük: "S<TAB>tr<TAB>en" tam metin, "P<TAB>tr<TAB>en" yer tutuculu kalıp, "F<TAB>tr<TAB>en" kanıt parçası; # ile başlayan satır başlıktır. */
  function parseDictionary(text) {
    const data = { strings: {}, patterns: [], fragments: [] };
    for (const line of String(text).split("\n")) {
      if (!line || line.startsWith("#")) continue;
      const [kind, src, dst] = line.split("\t");
      if (!src || dst === undefined) continue;
      if (kind === "S") data.strings[src] = dst;
      else if (kind === "P") data.patterns.push([src, dst]);
      else if (kind === "F") data.fragments.push([src, dst]);
    }
    return data;
  }

  function activateDictionary(data) {
    if (typeof data === "string") data = parseDictionary(data);
    if (!data || typeof data !== "object" || !data.strings) throw new Error("i18n sözlüğü geçersiz");
    dict = { strings: Object.assign(Object.create(null), data.strings), patterns: Array.isArray(data.patterns) ? data.patterns : [] };
    compiled = dict.patterns.map(([src, dst]) => compilePattern(String(src), String(dst)))
      .sort((a, b) => b.weight - a.weight);
    fragments = (Array.isArray(data.fragments) ? data.fragments : []).map(([a, b]) => [String(a), String(b)])
      .sort((a, b) => b[0].length - a[0].length);
    cache.clear();
    keysCache = null;
  }

  function setDictionary(data, locale) {
    if (typeof data === "string") data = parseDictionary(data);
    if (locale) dictionaries.set(normalizeLang(locale), data);
    activateDictionary(data);
  }

  function mergeDictionaries(base, overlay) {
    const strings = Object.assign(Object.create(null), base.strings || {}, overlay.strings || {});
    const keyed = (rows) => new Map((rows || []).map(([src, dst]) => [src, dst]));
    const patterns = keyed(base.patterns);
    for (const [src, dst] of overlay.patterns || []) patterns.set(src, dst);
    const fragments = keyed(base.fragments);
    for (const [src, dst] of overlay.fragments || []) fragments.set(src, dst);
    return { strings, patterns: Array.from(patterns), fragments: Array.from(fragments) };
  }

  function normalize(text) {
    return text.replace(/\s+/g, " ").trim();
  }

  function lookupExact(core) {
    if (!dict) return null;
    const hit = dict.strings[core];
    if (typeof hit === "string") return hit;
    // Sondaki iki nokta / üç nokta farkını tolere et ("Durum:" ↔ "Durum").
    const m = /^(.*?)(\s*(?:[:…—–]|\.\.\.))$/.exec(core);
    if (m && m[1] && typeof dict.strings[m[1]] === "string") return dict.strings[m[1]] + m[2];
    return null;
  }

  function lookupPattern(core, depth) {
    for (const p of compiled) {
      if (p.prefix && !core.startsWith(p.prefix)) continue;
      if (p.suffix && !core.endsWith(p.suffix)) continue;
      const m = p.re.exec(core);
      if (!m) continue;
      const values = Object.create(null);
      p.names.forEach((name, i) => {
        const raw = m[i + 1];
        const value = normalize(raw);
        const inner = value && depth < 3 ? translateCore(value, depth + 1) : null;
        values[name] = inner == null ? raw : inner;
      });
      return p.out.replace(/\{(\d+)\}/g, (_all, n) => (n in values ? values[n] : ""));
    }
    return null;
  }

  // "Kullanıcı / istemci…" gibi kırpılmış etiketler: önekiyle başlayan tek sözlük girdisi varsa çevirisi aynı uzunlukta kırpılır.
  let keysCache = null;
  function lookupTruncated(core) {
    if (!core.endsWith("…") || core.length < 8) return null;
    const head = core.slice(0, -1);
    if (!keysCache) keysCache = Object.keys(dict.strings);
    const hits = keysCache.filter((k) => k.length > head.length && k.startsWith(head));
    if (hits.length !== 1) return null;
    const full = dict.strings[hits[0]];
    return full.length > head.length + 1 ? full.slice(0, Math.max(head.length, 6)).trimEnd() + "…" : full;
  }

  // Birden çok cümlenin tek düğümde birleştiği metinler: en uzun sözlük eşleşmesiyle cümle cümle (açgözlü) çevrilir.
  function translateSentences(core) {
    const sentences = core.split(/(?<=[.!?])\s+(?=[A-ZÇĞİÖŞÜ0-9"“(])/);
    if (sentences.length < 2) return null;
    const out = [];
    let i = 0;
    let changed = 0;
    while (i < sentences.length) {
      let taken = false;
      for (let j = sentences.length; j > i; j -= 1) {
        const hit = lookupExact(sentences.slice(i, j).join(" "));
        if (hit != null) { out.push(hit); i = j; changed += 1; taken = true; break; }
      }
      if (!taken) { out.push(sentences[i]); i += 1; }
    }
    return changed ? out.join(" ") : null;
  }

  // Türkçe yerel ayarla biçimlenmiş tarihler ("19 Eyl 2026 13:00", "1 Eylül 2026"): ay adı İngilizceye çevrilir.
  const MONTHS = { oca: "Jan", şub: "Feb", mar: "Mar", nis: "Apr", may: "May", haz: "Jun", tem: "Jul", ağu: "Aug", eyl: "Sep", eki: "Oct", kas: "Nov", ara: "Dec" };
  const MONTH_NUMBERS = { oca: 1, şub: 2, mar: 3, nis: 4, may: 5, haz: 6, tem: 7, ağu: 8, eyl: 9, eki: 10, kas: 11, ara: 12 };
  const DATE_TR = /^(\d{1,2})[ .](Oca|Şub|Mar|Nis|May|Haz|Tem|Ağu|Eyl|Eki|Kas|Ara)[a-zçğıöşü]*\.?[ ](\d{4})(.*)$/i;
  function translateDate(core) {
    const m = DATE_TR.exec(core);
    if (!m) return null;
    const monthKey = m[2].toLocaleLowerCase("tr");
    const month = MONTHS[monthKey];
    const monthNumber = MONTH_NUMBERS[monthKey];
    if (!month || !monthNumber) return null;
    if (lang === "ja" || lang === "zh-CN") return `${m[3]}年${monthNumber}月${m[1]}日${m[4]}`;
    if (lang === "ko") return `${m[3]}년 ${monthNumber}월 ${m[1]}일${m[4]}`;
    return `${m[1]} ${month} ${m[3]}${m[4]}`;
  }

  // "14 kritik, 19 yüksek, 2 düşük" gibi virgüllü listeler: YALNIZ her öğe çevrilebiliyorsa öğe öğe çevrilir (22. tur QA;
  // aksi hâlde "{0} düşük" kalıbı listenin tamamını yutup yalnız son öğeyi çeviriyordu).
  function translateCommaList(core, depth) {
    if (depth >= 3 || !core.includes(", ")) return null;
    const parts = core.split(", ");
    if (parts.length < 2) return null;
    const out = [];
    for (const raw of parts) {
      // Öğe yalnız tam eşleşme ya da kalıpla ve Türkçe harf kalmadan çevrilirse kabul edilir (kısmi çeviri sayılmaz).
      const part = raw.trim();
      const t = part ? (lookupExact(part) ?? lookupPattern(part, depth + 1)) : null;
      if (t == null || /[çğıöşüÇĞİÖŞÜ]/.test(t)) return null;
      out.push(t);
    }
    return out.join(", ");
  }

  function translateCore(core, depth) {
    let hit = lookupExact(core);
    if (hit == null) hit = translateCommaList(core, depth);
    if (hit == null) hit = lookupPattern(core, depth);
    if (hit == null) {
      const b = BULLET.exec(core);
      if (b) { const inner = translateCore(b[2], depth); if (inner != null) hit = b[1] + inner; }
    }
    if (hit == null) hit = lookupTruncated(core);
    if (hit == null) hit = translateDate(core);
    if (hit == null) hit = translateSentences(core);
    if (hit == null && depth < 3) {
      // "Önem: Yüksek · Dosya: x" gibi birleşik metinler: parçalar ayrı ayrı çevrilir; en çok parçayı çeviren ayırıcı seçilir.
      let best = null;
      let bestCount = 0;
      for (const sep of SEPARATORS) {
        if (!core.includes(sep)) continue;
        let count = 0;
        const out = core.split(sep).map((piece) => {
          const trimmed = piece.trim();
          const t = trimmed ? translateCore(trimmed, depth + 1) : null;
          if (t == null) return piece;
          count += 1;
          return piece.replace(trimmed, t);
        }).join(sep);
        if (count > bestCount) { best = out; bestCount = count; }
      }
      if (best != null) hit = best;
    }
    return hit;
  }

  // Serbest biçimli kanıt metinleri ("Veri akışı: kaynak (dosya satır N) → …"): sözlükle çevrilemeyen ya da
  // çeviri sonrası Türkçe kalan metinde yalnız sözlükteki ayırt edici parçalar (F satırları, en uzun önce) değiştirilir.
  const TR_CHARS = /[çğıöşüÇĞİÖŞÜ]/;
  function applyFragments(hit, core) {
    const base = hit == null ? core : hit;
    if (!fragments.length || !TR_CHARS.test(base)) return hit;
    let out = base;
    for (const [src, dst] of fragments) if (out.includes(src)) out = out.split(src).join(dst);
    return out === base ? hit : out;
  }

  /** Türkçe metni etkin dile çevirir; çeviri yoksa null döner. Baştaki/sondaki boşluk korunur. */
  function translateText(text) {
    if (lang === "tr" || !dict || typeof text !== "string") return null;
    const core = normalize(text);
    if (!core || !/[A-Za-zÇĞİÖŞÜçğıöşü]/.test(core)) return null;
    let hit;
    if (cache.has(core)) {
      hit = cache.get(core);
    } else {
      hit = applyFragments(translateCore(core, 0), core);
      if (cache.size > CACHE_LIMIT) cache.clear();
      cache.set(core, hit);
    }
    if (hit == null || hit === core) return null;
    const lead = /^\s*/.exec(text)[0];
    const trail = /\s*$/.exec(text)[0];
    return lead + hit + trail;
  }

  /** Sözlükte yoksa metni aynen döndürür (betiklerden doğrudan kullanım için). */
  function t(text) {
    const out = translateText(String(text));
    return out == null ? String(text) : out;
  }

  function skipped(el) {
    return !el || (el.closest && el.closest(SKIP_SELECTOR) !== null);
  }

  function applyText(node) {
    const parent = node.parentElement;
    if (!parent || skipped(parent)) return;
    const current = node.nodeValue;
    const rec = textOrig.get(node);
    const src = rec && current === rec.out ? rec.src : current;
    if (lang === "tr") {
      if (rec && current === rec.out && rec.out !== rec.src) node.nodeValue = rec.src;
      if (rec) textOrig.delete(node);
      return;
    }
    const out = translateText(src);
    if (out == null) {
      if (rec) textOrig.delete(node);
      return;
    }
    textOrig.set(node, { src, out });
    if (current !== out) node.nodeValue = out;
  }

  function attrNames(el) {
    const names = ATTRS.filter((a) => el.hasAttribute(a));
    if (el.tagName === "INPUT" && VALUE_INPUT_TYPES.has((el.getAttribute("type") || "").toLowerCase()) && el.hasAttribute("value")) names.push("value");
    return names;
  }

  function applyAttr(el, name) {
    if (skipped(el) && !(el.matches && el.matches("textarea"))) return;
    let map = attrOrig.get(el);
    const current = el.getAttribute(name);
    if (current == null) return;
    const rec = map && map.get(name);
    const src = rec && current === rec.out ? rec.src : current;
    if (lang === "tr") {
      if (rec && current === rec.out && rec.out !== rec.src) el.setAttribute(name, rec.src);
      if (rec) map.delete(name);
      return;
    }
    const out = translateText(src);
    if (out == null) {
      if (rec) map.delete(name);
      return;
    }
    if (!map) attrOrig.set(el, (map = new Map()));
    map.set(name, { src, out });
    if (current !== out) el.setAttribute(name, out);
  }

  // HTML rapor bağlantıları (/api/…/report.html, executive-summary.html) etkin dilde açılsın: ?lang=en eklenir/kaldırılır.
  const REPORT_HREF = /^\/api\/[^?#]+\.html(?:[?#]|$)/;
  function applyHref(el) {
    const href = el.getAttribute("href");
    if (!href || !REPORT_HREF.test(href)) return;
    const [base, hash = ""] = href.split("#");
    const [path, query = ""] = base.split("?");
    const params = query.split("&").filter((p) => p && !p.startsWith("lang="));
    if (lang !== "tr") params.push("lang=" + lang);
    const next = path + (params.length ? "?" + params.join("&") : "") + (hash ? "#" + hash : "");
    if (next !== href) el.setAttribute("href", next);
  }

  function applyElement(el) {
    for (const name of attrNames(el)) applyAttr(el, name);
    if (el.tagName === "A") applyHref(el);
  }

  function applyTree(root) {
    if (!root) return;
    if (root.nodeType === 3) return applyText(root);
    if (root.nodeType !== 1 && root.nodeType !== 9 && root.nodeType !== 11) return;
    const doc = root.ownerDocument || root;
    if (root.nodeType === 1) {
      if (skipped(root) && !root.matches("textarea")) return;
      applyElement(root);
    }
    const walker = doc.createTreeWalker(root, 1 | 4, null);
    let node = walker.nextNode();
    while (node) {
      if (node.nodeType === 3) applyText(node);
      else applyElement(node);
      node = walker.nextNode();
    }
  }

  function onMutations(records) {
    for (const r of records) {
      if (r.type === "characterData") applyText(r.target);
      else if (r.type === "attributes") {
        if (r.target.nodeType !== 1) continue;
        if (r.attributeName === "href") { if (r.target.tagName === "A") applyHref(r.target); } else applyAttr(r.target, r.attributeName);
      }
      else r.addedNodes.forEach(applyTree);
    }
  }

  function observe(doc) {
    if (observer || typeof global.MutationObserver !== "function") return;
    observer = new global.MutationObserver(onMutations);
    observer.observe(doc.documentElement, {
      childList: true, subtree: true, characterData: true,
      attributes: true, attributeFilter: ATTRS.concat(["value", "href"]),
    });
  }

  function disconnect() {
    if (observer) observer.disconnect();
    observer = null;
  }

  /** Bir öğenin özgün (Türkçe) metni; çevrilmiş düğümlerde kaynak metni döndürür (metin karşılaştırmaları için). */
  function source(el) {
    if (!el) return "";
    if (el.nodeType === 3) {
      const rec = textOrig.get(el);
      return rec && el.nodeValue === rec.out ? rec.src : el.nodeValue;
    }
    let out = "";
    const kids = el.childNodes || [];
    for (let i = 0; i < kids.length; i += 1) out += kids[i].nodeType === 1 ? source(kids[i]) : kids[i].nodeType === 3 ? source(kids[i]) : "";
    return kids.length ? out : (el.textContent || "");
  }

  function wrapDialogs() {
    for (const name of ["alert", "confirm", "prompt"]) {
      const original = global[name];
      if (typeof original !== "function" || original.__sniperI18n) continue;
      const wrapped = function (message, ...rest) {
        return original.call(global, typeof message === "string" ? t(message) : message, ...rest);
      };
      wrapped.__sniperI18n = true;
      global[name] = wrapped;
    }
  }

  function fetchDictionary(locale) {
    if (dictionaries.has(locale)) return Promise.resolve(dictionaries.get(locale));
    if (loading.has(locale)) return loading.get(locale);
    if (typeof global.fetch !== "function") return Promise.reject(new Error("fetch yok"));
    const request = global.fetch(DICTIONARY_URLS[locale], { credentials: "same-origin" })
      .then((r) => { if (!r.ok) throw new Error("sözlük alınamadı: " + r.status); return r.text(); })
      .then((text) => {
        const data = parseDictionary(text);
        dictionaries.set(locale, data);
        return data;
      })
      .finally(() => { loading.delete(locale); });
    loading.set(locale, request);
    return request;
  }

  function loadDictionary(locale) {
    locale = normalizeLang(locale);
    if (locale === "tr") return Promise.resolve(null);
    if (locale === "en") return fetchDictionary("en");
    return Promise.all([fetchDictionary("en"), fetchDictionary(locale)])
      .then(([base, overlay]) => mergeDictionaries(base, overlay));
  }

  function syncSelectors(doc) {
    doc.querySelectorAll("[data-i18n-lang-select]").forEach((select) => { if (select.value !== lang) select.value = lang; });
  }

  function apply(doc) {
    doc.documentElement.setAttribute("lang", lang);
    syncSelectors(doc);
    applyTree(doc.documentElement);
    if (lang === "tr") disconnect(); else observe(doc);
    listeners.forEach((fn) => { try { fn(lang); } catch (_err) { /* dinleyici hatası katmanı durdurmaz */ } });
  }

  /** Dili değiştirir (sayfa yenilenmez). */
  function setLang(value, options) {
    const next = normalizeLang(value);
    const revision = ++selectionRevision;
    const doc = (options && options.document) || global.document;
    if (!(options && options.persist === false)) storeLang(next);
    if (next !== "tr") {
      return loadDictionary(next).then((data) => {
        if (revision !== selectionRevision) return lang;
        activateDictionary(data);
        lang = next;
        apply(doc);
        return lang;
      }, (err) => {
        if (revision !== selectionRevision) return lang;
        lang = "tr";
        apply(doc);
        if (global.console) global.console.warn("Sniper i18n:", err && err.message);
        return lang;
      });
    }
    lang = next;
    apply(doc);
    return Promise.resolve(lang);
  }

  function bindSelectors(doc) {
    doc.querySelectorAll("[data-i18n-lang-select]").forEach((select) => {
      if (select.__sniperI18nBound) return;
      select.__sniperI18nBound = true;
      select.value = lang;
      select.addEventListener("change", () => { setLang(select.value); });
    });
  }

  function init(doc) {
    wrapDialogs();
    bindSelectors(doc);
    const wanted = readStoredLang();
    if (wanted !== "tr") setLang(wanted, { document: doc, persist: false });
  }

  const api = {
    get lang() { return lang; },
    setLang,
    t,
    translate: translateText,
    source,
    setDictionary,
    parseDictionary,
    normalizeLang,
    applyTree,
    onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    _compilePattern: compilePattern,
  };
  global.SniperI18n = api;

  if (global.document) {
    if (global.document.readyState === "loading") global.document.addEventListener("DOMContentLoaded", () => init(global.document));
    else init(global.document);
  }
})(typeof window !== "undefined" ? window : globalThis);
