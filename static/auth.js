"use strict";
// Arayüz girişi istemci katmanı (index.html'de ilk betik).
// 1) fetch sarmalayıcı: aynı kökenli durum değiştiren isteklere CSRF başlığı; 401'de giriş sayfasına yönlendirme.
// 2) Kenar çubuğunda kullanıcı kutusu; "Hesap" (parola, iki adımlı doğrulama, oturumlar) ve yönetici için
//    "Kullanıcılar" pencereleri; giriş kapalıyken "Girişi etkinleştir" kurulum akışı.
// Tüm DOM metinleri textContent ile yazılır (sunucudan gelen değer HTML olarak yorumlanmaz).
(function () {
  const CSRF_COOKIE = "sniper_csrf";
  const CSRF_HEADER = "X-Sniper-CSRF";
  const nativeFetch = window.fetch.bind(window);

  function cookie(name) {
    for (const part of document.cookie.split(";")) {
      const [key, ...rest] = part.trim().split("=");
      if (key === name) return rest.join("=");
    }
    return "";
  }

  function sameOrigin(input) {
    try {
      const url = new URL(typeof input === "string" ? input : input.url, location.href);
      return url.origin === location.origin ? url : null;
    } catch (error) { return null; }
  }

  window.fetch = function (input, init) {
    const url = sameOrigin(input);
    const options = Object.assign({}, init || {});
    const method = String(options.method || (input && input.method) || "GET").toUpperCase();
    if (url && !["GET", "HEAD", "OPTIONS"].includes(method)) {
      const token = cookie(CSRF_COOKIE);
      if (token) {
        const headers = new Headers(options.headers || (input && input.headers) || {});
        headers.set(CSRF_HEADER, token);
        options.headers = headers;
      }
    }
    return nativeFetch(input, options).then(response => {
      if (url && response.status === 401 && url.pathname.startsWith("/api/") && !url.pathname.startsWith("/api/auth/login")) {
        location.href = "/login.html";
      }
      return response;
    });
  };

  // --- yardımcılar -----------------------------------------------------
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    for (const child of children) if (child != null) node.append(child);
    return node;
  }

  async function call(path, body) {
    const response = await window.fetch(path, body === undefined ? { credentials: "same-origin" } : {
      method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `İstek tamamlanamadı (${response.status})`);
    return data;
  }

  function notify(message, type) {
    if (typeof window.toast === "function") window.toast(message, type);
    else if (type === "error") console.warn(message);
  }

  function field(label, attrs) { return el("label", {}, label, el("input", attrs)); }

  function dialog(title, buildBody) {
    const body = el("div", { class: "auth-dialog-body" });
    const node = el("dialog", { class: "auth-dialog", "aria-label": title },
      el("div", { class: "auth-dialog-head" }, el("h2", { text: title }),
        el("button", { class: "mini-button", type: "button", text: "Kapat", onclick: () => node.close() })),
      body);
    node.addEventListener("close", () => node.remove());
    document.body.append(node);
    buildBody(body, node);
    node.showModal();
    return node;
  }

  function formValues(form) { return Object.fromEntries(new FormData(form).entries()); }

  // --- hesap -----------------------------------------------------------
  function openAccount(me) {
    dialog("Hesap", async body => {
      const user = me.user;
      body.append(el("p", { class: "auth-hint", text: `${user.username} · ${user.role_label} · oturum boşta ${me.session_idle_minutes} dk, en çok ${me.session_max_hours} sa` }));

      const pw = el("form", {},
        field("Mevcut parola", { name: "current_password", type: "password", autocomplete: "current-password", required: "" }),
        field("Yeni parola (en az 12)", { name: "new_password", type: "password", autocomplete: "new-password", minlength: "12", required: "" }),
        el("button", { class: "button primary", type: "submit", text: "Parolayı değiştir" }));
      pw.addEventListener("submit", async event => {
        event.preventDefault();
        try { await call("/api/auth/password", formValues(pw)); pw.reset(); notify("Parola değişti; diğer oturumlar kapatıldı."); }
        catch (error) { notify(error.message, "error"); }
      });
      body.append(el("section", { class: "auth-section" }, el("h3", { text: "Parola" }), pw));

      const totp = el("section", { class: "auth-section" }, el("h3", { text: "İki adımlı doğrulama (TOTP)" }));
      if (user.totp_enabled) {
        totp.append(el("p", { class: "auth-hint", text: `Etkin. Kalan kurtarma kodu: ${me.recovery_codes_left}.` }));
        const off = el("form", {},
          field("Parola", { name: "password", type: "password", autocomplete: "current-password", required: "" }),
          field("Doğrulama kodu", { name: "code", inputmode: "numeric", maxlength: "6", required: "" }),
          el("button", { class: "mini-button", type: "submit", text: "Kapat" }));
        off.addEventListener("submit", async event => {
          event.preventDefault();
          try { await call("/api/auth/totp/disable", formValues(off)); notify("İki adımlı doğrulama kapatıldı."); location.reload(); }
          catch (error) { notify(error.message, "error"); }
        });
        totp.append(off);
      } else {
        const start = el("button", { class: "mini-button accent", type: "button", text: "Kurulumu başlat" });
        start.addEventListener("click", async () => {
          try {
            const data = await call("/api/auth/totp/begin", {});
            start.remove();
            const confirm = el("form", {},
              field("Uygulamadaki 6 haneli kod", { name: "code", inputmode: "numeric", maxlength: "6", required: "" }),
              el("button", { class: "button primary", type: "submit", text: "Doğrula ve etkinleştir" }));
            totp.append(
              el("p", { class: "auth-hint", text: "Doğrulayıcı uygulamaya bu otpauth adresini ya da gizli anahtarı ekleyin:" }),
              el("div", { class: "auth-code", text: data.otpauth_uri }),
              el("div", { class: "auth-code", text: data.secret }), confirm);
            confirm.addEventListener("submit", async event => {
              event.preventDefault();
              try {
                const done = await call("/api/auth/totp/confirm", formValues(confirm));
                confirm.remove();
                totp.append(el("p", { class: "auth-hint", text: "Etkinleştirildi. Kurtarma kodlarını şimdi güvenli bir yere kaydedin; bir daha gösterilmez:" }),
                  el("div", { class: "auth-code", text: done.recovery_codes.join("  ") }));
              } catch (error) { notify(error.message, "error"); }
            });
          } catch (error) { notify(error.message, "error"); }
        });
        totp.append(start);
      }
      body.append(totp);

      const sessions = el("button", { class: "mini-button", type: "button", text: "Diğer tüm oturumları kapat" });
      sessions.addEventListener("click", async () => {
        try { const data = await call("/api/auth/sessions/revoke-all", {}); notify(`${data.revoked} oturum kapatıldı.`); }
        catch (error) { notify(error.message, "error"); }
      });
      body.append(el("section", { class: "auth-section" }, el("h3", { text: "Oturumlar" }), sessions));
    });
  }

  // --- kullanıcılar (yönetici) -------------------------------------------
  function openUsers(me) {
    dialog("Kullanıcılar", async body => {
      const roles = { reader: "okuyucu", analyst: "analist", admin: "yönetici" };
      const table = el("table", { class: "auth-users" });
      async function render() {
        const data = await call("/api/auth/users");
        table.replaceChildren(el("tr", {}, ...["Kullanıcı", "Rol", "Durum", "Son giriş", ""].map(t => el("th", { text: t }))));
        for (const user of data.users) {
          const select = el("select", { "aria-label": `${user.username} rolü` },
            ...Object.entries(roles).map(([value, label]) => {
              const option = el("option", { value, text: label });
              if (value === user.role) option.selected = true;
              return option;
            }));
          const update = async (changes, message) => {
            try { await call(`/api/auth/users/${encodeURIComponent(user.id)}`, changes); notify(message); await render(); }
            catch (error) { notify(error.message, "error"); await render(); }
          };
          select.addEventListener("change", () => update({ role: select.value }, "Rol güncellendi; kullanıcının oturumları kapatıldı."));
          const status = [user.disabled ? "kapalı" : "etkin", user.locked ? "kilitli" : "", user.totp_enabled ? "2FA" : ""].filter(Boolean).join(" · ");
          const last = user.last_login_at ? new Date(user.last_login_at * 1000).toLocaleString("tr-TR") : "—";
          const actions = el("div", { class: "button-row" },
            el("button", { class: "mini-button", type: "button", text: user.disabled ? "Etkinleştir" : "Kapat",
              onclick: () => update({ disabled: !user.disabled }, "Durum güncellendi.") }),
            user.locked ? el("button", { class: "mini-button", type: "button", text: "Kilidi aç", onclick: () => update({ unlock: true }, "Kilit açıldı.") }) : null,
            user.totp_enabled ? el("button", { class: "mini-button", type: "button", text: "2FA sıfırla", onclick: () => update({ reset_totp: true }, "İki adımlı doğrulama sıfırlandı.") }) : null,
            el("button", { class: "mini-button", type: "button", text: "Parola ata", onclick: () => {
              const value = window.prompt(`${user.username} için yeni parola (en az 12 karakter):`);
              if (value) update({ password: value }, "Parola atandı; kullanıcının oturumları kapatıldı.");
            } }));
          table.append(el("tr", {}, el("td", { text: user.username }), el("td", {}, select), el("td", { text: status }), el("td", { text: last }), el("td", {}, actions)));
        }
      }
      const create = el("form", {},
        field("Kullanıcı adı", { name: "username", maxlength: "64", required: "" }),
        field("Parola (en az 12)", { name: "password", type: "password", autocomplete: "new-password", minlength: "12", required: "" }),
        el("label", {}, "Rol", el("select", { name: "role" }, ...Object.entries(roles).map(([value, label]) => el("option", { value, text: label })))),
        el("button", { class: "button primary", type: "submit", text: "Kullanıcı ekle" }));
      create.addEventListener("submit", async event => {
        event.preventDefault();
        try { await call("/api/auth/users", formValues(create)); create.reset(); notify("Kullanıcı eklendi."); await render(); }
        catch (error) { notify(error.message, "error"); }
      });
      body.append(el("section", { class: "auth-section" }, el("h3", { text: "Yeni kullanıcı" }), create),
        el("section", { class: "auth-section" }, el("h3", { text: "Hesaplar" }), table),
        el("p", { class: "auth-hint", text: "Okuyucu yalnız görüntüler; analist analiz/tarama başlatır, triyaj ve bulgu durumu değiştirir; yönetici araç çalıştırır, ayarları ve kullanıcıları yönetir." }));
      try { await render(); } catch (error) { notify(error.message, "error"); }
    });
  }

  // --- kurulum (giriş kapalıyken) ------------------------------------------
  function openSetup() {
    dialog("Girişi etkinleştir", body => {
      body.append(el("p", { class: "auth-hint", text: "Etkinleşince arayüz ve API oturum ister. İlk yönetici hesabını oluşturmak için sunucuda tek seferlik bir kurulum belirteci dosyası (0600) üretilir; içeriğini yalnız bu makinedeki kullanıcı okuyabilir. Kurtarma: cli_reports.py users disable-auth / reset-password." }));
      const begin = el("button", { class: "mini-button accent", type: "button", text: "Kurulum belirteci üret" });
      const form = el("form", { class: "hidden" },
        field("Kurulum belirteci", { name: "token", autocomplete: "off", required: "" }),
        field("Yönetici kullanıcı adı", { name: "username", maxlength: "64", required: "" }),
        field("Parola (en az 12)", { name: "password", type: "password", autocomplete: "new-password", minlength: "12", required: "" }),
        el("button", { class: "button primary", type: "submit", text: "Yöneticiyi oluştur ve etkinleştir" }));
      const where = el("div", { class: "auth-code hidden" });
      begin.addEventListener("click", async () => {
        try {
          const data = await call("/api/auth/setup/begin", { confirm: true });
          where.textContent = `cat ${data.token_file}   (30 dk geçerli)`;
          where.classList.remove("hidden");
          form.classList.remove("hidden");
        } catch (error) { notify(error.message, "error"); }
      });
      form.addEventListener("submit", async event => {
        event.preventDefault();
        try { await call("/api/auth/setup/complete", formValues(form)); location.reload(); }
        catch (error) { notify(error.message, "error"); }
      });
      body.append(el("section", { class: "auth-section" }, begin, where, form));
    });
  }

  // --- kenar çubuğu kutusu ---------------------------------------------
  async function mount() {
    const host = document.querySelector(".sidebar-foot");
    if (!host) return;
    let status;
    try { status = await call("/api/auth/status"); } catch (error) { return; }
    const box = el("div", { class: "auth-user-box", id: "auth-user-box" });
    if (!status.enabled) {
      box.append(el("span", { text: "Giriş: kapalı (yalnız yerel erişim)" }),
        el("div", { class: "button-row" }, el("button", { class: "mini-button", type: "button", text: "Girişi etkinleştir", onclick: openSetup })));
    } else if (status.authenticated) {
      const me = await call("/api/auth/me").catch(() => null);
      if (!me) return;
      box.append(el("span", { class: "auth-user-name", text: `${me.user.username} · ${me.user.role_label}` }),
        el("div", { class: "button-row" },
          el("button", { class: "mini-button", type: "button", text: "Hesap", onclick: () => openAccount(me) }),
          me.user.role === "admin" ? el("button", { class: "mini-button", type: "button", text: "Kullanıcılar", onclick: () => openUsers(me) }) : null,
          el("button", { class: "mini-button", type: "button", text: "Çıkış", onclick: async () => {
            try { await call("/api/auth/logout", {}); } finally { location.href = "/login.html"; }
          } })));
    }
    host.append(box);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
