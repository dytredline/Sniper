"use strict";
// Giriş sayfası: parola → (gerekirse) TOTP/kurtarma kodu → ana sayfa. Sır içeren hiçbir değer saklanmaz/yazdırılmaz.
(function () {
  const $ = selector => document.querySelector(selector);
  let challenge = "";

  function say(text, kind) {
    const node = $("#auth-login-message");
    node.textContent = text || "";
    node.dataset.kind = kind || "";
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  }

  async function init() {
    try {
      const response = await fetch("/api/auth/status", { credentials: "same-origin" });
      const status = await response.json();
      if (!status.enabled) {
        say("Giriş etkin değil; Sniper yerel erişimle açık. Ana sayfaya yönlendiriliyorsunuz.", "info");
        setTimeout(() => { location.href = "/"; }, 1200);
        return;
      }
      if (status.authenticated) { location.href = "/"; return; }
    } catch (error) { say("Sunucuya ulaşılamadı.", "error"); }
    $("#auth-username").focus();
  }

  $("#auth-login-form").addEventListener("submit", async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    button.disabled = true;
    say("");
    const result = await post("/api/auth/login", { username: $("#auth-username").value, password: $("#auth-password").value });
    $("#auth-password").value = "";
    button.disabled = false;
    if (result.ok && result.data.totp_required) {
      challenge = result.data.challenge;
      $("#auth-login-form").classList.add("hidden");
      $("#auth-totp-form").classList.remove("hidden");
      say("İki adımlı doğrulama: uygulamanızdaki 6 haneli kodu girin.", "info");
      $("#auth-totp-code").focus();
      return;
    }
    if (result.ok) { location.href = "/"; return; }
    say(result.data.error || "Giriş başarısız.", "error");
  });

  $("#auth-totp-form").addEventListener("submit", async event => {
    event.preventDefault();
    const code = $("#auth-totp-code").value.trim();
    const recovery = $("#auth-recovery-code").value.trim();
    const body = recovery ? { challenge, recovery_code: recovery } : { challenge, code };
    const result = await post("/api/auth/login/totp", body);
    $("#auth-recovery-code").value = "";
    if (result.ok) { location.href = "/"; return; }
    say(result.data.error || "Doğrulama başarısız.", "error");
    if (result.status === 401 && /süresi doldu/.test(result.data.error || "")) {
      $("#auth-totp-form").classList.add("hidden");
      $("#auth-login-form").classList.remove("hidden");
    }
  });

  init();
})();
