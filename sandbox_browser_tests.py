"""Yalıtılmış Playwright tarayıcı testleri (bkz. tool_sandbox.py, sandbox_targets.py).

Kullanıcıdan betik alınmaz: sabit sürücü (sandbox_playwright_driver.cjs) seçilen yolları pinli Chromium ile açar ve
olgu toplar (durum kodu, güvenlik başlıkları, çerez bayrakları, formlar, konsol/sayfa hataları, karışık içerik,
isteğe bağlı yansıma sondası). Tarayıcı bwrap'ın ağ ad alanında yalnız aktarıcı üzerinden listedeki tek hedefe
ulaşır; başka kökenlere giden istekler başarısız olur ve yalnız köken adı raporlanır. Yanıt gövdesi, çerez değeri
ya da form değeri döndürülmez.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

from sandbox_load_tests import PATH_RE, _base_url, _relay_summary
from tool_sandbox import DRIVER, SandboxExecutionError, check_target, read_output, run_job

MAX_PATHS = 10
MAX_SCREENSHOT = 600_000
USER_AGENT = "Mozilla/5.0 (X11; Linux aarch64) SniperBrowserTest/1.0"


def driver_sha256() -> str:
    return hashlib.sha256(DRIVER.read_bytes()).hexdigest()


def _path(value: object) -> str:
    if type(value) is not str or not PATH_RE.fullmatch(value) or "//" in value or "/../" in value + "/" \
            or "/./" in value + "/":
        raise ValueError("Geçersiz yol.")
    return value


def _params(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {"confirm", "target", "paths", "reflection_probe", "screenshot", "ignore_https_errors", "timeout_s"}
    if not isinstance(payload, dict) or set(payload) - allowed or payload.get("confirm") is not True:
        raise ValueError("Onay (confirm: true) ve geçerli alanlar gerekli.")
    target = check_target("playwright", payload.get("target"))
    paths = payload.get("paths", ["/"])
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_PATHS:
        raise ValueError(f"1–{MAX_PATHS} yol verilmelidir.")
    paths = list(dict.fromkeys(_path(item) for item in paths))
    flags = {}
    for name in ("reflection_probe", "screenshot", "ignore_https_errors"):
        value = payload.get(name, False)
        if type(value) is not bool:
            raise ValueError(f"{name} true/false olmalı.")
        flags[name] = value
    timeout = payload.get("timeout_s", 20)
    if type(timeout) is not int or not 5 <= timeout <= 60:
        raise ValueError("Sayfa süresi 5–60 sn olmalı.")
    return {"target": target, "paths": paths, "timeout": timeout, **flags}


def _plan(params: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    token = secrets.token_hex(6)
    tag = f"sniper-x{token}"
    probe = {"tag": tag, "marker": f"sniperprobe{token}", "payload": f"sniperprobe{token}\"'><{tag}></{tag}>"}
    plan = {"base_url": _base_url(params["target"]), "paths": params["paths"],
            "reflection_probe": params["reflection_probe"], "probe": probe, "screenshot": params["screenshot"],
            "shots_left": 1, "ignore_https_errors": params["ignore_https_errors"],
            "nav_timeout_ms": params["timeout"] * 1000, "user_agent": USER_AGENT}
    return json.dumps(plan).encode(), probe


def _read_facts(work) -> dict[str, Any]:
    raw = read_output(work, "playwright.json", 1_000_000)
    if raw is None:
        raise SandboxExecutionError("playwright_ozet_yok")
    facts = json.loads(raw)
    if not isinstance(facts, dict) or facts.get("format") != "sniper-playwright-facts-v1":
        raise SandboxExecutionError("playwright_ozet_gecersiz")
    shot = read_output(work, "shot.png", MAX_SCREENSHOT)
    if shot and shot.startswith(b"\x89PNG\r\n\x1a\n"):
        facts["screenshot_png_base64"] = base64.b64encode(shot).decode("ascii")
    return facts


def _finding(severity: str, code: str, title: str, path: str, detail: str, cwe: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "title": title, "path": path, "detail": detail, "cwe": cwe}


def derive_findings(facts: dict[str, Any], https: bool) -> list[dict[str, str]]:
    """Olgulardan tarayıcı bulguları (sabit kurallar; kesinlik notu ``detail`` alanında)."""
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(item: dict[str, str]) -> None:
        key = (item["code"], item["path"])
        if key not in seen:
            seen.add(key)
            findings.append(item)

    for page in facts.get("pages") or []:
        if not isinstance(page, dict):
            continue
        path = str(page.get("path", "/"))[:200]
        reflection = page.get("reflection") or {}
        if page.get("probe"):
            if reflection.get("element_injected"):
                add(_finding("high", "reflected_html_injection", "Yansıyan HTML enjeksiyonu (XSS olasılığı)", path,
                             "sniper_probe parametresindeki etiket DOM'da öğe olarak oluştu; çıktı kodlaması yok.",
                             "CWE-79"))
            elif reflection.get("raw_text_reflected"):
                add(_finding("info", "reflected_parameter", "Parametre sayfaya yansıyor", path,
                             "Değer kodlanmış olarak yansıdı; bağlama göre (öznitelik/betik) elle doğrulayın.", "CWE-79"))
            continue
        if page.get("error") or page.get("status") is None:
            continue
        headers = page.get("headers") or {}
        if not headers.get("content-security-policy"):
            add(_finding("low", "missing_csp", "Content-Security-Policy yok", path,
                         "XSS etkisini sınırlayan CSP başlığı gönderilmiyor.", "CWE-693"))
        csp = str(headers.get("content-security-policy") or "")
        if not headers.get("x-frame-options") and "frame-ancestors" not in csp:
            add(_finding("low", "missing_clickjacking_protection", "Çerçeveleme koruması yok", path,
                         "X-Frame-Options ya da CSP frame-ancestors yok (clickjacking).", "CWE-1021"))
        if not headers.get("x-content-type-options"):
            add(_finding("info", "missing_nosniff", "X-Content-Type-Options: nosniff yok", path,
                         "MIME türü koklama kapatılmamış.", "CWE-693"))
        if https and not headers.get("strict-transport-security"):
            add(_finding("low", "missing_hsts", "HSTS yok", path, "HTTPS yanıtında Strict-Transport-Security yok.",
                         "CWE-319"))
        for name in sorted(page.get("disclosure_headers") or {}):
            add(_finding("info", "version_disclosure", f"Sunucu bilgisi ifşası ({name})", path,
                         f"{name} başlığı gönderiliyor.", "CWE-200"))
        forms = page.get("forms") or {}
        if forms.get("password_forms") and not https:
            add(_finding("medium", "password_over_http", "Parola formu şifresiz HTTP üzerinde", path,
                         "Parola alanı içeren form HTTP sayfasında.", "CWE-319"))
        if forms.get("password_get_forms"):
            add(_finding("medium", "password_get_form", "Parola GET ile gönderiliyor", path,
                         "Parola alanlı form method=GET; parola URL ve günlüklere düşer.", "CWE-598"))
        if page.get("mixed_content"):
            add(_finding("medium", "mixed_content", "Karışık içerik", path,
                         f"HTTPS sayfası {int(page['mixed_content'])} HTTP alt kaynak istedi.", "CWE-319"))
        if page.get("page_errors"):
            add(_finding("info", "page_errors", "Yakalanmamış JavaScript hataları", path,
                         f"{int(page['page_errors'])} sayfa hatası.", "CWE-754"))
    for cookie in facts.get("cookies") or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", ""))[:64]
        if not cookie.get("http_only"):
            add(_finding("low", "cookie_without_httponly", f"Çerez HttpOnly değil ({name})", "/",
                         "Betikten okunabilir çerez; oturum çerezi ise XSS ile çalınabilir.", "CWE-1004"))
        if https and not cookie.get("secure"):
            add(_finding("low", "cookie_without_secure", f"Çerez Secure değil ({name})", "/",
                         "HTTPS hedefte Secure bayrağı yok.", "CWE-614"))
        if cookie.get("same_site") == "None" and not cookie.get("secure"):
            add(_finding("low", "cookie_samesite_none_insecure", f"SameSite=None ve Secure yok ({name})", "/",
                         "Tarayıcılar reddeder ya da çapraz site isteklerde gönderilir.", "CWE-1275"))
    return findings


def run_playwright_sandbox(payload: object) -> dict[str, Any]:
    params = _params(payload)  # type: ignore[arg-type]
    plan, _probe = _plan(params)
    pages = len(params["paths"]) * (2 if params["reflection_probe"] else 1)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "TMPDIR": "/tmp",
           "PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS": "1", "NODE_OPTIONS": "--max-old-space-size=256"}
    argv = ["/opt/node/node", "/sbx/driver.cjs", "/job/plan.json"]
    outer = run_job("playwright", payload["target"], argv=argv, env=env,  # type: ignore[index]
                    timeout=min(900, 60 + pages * (params["timeout"] + 10)), files={"plan.json": plan},
                    max_connections=2000, max_bytes=128 * 1024 * 1024, reader=_read_facts)
    inner = outer.get("inner") or {}
    if outer.get("timed_out") or inner.get("timed_out"):
        raise SandboxExecutionError("sure_asildi")
    if inner.get("exit_code") != 0:
        raise SandboxExecutionError("playwright_basarisiz")
    facts = outer["parsed"]
    findings = derive_findings(facts, params["target"]["scheme"] == "https")
    return {"format": "playwright-sandbox-v1", "status": "completed", "target": outer["target"],
            "paths": params["paths"], "reflection_probe": params["reflection_probe"],
            "driver_sha256": driver_sha256(), "relay": _relay_summary(outer),
            "isolation": {"bwrap_namespaces": True, "network": "relay_only", "seccomp_denylist": True,
                          "chromium_internal_sandbox": False},
            "findings": findings, "facts": facts}
