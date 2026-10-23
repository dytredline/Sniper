from __future__ import annotations

from typing import Any

import legacy_basis


PATCH_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "patch_id": "PATCH-WEB-NGINX-01",
        "title": "Nginx Güvenlik Başlıkları, HSTS, CSP ve Çerez Sıkılaştırma",
        "category": "headers",
        "severity": "high",
        "target_file": "nginx.conf",
        "stack": "nginx",
        "match_tokens": ("headers", "cors", "session", "transport", "privacy", "hsts", "csp", "cookie", "x-frame-options", "web_hardening"),
        "description": "HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy ve güvenli çerez bayraklarını ekler.",
        "unified_diff": """--- a/nginx.conf
+++ b/nginx.conf
@@ -10,4 +10,12 @@
 server {
     listen 443 ssl http2;
+    server_tokens off;
+    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
+    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" always;
+    add_header X-Frame-Options "DENY" always;
+    add_header X-Content-Type-Options "nosniff" always;
+    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
+    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
+    proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Lax";
 }""",
        "snippet": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\nadd_header Content-Security-Policy "default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'" always;',
    },
    {
        "patch_id": "PATCH-WEB-FASTAPI-02",
        "title": "FastAPI / Starlette Güvenlik Başlıkları ve Kısıtlı CORS Ara Katmanı",
        "category": "cors",
        "severity": "medium",
        "target_file": "fastapi_security_middleware.py",
        "stack": "fastapi",
        "match_tokens": ("headers", "cors", "session", "transport", "cwe-942", "web_hardening"),
        "description": "Wildcard CORS yerine açık kaynak listesi ve yanıtlarda zorunlu güvenlik başlıkları uygular.",
        "unified_diff": """--- a/fastapi_security_middleware.py
+++ b/fastapi_security_middleware.py
@@ -1,6 +1,19 @@
 from fastapi import FastAPI, Request
 from fastapi.middleware.cors import CORSMiddleware
 
 app = FastAPI(docs_url=None, redoc_url=None)
-app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
+app.add_middleware(
+    CORSMiddleware,
+    allow_origins=["https://app.example.com"],
+    allow_credentials=True,
+    allow_methods=["GET", "POST", "PUT", "DELETE"],
+    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
+)
+
+@app.middleware("http")
+async def security_headers_middleware(request: Request, call_next):
+    response = await call_next(request)
+    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
+    response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
+    response.headers["X-Content-Type-Options"] = "nosniff"
+    response.headers["X-Frame-Options"] = "DENY"
+    return response""",
        "snippet": 'response.headers["Content-Security-Policy"] = "default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'"',
    },
    {
        "patch_id": "PATCH-WEB-EXPRESS-03",
        "title": "Express.js Helmet ve Güvenli Oturum Çerezi Yapılandırması",
        "category": "session",
        "severity": "medium",
        "target_file": "express_helmet.js",
        "stack": "express",
        "match_tokens": ("headers", "cors", "session", "cookie", "httponly", "samesite", "sniper-sess-02"),
        "description": "Express uygulamasında x-powered-by başlığını kapatır, Helmet CSP kurallarını ve HttpOnly/Secure/SameSite çerezlerini zorunlu kılar.",
        "unified_diff": """--- a/express_helmet.js
+++ b/express_helmet.js
@@ -1,5 +1,17 @@
 const express = require("express");
+const helmet = require("helmet");
 const app = express();
+app.disable("x-powered-by");
+app.use(helmet({
+  contentSecurityPolicy: {
+    directives: {
+      defaultSrc: ["'self'"],
+      objectSrc: ["'none'"],
+      frameAncestors: ["'none'"],
+    },
+  },
+  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
+}));""",
        "snippet": 'app.disable("x-powered-by");\napp.use(helmet());',
    },
    {
        "patch_id": "PATCH-WEB-DJANGO-04",
        "title": "Django Üretim Güvenlik Ayarları (HSTS, Çerez ve SSL Yönlendirme)",
        "category": "transport",
        "severity": "medium",
        "target_file": "django_settings.py",
        "stack": "django",
        "match_tokens": ("headers", "session", "transport", "cookie", "csrf", "debug", "sniper-conf-08"),
        "description": "Django üretim ortamında DEBUG=False, SECURE_SSL_REDIRECT, HSTS ve güvenli oturum/CSRF çerezlerini etkinleştirir.",
        "unified_diff": """--- a/django_settings.py
+++ b/django_settings.py
@@ -1,4 +1,12 @@
-DEBUG = True
-ALLOWED_HOSTS = ["*"]
+DEBUG = False
+ALLOWED_HOSTS = ["app.example.com"]
+SECURE_SSL_REDIRECT = True
+SECURE_HSTS_SECONDS = 63072000
+SECURE_HSTS_INCLUDE_SUBDOMAINS = True
+SECURE_HSTS_PRELOAD = True
+SESSION_COOKIE_SECURE = True
+SESSION_COOKIE_HTTPONLY = True
+SESSION_COOKIE_SAMESITE = "Lax"
+CSRF_COOKIE_SECURE = True
+CSRF_COOKIE_HTTPONLY = True""",
        "snippet": "DEBUG = False\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True",
    },
    {
        "patch_id": "PATCH-CONT-DOCKER-05",
        "title": "Dockerfile Sabit İmaj Etiketi, Non-Root Kullanıcı ve Sağlık Kontrolü",
        "category": "container",
        "severity": "high",
        "target_file": "Dockerfile",
        "stack": "docker",
        "match_tokens": ("container", "cwe-250", "cwe-1104", "dockerfile", "latest", "root"),
        "description": "latest etiketi yerine sabit sürüm kullanır, düşük yetkili uygulama kullanıcısına geçer ve HEALTHCHECK tanımlar.",
        "unified_diff": """--- a/Dockerfile
+++ b/Dockerfile
@@ -1,5 +1,9 @@
-FROM python:latest
+FROM python:3.12.3-slim-bookworm
 WORKDIR /app
 COPY . /app
-RUN pip install -r requirements.txt
+RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin appuser \\
+    && pip install --no-cache-dir -r requirements.txt \\
+    && chown -R appuser:appgroup /app
+USER appuser
+HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]
 CMD ["python3", "app.py"]""",
        "snippet": "USER appuser\nHEALTHCHECK --interval=30s --timeout=5s CMD [\"python3\", \"-c\", \"...\"]",
    },
    {
        "patch_id": "PATCH-CONT-K8S-06",
        "title": "Kubernetes Pod SecurityContext (Non-Root, ReadOnlyRootFilesystem, Drop ALL)",
        "category": "container",
        "severity": "high",
        "target_file": "k8s-pod-security.yaml",
        "stack": "kubernetes",
        "match_tokens": ("container", "cwe-250", "privileged", "securitycontext", "capabilities"),
        "description": "Kubernetes iş yükünde imtiyaz yükselmesini engeller, kök dosya sistemini salt okunur yapar ve tüm Linux yeteneklerini düşürür.",
        "unified_diff": """--- a/k8s-pod-security.yaml
+++ b/k8s-pod-security.yaml
@@ -8,4 +8,13 @@
     spec:
+      automountServiceAccountToken: false
       containers:
         - name: app
-          securityContext:
-            privileged: true
+          securityContext:
+            privileged: false
+            allowPrivilegeEscalation: false
+            runAsNonRoot: true
+            runAsUser: 10001
+            readOnlyRootFilesystem: true
+            capabilities:
+              drop: ["ALL"]""",
        "snippet": "allowPrivilegeEscalation: false\nrunAsNonRoot: true\nreadOnlyRootFilesystem: true",
    },
    {
        "patch_id": "PATCH-CICD-GHA-07",
        "title": "GitHub Actions En Az İzin (contents: read) ve Eylem SHA Sabitleme",
        "category": "supplychain",
        "severity": "high",
        "target_file": ".github/workflows/ci.yml",
        "stack": "github-actions",
        "match_tokens": ("supplychain", "pull_request_target", "workflow", "cwe-829", "cwe-250"),
        "description": "pull_request_target yerine güvenli pull_request tetikleyicisi, salt okunur GITHUB_TOKEN izinleri ve tam commit SHA sabitlemesi uygular.",
        "unified_diff": """--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,8 +1,11 @@
 name: CI
-on: [pull_request_target]
+on: [pull_request]
+permissions:
+  contents: read
 jobs:
   test:
     runs-on: ubuntu-latest
     steps:
-      - uses: actions/checkout@v4
+      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11""",
        "snippet": "permissions:\n  contents: read\nsteps:\n  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
    },
    {
        "patch_id": "PATCH-MOB-ANDROID-08",
        "title": "AndroidManifest.xml ve Ağ Güvenliği Yapılandırması (Cleartext/Backup/Exported Kapatma)",
        "category": "mobile_platform",
        "severity": "high",
        "target_file": "AndroidManifest.xml",
        "stack": "android",
        "match_tokens": ("mobile_platform", "mobile_network", "mobile_storage", "masvs-platform", "masvs-network", "masvs-storage", "cleartext", "allowbackup", "debuggable"),
        "description": "Android uygulamasında debuggable, allowBackup ve usesCleartextTraffic bayraklarını kapatır ve bileşenleri varsayılan olarak dışa kapatır.",
        "unified_diff": """--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -3,8 +3,9 @@
     <application
-        android:debuggable="true"
-        android:allowBackup="true"
-        android:usesCleartextTraffic="true">
+        android:debuggable="false"
+        android:allowBackup="false"
+        android:usesCleartextTraffic="false"
+        android:networkSecurityConfig="@xml/network_security_config">
         <activity
             android:name=".InternalActivity"
-            android:exported="true" />
+            android:exported="false" />
     </application>""",
        "snippet": 'android:debuggable="false"\nandroid:allowBackup="false"\nandroid:usesCleartextTraffic="false"',
    },
    {
        "patch_id": "PATCH-MOB-IOS-09",
        "title": "iOS Info.plist App Transport Security (NSAllowsArbitraryLoads Kaldırma)",
        "category": "mobile_network",
        "severity": "high",
        "target_file": "ios/Info.plist",
        "stack": "ios",
        "match_tokens": ("mobile_network", "masvs-network", "nsallowsarbitraryloads", "ats", "plist"),
        "description": "iOS App Transport Security (ATS) korumasını tam olarak etkinleştirir ve şifresiz HTTP istisnalarını kaldırır.",
        "unified_diff": """--- a/ios/Info.plist
+++ b/ios/Info.plist
@@ -4,6 +4,6 @@
 <dict>
     <key>NSAppTransportSecurity</key>
     <dict>
-        <key>NSAllowsArbitraryLoads</key>
-        <true/>
+        <key>NSAllowsArbitraryLoads</key>
+        <false/>
     </dict>
 </dict>""",
        "snippet": "<key>NSAllowsArbitraryLoads</key>\n<false/>",
    },
    {
        "patch_id": "PATCH-CODE-FIXES-10",
        "title": "Kaynak Kod Güvenlik Yaması (Parametreli SQL, Güvenli Alt Süreç, yaml.safe_load, Ortam Sırları)",
        "category": "code_security",
        "severity": "critical",
        "target_file": "security_fixes.patch",
        "stack": "python",
        "match_tokens": (
            "cwe-89",
            "cwe-78",
            "cwe-502",
            "cwe-327",
            "cwe-338",
            "cwe-798",
            "cwe-918",
            "cwe-347",
            "data_query",
            "command_data",
            "crypto",
            "secrets",
            "ssrf",
            "auth",
        ),
        "description": "SQL enjeksiyonu, shell=True komut çalıştırma, güvensiz YAML/pickle deserialization, sabit kodlu sırlar ve doğrulanmamış JWT çağrılarını güvenli alternatifleriyle değiştirir.",
        "unified_diff": """--- a/app/service.py
+++ b/app/service.py
@@ -1,14 +1,16 @@
+import os
+import secrets
 import subprocess
 import yaml
 import jwt
 
-API_SECRET = "hardcoded-production-secret"
+API_SECRET = os.environ["API_SECRET"]
 
 def get_user(cursor, user_id: str):
-    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
+    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
     return cursor.fetchone()
 
 def run_ping(host: str):
-    return subprocess.run(f"ping -c 1 {host}", shell=True, check=False)
+    return subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
 
 def parse_config(raw_yaml: str):
-    return yaml.load(raw_yaml, Loader=yaml.Loader)
+    return yaml.safe_load(raw_yaml)
 
 def verify_token(token: str):
-    return jwt.decode(token, options={"verify_signature": False})
+    return jwt.decode(token, API_SECRET, algorithms=["HS256"])
 
 def generate_reset_token() -> str:
-    import random
-    return str(random.randint(100000, 999999))
+    return secrets.token_urlsafe(32)""",
        "snippet": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\nsubprocess.run(["ping", "-c", "1", host], shell=False, check=False)\nyaml.safe_load(raw_yaml)',
    },
)


def _finding_blob(item: dict[str, Any]) -> str:
    parts = (
        str(item.get("category") or ""),
        str(item.get("owasp_category") or ""),
        str(item.get("title") or ""),
        str(item.get("reference") or ""),
        str(item.get("cwe") or ""),
        str(item.get("control_id") or ""),
        str(item.get("rule_id") or ""),
        str(item.get("masvs_id") or ""),
    )
    return " ".join(parts).casefold()


def generate_remediation_patches(
    *,
    findings: list[dict[str, Any]] | None = None,
    scan: dict[str, Any] | None = None,
    project_audit: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
    target_stack: str = "auto",
    include_templates: bool = False,
) -> dict[str, Any]:
    """23. tur: yamalar yalnız gerçek bulgularla eşleşen katalog girdileridir. Bulgu yoksa ya da eşleşme yoksa şablon
    yama yalnız ``include_templates`` ile ve "şablon" etiketiyle döner (önceden bulgusuz istek 10 yamayı, eşleşmesiz
    istek ilk 3 yamayı gerçek öneri gibi döndürüyordu). Proje analizinde otomatik yama üretilebilen akışlar için
    doğrulanmış yama uçları (fix_verification) ayrıca listelenir."""
    sources = legacy_basis.source_labels(scan=scan, project_audit=project_audit, findings=findings,
                                         mobile_audit=mobile_audit)
    if not sources and not include_templates:
        legacy_basis.require_sources(sources)
    all_findings: list[dict[str, Any]] = []
    if isinstance(findings, list):
        all_findings.extend(f for f in findings if isinstance(f, dict))
    if isinstance(scan, dict) and isinstance(scan.get("findings"), list):
        all_findings.extend(f for f in scan["findings"] if isinstance(f, dict))
    if isinstance(project_audit, dict) and isinstance(project_audit.get("findings"), list):
        all_findings.extend(f for f in project_audit["findings"] if isinstance(f, dict))
    if isinstance(mobile_audit, dict) and isinstance(mobile_audit.get("findings"), list):
        all_findings.extend(f for f in mobile_audit["findings"] if isinstance(f, dict))

    normalized_stack = (target_stack or "auto").strip().casefold()
    blobs = [_finding_blob(f) for f in all_findings]

    selected_patches: list[dict[str, Any]] = []
    for entry in PATCH_CATALOG:
        if normalized_stack not in ("auto", "all", "") and entry["stack"] != normalized_stack:
            continue
        tokens = entry["match_tokens"]
        matched_count = sum(1 for b in blobs if any(tok in b for tok in tokens)) if blobs else 0
        include = matched_count > 0 or include_templates
        if include:
            selected_patches.append({
                "patch_id": entry["patch_id"],
                "title": entry["title"],
                "category": entry["category"],
                "severity": entry["severity"],
                "target_file": entry["target_file"],
                "stack": entry["stack"],
                "matched_finding_count": matched_count,
                "basis": "matched" if matched_count else "template",
                "description": entry["description"],
                "unified_diff": entry["unified_diff"],
                "snippet": entry["snippet"],
            })

    unified_diff_bundle = "\n\n".join(p["unified_diff"] for p in selected_patches)
    matched = sum(1 for p in selected_patches if p["basis"] == "matched")
    templates = len(selected_patches) - matched
    verified = verified_fix_candidates(project_audit)
    if matched or verified:
        kind = "mixed" if templates else "real"
    else:
        kind = "template" if templates else "real"
    note = ("Katalog yamaları bulgu metniyle eşleşen yapılandırma örnekleridir; projeye uygulamadan önce gözden "
            "geçirin. Kod düzeyindeki doğrulanmış yamalar için verified_fix_candidates uçlarını kullanın.")
    if not matched and not templates:
        note = "Bulgularla eşleşen katalog yaması yok. " + note
    return {
        "format": "sniper-auto-remediation-patches-v1",
        "matched_patch_count": matched,
        "template_patch_count": templates,
        "verified_fix_candidates": verified,
        "data_basis": legacy_basis.data_basis(kind, sources, note),
        "target_stack": normalized_stack or "auto",
        "finding_count_analyzed": len(all_findings),
        "patch_count": len(selected_patches),
        "patches": selected_patches,
        "unified_diff_bundle": unified_diff_bundle,
    }


MAX_VERIFIED_CANDIDATES = 25


def verified_fix_candidates(project_audit: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Proje analizinde otomatik, doğrulanabilir yama üretilebilen bulgular (taint_autofix stratejisi olan Python /
    JS-TS akışları). Yama ``autofix.patch`` ucundan alınır, ``autofix/verify`` ucu geçici kopyada yeniden analizle
    açığın kapandığını doğrular (fix_verification)."""
    if not isinstance(project_audit, dict) or not project_audit.get("id"):
        return []
    try:
        import taint_autofix
    except Exception:  # noqa: BLE001 — yama modülü yoksa yalnız katalog
        return []
    audit_id = str(project_audit["id"])
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()  # aynı satırdaki akış + desen bulgusu tek yama adayıdır
    for index, finding in enumerate(project_audit.get("findings") or []):
        if not isinstance(finding, dict):
            continue
        relpath = str(finding.get("file") or "")
        if not relpath.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            continue
        kind = taint_autofix.finding_kind(finding)
        key = (relpath, int(finding.get("line") or 0), str(kind))
        if kind is None or key in seen:
            continue
        seen.add(key)
        out.append({"index": index, "title": str(finding.get("title") or ""), "file": relpath,
                    "line": int(finding.get("line") or 0), "kind": kind,
                    "patch_url": f"/api/project-audits/{audit_id}/findings/{index}/autofix.patch",
                    "verify_url": f"/api/project-audits/{audit_id}/findings/{index}/autofix/verify"})
        if len(out) >= MAX_VERIFIED_CANDIDATES:
            break
    return out
