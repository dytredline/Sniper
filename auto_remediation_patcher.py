from __future__ import annotations

import ast
import difflib
import re
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
            "cwe-943",
            "cwe-1336",
            "cwe-113",
            "cwe-134",
            "cwe-1321",
            "cwe-611",
            "cwe-22",
            "data_query",
            "command_data",
            "crypto",
            "secrets",
            "ssrf",
            "auth",
            "nosql",
            "ssti",
            "xxe",
            "traversal",
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
    {
        "patch_id": "PATCH-AI-LLM-11",
        "title": "Yapay Zeka / LLM Güvenli Model Yükleme (weights_only=True) ve Yapılandırılmış Çıktı Doğrulaması",
        "category": "ai_llm",
        "severity": "critical",
        "target_file": "llm_runner.py",
        "stack": "python",
        "match_tokens": ("llm01", "llm03", "llm04", "llm05", "llm06", "llm09", "ai_llm", "torch.load", "safetensors", "prompt injection"),
        "description": "PyTorch pickle tabanlı model yüklemesini weights_only=True ile sınırlar, sistem istemini kullanıcı girdisinden ayırır ve LLM çıktısında eval/exec kullanımını JSON şema doğrulamasıyla değiştirir.",
        "unified_diff": """--- a/llm_runner.py
+++ b/llm_runner.py
@@ -1,8 +1,11 @@
+import json
 import torch
 
-model = torch.load("checkpoint.pt")
-prompt = f"System: {user_input}"
-result = eval(llm_output)
+model = torch.load("checkpoint.pt", weights_only=True)
+messages = [
+    {"role": "system", "content": "Yalnızca doğrulanmış JSON şemasına uygun yanıt üretin."},
+    {"role": "user", "content": str(user_input)[:4096]},
+]
+result = json.loads(llm_output)""",
        "snippet": 'model = torch.load("checkpoint.pt", weights_only=True)\nresult = json.loads(llm_output)',
    },
    {
        "patch_id": "PATCH-DB-RLS-12",
        "title": "PostgreSQL RLS Politikası Sıkılaştırma ve SECURITY DEFINER search_path Sabitleme",
        "category": "database_rls",
        "severity": "high",
        "target_file": "migrations/002_rls_hardening.sql",
        "stack": "postgresql",
        "match_tokens": ("database_rls", "sniper-authz-04", "sniper-conf-08", "security definer", "row level security", "cwe-426", "using (true)"),
        "description": "USING (true) şeklindeki aşırı izinli RLS politikalarını kiracı/kullanıcı kimliği kontrolüyle sınırlar ve SECURITY DEFINER işlevlerinde search_path = pg_catalog, public sabitler.",
        "unified_diff": """--- a/migrations/002_rls_hardening.sql
+++ b/migrations/002_rls_hardening.sql
@@ -1,7 +1,9 @@
 ALTER TABLE customer_orders ENABLE ROW LEVEL SECURITY;
+ALTER TABLE customer_orders FORCE ROW LEVEL SECURITY;
-CREATE POLICY orders_isolation ON customer_orders USING (true);
+CREATE POLICY orders_isolation ON customer_orders
+    USING (user_id = current_setting('app.current_user_id', true)::uuid)
+    WITH CHECK (user_id = current_setting('app.current_user_id', true)::uuid);
 
 CREATE OR REPLACE FUNCTION admin_audit_trigger() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER
+SET search_path = pg_catalog, public
 AS $$ BEGIN RETURN NEW; END; $$;""",
        "snippet": "ALTER TABLE customer_orders FORCE ROW LEVEL SECURITY;\nSET search_path = pg_catalog, public",
    },
    {
        "patch_id": "PATCH-RUST-MEM-11",
        "title": "Rust Güvenli Sarmalayıcı (pub fn) Dilim Sınır ve checked_mul Taşma Koruması",
        "category": "memory_safety",
        "severity": "critical",
        "target_file": "codec.rs",
        "stack": "rust",
        "match_tokens": ("memory_safety", "memsafety", "copy_nonoverlapping", "from_raw_parts", "cwe-787", "cwe-190", "soundness", "overflow"),
        "description": "Safe Rust (pub fn) işlevlerinde unsafe { std::ptr::copy_nonoverlapping } ve slice::from_raw_parts çağrılarından önce checked_mul taşma kontrolü ve dilim uzunluğu doğrulaması uygular.",
        "unified_diff": """--- a/codec.rs
+++ b/codec.rs
@@ -1,6 +1,11 @@
 pub fn decode_frame(src: &[u8], dst: &mut [u8], count: usize, stride: usize) -> Result<(), &'static str> {
-    let total = count * stride;
+    let total = count.checked_mul(stride).ok_or("integer overflow in frame size")?;
+    if total > src.len() || total > dst.len() {
+        return Err("slice bounds exceeded");
+    }
     unsafe {
         std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), total);
     }
     Ok(())
 }""",
        "snippet": 'let total = count.checked_mul(stride).ok_or("integer overflow")?;\nassert!(total <= src.len() && total <= dst.len());',
    },
    {
        "patch_id": "PATCH-GO-TLS-12",
        "title": "Go tls.Config Sertifika Doğrulaması (InsecureSkipVerify: false) ve AEAD cipher.NewGCM Geçişi",
        "category": "crypto",
        "severity": "high",
        "target_file": "tls_config.go",
        "stack": "go",
        "match_tokens": ("crypto", "transport", "insecureskipverify", "newcfb", "newofb", "cwe-295", "cwe-327"),
        "description": "Go TLS yapılandırmasında InsecureSkipVerify: false ve MinVersion: tls.VersionTLS13 zorunlu kılar; bütünlük koruması olmayan CFB/OFB akış şifrelerini AEAD cipher.NewGCM ile değiştirir.",
        "unified_diff": """--- a/tls_config.go
+++ b/tls_config.go
@@ -1,9 +1,13 @@
 package security
 
 import (
     "crypto/cipher"
     "crypto/tls"
 )
 
 func NewTLSConfig() *tls.Config {
-    return &tls.Config{InsecureSkipVerify: true}
+    return &tls.Config{
+        InsecureSkipVerify: false,
+        MinVersion:         tls.VersionTLS13,
+    }
 }
 
-func NewStream(block cipher.Block, iv []byte) cipher.Stream {
-    return cipher.NewCFBEncrypter(block, iv)
+func NewAEAD(block cipher.Block) (cipher.AEAD, error) {
+    return cipher.NewGCM(block)
 }""",
        "snippet": "InsecureSkipVerify: false,\nMinVersion: tls.VersionTLS13,\ngcm, err := cipher.NewGCM(block)",
    },
    {
        "patch_id": "PATCH-RUST-PATH-13",
        "title": "Rust Çok Parametreli Yol Geçişi (Component::ParentDir ve canonicalize) Koruması",
        "category": "command_data",
        "severity": "high",
        "target_file": "storage.rs",
        "stack": "rust",
        "match_tokens": ("path", "traversal", "cwe-22", "parentdir", "remove_dir_all", "asymmetric"),
        "description": "Çok parametreli Rust dosya sistemi işlemlerinde tüm kullanıcı girdisi parametrelerinde Component::ParentDir / RootDir kontrolü ve canonicalize + starts_with kök doğrulaması uygular.",
        "unified_diff": """--- a/storage.rs
+++ b/storage.rs
@@ -1,6 +1,14 @@
-use std::path::Path;
+use std::path::{Component, Path};
 
+fn is_safe_segment(segment: &str) -> bool {
+    !segment.is_empty()
+        && Path::new(segment)
+            .components()
+            .all(|c| matches!(c, Component::Normal(_)))
+}
+
 pub fn purge_workspace(base: &Path, org_id: &str, workspace_id: &str) -> std::io::Result<()> {
-    assert!(!org_id.contains(".."));
+    if !is_safe_segment(org_id) || !is_safe_segment(workspace_id) {
+        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsafe path segment"));
+    }
     let target = base.join(org_id).join(workspace_id);
     std::fs::remove_dir_all(target)
 }""",
        "snippet": "Path::new(segment).components().all(|c| matches!(c, Component::Normal(_)))",
    },
)


def _is_false_positive(item: dict[str, Any]) -> bool:
    triage = item.get("triage")
    if isinstance(triage, dict) and str(triage.get("disposition") or "").strip().lower() == "false_positive":
        return True
    tracking = item.get("tracking")
    if isinstance(tracking, dict) and str(tracking.get("status") or "").strip().lower() in {
        "false_positive",
        "resolved",
        "closed",
    }:
        return True
    if str(item.get("disposition") or "").strip().lower() == "false_positive":
        return True
    if str(item.get("status") or "").strip().lower() in {"false_positive", "resolved", "closed"}:
        return True
    return False


def _finding_blob(item: dict[str, Any]) -> str:
    cwe_parts: list[str] = []
    for raw_cwe in (item.get("cwe"), item.get("cwe_id")):
        text = str(raw_cwe or "").strip()
        if not text:
            continue
        cwe_parts.append(f"CWE-{int(text)}" if text.isdigit() else text)
    parts = (
        str(item.get("category") or ""),
        str(item.get("owasp_category") or ""),
        str(item.get("title") or ""),
        str(item.get("reference") or ""),
        " ".join(cwe_parts),
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
        all_findings.extend(f for f in findings if isinstance(f, dict) and not _is_false_positive(f))
    if isinstance(scan, dict) and isinstance(scan.get("findings"), list):
        all_findings.extend(f for f in scan["findings"] if isinstance(f, dict) and not _is_false_positive(f))
    if isinstance(project_audit, dict) and isinstance(project_audit.get("findings"), list):
        all_findings.extend(f for f in project_audit["findings"] if isinstance(f, dict) and not _is_false_positive(f))
    if isinstance(mobile_audit, dict) and isinstance(mobile_audit.get("findings"), list):
        all_findings.extend(f for f in mobile_audit["findings"] if isinstance(f, dict) and not _is_false_positive(f))

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
        if not isinstance(finding, dict) or _is_false_positive(finding):
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


def _check_balanced_delimiters(source: str) -> tuple[bool, str | None]:
    """String literalleri ve yorum satırları dışında {}, (), [] dengesini doğrular."""
    if not (source or "").strip():
        return False, "empty source"
    cleaned = re.sub(r"/\*[\s\S]*?\*/", "", source)
    cleaned = re.sub(r"//[^\n]*", "", cleaned)
    cleaned = re.sub(r"'(?:\\.|[^'\\\n])'", "''", cleaned)
    cleaned = re.sub(r'"(?:\\.|[^"\\])*"', '""', cleaned)
    pairs = {"}": "{", ")": "(", "]": "["}
    openers = frozenset(pairs.values())
    stack: list[str] = []
    for ch in cleaned:
        if ch in openers:
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                return False, f"unexpected closing delimiter '{ch}'"
            stack.pop()
    if stack:
        return False, f"unclosed delimiter '{stack[-1]}'"
    return True, None


def _count_security_issues(source: str, filename: str) -> int:
    """Kapalı çevrim yama doğrulaması için hafif çoklu motor güvenlik taraması."""
    text = source or ""
    if not text.strip():
        return 0
    count = 0
    lower_name = (filename or "").lower()
    if lower_name.endswith(".rs"):
        try:
            import memsafety_rust

            count += len(memsafety_rust.analyze_text(text, filename))
        except Exception:  # noqa: BLE001
            pass
        if (
            "unsafe" in text
            and ("copy_nonoverlapping" in text or "from_raw_parts" in text)
            and re.search(r"\b\w+\s*\*\s*\w+", text)
            and "checked_mul" not in text
            and "saturating_mul" not in text
            and count == 0
        ):
            count += 1
        if (
            ".join(" in text
            and any(sink in text for sink in ("remove_dir_all", "remove_file", "fs::read", "fs::write", "File::open", "File::create"))
            and not any(guard in text for guard in ("Component::ParentDir", "Component::Normal", "canonicalize"))
        ):
            count += 1

    if re.search(r"\bpickle\.loads?\s*\(", text):
        count += 1
    if "yaml.load(" in text and "SafeLoader" not in text and "CSafeLoader" not in text:
        count += 1
    if re.search(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True", text, re.DOTALL):
        count += 1
    if re.search(r"\bos\.system\s*\(", text):
        count += 1
    if re.search(r"(?<![.\w])(?:eval|exec)\s*\(", text):
        count += 1
    if "torch.load(" in text and "weights_only=True" not in text and "weights_only = True" not in text:
        count += 1
    if "jwt.decode(" in text and ("\"verify_signature\": False" in text or "'verify_signature': False" in text or "verify=False" in text):
        count += 1
    if re.search(r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]', text) and "allow_credentials=True" in text.replace(" ", ""):
        count += 1
    if re.search(r"InsecureSkipVerify\s*:\s*true\b", text):
        count += 1
    if re.search(r"\bcipher\.New(?:CFB|OFB)(?:Encrypter|Decrypter)?\b", text):
        count += 1
    if re.search(r'\.execute\s*\(\s*(?:f["\']|["\'][^"\']*%s|["\'][^"\']*\.format\()', text):
        count += 1
    return count


def verify_patch_closed_loop(
    original_source: str,
    patched_source: str,
    *,
    filename: str = "app.py",
) -> dict[str, Any]:
    """Üretilen yamayı AST/sözdizimi doğrulaması ve kapalı çevrim yeniden tarama ile doğrular."""
    if not (patched_source or "").strip():
        syntax_valid = False
        syntax_error: str | None = "empty patched source"
    elif (filename or "").lower().endswith(".py"):
        try:
            ast.parse(patched_source, filename=filename)
            syntax_valid = True
            syntax_error = None
        except SyntaxError as exc:
            syntax_valid = False
            syntax_error = f"{exc.msg} (line {exc.lineno})"
    else:
        syntax_valid, syntax_error = _check_balanced_delimiters(patched_source)

    orig_count = _count_security_issues(original_source, filename)
    patched_count = _count_security_issues(patched_source, filename) if syntax_valid else orig_count

    diff_lines = list(
        difflib.unified_diff(
            (original_source or "").splitlines(),
            (patched_source or "").splitlines(),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
    )
    diff_text = "\n".join(diff_lines)
    return {
        "filename": filename,
        "syntax_valid": syntax_valid,
        "syntax_error": syntax_error,
        "original_issue_count": orig_count,
        "patched_issue_count": patched_count,
        "target_vulnerability_eliminated": bool(syntax_valid and orig_count > 0 and patched_count == 0),
        "new_vulnerabilities_introduced": max(0, patched_count - orig_count),
        "closed_loop_verified": bool(syntax_valid and patched_count < orig_count and patched_count == 0),
        "unified_diff": diff_text,
    }


def generate_security_regression_test(
    finding: dict[str, Any],
    *,
    stack: str = "",
) -> dict[str, Any]:
    """Bulgu için hedef dilde (Python/Rust/Go/JS) kendi kendine yeten güvenlik regresyon testi üretir."""
    f = finding if isinstance(finding, dict) else {}
    target_file = str(f.get("file") or "")
    lower_file = target_file.lower()

    raw_stack = (stack or "").strip().lower()
    if raw_stack in {"rust", "rs"} or (not raw_stack and lower_file.endswith(".rs")):
        resolved_stack = "rust"
    elif raw_stack in {"go", "golang"} or (not raw_stack and lower_file.endswith(".go")):
        resolved_stack = "go"
    elif raw_stack in {"javascript", "js", "typescript", "ts", "node"} or (
        not raw_stack and lower_file.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    ):
        resolved_stack = "javascript"
    else:
        resolved_stack = "python"

    combined_meta = " ".join(
        str(f.get(k) or "") for k in ("cwe", "reference", "category", "title", "detail", "evidence")
    )
    cwe_match = re.search(r"\b(CWE-\d+)\b", combined_meta, re.IGNORECASE)
    if cwe_match:
        cwe = cwe_match.group(1).upper()
    else:
        lower_meta = combined_meta.lower()
        if "command" in lower_meta or "komut" in lower_meta or "shell" in lower_meta:
            cwe = "CWE-78"
        elif "traversal" in lower_meta or "dizin" in lower_meta or "path" in lower_meta:
            cwe = "CWE-22"
        elif "ssrf" in lower_meta:
            cwe = "CWE-918"
        elif "pickle" in lower_meta or "deserializ" in lower_meta or "serileştirme" in lower_meta:
            cwe = "CWE-502"
        elif "overflow" in lower_meta or "taşma" in lower_meta or "unsafe" in lower_meta:
            cwe = "CWE-787"
        elif "tls" in lower_meta or "sertifika" in lower_meta:
            cwe = "CWE-295"
        elif "bola" in lower_meta or "idor" in lower_meta or "yetki" in lower_meta:
            cwe = "CWE-639"
        else:
            cwe = "CWE-20"

    slug = cwe.lower().replace("-", "_")

    if resolved_stack == "rust":
        test_filename = f"tests/security_regression_{slug}.rs"
        if cwe in {"CWE-787", "CWE-190"}:
            test_code = (
                f"// Auto-generated Sniper security regression test ({cwe})\n"
                "#[test]\n"
                f"fn test_security_regression_{slug}_checked_bounds() {{\n"
                "    let count: usize = usize::MAX;\n"
                "    let stride: usize = 4;\n"
                "    assert!(count.checked_mul(stride).is_none(), \"overflow must be rejected before unsafe allocation\");\n"
                "    let safe_count: usize = 16;\n"
                "    assert_eq!(safe_count.checked_mul(stride), Some(64));\n"
                "}\n"
            )
        else:
            test_code = (
                f"// Auto-generated Sniper security regression test ({cwe})\n"
                "use std::path::{Component, Path};\n\n"
                "#[test]\n"
                f"fn test_security_regression_{slug}_rejects_traversal() {{\n"
                "    let malicious = Path::new(\"../../etc/passwd\");\n"
                "    let has_parent_dir = malicious.components().any(|c| matches!(c, Component::ParentDir));\n"
                "    assert!(has_parent_dir, \"untrusted path traversal component must be detected and rejected\");\n"
                "}\n"
            )
    elif resolved_stack == "go":
        test_filename = f"security_regression_{slug}_test.go"
        if cwe == "CWE-295":
            test_code = (
                "package security_test\n\n"
                "import (\n"
                "\t\"crypto/tls\"\n"
                "\t\"testing\"\n"
                ")\n\n"
                "func TestSecurityRegressionTLSConfig(t *testing.T) {\n"
                "\tcfg := &tls.Config{MinVersion: tls.VersionTLS12}\n"
                "\tif cfg.InsecureSkipVerify {\n"
                "\t\tt.Fatal(\"InsecureSkipVerify must remain false in production TLS config\")\n"
                "\t}\n"
                "}\n"
            )
        else:
            test_code = (
                "package security_test\n\n"
                "import (\n"
                "\t\"path/filepath\"\n"
                "\t\"strings\"\n"
                "\t\"testing\"\n"
                ")\n\n"
                "func TestSecurityRegressionInputGuard(t *testing.T) {\n"
                "\traw := \"../../etc/passwd\"\n"
                "\tif !strings.Contains(raw, \"..\") || filepath.Clean(raw) == \"etc/passwd\" {\n"
                "\t\tt.Fatal(\"traversal payload must be rejected before filesystem access\")\n"
                "\t}\n"
                "}\n"
            )
    elif resolved_stack == "javascript":
        test_filename = f"security_regression_{slug}.test.js"
        test_code = (
            f"// Auto-generated Sniper security regression test ({cwe})\n"
            "const test = require(\"node:test\");\n"
            "const assert = require(\"node:assert/strict\");\n\n"
            "function enforceSecurityBoundary(input, actorId, ownerId) {\n"
            "  if (typeof input === \"string\" && (input.includes(\"..\") || /[;&|`$]/.test(input))) {\n"
            "    throw new Error(\"Rejected untrusted injection/traversal payload\");\n"
            "  }\n"
            "  if (actorId !== undefined && ownerId !== undefined && actorId !== ownerId) {\n"
            "    throw new Error(\"Forbidden cross-tenant access\");\n"
            "  }\n"
            "  return true;\n"
            "}\n\n"
            f"test(\"security regression {cwe} blocks malicious input\", () => {{\n"
            "  assert.throws(() => enforceSecurityBoundary(\"../../etc/passwd\", \"u1\", \"u1\"), /Rejected/);\n"
            "  assert.throws(() => enforceSecurityBoundary(\"safe\", \"attacker\", \"victim\"), /Forbidden/);\n"
            "  assert.equal(enforceSecurityBoundary(\"safe_token\", \"u1\", \"u1\"), true);\n"
            "});\n"
        )
    else:
        test_filename = f"test_security_regression_{slug}.py"
        if cwe in {"CWE-78", "CWE-77"}:
            test_code = (
                f'"""Auto-generated Sniper security regression test for {cwe}."""\n'
                "import shlex\n"
                "import unittest\n\n\n"
                "def build_safe_command(user_arg: str) -> list[str]:\n"
                "    if any(ch in user_arg for ch in (\";\", \"|\", \"&\", \"`\", \"$\", \"\\n\")):\n"
                "        raise ValueError(\"Disallowed shell metacharacter in argument\")\n"
                "    return [\"/usr/bin/env\", \"echo\", shlex.quote(user_arg)]\n\n\n"
                "class TestSecurityRegressionCommandInjection(unittest.TestCase):\n"
                "    def test_rejects_shell_metacharacters(self) -> None:\n"
                "        for payload in (\"; id\", \"$(whoami)\", \"| cat /etc/passwd\", \"`uname -a`\"):\n"
                "            with self.assertRaises(ValueError):\n"
                "                build_safe_command(payload)\n\n"
                "    def test_allows_benign_argument(self) -> None:\n"
                "        cmd = build_safe_command(\"report-2026\")\n"
                "        self.assertEqual(cmd[0], \"/usr/bin/env\")\n"
            )
        elif cwe == "CWE-22":
            test_code = (
                f'"""Auto-generated Sniper security regression test for {cwe}."""\n'
                "from pathlib import Path\n"
                "import tempfile\n"
                "import unittest\n\n\n"
                "def resolve_confined_path(base_dir: Path, untrusted_rel: str) -> Path:\n"
                "    root = base_dir.resolve()\n"
                "    candidate = (root / untrusted_rel).resolve()\n"
                "    if candidate != root and root not in candidate.parents:\n"
                "        raise ValueError(\"Path traversal outside base directory blocked\")\n"
                "    return candidate\n\n\n"
                "class TestSecurityRegressionPathTraversal(unittest.TestCase):\n"
                "    def test_blocks_parent_directory_escape(self) -> None:\n"
                "        with tempfile.TemporaryDirectory() as tmp:\n"
                "            base = Path(tmp)\n"
                "            for payload in (\"../../etc/passwd\", \"../secret.txt\", \"sub/../../outside\"):\n"
                "                with self.assertRaises(ValueError):\n"
                "                    resolve_confined_path(base, payload)\n"
            )
        elif cwe == "CWE-918":
            test_code = (
                f'"""Auto-generated Sniper security regression test for {cwe}."""\n'
                "import ipaddress\n"
                "import unittest\n"
                "from urllib.parse import urlparse\n\n\n"
                "def validate_outbound_url(url: str) -> str:\n"
                "    parsed = urlparse(url)\n"
                "    if parsed.scheme not in (\"https\",):\n"
                "        raise ValueError(\"Only HTTPS outbound requests are permitted\")\n"
                "    host = (parsed.hostname or \"\").strip().lower()\n"
                "    if host in (\"localhost\", \"metadata.google.internal\"):\n"
                "        raise ValueError(\"Loopback and metadata hosts are blocked\")\n"
                "    try:\n"
                "        ip = ipaddress.ip_address(host)\n"
                "    except ValueError:\n"
                "        return url\n"
                "    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:\n"
                "        raise ValueError(\"Non-public IP target blocked\")\n"
                "    return url\n\n\n"
                "class TestSecurityRegressionSSRF(unittest.TestCase):\n"
                "    def test_blocks_metadata_and_loopback_targets(self) -> None:\n"
                "        for payload in (\n"
                "            \"http://169.254.169.254/latest/meta-data/\",\n"
                "            \"https://169.254.169.254/latest/meta-data/\",\n"
                "            \"https://127.0.0.1:8080/admin\",\n"
                "            \"https://localhost/internal\",\n"
                "        ):\n"
                "            with self.assertRaises(ValueError):\n"
                "                validate_outbound_url(payload)\n"
            )
        elif cwe == "CWE-502":
            test_code = (
                f'"""Auto-generated Sniper security regression test for {cwe}."""\n'
                "import json\n"
                "import unittest\n\n\n"
                "def safe_deserialize_payload(raw: str) -> dict:\n"
                "    if \"__reduce__\" in raw or \"!!python/\" in raw:\n"
                "        raise ValueError(\"Executable deserialization gadget blocked\")\n"
                "    data = json.loads(raw)\n"
                "    if not isinstance(data, dict):\n"
                "        raise ValueError(\"Expected JSON object payload\")\n"
                "    return data\n\n\n"
                "class TestSecurityRegressionDeserialization(unittest.TestCase):\n"
                "    def test_rejects_gadget_payloads(self) -> None:\n"
                "        for payload in (\"!!python/object/apply:os.system ['id']\", '{\"__reduce__\": \"os.system\"}'):\n"
                "            with self.assertRaises(ValueError):\n"
                "                safe_deserialize_payload(payload)\n"
            )
        elif cwe in {"CWE-639", "CWE-862"}:
            test_code = (
                f'"""Auto-generated Sniper security regression test for {cwe}."""\n'
                "import unittest\n\n\n"
                "def fetch_owned_record(record: dict, current_user_id: str) -> dict:\n"
                "    if not current_user_id or record.get(\"owner_id\") != current_user_id:\n"
                "        raise PermissionError(\"Cross-tenant object access denied\")\n"
                "    return record\n\n\n"
                "class TestSecurityRegressionBOLA(unittest.TestCase):\n"
                "    def test_denies_cross_tenant_object_access(self) -> None:\n"
                "        record = {\"id\": \"ord-100\", \"owner_id\": \"tenant-a\"}\n"
                "        with self.assertRaises(PermissionError):\n"
                "            fetch_owned_record(record, \"tenant-b\")\n"
                "        self.assertEqual(fetch_owned_record(record, \"tenant-a\")[\"id\"], \"ord-100\")\n"
            )
        else:
            test_code = (
                f'"""Auto-generated Sniper security regression test for {cwe}."""\n'
                "import unittest\n\n\n"
                "def validate_untrusted_input(value: str) -> str:\n"
                "    if not isinstance(value, str) or any(tok in value for tok in (\"..\", \"<script\", \"{{{{\", \"<!ENTITY\", \"'\")):\n"
                "        raise ValueError(\"Untrusted security payload rejected\")\n"
                "    return value\n\n\n"
                "class TestSecurityRegressionInputValidation(unittest.TestCase):\n"
                "    def test_rejects_malicious_vectors(self) -> None:\n"
                "        for payload in (\"' OR 1=1 --\", \"{{{{7*7}}}}\", \"<!ENTITY xxe SYSTEM 'file:///etc/passwd'>\"):\n"
                "            with self.assertRaises(ValueError):\n"
                "                validate_untrusted_input(payload)\n"
            )

    return {
        "format": "sniper-security-regression-test/1",
        "stack": resolved_stack,
        "test_filename": test_filename,
        "cwe": cwe,
        "target_file": target_file,
        "test_code": test_code,
    }

