from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from project_analyzer import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, SKIP_DIRS, validate_project_path
from scanner import calculate_score, utc_now
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_PROTOCOL_BYTES = 512_000

DESKTOP_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".json", ".toml", ".rs",
}
DESKTOP_FILENAMES = {
    "package.json", "tauri.conf.json", "cargo.toml", "main.js", "index.js", "preload.js",
}


def _make_finding(
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    *,
    file: str = "",
    line: int = 0,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "reference": cwe,
        "cwe": cwe,
        "control_id": control_id,
    }
    if file:
        item["file"] = file
        item["line"] = line
    return item


@project_scan_scope
def audit_desktop_app_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots)
    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()
    frameworks: set[str] = set()
    scanned_files = 0
    total_bytes = 0

    def add(
        severity: str,
        category: str,
        title: str,
        description: str,
        evidence: str,
        recommendation: str,
        cwe: str,
        control_id: str,
        rel_file: str,
        line_no: int,
    ) -> None:
        key = (title, rel_file, line_no)
        if key in seen_keys:
            return
        seen_keys.add(key)
        findings.append(
            _make_finding(
                severity,
                category,
                title,
                description,
                evidence,
                recommendation,
                cwe,
                control_id,
                file=rel_file,
                line=line_no,
            )
        )

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink():
                continue
            normalized = name.casefold()
            suffix = path.suffix.casefold()
            if suffix not in DESKTOP_EXTENSIONS and normalized not in DESKTOP_FILENAMES:
                continue
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            except OSError:
                continue
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
                    os.close(fd)
                    continue
                if scanned_files + 1 > MAX_FILES or total_bytes + st.st_size > MAX_TOTAL_BYTES:
                    os.close(fd)
                    break
                text = os.read(fd, st.st_size).decode("utf-8", errors="ignore")
            except OSError:
                os.close(fd)
                continue
            os.close(fd)

            scanned_files += 1
            total_bytes += st.st_size
            rel_file = str(path.relative_to(root))

            if normalized == "package.json":
                try:
                    pkg = json.loads(text)
                except json.JSONDecodeError:
                    pkg = {}
                if isinstance(pkg, dict):
                    deps = {
                        **(pkg.get("dependencies") if isinstance(pkg.get("dependencies"), dict) else {}),
                        **(pkg.get("devDependencies") if isinstance(pkg.get("devDependencies"), dict) else {}),
                    }
                    if any("electron" in k.casefold() for k in deps) or "main" in pkg:
                        if "electron" in text.casefold():
                            frameworks.add("electron")
                    if any("tauri" in k.casefold() for k in deps):
                        frameworks.add("tauri")

            if normalized == "tauri.conf.json" or (suffix == ".json" and '"tauri"' in text):
                frameworks.add("tauri")
                for line_no, raw_line in enumerate(text.splitlines(), 1):
                    if (
                        re.search(r'(?i)"all"\s*:\s*true\b', raw_line)
                        or re.search(r'(?i)"csp"\s*:\s*null\b', raw_line)
                        or re.search(r'(?i)"dangerousRemoteDomainIpcAccess"', raw_line)
                    ):
                        add(
                            "high",
                            "desktop_security",
                            "Tauri yapılandırmasında aşırı geniş allowlist veya devre dışı CSP",
                            "tauri.conf.json içinde tüm API'leri açan allowlist (all: true), devre dışı CSP (csp: null) veya tehlikeli uzak IPC erişimi saptandı.",
                            f"{rel_file}:{line_no}",
                            "Tauri allowlist izinlerini yalnızca gerekli komutlarla sınırlandırın ve katı bir CSP politikası tanımlayın.",
                            "CWE-250",
                            "SNIPER-CONF-07",
                            rel_file,
                            line_no,
                        )

            if normalized == "cargo.toml" or suffix == ".rs":
                if "tauri" in text.casefold():
                    frameworks.add("tauri")

            if suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm"}:
                if re.search(r"\b(?:BrowserWindow|ipcMain|ipcRenderer|contextBridge|electron)\b", text):
                    frameworks.add("electron")
                has_https_url_check = bool(
                    re.search(r"(?:startsWith\s*\(\s*['\"]https://['\"]|protocol\s*===\s*['\"]https:['\"])", text)
                )
                for line_no, raw_line in enumerate(text.splitlines(), 1):
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("//"):
                        continue
                    if re.search(r"\bnodeIntegration\s*:\s*true\b", raw_line):
                        frameworks.add("electron")
                        add(
                            "critical",
                            "desktop_security",
                            "Electron penceresinde nodeIntegration: true etkin (Uzaktan Kod Çalıştırma riski)",
                            "Renderer sürecinde Node.js API'lerine doğrudan erişim (nodeIntegration: true) etkinleştirilmiş; olası bir XSS doğrudan RCE'ye dönüşebilir.",
                            f"{rel_file}:{line_no}",
                            "nodeIntegration: false ayarlayın ve yalnızca güvenli contextBridge API'lerini preload üzerinden açın.",
                            "CWE-250",
                            "SNIPER-CLNT-01",
                            rel_file,
                            line_no,
                        )
                    if re.search(r"\bcontextIsolation\s*:\s*false\b", raw_line):
                        frameworks.add("electron")
                        add(
                            "high",
                            "desktop_security",
                            "Electron penceresinde contextIsolation devre dışı",
                            "contextIsolation: false ayarı preload betiği ile web içeriğinin aynı global nesneyi paylaşmasına yol açar.",
                            f"{rel_file}:{line_no}",
                            "contextIsolation: true ayarını zorunlu kılın ve iletişim için contextBridge.exposeInMainWorld kullanın.",
                            "CWE-668",
                            "SNIPER-CLNT-01",
                            rel_file,
                            line_no,
                        )
                    if re.search(r"\b(?:webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true)\b", raw_line):
                        frameworks.add("electron")
                        add(
                            "high",
                            "desktop_security",
                            "Electron webSecurity devre dışı veya güvensiz içerik çalıştırma açık",
                            "Same-Origin Policy (webSecurity: false) kapatılmış veya HTTPS içinden şifresiz içerik yüklemeye izin verilmiş.",
                            f"{rel_file}:{line_no}",
                            "webSecurity: true ve allowRunningInsecureContent: false ayarlarını koruyun.",
                            "CWE-346",
                            "SNIPER-CONF-07",
                            rel_file,
                            line_no,
                        )
                    if re.search(r"\b(?:enableRemoteModule\s*:\s*true|sandbox\s*:\s*false)\b", raw_line):
                        frameworks.add("electron")
                        add(
                            "medium",
                            "desktop_security",
                            "Electron sandbox devre dışı veya eski remote modülü açık",
                            "Renderer işleminin işletim sistemi sanal alanı (sandbox: false) devre dışı bırakılmış veya güvenli olmayan remote modülü açılmış.",
                            f"{rel_file}:{line_no}",
                            "sandbox: true ayarını etkinleştirin ve enableRemoteModule yerine güvenli IPC kanalları kullanın.",
                            "CWE-250",
                            "SNIPER-CLNT-01",
                            rel_file,
                            line_no,
                        )
                    if re.search(r"\bshell\.openExternal\s*\(", raw_line) and not has_https_url_check:
                        frameworks.add("electron")
                        add(
                            "high",
                            "desktop_security",
                            "Electron shell.openExternal çağrısında protokol/URL doğrulaması eksik",
                            "shell.openExternal çağrısına verilen URL'nin yalnızca güvenli https:// şemasına ait olduğu doğrulanmıyor; file:// veya özel protokollerle komut çalıştırılabilir.",
                            f"{rel_file}:{line_no}",
                            "shell.openExternal öncesinde URL'yi new URL() ile ayrıştırıp yalnızca https: protokolüne izin verin.",
                            "CWE-78",
                            "SNIPER-INPV-07",
                            rel_file,
                            line_no,
                        )

    findings.sort(
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(item["severity"], 5),
            item.get("file", ""),
            item.get("line", 0),
        )
    )
    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-desktop-security-audit-v1",
        "created_at": utc_now(),
        "project": root.name,
        "project_path": str(root),
        "frameworks_detected": sorted(frameworks),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "finding_counts": counts,
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-CLNT-01",
            "SNIPER-CONF-07",
            "SNIPER-INPV-07",
            "SNIPER-SUPP-05",
        ],
    }


def audit_realtime_and_binary_protocols(
    raw_content: str,
    *,
    protocol_type: str = "auto",
    filename: str = "service.proto",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Analiz için geçerli bir protokol veya şema içeriği girin.")
    if len(raw_content.encode("utf-8", errors="ignore")) > MAX_PROTOCOL_BYTES:
        raise ValueError("Protokol içeriği izin verilen maksimum boyutu (512 KB) aşıyor.")

    requested = (protocol_type or "auto").strip().casefold()
    if requested in {"grpc", "protobuf", "proto"}:
        detected_type = "grpc"
    elif requested in {"websocket", "ws"}:
        detected_type = "websocket"
    elif requested == "webhook":
        detected_type = "webhook"
    else:
        if (
            filename.strip().casefold().endswith(".proto")
            or re.search(
                r'(?i)\bsyntax\s*=\s*["\']proto[23]["\']|\bservice\s+\w+\s*\{|\brpc\s+\w+\s*\(|\bgrpc\.insecure_channel\b|\busePlaintext\s*\(|\bWithInsecure\s*\(',
                raw_content,
            )
        ):
            detected_type = "grpc"
        elif re.search(
            r"(?i)\bws://|\bwss://|\bWebSocketServer\b|\bCheckOrigin\b|\bwebsocket\b|\bmaxPayload\b",
            raw_content,
        ):
            detected_type = "websocket"
        elif re.search(
            r"(?i)\bwebhook\b|\bX-Hub-Signature|\bStripe-Signature|\bslack-signature",
            raw_content,
        ):
            detected_type = "webhook"
        else:
            detected_type = "grpc"

    findings: list[dict[str, Any]] = []
    seen_titles: set[str] = set()

    def add_proto_finding(
        severity: str,
        category: str,
        title: str,
        description: str,
        evidence: str,
        recommendation: str,
        cwe: str,
        control_id: str,
    ) -> None:
        if title in seen_titles:
            return
        seen_titles.add(title)
        findings.append(
            _make_finding(
                severity,
                category,
                title,
                description,
                evidence,
                recommendation,
                cwe,
                control_id,
                file=filename,
            )
        )

    if detected_type == "grpc":
        if re.search(
            r"(?i)\b(?:string|bytes)\s+(?:password|passwd|secret|token|private_key|ssn|cvv|card_number|api_key)\s*=",
            raw_content,
        ):
            add_proto_finding(
                "high",
                "api_security",
                "Protobuf mesaj şemasında hassas alan adı maruziyeti",
                "Protobuf message tanımında parola, gizli anahtar veya kart numarası gibi hassas alanlar doğrudan yer alıyor.",
                "message içinde password/secret/token/private_key/cvv alanı tanımlı",
                "Hassas kimlik ve ödeme alanlarını genel yanıt mesajlarından ayırın ve alan düzeyinde maskeleme uygulayın.",
                "CWE-200",
                "SNIPER-APIT-09",
            )
        if re.search(r"\brepeated\s+\w+", raw_content) and not re.search(
            r"(?i)\b(?:page_size|page_token|limit|max_results)\b", raw_content
        ):
            add_proto_finding(
                "medium",
                "api_security",
                "gRPC/Protobuf mesajında sayfalama (pagination) olmadan sınırsız repeated alan",
                "Mesaj şemasında repeated dizi alanı bulunuyor ancak page_size/limit gibi bir üst sınır alanı tanımlanmamış.",
                "repeated alan mevcut; page_size / limit alanı görülmedi",
                "Büyük koleksiyon mesajlarında page_size ve page_token ile sayfalama sınırı zorunlu kılın.",
                "CWE-400",
                "SNIPER-APIT-05",
            )
        if re.search(
            r"(?i)\b(?:grpc\.insecure_channel|usePlaintext\s*\(|WithInsecure\s*\(|createInsecure\s*\()",
            raw_content,
        ):
            add_proto_finding(
                "high",
                "transport",
                "Şifresiz (cleartext) gRPC kanal bağlantısı",
                "gRPC istemci veya sunucu kanalında TLS şifrelemesi devre dışı bırakılmış (insecure_channel / usePlaintext / WithInsecure).",
                "grpc.insecure_channel / usePlaintext / WithInsecure kullanımı",
                "gRPC iletişiminde TLS veya mTLS (ssl_channel_credentials) zorunlu kılın.",
                "CWE-319",
                "SNIPER-CRYP-02",
            )
        if re.search(r"(?i)\b(?:ServerReflection|enable_server_reflection|reflection\.Register)\b", raw_content):
            add_proto_finding(
                "low",
                "configuration",
                "gRPC sunucu yansıması (Server Reflection) açık",
                "gRPC Server Reflection özelliği tüm servis ve mesaj şemalarının çalışma zamanında dışarıdan keşfedilmesine izin verir.",
                "ServerReflection / enable_server_reflection etkin",
                "Üretim ortamında gRPC Server Reflection özelliğini kapatın veya yalnızca yetkili iç ağlarla sınırlandırın.",
                "CWE-200",
                "SNIPER-INFO-02",
            )

    elif detected_type == "websocket":
        if re.search(r"(?i)\bws://(?!(?:localhost|127\.0\.0\.1)\b)", raw_content):
            add_proto_finding(
                "high",
                "transport",
                "Şifresiz WebSocket (ws://) bağlantısı",
                "WebSocket bağlantısı TLS olmadan şifresiz ws:// şeması üzerinden kuruluyor.",
                "ws:// bağlantı tanımı",
                "Tüm üretim WebSocket bağlantılarında wss:// (TLS) zorunlu kılın.",
                "CWE-319",
                "SNIPER-CRYP-02",
            )
        if (
            re.search(
                r"(?i)(?:CheckOrigin[^\n]*return\s+true|origins?\s*[:=]\s*['\"]\*['\"]|allowed_origins\s*=\s*\[\s*['\"]\*['\"])",
                raw_content,
            )
            or "origin" not in raw_content.casefold()
        ):
            add_proto_finding(
                "high",
                "web_hardening",
                "WebSocket Origin doğrulaması eksik (CSWSH riski)",
                "WebSocket el sıkışmasında Origin başlığı doğrulanmıyor veya tüm origin'lere izin veriliyor (Cross-Site WebSocket Hijacking).",
                "CheckOrigin => true veya Origin doğrulaması eksik",
                "WebSocket el sıkışmasında Origin başlığını güvenilir origin allowlist'i ile karşılaştırın.",
                "CWE-1385",
                "SNIPER-CLNT-07",
            )
        if not re.search(r"(?i)\b(?:maxPayload|ReadLimit|max_size|max_message_size|maxFrameSize)\b", raw_content):
            add_proto_finding(
                "medium",
                "api_security",
                "WebSocket sunucusunda maksimum mesaj boyutu (maxPayload/ReadLimit) sınırı eksik",
                "WebSocket bağlantısında gelen çerçeve/mesaj boyutu için açık bir üst sınır tanımlanmamış; bellek tüketimi (DoS) riski oluşabilir.",
                "maxPayload / ReadLimit / max_size ayarı görülmedi",
                "WebSocket sunucusunda maxPayload veya ReadLimit ile maksimum mesaj boyutunu sınırlandırın.",
                "CWE-400",
                "SNIPER-APIT-05",
            )

    elif detected_type == "webhook":
        has_constant_time = bool(
            re.search(
                r"(?i)\b(?:compare_digest|timingSafeEqual|secure_compare| hmac\.Equal|construct_event|verify_header)\b",
                raw_content,
            )
        )
        if not has_constant_time:
            add_proto_finding(
                "high",
                "crypto",
                "Webhook imza doğrulaması eksik veya sabit zamanlı karşılaştırma (compare_digest) kullanılmıyor",
                "Webhook işleyicisinde HMAC imza doğrulaması görülmedi veya zamanlama saldırısına açık standart eşitlik (==) operatörü kullanılıyor.",
                "hmac.compare_digest / crypto.timingSafeEqual doğrulaması görülmedi",
                "Webhook yükünü ham gövde (raw body) üzerinden HMAC-SHA256 ile doğrulayın ve sabit zamanlı karşılaştırma kullanın.",
                "CWE-347",
                "SNIPER-CRYP-06",
            )
        if not re.search(
            r"(?i)\b(?:timestamp|tolerance|replay|x-slack-request-timestamp|svix-timestamp|stripe-signature)\b",
            raw_content,
        ):
            add_proto_finding(
                "medium",
                "authentication",
                "Webhook işleyicisinde tekrar oynatma (replay) zaman damgası kontrolü eksik",
                "Webhook isteğinin zaman damgası (timestamp) ve kabul penceresi (ör. 5 dakika) doğrulanmıyor.",
                "Zaman damgası (timestamp/tolerance) kontrolü görülmedi",
                "Webhook başlığındaki zaman damgasını imzaya dahil edin ve eski istekleri reddedin.",
                "CWE-294",
                "SNIPER-AUTH-11",
            )

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-realtime-protocol-audit-v1",
        "created_at": utc_now(),
        "protocol_type": detected_type,
        "filename": filename,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "finding_counts": counts,
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-APIT-05",
            "SNIPER-APIT-09",
            "SNIPER-CRYP-02",
            "SNIPER-CLNT-07",
            "SNIPER-CRYP-06",
            "SNIPER-AUTH-11",
        ],
    }
