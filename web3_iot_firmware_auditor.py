from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any

from project_analyzer import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, SKIP_DIRS, validate_project_path
from scanner import calculate_score, utc_now
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000

SMART_CONTRACT_EXTENSIONS = {".sol"}
IOT_FIRMWARE_EXTENSIONS = {
    ".c", ".cpp", ".cc", ".h", ".hpp", ".ino", ".conf", ".yaml", ".yml", ".ini",
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
    swc_id: str = "",
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
    if swc_id:
        item["swc_id"] = swc_id
    if file:
        item["file"] = file
        item["line"] = line
    return item


def _scan_smart_contract_text(
    raw_content: str,
    rel_file: str,
    findings: list[dict[str, Any]],
    seen_keys: set[tuple[str, str, int]],
) -> None:
    has_non_reentrant = bool(re.search(r"\bnonReentrant\b|\bReentrancyGuard\b", raw_content))
    has_nonce = bool(re.search(r"(?i)\bnonce[s]?\b", raw_content))
    has_chainid = bool(re.search(r"(?i)\b(?:chainid|chainId|DOMAIN_SEPARATOR)\b", raw_content))

    lines = raw_content.splitlines()
    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue

        if re.search(r"\.call\s*(?:\{\s*value\s*:|\.value\s*\()", raw_line):
            trailing_window = "\n".join(lines[line_no : min(len(lines), line_no + 6)])
            state_updated_after = bool(
                re.search(r"\b\w+\s*\[[^\]]+\]\s*(?:[-+]?=\s*|=)|\b(?:balance|balances|total\w*)\b[^\n]*=", trailing_window)
            )
            if not has_non_reentrant or state_updated_after:
                title = "Solidity akıllı sözleşmesinde Reentrancy (SWC-107) zafiyeti (.call{value:})"
                key = (title, rel_file, line_no)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(
                        _make_finding(
                            "critical",
                            "smart_contract",
                            title,
                            "Harici sözleşmeye .call{value:} ile ETH gönderimi nonReentrant koruması olmadan veya durum (state) güncellemesinden önce yapılıyor (SWC-107).",
                            f"Satır {line_no}: {stripped[:80]}",
                            "Checks-Effects-Interactions (CEI) desenini uygulayın; bakiye sıfırlamayı harici çağrıdan önce yapın ve OpenZeppelin ReentrancyGuard (nonReentrant) kullanın.",
                            "CWE-841",
                            "SNIPER-BUSL-01",
                            file=rel_file,
                            line=line_no,
                            swc_id="SWC-107",
                        )
                    )

        if re.search(r"\b(?:require|if)\s*\([^\n]*\btx\.origin\b|\btx\.origin\s*==|==\s*tx\.origin\b", raw_line):
            title = "Solidity akıllı sözleşmesinde tx.origin ile kimlik doğrulama (SWC-115)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "high",
                        "smart_contract",
                        title,
                        "Yetkilendirme kontrolünde tx.origin kullanılması, aracı bir sözleşme üzerinden oltalama (phishing) saldırısına yol açar (SWC-115).",
                        f"Satır {line_no}: tx.origin yetkilendirme kontrolü",
                        "Yetkilendirme ve sahiplik kontrollerinde tx.origin yerine her zaman msg.sender kullanın.",
                        "CWE-477",
                        "SNIPER-AUTH-01",
                        file=rel_file,
                        line=line_no,
                        swc_id="SWC-115",
                    )
                )

        if re.search(r"\.delegatecall\s*\(", raw_line):
            title = "Solidity sözleşmesinde tehlikeli delegatecall kullanımı (SWC-112)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "critical",
                        "smart_contract",
                        title,
                        "delegatecall hedef sözleşmenin kodunu mevcut sözleşmenin depolama (storage) bağlamında çalıştırır; hedef adres kontrolü yoksa sözleşme ele geçirilebilir (SWC-112).",
                        f"Satır {line_no}: .delegatecall(...) çağrısı",
                        "Dinamik veya kullanıcı kontrollü adreslere delegatecall yapmayın; yalnızca sabit ve doğrulanmış kütüphane/uygulama adreslerine izin verin.",
                        "CWE-284",
                        "SNIPER-AUTHZ-02",
                        file=rel_file,
                        line=line_no,
                        swc_id="SWC-112",
                    )
                )

        if re.search(r"\b(?:selfdestruct|suicide)\s*\(", raw_line):
            title = "Solidity sözleşmesinde korumasız selfdestruct / suicide çağrısı (SWC-106)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "critical",
                        "smart_contract",
                        title,
                        "selfdestruct / suicide çağrısı sözleşmeyi kalıcı olarak devre dışı bırakabilir ve zorla bakiye transferine neden olabilir (SWC-106).",
                        f"Satır {line_no}: selfdestruct/suicide çağrısı",
                        "EIP-6049/EIP-6780 uyarınca selfdestruct kullanımından kaçının; acil durdurma için OpenZeppelin Pausable desenini tercih edin.",
                        "CWE-284",
                        "SNIPER-AUTHZ-02",
                        file=rel_file,
                        line=line_no,
                        swc_id="SWC-106",
                    )
                )

        if re.search(r"\becrecover\s*\(", raw_line) and (not has_nonce or not has_chainid):
            title = "Solidity ecrecover imza doğrulamasında Nonce veya ChainId eksikliği (SWC-121 Signature Replay)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "high",
                        "smart_contract",
                        title,
                        "ecrecover ile doğrulanan imzada tek kullanımlık nonce veya block.chainid bağlaması bulunmadığından imza tekrar (replay) saldırısına açıktır (SWC-121).",
                        f"Satır {line_no}: ecrecover(...) çağrısında nonce/chainid eksik",
                        "EIP-712 yapılandırılmış veri imzalama standardını, kullanıcı bazlı artan nonce değerini ve block.chainid kontrolünü zorunlu kılın.",
                        "CWE-294",
                        "SNIPER-CRYP-06",
                        file=rel_file,
                        line=line_no,
                        swc_id="SWC-121",
                    )
                )

        if re.search(r"\b(?:block\.timestamp|blockhash|block\.difficulty|block\.prevrandao|now)\b", raw_line) and (
            re.search(r"\bkeccak256\s*\(", raw_line) or re.search(r"\bkeccak256\s*\([^\n;]*\b(?:block\.timestamp|blockhash|block\.difficulty)", raw_content)
        ):
            title = "Zincir üstü (On-Chain) tahmin edilebilir rastgelelik kaynağı (SWC-120)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "medium",
                        "smart_contract",
                        title,
                        "keccak256 içinde block.timestamp veya blockhash kullanılarak rastgele sayı üretilmesi doğrulayıcı/madenci manipülasyonuna açıktır (SWC-120).",
                        f"Satır {line_no}: block.timestamp / blockhash ile rastgelelik üretimi",
                        "Gerçek kriptografik rastgelelik için Chainlink VRF veya commit-reveal şemasını kullanın.",
                        "CWE-330",
                        "SNIPER-CRYP-03",
                        file=rel_file,
                        line=line_no,
                        swc_id="SWC-120",
                    )
                )


def audit_smart_contract_inline(
    raw_content: str,
    *,
    filename: str = "Vault.sol",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Analiz için geçerli bir akıllı sözleşme (Solidity) içeriği girin.")
    if len(raw_content.encode("utf-8", errors="ignore")) > MAX_INLINE_BYTES:
        raise ValueError("Sözleşme içeriği izin verilen maksimum boyutu (512 KB) aşıyor.")

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()
    _scan_smart_contract_text(raw_content, filename, findings, seen_keys)

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-smart-contract-audit-v1",
        "created_at": utc_now(),
        "filename": filename,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "counts": counts,
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-BUSL-01",
            "SNIPER-AUTH-01",
            "SNIPER-AUTHZ-02",
            "SNIPER-CRYP-03",
            "SNIPER-CRYP-06",
        ],
    }


def _scan_iot_firmware_text(
    raw_content: str,
    rel_file: str,
    findings: list[dict[str, Any]],
    seen_keys: set[tuple[str, str, int]],
) -> None:
    for line_no, raw_line in enumerate(raw_content.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        overflow_match = re.search(
            r"(?<![A-Za-z0-9_])(?:(gets|strcpy|strcat|sprintf|vsprintf)\s*\(|(?:s?scanf|fscanf)\s*\([^\n)]*\"%s\")",
            raw_line,
        )
        if overflow_match:
            fn_name = overflow_match.group(1) or "scanf(\"%s\")"
            title = "Gömülü C/C++ kodunda klasik bellek taşması (Buffer Overflow) fonksiyonu"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "critical",
                        "iot_firmware",
                        title,
                        f"Sınır kontrolü yapmayan '{fn_name}' çağrısı yığın/öbek bellek taşmasına (stack/heap buffer overflow) ve uzaktan kod çalıştırmaya yol açar.",
                        f"Satır {line_no}: {fn_name} çağrısı",
                        "gets yerine fgets, strcpy/strcat yerine strncpy/strlcpy ve sprintf yerine snprintf kullanın.",
                        "CWE-120",
                        "SNIPER-INPV-07",
                        file=rel_file,
                        line=line_no,
                    )
                )

        if re.search(
            r"(?<![A-Za-z0-9_])(?:printf\s*\(\s*[A-Za-z_]\w*\s*\)"
            r"|(?:fprintf|syslog)\s*\(\s*[^,]+,\s*[A-Za-z_]\w*\s*\)"
            r"|snprintf\s*\(\s*[^,]+,\s*[^,]+,\s*[A-Za-z_]\w*\s*\))",
            raw_line,
        ):
            title = "Gömülü C/C++ kodunda Biçim Dizgesi (Format String) zafiyeti"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "high",
                        "iot_firmware",
                        title,
                        "printf/syslog ailesi fonksiyona sabit biçim dizgesi (\"%s\") yerine doğrudan değişken verilmesi bellek okuma/yazma istismarına yol açar.",
                        f"Satır {line_no}: Sabit olmayan format string argümanı",
                        "Biçim fonksiyonlarında her zaman sabit biçim dizgesi (ör. printf(\"%s\", user_buf)) kullanın.",
                        "CWE-134",
                        "SNIPER-INPV-07",
                        file=rel_file,
                        line=line_no,
                    )
                )

        if re.search(r"(?i)\ballow_anonymous\s+true\b", raw_line):
            title = "MQTT Broker yapılandırmasında kimlik doğrulamasız erişim (allow_anonymous true)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "high",
                        "iot_config",
                        title,
                        "MQTT broker üzerinde allow_anonymous true ayarı yetkisiz cihazların telemetri kanallarına abone olmasına ve komut yayınlamasına izin verir.",
                        f"Satır {line_no}: allow_anonymous true",
                        "allow_anonymous false ayarlayın ve cihaz başına mTLS istemci sertifikası veya güçlü kimlik doğrulama zorunlu kılın.",
                        "CWE-284",
                        "SNIPER-INFR-01",
                        file=rel_file,
                        line=line_no,
                    )
                )

        if re.search(r"(?i)(?:\bmqtt://(?!(?:localhost|127\.0\.0\.1)\b)|\blistener\s+1883\b|\bport\s*[:=]\s*1883\b)", raw_line):
            title = "Şifresiz MQTT telemetri bağlantısı (mqtt:// veya port 1883)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "high",
                        "iot_transport",
                        title,
                        "IoT telemetri veya komut trafiğinin TLS olmadan (mqtt:// / 1883) taşınması ağ dinleme ve komut enjeksiyonuna yol açar.",
                        f"Satır {line_no}: mqtt:// veya port 1883 kullanımı",
                        "MQTT iletişimini TLS 1.2/1.3 (mqtts://, port 8883) ve karşılıklı sertifika doğrulaması (mTLS) ile şifreleyin.",
                        "CWE-284",
                        "SNIPER-CRYP-02",
                        file=rel_file,
                        line=line_no,
                    )
                )

        if re.search(r"(?i)\btopic\s+(?:readwrite|write)?\s*#", raw_line):
            title = "MQTT ACL yapılandırmasında aşırı yetkili joker konu (topic readwrite #)"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "high",
                        "iot_config",
                        title,
                        "MQTT erişim kontrol listesinde '#' joker karakteri ile tüm konulara okuma/yazma izni verilmiş.",
                        f"Satır {line_no}: {stripped[:80]}",
                        "Cihazları yalnızca kendi client-id/device-id konu ağaçlarına (ör. devices/%c/telemetry) erişecek şekilde kısıtlayın.",
                        "CWE-284",
                        "SNIPER-INFR-01",
                        file=rel_file,
                        line=line_no,
                    )
                )

        if re.search(
            r"(?i)(?:\bskip_cert_common_name_check\s*=\s*true\b"
            r"|\b(?:esp_https_ota|ota_begin|ArduinoOTA)\b[^\n]*(?:http://|insecure|skip_verify))"
            r"|(?:(?:\bota_url\b|\bfirmware_url\b)[^\n]*http://)",
            raw_line,
        ):
            title = "IoT Firmware OTA güncellemesinde imza veya sertifika doğrulaması devre dışı"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "critical",
                        "iot_firmware",
                        title,
                        "Firmware OTA güncellemesinde TLS sertifika kontrolünün atlanması veya şifresiz HTTP kullanılması sahte firmware yüklenmesine izin verir.",
                        f"Satır {line_no}: Güvensiz OTA yapılandırması",
                        "OTA paketlerini çevrimdışı özel anahtarla (ECDSA / Ed25519 / ML-DSA) imzalayın, önyükleyicide (Secure Boot) doğrulayın ve TLS doğrulamasını zorunlu kılın.",
                        "CWE-284",
                        "SNIPER-SUPP-05",
                        file=rel_file,
                        line=line_no,
                    )
                )

        if re.search(
            r"(?i)(?:\btelnetd\b|\b(?:console|ttyS\d+|ttyAMA\d+)::respawn:/bin/sh\b)",
            raw_line,
        ):
            title = "Firmware içinde açık Telnet servisi veya kimlik doğrulamasız UART root kabuğu"
            key = (title, rel_file, line_no)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    _make_finding(
                        "critical",
                        "iot_firmware",
                        title,
                        "Firmware başlatma betiğinde telnetd servisi veya seri port (UART) üzerinde doğrudan /bin/sh root kabuğu etkinleştirilmiş.",
                        f"Satır {line_no}: {stripped[:80]}",
                        "Üretim firmware derlemelerinde telnetd ve kimlik doğrulamasız UART konsol erişimini devre dışı bırakın.",
                        "CWE-284",
                        "SNIPER-INFR-01",
                        file=rel_file,
                        line=line_no,
                    )
                )


def audit_iot_firmware_inline(
    raw_content: str,
    *,
    filename: str = "firmware.c",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Analiz için geçerli bir firmware kaynak kodu veya IoT yapılandırma içeriği girin.")
    if len(raw_content.encode("utf-8", errors="ignore")) > MAX_INLINE_BYTES:
        raise ValueError("İçerik izin verilen maksimum boyutu (512 KB) aşıyor.")

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()
    _scan_iot_firmware_text(raw_content, filename, findings, seen_keys)

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-iot-firmware-audit-v1",
        "created_at": utc_now(),
        "filename": filename,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "counts": counts,
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-INPV-07",
            "SNIPER-INFR-01",
            "SNIPER-CRYP-02",
            "SNIPER-SUPP-05",
        ],
    }


@project_scan_scope
def audit_web3_and_iot_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots)
    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()
    scanned_files = 0
    sol_files = 0
    iot_files = 0
    total_bytes = 0

    all_extensions = SMART_CONTRACT_EXTENSIONS | IOT_FIRMWARE_EXTENSIONS

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink():
                continue
            suffix = path.suffix.casefold()
            if suffix not in all_extensions:
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
                with os.fdopen(fd, "rb") as handle:
                    raw = handle.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if len(raw) > MAX_FILE_BYTES or b"\x00" in raw[:4096]:
                continue
            text = raw.decode("utf-8", errors="ignore")
            scanned_files += 1
            total_bytes += len(raw)
            rel_file = str(path.relative_to(root))

            if suffix in SMART_CONTRACT_EXTENSIONS:
                sol_files += 1
                _scan_smart_contract_text(text, rel_file, findings, seen_keys)
            else:
                iot_files += 1
                _scan_iot_firmware_text(text, rel_file, findings, seen_keys)

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-web3-iot-project-audit-v1",
        "created_at": utc_now(),
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "smart_contract_files": sol_files,
        "iot_firmware_files": iot_files,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "counts": counts,
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-BUSL-01",
            "SNIPER-AUTH-01",
            "SNIPER-AUTHZ-02",
            "SNIPER-CRYP-02",
            "SNIPER-CRYP-03",
            "SNIPER-CRYP-06",
            "SNIPER-INPV-07",
            "SNIPER-INFR-01",
            "SNIPER-SUPP-05",
        ],
    }
