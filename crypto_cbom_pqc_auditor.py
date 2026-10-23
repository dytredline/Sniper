from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any

from project_analyzer import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, SKIP_DIRS, validate_project_path
from scanner import calculate_score, utc_now
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_CRYPTO_BYTES = 512_000

CRYPTO_SCAN_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".go", ".rs", ".java", ".kt", ".kts", ".swift", ".dart",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php",
    ".sol", ".conf", ".yaml", ".yml", ".toml", ".json", ".pem", ".crt",
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


_QUANTUM_VULNERABLE_RULES: tuple[tuple[str, str, str, re.Pattern[str], str, str, str], ...] = (
    (
        "RSA-1024",
        "pke",
        "critical",
        re.compile(
            r"(?i)(?:\bRSA[-_ ]?(?:512|1024)\b"
            r"|\bRSA\.generate\s*\(\s*(?:512|1024)\b"
            r"|\bgenerate_private_key\s*\([^\n)]*key_size\s*=\s*(?:512|1024)\b"
            r"|\bmodulusLength\s*:\s*(?:512|1024)\b)"
        ),
        "Kritik düzeyde zayıf ve kuantum-kırılgan RSA anahtar boyutu (RSA-1024/512)",
        "1024-bit veya daha kısa RSA anahtarları hem klasik faktörleme hem de Shor kuantum algoritmasına karşı kırılgan durumdadır.",
        "Kısa vadede en az 3072-bit anahtar veya NIST FIPS 203 (ML-KEM-768) / FIPS 204 (ML-DSA-65) kuantum-sonrası algoritmalara geçin.",
    ),
    (
        "RSA-2048",
        "pke",
        "medium",
        re.compile(
            r"(?i)(?:\bRSA[-_ ]?(?:2048|3072|4096)\b"
            r"|\brsa\.generate_private_key\s*\((?![^\n)]*(?:512|1024))"
            r"|\bRSA\.generate\s*\(\s*(?:2048|3072|4096)\b"
            r"|\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]"
            r"|\bBEGIN RSA PRIVATE KEY\b)"
        ),
        "Kuantum bilgisayarlara (Shor algoritması) karşı kırılgan RSA açık anahtar kriptografisi",
        "Klasik RSA açık anahtar şifreleme ve imzalama işlemleri 'Şimdi Topla, Sonra Çöz' (HNDL) ve Shor algoritması tehdidine açıktır.",
        "Anahtar değişimi için NIST FIPS 203 (ML-KEM / Kyber) hibrit yapısına ve dijital imza için FIPS 204 (ML-DSA / Dilithium) standardına geçiş planlayın.",
    ),
    (
        "ECDSA-ECC",
        "signature",
        "medium",
        re.compile(
            r"(?i)(?:\bec\.generate_private_key\b"
            r"|\bSECP(?:256R1|384R1|521R1|256K1)\b"
            r"|\bprime256v1\b|\bsecp256k1\b"
            r"|\bEd25519(?:PrivateKey)?\b"
            r"|\bECDSA\b)"
        ),
        "Kuantum-kırılgan eliptik eğri dijital imza algoritması (ECDSA / Ed25519)",
        "Eliptik eğri ayrık logaritma problemine (ECDLP) dayanan ECDSA ve Ed25519 imzaları kuantum Shor algoritmasına karşı dayanıksızdır.",
        "Dijital imzalarda NIST FIPS 204 (ML-DSA / Dilithium) veya FIPS 205 (SLH-DSA / SPHINCS+) kuantum-dirençli imzalara geçiş yapın.",
    ),
    (
        "ECDH-DH-DSA",
        "key-agree",
        "medium",
        re.compile(
            r"(?i)(?:\bECDH\b|\bDiffieHellman\b"
            r"|\bdsa\.generate_private_key\b|\bDSA\.generate\b"
            r"|\bX25519(?:PrivateKey)?\b(?!(?:Kyber|MLKEM|_Kyber)))"
        ),
        "Kuantum-kırılgan anahtar değişimi veya ayrık logaritma algoritması (ECDH / DH / DSA)",
        "Klasik Diffie-Hellman, ECDH ve DSA protokolleri 'Harvest Now, Decrypt Later' (HNDL) saldırılarına karşı kuantum güvenliği sağlamaz.",
        "Anahtar uzlaşmasında X25519Kyber768 hibrit KEM veya NIST FIPS 203 ML-KEM-768/1024 kullanın.",
    ),
)

_DEPRECATED_CLASSICAL_RULES: tuple[tuple[str, str, str, re.Pattern[str], str, str, str], ...] = (
    (
        "Weak-Hash-MD5-SHA1",
        "hash",
        "high",
        re.compile(
            r"(?i)(?:\bhashlib\.(?:md4|md5|sha1)\b"
            r"|\b(?:MD4|MD5|SHA-?1)\.new\b"
            r"|\bCryptoJS\.(?:MD5|SHA1)\b"
            r"|\bMessageDigest\.getInstance\s*\(\s*['\"](?:MD4|MD5|SHA-?1)['\"]"
            r"|\bcrypto\.createHash\s*\(\s*['\"](?:md4|md5|sha1)['\"])"
        ),
        "Kırılmış veya kullanımdan kaldırılmış kriptografik özet algoritması (MD4 / MD5 / SHA-1)",
        "MD4, MD5 ve SHA-1 çakışma (collision) saldırılarına karşı kırılmıştır; bütünlük ve imza doğrulamasında kullanılamaz.",
        "Kuantum-dirençli özetleme için SHA-384, SHA-512 veya SHA3-256; parola saklama için Argon2id kullanın.",
    ),
    (
        "Broken-Cipher-DES-RC4-ECB",
        "block-cipher",
        "critical",
        re.compile(
            r"(?i)(?:\b(?:DES|3DES|TripleDES|DESede|RC4|ARC4|Blowfish)\b"
            r"|\bmodes\.ECB\s*\("
            r"|\bAES\.MODE_ECB\b"
            r"|\bAES/ECB\b)"
        ),
        "Güvensiz simetrik şifreleme algoritması veya ECB çalışma modu (DES / 3DES / RC4 / ECB)",
        "DES, 3DES, RC4, Blowfish veya ECB modu veri gizliliğini ve bütünlüğünü koruyamaz.",
        "Simetrik şifrelemede Grover algoritmasına karşı 256-bit anahtarlı AES-256-GCM veya ChaCha20-Poly1305 AEAD kullanın.",
    ),
)

_PQC_READY_PATTERNS: tuple[tuple[str, str, int, re.Pattern[str]], ...] = (
    ("ML-KEM", "kem", 3, re.compile(r"(?i)\b(?:ML[-_]?KEM(?:[-_ ]?(?:512|768|1024))?|Kyber(?:512|768|1024)?)\b")),
    ("X25519Kyber768", "kem", 3, re.compile(r"(?i)\b(?:X25519Kyber768(?:Draft00)?|X25519[-_]MLKEM768)\b")),
    ("ML-DSA", "signature", 3, re.compile(r"(?i)\b(?:ML[-_]?DSA(?:[-_ ]?(?:44|65|87))?|Dilithium(?:2|3|5)?)\b")),
    ("SLH-DSA", "signature", 3, re.compile(r"(?i)\b(?:SLH[-_]?DSA|SPHINCS\+?)\b")),
    ("Falcon", "signature", 1, re.compile(r"(?i)\bFalcon[-_ ]?(?:512|1024)\b")),
    ("AES-256-GCM", "ae", 5, re.compile(r"(?i)\b(?:AES[-_]?256[-_]?GCM|AESGCM)\b")),
    ("ChaCha20-Poly1305", "ae", 5, re.compile(r"(?i)\bChaCha20[-_]?Poly1305\b")),
    ("SHA-384/512/SHA3", "hash", 5, re.compile(r"(?i)\b(?:sha384|sha512|sha3_256|sha3_512|SHA-384|SHA-512|SHA3-256|SHA3-512)\b")),
    ("Argon2id", "kdf", 3, re.compile(r"(?i)\bargon2(?:id)?\b")),
)


def _compute_pqc_readiness_score(
    quantum_vulnerable_count: int,
    deprecated_crypto_count: int,
    pqc_ready_count: int,
) -> int:
    if quantum_vulnerable_count == 0 and deprecated_crypto_count == 0:
        return 100
    raw = (
        100
        - (deprecated_crypto_count * 25)
        - (quantum_vulnerable_count * 18)
        + min(20, pqc_ready_count * 5)
    )
    return max(0, min(85, raw))


MAX_CBOM_OCCURRENCES_PER_ASSET = 50
MAX_CBOM_ASSET_ROWS = 1_000


def _build_cyclonedx_cbom(cbom_assets: list[dict[str, Any]]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    for asset in cbom_assets:
        component = by_name.get(asset["name"])
        if component is None:
            slug = re.sub(r"[^a-z0-9]+", "-", asset["name"].casefold()).strip("-")
            component = {
                "type": "cryptographic-asset",
                "bom-ref": f"cbom-asset-{len(components) + 1}-{slug}",
                "name": asset["name"],
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": asset["primitive"],
                        "nistQuantumSecurityLevel": asset["nist_quantum_security_level"],
                        "quantumSafe": asset["quantum_safe"],
                    },
                },
                "evidence": {"occurrences": []},
                "properties": [{"name": "sniper:occurrence_count", "value": "0"}],
            }
            by_name[asset["name"]] = component
            components.append(component)
        occurrences = component["evidence"]["occurrences"]
        count = int(component["properties"][0]["value"]) + 1
        component["properties"][0]["value"] = str(count)
        if len(occurrences) < MAX_CBOM_OCCURRENCES_PER_ASSET:
            occurrences.append({"location": asset["file"], "line": asset["line"]})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": utc_now(),
            "tools": [
                {
                    "vendor": "Sniper",
                    "name": "sniper-crypto-cbom-pqc-auditor",
                    "version": "1.0.0",
                }
            ],
        },
        "components": components,
    }


def _scan_text_for_crypto(
    raw_content: str,
    rel_file: str,
    findings: list[dict[str, Any]],
    seen_finding_keys: set[tuple[str, str, int]],
    cbom_assets: list[dict[str, Any]],
) -> tuple[int, int, int]:
    q_count = 0
    d_count = 0
    p_count = 0

    for line_no, raw_line in enumerate(raw_content.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        for asset_name, primitive, severity, pattern, title, desc, rec in _QUANTUM_VULNERABLE_RULES:
            match = pattern.search(raw_line)
            if not match:
                continue
            q_count += 1
            cbom_assets.append(
                {
                    "name": asset_name,
                    "primitive": primitive,
                    "quantum_category": "quantum_vulnerable",
                    "quantum_safe": False,
                    "nist_quantum_security_level": 0,
                    "file": rel_file,
                    "line": line_no,
                }
            )
            key = (title, rel_file, line_no)
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                findings.append(
                    _make_finding(
                        severity,
                        "crypto_pqc",
                        title,
                        desc,
                        f"{asset_name} kullanımı ({match.group(0).strip()[:64]})",
                        rec,
                        "CWE-327",
                        "SNIPER-CRYP-03",
                        file=rel_file,
                        line=line_no,
                    )
                )

        for asset_name, primitive, severity, pattern, title, desc, rec in _DEPRECATED_CLASSICAL_RULES:
            match = pattern.search(raw_line)
            if not match:
                continue
            d_count += 1
            cbom_assets.append(
                {
                    "name": asset_name,
                    "primitive": primitive,
                    "quantum_category": "deprecated_classical",
                    "quantum_safe": False,
                    "nist_quantum_security_level": 0,
                    "file": rel_file,
                    "line": line_no,
                }
            )
            key = (title, rel_file, line_no)
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                findings.append(
                    _make_finding(
                        severity,
                        "crypto",
                        title,
                        desc,
                        f"{asset_name} kullanımı ({match.group(0).strip()[:64]})",
                        rec,
                        "CWE-327",
                        "SNIPER-CRYP-03",
                        file=rel_file,
                        line=line_no,
                    )
                )

        for asset_name, primitive, nist_level, pattern in _PQC_READY_PATTERNS:
            if pattern.search(raw_line):
                p_count += 1
                cbom_assets.append(
                    {
                        "name": asset_name,
                        "primitive": primitive,
                        "quantum_category": "pqc_ready",
                        "quantum_safe": True,
                        "nist_quantum_security_level": nist_level,
                        "file": rel_file,
                        "line": line_no,
                    }
                )

    return q_count, d_count, p_count


def audit_crypto_pqc_inline(
    raw_content: str,
    *,
    filename: str = "crypto.py",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Analiz için geçerli bir kaynak kod veya yapılandırma içeriği girin.")
    if len(raw_content.encode("utf-8", errors="ignore")) > MAX_CRYPTO_BYTES:
        raise ValueError("İçerik izin verilen maksimum boyutu (512 KB) aşıyor.")

    findings: list[dict[str, Any]] = []
    seen_finding_keys: set[tuple[str, str, int]] = set()
    cbom_assets: list[dict[str, Any]] = []

    q_count, d_count, p_count = _scan_text_for_crypto(
        raw_content,
        filename,
        findings,
        seen_finding_keys,
        cbom_assets,
    )

    score, grade, counts = calculate_score(findings)
    pqc_score = _compute_pqc_readiness_score(q_count, d_count, p_count)
    cyclonedx_cbom = _build_cyclonedx_cbom(cbom_assets)

    return {
        "format": "sniper-crypto-cbom-pqc-inline-v1",
        "created_at": utc_now(),
        "filename": filename,
        "score": score,
        "grade": grade,
        "pqc_readiness_score": pqc_score,
        "quantum_vulnerable_count": q_count,
        "deprecated_crypto_count": d_count,
        "pqc_ready_count": p_count,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "counts": counts,
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "cbom_assets": cbom_assets[:MAX_CBOM_ASSET_ROWS],
        "cbom_assets_truncated": len(cbom_assets) > MAX_CBOM_ASSET_ROWS,
        "cyclonedx_cbom": cyclonedx_cbom,
        "controls_evaluated": ["SNIPER-CRYP-01", "SNIPER-CRYP-03", "SNIPER-CRYP-05"],
    }


@project_scan_scope
def audit_crypto_pqc_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots)
    findings: list[dict[str, Any]] = []
    seen_finding_keys: set[tuple[str, str, int]] = set()
    cbom_assets: list[dict[str, Any]] = []
    scanned_files = 0
    total_bytes = 0
    q_total = 0
    d_total = 0
    p_total = 0

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink():
                continue
            if path.suffix.casefold() not in CRYPTO_SCAN_EXTENSIONS:
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

            q_c, d_c, p_c = _scan_text_for_crypto(
                text,
                rel_file,
                findings,
                seen_finding_keys,
                cbom_assets,
            )
            q_total += q_c
            d_total += d_c
            p_total += p_c

    score, grade, counts = calculate_score(findings)
    pqc_score = _compute_pqc_readiness_score(q_total, d_total, p_total)
    cyclonedx_cbom = _build_cyclonedx_cbom(cbom_assets)

    return {
        "format": "sniper-crypto-cbom-pqc-audit-v1",
        "created_at": utc_now(),
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "pqc_readiness_score": pqc_score,
        "quantum_vulnerable_count": q_total,
        "deprecated_crypto_count": d_total,
        "pqc_ready_count": p_total,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "counts": counts,
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "cbom_assets": cbom_assets[:MAX_CBOM_ASSET_ROWS],
        "cbom_assets_truncated": len(cbom_assets) > MAX_CBOM_ASSET_ROWS,
        "cyclonedx_cbom": cyclonedx_cbom,
        "controls_evaluated": ["SNIPER-CRYP-01", "SNIPER-CRYP-03", "SNIPER-CRYP-05"],
    }
