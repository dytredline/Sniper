from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from project_analyzer import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, ProjectRejected, SKIP_DIRS, validate_project_path
from project_tree import ProjectTree, ProjectTreeError
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
    (
        "Unauthenticated-Stream-Cipher-CFB-OFB",
        "stream-cipher",
        "high",
        re.compile(
            r"(?i)(?:\bcipher\.NewCFB(?:Encrypter|Decrypter)\b"
            r"|\bcipher\.NewOFB\b"
            r"|\bAES\.MODE_(?:CFB|OFB)\b"
            r"|\bAES/(?:CFB|OFB)\b"
            r"|\bmodes\.(?:CFB|CFB8|OFB)\s*\()"
        ),
        "Bütünlük doğrulamasız (MAC/AEAD içermeyen) akış şifreleme modu (AES-CFB / OFB)",
        "AES-CFB ve OFB modları bütünlük doğrulaması (MAC/AEAD) içermez; değiştirilebilir şifreli metin (malleable ciphertext) ve bit-flipping saldırılarına açıktır.",
        "Kimlik doğrulamalı şifreleme (AEAD) sağlayan AES-256-GCM veya ChaCha20-Poly1305 kullanın; geriye dönük CFB/OFB yedek (fallback) yollarını kaldırın.",
    ),
    (
        "AES-128-Grover-Weak",
        "block-cipher",
        "medium",
        re.compile(
            r"(?i)\b(?:AES[-_]?128(?:[-_](?:CBC|GCM|CTR|CFB|OFB))?|aes-128-(?:cbc|gcm|ctr))\b"
        ),
        "Grover kuantum algoritmasına karşı etkin güvenliği 64-bite düşen 128-bit simetrik şifreleme (AES-128)",
        "128-bit simetrik anahtarlar Grover kuantum arama algoritması altında ~2^64 etkin güvenlik seviyesine geriler ve CNSA 2.0 kuantum-direnç eşiğini karşılamaz.",
        "Kuantum-sonrası simetrik güvenlik için 256-bit anahtarlı AES-256-GCM veya ChaCha20-Poly1305 AEAD algoritmalarına geçin.",
    ),
    (
        "Static-IV-Nonce-Reuse",
        "iv-nonce",
        "critical",
        re.compile(
            r"(?i)\b(?:iv|nonce)\s*[:=]\s*(?:b['\"](?:\\x00){4,}|['\"]0{8,}['\"]|bytes\s*\(\s*(?:12|16)\s*\)|Buffer\.alloc\s*\(\s*(?:12|16)\s*\))"
        ),
        "Sabit veya sıfır dolu IV / Nonce kullanımı (Static IV / Nonce Reuse)",
        "Şifreleme işleminde sabit veya tamamı sıfır (all-zero) IV/Nonce kullanılması AES-GCM'de kimlik doğrulama anahtarının (GHASH) ele geçirilmesine ve düz metnin açığa çıkmasına yol açar.",
        "Her şifreleme işlemi için os.urandom(12) / secrets.token_bytes(12) veya crypto.randomBytes(12) ile kriptografik olarak benzersiz IV/Nonce üretin.",
    ),
    (
        "Weak-KDF-Iterations",
        "kdf",
        "high",
        re.compile(
            r"(?i)(?:\bpbkdf2_hmac\s*\([^)\n]*,\s*[1-9]\d{0,4}\s*\)"
            r"|\bgensalt\s*\(\s*(?:rounds\s*=\s*)?[4-9]\s*\))"
        ),
        "Yetersiz anahtar türetme (KDF) iterasyon/maliyet sayısı (PBKDF2 < 100.000 / bcrypt < 10)",
        "Parola özeti veya anahtar türetme işleminde OWASP/NIST alt sınırının altında iterasyon sayısı kullanılıyor; GPU/ASIC kaba kuvvet saldırılarına karşı kırılgandır.",
        "Parola ve anahtar türetmede Argon2id (m>=64MB, t>=3) veya PBKDF2-HMAC-SHA256 için en az 600.000 iterasyon kullanın.",
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

    if (
        re.search(r"\b(?:RootCAs|AppendCertsFromPEM|NewCertPool)\b", raw_content)
        and re.search(r"\bInsecureSkipVerify\s*:\s*true\b", raw_content)
        and not re.search(r"\b(?:VerifyPeerCertificate|VerifyConnection)\s*:", raw_content)
    ):
        for line_no, raw_line in enumerate(raw_content.splitlines(), 1):
            stripped = raw_line.strip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue
            if re.search(r"\bInsecureSkipVerify\s*:\s*true\b", raw_line):
                tls_title = "Go TLS yapılandırmasında RootCAs ile InsecureSkipVerify: true mantıksal çelişkisi (sertifika doğrulama atlama)"
                key = (tls_title, rel_file, line_no)
                if key not in seen_finding_keys:
                    seen_finding_keys.add(key)
                    d_count += 1
                    cbom_assets.append(
                        {
                            "name": "TLS-RootCAs-InsecureSkipVerify-Contradiction",
                            "primitive": "tls-policy",
                            "quantum_category": "deprecated_classical",
                            "quantum_safe": False,
                            "nist_quantum_security_level": 0,
                            "file": rel_file,
                            "line": line_no,
                        }
                    )
                    findings.append(
                        _make_finding(
                            "high",
                            "crypto",
                            tls_title,
                            "tls.Config içinde özel RootCAs / sertifika havuzu tanımlanmasına rağmen InsecureSkipVerify: true bırakıldığı için Go standart kütüphanesi RootCAs doğrulamasını tamamen atlar.",
                            "RootCAs + InsecureSkipVerify: true (VerifyPeerCertificate olmadan)",
                            "InsecureSkipVerify: false yapın veya özel doğrulama gerekiyorsa VerifyConnection / VerifyPeerCertificate içinde x509.Certificate.Verify(x509.VerifyOptions{Roots: rootCAs}) çağırın.",
                            "CWE-295",
                            "SNIPER-CRYP-05",
                            file=rel_file,
                            line=line_no,
                        )
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

    try:
        with ProjectTree(str(root)) as tree:
            for directory in tree.walk(skip_dirs=tuple(SKIP_DIRS), reject_unsafe=False):
                for project_file in directory.files:
                    if project_file.path.suffix.casefold() not in CRYPTO_SCAN_EXTENSIONS:
                        continue
                    if project_file.size > MAX_FILE_BYTES:
                        continue
                    if scanned_files + 1 > MAX_FILES or total_bytes + project_file.size > MAX_TOTAL_BYTES:
                        break
                    raw = tree.read_bytes(project_file, MAX_FILE_BYTES, allow_empty=True)
                    if b"\x00" in raw[:4096]:
                        continue
                    text = raw.decode("utf-8", errors="ignore")
                    scanned_files += 1
                    total_bytes += len(raw)
                    rel_file = project_file.path.as_posix()

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
    except ProjectTreeError as exc:
        raise ProjectRejected("Proje ağacı güvenli biçimde okunamadı.") from exc

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


_PQC_SIG_TOKEN_RE = re.compile(
    r"(?i)(?:\b(?:ECDSA|Ed25519|RSA[-_]?PSS|PKCS1v15)\b|\bpadding\.(?:PSS|PKCS1v15)\b|\b(?<!ML[-_])(?<!SLH[-_])DSA\b)"
)
_PQC_KEM_TOKEN_RE = re.compile(
    r"(?i)\b(?:RSA|ECDH|DiffieHellman|DH|X25519(?!(?:Kyber|MLKEM|_Kyber|[-_]MLKEM)))\b"
)
_PQC_SYM_TOKEN_RE = re.compile(
    r"(?i)\b(?:MD4|MD5|SHA-?1|3DES|TripleDES|DES|RC4|ARC4|AES[-_]?128|MODE_ECB|MODE_CBC|ECB|CBC)\b"
)


def _classify_pqc_migration_target(
    asset_name: str,
    primitive: str,
    src_line: str,
) -> tuple[str, str, str, bool]:
    if (
        asset_name == "ECDSA-ECC"
        or primitive == "signature"
        or (
            asset_name in {"RSA-1024", "RSA-2048"}
            and _PQC_SIG_TOKEN_RE.search(src_line) is not None
        )
        or (
            asset_name == "ECDH-DH-DSA"
            and re.search(r"(?i)\bdsa\b", src_line) is not None
            and re.search(r"(?i)\b(?:ECDH|DiffieHellman|X25519)\b", src_line) is None
        )
    ):
        return (
            "digital_signature",
            "NIST FIPS 204 (ML-DSA-65 / ML-DSA-87) veya FIPS 205 (SLH-DSA)",
            "ECDSA-P256 + ML-DSA-65",
            False,
        )
    if asset_name in {"RSA-1024", "RSA-2048", "ECDH-DH-DSA"} or primitive in {
        "pke",
        "key-agree",
        "kem",
    }:
        return (
            "asymmetric_kem_key_exchange",
            "NIST FIPS 203 (ML-KEM-768 / ML-KEM-1024)",
            "X25519MLKEM768",
            True,
        )
    return (
        "weak_symmetric_or_hash",
        "CNSA 2.0 (AES-256-GCM + SHA-384 / SHA3-256)",
        "AES-256-GCM",
        True,
    )


def generate_pqc_cbom_migration_plan(
    raw_content: str,
    *,
    filename: str = "crypto.py",
) -> dict[str, Any]:
    report = audit_crypto_pqc_inline(raw_content, filename=filename)
    lines = raw_content.splitlines()
    migration_steps: list[dict[str, Any]] = []
    covered_lines: set[int] = set()

    for asset in report.get("cbom_assets", []):
        if asset.get("quantum_safe"):
            continue
        line_no = int(asset.get("line", 0))
        src_line = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
        asset_name = str(asset.get("name", "unknown"))
        primitive = str(asset.get("primitive", "unknown"))
        step_category, target_standard, hybrid_transition, hndl_vulnerable = (
            _classify_pqc_migration_target(asset_name, primitive, src_line)
        )
        covered_lines.add(line_no)
        migration_steps.append(
            {
                "asset_name": asset_name,
                "current_algorithm": asset_name,
                "primitive": primitive,
                "category": step_category,
                "file": str(asset.get("file", filename)),
                "line": line_no,
                "target_standard": target_standard,
                "hybrid_transition": hybrid_transition,
                "hndl_vulnerable": hndl_vulnerable,
            }
        )

    for line_no, raw_line in enumerate(lines, 1):
        if line_no in covered_lines:
            continue
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue
        if any(pat.search(raw_line) for _, _, _, pat in _PQC_READY_PATTERNS):
            continue
        sig_match = _PQC_SIG_TOKEN_RE.search(raw_line)
        if sig_match:
            token = sig_match.group(0)
            migration_steps.append(
                {
                    "asset_name": token,
                    "current_algorithm": token,
                    "primitive": "signature",
                    "category": "digital_signature",
                    "file": filename,
                    "line": line_no,
                    "target_standard": "NIST FIPS 204 (ML-DSA-65 / ML-DSA-87) veya FIPS 205 (SLH-DSA)",
                    "hybrid_transition": "ECDSA-P256 + ML-DSA-65",
                    "hndl_vulnerable": False,
                }
            )
            covered_lines.add(line_no)
            continue
        kem_match = _PQC_KEM_TOKEN_RE.search(raw_line)
        if kem_match:
            token = kem_match.group(0)
            migration_steps.append(
                {
                    "asset_name": token,
                    "current_algorithm": token,
                    "primitive": "key-agree",
                    "category": "asymmetric_kem_key_exchange",
                    "file": filename,
                    "line": line_no,
                    "target_standard": "NIST FIPS 203 (ML-KEM-768 / ML-KEM-1024)",
                    "hybrid_transition": "X25519MLKEM768",
                    "hndl_vulnerable": True,
                }
            )
            covered_lines.add(line_no)
            continue
        sym_match = _PQC_SYM_TOKEN_RE.search(raw_line)
        if sym_match:
            token = sym_match.group(0)
            migration_steps.append(
                {
                    "asset_name": token,
                    "current_algorithm": token,
                    "primitive": "block-cipher",
                    "category": "weak_symmetric_or_hash",
                    "file": filename,
                    "line": line_no,
                    "target_standard": "CNSA 2.0 (AES-256-GCM + SHA-384 / SHA3-256)",
                    "hybrid_transition": "AES-256-GCM",
                    "hndl_vulnerable": True,
                }
            )
            covered_lines.add(line_no)

    has_hndl = any(bool(step.get("hndl_vulnerable")) for step in migration_steps)
    if has_hndl or int(report.get("quantum_vulnerable_count", 0)) > 0:
        hndl_risk_level = "critical"
    elif int(report.get("deprecated_crypto_count", 0)) > 0 or len(migration_steps) > 0:
        hndl_risk_level = "medium"
    else:
        hndl_risk_level = "low"

    return {
        "format": "sniper-pqc-cbom-migration-plan/1",
        "filename": filename,
        "pqc_readiness_score": report["pqc_readiness_score"],
        "hndl_risk_level": hndl_risk_level,
        "cyclonedx_cbom_v1_6": report["cyclonedx_cbom"],
        "migration_step_count": len(migration_steps),
        "migration_steps": migration_steps,
    }
