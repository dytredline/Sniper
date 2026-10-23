"""Linux sunucu CIS tarzı yapılandırma sıkılaştırma denetimi.

Yalnızca çevrimdışı dosya içeriği üzerinde statik analiz yapar: ağ erişimi,
alt süreç çalıştırma veya veritabanı yazımı yoktur. Desteklenen türler:
sshd_config, systemd *.service, sysctl, sudoers ve crontab.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable

from project_analyzer import SKIP_DIRS, validate_project_path
from safe_file_read import read_text_bounded
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500
MAX_WALKED_FILES = 50_000

HOST_CONFIG_TYPES: tuple[str, ...] = ("sshd", "systemd", "sysctl", "sudoers", "crontab", "unknown")

HOST_CONTROLS_BY_TYPE: dict[str, list[str]] = {
    "sshd": ["SNIPER-CONF-09"],
    "systemd": ["SNIPER-CONF-10"],
    "sysctl": ["SNIPER-CONF-11"],
    "sudoers": ["SNIPER-AUTHZ-05"],
    "crontab": ["SNIPER-CONF-12"],
    "unknown": [],
}

HOST_CONTROL_ORDER: list[str] = [
    "SNIPER-CONF-09",
    "SNIPER-CONF-10",
    "SNIPER-CONF-11",
    "SNIPER-CONF-12",
    "SNIPER-AUTHZ-05",
]

HOST_REFERENCES: dict[str, str] = {
    "sshd": "CIS Distribution Independent Linux Benchmark §5.2",
    "systemd": "systemd.exec(5) sandboxing / CIS §1-§5",
    "sysctl": "CIS §3.2 / §1.5",
    "sudoers": "CIS §5.3 / GTFOBins",
    "crontab": "CIS §5.1 / OWASP A08:2021",
}

# İçerik sezgisi yalnızca kaynak kod olmayan, yapılandırma benzeri dosyalarda çalışır.
_HEURISTIC_SUFFIXES = {"", ".conf", ".cfg", ".config", ".txt", ".ini", ".unit", ".tab"}
_HEURISTIC_SKIP_NAMES = {
    "readme", "license", "licence", "changelog", "makefile", "dockerfile",
    "containerfile", "notice", "authors", "contributing", "copying", "requirements.txt",
}


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


# --------------------------------------------------------------------------------------
# Tür algılama
# --------------------------------------------------------------------------------------

_SSHD_HINT_RE = re.compile(
    r"^[ \t]*(?:PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|"
    r"ChallengeResponseAuthentication|KbdInteractiveAuthentication|PubkeyAuthentication|"
    r"AuthorizedKeysFile|HostKey|UsePAM)[ \t=]",
    re.IGNORECASE | re.MULTILINE,
)
_SYSTEMD_HINT_RE = re.compile(r"^[ \t]*\[Service\][ \t]*$", re.MULTILINE)
_SYSCTL_HINT_RE = re.compile(
    r"^[ \t]*-?(?:kernel|net\.ipv4|net\.ipv6|net\.core|fs|vm)[./][A-Za-z0-9_./-]+[ \t]*=",
    re.MULTILINE,
)
_SUDOERS_HINT_RE = re.compile(
    r"(?:\bALL[ \t]*=[ \t]*\(|^[ \t]*Defaults[ \t]+!?(?:env_reset|use_pty|secure_path|mail_badpass|"
    r"logfile|requiretty|authenticate|env_keep)\b|^[ \t]*(?:User|Cmnd|Host|Runas)_Alias[ \t]+)",
    re.MULTILINE,
)

_CRON_NUM = r"[0-9*][0-9*/,\-]*"
_CRON_NAMED = r"(?:[0-9*][0-9*/,\-]*|[A-Za-z]{3}(?:[,\-][A-Za-z]{3})*)"
_CRON_JOB_RE = re.compile(
    r"^\s*(?:@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|"
    rf"{_CRON_NUM}\s+{_CRON_NUM}\s+{_CRON_NUM}\s+{_CRON_NAMED}\s+{_CRON_NAMED})"
    r"\s+(?P<command>\S.*)$",
    re.IGNORECASE,
)


def _normalized_parts(filename: str) -> tuple[str, list[str]]:
    text = (filename or "").replace("\\", "/").strip().lower()
    parts = [part for part in text.split("/") if part and part != "."]
    if not parts:
        return "", []
    return parts[-1], parts[:-1]


def _detect_by_filename(filename: str) -> str:
    name, parents = _normalized_parts(filename)
    if not name:
        return "unknown"
    parent = parents[-1] if parents else ""
    if name == "sshd_config" or name.endswith(".sshd_config") or (
        parent == "sshd_config.d" and name.endswith(".conf")
    ):
        return "sshd"
    if name.endswith(".service"):
        return "systemd"
    if name == "sysctl.conf" or (parent == "sysctl.d" and name.endswith(".conf")):
        return "sysctl"
    if name == "sudoers" or parent == "sudoers.d":
        return "sudoers"
    if (
        name == "crontab"
        or parent in {"cron.d", "crontabs"}
        or name.endswith(".cron")
        or name.endswith(".crontab")
    ):
        return "crontab"
    return "unknown"


def _heuristics_allowed(filename: str) -> bool:
    name, _parents = _normalized_parts(filename)
    if not name or name in _HEURISTIC_SKIP_NAMES:
        return False
    return PurePosixPath(name).suffix in _HEURISTIC_SUFFIXES


def detect_config_type(filename: str, raw_content: str) -> str:
    """Dosya adı (öncelikli) ve içerik sezgisiyle yapılandırma türünü döndürür."""
    clean_name = filename if isinstance(filename, str) else ""
    by_name = _detect_by_filename(clean_name)
    if by_name != "unknown":
        return by_name
    if not isinstance(raw_content, str) or not raw_content.strip():
        return "unknown"
    if clean_name.strip() and not _heuristics_allowed(clean_name):
        return "unknown"
    sample = raw_content[:65_536]
    if "\x00" in sample:
        return "unknown"
    if _SYSTEMD_HINT_RE.search(sample):
        return "systemd"
    if _SSHD_HINT_RE.search(sample):
        return "sshd"
    if _SUDOERS_HINT_RE.search(sample):
        return "sudoers"
    if _SYSCTL_HINT_RE.search(sample):
        return "sysctl"
    for line in sample.splitlines()[:400]:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and _CRON_JOB_RE.match(stripped):
            return "crontab"
    return "unknown"


# --------------------------------------------------------------------------------------
# Bulgu üretimi
# --------------------------------------------------------------------------------------

def _make_host_finding(
    *,
    config_type: str,
    check_id: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
) -> dict[str, Any]:
    clean_ev = (evidence or "").strip()[:320]
    reference = f"{HOST_REFERENCES.get(config_type, 'CIS Linux Benchmark')} · {cwe}"
    item = _finding(
        severity,
        "infrastructure",
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, check_id),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    item["check_id"] = check_id
    item["config_type"] = config_type
    return item


class _CheckCollector:
    def __init__(self, config_type: str, filename: str) -> None:
        self.config_type = config_type
        self.filename = filename
        self.findings: list[dict[str, Any]] = []
        self.evaluated: list[str] = []
        self.failed: set[str] = set()
        self._seen: set[tuple[str, int]] = set()

    def evaluate(self, check_id: str) -> None:
        if check_id not in self.evaluated:
            self.evaluated.append(check_id)

    def fail(
        self,
        check_id: str,
        *,
        severity: str,
        title: str,
        description: str,
        evidence: str,
        recommendation: str,
        cwe: str,
        control_id: str,
        line: int,
    ) -> None:
        self.evaluate(check_id)
        self.failed.add(check_id)
        key = (check_id, int(line))
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(
            _make_host_finding(
                config_type=self.config_type,
                check_id=check_id,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                cwe=cwe,
                control_id=control_id,
                filename=self.filename,
                line=int(line),
            )
        )

    def passed(self) -> list[str]:
        return [check for check in self.evaluated if check not in self.failed]


def _logical_lines(raw: str, comment_prefixes: tuple[str, ...] = ("#",)) -> list[tuple[int, str]]:
    """Ters eğik çizgiyle devam eden satırları birleştirir; yorum ve boş satırları atlar."""
    logical: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for index, raw_line in enumerate(raw.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(comment_prefixes):
            if buffer and not stripped:
                logical.append((start, buffer.strip()))
                buffer = ""
            continue
        if not buffer:
            start = index
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        logical.append((start, buffer.strip()))
        buffer = ""
    if buffer.strip():
        logical.append((start, buffer.strip()))
    return logical


# Uzak içerik indirip kabuğa aktaran komutlar (curl ... | sh, bash <(curl ...)).
_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:[\w./-]*/)?(?:ba|da|z|k)?sh\b"
    r"|\b(?:ba|z|k)?sh\s+(?:-\S+\s+)*<\(\s*(?:curl|wget)\b"
)


# --------------------------------------------------------------------------------------
# sshd_config (SNIPER-CONF-09)
# --------------------------------------------------------------------------------------

_SSHD_WEAK_CIPHERS = {
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc",
    "cast128-cbc", "rijndael-cbc@lysator.liu.se",
}
_SSHD_WEAK_MAC_PREFIXES = ("hmac-md5", "hmac-sha1", "umac-64")
_SSHD_WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}
_SSHD_DIRECTIVE_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9]*)(?:[ \t]*=[ \t]*|[ \t]+)(?P<value>.*)$")
_SSHD_TIME_UNITS = {"s": 1, "m": 60, "h": 3_600, "d": 86_400, "w": 604_800}


def _parse_sshd_global(raw: str) -> dict[str, tuple[str, int, str]]:
    """İlk Match bloğundan önceki genel bölümü ayrıştırır.

    OpenSSH sshd_config(5): "Her anahtar sözcük için ilk elde edilen değer kullanılır."
    Bu nedenle aynı yönerge tekrarlanırsa ilk geçerli tanım etkin kabul edilir.
    """
    directives: dict[str, tuple[str, int, str]] = {}
    for index, raw_line in enumerate(raw.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _SSHD_DIRECTIVE_RE.match(line)
        if not match:
            continue
        key = match.group("key").lower()
        if key == "match":
            break
        value = re.split(r"\s+#", match.group("value"), maxsplit=1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1].strip()
        if not value:
            continue
        if key not in directives:
            directives[key] = (value, index, line)
    return directives


def _parse_sshd_time(value: str) -> int | None:
    text = value.strip().lower()[:32]
    if not text:
        return None
    if text.isdigit():
        return int(text)
    total = 0
    number = ""
    for char in text:
        if char.isdigit():
            number += char
        elif char in _SSHD_TIME_UNITS and number:
            total += int(number) * _SSHD_TIME_UNITS[char]
            number = ""
        else:
            return None
    if number:
        total += int(number)
    return total


def _sshd_algorithms(value: str) -> list[str]:
    text = value.strip()
    if text.startswith("-"):
        return []
    if text[:1] in {"+", "^"}:
        text = text[1:]
    return [item.strip().lower() for item in text.split(",") if item.strip()]


def _check_sshd(raw: str, col: _CheckCollector) -> None:
    control = "SNIPER-CONF-09"
    directives = _parse_sshd_global(raw)

    def get(key: str) -> tuple[str, int, str] | None:
        return directives.get(key)

    # PermitRootLogin
    col.evaluate("ssh_permit_root_login")
    item = get("permitrootlogin")
    if item and item[0].lower() in {"yes", "without-password"}:
        col.fail(
            "ssh_permit_root_login",
            severity="high",
            title="SSH: root hesabıyla doğrudan oturum açmaya izin veriliyor",
            description=(
                "PermitRootLogin parola ile (yes) veya eski 'without-password' değeriyle root girişine izin veriyor. "
                "Kaba kuvvet saldırıları doğrudan en yetkili hesabı hedefler ve denetim izi kişiye bağlanamaz."
            ),
            evidence=item[2],
            recommendation="PermitRootLogin no (zorunluysa yalnızca prohibit-password) ayarlayın; yönetimi sudo ile yapın.",
            cwe="CWE-287",
            control_id=control,
            line=item[1],
        )

    # PasswordAuthentication
    col.evaluate("ssh_password_authentication")
    item = get("passwordauthentication")
    if item and item[0].lower() == "yes":
        col.fail(
            "ssh_password_authentication",
            severity="medium",
            title="SSH: parola ile kimlik doğrulama etkin",
            description="Parola tabanlı SSH girişi kaba kuvvet ve kimlik bilgisi doldurma saldırılarına açıktır.",
            evidence=item[2],
            recommendation="PasswordAuthentication no ayarlayıp yalnızca açık anahtar (ve tercihen MFA) kullanın.",
            cwe="CWE-287",
            control_id=control,
            line=item[1],
        )

    # PermitEmptyPasswords
    col.evaluate("ssh_permit_empty_passwords")
    item = get("permitemptypasswords")
    if item and item[0].lower() == "yes":
        col.fail(
            "ssh_permit_empty_passwords",
            severity="critical",
            title="SSH: boş parolalı hesaplarla oturum açılabiliyor",
            description="PermitEmptyPasswords yes, parolası boş olan herhangi bir hesabın kimlik doğrulamasız giriş yapmasına izin verir.",
            evidence=item[2],
            recommendation="PermitEmptyPasswords no ayarlayın ve boş parolalı hesapları kilitleyin.",
            cwe="CWE-287",
            control_id=control,
            line=item[1],
        )

    # X11Forwarding
    col.evaluate("ssh_x11_forwarding")
    item = get("x11forwarding")
    if item and item[0].lower() == "yes":
        col.fail(
            "ssh_x11_forwarding",
            severity="low",
            title="SSH: X11 yönlendirme etkin",
            description="X11 yönlendirme, istemci ekranına/klavyesine erişim yüzeyi açar ve sunucularda nadiren gereklidir.",
            evidence=item[2],
            recommendation="X11Forwarding no ayarlayın.",
            cwe="CWE-16",
            control_id=control,
            line=item[1],
        )

    # MaxAuthTries
    col.evaluate("ssh_max_auth_tries")
    item = get("maxauthtries")
    if item and item[0].isdigit() and int(item[0]) > 4:
        col.fail(
            "ssh_max_auth_tries",
            severity="low",
            title="SSH: bağlantı başına kimlik doğrulama deneme sınırı yüksek",
            description=f"MaxAuthTries {item[0]}; tek bağlantıda çok sayıda parola denemesine izin verir.",
            evidence=item[2],
            recommendation="MaxAuthTries 4 veya daha düşük (ör. 3) ayarlayın.",
            cwe="CWE-287",
            control_id=control,
            line=item[1],
        )

    # Protocol
    col.evaluate("ssh_protocol_v1")
    item = get("protocol")
    if item and "1" in [token for token in re.split(r"[,\s]+", item[0]) if token]:
        col.fail(
            "ssh_protocol_v1",
            severity="critical",
            title="SSH: kırık SSH protokol sürüm 1 etkin",
            description="SSHv1 kriptografik olarak kırıktır (oturum ele geçirme, CRC saldırıları).",
            evidence=item[2],
            recommendation="Protocol satırını kaldırın veya yalnızca 'Protocol 2' kullanın; OpenSSH'ı güncelleyin.",
            cwe="CWE-326",
            control_id=control,
            line=item[1],
        )

    # Ciphers / MACs / KexAlgorithms
    algorithm_checks: list[tuple[str, str, Callable[[str], bool], str, str]] = [
        (
            "ssh_weak_ciphers",
            "ciphers",
            lambda name: name in _SSHD_WEAK_CIPHERS or name.startswith("arcfour"),
            "SSH: zayıf şifreleme algoritmaları (Ciphers) etkin",
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
        ),
        (
            "ssh_weak_macs",
            "macs",
            lambda name: name.startswith(_SSHD_WEAK_MAC_PREFIXES),
            "SSH: zayıf mesaj doğrulama kodları (MACs) etkin",
            "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
        ),
        (
            "ssh_weak_kex",
            "kexalgorithms",
            lambda name: name in _SSHD_WEAK_KEX,
            "SSH: zayıf anahtar değişim algoritmaları (KexAlgorithms) etkin",
            "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
        ),
    ]
    for check_id, key, is_weak, title, recommended in algorithm_checks:
        col.evaluate(check_id)
        item = get(key)
        if not item:
            continue
        weak = [name for name in _sshd_algorithms(item[0]) if is_weak(name)]
        if weak:
            col.fail(
                check_id,
                severity="medium",
                title=title,
                description=f"Zayıf/eskimiş algoritmalar listede: {', '.join(weak[:8])}. Bunlar CBC kehanet, SHA-1 veya küçük grup saldırılarına açıktır.",
                evidence=item[2],
                recommendation=f"Yalnızca güçlü algoritmalara izin verin, örn.: {recommended}",
                cwe="CWE-326",
                control_id=control,
                line=item[1],
            )

    # PermitUserEnvironment
    col.evaluate("ssh_permit_user_environment")
    item = get("permituserenvironment")
    if item and item[0].lower() == "yes":
        col.fail(
            "ssh_permit_user_environment",
            severity="medium",
            title="SSH: kullanıcı ortam değişkenlerine izin veriliyor",
            description="PermitUserEnvironment yes, ~/.ssh/environment ile LD_PRELOAD gibi değişkenler üzerinden kısıtlamaların atlatılmasına olanak tanır.",
            evidence=item[2],
            recommendation="PermitUserEnvironment no ayarlayın.",
            cwe="CWE-16",
            control_id=control,
            line=item[1],
        )

    # AllowTcpForwarding
    col.evaluate("ssh_allow_tcp_forwarding")
    item = get("allowtcpforwarding")
    if item and item[0].lower() in {"yes", "all"}:
        col.fail(
            "ssh_allow_tcp_forwarding",
            severity="low",
            title="SSH: TCP port yönlendirme açık",
            description="TCP yönlendirme, SSH oturumunun iç ağa tünel/pivot olarak kullanılmasına izin verir.",
            evidence=item[2],
            recommendation="Gerekmiyorsa AllowTcpForwarding no ayarlayın.",
            cwe="CWE-16",
            control_id=control,
            line=item[1],
        )

    # ClientAliveInterval
    col.evaluate("ssh_client_alive_interval")
    item = get("clientaliveinterval")
    if item is None:
        col.fail(
            "ssh_client_alive_interval",
            severity="low",
            title="SSH: boşta oturum zaman aşımı (ClientAliveInterval) tanımlı değil",
            description="Boşta kalan SSH oturumları süresiz açık kalabilir; terk edilmiş terminaller ele geçirilebilir.",
            evidence="ClientAliveInterval yönergesi bulunamadı",
            recommendation="ClientAliveInterval 300 ve ClientAliveCountMax 3 (veya daha düşük) ayarlayın.",
            cwe="CWE-16",
            control_id=control,
            line=1,
        )
    else:
        seconds = _parse_sshd_time(item[0])
        if seconds == 0:
            col.fail(
                "ssh_client_alive_interval",
                severity="low",
                title="SSH: boşta oturum zaman aşımı devre dışı (ClientAliveInterval 0)",
                description="ClientAliveInterval 0 boşta oturum denetimini kapatır.",
                evidence=item[2],
                recommendation="ClientAliveInterval 300 ve ClientAliveCountMax 3 (veya daha düşük) ayarlayın.",
                cwe="CWE-16",
                control_id=control,
                line=item[1],
            )

    # LoginGraceTime
    col.evaluate("ssh_login_grace_time")
    item = get("logingracetime")
    if item:
        seconds = _parse_sshd_time(item[0])
        if seconds is not None and (seconds == 0 or seconds > 60):
            col.fail(
                "ssh_login_grace_time",
                severity="low",
                title="SSH: oturum açma bekleme süresi (LoginGraceTime) çok uzun",
                description=(
                    "LoginGraceTime 60 saniyeden uzun veya sınırsız (0); kimliği doğrulanmamış bağlantılar "
                    "MaxStartups yuvalarını uzun süre işgal ederek hizmet reddine yol açabilir."
                ),
                evidence=item[2],
                recommendation="LoginGraceTime 60 veya daha düşük (ör. 30) ayarlayın.",
                cwe="CWE-16",
                control_id=control,
                line=item[1],
            )


# --------------------------------------------------------------------------------------
# systemd *.service (SNIPER-CONF-10)
# --------------------------------------------------------------------------------------

_TRUTHY = {"1", "yes", "true", "on"}
_FALSY = {"0", "no", "false", "off"}


def _parse_systemd(raw: str) -> tuple[dict[str, dict[str, list[tuple[str, int, str]]]], dict[str, int]]:
    sections: dict[str, dict[str, list[tuple[str, int, str]]]] = {}
    header_lines: dict[str, int] = {}
    current: str | None = None
    for line_no, text in _logical_lines(raw, ("#", ";")):
        if text.startswith("[") and text.endswith("]"):
            current = text[1:-1].strip().lower()
            sections.setdefault(current, {})
            header_lines.setdefault(current, line_no)
            continue
        if current is None or "=" not in text:
            continue
        key, value = text.split("=", 1)
        sections[current].setdefault(key.strip(), []).append((value.strip(), line_no, text))
    return sections, header_lines


def _check_systemd(raw: str, col: _CheckCollector) -> None:
    control = "SNIPER-CONF-10"
    sections, header_lines = _parse_systemd(raw)
    service = sections.get("service")
    if service is None:
        return
    header_line = header_lines.get("service", 1)

    def last(key: str) -> tuple[str, int, str] | None:
        values = service.get(key)
        return values[-1] if values else None

    dynamic = last("DynamicUser")
    dynamic_user = bool(dynamic and dynamic[0].lower() in _TRUTHY)

    # User
    col.evaluate("svc_runs_as_root")
    user = last("User")
    if not dynamic_user:
        if user is None or not user[0]:
            col.fail(
                "svc_runs_as_root",
                severity="medium",
                title="systemd: hizmet root olarak çalışıyor (User= tanımlı değil)",
                description="User= veya DynamicUser=yes olmadığında hizmet root yetkisiyle çalışır; bir açık tam sistem ele geçirmeye dönüşür.",
                evidence="[Service] bölümünde User= yok",
                recommendation="Özel, ayrıcalıksız bir User= tanımlayın veya DynamicUser=yes kullanın.",
                cwe="CWE-250",
                control_id=control,
                line=header_line,
            )
        elif user[0].lower() in {"root", "0"}:
            col.fail(
                "svc_runs_as_root",
                severity="medium",
                title="systemd: hizmet açıkça root olarak çalıştırılıyor",
                description="User=root, hizmetin gereksiz şekilde en yüksek yetkiyle çalışmasına neden olur.",
                evidence=user[2],
                recommendation="Özel, ayrıcalıksız bir User= tanımlayın veya DynamicUser=yes kullanın.",
                cwe="CWE-250",
                control_id=control,
                line=user[1],
            )

    # NoNewPrivileges
    col.evaluate("svc_no_new_privileges")
    item = last("NoNewPrivileges")
    if item is None or item[0].lower() not in _TRUTHY:
        col.fail(
            "svc_no_new_privileges",
            severity="medium",
            title="systemd: NoNewPrivileges etkin değil",
            description="NoNewPrivileges=yes olmadan hizmet süreçleri setuid/dosya yetenekleriyle ayrıcalık yükseltebilir.",
            evidence=item[2] if item else "NoNewPrivileges= tanımlı değil",
            recommendation="[Service] bölümüne NoNewPrivileges=yes ekleyin.",
            cwe="CWE-250",
            control_id=control,
            line=item[1] if item else header_line,
        )

    # PrivateTmp (DynamicUser=yes bunu örtük olarak etkinleştirir)
    col.evaluate("svc_private_tmp")
    item = last("PrivateTmp")
    if not dynamic_user and (item is None or item[0].lower() not in _TRUTHY):
        col.fail(
            "svc_private_tmp",
            severity="low",
            title="systemd: PrivateTmp etkin değil",
            description="Paylaşılan /tmp, sembolik bağlantı ve geçici dosya yarış saldırılarına zemin hazırlar.",
            evidence=item[2] if item else "PrivateTmp= tanımlı değil",
            recommendation="PrivateTmp=yes ekleyin.",
            cwe="CWE-250",
            control_id=control,
            line=item[1] if item else header_line,
        )

    # ProtectSystem
    col.evaluate("svc_protect_system")
    item = last("ProtectSystem")
    if not dynamic_user and (item is None or item[0].lower() not in {"strict", "full"}):
        col.fail(
            "svc_protect_system",
            severity="low",
            title="systemd: ProtectSystem strict/full değil",
            description="Sistem dizinleri hizmete yazılabilir kalır; ele geçirilen hizmet ikili dosyaları veya yapılandırmayı değiştirebilir.",
            evidence=item[2] if item else "ProtectSystem= tanımlı değil",
            recommendation="ProtectSystem=strict (gerekirse ReadWritePaths= ile istisnalar) kullanın.",
            cwe="CWE-250",
            control_id=control,
            line=item[1] if item else header_line,
        )

    # ProtectHome
    col.evaluate("svc_protect_home")
    item = last("ProtectHome")
    if not dynamic_user and (item is None or not item[0] or item[0].lower() in _FALSY):
        col.fail(
            "svc_protect_home",
            severity="low",
            title="systemd: ProtectHome etkin değil",
            description="Hizmet /home, /root ve /run/user altındaki kullanıcı verilerine (SSH anahtarları dahil) erişebilir.",
            evidence=item[2] if item else "ProtectHome= tanımlı değil",
            recommendation="ProtectHome=yes (veya read-only/tmpfs) ekleyin.",
            cwe="CWE-250",
            control_id=control,
            line=item[1] if item else header_line,
        )

    # CapabilityBoundingSet (boş değer = tüm yetenekleri düşür, güvenlidir)
    col.evaluate("svc_capability_bounding_set")
    if not service.get("CapabilityBoundingSet"):
        col.fail(
            "svc_capability_bounding_set",
            severity="low",
            title="systemd: CapabilityBoundingSet ile Linux yetenekleri sınırlandırılmamış",
            description="Yetenek sınırı olmadan süreç, ihtiyaç duymadığı CAP_SYS_ADMIN gibi yetenekleri kullanabilir.",
            evidence="CapabilityBoundingSet= tanımlı değil",
            recommendation="CapabilityBoundingSet= ile yalnızca gerekli yetenekleri listeleyin (hiç gerekmiyorsa boş bırakın).",
            cwe="CWE-250",
            control_id=control,
            line=header_line,
        )

    # RestrictAddressFamilies
    col.evaluate("svc_restrict_address_families")
    item = last("RestrictAddressFamilies")
    if item is None or not item[0]:
        col.fail(
            "svc_restrict_address_families",
            severity="info",
            title="systemd: RestrictAddressFamilies tanımlı değil",
            description="Hizmet her soket ailesini (AF_PACKET, AF_NETLINK vb.) açabilir; çekirdek saldırı yüzeyi gereksiz geniştir.",
            evidence=item[2] if item else "RestrictAddressFamilies= tanımlı değil",
            recommendation="RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 gibi yalnızca gerekli aileleri listeleyin.",
            cwe="CWE-250",
            control_id=control,
            line=item[1] if item else header_line,
        )

    # ExecStart* içinde curl|sh
    col.evaluate("svc_exec_remote_pipe_shell")
    for key in ("ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop"):
        for value, line_no, text in service.get(key, []):
            if _PIPE_TO_SHELL_RE.search(value):
                col.fail(
                    "svc_exec_remote_pipe_shell",
                    severity="high",
                    title="systemd: hizmet uzak betiği indirip doğrudan kabukta çalıştırıyor",
                    description="curl/wget çıktısının sh/bash'e aktarılması bütünlük doğrulaması olmadan uzak kod çalıştırır; sunucu veya DNS ele geçirilirse hizmet kötü amaçlı kod yürütür.",
                    evidence=text,
                    recommendation="Betiği paketleyin/imzalayın, sabit sürüm ve hash doğrulamasıyla yerel olarak kurun.",
                    cwe="CWE-494",
                    control_id=control,
                    line=line_no,
                )


# --------------------------------------------------------------------------------------
# sysctl (SNIPER-CONF-11)
# --------------------------------------------------------------------------------------

_SYSCTL_RULES: list[tuple[str, str, Callable[[int], bool], str, str, str, str]] = [
    (
        "sysctl_aslr", "kernel.randomize_va_space", lambda v: v != 2, "high",
        "sysctl: ASLR tam etkin değil (kernel.randomize_va_space)",
        "Adres alanı rastgeleleştirmesi 2 değil; bellek bozulması açıklarının istismarı kolaylaşır.",
        "kernel.randomize_va_space = 2 ayarlayın.",
    ),
    (
        "sysctl_ip_forward", "net.ipv4.ip_forward", lambda v: v == 1, "low",
        "sysctl: IPv4 yönlendirme etkin (net.ipv4.ip_forward)",
        "Sunucu paket yönlendiriyor. Bilgi: yönlendirici, VPN veya konteyner ana makinesinde bu gerekli olabilir; aksi hâlde ağ segmentleri arası geçişe izin verir.",
        "Yönlendirici değilse net.ipv4.ip_forward = 0 ayarlayın.",
    ),
    (
        "sysctl_ipv4_accept_redirects", "net.ipv4.conf.all.accept_redirects", lambda v: v > 0, "medium",
        "sysctl: ICMP yönlendirmeleri kabul ediliyor (IPv4)",
        "ICMP redirect kabulü, saldırganın yönlendirme tablosunu değiştirerek trafiği ortadaki adam konumuna çekmesine izin verir.",
        "net.ipv4.conf.all.accept_redirects = 0 ve net.ipv4.conf.default.accept_redirects = 0 ayarlayın.",
    ),
    (
        "sysctl_ipv6_accept_redirects", "net.ipv6.conf.all.accept_redirects", lambda v: v > 0, "medium",
        "sysctl: ICMP yönlendirmeleri kabul ediliyor (IPv6)",
        "IPv6 ICMP redirect kabulü trafiğin saldırgan üzerinden yönlendirilmesine izin verir.",
        "net.ipv6.conf.all.accept_redirects = 0 ayarlayın.",
    ),
    (
        "sysctl_send_redirects", "net.ipv4.conf.all.send_redirects", lambda v: v > 0, "low",
        "sysctl: ICMP yönlendirme gönderimi etkin",
        "Yönlendirici olmayan bir ana makinenin ICMP redirect göndermesi ağ topolojisi bilgisini sızdırır ve kötüye kullanılabilir.",
        "net.ipv4.conf.all.send_redirects = 0 ayarlayın.",
    ),
    (
        "sysctl_accept_source_route", "net.ipv4.conf.all.accept_source_route", lambda v: v > 0, "medium",
        "sysctl: kaynak yönlendirmeli paketler kabul ediliyor",
        "Source-routed paketler güvenlik duvarı ve erişim kontrollerini atlatmak için kullanılabilir.",
        "net.ipv4.conf.all.accept_source_route = 0 ayarlayın.",
    ),
    (
        "sysctl_tcp_syncookies", "net.ipv4.tcp_syncookies", lambda v: v == 0, "medium",
        "sysctl: TCP SYN çerezleri kapalı",
        "SYN cookies kapalıyken sunucu SYN flood hizmet reddi saldırılarına karşı savunmasızdır.",
        "net.ipv4.tcp_syncookies = 1 ayarlayın.",
    ),
    (
        "sysctl_dmesg_restrict", "kernel.dmesg_restrict", lambda v: v == 0, "low",
        "sysctl: çekirdek günlüğü (dmesg) ayrıcalıksız kullanıcılara açık",
        "dmesg çıktısı çekirdek adresleri ve donanım ayrıntıları sızdırarak istismarı kolaylaştırabilir.",
        "kernel.dmesg_restrict = 1 ayarlayın.",
    ),
    (
        "sysctl_kptr_restrict", "kernel.kptr_restrict", lambda v: v == 0, "low",
        "sysctl: çekirdek işaretçi adresleri gizlenmiyor",
        "kptr_restrict = 0, /proc/kallsyms vb. üzerinden çekirdek adreslerini açığa çıkarır (KASLR atlatma).",
        "kernel.kptr_restrict = 1 (veya 2) ayarlayın.",
    ),
    (
        "sysctl_suid_dumpable", "fs.suid_dumpable", lambda v: v != 0, "low",
        "sysctl: setuid programlar çekirdek dökümü (core dump) üretebiliyor",
        "Ayrıcalıklı süreçlerin bellek dökümleri parola karmaları veya anahtarlar gibi gizli verileri içerebilir.",
        "fs.suid_dumpable = 0 ayarlayın.",
    ),
    (
        "sysctl_ptrace_scope", "kernel.yama.ptrace_scope", lambda v: v == 0, "low",
        "sysctl: Yama ptrace kısıtlaması kapalı",
        "ptrace_scope = 0, aynı kullanıcıya ait herhangi bir sürece bağlanıp bellekten gizli bilgi okunmasına izin verir.",
        "kernel.yama.ptrace_scope = 1 (veya daha yüksek) ayarlayın.",
    ),
    (
        "sysctl_rp_filter", "net.ipv4.conf.all.rp_filter", lambda v: v == 0, "low",
        "sysctl: ters yol filtreleme (rp_filter) kapalı",
        "rp_filter kapalıyken sahte kaynak adresli (spoofed) paketler kabul edilir.",
        "net.ipv4.conf.all.rp_filter = 1 (katı) veya 2 (gevşek) ayarlayın.",
    ),
]


def _parse_sysctl(raw: str) -> dict[str, tuple[str, int, str]]:
    values: dict[str, tuple[str, int, str]] = {}
    for index, raw_line in enumerate(raw.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        clean_key = key.strip().lstrip("-").strip().replace("/", ".").lower()
        if not clean_key:
            continue
        values[clean_key] = (value.strip(), index, line)  # sysctl sırayla uygular: son değer geçerli
    return values


def _sysctl_int(value: str) -> int | None:
    parts = value.split()
    if not parts:
        return None
    try:
        return int(parts[0])
    except ValueError:
        return None


def _check_sysctl(raw: str, col: _CheckCollector) -> None:
    control = "SNIPER-CONF-11"
    values = _parse_sysctl(raw)
    for check_id, key, is_bad, severity, title, description, recommendation in _SYSCTL_RULES:
        item = values.get(key)
        if item is None:
            continue
        number = _sysctl_int(item[0])
        if number is None:
            continue
        col.evaluate(check_id)
        if is_bad(number):
            col.fail(
                check_id,
                severity=severity,
                title=title,
                description=description,
                evidence=item[2],
                recommendation=recommendation,
                cwe="CWE-16",
                control_id=control,
                line=item[1],
            )


# --------------------------------------------------------------------------------------
# sudoers (SNIPER-AUTHZ-05)
# --------------------------------------------------------------------------------------

_GTFO_EXACT = {
    "vi", "vim", "view", "rvim", "rview", "less", "more", "find", "awk", "gawk", "mawk",
    "nawk", "bash", "sh", "dash", "zsh", "ksh", "tar", "zip", "nmap", "env", "tee",
}
_GTFO_PREFIX_RE = re.compile(r"^(?:python|perl|ruby)[0-9.]*$")
_SUDO_BROAD_GROUPS = {
    "users", "everyone", "staff", "guest", "guests", "domain^users", "domain users",
    "authenticated^users", "nogroup", "nobody", "all",
}
_SUDO_DEFAULTS_RE = re.compile(r"^Defaults(?P<qual>[:@!>][^\s]+)?\s+(?P<body>.+)$")
_SUDO_ALIAS_RE = re.compile(r"^(?P<kind>User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias)\s+(?P<body>.+)$")
_SUDO_SPEC_RE = re.compile(
    r"^(?P<who>[^\s=,]+(?:\s*,\s*[^\s=,]+)*)\s+(?P<hosts>[^\s=,]+(?:\s*,\s*[^\s=,]+)*)\s*=\s*(?P<cmds>.+)$"
)
_SUDO_NOPASSWD_ALL_RE = re.compile(r"\bNOPASSWD\s*:(?:\s*[A-Z_]+\s*:)*\s*ALL\s*(?:,|$)")
_SUDO_PREFIX_RE = re.compile(r"^(?:\([^)]*\)\s*|[A-Z_]+\s*:\s*|[A-Z_]+=\S+\s+)")
_SUDO_LD_VARS_RE = re.compile(r"\b(?:LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)\b")


def _split_sudo_commands(cmds: str) -> list[str]:
    commands: list[str] = []
    for raw_part in cmds.split(","):
        part = raw_part.strip()
        for _ in range(16):
            match = _SUDO_PREFIX_RE.match(part)
            if not match or match.end() == 0:
                break
            part = part[match.end():].lstrip()
        if part:
            commands.append(part)
    return commands


def _gtfo_binary(command: str) -> str | None:
    if command.startswith("!"):
        return None
    tokens = command.split()
    if not tokens:
        return None
    path = tokens[0]
    if not path.startswith("/"):
        return None
    base = path.rsplit("/", 1)[-1].lower()
    stripped = re.sub(r"[*?\[\]]+$", "", base)
    if not stripped and base:
        return path  # /usr/bin/* gibi tüm dizin joker karakteri
    if stripped in _GTFO_EXACT or _GTFO_PREFIX_RE.match(stripped):
        return path
    return None


def _check_sudoers(raw: str, col: _CheckCollector) -> None:
    control = "SNIPER-AUTHZ-05"
    cwe = "CWE-269"
    has_defaults = False
    use_pty: bool | None = None
    has_logfile = False
    first_line = 1

    lines: list[tuple[int, str]] = []
    for line_no, text in _logical_lines(raw, ()):
        if text.startswith("#") and not re.match(r"^#\d+\s+\S+\s*=", text):
            continue
        lines.append((line_no, text))
    if lines:
        first_line = lines[0][0]

    for check_id in (
        "sudo_nopasswd_all",
        "sudo_broad_group_all",
        "sudo_defaults_not_authenticate",
        "sudo_env_keep_ld",
        "sudo_gtfobins_shell_escape",
    ):
        col.evaluate(check_id)

    for line_no, text in lines:
        if text.startswith(("@include", "#include")):
            continue
        defaults = _SUDO_DEFAULTS_RE.match(text)
        if defaults:
            has_defaults = True
            body = defaults.group("body")
            if "env_keep" in body and _SUDO_LD_VARS_RE.search(body):
                col.fail(
                    "sudo_env_keep_ld",
                    severity="high",
                    title="sudoers: env_keep LD_PRELOAD/LD_LIBRARY_PATH koruyor",
                    description="Dinamik bağlayıcı değişkenlerinin sudo üzerinden korunması, izin verilen herhangi bir komutla kötü amaçlı kütüphaneyi root olarak yükleyip ayrıcalık yükseltmeye izin verir.",
                    evidence=text,
                    recommendation="env_keep listesinden LD_* değişkenlerini kaldırın; env_reset varsayılanını koruyun.",
                    cwe=cwe,
                    control_id=control,
                    line=line_no,
                )
            for token in (t.strip() for t in body.split(",")):
                normalized = re.sub(r"\s+", "", token)
                if normalized == "use_pty":
                    use_pty = True
                elif normalized == "!use_pty":
                    use_pty = False
                elif normalized.startswith("logfile="):
                    has_logfile = True
                elif normalized == "!authenticate":
                    col.fail(
                        "sudo_defaults_not_authenticate",
                        severity="critical",
                        title="sudoers: 'Defaults !authenticate' ile parola sorgusu tamamen kapalı",
                        description="Kimlik doğrulama kapatıldığında sudo hakkı olan herhangi bir oturum (ör. ele geçirilmiş bir hizmet hesabı) parola olmadan root olur.",
                        evidence=text,
                        recommendation="'!authenticate' satırını kaldırın; istisna gerekiyorsa tek komut için dar kapsamlı tanımlayın.",
                        cwe=cwe,
                        control_id=control,
                        line=line_no,
                    )
            continue

        alias = _SUDO_ALIAS_RE.match(text)
        if alias:
            if alias.group("kind") in {"Cmnd_Alias", "Cmd_Alias"} and "=" in alias.group("body"):
                command_text = alias.group("body").split("=", 1)[1]
                for command in _split_sudo_commands(command_text):
                    binary = _gtfo_binary(command)
                    if binary:
                        col.fail(
                            "sudo_gtfobins_shell_escape",
                            severity="high",
                            title="sudoers: kabuk kaçışına izin veren komut yetkilendirilmiş (GTFOBins)",
                            description=f"'{binary}' sudo ile çalıştırıldığında kabuk/komut kaçışı sağlar (GTFOBins); kısıtlı komut yetkisi tam root yetkisine dönüşür.",
                            evidence=text,
                            recommendation="Bu ikiliyi sudo kurallarından çıkarın; düzenleme için sudoedit, belirli işlemler için sabit argümanlı sarmalayıcı betik kullanın.",
                            cwe=cwe,
                            control_id=control,
                            line=line_no,
                        )
                        break
            continue

        spec = _SUDO_SPEC_RE.match(text)
        if not spec:
            continue
        cmds = spec.group("cmds")
        commands = _split_sudo_commands(cmds)

        if _SUDO_NOPASSWD_ALL_RE.search(cmds):
            col.fail(
                "sudo_nopasswd_all",
                severity="high",
                title="sudoers: parolasız tam root yetkisi (NOPASSWD: ALL)",
                description="Bu kural, ilgili hesap ele geçirildiğinde parola sorulmadan tüm komutların root olarak çalıştırılmasına izin verir.",
                evidence=text,
                recommendation="NOPASSWD'yi kaldırın veya yalnızca gerekli, tam yol ve sabit argümanlı komutlarla sınırlayın.",
                cwe=cwe,
                control_id=control,
                line=line_no,
            )

        broad = [
            who.strip()
            for who in spec.group("who").split(",")
            if who.strip().startswith("%")
            and who.strip().lstrip("%").lstrip(":").replace("\\ ", " ").lower() in _SUDO_BROAD_GROUPS
        ]
        if broad and any(command == "ALL" for command in commands):
            col.fail(
                "sudo_broad_group_all",
                severity="high",
                title="sudoers: geniş/yönetici olmayan gruba tam sudo yetkisi verilmiş",
                description=f"{', '.join(broad)} grubu tüm komutları root olarak çalıştırabiliyor; sistemdeki neredeyse her kullanıcı yönetici olur.",
                evidence=text,
                recommendation="Tam yetkiyi yalnızca özel bir yönetici grubuna (ör. %sudo/%wheel) verin; diğer gruplar için dar komut listeleri kullanın.",
                cwe=cwe,
                control_id=control,
                line=line_no,
            )

        for command in commands:
            binary = _gtfo_binary(command)
            if binary:
                col.fail(
                    "sudo_gtfobins_shell_escape",
                    severity="high",
                    title="sudoers: kabuk kaçışına izin veren komut yetkilendirilmiş (GTFOBins)",
                    description=f"'{binary}' sudo ile çalıştırıldığında kabuk/komut kaçışı sağlar (GTFOBins); kısıtlı komut yetkisi tam root yetkisine dönüşür.",
                    evidence=text,
                    recommendation="Bu ikiliyi sudo kurallarından çıkarın; düzenleme için sudoedit, belirli işlemler için sabit argümanlı sarmalayıcı betik kullanın.",
                    cwe=cwe,
                    control_id=control,
                    line=line_no,
                )
                break

    # Eksik Defaults denetimleri yalnızca ana sudoers dosyasında veya Defaults içeren dosyalarda anlamlıdır.
    name, _parents = _normalized_parts(col.filename)
    if name == "sudoers" or has_defaults:
        col.evaluate("sudo_use_pty")
        if not use_pty:
            col.fail(
                "sudo_use_pty",
                severity="low",
                title="sudoers: 'Defaults use_pty' etkin değil",
                description="use_pty olmadan sudo ile başlatılan süreçler kullanıcının terminaline TIOCSTI ile girdi enjekte edebilir ve arka planda kalabilir.",
                evidence="Defaults use_pty bulunamadı" if use_pty is None else "Defaults !use_pty",
                recommendation="'Defaults use_pty' ekleyin.",
                cwe=cwe,
                control_id=control,
                line=first_line,
            )
        col.evaluate("sudo_logfile")
        if not has_logfile:
            col.fail(
                "sudo_logfile",
                severity="info",
                title="sudoers: ayrı sudo günlük dosyası (Defaults logfile) tanımlı değil",
                description="Ayrı bir sudo günlüğü olmadan ayrıcalıklı komutların denetim izi yalnızca syslog yapılandırmasına bağlı kalır.",
                evidence="Defaults logfile=... bulunamadı",
                recommendation="'Defaults logfile=\"/var/log/sudo.log\"' ekleyin ve günlüğü merkezi sisteme iletin.",
                cwe=cwe,
                control_id=control,
                line=first_line,
            )


# --------------------------------------------------------------------------------------
# crontab (SNIPER-CONF-12)
# --------------------------------------------------------------------------------------

_CRON_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_CRON_WORLD_WRITABLE_RE = re.compile(
    r"(?:^(?:[A-Za-z_][\w.-]*\s+)?|[;&|]\s*"
    r"|\b(?:sudo\s+)?(?:sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|php|node|source|exec|nohup|nice)\s+(?:-\S+\s+)*"
    r"|(?:^|\s)\.\s+)"
    r"(?P<path>(?:/tmp|/var/tmp|/dev/shm)/[^\s;&|'\"]+)"
)
_CRON_SECRET_RES: list[re.Pattern[str]] = [
    re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mariadb|mariadb-dump)\b[^\n;|&]*?\s-p['\"]?(?P<secret>[^\s'\"$-][^\s'\"]*)"),
    re.compile(r"--password=['\"]?(?P<secret>(?!\$)[^\s'\"]+)"),
    re.compile(r"\bPGPASSWORD=['\"]?(?P<secret>(?!\$)[^\s'\";]+)"),
    re.compile(r"\bMYSQL_PWD=['\"]?(?P<secret>(?!\$)[^\s'\";]+)"),
    re.compile(r"\bsshpass\s+-p\s*['\"]?(?P<secret>(?!\$)[^\s'\"]+)"),
]


def _redact_secrets(text: str) -> str:
    redacted = text
    for regex in _CRON_SECRET_RES:
        def _mask(match: re.Match[str]) -> str:
            whole = match.group(0)
            offset = match.start()
            return whole[: match.start("secret") - offset] + "***" + whole[match.end("secret") - offset:]

        redacted = regex.sub(_mask, redacted)
    return redacted


def _check_crontab(raw: str, col: _CheckCollector) -> None:
    control = "SNIPER-CONF-12"
    for check_id in ("cron_world_writable_exec", "cron_remote_pipe_shell", "cron_plaintext_secret"):
        col.evaluate(check_id)
    for index, raw_line in enumerate(raw.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        safe_evidence = _redact_secrets(line)
        if any(regex.search(line) for regex in _CRON_SECRET_RES):
            col.fail(
                "cron_plaintext_secret",
                severity="medium",
                title="crontab: komut satırında düz metin parola",
                description="Cron girdisindeki parolalar crontab dosyasını okuyabilen herkese ve süreç listesinde (ps) diğer kullanıcılara görünür.",
                evidence=safe_evidence,
                recommendation="Parolayı ~/.my.cnf, ~/.pgpass (0600) veya bir gizli yönetim aracıyla sağlayın; komut satırına yazmayın.",
                cwe="CWE-798",
                control_id=control,
                line=index,
            )
        if _CRON_ENV_RE.match(line):
            continue
        job = _CRON_JOB_RE.match(line)
        if not job:
            continue
        command = job.group("command")
        writable = _CRON_WORLD_WRITABLE_RE.search(command)
        if writable:
            col.fail(
                "cron_world_writable_exec",
                severity="high",
                title="crontab: herkesin yazabildiği dizinden betik çalıştırılıyor",
                description=f"'{writable.group('path')}' herkesin yazabildiği bir dizinde; yerel bir kullanıcı dosyayı değiştirerek cron sahibinin (çoğu zaman root) yetkisiyle kod çalıştırabilir.",
                evidence=safe_evidence,
                recommendation="Betiği root'a ait, yalnızca sahibinin yazabildiği bir dizine (ör. /usr/local/sbin, 0755) taşıyın.",
                cwe="CWE-732",
                control_id=control,
                line=index,
            )
        if _PIPE_TO_SHELL_RE.search(command):
            col.fail(
                "cron_remote_pipe_shell",
                severity="high",
                title="crontab: uzak betik indirilip doğrudan kabukta çalıştırılıyor",
                description="Zamanlanmış görev her çalıştığında bütünlük doğrulaması olmadan uzak kod çalıştırır; uzak sunucu veya DNS ele geçirilirse kalıcı arka kapı oluşur.",
                evidence=safe_evidence,
                recommendation="Betiği yerel olarak, sabit sürüm ve hash/imza doğrulamasıyla kurun; cron yalnızca yerel dosyayı çalıştırsın.",
                cwe="CWE-494",
                control_id=control,
                line=index,
            )


_CHECKERS: dict[str, Callable[[str, _CheckCollector], None]] = {
    "sshd": _check_sshd,
    "systemd": _check_systemd,
    "sysctl": _check_sysctl,
    "sudoers": _check_sudoers,
    "crontab": _check_crontab,
}


# --------------------------------------------------------------------------------------
# Genel API
# --------------------------------------------------------------------------------------

def audit_host_config_inline(
    raw_content: str,
    *,
    filename: str = "sshd_config",
    config_type: str = "auto",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek sunucu yapılandırma içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "sshd_config"
    clean_filename = filename.strip()[:512]
    requested = config_type.strip().lower() if isinstance(config_type, str) and config_type.strip() else "auto"
    if requested == "auto":
        resolved = detect_config_type(clean_filename, raw_content)
    elif requested in HOST_CONFIG_TYPES:
        resolved = requested
    else:
        raise ValueError("Desteklenmeyen yapılandırma türü; auto, sshd, systemd, sysctl, sudoers veya crontab kullanın.")

    collector = _CheckCollector(resolved, clean_filename)
    checker = _CHECKERS.get(resolved)
    if checker is not None:
        checker(raw_content, collector)

    findings = collector.findings
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    report: dict[str, Any] = {
        "format": "sniper-host-cis-hardening-inline-v1",
        "filename": clean_filename,
        "config_type": resolved,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(HOST_CONTROLS_BY_TYPE.get(resolved, [])),
        "checks_passed": collector.passed(),
    }
    if resolved == "unknown":
        report["note"] = "Yapılandırma türü tanınamadı; CIS sıkılaştırma denetimi uygulanmadı."
    return report


@project_scan_scope
def audit_host_config_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    findings: list[dict[str, Any]] = []
    scanned_files = 0
    walked_files = 0
    type_counts: dict[str, int] = {}
    stop = False

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            if scanned_files >= MAX_PROJECT_FILES or walked_files >= MAX_WALKED_FILES:
                stop = True
                break
            walked_files += 1
            file_path = Path(current) / name
            if file_path.is_symlink():
                continue
            rel_name = file_path.relative_to(root).as_posix()
            by_name = _detect_by_filename(rel_name)
            if by_name == "unknown" and not _heuristics_allowed(rel_name):
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip():
                continue
            config_type = by_name if by_name != "unknown" else detect_config_type(rel_name, content)
            if config_type == "unknown":
                continue
            scanned_files += 1
            type_counts[config_type] = type_counts.get(config_type, 0) + 1
            file_report = audit_host_config_inline(content, filename=rel_name, config_type=config_type)
            findings.extend(file_report["findings"])
        if stop:
            break

    detected = sorted(type_counts)
    controls = [
        control
        for control in HOST_CONTROL_ORDER
        if any(control in HOST_CONTROLS_BY_TYPE[config_type] for config_type in detected)
    ]
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, PROJECT_FINDING_LIMIT)
    return {
        "format": "sniper-host-cis-hardening-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": controls,
        "config_types_detected": detected,
        "config_type_counts": dict(sorted(type_counts.items())),
    }
