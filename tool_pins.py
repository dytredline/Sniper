"""Yerel tarama araçlarının sabitlenmiş (pin) SHA-256 değerleri ve köken kayıtları.

Her değer bir resmi sürüm checksum dosyası / GitHub sürüm varlık özeti ya da bu
makinede kayıtlı, yeniden üretilebilir bir dönüşüm (kaynaktan derleme, UPX açma)
kaydıyla eşleştirildi; ayrıntılar ``source_url`` ve köken açıklamalarında.

Operatör ek bir ikiliyi ``SNIPER_<ARAÇ>_SHA256`` ortam değişkeniyle (virgülle
ayrılmış 64 haneli küçük harf onaltılık) sabitleyebilir. Bilinen geri çekilmiş
özetler ortam sabitlemesiyle yeniden etkinleştirilemez. Sabitleme yoksa araç
çalıştırılmaz.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from verified_exec import VerificationError, VerifiedExecutable, file_sha256, open_verified_executable

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OPERATOR_PROVENANCE = "operatör sabitlemesi (ortam değişkeni)"
SNIPER_TOOLS_DIR = Path.home() / ".local" / "share" / "sniper" / "tools"


@dataclass(frozen=True)
class ToolPin:
    tool: str
    label: str
    version: str
    env_binary: str
    env_sha256: str
    source_url: str
    # mimari → {sha256: köken}
    digests: dict[str, dict[str, str]] = field(default_factory=dict)
    # ortam değişkeni yoksa denenecek, Sniper'a ait kurulum yolu
    default_binary: Path | None = None
    # Bilinen güvensiz/geri çekilmiş ikililer operatör ortam sabitlemesiyle de yeniden kabul edilmez.
    revoked_digests: frozenset[str] = field(default_factory=frozenset)
    # SHA doğrulamasından sonra aynı fd-bound ikiliden okunacak sürüm sözleşmesi.
    version_args: tuple[str, ...] = ()
    version_pattern: str = ""
    supported_major: int | None = None
    minimum_version: tuple[int, ...] = ()


PINS: dict[str, ToolPin] = {
    "gitleaks": ToolPin(
        tool="gitleaks", label="Gitleaks", version="8.30.1",
        env_binary="SNIPER_GITLEAKS_BINARY", env_sha256="SNIPER_GITLEAKS_SHA256",
        source_url="https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1",
        digests={"aarch64": {
            "00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b":
                "resmi sürüm ikilisi (gitleaks_8.30.1_linux_arm64.tar.gz, checksums.txt "
                "e4a487ee…b080 ile doğrulandı)",
            "a56a110704baf742345d79eb56f8effde827c8499761f7cb2698412d100a01a9":
                "v8.30.1 etiketinden (commit 83d9cd68) güncel Go stdlib ile yerel derleme; "
                "BUILD-MANIFEST.json",
        }},
    ),
    "trufflehog": ToolPin(
        tool="trufflehog", label="TruffleHog", version="3.99.0",
        env_binary="SNIPER_TRUFFLEHOG_BINARY", env_sha256="SNIPER_TRUFFLEHOG_SHA256",
        source_url="https://github.com/trufflesecurity/trufflehog/releases/tag/v3.99.0",
        digests={"aarch64": {
            "6f6681885e3620ad0972eff26d8ce9b85d4392163597f33d5b7d05779128eb00":
                "resmi sürüm ikilisi (trufflehog_3.99.0_linux_arm64.tar.gz, cosign imzalı "
                "checksums ad6fb802…dfb7 ile doğrulandı)",
            "4cdfed417cc07a7cd3b08036ce07c87f26e8db21b82b5c7b90005f06da380a93":
                "resmi UPX paketli ikilinin (6f668188…eb00) upx 5.2.1 ile açılmış hali; "
                "UNPACKED-RUNTIME-PROVENANCE.json",
        }},
    ),
    "opengrep": ToolPin(
        tool="opengrep", label="Opengrep", version="1.30.1",
        env_binary="SNIPER_OPENGREP_BINARY", env_sha256="SNIPER_OPENGREP_SHA256",
        source_url="https://github.com/opengrep/opengrep/releases/tag/v1.30.1",
        digests={
            "aarch64": {
                "a730f6fdce1e978ea29e610a2e0503bfe1ec31fce08979a9a84e3699f03e16ee":
                    "resmi sürüm varlığı opengrep_manylinux_aarch64 (GitHub varlık özeti ve "
                    "cosign sertifika kimliği doğrulandı)",
            },
            "x86_64": {
                "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4":
                    "resmi sürüm varlığı opengrep_manylinux_x86 (GitHub varlık özeti)",
            },
        },
        default_binary=SNIPER_TOOLS_DIR / "opengrep" / "1.30.1" / "opengrep",
    ),
    # Semgrep bir Python paketi; tek bir ikiliyle sabitlenemez. Yalnız operatörün
    # SNIPER_SEMGREP_SHA256 ile açıkça sabitlediği giriş noktası kabul edilir.
    "semgrep": ToolPin(
        tool="semgrep", label="Semgrep", version="operatör",
        env_binary="SNIPER_SEMGREP_BINARY", env_sha256="SNIPER_SEMGREP_SHA256",
        source_url="https://pypi.org/project/semgrep/",
    ),
    # Joern derin analiz modunun JDK'sı (Eclipse Temurin 25 LTS; scripts/install_joern.py ile kurulur).
    "joern-jdk": ToolPin(
        tool="joern-jdk", label="Joern JDK (Temurin 25 LTS)", version="25.0.4.1+1",
        env_binary="SNIPER_JOERN_JDK_BINARY", env_sha256="SNIPER_JOERN_JDK_SHA256",
        source_url="https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.4%2B1",
        digests={"aarch64": {
            "e8201aed7118cbf3a77b9cb308a3cbe135fe97b055968b3b4797162fed1ca818":
                "resmi Temurin arşivindeki bin/java (OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.4.1_1.tar.gz, "
                "Adoptium sürüm özetiyle doğrulanan arşiv SHA-256 69df11a0…ac52)",
        }},
        default_binary=SNIPER_TOOLS_DIR / "jdk" / "25.0.4.1+1" / "bin" / "java",
        version_args=("-version",),
        version_pattern=(
            r'\Aopenjdk version "(25)\.(0)\.(4)\.(1)" 2026-08-18 LTS\r?\n'
            r'OpenJDK Runtime Environment Temurin-25\.0\.4\.1\+1 '
            r'\(build 25\.0\.4\.1\+1-LTS\)\r?\n'
            r'OpenJDK 64-Bit Server VM Temurin-25\.0\.4\.1\+1 '
            r'\(build 25\.0\.4\.1\+1-LTS, mixed mode, sharing\)\s*\Z'
        ),
        supported_major=25,
        minimum_version=(25, 0, 4, 1),
    ),
    # Yalıtılmış yerel yük testi (tool_sandbox.py): resmi k6 sürümü, bwrap içinde çalışır.
    "k6": ToolPin(
        tool="k6", label="k6", version="2.3.0",
        env_binary="SNIPER_K6_BINARY", env_sha256="SNIPER_K6_SHA256",
        source_url="https://github.com/grafana/k6/releases/tag/v2.3.0",
        digests={"aarch64": {
            "c458464bcc5e9f6e4ae9b6985286ff337cfb139a64dfe2c731a1f5d551cd601f":
                "resmi sürüm arşivindeki k6 (k6-v2.3.0-linux-arm64.tar.gz, k6-v2.3.0-checksums.txt "
                "5ca3433e…9b90 ile doğrulandı)",
        }},
        default_binary=SNIPER_TOOLS_DIR / "k6" / "2.3.0" / "k6",
    ),
    # Yalıtım katmanı: root'a ait, AppArmor sniper_bwrap profiline bağlı bubblewrap kopyası (host kurulumu).
    "bwrap": ToolPin(
        tool="bwrap", label="bubblewrap", version="0.9.0",
        env_binary="SNIPER_BWRAP_BINARY", env_sha256="SNIPER_BWRAP_SHA256",
        source_url="https://github.com/containers/bubblewrap/releases/tag/v0.9.0",
        digests={"aarch64": {
            "ae27935781511400c65ebcc0b4669775d602f46251b8707c947a1ac1b160c1c8":
                "host kurulumu /opt/sniper-bwrap/bwrap (root sahipli, 0750; Codex host devri 2026-10-20, "
                "AppArmor sniper_bwrap profili)",
        }},
        default_binary=Path("/opt/sniper-bwrap/bwrap"),
    ),
    # Yalıtılmış tarayıcı testleri (sandbox_browser_tests.py): Playwright sürücüsünü çalıştıran Node.
    "node": ToolPin(
        tool="node", label="Node.js", version="22.23.4",
        env_binary="SNIPER_NODE_BINARY", env_sha256="SNIPER_NODE_SHA256",
        source_url="https://nodejs.org/dist/v22.23.4/",
        digests={"aarch64": {
            "7e48183361053f039294fbbc3ba586722fe756bf296d6cb8195356d10819cd16":
                "resmi node-v22.23.4-linux-arm64 arşivindeki bin/node (arşiv SHA-256 "
                "6287aa46…f4b); dağıtım CHANGELOG.md kaydı 2026-10-21 güvenlik sürümünü listeler",
        }},
        default_binary=Path.home() / ".local" / "opt" / "node-v22.23.4-linux-arm64" / "bin" / "node",
        revoked_digests=frozenset({
            "1a638b0fe2b68da0489276aca95526c5122fc61ba54d6a2d0d00c1c92ab7b876",
        }),
        version_args=("--version",),
        version_pattern=r"(?m)^v(\d+)\.(\d+)\.(\d+)\s*$",
        supported_major=22,
        minimum_version=(22, 23, 4),
    ),
    # Root sahipli sabit Chromium (Playwright 1.56.1 browsers.json: chromium revision 1194, 141.0.7390.37).
    "chromium": ToolPin(
        tool="chromium", label="Chromium (Playwright 1194)", version="141.0.7390.37",
        env_binary="SNIPER_CHROMIUM_BINARY", env_sha256="SNIPER_CHROMIUM_SHA256",
        source_url="https://playwright.dev/docs/browsers",
        digests={"aarch64": {
            "7522aa366193273540bb458d2693fdc2437c4404441ab9fe672479b658b4710f":
                "host kurulumu /opt/sniper-playwright/chromium-1194/chrome-linux/chrome (root sahipli, 0750; "
                "Codex host devri 2026-10-20, AppArmor sniper-playwright-chromium userns istisnası)",
        }},
        default_binary=Path("/opt/sniper-playwright/chromium-1194/chrome-linux/chrome"),
    ),
}


@dataclass(frozen=True)
class TreePin:
    """Dizin ağacı sabitlemesi (ör. bir npm paketi): göreli yol + içerik özetlerinin SHA-256'sı."""
    name: str
    version: str
    env_dir: str
    default_dir: Path
    tree_sha256: str
    provenance: str
    max_files: int = 2000
    max_bytes: int = 64 * 1024 * 1024


TREE_PINS: dict[str, TreePin] = {
    "playwright-core": TreePin(
        name="playwright-core", version="1.56.1", env_dir="SNIPER_PLAYWRIGHT_CORE_DIR",
        default_dir=Path.home() / ".local" / "opt" / "playwright-core-1.56.1",
        tree_sha256="754bd0ae926dbf2a33019f0216af6c83e869f536e7c02f64f3ef3779d56bb6ea",
        provenance=("resmi npm paketi playwright-core-1.56.1.tgz (registry.npmjs.org; integrity sha512-hutrayny…gvmQ==, "
                    "tgz SHA-256 fa648e54…8238); Codex host kopyasıyla birebir aynı"),
    ),
}


def tree_sha256(root: str | os.PathLike[str], *, max_files: int = 2000, max_bytes: int = 64 * 1024 * 1024) -> str:
    """Dizin ağacının özeti. Sembolik bağ, normal olmayan dosya, grup/diğer yazılabilir öğe ya da başka bir
    kullanıcıya ait öğe varsa ``VerificationError``."""
    import hashlib
    import stat as stat_module

    base = os.fspath(root)
    try:
        top = os.lstat(base)
    except OSError as exc:
        raise VerificationError("Paket dizini bulunamadı.", "tree_unavailable") from exc
    if not stat_module.S_ISDIR(top.st_mode):
        raise VerificationError("Paket yolu bir dizin değil.", "tree_not_directory")
    entries: list[tuple[str, str]] = []
    total = 0
    for current, directories, files in os.walk(base, followlinks=False):
        for name in directories + files:
            full = os.path.join(current, name)
            info = os.lstat(full)
            if stat_module.S_ISLNK(info.st_mode) or not (stat_module.S_ISDIR(info.st_mode) or stat_module.S_ISREG(info.st_mode)):
                raise VerificationError("Paket ağacında sembolik bağ veya özel dosya var.", "tree_unsafe_entry")
            if info.st_mode & 0o022 or info.st_uid not in (0, os.getuid()):
                raise VerificationError("Paket ağacı başkaları tarafından yazılabilir.", "tree_unsafe_entry")
        directories.sort()
        for name in sorted(files):
            full = os.path.join(current, name)
            entries.append((os.path.relpath(full, base), full))
            if len(entries) > max_files:
                raise VerificationError("Paket ağacı çok büyük.", "tree_too_large")
    digest = hashlib.sha256()
    for relative, full in sorted(entries):
        file_digest = hashlib.sha256()
        with open(full, "rb", opener=lambda path, flags: os.open(path, flags | os.O_NOFOLLOW)) as handle:
            while chunk := handle.read(1 << 20):
                total += len(chunk)
                if total > max_bytes:
                    raise VerificationError("Paket ağacı çok büyük.", "tree_too_large")
                file_digest.update(chunk)
        digest.update(relative.encode("utf-8", "surrogateescape") + b"\0" + file_digest.digest())
    return digest.hexdigest()


def verified_tree(name: str) -> Path:
    """Sabitlenmiş dizin ağacını doğrular ve yolunu döndürür; ``VerificationError`` yükseltebilir."""
    pin = TREE_PINS[name]
    raw = os.environ.get(pin.env_dir, "").strip()
    path = Path(raw) if raw else pin.default_dir
    if not path.is_absolute():
        raise VerificationError("Paket yolu mutlak olmalı.", "tree_path_not_absolute")
    if tree_sha256(path, max_files=pin.max_files, max_bytes=pin.max_bytes) != pin.tree_sha256:
        raise VerificationError("Paket ağacı sabitlenmiş özetle uyuşmuyor.", "tree_digest_mismatch")
    return path


def machine() -> str:
    raw = platform.machine().lower()
    return {"arm64": "aarch64", "amd64": "x86_64", "x64": "x86_64"}.get(raw, raw)


def accepted_digests(tool: str) -> dict[str, str]:
    """Bu mimaride kabul edilen sha256 → köken eşlemesi (gömülü + operatör)."""
    pin = PINS[tool]
    accepted = dict(pin.digests.get(machine(), {}))
    for raw in os.environ.get(pin.env_sha256, "").split(","):
        value = raw.strip()
        if _HEX64.fullmatch(value) and value not in pin.revoked_digests:
            accepted.setdefault(value, OPERATOR_PROVENANCE)
    return accepted


def configured_binary(tool: str) -> str | None:
    pin = PINS[tool]
    value = os.environ.get(pin.env_binary, "").strip()
    if value:
        return value
    if pin.default_binary is not None and pin.default_binary.is_file():
        return str(pin.default_binary)
    return None


def open_pinned(tool: str, path: str | None = None) -> VerifiedExecutable:
    """Aracın ikilisini açıp SHA ve varsa çalıştırılabilir sürüm sözleşmesine göre doğrular."""
    pin = PINS[tool]
    executable = open_verified_executable(
        path if path is not None else configured_binary(tool), accepted_digests(tool), label=pin.label
    )
    try:
        _verify_runtime_version(pin, executable)
    except BaseException:
        executable.close()
        raise
    return executable


def _verify_runtime_version(pin: ToolPin, executable: VerifiedExecutable) -> None:
    """SHA-doğrulanmış fd-bound ikilinin sürümünü kısa ve sade bir alt süreçte fail-closed doğrula."""
    if not pin.version_args:
        return
    try:
        completed = subprocess.run(
            [executable.argv0, *pin.version_args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
            **executable.popen_kwargs(env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"{pin.label} sürümü güvenli biçimde doğrulanamadı.", "binary_version_unavailable") from exc
    output = completed.stdout or b""
    if completed.returncode != 0 or len(output) > 8192:
        raise VerificationError(f"{pin.label} geçerli ve sınırlı bir sürüm çıktısı vermedi.", "binary_version_output_invalid")
    match = re.search(pin.version_pattern, output.decode("utf-8", "replace"))
    if match is None:
        raise VerificationError(f"{pin.label} sürüm çıktısı beklenen biçimde değil.", "binary_version_output_invalid")
    version = tuple(int(part) for part in match.groups() if part is not None)
    width = max(len(version), len(pin.minimum_version))
    normalized = version + (0,) * (width - len(version))
    minimum = pin.minimum_version + (0,) * (width - len(pin.minimum_version))
    if not version or version[0] != pin.supported_major or normalized < minimum:
        raise VerificationError(
            f"{pin.label} desteklenen sürüm hattı veya en düşük güvenlik sürümüyle uyuşmuyor.",
            "binary_version_unsupported",
        )


def pin_status(tool: str, path: str | None = None) -> dict[str, object]:
    """Hazırlık raporu için yol içermeyen pin durumu.

    ``state``: ``pinned`` (eşleşti), ``mismatch`` (uyuşmuyor), ``unpinned`` (bu
    mimari için sabitleme yok), ``unavailable`` (ikili yok/güvenli değil).
    """
    pin = PINS[tool]
    accepted = accepted_digests(tool)
    result: dict[str, object] = {"tool": tool, "version": pin.version, "source_url": pin.source_url}
    try:
        digest = file_sha256(path if path is not None else configured_binary(tool), pin.label)
    except VerificationError as exc:
        result.update(state="unavailable", reason_code=exc.reason)
        return result
    if digest in pin.revoked_digests:
        result.update(state="mismatch", reason_code="binary_digest_revoked")
    elif not accepted:
        result.update(state="unpinned", reason_code="pin_missing")
    elif digest in accepted:
        result.update(state="pinned", reason_code="digest_matches_pin", provenance=accepted[digest])
    else:
        result.update(state="mismatch", reason_code="binary_digest_mismatch")
    return result


def tree_pin_status(name: str) -> dict[str, object]:
    """Hazırlık raporu için yol içermeyen dizin ağacı pin durumu (``pin_status`` ile aynı biçim)."""
    pin = TREE_PINS[name]
    result: dict[str, object] = {"tool": name, "version": pin.version, "source_url": "https://www.npmjs.com/package/" + name}
    try:
        verified_tree(name)
    except VerificationError as exc:
        state = "mismatch" if exc.reason == "tree_digest_mismatch" else "unavailable"
        result.update(state=state, reason_code=exc.reason)
        return result
    except OSError:
        result.update(state="unavailable", reason_code="tree_unavailable")
        return result
    result.update(state="pinned", reason_code="digest_matches_pin", provenance=pin.provenance)
    return result

