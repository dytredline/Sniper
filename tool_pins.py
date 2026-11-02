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
    # ortam değişkeni yoksa denenecek, VulKill'a ait kurulum yolu
    default_binary: Path | None = None
    # Bilinen güvensiz/geri çekilmiş ikililer operatör ortam sabitlemesiyle de yeniden kabul edilmez.
    revoked_digests: frozenset[str] = field(default_factory=frozenset)
    # SHA doğrulamasından sonra aynı fd-bound ikiliden okunacak sürüm sözleşmesi.
    version_args: tuple[str, ...] = ()
    version_pattern: str = ""
    supported_major: int | None = None
    minimum_version: tuple[int, ...] = ()


PINS: dict[str, ToolPin] = {
    "syft": ToolPin(
        tool="syft", label="Syft", version="1.55.0",
        env_binary="SNIPER_SYFT_BINARY", env_sha256="SNIPER_SYFT_BINARY_SHA256",
        source_url="https://github.com/anchore/syft/releases/tag/v1.55.0",
        digests={"aarch64": {
            "a25bda7a97403add93e9a384f70554b212a112e2e66c0989bbc4c35e8c8a319e":
                "v1.55.0 etiketinden (commit f15c3343) Go 1.27.3 ve güvenlik modül "
                "yükseltmeleriyle doğrulanmış yerel derleme; VERIFIED-TOOLCHAIN.lock.json",
        }},
        revoked_digests=frozenset({
            "4f8068b25551a42991a292a42078519fdc739a97a6f6310e1dcf1367a258c1c2",
            "b37c723afc00a1336d3472d6b84de349f67b8ed12dec69e46dead808ef32aad6",
        }),
        default_binary=Path.home() / ".local" / "state" / "sniper-tool-runtimes" / "syft-1.55.0" / "syft",
    ),
    "grype": ToolPin(
        tool="grype", label="Grype", version="0.121.0",
        env_binary="SNIPER_GRYPE_BINARY", env_sha256="SNIPER_GRYPE_BINARY_SHA256",
        source_url="https://github.com/anchore/grype/releases/tag/v0.121.0",
        digests={"aarch64": {
            "c8dc5f64e3d2c163aa2f4103ee08292cd6addd84f6994dfcd4e5018c68483069":
                "v0.121.0 etiketinden (commit afe27425) Go 1.27.3 ve güvenlik modül "
                "yükseltmeleriyle doğrulanmış yerel derleme; VERIFIED-TOOLCHAIN.lock.json",
        }},
        revoked_digests=frozenset({
            "e81fd2b6669c5a9ab7fee756e63e769cc40163310c11e546420b4d93e2118543",
            "3b6f67504e69e637535f8672b588917b1b4c16be6f9a4d20f3e2c89a4ef01859",
        }),
        default_binary=Path.home() / ".local" / "state" / "sniper-tool-runtimes" / "grype-0.121.0" / "grype",
    ),
    "gitleaks": ToolPin(
        tool="gitleaks", label="Gitleaks", version="8.30.1",
        env_binary="SNIPER_GITLEAKS_BINARY", env_sha256="SNIPER_GITLEAKS_SHA256",
        source_url="https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1",
        digests={"aarch64": {
            "d26b4da0d011da43fa7e22e309841faad203e0d9869a1127d3a65886a5072166":
                "v8.30.1 etiketinden (commit 83d9cd68) Go 1.27.3 ve güvenlik modül "
                "yükseltmeleriyle doğrulanmış yerel derleme; VERIFIED-TOOLCHAIN.lock.json",
        }},
        revoked_digests=frozenset({
            "00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b",
            "c0c79301a5e3cd357ab568d2bb439d5215793208da6081bc366433ce16e3df24",
            "a56a110704baf742345d79eb56f8effde827c8499761f7cb2698412d100a01a9",
        }),
    ),
    "trufflehog": ToolPin(
        tool="trufflehog", label="TruffleHog", version="3.99.7",
        env_binary="SNIPER_TRUFFLEHOG_BINARY", env_sha256="SNIPER_TRUFFLEHOG_SHA256",
        source_url="https://github.com/trufflesecurity/trufflehog/releases/tag/v3.99.7",
        digests={"aarch64": {
            "b00f2a9f2ff4263160289b144cde0d7a5d96568ea085e55b268d01e82a1dd6f5":
                "v3.99.7 etiketinden (commit 31ce31ee) Go 1.27.3 ve güvenlik modül "
                "yükseltmeleriyle doğrulanmış yerel derleme; VERIFIED-TOOLCHAIN.lock.json",
        }},
        revoked_digests=frozenset({
            "c51ee8bd6082eaccfd9cb5ff10d3fe1fc883332a0bb312868aeaff4d988c4493",
            "2af93536892db19976b0e81a43a4b2b2a3330bbf115290501d80a4621b0d8cdc",
            "6f6681885e3620ad0972eff26d8ce9b85d4392163597f33d5b7d05779128eb00",
            "4cdfed417cc07a7cd3b08036ce07c87f26e8db21b82b5c7b90005f06da380a93",
        }),
    ),
    "opengrep": ToolPin(
        tool="opengrep", label="Opengrep", version="1.33.1",
        env_binary="SNIPER_OPENGREP_BINARY", env_sha256="SNIPER_OPENGREP_SHA256",
        source_url="https://github.com/opengrep/opengrep/releases/tag/v1.33.1",
        digests={
            "aarch64": {
                "d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf":
                    "resmi sürüm varlığı opengrep_manylinux_aarch64 (GitHub varlık özeti; "
                    "yayıncı .sig/.cert yan dosyaları ayrıca yayımlandı)",
            },
            "x86_64": {
                "46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808":
                    "resmi sürüm varlığı opengrep_manylinux_x86 (GitHub varlık özeti)",
            },
        },
        default_binary=SNIPER_TOOLS_DIR / "opengrep" / "1.33.1" / "opengrep",
        revoked_digests=frozenset({
            "a730f6fdce1e978ea29e610a2e0503bfe1ec31fce08979a9a84e3699f03e16ee",
            "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4",
        }),
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
        tool="joern-jdk", label="Joern JDK (Temurin 25 LTS)", version="25.0.5+8",
        env_binary="SNIPER_JOERN_JDK_BINARY", env_sha256="SNIPER_JOERN_JDK_SHA256",
        source_url="https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8",
        digests={"aarch64": {
            "9773d145ea1adce8da70e0f9e87ecddad5446f7e5ac05b44a95cecf902b42cb9":
                "resmi Temurin arşivindeki bin/java (OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.5_8.tar.gz, "
                "Adoptium sürüm özeti ve .sha256.txt ile doğrulanan arşiv SHA-256 bb5b2ded…1880)",
        }},
        default_binary=SNIPER_TOOLS_DIR / "jdk" / "25.0.5+8" / "bin" / "java",
        revoked_digests=frozenset({
            "e8201aed7118cbf3a77b9cb308a3cbe135fe97b055968b3b4797162fed1ca818",
        }),
        version_args=("-version",),
        version_pattern=(
            r'\Aopenjdk version "(25)\.(0)\.(5)" 2026-10-20 LTS\r?\n'
            r'OpenJDK Runtime Environment Temurin-25\.0\.5\+8 '
            r'\(build 25\.0\.5\+8-LTS\)\r?\n'
            r'OpenJDK 64-Bit Server VM Temurin-25\.0\.5\+8 '
            r'\(build 25\.0\.5\+8-LTS, mixed mode, sharing\)\s*\Z'
        ),
        supported_major=25,
        minimum_version=(25, 0, 5),
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
        tool="node", label="Node.js LTS", version="26.13.0",
        env_binary="SNIPER_NODE_BINARY", env_sha256="SNIPER_NODE_SHA256",
        source_url="https://nodejs.org/dist/v26.13.0/",
        digests={"aarch64": {
            "66f4a883c880ef336276e7730c01cbae2b92fb8e6a51f7371f920599cac824b7":
                "resmi node-v26.13.0-linux-arm64 arşivindeki bin/node (arşiv SHA-256 "
                "406fe3fb…9a92; nodejs.org SHASUMS256.txt ile doğrulandı)",
        }},
        default_binary=Path.home() / ".local" / "opt" / "node-v26.13.0-linux-arm64" / "bin" / "node",
        revoked_digests=frozenset({
            "1a638b0fe2b68da0489276aca95526c5122fc61ba54d6a2d0d00c1c92ab7b876",
            "7e48183361053f039294fbbc3ba586722fe756bf296d6cb8195356d10819cd16",
        }),
        version_args=("--version",),
        version_pattern=r"(?m)^v(\d+)\.(\d+)\.(\d+)\s*$",
        supported_major=26,
        minimum_version=(26, 13, 0),
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
