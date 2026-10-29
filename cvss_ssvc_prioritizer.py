"""CVSS v3.1 / CVSS v4.0 vektörü ve CISA SSVC tabanlı bulgu önceliklendirici.

Bu modül tamamen deterministiktir; ağ erişimi, alt süreç veya veritabanı yazımı
yapmaz. Sniper bulgularının (dict) CWE / referans / kategori / önem bilgisinden
CVSS 3.1 temel vektörü çıkarır, FIRST CVSS v3.1 belirtimine (Ek A yuvarlama
dahil) göre birebir temel puanı hesaplar, aynı metriklerden bir CVSS 4.0 temel
vektörü üretip FIRST resmi MacroVector algoritmasıyla (``cvss40`` modülü) sayısal
puanını hesaplar ve CISA SSVC karar ağacının basitleştirilmiş, deterministik bir
sürümüyle (Track / Track* / Attend / Act) SLA tarihleri atar.

Dürüstlük notu: CVSS 4.0 puanı resmi FIRST tablosu ve algoritmasıyla hesaplanır, ancak
4.0 vektörü bulgudan doğrudan değil 3.1 vektöründen eşlenerek türetilir (AT varsayılan N,
UI:R→P); bu nedenle 4.0 puanı da çıkarımsal bir tahmindir.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import math
import re
from typing import Any

from cvss40 import compute_cvss40


MAX_FINDINGS = 10_000

CVSS40_NOTE = (
    "CVSS 4.0 puanı FIRST resmi MacroVector algoritmasıyla hesaplandı; vektör 3.1 vektöründen "
    "eşlenerek türetildiği için (AT:N varsayılır, UI:R→P) çıkarımsal bir tahmindir."
)

_CVSS31_RE = re.compile(
    r"^CVSS:3\.1/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])$"
)
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

EXPOSURE_VALUES = ("internet", "internal", "local")
EXPLOITATION_VALUES = ("none", "poc", "active")
TECHNICAL_IMPACT_VALUES = ("partial", "total")
MISSION_PREVALENCE_VALUES = ("minimal", "support", "essential")
PUBLIC_WELLBEING_VALUES = ("minimal", "material", "irreversible")

SSVC_RANK = {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "None")

DEFAULT_SLA_POLICY: dict[str, int] = {
    "Critical": 7,
    "High": 14,
    "Medium": 30,
    "Low": 90,
    "None": 180,
}

_FULL_RCE = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_AUTHZ = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
_DOS = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
_WEAK_CRYPTO = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
_XSS = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_INFO_LEAK = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
_MISSING_HEADER = "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
_COOKIE_FLAG = "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
_LOGGING = "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"
_PRIV_LOCAL = "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
_SUPPLY = "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"
_AUTH_BYPASS = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
_SECRET_STORAGE = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
_FILE_PERMS = "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

# CWE → CVSS 3.1 temel metrikleri (önek "CVSS:3.1/" olmadan). Deterministik, ihtiyatlı eşlemeler.
CWE_VECTOR_TABLE: dict[str, str] = {
    # Enjeksiyon / uzaktan kod çalıştırma
    "CWE-77": _FULL_RCE,
    "CWE-78": _FULL_RCE,
    "CWE-89": _FULL_RCE,
    "CWE-94": _FULL_RCE,
    "CWE-95": _FULL_RCE,
    "CWE-502": _FULL_RCE,
    "CWE-917": _FULL_RCE,
    "CWE-1336": _FULL_RCE,
    "CWE-434": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CWE-90": _AUTH_BYPASS,
    "CWE-643": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-1321": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    # İstemci tarafı
    "CWE-79": _XSS,
    "CWE-80": _XSS,
    "CWE-601": _XSS,
    "CWE-352": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "CWE-1021": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "CWE-942": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    # Sunucu tarafı istek / dosya / XML
    "CWE-918": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "CWE-22": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-23": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-611": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
    # Gizli bilgiler
    "CWE-798": _AUTH_BYPASS,
    "CWE-259": _AUTH_BYPASS,
    "CWE-312": _SECRET_STORAGE,
    "CWE-532": _SECRET_STORAGE,
    "CWE-200": _INFO_LEAK,
    "CWE-209": _INFO_LEAK,
    # Kaynak tüketimi / DoS
    "CWE-400": _DOS,
    "CWE-409": _DOS,
    "CWE-770": _DOS,
    "CWE-776": _DOS,
    "CWE-1333": _DOS,
    # Kriptografi / taşıma
    "CWE-319": _WEAK_CRYPTO,
    "CWE-326": _WEAK_CRYPTO,
    "CWE-327": _WEAK_CRYPTO,
    "CWE-328": _WEAK_CRYPTO,
    "CWE-330": _WEAK_CRYPTO,
    "CWE-338": _WEAK_CRYPTO,
    "CWE-916": _WEAK_CRYPTO,
    "CWE-295": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-347": _AUTH_BYPASS,
    # Kimlik doğrulama / yetkilendirme
    "CWE-284": _AUTHZ,
    "CWE-285": _AUTHZ,
    "CWE-639": _AUTHZ,
    "CWE-862": _AUTHZ,
    "CWE-863": _AUTHZ,
    "CWE-287": _AUTH_BYPASS,
    "CWE-306": _AUTH_BYPASS,
    "CWE-307": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-923": "AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    # İş mantığı / eşzamanlılık
    "CWE-362": "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "CWE-841": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    # Tedarik zinciri
    "CWE-1104": _SUPPLY,
    "CWE-829": _SUPPLY,
    # Yapılandırma / başlıklar / çerezler
    "CWE-16": _MISSING_HEADER,
    "CWE-693": _MISSING_HEADER,
    "CWE-614": _COOKIE_FLAG,
    "CWE-1004": _COOKIE_FLAG,
    # Günlükleme
    "CWE-117": _LOGGING,
    "CWE-778": _LOGGING,
    # Ayrıcalık / izinler
    "CWE-250": _PRIV_LOCAL,
    "CWE-269": _PRIV_LOCAL,
    "CWE-276": _FILE_PERMS,
    "CWE-732": _FILE_PERMS,
    "CWE-426": _PRIV_LOCAL,
    "CWE-427": _PRIV_LOCAL,
    # İş mantığı / bütünlük / istemci sınırları (Dalga 78–103)
    "CWE-190": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
    "CWE-252": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "CWE-359": _SECRET_STORAGE,
    "CWE-384": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "CWE-472": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "CWE-522": _SECRET_STORAGE,
    "CWE-523": _WEAK_CRYPTO,
    "CWE-598": _INFO_LEAK,
    "CWE-668": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "CWE-749": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "CWE-915": _AUTHZ,
    "CWE-939": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "CWE-1395": _SUPPLY,
    # Bellek güvenliği, NoSQL, başlık/istek kaçakçılığı ve kötü amaçlı paketler (Dalga 157)
    "CWE-943": _FULL_RCE,
    "CWE-113": _XSS,
    "CWE-134": _FULL_RCE,
    "CWE-416": _FULL_RCE,
    "CWE-415": _FULL_RCE,
    "CWE-119": _FULL_RCE,
    "CWE-120": _FULL_RCE,
    "CWE-787": _FULL_RCE,
    "CWE-125": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "CWE-401": _DOS,
    "CWE-506": _FULL_RCE,
    "CWE-501": _AUTHZ,
    "CWE-444": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "CWE-345": _AUTH_BYPASS,
    "CWE-346": _AUTH_BYPASS,
    "CWE-530": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# Sniper kategori → temsilî CWE (CWE bilgisi yoksa kullanılır).
CATEGORY_CWE_FALLBACK: dict[str, str] = {
    "headers": "CWE-693",
    "transport": "CWE-319",
    "session": "CWE-614",
    "cors": "CWE-942",
    "disclosure": "CWE-200",
    "information": "CWE-200",
    "privacy": "CWE-200",
    "data": "CWE-200",
    "errors": "CWE-209",
    "supplychain": "CWE-1104",
    "dependency": "CWE-1104",
    "dependencies": "CWE-1104",
    "components": "CWE-1104",
    "authentication": "CWE-287",
    "secrets": "CWE-798",
    "crypto": "CWE-327",
    "authorization": "CWE-862",
    "authz": "CWE-862",
    "ssrf": "CWE-918",
    "command_data": "CWE-78",
    "data_query": "CWE-89",
    "business": "CWE-841",
    "availability": "CWE-400",
    "logging": "CWE-778",
    "ai_llm": "CWE-77",
    "database_rls": "CWE-862",
    "cloud_iam": "CWE-269",
    "zero_trust": "CWE-319",
    "browser_extension": "CWE-79",
    "desktop_security": "CWE-78",
    "web3": "CWE-841",
    "iot_firmware": "CWE-798",
    "host_cis": "CWE-250",
    "dos_resilience": "CWE-400",
    "mobile_security": "CWE-312",
    "iac": "CWE-16",
    "container": "CWE-250",
}

SEVERITY_VECTOR_FALLBACK: dict[str, str] = {
    "critical": _FULL_RCE,
    "high": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "medium": "AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


def _roundup(value: float) -> float:
    """FIRST CVSS v3.1 belirtimi Ek A'daki Roundup işlevi (kayan nokta hatasına dayanıklı)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss31_severity(score: float) -> str:
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def compute_cvss31(vector: str) -> dict[str, Any]:
    """CVSS v3.1 temel puanını FIRST belirtimine göre birebir hesapla.

    Kabul edilen biçim (katı): ``CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_``.
    """
    if not isinstance(vector, str):
        raise ValueError("CVSS 3.1 vektörü metin olmalıdır.")
    clean = vector.strip()
    match = _CVSS31_RE.match(clean)
    if not match:
        raise ValueError(
            "Geçersiz CVSS 3.1 vektörü; beklenen biçim: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_"
        )
    av, ac, pr, ui, scope, conf, integ, avail = match.groups()
    changed = scope == "C"
    iss = 1.0 - (
        (1.0 - _CIA_WEIGHTS[conf]) * (1.0 - _CIA_WEIGHTS[integ]) * (1.0 - _CIA_WEIGHTS[avail])
    )
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr_weight = (_PR_WEIGHTS_CHANGED if changed else _PR_WEIGHTS_UNCHANGED)[pr]
    exploitability = 8.22 * _AV_WEIGHTS[av] * _AC_WEIGHTS[ac] * pr_weight * _UI_WEIGHTS[ui]
    if impact <= 0:
        base_score = 0.0
    elif changed:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base_score = _roundup(min(impact + exploitability, 10.0))
    return {
        "vector": clean,
        "base_score": base_score,
        "severity": cvss31_severity(base_score),
        "impact_subscore": round(max(impact, 0.0), 1),
        "exploitability_subscore": round(exploitability, 1),
        "metrics": {
            "AV": av,
            "AC": ac,
            "PR": pr,
            "UI": ui,
            "S": scope,
            "C": conf,
            "I": integ,
            "A": avail,
        },
    }


def build_cvss40_vector(cvss31_vector: str, *, attack_requirements: str = "N") -> str:
    """Aynı çıkarılmış metriklerden bir CVSS:4.0 temel vektörü üret.

    Eşleme: AV/AC/PR aynen; AT varsayılan N; UI:N→N, UI:R→P (pasif, ihtiyatlı);
    VC/VI/VA = C/I/A; S:C ise SC/SI/SA = C/I/A, aksi halde N.
    Sayısal puan için ``cvss40.compute_cvss40`` kullanılır (bkz. CVSS40_NOTE).
    """
    metrics = compute_cvss31(cvss31_vector)["metrics"]
    at = str(attack_requirements or "N").strip().upper()
    if at not in {"N", "P"}:
        raise ValueError("CVSS 4.0 AT (Attack Requirements) değeri N veya P olmalıdır.")
    ui = "N" if metrics["UI"] == "N" else "P"
    if metrics["S"] == "C":
        sc, si, sa = metrics["C"], metrics["I"], metrics["A"]
    else:
        sc, si, sa = "N", "N", "N"
    return (
        f"CVSS:4.0/AV:{metrics['AV']}/AC:{metrics['AC']}/AT:{at}/PR:{metrics['PR']}/UI:{ui}"
        f"/VC:{metrics['C']}/VI:{metrics['I']}/VA:{metrics['A']}/SC:{sc}/SI:{si}/SA:{sa}"
    )


def _candidate_cwes(finding: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for field in ("cwe", "cwe_id", "reference"):
        value = finding.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            cwe = f"CWE-{value}"
            if cwe not in found:
                found.append(cwe)
            continue
        if isinstance(value, (list, tuple)):
            value = " ".join(str(v) for v in value)
        if not isinstance(value, str):
            continue
        stripped = value.strip()
        if stripped.isdigit() and int(stripped) > 0:
            cwe = f"CWE-{int(stripped)}"
            if cwe not in found:
                found.append(cwe)
            continue
        for number in _CWE_RE.findall(value):
            cwe = f"CWE-{int(number)}"
            if cwe not in found:
                found.append(cwe)
    return found


def _apply_exposure(metrics_part: str, exposure: str) -> str:
    if exposure == "internal":
        return metrics_part.replace("AV:N/", "AV:A/")
    if exposure == "local":
        return metrics_part.replace("AV:N/", "AV:L/").replace("AV:A/", "AV:L/")
    return metrics_part


def infer_cvss31_vector(finding: dict[str, Any], *, exposure: str = "internet") -> str:
    """Bulgunun CWE / referans / kategori / önem bilgisinden deterministik CVSS 3.1 vektörü çıkar.

    Öncelik: açık CWE tablosu (cwe alanı, ardından referans metnindeki CWE-n) →
    kategori temsilî CWE'si → önem derecesi geri dönüşü. ``exposure``:
    'internet' AV'yi korur, 'internal' AV:N→AV:A, 'local' AV:N/AV:A→AV:L.
    """
    if not isinstance(finding, dict):
        raise ValueError("Bulgu bir sözlük (dict) olmalıdır.")
    exp = str(exposure or "internet").strip().lower()
    if exp not in EXPOSURE_VALUES:
        raise ValueError("exposure değeri 'internet', 'internal' veya 'local' olmalıdır.")
    metrics_part: str | None = None
    for cwe in _candidate_cwes(finding):
        if cwe in CWE_VECTOR_TABLE:
            metrics_part = CWE_VECTOR_TABLE[cwe]
            break
    if metrics_part is None:
        category = str(finding.get("category") or "").strip().lower()
        fallback_cwe = CATEGORY_CWE_FALLBACK.get(category)
        if fallback_cwe:
            metrics_part = CWE_VECTOR_TABLE[fallback_cwe]
    if metrics_part is None:
        severity = str(finding.get("severity") or "info").strip().lower()
        metrics_part = SEVERITY_VECTOR_FALLBACK.get(severity, SEVERITY_VECTOR_FALLBACK["info"])
    return "CVSS:3.1/" + _apply_exposure(metrics_part, exp)


def ssvc_decision(
    *,
    exploitation: str,
    automatable: bool,
    technical_impact: str,
    mission_prevalence: str,
    public_wellbeing: str = "minimal",
) -> str:
    """CISA SSVC (Coordinator/Deployer "CISA" ağacı) basitleştirilmiş deterministik karar.

    Karar tablosu (yukarıdan aşağı ilk eşleşen kural uygulanır):

    =============  ===========  ==========  ===================  ==============  ========
    exploitation   automatable  tech_imp.   mission_prevalence   public_wellb.   karar
    =============  ===========  ==========  ===================  ==============  ========
    active         evet         total       *                    *               Act
    active         *            total       essential            *               Act
    active         *            *           *                    material/irrev  Act
    active         *            *           *                    *               Attend
    poc            evet         total       *                    *               Attend
    poc            *            total       essential            *               Attend
    poc            *            *           *                    *               Track*
    none           evet         total       essential            *               Track*
    none           *            *           *                    *               Track
    =============  ===========  ==========  ===================  ==============  ========
    """
    expl = str(exploitation or "").strip().lower()
    impact = str(technical_impact or "").strip().lower()
    mission = str(mission_prevalence or "").strip().lower()
    wellbeing = str(public_wellbeing or "minimal").strip().lower()
    if expl not in EXPLOITATION_VALUES:
        raise ValueError("exploitation değeri 'none', 'poc' veya 'active' olmalıdır.")
    if impact not in TECHNICAL_IMPACT_VALUES:
        raise ValueError("technical_impact değeri 'partial' veya 'total' olmalıdır.")
    if mission not in MISSION_PREVALENCE_VALUES:
        raise ValueError("mission_prevalence değeri 'minimal', 'support' veya 'essential' olmalıdır.")
    if wellbeing not in PUBLIC_WELLBEING_VALUES:
        raise ValueError("public_wellbeing değeri 'minimal', 'material' veya 'irreversible' olmalıdır.")
    auto = bool(automatable)
    total = impact == "total"
    essential = mission == "essential"

    if expl == "active":
        if total and (essential or auto):
            return "Act"
        if wellbeing in {"material", "irreversible"}:
            return "Act"
        return "Attend"
    if expl == "poc":
        if auto and total:
            return "Attend"
        if total and essential:
            return "Attend"
        return "Track*"
    if auto and total and essential:
        return "Track*"
    return "Track"


def _parse_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Tarih değeri 'YYYY-MM-DD' veya ISO 8601 biçiminde olmalıdır.")
    text = value.strip()
    try:
        if len(text) == 10:
            return date.fromisoformat(text)
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError as exc:
        raise ValueError(f"Geçersiz tarih değeri: {text[:40]}") from exc


def _validated_sla_policy(sla_policy: dict[str, Any] | None) -> dict[str, int]:
    policy = dict(DEFAULT_SLA_POLICY)
    if sla_policy is None:
        return policy
    if not isinstance(sla_policy, dict):
        raise ValueError("sla_policy bir sözlük (dict) olmalıdır.")
    for key, value in sla_policy.items():
        if key not in policy:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 3650:
            raise ValueError(f"sla_policy['{key}'] 0-3650 arasında bir tam sayı (gün) olmalıdır.")
        policy[key] = value
    return policy


def prioritize_findings(
    findings: list[dict[str, Any]],
    *,
    exposure: str = "internet",
    mission_prevalence: str = "support",
    exploitation: str = "none",
    sla_policy: dict[str, Any] | None = None,
    discovered_at: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Bulguları CVSS 3.1 + SSVC ile önceliklendir ve SLA son tarihlerini hesapla."""
    if not isinstance(findings, list):
        raise ValueError("Önceliklendirilecek bulgular bir liste olmalıdır.")
    if len(findings) > MAX_FINDINGS:
        raise ValueError(f"Bulgu sayısı güvenli sınırı ({MAX_FINDINGS}) aşıyor.")
    exp = str(exposure or "internet").strip().lower()
    if exp not in EXPOSURE_VALUES:
        raise ValueError("exposure değeri 'internet', 'internal' veya 'local' olmalıdır.")
    mission = str(mission_prevalence or "support").strip().lower()
    if mission not in MISSION_PREVALENCE_VALUES:
        raise ValueError("mission_prevalence değeri 'minimal', 'support' veya 'essential' olmalıdır.")
    default_exploitation = str(exploitation or "none").strip().lower()
    if default_exploitation not in EXPLOITATION_VALUES:
        raise ValueError("exploitation değeri 'none', 'poc' veya 'active' olmalıdır.")
    policy = _validated_sla_policy(sla_policy)
    now_date = _parse_date(now) if now else datetime.now(timezone.utc).date()
    default_discovered = _parse_date(discovered_at) if discovered_at else now_date

    prioritized: list[dict[str, Any]] = []
    skipped = 0
    for finding in findings:
        if not isinstance(finding, dict):
            skipped += 1
            continue
        vector = infer_cvss31_vector(finding, exposure=exp)
        cvss = compute_cvss31(vector)
        metrics = cvss["metrics"]
        automatable = (
            metrics["AV"] == "N" and metrics["PR"] == "N" and metrics["UI"] == "N" and metrics["AC"] == "L"
        )
        any_high = "H" in (metrics["C"], metrics["I"], metrics["A"])
        technical_impact = (
            "total"
            if (metrics["C"] == "H" and metrics["I"] == "H") or (metrics["S"] == "C" and any_high)
            else "partial"
        )
        finding_exploitation = default_exploitation
        raw_expl = finding.get("exploitation")
        if isinstance(raw_expl, str) and raw_expl.strip().lower() in EXPLOITATION_VALUES:
            finding_exploitation = raw_expl.strip().lower()
        if finding.get("kev") is True:
            finding_exploitation = "active"
        decision = ssvc_decision(
            exploitation=finding_exploitation,
            automatable=automatable,
            technical_impact=technical_impact,
            mission_prevalence=mission,
        )
        sla_days = int(policy[cvss["severity"]])
        if decision == "Act":
            sla_days = min(sla_days, 2)
        elif decision == "Attend":
            sla_days = min(sla_days, 7)
        found_on = default_discovered
        raw_discovered = finding.get("discovered_at")
        if raw_discovered:
            try:
                found_on = _parse_date(raw_discovered)
            except ValueError:
                found_on = default_discovered
        due = found_on + timedelta(days=sla_days)
        days_remaining = (due - now_date).days
        cvss40 = compute_cvss40(build_cvss40_vector(cvss["vector"]))
        prioritized.append(
            {
                "id": finding.get("id"),
                "title": str(finding.get("title") or "Bulgu"),
                "severity": finding.get("severity"),
                "category": finding.get("category"),
                "cwe": finding.get("cwe") if finding.get("cwe") is not None else finding.get("cwe_id"),
                "control_id": finding.get("control_id"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "cvss31_vector": cvss["vector"],
                "cvss31_score": cvss["base_score"],
                "cvss31_severity": cvss["severity"],
                "cvss40_vector": cvss40["vector"],
                "cvss40_score": cvss40["score"],
                "cvss40_severity": cvss40["severity"],
                "cvss40_note": CVSS40_NOTE,
                "ssvc_decision": decision,
                "ssvc_inputs": {
                    "exploitation": finding_exploitation,
                    "automatable": automatable,
                    "technical_impact": technical_impact,
                    "mission_prevalence": mission,
                },
                "sla_days": sla_days,
                "discovered_at": found_on.isoformat(),
                "due_date": due.isoformat(),
                "sla_status": "overdue" if now_date > due else "within_sla",
                "days_remaining": days_remaining,
            }
        )

    prioritized.sort(
        key=lambda item: (SSVC_RANK[item["ssvc_decision"]], -float(item["cvss31_score"]), item["title"])
    )
    for rank, item in enumerate(prioritized, 1):
        item["priority_rank"] = rank

    ssvc_summary = {decision: 0 for decision in ("Act", "Attend", "Track*", "Track")}
    severity_summary = {name: 0 for name in SEVERITY_ORDER}
    for item in prioritized:
        ssvc_summary[item["ssvc_decision"]] += 1
        severity_summary[item["cvss31_severity"]] += 1
    scores = [float(item["cvss31_score"]) for item in prioritized]
    return {
        "format": "sniper-cvss-ssvc-prioritization-v1",
        "exposure": exp,
        "mission_prevalence": mission,
        "default_exploitation": default_exploitation,
        "evaluated_on": now_date.isoformat(),
        "finding_count": len(prioritized),
        "skipped": skipped,
        "prioritized_findings": prioritized,
        "ssvc_summary": ssvc_summary,
        "severity_summary": severity_summary,
        "overdue_count": sum(1 for item in prioritized if item["sla_status"] == "overdue"),
        "max_cvss31": max(scores) if scores else 0.0,
        "mean_cvss31": round(sum(scores) / len(scores), 1) if scores else 0.0,
        "sla_policy": policy,
        "cvss40_note": CVSS40_NOTE,
    }


_CISA_EXPOSURE_MAP: dict[str, str] = {
    "open": "internet",
    "internet": "internet",
    "public": "internet",
    "controlled": "internal",
    "internal": "internal",
    "restricted": "internal",
    "small": "local",
    "local": "local",
    "private": "local",
}

_CISA_ACTION_TIER_MAP: dict[str, str] = {
    "Act": "ACT_IMMEDIATELY_24H",
    "Attend": "ATTEND_SLA_7D",
    "Track*": "TRACK_STAR_14D",
    "Track": "TRACK_ROUTINE_30D",
}


def evaluate_cisa_ssvc_decisions(
    findings: list[dict[str, Any]],
    *,
    exposure: str = "open",
) -> dict[str, Any]:
    """CISA SSVC (Stakeholder-Specific Vulnerability Categorization) karar matrisini hesaplar."""
    raw_exp = str(exposure or "open").strip().lower()
    mapped_exposure = _CISA_EXPOSURE_MAP.get(raw_exp, "internet")

    normalized_findings: list[dict[str, Any]] = []
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        norm = dict(item)
        if not norm.get("cwe"):
            norm["cwe"] = norm.get("reference") or norm.get("cwe_id") or norm.get("rule_id") or "CWE-200"
        raw_expl = str(norm.get("exploitation") or "").strip().lower()
        if raw_expl not in EXPLOITATION_VALUES:
            expl_status = str(norm.get("exploitability") or norm.get("exploitation_status") or "").strip().lower()
            sev = str(norm.get("severity") or "").strip().lower()
            if expl_status in {"proven_exploitable", "active", "weaponized", "kev"} or norm.get("kev") is True:
                norm["exploitation"] = "active"
            elif expl_status in {"poc", "proof_of_concept", "likely_exploitable"} or sev in {"critical", "kritik"}:
                norm["exploitation"] = "poc"
            else:
                norm["exploitation"] = "none"
        normalized_findings.append(norm)

    if not normalized_findings:
        empty_summary = {decision: 0 for decision in ("Act", "Attend", "Track*", "Track")}
        return {
            "format": "sniper-cisa-ssvc-decision-matrix/1",
            "exposure": raw_exp,
            "decision_count": 0,
            "summary": empty_summary,
            "decisions": [],
        }

    base = prioritize_findings(normalized_findings, exposure=mapped_exposure)
    for decision_item in base["prioritized_findings"]:
        ssvc_dec = str(decision_item.get("ssvc_decision") or "Track")
        decision_item["cisa_action_tier"] = _CISA_ACTION_TIER_MAP.get(ssvc_dec, "TRACK_ROUTINE_30D")
        decision_item["exposure"] = raw_exp

    return {
        "format": "sniper-cisa-ssvc-decision-matrix/1",
        "exposure": raw_exp,
        "decision_count": len(base["prioritized_findings"]),
        "summary": base["ssvc_summary"],
        "decisions": base["prioritized_findings"],
    }
