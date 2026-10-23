"""FIRST CVSS v4.0 sayısal puan hesaplayıcı (çevrimdışı, deterministik).

FIRST'ün resmi hesaplayıcısındaki ``cvss_score.js`` / ``macroVector`` algoritmasının
birebir Python aktarımıdır; tablolar ``cvss40_tables`` modülündedir (BSD-2-Clause,
kaynak commit ve SHA-256 değerleri orada). İşlem sırası, JS ``Math.round`` yuvarlaması,
eksik alt MacroVector (NaN) davranışı ve en yüksek vektör arama döngüsü özgün koddaki
gibi korunur; böylece sonuçlar resmi hesaplayıcıyla aynı olur.

Ağ erişimi, alt süreç veya dosya yazımı yapmaz.
"""

from __future__ import annotations

import math
from typing import Any

from cvss40_tables import CVSS_LOOKUP, MAX_COMPOSED, MAX_SEVERITY, METRIC_ORDER


BASE_METRIC_COUNT = 11
_PREFIX = "CVSS:4.0"

_AV_LEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_PR_LEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI_LEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}
_AC_LEVELS = {"L": 0.0, "H": 0.1}
_AT_LEVELS = {"N": 0.0, "P": 0.1}
_VC_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
_VI_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
_VA_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
_SC_LEVELS = {"H": 0.1, "L": 0.2, "N": 0.3}
_SI_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_SA_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_CR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
_IR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
_AR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}

_DISTANCE_LEVELS = (
    ("AV", _AV_LEVELS), ("PR", _PR_LEVELS), ("UI", _UI_LEVELS),
    ("AC", _AC_LEVELS), ("AT", _AT_LEVELS),
    ("VC", _VC_LEVELS), ("VI", _VI_LEVELS), ("VA", _VA_LEVELS),
    ("SC", _SC_LEVELS), ("SI", _SI_LEVELS), ("SA", _SA_LEVELS),
    ("CR", _CR_LEVELS), ("IR", _IR_LEVELS), ("AR", _AR_LEVELS),
)


def parse_cvss40_vector(vector: str) -> dict[str, str]:
    """CVSS:4.0 vektörünü doğrula ve tüm metrikleri (eksikler X) içeren sözlük döndür.

    Kurallar resmi hesaplayıcıyla aynıdır: metrikler belirtimdeki sırada olmalı,
    11 temel metrik zorunludur, değerler büyük/küçük harf duyarlıdır ve tekrar edemez.
    """
    if not isinstance(vector, str):
        raise ValueError("CVSS 4.0 vektörü metin olmalıdır.")
    parts = vector.strip().split("/")
    if parts[0] != _PREFIX:
        raise ValueError("CVSS 4.0 vektörü 'CVSS:4.0/' önekiyle başlamalıdır.")
    order = list(METRIC_ORDER.items())
    selected = {name: "X" for name in METRIC_ORDER}
    position = 0
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or not key or not value:
            raise ValueError(f"Geçersiz CVSS 4.0 metrik parçası: {part!r}")
        while True:
            if position >= len(order):
                raise ValueError(f"CVSS 4.0 metriği beklenmedik, tekrar ediyor veya sırası yanlış: {key}")
            expected_key, allowed = order[position]
            position += 1
            if key == expected_key:
                break
            if position <= BASE_METRIC_COUNT:
                raise ValueError(f"Zorunlu CVSS 4.0 temel metriği eksik veya sırası yanlış: {expected_key}")
        if value not in allowed:
            raise ValueError(f"CVSS 4.0 {key} için geçersiz değer: {value}")
        selected[key] = value
    if position < BASE_METRIC_COUNT:
        missing = order[position][0]
        raise ValueError(f"Zorunlu CVSS 4.0 temel metriği eksik: {missing}")
    return selected


def _m(selected: dict[str, str], metric: str) -> str:
    value = selected[metric]
    if metric == "E" and value == "X":
        return "A"
    if metric in {"CR", "IR", "AR"} and value == "X":
        return "H"
    modified = selected.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value


def macro_vector(selected: dict[str, str]) -> str:
    """EQ1..EQ6 MacroVector dizesini (ör. ``"001100"``) döndür."""
    av, pr, ui = _m(selected, "AV"), _m(selected, "PR"), _m(selected, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if _m(selected, "AC") == "L" and _m(selected, "AT") == "N" else 1

    vc, vi, va = _m(selected, "VC"), _m(selected, "VI"), _m(selected, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    if _m(selected, "MSI") == "S" or _m(selected, "MSA") == "S":
        eq4 = 0
    elif _m(selected, "SC") == "H" or _m(selected, "SI") == "H" or _m(selected, "SA") == "H":
        eq4 = 1
    else:
        eq4 = 2

    eq5 = {"A": 0, "P": 1, "U": 2}[_m(selected, "E")]

    if (
        (_m(selected, "CR") == "H" and vc == "H")
        or (_m(selected, "IR") == "H" and vi == "H")
        or (_m(selected, "AR") == "H" and va == "H")
    ):
        eq6 = 0
    else:
        eq6 = 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _extract_value_metric(metric: str, text: str) -> str:
    extracted = text[text.index(metric) + len(metric) + 1:]
    slash = extracted.find("/")
    return extracted[:slash] if slash > 0 else extracted


def _js_round_1dp(value: float) -> float:
    """JS ``Math.round(value * 10) / 10`` ile aynı sonuç (yarım değerler yukarı)."""
    scaled = value * 10
    floor = math.floor(scaled)
    rounded = floor + 1 if scaled - floor >= 0.5 else floor
    return rounded / 10


def _lookup(macro: str) -> float | None:
    return CVSS_LOOKUP.get(macro)


def _minus(value: float, other: float | None) -> float | None:
    return None if other is None else value - other


def cvss40_base_score(selected: dict[str, str], macro: str) -> float:
    if all(_m(selected, metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    value = CVSS_LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(char) for char in macro)

    score_eq1_next = _lookup(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}")
    score_eq2_next = _lookup(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}")
    if eq3 == 1 and eq6 == 1:
        score_eq3eq6_next = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 0 and eq6 == 1:
        score_eq3eq6_next = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6_next = _lookup(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    elif eq3 == 0 and eq6 == 0:
        left = _lookup(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        right = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        # JS: left > right (undefined karşılaştırması false) ise left, aksi halde right.
        score_eq3eq6_next = left if left is not None and right is not None and left > right else right
    else:
        score_eq3eq6_next = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")
    score_eq4_next = _lookup(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
    score_eq5_next = _lookup(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

    max_vectors = [
        eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5_max
        for eq1_max in MAX_COMPOSED["eq1"][eq1]
        for eq2_max in MAX_COMPOSED["eq2"][eq2]
        for eq3_eq6_max in MAX_COMPOSED["eq3"][eq3][eq6]
        for eq4_max in MAX_COMPOSED["eq4"][eq4]
        for eq5_max in MAX_COMPOSED["eq5"][eq5]
    ]
    distances: dict[str, float] = {}
    for max_vector in max_vectors:
        distances = {
            metric: levels[_m(selected, metric)] - levels[_extract_value_metric(metric, max_vector)]
            for metric, levels in _DISTANCE_LEVELS
        }
        if any(distance < 0 for distance in distances.values()):
            continue
        break

    d = distances
    current_eq1 = d["AV"] + d["PR"] + d["UI"]
    current_eq2 = d["AC"] + d["AT"]
    current_eq3eq6 = d["VC"] + d["VI"] + d["VA"] + d["CR"] + d["IR"] + d["AR"]
    current_eq4 = d["SC"] + d["SI"] + d["SA"]

    step = 0.1
    available_eq1 = _minus(value, score_eq1_next)
    available_eq2 = _minus(value, score_eq2_next)
    available_eq3eq6 = _minus(value, score_eq3eq6_next)
    available_eq4 = _minus(value, score_eq4_next)
    available_eq5 = _minus(value, score_eq5_next)

    n_existing_lower = 0
    normalized_eq1 = normalized_eq2 = normalized_eq3eq6 = normalized_eq4 = normalized_eq5 = 0.0

    if available_eq1 is not None:
        n_existing_lower += 1
        normalized_eq1 = available_eq1 * (current_eq1 / (MAX_SEVERITY["eq1"][eq1] * step))
    if available_eq2 is not None:
        n_existing_lower += 1
        normalized_eq2 = available_eq2 * (current_eq2 / (MAX_SEVERITY["eq2"][eq2] * step))
    if available_eq3eq6 is not None:
        n_existing_lower += 1
        normalized_eq3eq6 = available_eq3eq6 * (current_eq3eq6 / (MAX_SEVERITY["eq3eq6"][eq3][eq6] * step))
    if available_eq4 is not None:
        n_existing_lower += 1
        normalized_eq4 = available_eq4 * (current_eq4 / (MAX_SEVERITY["eq4"][eq4] * step))
    if available_eq5 is not None:
        n_existing_lower += 1
        normalized_eq5 = available_eq5 * 0

    if n_existing_lower == 0:
        mean_distance = 0.0
    else:
        mean_distance = (
            normalized_eq1 + normalized_eq2 + normalized_eq3eq6 + normalized_eq4 + normalized_eq5
        ) / n_existing_lower

    value -= mean_distance
    if value < 0:
        value = 0.0
    if value > 10:
        value = 10.0
    return _js_round_1dp(value)


def cvss40_severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def compute_cvss40(vector: str) -> dict[str, Any]:
    """CVSS:4.0 vektörünün resmi FIRST algoritmasıyla sayısal puanını hesapla."""
    selected = parse_cvss40_vector(vector)
    macro = macro_vector(selected)
    score = cvss40_base_score(selected, macro)
    return {
        "vector": vector.strip(),
        "score": score,
        "severity": cvss40_severity(score),
        "macro_vector": macro,
        "metrics": {key: value for key, value in selected.items() if value != "X"},
    }
