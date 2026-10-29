from __future__ import annotations

import math
import re


CVSS31_PREFIX = "CVSS:3.1"
_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def normalize_cwe(value: str) -> str:
    if value is not None and not isinstance(value, str):
        raise ValueError("CWE değeri CWE-79 gibi geçerli bir kimlik olmalıdır.")
    candidate = (value or "").strip().upper()
    if not candidate:
        return ""
    if candidate in ("0", "00000", "0000", "000", "00"):
        raise ValueError("CWE değeri CWE-79 gibi geçerli bir kimlik olmalıdır.")
    match = re.fullmatch(r"(?:CWE-?)?([0-9]{1,5})", candidate)
    if not match:
        raise ValueError("CWE değeri CWE-79 gibi geçerli bir kimlik olmalıdır.")
    num = int(match.group(1))
    if num == 0:
        raise ValueError("CWE değeri CWE-79 gibi geçerli bir kimlik olmalıdır.")
    return f"CWE-{num}"


def calculate_cvss31(vector: str) -> tuple[str, float | None]:
    if vector is not None and not isinstance(vector, str):
        raise ValueError("vector bir metin olmalı")
    candidate = (vector or "").strip().upper()
    if not candidate:
        return "", None
    parts = candidate.split("/")
    if parts[0] != CVSS31_PREFIX:
        raise ValueError("CVSS vektörü CVSS:3.1/ ile başlamalıdır.")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError("CVSS vektörü geçersizdir.")
        key, value = part.split(":", 1)
        if key in metrics:
            raise ValueError(f"CVSS metriği yinelenmiş: {key}.")
        metrics[key] = value
    if any(metric not in metrics for metric in _REQUIRED_METRICS):
        raise ValueError("CVSS vektöründe AV, AC, PR, UI, S, C, I ve A metriklerinin tamamı bulunmalıdır.")

    scope = metrics["S"]
    if scope not in {"U", "C"}:
        raise ValueError("CVSS S metriği U veya C olmalıdır.")
    values = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56},
    }
    pr_values = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    try:
        av = values["AV"][metrics["AV"]]
        ac = values["AC"][metrics["AC"]]
        pr = pr_values[scope][metrics["PR"]]
        ui = values["UI"][metrics["UI"]]
        confidentiality = values["C"][metrics["C"]]
        integrity = values["I"][metrics["I"]]
        availability = values["A"][metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"CVSS metriği veya değeri geçersiz: {exc.args[0]}.") from exc

    impact_subscore = 1 - (
        (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )
    if scope == "U":
        impact = 6.42 * impact_subscore
    else:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * ((impact_subscore - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    else:
        raw = min(impact + exploitability, 10) if scope == "U" else min(1.08 * (impact + exploitability), 10)
        score = math.ceil((raw * 10) - 1e-10) / 10
    normalized = "/".join([CVSS31_PREFIX] + [f"{metric}:{metrics[metric]}" for metric in _REQUIRED_METRICS])
    return normalized, score
