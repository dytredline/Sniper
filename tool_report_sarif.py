from __future__ import annotations

import hashlib
import json
from typing import Any

ALLOWLISTED_TOOLS = {
    "Semgrep",
    "Opengrep OSS",  # Opengrep 1.x SARIF sürücü adı (tam eşleşme)
    "Nuclei",
    "Trivy",
    "Gitleaks",
    "TruffleHog",
    "CodeQL command-line toolchain",
    "osv-scanner",
}

MAX_RUNS = 10
MAX_RESULTS = 500


def _normalize_tool_name(driver_name: str) -> str | None:
    # Exact match only: a padded name ("Semgrep ", "osv-scanner\n") is not the
    # official driver and must not be presented under the allowlisted identity.
    if driver_name in ALLOWLISTED_TOOLS:
        return driver_name
    return None


_LEVELS = ("error", "warning", "note", "none")
_KINDS = {"pass", "open", "review", "fail", "informational", "notApplicable"}


def _checked_level(value: Any) -> str:
    if not isinstance(value, str) or value not in _LEVELS:
        raise ValueError("Geçersiz düzey")
    return value


def _reference_id_matches_descriptor(reference_id: str, descriptor_id: str) -> bool:
    # SARIF 3.52.4 permits exactly one extra hierarchical component.
    prefix = descriptor_id + "/"
    return reference_id == descriptor_id or (
        reference_id.startswith(prefix) and "/" not in reference_id[len(prefix):]
    )


def _rule_descriptor(
    run: dict[str, Any], reference: dict[str, Any],
    fallback_id: Any = None, fallback_index: Any = None,
    *, require_descriptor: bool = False,
) -> tuple[dict[str, Any] | None, tuple[int, int] | None]:
    """Resolve a rule reference, rejecting inconsistent lookup and display fields."""
    if not isinstance(reference, dict):
        raise ValueError("Geçersiz kural başvurusu")
    tool = run["tool"]
    driver = tool["driver"]
    component = driver
    component_index = -1  # The driver; extensions use their array index.
    if "toolComponent" in reference:
        component_ref = reference["toolComponent"]
        if not isinstance(component_ref, dict):
            raise ValueError("Geçersiz kural araç bileşeni")
        extensions = tool.get("extensions", [])
        if not isinstance(extensions, list):
            raise ValueError("Geçersiz araç uzantıları")
        index = component_ref.get("index")
        guid = component_ref.get("guid")
        name = component_ref.get("name")
        if "index" in component_ref and (isinstance(index, bool) or not isinstance(index, int)
                                          or not 0 <= index < len(extensions)):
            raise ValueError("Geçersiz araç bileşeni sırası")
        if "guid" in component_ref and not isinstance(guid, str):
            raise ValueError("Geçersiz araç bileşeni guid değeri")
        if "name" in component_ref and not isinstance(name, str):
            raise ValueError("Geçersiz araç bileşeni adı")
        matches = []
        if guid is not None:
            matches = [(-1, driver)] if driver.get("guid") == guid else []
            matches += [(i, item) for i, item in enumerate(extensions)
                        if isinstance(item, dict) and item.get("guid") == guid]
            if len(matches) != 1:
                raise ValueError("Bilinmeyen veya belirsiz araç bileşeni guid değeri")
        if index is not None:
            component_index, component = index, extensions[index]
            if guid is not None and matches[0][0] != index:
                raise ValueError("Uyuşmayan araç bileşeni")
        elif guid is not None:
            component_index, component = matches[0]
        if not isinstance(component, dict):
            raise ValueError("Geçersiz araç bileşeni")
        # SARIF 3.54.3: name documents selection but never selects it.
        if name is not None and component.get("name") != name:
            raise ValueError("Uyuşmayan araç bileşeni")
    if not isinstance(component, dict):
        raise ValueError("Geçersiz araç bileşeni")
    rules = component.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Geçersiz araç kuralları")

    if fallback_id is not None and not isinstance(fallback_id, str):
        raise ValueError("Geçersiz kural kimliği")
    if fallback_index is not None and (isinstance(fallback_index, bool)
                                       or not isinstance(fallback_index, int)
                                       or fallback_index < 0):
        raise ValueError("Geçersiz kural sırası")
    rule_id = reference.get("id", fallback_id)
    rule_index = reference.get("index", fallback_index)
    rule_guid = reference.get("guid")
    if "id" in reference and not isinstance(rule_id, str):
        raise ValueError("Geçersiz kural kimliği")
    if "index" in reference and (isinstance(rule_index, bool)
                                  or not isinstance(rule_index, int) or rule_index < 0):
        raise ValueError("Geçersiz kural sırası")
    if "guid" in reference and not isinstance(rule_guid, str):
        raise ValueError("Geçersiz kural guid değeri")
    if fallback_id is not None and "id" in reference and rule_id != fallback_id:
        raise ValueError("Uyuşmayan kural kimliği")
    if fallback_index is not None and "index" in reference and rule_index != fallback_index:
        raise ValueError("Uyuşmayan kural sırası")

    descriptor = None
    descriptor_index = None
    if rule_index is not None:
        if rule_index >= len(rules):
            raise ValueError("Geçersiz kural sırası")
        descriptor_index, descriptor = rule_index, rules[rule_index]
    elif rule_guid is not None:
        matches = [(i, item) for i, item in enumerate(rules)
                   if isinstance(item, dict) and item.get("guid") == rule_guid]
        if len(matches) != 1:
            raise ValueError("Bilinmeyen veya belirsiz kural guid değeri")
        descriptor_index, descriptor = matches[0]
    elif rule_id is not None:
        matches = [(i, item) for i, item in enumerate(rules)
                   if isinstance(item, dict) and isinstance(item.get("id"), str)
                   and _reference_id_matches_descriptor(rule_id, item["id"])]
        if len(matches) > 1:
            raise ValueError("Belirsiz kural kimliği")
        if matches:
            descriptor_index, descriptor = matches[0]

    if descriptor is None:
        if rule_index is not None or rule_guid is not None or require_descriptor:
            raise ValueError("Bilinmeyen kural tanımlayıcısı")
        return None, None
    if not isinstance(descriptor, dict) or not isinstance(descriptor.get("id"), str):
        raise ValueError("Geçersiz kural tanımlayıcısı")
    if rule_id is not None and not _reference_id_matches_descriptor(rule_id, descriptor["id"]):
        raise ValueError("Uyuşmayan kural kimliği")
    if rule_guid is not None and descriptor.get("guid") != rule_guid:
        raise ValueError("Uyuşmayan kural guid değeri")
    return descriptor, (component_index, descriptor_index)


def _effective_level(run: dict[str, Any], result: dict[str, Any]) -> str:
    kind = result.get("kind", "fail")
    if not isinstance(kind, str) or kind not in _KINDS:
        raise ValueError("Geçersiz sonuç türü")
    if "ruleId" in result and not isinstance(result["ruleId"], str):
        raise ValueError("Geçersiz kural kimliği")
    if "ruleIndex" in result and (isinstance(result["ruleIndex"], bool)
                                  or not isinstance(result["ruleIndex"], int)
                                  or result["ruleIndex"] < 0):
        raise ValueError("Geçersiz kural sırası")
    reference = result.get("rule", {})
    descriptor, identity = _rule_descriptor(
        run, reference, result.get("ruleId"), result.get("ruleIndex"),
    )
    provenance = result.get("provenance", {})
    if not isinstance(provenance, dict):
        raise ValueError("Geçersiz sonuç kökeni")
    invocations = run.get("invocations", [])
    if not isinstance(invocations, list):
        raise ValueError("Geçersiz çağrılar")
    if "invocationIndex" in provenance:
        invocation_index = provenance["invocationIndex"]
        if (isinstance(invocation_index, bool) or not isinstance(invocation_index, int)
                or not 0 <= invocation_index < len(invocations)):
            raise ValueError("Geçersiz çağrı sırası")
    else:
        # SARIF 3.48.6: a sole invocation is selected even without provenance.
        invocation_index = 0 if len(invocations) == 1 else -1

    override_level = None
    if invocation_index >= 0:
        invocation = invocations[invocation_index]
        if not isinstance(invocation, dict):
            raise ValueError("Geçersiz çağrı")
        overrides = invocation.get("ruleConfigurationOverrides", [])
        if not isinstance(overrides, list):
            raise ValueError("Geçersiz kural geçersiz kılmaları")
        for override in overrides:
            if not isinstance(override, dict) or not isinstance(override.get("descriptor"), dict):
                raise ValueError("Geçersiz kural geçersiz kılması")
            _, override_identity = _rule_descriptor(
                run, override["descriptor"], require_descriptor=True,
            )
            configuration = override.get("configuration")
            if not isinstance(configuration, dict):
                raise ValueError("Geçersiz kural geçersiz kılma yapılandırması")
            if override_identity == identity and "level" in configuration:
                override_level = _checked_level(configuration["level"])

    if "level" in result:
        level = _checked_level(result["level"])
        if kind != "fail" and level != "none":
            raise ValueError("Başarısız olmayan sonuçların düzeyi none olmalı")
        return level
    if kind != "fail":
        return "none"
    if override_level is not None:
        return override_level
    if descriptor is not None:
        configuration = descriptor.get("defaultConfiguration", {})
        if not isinstance(configuration, dict):
            raise ValueError("Geçersiz kural varsayılan yapılandırması")
        if "level" in configuration:
            return _checked_level(configuration["level"])
    return "warning"


def _count_levels(run: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in _LEVELS}
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Sonuç bir nesne olmalı")
        counts[_effective_level(run, result)] += 1
    return counts


def _extract_run_summary(run: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(run, dict):
        raise ValueError("run bir nesne olmalı")
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise ValueError("run.tool bir sözlük olmalı")
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        raise ValueError("run.tool.driver bir sözlük olmalı")
    name = driver.get("name", "")
    if not isinstance(name, str):
        raise ValueError("run.tool.driver.name bir metin olmalı")
    canonical = _normalize_tool_name(name)
    if canonical is None:
        raise ValueError("Bilinmeyen araç")
    results = run.get("results", [])
    if not isinstance(results, list):
        raise ValueError("run.results bir liste olmalı")
    if len(results) > MAX_RESULTS:
        raise ValueError("Çok fazla sonuç")
    levels = _count_levels(run, results)
    return {
        "name": canonical,
        "result_count": len(results),
        "levels": levels,
    }


def parse_sarif_summary(sarif: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sarif, dict):
        raise ValueError("SARIF bir JSON nesnesi olmalı")
    version = sarif.get("version")
    if version != "2.1.0":
        raise ValueError("SARIF sürümü 2.1.0 olmalı")
    runs = sarif.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError("SARIF runs bir liste olmalı")
    if not runs:
        raise ValueError("SARIF en az bir run içermeli")
    if len(runs) > MAX_RUNS:
        raise ValueError("En fazla 10 run'a izin verilir")
    tools_summary = []
    total_results = 0
    for run in runs:
        summary = _extract_run_summary(run)
        tools_summary.append(summary)
        total_results += summary["result_count"]
    if total_results > MAX_RESULTS:
        raise ValueError("Toplam sonuç sayısı 500'ü aşıyor")
    canonical = {
        "version": "2.1.0",
        "run_count": len(runs),
        "result_count": total_results,
        "tools": sorted(tools_summary, key=lambda t: t["name"]),
    }
    canonical_bytes = json.dumps(sarif, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    return {
        "format": "sarif",
        "run_count": len(runs),
        "result_count": total_results,
        "report_sha256": report_sha256,
        "tools": canonical["tools"],
    }
