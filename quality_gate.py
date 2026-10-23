"""CI/CD Security Quality Gate Policy Evaluator for Sniper."""

from __future__ import annotations

from typing import Any

import legacy_basis


SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def _is_false_positive(finding: dict[str, Any]) -> bool:
    triage = finding.get("triage")
    if isinstance(triage, dict) and str(triage.get("disposition") or "").strip().lower() == "false_positive":
        return True
    if str(finding.get("disposition") or "").strip().lower() == "false_positive":
        return True
    return False


def _resolve_latest_scan_for_target(store: Any, target_id: str) -> dict[str, Any] | None:
    if not hasattr(store, "list_scans"):
        return None
    for row in store.list_scans(limit=200):
        if isinstance(row, dict) and row.get("target_id") == target_id and row.get("status") == "completed":
            return store.get_scan(row["id"]) or row
    return None


def evaluate_quality_gate(
    store: Any,
    *,
    target_ref: str | None = None,
    project_audit_id: str | None = None,
    engagement_id: str | None = None,
    min_score: int = 80,
    max_critical: int = 0,
    max_high: int = 0,
    max_medium: int | None = None,
    max_overdue: int = 0,
    min_wstg_coverage: int = 0,
    fail_on_new_findings: bool = False,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate scan, project audit, dependency security, and engagement posture against policy thresholds."""
    scan: dict[str, Any] | None = None
    project_audit: dict[str, Any] | None = None
    engagement: dict[str, Any] | None = None

    if engagement_id:
        if engagement_id == "latest" and hasattr(store, "list_engagements"):
            engs = store.list_engagements()
            if engs:
                engagement = store.get_engagement(engs[0]["id"])
        else:
            engagement = store.get_engagement(engagement_id)
        if engagement is None:
            raise ValueError(f"Manuel denetim bulunamadı: {engagement_id}")

    if target_ref:
        direct_scan = store.get_scan(target_ref) if hasattr(store, "get_scan") else None
        if isinstance(direct_scan, dict) and direct_scan.get("status") == "completed":
            scan = direct_scan
        else:
            target = store.find_target(target_ref) if hasattr(store, "find_target") else store.get_target(target_ref)
            if target is None:
                raise ValueError(f"Hedef bulunamadı: {target_ref}")
            scan = _resolve_latest_scan_for_target(store, str(target["id"]))
            if scan is None:
                raise ValueError(f"Hedef için tamamlanmış tarama bulunamadı: {target_ref}")
    elif engagement is not None and isinstance(engagement.get("latest_scan"), dict):
        scan_cand = engagement["latest_scan"]
        scan = store.get_scan(scan_cand["id"]) if scan_cand.get("id") and hasattr(store, "get_scan") else scan_cand

    if project_audit_id:
        if project_audit_id == "latest" and hasattr(store, "list_project_audits"):
            audits = store.list_project_audits(limit=1)
            if audits:
                project_audit = store.get_project_audit(audits[0]["id"]) or audits[0]
        else:
            project_audit = store.get_project_audit(project_audit_id) if hasattr(store, "get_project_audit") else None
        if project_audit is None:
            raise ValueError(f"Proje denetimi bulunamadı: {project_audit_id}")
    elif target_ref is None and engagement_id is None:
        if scan is None and hasattr(store, "list_scans"):
            for row in store.list_scans(limit=50):
                if isinstance(row, dict) and row.get("status") == "completed":
                    scan = store.get_scan(row["id"]) or row
                    break
        if hasattr(store, "list_project_audits"):
            audits = store.list_project_audits(limit=1)
            if audits:
                project_audit = store.get_project_audit(audits[0]["id"]) or audits[0]

    severity_counts: dict[str, int] = {sev: 0 for sev in SEVERITIES}

    def _accumulate_finding(item: dict[str, Any]) -> None:
        sev = str(item.get("severity") or "info").strip().lower()
        if sev not in severity_counts:
            sev = "info"
        severity_counts[sev] += 1

    scan_active_count = 0
    if isinstance(scan, dict):
        for f in scan.get("findings") or []:
            if isinstance(f, dict) and not _is_false_positive(f):
                _accumulate_finding(f)
                scan_active_count += 1

    audit_active_count = 0
    if isinstance(project_audit, dict):
        for f in project_audit.get("findings") or []:
            if isinstance(f, dict) and not _is_false_positive(f):
                _accumulate_finding(f)
                audit_active_count += 1

    active_statuses = {"open", "in_progress", "retest_required", "reopened"}
    manual_active_count = 0
    if isinstance(engagement, dict):
        for f in engagement.get("findings") or []:
            if isinstance(f, dict) and str(f.get("status") or "open") in active_statuses:
                _accumulate_finding(f)
                manual_active_count += 1

    dep_sec = store.dependency_security() if hasattr(store, "dependency_security") else {}
    if not isinstance(dep_sec, dict):
        dep_sec = {}
    all_dep_active = [
        f for f in (dep_sec.get("findings") or [])
        if isinstance(f, dict) and str(f.get("status") or "open") in active_statuses
    ]
    if isinstance(project_audit, dict) and project_audit.get("project_path"):
        scoped_dep = [f for f in all_dep_active if f.get("project_path") == project_audit.get("project_path")]
        dep_active = scoped_dep if scoped_dep or target_ref is not None else all_dep_active
    elif target_ref is not None and project_audit is None and engagement is None:
        dep_active = []
    else:
        dep_active = all_dep_active

    # 23. tur: gerçek veri yoksa kapı "geçti" demez (önceden boş veritabanında 100 puanla geçiyordu).
    sources = legacy_basis.source_labels(
        scan=scan, project_audit=project_audit, engagement=engagement,
        extra=[f"{len(dep_active)} etkin bağımlılık bulgusu"] if dep_active else [])
    legacy_basis.require_sources(
        sources, "Değerlendirilecek veri yok: önce bir tarama, proje analizi ya da manuel denetim oluşturun.")

    for df in dep_active:
        _accumulate_finding(df)

    scores: list[int] = []
    scan_score: int | None = None
    audit_score: int | None = None
    if isinstance(scan, dict) and scan.get("score") is not None:
        scan_score = int(scan["score"])
        scores.append(scan_score)
    if isinstance(project_audit, dict) and project_audit.get("score") is not None:
        audit_score = int(project_audit["score"])
        scores.append(audit_score)

    effective_score = min(scores) if scores else 100

    if isinstance(engagement, dict):
        remediation = engagement.get("remediation") if isinstance(engagement.get("remediation"), dict) else {}
        overdue_count = int(remediation.get("overdue", 0) or 0)
        coverage_obj = engagement.get("coverage") if isinstance(engagement.get("coverage"), dict) else {}
        wstg_coverage = int(coverage_obj.get("percent", 0) or 0)
    else:
        dash = store.dashboard() if hasattr(store, "dashboard") else {}
        overdue_count = int((dash or {}).get("overdue_finding_count", 0) or 0) if target_ref is None else 0
        wstg_coverage = 0

    new_findings_count = 0
    if isinstance(scan, dict):
        comp = scan.get("comparison")
        if isinstance(comp, dict) and not comp.get("baseline", True):
            new_findings_count += int(comp.get("new_count", 0) or 0)

    if isinstance(project_audit, dict) and hasattr(store, "list_project_audits"):
        try:
            from project_audit_diff import compare_project_audits

            proj_path = project_audit.get("project_path")
            same_proj = [
                a for a in store.list_project_audits(limit=20)
                if isinstance(a, dict)
                and a.get("project_path") == proj_path
                and a.get("id") != project_audit.get("id")
                and str(a.get("created_at") or "") < str(project_audit.get("created_at") or "")
            ]
            if same_proj:
                diff_res = compare_project_audits(store, str(same_proj[0]["id"]), str(project_audit["id"]))
                new_findings_count += int(diff_res.get("new_count", 0) or 0)
        except Exception:
            pass

    checks: list[dict[str, Any]] = []
    blocking_reasons: list[str] = []

    def _add_check(check_id: str, title: str, check_passed: bool, actual: Any, threshold: Any, reason: str) -> None:
        checks.append({
            "id": check_id,
            "title": title,
            "status": "passed" if check_passed else "failed",
            "passed": check_passed,
            "actual": actual,
            "threshold": threshold,
            "detail": reason,
        })
        if not check_passed:
            blocking_reasons.append(reason)

    if isinstance(project_audit, dict):
        scope = project_audit.get("scope") if isinstance(project_audit.get("scope"), dict) else {}
        skipped = project_audit.get("skipped_files") if isinstance(project_audit.get("skipped_files"), dict) else {}
        warnings = [str(value) for value in project_audit.get("warnings") or []]
        resource_skips = {
            key: skipped[key] for key in ("budget", "time_budget", "large", "encoding")
            if isinstance(skipped.get(key), int) and skipped[key] > 0
        }
        incomplete_reasons = []
        if project_audit.get("partial"):
            incomplete_reasons.append("proje analizi kısmi")
        if scope.get("skipped_only") or scope.get("changed_only") or scope.get("only_paths") is not None:
            incomplete_reasons.append("tarama kapsamı tüm proje değil")
        if resource_skips:
            incomplete_reasons.append("kaynak sınırında atlanan dosya var")
        if any("kısmi kaldı" in warning.casefold() or "sonuç kısm" in warning.casefold() for warning in warnings):
            incomplete_reasons.append("alt motor kapsam uyarısı var")
        complete = not incomplete_reasons
        detail = ("Proje analizi kalite kapısı için tam kapsamlı."
                  if complete else "Kalite kapısı kısmi analizi geçiremez: " + ", ".join(dict.fromkeys(incomplete_reasons)) + ".")
        _add_check("analysis_complete", "Proje analiz kapsamı", complete,
                   "complete" if complete else "partial", "complete", detail)

    score_ok = effective_score >= int(min_score)
    _add_check(
        "min_score",
        "Minimum güvenlik puanı eşiği",
        score_ok,
        effective_score,
        int(min_score),
        f"Güvenlik puanı ({effective_score}) minimum eşiğin ({min_score}) altında."
        if not score_ok
        else f"Güvenlik puanı ({effective_score}) minimum eşiği ({min_score}) karşılıyor.",
    )

    crit_ok = severity_counts["critical"] <= int(max_critical)
    _add_check(
        "max_critical",
        "Maksimum kritik seviye bulgu sınırı",
        crit_ok,
        severity_counts["critical"],
        int(max_critical),
        f"Kritik seviye bulgu sayısı ({severity_counts['critical']}) izin verilen sınırı ({max_critical}) aşıyor."
        if not crit_ok
        else f"Kritik seviye bulgu sayısı ({severity_counts['critical']}) sınır ({max_critical}) içinde.",
    )

    high_ok = severity_counts["high"] <= int(max_high)
    _add_check(
        "max_high",
        "Maksimum yüksek seviye bulgu sınırı",
        high_ok,
        severity_counts["high"],
        int(max_high),
        f"Yüksek seviye bulgu sayısı ({severity_counts['high']}) izin verilen sınırı ({max_high}) aşıyor."
        if not high_ok
        else f"Yüksek seviye bulgu sayısı ({severity_counts['high']}) sınır ({max_high}) içinde.",
    )

    if max_medium is not None:
        med_ok = severity_counts["medium"] <= int(max_medium)
        _add_check(
            "max_medium",
            "Maksimum orta seviye bulgu sınırı",
            med_ok,
            severity_counts["medium"],
            int(max_medium),
            f"Orta seviye bulgu sayısı ({severity_counts['medium']}) izin verilen sınırı ({max_medium}) aşıyor."
            if not med_ok
            else f"Orta seviye bulgu sayısı ({severity_counts['medium']}) sınır ({max_medium}) içinde.",
        )

    overdue_ok = overdue_count <= int(max_overdue)
    _add_check(
        "max_overdue",
        "Maksimum süresi geçmiş (SLA aşımı) bulgu sınırı",
        overdue_ok,
        overdue_count,
        int(max_overdue),
        f"Süresi geçmiş bulgu sayısı ({overdue_count}) izin verilen sınırı ({max_overdue}) aşıyor."
        if not overdue_ok
        else f"Süresi geçmiş bulgu sayısı ({overdue_count}) sınır ({max_overdue}) içinde.",
    )

    if int(min_wstg_coverage) > 0 or engagement is not None:
        cov_ok = wstg_coverage >= int(min_wstg_coverage)
        _add_check(
            "min_wstg_coverage",
            "Minimum OWASP WSTG kapsam yüzdesi",
            cov_ok,
            wstg_coverage,
            int(min_wstg_coverage),
            f"WSTG test kapsamı (%{wstg_coverage}) minimum eşiğin (%{min_wstg_coverage}) altında."
            if not cov_ok
            else f"WSTG test kapsamı (%{wstg_coverage}) minimum eşiği (%{min_wstg_coverage}) karşılıyor.",
        )

    if fail_on_new_findings:
        new_ok = new_findings_count == 0
        _add_check(
            "fail_on_new_findings",
            "Yeni güvenlik bulgusu (regresyon) yasağı",
            new_ok,
            new_findings_count,
            0,
            f"Önceki denetime göre {new_findings_count} yeni güvenlik bulgusu tespit edildi."
            if not new_ok
            else "Yeni güvenlik bulgusu (regresyon) tespit edilmedi.",
        )

    # 23. tur: CI kapısıyla aynı politika (ci_gate) — proje analizi varsa bulgular ve bağımlılık açıkları
    # gruplarına göre değerlendirilir; kötü amaçlı paket her zaman başarısızdır.
    ci_policy = _ci_policy_decision(project_audit, dep_active, policy)
    legacy_passed = len(blocking_reasons) == 0
    if ci_policy is not None and not ci_policy["passed"]:
        blocking_reasons.extend(f"CI politikası: {reason}" for reason in ci_policy["reasons"])
    passed = len(blocking_reasons) == 0
    return {
        "format": "sniper-quality-gate-v1",
        "legacy_thresholds_passed": legacy_passed,
        "ci_policy": ci_policy,
        "data_basis": legacy_basis.data_basis("real", sources, "Eşikler ve CI politikası gerçek kayıtlar üzerinde değerlendirildi."),
        "passed": passed,
        "status": "passed" if passed else "failed",
        "exit_code": 0 if passed else 2,
        "checks": checks,
        "Blocking_reasons": list(blocking_reasons),
        "blocking_reasons": list(blocking_reasons),
        "metrics": {
            "score": effective_score,
            "scan_score": scan_score,
            "project_audit_score": audit_score,
            "scan_id": scan.get("id") if isinstance(scan, dict) else None,
            "project_audit_id": project_audit.get("id") if isinstance(project_audit, dict) else None,
            "engagement_id": engagement.get("id") if isinstance(engagement, dict) else None,
            "severity_counts": severity_counts,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "scan_active_findings": scan_active_count,
            "project_audit_active_findings": audit_active_count,
            "manual_active_findings": manual_active_count,
            "dependency_active_findings": len(dep_active),
            "overdue_findings": overdue_count,
            "wstg_coverage_percent": wstg_coverage,
            "new_findings_count": new_findings_count,
        },
    }


def _ci_policy_decision(project_audit: Any, dep_active: list[dict[str, Any]],
                        policy: dict[str, Any] | None) -> dict[str, Any] | None:
    """Proje analizi + bağımlılık açıkları üzerinde ci_gate politikası (geçersiz politika ValueError → 400)."""
    if not isinstance(project_audit, dict):
        return None
    import ci_gate
    import dependency_security

    effective = ci_gate.validate_policy(policy)
    items: list[dict[str, Any]] = [dict(f) for f in project_audit.get("findings") or [] if isinstance(f, dict)]
    for dep in dep_active:
        items.append({
            "_kind": "sca",
            "severity": str(dep.get("severity") or "medium"),
            "title": str(dep.get("title") or dep.get("vulnerability_id") or ""),
            "malicious": dependency_security.is_malicious_finding(dep),
            "priority": {"tier": dep.get("priority_tier") or ""},
        })
    decision = ci_gate.evaluate(items, effective, compared=False)
    failing = [{"title": f.get("title"), "severity": f.get("severity"), "group": ci_gate.group_of(f), "why": f.get("_why"),
                "location": f"{f.get('file')}:{f.get('line')}" if f.get("file") else ""}
               for f in decision["failing"][:25]]
    return {"passed": decision["passed"], "reasons": decision["reasons"], "failing_count": len(decision["failing"]),
            "failing": failing, "policy": {"fail_on": effective["fail_on"],
                                           "source": "istek" if policy is not None else "varsayılan"}}
