from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any

import legacy_basis
from project_analyzer import ProjectRejected, validate_project_path
from project_tree import ProjectTree, ProjectTreeError
from scanner import calculate_score


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

TRUST_BOUNDARY_SPECS: tuple[dict[str, Any], ...] = (
    {
        "boundary_id": "TB-01",
        "name": "TB-01 External Client & Edge",
        "description": "Public internet clients, browsers, mobile apps, TLS termination, and CORS/CSP edge headers.",
        "components": ["Web Browser / SPA", "Mobile Client (Android/iOS)", "TLS / Edge Proxy", "CORS & CSP Policy"],
        "tokens": (
            "cors", "headers", "web_hardening", "transport", "tls", "hsts", "cookie",
            "sri", "source_map", "disclosure", "masvs-network", "mobile_network",
            "cleartext", "cwe-319", "cwe-79", "cwe-942", "xss",
            "browser_extension", "pwa", "service_worker", "sniper-ext", "sniper-clnt",
            "electron", "desktop_security", "cwe-359", "cwe-668", "cwe-749",
            "cwe-113", "cwe-444", "request smuggling", "response splitting", "crlf",
        ),
    },
    {
        "boundary_id": "TB-02",
        "name": "TB-02 Application & API Gateway",
        "description": "HTTP/REST/GraphQL request routing, authentication, session verification, object-level authorization, and schema validation.",
        "components": ["REST / OpenAPI Gateway", "GraphQL Endpoint", "Session & JWT Verifier", "Rate Limiter & Input Validator"],
        "tokens": (
            "auth", "session", "api", "openapi", "graphql", "bola", "idor",
            "mass assignment", "sniper-apit", "sniper-sess", "sniper-auth",
            "owasp api", "cwe-287", "cwe-347", "cwe-352", "cwe-614", "cwe-400",
            "masvs-auth", "masvs-platform", "mobile_auth", "mobile_platform", "webview", "deeplink",
            "business", "sniper-busl", "sniper-authz", "cwe-472", "cwe-915", "cwe-841", "xsw", "saml",
            "cwe-943", "cwe-1336", "cwe-1321", "nosql", "ssti", "prototype pollution",
        ),
    },
    {
        "boundary_id": "TB-03",
        "name": "TB-03 AI / Worker & Integration Plane",
        "description": "LLM prompt orchestration, agent tool execution, outbound HTTP/webhook fetchers, and command/subprocess workers.",
        "components": ["LLM Prompt / RAG Pipeline", "Autonomous Agent Tool Runner", "Outbound HTTP / Webhook Client", "Background Task Worker"],
        "tokens": (
            "llm", "ai_llm", "prompt injection", "excessive agency", "output eval",
            "ssrf", "command_data", "subprocess", "cwe-77", "cwe-78", "cwe-94", "cwe-918",
            "llm04", "llm08", "llm09", "safetensors", "torch.load", "rag", "mcp",
            "cwe-416", "cwe-415", "cwe-787", "cwe-120", "cwe-134", "memory_safety",
            "use-after-free", "buffer overflow", "format string",
        ),
    },
    {
        "boundary_id": "TB-04",
        "name": "TB-04 Data Store & Secrets Vault",
        "description": "Relational/NoSQL databases, file storage, cryptographic keys, secrets management, and tamper-evident audit logs.",
        "components": ["Primary Database", "Secrets & Credentials Store", "Cryptographic Keyring", "Hash-Chained Audit Log"],
        "tokens": (
            "data_query", "sql", "deserializ", "pickle", "xxe", "crypto", "secrets",
            "errors", "information", "audit", "traversal", "masvs-storage", "masvs-crypto",
            "mobile_storage", "mobile_crypto", "cwe-22", "cwe-89", "cwe-200", "cwe-209",
            "cwe-327", "cwe-338", "cwe-502", "cwe-611", "cwe-798",
            "database_rls", "row level security", "security definer", "sniper-data",
            "pqc", "cbom", "cwe-312", "cwe-426", "cwe-598",
        ),
    },
    {
        "boundary_id": "TB-05",
        "name": "TB-05 Build, Container & Cloud Control Plane",
        "description": "Third-party package dependencies, CI/CD workflows, container images, Kubernetes manifests, and IaC control plane.",
        "components": ["CI/CD Workflow Runner", "Container & Kubernetes Runtime", "Package Registry & SBOM", "Cloud IAM & Metadata Service"],
        "tokens": (
            "supplychain", "dependency", "components", "container", "infrastructure",
            "workflow", "pull_request_target", "dockerfile", "privileged", "slsa",
            "typosquat", "confusion", "cve-", "ghsa-", "sniper-supp", "sniper-conf-08",
            "cwe-250", "cwe-427", "cwe-829", "cwe-1104",
            "cloud_iam", "zero_trust", "host_cis", "sniper-zt", "sniper-infr", "sniper-conf-09",
            "imdsv1", "docker.sock", "cwe-506", "mal-",
        ),
    },
)

STRIDE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "stride_code": "S",
        "category": "S: Spoofing",
        "mitigation": "Enforce MFA/strong token verification, strict CORS origins, anti-CSRF tokens, TLS 1.2+/1.3 with certificate pinning where applicable, and per-object authorization checks.",
        "tokens": (
            "auth", "session", "jwt", "cors", "csrf", "spoof", "bola", "idor",
            "sniper-sess", "sniper-auth", "sniper-apit-02", "sniper-apit-03",
            "owasp api1", "owasp api2", "masvs-auth", "mobile_auth",
            "cwe-287", "cwe-290", "cwe-345", "cwe-346", "cwe-347", "cwe-352", "cwe-942",
            "xsw", "saml",
        ),
    },
    {
        "stride_code": "T",
        "category": "T: Tampering",
        "mitigation": "Use parameterized queries, context-aware output encoding/CSP, safe deserializers, Subresource Integrity (SRI), and commit-SHA pinning for CI/CD actions and dependencies.",
        "tokens": (
            "data_query", "sql", "xss", "deserializ", "pickle", "command_data",
            "supplychain", "integrity", "sri", "mass assignment", "unpinned",
            "typosquat", "confusion", "sniper-apit-09", "sniper-supp",
            "cwe-78", "cwe-79", "cwe-89", "cwe-113", "cwe-427", "cwe-444",
            "cwe-502", "cwe-506", "cwe-829", "cwe-943", "cwe-1321",
            "nosql", "prototype pollution", "request smuggling", "mal-",
        ),
    },
    {
        "stride_code": "R",
        "category": "R: Repudiation",
        "mitigation": "Maintain tamper-evident SHA-256 hash-chained audit logs, generate SLSA v1.0 build provenance attestations, and publish valid RFC 9116 security.txt disclosure metadata.",
        "tokens": (
            "audit", "repudiation", "logging", "disclosure", "security.txt",
            "provenance", "slsa", "rfc 9116", "sniper-supp-02", "sniper-supp-05",
            "cwe-117", "cwe-778", "log injection",
        ),
    },
    {
        "stride_code": "I",
        "category": "I: Information Disclosure",
        "mitigation": "Remove hardcoded secrets, disable debug stack traces and production source maps, enforce strong encryption at rest and in transit (HSTS/TLS), and restrict XXE/path traversal.",
        "tokens": (
            "secrets", "crypto", "errors", "information", "transport", "cleartext",
            "source_map", "traversal", "xxe", "graphql", "introspection",
            "masvs-storage", "masvs-crypto", "masvs-network", "mobile_storage",
            "mobile_crypto", "mobile_network", "llm02", "llm07",
            "cwe-22", "cwe-125", "cwe-134", "cwe-200", "cwe-209", "cwe-319",
            "cwe-327", "cwe-338", "cwe-530", "cwe-532", "cwe-611", "cwe-798",
        ),
    },
    {
        "stride_code": "D",
        "category": "D: Denial of Service",
        "mitigation": "Enforce API rate limiting, bounded pagination/array schemas (maxItems/maxLength), request timeouts, and LLM token/cost quotas.",
        "tokens": (
            "rate limit", "resource", "pagination", "maxitems", "maxlength",
            "timeout", "dos", "sniper-apit-05", "owasp api4", "llm10",
            "cwe-400", "cwe-401", "cwe-415", "cwe-770", "cwe-1333", "redos",
        ),
    },
    {
        "stride_code": "E",
        "category": "E: Elevation of Privilege",
        "mitigation": "Run containers as non-root with dropped capabilities, block SSRF to internal/cloud metadata IPs, isolate LLM outputs from code/shell execution, and enforce least-privilege CI/CD tokens.",
        "tokens": (
            "container", "privileged", "root", "ssrf", "prompt injection",
            "excessive agency", "output eval", "pull_request_target", "rbac",
            "sniper-conf-08", "llm01", "llm05", "llm06",
            "cwe-77", "cwe-94", "cwe-119", "cwe-120", "cwe-250", "cwe-269",
            "cwe-416", "cwe-787", "cwe-915", "cwe-918", "cwe-1336",
            "ssti", "use-after-free", "buffer overflow",
        ),
    },
)

MITRE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "technique_id": "T1190",
        "name": "T1190 Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "mitigation": "Harden public endpoints with strict input validation, parameterized queries, SSRF allowlists, and WAF/CSP defenses.",
        "tokens": (
            "sql", "xss", "ssrf", "deserializ", "xxe", "traversal", "data_query",
            "cwe-22", "cwe-79", "cwe-89", "cwe-416", "cwe-444", "cwe-502",
            "cwe-611", "cwe-787", "cwe-918", "cwe-943", "cwe-1336",
            "nosql", "ssti", "request smuggling", "sniper-apit", "owasp api",
        ),
    },
    {
        "technique_id": "T1078",
        "name": "T1078 Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "mitigation": "Enforce strong authentication, HttpOnly/Secure/SameSite session cookies, JWT signature validation, and object-level authorization.",
        "tokens": (
            "auth", "session", "cookie", "jwt", "bola", "idor", "sniper-sess",
            "sniper-auth", "masvs-auth", "mobile_auth", "cwe-287", "cwe-347", "cwe-614",
        ),
    },
    {
        "technique_id": "T1552",
        "name": "T1552 Unsecured Credentials",
        "tactic": "Credential Access",
        "mitigation": "Eliminate hardcoded API keys/passwords in source code and mobile storage; store secrets in hardware-backed vaults or secret managers.",
        "tokens": (
            "secrets", "cwe-798", "masvs-storage", "mobile_storage",
            "sharedpreferences", "userdefaults", "key", "password", "token",
        ),
    },
    {
        "technique_id": "T1195",
        "name": "T1195 Supply Chain Compromise",
        "tactic": "Initial Access",
        "mitigation": "Pin CI/CD GitHub Actions to 40-char commit SHAs, remediate vulnerable third-party dependencies, and guard against typosquatting/dependency confusion.",
        "tokens": (
            "supplychain", "dependency", "components", "cve-", "ghsa-", "mal-", "workflow",
            "pull_request_target", "unpinned", "typosquat", "confusion",
            "sniper-supp", "cwe-427", "cwe-506", "cwe-829", "cwe-1104",
        ),
    },
    {
        "technique_id": "T1059",
        "name": "T1059 Command and Scripting Interpreter",
        "tactic": "Execution",
        "mitigation": "Avoid shell=True and dynamic eval/exec; pass command arguments as static arrays and validate all inputs.",
        "tokens": (
            "command_data", "subprocess", "eval", "exec", "cwe-77", "cwe-78", "cwe-94",
            "llm05", "ai_llm_output",
        ),
    },
    {
        "technique_id": "T1557",
        "name": "T1557 Adversary-in-the-Middle",
        "tactic": "Credential Access / Collection",
        "mitigation": "Enforce HTTPS/TLS 1.2+, HSTS preload, disable cleartext traffic on mobile (usesCleartextTraffic/NSAllowsArbitraryLoads), and validate TLS certificates.",
        "tokens": (
            "transport", "tls", "hsts", "http://", "cleartext", "masvs-network",
            "mobile_network", "cwe-319", "sniper-cryp-02",
        ),
    },
    {
        "technique_id": "T1610",
        "name": "T1610 Deploy Container",
        "tactic": "Execution / Privilege Escalation",
        "mitigation": "Enforce non-root USER in Dockerfiles, disallow privileged: true and allowPrivilegeEscalation in Kubernetes manifests, and pin image digests.",
        "tokens": (
            "container", "dockerfile", "privileged", "kubernetes", "k8s",
            "sniper-conf-08", "cwe-250",
        ),
    },
    {
        "technique_id": "AML.T0051",
        "name": "AML.T0051 LLM Prompt Injection",
        "tactic": "ML Attack Staging / Initial Access",
        "mitigation": "Separate untrusted user/RAG context from system instructions, enforce strict output schemas, and require human confirmation for high-impact agent tools.",
        "tokens": (
            "llm", "ai_llm", "prompt injection", "excessive agency", "llm01",
            "llm05", "llm06", "llm07", "llm09",
        ),
    },
    {
        "technique_id": "AML.T0020",
        "name": "AML.T0020 Poison Training Data",
        "tactic": "ML Attack Staging",
        "mitigation": "Pin Hugging Face dataset/model revisions to immutable commit SHAs, validate SFT/DPO fine-tuning corpora, and use safetensors/weights_only=True.",
        "tokens": (
            "llm03", "llm04", "llm08", "poison", "load_dataset", "sfttrainer",
            "dpotrainer", "fine_tuning", "torch.load",
        ),
    },
    {
        "technique_id": "T1528",
        "name": "T1528 Steal Application Access Token",
        "tactic": "Credential Access",
        "mitigation": "Enforce OAuth 2.0 PKCE S256, IMDSv2 (HttpTokens=required), Istio JWT audiences, and restrict browser extension cookie access.",
        "tokens": (
            "oauth", "oidc", "pkce", "sniper-ext-06", "cookies.getall",
            "imdsv1", "http_tokens", "token_endpoint", "sniper-zt-04",
            "cwe-359", "cwe-522", "cwe-598",
        ),
    },
)


def _is_false_positive(item: dict[str, Any]) -> bool:
    triage = item.get("triage")
    if isinstance(triage, dict) and str(triage.get("disposition") or "").strip().lower() == "false_positive":
        return True
    tracking = item.get("tracking")
    if isinstance(tracking, dict) and str(tracking.get("status") or "").strip().lower() in {
        "false_positive",
        "resolved",
        "closed",
    }:
        return True
    if str(item.get("disposition") or "").strip().lower() == "false_positive":
        return True
    if str(item.get("status") or "").strip().lower() in {"false_positive", "resolved", "closed"}:
        return True
    return False


def _normalize_cwe_token(raw_val: Any) -> str:
    text = str(raw_val or "").strip()
    if not text:
        return ""
    if text.isdigit():
        return f"CWE-{int(text)}"
    return text


def _normalize_finding(item: dict[str, Any], default_source: str) -> dict[str, str]:
    source = str(item.get("source") or default_source or "unknown").strip()
    category = str(
        item.get("category")
        or item.get("owasp_category")
        or item.get("domain")
        or ("dependency" if item.get("vulnerability_id") else "general")
    ).strip()
    severity = str(item.get("severity") or "medium").strip().casefold()
    if severity not in SEVERITY_RANK:
        severity = "medium"
    title = str(
        item.get("title")
        or item.get("vulnerability_id")
        or item.get("package_name")
        or "Security Finding"
    ).strip()
    cwe_norm = _normalize_cwe_token(item.get("cwe") or item.get("cwe_id"))
    reference = str(
        item.get("reference")
        or cwe_norm
        or item.get("vulnerability_id")
        or item.get("owasp_category")
        or ""
    ).strip()
    if reference.isdigit():
        reference = f"CWE-{int(reference)}"
    control_id = str(
        item.get("control_id")
        or item.get("rule_id")
        or item.get("id")
        or ""
    ).strip()
    masvs_id = str(item.get("masvs_id") or item.get("masvs") or "").strip()
    location = str(
        item.get("location")
        or item.get("file")
        or item.get("evidence")
        or item.get("package_name")
        or item.get("target")
        or ""
    ).strip()[:240]
    blob = " ".join((source, category, title, reference, cwe_norm, control_id, masvs_id, location)).casefold()
    return {
        "source": source,
        "category": category,
        "severity": severity,
        "title": title,
        "reference": reference,
        "control_id": control_id,
        "masvs_id": masvs_id,
        "location": location,
        "_blob": blob,
    }


def _matches_any(finding: dict[str, str], tokens: tuple[str, ...]) -> bool:
    blob = finding["_blob"]
    cat = finding["category"].casefold()
    ref = finding["reference"].casefold()
    ctrl = finding["control_id"].casefold()
    masvs = finding["masvs_id"].casefold()
    for token in tokens:
        low = token.casefold()
        if low in (cat, ref, ctrl, masvs) or low in blob:
            return True
    return False


def _assign_trust_boundary(finding: dict[str, str]) -> str:
    for spec in TRUST_BOUNDARY_SPECS:
        if _matches_any(finding, spec["tokens"]):
            return spec["boundary_id"]
    return "TB-02"


def _is_directory_chain(tree: ProjectTree, *parts: str) -> bool:
    directory_fd = os.dup(tree.fileno())
    try:
        for part in parts:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return True
    except OSError:
        return False
    finally:
        os.close(directory_fd)


def _is_regular_root_file(tree: ProjectTree, name: str) -> bool:
    try:
        info = os.stat(name, dir_fd=tree.fileno(), follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode)


def _discover_project_signals(tree: ProjectTree) -> list[str]:
    signals: list[str] = []
    if _is_directory_chain(tree, ".github", "workflows"):
        signals.append("github_actions")
    for name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Containerfile"):
        if _is_regular_root_file(tree, name):
            signals.append("container_runtime")
            break
    for name in ("openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "schema.graphql"):
        if _is_regular_root_file(tree, name):
            signals.append("api_contract")
            break
    for name in ("AndroidManifest.xml", "Info.plist", "Podfile.lock", "Package.resolved", "pubspec.yaml"):
        if _is_regular_root_file(tree, name):
            signals.append("mobile_surface")
            break
    for name in ("requirements.txt", "pyproject.toml", "package.json", "Cargo.toml", "go.mod", "pom.xml"):
        if _is_regular_root_file(tree, name):
            signals.append("package_manifest")
            break
    return signals


def _project_threat_model_summary(project_audit: Any) -> dict[str, Any] | None:
    """Proje analizinde saklanan gerçek tehdit modelinin (threat_model.py) özeti."""
    model = project_audit.get("threat_model") if isinstance(project_audit, dict) else None
    if not isinstance(model, dict) or not model.get("format"):
        return None
    threats = [t for t in (model.get("threats") or []) if isinstance(t, dict)]
    boundaries = [b for b in (model.get("boundaries") or []) if isinstance(b, dict)]
    return {
        "format": model.get("format"),
        "partial": bool(model.get("partial")),
        "route_count": int(model.get("route_count") or len(model.get("routes") or [])),
        "node_count": len(model.get("nodes") or []),
        "flow_count": len(model.get("flows") or []),
        "boundaries": [b.get("label") or b.get("id") for b in boundaries][:20],
        "stride_counts": model.get("stride_counts") or {},
        "threat_count": len(threats),
        "threats_with_findings": sum(1 for t in threats if t.get("status") == "finding"),
        "auth_components": list(model.get("auth_components") or [])[:20],
        "threats": threats[:25],
        "audit_id": project_audit.get("id"),
        "svg_url": f"/api/project-audits/{project_audit.get('id')}/threat-model" if project_audit.get("id") else "",
    }


def generate_threat_model(
    store: Any = None,
    *,
    project_path: str | None = None,
    scan_id: str | None = None,
    project_audit_id: str | None = None,
    engagement_id: str | None = None,
    scan: dict[str, Any] | None = None,
    project_audit: dict[str, Any] | None = None,
    engagement: dict[str, Any] | None = None,
    dependency_report: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    project_signals: list[str] = []
    if project_path is not None:
        root = validate_project_path(project_path, allowed_roots)
        try:
            with ProjectTree(root) as project_tree:
                project_signals = _discover_project_signals(project_tree)
        except ProjectTreeError as exc:
            raise ProjectRejected("Proje ağacı güvenli biçimde okunamadı.") from exc

    if store is not None:
        if scan is None and scan_id:
            if scan_id == "latest" and hasattr(store, "list_scans"):
                recent = store.list_scans(limit=1)
                if recent and isinstance(recent[0], dict):
                    scan = store.get_scan(recent[0]["id"]) if hasattr(store, "get_scan") else recent[0]
            elif hasattr(store, "get_scan"):
                scan = store.get_scan(scan_id)
        if project_audit is None and project_audit_id:
            if project_audit_id == "latest" and hasattr(store, "list_project_audits"):
                recent_audits = store.list_project_audits(limit=1)
                if recent_audits and isinstance(recent_audits[0], dict):
                    project_audit = (
                        store.get_project_audit(recent_audits[0]["id"])
                        if hasattr(store, "get_project_audit")
                        else recent_audits[0]
                    )
            elif hasattr(store, "get_project_audit"):
                project_audit = store.get_project_audit(project_audit_id)
        if engagement is None and engagement_id and hasattr(store, "get_engagement"):
            engagement = store.get_engagement(engagement_id)
        if dependency_report is None and hasattr(store, "dependency_security"):
            try:
                dependency_report = store.dependency_security()
            except Exception:
                dependency_report = None

    normalized: list[dict[str, str]] = []

    def _ingest(items: Any, default_source: str) -> None:
        if not isinstance(items, list):
            return
        for raw in items:
            if isinstance(raw, dict) and not _is_false_positive(raw):
                normalized.append(_normalize_finding(raw, default_source))

    if isinstance(scan, dict):
        _ingest(scan.get("findings"), "web_scan")
    if isinstance(project_audit, dict):
        _ingest(project_audit.get("findings"), "project_audit")
    if isinstance(engagement, dict):
        _ingest(engagement.get("findings"), "engagement")
    if isinstance(dependency_report, dict):
        _ingest(dependency_report.get("findings"), "dependency")
    if isinstance(mobile_audit, dict):
        _ingest(mobile_audit.get("findings"), "mobile_audit")
    if isinstance(findings, list):
        _ingest(findings, "explicit")

    # 23. tur: gerçek kaynak yoksa (proje klasörü, kayıt kimliği ya da bulgu listesi) şablon model üretme.
    # Bağımlılık raporu her zaman store'dan geldiği için tek başına kaynak sayılmaz.
    sources = legacy_basis.source_labels(scan=scan, project_audit=project_audit, engagement=engagement,
                                         findings=findings, mobile_audit=mobile_audit, project_path=project_path)
    legacy_basis.require_sources(sources)

    for f in normalized:
        f["trust_boundary"] = _assign_trust_boundary(f)

    # 1. Build Trust Boundaries
    trust_boundaries: list[dict[str, Any]] = []
    boundary_counts: dict[str, int] = {}
    for spec in TRUST_BOUNDARY_SPECS:
        bid = spec["boundary_id"]
        matched = [
            f for f in normalized
            if f["trust_boundary"] == bid or _matches_any(f, spec["tokens"])
        ]
        boundary_counts[bid] = len(matched)
        trust_boundaries.append({
            "boundary_id": bid,
            "name": spec["name"],
            "description": spec["description"],
            # Bulgu yokluğu sertleştirilmiş anlamına gelmez; yalnız "bulgu yok" denir.
            "status": "at_risk" if matched else "no_findings",
            "finding_count": len(matched),
            "components": list(spec["components"]),
        })

    # 2. Build STRIDE Matrix (all 6 categories always present)
    stride_matrix: list[dict[str, Any]] = []
    total_threats = 0
    for spec in STRIDE_SPECS:
        matched = [f for f in normalized if _matches_any(f, spec["tokens"])]
        threats = [
            {
                "title": f["title"],
                "severity": f["severity"],
                "category": f["category"],
                "reference": f["reference"],
                "location": f["location"],
                "trust_boundary": f["trust_boundary"],
            }
            for f in matched[:15]
        ]
        t_count = len(matched)
        total_threats += t_count
        stride_matrix.append({
            "stride_code": spec["stride_code"],
            "category": spec["category"],
            "status": "elevated" if t_count > 0 else "mitigated",
            "threat_count": t_count,
            "threats": threats,
            "mitigation": spec["mitigation"],
        })

    # 3. Build MITRE ATT&CK Mappings
    mitre_mappings: list[dict[str, Any]] = []
    for spec in MITRE_SPECS:
        matched = [f for f in normalized if _matches_any(f, spec["tokens"])]
        if not matched:
            continue
        max_rank = max((SEVERITY_RANK.get(f["severity"], 2) for f in matched), default=2)
        sev = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(max_rank, "medium")
        mitre_mappings.append({
            "technique_id": spec["technique_id"],
            "name": spec["name"],
            "tactic": spec["tactic"],
            "severity": sev,
            "finding_count": len(matched),
            "mitigation": spec["mitigation"],
            "evidence": [
                {
                    "title": f["title"],
                    "severity": f["severity"],
                    "reference": f["reference"],
                    "location": f["location"],
                }
                for f in matched[:8]
            ],
        })

    # 4. Generate Mermaid Data Flow Diagram (DFD)
    dfd_lines = [
        "flowchart LR",
        f'    TB01["TB-01 External Client & Edge ({boundary_counts.get("TB-01", 0)} bulgu)"]',
        f'    TB02["TB-02 Application & API Gateway ({boundary_counts.get("TB-02", 0)} bulgu)"]',
        f'    TB03["TB-03 AI / Worker & Integration Plane ({boundary_counts.get("TB-03", 0)} bulgu)"]',
        f'    TB04["TB-04 Data Store & Secrets Vault ({boundary_counts.get("TB-04", 0)} bulgu)"]',
        f'    TB05["TB-05 Build, Container & Cloud Control Plane ({boundary_counts.get("TB-05", 0)} bulgu)"]',
        '    TB01 -->|"HTTPS / TLS / Auth"| TB02',
        '    TB02 -->|"Tool / Prompt / Webhook"| TB03',
        '    TB02 -->|"Parameterized Query / Vault"| TB04',
        '    TB03 -->|"Scoped Data Access"| TB04',
        '    TB05 -.->|"CI/CD & Container Deploy"| TB02',
    ]
    dfd_mermaid = "\n".join(dfd_lines)

    score, grade, _ = calculate_score(normalized)

    # Proje analizinin gerçek tehdit modeli (rota envanteri, düğümler, sınırlar, STRIDE) varsa ekle.
    project_model = _project_threat_model_summary(project_audit)
    if project_model:
        sources.append("proje tehdit modeli")
    basis_kind = "real" if (normalized or project_model or project_signals) else "template"
    note = ("TB-01..TB-05 güven sınırları genel bir şablondur; bulgular bu sınırlara anahtar kelimeyle eşlenir. "
            "Projeye özgü sınırlar için project_threat_model alanına bakın.")
    if basis_kind == "template":
        note = "Kaynak bulgu içermiyor; çıktı yalnız genel şablondur. " + note

    return {
        "format": "sniper-stride-mitre-threat-model-v1",
        "project_signals": project_signals,
        "trust_boundaries": trust_boundaries,
        "boundaries_basis": "template",
        "project_threat_model": project_model,
        "data_basis": legacy_basis.data_basis(basis_kind, sources, note),
        "stride_matrix": stride_matrix,
        "mitre_attack_mappings": mitre_mappings,
        "threat_count": total_threats,
        "dfd_mermaid": dfd_mermaid,
        "risk_score": score,
        "risk_grade": grade,
    }
