"""Defensive Blue-Team Rule Synthesizer (ModSecurity WAF, Sigma SIEM, Suricata IDS).

Synthesizes actionable virtual-patching and detection rules from Sniper security
findings across scan reports, source code audits, and mobile security assessments.
All generated rules are defensive detection and WAF virtual-patch configurations.
"""

from __future__ import annotations

from typing import Any

import legacy_basis


THREAT_FAMILY_PACKS: tuple[dict[str, Any], ...] = (
    {
        "family_id": "sql_nosql_injection",
        "title": "SQL / NoSQL Injection Virtual Patch & Detection",
        "category": "data_query",
        "keywords": (
            "data_query",
            "cwe-89",
            "cwe-943",
            "sql",
            "sqli",
            "nosql",
            "input",
            "database_rls",
            "sniper-db-04",
        ),
        "modsec_id": "990101",
        "secrule": (
            'SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|'
            'ARGS_NAMES|ARGS|XML:/* "@rx (?i:(?:union\\s+all\\s+select|select\\s+.*\\s+from|'
            '\\b(?:sleep|benchmark|waitfor\\s+delay)\\b|\\$(?:where|ne|gt|lt|regex|nin)\\b))" '
            '"id:990101,phase:2,deny,status:403,log,t:none,t:urlDecodeUni,t:lowercase,'
            'msg:\'Sniper Virtual Patch: SQL/NoSQL Injection Attempt\','
            'tag:\'application-multi\',tag:\'attack-sqli\',tag:\'CWE-89\',severity:\'CRITICAL\'"'
        ),
        "sigma_id": "sniper-sigma-sqli-001",
        "sigma_level": "critical",
        "mitre_attack": ["T1190", "T1059"],
        "sigma_yaml": (
            "title: Sniper Detection - SQL and NoSQL Injection Payloads in HTTP Request\n"
            "id: 8b41c920-9001-4a7a-b101-000000990101\n"
            "status: stable\n"
            "description: Detects SQLi and NoSQL operator injection attempts synthesized by Sniper.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-uri-query|contains:\n"
            "      - 'UNION SELECT'\n"
            "      - 'OR 1=1'\n"
            "      - 'WAITFOR DELAY'\n"
            "      - '$where'\n"
            "      - '{\"$ne\":'\n"
            "  condition: selection\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.initial_access\n"
            "  - attack.t1190\n"
        ),
        "suricata_sid": 9901001,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE SQL/NoSQL Injection Attempt"; flow:established,to_server; '
            'http.uri; pcre:"/(?:union\\s+(?:all\\s+)?select|\\$(?:where|ne|gt|regex))/i"; '
            'classtype:web-application-attack; sid:9901001; rev:1;)'
        ),
    },
    {
        "family_id": "xss_dom_csp",
        "title": "Cross-Site Scripting (XSS) & DOM Script Injection Defense",
        "category": "web_hardening",
        "keywords": (
            "xss",
            "cwe-79",
            "headers",
            "web_hardening",
            "client",
            "csp",
            "content-security-policy",
            "dom",
            "script",
        ),
        "modsec_id": "990102",
        "secrule": (
            'SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* '
            '"@rx (?i:(?:<script[^>]*>|javascript\\s*:|on(?:error|load|mouseover|focus)\\s*=|'
            'document\\.(?:cookie|domain|write)|window\\.location))" '
            '"id:990102,phase:2,deny,status:403,log,t:none,t:urlDecodeUni,t:htmlEntityDecode,'
            'msg:\'Sniper Virtual Patch: Cross-Site Scripting (XSS) Payload\','
            'tag:\'application-multi\',tag:\'attack-xss\',tag:\'CWE-79\',severity:\'HIGH\'"'
        ),
        "sigma_id": "sniper-sigma-xss-002",
        "sigma_level": "high",
        "mitre_attack": ["T1189", "T1059.007"],
        "sigma_yaml": (
            "title: Sniper Detection - Cross-Site Scripting (XSS) Probe in Web Request\n"
            "id: 8b41c920-9002-4a7a-b102-000000990102\n"
            "status: stable\n"
            "description: Detects reflected, stored, and DOM XSS vectors in HTTP parameters.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-uri-query|contains:\n"
            "      - '<script'\n"
            "      - 'javascript:'\n"
            "      - 'onerror='\n"
            "      - 'onload='\n"
            "      - 'document.cookie'\n"
            "  condition: selection\n"
            "level: high\n"
            "tags:\n"
            "  - attack.initial_access\n"
            "  - attack.t1189\n"
        ),
        "suricata_sid": 9901002,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE Cross-Site Scripting (XSS) Vector"; flow:established,to_server; '
            'http.uri; pcre:"/(?:<script[^>]*>|javascript\\s*:|on(?:error|load)\\s*=)/i"; '
            'classtype:web-application-attack; sid:9901002; rev:1;)'
        ),
    },
    {
        "family_id": "ssrf_metadata_access",
        "title": "Server-Side Request Forgery (SSRF) & Cloud IMDS Protection",
        "category": "ssrf",
        "keywords": (
            "ssrf",
            "cwe-918",
            "metadata",
            "169.254.169.254",
            "imds",
            "internal_url",
            "webhook",
        ),
        "modsec_id": "990103",
        "secrule": (
            'SecRule ARGS|REQUEST_HEADERS:X-Forwarded-Host|REQUEST_HEADERS:Host '
            '"@rx (?i:(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200|'
            '\\[::ffff:169\\.254\\.169\\.254\\]|(?:file|gopher|dict|ftp|ldap)://|'
            'https?://(?:127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0)))" '
            '"id:990103,phase:2,deny,status:403,log,t:none,t:urlDecodeUni,'
            'msg:\'Sniper Virtual Patch: SSRF & Cloud Metadata Probe\','
            'tag:\'application-multi\',tag:\'attack-ssrf\',tag:\'CWE-918\',severity:\'CRITICAL\'"'
        ),
        "sigma_id": "sniper-sigma-ssrf-003",
        "sigma_level": "critical",
        "mitre_attack": ["T1552.005", "T1190"],
        "sigma_yaml": (
            "title: Sniper Detection - SSRF Cloud Instance Metadata Service (IMDS) Access\n"
            "id: 8b41c920-9003-4a7a-b103-000000990103\n"
            "status: stable\n"
            "description: Detects attempts to reach cloud metadata endpoints or internal loopback via SSRF.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-uri-query|contains:\n"
            "      - '169.254.169.254'\n"
            "      - 'metadata.google.internal'\n"
            "      - 'latest/meta-data'\n"
            "      - 'gopher://'\n"
            "      - 'dict://'\n"
            "  condition: selection\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1552.005\n"
        ),
        "suricata_sid": 9901003,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE SSRF Cloud Metadata Probe (169.254.169.254)"; '
            'flow:established,to_server; content:"169.254.169.254"; nocase; '
            'classtype:web-application-attack; sid:9901003; rev:1;)'
        ),
    },
    {
        "family_id": "cmdi_path_traversal",
        "title": "OS Command Injection & Path Traversal / LFI Virtual Patch",
        "category": "command_data",
        "keywords": (
            "command_data",
            "cwe-78",
            "cwe-22",
            "cwe-73",
            "traversal",
            "lfi",
            "cmdi",
            "command injection",
            "path traversal",
            "rce",
        ),
        "modsec_id": "990104",
        "secrule": (
            'SecRule REQUEST_URI|ARGS|REQUEST_HEADERS '
            '"@rx (?i:(?:\\.\\./\\.\\./|/etc/(?:passwd|shadow)|c:\\\\windows\\\\system32|'
            '(?:;|\\|\\||&&|`\\s*|\\$\\()(?:cat|ls|id|whoami|uname|curl|wget|nc|bash|sh)\\b))" '
            '"id:990104,phase:2,deny,status:403,log,t:none,t:urlDecodeUni,t:normalizePath,'
            'msg:\'Sniper Virtual Patch: Command Injection or Path Traversal Attempt\','
            'tag:\'application-multi\',tag:\'attack-rce\',tag:\'CWE-78\',tag:\'CWE-22\',severity:\'CRITICAL\'"'
        ),
        "sigma_id": "sniper-sigma-cmdi-004",
        "sigma_level": "critical",
        "mitre_attack": ["T1059.004", "T1083"],
        "sigma_yaml": (
            "title: Sniper Detection - OS Command Injection and Directory Traversal\n"
            "id: 8b41c920-9004-4a7a-b104-000000990104\n"
            "status: stable\n"
            "description: Detects shell metacharacter command chaining and path traversal sequences.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-uri-query|contains:\n"
            "      - '../'\n"
            "      - '..%2f'\n"
            "      - '/etc/passwd'\n"
            "      - ';whoami'\n"
            "      - '|id'\n"
            "      - '$(curl'\n"
            "  condition: selection\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.execution\n"
            "  - attack.t1059.004\n"
        ),
        "suricata_sid": 9901004,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE Command Injection or Path Traversal"; flow:established,to_server; '
            'http.uri; pcre:"/(?:(?:\\.\\.|%2e%2e)(?:\\/|%2f)|\\/etc\\/passwd|(?:;|\\||&&)\\s*(?:id|whoami|cat|sh)\\b)/i"; '
            'classtype:web-application-attack; sid:9901004; rev:1;)'
        ),
    },
    {
        "family_id": "auth_jwt_bola",
        "title": "Authentication Bypass, JWT Tampering & BOLA Enumeration Guard",
        "category": "authentication",
        "keywords": (
            "auth",
            "authentication",
            "authorization",
            "session",
            "cwe-287",
            "cwe-347",
            "cwe-639",
            "sniper-apit-02",
            "bola",
            "idor",
            "jwt",
            "token",
        ),
        "modsec_id": "990105",
        "secrule": (
            'SecRule REQUEST_HEADERS:Authorization|ARGS:token|REQUEST_COOKIES '
            '"@rx (?i:eyJ[A-Za-z0-9_-]*\\.(?:eyJ[A-Za-z0-9_-]*\\.)?)" '
            '"id:990105,phase:1,chain,deny,status:401,log,t:none,'
            'msg:\'Sniper Virtual Patch: JWT alg=none or Unsigned Token Tampering\','
            'tag:\'application-multi\',tag:\'attack-auth\',tag:\'CWE-347\',severity:\'CRITICAL\'"\n'
            'SecRule MATCHED_VARS "@rx (?:eyJhbGciOiJub25l|eyJhbGciOiJOT05F|\\.[\\s]*$)" "t:none"'
        ),
        "sigma_id": "sniper-sigma-auth-005",
        "sigma_level": "high",
        "mitre_attack": ["T1078", "T1110", "T1550.001"],
        "sigma_yaml": (
            "title: Sniper Detection - JWT Algorithm None Tampering and BOLA Enumeration\n"
            "id: 8b41c920-9005-4a7a-b105-000000990105\n"
            "status: stable\n"
            "description: Detects unsigned JWT tokens (alg:none) and rapid sequential object ID enumeration.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-headers|contains:\n"
            "      - 'eyJhbGciOiJub25l'\n"
            "      - 'eyJhbGciOiJOT05F'\n"
            "  condition: selection\n"
            "level: high\n"
            "tags:\n"
            "  - attack.defense_evasion\n"
            "  - attack.t1550.001\n"
        ),
        "suricata_sid": 9901005,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE JWT alg=none Authentication Bypass Attempt"; '
            'flow:established,to_server; http.header; content:"eyJhbGciOiJub25l"; '
            'classtype:attempted-admin; sid:9901005; rev:1;)'
        ),
    },
    {
        "family_id": "deserialization_xxe",
        "title": "Insecure Deserialization & XML External Entity (XXE) Shield",
        "category": "deserialization",
        "keywords": (
            "cwe-502",
            "cwe-611",
            "deserialization",
            "xxe",
            "pickle",
            "yaml",
            "marshal",
            "DOCTYPE",
            "ENTITY",
        ),
        "modsec_id": "990106",
        "secrule": (
            'SecRule REQUEST_BODY|ARGS '
            '"@rx (?i:(?:<!DOCTYPE[^>]*\\[\\s*<!ENTITY|<!ENTITY\\s+%?\\s*\\w+\\s+SYSTEM|'
            'rO0ABX|aced0005|gASV|__reduce__|!!python/object))" '
            '"id:990106,phase:2,deny,status:403,log,t:none,t:urlDecodeUni,'
            'msg:\'Sniper Virtual Patch: Insecure Deserialization or XXE Payload\','
            'tag:\'application-multi\',tag:\'attack-rce\',tag:\'CWE-502\',tag:\'CWE-611\',severity:\'CRITICAL\'"'
        ),
        "sigma_id": "sniper-sigma-deser-006",
        "sigma_level": "critical",
        "mitre_attack": ["T1190", "T1059"],
        "sigma_yaml": (
            "title: Sniper Detection - XXE SYSTEM Entity or Unsafe Object Deserialization\n"
            "id: 8b41c920-9006-4a7a-b106-000000990106\n"
            "status: stable\n"
            "description: Detects Java/Python/YAML deserialization gadgets and XML external entities.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-body|contains:\n"
            "      - '<!ENTITY'\n"
            "      - 'SYSTEM \"file://'\n"
            "      - 'rO0ABX'\n"
            "      - '!!python/object'\n"
            "      - 'gASV'\n"
            "  condition: selection\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.initial_access\n"
            "  - attack.t1190\n"
        ),
        "suricata_sid": 9901006,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE XXE or Object Deserialization Payload"; '
            'flow:established,to_server; http.request_body; '
            'pcre:"/(?:<!ENTITY\\s+[^>]*SYSTEM|rO0ABX|!!python\\/object)/i"; '
            'classtype:web-application-attack; sid:9901006; rev:1;)'
        ),
    },
    {
        "family_id": "ai_llm_prompt_injection",
        "title": "AI / LLM Prompt Injection, Jailbreak & System Prompt Exfiltration Guard",
        "category": "ai_llm",
        "keywords": (
            "llm01",
            "llm02",
            "llm06",
            "cwe-77",
            "ai_llm",
            "prompt_injection",
            "prompt injection",
            "llm",
            "mcp",
            "jailbreak",
        ),
        "modsec_id": "990107",
        "secrule": (
            'SecRule REQUEST_BODY|ARGS '
            '"@rx (?i:(?:ignore\\s+(?:all\\s+)?(?:previous|prior)\\s+instructions|'
            'reveal\\s+(?:your\\s+)?system\\s+prompt|developer\\s+mode\\s+enabled|'
            '<\\|im_start\\|>\\s*system|\\[SYSTEM\\s*OVERRIDE\\]))" '
            '"id:990107,phase:2,deny,status:403,log,t:none,t:urlDecodeUni,'
            'msg:\'Sniper Virtual Patch: AI/LLM Prompt Injection Attempt\','
            'tag:\'application-multi\',tag:\'OWASP-LLM01\',tag:\'CWE-77\',severity:\'HIGH\'"'
        ),
        "sigma_id": "sniper-sigma-llm-007",
        "sigma_level": "high",
        "mitre_attack": ["T1059", "T1190"],
        "sigma_yaml": (
            "title: Sniper Detection - AI/LLM Prompt Injection and System Prompt Extraction\n"
            "id: 8b41c920-9007-4a7a-b107-000000990107\n"
            "status: stable\n"
            "description: Detects adversarial prompt override and delimiter injection targeting LLM APIs.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: application\n"
            "detection:\n"
            "  selection:\n"
            "    request_body|contains:\n"
            "      - 'ignore previous instructions'\n"
            "      - 'ignore all prior instructions'\n"
            "      - 'reveal your system prompt'\n"
            "      - '<|im_start|>system'\n"
            "  condition: selection\n"
            "level: high\n"
            "tags:\n"
            "  - attack.initial_access\n"
            "  - attack.t1190\n"
        ),
        "suricata_sid": 9901007,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE AI/LLM Prompt Injection Payload"; '
            'flow:established,to_server; http.request_body; '
            'pcre:"/(?:ignore\\s+(?:all\\s+)?(?:previous|prior)\\s+instructions|<\\|im_start\\|>\\s*system)/i"; '
            'classtype:web-application-attack; sid:9901007; rev:1;)'
        ),
    },
    {
        "family_id": "business_logic_race_rate_limit",
        "title": "Business Logic Abuse, TOCTOU Race Condition & Burst Rate-Limiting",
        "category": "business_logic",
        "keywords": (
            "cwe-362",
            "cwe-840",
            "cwe-20",
            "sniper-busl-01",
            "sniper-busl-02",
            "sniper-busl-03",
            "sniper-busl-04",
            "sniper-busl-05",
            "api_security",
            "business",
            "race",
            "toctou",
            "idempotency",
            "rate_limit",
        ),
        "modsec_id": "990108",
        "secrule": (
            'SecRule REQUEST_URI "@rx (?i:/(?:checkout|withdraw|transfer|redeem|coupon|payment|refund))" '
            '"id:990108,phase:2,chain,deny,status:429,log,t:none,'
            'msg:\'Sniper Virtual Patch: Negative Quantity/Amount or Missing Idempotency on Financial Endpoint\','
            'tag:\'application-multi\',tag:\'attack-business-logic\',tag:\'CWE-362\',severity:\'HIGH\'"\n'
            'SecRule REQUEST_BODY|ARGS "@rx (?i:\"(?:amount|quantity|price|transfer_amount)\"\\s*:\\s*-[0-9]+)" "t:none"'
        ),
        "sigma_id": "sniper-sigma-busl-008",
        "sigma_level": "high",
        "mitre_attack": ["T1190", "T1499.004"],
        "sigma_yaml": (
            "title: Sniper Detection - Financial Race Condition Burst and Negative Value Tampering\n"
            "id: 8b41c920-9008-4a7a-b108-000000990108\n"
            "status: stable\n"
            "description: Detects concurrent burst requests or negative amount manipulation on state-changing routes.\n"
            "author: Sniper Blue-Team Rule Synthesizer\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection_uri:\n"
            "    cs-uri-stem|contains:\n"
            "      - '/withdraw'\n"
            "      - '/transfer'\n"
            "      - '/checkout'\n"
            "      - '/redeem'\n"
            "  selection_negative:\n"
            "    cs-body|contains:\n"
            "      - '\"amount\":-'\n"
            "      - '\"quantity\":-'\n"
            "  condition: selection_uri and selection_negative\n"
            "level: high\n"
            "tags:\n"
            "  - attack.impact\n"
            "  - attack.t1499.004\n"
        ),
        "suricata_sid": 9901008,
        "suricata_rule": (
            'alert http $EXTERNAL_NET any -> $HOME_NET any '
            '(msg:"SNIPER-BLUE Business Logic Concurrent Burst on Financial Endpoint"; '
            'flow:established,to_server; http.method; content:"POST"; '
            'http.uri; pcre:"/\\/(?:withdraw|transfer|checkout|redeem)/i"; '
            'threshold:type both,track by_src,count 10,seconds 2; '
            'classtype:web-application-attack; sid:9901008; rev:1;)'
        ),
    },
)


def _collect_findings(
    *,
    findings: list[dict[str, Any]] | None = None,
    scan: dict[str, Any] | None = None,
    project_audit: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict):
                collected.append(item)
    for container in (scan, project_audit, mobile_audit):
        if isinstance(container, dict):
            nested = container.get("findings")
            if isinstance(nested, list):
                for item in nested:
                    if isinstance(item, dict):
                        collected.append(item)
    return collected


def _finding_searchable_text(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "id",
        "rule_id",
        "category",
        "cwe",
        "owasp",
        "title",
        "summary",
        "description",
        "check_id",
    ):
        val = finding.get(key)
        if isinstance(val, str):
            parts.append(val.lower())
        elif isinstance(val, (list, tuple)):
            parts.extend(str(x).lower() for x in val)
    return " ".join(parts)


def synthesize_blue_team_rules(
    *,
    findings: list[dict[str, Any]] | None = None,
    scan: dict[str, Any] | None = None,
    project_audit: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
    target_domain: str = "app.example.com",
    include_baseline: bool = False,
) -> dict[str, Any]:
    """Synthesize ModSecurity, Sigma, Suricata, and Nginx WAF rules from Sniper findings.

    23. tur: kurallar yalnız gerçek bulgularla eşleşen tehdit aileleri için üretilir. Bulgu yoksa ya da eşleşme yoksa
    tüm aileler için "temel" (BASELINE) kural seti yalnız ``include_baseline`` ile ve şablon etiketiyle döner."""
    sources = legacy_basis.source_labels(scan=scan, project_audit=project_audit, findings=findings,
                                         mobile_audit=mobile_audit)
    if not sources and not include_baseline:
        legacy_basis.require_sources(sources)
    domain_placeholder = not (target_domain or "").strip() or target_domain.strip() == "app.example.com"
    clean_domain = (target_domain or "app.example.com").strip() or "app.example.com"
    all_findings = _collect_findings(
        findings=findings,
        scan=scan,
        project_audit=project_audit,
        mobile_audit=mobile_audit,
    )

    matched_packs: list[tuple[dict[str, Any], list[str]]] = []
    if all_findings:
        for pack in THREAT_FAMILY_PACKS:
            matched_ids: list[str] = []
            for idx, finding in enumerate(all_findings, start=1):
                blob = _finding_searchable_text(finding)
                if any(kw in blob for kw in pack["keywords"]):
                    fid = str(
                        finding.get("id")
                        or finding.get("rule_id")
                        or finding.get("cwe")
                        or f"FIN-{idx:03d}"
                    )
                    if fid not in matched_ids:
                        matched_ids.append(fid)
            if matched_ids:
                matched_packs.append((pack, matched_ids))

    baseline_used = False
    if not matched_packs and include_baseline:
        matched_packs = [(pack, ["BASELINE"]) for pack in THREAT_FAMILY_PACKS]
        baseline_used = True

    modsecurity_rules: list[dict[str, Any]] = []
    sigma_rules: list[dict[str, Any]] = []
    suricata_rules: list[dict[str, Any]] = []

    for pack, matched_ids in matched_packs:
        modsecurity_rules.append(
            {
                "rule_id": pack["modsec_id"],
                "title": pack["title"],
                "category": pack["category"],
                "threat_family": pack["family_id"],
                "matched_finding_ids": matched_ids,
                "secrule": pack["secrule"],
            }
        )
        sigma_rules.append(
            {
                "rule_id": pack["sigma_id"],
                "title": pack["title"],
                "level": pack["sigma_level"],
                "mitre_attack": list(pack["mitre_attack"]),
                "threat_family": pack["family_id"],
                "matched_finding_ids": matched_ids,
                "sigma_yaml": pack["sigma_yaml"],
            }
        )
        suricata_rules.append(
            {
                "sid": pack["suricata_sid"],
                "title": pack["title"],
                "threat_family": pack["family_id"],
                "matched_finding_ids": matched_ids,
                "suricata_rule": pack["suricata_rule"],
            }
        )

    combined_modsecurity_conf = (
        f"# Sniper Synthesized ModSecurity Virtual Patches for {clean_domain}\n"
        "SecRuleEngine On\n"
        "SecRequestBodyAccess On\n\n"
        + "\n\n".join(rule["secrule"] for rule in modsecurity_rules)
        + "\n"
    )

    combined_sigma_yaml = "\n---\n".join(
        rule["sigma_yaml"].rstrip() for rule in sigma_rules
    ) + "\n"

    nginx_waf_snippet = (
        f"# Sniper Blue-Team Hardening & Rate-Limit Snippet for {clean_domain}\n"
        "limit_req_zone $binary_remote_addr zone=sniper_api_burst:10m rate=10r/s;\n\n"
        "server {\n"
        f"    server_name {clean_domain};\n"
        "    modsecurity on;\n"
        "    modsecurity_rules_file /etc/nginx/modsec/sniper_virtual_patches.conf;\n\n"
        "    add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none';\" always;\n"
        "    add_header X-Content-Type-Options \"nosniff\" always;\n"
        "    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n\n"
        "    location ~* ^/(?:checkout|withdraw|transfer|redeem|payment|api/auth) {\n"
        "        limit_req zone=sniper_api_burst burst=5 nodelay;\n"
        "        proxy_pass http://sniper_upstream;\n"
        "    }\n"
        "}\n"
    )

    if baseline_used:
        basis = legacy_basis.data_basis("template", sources, "Bulgularla eşleşen tehdit ailesi yok; dönen kurallar "
                                        "bulguya bağlı olmayan temel (BASELINE) şablon setidir.")
    else:
        basis = legacy_basis.data_basis("real", sources, "Kurallar yalnız bulgularla eşleşen tehdit aileleri için "
                                        "üretildi; dağıtmadan önce izleme kipinde deneyin.")
    return {
        "format": "sniper-blue-team-rules-v1",
        "data_basis": basis,
        "baseline_rules": baseline_used,
        "target_domain_placeholder": domain_placeholder,
        "target_domain": clean_domain,
        "finding_count_analyzed": len(all_findings),
        "rule_count": len(modsecurity_rules) + len(sigma_rules) + len(suricata_rules),
        "modsecurity_rules": modsecurity_rules,
        "sigma_rules": sigma_rules,
        "suricata_rules": suricata_rules,
        "nginx_waf_snippet": nginx_waf_snippet,
        "combined_modsecurity_conf": combined_modsecurity_conf,
        "combined_sigma_yaml": combined_sigma_yaml,
    }
