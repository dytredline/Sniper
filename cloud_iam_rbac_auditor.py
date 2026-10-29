from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from project_tree import ProjectTree
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500

CLOUD_IAM_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-CONF-08",
    "SNIPER-AUTHZ-02",
    "SNIPER-DATA-02",
    "SNIPER-CRYP-03",
    "SNIPER-INFR-01",
    "SNIPER-INFR-03",
]

CLOUD_SCAN_EXTENSIONS: set[str] = {".json", ".yaml", ".yml", ".tf", ".tfvars"}

SENSITIVE_INGRESS_PORTS: tuple[int, ...] = (22, 3389, 3306, 5432, 6379, 27017, 9200)

PRIV_ESC_IAM_ACTIONS: tuple[str, ...] = (
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
)


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


_TERRAFORM_STORAGE_HEADER_RE = re.compile(
    r'\bresource\s+"(aws_db_instance|aws_ebs_volume|aws_rds_cluster)"\s+"[^"]+"\s*\{',
    re.IGNORECASE,
)
_K8S_VERBS_RE = re.compile(r"verbs", re.IGNORECASE)


def _iter_terraform_storage_blocks(content: str):
    """İlk `}` ile biten Terraform depolama bloklarını ileri yönlü tara."""
    cursor = 0
    while (header := _TERRAFORM_STORAGE_HEADER_RE.search(content, cursor)) is not None:
        close = content.find("}", header.end())
        if close < 0:
            return
        yield header.start(), header.group(1), content[header.end():close], content[header.start():close + 1]
        cursor = close + 1


def _iter_k8s_wildcard_verbs(content: str):
    for found in _K8S_VERBS_RE.finditer(content):
        pos = found.end()
        while pos < len(content) and content[pos].isspace():
            pos += 1
        if pos >= len(content) or content[pos] != ":":
            continue
        pos += 1
        saw_line_break = False
        while pos < len(content) and content[pos].isspace():
            saw_line_break = saw_line_break or content[pos] in "\r\n"
            pos += 1

        if pos < len(content) and content[pos] == "[":
            pos += 1
            while pos < len(content) and content[pos].isspace():
                pos += 1
            if pos + 2 >= len(content) or content[pos] not in "'\"" or content[pos + 1] != "*" \
                    or content[pos + 2] != content[pos]:
                continue
            pos += 3
            while pos < len(content) and content[pos].isspace():
                pos += 1
            if pos >= len(content) or content[pos] != "]":
                continue
        elif saw_line_break and pos < len(content) and content[pos] == "-":
            pos += 1
            while pos < len(content) and content[pos].isspace():
                pos += 1
            if pos + 2 >= len(content) or content[pos] not in "'\"" or content[pos + 1] != "*" \
                    or content[pos + 2] != content[pos]:
                continue
        else:
            continue

        line_start = content.rfind("\n", 0, found.start()) + 1
        line_end = content.find("\n", found.start())
        if line_end < 0:
            line_end = len(content)
        yield found.start(), content[line_start:line_end].strip() or "verbs: ['*']"


def _make_cloud_finding(
    *,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
) -> dict[str, Any]:
    clean_ev = evidence.strip()[:320]
    reference = f"CIS Cloud / Kubernetes Benchmark · {cwe}"
    item = _finding(
        severity,
        category,
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, title),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    return item


def _as_str_list(val: Any) -> list[str]:
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(x) for x in val if isinstance(x, (str, int, float))]
    return []


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for val in principal.values():
            if val == "*" or (isinstance(val, list) and "*" in val):
                return True
    return False


def audit_cloud_iam_and_k8s_rbac(
    raw_content: str,
    *,
    filename: str = "policy.json",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek bulut IAM / Kubernetes RBAC içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "policy.json"
    clean_filename = filename.strip()
    lines = raw_content.splitlines()

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()

    def _add(finding: dict[str, Any]) -> None:
        key = (finding["control_id"], finding["cwe"], int(finding["line"]))
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(finding)

    # 1. Structured JSON IAM Analysis (if valid JSON object)
    parsed_json: dict[str, Any] | None = None
    stripped = raw_content.strip()
    if stripped.startswith("{"):
        try:
            candidate = json.loads(stripped)
            if isinstance(candidate, dict):
                parsed_json = candidate
        except ValueError:
            parsed_json = None

    if parsed_json is not None:
        statements = parsed_json.get("Statement") or parsed_json.get("statement") or []
        if isinstance(statements, dict):
            statements = [statements]
        if isinstance(statements, list):
            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                effect = str(stmt.get("Effect") or stmt.get("effect") or "").strip().lower()
                if effect != "allow":
                    continue
                actions = _as_str_list(stmt.get("Action") or stmt.get("action"))
                resources = _as_str_list(stmt.get("Resource") or stmt.get("resource"))
                principal = stmt.get("Principal") if "Principal" in stmt else stmt.get("principal")
                condition = stmt.get("Condition") or stmt.get("condition")

                has_wildcard_action = any(a.strip() in {"*", "*:*"} for a in actions)
                has_wildcard_resource = any(r.strip() == "*" or r.strip().endswith(":*") for r in resources)

                if has_wildcard_action and has_wildcard_resource:
                    _add(
                        _make_cloud_finding(
                            severity="critical",
                            category="configuration",
                            title="IAM politikasında tam yönetici yetkisi (Action: * ve Resource: *)",
                            description=(
                                "IAM politikası tüm eylemlere (Action: '*') ve tüm kaynaklara (Resource: '*') "
                                "koşulsuz Allow izni tanımlıyor; en az ayrıcalık ilkesini ihlal eder."
                            ),
                            evidence=json.dumps(stmt, ensure_ascii=False)[:240],
                            recommendation=(
                                "Wildcard ('*') eylem ve kaynak izinlerini kaldırın; yalnızca gerekli "
                                "hizmet eylemlerini ve belirli ARN kaynaklarını tanımlayın."
                            ),
                            cwe="CWE-250",
                            control_id="SNIPER-CONF-08",
                            filename=clean_filename,
                            line=1,
                        )
                    )

                matched_esc = [
                    act
                    for act in actions
                    if any(
                        act.lower() == esc.lower() or act.lower() == "iam:*"
                        for esc in PRIV_ESC_IAM_ACTIONS
                    )
                ]
                if matched_esc and (has_wildcard_resource or not resources):
                    _add(
                        _make_cloud_finding(
                            severity="high",
                            category="authorization",
                            title="IAM ayrıcalık yükseltme (Privilege Escalation) yolu tespit edildi",
                            description=(
                                "IAM politikasında ayrıcalık yükseltmeye olanak tanıyan kritik izinler "
                                f"({', '.join(matched_esc)}) geniş kaynak kapsamıyla (Resource: '*') verilmiş."
                            ),
                            evidence=json.dumps(stmt, ensure_ascii=False)[:240],
                            recommendation=(
                                "iam:PassRole, iam:AttachRolePolicy, iam:PutUserPolicy, iam:CreateAccessKey ve "
                                "sts:AssumeRole izinlerini belirli hedef ARN'ler ve IAM Conditions ile kısıtlayın."
                            ),
                            cwe="CWE-269",
                            control_id="SNIPER-AUTHZ-02",
                            filename=clean_filename,
                            line=1,
                        )
                    )

                if _principal_is_public(principal) and not condition:
                    _add(
                        _make_cloud_finding(
                            severity="critical",
                            category="data",
                            title="Herkese açık (Principal: '*') bulut depolama / S3 kaynak politikası",
                            description=(
                                "Kaynak politikası Principal: '*' veya AWS: '*' ile anonim genel erişime "
                                "sıkı bir Condition kısıtlaması olmadan izin veriyor."
                            ),
                            evidence=json.dumps(stmt, ensure_ascii=False)[:240],
                            recommendation=(
                                "Genel Principal ('*') erişimini kaldırın, S3 Block Public Access ayarlarını "
                                "etkinleştirin ve erişimi belirli IAM rolleri veya VPC uç noktalarıyla sınırlandırın."
                            ),
                            cwe="CWE-284",
                            control_id="SNIPER-DATA-02",
                            filename=clean_filename,
                            line=1,
                        )
                    )

    # 2. Text / HCL / YAML Pattern Analysis for IAM Wildcard & Privilege Escalation
    wildcard_iam_re = re.compile(
        r"(?is)(?:[\"']?Effect[\"']?\s*[:=]\s*[\"']?Allow[\"']?.*?[\"']?Action[\"']?\s*[:=]\s*(?:\[\s*)?[\"']\*[\"']"
        r".*?[\"']?Resource[\"']?\s*[:=]\s*(?:\[\s*)?[\"']\*[\"']"
        r"|actions\s*=\s*\[\s*[\"']\*[\"']\s*\].*?resources\s*=\s*\[\s*[\"']\*[\"']\s*\])"
    )
    for match in wildcard_iam_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_cloud_finding(
                severity="critical",
                category="configuration",
                title="IAM politikasında tam yönetici yetkisi (Action: * ve Resource: *)",
                description=(
                    "IAM politikası tüm eylemlere (Action: '*') ve tüm kaynaklara (Resource: '*') "
                    "Allow izni tanımlıyor."
                ),
                evidence=snippet,
                recommendation=(
                    "Wildcard ('*') eylem ve kaynak izinlerini kaldırın; yalnızca gerekli "
                    "hizmet eylemlerini ve belirli ARN kaynaklarını tanımlayın."
                ),
                cwe="CWE-250",
                control_id="SNIPER-CONF-08",
                filename=clean_filename,
                line=line_no,
            )
        )

    priv_esc_re = re.compile(
        r"\b(?:iam:PassRole|iam:CreatePolicyVersion|iam:AttachRolePolicy|iam:AttachUserPolicy|"
        r"iam:PutUserPolicy|iam:PutRolePolicy|iam:CreateAccessKey|sts:AssumeRole)\b",
        re.IGNORECASE,
    )
    for match in priv_esc_re.finditer(raw_content):
        if re.search(r"[\"']?(?:Resource|resources)[\"']?\s*[:=]\s*(?:\[\s*)?[\"']\*[\"']", raw_content):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_cloud_finding(
                    severity="high",
                    category="authorization",
                    title=f"IAM ayrıcalık yükseltme izni ({match.group(0)}) wildcard kaynak ile kullanılıyor",
                    description=(
                        f"{match.group(0)} izni Resource: '*' ile birleştirildiğinde saldırganın daha yüksek "
                        "yetkili bir rolü devralmasına veya yeni yönetici anahtarı üretmesine imkan tanır."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "İzni yalnızca belirli hedef rol ARN'leriyle sınırlandırın ve zorunlu Condition "
                        "(ör. iam:PassedToService, MFA) kontrolleri ekleyin."
                    ),
                    cwe="CWE-269",
                    control_id="SNIPER-AUTHZ-02",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 3. Public Cloud Storage / Bucket Exposure (S3, GCS, Azure Blob, Terraform)
    public_storage_re = re.compile(
        r"(?im)(?:\b(?:allUsers|allAuthenticatedUsers)\b"
        r"|\bacl\s*[:=]\s*[\"']?public-read(?:-write)?[\"']?"
        r"|\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*[:=]\s*false\b"
        r"|\b(?:allow_blob_public_access|public_network_access_enabled)\s*[:=]\s*true\b"
        r"|[\"']Principal[\"']\s*:\s*(?:[\"']\*[\"']|\{\s*[\"']AWS[\"']\s*:\s*[\"']\*[\"']\s*\}))"
    )
    for match in public_storage_re.finditer(raw_content):
        if "Principal" in match.group(0) and re.search(r"[\"']Condition[\"']\s*:", raw_content):
            continue
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_cloud_finding(
                severity="critical",
                category="data",
                title="Herkese açık bulut depolama kovası (Public Storage Bucket) yapılandırması",
                description=(
                    "Bulut depolama yapılandırmasında anonim genel erişime (public-read, allUsers, "
                    "block_public_acls=false veya allow_blob_public_access=true) izin verildiği tespit edildi."
                ),
                evidence=snippet,
                recommendation=(
                    "Genel kova erişimini devre dışı bırakın (block_public_acls=true, allUsers kaldırımı) "
                    "ve nesne erişimini imzalı URL'ler veya özel IAM rolleri üzerinden sağlayın."
                ),
                cwe="CWE-284",
                control_id="SNIPER-DATA-02",
                filename=clean_filename,
                line=line_no,
            )
        )

    # 4. Unencrypted Cloud Storage / RDS / Disk
    unencrypted_re = re.compile(
        r"(?im)\b(?:storage_encrypted|encrypted|enable_https_traffic_only|infrastructure_encryption_enabled)\s*[:=]\s*false\b"
    )
    for match in unencrypted_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_cloud_finding(
                severity="high",
                category="cryptography",
                title="Bulut depolama veya veritabanı kaynağında şifreleme devre dışı",
                description=(
                    "Bulut diski, RDS veritabanı veya depolama kaynağında durağan veri şifrelemesi "
                    "(encrypted = false / storage_encrypted = false) açıkça kapatılmış."
                ),
                evidence=snippet,
                recommendation=(
                    "Tüm bulut depolama birimlerinde ve veritabanlarında KMS tabanlı durağan veri "
                    "şifrelemesini (encrypted = true, storage_encrypted = true) zorunlu kılın."
                ),
                cwe="CWE-311",
                control_id="SNIPER-CRYP-03",
                filename=clean_filename,
                line=line_no,
            )
        )

    for resource_start, resource_type, block_body, resource_text in _iter_terraform_storage_blocks(raw_content):
        if not re.search(r"\b(?:storage_encrypted|encrypted)\s*=\s*true\b", block_body, re.IGNORECASE):
            line_no = _line_number_for_offset(raw_content, resource_start)
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else resource_text.splitlines()[0]
            _add(
                _make_cloud_finding(
                    severity="high",
                    category="cryptography",
                    title=f"Terraform {resource_type} kaynağında durağan veri şifrelemesi tanımlanmamış",
                    description=(
                        f"{resource_type} kaynağında encrypted/storage_encrypted = true ayarı "
                        "bulunmuyor; veriler şifrelenmemiş olarak depolanabilir."
                    ),
                    evidence=snippet,
                    recommendation="Kaynak bloğuna encrypted = true / storage_encrypted = true ve kms_key_id ekleyin.",
                    cwe="CWE-311",
                    control_id="SNIPER-CRYP-03",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 5. Open Ingress Security Group / Firewall (0.0.0.0/0 or ::/0 on sensitive ports or all ports)
    open_cidr_re = re.compile(r"(?:0\.0\.0\.0/0|::/0)")
    ports_pattern = "|".join(str(p) for p in SENSITIVE_INGRESS_PORTS)
    sensitive_port_re = re.compile(
        rf"(?:\b(?:from_port|to_port|port|containerPort|destination_port_range)\s*[:=]\s*[\"']?(?:{ports_pattern}|0|65535)[\"']?\b"
        rf"|\bprotocol\s*[:=]\s*[\"']?-1[\"']?)"
    )
    for match in open_cidr_re.finditer(raw_content):
        window_start = max(0, match.start() - 450)
        window_end = min(len(raw_content), match.end() + 450)
        window = raw_content[window_start:window_end]
        if sensitive_port_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_cloud_finding(
                    severity="high",
                    category="infrastructure",
                    title="Güvenlik grubunda (Security Group / Firewall) hassas porta genel internet erişimi (0.0.0.0/0)",
                    description=(
                        "Güvenlik duvarı / Security Group kuralı 0.0.0.0/0 veya ::/0 üzerinden yönetim/veritabanı "
                        "portlarına (SSH 22, RDP 3389, DB 3306/5432/6379/27017/9200 veya tüm portlar) doğrudan erişim açıyor."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "0.0.0.0/0 ve ::/0 gelen (ingress) kurallarını kaldırın; yönetim ve veritabanı erişimini "
                        "VPN/Bastion, özel alt ağ (private subnet) veya belirli güvenlik gruplarıyla sınırlandırın."
                    ),
                    cwe="CWE-284",
                    control_id="SNIPER-INFR-01",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 6. Kubernetes RBAC Over-Privilege
    k8s_cluster_admin_re = re.compile(
        r"(?is)kind\s*:\s*(?:ClusterRoleBinding|RoleBinding)\b.*?\bname\s*:\s*[\"']?cluster-admin[\"']?"
    )
    for match in k8s_cluster_admin_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else "cluster-admin binding"
        _add(
            _make_cloud_finding(
                severity="critical",
                category="configuration",
                title="Kubernetes RBAC: cluster-admin rol bağlaması (ClusterRoleBinding)",
                description=(
                    "Rol bağlaması (RoleBinding/ClusterRoleBinding) doğrudan cluster-admin rolüne "
                    "atanmış; bu yetki küme üzerindeki tüm kaynaklarda tam denetim sağlar."
                ),
                evidence=snippet,
                recommendation=(
                    "cluster-admin rolünü iş yükü veya servis hesaplarına atamayın; ad alanı (namespace) "
                    "kapsamlı ve yalnızca gerekli fiilleri içeren özel Role tanımları kullanın."
                ),
                cwe="CWE-250",
                control_id="SNIPER-CONF-08",
                filename=clean_filename,
                line=line_no,
            )
        )

    for verbs_start, verbs_text in _iter_k8s_wildcard_verbs(raw_content):
        line_no = _line_number_for_offset(raw_content, verbs_start)
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else verbs_text
        _add(
            _make_cloud_finding(
                severity="critical",
                category="configuration",
                title="Kubernetes RBAC: Tüm eylemlere izin veren wildcard fiil (verbs: ['*'])",
                description=(
                    "Kubernetes Role/ClusterRole tanımı verbs: ['*'] ile tüm API işlemlerine izin veriyor."
                ),
                evidence=snippet,
                recommendation="Wildcard ('*') fiillerini kaldırıp yalnızca get, list, watch gibi gerekli fiilleri belirtin.",
                cwe="CWE-250",
                control_id="SNIPER-CONF-08",
                filename=clean_filename,
                line=line_no,
            )
        )

    k8s_sensitive_rbac_re = re.compile(
        r"(?im)\b(?:resources\s*:\s*\[[^\]]*[\"'](?:secrets|pods/exec|nodes/proxy|serviceaccounts/token)[\"']"
        r"|-\s*[\"']?(?:secrets|pods/exec|nodes/proxy)[\"']?\s*$"
        r"|verbs\s*:\s*\[[^\]]*[\"'](?:escalate|bind|impersonate)[\"'])"
    )
    if re.search(r"(?im)^kind\s*:\s*(?:ClusterRole|Role)\b", raw_content):
        for match in k8s_sensitive_rbac_re.finditer(raw_content):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_cloud_finding(
                    severity="high",
                    category="configuration",
                    title="Kubernetes RBAC: Hassas kaynak veya yetki yükseltme izni (secrets / pods/exec / escalate)",
                    description=(
                        "Kubernetes Role/ClusterRole tanımı secrets, pods/exec, nodes/proxy kaynaklarına "
                        "veya escalate/bind/impersonate fiillerine erişim veriyor."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Sır (secrets) okuma ve pod içinde komut çalıştırma (pods/exec) izinlerini "
                        "genel rollerden kaldırın ve RBAC kapsamını daraltın."
                    ),
                    cwe="CWE-250",
                    control_id="SNIPER-CONF-08",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 7. Kubernetes ServiceAccount & Network Isolation
    # YAML indentation is horizontal.  Using ``\s*`` after ``^`` can retry across
    # every following blank line and become quadratic on newline-heavy input.
    automount_re = re.compile(r"(?im)^[ \t]*automountServiceAccountToken[ \t]*:[ \t]*true\b")
    for match in automount_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_cloud_finding(
                severity="medium",
                category="infrastructure",
                title="Kubernetes: Servis hesabı jetonu otomatik bağlama açık (automountServiceAccountToken: true)",
                description=(
                    "Pod veya ServiceAccount üzerinde automountServiceAccountToken: true etkin; "
                    "ele geçirilen bir konteyner Kubernetes API jetonuna doğrudan erişebilir."
                ),
                evidence=snippet,
                recommendation=(
                    "Kubernetes API erişimine ihtiyaç duymayan tüm iş yüklerinde "
                    "automountServiceAccountToken: false ayarlayın."
                ),
                cwe="CWE-284",
                control_id="SNIPER-INFR-03",
                filename=clean_filename,
                line=line_no,
            )
        )

    workload_match = re.search(
        r"(?im)^[ \t]*kind[ \t]*:[ \t]*(Pod|Deployment|StatefulSet|DaemonSet|Job)\b",
        raw_content,
    )
    has_network_policy = bool(re.search(r"(?im)^[ \t]*kind[ \t]*:[ \t]*NetworkPolicy\b", raw_content))
    if workload_match and not has_network_policy:
        line_no = _line_number_for_offset(raw_content, workload_match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else workload_match.group(0)
        _add(
            _make_cloud_finding(
                severity="medium",
                category="infrastructure",
                title="Kubernetes iş yükü manifestinde NetworkPolicy ağ izolasyonu eksik",
                description=(
                    f"Kubernetes {workload_match.group(1)} iş yükü tanımlanmış ancak gelen/giden pod "
                    "trafiğini sınırlandıran eşleşen bir NetworkPolicy bulunamadı."
                ),
                evidence=snippet,
                recommendation=(
                    "Ad alanı (namespace) için varsayılan reddetme (default-deny) ve iş yüküne özel "
                    "ingress/egress kuralları içeren bir Kubernetes NetworkPolicy ekleyin."
                ),
                cwe="CWE-284",
                control_id="SNIPER-INFR-03",
                filename=clean_filename,
                line=line_no,
            )
        )

    # 8. AWS EC2 IMDSv1 Enabled (http_tokens = optional) & Kubernetes Container Escape Primitives
    imdsv1_re = re.compile(
        r"(?im)\b(?:http_tokens|HttpTokens)\s*[:=]\s*[\"']?optional[\"']?\b"
    )
    for match in imdsv1_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_cloud_finding(
                severity="high",
                category="infrastructure",
                title="Bulut örnek meta veri servisinde IMDSv1 etkin (http_tokens = optional): SSRF ile IAM rolü çalınma riski",
                description=(
                    "EC2 / bulut sanal makine yapılandırmasında IMDSv2 oturum jetonu zorunluluğu "
                    "(http_tokens = 'required') devre dışı bırakılmış ('optional'); olası bir SSRF açığı "
                    "169.254.169.254 üzerinden geçici IAM kimlik bilgilerini doğrudan sızdırabilir."
                ),
                evidence=snippet,
                recommendation=(
                    "metadata_options bloğunda http_tokens = 'required' ve "
                    "http_put_response_hop_limit = 1 ayarlarını zorunlu kılın."
                ),
                cwe="CWE-918",
                control_id="SNIPER-INFR-03",
                filename=clean_filename,
                line=line_no,
            )
        )

    k8s_escape_re = re.compile(
        r"(?im)^[ \t]*(?:privileged[ \t]*:[ \t]*true\b"
        r"|(?:hostPID|hostIPC|hostNetwork)[ \t]*:[ \t]*true\b"
        r"|path[ \t]*:[ \t]*[\"']?(?:/var/run/docker\.sock|/run/containerd/containerd\.sock|/var/run/crio/crio\.sock)[\"']?)"
    )
    for match in k8s_escape_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_cloud_finding(
                severity="critical",
                category="configuration",
                title="Kubernetes konteyner kaçış (Container Escape) yapılandırması: privileged / hostNamespace / runtime soketi",
                description=(
                    "İş yükü manifestinde privileged: true, hostPID/hostIPC/hostNetwork: true veya "
                    "konteyner çalışma zamanı soketi (docker.sock / containerd.sock) bağlaması tespit edildi; "
                    "konteynerden ana düğüme (host node) tam yetki kaçışı yapılabilir."
                ),
                evidence=snippet,
                recommendation=(
                    "privileged, hostPID, hostIPC ve hostNetwork bayraklarını false yapın; "
                    "docker.sock/containerd.sock hostPath bağlamalarını kaldırın ve Pod Security Standards 'restricted' profilini uygulayın."
                ),
                cwe="CWE-250",
                control_id="SNIPER-CONF-08",
                filename=clean_filename,
                line=line_no,
            )
        )

    score, grade = calculate_score(findings)
    return {
        "format": "sniper-cloud-iam-rbac-audit-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": list(CLOUD_IAM_CONTROLS_EVALUATED),
    }


@project_scan_scope
def audit_cloud_iam_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    findings: list[dict[str, Any]] = []
    scanned_files = 0

    with ProjectTree(root) as tree:
        for project_file in tree.iter_files(skip_dirs=SKIP_DIRS, reject_unsafe=False):
            if scanned_files >= MAX_PROJECT_FILES:
                continue
            if any(part.casefold() in SKIP_DIRS for part in project_file.path.parts[:-1]):
                continue
            ext = project_file.path.suffix.lower()
            if ext not in CLOUD_SCAN_EXTENSIONS:
                continue
            if project_file.size == 0 or project_file.size > MAX_INLINE_BYTES:
                continue
            content = tree.read_text(project_file, MAX_INLINE_BYTES, errors="replace")
            if not content.strip():
                continue
            rel_name = project_file.path.as_posix()
            scanned_files += 1
            file_report = audit_cloud_iam_and_k8s_rbac(content, filename=rel_name)
            findings.extend(file_report["findings"])

    score, grade = calculate_score(findings)
    return {
        "format": "sniper-cloud-iam-project-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "controls_evaluated": list(CLOUD_IAM_CONTROLS_EVALUATED),
    }


def audit_cloud_privesc_chains(
    raw_content: str,
    *,
    filename: str = "main.tf",
) -> dict[str, Any]:
    """Bulut IAM ve Kubernetes manifestlerinde kritik yetki yükseltme / kaçış zincirlerini denetler."""
    clean_filename = filename.strip() if isinstance(filename, str) and filename.strip() else "main.tf"
    if not isinstance(raw_content, str) or not raw_content.strip():
        return {"findings": [], "count": 0, "filename": clean_filename}

    lines = raw_content.splitlines()
    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()

    def _add(finding: dict[str, Any], description: str) -> None:
        finding["id"] = finding["control_id"]
        finding["rule_id"] = finding["control_id"]
        finding["description"] = description
        key = (finding["control_id"], finding["cwe"], int(finding["line"]))
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(finding)

    # (a) SNIPER-CLOUD-PRIVESC-01: AWS IAM PassRole + Workload Execution chain
    passrole_re = re.compile(r"\biam:(?:PassRole|\*)", re.IGNORECASE)
    workload_exec_re = re.compile(
        r"\b(?:ec2:(?:RunInstances|\*)|lambda:(?:CreateFunction|\*)|"
        r"ecs:(?:RunTask|\*)|glue:(?:CreateDevEndpoint|\*))",
        re.IGNORECASE,
    )
    passrole_match = passrole_re.search(raw_content)
    workload_match = workload_exec_re.search(raw_content)
    if passrole_match and workload_match:
        line_no = _line_number_for_offset(raw_content, passrole_match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else f"{passrole_match.group(0)} + {workload_match.group(0)}"
        desc = (
            f"Politikada '{passrole_match.group(0)}' izni ile iş yükü başlatma izni "
            f"('{workload_match.group(0)}') birlikte tanımlanmış; saldırgan yüksek yetkili bir IAM "
            "rolünü yeni bir EC2/Lambda/ECS/Glue iş yüküne aktararak tam yetki yükseltme yapabilir."
        )
        _add(
            _make_cloud_finding(
                severity="critical",
                category="cloud",
                title="AWS IAM PassRole + İş Yükü Çalıştırma (EC2/Lambda/ECS) yetki yükseltme zinciri",
                description=desc,
                evidence=snippet,
                recommendation=(
                    "iam:PassRole iznini yalnızca belirli hedef rol ARN'leriyle sınırlandırın ve "
                    "iam:PassedToService koşulunu zorunlu kılın."
                ),
                cwe="CWE-269",
                control_id="SNIPER-CLOUD-PRIVESC-01",
                filename=clean_filename,
                line=line_no,
            ),
            desc,
        )

    # (b) SNIPER-CLOUD-OIDC-02: GitHub Actions OIDC AssumeRoleWithWebIdentity missing/wildcard sub condition
    web_id_match = re.search(r"\b(?:sts:)?AssumeRoleWithWebIdentity\b", raw_content, re.IGNORECASE)
    gh_oidc_match = re.search(r"token\.actions\.githubusercontent\.com", raw_content, re.IGNORECASE)
    if web_id_match and gh_oidc_match:
        sub_matches = list(
            re.finditer(r"token\.actions\.githubusercontent\.com:sub\b", raw_content, re.IGNORECASE)
        )
        wildcard_sub_re = re.compile(
            r'["\']\s*(?:\*|repo:\*(?:[:/][^"\']*)?|repo:[^/"\']+/\*(?:[:/][^"\']*)?)\s*["\']',
            re.IGNORECASE,
        )
        has_missing_or_wildcard_sub = False
        anchor_offset = gh_oidc_match.start()
        if not sub_matches:
            has_missing_or_wildcard_sub = True
        else:
            for sub_m in sub_matches:
                w_start = max(0, sub_m.start() - 80)
                w_end = min(len(raw_content), sub_m.end() + 300)
                if wildcard_sub_re.search(raw_content[w_start:w_end]):
                    has_missing_or_wildcard_sub = True
                    anchor_offset = sub_m.start()
                    break

        if has_missing_or_wildcard_sub:
            line_no = _line_number_for_offset(raw_content, anchor_offset)
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else "token.actions.githubusercontent.com"
            desc = (
                "GitHub Actions OIDC güven politikasında (AssumeRoleWithWebIdentity) "
                "'token.actions.githubusercontent.com:sub' koşulu eksik veya wildcard ('*' / 'repo:*') "
                "olarak bırakılmış; herhangi bir GitHub deposu bu AWS IAM rolünü devralabilir."
            )
            _add(
                _make_cloud_finding(
                    severity="critical",
                    category="cloud",
                    title="GitHub Actions OIDC AssumeRoleWithWebIdentity güven politikasında depo (sub) kısıtı eksik",
                    description=desc,
                    evidence=snippet,
                    recommendation=(
                        "Condition bloğunda 'token.actions.githubusercontent.com:sub' değerini "
                        "'repo:ORG/REPO:ref:refs/heads/main' gibi belirli organizasyon, depo ve dal ile sınırlandırın."
                    ),
                    cwe="CWE-287",
                    control_id="SNIPER-CLOUD-OIDC-02",
                    filename=clean_filename,
                    line=line_no,
                ),
                desc,
            )

    # (c) SNIPER-K8S-ESCAPE-03: Kubernetes Pod-Escape chain (hostPID/hostIPC/hostNetwork/privileged/docker.sock)
    k8s_escape_chain_re = re.compile(
        r"(?im)(?:\b(?:privileged|hostPID|hostIPC|hostNetwork|host_pid|host_ipc|host_network)\s*[:=]\s*true\b"
        r"|(?:/var/run/docker\.sock|/run/containerd/containerd\.sock|/var/run/crio/crio\.sock))"
    )
    for match in k8s_escape_chain_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        desc = (
            "Kubernetes iş yükü tanımında hostPID/hostIPC/hostNetwork: true, privileged: true veya "
            "konteyner çalışma zamanı soketi (docker.sock / containerd.sock) bağlaması tespit edildi; "
            "konteynerden ana düğüme (node) kaçış yapılabilir."
        )
        _add(
            _make_cloud_finding(
                severity="critical",
                category="container",
                title="Kubernetes Pod-Escape zinciri (hostPID/hostNetwork veya docker.sock bağlama)",
                description=desc,
                evidence=snippet,
                recommendation=(
                    "hostPID, hostIPC, hostNetwork ve privileged bayraklarını devre dışı bırakın; "
                    "docker.sock ve containerd.sock hostPath bağlamalarını kaldırın."
                ),
                cwe="CWE-250",
                control_id="SNIPER-K8S-ESCAPE-03",
                filename=clean_filename,
                line=line_no,
            ),
            desc,
        )

    return {
        "findings": findings,
        "count": len(findings),
        "filename": clean_filename,
    }

