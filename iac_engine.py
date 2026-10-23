"""Yerleşik IaC denetim motoru: Terraform/HCL, Kubernetes (Helm şablonları kısmen), Dockerfile, docker-compose.

Trivy/Checkov gerektirmez; ağ yok, hiçbir dosya çalıştırılmaz. Kural meta verisi (başlık, önem, CWE, Checkov
eşdeğeri, öneri) ``rules/iac/*.json`` içinde; basit Terraform denetimleri orada bildirimsel ``match`` olarak,
karmaşık olanlar (güvenlik grubu, IAM/kaynak politikası, sabit sır, Kubernetes iş yükü) bu modülde.

İlke: yalnız *açıkça yazılmış* güvensiz değerler raporlanır; değişken/başvuru/şablon gibi bilinmeyen değerlerde
denetim susar (yanlış alarm yerine kaçırma). Tek istisna Kubernetes sertleştirme eksikleri (düşük önem, iş yükü
başına tek bulgu; Helm şablonu ve yama dosyalarında üretilmez).
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import iac_hcl
import iac_yaml
from iac_hcl import Block, Call, Unknown

RULES_DIR = Path(__file__).resolve().parent / "rules" / "iac"
FRAMEWORKS = ("dockerfile", "kubernetes", "compose", "terraform", "ci")


def _load_rules() -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for fw in FRAMEWORKS:
        data = json.loads((RULES_DIR / f"{'docker' if fw == 'dockerfile' else fw}.json").read_text(encoding="utf-8"))
        for check in data["checks"]:
            if check["id"] in rules:
                raise ValueError(f"yinelenen IaC kural kimliği: {check['id']}")
            check["framework"] = fw
            rules[check["id"]] = check
    return rules


RULES = _load_rules()


@dataclass
class IacResult:
    framework: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    resources: int = 0
    note: str = ""
    analysis_complete: bool = True


class ProjectResults(dict[str, IacResult]):
    """Proje düzeyi IaC sonuçları ve sessiz olmayan kapsam sinyali."""

    def __init__(self, *args, analysis_complete: bool = True, limitations=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.analysis_complete = bool(analysis_complete)
        self.limitations = tuple(dict.fromkeys(str(value) for value in limitations if value))

    def mark_incomplete(self, *limitations: str) -> "ProjectResults":
        self.analysis_complete = False
        self.limitations = tuple(dict.fromkeys((*self.limitations, *(x for x in limitations if x))))
        for result in self.values():
            result.analysis_complete = False
            note = ", ".join(self.limitations)
            result.note = f"{result.note}; project-budget: {note}".strip("; ")
        return self


class _Collector:
    def __init__(self, framework: str):
        self.result = IacResult(framework)
        self._seen: set[tuple[str, int, str]] = set()

    def add(self, rule_id: str, line: int, resource: str = "", severity: str | None = None, **fmt: str) -> None:
        rule = RULES[rule_id]
        resource = resource.replace(iac_yaml.HELM_PLACEHOLDER, "?")
        key = (rule_id, int(line or 1), resource)
        if key in self._seen:
            return
        self._seen.add(key)
        evidence = rule["evidence"].format(**fmt) if fmt else rule["evidence"]
        self.result.findings.append({
            "id": rule_id, "title": rule["title"], "severity": severity or rule["severity"], "category": rule["category"],
            "reference": rule["reference"], "evidence": evidence, "recommendation": rule["recommendation"],
            "line": int(line or 1), "checkov": list(rule.get("checkov") or ()), "resource": resource,
            "framework": rule["framework"],
        })


# --------------------------------------------------------------------------------------------- ortak yardımcılar
_SECRET_NAME = re.compile(
    r"(?i)^(?:.*[_.-])?(?:pass(?:word|wd)?|secret|secret[_-]?key|client[_-]?secret|access[_-]?key(?:[_-]?id)?|"
    r"api[_-]?key|apikey|auth[_-]?token|access[_-]?token|token|private[_-]?key|sas[_-]?token|connection[_-]?string)$"
)
_SECRET_NAME_EXCLUDE = re.compile(r"(?i)(?:_file|_path|_name|_ref|_arn|_id_ref|_length|_ttl|_url|_header|_policy)$")
# project_analyzer'daki genel "Kaynak kodda sabit sır olasılığı" satır kuralı; aynı satırı iki kez raporlamamak için.
_GENERIC_SECRET_LINE = re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']")
_NOT_SECRET_WORDS = {"true", "false", "none", "null", "yes", "no", "enabled", "disabled", "required", "optional"}
_PLACEHOLDER_VALUE = re.compile(r"^(?:\$\{?|\$\(|\{\{|<|%|\*+$|x+$|\.\.\.)", re.I)


_AWS_KEY_ID = re.compile(r"^(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}$")


def _aws_key_value(value: Any) -> bool:
    return isinstance(value, str) and bool(_AWS_KEY_ID.match(value.strip()))


def _secret_name(name: str) -> bool:
    return bool(_SECRET_NAME.match(name)) and not _SECRET_NAME_EXCLUDE.search(name)


_IDENT_LIKE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")


def _literal_secret(value: Any, name: str = "") -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return False
    value = value.strip().strip("'\"")
    if value.casefold() in _NOT_SECRET_WORDS:
        return False
    if _IDENT_LIKE.match(value) or (name and name.casefold() in value.casefold()):
        return False  # GOOGLE_API_KEY_VAL gibi dağıtımda değiştirilen yer tutucu adlar
    return len(value) >= 4 and not _PLACEHOLDER_VALUE.match(value) and "${" not in value \
        and iac_yaml.HELM_PLACEHOLDER not in value


def _line_text(lines: list[str], line: int) -> str:
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _as_list(value: Any) -> list[Any]:
    if value is None or isinstance(value, (Unknown, Call)):
        return []
    return list(value) if isinstance(value, list) else [value]


# --------------------------------------------------------------------------------------------- Dockerfile
_PIPE_SH = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b")
_SUDO = re.compile(r"(?:^|[;&|(]\s*|\s)sudo\s")
_CHMOD_777 = re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*(?:0?777|[augo]*\+rwx)\b")
_TLS_OFF = re.compile(
    r"(?i)(?:\bcurl\b[^;&|]*\s(?:-k|--insecure)\b|\bwget\b[^;&|]*--no-check-certificate|\bpip3?\b[^;&|]*--trusted-host|"
    r"\b(?:npm|yarn|pnpm)\b[^;&|]*strict[-_]ssl[\s=]+false|--allow-unauthenticated|AllowUnauthenticated\s*\"?true|"
    r"\bapk\b[^;&|]*--allow-untrusted|gpgcheck\s*=\s*0|--nogpgcheck|\brpm\b[^;&|]*--nosignature|"
    r"http\.sslverify\s*=?\s*false|\bgit\b[^;&|]*sslVerify=false)"
)
_TLS_OFF_ENV = re.compile(r"(?i)^(NODE_TLS_REJECT_UNAUTHORIZED\s*[= ]\s*[\"']?0|PYTHONHTTPSVERIFY\s*[= ]\s*[\"']?0|"
                          r"GIT_SSL_NO_VERIFY\s*[= ]\s*[\"']?(?:1|true))")


def _docker_instructions(text: str) -> list[tuple[int, str, str]]:
    """(başlangıç satırı, yönerge, argümanlar) — satır devamları (\\) birleştirilir, yorumlar atlanır."""
    out: list[tuple[int, str, str]] = []
    buf: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue  # devam satırları arasındaki yorumlar yok sayılır (Docker davranışı)
        if not buf:
            start = number
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        logical = " ".join(part.strip() for part in buf).strip()
        buf = []
        match = re.match(r"([A-Za-z]+)\s*(.*)$", logical, re.S)
        if match:
            out.append((start, match.group(1).upper(), match.group(2)))
    if buf:
        logical = " ".join(buf).strip()
        match = re.match(r"([A-Za-z]+)\s*(.*)$", logical, re.S)
        if match:
            out.append((start, match.group(1).upper(), match.group(2)))
    return out


def _env_pairs(args: str, instruction: str) -> list[tuple[str, str]]:
    args = args.strip()
    if instruction == "ENV" and "=" not in args.split(None, 1)[0]:
        parts = args.split(None, 1)  # eski biçim: ENV AD değer
        return [(parts[0], parts[1] if len(parts) > 1 else "")]
    pairs = []
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_.-]*)(?:=(\"(?:\\.|[^\"])*\"|'[^']*'|\S*))?", args):
        pairs.append((match.group(1), (match.group(2) or "").strip("\"'")))
    return pairs


def analyze_dockerfile(text: str) -> IacResult:
    col = _Collector("dockerfile")
    lines = text.splitlines()
    stage_aliases: set[str] = set()
    has_from = False
    users: list[tuple[int, str]] = []
    healthcheck = False
    for line, instruction, args in _docker_instructions(text):
        if instruction == "FROM":
            match = re.match(r"(?:--\S+\s+)*([^\s#]+)(?:\s+AS\s+([^\s#]+))?", args, re.I)
            if not match:
                continue
            image = match.group(1)
            if match.group(2):
                stage_aliases.add(match.group(2).casefold())
            low = image.casefold()
            if low != "scratch" and low not in stage_aliases:
                has_from = True
                if low.endswith(":latest") or (":" not in image and "@" not in image and not image.startswith("$")):
                    col.add("SNP-IAC-DF-001", line)
        elif instruction == "USER":
            if args.split():
                users.append((line, args.split()[0]))
        elif instruction == "RUN":
            if _PIPE_SH.search(args):
                col.add("SNP-IAC-DF-002", line)
            if _SUDO.search(" " + args):
                col.add("SNP-IAC-DF-006", line)
            if _CHMOD_777.search(args):
                col.add("SNP-IAC-DF-008", line)
            if _TLS_OFF.search(args):
                col.add("SNP-IAC-DF-009", line)
        elif instruction == "ADD":
            if re.search(r"(?i)\bhttps?://", args) and "--checksum" not in args:
                col.add("SNP-IAC-DF-005", line)
        elif instruction in ("ENV", "ARG"):
            for name, value in _env_pairs(args, instruction):
                if _TLS_OFF_ENV.match(f"{name}={value}"):
                    col.add("SNP-IAC-DF-009", line)
                elif ((_secret_name(name) and _literal_secret(value, name)) or _aws_key_value(value)) \
                        and not _GENERIC_SECRET_LINE.search(_line_text(lines, line)):
                    col.add("SNP-IAC-DF-007", line)
        elif instruction == "EXPOSE":
            if any(port.split("/")[0] == "22" for port in args.split()):
                col.add("SNP-IAC-DF-010", line)
        elif instruction == "HEALTHCHECK":
            healthcheck = not args.strip().upper().startswith("NONE")
    if has_from:
        if not users:
            col.add("SNP-IAC-DF-003", 1)
        else:
            last_line, last_user = users[-1]
            if last_user.split(":", 1)[0].strip().casefold() in {"root", "0"}:
                col.add("SNP-IAC-DF-004", last_line)
        if not healthcheck:
            col.add("SNP-IAC-DF-011", 1)
    return col.result


# --------------------------------------------------------------------------------------------- Kubernetes
WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job",
                  "CronJob", "DeploymentConfig"}
_DANGEROUS_CAPS = {"SYS_ADMIN", "ALL", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF"}
_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "dockershim.sock")
_SENSITIVE_HOST_PATHS = ("/", "/etc", "/proc", "/root", "/var/run", "/run", "/var/lib/kubelet", "/var/lib/docker",
                         "/boot", "/dev", "/sys", "/home")


def _d(value: Any) -> iac_yaml.LDict:
    return value if isinstance(value, iac_yaml.LDict) else iac_yaml.LDict()


def _pod_spec(doc: iac_yaml.LDict) -> tuple[iac_yaml.LDict, iac_yaml.LDict] | None:
    """(pod spec, pod şablonu metadata)"""
    kind = doc.get("kind")
    spec = _d(doc.get("spec"))
    if kind == "Pod":
        return spec, _d(doc.get("metadata"))
    if kind == "CronJob":
        template = _d(_d(_d(spec.get("jobTemplate")).get("spec")).get("template"))
    else:
        template = _d(spec.get("template"))
    if not template:
        return None
    return _d(template.get("spec")), _d(template.get("metadata"))


def _containers(spec: iac_yaml.LDict) -> list[iac_yaml.LDict]:
    out = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for item in spec.get(key) or []:
            if isinstance(item, iac_yaml.LDict):
                out.append(item)
    return out


def _image_unpinned(image: Any) -> bool:
    if not isinstance(image, str) or not image.strip() or iac_yaml.is_placeholder(image) or "$" in image:
        return False
    if "@" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


def _is_unconfined(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() in {"unconfined", "runtime/unconfined"}


def _workload(col: _Collector, doc: iac_yaml.LDict, templated: bool, resource: str) -> None:
    pod = _pod_spec(doc)
    if pod is None:
        return
    spec, meta = pod
    if not spec:
        return
    for key, rule in (("hostNetwork", "SNP-IAC-K8S-003"), ("hostPID", "SNP-IAC-K8S-005"), ("hostIPC", "SNP-IAC-K8S-006")):
        if spec.get(key) is True:
            col.add(rule, spec.line_of(key), resource)
    pod_sc = _d(spec.get("securityContext"))
    for volume in spec.get("volumes") or []:
        host = _d(_d(volume).get("hostPath"))
        path = host.get("path")
        if not isinstance(path, str):
            continue
        if any(sock in path for sock in _SOCKETS):
            col.add("SNP-IAC-K8S-004", host.line_of("path"), resource)
        elif path.rstrip("/") in _SENSITIVE_HOST_PATHS or path == "/" or \
                any(path.startswith(prefix + "/") for prefix in ("/etc", "/root", "/proc", "/var/lib/kubelet", "/boot")):
            col.add("SNP-IAC-K8S-007", host.line_of("path"), resource)
    annotations = _d(meta.get("annotations"))
    for key, value in annotations.items():
        if ("seccomp" in key or "apparmor" in key) and _is_unconfined(value):
            col.add("SNP-IAC-K8S-010", annotations.line_of(key), resource)
    if _d(pod_sc.get("seccompProfile")).get("type") == "Unconfined" or _d(pod_sc.get("appArmorProfile")).get("type") == "Unconfined":
        col.add("SNP-IAC-K8S-010", pod_sc.line_of("seccompProfile"), resource)
    containers = _containers(spec)
    # Pod düzeyindeki runAsUser: 0, kendi runAsUser'ını tanımlamayan konteynerler için geçerlidir.
    if pod_sc.get("runAsUser") == 0 and any("runAsUser" not in _d(c.get("securityContext")) for c in containers):
        col.add("SNP-IAC-K8S-009", pod_sc.line_of("runAsUser"), resource)
    missing: list[str] = []
    imaged = [c for c in containers if isinstance(c.get("image"), str) and c.get("image").strip()
              and not iac_yaml.is_placeholder(c.get("image"))]
    for container in containers:
        sc = _d(container.get("securityContext"))
        if sc.get("privileged") is True:
            col.add("SNP-IAC-K8S-001", sc.line_of("privileged"), resource)
        if sc.get("allowPrivilegeEscalation") is True:
            col.add("SNP-IAC-K8S-002", sc.line_of("allowPrivilegeEscalation"), resource)
        caps = _d(sc.get("capabilities"))
        added = caps.get("add") or []
        if isinstance(added, list) and any(isinstance(c, str) and c.upper().removeprefix("CAP_") in _DANGEROUS_CAPS
                                           for c in added):
            col.add("SNP-IAC-K8S-008", caps.line_of("add"), resource)
        if sc.get("runAsUser") == 0:
            col.add("SNP-IAC-K8S-009", sc.line_of("runAsUser"), resource)
        if _d(sc.get("seccompProfile")).get("type") == "Unconfined" or _d(sc.get("appArmorProfile")).get("type") == "Unconfined":
            col.add("SNP-IAC-K8S-010", sc.line_of("seccompProfile"), resource)
        if _image_unpinned(container.get("image")):
            col.add("SNP-IAC-K8S-011", container.line_of("image"), resource)
        env = container.get("env") or []
        if isinstance(env, list):
            for index, item in enumerate(env):
                item = _d(item)
                name = item.get("name")
                if isinstance(name, str) and "value" in item and (
                        (_secret_name(name) and _literal_secret(item.get("value"), name)) or _aws_key_value(item.get("value"))):
                    col.add("SNP-IAC-K8S-012", item.line_of("value"), resource)
    # Sertleştirme eksikleri: yalnız tam (şablonsuz, imajlı) iş yüklerinde; yama/kustomize parçaları atlanır.
    if templated or not imaged or doc.get("kind") not in WORKLOAD_KINDS:
        return
    pod_nonroot = pod_sc.get("runAsNonRoot") is True or (isinstance(pod_sc.get("runAsUser"), int) and pod_sc.get("runAsUser") > 0)
    checks = {
        "runAsNonRoot": lambda sc, c: pod_nonroot or sc.get("runAsNonRoot") is True
        or (isinstance(sc.get("runAsUser"), int) and sc.get("runAsUser") > 0),
        "readOnlyRootFilesystem": lambda sc, c: sc.get("readOnlyRootFilesystem") is True,
        "capabilities.drop: [ALL]": lambda sc, c: any(isinstance(x, str) and x.upper() == "ALL"
                                                      for x in (_d(sc.get("capabilities")).get("drop") or [])),
        "resources.limits": lambda sc, c: bool(_d(_d(c.get("resources")).get("limits"))),
    }
    for label, ok in checks.items():
        if not all(ok(_d(c.get("securityContext")), c) for c in imaged):
            missing.append(label)
    if missing:
        col.add("SNP-IAC-K8S-013", imaged[0].line, resource, missing=", ".join(missing))


def _rbac(col: _Collector, doc: iac_yaml.LDict, resource: str) -> None:
    kind = doc.get("kind")
    if kind in ("Role", "ClusterRole"):
        rules = doc.get("rules") or []
        for index, rule in enumerate(rules if isinstance(rules, list) else []):
            rule = _d(rule)
            verbs = rule.get("verbs") or []
            res = rule.get("resources") or []
            groups = rule.get("apiGroups")
            # Yalnız çekirdek ("") ya da tüm API grupları (*) — ör. metrics.k8s.io ile sınırlı joker düşük risklidir.
            core = isinstance(groups, list) and any(g in ("", "*") for g in groups)
            if isinstance(verbs, list) and isinstance(res, list) and "*" in verbs and "*" in res and core:
                col.add("SNP-IAC-K8S-014", rules.line_of(index), resource)
    elif kind in ("ClusterRoleBinding", "RoleBinding"):
        ref = _d(doc.get("roleRef"))
        subjects = doc.get("subjects") or []
        if ref.get("name") == "cluster-admin" and isinstance(subjects, list) and \
                any(_d(s).get("kind") == "ServiceAccount" for s in subjects):
            col.add("SNP-IAC-K8S-015", ref.line_of("name"), resource)


def k8s_relationships(docs: list[iac_yaml.LDict], *, stats: dict[str, int] | None = None) \
        -> list[tuple[iac_yaml.LDict, int, str]]:
    """Ingress/Gateway API Route → Service → Workload → ServiceAccount → Role bağını denetler.

    Tek kaynak denetimleri geniş bir rolü ve dışa açık iş yükünü ayrı ayrı gösteriyordu. Bu geçiş,
    aynı manifest demetindeki ad alanı ve selector ilişkilerini kurar; eksik ya da belirsiz bir bağda susar.
    """
    matches: list[tuple[iac_yaml.LDict, int, str]] = []
    if stats is not None:
        stats.update({"selectors": 0, "selector_candidates": 0, "selector_comparisons": 0,
                      "gateway_parent_checks": 0, "gateway_backend_refs": 0,
                      "gateway_reference_grants": 0, "gateway_namespace_selector_evaluations": 0})

    def meta(doc: iac_yaml.LDict) -> tuple[str, str]:
        md = _d(doc.get("metadata"))
        name = md.get("name")
        namespace = md.get("namespace")
        return (name if isinstance(name, str) else "", namespace if isinstance(namespace, str) else "default")

    namespace_labels: dict[str, dict[str, str]] = {}
    duplicate_namespaces: set[str] = set()
    for doc in docs:
        if doc.get("kind") != "Namespace" or doc.get("apiVersion") != "v1":
            continue
        md = _d(doc.get("metadata"))
        name, labels_value = md.get("name"), md.get("labels")
        if labels_value is not None and not isinstance(labels_value, iac_yaml.LDict):
            continue
        raw_labels = _d(labels_value)
        if not isinstance(name, str) or not name or \
                any(not isinstance(key, str) or not key or not isinstance(value, str)
                    for key, value in raw_labels.items()):
            continue
        if name in namespace_labels:
            duplicate_namespaces.add(name)
            continue
        namespace_labels[name] = dict(raw_labels)
    for name in duplicate_namespaces:
        namespace_labels.pop(name, None)

    def selected_namespaces(raw_selector: object) -> frozenset[str] | None:
        """Statik Namespace belgelerinde metav1 LabelSelector uygula; bozuk şemada kapalı kal."""
        if not isinstance(raw_selector, iac_yaml.LDict):
            return None
        match_labels_value = raw_selector.get("matchLabels")
        expressions_value = raw_selector.get("matchExpressions")
        if (match_labels_value is not None and not isinstance(match_labels_value, iac_yaml.LDict)) or \
                (expressions_value is not None and not isinstance(expressions_value, list)):
            return None
        raw_match_labels = _d(match_labels_value)
        raw_expressions = expressions_value if isinstance(expressions_value, list) else []
        if any(not isinstance(key, str) or not key or not isinstance(value, str)
               for key, value in raw_match_labels.items()) or \
                any(not isinstance(expression, iac_yaml.LDict) for expression in raw_expressions):
            return None
        expressions: list[tuple[str, str, frozenset[str]]] = []
        for expression in raw_expressions:
            key, operator = expression.get("key"), expression.get("operator")
            values = expression.get("values", [])
            if not isinstance(key, str) or not key or operator not in ("In", "NotIn", "Exists", "DoesNotExist") or \
                    not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
                return None
            if (operator in ("In", "NotIn") and not values) or \
                    (operator in ("Exists", "DoesNotExist") and values):
                return None
            expressions.append((key, operator, frozenset(values)))
        selected: set[str] = set()
        for namespace, labels in namespace_labels.items():
            if stats is not None:
                stats["gateway_namespace_selector_evaluations"] += 1
            if any(labels.get(key) != value for key, value in raw_match_labels.items()):
                continue
            matches = True
            for key, operator, values in expressions:
                present = key in labels
                if operator == "In" and (not present or labels[key] not in values):
                    matches = False
                elif operator == "NotIn" and present and labels[key] in values:
                    matches = False
                elif operator == "Exists" and not present:
                    matches = False
                elif operator == "DoesNotExist" and present:
                    matches = False
                if not matches:
                    break
            if matches:
                selected.add(namespace)
        return frozenset(selected)

    broad_roles: set[tuple[str, str, str]] = set()
    for doc in docs:
        kind = doc.get("kind")
        if kind not in ("Role", "ClusterRole"):
            continue
        name, namespace = meta(doc)
        for rule in doc.get("rules") or []:
            rule = _d(rule)
            verbs, resources, groups = rule.get("verbs"), rule.get("resources"), rule.get("apiGroups")
            # PolicyRule.apiGroups is a list.  Missing/scalar values do not grant core API access and
            # therefore cannot prove the broad-role side of this cross-resource relationship.
            core = isinstance(groups, list) and any(group in ("", "*") for group in groups)
            if isinstance(verbs, list) and isinstance(resources, list) and "*" in verbs and "*" in resources and core:
                broad_roles.add((str(kind), name, "" if kind == "ClusterRole" else namespace))
                break

    privileged_accounts: set[tuple[str, str]] = set()
    for doc in docs:
        kind = doc.get("kind")
        if kind not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        _, namespace = meta(doc)
        ref = _d(doc.get("roleRef"))
        ref_kind, ref_name = ref.get("kind"), ref.get("name")
        # Geçersiz RBAC nesneleri ilişki kanıtı değildir. ClusterRoleBinding yalnız ClusterRole'a
        # bağlanabilir; RoleBinding ise Role/ClusterRole kabul eder. roleRef apiGroup zorunludur.
        if ref.get("apiGroup") != "rbac.authorization.k8s.io" or not isinstance(ref_name, str) or not ref_name:
            continue
        if kind == "ClusterRoleBinding" and ref_kind != "ClusterRole":
            continue
        if kind == "RoleBinding" and ref_kind not in ("Role", "ClusterRole"):
            continue
        ref_key = (str(ref_kind), str(ref_name), "" if ref_kind == "ClusterRole" else namespace)
        if ref_key not in broad_roles:
            continue
        for subject in doc.get("subjects") or []:
            subject = _d(subject)
            if subject.get("kind") == "ServiceAccount" and isinstance(subject.get("name"), str):
                raw_namespace = subject.get("namespace")
                if kind == "ClusterRoleBinding" and (not isinstance(raw_namespace, str) or not raw_namespace):
                    continue
                subject_ns = raw_namespace if isinstance(raw_namespace, str) and raw_namespace else namespace
                privileged_accounts.add((subject_ns, subject.get("name")))

    # Ingress/Gateway API yalnız adı değil Service portunu da hedefler. Var olmayan bir port API tarafından
    # reddedilir; böyle bir manifesti dışa açık workload kanıtı saymak kritik ilişki bulgusunda yanlış pozitiftir.
    exposed_services: dict[tuple[str, str], set[tuple[str, int | str]]] = {}
    for doc in docs:
        if doc.get("kind") != "Ingress":
            continue
        _, namespace = meta(doc)
        spec = _d(doc.get("spec"))
        backends: list[iac_yaml.LDict] = []
        default_backend = _d(spec.get("defaultBackend") or spec.get("backend"))
        if default_backend:
            backends.append(default_backend)
        for rule in spec.get("rules") or []:
            for path in _d(_d(rule).get("http")).get("paths") or []:
                path = _d(path)
                # networking.k8s.io/v1 için path ve pathType zorunludur. API sunucusunun reddedeceği bir yol
                # dışa açıklık kanıtı olamaz. Eski beta biçimlerinde pathType isteğe bağlıydı.
                if doc.get("apiVersion") == "networking.k8s.io/v1":
                    path_value, path_type = path.get("path"), path.get("pathType")
                    if not isinstance(path_value, str) or not path_value.startswith("/") or \
                            path_type not in ("Exact", "Prefix", "ImplementationSpecific"):
                        continue
                backends.append(_d(path.get("backend")))
        for backend in backends:
            service = _d(backend.get("service"))
            name = service.get("name") or backend.get("serviceName")
            port_ref: tuple[str, int | str] | None = None
            if service:
                port = _d(service.get("port"))
                number, port_name = port.get("number"), port.get("name")
                if isinstance(number, int) and not isinstance(number, bool) and 1 <= number <= 65535:
                    port_ref = ("number", number)
                elif isinstance(port_name, str) and port_name:
                    port_ref = ("name", port_name)
            else:  # extensions/v1beta1: serviceName + servicePort (IntOrString)
                legacy_port = backend.get("servicePort")
                if isinstance(legacy_port, int) and not isinstance(legacy_port, bool) and 1 <= legacy_port <= 65535:
                    port_ref = ("number", legacy_port)
                elif isinstance(legacy_port, str) and legacy_port:
                    port_ref = ("name", legacy_port)
            if isinstance(name, str) and name and port_ref is not None:
                exposed_services.setdefault((namespace, name), set()).add(port_ref)

    def privately_scoped_load_balancer(value: Any) -> bool:
        if not isinstance(value, list) or not value:
            return False
        for raw_range in value:
            if not isinstance(raw_range, str) or not raw_range:
                return False
            try:
                network = ipaddress.ip_network(raw_range, strict=False)
            except ValueError:
                return False
            if not (network.is_private or network.is_loopback or network.is_link_local):
                return False
        return True

    def has_public_external_ip(value: Any) -> bool:
        if not isinstance(value, list) or not value:
            return False
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for raw_ip in value:
            if not isinstance(raw_ip, str) or not raw_ip:
                return False
            try:
                addresses.append(ipaddress.ip_address(raw_ip))
            except ValueError:
                return False
        return any(address.is_global for address in addresses)

    # NodePort and LoadBalancer Services expose their selected workload without
    # a separate Ingress/Gateway document.  Only an API-valid static port list
    # is evidence; malformed Services fail closed as a whole.
    for doc in docs:
        if doc.get("kind") != "Service" or doc.get("apiVersion") != "v1":
            continue
        name, namespace = meta(doc)
        spec = _d(doc.get("spec"))
        service_type = spec.get("type", "ClusterIP")
        if service_type not in ("ClusterIP", "NodePort", "LoadBalancer"):
            continue
        external_ip_exposed = has_public_external_ip(spec.get("externalIPs"))
        if not name or (service_type not in ("NodePort", "LoadBalancer") and not external_ip_exposed):
            continue
        if service_type == "LoadBalancer" and privately_scoped_load_balancer(
                spec.get("loadBalancerSourceRanges")):
            continue
        raw_ports = spec.get("ports")
        if not isinstance(raw_ports, list) or not raw_ports or any(
                not isinstance(raw_port, iac_yaml.LDict) for raw_port in raw_ports):
            continue
        service_ports: set[tuple[str, int | str]] = set()
        valid_ports = True
        for raw_port in raw_ports:
            port, port_name = raw_port.get("port"), raw_port.get("name")
            node_port, protocol = raw_port.get("nodePort"), raw_port.get("protocol", "TCP")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 or \
                    (port_name is not None and (not isinstance(port_name, str) or not port_name)) or \
                    (node_port is not None and (not isinstance(node_port, int) or isinstance(node_port, bool)
                                                or not 1 <= node_port <= 65535)) or \
                    protocol not in ("TCP", "UDP", "SCTP"):
                valid_ports = False
                break
            service_ports.add(("number", port))
            if isinstance(port_name, str):
                service_ports.add(("name", port_name))
        if valid_ports:
            exposed_services.setdefault((namespace, name), set()).update(service_ports)

    # ReferenceGrant hedef namespace içinde yaşar. Kaynak Route türü/namespace'i ile hedef Service adını
    # önceden indekslemek her backend için bütün grant belgelerini yeniden taramayı önler. ``to.name``
    # belirtilmemişse grant o namespace'teki bütün Service'lere izin verir.
    reference_grants: dict[tuple[str, str, str], set[str | None]] = {}
    for doc in docs:
        if doc.get("kind") != "ReferenceGrant" or \
                doc.get("apiVersion") != "gateway.networking.k8s.io/v1beta1":
            continue
        grant_name, target_namespace = meta(doc)
        spec = _d(doc.get("spec"))
        from_entries, to_entries = spec.get("from"), spec.get("to")
        if not grant_name or not isinstance(from_entries, list) or not from_entries or \
                not isinstance(to_entries, list) or not to_entries or \
                any(not isinstance(entry, iac_yaml.LDict) for entry in from_entries) or \
                any(not isinstance(entry, iac_yaml.LDict) for entry in to_entries):
            continue
        valid = True
        for entry in from_entries:
            if not isinstance(entry.get("group"), str) or not entry.get("group") or \
                    not isinstance(entry.get("kind"), str) or not entry.get("kind") or \
                    not isinstance(entry.get("namespace"), str) or not entry.get("namespace"):
                valid = False
                break
        for entry in to_entries:
            if not isinstance(entry.get("group"), str) or \
                    not isinstance(entry.get("kind"), str) or not entry.get("kind") or \
                    ("name" in entry and (not isinstance(entry.get("name"), str) or not entry.get("name"))):
                valid = False
                break
        if not valid:
            continue
        sources = {
            (entry.get("kind"), entry.get("namespace")) for entry in from_entries
            if entry.get("group") == "gateway.networking.k8s.io" and
            entry.get("kind") in ("HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute", "UDPRoute")
        }
        targets = {
            entry.get("name") for entry in to_entries
            if entry.get("group") == "" and entry.get("kind") == "Service"
        }
        for route_kind, source_namespace in sources:
            reference_grants.setdefault((str(route_kind), source_namespace, target_namespace), set()).update(targets)
            if stats is not None:
                stats["gateway_reference_grants"] += len(targets)

    # Gateway API: statik olarak doğrulanmış Gateway ebeveynine bağlanan HTTP/gRPC/TCP/TLS/UDP Route backend'leri. Dinleyicinin
    # namespace ilkesi Same ise aynı ad alanı, All ise açık cross-namespace bağ kabul edilir. Selector tabanlı
    # namespace kabulü fail-closed kalır; başka namespace'teki Service yalnız tam ReferenceGrant ile bağlanır.
    gateways: dict[tuple[str, str], dict[str, tuple[int, str, frozenset[str], frozenset[str]]]] = {}
    for doc in docs:
        if doc.get("kind") != "Gateway" or doc.get("apiVersion") not in (
                "gateway.networking.k8s.io/v1", "gateway.networking.k8s.io/v1beta1"):
            continue
        name, namespace = meta(doc)
        spec = _d(doc.get("spec"))
        if not name or not isinstance(spec.get("gatewayClassName"), str) or not spec.get("gatewayClassName"):
            continue
        raw_listeners = spec.get("listeners")
        if not isinstance(raw_listeners, list):
            continue
        listeners: dict[str, tuple[int, str, frozenset[str], frozenset[str]]] = {}
        valid_gateway = True
        for raw_listener in raw_listeners:
            if not isinstance(raw_listener, iac_yaml.LDict):
                valid_gateway = False
                break
            listener = raw_listener
            protocol = listener.get("protocol")
            if not isinstance(protocol, str) or protocol not in ("HTTP", "HTTPS", "TLS", "TCP", "UDP"):
                valid_gateway = False
                break
            listener_name, listener_port = listener.get("name"), listener.get("port")
            if not isinstance(listener_name, str) or not listener_name or \
                    not isinstance(listener_port, int) or isinstance(listener_port, bool) or \
                    not 1 <= listener_port <= 65535:
                valid_gateway = False
                break
            raw_tls = listener.get("tls")
            if protocol in ("HTTP", "TCP", "UDP") and raw_tls is not None:
                valid_gateway = False
                break
            if protocol == "HTTPS":
                if not isinstance(raw_tls, iac_yaml.LDict) or raw_tls.get("mode", "Terminate") != "Terminate":
                    valid_gateway = False
                    break
                certificate_refs = raw_tls.get("certificateRefs")
                if not isinstance(certificate_refs, list) or not certificate_refs or any(
                        not isinstance(ref, iac_yaml.LDict) or ref.get("group", "") != "" or
                        ref.get("kind", "Secret") != "Secret" or not isinstance(ref.get("name"), str) or
                        ref.get("namespace", namespace) != namespace
                        for ref in certificate_refs
                ):
                    valid_gateway = False
                    break
            if protocol == "TLS":
                if not isinstance(raw_tls, iac_yaml.LDict) or raw_tls.get("mode") != "Passthrough" or \
                        raw_tls.get("certificateRefs") is not None:
                    valid_gateway = False
                    break
            raw_allowed = listener.get("allowedRoutes")
            if raw_allowed is not None and not isinstance(raw_allowed, iac_yaml.LDict):
                valid_gateway = False
                break
            allowed = _d(raw_allowed)
            raw_namespaces = allowed.get("namespaces")
            if raw_namespaces is not None and not isinstance(raw_namespaces, iac_yaml.LDict):
                valid_gateway = False
                break
            namespaces = _d(raw_namespaces)
            namespace_from = namespaces.get("from", "Same")
            if namespace_from not in ("Same", "All", "Selector"):
                valid_gateway = False
                break
            selected = frozenset()
            if namespace_from == "Selector":
                selected_result = selected_namespaces(namespaces.get("selector"))
                if selected_result is None:
                    valid_gateway = False
                    break
                selected = selected_result
            kinds = allowed.get("kinds")
            if kinds is not None and not isinstance(kinds, list):
                valid_gateway = False
                break
            if isinstance(kinds, list) and not kinds:
                valid_gateway = False
                break
            if isinstance(kinds, list) and any(
                    not isinstance(kind, iac_yaml.LDict) or not isinstance(kind.get("kind"), str) or
                    ("group" in kind and not isinstance(kind.get("group"), str))
                    for kind in kinds
            ):
                valid_gateway = False
                break
            compatible_route_kinds = {
                "HTTP": frozenset({"HTTPRoute", "GRPCRoute"}),
                "HTTPS": frozenset({"HTTPRoute", "GRPCRoute"}),
                "TCP": frozenset({"TCPRoute"}),
                "TLS": frozenset({"TLSRoute"}),
                "UDP": frozenset({"UDPRoute"}),
            }[protocol]
            allowed_route_kinds = compatible_route_kinds if kinds is None else frozenset(
                _d(kind).get("kind") for kind in kinds
                if _d(kind).get("kind") in compatible_route_kinds and
                _d(kind).get("group", "gateway.networking.k8s.io") == "gateway.networking.k8s.io"
            )
            if not allowed_route_kinds:
                continue
            if listener_name in listeners:
                valid_gateway = False
                break
            listeners[listener_name] = (listener_port, namespace_from, selected, allowed_route_kinds)
        if valid_gateway and listeners:
            gateways[(namespace, name)] = listeners

    for doc in docs:
        route_kind = doc.get("kind")
        if route_kind not in ("HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute", "UDPRoute") or \
                doc.get("apiVersion") not in (
                "gateway.networking.k8s.io/v1", "gateway.networking.k8s.io/v1beta1",
                "gateway.networking.k8s.io/v1alpha2"):
            continue
        _, route_namespace = meta(doc)
        spec = _d(doc.get("spec"))
        parent_refs = spec.get("parentRefs")
        route_rules = spec.get("rules")
        if not isinstance(parent_refs, list) or not parent_refs or \
                not isinstance(route_rules, list) or not route_rules or \
                any(not isinstance(parent, iac_yaml.LDict) for parent in parent_refs) or \
                any(not isinstance(rule, iac_yaml.LDict) for rule in route_rules):
            continue
        attached = False
        for raw_parent in parent_refs:
            if stats is not None:
                stats["gateway_parent_checks"] += 1
            parent = raw_parent
            if not isinstance(parent.get("name"), str) or \
                    not isinstance(parent.get("group", "gateway.networking.k8s.io"), str) or \
                    not isinstance(parent.get("kind", "Gateway"), str) or \
                    ("namespace" in parent and not isinstance(parent.get("namespace"), str)) or \
                    ("sectionName" in parent and not isinstance(parent.get("sectionName"), str)) or \
                    ("port" in parent and (not isinstance(parent.get("port"), int) or
                                             isinstance(parent.get("port"), bool))):
                attached = False
                break
            if parent.get("group", "gateway.networking.k8s.io") != "gateway.networking.k8s.io" or \
                    parent.get("kind", "Gateway") != "Gateway":
                continue
            parent_name = parent.get("name")
            parent_namespace = parent.get("namespace", route_namespace)
            if not isinstance(parent_name, str) or not isinstance(parent_namespace, str):
                continue
            section, port = parent.get("sectionName"), parent.get("port")
            listener_index = gateways.get((parent_namespace, parent_name))
            if listener_index is None:
                continue

            def listener_allows(entry: tuple[int, str, frozenset[str], frozenset[str]]) -> bool:
                if route_kind not in entry[3]:
                    return False
                if entry[1] == "All":
                    return True
                if entry[1] == "Same":
                    return parent_namespace == route_namespace
                return route_namespace in entry[2]

            if section is not None:
                entry = listener_index.get(section) if isinstance(section, str) else None
                attached = entry is not None and listener_allows(entry) and (port is None or port == entry[0])
            elif port is not None:
                attached = isinstance(port, int) and not isinstance(port, bool) and any(
                    entry[0] == port and listener_allows(entry) for entry in listener_index.values()
                )
            else:
                attached = any(listener_allows(entry) for entry in listener_index.values())
            if attached:
                break
        if not attached:
            continue
        for raw_rule in route_rules:
            rule = raw_rule
            route_matches = rule.get("matches")
            if route_kind in ("TCPRoute", "TLSRoute", "UDPRoute") and route_matches is not None:
                continue
            if route_matches is not None and not isinstance(route_matches, list):
                continue
            if isinstance(route_matches, list):
                if not route_matches or any(not isinstance(match, iac_yaml.LDict) for match in route_matches):
                    continue
                valid_match = False
                for raw_match in route_matches:
                    if route_kind == "GRPCRoute":
                        raw_method = raw_match.get("method")
                        raw_headers = raw_match.get("headers")
                        if raw_method is not None and not isinstance(raw_method, iac_yaml.LDict):
                            continue
                        if raw_headers is not None and not isinstance(raw_headers, list):
                            continue
                        method = _d(raw_method)
                        if method and (
                                method.get("type", "Exact") not in ("Exact", "RegularExpression") or
                                any(key in method and (not isinstance(method.get(key), str) or not method.get(key))
                                    for key in ("service", "method"))):
                            continue
                        if isinstance(raw_headers, list) and (
                                not raw_headers or any(
                                    not isinstance(header, iac_yaml.LDict) or
                                    _d(header).get("type", "Exact") not in ("Exact", "RegularExpression") or
                                    not isinstance(_d(header).get("name"), str) or not _d(header).get("name") or
                                    not isinstance(_d(header).get("value"), str) or not _d(header).get("value")
                                    for header in raw_headers
                                )):
                            continue
                        valid_match = True
                        break
                    raw_path = raw_match.get("path")
                    if raw_path is not None and not isinstance(raw_path, iac_yaml.LDict):
                        continue
                    path = _d(raw_path)
                    if not path:  # path koşulu olmayan bir match tüm yollarla eşleşebilir
                        valid_match = True
                        break
                    path_type, value = path.get("type", "PathPrefix"), path.get("value", "/")
                    if path_type == "RegularExpression" and isinstance(value, str) and value:
                        valid_match = True
                        break
                    if path_type in ("Exact", "PathPrefix") and isinstance(value, str) and value.startswith("/"):
                        valid_match = True
                        break
                if not valid_match:
                    continue
            backend_refs = rule.get("backendRefs")
            if not isinstance(backend_refs, list) or \
                    any(not isinstance(backend, iac_yaml.LDict) for backend in backend_refs):
                continue
            for raw_backend in backend_refs:
                if stats is not None:
                    stats["gateway_backend_refs"] += 1
                backend = raw_backend
                if backend.get("group", "") != "" or backend.get("kind", "Service") != "Service":
                    continue
                name, port, weight = backend.get("name"), backend.get("port"), backend.get("weight", 1)
                target_namespace = backend.get("namespace", route_namespace)
                if not isinstance(name, str) or not name or not isinstance(port, int) or isinstance(port, bool) or \
                        not 1 <= port <= 65535 or not isinstance(weight, int) or isinstance(weight, bool) or weight <= 0 or \
                        not isinstance(target_namespace, str) or not target_namespace:
                    continue
                if target_namespace != route_namespace:
                    grants = reference_grants.get((str(route_kind), route_namespace, target_namespace), set())
                    if name not in grants and None not in grants:
                        continue
                exposed_services.setdefault((target_namespace, name), set()).add(("number", port))

    # Selector imzalarını tekilleştirip en seyrek bir etiket çiftiyle indeksle. Önceki uygulama her workload için
    # bütün Service selector'larını tarıyor ve benzersiz selector'larda O(Service*Workload) büyüyordu.
    selectors_by_namespace: dict[str, set[tuple[tuple[str, str], ...]]] = {}
    for doc in docs:
        if doc.get("kind") != "Service":
            continue
        name, namespace = meta(doc)
        service_spec = _d(doc.get("spec"))
        # ExternalName trafiği bir küme dışı DNS adına gider; manifestte geçersiz/artan bir selector bulunsa bile
        # bu Service bir yerel workload seçmez ve Ingress → workload kanıtı kuramaz.
        if service_spec.get("type") == "ExternalName":
            continue
        selector = _d(service_spec.get("selector"))
        ingress_ports = exposed_services.get((namespace, name), set())
        service_ports = service_spec.get("ports")
        port_matches = False
        for raw_port in service_ports if isinstance(service_ports, list) else []:
            port = _d(raw_port)
            number, port_name = port.get("port"), port.get("name")
            if isinstance(number, int) and not isinstance(number, bool) and ("number", number) in ingress_ports:
                port_matches = True
                break
            if isinstance(port_name, str) and ("name", port_name) in ingress_ports:
                port_matches = True
                break
        if port_matches and selector:
            signature = tuple(sorted((key, value) for key, value in selector.items()
                                     if isinstance(key, str) and isinstance(value, str)))
            if signature and len(signature) == len(selector):
                selectors_by_namespace.setdefault(namespace, set()).add(signature)

    pair_counts: dict[tuple[str, str, str], int] = {}
    for namespace, signatures in selectors_by_namespace.items():
        for signature in signatures:
            for key, value in signature:
                pair = (namespace, key, value)
                pair_counts[pair] = pair_counts.get(pair, 0) + 1
    selector_index: dict[tuple[str, str, str], set[tuple[tuple[str, str], ...]]] = {}
    for namespace, signatures in selectors_by_namespace.items():
        for signature in signatures:
            anchor = min(((namespace, key, value) for key, value in signature),
                         key=lambda pair: (pair_counts[pair], pair[1], pair[2]))
            selector_index.setdefault(anchor, set()).add(signature)
    if stats is not None:
        stats["selectors"] = sum(len(items) for items in selectors_by_namespace.values())

    for doc in docs:
        if doc.get("kind") not in WORKLOAD_KINDS:
            continue
        name, namespace = meta(doc)
        pod = _pod_spec(doc)
        if pod is None:
            continue
        spec, template_meta = pod
        labels = _d(template_meta.get("labels"))
        candidates: set[tuple[tuple[str, str], ...]] = set()
        for key, value in labels.items():
            if isinstance(key, str) and isinstance(value, str):
                candidates.update(selector_index.get((namespace, key, value), ()))
        if stats is not None:
            stats["selector_candidates"] += len(candidates)
        exposed = False
        for signature in candidates:
            if stats is not None:
                stats["selector_comparisons"] += 1
            if all(labels.get(key) == value for key, value in signature):
                exposed = True
                break
        if not exposed:
            continue
        account = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
        if isinstance(account, str) and (namespace, account) in privileged_accounts:
            line = spec.line_of("serviceAccountName") or spec.line_of("serviceAccount") or doc.line
            matches.append((doc, line, f"{doc.get('kind')}/{name or '?'}"))
    return matches


def _k8s_docs(docs: Iterable[Any]) -> Iterable[iac_yaml.LDict]:
    for doc in docs:
        if isinstance(doc, iac_yaml.LDict):
            kind = doc.get("kind")
            if isinstance(kind, str) and kind.endswith("List") and isinstance(doc.get("items"), list):
                yield from (item for item in doc.get("items") or [] if isinstance(item, iac_yaml.LDict))
            else:
                yield doc


def analyze_kubernetes(docs: list[Any], templated: bool) -> IacResult:
    col = _Collector("kubernetes")
    normalized = list(_k8s_docs(docs))
    for doc in normalized:
        if not isinstance(doc.get("kind"), str):
            continue
        name = _d(doc.get("metadata")).get("name")
        resource = f"{doc.get('kind')}/{name if isinstance(name, str) else '?'}"
        col.result.resources += 1
        _workload(col, doc, templated, resource)
        _rbac(col, doc, resource)
    for _doc, line, resource in k8s_relationships(normalized):
        col.add("SNP-IAC-K8S-016", line, resource)
    return col.result


# --------------------------------------------------------------------------------------------- docker-compose
def _env_items(env: Any) -> Iterable[tuple[str, Any, int]]:
    if isinstance(env, iac_yaml.LDict):
        for key, value in env.items():
            yield key, value, env.line_of(key)
    elif isinstance(env, iac_yaml.LList):
        for index, item in enumerate(env):
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                yield key.strip(), value, env.line_of(index)


# Geliştirici ortamı compose dosyaları (devcontainer, *.dev.yml, test/örnek): sabit parola çoğunlukla yerel
# veritabanı içindir; bulgu düşük önemle raporlanır.
_DEV_COMPOSE = re.compile(r"(?i)(?:^|/)\.devcontainer/|(?:^|[/._-])(?:dev|devel|development|local|test|tests|testing|"
                          r"example|examples|sample|demo|ci)(?:[/._-]|$)")


def analyze_compose(doc: iac_yaml.LDict, rel_path: str = "") -> IacResult:
    col = _Collector("compose")
    secret_severity = "low" if _DEV_COMPOSE.search(rel_path) else None
    services = _d(doc.get("services"))
    for name, service in services.items():
        service = _d(service)
        resource = f"service/{name}"
        col.result.resources += 1
        if service.get("privileged") is True:
            col.add("SNP-IAC-DC-001", service.line_of("privileged"), resource)
        if service.get("network_mode") == "host":
            col.add("SNP-IAC-DC-002", service.line_of("network_mode"), resource)
        if service.get("pid") == "host":
            col.add("SNP-IAC-DC-004", service.line_of("pid"), resource)
        if service.get("ipc") == "host":
            col.add("SNP-IAC-DC-005", service.line_of("ipc"), resource)
        volumes = service.get("volumes") or []
        for index, volume in enumerate(volumes if isinstance(volumes, list) else []):
            source = volume if isinstance(volume, str) else _d(volume).get("source")
            if isinstance(source, str) and any(sock in source for sock in _SOCKETS):
                col.add("SNP-IAC-DC-003", volumes.line_of(index), resource)
        caps = service.get("cap_add") or []
        if isinstance(caps, list) and any(isinstance(c, str) and c.upper().removeprefix("CAP_") in _DANGEROUS_CAPS for c in caps):
            col.add("SNP-IAC-DC-006", service.line_of("cap_add"), resource)
        opts = service.get("security_opt") or []
        if isinstance(opts, list) and any(isinstance(o, str) and re.match(r"(?i)^(seccomp|apparmor)[:=]unconfined$", o.strip())
                                          for o in opts):
            col.add("SNP-IAC-DC-007", service.line_of("security_opt"), resource)
        for key, value, line in _env_items(service.get("environment")):
            if (_secret_name(key) and _literal_secret(value, key)) or _aws_key_value(value):
                col.add("SNP-IAC-DC-008", line, resource, severity=secret_severity)
        if "build" not in service and _image_unpinned(service.get("image")):
            col.add("SNP-IAC-DC-009", service.line_of("image"), resource)
        user = service.get("user")
        if isinstance(user, (str, int)) and str(user).split(":", 1)[0].strip() in {"root", "0"}:
            col.add("SNP-IAC-DC-010", service.line_of("user"), resource)
    return col.result


# --------------------------------------------------------------------------------------------- CI/CD
_GH_WORKFLOW = re.compile(r"(?i)^\.github/workflows/.+\.ya?ml$")
_GITLAB_WORKFLOW = re.compile(r"(?i)(?:^|/)\.gitlab-ci\.ya?ml$")
_GH_UNTRUSTED = re.compile(
    r"github\.(?:head_ref|event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label))|"
    r"discussion\.(?:title|body)|workflow_run\.(?:head_branch|display_title|head_commit\.message)))"
)
_GH_STEP_ID = re.compile(r"^\s*(?:-\s*)?id\s*:\s*['\"]?([A-Za-z_][\w-]*)")
_GH_OUTPUT_WRITE = re.compile(r"([A-Za-z_][\w-]*)\s*=\s*\$\{\{\s*([^}]+)\}\}")
_GH_OUTPUT_BLOCK = re.compile(r"\b([A-Za-z_][\w-]*)\s*<<\s*([A-Za-z_][\w-]*)\b")
_GH_OUTPUT_READ = re.compile(r"\$\{\{\s*steps\.([A-Za-z_][\w-]*)\.outputs\.([A-Za-z_][\w-]*)\b")
_GH_JOB_OUTPUT_READ = re.compile(
    r"\$\{\{\s*needs\.([A-Za-z_][\w-]*)\.outputs\.([A-Za-z_][\w-]*)\b"
)
_GH_OUTPUT_ASSIGN = re.compile(r"\b([A-Za-z_][\w-]*)\s*=\s*([^\r\n]+)")
_GH_ENV_READ = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_GH_OUTPUT_REDIRECT = re.compile(r">>?\s*[\"']?(\$(?:\{GITHUB_OUTPUT\}|GITHUB_OUTPUT))[\"']?")
_GH_ENV_REDIRECT = re.compile(r">>?\s*[\"']?(\$(?:\{GITHUB_ENV\}|GITHUB_ENV))[\"']?")
_CI_COMMAND = re.compile(r"^(\s*)(?:-\s*)?(run|script)\s*:\s*(.*)$")
_GL_UNTRUSTED = re.compile(r"\$CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|SOURCE_PROJECT_URL|LABELS)\b")
_GL_DOTENV_WRITE = re.compile(r"\b([A-Z_][A-Z0-9_]*)\s*=.*\$CI_MERGE_REQUEST_")
_GL_REDIRECT = re.compile(r">>?(?:\s*)[\"']?([^\s\"']+)")


def _ci_root(text: str) -> iac_yaml.LDict | None:
    try:
        docs = iac_yaml.load_all(text)
    except iac_yaml.YamlError:
        return None
    return docs[0] if docs and isinstance(docs[0], iac_yaml.LDict) else None


def _script_lines(owner: iac_yaml.LDict, key: str) -> list[tuple[int, str]]:
    """Bir ``run``/``script`` alanını gerçek kaynak satırlarıyla düzleştirir."""
    value = owner.get(key)
    if isinstance(value, str):
        base = owner.line_of(key)
        return [(base + offset, line) for offset, line in enumerate(value.splitlines() or [""])]
    if isinstance(value, iac_yaml.LList):
        out: list[tuple[int, str]] = []
        for index, item in enumerate(value):
            if isinstance(item, str):
                base = value.line_of(index)
                out.extend((base + offset, line) for offset, line in enumerate(item.splitlines() or [""]))
        return out
    return []


def _shell_expands_at(text: str, position: int) -> bool:
    """Kabuk metnindeki ``$`` konumu genişletilir mi? Tek tırnak ve kaçışları sınırlı biçimde izler."""
    single = double = escaped = False
    for index, char in enumerate(text[:position]):
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
        elif char == '"' and not single:
            double = not double
    return not single and not escaped


def _gitlab_expanded_untrusted(text: str) -> bool:
    return any(_shell_expands_at(text, match.start()) for match in _GL_UNTRUSTED.finditer(text))


def _gitlab_variable_used(text: str, variable: str) -> bool:
    pattern = re.compile(rf"\$(?:\{{{re.escape(variable)}\}}|{re.escape(variable)})\b")
    return any(_shell_expands_at(text, match.start()) for match in pattern.finditer(text))


def _github_env_taint(owner: iac_yaml.LDict, inherited: set[str] | None = None) -> set[str]:
    """Workflow/job/step ``env`` gölgelemesini izleyip doğrudan olay verisi taşıyan adları döndürür."""
    tainted = set(inherited or ())
    env = owner.get("env")
    if not isinstance(env, iac_yaml.LDict):
        return tainted
    for raw_name, value in env.items():
        name = str(raw_name)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        if isinstance(value, str) and _GH_UNTRUSTED.search(value):
            tainted.add(name)
        else:
            tainted.discard(name)  # daha dar kapsam güvenli değerle üstüne yazabilir
    return tainted


def _github_env_used(text: str, tainted_env: set[str], start: int = 0, end: int | None = None) -> bool:
    for match in _GH_ENV_READ.finditer(text, start, len(text) if end is None else end):
        if (match.group(1) or match.group(2)) in tainted_env and _shell_expands_at(text, match.start()):
            return True
    return False


def _github_writes_output(text: str) -> bool:
    return any(_shell_expands_at(text, match.start(1)) for match in _GH_OUTPUT_REDIRECT.finditer(text))


def _github_writes_env(text: str) -> bool:
    return any(_shell_expands_at(text, match.start(1)) for match in _GH_ENV_REDIRECT.finditer(text))


def _github_echo_assignments(text: str) -> Iterable[re.Match[str]]:
    """Yalnız stdout üreten ``echo name=value`` parçaları; çıplak kabuk ataması dosyaya değer yazmaz."""
    for match in _GH_OUTPUT_ASSIGN.finditer(text):
        prefix = text[:match.start()]
        if re.search(r"(?:^|[;&|({]\s*)echo\b[^;&|{}()]*$", prefix):
            yield match


def _shell_command_end(text: str, start: int) -> int:
    """Bir echo değerini sonraki tırnaksız yönlendirme/komut ayırıcısına kadar sınırlar."""
    single = double = escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
            continue
        if char == '"' and not single:
            double = not double
            continue
        if not single and not double and char in ";|&><":
            return index
    return len(text)


def _github_redirect_regions(lines: list[str], writer) -> set[int]:
    """Doğrudan ya da ``{ ... } >> $GITHUB_*`` grubuyla hedef dosyaya yazılan satırlar."""
    regions = {index for index, line in enumerate(lines) if writer(line)}
    for closing, line in enumerate(lines):
        stripped = line.lstrip()
        if not writer(line) or not stripped.startswith(("}", ")")):
            continue
        opener = "{" if stripped.startswith("}") else "("
        for start in range(closing - 1, -1, -1):
            if lines[start].strip() == opener:
                regions.update(range(start + 1, closing + 1))
                break
    return regions


def _github_output_regions(lines: list[str]) -> set[int]:
    return _github_redirect_regions(lines, _github_writes_output)


def _github_env_updates(run: str, tainted_env: set[str] | None = None) -> dict[str, bool]:
    """Bir adımın sonraki adımlara yazdığı ``GITHUB_ENV`` adlarını ve son taint durumlarını döndürür."""
    lines = run.splitlines()
    tainted_env = set(tainted_env or ())
    updates: dict[str, bool] = {}
    regions = _github_redirect_regions(lines, _github_writes_env)
    for index in sorted(regions):
        raw = lines[index]
        for match in _github_echo_assignments(raw):
            name = match.group(1)
            end = _shell_command_end(raw, match.start(2))
            payload = raw[match.start(2):end]
            updates[name] = bool(_GH_UNTRUSTED.search(payload) or
                                 _github_env_used(raw, tainted_env, match.start(2), end))
    for start, raw in enumerate(lines):
        header = _GH_OUTPUT_BLOCK.search(raw)
        if not header:
            continue
        name, delimiter = header.groups()
        terminator = re.compile(rf"\becho\s+(?:['\"]{re.escape(delimiter)}['\"]|{re.escape(delimiter)})(?:\s|$)")
        for end in range(start + 1, len(lines)):
            if not terminator.search(lines[end]):
                continue
            payload = "\n".join(lines[start + 1:end])
            direct = all(index in regions for index in range(start, end + 1) if lines[index].strip())
            closing = lines[end + 1] if end + 1 < len(lines) else ""
            grouped = bool(re.match(r"^\s*[})]", closing)) and end + 1 in regions
            if direct or grouped:
                updates[name] = bool(_GH_UNTRUSTED.search(payload) or
                                     _github_env_used(payload, tainted_env))
            break
    return updates


def _github_tainted_outputs(run: str, tainted_env: set[str] | None = None) -> set[str]:
    """Bir adımın tek satırlı ve ``name<<DELIMITER`` çok satırlı çıktılarını bulur."""
    lines = run.splitlines()
    tainted_env = set(tainted_env or ())
    tainted: set[str] = set()
    for index in _github_output_regions(lines):
        raw = lines[index]
        for match in _github_echo_assignments(raw):
            end = _shell_command_end(raw, match.start(2))
            if _GH_UNTRUSTED.search(raw[match.start(2):end]) or \
                    _github_env_used(raw, tainted_env, match.start(2), end):
                tainted.add(match.group(1))
    for start, raw in enumerate(lines):
        header = _GH_OUTPUT_BLOCK.search(raw)
        if not header:
            continue
        name, delimiter = header.groups()
        terminator = re.compile(rf"\becho\s+(?:['\"]{re.escape(delimiter)}['\"]|{re.escape(delimiter)})(?:\s|$)")
        for end in range(start + 1, len(lines)):
            if not terminator.search(lines[end]):
                continue
            payload = "\n".join(lines[start + 1:end])
            # Ya her echo ayrı ayrı çıktı dosyasına yöneltilir ya da hemen sonraki ``}``/``)`` bütün komut
            # grubunu yöneltir. Yakındaki ilgisiz bir GITHUB_OUTPUT yazısını bu bloğun kanıtı sayma.
            direct = all(_github_writes_output(value) for value in lines[start:end + 1] if value.strip())
            closing = lines[end + 1] if end + 1 < len(lines) else ""
            grouped = bool(re.match(r"^\s*[})]", closing)) and _github_writes_output(closing)
            if (direct or grouped) and (_GH_UNTRUSTED.search(payload) or
                                        _github_env_used(payload, tainted_env)):
                tainted.add(name)
            break
    return tainted


def _github_flow(col: _Collector, root: iac_yaml.LDict, resource: str) -> bool:
    """Ayrıştırılmış GitHub iş akışını job sınırlarını koruyarak denetler."""
    jobs = root.get("jobs")
    if not isinstance(jobs, iac_yaml.LDict):
        return False
    workflow_env = _github_env_taint(root)
    job_outputs: dict[str, set[str]] = {}
    cross_job_reads: list[tuple[iac_yaml.LDict, list[tuple[int, str]]]] = []
    for raw_job_name, raw_job in jobs.items():
        job_name = str(raw_job_name)
        job = _d(raw_job)
        job_env = _github_env_taint(job, workflow_env)
        persisted_env: set[str] = set()
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        tainted: set[tuple[str, str]] = set()
        for step in steps:
            if not isinstance(step, iac_yaml.LDict):
                continue
            step_env = _github_env_taint(step, job_env | persisted_env)
            script_lines = _script_lines(step, "run")
            cross_job_reads.append((job, script_lines))
            # Bir adım yalnız daha önce tamamlanan adımların çıktılarını okuyabilir. Önce tüketimi denetle,
            # ardından bu adımın çıktısını sonraki adımlar için görünür yap.
            for number, payload in script_lines:
                if any((m.group(1), m.group(2)) in tainted for m in _GH_OUTPUT_READ.finditer(payload)):
                    col.add("SNP-IAC-CI-001", number, resource)
            step_id = step.get("id")
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if isinstance(step_id, str) and re.fullmatch(r"[A-Za-z_][\w-]*", step_id) and \
                    "GITHUB_OUTPUT" in run:
                tainted.update((step_id, name) for name in _github_tainted_outputs(run, step_env))
            if "GITHUB_ENV" in run:
                for name, is_tainted in _github_env_updates(run, step_env).items():
                    if is_tainted:
                        persisted_env.add(name)
                    else:
                        persisted_env.discard(name)
        declared = job.get("outputs")
        if isinstance(declared, iac_yaml.LDict):
            for raw_name, value in declared.items():
                if not isinstance(value, str):
                    continue
                if _GH_UNTRUSTED.search(value) or any(
                        (match.group(1), match.group(2)) in tainted
                        for match in _GH_OUTPUT_READ.finditer(value)):
                    job_outputs.setdefault(job_name, set()).add(str(raw_name))

    # Job çıktıları yalnız ``needs`` ile açıkça bağlanan tüketici işlerinde görünür. Üreticinin YAML'da
    # tüketiciden sonra yazılması anlamı değiştirmez; bu yüzden okuma denetimi bütün üreticiler toplandıktan
    # sonra yapılır.
    for job, script_lines in cross_job_reads:
        needs = job.get("needs")
        linked = ({needs} if isinstance(needs, str) else
                  {item for item in needs if isinstance(item, str)} if isinstance(needs, list) else set())
        if not linked:
            continue
        for number, payload in script_lines:
            if any(match.group(1) in linked and
                   match.group(2) in job_outputs.get(match.group(1), set())
                   for match in _GH_JOB_OUTPUT_READ.finditer(payload)):
                col.add("SNP-IAC-CI-001", number, resource)
    return True


def _gitlab_flow(col: _Collector, root: iac_yaml.LDict, resource: str) -> bool:
    """GitLab dotenv üreticisini yalnız bildirilen artifact ve bağlı tüketici işiyle ilişkilendirir."""
    jobs: dict[str, iac_yaml.LDict] = {str(name): value for name, value in root.items()
                                      if isinstance(value, iac_yaml.LDict) and "script" in value}
    if not jobs:
        return False
    stages_value = root.get("stages")
    stage_order = [item for item in stages_value if isinstance(item, str)] if isinstance(stages_value, list) \
        else [".pre", "build", "test", "deploy", ".post"]
    stage_positions = {stage: index for index, stage in enumerate(stage_order)}
    produced: dict[str, set[str]] = {}
    producer_stages: dict[str, str] = {}
    for name, job in jobs.items():
        reports = _d(_d(job.get("artifacts")).get("reports"))
        dotenv = reports.get("dotenv")
        paths = ({dotenv} if isinstance(dotenv, str) else
                 {item for item in dotenv if isinstance(item, str)} if isinstance(dotenv, list) else set())
        if not paths:
            continue
        names: set[str] = set()
        for _number, raw in _script_lines(job, "script"):
            match = _GL_DOTENV_WRITE.search(raw) if _gitlab_expanded_untrusted(raw) else None
            redirect = _GL_REDIRECT.search(raw)
            if match and redirect and redirect.group(1) in paths:
                names.add(match.group(1))
        if names:
            produced[name] = names
            stage = job.get("stage")
            producer_stages[name] = stage if isinstance(stage, str) else "test"
    for name, job in jobs.items():
        linked: set[str] = set()
        explicit_scope = "needs" in job or "dependencies" in job
        needs = job.get("needs")
        for item in needs if isinstance(needs, list) else []:
            if isinstance(item, str):
                linked.add(item)
            else:
                need = _d(item)
                dependency = need.get("job")
                if isinstance(dependency, str) and need.get("artifacts") is not False:
                    linked.add(dependency)
        dependencies = job.get("dependencies")
        for item in dependencies if isinstance(dependencies, list) else []:
            if isinstance(item, str):
                linked.add(item)
        if not explicit_scope:
            stage = job.get("stage")
            consumer_stage = stage if isinstance(stage, str) else "test"
            consumer_position = stage_positions.get(consumer_stage)
            if consumer_position is not None:
                linked.update(parent for parent, parent_stage in producer_stages.items()
                              if stage_positions.get(parent_stage, consumer_position) < consumer_position)
        tainted = set().union(*(produced.get(parent, set()) for parent in linked)) if linked else set()
        if not tainted:
            continue
        for number, raw in _script_lines(job, "script"):
            if any(_gitlab_variable_used(raw, variable) for variable in tainted):
                col.add("SNP-IAC-CI-002", number, resource)
    return True


def analyze_ci(rel_path: str, text: str) -> IacResult | None:
    """GitHub Actions ve GitLab CI'da adımlar/işler arası komut verisi akışı.

    Yalnız kaynağı açıkça güvenilmeyen olay alanı olan ve daha sonra kabuk/script bağlamında
    tüketilen adlandırılmış değerler raporlanır. Sıradan ``env`` aktarımı komut enjeksiyonu sayılmaz.
    """
    normalized = rel_path.replace("\\", "/")
    github = bool(_GH_WORKFLOW.match(normalized))
    gitlab = bool(_GITLAB_WORKFLOW.search(normalized))
    if not (github or gitlab):
        return None
    col = _Collector("ci")
    lines = text.splitlines()
    resource = f"workflow/{normalized}"
    root = _ci_root(text)
    if root is not None:
        parsed = _github_flow(col, root, resource) if github else _gitlab_flow(col, root, resource)
        if parsed:
            return col.result
    if github:
        tainted: set[tuple[str, str]] = set()
        step_id = ""
        for raw in lines:
            id_match = _GH_STEP_ID.match(raw)
            if id_match:
                step_id = id_match.group(1)
            if step_id and "GITHUB_OUTPUT" in raw:
                for match in _GH_OUTPUT_WRITE.finditer(raw):
                    if _GH_UNTRUSTED.search(match.group(2)):
                        tainted.add((step_id, match.group(1)))
        block_indent: int | None = None
        for number, raw in enumerate(lines, 1):
            command = _CI_COMMAND.match(raw)
            payload = ""
            if command:
                indent, payload = len(command.group(1)), command.group(3)
                block_indent = indent if payload.strip() in ("|", ">", "|-", ">-") else None
            elif block_indent is not None:
                indent = len(raw) - len(raw.lstrip())
                if raw.strip() and indent <= block_indent:
                    block_indent = None
                else:
                    payload = raw
            if payload and any((m.group(1), m.group(2)) in tainted for m in _GH_OUTPUT_READ.finditer(payload)):
                col.add("SNP-IAC-CI-001", number, resource)
    else:
        tainted_names: set[str] = set()
        source_lines: set[int] = set()
        for number, raw in enumerate(lines, 1):
            if _GL_UNTRUSTED.search(raw) and re.search(r">\s*[^\s]+\.env\b", raw):
                match = _GL_DOTENV_WRITE.search(raw)
                if match:
                    tainted_names.add(match.group(1))
                    source_lines.add(number)
        in_script = False
        script_indent = 0
        for number, raw in enumerate(lines, 1):
            indent = len(raw) - len(raw.lstrip())
            if re.match(r"^\s*script\s*:\s*$", raw):
                in_script, script_indent = True, indent
                continue
            if in_script and raw.strip() and indent <= script_indent:
                in_script = False
            if in_script and number not in source_lines and any(re.search(rf"\$(?:\{{{re.escape(name)}\}}|{re.escape(name)})\b", raw)
                                                                 for name in tainted_names):
                col.add("SNP-IAC-CI-002", number, resource)
    return col.result


# --------------------------------------------------------------------------------------------- Terraform
_WORLD = {"0.0.0.0/0", "::/0"}
_AZ_WORLD = {"*", "0.0.0.0/0", "0.0.0.0", "internet", "any", "::/0"}
SENSITIVE_PORTS = {20, 21, 22, 23, 25, 110, 135, 137, 138, 139, 143, 445, 1433, 1434, 1521, 2049, 2375, 2376, 3306,
                   3389, 4333, 5432, 5500, 5601, 5900, 5984, 6379, 6443, 7001, 8020, 8086, 9042, 9092, 9200, 9300,
                   11211, 27017, 27018, 50070}


def _num(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value)
    return None


# UDP üzerinden de sunulan hassas hizmetler (NetBIOS, SNMP, SQL Browser, NFS, RDP-UDP, memcached, SSDP).
SENSITIVE_UDP_PORTS = {137, 138, 161, 1434, 1900, 2049, 3389, 11211}


def _range_risky(start: Any, end: Any, protocol: Any) -> bool:
    proto = str(protocol).strip().casefold() if isinstance(protocol, (str, int)) and not isinstance(protocol, bool) else None
    if proto in ("-1", "all", "*"):
        return True
    lo, hi = _num(start), _num(end)
    if lo is None or hi is None:
        return False
    if lo <= 0 and hi in (0, 65535) and proto in ("tcp", "udp", "6", "17"):
        return True
    if hi - lo >= 1000:
        return True
    ports = SENSITIVE_UDP_PORTS if proto in ("udp", "17") else SENSITIVE_PORTS
    return any(lo <= port <= hi for port in ports)


def _port_spec_risky(spec: Any, protocol: Any = "tcp") -> bool:
    """'22', '1000-2000', '*' gibi port tanımları (GCP/Azure)."""
    if not isinstance(spec, (str, int)) or isinstance(spec, bool):
        return False
    text = str(spec).strip()
    if "," in text:
        parts = [part.strip() for part in text.split(",")]
        return bool(parts) and all(parts) and any(_port_spec_risky(part, protocol) for part in parts[:1_000])
    if text.casefold() in ("*", "all", "any", "-1"):
        return True
    match = re.fullmatch(r"(\d+)(?:[-:](\d+))?", text)
    if not match:
        return False
    lo = int(match.group(1))
    hi = int(match.group(2) or lo)
    proto = str(protocol).strip().casefold() if isinstance(protocol, str) else "tcp"
    return _range_risky(lo, hi, "tcp" if proto in ("*", "all", "") else proto)


class _Res:
    """Kaynak bloğunu ya da sözlük değerini aynı arayüzle okumak için (ingress = [{...}] biçimi)."""

    def __init__(self, src: Any, line: int):
        self.src, self.line = src, line

    def get(self, key: str) -> Any:
        if isinstance(self.src, Block):
            attr = self.src.attrs.get(key)
            return None if attr is None else attr.value
        return self.src.get(key) if isinstance(self.src, dict) else None

    def line_of(self, key: str) -> int:
        if isinstance(self.src, Block):
            attr = self.src.attrs.get(key)
            return attr.line if attr else self.src.line
        return self.line

    def children(self, key: str) -> list["_Res"]:
        out: list[_Res] = []
        if isinstance(self.src, Block):
            out += [_Res(b, b.line) for b in self.src.children(key)]
            attr = self.src.attrs.get(key)
            if attr is not None:
                out += [_Res(item, attr.line) for item in _as_list(attr.value) if isinstance(item, dict)]
        elif isinstance(self.src, dict):
            out += [_Res(item, self.line) for item in _as_list(self.src.get(key)) if isinstance(item, dict)]
        return out


def _world(values: Any) -> bool:
    return any(isinstance(v, str) and v.strip() in _WORLD for v in _as_list(values))


def _tf_security_groups(col: _Collector, rtype: str, res: _Res, address: str) -> None:
    def rule(r: _Res, cidr_keys: tuple[str, ...], proto_key: str = "protocol") -> None:
        for key in cidr_keys:
            if _world(r.get(key)) and _range_risky(r.get("from_port"), r.get("to_port"), r.get(proto_key)):
                col.add("SNP-IAC-TF-001", r.line_of(key), address)
                return

    if rtype in ("aws_security_group", "aws_default_security_group"):
        for ingress in res.children("ingress"):
            rule(ingress, ("cidr_blocks", "ipv6_cidr_blocks"))
    elif rtype == "aws_security_group_rule":
        if res.get("type") == "ingress":
            rule(res, ("cidr_blocks", "ipv6_cidr_blocks"))
    elif rtype == "aws_vpc_security_group_ingress_rule":
        rule(res, ("cidr_ipv4", "cidr_ipv6"), "ip_protocol")
    elif rtype == "aws_network_acl_rule":
        egress = res.get("egress")
        if (egress is None or egress is False) and res.get("rule_action") == "allow":
            rule(res, ("cidr_block", "ipv6_cidr_block"))
    elif rtype in ("aws_network_acl", "aws_default_network_acl"):
        for ingress in res.children("ingress"):
            if ingress.get("action") == "allow":
                rule(ingress, ("cidr_block", "ipv6_cidr_block"))
    elif rtype == "google_compute_firewall":
        if res.get("disabled") is True:
            return
        direction = res.get("direction")
        source_ranges = res.get("source_ranges")
        missing = lambda value: value is None or isinstance(value, list) and not value
        defaults_to_world = missing(source_ranges) and missing(res.get("source_tags")) \
            and missing(res.get("source_service_accounts"))
        if (direction is None or direction == "INGRESS") and (_world(source_ranges) or defaults_to_world):
            for allow in res.children("allow"):
                ports = _as_list(allow.get("ports"))
                protocol = allow.get("protocol")
                if (protocol in ("all", "-1")) or (not ports and protocol in ("tcp", "udp")) \
                        or any(_port_spec_risky(p, protocol) for p in ports):
                    col.add("SNP-IAC-TF-001", res.line_of("source_ranges"), address)
                    break
    elif rtype in ("google_compute_firewall_policy_rule", "google_compute_network_firewall_policy_rule"):
        if res.get("disabled") is True or res.get("direction") != "INGRESS" or res.get("action") != "allow":
            return
        for match in res.children("match"):
            if not _world(match.get("src_ip_ranges")):
                continue
            for layer in match.children("layer4_configs"):
                protocol = layer.get("ip_protocol")
                ports = _as_list(layer.get("ports"))
                if protocol in ("all", "-1") or (not ports and protocol in ("tcp", "udp")) \
                        or any(_port_spec_risky(port, protocol) for port in ports):
                    col.add("SNP-IAC-TF-001", match.line_of("src_ip_ranges"), address)
                    return
    elif rtype in ("azurerm_network_security_rule", "azurerm_network_security_group"):
        rules = [res] if rtype == "azurerm_network_security_rule" else res.children("security_rule")
        for r in rules:
            if str(r.get("direction") or "").casefold() != "inbound" or str(r.get("access") or "").casefold() != "allow":
                continue
            sources = [r.get("source_address_prefix")] + _as_list(r.get("source_address_prefixes"))
            if not any(isinstance(s, str) and s.strip().casefold() in _AZ_WORLD for s in sources):
                continue
            ports = [r.get("destination_port_range")] + _as_list(r.get("destination_port_ranges"))
            if any(_port_spec_risky(p, r.get("protocol") or "tcp") for p in ports):
                key = "source_address_prefix" if r.get("source_address_prefix") is not None else "source_address_prefixes"
                col.add("SNP-IAC-TF-001", r.line_of(key), address)
    elif rtype == "digitalocean_firewall":
        for inbound in res.children("inbound_rule"):
            if _world(inbound.get("source_addresses")) and _port_spec_risky(
                    inbound.get("port_range"), inbound.get("protocol")):
                col.add("SNP-IAC-TF-001", inbound.line_of("source_addresses"), address)
    elif rtype == "linode_firewall":
        for inbound in res.children("inbound"):
            if str(inbound.get("action") or "").casefold() != "accept":
                continue
            if (_world(inbound.get("ipv4")) or _world(inbound.get("ipv6"))) \
                    and _port_spec_risky(inbound.get("ports"), inbound.get("protocol")):
                key = "ipv4" if inbound.get("ipv4") is not None else "ipv6"
                col.add("SNP-IAC-TF-001", inbound.line_of(key), address)
    elif rtype == "hcloud_firewall":
        for rule in res.children("rule"):
            port = rule.get("port")
            protocol = str(rule.get("protocol") or "").strip().casefold()
            risky_port = _port_spec_risky(port, protocol) or port is None and protocol in ("tcp", "udp", "6", "17")
            if str(rule.get("direction") or "").casefold() == "in" \
                    and _world(rule.get("source_ips")) \
                    and risky_port:
                col.add("SNP-IAC-TF-001", rule.line_of("source_ips"), address)
    elif rtype == "vultr_firewall_rule":
        subnet = str(res.get("subnet") or "").strip()
        subnet_size = _num(res.get("subnet_size"))
        public = subnet_size == 0 and subnet in ("0.0.0.0", "::")
        if public and _port_spec_risky(res.get("port"), res.get("protocol")):
            col.add("SNP-IAC-TF-001", res.line_of("subnet"), address)
    elif rtype == "openstack_networking_secgroup_rule_v2":
        if str(res.get("direction") or "").casefold() == "ingress" and _world(res.get("remote_ip_prefix")) \
                and _range_risky(res.get("port_range_min"), res.get("port_range_max"), res.get("protocol")):
            col.add("SNP-IAC-TF-001", res.line_of("remote_ip_prefix"), address)
    elif rtype == "alicloud_security_group_rule":
        policy = str(res.get("policy") or "accept").casefold()
        sources = [res.get("cidr_ip"), res.get("ipv6_cidr_ip")]
        protocol = res.get("ip_protocol")
        if str(res.get("type") or "").casefold() != "ingress" or policy != "accept" or not _world(sources):
            return
        if str(protocol).strip().casefold() in ("-1", "all", "*"):
            col.add("SNP-IAC-TF-001", res.line_of("cidr_ip"), address)
            return
        port_range = str(res.get("port_range") or "")
        match = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", port_range)
        if match and _range_risky(int(match.group(1)), int(match.group(2)), protocol):
            key = "cidr_ip" if res.get("cidr_ip") is not None else "ipv6_cidr_ip"
            col.add("SNP-IAC-TF-001", res.line_of(key), address)
    elif rtype == "huaweicloud_networking_secgroup_rule":
        if str(res.get("direction") or "").casefold() == "ingress" \
                and _world(res.get("remote_ip_prefix")) \
                and _port_spec_risky(res.get("ports"), res.get("protocol")):
            col.add("SNP-IAC-TF-001", res.line_of("remote_ip_prefix"), address)
    elif rtype == "oci_core_security_list":
        for ingress in res.children("ingress_security_rules"):
            if not _world(ingress.get("source")):
                continue
            protocol = ingress.get("protocol")
            if str(protocol).strip().casefold() in ("-1", "all", "*"):
                col.add("SNP-IAC-TF-001", ingress.line_of("source"), address)
                continue
            option_key = "udp_options" if str(protocol).strip() == "17" else "tcp_options"
            for options in ingress.children(option_key):
                destination_ranges = options.children("destination_port_range")
                if _range_risky(options.get("min"), options.get("max"), protocol) or any(
                        _range_risky(port_range.get("min"), port_range.get("max"), protocol)
                        for port_range in destination_ranges):
                    col.add("SNP-IAC-TF-001", ingress.line_of("source"), address)
                    break
    elif rtype == "oci_core_network_security_group_security_rule":
        if str(res.get("direction") or "").casefold() != "ingress" or not _world(res.get("source")):
            return
        protocol = res.get("protocol")
        if str(protocol).strip().casefold() in ("-1", "all", "*"):
            col.add("SNP-IAC-TF-001", res.line_of("source"), address)
            return
        option_key = "udp_options" if str(protocol).strip() == "17" else "tcp_options"
        for options in res.children(option_key):
            destination_ranges = options.children("destination_port_range")
            if _range_risky(options.get("min"), options.get("max"), protocol) or any(
                    _range_risky(port_range.get("min"), port_range.get("max"), protocol)
                    for port_range in destination_ranges):
                col.add("SNP-IAC-TF-001", res.line_of("source"), address)
                break


def _policy_statements(value: Any) -> list[dict] | None:
    if isinstance(value, Call) and value.name == "jsonencode" and value.args:
        value = value.args[0]
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if not isinstance(value, dict):
        return None
    statements = value.get("Statement")
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [s for s in statements if isinstance(s, dict)]
    return None


def _star(values: Any) -> bool:
    return any(v == "*" for v in _as_list(values))


def _principal_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_star(v) for v in principal.values())
    return False


_RESOURCE_POLICY = {
    "aws_s3_bucket_policy": "policy", "aws_sqs_queue_policy": "policy", "aws_sns_topic_policy": "policy",
    "aws_ecr_repository_policy": "policy", "aws_secretsmanager_secret_policy": "policy", "aws_s3_bucket": "policy",
    "aws_kms_key": "policy", "aws_elasticsearch_domain_policy": "access_policies",
    "aws_elasticsearch_domain": "access_policies", "aws_opensearch_domain_policy": "access_policies",
    "aws_opensearch_domain": "access_policies", "aws_glacier_vault": "access_policy", "aws_sqs_queue": "policy",
    "aws_sns_topic": "policy", "aws_api_gateway_rest_api_policy": "policy", "aws_lambda_layer_version_permission": "",
}
_IAM_POLICY = {"aws_iam_policy": "policy", "aws_iam_role_policy": "policy", "aws_iam_user_policy": "policy",
               "aws_iam_group_policy": "policy"}


def _tf_policies(col: _Collector, kind: str, rtype: str, block: Block, address: str) -> None:
    targets: list[tuple[Any, int, bool]] = []  # (değer, satır, kaynak politikası mı)
    if kind == "resource" and rtype in _IAM_POLICY:
        attr = block.attrs.get("policy")
        if attr:
            targets.append((attr.value, attr.line, False))
    if kind == "resource" and rtype == "aws_iam_role":
        for inline in block.children("inline_policy"):
            attr = inline.attrs.get("policy")
            if attr:
                targets.append((attr.value, attr.line, False))
    if kind == "resource" and _RESOURCE_POLICY.get(rtype):
        attr = block.attrs.get(_RESOURCE_POLICY[rtype])
        if attr:
            targets.append((attr.value, attr.line, True))
    for value, line, resource_policy in targets:
        for statement in _policy_statements(value) or []:
            if statement.get("Effect", "Allow") != "Allow":
                continue
            if _star(statement.get("Action")) and _star(statement.get("Resource")):
                col.add("SNP-IAC-TF-006", line, address)
            if resource_policy and _principal_public(statement.get("Principal")) and not statement.get("Condition"):
                col.add("SNP-IAC-TF-007", line, address)
    if kind == "data" and rtype == "aws_iam_policy_document":
        for statement in block.children("statement"):
            effect = statement.attrs.get("effect")
            if effect is not None and effect.value != "Allow":
                continue
            actions = statement.attrs.get("actions")
            resources = statement.attrs.get("resources")
            if actions and resources and _star(actions.value) and _star(resources.value):
                col.add("SNP-IAC-TF-006", statement.line, address)
            for principals in statement.children("principals"):
                ptype = principals.attrs.get("type")
                ids = principals.attrs.get("identifiers")
                if ptype and ids and (ptype.value == "*" or (ptype.value == "AWS" and _star(ids.value))) \
                        and _star(ids.value) and not statement.children("condition"):
                    col.add("SNP-IAC-TF-007", principals.line, address)


def _tf_misc(col: _Collector, rtype: str, block: Block, address: str) -> None:
    if rtype == "aws_eks_cluster":
        for vpc in block.children("vpc_config"):
            public = vpc.attrs.get("endpoint_public_access")
            cidrs = vpc.attrs.get("public_access_cidrs")
            if public is not None and public.value is True and (cidrs is None or _world(cidrs.value)):
                col.add("SNP-IAC-TF-013", public.line, address)
    if rtype.startswith("azurerm_") and rtype.endswith("firewall_rule"):
        start, end = block.attrs.get("start_ip_address"), block.attrs.get("end_ip_address")
        if start and end and start.value == "0.0.0.0" and end.value == "255.255.255.255":
            col.add("SNP-IAC-TF-016", start.line, address)


def _walk_values(block: Block) -> Iterable[tuple[str, Any, int]]:
    """Bloğun (iç içe bloklar ve harita değerleri dahil) tüm (ad, değer, satır) üçlüleri."""
    for name, attr in block.attrs.items():
        yield name, attr.value, attr.line
        stack = [attr.value]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                for key, sub in value.items():
                    yield key, sub, attr.line
                    if isinstance(sub, (dict, list)):
                        stack.append(sub)
            elif isinstance(value, list):
                stack.extend(v for v in value if isinstance(v, (dict, list)))
    for child in block.blocks:
        yield from _walk_values(child)


_SECRET_SKIP_RESOURCES = re.compile(r"^(?:random_|tls_|aws_iam_access_key$|null_resource$|terraform_data$|time_)")


def _tf_secrets(col: _Collector, block: Block, address: str, lines: list[str]) -> None:
    for name, value, line in _walk_values(block):
        if isinstance(value, (dict, list)):
            continue
        if not ((_secret_name(name) and _literal_secret(value, name)) or _aws_key_value(value)):
            continue
        if _GENERIC_SECRET_LINE.search(_line_text(lines, line)):
            continue  # genel sır kuralı aynı satırı zaten raporluyor
        col.add("SNP-IAC-TF-020", line, address)


def _resolve(node: Any, parts: list[str], line: int) -> Iterable[tuple[Any, int]]:
    if not parts:
        yield node, line
        return
    head, rest = parts[0], parts[1:]
    if isinstance(node, Block):
        attr = node.attrs.get(head)
        if attr is not None:
            yield from _resolve(attr.value, rest, attr.line)
        for child in node.children(head):
            yield from _resolve(child, rest, child.line)
    elif isinstance(node, dict):
        if head in node:
            yield from _resolve(node[head], rest, line)
    elif isinstance(node, list):
        for item in node:
            yield from _resolve(item, parts, line)


def _type_matches(spec: Any, rtype: str) -> bool:
    if spec == "*":
        return True
    if isinstance(spec, str):
        return fnmatch.fnmatchcase(rtype, spec)
    return rtype in spec


def _value_matches(op: str, actual: Any, expected: Any) -> bool:
    if isinstance(actual, (Unknown, Call)):
        return False

    def same(a: Any, b: Any) -> bool:
        if isinstance(b, bool):
            return a is b or (isinstance(a, str) and a.strip().casefold() == str(b).casefold())
        if isinstance(a, bool):
            return False
        return a == b

    if op == "eq":
        return same(actual, expected)
    if op == "in":
        return any(same(actual, e) for e in expected)
    if op == "contains_any":
        return any(same(a, e) for a in _as_list(actual) for e in expected)
    if op == "absent":
        return False  # "absent" _tf_declarative içinde ayrıca ele alınır
    raise ValueError(f"bilinmeyen işleç: {op}")


_MATCH_RULES = [(rule_id, spec) for rule_id, rule in RULES.items() for spec in rule.get("match") or ()]


def _unless(spec: dict, node: Block) -> bool:
    unless = spec.get("unless")
    if not unless:
        return False
    op, expected = ("in", unless["value"]) if isinstance(unless["value"], list) else ("eq", unless["value"])
    return any(_value_matches(op, v, expected) for v, _ in _resolve(node, unless["path"].split("."), node.line))


def _tf_declarative(col: _Collector, rtype: str, node: Block, address: str, root_level: bool = False,
                    suppressed: frozenset[str] = frozenset()) -> None:
    for rule_id, spec in _MATCH_RULES:
        if root_level and (spec["resources"] != "*" or "." in spec["path"]):
            continue
        if not root_level and not _type_matches(spec["resources"], rtype):
            continue
        if spec["path"] in suppressed:
            continue
        if _unless(spec, node):
            continue  # ör. http_endpoint = "disabled" iken IMDSv1 ayarı anlamsız
        if spec["op"] == "absent":
            # Varsayılanı güvensiz ayar hiç yazılmamış. Bilinmeyen (değişken) değer "var" sayılır; dinamik blok ya da
            # kaçınma alanlarından biri (ör. snapshot'tan geri yükleme) varsa susulur.
            head = spec["path"].split(".")[0]
            if head in node.attrs or node.children(head) or node.children("dynamic") \
                    or any(key in node.attrs for key in spec.get("unless_present", ())):
                continue
            col.add(rule_id, node.line, address)
            continue
        for actual, line in _resolve(node, spec["path"].split("."), node.line):
            if _value_matches(spec["op"], actual, spec["value"]):
                col.add(rule_id, line, address)
                break


# Yaygın topluluk modüllerinin girdileri ilgili kaynağın öznitelikleriyle aynı adı taşır.
_MODULE_TYPES = (
    ("terraform-aws-modules/s3-bucket/", "aws_s3_bucket"), ("terraform-aws-modules/rds-aurora/", "aws_rds_cluster"),
    ("terraform-aws-modules/rds/", "aws_db_instance"), ("terraform-aws-modules/ec2-instance/", "aws_instance"),
    ("terraform-aws-modules/sns/", "aws_sns_topic"), ("terraform-aws-modules/sqs/", "aws_sqs_queue"),
    ("terraform-aws-modules/kms/", "aws_kms_key"), ("terraform-aws-modules/eks/", "aws_eks_cluster"),
)
_MODULE_RESOURCE_POLICY = {"aws_s3_bucket", "aws_sns_topic", "aws_sqs_queue", "aws_kms_key"}


def _tf_module(col: _Collector, block: Block, lines: list[str], prefix: str = "", original: Block | None = None) -> None:
    address = f"{prefix}module.{block.labels[0]}"
    source = block.attrs.get("source")
    src = source.value if source and isinstance(source.value, str) else ""
    rtype = next((rt for prefix, rt in _MODULE_TYPES if src.startswith(prefix)), "")
    col.result.resources += 1
    # Bilinen modülde kaynak kuralları, bilinmeyende yalnız kaynaktan bağımsız ("*") kurallar; "absent" kuralları
    # modüllerde uygulanmaz (modülün kendi varsayılanı bilinmez).
    for rule_id, spec in _MATCH_RULES:
        if spec["op"] == "absent":
            continue
        if not (spec["resources"] == "*" or (rtype and _type_matches(spec["resources"], rtype))) or _unless(spec, block):
            continue
        for actual, line in _resolve(block, spec["path"].split("."), block.line):
            if _value_matches(spec["op"], actual, spec["value"]):
                col.add(rule_id, line, address)
                break
    _tf_secrets(col, original or block, address, lines)
    for name, attr in block.attrs.items():
        if not name.endswith("policy"):
            continue
        for statement in _policy_statements(attr.value) or []:
            if statement.get("Effect", "Allow") != "Allow":
                continue
            if _star(statement.get("Action")) and _star(statement.get("Resource")):
                col.add("SNP-IAC-TF-006", attr.line, address)
            if rtype in _MODULE_RESOURCE_POLICY and _principal_public(statement.get("Principal")) \
                    and not statement.get("Condition"):
                col.add("SNP-IAC-TF-007", attr.line, address)


_S3_REF = re.compile(r"\baws_s3_bucket\.([A-Za-z_][\w-]*)")


def _raw_refs(value: Any) -> str:
    """Bilinmeyen ifadelerin özgün metni (başvuru adlarını aramak için)."""
    if isinstance(value, Unknown):
        return "".join(str(t.value) for t in value.toks) if value.toks else value.raw.replace(" ", "")
    if isinstance(value, Call):
        return " ".join(_raw_refs(a) for a in value.args)
    if isinstance(value, list):
        return " ".join(_raw_refs(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_raw_refs(v) for v in value.values())
    return str(value) if isinstance(value, str) else ""


@dataclass
class ModuleFacts:
    """Modül (dizin) genelindeki kaynaklar arası olgular — "eksik ayar" denetimleri için."""
    versioned: set[str] = field(default_factory=set)  # sürümlemesi ayrı kaynakla bağlanan kovalar
    logged: set[str] = field(default_factory=set)
    log_targets: set[str] = field(default_factory=set)  # başka kovaların günlük hedefi olan kovalar
    versioning_unmapped: bool = False  # kovası çözülemeyen sürümleme kaynağı var → denetim susar
    logging_unmapped: bool = False
    ebs_default_encryption: bool = False


def module_facts(roots: Iterable[Block]) -> ModuleFacts:
    facts = ModuleFacts()
    for root in roots:
        for block in root.blocks:
            if block.type != "resource" or len(block.labels) < 2 or _disabled(block):
                continue
            rtype = block.labels[0]
            if rtype == "aws_ebs_encryption_by_default":
                enabled = block.attrs.get("enabled")
                if enabled is None or enabled.value is not False:
                    facts.ebs_default_encryption = True
            elif rtype in ("aws_s3_bucket_versioning", "aws_s3_bucket_logging"):
                bucket = block.attrs.get("bucket")
                names = set(_S3_REF.findall(_raw_refs(bucket.value))) if bucket else set()
                if rtype == "aws_s3_bucket_versioning":
                    statuses = [c.attrs["status"].value for c in block.children("versioning_configuration")
                                if "status" in c.attrs]
                    if any(s in ("Suspended", "Disabled") for s in statuses):
                        continue  # askıya alınmış sürümleme sürümleme sayılmaz
                    facts.versioned |= names
                    facts.versioning_unmapped |= not names
                else:
                    facts.logged |= names
                    facts.logging_unmapped |= not names
            if rtype == "aws_s3_bucket_logging" or rtype == "aws_s3_bucket":
                for holder in [block, *block.children("logging")]:
                    target = holder.attrs.get("target_bucket")
                    if target is not None:
                        facts.log_targets |= set(_S3_REF.findall(_raw_refs(target.value)))
    return facts


def _tf_defaults(col: _Collector, rtype: str, block: Block, address: str, name: str, facts: ModuleFacts) -> None:
    """Kaynaklar arası bilgi gerektiren "eksik ayar" (varsayılan güvensiz) denetimleri."""
    if rtype == "aws_s3_bucket":
        inline_versioning = any(b.attrs.get("enabled") is None or b.attrs["enabled"].value is not False
                                for b in block.children("versioning")) or "versioning" in block.attrs
        if not (inline_versioning or name in facts.versioned or facts.versioning_unmapped or block.children("dynamic")):
            col.add("SNP-IAC-TF-025", block.line, address)
        inline_logging = bool(block.children("logging")) or "logging" in block.attrs
        if not (inline_logging or name in facts.logged or name in facts.log_targets or facts.logging_unmapped
                or block.children("dynamic")):
            acl = block.attrs.get("acl")
            if not (acl is not None and acl.value == "log-delivery-write"):
                col.add("SNP-IAC-TF-026", block.line, address)
    elif rtype == "aws_ebs_volume":
        if not ("encrypted" in block.attrs or "snapshot_id" in block.attrs or "kms_key_id" in block.attrs
                or facts.ebs_default_encryption):
            col.add("SNP-IAC-TF-027", block.line, address)


def _disabled(block: Block) -> bool:
    """Açıkça yazılmış ``count = 0`` veya boş ``for_each`` bloğunun örnek üretmediğini gösterir."""
    count = block.attrs.get("count")
    if count is not None and isinstance(count.value, (int, float)) and not isinstance(count.value, bool) \
            and count.value == 0:
        return True
    if count is not None and count.value is False:
        return True
    for_each = block.attrs.get("for_each")
    return for_each is not None and isinstance(for_each.value, (list, dict)) and not for_each.value


def analyze_terraform_root(root: Block, lines: list[str], *, original: Block | None = None,
                           facts: ModuleFacts | None = None, local_modules: frozenset[str] = frozenset(),
                           prefix: str = "", resolved: bool = False) -> IacResult:
    """Ayrıştırılmış (isteğe bağlı olarak bağlamda çözülmüş) kök bloğu denetler. Sabit sır denetimi özgün (çözülmemiş)
    blokla yapılır: değişken varsayılanından gelen değer kaynak satırında yeniden raporlanmaz. ``local_modules``:
    proje içinde çözülen yerel modül çağrıları — bunlar modülün kendi dosyalarında denetlendiği için çağrı bloğunda
    yalnız sır denetimi yapılır."""
    original = original or root
    facts = facts if facts is not None else module_facts([root])
    col = _Collector("terraform")
    # Hesap düzeyi S3 genel erişim engeli, kova düzeyindeki aynı bayrağın false olmasını etkisiz kılar.
    account_blocks = frozenset(
        flag for block in root.blocks
        if block.type == "resource" and block.labels[:1] == ["aws_s3_account_public_access_block"]
        for flag, attr in block.attrs.items() if attr.value is True
    )
    for block, orig in zip(root.blocks, original.blocks):
        if block.type == "provider":
            _tf_secrets(col, orig, f"provider.{block.labels[0] if block.labels else '?'}", lines)
            continue
        if block.type == "module" and block.labels:
            if _disabled(orig):
                continue
            if block.labels[0] in local_modules:
                col.result.resources += 1
                _tf_secrets(col, orig, f"{prefix}module.{block.labels[0]}", lines)
            else:
                _tf_module(col, block, lines, prefix=prefix, original=orig)
            continue
        if block.type not in ("resource", "data") or len(block.labels) < 2:
            continue
        if _disabled(orig):
            continue
        rtype, name = block.labels[0], block.labels[1]
        address = f"{prefix}{'data.' if block.type == 'data' else ''}{rtype}.{name}"
        # Yalnız özgün bloktaki değişmez sıfır/boş meta argüman atlanır. ``count = var.instances`` gibi
        # sonradan ``-var`` ile değiştirilebilen ifadeler, varsayılan sıfıra çözülse de ihtiyatlı biçimde denetlenir.
        col.result.resources += 1
        if block.type == "resource":
            _tf_declarative(col, rtype, block, address,
                            suppressed=account_blocks if rtype == "aws_s3_bucket_public_access_block" else frozenset())
            _tf_defaults(col, rtype, block, address, name, facts)
            _tf_security_groups(col, rtype, _Res(block, block.line), address)
            _tf_misc(col, rtype, block, address)
            if not _SECRET_SKIP_RESOURCES.match(rtype):
                _tf_secrets(col, orig, address, lines)
        _tf_policies(col, block.type, rtype, block, address)
    return col.result


def analyze_terraform(text: str, tfvars: bool = False) -> IacResult:
    root = iac_hcl.parse(text)
    lines = text.splitlines()
    if tfvars:
        # .tfvars: modül girdileri; yalnız kaynaktan bağımsız düz ayarlar (encrypted = false gibi) denetlenir.
        col = _Collector("terraform")
        _tf_declarative(col, "", root, "tfvars", root_level=True)
        return col.result
    return analyze_terraform_root(root, lines)


# --------------------------------------------------------------------------------------------- giriş noktası
IAC_SUFFIXES = {".tf", ".tfvars", ".yml", ".yaml"}
_K8S_HINT = re.compile(r"(?m)^\s*apiVersion\s*:")
_KIND_HINT = re.compile(r"(?m)^\s*kind\s*:")
_COMPOSE_HINT = re.compile(r"(?m)^services\s*:")
_COMPOSE_NAME = re.compile(r"(?i)^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$")


def is_dockerfile_name(name: str) -> bool:
    low = name.casefold()
    return low in ("dockerfile", "containerfile") or low.startswith(("dockerfile.", "containerfile.")) \
        or low.endswith(".dockerfile")


def analyze(rel_path: str, text: str, helm_values: dict | None = None) -> IacResult | None:
    """Dosya IaC değilse ya da ayrıştırılamazsa None (çağıran eski desen kurallarına düşer). ``helm_values``:
    şablon bir Helm grafiğindeyse grafiğin values.yaml değerleri (19. tur: değerlerle render)."""
    name = rel_path.replace("\\", "/").rsplit("/", 1)[-1]
    suffix = ("." + name.rsplit(".", 1)[-1].casefold()) if "." in name else ""
    if is_dockerfile_name(name):
        return analyze_dockerfile(text)
    if suffix in (".tf", ".tfvars"):
        try:
            return analyze_terraform(text, tfvars=suffix == ".tfvars")
        except iac_hcl.HclError:
            return None
    ci = analyze_ci(rel_path, text)
    if ci is not None:
        return ci
    if suffix not in (".yml", ".yaml"):
        return None
    k8s = bool(_K8S_HINT.search(text) and _KIND_HINT.search(text))
    compose = bool(_COMPOSE_HINT.search(text)) and (bool(_COMPOSE_NAME.match(name)) or "image:" in text or "build:" in text)
    if not (k8s or compose):
        return None
    templated = "{{" in text
    if templated and k8s and helm_values is not None:
        rendered = _analyze_helm(text, helm_values)
        if rendered is not None:
            return rendered
    try:
        docs = iac_yaml.load_all(iac_yaml.render_helm_lite(text) if templated else text)
    except iac_yaml.YamlError:
        return None
    if k8s and any(isinstance(d, iac_yaml.LDict) and isinstance(d.get("kind"), str) and "apiVersion" in d
                   for d in docs):
        return analyze_kubernetes(docs, templated)
    if compose:
        for doc in docs:
            if isinstance(doc, iac_yaml.LDict) and isinstance(doc.get("services"), iac_yaml.LDict):
                return analyze_compose(doc, rel_path)
    return None


def _analyze_helm(text: str, values: dict) -> IacResult | None:
    """Helm şablonunu grafik değerleriyle render edip denetler; bulgu satırları şablon satırına çevrilir. Render ya da
    YAML ayrıştırması başarısızsa None (çağıran eski yer tutuculu yaklaşıma düşer)."""
    import iac_helm

    variants = iac_helm.render_variants(text, values)
    result = IacResult("kubernetes")
    if not variants:
        if not variants.analysis_complete:
            result.analysis_complete = False
            result.note = (f"helm-values; incomplete; {variants.strategy}; "
                           f"unknown-controls={variants.unknown_controls}; covered-controls={variants.covered_controls}; "
                           f"partial-ranges={variants.partial_ranges}")
            return result
        return None
    seen: set[tuple[str, int, str]] = set()
    parsed = False
    for rendered, mapping in variants:
        try:
            docs = iac_yaml.load_all(rendered)
        except iac_yaml.YamlError:
            continue
        if not any(isinstance(d, iac_yaml.LDict) and isinstance(d.get("kind"), str) and "apiVersion" in d for d in docs):
            continue
        parsed = True
        # templated=True: koşullu/yer tutuculu kısımlar kalabileceği için sertleştirme eksikleri üretilmez.
        branch = analyze_kubernetes(docs, templated=True)
        result.resources = max(result.resources, branch.resources)
        for item in branch.findings:
            line = item["line"]
            item["line"] = mapping[line - 1] if 1 <= line <= len(mapping) else line
            key = (item["id"], item["line"], item["resource"])
            if key not in seen:
                seen.add(key)
                result.findings.append(item)
    if not parsed:
        return None
    result.analysis_complete = variants.analysis_complete
    if variants.analysis_complete:
        result.note = "helm-values"
    else:
        result.note = (f"helm-values; incomplete; {variants.strategy}; "
                       f"unknown-controls={variants.unknown_controls}; covered-controls={variants.covered_controls}; "
                       f"partial-ranges={variants.partial_ranges}")
    return result


def helm_values_for(root: Path, rel_path: str) -> dict | None:
    """``<grafik>/templates/…`` dosyası için grafiğin values.yaml değerleri (Chart.yaml olan dizin). Proje kökü dışına
    çıkılmaz, sembolik bağ izlenmez; 1 MB üstü değer dosyası okunmaz."""
    import iac_helm

    parts = rel_path.replace("\\", "/").split("/")
    if "templates" not in parts:
        return None
    chart_parts = parts[:len(parts) - 1 - parts[::-1].index("templates")]
    chart = root.joinpath(*chart_parts) if chart_parts else root
    values_path = chart / "values.yaml"
    try:
        if not (chart / "Chart.yaml").is_file() or values_path.is_symlink() or not values_path.is_file():
            return None
        resolved = values_path.resolve()
        if root.resolve() not in resolved.parents:
            return None
        info = values_path.stat()
        if info.st_size > 1_000_000:
            return None
        raw = values_path.read_bytes()
        key = (str(resolved), hashlib.sha256(raw).digest())
        with _HELM_VALUES_CACHE_LOCK:
            cached = _HELM_VALUES_CACHE.get(key, _HELM_CACHE_MISS)
        if cached is _HELM_CACHE_MISS:
            parsed = iac_helm.load_values(raw.decode("utf-8", errors="replace"))
            with _HELM_VALUES_CACHE_LOCK:
                if len(_HELM_VALUES_CACHE) >= 256:
                    _HELM_VALUES_CACHE.clear()
                cached = _HELM_VALUES_CACHE.setdefault(key, parsed)
        return cached
    except OSError:
        return None


_HELM_CACHE_MISS = object()
_HELM_VALUES_CACHE: dict[tuple[str, bytes], dict | None] = {}
_HELM_VALUES_CACHE_LOCK = threading.Lock()


def checks_summary() -> dict[str, int]:
    """Çerçeve başına kural sayısı (arayüz/belge için)."""
    out: dict[str, int] = {}
    for rule in RULES.values():
        out[rule["framework"]] = out.get(rule["framework"], 0) + max(1, len(rule.get("match") or ()))
    return out
