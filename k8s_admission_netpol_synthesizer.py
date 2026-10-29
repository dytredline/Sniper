"""Wave 6 — Bulut-Yerli (Cloud-Native) Kubernetes Admission, NetworkPolicy ve Tetragon eBPF Sentezleyici.

Projenin gerçek servis güven grafiğini (service_trust_graph) ve Sniper güvenlik
bulgularını kullanarak en az ayrıcalıklı Kubernetes NetworkPolicy, CEL tabanlı
ValidatingAdmissionPolicy ve Cilium Tetragon eBPF TracingPolicy manifestolarını üretir.
"""

from __future__ import annotations

import re
from typing import Any

FORMAT = "sniper-k8s-ebpf-zero-trust-synthesis/1"

_LABEL_CLEAN_RE = re.compile(r"[^a-z0-9\-]+")


def _clean_k8s_name(raw: object, fallback: str = "service") -> str:
    text = str(raw or "").strip().lower()
    for prefix in ("repo:", "service:", "svc:"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    cleaned = _LABEL_CLEAN_RE.sub("-", text).strip("-")[:63].rstrip("-")
    return cleaned or fallback


def _resolve_port_and_protocol(edge: dict[str, Any]) -> tuple[int, str]:
    raw_proto = str(edge.get("protocol") or "TCP").strip().upper()
    raw_port = edge.get("port")
    if isinstance(raw_port, int) and not isinstance(raw_port, bool) and 1 <= raw_port <= 65535:
        port = raw_port
    else:
        try:
            port = int(str(raw_port).strip())
            if not (1 <= port <= 65535):
                port = 8080
        except (TypeError, ValueError):
            if raw_proto == "HTTPS":
                port = 443
            elif raw_proto in {"GRPC", "GRPCS"}:
                port = 50051
            elif raw_proto in {"POSTGRES", "POSTGRESQL"}:
                port = 5432
            elif raw_proto == "REDIS":
                port = 6379
            else:
                port = 8080

    k8s_proto = "UDP" if raw_proto == "UDP" else ("SCTP" if raw_proto == "SCTP" else "TCP")
    return port, k8s_proto


def _finding_blob(findings: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        for key in ("id", "rule_id", "cwe", "category", "title", "description", "sink"):
            val = item.get(key)
            if val is not None:
                parts.append(str(val).lower())
    return " ".join(parts)


def synthesize_zero_trust_k8s_and_ebpf_policies(
    findings: list[dict[str, Any]],
    *,
    service_graph: dict[str, Any] | None = None,
    namespace: str = "production",
    app_name: str = "sniper-guarded-app",
) -> dict[str, Any]:
    """Servis grafiği ve bulgulardan sıfır-güven Kubernetes NetworkPolicy, ValidatingAdmissionPolicy ve Tetragon eBPF politikaları üretir."""
    clean_ns = _clean_k8s_name(namespace, fallback="production")
    clean_app = _clean_k8s_name(app_name, fallback="sniper-guarded-app")
    safe_findings = [f for f in (findings or []) if isinstance(f, dict)]
    blob = _finding_blob(safe_findings)

    # -------------------------------------------------------------------------
    # 1. Kubernetes NetworkPolicy (default-deny-all + doğrulanmış servis kenarları)
    # -------------------------------------------------------------------------
    netpols: list[dict[str, Any]] = [
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-all",
                "namespace": clean_ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "sniper-zero-trust",
                    "app.kubernetes.io/part-of": clean_app,
                },
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
            },
        }
    ]

    raw_edges = service_graph.get("edges") if isinstance(service_graph, dict) else []
    edges_list = raw_edges if isinstance(raw_edges, list) else []
    seen_edges: set[tuple[str, str, int, str]] = set()

    for edge in edges_list:
        if not isinstance(edge, dict):
            continue
        verification_state = str(edge.get("verification_state") or "runtime_confirmed").strip().lower()
        if verification_state == "contradicted":
            continue

        raw_producer = edge.get("producer") or edge.get("source") or edge.get("from")
        raw_consumer = edge.get("consumer") or edge.get("target") or edge.get("to")
        if not raw_producer or not raw_consumer:
            continue

        producer = _clean_k8s_name(raw_producer, fallback="producer")
        consumer = _clean_k8s_name(raw_consumer, fallback="consumer")
        port, k8s_proto = _resolve_port_and_protocol(edge)

        edge_key = (producer, consumer, port, k8s_proto)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        netpols.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": f"allow-{producer}-to-{consumer}-{port}",
                    "namespace": clean_ns,
                    "labels": {
                        "app.kubernetes.io/managed-by": "sniper-zero-trust",
                        "sniper.io/producer": producer,
                        "sniper.io/consumer": consumer,
                        "sniper.io/verification-state": verification_state,
                    },
                },
                "spec": {
                    "podSelector": {
                        "matchLabels": {
                            "app": consumer,
                        }
                    },
                    "policyTypes": ["Ingress"],
                    "ingress": [
                        {
                            "from": [
                                {
                                    "podSelector": {
                                        "matchLabels": {
                                            "app": producer,
                                        }
                                    }
                                }
                            ],
                            "ports": [
                                {
                                    "protocol": k8s_proto,
                                    "port": port,
                                }
                            ],
                        }
                    ],
                },
            }
        )

    # -------------------------------------------------------------------------
    # 2. Kubernetes ValidatingAdmissionPolicy & ValidatingAdmissionPolicyBinding (CEL)
    # -------------------------------------------------------------------------
    cel_rules: list[dict[str, str]] = [
        {
            "expression": "!object.spec.template.spec.containers.exists(c, c.?securityContext.?privileged.orValue(false) == true)",
            "message": "SNIPER-K8S-CEL-01: Privileged containers are strictly prohibited in zero-trust namespaces.",
            "reason": "Forbidden",
        },
        {
            "expression": (
                "!object.spec.template.spec.containers.exists(c, "
                "c.?securityContext.?capabilities.?add.orValue([]).exists(cap, "
                "cap in ['NET_ADMIN', 'SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_OVERRIDE']))"
            ),
            "message": "SNIPER-K8S-CEL-02: Dangerous Linux capabilities (NET_ADMIN, SYS_ADMIN, SYS_PTRACE) are prohibited.",
            "reason": "Forbidden",
        },
        {
            "expression": (
                "!object.spec.template.spec.?volumes.orValue([]).exists(v, "
                "v.?hostPath.?path.orValue('') in ['/var/run/docker.sock', '/run/containerd/containerd.sock', '/dev/kvm', '/'])"
            ),
            "message": "SNIPER-K8S-CEL-03: HostPath mounts exposing container runtime sockets (/var/run/docker.sock) or /dev/kvm are prohibited.",
            "reason": "Forbidden",
        },
        {
            "expression": (
                "object.spec.template.spec.containers.all(c, "
                "c.?securityContext.?runAsNonRoot.orValue(false) == true && "
                "c.?securityContext.?runAsUser.orValue(1000) != 0)"
            ),
            "message": "SNIPER-K8S-CEL-04: All containers must enforce runAsNonRoot == true and non-zero UID.",
            "reason": "Forbidden",
        },
    ]

    policy_name = f"{clean_app}-zero-trust-admission"
    admission_policy: dict[str, Any] = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {
            "name": policy_name,
            "labels": {
                "app.kubernetes.io/managed-by": "sniper-zero-trust",
                "app.kubernetes.io/name": clean_app,
            },
        },
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": ["deployments", "daemonsets", "statefulsets"],
                    },
                    {
                        "apiGroups": ["batch"],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": ["jobs", "cronjobs"],
                    },
                ]
            },
            "validations": cel_rules,
        },
        "binding": {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {
                "name": f"{policy_name}-binding",
            },
            "spec": {
                "policyName": policy_name,
                "validationActions": ["Deny"],
                "matchResources": {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": clean_ns,
                        }
                    }
                },
            },
        },
    }

    # -------------------------------------------------------------------------
    # 3. Cilium Tetragon eBPF TracingPolicy (sys_execve & hassas dosya erişimi)
    # -------------------------------------------------------------------------
    has_cmdi_or_rce = any(
        tok in blob for tok in ("cwe-78", "cwe-77", "cwe-94", "cwe-502", "cmdi", "command", "rce", "exec")
    )
    has_lfi_or_traversal = any(
        tok in blob for tok in ("cwe-22", "cwe-73", "cwe-200", "traversal", "lfi", "path", "shadow", "environ")
    )

    watched_binaries = ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget", "/bin/nc", "curl", "wget", "nc"]
    watched_files = [
        "/etc/shadow",
        "/proc/self/environ",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ]
    if has_lfi_or_traversal and "/etc/passwd" not in watched_files:
        watched_files.append("/etc/passwd")

    execve_action = "Sigkill" if has_cmdi_or_rce else "Post"
    file_action = "Sigkill" if has_lfi_or_traversal else "Post"

    tetragon_policy: dict[str, Any] = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": f"{clean_app}-ebpf-runtime-guard",
            "namespace": clean_ns,
            "annotations": {
                "sniper.io/cmdi-rce-guard-active": str(has_cmdi_or_rce).lower(),
                "sniper.io/lfi-traversal-guard-active": str(has_lfi_or_traversal).lower(),
                "sniper.io/finding-count": str(len(safe_findings)),
            },
        },
        "spec": {
            "podSelector": {
                "matchLabels": {
                    "app": clean_app,
                }
            },
            "kprobes": [
                {
                    "call": "sys_execve",
                    "syscall": True,
                    "args": [
                        {
                            "index": 0,
                            "type": "string",
                        }
                    ],
                    "selectors": [
                        {
                            "matchArgs": [
                                {
                                    "index": 0,
                                    "operator": "In",
                                    "values": watched_binaries,
                                }
                            ],
                            "matchActions": [
                                {
                                    "action": execve_action,
                                }
                            ],
                        }
                    ],
                },
                {
                    "call": "security_file_open",
                    "syscall": False,
                    "args": [
                        {
                            "index": 0,
                            "type": "file",
                        }
                    ],
                    "selectors": [
                        {
                            "matchArgs": [
                                {
                                    "index": 0,
                                    "operator": "Prefix",
                                    "values": watched_files,
                                }
                            ],
                            "matchActions": [
                                {
                                    "action": file_action,
                                }
                            ],
                        }
                    ],
                },
            ],
        },
    }

    return {
        "format": FORMAT,
        "namespace": clean_ns,
        "app_name": clean_app,
        "network_policy_count": len(netpols),
        "kubernetes_network_policies": netpols,
        "validating_admission_policy": admission_policy,
        "tetragon_ebpf_tracing_policy": tetragon_policy,
        "cel_expression_count": len(cel_rules),
    }
