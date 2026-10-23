"""Small dependency-free Prometheus exporter for the local Sniper service."""

from __future__ import annotations

from collections import Counter
import threading
import time
from urllib.parse import urlsplit
import json


BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

# Etiket kardinalitesi sınırları: istemci kontrolündeki HTTP metodu ve yol
# serbest etiket olamaz; aksi halde rastgele yollar sınırsız seri üretir.
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
OTHER_METHOD = "OTHER"
OTHER_ROUTE = "/:other"
STATIC_ROUTE = "/:static"
MAX_ROUTE_DEPTH = 4
# Ayrı rota etiketi sayısının sabit üst sınırı; aşılırsa yeni rotalar OTHER_ROUTE olur.
MAX_ROUTE_LABELS = 256
STATIC_SUFFIXES = (".html", ".js", ".mjs", ".css", ".map", ".ico", ".svg", ".png", ".woff", ".woff2", ".txt", ".json")

# server.py'deki /api/<kaynak> önekleri (izin listesi). Listede olmayan kaynak "/api/:other" olur.
API_RESOURCES = frozenset({
    "ai-llm-security", "attack-paths", "audit-log", "audit-logging", "auth-protocol", "blue-team",
    "browser-extension-pwa", "business-logic", "cloud-iam-security", "crypto-cbom-pqc", "cvss-ssvc",
    "dashboard", "database-security", "dependency-security", "desktop-security", "dos-resilience",
    "engagements", "health", "host-hardening", "lab-runs", "methodology", "mobile-security", "nmap",
    "nuclei", "openapi-security", "plugins", "privacy-dataflow", "project-audits",
    "protocol-security", "quality-gate", "remediation", "reports", "scans", "secret-intelligence",
    "supply-chain-slsa", "targets", "threat-model", "tool-plans", "tool-reports", "tool-runs",
    "tooling", "tools", "web-infra", "web3-iot-security", "zap", "zero-trust-mesh",
})

# /api/<kaynak>/... altindaki sabit (kimlik olmayan) yol parcalari; digerleri ':id' olur.
ROUTE_SEGMENTS = frozenset({
    "active", "af-plan-preview", "audit", "audit-manifest", "audit-package", "audit-project",
    "auto-patch", "autodiscover", "batch-summary", "boundary-contract", "boundary-verify",
    "bundle-manifest", "burp", "burp-logger-csv", "burp-sitemap", "cache-contract", "cached-query",
    "cargo-lock", "correlate", "db-freshness", "dependabot", "dependencies",
    "dependency-remediation-plan", "diff", "discovery-audit", "dns-email-audit", "enable-builtins",
    "evaluate", "executive-pentest", "generate", "git-history", "gitleaks", "gitleaks-git-history",
    "go-mod", "handoff-manifest", "handoff-profile", "http-scans", "import", "k6", "k6-loopback",
    "k6-loopback-smoke", "k6-machine-summary-v1", "k6-summary-json", "live", "local-fixture",
    "loopback", "maven-pom", "nmap", "npm-audit", "npm-audit-local", "nuclei", "nuclei-jsonl",
    "nuclei-loopback", "offline-sync", "openssl-x509", "openssl-x509-loopback", "osv-scanner-local",
    "playwright", "playwright-json", "playwright-local-fixture", "pnpm-lock", "prepare", "preview",
    "prioritize", "rate-state", "reachability", "readiness", "remediation-plan", "report.csv",
    "report.html", "report.json", "ruby-gemfile-lock", "rulepack-inventory", "sarif", "sbom",
    "schemathesis-junit", "schemathesis-local", "schemathesis-loopback", "secret-bundle",
    "selected-path-scope", "selected-path-spider", "semgrep", "semgrep-native-json",
    "service-fingerprint", "siem-ecs-ndjson", "site-active", "ssllabs", "ssllabs-cached-query",
    "ssllabs-host", "ssllabs-live", "ssllabs-rate-state", "summary", "sync", "synthesize-rules",
    "tcp-scan", "tcp-service-fingerprint", "terraform-batch", "testssl", "testssl-full",
    "testssl-protocols", "tls-trivy", "tls-verify-filter", "trivy", "trivy-cargo-lock",
    "trivy-cargo-lock-vulnerability", "trivy-dockerfile-config", "trivy-go-mod",
    "trivy-go-mod-vulnerability", "trivy-image-archive-vulnerability", "trivy-kubernetes-config",
    "trivy-kubernetes-config-batch", "trivy-maven-pom", "trivy-maven-vulnerability",
    "trivy-native-json", "trivy-npm-vulnerability", "trivy-pnpm-lock", "trivy-pnpm-vulnerability",
    "trivy-ruby-gemfile-lock", "trivy-ruby-vulnerability", "trivy-secret", "trivy-terraform-config",
    "trivy-terraform-config-batch", "trivy-vulnerability", "trivy-yarn-lock",
    "trivy-yarn-vulnerability", "trufflehog", "trufflehog-filesystem", "trufflehog-git-history",
    "validate", "verification-contract", "verification-coverage", "verify", "yarn-lock", "zap",
    "zap-af", "zap-self-passive", "zap-site-active", "zap-target-active", "zap-target-spider",
    "zap-target-spider-scope",
})


def _method(method: str) -> str:
    normalized = str(method or "").upper()
    return normalized if normalized in ALLOWED_METHODS else OTHER_METHOD


def _status(status: int) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "0"
    return str(code) if 100 <= code <= 599 else "0"


def _route(path: str) -> str:
    try:
        parts = [part for part in urlsplit(path).path.split("/") if part]
    except ValueError:
        return "/:invalid"
    if not parts:
        return "/"
    head = parts[0]
    if head != "api":
        if len(parts) == 1 and head == "metrics":
            return "/metrics"
        if len(parts) == 1 and head.lower().endswith(STATIC_SUFFIXES):
            return STATIC_ROUTE
        return OTHER_ROUTE
    if len(parts) == 1:
        return "/api"
    resource = parts[1]
    if resource not in API_RESOURCES:
        return "/api/:other"
    safe = ["api", resource]
    for part in parts[2:MAX_ROUTE_DEPTH]:
        safe.append(part if part in ROUTE_SEGMENTS else ":id")
    return "/" + "/".join(safe)


class Metrics:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.requests: Counter[tuple[str, str, str]] = Counter()
        self.duration_count: Counter[tuple[str, str]] = Counter()
        self.duration_sum: Counter[tuple[str, str]] = Counter()
        self.duration_buckets: Counter[tuple[str, str, float]] = Counter()
        self.scan_results: Counter[str] = Counter()
        self._routes: set[str] = set()
        self._lock = threading.Lock()

    def observe_request(self, method: str, path: str, status: int, duration: float) -> None:
        method = _method(method)
        route = _route(path)
        status_label = _status(status)
        with self._lock:
            if route not in self._routes:
                if len(self._routes) >= MAX_ROUTE_LABELS:
                    route = OTHER_ROUTE
                else:
                    self._routes.add(route)
            self.requests[(method, route, status_label)] += 1
            self.duration_count[(method, route)] += 1
            self.duration_sum[(method, route)] += max(0.0, duration)
            for bucket in BUCKETS:
                if duration <= bucket:
                    self.duration_buckets[(method, route, bucket)] += 1

    def record_scan(self, status: str) -> None:
        with self._lock:
            self.scan_results[status[:20]] += 1

    def render(self, *, active_scans: int, loaded_plugins: int, posture: dict | None = None) -> str:
        lines = [
            "# HELP sniper_uptime_seconds Sniper process uptime.",
            "# TYPE sniper_uptime_seconds gauge",
            f"sniper_uptime_seconds {time.monotonic() - self.started:.3f}",
            "# HELP sniper_scans_active Currently active baseline scans.",
            "# TYPE sniper_scans_active gauge",
            f"sniper_scans_active {max(0, active_scans)}",
            "# HELP sniper_plugins_loaded Loaded trusted local plugins.",
            "# TYPE sniper_plugins_loaded gauge",
            f"sniper_plugins_loaded {max(0, loaded_plugins)}",
            "# HELP sniper_http_requests_total HTTP responses by method, route and status.",
            "# TYPE sniper_http_requests_total counter",
        ]
        with self._lock:
            requests = list(self.requests.items())
            counts = list(self.duration_count.items())
            sums = dict(self.duration_sum)
            bucket_values = dict(self.duration_buckets)
            scans = list(self.scan_results.items())
        for (method, route, status), value in sorted(requests):
            route_str = json.dumps(route, ensure_ascii=False)
            method_str = json.dumps(method, ensure_ascii=False)
            lines.append(f'sniper_http_requests_total{{method={method_str},route={route_str},status="{status}"}} {value}')
        lines.extend([
            "# HELP sniper_http_request_duration_seconds HTTP response duration.",
            "# TYPE sniper_http_request_duration_seconds histogram",
        ])
        for (method, route), count in sorted(counts):
            route_str = json.dumps(route, ensure_ascii=False)
            method_str = json.dumps(method, ensure_ascii=False)
            labels = f'method={method_str},route={route_str}'
            for bucket in BUCKETS:
                value = bucket_values.get((method, route, bucket), 0)
                lines.append(f'sniper_http_request_duration_seconds_bucket{{{labels},le="{bucket:g}"}} {value}')
            lines.append(f'sniper_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} {count}')
            lines.append(f'sniper_http_request_duration_seconds_sum{{{labels}}} {sums.get((method, route), 0.0):.6f}')
            lines.append(f'sniper_http_request_duration_seconds_count{{{labels}}} {count}')
        lines.extend(["# HELP sniper_scans_total Completed and failed scans.", "# TYPE sniper_scans_total counter"])
        for status, value in sorted(scans):
            lines.append(f'sniper_scans_total{{status="{status}"}} {value}')
        if isinstance(posture, dict):
            targets_total = max(0, int(posture.get("targets_total", posture.get("target_count", 0)) or 0))
            project_audits_total = max(
                0, int(posture.get("project_audits_total", posture.get("project_audit_count", 0)) or 0)
            )
            open_dep_total = max(
                0,
                int(
                    posture.get(
                        "open_dependency_findings",
                        posture.get("open_dependency_findings_total", posture.get("dependency_finding_count", 0)),
                    )
                    or 0
                ),
            )
            lines.extend([
                "# HELP sniper_targets_total Total registered scan targets.",
                "# TYPE sniper_targets_total gauge",
                f"sniper_targets_total {targets_total}",
                "# HELP sniper_project_audits_total Total completed local project security audits.",
                "# TYPE sniper_project_audits_total gauge",
                f"sniper_project_audits_total {project_audits_total}",
                "# HELP sniper_open_dependency_findings_total Currently active dependency security findings.",
                "# TYPE sniper_open_dependency_findings_total gauge",
                f"sniper_open_dependency_findings_total {open_dep_total}",
            ])
        return "\n".join(lines) + "\n"

