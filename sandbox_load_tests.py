"""Yalıtılmış k6 ve Schemathesis çalıştırmaları (bkz. tool_sandbox.py, sandbox_targets.py).

Kullanıcıdan betik alınmaz: k6 sabit şablonla ve seçilen yük profiliyle (Hafif/Orta/Yoğun/Özel), Schemathesis yalnız
JSON OpenAPI şemasıyla çalışır. Hedef, Sniper içinden yönetilen listedeki tek hedeftir (127.0.0.1:port ya da
sahipliği doğrulanmış uzak alan:port); araç ağ ad alanında yalnız aktarıcıya ulaşır, yönlendirmeler izlenmez.
Sonuçlar mevcut rapor ayrıştırıcılarıyla özetlenir; ham çıktı ya da yanıt gövdesi döndürülmez.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import sandbox_targets
from tool_report_k6_summary import parse_k6_handle_summary_json
from tool_report_schemathesis_junit import parse_schemathesis_junit_summary
from tool_sandbox import SandboxExecutionError, check_authorized_target, check_target, read_output, run_job

PATH_RE = re.compile(r"/[A-Za-z0-9_.~/-]{0,200}\Z")
MAX_SCHEMA_BYTES = 512 * 1024
MAX_SCHEMA_NODES = 50_000
MAX_SCHEMA_DEPTH = 64

# Sabit k6 şablonu: yalnız ortamdaki doğrulanmış değerleri okur. handleSummary klasik özeti /out'a yazar.
K6_SCRIPT = b"""import http from 'k6/http';
import { check } from 'k6';

const TARGET = __ENV.SNIPER_TARGET;
const PATH = __ENV.SNIPER_PATH;
const METHOD = __ENV.SNIPER_METHOD;

export const options = {
  vus: Number(__ENV.SNIPER_VUS),
  duration: __ENV.SNIPER_DURATION + 's',
  maxRedirects: 0,
  discardResponseBodies: true,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)'],
  thresholds: { http_req_failed: ['rate<0.05'], http_req_duration: ['p(95)<2000'] },
};

export default function () {
  const url = TARGET + PATH;
  const res = METHOD === 'HEAD' ? http.head(url) : http.get(url);
  check(res, { 'durum 5xx degil': (r) => r.status > 0 && r.status < 500 });
}

export function handleSummary(data) {
  return { '/out/summary.json': JSON.stringify(data) };
}
"""
K6_SCRIPT_SHA256 = hashlib.sha256(K6_SCRIPT).hexdigest()


def _base_url(target: dict) -> str:
    return f"{target['scheme']}://{target['host']}:{target['port']}"


def _k6_params(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {"confirm", "target", "path", "method", "preset"}
    if not isinstance(payload, dict) or set(payload) - allowed or payload.get("confirm") is not True:
        raise ValueError("Onay (confirm: true) ve geçerli alanlar gerekli.")
    target = check_target("k6", payload.get("target"))
    path = payload.get("path", "/")
    if type(path) is not str or not PATH_RE.fullmatch(path) or "//" in path or "/../" in path + "/" \
            or "/./" in path + "/":
        raise ValueError("Geçersiz yol.")
    method = payload.get("method", "GET")
    if method not in ("GET", "HEAD"):
        raise ValueError("Yalnız GET veya HEAD.")
    preset = sandbox_targets.resolve_preset(payload.get("preset"), target)
    return {"target": target, "path": path, "method": method, "preset": preset}


def _read_k6(work) -> dict[str, Any]:
    raw = read_output(work, "summary.json", 2_000_000)
    if raw is None:
        raise SandboxExecutionError("k6_ozet_yok")
    return parse_k6_handle_summary_json(json.loads(raw))


def _relay_summary(outer: dict[str, Any]) -> dict[str, Any]:
    relay = outer.get("relay") or {}
    return {"connections": int(relay.get("connections", 0)), "refused": int(relay.get("refused", 0)),
            "bytes": int(relay.get("bytes", 0))}


def run_k6_sandbox(payload: object) -> dict[str, Any]:
    params = _k6_params(payload)  # type: ignore[arg-type]
    target, preset = params["target"], params["preset"]
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "K6_NO_USAGE_REPORT": "true",
           "SNIPER_TARGET": _base_url(target), "SNIPER_PATH": params["path"], "SNIPER_METHOD": params["method"],
           "SNIPER_VUS": str(preset["vus"]), "SNIPER_DURATION": str(preset["duration_s"])}
    argv = ["/opt/k6/k6", "run", "--quiet", "--no-color", "--no-usage-report", "--max-redirects", "0",
            "/job/script.js"]
    outer = run_job("k6", payload["target"], argv=argv, env=env,  # type: ignore[index]
                    timeout=preset["duration_s"] + 40, files={"script.js": K6_SCRIPT},
                    # Bağlantı başına tek istek yapan (keep-alive'sız) sunucular için süre ve VU ile ölçeklenir;
                    # toplam trafik ayrıca bayt sınırıyla bağlıdır.
                    max_connections=min(2_000_000, max(1000, preset["vus"] * preset["duration_s"] * 1000)),
                    max_bytes=512 * 1024 * 1024, reader=_read_k6)
    inner = outer.get("inner") or {}
    if outer.get("timed_out") or inner.get("timed_out"):
        raise SandboxExecutionError("sure_asildi")
    # k6 eşik başarısızlığında 99 döner; özet yine geçerlidir.
    if inner.get("exit_code") not in (0, 99):
        raise SandboxExecutionError("k6_basarisiz")
    return {"format": "k6-sandbox-v2", "status": "completed", "target": outer["target"], "preset": preset,
            "method": params["method"], "thresholds_ok": inner.get("exit_code") == 0,
            "script_sha256": K6_SCRIPT_SHA256, "relay": _relay_summary(outer), "summary": outer["parsed"]}


def _k6_authorized_params(payload: object) -> dict[str, Any]:
    allowed = {"confirm_authorized", "target", "path", "method", "preset"}
    if not isinstance(payload, dict) or set(payload) - allowed or payload.get("confirm_authorized") is not True:
        raise ValueError("confirm_authorized tam olarak true ve alanlar geçerli olmalı.")
    target = check_authorized_target("k6", payload.get("target"))
    path = payload.get("path", "/")
    if type(path) is not str or not PATH_RE.fullmatch(path) or "//" in path or "/../" in path + "/" \
            or "/./" in path + "/":
        raise ValueError("Geçersiz yol.")
    method = payload.get("method", "GET")
    if method not in ("GET", "HEAD"):
        raise ValueError("Yalnız GET veya HEAD.")
    # A free-form target is never silently assigned the larger registered-target
    # default.  The operator can still choose any configured bounded preset.
    preset = sandbox_targets.resolve_preset(payload.get("preset") or "hafif", target)
    return {"target": target, "path": path, "method": method, "preset": preset}


def run_k6_authorized(payload: object) -> dict[str, Any]:
    """Run k6 against one exact target approved for this invocation only."""
    params = _k6_authorized_params(payload)
    target, preset = params["target"], params["preset"]
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "K6_NO_USAGE_REPORT": "true",
           "SNIPER_TARGET": target["normalized"], "SNIPER_PATH": params["path"],
           "SNIPER_METHOD": params["method"], "SNIPER_VUS": str(preset["vus"]),
           "SNIPER_DURATION": str(preset["duration_s"])}
    argv = ["/opt/k6/k6", "run", "--quiet", "--no-color", "--no-usage-report", "--max-redirects", "0",
            "/job/script.js"]
    outer = run_job("k6", target["normalized"], argv=argv, env=env,
                    timeout=preset["duration_s"] + 40, files={"script.js": K6_SCRIPT},
                    max_connections=min(2_000_000, max(1000, preset["vus"] * preset["duration_s"] * 1000)),
                    max_bytes=512 * 1024 * 1024, reader=_read_k6, target_mode="authorized")
    inner = outer.get("inner") or {}
    if outer.get("timed_out") or inner.get("timed_out"):
        raise SandboxExecutionError("sure_asildi")
    if inner.get("exit_code") not in (0, 99):
        raise SandboxExecutionError("k6_basarisiz")
    return {"format": "k6-authorized-target-v1", "status": "completed",
            "normalized_target": target["normalized"], "target": outer["target"], "preset": preset,
            "method": params["method"], "thresholds_ok": inner.get("exit_code") == 0,
            "script_sha256": K6_SCRIPT_SHA256, "relay": _relay_summary(outer), "summary": outer["parsed"]}


# ---------------------------------------------------------------------------
# Schemathesis
# ---------------------------------------------------------------------------
def _walk_schema(value: Any, depth: int, budget: list[int]) -> None:
    budget[0] += 1
    if depth > MAX_SCHEMA_DEPTH or budget[0] > MAX_SCHEMA_NODES:
        raise ValueError("OpenAPI şeması çok büyük veya çok derin.")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("Geçersiz OpenAPI şeması.")
            if key == "$ref" and (not isinstance(child, str) or not child.startswith("#/")):
                raise ValueError("Yalnız şema içi ($ref: '#/…') başvurulara izin verilir.")
            _walk_schema(child, depth + 1, budget)
    elif isinstance(value, list):
        for child in value:
            _walk_schema(child, depth + 1, budget)
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ValueError("Geçersiz OpenAPI şeması.")


def validated_schema(schema: object) -> bytes:
    if not isinstance(schema, dict) or not isinstance(schema.get("paths"), dict):
        raise ValueError("Geçersiz OpenAPI şeması.")
    version = schema.get("openapi") or schema.get("swagger")
    if not isinstance(version, str) or not re.fullmatch(r"(3\.(0|1)\.[0-9]+|2\.0)", version):
        raise ValueError("Yalnız OpenAPI 3.0/3.1 veya Swagger 2.0.")
    _walk_schema(schema, 0, [0])
    cleaned = {k: v for k, v in schema.items() if k not in ("servers", "host", "basePath", "schemes")}
    try:
        raw = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Geçersiz OpenAPI şeması.") from exc
    if len(raw) > MAX_SCHEMA_BYTES:
        raise ValueError("OpenAPI şeması çok büyük.")
    return raw


def _st_params(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {"confirm", "target", "schema", "max_examples", "max_time_s"}
    if not isinstance(payload, dict) or set(payload) - allowed or payload.get("confirm") is not True:
        raise ValueError("Onay (confirm: true) ve geçerli alanlar gerekli.")
    target = check_target("schemathesis", payload.get("target"))
    limits = sandbox_targets.read_settings()["limits"]
    examples = payload.get("max_examples", min(10, limits["st_max_examples"]))
    max_time = payload.get("max_time_s", min(60, limits["st_max_time_s"]))
    if type(examples) is not int or not 1 <= examples <= limits["st_max_examples"]:
        raise ValueError(f"Örnek sayısı 1–{limits['st_max_examples']} olmalı.")
    if type(max_time) is not int or not 10 <= max_time <= limits["st_max_time_s"]:
        raise ValueError(f"Süre 10–{limits['st_max_time_s']} sn olmalı.")
    return {"target": target, "schema": validated_schema(payload.get("schema")), "examples": examples,
            "max_time": max_time}


def _junit_counts(raw: bytes) -> dict[str, Any]:
    """60 KB'ı aşan JUnit raporları için yalnız sayılar (aynı XML sertleştirmesiyle)."""
    from xml.parsers import expat
    counts = {"testcases": 0, "failures": 0, "errors": 0, "skipped": 0}
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def reject(*_args: object) -> None:
        raise ValueError("Geçersiz JUnit XML.")

    def start(name: str, _attrs: dict) -> None:
        key = {"testcase": "testcases", "failure": "failures", "error": "errors", "skipped": "skipped"}.get(name)
        if key:
            counts[key] += 1

    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.ProcessingInstructionHandler = reject
    parser.StartElementHandler = start
    parser.Parse(raw, True)
    return {"format": "schemathesis-junit-counts", **counts, "report_sha256": hashlib.sha256(raw).hexdigest()}


def _read_junit(work) -> dict[str, Any]:
    raw = read_output(work, "report.xml", 2_000_000)
    if raw is None:
        raise SandboxExecutionError("schemathesis_rapor_yok")
    if len(raw) <= 60_000:
        return parse_schemathesis_junit_summary(raw.decode("utf-8"))
    return _junit_counts(raw)


def run_schemathesis_sandbox(payload: object) -> dict[str, Any]:
    from tool_sandbox import schemathesis_venv
    params = _st_params(payload)  # type: ignore[arg-type]
    st = str(schemathesis_venv() / "bin" / "st")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1",
           "XDG_CACHE_HOME": "/tmp/cache", "HYPOTHESIS_STORAGE_DIRECTORY": "/tmp/hypothesis",
           "PYTHONDONTWRITEBYTECODE": "1"}
    argv = [st, "--config-file", "/job/schemathesis.toml", "--no-color", "run", "/job/schema.json",
            "--url", _base_url(params["target"]), "--workers", "1",
            "--phases", "examples,coverage,fuzzing", "--max-examples", str(params["examples"]),
            "--max-time", str(params["max_time"]), "--max-failures", "100", "--request-timeout", "5",
            "--request-retries", "0", "--max-redirects", "0", "--rate-limit", "20/s",
            "--report-junit-path", "/out/report.xml"]
    outer = run_job("schemathesis", payload["target"], argv=argv, env=env,  # type: ignore[index]
                    timeout=params["max_time"] + 40,
                    files={"schema.json": params["schema"], "schemathesis.toml": b""},
                    max_connections=20_000, max_bytes=256 * 1024 * 1024, reader=_read_junit)
    inner = outer.get("inner") or {}
    if outer.get("timed_out") or inner.get("timed_out"):
        raise SandboxExecutionError("sure_asildi")
    # Schemathesis bulgu bulduğunda 1 döner; rapor yine geçerlidir.
    if inner.get("exit_code") not in (0, 1):
        raise SandboxExecutionError("schemathesis_basarisiz")
    return {"format": "schemathesis-sandbox-v2", "status": "completed", "target": outer["target"],
            "issues_found": inner.get("exit_code") == 1, "schema_sha256": hashlib.sha256(params["schema"]).hexdigest(),
            "relay": _relay_summary(outer), "summary": outer["parsed"]}


def _schemathesis_authorized_params(payload: object) -> dict[str, Any]:
    allowed = {"confirm_authorized", "target", "schema", "max_examples", "max_time_s"}
    if not isinstance(payload, dict) or set(payload) - allowed or payload.get("confirm_authorized") is not True:
        raise ValueError("confirm_authorized tam olarak true ve alanlar geçerli olmalı.")
    target = check_authorized_target("schemathesis", payload.get("target"))
    limits = sandbox_targets.read_settings()["limits"]
    examples = payload.get("max_examples", min(10, limits["st_max_examples"]))
    max_time = payload.get("max_time_s", min(60, limits["st_max_time_s"]))
    if type(examples) is not int or not 1 <= examples <= limits["st_max_examples"]:
        raise ValueError(f"Örnek sayısı 1–{limits['st_max_examples']} olmalı.")
    if type(max_time) is not int or not 10 <= max_time <= limits["st_max_time_s"]:
        raise ValueError(f"Süre 10–{limits['st_max_time_s']} sn olmalı.")
    return {"target": target, "schema": validated_schema(payload.get("schema")), "examples": examples,
            "max_time": max_time}


def run_schemathesis_authorized(payload: object) -> dict[str, Any]:
    """Run Schemathesis against one exact target approved for this invocation."""
    from tool_sandbox import schemathesis_venv
    params = _schemathesis_authorized_params(payload)
    target = params["target"]
    st = str(schemathesis_venv() / "bin" / "st")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1",
           "XDG_CACHE_HOME": "/tmp/cache", "HYPOTHESIS_STORAGE_DIRECTORY": "/tmp/hypothesis",
           "PYTHONDONTWRITEBYTECODE": "1"}
    argv = [st, "--config-file", "/job/schemathesis.toml", "--no-color", "run", "/job/schema.json",
            "--url", target["normalized"], "--workers", "1", "--phases", "examples,coverage,fuzzing",
            "--max-examples", str(params["examples"]), "--max-time", str(params["max_time"]),
            "--max-failures", "100", "--request-timeout", "5", "--request-retries", "0",
            "--max-redirects", "0", "--rate-limit", "20/s", "--report-junit-path", "/out/report.xml"]
    outer = run_job("schemathesis", target["normalized"], argv=argv, env=env,
                    timeout=params["max_time"] + 40,
                    files={"schema.json": params["schema"], "schemathesis.toml": b""},
                    max_connections=20_000, max_bytes=256 * 1024 * 1024,
                    reader=_read_junit, target_mode="authorized")
    inner = outer.get("inner") or {}
    if outer.get("timed_out") or inner.get("timed_out"):
        raise SandboxExecutionError("sure_asildi")
    if inner.get("exit_code") not in (0, 1):
        raise SandboxExecutionError("schemathesis_basarisiz")
    return {"format": "schemathesis-authorized-target-v1", "status": "completed",
            "normalized_target": target["normalized"], "target": outer["target"],
            "issues_found": inner.get("exit_code") == 1,
            "schema_sha256": hashlib.sha256(params["schema"]).hexdigest(), "relay": _relay_summary(outer),
            "summary": outer["parsed"]}
