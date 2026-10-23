"""Offline, deterministic OWASP ZAP Automation Framework plan builder.

The output plan uses JSON syntax, which is a YAML 1.2 subset. No scanner is
started and no network operation is performed by this module.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit


class PlanError(ValueError):
    """Input cannot be represented as a safe, bounded scope plan."""


# Reserve time for AF setup, job transitions, and final bookkeeping.
_PLAN_MARGIN_SECONDS = 300


@dataclass(frozen=True, slots=True)
class ScanSettings:
    plan_max_duration_seconds: int = 2400
    spider_max_duration_minutes: int = 10
    passive_wait_max_duration_minutes: int = 5
    active_scan_max_duration_minutes: int = 15
    max_rule_duration_minutes: int = 3
    thread_per_host: int = 2
    delay_in_ms: int = 100
    max_alerts_per_rule: int = 20

    def __post_init__(self) -> None:
        limits = {
            "plan_max_duration_seconds": (self.plan_max_duration_seconds, 60, 7200),
            "spider_max_duration_minutes": (self.spider_max_duration_minutes, 1, 60),
            "passive_wait_max_duration_minutes": (self.passive_wait_max_duration_minutes, 1, 60),
            "active_scan_max_duration_minutes": (self.active_scan_max_duration_minutes, 1, 120),
            "max_rule_duration_minutes": (self.max_rule_duration_minutes, 1, 30),
            "thread_per_host": (self.thread_per_host, 1, 4),
            "delay_in_ms": (self.delay_in_ms, 0, 5000),
            "max_alerts_per_rule": (self.max_alerts_per_rule, 1, 100),
        }
        for name, (value, low, high) in limits.items():
            if type(value) is not int or not low <= value <= high:
                raise PlanError(f"{name} [{low}, {high}] aralığında bir tamsayı olmalı")
        if self.max_rule_duration_minutes > self.active_scan_max_duration_minutes:
            raise PlanError("max_rule_duration_minutes, active_scan_max_duration_minutes değerini aşamaz")
        required_seconds = 60 * (
            self.spider_max_duration_minutes
            + 2 * self.passive_wait_max_duration_minutes
            + self.active_scan_max_duration_minutes
        ) + _PLAN_MARGIN_SECONDS
        if self.plan_max_duration_seconds < required_seconds:
            raise PlanError(
                "plan_max_duration_seconds sıralı örümceği, iki pasif beklemeyi, "
                f"aktif taramayı ve {_PLAN_MARGIN_SECONDS} sn payı kapsamalı (en az {required_seconds} sn)"
            )


@dataclass(frozen=True, slots=True)
class PassiveScanSettings:
    # Spider plus two passive waits, with a fixed transition/bookkeeping margin.
    plan_max_duration_seconds: int = 1500
    spider_max_duration_minutes: int = 10
    passive_wait_max_duration_minutes: int = 5

    def __post_init__(self) -> None:
        limits = {
            "plan_max_duration_seconds": (self.plan_max_duration_seconds, 60, 7200),
            "spider_max_duration_minutes": (self.spider_max_duration_minutes, 1, 60),
            "passive_wait_max_duration_minutes": (self.passive_wait_max_duration_minutes, 1, 60),
        }
        for name, (value, low, high) in limits.items():
            if type(value) is not int or not low <= value <= high:
                raise PlanError(f"{name} [{low}, {high}] aralığında bir tamsayı olmalı")
        required_seconds = 60 * (
            self.spider_max_duration_minutes + 2 * self.passive_wait_max_duration_minutes
        ) + _PLAN_MARGIN_SECONDS
        if self.plan_max_duration_seconds < required_seconds:
            raise PlanError(
                "pasif plan_max_duration_seconds sıralı örümceği, "
                f"iki pasif beklemeyi ve {_PLAN_MARGIN_SECONDS} sn payı kapsamalı (en az {required_seconds} sn)"
            )


@dataclass(frozen=True, slots=True)
class PlanArtifact:
    plan_yaml: str
    scope_receipt_json: str


_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@-]+\Z")
_AUTH_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/# -]{0,159}\Z")


def _has_control_or_space(value: str) -> bool:
    return any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)


def _canonical_origin(origin: str) -> str:
    if not isinstance(origin, str) or not origin or len(origin) > 512:
        raise PlanError("authorized_origin en fazla 512 karakterlik boş olmayan bir URL olmalı")
    if _has_control_or_space(origin) or "?" in origin or "#" in origin or "%" in origin:
        raise PlanError("köken boşluk, denetim karakteri, sorgu, parça veya yüzde kodlaması içeriyor")
    try:
        parsed = urlsplit(origin)
        if parsed.scheme.lower() != "https":
            raise PlanError("yalnız HTTPS kökenleri kabul edilir")
        if not parsed.netloc or parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise PlanError("köken bir ana makine içermeli ve kimlik bilgisi içermemeli")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise PlanError("authorized_origin kök olmayan yol, sorgu veya parça içermemeli")
        if parsed.netloc.endswith(":"):
            raise PlanError("boş port geçersiz")
        host = parsed.hostname
        if not host:
            raise PlanError("köken ana makinesi eksik")
        if "%" in host or host.endswith("."):
            raise PlanError("bölge tanımlayıcıları ve sonu noktalı ana makine adları kabul edilmez")

        explicit_port = parsed.port  # raises on malformed/out-of-range ports
        if explicit_port is not None and not 1 <= explicit_port <= 65535:
            raise PlanError("port [1, 65535] aralığında olmalı")

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                ascii_host = host.encode("idna").decode("ascii").lower()
            except UnicodeError as error:
                raise PlanError("geçersiz uluslararasılaştırılmış ana makine adı") from error
            if all(char in "0123456789." for char in ascii_host):
                raise PlanError("kanonik olmayan sayısal ana makine belirsizdir")
            if len(ascii_host) > 253 or not all(_HOST_LABEL.fullmatch(label) for label in ascii_host.split(".")):
                raise PlanError("geçersiz DNS ana makine adı")
            rendered_host = ascii_host
        else:
            rendered_host = f"[{address.compressed}]" if address.version == 6 else address.compressed

        port_suffix = "" if explicit_port in (None, 443) else f":{explicit_port}"
        return f"https://{rendered_host}{port_suffix}"
    except PlanError:
        raise
    except (ValueError, UnicodeError) as error:
        raise PlanError("geçersiz HTTPS kökeni") from error


def _canonical_path(path: str) -> str:
    if not isinstance(path, str) or not path or len(path) > 512:
        raise PlanError("selected_path en fazla 512 karakterlik boş olmayan bir yol olmalı")
    if not path.startswith("/") or path.startswith("//"):
        raise PlanError("selected_path tam olarak bir baştaki eğik çizgiyle mutlak bir yol olmalı")
    if path != "/" and path.endswith("/"):
        raise PlanError("selected_path kanonik olmalı ve sondaki eğik çizgiyi içermemeli")
    if _has_control_or_space(path) or any(char in path for char in "?#%\\"):
        raise PlanError("selected_path boşluk, denetim karakteri, sorgu, parça, yüzde kodlaması veya ters eğik çizgi içeriyor")
    if len(path) > 1:
        segments = path[1:].split("/")
        if any(not segment for segment in segments):
            raise PlanError("boş yol bölümleri belirsizdir")
        for segment in segments:
            if segment in (".", ".."):
                raise PlanError("nokta bölümleri kabul edilmez")
            if not _PATH_SEGMENT.fullmatch(segment):
                raise PlanError("selected_path kabul edilen ASCII yol kümesi dışında karakterler içeriyor")
    return path


def _escape_regex_literal(value: str) -> str:
    # Only escapes characters special in Java/Python regular-expression syntax.
    return re.sub(r"([\\.^$|?*+(){}\[\]])", r"\\\1", value)


def _scope_patterns(origin: str, path: str) -> tuple[str, str]:
    escaped_origin = _escape_regex_literal(origin)
    segment = r"(?!\.{1,2}(?:/|\?|\Z))[^/?#%\\]+"
    if path == "/":
        # Root itself plus non-empty safe descendant segments.
        include = rf"\A{escaped_origin}/(?:{segment}(?:/{segment})*/?)?(?:\?[^#]*)?\Z"
    else:
        escaped_path = _escape_regex_literal(path)
        include = rf"\A{escaped_origin}{escaped_path}(?:/{segment})*/?(?:\?[^#]*)?\Z"

    # Defense-in-depth exclusions, scoped to this origin. The include pattern
    # already rejects '%' in path and literal dot-segment descendants.
    exclude = rf"\A{escaped_origin}/(?:[^?#]*[%\\\\][^?#]*|(?:[^/?#]+/)*\.{{1,2}}(?:/[^?#]*)?)(?:\?[^#]*)?\Z"
    try:
        re.compile(include)
        re.compile(exclude)
    except re.error as error:
        raise PlanError("üretilen kapsam ifadesi yerel regex doğrulamasından geçemedi") from error
    return include, exclude


def _validate_authorization(
    authorization_input: Mapping[str, Any], canonical_origin: str, canonical_path: str,
    mode: str,
) -> dict[str, Any]:
    if not isinstance(authorization_input, Mapping):
        raise PlanError("authorization_input bir eşleme olmalı")
    permission_key = "crawl_permitted" if mode == "PASSIVE_ONLY" else "active_scan_permitted"
    required = {"authorized_origin", "authorized_path", "authorization_reference", permission_key}
    if set(authorization_input) != required:
        raise PlanError(f"authorization_input tam olarak {sorted(required)} içermeli")
    auth_origin = _canonical_origin(authorization_input["authorized_origin"])
    auth_path = _canonical_path(authorization_input["authorized_path"])
    if auth_origin != canonical_origin or auth_path != canonical_path:
        raise PlanError("yetki girdisi kanonik köken ve seçilen yolla birebir eşleşmeli")
    reference = authorization_input["authorization_reference"]
    if not isinstance(reference, str) or not _AUTH_REFERENCE.fullmatch(reference):
        raise PlanError("authorization_reference 1-160 güvenli karakterden oluşan, sır olmayan bir başvuru olmalı")
    if authorization_input[permission_key] is not True:
        raise PlanError(f"açık {permission_key}=true gerekli")
    return {
        "authorized_origin": authorization_input["authorized_origin"],
        "authorized_path": authorization_input["authorized_path"],
        "canonical_authorized_origin": auth_origin,
        "canonical_authorized_path": auth_path,
        "authorization_reference": reference,
        permission_key: True,
    }


def build_scoped_plan(
    *,
    authorized_origin: str,
    selected_path: str,
    authorization_input: Mapping[str, Any],
    settings: ScanSettings | PassiveScanSettings | None = None,
    mode: str = "ACTIVE_ROOT",
) -> PlanArtifact:
    """Return deterministic AF JSON-subset YAML and a machine-readable receipt.

    This function is pure: it performs no DNS lookup, file write, scanner launch,
    or network operation.
    """
    if mode not in ("ACTIVE_ROOT", "PASSIVE_ONLY"):
        raise PlanError("mode ACTIVE_ROOT veya PASSIVE_ONLY olmalı")
    origin = _canonical_origin(authorized_origin)
    path = _canonical_path(selected_path)
    auth = _validate_authorization(authorization_input, origin, path, mode)
    # The synthetic active trial reached outside /app; the passive-only
    # control did not, but one small control is not a universal containment
    # proof. The ACTIVE_ROOT branch retains v3's strict root-only rule.
    if mode == "ACTIVE_ROOT" and path != "/":
        raise PlanError(
            "birleşik aktif AF planı selected_path='/' gerektirir; sentetik ZAP 2.17 aktif taraması kök olmayan seçili yolun dışına çıktı"
        )
    if mode == "ACTIVE_ROOT":
        limits = settings if settings is not None else ScanSettings()
        if not isinstance(limits, ScanSettings):
            raise PlanError("ACTIVE_ROOT ayarları bir ScanSettings örneği olmalı")
    else:
        limits = settings if settings is not None else PassiveScanSettings()
        if not isinstance(limits, PassiveScanSettings):
            raise PlanError("PASSIVE_ONLY ayarları bir PassiveScanSettings örneği olmalı")

    selected_url = origin + ("" if path == "/" else path) + ("/" if path == "/" else "")
    include_regex, exclude_regex = _scope_patterns(origin, path)
    context_digest = hashlib.sha256(f"{origin}\n{path}".encode("utf-8")).hexdigest()[:12]
    context_name = f"sniper-authorized-{context_digest}"

    jobs = [
        {
            "type": "spider",
            "parameters": {
                "context": context_name,
                "url": selected_url,
                "maxDuration": limits.spider_max_duration_minutes,
                "postForm": False,
                "processForm": False,
                "logoutAvoidance": True,
            },
        },
        {
            "type": "passiveScan-wait",
            "parameters": {"maxDuration": limits.passive_wait_max_duration_minutes},
        },
    ]
    if mode == "ACTIVE_ROOT":
        jobs.append({
            "type": "activeScan",
            "parameters": {
                "context": context_name,
                "url": selected_url,
                "maxScanDurationInMins": limits.active_scan_max_duration_minutes,
                "maxRuleDurationInMins": limits.max_rule_duration_minutes,
                "threadPerHost": limits.thread_per_host,
                "delayInMs": limits.delay_in_ms,
                "maxAlertsPerRule": limits.max_alerts_per_rule,
            },
        })
    jobs.append({
        "type": "passiveScan-wait",
        "parameters": {"maxDuration": limits.passive_wait_max_duration_minutes},
    })
    plan = {
        "env": {
            "contexts": [
                {
                    "name": context_name,
                    "urls": [selected_url],
                    "includePaths": [include_regex],
                    "excludePaths": [exclude_regex],
                }
            ],
            "parameters": {
                "failOnError": True,
                "failOnWarning": True,
                "continueOnFailure": False,
                "progressToStdout": True,
                "maxDuration": limits.plan_max_duration_seconds,
            },
        },
        "jobs": jobs,
    }
    receipt = {
        "schema": "sniper.zap.scope-receipt.v1" if mode == "ACTIVE_ROOT" else "sniper.zap.scope-receipt.v2",
        "plan_only": True,
        **({"mode": "PASSIVE_ONLY"} if mode == "PASSIVE_ONLY" else {}),
        "authorization_input": auth,
        "scope": {
            "origin": origin,
            "selected_path": path,
            "selected_url": selected_url,
            "context_name": context_name,
            "include_regex": include_regex,
            "exclude_regex": exclude_regex,
        },
        "jobs": [
            {"index": index, "type": job["type"], "context": job.get("parameters", {}).get("context"), "url": job.get("parameters", {}).get("url")}
            for index, job in enumerate(jobs)
        ],
        "settings": asdict(limits),
        "limitations": [
            "Plan generation only; no ZAP import or execution was performed.",
            "AF context includePaths did not contain activeScan to a selected non-root path in a synthetic ZAP 2.17 trial; this builder rejects such plans.",
            "Root-path selection covers the origin path space and does not prove DNS, redirect, or OS-level egress containment.",
            "CONNECT-only egress controls cannot inspect encrypted HTTP Host, path, or redirects.",
            "Finite regex vectors and one synthetic ZAP 2.17 AF run do not establish general scanner scope or live safety.",
        ] if mode == "ACTIVE_ROOT" else [
            "PASSIVE_ONLY plan generation only; this candidate did not launch ZAP.",
            "One Docker --internal ZAP 2.17 passive-only /app trial made 4 requests and 0 outside the selected subtree; this is not a general path-containment proof.",
            "The plan contains spider and passive waits only; traditional spider GETs may still have application side effects.",
            "No DNS, redirect, host, or OS-level egress containment is established for live use.",
        ],
    }
    return PlanArtifact(
        plan_yaml=json.dumps(plan, ensure_ascii=False, indent=2) + "\n",
        scope_receipt_json=json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
