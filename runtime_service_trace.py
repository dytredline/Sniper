"""Annotate static service edges with bounded, local observed-runtime evidence.

The input is an optional exact-name manifest in a selected repository root.  The
manifest is never executed and its operation strings, timestamps, nonces, and
integrity values are never copied to output.  A SHA-256 integrity value detects
accidental or stale-content mismatch; it is deliberately not treated as an
authenticity signature.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterable


FORMAT = "sniper-runtime-service-trace/1"
MANIFEST_NAME = "sniper-runtime-service-trace.json"
MAX_REPOSITORIES = 300
MAX_MANIFEST_BYTES = 256_000
MAX_OBSERVATIONS_PER_MANIFEST = 128
MAX_TOTAL_OBSERVATIONS = 4_096
MAX_EVENT_COUNT = 1_000_000

_MANIFEST_KEYS = frozenset({
    "format", "repository", "generated_at", "nonce", "observations", "integrity_sha256",
})
_OBSERVATION_KEYS = frozenset({
    "source_repository", "target_repository", "protocol", "operation", "event_count",
})
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/\-]{0,159}\Z")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_HTTP_OPERATION_RE = re.compile(
    r"(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD) /[^\s?#]{0,2047}\Z",
)
_KAFKA_OPERATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,248}\Z")
_GRAPHQL_OPERATION_RE = re.compile(
    r"(?:query|mutation|subscription) [_A-Za-z][_0-9A-Za-z]{0,127}\Z",
)


@dataclass(frozen=True)
class _Observation:
    source: str
    target: str
    protocol: str
    operation: str
    event_count: int

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.source, self.target, self.protocol, self.operation


def _safe_repository(value: object) -> str | None:
    if not isinstance(value, str) or not _REPOSITORY_RE.fullmatch(value):
        return None
    if value.startswith("/") or value.endswith("/") or "//" in value:
        return None
    if any(part in {"", ".", ".."} for part in value.split("/")):
        return None
    return value


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        return False
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _valid_operation(protocol: str, operation: str) -> bool:
    if not 1 <= len(operation) <= 2_048 or "://" in operation:
        return False
    if protocol in {"http", "webhook-http"}:
        return _HTTP_OPERATION_RE.fullmatch(operation) is not None
    if protocol == "kafka":
        return _KAFKA_OPERATION_RE.fullmatch(operation) is not None
    if protocol == "graphql":
        return _GRAPHQL_OPERATION_RE.fullmatch(operation) is not None
    return False


def _canonical_payload(document: dict) -> bytes:
    payload = {key: value for key, value in document.items() if key != "integrity_sha256"}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    document: dict = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _read_manifest(path: Path) -> str | None:
    """Read one regular file without following a final-component symlink where supported."""
    descriptor: int | None = None
    try:
        if path.is_symlink():
            return None
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANIFEST_BYTES:
            return None
        chunks: list[bytes] = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_MANIFEST_BYTES:
            return None
        return raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _parse_manifest(
    path: Path,
    expected_repository: str,
    repositories: frozenset[str],
) -> tuple[list[_Observation], str] | None:
    try:
        text = _read_manifest(path)
        if text is None:
            return None
        document = json.loads(text, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError):
        return None
    if not isinstance(document, dict) or frozenset(document) != _MANIFEST_KEYS:
        return None
    repository = _safe_repository(document.get("repository"))
    generated_at = document.get("generated_at")
    nonce = document.get("nonce")
    integrity = document.get("integrity_sha256")
    raw_observations = document.get("observations")
    if (
        document.get("format") != FORMAT
        or repository != expected_repository
        or repository not in repositories
        or not _valid_timestamp(generated_at)
        or not isinstance(nonce, str)
        or _NONCE_RE.fullmatch(nonce) is None
        or not isinstance(integrity, str)
        or _SHA256_RE.fullmatch(integrity) is None
        or not isinstance(raw_observations, list)
        or not 1 <= len(raw_observations) <= MAX_OBSERVATIONS_PER_MANIFEST
    ):
        return None
    calculated = hashlib.sha256(_canonical_payload(document)).hexdigest()
    if not hmac.compare_digest(integrity, calculated):
        return None

    observations: list[_Observation] = []
    seen: set[tuple[str, str, str, str]] = set()
    for raw in raw_observations:
        if not isinstance(raw, dict) or frozenset(raw) != _OBSERVATION_KEYS:
            return None
        source = _safe_repository(raw.get("source_repository"))
        target = _safe_repository(raw.get("target_repository"))
        protocol = raw.get("protocol")
        operation = raw.get("operation")
        event_count = raw.get("event_count")
        if (
            source != repository
            or target not in repositories
            or target == source
            or not isinstance(protocol, str)
            or not isinstance(operation, str)
            or not _valid_operation(protocol, operation)
            or type(event_count) is not int
            or not 1 <= event_count <= MAX_EVENT_COUNT
        ):
            return None
        observation = _Observation(source, target, protocol, operation, event_count)
        if observation.key in seen:
            return None
        seen.add(observation.key)
        observations.append(observation)
    return observations, nonce


def _manifest_present(path: Path) -> bool:
    try:
        return path.is_symlink() or path.exists()
    except OSError:
        return False


def _local_repository(root: Path) -> bool:
    try:
        return not root.is_symlink() and root.is_dir()
    except OSError:
        return False


def _load_observations(
    repositories: Iterable[tuple[str, Path]],
) -> tuple[list[_Observation], int, int, bool]:
    candidates: list[tuple[str, Path]] = []
    truncated = False
    for raw_name, raw_root in repositories:
        if len(candidates) >= MAX_REPOSITORIES:
            truncated = True
            break
        candidates.append((str(raw_name), Path(raw_root)))

    valid_names = frozenset(
        name for name, root in candidates
        if _safe_repository(name) == name and _local_repository(root)
    )
    observations: list[_Observation] = []
    accepted = 0
    rejected = 0
    nonces: set[str] = set()
    seen_names: set[str] = set()
    for name, root in candidates:
        manifest = root / MANIFEST_NAME
        if not _manifest_present(manifest):
            continue
        if name in seen_names or name not in valid_names:
            rejected += 1
            continue
        seen_names.add(name)
        parsed = _parse_manifest(manifest, name, valid_names)
        if parsed is None:
            rejected += 1
            continue
        repo_observations, nonce = parsed
        if nonce in nonces or len(observations) + len(repo_observations) > MAX_TOTAL_OBSERVATIONS:
            rejected += 1
            truncated = truncated or len(observations) + len(repo_observations) > MAX_TOTAL_OBSERVATIONS
            continue
        nonces.add(nonce)
        observations.extend(repo_observations)
        accepted += 1
    return observations, accepted, rejected, truncated


def _repo_reference(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("repo:"):
        return None
    return _safe_repository(value[5:])


def _edge_key(graph_name: str, edge: dict) -> tuple[str, str, str, str] | None:
    if graph_name == "service_graph":
        source = _repo_reference(edge.get("consumer"))
        target = _repo_reference(edge.get("producer"))
        protocol = edge.get("protocol")
        operation = edge.get("operation")
    elif graph_name == "webhook_graph":
        source = _repo_reference(edge.get("producer"))
        target = _repo_reference(edge.get("receiver"))
        protocol = edge.get("protocol")
        operation = edge.get("operation")
    elif graph_name == "message_graph":
        source = _repo_reference(edge.get("publisher"))
        target = _repo_reference(edge.get("consumer"))
        protocol = edge.get("broker")
        operation = edge.get("channel")
    elif graph_name == "graphql_service_graph":
        source = _safe_repository(edge.get("consumer_repo"))
        target = _safe_repository(edge.get("producer_repo"))
        operation_type = edge.get("operation_type")
        root_field = edge.get("root_field")
        protocol = "graphql"
        operation = f"{operation_type} {root_field}" if isinstance(operation_type, str) \
            and isinstance(root_field, str) else None
    else:
        return None
    if (
        source is None
        or target is None
        or not isinstance(protocol, str)
        or not isinstance(operation, str)
        or not _valid_operation(protocol, operation)
    ):
        return None
    return source, target, protocol, operation


def empty_summary(status: str = "evaluated") -> dict:
    """Return a redacted, stable summary for absent or unavailable trace evidence."""
    return {
        "format": FORMAT,
        "status": status,
        "accepted_manifest_count": 0,
        "rejected_manifest_count": 0,
        "observation_count": 0,
        "matched_edge_count": 0,
        "unmatched_observation_count": 0,
        "truncated": False,
    }


def correlate(
    repositories: Iterable[tuple[str, Path]],
    graphs: dict[str, dict],
) -> tuple[dict[str, dict], dict]:
    """Return copied graphs annotated only for exact, integrity-verified observations."""
    correlated = copy.deepcopy(graphs)
    observations, accepted, rejected, truncated = _load_observations(repositories)
    evidence: dict[tuple[str, str, str, str], tuple[int, int]] = {}
    for observation in observations:
        count, events = evidence.get(observation.key, (0, 0))
        evidence[observation.key] = (count + 1, min(MAX_EVENT_COUNT, events + observation.event_count))

    matched_keys: set[tuple[str, str, str, str]] = set()
    matched_edges = 0
    for graph_name in ("service_graph", "webhook_graph", "message_graph", "graphql_service_graph"):
        graph = correlated.get(graph_name)
        if not isinstance(graph, dict) or not isinstance(graph.get("edges"), list):
            continue
        for edge in graph["edges"]:
            if not isinstance(edge, dict):
                continue
            key = _edge_key(graph_name, edge)
            if key is None or key not in evidence:
                continue
            evidence_count, event_count = evidence[key]
            edge["observed"] = True
            edge["runtime_evidence_count"] = evidence_count
            edge["runtime_event_count"] = event_count
            matched_keys.add(key)
            matched_edges += 1

    summary = {
        "format": FORMAT,
        "status": "evaluated",
        "accepted_manifest_count": accepted,
        "rejected_manifest_count": rejected,
        "observation_count": len(observations),
        "matched_edge_count": matched_edges,
        "unmatched_observation_count": sum(1 for item in observations if item.key not in matched_keys),
        "truncated": truncated,
    }
    return correlated, summary


SIGNED_TRACE_VERIFICATION_FORMAT = "sniper-signed-trace-manifest-verification/1"


def _parse_iso8601_utc(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def verify_signed_trace_manifest_and_freshness(
    manifest: dict[str, object],
    *,
    public_key_pem: str | bytes | None = None,
    max_age_seconds: int = 3600,
    reference_time_iso: str | None = None,
) -> dict[str, object]:
    """Verify Ed25519 signature, canonical SHA-256 digest, and timestamp freshness of a trace manifest."""
    import base64
    import binascii

    if not isinstance(manifest, dict):
        return {
            "format": SIGNED_TRACE_VERIFICATION_FORMAT,
            "valid": False,
            "freshness_status": "invalid_manifest",
            "age_seconds": -1,
            "signature_status": "invalid_manifest",
            "canonical_sha256": "",
        }

    # 1. Canonical JSON payload & SHA-256 digest verification
    payload_no_sig = {
        k: v for k, v in manifest.items()
        if k not in {"signature", "signature_b64"}
    }
    payload_no_sig_no_sha = {
        k: v for k, v in manifest.items()
        if k not in {"signature", "signature_b64", "sha256", "integrity_sha256", "canonical_sha256"}
    }
    bytes_no_sig = json.dumps(
        payload_no_sig, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    bytes_no_sig_no_sha = json.dumps(
        payload_no_sig_no_sha, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")

    sha_no_sig = hashlib.sha256(bytes_no_sig).hexdigest()
    sha_no_sig_no_sha = hashlib.sha256(bytes_no_sig_no_sha).hexdigest()

    declared_sha = (
        manifest.get("sha256")
        or manifest.get("integrity_sha256")
        or manifest.get("canonical_sha256")
    )
    if isinstance(declared_sha, str) and declared_sha.strip():
        canonical_sha256 = sha_no_sig_no_sha
        digest_ok = hmac.compare_digest(declared_sha.strip().lower(), sha_no_sig_no_sha.lower())
    else:
        canonical_sha256 = sha_no_sig
        digest_ok = True

    # 2. Freshness verification
    raw_ts = (
        manifest.get("captured_at")
        or manifest.get("created_at")
        or manifest.get("generated_at")
        or manifest.get("timestamp")
    )
    manifest_dt = _parse_iso8601_utc(raw_ts)
    ref_dt = (
        _parse_iso8601_utc(reference_time_iso)
        if reference_time_iso is not None
        else dt.datetime.now(dt.timezone.utc)
    )
    if manifest_dt is None or ref_dt is None:
        freshness_ok = False
        freshness_status = "invalid_timestamp"
        age_seconds = -1
    else:
        age_seconds = int((ref_dt - manifest_dt).total_seconds())
        if age_seconds < 0:
            freshness_ok = False
            freshness_status = "future_skew"
        elif age_seconds > int(max_age_seconds):
            freshness_ok = False
            freshness_status = "expired"
        else:
            freshness_ok = True
            freshness_status = "fresh"

    # 3. Ed25519 signature verification
    raw_sig = manifest.get("signature_b64") or manifest.get("signature")
    key_material = public_key_pem if public_key_pem is not None else manifest.get("public_key_pem")
    sig_ok = False
    sig_status = "unsigned"

    if key_material is not None:
        if not isinstance(raw_sig, (str, bytes)) or not raw_sig:
            sig_ok = False
            sig_status = "missing_signature"
        else:
            try:
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

                pem_bytes = (
                    key_material.encode("utf-8")
                    if isinstance(key_material, str)
                    else bytes(key_material)
                )
                pub_key = serialization.load_pem_public_key(pem_bytes)
                if not isinstance(pub_key, Ed25519PublicKey):
                    sig_status = "invalid_key_type"
                else:
                    if isinstance(raw_sig, bytes):
                        sig_bytes = raw_sig
                    elif re.fullmatch(r"[0-9a-fA-F]{128}", raw_sig.strip()):
                        sig_bytes = bytes.fromhex(raw_sig.strip())
                    else:
                        sig_bytes = base64.b64decode(raw_sig.strip(), validate=True)

                    candidate_messages = [bytes_no_sig]
                    if bytes_no_sig_no_sha != bytes_no_sig:
                        candidate_messages.append(bytes_no_sig_no_sha)
                    candidate_messages.append(canonical_sha256.encode("ascii"))

                    verified_any = False
                    for msg in candidate_messages:
                        try:
                            pub_key.verify(sig_bytes, msg)
                            verified_any = True
                            break
                        except InvalidSignature:
                            continue

                    if verified_any and digest_ok:
                        sig_ok = True
                        sig_status = "verified"
                    else:
                        sig_ok = False
                        sig_status = "invalid_signature"
            except (ValueError, TypeError, binascii.Error):
                sig_ok = False
                sig_status = "invalid_signature"
    else:
        sig_ok = False
        sig_status = "missing_public_key" if raw_sig else "unsigned"

    return {
        "format": SIGNED_TRACE_VERIFICATION_FORMAT,
        "valid": bool(freshness_ok and sig_ok and digest_ok),
        "freshness_status": freshness_status,
        "age_seconds": age_seconds,
        "signature_status": sig_status,
        "canonical_sha256": canonical_sha256,
    }

