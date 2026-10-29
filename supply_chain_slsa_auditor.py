"""Yerel SCA/SLSA denetimi ve dosyalar arası GitHub artifact güven grafiği."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import textwrap
import tomllib
from typing import Any

from dependency_security import DependencySecurityError, discover_components
import iac_yaml
import legacy_basis
from project_analyzer import validate_project_path
from project_tree import ProjectFile, ProjectTree, ProjectTreeError
from scanner import calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups


POPULAR_PACKAGES: tuple[str, ...] = (
    "requests",
    "urllib3",
    "cryptography",
    "fastapi",
    "django",
    "flask",
    "pydantic",
    "sqlalchemy",
    "numpy",
    "pandas",
    "torch",
    "openai",
    "anthropic",
    "lodash",
    "express",
    "axios",
    "react",
    "next",
    "chalk",
    "commander",
    "moment",
    "jsonwebtoken",
    "tokio",
    "serde",
    "reqwest",
    "hyper",
    "spring-boot",
    "jackson-databind",
)

POPULAR_SET = frozenset(POPULAR_PACKAGES)

KNOWN_SAFE_PACKAGES = frozenset({
    *POPULAR_PACKAGES,
    "nuxt",
    "preact",
    "pytest",
    "uvicorn",
    "starlette",
    "httpx",
    "aiohttp",
    "boto3",
    "botocore",
    "scipy",
    "matplotlib",
    "celery",
    "redis",
    "alembic",
    "click",
    "typer",
    "rich",
    "gunicorn",
    "attrs",
    "cattrs",
    "idna",
    "certifi",
    "six",
    "pyyaml",
    "jinja2",
    "werkzeug",
    "markupsafe",
    "itsdangerous",
    "blinker",
    "anyio",
    "sniffio",
    "h11",
    "hyperscan",
    "hypercorn",
    "serde_json",
    "serde_derive",
})

INTERNAL_PACKAGE_PATTERN = re.compile(
    r"(?:^|[-_.])(internal|private|corp|intranet|confidential)(?:$|[-_.])",
    re.IGNORECASE,
)

USES_ACTION_PATTERN = re.compile(
    r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?",
    re.MULTILINE,
)

SHA40_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")

PR_TARGET_TRIGGER_PATTERN = re.compile(r"(?m)^\s*pull_request_target\s*:")
UNTRUSTED_PR_CHECKOUT_PATTERN = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/\$\{\{\s*github\.event\.number",
    re.IGNORECASE,
)
GHA_EXPRESSION_INJECTION_PATTERN = re.compile(
    r"\$\{\{\s*(?:github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|commits\[[^\]]+\]\.message|head_commit\.message)|head_ref))\s*\}\}",
    re.IGNORECASE,
)

RESTRICTIVE_LICENSE_PATTERN = re.compile(
    r"(?<![A-Za-z])(?:AGPL(?:-?\d+(?:\.\d+)?)?|GPL(?:-?[23](?:\.\d+)?)?|SSPL(?:-?\d+(?:\.\d+)?)?|BUSL(?:-?\d+(?:\.\d+)?)?)(?:-(?:only|or-later))?(?![A-Za-z])",
    re.IGNORECASE,
)

EXTRA_INDEX_URL_PATTERN = re.compile(
    r"(?:--extra-index-url(?:\s+|=)\S+|\bextra[-_]index[-_]url\s*(?:=|:)\s*\S+|--extra-index-url\b|\bextra-index-url\b)",
    re.IGNORECASE,
)
REQUIRE_HASHES_PATTERN = re.compile(
    r"(?:--require-hashes\b|\brequire[-_]hashes\s*(?:=|:)\s*(?:true|1|yes)\b)",
    re.IGNORECASE,
)
INSTALL_HOOK_RCE_PATTERN = re.compile(
    r"(?:\b(?:curl|wget|powershell|pwsh|eval)\b|\b(?:ba)?sh\s+-c\b|\bnode\s+(?:-e|--eval)\b|\bpython3?\s+-c\b|\bbase64\s+(?:-d|--decode)\b)",
    re.IGNORECASE,
)
PACKAGE_JSON_HOOK_SCRIPT_PATTERN = re.compile(
    r'["\'](preinstall|postinstall|install)["\']\s*:\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
WORKFLOW_RUN_TRIGGER_PATTERN = re.compile(
    r"(?m)^\s*+workflow_run\s*+:|\bon\s*+:\s*+\[?[^\n\]]{0,2048}\bworkflow_run\b",
)
DOWNLOAD_ARTIFACT_PATTERN = re.compile(
    r"uses\s*+:\s*+['\"]?actions/download-artifact(?:@[^'\"\s#]++)?['\"]?",
    re.IGNORECASE,
)
ARTIFACT_SHELL_EXEC_PATTERN = re.compile(
    r"(?:chmod\s+\+x|\b(?:bash|sh|python3?|npm|source)\b|(?:\s|^|&&|;|\||['\"])\./[A-Za-z0-9_.-])",
    re.IGNORECASE,
)
LOCAL_REUSABLE_WORKFLOW_PATTERN = re.compile(
    r"^\./\.github/workflows/[A-Za-z0-9_.\-/]+\.ya?ml$",
    re.IGNORECASE,
)

WORKFLOW_MIRROR_LOCK = ".sniper-workflow-mirror.lock.json"
WORKFLOW_MIRROR_FORMAT = "sniper-workflow-mirror-resolution-v1"
WORKFLOW_MIRROR_SCHEMA = "sniper-workflow-mirror-lock-v1"
WORKFLOW_MIRROR_MAX_LOCK_BYTES = 256 * 1024
WORKFLOW_MIRROR_MAX_WORKFLOW_BYTES = 1_000_000
WORKFLOW_MIRROR_MAX_ENTRIES = 128
_REMOTE_WORKFLOW_PATTERN = re.compile(
    r"(?P<repository>[a-z0-9_.-]++/[a-z0-9_.-]++)/"
    r"(?P<workflow>\.github/workflows/[A-Za-z0-9_.-]{1,240}\.ya?ml)@(?P<commit>[0-9a-f]{40})\Z"
)


def _yaml_entry(raw_line: str) -> tuple[int, str, str] | None:
    if not raw_line.strip() or raw_line.lstrip().startswith("#"):
        return None
    indentation = len(raw_line) - len(raw_line.lstrip())
    key_raw, separator, value_raw = raw_line.lstrip().partition(":")
    key = key_raw.strip()
    if not separator or re.fullmatch(r"[A-Za-z0-9_.-]++", key) is None:
        return None
    value = value_raw.split(" #", 1)[0].strip().strip("'\"")
    return indentation, key, value


def _permission_set_at_indent(lines: list[str], indent: int) -> tuple[bool, set[str]]:
    for index, raw_line in enumerate(lines):
        entry = _yaml_entry(raw_line)
        if entry is None or entry[0] != indent or entry[1].casefold() != "permissions":
            continue
        value = entry[2].casefold()
        if value == "write-all":
            return True, {"*"}
        if value and value not in {"{}", "null", "read-all"}:
            return True, {
                match.group(1).casefold()
                for match in re.finditer(r"([A-Za-z0-9_-]++)\s*+:\s*+write\b", value, re.IGNORECASE)
            }
        writes: set[str] = set()
        for nested_line in lines[index + 1:]:
            nested = _yaml_entry(nested_line)
            if nested is None:
                continue
            if nested[0] <= indent:
                break
            if nested[2].casefold() == "write":
                writes.add(nested[1].casefold())
        return True, writes
    return False, set()


def _workflow_job_blocks(raw_content: str) -> list[tuple[str, int, list[str]]]:
    lines = textwrap.dedent(raw_content).splitlines()
    jobs_index: int | None = None
    jobs_indent = 0
    for index, raw_line in enumerate(lines):
        entry = _yaml_entry(raw_line)
        if entry is not None and entry[1].casefold() == "jobs":
            jobs_index = index
            jobs_indent = entry[0]
            break
    if jobs_index is None:
        return []

    headers: list[tuple[int, str, int]] = []
    for index in range(jobs_index + 1, len(lines)):
        entry = _yaml_entry(lines[index])
        if entry is None:
            continue
        if entry[0] <= jobs_indent:
            break
        if not headers:
            headers.append((index, entry[1], entry[0]))
        elif entry[0] == headers[0][2]:
            headers.append((index, entry[1], entry[0]))

    blocks: list[tuple[str, int, list[str]]] = []
    for position, (start, name, indent) in enumerate(headers):
        end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        blocks.append((name, indent, lines[start:end]))
    return blocks


def _job_scalar(block: list[str], indent: int, key: str) -> str | None:
    for raw_line in block:
        entry = _yaml_entry(raw_line)
        if entry is not None and entry[0] == indent + 2 and entry[1].casefold() == key:
            return entry[2]
    return None


def _job_secrets_mode(block: list[str], indent: int) -> str:
    value = _job_scalar(block, indent, "secrets")
    if value is None:
        return "none"
    return "inherit" if value.casefold() == "inherit" else "mapped"


def _workflow_has_trigger(raw_content: str, trigger: str) -> bool:
    lines = textwrap.dedent(raw_content).splitlines()
    wanted = trigger.casefold()
    for index, raw_line in enumerate(lines):
        entry = _yaml_entry(raw_line)
        if entry is None or entry[0] != 0 or entry[1].casefold() != "on":
            continue
        scalar = entry[2].casefold()
        if re.search(rf"(?:^|[\s,\[])({re.escape(wanted)})(?:$|[\s,\]])", scalar):
            return True
        for nested_line in lines[index + 1:]:
            nested = _yaml_entry(nested_line)
            if nested is None:
                continue
            if nested[0] <= entry[0]:
                break
            if nested[1].casefold() == wanted:
                return True
        return False
    return False


def _workflow_has_untrusted_pr_trigger(raw_content: str) -> bool:
    return _workflow_has_trigger(raw_content, "pull_request") or _workflow_has_trigger(
        raw_content, "pull_request_target"
    )


def _local_workflow_path(spec: str) -> str | None:
    normalized = spec.strip().strip("'\"")
    if not LOCAL_REUSABLE_WORKFLOW_PATTERN.fullmatch(normalized) or "@" in normalized:
        return None
    relative = Path(normalized[2:])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    return relative.as_posix()


def _has_remote_workflow_path_shape(value: str) -> bool:
    parts = value.split("/")
    if len(parts) != 5 or parts[2:4] != [".github", "workflows"]:
        return False
    owner, repository, _github, _workflows, filename = parts
    allowed = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
    return (
        bool(owner)
        and bool(repository)
        and all(character in allowed for character in owner)
        and all(character in allowed for character in repository)
        and filename.endswith((".yml", ".yaml"))
        and len(filename) > 4
        and all(character in allowed for character in filename)
    )


def _remote_workflow_reference(spec: str) -> dict[str, str] | None:
    """Classify a remote reusable-workflow reference without echoing unsafe input."""
    normalized = spec.strip().strip("'\"")
    if "/.github/workflows/" not in normalized:
        return None
    base = {"callee": "remote-workflow"}
    if len(normalized) > 512 or any(ord(char) < 32 for char in normalized):
        return {**base, "resolution": "invalid_ref"}
    if "${{" in normalized:
        return {**base, "resolution": "dynamic_ref"}
    match = _REMOTE_WORKFLOW_PATTERN.fullmatch(normalized)
    if match is not None:
        return {
            "callee": normalized,
            "repository": match.group("repository"),
            "workflow": match.group("workflow"),
            "commit": match.group("commit"),
            "resolution": "pending_mirror",
        }
    repository_and_path, separator, ref = normalized.rpartition("@")
    if separator and _has_remote_workflow_path_shape(repository_and_path):
        if SHA40_PATTERN.fullmatch(ref):
            return {**base, "resolution": "noncanonical_identity"}
        return {**base, "resolution": "mutable_ref"}
    return {**base, "resolution": "invalid_ref"}


def _workflow_mirror(
    tree: ProjectTree,
    files_by_path: dict[str, ProjectFile],
) -> tuple[dict[tuple[str, str, str], str], dict[str, Any]]:
    """Load a bounded exact-schema offline mirror lock through no-follow descriptors."""
    report: dict[str, Any] = {
        "format": WORKFLOW_MIRROR_FORMAT,
        "status": "absent",
        "lock_present": False,
        "entry_count": 0,
        "verified_entries": 0,
        "errors": [],
    }
    lock_record = files_by_path.get(WORKFLOW_MIRROR_LOCK)
    if lock_record is None:
        return {}, report
    report["lock_present"] = True
    errors: list[str] = []
    try:
        lock_text = tree.read_text(lock_record, WORKFLOW_MIRROR_MAX_LOCK_BYTES)
        payload = json.loads(lock_text)
    except ProjectTreeError:
        errors.append("lock_oversize_or_changed")
        payload = None
    except (UnicodeDecodeError, ValueError, RecursionError):
        errors.append("lock_invalid_json")
        payload = None
    if not isinstance(payload, dict) or set(payload) != {"schema", "workflows"}:
        errors.append("lock_schema_invalid")
        entries: list[Any] = []
    else:
        entries = payload.get("workflows") if isinstance(payload.get("workflows"), list) else []
        if payload.get("schema") != WORKFLOW_MIRROR_SCHEMA or not isinstance(payload.get("workflows"), list):
            errors.append("lock_schema_invalid")
    report["entry_count"] = len(entries)
    if len(entries) > WORKFLOW_MIRROR_MAX_ENTRIES:
        errors.append("lock_entry_limit")
        entries = []

    resolved: dict[tuple[str, str, str], str] = {}
    mirror_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "repository", "commit", "workflow", "mirror_path", "sha256"
        }:
            errors.append("entry_schema_invalid")
            continue
        repository = entry.get("repository")
        commit = entry.get("commit")
        workflow = entry.get("workflow")
        mirror_path = entry.get("mirror_path")
        expected_sha = entry.get("sha256")
        if not isinstance(repository, str) or re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", repository) is None:
            errors.append("repository_identity_invalid")
            continue
        if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            errors.append("commit_sha_invalid")
            continue
        if not isinstance(workflow, str) or re.fullmatch(
            r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", workflow
        ) is None:
            errors.append("workflow_identity_invalid")
            continue
        if not isinstance(mirror_path, str) or not mirror_path.startswith(".sniper-workflow-mirror/"):
            errors.append("mirror_path_invalid")
            continue
        relative = PurePosixPath(mirror_path)
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 3:
            errors.append("mirror_path_invalid")
            continue
        if not isinstance(expected_sha, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None:
            errors.append("mirror_digest_invalid")
            continue
        key = (repository, commit, workflow)
        if key in resolved:
            errors.append("duplicate_identity")
            continue
        if mirror_path in mirror_paths:
            errors.append("duplicate_mirror_path")
            continue
        mirror_paths.add(mirror_path)
        record = files_by_path.get(mirror_path)
        if record is None:
            errors.append("mirror_file_missing")
            continue
        if record.size > WORKFLOW_MIRROR_MAX_WORKFLOW_BYTES:
            errors.append("mirror_file_oversize")
            continue
        try:
            content_bytes = tree.read_bytes(record, WORKFLOW_MIRROR_MAX_WORKFLOW_BYTES)
            content = content_bytes.decode("utf-8")
        except (ProjectTreeError, UnicodeDecodeError):
            errors.append("mirror_file_invalid")
            continue
        if hashlib.sha256(content_bytes).hexdigest() != expected_sha:
            errors.append("mirror_digest_mismatch")
            continue
        if not _workflow_has_trigger(content, "workflow_call"):
            errors.append("mirror_not_reusable")
            continue
        resolved[key] = content

    if errors:
        report["status"] = "invalid"
        report["errors"] = sorted(set(errors))
        return {}, report
    report["status"] = "valid"
    report["verified_entries"] = len(resolved)
    return resolved, report


def _effective_write_permissions(caller: set[str], callee: set[str]) -> set[str]:
    if "*" in caller:
        return set(callee)
    if "*" in callee:
        return set(caller)
    return caller & callee


def _workflow_call_trust_graph(
    workflows: list[tuple[str, str]],
    remote_workflows: dict[tuple[str, str, str], str] | None = None,
    mirror_status: str = "absent",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_path = {name: content for name, content in workflows}
    graph: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for caller_name, caller_content in sorted(workflows):
        caller_lines = textwrap.dedent(caller_content).splitlines()
        _caller_top_present, caller_top_writes = _permission_set_at_indent(caller_lines, 0)
        untrusted_trigger = _workflow_has_untrusted_pr_trigger(caller_content)
        for job_name, job_indent, job_block in _workflow_job_blocks(caller_content):
            uses = _job_scalar(job_block, job_indent, "uses")
            callee_name = _local_workflow_path(uses or "")
            remote = None if callee_name is not None else _remote_workflow_reference(uses or "")
            if callee_name is None and remote is None:
                continue
            job_permissions_present, job_writes = _permission_set_at_indent(job_block, job_indent + 2)
            caller_writes = job_writes if job_permissions_present else caller_top_writes
            secrets_mode = _job_secrets_mode(job_block, job_indent)
            edge_extras: dict[str, Any] = {}
            resolution = "verified_local"
            ref_trust = "same_commit_local"
            if remote is None:
                callee_content = by_path.get(callee_name)
            else:
                callee_name = remote["callee"]
                resolution = remote["resolution"]
                callee_content = None
                if resolution == "pending_mirror":
                    key = (remote["repository"], remote["commit"], remote["workflow"])
                    if mirror_status == "absent":
                        resolution = "mirror_lock_absent"
                    elif mirror_status != "valid":
                        resolution = "mirror_lock_invalid"
                    elif remote_workflows is None or key not in remote_workflows:
                        resolution = "mirror_entry_missing"
                    else:
                        callee_content = remote_workflows[key]
                        resolution = "verified_lock"
                        ref_trust = "offline_mirror_locked"
                    edge_extras = {
                        "repository": remote["repository"],
                        "commit": remote["commit"],
                        "workflow": remote["workflow"],
                        "mirror_content_sha256_verified": resolution == "verified_lock",
                    }
                else:
                    ref_trust = "untrusted_remote_ref"
            resolved = bool(callee_content and _workflow_has_trigger(callee_content, "workflow_call"))
            callee_writes: set[str] = set()
            if resolved and callee_content is not None:
                callee_lines = textwrap.dedent(callee_content).splitlines()
                _callee_top_present, callee_top_writes = _permission_set_at_indent(callee_lines, 0)
                callee_jobs = _workflow_job_blocks(callee_content)
                if not callee_jobs:
                    callee_writes.update(callee_top_writes)
                for _callee_job, callee_job_indent, callee_block in callee_jobs:
                    present, job_requested = _permission_set_at_indent(callee_block, callee_job_indent + 2)
                    callee_writes.update(job_requested if present else callee_top_writes)
            effective_writes = _effective_write_permissions(caller_writes, callee_writes)
            edge = {
                "caller": caller_name,
                "caller_job": job_name,
                "callee": callee_name,
                "resolved": resolved,
                "ref_trust": ref_trust,
                "untrusted_trigger": untrusted_trigger,
                "secrets_mode": secrets_mode,
                "caller_write_permissions": sorted(caller_writes),
                "callee_write_permissions": sorted(callee_writes),
                "effective_write_permissions": sorted(effective_writes),
                **({"resolution": resolution} if remote is not None else {}),
                **edge_extras,
            }
            graph.append(edge)
            if not (resolved and untrusted_trigger and secrets_mode == "inherit" and effective_writes):
                continue
            findings.append({
                "severity": "critical",
                "category": "supplychain",
                "title": "Güvenilmeyen PR iş akışından sır ve yazma yetkisi miras alan reusable workflow zinciri",
                "summary": (
                    "Güvenilmeyen pull request bağlamındaki çağıran iş, tüm erişilebilir sırları yerel reusable "
                    "workflow'a aktarıyor ve her iki workflow'un açık izinlerinin kesişiminde yazma yetkisi kalıyor."
                ),
                "evidence": (
                    f"{caller_name}:{job_name} -> {callee_name}; secrets=inherit; "
                    f"effective_write={','.join(sorted(effective_writes))}"
                ),
                "recommendation": (
                    "PR bağlamında secrets: inherit kullanmayın; yalnız gereken sırları açıkça eşleyin ve caller ile "
                    "reusable workflow izinlerini contents: read seviyesine daraltın."
                ),
                "reference": "CWE-250",
                "control_id": "SNIPER-SLSA-WORKFLOW-CALL-04",
                "caller": caller_name,
                "caller_job": job_name,
                "callee": callee_name,
                "secrets_mode": secrets_mode,
                "effective_write_permissions": sorted(effective_writes),
            })

    return graph, findings



ARTIFACT_TRUST_GRAPH_FORMAT = "sniper-github-artifact-trust-graph-v1"
ARTIFACT_GRAPH_MAX_WORKFLOWS = 200
ARTIFACT_GRAPH_MAX_EDGES = 500
_ARTIFACT_LITERAL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._\-]{0,127}\Z")
_ARTIFACT_VERIFY_PATTERN = re.compile(
    r"(?:gh\s+attestation\s+verify|slsa-verifier\b|cosign\s+verify(?:-attestation)?\b|"
    r"sha256sum\s+(?:--check|-c)\b|shasum\s+-a\s+256\s+(?:--check|-c)\b)",
    re.IGNORECASE,
)


def _yaml_line(owner: object, key: str, default: int = 1) -> int:
    line_of = getattr(owner, "line_of", None)
    if callable(line_of):
        try:
            value = int(line_of(key))
            return value if value > 0 else default
        except (TypeError, ValueError):
            pass
    return default


def _github_event(root: dict[str, Any], event: str) -> tuple[bool, Any]:
    # YAML 1.1 tags an unquoted GitHub Actions `on` key as boolean true. iac_yaml intentionally preserves
    # that scalar tag as the string "True", so accept both spellings without mutating the shared YAML loader.
    triggers = root.get("on") if "on" in root else root.get("True")
    if isinstance(triggers, str):
        return triggers.casefold() == event.casefold(), None
    if isinstance(triggers, list):
        return any(isinstance(item, str) and item.casefold() == event.casefold() for item in triggers), None
    if isinstance(triggers, dict):
        for key, value in triggers.items():
            if str(key).casefold() == event.casefold():
                return True, value
    return False, None


def _literal(value: object, pattern: re.Pattern[str]) -> str | None:
    if not isinstance(value, str):
        return None
    clean = value.strip().strip("'\"")
    if "${{" in clean or not pattern.fullmatch(clean):
        return None
    return clean


def _workflow_name(root: dict[str, Any]) -> str | None:
    return _literal(root.get("name"), re.compile(r"[^\x00-\x1f]{1,160}\Z"))


def _artifact_name(step: dict[str, Any]) -> str | None:
    inputs = step.get("with")
    return _literal(inputs.get("name"), _ARTIFACT_LITERAL_PATTERN) if isinstance(inputs, dict) else None


def _download_path(step: dict[str, Any]) -> str | None:
    inputs = step.get("with")
    value = inputs.get("path") if isinstance(inputs, dict) else None
    if not isinstance(value, str) or "${{" in value or len(value) > 240:
        return None
    clean = value.strip().strip("'\"").replace("\\", "/").rstrip("/")
    if not clean or clean.startswith("/") or any(part in {"", ".", ".."} for part in clean.split("/")):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.\-/]+", clean):
        return None
    return clean


def _uses_action(step: dict[str, Any], action: str) -> bool:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    return uses.strip().strip("'\"").split("@", 1)[0].casefold() == action.casefold()


def _workflow_run_names(config: object) -> list[str]:
    if not isinstance(config, dict):
        return []
    raw = config.get("workflows")
    values = raw if isinstance(raw, list) else [raw]
    names = []
    for value in values:
        name = _literal(value, re.compile(r"[^\x00-\x1f]{1,160}\Z"))
        if name is not None and name not in names:
            names.append(name)
    return names


def _permissions_state(workflow: dict[str, Any], job: dict[str, Any]) -> str:
    raw = job.get("permissions") if "permissions" in job else workflow.get("permissions")
    if isinstance(raw, str):
        normalized = raw.strip().casefold()
        if normalized in {"read-all", "none"}:
            return "read-only"
        if normalized == "write-all":
            return "write-capable"
        return "unspecified"
    if isinstance(raw, dict):
        values = [str(value).strip().casefold() for value in raw.values()]
        if any(value == "write" for value in values):
            return "write-capable"
        if all(value in {"read", "none"} for value in values):
            return "read-only"
    return "unspecified"


def _references_secret(value: object) -> bool:
    pending = [value]
    seen: set[int] = set()
    budget = 5_000
    while pending:
        budget -= 1
        if budget < 0:
            return True  # bütçe aşımı güvenli kabul edilmez
        item = pending.pop()
        if isinstance(item, str):
            if re.search(r"(?i)(?:\$\{\{\s*)?secrets\.[A-Za-z_][A-Za-z0-9_]*", item):
                return True
            continue
        if not isinstance(item, (dict, list)) or id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        else:
            pending.extend(item)
    return False


def _cross_run_download(step: dict[str, Any]) -> bool:
    inputs = step.get("with")
    if not isinstance(inputs, dict):
        return False
    run_id = inputs.get("run-id")
    token = inputs.get("github-token")
    return (
        isinstance(run_id, str)
        and "github.event.workflow_run.id" in run_id
        and isinstance(token, str)
        and ("github.token" in token or "secrets.github_token" in token.casefold())
    )


def _script_references_path(script: str, path: str) -> bool:
    return re.search(
        r"(?<![A-Za-z0-9_.-])(?:\./)?" + re.escape(path) + r"(?:/|(?=$)|(?=[\s'\";|&)]))",
        script,
    ) is not None


def _execution_after_download(steps: list[Any], start: int, download_path: str) -> tuple[int, str] | None:
    declared_verifier = False
    for step in steps[start + 1:]:
        if not isinstance(step, dict):
            continue
        script = step.get("run")
        if not isinstance(script, str):
            continue
        execution = ARTIFACT_SHELL_EXEC_PATTERN.search(script)
        verification = _ARTIFACT_VERIFY_PATTERN.search(script)
        references_download = _script_references_path(script, download_path)
        if execution is not None and references_download:
            if verification is not None and verification.start() < execution.start():
                declared_verifier = True
            return _yaml_line(step, "run"), (
                "declared_unverified" if declared_verifier else "missing"
            )
        if verification is not None and references_download:
            declared_verifier = True
    return None


def _github_artifact_trust_graph(workflows: list[tuple[str, str]]) -> dict[str, Any]:
    """Literal PR producer -> workflow_run consumer artifact edges; ambiguity never becomes an edge."""
    parsed: list[tuple[str, dict[str, Any]]] = []
    parse_errors = 0
    truncated = len(workflows) > ARTIFACT_GRAPH_MAX_WORKFLOWS
    for filename, content in sorted(workflows)[:ARTIFACT_GRAPH_MAX_WORKFLOWS]:
        try:
            docs = iac_yaml.load_all(content)
        except iac_yaml.YamlError:
            parse_errors += 1
            continue
        root = docs[0] if len(docs) == 1 and isinstance(docs[0], dict) else None
        if root is None:
            parse_errors += 1
            continue
        parsed.append((filename, root))

    producers: list[dict[str, Any]] = []
    consumers: list[dict[str, Any]] = []
    for filename, root in parsed:
        name = _workflow_name(root)
        jobs = root.get("jobs")
        if name is None or not isinstance(jobs, dict):
            continue
        is_pr, _pr_config = _github_event(root, "pull_request")
        is_workflow_run, workflow_run_config = _github_event(root, "workflow_run")
        listened_workflows = _workflow_run_names(workflow_run_config) if is_workflow_run else []
        for raw_job in jobs.values():
            if not isinstance(raw_job, dict):
                continue
            steps = raw_job.get("steps")
            if not isinstance(steps, list):
                continue
            if is_pr:
                for step in steps:
                    if not isinstance(step, dict) or not _uses_action(step, "actions/upload-artifact"):
                        continue
                    artifact = _artifact_name(step)
                    if artifact is not None:
                        producers.append({
                            "file": filename,
                            "workflow": name,
                            "artifact": artifact,
                            "line": _yaml_line(step, "uses"),
                        })
            if listened_workflows:
                for index, step in enumerate(steps):
                    if not isinstance(step, dict) or not _uses_action(step, "actions/download-artifact"):
                        continue
                    download_path = _download_path(step)
                    execution = _execution_after_download(steps, index, download_path) if download_path else None
                    if execution is None:
                        if any(isinstance(later, dict) and isinstance(later.get("run"), str)
                               and ARTIFACT_SHELL_EXEC_PATTERN.search(later["run"])
                               for later in steps[index + 1:]):
                            consumers.append({
                                "file": filename, "workflow": name, "artifact": None,
                                "line": _yaml_line(step, "uses"), "execution_line": 0,
                                "verification": "missing", "permissions": _permissions_state(root, raw_job),
                                "secrets_referenced": _references_secret(raw_job),
                                "upstream": listened_workflows, "cross_run": False,
                            })
                        continue
                    execution_line, verification = execution
                    consumers.append({
                        "file": filename,
                        "workflow": name,
                        "artifact": _artifact_name(step),
                        "line": _yaml_line(step, "uses"),
                        "execution_line": execution_line,
                        "verification": verification,
                        "permissions": _permissions_state(root, raw_job),
                        "secrets_referenced": _references_secret(raw_job),
                        "upstream": listened_workflows,
                        "cross_run": _cross_run_download(step),
                    })

    producer_index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for producer in producers:
        producer_index.setdefault((producer["workflow"], producer["artifact"]), []).append(producer)

    edges: list[dict[str, Any]] = []
    unresolved = 0
    for consumer in consumers:
        artifact = consumer["artifact"]
        candidates = [] if artifact is None or not consumer["cross_run"] else [
            producer
            for upstream in consumer["upstream"]
            for producer in producer_index.get((upstream, artifact), [])
            if producer["file"] != consumer["file"]
        ]
        if len(candidates) != 1:
            unresolved += 1
            continue
        if len(edges) >= ARTIFACT_GRAPH_MAX_EDGES:
            truncated = True
            break
        producer = candidates[0]
        status = "mitigated" if (
            consumer["permissions"] == "read-only" and not consumer["secrets_referenced"]
        ) else "review"
        edges.append({
            "producer": "workflow:" + producer["file"],
            "consumer": "workflow:" + consumer["file"],
            "artifact": artifact,
            "consumer_trigger": "workflow_run",
            "permissions": consumer["permissions"],
            "secrets": "referenced" if consumer["secrets_referenced"] else "not-seen",
            "verification": consumer.get("verification", "missing"),
            "status": status,
            "evidence": {
                "upload_line": producer["line"],
                "download_line": consumer["line"],
                "execution_line": consumer["execution_line"],
            },
        })
    edges.sort(key=lambda edge: (edge["producer"], edge["consumer"], edge["artifact"]))

    nodes_by_id: dict[str, dict[str, Any]] = {}
    by_file = {filename: root for filename, root in parsed}
    for edge in edges:
        producer_file = edge["producer"][len("workflow:"):]
        consumer_file = edge["consumer"][len("workflow:"):]
        nodes_by_id[edge["producer"]] = {
            "id": edge["producer"],
            "workflow": _workflow_name(by_file[producer_file]),
            "file": producer_file,
            "role": "producer",
            "trigger": "pull_request",
        }
        nodes_by_id[edge["consumer"]] = {
            "id": edge["consumer"],
            "workflow": _workflow_name(by_file[consumer_file]),
            "file": consumer_file,
            "role": "consumer",
            "trigger": "workflow_run",
        }
    return {
        "format": ARTIFACT_TRUST_GRAPH_FORMAT,
        "summary": {
            "workflows": len(parsed),
            "producers": len(producers),
            "consumers": len(consumers),
            "edges": len(edges),
            "review_edges": sum(edge["status"] == "review" for edge in edges),
            "unresolved_downloads": unresolved,
            "parse_errors": parse_errors,
            "truncated": truncated,
        },
        "nodes": [nodes_by_id[node_id] for node_id in sorted(nodes_by_id)],
        "edges": edges,
    }


def audit_supply_chain_enterprise_inline(
    raw_content: str,
    *,
    filename: str = "package.json",
) -> dict[str, Any]:
    text = raw_content if isinstance(raw_content, str) else ""
    findings: list[dict[str, Any]] = []
    if not text.strip():
        return {"findings": findings, "count": 0, "filename": filename}

    # 1. SNIPER-SLSA-CONFUSION-01: --extra-index-url / extra-index-url without --require-hashes
    extra_match = EXTRA_INDEX_URL_PATTERN.search(text)
    if extra_match is not None and not REQUIRE_HASHES_PATTERN.search(text):
        findings.append({
            "id": "SNIPER-SLSA-CONFUSION-01",
            "rule_id": "SNIPER-SLSA-CONFUSION-01",
            "control_id": "SNIPER-SLSA-CONFUSION-01",
            "severity": "high",
            "category": "supplychain",
            "cwe": "CWE-427",
            "reference": "CWE-427",
            "title": "Tedarik zincirinde Dependency Confusion riski (--extra-index-url kullanımı)",
            "summary": (
                "Paket yapılandırmasında --extra-index-url veya extra-index-url kullanılmış ancak "
                "--require-hashes zorunlu tutulmamış; genel paket deposundaki sahte üst sürüm paket "
                "özel depo paketini gölgeleyerek Dependency Confusion saldırısına yol açabilir."
            ),
            "evidence": f"{filename}: {extra_match.group(0).strip()[:160]}",
            "recommendation": (
                "--extra-index-url yerine tekil --index-url kullanın veya tüm bağımlılıkları "
                "--require-hashes ile SHA-256 özetlerine sabitleyin."
            ),
            "file": filename,
        })

    # 2. SNIPER-SLSA-HOOK-02: Install hook RCE in package.json (preinstall/postinstall/install) or setup.py (cmdclass)
    hook_evidence: str | None = None
    try:
        parsed_json = json.loads(text)
    except Exception:
        parsed_json = None

    if isinstance(parsed_json, dict) and isinstance(parsed_json.get("scripts"), dict):
        scripts_dict = parsed_json["scripts"]
        for hook_key in ("preinstall", "postinstall", "install"):
            script_val = scripts_dict.get(hook_key)
            if isinstance(script_val, str) and INSTALL_HOOK_RCE_PATTERN.search(script_val):
                hook_evidence = f"{filename}: scripts.{hook_key}: {script_val.strip()[:140]}"
                break

    if hook_evidence is None:
        for match in PACKAGE_JSON_HOOK_SCRIPT_PATTERN.finditer(text):
            hook_key, script_val = match.group(1), match.group(2)
            if INSTALL_HOOK_RCE_PATTERN.search(script_val):
                hook_evidence = f"{filename}: {hook_key}: {script_val.strip()[:140]}"
                break

    if hook_evidence is None:
        has_setup_hook = bool(re.search(r"\bcmdclass\b", text)) or (
            filename.casefold().endswith("setup.py") and bool(re.search(r"\bsetup\s*\(", text))
        )
        if has_setup_hook:
            rce_match = INSTALL_HOOK_RCE_PATTERN.search(text)
            if rce_match is not None:
                hook_evidence = f"{filename}: cmdclass/setup.py -> {rce_match.group(0).strip()}"

    if hook_evidence is not None:
        findings.append({
            "id": "SNIPER-SLSA-HOOK-02",
            "rule_id": "SNIPER-SLSA-HOOK-02",
            "control_id": "SNIPER-SLSA-HOOK-02",
            "severity": "critical",
            "category": "supplychain",
            "cwe": "CWE-506",
            "reference": "CWE-506",
            "title": "Paket kurulum kancasında (preinstall/postinstall/setup.py) uzaktan kod çalıştırma sinyali",
            "summary": (
                "Paket kurulum kancasında (preinstall/postinstall/install veya setup.py cmdclass) "
                "uzaktan betik indirme veya dinamik kabuk/yorumlayıcı komutu çalıştırma sinyali tespit edildi."
            ),
            "evidence": hook_evidence,
            "recommendation": (
                "Paket kurulum kancalarında uzak betik indirme ve dinamik kod çalıştırma komutlarını kaldırın; "
                "CI/CD ortamında npm ci --ignore-scripts kullanın."
            ),
            "file": filename,
        })

    # 3. SNIPER-SLSA-ARTIFACT-03: GitHub Actions workflow_run + actions/download-artifact + shell execution
    if WORKFLOW_RUN_TRIGGER_PATTERN.search(text):
        dl_match = DOWNLOAD_ARTIFACT_PATTERN.search(text)
        if dl_match is not None:
            after_download = text[dl_match.end():]
            run_match = re.search(r"(?m)^\s*+(?:-\s*+)?run\s*+:", after_download)
            if run_match is not None:
                exec_match = ARTIFACT_SHELL_EXEC_PATTERN.search(after_download[run_match.start():])
                if exec_match is not None:
                    findings.append({
                        "id": "SNIPER-SLSA-ARTIFACT-03",
                        "rule_id": "SNIPER-SLSA-ARTIFACT-03",
                        "control_id": "SNIPER-SLSA-ARTIFACT-03",
                        "severity": "critical",
                        "category": "supplychain",
                        "cwe": "CWE-829",
                        "reference": "CWE-829",
                        "title": "GitHub Actions workflow_run iş akışında güvenilmeyen PR artifact yürütme (Artifact Poisoning)",
                        "summary": (
                            "Ayrıcalıklı workflow_run iş akışında actions/download-artifact ile indirilen güvenilmeyen "
                            "PR artefaktı, kaynak/imza doğrulaması yapılmadan kabukta yürütülüyor."
                        ),
                        "evidence": f"{filename}: workflow_run + {dl_match.group(0).strip()} -> {exec_match.group(0).strip()}",
                        "recommendation": (
                            "workflow_run içinde indirilen artefaktları doğrudan çalıştırmayın; "
                            "çalıştırmadan önce kriptografik provenance/attestation doğrulaması uygulayın."
                        ),
                        "file": filename,
                    })

    return {"findings": findings, "count": len(findings), "filename": filename}


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return abs(len(a) - len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _is_adjacent_transposition(a: str, b: str) -> bool:
    if len(a) != len(b) or a == b:
        return False
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
        i = diffs[0]
        return a[i] == b[i + 1] and a[i + 1] == b[i]
    return False


def _detect_typosquat(pkg_name: str) -> tuple[str, str] | None:
    raw = pkg_name.strip().casefold()
    if not raw or raw.startswith("@"):
        return None
    if ":" in raw:
        raw = raw.rsplit(":", 1)[-1]
    if raw in KNOWN_SAFE_PACKAGES:
        return None
    normalized_collapsed = re.sub(r"[-_.]", "", raw)
    for target in POPULAR_PACKAGES:
        if raw == target:
            continue
        if _is_adjacent_transposition(raw, target):
            return target, f"Adjacent character transposition of popular package '{target}'"
        if _levenshtein_distance(raw, target) == 1:
            return target, f"Edit distance 1 from popular package '{target}'"
        target_collapsed = re.sub(r"[-_.]", "", target)
        if normalized_collapsed == target_collapsed:
            return target, f"Hyphen/separator spoofing of popular package '{target}'"
    return None


def _read_manifest_licenses(
    tree: ProjectTree,
    files_by_path: dict[str, ProjectFile],
) -> list[tuple[str, str]]:
    discovered: list[tuple[str, str]] = []
    pkg_json = files_by_path.get("package.json")
    if pkg_json is not None and pkg_json.size <= 1_000_000:
        pkg_json_text = tree.read_text(pkg_json, 1_000_000, errors="ignore", allow_empty=True)
        try:
            data = json.loads(pkg_json_text)
            if isinstance(data, dict):
                lic = data.get("license")
                name = str(data.get("name") or "package.json")
                if isinstance(lic, str) and lic.strip():
                    discovered.append((name, lic.strip()))
        except Exception:
            pass

    pyproject = files_by_path.get("pyproject.toml")
    if pyproject is not None and pyproject.size <= 1_000_000:
        pyproject_text = tree.read_text(pyproject, 1_000_000, errors="ignore", allow_empty=True)
        try:
            data = tomllib.loads(pyproject_text)
            if isinstance(data, dict):
                proj = data.get("project")
                if isinstance(proj, dict):
                    name = str(proj.get("name") or "pyproject.toml")
                    lic = proj.get("license")
                    if isinstance(lic, str) and lic.strip():
                        discovered.append((name, lic.strip()))
                    elif isinstance(lic, dict):
                        text = str(lic.get("text") or lic.get("file") or "").strip()
                        if text:
                            discovered.append((name, text))
        except Exception:
            pass

    cargo = files_by_path.get("Cargo.toml")
    if cargo is not None and cargo.size <= 1_000_000:
        cargo_text = tree.read_text(cargo, 1_000_000, errors="ignore", allow_empty=True)
        try:
            data = tomllib.loads(cargo_text)
            if isinstance(data, dict):
                pkg = data.get("package")
                if isinstance(pkg, dict):
                    name = str(pkg.get("name") or "Cargo.toml")
                    lic = pkg.get("license")
                    if isinstance(lic, str) and lic.strip():
                        discovered.append((name, lic.strip()))
        except Exception:
            pass

    return discovered


# 23. tur: proje klasöründe aranan kaynak/imza/SBOM/VEX artefaktları (en çok 2 düzey derinlik, sembolik bağ yok).
_PROVENANCE_SCAN_SKIP = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", "dist-packages", "data"})
_PROVENANCE_MAX_ENTRIES = 5_000


def _classify_provenance_file(name: str) -> str | None:
    low = name.casefold()
    if low.endswith((".intoto.jsonl", ".intoto.json")) or ("provenance" in low and low.endswith((".json", ".jsonl"))):
        return "provenance"
    if low.endswith((".sig", ".asc", ".sigstore", ".sigstore.json")) or low in {"cosign.pub", "release-signing.pub"}:
        return "signature"
    if low.endswith((".vex.json", ".openvex.json")) or low.startswith(("vex.", "openvex")) or low.endswith(".csaf.json"):
        return "vex"
    if (low.endswith((".cdx.json", ".cdx.xml", ".spdx.json", ".spdx", ".spdx.xml"))
            or (low.startswith(("bom.", "sbom")) and low.endswith((".json", ".xml")))):
        return "sbom"
    if low == "sha256sums" or low.endswith(".sha256"):
        return "checksum"
    return None


def _project_provenance_signals(
    tree: ProjectTree,
    project_files: list[ProjectFile],
    files_by_path: dict[str, ProjectFile],
) -> dict[str, Any]:
    """Projede gerçekten bulunan sürüm manifesti, imza, SBOM ve VEX dosyaları."""
    found: dict[str, list[str]] = {"provenance": [], "signature": [], "sbom": [], "vex": [], "checksum": []}
    release_manifest: dict[str, Any] | None = None
    for entry in project_files:
        rel = entry.path.as_posix()
        if entry.name == "MANIFEST.json" and release_manifest is None:
            if entry.size <= 4_000_000:
                text = tree.read_text(entry, 4_000_000, errors="ignore", allow_empty=True)
                try:
                    data = json.loads(text) if text else None
                except ValueError:
                    data = None
                if isinstance(data, dict) and str(data.get("format") or "").startswith("sniper-release/"):
                    sig = entry.path.with_name("MANIFEST.json.sig").as_posix()
                    release_manifest = {
                        "path": rel, "format": data.get("format"), "version": str(data.get("version") or ""),
                        "file_count": len(data.get("files") or []),
                        "signed": sig in files_by_path,
                    }
            continue
        kind = _classify_provenance_file(entry.name)
        if kind and len(found[kind]) < 20:
            found[kind].append(rel)
    return {"files": found, "release_manifest": release_manifest}


def _vex_status(store: Any, project_path: str, allowed_roots: tuple[Path, ...] | None) -> dict[str, Any] | None:
    """Depodaki bağımlılık bulguları için kayıtlı VEX kararlarının sayısı."""
    if store is None or not hasattr(store, "dependency_findings_for_project"):
        return None
    try:
        import vex_export
        _, dep_findings = vex_export.project_findings(store, project_path, allowed_roots)
        ids = [str(f.get("id")) for f in dep_findings if f.get("id") is not None]
        decisions = store.vex_decisions(ids) if ids and hasattr(store, "vex_decisions") else {}
    except Exception:
        return None
    return {"dependency_findings": len(dep_findings), "vex_decisions": len(decisions),
            "undecided": max(0, len(dep_findings) - len(decisions))}


def audit_supply_chain_slsa(
    project_path: str | None = None,
    *,
    components: list[dict[str, Any]] | None = None,
    workflow_content: str | None = None,
    license_policy: str = "commercial",
    allowed_roots: tuple[Path, ...] | None = None,
    store: Any = None,
) -> dict[str, Any]:
    has_components = isinstance(components, list) and any(isinstance(c, dict) for c in components)
    has_workflow = isinstance(workflow_content, str) and bool(workflow_content.strip())
    if project_path is None and not has_components and not has_workflow:
        raise legacy_basis.NoSourceError(
            "Tedarik zinciri denetimi için proje klasörü (project_path), bileşen listesi (components) "
            "ya da CI iş akışı içeriği (workflow_content) gönderin.")
    comp_list: list[dict[str, Any]] = []
    provenance: dict[str, Any] = {"files": {}, "release_manifest": None}
    vex_state: dict[str, Any] | None = None
    workflows: list[tuple[str, str]] = []
    remote_workflows: dict[tuple[str, str, str], str] = {}
    workflow_mirror: dict[str, Any] = {
        "format": WORKFLOW_MIRROR_FORMAT,
        "status": "absent",
        "lock_present": False,
        "entry_count": 0,
        "verified_entries": 0,
        "errors": [],
    }
    enterprise_files: list[tuple[str, str]] = []
    manifest_licenses: list[tuple[str, str]] = []
    root: Path | None = None

    if project_path is not None:
        root = validate_project_path(project_path, allowed_roots)
        with ProjectTree(root) as tree:
            try:
                _, discovered = discover_components(
                    str(root), allowed_roots=allowed_roots, project_tree=tree
                )
                comp_list.extend(discovered)
            except ProjectTreeError:
                raise
            except (DependencySecurityError, OSError, ValueError, TypeError, KeyError) as exc:
                if isinstance(exc.__cause__, ProjectTreeError):
                    raise
                try:
                    from dependency_security import discover_inventory
                    _, discovered_lenient, _ = discover_inventory(
                        str(root), allowed_roots=allowed_roots, lenient=True, project_tree=tree
                    )
                    comp_list.extend(discovered_lenient)
                except ProjectTreeError:
                    raise
                except Exception:
                    pass
            project_files: list[ProjectFile] = []
            for project_file in tree.iter_files(
                skip_dirs=_PROVENANCE_SCAN_SKIP,
                reject_unsafe=False,
            ):
                if len(project_file.path.parts) <= 3:
                    project_files.append(project_file)
                    if len(project_files) >= _PROVENANCE_MAX_ENTRIES:
                        break
            files_by_path = {project_file.path.as_posix(): project_file for project_file in project_files}
            remote_workflows, workflow_mirror = _workflow_mirror(tree, files_by_path)
            manifest_licenses.extend(_read_manifest_licenses(tree, files_by_path))
            provenance = _project_provenance_signals(tree, project_files, files_by_path)
            for project_file in project_files:
                if project_file.size > 1_000_000:
                    continue
                low_name = project_file.name.casefold()
                if (
                    project_file.path.parent.as_posix() == ".github/workflows"
                    and project_file.path.suffix.casefold() in {".yml", ".yaml"}
                ):
                    wf_text = tree.read_text(project_file, 1_000_000, errors="ignore", allow_empty=True)
                    workflows.append((project_file.path.as_posix(), wf_text))
                elif (
                    low_name in {"package.json", "setup.py", "pip.conf", "pip.ini", "pyproject.toml", "dockerfile"}
                    or (low_name.startswith("requirements") and low_name.endswith((".txt", ".in")))
                    or low_name.startswith("dockerfile.")
                    or low_name.endswith(".dockerfile")
                ):
                    ent_text = tree.read_text(project_file, 1_000_000, errors="ignore", allow_empty=True)
                    enterprise_files.append((project_file.path.as_posix(), ent_text))
        vex_state = _vex_status(store, str(root), allowed_roots)

    if isinstance(components, list):
        for item in components:
            if isinstance(item, dict):
                comp_list.append(dict(item))

    if isinstance(workflow_content, str) and workflow_content.strip():
        workflows.append((".github/workflows/inline.yml", workflow_content))

    typos: list[dict[str, Any]] = []
    confusion: list[dict[str, Any]] = []
    unpinned: list[dict[str, Any]] = []
    licenses: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    artifact_trust_graph = _github_artifact_trust_graph(workflows)
    graph_consumer_files = {
        edge["consumer"][len("workflow:"):]
        for edge in artifact_trust_graph["edges"]
        if isinstance(edge.get("consumer"), str) and edge["consumer"].startswith("workflow:")
    }
    for edge in artifact_trust_graph["edges"]:
        if edge["status"] != "review":
            continue
        producer_file = edge["producer"][len("workflow:"):]
        consumer_file = edge["consumer"][len("workflow:"):]
        evidence = edge["evidence"]
        findings.append({
            "severity": "critical",
            "category": "supplychain",
            "title": "Dosyalar arası GitHub Actions artifact güven zinciri ayrıcalıklı yürütmeye ulaşıyor",
            "summary": (
                "pull_request ile tetiklenen iş akışının yüklediği literal artifact, ayrı workflow_run tüketicisinde "
                "tam workflow/artifact adıyla indirilip doğrulama veya açık salt-okunur izin daraltması olmadan çalıştırılıyor."
            ),
            "evidence": (
                f"{producer_file}:{evidence['upload_line']} upload '{edge['artifact']}' -> "
                f"{consumer_file}:{evidence['download_line']} download -> "
                f"{consumer_file}:{evidence['execution_line']} execute"
            ),
            "recommendation": (
                "Artifactı çalıştırmadan önce SHA-256/provenance/attestation doğrulayın veya tüketici işinin "
                "GitHub token izinlerini açıkça salt-okunur kapsamla sınırlandırın."
            ),
            "reference": "CWE-829",
            "control_id": "SNIPER-SLSA-ARTIFACT-GRAPH-04",
            "file": consumer_file,
            "line": evidence["download_line"],
        })

    seen_typos: set[str] = set()
    seen_confusion: set[str] = set()
    seen_licenses: set[tuple[str, str]] = set()

    # 1 & 2 & 4: Component checks (Typosquatting, Dependency Confusion, License Risk)
    for comp in comp_list:
        raw_name = str(comp.get("name") or comp.get("package") or "").strip()
        if not raw_name:
            continue
        ecosystem = str(comp.get("ecosystem") or "generic").strip()
        manifest = str(comp.get("manifest") or "manifest").strip()
        version = str(comp.get("version") or "").strip()

        typo_match = _detect_typosquat(raw_name)
        if typo_match is not None and raw_name.casefold() not in seen_typos:
            seen_typos.add(raw_name.casefold())
            target_pkg, reason = typo_match
            typos.append({
                "package": raw_name,
                "version": version,
                "suspected_target": target_pkg,
                "ecosystem": ecosystem,
                "manifest": manifest,
                "reason": reason,
            })
            findings.append({
                "severity": "critical",
                "category": "supplychain",
                "title": f"Olası typosquatting paketi tespit edildi: {raw_name} (hedef: {target_pkg})",
                "summary": f"'{raw_name}' paket adı popüler '{target_pkg}' paketine çok yakın ({reason}).",
                "evidence": f"{manifest}: {raw_name}@{version or '*'}",
                "recommendation": f"Paket adını '{target_pkg}' olarak doğrulayın ve şüpheli paketi derhal kaldırın.",
                "reference": "CWE-829",
                "control_id": "SNIPER-SUPP-01",
            })

        if (
            not raw_name.startswith("@")
            and ":" not in raw_name
            and INTERNAL_PACKAGE_PATTERN.search(raw_name)
            and raw_name.casefold() not in seen_confusion
        ):
            seen_confusion.add(raw_name.casefold())
            confusion.append({
                "package": raw_name,
                "version": version,
                "ecosystem": ecosystem,
                "manifest": manifest,
                "reason": "Kapsamsız, iç paket gibi görünen ad bağımlılık karışıklığına açık",
            })
            findings.append({
                "severity": "high",
                "category": "supplychain",
                "title": f"Dependency Confusion riski taşıyan kapsamsız iç paket adı: {raw_name}",
                "summary": "Kapsamsız (unscoped) iç paket adları genel paket kayıtlarında gölgelenerek uzaktan kod çalıştırmaya yol açabilir.",
                "evidence": f"{manifest}: {raw_name}",
                "recommendation": "İç paketlerde organizasyon kapsamı (@corp/pkg) kullanın ve kayıt defteri önceliğini sabitleyin.",
                "reference": "CWE-427",
                "control_id": "SNIPER-SUPP-01",
            })

        raw_lic = comp.get("license") or comp.get("licenses") or ""
        if isinstance(raw_lic, list):
            raw_lic = ", ".join(str(x) for x in raw_lic)
        lic_str = str(raw_lic).strip()
        if lic_str:
            manifest_licenses.append((raw_name, lic_str))

    if license_policy.strip().casefold() == "commercial":
        for pkg_name, lic_str in manifest_licenses:
            if "lgpl" in lic_str.casefold() and not re.search(r"(?<![lL])gpl", lic_str):
                continue
            if RESTRICTIVE_LICENSE_PATTERN.search(lic_str):
                key = (pkg_name.casefold(), lic_str.upper())
                if key not in seen_licenses:
                    seen_licenses.add(key)
                    licenses.append({
                        "package": pkg_name,
                        "license": lic_str,
                        "policy": license_policy,
                    })
                    findings.append({
                        "severity": "medium",
                        "category": "supplychain",
                        "title": f"Ticari politikayla uyumsuz kısıtlayıcı lisans: {pkg_name} ({lic_str})",
                        "summary": f"'{pkg_name}' bileşeni '{lic_str}' copyleft/kısıtlayıcı lisansını kullanıyor.",
                        "evidence": f"{pkg_name}: license={lic_str}",
                        "recommendation": "Ticari dağıtım politikasına uygun (MIT, Apache-2.0, BSD-3-Clause) bir alternatif kullanın veya hukuki inceleme yapın.",
                        "reference": "CWE-1104",
                        "control_id": "SNIPER-SUPP-01",
                    })

    # 3: SLSA v1.0 Provenance & GitHub Actions Commit SHA Pinning
    has_provenance = False
    declared_provenance_tools: list[str] = []
    provenance_tokens = (
        "attest-build-provenance",
        "slsa-github-generator",
        "slsa-framework",
        "cosign",
        "sigstore",
    )

    for wf_name, content in workflows:
        low_content = content.casefold()
        declared_provenance_tools.extend(
            token for token in provenance_tokens if token in low_content and token not in declared_provenance_tools
        )
        for match in USES_ACTION_PATTERN.finditer(content):
            action_spec = match.group(1).strip()
            if action_spec.startswith(("./", ".\\", "docker://")):
                continue
            if "@" not in action_spec:
                continue
            repo_part, ref_part = action_spec.rsplit("@", 1)
            if SHA40_PATTERN.fullmatch(ref_part):
                continue
            sev = "high" if ref_part.casefold() in {"main", "master", "head", "latest"} else "medium"
            unpinned.append({
                "action": action_spec,
                "repository": repo_part,
                "ref": ref_part,
                "workflow": wf_name,
            })
            findings.append({
                "severity": sev,
                "category": "supplychain",
                "title": f"SHA ile sabitlenmemiş GitHub Action kullanımı: {action_spec}",
                "summary": f"CI/CD iş akışında değiştirilebilir '{ref_part}' etiketi/dalı kullanılıyor; SLSA v1.0 40 karakterlik commit SHA sabitlemesi gerektirir.",
                "evidence": f"{wf_name}: uses: {action_spec}",
                "recommendation": f"'{repo_part}' eylemini tam 40 karakterlik git commit SHA özeti ile sabitleyin.",
                "reference": "CWE-829",
                "control_id": "SNIPER-SUPP-05",
            })

        if PR_TARGET_TRIGGER_PATTERN.search(content) and UNTRUSTED_PR_CHECKOUT_PATTERN.search(content):
            findings.append({
                "severity": "critical",
                "category": "supplychain",
                "title": f"GitHub Actions pull_request_target iş akışında güvenilmeyen PR kodu checkout ediliyor (Pwn Request): {wf_name}",
                "summary": "pull_request_target tetikleyicisi depo sırlarına ve yazma izinlerine erişim sağlar; çatal (fork) PR kodunun doğrudan checkout edilmesi uzaktan kod çalıştırmaya ve sır sızıntısına yol açar.",
                "evidence": f"{wf_name}: pull_request_target + github.event.pull_request.head checkout",
                "recommendation": "pull_request_target içinde PR dalını checkout etmeyin veya ayrıcalıksız pull_request iş akışı kullanın.",
                "reference": "CWE-829",
                "control_id": "SNIPER-SUPP-05",
            })

        expr_match = GHA_EXPRESSION_INJECTION_PATTERN.search(content)
        if expr_match is not None and re.search(r"(?m)^\s*(?:-\s*)?run\s*:", content):
            findings.append({
                "severity": "critical",
                "category": "supplychain",
                "title": f"GitHub Actions iş akışında güvenilmeyen bağlam ifadesiyle kabuk komutu enjeksiyonu: {wf_name}",
                "summary": "run: kabuk adımında doğrudan ${{ github.event... }} veya ${{ github.head_ref }} ifadesi enterpole ediliyor; PR başlığı veya yorumu üzerinden rastgele kabuk komutu çalıştırılabilir.",
                "evidence": f"{wf_name}: {expr_match.group(0)}",
                "recommendation": "Güvenilmeyen GitHub bağlam değerlerini doğrudan run: bloğuna yazmak yerine env: ortam değişkeni olarak aktarın ve kabukta çift tırnak içinde okuyun.",
                "reference": "CWE-78",
                "control_id": "SNIPER-SUPP-05",
            })

    workflow_call_graph, workflow_call_findings = _workflow_call_trust_graph(
        workflows,
        remote_workflows,
        str(workflow_mirror.get("status") or "invalid"),
    )
    findings.extend(workflow_call_findings)

    seen_enterprise_keys: set[tuple[str, str]] = set()
    for ent_filename, ent_content in [*enterprise_files, *workflows]:
        inline_res = audit_supply_chain_enterprise_inline(ent_content, filename=ent_filename)
        for ent_finding in inline_res.get("findings") or []:
            if ent_finding.get("control_id") == "SNIPER-SLSA-ARTIFACT-03" and ent_filename in graph_consumer_files:
                continue  # dosyalar arası graph aynı tüketiciyi daha kesin kontrol/kanıtla değerlendirir
            key = (str(ent_finding.get("control_id") or ""), str(ent_finding.get("evidence") or ""))
            if key in seen_enterprise_keys:
                continue
            seen_enterprise_keys.add(key)
            findings.append(ent_finding)
            if ent_finding.get("control_id") == "SNIPER-SLSA-CONFUSION-01":
                confusion.append({
                    "package": "--extra-index-url",
                    "version": "",
                    "ecosystem": "pypi",
                    "manifest": ent_filename,
                    "reason": "Hash sabitlemesi olmadan --extra-index-url kullanımı Dependency Confusion riski oluşturuyor",
                })

    # Projede gerçekten bulunan imzalı sürüm manifesti / in-toto kaydı da kaynak kanıtıdır.
    prov_files = provenance.get("files") or {}
    release_manifest = provenance.get("release_manifest")
    if prov_files.get("provenance") or (release_manifest and release_manifest.get("signed")):
        has_provenance = True
    if root is not None and not prov_files.get("sbom"):
        findings.append({
            "severity": "low",
            "category": "supplychain",
            "title": "Projede SBOM (CycloneDX/SPDX) dosyası yok",
            "summary": "Sürümle birlikte yayımlanan bir SBOM, bileşen envanterinin alıcı tarafından doğrulanmasını sağlar.",
            "evidence": "bom.json / *.cdx.json / *.spdx.json bulunamadı (2 düzey derinlik)",
            "recommendation": "CI'da CycloneDX SBOM üretip sürüm artefaktına ekleyin (Sniper: SBOM dışa aktarma).",
            "reference": "CWE-1104",
            "control_id": "SNIPER-SUPP-02",
        })

    if has_provenance or (len(workflows) > 0 and len(unpinned) == 0):
        slsa_level = 2
    elif len(workflows) > 0 or len(comp_list) > 0:
        slsa_level = 1
    else:
        slsa_level = 0

    score, grade, _ = calculate_score(findings)

    return {
        "format": "sniper-supply-chain-slsa-audit-v1",
        "component_count": len(comp_list),
        "estimated_slsa_level": slsa_level,
        "typosquatting_suspects": typos,
        "dependency_confusion_risks": confusion,
        "unpinned_actions": unpinned,
        "license_risks": licenses,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": ["SNIPER-SUPP-01", "SNIPER-SUPP-02", "SNIPER-SUPP-05",
                               "SNIPER-SLSA-WORKFLOW-CALL-04", "SNIPER-SLSA-ARTIFACT-GRAPH-04"],
        "workflow_call_graph": workflow_call_graph,
        "workflow_mirror": workflow_mirror,
        "artifact_trust_graph": artifact_trust_graph,
        "has_provenance": has_provenance,
        "provenance_verification_status": "structural_only" if has_provenance else "not_run",
        "declared_provenance_tools": sorted(declared_provenance_tools),
        "provenance_files": prov_files,
        "release_manifest": release_manifest,
        "vex_status": vex_state,
        "slsa_level_note": (
            "Tahmini düzey yalnız iş akışı, yerel imza/in-toto dosyası varlığı ve SHA sabitlemesine dayanır; "
            "dosya/komut varlığı kriptografik doğrulama sayılmaz ve statik kanıt SLSA 3 olarak raporlanmaz."
        ),
        "data_basis": legacy_basis.data_basis("real", [
            "proje klasörü" if root is not None else "",
            f"istekteki {len(components)} bileşen" if has_components else "",
            "istekteki iş akışı" if has_workflow else "",
            "depodaki VEX kararları" if vex_state else "",
        ]),
    }

def verify_offline_workflow_and_sigstore_provenance(
    workflow_content: str,
    *,
    mirror_workflows: dict[str, str] | None = None,
    sigstore_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Faz 2 R6: Çevrimdışı reusable workflow aynalarını (mirror_workflows) ve Sigstore/Cosign
    bundle bütünlüğünü (mediaType, verificationMaterial, dsseEnvelope/messageSignature, SHA-256
    digest binding) doğrular."""
    if not isinstance(workflow_content, str):
        raise ValueError("workflow_content metin olmalıdır.")
    if len(workflow_content.encode("utf-8", errors="replace")) > 4 * 1024 * 1024:
        raise ValueError("workflow_content 4 MB sınırını aşıyor.")

    findings: list[dict[str, Any]] = []
    resolved_mirrors: list[str] = []

    has_secrets_inherit = bool(re.search(r"(?mi)^\s*secrets\s*:\s*inherit\b", workflow_content))
    if isinstance(mirror_workflows, dict):
        called_specs = [
            m.group(1).strip().strip("'\"")
            for m in re.finditer(r"(?mi)^\s*uses\s*:\s*([^\s#'\"]+)", workflow_content)
        ]
        matched_items: list[tuple[str, str]] = []
        for ref_key, callee_yaml in mirror_workflows.items():
            if not isinstance(callee_yaml, str):
                continue
            ref_base = ref_key.split("@", 1)[0]
            if (
                ref_key in workflow_content
                or any(spec == ref_key or spec.split("@", 1)[0] == ref_base for spec in called_specs)
                or not called_specs
            ):
                matched_items.append((ref_key, callee_yaml))
        if not matched_items:
            matched_items = [(k, v) for k, v in mirror_workflows.items() if isinstance(v, str)]

        for ref_key, callee_yaml in matched_items:
            resolved_mirrors.append(ref_key)
            callee_priv_esc = bool(
                re.search(
                    r"(?mi)(?:^\s*permissions\s*:\s*write-all\b"
                    r"|^\s*(?:contents|id-token|packages|actions|deployments|security-events|pull-requests)\s*:\s*write\b"
                    r"|\bpull_request_target\b"
                    r"|^\s*secrets\s*:\s*inherit\b"
                    r"|\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b)",
                    callee_yaml,
                )
            )
            callee_expr_inj = bool(
                GHA_EXPRESSION_INJECTION_PATTERN.search(callee_yaml)
                and re.search(r"(?m)^\s*(?:-\s*)?run\s*:", callee_yaml)
            )
            callee_unpinned = False
            for m_use in USES_ACTION_PATTERN.finditer(callee_yaml):
                act_spec = m_use.group(1).strip()
                if "@" in act_spec and not act_spec.startswith(("./", "docker://")):
                    _r, r_ref = act_spec.rsplit("@", 1)
                    if not SHA40_PATTERN.fullmatch(r_ref):
                        callee_unpinned = True
                        break
            if has_secrets_inherit or callee_priv_esc or callee_expr_inj or callee_unpinned:
                reasons: list[str] = []
                if has_secrets_inherit:
                    reasons.append("secrets: inherit")
                if callee_priv_esc:
                    reasons.append("callee privilege escalation / write permissions")
                if callee_expr_inj:
                    reasons.append("callee untrusted expression injection")
                if callee_unpinned:
                    reasons.append("callee unpinned action")
                findings.append({
                    "severity": "high",
                    "category": "supplychain",
                    "title": f"Çevrimdışı reusable workflow aynasında aşırı yetki veya sır mirası riski: {ref_key}",
                    "summary": (
                        "Çağrılan yerel/ayna iş akışında 'secrets: inherit' veya aşırı yazma/ayrıcalık yükseltme "
                        "yapılandırması tespit edildi."
                    ),
                    "evidence": f"{ref_key}: {', '.join(reasons)}",
                    "recommendation": (
                        "Reusable workflow çağrılarında 'secrets: inherit' yerine yalnızca gerekli sırları açıkça "
                        "aktarın ve çağrılan iş akışını en az ayrıcalık (permissions: read-all) + 40-haneli SHA ile sabitleyin."
                    ),
                    "reference": "CWE-829",
                    "cwe": "CWE-829",
                    "control_id": "SNIPER-SLSA-MIRROR-01",
                })
    elif has_secrets_inherit:
        findings.append({
            "severity": "high",
            "category": "supplychain",
            "title": "Reusable workflow çağrısında koşulsuz sır mirası (secrets: inherit)",
            "summary": "İş akışı çağrısında tüm depo sırları alt iş akışına koşulsuz devrediliyor.",
            "evidence": "secrets: inherit",
            "recommendation": "Yalnızca gerekli sırları açık anahtarlarla aktarın.",
            "reference": "CWE-829",
            "cwe": "CWE-829",
            "control_id": "SNIPER-SLSA-MIRROR-01",
        })

    sig_ok = False
    if isinstance(sigstore_bundle, dict) and sigstore_bundle:
        import base64

        media_type = str(sigstore_bundle.get("mediaType") or "").strip()
        ver_mat = sigstore_bundle.get("verificationMaterial")
        dsse = sigstore_bundle.get("dsseEnvelope")
        msg_sig = sigstore_bundle.get("messageSignature")

        media_ok = media_type.startswith("application/vnd.dev.sigstore.bundle")
        ver_mat_ok = isinstance(ver_mat, dict) and bool(ver_mat)
        envelope_ok = False
        extracted_digest = ""

        if isinstance(dsse, dict) and dsse:
            payload_raw = str(dsse.get("payload") or "").strip()
            sigs = dsse.get("signatures")
            if payload_raw and isinstance(sigs, list) and any(
                isinstance(s, dict) and str(s.get("sig") or "").strip() for s in sigs
            ):
                envelope_ok = True
            extracted_digest = str(dsse.get("sha256") or dsse.get("digest") or "").strip()
            if not extracted_digest and payload_raw:
                decoded_text = payload_raw
                try:
                    decoded_text = base64.b64decode(payload_raw).decode("utf-8", errors="ignore")
                except Exception:
                    pass
                try:
                    stmt = json.loads(decoded_text)
                    if isinstance(stmt, dict):
                        subjects = stmt.get("subject") or []
                        if isinstance(subjects, list) and subjects and isinstance(subjects[0], dict):
                            dig_map = subjects[0].get("digest") or {}
                            if isinstance(dig_map, dict):
                                extracted_digest = str(dig_map.get("sha256") or "").strip()
                except Exception:
                    pass
        elif isinstance(msg_sig, dict) and msg_sig:
            sig_val = str(msg_sig.get("signature") or "").strip()
            msg_dig = msg_sig.get("messageDigest")
            if sig_val and isinstance(msg_dig, dict):
                extracted_digest = str(msg_dig.get("digest") or "").strip()
                if extracted_digest:
                    envelope_ok = True

        expected_digest = str(
            sigstore_bundle.get("expected_sha256")
            or sigstore_bundle.get("artifact_sha256")
            or sigstore_bundle.get("subject_sha256")
            or sigstore_bundle.get("expected_digest")
            or ""
        ).strip()

        digest_ok = True
        if expected_digest and extracted_digest and expected_digest.lower() != extracted_digest.lower():
            digest_ok = False
        elif expected_digest and not extracted_digest:
            digest_ok = False
        elif extracted_digest and (
            extracted_digest.lower() in {"invalid", "mismatch", "tampered", "0" * 64}
            or (len(extracted_digest) == 64 and not re.fullmatch(r"[0-9a-fA-F]{64}", extracted_digest))
        ):
            digest_ok = False

        sig_ok = bool(media_ok and ver_mat_ok and envelope_ok and digest_ok)
        if not sig_ok:
            findings.append({
                "severity": "high",
                "category": "supplychain",
                "title": "Sigstore/Cosign provenance doğrulaması başarısız veya SHA-256 özeti uyuşmuyor",
                "summary": (
                    "Sigstore bundle yapısı eksik (mediaType/verificationMaterial/dsseEnvelope) veya artefakt "
                    "SHA-256 özeti imzalı zarfla eşleşmiyor."
                ),
                "evidence": f"mediaType={media_type or 'missing'}, digest_ok={digest_ok}, envelope_ok={envelope_ok}",
                "recommendation": (
                    "Cosign/Sigstore bundle zarfının geçerli bir DSSE imzası, Fulcio/Rekor doğrulama materyali ve "
                    "birebir eşleşen SHA-256 artefakt özeti içerdiğini doğrulayın."
                ),
                "reference": "CWE-347",
                "cwe": "CWE-347",
                "control_id": "SNIPER-SLSA-COSIGN-02",
            })
    elif sigstore_bundle is not None or mirror_workflows is None:
        findings.append({
            "severity": "high",
            "category": "supplychain",
            "title": "Sigstore/Cosign provenance imzası bulunamadı (unsigned artifact)",
            "summary": "İş akışı veya sürüm artefaktı için doğrulanabilir Sigstore bundle kanıtı sunulmadı.",
            "evidence": "sigstore_bundle=missing/empty",
            "recommendation": "Sürüm artefaktlarını Cosign / Sigstore DSSE provenance zarfı ile imzalayın.",
            "reference": "CWE-347",
            "cwe": "CWE-347",
            "control_id": "SNIPER-SLSA-COSIGN-02",
        })

    return {
        "format": "sniper-offline-workflow-sigstore-provenance/1",
        "sigstore_verified": sig_ok,
        "resolved_mirrors": resolved_mirrors,
        "finding_count": len(findings),
        "findings": findings,
    }


