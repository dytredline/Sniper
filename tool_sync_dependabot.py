"""Opt-in, mock-transport-only Dependabot alerts summary sync core.

This module has no HTTP client, credential store, route, or persistence.
Callers must inject repository authorization, credentials, and a transport.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlsplit

from tool_report_dependabot import parse_dependabot_alerts_summary


class DependabotSyncError(ValueError):
    """A deliberately sanitized failure with no remote or private content."""


_ORIGIN = "https://api.github.com"
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_LINK_PART = re.compile(r'\s*<([^<>]+)>\s*;\s*rel\s*=\s*"?([A-Za-z]+)"?\s*\Z')
_MAX_PAGES = 5
_MAX_ALERTS = 500
_MAX_PAGE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 8 * 1024 * 1024
_MAX_LINK_BYTES = 4096
_ERROR = "Dependabot özet eşitlemesi başarısız oldu."


def _fail() -> None:
    raise DependabotSyncError(_ERROR)


def _canonical_repository(payload: object) -> tuple[str, str, str]:
    if not isinstance(payload, dict) or set(payload) != {"owner", "repo", "confirm_sync"}:
        _fail()
    if payload["confirm_sync"] is not True:
        _fail()
    owner, repo = payload["owner"], payload["repo"]
    if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
        _fail()
    if not isinstance(repo, str) or not _REPO.fullmatch(repo) or repo in {".", ".."}:
        _fail()
    owner, repo = owner.lower(), repo.lower()
    return owner, repo, f"{owner}/{repo}"


def _next_link(headers: Mapping, path: str) -> str | None:
    links: list[str] = []
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            _fail()
        if key.lower() == "link":
            links.append(value)
    if not links:
        return None
    if len(links) != 1 or len(links[0].encode("utf-8")) > _MAX_LINK_BYTES:
        _fail()
    if any(ord(char) < 32 or ord(char) == 127 for char in links[0]):
        _fail()
    next_url: str | None = None
    for part in links[0].split(","):
        match = _LINK_PART.fullmatch(part)
        if match is None:
            _fail()
        url, rel = match.groups()
        if rel.lower() != "next":
            continue
        if next_url is not None:
            _fail()
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.netloc, parsed.path) != ("https", "api.github.com", path):
            _fail()
        if parsed.fragment or not parsed.query or re.search(r"%(?![0-9A-Fa-f]{2})", parsed.query):
            _fail()
        try:
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            _fail()
        query: dict[str, str] = {}
        for key, value in pairs:
            if key in query or key not in {"per_page", "after", "before"}:
                _fail()
            query[key] = value
        if query.get("per_page") != "100":
            _fail()
        if ("after" in query) == ("before" in query):
            _fail()
        cursor = query.get("after", query.get("before", ""))
        if not cursor or len(cursor) > 256 or any(ord(ch) < 33 or ord(ch) > 126 for ch in cursor):
            _fail()
        if urlsplit(url).geturl() != url:
            _fail()
        next_url = url
    return next_url


def _parse_page(body: object) -> list[dict]:
    if not isinstance(body, bytes) or len(body) > _MAX_PAGE_BYTES:
        _fail()
    try:
        def invalid_constant(_value: str) -> None:
            _fail()
        value = json.loads(body.decode("utf-8"), parse_constant=invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail()
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        _fail()
    return value


def sync_dependabot_summary(
    payload: dict,
    *,
    allowed_repositories: set[str] | frozenset[str],
    credential_provider,
    transport,
) -> dict:
    """Return only the complete validated aggregate from an injected transport."""
    try:
        owner, repo, canonical = _canonical_repository(payload)
        if not isinstance(allowed_repositories, (set, frozenset)):
            _fail()
        if canonical not in allowed_repositories:
            _fail()
        if not callable(credential_provider) or not callable(transport):
            _fail()
        token = credential_provider(canonical)
        if (not isinstance(token, str) or not token or
                any(ord(ch) < 33 or ord(ch) > 126 for ch in token)):
            _fail()
        path = f"/repos/{owner}/{repo}/dependabot/alerts"
        url = _ORIGIN + path + "?per_page=100"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": "Bearer " + token,
        }
        visited: set[str] = set()
        alerts: list[dict] = []
        total_bytes = 0
        for page_number in range(_MAX_PAGES):
            if url in visited:
                _fail()
            visited.add(url)
            response = transport(url, headers)
            if not isinstance(response, tuple) or len(response) != 3:
                _fail()
            status, response_headers, body = response
            if type(status) is not int or status != 200 or not isinstance(response_headers, Mapping):
                _fail()
            if not isinstance(body, bytes) or len(body) > _MAX_PAGE_BYTES:
                _fail()
            total_bytes += len(body)
            if total_bytes > _MAX_TOTAL_BYTES:
                _fail()
            page_alerts = _parse_page(body)
            if len(alerts) + len(page_alerts) > _MAX_ALERTS:
                _fail()
            alerts.extend(page_alerts)
            following = _next_link(response_headers, path)
            if following is None:
                return parse_dependabot_alerts_summary({"alerts": alerts})
            if page_number + 1 == _MAX_PAGES or len(alerts) == _MAX_ALERTS:
                _fail()
            url = following
        _fail()
    except Exception:
        raise DependabotSyncError(_ERROR) from None
