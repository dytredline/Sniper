"""Scope behavior checks for the opt-in same-origin ZAP traditional spider."""
import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from zap_target_spider import _plan, validate_exclusions


def _patterns(plan, key):
    lines = plan.splitlines()
    anchor = "      " + key + ":"
    if anchor not in lines:
        return []
    values = []
    for line in lines[lines.index(anchor) + 1:]:
        if not line.startswith("        - "):
            break
        values.append(json.loads(line[10:]))
    return values


def test_spider_plan_is_same_origin_and_exclusions_are_segment_bounded():
    with TemporaryDirectory() as temp:
        plan = _plan("https://fixture.example/", Path(temp), ["/admin", "/private/logs"])
    include = _patterns(plan, "includePaths")
    exclude = _patterns(plan, "excludePaths")
    assert len(include) == 1 and len(exclude) == 2
    assert re.fullmatch(include[0], "https://fixture.example/safe")
    assert not re.fullmatch(include[0], "https://other.example/safe")
    for url in ("https://fixture.example/admin", "https://fixture.example/admin?x=1", "https://fixture.example/admin/users"):
        assert re.fullmatch(exclude[0], url)
    for url in ("https://fixture.example/administrator", "https://other.example/admin", "http://fixture.example/admin"):
        assert not re.fullmatch(exclude[0], url)
    assert re.fullmatch(exclude[1], "https://fixture.example/private/logs/item")
    assert not re.fullmatch(exclude[1], "https://fixture.example/private/logstash")
    assert "type: spider" in plan
    assert "type: activeScan" not in plan


def test_exclusions_accept_empty_and_reject_ambiguous_paths():
    assert validate_exclusions([]) == []
    assert validate_exclusions(["/admin", "/private/logs"]) == ["/admin", "/private/logs"]
    for invalid in (["/"], ["/admin/"], ["//admin"], ["/foo//bar"], ["/ümlaut"], ["/admin?x"], ["/admin%2Fbar"], ["/foo/../bar"], ["/admin", "/admin"]):
        with pytest.raises(ValueError):
            validate_exclusions(invalid)
