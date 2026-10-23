from __future__ import annotations

import hashlib
from typing import Any
from xml.etree import ElementTree
from xml.parsers import expat


MAX_REPORT_BYTES = 60_000
MAX_SUITES = 20
MAX_TESTCASES = 500
_ERROR = "Geçersiz Schemathesis JUnit XML."
_CASE_CHILDREN = {"failure", "error", "skipped", "system-out", "system-err", "properties"}
_SUITE_CHILDREN = {"testcase", "properties", "system-out", "system-err"}


def _safe_root(report_bytes: bytes) -> ElementTree.Element:
    # ElementTree ignores external entities, but explicitly reject declarations and
    # processing instructions before it sees potentially sensitive report content.
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def reject(*_args: object) -> None:
        raise ValueError(_ERROR)

    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.ProcessingInstructionHandler = reject
    try:
        parser.Parse(report_bytes, True)
        return ElementTree.fromstring(report_bytes)
    except (expat.ExpatError, ElementTree.ParseError, ValueError) as exc:
        raise ValueError(_ERROR) from exc


def parse_schemathesis_junit_summary(report: str) -> dict[str, Any]:
    """Summarize already exported JUnit testcases; never run Schemathesis.

    JUnit testcases represent API operations or stateful test groups, not the
    individual generated HTTP requests made during a Schemathesis run.
    """
    if not isinstance(report, str):
        raise ValueError(_ERROR)
    try:
        report_bytes = report.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(_ERROR) from exc
    if not report_bytes or len(report_bytes) > MAX_REPORT_BYTES:
        raise ValueError(_ERROR)

    root = _safe_root(report_bytes)
    if root.tag == "testsuite":
        suites = [root]
    elif root.tag == "testsuites":
        suites = list(root)
    else:
        raise ValueError(_ERROR)
    if not suites or len(suites) > MAX_SUITES or any(suite.tag != "testsuite" for suite in suites):
        raise ValueError(_ERROR)

    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    testcase_count = 0
    for suite in suites:
        for child in suite:
            if child.tag not in _SUITE_CHILDREN:
                raise ValueError(_ERROR)
            if child.tag != "testcase":
                continue
            testcase_count += 1
            if testcase_count > MAX_TESTCASES:
                raise ValueError(_ERROR)
            outcomes = []
            for outcome in child:
                if outcome.tag not in _CASE_CHILDREN:
                    raise ValueError(_ERROR)
                if outcome.tag in {"failure", "error", "skipped"}:
                    outcomes.append(outcome.tag)
            if len(outcomes) > 1:
                raise ValueError(_ERROR)
            if not outcomes:
                counts["passed"] += 1
            else:
                counts[{"failure": "failed", "error": "errors", "skipped": "skipped"}[outcomes[0]]] += 1

    return {
        "format": "schemathesis-junit-xml",
        "suite_count": len(suites),
        "testcase_count": testcase_count,
        "outcome_counts": counts,
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
