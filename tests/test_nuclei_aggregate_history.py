import json
import os
from pathlib import Path

import pytest

from nuclei_aggregate_history import AggregateHistoryError, AggregateHistoryJournal


def _record(number: int) -> tuple[str, dict]:
    job_id = f"{number:016x}"
    return job_id, {
        "job_id": job_id,
        "state": "completed",
        "elapsed_seconds": 0.25,
        "record_count": 1,
        "unique_template_count": 1,
        "severity_counts": {"low": 1},
        "report_sha256": "a" * 64,
    }


def test_private_aggregate_survives_new_instance_without_raw_data(tmp_path: Path):
    journal = AggregateHistoryJournal(tmp_path)
    journal.save([_record(1)])
    expected = _record(1)
    expected[1].pop("job_id")
    assert AggregateHistoryJournal(tmp_path).load() == [expected]
    assert journal.path.stat().st_mode & 0o777 == 0o600
    assert b"target" not in journal.path.read_bytes()
    assert b"matched-at" not in journal.path.read_bytes()


def test_unexpected_raw_field_cannot_replace_existing_history(tmp_path: Path):
    journal = AggregateHistoryJournal(tmp_path)
    journal.save([_record(1)])
    original = journal.path.read_bytes()
    job_id, aggregate = _record(2)
    aggregate["matched-at"] = "synthetic-secret"
    with pytest.raises(AggregateHistoryError):
        journal.save([(job_id, aggregate)])
    assert journal.path.read_bytes() == original


def test_reject_symlink_without_touching_destination(tmp_path: Path):
    destination = tmp_path / "protected.txt"
    destination.write_text("unchanged")
    journal = AggregateHistoryJournal(tmp_path)
    journal.path.symlink_to(destination)
    with pytest.raises(AggregateHistoryError):
        journal.load()
    with pytest.raises(AggregateHistoryError):
        journal.save([_record(1)])
    assert destination.read_text() == "unchanged"


@pytest.mark.parametrize("bad", [
    '{"version":1,"entries":[],"entries":[]}',
    '{"version":1,"entries":[{"job_id":"0000000000000001","state":"completed","elapsed_seconds":1,"target":"secret"}]}',
    '{"version":1,"entries":1}',
    '{"version":1,"entries":[{"job_id":"0000000000000001","state":"completed","elapsed_seconds":NaN}]}',
])
def test_reject_malformed_or_unexpected_journal(tmp_path: Path, bad: str):
    journal = AggregateHistoryJournal(tmp_path)
    journal.path.write_text(bad)
    os.chmod(journal.path, 0o600)
    with pytest.raises(AggregateHistoryError):
        journal.load()


def test_reject_oversized_or_world_readable_journal(tmp_path: Path):
    journal = AggregateHistoryJournal(tmp_path)
    journal.path.write_bytes(b"x" * 65537)
    os.chmod(journal.path, 0o600)
    with pytest.raises(AggregateHistoryError):
        journal.load()
    journal.path.write_text('{"version":1,"entries":[]}')
    os.chmod(journal.path, 0o644)
    with pytest.raises(AggregateHistoryError):
        journal.load()


def test_bounded_to_twenty_records(tmp_path: Path):
    journal = AggregateHistoryJournal(tmp_path)
    journal.save([_record(number) for number in range(20)])
    assert len(journal.load()) == 20
    with pytest.raises(AggregateHistoryError):
        journal.save([_record(number) for number in range(21)])
    assert len(journal.load()) == 20
