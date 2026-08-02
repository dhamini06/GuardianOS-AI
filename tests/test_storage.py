"""Tests for the SQLite persistence layer."""

from __future__ import annotations

from backend.core.analysis import (
    DetectionResult,
    Explanation,
    Severity,
    ThreatReport,
)
from backend.core.events import EventKind, make_event
from backend.storage.sqlite import SqliteStorage


def _report(report_id: str = "report-1") -> ThreatReport:
    detection = DetectionResult(
        pid=2100,
        exe="/usr/bin/python3",
        raw_score=1.2,
        anomaly_score=0.95,
        confidence=0.9,
        severity=Severity.CRITICAL,
        flagged=True,
    )
    explanation = Explanation(
        summary="reverse shell staged from /tmp",
        reasons=["curl download to /tmp", "egress to 185.220.101.42:4444"],
        confidence=0.9,
        severity=Severity.CRITICAL,
    )
    return ThreatReport(report_id=report_id, timestamp=1234.0, detection=detection, explanation=explanation)


def test_save_and_read_events(tmp_path):
    storage = SqliteStorage(tmp_path / "guardian.db")
    events = [
        make_event(EventKind.FILE_WRITE, pid=1, ppid=0, exe="/usr/bin/curl", details={"path": "/tmp/p.sh"}),
        make_event(EventKind.NETWORK_CONNECT, pid=1, ppid=0, exe="/usr/bin/curl", details={"remote_ip": "8.8.8.8"}),
    ]
    storage.save_events(events)
    recent = storage.recent_events()
    assert len(recent) == 2
    by_kind = {e["kind"]: e for e in recent}
    assert by_kind["file_write"]["details"]["path"] == "/tmp/p.sh"
    assert by_kind["network_connect"]["details"]["remote_ip"] == "8.8.8.8"
    assert storage.counts()["events"] == 2
    storage.close()


def test_save_and_read_reports(tmp_path):
    storage = SqliteStorage(tmp_path / "guardian.db")
    storage.save_report(_report())
    reports = storage.recent_reports()
    assert len(reports) == 1
    assert reports[0]["report_id"] == "report-1"
    assert reports[0]["severity"] == "critical"
    assert reports[0]["explanation"]["summary"].startswith("reverse shell")
    storage.close()


def test_report_upsert(tmp_path):
    storage = SqliteStorage(tmp_path / "guardian.db")
    storage.save_report(_report("r1"))
    storage.save_report(_report("r1"))
    storage.save_report(_report("r2"))
    assert storage.counts()["reports"] == 2
    storage.close()


def test_max_events_pruning(tmp_path):
    storage = SqliteStorage(tmp_path / "guardian.db", max_events=2)
    storage.save_events([make_event(EventKind.EXEC, pid=i, ppid=0, exe="/bin/true") for i in range(5)])
    assert storage.counts()["events"] == 2
    assert storage.recent_events()[0]["pid"] == 4  # newest survives
    storage.close()


def test_empty_save_noop(tmp_path):
    storage = SqliteStorage(tmp_path / "guardian.db")
    assert storage.save_events([]) == 0
    assert storage.counts() == {"events": 0, "reports": 0}
    storage.close()
