"""Tests for M3 telemetry data sources (audit log tailer, subprocess reader)."""

from __future__ import annotations

import sys
import time

import pytest

from backend.telemetry.base import TelemetryError
from backend.telemetry.sources import AuditLogSource, SubprocessLineSource


def test_audit_source_only_reads_appended_lines(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("old1\nold2\n", encoding="utf-8")

    source = AuditLogSource(str(path))
    source.start()
    assert source.read_new_lines() == []  # pre-existing lines are skipped

    with path.open("a", encoding="utf-8") as fh:
        fh.write("new1\n")
        fh.write("new2\n")
    assert source.read_new_lines() == ["new1", "new2"]
    assert source.read_new_lines() == []

    with path.open("a", encoding="utf-8") as fh:
        fh.write("new3\n")
    assert source.read_new_lines() == ["new3"]
    source.stop()


def test_audit_source_missing_file_raises(tmp_path):
    source = AuditLogSource(str(tmp_path / "nope.log"))
    with pytest.raises(TelemetryError, match="not found"):
        source.start()


def test_audit_source_read_before_start_raises(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("", encoding="utf-8")
    source = AuditLogSource(str(path))
    with pytest.raises(TelemetryError):
        source.read_new_lines()
    source.start()
    source.stop()


def test_subprocess_source_reads_lines():
    script = "import time; [print(f'e{i}') for i in range(5)]; time.sleep(0.1)"
    source = SubprocessLineSource([sys.executable, "-c", script])
    source.start()
    try:
        lines: list[str] = []
        deadline = time.time() + 10
        while len(lines) < 5 and time.time() < deadline:
            lines.extend(source.read_lines())
            time.sleep(0.02)
        assert sorted(lines) == [f"e{i}" for i in range(5)]
    finally:
        source.stop()


def test_subprocess_source_missing_binary_raises():
    source = SubprocessLineSource(["definitely-not-a-real-binary-xyz"])
    with pytest.raises(TelemetryError, match="not found"):
        source.start()
