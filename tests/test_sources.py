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
    source = SubprocessLineSource([sys.executable, "-c", script], auto_restart=False)
    source.start()
    try:
        lines: list[str] = []
        deadline = time.time() + 10
        while len(lines) < 5 and time.time() < deadline:
            lines.extend(source.read_lines())
            time.sleep(0.02)
        assert sorted(lines) == [f"e{i}" for i in range(5)]
        deadline = time.time() + 10
        while source.status()["alive"] and time.time() < deadline:
            time.sleep(0.02)
        assert not source.status()["alive"]
    finally:
        source.stop()


def test_subprocess_source_missing_binary_raises():
    source = SubprocessLineSource(["definitely-not-a-real-binary-xyz"])
    with pytest.raises(TelemetryError, match="not found"):
        source.start()


# -- M8: log rotation -----------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="logrotate semantics are Linux-only")
def test_audit_source_handles_rename_rotation(tmp_path):
    """Default logrotate: file is renamed away and a fresh file appears."""
    path = tmp_path / "audit.log"
    path.write_text("", encoding="utf-8")
    source = AuditLogSource(str(path))
    source.start()
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write("pre-rotation\n")
        assert source.read_new_lines() == ["pre-rotation"]

        path.rename(tmp_path / "audit.log.1")
        with path.open("a", encoding="utf-8") as fh:
            fh.write("post-rotation\n")
        assert source.read_new_lines() == ["post-rotation"]
        assert source.rotations == 1
    finally:
        source.stop()


@pytest.mark.skipif(sys.platform == "win32", reason="logrotate semantics are Linux-only")
def test_audit_source_handles_copytruncate(tmp_path):
    """copytruncate logrotate: same inode, file shrinks under the cursor."""
    path = tmp_path / "audit.log"
    path.write_text("", encoding="utf-8")
    source = AuditLogSource(str(path))
    source.start()
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write("line1\nline2\n")
        assert source.read_new_lines() == ["line1", "line2"]

        path.write_text("", encoding="utf-8")  # truncate in place
        with path.open("a", encoding="utf-8") as fh:
            fh.write("after-truncate\n")
        assert source.read_new_lines() == ["after-truncate"]
        assert source.truncations == 1
    finally:
        source.stop()


# -- M8: subprocess resilience --------------------------------------------
def test_subprocess_auto_restarts_on_exit():
    script = "import time; print('boom', flush=True); time.sleep(0.1)"
    source = SubprocessLineSource(
        [sys.executable, "-c", script],
        auto_restart=True,
        restart_backoff=0.1,
    )
    source.start()
    try:
        lines: list[str] = []
        deadline = time.time() + 15
        while len(lines) < 3 and time.time() < deadline:
            lines.extend(source.read_lines())
            time.sleep(0.05)
        assert lines.count("boom") >= 3
        assert source.status()["restarts"] >= 1
    finally:
        source.stop()


def test_subprocess_queue_is_bounded():
    """A stalled reader must never balloon memory: the queue caps and drops."""
    script = "import sys; [print('x'*100, flush=True) for _ in range(5000)]; time.sleep(0.1)"
    source = SubprocessLineSource(
        [sys.executable, "-c", script],
        max_queue=100,
        auto_restart=False,
    )
    source.start()
    try:
        deadline = time.time() + 10
        while source.status()["dropped_lines"] == 0 and time.time() < deadline:
            time.sleep(0.05)
        status = source.status()
        assert status["dropped_lines"] > 0
        assert status["queue_size"] <= 100
    finally:
        source.stop()


def test_subprocess_captures_stderr():
    script = "import sys; print('oops on stderr', file=sys.stderr); time.sleep(0.1)"
    source = SubprocessLineSource([sys.executable, "-c", script], auto_restart=False)
    source.start()
    try:
        deadline = time.time() + 10
        while not source.status()["stderr_tail"] and time.time() < deadline:
            time.sleep(0.05)
        assert "oops on stderr" in source.status()["stderr_tail"]
    finally:
        source.stop()
